// riftbench — Rift 부하 테스트기.
//
// gophertunnel 봇 N명을 "오프라인"(Xbox 인증 없음)으로 Rift 에 접속시켜 스폰까지
// 완료한 뒤, PlayerAuthInput(움직임 입력)을 주기적으로 보내 실제 플레이어와 비슷한
// 업스트림 부하를 만든다. 그동안 Rift 의 /metrics(또는 metrics.jsonl)·perf 로 프록시가
// 얼마나 버티는지 직접 측정할 수 있다.
//
// 전제 조건:
//   - 백엔드(PMMP/BDS)가 오프라인 모드여야 한다 (xbox-auth=false / online-mode=false).
//     인증 없는 봇이 접속하려면 필수.
//   - 테스트용 백엔드는 "다른 기기 중복접속 차단" 같은 안티-듀프가 없어야 한다(봇이 튕김).
//   - 봇마다 고유 XUID/UUID/이름을 부여 → 결정론 엔티티ID(crc32 XUID) 충돌·중복차단 회피.
//   - 프록시 자체 한계를 보려면 봇을 프록시 근처(같은 머신/같은 DC)에서 돌려 네트워크를
//     변수에서 제거하라. (집 PC→VPS 로 돌리면 업로드 대역폭이 먼저 막힐 수 있다.)
//
// 사용:
//   go run . -target 127.0.0.1:19132 -n 100 -dur 120
//   go run . -target rift.example.com:19132 -n 500 -ramp 20 -rate 20
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gl/mathgl/mgl32"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

var (
	target = flag.String("target", "127.0.0.1:19132", "Rift 주소 (raknet UDP)")
	n      = flag.Int("n", 50, "봇 수")
	rampMs = flag.Int("ramp", 50, "봇 접속 간격(ms) — 한 번에 몰리지 않게")
	durSec = flag.Int("dur", 60, "유지 시간(초). 0=무한(Ctrl+C 까지)")
	move   = flag.Bool("move", true, "스폰 후 PlayerAuthInput 전송(업스트림 부하 생성)")
	rate   = flag.Int("rate", 20, "봇당 초당 입력 패킷 수 (실제 클라 ≈ 20)")
)

type stats struct {
	connected atomic.Int64 // RakNet+로그인 성공
	spawned   atomic.Int64 // 스폰 시퀀스 완료(완전한 플레이어)
	failed    atomic.Int64 // 접속/스폰 실패
	dropped   atomic.Int64 // 스폰 후 끊김(킥/에러)
	sent      atomic.Int64 // 보낸 입력 패킷 누계

	mu         sync.Mutex
	lats       []time.Duration // 부하 중 표본 RTT(봇별 주기 수집)
	errSamples []string        // 실패 원인 표본(최대 6개) — 왜 실패했는지
}

func (st *stats) addErr(s string) {
	st.mu.Lock()
	if len(st.errSamples) < 6 {
		st.errSamples = append(st.errSamples, s)
	}
	st.mu.Unlock()
}

func main() {
	flag.Parse()
	var st stats

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *durSec > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*durSec)*time.Second)
		defer cancel()
	}

	fmt.Printf("riftbench → %s  | 봇 %d명, ramp %dms, %s, rate %d/s\n",
		*target, *n, *rampMs,
		func() string {
			if *durSec > 0 {
				return fmt.Sprintf("%ds", *durSec)
			}
			return "무한(Ctrl+C)"
		}(),
		*rate)
	if !*move {
		fmt.Println("(-move=false: 접속만 유지 — 연결 확장성 측정 모드)")
	}

	start := time.Now()
	go reporter(ctx, &st, start)

	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go bot(ctx, i, &st, &wg)
		time.Sleep(time.Duration(*rampMs) * time.Millisecond)
	}
	wg.Wait()

	// 최종 요약.
	fmt.Printf("\n\n=== 결과 (%.0fs) ===\n", time.Since(start).Seconds())
	fmt.Printf("접속 성공 : %d / %d\n", st.connected.Load(), *n)
	fmt.Printf("스폰 완료 : %d\n", st.spawned.Load())
	fmt.Printf("접속 실패 : %d\n", st.failed.Load())
	fmt.Printf("도중 끊김 : %d\n", st.dropped.Load())
	fmt.Printf("입력 전송 : %d 패킷\n", st.sent.Load())
	st.mu.Lock()
	if len(st.errSamples) > 0 {
		fmt.Println("실패 원인(표본):")
		for _, e := range st.errSamples {
			fmt.Println("  -", e)
		}
	}
	st.mu.Unlock()
	printLatency(&st)
	fmt.Println("\n프록시 측 지표는 Rift 대시보드(/metrics·/players)·metrics.jsonl 에서 같은 구간을 확인하라.")
}

func bot(ctx context.Context, i int, st *stats, wg *sync.WaitGroup) {
	defer wg.Done()

	d := minecraft.Dialer{
		IdentityData: login.IdentityData{
			DisplayName: fmt.Sprintf("rbench%04d", i),
			Identity:    uuid.New().String(),
			// 고유 XUID → 봇마다 다른 crc32 엔티티ID. 충돌·중복차단 회피.
			XUID: fmt.Sprintf("%013d", int64(9_000_000_000_000)+int64(i)),
		},
	}

	// 다이얼당 15초 상한 — 안 듣는 포트면 빨리 실패하게.
	dctx, dcancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := d.DialContext(dctx, "raknet", *target)
	dcancel()
	if err != nil {
		st.failed.Add(1)
		st.addErr("dial: " + err.Error())
		return
	}
	defer conn.Close()
	st.connected.Add(1)

	if err := conn.DoSpawnTimeout(20 * time.Second); err != nil {
		st.failed.Add(1)
		st.addErr("spawn: " + err.Error())
		return
	}
	st.spawned.Add(1)

	// 다운스트림을 계속 비워줘야(읽어줘야) 연결이 건강하게 유지된다.
	go func() {
		for {
			if _, e := conn.ReadPacket(); e != nil {
				return
			}
		}
	}()

	// 부하 중 RTT 주기 수집.
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l := conn.Latency()
				st.mu.Lock()
				st.lats = append(st.lats, l)
				st.mu.Unlock()
			}
		}
	}()

	if !*move {
		<-ctx.Done()
		return
	}

	// 실제 클라처럼 PlayerAuthInput 을 rate/s 로 전송(살짝 랜덤워크).
	pos := conn.GameData().PlayerPosition
	empty := protocol.NewBitset(packet.PlayerAuthInputBitsetSize) // 입력 플래그 없음 = 정상
	interval := time.Second / time.Duration(maxInt(*rate, 1))
	t := time.NewTicker(interval)
	defer t.Stop()
	var tick uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick++
			pos[0] += (rand.Float32() - 0.5) * 0.2
			pos[2] += (rand.Float32() - 0.5) * 0.2
			pk := &packet.PlayerAuthInput{
				Pitch:            0,
				Yaw:              rand.Float32() * 360,
				HeadYaw:          rand.Float32() * 360,
				Position:         pos,
				MoveVector:       mgl32.Vec2{},
				InputData:        empty,
				InputMode:        1, // mouse
				PlayMode:         0, // normal
				InteractionModel: 0,
				Tick:             tick,
			}
			if err := conn.WritePacket(pk); err != nil {
				st.dropped.Add(1)
				return
			}
			st.sent.Add(1)
		}
	}
}

// 매초 진행 상황을 한 줄(\r)로 갱신.
func reporter(ctx context.Context, st *stats, start time.Time) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	var lastSent int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sent := st.sent.Load()
			pps := sent - lastSent
			lastSent = sent
			fmt.Printf("\r[%4.0fs] 접속=%d 스폰=%d 실패=%d 끊김=%d | 입력 %d/s        ",
				time.Since(start).Seconds(),
				st.connected.Load(), st.spawned.Load(),
				st.failed.Load(), st.dropped.Load(), pps)
		}
	}
}

func printLatency(st *stats) {
	st.mu.Lock()
	lats := append([]time.Duration(nil), st.lats...)
	st.mu.Unlock()
	if len(lats) == 0 {
		fmt.Println("RTT 표본 : 없음")
		return
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p := func(q float64) time.Duration { return lats[int(float64(len(lats)-1)*q)] }
	fmt.Printf("RTT(부하중) : p50=%v  p95=%v  p99=%v  max=%v  (표본 %d)\n",
		p(0.50).Round(time.Millisecond), p(0.95).Round(time.Millisecond),
		p(0.99).Round(time.Millisecond), lats[len(lats)-1].Round(time.Millisecond), len(lats))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
