// riftbench — Rift load testing tool.
//
// Connects N gophertunnel bots to Rift in "offline" mode (no Xbox authentication),
// waits for each bot to complete the spawn sequence, then sends periodic
// PlayerAuthInput (movement input) packets to simulate realistic upstream load.
// While the bots run, use Rift's /metrics (or metrics.jsonl) and perf to
// measure how well the proxy holds up under load.
//
// Prerequisites:
//   - The backend (PMMP/BDS) must run in offline mode (xbox-auth=false / online-mode=false).
//     Required so unauthenticated bots can connect.
//   - The test backend must not have duplicate-login prevention (anti-dupe); bots will be
//     kicked if it does.
//   - Each bot gets a unique XUID/UUID/name to avoid deterministic entity-ID (crc32 XUID)
//     collisions and duplicate-connection blocks.
//   - To measure the proxy's own ceiling, run the bots close to the proxy (same machine /
//     same DC) to remove network as a variable. (Running from a home PC to a VPS may hit
//     upload bandwidth before the proxy does.)
//
// Usage:
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
	target = flag.String("target", "127.0.0.1:19132", "Rift address (raknet UDP)")
	n      = flag.Int("n", 50, "number of bots")
	rampMs = flag.Int("ramp", 50, "delay between bot connections (ms) — prevents thundering herd")
	durSec = flag.Int("dur", 60, "run duration in seconds. 0=unlimited (until Ctrl+C)")
	move   = flag.Bool("move", true, "send PlayerAuthInput after spawn (generates upstream load)")
	rate   = flag.Int("rate", 20, "input packets per second per bot (real client ≈ 20)")
)

type stats struct {
	connected atomic.Int64 // RakNet + login succeeded
	spawned   atomic.Int64 // spawn sequence completed (fully in-world)
	failed    atomic.Int64 // connect / spawn failed
	dropped   atomic.Int64 // disconnected after spawn (kick / error)
	sent      atomic.Int64 // cumulative input packets sent

	mu         sync.Mutex
	lats       []time.Duration // sampled RTTs collected periodically per bot during load
	errSamples []string        // sample failure reasons (up to 6) — why connections failed
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

	fmt.Printf("riftbench → %s  | bots %d, ramp %dms, %s, rate %d/s\n",
		*target, *n, *rampMs,
		func() string {
			if *durSec > 0 {
				return fmt.Sprintf("%ds", *durSec)
			}
			return "unlimited (Ctrl+C)"
		}(),
		*rate)
	if !*move {
		fmt.Println("(-move=false: connection-only mode — measuring connection scalability)")
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

	// Final summary.
	fmt.Printf("\n\n=== results (%.0fs) ===\n", time.Since(start).Seconds())
	fmt.Printf("connected : %d / %d\n", st.connected.Load(), *n)
	fmt.Printf("spawned   : %d\n", st.spawned.Load())
	fmt.Printf("failed    : %d\n", st.failed.Load())
	fmt.Printf("dropped   : %d\n", st.dropped.Load())
	fmt.Printf("sent      : %d packets\n", st.sent.Load())
	st.mu.Lock()
	if len(st.errSamples) > 0 {
		fmt.Println("failure reasons (sample):")
		for _, e := range st.errSamples {
			fmt.Println("  -", e)
		}
	}
	st.mu.Unlock()
	printLatency(&st)
	fmt.Println("\nFor proxy-side metrics over the same window, check the Rift dashboard (/metrics · /players) and metrics.jsonl.")
}

func bot(ctx context.Context, i int, st *stats, wg *sync.WaitGroup) {
	defer wg.Done()

	d := minecraft.Dialer{
		IdentityData: login.IdentityData{
			DisplayName: fmt.Sprintf("rbench%04d", i),
			Identity:    uuid.New().String(),
			// Unique XUID per bot → distinct crc32 entity ID. Avoids collisions and duplicate-login blocks.
			XUID: fmt.Sprintf("%013d", int64(9_000_000_000_000)+int64(i)),
		},
	}

	// 15-second ceiling per dial — fail fast if the port is not listening.
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

	// Drain the downstream continuously so the connection stays healthy.
	go func() {
		for {
			if _, e := conn.ReadPacket(); e != nil {
				return
			}
		}
	}()

	// Collect sampled RTTs periodically during load.
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

	// Send PlayerAuthInput at rate/s with a small random walk, like a real client.
	pos := conn.GameData().PlayerPosition
	empty := protocol.NewBitset(packet.PlayerAuthInputBitsetSize) // no input flags = idle
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

// reporter refreshes a single status line (\r) every second.
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
			fmt.Printf("\r[%4.0fs] conn=%d spawn=%d fail=%d drop=%d | input %d/s        ",
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
		fmt.Println("RTT samples : none")
		return
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p := func(q float64) time.Duration { return lats[int(float64(len(lats)-1)*q)] }
	fmt.Printf("RTT (under load) : p50=%v  p95=%v  p99=%v  max=%v  (samples %d)\n",
		p(0.50).Round(time.Millisecond), p(0.95).Round(time.Millisecond),
		p(0.99).Round(time.Millisecond), lats[len(lats)-1].Round(time.Millisecond), len(lats))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
