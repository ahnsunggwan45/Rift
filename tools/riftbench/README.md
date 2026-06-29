# riftbench — Rift 부하 테스트기

gophertunnel 봇 N명을 **오프라인**(Xbox 인증 없음)으로 Rift 에 접속시켜 스폰까지 완료한 뒤
실제 플레이어처럼 `PlayerAuthInput`(움직임)을 보내, 그동안 Rift 가 얼마나 버티는지 직접 측정한다.

## 전제 조건
- 백엔드(PMMP/BDS)가 **오프라인 모드** (`xbox-auth=false` / `online-mode=false`) — 인증 없는 봇 접속에 필수
- 테스트 백엔드에 **중복접속 차단(안티-듀프)이 없어야** 함 (있으면 봇이 튕김)
- **프록시 자체 한계**를 보려면 봇을 **프록시 근처**(같은 머신/DC)에서 돌려 네트워크를 변수에서 제거
  (집 PC→VPS 로 돌리면 업로드 대역폭이 먼저 막힐 수 있다)

## 빌드 & 실행
```bash
cd tools/riftbench
go build -o riftbench .
./riftbench -target 127.0.0.1:19132 -n 100 -dur 120
```

## 플래그
| 플래그 | 기본 | 설명 |
|---|---|---|
| `-target` | `127.0.0.1:19132` | Rift 주소 (raknet UDP) |
| `-n` | `50` | 봇 수 |
| `-ramp` | `50` | 봇 접속 간격(ms) — 한 번에 몰리지 않게 |
| `-dur` | `60` | 유지 시간(초). `0`=무한(Ctrl+C 까지) |
| `-move` | `true` | 스폰 후 입력 전송(업스트림 부하). `false`=접속만 유지 |
| `-rate` | `20` | 봇당 초당 입력 패킷 수 (실제 클라 ≈ 20) |

## 결과 읽는 법
- **riftbench 출력**: 접속/스폰/실패/끊김 + 부하 중 RTT `p50/p95/p99/max`
- **같은 구간 Rift** `/metrics`·`metrics.jsonl`: `active`, `msgs/s`(pps), `avg_forward_us`, `peak_active`
- 둘을 맞춰 보면 *"봇 N명에서 forward latency 가 X μs 로 오르고 실패가 시작"* 같은 **천장**을 잡는다

## 측정 전략
1. **단계적 램프업**: 50 → 200 → 500 … 올리며 실패/끊김이 시작되는 지점 = 연결 천장
2. **유휴 vs 부하**: 같은 N 에서 `-move=false`(접속만) vs `-move`(20/s) 비교 → 데이터패스 비용 분리
3. **프록시 오버헤드**: 프록시 경유 RTT vs 백엔드 직결 RTT 비교 → Rift 가 더한 지연
4. 천장 근처에서 [`PROFILING.md`](../../PROFILING.md) 의 `rift-prof` + `perf` 로 핫 함수까지 확인

> riftbench 는 봇마다 고유 XUID/UUID/이름을 부여해 결정론 엔티티ID(crc32 XUID) 충돌과
> 중복접속 차단을 피한다. 실계정·실서버를 건드리지 않는다.
