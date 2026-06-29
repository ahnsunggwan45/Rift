# riftbench — Rift Load Testing Tool

Connects N gophertunnel bots to Rift in **offline** mode (no Xbox authentication),
waits for each bot to complete the spawn sequence, then sends `PlayerAuthInput`
(movement) packets at a configurable rate to simulate realistic upstream load —
letting you directly measure how well Rift holds up.

## Prerequisites
- The backend (PMMP/BDS) must run in **offline mode** (`xbox-auth=false` / `online-mode=false`) — required for unauthenticated bots to connect
- The test backend must **not** have duplicate-login prevention (anti-dupe); bots will be kicked if it does
- To measure the **proxy's own ceiling**, run the bots **close to the proxy** (same machine / DC) to remove network as a variable
  (running from a home PC to a VPS may hit upload bandwidth before the proxy does)

## Build & Run
```bash
cd tools/riftbench
go build -o riftbench .
./riftbench -target 127.0.0.1:19132 -n 100 -dur 120
```

## Flags
| Flag | Default | Description |
|---|---|---|
| `-target` | `127.0.0.1:19132` | Rift address (raknet UDP) |
| `-n` | `50` | number of bots |
| `-ramp` | `50` | delay between bot connections (ms) — prevents thundering herd |
| `-dur` | `60` | run duration in seconds. `0`=unlimited (until Ctrl+C) |
| `-move` | `true` | send input packets after spawn (upstream load). `false`=connection-only mode |
| `-rate` | `20` | input packets per second per bot (real client ≈ 20) |

## Reading the Results
- **riftbench output**: connected / spawned / failed / dropped counts + RTT under load `p50/p95/p99/max`
- **Rift `/metrics` · `metrics.jsonl` for the same window**: `active`, `msgs/s` (pps), `avg_forward_us`, `peak_active`
- Correlating both gives you a concrete **ceiling** — e.g. *"at N bots, forward latency climbs to X μs and failures begin"*

## Measurement Strategy
1. **Stepped ramp-up**: 50 → 200 → 500 … increase until failures / drops appear = connection ceiling
2. **Idle vs load**: same N with `-move=false` (connections only) vs `-move` (20/s) — isolates data-path cost
3. **Proxy overhead**: proxy RTT vs direct-to-backend RTT — measures latency added by Rift
4. Near the ceiling, use [`PROFILING.md`](../../PROFILING.md) with `rift-prof` + `perf` to identify hot functions

> riftbench assigns each bot a unique XUID/UUID/name to avoid deterministic entity-ID (crc32 XUID)
> collisions and duplicate-connection blocks. It never touches real accounts or live servers.
