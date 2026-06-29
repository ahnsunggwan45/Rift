# Rift Profiling (CPU Hot-Path Analysis)

Metrics (`/metrics`, `metrics.jsonl`) tell you *when / what* is slow.
Identifying *which code* is hot requires a CPU profile, which needs a **symbols-included build + Linux `perf`**.

Three artifacts to collect:
1. `metrics.jsonl` — time-series data (situational patterns: player count · throughput · forward latency changes)
2. `perf-report.txt` — hot functions under load
3. (optional) a short run with `--features profiling` to populate `alloc_count`/`alloc_bytes` — validates hot-path allocations

With these three, you can pinpoint *"function Y is hot in situation X with Z allocations"* and make targeted optimizations (sendmmsg / worker sharding / pooling, etc.).

---

## 1. Build with Symbols (`rift-prof`)

Release binaries are stripped, so `perf` cannot resolve function names. Build with the `profiling` profile for profiling sessions (same optimizations as release, but symbols retained):

```bash
cargo build --profile profiling     # → target/profiling/rift
```

You can also use the pre-built **`dist-linux/rift-prof`** (glibc + x86-64-v2, symbols included) directly.

## 2. Profiling Session (production server, under load)

Run `rift` (stripped) for normal operations and swap in `rift-prof` only when profiling:

```bash
# stop the running rift instance first
./rift-prof config.toml
```

From a separate shell, sample for 30 seconds while the server is under load:

```bash
# install perf (once): sudo apt install -y linux-tools-$(uname -r)   (or linux-perf)
sudo sysctl kernel.perf_event_paranoid=1      # allow sampling (may not work in some container VPS environments)

PID=$(pgrep -n rift-prof)
sudo perf record -F 99 -g -p "$PID" -- sleep 30
sudo perf report --stdio > perf-report.txt    # hot function list — this is sufficient
```

Send `perf-report.txt` to identify hot functions and drive optimizations.
For a visual flame graph: `sudo perf script > perf.script`, then convert to SVG with the [FlameGraph](https://github.com/brendangregg/FlameGraph) tooling.

## 3. Allocation Data

A `--features profiling` build uses a counting allocator to populate `alloc_count`/`alloc_bytes` in `/metrics` and `metrics.jsonl`, validating that hot-path allocations are truly zero. Because the counting allocator adds overhead, use it **only during the measurement window**:

```bash
cargo build --release --features profiling
```

> Note: the flame-graph build (`--profile profiling`) and the allocation-measurement build (`--features profiling`) are **separate**.
> Use `--profile profiling` (no counting allocator — reflects real performance) for flame graphs; use `--features profiling` for allocation counts.
