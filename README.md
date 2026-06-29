# Rift

A fast, seamless reverse proxy for **Minecraft: Bedrock Edition**, written in Rust.

Rift sits in front of your [PocketMine-MP](https://github.com/pmmp/PocketMine-MP) servers and moves players between them **without a reconnect** — no "Disconnected" screen, no re-login, no resource-pack reload. It's a lightweight, high-performance alternative to WaterdogPE.

> **Status:** actively developed. Core proxying and seamless transfer are verified in-game. See the [Roadmap](#roadmap) for what's done vs. planned.

## Goals

Rift optimizes for a few **measurable** targets (observe them at [`/metrics`](#web-monitoring)):

- **Zero hot-path allocation** — forwarding a packet allocates nothing on the heap (verify with a `--features profiling` build → `alloc_count`).
- **No work for uninteresting packets** — packets Rift doesn't touch are never decoded into objects; they pass through as raw bytes.
- **Minimal forward latency** and **0% drop** for reliable traffic.
- **Lower CPU than WaterdogPE** at equivalent load.

> **On "zero-copy":** Rift is **application-level zero-copy** — a *copy-minimized data path*. Within the process, forwarded bytes are moved (ref-counted), not copied. The unavoidable NIC → kernel → userspace copy still happens; true kernel-bypass zero-copy (io_uring registered buffers) is on the roadmap.

## Features

- ⚡ **High-performance Bedrock / RakNet proxy** written in Rust.
- 🚀 **Packet pass-through fast path** — zero object creation for non-intercepted packets.
- 🎯 **Selective packet interception** — only the few packets Rift must act on are decoded.
- 🔀 **Seamless server transfer** — switch backends with no reconnect; game mode, game rules, boss bars and scoreboards carry over.
- 🧩 **PMMP-optimized** — deterministic entity IDs via the drop-in [RiftSupport](downstream/RiftSupport) plugin.
- 🌐 **Cross-platform** — builds on Linux & Windows; fully static `musl` binaries run on any distro.
- 📊 **Built-in observability** — `/metrics` + a live web dashboard, per-player ping, JSONL metrics history, and CPU / allocation profiling hooks.
- 🎛️ **Live console** — `info` / `list` / `transfer` / `kick` / `stop`.
- 🛡️ **Production-minded** — graceful shutdown, panic-free parsing, DoS-resistant fragment reassembly, reliable-packet de-dup.

## Quick start

1. **Build** (or grab a release binary): `cargo build --release` → `target/release/rift`
2. **Configure**: `cp config.example.toml config.toml`, then point `[servers]` at your backend addresses.
3. **Run**: `./rift config.toml`
4. **Prepare each backend** PMMP server: set `enable-encryption: false` and install the [RiftSupport](downstream/RiftSupport) plugin (one drop-in — see [Requirements](#requirements)).
5. **Connect** your Bedrock client to the proxy's address, and switch servers seamlessly.

For production (auto-restart, console, firewall), see [Run](#run) and [`dist-linux/DEPLOY.md`](dist-linux/DEPLOY.md).

## How it works

Rift terminates RakNet itself: clients connect to Rift, and Rift opens its own RakNet connection to each downstream server. Game packets are shuttled as opaque bytes — only login, transfer, resource-pack and a few spawn-related packets are decoded.

**Seamless transfer** (triggered by a downstream `TransferPacket`, or the console `transfer` command):

1. Rift connects to the target server and drives the handshake to full spawn, buffering the spawn stream.
2. The client is flipped to a dummy dimension (clearing the old world) and filled with empty chunks.
3. The downstream connection is swapped; `SetLocalPlayerAsInitialized` triggers the real spawn.
4. The client returns to the overworld and the buffered spawn stream is replayed.

Entity IDs are **not** rewritten. Instead, every server assigns the same player the same runtime ID — `crc32(XUID) & 0x7FFFFFFFFFFFFFFF` — so the client's view stays consistent across servers (see [Requirements](#requirements)).

## Design principles

- **Keep the fast path small** — decode only the few packets Rift must act on; forward everything else as raw bytes (no object creation, no parsing on the hot path).
- **Zero unnecessary allocations / parsing** — uninteresting packet IDs are rejected by a single interest-bitmap lookup and passed straight through.
- **Own the transport** — Rift vendors a patched RakNet fork ([`vendor/rift-raknet`](vendor/rift-raknet)), so the data path is tuned directly: copy-minimized framing, bounded fragment reassembly (DoS-resistant), reliable-packet de-duplication.
- **PMMP-first** — the transfer model and deterministic entity-ID scheme are built around PocketMine-MP.
- **Measure, then optimize** — metrics first; heavier work (pooling, worker-sharding, io_uring) only after real-server measurement. Predictable latency over feature bloat.

## Requirements

Each **downstream PMMP server** behind Rift needs two things:

1. **Encryption off** — `enable-encryption: false` in `pocketmine.yml`. Rift forwards the client's login token verbatim, so the XUID is preserved.
2. **Deterministic entity IDs** — every server must assign the same player the same runtime entity id, so the client's view of "itself" stays consistent across a transfer.

### Easiest: the RiftSupport plugin

Drop the [`downstream/RiftSupport`](downstream/RiftSupport) plugin into each backend server. It:

- swaps in a `Player` that sets a deterministic id (`crc32(XUID)`), and
- warns you on startup if encryption is still on, or if a custom `Player` class needs the manual step below.

Load it as a folder with [DevTools](https://github.com/pmmp/DevTools), or build a `.phar`.

### Manual (servers with a custom `Player` class)

If your server already uses its own `Player` subclass, RiftSupport won't replace it — add this to that class instead:

```php
protected function initEntity(CompoundTag $nbt) : void {
    parent::initEntity($nbt);
    $xuid = $this->getXuid();
    $key  = $xuid !== "" ? $xuid : $this->getName();
    $this->id = crc32($key) & 0x7FFFFFFFFFFFFFFF;
}
```

> Either way this must apply on **every** downstream server, or a transferred player's own entity (and warps) will break.

## Security / trust model

Rift uses a **split trust model**: encryption is intentionally dropped on the trusted hop to avoid double-encryption overhead, while the untrusted hop stays protected.

- **Proxy ↔ backend: plaintext** — backends run `enable-encryption: false`. The proxy and backends are expected to sit on the same trusted private network, so encrypting this hop would only add cost.
- **Client ↔ proxy:** the public hop. The intended model is to **terminate Bedrock encryption at the proxy** here, so the client link is encrypted while the backend link stays plaintext.

> ⚠️ **Current status:** client-side encryption termination is **not wired yet** — Rift currently runs plaintext on *both* hops. Until it lands, deploy Rift where the **client↔proxy path is trusted** (LAN / VPN / a fronting layer). The crypto layer (`src/crypto.rs`, P-384 ECDH + AES-CTR) is in the tree; wiring it is the next security milestone (see [Roadmap](#roadmap)).

## Build

Requires a recent Rust toolchain.

```bash
cargo build --release
# → target/release/rift
```

**Fully static Linux binary** (runs on any distro, no glibc-version or `musl-gcc` worries):
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --no-default-features
# → target/x86_64-unknown-linux-musl/release/rift
```
`--no-default-features` drops the optional [mimalloc](https://github.com/microsoft/mimalloc) allocator (Rift's only C dependency), yielding a pure-Rust static build.

## Configure

```bash
cp config.example.toml config.toml
# edit config.toml — point [servers] at your downstream addresses
```
All options are documented in [`config.example.toml`](config.example.toml).

## Run

**Development:**
```bash
./rift config.toml
```

**Production** — two options, both in [`dist-linux/`](dist-linux) (see [`dist-linux/DEPLOY.md`](dist-linux/DEPLOY.md)):

- **screen + `start.sh`** — recommended if you want the live console. Auto-restarts on crash.
  ```bash
  screen -S rift ./start.sh
  ```
- **systemd + `setup.sh`** — hands-off, starts on boot, no console (manage via dashboard + `systemctl`).
  ```bash
  sudo bash setup.sh        # installs to /opt/rift, opens firewall, registers + starts the service
  ```

## Console commands

| Command | Description |
| --- | --- |
| `info` | uptime, player count, throughput, per-server breakdown |
| `list` | connected players (`#id  name  ip → server`) |
| `transfer <name\|id> <server>` | move a player to another channel |
| `kick <name\|id>` | disconnect a player |
| `stop` | graceful shutdown |

## Web monitoring

Set `web_addr` in `config.toml` (e.g. `"0.0.0.0:8080"`):

- `http://<host>:8080/` — auto-refreshing dashboard
- `GET /metrics` — JSON: active/peak players, throughput, packet rate, avg packet size, avg forward latency, transfers, per-server (plus `alloc_*` on a profiling build)
- `GET /players` — JSON: id, name, ip, server, ping (RTT), uptime

> `/players` exposes player names and IPs — keep the port behind a firewall if it's reachable publicly.

## Performance measurement

Rift follows a **measure-then-optimize** policy, so the tooling to gather real data is built in:

- **Time-series history** — set `history_file` in `config.toml` to append a metrics snapshot (one JSON object per line) every `history_interval_secs`. Leave it on in production to collect throughput / latency / player-count history over time.
- **CPU profiling** — to find *which function* is hot, build the symbol-included `profiling` profile and sample with Linux `perf`. See [`PROFILING.md`](PROFILING.md).
- **Allocation profiling** — a `--features profiling` build exposes `alloc_count` / `alloc_bytes` at `/metrics` to verify the hot path stays allocation-free.
- **Load testing** — [`tools/riftbench`](tools/riftbench) connects N offline bots through Rift and generates realistic player traffic, so you can find the ceiling yourself (requires an offline-mode backend).

## Project layout

```
src/                    proxy core — intercept, transfer, packets, web, console, registry, ...
vendor/rift-raknet/     vendored, patched fork of rust-raknet (Bedrock RakNet)
downstream/RiftSupport/ drop-in PMMP plugin — deterministic entity ids for backends
tools/riftbench/        load tester — N offline bots over gophertunnel
dist-linux/             deploy assets — start.sh, setup.sh, rift.service, DEPLOY.md
PROFILING.md            CPU / allocation profiling workflow
```

## Compatibility

Rift targets the Bedrock protocol used by current PocketMine-MP builds. The specific packet IDs Rift decodes live in `src/` and may need updating when Bedrock bumps its protocol.

## Roadmap

**Core**
- ✅ RakNet transport · login · resource-pack phase
- ✅ Seamless server transfer — StartGame interception, state teardown (verified in-game)
- ✅ Metrics endpoint · web dashboard · live console
- ⬜ Client-side encryption termination (see [Security](#security--trust-model))
- ⬜ Config hot-reload

**Performance**
- ✅ mimalloc (optional) · packet pass-through fast path
- ✅ Application-level zero-copy (Bytes data path)
- ✅ Bounded fragment reassembly · reliable-packet de-dup
- ✅ Profiling build with allocation counters (`--features profiling`)
- ⬜ Buffer / packet pool · arena allocation
- ⬜ `sendmmsg` / `recvmmsg` · worker sharding + `SO_REUSEPORT` · CPU affinity / NUMA
- ⬜ io_uring · libdeflate

**Networking**
- ✅ Multiple backends + transfer · configurable MTU
- ⬜ Health checks · auto-reconnect · weighted routing / load balancing
- ⬜ Proxy Protocol · MTU auto-negotiation

**Operations**
- ✅ Graceful shutdown
- ✅ Metrics history (JSONL time-series) · CPU/alloc profiling guide · load tester ([`tools/riftbench`](tools/riftbench))
- ⬜ Connection rate limiting
- ⬜ Prometheus / OpenTelemetry · JSON logging · admin API · graceful (zero-downtime) restart

> ⚠️ Resource-pack serving is implemented but **not yet verified in-game** (off by default). Linux performance items are deferred until real-server measurement.

## License

[MIT](LICENSE).

`vendor/rift-raknet/` is a patched fork of [rust-raknet](https://github.com/b23r0/rust-raknet) by b23r0, also under the MIT license (see `vendor/rift-raknet/LICENSE`).
