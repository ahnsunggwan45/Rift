# Rift

A fast, seamless reverse proxy for **Minecraft: Bedrock Edition**, written in Rust.

Rift sits in front of your [PocketMine-MP](https://github.com/pmmp/PocketMine-MP) servers and moves players between them **without a reconnect** — no "Disconnected" screen, no re-login, no resource-pack reload. It's a lightweight, high-performance alternative to WaterdogPE.

> **Status:** actively developed. Core proxying and seamless transfer are verified in-game. See [Status](#status) for what's battle-tested vs. experimental.

## Features

- **Seamless server switching** — players move between downstream servers with only a brief loading screen (dimension-flip technique, inspired by [Spectrum](https://github.com/cooldogedev/spectrum)). Game mode, game rules, boss bars and scoreboards are carried over.
- **Transparent byte-stream proxy** — game packets are forwarded as raw bytes; only the handful Rift needs to act on are decoded. Low CPU, low latency.
- **Resource-pack serving** — optionally serve one pack set from the proxy to every downstream server (Waterdog-style replace).
- **Built-in web dashboard** — live player counts, throughput, transfers and a per-server breakdown.
- **Console** — `info` / `list` / `transfer` / `kick` / `stop`, just like a PMMP console.
- **Production-minded** — graceful shutdown, panic-free packet parsing, bounded fragment reassembly (DoS-resistant), reliable-packet de-duplication, multi-core Tokio runtime.
- Configurable MTU, Vibrant Visuals override, metrics.

## How it works

Rift terminates RakNet itself: clients connect to Rift, and Rift opens its own RakNet connection to each downstream server. Game packets are shuttled as opaque bytes — only login, transfer, resource-pack and a few spawn-related packets are decoded.

**Seamless transfer** (triggered by a downstream `TransferPacket`, or the console `transfer` command):

1. Rift connects to the target server and drives the handshake to full spawn, buffering the spawn stream.
2. The client is flipped to a dummy dimension (clearing the old world) and filled with empty chunks.
3. The downstream connection is swapped; `SetLocalPlayerAsInitialized` triggers the real spawn.
4. The client returns to the overworld and the buffered spawn stream is replayed.

Entity IDs are **not** rewritten. Instead, every server assigns the same player the same runtime ID — `crc32(XUID) & 0x7FFFFFFFFFFFFFFF` — so the client's view stays consistent across servers (see [Requirements](#requirements)).

## Requirements

Each **downstream PMMP server** must:

**1. Disable encryption** (`pocketmine.yml`):
```yaml
network:
  enable-encryption: false
```
Rift forwards the client's login token verbatim, so the XUID is preserved.

**2. Assign deterministic entity IDs.** In your custom `Player` class (a tiny plugin works), make the runtime/entity ID identical on every server:
```php
protected function initEntity(CompoundTag $nbt) : void {
    parent::initEntity($nbt);
    $xuid = $this->getXuid();
    $key  = $xuid !== "" ? $xuid : $this->getName();
    $this->id = crc32($key) & 0x7FFFFFFFFFFFFFFF;
}
```
> Deploy this to **every** downstream server. Otherwise a transferred player's own entity (and warps) will break.

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
- `GET /metrics` — JSON: counts, throughput, transfers, per-server
- `GET /players` — JSON: id, name, ip, server

> `/players` exposes player names and IPs — keep the port behind a firewall if it's reachable publicly.

## Project layout

```
src/                  proxy core — intercept, transfer, packets, web, console, registry, ...
vendor/rift-raknet/   vendored, patched fork of rust-raknet (Bedrock RakNet)
dist-linux/           deploy assets — start.sh, setup.sh, rift.service, DEPLOY.md
```

## Compatibility

Rift targets the Bedrock protocol used by current PocketMine-MP builds. The specific packet IDs Rift decodes live in `src/` and may need updating when Bedrock bumps its protocol.

## Status

- ✅ Connect + seamless transfer (chunks, players, game mode, game rules, state teardown) — verified in-game.
- ✅ Zero-copy data path, panic-free parsing, fragment + reliable-packet hardening — unit & integration tested.
- ⚠️ Resource-pack serving — implemented, not yet verified in-game (disabled by default).
- 🔭 Roadmap: deeper Linux performance (sendmmsg/recvmmsg, io_uring, NUMA), packet pooling — pending real-server measurement.

## License

[MIT](LICENSE).

`vendor/rift-raknet/` is a patched fork of [rust-raknet](https://github.com/b23r0/rust-raknet) by b23r0, also under the MIT license (see `vendor/rift-raknet/LICENSE`).
