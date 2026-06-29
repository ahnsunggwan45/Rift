# Rift Deployment Guide (Linux)

## Choosing a Binary
- **`rift-musl`** — fully static (static-pie), runs on any x86-64 Linux regardless of glibc version. **Recommended.**
- `rift.stripped` — dynamically linked against glibc (Ubuntu 22.04+ / glibc 2.35+ only).

## 1. Upload
Upload to the server: the binary + `config.toml` + (if serving resource packs) the `packs/` directory.
```bash
scp dist-linux/rift-musl config.toml user@SERVER:/opt/rift/
# If using resource packs: scp -r packs user@SERVER:/opt/rift/
```

## 2. Review config.toml
- `[listener] host = "0.0.0.0:19132"`
- Set `[listener] default_server` and `[servers]` addresses to match your environment.
- `[metrics] web_addr = "0.0.0.0:8080"` — remote monitoring. **Always place behind a firewall** (exposes player names and IPs).
- `[resource_packs] enabled = true` — enable only after validating resource pack serving in-game.

## 3-A. Running via systemd (Recommended — auto-restart and boot start)
Edit the paths in `rift.service`, then install:
```bash
sudo cp rift.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rift
journalctl -u rift -f          # Stream logs
sudo systemctl restart rift    # Restart the service
```
Note: in systemd mode there is no stdin, so **console commands (transfer/kick/stop) are not available** — manage the proxy via the web dashboard and `systemctl`.

## 3-B. Running via screen/tmux (for console command access)
```bash
chmod +x rift-musl
screen -S proxy ./rift-musl config.toml
# Console commands: info / list / transfer <name|index> <server> / kick / stop
# Detach: Ctrl+A D    Re-attach: screen -r proxy
```

## Prerequisites (required for channel transfers to work)
- **Deploy the Optimizer plugin on every downstream server** (deterministic crc32 entity IDs). If any downstream is missing the plugin, entity state (player position/appearance) will break on transfer to that server.
- All downstream servers must have `enable-encryption: false`.

## Monitoring
- Dashboard: `http://SERVER_IP:8080`
- JSON endpoints: `/metrics` (throughput and player count), `/players` (player names, IPs, and current server)

## Troubleshooting
- `GLIBC_2.xx not found` — the glibc-linked binary is too new for this server. **Use `rift-musl` (static binary).**
- Entity state (player position/appearance) breaks after a transfer — the Optimizer plugin is not deployed on that downstream server. Deploy it.
- Zero chunks loaded / client hangs — check that `enable-encryption` on the downstream server is `false`.
