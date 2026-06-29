#!/usr/bin/env bash
# Rift VPS one-click installer.
#   Usage: place this file, a binary (rift-musl recommended), and config.toml in the same directory,
#          then from that directory run:  sudo bash setup.sh
# What it does: installs to /opt/rift → registers a systemd service → opens firewall ports (ufw) → starts the service.
set -euo pipefail

INSTALL_DIR=/opt/rift
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== Rift installer starting =="

if [ "$(id -u)" -ne 0 ]; then
  echo "!! Must be run as root:  sudo bash setup.sh"; exit 1
fi

# 1) Select binary (musl static preferred → glibc fallback)
BIN=""
for cand in rift-musl rift.stripped rift; do
  if [ -f "$SRC_DIR/$cand" ]; then BIN="$cand"; break; fi
done
if [ -z "$BIN" ]; then
  echo "!! No binary found. Place rift-musl (or rift.stripped) in this directory."; exit 1
fi
if [ ! -f "$SRC_DIR/config.toml" ]; then
  echo "!! config.toml not found in this directory. Place it here before running."; exit 1
fi
echo "-> Binary: $BIN"

# 2) Copy to install directory (skip if already in place)
mkdir -p "$INSTALL_DIR"
if ! [ "$SRC_DIR/$BIN" -ef "$INSTALL_DIR/rift" ]; then
  cp -f "$SRC_DIR/$BIN" "$INSTALL_DIR/rift"
fi
if ! [ "$SRC_DIR/config.toml" -ef "$INSTALL_DIR/config.toml" ]; then
  cp -f "$SRC_DIR/config.toml" "$INSTALL_DIR/config.toml"
fi
if [ -d "$SRC_DIR/packs" ] && ! [ "$SRC_DIR/packs" -ef "$INSTALL_DIR/packs" ]; then
  cp -rf "$SRC_DIR/packs" "$INSTALL_DIR/"
  echo "-> packs/ copied (resource pack serving)"
fi
chmod +x "$INSTALL_DIR/rift"
echo "-> Installed to $INSTALL_DIR"

# 3) Write systemd unit
cat > /etc/systemd/system/rift.service <<EOF
[Unit]
Description=Rift (Bedrock proxy)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/rift $INSTALL_DIR/config.toml
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
Environment=RUST_LOG=rift=info
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
echo "-> systemd unit registered (/etc/systemd/system/rift.service)"

# 4) Firewall (ufw only, if present) — ports are extracted from config.toml automatically
CFG="$INSTALL_DIR/config.toml"
LISTEN_PORT=$(grep -E '^[[:space:]]*host[[:space:]]*=' "$CFG" 2>/dev/null | grep -oE '[0-9]+' | tail -1 || true)
LISTEN_PORT=${LISTEN_PORT:-19132}
WEB_PORT=$(grep -E '^[[:space:]]*web_addr[[:space:]]*=' "$CFG" 2>/dev/null | grep -oE '[0-9]+' | tail -1 || true)
if command -v ufw >/dev/null 2>&1; then
  ufw allow ${LISTEN_PORT}/udp >/dev/null 2>&1 || true
  [ -n "$WEB_PORT" ] && { ufw allow ${WEB_PORT}/tcp >/dev/null 2>&1 || true; }
  echo "-> ufw opened: ${LISTEN_PORT}/udp (game)${WEB_PORT:+, ${WEB_PORT}/tcp (monitoring)}"
else
  echo "-> ufw not found — manually open: UDP ${LISTEN_PORT}${WEB_PORT:+, TCP ${WEB_PORT}}"
fi

# 5) Start
systemctl daemon-reload
systemctl enable rift >/dev/null 2>&1 || true
systemctl restart rift
sleep 1

echo
echo "== Installation complete =="
systemctl --no-pager status rift | head -n 6 || true
echo
echo "Quick reference:"
echo "  Logs         :  journalctl -u rift -f"
echo "  Monitoring   :  http://<this VPS IP>:${WEB_PORT:-8080}"
echo "  Game connect :  <this VPS IP>:${LISTEN_PORT}"
echo
echo "!! Important checklist:"
echo "  1) Open UDP ${LISTEN_PORT} inbound in your cloud firewall / security group as well (ufw alone may not be enough)"
echo "  2) All downstream PMMP servers: deploy the Optimizer plugin + set enable-encryption: false"
echo "     (without this, entity state will break on channel transfer)"
