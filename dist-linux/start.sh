#!/usr/bin/env bash
# Rift launcher script (PMMP/WDPE style).
#   Run with:  screen -S proxy ./start.sh   to keep console commands (info/list/transfer/kick/stop) accessible.
#   Detach: Ctrl+A then D    Re-attach: screen -r proxy
#
# Behavior: runs the proxy in the foreground (console input enabled). Restarts automatically on crash,
#           exits cleanly when stopped via the console 'stop' command (clean exit code 0).
cd "$(dirname "$0")"

# Auto-select binary (installed copy → musl static → glibc)
BIN=""
for c in rift rift-musl rift.stripped; do
  if [ -f "./$c" ]; then BIN="./$c"; break; fi
done
if [ -z "$BIN" ]; then
  echo "!! Binary not found (rift / rift-musl / rift.stripped must be in the same directory)"
  exit 1
fi
chmod +x "$BIN" 2>/dev/null || true

if [ ! -f ./config.toml ]; then
  echo "!! config.toml not found in the current directory."
  exit 1
fi

export RUST_LOG="${RUST_LOG:-rift=info}"

echo "== Rift starting ($BIN) =="
echo "   Console commands: info | list | transfer <name|index> <server> | kick <name|index> | stop"
echo "   Detach: Ctrl+A then D    Re-attach: screen -r proxy"
echo

while true; do
  "$BIN" config.toml
  CODE=$?
  if [ "$CODE" -eq 0 ]; then
    echo "[start.sh] Clean shutdown (stop). Exiting."
    break
  fi
  echo "[start.sh] Unexpected exit (code=$CODE) — restarting in 3 seconds (press Ctrl+C to abort)"
  sleep 3
done
