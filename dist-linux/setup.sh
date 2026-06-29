#!/usr/bin/env bash
# Rift VPS 원클릭 설치.
#   사용법: 이 파일 + 바이너리(rift-musl 권장) + config.toml 을 한 폴더에 올리고
#           그 폴더에서  sudo bash setup.sh
# 하는 일: /opt/rift 에 설치 → systemd 서비스 등록 → 방화벽(ufw) 개방 → 자동 시작.
set -euo pipefail

INSTALL_DIR=/opt/rift
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== Rift 설치 시작 =="

if [ "$(id -u)" -ne 0 ]; then
  echo "!! root 로 실행하세요:  sudo bash setup.sh"; exit 1
fi

# 1) 바이너리 선택 (musl 정적 우선 → glibc 순)
BIN=""
for cand in rift-musl rift.stripped rift; do
  if [ -f "$SRC_DIR/$cand" ]; then BIN="$cand"; break; fi
done
if [ -z "$BIN" ]; then
  echo "!! 바이너리를 못 찾음. rift-musl (또는 .stripped) 를 이 폴더에 함께 올리세요."; exit 1
fi
if [ ! -f "$SRC_DIR/config.toml" ]; then
  echo "!! config.toml 이 이 폴더에 없습니다. 함께 올리세요."; exit 1
fi
echo "-> 바이너리: $BIN"

# 2) 설치 디렉터리로 복사 (이미 같은 위치면 건너뜀)
mkdir -p "$INSTALL_DIR"
if ! [ "$SRC_DIR/$BIN" -ef "$INSTALL_DIR/rift" ]; then
  cp -f "$SRC_DIR/$BIN" "$INSTALL_DIR/rift"
fi
if ! [ "$SRC_DIR/config.toml" -ef "$INSTALL_DIR/config.toml" ]; then
  cp -f "$SRC_DIR/config.toml" "$INSTALL_DIR/config.toml"
fi
if [ -d "$SRC_DIR/packs" ] && ! [ "$SRC_DIR/packs" -ef "$INSTALL_DIR/packs" ]; then
  cp -rf "$SRC_DIR/packs" "$INSTALL_DIR/"
  echo "-> packs/ 복사됨 (리소스팩 서빙)"
fi
chmod +x "$INSTALL_DIR/rift"
echo "-> $INSTALL_DIR 에 설치 완료"

# 3) systemd 유닛 생성
cat > /etc/systemd/system/rift.service <<EOF
[Unit]
Description=Rift (Bedrock 프록시)
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
echo "-> systemd 유닛 등록 (/etc/systemd/system/rift.service)"

# 4) 방화벽 (ufw 있을 때만) — 포트는 config.toml 에서 자동 추출
CFG="$INSTALL_DIR/config.toml"
LISTEN_PORT=$(grep -E '^[[:space:]]*host[[:space:]]*=' "$CFG" 2>/dev/null | grep -oE '[0-9]+' | tail -1 || true)
LISTEN_PORT=${LISTEN_PORT:-19132}
WEB_PORT=$(grep -E '^[[:space:]]*web_addr[[:space:]]*=' "$CFG" 2>/dev/null | grep -oE '[0-9]+' | tail -1 || true)
if command -v ufw >/dev/null 2>&1; then
  ufw allow ${LISTEN_PORT}/udp >/dev/null 2>&1 || true
  [ -n "$WEB_PORT" ] && { ufw allow ${WEB_PORT}/tcp >/dev/null 2>&1 || true; }
  echo "-> ufw 개방: ${LISTEN_PORT}/udp (접속)${WEB_PORT:+, ${WEB_PORT}/tcp (모니터링)}"
else
  echo "-> ufw 없음 → 방화벽 수동 확인: UDP ${LISTEN_PORT}${WEB_PORT:+, TCP ${WEB_PORT}}"
fi

# 5) 시작
systemctl daemon-reload
systemctl enable rift >/dev/null 2>&1 || true
systemctl restart rift
sleep 1

echo
echo "== 설치 완료 =="
systemctl --no-pager status rift | head -n 6 || true
echo
echo "확인:"
echo "  로그        :  journalctl -u rift -f"
echo "  모니터링     :  http://<이 VPS의 IP>:${WEB_PORT:-8080}"
echo "  게임 접속    :  <이 VPS의 IP>:${LISTEN_PORT}"
echo
echo "!! 반드시 확인:"
echo "  1) 클라우드 방화벽/보안그룹에서도 UDP ${LISTEN_PORT} 인바운드 개방 (ufw만으론 부족할 수 있음)"
echo "  2) 모든 다운스트림 PMMP 서버: Optimizer 플러그인 배포 + enable-encryption: false"
echo "     (안 하면 채널이동 시 워프/자기 캐릭터가 깨짐)"
