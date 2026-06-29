#!/usr/bin/env bash
# Rift 실행 스크립트 (PMMP/WDPE 스타일).
#   screen -S proxy ./start.sh   로 띄우면 콘솔(info/list/transfer/kick/stop)이 화면에 보인다.
#   화면 빠져나오기: Ctrl+A 뗀 뒤 D    /    다시 들어가기: screen -r proxy
#
# 동작: 프록시를 포그라운드로 실행(=콘솔 입력 가능). 크래시(비정상 종료)면 자동 재시작,
#       콘솔 stop(정상 종료)이면 깔끔히 종료.
cd "$(dirname "$0")"

# 바이너리 자동 선택 (설치본 → musl 정적 → glibc 순)
BIN=""
for c in rift rift-musl rift.stripped; do
  if [ -f "./$c" ]; then BIN="./$c"; break; fi
done
if [ -z "$BIN" ]; then
  echo "!! 바이너리를 못 찾음 (rift / rift-musl / .stripped 중 하나가 같은 폴더에 있어야 함)"
  exit 1
fi
chmod +x "$BIN" 2>/dev/null || true

if [ ! -f ./config.toml ]; then
  echo "!! config.toml 이 같은 폴더에 없습니다."
  exit 1
fi

export RUST_LOG="${RUST_LOG:-rift=info}"

echo "== Rift 시작 ($BIN) =="
echo "   콘솔 명령: info | list | transfer <이름|번호> <서버> | kick <이름|번호> | stop"
echo "   화면 분리: Ctrl+A 뗀 뒤 D    재접속: screen -r proxy"
echo

while true; do
  "$BIN" config.toml
  CODE=$?
  if [ "$CODE" -eq 0 ]; then
    echo "[start.sh] 정상 종료(stop). 끝."
    break
  fi
  echo "[start.sh] 비정상 종료(code=$CODE) — 3초 후 재시작 (완전히 끄려면 Ctrl+C 한 번 더)"
  sleep 3
done
