# Rift 배포 가이드 (Linux)

## 바이너리 선택
- **`rift-musl`** — 완전 정적(static-pie), 어떤 리눅스 x86-64 에서든 실행. glibc 버전 무관. **권장.**
- `rift.stripped` — glibc 동적 링크 (Ubuntu 22.04+ / glibc 2.35+ 전용).

## 1. 업로드
서버에 올릴 것: 바이너리 + `config.toml` + (RP 서빙 시) `packs/` 폴더.
```bash
scp dist-linux/rift-musl config.toml user@SERVER:/opt/rift/
# RP 쓰면: scp -r packs user@SERVER:/opt/rift/
```

## 2. config.toml 점검
- `[listener] host = "0.0.0.0:19132"`
- `[listener] default_server` + `[servers]` 주소를 서버 환경에 맞게
- `[metrics] web_addr = "0.0.0.0:8080"` — 원격 모니터링. **반드시 방화벽으로 보호**(접속자 이름/IP 노출).
- `[resource_packs] enabled = true` — RP 서빙 인게임 검증할 때

## 3-A. systemd 로 운영 (권장 — 자동재시작·부팅시작)
`rift.service` 를 경로 수정 후 설치:
```bash
sudo cp rift.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rift
journalctl -u rift -f          # 로그 보기
sudo systemctl restart rift    # 재시작
```
※ systemd 모드는 stdin 이 없어 **콘솔 명령(transfer/kick/stop) 입력 불가** → 웹 대시보드 + `systemctl` 로 관리.

## 3-B. screen/tmux 로 운영 (콘솔 명령 쓰려면)
```bash
chmod +x rift-musl
screen -S proxy ./rift-musl config.toml
# 콘솔에 입력: info / list / transfer <이름|번호> <서버> / kick / stop
# 분리: Ctrl+A D,  재접속: screen -r proxy
```

## 전제조건 (채널이동이 동작하려면 — 중요)
- **모든 다운스트림 서버에 Optimizer 플러그인 배포** (crc32 결정론 엔티티 ID). 일부만 배포되면 그 서버 전환 시 자기 엔티티(워프) 깨짐.
- 다운스트림 전부 `enable-encryption: false`.

## 모니터링
- 대시보드: `http://SERVER_IP:8080`
- JSON: `/metrics` (처리량·인원), `/players` (접속자 이름/IP/서버)

## 트러블슈팅
- `GLIBC_2.xx not found` → glibc 동적 바이너리가 구버전 서버에서 실패. **`rift-musl`(정적) 사용.**
- 전환 시 자기 캐릭터(워프) 깨짐 → 그 다운스트림에 Optimizer 미배포. 배포 확인.
- 0 청크/먹통 → 다운스트림 `enable-encryption` 가 true 인지 확인(false 여야 함).
