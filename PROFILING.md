# Rift 프로파일링 (성능 핫패스 분석)

메트릭(`/metrics`, `metrics.jsonl`)은 *언제 / 무엇이* 느린지 보여준다.
*어느 코드가* 핫한지는 CPU 프로파일이 필요하고, 그건 **심볼 포함 빌드 + Linux `perf`** 로 뜬다.

수집할 3종:
1. `metrics.jsonl` — 시계열 (상황별 패턴: 인원·throughput·forward latency 변화)
2. `perf-report.txt` — 부하 중 CPU 핫 함수
3. (선택) `--features profiling` 로 잠깐 돌린 뒤의 `alloc_count`/`alloc_bytes` — 핫패스 할당 검증

이 셋을 받으면 *"X 상황에서 Y 함수가 핫 + Z 할당"* 을 짚어 정확한 최적화(sendmmsg / 워커샤딩 / 풀링 등)를 결정한다.

---

## 1. 심볼 포함 빌드 (`rift-prof`)

릴리스 바이너리는 `strip` 돼서 `perf` 가 함수명을 못 푼다. 프로파일링용은 `profiling` 프로파일로 (최적화는 릴리스와 동일, 심볼만 유지):

```bash
cargo build --profile profiling     # → target/profiling/rift
```

이미 빌드된 **`dist-linux/rift-prof`** (glibc + x86-64-v2, 심볼 포함) 를 그대로 써도 된다.

## 2. 프로파일링 세션 (실서버, 부하 중)

평소엔 `rift`(stripped)로 운영하고, 프로파일링할 때만 `rift-prof` 로 잠깐 교체한다:

```bash
# 운영 rift 중지 후
./rift-prof config.toml
```

다른 셸에서, 부하가 있는 동안 30초 샘플링:

```bash
# perf 설치(1회): sudo apt install -y linux-tools-$(uname -r)   (또는 linux-perf)
sudo sysctl kernel.perf_event_paranoid=1      # 샘플링 권한 (일부 컨테이너 VPS는 불가)

PID=$(pgrep -n rift-prof)
sudo perf record -F 99 -g -p "$PID" -- sleep 30
sudo perf report --stdio > perf-report.txt    # 핫 함수 목록 — 이거면 충분
```

`perf-report.txt` 를 보내면 핫 함수를 짚어 최적화한다.
시각 플레임그래프를 원하면: `sudo perf script > perf.script` 후 [FlameGraph](https://github.com/brendangregg/FlameGraph) 도구로 svg 변환.

## 3. 할당(alloc) 데이터

`--features profiling` 빌드는 카운팅 할당자로 `/metrics`·`metrics.jsonl` 의 `alloc_count`/`alloc_bytes` 를 채운다(핫패스 할당이 정말 0인지 검증). 카운팅 할당자는 약간 느리니 **측정 윈도우에만** 쓴다:

```bash
cargo build --release --features profiling
```

> 주의: perf 플레임그래프용 빌드(`--profile profiling`)와 alloc 측정 빌드(`--features profiling`)는 **별개다.**
> 플레임그래프는 카운팅 할당자가 없는 `--profile profiling`(실제 성능 반영)으로, alloc 수치는 `--features profiling` 으로.
