//! 경량 메트릭 + 서버별 인원 집계.
//!
//! "측정 기반 하드닝" 게이트: bolt-on 최적화(버퍼풀/샤딩 등) 전에 먼저 여기서 핫스팟을 본다.
//! 핫패스 비용은 패킷당 AtomicU64 relaxed 가산 1회뿐(수 ns) — 무시 가능.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub struct Metrics {
    /// 프로세스 시작 시각 (uptime 계산용).
    start_time: Instant,
    connections_total: AtomicU64,
    active: AtomicUsize,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    msgs_up: AtomicU64,
    msgs_down: AtomicU64,
    transfers: AtomicU64,
    transfers_failed: AtomicU64,
    /// 서버명 → 현재 인원 (plist/모니터링 기반).
    per_server: RwLock<HashMap<String, usize>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            connections_total: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            msgs_up: AtomicU64::new(0),
            msgs_down: AtomicU64::new(0),
            transfers: AtomicU64::new(0),
            transfers_failed: AtomicU64::new(0),
            per_server: RwLock::new(HashMap::new()),
        }
    }
}

/// 웹 모니터링/콘솔용 메트릭 스냅샷 (JSON 직렬화).
#[derive(serde::Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub active: usize,
    pub connections_total: u64,
    pub transfers: u64,
    pub transfers_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub msgs_up: u64,
    pub msgs_down: u64,
    pub per_server: HashMap<String, usize>,
}

impl Metrics {
    pub fn on_connect(&self, server: &str) {
        self.connections_total.fetch_add(1, Relaxed);
        self.active.fetch_add(1, Relaxed);
        self.inc_server(server);
    }

    pub fn on_disconnect(&self, server: &str) {
        self.active.fetch_sub(1, Relaxed);
        self.dec_server(server);
    }

    #[inline]
    pub fn on_bytes_up(&self, n: usize) {
        self.bytes_up.fetch_add(n as u64, Relaxed);
        self.msgs_up.fetch_add(1, Relaxed);
    }

    #[inline]
    pub fn on_bytes_down(&self, n: usize) {
        self.bytes_down.fetch_add(n as u64, Relaxed);
        self.msgs_down.fetch_add(1, Relaxed);
    }

    pub fn on_transfer(&self, from: &str, to: &str) {
        self.transfers.fetch_add(1, Relaxed);
        self.dec_server(from);
        self.inc_server(to);
    }

    pub fn on_transfer_failed(&self) {
        self.transfers_failed.fetch_add(1, Relaxed);
    }

    pub fn active(&self) -> usize {
        self.active.load(Relaxed)
    }

    /// 서버별 현재 인원 스냅샷 (plist 용).
    pub fn per_server_snapshot(&self) -> HashMap<String, usize> {
        self.per_server.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// 전체 메트릭 스냅샷 (웹 /metrics, 콘솔 info 용).
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            active: self.active.load(Relaxed),
            connections_total: self.connections_total.load(Relaxed),
            transfers: self.transfers.load(Relaxed),
            transfers_failed: self.transfers_failed.load(Relaxed),
            bytes_up: self.bytes_up.load(Relaxed),
            bytes_down: self.bytes_down.load(Relaxed),
            msgs_up: self.msgs_up.load(Relaxed),
            msgs_down: self.msgs_down.load(Relaxed),
            per_server: self.per_server_snapshot(),
        }
    }

    fn inc_server(&self, s: &str) {
        if let Ok(mut m) = self.per_server.write() {
            *m.entry(s.to_string()).or_insert(0) += 1;
        }
    }

    fn dec_server(&self, s: &str) {
        if let Ok(mut m) = self.per_server.write() {
            if let Some(c) = m.get_mut(s) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    m.remove(s);
                }
            }
        }
    }

    /// 주기 메트릭 로깅 태스크. interval_secs=0 이면 시작 안 함.
    pub fn spawn_logger(self: &Arc<Self>, interval_secs: u64) {
        if interval_secs == 0 {
            return;
        }
        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
            tick.tick().await; // 즉시 발화 소비
            let (mut last_up, mut last_down) = (0u64, 0u64);
            let (mut last_mu, mut last_md) = (0u64, 0u64);
            loop {
                tick.tick().await;
                let up = m.bytes_up.load(Relaxed);
                let down = m.bytes_down.load(Relaxed);
                let mu = m.msgs_up.load(Relaxed);
                let md = m.msgs_down.load(Relaxed);
                let servers = m.per_server_snapshot();
                tracing::info!(
                    active = m.active(),
                    total = m.connections_total.load(Relaxed),
                    transfers = m.transfers.load(Relaxed),
                    transfers_failed = m.transfers_failed.load(Relaxed),
                    up_kib_s = (up - last_up) / 1024 / interval_secs,
                    down_kib_s = (down - last_down) / 1024 / interval_secs,
                    msgs_up_s = (mu - last_mu) / interval_secs,
                    msgs_down_s = (md - last_md) / interval_secs,
                    ?servers,
                    "metrics"
                );
                last_up = up;
                last_down = down;
                last_mu = mu;
                last_md = md;
            }
        });
    }
}
