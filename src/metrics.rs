//! Lightweight metrics + per-server player count aggregation.
//!
//! Gate for measurement-driven hardening: identify hot spots here before applying
//! bolt-on optimizations (buffer pools, sharding, etc.).
//! Hot-path cost is a single AtomicU64 relaxed increment per packet (nanoseconds) — negligible.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Forward-latency histogram bucket upper bounds (μs); a final overflow bucket catches anything larger.
const FWD_BUCKETS: [u64; 8] = [10, 25, 50, 100, 250, 500, 1000, 2500];

/// Approximate p50/p95/p99 (μs) from the forward-latency histogram: the upper bound of the bucket where
/// the cumulative count crosses each quantile (the overflow bucket reports the last bound as a floor).
fn forward_percentiles(hist: &[u64]) -> (u64, u64, u64) {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return (0, 0, 0);
    }
    let q = |num: u64| -> u64 {
        let target = total * num / 100;
        let mut cum = 0u64;
        for (i, &c) in hist.iter().enumerate() {
            cum += c;
            if cum >= target {
                return *FWD_BUCKETS.get(i).unwrap_or_else(|| FWD_BUCKETS.last().unwrap());
            }
        }
        *FWD_BUCKETS.last().unwrap()
    };
    (q(50), q(95), q(99))
}

pub struct Metrics {
    /// Process start time (used to calculate uptime).
    start_time: Instant,
    connections_total: AtomicU64,
    active: AtomicUsize,
    peak_active: AtomicUsize,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    msgs_up: AtomicU64,
    msgs_down: AtomicU64,
    transfers: AtomicU64,
    transfers_failed: AtomicU64,
    /// Cumulative downstream forward processing time (ns) + count → average forward latency. Hot-path cost: two `Instant` calls (~tens of ns).
    fwd_ns_total: AtomicU64,
    fwd_count: AtomicU64,
    /// Forward-latency histogram (bucketed μs) → p50/p95/p99 in the snapshot. Captures the distribution
    /// the cumulative average hides (e.g. occasional chunk-decompress spikes). Hot-path cost: one atomic add.
    fwd_hist: [AtomicU64; FWD_BUCKETS.len() + 1],
    /// Down-direction routing tiers (the independent classification layer): how many down game packets
    /// were forwarded as raw bytes (Tier 1 pass-through — no decompress/decode/alloc) vs required
    /// game-level inspection (Tier 2/3 decode). The ratio proves the steady-state stream stays cheap.
    down_pass: AtomicU64,
    down_inspect: AtomicU64,
    /// Server name → current player count (driven by plist/monitoring).
    per_server: RwLock<HashMap<String, usize>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            connections_total: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            peak_active: AtomicUsize::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            msgs_up: AtomicU64::new(0),
            msgs_down: AtomicU64::new(0),
            transfers: AtomicU64::new(0),
            transfers_failed: AtomicU64::new(0),
            fwd_ns_total: AtomicU64::new(0),
            fwd_count: AtomicU64::new(0),
            fwd_hist: Default::default(),
            down_pass: AtomicU64::new(0),
            down_inspect: AtomicU64::new(0),
            per_server: RwLock::new(HashMap::new()),
        }
    }
}

/// Metrics snapshot for web monitoring / console (JSON-serializable).
#[derive(serde::Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub active: usize,
    pub peak_active: usize,
    pub connections_total: u64,
    pub transfers: u64,
    pub transfers_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub msgs_up: u64,
    pub msgs_down: u64,
    /// Average packet size in bytes = total bytes / total messages.
    pub avg_packet_size_bytes: u64,
    /// Average downstream forward latency in μs. Typically a few to tens of μs; spikes signal downstream or contention issues.
    pub avg_forward_us: u64,
    /// Forward-latency distribution (μs, bucket-approximate upper bound). p99 surfaces spikes the average hides.
    pub forward_p50_us: u64,
    pub forward_p95_us: u64,
    pub forward_p99_us: u64,
    /// Down-direction classification tiers: pass-through (raw forward, no decode) vs inspected (decoded).
    /// In lazy-decode mode the steady-state stream should be almost entirely pass-through.
    pub down_passthrough: u64,
    pub down_inspect: u64,
    /// Cumulative allocation count/bytes. Non-zero only in profiling builds (`--features profiling`); zero otherwise.
    pub alloc_count: u64,
    pub alloc_bytes: u64,
    pub per_server: HashMap<String, usize>,
}

impl Metrics {
    pub fn on_connect(&self, server: &str) {
        self.connections_total.fetch_add(1, Relaxed);
        let now_active = self.active.fetch_add(1, Relaxed) + 1;
        self.peak_active.fetch_max(now_active, Relaxed); // peak concurrent connections high-water mark
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

    /// Records the down-direction routing decision from the classification layer: `inspected = false`
    /// means Tier 1 pass-through (raw forward, no decode); `true` means Tier 2/3 (decompress + decode).
    /// One relaxed atomic add — the classification itself is branch-only.
    #[inline]
    pub fn on_down_route(&self, inspected: bool) {
        if inspected {
            self.down_inspect.fetch_add(1, Relaxed);
        } else {
            self.down_pass.fetch_add(1, Relaxed);
        }
    }

    /// Records the processing time for one downstream forward (recv → client send complete) — used for average forward latency.
    #[inline]
    pub fn on_forward(&self, elapsed: std::time::Duration) {
        let ns = elapsed.as_nanos() as u64;
        self.fwd_ns_total.fetch_add(ns, Relaxed);
        self.fwd_count.fetch_add(1, Relaxed);
        let us = ns / 1000;
        let idx = FWD_BUCKETS.iter().position(|&b| us < b).unwrap_or(FWD_BUCKETS.len());
        self.fwd_hist[idx].fetch_add(1, Relaxed);
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

    /// Snapshot of current player counts per server (for plist).
    pub fn per_server_snapshot(&self) -> HashMap<String, usize> {
        self.per_server.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// Full metrics snapshot (for web /metrics and console info).
    pub fn snapshot(&self) -> MetricsSnapshot {
        let bytes_up = self.bytes_up.load(Relaxed);
        let bytes_down = self.bytes_down.load(Relaxed);
        let msgs_up = self.msgs_up.load(Relaxed);
        let msgs_down = self.msgs_down.load(Relaxed);
        let total_msgs = msgs_up + msgs_down;
        let avg_packet_size_bytes = if total_msgs > 0 {
            (bytes_up + bytes_down) / total_msgs
        } else {
            0
        };
        let fwd_count = self.fwd_count.load(Relaxed);
        let avg_forward_us = if fwd_count > 0 {
            self.fwd_ns_total.load(Relaxed) / fwd_count / 1000
        } else {
            0
        };
        let mut hist = [0u64; FWD_BUCKETS.len() + 1];
        for (i, h) in hist.iter_mut().enumerate() {
            *h = self.fwd_hist[i].load(Relaxed);
        }
        let (forward_p50_us, forward_p95_us, forward_p99_us) = forward_percentiles(&hist);
        // Allocation counters are meaningful only in profiling builds; zero at runtime (counting allocator not installed).
        #[cfg(feature = "profiling")]
        let (alloc_count, alloc_bytes) = (
            crate::profiling::ALLOC_COUNT.load(Relaxed),
            crate::profiling::ALLOC_BYTES.load(Relaxed),
        );
        #[cfg(not(feature = "profiling"))]
        let (alloc_count, alloc_bytes) = (0u64, 0u64);

        MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            active: self.active.load(Relaxed),
            peak_active: self.peak_active.load(Relaxed),
            connections_total: self.connections_total.load(Relaxed),
            transfers: self.transfers.load(Relaxed),
            transfers_failed: self.transfers_failed.load(Relaxed),
            bytes_up,
            bytes_down,
            msgs_up,
            msgs_down,
            avg_packet_size_bytes,
            avg_forward_us,
            forward_p50_us,
            forward_p95_us,
            forward_p99_us,
            down_passthrough: self.down_pass.load(Relaxed),
            down_inspect: self.down_inspect.load(Relaxed),
            alloc_count,
            alloc_bytes,
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

    /// Spawns the periodic metrics logging task. Does nothing if `interval_secs` is 0.
    pub fn spawn_logger(self: &Arc<Self>, interval_secs: u64) {
        if interval_secs == 0 {
            return;
        }
        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
            tick.tick().await; // consume the immediate first tick
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

    /// Spawns the performance data collection task: appends one JSONL line per metrics snapshot every `interval` seconds.
    /// Each line includes `ts_ms` (epoch ms) — retrieve the file later for time-series analysis to identify hot paths.
    pub fn spawn_history(self: &Arc<Self>, path: String, interval_secs: u64) {
        let interval = if interval_secs == 0 { 10 } else { interval_secs };
        let m = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(interval));
            loop {
                tick.tick().await;
                let ts_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let mut v = serde_json::to_value(m.snapshot()).unwrap_or_default();
                if let Some(o) = v.as_object_mut() {
                    o.insert("ts_ms".to_string(), ts_ms.into());
                }
                if let Ok(line) = serde_json::to_string(&v) {
                    use std::io::Write;
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = writeln!(f, "{line}");
                    }
                }
            }
        });
    }
}
