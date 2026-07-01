//! Session registry — the single source of truth for the console/web to query and manipulate
//! active sessions (transfer, kick).
//!
//! Each relay task registers itself on start via `register` and unregisters on exit via `remove`.
//! The console and web layer access sessions through `snapshot` (read) and `find_control`
//! (manipulate). Control commands are delivered over a per-session mpsc channel and processed by
//! the relay's select loop (no direct socket access — no races).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use tokio::sync::mpsc;

/// Control commands sent from the console/web to a specific session's relay loop.
pub enum Control {
    /// Transfer the session to the specified server.
    Transfer(String),
    /// Force-disconnect the session.
    Kick,
}

/// Relay stages — what a session's relay loop is currently doing. Read by the stall watchdog so a hang
/// can be pinned to a specific operation (e.g. `intercept_down` covers downstream decompression/decoding).
pub mod stage {
    pub const IDLE: u8 = 0; // waiting in select! for I/O (normal)
    pub const INTERCEPT_UP: u8 = 1; // handling a client→server message
    pub const SEND_SERVER: u8 = 2; // forwarding to the downstream
    pub const INTERCEPT_DOWN: u8 = 3; // handling a server→client message (decompress lives here)
    pub const SEND_CLIENT: u8 = 4; // forwarding to the client
    pub const RTT: u8 = 5; // measuring client RTT
    pub const TRANSFER: u8 = 6; // performing a seamless transfer

    pub fn name(s: u8) -> &'static str {
        match s {
            INTERCEPT_UP => "intercept_up",
            SEND_SERVER => "send_server",
            INTERCEPT_DOWN => "intercept_down",
            SEND_CLIENT => "send_client",
            RTT => "rtt",
            TRANSFER => "transfer",
            _ => "idle",
        }
    }
}

/// Per-session liveness for the stall watchdog. Relaxed atomics — a couple of cheap stores per packet.
#[derive(Default)]
pub struct Health {
    /// Current relay stage (see [`stage`]).
    pub stage: AtomicU8,
    /// Incremented once per relay loop iteration — proves the loop is still progressing.
    pub loop_beat: AtomicU64,
    /// Backend-connection reliability diagnostics (sampled periodically) — for the dashboard/console so a
    /// stall is visible before it becomes a freeze. `srv_ordered_index` should climb and wrap past 2^24
    /// without sticking; a rising `srv_ordered_dropped` while frozen is the ordered-index-wrap signature.
    pub srv_ordered_index: AtomicU64,
    pub srv_ordered_backlog: AtomicU64,
    pub srv_ordered_dropped: AtomicU64,
    pub srv_sendq_unacked: AtomicU64,
}

impl Health {
    /// Mark the current relay stage (cheap relaxed store).
    #[inline]
    pub fn set_stage(&self, s: u8) {
        self.stage.store(s, Relaxed);
    }
    /// Record one loop iteration of progress.
    #[inline]
    pub fn beat(&self) {
        self.loop_beat.fetch_add(1, Relaxed);
    }
    /// Sample the backend connection's reliability state (called periodically from the relay).
    pub fn set_diag(&self, ordered_index: u32, backlog: usize, dropped: u64, sendq_unacked: usize) {
        self.srv_ordered_index.store(ordered_index as u64, Relaxed);
        self.srv_ordered_backlog.store(backlog as u64, Relaxed);
        self.srv_ordered_dropped.store(dropped, Relaxed);
        self.srv_sendq_unacked.store(sendq_unacked as u64, Relaxed);
    }
}

/// Snapshot of one session's health for a watchdog scan.
pub struct HealthSnap {
    pub id: u64,
    pub name: Option<String>,
    pub stage: u8,
    pub loop_beat: u64,
}

/// Registry entry for a single session.
struct Entry {
    name: Option<String>,
    #[allow(dead_code)]
    xuid: Option<String>,
    peer: SocketAddr,
    server: String,
    control: mpsc::Sender<Control>,
    connected: Instant,
    rtt_ms: u32,
    health: Arc<Health>,
}

/// Session summary serialized for `GET /players` and the console `list` command.
#[derive(serde::Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub name: Option<String>,
    pub peer: String,
    pub server: String,
    /// Seconds elapsed since connection.
    pub connected_secs: u64,
    /// Estimated client↔proxy RTT in ms (SRTT).
    pub rtt_ms: u32,
    /// Backend-connection reliability diagnostics (sampled ~every 3s). `ordered_index` should keep
    /// advancing (and wrap past 2^24) — a stuck value or rising `ordered_dropped` signals a stall.
    pub ordered_index: u64,
    pub ordered_backlog: u64,
    pub ordered_dropped: u64,
    pub sendq_unacked: u64,
}

#[derive(Default)]
pub struct Registry {
    next_id: AtomicU64,
    sessions: RwLock<HashMap<u64, Entry>>,
}

impl Registry {
    /// Register a new session. Use the returned id for subsequent set_identity/set_server/remove calls.
    pub fn register(&self, peer: SocketAddr, server: String, control: mpsc::Sender<Control>, health: Arc<Health>) -> u64 {
        let id = self.next_id.fetch_add(1, Relaxed);
        if let Ok(mut s) = self.sessions.write() {
            s.insert(id, Entry { name: None, xuid: None, peer, server, control, connected: Instant::now(), rtt_ms: 0, health });
        }
        id
    }

    /// Snapshot of per-session health (current stage + loop heartbeat) for the stall watchdog.
    pub fn health_snapshot(&self) -> Vec<HealthSnap> {
        self.sessions
            .read()
            .map(|s| {
                s.iter()
                    .map(|(id, e)| HealthSnap {
                        id: *id,
                        name: e.name.clone(),
                        stage: e.health.stage.load(Relaxed),
                        loop_beat: e.health.loop_beat.load(Relaxed),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Populate the session with name/XUID extracted from the login packet (only non-None values are applied).
    pub fn set_identity(&self, id: u64, name: Option<String>, xuid: Option<String>) {
        if let Ok(mut s) = self.sessions.write() {
            if let Some(e) = s.get_mut(&id) {
                if name.is_some() {
                    e.name = name;
                }
                if xuid.is_some() {
                    e.xuid = xuid;
                }
            }
        }
    }

    /// Update the session's current server after a transfer.
    pub fn set_server(&self, id: u64, server: String) {
        if let Ok(mut s) = self.sessions.write() {
            if let Some(e) = s.get_mut(&id) {
                e.server = server;
            }
        }
    }

    /// Update the periodically measured client↔proxy RTT (ms).
    pub fn set_rtt(&self, id: u64, rtt_ms: u32) {
        if let Ok(mut s) = self.sessions.write() {
            if let Some(e) = s.get_mut(&id) {
                e.rtt_ms = rtt_ms;
            }
        }
    }

    pub fn remove(&self, id: u64) {
        if let Ok(mut s) = self.sessions.write() {
            s.remove(&id);
        }
    }

    /// Return a snapshot of all active sessions sorted by id (ascending).
    pub fn snapshot(&self) -> Vec<SessionInfo> {
        let mut v: Vec<SessionInfo> = self
            .sessions
            .read()
            .map(|s| {
                s.iter()
                    .map(|(id, e)| SessionInfo {
                        id: *id,
                        name: e.name.clone(),
                        peer: e.peer.to_string(),
                        server: e.server.clone(),
                        connected_secs: e.connected.elapsed().as_secs(),
                        rtt_ms: e.rtt_ms,
                        ordered_index: e.health.srv_ordered_index.load(Relaxed),
                        ordered_backlog: e.health.srv_ordered_backlog.load(Relaxed),
                        ordered_dropped: e.health.srv_ordered_dropped.load(Relaxed),
                        sendq_unacked: e.health.srv_sendq_unacked.load(Relaxed),
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by_key(|x| x.id);
        v
    }

    /// Look up a session by name (case-insensitive) or numeric id; returns (id, control channel clone).
    pub fn find_control(&self, who: &str) -> Option<(u64, mpsc::Sender<Control>)> {
        let s = self.sessions.read().ok()?;
        // Numeric id takes precedence.
        if let Ok(id) = who.parse::<u64>() {
            if let Some(e) = s.get(&id) {
                return Some((id, e.control.clone()));
            }
        }
        // Name match.
        s.iter()
            .find(|(_, e)| {
                e.name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(who))
                    .unwrap_or(false)
            })
            .map(|(id, e)| (*id, e.control.clone()))
    }
}
