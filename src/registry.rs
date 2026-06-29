//! Session registry — the single source of truth for the console/web to query and manipulate
//! active sessions (transfer, kick).
//!
//! Each relay task registers itself on start via `register` and unregisters on exit via `remove`.
//! The console and web layer access sessions through `snapshot` (read) and `find_control`
//! (manipulate). Control commands are delivered over a per-session mpsc channel and processed by
//! the relay's select loop (no direct socket access — no races).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::RwLock;
use std::time::Instant;

use tokio::sync::mpsc;

/// Control commands sent from the console/web to a specific session's relay loop.
pub enum Control {
    /// Transfer the session to the specified server.
    Transfer(String),
    /// Force-disconnect the session.
    Kick,
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
}

#[derive(Default)]
pub struct Registry {
    next_id: AtomicU64,
    sessions: RwLock<HashMap<u64, Entry>>,
}

impl Registry {
    /// Register a new session. Use the returned id for subsequent set_identity/set_server/remove calls.
    pub fn register(&self, peer: SocketAddr, server: String, control: mpsc::Sender<Control>) -> u64 {
        let id = self.next_id.fetch_add(1, Relaxed);
        if let Ok(mut s) = self.sessions.write() {
            s.insert(id, Entry { name: None, xuid: None, peer, server, control, connected: Instant::now(), rtt_ms: 0 });
        }
        id
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
