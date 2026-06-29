//! 세션 레지스트리 — 콘솔/웹이 활성 세션을 조회하고 조작(전환·강제종료)하는 단일 출처.
//!
//! 각 relay 태스크는 시작 시 `register` 로 자신을 등록하고 종료 시 `remove` 한다. 콘솔/웹은
//! `snapshot`(읽기)·`find_control`(조작)으로 접근한다. 조작은 세션별 mpsc 제어 채널로 전달돼
//! relay 의 select 루프가 처리한다(직접 소켓을 건드리지 않음 → 경쟁 없음).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::RwLock;
use std::time::Instant;

use tokio::sync::mpsc;

/// 콘솔/웹 → 특정 세션 relay 루프로 보내는 제어 명령.
pub enum Control {
    /// 지정 서버로 채널이동.
    Transfer(String),
    /// 세션 강제 종료.
    Kick,
}

/// 한 세션의 레지스트리 항목.
struct Entry {
    name: Option<String>,
    #[allow(dead_code)]
    xuid: Option<String>,
    peer: SocketAddr,
    server: String,
    control: mpsc::Sender<Control>,
    connected: Instant,
}

/// 웹 `/players` · 콘솔 `list` 직렬화용 세션 요약.
#[derive(serde::Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub name: Option<String>,
    pub peer: String,
    pub server: String,
    /// 접속 후 경과 시간(초).
    pub connected_secs: u64,
}

#[derive(Default)]
pub struct Registry {
    next_id: AtomicU64,
    sessions: RwLock<HashMap<u64, Entry>>,
}

impl Registry {
    /// 새 세션 등록. 반환된 id 로 이후 set_identity/set_server/remove.
    pub fn register(&self, peer: SocketAddr, server: String, control: mpsc::Sender<Control>) -> u64 {
        let id = self.next_id.fetch_add(1, Relaxed);
        if let Ok(mut s) = self.sessions.write() {
            s.insert(id, Entry { name: None, xuid: None, peer, server, control, connected: Instant::now() });
        }
        id
    }

    /// Login 에서 뽑은 이름/XUID 를 세션에 채운다(있는 값만).
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

    /// 채널이동 후 현재 서버 갱신.
    pub fn set_server(&self, id: u64, server: String) {
        if let Ok(mut s) = self.sessions.write() {
            if let Some(e) = s.get_mut(&id) {
                e.server = server;
            }
        }
    }

    pub fn remove(&self, id: u64) {
        if let Ok(mut s) = self.sessions.write() {
            s.remove(&id);
        }
    }

    /// 활성 세션 요약 (id 오름차순).
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
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by_key(|x| x.id);
        v
    }

    /// 이름(대소문자 무시) 또는 세션 번호로 세션을 찾아 (id, 제어 채널 복제)를 반환.
    pub fn find_control(&self, who: &str) -> Option<(u64, mpsc::Sender<Control>)> {
        let s = self.sessions.read().ok()?;
        // 번호 우선.
        if let Ok(id) = who.parse::<u64>() {
            if let Some(e) = s.get(&id) {
                return Some((id, e.control.clone()));
            }
        }
        // 이름 매칭.
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
