use std::sync::atomic::{AtomicU16, Ordering};

pub const RAKNET_PROTOCOL_VERSION: u8 = 10;
pub const RAKNET_PROTOCOL_VERSION_LIST: [u8; 2] = [10, 11];
// 협상 MTU 기본값. 기존 1400 → 안정성 위해 1200(Rift 패치). set_mtu 로 런타임 변경.
pub const RAKNET_CLIENT_MTU: u16 = 1200;

/// 협상 MTU 상한(클라↔프록시 reply + 프록시↔다운스트림 요청 + 인바운드 캡 공통).
pub static RAKNET_MTU: AtomicU16 = AtomicU16::new(RAKNET_CLIENT_MTU);

/// 현재 MTU 상한.
pub fn mtu() -> u16 {
    RAKNET_MTU.load(Ordering::Relaxed)
}

/// MTU 상한 설정. RakNet 최소(576)~이더넷(1500) 범위로 클램프.
pub fn set_mtu(m: u16) {
    RAKNET_MTU.store(m.clamp(576, 1500), Ordering::Relaxed);
}

pub const RECEIVE_TIMEOUT: i64 = 60000;

pub enum Endian {
    Big,
    Little,
}

pub fn cur_timestamp_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap_or(0)
}

pub fn _is_timeout(time: i64, timeout: u64) -> bool {
    let cur = cur_timestamp_millis();
    cur >= time + timeout as i64
}
