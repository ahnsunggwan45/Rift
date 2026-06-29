use std::sync::atomic::{AtomicU16, Ordering};

pub const RAKNET_PROTOCOL_VERSION: u8 = 10;
pub const RAKNET_PROTOCOL_VERSION_LIST: [u8; 2] = [10, 11];
// Negotiated MTU default. Was 1400 — lowered to 1200 for stability (Rift patch). Override at runtime via set_mtu.
pub const RAKNET_CLIENT_MTU: u16 = 1200;

/// Negotiated MTU cap (shared by client↔proxy reply, proxy↔downstream request, and inbound cap).
pub static RAKNET_MTU: AtomicU16 = AtomicU16::new(RAKNET_CLIENT_MTU);

/// Returns the current MTU cap.
pub fn mtu() -> u16 {
    RAKNET_MTU.load(Ordering::Relaxed)
}

/// Sets the MTU cap, clamped to the RakNet minimum (576) – Ethernet maximum (1500) range.
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
