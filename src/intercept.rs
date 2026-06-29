//! 다운스트림→클라 게임패킷 인터셉션 (평문 A모드).
//!
//! 핫패스 철학: 배치를 디코드해 **패킷 ID만 peek**, 우리가 손댈 패킷만 처리하고
//! 나머지는 원본 바이트 그대로 전달(재압축 없음).
//! - VV flip: 리소스팩 단계(청크 前) 1회 → 끝나면 더 안 봄.
//! - TransferPacket 감지: 계속 감시하되, **작은 배치만 디코드**(큰 청크 배치는 스킵)해 비용 회피.
//!
//! 게임패킷: `0xfe` + (NetworkSettings 후) `[압축타입][데이터]`, 그 전엔 raw 배치.

use std::collections::HashSet;

use anyhow::Result;

use crate::compression::{self, NONE};
use crate::framing::{build_batch, peek_packet_id, read_varint_u32, split_batch};
use crate::packets;
use crate::packs::PackStore;

const GAME_PACKET: u8 = 0xfe;
const ID_LOGIN: u32 = 0x01;
const ID_NETWORK_SETTINGS: u32 = 0x8f;
const ID_RESOURCE_PACKS_INFO: u32 = 0x06;
const ID_RESOURCE_PACK_STACK: u32 = 0x07;
const ID_RESOURCE_PACK_RESPONSE: u32 = 0x08;
const ID_RESOURCE_PACK_CHUNK_REQUEST: u32 = 0x54;
const ID_TRANSFER: u32 = 0x55;

// ResourcePackClientResponse status.
const RP_STATUS_REFUSED: u8 = 1;
const RP_STATUS_SEND_PACKS: u8 = 2;
const RP_STATUS_HAVE_ALL_PACKS: u8 = 3;
const RP_STATUS_COMPLETED: u8 = 4;

/// 관심 패킷 ID bitmap(10비트 ID 공간). 핫패스에서 배열 1회 조회로 대다수 패킷을 즉시 통과시킨다
/// (분기예측 친화 — match 의 순차 비교보다 비관심 패킷에서 유리). 관심 ID 만 true 인 superset이고,
/// 동적 게이팅(watching_vv/channel_transfer/rp)은 match 가드가 담당한다.
const fn interest(ids: &[u32]) -> [bool; 1024] {
    let mut t = [false; 1024];
    let mut i = 0;
    while i < ids.len() {
        t[ids[i] as usize] = true;
        i += 1;
    }
    t
}

/// down(서버→클라)에서 우리가 손대는 패킷 ID 전체.
const DOWN_INTEREST: [bool; 1024] = interest(&[
    ID_NETWORK_SETTINGS,
    ID_RESOURCE_PACKS_INFO,
    ID_RESOURCE_PACK_STACK,
    ID_TRANSFER,
    packets::ID_BOSS_EVENT,
    packets::ID_SET_DISPLAY_OBJECTIVE,
    packets::ID_REMOVE_OBJECTIVE,
]);

/// transfer 감시 시(VV 끝난 후) 이 크기(바이트) 넘는 배치는 디코드 안 함 — 청크 등 대형 패킷 회피.
/// TransferPacket 배치는 작다(서버명 + 몇 바이트).
const TRANSFER_SCAN_MAX: usize = 512;

/// 연결당 세션 상태 (up/down 공유).
#[derive(Default)]
pub struct SessionState {
    /// NetworkSettings 이후 압축 ON (양방향 공유).
    compression_on: bool,
    /// VV flip 완료.
    vv_done: bool,
    /// 캡처한 클라 Login 패킷(압축 해제된 패킷 바이트). 전환 시 새 서버에 리플레이.
    captured_login: Option<Vec<u8>>,
    /// 현재 서버가 띄운 보스바(bossActorUniqueId). 전환 시 HIDE 로 청소.
    bossbars: HashSet<i64>,
    /// 현재 서버가 띄운 스코어보드 목표 이름. 전환 시 RemoveObjective 로 청소.
    objectives: HashSet<String>,
    /// 리소스팩 서빙 중(프록시가 다운스트림 ResourcePacksInfo 를 프록시 팩으로 대체함).
    /// 이후 클라 RP 응답을 프록시가 처리하고, 다운스트림엔 HAVE_ALL/COMPLETED 로 답한다.
    rp_serving: bool,
}

impl SessionState {
    /// 캡처된 Login 패킷(있으면). 전환 로직이 새 다운스트림에 리플레이할 때 사용.
    pub fn captured_login(&self) -> Option<&[u8]> {
        self.captured_login.as_deref()
    }

    /// 추적된 보스바/스코어보드를 비우고 반환(전환 시 옛 서버 잔재 teardown 용).
    pub fn take_tracked(&mut self) -> (Vec<i64>, Vec<String>) {
        let bossbars = self.bossbars.drain().collect();
        let objectives = self.objectives.drain().collect();
        (bossbars, objectives)
    }

    /// 새 서버 초기 상태로 추적 세트를 시드한다(전환 후 다음 전환 대비).
    pub fn seed_tracked(&mut self, bossbars: Vec<i64>, objectives: Vec<String>) {
        self.bossbars = bossbars.into_iter().collect();
        self.objectives = objectives.into_iter().collect();
    }
}

/// up(클라→서버) 메시지 인터셉션. ① Login 1회 캡처(전환 리플레이용) ② 리소스팩 서빙 중이면
/// 클라 RP 응답(SEND_PACKS/HAVE_ALL/COMPLETED)·청크요청을 프록시가 처리. 그 외엔 Forward(→서버).
/// 디코드 실패 시 Forward 폴백.
pub fn intercept_up(state: &mut SessionState, msg: &[u8], packs: Option<&PackStore>) -> Outcome {
    if msg.first() != Some(&GAME_PACKET) {
        return Outcome::Forward;
    }
    match try_intercept_up(state, msg, packs) {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("up 디코드 실패(원본 전달): {e}");
            Outcome::Forward
        }
    }
}

fn try_intercept_up(state: &mut SessionState, msg: &[u8], packs: Option<&PackStore>) -> Result<Outcome> {
    // RP 서빙도 아니고 Login 도 이미 잡았으면 디코드 불필요 → 불투명 통과(핫패스 보호).
    let need_rp = packs.is_some() && state.rp_serving;
    if state.captured_login.is_some() && !need_rp {
        return Ok(Outcome::Forward);
    }

    let payload = &msg[1..];
    let (comp_type, batch_data): (u8, &[u8]) = if state.compression_on {
        match payload.split_first() {
            Some((&t, rest)) => (t, rest),
            None => return Ok(Outcome::Forward),
        }
    } else {
        (NONE, payload)
    };
    let batch = compression::decompress(comp_type, batch_data)?;
    let pkts = split_batch(&batch)?;

    // Login 1회 캡처.
    if state.captured_login.is_none() {
        for p in &pkts {
            if peek_packet_id(p).ok() == Some(ID_LOGIN) {
                state.captured_login = Some(p.to_vec());
                tracing::info!(bytes = p.len(), "클라 Login 캡처 완료 (전환 리플레이용)");
                break;
            }
        }
    }

    // 리소스팩 중개: 서빙 중이면 클라 RP 패킷을 프록시가 처리하고 배치를 삼킨다.
    if need_rp {
        let store = packs.expect("need_rp 면 packs Some");
        let mut to_client_raw: Vec<Vec<u8>> = Vec::new();
        let mut to_server_raw: Vec<Vec<u8>> = Vec::new();
        let mut handled = false;
        for p in &pkts {
            match peek_packet_id(p) {
                Ok(ID_RESOURCE_PACK_RESPONSE) => {
                    handled = true;
                    handle_rp_response(store, p, &mut to_client_raw, &mut to_server_raw);
                }
                Ok(ID_RESOURCE_PACK_CHUNK_REQUEST) => {
                    handled = true;
                    if let Some(cd) = handle_chunk_request(store, p) {
                        to_client_raw.push(cd);
                    }
                }
                _ => {}
            }
        }
        if handled {
            return Ok(Outcome::Inject {
                to_client: frame_all(&to_client_raw)?,
                to_server: frame_all(&to_server_raw)?,
            });
        }
    }

    Ok(Outcome::Forward)
}

/// 클라 ResourcePackClientResponse 처리 → 클라/서버로 보낼 raw 패킷을 채운다.
fn handle_rp_response(
    store: &PackStore,
    pkt: &[u8],
    to_client: &mut Vec<Vec<u8>>,
    to_server: &mut Vec<Vec<u8>>,
) {
    let Some((status, ids)) = crate::packs::parse_client_response(pkt) else {
        return;
    };
    match status {
        RP_STATUS_SEND_PACKS => {
            // 요청한 각 팩("uuid_version")에 DataInfo 전송.
            let mut served = 0;
            for id in &ids {
                let uuid = id.split('_').next().unwrap_or(id);
                if let Some(pack) = store.find(uuid) {
                    to_client.push(PackStore::data_info_packet(pack));
                    served += 1;
                } else {
                    tracing::warn!(%uuid, "RP SEND_PACKS: 알 수 없는 팩 요청");
                }
            }
            tracing::info!(requested = ids.len(), served, "RP SEND_PACKS → DataInfo 전송");
        }
        RP_STATUS_HAVE_ALL_PACKS => {
            // 다운로드 완료 → 프록시 스택 전송(팩 활성화).
            to_client.push(store.stack_packet.clone());
            tracing::info!("RP HAVE_ALL → 프록시 스택 전송");
        }
        RP_STATUS_COMPLETED => {
            // 클라 RP 끝 → 다운스트림에 HAVE_ALL_PACKS 로 응답(다운스트림 RP 진행 트리거).
            to_server.push(packets::resource_pack_client_response(RP_STATUS_HAVE_ALL_PACKS));
            tracing::info!("RP COMPLETED → 다운스트림에 HAVE_ALL 응답");
        }
        RP_STATUS_REFUSED => {
            tracing::warn!("클라가 리소스팩 거부 — 다운스트림 진행");
            to_server.push(packets::resource_pack_client_response(RP_STATUS_HAVE_ALL_PACKS));
        }
        other => tracing::warn!(other, "알 수 없는 RP status"),
    }
}

/// 클라 ResourcePackChunkRequest 처리 → ChunkData 패킷(raw) 반환.
fn handle_chunk_request(store: &PackStore, pkt: &[u8]) -> Option<Vec<u8>> {
    let (uuid, idx) = crate::packs::parse_chunk_request(pkt)?;
    let Some(pack) = store.find(&uuid) else {
        tracing::warn!(%uuid, "RP ChunkRequest: 알 수 없는 팩");
        return None;
    };
    let offset = idx as u64 * crate::packs::CHUNK_SIZE as u64;
    let start = offset as usize;
    if start >= pack.bytes.len() {
        tracing::warn!(%uuid, idx, "RP ChunkRequest 범위 초과");
        return None;
    }
    let end = (start + crate::packs::CHUNK_SIZE as usize).min(pack.bytes.len());
    tracing::debug!(%uuid, idx, len = end - start, "RP ChunkData 전송");
    Some(PackStore::chunk_data_packet(&pack.uuid_str, idx, offset, &pack.bytes[start..end]))
}

/// raw 패킷들을 게임패킷 메시지(zlib 압축)로 프레이밍. (RP 단계는 NetworkSettings 이후라 압축 ON)
fn frame_all(raw: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    raw.iter()
        .map(|p| packets::frame_game_packet(p, true, compression::ZLIB))
        .collect()
}

/// 인터셉션 결과 (up/down 공용). Forward/Replace 의 "반대편"은 방향에 따라 결정된다
/// (up → 서버, down → 클라). Inject 는 명시적으로 양쪽에 보낸다(원본은 버림).
pub enum Outcome {
    /// 원본 그대로 반대편으로 전달.
    Forward,
    /// 수정본을 반대편으로 전달.
    Replace(Vec<u8>),
    /// 원본을 버리고 지정한 메시지들을 각각 클라/서버로 보낸다(리소스팩 중개 등).
    Inject {
        to_client: Vec<Vec<u8>>,
        to_server: Vec<Vec<u8>>,
    },
    /// (down 전용) 채널이동 트리거 — 대상 서버명. 원본은 클라로 안 보냄.
    Transfer(String),
}

/// down 메시지를 검사한다. 디코드 실패 시 `Forward`(원본 전달)로 폴백해 연결을 보호한다.
pub fn intercept_down(
    state: &mut SessionState,
    msg: &[u8],
    force_vv: bool,
    channel_transfer: bool,
    packs: Option<&PackStore>,
) -> Outcome {
    if msg.first() != Some(&GAME_PACKET) {
        return Outcome::Forward;
    }

    let watching_vv = force_vv && !state.vv_done;
    let rp_active = packs.is_some();
    if !watching_vv && !channel_transfer && !rp_active {
        return Outcome::Forward; // 볼 게 없음 → 완전 불투명
    }

    // VV flip 단계가 끝나면 작은 배치만 디코드(청크 회피). transfer/RP 패킷은 작다.
    if !watching_vv {
        let payload = &msg[1..];
        let data_len = if state.compression_on {
            payload.len().saturating_sub(1)
        } else {
            payload.len()
        };
        if data_len > TRANSFER_SCAN_MAX {
            return Outcome::Forward;
        }
    }

    match try_intercept(state, msg, watching_vv, channel_transfer, packs) {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::debug!("down 디코드 실패(원본 전달): {e}");
            Outcome::Forward
        }
    }
}

fn try_intercept(
    state: &mut SessionState,
    msg: &[u8],
    watching_vv: bool,
    channel_transfer: bool,
    packs: Option<&PackStore>,
) -> Result<Outcome> {
    let payload = &msg[1..];

    let compressed_now = state.compression_on;
    let (comp_type, batch_data): (u8, &[u8]) = if compressed_now {
        match payload.split_first() {
            Some((&t, rest)) => (t, rest),
            None => return Ok(Outcome::Forward),
        }
    } else {
        (NONE, payload)
    };

    let batch = compression::decompress(comp_type, batch_data)?;
    let packets = split_batch(&batch)?;

    let mut vv_idx = None;
    let mut transfer_idx = None;
    let mut saw_network_settings = false;
    let mut rp_info_seen = false;
    let mut rp_stack_seen = false;
    for (i, p) in packets.iter().enumerate() {
        let Ok(id) = peek_packet_id(p) else { continue };
        // 핫패스 fast-reject: 관심 ID bitmap 1회 조회로 대다수(이동/엔티티 등) 패킷을 즉시 통과.
        if !DOWN_INTEREST[id as usize] {
            continue;
        }
        match id {
            ID_NETWORK_SETTINGS => saw_network_settings = true,
            // RP 서빙: 다운스트림 ResourcePacksInfo 는 프록시 팩으로 대체(VV flip 보다 우선).
            ID_RESOURCE_PACKS_INFO if packs.is_some() => rp_info_seen = true,
            ID_RESOURCE_PACKS_INFO if watching_vv => vv_idx = Some(i),
            ID_RESOURCE_PACK_STACK if state.rp_serving => rp_stack_seen = true,
            ID_TRANSFER if channel_transfer => transfer_idx = Some(i),
            // 전환 teardown 대비 상태 추적 (보스바/스코어보드 — 작은 패킷이라 디코드 비용 미미).
            packets::ID_BOSS_EVENT if channel_transfer => {
                if let Some((bid, ev)) = packets::parse_boss_event(p) {
                    if ev == packets::BOSS_EVENT_TYPE_SHOW {
                        state.bossbars.insert(bid);
                    } else if ev == packets::BOSS_EVENT_TYPE_HIDE {
                        state.bossbars.remove(&bid);
                    }
                }
            }
            packets::ID_SET_DISPLAY_OBJECTIVE if channel_transfer => {
                if let Some(name) = packets::parse_set_display_objective_name(p) {
                    state.objectives.insert(name);
                }
            }
            packets::ID_REMOVE_OBJECTIVE if channel_transfer => {
                if let Some(name) = packets::parse_remove_objective_name(p) {
                    state.objectives.remove(&name);
                }
            }
            _ => {}
        }
    }

    if saw_network_settings && !state.compression_on {
        state.compression_on = true;
    }

    // TransferPacket 우선 — 전환은 곧 연결을 바꾸므로 같은 배치의 다른 처리보다 우선.
    if let Some(idx) = transfer_idx {
        if let Ok(server) = read_transfer_address(packets[idx]) {
            return Ok(Outcome::Transfer(server));
        }
    }

    // RP 서빙 시작: 배치 내 ResourcePacksInfo 패킷만 프록시 info 로 교체하고 나머지 패킷
    // (PlayStatus(LOGIN_SUCCESS) 등)은 보존한다. 다운스트림엔 아직 응답 안 함(HOLD).
    if rp_info_seen {
        if let Some(store) = packs {
            state.rp_serving = true;
            state.vv_done = true; // 프록시 info 가 forceDisableVibrantVisuals=0 이라 VV flip 불필요
            let mut owned: Vec<Vec<u8>> = packets.iter().map(|p| p.to_vec()).collect();
            let mut others = 0usize;
            for pkt in owned.iter_mut() {
                if peek_packet_id(pkt).ok() == Some(ID_RESOURCE_PACKS_INFO) {
                    *pkt = store.info_packet.clone();
                } else {
                    others += 1;
                }
            }
            let new_batch = build_batch(&owned);
            let recompressed = compression::compress(comp_type, &new_batch)?;
            let mut out = Vec::with_capacity(2 + recompressed.len());
            out.push(GAME_PACKET);
            if compressed_now {
                out.push(comp_type);
            }
            out.extend_from_slice(&recompressed);
            tracing::info!(packs = store.packs.len(), batch_others = others, "리소스팩 서빙 시작 — 다운스트림 info 대체(배치 보존)");
            return Ok(Outcome::Replace(out));
        }
    }

    // RP 다운스트림 Stack: 클라엔 안 보내고(프록시 스택 이미 전송) 다운스트림에 COMPLETED 응답 → 진행.
    if rp_stack_seen {
        let completed = packets::frame_game_packet(
            &packets::resource_pack_client_response(RP_STATUS_COMPLETED),
            compressed_now,
            comp_type,
        )?;
        return Ok(Outcome::Inject {
            to_client: vec![],
            to_server: vec![completed],
        });
    }

    // VV flip
    if let Some(idx) = vv_idx {
        let mut owned: Vec<Vec<u8>> = packets.iter().map(|p| p.to_vec()).collect();
        let flipped = flip_vibrant_visuals(&mut owned[idx]);
        state.vv_done = true;
        if !flipped {
            return Ok(Outcome::Forward);
        }
        tracing::info!("Vibrant Visuals 강제비활성 플래그 해제 (VV 활성화)");
        let new_batch = build_batch(&owned);
        let recompressed = compression::compress(comp_type, &new_batch)?;
        let mut out = Vec::with_capacity(2 + recompressed.len());
        out.push(GAME_PACKET);
        if compressed_now {
            out.push(comp_type);
        }
        out.extend_from_slice(&recompressed);
        return Ok(Outcome::Replace(out));
    }

    Ok(Outcome::Forward)
}

/// TransferPacket: `[header VarInt][address: VarInt-len + bytes][port LE u16][reloadWorld 1]`.
/// address(대상 서버명) 문자열을 읽는다.
fn read_transfer_address(packet: &[u8]) -> Result<String> {
    let (_, header_len) = read_varint_u32(packet)?;
    let rest = &packet[header_len..];
    let (str_len, consumed) = read_varint_u32(rest)?;
    let start = consumed;
    let end = start + str_len as usize;
    if end > rest.len() {
        anyhow::bail!("transfer address 길이 초과");
    }
    Ok(String::from_utf8_lossy(&rest[start..end]).into_owned())
}

/// ResourcePacksInfoPacket 의 `forceDisableVibrantVisuals`(헤더 다음 4번째 bool)를 false 로.
/// 레이아웃: `[header VarInt][mustAccept][hasAddons][hasScripts][forceDisableVibrantVisuals]...`
fn flip_vibrant_visuals(packet: &mut [u8]) -> bool {
    let Ok((_, header_len)) = read_varint_u32(packet) else {
        return false;
    };
    let offset = header_len + 3;
    if offset < packet.len() && packet[offset] != 0 {
        packet[offset] = 0;
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::write_varint_u32;

    fn make_resource_packs_info(force_vv: u8) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_RESOURCE_PACKS_INFO, &mut p);
        p.push(0); // mustAccept
        p.push(0); // hasAddons
        p.push(0); // hasScripts
        p.push(force_vv); // forceDisableVibrantVisuals
        p.extend_from_slice(&[0u8; 16]); // worldTemplateId
        p.push(0); // worldTemplateVersion len
        p.extend_from_slice(&[0, 0]); // resourcePackCount
        p
    }

    fn make_transfer(addr: &str) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_TRANSFER, &mut p);
        write_varint_u32(addr.len() as u32, &mut p);
        p.extend_from_slice(addr.as_bytes());
        p.extend_from_slice(&[0x33, 0x4b]); // port LE u16
        p.push(1); // reloadWorld
        p
    }

    fn frame_uncompressed(packets: &[Vec<u8>]) -> Vec<u8> {
        let batch = build_batch(packets);
        let mut msg = vec![GAME_PACKET];
        msg.extend_from_slice(&batch);
        msg
    }

    fn dummy_store() -> crate::packs::PackStore {
        let mut info = Vec::new();
        write_varint_u32(ID_RESOURCE_PACKS_INFO, &mut info);
        let mut stack = Vec::new();
        write_varint_u32(ID_RESOURCE_PACK_STACK, &mut stack);
        crate::packs::PackStore { packs: vec![], info_packet: info, stack_packet: stack }
    }

    fn make_rp_response(status: u8) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_RESOURCE_PACK_RESPONSE, &mut p);
        p.push(status);
        p.extend_from_slice(&[0u8, 0u8]); // packIds count (LE u16) = 0
        p
    }

    #[test]
    fn rp_replaces_downstream_info_then_responds_on_completed() {
        let store = dummy_store();
        let mut state = SessionState::default();
        // 다운스트림 ResourcePacksInfo → 프록시 info 로 대체 + rp_serving 설정.
        let info_msg = frame_uncompressed(&[make_resource_packs_info(1)]);
        match intercept_down(&mut state, &info_msg, true, true, Some(&store)) {
            Outcome::Replace(_) => {}
            _ => panic!("RP info 대체(Replace) 기대"),
        }
        assert!(state.rp_serving);

        // 클라 COMPLETED → 다운스트림에 HAVE_ALL 응답(Inject to_server 비어있지 않음).
        let resp = frame_uncompressed(&[make_rp_response(RP_STATUS_COMPLETED)]);
        match intercept_up(&mut state, &resp, Some(&store)) {
            Outcome::Inject { to_server, .. } => assert!(!to_server.is_empty()),
            _ => panic!("COMPLETED 시 다운스트림 응답(Inject) 기대"),
        }
    }

    #[test]
    fn rp_disabled_keeps_vv_flip() {
        // packs None 이면 기존 VV flip 경로 유지(rp_serving 안 됨).
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_resource_packs_info(1)]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Replace(_) => {}
            _ => panic!("VV flip Replace 기대"),
        }
        assert!(!state.rp_serving);
    }

    #[test]
    fn detects_transfer_and_reads_server_name() {
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_transfer("island1")]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Transfer(s) => assert_eq!(s, "island1"),
            _ => panic!("Transfer 가 감지돼야 함"),
        }
    }

    #[test]
    fn flips_vv() {
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_resource_packs_info(1)]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Replace(out) => {
                let packets = split_batch(&out[1..]).unwrap();
                let (_, hl) = read_varint_u32(packets[0]).unwrap();
                assert_eq!(packets[0][hl + 3], 0);
            }
            _ => panic!("VV flip 수정본이 나와야 함"),
        }
        assert!(state.vv_done);
    }

    #[test]
    fn large_batch_skipped_when_only_transfer_watching() {
        let mut state = SessionState { compression_on: true, vv_done: true, ..Default::default() };
        // 큰 배치 = 청크로 간주, 디코드 스킵 → Forward
        let big = vec![GAME_PACKET; TRANSFER_SCAN_MAX + 100];
        assert!(matches!(
            intercept_down(&mut state, &big, true, true, None),
            Outcome::Forward
        ));
    }

    #[test]
    fn opaque_when_both_features_off() {
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_transfer("island1")]);
        assert!(matches!(
            intercept_down(&mut state, &msg, false, false, None),
            Outcome::Forward
        ));
    }

    #[test]
    fn transfer_still_watched_after_vv_done() {
        // vv_done 이어도 transfer 는 계속 감시(작은 배치).
        let mut state = SessionState { compression_on: false, vv_done: true, ..Default::default() };
        let msg = frame_uncompressed(&[make_transfer("spawn2")]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Transfer(s) => assert_eq!(s, "spawn2"),
            _ => panic!("vv_done 후에도 transfer 감지돼야 함"),
        }
    }

    #[test]
    fn tracks_compression_after_network_settings() {
        let mut state = SessionState::default();
        let mut ns = Vec::new();
        write_varint_u32(ID_NETWORK_SETTINGS, &mut ns);
        ns.extend_from_slice(&[0u8; 6]);
        let msg = frame_uncompressed(&[ns]);
        let _ = intercept_down(&mut state, &msg, true, true, None);
        assert!(state.compression_on);
    }

    fn make_login(payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_LOGIN, &mut p);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn captures_login_for_replay() {
        let mut state = SessionState::default();
        let login = make_login(b"protocol+authInfo+clientData");
        let _ = intercept_up(&mut state, &frame_uncompressed(&[login.clone()]), None);
        assert_eq!(state.captured_login(), Some(login.as_slice()));
    }

    #[test]
    fn captures_login_only_once() {
        let mut state = SessionState::default();
        let first = make_login(b"first");
        let _ = intercept_up(&mut state, &frame_uncompressed(&[first.clone()]), None);
        // 이후 다른 Login 은 무시(최초 1회만).
        let _ = intercept_up(&mut state, &frame_uncompressed(&[make_login(b"second-different")]), None);
        assert_eq!(state.captured_login(), Some(first.as_slice()));
    }

    #[test]
    fn ignores_non_login_up_packets() {
        let mut state = SessionState::default();
        // RequestNetworkSettings(0xc1) 같은 비-Login 은 캡처 안 함.
        let mut req = Vec::new();
        write_varint_u32(0xc1, &mut req);
        req.extend_from_slice(&[0, 0, 0, 0]);
        let _ = intercept_up(&mut state, &frame_uncompressed(&[req]), None);
        assert!(state.captured_login().is_none());
    }
}
