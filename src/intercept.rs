//! Downstream→client game-packet interception (plaintext mode A).
//!
//! Hot-path philosophy: decode the batch to **peek packet IDs only**; handle only
//! the packets we care about and forward everything else as raw bytes (no recompression).
//! - VV flip: one-shot during the resource-pack phase (before chunks) → ignored afterwards.
//! - TransferPacket detection: always watched, but **only small batches are decoded**
//!   (large chunk batches are skipped) to avoid unnecessary overhead.
//!
//! Game packets: `0xfe` + (after NetworkSettings) `[compression_type][data]`; raw batches before that.

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

/// Bitmap of interesting packet IDs (10-bit ID space). A single array lookup on the hot path
/// lets most packets pass immediately (branch-prediction friendly — faster than sequential match
/// comparisons for uninteresting packets). This is a superset of IDs we might care about;
/// dynamic gating (watching_vv / channel_transfer / rp) is handled by match guards.
const fn interest(ids: &[u32]) -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < ids.len() {
        t[ids[i] as usize] = true;
        i += 1;
    }
    t
}

/// All packet IDs we touch in the down (server→client) direction.
const DOWN_INTEREST: [bool; 256] = interest(&[
    ID_NETWORK_SETTINGS,
    ID_RESOURCE_PACKS_INFO,
    ID_RESOURCE_PACK_STACK,
    ID_TRANSFER,
    packets::ID_BOSS_EVENT,
    packets::ID_SET_DISPLAY_OBJECTIVE,
    packets::ID_REMOVE_OBJECTIVE,
    packets::ID_ADD_PLAYER,
    packets::ID_ADD_ACTOR,
    packets::ID_ADD_ITEM_ACTOR,
    packets::ID_ADD_PAINTING,
    packets::ID_REMOVE_ACTOR,
]);

/// Fast-path threshold. Once past the initial VV/RP phase, batches larger than this are forwarded
/// **opaquely** — no decompress, no decode, no allocation, zero-copy. They are chunk data; every packet
/// Rift acts on (TransferPacket, entity Add/Remove, resource-pack) is far smaller. Decompressing only
/// the smaller batches is what keeps the hot path cheap ("don't touch what we don't need to").
/// Entities in a destination server's full spawn stream are captured separately during the handshake
/// (downstream.rs), regardless of size, so this cap doesn't drop them on transfer.
const MAX_DECODE_BATCH_BYTES: usize = 8192;

/// Per-connection session state (shared between the up and down paths).
#[derive(Default)]
pub struct SessionState {
    /// Compression enabled after NetworkSettings (shared for both directions).
    compression_on: bool,
    /// VV flip completed.
    vv_done: bool,
    /// Captured client Login packet (decompressed packet bytes). Replayed to the new server on transfer.
    captured_login: Option<Vec<u8>>,
    /// Boss bars (bossActorUniqueId) raised by the current server. Cleaned up with HIDE on transfer.
    bossbars: HashSet<i64>,
    /// Scoreboard objective names raised by the current server. Cleaned up with RemoveObjective on transfer.
    objectives: HashSet<String>,
    /// Actor entities (mobs/NPCs/items/paintings) spawned by the current server, keyed by actorUniqueId.
    /// Despawned with RemoveActor on transfer — the dimension flip alone does not reliably clear them.
    entities: HashSet<i64>,
    /// Resource pack serving is active (proxy has replaced the downstream ResourcePacksInfo with its own pack list).
    /// Client RP responses are handled by the proxy; the downstream receives HAVE_ALL/COMPLETED.
    rp_serving: bool,
}

impl SessionState {
    /// Returns the captured Login packet, if any. Used by transfer logic to replay to a new downstream.
    pub fn captured_login(&self) -> Option<&[u8]> {
        self.captured_login.as_deref()
    }

    /// Whether batch compression is active (post-NetworkSettings). The transfer path needs this to
    /// decode the client's packets while waiting for the dimension-change ack.
    pub fn compression_on(&self) -> bool {
        self.compression_on
    }

    /// Drains and returns tracked boss bars, scoreboard objectives, and actor entities
    /// (used to tear down the previous server's state on transfer).
    pub fn take_tracked(&mut self) -> (Vec<i64>, Vec<String>, Vec<i64>) {
        let bossbars = self.bossbars.drain().collect();
        let objectives = self.objectives.drain().collect();
        let entities = self.entities.drain().collect();
        (bossbars, objectives, entities)
    }

    /// Seeds the tracking sets with the new server's initial state (in preparation for the next transfer).
    pub fn seed_tracked(&mut self, bossbars: Vec<i64>, objectives: Vec<String>, entities: Vec<i64>) {
        self.bossbars = bossbars.into_iter().collect();
        self.objectives = objectives.into_iter().collect();
        self.entities = entities.into_iter().collect();
    }
}

/// Intercepts up (client→server) messages. ① Captures the Login packet once (for transfer replay).
/// ② While serving resource packs, handles client RP responses (SEND_PACKS/HAVE_ALL/COMPLETED)
/// and chunk requests directly in the proxy. Everything else is forwarded to the server.
/// Falls back to Forward on decode failure.
pub fn intercept_up(state: &mut SessionState, msg: &[u8], packs: Option<&PackStore>) -> Outcome {
    if msg.first() != Some(&GAME_PACKET) {
        return Outcome::Forward;
    }
    match try_intercept_up(state, msg, packs) {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!("up decode failed (forwarding original): {e}");
            Outcome::Forward
        }
    }
}

fn try_intercept_up(state: &mut SessionState, msg: &[u8], packs: Option<&PackStore>) -> Result<Outcome> {
    // Not serving RP and Login already captured — no decode needed; pass through opaquely (hot-path guard).
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

    // Capture Login once.
    if state.captured_login.is_none() {
        for p in &pkts {
            if peek_packet_id(p).ok() == Some(ID_LOGIN) {
                state.captured_login = Some(p.to_vec());
                tracing::info!(bytes = p.len(), "client Login captured (for transfer replay)");
                break;
            }
        }
    }

    // Resource pack brokering: while serving, the proxy handles client RP packets and consumes the batch.
    if need_rp {
        let store = packs.expect("need_rp implies packs is Some");
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

/// Handles a client ResourcePackClientResponse, populating raw packets to send to the client and/or server.
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
            // Send DataInfo for each requested pack ("uuid_version").
            let mut served = 0;
            for id in &ids {
                let uuid = id.split('_').next().unwrap_or(id);
                if let Some(pack) = store.find(uuid) {
                    to_client.push(PackStore::data_info_packet(pack));
                    served += 1;
                } else {
                    tracing::warn!(%uuid, "RP SEND_PACKS: unknown pack requested");
                }
            }
            tracing::info!(requested = ids.len(), served, "RP SEND_PACKS → sending DataInfo");
        }
        RP_STATUS_HAVE_ALL_PACKS => {
            // Download complete → send the proxy stack packet (activates packs).
            to_client.push(store.stack_packet.clone());
            tracing::info!("RP HAVE_ALL → sending proxy stack");
        }
        RP_STATUS_COMPLETED => {
            // Client RP done → acknowledge downstream with HAVE_ALL_PACKS to continue its RP flow.
            to_server.push(packets::resource_pack_client_response(RP_STATUS_HAVE_ALL_PACKS));
            tracing::info!("RP COMPLETED → sending HAVE_ALL to downstream");
        }
        RP_STATUS_REFUSED => {
            tracing::warn!("client refused resource packs — continuing downstream");
            to_server.push(packets::resource_pack_client_response(RP_STATUS_HAVE_ALL_PACKS));
        }
        other => tracing::warn!(other, "unknown RP status"),
    }
}

/// Handles a client ResourcePackChunkRequest and returns a raw ChunkData packet.
fn handle_chunk_request(store: &PackStore, pkt: &[u8]) -> Option<Vec<u8>> {
    let (uuid, idx) = crate::packs::parse_chunk_request(pkt)?;
    let Some(pack) = store.find(&uuid) else {
        tracing::warn!(%uuid, "RP ChunkRequest: unknown pack");
        return None;
    };
    let offset = idx as u64 * crate::packs::CHUNK_SIZE as u64;
    let start = offset as usize;
    if start >= pack.bytes.len() {
        tracing::warn!(%uuid, idx, "RP ChunkRequest out of range");
        return None;
    }
    let end = (start + crate::packs::CHUNK_SIZE as usize).min(pack.bytes.len());
    tracing::debug!(%uuid, idx, len = end - start, "RP ChunkData sending");
    Some(PackStore::chunk_data_packet(&pack.uuid_str, idx, offset, &pack.bytes[start..end]))
}

/// Frames raw packets into a game-packet message (zlib compressed). The RP phase is post-NetworkSettings so compression is always on.
fn frame_all(raw: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    raw.iter()
        .map(|p| packets::frame_game_packet(p, true, compression::ZLIB))
        .collect()
}

/// Interception result (shared by up and down paths). The "other side" for Forward/Replace
/// is direction-dependent (up → server, down → client). Inject explicitly addresses both sides
/// and discards the original.
pub enum Outcome {
    /// Forward the original message to the other side unchanged.
    Forward,
    /// Forward a modified message to the other side.
    Replace(Vec<u8>),
    /// Discard the original and send the specified messages to the client and/or server (e.g. resource pack brokering).
    Inject {
        to_client: Vec<Vec<u8>>,
        to_server: Vec<Vec<u8>>,
    },
    /// (down only) Transfer trigger — target server name. The original is not forwarded to the client.
    Transfer(String),
}

/// Inspects a down message. Falls back to `Forward` (pass original) on decode failure to protect the connection.
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
        return Outcome::Forward; // nothing to watch → fully opaque
    }

    // FAST PATH: once past the initial VV/RP phase, forward large batches (chunk data) opaquely
    // without decoding. This is the core "don't touch 99%" rule — the packets we act on (transfers,
    // entity Add/Remove, RP) are all small, so only the smaller batches are decompressed. Applies
    // regardless of channel_transfer; entity tracking still works because (a) destination spawn
    // entities are seeded from the handshake spawn buffer (any size) and (b) live entity spawns are
    // small batches under this cap.
    if !watching_vv {
        let payload = &msg[1..];
        let data_len = if state.compression_on {
            payload.len().saturating_sub(1)
        } else {
            payload.len()
        };
        if data_len > MAX_DECODE_BATCH_BYTES {
            return Outcome::Forward;
        }
    }

    match try_intercept(state, msg, watching_vv, channel_transfer, packs) {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::debug!("down decode failed (forwarding original): {e}");
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
        // Hot-path fast-reject: single bitmap lookup passes most packets (movement, entity, etc.) immediately.
        // All interesting IDs are <256. IDs outside that range are not our concern; bounds check passes them (panic-safe).
        let idx = id as usize;
        if idx >= DOWN_INTEREST.len() || !DOWN_INTEREST[idx] {
            continue;
        }
        match id {
            ID_NETWORK_SETTINGS => saw_network_settings = true,
            // RP serving: replace downstream ResourcePacksInfo with proxy packs (takes priority over VV flip).
            ID_RESOURCE_PACKS_INFO if packs.is_some() => rp_info_seen = true,
            ID_RESOURCE_PACKS_INFO if watching_vv => vv_idx = Some(i),
            ID_RESOURCE_PACK_STACK if state.rp_serving => rp_stack_seen = true,
            ID_TRANSFER if channel_transfer => transfer_idx = Some(i),
            // Track state for transfer teardown (boss bars/scoreboards — small packets, decode cost is negligible).
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
            // Track actor entities so they can be despawned on the next transfer. Live tracking only
            // sees small batches (large ones are skipped); the initial spawn's entities are captured
            // separately from the new server's spawn buffer (see downstream.rs).
            packets::ID_ADD_PLAYER if channel_transfer => {
                // Human NPCs (shops, etc.). actorRuntimeId == getId() in PMMP → valid for RemoveActor.
                if let Some(id) = packets::parse_add_player_runtime_id(p) {
                    state.entities.insert(id);
                }
            }
            packets::ID_ADD_ACTOR | packets::ID_ADD_ITEM_ACTOR | packets::ID_ADD_PAINTING
                if channel_transfer =>
            {
                if let Some(uid) = packets::parse_actor_unique_id(p) {
                    state.entities.insert(uid);
                }
            }
            packets::ID_REMOVE_ACTOR if channel_transfer => {
                if let Some(uid) = packets::parse_actor_unique_id(p) {
                    state.entities.remove(&uid);
                }
            }
            _ => {}
        }
    }

    if saw_network_settings && !state.compression_on {
        state.compression_on = true;
    }

    // TransferPacket takes priority — a transfer replaces the connection, so it wins over other processing in the same batch.
    if let Some(idx) = transfer_idx {
        if let Ok(server) = read_transfer_address(packets[idx]) {
            return Ok(Outcome::Transfer(server));
        }
    }

    // Start RP serving: replace only the ResourcePacksInfo packet in the batch with the proxy info packet;
    // preserve other packets in the batch (e.g. PlayStatus(LOGIN_SUCCESS)). No downstream response yet (HOLD).
    if rp_info_seen {
        if let Some(store) = packs {
            state.rp_serving = true;
            state.vv_done = true; // proxy info has forceDisableVibrantVisuals=0 so VV flip is unnecessary
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
            tracing::info!(packs = store.packs.len(), batch_others = others, "resource pack serving started — replaced downstream info (batch preserved)");
            return Ok(Outcome::Replace(out));
        }
    }

    // RP downstream Stack: do not forward to client (proxy stack already sent); respond to downstream with COMPLETED to advance.
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
        tracing::info!("Vibrant Visuals force-disable flag cleared (VV enabled)");
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
/// Reads the address (target server name) string.
fn read_transfer_address(packet: &[u8]) -> Result<String> {
    let (_, header_len) = read_varint_u32(packet)?;
    let rest = &packet[header_len..];
    let (str_len, consumed) = read_varint_u32(rest)?;
    let start = consumed;
    let end = start + str_len as usize;
    if end > rest.len() {
        anyhow::bail!("transfer address length overflow");
    }
    Ok(String::from_utf8_lossy(&rest[start..end]).into_owned())
}

/// Sets `forceDisableVibrantVisuals` (4th bool after the header) to false in a ResourcePacksInfoPacket.
/// Layout: `[header VarInt][mustAccept][hasAddons][hasScripts][forceDisableVibrantVisuals]...`
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
        // Downstream ResourcePacksInfo → replaced with proxy info + rp_serving set.
        let info_msg = frame_uncompressed(&[make_resource_packs_info(1)]);
        match intercept_down(&mut state, &info_msg, true, true, Some(&store)) {
            Outcome::Replace(_) => {}
            _ => panic!("expected Replace for RP info substitution"),
        }
        assert!(state.rp_serving);

        // Client COMPLETED → downstream receives HAVE_ALL (Inject to_server non-empty).
        let resp = frame_uncompressed(&[make_rp_response(RP_STATUS_COMPLETED)]);
        match intercept_up(&mut state, &resp, Some(&store)) {
            Outcome::Inject { to_server, .. } => assert!(!to_server.is_empty()),
            _ => panic!("expected Inject with downstream response on COMPLETED"),
        }
    }

    #[test]
    fn rp_disabled_keeps_vv_flip() {
        // With packs = None, the existing VV flip path is used (rp_serving stays false).
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_resource_packs_info(1)]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Replace(_) => {}
            _ => panic!("expected Replace for VV flip"),
        }
        assert!(!state.rp_serving);
    }

    #[test]
    fn detects_transfer_and_reads_server_name() {
        let mut state = SessionState::default();
        let msg = frame_uncompressed(&[make_transfer("island1")]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Transfer(s) => assert_eq!(s, "island1"),
            _ => panic!("expected Transfer to be detected"),
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
            _ => panic!("expected Replace with VV-flipped output"),
        }
        assert!(state.vv_done);
    }

    #[test]
    fn large_batch_forwarded_opaque_fast_path() {
        // Fast path: a batch larger than MAX_DECODE_BATCH_BYTES is forwarded opaquely (never decoded),
        // even with channel_transfer on. This is the "don't touch chunk data" rule.
        let mut state = SessionState { compression_on: true, vv_done: true, ..Default::default() };
        let big = vec![GAME_PACKET; MAX_DECODE_BATCH_BYTES + 100];
        assert!(matches!(
            intercept_down(&mut state, &big, true, true, None),
            Outcome::Forward
        ));
    }

    #[test]
    fn large_batch_forwarded_opaque_during_rp() {
        // Same fast-path skip applies during RP serving (vv done) — large batches are never decoded.
        let store = dummy_store();
        let mut state = SessionState { compression_on: true, vv_done: true, rp_serving: true, ..Default::default() };
        let big = vec![GAME_PACKET; MAX_DECODE_BATCH_BYTES + 100];
        assert!(matches!(
            intercept_down(&mut state, &big, false, false, Some(&store)),
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
        // Transfer is still watched after vv_done (small batches only).
        let mut state = SessionState { compression_on: false, vv_done: true, ..Default::default() };
        let msg = frame_uncompressed(&[make_transfer("spawn2")]);
        match intercept_down(&mut state, &msg, true, true, None) {
            Outcome::Transfer(s) => assert_eq!(s, "spawn2"),
            _ => panic!("expected transfer to be detected even after vv_done"),
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
        // Subsequent Login packets are ignored (captured only once).
        let _ = intercept_up(&mut state, &frame_uncompressed(&[make_login(b"second-different")]), None);
        assert_eq!(state.captured_login(), Some(first.as_slice()));
    }

    #[test]
    fn ignores_non_login_up_packets() {
        let mut state = SessionState::default();
        // Non-Login packets such as RequestNetworkSettings (0xc1) are not captured.
        let mut req = Vec::new();
        write_varint_u32(0xc1, &mut req);
        req.extend_from_slice(&[0, 0, 0, 0]);
        let _ = intercept_up(&mut state, &frame_uncompressed(&[req]), None);
        assert!(state.captured_login().is_none());
    }
}
