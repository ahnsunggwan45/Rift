//! New downstream handshake driver — on transfer, the proxy impersonates the client to drive login.
//!
//! The client is already fully logged in to the first server, so the proxy drives the login
//! handshake with the new server (B) itself by replaying the stored client Login packet.
//! Plaintext mode A (enable-encryption=false) means no encryption handshake is required.
//!
//! Sequence:
//!   RequestNetworkSettings → NetworkSettings → Login (replay)
//!     → ResourcePacksInfo → [HAVE_ALL_PACKS] → ResourcePackStack → [COMPLETED]
//!     → StartGame (extract runtime_id / spawn position) → [RequestChunkRadius] → buffer spawn stream
//!     → PlayStatus(PLAYER_SPAWN) (ready)
//!
//! After StartGame, the proxy sends RequestChunkRadius so the new server begins streaming chunks.
//! That stream (excluding StartGame) is buffered and replayed to the client after the transfer.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use rift_raknet::{RaknetSocket, Reliability};
use tokio::time::timeout;

use crate::compression;
use crate::framing::{build_batch, peek_packet_id, split_batch};
use crate::packets;

const GAME_PACKET: u8 = 0xfe;
const ID_NETWORK_SETTINGS: u32 = 0x8f;
const ID_RESOURCE_PACKS_INFO: u32 = 0x06;
const ID_RESOURCE_PACK_STACK: u32 = 0x07;
const ID_START_GAME: u32 = 0x0b;
const ID_PLAY_STATUS: u32 = 0x02;
const ID_DISCONNECT: u32 = 0x05;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// A new downstream that has completed handshake and spawn.
pub struct ReadyDownstream {
    pub socket: RaknetSocket,
    /// Player runtime entity ID assigned by the new server.
    /// (Matches the value the client already knows, thanks to the deterministic ID plugin — no rewriting needed.)
    pub runtime_id: u64,
    /// Spawn position [x,y,z] on the new server (client position after a dimension transfer).
    pub spawn_pos: [f32; 3],
    /// Player gamemode on the new server. Sent as SetPlayerGameType after transfer to sync the client HUD.
    pub gamemode: i32,
    /// Raw StartGame packet bytes (decompressed) from the new server. Used to extract game rules, etc.
    pub start_game: Vec<u8>,
    /// Boss bars and scoreboard objectives raised during the spawn stream (seed for the next transfer's teardown).
    pub bossbars: Vec<i64>,
    pub objectives: Vec<String>,
    /// Spawn stream messages sent by the new server from StartGame through PlayStatus(PLAYER_SPAWN),
    /// excluding the StartGame packet itself. Replayed to the client after the transfer to populate
    /// chunks, inventory, and entities — without this the client lands in an empty world (0-chunk bug).
    pub spawn_buffer: Vec<Vec<u8>>,
}

/// Connects to a new downstream and drives the client login handshake. Completes when StartGame is received.
pub async fn connect_and_handshake(
    addr: SocketAddr,
    raknet_version: u8,
    login_packet: &[u8],
) -> Result<ReadyDownstream> {
    match timeout(HANDSHAKE_TIMEOUT, drive(addr, raknet_version, login_packet)).await {
        Ok(r) => r,
        Err(_) => bail!("downstream handshake timed out ({addr})"),
    }
}

async fn drive(addr: SocketAddr, raknet_version: u8, login_packet: &[u8]) -> Result<ReadyDownstream> {
    let socket = RaknetSocket::connect_with_version(&addr, raknet_version)
        .await
        .map_err(|e| anyhow!("RakNet connection failed {addr}: {e:?}"))?;

    let protocol = packets::extract_login_protocol(login_packet)?;

    // 1) RequestNetworkSettings (uncompressed)
    let req = packets::frame_game_packet(
        &packets::request_network_settings(protocol),
        false,
        compression::NONE,
    )?;
    raknet_send(&socket, &req).await?;

    let mut compression_on = false;
    let mut got_start_game = false;
    let mut runtime_id: u64 = 0;
    let mut spawn_pos = [0.0f32; 3];
    let mut gamemode: i32 = 0;
    let mut start_game_bytes: Vec<u8> = Vec::new();
    let mut spawn_buffer: Vec<Vec<u8>> = Vec::new();
    // Track boss bars and scoreboard objectives on the new server (seed for the next transfer's teardown).
    let mut track_bossbars: HashSet<i64> = HashSet::new();
    let mut track_objectives: HashSet<String> = HashSet::new();

    loop {
        let msg = raknet_recv(&socket).await?;
        if msg.first() != Some(&GAME_PACKET) {
            continue;
        }
        let payload = &msg[1..];
        let (comp_type, batch_data): (u8, &[u8]) = if compression_on {
            match payload.split_first() {
                Some((&t, rest)) => (t, rest),
                None => continue,
            }
        } else {
            (compression::NONE, payload)
        };
        let batch = compression::decompress(comp_type, batch_data)?;
        let pkts = split_batch(&batch)?;

        let mut start_game_here = false;
        let mut saw_player_spawn = false;
        for pkt in &pkts {
            match peek_packet_id(pkt)? {
                ID_NETWORK_SETTINGS => {
                    // Compression enabled from here on. We send with zlib (server identifies type by the compression-type byte).
                    compression_on = true;
                    let login_msg =
                        packets::frame_game_packet(login_packet, true, compression::ZLIB)?;
                    raknet_send(&socket, &login_msg).await?;
                }
                ID_RESOURCE_PACKS_INFO => {
                    let resp = packets::frame_game_packet(
                        &packets::resource_pack_client_response(packets::RP_STATUS_HAVE_ALL_PACKS),
                        true,
                        compression::ZLIB,
                    )?;
                    raknet_send(&socket, &resp).await?;
                }
                ID_RESOURCE_PACK_STACK => {
                    let resp = packets::frame_game_packet(
                        &packets::resource_pack_client_response(packets::RP_STATUS_COMPLETED),
                        true,
                        compression::ZLIB,
                    )?;
                    raknet_send(&socket, &resp).await?;
                }
                ID_START_GAME => {
                    let (rid, pos, gm) = packets::extract_start_game_info(pkt)?;
                    runtime_id = rid;
                    spawn_pos = pos;
                    gamemode = gm;
                    start_game_bytes = pkt.to_vec();
                    got_start_game = true;
                    start_game_here = true;
                    // ★ Chunk streaming trigger. Without this RequestChunkRadius the new server
                    //   sent zero chunks (0-chunk bug) and the handshake stalled at StartGame.
                    let rcr = packets::frame_game_packet(
                        &packets::request_chunk_radius(8, 12),
                        true,
                        compression::ZLIB,
                    )?;
                    raknet_send(&socket, &rcr).await?;
                }
                ID_PLAY_STATUS => {
                    let st = packets::read_play_status(pkt).ok();
                    if got_start_game && st == Some(packets::PLAY_STATUS_PLAYER_SPAWN) {
                        saw_player_spawn = true;
                    } else if let Some(s) = st {
                        // Non-spawn PlayStatus may indicate a login failure code (1/2=version mismatch, 7=server full, etc.).
                        tracing::warn!(%addr, play_status = s, "non-spawn PlayStatus during handshake");
                    }
                }
                ID_DISCONNECT => {
                    // Downstream kicked us during handshake. The reason string is in the payload; log it lossily for diagnostics.
                    let dump: String = String::from_utf8_lossy(pkt)
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .take(180)
                        .collect();
                    tracing::warn!(%addr, raw = %dump.trim(), "downstream Disconnect (kick) received — reason in raw payload");
                }
                // Track initial boss bars and scoreboard objectives on the new server.
                packets::ID_BOSS_EVENT => {
                    if let Some((id, ev)) = packets::parse_boss_event(pkt) {
                        if ev == packets::BOSS_EVENT_TYPE_SHOW {
                            track_bossbars.insert(id);
                        } else if ev == packets::BOSS_EVENT_TYPE_HIDE {
                            track_bossbars.remove(&id);
                        }
                    }
                }
                packets::ID_SET_DISPLAY_OBJECTIVE => {
                    if let Some(name) = packets::parse_set_display_objective_name(pkt) {
                        track_objectives.insert(name);
                    }
                }
                packets::ID_REMOVE_OBJECTIVE => {
                    if let Some(name) = packets::parse_remove_objective_name(pkt) {
                        track_objectives.remove(&name);
                    }
                }
                _ => {}
            }
        }

        // Buffer the spawn stream after StartGame (replayed to the client after transfer).
        if got_start_game {
            if start_game_here {
                // Batch containing StartGame: keep everything except StartGame (ItemRegistry, inventory, stats, etc.).
                let kept: Vec<Vec<u8>> = pkts
                    .iter()
                    .filter(|p| peek_packet_id(p).ok() != Some(ID_START_GAME))
                    .map(|p| p.to_vec())
                    .collect();
                if !kept.is_empty() {
                    spawn_buffer.push(rebuild_message(&kept, compression_on, comp_type)?);
                }
            } else {
                // Pure spawn stream (chunks, publisher, entities, PlayStatus) — buffer the original message as-is.
                spawn_buffer.push(msg.clone());
            }
        }

        if saw_player_spawn {
            return Ok(ReadyDownstream {
                socket,
                runtime_id,
                spawn_pos,
                gamemode,
                start_game: start_game_bytes,
                bossbars: track_bossbars.into_iter().collect(),
                objectives: track_objectives.into_iter().collect(),
                spawn_buffer,
            });
        }
    }
}

/// Reassembles decompressed packets into a game-packet message (`[0xfe](+comp_type)[batch]`).
/// Used in drive() to reconstruct a batch with StartGame removed.
fn rebuild_message(packets: &[Vec<u8>], compressed: bool, comp_type: u8) -> Result<Vec<u8>> {
    let batch = build_batch(packets);
    let mut out = vec![GAME_PACKET];
    if compressed {
        out.push(comp_type);
        out.extend_from_slice(&compression::compress(comp_type, &batch)?);
    } else {
        out.extend_from_slice(&batch);
    }
    Ok(out)
}

async fn raknet_send(socket: &RaknetSocket, msg: &[u8]) -> Result<()> {
    socket
        .send(msg, Reliability::ReliableOrdered)
        .await
        .map_err(|e| anyhow!("downstream send failed: {e:?}"))
}

async fn raknet_recv(socket: &RaknetSocket) -> Result<Vec<u8>> {
    // Handshake path (not hot path) — one Bytes→Vec copy is acceptable. The relay hot path uses Bytes directly.
    match timeout(RECV_TIMEOUT, socket.recv()).await {
        Ok(Ok(data)) => Ok(data.to_vec()),
        Ok(Err(e)) => bail!("downstream recv failed: {e:?}"),
        Err(_) => bail!("downstream recv timed out"),
    }
}
