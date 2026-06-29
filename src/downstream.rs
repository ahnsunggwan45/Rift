//! 새 다운스트림 핸드셰이크 드라이버 — 채널이동 시 프록시가 클라 행세로 로그인 구동.
//!
//! 클라는 이미 첫 서버에 로그인 완료 상태라, 새 서버(B)의 로그인 핸드셰이크는
//! 프록시가 직접 수행한다(저장한 클라 Login 리플레이). 평문 A모드(enable-encryption=false)
//! 라 암호화 핸드셰이크는 없다.
//!
//! 시퀀스:
//!   RequestNetworkSettings → NetworkSettings → Login(리플레이)
//!     → ResourcePacksInfo → [HAVE_ALL_PACKS] → ResourcePackStack → [COMPLETED]
//!     → StartGame (runtime_id/스폰위치 추출) → [RequestChunkRadius] → 스폰 스트림 버퍼링
//!     → PlayStatus(PLAYER_SPAWN) (준비 완료)
//!
//! StartGame 에서 멈추지 않고 RequestChunkRadius 를 보내 새 서버가 청크를 스트리밍하게
//! 하고, 그 스트림(StartGame 제외)을 버퍼에 모은다. 전환 후 클라에 재생한다.

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

/// 핸드셰이크 + 스폰까지 완료된 새 다운스트림.
pub struct ReadyDownstream {
    pub socket: RaknetSocket,
    /// 새 서버가 부여한 플레이어 runtime entity id.
    /// (결정론 ID 플러그인 덕에 클라가 인식 중인 값과 동일 — 재작성 불필요.)
    pub runtime_id: u64,
    /// 새 서버의 스폰 위치 [x,y,z] (디멘션 전환 시 클라 위치).
    pub spawn_pos: [f32; 3],
    /// 새 서버의 playerGamemode. 전환 후 SetPlayerGameType 으로 클라 HUD 동기화.
    pub gamemode: i32,
    /// 새 서버 StartGame 패킷(압축 해제된 바이트). 게임룰 등 추출용.
    pub start_game: Vec<u8>,
    /// 새 서버가 스폰 스트림에서 띄운 보스바/스코어보드(전환 후 다음 전환 대비 추적 시드).
    pub bossbars: Vec<i64>,
    pub objectives: Vec<String>,
    /// StartGame 직후부터 PlayStatus(PLAYER_SPAWN) 까지 새 서버가 보낸 스폰 스트림
    /// (StartGame 패킷만 제외한 원본 게임패킷 메시지들). 클라 전환 후 그대로 재생해
    /// 청크/인벤토리/엔티티를 채운다 — 이게 없으면 클라가 빈 월드에 떨어진다(0-청크 버그).
    pub spawn_buffer: Vec<Vec<u8>>,
}

/// 새 다운스트림에 연결하고 클라 로그인 핸드셰이크를 구동한다. StartGame 까지 받으면 완료.
pub async fn connect_and_handshake(
    addr: SocketAddr,
    raknet_version: u8,
    login_packet: &[u8],
) -> Result<ReadyDownstream> {
    match timeout(HANDSHAKE_TIMEOUT, drive(addr, raknet_version, login_packet)).await {
        Ok(r) => r,
        Err(_) => bail!("다운스트림 핸드셰이크 타임아웃 ({addr})"),
    }
}

async fn drive(addr: SocketAddr, raknet_version: u8, login_packet: &[u8]) -> Result<ReadyDownstream> {
    let socket = RaknetSocket::connect_with_version(&addr, raknet_version)
        .await
        .map_err(|e| anyhow!("RakNet 연결 실패 {addr}: {e:?}"))?;

    let protocol = packets::extract_login_protocol(login_packet)?;

    // 1) RequestNetworkSettings (비압축)
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
    // 새 서버 초기 보스바/스코어보드 추적(전환 후 다음 전환 teardown 시드용).
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
                    // 이후 압축 ON. 우리 송신은 zlib 로(서버가 압축타입 바이트로 판별).
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
                    // ★ 청크 스트리밍 트리거. 이 RequestChunkRadius 가 없어서 새 서버가
                    //   청크를 한 개도 안 보냈고(0-청크 버그), 핸드셰이크가 StartGame 에서 멈췄다.
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
                        // 스폰 외 PlayStatus = 로그인 실패 코드일 수 있음(1/2=버전 불일치, 7=서버 가득 등). 진단.
                        tracing::warn!(%addr, play_status = s, "핸드셰이크 중 비-스폰 PlayStatus");
                    }
                }
                ID_DISCONNECT => {
                    // 다운스트림이 핸드셰이크 중 kick. 사유 문자열이 페이로드에 있어 lossy 로 찍어 진단한다.
                    let dump: String = String::from_utf8_lossy(pkt)
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .take(180)
                        .collect();
                    tracing::warn!(%addr, raw = %dump.trim(), "다운스트림 Disconnect(kick) 수신 — raw 에 사유 포함");
                }
                // 새 서버 초기 보스바/스코어보드 추적.
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

        // StartGame 이후의 스폰 스트림을 버퍼링(전환 후 클라에 재생).
        if got_start_game {
            if start_game_here {
                // StartGame 이 든 배치: StartGame 만 빼고 나머지(ItemRegistry/인벤/능력치 등)는 버퍼.
                let kept: Vec<Vec<u8>> = pkts
                    .iter()
                    .filter(|p| peek_packet_id(p).ok() != Some(ID_START_GAME))
                    .map(|p| p.to_vec())
                    .collect();
                if !kept.is_empty() {
                    spawn_buffer.push(rebuild_message(&kept, compression_on, comp_type)?);
                }
            } else {
                // 순수 스폰 스트림(청크/퍼블리셔/엔티티/PlayStatus) — 원본 메시지 그대로 버퍼.
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

/// 압축 해제된 패킷들을 다시 게임패킷 메시지(`[0xfe](+comp_type)[batch]`)로 묶는다.
/// drive() 에서 StartGame 을 제거한 배치를 재구성할 때 사용.
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
        .map_err(|e| anyhow!("다운스트림 send 실패: {e:?}"))
}

async fn raknet_recv(socket: &RaknetSocket) -> Result<Vec<u8>> {
    // 핸드셰이크 경로(핫패스 아님) — Bytes→Vec 1회 복사 수용. 릴레이 핫패스는 Bytes 그대로 사용.
    match timeout(RECV_TIMEOUT, socket.recv()).await {
        Ok(Ok(data)) => Ok(data.to_vec()),
        Ok(Err(e)) => bail!("다운스트림 recv 실패: {e:?}"),
        Err(_) => bail!("다운스트림 recv 타임아웃"),
    }
}
