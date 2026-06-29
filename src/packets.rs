//! 다운스트림 핸드셰이크용 패킷 생성/파싱 (프록시가 새 서버에 클라 행세할 때).
//!
//! 프록시가 *보내는* 패킷: RequestNetworkSettings, ResourcePackClientResponse.
//! 프록시가 *읽는* 값: Login 의 protocol, StartGame 의 actorRuntimeId.

#![allow(dead_code)] // 핸드셰이크 드라이버 배선 전까지 일부 미사용

use anyhow::{Context, Result};

use crate::compression;
use crate::framing::{
    build_batch, read_varint_u32, read_varint_u64, read_zigzag_i32, read_zigzag_i64,
    write_varint_u32, write_varint_u64, write_zigzag_i32, write_zigzag_i64,
};

pub const ID_REQUEST_NETWORK_SETTINGS: u32 = 0xc1;
pub const ID_RESOURCE_PACK_CLIENT_RESPONSE: u32 = 0x08;
pub const ID_PLAY_STATUS: u32 = 0x02;
pub const ID_CHANGE_DIMENSION: u32 = 0x3d;
pub const ID_REQUEST_CHUNK_RADIUS: u32 = 0x45;
pub const ID_LEVEL_CHUNK: u32 = 0x3a;
pub const ID_PLAYER_ACTION: u32 = 0x24;
pub const ID_SET_LOCAL_PLAYER_INITIALIZED: u32 = 0x71;
pub const ID_SET_PLAYER_GAME_TYPE: u32 = 0x3e;
pub const ID_GAME_RULES_CHANGED: u32 = 0x48;
pub const ID_BOSS_EVENT: u32 = 0x4a;
pub const ID_SET_DISPLAY_OBJECTIVE: u32 = 0x6b;
pub const ID_REMOVE_OBJECTIVE: u32 = 0x6a;

// GameRuleType.
const GAMERULE_TYPE_BOOL: u32 = 1;
const GAMERULE_TYPE_INT: u32 = 2;
const GAMERULE_TYPE_FLOAT: u32 = 3;

// BossEvent eventType (전환 teardown 추적용).
pub const BOSS_EVENT_TYPE_SHOW: u8 = 0;
pub const BOSS_EVENT_TYPE_HIDE: u8 = 2;

// ResourcePackClientResponse status
pub const RP_STATUS_HAVE_ALL_PACKS: u8 = 3;
pub const RP_STATUS_COMPLETED: u8 = 4;

// PlayStatus status
pub const PLAY_STATUS_PLAYER_SPAWN: u32 = 3;

// PlayerAction action id (zigzag VarInt). 차원전환 ACK = 14 (PMMP PlayerAction::DIMENSION_CHANGE_ACK).
pub const PLAYER_ACTION_DIMENSION_CHANGE_DONE: i32 = 14;

// DimensionIds.
pub const DIM_OVERWORLD: i32 = 0;
pub const DIM_NETHER: i32 = 1;
pub const DIM_END: i32 = 2;

const GAME_PACKET: u8 = 0xfe;

/// RequestNetworkSettings 패킷: `[VarInt 0xc1][BE u32 protocol]`.
pub fn request_network_settings(protocol: u32) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_REQUEST_NETWORK_SETTINGS, &mut p);
    p.extend_from_slice(&protocol.to_be_bytes());
    p
}

/// ResourcePackClientResponse 패킷: `[VarInt 0x08][status u8][LE u16 packIds=0]`.
pub fn resource_pack_client_response(status: u8) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_RESOURCE_PACK_CLIENT_RESPONSE, &mut p);
    p.push(status);
    p.extend_from_slice(&[0u8, 0u8]); // packIds count = 0 (LE u16)
    p
}

/// 단일 패킷을 게임패킷 메시지로 프레이밍한다.
/// `compressed=false` 면 `[0xfe][raw batch]`, true 면 `[0xfe][comp_type][압축 batch]`.
pub fn frame_game_packet(packet: &[u8], compressed: bool, comp_type: u8) -> Result<Vec<u8>> {
    let batch = build_batch(&[packet.to_vec()]);
    let mut msg = vec![GAME_PACKET];
    if compressed {
        msg.push(comp_type);
        msg.extend_from_slice(&compression::compress(comp_type, &batch)?);
    } else {
        msg.extend_from_slice(&batch);
    }
    Ok(msg)
}

/// Login 패킷에서 protocol(헤더 다음 BE u32)을 추출한다.
pub fn extract_login_protocol(login_packet: &[u8]) -> Result<u32> {
    let (_, header_len) = read_varint_u32(login_packet)?;
    let bytes = login_packet
        .get(header_len..header_len + 4)
        .context("Login protocol 필드 부족")?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// StartGame 패킷에서 actorRuntimeId 를 추출한다.
pub fn extract_start_game_runtime_id(start_game: &[u8]) -> Result<u64> {
    Ok(extract_start_game_info(start_game)?.0)
}

/// StartGame 에서 (actorRuntimeId, 스폰위치[x,y,z], playerGamemode) 를 추출한다.
/// 레이아웃: `[header][actorUniqueId zigzag-VarLong][actorRuntimeId VarLong][playerGamemode zigzag-VarInt][pos 3×LE f32]...`
pub fn extract_start_game_info(start_game: &[u8]) -> Result<(u64, [f32; 3], i32)> {
    let (_, header_len) = read_varint_u32(start_game)?;
    let mut off = header_len;
    let (_unique, n1) = read_zigzag_i64(start_game.get(off..).context("StartGame unique id 부족")?)?;
    off += n1;
    let (runtime, n2) = read_varint_u64(start_game.get(off..).context("StartGame runtime id 부족")?)?;
    off += n2;
    let (gamemode, n3) = read_zigzag_i32(start_game.get(off..).context("StartGame gamemode 부족")?)?;
    off += n3;
    let pos = start_game.get(off..off + 12).context("StartGame position 부족")?;
    let x = f32::from_le_bytes([pos[0], pos[1], pos[2], pos[3]]);
    let y = f32::from_le_bytes([pos[4], pos[5], pos[6], pos[7]]);
    let z = f32::from_le_bytes([pos[8], pos[9], pos[10], pos[11]]);
    Ok((runtime, [x, y, z], gamemode))
}

/// ChangeDimensionPacket: `[header][dimension zigzag-VarInt][pos 3×LE f32][respawn u8][loadingScreenId optional=0]`.
pub fn change_dimension(dimension: i32, pos: [f32; 3], respawn: bool) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_CHANGE_DIMENSION, &mut p);
    write_zigzag_i32(dimension, &mut p);
    for c in pos {
        p.extend_from_slice(&c.to_le_bytes());
    }
    p.push(respawn as u8);
    p.push(0x00); // loadingScreenId: optional, none
    p
}

/// PlayStatusPacket: `[header][status BE u32]`.
pub fn play_status(status: u32) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_PLAY_STATUS, &mut p);
    p.extend_from_slice(&status.to_be_bytes());
    p
}

/// PlayStatusPacket 의 status(BE u32) 를 읽는다. (전환 핸드셰이크에서 PLAYER_SPAWN 감지용)
pub fn read_play_status(packet: &[u8]) -> Result<u32> {
    let (_, hl) = read_varint_u32(packet)?;
    let b = packet.get(hl..hl + 4).context("PlayStatus status 필드 부족")?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// RequestChunkRadiusPacket: `[header][radius zigzag][maxRadius u8]`.
/// 프록시가 새 서버에 보내 청크 스트리밍을 시작시킨다(이게 빠져서 청크가 0개였음).
pub fn request_chunk_radius(radius: i32, max_radius: u8) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_REQUEST_CHUNK_RADIUS, &mut p);
    write_zigzag_i32(radius, &mut p);
    p.push(max_radius);
    p
}

/// SetLocalPlayerAsInitializedPacket: `[header][actorRuntimeId UVarLong]`.
/// 프록시가 새 서버에 보내 doFirstSpawn(엔티티/후속 스트리밍)을 트리거한다.
pub fn set_local_player_as_initialized(runtime_id: u64) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_SET_LOCAL_PLAYER_INITIALIZED, &mut p);
    write_varint_u64(runtime_id, &mut p);
    p
}

/// SetPlayerGameTypePacket: `[header][gamemode zigzag-VarInt]`.
/// 전환 시 클라 게임모드 HUD(체력바 표시 등)를 새 서버 값으로 동기화.
/// (StartGame 을 클라에 안 보내므로 게임모드를 따로 알려줘야 한다.)
pub fn set_player_game_type(gamemode: i32) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_SET_PLAYER_GAME_TYPE, &mut p);
    write_zigzag_i32(gamemode, &mut p);
    p
}

/// GameRulesChangedPacket: `[header][gameRules 배열(isStartGame=false)]`.
/// body 는 extract_start_game_gamerules() 가 만든 재인코딩 배열.
pub fn game_rules_changed(body: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + body.len());
    write_varint_u32(ID_GAME_RULES_CHANGED, &mut p);
    p.extend_from_slice(body);
    p
}

/// BossEventPacket(HIDE) — 1.26.30 평탄화 레이아웃(8필드 무조건 인코딩).
/// 전환 시 옛 서버 보스바를 클라에서 제거.
pub fn boss_event_hide(boss_unique_id: i64) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_BOSS_EVENT, &mut p);
    write_zigzag_i64(boss_unique_id, &mut p); // bossActorUniqueId
    write_zigzag_i64(0, &mut p); // playerActorUniqueId
    p.push(BOSS_EVENT_TYPE_HIDE); // eventType
    write_varint_u32(0, &mut p); // title (빈 string)
    write_varint_u32(0, &mut p); // filteredTitle (빈 string)
    p.extend_from_slice(&0f32.to_le_bytes()); // healthPercent
    p.push(0); // color
    p.push(0); // overlay
    p
}

/// RemoveObjectivePacket — 전환 시 옛 서버 스코어보드(목표)를 클라에서 제거.
pub fn remove_objective(name: &str) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_REMOVE_OBJECTIVE, &mut p);
    write_varint_u32(name.len() as u32, &mut p);
    p.extend_from_slice(name.as_bytes());
    p
}

/// 오프셋의 string(UnsignedVarInt 길이 + 바이트)을 읽는다. (값, 새 오프셋은 호출측이 계산 불필요)
fn read_string_at(buf: &[u8], off: usize) -> Option<String> {
    let (len, n) = read_varint_u32(buf.get(off..)?).ok()?;
    let start = off + n;
    let end = start + len as usize;
    Some(String::from_utf8_lossy(buf.get(start..end)?).into_owned())
}

/// BossEventPacket 에서 (bossActorUniqueId, eventType)을 추출(보스바 추적용). best-effort.
pub fn parse_boss_event(pkt: &[u8]) -> Option<(i64, u8)> {
    let (_, hl) = read_varint_u32(pkt).ok()?;
    let mut off = hl;
    let (boss_id, n) = read_zigzag_i64(pkt.get(off..)?).ok()?;
    off += n;
    let (_player, n) = read_zigzag_i64(pkt.get(off..)?).ok()?;
    off += n;
    Some((boss_id, *pkt.get(off)?))
}

/// SetDisplayObjectivePacket 에서 objectiveName(displaySlot 다음 두번째 string)을 추출. best-effort.
pub fn parse_set_display_objective_name(pkt: &[u8]) -> Option<String> {
    let (_, hl) = read_varint_u32(pkt).ok()?;
    let off = skip_string(pkt, hl).ok()?; // displaySlot
    read_string_at(pkt, off)
}

/// RemoveObjectivePacket 에서 objectiveName 을 추출. best-effort.
pub fn parse_remove_objective_name(pkt: &[u8]) -> Option<String> {
    let (_, hl) = read_varint_u32(pkt).ok()?;
    read_string_at(pkt, hl)
}

/// string(UnsignedVarInt 길이 + 바이트)을 건너뛴 새 오프셋.
fn skip_string(buf: &[u8], off: usize) -> Result<usize> {
    let (len, n) = read_varint_u32(buf.get(off..).context("string 길이 부족")?)?;
    let end = off + n + len as usize;
    if end > buf.len() {
        anyhow::bail!("string 잘림");
    }
    Ok(end)
}

/// StartGame 의 gameRules 를 추출해 GameRulesChangedPacket 본문으로 **재인코딩**한다.
/// StartGame(isStartGame=true)은 int 게임룰 값을 VarInt 로, GameRulesChanged(false)는 LE u32 로
/// 쓰므로 그대로 복사 불가 → int 만 변환, bool/float 는 그대로. (LevelSettings 필드 워킹)
///
/// 전환 시 클라에 보내 좌표표시 등 게임룰을 새 서버 값으로 맞춘다. 실패 시 Err(전환은 계속).
pub fn extract_start_game_gamerules(sg: &[u8]) -> Result<Vec<u8>> {
    let (_, hdr) = read_varint_u32(sg)?;
    let mut off = hdr;

    fn need(sg: &[u8], off: usize, n: usize) -> Result<()> {
        if off + n > sg.len() {
            anyhow::bail!("StartGame 잘림 (off={off} need={n} len={})", sg.len());
        }
        Ok(())
    }

    // StartGame 선행 필드 (header 직후)
    let (_, n) = read_zigzag_i64(sg.get(off..).context("actorUniqueId")?)?;
    off += n;
    let (_, n) = read_varint_u64(sg.get(off..).context("actorRuntimeId")?)?;
    off += n;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("playerGamemode")?)?;
    off += n;
    need(sg, off, 20)?;
    off += 20; // playerPosition(12) + pitch(4) + yaw(4)

    // LevelSettings::read
    need(sg, off, 8)?;
    off += 8; // seed (LE u64)
    // SpawnSettings: biomeType(LE u16) + biomeName(string) + dimension(zigzag VarInt)
    need(sg, off, 2)?;
    off += 2;
    off = skip_string(sg, off)?;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("dimension")?)?;
    off += n;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("generator")?)?;
    off += n;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("worldGamemode")?)?;
    off += n;
    need(sg, off, 1)?;
    off += 1; // hardcore
    let (_, n) = read_zigzag_i32(sg.get(off..).context("difficulty")?)?;
    off += n;
    // spawnPosition: BlockPosition (3× zigzag VarInt)
    for _ in 0..3 {
        let (_, n) = read_zigzag_i32(sg.get(off..).context("spawnPosition")?)?;
        off += n;
    }
    need(sg, off, 1)?;
    off += 1; // hasAchievementsDisabled
    let (_, n) = read_zigzag_i32(sg.get(off..).context("editorWorldType")?)?;
    off += n;
    need(sg, off, 2)?;
    off += 2; // createdInEditorMode, exportedFromEditorMode
    let (_, n) = read_zigzag_i32(sg.get(off..).context("time")?)?;
    off += n;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("eduEditionOffer")?)?;
    off += n;
    need(sg, off, 1)?;
    off += 1; // hasEduFeaturesEnabled
    off = skip_string(sg, off)?; // eduProductUUID
    need(sg, off, 8)?;
    off += 8; // rainLevel, lightningLevel (LE f32 ×2)
    need(sg, off, 3)?;
    off += 3; // hasConfirmedPlatformLockedContent, isMultiplayerGame, hasLANBroadcast
    let (_, n) = read_zigzag_i32(sg.get(off..).context("xboxLiveBroadcastMode")?)?;
    off += n;
    let (_, n) = read_zigzag_i32(sg.get(off..).context("platformBroadcastMode")?)?;
    off += n;
    need(sg, off, 2)?;
    off += 2; // commandsEnabled, isTexturePacksRequired

    // gameRules (isStartGame=true) → GameRulesChanged body (isStartGame=false)
    let (count, n) = read_varint_u32(sg.get(off..).context("gameRules count")?)?;
    off += n;
    let mut body = Vec::new();
    write_varint_u32(count, &mut body);
    for _ in 0..count {
        let (slen, n) = read_varint_u32(sg.get(off..).context("rule name len")?)?;
        off += n;
        let slen = slen as usize;
        need(sg, off, slen)?;
        write_varint_u32(slen as u32, &mut body);
        body.extend_from_slice(&sg[off..off + slen]);
        off += slen;
        need(sg, off, 1)?;
        body.push(sg[off]); // isPlayerModifiable
        off += 1;
        let (ty, n) = read_varint_u32(sg.get(off..).context("rule type")?)?;
        off += n;
        write_varint_u32(ty, &mut body);
        match ty {
            GAMERULE_TYPE_BOOL => {
                need(sg, off, 1)?;
                body.push(sg[off]);
                off += 1;
            }
            GAMERULE_TYPE_INT => {
                // StartGame: UnsignedVarInt → GameRulesChanged: LE u32
                let (v, n) = read_varint_u32(sg.get(off..).context("int rule value")?)?;
                off += n;
                body.extend_from_slice(&v.to_le_bytes());
            }
            GAMERULE_TYPE_FLOAT => {
                need(sg, off, 4)?;
                body.extend_from_slice(&sg[off..off + 4]);
                off += 4;
            }
            other => anyhow::bail!("알 수 없는 게임룰 타입 {other}"),
        }
    }
    Ok(body)
}

/// PlayerActionPacket: `[header][actorRuntimeId UVarLong][action zigzag][blockPos 3×zigzag][resultPos 3×zigzag][face zigzag]`.
/// 전환 시 차원변경 ACK(DIMENSION_CHANGE_DONE)를 클라에 주입 — 블록/결과 좌표·face 는 0.
pub fn player_action(runtime_id: u64, action: i32) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_PLAYER_ACTION, &mut p);
    write_varint_u64(runtime_id, &mut p);
    write_zigzag_i32(action, &mut p);
    for _ in 0..3 {
        write_zigzag_i32(0, &mut p); // blockPosition (x,y,z)
    }
    for _ in 0..3 {
        write_zigzag_i32(0, &mut p); // resultPosition (x,y,z)
    }
    write_zigzag_i32(0, &mut p); // face
    p
}

/// 차원별 바이옴 섹션 수(= 프로토콜 청크 높이 경계 폭). ChunkSerializer::getDimensionChunkBounds 기준.
pub fn dimension_biome_sections(dimension: i32) -> usize {
    match dimension {
        DIM_NETHER => 8, // [0,7]
        DIM_END => 16,   // [0,15]
        _ => 24,         // overworld [-4,19]
    }
}

/// 빈(공기) 청크 페이로드. WDPE/PMMP ChunkSerializer 와 바이트 동일하게 구성:
/// 빈 서브청크 1개(`08 00`) + 바이옴 팔레트(첫 섹션은 풀, 나머지는 이전-복사 마커) + 보더(0).
/// 차원 플립 시 로딩 화면 필러로 클라에 보낸다. `biome_sections` = dimension_biome_sections().
pub fn empty_chunk_payload(biome_sections: usize) -> Vec<u8> {
    let mut p = Vec::with_capacity(2 + 1 + 512 + 2 + biome_sections + 1);
    // 빈 서브청크 1개: version 8, 블록 스토리지 레이어 0개.
    p.push(8);
    p.push(0);
    // 바이옴 섹션 0: bitsPerBlock=1 + runtime 플래그 → (1<<1)|1 = 3. words 512바이트(전부 인덱스 0),
    // 팔레트 크기 1(zigzag), 팔레트 엔트리 biome 0(zigzag). (ChunkSerializer.php:153-167)
    p.push((1 << 1) | 1);
    p.extend(std::iter::repeat(0u8).take(512));
    write_zigzag_i32(1, &mut p); // 팔레트 크기 (intentionally zigzag)
    write_zigzag_i32(0, &mut p); // biome id 0
    // 나머지 바이옴 섹션: 이전 섹션 복사 마커 (127<<1)|1 = 0xFF.
    for _ in 1..biome_sections {
        p.push((127 << 1) | 1);
    }
    // 보더 블록 수 0.
    p.push(0);
    p
}

/// LevelChunkPacket: `[header][chunkX zigzag][chunkZ zigzag][dimension zigzag][subChunkCount UVarInt][cacheEnabled bool][extraPayload string]`.
pub fn level_chunk(chunk_x: i32, chunk_z: i32, dimension: i32, sub_chunk_count: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_LEVEL_CHUNK, &mut p);
    write_zigzag_i32(chunk_x, &mut p);
    write_zigzag_i32(chunk_z, &mut p);
    write_zigzag_i32(dimension, &mut p);
    write_varint_u32(sub_chunk_count, &mut p);
    p.push(0); // cacheEnabled = false (블롭 캐시 미사용)
    write_varint_u32(payload.len() as u32, &mut p);
    p.extend_from_slice(payload);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{peek_packet_id, split_batch};

    #[test]
    fn request_network_settings_roundtrip() {
        let p = request_network_settings(0x3e9); // 1001
        assert_eq!(peek_packet_id(&p).unwrap(), ID_REQUEST_NETWORK_SETTINGS);
        // protocol 은 헤더(2바이트 VarInt for 0xc1) 다음 BE u32
        let (_, hl) = read_varint_u32(&p).unwrap();
        assert_eq!(&p[hl..hl + 4], &0x3e9u32.to_be_bytes());
    }

    #[test]
    fn resource_pack_response_format() {
        let p = resource_pack_client_response(RP_STATUS_COMPLETED);
        assert_eq!(peek_packet_id(&p).unwrap(), ID_RESOURCE_PACK_CLIENT_RESPONSE);
        let (_, hl) = read_varint_u32(&p).unwrap();
        assert_eq!(p[hl], RP_STATUS_COMPLETED);
        assert_eq!(&p[hl + 1..hl + 3], &[0, 0]); // packIds = 0
    }

    #[test]
    fn frame_uncompressed_and_compressed() {
        let pkt = request_network_settings(100);
        let raw = frame_game_packet(&pkt, false, compression::NONE).unwrap();
        assert_eq!(raw[0], GAME_PACKET);
        let packets = split_batch(&raw[1..]).unwrap();
        assert_eq!(packets[0], pkt.as_slice());

        let zlib = frame_game_packet(&pkt, true, compression::ZLIB).unwrap();
        assert_eq!(zlib[0], GAME_PACKET);
        assert_eq!(zlib[1], compression::ZLIB);
        let decompressed = compression::decompress(compression::ZLIB, &zlib[2..]).unwrap();
        assert_eq!(split_batch(&decompressed).unwrap()[0], pkt.as_slice());
    }

    #[test]
    fn extract_protocol_from_login() {
        // Login 모형: [header 0x01][BE u32 protocol][...]
        let mut login = Vec::new();
        write_varint_u32(0x01, &mut login);
        login.extend_from_slice(&0x3e9u32.to_be_bytes());
        login.extend_from_slice(b"connreq...");
        assert_eq!(extract_login_protocol(&login).unwrap(), 0x3e9);
    }

    #[test]
    fn extract_runtime_id_and_pos_from_start_game() {
        // StartGame 모형: [header 0x0b][uniqueId zigzag][runtimeId varlong][gamemode zigzag][pos 3×LE f32]...
        let mut sg = Vec::new();
        write_varint_u32(0x0b, &mut sg);
        sg.push(0x0a); // actorUniqueId = 5 (zigzag)
        sg.push(0xd2);
        sg.push(0x09); // actorRuntimeId = 1234
        sg.push(0x02); // playerGamemode = 1 (zigzag)
        sg.extend_from_slice(&100.5f32.to_le_bytes()); // x
        sg.extend_from_slice(&64.0f32.to_le_bytes()); // y
        sg.extend_from_slice(&(-200.0f32).to_le_bytes()); // z
        sg.extend_from_slice(b"rest");

        let (rid, pos, gm) = extract_start_game_info(&sg).unwrap();
        assert_eq!(rid, 1234);
        assert_eq!(pos, [100.5, 64.0, -200.0]);
        assert_eq!(gm, 1); // playerGamemode = 1 (creative)
        assert_eq!(extract_start_game_runtime_id(&sg).unwrap(), 1234);
    }

    #[test]
    fn set_player_game_type_format() {
        let p = set_player_game_type(1);
        assert_eq!(peek_packet_id(&p).unwrap(), ID_SET_PLAYER_GAME_TYPE);
        let (_, hl) = read_varint_u32(&p).unwrap();
        assert_eq!(p[hl], 0x02); // gamemode 1 zigzag
    }

    #[test]
    fn extract_gamerules_transcodes_int_to_le() {
        // 합성 StartGame: 선행 필드는 0/빈값, gameRules 만 의미있게 채운다.
        let mut sg = Vec::new();
        write_varint_u32(0x0b, &mut sg); // header
        sg.push(0x00); // actorUniqueId zigzag 0
        sg.push(0x00); // actorRuntimeId uVL 0
        sg.push(0x00); // playerGamemode zigzag 0
        sg.extend_from_slice(&[0u8; 20]); // pos(12)+pitch(4)+yaw(4)
        // LevelSettings
        sg.extend_from_slice(&[0u8; 8]); // seed
        sg.extend_from_slice(&[0u8, 0u8]); // biomeType (LE u16)
        sg.push(0x00); // biomeName len 0
        sg.push(0x00); // dimension
        sg.push(0x00); // generator
        sg.push(0x00); // worldGamemode
        sg.push(0x00); // hardcore
        sg.push(0x00); // difficulty
        sg.extend_from_slice(&[0u8, 0u8, 0u8]); // spawnPosition
        sg.push(0x00); // hasAchievementsDisabled
        sg.push(0x00); // editorWorldType
        sg.extend_from_slice(&[0u8, 0u8]); // created/exported editor mode
        sg.push(0x00); // time
        sg.push(0x00); // eduEditionOffer
        sg.push(0x00); // hasEduFeaturesEnabled
        sg.push(0x00); // eduProductUUID len 0
        sg.extend_from_slice(&[0u8; 8]); // rainLevel, lightningLevel
        sg.extend_from_slice(&[0u8, 0u8, 0u8]); // 3 bools
        sg.push(0x00); // xboxLiveBroadcastMode
        sg.push(0x00); // platformBroadcastMode
        sg.extend_from_slice(&[0u8, 0u8]); // commandsEnabled, isTexturePacksRequired
        // gameRules: count=2
        write_varint_u32(2, &mut sg);
        write_varint_u32(4, &mut sg);
        sg.extend_from_slice(b"test"); // name
        sg.push(1); // isPlayerModifiable
        write_varint_u32(GAMERULE_TYPE_BOOL, &mut sg);
        sg.push(1); // bool value
        write_varint_u32(1, &mut sg);
        sg.extend_from_slice(b"n"); // name
        sg.push(0); // isPlayerModifiable
        write_varint_u32(GAMERULE_TYPE_INT, &mut sg);
        write_varint_u32(300, &mut sg); // int value as VarInt (StartGame side)
        sg.extend_from_slice(b"junk-after-gamerules"); // 무시돼야 함

        let body = extract_start_game_gamerules(&sg).unwrap();
        let mut expected = Vec::new();
        write_varint_u32(2, &mut expected);
        write_varint_u32(4, &mut expected);
        expected.extend_from_slice(b"test");
        expected.push(1);
        write_varint_u32(GAMERULE_TYPE_BOOL, &mut expected);
        expected.push(1);
        write_varint_u32(1, &mut expected);
        expected.extend_from_slice(b"n");
        expected.push(0);
        write_varint_u32(GAMERULE_TYPE_INT, &mut expected);
        expected.extend_from_slice(&300u32.to_le_bytes()); // int → LE u32 (GameRulesChanged side)
        assert_eq!(body, expected);

        // 래퍼가 헤더를 붙이고 본문을 보존하는지.
        let pkt = game_rules_changed(&body);
        assert_eq!(peek_packet_id(&pkt).unwrap(), ID_GAME_RULES_CHANGED);
    }

    #[test]
    fn boss_event_hide_roundtrips_via_parse() {
        let p = boss_event_hide(-42);
        assert_eq!(peek_packet_id(&p).unwrap(), ID_BOSS_EVENT);
        let (id, ev) = parse_boss_event(&p).unwrap();
        assert_eq!(id, -42);
        assert_eq!(ev, BOSS_EVENT_TYPE_HIDE);
    }

    #[test]
    fn remove_objective_roundtrips_via_parse() {
        let p = remove_objective("sidebar_obj");
        assert_eq!(peek_packet_id(&p).unwrap(), ID_REMOVE_OBJECTIVE);
        assert_eq!(parse_remove_objective_name(&p).unwrap(), "sidebar_obj");
    }

    #[test]
    fn parse_set_display_objective_reads_second_string() {
        // [header][displaySlot string][objectiveName string][...]
        let mut p = Vec::new();
        write_varint_u32(ID_SET_DISPLAY_OBJECTIVE, &mut p);
        write_varint_u32("sidebar".len() as u32, &mut p);
        p.extend_from_slice(b"sidebar");
        write_varint_u32("myobj".len() as u32, &mut p);
        p.extend_from_slice(b"myobj");
        p.extend_from_slice(b"trailing-junk");
        assert_eq!(parse_set_display_objective_name(&p).unwrap(), "myobj");
    }

    #[test]
    fn change_dimension_and_play_status_format() {
        let cd = change_dimension(1, [1.0, 2.0, 3.0], true);
        assert_eq!(peek_packet_id(&cd).unwrap(), ID_CHANGE_DIMENSION);
        let ps = play_status(PLAY_STATUS_PLAYER_SPAWN);
        assert_eq!(peek_packet_id(&ps).unwrap(), ID_PLAY_STATUS);
        let (_, hl) = read_varint_u32(&ps).unwrap();
        assert_eq!(&ps[hl..hl + 4], &3u32.to_be_bytes());
    }

    #[test]
    fn read_play_status_roundtrip() {
        let p = play_status(PLAY_STATUS_PLAYER_SPAWN);
        assert_eq!(read_play_status(&p).unwrap(), PLAY_STATUS_PLAYER_SPAWN);
    }

    #[test]
    fn request_chunk_radius_format() {
        let p = request_chunk_radius(8, 12);
        assert_eq!(peek_packet_id(&p).unwrap(), ID_REQUEST_CHUNK_RADIUS);
        let (_, hl) = read_varint_u32(&p).unwrap();
        assert_eq!(p[hl], 0x10); // radius zigzag(8) = 16
        assert_eq!(p[hl + 1], 12); // maxRadius u8
    }

    #[test]
    fn player_action_and_set_initialized_ids() {
        let pa = player_action(1234, PLAYER_ACTION_DIMENSION_CHANGE_DONE);
        assert_eq!(peek_packet_id(&pa).unwrap(), ID_PLAYER_ACTION);
        let si = set_local_player_as_initialized(1234);
        assert_eq!(peek_packet_id(&si).unwrap(), ID_SET_LOCAL_PLAYER_INITIALIZED);
        // runtime id round-trips as UVarLong right after header.
        let (_, hl) = read_varint_u32(&si).unwrap();
        let (rid, _) = read_varint_u64(&si[hl..]).unwrap();
        assert_eq!(rid, 1234);
    }

    #[test]
    fn empty_chunk_payload_overworld_shape() {
        let payload = empty_chunk_payload(dimension_biome_sections(DIM_OVERWORLD));
        // 08 00 | 03 | 512×00 | 02(zigzag 1) | 00 | 23×FF | 00
        assert_eq!(&payload[0..3], &[8, 0, 3]);
        assert!(payload[3..3 + 512].iter().all(|&b| b == 0));
        assert_eq!(payload[3 + 512], 0x02); // palette size 1 (zigzag)
        assert_eq!(payload[3 + 512 + 1], 0x00); // biome id 0
        let inherit = 3 + 512 + 2;
        assert_eq!(&payload[inherit..inherit + 23], &[0xFFu8; 23][..]); // 24 sections → 23 copies
        assert_eq!(payload[inherit + 23], 0); // border
        assert_eq!(payload.len(), inherit + 23 + 1);
    }

    #[test]
    fn level_chunk_fields_roundtrip() {
        let payload = empty_chunk_payload(dimension_biome_sections(DIM_OVERWORLD));
        let lc = level_chunk(-3, 5, DIM_OVERWORLD, 1, &payload);
        assert_eq!(peek_packet_id(&lc).unwrap(), ID_LEVEL_CHUNK);
        let (_, hl) = read_varint_u32(&lc).unwrap();
        let mut off = hl;
        let (cx, n) = read_zigzag_i32(&lc[off..]).unwrap();
        off += n;
        let (cz, n) = read_zigzag_i32(&lc[off..]).unwrap();
        off += n;
        let (dim, n) = read_zigzag_i32(&lc[off..]).unwrap();
        off += n;
        let (scc, n) = read_varint_u32(&lc[off..]).unwrap();
        off += n;
        assert_eq!((cx, cz, dim, scc), (-3, 5, 0, 1));
        assert_eq!(lc[off], 0); // cacheEnabled
        off += 1;
        let (plen, n) = read_varint_u32(&lc[off..]).unwrap();
        off += n;
        assert_eq!(plen as usize, payload.len());
        assert_eq!(&lc[off..off + payload.len()], payload.as_slice());
    }
}
