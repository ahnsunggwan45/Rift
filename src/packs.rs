//! 리소스팩 로딩 + 서빙 (WDPE replace 방식).
//!
//! 프록시가 `packs/` 폴더의 `.mcpack`/`.zip` 을 로드해 클라 리소스팩 단계를 **직접 소유**한다.
//! 다운스트림이 보내는 ResourcePacksInfo/Stack 은 무시(클라엔 프록시 팩만 노출)되고,
//! 모든 다운스트림에 동일하게 적용된다. (intercept.rs 가 흐름을 중개)
//!
//! packId 체계 (PMMP ResourcePacksPacketHandler 기준):
//! - ResourcePacksInfo 엔트리: **바이너리 UUID(16)** + version 문자열.
//! - 클라 SEND_PACKS: `"uuid_version"` 문자열 목록 (서버는 '_' 로 분리해 uuid 추출).
//! - DataInfo/ChunkRequest/ChunkData/Stack: **uuid 문자열**.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::framing::write_varint_u32;

/// 청크 크기 (PMMP PACK_CHUNK_SIZE 와 동일, 256KB).
pub const CHUNK_SIZE: u32 = 256 * 1024;

// 패킷 ID.
const ID_RESOURCE_PACKS_INFO: u32 = 0x06;
const ID_RESOURCE_PACK_STACK: u32 = 0x07;
const ID_RESOURCE_PACK_DATA_INFO: u32 = 0x52;
const ID_RESOURCE_PACK_CHUNK_DATA: u32 = 0x53;

/// ResourcePackType (RESOURCES).
const PACK_TYPE_RESOURCES: u8 = 6;

/// 로드된 팩 하나.
pub struct LoadedPack {
    /// manifest header.uuid 의 16바이트 (표준 big-endian 순서; 인코딩 시 Bedrock 형식으로 변환).
    pub uuid: [u8; 16],
    /// 정규 uuid 문자열("xxxxxxxx-xxxx-..."). DataInfo/Stack/ChunkRequest 매칭용.
    pub uuid_str: String,
    /// "major.minor.patch".
    pub version: String,
    /// 전체 .mcpack/.zip 바이트 (청크로 서빙).
    pub bytes: Arc<Vec<u8>>,
    /// 파일 전체 SHA-256.
    pub sha256: [u8; 32],
    pub size: u64,
    pub chunk_count: u32,
}

/// 로드된 전체 팩 + 사전 빌드된 ResourcePacksInfo/Stack 게임패킷.
pub struct PackStore {
    pub packs: Vec<LoadedPack>,
    /// 사전 빌드된 ResourcePacksInfo 패킷(0x06, 압축 전 단일 패킷 바이트).
    pub info_packet: Vec<u8>,
    /// 사전 빌드된 ResourcePackStack 패킷(0x07).
    pub stack_packet: Vec<u8>,
}

impl PackStore {
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    /// uuid 문자열로 팩 찾기 (대소문자 무시 — PMMP 동일).
    pub fn find(&self, uuid_str: &str) -> Option<&LoadedPack> {
        self.packs.iter().find(|p| p.uuid_str.eq_ignore_ascii_case(uuid_str))
    }

    /// DataInfo 패킷(0x52) 빌드.
    pub fn data_info_packet(pack: &LoadedPack) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_RESOURCE_PACK_DATA_INFO, &mut p);
        put_string(&mut p, pack.uuid_str.as_bytes());
        p.extend_from_slice(&CHUNK_SIZE.to_le_bytes()); // maxChunkSize LE u32
        p.extend_from_slice(&pack.chunk_count.to_le_bytes()); // chunkCount LE u32
        p.extend_from_slice(&pack.size.to_le_bytes()); // compressedPackSize LE u64
        put_string(&mut p, &pack.sha256); // sha256 (string = len+bytes)
        p.push(0); // isPremium
        p.push(PACK_TYPE_RESOURCES); // packType
        p
    }

    /// ChunkData 패킷(0x53) 빌드.
    pub fn chunk_data_packet(uuid_str: &str, chunk_index: u32, offset: u64, data: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        write_varint_u32(ID_RESOURCE_PACK_CHUNK_DATA, &mut p);
        put_string(&mut p, uuid_str.as_bytes());
        p.extend_from_slice(&chunk_index.to_le_bytes()); // chunkIndex LE u32
        p.extend_from_slice(&offset.to_le_bytes()); // offset LE u64
        put_string(&mut p, data);
        p
    }
}

/// 폴더의 .mcpack/.zip 을 모두 로드하고 info/stack 패킷을 사전 빌드한다.
pub fn load(folder: &str, force: bool) -> Result<PackStore> {
    let mut packs = Vec::new();
    let dir = Path::new(folder);
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("팩 폴더 읽기 실패: {folder}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort(); // 결정론적 순서
        for path in entries {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if ext != "mcpack" && ext != "zip" {
                continue;
            }
            match load_one(&path) {
                Ok(p) => {
                    tracing::info!(pack = %p.uuid_str, version = %p.version, size = p.size, chunks = p.chunk_count, "리소스팩 로드");
                    packs.push(p);
                }
                Err(e) => tracing::warn!(path = %path.display(), "리소스팩 로드 실패(스킵): {e}"),
            }
        }
    } else {
        tracing::warn!(%folder, "팩 폴더가 없음 — 빈 팩 세트로 진행");
    }
    let info_packet = build_info_packet(&packs, force);
    let stack_packet = build_stack_packet(&packs, force);
    Ok(PackStore { packs, info_packet, stack_packet })
}

fn load_one(path: &Path) -> Result<LoadedPack> {
    let bytes = std::fs::read(path).with_context(|| format!("팩 파일 읽기 실패: {}", path.display()))?;
    let manifest = read_manifest(&bytes)?;
    let json: serde_json::Value = serde_json::from_slice(&manifest).context("manifest.json 파싱 실패")?;
    let header = json.get("header").context("manifest 에 header 없음")?;
    let uuid_str = header
        .get("uuid")
        .and_then(|v| v.as_str())
        .context("manifest header.uuid 없음")?
        .to_string();
    let uuid = parse_uuid(&uuid_str)?;
    let version = header
        .get("version")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|n| n.as_u64())
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "1.0.0".to_string());
    let size = bytes.len() as u64;
    let chunk_count = size.div_ceil(CHUNK_SIZE as u64) as u32;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(LoadedPack {
        uuid,
        uuid_str,
        version,
        bytes: Arc::new(bytes),
        sha256,
        size,
        chunk_count,
    })
}

/// zip 안에서 manifest.json 을 찾아 읽는다(루트 또는 하위 폴더).
fn read_manifest(zip_bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("zip 아카이브 열기 실패")?;
    // manifest.json 의 정확 경로(루트 우선, 없으면 *manifest.json 으로 끝나는 첫 엔트리).
    let name = if zip.by_name("manifest.json").is_ok() {
        "manifest.json".to_string()
    } else {
        zip.file_names()
            .find(|n| n.ends_with("manifest.json") || n.ends_with("manifest.json/"))
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("zip 안에 manifest.json 없음"))?
    };
    let mut f = zip.by_name(&name).context("manifest.json 엔트리 열기 실패")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" → 16바이트(표준 big-endian 순서).
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(anyhow!("UUID 형식 오류: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).context("UUID hex 파싱 실패")?;
    }
    Ok(out)
}

/// ResourcePacksInfoPacket(0x06) 빌드.
fn build_info_packet(packs: &[LoadedPack], force: bool) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_RESOURCE_PACKS_INFO, &mut p);
    p.push(force as u8); // mustAccept
    p.push(0); // hasAddons
    p.push(0); // hasScripts
    p.push(0); // forceDisableVibrantVisuals = false (VV 활성 유지)
    put_uuid(&mut p, &[0u8; 16]); // worldTemplateId
    put_string(&mut p, b""); // worldTemplateVersion
    p.extend_from_slice(&(packs.len() as u16).to_le_bytes()); // 엔트리 수 (LE u16)
    for pack in packs {
        put_uuid(&mut p, &pack.uuid); // packId (바이너리 UUID)
        put_string(&mut p, pack.version.as_bytes()); // version
        p.extend_from_slice(&pack.size.to_le_bytes()); // sizeBytes LE u64
        put_string(&mut p, b""); // encryptionKey
        put_string(&mut p, b""); // subPackName
        put_string(&mut p, pack.uuid_str.as_bytes()); // contentId (PMMP 는 packId 사용)
        p.push(0); // hasScripts
        p.push(0); // isAddonPack
        p.push(0); // isRtxCapable
        put_string(&mut p, b""); // cdnUrl
    }
    p
}

/// ResourcePackStackPacket(0x07) 빌드.
fn build_stack_packet(packs: &[LoadedPack], force: bool) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_RESOURCE_PACK_STACK, &mut p);
    p.push(force as u8); // mustAccept
    write_varint_u32(packs.len() as u32, &mut p); // 스택 엔트리 수 (UnsignedVarInt)
    for pack in packs {
        put_string(&mut p, pack.uuid_str.as_bytes()); // packId
        put_string(&mut p, pack.version.as_bytes()); // version
        put_string(&mut p, b""); // subPackName
    }
    put_string(&mut p, b"1.26.30"); // baseGameVersion
    // Experiments: count(LE u32)=0, hasPreviouslyUsedExperiments(bool)=0
    p.extend_from_slice(&0u32.to_le_bytes());
    p.push(0);
    p.push(0); // useVanillaEditorPacks
    p
}

/// ResourcePackClientResponsePacket(0x08) 파싱 → (status, packIds). best-effort.
/// packIds 는 "uuid_version" 형식.
pub fn parse_client_response(pkt: &[u8]) -> Option<(u8, Vec<String>)> {
    let (_, hl) = crate::framing::read_varint_u32(pkt).ok()?;
    let mut off = hl;
    let status = *pkt.get(off)?;
    off += 1;
    let count = u16::from_le_bytes([*pkt.get(off)?, *pkt.get(off + 1)?]);
    off += 2;
    let mut ids = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (s, n) = read_string(pkt, off)?;
        off = n;
        ids.push(s);
    }
    Some((status, ids))
}

/// ResourcePackChunkRequestPacket(0x54) 파싱 → (packId uuid 문자열, chunkIndex). best-effort.
pub fn parse_chunk_request(pkt: &[u8]) -> Option<(String, u32)> {
    let (_, hl) = crate::framing::read_varint_u32(pkt).ok()?;
    let (uuid, off) = read_string(pkt, hl)?;
    let idx = u32::from_le_bytes([
        *pkt.get(off)?,
        *pkt.get(off + 1)?,
        *pkt.get(off + 2)?,
        *pkt.get(off + 3)?,
    ]);
    Some((uuid, idx))
}

// ---- 인코딩 헬퍼 ----

/// Bedrock UUID 인코딩: 앞 8바이트 역순 + 뒤 8바이트 역순.
fn put_uuid(out: &mut Vec<u8>, uuid: &[u8; 16]) {
    out.extend(uuid[0..8].iter().rev());
    out.extend(uuid[8..16].iter().rev());
}

/// string: UnsignedVarInt 길이 + 바이트.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

/// 오프셋의 string 을 읽어 (값, 다음 오프셋) 반환.
fn read_string(buf: &[u8], off: usize) -> Option<(String, usize)> {
    let (len, n) = crate::framing::read_varint_u32(buf.get(off..)?).ok()?;
    let start = off + n;
    let end = start + len as usize;
    let bytes = buf.get(start..end)?;
    Some((String::from_utf8_lossy(bytes).into_owned(), end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::peek_packet_id;

    #[test]
    fn parse_uuid_standard() {
        let u = parse_uuid("12345678-9abc-def0-1234-56789abcdef0").unwrap();
        assert_eq!(u[0], 0x12);
        assert_eq!(u[1], 0x34);
        assert_eq!(u[15], 0xf0);
    }

    #[test]
    fn put_uuid_reverses_halves() {
        let mut out = Vec::new();
        let uuid = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        put_uuid(&mut out, &uuid);
        assert_eq!(out, vec![7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8]);
    }

    #[test]
    fn empty_store_builds_valid_packets() {
        let store = PackStore { packs: vec![], info_packet: build_info_packet(&[], false), stack_packet: build_stack_packet(&[], false) };
        assert_eq!(peek_packet_id(&store.info_packet).unwrap(), ID_RESOURCE_PACKS_INFO);
        assert_eq!(peek_packet_id(&store.stack_packet).unwrap(), ID_RESOURCE_PACK_STACK);
        assert!(store.is_empty());
    }

    #[test]
    fn data_info_and_chunk_data_ids() {
        let pack = LoadedPack {
            uuid: [0u8; 16],
            uuid_str: "abc".to_string(),
            version: "1.0.0".to_string(),
            bytes: Arc::new(vec![0u8; 1000]),
            sha256: [0u8; 32],
            size: 1000,
            chunk_count: 1,
        };
        let di = PackStore::data_info_packet(&pack);
        assert_eq!(peek_packet_id(&di).unwrap(), ID_RESOURCE_PACK_DATA_INFO);
        let cd = PackStore::chunk_data_packet("abc", 0, 0, &[1, 2, 3]);
        assert_eq!(peek_packet_id(&cd).unwrap(), ID_RESOURCE_PACK_CHUNK_DATA);
    }

    #[test]
    fn client_response_and_chunk_request_roundtrip() {
        // ClientResponse: status + LE u16 count + strings
        let mut resp = Vec::new();
        write_varint_u32(0x08, &mut resp);
        resp.push(2); // SEND_PACKS
        resp.extend_from_slice(&1u16.to_le_bytes());
        put_string(&mut resp, b"abc-uuid_1.0.0");
        let (status, ids) = parse_client_response(&resp).unwrap();
        assert_eq!(status, 2);
        assert_eq!(ids, vec!["abc-uuid_1.0.0".to_string()]);

        // ChunkRequest: packId + LE u32 chunkIndex
        let mut req = Vec::new();
        write_varint_u32(0x54, &mut req);
        put_string(&mut req, b"abc-uuid");
        req.extend_from_slice(&5u32.to_le_bytes());
        let (uuid, idx) = parse_chunk_request(&req).unwrap();
        assert_eq!(uuid, "abc-uuid");
        assert_eq!(idx, 5);
    }
}
