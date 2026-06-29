//! Resource pack loading + serving (WDPE replace approach).
//!
//! The proxy takes full ownership of the client resource-pack handshake by loading every
//! `.mcpack`/`.zip` from the `packs/` directory. ResourcePacksInfo/Stack sent by the downstream
//! are ignored; only proxy-owned packs are exposed to the client, applied uniformly across all
//! downstreams. (intercept.rs brokers the flow.)
//!
//! packId scheme (based on PMMP ResourcePacksPacketHandler):
//! - ResourcePacksInfo entry: **binary UUID (16 bytes)** + version string.
//! - Client SEND_PACKS: list of `"uuid_version"` strings (server splits on '_' to extract uuid).
//! - DataInfo/ChunkRequest/ChunkData/Stack: **uuid string**.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::framing::write_varint_u32;

/// Chunk size (matches PMMP PACK_CHUNK_SIZE, 256 KB).
pub const CHUNK_SIZE: u32 = 256 * 1024;

// Packet IDs.
const ID_RESOURCE_PACKS_INFO: u32 = 0x06;
const ID_RESOURCE_PACK_STACK: u32 = 0x07;
const ID_RESOURCE_PACK_DATA_INFO: u32 = 0x52;
const ID_RESOURCE_PACK_CHUNK_DATA: u32 = 0x53;

/// ResourcePackType (RESOURCES).
const PACK_TYPE_RESOURCES: u8 = 6;

/// A single loaded resource pack.
pub struct LoadedPack {
    /// 16 bytes from manifest header.uuid (standard big-endian order; converted to Bedrock format on encode).
    pub uuid: [u8; 16],
    /// Canonical uuid string ("xxxxxxxx-xxxx-..."). Used for matching DataInfo/Stack/ChunkRequest.
    pub uuid_str: String,
    /// "major.minor.patch".
    pub version: String,
    /// Full .mcpack/.zip bytes (served in chunks).
    pub bytes: Arc<Vec<u8>>,
    /// SHA-256 of the entire file.
    pub sha256: [u8; 32],
    pub size: u64,
    pub chunk_count: u32,
}

/// All loaded packs plus pre-built ResourcePacksInfo/Stack game packets.
pub struct PackStore {
    pub packs: Vec<LoadedPack>,
    /// Pre-built ResourcePacksInfo packet (0x06, single packet bytes before compression).
    pub info_packet: Vec<u8>,
    /// Pre-built ResourcePackStack packet (0x07).
    pub stack_packet: Vec<u8>,
}

impl PackStore {
    pub fn is_empty(&self) -> bool {
        self.packs.is_empty()
    }

    /// Find a pack by uuid string (case-insensitive — matches PMMP behavior).
    pub fn find(&self, uuid_str: &str) -> Option<&LoadedPack> {
        self.packs.iter().find(|p| p.uuid_str.eq_ignore_ascii_case(uuid_str))
    }

    /// Build a DataInfo packet (0x52).
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

    /// Build a ChunkData packet (0x53).
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

/// Load all .mcpack/.zip files from a folder and pre-build info/stack packets.
pub fn load(folder: &str, force: bool) -> Result<PackStore> {
    let mut packs = Vec::new();
    let dir = Path::new(folder);
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("failed to read pack folder: {folder}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort(); // deterministic ordering
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
                    tracing::info!(pack = %p.uuid_str, version = %p.version, size = p.size, chunks = p.chunk_count, "resource pack loaded");
                    packs.push(p);
                }
                Err(e) => tracing::warn!(path = %path.display(), "resource pack load failed (skipping): {e}"),
            }
        }
    } else {
        tracing::warn!(%folder, "pack folder not found — proceeding with empty pack set");
    }
    let info_packet = build_info_packet(&packs, force);
    let stack_packet = build_stack_packet(&packs, force);
    Ok(PackStore { packs, info_packet, stack_packet })
}

fn load_one(path: &Path) -> Result<LoadedPack> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read pack file: {}", path.display()))?;
    let manifest = read_manifest(&bytes)?;
    let json: serde_json::Value = serde_json::from_slice(&manifest).context("failed to parse manifest.json")?;
    let header = json.get("header").context("manifest missing header")?;
    let uuid_str = header
        .get("uuid")
        .and_then(|v| v.as_str())
        .context("manifest header.uuid missing")?
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

/// Locate and read manifest.json inside a zip (root preferred, falls back to any sub-path).
fn read_manifest(zip_bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("failed to open zip archive")?;
    // Exact path for manifest.json (root preferred; otherwise first entry ending with manifest.json).
    let name = if zip.by_name("manifest.json").is_ok() {
        "manifest.json".to_string()
    } else {
        zip.file_names()
            .find(|n| n.ends_with("manifest.json") || n.ends_with("manifest.json/"))
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("manifest.json not found in zip"))?
    };
    let mut f = zip.by_name(&name).context("failed to open manifest.json entry")?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Parse "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into 16 bytes (standard big-endian order).
fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(anyhow!("invalid UUID format: {s}"));
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).context("failed to parse UUID hex")?;
    }
    Ok(out)
}

/// Build a ResourcePacksInfoPacket (0x06).
fn build_info_packet(packs: &[LoadedPack], force: bool) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_RESOURCE_PACKS_INFO, &mut p);
    p.push(force as u8); // mustAccept
    p.push(0); // hasAddons
    p.push(0); // hasScripts
    p.push(0); // forceDisableVibrantVisuals = false (keep VV enabled)
    put_uuid(&mut p, &[0u8; 16]); // worldTemplateId
    put_string(&mut p, b""); // worldTemplateVersion
    p.extend_from_slice(&(packs.len() as u16).to_le_bytes()); // entry count (LE u16)
    for pack in packs {
        put_uuid(&mut p, &pack.uuid); // packId (binary UUID)
        put_string(&mut p, pack.version.as_bytes()); // version
        p.extend_from_slice(&pack.size.to_le_bytes()); // sizeBytes LE u64
        put_string(&mut p, b""); // encryptionKey
        put_string(&mut p, b""); // subPackName
        put_string(&mut p, pack.uuid_str.as_bytes()); // contentId (PMMP uses packId here)
        p.push(0); // hasScripts
        p.push(0); // isAddonPack
        p.push(0); // isRtxCapable
        put_string(&mut p, b""); // cdnUrl
    }
    p
}

/// Build a ResourcePackStackPacket (0x07).
fn build_stack_packet(packs: &[LoadedPack], force: bool) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint_u32(ID_RESOURCE_PACK_STACK, &mut p);
    p.push(force as u8); // mustAccept
    write_varint_u32(packs.len() as u32, &mut p); // stack entry count (UnsignedVarInt)
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

/// Parse a ResourcePackClientResponsePacket (0x08) → (status, packIds). Best-effort.
/// packIds are in "uuid_version" format.
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

/// Parse a ResourcePackChunkRequestPacket (0x54) → (packId uuid string, chunkIndex). Best-effort.
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

// ---- Encoding helpers ----

/// Bedrock UUID encoding: reverse the first 8 bytes, then reverse the last 8 bytes.
fn put_uuid(out: &mut Vec<u8>, uuid: &[u8; 16]) {
    out.extend(uuid[0..8].iter().rev());
    out.extend(uuid[8..16].iter().rev());
}

/// String encoding: UnsignedVarInt length prefix + bytes.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint_u32(bytes.len() as u32, out);
    out.extend_from_slice(bytes);
}

/// Read a string at the given offset; returns (value, next offset).
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
