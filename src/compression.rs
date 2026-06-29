//! Bedrock 배치 압축 — NetworkSettings 협상 후 게임패킷에 적용.
//!
//! 게임패킷 페이로드(0xfe 다음): `[압축타입 1바이트][데이터]`.
//! 압축타입: 0=ZLIB, 1=SNAPPY, 255=NONE (ground truth: PMMP NetworkSession.php:414-434).
//! - ZLIB 은 **RAW DEFLATE**(헤더/체크섬 없음, PMMP `ZLIB_ENCODING_RAW`) — zlib-wrapped 아님!
//! - SNAPPY 는 raw 블록 포맷.
//! - NONE 은 비압축(임계값 미만 배치).

#![allow(dead_code)] // 디코드 핫패스 배선 전까지 일부 미사용

use std::io::Write;

use anyhow::{bail, Result};
use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::Compression as FlateLevel;

/// 압축타입 바이트 (PMMP CompressionAlgorithm).
pub const ZLIB: u8 = 0;
pub const SNAPPY: u8 = 1;
pub const NONE: u8 = 255;

/// PMMP 기본 zlib 압축 레벨.
const ZLIB_LEVEL: u32 = 7;

/// RAW DEFLATE 압축 해제 (zlib 헤더 없음).
pub fn inflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(Vec::new());
    decoder.write_all(data)?;
    Ok(decoder.finish()?)
}

/// RAW DEFLATE 압축.
pub fn deflate_raw(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), FlateLevel::new(level));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

pub fn snappy_compress(data: &[u8]) -> Result<Vec<u8>> {
    snap::raw::Encoder::new()
        .compress_vec(data)
        .map_err(|e| anyhow::anyhow!("snappy 압축 실패: {e}"))
}

pub fn snappy_decompress(data: &[u8]) -> Result<Vec<u8>> {
    snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|e| anyhow::anyhow!("snappy 해제 실패: {e}"))
}

/// 압축타입에 따라 데이터를 해제해 평문 배치를 반환.
pub fn decompress(comp_type: u8, data: &[u8]) -> Result<Vec<u8>> {
    match comp_type {
        ZLIB => inflate_raw(data),
        SNAPPY => snappy_decompress(data),
        NONE => Ok(data.to_vec()),
        other => bail!("알 수 없는 압축타입 {other}"),
    }
}

/// 평문 배치를 주어진 압축타입으로 압축. (수정한 배치를 재방출할 때 사용)
pub fn compress(comp_type: u8, data: &[u8]) -> Result<Vec<u8>> {
    match comp_type {
        ZLIB => deflate_raw(data, ZLIB_LEVEL),
        SNAPPY => snappy_compress(data),
        NONE => Ok(data.to_vec()),
        other => bail!("알 수 없는 압축타입 {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zlib_raw_roundtrip() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let compressed = deflate_raw(&data, ZLIB_LEVEL).unwrap();
        // raw deflate 는 zlib 헤더(0x78)로 시작하지 않아야 함
        assert_ne!(compressed[0], 0x78, "zlib-wrapped 로 보임 (raw 여야 함)");
        let restored = inflate_raw(&compressed).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn snappy_roundtrip() {
        let data = b"minecraft bedrock packet batch payload".repeat(10);
        let compressed = snappy_compress(&data).unwrap();
        assert_eq!(snappy_decompress(&compressed).unwrap(), data);
    }

    #[test]
    fn dispatch_roundtrip_all_types() {
        let data = b"resource packs info packet payload here".repeat(8);
        for &t in &[ZLIB, SNAPPY, NONE] {
            let c = compress(t, &data).unwrap();
            let d = decompress(t, &c).unwrap();
            assert_eq!(d, data, "압축타입 {t} round-trip 실패");
        }
    }

    #[test]
    fn none_is_passthrough() {
        let data = b"uncompressed batch";
        assert_eq!(compress(NONE, data).unwrap(), data);
        assert_eq!(decompress(NONE, data).unwrap(), data);
    }

    #[test]
    fn unknown_type_errors() {
        assert!(decompress(42, b"x").is_err());
        assert!(compress(42, b"x").is_err());
    }
}
