//! Bedrock batch compression — applied to game packets after NetworkSettings negotiation.
//!
//! Game packet payload (after 0xfe): `[compression type 1 byte][data]`.
//! Compression type: 0=ZLIB, 1=SNAPPY, 255=NONE (ground truth: PMMP NetworkSession.php:414-434).
//! - ZLIB uses **RAW DEFLATE** (no header/checksum, PMMP `ZLIB_ENCODING_RAW`) — not zlib-wrapped!
//! - SNAPPY uses raw block format.
//! - NONE is uncompressed (batches below the compression threshold).

#![allow(dead_code)] // Some items unused until the decode hot path is wired up

use std::io::Write;

use anyhow::{bail, Result};
use flate2::write::{DeflateDecoder, DeflateEncoder};
use flate2::Compression as FlateLevel;

/// Compression type byte (PMMP CompressionAlgorithm).
pub const ZLIB: u8 = 0;
pub const SNAPPY: u8 = 1;
pub const NONE: u8 = 255;

/// Default zlib compression level (matches PMMP).
const ZLIB_LEVEL: u32 = 7;

/// Decompresses raw DEFLATE data (no zlib header).
pub fn inflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    // Pre-size the output to cut reallocations during inflate (typical DEFLATE ratio is a few ×).
    let mut decoder = DeflateDecoder::new(Vec::with_capacity(data.len().saturating_mul(4)));
    decoder.write_all(data)?;
    Ok(decoder.finish()?)
}

/// Compresses data using raw DEFLATE.
pub fn deflate_raw(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), FlateLevel::new(level));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

pub fn snappy_compress(data: &[u8]) -> Result<Vec<u8>> {
    snap::raw::Encoder::new()
        .compress_vec(data)
        .map_err(|e| anyhow::anyhow!("snappy compression failed: {e}"))
}

pub fn snappy_decompress(data: &[u8]) -> Result<Vec<u8>> {
    snap::raw::Decoder::new()
        .decompress_vec(data)
        .map_err(|e| anyhow::anyhow!("snappy decompression failed: {e}"))
}

/// Decompresses data according to the given compression type; returns the plaintext batch.
pub fn decompress(comp_type: u8, data: &[u8]) -> Result<Vec<u8>> {
    match comp_type {
        ZLIB => inflate_raw(data),
        SNAPPY => snappy_decompress(data),
        NONE => Ok(data.to_vec()),
        other => bail!("unknown compression type {other}"),
    }
}

/// Compresses a plaintext batch using the given compression type. Used when re-emitting a modified batch.
pub fn compress(comp_type: u8, data: &[u8]) -> Result<Vec<u8>> {
    match comp_type {
        ZLIB => deflate_raw(data, ZLIB_LEVEL),
        SNAPPY => snappy_compress(data),
        NONE => Ok(data.to_vec()),
        other => bail!("unknown compression type {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zlib_raw_roundtrip() {
        let data = b"the quick brown fox jumps over the lazy dog".repeat(20);
        let compressed = deflate_raw(&data, ZLIB_LEVEL).unwrap();
        // raw DEFLATE must not start with the zlib header byte (0x78)
        assert_ne!(compressed[0], 0x78, "output looks zlib-wrapped (expected raw DEFLATE)");
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
            assert_eq!(d, data, "compression type {t} round-trip failed");
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
