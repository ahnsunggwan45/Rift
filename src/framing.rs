//! Bedrock game packet batch framing — operates on decompressed plaintext batches.
//!
//! Batch structure (after decompression): repeated `[VarInt len][packet]`.
//! The first VarInt of each packet is the header: `packetId(0x3ff) | senderSubId<<10 | recipientSubId<<12`
//! (ground truth: PMMP bedrock-protocol DataPacket.php).
//!
//! The proxy hot path splits a batch into individual packets, **peeks only the ID**, touches
//! the small subset it needs to handle, and reassembles the rest unchanged.

#![allow(dead_code)] // Some items unused until handshake/interception is wired up

use anyhow::{bail, Result};

/// Packet ID mask (lower 10 bits).
pub const PID_MASK: u32 = 0x3ff;

/// Reads an unsigned VarInt (LEB128). Returns `(value, bytes_consumed)`.
pub fn read_varint_u32(buf: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 35 {
            bail!("VarInt overflow (too many bytes)");
        }
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    bail!("VarInt truncated (unexpected end of buffer)");
}

/// Writes an unsigned VarInt (LEB128) into `out`.
pub fn write_varint_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Writes an unsigned VarLong (LEB128) into `out` (used for Bedrock ActorRuntimeId, etc.).
pub fn write_varint_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Reads an unsigned VarLong (LEB128, up to 10 bytes). Returns `(value, bytes_consumed)`.
pub fn read_varint_u64(buf: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 70 {
            bail!("VarLong overflow (too many bytes)");
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    bail!("VarLong truncated (unexpected end of buffer)");
}

/// Reads a zigzag-encoded signed VarLong (used for Bedrock ActorUniqueId, etc.).
pub fn read_zigzag_i64(buf: &[u8]) -> Result<(i64, usize)> {
    let (raw, n) = read_varint_u64(buf)?;
    let value = ((raw >> 1) as i64) ^ -((raw & 1) as i64);
    Ok((value, n))
}

/// Reads a zigzag-encoded signed VarInt (32-bit Bedrock signed VarInt, e.g. playerGamemode).
pub fn read_zigzag_i32(buf: &[u8]) -> Result<(i32, usize)> {
    let (raw, n) = read_varint_u32(buf)?;
    let value = ((raw >> 1) as i32) ^ -((raw & 1) as i32);
    Ok((value, n))
}

/// Writes a zigzag-encoded signed VarInt (32-bit).
pub fn write_zigzag_i32(value: i32, out: &mut Vec<u8>) {
    let zigzag = ((value << 1) ^ (value >> 31)) as u32;
    write_varint_u32(zigzag, out);
}

/// Writes a zigzag-encoded signed VarLong (64-bit, used for Bedrock ActorUniqueId, etc.).
pub fn write_zigzag_i64(value: i64, out: &mut Vec<u8>) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    write_varint_u64(zigzag, out);
}

/// Splits a decompressed batch into individual packet slices.
pub fn split_batch(batch: &[u8]) -> Result<Vec<&[u8]>> {
    let mut packets = Vec::new();
    let mut pos = 0;
    while pos < batch.len() {
        let (len, consumed) = read_varint_u32(&batch[pos..])?;
        pos += consumed;
        let len = len as usize;
        if pos + len > batch.len() {
            bail!("batch packet length ({len}) exceeds buffer bounds");
        }
        packets.push(&batch[pos..pos + len]);
        pos += len;
    }
    Ok(packets)
}

/// Peeks the packet ID (lower 10 bits) without consuming the packet.
pub fn peek_packet_id(packet: &[u8]) -> Result<u32> {
    let (header, _) = read_varint_u32(packet)?;
    Ok(header & PID_MASK)
}

/// Reassembles packets into a batch (`[VarInt len][packet]` repeated).
pub fn build_batch(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in packets {
        write_varint_u32(p.len() as u32, &mut out);
        out.extend_from_slice(p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u32, 1, 127, 128, 255, 300, 16383, 16384, 0x3ff, 1_000_000, u32::MAX] {
            let mut buf = Vec::new();
            write_varint_u32(v, &mut buf);
            let (decoded, n) = read_varint_u32(&buf).unwrap();
            assert_eq!(decoded, v, "value {v} mismatch");
            assert_eq!(n, buf.len(), "value {v} consumed wrong byte count");
        }
    }

    #[test]
    fn varint_known_encodings() {
        // 0 -> [0x00], 127 -> [0x7f], 128 -> [0x80,0x01], 300 -> [0xac,0x02]
        let mut b = Vec::new();
        write_varint_u32(300, &mut b);
        assert_eq!(b, vec![0xac, 0x02]);
        let mut b = Vec::new();
        write_varint_u32(128, &mut b);
        assert_eq!(b, vec![0x80, 0x01]);
    }

    #[test]
    fn varint_truncated_errors() {
        // all continuation bits set, never terminates
        assert!(read_varint_u32(&[0x80, 0x80]).is_err());
    }

    /// Header encoding: packetId | senderSubId<<10 | recipientSubId<<12 — peek must extract only the ID.
    #[test]
    fn peek_id_ignores_subclient_bits() {
        let packet_id = 0x8b; // e.g. 139
        let header = packet_id | (1u32 << 10) | (2u32 << 12); // mix in sub-client bits
        let mut packet = Vec::new();
        write_varint_u32(header, &mut packet);
        packet.extend_from_slice(b"payload");
        assert_eq!(peek_packet_id(&packet).unwrap(), packet_id);
    }

    /// Multi-packet batch round-trip: build → split → identical contents.
    #[test]
    fn batch_roundtrip_multi() {
        let mk = |id: u32, body: &[u8]| {
            let mut p = Vec::new();
            write_varint_u32(id, &mut p); // header (== ID, subclient 0)
            p.extend_from_slice(body);
            p
        };
        let packets = vec![
            mk(1, b"login"),
            mk(0x52, b""),                       // empty body packet
            mk(0x3a, &[0u8; 500]),               // large body (2-byte VarInt length)
        ];
        let batch = build_batch(&packets);
        let split = split_batch(&batch).unwrap();
        assert_eq!(split.len(), packets.len());
        for (orig, got) in packets.iter().zip(split.iter()) {
            assert_eq!(*got, orig.as_slice());
        }
        // verify ID peek
        assert_eq!(peek_packet_id(split[0]).unwrap(), 1);
        assert_eq!(peek_packet_id(split[1]).unwrap(), 0x52);
        assert_eq!(peek_packet_id(split[2]).unwrap(), 0x3a);
    }

    #[test]
    fn varlong_roundtrip_via_known() {
        // 0x80 0x01 = 128 (unsigned VarLong)
        let (v, n) = read_varint_u64(&[0x80, 0x01]).unwrap();
        assert_eq!((v, n), (128, 2));
        // large value
        let (v, n) = read_varint_u64(&[0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap();
        assert_eq!((v, n), (0xffff_ffff, 5));
    }

    #[test]
    fn zigzag_decode() {
        // zigzag: 0->0, 1->-1, 2->1, 3->-2, 4->2
        assert_eq!(read_zigzag_i64(&[0]).unwrap().0, 0);
        assert_eq!(read_zigzag_i64(&[1]).unwrap().0, -1);
        assert_eq!(read_zigzag_i64(&[2]).unwrap().0, 1);
        assert_eq!(read_zigzag_i64(&[4]).unwrap().0, 2);
    }

    #[test]
    fn split_rejects_overflow_length() {
        // declared length exceeds actual buffer size
        let mut bad = Vec::new();
        write_varint_u32(100, &mut bad); // declares length 100
        bad.extend_from_slice(b"short"); // only 5 bytes follow
        assert!(split_batch(&bad).is_err());
    }
}
