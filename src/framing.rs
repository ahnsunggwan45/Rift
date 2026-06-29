//! Bedrock 게임패킷 배치 프레이밍 — 압축 해제된 평문 배치를 다룬다.
//!
//! 배치 구조(압축 해제 후): `[VarInt len][packet]` 반복.
//! 각 packet 의 첫 VarInt = 헤더: `packetId(0x3ff) | senderSubId<<10 | recipientSubId<<12`
//! (ground truth: PMMP bedrock-protocol DataPacket.php).
//!
//! 프록시 핫패스는 배치를 패킷들로 쪼개 **ID만 peek** 하고, 우리가 처리할 소수만
//! 손대고 나머지는 그대로 다시 배치로 묶는다.

#![allow(dead_code)] // 핸드셰이크/인터셉션 배선 전까지 일부 미사용

use anyhow::{bail, Result};

/// 패킷 ID 마스크 (하위 10비트).
pub const PID_MASK: u32 = 0x3ff;

/// unsigned VarInt(LEB128) 를 읽는다. (값, 소비한 바이트수) 반환.
pub fn read_varint_u32(buf: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 35 {
            bail!("VarInt 가 너무 김");
        }
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    bail!("VarInt 가 잘림 (버퍼 끝)");
}

/// unsigned VarInt(LEB128) 를 out 에 기록한다.
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

/// unsigned VarLong(LEB128) 를 out 에 기록한다 (Bedrock ActorRuntimeId 등).
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

/// unsigned VarLong(LEB128, 최대 10바이트) 를 읽는다. (값, 소비 바이트수).
pub fn read_varint_u64(buf: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 70 {
            bail!("VarLong 가 너무 김");
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    bail!("VarLong 가 잘림");
}

/// zigzag 부호 VarLong 을 읽는다 (Bedrock ActorUniqueId 등).
pub fn read_zigzag_i64(buf: &[u8]) -> Result<(i64, usize)> {
    let (raw, n) = read_varint_u64(buf)?;
    let value = ((raw >> 1) as i64) ^ -((raw & 1) as i64);
    Ok((value, n))
}

/// zigzag 부호 VarInt(32bit) 를 읽는다 (Bedrock signed VarInt, 예: playerGamemode).
pub fn read_zigzag_i32(buf: &[u8]) -> Result<(i32, usize)> {
    let (raw, n) = read_varint_u32(buf)?;
    let value = ((raw >> 1) as i32) ^ -((raw & 1) as i32);
    Ok((value, n))
}

/// zigzag 부호 VarInt(32bit) 를 기록한다.
pub fn write_zigzag_i32(value: i32, out: &mut Vec<u8>) {
    let zigzag = ((value << 1) ^ (value >> 31)) as u32;
    write_varint_u32(zigzag, out);
}

/// zigzag 부호 VarLong(64bit) 를 기록한다 (Bedrock ActorUniqueId 등).
pub fn write_zigzag_i64(value: i64, out: &mut Vec<u8>) {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    write_varint_u64(zigzag, out);
}

/// 압축 해제된 배치를 개별 패킷 슬라이스들로 쪼갠다.
pub fn split_batch(batch: &[u8]) -> Result<Vec<&[u8]>> {
    let mut packets = Vec::new();
    let mut pos = 0;
    while pos < batch.len() {
        let (len, consumed) = read_varint_u32(&batch[pos..])?;
        pos += consumed;
        let len = len as usize;
        if pos + len > batch.len() {
            bail!("배치 패킷 길이({len})가 버퍼를 초과");
        }
        packets.push(&batch[pos..pos + len]);
        pos += len;
    }
    Ok(packets)
}

/// 패킷의 ID(하위 10비트)를 peek 한다. 패킷을 소비하지 않는다.
pub fn peek_packet_id(packet: &[u8]) -> Result<u32> {
    let (header, _) = read_varint_u32(packet)?;
    Ok(header & PID_MASK)
}

/// 패킷들을 다시 배치로 묶는다 (`[VarInt len][packet]` 반복).
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
            assert_eq!(decoded, v, "값 {v} 불일치");
            assert_eq!(n, buf.len(), "값 {v} 소비 길이 불일치");
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
        // 연속 비트만 있고 끝나지 않음
        assert!(read_varint_u32(&[0x80, 0x80]).is_err());
    }

    /// 헤더 인코딩: packetId | senderSubId<<10 | recipientSubId<<12 → peek 가 ID만 뽑아야.
    #[test]
    fn peek_id_ignores_subclient_bits() {
        let packet_id = 0x8b; // 예: 139
        let header = packet_id | (1u32 << 10) | (2u32 << 12); // sub-client 비트 섞기
        let mut packet = Vec::new();
        write_varint_u32(header, &mut packet);
        packet.extend_from_slice(b"payload");
        assert_eq!(peek_packet_id(&packet).unwrap(), packet_id);
    }

    /// 여러 패킷 배치 round-trip: build → split → 같은 내용.
    #[test]
    fn batch_roundtrip_multi() {
        let mk = |id: u32, body: &[u8]| {
            let mut p = Vec::new();
            write_varint_u32(id, &mut p); // 헤더(=ID, subclient 0)
            p.extend_from_slice(body);
            p
        };
        let packets = vec![
            mk(1, b"login"),
            mk(0x52, b""),                       // 빈 바디 패킷
            mk(0x3a, &[0u8; 500]),               // 큰 바디(2바이트 VarInt 길이)
        ];
        let batch = build_batch(&packets);
        let split = split_batch(&batch).unwrap();
        assert_eq!(split.len(), packets.len());
        for (orig, got) in packets.iter().zip(split.iter()) {
            assert_eq!(*got, orig.as_slice());
        }
        // ID peek 확인
        assert_eq!(peek_packet_id(split[0]).unwrap(), 1);
        assert_eq!(peek_packet_id(split[1]).unwrap(), 0x52);
        assert_eq!(peek_packet_id(split[2]).unwrap(), 0x3a);
    }

    #[test]
    fn varlong_roundtrip_via_known() {
        // 0x80 0x01 = 128 (unsigned VarLong)
        let (v, n) = read_varint_u64(&[0x80, 0x01]).unwrap();
        assert_eq!((v, n), (128, 2));
        // 큰 값
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
        // 길이 VarInt 가 버퍼보다 큼
        let mut bad = Vec::new();
        write_varint_u32(100, &mut bad); // 길이 100 선언
        bad.extend_from_slice(b"short"); // 실제론 5바이트
        assert!(split_batch(&bad).is_err());
    }
}
