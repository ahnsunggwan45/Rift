//! Bedrock 게임패킷 암호화 — AES-256-CTR "fake GCM".
//!
//! PMMP `EncryptionContext` 의 1:1 포팅 (ground truth: docs/phase1b-design.md).
//! - 암호: AES-256-CTR, IV = key[0:12] ++ 00 00 00 02 (OpenSSL CTR = 128bit BE 카운터).
//! - CTR 키스트림은 연결 내내 연속(패킷마다 재초기화 X).
//! - 패킷마다 8바이트 checksum = SHA256( LE_u64(counter) ++ payload ++ key )[0:8].
//! - 암/복호 counter 분리, 각 0부터 패킷당 +1.

#![allow(dead_code)] // Phase 1b 핸드셰이크 연결 전까지 일부 미사용

use aes::cipher::{KeyIvInit, StreamCipher};
use p384::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// OpenSSL "AES-256-CTR" 과 동일: 16바이트 IV 전체를 128bit 빅엔디언 카운터로 사용.
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// 페이로드가 checksum(8) 을 담기엔 너무 짧음.
    TooShort,
    /// checksum 불일치 (변조 또는 카운터/키 불일치).
    BadChecksum,
}

pub struct EncryptionContext {
    key: [u8; 32],
    encrypt_cipher: Aes256Ctr,
    decrypt_cipher: Aes256Ctr,
    encrypt_counter: u64,
    decrypt_counter: u64,
}

impl EncryptionContext {
    /// 32바이트 키로 컨텍스트를 만든다. IV 는 key[0:12] ++ 00000002.
    pub fn new(key: [u8; 32]) -> Self {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&key[..12]);
        iv[12..].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        Self {
            key,
            encrypt_cipher: Aes256Ctr::new(&key.into(), &iv.into()),
            decrypt_cipher: Aes256Ctr::new(&key.into(), &iv.into()),
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    /// 평문 배치를 암호화한다: AES_CTR(payload ++ checksum).
    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let checksum = self.checksum(self.encrypt_counter, payload);
        self.encrypt_counter = self.encrypt_counter.wrapping_add(1);

        let mut buf = Vec::with_capacity(payload.len() + 8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&checksum);
        self.encrypt_cipher.apply_keystream(&mut buf);
        buf
    }

    /// 암호문을 복호화하고 checksum 을 검증한다. 성공 시 평문 배치를 반환.
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if data.len() < 9 {
            return Err(DecryptError::TooShort);
        }
        let mut buf = data.to_vec();
        self.decrypt_cipher.apply_keystream(&mut buf);

        let split = buf.len() - 8;
        let counter = self.decrypt_counter;
        self.decrypt_counter = self.decrypt_counter.wrapping_add(1);

        let expected = self.checksum(counter, &buf[..split]);
        if expected != buf[split..] {
            return Err(DecryptError::BadChecksum);
        }
        buf.truncate(split);
        Ok(buf)
    }

    /// checksum = SHA256( LE_u64(counter) ++ payload ++ key )[0:8].
    fn checksum(&self, counter: u64, payload: &[u8]) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_le_bytes());
        hasher.update(payload);
        hasher.update(self.key);
        let digest = hasher.finalize();
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        out
    }
}

/// P-384(secp384r1) 비밀키를 생성한다. 같은 키를 ECDH(공유비밀)와 ECDSA/ES384
/// JWT 서명에 모두 쓴다 — Bedrock 핸드셰이크는 한 키로 서명+키교환을 한다.
/// 프록시는 클라측/다운스트림측에 각각 별도 키를 생성해 제시한다.
pub fn generate_secret_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

/// ECDH 공유비밀(48바이트 빅엔디언 X좌표)을 도출한다. OpenSSL `openssl_pkey_derive`
/// (PMMP) 와 동일한 바이트열이 나오므로 그대로 `derive_key` 에 넣을 수 있다.
pub fn ecdh_shared_secret(local: &SecretKey, remote: &PublicKey) -> [u8; 48] {
    let shared = p384::ecdh::diffie_hellman(local.to_nonzero_scalar(), remote.as_affine());
    let mut out = [0u8; 48];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    out
}

/// 암호화 키 유도: key = SHA256( salt ++ shared_secret ).
///
/// `shared_secret` 는 P-384 ECDH 의 48바이트 빅엔디언 X좌표여야 한다
/// (PMMP: hex2bin(str_pad(secret,96,'0',LEFT))).
pub fn derive_key(salt: &[u8], shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(shared_secret);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 같은 키를 가진 두 컨텍스트(서버/클라)가 실제로 통신 가능한지 —
    /// 한쪽 encrypt → 다른쪽 decrypt 가 여러 패킷에 걸쳐 키스트림/카운터 동기 유지.
    #[test]
    fn cross_context_roundtrip_multi_packet() {
        let key = [7u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        for i in 0..32u8 {
            let msg = vec![i; (i as usize) * 13 + 1]; // 길이 가변
            let ct = server.encrypt(&msg);
            // 암호문은 평문과 달라야 함 (checksum 8바이트 추가)
            assert_eq!(ct.len(), msg.len() + 8);
            let pt = client.decrypt(&ct).expect("복호 성공");
            assert_eq!(pt, msg, "패킷 {i} 라운드트립 불일치");
        }
    }

    /// 양방향 동시 통신 (한 컨텍스트의 encrypt/decrypt 스트림이 독립).
    #[test]
    fn bidirectional() {
        let key = [0x42u8; 32];
        let mut a = EncryptionContext::new(key);
        let mut b = EncryptionContext::new(key);

        let m1 = b"hello from a".to_vec();
        let m2 = b"reply from b, longer message here".to_vec();

        let c1 = a.encrypt(&m1);
        assert_eq!(b.decrypt(&c1).unwrap(), m1);
        let c2 = b.encrypt(&m2);
        assert_eq!(a.decrypt(&c2).unwrap(), m2);
    }

    /// 변조된 암호문은 checksum 검증에서 거부돼야 함.
    #[test]
    fn tampered_rejected() {
        let key = [1u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        let mut ct = server.encrypt(b"important payload");
        ct[3] ^= 0xff; // 변조
        assert_eq!(client.decrypt(&ct), Err(DecryptError::BadChecksum));
    }

    /// 너무 짧은 입력 거부.
    #[test]
    fn too_short_rejected() {
        let key = [9u8; 32];
        let mut ctx = EncryptionContext::new(key);
        assert_eq!(ctx.decrypt(&[0u8; 8]), Err(DecryptError::TooShort));
    }

    /// 카운터가 어긋나면(패킷 유실 시뮬) checksum 이 깨져야 함 — 순서 의존성 확인.
    #[test]
    fn counter_desync_detected() {
        let key = [5u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        let _c0 = server.encrypt(b"packet 0");
        let c1 = server.encrypt(b"packet 1");
        // 클라가 c0 를 건너뛰고 c1 을 복호하려 하면 키스트림/카운터 어긋나 실패.
        assert!(client.decrypt(&c1).is_err());
    }

    /// derive_key 결정성.
    #[test]
    fn derive_key_deterministic() {
        let salt = [0xab; 16];
        let secret = [0xcd; 48];
        assert_eq!(derive_key(&salt, &secret), derive_key(&salt, &secret));
        assert_ne!(derive_key(&salt, &secret), derive_key(&[0u8; 16], &secret));
    }

    /// ECDH: 양측이 상대 공개키로 도출한 공유비밀(48B)이 동일해야 하고,
    /// 그걸 derive_key 에 넣으면 같은 AES 키가 나와야 한다 (핸드셰이크 정합성).
    #[test]
    fn ecdh_both_sides_derive_same_key() {
        let a_sec = generate_secret_key();
        let a_pub = a_sec.public_key();
        let b_sec = generate_secret_key();
        let b_pub = b_sec.public_key();

        let s_ab = ecdh_shared_secret(&a_sec, &b_pub);
        let s_ba = ecdh_shared_secret(&b_sec, &a_pub);
        assert_eq!(s_ab, s_ba, "ECDH 공유비밀 양측 불일치");

        let salt = [0x11u8; 16];
        assert_eq!(derive_key(&salt, &s_ab), derive_key(&salt, &s_ba));

        // 그리고 이 키로 만든 두 EncryptionContext 가 실제 통신 가능해야 한다.
        let key = derive_key(&salt, &s_ab);
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);
        let msg = b"vibrant visuals on".to_vec();
        let ct = server.encrypt(&msg);
        assert_eq!(client.decrypt(&ct).unwrap(), msg);
    }
}
