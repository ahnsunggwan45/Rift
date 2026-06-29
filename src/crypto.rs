//! Bedrock game-packet encryption — AES-256-CTR "fake GCM".
//!
//! A 1:1 port of PMMP `EncryptionContext` (ground truth: docs/phase1b-design.md).
//! - Cipher: AES-256-CTR, IV = key[0:12] ++ 00 00 00 02 (OpenSSL CTR = 128-bit BE counter).
//! - The CTR keystream is continuous across the entire connection (no re-initialization per packet).
//! - Per-packet 8-byte checksum = SHA256( LE_u64(counter) ++ payload ++ key )[0:8].
//! - Separate encrypt/decrypt counters, each starting at 0 and incrementing by 1 per packet.

#![allow(dead_code)] // Some items unused until the Phase 1b handshake is wired up

use aes::cipher::{KeyIvInit, StreamCipher};
use p384::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Matches OpenSSL "AES-256-CTR": the full 16-byte IV is treated as a 128-bit big-endian counter.
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

#[derive(Debug, PartialEq, Eq)]
pub enum DecryptError {
    /// Payload is too short to contain the 8-byte checksum.
    TooShort,
    /// Checksum mismatch (tampering or counter/key desync).
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
    /// Creates a context from a 32-byte key. IV = key[0:12] ++ 00000002.
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

    /// Encrypts a plaintext batch: AES_CTR(payload ++ checksum).
    pub fn encrypt(&mut self, payload: &[u8]) -> Vec<u8> {
        let checksum = self.checksum(self.encrypt_counter, payload);
        self.encrypt_counter = self.encrypt_counter.wrapping_add(1);

        let mut buf = Vec::with_capacity(payload.len() + 8);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&checksum);
        self.encrypt_cipher.apply_keystream(&mut buf);
        buf
    }

    /// Decrypts ciphertext and verifies the checksum. Returns the plaintext batch on success.
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

/// Generates a P-384 (secp384r1) secret key. The same key is used for both ECDH (shared secret)
/// and ECDSA/ES384 JWT signing — the Bedrock handshake uses one key for both signing and key exchange.
/// The proxy generates a separate key for each side: client-facing and downstream-facing.
pub fn generate_secret_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

/// Derives the ECDH shared secret (48-byte big-endian X coordinate). Produces the same byte sequence
/// as OpenSSL `openssl_pkey_derive` (PMMP), so the result can be passed directly to `derive_key`.
pub fn ecdh_shared_secret(local: &SecretKey, remote: &PublicKey) -> [u8; 48] {
    let shared = p384::ecdh::diffie_hellman(local.to_nonzero_scalar(), remote.as_affine());
    let mut out = [0u8; 48];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    out
}

/// Derives the encryption key: key = SHA256( salt ++ shared_secret ).
///
/// `shared_secret` must be the 48-byte big-endian X coordinate from P-384 ECDH
/// (PMMP: `hex2bin(str_pad(secret,96,'0',LEFT))`).
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

    /// Verifies that two contexts sharing the same key (server/client) can communicate —
    /// encrypt on one side → decrypt on the other maintains keystream/counter sync across multiple packets.
    #[test]
    fn cross_context_roundtrip_multi_packet() {
        let key = [7u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        for i in 0..32u8 {
            let msg = vec![i; (i as usize) * 13 + 1]; // variable length
            let ct = server.encrypt(&msg);
            // Ciphertext must differ from plaintext (8 checksum bytes appended)
            assert_eq!(ct.len(), msg.len() + 8);
            let pt = client.decrypt(&ct).expect("decryption succeeded");
            assert_eq!(pt, msg, "packet {i} round-trip mismatch");
        }
    }

    /// Bidirectional simultaneous communication (encrypt and decrypt streams within one context are independent).
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

    /// Tampered ciphertext must be rejected by checksum verification.
    #[test]
    fn tampered_rejected() {
        let key = [1u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        let mut ct = server.encrypt(b"important payload");
        ct[3] ^= 0xff; // tamper
        assert_eq!(client.decrypt(&ct), Err(DecryptError::BadChecksum));
    }

    /// Inputs that are too short must be rejected.
    #[test]
    fn too_short_rejected() {
        let key = [9u8; 32];
        let mut ctx = EncryptionContext::new(key);
        assert_eq!(ctx.decrypt(&[0u8; 8]), Err(DecryptError::TooShort));
    }

    /// Counter desync (simulating packet loss) must corrupt the checksum — validates ordering dependency.
    #[test]
    fn counter_desync_detected() {
        let key = [5u8; 32];
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);

        let _c0 = server.encrypt(b"packet 0");
        let c1 = server.encrypt(b"packet 1");
        // If the client skips c0 and tries to decrypt c1, the keystream/counter is desynced and decryption fails.
        assert!(client.decrypt(&c1).is_err());
    }

    /// `derive_key` must be deterministic.
    #[test]
    fn derive_key_deterministic() {
        let salt = [0xab; 16];
        let secret = [0xcd; 48];
        assert_eq!(derive_key(&salt, &secret), derive_key(&salt, &secret));
        assert_ne!(derive_key(&salt, &secret), derive_key(&[0u8; 16], &secret));
    }

    /// ECDH: both sides deriving the shared secret (48 B) from each other's public key must agree,
    /// and feeding that secret into `derive_key` must produce the same AES key (handshake correctness).
    #[test]
    fn ecdh_both_sides_derive_same_key() {
        let a_sec = generate_secret_key();
        let a_pub = a_sec.public_key();
        let b_sec = generate_secret_key();
        let b_pub = b_sec.public_key();

        let s_ab = ecdh_shared_secret(&a_sec, &b_pub);
        let s_ba = ecdh_shared_secret(&b_sec, &a_pub);
        assert_eq!(s_ab, s_ba, "ECDH shared secret mismatch between sides");

        let salt = [0x11u8; 16];
        assert_eq!(derive_key(&salt, &s_ab), derive_key(&salt, &s_ba));

        // The two EncryptionContexts built from this key must also be able to communicate.
        let key = derive_key(&salt, &s_ab);
        let mut server = EncryptionContext::new(key);
        let mut client = EncryptionContext::new(key);
        let msg = b"vibrant visuals on".to_vec();
        let ct = server.encrypt(&msg);
        assert_eq!(client.decrypt(&ct).unwrap(), msg);
    }
}
