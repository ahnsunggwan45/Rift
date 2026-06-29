//! Bedrock handshake JWT — ES384 (P-384 + SHA-384), header x5u = base64(DER public key).
//!
//! Ground truth: PMMP `EncryptionUtils::generateServerHandshakeJwt` (docs/phase1b-design.md).
//! - JWT structural parts (header.payload.sig) use base64url (no padding).
//! - x5u / salt values use standard base64 (with padding) — PMMP uses `base64_encode`.
//! - Signature: ECDSA P-384 / SHA-384, r||s 96 bytes.
//!
//! Usage:
//! - Proxy → client: build the `ServerToClientHandshake` JWT (signed with the proxy key).
//! - Downstream → proxy: parse the received `ServerToClientHandshake` JWT (extract server public key x5u + salt).

#![allow(dead_code)] // Some items unused until the handshake state machine is wired up

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::{PublicKey, SecretKey};
use serde_json::{json, Value};

/// Encodes a P-384 public key as DER (SubjectPublicKeyInfo) then standard base64. Used for the JWT x5u field.
pub fn public_key_der_b64(public: &PublicKey) -> Result<String> {
    let der = public
        .to_public_key_der()
        .map_err(|e| anyhow!("DER encoding failed: {e}"))?;
    Ok(B64.encode(der.as_bytes()))
}

/// Builds a `ServerToClientHandshake` JWT with header `{alg:ES384, x5u}` and payload `{salt}`.
pub fn create_handshake_jwt(secret: &SecretKey, salt: &[u8]) -> Result<String> {
    let public = secret.public_key();
    let header = json!({ "alg": "ES384", "x5u": public_key_der_b64(&public)? });
    let payload = json!({ "salt": B64.encode(salt) });

    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header)?),
        B64URL.encode(serde_json::to_vec(&payload)?),
    );

    let signing_key = SigningKey::from(secret);
    let sig: Signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!("{}.{}", signing_input, B64URL.encode(sig.to_bytes())))
}

/// Parsed handshake JWT result: the remote public key (for ECDH) and salt.
pub struct HandshakeData {
    pub remote_public: PublicKey,
    pub salt: Vec<u8>,
}

/// Parses and signature-verifies a `ServerToClientHandshake` JWT, returning (public key, salt).
/// The signature is self-verified against the x5u public key in the header (Mojang root chain
/// verification is a separate concern).
pub fn parse_handshake_jwt(token: &str) -> Result<HandshakeData> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("malformed JWT: expected 3 parts, got {}", parts.len());
    }

    let header: Value =
        serde_json::from_slice(&B64URL.decode(parts[0])?).context("JWT header decode")?;
    let x5u = header
        .get("x5u")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWT header missing x5u"))?;
    let der = B64.decode(x5u).context("x5u base64 decode")?;

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = Signature::from_slice(&B64URL.decode(parts[2])?).context("signature decode")?;
    let verifying_key =
        VerifyingKey::from_public_key_der(&der).map_err(|e| anyhow!("failed to parse x5u public key: {e}"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("JWT signature verification failed"))?;

    let remote_public =
        PublicKey::from_public_key_der(&der).map_err(|e| anyhow!("failed to parse x5u public key: {e}"))?;

    let payload: Value =
        serde_json::from_slice(&B64URL.decode(parts[1])?).context("JWT payload decode")?;
    let salt = B64.decode(
        payload
            .get("salt")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("payload missing salt"))?,
    )
    .context("salt base64 decode")?;

    Ok(HandshakeData { remote_public, salt })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, ecdh_shared_secret, generate_secret_key, EncryptionContext};

    /// The peer parses and verifies a handshake JWT produced by the proxy; running ECDH → derive_key
    /// on the extracted public key + salt must yield the same AES key as the proxy (actual handshake flow).
    #[test]
    fn handshake_jwt_roundtrip_and_key_agreement() {
        // Proxy (server role) key + salt
        let server_secret = generate_secret_key();
        let salt = [0x5a_u8; 16];
        let token = create_handshake_jwt(&server_secret, &salt).unwrap();

        // Peer (client role) parses the JWT
        let parsed = parse_handshake_jwt(&token).unwrap();
        assert_eq!(parsed.salt, salt, "salt mismatch");
        assert_eq!(parsed.remote_public, server_secret.public_key(), "x5u public key mismatch");

        // Key agreement: generate client key pair → both sides derive the same AES key
        let client_secret = generate_secret_key();
        let client_public = client_secret.public_key();

        // Server side: ECDH(serverPriv, clientPub)
        let server_key = derive_key(&salt, &ecdh_shared_secret(&server_secret, &client_public));
        // Client side: ECDH(clientPriv, serverPub=parsed.remote_public)
        let client_key = derive_key(&salt, &ecdh_shared_secret(&client_secret, &parsed.remote_public));
        assert_eq!(server_key, client_key, "AES key mismatch between sides");

        // Confirm that the two contexts can communicate with this key
        let mut s = EncryptionContext::new(server_key);
        let mut c = EncryptionContext::new(client_key);
        let ct = s.encrypt(b"handshake complete");
        assert_eq!(c.decrypt(&ct).unwrap(), b"handshake complete");
    }

    /// A tampered JWT must be rejected by signature verification.
    #[test]
    fn tampered_jwt_rejected() {
        let secret = generate_secret_key();
        let token = create_handshake_jwt(&secret, &[1u8; 16]).unwrap();

        // Flip one byte of the payload part to tamper with it
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        let bytes = unsafe { parts[1].as_bytes_mut() };
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered = parts.join(".");

        assert!(parse_handshake_jwt(&tampered).is_err(), "tampered JWT passed verification");
    }
}
