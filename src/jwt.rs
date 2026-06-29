//! Bedrock 핸드셰이크 JWT — ES384 (P-384 + SHA-384), 헤더 x5u = base64(DER 공개키).
//!
//! ground truth: PMMP `EncryptionUtils::generateServerHandshakeJwt` (docs/phase1b-design.md).
//! - JWT 구조 부분(header.payload.sig)은 base64url(no pad).
//! - x5u / salt 값은 표준 base64(padding) — PMMP 가 base64_encode 사용.
//! - 서명: ECDSA P-384 / SHA-384, r||s 96바이트.
//!
//! 용도:
//! - 프록시→클라: ServerToClientHandshake JWT 생성(프록시 키로 서명).
//! - 다운스트림→프록시: 받은 ServerToClientHandshake 파싱(서버 공개키 x5u + salt 추출).

#![allow(dead_code)] // 핸드셰이크 상태머신 연결 전까지 일부 미사용

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use p384::ecdsa::signature::{Signer, Verifier};
use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::{PublicKey, SecretKey};
use serde_json::{json, Value};

/// P-384 공개키를 DER(SubjectPublicKeyInfo)로 인코딩 후 표준 base64. JWT x5u 용.
pub fn public_key_der_b64(public: &PublicKey) -> Result<String> {
    let der = public
        .to_public_key_der()
        .map_err(|e| anyhow!("DER 인코딩 실패: {e}"))?;
    Ok(B64.encode(der.as_bytes()))
}

/// ServerToClientHandshake JWT 를 만든다. header{alg:ES384, x5u}, payload{salt}.
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

/// 핸드셰이크 JWT 파싱 결과: 상대 공개키(ECDH 용)와 salt.
pub struct HandshakeData {
    pub remote_public: PublicKey,
    pub salt: Vec<u8>,
}

/// ServerToClientHandshake JWT 를 파싱·서명검증하고 (공개키, salt)를 반환한다.
/// 서명은 헤더 x5u 의 공개키로 self-verify 한다 (Mojang 루트 체인 검증은 별도 관심사).
pub fn parse_handshake_jwt(token: &str) -> Result<HandshakeData> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("JWT 형식 오류 (부분 {}개)", parts.len());
    }

    let header: Value =
        serde_json::from_slice(&B64URL.decode(parts[0])?).context("JWT 헤더 디코드")?;
    let x5u = header
        .get("x5u")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("JWT 헤더에 x5u 없음"))?;
    let der = B64.decode(x5u).context("x5u base64 디코드")?;

    // 서명 검증
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = Signature::from_slice(&B64URL.decode(parts[2])?).context("서명 디코드")?;
    let verifying_key =
        VerifyingKey::from_public_key_der(&der).map_err(|e| anyhow!("x5u 공개키 파싱 실패: {e}"))?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| anyhow!("JWT 서명 검증 실패"))?;

    let remote_public =
        PublicKey::from_public_key_der(&der).map_err(|e| anyhow!("x5u 공개키 파싱 실패: {e}"))?;

    let payload: Value =
        serde_json::from_slice(&B64URL.decode(parts[1])?).context("JWT payload 디코드")?;
    let salt = B64.decode(
        payload
            .get("salt")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("payload 에 salt 없음"))?,
    )
    .context("salt base64 디코드")?;

    Ok(HandshakeData { remote_public, salt })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, ecdh_shared_secret, generate_secret_key, EncryptionContext};

    /// 프록시가 만든 핸드셰이크 JWT 를 상대가 파싱·검증하고, 추출한 공개키+salt 로
    /// ECDH→derive_key 하면 프록시와 같은 AES 키가 나와야 한다 (실제 핸드셰이크 흐름).
    #[test]
    fn handshake_jwt_roundtrip_and_key_agreement() {
        // 프록시(서버 역) 키 + salt
        let server_secret = generate_secret_key();
        let salt = [0x5a_u8; 16];
        let token = create_handshake_jwt(&server_secret, &salt).unwrap();

        // 상대(클라 역)가 파싱
        let parsed = parse_handshake_jwt(&token).unwrap();
        assert_eq!(parsed.salt, salt, "salt 불일치");
        assert_eq!(parsed.remote_public, server_secret.public_key(), "x5u 공개키 불일치");

        // 양측 키 합의: 클라 키쌍 생성 → 양쪽이 같은 AES 키 도출
        let client_secret = generate_secret_key();
        let client_public = client_secret.public_key();

        // 서버측: ECDH(serverPriv, clientPub)
        let server_key = derive_key(&salt, &ecdh_shared_secret(&server_secret, &client_public));
        // 클라측: ECDH(clientPriv, serverPub=parsed.remote_public)
        let client_key = derive_key(&salt, &ecdh_shared_secret(&client_secret, &parsed.remote_public));
        assert_eq!(server_key, client_key, "양측 AES 키 불일치");

        // 그 키로 통신 가능 확인
        let mut s = EncryptionContext::new(server_key);
        let mut c = EncryptionContext::new(client_key);
        let ct = s.encrypt(b"handshake complete");
        assert_eq!(c.decrypt(&ct).unwrap(), b"handshake complete");
    }

    /// 변조된 JWT 는 서명 검증에서 거부돼야 한다.
    #[test]
    fn tampered_jwt_rejected() {
        let secret = generate_secret_key();
        let token = create_handshake_jwt(&secret, &[1u8; 16]).unwrap();

        // payload 부분의 한 글자를 바꿔 변조
        let mut parts: Vec<String> = token.split('.').map(|s| s.to_string()).collect();
        let bytes = unsafe { parts[1].as_bytes_mut() };
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered = parts.join(".");

        assert!(parse_handshake_jwt(&tampered).is_err(), "변조 JWT 가 통과됨");
    }
}
