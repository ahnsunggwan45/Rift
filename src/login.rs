//! Login 패킷에서 displayName/XUID 추출 (best-effort, 콘솔/모니터링 표시 전용).
//!
//! 프록시는 로그인 토큰을 검증·복호화하지 않고 그대로 포워딩한다(평문 A모드). 여기서는
//! **표시 목적으로만** chain JWT 페이로드를 base64 디코드해 읽는다 — 서명 검증 없음, 어떤
//! 단계든 실패하면 조용히 None. 신뢰 경계가 아니므로 표시값이 위조돼도 보안 영향 없음.

use base64::Engine;

#[derive(Default)]
pub struct Identity {
    pub name: Option<String>,
    pub xuid: Option<String>,
}

/// Login 게임패킷 바이트(VarInt 패킷헤더로 시작)에서 이름/XUID 를 뽑는다. 실패는 전부 None.
pub fn extract(login_pkt: &[u8]) -> Identity {
    parse(login_pkt).unwrap_or_default()
}

fn parse(pkt: &[u8]) -> Option<Identity> {
    // 패킷 헤더(VarInt). Login 은 sub-client id 0 이라 헤더 == id == 1.
    let (_hdr, adv) = read_varuint(pkt, 0)?;
    let mut p = adv;
    // protocol: int32 BE (4 bytes).
    p = p.checked_add(4)?;
    if p > pkt.len() {
        return None;
    }
    // connection request: ByteArray (VarUint 길이 + 내용).
    let (cr_len, adv) = read_varuint(pkt, p)?;
    p += adv;
    let cr_end = p.checked_add(cr_len as usize)?;
    if cr_end > pkt.len() {
        return None;
    }
    let cr = &pkt[p..cr_end];

    // connection request 내부: LE u32 chainLen + chain JSON + (이후 clientData, 미사용).
    if cr.len() < 4 {
        return None;
    }
    let chain_len = u32::from_le_bytes([cr[0], cr[1], cr[2], cr[3]]) as usize;
    let chain_end = 4usize.checked_add(chain_len)?;
    if chain_end > cr.len() {
        return None;
    }
    let chain_json = &cr[4..chain_end];

    let v: serde_json::Value = serde_json::from_slice(chain_json).ok()?;
    let chain = v.get("chain")?.as_array()?;
    // extraData 를 가진 JWT(보통 마지막)에서 displayName/XUID 추출.
    for jwt in chain {
        if let Some(id) = jwt.as_str().and_then(identity_from_jwt) {
            return Some(id);
        }
    }
    None
}

fn identity_from_jwt(token: &str) -> Option<Identity> {
    let payload_b64 = token.split('.').nth(1)?.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let extra = v.get("extraData")?;
    let name = extra
        .get("displayName")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let xuid = extra.get("XUID").and_then(|x| x.as_str()).map(str::to_string);
    if name.is_none() && xuid.is_none() {
        return None;
    }
    Some(Identity { name, xuid })
}

/// VarUint(LEB128) 디코드. (값, 소비 바이트) 반환. 5바이트 초과/버퍼 부족이면 None.
fn read_varuint(buf: &[u8], start: usize) -> Option<(u32, usize)> {
    let mut p = start;
    let mut result = 0u32;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(p)?;
        p += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
    Some((result, p - start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_garbage_is_none() {
        assert!(extract(&[]).name.is_none());
        assert!(extract(&[0x01]).name.is_none());
        assert!(extract(&[0x01, 0, 0, 0, 0]).name.is_none());
    }

    #[test]
    fn extracts_from_synthetic_login() {
        // 합성 Login: 헤더(1) + protocol(4 BE) + connReq(VarUint len + [LE u32 chainLen + chainJSON]).
        let payload = serde_json::json!({"extraData": {"displayName": "Steve", "XUID": "2535"}});
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
        let jwt = format!("eyJhbGciOiJFUzM4NCJ9.{payload_b64}.sig");
        let chain = serde_json::json!({"chain": [jwt]}).to_string();
        let chain_bytes = chain.as_bytes();

        let mut cr = Vec::new();
        cr.extend_from_slice(&(chain_bytes.len() as u32).to_le_bytes());
        cr.extend_from_slice(chain_bytes);

        let mut pkt = Vec::new();
        pkt.push(0x01); // 헤더
        pkt.extend_from_slice(&[0, 0, 0, 100]); // protocol int32 BE
        // connection request 길이(VarUint) + 내용
        let mut len = cr.len() as u32;
        loop {
            let mut b = (len & 0x7f) as u8;
            len >>= 7;
            if len != 0 {
                b |= 0x80;
            }
            pkt.push(b);
            if len == 0 {
                break;
            }
        }
        pkt.extend_from_slice(&cr);

        let id = extract(&pkt);
        assert_eq!(id.name.as_deref(), Some("Steve"));
        assert_eq!(id.xuid.as_deref(), Some("2535"));
    }
}
