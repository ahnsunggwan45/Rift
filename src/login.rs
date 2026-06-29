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
    let id = parse(login_pkt).unwrap_or_default();
    if id.name.is_none() {
        // 이름 추출 실패 — Bedrock 버전마다 Login/chain 포맷이 다를 수 있다. 포맷 파악용으로
        // 로그인 앞부분(헤더·길이 등 바이너리는 '.')을 1회 로깅한다(세션당 1회만 호출됨).
        let head: String = String::from_utf8_lossy(&login_pkt[..login_pkt.len().min(96)])
            .chars()
            .map(|c| if c.is_control() { '.' } else { c })
            .collect();
        tracing::warn!(len = login_pkt.len(), head = %head, "login: displayName 추출 실패 — 앞 96B(포맷 진단)");
    }
    id
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

    let jwts = collect_chain_jwts(&v);
    let mut xuid_only: Option<String> = None;
    for jwt in &jwts {
        if let Some(id) = identity_from_jwt(jwt) {
            if id.name.is_some() {
                return Some(id); // 이름 찾으면 즉시 반환
            }
            if xuid_only.is_none() {
                xuid_only = id.xuid;
            }
        }
    }

    // 이름 못 찾음 — xuid 만이라도 있으면 반환(진단 로깅은 호출부 extract 에서 일괄 처리).
    xuid_only.map(|xuid| Identity { name: None, xuid: Some(xuid) })
}

/// chain JWT 문자열들을 모은다. 알려진 포맷 모두 대응:
///  - `{"chain":[...]}`              (구 포맷)
///  - `{"Certificate":"{...chain...}"}` (신 포맷, 문자열 안에 중첩)
///  - 순수 배열 `[...]`
fn collect_chain_jwts(v: &serde_json::Value) -> Vec<String> {
    fn as_str_vec(val: &serde_json::Value) -> Option<Vec<String>> {
        Some(
            val.as_array()?
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
        )
    }
    if let Some(c) = v.get("chain").and_then(as_str_vec) {
        return c;
    }
    if let Some(cert) = v.get("Certificate").and_then(|c| c.as_str()) {
        if let Ok(inner) = serde_json::from_str::<serde_json::Value>(cert) {
            if let Some(c) = inner.get("chain").and_then(as_str_vec) {
                return c;
            }
        }
    }
    as_str_vec(v).unwrap_or_default()
}

fn identity_from_jwt(token: &str) -> Option<Identity> {
    let payload_b64 = token.split('.').nth(1)?.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    // displayName/XUID 는 보통 extraData 안에 있으나, 버전에 따라 페이로드 최상위에 있기도 하다.
    let src = v.get("extraData").unwrap_or(&v);
    let name = src
        .get("displayName")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let xuid = src.get("XUID").and_then(|x| x.as_str()).map(str::to_string);
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

    // 헤더(1) + protocol(4 BE) + connReq(VarUint len + [LE u32 chainLen + chainJSON]) 로 합성 Login 생성.
    fn synth_login(chain_json: &str) -> Vec<u8> {
        let cb = chain_json.as_bytes();
        let mut cr = Vec::new();
        cr.extend_from_slice(&(cb.len() as u32).to_le_bytes());
        cr.extend_from_slice(cb);
        let mut pkt = vec![0x01u8, 0, 0, 0, 100]; // 헤더 + protocol
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
        pkt
    }

    fn jwt_with(extra: serde_json::Value) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "extraData": extra }).to_string());
        format!("hdr.{b64}.sig")
    }

    #[test]
    fn extracts_from_nested_certificate_format() {
        // 신 포맷: 최상위 {"Certificate": "<json string with chain>"}.
        let jwt = jwt_with(serde_json::json!({"displayName": "Alex", "XUID": "9001"}));
        let inner = serde_json::json!({ "chain": [jwt] }).to_string();
        let chain = serde_json::json!({"AuthenticationType": 2, "Certificate": inner}).to_string();
        let id = extract(&synth_login(&chain));
        assert_eq!(id.name.as_deref(), Some("Alex"));
        assert_eq!(id.xuid.as_deref(), Some("9001"));
    }
}
