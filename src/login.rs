//! Extracts the displayName and XUID from a Login packet (best-effort, for console/monitoring display only).
//!
//! The proxy forwards login tokens as-is without verifying or decrypting them (plaintext passthrough mode).
//! Here, the chain JWT payload is base64-decoded **for display purposes only** — no signature verification.
//! Any failure at any step silently returns None. This is not a trust boundary; spoofed display values
//! have no security impact.

use base64::Engine;

#[derive(Default)]
pub struct Identity {
    pub name: Option<String>,
    pub xuid: Option<String>,
}

/// Extracts the display name and XUID from a Login game packet (starts with a VarInt packet header). All failures return None.
pub fn extract(login_pkt: &[u8]) -> Identity {
    let id = parse(login_pkt).unwrap_or_default();
    if id.name.is_none() {
        // Display name extraction failed — the Login/chain format may vary across Bedrock versions.
        // Log the first 96 bytes (binary bytes rendered as '.') once per session to aid format diagnosis.
        let head: String = String::from_utf8_lossy(&login_pkt[..login_pkt.len().min(96)])
            .chars()
            .map(|c| if c.is_control() { '.' } else { c })
            .collect();
        tracing::warn!(len = login_pkt.len(), head = %head, "login: failed to extract displayName — first 96B for format diagnosis");
    }
    id
}

fn parse(pkt: &[u8]) -> Option<Identity> {
    // Packet header (VarInt). Login has sub-client id 0, so header == id == 1.
    let (_hdr, adv) = read_varuint(pkt, 0)?;
    let mut p = adv;
    // protocol: int32 BE (4 bytes).
    p = p.checked_add(4)?;
    if p > pkt.len() {
        return None;
    }
    // Connection request: ByteArray (VarUint length prefix + content).
    let (cr_len, adv) = read_varuint(pkt, p)?;
    p += adv;
    let cr_end = p.checked_add(cr_len as usize)?;
    if cr_end > pkt.len() {
        return None;
    }
    let cr = &pkt[p..cr_end];

    // Inside the connection request: LE u32 chainLen + chain JSON + (clientData follows, unused here).
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
                return Some(id); // found a name — return immediately
            }
            if xuid_only.is_none() {
                xuid_only = id.xuid;
            }
        }
    }

    // Fallback: ThirdPartyName from the clientData JWT (display name lives here in offline/newer formats).
    if let Some(name) = client_data_name(cr, chain_end) {
        return Some(Identity { name: Some(name), xuid: xuid_only });
    }
    // No name found — return xuid alone if available (diagnostic logging is handled by the caller).
    xuid_only.map(|xuid| Identity { name: None, xuid: Some(xuid) })
}

/// Extracts ThirdPartyName (display name) from the second block (clientData JWT) of the connectionRequest.
/// Layout: [LE u32 chainLen][chain][LE u32 clientDataLen][clientData JWT].
fn client_data_name(cr: &[u8], chain_end: usize) -> Option<String> {
    if chain_end + 4 > cr.len() {
        return None;
    }
    let cd_len = u32::from_le_bytes([
        cr[chain_end],
        cr[chain_end + 1],
        cr[chain_end + 2],
        cr[chain_end + 3],
    ]) as usize;
    let cd_start = chain_end + 4;
    let cd_end = cd_start.checked_add(cd_len)?;
    if cd_end > cr.len() {
        return None;
    }
    let jwt = std::str::from_utf8(&cr[cd_start..cd_end]).ok()?;
    jwt_payload(jwt)?
        .get("ThirdPartyName")
        .and_then(|x| x.as_str())
        .map(str::to_string)
}

/// Decodes the payload (base64url middle segment) of a JWT (header.payload.sig) into a JSON value.
fn jwt_payload(token: &str) -> Option<serde_json::Value> {
    let b64 = token.split('.').nth(1)?.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Collects chain JWT strings, handling all known formats:
///  - `{"chain":[...]}`                    (legacy format)
///  - `{"Certificate":"{...chain...}"}` (newer format, chain nested inside a string)
///  - Plain array `[...]`
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
    // Newer format (1.26.30): {"AuthenticationType":N, "Token":"<jwt>"} — single-token JWT.
    if let Some(tok) = v.get("Token").and_then(|t| t.as_str()) {
        if !tok.is_empty() {
            return vec![tok.to_string()];
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
    // displayName/XUID are typically inside extraData, but may appear at the payload top level in some versions.
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

/// Decodes a VarUint (LEB128). Returns `(value, bytes_consumed)`, or None if the input exceeds 5 bytes or is truncated.
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
        // Synthetic Login: header(1) + protocol(4 BE) + connReq(VarUint len + [LE u32 chainLen + chainJSON]).
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
        pkt.push(0x01); // header
        pkt.extend_from_slice(&[0, 0, 0, 100]); // protocol int32 BE
        // connection request length (VarUint) + content
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

    // Builds a synthetic Login packet: header(1) + protocol(4 BE) + connReq(VarUint len + [LE u32 chainLen + chainJSON]).
    fn synth_login(chain_json: &str) -> Vec<u8> {
        let cb = chain_json.as_bytes();
        let mut cr = Vec::new();
        cr.extend_from_slice(&(cb.len() as u32).to_le_bytes());
        cr.extend_from_slice(cb);
        let mut pkt = vec![0x01u8, 0, 0, 0, 100]; // header + protocol
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
        // Newer format: top-level {"Certificate": "<json string with chain>"}.
        let jwt = jwt_with(serde_json::json!({"displayName": "Alex", "XUID": "9001"}));
        let inner = serde_json::json!({ "chain": [jwt] }).to_string();
        let chain = serde_json::json!({"AuthenticationType": 2, "Certificate": inner}).to_string();
        let id = extract(&synth_login(&chain));
        assert_eq!(id.name.as_deref(), Some("Alex"));
        assert_eq!(id.xuid.as_deref(), Some("9001"));
    }

    #[test]
    fn extracts_displayname_from_token_format() {
        // 1.26.30 newer format: {"AuthenticationType":N, "Token":"<jwt>"}, name is in Token's extraData.
        let token = jwt_with(serde_json::json!({"displayName": "Jeb", "XUID": "7"}));
        let chain = serde_json::json!({"AuthenticationType": 0, "Token": token}).to_string();
        let id = extract(&synth_login(&chain));
        assert_eq!(id.name.as_deref(), Some("Jeb"));
        assert_eq!(id.xuid.as_deref(), Some("7"));
    }

    #[test]
    fn falls_back_to_clientdata_thirdpartyname() {
        // If Token has no displayName (e.g. offline mode), fall back to ThirdPartyName from clientData.
        let token = jwt_with(serde_json::json!({"XUID": "5"})); // no displayName
        let chain = serde_json::json!({"AuthenticationType": 0, "Token": token}).to_string();
        let client_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({"ThirdPartyName": "Notch"}).to_string());
        let client_jwt = format!("hdr.{client_payload}.sig");

        // cr = [LE u32 chainLen][chain][LE u32 clientDataLen][clientData JWT]
        let mut cr = Vec::new();
        cr.extend_from_slice(&(chain.len() as u32).to_le_bytes());
        cr.extend_from_slice(chain.as_bytes());
        cr.extend_from_slice(&(client_jwt.len() as u32).to_le_bytes());
        cr.extend_from_slice(client_jwt.as_bytes());

        let mut pkt = vec![0x01u8, 0, 0, 0, 100]; // header + protocol
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
        assert_eq!(id.name.as_deref(), Some("Notch"));
        assert_eq!(id.xuid.as_deref(), Some("5"));
    }
}
