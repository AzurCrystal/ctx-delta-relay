use http::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashSet;
use subtle::ConstantTimeEq;

pub const HDR_AUTH: &str = "x-delta-auth";
pub const HDR_CLIENT_AUTH: &str = "x-delta-client-auth";
pub const HDR_MODE: &str = "x-delta-mode";
pub const HDR_BASE: &str = "x-delta-base";
pub const HDR_FULL: &str = "x-delta-full";
pub const HDR_RAW_LEN: &str = "x-delta-raw-len";
pub const HDR_MISS: &str = "x-delta-miss";
pub const HDR_CACHED: &str = "x-delta-cached";

pub const MODE_PASS: &str = "pass";
pub const MODE_FULL: &str = "full";
pub const MODE_DELTA: &str = "delta";

/// Constant-time authentication check against an expected secret in `header_name`.
pub fn verify_header_secret(headers: &HeaderMap, header_name: &str, expected: &str) -> bool {
    let Some(val) = headers.get(header_name) else {
        return false;
    };
    let provided = val.as_bytes();
    let expected_bytes = expected.as_bytes();
    if provided.len() != expected_bytes.len() {
        return false;
    }
    bool::from(provided.ct_eq(expected_bytes))
}

pub fn verify_secret(headers: &HeaderMap, expected: &str) -> bool {
    verify_header_secret(headers, HDR_AUTH, expected)
}

/// Detect WebSocket upgrade attempts so they are explicitly rejected with 501 instead of
/// silently mangled into broken plain HTTP requests.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Collect any additional hop-by-hop header names nominated by `Connection` headers (RFC 9110 §7.6.1).
fn connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for val in headers.get_all(http::header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let name = token.trim().to_ascii_lowercase();
                if !name.is_empty() {
                    out.insert(name);
                }
            }
        }
    }
    out
}

/// Static hop-by-hop and internal delta headers stripped from forwarded requests.
pub fn is_stripped_request_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    matches!(
        s,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | HDR_AUTH
            | HDR_CLIENT_AUTH
            | HDR_MODE
            | HDR_BASE
            | HDR_FULL
            | HDR_RAW_LEN
            | HDR_MISS
            | HDR_CACHED
    )
}

/// Static hop-by-hop and internal delta headers stripped from forwarded responses.
pub fn is_stripped_response_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    matches!(
        s,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | HDR_MISS
            | HDR_CACHED
    )
}

/// Copy headers while stripping both static hop-by-hop/internal headers AND any headers
/// dynamically listed in `Connection` (RFC 9110 §7.6.1).
pub fn copy_filtered_headers(src: &HeaderMap, filter: fn(&HeaderName) -> bool) -> HeaderMap {
    let dynamic_hop = connection_nominated_headers(src);
    let mut dst = HeaderMap::with_capacity(src.len());
    for (k, v) in src.iter() {
        if !filter(k) && !dynamic_hop.contains(k.as_str()) {
            dst.append(k.clone(), v.clone());
        }
    }
    dst
}

pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in hash {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_to_hash(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = from_hex_nibble(bytes[i * 2])?;
        let lo = from_hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn header_str<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key)?.to_str().ok()
}

pub fn set_header(headers: &mut HeaderMap, key: &'static str, val: &str) {
    if let Ok(hv) = HeaderValue::from_str(val) {
        headers.insert(HeaderName::from_static(key), hv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_connection_nominated_hop_by_hop_headers() {
        let mut src = HeaderMap::new();
        src.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Custom-Hop, X-Trace-Hop"),
        );
        src.insert("x-custom-hop", HeaderValue::from_static("drop-me"));
        src.insert("x-trace-hop", HeaderValue::from_static("drop-me-too"));
        src.insert("x-keep-me", HeaderValue::from_static("preserve"));
        src.insert(HDR_CLIENT_AUTH, HeaderValue::from_static("secret"));

        let dst = copy_filtered_headers(&src, is_stripped_request_header);
        assert!(dst.get(http::header::CONNECTION).is_none());
        assert!(dst.get("x-custom-hop").is_none());
        assert!(dst.get("x-trace-hop").is_none());
        assert!(dst.get(HDR_CLIENT_AUTH).is_none());
        assert_eq!(dst.get("x-keep-me").unwrap(), "preserve");
    }
}
