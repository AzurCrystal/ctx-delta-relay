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

/// Detect WebSocket upgrade attempts so they are explicitly rejected with 501.
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

/// Static hop-by-hop (RFC 9110 §7.6.1 + §6.5.1 `trailer`) and ALL internal `x-delta-*` headers
/// stripped from forwarded requests (fixes R2-12).
pub fn is_stripped_request_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    s.starts_with("x-delta-")
        || matches!(
            s,
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "http2-settings"
                | "host"
                | "content-length"
        )
}

/// Static hop-by-hop and ALL internal `x-delta-*` headers stripped from forwarded responses (fixes R2-12).
pub fn is_stripped_response_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    s.starts_with("x-delta-")
        || matches!(
            s,
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "http2-settings"
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

/// Derive a 32-byte tenant/credential isolation scope from ALL common API auth headers & query key
/// so distinct tenants can never collide in sender session index OR share cache entries on receiver (R2-07).
pub fn derive_tenant_scope(headers: &HeaderMap, query: Option<&str>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ctx-delta-tenant-v1\0");

    let mut found_any = false;
    for hdr in [
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "x-tenant-id",
    ] {
        for val in headers.get_all(hdr) {
            if !val.is_empty() {
                found_any = true;
                hasher.update(&(hdr.len() as u32).to_le_bytes());
                hasher.update(hdr.as_bytes());
                hasher.update(&(val.len() as u64).to_le_bytes());
                hasher.update(val.as_bytes());
            }
        }
    }

    if let Some(q) = query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && matches!(k, "key" | "api_key" | "apikey")
                && !v.is_empty()
            {
                found_any = true;
                hasher.update(b"qkey");
                hasher.update(&(v.len() as u64).to_le_bytes());
                hasher.update(v.as_bytes());
            }
        }
    }

    if !found_any {
        hasher.update(b"anonymous");
    }
    *hasher.finalize().as_bytes()
}

/// Combine tenant scope + content hash into an isolated cache key on receiver/sender (R2-07).
pub fn scoped_cache_key(tenant_scope: &[u8; 32], content_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ctx-delta-scoped-key-v1\0");
    hasher.update(tenant_scope);
    hasher.update(content_hash);
    *hasher.finalize().as_bytes()
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
    fn strips_trailer_internal_x_delta_and_connection_nominated_headers() {
        let mut src = HeaderMap::new();
        src.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive, X-Custom-Hop, X-Trace-Hop"),
        );
        src.insert("trailer", HeaderValue::from_static("Expires"));
        src.insert("http2-settings", HeaderValue::from_static("AAMAAABkAAQAAP__"));
        src.insert("x-custom-hop", HeaderValue::from_static("drop-me"));
        src.insert("x-trace-hop", HeaderValue::from_static("drop-me-too"));
        src.insert("x-delta-unknown-future", HeaderValue::from_static("strip-me"));
        src.insert("x-keep-me", HeaderValue::from_static("preserve"));
        src.insert(HDR_CLIENT_AUTH, HeaderValue::from_static("secret"));

        let dst = copy_filtered_headers(&src, is_stripped_request_header);
        assert!(dst.get(http::header::CONNECTION).is_none());
        assert!(dst.get("trailer").is_none());
        assert!(dst.get("http2-settings").is_none());
        assert!(dst.get("x-custom-hop").is_none());
        assert!(dst.get("x-trace-hop").is_none());
        assert!(dst.get("x-delta-unknown-future").is_none());
        assert!(dst.get(HDR_CLIENT_AUTH).is_none());
        assert_eq!(dst.get("x-keep-me").unwrap(), "preserve");
    }

    #[test]
    fn tenant_scope_isolates_api_key_headers_and_query_keys() {
        let mut h1 = HeaderMap::new();
        h1.insert("x-goog-api-key", HeaderValue::from_static("key-tenant-a"));
        let mut h2 = HeaderMap::new();
        h2.insert("x-goog-api-key", HeaderValue::from_static("key-tenant-b"));

        assert_ne!(derive_tenant_scope(&h1, None), derive_tenant_scope(&h2, None));

        let empty = HeaderMap::new();
        assert_ne!(
            derive_tenant_scope(&empty, Some("key=alpha")),
            derive_tenant_scope(&empty, Some("key=beta"))
        );
    }
}
