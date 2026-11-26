use http::{HeaderMap, HeaderName, HeaderValue};
use subtle::ConstantTimeEq;

pub const HDR_AUTH: &str = "x-delta-auth";
pub const HDR_MODE: &str = "x-delta-mode";
pub const HDR_BASE: &str = "x-delta-base";
pub const HDR_FULL: &str = "x-delta-full";
pub const HDR_RAW_LEN: &str = "x-delta-raw-len";
pub const HDR_MISS: &str = "x-delta-miss";

pub const MODE_PASS: &str = "pass";
pub const MODE_FULL: &str = "full";
pub const MODE_DELTA: &str = "delta";

/// Constant-time authentication check against the shared secret.
pub fn verify_secret(headers: &HeaderMap, expected: &str) -> bool {
    let Some(val) = headers.get(HDR_AUTH) else {
        return false;
    };
    let provided = val.as_bytes();
    let expected_bytes = expected.as_bytes();
    if provided.len() != expected_bytes.len() {
        return false;
    }
    bool::from(provided.ct_eq(expected_bytes))
}

/// Returns true if a header is hop-by-hop or belongs to the internal delta protocol.
pub fn is_stripped_request_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    matches!(
        s,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | HDR_AUTH
            | HDR_MODE
            | HDR_BASE
            | HDR_FULL
            | HDR_RAW_LEN
            | HDR_MISS
    )
}

/// Returns true if a response header should not be forwarded verbatim.
pub fn is_stripped_response_header(name: &HeaderName) -> bool {
    let s = name.as_str();
    matches!(
        s,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | HDR_MISS
    )
}

pub fn copy_filtered_headers(
    src: &HeaderMap,
    filter: fn(&HeaderName) -> bool,
) -> HeaderMap {
    let mut dst = HeaderMap::with_capacity(src.len());
    for (k, v) in src.iter() {
        if !filter(k) {
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
