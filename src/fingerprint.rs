use http::HeaderMap;

/// Derive a stable 32-byte conversation fingerprint WITHOUT parsing the full JSON DOM.
///
/// Priority order:
/// 1. Explicit headers (`x-session-id`, `x-conversation-id`) + `Authorization` hash.
/// 2. Explicit JSON session fields (`prompt_cache_key`, `conversation`, `conversation_id`, `session_id`).
/// 3. Structural content anchor: `Authorization` hash + `model` + first `"role":"user"` content window
///    (so parallel sessions sharing the exact same 30 KiB system prompt + tools never collide!).
/// 4. Fallback: `Authorization` hash + `model` + first 4 KiB bytes.
pub fn derive_session_key(headers: &HeaderMap, path: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ctx-delta-session-v1\0");
    hasher.update(path.as_bytes());
    hasher.update(b"\0");

    // Scope sessions per API token / Authorization header to avoid cross-user collision.
    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        let auth_hash = blake3::hash(auth.as_bytes());
        hasher.update(auth_hash.as_bytes());
    } else if let Some(api_key) = headers.get("x-api-key") {
        let key_hash = blake3::hash(api_key.as_bytes());
        hasher.update(key_hash.as_bytes());
    }
    hasher.update(b"\0");

    // 1. Explicit session headers.
    for hdr in ["x-session-id", "x-conversation-id", "x-codex-session-id"] {
        if let Some(val) = headers.get(hdr)
            && !val.is_empty()
        {
            hasher.update(b"hdr:");
            hasher.update(val.as_bytes());
            return *hasher.finalize().as_bytes();
        }
    }

    // Limit scan to first 256 KiB (covers huge system prompts + tool schemas + first user turn).
    let scan_head = &body[..body.len().min(256 * 1024)];
    // Also check tail (last 16 KiB) since some serializers put `prompt_cache_key`/`model` at the end.
    let scan_tail = if body.len() > 256 * 1024 {
        &body[body.len() - 16 * 1024..]
    } else {
        &[]
    };

    // 2. Explicit JSON session keys (e.g. OpenAI Responses `prompt_cache_key`).
    for key in [
        b"\"prompt_cache_key\"".as_slice(),
        b"\"conversation_id\"".as_slice(),
        b"\"session_id\"".as_slice(),
        b"\"conversation\"".as_slice(),
    ] {
        if let Some(val) = find_json_string_value(scan_head, key)
            .or_else(|| find_json_string_value(scan_tail, key))
            && !val.is_empty()
            && val.len() <= 256
        {
            hasher.update(b"json_key:");
            hasher.update(key);
            hasher.update(val);
            return *hasher.finalize().as_bytes();
        }
    }

    // 3. Model + first user message anchor.
    if let Some(model) = find_json_string_value(scan_head, b"\"model\"")
        .or_else(|| find_json_string_value(scan_tail, b"\"model\""))
    {
        hasher.update(b"model:");
        hasher.update(model);
        hasher.update(b"\0");
    }

    if let Some(user_anchor) = find_first_user_anchor(scan_head) {
        hasher.update(b"first_user:");
        hasher.update(user_anchor);
        return *hasher.finalize().as_bytes();
    }

    // 4. Fallback: prefix slice (up to 4 KiB).
    hasher.update(b"prefix:");
    hasher.update(&body[..body.len().min(4096)]);
    *hasher.finalize().as_bytes()
}

/// Find the string value immediately following `"key" : "..."` without building a JSON AST.
fn find_json_string_value<'a>(haystack: &'a [u8], quoted_key: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0usize;
    while let Some(idx) = find_subslice(&haystack[pos..], quoted_key) {
        let mut cur = pos + idx + quoted_key.len();
        cur = skip_ws(haystack, cur);
        if cur < haystack.len() && haystack[cur] == b':' {
            cur = skip_ws(haystack, cur + 1);
            if cur < haystack.len() && haystack[cur] == b'"' {
                let start = cur + 1;
                if let Some(end) = find_json_string_end(haystack, start) {
                    return Some(&haystack[start..end]);
                }
            }
        }
        pos = pos + idx + quoted_key.len();
    }
    None
}

/// Locate the first `"role" : "user"` occurrence and return a stable slice of its content
/// (up to 512 bytes) to distinguish concurrent conversations that share an identical system prompt.
fn find_first_user_anchor(haystack: &[u8]) -> Option<&[u8]> {
    let role_key = b"\"role\"";
    let mut pos = 0usize;
    while let Some(idx) = find_subslice(&haystack[pos..], role_key) {
        let mut cur = pos + idx + role_key.len();
        cur = skip_ws(haystack, cur);
        if cur < haystack.len() && haystack[cur] == b':' {
            cur = skip_ws(haystack, cur + 1);
            if cur < haystack.len() && haystack[cur] == b'"' {
                let val_start = cur + 1;
                if let Some(val_end) = find_json_string_end(haystack, val_start)
                    && &haystack[val_start..val_end] == b"user"
                {
                    // Look ahead within the same message object (next 4 KiB) for `"text"` or `"content"`.
                    let window_end = (val_end + 4096).min(haystack.len());
                    let window = &haystack[val_end..window_end];
                    if let Some(text) = find_json_string_value(window, b"\"text\"")
                        .or_else(|| find_json_string_value(window, b"\"content\""))
                        && !text.is_empty()
                    {
                        return Some(&text[..text.len().min(512)]);
                    }
                    // Fallback to a raw slice right after `"role":"user"`.
                    let fallback_end = (val_end + 512).min(haystack.len());
                    return Some(&haystack[val_end..fallback_end]);
                }
            }
        }
        pos = pos + idx + role_key.len();
    }
    None
}

fn skip_ws(buf: &[u8], mut i: usize) -> usize {
    while i < buf.len() && matches!(buf[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    i
}

fn find_json_string_end(buf: &[u8], mut i: usize) -> Option<usize> {
    while i < buf.len() {
        match buf[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn parallel_sessions_with_same_system_prompt_get_distinct_keys() {
        let sys = "You are an expert coding assistant. ".repeat(500);
        let req_a_turn1 = format!(
            r#"{{"model":"example-model","messages":[{{"role":"system","content":"{sys}"}},{{"role":"user","content":"Fix bug in auth.rs"}}]}}"#
        );
        let req_a_turn2 = format!(
            r#"{{"model":"example-model","messages":[{{"role":"system","content":"{sys}"}},{{"role":"user","content":"Fix bug in auth.rs"}},{{"role":"assistant","content":"Done"}},{{"role":"user","content":"Run tests"}}]}}"#
        );
        let req_b_turn1 = format!(
            r#"{{"model":"example-model","messages":[{{"role":"system","content":"{sys}"}},{{"role":"user","content":"Design NixOS flake"}}]}}"#
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-test-123"),
        );

        let ka1 = derive_session_key(&headers, "/v1/chat/completions", req_a_turn1.as_bytes());
        let ka2 = derive_session_key(&headers, "/v1/chat/completions", req_a_turn2.as_bytes());
        let kb1 = derive_session_key(&headers, "/v1/chat/completions", req_b_turn1.as_bytes());

        assert_eq!(ka1, ka2, "same conversation across turns must map to same key");
        assert_ne!(ka1, kb1, "parallel sessions sharing system prompt must not collide");
    }

    #[test]
    fn prompt_cache_key_takes_precedence() {
        let headers = HeaderMap::new();
        let body1 = br#"{"model":"example-model","prompt_cache_key":"sess-uuid-42","input":[{"role":"user","content":"hi"}]}"#;
        let body2 = br#"{"model":"example-model","input":[{"role":"user","content":"different"}],"prompt_cache_key":"sess-uuid-42"}"#;
        let k1 = derive_session_key(&headers, "/v1/responses", body1);
        let k2 = derive_session_key(&headers, "/v1/responses", body2);
        assert_eq!(k1, k2);
    }
}
