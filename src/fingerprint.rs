use crate::protocol::derive_tenant_scope;
use http::HeaderMap;
use serde_json::Value;

/// Maximum raw byte length of the single first `"role": "user"` JSON object parsed semantically.
const MAX_FIRST_USER_OBJECT_BYTES: usize = 128 * 1024;
/// Maximum byte length of decoded short control keys/values (`prompt_cache_key`, `model`, `role`).
const MAX_SHORT_STRING_BYTES: usize = 512;

/// Derive a collision-resistant, tenant-isolated 32-byte conversation fingerprint using a
/// zero-DOM streaming JSON scanner (O(1) memory on multi-MB bodies, RFC 8259 string decoding
/// on short keys/values, and canonical hashing of the first user turn object).
///
/// Priority order:
/// 1. Explicit headers (`x-session-id`, `x-conversation-id`, `x-codex-session-id`).
/// 2. Top-level JSON session keys (`prompt_cache_key`, `conversation_id`, `session_id`, `conversation`).
/// 3. Top-level `model` + canonicalized first `"role": "user"` item in top-level
///    `messages` / `input` / `contents`.
/// 4. Fallback: top-level `model` + first 64 KiB of body.
pub fn derive_session_key(
    headers: &HeaderMap,
    path: &str,
    query: Option<&str>,
    body: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let tenant_scope = derive_tenant_scope(headers, query);
    hash_field(&mut hasher, b"ver", b"ctx-delta-session-v3");
    hash_field(&mut hasher, b"tenant", &tenant_scope);
    hash_field(&mut hasher, b"path", path.as_bytes());

    // 1. Explicit session headers.
    for hdr in ["x-session-id", "x-conversation-id", "x-codex-session-id"] {
        if let Some(val) = headers.get(hdr)
            && !val.is_empty()
        {
            hash_field(&mut hasher, b"hdr_name", hdr.as_bytes());
            hash_field(&mut hasher, b"hdr_val", val.as_bytes());
            return *hasher.finalize().as_bytes();
        }
    }

    // Strip optional UTF-8 BOM before JSON scan (R2-13).
    let json_body = body.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(body);
    let extracted = scan_top_level_json(json_body);

    // 2. Top-level JSON session key.
    if let Some((key_name, val_str)) = extracted.session_id {
        hash_field(&mut hasher, b"json_sess_key", key_name);
        hash_field(&mut hasher, b"json_sess_val", val_str.as_bytes());
        return *hasher.finalize().as_bytes();
    }

    if let Some(model) = extracted.model {
        hash_field(&mut hasher, b"model", model.as_bytes());
    }

    // 3. Canonical hash of the first user turn (immune to key-order/whitespace/unicode-escape drift).
    if let Some(user_span) = extracted.first_user_item {
        if user_span.len() <= MAX_FIRST_USER_OBJECT_BYTES
            && let Ok(val) = serde_json::from_slice::<Value>(user_span)
        {
            hash_canonical_json(&mut hasher, &val);
            return *hasher.finalize().as_bytes();
        }
        hash_field(
            &mut hasher,
            b"first_user_raw",
            &user_span[..user_span.len().min(MAX_FIRST_USER_OBJECT_BYTES)],
        );
        return *hasher.finalize().as_bytes();
    }

    // 4. Fallback for non-JSON or chat-less payloads.
    hash_field(&mut hasher, b"prefix", &body[..body.len().min(64 * 1024)]);
    *hasher.finalize().as_bytes()
}

/// Length-prefixed field hashing prevents canonical concatenation collisions.
fn hash_field(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    hasher.update(&(tag.len() as u32).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

/// Hash a parsed JSON Value canonically (sorted object keys, decoded strings, type tags).
/// Only ever invoked on the single small first-user message object (`<= 128 KiB`).
fn hash_canonical_json(hasher: &mut blake3::Hasher, val: &Value) {
    match val {
        Value::Null => {
            hasher.update(b"N");
        }
        Value::Bool(b) => {
            hasher.update(if *b { b"T" } else { b"F" });
        }
        Value::Number(n) => hash_field(hasher, b"num", n.to_string().as_bytes()),
        Value::String(s) => hash_field(hasher, b"str", s.as_bytes()),
        Value::Array(arr) => {
            hasher.update(b"A");
            hasher.update(&(arr.len() as u64).to_le_bytes());
            for item in arr {
                hash_canonical_json(hasher, item);
            }
        }
        Value::Object(map) => {
            // serde_json::Map uses BTreeMap by default unless preserve_order is enabled,
            // but sort explicitly so canonical order is guaranteed regardless of Cargo features.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            hasher.update(b"O");
            hasher.update(&(keys.len() as u64).to_le_bytes());
            for k in keys {
                hash_field(hasher, b"k", k.as_bytes());
                if let Some(v) = map.get(k) {
                    hash_canonical_json(hasher, v);
                }
            }
        }
    }
}

/// Decode a short JSON string literal (including quotes) per RFC 8259 so `\uXXXX` and escapes
/// match semantically (fixes R2-13).
fn decode_short_json_string(raw_with_quotes: &[u8]) -> Option<String> {
    if raw_with_quotes.len() < 2 || raw_with_quotes.len() > MAX_SHORT_STRING_BYTES + 2 {
        return None;
    }
    if !raw_with_quotes.contains(&b'\\') {
        return std::str::from_utf8(&raw_with_quotes[1..raw_with_quotes.len() - 1])
            .ok()
            .map(str::to_owned);
    }
    serde_json::from_slice::<String>(raw_with_quotes).ok()
}

#[derive(Default)]
struct ExtractedFields<'a> {
    session_id: Option<(&'static [u8], String)>,
    session_priority: u8,
    model: Option<String>,
    first_user_item: Option<&'a [u8]>,
}

struct JsonScanner<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> JsonScanner<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.buf.len()
            && matches!(self.buf[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Consume a JSON string literal starting at `"`, returning the raw slice INCLUDING quotes.
    fn read_string_raw(&mut self) -> Option<&'a [u8]> {
        self.skip_ws();
        if self.peek() != Some(b'"') {
            return None;
        }
        let start = self.pos;
        self.pos += 1;
        while self.pos < self.buf.len() {
            match self.buf[self.pos] {
                b'\\' => {
                    self.pos += 2;
                    if self.pos > self.buf.len() {
                        return None;
                    }
                }
                b'"' => {
                    self.pos += 1;
                    return Some(&self.buf[start..self.pos]);
                }
                // RFC 8259 forbids unescaped control characters (0x00..=0x1F) inside strings.
                0x00..=0x1F => return None,
                _ => self.pos += 1,
            }
        }
        None
    }

    /// Skip any JSON value iteratively without recursion overflow.
    fn skip_value(&mut self) -> Option<()> {
        self.skip_ws();
        let b = self.peek()?;
        match b {
            b'"' => {
                self.read_string_raw()?;
                Some(())
            }
            b'{' | b'[' => {
                let mut depth: usize = 0;
                while self.pos < self.buf.len() {
                    match self.buf[self.pos] {
                        b'"' => {
                            self.read_string_raw()?;
                        }
                        b'{' | b'[' => {
                            depth += 1;
                            self.pos += 1;
                        }
                        b'}' | b']' => {
                            depth = depth.checked_sub(1)?;
                            self.pos += 1;
                            if depth == 0 {
                                return Some(());
                            }
                        }
                        _ => self.pos += 1,
                    }
                }
                None
            }
            b't' => self.consume_literal(b"true"),
            b'f' => self.consume_literal(b"false"),
            b'n' => self.consume_literal(b"null"),
            b'-' | b'0'..=b'9' => {
                let start = self.pos;
                while self.pos < self.buf.len()
                    && matches!(
                        self.buf[self.pos],
                        b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'
                    )
                {
                    self.pos += 1;
                }
                if self.pos > start { Some(()) } else { None }
            }
            _ => None,
        }
    }

    fn consume_literal(&mut self, lit: &[u8]) -> Option<()> {
        if self.buf.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Some(())
        } else {
            None
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Option<()> {
        self.skip_ws();
        if self.peek() == Some(expected) {
            self.pos += 1;
            Some(())
        } else {
            None
        }
    }
}

fn session_key_priority(key: &str) -> Option<(u8, &'static [u8])> {
    match key {
        "prompt_cache_key" => Some((4, b"prompt_cache_key")),
        "conversation_id" => Some((3, b"conversation_id")),
        "session_id" => Some((2, b"session_id")),
        "conversation" => Some((1, b"conversation")),
        _ => None,
    }
}

fn scan_top_level_json<'a>(body: &'a [u8]) -> ExtractedFields<'a> {
    let mut out = ExtractedFields::default();
    let mut sc = JsonScanner::new(body);
    if sc.expect_byte(b'{').is_none() {
        return out;
    }

    loop {
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            break;
        }
        let Some(raw_key) = sc.read_string_raw() else {
            break;
        };
        if sc.expect_byte(b':').is_none() {
            break;
        }
        sc.skip_ws();

        let key_decoded = decode_short_json_string(raw_key);
        let key_str = key_decoded.as_deref().unwrap_or("");

        if let Some((prio, canonical_key)) = session_key_priority(key_str) {
            if sc.peek() == Some(b'"') {
                if let Some(raw_val) = sc.read_string_raw() {
                    if let Some(val) = decode_short_json_string(raw_val)
                        && !val.is_empty()
                        && val.len() <= 256
                        && prio > out.session_priority
                    {
                        out.session_id = Some((canonical_key, val));
                        out.session_priority = prio;
                    }
                } else {
                    break;
                }
            } else if sc.skip_value().is_none() {
                break;
            }
        } else if key_str == "model" {
            if sc.peek() == Some(b'"') {
                if let Some(raw_val) = sc.read_string_raw() {
                    if let Some(val) = decode_short_json_string(raw_val)
                        && !val.is_empty()
                        && val.len() <= 256
                    {
                        out.model = Some(val);
                    }
                } else {
                    break;
                }
            } else if sc.skip_value().is_none() {
                break;
            }
        } else if matches!(key_str, "messages" | "input" | "contents")
            && out.first_user_item.is_none()
        {
            if sc.peek() == Some(b'[') {
                out.first_user_item = scan_messages_array_for_first_user(&mut sc);
            } else if sc.peek() == Some(b'"') {
                if let Some(raw_val) = sc.read_string_raw() {
                    if raw_val.len() > 2 {
                        out.first_user_item = Some(raw_val);
                    }
                } else {
                    break;
                }
            } else if sc.skip_value().is_none() {
                break;
            }
        } else if sc.skip_value().is_none() {
            break;
        }

        sc.skip_ws();
        match sc.peek() {
            Some(b',') => sc.pos += 1,
            Some(b'}') => break,
            _ => break,
        }
    }

    out
}

fn scan_messages_array_for_first_user<'a>(sc: &mut JsonScanner<'a>) -> Option<&'a [u8]> {
    sc.expect_byte(b'[')?;
    let mut found: Option<&'a [u8]> = None;

    loop {
        sc.skip_ws();
        if sc.peek() == Some(b']') {
            sc.pos += 1;
            return found;
        }
        let elem_start = sc.pos;
        if found.is_none() && sc.peek() == Some(b'{') {
            let is_user = scan_object_is_user_role(sc)?;
            let elem_end = sc.pos;
            if is_user {
                found = Some(&sc.buf[elem_start..elem_end]);
            }
        } else {
            sc.skip_value()?;
        }

        sc.skip_ws();
        match sc.peek() {
            Some(b',') => sc.pos += 1,
            Some(b']') => {
                sc.pos += 1;
                return found;
            }
            _ => return found,
        }
    }
}

fn scan_object_is_user_role(sc: &mut JsonScanner<'_>) -> Option<bool> {
    sc.expect_byte(b'{')?;
    let mut is_user = false;
    loop {
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            sc.pos += 1;
            return Some(is_user);
        }
        let raw_key = sc.read_string_raw()?;
        sc.expect_byte(b':')?;
        sc.skip_ws();
        let key_decoded = decode_short_json_string(raw_key);
        if key_decoded.as_deref() == Some("role") && sc.peek() == Some(b'"') {
            let raw_role = sc.read_string_raw()?;
            if decode_short_json_string(raw_role).as_deref() == Some("user") {
                is_user = true;
            }
        } else {
            sc.skip_value()?;
        }
        sc.skip_ws();
        match sc.peek() {
            Some(b',') => sc.pos += 1,
            Some(b'}') => {
                sc.pos += 1;
                return Some(is_user);
            }
            _ => return None,
        }
    }
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

        let ka1 = derive_session_key(&headers, "/v1/chat/completions", None, req_a_turn1.as_bytes());
        let ka2 = derive_session_key(&headers, "/v1/chat/completions", None, req_a_turn2.as_bytes());
        let kb1 = derive_session_key(&headers, "/v1/chat/completions", None, req_b_turn1.as_bytes());

        assert_eq!(ka1, ka2);
        assert_ne!(ka1, kb1);
    }

    #[test]
    fn large_boilerplate_prefix_in_first_user_message_does_not_collide() {
        let env_boilerplate = "<environment_context>workspace=/repo/project; os=linux; rules="
            .to_string()
            + &"keep clean; ".repeat(200)
            + "</environment_context>\n";
        let req_a = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":[{{"type":"input_text","text":"{env_boilerplate}"}},{{"type":"input_text","text":"Task A: refactor cache.rs"}}]}}]}}"#
        );
        let req_b = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":[{{"type":"input_text","text":"{env_boilerplate}"}},{{"type":"input_text","text":"Task B: audit security"}}]}}]}}"#
        );

        let headers = HeaderMap::new();
        let ka = derive_session_key(&headers, "/v1/responses", None, req_a.as_bytes());
        let kb = derive_session_key(&headers, "/v1/responses", None, req_b.as_bytes());
        assert_ne!(ka, kb);
    }

    #[test]
    fn ignores_fake_keys_embedded_inside_system_prompt_string() {
        let req_a = r#"{"model":"example-model","messages":[{"role":"system","content":"Example payload: {\"prompt_cache_key\":\"fake-shared\",\"role\":\"user\",\"content\":\"fake\"}"},{"role":"user","content":"Real question A"}]}"#;
        let req_b = r#"{"model":"example-model","messages":[{"role":"system","content":"Example payload: {\"prompt_cache_key\":\"fake-shared\",\"role\":\"user\",\"content\":\"fake\"}"},{"role":"user","content":"Real question B"}]}"#;

        let headers = HeaderMap::new();
        let ka = derive_session_key(&headers, "/v1/chat/completions", None, req_a.as_bytes());
        let kb = derive_session_key(&headers, "/v1/chat/completions", None, req_b.as_bytes());
        assert_ne!(ka, kb);
    }

    #[test]
    fn handles_unicode_escapes_bom_and_canonical_key_order() {
        // R2-13 regression: UTF-8 BOM + \uXXXX escape in role + reordered keys inside user item!
        let mut body1 = Vec::from([0xEF, 0xBB, 0xBF]);
        body1.extend_from_slice(
            br#"{"model":"example-model","messages":[{"\u0072ole":"\u0075ser","content":"Hello world"}]}"#,
        );
        let body2 =
            br#"{"model":"example-model","messages":[{"content":"Hello world","role":"user"}]}"#;

        let headers = HeaderMap::new();
        let k1 = derive_session_key(&headers, "/v1/chat/completions", None, &body1);
        let k2 = derive_session_key(&headers, "/v1/chat/completions", None, body2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn trailing_top_level_prompt_cache_key_after_large_input_is_extracted() {
        let big_pad = "x".repeat(300_000);
        let body1 = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":"{big_pad}"}}],"prompt_cache_key":"sess-uuid-42"}}"#
        );
        let body2 = r#"{"prompt_cache_key":"sess-uuid-42","model":"example-model","input":[{"role":"user","content":"different"}]}"#;
        let headers = HeaderMap::new();
        let k1 = derive_session_key(&headers, "/v1/responses", None, body1.as_bytes());
        let k2 = derive_session_key(&headers, "/v1/responses", None, body2.as_bytes());
        assert_eq!(k1, k2);
    }
}
