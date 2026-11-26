use http::HeaderMap;

/// Maximum byte slice hashed from the first `"role": "user"` message object.
/// Hashing the full first user object (up to 128 KiB) prevents deterministic collisions when
/// coding agents prepend multi-kilobyte `<environment_context>` boilerplate before the user's task.
const MAX_FIRST_USER_SPAN: usize = 128 * 1024;

/// Derive a collision-resistant 32-byte conversation fingerprint using a zero-DOM
/// streaming JSON scanner (O(1) heap memory, strictly respects JSON strings & nesting).
///
/// Priority order:
/// 1. Explicit headers (`x-session-id`, `x-conversation-id`, `x-codex-session-id`).
/// 2. Top-level JSON session keys (`prompt_cache_key`, `conversation_id`, `session_id`, `conversation`).
/// 3. Top-level `model` + full byte span of the first `"role": "user"` item in top-level
///    `messages` / `input` / `contents`.
/// 4. Fallback: top-level `model` + first 64 KiB of body.
pub fn derive_session_key(headers: &HeaderMap, path: &str, body: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, b"ver", b"ctx-delta-session-v2");
    hash_field(&mut hasher, b"path", path.as_bytes());

    // Scope sessions per credential to isolate different callers cleanly.
    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        let auth_hash = blake3::hash(auth.as_bytes());
        hash_field(&mut hasher, b"auth", auth_hash.as_bytes());
    } else if let Some(api_key) = headers.get("x-api-key") {
        let key_hash = blake3::hash(api_key.as_bytes());
        hash_field(&mut hasher, b"apikey", key_hash.as_bytes());
    } else {
        hash_field(&mut hasher, b"auth", b"");
    }

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

    // 2. Single-pass zero-DOM JSON scan over top-level object.
    let extracted = scan_top_level_json(body);

    if let Some((key_name, val_bytes)) = extracted.session_id {
        hash_field(&mut hasher, b"json_sess_key", key_name);
        hash_field(&mut hasher, b"json_sess_val", val_bytes);
        return *hasher.finalize().as_bytes();
    }

    if let Some(model) = extracted.model {
        hash_field(&mut hasher, b"model", model);
    }

    if let Some(user_span) = extracted.first_user_item {
        hash_field(
            &mut hasher,
            b"first_user_item",
            &user_span[..user_span.len().min(MAX_FIRST_USER_SPAN)],
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

#[derive(Default)]
struct ExtractedFields<'a> {
    session_id: Option<(&'static [u8], &'a [u8])>,
    session_priority: u8,
    model: Option<&'a [u8]>,
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

    /// Consume a JSON string literal starting at `"`, returning the raw unescaped slice inside quotes.
    fn read_string(&mut self) -> Option<&'a [u8]> {
        self.skip_ws();
        if self.peek() != Some(b'"') {
            return None;
        }
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.buf.len() {
            match self.buf[self.pos] {
                b'\\' => {
                    self.pos += 2;
                    if self.pos > self.buf.len() {
                        return None;
                    }
                }
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Some(&self.buf[start..end]);
                }
                _ => self.pos += 1,
            }
        }
        None
    }

    /// Skip any JSON value (object, array, string, number, bool, null) iteratively without recursion overflow.
    fn skip_value(&mut self) -> Option<()> {
        self.skip_ws();
        let b = self.peek()?;
        match b {
            b'"' => {
                self.read_string()?;
                Some(())
            }
            b'{' | b'[' => {
                let mut depth: usize = 0;
                while self.pos < self.buf.len() {
                    match self.buf[self.pos] {
                        b'"' => {
                            self.read_string()?;
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
            _ => {
                // Number, true, false, null
                let start = self.pos;
                while self.pos < self.buf.len()
                    && !matches!(
                        self.buf[self.pos],
                        b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n'
                    )
                {
                    self.pos += 1;
                }
                if self.pos > start { Some(()) } else { None }
            }
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

fn session_key_priority(key: &[u8]) -> Option<(u8, &'static [u8])> {
    match key {
        b"prompt_cache_key" => Some((4, b"prompt_cache_key")),
        b"conversation_id" => Some((3, b"conversation_id")),
        b"session_id" => Some((2, b"session_id")),
        b"conversation" => Some((1, b"conversation")),
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
        let Some(key) = sc.read_string() else {
            break;
        };
        if sc.expect_byte(b':').is_none() {
            break;
        }
        sc.skip_ws();

        if let Some((prio, canonical_key)) = session_key_priority(key) {
            if sc.peek() == Some(b'"') {
                if let Some(val) = sc.read_string() {
                    if !val.is_empty() && val.len() <= 256 && prio > out.session_priority {
                        out.session_id = Some((canonical_key, val));
                        out.session_priority = prio;
                    }
                } else {
                    break;
                }
            } else if sc.skip_value().is_none() {
                break;
            }
        } else if key == b"model" {
            if sc.peek() == Some(b'"') {
                if let Some(val) = sc.read_string() {
                    if !val.is_empty() && val.len() <= 256 {
                        out.model = Some(val);
                    }
                } else {
                    break;
                }
            } else if sc.skip_value().is_none() {
                break;
            }
        } else if matches!(key, b"messages" | b"input" | b"contents") && out.first_user_item.is_none()
        {
            if sc.peek() == Some(b'[') {
                out.first_user_item = scan_messages_array_for_first_user(&mut sc);
            } else if sc.peek() == Some(b'"') {
                // OpenAI Responses API allows `"input": "plain string"`
                if let Some(val) = sc.read_string() {
                    if !val.is_empty() {
                        out.first_user_item = Some(val);
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

/// Scans a top-level `messages` / `input` / `contents` JSON array, finds the first element
/// object whose own `"role"` field equals `"user"`, returns its full raw JSON byte span,
/// and advances the scanner cleanly past the end of the array so trailing top-level keys
/// (such as `"model"` or `"prompt_cache_key"`) are still visited.
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

/// Inspects an object at the current scanner position, advances cleanly past its closing `}`,
/// and returns true iff it has a direct field `"role": "user"`.
fn scan_object_is_user_role(sc: &mut JsonScanner<'_>) -> Option<bool> {
    sc.expect_byte(b'{')?;
    let mut is_user = false;
    loop {
        sc.skip_ws();
        if sc.peek() == Some(b'}') {
            sc.pos += 1;
            return Some(is_user);
        }
        let key = sc.read_string()?;
        sc.expect_byte(b':')?;
        sc.skip_ws();
        if key == b"role" && sc.peek() == Some(b'"') {
            let role_val = sc.read_string()?;
            if role_val == b"user" {
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

        let ka1 = derive_session_key(&headers, "/v1/chat/completions", req_a_turn1.as_bytes());
        let ka2 = derive_session_key(&headers, "/v1/chat/completions", req_a_turn2.as_bytes());
        let kb1 = derive_session_key(&headers, "/v1/chat/completions", req_b_turn1.as_bytes());

        assert_eq!(ka1, ka2, "same conversation across turns must map to same key");
        assert_ne!(ka1, kb1, "parallel sessions sharing system prompt must not collide");
    }

    #[test]
    fn large_boilerplate_prefix_in_first_user_message_does_not_collide() {
        // BUG-04 regression: >2 KiB identical <environment_context> prefix inside first user turn!
        let env_boilerplate = "<environment_context>workspace=/repo/project; os=linux; rules=".to_string()
            + &"keep clean; ".repeat(200)
            + "</environment_context>\n";
        let req_a = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":[{{"type":"input_text","text":"{env_boilerplate}"}},{{"type":"input_text","text":"Task A: refactor cache.rs"}}]}}]}}"#
        );
        let req_b = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":[{{"type":"input_text","text":"{env_boilerplate}"}},{{"type":"input_text","text":"Task B: audit security"}}]}}]}}"#
        );

        let headers = HeaderMap::new();
        let ka = derive_session_key(&headers, "/v1/responses", req_a.as_bytes());
        let kb = derive_session_key(&headers, "/v1/responses", req_b.as_bytes());
        assert_ne!(ka, kb, "sessions with identical 2 KiB boilerplate prefix must not collide");
    }

    #[test]
    fn ignores_fake_keys_embedded_inside_system_prompt_string() {
        // BUG-05 regression: escaped `"prompt_cache_key"` and `"role":"user"` inside system prompt text
        // MUST NOT fool the JSON scanner!
        let req_a = r#"{"model":"example-model","messages":[{"role":"system","content":"Example payload: {\"prompt_cache_key\":\"fake-shared\",\"role\":\"user\",\"content\":\"fake\"}"},{"role":"user","content":"Real question A"}]}"#;
        let req_b = r#"{"model":"example-model","messages":[{"role":"system","content":"Example payload: {\"prompt_cache_key\":\"fake-shared\",\"role\":\"user\",\"content\":\"fake\"}"},{"role":"user","content":"Real question B"}]}"#;

        let headers = HeaderMap::new();
        let ka = derive_session_key(&headers, "/v1/chat/completions", req_a.as_bytes());
        let kb = derive_session_key(&headers, "/v1/chat/completions", req_b.as_bytes());
        assert_ne!(ka, kb, "escaped JSON inside system prompt string must be ignored");
    }

    #[test]
    fn trailing_top_level_prompt_cache_key_after_large_input_is_extracted() {
        let big_pad = "x".repeat(300_000);
        let body1 = format!(
            r#"{{"model":"example-model","input":[{{"role":"user","content":"{big_pad}"}}],"prompt_cache_key":"sess-uuid-42"}}"#
        );
        let body2 = r#"{"prompt_cache_key":"sess-uuid-42","model":"example-model","input":[{"role":"user","content":"different"}]}"#;
        let headers = HeaderMap::new();
        let k1 = derive_session_key(&headers, "/v1/responses", body1.as_bytes());
        let k2 = derive_session_key(&headers, "/v1/responses", body2.as_bytes());
        assert_eq!(k1, k2);
    }
}
