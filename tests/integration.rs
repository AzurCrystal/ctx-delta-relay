use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ctx_delta_relay::{receiver, sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

struct MockUpstreamState {
    received_bodies: Mutex<Vec<Vec<u8>>>,
    received_paths: Mutex<Vec<String>>,
}

async fn spawn_mock_upstream() -> (String, Arc<MockUpstreamState>) {
    let state = Arc::new(MockUpstreamState {
        received_bodies: Mutex::new(Vec::new()),
        received_paths: Mutex::new(Vec::new()),
    });

    let app = Router::new()
        .fallback(
            |State(st): State<Arc<MockUpstreamState>>, req: Request| async move {
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_default();
                let method = req.method().clone();
                let body = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
                    .await
                    .unwrap();

                st.received_paths.lock().unwrap().push(path.clone());
                st.received_bodies.lock().unwrap().push(body.to_vec());

                if path == "/v1/conflict-test" {
                    return (StatusCode::CONFLICT, "upstream real 409").into_response();
                }
                if method == http::Method::GET && path == "/v1/models" {
                    return (
                        StatusCode::OK,
                        [(http::header::CONTENT_TYPE, "application/json")],
                        r#"{"data":[{"id":"example-model"}]}"#,
                    )
                        .into_response();
                }

                // Stream realistic SSE chunks back with BLAKE3 of received body so caller can verify byte-exact match.
                let hash = blake3::hash(&body).to_hex().to_string();
                let len = body.len();
                let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
                tokio::spawn(async move {
                    let _ = tx
                        .send(Ok(Bytes::from(format!(
                            "data: {{\"type\":\"response.created\",\"raw_len\":{len}}}\n\n"
                        ))))
                        .await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    let _ = tx
                        .send(Ok(Bytes::from(format!(
                            "data: {{\"type\":\"response.completed\",\"blake3\":\"{hash}\"}}\n\n"
                        ))))
                        .await;
                    let _ = tx.send(Ok(Bytes::from("data: [DONE]\n\n"))).await;
                });

                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("text/event-stream"),
                );
                headers.insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-cache"),
                );
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "text/event-stream")
                    .header(http::header::CACHE_CONTROL, "no-cache")
                    .body(Body::from_stream(ReceiverStream::new(rx)))
                    .unwrap()
            },
        )
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .with_state(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), state)
}

async fn spawn_pair(
    upstream_url: String,
    receiver_max_cache_bytes: usize,
    ttl: Duration,
) -> (String, String, Arc<sender::SenderState>, Arc<receiver::ReceiverState>) {
    let secret = "super-secret-tunnel-token-2026".to_string();

    let recv_state = receiver::ReceiverState::new(receiver::ReceiverConfig {
        upstream_url,
        upstream_host: None,
        secret: secret.clone(),
        max_cache_bytes: receiver_max_cache_bytes,
        ttl,
        max_body_bytes: 16 * 1024 * 1024,
        cache_zstd_level: 1,
        insecure_upstream_tls: false,
        read_timeout: Duration::from_secs(60),
    })
    .unwrap();

    let recv_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = recv_listener.local_addr().unwrap();
    let recv_app = receiver::router(Arc::clone(&recv_state));
    tokio::spawn(async move {
        let _ = axum::serve(recv_listener, recv_app).await;
    });
    let recv_url = format!("http://{recv_addr}");

    let send_state = sender::SenderState::new(sender::SenderConfig {
        receiver_url: recv_url.clone(),
        secret,
        max_cache_bytes: 64 * 1024 * 1024,
        ttl,
        min_delta_bytes: 4096,
        max_body_bytes: 16 * 1024 * 1024,
        zstd_level: 3,
        insecure_tls: false,
        read_timeout: Duration::from_secs(60),
    })
    .unwrap();

    let send_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let send_addr = send_listener.local_addr().unwrap();
    let send_app = sender::router(Arc::clone(&send_state));
    tokio::spawn(async move {
        let _ = axum::serve(send_listener, send_app).await;
    });

    (format!("http://{send_addr}"), recv_url, send_state, recv_state)
}

fn build_realistic_coding_turn(session_tag: &str, turns: usize, base_blocks: usize) -> Vec<u8> {
    let mut s = String::with_capacity(base_blocks * 1200 + turns * 2048);
    s.push_str(r#"{"model":"example-model","stream":true,"input":["#);
    // Shared large system prompt + tool definitions (~30 KiB)
    s.push_str(r#"{"role":"system","content":"You are an autonomous systems engineer. Follow strict Rust and NixOS conventions. "#);
    for i in 0..300 {
        s.push_str(&format!("Rule {i}: keep modules explicit, verify checksums, preserve SSE streaming; "));
    }
    s.push_str(r#""},"#);
    // Unique first user message per session (distinct anchor!)
    s.push_str(&format!(
        r#"{{"role":"user","content":"Session {session_tag}: migrate production k3s workloads to NixOS on GCP and analyze codebase."}}"#
    ));
    // Initial large codebase context (~500 KiB of distinct code lines to mimic 150K+ tokens)
    for b in 0..base_blocks {
        s.push_str(&format!(
            r#", {{"role":"tool","content":"// file_{b:04}.rs\npub fn compute_state_{b}(input: &[u8], seed: u64) -> u64 {{ let mut acc = seed ^ {m}; for (idx, &v) in input.iter().enumerate() {{ acc = acc.wrapping_mul(6364136223846793005).wrapping_add((v as u64) ^ (idx as u64) ^ {b}); }} acc }}"}}"#,
            m = (b as u64).wrapping_mul(0x9e3779b97f4a7c15)
        ));
    }
    // Incremental multi-turn agent loop
    for t in 1..=turns {
        s.push_str(&format!(
            r#", {{"role":"assistant","content":"Turn {t}: inspecting module {t} and proposing patch #{t} with hash {h:x}."}}, {{"role":"user","content":"Turn {t} tool_result: cargo test passed 42/42 cases in {ms}ms; proceed to step {next}."}}"#,
            h = (t as u64).wrapping_mul(0xdeadbeef1234567),
            ms = 120 + t * 7,
            next = t + 1
        ));
    }
    s.push_str("]}");
    s.into_bytes()
}

#[tokio::test]
async fn multi_turn_llm_session_achieves_high_delta_savings_and_recovers_on_restart() {
    let (upstream_url, upstream_state) = spawn_mock_upstream().await;
    let (sender_url, _recv_url, send_state, recv_state) =
        spawn_pair(upstream_url, 64 * 1024 * 1024, Duration::from_secs(600)).await;
    let client = reqwest::Client::new();

    let total_turns = 20usize;
    for turn in 1..=total_turns {
        // Simulate receiver restart / full cache wipe right before turn 12!
        if turn == 12 {
            recv_state.clear_cache();
        }

        let payload = build_realistic_coding_turn("session-alpha", turn, 1200);
        let expected_hash = blake3::hash(&payload).to_hex().to_string();

        let resp = client
            .post(format!("{sender_url}/v1/responses"))
            .header("Authorization", "Bearer sk-example-token")
            .header("Content-Type", "application/json")
            .body(payload.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "turn {turn} must return 200 OK");
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
        let text = resp.text().await.unwrap();
        assert!(
            text.contains(&expected_hash),
            "upstream must receive byte-for-byte identical body on turn {turn}"
        );
        assert!(text.contains("[DONE]"));
    }

    let s_stats = send_state.stats();
    let r_stats = recv_state.stats();

    println!(
        "\n=== 20-Turn ~360KB/turn Benchmark ===\nSender:   raw={} KiB, wire={} KiB, saved={:.2}%, delta={}, full={}, retries={}\nReceiver: lru_entries={}, lru_bytes={} KiB / {} KiB",
        s_stats.raw_bytes_total / 1024,
        s_stats.wire_bytes_total / 1024,
        s_stats.savings_percent,
        s_stats.mode_delta_total,
        s_stats.mode_full_total,
        s_stats.miss_retries_total,
        r_stats.lru_entries,
        r_stats.lru_bytes / 1024,
        r_stats.lru_max_bytes / 1024,
    );

    assert_eq!(upstream_state.received_bodies.lock().unwrap().len(), total_turns);
    assert_eq!(s_stats.miss_retries_total, 1, "turn 12 restart must trigger exactly 1 automatic 409 retry");
    assert_eq!(s_stats.mode_full_total, 2, "turn 1 initial + turn 12 recovery full");
    assert_eq!(s_stats.mode_delta_total, (total_turns - 2) as u64);
    assert!(
        s_stats.savings_percent > 96.0,
        "expected >96% wire bandwidth reduction, got {:.2}%",
        s_stats.savings_percent
    );
}

#[tokio::test]
async fn parallel_sessions_same_system_prompt_do_not_collide() {
    let (upstream_url, _upstream_state) = spawn_mock_upstream().await;
    let (sender_url, _recv_url, send_state, _recv_state) =
        spawn_pair(upstream_url, 64 * 1024 * 1024, Duration::from_secs(600)).await;
    let client = reqwest::Client::new();

    // Interleave 3 parallel sessions sharing the exact same 30 KiB system prompt & Bearer token.
    for turn in 1..=6 {
        for sess in ["sess-A", "sess-B", "sess-C"] {
            let payload = build_realistic_coding_turn(sess, turn, 600);
            let expected_hash = blake3::hash(&payload).to_hex().to_string();
            let resp = client
                .post(format!("{sender_url}/v1/responses"))
                .header("Authorization", "Bearer sk-same-token")
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let text = resp.text().await.unwrap();
            assert!(text.contains(&expected_hash));
        }
    }

    let stats = send_state.stats();
    println!(
        "\n=== 3 Interleaved Parallel Sessions ===\nraw={} KiB, wire={} KiB, saved={:.2}%, delta={}, full={}",
        stats.raw_bytes_total / 1024,
        stats.wire_bytes_total / 1024,
        stats.savings_percent,
        stats.mode_delta_total,
        stats.mode_full_total,
    );
    assert_eq!(stats.mode_full_total, 3, "1 initial full per parallel session");
    assert_eq!(stats.mode_delta_total, 15, "all subsequent 15 interleaved turns hit delta");
    assert!(stats.savings_percent > 94.0);
}

#[tokio::test]
async fn strict_memory_cap_evicts_and_recovers_gracefully() {
    let (upstream_url, _upstream_state) = spawn_mock_upstream().await;
    // Tiny 120 KiB hard RAM cap on receiver!
    let cap = 120 * 1024;
    let (sender_url, _recv_url, send_state, recv_state) =
        spawn_pair(upstream_url, cap, Duration::from_secs(600)).await;
    let client = reqwest::Client::new();

    // Create 8 distinct sessions so receiver MUST evict older ones to stay <= 120 KiB.
    for i in 0..8 {
        let payload = build_realistic_coding_turn(&format!("cap-sess-{i}"), 1, 800);
        let expected_hash = blake3::hash(&payload).to_hex().to_string();
        let resp = client
            .post(format!("{sender_url}/v1/responses"))
            .body(payload)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.text().await.unwrap().contains(&expected_hash));
        assert!(
            recv_state.stats().lru_bytes <= cap,
            "receiver LRU exceeded hard cap!"
        );
    }

    assert!(recv_state.stats().lru_evictions_total > 0);

    // Now send turn 2 of the evicted oldest session (cap-sess-0): must recover seamlessly via 409!
    let turn2 = build_realistic_coding_turn("cap-sess-0", 2, 800);
    let expected_hash = blake3::hash(&turn2).to_hex().to_string();
    let resp = client
        .post(format!("{sender_url}/v1/responses"))
        .body(turn2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains(&expected_hash));
    assert!(send_state.stats().miss_retries_total >= 1);
    assert!(recv_state.stats().lru_bytes <= cap);
}

#[tokio::test]
async fn auth_passthrough_and_real_upstream_409_work_correctly() {
    let (upstream_url, _upstream_state) = spawn_mock_upstream().await;
    let (sender_url, recv_url, _send_state, _recv_state) =
        spawn_pair(upstream_url, 16 * 1024 * 1024, Duration::from_secs(600)).await;
    let client = reqwest::Client::new();

    // 1. Direct unauthorized call to receiver must be rejected with 403.
    let unauth = client
        .get(format!("{recv_url}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::FORBIDDEN);

    // 2. GET /v1/models through sender passes cleanly.
    let models = client
        .get(format!("{sender_url}/v1/models"))
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), StatusCode::OK);
    assert!(models.text().await.unwrap().contains("example-model"));

    // 3. A real 409 from upstream must NOT be misclassified as a delta miss!
    let big_body = "x".repeat(8192);
    let conflict = client
        .post(format!("{sender_url}/v1/conflict-test"))
        .body(big_body)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(conflict.text().await.unwrap(), "upstream real 409");
}
