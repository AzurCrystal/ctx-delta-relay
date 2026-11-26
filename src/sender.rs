use crate::cache::{ByteBoundedLru, SessionIndex};
use crate::codec::{compress_delta, compress_standalone, decompress_cached_snapshot};
use crate::fingerprint::derive_session_key;
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_AUTH, HDR_BASE, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN, MODE_DELTA, MODE_FULL,
    MODE_PASS, copy_filtered_headers, hash_to_hex, header_str, is_stripped_request_header,
    is_stripped_response_header, set_header,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct SenderConfig {
    /// Base URL of the remote receiver, e.g. "https://relay.example.com:18443"
    pub receiver_url: String,
    /// Shared secret sent in X-Delta-Auth
    pub secret: String,
    /// Hard memory ceiling (in bytes) for sender-side compressed snapshot LRU
    pub max_cache_bytes: usize,
    /// Session/snapshot TTL (recommended slightly shorter than receiver TTL)
    pub ttl: Duration,
    /// Minimum request body size to compress/delta-encode (smaller bodies pass through)
    pub min_delta_bytes: usize,
    /// Maximum request body size accepted
    pub max_body_bytes: usize,
    /// Zstd compression level (1..=6 recommended; default 3)
    pub zstd_level: i32,
    /// Accept invalid TLS certs on receiver (useful only for self-signed IP-direct testing)
    pub insecure_tls: bool,
    /// Idle read timeout per streamed chunk
    pub read_timeout: Duration,
}

pub struct SenderState {
    cfg: SenderConfig,
    client: reqwest::Client,
    cache: Mutex<ByteBoundedLru>,
    sessions: Mutex<SessionIndex>,
    metrics: RelayMetrics,
}

impl SenderState {
    pub fn new(cfg: SenderConfig) -> Result<Arc<Self>, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build()?;

        let max_sessions = (cfg.max_cache_bytes / (32 * 1024)).clamp(256, 65536);
        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            sessions: Mutex::new(SessionIndex::new(max_sessions, cfg.ttl)),
            metrics: RelayMetrics::default(),
            client,
            cfg,
        }))
    }

    pub fn stats(&self) -> StatsSnapshot {
        let cache = self.cache.lock().unwrap();
        self.metrics.snapshot(
            "sender",
            cache.len(),
            cache.current_bytes(),
            cache.max_bytes(),
            cache.evictions(),
        )
    }

    pub fn purge_expired(&self) -> usize {
        self.cache.lock().unwrap().purge_expired(Instant::now())
    }

    pub fn spawn_sweeper(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let purged = state.purge_expired();
                if purged > 0 {
                    debug!(purged, "sender swept expired snapshots");
                }
            }
        })
    }
}

pub fn router(state: Arc<SenderState>) -> Router {
    let limit = state.cfg.max_body_bytes;
    Router::new()
        .fallback(handle_proxy)
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

pub fn admin_router(state: Arc<SenderState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/stats",
            get(|State(s): State<Arc<SenderState>>| async move { Json(s.stats()) }),
        )
        .with_state(state)
}

fn should_bypass_encoding(method: &Method, headers: &HeaderMap, body_len: usize, cfg: &SenderConfig) -> bool {
    if !matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        return true;
    }
    if body_len < cfg.min_delta_bytes || body_len > cfg.max_body_bytes {
        return true;
    }
    if let Some(ce) = headers.get(http::header::CONTENT_ENCODING)
        && let Ok(s) = ce.to_str()
        && !s.eq_ignore_ascii_case("identity")
        && !s.trim().is_empty()
    {
        return true;
    }
    false
}

async fn handle_proxy(State(state): State<Arc<SenderState>>, req: Request) -> Response {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.cfg.receiver_url.trim_end_matches('/'),
        path_and_query
    );

    let raw_bytes: Bytes = match axum::body::to_bytes(body, state.cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender failed reading client body");
            return (StatusCode::PAYLOAD_TOO_LARGE, format!("body read error: {e}"))
                .into_response();
        }
    };

    let raw_len = raw_bytes.len();
    state
        .metrics
        .raw_bytes_total
        .fetch_add(raw_len as u64, Ordering::Relaxed);

    // 1. Pass-through for small, non-mutating, or already-encoded requests.
    if should_bypass_encoding(&method, &headers, raw_len, &state.cfg) {
        state.metrics.mode_pass_total.fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .wire_bytes_total
            .fetch_add(raw_len as u64, Ordering::Relaxed);
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
        return send_and_stream(&state, method, &target_url, fwd_headers, raw_bytes).await;
    }

    // 2. Compute conversation fingerprint & look up candidate base snapshot.
    let path_only = uri.path().to_string();
    let session_key = derive_session_key(&headers, &path_only, &raw_bytes);
    let candidate_base: Option<([u8; 32], Arc<Vec<u8>>)> = {
        let hashes = state.sessions.lock().unwrap().candidates(&session_key);
        let mut cache = state.cache.lock().unwrap();
        let mut found = None;
        for h in hashes {
            if let Some(compressed) = cache.get(&h) {
                found = Some((h, compressed));
                break;
            }
        }
        found
    };

    // 3. Perform BLAKE3 + zstd compression on blocking pool to keep Tokio I/O workers free.
    let level = state.cfg.zstd_level;
    let max_body = state.cfg.max_body_bytes;
    let raw_for_cpu = raw_bytes.clone();
    let encoded = tokio::task::spawn_blocking(move || -> Result<EncodedPayload, String> {
        let full_hash = *blake3::hash(&raw_for_cpu).as_bytes();
        let full_zstd =
            compress_standalone(&raw_for_cpu, level).map_err(|e| e.to_string())?;

        let mut delta_attempt: Option<([u8; 32], Vec<u8>)> = None;
        if let Some((base_hash, base_zstd)) = candidate_base
            && let Ok(base_raw) = decompress_cached_snapshot(&base_zstd, max_body)
            && let Ok(delta) = compress_delta(&raw_for_cpu, &base_raw, level)
            && delta.len() < full_zstd.len()
        {
            delta_attempt = Some((base_hash, delta));
        }

        Ok(EncodedPayload {
            full_hash,
            full_zstd: Arc::new(full_zstd),
            delta_attempt,
        })
    })
    .await;

    let encoded = match encoded {
        Ok(Ok(e)) => e,
        Ok(Err(e)) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender compression failed, falling back to pass-through");
            state.metrics.mode_pass_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(raw_len as u64, Ordering::Relaxed);
            let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
            set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
            set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
            return send_and_stream(&state, method, &target_url, fwd_headers, raw_bytes).await;
        }
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("worker panic: {e}"))
                .into_response();
        }
    };

    let full_hex = hash_to_hex(&encoded.full_hash);
    let raw_len_str = raw_len.to_string();

    // 4. Send delta if beneficial; automatically retry once in `full` mode on 409 X-Delta-Miss: 1.
    if let Some((base_hash, delta_bytes)) = encoded.delta_attempt {
        let base_hex = hash_to_hex(&base_hash);
        let delta_len = delta_bytes.len();
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_DELTA);
        set_header(&mut fwd_headers, HDR_BASE, &base_hex);
        set_header(&mut fwd_headers, HDR_FULL, &full_hex);
        set_header(&mut fwd_headers, HDR_RAW_LEN, &raw_len_str);

        state
            .metrics
            .wire_bytes_total
            .fetch_add(delta_len as u64, Ordering::Relaxed);

        match state
            .client
            .request(method.clone(), &target_url)
            .headers(fwd_headers)
            .body(delta_bytes)
            .send()
            .await
        {
            Ok(resp)
                if resp.status() == StatusCode::CONFLICT
                    && header_str(resp.headers(), HDR_MISS) == Some("1") =>
            {
                // Transparent self-healing fallback: receiver evicted/restarted/expired base.
                debug!(base = %base_hex, "receiver reported 409 cache miss; retrying in full zstd mode");
                state
                    .metrics
                    .miss_retries_total
                    .fetch_add(1, Ordering::Relaxed);
                {
                    state.cache.lock().unwrap().remove(&base_hash);
                    state
                        .sessions
                        .lock()
                        .unwrap()
                        .invalidate_hash(&session_key, &base_hash);
                }
                // Fall through to full-zstd send below.
            }
            Ok(resp) => {
                state.metrics.mode_delta_total.fetch_add(1, Ordering::Relaxed);
                record_snapshot(&state, session_key, encoded.full_hash, encoded.full_zstd, raw_len);
                return stream_reqwest_response(resp);
            }
            Err(e) => {
                state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                warn!(error = %e, "sender delta request to receiver failed");
                return (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response();
            }
        }
    }

    // 5. Full standalone zstd mode (first turn, expired TTL, non-beneficial delta, or 409 retry).
    let full_wire_len = encoded.full_zstd.len();
    state.metrics.mode_full_total.fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .wire_bytes_total
        .fetch_add(full_wire_len as u64, Ordering::Relaxed);

    let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
    set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
    set_header(&mut fwd_headers, HDR_MODE, MODE_FULL);
    set_header(&mut fwd_headers, HDR_FULL, &full_hex);
    set_header(&mut fwd_headers, HDR_RAW_LEN, &raw_len_str);

    let payload = Bytes::copy_from_slice(&encoded.full_zstd);
    match state
        .client
        .request(method, &target_url)
        .headers(fwd_headers)
        .body(payload)
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status() != StatusCode::FORBIDDEN && resp.status() != StatusCode::BAD_REQUEST {
                record_snapshot(&state, session_key, encoded.full_hash, encoded.full_zstd, raw_len);
            }
            stream_reqwest_response(resp)
        }
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender full request to receiver failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

struct EncodedPayload {
    full_hash: [u8; 32],
    full_zstd: Arc<Vec<u8>>,
    delta_attempt: Option<([u8; 32], Vec<u8>)>,
}

fn record_snapshot(
    state: &SenderState,
    session_key: [u8; 32],
    full_hash: [u8; 32],
    full_zstd: Arc<Vec<u8>>,
    raw_len: usize,
) {
    let inserted = state.cache.lock().unwrap().insert(full_hash, full_zstd);
    if inserted {
        state
            .sessions
            .lock()
            .unwrap()
            .record(session_key, full_hash, raw_len);
    }
}

async fn send_and_stream(
    state: &SenderState,
    method: Method,
    target_url: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match state
        .client
        .request(method, target_url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(resp) => stream_reqwest_response(resp),
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender pass-through request failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

fn stream_reqwest_response(resp: reqwest::Response) -> Response {
    let status = resp.status();
    let resp_headers = copy_filtered_headers(resp.headers(), is_stripped_response_header);
    let stream = resp.bytes_stream();
    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        *h = resp_headers;
    }
    builder
        .body(Body::from_stream(stream))
        .unwrap_or_else(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("response build error: {e}"),
            )
                .into_response()
        })
}
