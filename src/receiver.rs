use crate::cache::ByteBoundedLru;
use crate::codec::{
    compress_standalone, decompress_cached_snapshot, decompress_delta, decompress_standalone,
};
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_BASE, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN, MODE_DELTA, MODE_FULL, MODE_PASS,
    copy_filtered_headers, header_str, hex_to_hash, is_stripped_request_header,
    is_stripped_response_header, set_header, verify_secret,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

#[derive(Clone, Debug)]
pub struct ReceiverConfig {
    /// Local upstream base URL, e.g. "http://127.0.0.1:3000"
    pub upstream_url: String,
    /// Optional Host header override when forwarding to a local vhost reverse proxy
    pub upstream_host: Option<String>,
    /// Shared secret required in X-Delta-Auth
    pub secret: String,
    /// Strict RAM ceiling (in bytes) for compressed snapshot LRU (zero disk!)
    pub max_cache_bytes: usize,
    /// Snapshot idle TTL
    pub ttl: Duration,
    /// Maximum reconstructed raw body size
    pub max_body_bytes: usize,
    /// Zstd compression level used for storing reconstructed snapshots in memory (1 = fastest)
    pub cache_zstd_level: i32,
    /// Accept invalid TLS certs on local upstream if forwarding to loopback HTTPS
    pub insecure_upstream_tls: bool,
    /// Idle read timeout per streamed chunk
    pub read_timeout: Duration,
}

pub struct ReceiverState {
    cfg: ReceiverConfig,
    client: reqwest::Client,
    cache: Mutex<ByteBoundedLru>,
    metrics: RelayMetrics,
}

impl ReceiverState {
    pub fn new(cfg: ReceiverConfig) -> Result<Arc<Self>, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_upstream_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build()?;

        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            metrics: RelayMetrics::default(),
            client,
            cfg,
        }))
    }

    pub fn stats(&self) -> StatsSnapshot {
        let cache = self.cache.lock().unwrap();
        self.metrics.snapshot(
            "receiver",
            cache.len(),
            cache.current_bytes(),
            cache.max_bytes(),
            cache.evictions(),
        )
    }

    /// Clear all cached snapshots (useful for ops or simulating restart in tests).
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
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
                    debug!(purged, "receiver swept expired snapshots");
                }
            }
        })
    }
}

pub fn router(state: Arc<ReceiverState>) -> Router {
    let limit = state.cfg.max_body_bytes;
    Router::new()
        .fallback(handle_receive)
        .layer(DefaultBodyLimit::max(limit))
        .with_state(state)
}

pub fn admin_router(state: Arc<ReceiverState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/stats",
            get(|State(s): State<Arc<ReceiverState>>| async move { Json(s.stats()) }),
        )
        .with_state(state)
}

fn cache_miss_response() -> Response {
    let mut headers = HeaderMap::new();
    set_header(&mut headers, HDR_MISS, "1");
    (StatusCode::CONFLICT, headers, Body::empty()).into_response()
}

async fn handle_receive(State(state): State<Arc<ReceiverState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;

    // Constant-time auth check — never act as an open proxy.
    if !verify_secret(&headers, &state.cfg.secret) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let method = parts.method;
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.cfg.upstream_url.trim_end_matches('/'),
        path_and_query
    );

    let mode = header_str(&headers, HDR_MODE).unwrap_or(MODE_PASS);
    let mut upstream_headers = copy_filtered_headers(&headers, is_stripped_request_header);
    if let Some(ref host_override) = state.cfg.upstream_host
        && let Ok(hv) = HeaderValue::from_str(host_override)
    {
        upstream_headers.insert(http::header::HOST, hv);
    }

    let wire_bytes = match axum::body::to_bytes(body, state.cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            return (StatusCode::PAYLOAD_TOO_LARGE, format!("wire body error: {e}"))
                .into_response();
        }
    };

    state
        .metrics
        .wire_bytes_total
        .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);

    match mode {
        MODE_PASS => {
            state.metrics.mode_pass_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);
            forward_to_upstream(&state, method, &target_url, upstream_headers, wire_bytes).await
        }
        MODE_FULL => {
            let Some(full_hash) = header_str(&headers, HDR_FULL).and_then(hex_to_hash) else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-full").into_response();
            };
            let Some(raw_len) = header_str(&headers, HDR_RAW_LEN)
                .and_then(|s| s.parse::<usize>().ok())
            else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-raw-len")
                    .into_response();
            };

            let max_body = state.cfg.max_body_bytes;
            let wire_vec = wire_bytes.to_vec();
            let wire_arc = Arc::new(wire_vec);
            let wire_for_cpu = Arc::clone(&wire_arc);

            let decoded = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                let raw = decompress_standalone(&wire_for_cpu, raw_len, max_body)
                    .map_err(|e| e.to_string())?;
                let actual_hash = *blake3::hash(&raw).as_bytes();
                if actual_hash != full_hash {
                    return Err("blake3 integrity mismatch on full payload".into());
                }
                Ok(raw)
            })
            .await;

            let raw = match decoded {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    warn!(error = %e, "receiver full decode failed");
                    return (StatusCode::BAD_REQUEST, e).into_response();
                }
                Err(e) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            state.metrics.mode_full_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            // Zero re-compression cost on `full`: store the already-zstd wire bytes directly!
            state.cache.lock().unwrap().insert(full_hash, wire_arc);

            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
            )
            .await
        }
        MODE_DELTA => {
            let Some(base_hash) = header_str(&headers, HDR_BASE).and_then(hex_to_hash) else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-base").into_response();
            };
            let Some(full_hash) = header_str(&headers, HDR_FULL).and_then(hex_to_hash) else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-full").into_response();
            };
            let Some(raw_len) = header_str(&headers, HDR_RAW_LEN)
                .and_then(|s| s.parse::<usize>().ok())
            else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-raw-len")
                    .into_response();
            };

            let base_zstd = match state.cache.lock().unwrap().get(&base_hash) {
                Some(b) => b,
                None => {
                    state
                        .metrics
                        .miss_retries_total
                        .fetch_add(1, Ordering::Relaxed);
                    debug!("receiver delta base miss -> 409 X-Delta-Miss: 1");
                    return cache_miss_response();
                }
            };

            let max_body = state.cfg.max_body_bytes;
            let cache_level = state.cfg.cache_zstd_level;
            let delta_bytes = wire_bytes;

            let decoded =
                tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Arc<Vec<u8>>), String> {
                    let base_raw = decompress_cached_snapshot(&base_zstd, max_body)
                        .map_err(|e| format!("base snapshot corrupt: {e}"))?;
                    let raw = decompress_delta(&delta_bytes, &base_raw, raw_len, max_body)
                        .map_err(|e| format!("delta decode failed: {e}"))?;
                    let actual_hash = *blake3::hash(&raw).as_bytes();
                    if actual_hash != full_hash {
                        return Err("blake3 integrity mismatch after delta reconstruction".into());
                    }
                    let new_zstd = compress_standalone(&raw, cache_level)
                        .map_err(|e| format!("cache recompress failed: {e}"))?;
                    Ok((raw, Arc::new(new_zstd)))
                })
                .await;

            let (raw, new_zstd) = match decoded {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    // Self-heal any delta reconstruction discrepancy by triggering a full resend.
                    state
                        .metrics
                        .miss_retries_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(error = %e, "receiver delta reconstruction failed -> 409 self-heal");
                    state.cache.lock().unwrap().remove(&base_hash);
                    return cache_miss_response();
                }
                Err(e) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            state.metrics.mode_delta_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            state.cache.lock().unwrap().insert(full_hash, new_zstd);

            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
            )
            .await
        }
        other => (
            StatusCode::BAD_REQUEST,
            format!("unsupported x-delta-mode: {other}"),
        )
            .into_response(),
    }
}

async fn forward_to_upstream(
    state: &ReceiverState,
    method: Method,
    target_url: &str,
    headers: HeaderMap,
    raw_body: Bytes,
) -> Response {
    match state
        .client
        .request(method, target_url)
        .headers(headers)
        .body(raw_body)
        .send()
        .await
    {
        Ok(resp) => {
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
                        format!("upstream response build error: {e}"),
                    )
                        .into_response()
                })
        }
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "receiver upstream forward failed");
            (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response()
        }
    }
}
