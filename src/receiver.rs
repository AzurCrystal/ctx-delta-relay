use crate::cache::ByteBoundedLru;
use crate::codec::{
    compress_standalone, decompress_cached_snapshot, decompress_delta, decompress_standalone,
    max_wire_body_bytes,
};
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_BASE, HDR_CACHED, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN, MODE_DELTA, MODE_FULL,
    MODE_PASS, copy_filtered_headers, header_str, hex_to_hash, is_stripped_request_header,
    is_stripped_response_header, is_websocket_upgrade, set_header, verify_secret,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use futures_util::TryStreamExt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

const MEM_PERMIT_UNIT: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct ReceiverConfig {
    /// Local upstream base URL, e.g. "http://127.0.0.1:3000"
    pub upstream_url: String,
    /// Optional Host header override when forwarding to a local reverse proxy vhost
    pub upstream_host: Option<String>,
    /// Shared secret required in X-Delta-Auth
    pub secret: String,
    /// Strict RAM ceiling (in bytes) for compressed snapshot LRU (zero disk!)
    pub max_cache_bytes: usize,
    /// Hard memory budget (in bytes) for concurrent in-flight codec/decompression buffers
    pub max_inflight_bytes: usize,
    /// Maximum concurrent blocking zstd codec tasks
    pub max_codec_concurrency: usize,
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
    mem_budget: Arc<Semaphore>,
    codec_sem: Arc<Semaphore>,
    metrics: Arc<RelayMetrics>,
}

impl ReceiverState {
    pub fn new(cfg: ReceiverConfig) -> Result<Arc<Self>, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            // BUG-03: Never auto-follow redirects on upstream calls.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_upstream_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build()?;

        let total_mem_permits = cfg.max_inflight_bytes.div_ceil(MEM_PERMIT_UNIT).max(16);
        let codec_permits = cfg.max_codec_concurrency.max(1);

        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            mem_budget: Arc::new(Semaphore::new(total_mem_permits)),
            codec_sem: Arc::new(Semaphore::new(codec_permits)),
            metrics: Arc::new(RelayMetrics::default()),
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
    // BUG-06: Wire body limit allows zstd framing overhead above max_body_bytes.
    let wire_limit = max_wire_body_bytes(state.cfg.max_body_bytes);
    Router::new()
        .fallback(handle_receive)
        .layer(DefaultBodyLimit::max(wire_limit))
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

fn permits_for_bytes(bytes: usize) -> u32 {
    bytes.div_ceil(MEM_PERMIT_UNIT).max(1).min(u32::MAX as usize) as u32
}

async fn handle_receive(State(state): State<Arc<ReceiverState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;

    // Constant-time auth check — never act as an open proxy.
    if !verify_secret(&headers, &state.cfg.secret) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    // BUG-07: Explicitly reject WebSocket upgrades.
    if is_websocket_upgrade(&headers) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "ctx-delta-relay is an HTTP/SSE relay; connect WebSocket endpoints directly",
        )
            .into_response();
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

    // Estimate memory required for decompression/reconstruction BEFORE reading & allocating.
    let declared_raw_len = header_str(&headers, HDR_RAW_LEN)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    if declared_raw_len > state.cfg.max_body_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "x-delta-raw-len exceeds max-body-mb",
        )
            .into_response();
    }
    let content_len_hint = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MEM_PERMIT_UNIT);
    let estimated_mem = match mode {
        MODE_DELTA => declared_raw_len.saturating_mul(2).max(content_len_hint),
        MODE_FULL => declared_raw_len.saturating_add(content_len_hint),
        _ => content_len_hint,
    };

    // BUG-02: Acquire concurrent memory budget before allocating body/codec buffers.
    let permits = permits_for_bytes(estimated_mem)
        .min(permits_for_bytes(state.cfg.max_inflight_bytes));
    let Ok(Ok(mem_permit)) = tokio::time::timeout(
        Duration::from_secs(10),
        Arc::clone(&state.mem_budget).acquire_many_owned(permits),
    )
    .await
    else {
        state
            .metrics
            .overload_rejects_total
            .fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(http::header::RETRY_AFTER, "1")],
            "receiver in-flight memory budget saturated",
        )
            .into_response();
    };

    let wire_limit = max_wire_body_bytes(state.cfg.max_body_bytes);
    let wire_bytes = match axum::body::to_bytes(body, wire_limit).await {
        Ok(b) => b,
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            return (StatusCode::PAYLOAD_TOO_LARGE, format!("wire body error: {e}"))
                .into_response();
        }
    };

    let wire_len = wire_bytes.len() as u64;

    match mode {
        MODE_PASS => {
            if wire_bytes.len() > state.cfg.max_body_bytes {
                return (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "pass-through body exceeds max-body-mb",
                )
                    .into_response();
            }
            state.metrics.mode_pass_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            drop(mem_permit);
            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                wire_bytes,
                false,
            )
            .await
        }
        MODE_FULL => {
            let Some(full_hash) = header_str(&headers, HDR_FULL).and_then(hex_to_hash) else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-full").into_response();
            };
            let Some(raw_len) =
                header_str(&headers, HDR_RAW_LEN).and_then(|s| s.parse::<usize>().ok())
            else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-raw-len")
                    .into_response();
            };

            let Ok(codec_permit) = Arc::clone(&state.codec_sem).acquire_owned().await else {
                return (StatusCode::SERVICE_UNAVAILABLE, "codec pool closed").into_response();
            };

            let max_body = state.cfg.max_body_bytes;
            // BUG-01: Exact-sized boxed slice stored in Arc<[u8]> — zero wasted spare capacity.
            let wire_arc: Arc<[u8]> = Arc::from(wire_bytes.to_vec().into_boxed_slice());
            let wire_for_cpu = Arc::clone(&wire_arc);

            let decoded = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                let _guard = codec_permit;
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
                .wire_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            // Zero re-compression cost on `full`: store exact-sized compressed wire bytes directly.
            let cached_ok = state.cache.lock().unwrap().insert(full_hash, wire_arc);

            drop(mem_permit);
            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
                cached_ok,
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
            let Some(raw_len) =
                header_str(&headers, HDR_RAW_LEN).and_then(|s| s.parse::<usize>().ok())
            else {
                return (StatusCode::BAD_REQUEST, "missing/invalid x-delta-raw-len")
                    .into_response();
            };

            let base_zstd = match state.cache.lock().unwrap().get(&base_hash) {
                Some(b) => b,
                None => {
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(wire_len, Ordering::Relaxed);
                    state
                        .metrics
                        .miss_retries_total
                        .fetch_add(1, Ordering::Relaxed);
                    debug!("receiver delta base miss -> 409 X-Delta-Miss: 1");
                    return cache_miss_response();
                }
            };

            let Ok(codec_permit) = Arc::clone(&state.codec_sem).acquire_owned().await else {
                return (StatusCode::SERVICE_UNAVAILABLE, "codec pool closed").into_response();
            };

            let max_body = state.cfg.max_body_bytes;
            let cache_level = state.cfg.cache_zstd_level;
            let delta_bytes = wire_bytes;

            let decoded =
                tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Arc<[u8]>), String> {
                    let _guard = codec_permit;
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
                    Ok((raw, Arc::from(new_zstd)))
                })
                .await;

            let (raw, new_zstd) = match decoded {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(wire_len, Ordering::Relaxed);
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
                .wire_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            let cached_ok = state.cache.lock().unwrap().insert(full_hash, new_zstd);

            drop(mem_permit);
            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
                cached_ok,
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
    cached_ok: bool,
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
            let mut resp_headers =
                copy_filtered_headers(resp.headers(), is_stripped_response_header);
            // BUG-08: Explicitly acknowledge whether this snapshot was admitted to receiver's LRU.
            if cached_ok {
                set_header(&mut resp_headers, HDR_CACHED, "1");
            }
            let metrics = Arc::clone(&state.metrics);
            // BUG-13: Track mid-stream SSE/network read errors in metrics & logs.
            let stream = resp.bytes_stream().inspect_err(move |e| {
                metrics.stream_errors_total.fetch_add(1, Ordering::Relaxed);
                metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                warn!(error = %e, "receiver mid-stream upstream response error");
            });
            let mut builder = Response::builder().status(status);
            if let Some(h) = builder.headers_mut() {
                *h = resp_headers;
            }
            builder.body(Body::from_stream(stream)).unwrap_or_else(|e| {
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
