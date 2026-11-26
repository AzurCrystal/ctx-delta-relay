use crate::budget::{BudgetError, MemoryLease, ResourceBudget, read_body_with_budget};
use crate::cache::ByteBoundedLru;
use crate::codec::{
    cached_snapshot_raw_len, compress_standalone, decompress_cached_snapshot, decompress_delta,
    decompress_standalone, estimate_delta_decompress_mem, estimate_full_decompress_mem,
    max_wire_body_bytes, minimum_inflight_budget_bytes,
};
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_BASE, HDR_CACHED, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN, MODE_DELTA, MODE_FULL,
    MODE_PASS, copy_filtered_headers, derive_tenant_scope, header_str, hex_to_hash,
    is_stripped_request_header, is_stripped_response_header, is_websocket_upgrade,
    scoped_cache_key, set_header, verify_secret,
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
use tracing::{debug, warn};
use url::Url;

#[derive(Clone, Debug)]
pub struct ReceiverConfig {
    /// Local upstream base URL, e.g. "http://127.0.0.1:3000"
    pub upstream_url: String,
    /// Optional Host header override when forwarding to a local reverse proxy vhost
    pub upstream_host: Option<String>,
    /// Shared secret required in X-Delta-Auth (minimum 16 chars)
    pub secret: String,
    /// Strict RAM ceiling (in bytes) for compressed snapshot LRU (zero disk!)
    pub max_cache_bytes: usize,
    /// Hard memory budget (in bytes) for concurrent in-flight body & decompression buffers
    pub max_inflight_bytes: usize,
    /// Maximum concurrent active requests before immediate 503 load shedding
    pub max_concurrent_requests: usize,
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
    /// Maximum time allowed for sender to finish uploading request body
    pub body_read_timeout: Duration,
    /// Idle read timeout per streamed chunk
    pub read_timeout: Duration,
}

impl ReceiverConfig {
    /// Strict startup configuration validation (R2-05 & R2-14).
    pub fn validate(&self) -> Result<(), String> {
        let parsed = Url::parse(&self.upstream_url)
            .map_err(|e| format!("invalid upstream_url '{}': {e}", self.upstream_url))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(format!(
                "upstream_url '{}' must be a valid http:// or https:// URL",
                self.upstream_url
            ));
        }
        if self.secret.len() < 16 {
            return Err("DELTA_SECRET / --secret must be at least 16 characters".into());
        }
        if self.max_body_bytes < 64 * 1024 || self.max_body_bytes > 64 * 1024 * 1024 {
            return Err("max_body_bytes must be between 64 KiB and 64 MiB".into());
        }
        let min_inflight = minimum_inflight_budget_bytes(self.max_body_bytes);
        if self.max_inflight_bytes < min_inflight {
            return Err(format!(
                "max_inflight_bytes ({} MiB) is too small for max_body_bytes ({} MiB); minimum required is {} MiB",
                self.max_inflight_bytes / (1024 * 1024),
                self.max_body_bytes / (1024 * 1024),
                min_inflight.div_ceil(1024 * 1024)
            ));
        }
        if self.max_concurrent_requests == 0 || self.max_codec_concurrency == 0 {
            return Err("max_concurrent_requests and max_codec_concurrency must be >= 1".into());
        }
        if !(1..=19).contains(&self.cache_zstd_level) {
            return Err("cache_zstd_level must be in 1..=19".into());
        }
        if self.ttl.is_zero() || self.body_read_timeout.is_zero() || self.read_timeout.is_zero() {
            return Err("ttl, body_read_timeout, and read_timeout must be > 0".into());
        }
        Ok(())
    }
}

pub struct ReceiverState {
    cfg: ReceiverConfig,
    client: reqwest::Client,
    cache: Mutex<ByteBoundedLru>,
    budget: Arc<ResourceBudget>,
    metrics: Arc<RelayMetrics>,
}

impl ReceiverState {
    pub fn new(cfg: ReceiverConfig) -> Result<Arc<Self>, String> {
        cfg.validate()?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_upstream_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| format!("reqwest client build failed: {e}"))?;

        let budget = Arc::new(ResourceBudget::new(
            cfg.max_concurrent_requests,
            cfg.max_inflight_bytes,
            cfg.max_codec_concurrency,
            Duration::from_secs(10),
        ));

        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            budget,
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

fn budget_error_response(state: &ReceiverState, err: BudgetError) -> Response {
    match err {
        BudgetError::TooManyRequests | BudgetError::Saturated => {
            state
                .metrics
                .overload_rejects_total
                .fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(http::header::RETRY_AFTER, "1")],
                "receiver overloaded",
            )
                .into_response()
        }
        BudgetError::ExceedsTotalBudget { needed, budget } => {
            state
                .metrics
                .overload_rejects_total
                .fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("request working set ({needed} B) exceeds receiver memory budget ({budget} B)"),
            )
                .into_response()
        }
        BudgetError::PayloadTooLarge => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::PAYLOAD_TOO_LARGE, "wire body exceeds limit").into_response()
        }
        BudgetError::BodyReadTimeout => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::REQUEST_TIMEOUT, "wire body read timed out").into_response()
        }
        BudgetError::BodyReadError(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::BAD_REQUEST, format!("wire body error: {e}")).into_response()
        }
    }
}

async fn handle_receive(State(state): State<Arc<ReceiverState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;

    if !verify_secret(&headers, &state.cfg.secret) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    if is_websocket_upgrade(&headers) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "ctx-delta-relay is an HTTP/SSE relay; connect WebSocket endpoints directly",
        )
            .into_response();
    }

    // Global active-request cap (R2-06).
    let _req_slot = match state.budget.try_acquire_request() {
        Ok(slot) => slot,
        Err(e) => return budget_error_response(&state, e),
    };

    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let method = parts.method;
    let uri = parts.uri;
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.cfg.upstream_url.trim_end_matches('/'),
        path_and_query
    );

    let mode = header_str(&headers, HDR_MODE).unwrap_or(MODE_PASS);
    let tenant_scope = derive_tenant_scope(&headers, uri.query());

    let mut upstream_headers = copy_filtered_headers(&headers, is_stripped_request_header);
    if let Some(ref host_override) = state.cfg.upstream_host
        && let Ok(hv) = HeaderValue::from_str(host_override)
    {
        upstream_headers.insert(http::header::HOST, hv);
    }

    let wire_limit = max_wire_body_bytes(state.cfg.max_body_bytes);
    let mut body_lease = state.budget.new_lease();
    let wire_bytes = match read_body_with_budget(
        body,
        wire_limit,
        state.cfg.body_read_timeout,
        &mut body_lease,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return budget_error_response(&state, e),
    };

    let wire_len = wire_bytes.len() as u64;

    match mode {
        MODE_PASS => {
            if wire_bytes.len() > state.cfg.max_body_bytes {
                return budget_error_response(&state, BudgetError::PayloadTooLarge);
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
            // R2-02: body_lease stays alive until upstream send().await completes!
            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                wire_bytes,
                body_lease,
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
            if raw_len > state.cfg.max_body_bytes {
                return budget_error_response(&state, BudgetError::PayloadTooLarge);
            }

            // R2-03 & R2-04 & R2-05: Reserve exact decompression working set and move into blocking task.
            let work_mem = estimate_full_decompress_mem(raw_len, wire_bytes.len());
            let work_lease = match body_lease.acquire_child(work_mem).await {
                Ok(l) => l,
                Err(e) => return budget_error_response(&state, e),
            };
            let codec_slot = match state.budget.acquire_codec().await {
                Ok(s) => s,
                Err(e) => return budget_error_response(&state, e),
            };

            let max_body = state.cfg.max_body_bytes;
            let wire_arc: Arc<[u8]> = Arc::from(wire_bytes.to_vec().into_boxed_slice());
            drop(wire_bytes);
            let wire_for_cpu = Arc::clone(&wire_arc);

            let decoded = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                let _mem_guard = work_lease;
                let _cpu_guard = codec_slot;
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
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(wire_len, Ordering::Relaxed);
                    state
                        .metrics
                        .failed_wire_bytes_total
                        .fetch_add(wire_len, Ordering::Relaxed);
                    warn!(error = %e, "receiver full decode failed");
                    return (StatusCode::BAD_REQUEST, e).into_response();
                }
                Err(e) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            // R2-02: Reserve raw_len on body_lease for the upstream send() lifetime!
            if let Err(e) = body_lease.reserve_at_least(raw.len()).await {
                return budget_error_response(&state, e);
            }

            state.metrics.mode_full_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            // R2-07: Tenant-scoped cache key!
            let scoped_full = scoped_cache_key(&tenant_scope, &full_hash);
            let cached_ok = state.cache.lock().unwrap().insert(scoped_full, wire_arc);

            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
                body_lease,
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
            if raw_len > state.cfg.max_body_bytes {
                return budget_error_response(&state, BudgetError::PayloadTooLarge);
            }

            // R2-07: Tenant-scoped base lookup prevents cross-tenant cache access!
            let scoped_base = scoped_cache_key(&tenant_scope, &base_hash);
            let base_zstd = match state.cache.lock().unwrap().get(&scoped_base) {
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

            let approx_base_len = cached_snapshot_raw_len(&base_zstd).unwrap_or(raw_len);
            let work_mem = estimate_delta_decompress_mem(raw_len, approx_base_len);
            let work_lease = match body_lease.acquire_child(work_mem).await {
                Ok(l) => l,
                Err(e) => return budget_error_response(&state, e),
            };
            let codec_slot = match state.budget.acquire_codec().await {
                Ok(s) => s,
                Err(e) => return budget_error_response(&state, e),
            };

            let max_body = state.cfg.max_body_bytes;
            let cache_level = state.cfg.cache_zstd_level;
            let delta_bytes = wire_bytes;

            let decoded =
                tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Arc<[u8]>), String> {
                    let _mem_guard = work_lease;
                    let _cpu_guard = codec_slot;
                    let base_raw = decompress_cached_snapshot(&base_zstd, max_body)
                        .map_err(|e| format!("base snapshot corrupt: {e}"))?;
                    let raw = decompress_delta(&delta_bytes, &base_raw, raw_len, max_body)
                        .map_err(|e| format!("delta decode failed: {e}"))?;
                    drop(base_raw);
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
                    state.cache.lock().unwrap().remove(&scoped_base);
                    return cache_miss_response();
                }
                Err(e) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            // R2-02: Reserve raw_len on body_lease across upstream send().await!
            if let Err(e) = body_lease.reserve_at_least(raw.len()).await {
                return budget_error_response(&state, e);
            }

            state.metrics.mode_delta_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(wire_len, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw.len() as u64, Ordering::Relaxed);

            let scoped_full = scoped_cache_key(&tenant_scope, &full_hash);
            let cached_ok = state.cache.lock().unwrap().insert(scoped_full, new_zstd);

            forward_to_upstream(
                &state,
                method,
                &target_url,
                upstream_headers,
                Bytes::from(raw),
                body_lease,
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
    body_lease: MemoryLease,
    cached_ok: bool,
) -> Response {
    let result = state
        .client
        .request(method, target_url)
        .headers(headers)
        .body(raw_body)
        .send()
        .await;
    // R2-02: Only release body_lease AFTER send().await completes and raw_body has been dropped!
    drop(body_lease);

    match result {
        Ok(resp) => {
            let status = resp.status();
            let mut resp_headers =
                copy_filtered_headers(resp.headers(), is_stripped_response_header);
            if cached_ok {
                set_header(&mut resp_headers, HDR_CACHED, "1");
            }
            let metrics = Arc::clone(&state.metrics);
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
