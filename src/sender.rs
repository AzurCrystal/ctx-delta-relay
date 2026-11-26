use crate::budget::{BudgetError, MemoryLease, ResourceBudget, read_body_with_budget};
use crate::cache::{ByteBoundedLru, SessionIndex};
use crate::codec::{
    cached_snapshot_raw_len, compress_delta, compress_standalone, decompress_cached_snapshot,
    estimate_delta_compress_mem, estimate_standalone_compress_mem, minimum_inflight_budget_bytes,
};
use crate::fingerprint::derive_session_key;
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_AUTH, HDR_BASE, HDR_CACHED, HDR_CLIENT_AUTH, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN,
    MODE_DELTA, MODE_FULL, MODE_PASS, copy_filtered_headers, derive_tenant_scope, hash_to_hex,
    header_str, is_stripped_request_header, is_stripped_response_header, is_websocket_upgrade,
    scoped_cache_key, set_header, verify_header_secret,
};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use futures_util::TryStreamExt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use url::Url;

/// Fast zstd level used purely for storing local cached snapshots in the background after a delta hit.
const LOCAL_CACHE_ZSTD_LEVEL: i32 = 1;

#[derive(Clone, Debug)]
pub struct SenderConfig {
    /// Base URL of the remote receiver, e.g. "https://relay.example.com:18443"
    pub receiver_url: String,
    /// Shared secret sent in X-Delta-Auth (minimum 16 chars)
    pub secret: String,
    /// Optional client access secret required in X-Delta-Client-Auth (minimum 16 chars if set)
    pub client_auth: Option<String>,
    /// Hard memory ceiling (in bytes) for sender-side compressed snapshot LRU
    pub max_cache_bytes: usize,
    /// Hard memory budget (in bytes) for concurrent in-flight body & codec working sets
    pub max_inflight_bytes: usize,
    /// Maximum concurrent active requests before immediate 503 load shedding
    pub max_concurrent_requests: usize,
    /// Maximum concurrent blocking zstd codec tasks
    pub max_codec_concurrency: usize,
    /// Session/snapshot TTL (recommended slightly shorter than receiver TTL)
    pub ttl: Duration,
    /// Minimum request body size to compress/delta-encode (smaller bodies pass through)
    pub min_delta_bytes: usize,
    /// Maximum request body size accepted
    pub max_body_bytes: usize,
    /// Zstd compression level (1..=19; 1..=6 recommended)
    pub zstd_level: i32,
    /// Accept invalid TLS certs on receiver (testing only)
    pub insecure_tls: bool,
    /// Maximum time allowed for client to finish uploading the request body
    pub body_read_timeout: Duration,
    /// Idle read timeout per streamed response chunk
    pub read_timeout: Duration,
}

impl SenderConfig {
    /// Strict startup configuration validation (R2-05 & R2-14).
    pub fn validate(&self) -> Result<(), String> {
        let parsed = Url::parse(&self.receiver_url)
            .map_err(|e| format!("invalid receiver_url '{}': {e}", self.receiver_url))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(format!(
                "receiver_url '{}' must be a valid http:// or https:// URL",
                self.receiver_url
            ));
        }
        if self.secret.len() < 16 {
            return Err("DELTA_SECRET / --secret must be at least 16 characters".into());
        }
        if let Some(ref ca) = self.client_auth
            && ca.len() < 16
        {
            return Err("DELTA_CLIENT_AUTH / --client-auth must be at least 16 characters".into());
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
        if !(1..=19).contains(&self.zstd_level) {
            return Err("zstd_level must be in 1..=19".into());
        }
        if self.ttl.is_zero() || self.body_read_timeout.is_zero() || self.read_timeout.is_zero() {
            return Err("ttl, body_read_timeout, and read_timeout must be > 0".into());
        }
        Ok(())
    }

    pub fn is_plaintext_non_loopback_receiver(&self) -> bool {
        let Ok(parsed) = Url::parse(&self.receiver_url) else {
            return false;
        };
        if parsed.scheme() != "http" {
            return false;
        }
        !matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1" | "[::1]")
        )
    }
}

pub struct SenderState {
    cfg: SenderConfig,
    client: reqwest::Client,
    cache: Mutex<ByteBoundedLru>,
    sessions: Mutex<SessionIndex>,
    budget: Arc<ResourceBudget>,
    metrics: Arc<RelayMetrics>,
}

impl SenderState {
    pub fn new(cfg: SenderConfig) -> Result<Arc<Self>, String> {
        cfg.validate()?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| format!("reqwest client build failed: {e}"))?;

        let max_sessions = (cfg.max_cache_bytes / (32 * 1024)).clamp(256, 65536);
        let budget = Arc::new(ResourceBudget::new(
            cfg.max_concurrent_requests,
            cfg.max_inflight_bytes,
            cfg.max_codec_concurrency,
            Duration::from_secs(10),
        ));

        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            sessions: Mutex::new(SessionIndex::new(max_sessions, cfg.ttl)),
            budget,
            metrics: Arc::new(RelayMetrics::default()),
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
        let now = Instant::now();
        let purged = self.cache.lock().unwrap().purge_expired(now);
        self.sessions.lock().unwrap().purge_expired(now);
        purged
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

fn should_bypass_encoding(
    method: &Method,
    headers: &HeaderMap,
    body_len: usize,
    cfg: &SenderConfig,
) -> bool {
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

fn budget_error_response(state: &SenderState, err: BudgetError) -> Response {
    match err {
        BudgetError::TooManyRequests | BudgetError::Saturated => {
            state
                .metrics
                .overload_rejects_total
                .fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(http::header::RETRY_AFTER, "1")],
                "sender overloaded",
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
                format!("request working set ({needed} B) exceeds sender memory budget ({budget} B)"),
            )
                .into_response()
        }
        BudgetError::PayloadTooLarge => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::PAYLOAD_TOO_LARGE, "request exceeds max-body-mb").into_response()
        }
        BudgetError::BodyReadTimeout => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::REQUEST_TIMEOUT, "request body read timed out").into_response()
        }
        BudgetError::BodyReadError(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            (StatusCode::BAD_REQUEST, format!("body read error: {e}")).into_response()
        }
    }
}

async fn handle_proxy(State(state): State<Arc<SenderState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    // Optional sender-side client access control.
    if let Some(ref client_secret) = state.cfg.client_auth
        && !verify_header_secret(&headers, HDR_CLIENT_AUTH, client_secret)
    {
        return (StatusCode::FORBIDDEN, "sender client auth required").into_response();
    }

    // Explicitly reject WebSocket upgrades.
    if is_websocket_upgrade(&headers) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "ctx-delta-relay is an HTTP/SSE relay; connect WebSocket endpoints directly",
        )
            .into_response();
    }

    // Global active-request queue guard (R2-06).
    let _req_slot = match state.budget.try_acquire_request() {
        Ok(slot) => slot,
        Err(e) => return budget_error_response(&state, e),
    };

    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.cfg.receiver_url.trim_end_matches('/'),
        path_and_query
    );

    if let Some(cl) = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && cl > state.cfg.max_body_bytes
    {
        return budget_error_response(&state, BudgetError::PayloadTooLarge);
    }

    // R2-01 & R2-06: Stream-read body while reserving memory permits incrementally BEFORE allocation!
    let mut body_lease = state.budget.new_lease();
    let raw_bytes = match read_body_with_budget(
        body,
        state.cfg.max_body_bytes,
        state.cfg.body_read_timeout,
        &mut body_lease,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return budget_error_response(&state, e),
    };

    let raw_len = raw_bytes.len();

    // 1. Pass-through for small, non-mutating, or already-encoded requests.
    if should_bypass_encoding(&method, &headers, raw_len, &state.cfg) {
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
        // R2-02: body_lease stays alive until send().await finishes!
        return send_pass_and_stream(&state, method, &target_url, fwd_headers, raw_bytes, body_lease, 0)
            .await;
    }

    // 2. Tenant-isolated cache lookup & ranked candidate selection (R2-07 & BUG-10).
    let full_hash = *blake3::hash(&raw_bytes).as_bytes();
    let tenant_scope = derive_tenant_scope(&headers, uri.query());
    let path_only = uri.path().to_string();
    let session_key = derive_session_key(&headers, &path_only, uri.query(), &raw_bytes);

    let candidate_base: Option<([u8; 32], Arc<[u8]>)> = {
        let hashes =
            state
                .sessions
                .lock()
                .unwrap()
                .ranked_candidates(&session_key, &full_hash, raw_len);
        let mut cache = state.cache.lock().unwrap();
        let mut found = None;
        for content_hash in hashes {
            let cache_key = scoped_cache_key(&tenant_scope, &content_hash);
            if let Some(compressed) = cache.get(&cache_key) {
                found = Some((content_hash, compressed));
                break;
            }
        }
        found
    };

    let full_hex = hash_to_hex(&full_hash);
    let raw_len_str = raw_len.to_string();
    let level = state.cfg.zstd_level;
    let max_body = state.cfg.max_body_bytes;

    let mut cached_full_zstd: Option<Arc<[u8]>> = None;
    let mut prior_wire_bytes: u64 = 0;

    // 3. Delta hot path: reserve accurate Zstd LDM working set inside child lease moved into
    // spawn_blocking (R2-03 & R2-04).
    if let Some((base_hash, base_zstd)) = candidate_base {
        let approx_base_len = cached_snapshot_raw_len(&base_zstd).unwrap_or(raw_len);
        let delta_work_mem = estimate_delta_compress_mem(raw_len, approx_base_len);

        let delta_attempt = match body_lease.acquire_child(delta_work_mem).await {
            Ok(codec_lease) => match state.budget.acquire_codec().await {
                Ok(codec_slot) => {
                    let raw_for_cpu = raw_bytes.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        // R2-04: Both codec_lease and codec_slot live until blocking thread exits!
                        let _mem_guard = codec_lease;
                        let _cpu_guard = codec_slot;
                        let base_raw = decompress_cached_snapshot(&base_zstd, max_body)
                            .map_err(|e| e.to_string())?;
                        compress_delta(&raw_for_cpu, &base_raw, level).map_err(|e| e.to_string())
                    })
                    .await;
                    match res {
                        Ok(Ok(d)) => Some(d),
                        Ok(Err(e)) => {
                            warn!(error = %e, "sender delta encode failed, falling back to full mode");
                            None
                        }
                        Err(e) => {
                            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                            return (StatusCode::INTERNAL_SERVER_ERROR, format!("worker panic: {e}"))
                                .into_response();
                        }
                    }
                }
                Err(e) => return budget_error_response(&state, e),
            },
            Err(e) => return budget_error_response(&state, e),
        };

        // R2-08: Fast-accept delta ONLY when <= 5% of raw_len (or <= 2 KiB), which is guaranteed
        // smaller than standalone zstd on JSON text. Otherwise compare explicitly against standalone zstd!
        let fast_accept_limit = (raw_len / 20).max(2048);
        let use_delta = match delta_attempt {
            Some(delta) if delta.len() <= fast_accept_limit => Some(delta),
            Some(delta) if delta.len() < raw_len => {
                match run_standalone_compress(&state, &body_lease, raw_bytes.clone(), level).await {
                    Ok(full_z) => {
                        let full_arc: Arc<[u8]> = Arc::from(full_z);
                        let pick_delta = delta.len() < full_arc.len();
                        cached_full_zstd = Some(full_arc);
                        if pick_delta { Some(delta) } else { None }
                    }
                    Err(BudgetError::ExceedsTotalBudget { .. } | BudgetError::Saturated) => {
                        return budget_error_response(&state, BudgetError::Saturated);
                    }
                    Err(_) => Some(delta),
                }
            }
            _ => None,
        };

        if let Some(delta_box) = use_delta {
            let base_hex = hash_to_hex(&base_hash);
            let delta_len = delta_box.len();
            let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
            set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
            set_header(&mut fwd_headers, HDR_MODE, MODE_DELTA);
            set_header(&mut fwd_headers, HDR_BASE, &base_hex);
            set_header(&mut fwd_headers, HDR_FULL, &full_hex);
            set_header(&mut fwd_headers, HDR_RAW_LEN, &raw_len_str);

            // R2-02: body_lease remains held across send().await until wire payload is transmitted!
            match state
                .client
                .request(method.clone(), &target_url)
                .headers(fwd_headers)
                .body(delta_box.into_vec())
                .send()
                .await
            {
                Ok(resp)
                    if resp.status() == StatusCode::CONFLICT
                        && header_str(resp.headers(), HDR_MISS) == Some("1") =>
                {
                    debug!(base = %base_hex, "receiver reported 409 cache miss; retrying in full mode");
                    prior_wire_bytes = delta_len as u64;
                    state
                        .metrics
                        .miss_retries_total
                        .fetch_add(1, Ordering::Relaxed);
                    let scoped_base = scoped_cache_key(&tenant_scope, &base_hash);
                    state.cache.lock().unwrap().remove(&scoped_base);
                    state
                        .sessions
                        .lock()
                        .unwrap()
                        .invalidate_hash(&session_key, &base_hash);
                    // Fall through to full zstd retry below.
                }
                Ok(resp) => {
                    state.metrics.mode_delta_total.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .raw_bytes_total
                        .fetch_add(raw_len as u64, Ordering::Relaxed);
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(delta_len as u64, Ordering::Relaxed);

                    // R2-09 + R2-04 + BUG-08: NEVER block SSE first byte for local cache compression!
                    // If receiver confirmed X-Delta-Cached: 1, store immediately if already compressed,
                    // or spawn a budget-accounted background task transferring `body_lease` into it.
                    if header_str(resp.headers(), HDR_CACHED) == Some("1") {
                        let scoped_full = scoped_cache_key(&tenant_scope, &full_hash);
                        if let Some(existing) = cached_full_zstd.take() {
                            record_snapshot(
                                &state,
                                session_key,
                                full_hash,
                                scoped_full,
                                existing,
                                raw_len,
                            );
                            drop(body_lease);
                        } else {
                            spawn_background_cache_fill(
                                Arc::clone(&state),
                                body_lease,
                                raw_bytes,
                                session_key,
                                full_hash,
                                scoped_full,
                                raw_len,
                            );
                        }
                    } else {
                        drop(body_lease);
                    }

                    return stream_reqwest_response(resp, Arc::clone(&state.metrics));
                }
                Err(e) => {
                    // R2-11: Count wire bytes even on transport error!
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(delta_len as u64, Ordering::Relaxed);
                    state
                        .metrics
                        .failed_wire_bytes_total
                        .fetch_add(delta_len as u64, Ordering::Relaxed);
                    warn!(error = %e, "sender delta request to receiver failed");
                    return (StatusCode::BAD_GATEWAY, format!("receiver error: {e}"))
                        .into_response();
                }
            }
        }
    }

    // 4. Full standalone zstd mode (first turn, expired TTL, poor delta, or 409 retry).
    let full_zstd = match cached_full_zstd {
        Some(existing) => existing,
        None => match run_standalone_compress(&state, &body_lease, raw_bytes.clone(), level).await {
            Ok(z) => Arc::from(z),
            Err(e @ (BudgetError::ExceedsTotalBudget { .. } | BudgetError::Saturated)) => {
                if prior_wire_bytes > 0 {
                    state
                        .metrics
                        .wire_bytes_total
                        .fetch_add(prior_wire_bytes, Ordering::Relaxed);
                    state
                        .metrics
                        .failed_wire_bytes_total
                        .fetch_add(prior_wire_bytes, Ordering::Relaxed);
                }
                return budget_error_response(&state, e);
            }
            Err(_) => {
                let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
                set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
                set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
                return send_pass_and_stream(
                    &state,
                    method,
                    &target_url,
                    fwd_headers,
                    raw_bytes,
                    body_lease,
                    prior_wire_bytes,
                )
                .await;
            }
        },
    };

    // Never send an expanded compressed body when payload is incompressible (BUG-06 & BUG-14).
    if full_zstd.len() >= raw_len {
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
        return send_pass_and_stream(
            &state,
            method,
            &target_url,
            fwd_headers,
            raw_bytes,
            body_lease,
            prior_wire_bytes,
        )
        .await;
    }

    let full_wire_len = full_zstd.len();
    let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
    set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
    set_header(&mut fwd_headers, HDR_MODE, MODE_FULL);
    set_header(&mut fwd_headers, HDR_FULL, &full_hex);
    set_header(&mut fwd_headers, HDR_RAW_LEN, &raw_len_str);

    // Drop raw_bytes now — we only hold compressed `full_zstd` during send().
    drop(raw_bytes);
    let payload = Bytes::copy_from_slice(&full_zstd);
    match state
        .client
        .request(method, &target_url)
        .headers(fwd_headers)
        .body(payload)
        .send()
        .await
    {
        Ok(resp) => {
            state.metrics.mode_full_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .raw_bytes_total
                .fetch_add(raw_len as u64, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(prior_wire_bytes + full_wire_len as u64, Ordering::Relaxed);

            if header_str(resp.headers(), HDR_CACHED) == Some("1") {
                let scoped_full = scoped_cache_key(&tenant_scope, &full_hash);
                record_snapshot(
                    &state,
                    session_key,
                    full_hash,
                    scoped_full,
                    full_zstd,
                    raw_len,
                );
            }

            // R2-02: Release body_lease ONLY after send().await finishes!
            drop(body_lease);
            stream_reqwest_response(resp, Arc::clone(&state.metrics))
        }
        Err(e) => {
            // R2-11: Honestly record failed wire bytes (including any prior 409 delta attempt)!
            let wasted = prior_wire_bytes + full_wire_len as u64;
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(wasted, Ordering::Relaxed);
            state
                .metrics
                .failed_wire_bytes_total
                .fetch_add(wasted, Ordering::Relaxed);
            warn!(error = %e, "sender full request to receiver failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

/// R2-09 & R2-04: Compress and insert the confirmed snapshot asynchronously so SSE first-byte
/// latency is NEVER blocked, while keeping the task's memory strictly accounted under `body_lease`.
fn spawn_background_cache_fill(
    state: Arc<SenderState>,
    body_lease: MemoryLease,
    raw_bytes: Bytes,
    session_key: [u8; 32],
    full_hash: [u8; 32],
    scoped_full: [u8; 32],
    raw_len: usize,
) {
    tokio::spawn(async move {
        let work_mem = estimate_standalone_compress_mem(raw_len);
        let Ok(work_lease) = body_lease.acquire_child(work_mem).await else {
            debug!("skipping background cache fill under memory pressure");
            return;
        };
        let Ok(codec_slot) = state.budget.acquire_codec().await else {
            return;
        };
        let res = tokio::task::spawn_blocking(move || {
            let _raw_lease = body_lease;
            let _work_lease = work_lease;
            let _cpu_slot = codec_slot;
            compress_standalone(&raw_bytes, LOCAL_CACHE_ZSTD_LEVEL).ok()
        })
        .await;
        if let Ok(Some(z)) = res {
            record_snapshot(&state, session_key, full_hash, scoped_full, Arc::from(z), raw_len);
        }
    });
}

async fn run_standalone_compress(
    state: &SenderState,
    parent_lease: &MemoryLease,
    raw: Bytes,
    level: i32,
) -> Result<Box<[u8]>, BudgetError> {
    let work_mem = estimate_standalone_compress_mem(raw.len());
    let work_lease = parent_lease.acquire_child(work_mem).await?;
    let codec_slot = state.budget.acquire_codec().await?;
    tokio::task::spawn_blocking(move || {
        // R2-04: Both work_lease and codec_slot stay held until blocking task completes!
        let _mem_guard = work_lease;
        let _cpu_guard = codec_slot;
        compress_standalone(&raw, level).map_err(|e| BudgetError::BodyReadError(e.to_string()))
    })
    .await
    .map_err(|e| BudgetError::BodyReadError(format!("worker panic: {e}")))?
}

fn record_snapshot(
    state: &SenderState,
    session_key: [u8; 32],
    content_hash: [u8; 32],
    scoped_key: [u8; 32],
    full_zstd: Arc<[u8]>,
    raw_len: usize,
) {
    let inserted = state.cache.lock().unwrap().insert(scoped_key, full_zstd);
    if inserted {
        state
            .sessions
            .lock()
            .unwrap()
            .record(session_key, content_hash, raw_len);
    }
}

async fn send_pass_and_stream(
    state: &SenderState,
    method: Method,
    target_url: &str,
    headers: HeaderMap,
    body: Bytes,
    body_lease: MemoryLease,
    prior_wire_bytes: u64,
) -> Response {
    let len = body.len() as u64;
    match state
        .client
        .request(method, target_url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(resp) => {
            state.metrics.mode_pass_total.fetch_add(1, Ordering::Relaxed);
            state.metrics.raw_bytes_total.fetch_add(len, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(prior_wire_bytes + len, Ordering::Relaxed);
            // R2-02: Drop lease ONLY after send().await finishes!
            drop(body_lease);
            stream_reqwest_response(resp, Arc::clone(&state.metrics))
        }
        Err(e) => {
            let wasted = prior_wire_bytes + len;
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .wire_bytes_total
                .fetch_add(wasted, Ordering::Relaxed);
            state
                .metrics
                .failed_wire_bytes_total
                .fetch_add(wasted, Ordering::Relaxed);
            drop(body_lease);
            warn!(error = %e, "sender pass-through request failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

fn stream_reqwest_response(resp: reqwest::Response, metrics: Arc<RelayMetrics>) -> Response {
    let status = resp.status();
    let resp_headers = copy_filtered_headers(resp.headers(), is_stripped_response_header);
    let stream = resp.bytes_stream().inspect_err(move |e| {
        metrics.stream_errors_total.fetch_add(1, Ordering::Relaxed);
        metrics.errors_total.fetch_add(1, Ordering::Relaxed);
        warn!(error = %e, "sender mid-stream response error");
    });
    let mut builder = Response::builder().status(status);
    if let Some(h) = builder.headers_mut() {
        *h = resp_headers;
    }
    builder.body(Body::from_stream(stream)).unwrap_or_else(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("response build error: {e}"),
        )
            .into_response()
    })
}
