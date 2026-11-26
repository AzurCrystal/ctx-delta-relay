use crate::cache::{ByteBoundedLru, SessionIndex};
use crate::codec::{compress_delta, compress_standalone, decompress_cached_snapshot};
use crate::fingerprint::derive_session_key;
use crate::metrics::{RelayMetrics, StatsSnapshot};
use crate::protocol::{
    HDR_AUTH, HDR_BASE, HDR_CACHED, HDR_CLIENT_AUTH, HDR_FULL, HDR_MISS, HDR_MODE, HDR_RAW_LEN,
    MODE_DELTA, MODE_FULL, MODE_PASS, copy_filtered_headers, hash_to_hex, header_str,
    is_stripped_request_header, is_stripped_response_header, is_websocket_upgrade, set_header,
    verify_header_secret,
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
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Granularity for in-flight memory budget permits (64 KiB per permit).
const MEM_PERMIT_UNIT: usize = 64 * 1024;
/// Fast zstd level used purely for storing local cached snapshots after a delta hit.
const LOCAL_CACHE_ZSTD_LEVEL: i32 = 1;

#[derive(Clone, Debug)]
pub struct SenderConfig {
    /// Base URL of the remote receiver, e.g. "https://relay.example.com:18443"
    pub receiver_url: String,
    /// Shared secret sent in X-Delta-Auth
    pub secret: String,
    /// Optional client access secret required in X-Delta-Client-Auth when exposed beyond loopback
    pub client_auth: Option<String>,
    /// Hard memory ceiling (in bytes) for sender-side compressed snapshot LRU
    pub max_cache_bytes: usize,
    /// Hard memory budget (in bytes) for concurrent in-flight codec/body buffers
    pub max_inflight_bytes: usize,
    /// Maximum concurrent blocking zstd codec tasks
    pub max_codec_concurrency: usize,
    /// Session/snapshot TTL (recommended slightly shorter than receiver TTL)
    pub ttl: Duration,
    /// Minimum request body size to compress/delta-encode (smaller bodies pass through)
    pub min_delta_bytes: usize,
    /// Maximum request body size accepted
    pub max_body_bytes: usize,
    /// Zstd compression level (1..=6 recommended; default 3)
    pub zstd_level: i32,
    /// Accept invalid TLS certs on receiver (testing only)
    pub insecure_tls: bool,
    /// Idle read timeout per streamed chunk
    pub read_timeout: Duration,
}

pub struct SenderState {
    cfg: SenderConfig,
    client: reqwest::Client,
    cache: Mutex<ByteBoundedLru>,
    sessions: Mutex<SessionIndex>,
    mem_budget: Arc<Semaphore>,
    codec_sem: Arc<Semaphore>,
    metrics: Arc<RelayMetrics>,
}

impl SenderState {
    pub fn new(cfg: SenderConfig) -> Result<Arc<Self>, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            // BUG-03: Never auto-follow redirects (prevents leaking X-Delta-Auth / API keys).
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(cfg.read_timeout)
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .pool_idle_timeout(Some(Duration::from_secs(90)));
        if cfg.insecure_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build()?;

        let max_sessions = (cfg.max_cache_bytes / (32 * 1024)).clamp(256, 65536);
        let total_mem_permits = cfg.max_inflight_bytes.div_ceil(MEM_PERMIT_UNIT).max(16);
        let codec_permits = cfg.max_codec_concurrency.max(1);

        Ok(Arc::new(Self {
            cache: Mutex::new(ByteBoundedLru::new(cfg.max_cache_bytes, cfg.ttl)),
            sessions: Mutex::new(SessionIndex::new(max_sessions, cfg.ttl)),
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

fn permits_for_bytes(bytes: usize) -> u32 {
    bytes.div_ceil(MEM_PERMIT_UNIT).max(1).min(u32::MAX as usize) as u32
}

async fn handle_proxy(State(state): State<Arc<SenderState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    // BUG-09: Optional sender-side client access control for non-loopback deployments.
    if let Some(ref client_secret) = state.cfg.client_auth
        && !verify_header_secret(&headers, HDR_CLIENT_AUTH, client_secret)
    {
        return (StatusCode::FORBIDDEN, "sender client auth required").into_response();
    }

    // BUG-07: Explicitly reject WebSocket upgrades instead of silently mangling them.
    if is_websocket_upgrade(&headers) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "ctx-delta-relay is an HTTP/SSE relay; connect WebSocket endpoints directly",
        )
            .into_response();
    }

    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target_url = format!(
        "{}{}",
        state.cfg.receiver_url.trim_end_matches('/'),
        path_and_query
    );

    // Pre-reserve in-flight memory budget based on Content-Length hint (or 1 unit if chunked).
    let hinted_len = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(MEM_PERMIT_UNIT);
    if hinted_len > state.cfg.max_body_bytes {
        return (StatusCode::PAYLOAD_TOO_LARGE, "request exceeds max-body-mb").into_response();
    }

    // Reserve roughly 2x raw_len for in-flight raw + base/output working buffers.
    let pre_permits = permits_for_bytes(hinted_len.saturating_mul(2))
        .min(permits_for_bytes(state.cfg.max_inflight_bytes));
    let Ok(Ok(mem_permit)) = tokio::time::timeout(
        Duration::from_secs(10),
        Arc::clone(&state.mem_budget).acquire_many_owned(pre_permits),
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
            "sender in-flight memory budget saturated",
        )
            .into_response();
    };

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

    // If chunked upload turned out much larger than hint, acquire the delta permits now.
    let actual_permits = permits_for_bytes(raw_len.saturating_mul(2))
        .min(permits_for_bytes(state.cfg.max_inflight_bytes));
    let _extra_permit = if actual_permits > pre_permits {
        match tokio::time::timeout(
            Duration::from_secs(10),
            Arc::clone(&state.mem_budget).acquire_many_owned(actual_permits - pre_permits),
        )
        .await
        {
            Ok(Ok(p)) => Some(p),
            _ => {
                state
                    .metrics
                    .overload_rejects_total
                    .fetch_add(1, Ordering::Relaxed);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(http::header::RETRY_AFTER, "1")],
                    "sender in-flight memory budget saturated",
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    // 1. Pass-through for small, non-mutating, or already-encoded requests.
    if should_bypass_encoding(&method, &headers, raw_len, &state.cfg) {
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
        drop(mem_permit);
        drop(_extra_permit);
        return send_pass_and_stream(&state, method, &target_url, fwd_headers, raw_bytes).await;
    }

    // 2. Compute BLAKE3 hash & conversation fingerprint; select best ranked base candidate (BUG-10).
    let full_hash = *blake3::hash(&raw_bytes).as_bytes();
    let path_only = uri.path().to_string();
    let session_key = derive_session_key(&headers, &path_only, &raw_bytes);
    let candidate_base: Option<([u8; 32], Arc<[u8]>)> = {
        let hashes =
            state
                .sessions
                .lock()
                .unwrap()
                .ranked_candidates(&session_key, &full_hash, raw_len);
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

    let full_hex = hash_to_hex(&full_hash);
    let raw_len_str = raw_len.to_string();
    let level = state.cfg.zstd_level;
    let max_body = state.cfg.max_body_bytes;

    // 3. Hot-path optimization (BUG-11): when a base exists, ONLY run delta compression first —
    // skip redundant standalone full compression unless delta is poor or receiver returns 409!
    let mut cached_full_zstd: Option<Arc<[u8]>> = None;
    let mut tried_delta_wire_bytes: u64 = 0;

    if let Some((base_hash, base_zstd)) = candidate_base {
        let Ok(codec_permit) = Arc::clone(&state.codec_sem).acquire_owned().await else {
            return (StatusCode::SERVICE_UNAVAILABLE, "codec pool closed").into_response();
        };
        let raw_for_cpu = raw_bytes.clone();
        let delta_res = tokio::task::spawn_blocking(move || {
            let _guard = codec_permit;
            let base_raw = decompress_cached_snapshot(&base_zstd, max_body)
                .map_err(|e| e.to_string())?;
            let delta =
                compress_delta(&raw_for_cpu, &base_raw, level).map_err(|e| e.to_string())?;
            Ok::<Box<[u8]>, String>(delta)
        })
        .await;

        let maybe_delta = match delta_res {
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
        };

        // Only verify against standalone zstd if delta isn't already tiny (< 25% of raw_len).
        let use_delta = match maybe_delta {
            Some(delta) if delta.len() < raw_len / 4 => Some(delta),
            Some(delta) if delta.len() < raw_len => {
                // Compare against standalone zstd so we never send a delta worse than full zstd.
                if let Ok(full_z) = run_standalone_compress(&state, raw_bytes.clone(), level).await {
                    let full_arc: Arc<[u8]> = Arc::from(full_z);
                    let pick_delta = delta.len() < full_arc.len();
                    cached_full_zstd = Some(full_arc);
                    if pick_delta { Some(delta) } else { None }
                } else {
                    Some(delta)
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
                    tried_delta_wire_bytes = delta_len as u64;
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

                    // BUG-08: Only record snapshot locally if receiver explicitly confirmed caching it!
                    if header_str(resp.headers(), HDR_CACHED) == Some("1") {
                        let snap = match cached_full_zstd.take() {
                            Some(existing) => Some(existing),
                            None => run_standalone_compress(
                                &state,
                                raw_bytes.clone(),
                                LOCAL_CACHE_ZSTD_LEVEL,
                            )
                            .await
                            .ok()
                            .map(Arc::from),
                        };
                        if let Some(snap_arc) = snap {
                            record_snapshot(&state, session_key, full_hash, snap_arc, raw_len);
                        }
                    }

                    drop(mem_permit);
                    drop(_extra_permit);
                    return stream_reqwest_response(resp, Arc::clone(&state.metrics));
                }
                Err(e) => {
                    state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
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
        None => match run_standalone_compress(&state, raw_bytes.clone(), level).await {
            Ok(z) => Arc::from(z),
            Err(e) => {
                warn!(error = %e, "sender standalone compression failed, falling back to pass");
                let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
                set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
                set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
                drop(mem_permit);
                drop(_extra_permit);
                return send_pass_and_stream(&state, method, &target_url, fwd_headers, raw_bytes)
                    .await;
            }
        },
    };

    // BUG-06 & BUG-14: Never send an expanded compressed body when payload is incompressible!
    if full_zstd.len() >= raw_len {
        let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
        set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
        set_header(&mut fwd_headers, HDR_MODE, MODE_PASS);
        drop(mem_permit);
        drop(_extra_permit);
        return send_pass_with_prior_overhead(
            &state,
            method,
            &target_url,
            fwd_headers,
            raw_bytes,
            tried_delta_wire_bytes,
        )
        .await;
    }

    let full_wire_len = full_zstd.len();
    let mut fwd_headers = copy_filtered_headers(&headers, is_stripped_request_header);
    set_header(&mut fwd_headers, HDR_AUTH, &state.cfg.secret);
    set_header(&mut fwd_headers, HDR_MODE, MODE_FULL);
    set_header(&mut fwd_headers, HDR_FULL, &full_hex);
    set_header(&mut fwd_headers, HDR_RAW_LEN, &raw_len_str);

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
                .fetch_add(tried_delta_wire_bytes + full_wire_len as u64, Ordering::Relaxed);

            // BUG-08: Only cache locally when receiver confirms X-Delta-Cached: 1!
            if header_str(resp.headers(), HDR_CACHED) == Some("1") {
                record_snapshot(&state, session_key, full_hash, full_zstd, raw_len);
            }

            drop(mem_permit);
            drop(_extra_permit);
            stream_reqwest_response(resp, Arc::clone(&state.metrics))
        }
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender full request to receiver failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

async fn run_standalone_compress(
    state: &SenderState,
    raw: Bytes,
    level: i32,
) -> Result<Box<[u8]>, String> {
    let permit = Arc::clone(&state.codec_sem)
        .acquire_owned()
        .await
        .map_err(|_| "codec pool closed".to_string())?;
    tokio::task::spawn_blocking(move || {
        let _guard = permit;
        compress_standalone(&raw, level).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("worker panic: {e}"))?
}

fn record_snapshot(
    state: &SenderState,
    session_key: [u8; 32],
    full_hash: [u8; 32],
    full_zstd: Arc<[u8]>,
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

async fn send_pass_and_stream(
    state: &SenderState,
    method: Method,
    target_url: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    send_pass_with_prior_overhead(state, method, target_url, headers, body, 0).await
}

async fn send_pass_with_prior_overhead(
    state: &SenderState,
    method: Method,
    target_url: &str,
    headers: HeaderMap,
    body: Bytes,
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
            stream_reqwest_response(resp, Arc::clone(&state.metrics))
        }
        Err(e) => {
            state.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "sender pass-through request failed");
            (StatusCode::BAD_GATEWAY, format!("receiver error: {e}")).into_response()
        }
    }
}

fn stream_reqwest_response(resp: reqwest::Response, metrics: Arc<RelayMetrics>) -> Response {
    let status = resp.status();
    let resp_headers = copy_filtered_headers(resp.headers(), is_stripped_response_header);
    // BUG-13: Track mid-stream SSE/network read errors in metrics & logs.
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
