use clap::{Parser, Subcommand};
use ctx_delta_relay::{receiver, sender};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "ctx-delta-relay",
    version,
    about = "Dual-end transparent LLM context delta + zstd relay (sender <-> receiver)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the client/egress-side delta encoder sidecar (receives plaintext LLM API requests)
    Sender {
        /// Local address to listen on for gateway / client requests
        #[arg(long, env = "DELTA_LISTEN", default_value = "127.0.0.1:18080")]
        listen: SocketAddr,

        /// Optional local admin address for /healthz and /stats
        #[arg(long, env = "DELTA_ADMIN_LISTEN")]
        admin_listen: Option<SocketAddr>,

        /// Remote receiver base URL (e.g. https://relay.example.com:18443)
        #[arg(long, env = "DELTA_RECEIVER_URL")]
        receiver_url: String,

        /// Pre-shared tunnel secret (X-Delta-Auth, minimum 16 chars)
        #[arg(long, env = "DELTA_SECRET")]
        secret: String,

        /// Optional client access secret (X-Delta-Client-Auth, >= 16 chars) recommended if binding non-loopback
        #[arg(long, env = "DELTA_CLIENT_AUTH")]
        client_auth: Option<String>,

        /// Hard RAM cap in MiB for sender compressed snapshot LRU
        #[arg(long, env = "DELTA_MAX_CACHE_MB", default_value_t = 256)]
        max_cache_mb: usize,

        /// Hard RAM budget in MiB for concurrent in-flight body & zstd working sets
        #[arg(long, env = "DELTA_MAX_INFLIGHT_MB", default_value_t = 96)]
        max_inflight_mb: usize,

        /// Maximum concurrent active requests before immediate 503 load shedding
        #[arg(long, env = "DELTA_MAX_CONCURRENT_REQUESTS", default_value_t = 256)]
        max_concurrent_requests: usize,

        /// Max concurrent blocking zstd codec tasks
        #[arg(long, env = "DELTA_MAX_CODEC_CONCURRENCY", default_value_t = 4)]
        max_codec_concurrency: usize,

        /// Snapshot TTL in seconds (set slightly shorter than receiver TTL, e.g. 1500 vs 1800)
        #[arg(long, env = "DELTA_TTL_SECS", default_value_t = 1500)]
        ttl_secs: u64,

        /// Minimum request body bytes before applying zstd/delta encoding
        #[arg(long, env = "DELTA_MIN_BYTES", default_value_t = 4096)]
        min_delta_bytes: usize,

        /// Maximum request body size in MiB
        #[arg(long, env = "DELTA_MAX_BODY_MB", default_value_t = 16)]
        max_body_mb: usize,

        /// Zstd compression level (1..=6 recommended)
        #[arg(long, env = "DELTA_ZSTD_LEVEL", default_value_t = 3)]
        zstd_level: i32,

        /// Skip TLS cert verification when calling receiver (testing only)
        #[arg(long, env = "DELTA_INSECURE_TLS", default_value_t = false)]
        insecure_tls: bool,

        /// Maximum seconds allowed for a client to finish uploading the request body
        #[arg(long, env = "DELTA_BODY_READ_TIMEOUT_SECS", default_value_t = 30)]
        body_read_timeout_secs: u64,

        /// Idle read timeout per streamed response chunk in seconds
        #[arg(long, env = "DELTA_READ_TIMEOUT_SECS", default_value_t = 300)]
        read_timeout_secs: u64,
    },

    /// Run the upstream-side Hydrator (reconstructs exact request bodies and forwards locally)
    Receiver {
        /// Listen address for incoming delta-encoded requests
        #[arg(long, env = "DELTA_LISTEN", default_value = "127.0.0.1:18080")]
        listen: SocketAddr,

        /// Optional local admin address for /healthz and /stats
        #[arg(long, env = "DELTA_ADMIN_LISTEN")]
        admin_listen: Option<SocketAddr>,

        /// Local upstream URL to forward reconstructed requests to (e.g. http://127.0.0.1:3000)
        #[arg(long, env = "DELTA_UPSTREAM_URL")]
        upstream_url: String,

        /// Optional Host header override when forwarding to a local reverse proxy vhost
        #[arg(long, env = "DELTA_UPSTREAM_HOST")]
        upstream_host: Option<String>,

        /// Pre-shared tunnel secret (X-Delta-Auth, minimum 16 chars)
        #[arg(long, env = "DELTA_SECRET")]
        secret: String,

        /// Strict RAM cap in MiB for receiver compressed snapshot LRU (zero disk)
        #[arg(long, env = "DELTA_MAX_CACHE_MB", default_value_t = 256)]
        max_cache_mb: usize,

        /// Hard RAM budget in MiB for concurrent in-flight body & zstd working sets
        #[arg(long, env = "DELTA_MAX_INFLIGHT_MB", default_value_t = 96)]
        max_inflight_mb: usize,

        /// Maximum concurrent active requests before immediate 503 load shedding
        #[arg(long, env = "DELTA_MAX_CONCURRENT_REQUESTS", default_value_t = 256)]
        max_concurrent_requests: usize,

        /// Max concurrent blocking zstd codec tasks
        #[arg(long, env = "DELTA_MAX_CODEC_CONCURRENCY", default_value_t = 4)]
        max_codec_concurrency: usize,

        /// Snapshot idle TTL in seconds
        #[arg(long, env = "DELTA_TTL_SECS", default_value_t = 1800)]
        ttl_secs: u64,

        /// Maximum reconstructed raw request body size in MiB
        #[arg(long, env = "DELTA_MAX_BODY_MB", default_value_t = 16)]
        max_body_mb: usize,

        /// Zstd level for in-memory cached snapshots (1 = fastest, lowest CPU)
        #[arg(long, env = "DELTA_CACHE_ZSTD_LEVEL", default_value_t = 1)]
        cache_zstd_level: i32,

        /// Skip TLS cert verification when calling local upstream HTTPS
        #[arg(long, env = "DELTA_INSECURE_UPSTREAM_TLS", default_value_t = false)]
        insecure_upstream_tls: bool,

        /// Maximum seconds allowed for a sender to finish uploading the wire body
        #[arg(long, env = "DELTA_BODY_READ_TIMEOUT_SECS", default_value_t = 30)]
        body_read_timeout_secs: u64,

        /// Idle read timeout per streamed response chunk in seconds
        #[arg(long, env = "DELTA_READ_TIMEOUT_SECS", default_value_t = 300)]
        read_timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Sender {
            listen,
            admin_listen,
            receiver_url,
            secret,
            client_auth,
            max_cache_mb,
            max_inflight_mb,
            max_concurrent_requests,
            max_codec_concurrency,
            ttl_secs,
            min_delta_bytes,
            max_body_mb,
            zstd_level,
            insecure_tls,
            body_read_timeout_secs,
            read_timeout_secs,
        } => {
            if !listen.ip().is_loopback() && client_auth.is_none() {
                warn!(
                    %listen,
                    "sender is listening on a non-loopback address without --client-auth (DELTA_CLIENT_AUTH); restrict access via firewall/NetworkPolicy or enable client auth"
                );
            }
            if insecure_tls {
                warn!("--insecure-tls is enabled; do NOT use this in production");
            }
            let cfg = sender::SenderConfig {
                receiver_url: receiver_url.clone(),
                secret,
                client_auth,
                max_cache_bytes: max_cache_mb * 1024 * 1024,
                max_inflight_bytes: max_inflight_mb * 1024 * 1024,
                max_concurrent_requests,
                max_codec_concurrency,
                ttl: Duration::from_secs(ttl_secs),
                min_delta_bytes,
                max_body_bytes: max_body_mb * 1024 * 1024,
                zstd_level,
                insecure_tls,
                body_read_timeout: Duration::from_secs(body_read_timeout_secs),
                read_timeout: Duration::from_secs(read_timeout_secs),
            };
            if cfg.is_plaintext_non_loopback_receiver() {
                warn!(
                    receiver = %receiver_url,
                    "receiver_url uses plaintext http:// to a non-loopback host; wrap receiver with HTTPS/TLS in production!"
                );
            }
            let state = sender::SenderState::new(cfg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let _sweeper = state.spawn_sweeper();

            if let Some(admin_addr) = admin_listen {
                let admin_app = sender::admin_router(state.clone());
                let admin_listener = TcpListener::bind(admin_addr).await?;
                info!(%admin_addr, "sender admin endpoint listening (/healthz, /stats)");
                tokio::spawn(async move {
                    let _ = axum::serve(admin_listener, admin_app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await;
                });
            }

            let app = sender::router(state);
            let listener = TcpListener::bind(listen).await?;
            info!(
                %listen,
                receiver = %receiver_url,
                max_cache_mb,
                max_inflight_mb,
                max_concurrent_requests,
                max_codec_concurrency,
                ttl_secs,
                "ctx-delta-relay sender started"
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }

        Command::Receiver {
            listen,
            admin_listen,
            upstream_url,
            upstream_host,
            secret,
            max_cache_mb,
            max_inflight_mb,
            max_concurrent_requests,
            max_codec_concurrency,
            ttl_secs,
            max_body_mb,
            cache_zstd_level,
            insecure_upstream_tls,
            body_read_timeout_secs,
            read_timeout_secs,
        } => {
            if !listen.ip().is_loopback() {
                warn!(
                    %listen,
                    "receiver is listening on a non-loopback address without built-in TLS; prefer binding 127.0.0.1 behind an HTTPS reverse proxy"
                );
            }
            let cfg = receiver::ReceiverConfig {
                upstream_url: upstream_url.clone(),
                upstream_host,
                secret,
                max_cache_bytes: max_cache_mb * 1024 * 1024,
                max_inflight_bytes: max_inflight_mb * 1024 * 1024,
                max_concurrent_requests,
                max_codec_concurrency,
                ttl: Duration::from_secs(ttl_secs),
                max_body_bytes: max_body_mb * 1024 * 1024,
                cache_zstd_level,
                insecure_upstream_tls,
                body_read_timeout: Duration::from_secs(body_read_timeout_secs),
                read_timeout: Duration::from_secs(read_timeout_secs),
            };
            let state = receiver::ReceiverState::new(cfg)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let _sweeper = state.spawn_sweeper();

            if let Some(admin_addr) = admin_listen {
                let admin_app = receiver::admin_router(state.clone());
                let admin_listener = TcpListener::bind(admin_addr).await?;
                info!(%admin_addr, "receiver admin endpoint listening (/healthz, /stats)");
                tokio::spawn(async move {
                    let _ = axum::serve(admin_listener, admin_app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await;
                });
            }

            let app = receiver::router(state);
            let listener = TcpListener::bind(listen).await?;
            info!(
                %listen,
                upstream = %upstream_url,
                max_cache_mb,
                max_inflight_mb,
                max_concurrent_requests,
                max_codec_concurrency,
                ttl_secs,
                "ctx-delta-relay receiver started"
            );
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }
    }

    Ok(())
}

/// Graceful shutdown on both SIGINT (Ctrl+C) and Unix SIGTERM (systemd stop/restart).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("SIGINT received, draining in-flight connections"),
        _ = terminate => info!("SIGTERM received, draining in-flight connections"),
    }
}
