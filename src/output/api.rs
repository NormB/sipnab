//! REST API daemon mode for sipnab.
//!
//! Provides a read-only REST API over active SIP dialogs and RTP streams.
//! Feature-gated behind `--features api`, which pulls in `axum` and `tokio`.
//!
//! # Endpoints
//!
//! | Method | Path                            | Description                     |
//! |--------|----------------------------------|--------------------------------|
//! | GET    | `/health`                       | Health check                    |
//! | GET    | `/v1/dialogs`                   | List dialogs (paginated)        |
//! | GET    | `/v1/dialogs/:call_id`          | Get single dialog               |
//! | GET    | `/v1/dialogs/:call_id/report`   | Get dialog call report          |
//! | GET    | `/v1/streams`                   | List RTP streams (paginated)    |
//! | GET    | `/v1/streams/:id`               | Get single RTP stream           |
//! | GET    | `/v1/stats`                     | Aggregate statistics            |
//! | GET    | `/metrics`                      | Prometheus metrics (if enabled) |
//!
//! # Authentication
//!
//! If `--api-key` is provided, all endpoints (except `/health`) require
//! `Authorization: Bearer <key>`. Missing or invalid keys return 401.
//!
//! # Rate Limiting
//!
//! Requests are rate-limited to 100 per second per source IP. Excess
//! requests return 503 Service Unavailable.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use parking_lot::{Mutex, RwLock};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::output;
use crate::output::prometheus::{self, PrometheusMetrics};
use crate::rtp::diagnosis::diagnose_media;
use crate::rtp::quality;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog::DialogState;
use crate::sip::dialog_store::DialogStore;

// ── Shared application state ────────────────────────────────────────

/// Shared state passed to every axum handler via `State(...)`.
#[derive(Clone)]
pub struct ApiState {
    /// Shared dialog store (same instance used by capture threads).
    pub dialog_store: Arc<RwLock<DialogStore>>,
    /// Shared RTP stream store (same instance used by capture threads).
    pub stream_store: Arc<RwLock<StreamStore>>,
    /// Optional bearer token for API authentication.
    pub api_key: Option<String>,
    /// Per-IP rate limiter.
    pub rate_limiter: Arc<Mutex<RateLimiter>>,
}

// ── Rate limiter ────────────────────────────────────────────────────

/// Simple per-IP sliding-window rate limiter.
///
/// Tracks request counts per source IP within a one-second window.
/// Resets the window when the current second changes.
pub struct RateLimiter {
    /// Map of source IP to (window start, count).
    buckets: HashMap<IpAddr, (Instant, u32)>,
    /// Maximum requests per second per IP.
    max_rps: u32,
    /// Monotonic call counter for periodic cleanup.
    call_count: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given per-IP max requests/second.
    pub fn new(max_rps: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            max_rps,
            call_count: 0,
        }
    }

    /// Check whether a request from `ip` is allowed. Returns `true` if under limit.
    ///
    /// Periodically cleans up stale entries (every 100th call) to prevent
    /// unbounded memory growth from unique source IPs.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.call_count += 1;

        // Periodic cleanup: remove entries older than 2 seconds
        if self.call_count.is_multiple_of(100) {
            self.buckets
                .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 2);
        }

        let entry = self.buckets.entry(ip).or_insert((now, 0));

        // Reset window if more than 1 second has passed
        if now.duration_since(entry.0).as_secs() >= 1 {
            *entry = (now, 0);
        }

        entry.1 += 1;
        entry.1 <= self.max_rps
    }
}

// ── Query parameter types ───────────────────────────────────────────

/// Query parameters for the `GET /v1/dialogs` endpoint.
#[derive(Debug, Deserialize)]
pub struct DialogListParams {
    /// Pagination offset (default 0).
    pub offset: Option<usize>,
    /// Maximum results to return (default 50).
    pub limit: Option<usize>,
    /// Filter by dialog state (e.g., "Trying", "InCall", "Completed").
    pub state: Option<String>,
    /// Filter by From user (regex pattern).
    pub from: Option<String>,
}

/// Query parameters for the `GET /v1/streams` endpoint.
#[derive(Debug, Deserialize)]
pub struct StreamListParams {
    /// Pagination offset (default 0).
    pub offset: Option<usize>,
    /// Maximum results to return (default 50).
    pub limit: Option<usize>,
    /// Filter to show only orphaned streams.
    pub orphaned: Option<bool>,
    /// Filter streams with MOS below this threshold.
    pub mos_below: Option<f64>,
}

// ── Router construction ─────────────────────────────────────────────

/// Build the axum [`Router`] with all API endpoints.
///
/// The returned router expects an [`ApiState`] to be supplied as shared state.
pub fn build_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/dialogs", get(list_dialogs))
        .route("/v1/dialogs/{call_id}", get(get_dialog))
        .route("/v1/dialogs/{call_id}/report", get(get_dialog_report))
        .route("/v1/streams", get(list_streams))
        .route("/v1/streams/{id}", get(get_stream))
        .route("/v1/stats", get(get_stats))
        .route("/metrics", get(get_metrics))
        .with_state(state)
}

/// Parse a bind address string into a [`SocketAddr`].
///
/// Accepts:
/// - `":8080"` or `"8080"` — binds to `127.0.0.1:8080` (D18 default)
/// - `"0.0.0.0:8080"` — binds to all interfaces
/// - Any valid `addr:port` pair
///
/// Returns an error string if parsing fails.
pub fn parse_bind_addr(addr: &str) -> Result<SocketAddr, String> {
    // Just a port number
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }

    // ":port" shorthand
    if let Some(stripped) = addr.strip_prefix(':')
        && let Ok(port) = stripped.parse::<u16>()
    {
        return Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }

    // Full addr:port
    addr.parse::<SocketAddr>()
        .map_err(|e| format!("invalid bind address '{addr}': {e}"))
}

/// Configuration for the API server.
#[derive(Debug, Clone, Default)]
pub struct ApiServerConfig {
    /// Maximum concurrent connections (0 = unlimited).
    pub max_conn: u32,
    /// TLS certificate file path.
    pub tls_cert: Option<String>,
    /// TLS private key file path.
    pub tls_key: Option<String>,
}

/// Start the API server on the given address.
///
/// This function blocks the current tokio runtime until the server is
/// shut down. It should be spawned in a dedicated thread or task.
///
/// Logs a warning if the bind address is non-loopback without TLS.
pub async fn run_server(
    bind_addr: SocketAddr,
    state: ApiState,
    server_config: ApiServerConfig,
) -> Result<(), String> {
    let has_tls = server_config.tls_cert.is_some() && server_config.tls_key.is_some();

    if has_tls {
        return Err(
            "API TLS (--api-tls-cert/--api-tls-key) requires the axum-server crate \
             which is not yet integrated. Use a TLS-terminating reverse proxy instead."
                .to_string(),
        );
    }

    if !bind_addr.ip().is_loopback() {
        log::warn!(
            "API server binding to non-loopback address {} without TLS — \
             consider using 127.0.0.1 or enabling TLS",
            bind_addr
        );
    }

    let max_conn = server_config.max_conn;
    let router = build_router(state);

    // Wrap with connection limiter if max_conn > 0
    let router = if max_conn > 0 {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_conn as usize));
        log::info!("API server max concurrent connections: {}", max_conn);
        router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let sem = Arc::clone(&semaphore);
                async move {
                    let _permit = match sem.try_acquire() {
                        Ok(p) => p,
                        Err(_) => {
                            return Ok::<_, std::convert::Infallible>(
                                StatusCode::SERVICE_UNAVAILABLE.into_response(),
                            );
                        }
                    };
                    Ok(next.run(req).await)
                }
            },
        ))
    } else {
        router
    };

    log::info!("REST API listening on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .map_err(|e| format!("failed to bind API to {bind_addr}: {e}"))?;

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| format!("API server error: {e}"))
}

// ── Auth + rate-limit helpers ───────────────────────────────────────


/// Check authentication. Returns `Err(StatusCode)` if auth fails.
fn check_auth(state: &ApiState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(ref expected_key) = state.api_key else {
        return Ok(());
    };

    let Some(auth_header) = headers.get("authorization") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    if let Some(token) = auth_str.strip_prefix("Bearer ")
        && constant_time_eq(token.as_bytes(), expected_key.as_bytes())
    {
        return Ok(());
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Constant-time byte comparison to prevent timing side-channel attacks on API keys.
///
/// Does not leak the length of either input: both are compared up to
/// the length of the longer input, and the length check is folded into
/// the final result without early return.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_match = a.len() == b.len();
    let max_len = a.len().max(b.len());
    let mut byte_diff = 0u8;
    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        byte_diff |= x ^ y;
    }
    len_match && byte_diff == 0
}

/// Check rate limit. Returns `Err(StatusCode)` if over limit.
fn check_rate_limit(state: &ApiState, ip: IpAddr) -> Result<(), StatusCode> {
    let mut limiter = state.rate_limiter.lock();
    if limiter.check(ip) {
        Ok(())
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Combined auth + rate-limit guard for protected endpoints.
///
/// Uses the real client IP from `ConnectInfo<SocketAddr>` (provided by
/// `into_make_service_with_connect_info`) for rate limiting. X-Forwarded-For
/// and X-Real-IP headers are NOT trusted, as they are attacker-controlled.
fn guard(state: &ApiState, headers: &HeaderMap, client_ip: IpAddr) -> Result<(), StatusCode> {
    check_auth(state, headers)?;
    check_rate_limit(state, client_ip)
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /health` — always returns "ok", no auth required.
async fn health_check() -> &'static str {
    "ok"
}

/// `GET /v1/dialogs` — list dialogs with optional filtering and pagination.
async fn list_dialogs(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DialogListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(1000);

    let state_filter = params.state.as_deref();
    // NOTE: Regex is compiled per-request. Under the 100 RPS rate limit this
    // is acceptable (~1ms compile time). For higher throughput, consider caching.
    let from_regex = params.from.as_deref().and_then(|pat| {
        regex::RegexBuilder::new(pat)
            .size_limit(1_000_000)
            .build()
            .ok()
    });

    let ds = state.dialog_store.read();
    let dialogs: Vec<Value> = ds
        .iter()
        .filter(|d| {
            if let Some(sf) = state_filter {
                let state_str = format!("{:?}", d.state);
                if !state_str.eq_ignore_ascii_case(sf) {
                    return false;
                }
            }
            if let Some(ref re) = from_regex {
                let from_str = d.from_user.as_deref().unwrap_or("");
                if !re.is_match(from_str) {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .map(dialog_summary)
        .collect();

    let total = ds.len();
    drop(ds);

    Ok(Json(json!({
        "schema_version": 1,
        "total": total,
        "offset": offset,
        "limit": limit,
        "dialogs": dialogs,
    })))
}

/// `GET /v1/dialogs/:call_id` — get a single dialog with full detail.
async fn get_dialog(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let dialog = ds.get(&call_id).ok_or(StatusCode::NOT_FOUND)?;

    let ss = state.stream_store.read();
    let streams: Vec<&crate::rtp::stream::RtpStream> = ss
        .iter()
        .filter(|s| s.associated_dialog.as_deref() == Some(call_id.as_str()))
        .collect();

    let diagnosis = diagnose_media(&streams, None);
    let json_str = output::json::dialog_to_json(dialog, &streams, &diagnosis);
    drop(ss);
    drop(ds);

    let parsed: Value =
        serde_json::from_str(&json_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/dialogs/:call_id/report` — get a call report in JSON format.
async fn get_dialog_report(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let dialog = ds.get(&call_id).ok_or(StatusCode::NOT_FOUND)?;

    let ss = state.stream_store.read();
    let streams: Vec<&crate::rtp::stream::RtpStream> = ss
        .iter()
        .filter(|s| s.associated_dialog.as_deref() == Some(call_id.as_str()))
        .collect();

    let diagnosis = diagnose_media(&streams, None);
    let report =
        output::generate_call_report(dialog, &streams, &diagnosis, output::ReportFormat::Json);
    drop(ss);
    drop(ds);

    let parsed: Value =
        serde_json::from_str(&report).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/streams` — list RTP streams with optional filtering and pagination.
async fn list_streams(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<StreamListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(50).min(1000);
    let orphaned_filter = params.orphaned;
    let mos_threshold = params.mos_below;

    let ss = state.stream_store.read();
    let streams: Vec<Value> = ss
        .iter()
        .filter(|s| {
            if let Some(orphaned) = orphaned_filter
                && s.orphaned != orphaned
            {
                return false;
            }
            if let Some(threshold) = mos_threshold {
                let mos = approximate_mos(s);
                if mos >= threshold {
                    return false;
                }
            }
            true
        })
        .skip(offset)
        .take(limit)
        .map(stream_summary)
        .collect();

    let total = ss.len();
    drop(ss);

    Ok(Json(json!({
        "schema_version": 1,
        "total": total,
        "offset": offset,
        "limit": limit,
        "streams": streams,
    })))
}

/// `GET /v1/streams/:id` — get a single RTP stream by SSRC hex string.
async fn get_stream(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let ss = state.stream_store.read();
    // Find stream by SSRC hex string (e.g., "0x12345678" or "12345678")
    let needle = id.strip_prefix("0x").unwrap_or(&id);
    let ssrc = u32::from_str_radix(needle, 16).map_err(|_| StatusCode::BAD_REQUEST)?;

    let stream = ss
        .iter()
        .find(|s| s.key.ssrc == ssrc)
        .ok_or(StatusCode::NOT_FOUND)?;

    let json_str = output::json::stream_to_json(stream);
    drop(ss);

    let parsed: Value =
        serde_json::from_str(&json_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/stats` — aggregate statistics across dialogs and streams.
async fn get_stats(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let total_dialogs = ds.len();
    let active_calls = ds.active_count();

    // Collect PDD values for percentile computation
    let mut pdd_values: Vec<i64> = ds.iter().filter_map(|d| d.timing.pdd_ms()).collect();
    pdd_values.sort_unstable();

    // Diagnosis counts
    let mut failed_count = 0usize;
    let mut completed_count = 0usize;
    let mut cancelled_count = 0usize;
    for d in ds.iter() {
        match d.state {
            DialogState::Failed => failed_count += 1,
            DialogState::Completed => completed_count += 1,
            DialogState::Cancelled => cancelled_count += 1,
            _ => {}
        }
    }
    drop(ds);

    let ss = state.stream_store.read();
    let total_streams = ss.len();
    let orphaned_count = ss.orphaned_count();
    drop(ss);

    let pdd_p50 = percentile(&pdd_values, 50);
    let pdd_p95 = percentile(&pdd_values, 95);
    let pdd_p99 = percentile(&pdd_values, 99);

    Ok(Json(json!({
        "schema_version": 1,
        "dialogs": {
            "total": total_dialogs,
            "active": active_calls,
            "completed": completed_count,
            "failed": failed_count,
            "cancelled": cancelled_count,
        },
        "streams": {
            "total": total_streams,
            "orphaned": orphaned_count,
        },
        "timing": {
            "pdd_p50_ms": pdd_p50,
            "pdd_p95_ms": pdd_p95,
            "pdd_p99_ms": pdd_p99,
        },
    })))
}

/// `GET /metrics` — Prometheus-compatible metrics endpoint.
///
/// Populates a `PrometheusMetrics` from the shared stores and formats
/// via `prometheus::format_metrics` for full metric coverage.
async fn get_metrics(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    guard(&state, &headers, addr.ip())?;

    let mut metrics = PrometheusMetrics::default();

    // Populate from dialog store
    let ds = state.dialog_store.read();
    for d in ds.iter() {
        let state_str = format!("{:?}", d.state).to_lowercase();
        *metrics.dialogs_total.entry(state_str).or_insert(0) += 1;

        // PDD histogram
        if let Some(pdd_ms) = d.timing.pdd_ms() {
            metrics.pdd_histogram.push(pdd_ms as f64 / 1000.0);
        }

        // Count messages by method
        *metrics.messages_total.entry(d.method.clone()).or_insert(0) += 1;
    }
    drop(ds);

    // Populate from stream store
    let ss = state.stream_store.read();
    let mut established = 0u64;
    let mut orphaned = 0u64;
    for s in ss.iter() {
        if s.orphaned {
            orphaned += 1;
        } else {
            established += 1;
        }
        metrics.mos_histogram.push(approximate_mos(s));
        metrics.jitter_histogram.push(s.jitter);
        let total = s.packet_count + s.lost_packets;
        if total > 0 {
            metrics
                .loss_histogram
                .push((s.lost_packets as f64 / total as f64) * 100.0);
        }
    }
    metrics.rtp_streams_active = established;
    metrics
        .rtp_streams_total
        .insert("established".to_string(), established);
    metrics
        .rtp_streams_total
        .insert("orphaned".to_string(), orphaned);
    drop(ss);

    let body = prometheus::format_metrics(&metrics);

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}

// ── Helper functions ────────────────────────────────────────────────

/// Build a JSON summary of a dialog (lighter than the full dialog_to_json).
fn dialog_summary(d: &crate::sip::dialog::SipDialog) -> Value {
    let duration_sec = if d.messages.len() >= 2 {
        (d.updated_at - d.created_at).num_milliseconds() as f64 / 1000.0
    } else {
        0.0
    };

    json!({
        "call_id": d.call_id,
        "from": d.from_user,
        "to": d.to_user,
        "state": format!("{:?}", d.state),
        "method": d.method,
        "duration_sec": duration_sec,
        "msg_count": d.messages.len(),
        "timing": {
            "pdd_ms": d.timing.pdd_ms(),
            "setup_ms": d.timing.setup_ms(),
            "retransmits": d.timing.total_retransmits(),
        },
        "created_at": d.created_at.to_rfc3339(),
        "updated_at": d.updated_at.to_rfc3339(),
    })
}

/// Build a JSON summary of an RTP stream.
fn stream_summary(s: &crate::rtp::stream::RtpStream) -> Value {
    let total = s.packet_count + s.lost_packets;
    let loss_pct = if total > 0 {
        (s.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    json!({
        "ssrc": format!("0x{:08x}", s.key.ssrc),
        "codec": s.codec,
        "src": s.key.src.to_string(),
        "dst": s.key.dst.to_string(),
        "packets": s.packet_count,
        "jitter_ms": s.jitter,
        "loss_pct": loss_pct,
        "orphaned": s.orphaned,
        "associated_dialog": s.associated_dialog,
        "mos": approximate_mos(s),
    })
}

/// Approximate MOS score from jitter and loss using the canonical E-model.
///
/// Delegates to `rtp::quality::estimate_mos` for a single MOS implementation.
fn approximate_mos(stream: &crate::rtp::stream::RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    quality::estimate_mos(stream.jitter, loss_pct, stream.codec.as_deref())
}

/// Compute the p-th percentile of a sorted slice.
///
/// Returns `None` if the slice is empty.
fn percentile(sorted: &[i64], p: u8) -> Option<i64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((p as f64 / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    Some(sorted[idx.min(sorted.len() - 1)])
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use crate::capture::parse::TransportProto;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_state() -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            api_key: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        }
    }

    fn make_state_with_key(key: &str) -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            api_key: Some(key.to_string()),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        }
    }

    use crate::test_utils::build_sip_message as build_sip;

    fn populate_dialogs(state: &ApiState) {
        let mut ds = state.dialog_store.write();
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap();
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        for i in 0..3 {
            let raw = build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    &format!("From: <sip:user{i}@example.com>;tag=t{i}"),
                    "To: <sip:bob@example.com>",
                    &format!("Call-ID: call-{i}@test"),
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            );
            let msg =
                crate::sip::parser::parse_sip(&raw, ts, localhost, localhost, 5060, 5060, TransportProto::Udp)
                    .expect("parse");
            ds.process_message(msg);
        }
    }

    /// Build a test request with the ConnectInfo extension set to localhost.
    fn test_request(uri: &str) -> Request<Body> {
        let mut req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("build request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                12345,
            )));
        req
    }

    /// Build a test request with custom headers and ConnectInfo.
    fn test_request_with_header(uri: &str, header_name: &str, header_value: &str) -> Request<Body> {
        let mut req = Request::builder()
            .uri(uri)
            .header(header_name, header_value)
            .body(Body::empty())
            .expect("build request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                12345,
            )));
        req
    }

    async fn body_to_string(body: Body) -> String {
        let bytes = body.collect().await.expect("collect body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[tokio::test]
    async fn health_check_returns_ok() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/health");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn list_dialogs_returns_json_array() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request("/v1/dialogs");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["dialogs"].is_array());
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 3);
        assert_eq!(parsed["total"], 3);
    }

    #[tokio::test]
    async fn get_dialog_by_call_id() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request("/v1/dialogs/call-1@test");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["call_id"], "call-1@test");
    }

    #[tokio::test]
    async fn get_nonexistent_dialog_returns_404() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/v1/dialogs/does-not-exist");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn stats_endpoint_returns_expected_fields() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request("/v1/stats");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert!(parsed["dialogs"].is_object());
        assert!(parsed["streams"].is_object());
        assert!(parsed["timing"].is_object());
        assert_eq!(parsed["dialogs"]["total"], 3);
        assert!(parsed["dialogs"]["active"].is_number());
        assert!(parsed["streams"]["orphaned"].is_number());
    }

    #[tokio::test]
    async fn auth_missing_key_returns_401() {
        let state = make_state_with_key("secret-key");
        let app = build_router(state);

        let req = test_request("/v1/dialogs");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_correct_key_returns_200() {
        let state = make_state_with_key("secret-key");
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request_with_header("/v1/dialogs", "Authorization", "Bearer secret-key");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pagination_offset_and_limit() {
        let state = make_state();
        populate_dialogs(&state); // 3 dialogs
        let app = build_router(state);

        let req = test_request("/v1/dialogs?offset=1&limit=1");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 1);
        assert_eq!(parsed["offset"], 1);
        assert_eq!(parsed["limit"], 1);
    }

    #[test]
    fn parse_bind_addr_port_only() {
        let addr = parse_bind_addr("8080").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn parse_bind_addr_colon_port() {
        let addr = parse_bind_addr(":9090").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9090)
        );
    }

    #[test]
    fn parse_bind_addr_full() {
        let addr = parse_bind_addr("0.0.0.0:8080").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 8080)
        );
    }

    #[test]
    fn parse_bind_addr_invalid() {
        assert!(parse_bind_addr("not-an-address").is_err());
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        let mut limiter = RateLimiter::new(5);
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

        for _ in 0..5 {
            assert!(limiter.check(ip));
        }
        // 6th should fail
        assert!(!limiter.check(ip));
    }

    #[tokio::test]
    async fn get_dialog_report_returns_report() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request("/v1/dialogs/call-1@test/report");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            body.contains("call_id") || body.contains("call-1@test"),
            "report should contain call_id, got: {body}"
        );
        assert!(parsed.is_object(), "report should be a JSON object");
    }

    #[tokio::test]
    async fn list_streams_returns_empty() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/v1/streams");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(parsed["streams"].is_array());
        assert_eq!(parsed["streams"].as_array().expect("array").len(), 0);
        assert_eq!(parsed["total"], 0);
    }

    #[tokio::test]
    async fn get_stream_not_found() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/v1/streams/0x12345678");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_metrics_returns_prometheus_format() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request("/metrics");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        assert!(
            body.contains("sipnab_"),
            "metrics should contain sipnab_ prefix, got: {body}"
        );
    }

    #[tokio::test]
    async fn auth_wrong_key_returns_401() {
        let state = make_state_with_key("correct-key");
        let app = build_router(state);

        let req = test_request_with_header("/v1/dialogs", "Authorization", "Bearer wrong-key");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limit_exceeded_returns_503() {
        // Create state with rate_limiter max_rps = 1
        let state = ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            api_key: None,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1))),
        };
        populate_dialogs(&state);

        // First request should succeed
        let app = build_router(state.clone());
        let req1 = test_request("/v1/dialogs");
        let resp1 = app.oneshot(req1).await.expect("oneshot");
        assert_eq!(resp1.status(), StatusCode::OK);

        // Second request from same IP should be rate-limited (503)
        let app2 = build_router(state);
        let req2 = test_request("/v1/dialogs");
        let resp2 = app2.oneshot(req2).await.expect("oneshot");
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn percentile_computation() {
        let values = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        // p50 with 10 elements: index = round(0.50 * 9) = round(4.5) = 5 -> 60
        assert_eq!(percentile(&values, 50), Some(60));
        assert_eq!(percentile(&values, 95), Some(100));
        assert_eq!(percentile(&[], 50), None);

        // Odd-length array: p50 of [10,20,30,40,50] -> index = round(0.50*4) = 2 -> 30
        let odd = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(&odd, 50), Some(30));
        assert_eq!(percentile(&odd, 0), Some(10));
        assert_eq!(percentile(&odd, 100), Some(50));
    }
}
