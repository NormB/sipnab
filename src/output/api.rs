// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! If a static `--api-key` and/or one or more HMAC signing keys
//! (`--api-signing-key`/`--api-signing-key-file`) are configured, all
//! endpoints (except `/health`) require `Authorization: Bearer <token>`.
//! Bearer values may be self-describing signed `s1.` tokens (with expiry,
//! signing-key rotation, and revocation via `--api-revoked-file`) or the
//! static API key. Missing or invalid credentials return 401. See
//! `crate::auth`.
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
use crate::rtp::diagnosis::{
    AsymmetryThresholds, CaptureMedia, MediaContext, diagnose_asymmetry, diagnose_media,
};
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
    /// Bearer-token verifier (signed tokens + static secrets + revocation).
    pub verifier: Arc<crate::auth::TokenVerifier>,
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
    ///
    /// # Arguments
    ///
    /// * `ip` — Source IP whose one-second window is checked.
    ///
    /// # Side effects
    ///
    /// Mutates the limiter: bumps the monotonic call counter, resets the
    /// per-IP window when >1 s has elapsed, increments the per-IP request
    /// count (even when the request ends up rejected), and every 100th call
    /// evicts buckets older than 2 s.
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

/// Per-request wall-clock cap. The API is request/response (no streaming), so a
/// blanket timeout is safe and stops a slow client from pinning a connection.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Max request body accepted (defense in depth; the API is GET-only today).
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Middleware: fail a request exceeding `REQUEST_TIMEOUT` with 408 rather than
/// letting it hold a connection slot indefinitely.
///
/// # Arguments
///
/// * `req` — The incoming request, forwarded unchanged to `next`.
/// * `next` — The rest of the middleware/handler chain.
///
/// # Returns
///
/// The inner handler's response, or `408 Request Timeout` if the handler
/// does not complete within `REQUEST_TIMEOUT`.
async fn request_timeout_mw(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

/// Build the axum `Router` with all API endpoints.
///
/// The returned router expects an `ApiState` to be supplied as shared state.
/// Every route is wrapped in the request-timeout middleware and a 1 MiB
/// body-size limit.
///
/// # Arguments
///
/// * `state` — Shared stores, verifier, and rate limiter for all handlers.
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
        // Request hardening on every route.
        .layer(axum::middleware::from_fn(request_timeout_mw))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

/// Parse a bind address string into a `SocketAddr`.
///
/// Accepts:
/// - `":8080"` or `"8080"` — binds to `127.0.0.1:8080` (D18 default)
/// - `"0.0.0.0:8080"` — binds to all interfaces
/// - Any valid `addr:port` pair
///
/// # Arguments
///
/// * `addr` — The bind address string from the CLI.
///
/// # Errors
///
/// Returns `crate::Error::InvalidBindAddr` (carrying the input and a
/// reason string) when the input is neither a bare port, a `:port`
/// shorthand, nor a valid `addr:port` pair.
pub fn parse_bind_addr(addr: &str) -> Result<SocketAddr, crate::Error> {
    output::parse_listen_addr(addr, "bind address")
}

/// Configuration for the API server.
#[derive(Debug, Clone, Default)]
pub struct ApiServerConfig {
    /// Maximum concurrently in-flight requests (0 = unlimited). Named for the
    /// `--api-max-conn` CLI flag, but `serve_on` holds the permit for the
    /// lifetime of a request, so it caps in-flight requests, not open TCP
    /// connections.
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
/// # Arguments
///
/// * `bind_addr` — Address to bind the TCP listener on.
/// * `state` — Shared stores, verifier, and rate limiter.
/// * `server_config` — Connection cap and (unsupported) TLS paths.
///
/// # Errors
///
/// Propagates every failure from `prepare_listener` (TLS flags supplied,
/// unauthenticated non-loopback bind, bind failure) and `serve_on`.
///
/// # Side effects
///
/// Binds a TCP listener and serves HTTP until shutdown; logs a warning if
/// the bind address is non-loopback without TLS.
pub async fn run_server(
    bind_addr: SocketAddr,
    state: ApiState,
    server_config: ApiServerConfig,
) -> Result<(), crate::Error> {
    let listener = prepare_listener(bind_addr, &state.verifier, &server_config)?;
    serve_on(listener, state, server_config).await
}

/// Vet the API configuration and bind its listener synchronously, so
/// configuration and bind errors (port in use, unauthenticated non-loopback
/// bind, unsupported TLS flags) surface on the caller's thread BEFORE the TUI
/// takes over the terminal — logged from the detached servers thread they are
/// invisible.
///
/// # Arguments
///
/// * `bind_addr` — Requested listen address.
/// * `verifier` — Used to decide whether the bind-auth policy is satisfied.
/// * `server_config` — Checked for the (unsupported) TLS flags.
///
/// # Returns
///
/// The bound, non-blocking `std::net::TcpListener` ready for `serve_on`.
///
/// # Errors
///
/// Returns `crate::Error::Server` when TLS flags are supplied (not yet
/// integrated), when the bind is non-loopback with no authentication
/// configured, or when binding/configuring the listener fails.
///
/// # Side effects
///
/// Binds the OS socket and logs a warning for a non-loopback bind without
/// TLS.
pub fn prepare_listener(
    bind_addr: SocketAddr,
    verifier: &crate::auth::TokenVerifier,
    server_config: &ApiServerConfig,
) -> Result<std::net::TcpListener, crate::Error> {
    let has_tls = server_config.tls_cert.is_some() && server_config.tls_key.is_some();

    if has_tls {
        return Err(crate::Error::Server(
            "API TLS (--api-tls-cert/--api-tls-key) requires the axum-server crate \
             which is not yet integrated. Use a TLS-terminating reverse proxy instead."
                .to_string(),
        ));
    }

    enforce_bind_auth_policy(&bind_addr, verifier)?;
    if !bind_addr.ip().is_loopback() {
        tracing::warn!(
            "API server binding to non-loopback address {} without TLS — \
             consider using 127.0.0.1 or enabling TLS",
            bind_addr
        );
    }

    let listener = std::net::TcpListener::bind(bind_addr)
        .map_err(|e| crate::Error::Server(format!("failed to bind API to {bind_addr}: {e}")))?;
    // tokio's from_std requires the listener to be non-blocking already.
    listener
        .set_nonblocking(true)
        .map_err(|e| crate::Error::Server(format!("failed to configure the API listener: {e}")))?;
    Ok(listener)
}

/// Serve the REST API on an already-bound listener from `prepare_listener`.
///
/// # Arguments
///
/// * `listener` — Bound, non-blocking listener to serve on.
/// * `state` — Shared stores, verifier, and rate limiter.
/// * `server_config` — `max_conn > 0` adds a semaphore middleware that caps
///   concurrently in-flight requests, answering 503 once that many are being
///   handled at once. Despite the `max_conn` name, the permit is held for the
///   duration of a request (not a TCP connection), so it bounds in-flight
///   requests, not open connections.
///
/// # Errors
///
/// Returns `crate::Error::Server` if the listener cannot be registered with
/// tokio or the axum server itself fails.
///
/// # Side effects
///
/// Runs the HTTP accept loop until shutdown (never returns `Ok` before
/// then) and logs the actual bound address at startup.
pub async fn serve_on(
    listener: std::net::TcpListener,
    state: ApiState,
    server_config: ApiServerConfig,
) -> Result<(), crate::Error> {
    let max_inflight = server_config.max_conn;
    let router = build_router(state);

    // Wrap with an in-flight-request limiter if the cap is enabled. The
    // semaphore permit is held for the whole request, so it bounds requests
    // in flight, not open TCP connections.
    let router = if max_inflight > 0 {
        let inflight_limiter = Arc::new(tokio::sync::Semaphore::new(max_inflight as usize));
        tracing::info!("API server max in-flight requests: {}", max_inflight);
        router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let sem = Arc::clone(&inflight_limiter);
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

    let listener = tokio::net::TcpListener::from_std(listener)
        .map_err(|e| crate::Error::Server(format!("failed to register the API listener: {e}")))?;

    // Log the *actual* bound address: with port 0 the OS assigns an ephemeral
    // port, so logging the requested address would print ":0". Matches the
    // MCP HTTP server.
    match listener.local_addr() {
        Ok(addr) => tracing::info!("REST API listening on {}", addr),
        Err(_) => tracing::info!("REST API listening"),
    }

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| crate::Error::Server(format!("API server error: {e}")))
}

// ── Auth + rate-limit helpers ───────────────────────────────────────

/// Refuse to start a non-loopback bind when no authentication is configured,
/// matching the MCP HTTP transport's rule. A public, unauthenticated REST API
/// would expose all captured SIP/RTP metadata to anyone who can reach the port.
///
/// # Arguments
///
/// * `bind_addr` — Requested listen address.
/// * `verifier` — Consulted for whether any credential is configured.
///
/// # Errors
///
/// Returns `crate::Error::Server` with remediation guidance when the bind
/// is non-loopback and the verifier has no keys configured.
fn enforce_bind_auth_policy(
    bind_addr: &SocketAddr,
    verifier: &crate::auth::TokenVerifier,
) -> Result<(), crate::Error> {
    if !bind_addr.ip().is_loopback() && verifier.is_unconfigured() {
        return Err(crate::Error::Server(format!(
            "REST API refuses to start: --api {bind_addr} is non-loopback but no \
             --api-key / SIPNAB_API_KEY or --api-signing-key / SIPNAB_API_SIGNING_KEY \
             was supplied. Bind 127.0.0.1, or configure authentication."
        )));
    }
    Ok(())
}

/// Check authentication. Returns `Err(StatusCode)` if auth fails.
///
/// # Arguments
///
/// * `state` — Holds the token verifier.
/// * `headers` — Request headers; the `Authorization` header is inspected.
///
/// # Returns
///
/// `Ok(())` when auth is unconfigured (disabled) or a valid
/// `Bearer <token>` credential is presented; `Err(401 UNAUTHORIZED)` for a
/// missing, non-ASCII, non-Bearer, or unverifiable credential.
fn check_auth(
    state: &ApiState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<(), StatusCode> {
    // No signing keys and no static secret configured ⇒ auth disabled
    // (loopback-allowed behavior unchanged from before this feature).
    if state.verifier.is_unconfigured() {
        return Ok(());
    }

    let Some(auth_header) = headers.get("authorization") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    if let Some(token) = auth_str.strip_prefix("Bearer ")
        && state
            .verifier
            .verify(token, chrono::Utc::now().timestamp(), required_scope)
    {
        return Ok(());
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Check rate limit. Returns `Err(StatusCode)` if over limit.
///
/// # Arguments
///
/// * `state` — Holds the shared per-IP rate limiter.
/// * `ip` — Client IP charged for this request.
///
/// # Returns
///
/// `Ok(())` under the limit; `Err(503 SERVICE_UNAVAILABLE)` when over.
///
/// # Side effects
///
/// Takes the rate-limiter mutex and mutates its per-IP counters (see
/// `RateLimiter::check`).
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
///
/// # Returns
///
/// `Ok(())` when both checks pass; `Err(503)` when the client IP is over its
/// request budget (checked first, so every request — including one that will
/// fail auth — is charged, throttling brute-force of the Bearer token); or
/// `Err(401)` on auth failure.
///
/// # Side effects
///
/// Mutates the shared rate limiter via `check_rate_limit`.
fn guard(state: &ApiState, headers: &HeaderMap, client_ip: IpAddr) -> Result<(), StatusCode> {
    // SCOPE_FULL is the default on purpose: it is the RESTRICTIVE direction.
    // A `full` token satisfies every requirement, so demanding `full` admits
    // only full tokens, while demanding `metrics` would admit both. A route
    // added later and wired to this function therefore inherits "full tokens
    // only" rather than quietly accepting a scrape-only credential.
    guard_scoped(state, headers, client_ip, crate::auth::SCOPE_FULL)
}

/// [`guard`], with the scope a caller demands stated explicitly.
///
/// # Arguments
///
/// * `state` — holds the rate limiter and token verifier.
/// * `headers` — request headers; the `Authorization` header is inspected.
/// * `client_ip` — peer address, charged to the per-IP rate budget.
/// * `required_scope` — [`crate::auth::SCOPE_FULL`] or
///   [`crate::auth::SCOPE_METRICS`].
///
/// # Errors
///
/// `429` when over the rate budget, `401` when the credential is missing,
/// malformed, unverifiable, or scoped too narrowly for this route.
///
/// # Side effects
///
/// Mutates the shared rate limiter via `check_rate_limit`.
fn guard_scoped(
    state: &ApiState,
    headers: &HeaderMap,
    client_ip: IpAddr,
    required_scope: &str,
) -> Result<(), StatusCode> {
    // Rate-limit BEFORE authenticating: if auth ran first, a wrong-token
    // request would 401 without ever touching the limiter, letting an
    // attacker brute-force the token at unlimited speed. Charging every
    // request to the per-IP budget throttles that flood.
    check_rate_limit(state, client_ip)?;
    check_auth(state, headers, required_scope)
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /health` — always returns "ok" (200), no auth or rate limit.
async fn health_check() -> &'static str {
    "ok"
}

/// `GET /v1/dialogs` — list dialogs with optional filtering and pagination.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — Offset/limit pagination plus `state` (case-insensitive
///   exact match) and `from` (regex, invalid patterns silently ignored)
///   filters.
///
/// # Returns
///
/// 200 with `{schema_version, total, offset, limit, dialogs}` where
/// `total` is the FILTERED result-set size (the count the returned rows are
/// drawn from, after `state`/`from` filters), so paging by `total`
/// terminates correctly; 401/503 from the guard. `limit` is clamped to 1000.
///
/// # Side effects
///
/// Holds the dialog-store read lock while filtering; mutates the rate
/// limiter.
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
    // Materialize the FILTERED set first so `total` reflects what the page is
    // drawn from. Reporting the unfiltered store size here would break
    // pagination: a client paging by `total` over a narrower filtered result
    // would request empty pages past the real end.
    let filtered: Vec<&crate::sip::dialog::SipDialog> = ds
        .iter()
        .filter(|d| {
            if let Some(sf) = state_filter {
                let state_str = d.state().to_string();
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
        .collect();

    let total = filtered.len();
    let dialogs: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|&d| dialog_summary(d))
        .collect();
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
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `call_id` — Call-ID path segment identifying the dialog.
///
/// # Returns
///
/// 200 with the full `dialog_to_json` object (including associated
/// streams and a freshly computed media/asymmetry diagnosis); 404 when the
/// Call-ID is unknown; 500 if the JSON round-trip fails; 401/503 from the
/// guard.
///
/// # Side effects
///
/// Holds the dialog- and stream-store read locks while building the
/// response; mutates the rate limiter.
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
    let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&call_id).collect();

    let media = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
    let mut diagnosis = diagnose_media(&streams, &media);
    diagnose_asymmetry(
        &mut diagnosis,
        Some(dialog),
        &streams,
        &AsymmetryThresholds::default(),
    );
    let json_str = output::json::dialog_to_json(dialog, &streams, &diagnosis);
    drop(ss);
    drop(ds);

    let parsed: Value =
        serde_json::from_str(&json_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/dialogs/:call_id/report` — get a call report in JSON format.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `call_id` — Call-ID path segment identifying the dialog.
///
/// # Returns
///
/// 200 with the JSON-format `generate_call_report` output; 404 when the
/// Call-ID is unknown; 500 if the report is not valid JSON; 401/503 from
/// the guard.
///
/// # Side effects
///
/// Holds the dialog- and stream-store read locks while building the
/// report; mutates the rate limiter.
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
    let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&call_id).collect();

    let media = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
    let mut diagnosis = diagnose_media(&streams, &media);
    diagnose_asymmetry(
        &mut diagnosis,
        Some(dialog),
        &streams,
        &AsymmetryThresholds::default(),
    );
    let report =
        output::generate_call_report(dialog, &streams, &diagnosis, output::ReportFormat::Json);
    drop(ss);
    drop(ds);

    let parsed: Value =
        serde_json::from_str(&report).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/streams` — list RTP streams with optional filtering and pagination.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — Offset/limit pagination plus `orphaned` (exact match) and
///   `mos_below` (streams whose estimated MOS is strictly below the
///   threshold) filters.
///
/// # Returns
///
/// 200 with `{schema_version, total, offset, limit, streams}` where
/// `total` is the FILTERED result-set size (the count the returned rows are
/// drawn from, after `orphaned`/`mos_below` filters), so paging by `total`
/// terminates correctly; 401/503 from the guard. `limit` is clamped to 1000.
///
/// # Side effects
///
/// Holds the stream-store read lock while filtering; mutates the rate
/// limiter.
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
    // Materialize the FILTERED set first so `total` reflects what the page is
    // drawn from (see `list_dialogs`); the unfiltered store size would break a
    // client paging by `total`.
    let filtered: Vec<&crate::rtp::stream::RtpStream> = ss
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
        .collect();

    let total = filtered.len();
    let streams: Vec<Value> = filtered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|&s| stream_summary(s))
        .collect();
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
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `id` — SSRC as hex, with or without a `0x` prefix.
///
/// # Returns
///
/// 200 with the `stream_to_json` object; 400 for a non-hex id; 404 when no
/// stream has that SSRC; 500 if the JSON round-trip fails; 401/503 from
/// the guard.
///
/// # Side effects
///
/// Holds the stream-store read lock during lookup; mutates the rate
/// limiter.
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

    // SSRC is not unique (the stream key is ssrc + src + dst), so several
    // streams can share it. Return the most-active one deterministically
    // instead of an arbitrary first match, so a colliding orphan doesn't
    // shadow the real media stream.
    let stream = ss
        .iter()
        .filter(|s| s.key.ssrc == ssrc)
        .max_by_key(|s| s.packet_count)
        .ok_or(StatusCode::NOT_FOUND)?;

    let json_str = output::json::stream_to_json(stream);
    drop(ss);

    let parsed: Value =
        serde_json::from_str(&json_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/stats` — aggregate statistics across dialogs and streams.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
///
/// # Returns
///
/// 200 with `{schema_version, dialogs{total,active,completed,failed,
/// cancelled}, streams{total,orphaned}, timing{pdd_p50_ms,pdd_p95_ms,
/// pdd_p99_ms}}`; the percentiles are `null` when no dialog has a PDD.
/// 401/503 from the guard.
///
/// # Side effects
///
/// Takes the dialog- then stream-store read locks (sequentially, not
/// overlapping); mutates the rate limiter.
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
        match d.state() {
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
/// Populates a `PrometheusMetrics` from the process-wide capture counters
/// (`PrometheusMetrics::for_scrape`) plus the shared stores, and formats via
/// `prometheus::format_metrics` for full metric coverage. The per-dialog
/// media diagnosis is computed here, so scrape cost scales with the number
/// of tracked dialogs (bounded by `-l`/`--limit`).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
///
/// # Returns
///
/// 200 with a `text/plain; version=0.0.4; charset=utf-8` body in
/// Prometheus text exposition format; 401/503 from the guard.
///
/// # Side effects
///
/// Takes the dialog- then stream-store read locks (both held while the
/// per-dialog diagnosis is computed, in the same order as every other
/// handler); mutates the rate limiter.
async fn get_metrics(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // The only route a SCOPE_METRICS token reaches. A `full` token still works
    // here — full satisfies every requirement — so this narrows nothing for an
    // existing deployment.
    guard_scoped(&state, &headers, addr.ip(), crate::auth::SCOPE_METRICS)?;

    // `for_scrape`, never `default`: it loads the counters the capture path
    // and the alerting engine feed, and initializes the closed label sets so
    // a rule over an unseen response class reads zero rather than no-data.
    let mut metrics = PrometheusMetrics::for_scrape();

    // Populate from dialog store. The stream store is read alongside it (in
    // that order, matching every other handler) because the per-dialog media
    // diagnosis needs both.
    let ds = state.dialog_store.read();
    let ss = state.stream_store.read();
    let capture_media = CaptureMedia::of_store(&ss);
    for d in ds.iter() {
        let state_str = d.state().to_string().to_lowercase();
        *metrics.dialogs_total.entry(state_str).or_insert(0) += 1;

        // PDD histogram
        if let Some(pdd_ms) = d.timing.pdd_ms() {
            metrics.pdd_histogram.push(pdd_ms as f64 / 1000.0);
        }

        // Count SIP messages by dialog method (matching the standalone
        // metrics server): the metric is named messages_total, so it counts
        // messages, not dialogs — `+= 1` here undercounted every multi-message
        // dialog and disagreed with the /metrics server's value.
        *metrics
            .messages_total
            .entry(d.method.to_string())
            .or_insert(0) += d.messages.len() as u64;

        for msg in &d.messages {
            if let Some(code) = msg.status_code {
                metrics.record_response(code);
            }
        }

        let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
            ss.streams_for(&d.call_id).collect();
        let media = MediaContext::for_dialog(d, capture_media);
        metrics.record_media_diagnosis(&diagnose_media(&dialog_streams, &media));
    }
    drop(ds);

    // Populate from stream store
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
///
/// Projects through the canonical `crate::output::model::DialogSummary`
/// so this endpoint cannot drift from the CLI/MCP surfaces. WS3 wire
/// change: the `from`/`to` keys became `from_user`/`to_user` (they always
/// carried the URI user parts). Returns an `{"error": ...}` object if
/// serialization fails.
fn dialog_summary(d: &crate::sip::dialog::SipDialog) -> Value {
    serde_json::to_value(crate::output::model::DialogSummary::from(d))
        .unwrap_or_else(|e| json!({"error": format!("serialization failed: {e}")}))
}

/// Build a JSON summary of an RTP stream via the canonical
/// `crate::output::model::StreamSummary` projection. Returns an
/// `{"error": ...}` object if serialization fails.
fn stream_summary(s: &crate::rtp::stream::RtpStream) -> Value {
    serde_json::to_value(crate::output::model::StreamSummary::from(s))
        .unwrap_or_else(|e| json!({"error": format!("serialization failed: {e}")}))
}

/// Approximate MOS score from jitter and loss using the canonical E-model.
///
/// Delegates to `rtp::quality::estimate_mos` for a single MOS
/// implementation; loss is computed as `lost / (received + lost)` (0.0 for
/// an empty stream).
fn approximate_mos(stream: &crate::rtp::stream::RtpStream) -> f64 {
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    quality::estimate_mos(stream.jitter, loss_pct, stream.codec.as_deref())
}

/// Compute the p-th percentile of a sorted slice (nearest-rank by rounded
/// index).
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

/// Router-level tests: each spins up the axum router with `oneshot`
/// requests against in-memory stores, plus unit tests for the auth guard,
/// rate limiter, bind-address parsing, and summary helpers.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// Build an `ApiState` with empty stores and no auth configured.
    fn make_state() -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig::default(),
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        }
    }

    /// Build an `ApiState` whose verifier accepts only the given static key.
    fn make_state_with_key(key: &str) -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    static_keys: vec![key.to_string()],
                    ..Default::default()
                },
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        }
    }

    /// Bind-auth policy: public bind without auth refused, loopback and
    /// authenticated public binds allowed.
    #[test]
    fn refuses_non_loopback_bind_without_auth() {
        use std::net::{IpAddr, Ipv4Addr};
        let public: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080);
        let loopback: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);

        // Public bind with no auth configured → refuse to start.
        let unconfigured = make_state();
        assert!(enforce_bind_auth_policy(&public, &unconfigured.verifier).is_err());
        // Loopback with no auth → allowed (unchanged behavior).
        assert!(enforce_bind_auth_policy(&loopback, &unconfigured.verifier).is_ok());
        // Public bind WITH auth → allowed.
        let configured = make_state_with_key("supersecret");
        assert!(enforce_bind_auth_policy(&public, &configured.verifier).is_ok());
    }

    use crate::test_utils::build_sip_message as build_sip;

    /// Insert three INVITE dialogs (`call-0..2@test`, users `user0..2`)
    /// into the state's dialog store.
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
            let msg = crate::sip::parser::parse_sip(
                &raw,
                ts,
                localhost,
                localhost,
                5060,
                5060,
                TransportProto::Udp,
            )
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
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
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
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            12345,
        )));
        req
    }

    /// Collect a response `Body` into a UTF-8 `String`.
    async fn body_to_string(body: Body) -> String {
        let bytes = body.collect().await.expect("collect body").to_bytes();
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    /// `GET /health` returns 200 with the literal body "ok".
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

    /// `GET /v1/dialogs` returns 200 with all three seeded dialogs and the
    /// pagination envelope.
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

    /// `GET /v1/dialogs/:call_id` returns 200 with the matching dialog's
    /// full JSON.
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

    /// An unknown Call-ID yields 404 Not Found.
    #[tokio::test]
    async fn get_nonexistent_dialog_returns_404() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/v1/dialogs/does-not-exist");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `GET /v1/stats` returns 200 with dialogs/streams/timing objects and
    /// correct dialog totals.
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

    /// With a static key configured, a request without credentials gets 401.
    #[tokio::test]
    async fn auth_missing_key_returns_401() {
        let state = make_state_with_key("secret-key");
        let app = build_router(state);

        let req = test_request("/v1/dialogs");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// The correct static Bearer key authenticates and gets 200.
    #[tokio::test]
    async fn auth_correct_key_returns_200() {
        let state = make_state_with_key("secret-key");
        populate_dialogs(&state);
        let app = build_router(state);

        let req = test_request_with_header("/v1/dialogs", "Authorization", "Bearer secret-key");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Build an `ApiState` whose verifier accepts tokens signed with `key`.
    fn make_state_with_signing_key(key: &[u8]) -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    signing_keys: vec![key.to_vec()],
                    audience: crate::auth::AUDIENCE_API.to_string(),
                    ..Default::default()
                },
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
        }
    }

    /// A signed token with a future expiry authenticates and gets 200.
    #[tokio::test]
    async fn auth_valid_signed_token_returns_200() {
        let key = b"router-signing-key";
        let state = make_state_with_signing_key(key);
        populate_dialogs(&state);
        let app = build_router(state);
        // exp far in the future.
        let token = crate::auth::mint(
            key,
            "id1",
            chrono::Utc::now().timestamp() + 3600,
            crate::auth::AUDIENCE_API,
            crate::auth::SCOPE_FULL,
        );
        let req =
            test_request_with_header("/v1/dialogs", "Authorization", &format!("Bearer {token}"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A signed token whose expiry is in the past is rejected with 401.
    #[tokio::test]
    async fn auth_expired_signed_token_returns_401() {
        let key = b"router-signing-key";
        let state = make_state_with_signing_key(key);
        let app = build_router(state);
        // exp already in the past — deterministic, no sleeping.
        let token = crate::auth::mint(
            key,
            "id1",
            chrono::Utc::now().timestamp() - 1,
            crate::auth::AUDIENCE_API,
            crate::auth::SCOPE_FULL,
        );
        let req =
            test_request_with_header("/v1/dialogs", "Authorization", &format!("Bearer {token}"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A token signed with the wrong key is rejected with 401.
    #[tokio::test]
    async fn auth_forged_signed_token_returns_401() {
        let key = b"router-signing-key";
        let state = make_state_with_signing_key(key);
        let app = build_router(state);
        // Signed by a different key.
        let token = crate::auth::mint(
            b"other-key",
            "id1",
            chrono::Utc::now().timestamp() + 3600,
            crate::auth::AUDIENCE_API,
            crate::auth::SCOPE_FULL,
        );
        let req =
            test_request_with_header("/v1/dialogs", "Authorization", &format!("Bearer {token}"));
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// `offset`/`limit` query params page the dialog list (1 of 3 returned).
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

    /// A bare port string binds to `127.0.0.1:<port>`.
    #[test]
    fn parse_bind_addr_port_only() {
        let addr = parse_bind_addr("8080").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8080)
        );
    }

    /// The `:port` shorthand binds to `127.0.0.1:<port>`.
    #[test]
    fn parse_bind_addr_colon_port() {
        let addr = parse_bind_addr(":9090").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9090)
        );
    }

    /// A full `addr:port` pair parses verbatim.
    #[test]
    fn parse_bind_addr_full() {
        let addr = parse_bind_addr("0.0.0.0:8080").expect("parse");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 8080)
        );
    }

    /// A non-address string is rejected.
    #[test]
    fn parse_bind_addr_invalid() {
        assert!(parse_bind_addr("not-an-address").is_err());
    }

    /// A limiter with max 5 allows exactly 5 requests, then rejects the 6th.
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

    /// `GET /v1/dialogs/:call_id/report` returns 200 with a JSON report
    /// object referencing the call.
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

    /// `GET /v1/streams` on an empty store returns 200 with an empty array
    /// and total 0.
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

    /// A valid-hex but unknown SSRC yields 404 Not Found.
    #[tokio::test]
    async fn get_stream_not_found() {
        let state = make_state();
        let app = build_router(state);

        let req = test_request("/v1/streams/0x12345678");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// `sipnab_messages_total` counts SIP messages (matching the standalone
    /// metrics server), not dialogs: one dialog with two messages reports 2.
    #[tokio::test]
    async fn metrics_messages_total_counts_messages_not_dialogs() {
        let state = make_state();
        {
            let mut ds = state.dialog_store.write();
            let ts =
                chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap();
            let lo = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            let msgs = [
                build_sip(
                    "INVITE sip:bob@example.com SIP/2.0",
                    &[
                        "From: <sip:a@example.com>;tag=1",
                        "To: <sip:bob@example.com>",
                        "Call-ID: mt@test",
                        "CSeq: 1 INVITE",
                        "Content-Length: 0",
                    ],
                    b"",
                ),
                build_sip(
                    "SIP/2.0 200 OK",
                    &[
                        "From: <sip:a@example.com>;tag=1",
                        "To: <sip:bob@example.com>;tag=2",
                        "Call-ID: mt@test",
                        "CSeq: 1 INVITE",
                        "Content-Length: 0",
                    ],
                    b"",
                ),
            ];
            for raw in msgs {
                let msg = crate::sip::parser::parse_sip(
                    &raw,
                    ts,
                    lo,
                    lo,
                    5060,
                    5060,
                    TransportProto::Udp,
                )
                .expect("parse");
                ds.process_message(msg);
            }
        }

        let app = build_router(state);
        let resp = app
            .oneshot(test_request("/metrics"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        assert!(
            body.contains("sipnab_messages_total{method=\"INVITE\"} 2"),
            "expected 2 messages, got:\n{body}"
        );
    }

    /// `GET /metrics` returns 200 with `sipnab_`-prefixed exposition text.
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

    /// A wrong static Bearer key is rejected with 401.
    #[tokio::test]
    async fn auth_wrong_key_returns_401() {
        let state = make_state_with_key("correct-key");
        let app = build_router(state);

        let req = test_request_with_header("/v1/dialogs", "Authorization", "Bearer wrong-key");

        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// With max 1 request/second, the second request from the same IP gets
    /// 503 Service Unavailable.
    #[tokio::test]
    async fn rate_limit_exceeded_returns_503() {
        // Create state with rate_limiter max_rps = 1
        let state = ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig::default(),
            )),
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

    /// A flood of requests bearing a wrong token must eventually be
    /// rate-limited (503), not answered with an unbounded stream of 401s —
    /// otherwise the Bearer token can be brute-forced at unlimited speed
    /// because failed auth never consumes the per-IP budget.
    #[test]
    fn guard_rate_limits_failed_auth_flood() {
        let mut state = make_state_with_key("correct-secret");
        // Tiny per-IP budget so the flood trips the limiter quickly.
        state.rate_limiter = Arc::new(Mutex::new(RateLimiter::new(3)));

        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer wrong-token".parse().unwrap());

        let mut saw_rate_limit = false;
        for _ in 0..25 {
            match guard(&state, &headers, ip) {
                Err(StatusCode::SERVICE_UNAVAILABLE) => {
                    saw_rate_limit = true;
                    break;
                }
                Err(StatusCode::UNAUTHORIZED) => {} // still under budget
                other => panic!("unexpected guard result: {other:?}"),
            }
        }
        assert!(
            saw_rate_limit,
            "failed-auth flood must eventually be throttled with 503"
        );
    }

    /// Percentile picks the rounded nearest-rank index for even- and
    /// odd-length inputs, and `None` for empty.
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

    // ── Stream-store helpers ──────────────────────────────────────────

    /// Insert one RTP stream into the store via `process_rtp`.
    ///
    /// Returns after a single packet so the stream exists with `packet_count`
    /// of at least 1 and no loss/jitter (MOS near the codec ceiling).
    fn add_stream(state: &ApiState, ssrc: u32, src_port: u16, dst_port: u16) {
        use crate::capture::parse::TransportProto;
        use crate::rtp::parser::RtpHeader;

        let parsed = crate::capture::ParsedPacket {
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("ts"),
            src_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            transport: TransportProto::Udp,
            payload: vec![0u8; 12 + 160].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0, // PCMU
            sequence: 1,
            timestamp: 160,
            ssrc,
            payload_offset: 12,
        };
        let mut ss = state.stream_store.write();
        ss.process_rtp(&parsed, &rtp, parsed.timestamp);
    }

    // ── list_streams branches ─────────────────────────────────────────

    /// `GET /v1/streams` returns both inserted streams with summary fields
    /// (`ssrc`, `mos`, `loss_pct`).
    #[tokio::test]
    async fn list_streams_returns_populated() {
        let state = make_state();
        add_stream(&state, 0x1111_1111, 20000, 30000);
        add_stream(&state, 0x2222_2222, 20002, 30002);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/streams"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["total"], 2);
        assert_eq!(parsed["streams"].as_array().expect("array").len(), 2);
        // stream_summary fields
        let first = &parsed["streams"][0];
        assert!(first["ssrc"].as_str().expect("ssrc").starts_with("0x"));
        assert!(first["mos"].is_number());
        assert!(first["loss_pct"].is_number());
    }

    /// `orphaned=true` filters out non-orphaned streams and `total` reflects
    /// the filtered result-set (0 here), not the store size.
    #[tokio::test]
    async fn list_streams_orphaned_filter_excludes_active() {
        let state = make_state();
        add_stream(&state, 0x3333_3333, 21000, 31000);
        let app = build_router(state);

        // Streams created here are not orphaned; filtering orphaned=true yields none.
        let resp = app
            .oneshot(test_request("/v1/streams?orphaned=true"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["streams"].as_array().expect("array").len(), 0);
        // total reflects the filtered result-set (0), not the store's 1.
        assert_eq!(parsed["total"], 0);
    }

    /// `mos_below` excludes a clean high-MOS stream at 1.0 and includes it
    /// at 5.0.
    #[tokio::test]
    async fn list_streams_mos_below_filter() {
        let state = make_state();
        add_stream(&state, 0x4444_4444, 22000, 32000);
        let app = build_router(state);

        // A clean stream has high MOS; mos_below=1.0 should exclude it.
        let resp = app
            .oneshot(test_request("/v1/streams?mos_below=1.0"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["streams"].as_array().expect("array").len(), 0);

        // A generous threshold should include it.
        let state2 = make_state();
        add_stream(&state2, 0x4444_4444, 22000, 32000);
        let app2 = build_router(state2);
        let resp2 = app2
            .oneshot(test_request("/v1/streams?mos_below=5.0"))
            .await
            .expect("oneshot");
        let body2 = body_to_string(resp2.into_body()).await;
        let parsed2: Value = serde_json::from_str(&body2).expect("valid JSON");
        assert_eq!(parsed2["streams"].as_array().expect("array").len(), 1);
    }

    // ── get_stream branches ───────────────────────────────────────────

    /// A `0x`-prefixed SSRC hex id resolves to its stream (200).
    #[tokio::test]
    async fn get_stream_found_by_hex() {
        let state = make_state();
        add_stream(&state, 0x1234_5678, 23000, 33000);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/streams/0x12345678"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(parsed.is_object());
    }

    /// When several streams share an SSRC (endpoint collision), the detail
    /// endpoint returns the most-active one deterministically, not the
    /// arbitrary first-inserted stream.
    #[tokio::test]
    async fn get_stream_ssrc_collision_returns_most_active() {
        use crate::capture::parse::TransportProto;
        use crate::rtp::parser::RtpHeader;

        let state = make_state();
        // Stream A: same SSRC, one packet, inserted first.
        add_stream(&state, 0x1234, 20000, 30000);
        // Stream B: same SSRC, different endpoint, five packets.
        {
            let mut ss = state.stream_store.write();
            for seq in 1..=5u16 {
                let parsed = crate::capture::ParsedPacket {
                    timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
                    src_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20001,
                    dst_port: 30001,
                    transport: TransportProto::Udp,
                    payload: vec![0u8; 12 + 160].into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                    from_hep: false,
                };
                let rtp = RtpHeader {
                    version: 2,
                    padding: false,
                    extension: false,
                    csrc_count: 0,
                    marker: false,
                    payload_type: 0,
                    sequence: seq,
                    timestamp: seq as u32 * 160,
                    ssrc: 0x1234,
                    payload_offset: 12,
                };
                ss.process_rtp(&parsed, &rtp, parsed.timestamp);
            }
        }

        let app = build_router(state);
        let resp = app
            .oneshot(test_request("/v1/streams/0x1234"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let v: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(
            v["packets"].as_u64().expect("packets"),
            5,
            "collision must resolve to the most-active (5-packet) stream, not the 1-packet one"
        );
    }

    /// A bare hex SSRC (no `0x` prefix) also resolves (200).
    #[tokio::test]
    async fn get_stream_found_without_0x_prefix() {
        let state = make_state();
        add_stream(&state, 0x0000_ABCD, 24000, 34000);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/streams/0000abcd"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A non-hex stream id yields 400 Bad Request.
    #[tokio::test]
    async fn get_stream_invalid_hex_returns_400() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/streams/not-hex-zz"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── get_dialog with associated streams (full detail path) ─────────

    /// `GET /v1/dialogs/:call_id` still returns 200 when a linked RTP
    /// stream exercises the full-detail (streams + diagnosis) path.
    #[tokio::test]
    async fn get_dialog_includes_associated_streams() {
        let state = make_state();
        populate_dialogs(&state);
        // Associate a stream with call-1@test by linking on its media address.
        add_stream(&state, 0x5555_5555, 25000, 35000);
        {
            let mut ss = state.stream_store.write();
            ss.link_to_dialog(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                25000,
                "call-1@test",
            );
        }
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/call-1@test"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["call_id"], "call-1@test");
    }

    // ── list_dialogs filters ──────────────────────────────────────────

    /// A case-insensitive `state` filter matching all dialogs returns all 3.
    #[tokio::test]
    async fn list_dialogs_state_filter_matches() {
        let state = make_state();
        populate_dialogs(&state); // all INVITE dialogs are in "Trying" state
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?state=trying"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 3);
    }

    /// A `state` filter matching nothing returns an empty page and a filtered
    /// total of 0 (so a client paging by `total` stops immediately).
    #[tokio::test]
    async fn list_dialogs_state_filter_excludes() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?state=Completed"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 0);
        // total reflects the filtered result-set (0), not the store's 3.
        assert_eq!(parsed["total"], 0);
    }

    /// A `from` regex filter selects the single matching dialog and the
    /// canonical `from_user` key carries the user part.
    #[tokio::test]
    async fn list_dialogs_from_regex_filter() {
        let state = make_state();
        populate_dialogs(&state); // from users: user0, user1, user2
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?from=user1"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 1);
        // WS3 canonical key (was "from" before the projection unification).
        assert_eq!(parsed["dialogs"][0]["from_user"], "user1");
    }

    /// An uncompilable `from` regex is ignored (no filtering, still 200).
    #[tokio::test]
    async fn list_dialogs_invalid_from_regex_is_ignored() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        // An invalid regex fails to compile -> from_regex is None -> no filtering.
        let resp = app
            .oneshot(test_request("/v1/dialogs?from=%5B"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 3);
    }

    // ── list_* filtered-total (pagination correctness) ────────────────

    /// With a filter applied, `total` reflects the FILTERED result-set size
    /// (what the returned rows are drawn from), not the unfiltered store, so
    /// a client paging by `total` terminates instead of over-paging.
    #[tokio::test]
    async fn list_dialogs_total_reflects_filtered_count() {
        let state = make_state();
        populate_dialogs(&state); // 3 dialogs: user0, user1, user2
        let app = build_router(state);

        // from=user1 matches exactly one dialog.
        let resp = app
            .oneshot(test_request("/v1/dialogs?from=user1"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 1);
        assert_eq!(
            parsed["total"], 1,
            "total must be the filtered count, not 3"
        );
    }

    /// An `orphaned` filter that excludes every stream yields `total` 0, so a
    /// client paging by `total` stops immediately rather than requesting
    /// empty pages up to the unfiltered store size.
    #[tokio::test]
    async fn list_streams_total_reflects_filtered_count() {
        let state = make_state();
        add_stream(&state, 0x9999_0001, 40000, 50000);
        add_stream(&state, 0x9999_0002, 40002, 50002);
        let app = build_router(state);

        // Freshly-created streams are not orphaned; orphaned=true excludes all.
        let resp = app
            .oneshot(test_request("/v1/streams?orphaned=true"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["streams"].as_array().expect("array").len(), 0);
        assert_eq!(
            parsed["total"], 0,
            "total must be the filtered count, not 2"
        );
    }

    /// Paging by `total`/`limit` over a filtered dialog list visits exactly
    /// the filtered rows once and then terminates (no over-paging past the
    /// filtered set).
    #[tokio::test]
    async fn list_dialogs_filtered_paging_terminates() {
        let state = make_state();
        populate_dialogs(&state); // user0, user1, user2

        // Filter "user[12]" (URL-encoded) matches user1 and user2 => 2 rows.
        let filter = "/v1/dialogs?from=user%5B12%5D";
        let first = build_router(state.clone())
            .oneshot(test_request(&format!("{filter}&offset=0&limit=1")))
            .await
            .expect("oneshot");
        let parsed: Value =
            serde_json::from_str(&body_to_string(first.into_body()).await).expect("json");
        let total = parsed["total"].as_u64().expect("total");
        assert_eq!(total, 2, "filtered total should be 2, not the store's 3");

        // Walk pages of size 1 by `total` and collect exactly `total` rows.
        let limit = 1u64;
        let mut collected = 0u64;
        let mut offset = 0u64;
        while offset < total {
            let uri = format!("{filter}&offset={offset}&limit={limit}");
            let r = build_router(state.clone())
                .oneshot(test_request(&uri))
                .await
                .expect("oneshot");
            let p: Value =
                serde_json::from_str(&body_to_string(r.into_body()).await).expect("json");
            collected += p["dialogs"].as_array().expect("array").len() as u64;
            offset += limit;
        }
        assert_eq!(
            collected, total,
            "paging by total must visit exactly the filtered rows"
        );
    }

    // ── metrics with stream data ──────────────────────────────────────

    /// `/metrics` with stream data returns 200, the Prometheus content
    /// type, and `sipnab_` metrics.
    #[tokio::test]
    async fn get_metrics_with_streams_populates_rtp() {
        let state = make_state();
        populate_dialogs(&state);
        add_stream(&state, 0x6666_6666, 26000, 36000);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/metrics"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        // content-type header set by the handler
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/plain"), "got content-type: {ct}");

        let body = body_to_string(resp.into_body()).await;
        assert!(body.contains("sipnab_"));
    }

    // ── stats with empty stores ───────────────────────────────────────

    /// `/v1/stats` on empty stores reports total 0 and `null` PDD
    /// percentiles.
    #[tokio::test]
    async fn stats_empty_store_has_null_percentiles() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/stats"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"]["total"], 0);
        // percentile(&[], _) is None -> serialized as null
        assert!(parsed["timing"]["pdd_p50_ms"].is_null());
    }

    // ── auth guard arms ───────────────────────────────────────────────

    /// With no credential configured, auth is disabled and requests pass.
    #[tokio::test]
    async fn auth_no_key_configured_allows_request() {
        // make_state has api_key = None -> check_auth short-circuits to Ok.
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A non-Bearer scheme (`Basic ...`) is rejected with 401.
    #[tokio::test]
    async fn auth_non_bearer_scheme_returns_401() {
        let state = make_state_with_key("secret-key");
        let app = build_router(state);

        // "Basic ..." does not start with "Bearer " -> 401.
        let req = test_request_with_header("/v1/dialogs", "Authorization", "Basic secret-key");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// An Authorization value that fails `to_str()` (non-visible-ASCII) is
    /// rejected with 401.
    #[tokio::test]
    async fn auth_non_ascii_header_returns_401() {
        let state = make_state_with_key("secret-key");
        let app = build_router(state);

        // A non-visible-ASCII header value makes to_str() fail -> 401.
        let req = test_request_with_header("/v1/dialogs", "Authorization", "Bearer \u{00ff}key");
        let resp = app.oneshot(req).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// `/health` bypasses the guard: 200 "ok" even with a key configured.
    #[tokio::test]
    async fn health_check_ignores_rate_limit_and_auth() {
        // /health is not guarded; works even with a key configured.
        let state = make_state_with_key("secret-key");
        let app = build_router(state);

        let resp = app.oneshot(test_request("/health")).await.expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_to_string(resp.into_body()).await, "ok");
    }

    // ── helper unit tests ─────────────────────────────────────────────

    /// Any percentile of a single-element slice is that element.
    #[test]
    fn percentile_single_element() {
        let one = vec![42];
        assert_eq!(percentile(&one, 0), Some(42));
        assert_eq!(percentile(&one, 50), Some(42));
        assert_eq!(percentile(&one, 100), Some(42));
    }

    /// Percentiles of an empty slice are `None`.
    #[test]
    fn percentile_empty_is_none() {
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[], 99), None);
    }

    /// A loss-free, jitter-free PCMU stream scores between 3.0 and 5.0.
    #[test]
    fn approximate_mos_clean_stream_is_high() {
        let state = make_state();
        add_stream(&state, 0x7777_7777, 27000, 37000);
        let ss = state.stream_store.read();
        let s = ss.iter().next().expect("one stream");
        let mos = approximate_mos(s);
        // A loss-free, jitter-free PCMU stream should score well above 3.0.
        assert!(mos > 3.0, "expected good MOS, got {mos}");
        assert!(mos <= 5.0, "MOS should not exceed ceiling, got {mos}");
    }

    /// `dialog_summary` emits the canonical projection keys (`call_id`,
    /// `method`, `timing`, `created_at`).
    #[test]
    fn dialog_summary_shape() {
        let state = make_state();
        populate_dialogs(&state);
        let ds = state.dialog_store.read();
        let d = ds.iter().next().expect("one dialog");
        let summary = dialog_summary(d);
        assert!(summary["call_id"].is_string());
        assert_eq!(summary["method"], "INVITE");
        assert!(summary["timing"].is_object());
        assert!(summary["created_at"].is_string());
    }

    /// `stream_summary` emits `0x`-prefixed SSRC, numeric MOS, and
    /// `orphaned`.
    #[test]
    fn stream_summary_shape() {
        let state = make_state();
        add_stream(&state, 0x8888_8888, 28000, 38000);
        let ss = state.stream_store.read();
        let s = ss.iter().next().expect("one stream");
        let summary = stream_summary(s);
        assert_eq!(summary["ssrc"], "0x88888888");
        assert!(summary["mos"].is_number());
        assert_eq!(summary["orphaned"], false);
    }

    /// Port 0 (OS-assigned ephemeral) parses to loopback:0.
    #[test]
    fn parse_bind_addr_port_zero() {
        let addr = parse_bind_addr("0").expect("parse");
        assert_eq!(addr.port(), 0);
        assert!(addr.ip().is_loopback());
    }

    /// A bare ":" is rejected (empty port).
    #[test]
    fn parse_bind_addr_colon_only_is_invalid() {
        // ":" strips to empty, which is not a valid u16 and not a SocketAddr.
        assert!(parse_bind_addr(":").is_err());
    }

    /// A port above `u16::MAX` is rejected on every parse branch.
    #[test]
    fn parse_bind_addr_out_of_range_port_is_invalid() {
        // 70000 > u16::MAX so the bare-port branch fails, then SocketAddr parse fails.
        assert!(parse_bind_addr("70000").is_err());
    }

    /// A bracketed IPv6 `[::1]:port` address parses.
    #[test]
    fn parse_bind_addr_ipv6_full() {
        let addr = parse_bind_addr("[::1]:8080").expect("parse");
        assert_eq!(addr.port(), 8080);
        assert!(addr.ip().is_loopback());
    }

    /// Each source IP gets its own rate-limit bucket.
    #[test]
    fn rate_limiter_separate_ips_independent() {
        let mut limiter = RateLimiter::new(1);
        let ip_a = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
        assert!(limiter.check(ip_a));
        // Different IP has its own bucket.
        assert!(limiter.check(ip_b));
        // ip_a is now over its limit.
        assert!(!limiter.check(ip_a));
    }
}
