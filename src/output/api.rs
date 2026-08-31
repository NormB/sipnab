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
//! | GET    | `/v1/dialogs/:call_id/vcon`     | Export dialog as vCon (`vcon`)  |
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

/// An RFC 9457 `application/problem+json` error body.
///
/// sipnab's REST errors used to be a bare [`StatusCode`] with NO body at all,
/// so a client received a number and nothing else — not which resource, not
/// which of the several reasons a 400 has, and nothing stable to branch on.
///
/// RFC 9457 is the registered way to say more. `type` is a URI naming the
/// problem KIND, and it is the field a client should switch on; `title` is a
/// short human-readable summary of that kind; `status` repeats the HTTP code
/// so the body survives being logged apart from its response; `detail` is
/// about THIS occurrence.
///
/// One vCon store this project probes answers exactly this shape live while
/// its own OpenAPI document advertises `{"error": "..."}`, which is a useful
/// warning in both directions: a client must not trust a documented error
/// shape it has not seen, and a server should not document one it does not
/// send.
///
/// No `instance` member. RFC 9457 makes it optional, and it would be a URI
/// identifying this specific occurrence — sipnab has no such identifier to
/// give, and inventing one that resolves to nothing is worse than omitting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// HTTP status, and the value of the body's `status` member.
    pub status: StatusCode,
    /// What went wrong THIS time, or `None` to send the kind's title alone.
    pub detail: Option<String>,
}

impl Problem {
    /// The base for every `type` URI sipnab sends.
    ///
    /// A relative URI would resolve against the request, so two deployments
    /// would give one problem kind two identities and a client could not
    /// compare them.
    pub const TYPE_BASE: &'static str = "https://sipnab.com/problems/";

    /// A problem carrying only its kind.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            detail: None,
        }
    }

    /// A problem that also says what happened this time.
    #[must_use]
    pub fn detailed(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: Some(detail.into()),
        }
    }

    /// The slug in this problem's `type` URI.
    ///
    /// Derived from the status rather than free text, so one kind of failure
    /// has one URI across every handler. A client branching on `type` is the
    /// whole point, and two handlers spelling the same problem differently
    /// would defeat it.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        match self.status {
            StatusCode::BAD_REQUEST => "bad-request",
            StatusCode::UNAUTHORIZED => "unauthorized",
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not-found",
            StatusCode::TOO_MANY_REQUESTS => "rate-limited",
            StatusCode::PAYLOAD_TOO_LARGE => "payload-too-large",
            StatusCode::SERVICE_UNAVAILABLE => "unavailable",
            StatusCode::INTERNAL_SERVER_ERROR => "internal",
            _ => "error",
        }
    }
}

impl From<StatusCode> for Problem {
    fn from(status: StatusCode) -> Self {
        Self::new(status)
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> axum::response::Response {
        let title = self
            .status
            .canonical_reason()
            .unwrap_or("Error")
            .to_string();
        let mut body = json!({
            "type": format!("{}{}", Self::TYPE_BASE, self.slug()),
            "title": title,
            "status": self.status.as_u16(),
        });
        if let Some(detail) = self.detail {
            body["detail"] = Value::String(detail);
        }
        let mut response = (self.status, Json(body)).into_response();
        // RFC 9457 §3: the media type is what tells a generic client this body
        // is a problem rather than the resource it asked for. `Json` sets
        // application/json, so this replaces it.
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

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
    /// Rows one list-style response may return, resolved from
    /// `--api-max-rows` / `[limits] api_max_rows` by the caller that starts
    /// the server (config is in scope there and not here).
    pub max_rows: usize,
    /// Largest inline media body a container this server builds may carry,
    /// resolved from `--vcon-max-inline-media` by the caller that starts the
    /// server — the same arrangement as [`Self::max_rows`], and for the same
    /// reason: the CLI is in scope there and not here.
    ///
    /// `None` takes the measured default. A server and a batch run on one host
    /// must enforce ONE budget, or the same call exported through two doors
    /// comes back carrying audio in one container and a refusal in the other.
    pub max_inline_media_bytes: Option<usize>,
    /// Which capture this process holds — the SAME object the MCP server
    /// stamps its answers with, when both are running.
    ///
    /// Shared rather than copied because the identity rotates: `open_capture`
    /// swaps the file underneath, and two copies would disagree from that
    /// moment on. A client comparing an MCP answer against `GET /v1/stats`
    /// would then be told the capture changed when it had not, or that it had
    /// not when it did.
    ///
    /// `None` when nobody supplied one — a REST server started without capture
    /// context, which every test in this module builds. The response then says
    /// `source: "unknown"` and omits the identity, which is the same answer
    /// `capture_status` gives and for the same reason: a wrong `"live"` would
    /// be worse than an admission of ignorance.
    pub capture: Option<Arc<RwLock<crate::capture::session::CaptureState>>>,
    /// Set once a file source has been read to the end.
    ///
    /// The same `Arc` the capture owner and the MCP server hold, so all three
    /// flip together. A copy would let one door report a finished file as
    /// still running.
    pub source_exhausted: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Whether content may still reach disk on this run.
    ///
    /// Not an `Option`, unlike the two flags above. Those describe a subsystem
    /// that may not be running; this one answers a question every run has an
    /// answer to, and `None` would be a third state meaning "ask somebody
    /// else". A run the command line never authorized carries a gate whose
    /// ceiling is `false`, which is the same answer said out loud.
    ///
    /// The same `Arc` the exporter holds, so the socket and the writer cannot
    /// disagree about whether this capture is writing.
    pub persistence_gate: Arc<crate::output::persistence::PersistenceGate>,
}

/// Rows a list-style response returns when the caller names no `limit`.
///
/// A page size, not a ceiling: it is what `?limit=` defaults to, and any
/// caller can ask for more up to [`ApiState::max_rows`].
const DEFAULT_PAGE_ROWS: usize = 50;

// ── Rate limiter ────────────────────────────────────────────────────

/// Simple per-IP sliding-window rate limiter.
///
/// Tracks request counts per source IP within a one-second window.
/// Resets the window when the current second changes.
pub struct RateLimiter {
    /// Map of source IP to (window start, count).
    buckets: HashMap<IpAddr, (Instant, u32)>,
    /// Maximum requests per second per IP; `0` disables the cap.
    max_rps: u32,
    /// Monotonic call counter for periodic cleanup.
    call_count: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given per-IP max requests/second.
    ///
    /// `0` DISABLES the cap rather than refusing every request. That is the
    /// reading `--mcp-rate-limit-per-peer`, `--hep-rate-limit-per-peer` and
    /// `--hep-rate-limit` all give a zero, and this became reachable the
    /// moment the figure stopped being a hard-coded 100 — an operator who has
    /// learned the convention on one listener must not be locked out of the
    /// REST API by using it on another.
    pub fn new(max_rps: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            max_rps,
            call_count: 0,
        }
    }

    /// Check whether a request from `ip` is allowed. Returns `true` if under
    /// limit, and always `true` when the cap is `0` (disabled).
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
    /// evicts buckets older than 2 s. NONE of that happens when the cap is
    /// `0`: a disabled limiter is a pure `true`, so it never grows a bucket
    /// map for addresses it will not meter.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        // Disabled: return before touching the map, so an uncapped server does
        // not carry a bucket per source address it will never consult.
        if self.max_rps == 0 {
            return true;
        }
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
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
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
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
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
    let router = Router::new()
        .route("/health", get(health_check))
        .route("/v1/dialogs", get(list_dialogs))
        .route("/v1/dialogs/{call_id}", get(get_dialog))
        .route("/v1/dialogs/{call_id}/report", get(get_dialog_report));
    // Registered only where the exporter exists. A route that answered 501
    // in a build without the feature would leave a client unable to tell
    // "this sipnab cannot" from "this call has no data", and the second
    // reading is the one it would act on.
    #[cfg(feature = "vcon")]
    let router = router.route("/v1/dialogs/{call_id}/vcon", get(get_dialog_vcon));
    router
        .route(
            "/v1/persistence",
            get(get_persistence).post(set_persistence),
        )
        .route("/v1/streams", get(list_streams))
        .route("/v1/streams/{id}", get(get_stream))
        .route("/v1/report", get(get_capture_report))
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
fn check_auth(state: &ApiState, headers: &HeaderMap, required_scope: &str) -> Result<(), Problem> {
    // No signing keys and no static secret configured ⇒ auth disabled
    // (loopback-allowed behavior unchanged from before this feature).
    if state.verifier.is_unconfigured() {
        return Ok(());
    }

    let Some(auth_header) = headers.get("authorization") else {
        return Err(Problem::new(StatusCode::UNAUTHORIZED));
    };

    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    if let Some(token) = auth_str.strip_prefix("Bearer ")
        && state
            .verifier
            .verify(token, chrono::Utc::now().timestamp(), required_scope)
    {
        return Ok(());
    }

    Err(Problem::new(StatusCode::UNAUTHORIZED))
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
fn check_rate_limit(state: &ApiState, ip: IpAddr) -> Result<(), Problem> {
    let mut limiter = state.rate_limiter.lock();
    if limiter.check(ip) {
        Ok(())
    } else {
        Err(Problem::new(StatusCode::SERVICE_UNAVAILABLE))
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
fn guard(state: &ApiState, headers: &HeaderMap, client_ip: IpAddr) -> Result<(), Problem> {
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
/// `503` when over the rate budget — NOT `429`, and the difference matters to
/// a caller: the limiter runs BEFORE auth, so a `503` says nothing about the
/// credential because nothing has looked at it yet. `401` when the credential
/// is missing, malformed, unverifiable, or scoped too narrowly for this route.
///
/// # Side effects
///
/// Mutates the shared rate limiter via `check_rate_limit`.
fn guard_scoped(
    state: &ApiState,
    headers: &HeaderMap,
    client_ip: IpAddr,
    required_scope: &str,
) -> Result<(), Problem> {
    // Rate-limit BEFORE authenticating: if auth ran first, a wrong-token
    // request would 401 without ever touching the limiter, letting an
    // attacker brute-force the token at unlimited speed. Charging every
    // request to the per-IP budget throttles that flood.
    check_rate_limit(state, client_ip)?;
    check_auth(state, headers, required_scope)
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /health` — always returns "ok" (200), no auth or rate limit.
#[utoipa::path(
    get,
    path = "/health",
    tag = "operations",
    summary = "Liveness check",
    description = "Answers 200 with the literal body `ok`, whatever else is wrong.\n\nDeliberately outside the guard: no credential, no rate limit, and no store access. A liveness probe that a rate limit could starve is a probe that reports an outage it caused, and one that reads the stores answers slowly on the capture that most needs watching.",
    responses(
        (status = 200, description = "The process is up. Deliberately outside the guard: no \
                                      credential, no rate limit, and no store access, so a \
                                      liveness probe cannot be starved by one and cannot read \
                                      anything.", body = String, content_type = "text/plain", example = json!("ok"))
    )
)]
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
/// terminates correctly; 401/503 from the guard. `limit` is clamped to
/// `--api-max-rows` (default 1000).
///
/// # Side effects
///
/// Holds the dialog-store read lock while filtering; mutates the rate
/// limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs",
    tag = "dialogs",
    summary = "List dialogs",
    description = "One page of dialog summaries, newest store order.\n\n`total` is the size of the FILTERED set — the count the rows are drawn from, after `state` and `from` are applied — so a client paging by `total` terminates instead of asking for empty pages past the end. `limit` is clamped to the operator's `--api-max-rows`, and the response echoes the value actually used.",
    params(DialogListParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of dialog summaries. `total` is the size of the \
                                      FILTERED set, so paging by it terminates.", body = schema::DialogList),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn list_dialogs(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DialogListParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let offset = params.offset.unwrap_or(0);
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_ROWS)
        .min(state.max_rows);

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
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}",
    tag = "dialogs",
    summary = "Get one dialog",
    description = "The dialog in full: display names, the SDP timeline, the media and asymmetry diagnosis, and the RTP streams it claims.\n\nA superset of the summary the list returns, and freshly diagnosed on each call rather than cached.",
    params(("call_id" = String, Path, description = "Call-ID of the dialog, percent-encoded. \
                                                     Call-IDs routinely carry `@` and may carry \
                                                     `;`, `+` or `/`.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The dialog in full, with its streams and a freshly \
                                      computed media/asymmetry diagnosis.", body = schema::Dialog),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 500, description = "The dialog would not serialize.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_dialog(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let dialog = ds
        .get(&call_id)
        .ok_or(Problem::new(StatusCode::NOT_FOUND))?;

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
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}/report",
    tag = "dialogs",
    summary = "Get a call report",
    description = "The per-call analysis report — byte for byte the object `--call-report --json` writes, so a report fetched here and one produced offline are comparable.",
    params(("call_id" = String, Path, description = "Call-ID of the dialog, percent-encoded.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The per-call analysis report — the same object \
                                      `--call-report --json` writes.", body = schema::CallReport),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 500, description = "The report would not serialize.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_dialog_report(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let dialog = ds
        .get(&call_id)
        .ok_or(Problem::new(StatusCode::NOT_FOUND))?;

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

/// `GET /v1/dialogs/:call_id/vcon` — one observed dialog as a vCon container.
///
/// Registered only in a build with the `vcon` feature. See the gate in
/// [`build_router`] for why the route is absent rather than answering an
/// error: a client can distinguish a missing route from a missing call, and
/// cannot distinguish two different errors on the same one.
///
/// # What this returns, and what a reader must not conclude from it
///
/// An OBSERVER's record. sipnab watched these packets go past; it did not
/// place the call, record it, or obtain anyone's consent to keep it. The
/// container carries signaling only — no media and no reference to media held
/// elsewhere — nothing in it is signed, and the party entries are what the
/// `From` and `To` headers said rather than identities anyone established.
/// Every one of those is stated inside the container itself, in the
/// completeness caveat that [`crate::output::vcon`] duplicates into the
/// analysis body and an attachment.
///
/// # Why the capture analysis runs here
///
/// `blind_spots: None` and `blind_spots: []` are different answers — "nobody
/// looked" against "somebody looked and found nothing" — and this door has
/// both stores in hand, so declining to look would make every container it
/// emits read as unexamined. `/v1/report` already pays the same per-request
/// analysis cost for the same stores.
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
/// 200 with the container serialized as a JSON OBJECT — not
/// [`Vcon::to_json`](crate::output::vcon::Vcon::to_json)'s string, which would
/// make a client parse JSON out of JSON; 404 when the Call-ID is unknown; 500
/// if the container fails to serialize; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog- then stream-store read locks (in that order, the one
/// `/v1/report` takes, so the two can never deadlock against each other)
/// while reading the facts and running the analysis; mutates the rate limiter.
#[cfg(feature = "vcon")]
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}/vcon",
    tag = "dialogs",
    summary = "Export a dialog as a vCon",
    description = "One observed dialog as an unsigned OBSERVER vCon container (draft-ietf-vcon-vcon-core).\n\nRead the caveat before reading the container: sipnab watched these packets go past. It did not place the call, record it, or obtain anyone's consent to keep it. Nothing here is signed, and the party entries are what the `From` and `To` headers said rather than identities anyone established. The container states all of that itself, twice.\n\nRegistered only in a build carrying the vCon exporter. A build without it has no such route — rather than a route that answers an error, which a client cannot tell from a missing call.",
    params(("call_id" = String, Path, description = "Call-ID of the dialog, percent-encoded.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One observed dialog as an unsigned OBSERVER vCon \
                                      container. sipnab watched these packets go past; it did \
                                      not place the call, record it, or obtain anyone's consent \
                                      to keep it. The container states that itself, in a \
                                      completeness caveat it carries twice.", body = schema::Vcon),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 500, description = "The container would not serialize.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_dialog_vcon(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    let dialog = ds
        .get(&call_id)
        .ok_or(Problem::new(StatusCode::NOT_FOUND))?;
    let ss = state.stream_store.read();

    // Frames read comes from the same process-global the Prometheus scrape and
    // `/v1/report` report, so the denominator the caveat quotes is the one
    // every other number in the run is read against.
    let facts =
        crate::analysis::CaptureFacts::observed(&ds, &ss, crate::capture::captured_packets());
    let analysis = crate::analysis::analyze_with(&ds, &ss, None, &facts);
    // The SAME builder the CLI and MCP doors call, with the SAME per-dialog
    // capture id. This door called the signaling-only entry point with a
    // constant id until 0.5.125, so one run answered two ways: an agent asking
    // over MCP got a container with the audio inline, a program asking over
    // REST got one without it, and the two carried DIFFERENT uuids for one
    // dialog — which a store reads as two observations of two calls.
    //
    // Media is attempted always. When the run retained no payload the decode
    // fails and its message travels in the container, which reports what was
    // MEASURED rather than claiming the call was silent.
    let dialog_streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(&call_id).collect();
    let decoded = crate::rtp::audio_export::decode_dialog_audio(&dialog_streams);
    let reason = decoded
        .as_ref()
        .err()
        .map_or_else(String::new, |e| e.to_string());
    let audio = match decoded.as_ref() {
        Ok(audio) => output::vcon::ObservedAudio::Decoded(audio),
        Err(_) => output::vcon::ObservedAudio::NothingToDecode(&reason),
    };
    let container = output::vcon::export_dialog_with_audio(
        dialog,
        &output::vcon::ExportContext {
            capture_id: output::vcon::dialog_capture_id(dialog),
            facts: &facts,
            analysis: Some(&analysis),
            max_inline_media_bytes: state.max_inline_media_bytes,
        },
        audio,
    );
    drop(ss);
    drop(ds);

    let parsed = serde_json::to_value(&container).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// The body `POST /v1/persistence` accepts.
///
/// `deny_unknown_fields` so a caller who misspells the key is told, rather
/// than getting a 200 that moved nothing. The field is required and typed:
/// serde refuses a string, a number, and a missing key alike, and every one of
/// those refusals leaves the gate where it was.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct PersistenceRequest {
    /// What the caller wants the gate to be, narrowed by the command line.
    enabled: bool,
}

/// The shape both doors of `/v1/persistence` answer with.
fn persistence_body(gate: &crate::output::persistence::PersistenceGate) -> Json<Value> {
    Json(json!({
        "enabled": gate.writes_permitted(),
        "authorized": gate.authorized(),
    }))
}

/// `GET /v1/persistence` — whether this capture is writing content.
///
/// Behind the same guard as every other route. It reports what a capture is
/// keeping, which is not a public fact, and a reader who can see the answer is
/// one step from a writer who can change it.
#[utoipa::path(
    get,
    path = "/v1/persistence",
    tag = "operations",
    summary = "Read the persistence gate",
    description = "Whether this capture is writing content to disk, and whether the command line allows it to.\n\nBehind the same guard as every other route: what a capture is keeping is not a public fact, and a reader who can see the answer is one step from a writer who can change it.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Whether this capture is writing content, and whether the \
                                      command line allows it to.", body = schema::PersistenceState),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_persistence(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    Ok(persistence_body(&state.persistence_gate))
}

/// `POST /v1/persistence` — close the gate, or open it as far as allowed.
///
/// Answers with the same shape `GET` does, carrying both the gate's state and
/// the command line's ceiling. A caller that asked to enable an unauthorized
/// run therefore reads `enabled: false, authorized: false` rather than a bare
/// 200 it would take for success.
#[utoipa::path(
    post,
    path = "/v1/persistence",
    tag = "operations",
    summary = "Set the persistence gate",
    description = "Close the gate, or open it as far as the command line allows.\n\nAnswers with the same shape `GET` does, carrying both the gate's state and the ceiling. A caller that asked to enable an unauthorized run therefore reads `enabled: false, authorized: false` rather than a bare 200 it would take for success.",
    request_body(content = PersistenceRequest, description = "What the caller wants the gate to \
                                                              be. Unknown keys are refused, and \
                                                              so is a JSON array — `[true]` is \
                                                              not `{\"enabled\": true}`."),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The gate as it now stands, narrowed by the command line. \
                                      A caller that asked to enable an unauthorized run reads \
                                      `enabled: false, authorized: false` here rather than a \
                                      bare 200 it would take for success.", body = schema::PersistenceState),
        (status = 400, description = "The body was not a JSON object with exactly an `enabled` \
                                      boolean. A rejection stays a rejection: the dangerous \
                                      reading of \"I could not understand this\" is \
                                      `enabled: true`.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn set_persistence(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    // The body is extracted fallibly and AFTER the guard, in that order and
    // for two reasons. Taken infallibly, axum would answer a malformed body
    // itself, before the guard ran, telling an unauthenticated caller whether
    // its JSON parsed. And a rejection has to stay a rejection: the dangerous
    // reading of "I could not understand this request" is `enabled: true`.
    let Ok(Json(raw)) = body else {
        return Err(Problem::new(StatusCode::BAD_REQUEST));
    };
    // A JSON object, and nothing else. Extracting straight into the struct
    // looks equivalent and is not: a derived `Deserialize` also accepts a
    // SEQUENCE, filling the fields in declaration order, so the body `[true]`
    // parsed as `enabled: true` and reopened a closed gate. `deny_unknown_
    // fields` does not catch it -- a sequence has no field names to be
    // unknown. Nothing but this check stands between a stray array and an
    // operator's close being undone.
    if !raw.is_object() {
        return Err(Problem::new(StatusCode::BAD_REQUEST));
    }
    let Ok(req) = serde_json::from_value::<PersistenceRequest>(raw) else {
        return Err(Problem::new(StatusCode::BAD_REQUEST));
    };
    state.persistence_gate.set(req.enabled);
    Ok(persistence_body(&state.persistence_gate))
}

/// `GET /v1/streams` — list RTP streams with optional filtering and pagination.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — Offset/limit pagination plus `orphaned` (exact match) and
///   `mos_below` (streams whose GROUNDED estimated MOS is strictly below the
///   threshold) filters.
///
/// `mos_below` admits only streams whose MOS is a measurement. A codec with no
/// published impairment value scores a placeholder that means "unknown", and
/// the placeholder is low, so a bound applied without that test returns every
/// unscoreable stream dressed as a bad one. How many were held back is
/// reported rather than hidden — see `ungrounded_excluded` below.
///
/// # Returns
///
/// 200 with `{schema_version, total, offset, limit, ungrounded_excluded,
/// streams}` where `total` is the FILTERED result-set size (the count the
/// returned rows are drawn from, after `orphaned`/`mos_below` filters), so
/// paging by `total` terminates correctly, and `ungrounded_excluded` is how
/// many streams `mos_below` skipped for want of a grounded score (always 0
/// when `mos_below` is absent, because nothing was bounded); 401/503 from the
/// guard. `limit` is clamped to `--api-max-rows` (default 1000).
///
/// `schema_version` is 2. Version 1 served a `mos` with no grounding beside it
/// and a `mos_below` that selected placeholders; each row now carries
/// `mos_grounded`, `mos_grounding` and, when there is a caveat, `mos_note`.
///
/// # Side effects
///
/// Holds the stream-store read lock while filtering; mutates the rate
/// limiter.
#[utoipa::path(
    get,
    path = "/v1/streams",
    tag = "streams",
    summary = "List RTP streams",
    description = "One page of stream summaries.\n\n`mos_below` admits only streams whose MOS is a measurement. A codec with no published impairment value scores a placeholder that stands in for a missing measurement, and the placeholder is low, so a bound applied without that test would return every unscoreable stream dressed as a bad one. How many were held back is reported in `ungrounded_excluded` rather than hidden.",
    params(StreamListParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One page of stream summaries. `ungrounded_excluded` \
                                      reports how many streams a `mos_below` bound skipped for \
                                      want of a grounded score, rather than dropping them \
                                      silently.", body = schema::StreamList),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn list_streams(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<StreamListParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let offset = params.offset.unwrap_or(0);
    let limit = params
        .limit
        .unwrap_or(DEFAULT_PAGE_ROWS)
        .min(state.max_rows);
    let orphaned_filter = params.orphaned;
    let mos_threshold = params.mos_below;

    let ss = state.stream_store.read();
    // The delay every MOS on this response is scored with — the `mos_below`
    // test below and the `mos` field of each row it admits.
    let delay = quality::MosDelay::from_capture(&ss);
    // Materialize the FILTERED set first so `total` reflects what the page is
    // drawn from (see `list_dialogs`); the unfiltered store size would break a
    // client paging by `total`.
    // Streams a `mos_below` bound would have selected on a placeholder, and
    // did not. Counted rather than silently dropped: a caller asking "show me
    // bad calls" who gets four rows must be able to tell that from the same
    // four rows out of a store where sixty streams could not be scored at all.
    let mut ungrounded_excluded = 0usize;
    let filtered: Vec<&crate::rtp::stream::RtpStream> = ss
        .iter()
        .filter(|s| {
            if let Some(orphaned) = orphaned_filter
                && s.orphaned() != orphaned
            {
                return false;
            }
            if let Some(threshold) = mos_threshold {
                // Grounding first, and independently of the bound. An
                // unpublished codec scores the placeholder, the placeholder is
                // low, and a `mos_below` filter without this test returns every
                // stream sipnab could not score AS IF it had scored them badly
                // -- which is the one answer worse than returning nothing. MCP
                // has tested this since `min_mos` existed; REST had not, and
                // both now decide through `quality::mos_is_grounded`.
                if !quality::mos_is_grounded(s.codec.as_deref()) {
                    ungrounded_excluded += 1;
                    return false;
                }
                let mos = approximate_mos(s, delay);
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
        .map(|&s| stream_summary(s, &ss))
        .collect();
    drop(ss);

    Ok(Json(json!({
        "schema_version": 2,
        "total": total,
        "offset": offset,
        "limit": limit,
        "ungrounded_excluded": ungrounded_excluded,
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
#[utoipa::path(
    get,
    path = "/v1/streams/{id}",
    tag = "streams",
    summary = "Get one RTP stream",
    description = "The stream in full, including the burst/gap and quality-interval detail the list summary omits.",
    params(("id" = String, Path, description = "SSRC as hex, with or without a `0x` prefix. An \
                                                SSRC is not unique — the stream key is SSRC plus \
                                                source plus destination — so the busiest match \
                                                is returned, deterministically, rather than an \
                                                arbitrary first one.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The stream in full.", body = schema::RtpStream),
        (status = 400, description = "The id is not hexadecimal.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No stream carries that SSRC in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 500, description = "The stream would not serialize.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_stream(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
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
        .ok_or(Problem::new(StatusCode::NOT_FOUND))?;

    let json_str = output::json::stream_to_json(stream);
    drop(ss);

    let parsed: Value =
        serde_json::from_str(&json_str).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(parsed))
}

/// `GET /v1/report` — the whole-capture analysis report.
///
/// The capture-level view: findings across every dialog and stream, orphaned
/// media, STUN and ICMP evidence, and what the retention caps shed.
/// `GET /v1/dialogs/{call_id}/report` answers for one Call-ID; this answers for
/// the capture. The CLI has had it as `--report` since before either server
/// existed, and MCP as `get_capture_report`; REST could not answer the question
/// at all, so a client wanting it had to reimplement the analysis it came here
/// for.
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
///
/// # Returns
///
/// 200 with the analysis object; 401/503 from the guard. Frames read comes from
/// [`crate::capture::captured_packets`], the same process-global the Prometheus
/// scrape reports, so the denominator here is the one every other number in the
/// run is read against.
///
/// # Side effects
///
/// Holds both store read locks while building the report; mutates the rate
/// limiter.
#[utoipa::path(
    get,
    path = "/v1/report",
    tag = "capture",
    summary = "Analyze the whole capture",
    description = "The capture-level view: findings across every dialog and stream, orphaned media, STUN and ICMP evidence, and what the retention caps shed.\n\n`GET /v1/dialogs/{call_id}/report` answers for one Call-ID; this answers for the capture. `complete: false` means a cap shed something and every count beside it is a floor.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The whole-capture analysis: findings across every dialog \
                                      and stream, orphaned media, STUN and ICMP evidence, and \
                                      what the retention caps shed.                                       `/v1/dialogs/{call_id}/report` answers for one \
                                      Call-ID; this answers for the capture.", body = schema::CaptureReport),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 500, description = "The analysis would not serialize.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_capture_report(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let analysis = {
        // Dialogs then streams, the order `CaptureState` documents and the
        // order MCP's `get_capture_report` takes them in, so the two halves of
        // one analysis describe one store revision -- and so the two doors can
        // never deadlock against each other.
        let ds = state.dialog_store.read();
        let ss = state.stream_store.read();
        crate::analysis::analyze(&ds, &ss, None, crate::capture::captured_packets())
    };

    // Serialized from the ANALYSIS, not re-parsed out of a rendered report.
    // `print_analysis_report_as` looks like it has a JSON arm and does not: its
    // `format` argument only chooses between markdown headings and plain text,
    // so `ReportFormat::Json` returns prose. Asking it for JSON and parsing the
    // result is how this endpoint first returned 500 -- and how MCP's tool of
    // the same name had been quietly serving text under a `format: "json"`
    // default, because its parse failure fell through to a text block.
    let parsed = serde_json::to_value(&analysis).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
/// canceled}, streams{total,orphaned}, timing{pdd_p50_ms,pdd_p95_ms,
/// pdd_p99_ms}, capture_quality{kernel_dropped_packets,
/// interface_dropped_packets, invalid_timestamps, undecodable_frames,
/// degraded}}`; the percentiles are `null` when no dialog has a PDD. 401/503
/// from the guard.
///
/// `capture_quality` says how much of the wire the counts above are drawn
/// from. Without it every number here reads as a total when it may be a
/// floor, and the timing percentiles read as measured when the clock they
/// came from may have been substituted. `undecodable_frames` answers the
/// question one layer further in: whether the counts describe traffic sipnab
/// READ, or a capture it could not decode at all — a zero dialog count means
/// opposite things in the two cases and used to render identically.
///
/// # Side effects
///
/// Takes the dialog- then stream-store read locks (sequentially, not
/// overlapping); mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/stats",
    tag = "capture",
    summary = "Aggregate statistics",
    description = "Counts across dialogs and streams, with post-dial-delay percentiles — and, beside them, what they are drawn from.\n\n`capture_quality` says how much of the wire went missing and `unanalysed_sip_messages` how much the port gate set aside before anything analyzed it. Without those two, every total here reads as a total when it may be a floor: measured on one corpus the port gate alone excluded 37.7% of the SIP.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Aggregate counts, plus what they are drawn from: \
                                      `capture_quality` says how much of the wire was lost and \
                                      `unanalysed_sip_messages` how much the port gate set \
                                      aside. Without those, every total here reads as a total \
                                      when it may be a floor.", body = schema::Stats),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_stats(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    // Capture lock first, then dialogs, then streams -- the order
    // `CaptureState` documents and MCP's `capture_status` takes. Two doors
    // taking one set of locks in two orders is a deadlock waiting for load,
    // and `open_capture` clears both stores while holding the capture lock.
    //
    // Held ACROSS both stores, which this handler did not do: it released the
    // dialog guard before taking the stream guard, so its dialog counts and
    // stream counts described two different instants. That was survivable
    // while nothing tied them together. It stops being survivable the moment
    // the response carries an identity, because the etag pairs the instance
    // with BOTH generations and would assert a consistency the code did not
    // provide.
    let capture = state.capture.as_ref().map(|c| c.read());
    let ds = state.dialog_store.read();
    let ss = state.stream_store.read();

    let total_dialogs = ds.len();
    let active_dialogs = ds.active_dialog_count();
    let active_calls = ds.active_call_count();

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
            DialogState::Canceled => cancelled_count += 1,
            _ => {}
        }
    }
    let total_streams = ss.len();
    let orphaned_count = ss.orphaned_count();

    // Stamped while all three guards are held, so the instance and the two
    // generations name one moment. `None` when nobody supplied a capture --
    // the same admission `capture_status` makes, rather than an identity for a
    // capture this server cannot describe.
    let capture_identity = capture
        .as_ref()
        .map(|c| c.identity.etag(ds.generation(), ss.generation()));
    let source = crate::capture::session::CaptureContext::source_label(
        capture.as_ref().and_then(|c| c.context.as_ref()),
    );
    let (capture_name, uptime_sec, writing_to) = capture
        .as_ref()
        .and_then(|c| c.context.as_ref())
        .map_or((None, None, None), |c| {
            (
                Some(c.name.clone()),
                Some(c.started.elapsed().as_secs()),
                c.writing_to.clone(),
            )
        });
    let unsaved = crate::capture::session::CaptureContext::unsaved(
        capture.as_ref().and_then(|c| c.context.as_ref()),
    );
    let source_exhausted = state
        .source_exhausted
        .as_ref()
        .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire));

    drop(ss);
    drop(ds);
    drop(capture);

    let pdd_p50 = percentile(&pdd_values, 50);
    let pdd_p95 = percentile(&pdd_values, 95);
    let pdd_p99 = percentile(&pdd_values, 99);

    // Read after the store locks are released: these are process-global
    // atomics with no relationship to either store's revision, so holding a
    // lock across the read would buy nothing and cost contention.
    let quality = output::prometheus::CaptureQuality::current();
    // What the capture DECLINED, beside what it lost. `capture_quality` below
    // counts packets that went missing; this counts work sipnab chose not to
    // do and owes the reader a number for. Same projection MCP's
    // `capture_status` embeds, so the two doors cannot disagree about it.
    let caveats = output::json::CaptureCaveats::current();
    // SIP the PORT GATE excluded, before anything analyzed it. A different loss
    // from `capture_quality` above -- nothing was dropped and nothing failed to
    // decode; the bytes were read and then set aside because both ports fell
    // outside the configured range.
    //
    // Measured on the corpus: 2,311 dialogs against 3,712 real, 37.7% lost,
    // because a third of the SIP never touches 5060/5061. `dialogs.total` alone
    // reads as "how much was there", and a capture missing a third of its calls
    // renders identically to one that only had two-thirds.
    //
    // Same keys and same names as MCP `capture_status`, deliberately: a client
    // that learned this from one door must not have to learn it again at the
    // other.
    let skipped = crate::pipeline::portrange_skip_report();
    let ws_skipped = crate::pipeline::ws_port_skip_report();
    // Top five, because the answer names its own remedy and an operator writes
    // a `--portrange` from it. A full table would bury that.
    // Takes the port slice rather than either report type: the two reports are
    // separate structs that happen to carry the same `Vec<SkippedPort>`, and a
    // closure over the slice serves both without a trait or a second copy.
    let port_rows = |ports: &[crate::pipeline::SkippedPort]| -> Vec<Value> {
        ports
            .iter()
            .take(5)
            .map(|p| json!({ "port": p.port, "messages": p.messages }))
            .collect()
    };

    Ok(Json(json!({
        // 2: `dialogs.in_call` added. `dialogs.active` is unchanged — it
        // always named dialogs, not calls — but a reader that had been using
        // it as a call count needs the version to notice the better key.
        "schema_version": 2,
        "dialogs": {
            "total": total_dialogs,
            // Six states, two of which are SUBSCRIBE dialogs carrying no
            // media. Not a count of calls.
            "active": active_dialogs,
            // Calls that are up: InCall only.
            "in_call": active_calls,
            "completed": completed_count,
            "failed": failed_count,
            // WIRE FORMAT, not prose: this key shipped as `canceled` and
            // dashboards read it by name. The US-English sweep renamed the
            // Rust identifiers around it; the key a consumer matches on
            // does not move for a spelling preference.
            "canceled": cancelled_count,
        },
        "streams": {
            "total": total_streams,
            "orphaned": orphaned_count,
        },
        // Always present, always complete, and zero is a real answer. A key
        // that shows up only on a bad run is a key no client learns exists.
        "caveats": caveats.to_json(),
        // WHICH capture these counts came from, and which revision of its
        // stores. Compare it across calls: a higher generation on the same
        // instance means the capture grew; a different instance means the file
        // was swapped and every count you were holding describes something
        // else. `null` when nobody told this server what it is attached to.
        //
        // The SAME identity MCP `capture_status` stamps its answers with, from
        // the same object, so an agent and an HTTP client polling one process
        // can tell they are describing one capture.
        "capture_identity": capture_identity,
        // What this server is attached to. `unknown` is a real answer and not
        // a default: it is the field consulted before deciding whether
        // stopping is destructive, and a wrong `live` would be worse than an
        // admission of ignorance.
        "source": source,
        "capture_name": capture_name,
        "uptime_sec": uptime_sec,
        "source_exhausted": source_exhausted,
        "writing_to": writing_to,
        // True only for a LIVE capture with no output file: packets held in
        // memory and nowhere else. A file replay is already on disk.
        "unsaved": unsaved,
        // Kept at the top level rather than folded into `caveats`, because MCP
        // publishes them at the top level and the whole point is that the two
        // doors name one fact the same way.
        "unanalysed_sip_messages": skipped.messages,
        "unanalysed_busiest_ports": port_rows(&skipped.ports),
        // Counted apart, because the remedies differ and only one of them is
        // `--portrange`. SIP-over-WebSocket outside the WS port set needs
        // `--ws-portrange`; widening `--portrange` recovers none of it.
        "unanalysed_websocket_messages": ws_skipped.messages,
        "unanalysed_websocket_ports": port_rows(&ws_skipped.ports),
        "timing": {
            "pdd_p50_ms": pdd_p50,
            "pdd_p95_ms": pdd_p95,
            "pdd_p99_ms": pdd_p99,
        },
        "capture_quality": {
            "kernel_dropped_packets": quality.kernel_dropped_packets,
            "interface_dropped_packets": quality.interface_dropped_packets,
            "invalid_timestamps": quality.invalid_timestamps,
            "undecodable_frames": quality.undecodable_frames,
            "snapped_frames": quality.snapped_frames,
            "unanswered_nat_requests": quality.unanswered_nat_requests,
            "lapsed_turn_allocations": quality.lapsed_turn_allocations,
            "lapsed_turn_allocation_streams": quality.lapsed_turn_allocation_streams,
            "ice_role_conflicts": quality.ice_role_conflicts,
            "degraded": quality.degraded(),
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
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "operations",
    summary = "Prometheus metrics",
    description = "The Prometheus text exposition format, over the same stores every other route reads.\n\nThe only route a metrics-scoped bearer token reaches — which is the point of that scope: a scrape credential on a capture tool that can decrypt TLS should not also open `/v1/dialogs`. A full-scope token works here too.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Prometheus text exposition format. The only route a \
                                      metrics-scoped token reaches; a full-scope token also \
                                      works.", body = String, content_type = "text/plain; version=0.0.4; charset=utf-8"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_metrics(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
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
    // Hoisted: the scrape's MOS histogram must describe the same scores the
    // `/v1/streams` rows carry, so it reads the same evidence rather than a
    // per-stream reconstruction of it.
    let delay = quality::MosDelay::from_capture(&ss);
    for s in ss.iter() {
        if s.orphaned() {
            orphaned += 1;
        } else {
            established += 1;
        }
        metrics.mos_histogram.push(approximate_mos(s, delay));
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
fn stream_summary(
    s: &crate::rtp::stream::RtpStream,
    store: &crate::rtp::stream_store::StreamStore,
) -> Value {
    serde_json::to_value(
        crate::output::model::StreamSummary::of(s, quality::MosDelay::from_capture(store))
            .with_round_trip(store.round_trip_for(s)),
    )
    .unwrap_or_else(|e| json!({"error": format!("serialization failed: {e}")}))
}

/// Approximate MOS score for a stream, on the delay the capture supports.
///
/// Delegates to [`quality::MosDelay::score`] for a single MOS implementation.
/// `delay` is not optional and not defaulted: this number decides which
/// streams `?mos_below=` returns, and while it was scored on the assumed
/// 100 ms path it disagreed with the `mos` field in the very rows it
/// selected — one endpoint, two numbers.
fn approximate_mos(stream: &crate::rtp::stream::RtpStream, delay: quality::MosDelay<'_>) -> f64 {
    delay.score(stream)
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

// ── OpenAPI document ────────────────────────────────────────────────

/// The response and request bodies the OpenAPI document names.
///
/// # Why these types exist beside the handlers rather than inside them
///
/// Most handlers build their body with `json!`, and several of them delegate
/// the whole body to a serializer that lives in another module
/// (`output::json`, `output::vcon`, `crate::analysis`). A schema derived from
/// the Rust type would therefore have to reach across three modules and force
/// a `ToSchema` derive onto types that have nothing to do with HTTP.
///
/// So the schema is declared here, next to the route that serves it, and
/// `tests/openapi_contract_test.rs` boots the REAL server against a real
/// capture and checks every documented response against the body that comes
/// back. A schema that drifts from the handler fails there — which is the only
/// check worth having, because a schema nobody compares to a response is
/// prose with a `.json` extension.
///
/// Two components are NOT declared here. `CallReport` and `RtpStream` already
/// have canonical JSON Schemas in `tests/schemas/`; the generator splices those
/// files in, so each has one definition and not two. The empty marker types
/// below reserve the component name and the `$ref` that points at it, and
/// `every_documented_response_matches_what_the_server_sends` is what proves the
/// spliced schema still describes the live body. (`call_report.schema.json` is
/// checked a second way, by `tests/json_schema_test.rs` against
/// `--call-report --json`. `stream.schema.json` was not checked against live
/// output by anything until that test.)
///
/// `DialogSummary` is declared here AND has a schema file, because the two are
/// read by different tools and neither can be dropped. They are cross-checked
/// instead: `openapi_dialog_summary_agrees_with_the_shared_schema` fails if
/// either grows a property the other does not have.
pub mod schema {
    use utoipa::ToSchema;

    /// An RFC 9457 `application/problem+json` body: what every 4xx and 5xx
    /// carries.
    ///
    /// Serialized by [`super::Problem`]'s `IntoResponse`, so this is the wire
    /// type itself rather than a description of one.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    #[schema(as = Problem)]
    pub struct ProblemJson {
        /// URI naming the problem KIND. The field a client branches on.
        #[serde(rename = "type")]
        #[schema(rename = "type", example = "https://sipnab.com/problems/not-found")]
        pub kind: String,
        /// Short, human-readable summary of that kind.
        #[schema(example = "Not Found")]
        pub title: String,
        /// The HTTP status, repeated so the body survives being logged apart
        /// from its response.
        #[schema(example = 404)]
        pub status: u16,
        /// What went wrong THIS time. Absent when the kind says it all.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub detail: Option<String>,
    }

    /// Transaction timing, as carried by every dialog summary.
    #[derive(Debug, Clone, ToSchema)]
    pub struct TimingSummary {
        /// Post-dial delay: INVITE to first ringing response, milliseconds.
        pub pdd_ms: Option<i64>,
        /// INVITE to 200 OK, milliseconds.
        pub setup_ms: Option<i64>,
        /// Retransmitted requests and responses seen in this dialog.
        #[schema(minimum = 0)]
        pub retransmits: u32,
        /// Answer to BYE, milliseconds. Absent for unanswered or live calls.
        pub duration_ms: Option<i64>,
    }

    /// One row of `GET /v1/dialogs`.
    ///
    /// Marker only: the component is spliced from
    /// `tests/schemas/dialog.schema.json`, which
    /// `tests/openapi_contract_test.rs` also checks against this declaration,
    /// so the two cannot disagree about a property name.
    #[derive(Debug, Clone, ToSchema)]
    pub struct DialogSummary {
        /// Call-ID identifying the dialog.
        pub call_id: String,
        /// Current dialog state, e.g. `InCall`, `Completed`.
        pub state: String,
        /// SIP method that opened the dialog, canonical form.
        pub method: String,
        /// User part of the From URI.
        pub from_user: Option<String>,
        /// User part of the To URI.
        pub to_user: Option<String>,
        /// SIP messages in the dialog.
        #[schema(minimum = 0)]
        pub msg_count: usize,
        /// Final INVITE response code, once the call reached one. Absent —
        /// never zero — while the call is still in progress.
        pub final_status_code: Option<u16>,
        /// Reason phrase that came with `final_status_code`.
        pub final_status_reason: Option<String>,
        /// First to last message, seconds. `0` for a single-message dialog.
        pub duration_sec: f64,
        /// RFC 3339 timestamp of the first message.
        #[schema(format = DateTime)]
        pub created_at: String,
        /// RFC 3339 timestamp of the most recent message.
        #[schema(format = DateTime)]
        pub updated_at: String,
        /// Transaction timing metrics.
        pub timing: TimingSummary,
        /// `<source>#<ordinal>` pointer to the frame this dialog opened in.
        pub frame: Option<String>,
        /// Which capture source delivered the opening message — `wire`, `hep`
        /// or `uprobe`.
        pub input_origin: Option<String>,
    }

    /// One row of `GET /v1/streams`.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StreamSummary {
        /// SSRC as a `0x`-prefixed hex string.
        #[schema(example = "0x1a2b3c4d")]
        pub ssrc: String,
        /// Payload codec, when one was identified.
        pub codec: Option<String>,
        /// Source `address:port`.
        pub src: String,
        /// Destination `address:port`.
        pub dst: String,
        /// RTP packets counted on this stream.
        #[schema(minimum = 0)]
        pub packets: u64,
        /// Interarrival jitter, milliseconds.
        pub jitter_ms: f64,
        /// Loss as a percentage of expected packets.
        pub loss_pct: f64,
        /// No dialog claims this stream.
        pub orphaned: bool,
        /// Call-ID of the dialog that does claim it.
        pub associated_dialog: Option<String>,
        /// Estimated MOS. Read `mos_grounded` before comparing it.
        pub mos: f64,
        /// Whether `mos` is a measurement or a placeholder standing in for a
        /// codec with no published impairment value. `?mos_below=` admits only
        /// grounded scores.
        pub mos_grounded: bool,
        /// What `mos` was computed from.
        pub mos_grounding: String,
        /// Caveat attached to this particular score.
        pub mos_note: Option<String>,
        /// `<source>#<ordinal>` pointer to the first frame of the stream.
        pub frame: Option<String>,
        /// Round-trip time, milliseconds, when one could be measured.
        pub round_trip_ms: Option<f64>,
        /// What the round trip was measured from.
        pub round_trip_source: Option<String>,
        /// Capture source that delivered the first packet.
        pub input_origin: Option<String>,
        /// Capture source that delivered the owning dialog.
        pub dialog_origin: Option<String>,
    }

    /// `GET /v1/dialogs` — one page of dialog summaries.
    #[derive(Debug, Clone, ToSchema)]
    pub struct DialogList {
        /// Wire-format version of this envelope.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// Size of the FILTERED result set — the count the rows are drawn
        /// from, so paging by `total` terminates.
        pub total: usize,
        /// The `offset` this page was taken at.
        pub offset: usize,
        /// The `limit` actually applied, after clamping to `--api-max-rows`.
        pub limit: usize,
        /// The page.
        pub dialogs: Vec<DialogSummary>,
    }

    /// `GET /v1/streams` — one page of stream summaries.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StreamList {
        /// Wire-format version of this envelope.
        #[schema(example = 2)]
        pub schema_version: u32,
        /// Size of the FILTERED result set.
        pub total: usize,
        /// The `offset` this page was taken at.
        pub offset: usize,
        /// The `limit` actually applied.
        pub limit: usize,
        /// Streams a `mos_below` bound skipped for want of a grounded score.
        /// Always `0` when `mos_below` is absent, because nothing was bounded.
        pub ungrounded_excluded: usize,
        /// The page.
        pub streams: Vec<StreamSummary>,
    }

    /// The body both doors of `/v1/persistence` answer with.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct PersistenceState {
        /// Whether content may reach disk on this run right now.
        pub enabled: bool,
        /// The command line's ceiling. A caller that asked to enable an
        /// unauthorized run reads `enabled: false, authorized: false` rather
        /// than a bare 200 it would take for success.
        pub authorized: bool,
    }

    /// Dialog counts, by state, from `GET /v1/stats`.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StatsDialogs {
        /// Dialogs tracked.
        pub total: usize,
        /// Dialogs in an active state. Six states, two of them SUBSCRIBE
        /// dialogs carrying no media — not a count of calls.
        pub active: usize,
        /// Calls that are up: `InCall` only.
        pub in_call: usize,
        /// Dialogs that reached `Completed`.
        pub completed: usize,
        /// Dialogs that reached `Failed`.
        pub failed: usize,
        /// Dialogs that reached `Canceled`.
        pub canceled: usize,
    }

    /// Stream counts from `GET /v1/stats`.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StatsStreams {
        /// Streams tracked.
        pub total: usize,
        /// Streams no dialog claims.
        pub orphaned: usize,
    }

    /// Post-dial-delay percentiles from `GET /v1/stats`.
    ///
    /// Every member is `null` when no dialog has a PDD — an absent
    /// measurement, not a zero one.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StatsTiming {
        /// Median post-dial delay, milliseconds.
        pub pdd_p50_ms: Option<i64>,
        /// 95th-percentile post-dial delay, milliseconds.
        pub pdd_p95_ms: Option<i64>,
        /// 99th-percentile post-dial delay, milliseconds.
        pub pdd_p99_ms: Option<i64>,
    }

    /// How much of the wire every other count in `GET /v1/stats` is drawn
    /// from.
    ///
    /// Without it a total reads as a total when it may be a floor.
    #[derive(Debug, Clone, ToSchema)]
    pub struct StatsCaptureQuality {
        /// Packets the kernel dropped before sipnab saw them.
        pub kernel_dropped_packets: u64,
        /// Packets the interface dropped.
        pub interface_dropped_packets: u64,
        /// Frames carrying a timestamp that could not be believed.
        pub invalid_timestamps: u64,
        /// Frames sipnab could not decode at all.
        pub undecodable_frames: u64,
        /// Frames truncated by the capture snap length.
        pub snapped_frames: u64,
        /// NAT-keepalive requests that never drew a response.
        pub unanswered_nat_requests: u64,
        /// TURN allocations observed expiring.
        pub lapsed_turn_allocations: u64,
        /// Streams affected by a lapsed TURN allocation.
        pub lapsed_turn_allocation_streams: u64,
        /// ICE role conflicts observed.
        pub ice_role_conflicts: u64,
        /// Whether any of the above is non-zero.
        pub degraded: bool,
    }

    /// Which capture an answer came from, and which revision of its stores.
    ///
    /// Compare two of these to learn what changed: a different `instance`
    /// means a different capture, and every cursor, index and Call-ID from the
    /// earlier answer is meaningless; the same instance with a higher
    /// generation means the same capture grew.
    ///
    /// The SAME identity MCP's `capture_status` stamps its answers with, from
    /// the same object, so an agent and an HTTP client polling one process can
    /// tell they are describing one capture.
    #[derive(Debug, Clone, ToSchema)]
    pub struct CaptureIdentity {
        /// Which box saw this. Stable for the process; does not rotate with
        /// `instance`.
        pub node: String,
        /// Identifies the loaded capture. Opaque — compare it, never parse it.
        pub instance: String,
        /// Dialog-store mutations since it was created or cleared.
        pub dialog_generation: u64,
        /// Stream-store mutations since it was created or cleared.
        pub stream_generation: u64,
    }

    /// One of the busiest ports the port gate excluded.
    #[derive(Debug, Clone, ToSchema)]
    pub struct SkippedPort {
        /// The port.
        pub port: u16,
        /// SIP messages seen on it and set aside.
        pub messages: u64,
    }

    /// `GET /v1/stats` — the aggregate view.
    #[derive(Debug, Clone, ToSchema)]
    pub struct Stats {
        /// Wire-format version of this envelope.
        #[schema(example = 2)]
        pub schema_version: u32,
        /// Dialog counts by state.
        pub dialogs: StatsDialogs,
        /// Stream counts.
        pub streams: StatsStreams,
        /// What this capture DECLINED to do, beside what it lost. Always
        /// present and always complete: zero is a real answer, and a key that
        /// shows up only on a bad run is a key no client learns exists.
        pub caveats: serde_json::Value,
        /// WHICH capture these counts came from, and which revision of its
        /// stores. `null` when nobody told this server what it is attached to.
        pub capture_identity: Option<CaptureIdentity>,
        /// What the server is attached to. `unknown` is a real answer.
        pub source: String,
        /// Human name of the capture, when one is known.
        pub capture_name: Option<String>,
        /// Seconds since the capture started.
        pub uptime_sec: Option<u64>,
        /// Whether a file source has been read to the end.
        pub source_exhausted: bool,
        /// Path this capture is writing to, when it is writing.
        pub writing_to: Option<String>,
        /// True only for a LIVE capture with no output file: packets held in
        /// memory and nowhere else.
        pub unsaved: bool,
        /// SIP messages the port gate excluded before anything analyzed them.
        pub unanalysed_sip_messages: u64,
        /// The five busiest ports behind `unanalysed_sip_messages`. Widen
        /// `--portrange` to recover them.
        pub unanalysed_busiest_ports: Vec<SkippedPort>,
        /// SIP-over-WebSocket messages excluded by the WS port gate. Counted
        /// apart because widening `--portrange` recovers none of it;
        /// `--ws-portrange` does.
        pub unanalysed_websocket_messages: u64,
        /// The five busiest ports behind `unanalysed_websocket_messages`.
        pub unanalysed_websocket_ports: Vec<SkippedPort>,
        /// Post-dial-delay percentiles.
        pub timing: StatsTiming,
        /// How much of the wire the counts above are drawn from.
        pub capture_quality: StatsCaptureQuality,
    }

    /// `GET /v1/dialogs/{call_id}` — the full dialog.
    ///
    /// The projection `output::json::dialog_to_json` builds, which is a
    /// SUPERSET of [`DialogSummary`] and not the same shape: it carries the
    /// display names, the SDP timeline, the media diagnosis and the streams
    /// themselves. `tests/openapi_contract_test.rs` reads a real one off a
    /// running server and fails if a key here is missing from it, or one of
    /// its keys is missing from here.
    ///
    /// The nested objects are left open rather than enumerated. Their
    /// definitions live in `output::json`, and repeating them here would be
    /// the drift this document exists to remove; the live check is what holds
    /// the top level honest.
    #[derive(Debug, Clone, ToSchema)]
    pub struct Dialog {
        /// Wire-format version of this object.
        pub schema_version: u32,
        /// Call-ID identifying the dialog.
        pub call_id: String,
        /// User part of the From URI.
        pub from: Option<String>,
        /// User part of the To URI.
        pub to: Option<String>,
        /// Display name from the From header.
        pub from_display: Option<String>,
        /// Display name from the To header.
        pub to_display: Option<String>,
        /// Current dialog state.
        pub state: String,
        /// Final INVITE response code, once the call reached one.
        pub final_status_code: Option<u16>,
        /// Reason phrase that came with `final_status_code`.
        pub final_status_reason: Option<String>,
        /// SIP method that opened the dialog.
        pub method: String,
        /// SIP messages in the dialog.
        pub msg_count: usize,
        /// First to last message, seconds.
        pub duration_sec: f64,
        /// Labels the analysis attached to this dialog. Absent, not empty,
        /// when it attached none.
        pub tags: Option<Vec<String>>,
        /// Transaction timing, with the ring and teardown legs the summary
        /// omits.
        pub timing: serde_json::Value,
        /// Every SDP offer and answer, in order.
        pub sdp_timeline: Vec<serde_json::Value>,
        /// The media diagnosis: three booleans plus `hints`. There is no
        /// `summary` member.
        pub diagnosis: serde_json::Value,
        /// The signaling diagnosis, when one could be made.
        pub signaling_diagnosis: Option<serde_json::Value>,
        /// ICMP evidence bearing on the media, when any was seen.
        pub icmp_media: Option<serde_json::Value>,
        /// `<source>#<ordinal>` pointer to the frame this dialog opened in.
        pub frame: Option<String>,
        /// Capture source that delivered the opening message.
        pub input_origin: Option<String>,
        /// The RTP streams this dialog claims.
        pub streams: Vec<serde_json::Value>,
    }

    /// `GET /v1/dialogs/{call_id}/report` — the per-call analysis report.
    ///
    /// Marker only: the component is spliced from
    /// `tests/schemas/call_report.schema.json`, the schema
    /// `tests/json_schema_test.rs` validates real `--call-report --json`
    /// output against.
    #[derive(Debug, Clone, ToSchema)]
    pub struct CallReport {}

    /// `GET /v1/streams/{id}` — the full RTP stream.
    ///
    /// Marker only: the component is spliced from
    /// `tests/schemas/stream.schema.json`.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RtpStream {}

    /// `GET /v1/report` — the whole-capture analysis.
    ///
    /// Serialized from `crate::analysis::CaptureAnalysis` itself, never
    /// re-parsed out of a rendered report: `print_analysis_report_as` looks
    /// like it has a JSON arm and does not, and asking it for JSON is how this
    /// endpoint once returned 500.
    #[derive(Debug, Clone, ToSchema)]
    pub struct CaptureReport {
        /// Frames the capture read, from the same process-global the
        /// Prometheus scrape reports — so this denominator is the one every
        /// other number in the run is read against.
        pub frames_read: u64,
        /// Dialogs the analysis looked at.
        pub dialogs_examined: usize,
        /// Streams the analysis looked at.
        pub streams_examined: usize,
        /// Whether the analysis saw the whole capture. `false` means a
        /// retention cap shed something, and every count above is a floor.
        pub complete: bool,
        /// What the analysis found, across every dialog and stream.
        pub findings: Vec<serde_json::Value>,
    }

    /// `GET /v1/dialogs/{call_id}/vcon` — one observed dialog as an unsigned
    /// OBSERVER vCon container (draft-ietf-vcon-vcon-core).
    ///
    /// The container is serialized as a JSON OBJECT, not as `Vcon::to_json`'s
    /// string — a client must not have to parse JSON out of JSON.
    ///
    /// `tests/schemas/vcon.schema.json` is the working group's schema and is
    /// deliberately NOT reproduced here: it is theirs, it is draft-07, and its
    /// own text rejects a container shape the working group agreed to at IETF
    /// 124. This describes what sipnab sends.
    #[derive(Debug, Clone, ToSchema)]
    pub struct Vcon {
        /// Version of the vCon container format.
        pub vcon: String,
        /// UUIDv8 derived from the capture and the dialog, so one dialog
        /// exported through two doors carries one identity.
        pub uuid: String,
        /// RFC 3339 timestamp the container was built at.
        pub created_at: String,
        /// One-line subject for the conversation.
        pub subject: String,
        /// Present only on a container that redacts another.
        pub redacted: Option<serde_json::Value>,
        /// vCon extensions this container uses.
        pub extensions: Vec<String>,
        /// The parties, as the `From` and `To` headers said them — not
        /// identities anyone established.
        pub parties: Vec<serde_json::Value>,
        /// The dialog entries. Signaling only.
        pub dialog: Vec<serde_json::Value>,
        /// Attachments, including the completeness caveat.
        pub attachments: Vec<serde_json::Value>,
        /// The analysis bodies, carrying the same completeness caveat.
        pub analysis: Vec<serde_json::Value>,
    }
}

/// Adds the bearer scheme every route but `/health` requires.
///
/// A document that describes the routes and not the credential is a document a
/// reader cannot use: sipnab's API answers 401 to an unauthenticated request
/// on eleven of its twelve operations, and a reference that does not say so
/// sends every first-time caller into that 401.
struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "A self-describing signed `s1.` token \
                         (`--api-signing-key`), or the static `--api-key`. \
                         `/metrics` also accepts a token scoped to metrics \
                         alone, which reaches no other route.",
                    ))
                    .build(),
            ),
        );
    }
}

/// The OpenAPI 3.1 document for sipnab's REST surface.
///
/// # Why `info.version` is not the crate version
///
/// It is `1`, the version in the `/v1` path prefix, and it moves when the wire
/// contract does. Binding it to `CARGO_PKG_VERSION` would put a second version
/// marker in the tree that has to move on every release — and this repository
/// enforces its version markers in ONE place on purpose. A patch release that
/// changes no endpoint must not invalidate a client's cached contract.
///
/// # What is missing from this type alone
///
/// Three of the components it names are declared as open objects here and
/// filled in by the generator from `tests/schemas/`. Call
/// [`openapi_json`] for the document as this crate can build it; the published
/// artifact at `website/static/openapi.json` is that document with the shared
/// schemas spliced in, and `tests/openapi_contract_test.rs` is what keeps the
/// two in step.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "sipnab REST API",
        version = "1",
        description = "Read-only HTTP access to the dialogs, RTP streams, \
                       analysis and Prometheus metrics of a running sipnab \
                       capture, plus the one write the surface has: closing \
                       the persistence gate.\n\nThe server reads the same \
                       in-memory stores as the capture pipeline, in the same \
                       process. There is no database and no history: every \
                       answer describes the capture as it stands.",
        license(name = "MIT OR Apache-2.0"),
        contact(name = "sipnab", url = "https://sipnab.com")
    ),
    servers((url = "http://127.0.0.1:8080", description = "The default bind, which is loopback on purpose")),
    modifiers(&BearerAuth),
    paths(
        health_check,
        list_dialogs,
        get_dialog,
        get_dialog_report,
        get_persistence,
        set_persistence,
        list_streams,
        get_stream,
        get_capture_report,
        get_stats,
        get_metrics,
    ),
    components(schemas(
        schema::ProblemJson,
        schema::DialogList,
        schema::DialogSummary,
        schema::TimingSummary,
        schema::StreamList,
        schema::StreamSummary,
        schema::PersistenceState,
        PersistenceRequest,
        schema::Stats,
        schema::StatsDialogs,
        schema::StatsStreams,
        schema::StatsTiming,
        schema::StatsCaptureQuality,
        schema::SkippedPort,
        schema::CaptureIdentity,
        schema::Dialog,
        schema::CallReport,
        schema::RtpStream,
        schema::CaptureReport,
    )),
    tags(
        (name = "dialogs", description = "SIP dialogs the capture is tracking"),
        (name = "streams", description = "RTP streams the capture is tracking"),
        (name = "capture", description = "The capture as a whole"),
        (name = "operations", description = "Liveness, metrics, and the persistence gate")
    )
)]
pub struct ApiDoc;

/// The OpenAPI 3.1 document for the routes THIS BUILD serves, as JSON.
///
/// Feature-dependent by construction, and that is the point:
/// `/v1/dialogs/{call_id}/vcon` is registered by [`build_router`] only where
/// the exporter exists, and it appears here only under the same `cfg`. A
/// document that advertised a route the binary does not serve would be worse
/// than no document.
///
/// # Returns
///
/// The document, pretty-printed with a trailing newline so it survives a
/// text-mode diff.
///
/// # Panics
///
/// Never in practice: the value being serialized is built by `utoipa` out of
/// owned `String`s and numbers, which `serde_json` cannot fail on. The
/// `expect` is the honest way to say that — the alternative is a `Result` on
/// an infallible operation, which every caller would then have to pretend to
/// handle.
#[must_use]
pub fn openapi_json() -> String {
    use utoipa::OpenApi as _;

    #[cfg_attr(
        not(feature = "vcon"),
        expect(
            unused_mut,
            reason = "the vcon route is the only mutation, and it is cfg-gated"
        )
    )]
    let mut doc = ApiDoc::openapi();
    #[cfg(feature = "vcon")]
    doc.merge(VconDoc::openapi());

    #[expect(
        clippy::expect_used,
        reason = "a utoipa::openapi::OpenApi is owned Strings, numbers and \
                  String-keyed maps, none of which serde_json can fail on. A \
                  Result here would be an error case every caller has to \
                  pretend to handle"
    )]
    let mut out = serde_json::to_string_pretty(&doc).expect("OpenApi serializes");
    out.push('\n');
    out
}

/// The `vcon` route's half of the document.
///
/// A separate derive rather than a `cfg` inside `ApiDoc`'s `paths(...)`: that
/// list is a macro argument and cannot be gated item by item. [`build_router`]
/// gates the route itself the same way and for the same reason — a document
/// advertising a route the binary does not serve is worse than no document.
#[cfg(feature = "vcon")]
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_dialog_vcon), components(schemas(schema::Vcon)))]
struct VconDoc;

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

    /// PV11: an error carries an RFC 9457 body, not a bare status code.
    ///
    /// The previous behavior returned a [`StatusCode`] and no body at all, so
    /// a client got a number and had to guess which of a handler's several
    /// 400s it had hit.
    #[tokio::test]
    async fn an_error_response_is_rfc_9457_problem_json() {
        use axum::response::IntoResponse as _;
        use http_body_util::BodyExt as _;

        let response = Problem::detailed(
            StatusCode::BAD_REQUEST,
            "`since` is not an RFC 3339 instant",
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
            "RFC 9457 §3: the media type is what tells a generic client this \
             body describes a problem rather than the resource it asked for"
        );

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).expect("valid JSON");

        assert_eq!(
            body["type"], "https://sipnab.com/problems/bad-request",
            "`type` is the member a client branches on, and it must be \
             absolute: a relative URI resolves against the request, so two \
             deployments would give one problem two identities: {body}"
        );
        assert_eq!(body["title"], "Bad Request", "title names the KIND: {body}");
        assert_eq!(
            body["status"], 400,
            "the status is repeated in the body so it survives being logged \
             apart from its response: {body}"
        );
        assert_eq!(
            body["detail"], "`since` is not an RFC 3339 instant",
            "detail is about THIS occurrence: {body}"
        );
        assert!(
            body.get("instance").is_none(),
            "RFC 9457 makes `instance` optional and sipnab has no per-occurrence \
             URI to give; inventing one that resolves to nothing is worse than \
             omitting it: {body}"
        );
    }

    /// A problem with no detail still carries the three required members.
    #[tokio::test]
    async fn a_problem_without_detail_omits_it_rather_than_sending_a_placeholder() {
        use axum::response::IntoResponse as _;
        use http_body_util::BodyExt as _;

        let response = Problem::new(StatusCode::NOT_FOUND).into_response();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes();
        let body: Value = serde_json::from_slice(&bytes).expect("valid JSON");

        assert_eq!(body["type"], "https://sipnab.com/problems/not-found");
        assert_eq!(body["title"], "Not Found");
        assert_eq!(body["status"], 404);
        assert!(
            body.get("detail").is_none(),
            "an empty-string detail reads as `we have nothing to say about \
             this`, which is different from having nothing to add: {body}"
        );
    }

    /// One kind of failure has ONE `type` URI across every handler.
    ///
    /// The slug comes from the status rather than from free text at each call
    /// site, because a client branching on `type` is the entire point and two
    /// handlers spelling one problem differently would defeat it.
    #[test]
    fn every_status_maps_to_a_stable_problem_slug() {
        for (status, slug) in [
            (StatusCode::BAD_REQUEST, "bad-request"),
            (StatusCode::UNAUTHORIZED, "unauthorized"),
            (StatusCode::FORBIDDEN, "forbidden"),
            (StatusCode::NOT_FOUND, "not-found"),
            (StatusCode::TOO_MANY_REQUESTS, "rate-limited"),
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        ] {
            assert_eq!(
                Problem::new(status).slug(),
                slug,
                "{status} must map to one stable slug"
            );
            assert_eq!(
                Problem::detailed(status, "anything").slug(),
                slug,
                "detail describes an occurrence and must not change the KIND \
                 a client branches on"
            );
        }
    }

    /// Build an `ApiState` with empty stores and no auth configured.
    fn make_state() -> ApiState {
        ApiState {
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig::default(),
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100))),
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
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
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
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

    /// SIP the port gate excluded is on `/v1/stats`, under the SAME names MCP
    /// `capture_status` uses, and the busiest ports come with it.
    ///
    /// The loss this catches is the largest one this project has measured: on
    /// the corpus, 2,311 dialogs against 3,712 real -- 37.7% gone, because a
    /// third of the SIP never touches 5060/5061. Nothing was dropped and
    /// nothing failed to decode, so `capture_quality` is clean and
    /// `dialogs.total` reads as "how much was there". A capture missing a third
    /// of its calls renders identically to one that only had two-thirds.
    ///
    /// The ports travel with the count because the answer has to name its own
    /// remedy: they are literally what an operator writes into `--portrange`.
    /// A bare number tells a reader something is wrong and not where to look.
    ///
    /// Driven through the REAL gate rather than by poking the tally, so this
    /// also proves the endpoint reads the counter the pipeline actually writes.
    /// `serial`, because that counter is process-global and shared with every
    /// other test in this binary.
    #[tokio::test]
    #[serial_test::serial(portrange_skips)]
    async fn stats_reports_sip_the_port_gate_excluded_and_where_it_was() {
        use crate::capture::parse::TransportProto;

        crate::pipeline::reset_portrange_skips();

        let app = build_router(make_state());
        let stats = |app: axum::Router| async move {
            let body = body_to_string(
                app.oneshot(test_request("/v1/stats"))
                    .await
                    .expect("oneshot")
                    .into_body(),
            )
            .await;
            serde_json::from_str::<Value>(&body).expect("valid JSON")
        };

        let v = stats(app.clone()).await;
        // Present at ZERO. A key that shows up only on a bad capture is a key
        // no client learns exists, and a dashboard cannot ask for a field it
        // has never seen.
        for key in [
            "unanalysed_sip_messages",
            "unanalysed_busiest_ports",
            "unanalysed_websocket_messages",
            "unanalysed_websocket_ports",
        ] {
            assert!(v.get(key).is_some(), "`{key}` missing from /v1/stats: {v}");
        }
        assert_eq!(v["unanalysed_sip_messages"], 0);
        assert!(
            v["unanalysed_busiest_ports"]
                .as_array()
                .expect("array")
                .is_empty()
        );

        // One OPTIONS to a SIP service on 8090, with the gate set to 5060-5061.
        // The pipeline recognizes it as SIP, declines it, and counts it.
        let sip = b"OPTIONS sip:probe@test SIP/2.0\r\nCall-ID: oor@test\r\nCSeq: 1 OPTIONS\r\n\r\n";
        let pp = crate::capture::ParsedPacket {
            frame_bytes: None,
            frame: None,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("ts"),
            src_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 41000,
            dst_port: 8090,
            transport: TransportProto::Udp,
            payload: sip.to_vec().into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
        };
        let gated = crate::pipeline::PipelineOptions {
            sip_portrange: Some((5060, 5061)),
            ..Default::default()
        };
        let mut decrypt = crate::pipeline::MediaDecrypt::default();
        let mut heuristic = crate::rtp::heuristic::RtpHeuristic::default();
        let action = crate::pipeline::classify_packet(&pp, &mut heuristic, &gated, &mut decrypt);
        assert!(
            matches!(action, crate::pipeline::PacketAction::None),
            "the gate must still skip -- --portrange means what it says"
        );

        let v = stats(app).await;
        assert_eq!(
            v["unanalysed_sip_messages"], 1,
            "the skipped SIP did not reach the response: {v}"
        );
        assert_eq!(
            v["unanalysed_busiest_ports"][0]["port"], 8090,
            "the count arrived without the port an operator needs. The service \
             port is a request's DESTINATION, not the ephemeral client port: {v}"
        );
        assert_eq!(v["unanalysed_busiest_ports"][0]["messages"], 1);

        crate::pipeline::reset_portrange_skips();
    }

    /// The declined-work count is on `/v1/stats`, present at zero, and moves
    /// when a media-creating command goes past.
    ///
    /// Zero is the assertion that matters most here. A key that appears only
    /// once something has gone wrong is a key no client learns exists, and a
    /// dashboard cannot ask about a field it has never seen. The second half
    /// then proves the key is wired to the tally rather than to the literal 0
    /// that would satisfy the first half on its own.
    #[tokio::test]
    async fn stats_reports_declined_work_at_zero_and_when_it_happens() {
        let before = crate::relay::media_creating_commands_seen();

        let app = build_router(make_state());
        let parsed: Value = serde_json::from_str(
            &body_to_string(
                app.clone()
                    .oneshot(test_request("/v1/stats"))
                    .await
                    .expect("oneshot")
                    .into_body(),
            )
            .await,
        )
        .expect("valid JSON");
        assert_eq!(
            parsed["caveats"]["media_creating_commands"], before,
            "the count must be present and complete on an ordinary response: {}",
            parsed["caveats"]
        );

        // The tally is process-global and shared with every other test in this
        // binary, so this asserts a DELTA rather than an absolute -- an exact
        // figure here would be true only until the next test ran.
        crate::relay::note_media_creating_command();

        let parsed: Value = serde_json::from_str(
            &body_to_string(
                app.oneshot(test_request("/v1/stats"))
                    .await
                    .expect("oneshot")
                    .into_body(),
            )
            .await,
        )
        .expect("valid JSON");
        let after = parsed["caveats"]["media_creating_commands"]
            .as_u64()
            .expect("the count is a number");
        assert!(
            after > before,
            "a media-creating command went past and the count did not move \
             ({before} -> {after}); the key is wired to nothing"
        );
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
        assert_eq!(parsed["schema_version"], 2);
        assert!(parsed["dialogs"].is_object());
        assert!(parsed["streams"].is_object());
        assert!(parsed["timing"].is_object());
        assert_eq!(parsed["dialogs"]["total"], 3);
        assert!(parsed["dialogs"]["active"].is_number());
        assert!(
            parsed["dialogs"]["in_call"].is_number(),
            "the concurrent-call figure must be its own key, not left to be \
             inferred from dialogs.active: {parsed}"
        );
        assert!(parsed["streams"]["orphaned"].is_number());
    }

    /// `/v1/stats` carries a capture-quality block naming the three losses
    /// separately, plus the one flag that says whether the counts above
    /// describe the whole capture.
    ///
    /// Present on every response, including a clean one. A block that
    /// appeared only when something had gone wrong would be a block no
    /// client learns exists, and the client here is frequently an agent that
    /// cannot ask a follow-up question.
    #[tokio::test]
    async fn stats_reports_capture_quality_separately() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/stats"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        let q = &parsed["capture_quality"];
        assert!(q.is_object(), "capture_quality missing from {body}");
        for field in [
            "kernel_dropped_packets",
            "interface_dropped_packets",
            "invalid_timestamps",
            // Frames that arrived intact and decoded to nothing. A zero
            // dialog count means opposite things with and without this.
            "undecodable_frames",
            // A snaplen cut these short: they arrived, and the payload did
            // not. Distinct from loss, and from a decode failure.
            "snapped_frames",
            // About the NETWORK, not the capture: STUN/TURN transactions sent
            // with no reply. An agent reading a one-way-audio complaint needs
            // this, and it used to exist only as a log line.
            "unanswered_nat_requests",
            // Also about the NETWORK: a relay torn down mid-call, which has no
            // other symptom anywhere — no SIP message says the media stopped.
            "lapsed_turn_allocations",
            // How much audio was ON those relays when they were torn down. One
            // lapsed allocation carrying nothing and one carrying four calls
            // rendered identically until relayed media became attributable.
            "lapsed_turn_allocation_streams",
            // Two ICE agents that both claimed to be controlling. ICE can
            // resolve it; a fleet where it happens constantly is misconfigured
            // whether or not any single call survived it.
            "ice_role_conflicts",
        ] {
            assert!(
                q[field].is_u64(),
                "capture_quality.{field} must be a count, got {:?}",
                q[field]
            );
        }
        assert!(
            q["degraded"].is_boolean(),
            "capture_quality.degraded must be a boolean, got {:?}",
            q["degraded"]
        );
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
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
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

    /// A cap of `0` disables the limiter rather than refusing everything.
    ///
    /// The convention `--mcp-rate-limit-per-peer`, `--hep-rate-limit-per-peer`
    /// and `--hep-rate-limit` all carry, reachable here only since the figure
    /// became `--api-rate-limit-per-peer`: an operator who spells "unlimited"
    /// the way sipnab taught them must not lock themselves out of the API.
    #[test]
    fn a_zero_cap_disables_the_limiter_rather_than_refusing_everything() {
        let mut limiter = RateLimiter::new(0);
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        for i in 0..10_000 {
            assert!(
                limiter.check(ip),
                "request {i} must pass an uncapped limiter"
            );
        }
    }

    /// `GET /v1/dialogs` returns at most the configured row ceiling, whatever
    /// the caller asks for.
    ///
    /// The response ceiling used to be a hard-coded 1000, so a batch consumer
    /// piping the endpoint to a file could never exceed it and a dashboard
    /// could never tighten it. Asserted on the rows themselves rather than on
    /// the echoed `limit`, because a wiring that only moved the echo would
    /// still hand back a thousand rows.
    #[tokio::test]
    async fn the_row_ceiling_bounds_a_list_response_however_much_is_asked_for() {
        let mut state = make_state();
        state.max_rows = 2;
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?limit=1000"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            json["total"], 3,
            "the fixture must hold more dialogs than the ceiling, or the case \
             proves nothing"
        );
        assert_eq!(
            json["dialogs"].as_array().expect("dialogs array").len(),
            2,
            "the configured ceiling must bound the rows returned"
        );
        assert_eq!(json["limit"], 2, "and the response must report it");
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

    /// `/v1/stats` names WHICH capture its counts came from, and says
    /// `unknown` when nobody told it.
    ///
    /// The identity pairs the instance with BOTH store generations, so it is
    /// only honest if the instance and the two generations describe one
    /// moment. This handler used to release the dialog guard before taking the
    /// stream guard -- survivable while nothing tied the counts together, and
    /// not survivable once a single etag claims they belong to each other. The
    /// three guards are now held across the read, in the order `CaptureState`
    /// documents and MCP takes them.
    ///
    /// The `None` arm is asserted first because it is the one a REST-only
    /// deployment actually hits, and because `unknown` is a real answer rather
    /// than a default: it is what a reader consults before deciding whether
    /// stopping a capture is destructive, and a wrong `"live"` would be worse
    /// than an admission of ignorance.
    #[tokio::test]
    async fn stats_names_the_capture_or_admits_it_does_not_know() {
        let app = build_router(make_state());
        let v: Value = serde_json::from_str(
            &body_to_string(
                app.oneshot(test_request("/v1/stats"))
                    .await
                    .expect("oneshot")
                    .into_body(),
            )
            .await,
        )
        .expect("valid JSON");

        assert_eq!(
            v["source"], "unknown",
            "a server nobody described must say so rather than guess: {v}"
        );
        assert!(
            v["capture_identity"].is_null(),
            "there is no capture to identify, and an identity here would name \
             one that does not exist: {v}"
        );
        assert_eq!(
            v["unsaved"], false,
            "an unknown source holds nothing, and reporting it as unsaved would \
             make every shutdown look destructive: {v}"
        );
        // Present at null rather than omitted, for the reason every optional
        // key on this endpoint is: a field that appears only sometimes is a
        // field no client learns exists.
        for key in [
            "capture_name",
            "uptime_sec",
            "writing_to",
            "source_exhausted",
        ] {
            assert!(v.get(key).is_some(), "`{key}` missing from /v1/stats: {v}");
        }
    }

    /// With a capture, `/v1/stats` reports the identity from the SHARED object
    /// -- the same one MCP stamps its answers with.
    ///
    /// This is what the whole change is for. A copy would have been simpler
    /// and wrong: the identity ROTATES when `open_capture` swaps the file
    /// underneath, and two copies disagree from that moment on. A client
    /// comparing an MCP answer against this one would be told the capture
    /// changed when it had not, or that it had not when it did.
    ///
    /// So the test rotates the shared state and requires the endpoint to
    /// follow. Reading the identity once proves only that a field exists.
    #[tokio::test]
    async fn stats_follows_a_rotation_of_the_shared_capture() {
        use crate::capture::session::{CaptureContext, CaptureState};

        let capture = Arc::new(RwLock::new(CaptureState::describing(CaptureContext {
            live: true,
            name: "eth0".into(),
            started: std::time::Instant::now(),
            writing_to: None,
        })));
        let mut state = make_state();
        state.capture = Some(Arc::clone(&capture));
        let app = build_router(state);

        let read = |app: axum::Router| async move {
            let body = body_to_string(
                app.oneshot(test_request("/v1/stats"))
                    .await
                    .expect("oneshot")
                    .into_body(),
            )
            .await;
            serde_json::from_str::<Value>(&body).expect("valid JSON")
        };

        let before = read(app.clone()).await;
        assert_eq!(before["source"], "live");
        assert_eq!(before["capture_name"], "eth0");
        assert_eq!(
            before["unsaved"], true,
            "a live capture with no output file holds packets that exist \
             nowhere else: {before}"
        );
        // An OBJECT, not a string: node, instance and both store generations,
        // the same four fields MCP `capture_status` publishes under this key.
        // The instance is the half a swap changes.
        for key in ["node", "instance", "dialog_generation", "stream_generation"] {
            assert!(
                before["capture_identity"].get(key).is_some(),
                "`capture_identity.{key}` missing -- the etag must pair the \
                 instance with BOTH generations, or a client cannot tell a \
                 capture that grew from one that was swapped: {before}"
            );
        }
        let first = before["capture_identity"]["instance"]
            .as_str()
            .expect("a described capture has an instance")
            .to_string();

        // STABILITY FIRST, and this is the assertion that does the work.
        //
        // "the identity changed after a rotation" is satisfied by any handler
        // that mints a fresh identity per request -- exactly the private-copy
        // design this change exists to avoid. Only the unchanged case
        // distinguishes reading the shared object from inventing one: two
        // reads with nothing in between must be identical.
        //
        // Found by mutation. The rotation assertion alone passed against a
        // handler calling `CaptureIdentity::new()` on every request.
        let again = read(app.clone()).await;
        assert_eq!(
            again["capture_identity"]["instance"], first,
            "two reads with no swap between them returned different instances, \
             so this endpoint is minting an identity rather than reading the \
             one the capture holds: {again}"
        );

        // What `open_capture` does: a different capture is now loaded.
        capture.write().identity.rotate();

        let after = read(app).await;
        let second = after["capture_identity"]["instance"]
            .as_str()
            .expect("still identified")
            .to_string();
        assert_ne!(
            first, second,
            "the endpoint is reading its own copy of the identity, so a swap \
             MCP performed would be invisible here and the two doors would \
             disagree about which capture they describe"
        );
    }

    /// `GET /v1/report` answers for the whole capture, and says what it could
    /// not see.
    ///
    /// The per-call route below answers for one Call-ID. This is the view that
    /// names orphaned media, STUN and ICMP evidence, and what the retention
    /// caps shed -- the things belonging to no single dialog and therefore
    /// invisible to every other REST route.
    ///
    /// Asserted as STRUCTURED JSON, not a string. The generator returns a
    /// String and the handler re-parses it; a handler that forgot to would
    /// still return 200 with a body that looks like JSON to a human and is a
    /// quoted blob to a parser.
    #[tokio::test]
    async fn the_capture_report_is_answerable_over_rest() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/report"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK, "/v1/report status");

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            parsed.is_object(),
            "the report must be an object a client can read fields out of, not \
             a stringified blob it has to parse a second time: {body}"
        );
        // The facts that make this a capture-level answer rather than a sum of
        // per-call ones. `complete` is the honesty flag: a findings list built
        // from a capture that lost packets is a FLOOR, and a reader who does
        // not know that reads it as a total.
        for key in ["dialogs_examined", "streams_examined", "complete"] {
            assert!(
                parsed.get(key).is_some(),
                "`{key}` missing -- the report must say what it looked at and \
                 whether it saw all of it: {parsed}"
            );
        }
        assert_eq!(
            parsed["dialogs_examined"], 3,
            "the report must describe the store it was built from: {parsed}"
        );
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

    /// `GET /v1/dialogs/:call_id/vcon` returns the container as an OBJECT,
    /// carrying the syntax version and the Call-ID it was built from.
    ///
    /// The object check is the half with teeth. `Vcon::to_json` exists and
    /// returns a `String`, so the shortest handler that compiles hands back a
    /// stringified blob — and a client then parses JSON out of JSON, which is
    /// exactly the mistake `get_capture_report` was written to correct after
    /// MCP had been serving text under a `format: "json"` default.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn dialog_vcon_returns_a_container_object() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/call-1@test/vcon"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            parsed.is_object(),
            "the container must be an object a client reads fields out of, \
             not a string it parses a second time: {body}"
        );
        assert_eq!(
            parsed["vcon"],
            crate::output::vcon::VCON_SYNTAX_VERSION,
            "the syntax version names the draft the layout was written \
             against; a consumer keys its parser on it: {parsed}"
        );
        assert_eq!(
            parsed["dialog"][0]["sip_call_id"], "call-1@test",
            "the container must name the Call-ID it was built from: {parsed}"
        );
    }

    /// The completeness caveat reaches BOTH surfaces through this door.
    ///
    /// The caveat is the whole reason an observer vCon is defensible, and
    /// `export_dialog` duplicates it into the analysis body and an attachment
    /// on purpose. A handler that serialized some narrower projection —
    /// `DialogSummary`, a hand-built object, the analysis alone — would still
    /// pass every shape assertion above while shipping a container that reads
    /// as a complete record of the call.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn dialog_vcon_carries_the_completeness_caveat_on_both_surfaces() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/call-1@test/vcon"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let parsed: Value =
            serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON");

        let attachment = parsed["attachments"]
            .as_array()
            .expect("attachments array")
            .iter()
            .find(|a| a["purpose"] == crate::output::vcon::COMPLETENESS_PURPOSE)
            .unwrap_or_else(|| panic!("no completeness attachment: {parsed}"));
        // §2.3.2 makes `body` a String, so both reads parse it rather than
        // indexing a `Value` that is not an object.
        let attachment_body: serde_json::Value = serde_json::from_str(
            attachment["body"]
                .as_str()
                .expect("a json body is a string"),
        )
        .expect("the attachment body parses");
        let from_attachment = attachment_body["note"]
            .as_str()
            .unwrap_or_else(|| panic!("attachment note is not a string: {parsed}"));
        let analysis_body: serde_json::Value = serde_json::from_str(
            parsed["analysis"][0]["body"]
                .as_str()
                .expect("a json body is a string"),
        )
        .expect("the analysis body parses");
        let from_analysis = analysis_body["capture_completeness"]["note"]
            .as_str()
            .unwrap_or_else(|| panic!("analysis note is not a string: {parsed}"));

        assert_eq!(
            from_attachment, from_analysis,
            "two caveats that disagree read as authoritative while \
             contradicting each other, which is worse than carrying none"
        );
        // NOT "SIGNALING ONLY" any more. This door attempts media like the
        // other two since 0.5.125, so the caveat states what the run actually
        // MEASURED about media rather than a fixed claim that it carries none.
        // What must never soften is the observer clause: it is the sentence
        // that stops a reader taking an observation for a recording.
        assert!(
            from_attachment.contains("OBSERVED"),
            "the caveat must say sipnab watched this call rather than took \
             part in it: {from_attachment}"
        );
        assert!(
            from_attachment.contains("nothing here is signed"),
            "the caveat must say sipnab signed nothing: {from_attachment}"
        );
        assert!(
            analysis_body["capture_completeness"]["media"].is_string(),
            "the container must SAY what happened to media rather than leave \
             a reader to infer it from an absence: {analysis_body}"
        );
        assert!(
            analysis_body["capture_completeness"]["blind_spots"].is_array(),
            "this door runs the capture analysis, so `blind_spots` must be a \
             list and not absent — absent means NOBODY LOOKED, and an export \
             that skipped the analysis would then read as a clean one: {parsed}"
        );
    }

    /// An unknown Call-ID is a 404, matching every other per-call route.
    ///
    /// The alternative a handler falls into is a 200 carrying an empty or
    /// default container, which a client cannot tell from a real observation
    /// of a call that had no messages.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn unknown_call_id_has_no_vcon() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/does-not-exist@nowhere/vcon"))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "an unknown Call-ID must 404 rather than return an empty container"
        );
    }

    /// Two different dialogs export two different containers.
    ///
    /// Without this a handler that ignores its `call_id` and always exports
    /// the first dialog in the store passes both the success and the 404 case
    /// above, and every client silently receives one call's record under every
    /// other call's URL.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn two_dialogs_export_two_different_containers() {
        let state = make_state();
        populate_dialogs(&state);

        let mut seen = Vec::new();
        for call_id in ["call-0@test", "call-1@test"] {
            let app = build_router(state.clone());
            let resp = app
                .oneshot(test_request(&format!("/v1/dialogs/{call_id}/vcon")))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "{call_id} status");
            let parsed: Value =
                serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON");
            seen.push((
                parsed["dialog"][0]["sip_call_id"].clone(),
                parsed["uuid"].clone(),
            ));
        }

        assert_eq!(seen[0].0, "call-0@test", "first container names its call");
        assert_eq!(seen[1].0, "call-1@test", "second container names its call");
        assert_ne!(
            seen[0].1, seen[1].1,
            "two conversations must not share a uuid — a consumer keyed on it \
             would keep one and discard the other: {seen:?}"
        );
    }

    /// Re-exporting ONE dialog returns the SAME uuid.
    ///
    /// The assertion that discriminates, and the one the other tests cannot
    /// make. "The containers differ" passes against a handler that stamps
    /// something fresh per request — a rotated capture instance, a random id,
    /// the export clock — and a consumer deduplicating on `uuid` then
    /// accumulates one copy of the conversation per poll. `created_at` is
    /// deliberately NOT asserted stable: it records when the container was
    /// written and legitimately moves.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn re_exporting_one_dialog_keeps_its_uuid() {
        let state = make_state();
        populate_dialogs(&state);

        let mut uuids = Vec::new();
        for _ in 0..2 {
            let app = build_router(state.clone());
            let resp = app
                .oneshot(test_request("/v1/dialogs/call-1@test/vcon"))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);
            let parsed: Value =
                serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON");
            uuids.push(parsed["uuid"].clone());
        }

        assert_eq!(
            uuids[0], uuids[1],
            "one dialog out of one capture is one container, however many \
             times it is asked for: {uuids:?}"
        );
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
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
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
                Err(p) if p.status == StatusCode::SERVICE_UNAVAILABLE => {
                    saw_rate_limit = true;
                    break;
                }
                Err(p) if p.status == StatusCode::UNAUTHORIZED => {} // still under budget
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
        // PT 0 is PCMU, which G.113 publishes an impairment value for -- so
        // every stream built by this helper carries a GROUNDED MOS. Tests that
        // need the other case say so by naming a payload type.
        add_stream_with_pt(state, ssrc, src_port, dst_port, 0);
    }

    /// `add_stream`, with the RTP payload type spelled out.
    ///
    /// Exists because grounding is decided by the codec and nothing else: a
    /// dynamic payload type with no SDP to name it leaves `codec` unknown, and
    /// an unknown codec scores the placeholder. That is the stream a
    /// `mos_below` bound must refuse to select.
    fn add_stream_with_pt(state: &ApiState, ssrc: u32, src_port: u16, dst_port: u16, pt: u8) {
        use crate::capture::parse::TransportProto;
        use crate::rtp::parser::RtpHeader;

        let parsed = crate::capture::ParsedPacket {
            frame_bytes: None,
            frame: None,
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
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
            hep: None,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: pt,
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

    /// `orphaned=` selects on whether a dialog claims the stream, in both
    /// directions, and `total` reflects the filtered result-set rather than
    /// the store size.
    ///
    /// The fixture used to rely on "freshly-created streams are not orphaned",
    /// which was true only because the orphan flag waited 30 seconds — so
    /// `orphaned=true` on a store of nothing but unclaimed streams answered
    /// with an empty list. Orphan status is now `associated_dialog.is_none()`,
    /// so the two arms below are a real partition of the store.
    #[tokio::test]
    async fn list_streams_orphaned_filter_selects_by_dialog_association() {
        let state = make_state();
        add_stream(&state, 0x3333_3333, 21000, 31000);
        add_stream(&state, 0x4444_4444, 21002, 31002);
        // One of the two is claimed by a dialog; the other never is.
        state.stream_store.write().link_to_dialog(
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            31002,
            "claimed@example.invalid",
        );
        let app = build_router(state);

        for (query, expected_ssrc) in [
            ("/v1/streams?orphaned=true", "0x33333333"),
            ("/v1/streams?orphaned=false", "0x44444444"),
        ] {
            let resp = app
                .clone()
                .oneshot(test_request(query))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK);

            let body = body_to_string(resp.into_body()).await;
            let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
            let rows = parsed["streams"].as_array().expect("array");
            assert_eq!(rows.len(), 1, "{query} returned {}", parsed["streams"]);
            assert_eq!(rows[0]["ssrc"], expected_ssrc, "{query} selected wrongly");
            // total reflects the filtered result-set (1), not the store's 2.
            assert_eq!(parsed["total"], 1, "{query} reported the store size");
        }
    }

    /// A `mos_below` bound selects only streams whose MOS is a MEASUREMENT,
    /// and reports how many it held back for want of one.
    ///
    /// The bug this pins: a codec sipnab has no impairment value for still
    /// scores a number, because every surface showing MOS predates the
    /// distinction and a sudden `Option` would break four of them at once.
    /// That number is a placeholder standing in for "unknown". Applied without
    /// a grounding test, `?mos_below=5.0` therefore returned every unscoreable
    /// stream in the store dressed as a bad call -- and an operator triaging a
    /// bridge would work the list top to bottom, chasing streams whose quality
    /// nobody ever measured.
    ///
    /// MCP has tested this since `min_mos` existed. REST had not, which is the
    /// whole reason both now decide through `quality::mos_is_grounded`.
    ///
    /// Two streams, identical but for the payload type: PT 0 is PCMU and
    /// grounded; PT 96 is dynamic with no SDP to name it, so the codec is
    /// unknown and the score is the placeholder. A bound generous enough to
    /// admit both on the number alone must admit exactly one.
    #[tokio::test]
    async fn mos_below_refuses_to_select_on_a_placeholder_and_counts_what_it_held_back() {
        let state = make_state();
        add_stream_with_pt(&state, 0x5555_5555, 23000, 33000, 0);
        add_stream_with_pt(&state, 0x6666_6666, 23002, 33002, 96);
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(test_request("/v1/streams?mos_below=5.0"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let parsed: Value =
            serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON");

        let rows = parsed["streams"].as_array().expect("array");
        assert_eq!(
            rows.len(),
            1,
            "a bound below 5.0 admitted the ungrounded stream: {}",
            parsed["streams"]
        );
        assert_eq!(
            rows[0]["ssrc"], "0x55555555",
            "the wrong stream survived the bound"
        );
        assert!(
            rows[0]["mos_grounded"].as_bool().expect("mos_grounded"),
            "a row a MOS bound admitted must carry a grounded MOS"
        );
        assert_eq!(rows[0]["mos_grounding"], "published");
        assert!(
            rows[0].get("mos_note").is_none(),
            "a published score has no caveat to disclose: {}",
            rows[0]
        );
        assert_eq!(parsed["total"], 1, "total must count the filtered set");
        assert_eq!(
            parsed["ungrounded_excluded"], 1,
            "the stream the bound could not score must be counted, not silently \
             dropped -- four rows out of a store where sixty were unscoreable is \
             a different answer from four out of four"
        );
    }

    /// Without a bound there is nothing to hold back, and every row still says
    /// what its MOS is worth.
    ///
    /// The counterpart to the test above, and the one that keeps its number
    /// honest: a `ungrounded_excluded` that counted ungrounded streams
    /// regardless of whether anything was filtered would report a store's
    /// codec mix as an exclusion, on a request that excluded nothing.
    #[tokio::test]
    async fn an_unbounded_list_holds_nothing_back_and_still_grounds_every_row() {
        let state = make_state();
        add_stream_with_pt(&state, 0x7777_7777, 24000, 34000, 96);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/streams"))
            .await
            .expect("oneshot");
        let parsed: Value =
            serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON");

        assert_eq!(parsed["schema_version"], 2);
        assert_eq!(
            parsed["ungrounded_excluded"], 0,
            "nothing was bounded, so nothing was held back"
        );
        let row = &parsed["streams"][0];
        assert_eq!(row["ssrc"], "0x77777777");
        assert_eq!(
            row["mos_grounded"], false,
            "an unknown codec has no published impairment value"
        );
        assert_eq!(row["mos_grounding"], "unpublished");
        assert!(
            row["mos_note"]
                .as_str()
                .expect("an ungrounded score owes the reader a sentence")
                .contains("placeholder"),
            "the note must say the number is a placeholder: {row}"
        );
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
                    frame_bytes: None,
                    frame: None,
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
                    dscp: None,
                    input_origin: crate::capture::parse::InputOrigin::Wire,
                    hep: None,
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

        // No SDP named either stream, so no dialog claims them and
        // `orphaned=false` excludes both.
        let resp = app
            .oneshot(test_request("/v1/streams?orphaned=false"))
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
        let mos = approximate_mos(s, quality::MosDelay::from_capture(&ss));
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

    /// The REST stream row CARRIES a round trip when the store has one, and
    /// omits the key when it does not.
    ///
    /// Behavioral on purpose. The parity gate in `tests/surface_parity_test.rs`
    /// scans source text, and once its REST scope had to include
    /// `src/output/model.rs` — which is where the field is DECLARED — it could
    /// no longer tell a populated field from a declared one. Deleting
    /// `.with_round_trip(...)` from `stream_summary` left that gate green, which
    /// a mutation run caught and is the only reason this test exists.
    ///
    /// A text scan cannot express "the handler fills this in". This can.
    #[test]
    fn stream_summary_carries_a_round_trip_when_one_was_reported() {
        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport, RtcpPacket};

        let state = make_state();
        add_stream(&state, 0x7777_7777, 29000, 39000);

        let seen_at = chrono::DateTime::from_timestamp(1_700_000_100, 0).expect("ts");
        {
            let mut ss = state.stream_store.write();
            ss.process_rtcp(
                &[RtcpPacket::ReceiverReport(ReceiverReport {
                    ssrc: 0x9999,
                    reports: vec![ReceptionReport {
                        ssrc: 0x7777_7777,
                        fraction_lost: 0,
                        cumulative_lost: 0,
                        highest_seq: 10,
                        jitter: 5,
                        last_sr: crate::rtp::rtcp::compact_ntp_for_test(
                            seen_at - chrono::TimeDelta::milliseconds(120),
                        ),
                        delay_since_sr: 0,
                    }],
                })],
                seen_at,
            );
        }

        let ss = state.stream_store.read();
        let s = ss.iter().next().expect("one stream");
        let v = stream_summary(s, &ss);

        let ms = v["round_trip_ms"].as_f64().unwrap_or_else(|| {
            panic!("the REST row must carry the round trip the store resolved: {v}")
        });
        assert!(
            (ms - 120.0).abs() < 2.0,
            "expected ~120 ms from the SR echo, got {ms}"
        );
        assert_eq!(v["round_trip_source"], "sender_report_echo");
    }

    /// A stream nobody reported on omits the key rather than reporting 0 ms.
    #[test]
    fn stream_summary_omits_the_round_trip_when_nothing_measured_one() {
        let state = make_state();
        add_stream(&state, 0x6666_6666, 27000, 37000);
        let ss = state.stream_store.read();
        let s = ss.iter().next().expect("one stream");
        let v = stream_summary(s, &ss);

        assert!(
            v.get("round_trip_ms").is_none(),
            "no RTCP means no latency figure, and an absent key is not 0 ms: {v}"
        );
        // Anti-vacuity: the row is otherwise populated, so the absence above is
        // about the round trip and not about an empty summary.
        assert!(v["jitter_ms"].is_number() && v["mos"].is_number());
    }

    /// `stream_summary` emits `0x`-prefixed SSRC, numeric MOS, and
    /// `orphaned`.
    #[test]
    fn stream_summary_shape() {
        let state = make_state();
        add_stream(&state, 0x8888_8888, 28000, 38000);
        let ss = state.stream_store.read();
        let s = ss.iter().next().expect("one stream");
        let summary = stream_summary(s, &ss);
        assert_eq!(summary["ssrc"], "0x88888888");
        assert!(summary["mos"].is_number());
        // No SDP named this stream, so no dialog claims it — which is what
        // `orphaned` reports. It read `false` here while the flag waited out a
        // 30-second timeout that a test never advances past.
        assert_eq!(summary["orphaned"], true);
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

    // ── The persistence runtime gate ────────────────────────────────

    /// A gate-carrying state with a static bearer key.
    fn make_state_with_gate(gate: &Arc<crate::output::persistence::PersistenceGate>) -> ApiState {
        ApiState {
            persistence_gate: Arc::clone(gate),
            ..make_state_with_key(GATE_KEY)
        }
    }

    /// The bearer key every persistence test authenticates with.
    const GATE_KEY: &str = "gate-test-key";

    fn test_post(uri: &str, body: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .expect("build request");
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            12345,
        )));
        req
    }

    fn test_post_with_key(uri: &str, body: &str, key: &str) -> Request<Body> {
        let mut req = test_post(uri, body);
        req.headers_mut().insert(
            "authorization",
            format!("Bearer {key}").parse().expect("header value"),
        );
        req
    }

    fn test_get_with_key(uri: &str, key: &str) -> Request<Body> {
        test_request_with_header(uri, "authorization", &format!("Bearer {key}"))
    }

    async fn json_of(resp: axum::response::Response) -> Value {
        serde_json::from_str(&body_to_string(resp.into_body()).await).expect("valid JSON")
    }

    /// A control that stops call content reaching disk is not public.
    ///
    /// It is on the same guard as every other route, and this pins that: the
    /// route was added by hand and a forgotten `guard(...)` would leave an
    /// unauthenticated caller able to switch recording off on a production
    /// capture.
    #[tokio::test]
    async fn the_persistence_route_requires_the_api_key() {
        let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
        let app = build_router(make_state_with_gate(&gate));

        let resp = app
            .clone()
            .oneshot(test_post("/v1/persistence", r#"{"enabled":false}"#))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            gate.writes_permitted(),
            "a refused request must not have moved the gate"
        );

        let resp = app
            .oneshot(test_request("/v1/persistence"))
            .await
            .expect("oneshot");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "reading the gate is as guarded as moving it: it reports whether \
             this capture is writing content"
        );
    }

    /// Closing over REST is visible to the next read, and to the exporter.
    ///
    /// The second assertion is the one that matters. The handler and the
    /// exporter hold `Arc` clones of one gate; a state that had copied it
    /// would pass the round-trip and still write containers.
    #[tokio::test]
    async fn closing_the_gate_over_rest_reaches_the_exporter() {
        let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
        let app = build_router(make_state_with_gate(&gate));

        let resp = app
            .clone()
            .oneshot(test_post_with_key(
                "/v1/persistence",
                r#"{"enabled":false}"#,
                GATE_KEY,
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_of(resp).await;
        assert_eq!(body["enabled"], false);
        assert_eq!(body["authorized"], true);

        assert!(
            !gate.writes_permitted(),
            "the exporter holds the same gate the socket moved"
        );

        let resp = app
            .oneshot(test_get_with_key("/v1/persistence", GATE_KEY))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_of(resp).await;
        assert_eq!(body["enabled"], false, "the next read agrees");
        assert_eq!(body["authorized"], true);
    }

    /// Enabling on a run the command line never authorized says so.
    ///
    /// A bare 200 would read as success to a client that asked to enable, and
    /// the client would go on believing content was being written.
    #[tokio::test]
    async fn enabling_persistence_on_an_unauthorized_run_reports_that_it_did_nothing() {
        let gate = Arc::new(crate::output::persistence::PersistenceGate::new(false));
        let app = build_router(make_state_with_gate(&gate));

        let resp = app
            .oneshot(test_post_with_key(
                "/v1/persistence",
                r#"{"enabled":true}"#,
                GATE_KEY,
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_of(resp).await;
        assert_eq!(body["enabled"], false, "nothing was enabled");
        assert_eq!(
            body["authorized"], false,
            "and the reason is visible: this run was never authorized, which \
             is a different answer from an operator having closed the gate"
        );
        assert!(!gate.writes_permitted());
    }

    /// A body the handler cannot read never opens the gate.
    ///
    /// The dangerous direction for a parse failure is a default of `true`.
    /// Each of these is rejected with the gate left where it was.
    #[tokio::test]
    async fn a_body_the_handler_cannot_read_never_opens_the_gate() {
        for body in [
            "",
            "not json",
            "{}",
            r#"{"enable":true}"#,
            r#"{"enabled":"true"}"#,
            r#"{"enabled":1}"#,
            r#"{"enabled":null}"#,
            "[true]",
        ] {
            let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
            gate.set(false);
            let app = build_router(make_state_with_gate(&gate));

            let resp = app
                .oneshot(test_post_with_key("/v1/persistence", body, GATE_KEY))
                .await
                .expect("oneshot");
            assert!(
                resp.status().is_client_error(),
                "body {body:?} was accepted; a body the handler cannot read \
                 must be refused, not guessed at"
            );
            assert!(
                !gate.writes_permitted(),
                "body {body:?} reopened a closed gate"
            );
        }
    }

    /// A JSON sequence never reaches the gate.
    ///
    /// Its own test rather than a row in the table above, because it is the
    /// one shape that got through. A derived `Deserialize` accepts a sequence
    /// as well as a map, filling fields in declaration order, so `[true]`
    /// arrived as `enabled: true` and reopened a gate an operator had closed.
    /// A one-field struct makes the array that does it a single token long.
    #[tokio::test]
    async fn a_json_sequence_never_reaches_the_gate() {
        for body in ["[true]", "[false]", "[]", r#"[true,"ignored"]"#, "[[true]]"] {
            let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
            gate.set(false);
            let app = build_router(make_state_with_gate(&gate));

            let resp = app
                .oneshot(test_post_with_key("/v1/persistence", body, GATE_KEY))
                .await
                .expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "sequence body {body:?} was accepted"
            );
            assert!(
                !gate.writes_permitted(),
                "sequence body {body:?} reopened a closed gate"
            );
        }
    }

    /// A sequence cannot close the gate either.
    ///
    /// The fix has to reject the SHAPE, not the value. A handler that refused
    /// only sequences carrying `true` would still be reading fields out of an
    /// array, and the next field added to the request struct would decide
    /// which array position meant what.
    #[tokio::test]
    async fn a_sequence_cannot_move_the_gate_in_either_direction() {
        let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
        let app = build_router(make_state_with_gate(&gate));

        let resp = app
            .oneshot(test_post_with_key("/v1/persistence", "[false]", GATE_KEY))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            gate.writes_permitted(),
            "a sequence closed the gate; the shape is refused, not the value"
        );
    }

    /// An object with an unknown key is refused rather than half-read.
    ///
    /// `deny_unknown_fields` is what does it, and this is where that attribute
    /// is held: a caller who typed `enable` alongside `enabled` has said two
    /// things and meant one, and guessing which is the reading that ends with
    /// content on disk nobody asked for.
    #[tokio::test]
    async fn an_object_with_an_unknown_key_is_refused() {
        for body in [
            r#"{"enabled":true,"enable":false}"#,
            r#"{"enabled":true,"forever":true}"#,
        ] {
            let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
            gate.set(false);
            let app = build_router(make_state_with_gate(&gate));

            let resp = app
                .oneshot(test_post_with_key("/v1/persistence", body, GATE_KEY))
                .await
                .expect("oneshot");
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "body {body:?} was accepted"
            );
            assert!(!gate.writes_permitted(), "body {body:?} moved the gate");
        }
    }

    /// Exactly one body shape moves the gate.
    ///
    /// Stated as a sweep rather than as cases so a body shape nobody thought
    /// of has to be added to the accepted list deliberately. The two accepted
    /// rows are the whole documented surface of this route.
    #[tokio::test]
    async fn exactly_one_body_shape_moves_the_gate() {
        let accepted = [
            (r#"{"enabled":true}"#, true),
            (r#"{"enabled":false}"#, false),
        ];
        let refused = [
            "",
            "null",
            "true",
            "0",
            r#""enabled""#,
            "{}",
            "[true]",
            r#"{"enabled":[true]}"#,
            r#"{"enabled":{"value":true}}"#,
        ];

        for (body, want) in accepted {
            let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
            gate.set(!want);
            let app = build_router(make_state_with_gate(&gate));
            let resp = app
                .oneshot(test_post_with_key("/v1/persistence", body, GATE_KEY))
                .await
                .expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "body {body:?} was refused");
            assert_eq!(gate.writes_permitted(), want, "body {body:?} did not land");
        }

        for body in refused {
            for start in [true, false] {
                let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
                gate.set(start);
                let app = build_router(make_state_with_gate(&gate));
                let resp = app
                    .oneshot(test_post_with_key("/v1/persistence", body, GATE_KEY))
                    .await
                    .expect("oneshot");
                assert!(
                    resp.status().is_client_error(),
                    "body {body:?} was accepted"
                );
                assert_eq!(
                    gate.writes_permitted(),
                    start,
                    "body {body:?} moved a gate it should not have touched"
                );
            }
        }
    }

    /// Reading the gate does not move it.
    #[tokio::test]
    async fn reading_the_gate_leaves_it_where_it_was() {
        for start_open in [true, false] {
            let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
            gate.set(start_open);
            let app = build_router(make_state_with_gate(&gate));

            for _ in 0..3 {
                let resp = app
                    .clone()
                    .oneshot(test_get_with_key("/v1/persistence", GATE_KEY))
                    .await
                    .expect("oneshot");
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(json_of(resp).await["enabled"], start_open);
            }
            assert_eq!(gate.writes_permitted(), start_open, "reads are reads");
        }
    }

    /// Both doors of the route report the same shape.
    ///
    /// A client polls `GET` and acts on `POST`; two shapes would make it parse
    /// twice and eventually parse one of them wrong.
    #[tokio::test]
    async fn both_doors_report_the_same_shape() {
        let gate = Arc::new(crate::output::persistence::PersistenceGate::new(true));
        let app = build_router(make_state_with_gate(&gate));

        let posted = json_of(
            app.clone()
                .oneshot(test_post_with_key(
                    "/v1/persistence",
                    r#"{"enabled":true}"#,
                    GATE_KEY,
                ))
                .await
                .expect("oneshot"),
        )
        .await;
        let got = json_of(
            app.oneshot(test_get_with_key("/v1/persistence", GATE_KEY))
                .await
                .expect("oneshot"),
        )
        .await;
        assert_eq!(posted, got, "POST and GET answer with one shape");
    }
}
