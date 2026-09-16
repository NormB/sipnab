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
            StatusCode::BAD_GATEWAY => "bad-gateway",
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

/// What a relay-statistics REST handler needs to answer (ST5).
///
/// Carried together, and each half is a distinct refusal when absent: no `addr`
/// is `not_configured` (the operator named no relay), an `addr` with no
/// `permit` is `not_permitted` (a file-backed run, or `--api-allow-relay-query`
/// off). Both `None` -- the default -- is a server with no relay access, which
/// is every test in this module and every run that did not opt in. The handler
/// builds a fresh `ControlClient` from `addr` per request, exactly as the CLI's
/// one-shot path does, so nothing long-lived holds a socket open.
#[derive(Clone, Default)]
pub struct RelayRestConfig {
    /// The relay to ask, chosen by the composition root and named by nothing
    /// here -- a trait object, so this layer stays free of any implementation.
    /// `None` when the run configured no relay, which reads as `not_configured`.
    pub relay: Option<std::sync::Arc<dyn crate::relay::reconcile::ReadOnlyRelay + Send + Sync>>,
    /// Proof this run may transmit: present only when the run is live AND
    /// `--api-allow-relay-query` is set. Its absence beside a present `relay` is
    /// exactly `not_permitted`.
    pub permit: Option<crate::security::transmit_guard::TransmitPermit>,
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
    /// Interfaces sipnab was asked to capture on, for per-interface counters.
    pub capture_interfaces: Vec<String>,
    /// When this server started, for the uptime the runtime answer reports.
    pub started_at: std::time::Instant,
    /// The capture queue's meter, when this run owns a capture.
    ///
    /// `None` on a run with no capture path — a replayed file served through
    /// the API, or any test harness — and the queue-depth and backpressure
    /// fields then report absent rather than zero. That distinction is the
    /// point: a confident `0` reads as "the capture path is healthy", which is
    /// the one answer a saturated pipeline must never give.
    pub capture_meter: Option<crate::capture::channel::CaptureMeter>,
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
    /// Where the TFPS peer's `tfps_ctl` is, for the `/v1/tfps/` routes.
    ///
    /// The same locator the MCP server carries, built once by the caller
    /// that starts both. Its default looks on `PATH` at call time, so a
    /// state built without one -- every test in this module -- still
    /// answers, with `installed: false` on a machine that has no TFPS.
    pub tfps: crate::security::tfps::TfpsLocator,
    /// Relay access for the `GET /v1/relay/...` routes (ST5), when this run
    /// opted in with `--api-allow-relay-query` on a live source. `default()`
    /// (both halves `None`) is a server with no relay access, which answers
    /// those routes `not_configured` -- the state every test here builds.
    pub relay_query: RelayRestConfig,
}

/// Resolve a caller's `?limit=` to a row count.
///
/// `None` and `Some(0)` both mean "the default page", which is the reading the
/// MCP door has always given a zero (`mcp::shape::resolve_limit`) and the
/// reading `GET /v1/tfps/labels` in this same file already gave it. The other
/// two list routes treated `0` as a literal zero and returned an EMPTY page —
/// so one product answered a `limit=0` three different ways depending on which
/// endpoint received it.
///
/// Empty is the worse of the two readings on its own terms: a caller who sends
/// `limit=0` by accident (an unset variable interpolated into a URL) gets a
/// successful response with no rows, which reads as "there is nothing here"
/// rather than as a mistake.
///
/// # Arguments
/// * `requested` — the `?limit=` the caller sent.
/// * `cap` — this server's `max_rows` ceiling.
fn resolve_page_limit(requested: Option<usize>, cap: usize) -> usize {
    match requested {
        None | Some(0) => DEFAULT_PAGE_ROWS.min(cap),
        Some(n) => n.min(cap),
    }
}

/// Rows a list-style response returns when the caller names no `limit`.
///
/// A page size, not a ceiling: it is what `?limit=` defaults to, and any
/// caller can ask for more up to [`ApiState::max_rows`].
const DEFAULT_PAGE_ROWS: usize = 50;

// ── Rate limiter ────────────────────────────────────────────────────

/// Per-IP request limiter for the REST surface.
///
/// A thin adapter over the shared [`crate::rate_limit::FixedWindowLimiter`],
/// not a limiter of its own. This door used to carry a private implementation,
/// and `rate_limit.rs` exists precisely because the rule had already been
/// written twice — its module doc says so: "Written twice, the two copies
/// drift... the deployment that reads the same knob on two surfaces gets two
/// behaviors."
///
/// It got two behaviors. `[limits] max_tracked_peers` reached MCP and HEP and
/// stopped here, so the bucket map had no configured bound against a
/// spoofed-source flood, and the private version anchored a window per IP
/// where the shared one resets a single window for every peer.
pub struct RateLimiter {
    /// The shared limiter, keyed by source address. No global ceiling: the
    /// REST surface has only ever capped per peer, and `0` there disables it.
    inner: crate::rate_limit::FixedWindowLimiter<IpAddr>,
}

impl RateLimiter {
    /// Build a limiter capping each peer at `max_rps` requests per second and
    /// tracking at most `max_tracked_peers` of them.
    ///
    /// `0` for `max_rps` DISABLES the cap rather than refusing every request.
    /// That is the reading `--mcp-rate-limit-per-peer`,
    /// `--hep-rate-limit-per-peer` and `--hep-rate-limit` all give a zero, and
    /// an operator who has learned the convention on one listener must not be
    /// locked out of the REST API by using it on another.
    ///
    /// # Arguments
    /// * `max_rps` — per-peer ceiling; `0` disables.
    /// * `max_tracked_peers` — how many distinct peers the map may hold.
    #[must_use]
    pub fn new(max_rps: u32, max_tracked_peers: usize) -> Self {
        Self {
            inner: crate::rate_limit::FixedWindowLimiter::new(
                0,
                u64::from(max_rps),
                max_tracked_peers,
            ),
        }
    }

    /// Check whether a request from `ip` is allowed right now.
    ///
    /// # Side effects
    /// Counts the request against the current window.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        self.check_at(ip, Instant::now())
    }

    /// How many distinct peers this limiter will track, and the per-peer cap.
    ///
    /// Read by `the_api_door_receives_both_rate_limit_knobs`, which is the
    /// only way to prove the CLI values REACH this door. Testing the limiter
    /// directly proves the limiter works and says nothing about whether
    /// `start_servers` hands it the configured numbers -- and that wiring is
    /// exactly what was missing: `max_tracked_peers` reached MCP and stopped
    /// here.
    #[must_use]
    pub fn caps(&self) -> (u64, usize) {
        (self.inner.per_peer_max(), self.inner.max_tracked_peers())
    }

    /// How many peers the bucket map is holding right now.
    ///
    /// For asserting the memory bound directly rather than through process
    /// heap, which every other allocation in a test binary perturbs.
    #[must_use]
    pub fn tracked_peers(&self) -> usize {
        self.inner.tracked_peers()
    }

    /// The same decision at a caller-supplied instant.
    ///
    /// Separate so the window and the peer bound can be driven in a test
    /// without sleeping: a limiter tested only through `check()` can only be
    /// checked for the behavior that fits inside one real second.
    pub fn check_at(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.inner.check(ip, now).is_ok()
    }
}

// ── Query parameter types ───────────────────────────────────────────

/// Query parameters for the `GET /v1/runtime` endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RuntimeParams {
    /// Seconds to sample rates across. Omitted, the route answers with the
    /// cumulative counters and no `rates` object. Zero is refused; a window
    /// longer than this route can answer inside its request timeout is clamped
    /// to one it can, and the window actually applied comes back as
    /// `rates.window_seconds` rather than being assumed.
    pub sample_seconds: Option<u32>,
}

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
    /// Filter by a DSL expression — the same language the CLI `--filter` and
    /// the TUI filter dialog compile (e.g. `problems`, `from.user == '1001'`,
    /// `payload =~ 'scanner'`, `method == 'INVITE' AND rtp.loss > 2.0`). An
    /// expression that does not parse is a 400, so a client learns its query
    /// was rejected rather than receiving every row. ANDed with `state`/`from`.
    pub filter: Option<String>,
    /// Only dialogs whose first message is at or after this RFC 3339 instant
    /// (e.g. `2026-09-15T12:00:00Z`). A timestamp that does not parse is a 400.
    pub after: Option<String>,
    /// Only dialogs whose first message is at or before this RFC 3339 instant.
    /// A timestamp that does not parse is a 400.
    pub before: Option<String>,
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

/// Query parameters for the `GET /v1/aggregate` endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AggregateParams {
    /// The dimension to group by — one of the groupable fields (`state`,
    /// `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`,
    /// `dst.ip`, `rtp.codec`). A key outside that set is a 400. Required.
    pub by: Option<String>,
    /// A DSL expression narrowing which dialogs are counted, the same language
    /// `/v1/dialogs?filter=` compiles. An expression that does not parse is a 400.
    pub filter: Option<String>,
    /// Keep the largest N buckets; the rest fold into `other_count`. Clamped to
    /// the server's row cap.
    pub top_n: Option<usize>,
}

/// Query parameters for the `GET /v1/timeline` endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimelineParams {
    /// Bucket width in seconds (default 60). Zero is a 400: a zero-width bucket
    /// describes no interval, and every dialog would fall into all of them.
    pub bucket_seconds: Option<u64>,
}

/// Query parameters for the `GET /v1/dialogs/compare` endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CompareParams {
    /// Call-ID of the first dialog. A Call-ID with no dialog is a 404. Required.
    pub a: Option<String>,
    /// Call-ID of the second dialog. A Call-ID with no dialog is a 404.
    /// Required.
    pub b: Option<String>,
}

/// Query parameters for the `GET /v1/dialogs/tail` endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TailParams {
    /// Resume cursor: pass back the previous response's `next_cursor` verbatim
    /// (`<RFC 3339>|<Call-ID>`). Only dialogs updated strictly after that
    /// position are returned. A bare RFC 3339 timestamp is also accepted. Omit
    /// on the first poll to start from the beginning. A cursor whose timestamp
    /// half is not RFC 3339 is a 400.
    pub since: Option<String>,
    /// Maximum dialogs to return, clamped to the server's row cap.
    pub limit: Option<usize>,
}

// ── Router construction ─────────────────────────────────────────────

/// Per-request wall-clock cap. The API is request/response (no streaming), so a
/// blanket timeout is safe and stops a slow client from pinning a connection.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Max request body accepted (defense in depth; the API is GET-only today).
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// Longest rate window this route will wait out before answering.
///
/// `REQUEST_TIMEOUT` cancels the handler, so a window equal to it is killed
/// mid-sleep and the caller gets a timeout instead of a rate. The margin is
/// subtracted from the timeout rather than written beside it: lowering
/// `REQUEST_TIMEOUT` has to lower this too, and two numbers maintained by hand
/// drift until one of them is wrong.
///
/// The MCP cap ([`crate::output::runtime::MAX_SAMPLE_SECONDS`]) applies first;
/// this only narrows it, so no window either surface accepts is one the other
/// silently truncates.
const MAX_REST_SAMPLE_SECONDS: u32 = {
    let budget = REQUEST_TIMEOUT.as_secs().saturating_sub(5) as u32;
    if budget < crate::output::runtime::MAX_SAMPLE_SECONDS {
        budget
    } else {
        crate::output::runtime::MAX_SAMPLE_SECONDS
    }
};

// Asserted at compile time rather than in a test, because both are statements
// about constants and there is no reason to wait for a test run to learn that
// the derivation collapsed. Lower `REQUEST_TIMEOUT` past the margin and the
// build stops here, naming which half broke.
const _: () = assert!(
    (MAX_REST_SAMPLE_SECONDS as u64) < REQUEST_TIMEOUT.as_secs(),
    "the REST rate window must fit inside the request timeout, or the handler \
     is canceled mid-sleep and the caller gets a timeout where they asked for \
     a rate"
);
const _: () = assert!(
    MAX_REST_SAMPLE_SECONDS >= 1,
    "the REST rate window collapsed to zero, which refuses every window a \
     caller can ask for"
);
const _: () = assert!(
    MAX_REST_SAMPLE_SECONDS <= crate::output::runtime::MAX_SAMPLE_SECONDS,
    "REST may narrow the shared cap, never widen it: a window MCP refuses must \
     not be one REST accepts"
);

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
        // Static segment, so it wins over `{call_id}` (matchit 0.8): a dialog
        // whose Call-ID is literally "compare" is unreachable here, which no
        // real capture hits.
        .route("/v1/dialogs/compare", get(get_compare))
        // Static segment, wins over `{call_id}` — see the note on compare.
        .route("/v1/dialogs/tail", get(get_dialogs_tail))
        .route("/v1/dialogs/{call_id}", get(get_dialog))
        .route("/v1/dialogs/{call_id}/report", get(get_dialog_report))
        .route("/v1/dialogs/{call_id}/correlated", get(get_correlated))
        .route("/v1/dialogs/{call_id}/tree", get(get_tree))
        .route("/v1/dialogs/{call_id}/lint", get(get_lint));
    // Registered only where the exporter exists. A route that answered 501
    // in a build without the feature would leave a client unable to tell
    // "this sipnab cannot" from "this call has no data", and the second
    // reading is the one it would act on.
    #[cfg(feature = "vcon")]
    let router = router.route("/v1/dialogs/{call_id}/vcon", get(get_dialog_vcon));
    // Validating a caller's vCon needs the vendored schema, which is part of the
    // vcon feature, so this route is gated with it too.
    #[cfg(feature = "vcon")]
    let router = router.route("/v1/vcon/validate", axum::routing::post(post_vcon_validate));
    router
        .route(
            "/v1/persistence",
            get(get_persistence).post(set_persistence),
        )
        .route("/v1/tfps/status", get(get_tfps_status))
        .route("/v1/tfps/banned", get(get_tfps_banned))
        .route("/v1/tfps/dropped", get(get_tfps_dropped))
        .route("/v1/tfps/labels", get(get_tfps_labels))
        .route("/v1/tfps/ban", axum::routing::post(post_tfps_ban))
        .route("/v1/tfps/unban", axum::routing::post(post_tfps_unban))
        .route("/v1/streams", get(list_streams))
        .route("/v1/streams/{id}", get(get_stream))
        .route("/v1/report", get(get_capture_report))
        .route("/v1/stats", get(get_stats))
        .route("/v1/aggregate", get(get_aggregate))
        .route("/v1/timeline", get(get_timeline))
        // Relay statistics (ST5). Each transmits once, behind
        // --api-allow-relay-query; the /call/ segment keeps C2 from colliding
        // with the static /names path. Polling (C5) is not offered here.
        .route("/v1/relay/stats", get(get_relay_stats))
        .route("/v1/relay/stats/names", get(get_relay_stat_names))
        .route("/v1/relay/stats/call/{call_id}", get(get_relay_stats_call))
        .route("/v1/relay/compare/{call_id}", get(get_relay_compare))
        .route("/v1/runtime", get(get_runtime))
        .route("/v1/capabilities", get(get_capabilities))
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

/// `GET /v1/capabilities` — what this build can do and what the operator turned
/// on, so a client can discover the surface before a refusal it could have
/// predicted reads as a dead end (PAR3: the machine contract REST had lacked).
///
/// # Arguments
///
/// * `state` — Shared application state (for the relay opt-in and the guard).
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
///
/// # Returns
///
/// 200 with the compiled feature set and the run's opt-ins; 401/503 from the
/// guard.
#[utoipa::path(
    get,
    path = "/v1/capabilities",
    tag = "operations",
    summary = "Server capabilities",
    description = "The build's compiled feature set — the same canonical list `--version` and the MCP `server_capabilities` tool report — and the REST server's runtime opt-ins.\n\nA program reads this before it asks: a capability absent from `features` is one this binary cannot do, and a runtime opt-in that is off is one this run did not turn on. A mid-integration refusal would blur those two facts, and this route keeps them apart.",
    responses(
        (status = 200, description = "The build's features and the run's opt-ins.", body = schema::Capabilities),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_capabilities(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    // The one canonical list, so `--version`, the MCP tool and this route can
    // never claim different builds of the same binary.
    let mut features: Vec<String> = crate::cli::compiled_features()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    features.sort();

    Ok(Json(schema::Capabilities {
        schema_version: 1,
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        can_decrypt: cfg!(feature = "tls"),
        can_hep: cfg!(feature = "hep"),
        can_plugins: cfg!(feature = "plugins"),
        runtime: schema::CapabilitiesRuntime {
            api_allow_relay_query: state.relay_query.permit.is_some(),
        },
    }))
}

/// `GET /v1/dialogs/{call_id}/correlated` — the other legs of this call and the
/// strategy that matched each (PAR3: find_correlated on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `call_id` — Call-ID of the dialog to correlate from.
///
/// # Returns
///
/// 200 with the correlated legs, highest score first; 404 when the Call-ID is
/// unknown; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog-store read lock while correlating; mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}/correlated",
    tag = "dialogs",
    summary = "Correlate a call's legs",
    description = "The other legs of this call across a B2BUA, SBC or PBX, each with the strategy that matched it and whether that strategy compared identifiers or guessed from timing.\n\nOne hop from one Call-ID. To walk a whole tree, follow each `call_id` back into this route. `heuristic_only` is true when every match is a timing guess, so a reader weighs the answer accordingly.",
    params(("call_id" = String, Path, description = "Call-ID of the dialog, percent-encoded. \
                                                     Call-IDs routinely carry `@` and may carry \
                                                     `;`, `+` or `/`.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The other legs of this call, each with the strategy that \
                                      matched it.", body = schema::Correlated),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_correlated(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    // 404 an unknown Call-ID, the same answer `/v1/dialogs/{call_id}` gives, so
    // an empty-legs 200 always means "this call stands alone" and never "this
    // call is not here" — two facts a caller acts on differently.
    let source_created = match ds.get(&call_id) {
        Some(d) => d.created_at,
        None => return Err(Problem::new(StatusCode::NOT_FOUND)),
    };
    let results = ds.find_correlated_scored(&call_id);
    let total_matched = results.len();
    let legs: Vec<schema::CorrelatedLeg> = results
        .iter()
        .take(state.max_rows)
        .map(|r| {
            let (strategy, identifier_match, observed_gap_ms) =
                r.strategy_and_gap(Some(source_created));
            schema::CorrelatedLeg {
                call_id: r.dialog.call_id.clone(),
                score: r.score,
                strategy: strategy.to_string(),
                identifier_match,
                observed_gap_ms,
            }
        })
        .collect();
    let heuristic_only = !legs.is_empty() && legs.iter().all(|l| !l.identifier_match);

    Ok(Json(schema::Correlated {
        schema_version: 1,
        source_call_id: call_id,
        legs,
        total_matched,
        heuristic_only,
    }))
}

/// `GET /v1/dialogs/{call_id}/tree` — the whole tree of legs reachable from this
/// call, walked transitively across a B2BUA, SBC or PBX (PAR3: get_call_tree on
/// REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `call_id` — Call-ID of any leg of the call; the walk is symmetric.
///
/// # Returns
///
/// 200 with the tree, legs ordered by depth then creation time; 404 when the
/// Call-ID is unknown; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog-store read lock while walking; mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}/tree",
    tag = "dialogs",
    summary = "Walk a call's tree",
    description = "The whole tree of legs reachable from this call, walked transitively across a B2BUA, SBC or PBX — where `/correlated` answers one hop, this follows every identifier match to the end.\n\nA timing guess is a leaf: `followed` is false and its subtree is not searched, because a guess is not firm enough to walk through. `heuristic_edges` counts the guesses in the tree, and `truncated` is true when the row cap stopped the walk early. Follow each leg's `call_id` to `/v1/dialogs/{call_id}` for its detail.",
    params(("call_id" = String, Path, description = "Call-ID of any leg, percent-encoded. \
                                                     The walk is symmetric, so any leg returns \
                                                     the same tree, rooted differently.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The tree of legs, root included.", body = schema::CallTree),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_tree(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let ds = state.dialog_store.read();
    // The one walk, shared with the MCP `get_call_tree` tool. 404 an unknown
    // Call-ID, the same answer the sibling routes give.
    let tree = ds
        .correlation_tree(&call_id, state.max_rows)
        .ok_or_else(|| Problem::new(StatusCode::NOT_FOUND))?;
    let legs: Vec<schema::CallTreeLeg> = tree
        .legs
        .iter()
        .map(|leg| schema::CallTreeLeg {
            call_id: leg.call_id.clone(),
            depth: leg.depth,
            parent_call_id: leg.parent_call_id.clone(),
            score: leg.score,
            strategy: leg.strategy.map(str::to_string),
            identifier_match: leg.identifier_match,
            followed: leg.followed,
        })
        .collect();

    Ok(Json(schema::CallTree {
        schema_version: 1,
        root_call_id: call_id,
        total_legs: legs.len(),
        legs,
        max_depth: tree.max_depth,
        truncated: tree.truncated,
        heuristic_edges: tree.heuristic_edges,
        total_messages: tree.total_messages,
        first_activity: tree.first_activity.map(|t| t.to_rfc3339()),
        last_activity: tree.last_activity.map(|t| t.to_rfc3339()),
    }))
}

/// `GET /v1/aggregate` — count dialogs grouped by one dimension (PAR3:
/// aggregate_dialogs on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — `by` (the dimension), optional `filter` and `top_n`.
///
/// # Returns
///
/// 200 with the buckets, largest first; 400 for an unknown dimension or a filter
/// that does not parse; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog- and stream-store read locks while tallying; mutates the
/// rate limiter.
#[utoipa::path(
    get,
    path = "/v1/aggregate",
    tag = "dialogs",
    summary = "Count dialogs by a dimension",
    description = "How many dialogs, grouped by one dimension — the same question the MCP `aggregate_dialogs` tool answers.\n\nOne dimension at a time: narrow with `filter` rather than asking for a second. The buckets are largest first, ties broken by value so the same store always gives the same answer, and `other_count` carries everything past `top_n` so the buckets plus it sum to `total_matched`. A `(none)` bucket counts the dialogs with no value for the dimension.",
    params(AggregateParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The buckets, largest first.", body = schema::Aggregate),
        (status = 400, description = "An unknown dimension, or a filter that does not parse.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_aggregate(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<AggregateParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let key = params.by.as_deref().map(str::trim).unwrap_or("");
    if !crate::sip::dialog::GROUPABLE.contains(&key) {
        return Err(Problem::detailed(
            StatusCode::BAD_REQUEST,
            format!(
                "cannot group by '{key}'; one of: {}. One dimension only — narrow \
                 with `filter` rather than adding a second.",
                crate::sip::dialog::GROUPABLE.join(", ")
            ),
        ));
    }

    // Same DSL and 400-on-parse-failure as `/v1/dialogs?filter=`.
    let dsl = match params.filter.as_deref() {
        Some(expr) => Some(
            crate::sip::dsl::FilterExpr::parse(expr)
                .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, format!("filter: {e}")))?,
        ),
        None => None,
    };
    let top_n = resolve_page_limit(params.top_n, state.max_rows);

    let ds = state.dialog_store.read();
    let ss = state.stream_store.read();
    // `select_dialogs` applies the filter and pairs each dialog with its
    // streams, the path the CLI and the MCP tool also take, so the surfaces
    // count the same store. The bucketing rule is `dialog_group_value_raw`.
    let selection = crate::sip::dsl::select_dialogs(dsl.as_ref(), &ds, &ss);
    let total_matched = selection.dialogs.len();
    let mut tally: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for item in &selection.dialogs {
        if let Some(value) = crate::sip::dialog::dialog_group_value_raw(key, item.0, &item.1) {
            *tally.entry(value).or_insert(0) += 1;
        }
    }
    drop(ss);
    drop(ds);

    let distinct_values = tally.len();
    let mut ordered: Vec<(String, usize)> = tally.into_iter().collect();
    // Largest first, ties broken by value so a cursor-free aggregate does not
    // reorder between calls and look like the capture changed.
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let other_count: usize = ordered.iter().skip(top_n).map(|(_, c)| *c).sum();
    let buckets: Vec<schema::AggregateBucket> = ordered
        .into_iter()
        .take(top_n)
        .map(|(value, count)| schema::AggregateBucket { value, count })
        .collect();

    Ok(Json(schema::Aggregate {
        schema_version: 1,
        group_by: key.to_string(),
        buckets,
        other_count,
        distinct_values,
        total_matched,
    }))
}

/// `GET /v1/timeline` — call volume over time, in fixed-width buckets (PAR3:
/// timeline on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — optional `bucket_seconds` (default 60).
///
/// # Returns
///
/// 200 with one row per interval, oldest first, gaps included; 400 for a zero
/// bucket width; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog-store read lock while bucketing; mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/timeline",
    tag = "dialogs",
    summary = "Call volume over time",
    description = "How many calls opened over time, in fixed-width buckets — the volume series a dashboard polls, which no other route exposed.\n\nBuckets align to the epoch rather than to the first call, so two captures line up, and an empty interval is kept rather than dropped because an empty bucket is exactly what an outage looks like. The MCP `timeline` tool buckets the same way.",
    params(TimelineParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "One row per interval, oldest first.", body = schema::Timeline),
        (status = 400, description = "A bucket width of zero.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_timeline(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<TimelineParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let width = params.bucket_seconds.unwrap_or(60);
    if width == 0 {
        return Err(Problem::detailed(
            StatusCode::BAD_REQUEST,
            "bucket_seconds must be greater than zero: a zero-width bucket \
             describes no interval, and every dialog would fall into all of them",
        ));
    }

    // The shared bucketing rule, so this route and the MCP `timeline` tool
    // agree; this surface renders the interval start as RFC 3339.
    let buckets: Vec<schema::TimelineBucket> = state
        .dialog_store
        .read()
        .timeline_buckets(width)
        .into_iter()
        .map(|(start, dialogs)| schema::TimelineBucket {
            start: start.to_rfc3339(),
            bucket_seconds: width,
            dialogs,
        })
        .collect();

    Ok(Json(schema::Timeline {
        schema_version: 1,
        returned: buckets.len(),
        bucket_seconds: width,
        buckets,
    }))
}

/// `GET /v1/dialogs/compare` — two calls side by side, with the fields that
/// differ named (PAR3: compare_dialogs on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — `a` and `b`, the two Call-IDs to compare.
///
/// # Returns
///
/// 200 with the two summaries and the differing fields; 400 when `a` or `b` is
/// missing; 404 when either Call-ID has no dialog, naming which; 401/503 from
/// the guard.
///
/// # Side effects
///
/// Holds the dialog-store read lock while summarizing; mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs/compare",
    tag = "dialogs",
    summary = "Compare two calls side by side",
    description = "Two calls side by side — state, outcome code, message count and method set — with the fields that differ named for you. The same comparison the MCP `compare_dialogs` tool answers.\n\nA client could fetch both dialogs and diff them, but one asked to spot the difference itself will sometimes report a difference that is not there. This route names them: `differences` lists the fields that moved, a subset of `state`, `final_status_code`, `msg_count` and `methods`. A Call-ID with no dialog is a 404 that names which of the two is missing.",
    params(CompareParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The two summaries and the fields that differ.", body = schema::Comparison),
        (status = 400, description = "A missing `a` or `b` query parameter.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries one of the two Call-IDs in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_compare(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<CompareParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let a_id = params
        .a
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Problem::detailed(
                StatusCode::BAD_REQUEST,
                "the `a` query parameter is required: the Call-ID of the first call to compare",
            )
        })?;
    let b_id = params
        .b
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            Problem::detailed(
                StatusCode::BAD_REQUEST,
                "the `b` query parameter is required: the Call-ID of the second call to compare",
            )
        })?;

    let ds = state.dialog_store.read();
    let a = ds.get(a_id).ok_or_else(|| {
        Problem::detailed(
            StatusCode::NOT_FOUND,
            format!("no dialog carries a='{a_id}'"),
        )
    })?;
    let b = ds.get(b_id).ok_or_else(|| {
        Problem::detailed(
            StatusCode::NOT_FOUND,
            format!("no dialog carries b='{b_id}'"),
        )
    })?;

    // The shared comparison rule, so this route and the MCP `compare_dialogs`
    // tool name the same differences.
    let cmp = crate::sip::dialog::compare_dialogs(a, b);
    let side = |s: crate::sip::dialog::DialogSide| schema::ComparisonSide {
        call_id: s.call_id,
        state: s.state,
        final_status_code: s.final_status_code,
        msg_count: s.msg_count,
        methods: s.methods,
        hints: s.hints,
    };
    Ok(Json(schema::Comparison {
        schema_version: 1,
        a: side(cmp.a),
        b: side(cmp.b),
        differences: cmp.differences,
    }))
}

/// `GET /v1/dialogs/tail` — dialogs changed since a cursor, for change-tracking
/// pollers (PAR3: tail_dialogs on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `params` — optional `since` cursor and `limit`.
///
/// # Returns
///
/// 200 with the dialogs updated after the cursor (oldest update first) and a
/// `next_cursor` to resume from; 400 for a `since` whose timestamp half is not
/// RFC 3339; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog-store read lock while paging; mutates the rate limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs/tail",
    tag = "dialogs",
    summary = "Poll for dialogs changed since a cursor",
    description = "The dialogs updated since your last poll — cursor-based change tracking, the pattern a monitoring system uses and one that `/v1/dialogs` offset pagination cannot express. The same question the MCP `tail_dialogs` tool answers.\n\nPass the previous response's `next_cursor` back as `since`, and only dialogs updated strictly after it are returned, oldest update first. Omit `since` on the first poll. The rows are the same summaries `/v1/dialogs` returns. `next_cursor` is null when nothing changed.",
    params(TailParams),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The changed dialogs and the cursor to resume from.", body = schema::TailPage),
        (status = 400, description = "A `since` cursor whose timestamp half is not RFC 3339.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_dialogs_tail(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<TailParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let cursor = match params.since.as_deref() {
        Some(raw) => Some(
            crate::cursor::parse_cursor(raw)
                .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, format!("since: {e}")))?,
        ),
        None => None,
    };
    let limit = resolve_page_limit(params.limit, state.max_rows);

    // The order + truncation + next_cursor rule is shared with the MCP
    // `tail_dialogs` tool, so the two surfaces page the same store the same
    // way. This surface renders each row with the same `dialog_summary` the
    // `/v1/dialogs` list uses.
    let ds = state.dialog_store.read();
    let (page, next_cursor) = ds.tail_page(cursor.as_ref(), limit);
    let dialogs: Vec<Value> = page.iter().map(|&d| dialog_summary(d)).collect();
    drop(ds);
    let returned = dialogs.len();

    Ok(Json(json!({
        "schema_version": 1,
        "dialogs": dialogs,
        "next_cursor": next_cursor,
        "returned": returned,
    })))
}

/// `GET /v1/dialogs/{call_id}/lint` — the RFC-conformance findings for one
/// dialog (PAR3: lint_dialog on REST).
///
/// # Arguments
///
/// * `state` — Shared application state.
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `call_id` — Call-ID of the dialog to lint.
///
/// # Returns
///
/// 200 with the findings, in the linter's order; 404 when the Call-ID is
/// unknown; 401/503 from the guard.
///
/// # Side effects
///
/// Holds the dialog- and stream-store read locks while linting; mutates the
/// rate limiter.
#[utoipa::path(
    get,
    path = "/v1/dialogs/{call_id}/lint",
    tag = "dialogs",
    summary = "Lint a dialog for RFC conformance",
    description = "The RFC-conformance defects this dialog trips, each with its rule, severity, basis, RFC number and section, and what the message held against what the section calls for — the same checks the CLI `--lint` runs and the MCP `lint_dialog` tool reports.\n\n`basis` separates a `must` violation from an interop wart or an observation the wire contradicts, so a reader does not discount an RFC breach because it sits beside a heuristic. The media-derived rules run too, from the dialog's RTP streams.",
    params(("call_id" = String, Path, description = "Call-ID of the dialog, percent-encoded. \
                                                     Call-IDs routinely carry `@` and may carry \
                                                     `;`, `+` or `/`.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The conformance findings for this dialog.", body = schema::Lint),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 404, description = "No dialog carries that Call-ID in this capture.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_lint(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(call_id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    // DialogStore before StreamStore, the lock order the stores document.
    let ds = state.dialog_store.read();
    let dialog = ds
        .get(&call_id)
        .ok_or_else(|| Problem::new(StatusCode::NOT_FOUND))?;
    let media = {
        let ss = state.stream_store.read();
        crate::sip::lint::ObservedMedia::from_streams(ss.streams_for(&call_id))
    };
    // The same linter the CLI `--lint` and the MCP tool run. Media-derived rules
    // read `media`; the rest read the dialog's messages.
    let outcome = crate::sip::lint::Linter::new(crate::sip::lint::LintConfig::new())
        .lint_dialog_with_media_detailed(dialog, &media);
    let findings: Vec<schema::LintFinding> = outcome
        .findings
        .iter()
        .map(|f| schema::LintFinding {
            rule_id: f.rule_id.to_string(),
            severity: f.severity.as_str().to_string(),
            basis: f.basis.as_str().to_string(),
            rfc: f.rfc,
            section: f.section.to_string(),
            message_index: f.message_index,
            observed: f.observed.clone(),
            expected: f.expected.clone(),
            explanation: f.explanation.clone(),
        })
        .collect();
    drop(ds);

    Ok(Json(schema::Lint {
        schema_version: 1,
        call_id,
        finding_count: findings.len(),
        findings,
    }))
}

#[cfg(feature = "vcon")]
/// `POST /v1/vcon/validate` — check a vCon container against sipnab's vendored
/// schema (PAR3: validate_vcon on REST).
///
/// # Arguments
///
/// * `state` — Shared application state (for the guard).
/// * `addr` — Client socket address used for rate limiting.
/// * `headers` — Request headers (auth).
/// * `body` — The vCon container to validate, a JSON object.
///
/// # Returns
///
/// 200 with the verdict and any findings; 400 when the body is not a JSON
/// object; 401/503 from the guard.
///
/// # Side effects
///
/// Mutates the rate limiter. Reads no store — the container comes from the
/// request, so this is the one route that validates input a caller holds.
#[utoipa::path(
    post,
    path = "/v1/vcon/validate",
    tag = "operations",
    summary = "Validate a vCon container",
    description = "Check a vCon container a caller holds against sipnab's vendored schema, the producer-and-conserver boundary where a store that would refuse a container can tell whoever built it, before it is stored.\n\n`verdict` is `valid`, `valid-except-documented-deviation` (a shape sipnab emits on purpose that the schema rejects on purpose, named in `deviations` with a paragraph in `explanations`) or `invalid` (real `errors`). The MCP `validate_vcon` tool runs the same `vcon_schema::validate`.",
    request_body(content = serde_json::Value, description = "The vCon container to validate.", content_type = "application/json"),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "The verdict and any findings.", body = schema::VconValidation),
        (status = 400, description = "The body is not a JSON object.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn post_vcon_validate(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    let Json(container) = body.map_err(|_| {
        Problem::detailed(
            StatusCode::BAD_REQUEST,
            "the body must be a JSON vCon container",
        )
    })?;
    if !container.is_object() {
        return Err(Problem::detailed(
            StatusCode::BAD_REQUEST,
            "a vCon container is a JSON object; pass the container itself, not a \
             string or array holding it",
        ));
    }

    // The shared validator the MCP tool also runs; not feature-gated, so an
    // api-only build validates too.
    let report = crate::output::vcon_schema::validate(&container);
    let finding = |f: &crate::output::vcon_schema::SchemaFinding| schema::VconFinding {
        instance_path: f.instance_path.clone(),
        keyword: f.keyword.to_string(),
        detail: f.detail.clone(),
        deviation: f.deviation.map(str::to_string),
    };

    Ok(Json(schema::VconValidation {
        schema_version: 1,
        verdict: report.verdict.as_str().to_string(),
        schema_id: report.schema_id.clone(),
        schema_path: report.schema_path.to_string(),
        errors: report.errors.iter().map(finding).collect(),
        deviations: report.deviations.iter().map(finding).collect(),
        explanations: report
            .explanations
            .iter()
            .map(|e| schema::VconExplanation {
                name: e.name.to_string(),
                explanation: e.explanation.to_string(),
            })
            .collect(),
    }))
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
    let limit = resolve_page_limit(params.limit, state.max_rows);

    let state_filter = params.state.as_deref();
    // NOTE: Regex is compiled per-request. Under the 100 RPS rate limit this
    // is acceptable (~1ms compile time). For higher throughput, consider caching.
    let from_regex = params.from.as_deref().and_then(|pat| {
        regex::RegexBuilder::new(pat)
            .size_limit(1_000_000)
            .build()
            .ok()
    });

    // Compile the DSL filter before touching the store, so a malformed
    // expression is a 400 with a reason rather than a silent unfiltered page.
    // Deliberately stricter than the `from` regex above, which is best-effort:
    // a structured query a client got wrong is a client error it must see.
    let dsl = match params.filter.as_deref() {
        Some(expr) => Some(
            crate::sip::dsl::FilterExpr::parse(expr)
                .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, format!("filter: {e}")))?,
        ),
        None => None,
    };

    // Parse the time window up front, so a malformed timestamp is a 400 rather
    // than a silently ignored window a client would read as the answer to its
    // question. `after`/`before` bound the dialog's first-message instant.
    let parse_ts = |name: &str,
                    v: Option<&str>|
     -> Result<Option<chrono::DateTime<chrono::Utc>>, Problem> {
        match v {
            Some(s) => chrono::DateTime::parse_from_rfc3339(s)
                .map(|t| Some(t.with_timezone(&chrono::Utc)))
                .map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, format!("{name}: {e}"))),
            None => Ok(None),
        }
    };
    let after = parse_ts("after", params.after.as_deref())?;
    let before = parse_ts("before", params.before.as_deref())?;

    let ds = state.dialog_store.read();
    // The DSL reads media/asymmetry fields, so it is evaluated against the
    // streams too. `select_dialogs` groups streams by Call-ID once (the same
    // path `--report` and `--json-dialogs` take, so the surfaces agree), and
    // the selected Call-IDs are ANDed with `state`/`from` below.
    let dsl_selected: Option<std::collections::HashSet<String>> = dsl.as_ref().map(|expr| {
        let ss = state.stream_store.read();
        crate::sip::dsl::select_dialogs(Some(expr), &ds, &ss)
            .dialogs
            .iter()
            .map(|(d, _)| d.call_id.clone())
            .collect()
    });

    // Materialize the FILTERED set first so `total` reflects what the page is
    // drawn from. Reporting the unfiltered store size here would break
    // pagination: a client paging by `total` over a narrower filtered result
    // would request empty pages past the real end.
    let filtered: Vec<&crate::sip::dialog::SipDialog> = ds
        .iter()
        .filter(|d| {
            if let Some(sel) = &dsl_selected
                && !sel.contains(d.call_id.as_str())
            {
                return false;
            }
            if let Some(a) = after
                && d.created_at < a
            {
                return false;
            }
            if let Some(b) = before
                && d.created_at > b
            {
                return false;
            }
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
    // Over the FILTERED set, which is what `total` counts — not over the page.
    // A breakdown of the page would describe the page, and the question this
    // answers is what `total` is made of. Same derivation the MCP `DialogPage`
    // uses, so the two surfaces cannot report different compositions of the
    // same store.
    let by_method: Vec<Value> = crate::sip::dialog::method_breakdown(filtered.iter().copied())
        .into_iter()
        .map(|(method, count)| json!({ "method": method, "count": count }))
        .collect();
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
        "by_method": by_method,
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
    let json_str = output::json::dialog_to_json(
        dialog,
        &streams,
        &diagnosis,
        quality::MosDelay::from_capture(&ss),
    );
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
    let report = output::generate_call_report(
        dialog,
        &streams,
        &diagnosis,
        output::ReportFormat::Json,
        quality::MosDelay::from_capture(&ss),
    );
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

// ── The TFPS peer ───────────────────────────────────────────────────
//
// Six routes over the toll-fraud prevention system on the same host, when
// there is one. They answer the same shapes the MCP tools of the same names
// answer, serialized from the same types in `crate::security::tfps`, so the
// two doors cannot drift. A machine without TFPS answers `200` with
// `installed: false` and the reason: that is the ordinary case and a result,
// not a failure of this server. The peer failing IS a failure -- `502` with
// its standard error verbatim in `detail`.

/// The body `POST /v1/tfps/ban` accepts.
///
/// `deny_unknown_fields` for the reason `PersistenceRequest` gives: a caller
/// who misspells `ttl_secs` is told, rather than getting a ban of the wrong
/// duration.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct TfpsBanRequest {
    /// The source to condemn, an IPv4 address (TFPS's block map is IPv4).
    ip: String,
    /// How long the ban lasts, in seconds; `0` is forever. Absent takes
    /// TFPS's default of an hour. TFPS's `ban` takes no reason.
    ttl_secs: Option<u64>,
}

/// The body `POST /v1/tfps/unban` accepts.
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
struct TfpsUnbanRequest {
    /// The source to release.
    ip: String,
}

/// Query parameters for `GET /v1/tfps/labels`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TfpsLabelsQuery {
    /// Rows TFPS returns; `0` or absent asks for the whole log. The server's
    /// `--api-max-rows` then bounds the page.
    pub limit: Option<u64>,
}

/// The peer's failure, as the problem a client sees.
///
/// `502`: the request was understood and this server is fine; the program it
/// asked on the client's behalf is what did not answer. `detail` is the
/// peer's own standard error, verbatim, because that is the diagnosis.
fn tfps_problem(e: crate::security::tfps::TfpsError) -> Problem {
    Problem::detailed(StatusCode::BAD_GATEWAY, e.to_string())
}

/// Ask the peer off the runtime thread.
///
/// `tfps_ctl` is a child process waited on synchronously; on the runtime
/// thread that wait would stall every other request for its duration.
async fn ask_tfps<T, F>(state: &ApiState, f: F) -> Result<T, Problem>
where
    T: Send + 'static,
    F: FnOnce(&crate::security::tfps::TfpsLocator) -> Result<T, crate::security::tfps::TfpsError>
        + Send
        + 'static,
{
    let locator = state.tfps.clone();
    tokio::task::spawn_blocking(move || f(&locator))
        .await
        .map_err(|_| Problem::new(StatusCode::INTERNAL_SERVER_ERROR))?
        .map_err(tfps_problem)
}

/// Read a request body as a JSON OBJECT of type `T`, or answer `400`.
///
/// The same three steps `set_persistence` spells out inline, for the same
/// reason: a derived `Deserialize` also reads a SEQUENCE, so the body has to
/// be extracted as a `Value`, checked to be an object, and only then typed.
fn object_body<T: serde::de::DeserializeOwned>(
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<T, Problem> {
    let Ok(Json(raw)) = body else {
        return Err(Problem::new(StatusCode::BAD_REQUEST));
    };
    if !raw.is_object() {
        return Err(Problem::new(StatusCode::BAD_REQUEST));
    }
    serde_json::from_value(raw).map_err(|_| Problem::new(StatusCode::BAD_REQUEST))
}

/// Parse an address out of a request, refusing anything that is not one.
///
/// Refused before the peer is asked, so the positional slot of `tfps_ctl
/// ban` can only ever hold an address.
fn tfps_ip(s: &str) -> Result<IpAddr, Problem> {
    s.trim().parse().map_err(|_| {
        Problem::detailed(
            StatusCode::BAD_REQUEST,
            format!("ip must be an IPv4 or IPv6 address, got {s:?}"),
        )
    })
}

/// `GET /v1/tfps/status` — whether TFPS is installed, and what it reports.
#[utoipa::path(
    get,
    path = "/v1/tfps/status",
    tag = "tfps",
    summary = "Read the TFPS peer's status",
    description = "Whether the toll-fraud prevention system on this host is installed and enforcing, and what it reports: enforcement state, firewall mode, interface, sources blocked right now, its database and version.\n\nA machine without TFPS answers `200` with `installed: false` and a reason. That is a result: TFPS is optional peer software, and its absence is the ordinary case.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or `installed: true` with which `tfps_ctl` answered and its `status`.", body = crate::security::tfps::TfpsStatusAnswer),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` exited non-zero, hung, or answered something off the contract. `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_tfps_status(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let reply = ask_tfps(&state, crate::security::tfps::TfpsLocator::status).await?;
    Ok(Json(crate::security::tfps::TfpsStatusAnswer::from(reply)))
}

/// `GET /v1/tfps/banned` — every source TFPS holds condemned right now.
#[utoipa::path(
    get,
    path = "/v1/tfps/banned",
    tag = "tfps",
    summary = "List the sources TFPS condemns",
    description = "The sources TFPS currently condemns: address, the rule that condemned it, what that rule saw, when the ban began and lapses, and whether the firewall holds it. Bounded by `--api-max-rows`; `total` and `truncated` say what was withheld.\n\nA machine without TFPS answers `200` with `installed: false`.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or the bounded page under `rows`.", body = crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsBanned>),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` failed; `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_tfps_banned(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let reply = ask_tfps(&state, crate::security::tfps::TfpsLocator::banned).await?;
    Ok(Json(crate::security::tfps::TfpsListAnswer::bounded(
        reply,
        state.max_rows,
    )))
}

/// `GET /v1/tfps/dropped` — what the enforcement has dropped, per source.
#[utoipa::path(
    get,
    path = "/v1/tfps/dropped",
    tag = "tfps",
    summary = "Read what TFPS's enforcement dropped",
    description = "Per condemned source, how many packets TFPS's enforcement has dropped, how many events it recorded, when it last saw the source, the rule behind the block and the last request line the source sent. Bounded by `--api-max-rows`.\n\nA machine without TFPS answers `200` with `installed: false`.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or the bounded page under `rows`.", body = crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsDropped>),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` failed; `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_tfps_dropped(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let reply = ask_tfps(&state, crate::security::tfps::TfpsLocator::dropped).await?;
    Ok(Json(crate::security::tfps::TfpsListAnswer::bounded(
        reply,
        state.max_rows,
    )))
}

/// `GET /v1/tfps/labels` — TFPS's verdict log.
#[utoipa::path(
    get,
    path = "/v1/tfps/labels",
    tag = "tfps",
    summary = "Read TFPS's verdict log",
    description = "One row per decision TFPS reached about a source: `blocked`, `would-block` (observing only) or `exempt`, with the rule, what it saw, when, and whether an operator later lifted the block. The same export the label corpus harness scores sipnab's scanner detector against. `limit` passes through to TFPS (`0` is everything); `--api-max-rows` bounds the page.\n\nA machine without TFPS answers `200` with `installed: false`.",
    params(TfpsLabelsQuery),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or the bounded page under `rows`.", body = crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsLabel>),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` failed; `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_tfps_labels(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<TfpsLabelsQuery>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    // `0` means the default, as on the MCP door -- and the export's default
    // is everything, so no `--limit` is sent.
    let limit = query.limit.filter(|n| *n > 0);
    let reply = ask_tfps(&state, move |l| l.labels(limit)).await?;
    Ok(Json(crate::security::tfps::TfpsListAnswer::bounded(
        reply,
        state.max_rows,
    )))
}

/// `POST /v1/tfps/ban` — relay an operator's decision to condemn a source.
#[utoipa::path(
    post,
    path = "/v1/tfps/ban",
    tag = "tfps",
    summary = "Ask TFPS to condemn a source",
    description = "An operator action relayed through sipnab, not a decision sipnab makes: TFPS refuses its host's own addresses and anything in its `ignoreip`, and answers with what it did -- applied, or refused and why -- which is reported as given. The automated path from sipnab's own findings to TFPS is a separate channel, never this route.\n\nA machine without TFPS answers `200` with `installed: false`.",
    request_body(content = TfpsBanRequest, description = "The source, and optionally how long. Unknown keys are refused, and so is a JSON array."),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or `installed: true` with what TFPS did under `action`. A refusal is `applied: false` with `refused` saying why, not an error.", body = crate::security::tfps::TfpsActionAnswer),
        (status = 400, description = "The body was not a JSON object with an `ip` that is an address, or it carried an unknown key.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` failed; `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn post_tfps_ban(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let req: TfpsBanRequest = object_body(body)?;
    let ip = tfps_ip(&req.ip)?;
    let ttl = req.ttl_secs;
    let reply = ask_tfps(&state, move |l| l.ban(ip, ttl)).await?;
    Ok(Json(crate::security::tfps::TfpsActionAnswer::from(reply)))
}

/// `POST /v1/tfps/unban` — relay an operator's decision to release a source.
#[utoipa::path(
    post,
    path = "/v1/tfps/unban",
    tag = "tfps",
    summary = "Ask TFPS to release a source",
    description = "An operator action relayed through sipnab. TFPS answers with what it did, and the answer is reported as given.\n\nA machine without TFPS answers `200` with `installed: false`.",
    request_body(content = TfpsUnbanRequest, description = "The source to release. Unknown keys are refused, and so is a JSON array."),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "`installed: false` with `reason`, or `installed: true` with what TFPS did under `action`.", body = crate::security::tfps::TfpsActionAnswer),
        (status = 400, description = "The body was not a JSON object with an `ip` that is an address, or it carried an unknown key.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 502, description = "`tfps_ctl` failed; `detail` carries its standard error verbatim.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn post_tfps_unban(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let req: TfpsUnbanRequest = object_body(body)?;
    let ip = tfps_ip(&req.ip)?;
    let reply = ask_tfps(&state, move |l| l.unban(ip)).await?;
    Ok(Json(crate::security::tfps::TfpsActionAnswer::from(reply)))
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
    let limit = resolve_page_limit(params.limit, state.max_rows);
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

    let json_str = output::json::stream_to_json(stream, quality::MosDelay::from_capture(&ss));
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

/// Resolve a REST caller's rate window: the shared rule, narrowed to what this
/// transport can wait out.
///
/// Extracted rather than written inline because the narrowing is the half no
/// HTTP test can afford to prove — driving it over the wire means waiting out
/// the cap — and an unexercised clamp is one somebody deletes.
///
/// # Arguments
///
/// * `requested` — the `sample_seconds` the caller sent.
///
/// # Errors
///
/// Propagates the shared refusal for a zero window.
fn rest_sample_seconds(requested: u32) -> Result<u32, &'static str> {
    Ok(crate::output::runtime::resolve_sample_seconds(requested)?.min(MAX_REST_SAMPLE_SECONDS))
}

/// `GET /v1/runtime` — what sipnab is doing and what it is costing the host.
///
/// 200 with the [`schema::Runtime`] envelope: process resources, the host's
/// totals and which basis they came from, sipnab's share of them, per-interface
/// counters, store occupancy against the caps, and the capture-path counters.
#[utoipa::path(
    get,
    path = "/v1/runtime",
    tag = "runtime",
    description = "Runtime statistics: sipnab's own resource use, the host's totals and which basis they came from, its share of them, per-interface counters read from the interface rather than from the capture handle, and store occupancy against the caps that bound it.\n\nEvery process and host field is optional: absent means \"not readable on this platform\", which is a different fact from zero and must not be rendered as one.\n\nRates are opt-in via `sample_seconds`, because measuring one costs a wait of that length. The reply carries the window that was actually applied, not the one requested.",
    params(RuntimeParams),
    responses(
        (status = 200, description = "Runtime statistics.", body = schema::Runtime),
        (status = 400, description = "A sample window of zero, or one that is not a number.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_runtime(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<RuntimeParams>,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;

    // Rates cost a wait, so they are opt-in — every counter below is
    // cumulative without them, and a cumulative total answers a different
    // question from a rate. The refusal and the clamp come from the same
    // function MCP calls, so a window one surface takes is not one the other
    // rejects.
    let sampled = match params.sample_seconds {
        Some(n) => {
            let applied = rest_sample_seconds(n)
                .map_err(|why| Problem::detailed(StatusCode::BAD_REQUEST, why.to_string()))?;
            // Sampled without holding a store lock across the wait: a reader
            // held for thirty seconds is a stall in the capture path, which is
            // the exact harm this route exists to report.
            let before = {
                let ds = state.dialog_store.read();
                crate::output::runtime::RateSample::read(&ds)
            };
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(applied))).await;
            let after = {
                let ds = state.dialog_store.read();
                crate::output::runtime::RateSample::read(&ds)
            };
            Some(crate::output::runtime::rates(&before, &after))
        }
        None => None,
    };

    let ds = state.dialog_store.read();
    let ss = state.stream_store.read();
    // One collector, shared with the MCP tool, so the two surfaces cannot
    // report different numbers for the same process.
    let mut stats = crate::output::runtime::collect(
        &ds,
        &ss,
        state.capture_meter.as_ref(),
        &state.capture_interfaces,
        state.started_at.elapsed().as_secs(),
        crate::output::runtime::SIGNIFICANT_MEMORY_PCT,
    );
    stats.rates = sampled;
    drop(ss);
    drop(ds);
    Ok(Json(serde_json::to_value(stats).unwrap_or_else(
        |e| json!({"error": format!("serialization failed: {e}")}),
    )))
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
    let mut canceled_count = 0usize;
    for d in ds.iter() {
        match d.state() {
            DialogState::Failed => failed_count += 1,
            DialogState::Completed => completed_count += 1,
            DialogState::Canceled => canceled_count += 1,
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
            "canceled": canceled_count,
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

// ── Relay statistics over REST (ST5) ─────────────────────────────────────────
//
// Four GET routes that ask the relay named by `--rtpengine-control`. Each
// transmits ONCE per request, behind `--api-allow-relay-query` and a live
// source; polling (C5) is deliberately not offered here. The five ST-S4
// refusals are HTTP 200 with a `classification` in the body, never a 4xx: the
// route exists, the relay is what did not answer. Only auth (401) and the rate
// limit (503) are `Problem` errors, via `guard`.

/// Which relay-statistics answer a REST route asks for.
enum RelayAsk {
    /// The relay's own global counters (C1).
    Wide,
    /// Its per-call counters, by Call-ID (C2).
    Call(String),
    /// Which statistics it knows, by name (C3).
    Names,
    /// Its per-call RTP count beside sipnab's own (C4).
    Compare(String),
}

/// Build the JSON body for a relay-statistics REST route (ST5).
///
/// Sync because it makes a blocking control round trip; handlers run it under
/// `spawn_blocking` so the async runtime is never held for the up-to-timeout
/// wait. Returns a 200 body in every case -- a clean answer wrapped
/// `outcome: "ok"`, or one of the five ST-S4 classifications.
fn relay_rest_answer(
    rq: &RelayRestConfig,
    ask: &RelayAsk,
    stream_store: &Arc<RwLock<StreamStore>>,
) -> Value {
    use crate::output::relay_statistics as fmt;
    use crate::relay::types::ControlReply;
    use crate::stats_vocab::{
        CompareOutcome, RelayCompareValue, StatisticsOutcome as O, known_names, ready_comparison,
        relay_compare_value, relay_reply_refusal, relay_reported, resolve_for_wire,
    };
    let to_value = |s: String| -> Value {
        serde_json::from_str(&s).unwrap_or_else(|_| json!({ "outcome": "suspect" }))
    };

    // The two invocation refusals, told apart: no relay is not_configured, a
    // relay without a permit is not_permitted. Never collapse them.
    let (relay, permit) = match (rq.relay.as_ref(), rq.permit) {
        (None, _) => {
            return to_value(fmt::relay_rest_outcome(
                O::NotConfigured,
                "no relay to ask; start the server with a relay control address",
            ));
        }
        (Some(_), None) => {
            return to_value(fmt::relay_rest_outcome(
                O::NotPermitted,
                "this run may not query the relay; it needs a live capture source and \
                 --api-allow-relay-query",
            ));
        }
        (Some(r), Some(p)) => (r, p),
    };

    let label = format!("relay ({})", relay.describe());
    let now = chrono::Utc::now();
    // A fetch that did not yield a trustworthy reply. ST-S4: a reply that
    // arrived but could not be trusted (a mismatched cookie) is `suspect` -- the
    // answer's own problem -- and everything else is `unreachable`. Classified
    // through the single seam rule so REST and the CLI agree.
    let fetch_failure = |e: &anyhow::Error| match crate::relay::types::fetch_error_outcome(e) {
        O::Suspect => to_value(fmt::relay_rest_outcome(
            O::Suspect,
            &format!("{label}: {e}; the reply was discarded and not read"),
        )),
        _ => to_value(fmt::relay_rest_outcome(
            O::Unreachable,
            &format!("{label} did not answer ({e}); asked, nothing came back"),
        )),
    };

    match ask {
        RelayAsk::Wide => match relay.statistics(&permit) {
            Ok(ControlReply::Statistics(pairs)) => {
                let wire = resolve_for_wire(&relay_reported(&pairs));
                to_value(fmt::relay_rest_ok(&fmt::format_relay_statistics_json(
                    &wire,
                    &label,
                    now,
                    fmt::FetchOrigin::Asked,
                )))
            }
            Ok(_) => to_value(fmt::relay_rest_outcome(
                O::Suspect,
                "the relay answered with something other than statistics",
            )),
            Err(e) => fetch_failure(&e),
        },
        RelayAsk::Names => match relay.statistics(&permit) {
            Ok(ControlReply::Statistics(pairs)) => {
                let names = known_names(&relay_reported(&pairs));
                to_value(fmt::relay_rest_ok(&fmt::format_relay_stat_names_json(
                    &names,
                    crate::stats_vocab::NameSource::Listed,
                    &label,
                    now,
                )))
            }
            Ok(_) => to_value(fmt::relay_rest_outcome(
                O::Suspect,
                "the relay answered with something other than statistics",
            )),
            Err(e) => fetch_failure(&e),
        },
        RelayAsk::Call(call_id) => match relay.call_statistics(&permit, call_id) {
            Ok(ControlReply::Statistics(pairs)) => {
                if let Some(reason) = relay_reply_refusal(&pairs) {
                    return to_value(fmt::relay_rest_outcome(
                        O::Refused,
                        &format!("{label} for call {call_id}: {reason}"),
                    ));
                }
                let wire = resolve_for_wire(&relay_reported(&pairs));
                to_value(fmt::relay_rest_ok(&fmt::format_relay_statistics_json(
                    &wire,
                    &format!("{label}, call {call_id}"),
                    now,
                    fmt::FetchOrigin::Asked,
                )))
            }
            Ok(_) => to_value(fmt::relay_rest_outcome(
                O::Suspect,
                "the relay answered with something other than statistics",
            )),
            Err(e) => fetch_failure(&e),
        },
        RelayAsk::Compare(call_id) => {
            // sipnab's own side: absent (no linked stream) is not measured zero.
            let ss = stream_store.read();
            let sipnab_side = if ss.streams_for(call_id).next().is_some() {
                Some(ss.measured_packet_count_for(call_id))
            } else {
                None
            };
            drop(ss);
            match relay.call_statistics(&permit, call_id) {
                Ok(ControlReply::Statistics(pairs)) => {
                    if let Some(reason) = relay_reply_refusal(&pairs) {
                        return to_value(fmt::relay_rest_outcome(
                            O::Refused,
                            &format!("{label} for call {call_id}: {reason}"),
                        ));
                    }
                    let tiered = relay_reported(&pairs);
                    // ST-S4 condition 11: a per-call total too large for u64 is a
                    // SUSPECT answer carrying its digits, never coerced to an
                    // absent side that reads as "the relay does not hold the call".
                    let relay_side = match relay_compare_value(&tiered, "totals.RTP.packets") {
                        RelayCompareValue::Overflow(digits) => {
                            return to_value(fmt::relay_rest_outcome(
                                O::Suspect,
                                &format!(
                                    "{label} reported {digits} RTP packet(s) for call {call_id}, \
                                     a value too large to compare; carried as received, not \
                                     truncated"
                                ),
                            ));
                        }
                        RelayCompareValue::Counted(n) => Some(n),
                        RelayCompareValue::Absent => None,
                    };
                    match ready_comparison(relay_side, sipnab_side) {
                        CompareOutcome::Compared(c) => to_value(fmt::relay_rest_ok(
                            &fmt::format_relay_comparison_json(&c, call_id, &label, now),
                        )),
                        // The call is on the relay, but sipnab captured no RTP for
                        // it. ST-S4: C4 with no capture reads not_configured, naming
                        // the capture (not the relay).
                        CompareOutcome::SipnabHasNoRtp { relay_value } => {
                            to_value(fmt::relay_rest_outcome(
                                O::NotConfigured,
                                &format!(
                                    "the relay reports {relay_value} RTP packet(s) for call \
                                     {call_id}, but this capture measured none for it; widen the \
                                     capture filter to include the media"
                                ),
                            ))
                        }
                        CompareOutcome::RelayDoesNotHoldCall { .. } => {
                            to_value(fmt::relay_rest_outcome(
                                O::Refused,
                                &format!("{label} does not hold call {call_id}"),
                            ))
                        }
                        CompareOutcome::NeitherSide => to_value(fmt::relay_rest_outcome(
                            O::Refused,
                            &format!(
                                "neither the relay nor this capture has RTP for call {call_id}"
                            ),
                        )),
                    }
                }
                Ok(_) => to_value(fmt::relay_rest_outcome(
                    O::Suspect,
                    "the relay answered with something other than statistics",
                )),
                Err(e) => fetch_failure(&e),
            }
        }
    }
}

/// `GET /v1/relay/stats` — the relay's own global counters (ST5 / C1).
#[utoipa::path(
    get,
    path = "/v1/relay/stats",
    tag = "relay",
    summary = "The relay's own global statistics",
    description = "The counters the configured relay keeps about itself, tiered relay_reported. \
                   Transmits once, behind --api-allow-relay-query on a live run. When no clean \
                   answer is obtained the body carries an ST-S4 classification and is still 200 \
                   -- the route exists, the relay is what did not answer.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "outcome=ok with the relay's counters, or a classification (not_configured/not_permitted/unreachable/refused/suspect).", body = schema::RelayStatsResponse),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_relay_stats(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let rq = state.relay_query.clone();
    let ss = Arc::clone(&state.stream_store);
    let body = tokio::task::spawn_blocking(move || relay_rest_answer(&rq, &RelayAsk::Wide, &ss))
        .await
        .unwrap_or_else(|_| json!({ "outcome": "suspect" }));
    Ok(Json(body))
}

/// `GET /v1/relay/stats/names` — which statistics the relay knows (ST5 / C3).
#[utoipa::path(
    get,
    path = "/v1/relay/stats/names",
    tag = "relay",
    summary = "Which statistics the relay knows",
    description = "The names the relay can report, obtained by asking it (never a built-in \
                   table), so a caller learns what to ask for before a request fails on a name \
                   this build lacks. Names only, no values. Same gate and 200-classification \
                   rule as /v1/relay/stats.",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "outcome=ok with the name list, or a classification.", body = schema::RelayStatsResponse),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_relay_stat_names(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let rq = state.relay_query.clone();
    let ss = Arc::clone(&state.stream_store);
    let body = tokio::task::spawn_blocking(move || relay_rest_answer(&rq, &RelayAsk::Names, &ss))
        .await
        .unwrap_or_else(|_| json!({ "outcome": "suspect" }));
    Ok(Json(body))
}

/// `GET /v1/relay/stats/call/{call_id}` — the relay's per-call counters (C2).
#[utoipa::path(
    get,
    path = "/v1/relay/stats/call/{call_id}",
    tag = "relay",
    summary = "The relay's per-call statistics",
    description = "The relay's own counters for one call, by Call-ID, tiered relay_reported. A \
                   relay that does not hold the call answers in its own words, reported as \
                   refused with the relay's reason -- not rendered as counters. Same gate and \
                   200-classification rule as /v1/relay/stats.",
    params(("call_id" = String, Path, description = "The SIP Call-ID, as the relay knows it.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "outcome=ok with the per-call counters, or a classification.", body = schema::RelayStatsResponse),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_relay_stats_call(
    State(state): State<ApiState>,
    axum::extract::Path(call_id): axum::extract::Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let rq = state.relay_query.clone();
    let ss = Arc::clone(&state.stream_store);
    let body =
        tokio::task::spawn_blocking(move || relay_rest_answer(&rq, &RelayAsk::Call(call_id), &ss))
            .await
            .unwrap_or_else(|_| json!({ "outcome": "suspect" }));
    Ok(Json(body))
}

/// `GET /v1/relay/compare/{call_id}` — relay's count vs sipnab's capture (C4).
#[utoipa::path(
    get,
    path = "/v1/relay/compare/{call_id}",
    tag = "relay",
    summary = "Compare the relay's per-call count against this capture",
    description = "The relay's totals.RTP.packets for one call beside sipnab's own measured \
                   count, both tiers named, with a word verdict and a note -- never summed. A \
                   call this capture measured no RTP for reads not_configured (naming the \
                   capture), a relay that does not hold it reads refused. Same gate and \
                   200-classification rule as /v1/relay/stats.",
    params(("call_id" = String, Path, description = "The SIP Call-ID to compare.")),
    security(("bearer" = [])),
    responses(
        (status = 200, description = "outcome=ok with the comparison, or a classification.", body = schema::RelayStatsResponse),
        (status = 401, description = "No bearer credential, or one this server does not accept.", body = schema::ProblemJson, content_type = "application/problem+json"),
        (status = 503, description = "Over the per-source-IP rate limit of 100 requests per second.", body = schema::ProblemJson, content_type = "application/problem+json"),
    )
)]
async fn get_relay_compare(
    State(state): State<ApiState>,
    axum::extract::Path(call_id): axum::extract::Path<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, Problem> {
    guard(&state, &headers, addr.ip())?;
    let rq = state.relay_query.clone();
    let ss = Arc::clone(&state.stream_store);
    let body = tokio::task::spawn_blocking(move || {
        relay_rest_answer(&rq, &RelayAsk::Compare(call_id), &ss)
    })
    .await
    .unwrap_or_else(|_| json!({ "outcome": "suspect" }));
    Ok(Json(body))
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

    // The capture meter, same as the standalone server. Without it these two
    // read a flat `0` -- "the queue is clear" on a box whose queue is full --
    // which is what this door published until `ApiState` started carrying the
    // meter.
    if let Some(meter) = state.capture_meter.as_ref() {
        metrics.capture_queue_depth_packets = meter.in_flight() as u64;
        metrics.capture_backpressure_blocks_total = meter.backpressure_blocks();
    }

    // Populate from dialog store. The stream store is read alongside it (in
    // that order, matching every other handler) because the per-dialog media
    // diagnosis needs both.
    //
    // One assembler, shared with the standalone `--metrics` server. They used
    // to be two, and they disagreed about the dialog-state label's case and
    // about what `rtp_streams_active` counts.
    let ds = state.dialog_store.read();
    let ss = state.stream_store.read();
    prometheus::populate_from_stores(&mut metrics, &ds, &ss);
    drop(ss);
    drop(ds);

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

    /// What this build can do and what the operator turned on: the machine
    /// contract a client reads before it asks, so a refusal it could have
    /// predicted does not read as a dead end. The build fields are the same the
    /// MCP `server_capabilities` tool returns — one canonical `compiled_features`
    /// list — paired with the REST server's own runtime opt-ins.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Capabilities {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The crate version this binary was built from.
        pub version: String,
        /// Compiled-in feature names, sorted. The canonical `compiled_features`
        /// list, shared with `--version` and the MCP tool so no two surfaces
        /// claim different builds of the same binary.
        pub features: Vec<String>,
        /// True when this build can decrypt TLS.
        pub can_decrypt: bool,
        /// True when this build can receive HEP.
        pub can_hep: bool,
        /// True when this build can load WASM plugins.
        pub can_plugins: bool,
        /// The REST server's runtime opt-ins.
        pub runtime: CapabilitiesRuntime,
    }

    /// The REST server's startup opt-ins, each off by default, so a client can
    /// tell a capability this build lacks from one this run did not turn on.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct CapabilitiesRuntime {
        /// Whether this run may transmit a relay query — `--api-allow-relay-query`
        /// on a live source. Off means the `/v1/relay/...` routes answer
        /// `not_configured` or `not_permitted` rather than reaching the relay.
        pub api_allow_relay_query: bool,
    }

    /// One other leg of a call, and the strategy that matched it. The fields
    /// mirror the MCP `find_correlated` tool's `CorrelatedLeg`, built from the
    /// one `CorrelationResult::strategy_and_gap` rule so the two surfaces cannot
    /// disagree about whether a strategy is an identifier match.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct CorrelatedLeg {
        /// Call-ID of the correlated dialog. Feed it to `/v1/dialogs/{call_id}`.
        pub call_id: String,
        /// Confidence, 0-100.
        #[schema(minimum = 0, maximum = 100)]
        pub score: u8,
        /// Which strategy matched, by name: `session_id`, `x_call_id`,
        /// `sdp_origin`, `charging_vector_related_icid`, `charging_vector_icid`,
        /// `via_branch` or `timing_heuristic`.
        pub strategy: String,
        /// True when the strategy compared identifiers, false for a guess.
        pub identifier_match: bool,
        /// For `timing_heuristic` only: the observed gap between the two
        /// dialogs' creation, in milliseconds. Null for an identifier match,
        /// where it would be a number with no bearing on why they matched.
        pub observed_gap_ms: Option<i64>,
    }

    /// The other legs of one call, with the source it was asked about.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Correlated {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The Call-ID the legs were correlated against.
        pub source_call_id: String,
        /// The correlated legs, highest score first.
        pub legs: Vec<CorrelatedLeg>,
        /// How many legs matched before the row cap.
        pub total_matched: usize,
        /// True when every matched leg is a timing guess rather than an
        /// identifier match, so a reader weighs the whole answer accordingly.
        pub heuristic_only: bool,
    }

    /// One leg of a call tree: a dialog, and how the walk reached it. Follow
    /// `call_id` to `/v1/dialogs/{call_id}` for the leg's detail.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct CallTreeLeg {
        /// Call-ID of this leg.
        pub call_id: String,
        /// Hops from the root. Zero for the root itself.
        pub depth: u32,
        /// The leg this one was correlated FROM. Null for the root.
        pub parent_call_id: Option<String>,
        /// Confidence of the edge from the parent, 0-100. Null for the root.
        #[schema(minimum = 0, maximum = 100)]
        pub score: Option<u8>,
        /// Which strategy matched this edge. Null for the root.
        pub strategy: Option<String>,
        /// Whether the edge compared identifiers rather than guessing. Null for
        /// the root, which the caller named rather than the walk matching.
        pub identifier_match: Option<bool>,
        /// Whether the walk continued THROUGH this leg. False on a leg reached
        /// by a timing guess, and on any leg the cap cut the walk short of.
        pub followed: bool,
    }

    /// The tree of legs reachable from one call across a B2BUA, SBC or PBX.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct CallTree {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// Call-ID the walk started from, echoed verbatim.
        pub root_call_id: String,
        /// Every leg found, ordered by depth then creation time.
        pub legs: Vec<CallTreeLeg>,
        /// Number of legs returned, root included.
        pub total_legs: usize,
        /// Deepest hop count reached.
        pub max_depth: u32,
        /// True when the row cap stopped the walk before it ran out of legs.
        pub truncated: bool,
        /// How many edges are timing guesses rather than identifier matches.
        pub heuristic_edges: usize,
        /// Total SIP messages across every leg.
        pub total_messages: usize,
        /// Earliest leg creation time in the tree, RFC 3339.
        pub first_activity: Option<String>,
        /// Latest leg update time in the tree, RFC 3339.
        pub last_activity: Option<String>,
    }

    /// One bucket of an aggregate: a grouped value and how many dialogs fell in
    /// it. A null in the data becomes the literal `(none)` rather than being
    /// dropped, so the buckets sum to the total.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct AggregateBucket {
        /// The grouped value, rendered as a string.
        pub value: String,
        /// How many dialogs fell in this bucket.
        pub count: usize,
    }

    /// A "how many, by what" count over the dialog store, one dimension.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Aggregate {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The dimension the count grouped by, echoed verbatim.
        pub group_by: String,
        /// The buckets, largest first, ties broken by value for a stable answer.
        pub buckets: Vec<AggregateBucket>,
        /// Total count in every bucket past the `top_n` cut, so the answer still
        /// sums to `total_matched`.
        pub other_count: usize,
        /// How many distinct values the dimension took, before the cut.
        pub distinct_values: usize,
        /// How many dialogs the filter admitted, across all buckets.
        pub total_matched: usize,
    }

    /// One RFC-conformance finding: the rule, its severity and basis, the RFC
    /// section it reads from, and what the message held against what the section
    /// calls for. The same fields the MCP `lint_dialog` tool reports.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct LintFinding {
        /// The rule that fired.
        pub rule_id: String,
        /// How loudly to report it: `error`, `warning` or `info`.
        pub severity: String,
        /// What kind of claim the rule makes: `must`, `should`, `interop` or
        /// `observation`. A `must` violation and an interop wart are not the
        /// same finding, and the word keeps them apart.
        pub basis: String,
        /// RFC number the rule reads from.
        pub rfc: u32,
        /// Section within that RFC.
        pub section: String,
        /// Index into the dialog's messages of the message the finding is drawn
        /// from.
        pub message_index: usize,
        /// What the capture actually holds.
        pub observed: String,
        /// What the cited section calls for.
        pub expected: String,
        /// Why the difference matters, in the terms an operator acts on.
        pub explanation: String,
    }

    /// The RFC-conformance findings for one dialog.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Lint {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The Call-ID the findings are for.
        pub call_id: String,
        /// How many findings the dialog tripped.
        pub finding_count: usize,
        /// The findings, in the linter's own order.
        pub findings: Vec<LintFinding>,
    }

    /// One place a vCon container disagrees with the vendored schema.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct VconFinding {
        /// JSON Pointer to the offending value, `/dialog/2` shaped.
        pub instance_path: String,
        /// The schema keyword that refused it.
        pub keyword: String,
        /// What was wrong, in one sentence.
        pub detail: String,
        /// The documented deviation this finding IS, when it is one; absent for
        /// an ordinary error.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub deviation: Option<String>,
    }

    /// Why a documented deviation is a deviation rather than an error.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct VconExplanation {
        /// The deviation name the findings reference.
        pub name: String,
        /// One paragraph on why sipnab emits it and the schema rejects it.
        pub explanation: String,
    }

    /// The verdict on a vCon container checked against the vendored schema.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct VconValidation {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The one-word verdict: `valid`, `valid-except-documented-deviation`
        /// or `invalid`.
        pub verdict: String,
        /// The `$id` the vendored schema declares.
        pub schema_id: String,
        /// Where that schema lives in the repository.
        pub schema_path: String,
        /// Findings that are NOT documented deviations. Empty on a clean pass.
        pub errors: Vec<VconFinding>,
        /// Findings that ARE documented deviations, kept apart from the errors.
        pub deviations: Vec<VconFinding>,
        /// One paragraph per distinct deviation named above.
        pub explanations: Vec<VconExplanation>,
    }

    /// One interval of a call-volume histogram.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct TimelineBucket {
        /// Start of the interval, inclusive, RFC 3339. Aligned to the epoch, not
        /// to the first call, so two captures line up.
        pub start: String,
        /// Width of the interval in seconds, echoed so a row reads on its own.
        pub bucket_seconds: u64,
        /// Dialogs whose first message fell in this interval.
        pub dialogs: u64,
    }

    /// Call volume over time, in fixed-width buckets.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Timeline {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// One row per interval, oldest first, gaps included (an empty interval
        /// is the outage, so it is not dropped).
        pub buckets: Vec<TimelineBucket>,
        /// Rows in `buckets`.
        pub returned: usize,
        /// The bucket width actually used, echoed because the caller may have
        /// omitted it.
        pub bucket_seconds: u64,
    }

    /// One call summarized for a side-by-side comparison: the fields
    /// `/v1/dialogs/compare` diffs, the same the MCP `compare_dialogs` tool
    /// reports.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct ComparisonSide {
        /// The dialog's Call-ID.
        pub call_id: String,
        /// The dialog state (`InCall`, `Failed`, `Completed`, …).
        pub state: String,
        /// The final INVITE response code, null while the call is in progress.
        pub final_status_code: Option<u16>,
        /// How many SIP messages the dialog holds.
        pub msg_count: usize,
        /// The distinct request methods seen, sorted.
        pub methods: Vec<String>,
        /// The signaling-diagnosis hints for the call.
        pub hints: Vec<String>,
    }

    /// Two calls side by side, naming which fields differ.
    #[derive(Debug, Clone, serde::Serialize, ToSchema)]
    pub struct Comparison {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The first call's summary.
        pub a: ComparisonSide,
        /// The second call's summary.
        pub b: ComparisonSide,
        /// The field names that differ — a subset of `state`,
        /// `final_status_code`, `msg_count`, `methods`, in that order. Empty
        /// when the two calls match on all four. `hints` is reported per side
        /// but not diffed.
        pub differences: Vec<String>,
    }

    /// A page of dialogs updated since a cursor, for change-tracking pollers.
    /// Doc-only, like [`DialogList`]: the route answers with the same untyped
    /// summaries `/v1/dialogs` builds, so this mirrors the shape for the
    /// contract test rather than being serialized directly.
    #[derive(Debug, Clone, ToSchema)]
    pub struct TailPage {
        /// Version of this response's shape.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// The dialogs updated strictly after the request cursor, oldest update
        /// first, ties broken by Call-ID.
        pub dialogs: Vec<DialogSummary>,
        /// Opaque cursor (`<RFC 3339>|<Call-ID>` of the last row) to pass back
        /// as `since` to resume. Null when no dialogs matched.
        pub next_cursor: Option<String>,
        /// Rows in `dialogs`.
        pub returned: usize,
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
        /// The E-model R-factor the MOS was converted from, same delay basis
        /// and same grounding caveat. An SLA is written in R, and R is the
        /// linear scale.
        pub r_factor: f64,
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
        /// WHO asserted the SDP media endpoint that named the dialog:
        /// `signaled` or `media-relay`.
        ///
        /// Missing from this document until 0.5.161 while the response
        /// carried it, because nothing compares this schema against the model
        /// it describes — see the backlog's DUP section.
        pub dialog_assertion: Option<String>,
        /// The single AMR or AMR-WB mode, kbit/s, that every readable frame of
        /// this stream was coded at. Absent when the sender switched mode, and
        /// absent when the payloads could not be read at all.
        pub amr_mode_kbps: Option<f64>,
        /// How many DISTINCT AMR speech modes the payloads carried. Absent,
        /// never zero, when none were read — so a present value always means
        /// sipnab read the wire.
        pub amr_modes_observed: Option<u32>,
    }

    /// One opening method and how many dialogs in the filtered set it opened.
    ///
    /// A list of pairs rather than an object: JSON object key order is not
    /// guaranteed, and the useful reading of this field is "what dominates",
    /// which only an ordered sequence can carry.
    #[derive(Debug, Clone, ToSchema)]
    pub struct MethodCount {
        /// The method that opened the dialogs — `INVITE`, `REGISTER`, and so
        /// on.
        #[schema(example = "OPTIONS")]
        pub method: String,
        /// How many dialogs in the filtered set it opened.
        #[schema(example = 98)]
        pub count: usize,
    }

    /// sipnab's own process, from `/proc/self`.
    ///
    /// Every field is optional: absent means "not readable on this platform",
    /// which is a different fact from zero and must not be rendered as one.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeProcess {
        /// Resident set size, bytes.
        pub rss_bytes: Option<u64>,
        /// Virtual size, bytes.
        pub virtual_bytes: Option<u64>,
        /// OS threads.
        pub threads: Option<u64>,
        /// Open file descriptors.
        pub open_fds: Option<u64>,
        /// CPU seconds, user plus system.
        pub cpu_seconds: Option<f64>,
    }

    /// The host's totals, or the cgroup's limits inside a container.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeHost {
        /// Total memory, bytes.
        pub memory_total_bytes: Option<u64>,
        /// Memory available without swapping, bytes.
        pub memory_available_bytes: Option<u64>,
        /// Logical CPUs.
        pub cpus: Option<u64>,
        /// Which denominator the figures came from: `host` or `cgroup`.
        ///
        /// Named rather than assumed. A percentage against the machine's total
        /// is wrong by a large factor inside a container with a small limit.
        #[schema(example = "host")]
        pub basis: String,
    }

    /// sipnab's share of the host, and whether that share is load-bearing.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeImpact {
        /// Resident set as a percentage of the host total.
        pub memory_pct: Option<f64>,
        /// Whether sipnab is a load-bearing consumer right now.
        pub significant: Option<bool>,
        /// Why, including the threshold and the basis.
        pub note: Option<String>,
    }

    /// What an interface reports about itself, as distinct from what sipnab's
    /// capture handle saw.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeInterface {
        /// The interface name.
        pub name: String,
        /// Link state.
        pub operstate: Option<String>,
        /// Negotiated speed, Mbit/s. Absent on a virtual interface.
        pub speed_mbps: Option<u64>,
        /// MTU.
        pub mtu: Option<u64>,
        /// Packets received by the interface.
        pub rx_packets: Option<u64>,
        /// Bytes received by the interface.
        pub rx_bytes: Option<u64>,
        /// Receive errors.
        pub rx_errors: Option<u64>,
        /// Packets the interface dropped.
        pub rx_dropped: Option<u64>,
        /// Packets missed because the NIC could not keep up.
        pub rx_missed_errors: Option<u64>,
    }

    /// A store's occupancy against the cap it evicts at.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeOccupancy {
        /// What the store holds now.
        pub used: u64,
        /// What it can hold.
        pub capacity: u64,
        /// `used` over `capacity`, absent when the cap is zero.
        pub pct: Option<f64>,
    }

    /// `GET /v1/runtime` — runtime statistics.
    #[derive(Debug, Clone, ToSchema)]
    pub struct Runtime {
        /// Wire-format version of this envelope.
        #[schema(example = 1)]
        pub schema_version: u32,
        /// sipnab's own process.
        pub process: RuntimeProcess,
        /// The host, or the cgroup when sipnab runs inside one.
        pub host: RuntimeHost,
        /// sipnab's share of it.
        pub impact: RuntimeImpact,
        /// Per-capture-interface counters.
        pub interfaces: Vec<RuntimeInterface>,
        /// Dialog-store occupancy.
        pub dialogs: RuntimeOccupancy,
        /// Stream-store occupancy.
        pub streams: RuntimeOccupancy,
        /// Packets the capture path has seen.
        pub capture_packets_total: u64,
        /// Packets waiting in the capture queue. Absent when this run owns no
        /// capture meter — never zero, which would read as a clear queue.
        pub capture_queue_depth_packets: Option<u64>,
        /// Times the capture path blocked on a full queue. Absent for the
        /// reason above.
        pub capture_backpressure_blocks_total: Option<u64>,
        /// Seconds this process has been serving.
        pub uptime_seconds: u64,
        /// Rates across the sampled window. Present only when the caller sent
        /// `sample_seconds`.
        pub rates: Option<RuntimeRates>,
    }

    /// Rates measured across a sampling window.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RuntimeRates {
        /// The window actually sampled, seconds — not the one requested.
        pub window_seconds: u64,
        /// Packets per second across the window.
        pub packets_per_second: f64,
        /// Dialogs opened per second across the window.
        pub calls_per_second: f64,
        /// Dialogs opened per second, split by the method that opened them,
        /// most-opened first. `[["OPTIONS", 2.8], ["INVITE", 0.6]]`.
        pub calls_per_second_by_method: Vec<(String, f64)>,
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
        /// What `total` is made of, split by the method that opened each
        /// dialog and ordered dominant-first.
        ///
        /// Over the filtered set, not over this page: a breakdown of the page
        /// would describe the page. A dialog list is dominated by whatever the
        /// deployment does most, which in the field is usually the keepalive
        /// plane rather than the calls, and without this a client cannot tell
        /// that from the rows it was handed.
        pub by_method: Vec<MethodCount>,
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

    /// `GET /v1/relay/...` — one envelope for all four relay-statistics routes
    /// (ST5).
    ///
    /// `outcome` is always present: `ok` for a clean answer, or one of the five
    /// ST-S4 classifications. Every other field is optional because the shape
    /// depends on which route answered and whether it was clean -- a client
    /// branches on `outcome` first. Deliberately permissive (the payload
    /// sub-objects are open) because one envelope carries four different clean
    /// shapes plus the classifications, and pinning each would be five schemas
    /// where the discriminator already tells them apart.
    #[derive(Debug, Clone, ToSchema)]
    pub struct RelayStatsResponse {
        /// `ok`, or `not_configured` / `not_permitted` / `unreachable` /
        /// `refused` / `suspect`.
        pub outcome: String,
        /// The relay and where it was asked, on any answer that reached it.
        pub relay: Option<String>,
        /// When the relay answered.
        pub obtained_at: Option<String>,
        /// `asked` on these routes (a poll is CLI-only and never appears here).
        pub origin: Option<String>,
        /// The relay's counters (C1/C2), each with its tier.
        pub statistics: Option<serde_json::Value>,
        /// Statistics the relay refused, with its own code, listed apart.
        pub refusals: Option<serde_json::Value>,
        /// How the name list was determined: `listed` or `probed` (C3).
        pub source: Option<String>,
        /// The names the relay knows (C3).
        pub names: Option<serde_json::Value>,
        /// The relay-vs-capture comparison (C4): both tiers, a verdict, a note.
        pub packets: Option<serde_json::Value>,
        /// Whose problem a non-`ok` outcome is: `invocation` / `relay_or_network`
        /// / `request` / `answer`.
        pub responsibility: Option<String>,
        /// A sentence explaining a non-`ok` outcome.
        pub detail: Option<String>,
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
                       capture, plus three writes: closing the persistence \
                       gate, and relaying an operator's ban or release to the \
                       toll-fraud prevention peer when one is installed.\n\n\
                       The server reads the same \
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
        get_correlated,
        get_tree,
        get_aggregate,
        get_timeline,
        get_compare,
        get_dialogs_tail,
        get_lint,
        get_persistence,
        set_persistence,
        get_tfps_status,
        get_tfps_banned,
        get_tfps_dropped,
        get_tfps_labels,
        post_tfps_ban,
        post_tfps_unban,
        list_streams,
        get_stream,
        get_capture_report,
        get_stats,
        get_relay_stats,
        get_relay_stat_names,
        get_relay_stats_call,
        get_relay_compare,
        get_runtime,
        get_capabilities,
        get_metrics,
    ),
    components(schemas(
        schema::ProblemJson,
        schema::Capabilities,
        schema::CapabilitiesRuntime,
        schema::CorrelatedLeg,
        schema::Correlated,
        schema::CallTreeLeg,
        schema::CallTree,
        schema::AggregateBucket,
        schema::Aggregate,
        schema::LintFinding,
        schema::Lint,
        schema::TimelineBucket,
        schema::Timeline,
        schema::ComparisonSide,
        schema::Comparison,
        schema::TailPage,
        schema::RelayStatsResponse,
        schema::DialogList,
        schema::DialogSummary,
        schema::TimingSummary,
        schema::StreamList,
        schema::StreamSummary,
        schema::PersistenceState,
        PersistenceRequest,
        TfpsBanRequest,
        TfpsUnbanRequest,
        crate::security::tfps::TfpsStatus,
        crate::security::tfps::TfpsBanned,
        crate::security::tfps::TfpsDropped,
        crate::security::tfps::TfpsLabel,
        crate::security::tfps::TfpsAction,
        crate::security::tfps::TfpsStatusAnswer,
        crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsBanned>,
        crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsDropped>,
        crate::security::tfps::TfpsListAnswer<crate::security::tfps::TfpsLabel>,
        crate::security::tfps::TfpsActionAnswer,
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
        (name = "operations", description = "Liveness, metrics, and the persistence gate"),
        (name = "tfps", description = "The toll-fraud prevention peer on this host, when one is installed: what it condemns, what it dropped, its verdict log, and an operator's ban or release relayed to it")
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
#[openapi(
    paths(get_dialog_vcon, post_vcon_validate),
    components(schemas(
        schema::Vcon,
        schema::VconValidation,
        schema::VconFinding,
        schema::VconExplanation
    ))
)]
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
    /// Two dialogs sharing one RFC 7989 Session-ID, so `find_correlated` links
    /// them by the `session_id` strategy (an identifier match). `leg-0@test`
    /// and `leg-1@test`.
    fn populate_correlated_dialogs(state: &ApiState) {
        let mut ds = state.dialog_store.write();
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap();
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let session = "ab30317f1a784dc48ff97d6dd1a2b3c4";
        for i in 0..2 {
            let raw = build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    &format!("From: <sip:user{i}@example.com>;tag=t{i}"),
                    "To: <sip:bob@example.com>",
                    &format!("Call-ID: leg-{i}@test"),
                    &format!("Session-ID: {session}"),
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

    /// `GET /v1/dialogs/{id}/correlated` names the other legs of a call and the
    /// strategy that matched each. Closes the find_correlated REST gap.
    #[tokio::test]
    async fn correlated_returns_the_linked_leg() {
        let state = make_state();
        populate_correlated_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/leg-0%40test/correlated"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["source_call_id"], "leg-0@test");
        let legs = parsed["legs"].as_array().expect("legs array");
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0]["call_id"], "leg-1@test");
        assert_eq!(legs[0]["strategy"], "session_id");
        assert_eq!(legs[0]["identifier_match"], true);
        assert_eq!(parsed["total_matched"], 1);
    }

    /// An unknown Call-ID is a 404, the same answer `GET /v1/dialogs/{id}`
    /// gives, rather than an empty-legs 200 that reads as "this call has no
    /// other legs" when the truth is "this call is not here".
    #[tokio::test]
    async fn correlated_unknown_call_id_is_404() {
        let state = make_state();
        populate_correlated_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/nope%40nowhere/correlated"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A known dialog with no correlated legs is an empty list, not a 404: the
    /// call exists, it simply stands alone. Built as the only dialog in the
    /// store, so nothing — not even the timing heuristic — can match it.
    #[tokio::test]
    async fn correlated_uncorrelated_dialog_is_empty() {
        let state = make_state();
        {
            let mut ds = state.dialog_store.write();
            let ts =
                chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap();
            let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            let raw = build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    "From: <sip:alice@example.com>;tag=t0",
                    "To: <sip:bob@example.com>",
                    "Call-ID: lonely@test",
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
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/lonely%40test/correlated"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["legs"].as_array().expect("array").len(), 0);
        assert_eq!(parsed["total_matched"], 0);
    }

    /// `GET /v1/dialogs/{id}/tree` walks the whole correlation tree, root first.
    /// Closes the get_call_tree REST gap.
    #[tokio::test]
    async fn tree_walks_from_the_root() {
        let state = make_state();
        populate_correlated_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/leg-0%40test/tree"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["root_call_id"], "leg-0@test");
        assert_eq!(parsed["total_legs"], 2);
        assert_eq!(parsed["max_depth"], 1);
        // Both legs are joined by session_id, an identifier match, so no edge is
        // a guess.
        assert_eq!(parsed["heuristic_edges"], 0);
        let legs = parsed["legs"].as_array().expect("legs");
        assert_eq!(legs[0]["call_id"], "leg-0@test");
        assert_eq!(legs[0]["depth"], 0);
        assert_eq!(legs[1]["call_id"], "leg-1@test");
        assert_eq!(legs[1]["depth"], 1);
        assert_eq!(legs[1]["strategy"], "session_id");
        assert_eq!(legs[1]["identifier_match"], true);
    }

    /// An unknown Call-ID is a 404, matching the sibling dialog routes.
    #[tokio::test]
    async fn tree_unknown_call_id_is_404() {
        let state = make_state();
        populate_correlated_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/nope%40nowhere/tree"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── aggregate (PAR3: aggregate_dialogs) ───────────────────────────

    /// `GET /v1/aggregate?by=from.user` counts each distinct user once. Closes
    /// the aggregate_dialogs REST gap.
    #[tokio::test]
    async fn aggregate_groups_by_from_user() {
        let state = make_state();
        populate_dialogs(&state); // from users user0/user1/user2
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/aggregate?by=from.user"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["group_by"], "from.user");
        assert_eq!(parsed["distinct_values"], 3);
        assert_eq!(parsed["total_matched"], 3);
        let buckets = parsed["buckets"].as_array().expect("buckets");
        assert_eq!(buckets.len(), 3);
        // Each user appears once; ties broken by value, so user0/1/2 in order.
        for (i, b) in buckets.iter().enumerate() {
            assert_eq!(b["value"], format!("user{i}"));
            assert_eq!(b["count"], 1);
        }
    }

    /// Grouping by `state` puts all three seeded dialogs in one bucket.
    #[tokio::test]
    async fn aggregate_by_state_is_one_bucket() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/aggregate?by=state"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["distinct_values"], 1);
        assert_eq!(parsed["total_matched"], 3);
        assert_eq!(parsed["buckets"][0]["count"], 3);
    }

    /// A dimension outside the groupable set is a 400 that lists the real ones.
    #[tokio::test]
    async fn aggregate_unknown_dimension_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/aggregate?by=bogus"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A missing dimension is a 400: `by` is required.
    #[tokio::test]
    async fn aggregate_missing_dimension_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/aggregate"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── timeline (PAR3: timeline) ─────────────────────────────────────

    /// `GET /v1/timeline` buckets calls by time. The three seeded dialogs share
    /// one second, so they fall in one bucket. Closes the timeline REST gap.
    #[tokio::test]
    async fn timeline_buckets_the_calls() {
        let state = make_state();
        populate_dialogs(&state); // all open at 2024-06-15T12:00:00Z
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/timeline"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["bucket_seconds"], 60);
        assert_eq!(parsed["returned"], 1);
        let buckets = parsed["buckets"].as_array().expect("buckets");
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0]["dialogs"], 3);
        assert_eq!(buckets[0]["bucket_seconds"], 60);
    }

    /// The requested bucket width is honored and echoed on the answer.
    #[tokio::test]
    async fn timeline_honors_the_requested_width() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/timeline?bucket_seconds=3600"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["bucket_seconds"], 3600);
        assert_eq!(parsed["buckets"][0]["dialogs"], 3);
    }

    /// A zero bucket width is a 400, not an answer: it describes no interval.
    #[tokio::test]
    async fn timeline_zero_width_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/timeline?bucket_seconds=0"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── compare (PAR3: compare_dialogs) ───────────────────────────────

    /// Seed one answered call (`answered@test`, INVITE→200) and one busy call
    /// (`busy@test`, INVITE→486), so a comparison has both a difference (state
    /// and outcome code) and a match (one INVITE each, two messages each).
    fn seed_compare_pair(state: &ApiState) {
        let mut ds = state.dialog_store.write();
        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap();
        let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut feed = |start: &str, call_id: &str, to_tag: bool| {
            let to = if to_tag {
                "To: <sip:bob@example.com>;tag=t2"
            } else {
                "To: <sip:bob@example.com>"
            };
            let raw = build_sip(
                start,
                &[
                    "From: <sip:alice@example.com>;tag=t1",
                    to,
                    &format!("Call-ID: {call_id}"),
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
        };
        feed("INVITE sip:bob@example.com SIP/2.0", "answered@test", false);
        feed("SIP/2.0 200 OK", "answered@test", true);
        feed("INVITE sip:bob@example.com SIP/2.0", "busy@test", false);
        feed("SIP/2.0 486 Busy Here", "busy@test", true);
    }

    /// `GET /v1/dialogs/compare` names the fields that differ and stays silent
    /// on the ones that match. Closes the compare_dialogs REST gap.
    #[tokio::test]
    async fn compare_names_the_fields_that_differ() {
        let state = make_state();
        seed_compare_pair(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request(
                "/v1/dialogs/compare?a=answered@test&b=busy@test",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["a"]["state"], "InCall");
        assert_eq!(parsed["a"]["final_status_code"], 200);
        assert_eq!(parsed["b"]["state"], "Failed");
        assert_eq!(parsed["b"]["final_status_code"], 486);
        // State and outcome moved; method set and message count did not.
        assert_eq!(
            parsed["differences"],
            serde_json::json!(["state", "final_status_code"])
        );
    }

    /// A Call-ID with no dialog is a 404 that names which of the two is missing.
    #[tokio::test]
    async fn compare_unknown_call_id_is_404() {
        let state = make_state();
        seed_compare_pair(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request(
                "/v1/dialogs/compare?a=answered@test&b=ghost@test",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A comparison with no second call is a 400: the route needs two Call-IDs,
    /// and a request naming one is a mistake, not an empty answer.
    #[tokio::test]
    async fn compare_missing_b_is_400() {
        let state = make_state();
        seed_compare_pair(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/compare?a=answered@test"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── tail (PAR3: tail_dialogs) ─────────────────────────────────────

    /// Without a cursor, every dialog comes back and a `next_cursor` names the
    /// last row — and that cursor is URL-safe (Zulu, no `+`), because a client
    /// passes it straight back in the `since` query. Closes the tail REST gap.
    #[tokio::test]
    async fn tail_without_a_cursor_returns_every_dialog_and_a_url_safe_cursor() {
        let state = make_state();
        populate_dialogs(&state); // call-0/1/2@test, all at 2024-06-15T12:00:00Z
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/tail"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["returned"], 3);
        assert_eq!(parsed["dialogs"].as_array().expect("dialogs").len(), 3);
        let cursor = parsed["next_cursor"].as_str().expect("a cursor");
        assert!(
            !cursor.contains('+'),
            "the cursor rides back in a URL query, where `+` becomes a space: {cursor}"
        );
    }

    /// A cursor at the first row returns only what sorts strictly after it — the
    /// identity tie-break, since all three share an update instant.
    #[tokio::test]
    async fn tail_since_a_cursor_returns_only_later_rows() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        // `%7C` is the `|` separator, percent-encoded for the query.
        let resp = app
            .oneshot(test_request(
                "/v1/dialogs/tail?since=2024-06-15T12:00:00Z%7Ccall-0@test",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["returned"], 2, "call-1 and call-2, not call-0");
    }

    /// Re-polling with the response's own `next_cursor` returns nothing new: the
    /// client has seen everything up to that position. Proves the cursor round-
    /// trips through the query unencoded-corrupted.
    #[tokio::test]
    async fn tail_re_poll_with_its_cursor_sees_nothing_new() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let first = app
            .clone()
            .oneshot(test_request("/v1/dialogs/tail"))
            .await
            .expect("oneshot");
        let body = body_to_string(first.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        let cursor = parsed["next_cursor"].as_str().expect("a cursor");

        // Pass it back verbatim, percent-encoding only the `|` separator the
        // query grammar reserves — the client's job, and the Zulu timestamp
        // needs nothing more.
        let uri = format!("/v1/dialogs/tail?since={}", cursor.replace('|', "%7C"));
        let again = app.oneshot(test_request(&uri)).await.expect("oneshot");
        assert_eq!(again.status(), StatusCode::OK);
        let body = body_to_string(again.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(
            parsed["returned"], 0,
            "nothing updated after the last cursor"
        );
    }

    /// A `since` whose timestamp half is not RFC 3339 is a 400, not a silent
    /// reset to the beginning that would loop a poller forever.
    #[tokio::test]
    async fn tail_bad_cursor_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/tail?since=not-a-timestamp"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── lint (PAR3: lint_dialog) ──────────────────────────────────────

    /// `GET /v1/dialogs/{id}/lint` returns the dialog's RFC-conformance
    /// findings. Closes the lint_dialog REST gap.
    #[tokio::test]
    async fn lint_returns_conformance_findings() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/call-0%40test/lint"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["call_id"], "call-0@test");
        let findings = parsed["findings"].as_array().expect("findings array");
        assert_eq!(
            parsed["finding_count"].as_u64().expect("count") as usize,
            findings.len(),
            "finding_count must match the findings it counts"
        );
        // The bare INVITE (no Via, no Max-Forwards) trips conformance rules, and
        // each finding carries its rule, severity and RFC section.
        assert!(
            !findings.is_empty(),
            "a bare INVITE trips conformance rules"
        );
        let f = &findings[0];
        assert!(f["rule_id"].is_string());
        assert!(f["severity"].is_string());
        assert!(f["rfc"].is_number());
        assert!(f["section"].is_string());
    }

    /// An unknown Call-ID is a 404, matching the sibling dialog routes.
    #[tokio::test]
    async fn lint_unknown_call_id_is_404() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs/nope%40nowhere/lint"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── vcon validate (PAR3: validate_vcon) ───────────────────────────

    /// `POST /v1/vcon/validate` checks a container against the vendored schema.
    /// An empty object is not a valid vCon, so the verdict is `invalid` with
    /// errors naming the missing required fields. Closes the validate_vcon gap.
    ///
    /// Gated with the route it drives: `post_vcon_validate` exists only when the
    /// `vcon` feature is compiled in, so without it the route is a 404 and this
    /// test would fail in the no-vcon feature combos CI runs.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn vcon_validate_reports_an_invalid_container() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_post("/v1/vcon/validate", "{}"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["verdict"], "invalid");
        assert!(
            !parsed["errors"].as_array().expect("errors").is_empty(),
            "an empty object trips the schema's required fields"
        );
    }

    /// A body that is not a JSON object is a 400, not a verdict: a vCon
    /// container is an object, and a string or array holding one is a caller
    /// mistake worth naming rather than validating.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn vcon_validate_non_object_is_400() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_post("/v1/vcon/validate", "[1, 2, 3]"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A body that is not JSON at all is a 400.
    #[cfg(feature = "vcon")]
    #[tokio::test]
    async fn vcon_validate_malformed_body_is_400() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_post("/v1/vcon/validate", "not json at all"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    fn make_state() -> ApiState {
        ApiState {
            relay_query: Default::default(),
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig::default(),
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100, 1024))),
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            capture_interfaces: Vec::new(),
            capture_meter: None,
            started_at: std::time::Instant::now(),
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
            tfps: Default::default(),
        }
    }

    // ── ST5: relay-statistics REST classification (no network) ───────────────

    fn empty_streams() -> Arc<RwLock<StreamStore>> {
        Arc::new(RwLock::new(StreamStore::new(64)))
    }

    /// A relay stand-in that names no vendor and refuses everything -- enough to
    /// stand in the `relay` slot for the invocation refusals, which return
    /// before any method is called.
    struct StubRelay;
    impl crate::relay::reconcile::ReadOnlyRelay for StubRelay {
        fn list(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
            _l: u32,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("stub")
        }
        fn query(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
            _c: &str,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("stub")
        }
        fn statistics(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<crate::relay::types::ControlReply> {
            anyhow::bail!("stub")
        }
        fn describe(&self) -> String {
            "a relay".to_string()
        }
    }

    /// No relay configured (`addr: None`) is `not_configured`, whose problem is
    /// the invocation -- on every one of the four routes.
    #[test]
    fn relay_rest_no_relay_is_not_configured() {
        let rq = RelayRestConfig::default();
        let ss = empty_streams();
        for ask in [
            RelayAsk::Wide,
            RelayAsk::Names,
            RelayAsk::Call("c".into()),
            RelayAsk::Compare("c".into()),
        ] {
            let v = relay_rest_answer(&rq, &ask, &ss);
            assert_eq!(
                v["outcome"], "not_configured",
                "route must classify, not transmit"
            );
            assert_eq!(v["responsibility"], "invocation");
            assert!(
                v.get("statistics").is_none(),
                "a refusal carries no counters"
            );
        }
    }

    /// A relay configured but no permit (a file-backed run, or the flag off) is
    /// `not_permitted` -- never quietly degraded to `unreachable`, and never a
    /// transmit. `permit: None` is the only field that differs from a run that
    /// would transmit.
    #[test]
    fn relay_rest_no_permit_is_not_permitted() {
        let rq = RelayRestConfig {
            relay: Some(Arc::new(StubRelay)),
            permit: None,
        };
        let v = relay_rest_answer(&rq, &RelayAsk::Wide, &empty_streams());
        assert_eq!(v["outcome"], "not_permitted");
        assert_ne!(v["outcome"], "unreachable", "the two must not collapse");
        assert_eq!(v["responsibility"], "invocation");
    }

    /// A relay reply carrying `result: error` is a refusal, and its
    /// `error-reason` travels verbatim; a clean reply is not a refusal.
    #[test]
    fn relay_reply_refusal_reads_the_relays_own_no() {
        let refused = [
            ("result".to_string(), "error".to_string()),
            ("error-reason".to_string(), "Unknown call-id".to_string()),
        ];
        assert_eq!(
            crate::stats_vocab::relay_reply_refusal(&refused).as_deref(),
            Some("Unknown call-id"),
            "the relay's own reason is carried, not invented"
        );
        let clean = [
            ("result".to_string(), "ok".to_string()),
            ("totals.RTP.packets".to_string(), "9000".to_string()),
        ];
        assert!(
            crate::stats_vocab::relay_reply_refusal(&clean).is_none(),
            "a clean reply is not a refusal"
        );
    }

    // ── ST5: relay-statistics REST failure paths and edge cases (ST-S4) ───────
    //
    // These drive `relay_rest_answer` with a scripted relay behind a REAL
    // transmit permit, so every reachable ST-S4 condition is exercised through
    // the actual routing rather than only the pure conversion. No live relay is
    // needed: the seam is `ReadOnlyRelay`, so a double answers from a script.
    //
    // What is deliberately NOT driven here, by the shipped architecture
    // (ST9, `docs/design/relay-statistics-failures.md`): sipnab has ONE
    // transmitting control client and it speaks rtpengine; it never SENDS to
    // rtpproxy, which it reads off the wire. So the rtpproxy-only rows -- the
    // bulk `G` partial that returns `E68` for the whole set (condition 5), the
    // six numeric rtpproxy `E`-codes (condition 4), the per-name `G` refusal
    // (condition 8) and the `;1` tag-rewrite `E50` (condition 10) -- have no
    // wire to reach here. Their classification vocabulary is single-sourced in
    // `stats_vocab` and driven in `tests/statistics_vocabulary_test.rs`; the
    // partial RENDERING a probed path would need is pinned in
    // `tests/relay_rest_envelope_test.rs`. Here we cover what the rtpengine
    // transmit path can actually produce.

    use crate::relay::types::{ControlReply, Enumeration, UntrustedReply};

    /// What a scripted relay answers one ask with.
    #[derive(Clone)]
    enum Scripted {
        /// A clean `statistics` reply carrying these name/value pairs.
        Stats(Vec<(&'static str, &'static str)>),
        /// A well-formed reply that is NOT statistics (a `list` answer), so a
        /// route sees a shape it did not ask for -- ST-S4 `suspect`.
        WrongShape,
        /// The fetch failed and nothing came back -- ST-S4 `unreachable`.
        Timeout,
        /// A reply arrived that cannot be trusted (a cookie mismatch) -- ST-S4
        /// `suspect`, never `unreachable`.
        Untrusted,
    }

    impl Scripted {
        fn produce(&self) -> anyhow::Result<ControlReply> {
            match self {
                Self::Stats(pairs) => Ok(ControlReply::Statistics(
                    pairs
                        .iter()
                        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                        .collect(),
                )),
                Self::WrongShape => Ok(ControlReply::Calls(Enumeration {
                    call_ids: Vec::new(),
                    truncated: false,
                })),
                Self::Timeout => anyhow::bail!("no route to host"),
                Self::Untrusted => Err(anyhow::Error::new(UntrustedReply {
                    reason: "reply cookie did not match the request".to_owned(),
                })),
            }
        }
    }

    /// A relay double answering the wide/names ask and the per-call ask from two
    /// independent scripts, so a route's exact fetch can be shaped.
    struct ScriptedRelay {
        wide: Scripted,
        per_call: Scripted,
    }

    impl crate::relay::reconcile::ReadOnlyRelay for ScriptedRelay {
        fn list(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
            _l: u32,
        ) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double lists no calls")
        }
        fn query(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
            _c: &str,
        ) -> anyhow::Result<ControlReply> {
            anyhow::bail!("this double queries no calls")
        }
        fn statistics(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
        ) -> anyhow::Result<ControlReply> {
            self.wide.produce()
        }
        fn call_statistics(
            &self,
            _p: &crate::security::transmit_guard::TransmitPermit,
            _call_id: &str,
        ) -> anyhow::Result<ControlReply> {
            self.per_call.produce()
        }
        fn describe(&self) -> String {
            "relay-under-test".to_owned()
        }
    }

    /// A permit only a live source grants -- the property that keeps a
    /// file-backed run from ever transmitting to an address it read out of a
    /// capture.
    fn live_permit() -> crate::security::transmit_guard::TransmitPermit {
        crate::security::transmit_guard::TransmitPermit::for_source(
            &crate::capture::CaptureSource::Live {
                device: "eth0".to_owned(),
            },
        )
        .expect("a live source grants a permit")
    }

    /// A relay config that WILL transmit: a scripted relay behind a live permit.
    fn transmitting(wide: Scripted, per_call: Scripted) -> RelayRestConfig {
        RelayRestConfig {
            relay: Some(Arc::new(ScriptedRelay { wide, per_call })),
            permit: Some(live_permit()),
        }
    }

    /// A stream store holding `n` measured RTP packets linked to `call_id`, so
    /// `measured_packet_count_for(call_id)` is `n`: the `sipnab_measured` side
    /// of a C4 comparison. Built by driving the real correlation path (record
    /// packets, link the endpoint) rather than hand-setting a field, so it is
    /// the count a live run would measure.
    fn streams_with_call(call_id: &str, n: u16) -> Arc<RwLock<StreamStore>> {
        use crate::capture::parse::{InputOrigin, ParsedPacket, TransportProto};
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));
        let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        let (src_port, dst_port, ssrc) = (20000u16, 40000u16, 0x1234u32);
        let mut ss = StreamStore::new(64);
        for i in 0..n {
            let seq = 100 + i;
            let mut payload = Vec::with_capacity(172);
            payload.push(0x80);
            payload.push(0x00); // PT 0, PCMU
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            payload.extend_from_slice(&ssrc.to_be_bytes());
            payload.extend_from_slice(&[0x7F; 160]);
            let parsed = ParsedPacket {
                frame_bytes: None,
                frame: None,
                timestamp: chrono::Utc::now(),
                src_addr: src,
                dst_addr: dst,
                src_port,
                dst_port,
                transport: TransportProto::Udp,
                payload: payload.into(),
                ip_id: None,
                tcp_seq: None,
                tcp_flags: None,
                fragment_offset: None,
                more_fragments: false,
                ip_protocol: 17,
                dscp: None,
                input_origin: InputOrigin::Wire,
                hep: None,
            };
            let hdr = crate::rtp::parser::parse_rtp_header(&parsed.payload)
                .expect("synthetic RTP header parses");
            ss.process_rtp(&parsed, &hdr, chrono::Utc::now());
        }
        ss.link_endpoint(src, src_port, call_id, &[]);
        assert_eq!(
            ss.measured_packet_count_for(call_id),
            u64::from(n),
            "the fixture must actually link {n} packets, or the compare test is \
             asserting against a side it did not build"
        );
        Arc::new(RwLock::new(ss))
    }

    /// Condition 3: a relay that does not answer is `unreachable` on every route
    /// that asks it -- the network's or the relay's problem -- and the message
    /// says the weaker true thing, never "the relay is down": over UDP a wrong
    /// port, a filtered port and a lost reply are indistinguishable.
    #[test]
    fn relay_rest_no_answer_is_unreachable_told_the_weaker_way() {
        let ss = empty_streams();
        for ask in [RelayAsk::Wide, RelayAsk::Names, RelayAsk::Call("c".into())] {
            let rq = transmitting(Scripted::Timeout, Scripted::Timeout);
            let v = relay_rest_answer(&rq, &ask, &ss);
            assert_eq!(v["outcome"], "unreachable", "asked, nothing came back");
            assert_eq!(v["responsibility"], "relay_or_network");
            let detail = v["detail"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            assert!(
                !detail.contains("is down") && !detail.contains("relay is down"),
                "must not claim the relay is down; nothing observed proves it: {detail}"
            );
            assert!(
                v.get("statistics").is_none(),
                "an unreachable relay yields no counters"
            );
        }
    }

    /// Condition 3 on the compare route too: no answer is `unreachable`, not a
    /// comparison against an absent relay side.
    #[test]
    fn relay_rest_compare_no_answer_is_unreachable() {
        let rq = transmitting(Scripted::Timeout, Scripted::Timeout);
        let v = relay_rest_answer(&rq, &RelayAsk::Compare("c".into()), &empty_streams());
        assert_eq!(v["outcome"], "unreachable");
        assert_eq!(v["responsibility"], "relay_or_network");
    }

    /// Condition 7: a reply that arrived but cannot be trusted (a mismatched
    /// cookie) is `suspect` -- the answer's own problem -- and never smoothed
    /// into `unreachable`. The two send an operator to different places.
    #[test]
    fn relay_rest_untrusted_reply_is_suspect_not_unreachable() {
        for ask in [RelayAsk::Wide, RelayAsk::Call("c".into())] {
            let rq = transmitting(Scripted::Untrusted, Scripted::Untrusted);
            let v = relay_rest_answer(&rq, &ask, &empty_streams());
            assert_eq!(v["outcome"], "suspect", "a reply that cannot be trusted");
            assert_ne!(v["outcome"], "unreachable", "the two must not collapse");
            assert_eq!(v["responsibility"], "answer");
            let detail = v["detail"].as_str().unwrap_or_default();
            assert!(
                detail.contains("discarded") || detail.contains("not read"),
                "a suspect reply says it was discarded, not interpreted: {detail}"
            );
        }
    }

    /// A well-formed reply of the WRONG kind (a `list` where statistics were
    /// asked) is `suspect`, never rendered as if it were counters.
    #[test]
    fn relay_rest_wrong_reply_shape_is_suspect() {
        for ask in [RelayAsk::Wide, RelayAsk::Names, RelayAsk::Call("c".into())] {
            let rq = transmitting(Scripted::WrongShape, Scripted::WrongShape);
            let v = relay_rest_answer(&rq, &ask, &empty_streams());
            assert_eq!(
                v["outcome"], "suspect",
                "a reply that is not statistics is suspect, not ok"
            );
            assert!(v.get("statistics").is_none());
        }
    }

    /// Condition 4: a per-call reply of `result: error` is a REFUSAL carrying
    /// the relay's own words verbatim -- the request's problem -- never rendered
    /// as counter rows. Each of the four rtpengine reasons travels unchanged.
    #[test]
    fn relay_rest_per_call_refusal_carries_the_relays_own_words() {
        // Three of the four documented reasons. The fourth ("could not decode
        // the ... dictionary") is left out here on purpose: its real wording
        // names the relay's wire format, and `relay_seam_test` forbids a vendor
        // token anywhere in `src/output/` code. The verbatim-travel property it
        // would test is already proven by these three and by the envelope test,
        // so the seam is worth more than a fourth near-identical case.
        for reason in [
            "Unrecognized command",
            "No call-id in message",
            "Unknown call-id",
        ] {
            let per_call = Scripted::Stats(vec![("result", "error"), ("error-reason", reason)]);
            let rq = transmitting(Scripted::Timeout, per_call);
            let v = relay_rest_answer(&rq, &RelayAsk::Call("1-7@h".into()), &empty_streams());
            assert_eq!(v["outcome"], "refused", "the relay reached, and said no");
            assert_eq!(v["responsibility"], "request");
            let detail = v["detail"].as_str().unwrap_or_default();
            assert!(
                detail.contains(reason),
                "the relay's own reason must travel verbatim: {reason:?} not in {detail:?}"
            );
        }
    }

    /// Condition 4's core: "the vocabulary" and "their call" are never the same
    /// message. `Unrecognized command` (the request is malformed) and
    /// `Unknown call-id` (this call is not held) reach the caller as DIFFERENT
    /// details, the rtpengine analogue of rtpproxy's `E68`/`E50` split.
    #[test]
    fn relay_rest_two_refusal_reasons_do_not_share_a_message() {
        let vocab = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![
                ("result", "error"),
                ("error-reason", "Unrecognized command"),
            ]),
        );
        let call = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![
                ("result", "error"),
                ("error-reason", "Unknown call-id"),
            ]),
        );
        let vocab_detail = relay_rest_answer(&vocab, &RelayAsk::Call("c".into()), &empty_streams())
            ["detail"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let call_detail =
            relay_rest_answer(&call, &RelayAsk::Call("c".into()), &empty_streams())["detail"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
        assert_ne!(
            vocab_detail, call_detail,
            "a misspelled command and a missing call must not read as one refusal"
        );
    }

    /// The compare route reads a `result: error` reply through the SAME refusal
    /// rule as the per-call route, so the two surfaces cannot classify one reply
    /// as a refusal and the other as counters.
    #[test]
    fn relay_rest_compare_refusal_uses_the_one_rule() {
        let per_call = Scripted::Stats(vec![
            ("result", "error"),
            ("error-reason", "Unknown call-id"),
        ]);
        let rq = transmitting(Scripted::Timeout, per_call);
        let v = relay_rest_answer(&rq, &RelayAsk::Compare("c".into()), &empty_streams());
        assert_eq!(v["outcome"], "refused");
        assert!(
            v["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("Unknown call-id"),
            "the compare route carries the relay's own reason too: {v}"
        );
    }

    /// A clean wide answer is `ok`, tiered `relay_reported`, and every value
    /// survives EXACTLY as the relay sent it: an integer counter stays its
    /// digits and rtpengine's string `uptime` stays a string, never coerced.
    #[test]
    fn relay_rest_wide_ok_carries_values_uncoerced() {
        let rq = transmitting(
            Scripted::Stats(vec![("npkts_relayed", "9000"), ("uptime", "134")]),
            Scripted::Timeout,
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Wide, &empty_streams());
        assert_eq!(v["outcome"], "ok");
        assert_eq!(v["origin"], "asked");
        let stats = v["statistics"].as_array().expect("statistics array");
        let find = |name: &str| {
            stats
                .iter()
                .find(|s| s["name"] == name)
                .unwrap_or_else(|| panic!("{name} present: {v}"))
        };
        assert_eq!(find("npkts_relayed")["value"], "9000");
        assert_eq!(find("npkts_relayed")["tier"], "relay_reported");
        assert_eq!(
            find("uptime")["value"],
            "134",
            "a value the relay sent as a string stays a string"
        );
    }

    /// Conditions 6 and 9: after a relay restart every counter reads `0`, and a
    /// single REST ask reports that honestly -- a counted zero is a VALUE
    /// (present, `\"0\"`), not an absent key and not a refusal, and never
    /// `unreachable`. REST does not poll (C5 omitted), so the backwards-STEP
    /// detection that would flag a restart as suspect lives in the polled path,
    /// not here; a lone post-restart sample is a legitimate zero.
    #[test]
    fn relay_rest_a_post_restart_zero_is_a_value_not_absent() {
        let rq = transmitting(
            Scripted::Stats(vec![("nsess_created", "0"), ("npkts_rcvd", "0")]),
            Scripted::Timeout,
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Wide, &empty_streams());
        assert_eq!(v["outcome"], "ok", "a relay that restarted still answered");
        let stats = v["statistics"].as_array().expect("statistics array");
        let zero = stats
            .iter()
            .find(|s| s["name"] == "npkts_rcvd")
            .expect("the zero counter occupies a key");
        assert_eq!(zero["value"], "0", "a counted zero is carried, not omitted");
    }

    /// C3: the names route reports exactly the keys the relay listed, sorted,
    /// with `source: listed` -- the answer comes from asking, never a table
    /// compiled into sipnab.
    #[test]
    fn relay_rest_names_are_the_relays_listed_keys() {
        let rq = transmitting(
            Scripted::Stats(vec![
                ("uptime", "5"),
                ("npkts_relayed", "1"),
                ("nsess", "2"),
            ]),
            Scripted::Timeout,
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Names, &empty_streams());
        assert_eq!(v["outcome"], "ok");
        assert_eq!(v["source"], "listed", "the relay enumerated its own set");
        let names: Vec<&str> = v["names"]
            .as_array()
            .expect("names array")
            .iter()
            .map(|n| n.as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            names,
            vec!["npkts_relayed", "nsess", "uptime"],
            "the names are the keys the relay reported, sorted: {v}"
        );
    }

    /// Condition 8: a key present in one relay version and absent in the next.
    /// The names route reflects each version's own reply, so `rtpa_nlost`
    /// appears for the build that lists it and is absent for the build that does
    /// not -- the surface offers no fixed menu, and a caller can discover the
    /// difference before a request fails on the missing name.
    #[test]
    fn relay_rest_names_track_the_relay_version() {
        let has = transmitting(
            Scripted::Stats(vec![("rtpa_nlost", "3"), ("npkts_relayed", "9")]),
            Scripted::Timeout,
        );
        let lacks = transmitting(
            Scripted::Stats(vec![("npkts_relayed", "9")]),
            Scripted::Timeout,
        );
        let names = |rq: &RelayRestConfig| -> Vec<String> {
            relay_rest_answer(rq, &RelayAsk::Names, &empty_streams())["names"]
                .as_array()
                .expect("names array")
                .iter()
                .map(|n| n.as_str().unwrap_or_default().to_owned())
                .collect()
        };
        assert!(
            names(&has).iter().any(|n| n == "rtpa_nlost"),
            "the version that lists rtpa_nlost offers it"
        );
        assert!(
            !names(&lacks).iter().any(|n| n == "rtpa_nlost"),
            "the version that does not list it does not invent it"
        );
    }

    /// C2 success: a clean per-call reply is `ok`, the relay's counters tiered
    /// `relay_reported`, and the label names the call so a two-relay estate
    /// keeps the answer attributed.
    #[test]
    fn relay_rest_call_ok_carries_per_call_counters() {
        let rq = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![("totals.RTP.packets", "8994"), ("result", "ok")]),
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Call("1-7@h".into()), &empty_streams());
        assert_eq!(v["outcome"], "ok");
        let stats = v["statistics"].as_array().expect("statistics array");
        assert!(
            stats
                .iter()
                .any(|s| s["name"] == "totals.RTP.packets" && s["value"] == "8994"),
            "the per-call counter is carried: {v}"
        );
        assert!(
            v["relay"].as_str().unwrap_or_default().contains("1-7@h"),
            "the label names the call: {v}"
        );
    }

    /// Condition 11: a per-call total too large for `u64` is `suspect`, carrying
    /// its digits as received -- never truncated into a narrower type, and never
    /// coerced to an absent side that would read as "the relay does not hold the
    /// call". The wire case (a real counter wrapping) is unreachable -- no relay
    /// in reach has run long enough -- so the OVERSIZED VALUE is manufactured and
    /// the conversion it forces is what is driven.
    #[test]
    fn relay_rest_compare_overflow_is_suspect_carrying_its_digits() {
        let huge = "99999999999999999999999999"; // 26 nines, past u64::MAX
        let rq = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![("totals.RTP.packets", huge)]),
        );
        let v = relay_rest_answer(
            &rq,
            &RelayAsk::Compare("c".into()),
            &streams_with_call("c", 5),
        );
        assert_eq!(
            v["outcome"], "suspect",
            "a value that will not fit is suspect"
        );
        assert_eq!(v["responsibility"], "answer");
        assert!(
            v["detail"].as_str().unwrap_or_default().contains(huge),
            "the digits are carried as received, not truncated: {v}"
        );
    }

    /// Condition 12: C4 on a call this capture measured no RTP for is
    /// `not_configured` naming the CAPTURE, not the relay -- so an operator is
    /// not sent to debug a relay that is working. The relay holds the call
    /// (a real count), sipnab simply did not see its media.
    #[test]
    fn relay_rest_compare_with_no_capture_side_names_the_capture() {
        let rq = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![("totals.RTP.packets", "9000")]),
        );
        // Empty store: sipnab measured nothing for this call.
        let v = relay_rest_answer(&rq, &RelayAsk::Compare("c".into()), &empty_streams());
        assert_eq!(v["outcome"], "not_configured");
        assert_eq!(v["responsibility"], "invocation");
        let detail = v["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("capture"),
            "the message points at the capture, not the relay: {detail}"
        );
    }

    /// C4 when the relay does not hold the call either: the relay side is absent
    /// (not a measured zero) and this capture has none, so there is nothing to
    /// compare -- `refused`, never a zero-versus-zero match invented from two
    /// absences.
    #[test]
    fn relay_rest_compare_with_neither_side_is_refused() {
        let rq = transmitting(
            Scripted::Timeout,
            // A clean reply that simply lacks totals.RTP.packets: the relay does
            // not hold this call, but did not error.
            Scripted::Stats(vec![("result", "ok")]),
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Compare("c".into()), &empty_streams());
        assert_eq!(v["outcome"], "refused");
        assert!(
            v["detail"].as_str().unwrap_or_default().contains("neither"),
            "neither side had RTP for the call: {v}"
        );
    }

    /// C4 when sipnab measured the call but the relay's reply lacks the key: the
    /// relay side is absent, sipnab's is a real count, so the relay does not hold
    /// the call -- `refused`. sipnab's figure is not rendered against an invented
    /// relay zero.
    #[test]
    fn relay_rest_compare_relay_absent_capture_present_is_refused() {
        let rq = transmitting(Scripted::Timeout, Scripted::Stats(vec![("result", "ok")]));
        let v = relay_rest_answer(
            &rq,
            &RelayAsk::Compare("c".into()),
            &streams_with_call("c", 8),
        );
        assert_eq!(v["outcome"], "refused");
        assert!(
            v["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("does not hold"),
            "the relay does not hold the call sipnab measured: {v}"
        );
    }

    /// C4 with both sides: `ok`, both figures shown, both tiers named, a word
    /// verdict, and a note that is never optional -- and never a summed or
    /// differenced field, which the cross-tier arithmetic rule forbids. Equal
    /// counts read `match`.
    #[test]
    fn relay_rest_compare_both_sides_present_is_ok_and_names_both_tiers() {
        let rq = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![("totals.RTP.packets", "10")]),
        );
        let v = relay_rest_answer(
            &rq,
            &RelayAsk::Compare("c".into()),
            &streams_with_call("c", 10),
        );
        assert_eq!(v["outcome"], "ok");
        let packets = &v["packets"];
        assert_eq!(packets["relay_reported"]["value"], 10);
        assert_eq!(packets["sipnab_measured"]["value"], 10);
        assert_eq!(packets["verdict"], "match", "equal counts match");
        assert!(
            packets["note"].as_str().is_some_and(|n| !n.is_empty()),
            "the note is not optional decoration: {v}"
        );
        assert!(
            packets.get("difference").is_none() && packets.get("total").is_none(),
            "a comparison never carries a summed or differenced field: {v}"
        );
    }

    /// C4 when the two sides disagree: `differ`, and BOTH figures survive so an
    /// operator reads the gap rather than a single reconciled number. The note
    /// stays, because a bare "differ" sends an operator to the relay first.
    #[test]
    fn relay_rest_compare_differing_sides_keep_both_figures() {
        let rq = transmitting(
            Scripted::Timeout,
            Scripted::Stats(vec![("totals.RTP.packets", "12")]),
        );
        let v = relay_rest_answer(
            &rq,
            &RelayAsk::Compare("c".into()),
            &streams_with_call("c", 10),
        );
        assert_eq!(v["outcome"], "ok");
        assert_eq!(v["packets"]["verdict"], "differ");
        assert_eq!(v["packets"]["relay_reported"]["value"], 12);
        assert_eq!(v["packets"]["sipnab_measured"]["value"], 10);
        assert!(
            v["packets"]["note"].as_str().is_some_and(|n| !n.is_empty()),
            "a differ verdict must carry its note: {v}"
        );
    }

    /// Condition 12's other half: C1/C2/C3 do NOT need a capture -- the relay is
    /// asked directly. A wide ask answers `ok` against an empty stream store,
    /// so an operator querying a relay on a run with no capture is not refused.
    #[test]
    fn relay_rest_global_stats_answer_without_a_capture() {
        let rq = transmitting(
            Scripted::Stats(vec![("npkts_relayed", "1")]),
            Scripted::Timeout,
        );
        let v = relay_rest_answer(&rq, &RelayAsk::Wide, &empty_streams());
        assert_eq!(
            v["outcome"], "ok",
            "global relay stats need no capture; the relay answers directly"
        );
    }

    /// Build an `ApiState` whose verifier accepts only the given static key.
    fn make_state_with_key(key: &str) -> ApiState {
        ApiState {
            relay_query: Default::default(),
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    static_keys: vec![key.to_string()],
                    ..Default::default()
                },
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100, 1024))),
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            capture_interfaces: Vec::new(),
            capture_meter: None,
            started_at: std::time::Instant::now(),
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
            tfps: Default::default(),
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

    // ── capabilities (PAR3: server_capabilities on REST) ──────────────

    /// `GET /v1/capabilities` reports the build's compiled feature set, so a
    /// program can discover what this sipnab can do before it asks and reads a
    /// mid-integration refusal as a dead end.
    #[tokio::test]
    async fn capabilities_reports_the_compiled_feature_set() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/capabilities"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["version"], env!("CARGO_PKG_VERSION"));
        let features: Vec<String> = parsed["features"]
            .as_array()
            .expect("features array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        // The `api` feature is on in the build that serves this route.
        assert!(features.contains(&"api".to_string()));
    }

    /// The feature list REST reports IS the one canonical `compiled_features()`
    /// the CLI `--version` and the MCP `server_capabilities` also derive from,
    /// so no two surfaces can claim different builds of the same binary.
    #[tokio::test]
    async fn capabilities_features_are_the_canonical_list() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/capabilities"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        let mut got: Vec<String> = parsed["features"]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v.as_str().expect("string").to_string())
            .collect();
        got.sort();
        let mut want: Vec<String> = crate::cli::compiled_features()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        want.sort();
        assert_eq!(got, want);
    }

    /// The response carries the REST opt-ins the operator set, so a client can
    /// tell a capability this build lacks from one this run did not turn on. A
    /// state built without `--api-allow-relay-query` reports it off.
    #[tokio::test]
    async fn capabilities_reports_the_relay_opt_in() {
        let state = make_state();
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/capabilities"))
            .await
            .expect("oneshot");
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["runtime"]["api_allow_relay_query"], false);
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
        // `>= before`, not `== before`: the tally is process-global and only
        // grows (no test resets it), so a concurrent note between reading
        // `before` and the handler reading it again can only raise it. An
        // `==` here raced exactly that and turned a sibling test's CI run red.
        // The second half below proves the key is WIRED, not a literal zero.
        let at_rest = parsed["caveats"]["media_creating_commands"]
            .as_u64()
            .expect("declined work is a number on every response");
        assert!(
            at_rest >= before,
            "the count must be present on an ordinary response and cannot have \
             dropped below {before}: {}",
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
            relay_query: Default::default(),
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    signing_keys: vec![key.to_vec()],
                    audience: crate::auth::AUDIENCE_API.to_string(),
                    ..Default::default()
                },
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(100, 1024))),
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            capture_interfaces: Vec::new(),
            capture_meter: None,
            started_at: std::time::Instant::now(),
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
            tfps: Default::default(),
        }
    }

    /// A signed token with a future expiry authenticates and gets 200.
    #[tokio::test]
    async fn auth_valid_signed_token_returns_200() {
        let key = crate::test_material::key_bytes("rest-router-signing");
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
        let key = crate::test_material::key_bytes("rest-router-signing");
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
        let key = crate::test_material::key_bytes("rest-router-signing");
        let state = make_state_with_signing_key(key);
        let app = build_router(state);
        // Signed by a different key.
        let token = crate::auth::mint(
            crate::test_material::key_bytes("rest-router-other"),
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
        let mut limiter = RateLimiter::new(0, 1024);
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

    /// `limit=0` means the default page, the same as it does on MCP.
    ///
    /// One product answered a `limit=0` three ways: `mcp::shape::resolve_limit`
    /// read it as the default, `GET /v1/tfps/labels` in this file read it as
    /// the default, and the dialog and stream list routes returned an EMPTY
    /// page. A caller who interpolates an unset variable into a URL got a
    /// successful response with no rows, which reads as "there is nothing
    /// here" rather than as a mistake.
    #[test]
    fn a_zero_limit_is_the_default_page_not_an_empty_one() {
        assert_eq!(
            resolve_page_limit(Some(0), 1000),
            DEFAULT_PAGE_ROWS,
            "zero is the default page, as on the MCP door"
        );
        assert_eq!(
            resolve_page_limit(None, 1000),
            DEFAULT_PAGE_ROWS,
            "and so is an absent limit"
        );
    }

    /// The server's ceiling still wins over anything the caller asks for.
    #[test]
    fn the_row_cap_bounds_every_reading_of_limit() {
        assert_eq!(resolve_page_limit(Some(10_000), 25), 25, "an explicit ask");
        assert_eq!(
            resolve_page_limit(Some(0), 5),
            5,
            "and the default, on a server whose cap is below it"
        );
        assert_eq!(resolve_page_limit(Some(7), 25), 7, "an ask under the cap");
    }

    /// REST honors `max_tracked_peers`, like every other listener.
    ///
    /// It used to carry its own limiter, so `[limits] max_tracked_peers` was
    /// inert here: the knob an operator sets to bound the bucket map against a
    /// spoofed-source flood reached MCP and HEP and stopped at the REST door.
    /// `rate_limit.rs` exists because this rule was written twice before, and
    /// says so in its own module doc.
    #[test]
    fn the_rest_limiter_bounds_its_peer_map() {
        let mut limiter = RateLimiter::new(1_000_000, 2);
        let t0 = std::time::Instant::now();
        // Two peers fit. The third is refused rather than tracked, which is
        // the fail-closed half: letting an untracked newcomer through is
        // exactly the flood the cap exists to resist.
        for n in 0..2u8 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n));
            assert!(limiter.check_at(ip, t0), "peer {n} is inside the bound");
        }
        assert!(
            !limiter.check_at(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 9)), t0),
            "a peer past max_tracked_peers must be refused, not admitted \
             untracked"
        );
    }

    /// One window for every peer, as on the other listeners.
    ///
    /// The private limiter anchored a window per IP, so a peer's second
    /// started whenever its first request happened to land. The shared one
    /// resets a single window, which is what `--mcp-rate-limit-per-peer` and
    /// `--hep-rate-limit-per-peer` have always meant.
    #[test]
    fn the_rest_limiter_shares_one_window_with_the_other_listeners() {
        let mut limiter = RateLimiter::new(2, 64);
        let t0 = std::time::Instant::now();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert!(limiter.check_at(ip, t0));
        assert!(limiter.check_at(ip, t0));
        assert!(!limiter.check_at(ip, t0), "the third exceeds a cap of 2");

        let next = t0 + std::time::Duration::from_millis(1_100);
        assert!(
            limiter.check_at(ip, next),
            "the window resets and the peer is served again"
        );
    }

    /// A limiter with max 5 allows exactly 5 requests, then rejects the 6th.
    #[test]
    fn rate_limiter_allows_under_limit() {
        let mut limiter = RateLimiter::new(5, 1024);
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
            relay_query: Default::default(),
            dialog_store: Arc::new(RwLock::new(DialogStore::new(1000, false))),
            stream_store: Arc::new(RwLock::new(StreamStore::new(1000))),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig::default(),
            )),
            rate_limiter: Arc::new(Mutex::new(RateLimiter::new(1, 1024))),
            max_inline_media_bytes: None,
            max_rows: crate::cli::Cli::DEFAULT_API_MAX_ROWS as usize,
            // No capture context: these fixtures build a server around bare
            // stores, which is exactly the state `source: "unknown"` and a
            // null identity exist to describe. A fixture that invented one
            // would test a shape production never produces.
            capture: None,
            source_exhausted: None,
            capture_interfaces: Vec::new(),
            capture_meter: None,
            started_at: std::time::Instant::now(),
            // Fixtures build a run the command line never authorized, which
            // is the state a test has to opt OUT of rather than into: a
            // fixture defaulting to an open gate would let a route that
            // forgot to consult it pass.
            persistence_gate: Arc::new(crate::output::persistence::PersistenceGate::new(false)),
            tfps: Default::default(),
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
        state.rate_limiter = Arc::new(Mutex::new(RateLimiter::new(3, 1024)));

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

    // ── list_dialogs DSL filter (PAR3: find_problems, search_messages) ─

    /// A DSL `filter` narrows the page to matching dialogs, using the same
    /// expression language the CLI `--filter` and the TUI filter dialog compile.
    /// Closes the find_problems REST gap: a program can now poll by any DSL
    /// field or alias, not only `state` and a `from` regex.
    #[tokio::test]
    async fn list_dialogs_dsl_filter_narrows() {
        let state = make_state();
        populate_dialogs(&state); // from users user0/user1/user2
        let app = build_router(state);

        // filter=from.user == 'user1'
        let resp = app
            .oneshot(test_request(
                "/v1/dialogs?filter=from.user%20%3D%3D%20%27user1%27",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 1);
        assert_eq!(parsed["dialogs"][0]["from_user"], "user1");
        // total reflects the filtered set, so a client paging by it terminates.
        assert_eq!(parsed["total"], 1);
    }

    /// A DSL `payload` regex searches the full raw message text. Closes the
    /// search_messages REST gap: a substring in any header or body was
    /// unreachable over REST, which filtered only by state and a `from` regex.
    #[tokio::test]
    async fn list_dialogs_dsl_payload_search() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        // filter=payload =~ 'user2'  (the From header of dialog 2)
        let resp = app
            .oneshot(test_request(
                "/v1/dialogs?filter=payload%20%3D~%20%27user2%27",
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 1);
        assert_eq!(parsed["dialogs"][0]["from_user"], "user2");
    }

    /// An unparseable DSL `filter` is a 400 that says so, not a silent
    /// unfiltered 200. A structured query a client got wrong must fail loudly,
    /// so it learns the expression was rejected rather than acting on every row
    /// (the deliberate difference from the `from` regex, which is best-effort).
    #[tokio::test]
    async fn list_dialogs_dsl_invalid_filter_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        // filter=from.user ==   (no value: does not parse)
        let resp = app
            .oneshot(test_request("/v1/dialogs?filter=from.user%20%3D%3D"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── list_dialogs time window (PAR3: search_by_time) ───────────────

    /// `after` excludes dialogs that opened before it. The fixture's three
    /// dialogs open at 12:00, so an `after` of 13:00 admits none. Closes the
    /// search_by_time REST gap: a wall-clock window was unreachable over REST.
    #[tokio::test]
    async fn list_dialogs_after_excludes_earlier_dialogs() {
        let state = make_state();
        populate_dialogs(&state); // all open at 2024-06-15T12:00:00Z
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?after=2024-06-15T13:00:00Z"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 0);
        assert_eq!(parsed["total"], 0);
    }

    /// `after` admits dialogs that opened at or after it.
    #[tokio::test]
    async fn list_dialogs_after_admits_later_dialogs() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?after=2024-06-15T11:00:00Z"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 3);
    }

    /// `before` excludes dialogs that opened after it.
    #[tokio::test]
    async fn list_dialogs_before_excludes_later_dialogs() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?before=2024-06-15T11:00:00Z"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["dialogs"].as_array().expect("array").len(), 0);
    }

    /// A timestamp that is not RFC 3339 is a 400, not a silently ignored
    /// window, so a client learns its query was malformed rather than reading
    /// an unfiltered page as the answer to its question.
    #[tokio::test]
    async fn list_dialogs_invalid_timestamp_is_400() {
        let state = make_state();
        populate_dialogs(&state);
        let app = build_router(state);

        let resp = app
            .oneshot(test_request("/v1/dialogs?after=notatimestamp"))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
                None,
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
        let mut limiter = RateLimiter::new(1, 1024);
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
            relay_query: Default::default(),
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

    // ── The TFPS routes ──────────────────────────────────────────────

    /// A `tfps_ctl` that prints `text`, in its own directory.
    fn fake_tfps(text: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tfps_ctl");
        std::fs::write(
            &path,
            format!("#!/bin/sh\ncat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE\n"),
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        dir
    }

    /// The key every TFPS test authenticates with.
    const TFPS_KEY: &str = "tfps-route-test-key";
    /// Every outcome `ban` can answer with, one per line.
    const BAN: &str = include_str!("../../tests/fixtures/tfps-ban-golden.jsonl");

    /// State whose locator names the fake in `dir`.
    fn state_with_tfps(dir: &tempfile::TempDir) -> ApiState {
        ApiState {
            relay_query: Default::default(),
            tfps: crate::security::tfps::TfpsLocator::new(Some(dir.path().join("tfps_ctl")), None),
            ..make_state_with_key(TFPS_KEY)
        }
    }

    /// State on a machine with no TFPS: the search path is an empty dir.
    fn state_without_tfps(dir: &tempfile::TempDir) -> ApiState {
        ApiState {
            relay_query: Default::default(),
            tfps: crate::security::tfps::TfpsLocator::new(None, None)
                .with_search_path(dir.path().as_os_str()),
            ..make_state_with_key(TFPS_KEY)
        }
    }

    /// The ordinary case: no TFPS, and every route says so with `200`.
    #[tokio::test]
    async fn every_tfps_route_answers_installed_false_on_a_bare_machine() {
        let empty = tempfile::tempdir().expect("tempdir");
        for (method, uri, body) in [
            ("GET", "/v1/tfps/status", ""),
            ("GET", "/v1/tfps/banned", ""),
            ("GET", "/v1/tfps/dropped", ""),
            ("GET", "/v1/tfps/labels", ""),
            ("POST", "/v1/tfps/ban", r#"{"ip":"198.51.100.20"}"#),
            ("POST", "/v1/tfps/unban", r#"{"ip":"198.51.100.20"}"#),
        ] {
            let app = build_router(state_without_tfps(&empty));
            let req = if method == "GET" {
                test_get_with_key(uri, TFPS_KEY)
            } else {
                test_post_with_key(uri, body, TFPS_KEY)
            };
            let resp = app.oneshot(req).await.expect("oneshot");
            assert_eq!(resp.status(), StatusCode::OK, "{method} {uri}");
            let v = json_of(resp).await;
            assert_eq!(
                v,
                json!({
                    "installed": false,
                    "reason": crate::security::tfps::NOT_INSTALLED_REASON
                }),
                "{method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn the_tfps_routes_answer_the_contract_when_the_peer_is_there() {
        const STATUS: &str = include_str!("../../tests/fixtures/tfps-status-golden.json");
        const BANNED: &str = include_str!("../../tests/fixtures/tfps-banned-golden.jsonl");

        let dir = fake_tfps(STATUS);
        let resp = build_router(state_with_tfps(&dir))
            .oneshot(test_get_with_key("/v1/tfps/status", TFPS_KEY))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;
        assert_eq!(v["installed"], true);
        assert_eq!(v["status"]["blocked_now"], 3);
        assert_eq!(
            v["tfps_ctl"],
            dir.path().join("tfps_ctl").display().to_string()
        );

        let dir = fake_tfps(BANNED);
        let v = json_of(
            build_router(state_with_tfps(&dir))
                .oneshot(test_get_with_key("/v1/tfps/banned", TFPS_KEY))
                .await
                .expect("oneshot"),
        )
        .await;
        assert_eq!(v["total"], 3);
        assert_eq!(v["returned"], 3);
        assert_eq!(v["truncated"], false);
        assert_eq!(
            v["rows"][0]["detail"], "pplsip",
            "REST returns the sender's text verbatim; fencing is the MCP door's rule"
        );
        assert_eq!(
            v["rows"][2]["rule"],
            Value::Null,
            "null survives the round trip"
        );

        let dir = fake_tfps(BAN.lines().next().expect("a line"));
        let v = json_of(
            build_router(state_with_tfps(&dir))
                .oneshot(test_post_with_key(
                    "/v1/tfps/ban",
                    r#"{"ip":"198.51.100.20","ttl_secs":60}"#,
                    TFPS_KEY,
                ))
                .await
                .expect("oneshot"),
        )
        .await;
        assert_eq!(v["installed"], true);
        assert_eq!(v["action"]["applied"], true);
    }

    /// The row cap applies here as it does to every list route.
    #[tokio::test]
    async fn a_tfps_list_is_bounded_by_the_api_row_cap() {
        const LABELS: &str = include_str!("../../tests/fixtures/tfps-labels-golden.jsonl");
        let dir = fake_tfps(LABELS);
        let mut state = state_with_tfps(&dir);
        state.max_rows = 2;
        let v = json_of(
            build_router(state)
                .oneshot(test_get_with_key("/v1/tfps/labels?limit=0", TFPS_KEY))
                .await
                .expect("oneshot"),
        )
        .await;
        assert_eq!(v["total"], 5);
        assert_eq!(v["returned"], 2);
        assert_eq!(v["truncated"], true);
    }

    /// A refusal TFPS signals with exit 1 is `200` with `applied: false` and
    /// the reason: TFPS's answer, reported as given.
    #[tokio::test]
    async fn a_refused_ban_is_reported_not_raised() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tfps_ctl");
        let refused = BAN.lines().nth(2).expect("the self refusal");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncat <<'SIPNAB_FIXTURE'\n{refused}\nSIPNAB_FIXTURE\necho 'error: 1 of 1 refused' >&2\nexit 1\n"
            ),
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let resp = build_router(state_with_tfps(&dir))
            .oneshot(test_post_with_key(
                "/v1/tfps/ban",
                r#"{"ip":"192.0.2.1"}"#,
                TFPS_KEY,
            ))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;
        assert_eq!(v["action"]["applied"], false);
        assert_eq!(v["action"]["refused"], "self");
    }

    /// An address that is not one, or a body with a key the route does not
    /// know, is `400` -- and the peer is never asked.
    #[tokio::test]
    async fn a_ban_with_a_bad_address_or_an_unknown_key_is_refused() {
        let dir = fake_tfps(BAN.lines().next().expect("a line"));
        for body in [
            r#"{"ip":"not-an-address"}"#,
            r#"{"ip":"198.51.100.20","ttl":60}"#,
            r#"{"ip":"198.51.100.20","reason":"tfps has no reason option"}"#,
            r#"{}"#,
            r#"{"ip":"198.51.100.20; rm -rf /"}"#,
        ] {
            for route in ["/v1/tfps/ban", "/v1/tfps/unban"] {
                let resp = build_router(state_with_tfps(&dir))
                    .oneshot(test_post_with_key(route, body, TFPS_KEY))
                    .await
                    .expect("oneshot");
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{route} {body}");
            }
        }
    }

    /// The peer failing is `502`, as `application/problem+json`, with its
    /// standard error verbatim in `detail`.
    #[tokio::test]
    async fn a_failing_peer_is_a_502_problem_carrying_its_stderr() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tfps_ctl");
        std::fs::write(
            &path,
            "#!/bin/sh\necho 'tfps.db: database is locked' >&2\nexit 3\n",
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let resp = build_router(state_with_tfps(&dir))
            .oneshot(test_get_with_key("/v1/tfps/status", TFPS_KEY))
            .await
            .expect("oneshot");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        let v = json_of(resp).await;
        assert_eq!(v["type"], "https://sipnab.com/problems/bad-gateway");
        assert_eq!(v["status"], 502);
        assert!(
            v["detail"]
                .as_str()
                .is_some_and(|d| d.contains("tfps.db: database is locked")),
            "{v}"
        );
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
    /// A window past what the transport can hold is narrowed, not refused.
    ///
    /// The caller still gets a measurement, and `rates.window_seconds` reports
    /// the window that was applied, so the narrowing is visible rather than
    /// silent.
    #[test]
    fn a_rest_window_past_the_transport_budget_is_narrowed() {
        for requested in [crate::output::runtime::MAX_SAMPLE_SECONDS, 600, u32::MAX] {
            assert_eq!(
                rest_sample_seconds(requested),
                Ok(MAX_REST_SAMPLE_SECONDS),
                "{requested}s must come back as the window this route can \
                 actually wait out"
            );
        }
    }

    /// A window the route can wait out survives intact.
    #[test]
    fn a_rest_window_inside_the_budget_is_returned_unchanged() {
        for requested in [1u32, 2, MAX_REST_SAMPLE_SECONDS] {
            assert_eq!(rest_sample_seconds(requested), Ok(requested));
        }
    }

    /// Zero is refused here for the same reason it is refused over MCP.
    #[test]
    fn a_rest_window_of_zero_is_refused() {
        assert!(
            rest_sample_seconds(0).is_err(),
            "zero deltas is what a quiet capture reports; an empty window must \
             not be answered with one"
        );
    }
}
