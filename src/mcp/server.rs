// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SipnabMcp` server: the MCP tools backed by the existing
//! dialog/stream stores (plus the optional alert engine).
//!
//! # Tool descriptions and prompt-injection defense (D22)
//!
//! Tool descriptions never instruct the LLM to "trust", "verify", or
//! "act on" returned content. They state what the tool returns and stop.
//! A test enforces this — `tests/mcp_tool_descriptions_test.rs`. This line
//! previously named a shell lint that was never written, so the rule read
//! as enforced while nothing checked it; the test also asserts that any
//! gate named here exists.
//!
//! # Lock discipline (Gotcha 3)
//!
//! Every tool handler acquires its parking_lot guards, snapshots/clones
//! the data it needs into owned types, **drops the guard explicitly**,
//! and only then awaits or builds the response. The workspace-wide
//! `clippy::await_holding_lock = "deny"` (Cargo.toml [workspace.lints])
//! catches violations mechanically.

use std::sync::Arc;

use parking_lot::RwLock;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::output::{ReportFormat, generate_call_report};
use crate::rtp::diagnosis::{
    AsymmetryThresholds, CaptureMedia, MediaContext, diagnose_asymmetry, diagnose_media,
};
use crate::rtp::stream_store::StreamStore;
use crate::security::alerting::AlertEngine;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::{FilterExpr, expand_alias};

use super::shape::{HARD_LIMIT, resolve_limit_with_cap};

/// Holds the shared analysis state and the rmcp tool router.
#[derive(Clone)]
pub struct SipnabMcp {
    /// Shared dialog store the read-only tools query.
    pub dialog_store: Arc<RwLock<DialogStore>>,
    /// Shared RTP stream store the read-only tools query.
    pub stream_store: Arc<RwLock<StreamStore>>,
    /// Optional shared alert engine for `security_findings`. When None,
    /// the tool returns an empty list rather than erroring.
    pub alert_engine: Option<Arc<RwLock<AlertEngine>>>,
    /// Shared flag the capture owner sets once the source (typically a pcap
    /// file) is fully consumed; `tail_dialogs` reports it as
    /// `source_exhausted` so pollers know no more updates will come. When
    /// None (no capture owner attached), it reads as not exhausted.
    source_exhausted: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Ceiling on rows in one list-style response, from `--mcp-max-rows` or
    /// `[limits] mcp_max_rows`. Defaults to [`HARD_LIMIT`].
    ///
    /// Carried on the server rather than read from a constant at each call
    /// site, because a value that exists only in a signature is not a setting:
    /// six detectors in this tree accept a threshold no production caller ever
    /// supplies, and this must not become the seventh.
    row_cap: usize,
    /// Directory the file tools are confined to. `None` disables them.
    file_root: Option<std::path::PathBuf>,
    /// Capture files and directories this server is reading, which the file
    /// tools must never write over.
    ///
    /// `--mcp-file-root` and `-I` routinely name the same directory — one
    /// folder of captures is the obvious setup — so an export named after an
    /// input is one autocompletion away, and an agent picking a filename has no
    /// way to know which names are inputs.
    protected_inputs: crate::capture::output_guard::ProtectedInputs,
    /// Whether `shutdown_server` may stop this process.
    allow_shutdown: bool,
    /// Whether `open_capture` may replace the loaded capture.
    allow_open_capture: bool,
    /// Whether `save_findings` may record an agent's annotation.
    allow_save_findings: bool,
    /// Annotations written through `save_findings`.
    ///
    /// **Shared, not per-session**, for the same reason `state` below is:
    /// `SipnabMcp` is cloned per HTTP session, so a plain field would give every
    /// session a private log and make the counts each one reports meaningless —
    /// two agents on one server would each be told they held the only findings.
    ///
    /// Nothing reads this back. See [`crate::mcp::findings`] for why that is
    /// structural rather than a convention.
    findings: Arc<RwLock<crate::mcp::findings::FindingsLog>>,
    /// What this server is attached to, which capture that is, and whether a
    /// load is filling it.
    ///
    /// **Shared, not per-session.** `SipnabMcp` is cloned per HTTP session
    /// (`transport.rs`), so a plain field would leave `open_capture` naming the
    /// new file in nobody's session, including the calling one: every clone
    /// carries its own copy and the swap reaches none of them. Two agents on
    /// one server would read the same stores and disagree about which capture
    /// they were reading.
    capture: Arc<RwLock<CaptureState>>,
    /// Bounds tool calls in flight at once, or `None` for no cap.
    ///
    /// **Shared, not per-session**, for the same reason `capture` and
    /// `findings` are: `SipnabMcp` is cloned per HTTP session, so a plain
    /// per-clone semaphore would give every session its own budget and the
    /// server-wide cap the operator asked for would not exist — N sessions
    /// could run N times the permitted work. One `Arc<Semaphore>` shared by
    /// every clone is the only thing that bounds the whole server.
    ///
    /// A permit is taken with `try_acquire_owned` (never a blocking wait) at
    /// the one `call_tool` choke point and held for the whole call, so it
    /// bounds concurrent tool executions, not connections. Refusing rather
    /// than queueing is deliberate: a blocking acquire would let an unbounded
    /// backlog of callers pile up behind the cap, which is the resource
    /// exhaustion the cap exists to prevent, deferred rather than avoided.
    call_limiter: Option<Arc<tokio::sync::Semaphore>>,
    /// Bounds tool calls per second from any ONE peer, or `None` for no rate
    /// limit.
    ///
    /// The other half of `call_limiter`, and it is a different question. The
    /// semaphore bounds calls IN FLIGHT; this bounds their ARRIVAL RATE. An
    /// agent that never exceeds the concurrency cap and simply loops as fast
    /// as it is answered is unbounded under the semaphore alone — it holds one
    /// permit at a time and asks again the instant it is free.
    ///
    /// **Shared, not per-session**, for the same reason `call_limiter` is:
    /// `SipnabMcp` is cloned per HTTP session, so a per-clone limiter would
    /// give each session its own allowance and one peer could multiply its
    /// budget by opening sessions — which is precisely the loop this bounds.
    ///
    /// Keyed on what the transport can prove about the caller (see
    /// `PeerKey`), and refusing rather than delaying: a call held until its
    /// allowance returns is a call still occupying the server, which is the
    /// exhaustion the limit exists to prevent, only slower.
    rate_limiter: Option<Arc<parking_lot::Mutex<crate::rate_limit::FixedWindowLimiter<PeerKey>>>>,
    /// rmcp router mapping tool names to the handler methods below.
    tool_router: ToolRouter<Self>,
}

/// The identity a per-peer MCP rate limit counts against.
///
/// The peer's IP address where the transport can prove one, and `None` where
/// it cannot: the stdio pipe (one process, one peer, and its owner is the
/// operator who started the server) and an HTTP request that arrived with no
/// connection info both land there. Sharing one bucket between those two is
/// harmless because a run serves one transport, never both — and it fails
/// closed, which an "unattributable means unlimited" key would not.
///
/// The **address**, not address:port: a client that opens a fresh connection
/// per call gets a new ephemeral port every time, so keying on the socket
/// would hand a looping caller a fresh allowance on every loop.
type PeerKey = Option<std::net::IpAddr>;

/// Which capture this server holds, behind one lock so a swap is atomic.
///
/// Everything a swap changes lives here together on purpose. The identity and
/// the description have to move as one: an answer stamped with the old
/// instance and the new filename, or the reverse, is worse than either alone
/// because it looks self-consistent.
///
/// **Lock order: this lock, then the dialog store, then the stream store.**
/// `open_capture` clears both stores while holding this one, so a reader that
/// takes a store guard and then reaches for this lock deadlocks against it.
/// Every handler that stamps an answer with the identity holds all three
/// across the read for the same reason: releasing this lock first lets a swap
/// land between the id and the rows, and the answer then names a capture it
/// did not come from.
#[derive(Debug, Default)]
pub struct CaptureState {
    /// Identity of the capture currently loaded — see [`crate::provenance`].
    /// Rotated in the same critical section that clears the stores.
    pub identity: crate::provenance::CaptureIdentity,
    /// What this server is attached to, and when that capture began.
    ///
    /// An agent had no way to ask whether it was reading a live interface or
    /// replaying a file — so it could not tell whether "stop the capture"
    /// would lose anything, nor whether a quiet capture meant a quiet network
    /// or a finished file. Every downstream misjudgement traced back to that.
    pub context: Option<CaptureContext>,
    /// The background load filling this capture, while one is running.
    pub load: Option<Arc<super::load::CaptureLoad>>,
}

/// Where this server's packets come from, for `capture_status`.
#[derive(Debug, Clone)]
pub struct CaptureContext {
    /// `true` for a live interface, `false` for a file replay.
    pub live: bool,
    /// Interface name when live, file path when replaying.
    pub name: String,
    /// When capture began, for uptime.
    pub started: std::time::Instant,
    /// Path packets are being written to, when one was configured.
    ///
    /// `None` on a live capture means the packets exist only in memory: stop
    /// the process and they are gone. That is the fact `shutdown_server` has
    /// to consult before it agrees to stop anything.
    pub writing_to: Option<String>,
}

impl SipnabMcp {
    /// Build a new MCP server bound to the given (already-shared) stores.
    pub fn new(
        dialog_store: Arc<RwLock<DialogStore>>,
        stream_store: Arc<RwLock<StreamStore>>,
    ) -> Self {
        Self {
            dialog_store,
            stream_store,
            alert_engine: None,
            source_exhausted: None,
            row_cap: HARD_LIMIT,
            file_root: None,
            protected_inputs: Default::default(),
            allow_shutdown: false,
            allow_open_capture: false,
            allow_save_findings: false,
            findings: Arc::new(RwLock::new(crate::mcp::findings::FindingsLog::new())),
            capture: Arc::new(RwLock::new(CaptureState::default())),
            call_limiter: None,
            rate_limiter: None,
            tool_router: Self::tool_router(),
        }
    }

    /// Cap the number of tool calls this server runs at once. `max == 0`
    /// leaves the cap off (the default), matching the REST API's
    /// `--api-max-conn` convention where zero means unbounded. Any positive
    /// value installs a shared semaphore; a call that cannot take a permit
    /// immediately is refused, not queued. See the `call_limiter` field.
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.call_limiter = (max > 0).then(|| Arc::new(tokio::sync::Semaphore::new(max)));
        self
    }

    /// Cap the rows any list-style tool returns in one response.
    ///
    /// `0` is treated as the default rather than as "unlimited": an unbounded
    /// response is not a thing an operator can want by accident, and the
    /// config layer already rejects 0 by name.
    #[must_use]
    pub fn with_row_cap(mut self, rows: usize) -> Self {
        self.row_cap = if rows == 0 { HARD_LIMIT } else { rows };
        self
    }

    /// Cap the tool calls this server accepts per second from any ONE peer.
    /// `per_second == 0` leaves the limit off, the same spelling of
    /// "unlimited" [`Self::with_max_concurrent`] uses — a positive value
    /// installs a shared limiter and a call over the cap is refused with a
    /// retry-shortly error, not queued. See the `rate_limiter` field.
    pub fn with_rate_limit_per_peer(mut self, per_second: u32) -> Self {
        self.rate_limiter = (per_second > 0).then(|| {
            Arc::new(parking_lot::Mutex::new(
                // No global ceiling: the server-wide bound on MCP work is the
                // concurrency cap, and a second server-wide knob metering the
                // same calls would be two answers to one question.
                crate::rate_limit::FixedWindowLimiter::new(0, u64::from(per_second)),
            ))
        });
        self
    }

    /// Tool calls this server has refused for exceeding a peer's rate limit,
    /// since it started. `0` when no limit is configured.
    ///
    /// Read on the refusal path so the audit line carries the running total: a
    /// single `outcome=refused` line says a call was turned away, and the
    /// total is what says whether that is one confused client or a flood.
    fn rate_limit_refusals(&self) -> u64 {
        self.rate_limiter
            .as_ref()
            .map(|l| l.lock().refused_total())
            .unwrap_or(0)
    }

    /// Declare the capture inputs this server is reading so the file tools
    /// refuse to write over them.
    pub fn with_protected_inputs(
        mut self,
        protected: crate::capture::output_guard::ProtectedInputs,
    ) -> Self {
        self.protected_inputs = protected;
        self
    }

    /// Attach a shared alert engine so the `security_findings` tool can
    /// read from its FindingsHistory ring buffer.
    pub fn with_alert_engine(mut self, alerts: Arc<RwLock<AlertEngine>>) -> Self {
        self.alert_engine = Some(alerts);
        self
    }

    /// Attach the shared "capture source fully consumed" flag that
    /// `tail_dialogs` reports as `source_exhausted`. The capture owner
    /// stores `true` once the packet source drains (pcap EOF).
    pub fn with_source_exhausted(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.source_exhausted = Some(flag);
        self
    }

    /// Describe what this server is attached to, so `capture_status` can
    /// answer. Without it the tool reports `source: "unknown"` rather than
    /// guessing.
    pub fn with_capture_context(self, ctx: CaptureContext) -> Self {
        {
            let mut state = self.capture.write();
            state.context = Some(ctx);
        }
        self
    }

    /// Confine the file tools to `dir`. Without this they refuse to run.
    pub fn with_file_root(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.file_root = Some(dir.into());
        self
    }

    /// Permit `shutdown_server` to stop this process.
    pub fn with_shutdown(mut self) -> Self {
        self.allow_shutdown = true;
        self
    }

    /// Permit `open_capture` to replace the capture this server holds.
    pub fn with_open_capture(mut self) -> Self {
        self.allow_open_capture = true;
        self
    }

    /// Permit `save_findings` to record an agent's annotation.
    ///
    /// Off by default like the other two, and for a sharper reason: this is the
    /// only verb on sipnab's whole network surface that accepts a write, and its
    /// caller is a language model reading attacker-controlled text off the wire.
    /// What keeps that safe is not that the text is harmless — it is that an
    /// annotation reaches nothing: it goes to the log, and no tool, query or
    /// analysis can read it back. That dead end is enforced by the private
    /// `findings` module's visibility rather than by convention — which is
    /// also why this doc cannot link to it.
    pub fn with_save_findings(mut self) -> Self {
        self.allow_save_findings = true;
        self
    }

    /// Resolve a caller-supplied FILENAME inside the configured root.
    ///
    /// The only accepted input is a bare filename. Anything with a separator,
    /// a `..`, a root prefix, or a Windows drive letter is refused before any
    /// filesystem call — this is a rejection list applied to a value that must
    /// already be a single component, not an attempt to sanitise a path.
    ///
    /// Sanitising paths is where this class of bug lives: every clever
    /// normaliser eventually meets a symlink, a unicode separator, or a
    /// `..%2f`. Requiring one component and rejecting everything else has no
    /// such middle ground.
    fn resolve_in_root(&self, name: &str) -> Result<std::path::PathBuf, rmcp::ErrorData> {
        let root = self.file_root.as_ref().ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                "file tools are disabled: start sipnab with --mcp-file-root <DIR> \
                 to enable them"
                    .to_string(),
                None,
            )
        })?;

        if name.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "filename must not be empty".to_string(),
                None,
            ));
        }
        // One path component, and it must be a plain name.
        let mut parts = std::path::Path::new(name).components();
        let only = parts.next();
        let extra = parts.next();
        let ok = matches!(only, Some(std::path::Component::Normal(_))) && extra.is_none();
        if !ok || name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "'{name}' is not a bare filename. These tools take a name, not \
                     a path, and write only inside the configured --mcp-file-root."
                ),
                None,
            ));
        }
        let target = root.join(name);

        // A bare name can still leave the root, because the escape is not in
        // the string: a symlink someone already placed in the root is one
        // normal component and passes every check above, and the kernel follows
        // it at `open`. Measured before this: an export wrote 77,736 bytes
        // through such a link to a path outside the root, exit 0, and returned
        // the in-root path as though that were where the bytes went.
        //
        // `canonical_target` is the same resolver `-O` uses to catch different
        // spellings of one file — reused rather than reimplemented, because two
        // implementations of one rule is a defect pattern this tree has already
        // been bitten by.
        //
        // The resolved path is what gets returned, so a caller is told where
        // the bytes will actually land rather than where it asked for them.
        let resolved = crate::capture::output_guard::canonical_target(&target);
        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
        if !resolved.starts_with(&canonical_root) {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "'{name}' resolves outside the configured --mcp-file-root. \
                     The name is a link to '{}', and these tools write only \
                     inside the root.",
                    resolved.display()
                ),
                None,
            ));
        }
        let target = resolved;

        // Refuse before the caller opens anything: every file tool writes with
        // truncation, so a check made after the open has already destroyed the
        // capture. This is the same precondition `-O` enforces, applied at the
        // one place all file tools resolve their path.
        self.protected_inputs
            .check(&target, "the requested filename", false)
            .map_err(|msg| rmcp::ErrorData::invalid_params(msg, None))?;

        Ok(target)
    }
}

impl SipnabMcp {
    /// The suppression list governing a lint run, explicit or discovered.
    ///
    /// An explicit filename wins outright and never falls back to discovery:
    /// naming a file that cannot be read is an error, because a caller that
    /// pointed at one and got a full-catalogue run would read the result as
    /// "my suppressions matched nothing".
    ///
    /// Discovery starts at the directory holding the capture, and only a file
    /// replay has one — a live interface is not a path. See
    /// [`SuppressionFile::discover`](crate::sip::lint::SuppressionFile::discover)
    /// for why the walk stops at a project root.
    fn resolve_suppressions(
        &self,
        explicit: Option<&String>,
    ) -> Result<Option<crate::sip::lint::SuppressionFile>, rmcp::ErrorData> {
        if let Some(name) = explicit {
            // The same one-component, symlink-resolved resolver every file
            // tool uses, rather than a second path check that could differ.
            let path = self.resolve_in_root(name)?;
            let file = crate::sip::lint::SuppressionFile::load(&path).map_err(|e| {
                rmcp::ErrorData::invalid_params(
                    format!("cannot read suppression file '{name}': {e}"),
                    None,
                )
            })?;
            return Ok(Some(file));
        }

        let capture_dir = {
            let state = self.capture.read();
            state.context.as_ref().and_then(|c| {
                if c.live {
                    return None;
                }
                std::path::Path::new(&c.name)
                    .parent()
                    .map(std::path::Path::to_path_buf)
            })
        };
        let Some(dir) = capture_dir else {
            return Ok(None);
        };
        let Some(found) = crate::sip::lint::SuppressionFile::discover(&dir) else {
            return Ok(None);
        };
        // A discovered file that cannot be read is reported rather than
        // silently ignored: it is on disk and the operator believes it applies.
        crate::sip::lint::SuppressionFile::load(&found)
            .map(Some)
            .map_err(|e| {
                rmcp::ErrorData::internal_error(
                    format!("cannot read discovered {}: {e}", found.display()),
                    None,
                )
            })
    }
}

/// The suppression half of a lint response, always emitted.
///
/// Present even when nothing was suppressed and no file was found. A response
/// carrying no field and a response carrying zero must not be the same bytes:
/// the first says nothing about whether findings were hidden, the second says
/// none were. The file is named because "3 findings suppressed" is
/// unactionable when discovery walked up several directories to find it.
fn suppression_json(
    file: Option<&crate::sip::lint::SuppressionFile>,
    withheld: crate::sip::lint::WithheldCounts,
) -> serde_json::Value {
    serde_json::json!({
        "file": file.map(|f| f.path().display().to_string()),
        "patterns": file.map(|f| f.patterns().to_vec()).unwrap_or_default(),
        "findings_suppressed": withheld.suppressed,
    })
}

/// What the run kept back, by reason, always emitted.
///
/// Three counts rather than one, because they send an operator to three
/// different places: a suppression file they wrote, a severity floor they
/// chose, and a per-rule cap that means there was simply too much.
fn withheld_json(withheld: crate::sip::lint::WithheldCounts) -> serde_json::Value {
    serde_json::json!({
        "suppressed": withheld.suppressed,
        "below_severity": withheld.below_severity,
        "capped": withheld.capped,
    })
}

// ── Tool parameter structs ──────────────────────────────────────────

/// Filter and pagination parameters for `list_dialogs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ListDialogsParams {
    /// Optional filter — either a named alias (e.g. "problems",
    /// "codec-asym") or a raw DSL expression.
    pub filter: Option<String>,
    /// Maximum dialogs to return (1..=1000, default 50).
    pub limit: Option<u32>,
    /// Cursor: pass back the previous response's `next_cursor` verbatim
    /// (`<RFC 3339>|<Call-ID>`) to continue after that page. Omit on the
    /// first call.
    pub cursor: Option<String>,
}

/// Parameters for `get_dialog_report`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GetDialogReportParams {
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Output format: "json", "markdown", or "text". Default "json".
    #[serde(default)]
    pub format: Option<String>,
}

/// Parameters for `find_problems`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct FindProblemsParams {
    /// Diagnostic alias names to OR together. Defaults to ["problems"].
    pub kinds: Option<Vec<String>>,
    /// Extra filter ANDed with the alias match — a named alias or a raw DSL
    /// expression. Narrows "anything problematic" to "problems on this
    /// trunk".
    pub filter: Option<String>,
    /// Maximum dialogs to return (1..=1000, default 50).
    pub limit: Option<u32>,
    /// Cursor: pass back the previous response's `next_cursor` verbatim
    /// (`<RFC 3339>|<Call-ID>`). Omit on the first call.
    pub cursor: Option<String>,
}

// ── Dialog-inspection parameter structs ─────────────────────────────

/// Parameters for `get_dialog`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GetDialogParams {
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Maximum messages to return per page (default 100, max 1000).
    pub max_messages: Option<u32>,
    /// Cursor — index of the first message to return. Default 0.
    pub cursor: Option<u32>,
}

/// Parameters for `get_message`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct GetMessageParams {
    /// Call-ID identifying the dialog, as returned by `list_dialogs`.
    pub call_id: String,
    /// Zero-based position of the message within this dialog, in the order the
    /// dialog holds them.
    ///
    /// How to obtain one, because the number is meaningless on its own:
    /// `get_dialog` returns a page of messages beginning at its `cursor`, so
    /// the Nth message of that page is at index `cursor + N`. The upper bound
    /// is `msg_count` from `list_dialogs` — the last valid index is
    /// `msg_count - 1`.
    ///
    /// An index at or past the end is refused with `invalid_params`, and the
    /// error names how many messages the dialog actually has, so a caller that
    /// guessed can correct itself without another round trip.
    pub index: u32,
}

/// Parameters for `render_ladder`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RenderLadderParams {
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Output format: "markdown" (default) or "text".
    pub format: Option<String>,
}

/// Parameters for `rtp_stats`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RtpStatsParams {
    /// Call-ID identifying the dialog. Omit to sweep every stream in the
    /// capture, including the orphans no Call-ID can name.
    pub call_id: Option<String>,
    /// Capture-wide sweep only: keep streams whose MOS is at or above this.
    /// Applies to grounded streams only — see `max_mos`.
    pub min_mos: Option<f64>,
    /// Capture-wide sweep only: keep streams whose MOS is strictly below this.
    ///
    /// Either bound restricts the sweep to codecs with a published ITU-T G.113
    /// impairment value. Everything else scores from a placeholder that is
    /// byte-identical to an unidentified stream's, and `ungrounded_excluded`
    /// reports how many streams the bound therefore could not judge.
    pub max_mos: Option<f64>,
    /// Capture-wide sweep only: maximum streams to return (1..=1000,
    /// default 50).
    pub limit: Option<u32>,
    /// Capture-wide sweep only: pass back the previous response's
    /// `next_cursor` verbatim. Omit on the first call.
    pub cursor: Option<String>,
}

/// Parameters for `search_messages`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SearchMessagesParams {
    /// Substring to match against method, status, From, To, User-Agent, body.
    /// Case-insensitive.
    pub query: String,
    /// Maximum hits to return (default 50, max 1000).
    pub limit: Option<u32>,
}

/// Zero-allocation ASCII-case-insensitive substring test used by
/// `search_messages`: is `needle` (already ASCII-lowercased by the caller)
/// contained in `haystack`, folding ASCII upper-case bytes on the fly? This
/// lets each SIP field be scanned in place — no per-message combined-string
/// `format!` and no whole-message `to_lowercase` allocation.
fn ascii_contains_ci(haystack: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    if needle.len() > h.len() {
        return false;
    }
    h.windows(needle.len())
        .any(|w| w.iter().zip(needle).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

/// Parameters for `tail_dialogs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TailDialogsParams {
    /// Cursor: pass back the previous response's `next_cursor` verbatim
    /// (`<RFC 3339>|<Call-ID>`); only dialogs updated after that position
    /// are returned. A bare RFC 3339 timestamp (the pre-compound format)
    /// is also accepted and filters strictly after it. Omit on the first
    /// call to start from the beginning.
    pub cursor: Option<String>,
    /// Maximum dialogs to return (default 50, max 1000).
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// One `search_messages` hit: the dialog and message that matched, with a snippet.
pub struct SearchHit {
    /// Call-ID of the dialog containing the matching message.
    pub call_id: String,
    /// Zero-based index of the matching message within the dialog.
    pub message_index: usize,
    /// Short excerpt of the matched text, for context.
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// Response for `tail_dialogs`: a page of updated dialogs plus a continuation cursor.
pub struct TailDialogsResponse {
    /// Dialogs updated since the request cursor, oldest first (ties broken
    /// by Call-ID).
    pub dialogs: Vec<DialogSummary>,
    /// Opaque cursor (`<RFC 3339>|<Call-ID>` of the last dialog returned)
    /// to pass to the next call. Null when no dialogs matched.
    pub next_cursor: Option<String>,
    /// True when the underlying capture source has been fully consumed
    /// (e.g., pcap EOF). Subsequent calls will keep returning empty
    /// dialogs arrays unless a new capture starts.
    pub source_exhausted: bool,
    /// Which capture these dialogs came from, and which revision of its stores.
    ///
    /// This is the response that most needs it: a poller holding a cursor
    /// sees an empty page after a swap and reads it as "nothing changed",
    /// when the truth is that everything did.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// Parameters for `explain_response_code`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExplainCodeParams {
    /// SIP response status code, e.g. 488.
    pub code: u16,
}

/// Parameters for `compare_dialogs`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CompareDialogsParams {
    /// Call-ID of the first dialog.
    pub call_id_a: String,
    /// Call-ID of the second dialog.
    pub call_id_b: String,
}

/// Parameters for `find_correlated`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct FindCorrelatedParams {
    /// Call-ID of the leg to correlate FROM.
    pub call_id: String,
    /// Maximum legs to return (1..=1000, default 50).
    pub limit: Option<u32>,
}

/// One leg correlated to the requested dialog.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CorrelatedLeg {
    /// Call-ID of the correlated dialog. Feed it to `get_dialog` for detail.
    pub call_id: String,
    /// Confidence, 0-100.
    pub score: u8,
    /// WHICH strategy matched, by name. The decisive field.
    ///
    /// `session_id` and `x_call_id` both score 100 and are not the same claim:
    /// one is an RFC 7989 identifier designed to cross a B2BUA, the other a
    /// vendor header someone configured. `charging_vector_related_icid` and
    /// `charging_vector_icid` come out of ONE header and are likewise not the
    /// same claim: RFC 7315's `related-icid` is an intermediary declaring the
    /// link across a B2BUA, while plain `icid-value` equality is silent across
    /// a conformant one, because an ICID identifies a dialog and a B2BUA is
    /// two. `timing_heuristic` is not an identifier at all.
    pub strategy: String,
    /// True when this strategy compared identifiers. False for a guess.
    ///
    /// Present so a caller can filter on the distinction without having to know
    /// which strategy names mean what.
    pub identifier_match: bool,
    /// For `timing_heuristic` only: the observed gap between the two dialogs'
    /// creation, in milliseconds.
    ///
    /// The evidence behind the guess, so a reader can judge it. A 15 ms gap on
    /// a quiet box and a 1,900 ms gap on a busy SBC score identically and mean
    /// very different things.
    pub observed_gap_ms: Option<i64>,
}

/// What `find_correlated` returns.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct FindCorrelatedResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// The Call-ID that was asked about.
    pub source_call_id: String,
    /// Legs correlated to it, best first.
    pub legs: Vec<CorrelatedLeg>,
    /// Total correlated legs found, before `limit` truncated the list.
    pub total_matched: usize,
    /// True when every returned leg came from a heuristic rather than an
    /// identifier.
    ///
    /// Stated rather than left to inference: a call tree built only from
    /// timing guesses is a hypothesis, and an agent that cannot tell the
    /// difference will present it as a finding.
    pub heuristic_only: bool,
    /// Which capture and store revision this answer describes.
    pub capture_identity: crate::provenance::CaptureEtag,
    /// The clock a `timing_heuristic` match depended on — present ONLY when
    /// such a match is in `legs`.
    ///
    /// Attached where it is the evidence and omitted where it is not. Within
    /// one capture, skew is irrelevant: both timestamps came from this clock
    /// and a constant offset cancels. It becomes decisive the moment an agent
    /// joins this answer to another server's, because the two-second window is
    /// smaller than the skew an undisciplined host accumulates in a day.
    ///
    /// `null` here therefore means "no time-based match was returned", never
    /// "the clock is fine".
    pub timing_clock: Option<crate::clock::ClockDiscipline>,
}

/// Parameters for `export_capture`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExportCaptureParams {
    /// Bare filename inside `--mcp-file-root`, e.g. "outage.pcap".
    pub filename: String,
}

/// Parameters for `export_audio`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExportAudioParams {
    /// Call whose audio to export.
    pub call_id: String,
    /// Bare filename inside `--mcp-file-root`, e.g. "call.wav".
    pub filename: String,
}

/// Parameters for `open_capture`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct OpenCaptureParams {
    /// Bare filename inside `--mcp-file-root`, e.g. "outage-0722.pcap".
    /// A path is refused: these tools take a name.
    pub filename: String,
}

/// Parameters for `save_findings`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SaveFindingsParams {
    /// One-line conclusion. Required.
    pub summary: String,
    /// Call-ID this is about, when it is about one. Not checked against the
    /// store: a note about a call that has since been evicted is still the note
    /// that mattered, and refusing it would lose exactly the record worth
    /// keeping.
    pub call_id: Option<String>,
    /// Supporting text.
    pub detail: Option<String>,
}

/// What `save_findings` did, reported rather than implied.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SaveFindingsResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// Sequence number assigned. Monotonic for the process and never reused,
    /// so two findings can be ordered even after the older one is evicted.
    pub seq: u64,
    /// When it was recorded, RFC 3339 UTC.
    pub written_at: String,
    /// Characters of `summary` submitted, before any clipping.
    pub summary_chars_submitted: usize,
    /// Characters of `detail` submitted, before any clipping.
    pub detail_chars_submitted: usize,
    /// True when either field was shortened to fit. The caller is told rather
    /// than left to compare lengths.
    pub truncated: bool,
    /// Findings this process has accepted, including this one.
    pub recorded_total: u64,
    /// Findings this process will still accept. Counts down, so the bound is
    /// visible before it bites rather than only when it refuses.
    pub remaining: u64,
    /// Stated so the caller cannot mistake a write for a readable store.
    pub readable_over_mcp: bool,
    /// Where a human actually reads this back.
    pub delivered_to: String,
    /// Capture and store generations current when this was recorded.
    pub capture_identity: crate::provenance::CaptureEtag,
}

/// Parameters for `shutdown_server`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ShutdownParams {
    /// Report what would happen without doing it. Defaults to TRUE — stopping
    /// requires a deliberate second call.
    pub dry_run: Option<bool>,
    /// Save the capture to this filename (inside `--mcp-file-root`) first.
    pub save_to: Option<String>,
    /// Required to stop a live capture whose packets are unsaved.
    pub discard_unsaved: Option<bool>,
}

/// Parameters for the per-call diagnostic tools.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CallIdParams {
    /// Call-ID to diagnose.
    pub call_id: String,
}

/// Parameters for `get_sdp_timeline`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SdpTimelineParams {
    /// Call-ID to report on.
    pub call_id: String,
}

/// Parameters for `lint_dialog`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct LintDialogParams {
    /// Call-ID to lint.
    pub call_id: String,
    /// Rule selectors, OR-ed together. Omit for every rule.
    ///
    /// Either a named subset of the catalogue (`all`, `must`, `rfc`,
    /// `interop`, `observation`/`observed`, `syntax`) or an RFC the rules read
    /// from (`rfc3261`, `rfc3264`, `rfc4566`, `rfc3551`, `rfc5761`).
    pub rulesets: Option<Vec<String>>,
    /// Drop findings quieter than this: `info`, `notice`, `warning`, `error`.
    pub severity_min: Option<String>,
    /// Bare filename of a suppression list inside `--mcp-file-root`.
    ///
    /// Wins outright over the `.sipnablint` discovery walk: a caller that
    /// names a file has stated an intent, and quietly linting against a
    /// different file found by searching upward would be the opposite of it.
    pub suppression_file: Option<String>,
}

/// Parameters for `validate_message`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ValidateMessageParams {
    /// Call-ID holding the message.
    pub call_id: String,
    /// Zero-based position of the message within the dialog.
    pub index: u32,
    /// Bare filename of a suppression list inside `--mcp-file-root`. Wins
    /// outright over the `.sipnablint` discovery walk.
    pub suppression_file: Option<String>,
}

/// Parameters for `explain_rule`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExplainRuleParams {
    /// Rule identifier, e.g. "OBS-3264-6.1-PT-UNDECLARED".
    pub rule_id: String,
}

/// Attach each finding's frame pointer, so a lint result can be checked
/// against the bytes that provoked it (#128).
///
/// A finding names a rule, a citation and a message INDEX. An index is only
/// meaningful next to the message list it indexes, which the caller may not
/// have and which changes as compaction runs — so on its own it is not
/// something a reviewer can follow. `frame_ref` is, and `show_evidence` turns
/// it back into the offending frame.
///
/// The key is OMITTED when the message carries no pointer, never emitted
/// empty. `"frame_ref": ""` and `"frame_ref": "x#0"` both read as a real
/// pointer, and a finding citing frame 0 of nothing is the manufactured
/// confidence this mechanism exists to prevent. A reader can distinguish
/// "this finding is unciteable" from "this finding cites frame 0" only if the
/// unciteable case says nothing at all.
fn findings_with_refs(
    findings: &[crate::sip::lint::Finding],
    messages: &[crate::sip::SipMessage],
) -> Vec<serde_json::Value> {
    findings
        .iter()
        .map(|f| {
            let mut v = serde_json::to_value(f).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = v.as_object_mut()
                && let Some(reference) =
                    messages.get(f.message_index).and_then(|m| m.frame.as_ref())
            {
                obj.insert(
                    "frame_ref".to_string(),
                    serde_json::Value::String(reference.to_string()),
                );
            }
            v
        })
        .collect()
}

/// Parameters for `show_evidence`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ShowEvidenceParams {
    /// Frame pointers to follow, in the `<source>#<ordinal>@<digest>` form the
    /// query tools emit — as `frame` on a dialog, a message or a stream, and
    /// as `frame_ref` on a `lint_dialog` or `validate_message` finding. Both
    /// names carry the same text and both are accepted here; `show_evidence`
    /// lists which tools emit
    /// which. The `@<digest>` half is what makes an answer verifiable; a
    /// pointer without it still resolves, and says it was not checked.
    pub refs: Vec<String>,
    /// Bytes of each frame to return as hex, capped at 4096. Defaults to 256,
    /// which covers a SIP message's start line and headers without pulling a
    /// whole jumbo frame into the context window.
    pub max_bytes: Option<usize>,
}

/// One entry in the `rulesets` list: a named subset, or an RFC number.
///
/// The catalogue's own vocabulary comes from
/// [`Ruleset::from_name`](crate::sip::lint::Ruleset::from_name) rather than a
/// second table here, so a ruleset added to the engine is selectable over MCP
/// the day it lands. The RFC form exists because an agent that has just read a
/// citation asks for "the RFC 3264 rules", and `rfc` alone already means
/// something else in the catalogue — MUST and SHOULD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSelector {
    /// A named subset of the catalogue.
    Set(crate::sip::lint::Ruleset),
    /// Every rule reading from one RFC.
    Rfc(u32),
}

impl RuleSelector {
    /// Parse one selector name, or `None` when it names nothing.
    fn parse(name: &str) -> Option<Self> {
        let lower = name.trim().to_ascii_lowercase();
        // `observed` is the word an agent reaches for after reading a finding
        // whose basis is `observation`. Accepted here rather than in the
        // engine: the catalogue keeps one spelling per concept, and a
        // convenience alias belongs at the surface that needs it.
        if lower == "observed" {
            return Some(Self::Set(crate::sip::lint::Ruleset::Observation));
        }
        if let Some(set) = crate::sip::lint::Ruleset::from_name(&lower) {
            return Some(Self::Set(set));
        }
        // Only an RFC the catalogue really cites. `rfc3621` is one keystroke
        // from `rfc3261` and would otherwise parse, select nothing, and return
        // an empty finding list — which reads exactly like a clean call. A
        // refusal naming the vocabulary cannot be misread that way.
        lower
            .strip_prefix("rfc")
            .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
            .and_then(|n| n.parse().ok())
            .filter(|n| crate::sip::lint::RULES.iter().any(|r| r.rfc == *n))
            .map(Self::Rfc)
    }

    /// Whether this selector picks `rule`.
    fn contains(self, rule: &crate::sip::lint::RuleMeta) -> bool {
        match self {
            Self::Set(set) => set.contains(rule),
            Self::Rfc(n) => rule.rfc == n,
        }
    }
}

/// Every selector name a caller may pass, for help text and error messages.
///
/// The RFC half is derived from the catalogue rather than listed, so a rule
/// citing a new RFC becomes selectable — and appears in the refusal that names
/// the vocabulary — without anyone remembering to add it here.
fn rule_selector_names() -> Vec<String> {
    let mut names: Vec<String> = crate::sip::lint::Ruleset::names()
        .iter()
        .map(|n| (*n).to_string())
        .collect();
    names.push("observed".to_string());
    let mut rfcs: Vec<u32> = crate::sip::lint::RULES.iter().map(|r| r.rfc).collect();
    rfcs.sort_unstable();
    rfcs.dedup();
    names.extend(rfcs.into_iter().map(|n| format!("rfc{n}")));
    names
}

/// Parse the `rulesets` argument, refusing an unknown name by naming the set.
///
/// An unrecognised selector could reasonably be ignored. It must not be: a
/// caller that asks for `rfc3621` and is handed the full catalogue reads more
/// findings than it selected and believes the filter worked.
fn parse_rule_selectors(names: Option<&Vec<String>>) -> Result<Vec<RuleSelector>, rmcp::ErrorData> {
    let Some(names) = names else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for name in names {
        let selector = RuleSelector::parse(name).ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!(
                    "unknown ruleset '{name}'. Valid selectors: {}",
                    rule_selector_names().join(", ")
                ),
                None,
            )
        })?;
        out.push(selector);
    }
    Ok(out)
}

/// Parse the `severity_min` argument, refusing an unknown name by naming the set.
fn parse_min_severity(
    name: Option<&String>,
) -> Result<crate::sip::lint::Severity, rmcp::ErrorData> {
    match name {
        None => Ok(crate::sip::lint::Severity::Info),
        Some(n) => crate::sip::lint::Severity::from_name(n).ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                format!("unknown severity '{n}'. Valid values: info, notice, warning, error"),
                None,
            )
        }),
    }
}

/// What a lint run had to read, which decides which rules could fire at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LintRun {
    /// One message, read alone — `validate_message`.
    OneMessage,
    /// A whole dialog, with or without RTP attributed to it — `lint_dialog`.
    WholeDialog {
        /// Whether at least one RTP stream was attributed to the call.
        media: bool,
    },
}

/// The rules this run could not settle, grouped by the reason each was skipped.
///
/// A conformance report listing four findings reads as "these four defects and
/// nothing else". Where a rule never got the input it needs that reading is
/// wrong, and the finding list cannot say so — a rule that did not run and a
/// rule that found nothing produce identical output. So the response names
/// them, the same way `DialogPage` reports the rows it withheld.
///
/// Grouped rather than listed one rule at a time because the reason is the
/// long half and `validate_message` skips twelve rules for three reasons. A
/// per-rule list repeated the same paragraph eleven times, which costs an agent
/// its context window for no information.
fn skipped_rules(run: LintRun) -> Vec<serde_json::Value> {
    let mut groups: Vec<(&'static str, Vec<&'static str>)> = Vec::new();
    for (rule_id, reason) in skip_reasons(run) {
        match groups.iter_mut().find(|(r, _)| *r == reason) {
            Some((_, ids)) => ids.push(rule_id),
            None => groups.push((reason, vec![rule_id])),
        }
    }
    groups
        .into_iter()
        .map(|(reason, rule_ids)| serde_json::json!({ "reason": reason, "rule_ids": rule_ids }))
        .collect()
}

/// Each skipped rule and why, before grouping.
fn skip_reasons(run: LintRun) -> Vec<(&'static str, &'static str)> {
    use crate::sip::lint::{RTCP_MUX_UNANSWERED, RULES, Scope};
    RULES
        .iter()
        .filter_map(|rule| {
            // Checked before the scope arms, and in both runs: the stream
            // store folds an RTCP report into the stream it describes and
            // keeps no record of the endpoint pair it landed on, which is
            // exactly what RFC 5761 §5.1.1 asks about. So this rule cannot
            // fire over MCP even with media in hand, and pointing the caller
            // at `lint_dialog` for it would be a dead end.
            let reason = if rule.id == RTCP_MUX_UNANSWERED.id {
                Some(
                    "needs the endpoint pairs RTCP arrived on. The stream store \
                     folds RTCP into the stream it reports on and keeps no record \
                     of where it landed, so no MCP tool can raise this rule.",
                )
            } else {
                match (run, rule.scope()) {
                    (LintRun::OneMessage, Scope::Dialog) => Some(
                        "reads a dialog's messages against each other, and this \
                         tool reads one message alone. Call lint_dialog.",
                    ),
                    (LintRun::OneMessage, Scope::Media) => Some(
                        "compares the declaration against the observed media, and \
                         this tool reads one message alone. Call lint_dialog.",
                    ),
                    (LintRun::WholeDialog { media: false }, Scope::Media) => Some(
                        "no RTP stream was attributed to this call, so there is \
                         nothing to compare the declaration against.",
                    ),
                    _ => None,
                }
            };
            reason.map(|reason| (rule.id, reason))
        })
        .collect()
}

/// Count findings by severity, so a caller can size a report without walking it.
fn severity_counts(findings: &[crate::sip::lint::Finding]) -> serde_json::Value {
    use crate::sip::lint::Severity;
    let count = |s: Severity| findings.iter().filter(|f| f.severity == s).count();
    serde_json::json!({
        "error": count(Severity::Error),
        "warning": count(Severity::Warning),
        "notice": count(Severity::Notice),
        "info": count(Severity::Info),
    })
}

/// Parameters for `search_by_time`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SearchByTimeParams {
    /// Inclusive RFC 3339 start, e.g. "2026-07-31T10:00:00Z".
    pub start: String,
    /// Exclusive RFC 3339 end. Omit for "everything since `start`".
    pub end: Option<String>,
    /// Extra filter ANDed with the window — a named alias (e.g. "problems")
    /// or a raw DSL expression, so "failed calls between 14:00 and 14:05" is
    /// one call rather than two.
    pub filter: Option<String>,
    /// Maximum dialogs to return (1..=1000, default 50).
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// What this server is attached to, returned by `capture_status`.
pub struct CaptureStatusResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// `"live"`, `"file"`, or `"unknown"` when no context was attached.
    pub source: String,
    /// Interface name when live, file path when replaying.
    pub name: Option<String>,
    /// Seconds since capture began.
    pub uptime_sec: Option<u64>,
    /// Dialogs held right now.
    pub dialog_count: usize,
    /// RTP streams held right now.
    pub stream_count: usize,
    /// Streams with no dialog to attach to.
    pub orphaned_stream_count: usize,
    /// Dialogs in any non-terminal state, calls and subscriptions alike.
    pub active_dialog_count: usize,
    /// Calls that are UP — dialogs in `InCall`, and nothing else. Never
    /// greater than `active_dialog_count`, which also counts setup and
    /// subscriptions.
    pub active_call_count: usize,
    /// Drops, invalid timestamps and undecodable frames on the capture path.
    pub capture_quality: CaptureQualityJson,
    /// True once a file source has been read to the end.
    pub source_exhausted: bool,
    /// Where packets are being written, if anywhere.
    pub writing_to: Option<String>,
    /// True when stopping now would lose packets that exist only in memory.
    ///
    /// The most useful field here: the difference between "restart this
    /// whenever you like" and "an afternoon of capture ends with this process".
    pub unsaved: bool,
    /// Which capture this is, and which revision of its stores.
    ///
    /// The instance changes the moment `open_capture` clears the stores, so
    /// two answers carrying different instances describe different captures
    /// however similar the rest of the fields look.
    pub capture_identity: crate::provenance::CaptureEtag,
    /// SIP messages seen and NOT analysed because both ports fell outside
    /// `--portrange`.
    ///
    /// `dialog_count` above answers "how much is held". Without this it also
    /// reads as "how much was there", and on real carrier traffic those differ
    /// badly: the corpus sweep measured 2,311 dialogs reported against 3,712
    /// real — 1,401 lost, 37.7% — because a third of the SIP never touches
    /// 5060/5061. That loss reached the operator as stderr warnings and a CLI
    /// summary line, and reached an MCP client not at all: the response was
    /// byte-identical with and without it (#95).
    ///
    /// The asymmetry is the point. A human sees a warning scroll past and can
    /// ask a follow-up. An agent answering "what calls are in this capture"
    /// from two-thirds of them cannot, and will answer with full confidence.
    /// Zero on live capture, where BPF filtered before the pipeline saw
    /// anything and there is nothing to under-report.
    pub unanalysed_sip_messages: u64,
    /// The busiest ports carrying that unanalysed SIP, up to five.
    ///
    /// Actionable rather than merely alarming: these are the values to pass to
    /// `--portrange`, so the answer names its own remedy.
    pub unanalysed_busiest_ports: Vec<UnanalysedPort>,
    /// The background load filling this capture, while one runs. Null
    /// otherwise, including before any `open_capture` call.
    pub load: Option<LoadStatus>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// Progress of an `open_capture` load, reported by `capture_status`.
///
/// The load runs on its own thread and the stores fill as it goes, so a poller
/// sees dialogs appear before `done`. What it must not do is treat a partial
/// capture as a complete one, which is what every field here is for.
pub struct LoadStatus {
    /// The file being read, as `open_capture` was asked for it.
    pub filename: String,
    /// Capture instance this load fills. Matches `capture_identity.instance`
    /// unless another load has started since.
    pub instance: String,
    /// Packets read so far.
    pub packets: u64,
    /// Seconds since the load started.
    pub elapsed_sec: u64,
    /// True once the reader stopped, whether it finished the file or failed.
    pub done: bool,
    /// Why the load stopped early, when it did. A partial load keeps whatever
    /// it read; this says the capture is not all of the file.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// Compiled-in features, returned by `server_capabilities`.
pub struct CapabilitiesResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// Crate version.
    pub version: String,
    /// Compiled-in feature names, sorted.
    pub features: Vec<String>,
    /// True when this build can decrypt TLS/SRTP.
    pub can_decrypt: bool,
    /// True when this build can receive HEP.
    pub can_hep: bool,
    /// True when this build can load WASM plugins.
    pub can_plugins: bool,
    /// Server-side opt-ins the operator passed at startup.
    pub runtime: RuntimeFlags,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// The startup flags that decide which tools do anything.
///
/// Compiled features and operator choices are different questions, and this
/// answers the second. Every tool that needs one of these refuses by name when
/// it is missing, so the two agree: what is reported here is what the refusal
/// would have named.
pub struct RuntimeFlags {
    /// Directory the file tools are confined to (`--mcp-file-root`), or null
    /// when they are disabled. `list_captures`, `export_capture`,
    /// `export_audio` and `open_capture` all need it.
    pub mcp_file_root: Option<String>,
    /// Whether `shutdown_server` may stop this process
    /// (`--mcp-allow-shutdown`).
    pub mcp_allow_shutdown: bool,
    /// Whether `open_capture` may replace the loaded capture
    /// (`--mcp-allow-open-capture`).
    pub mcp_allow_open_capture: bool,
    /// Whether `save_findings` may record an annotation
    /// (`--mcp-allow-save-findings`). The only write verb on this surface.
    pub mcp_allow_save_findings: bool,
}

/// The three ways this run's analysis can be incomplete or mistimed, plus the
/// one flag that says whether any of them happened.
///
/// Kept as three counters rather than a sum because the remedies differ and
/// disagree: kernel-ring drops are answered by a bigger `-B`/`--buffer`, a
/// narrower BPF filter or a smaller `--snaplen`; interface drops cannot be
/// recovered by a bigger buffer at all and point at the NIC, the driver or
/// the mirror; and an invalid timestamp loses no packet whatever, but makes
/// every timing figure in the capture — post-dial delay, RFC 3550 jitter,
/// MOS, call duration — unreliable. One collapsed total would send a reader
/// to the wrong one of the three.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureQualityJson {
    /// Packets the kernel discarded because the capture ring was full. Dialogs
    /// may be missing messages and RTP loss will overstate the wire.
    pub kernel_dropped_packets: u64,
    /// Packets the interface or its driver discarded before libpcap saw them.
    /// A larger capture buffer does not recover these.
    pub interface_dropped_packets: u64,
    /// Packets whose pcap timestamp was unusable and were stamped with the
    /// wall clock instead. Timing figures for this run are unreliable.
    pub invalid_timestamps: u64,
    /// Frames that arrived intact and produced nothing, because no decoder in
    /// sipnab could read them.
    ///
    /// Nothing was dropped and no byte is missing — the analysis simply saw
    /// none of it. Non-zero means a zero elsewhere in this response may mean
    /// "unknown" rather than "none", and a reader that cannot ask a follow-up
    /// question has no other way to tell those apart. Not folded into
    /// `degraded`: ordinary ARP is an undecodable frame on almost every
    /// capture, so a flag including it would always be true.
    pub undecodable_frames: u64,
    /// `true` when any of the three LOSS counters above is non-zero.
    ///
    /// Named for the direction there is evidence for. `false` means nothing
    /// was **observed** to go wrong — not that the capture provably saw every
    /// packet, since loss upstream of the capture point (an oversubscribed
    /// SPAN port, a one-directional tap, a filter that excluded the traffic)
    /// is invisible to all three counters.
    pub degraded: bool,
}

impl From<crate::output::prometheus::CaptureQuality> for CaptureQualityJson {
    fn from(q: crate::output::prometheus::CaptureQuality) -> Self {
        Self {
            kernel_dropped_packets: q.kernel_dropped_packets,
            interface_dropped_packets: q.interface_dropped_packets,
            invalid_timestamps: q.invalid_timestamps,
            undecodable_frames: q.undecodable_frames,
            degraded: q.degraded(),
        }
    }
}

/// One port carrying SIP that `--portrange` excluded from the analysis.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct UnanalysedPort {
    /// The service port.
    pub port: u16,
    /// SIP messages skipped on it.
    pub messages: u64,
}

/// Parameters for `security_findings`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SecurityFindingsParams {
    /// Filter to specific rule kinds (e.g. ["scanner","fraud"]). Empty/None
    /// returns all kinds.
    pub kinds: Option<Vec<String>>,
    /// RFC 3339 timestamp; only findings recorded strictly after are returned.
    pub since: Option<String>,
    /// Maximum findings to return (default 50, max 1000).
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// A single security finding rendered for MCP clients.
pub struct FindingJson {
    /// Name of the detection rule that fired.
    pub rule_name: String,
    /// Source IP associated with the finding.
    pub src_ip: String,
    /// Human-readable detail describing the finding.
    pub detail: String,
    /// RFC 3339 timestamp of when the finding was recorded.
    pub timestamp: String,
}

// ── Compact summary returned by list_dialogs / find_problems ────────

/// The canonical compact per-dialog row (see `crate::output::model`):
/// field names and value formats are shared with the CLI/NDJSON and REST
/// surfaces, so MCP cannot drift on the wire again (`message_count` vs
/// `msg_count`, Debug-formatted methods).
pub use crate::output::model::DialogSummary;

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// A bounded page of dialogs that says how much of the answer it is.
///
/// `list_dialogs` and `find_problems` returned a bare JSON array. On a
/// production capture holding 2311 dialogs the default page was 50 of them,
/// with nothing in the response to say so and no cursor to reach the rest —
/// even `limit: 100000` clamps to the hard cap of 1000 and leaves 1311
/// unreachable.
///
/// The consumer here is a language model. An agent asked "how many calls
/// failed?" counts the rows it was handed and answers with confidence, so a
/// silently short list is not a missing feature but a wrong answer delivered
/// convincingly. Every field below exists to make that impossible: the count
/// it did not send, the flag saying it did not, and the cursor that reaches
/// the remainder.
pub struct DialogPage {
    /// Version of this response schema.
    pub schema_version: u32,
    /// This page of dialog summaries, oldest first (ties broken by Call-ID).
    pub dialogs: Vec<DialogSummary>,
    /// Rows in `dialogs`, so counting the array is never necessary.
    pub returned: usize,
    /// Dialogs matching the query across the WHOLE store, independent of
    /// `limit` and `cursor`. This is the number that answers "how many".
    pub total_matched: usize,
    /// True when matches remain after this page. Pass `next_cursor` back to
    /// continue.
    pub truncated: bool,
    /// Opaque cursor (`<RFC 3339 created_at>|<Call-ID>` of the last row) to
    /// pass to the next call. Null on the final page.
    pub next_cursor: Option<String>,
    /// Which capture this page came from, and which revision of its stores.
    ///
    /// A cursor is only meaningful within one capture. `open_capture` can
    /// replace the whole dialog set between two pages, and without this the
    /// second page would look like an ordinary continuation of the first.
    pub capture_identity: crate::provenance::CaptureEtag,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// A bounded page of RTP streams from a capture-wide `rtp_stats` sweep.
pub struct StreamPage {
    /// Version of this response schema.
    pub schema_version: u32,
    /// This page of stream objects, oldest `first_seen` first.
    pub streams: Vec<serde_json::Value>,
    /// Rows in `streams`.
    pub returned: usize,
    /// Streams matching the query across the whole store, independent of
    /// `limit` and `cursor`.
    pub total_matched: usize,
    /// Streams a MOS bound could not judge, because no published ITU-T G.113
    /// impairment value exists for their codec.
    ///
    /// Reported rather than folded into the answer. "2 streams below 3.5" and
    /// "2 streams below 3.5, plus 200 I cannot score" describe different
    /// captures, and the second one is the truth on any network carrying
    /// AMR-WB, EVS or G.722. Zero whenever no MOS bound was given.
    pub ungrounded_excluded: usize,
    /// True when matches remain after this page.
    pub truncated: bool,
    /// Opaque cursor to pass to the next call. Null on the final page.
    pub next_cursor: Option<String>,
    /// Which capture this page came from, and which revision of its stores.
    pub capture_identity: crate::provenance::CaptureEtag,
}

// ── capture_health ──────────────────────────────────────────────────────
//
// `capture_health` is meant to run on a busy production server carrying
// other people's calls, reached over MCP from somewhere else. It answers
// three questions no sipnab deployment has ever been able to answer: does
// the capture path drop packets under real load, what is on that wire that
// sipnab cannot decode, and what does the encapsulation-aware BPF filter
// cost. Every one of those answers is a number.
//
// That machine's traffic is confidential, which makes this both the
// highest-value and the highest-risk surface here. The guarantee is
// therefore STRUCTURAL, not documentary: the response type below is
// integers, codes and one proportion, with no `String` anywhere in it or
// anything nested in it. A type that cannot represent packet content cannot
// leak packet content, so the guarantee survives a reviewer having a bad day
// and a comment going stale. It is the same discipline that makes
// `unless_declared` in `capture::declared_media` safe: that function cannot
// construct a `T`, so it can only ever suppress and never assert.
//
// `a_populated_capture_health_response_carries_no_string_value_anywhere`
// enforces it by walking a serialized response and failing on any string
// value at any depth.

/// Longest window `capture_health` will hold one MCP call open for.
///
/// A tool call is synchronous from the agent's side: the handler occupies a
/// request slot and the caller waits. Clients cancel a call that has not
/// answered — 60 seconds is the common default — so a window that can run for
/// minutes turns a diagnostic into a denial of service against the agent that
/// asked for it. 30 seconds keeps the whole call, including transport and
/// serialization, inside half of that budget while still being a window worth
/// having: on a trunk carrying 10,000 packets per second it observes 300,000
/// packets, which is enough for a drop rate to mean something.
///
/// Requests above the cap are clamped rather than refused, and the response
/// reports `requested_seconds` beside `applied_seconds` so the clamp is
/// visible instead of silent.
pub const MAX_SAMPLE_SECONDS: u32 = 30;

/// How long `capture_health` should watch the counters for.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureHealthParams {
    /// Seconds to wait between the two counter snapshots. Clamped to 30; zero
    /// is refused.
    pub sample_seconds: u32,
}

/// What this server has packets from, as a code rather than a name.
///
/// A dedicated "nothing attached" variant exists because the alternative is
/// the failure this whole release is about: a tool with nothing to read
/// returning zeros, which is indistinguishable from a healthy quiet wire.
///
/// No code is zero. A zeroed or defaulted struct therefore cannot be mistaken
/// for a real answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CaptureAttachment {
    /// No capture context was ever attached to this server.
    NotAttached = 1,
    /// A live interface.
    LiveInterface = 2,
    /// A capture file being replayed.
    ReplayedFile = 3,
}

/// Which kind of frame sipnab could not decode, as a code.
///
/// The number that goes with it travels separately, in
/// [`UndecodableReasonCount::number`], because the number IS the fact: DLT 0
/// says `editcap -T ether` will fix the file, EtherType 0x8847 says the span
/// port is mirroring MPLS. There is deliberately no label field — a
/// human-readable name belongs in `docs/mcp.md`, not on the wire, where it
/// would be a string in a response that must not carry one.
///
/// No code is zero, for the reason given on [`CaptureAttachment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UndecodableReasonCode {
    /// The pcap link type has no decoder here. `number` is the DLT.
    UnsupportedLinkType = 1,
    /// The link layer named a payload that is not IP. `number` is the
    /// EtherType, or null when the link layer records none.
    NotIp = 2,
    /// An IP header decoded but its payload is no transport sipnab handles.
    /// `number` is the outermost IP protocol, or null when unrecorded.
    NoTransport = 3,
    /// The frame is shorter than a header it claims. `number` is null.
    Truncated = 4,
    /// A decoder rejected the bytes. `number` is null.
    DecodeError = 5,
}

impl UndecodableReasonCode {
    /// Split a capture-side reason into its code and the number it carries.
    ///
    /// Matched exhaustively on purpose: a variant added to
    /// [`crate::capture::UndecodableReason`] must be given a code here rather
    /// than being swept into a catch-all that reports it as something else.
    fn split(reason: crate::capture::UndecodableReason) -> (Self, Option<i64>) {
        use crate::capture::UndecodableReason as R;
        match reason {
            R::UnsupportedLinkType(dlt) => (Self::UnsupportedLinkType, Some(i64::from(dlt))),
            R::NotIp(ethertype) => (Self::NotIp, ethertype.map(i64::from)),
            R::NoTransport(protocol) => (Self::NoTransport, protocol.map(i64::from)),
            R::Truncated => (Self::Truncated, None),
            R::DecodeError => (Self::DecodeError, None),
        }
    }
}

/// Serialize an integer-coded response enum, and describe it as an integer.
///
/// Hand-written rather than derived because serde renders a unit variant as
/// its NAME — a string on the wire, in the one response that must not carry
/// one. Writing the discriminant keeps the no-string guarantee absolute
/// instead of carving out an exception the walker would then have to trust.
macro_rules! integer_coded_enum {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_u8(*self as u8)
            }
        }

        impl JsonSchema for $ty {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($ty))
            }

            fn json_schema(
                generator: &mut rmcp::schemars::SchemaGenerator,
            ) -> rmcp::schemars::Schema {
                u8::json_schema(generator)
            }
        }
    };
}

integer_coded_enum!(CaptureAttachment);
integer_coded_enum!(UndecodableReasonCode);

/// The window `capture_health` actually observed.
///
/// Three numbers rather than one, because they can disagree and the
/// difference is the caller's business: `requested_seconds` is what was
/// asked for, `applied_seconds` is what the cap allowed, and `observed_ms`
/// is what the wall clock says elapsed. A rate computed against the number
/// that was asked for rather than the one that was observed is wrong by
/// however long the runtime took to wake the handler up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureHealthWindow {
    /// `sample_seconds` as the caller sent it.
    pub requested_seconds: u32,
    /// What the cap allowed, at most [`MAX_SAMPLE_SECONDS`].
    pub applied_seconds: u32,
    /// Wall-clock milliseconds between the two snapshots.
    pub observed_ms: u64,
}

/// The capture-path counters at one instant, or their change across a window.
///
/// The four loss channels are kept apart rather than summed because their
/// remedies disagree — see [`crate::output::prometheus::CaptureQuality`],
/// which is where these numbers come from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureCounters {
    /// Packets handed to the processing pipeline.
    pub packets: u64,
    /// Packets the kernel discarded because the capture ring was full. Raise
    /// `-B`/`--buffer`, narrow the filter, or cut `--snaplen`.
    pub kernel_dropped: u64,
    /// Packets the NIC or its driver discarded before libpcap saw them. A
    /// bigger buffer cannot recover these.
    pub interface_dropped: u64,
    /// Packets whose pcap timestamp was unusable, so every timing figure from
    /// this run rests on a substituted clock.
    pub invalid_timestamps: u64,
    /// Frames that arrived intact and produced nothing, because no decoder
    /// here could read them.
    pub undecodable_frames: u64,
}

impl CaptureCounters {
    /// This snapshot minus an earlier one.
    ///
    /// Saturating: the counters are monotonic within a run, but a reset
    /// between the two reads must not underflow into an enormous delta that
    /// reads as a catastrophic loss event.
    fn since(self, earlier: Self) -> Self {
        Self {
            packets: self.packets.saturating_sub(earlier.packets),
            kernel_dropped: self.kernel_dropped.saturating_sub(earlier.kernel_dropped),
            interface_dropped: self
                .interface_dropped
                .saturating_sub(earlier.interface_dropped),
            invalid_timestamps: self
                .invalid_timestamps
                .saturating_sub(earlier.invalid_timestamps),
            undecodable_frames: self
                .undecodable_frames
                .saturating_sub(earlier.undecodable_frames),
        }
    }
}

/// Frames counted against one undecodable reason, with the number that names
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct UndecodableReasonCount {
    /// Which reason. See the code table in `docs/mcp.md`.
    pub reason: UndecodableReasonCode,
    /// The DLT, EtherType or IP protocol the reason carries. Null when the
    /// reason carries no number, or when the decoder never recorded one.
    pub number: Option<i64>,
    /// Frames counted against this reason since the process started.
    pub frames: u64,
    /// Frames counted against it inside the observed window.
    pub frames_in_window: u64,
}

/// What the capture path did, as totals and as deltas across one window.
///
/// Numbers only, by construction. See the section comment above
/// [`MAX_SAMPLE_SECONDS`] for why that is the design rather than a
/// convention.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct CaptureHealth {
    /// Version of this response schema.
    pub schema_version: u32,
    /// What this server has packets from, or that it has nothing.
    pub attachment: CaptureAttachment,
    /// The window the deltas below were measured over.
    pub window: CaptureHealthWindow,
    /// Counters since the process started.
    pub totals: CaptureCounters,
    /// Their change across the observed window — the rates live here.
    pub in_window: CaptureCounters,
    /// `undecodable_frames / packets` since the process started, or `0.0`
    /// when nothing was captured, which is "nothing was observed to fail"
    /// rather than "everything failed".
    pub undecoded_fraction: f64,
    /// The same proportion computed over the window alone. A run that started
    /// on an unreadable encapsulation and has since been fixed shows a high
    /// total and a low window figure, and the pair is the only way to tell
    /// that from a link that is still unreadable now.
    pub undecoded_fraction_in_window: f64,
    /// Per-reason breakdown, busiest first, each with the number it carries.
    pub undecodable_by_reason: Vec<UndecodableReasonCount>,
    /// Frames counted in `totals.undecodable_frames` whose specific number is
    /// absent from `undecodable_by_reason`, because the capture carried more
    /// distinct numbers than the fixed-slot tables hold. Reported rather than
    /// hidden: a breakdown that quietly fails to add up to its total is the
    /// same confident wrong answer the tally itself exists to remove.
    pub undecodable_reasons_dropped: u64,
    /// Dialogs held right now.
    pub dialogs_tracked: usize,
    /// RTP streams held right now.
    pub streams_tracked: usize,
    /// Whether THIS host's clock is disciplined, and by how much it may be off.
    ///
    /// Irrelevant to a single capture, where one clock stamped every packet and
    /// a constant offset cancels out of every interval sipnab reports. It
    /// matters the moment an agent correlates across NODES: `find_correlated`'s
    /// `timing_heuristic` matches dialogs created within two seconds of each
    /// other, and two seconds is smaller than the skew an undisciplined host
    /// accumulates in a day. A caller comparing times between two servers
    /// should read this from both before trusting a time-based match.
    pub clock: crate::clock::ClockDiscipline,
}

/// One reading of the process-global capture counters.
///
/// Internal: it carries [`crate::capture::UndecodableTally`], which is not
/// part of the response shape. Only [`build_health`] turns it into one.
struct HealthSample {
    /// The scalar counters at this instant.
    counters: CaptureCounters,
    /// The per-reason breakdown at this instant, busiest first.
    reasons: Vec<crate::capture::UndecodableTally>,
    /// Frames whose reason overflowed the fixed-slot tables.
    reasons_dropped: u64,
}

impl HealthSample {
    /// Read every capture counter this process keeps.
    ///
    /// Relaxed atomic loads and one walk of the reason tables. Nothing here
    /// opens a device, starts a thread, or touches the capture in any way —
    /// which is the property that lets `capture_health` run against a live
    /// production capture at all.
    fn read() -> Self {
        let quality = crate::output::prometheus::CaptureQuality::current();
        let report = crate::capture::undecodable_report();
        Self {
            counters: CaptureCounters {
                packets: crate::capture::captured_packets(),
                kernel_dropped: quality.kernel_dropped_packets,
                interface_dropped: quality.interface_dropped_packets,
                invalid_timestamps: quality.invalid_timestamps,
                // From the report rather than from `quality`, so the total and
                // the breakdown below it come from one read and cannot
                // disagree about the same window.
                undecodable_frames: report.frames,
            },
            reasons: report.reasons,
            reasons_dropped: report.reasons_dropped,
        }
    }
}

/// Which capture this server is attached to, from its context.
fn attachment_of(context: Option<&CaptureContext>) -> CaptureAttachment {
    match context {
        None => CaptureAttachment::NotAttached,
        Some(c) if c.live => CaptureAttachment::LiveInterface,
        Some(_) => CaptureAttachment::ReplayedFile,
    }
}

/// Clamp a requested window to the cap, refusing zero.
///
/// Zero is an error rather than an empty window because a response of zero
/// deltas is exactly what a healthy quiet capture looks like, and the caller
/// would have no way to tell the two apart.
fn resolve_sample_seconds(requested: u32) -> Result<u32, rmcp::ErrorData> {
    if requested == 0 {
        return Err(rmcp::ErrorData::invalid_params(
            "sample_seconds must be at least 1. A zero-second window observes \
             nothing, and a response of zero deltas reads as a quiet capture."
                .to_string(),
            None,
        ));
    }
    Ok(requested.min(MAX_SAMPLE_SECONDS))
}

/// `undecodable / packets`, or `0.0` when nothing was captured.
///
/// Zero rather than NaN: a NaN serializes as `null`, which an agent reads as
/// "no answer" when the truth is "nothing was observed to fail".
fn undecoded_fraction(undecodable: u64, packets: u64) -> f64 {
    if packets == 0 {
        return 0.0;
    }
    undecodable as f64 / packets as f64
}

/// Build the response from two readings of the counters.
///
/// Pure, and separate from the handler on purpose: the counters are
/// process-global atomics that every other test in this binary also moves, so
/// the arithmetic is proved here against fixed inputs rather than against a
/// shared process.
fn build_health(
    attachment: CaptureAttachment,
    window: CaptureHealthWindow,
    before: &HealthSample,
    after: &HealthSample,
    dialogs_tracked: usize,
    streams_tracked: usize,
) -> CaptureHealth {
    let in_window = after.counters.since(before.counters);
    let undecodable_by_reason = after
        .reasons
        .iter()
        .map(|tally| {
            // A reason absent from the earlier reading first appeared inside
            // the window, so all of its frames belong to the window.
            let earlier = before
                .reasons
                .iter()
                .find(|b| b.reason == tally.reason)
                .map_or(0, |b| b.frames);
            let (reason, number) = UndecodableReasonCode::split(tally.reason);
            UndecodableReasonCount {
                reason,
                number,
                frames: tally.frames,
                frames_in_window: tally.frames.saturating_sub(earlier),
            }
        })
        .collect();

    CaptureHealth {
        schema_version: 1,
        attachment,
        window,
        undecoded_fraction: undecoded_fraction(
            after.counters.undecodable_frames,
            after.counters.packets,
        ),
        undecoded_fraction_in_window: undecoded_fraction(
            in_window.undecodable_frames,
            in_window.packets,
        ),
        totals: after.counters,
        in_window,
        undecodable_by_reason,
        undecodable_reasons_dropped: after.reasons_dropped,
        dialogs_tracked,
        streams_tracked,
        // Read at report time rather than cached at startup: a host can lose
        // or gain its time source while sipnab runs, and a cached "synced"
        // would keep saying so for the life of the process.
        clock: crate::clock::discipline(),
    }
}

/// Render one RTP stream as the MCP JSON object, MOS grounding included.
///
/// Shared by the per-call and capture-wide `rtp_stats` modes so the two cannot
/// describe the same stream differently.
fn stream_json(s: &crate::rtp::stream::RtpStream) -> serde_json::Value {
    let line = crate::output::json::stream_to_json(s);
    let mut v: serde_json::Value = serde_json::from_str(&line).unwrap_or(serde_json::Value::Null);
    // Say whether the MOS is a real estimate or a placeholder.
    //
    // An agent reading `mos: 4.2` cannot otherwise tell a grounded G.711 score
    // from the identical number sipnab returns for AMR-WB, EVS or an
    // unidentified stream — they are byte-identical today. Reporting a guess as
    // a measurement to something that will then reason about it is how a
    // confident wrong answer reaches an operator.
    if let Some(obj) = v.as_object_mut() {
        // The MOS itself, because the NDJSON stream shape this builds on does
        // not carry one — that is the CLI's per-stream line, where MOS lives on
        // the dialog instead. Without this the grounding flag below described a
        // number absent from the payload, which is worse than saying nothing:
        // it implies a MOS is there.
        if let Some(n) = serde_json::Number::from_f64(stream_mos(s)) {
            obj.insert("mos".into(), serde_json::Value::Number(n));
        }
        let grounded = mos_is_grounded(s);
        obj.insert("mos_grounded".into(), serde_json::Value::Bool(grounded));
        if !grounded {
            obj.insert(
                "mos_note".into(),
                serde_json::Value::String(
                    "No published ITU-T G.113 impairment value for this codec. \
                     The MOS is a placeholder meaning 'unknown', not an estimate."
                        .into(),
                ),
            );
        }
    }
    v
}

/// The MOS `rtp_stats` reports for a stream, on the narrowband G.107 scale.
fn stream_mos(s: &crate::rtp::stream::RtpStream) -> f64 {
    let total = s.packet_count + s.lost_packets;
    let loss_pct = if total > 0 {
        (s.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    crate::rtp::quality::estimate_mos(s.jitter, loss_pct, s.codec.as_deref())
}

/// Whether ITU-T G.113 publishes an impairment value for this stream's codec.
fn mos_is_grounded(s: &crate::rtp::stream::RtpStream) -> bool {
    matches!(
        crate::rtp::quality::mos_grounding(s.codec.as_deref()),
        crate::rtp::quality::MosGrounding::Published
    )
}

/// The tie-break half of a stream cursor: `0xSSRC@src>dst`.
///
/// Unique per stream (the store keys on exactly these three values) and free
/// of the cursor separator, so `<first_seen>|<identity>` splits unambiguously.
fn stream_identity(s: &crate::rtp::stream::RtpStream) -> String {
    format!("0x{:08x}@{}>{}", s.key.ssrc, s.key.src, s.key.dst)
}

// ── Tool implementations ────────────────────────────────────────────

impl SipnabMcp {
    /// Compile a caller-supplied filter: a named alias or a raw DSL expression.
    ///
    /// Done outside every lock, so a pathological expression cannot hold the
    /// stores while it parses.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) naming the offending expression when it is
    /// neither a known alias nor parseable.
    fn compile_filter(filter: Option<&str>) -> Result<Option<FilterExpr>, rmcp::ErrorData> {
        let Some(f) = filter else { return Ok(None) };
        let expr_str = expand_alias(f).unwrap_or(f);
        FilterExpr::parse(expr_str).map(Some).map_err(|e| {
            rmcp::ErrorData::invalid_params(format!("invalid filter '{f}': {e}"), None)
        })
    }

    /// Build one bounded page of dialogs from a predicate over the store.
    ///
    /// The single implementation behind `list_dialogs` and `find_problems`,
    /// because the two differ only in which dialogs they select and the
    /// counting is the part that has to be right.
    ///
    /// Order is `(created_at, Call-ID)`. Creation time is used rather than the
    /// `updated_at` that `tail_dialogs` pages on, and the difference matters:
    /// `tail_dialogs` exists to report change, so it must follow records as
    /// they move, while a full listing must not. A dialog that receives one
    /// more message mid-pagination would jump forward in an `updated_at`
    /// ordering, past a cursor that already went by — silently dropping it from
    /// the sweep. `created_at` never changes, so a page boundary stays where it
    /// was put.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `cursor`'s timestamp half is not RFC 3339.
    fn dialog_page(
        &self,
        cursor: Option<&str>,
        limit: usize,
        select: impl Fn(
            &crate::sip::dialog::SipDialog,
            &[&crate::rtp::stream::RtpStream],
            CaptureMedia,
        ) -> bool,
    ) -> Result<DialogPage, rmcp::ErrorData> {
        let cursor = match cursor {
            Some(raw) => Some(
                super::shape::parse_cursor(raw)
                    .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?,
            ),
            None => None,
        };

        // Capture lock first, stores second, all three held together — see
        // `CaptureState`. A page and the identity stamped on it must describe
        // one capture.
        let state = self.capture.read();
        let ds = self.dialog_store.read();
        let ss = self.stream_store.read();

        // Group streams by Call-ID once. `streams_for` scans the whole stream
        // store per dialog, which was affordable while these tools stopped at
        // the first `limit` matches and is quadratic now that they must visit
        // every dialog to count one.
        let mut by_call: std::collections::HashMap<&str, Vec<&crate::rtp::stream::RtpStream>> =
            std::collections::HashMap::new();
        for s in ss.iter() {
            if let Some(id) = s.associated_dialog.as_deref() {
                by_call.entry(id).or_default().push(s);
            }
        }

        // Every match, not the first `limit` of them: `total_matched` is the
        // whole point and cannot be known from a truncated scan.
        const NO_STREAMS: &[&crate::rtp::stream::RtpStream] = &[];
        // One run-level fact, read once rather than per dialog.
        let capture = CaptureMedia::of_store(&ss);
        let mut matched: Vec<&crate::sip::dialog::SipDialog> = ds
            .iter()
            .filter(|d| {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                select(d, streams, capture)
            })
            .collect();
        let total_matched = matched.len();

        matched.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.call_id.cmp(&b.call_id))
        });
        // Sort BEFORE the cursor filter and the truncation. Store order is
        // insertion order, so cutting first would let `next_cursor` skip past
        // dialogs that were never returned.
        let remaining: Vec<&crate::sip::dialog::SipDialog> = match &cursor {
            None => matched,
            Some(c) => matched
                .into_iter()
                .filter(|d| c.precedes(d.created_at, &d.call_id))
                .collect(),
        };

        let truncated = remaining.len() > limit;
        let page = &remaining[..remaining.len().min(limit)];
        let next_cursor = truncated
            .then(|| page.last())
            .flatten()
            .map(|d| super::shape::format_cursor(d.created_at, &d.call_id));
        let dialogs: Vec<DialogSummary> = page
            .iter()
            .map(|d| super::shape::fenced_dialog_summary(d))
            .collect();
        let capture_identity = state.identity.etag(ds.generation(), ss.generation());
        drop(ss);
        drop(ds);
        drop(state);

        Ok(DialogPage {
            schema_version: 1,
            returned: dialogs.len(),
            dialogs,
            total_matched,
            truncated,
            next_cursor,
            capture_identity,
        })
    }

    /// Sweep every RTP stream in the capture, optionally bounded by MOS.
    ///
    /// The mode exists because `rtp_stats { call_id }` cannot answer "which
    /// streams sound bad". Asking it per call costs one round trip per dialog —
    /// thousands on a real capture — and it never reaches an orphaned stream at
    /// all, since there is no Call-ID to name one with. Orphans are not an edge
    /// case: a stream with no dialog is what a NAT or one-way-audio fault looks
    /// like from the media side.
    ///
    /// # A MOS bound only judges what G.113 publishes
    ///
    /// `estimate_mos` returns 4.216 at 10 ms jitter for AMR, AMR-WB, EVS and
    /// G.722 — the same number it returns for a stream whose codec was never
    /// identified. Selecting on that is selecting on a placeholder, and it is
    /// wrong in both directions: a healthy AMR-WB stream is invisible to a
    /// `max_mos` sweep, and a degraded one gets picked out on a figure that
    /// never described it.
    ///
    /// So a bound restricts the sweep to codecs with a published impairment
    /// value and reports `ungrounded_excluded`. Filtering silently would let an
    /// agent report a clean capture on the strength of streams it could not
    /// score; the count turns that into a question the agent can ask.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `cursor`'s timestamp half is not RFC 3339.
    fn rtp_stats_capture_wide(
        &self,
        params: &RtpStatsParams,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let cursor = match params.cursor.as_deref() {
            Some(raw) => Some(
                super::shape::parse_cursor(raw)
                    .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?,
            ),
            None => None,
        };
        let bounded = params.min_mos.is_some() || params.max_mos.is_some();

        let page = {
            // Capture, then dialogs, then streams — the order `CaptureState`
            // documents. The dialog store is read only for its generation, so
            // the identity on this page names the same store revision the rows
            // came from.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();

            let mut ungrounded_excluded = 0usize;
            let mut matched: Vec<&crate::rtp::stream::RtpStream> = Vec::new();
            for s in ss.iter() {
                if !bounded {
                    matched.push(s);
                    continue;
                }
                if !mos_is_grounded(s) {
                    ungrounded_excluded += 1;
                    continue;
                }
                let mos = stream_mos(s);
                if params.min_mos.is_some_and(|lo| mos < lo)
                    || params.max_mos.is_some_and(|hi| mos >= hi)
                {
                    continue;
                }
                matched.push(s);
            }
            let total_matched = matched.len();

            matched.sort_by(|a, b| {
                a.first_seen
                    .cmp(&b.first_seen)
                    .then_with(|| stream_identity(a).cmp(&stream_identity(b)))
            });
            let remaining: Vec<&crate::rtp::stream::RtpStream> = match &cursor {
                None => matched,
                Some(c) => matched
                    .into_iter()
                    .filter(|s| c.precedes(s.first_seen, &stream_identity(s)))
                    .collect(),
            };

            let truncated = remaining.len() > limit;
            let rows = &remaining[..remaining.len().min(limit)];
            let next_cursor = truncated
                .then(|| rows.last())
                .flatten()
                .map(|s| super::shape::format_cursor(s.first_seen, &stream_identity(s)));
            let streams: Vec<serde_json::Value> = rows.iter().map(|s| stream_json(s)).collect();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            drop(ss);
            drop(ds);
            drop(state);

            StreamPage {
                schema_version: 1,
                returned: streams.len(),
                streams,
                total_matched,
                ungrounded_excluded,
                truncated,
                next_cursor,
                capture_identity,
            }
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(page)?]))
    }
}

#[tool_router(router = tool_router)]
impl SipnabMcp {
    /// Returns dialog summaries from the live store. Optional `filter` accepts
    /// named aliases (problems, slow-setup, short-calls, one-way, nat-issues,
    /// codec-asym, ptime-asym, payload-asym, duration-asym, late-media) or a
    /// raw DSL expression. Output is bounded by `limit` (default 50, max 1000).
    ///
    /// # Returns
    ///
    /// A `DialogPage`: this page of `DialogSummary` rows, the `total_matched`
    /// across the whole store, a `truncated` flag, and a `next_cursor` (null on
    /// the final page).
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `filter` is neither a known alias nor a
    /// parseable DSL expression, or when `cursor`'s timestamp half is not
    /// RFC 3339.
    #[tool(
        name = "list_dialogs",
        description = "Returns a page of dialog summaries from the live capture \
                       store. Filter accepts a diagnostic alias name or a raw DSL \
                       expression. The response carries total_matched, a truncated \
                       flag, and next_cursor for the remaining dialogs.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn list_dialogs(
        &self,
        Parameters(params): Parameters<ListDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let filter = Self::compile_filter(params.filter.as_deref())?;
        let page = self.dialog_page(params.cursor.as_deref(), limit, |d, streams, capture| {
            filter
                .as_ref()
                .is_none_or(|expr| expr.matches_dialog(d, streams, capture))
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::json(page)?]))
    }

    /// Returns a structured per-call report (timing, parties, RTP quality,
    /// diagnosis hints) for one Call-ID. Format defaults to JSON; "markdown"
    /// and "text" produce human-readable variants identical to
    /// `--call-report --markdown` and `--call-report` respectively.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `format` or an unknown
    /// `call_id`.
    #[tool(
        name = "get_dialog_report",
        description = "Returns a structured per-call report (timing, parties, \
                       RTP quality, diagnosis hints) for one Call-ID. Format \
                       'json', 'markdown', or 'text'. Returns an error when the \
                       Call-ID is not found in the active store.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_dialog_report(
        &self,
        Parameters(params): Parameters<GetDialogReportParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let format = match params.format.as_deref() {
            Some("markdown") | Some("md") => ReportFormat::Markdown,
            Some("text") | Some("txt") => ReportFormat::Text,
            None | Some("json") => ReportFormat::Json,
            Some(other) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("unknown format '{other}', expected json|markdown|text"),
                    None,
                ));
            }
        };

        // Acquire both stores, build the report fully inside the locks (the
        // report generator is sync), then drop the guards before constructing
        // the response.
        let report: String = {
            let ds = self.dialog_store.read();
            let dialog = match ds.get(&params.call_id) {
                Some(d) => d,
                None => {
                    drop(ds);
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("call_id '{}' not found", params.call_id),
                        None,
                    ));
                }
            };
            let ss = self.stream_store.read();
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&params.call_id).collect();

            let media = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
            let mut diag = diagnose_media(&dialog_streams, &media);
            diagnose_asymmetry(
                &mut diag,
                Some(dialog),
                &dialog_streams,
                &AsymmetryThresholds::default(),
            );
            let report = generate_call_report(dialog, &dialog_streams, &diag, format);
            drop(ss);
            drop(ds);
            report
        };

        let content = if format == ReportFormat::Json {
            // Re-parse so the response is structured JSON, not a stringified blob.
            match serde_json::from_str::<serde_json::Value>(&report) {
                Ok(v) => ContentBlock::json(v)?,
                Err(_) => ContentBlock::text(report),
            }
        } else {
            ContentBlock::text(report)
        };
        // A report is a mixed document: sipnab's own diagnosis interleaved with
        // header values the sender wrote. Fencing the whole thing would tell the
        // agent to distrust the analysis too, so the note carries the provenance
        // instead of a marker pair that cannot be placed accurately here.
        Ok(CallToolResult::success(vec![
            content,
            ContentBlock::text(super::shape::untrusted_note()),
        ]))
    }

    /// Convenience wrapper over `list_dialogs` — runs each named alias from
    /// `kinds` (default `["problems"]`) and ORs the matches together, then ANDs
    /// the optional `filter`. Useful when you want "anything that looks
    /// problematic" in one call, or that narrowed to one trunk.
    ///
    /// # Returns
    ///
    /// A `DialogPage` of `DialogSummary` rows matching any alias and the
    /// filter, with `total_matched`, `truncated` and `next_cursor`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown alias name, an alias whose
    /// expansion fails to parse, an unparseable `filter`, or a `cursor` whose
    /// timestamp half is not RFC 3339.
    #[tool(
        name = "find_problems",
        description = "Returns a page of dialogs matching any of the named \
                       diagnostic aliases (problems, slow-setup, short-calls, \
                       one-way, nat-issues, codec-asym, ptime-asym, \
                       payload-asym, duration-asym, late-media), optionally \
                       narrowed by a DSL filter. Defaults to ['problems']. The \
                       response carries total_matched, truncated and next_cursor.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn find_problems(
        &self,
        Parameters(params): Parameters<FindProblemsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let kinds = params.kinds.unwrap_or_else(|| vec!["problems".to_string()]);

        // Compile each kind individually so a bad alias is reported by name.
        let mut compiled: Vec<FilterExpr> = Vec::with_capacity(kinds.len());
        for k in &kinds {
            let expr_str = expand_alias(k).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(format!("unknown alias '{k}'"), None)
            })?;
            match FilterExpr::parse(expr_str) {
                Ok(expr) => compiled.push(expr),
                Err(e) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("alias '{k}' expanded to a non-parseable expression: {e}"),
                        None,
                    ));
                }
            }
        }
        let extra = Self::compile_filter(params.filter.as_deref())?;

        // ANY alias AND the filter. The aliases answer "is this call
        // interesting", the filter answers "is it the one I am looking at" —
        // ORing them instead would widen the triage sweep rather than narrow it.
        let page = self.dialog_page(params.cursor.as_deref(), limit, |d, streams, capture| {
            compiled
                .iter()
                .any(|expr| expr.matches_dialog(d, streams, capture))
                && extra
                    .as_ref()
                    .is_none_or(|expr| expr.matches_dialog(d, streams, capture))
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::json(page)?]))
    }

    // ── Dialog-inspection and monitoring tools ──────────────────────

    /// Returns a paginated dialog including its SIP messages.
    ///
    /// # Returns
    ///
    /// A JSON object with the dialog summary, the requested message page,
    /// `total_messages`, a `next_cursor` (null on the last page), and a
    /// `complete` flag. A cursor past the end yields an empty page.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` is not found.
    #[tool(
        name = "get_dialog",
        description = "Returns a paginated dialog including SIP messages. \
                       Supports cursor-based pagination via max_messages \
                       (default 100, max 1000) and cursor (default 0).",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_dialog(
        &self,
        Parameters(params): Parameters<GetDialogParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let max = match params.max_messages {
            None | Some(0) => 100usize,
            Some(n) => (n as usize).min(self.row_cap),
        };
        let cursor = params.cursor.unwrap_or(0) as usize;

        let payload: serde_json::Value = {
            let ds = self.dialog_store.read();
            let dialog = match ds.get(&params.call_id) {
                Some(d) => d,
                None => {
                    drop(ds);
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("call_id '{}' not found", params.call_id),
                        None,
                    ));
                }
            };
            let total = dialog.messages.len();
            let end = (cursor + max).min(total);
            let slice = if cursor >= total {
                Vec::new()
            } else {
                dialog.messages[cursor..end]
                    .iter()
                    .map(crate::output::json::message_to_json_value)
                    .collect()
            };
            let summary = super::shape::fenced_dialog_summary(dialog);
            let next_cursor = if end < total { Some(end) } else { None };
            drop(ds);
            serde_json::json!({
                "dialog": summary,
                "messages": slice,
                "total_messages": total,
                "next_cursor": next_cursor,
                "complete": end >= total,
            })
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Returns a single SIP message at the given index, serialized as the
    /// same JSON object the NDJSON output emits.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` is unknown or `index` is out
    /// of range for the dialog.
    #[tool(
        name = "get_message",
        description = "Returns one SIP message from a dialog, by its position \
                       in that dialog's message list. Use it to re-read a \
                       single message in full after `get_dialog` showed you a \
                       page of them. To find an index: `get_dialog` returns \
                       messages in order starting at its `cursor`, so the Nth \
                       message of that page is at index cursor+N, and \
                       `list_dialogs` reports `msg_count`, which is one past \
                       the last valid index. Returns invalid_params when the \
                       Call-ID is unknown, or when the index is out of range \
                       — that error names the dialog's message count.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_message(
        &self,
        Parameters(params): Parameters<GetMessageParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let parsed: serde_json::Value = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let idx = params.index as usize;
            let msg = dialog.messages.get(idx).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!(
                        "index {idx} out of range for dialog with {} messages",
                        dialog.messages.len()
                    ),
                    None,
                )
            })?;
            let mut v = crate::output::json::message_to_json_value(msg);
            // Free-text headers fenced here, at the boundary — not in the
            // shared serializer, which also feeds `--json` on the CLI.
            super::shape::fence_message_json(&mut v);
            v
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::json(parsed)?,
            ContentBlock::text(super::shape::untrusted_note()),
        ]))
    }

    /// Renders a SIP call-flow ladder as markdown (default) or text for one
    /// Call-ID, returned as a text content block.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `format` or an unknown
    /// `call_id`.
    #[tool(
        name = "render_ladder",
        description = "Renders a SIP call-flow ladder for one Call-ID. \
                       Format 'markdown' (default) or 'text'. Output is \
                       byte-identical to `--call-report --markdown`.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn render_ladder(
        &self,
        Parameters(params): Parameters<RenderLadderParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let format = match params.format.as_deref() {
            Some("text") | Some("txt") => ReportFormat::Text,
            None | Some("markdown") | Some("md") => ReportFormat::Markdown,
            Some(other) => {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("unknown format '{other}', expected markdown|text"),
                    None,
                ));
            }
        };
        let report: String = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let ss = self.stream_store.read();
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&params.call_id).collect();
            let media = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
            let mut diag = diagnose_media(&dialog_streams, &media);
            diagnose_asymmetry(
                &mut diag,
                Some(dialog),
                &dialog_streams,
                &AsymmetryThresholds::default(),
            );
            let r = generate_call_report(dialog, &dialog_streams, &diag, format);
            drop(ss);
            drop(ds);
            r
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::text(report),
            ContentBlock::text(super::shape::untrusted_note()),
        ]))
    }

    /// Returns RTP quality stats: for one dialog, or across the whole capture.
    ///
    /// # Returns
    ///
    /// With `call_id`, a JSON object carrying the `call_id`, a `streams` array
    /// (empty when the dialog has no media), and the media `diagnosis`.
    ///
    /// Without `call_id`, a `StreamPage` sweeping every stream in the store —
    /// including the orphans no Call-ID can name — with `total_matched`,
    /// `ungrounded_excluded`, `truncated` and `next_cursor`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` is not found, when a MOS bound
    /// accompanies a `call_id`, or when `cursor`'s timestamp half is not
    /// RFC 3339.
    #[tool(
        name = "rtp_stats",
        description = "Returns per-stream RTP quality (codec, MOS, mos_grounded, \
                       jitter, loss%, packet count, SSRC). With call_id: every \
                       stream of that dialog plus its media diagnosis. Without \
                       call_id: a paged sweep of every stream in the capture, \
                       optionally bounded by min_mos / max_mos, which apply only \
                       to codecs with a published ITU-T G.113 impairment value.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn rtp_stats(
        &self,
        Parameters(params): Parameters<RtpStatsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let Some(call_id) = params.call_id.as_deref() else {
            return self.rtp_stats_capture_wide(&params);
        };
        // A MOS bound alongside a Call-ID is a misunderstanding of the tool,
        // and silently dropping it would answer a question nobody asked.
        if params.min_mos.is_some() || params.max_mos.is_some() {
            return Err(rmcp::ErrorData::invalid_params(
                "min_mos and max_mos sweep the whole capture; omit call_id to \
                 use them, or drop them to report on one call"
                    .to_string(),
                None,
            ));
        }

        let payload: serde_json::Value = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(format!("call_id '{call_id}' not found"), None)
            })?;
            let ss = self.stream_store.read();
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(call_id).collect();
            let stream_jsons: Vec<serde_json::Value> =
                dialog_streams.iter().map(|s| stream_json(s)).collect();
            let ctx = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
            let mut diag = diagnose_media(&dialog_streams, &ctx);
            diagnose_asymmetry(
                &mut diag,
                Some(dialog),
                &dialog_streams,
                &AsymmetryThresholds::default(),
            );
            let diag_json = serde_json::to_value(&diag).unwrap_or(serde_json::Value::Null);
            drop(ss);
            drop(ds);
            serde_json::json!({
                "call_id": call_id,
                "streams": stream_jsons,
                "diagnosis": diag_json,
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Substring-search SIP messages across all dialogs (case-insensitive
    /// over method, status, From, To, User-Agent, and body).
    ///
    /// # Returns
    ///
    /// A JSON array of `SearchHit` rows, empty when nothing matches;
    /// snippets are truncated to `MAX_BODY_BYTES`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `query` is empty.
    #[tool(
        name = "search_messages",
        description = "Case-insensitive substring search over SIP method, \
                       status, From, To, User-Agent, and body across all \
                       dialogs in the active store. Returns up to `limit` \
                       (default 50, max 1000) (call_id, message_index, \
                       snippet) hits.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn search_messages(
        &self,
        Parameters(params): Parameters<SearchMessagesParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if params.query.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "query must be non-empty".to_string(),
                None,
            ));
        }
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        // Lower-case the needle ONCE (ASCII-fold, matching the TUI search
        // paths in `tui::msg_raw` / `tui::stream_list`). Each message is then
        // scanned field-by-field with a zero-allocation case-insensitive
        // substring test, short-circuiting on the first match — avoiding the
        // per-message `format!` (a whole-message String) plus a second
        // whole-message `to_lowercase` allocation the old code paid on every
        // message of every call.
        let needle = params.query.to_ascii_lowercase();
        let needle_bytes = needle.as_bytes();
        let hits: Vec<SearchHit> = {
            let ds = self.dialog_store.read();
            let mut out: Vec<SearchHit> = Vec::new();
            'outer: for d in ds.iter() {
                for (idx, msg) in d.messages.iter().enumerate() {
                    // Cheap borrowed fields first; the body's lossy view (a
                    // borrow for valid UTF-8) is scanned last and only if the
                    // earlier fields miss.
                    let status = msg.status_code.map(|s| s.to_string());
                    let body = String::from_utf8_lossy(&msg.body);
                    let matched =
                        ascii_contains_ci(
                            msg.method.as_ref().map(|m| m.as_str()).unwrap_or(""),
                            needle_bytes,
                        ) || ascii_contains_ci(status.as_deref().unwrap_or(""), needle_bytes)
                            || ascii_contains_ci(msg.from_header().unwrap_or(""), needle_bytes)
                            || ascii_contains_ci(msg.to_header().unwrap_or(""), needle_bytes)
                            || ascii_contains_ci(msg.user_agent().unwrap_or(""), needle_bytes)
                            || ascii_contains_ci(&body, needle_bytes);
                    if matched {
                        // Fenced, not raw: this is the whole message as the
                        // sender wrote it, the largest run of attacker-authored
                        // text the MCP surface returns.
                        let snippet = super::shape::fence(&super::shape::truncate_string(
                            &String::from_utf8_lossy(&msg.raw),
                            super::shape::MAX_BODY_BYTES,
                        ));
                        out.push(SearchHit {
                            call_id: d.call_id.clone(),
                            message_index: idx,
                            snippet,
                        });
                        if out.len() >= limit {
                            break 'outer;
                        }
                    }
                }
            }
            drop(ds);
            out
        };
        Ok(CallToolResult::success(vec![
            ContentBlock::json(hits)?,
            ContentBlock::text(super::shape::untrusted_note()),
        ]))
    }

    /// Incremental dialog fetch — returns dialogs updated strictly after the
    /// supplied cursor.
    ///
    /// # Returns
    ///
    /// A `TailDialogsResponse`: matching dialogs sorted oldest-first
    /// (ties broken by Call-ID), a `next_cursor` derived from the last
    /// dialog returned (null when no dialogs matched), and the
    /// `source_exhausted` flag.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `cursor`'s timestamp half is not
    /// RFC 3339.
    #[tool(
        name = "tail_dialogs",
        description = "Returns dialogs updated strictly after `cursor` \
                       (omit for first call, then pass back next_cursor \
                       verbatim; a bare RFC 3339 timestamp is also \
                       accepted). Used for polling-based change tracking. \
                       The response carries source_exhausted=true after a \
                       pcap source has been fully consumed.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn tail_dialogs(
        &self,
        Parameters(params): Parameters<TailDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        // The cursor is `<RFC 3339>` (legacy) or `<RFC 3339>|<Call-ID>`
        // (compound, what next_cursor emits) — parsed by the shared helper in
        // `shape`, which the paged list tools use too. One implementation of
        // the tie-break, because it is the part that goes silently wrong.
        let cursor = match params.cursor.as_deref() {
            Some(raw) => Some(
                super::shape::parse_cursor(raw)
                    .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?,
            ),
            None => None,
        };

        let response: TailDialogsResponse = {
            // Capture lock first, then the stores — see `CaptureState`.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            // Collect EVERY dialog past the cursor, sort by the cursor's
            // ordering key (updated_at, Call-ID tie-break), and only then
            // truncate to `limit`. Truncating first (store order is
            // insertion order, not update order) would let next_cursor
            // jump past dialogs that were never returned. A compound
            // cursor keeps a legacy bare-timestamp cursor's strictly-after
            // filter, and resumes after (updated_at, call_id) so a tie
            // group split across a page boundary is neither dropped nor
            // duplicated.
            let mut changed: Vec<&crate::sip::dialog::SipDialog> = ds
                .iter()
                .filter(|d| {
                    cursor
                        .as_ref()
                        .is_none_or(|c| c.precedes(d.updated_at, &d.call_id))
                })
                .collect();
            changed.sort_by(|a, b| {
                a.updated_at
                    .cmp(&b.updated_at)
                    .then_with(|| a.call_id.cmp(&b.call_id))
            });
            changed.truncate(limit);
            let next_cursor = changed
                .last()
                .map(|d| super::shape::format_cursor(d.updated_at, &d.call_id));
            let summaries: Vec<DialogSummary> = changed
                .into_iter()
                .map(super::shape::fenced_dialog_summary)
                .collect();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            drop(ss);
            drop(ds);
            drop(state);
            TailDialogsResponse {
                dialogs: summaries,
                next_cursor,
                source_exhausted: self
                    .source_exhausted
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed)),
                capture_identity,
            }
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(response)?]))
    }

    /// Returns recent security findings (scanner/fraud/digest/reg-flood/etc.)
    /// from the in-memory ring buffer. When the AlertEngine isn't attached
    /// (e.g. running in a query-only mode without active detection rules),
    /// returns an empty list rather than erroring.
    ///
    /// # Returns
    ///
    /// A JSON array of `FindingJson` rows with details truncated to
    /// `MAX_BODY_BYTES`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `since` is not RFC 3339.
    #[tool(
        name = "security_findings",
        description = "Returns recent security findings recorded by the \
                       active detection rules (scanner, fraud, digest leaks, \
                       reg flood). Optional `kinds` filter and `since` RFC \
                       3339 cursor; empty list when no AlertEngine is \
                       attached.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn security_findings(
        &self,
        Parameters(params): Parameters<SecurityFindingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);
        let since: Option<chrono::DateTime<chrono::Utc>> = match params.since {
            Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                Err(e) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("since must be RFC 3339: {e}"),
                        None,
                    ));
                }
            },
            None => None,
        };
        let findings: Vec<FindingJson> = match &self.alert_engine {
            Some(engine) => {
                let kinds_owned: Vec<String> = params.kinds.unwrap_or_default();
                let kinds_ref: Vec<&str> = kinds_owned.iter().map(String::as_str).collect();
                let guard = engine.read();
                let raw = guard.iter_findings(&kinds_ref, since, limit);
                raw.iter()
                    .map(|f| FindingJson {
                        rule_name: f.rule_name.clone(),
                        src_ip: f.src_ip.to_string(),
                        detail: super::shape::truncate_string(
                            &f.detail,
                            super::shape::MAX_BODY_BYTES,
                        ),
                        timestamp: f.timestamp.to_rfc3339(),
                    })
                    .collect::<Vec<_>>()
            }
            None => Vec::new(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(findings)?]))
    }

    /// What this server is attached to: live interface or file, for how long,
    /// how much it holds, and whether stopping would lose anything.
    #[tool(
        name = "capture_status",
        description = "Returns what this server is capturing: live interface or \
                       replayed file, its name, uptime, how many dialogs and \
                       streams are held, whether a file source is exhausted, and \
                       whether stopping now would lose unsaved packets. Call this \
                       before reasoning about stopping or restarting a capture.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn capture_status(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        // Read before the locks below: a process-global atomic unrelated to
        // either store's revision, so nothing is gained by holding a guard
        // across it.
        let capture_quality = crate::output::prometheus::CaptureQuality::current().into();
        let payload = {
            // Capture lock first, then the stores — see `CaptureState`. Held
            // together so the identity, the source name and the counts all
            // describe one capture; an `open_capture` landing mid-answer
            // would otherwise produce a status that is true of nothing.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let (source, name, uptime_sec, writing_to, live) = match &state.context {
                Some(c) => (
                    if c.live { "live" } else { "file" }.to_string(),
                    Some(c.name.clone()),
                    Some(c.started.elapsed().as_secs()),
                    c.writing_to.clone(),
                    c.live,
                ),
                // Reported honestly rather than guessed. A wrong "live" here
                // would be worse than an admission of ignorance: it is the
                // field an agent consults before deciding whether stopping is
                // destructive.
                None => ("unknown".to_string(), None, None, None, false),
            };
            let load = state.load.as_ref().map(|l| {
                let outcome = l.outcome.lock();
                LoadStatus {
                    filename: l.filename.clone(),
                    instance: l.instance.clone(),
                    packets: l.packets.load(std::sync::atomic::Ordering::Relaxed),
                    elapsed_sec: l.started.elapsed().as_secs(),
                    done: l.finished(),
                    error: outcome.as_ref().and_then(|o| o.error.clone()),
                }
            });
            // Read AFTER `finished()`, never before. The loader stores this flag
            // and then releases `done`, so an Acquire read of `done` is what
            // makes the store visible. Sampling it first — which this did — lets
            // one answer pair a fresh `done: true` with a stale
            // `source_exhausted: false`, and a poller that stops on `done` then
            // trusts `source_exhausted` waits for an update that never comes.
            // Reproduced on macOS in CI; the window is real, not a slow test.
            let exhausted = self
                .source_exhausted
                .as_ref()
                .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire));
            let skipped = crate::pipeline::portrange_skip_report();
            let resp = CaptureStatusResponse {
                // 2: absorbed the `stats` tool — the counters and
                // capture_quality it used to return alone now live here.
                schema_version: 2,
                source,
                name,
                uptime_sec,
                dialog_count: ds.len(),
                stream_count: ss.len(),
                orphaned_stream_count: ss.orphaned_count(),
                active_dialog_count: ds.active_dialog_count(),
                active_call_count: ds.active_call_count(),
                capture_quality,
                source_exhausted: exhausted,
                writing_to: writing_to.clone(),
                // Only a live capture can hold packets that exist nowhere else.
                // A file replay is by definition already on disk.
                unsaved: live && writing_to.is_none(),
                capture_identity: state.identity.etag(ds.generation(), ss.generation()),
                unanalysed_sip_messages: skipped.messages,
                unanalysed_busiest_ports: skipped
                    .ports
                    .iter()
                    .take(5)
                    .map(|p| UnanalysedPort {
                        port: p.port,
                        messages: p.messages,
                    })
                    .collect(),
                load,
            };
            drop(ss);
            drop(ds);
            drop(state);
            resp
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Which optional features this binary was built with, and which
    /// server-side opt-ins the operator turned on.
    #[tool(
        name = "server_capabilities",
        description = "Returns the sipnab version, which optional features this \
                       binary was compiled with (tls, hep, plugins, ...), and \
                       which server-side opt-ins are on (--mcp-file-root, \
                       --mcp-allow-shutdown, --mcp-allow-open-capture). Call \
                       this before asking for decryption, HEP, a file export or \
                       a capture swap: a build or a server without them fails \
                       confusingly otherwise.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn server_capabilities(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        // Read from cfg! rather than a hand-kept list, so this cannot claim a
        // feature the binary does not actually have.
        let mut features: Vec<String> = Vec::new();
        for (name, on) in [
            ("native", cfg!(feature = "native")),
            ("tui", cfg!(feature = "tui")),
            ("tls", cfg!(feature = "tls")),
            ("hep", cfg!(feature = "hep")),
            ("api", cfg!(feature = "api")),
            ("mcp", cfg!(feature = "mcp")),
            ("mcp-http", cfg!(feature = "mcp-http")),
            ("metrics", cfg!(feature = "metrics")),
            ("audio", cfg!(feature = "audio")),
            ("plugins", cfg!(feature = "plugins")),
        ] {
            if on {
                features.push(name.to_string());
            }
        }
        features.sort();

        let payload = CapabilitiesResponse {
            schema_version: 1,
            version: env!("CARGO_PKG_VERSION").to_string(),
            can_decrypt: cfg!(feature = "tls"),
            can_hep: cfg!(feature = "hep"),
            can_plugins: cfg!(feature = "plugins"),
            features,
            // What the OPERATOR turned on, which no `cfg!` can answer. Every
            // one of these is off by default, so without them an agent could
            // only discover the setup by calling a tool and being refused —
            // and a refusal mid-investigation reads as a dead end rather than
            // as a server it was never allowed to use that way.
            runtime: RuntimeFlags {
                mcp_file_root: self.file_root.as_ref().map(|d| d.display().to_string()),
                mcp_allow_shutdown: self.allow_shutdown,
                mcp_allow_open_capture: self.allow_open_capture,
                mcp_allow_save_findings: self.allow_save_findings,
            },
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Explain a SIP response code from the IANA registry.
    #[tool(
        name = "explain_response_code",
        description = "Explains a SIP response status code from the IANA \
                       registry: its reason phrase, class (provisional, \
                       success, redirect, challenge, cancelled, declined, \
                       failure) and what it means operationally. Use this \
                       instead of recalling codes from memory.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn explain_response_code(
        &self,
        Parameters(params): Parameters<ExplainCodeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use crate::sip::response_codes::{ResponseClass, explain_response_code, response_class};
        let code = params.code;
        if !(100..700).contains(&code) {
            return Err(rmcp::ErrorData::invalid_params(
                format!("{code} is not a SIP response code (100-699)"),
                None,
            ));
        }
        let class = match response_class(code) {
            ResponseClass::Provisional => "provisional",
            ResponseClass::Success => "success",
            ResponseClass::Redirect => "redirect",
            ResponseClass::Challenge => "challenge",
            ResponseClass::Cancelled => "cancelled",
            ResponseClass::Declined => "declined",
            ResponseClass::Failure => "failure",
        };
        // `registered: false` is deliberate signal, not an omission: a code
        // outside the registry is usually a vendor extension, and saying so is
        // more useful than inventing a meaning for it.
        let payload = serde_json::json!({
            "schema_version": 1,
            "code": code,
            "class": class,
            "explanation": explain_response_code(code),
            "registered": explain_response_code(code).is_some(),
        });
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Compare two dialogs side by side.
    #[tool(
        name = "compare_dialogs",
        description = "Compares two calls side by side — state, outcome code, \
                       duration, message count, methods seen, and their \
                       diagnoses — and lists what differs. Use it for \
                       'why did this call work and that one not?'.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn compare_dialogs(
        &self,
        Parameters(params): Parameters<CompareDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let a = ds.get(&params.call_id_a).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id_a '{}' not found", params.call_id_a),
                    None,
                )
            })?;
            let b = ds.get(&params.call_id_b).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id_b '{}' not found", params.call_id_b),
                    None,
                )
            })?;

            let side = |d: &crate::sip::dialog::SipDialog| {
                let mut methods: Vec<String> = d
                    .messages
                    .iter()
                    .filter(|m| m.is_request)
                    .filter_map(|m| m.method.as_ref().map(|x| x.as_str().to_string()))
                    .collect();
                methods.sort();
                methods.dedup();
                let diag = crate::sip::diagnosis::diagnose_signaling(&d.messages);
                serde_json::json!({
                    "call_id": d.call_id,
                    "state": format!("{:?}", d.state()),
                    "final_status_code": d.final_status_code(),
                    "msg_count": d.messages.len(),
                    "methods": methods,
                    "hints": diag.hints,
                })
            };
            let (ja, jb) = (side(a), side(b));

            // Name the differences rather than leaving the caller to diff two
            // objects. The whole point of the tool is the comparison, and an
            // agent asked to spot it itself will sometimes report a difference
            // that is not there.
            let mut differences = Vec::new();
            for key in ["state", "final_status_code", "msg_count", "methods"] {
                if ja[key] != jb[key] {
                    differences.push(key.to_string());
                }
            }
            serde_json::json!({
                "schema_version": 1,
                "a": ja,
                "b": jb,
                "differences": differences,
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// SDP offer/answer timeline for one dialog.
    #[tool(
        name = "get_sdp_timeline",
        description = "Returns the SDP offer/answer exchanges for a call in \
                       order — codecs, ptime and direction per negotiation, \
                       including re-INVITEs. Use it when audio changed mid-call \
                       or the two ends disagree about the codec.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn get_sdp_timeline(
        &self,
        Parameters(params): Parameters<SdpTimelineParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            // Built here rather than reaching into dialog_to_json, whose
            // output is a whole call report — an agent asking about codec
            // negotiation should not have to receive every message to get it.
            let exchanges: Vec<serde_json::Value> = dialog
                .sdp_timeline
                .iter()
                .map(|ex| {
                    serde_json::json!({
                        "timestamp": ex.timestamp.to_rfc3339(),
                        "direction": match ex.direction {
                            crate::sip::sdp_timeline::OfferAnswer::Offer => "offer",
                            crate::sip::sdp_timeline::OfferAnswer::Answer => "answer",
                        },
                        "codecs": ex.codecs,
                        "media_addr": ex.media_addr,
                        "media_port": ex.media_port,
                        "mode": ex.mode,
                        "event": ex.event.as_ref().map(|e| format!("{e:?}")),
                    })
                })
                .collect();
            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "exchanges": exchanges,
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Dialogs that started inside a time window, optionally filtered.
    #[tool(
        name = "search_by_time",
        description = "Returns dialogs whose first message falls in an RFC 3339 \
                       time window, optionally narrowed by a diagnostic alias or \
                       DSL filter. Use it to scope an investigation to when a \
                       user says the problem happened. The response carries \
                       total_matched and a truncated flag.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn search_by_time(
        &self,
        Parameters(params): Parameters<SearchByTimeParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        use chrono::{DateTime, Utc};
        let parse = |s: &str, which: &str| -> Result<DateTime<Utc>, rmcp::ErrorData> {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    rmcp::ErrorData::invalid_params(
                        format!("{which} '{s}' is not RFC 3339: {e}"),
                        None,
                    )
                })
        };
        let start = parse(&params.start, "start")?;
        let end = match &params.end {
            Some(e) => Some(parse(e, "end")?),
            None => None,
        };
        if let Some(e) = end
            && e <= start
        {
            return Err(rmcp::ErrorData::invalid_params(
                format!("end {e} is not after start {start}"),
                None,
            ));
        }
        let limit = crate::mcp::shape::resolve_limit_with_cap(params.limit, self.row_cap);
        let filter = Self::compile_filter(params.filter.as_deref())?;

        let payload = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture = CaptureMedia::of_store(&ss);
            let mut hits: Vec<serde_json::Value> = ds
                .iter()
                .filter(|d| {
                    let t = d.created_at;
                    t >= start && end.is_none_or(|e| t < e)
                })
                .filter(|d| {
                    // Streams are collected only for the dialogs that survived
                    // the window, which is the cheap test and usually the
                    // selective one.
                    filter.as_ref().is_none_or(|expr| {
                        let streams: Vec<&crate::rtp::stream::RtpStream> =
                            ss.streams_for(&d.call_id).collect();
                        expr.matches_dialog(d, &streams, capture)
                    })
                })
                .map(|d| {
                    serde_json::json!({
                        "call_id": d.call_id,
                        "created_at": d.created_at.to_rfc3339(),
                        "state": format!("{:?}", d.state()),
                        "final_status_code": d.final_status_code(),
                    })
                })
                .collect();
            // Oldest first: an investigation reads forward from when the
            // problem started.
            hits.sort_by(|a, b| a["created_at"].as_str().cmp(&b["created_at"].as_str()));
            let total = hits.len();
            hits.truncate(limit);
            drop(ss);
            drop(ds);
            serde_json::json!({
                "schema_version": 1,
                "dialogs": hits,
                "returned": hits.len(),
                "total_matched": total,
                "truncated": total > limit,
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// First-pass triage: signalling problem, media problem, or neither.
    #[tool(
        name = "triage_call",
        description = "First-pass triage for one call: classifies the problem as \
                       signalling, media, both or none, with the evidence for \
                       each. Start here — the signalling/media split decides \
                       which half of the stack to investigate, and they have \
                       different causes and different fixes.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn triage_call(
        &self,
        Parameters(params): Parameters<CallIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let sig = crate::sip::diagnosis::diagnose_signaling(&dialog.messages);

            let ss = self.stream_store.read();
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&dialog.call_id).collect();
            let ctx = MediaContext::for_dialog(dialog, CaptureMedia::of_store(&ss));
            let mut media = crate::rtp::diagnosis::diagnose_media(&streams, &ctx);
            crate::rtp::diagnosis::diagnose_asymmetry(
                &mut media,
                Some(dialog),
                &streams,
                &crate::rtp::diagnosis::AsymmetryThresholds::default(),
            );

            // The split that matters. Signalling decides whether the call
            // connects; media decides whether you can hear it. They have
            // different causes and different fixes, and conflating them is the
            // most common wrong turn in VoIP triage — so name which half is
            // implicated before saying anything else.
            let sig_bad = !sig.is_empty();
            let media_bad = media.one_way_audio || media.nat_mismatch || media.no_media;
            let verdict = match (sig_bad, media_bad) {
                (true, true) => "both",
                (true, false) => "signalling",
                (false, true) => "media",
                (false, false) => "none",
            };

            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "verdict": verdict,
                "state": format!("{:?}", dialog.state()),
                "final_status_code": dialog.final_status_code(),
                "signalling": {
                    "problem": sig_bad,
                    "hints": sig.hints,
                },
                "media": {
                    "problem": media_bad,
                    "one_way_audio": media.one_way_audio,
                    "nat_mismatch": media.nat_mismatch,
                    "no_media": media.no_media,
                    "stream_count": streams.len(),
                    "hints": media.hints,
                },
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Codec negotiation for one call — what was offered against what was answered.
    #[tool(
        name = "check_codec_negotiation",
        description = "Lists the codecs offered and answered for a call and \
                       whether they intersect. Use it for 488 Not Acceptable \
                       Here, which usually means the far end was offered no \
                       codec it accepts.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn check_codec_negotiation(
        &self,
        Parameters(params): Parameters<CallIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;

            let mut offered: Vec<String> = Vec::new();
            let mut answered: Vec<String> = Vec::new();
            for ex in &dialog.sdp_timeline {
                let bucket = match ex.direction {
                    crate::sip::sdp_timeline::OfferAnswer::Offer => &mut offered,
                    crate::sip::sdp_timeline::OfferAnswer::Answer => &mut answered,
                };
                for c in &ex.codecs {
                    if !bucket.contains(c) {
                        bucket.push(c.clone());
                    }
                }
            }
            // Case-insensitive, because RFC 4855 §1 makes the encoding name
            // case-insensitive and vendors genuinely disagree on spelling: in
            // SIP_CALL_RTP_G711 the offer says PCMA/PCMU and the answer says
            // pcma/pcmu. An exact match reported "no_common_codec" for a call
            // that answered 200 OK and carried real G.711 audio — not an
            // error, but a confident wrong answer sending an operator to
            // reconfigure a codec list that was already working.
            //
            // `offered` and `answered` keep each side's own spelling: that is
            // what was on the wire, and normalising it would destroy the
            // evidence for the mismatch an operator may be chasing. Only the
            // comparison is case-folded, and `common` reports the offer's
            // spelling because the offer is what the answer is matched against.
            let common: Vec<String> = offered
                .iter()
                .filter(|c| answered.iter().any(|a| a.eq_ignore_ascii_case(c)))
                .cloned()
                .collect();

            // Four outcomes, not three. "no SDP at all" is a different
            // finding from "the far end did not answer", and reporting the
            // second for the first sends an operator hunting a reply that was
            // never expected — during an outage that is time spent on a
            // question the capture cannot answer. A call can legitimately
            // carry no SDP (hold with inactive media, a reject before any
            // offer), and the tool has to say so.
            let negotiated = if dialog.sdp_timeline.is_empty() {
                "no_sdp_in_capture"
            } else if offered.is_empty() && answered.is_empty() {
                "sdp_present_but_no_codecs"
            } else if answered.is_empty() {
                "no_answer"
            } else if common.is_empty() {
                "no_common_codec"
            } else {
                "ok"
            };

            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "offered": offered,
                "answered": answered,
                "common": common,
                "result": negotiated,
                "sdp_exchange_count": dialog.sdp_timeline.len(),
                "final_status_code": dialog.final_status_code(),
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Registration health for one endpoint.
    #[tool(
        name = "diagnose_registration",
        description = "Diagnoses REGISTER traffic for a call: whether the \
                       endpoint registered, was rejected, is looping on auth, \
                       or was granted a shorter expiry than it asked for. \
                       Answers 'is this phone online?', which is a different \
                       question from 'why did this call fail?'.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn diagnose_registration(
        &self,
        Parameters(params): Parameters<CallIdParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;

            let is_register = dialog
                .messages
                .iter()
                .any(|m| m.is_request && m.method == Some(crate::sip::method::SipMethod::Register));
            // Say so rather than reporting a healthy registration for a call
            // that contains none.
            if !is_register {
                return Ok(CallToolResult::success(vec![ContentBlock::json(
                    serde_json::json!({
                        "schema_version": 1,
                        "call_id": dialog.call_id,
                        "applicable": false,
                        "reason": "this dialog carries no REGISTER request",
                    }),
                )?]));
            }

            let diag = crate::sip::diagnosis::diagnose_signaling(&dialog.messages);
            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "applicable": true,
                "registration_failure": diag.registration_failure,
                "auth_loop": diag.auth_loop,
                "final_status_code": dialog.final_status_code(),
                "hints": diag.hints,
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Conformance findings for one call, media included.
    ///
    /// # Returns
    ///
    /// The findings exactly as [`crate::sip::lint::Finding`] serialises them —
    /// `rule_id`, `severity`, `basis`, `rfc`, `section`, `message_index`,
    /// `observed`, `expected`, `explanation` — plus severity counts, the
    /// selectors applied, and the rules this run could not settle.
    ///
    /// `rfc` and `section` stay separate fields rather than being folded into
    /// the explanation. A citation an agent can read is a citation it can
    /// check, and the alternative is a plausible-looking section number nobody
    /// can trace.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `call_id`, an unknown ruleset
    /// selector, or an unknown severity name.
    #[tool(
        name = "lint_dialog",
        description = "Checks one call for SIP conformance defects and returns \
                       structured findings. The declaration-versus-observation \
                       rules come first because no other tool can run them: SDP \
                       declaring PCMU on payload type 0 while the wire carries \
                       payload type 8, RTP arriving on a port no m= line \
                       advertised, sendrecv negotiated with media flowing one \
                       way, packet spacing contradicting a=ptime, a payload size \
                       the negotiated codec cannot produce. sipnab holds the \
                       signalling and the RTP in one process, so those \
                       comparisons are available here and are invisible to a \
                       linter that reads message text. The RFC 3261 syntax rules \
                       and the RFC 3264 offer/answer rules run alongside them. \
                       Each finding carries the rule identifier, severity, \
                       basis, and the RFC number and section as separate fields, \
                       with what the capture held beside what the section calls \
                       for. Optional 'rulesets' narrows the run (all, must, rfc, \
                       interop, observation/observed, syntax, or rfc3261, \
                       rfc3264, rfc4566, rfc3551, rfc5761) and 'severity_min' \
                       drops the quieter findings. A .sipnablint beside the \
                       capture, or one named by 'suppression_file', silences \
                       rules by identifier; the response always reports which \
                       file was applied and how many findings it silenced, \
                       alongside counts for the severity floor and the \
                       per-rule cap. The response also names every rule that \
                       had no input to read, so a short list is not mistaken \
                       for a clean call.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn lint_dialog(
        &self,
        Parameters(params): Parameters<LintDialogParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let selectors = parse_rule_selectors(params.rulesets.as_ref())?;
        let min_severity = parse_min_severity(params.severity_min.as_ref())?;
        let suppressions = self.resolve_suppressions(params.suppression_file.as_ref())?;

        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;

            let ss = self.stream_store.read();
            // The projection the linter reads, built from the same
            // `streams_for` view every other per-call tool uses, so a stream
            // this server attributes to the call is a stream the linter sees.
            let media =
                crate::sip::lint::ObservedMedia::from_streams(ss.streams_for(&params.call_id));
            let stream_count = media.streams().len();

            let mut config = crate::sip::lint::LintConfig::new().with_min_severity(min_severity);
            if let Some(file) = &suppressions {
                config = config.with_suppression_file(file);
            }
            let outcome = crate::sip::lint::Linter::new(config)
                .lint_dialog_with_media_detailed(dialog, &media);
            let withheld = outcome.withheld;
            let findings = outcome.findings;
            // Selection runs over the findings rather than over the config,
            // because `LintConfig` holds one ruleset and the argument is a
            // list. Every rule is independent of every other, so filtering
            // afterwards selects the same set a per-ruleset run would.
            let findings: Vec<crate::sip::lint::Finding> = findings
                .into_iter()
                .filter(|f| {
                    selectors.is_empty()
                        || crate::sip::lint::rule_by_id(f.rule_id)
                            .is_some_and(|r| selectors.iter().any(|s| s.contains(r)))
                })
                .collect();

            // An empty list runs the whole catalogue, the same as an omitted
            // one — the convention `security_findings.kinds` already follows.
            // What the response must never do is echo `rulesets: []` beside a
            // full run, which reads as a filter that selected nothing and
            // found nothing anyway.
            let applied: Vec<&str> = params
                .rulesets
                .as_deref()
                .filter(|names| !names.is_empty())
                .map(|names| names.iter().map(String::as_str).collect())
                .unwrap_or_else(|| vec!["all"]);

            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "rulesets": applied,
                "severity_min": min_severity.as_str(),
                "message_count": dialog.messages.len(),
                "rtp_streams_observed": stream_count,
                "finding_count": findings.len(),
                "severity_counts": severity_counts(&findings),
                "findings": findings_with_refs(&findings, &dialog.messages),
                "suppressions": suppression_json(suppressions.as_ref(), withheld),
                "findings_withheld": withheld_json(withheld),
                "rules_not_evaluated": skipped_rules(LintRun::WholeDialog {
                    media: stream_count > 0,
                }),
                "rule_catalogue": "docs/sip-lint-rules.md",
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Conformance findings for one message of a call, read alone.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown `call_id` or an out-of-range
    /// `index`.
    #[tool(
        name = "validate_message",
        description = "Checks one SIP message of a call, named by its zero-based \
                       index, against the message-scoped conformance rules, and \
                       returns findings in the same shape as lint_dialog: rule \
                       identifier, severity, basis, RFC number and section as \
                       separate fields, what the message held and what the \
                       section calls for. Reads that message alone, so the rules \
                       needing a dialog or the observed media do not run; the \
                       response names each of them, and reports any \
                       .sipnablint applied with the counts it silenced.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn validate_message(
        &self,
        Parameters(params): Parameters<ValidateMessageParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let suppressions = self.resolve_suppressions(params.suppression_file.as_ref())?;
        let payload = {
            let ds = self.dialog_store.read();
            let dialog = ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let index = params.index as usize;
            let msg = dialog.messages.get(index).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!(
                        "index {index} out of range for dialog with {} messages",
                        dialog.messages.len()
                    ),
                    None,
                )
            })?;

            let mut config = crate::sip::lint::LintConfig::new();
            if let Some(file) = &suppressions {
                config = config.with_suppression_file(file);
            }
            let outcome = crate::sip::lint::Linter::new(config).lint_message_detailed(msg, index);
            let withheld = outcome.withheld;
            let findings = outcome.findings;

            serde_json::json!({
                "schema_version": 1,
                "call_id": dialog.call_id,
                "message_index": index,
                "message_count": dialog.messages.len(),
                "finding_count": findings.len(),
                "severity_counts": severity_counts(&findings),
                // The same projection `lint_dialog` runs its findings through.
                // A finding cites a message INDEX, which means nothing without
                // the list it counts within; `frame_ref` is what a reviewer
                // can actually follow. Passing the whole message list rather
                // than the one message keeps the index the finding carries
                // meaningful — `findings_with_refs` indexes by it, and a
                // one-element slice would silently re-point every finding at
                // message 0.
                "findings": findings_with_refs(&findings, &dialog.messages),
                "suppressions": suppression_json(suppressions.as_ref(), withheld),
                "findings_withheld": withheld_json(withheld),
                "rules_not_evaluated": skipped_rules(LintRun::OneMessage),
                "rule_catalogue": "docs/sip-lint-rules.md",
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// The catalogue entry behind one rule identifier.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when the identifier is not in the catalogue.
    /// The refusal lists every identifier that is, because the alternative —
    /// an empty answer — reads as "this rule found nothing".
    #[tool(
        name = "explain_rule",
        description = "Returns the catalogue entry behind one conformance rule \
                       identifier, such as OBS-3264-6.1-PT-UNDECLARED: its \
                       title, severity, basis, the RFC number and section it \
                       reads from, a link to that section on rfc-editor.org, \
                       what the rule has to read before it can run, and every \
                       ruleset selector that reaches it. An unknown identifier \
                       returns invalid_params listing the whole catalogue.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn explain_rule(
        &self,
        Parameters(params): Parameters<ExplainRuleParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let rule = crate::sip::lint::rule_by_id(&params.rule_id).ok_or_else(|| {
            let known: Vec<&str> = crate::sip::lint::RULES.iter().map(|r| r.id).collect();
            rmcp::ErrorData::invalid_params(
                format!(
                    "'{}' is not a rule in the catalogue. The {} rules are: {}",
                    params.rule_id,
                    known.len(),
                    known.join(", ")
                ),
                None,
            )
        })?;

        // Every selector that would include this rule, and none that would
        // not, so the field is directly usable as `lint_dialog.rulesets`
        // rather than being a fact about the catalogue the caller has to
        // translate. `rule_selectors_round_trip` holds it to that contract.
        let rulesets: Vec<String> = rule_selector_names()
            .into_iter()
            .filter(|name| RuleSelector::parse(name).is_some_and(|s| s.contains(rule)))
            .collect();

        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "rule_id": rule.id,
                "title": rule.title,
                "severity": rule.severity.as_str(),
                "basis": rule.basis.as_str(),
                "rfc": rule.rfc,
                "section": rule.section,
                "citation": rule.citation(),
                "url": rule.url(),
                "scope": rule.scope().as_str(),
                "rulesets": rulesets,
                "rule_catalogue": "docs/sip-lint-rules.md",
            }),
        )?]))
    }

    /// Follow frame pointers back to the bytes they name.
    ///
    /// This is the half of #128 that makes the other half worth having: until
    /// something could FOLLOW a pointer, it was a string nobody could check,
    /// and a claim carrying it was exactly as verifiable as a claim without
    /// it.
    ///
    /// # Which facts carry a pointer, and which do not
    ///
    /// **Corrected 2026-08-07.** This used to open *"Every query tool emits
    /// `frame_ref` on the facts it returns"*, which was never true of this
    /// surface. It is replaced by the enumeration rather than by a hedge,
    /// because a caller told "every tool" will read a missing pointer as a bug
    /// and a caller told "some tools" cannot plan at all. Two key names, and
    /// they are not interchangeable:
    ///
    /// * **`frame_ref`** — the findings `lint_dialog` returns and — corrected
    ///   2026-08-08 — the findings `validate_message` returns, both via
    ///   `findings_with_refs`. Named apart from `frame` because a finding is
    ///   not the message: it cites a message INDEX, and the pointer is what
    ///   makes it checkable without the list that index counts within.
    ///   `validate_message` used to serialize the same `Vec<Finding>` raw, so
    ///   one tool's finding was checkable and the other tool's identical
    ///   finding was an assertion; `validate_message_findings_cite_their_frame_or_say_nothing`
    ///   holds them together, against a message that really trips a rule.
    /// * **`frame`** — every object projected through `DialogSummary`
    ///   (`list_dialogs`, `find_problems`, `tail_dialogs`, and the `dialog`
    ///   half of `get_dialog`); every SIP message projected through
    ///   `MessageJson` (`get_message`, and the `messages` array of
    ///   `get_dialog`); the dialog body of `get_dialog_report` in `json`
    ///   format; and — new with this change — every stream object, which
    ///   reaches `rtp_stats` in both its per-call and capture-wide modes and
    ///   the `streams` array of `get_dialog_report`.
    ///
    /// Both names carry the same `<source>#<ordinal>@<digest>` text and both
    /// are accepted in `refs`, so the split costs a caller nothing here — it
    /// matters only when reading a response.
    ///
    /// What carries NO pointer, stated so a caller stops looking for one
    /// rather than concluding the capture lost it:
    ///
    /// * The tools that return an index or a Call-ID instead of the thing
    ///   itself: `search_messages`, `search_by_time`, `find_correlated`.
    /// * The derived verdicts, which summarise many packets rather than cite
    ///   one: `triage_call`, `check_codec_negotiation`, `diagnose_registration`,
    ///   `compare_dialogs`, `get_sdp_timeline`.
    /// * The RTCP reception and XR reports filed beside a stream. Those
    ///   describe what a remote endpoint asserted, and `process_rtcp` is
    ///   handed parsed reports without the packet they arrived in.
    /// * Every capture-level counter — `stats`, `capture_status`,
    ///   `capture_health` — which is about the run, not about a frame.
    ///   `stats` and `capture_status` carry `capture_identity` instead.
    ///   `capture_health` carries NEITHER, which is deliberate rather than an
    ///   omission: it reads relaxed atomics and nothing else, so that it can
    ///   run against a live production capture, and taking a store generation
    ///   would mean taking the store locks it exists to avoid. A caller that
    ///   needs to attribute a health reading to a node reads `capture_status`
    ///   alongside it.
    ///
    /// Granularity is whole-frame throughout: `FrameOrigin` is
    /// `{ ordinal, digest }`, so a pointer names a packet and never a byte
    /// range or a header field within it.
    ///
    /// # What a caller can conclude, and what it cannot
    ///
    /// Each entry reports one of three states, and they are deliberately not
    /// collapsible:
    ///
    /// * `verified` — the frame is there and its bytes hash to what the pointer
    ///   recorded. The capture has not moved under the claim.
    /// * `unverified` — the frame is there, the pointer carried no digest, and
    ///   NOTHING WAS CHECKED. The bytes may be from a rotated or rewritten
    ///   capture. Reported separately because folding it into `verified` would
    ///   be the manufactured confidence this whole feature exists to prevent.
    /// * `unresolvable` — no bytes, and `reason` says why. A pointer that
    ///   cannot be followed is a finding, not an omission.
    ///
    /// A run that returns zero resolved frames says so in `resolved`, so "the
    /// evidence did not check out" cannot be mistaken for "there was none".
    ///
    /// # Confinement
    ///
    /// A pointer's `source` is whatever the producing run read — often an
    /// absolute path outside this server's reach. This tool NEVER opens that
    /// path. It takes the final component and resolves it through
    /// `resolve_in_root`, the same guard the file tools use, so the
    /// worst a crafted pointer can do is name a file the operator already
    /// exposed. Without that, a tool taking a caller-supplied path and
    /// returning its bytes is an arbitrary-file-read primitive with a
    /// `readOnlyHint` on it.
    ///
    /// A pointer whose source is a live device or a HEP listener is
    /// `unresolvable` by construction: this architecture holds parsed messages,
    /// not frames, so there is nothing on disk to seek to. It says that rather
    /// than reconstructing something and calling it evidence.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `refs` is empty, when it exceeds 64
    /// entries, or when the file root is not configured. Individual pointers
    /// never fail the call — one bad pointer in a batch must not discard the
    /// good ones.
    #[tool(
        name = "show_evidence",
        description = "Follows frame pointers (the `frame` field on a dialog, \
                       message or stream, or the `frame_ref` field on a \
                       lint_dialog or validate_message finding — both of the \
                       form <source>#<ordinal>@<digest>) \
                       back to the captured bytes, so a claim about a capture \
                       can be checked against the packet it came from. Each \
                       pointer resolves as `verified` (bytes match the digest \
                       recorded when the pointer was made), `unverified` (frame \
                       found, no digest to check it against), or `unresolvable` \
                       with a reason. Sources are confined to --mcp-file-root; \
                       live-capture pointers are unresolvable because no frames \
                       are retained.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn show_evidence(
        &self,
        Parameters(params): Parameters<ShowEvidenceParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        const MAX_REFS: usize = 64;
        const MAX_HEX_BYTES: usize = 4096;
        const DEFAULT_HEX_BYTES: usize = 256;

        if params.refs.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "refs must name at least one frame pointer; an empty batch \
                 would return an empty result that reads like 'nothing \
                 resolved'"
                    .to_string(),
                None,
            ));
        }
        if params.refs.len() > MAX_REFS {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "{} pointers exceeds the {MAX_REFS} per call; split the \
                     batch rather than receiving a silently truncated answer",
                    params.refs.len()
                ),
                None,
            ));
        }
        let hex_bytes = params
            .max_bytes
            .unwrap_or(DEFAULT_HEX_BYTES)
            .min(MAX_HEX_BYTES);

        let mut entries = Vec::with_capacity(params.refs.len());
        let mut resolved = 0usize;
        let mut verified = 0usize;

        for text in &params.refs {
            let entry = match crate::capture::resolve::parse_pointer(text) {
                Err(e) => serde_json::json!({
                    "pointer": text,
                    "status": "unresolvable",
                    "reason": e.to_string(),
                }),
                Ok(pointer) => {
                    // The source names a file only for replay. Anything else —
                    // a device, a HEP listener — has no bytes on disk, and
                    // saying so beats returning a reconstruction.
                    let leaf = std::path::Path::new(pointer.source.as_ref())
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned());
                    match leaf {
                        None => serde_json::json!({
                            "pointer": text,
                            "status": "unresolvable",
                            "reason": format!(
                                "'{}' does not name a capture file. Pointers \
                                 from live capture or a HEP listener cannot be \
                                 followed: sipnab retains parsed messages, not \
                                 frames, so there is nothing to seek to.",
                                pointer.source
                            ),
                        }),
                        Some(name) => match self.resolve_in_root(&name) {
                            Err(e) => serde_json::json!({
                                "pointer": text,
                                "status": "unresolvable",
                                "reason": format!(
                                    "source '{}' is not reachable from the \
                                     configured file root: {}",
                                    pointer.source, e.message
                                ),
                            }),
                            Ok(path) => {
                                // Resolve against the CONFINED path, never the
                                // one the pointer carried.
                                let confined = crate::capture::packet::FrameRef {
                                    source: path.display().to_string().into(),
                                    origin: pointer.origin,
                                };
                                match crate::capture::resolve::resolve(&confined) {
                                    Err(e) => serde_json::json!({
                                        "pointer": text,
                                        "status": "unresolvable",
                                        "reason": e.to_string(),
                                    }),
                                    Ok(res) => {
                                        resolved += 1;
                                        if res.is_verified() {
                                            verified += 1;
                                        }
                                        let bytes = res.bytes();
                                        let shown = bytes.len().min(hex_bytes);
                                        serde_json::json!({
                                            "pointer": text,
                                            "status": if res.is_verified() {
                                                "verified"
                                            } else {
                                                "unverified"
                                            },
                                            "source": name,
                                            "ordinal": pointer.origin.ordinal,
                                            "frame_bytes": bytes.len(),
                                            "hex_bytes_shown": shown,
                                            "truncated": shown < bytes.len(),
                                            "hex": bytes[..shown]
                                                .iter()
                                                .map(|b| format!("{b:02x}"))
                                                .collect::<Vec<_>>()
                                                .join(" "),
                                        })
                                    }
                                }
                            }
                        },
                    }
                }
            };
            entries.push(entry);
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "requested": params.refs.len(),
                "resolved": resolved,
                "verified": verified,
                // Spelled out because `resolved: 0` and a short `frames` list
                // otherwise read as "the capture held nothing", which is a
                // different claim from "none of these pointers could be
                // followed".
                "summary": format!(
                    "{resolved} of {} pointer(s) resolved; {verified} verified \
                     against a recorded digest",
                    params.refs.len()
                ),
                "frames": entries,
            }),
        )?]))
    }

    /// List capture files in the configured root.
    #[tool(
        name = "list_captures",
        description = "Lists capture files (.pcap/.pcapng) in the server's \
                       configured file root, with sizes. Requires \
                       --mcp-file-root.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn list_captures(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let root = self.file_root.as_ref().ok_or_else(|| {
            rmcp::ErrorData::invalid_params(
                "file tools are disabled: start sipnab with --mcp-file-root <DIR>".to_string(),
                None,
            )
        })?;
        let mut files: Vec<serde_json::Value> = Vec::new();
        let entries = std::fs::read_dir(root).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("cannot read {}: {e}", root.display()), None)
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            let is_capture = path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                e.eq_ignore_ascii_case("pcap") || e.eq_ignore_ascii_case("pcapng")
            });
            // Files only: a directory here would tempt a caller into a path.
            if !is_capture || !path.is_file() {
                continue;
            }
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            files.push(serde_json::json!({
                "filename": path.file_name().and_then(|n| n.to_str()).unwrap_or_default(),
                "bytes": size,
            }));
        }
        files.sort_by(|a, b| a["filename"].as_str().cmp(&b["filename"].as_str()));
        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({ "schema_version": 1, "captures": files }),
        )?]))
    }

    /// Write the retained packets to a capture file.
    #[tool(
        name = "export_capture",
        description = "Writes the SIP signalling sipnab is holding to a pcap file \
                       in the configured file root and returns the path. The \
                       file is NOT a copy of the capture: sipnab keeps parsed \
                       messages rather than the original frames, so each message \
                       is written as a re-synthesised Ethernet/IP/UDP frame with \
                       reconstructed link and IP headers. It contains no RTP, no \
                       RTCP and no non-SIP traffic, and a SIP-over-TCP message \
                       is written as UDP. Use it to preserve signalling before \
                       stopping a live capture — otherwise the messages end with \
                       the process.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn export_capture(
        &self,
        Parameters(params): Parameters<ExportCaptureParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let path = self.resolve_in_root(&params.filename)?;
        let messages: Vec<crate::sip::SipMessage> = {
            let ds = self.dialog_store.read();
            ds.iter().flat_map(|d| d.messages.iter().cloned()).collect()
        };
        if messages.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "nothing to export: no messages are held".to_string(),
                None,
            ));
        }
        let count = messages.len();
        write_messages_to_pcap(&messages, &path).map_err(|e| {
            rmcp::ErrorData::internal_error(format!("writing {}: {e}", path.display()), None)
        })?;
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        tracing::info!(
            "MCP export_capture wrote {count} messages to {}",
            path.display()
        );
        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "path": path.display().to_string(),
                "messages": count,
                "bytes": bytes,
            }),
        )?]))
    }

    /// Export one call's audio as a WAV file.
    #[tool(
        name = "export_audio",
        description = "Exports a call's RTP audio to a WAV file in the \
                       configured file root. Fails when the call has no \
                       decodable audio.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn export_audio(
        &self,
        Parameters(params): Parameters<ExportAudioParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let path = self.resolve_in_root(&params.filename)?;
        let summary = {
            let ds = self.dialog_store.read();
            ds.get(&params.call_id).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("call_id '{}' not found", params.call_id),
                    None,
                )
            })?;
            let ss = self.stream_store.read();
            let streams: Vec<&crate::rtp::stream::RtpStream> =
                ss.streams_for(&params.call_id).collect();
            if streams.is_empty() {
                return Err(rmcp::ErrorData::invalid_params(
                    format!("call '{}' has no RTP streams to export", params.call_id),
                    None,
                ));
            }
            crate::rtp::audio_export::export_dialog_to_wav(&streams, &path).map_err(|e| {
                rmcp::ErrorData::internal_error(format!("writing {}: {e}", path.display()), None)
            })?
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "path": path.display().to_string(),
                "summary": summary,
            }),
        )?]))
    }

    /// Replace the loaded capture with another file from the file root.
    /// Opt-in, refused against a live or still-loading source, and the read
    /// itself runs on a background thread.
    ///
    /// # Returns
    ///
    /// The new capture identity and the path being read, as soon as the load
    /// thread starts. The dialogs arrive over the following seconds; poll
    /// `capture_status` for `load.done`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when the server did not opt in, when the
    /// filename is not a bare name inside `--mcp-file-root`, when the current
    /// source is a live interface or has not finished reading, or when a load
    /// is already running.
    ///
    /// `internal_error` (-32603) when the load thread cannot be spawned. The
    /// stores are untouched in that case — the swap happens only once the
    /// thread is running.
    #[tool(
        name = "open_capture",
        description = "Loads a different capture file from --mcp-file-root, \
                       REPLACING every dialog and stream this server holds. \
                       Requires --mcp-allow-open-capture. Takes a bare \
                       filename, never a path. Refused while the current \
                       source is a live interface or is still being read. \
                       Returns as soon as the background load starts, with the \
                       new capture_identity; poll capture_status until \
                       load.done is true. Answers from the previous capture \
                       carry a different capture_identity and cannot be mixed \
                       with answers from this one.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn open_capture(
        &self,
        Parameters(params): Parameters<OpenCaptureParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !self.allow_open_capture {
            return Err(rmcp::ErrorData::invalid_params(
                "opening a capture is disabled: start sipnab with \
                 --mcp-allow-open-capture to permit it. A stock server holds \
                 the capture it was started on."
                    .to_string(),
                None,
            ));
        }
        // The same resolver every file tool uses, unchanged: one bare
        // component, then a symlink-resolved re-check against the root. A
        // capture that is part of THIS run's `-I` set is refused by it too —
        // the message says "would overwrite", because the resolver is the
        // output guard, and the outcome is right for a different reason: that
        // file is already loaded, and re-reading it under a new identity would
        // duplicate what the store holds.
        let path = self.resolve_in_root(&params.filename)?;

        // A live capture's writer never finishes, so a second writer against
        // the same stores would race it for as long as the process runs. This
        // is the one refusal with no opt-out.
        let exhausted = self
            .source_exhausted
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed));

        // One critical section for the whole swap: check, rotate, clear,
        // spawn. Two agents calling this at once must not both get past the
        // in-flight check, and no reader may see a cleared store still
        // wearing the previous capture's identity.
        let (identity, previous_dialogs) = {
            let mut state = self.capture.write();
            if let Some(c) = &state.context
                && c.live
            {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "refusing to open '{}': this server is capturing live from '{}'. \
                         The capture thread never finishes, so loading a file would leave \
                         two writers on one store. Restart sipnab with -I to analyse files.",
                        params.filename, c.name
                    ),
                    None,
                ));
            }
            // The in-flight check comes FIRST of the two, because a running
            // load also holds `source_exhausted` false: testing exhaustion
            // first answered "the current source has not finished reading" to
            // an agent whose own previous call is the thing still reading, and
            // sent it to poll a field that describes the wrong subject.
            if let Some(load) = &state.load
                && !load.finished()
            {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "refusing to open '{}': '{}' is still loading ({} packets so far). \
                         Poll capture_status until load.done is true.",
                        params.filename,
                        load.filename,
                        load.packets.load(std::sync::atomic::Ordering::Relaxed)
                    ),
                    None,
                ));
            }
            if !exhausted {
                return Err(rmcp::ErrorData::invalid_params(
                    format!(
                        "refusing to open '{}': the current source has not finished \
                         reading. Poll capture_status until source_exhausted is true, \
                         then call again.",
                        params.filename
                    ),
                    None,
                ));
            }

            let previous_dialogs = self.dialog_store.read().len();
            // Rotate BEFORE the stores are touched. Every answer from here on
            // names the new capture, including one that catches the stores
            // half-filled — which is true and useful, where the old id would
            // have been a lie about data that is already gone.
            let instance = state.identity.rotate().to_string();
            let identity = {
                let mut ds = self.dialog_store.write();
                ds.clear();
                let dialog_generation = ds.generation();
                drop(ds);
                let mut ss = self.stream_store.write();
                ss.clear();
                let stream_generation = ss.generation();
                drop(ss);
                state.identity.etag(dialog_generation, stream_generation)
            };

            let load = super::load::spawn(
                path.clone(),
                &params.filename,
                &instance,
                Arc::clone(&self.dialog_store),
                Arc::clone(&self.stream_store),
                self.source_exhausted.clone(),
            )
            .map_err(|e| {
                rmcp::ErrorData::internal_error(format!("cannot start the load thread: {e}"), None)
            })?;

            // The description follows the data. `writing_to` is deliberately
            // dropped: any `-O` on the command line belongs to the source this
            // run started with, and the packets read here are not written
            // there.
            state.context = Some(CaptureContext {
                live: false,
                name: path.display().to_string(),
                started: std::time::Instant::now(),
                writing_to: None,
            });
            state.load = Some(load);
            drop(state);
            (identity, previous_dialogs)
        };

        tracing::warn!(
            "MCP open_capture: replacing the capture ({previous_dialogs} dialogs discarded) \
             with '{}' as instance {}",
            path.display(),
            identity.instance
        );

        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "status": "loading",
                "filename": params.filename,
                "path": path.display().to_string(),
                "capture_identity": identity,
                "discarded_dialogs": previous_dialogs,
                "note": "the previous capture is gone; poll capture_status until \
                         load.done is true, and treat every answer carrying a \
                         different capture_identity.instance as a different capture",
            }),
        )?]))
    }

    /// Find the other legs of this call, and say how each was matched.
    ///
    /// The engine behind it has existed in `DialogStore` since long before this
    /// tool; nothing on the MCP surface could reach it, so every agent asking
    /// "where did this call go next" got no answer to a question the library
    /// could already compute.
    #[tool(
        name = "find_correlated",
        description = "Finds other dialogs belonging to the same call — the far \
                       legs of a B2BUA, SBC or PBX hop. Returns each with a \
                       score AND the strategy that matched it. Read the \
                       strategy, not just the score: every strategy except \
                       timing_heuristic is an identifier match, and \
                       timing_heuristic is a guess from endpoint overlap and \
                       elapsed time on which a busy server routinely puts \
                       unrelated calls. charging_vector_related_icid crosses a \
                       B2BUA; charging_vector_icid does NOT, because an RFC \
                       7315 ICID identifies one dialog and a B2BUA is two.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn find_correlated(
        &self,
        Parameters(params): Parameters<FindCorrelatedParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit_with_cap(params.limit, self.row_cap);

        // Lock discipline: capture first, then the stores, copy out, drop.
        let payload = {
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let capture_identity = state.identity.etag(ds.generation(), ss.generation());
            drop(ss);

            let source_created = ds.get(&params.call_id).map(|d| d.created_at);
            let results = ds.find_correlated_scored(&params.call_id);
            let total_matched = results.len();

            let legs: Vec<CorrelatedLeg> = results
                .iter()
                .take(limit)
                .map(|r| {
                    use crate::sip::dialog_store::CorrelationReason as R;
                    let (strategy, identifier_match) = match r.reason {
                        R::SessionId => ("session_id", true),
                        R::XCallId => ("x_call_id", true),
                        // An identifier comparison, so `true` — but of the
                        // MEDIA SESSION rather than the dialog. It is the whole
                        // RFC 8866 uniqueness tuple, never `sess-id` alone.
                        R::SdpOrigin => ("sdp_origin", true),
                        // Both charging-vector strategies compare identifiers,
                        // so both are `true` — and they are two names rather
                        // than one because they are two claims. RFC 7315's
                        // `related-icid` is an intermediary DECLARING the link
                        // across a B2BUA; plain `icid-value` equality is an
                        // intermediary having copied a per-dialog identifier
                        // onto a second dialog, which no RFC grants.
                        //
                        // Neither value leaves the server. RFC 7315 §4.6's own
                        // suggested construction embeds the generating proxy's
                        // hostname or address in the icid, so it is treated as
                        // operator-internal, not as an opaque token.
                        R::ChargingVectorRelatedIcid => ("charging_vector_related_icid", true),
                        R::ChargingVectorIcid => ("charging_vector_icid", true),
                        R::ViaBranch => ("via_branch", true),
                        R::TimingHeuristic => ("timing_heuristic", false),
                        // NO CATCH-ALL, deliberately. `CorrelationReason` is
                        // `#[non_exhaustive]` for external crates, but this
                        // match lives in the defining crate, so it is checked
                        // exhaustively: a new strategy is a COMPILE ERROR here
                        // rather than something that quietly reports as
                        // "unknown, not an identifier". Whoever adds the next
                        // strategy has to decide, in this file, whether it is
                        // an identifier match — which is exactly the decision
                        // that must not be made by default.
                    };
                    // The gap is the evidence for the guess, so it is attached
                    // only where it IS the evidence. On an identifier match it
                    // would be a number with no bearing on why they matched.
                    let observed_gap_ms = (!identifier_match)
                        .then(|| {
                            source_created
                                .map(|src| (r.dialog.created_at - src).num_milliseconds().abs())
                        })
                        .flatten();
                    CorrelatedLeg {
                        call_id: r.dialog.call_id.clone(),
                        score: r.score,
                        strategy: strategy.to_string(),
                        identifier_match,
                        observed_gap_ms,
                    }
                })
                .collect();
            drop(ds);
            drop(state);

            let heuristic_only = !legs.is_empty() && legs.iter().all(|l| !l.identifier_match);
            // Only when a time-based match is actually being reported. Sending
            // the clock unconditionally would invite a reader to weigh it
            // against identifier matches, which do not depend on it at all.
            let timing_clock = legs
                .iter()
                .any(|l| !l.identifier_match)
                .then(crate::clock::discipline);
            FindCorrelatedResponse {
                schema_version: 1,
                source_call_id: params.call_id.clone(),
                legs,
                total_matched,
                heuristic_only,
                capture_identity,
                timing_clock,
            }
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Record what the agent concluded, as a log line and nothing else.
    ///
    /// The only write verb on sipnab's network surface. It is safe not because
    /// the text is trustworthy — it is quoted from a wire an attacker may be
    /// on — but because the write reaches nothing: no store, no detector, no
    /// other tool, and no later answer. The types that hold it are private to
    /// this module tree, so no analysis path can name them — the dead end is a
    /// visibility guarantee the compiler checks, not a convention.
    #[tool(
        name = "save_findings",
        description = "Records a one-line conclusion about this capture. WRITE. \
                       Requires --mcp-allow-save-findings on the server. The \
                       annotation is appended to sipnab's log for a human to \
                       read; it is not readable through any tool, does not \
                       appear in any query result, and no analysis consumes it, \
                       so it cannot affect a later answer.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    pub async fn save_findings(
        &self,
        Parameters(params): Parameters<SaveFindingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !self.allow_save_findings {
            return Err(rmcp::ErrorData::invalid_params(
                "saving findings is disabled: start sipnab with \
                 --mcp-allow-save-findings to permit it. A stock server accepts \
                 no writes at all."
                    .to_string(),
                None,
            ));
        }
        // An empty summary is the one input worth refusing. Everything else is
        // the agent's to phrase, but a blank annotation is a log line that says
        // nothing while claiming a sequence number.
        if params.summary.trim().is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                "summary must not be empty: a finding with no text records \
                 nothing but occupies a sequence number."
                    .to_string(),
                None,
            ));
        }

        // Lock discipline, per the module doc: take the guards, copy what is
        // needed, drop them, and only then touch anything that can await.
        let (capture_identity, written_at) = {
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let etag = state.identity.etag(ds.generation(), ss.generation());
            drop(ss);
            drop(ds);
            drop(state);
            (etag, chrono::Utc::now())
        };

        let recorded = {
            let mut log = self.findings.write();
            log.record(
                written_at,
                params.call_id.as_deref(),
                &params.summary,
                params.detail.as_deref(),
                &capture_identity.instance,
                capture_identity.dialog_generation,
                capture_identity.stream_generation,
            )
        };
        // Refused, not silently dropped: an agent told "recorded" about a
        // finding this process threw away is worse off than one told plainly
        // that it was not.
        let Some(recorded) = recorded else {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "this process has already recorded its limit of {} findings \
                     and will accept no more. Nothing was written. Restart \
                     sipnab to reset the count; the findings already recorded \
                     are in the log.",
                    crate::mcp::findings::MAX_FINDINGS_PER_PROCESS
                ),
                None,
            ));
        };

        let payload = SaveFindingsResponse {
            schema_version: 1,
            seq: recorded.seq,
            written_at: written_at.to_rfc3339(),
            summary_chars_submitted: recorded.summary_chars_submitted,
            detail_chars_submitted: recorded.detail_chars_submitted,
            truncated: recorded.truncated,
            recorded_total: recorded.recorded_total,
            remaining: recorded.remaining,
            // Both of these are constants, and they are in the response on
            // purpose: an agent that writes and then looks for a way to read it
            // back should find the answer in the reply rather than by trying
            // every tool.
            readable_over_mcp: false,
            delivered_to: "sipnab log (tracing/journald/stderr)".to_string(),
            capture_identity,
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Stop this sipnab process. Opt-in, dry-run by default.
    #[tool(
        name = "shutdown_server",
        description = "Stops this sipnab process. DESTRUCTIVE. Requires \
                       --mcp-allow-shutdown on the server. Defaults to a DRY \
                       RUN that only reports what would happen; pass \
                       dry_run=false to actually stop. Refuses to discard an \
                       unsaved live capture unless save_to is given or \
                       discard_unsaved=true.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    pub async fn shutdown_server(
        &self,
        Parameters(params): Parameters<ShutdownParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if !self.allow_shutdown {
            return Err(rmcp::ErrorData::invalid_params(
                "shutdown is disabled: start sipnab with --mcp-allow-shutdown to \
                 permit it. A stock server cannot be stopped by an agent."
                    .to_string(),
                None,
            ));
        }
        // Dry run unless the caller explicitly says otherwise. The default has
        // to be the safe one: an agent that omits the argument gets a report,
        // not a stopped capture.
        let dry_run = params.dry_run.unwrap_or(true);

        let (live, writing_to) = {
            let state = self.capture.read();
            let pair = match &state.context {
                Some(c) => (c.live, c.writing_to.clone()),
                None => (false, None),
            };
            drop(state);
            pair
        };
        let unsaved = live && writing_to.is_none();
        let (dialogs, streams) = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            (ds.len(), ss.len())
        };

        let mut saved_to = None;
        if let Some(name) = &params.save_to {
            let path = self.resolve_in_root(name)?;
            if !dry_run {
                let messages: Vec<crate::sip::SipMessage> = {
                    let ds = self.dialog_store.read();
                    ds.iter().flat_map(|d| d.messages.iter().cloned()).collect()
                };
                write_messages_to_pcap(&messages, &path).map_err(|e| {
                    rmcp::ErrorData::internal_error(format!("save failed, NOT stopping: {e}"), None)
                })?;
            }
            saved_to = Some(path.display().to_string());
        }

        // Losing a live capture to a misread sentence is the failure that
        // matters, so the destructive path must be named rather than defaulted
        // into.
        if !dry_run && unsaved && saved_to.is_none() && !params.discard_unsaved.unwrap_or(false) {
            return Err(rmcp::ErrorData::invalid_params(
                format!(
                    "refusing to stop: this is a LIVE capture holding {dialogs} dialogs \
                     that are not written anywhere. Pass save_to=\"<filename>\" to keep \
                     them, or discard_unsaved=true to accept losing them."
                ),
                None,
            ));
        }

        if !dry_run {
            tracing::warn!(
                "MCP shutdown_server: stopping (dialogs={dialogs}, streams={streams}, \
                 unsaved={unsaved}, saved_to={saved_to:?})"
            );
            // The same path SIGTERM takes. Reusing it means the shutdown is
            // the graceful one the process already knows how to perform —
            // writers flushed, files closed — rather than a second mechanism
            // that has to relearn all of that.
            crate::signals::request_shutdown();
        }

        Ok(CallToolResult::success(vec![ContentBlock::json(
            serde_json::json!({
                "schema_version": 1,
                "dry_run": dry_run,
                "would_stop": !dry_run,
                "live": live,
                "unsaved": unsaved,
                "dialogs": dialogs,
                "streams": streams,
                "saved_to": saved_to,
                "note": if dry_run {
                    "dry run — nothing stopped. Call again with dry_run=false to stop."
                } else {
                    "shutdown requested"
                },
            }),
        )?]))
    }

    /// Capture-path counters sampled twice, with the totals and the deltas.
    ///
    /// # Why this samples rather than captures
    ///
    /// The tool does **not** start a capture. When sipnab runs with `--mcp`
    /// attached to a live interface, the counters are already accumulating,
    /// so a rate is two reads and a wait. That is not merely the cheap
    /// implementation, it is the safe one: there is no capture to open, no
    /// device to name, no file to write, and therefore no path from this
    /// handler to a transmitting flag or to a byte of anybody's traffic. An
    /// implementation that spawned its own capture to measure one would have
    /// all of those.
    ///
    /// # Why the response is numbers only
    ///
    /// This runs on production servers carrying other people's calls. See the
    /// section comment above [`MAX_SAMPLE_SECONDS`]: the response type has no
    /// `String` in it or in anything nested in it, so it cannot represent
    /// packet content at all.
    #[tool(
        name = "capture_health",
        description = "Returns capture-path counters read twice, once at the \
                       call and once after the sampling window: packets, \
                       kernel drops, interface drops, invalid timestamps and \
                       undecodable frames, as run totals and as deltas across \
                       the window, plus the undecoded fraction, the \
                       per-reason breakdown of frames no decoder here could \
                       read with the DLT, EtherType or IP protocol each one \
                       carries, the dialogs and streams held, and whether a \
                       live capture, a file replay or nothing at all is \
                       attached. Starts no capture. Every value is a number: \
                       the response type carries no text from any packet. \
                       sample_seconds is clamped to 30 and zero is refused.",
        annotations(read_only_hint = true, open_world_hint = false)
    )]
    pub async fn capture_health(
        &self,
        Parameters(params): Parameters<CaptureHealthParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let applied_seconds = resolve_sample_seconds(params.sample_seconds)?;

        // Read the attachment before the wait, from the same lock discipline
        // every other handler uses: take the guard, copy what is needed, drop
        // it. Nothing here may be held across the sleep below.
        let attachment = {
            let state = self.capture.read();
            let attachment = attachment_of(state.context.as_ref());
            drop(state);
            attachment
        };

        let before = HealthSample::read();
        let started = std::time::Instant::now();
        tokio::time::sleep(std::time::Duration::from_secs(u64::from(applied_seconds))).await;
        // What the clock says, not what was asked for. A runtime under load
        // wakes the handler late, and a rate divided by the requested window
        // is then wrong by the difference.
        let observed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let after = HealthSample::read();

        let (dialogs_tracked, streams_tracked) = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let counts = (ds.len(), ss.len());
            drop(ss);
            drop(ds);
            counts
        };

        let payload = build_health(
            attachment,
            CaptureHealthWindow {
                requested_seconds: params.sample_seconds,
                applied_seconds,
                observed_ms,
            },
            &before,
            &after,
            dialogs_tracked,
            streams_tracked,
        );
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }
}

/// Attribute a tool call to its transport identity, for the audit line.
///
/// Over HTTP the rmcp service folds the request's `http::request::Parts` into
/// the per-call extensions; the socket address rides in there via axum's
/// `ConnectInfo`, and the auth middleware stamps how the request was admitted
/// ([`super::transport::McpAuth`]). Over stdio there are no parts — the caller
/// is whoever owns the other end of the pipe, and "stdio" names that boundary
/// honestly rather than inventing an identity the transport cannot prove.
///
/// A verified token is named by its `id`, so the record answers WHICH
/// credential and not merely that one verified — see [`audit_token_id`] for
/// what is recorded and why. A credential with no id (a static shared secret)
/// gets NO `token=` key at all: an empty or placeholder value would be
/// indistinguishable from a real id, and would put credentials that never had
/// one into a `token=` search.
///
/// The `no-admission-record` arm should be unreachable — the auth layer stamps
/// every request it admits — but if a future transport skips the middleware,
/// an audit line that SAYS the record is missing beats one that quietly
/// reports the call as local.
#[cfg(feature = "mcp-http")]
fn caller_of(extensions: &rmcp::model::Extensions) -> String {
    use crate::mcp::transport::McpAuth;
    match extensions.get::<axum::http::request::Parts>() {
        Some(parts) => {
            let addr = parts
                .extensions
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.to_string())
                .unwrap_or_else(|| "unknown-peer".to_string());
            match parts.extensions.get::<McpAuth>() {
                Some(McpAuth::BearerVerified { scope, token_id }) => {
                    let named = match token_id {
                        Some(id) => format!(" token={}", audit_token_id(id)),
                        None => String::new(),
                    };
                    format!("{addr} bearer-verified scope={scope}{named}")
                }
                Some(McpAuth::Unauthenticated) => format!("{addr} unauthenticated"),
                None => format!("{addr} no-admission-record"),
            }
        }
        None => "stdio".to_string(),
    }
}

/// Render a verified token's id for the audit line's `token=` field.
///
/// # What is recorded, and why it is the id itself
///
/// The id verbatim, escaped and bounded — not a digest and not a prefix. The
/// point of naming the token is that somebody can act on the name: the id is
/// the same string the operator passed to `--token-id` and the same string a
/// revocation denylist matches on, so an audit line carrying it goes straight
/// to "revoke that credential". A digest would break that hop for no gain,
/// because token ids are low-entropy operator-chosen labels (`ci-runner-1`,
/// `prom-scraper`) that a wordlist reverses in seconds — it would cost
/// legibility and buy no secrecy. The id is also not a secret to begin with:
/// the credential is `s2.<payload>.<signature>`, and the id alone reconstructs
/// none of it without the HMAC signing key. What the audit line must never
/// carry is the presented token or its signature, and neither is in scope
/// here — the `Authorization` header never reaches this code.
///
/// # Why it is encoded and bounded anyway
///
/// The id arrives from a signed payload, which makes it operator-chosen while
/// the keys are intact — and an audit log is what gets read when they are not.
/// Anyone holding a signing key chooses ids, and the audit line is flat text:
/// the caller is written as `caller="…"` and its neighbours are
/// space-separated `key=value`. So an id of `x" outcome=ok` closes the quoted
/// field, an id of `x outcome=ok` does not even need to — every reader in this
/// repo greps these lines, and a substring search cannot tell a forged
/// `outcome=ok` from the real one. A newline forges a whole line.
///
/// Percent-encoding is what closes all three at once: everything outside a
/// conservative unreserved set becomes `%XX`, so the rendered id is a single
/// run of characters with no space, quote, backslash, `=` or control byte in
/// it, and it is still reversible — an operator percent-decodes to get the
/// exact id back. Ordinary ids are entirely inside the safe set and render
/// verbatim, so the encoding is invisible on every real line.
///
/// The cap bounds the field: the token format puts no length on `id`, and the
/// audit record is one line per call. It is applied BEFORE encoding, so the
/// cut can never land inside a `%XX` triple and leave a half-escape behind.
/// Shortening is marked, so a reader cannot take a prefix for a whole id and
/// then fail to find it in the issuance record.
#[cfg(feature = "mcp-http")]
fn audit_token_id(id: &str) -> String {
    /// Characters of the id kept before encoding. Comfortably longer than
    /// anything sipnab mints (an auto-derived `tok-<micros>` is 24 and a UUID
    /// is 36) so the real cases render whole, and short enough that the caller
    /// field cannot dominate the line.
    const CAP: usize = 64;
    /// Uppercase hex digits for the `%XX` escapes.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    /// Bytes recorded as themselves: RFC 3986 unreserved plus the few
    /// punctuation marks real token ids carry. None of them can end the quoted
    /// caller field, separate a field, or start a line.
    fn is_safe(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':' | b'@' | b'+')
    }

    // Cut by characters, not bytes: a byte cut could split a UTF-8 sequence.
    let kept: String = id.chars().take(CAP).collect();
    let mut out = String::with_capacity(kept.len());
    for b in kept.bytes() {
        if is_safe(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
    }
    if id.chars().count() > CAP {
        // No space in the marker — it would forge a field of its own. Nothing
        // the encoder emits can produce this sequence, so it cannot be
        // mistaken for part of an id.
        out.push_str("…(truncated)");
    }
    out
}

/// Without the HTTP transport compiled in, stdio is the only way a call can
/// arrive.
#[cfg(not(feature = "mcp-http"))]
fn caller_of(_extensions: &rmcp::model::Extensions) -> String {
    "stdio".to_string()
}

/// The peer a call is rate-limited against.
///
/// Derived from the same HTTP `Parts` `caller_of` reads, but deliberately
/// narrower: the audit line wants everything the transport knows (address,
/// port, admission record), while the limiter wants the one field that
/// identifies the *sender across calls*. Scope and token identity are not it —
/// a token is a credential, and rate limiting a credential rather than an
/// address would let one flooding host hide behind a handful of tokens.
#[cfg(feature = "mcp-http")]
fn peer_key_of(extensions: &rmcp::model::Extensions) -> PeerKey {
    let parts = extensions.get::<axum::http::request::Parts>()?;
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Without the HTTP transport compiled in, every call arrives on stdio, which
/// is one peer with no address.
#[cfg(not(feature = "mcp-http"))]
fn peer_key_of(_extensions: &rmcp::model::Extensions) -> PeerKey {
    None
}

/// The scope the caller's admission record grants, for the per-tool check in
/// `call_tool`.
///
/// - Stdio (no HTTP `Parts` in the extensions) is FULL: whoever spawned the
///   process owns its stdin, and process ownership is the boundary there —
///   a scope claim would restrict the very operator who configured the server.
/// - HTTP with a verified bearer token carries the token's scope claim.
/// - HTTP admitted without credentials (loopback, no verifier configured) is
///   FULL: the boundary there is network position, and narrowing it would
///   break every existing loopback deployment.
/// - HTTP with NO admission record should be unreachable (the auth layer
///   stamps every request it admits). It is treated as full rather than
///   refused because refusing would turn a middleware-wiring bug into a
///   total outage with no scope involved at all — and the same missing
///   record is already called out by `caller_of` as `no-admission-record`
///   on the audit line, which is the alarm that matters.
#[cfg(feature = "mcp-http")]
fn scope_of(extensions: &rmcp::model::Extensions) -> String {
    use crate::mcp::transport::McpAuth;
    match extensions.get::<axum::http::request::Parts>() {
        Some(parts) => match parts.extensions.get::<McpAuth>() {
            Some(McpAuth::BearerVerified { scope, .. }) => scope.clone(),
            Some(McpAuth::Unauthenticated) | None => crate::auth::SCOPE_FULL.to_string(),
        },
        None => crate::auth::SCOPE_FULL.to_string(),
    }
}

/// Without the HTTP transport compiled in, every call is stdio and stdio is
/// full-scope: process ownership is the boundary.
#[cfg(not(feature = "mcp-http"))]
fn scope_of(_extensions: &rmcp::model::Extensions) -> String {
    crate::auth::SCOPE_FULL.to_string()
}

/// JSON-RPC error code for a refused-because-busy tool call.
///
/// The server-error range (-32000..=-32099) is where JSON-RPC 2.0 puts
/// application-defined conditions, and this is one: not a malformed request
/// (that is `INVALID_PARAMS`) and not an unexpected fault (`INTERNAL_ERROR`,
/// which reads as a bug and is not a retry signal), but a transient capacity
/// limit the caller should back off from and retry. A distinct code lets a
/// well-behaved client tell "try again in a moment" from "this will never
/// work", which is the whole point of returning a cap rather than hanging.
const AT_CAPACITY_CODE: i32 = -32000;

/// Take a concurrency permit for a tool call, or return the refusal to send
/// when the server is already at its cap.
///
/// Split out from `call_tool` so the cap is a plain function a test can drive
/// directly — the same reason [`scope_refusal`] is one. `try_acquire_owned`
/// never blocks: at the cap this returns the refusal immediately rather than
/// queueing the caller, because queueing is the resource exhaustion the cap
/// exists to prevent, only deferred. `Ok(None)` means no cap is configured
/// and every call proceeds; `Ok(Some(permit))` holds the slot until the
/// permit is dropped at the end of the call.
fn acquire_call_permit(
    limiter: &Option<Arc<tokio::sync::Semaphore>>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, rmcp::ErrorData> {
    match limiter {
        None => Ok(None),
        Some(sem) => match Arc::clone(sem).try_acquire_owned() {
            Ok(permit) => Ok(Some(permit)),
            Err(_) => Err(rmcp::ErrorData::new(
                rmcp::model::ErrorCode(AT_CAPACITY_CODE),
                "sipnab MCP server is at its concurrent tool-call cap; retry shortly".to_string(),
                None,
            )),
        },
    }
}

/// Count one tool call against its peer's rate limit, returning the refusal to
/// send when that peer has already spent its allowance for this second.
///
/// Split out from `call_tool` so the limit is a plain function a test can
/// drive directly, the same reason [`acquire_call_permit`] and
/// [`scope_refusal`] are. The refusal carries [`AT_CAPACITY_CODE`], not a
/// second code of its own: to the caller both mean the identical thing — the
/// call did not run, nothing is wrong with it, retry shortly — and a client
/// that has to learn a second "try again" code will eventually treat one of
/// them as fatal.
///
/// `None` for the limiter means no limit is configured and every call
/// proceeds. The clock is passed in rather than read here so `call_tool` meters
/// against the same instant it audits with, and so tests can cross a window
/// boundary without sleeping.
fn rate_limit_refusal(
    limiter: &Option<Arc<parking_lot::Mutex<crate::rate_limit::FixedWindowLimiter<PeerKey>>>>,
    peer: PeerKey,
    now: std::time::Instant,
) -> Option<rmcp::ErrorData> {
    let mut limiter = limiter.as_ref()?.lock();
    let refusal = limiter.check(peer, now).err()?;
    let per_second = limiter.per_peer_max();
    let refused = limiter.refused_total();
    drop(limiter);
    // A caller refused because the tracking table is full is told THAT, not
    // that it exceeded an allowance it never touched. Its very first call can
    // land here — the table fails closed once too many distinct peers have
    // been seen this second — and "you are over 100 calls/s" would send
    // whoever debugs it looking for a loop that does not exist.
    let cause = match refusal {
        crate::rate_limit::Refusal::TrackingFull => {
            " (too many distinct peers this second to account for yours)".to_string()
        }
        _ => format!(" of {per_second} call(s)/s"),
    };
    tracing::debug!(
        "MCP per-peer rate limit{cause} exceeded for {}, refusing \
         (total refused: {refused})",
        peer.map_or_else(|| "stdio".to_string(), |ip| ip.to_string())
    );
    Some(rmcp::ErrorData::new(
        rmcp::model::ErrorCode(AT_CAPACITY_CODE),
        format!("sipnab MCP server is at its per-peer rate limit{cause}; retry shortly"),
        None,
    ))
}

/// Decide whether `scope` is allowed to invoke the tool, returning the
/// refusal to send when it is not.
///
/// The decision is DERIVED from the registered tool's `read_only_hint`
/// annotation — the same annotation the client is shown by `tools/list` —
/// never from a hand-kept list of destructive tools. One source of truth:
/// if a tool's annotation says read-only, a read token may call it, and if
/// the annotation is wrong, the listing shown to clients is wrong in exactly
/// the same way, which is a single bug instead of two that drift apart.
///
/// A known tool whose annotations are missing or carry no `read_only_hint`
/// is refused under a narrow scope: absent means nobody decided, and a
/// permission check must not guess in the caller's favor. (The annotation
/// test gate keeps this branch theoretical — every registered tool carries
/// the hint.)
///
/// An UNKNOWN tool returns no refusal here so dispatch produces its own
/// "tool not found" — a scope error naming a tool that does not exist would
/// misreport both what happened and what the token lacks.
fn scope_refusal(
    scope: &str,
    tool_name: &str,
    tool: Option<&rmcp::model::Tool>,
) -> Option<rmcp::ErrorData> {
    if scope == crate::auth::SCOPE_FULL {
        return None;
    }
    let tool = tool?;
    let read_only = tool
        .annotations
        .as_ref()
        .and_then(|a| a.read_only_hint)
        .unwrap_or(false);
    if read_only {
        return None;
    }
    Some(rmcp::ErrorData::invalid_params(
        format!(
            "tool {tool_name} is not read-only and this token's scope is \
             \"{scope}\" — calling it requires a full-scope token"
        ),
        None,
    ))
}

/// Render the tool arguments for the audit line, bounded.
///
/// The arguments are the caller's own input, and recording them is the point
/// of an audit log — "read dialog X" and "read something" answer different
/// questions later. Bounded because a filter expression can be arbitrarily
/// long and the audit line must stay one line; the cap names how much was
/// withheld so a truncated record reads as truncated, not complete.
fn audit_args(arguments: Option<&rmcp::model::JsonObject>) -> String {
    const CAP: usize = 300;
    let Some(args) = arguments else {
        return "{}".to_string();
    };
    let rendered = serde_json::to_string(args).unwrap_or_else(|_| "<unserializable>".to_string());
    if rendered.len() <= CAP {
        return rendered;
    }
    let cut = rendered
        .char_indices()
        .take_while(|(i, _)| *i <= CAP)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(0);
    format!(
        "{}… ({} byte(s) withheld)",
        &rendered[..cut],
        rendered.len() - cut
    )
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SipnabMcp {
    /// Dispatch a tool call through the generated router, leaving an audit
    /// line either way.
    ///
    /// This is the ONE hand-written point every tool call passes through: the
    /// `#[tool_handler]` macro generates dispatch only when the impl block
    /// does not already carry a `call_tool`, so writing one here wraps all 28
    /// tools without touching any of them, and a 29th tool is covered the day
    /// it is registered. Before this method existed there was no such point,
    /// which is why tool calls went unaudited (and why per-tool authorization
    /// had nowhere to live — this is also that future check's home).
    ///
    /// One line per call, emitted AFTER dispatch so it can carry the outcome:
    /// who (transport identity), what (tool + bounded arguments), the JSON-RPC
    /// request id, how it ended, and how long it took. Refusals are audited
    /// too — an unknown tool name or bad arguments is exactly the probing an
    /// audit log exists to show.
    ///
    /// Scope is enforced HERE, before dispatch: the auth middleware admits
    /// any valid token and stamps its scope, and this is the first point
    /// where the requested tool — and therefore its `read_only_hint`
    /// annotation — is known. A scope refusal takes the same path as any
    /// other `Err`, so it lands on the audit line as `outcome=refused`.
    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        let tool = request.name.clone();
        let request_id = context.id.clone();
        let caller = caller_of(&context.extensions);
        let scope = scope_of(&context.extensions);
        let args = audit_args(request.arguments.as_ref());
        let started = std::time::Instant::now();

        // One emitter for every outcome. Three copies of this format string
        // used to be two refusals and a tail that could drift apart field by
        // field, and an audit trail whose lines do not share a shape is one
        // nobody can grep.
        let audit = |outcome: &str, error: &str| {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            tracing::info!(
                target: "mcp_audit",
                "tool={tool} id={request_id} caller=\"{caller}\" outcome={outcome} \
                 elapsed_ms={elapsed_ms} args={args}{error}"
            );
        };

        // Arrival rate first, ahead of the concurrency permit: a peer past its
        // calls/second allowance is turned away before it can also take a slot
        // that a peer inside its allowance is competing for. Same ordering, and
        // the same reason, as the per-peer check in `HepRateLimiter`.
        if let Some(refusal) = rate_limit_refusal(
            &self.rate_limiter,
            peer_key_of(&context.extensions),
            started,
        ) {
            audit(
                "refused",
                &format!(
                    " error=rate limited ({} refused since start)",
                    self.rate_limit_refusals()
                ),
            );
            return Err(refusal);
        }

        // Concurrency cap, before scope and before dispatch: take a permit if
        // one is configured, held for the whole call so it bounds tool calls
        // in flight. A call that cannot take one immediately is refused and
        // audited, never queued -- see `call_limiter` and `acquire_call_permit`.
        let _permit = match acquire_call_permit(&self.call_limiter) {
            Ok(permit) => permit,
            Err(refusal) => {
                audit("refused", " error=at capacity");
                return Err(refusal);
            }
        };

        let result = match scope_refusal(&scope, &tool, self.tool_router.get(&tool)) {
            Some(refusal) => Err(refusal),
            None => {
                let tcc = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
                self.tool_router.call(tcc).await
            }
        };

        let outcome = match &result {
            Ok(rmcp::model::CallToolResponse::Complete(r)) if r.is_error == Some(true) => {
                "tool_error"
            }
            Ok(_) => "ok",
            Err(_) => "refused",
        };
        let error = match &result {
            Err(e) => format!(" error={}", e.message),
            Ok(_) => String::new(),
        };
        audit(outcome, &error);
        result
    }
    /// Advertise server capabilities (tools only) and the human-readable
    /// instructions string shown to MCP clients.
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        // Name ourselves. The default comes from `Implementation::from_build_env`,
        // whose `env!("CARGO_CRATE_NAME")` expands when *rmcp* compiles, so a
        // client asking what it is connected to was told "rmcp" and rmcp's
        // version. That is both the wrong identity and a dependency's version
        // number leaking onto the wire as though it were the application's — and
        // it changed silently on every rmcp bump. `env!` here expands in this
        // crate, so these are sipnab's own values.
        info.server_info = Implementation::new("sipnab", env!("CARGO_PKG_VERSION"));
        // Every client reads this string, so it is a promise on the wire rather
        // than documentation. It used to say "read-only access", which stopped
        // being exactly true once file exports and an opt-in shutdown existed.
        // The invariant that does hold is narrower and worth stating precisely:
        // no tool changes the analysis being read.
        info.instructions = Some(
            "sipnab MCP server — queries captured SIP dialogs, RTP streams, \
             diagnostics and security findings. No tool alters the analysis. \
             File exports write only under the configured file root, and \
             stopping the server requires an explicit server-side opt-in."
                .to_string(),
        );
        info
    }
}

/// Write held SIP messages to a pcap by re-synthesising a frame per message.
///
/// The dialog store keeps parsed messages, not the original frames, so an
/// export rebuilds an Ethernet/IP/UDP packet around each message's raw bytes —
/// the same `build_synthetic_packet` the TUI's save path uses, rather than a
/// second implementation that could drift from it.
///
/// The result is faithful to the SIP layer and honest about the rest: link and
/// IP headers are reconstructed from the addresses and ports sipnab recorded,
/// not the bytes originally on the wire.
#[cfg(feature = "mcp")]
fn write_messages_to_pcap(
    messages: &[crate::sip::SipMessage],
    path: &std::path::Path,
) -> anyhow::Result<usize> {
    use crate::capture::{PcapExportMode, PcapWriter};
    let pcapng = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pcapng"));
    // #106: the file has to say what it is. Whoever opens this never saw the
    // tool description and has no reason to suspect the frames were rebuilt,
    // and this is the artifact that gets forwarded to a carrier or into a
    // ticket. pcapng carries it as the section comment; classic pcap has
    // nowhere to put it, which is itself a reason to prefer .pcapng here.
    let note = format!(
        "Produced by sipnab {} via the MCP export_capture tool.\n\
         \n\
         THE FRAMES IN THIS FILE WERE REBUILT, NOT COPIED. sipnab retains \
         parsed SIP messages rather than captured frames, so each packet here \
         is a synthetic Ethernet/IPv4/UDP frame constructed around one \
         message's bytes. The SIP layer is byte-faithful; the link, IP and \
         transport headers are reconstructed from the addresses and ports \
         sipnab recorded, and MAC addresses, IP identification, checksums, \
         fragmentation and TCP state are not what was on the wire.\n\
         \n\
         Non-SIP traffic present in the original capture — RTP, RTCP, DNS, \
         ICMP — is NOT in this file. Do not read packet counts here as \
         capture-level counts.\n\
         \n\
         {} message(s) written.",
        env!("CARGO_PKG_VERSION"),
        messages.len(),
    );
    let mut writer = PcapWriter::with_provenance(
        path,
        // DLT_EN10MB: the synthetic frames carry an Ethernet header.
        1,
        None,
        None,
        pcapng,
        // Raw: no key material embedded. An agent-triggered export must not
        // write decryption secrets into a file it just named.
        PcapExportMode::Raw,
        None,
        Some(note),
    )?;
    let mut written = 0;
    for msg in messages {
        writer.write(&crate::output::synthetic::build_synthetic_packet(msg))?;
        written += 1;
    }
    writer.finish()?;
    Ok(written)
}

/// Unit tests for every MCP tool handler: success paths, error codes, and
/// pagination/cursor semantics, driven directly (no transport).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use std::net::{IpAddr, Ipv4Addr};

    /// A server over fresh, empty dialog/stream stores.
    fn empty_server() -> SipnabMcp {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        SipnabMcp::new(ds, ss)
    }

    /// 127.0.0.1 as an `IpAddr`.
    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    /// A fixed timestamp so dialog `updated_at` values are deterministic.
    fn base_ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Parse `raw` as SIP between localhost:5060 endpoints at time `ts`.
    fn parse_at(raw: &[u8], ts: chrono::DateTime<chrono::Utc>) -> crate::sip::SipMessage {
        parse_sip(
            raw,
            ts,
            localhost(),
            localhost(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("should parse SIP")
    }

    /// A minimal well-formed INVITE for `call_id`, parsed at `ts`.
    /// An INVITE carrying one extra header, for correlation tests.
    ///
    /// The Via branch differs per call so a `ViaBranch` match cannot be what
    /// the Session-ID test is actually observing.
    fn invite_with_header(
        call_id: &str,
        name: &str,
        value: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::sip::SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK{call_id}"),
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("{name}: {value}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, ts)
    }

    fn invite(call_id: &str, ts: chrono::DateTime<chrono::Utc>) -> crate::sip::SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: TestUA/1.0",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, ts)
    }

    /// The matching 200 OK response for `call_id`, parsed at `ts`.
    fn ok200(call_id: &str, ts: chrono::DateTime<chrono::Utc>) -> crate::sip::SipMessage {
        let raw = build_sip(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                // RFC 3261 §12.1.1: a 2xx to INVITE is the dialog's remote
                // target. Without it this fixture is not the conformant call
                // it claims to be, and CONTACT_MISSING_IN_2XX says so.
                "Contact: <sip:bob@127.0.0.1>",
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, ts)
    }

    /// A server whose dialog store holds one dialog (`call_id`) with an
    /// INVITE followed by a 200 OK (two messages).
    /// A bare filename that is a symlink out of the root is refused.
    ///
    /// `resolve_in_root` rejected separators, `..` and anything that was not a
    /// single normal component, then joined and returned. String validation
    /// cannot see a symlink, because the escape is not in the string: the name
    /// really is one bare component, and the kernel does the rest at `open`.
    ///
    /// Measured before this check existed: an export wrote 77,736 bytes through
    /// an in-root symlink to a path outside the root, exit 0, and returned the
    /// in-root path as though that were where the bytes went. The shipped
    /// security model says "naming one directory means the worst an agent can
    /// do is fill it", and that did not hold.
    ///
    /// The escape needs prior write access inside the root, so this is not a
    /// remote break. It is listed and fixed because it is the STATED boundary of
    /// an agent-facing surface, and a boundary documented as absolute should be.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_file_root_is_refused() {
        let base =
            std::env::temp_dir().join(format!("sipnab-mcp-root-symlink-{}", std::process::id()));
        let root = base.join("root");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");

        let escape = outside.join("secrets.pcap");
        std::fs::write(&escape, b"original").expect("seed the file outside");
        std::os::unix::fs::symlink(&escape, root.join("innocent.pcap")).expect("symlink");

        let srv = server_with_dialog("sym@test").with_file_root(&root);
        let err = srv
            .resolve_in_root("innocent.pcap")
            .expect_err("a name that resolves outside the root must be refused");

        let msg = format!("{err:?}");
        assert!(
            msg.contains("outside") || msg.contains("symlink") || msg.contains("root"),
            "the refusal must say the name leaves the root, not merely that it \
             failed: {msg}"
        );
        assert_eq!(
            std::fs::read(&escape).expect("read"),
            b"original",
            "the file outside the root must be untouched"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `capture_status` reports SIP the portrange skipped (#95).
    ///
    /// `dialog_count` alone reads as "how much was there". On the corpus it was
    /// 2,311 against 3,712 real — 37.7% lost — because a third of the SIP never
    /// touches 5060/5061. That reached the operator as stderr warnings and
    /// reached an MCP client not at all: the response was byte-identical with
    /// and without the loss, so an agent answered "what calls are in this
    /// capture" from two-thirds of them with full confidence.
    ///
    /// Asserted as KEY PRESENCE, not a value. The count is process-global and
    /// whatever this test's process happens to have skipped is not the point —
    /// the defect was a field that did not exist, and a client that cannot see
    /// the key cannot see the loss whatever number would have been in it.
    #[tokio::test]
    async fn capture_status_carries_the_unanalysed_sip_count() {
        let result = empty_server()
            .capture_status()
            .await
            .expect("capture_status");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert!(
            v.get("unanalysed_sip_messages").is_some(),
            "a client must be able to see that SIP went unanalysed: {v}"
        );
        assert!(
            v["unanalysed_busiest_ports"].is_array(),
            "the ports carrying it are what the operator passes to --portrange, \
             so the answer names its own remedy: {v}"
        );
        // Present on `stats` too, and the two must not drift into naming the
        // same fact differently.
        let stats = empty_server().capture_status().await.expect("stats");
        let sv: serde_json::Value = serde_json::from_str(&text_of(&stats)).unwrap();
        for key in ["unanalysed_sip_messages", "unanalysed_busiest_ports"] {
            assert!(
                sv.get(key).is_some(),
                "stats must carry {key} under the same name as capture_status, \
                 or a client learns the loss from one tool and not the other"
            );
        }
    }

    /// A lint finding cites the frame it was drawn from, and stays silent when
    /// it cannot.
    ///
    /// A finding names a rule and a message INDEX. The index means nothing
    /// without the message list it indexes — which a reviewer may not have, and
    /// which compaction reshuffles — so on its own a finding is an assertion
    /// again. `frame_ref` makes it checkable through `show_evidence`.
    ///
    /// The second half matters more than the first: a message with no pointer
    /// must produce NO key. `""` and `"x#0"` both read as a real pointer, and a
    /// finding citing frame 0 of nothing manufactures the confidence the whole
    /// mechanism exists to prevent.
    #[test]
    fn a_finding_cites_its_frame_or_says_nothing() {
        use crate::capture::packet::{FrameOrigin, FrameRef};

        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKcite",
                "From: Alice <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                "Call-ID: cite@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ts = chrono::Utc::now();
        let mut msg = parse_at(&raw, ts);
        msg.frame = Some(FrameRef {
            source: "calls.pcap".into(),
            origin: FrameOrigin {
                ordinal: 41,
                digest: Some(0x6d1f_4c0a_9b2e_7a53),
            },
        });
        let mut unciteable = parse_at(&raw, ts);
        unciteable.frame = None;
        let messages = vec![msg, unciteable];

        let finding = |idx: usize| crate::sip::lint::Finding {
            rule_id: "SIP-3261-8.1.1-MANDATORY-HEADER-MISSING",
            severity: crate::sip::lint::Severity::Error,
            basis: crate::sip::lint::Basis::Must,
            rfc: 3261,
            section: "8.1.1",
            message_index: idx,
            observed: "o".to_string(),
            expected: "e".to_string(),
            explanation: "x".to_string(),
        };

        let out = findings_with_refs(&[finding(0), finding(1)], &messages);

        assert_eq!(
            out[0]["frame_ref"], "calls.pcap#41@6d1f4c0a9b2e7a53",
            "a finding on a message with a pointer must carry it, digest and \
             all -- without the digest a later reader cannot tell the capture \
             was rotated: {:?}",
            out[0]
        );
        assert!(
            out[1].get("frame_ref").is_none(),
            "a finding on a message with NO pointer must omit the key, not \
             emit an empty or zero one: {:?}",
            out[1]
        );
        // An out-of-range index must not borrow a neighbouring frame.
        let stray = findings_with_refs(&[finding(99)], &messages);
        assert!(
            stray[0].get("frame_ref").is_none(),
            "an index past the end must cite nothing rather than the last \
             message: {:?}",
            stray[0]
        );
    }

    /// A stream cites the frame it began in, and stays silent when it cannot.
    ///
    /// `rtp_stats` is the one query tool whose facts are entirely about media,
    /// and media is where a pointer is worth the most: an orphaned stream has
    /// no `Call-ID`, no dialog and no message list, so an SSRC and a jitter
    /// figure were the whole of what a caller could check. There was nothing
    /// to hand `show_evidence`.
    ///
    /// The second half is the same rule every other surface here follows: a
    /// stream with no pointer emits NO key. `""` and `"x#0"` both read as a
    /// real pointer, and a stream citing frame 0 of nothing is worse than one
    /// citing nothing at all.
    #[test]
    fn a_stream_cites_its_frame_or_says_nothing() {
        use crate::capture::packet::{FrameOrigin, FrameRef};
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};

        let key = StreamKey {
            ssrc: 0x1a2b_3c4d,
            src: "192.0.2.1:10000".parse().expect("src"),
            dst: "192.0.2.2:20000".parse().expect("dst"),
        };
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: key.ssrc,
            payload_offset: 12,
        };
        let mut stream = RtpStream::new(key, &header, chrono::Utc::now());
        stream.first_frame = Some(FrameRef {
            source: "calls.pcap".into(),
            origin: FrameOrigin {
                ordinal: 41,
                digest: Some(0x6d1f_4c0a_9b2e_7a53),
            },
        });

        let with = stream_json(&stream);
        assert_eq!(
            with["frame"], "calls.pcap#41@6d1f4c0a9b2e7a53",
            "a stream with a pointer must carry it, digest and all -- without \
             the digest a later reader cannot tell the capture was rotated: \
             {with}"
        );

        stream.first_frame = None;
        let without = stream_json(&stream);
        assert!(
            without.get("frame").is_none(),
            "a stream with NO pointer must omit the key, not emit an empty or \
             zero one: {without}"
        );
    }

    /// A pointer whose source escapes the file root is refused, not followed.
    ///
    /// THE reason this tool needs a test more than the others: it takes a
    /// caller-supplied string, extracts a path from it, and returns the bytes
    /// at that path. Resolving the pointer's own `source` would make
    /// `show_evidence` an arbitrary-file-read primitive wearing a
    /// `readOnlyHint`. The tool takes the final component and pushes it through
    /// `resolve_in_root`, so a crafted pointer can at worst name a file the
    /// operator already exposed.
    ///
    /// Asserted on the EFFECT — no bytes come back — rather than on the wording
    /// of the refusal, so a reworded message cannot quietly turn this green
    /// while the read succeeds.
    #[cfg(unix)]
    #[tokio::test]
    async fn show_evidence_refuses_a_pointer_that_escapes_the_file_root() {
        let base = std::env::temp_dir().join(format!(
            "sipnab-show-evidence-escape-{}",
            std::process::id()
        ));
        let root = base.join("root");
        let outside = base.join("outside");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        // A REAL capture, so that a bypass of the confinement would actually
        // succeed and return frame bytes. Seeding junk here would make the test
        // pass for the wrong reason: the resolver would reject it as an
        // unreadable capture, and the assertion below would hold even with the
        // guard removed.
        let secret = outside.join("secret.pcap");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/pcap-samples/sip-register.pcap"
            ),
            &secret,
        )
        .expect("seed a real capture outside the root");

        let srv = server_with_dialog("esc@test").with_file_root(&root);
        let result = srv
            .show_evidence(Parameters(ShowEvidenceParams {
                refs: vec![
                    format!("{}#0", secret.display()),
                    "../../../etc/passwd#0".to_string(),
                    "/etc/shadow#0".to_string(),
                ],
                max_bytes: None,
            }))
            .await
            .expect("the call itself succeeds; individual pointers are refused");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert_eq!(
            v["resolved"], 0,
            "nothing outside the root may resolve: {v}"
        );
        // The frame the bypass would return, computed independently so this
        // asserts on the real bytes rather than on a marker string.
        let leaked_hex = {
            let raw = std::fs::read(&secret).expect("read the outside capture");
            raw.iter()
                .skip(40)
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let body = v.to_string();
        assert!(
            !body.contains(&leaked_hex),
            "bytes from the capture outside the root reached the response -- \
             the confinement was bypassed: {body}"
        );
        for frame in v["frames"].as_array().expect("frames") {
            assert_eq!(frame["status"], "unresolvable", "{frame}");
            assert!(
                frame["hex"].is_null(),
                "no bytes for a refused pointer: {frame}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A pointer naming a live device says it cannot be followed, and says why.
    ///
    /// sipnab retains parsed messages, not frames, so there is nothing on disk
    /// to seek to. Reconstructing something and presenting it as evidence is
    /// the defect `export_capture` had; this reports the limit instead.
    #[tokio::test]
    async fn show_evidence_says_a_live_pointer_has_no_frames_to_follow() {
        let root =
            std::env::temp_dir().join(format!("sipnab-show-evidence-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");

        let result = server_with_dialog("live@test")
            .with_file_root(&root)
            .show_evidence(Parameters(ShowEvidenceParams {
                refs: vec!["eth0#17".to_string()],
                max_bytes: None,
            }))
            .await
            .expect("show_evidence");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert_eq!(v["resolved"], 0);
        assert_eq!(v["frames"][0]["status"], "unresolvable");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty batch is refused rather than answered with an empty list.
    ///
    /// `resolved: 0` over no pointers and `resolved: 0` over three that all
    /// failed are different facts, and only one of them is a caller error.
    #[tokio::test]
    async fn show_evidence_refuses_an_empty_batch() {
        let err = empty_server()
            .show_evidence(Parameters(ShowEvidenceParams {
                refs: vec![],
                max_bytes: None,
            }))
            .await
            .expect_err("an empty ref list must be refused");
        assert!(
            err.message.contains("at least one"),
            "the refusal must say what was wrong: {}",
            err.message
        );
    }

    /// One unfollowable pointer does not discard the rest of the batch, and the
    /// summary counts what actually resolved.
    #[tokio::test]
    async fn show_evidence_reports_each_pointer_independently() {
        let root =
            std::env::temp_dir().join(format!("sipnab-show-evidence-mixed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");

        let result = server_with_dialog("mixed@test")
            .with_file_root(&root)
            .show_evidence(Parameters(ShowEvidenceParams {
                refs: vec![
                    "not a pointer at all".to_string(),
                    "absent.pcap#3".to_string(),
                ],
                max_bytes: None,
            }))
            .await
            .expect("show_evidence");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert_eq!(v["requested"], 2, "every pointer is accounted for: {v}");
        assert_eq!(
            v["frames"].as_array().map(Vec::len),
            Some(2),
            "a failing pointer still gets an entry, so a caller can tell WHICH \
             one failed: {v}"
        );
        // The malformed one and the missing one fail for different reasons, and
        // both reasons must be present rather than a single generic refusal.
        let reasons: Vec<String> = v["frames"]
            .as_array()
            .expect("frames")
            .iter()
            .map(|f| f["reason"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            reasons.iter().all(|r| !r.is_empty()),
            "every unresolvable pointer must say why: {reasons:?}"
        );
        assert!(
            reasons[0] != reasons[1],
            "a malformed pointer and a missing frame are different failures and \
             must not share one message: {reasons:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An ordinary name inside the root still resolves, so the check above is
    /// not simply refusing everything.
    #[cfg(unix)]
    #[test]
    fn a_plain_name_inside_the_file_root_still_resolves() {
        let root =
            std::env::temp_dir().join(format!("sipnab-mcp-root-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("mkdir");

        let srv = server_with_dialog("plain@test").with_file_root(&root);
        let path = srv
            .resolve_in_root("out.pcap")
            .expect("a bare name inside the root must resolve");
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("out.pcap"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The handshake must name sipnab, not whichever MCP crate we build on.
    ///
    /// `ServerInfo::new` fills `server_info` from `Implementation::default()`,
    /// which is `from_build_env()`, whose `env!("CARGO_CRATE_NAME")` expands
    /// when *rmcp* compiles. So the default is literally the string "rmcp" plus
    /// rmcp's own version, and it moved on its own during the 2.2.0 -> 3.0.1
    /// bump. Asserting the name is not "rmcp" is the half that catches a
    /// regression: a future refactor that drops the explicit assignment would
    /// still produce a well-formed handshake naming the wrong software.
    #[test]
    fn the_handshake_names_sipnab_and_not_the_transport_crate() {
        let info = server_with_dialog("id@test").get_info();

        assert_eq!(info.server_info.name, "sipnab");
        assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
        assert_ne!(
            info.server_info.name, "rmcp",
            "server_info fell back to rmcp's build environment"
        );
        // The version must track this crate, so it cannot be a dependency's.
        assert!(
            !info.server_info.version.is_empty(),
            "an empty version is not an identity"
        );
    }

    fn server_with_dialog(call_id: &str) -> SipnabMcp {
        let mut ds = DialogStore::new(100, false);
        ds.process_message(invite(call_id, base_ts()));
        ds.process_message(ok200(call_id, base_ts()));
        let ds = Arc::new(RwLock::new(ds));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        SipnabMcp::new(ds, ss)
    }

    /// A server whose dialogs ALL share one `created_at`.
    ///
    /// The case no fixture in `tests/pcap-samples/` produces: sipp spaces its
    /// registrations far enough apart that every dialog gets a distinct
    /// microsecond, so a pagination test over a real capture never puts two
    /// dialogs on the same instant. Real traffic does it constantly.
    ///
    /// Call-IDs are inserted in an order that disagrees with their sort order,
    /// so a sort that leaves ties in store order is visibly different from one
    /// that orders them by Call-ID.
    fn server_with_simultaneous_dialogs(call_ids: &[&str]) -> SipnabMcp {
        let mut ds = DialogStore::new(100, false);
        for id in call_ids {
            ds.process_message(invite(id, base_ts()));
            ds.process_message(ok200(id, base_ts()));
        }
        SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        )
    }

    /// One page of `list_dialogs`, as parsed JSON.
    async fn page(server: &SipnabMcp, limit: u32, cursor: Option<&str>) -> serde_json::Value {
        let result = server
            .list_dialogs(Parameters(ListDialogsParams {
                filter: None,
                limit: Some(limit),
                cursor: cursor.map(str::to_string),
            }))
            .await
            .expect("list_dialogs should succeed");
        serde_json::from_str(&text_of(&result)).expect("valid JSON page")
    }

    /// Paging through dialogs that share a timestamp loses none and repeats none.
    ///
    /// The `(created_at, Call-ID)` ordering has to hold in BOTH places or the
    /// pages do not line up: the sort decides where the boundary falls, and the
    /// cursor comparison decides where the next page resumes. Sorting on the
    /// timestamp alone leaves ties in store insertion order while the cursor
    /// still resumes by Call-ID, so a dialog sorted before the boundary but
    /// named after it disappears from the sweep — silently, and only when two
    /// dialogs happen to share an instant.
    ///
    /// A mutation dropping `.then_with(|| a.call_id.cmp(&b.call_id))` from the
    /// sort survived every capture-driven test in the suite. This one fails.
    #[tokio::test]
    async fn list_dialogs_pages_through_dialogs_sharing_one_timestamp() {
        // Inserted in an order that is not sorted order.
        let server = server_with_simultaneous_dialogs(&["d@h", "b@h", "e@h", "a@h", "c@h"]);

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let v = page(&server, 2, cursor.as_deref()).await;
            assert_eq!(v["total_matched"], 5, "the store holds 5: {v}");
            for d in v["dialogs"].as_array().expect("dialogs") {
                seen.push(d["call_id"].as_str().expect("call_id").to_string());
            }
            match v["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => break,
            }
        }

        assert_eq!(
            seen,
            vec!["a@h", "b@h", "c@h", "d@h", "e@h"],
            "every dialog exactly once, in Call-ID order within the shared \
             instant; got {seen:?}"
        );
    }

    /// Extract the text body of the first content item.
    /// The payload block of a tool result.
    ///
    /// Tools that return capture-derived data lead with the provenance note
    /// (`shape::untrusted_note`), so `content[0]` is the note for those and the
    /// payload for the rest. This finds the first block that is not the note,
    /// which works for both shapes — and, unlike indexing past a fixed offset,
    /// does not start silently asserting against the note if a tool stops
    /// emitting one.
    fn text_of(result: &CallToolResult) -> String {
        let note = crate::mcp::shape::untrusted_note();
        result
            .content
            .iter()
            .filter_map(|c| c.as_text())
            .map(|t| t.text.clone())
            .find(|t| *t != note)
            .expect("result should carry a payload block that is not the note")
    }

    /// The shared exhausted flag flows through to `source_exhausted`:
    /// false while unset, true after the capture owner stores it.
    #[tokio::test]
    async fn tail_dialogs_reports_source_exhausted_from_shared_flag() {
        // The tool description promises source_exhausted=true once the pcap
        // source is fully consumed; an LLM polling tail_dialogs to know when
        // a replay is done relies on it.
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = empty_server().with_source_exhausted(Arc::clone(&flag));

        let result = server
            .tail_dialogs(Parameters(TailDialogsParams::default()))
            .await
            .expect("tail_dialogs should not error");
        let json: serde_json::Value =
            serde_json::from_str(&text_of(&result)).expect("valid JSON response");
        assert_eq!(
            json["source_exhausted"], false,
            "flag unset ⇒ source not exhausted"
        );

        flag.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams::default()))
            .await
            .expect("tail_dialogs should not error");
        let json: serde_json::Value =
            serde_json::from_str(&text_of(&result)).expect("valid JSON response");
        assert_eq!(
            json["source_exhausted"], true,
            "flag set ⇒ source_exhausted must be reported"
        );
    }

    /// With no capture owner attached, `source_exhausted` stays false.
    #[tokio::test]
    async fn tail_dialogs_without_flag_reports_not_exhausted() {
        // No capture owner attached (e.g. unit contexts): stay false rather
        // than lying about EOF.
        let server = empty_server();
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams::default()))
            .await
            .expect("tail_dialogs should not error");
        let json: serde_json::Value =
            serde_json::from_str(&text_of(&result)).expect("valid JSON response");
        assert_eq!(json["source_exhausted"], false);
    }

    /// The configured cap REACHES a real response, not just the helper.
    ///
    /// This is the test that separates a setting from a signature. Six
    /// thresholds in this tree are accepted as parameters, documented as
    /// tunable, and supplied by no production caller — `RegFloodDetector::new(0)`,
    /// `FraudDetector::new(None)`, every `AsymmetryThresholds::default()`. Each
    /// would pass a unit test of its resolver and change nothing a user sees.
    /// So: drive `list_dialogs` on a server built with a small cap and count
    /// the rows that come back.
    #[tokio::test]
    async fn the_row_cap_bounds_an_actual_list_response() {
        let server =
            server_with_simultaneous_dialogs(&["a@h", "b@h", "c@h", "d@h", "e@h"]).with_row_cap(2);
        // Ask for far more than the cap allows.
        let v = page(&server, 100, None).await;
        let rows = v["dialogs"].as_array().expect("dialogs array").len();
        assert_eq!(
            rows, 2,
            "with_row_cap(2) must bound the response; got {rows} rows, so the \
             cap is a field nothing reads"
        );

        // And a cap ABOVE the old constant must be honoured, or the setting can
        // only ever tighten — half a knob.
        let wide =
            server_with_simultaneous_dialogs(&["a@h", "b@h", "c@h", "d@h", "e@h"]).with_row_cap(4);
        let v = page(&wide, 100, None).await;
        assert_eq!(v["dialogs"].as_array().unwrap().len(), 4);
    }

    /// An empty store yields an empty JSON array, not an error.
    #[tokio::test]
    async fn list_dialogs_empty_store_returns_empty() {
        let server = empty_server();
        let result = server
            .list_dialogs(Parameters(ListDialogsParams::default()))
            .await
            .expect("list_dialogs should not error on empty store");
        // Inspect the wrapped JSON content.
        let content = &result.content[0];
        let raw = content.as_text().expect("should be text-able").text.clone();
        // Empty list → "[]"
        assert!(
            raw.contains("[]"),
            "empty store should return [], got: {raw}"
        );
    }

    /// An unparseable filter expression errors with invalid_params (-32602).
    #[tokio::test]
    async fn list_dialogs_with_invalid_filter_returns_invalid_params() {
        let server = empty_server();
        let err = server
            .list_dialogs(Parameters(ListDialogsParams {
                filter: Some("THIS IS NOT A FILTER".to_string()),
                ..Default::default()
            }))
            .await
            .expect_err("invalid filter must error");
        // ErrorData has a code field; invalid_params is -32602.
        let json = serde_json::to_value(err).expect("error should serialize");
        assert_eq!(json["code"], -32602);
    }

    /// An unknown Call-ID errors with invalid_params (-32602).
    #[tokio::test]
    async fn get_dialog_report_unknown_call_id_errors() {
        let server = empty_server();
        let err = server
            .get_dialog_report(Parameters(GetDialogReportParams {
                call_id: "nonexistent@nowhere".to_string(),
                format: None,
            }))
            .await
            .expect_err("unknown call_id must error");
        let json = serde_json::to_value(err).expect("error should serialize");
        assert_eq!(json["code"], -32602);
    }

    /// An unsupported format string errors with invalid_params (-32602).
    #[tokio::test]
    async fn get_dialog_report_unknown_format_errors() {
        let server = empty_server();
        let err = server
            .get_dialog_report(Parameters(GetDialogReportParams {
                call_id: "anything".to_string(),
                format: Some("yaml".to_string()),
            }))
            .await
            .expect_err("unknown format must error");
        let json = serde_json::to_value(err).expect("error should serialize");
        assert_eq!(json["code"], -32602);
    }

    /// An unknown diagnostic alias errors with invalid_params (-32602).
    #[tokio::test]
    async fn find_problems_unknown_alias_errors() {
        let server = empty_server();
        let err = server
            .find_problems(Parameters(FindProblemsParams {
                kinds: Some(vec!["this-alias-does-not-exist".to_string()]),
                ..Default::default()
            }))
            .await
            .expect_err("unknown alias must error");
        let json = serde_json::to_value(err).expect("error should serialize");
        assert_eq!(json["code"], -32602);
    }

    /// The default "problems" kind on an empty store yields an empty list.
    #[tokio::test]
    async fn find_problems_default_kind_returns_empty_list_on_empty_store() {
        let server = empty_server();
        let result = server
            .find_problems(Parameters(FindProblemsParams::default()))
            .await
            .expect("find_problems on empty store should succeed");
        let content = &result.content[0];
        let raw = content.as_text().expect("should be text-able").text.clone();
        assert!(raw.contains("[]"), "empty store → empty list, got: {raw}");
    }

    // ── list_dialogs success path with populated store ───────────────

    /// A populated store returns a summary naming the dialog and its party.
    #[tokio::test]
    async fn list_dialogs_returns_summary_for_populated_store() {
        let server = server_with_dialog("call-list@x");
        let result = server
            .list_dialogs(Parameters(ListDialogsParams::default()))
            .await
            .expect("list_dialogs should succeed");
        let raw = text_of(&result);
        assert!(
            raw.contains("call-list@x"),
            "summary must name the dialog: {raw}"
        );
        assert!(raw.contains("alice"), "from_user should appear: {raw}");
    }

    // ── get_dialog_report success paths ──────────────────────────────

    /// The default JSON format re-parses into a structured object, not a
    /// stringified blob.
    #[tokio::test]
    async fn get_dialog_report_json_returns_structured_object() {
        let server = server_with_dialog("rep@x");
        let result = server
            .get_dialog_report(Parameters(GetDialogReportParams {
                call_id: "rep@x".to_string(),
                format: None,
            }))
            .await
            .expect("report should succeed");
        let raw = text_of(&result);
        // JSON path re-parses to structured JSON; it must be a JSON object.
        let v: serde_json::Value = serde_json::from_str(&raw).expect("report is JSON");
        assert!(v.is_object(), "json report should be an object, got: {raw}");
    }

    /// Markdown format yields non-empty text that is not standalone JSON.
    #[tokio::test]
    async fn get_dialog_report_markdown_returns_text() {
        let server = server_with_dialog("repmd@x");
        let result = server
            .get_dialog_report(Parameters(GetDialogReportParams {
                call_id: "repmd@x".to_string(),
                format: Some("markdown".to_string()),
            }))
            .await
            .expect("markdown report should succeed");
        let raw = text_of(&result);
        assert!(!raw.is_empty(), "markdown report must be non-empty");
        // markdown report is not valid standalone JSON
        assert!(serde_json::from_str::<serde_json::Value>(&raw).is_err());
    }

    // ── get_dialog ───────────────────────────────────────────────────

    /// An unknown Call-ID errors with invalid_params (-32602).
    #[tokio::test]
    async fn get_dialog_unknown_call_id_errors() {
        let server = empty_server();
        let err = server
            .get_dialog(Parameters(GetDialogParams {
                call_id: "missing@x".to_string(),
                max_messages: None,
                cursor: None,
            }))
            .await
            .expect_err("unknown call_id must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// A full fetch returns all messages, complete=true, and a null cursor.
    #[tokio::test]
    async fn get_dialog_returns_messages_and_completion() {
        let server = server_with_dialog("dlg@x");
        let result = server
            .get_dialog(Parameters(GetDialogParams {
                call_id: "dlg@x".to_string(),
                max_messages: None,
                cursor: None,
            }))
            .await
            .expect("get_dialog should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["total_messages"], 2);
        assert_eq!(v["complete"], true);
        assert!(v["next_cursor"].is_null());
        assert_eq!(v["messages"].as_array().unwrap().len(), 2);
    }

    /// A page smaller than the dialog yields complete=false and next_cursor.
    #[tokio::test]
    async fn get_dialog_pagination_yields_next_cursor() {
        let server = server_with_dialog("page@x");
        let result = server
            .get_dialog(Parameters(GetDialogParams {
                call_id: "page@x".to_string(),
                max_messages: Some(1),
                cursor: Some(0),
            }))
            .await
            .expect("get_dialog should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["total_messages"], 2);
        assert_eq!(v["complete"], false);
        assert_eq!(v["next_cursor"], 1);
        assert_eq!(v["messages"].as_array().unwrap().len(), 1);
    }

    /// A cursor past the last message yields an empty page, complete=true.
    #[tokio::test]
    async fn get_dialog_cursor_past_end_returns_empty_slice() {
        let server = server_with_dialog("end@x");
        let result = server
            .get_dialog(Parameters(GetDialogParams {
                call_id: "end@x".to_string(),
                max_messages: Some(100),
                cursor: Some(99),
            }))
            .await
            .expect("get_dialog should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert!(v["messages"].as_array().unwrap().is_empty());
        assert_eq!(v["complete"], true);
        assert!(v["next_cursor"].is_null());
    }

    // ── get_message ──────────────────────────────────────────────────

    /// An unknown Call-ID errors with invalid_params (-32602).
    #[tokio::test]
    async fn get_message_unknown_call_id_errors() {
        let server = empty_server();
        let err = server
            .get_message(Parameters(GetMessageParams {
                call_id: "missing@x".to_string(),
                index: 0,
            }))
            .await
            .expect_err("unknown call_id must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// An out-of-range index errors (-32602) and the message names the range.
    #[tokio::test]
    async fn get_message_index_out_of_range_errors() {
        let server = server_with_dialog("msgoob@x");
        let err = server
            .get_message(Parameters(GetMessageParams {
                call_id: "msgoob@x".to_string(),
                index: 99,
            }))
            .await
            .expect_err("out-of-range index must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
        assert!(
            json["message"].as_str().unwrap().contains("out of range"),
            "message should mention range: {json}"
        );
    }

    /// A valid index returns the message as a structured JSON object.
    #[tokio::test]
    async fn get_message_returns_structured_message() {
        let server = server_with_dialog("msg@x");
        let result = server
            .get_message(Parameters(GetMessageParams {
                call_id: "msg@x".to_string(),
                index: 0,
            }))
            .await
            .expect("get_message should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert!(v.is_object(), "message should serialize to a JSON object");
    }

    // ── render_ladder ────────────────────────────────────────────────

    /// An unsupported ladder format errors with invalid_params (-32602).
    #[tokio::test]
    async fn render_ladder_unknown_format_errors() {
        let server = server_with_dialog("ladfmt@x");
        let err = server
            .render_ladder(Parameters(RenderLadderParams {
                call_id: "ladfmt@x".to_string(),
                format: Some("html".to_string()),
            }))
            .await
            .expect_err("unknown format must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// An unknown Call-ID errors with invalid_params (-32602).
    #[tokio::test]
    async fn render_ladder_unknown_call_id_errors() {
        let server = empty_server();
        let err = server
            .render_ladder(Parameters(RenderLadderParams {
                call_id: "missing@x".to_string(),
                format: None,
            }))
            .await
            .expect_err("unknown call_id must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// Text format renders a non-empty ladder for a tracked dialog.
    #[tokio::test]
    async fn render_ladder_text_format_returns_non_empty() {
        let server = server_with_dialog("lad@x");
        let result = server
            .render_ladder(Parameters(RenderLadderParams {
                call_id: "lad@x".to_string(),
                format: Some("text".to_string()),
            }))
            .await
            .expect("render_ladder should succeed");
        assert!(
            !text_of(&result).is_empty(),
            "ladder text must be non-empty"
        );
    }

    // ── rtp_stats ────────────────────────────────────────────────────

    /// An unknown Call-ID errors with invalid_params (-32602).
    #[tokio::test]
    async fn rtp_stats_unknown_call_id_errors() {
        let server = empty_server();
        let err = server
            .rtp_stats(Parameters(RtpStatsParams {
                call_id: Some("missing@x".to_string()),
                ..Default::default()
            }))
            .await
            .expect_err("unknown call_id must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// A media-less dialog yields an empty streams array plus a diagnosis.
    #[tokio::test]
    async fn rtp_stats_no_streams_returns_empty_streams_array() {
        let server = server_with_dialog("rtp@x");
        let result = server
            .rtp_stats(Parameters(RtpStatsParams {
                call_id: Some("rtp@x".to_string()),
                ..Default::default()
            }))
            .await
            .expect("rtp_stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["call_id"], "rtp@x");
        assert!(v["streams"].as_array().unwrap().is_empty());
        assert!(v.get("diagnosis").is_some());
    }

    // ── search_messages ──────────────────────────────────────────────

    /// An empty query errors with invalid_params (-32602).
    #[tokio::test]
    async fn search_messages_empty_query_errors() {
        let server = empty_server();
        let err = server
            .search_messages(Parameters(SearchMessagesParams {
                query: String::new(),
                limit: None,
            }))
            .await
            .expect_err("empty query must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// A query matching nothing returns an empty hits array.
    #[tokio::test]
    async fn search_messages_no_match_returns_empty() {
        let server = server_with_dialog("srch@x");
        let result = server
            .search_messages(Parameters(SearchMessagesParams {
                query: "zzz-no-such-token".to_string(),
                limit: None,
            }))
            .await
            .expect("search should succeed");
        assert!(text_of(&result).contains("[]"));
    }

    /// An upper-cased query still matches the lower-cased From header.
    #[tokio::test]
    async fn search_messages_case_insensitive_hit() {
        let server = server_with_dialog("srch2@x");
        let result = server
            .search_messages(Parameters(SearchMessagesParams {
                // Upper-cased query against lower-cased "alice".
                query: "ALICE".to_string(),
                limit: Some(10),
            }))
            .await
            .expect("search should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        let hits = v.as_array().expect("hits array");
        assert!(!hits.is_empty(), "should match the From header");
        assert_eq!(hits[0]["call_id"], "srch2@x");
        assert!(
            hits[0]["snippet"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("alice")
        );
    }

    /// The field scan still matches each searchable field: the method
    /// (case-insensitively), the numeric status code, and the User-Agent.
    #[tokio::test]
    async fn search_messages_matches_each_field() {
        let server = server_with_dialog("srch3@x");
        for q in ["InViTe", "200", "testua"] {
            let result = server
                .search_messages(Parameters(SearchMessagesParams {
                    query: q.to_string(),
                    limit: Some(10),
                }))
                .await
                .expect("search should succeed");
            let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
            let hits = v.as_array().expect("hits array");
            assert!(!hits.is_empty(), "query {q:?} should match a field");
        }
    }

    // ── ascii_contains_ci ────────────────────────────────────────────

    /// The zero-allocation matcher folds ASCII case, honors substrings, and
    /// rejects a needle longer than the haystack (empty needle always hits).
    #[test]
    fn ascii_contains_ci_folds_case_and_bounds() {
        assert!(ascii_contains_ci("INVITE", b"invite"));
        assert!(ascii_contains_ci("User-Agent: TestUA/1.0", b"testua"));
        assert!(ascii_contains_ci("anything", b""));
        assert!(!ascii_contains_ci("abc", b"abcd"));
        assert!(!ascii_contains_ci("hello", b"xyz"));
    }

    // ── tail_dialogs ─────────────────────────────────────────────────

    /// A non-RFC-3339 cursor errors with invalid_params (-32602).
    #[tokio::test]
    async fn tail_dialogs_invalid_cursor_errors() {
        let server = empty_server();
        let err = server
            .tail_dialogs(Parameters(TailDialogsParams {
                cursor: Some("not-a-timestamp".to_string()),
                limit: None,
            }))
            .await
            .expect_err("bad cursor must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// Omitting the cursor returns every dialog and sets next_cursor.
    #[tokio::test]
    async fn tail_dialogs_no_cursor_returns_all_with_next_cursor() {
        let server = server_with_dialog("tail@x");
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams::default()))
            .await
            .expect("tail should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["dialogs"].as_array().unwrap().len(), 1);
        assert!(
            v["next_cursor"].is_string(),
            "next_cursor set when dialogs returned"
        );
        assert_eq!(v["source_exhausted"], false);
    }

    /// A cursor after every update filters all dialogs; next_cursor is null.
    #[tokio::test]
    async fn tail_dialogs_future_cursor_filters_everything() {
        let server = server_with_dialog("tailf@x");
        // A cursor strictly after the dialog's updated_at filters it out.
        let future = "2099-01-01T00:00:00Z".to_string();
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams {
                cursor: Some(future),
                limit: None,
            }))
            .await
            .expect("tail should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert!(v["dialogs"].as_array().unwrap().is_empty());
        assert!(v["next_cursor"].is_null(), "no dialogs → null cursor");
    }

    /// Follow `next_cursor` pages to exhaustion and return every call_id
    /// seen, in arrival order. Bounded so a broken cursor cannot loop
    /// forever.
    async fn drain_tail_pages(server: &SipnabMcp, limit: u32) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..20 {
            let result = server
                .tail_dialogs(Parameters(TailDialogsParams {
                    cursor: cursor.clone(),
                    limit: Some(limit),
                }))
                .await
                .expect("tail should succeed");
            let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
            let dialogs = v["dialogs"].as_array().unwrap();
            if dialogs.is_empty() {
                break;
            }
            for d in dialogs {
                seen.push(d["call_id"].as_str().unwrap().to_string());
            }
            cursor = v["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        seen
    }

    /// Paging with a small limit must eventually visit every dialog exactly
    /// once, even when store insertion order disagrees with `updated_at`
    /// order (regression: truncating before sorting let `next_cursor` jump
    /// past dialogs that were never returned).
    #[tokio::test]
    async fn tail_dialogs_paging_visits_every_dialog_exactly_once() {
        let mut ds = DialogStore::new(100, false);
        // Insertion order is the reverse of updated_at order: the first
        // inserted dialog has the newest timestamp. A pass that takes the
        // first `limit` dialogs in store order and only then sorts would
        // return the newest ones first and advance the cursor past the
        // older ones forever.
        for i in 0..5u32 {
            let ts = base_ts() + chrono::Duration::seconds(i64::from(50 - 10 * i));
            ds.process_message(invite(&format!("page{i}@x"), ts));
        }
        let ds = Arc::new(RwLock::new(ds));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let server = SipnabMcp::new(ds, ss);

        let seen = drain_tail_pages(&server, 2).await;

        let mut sorted = seen.clone();
        sorted.sort();
        let expected: Vec<String> = (0..5).map(|i| format!("page{i}@x")).collect();
        assert_eq!(
            sorted, expected,
            "every dialog must be seen exactly once; saw {seen:?}"
        );
    }

    /// Dialogs sharing the same `updated_at` must not be lost when a page
    /// boundary splits the tie group (regression: a bare-timestamp cursor
    /// with a strict `>` filter dropped the unreturned half forever).
    #[tokio::test]
    async fn tail_dialogs_tied_updated_at_survives_page_boundary() {
        let mut ds = DialogStore::new(100, false);
        ds.process_message(invite("tie-a@x", base_ts()));
        ds.process_message(invite("tie-b@x", base_ts()));
        let ds = Arc::new(RwLock::new(ds));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let server = SipnabMcp::new(ds, ss);

        let mut seen = drain_tail_pages(&server, 1).await;
        seen.sort();
        assert_eq!(
            seen,
            vec!["tie-a@x".to_string(), "tie-b@x".to_string()],
            "both tied dialogs must be seen exactly once"
        );
    }

    /// A bare RFC 3339 cursor (the pre-compound format) is still accepted
    /// and keeps its strictly-after semantics.
    #[tokio::test]
    async fn tail_dialogs_bare_timestamp_cursor_still_supported() {
        let server = server_with_dialog("bare@x");
        // Equal to the dialog's updated_at → strictly-after excludes it.
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams {
                cursor: Some(base_ts().to_rfc3339()),
                limit: None,
            }))
            .await
            .expect("tail should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert!(
            v["dialogs"].as_array().unwrap().is_empty(),
            "bare timestamp cursor keeps strictly-after semantics"
        );
    }

    // ── security_findings ────────────────────────────────────────────

    /// Without an attached AlertEngine the tool returns an empty list.
    #[tokio::test]
    async fn security_findings_no_engine_returns_empty() {
        let server = empty_server();
        let result = server
            .security_findings(Parameters(SecurityFindingsParams::default()))
            .await
            .expect("no engine → empty list");
        assert!(text_of(&result).contains("[]"));
    }

    /// A non-RFC-3339 `since` errors with invalid_params (-32602).
    #[tokio::test]
    async fn security_findings_invalid_since_errors() {
        let server = empty_server();
        let err = server
            .security_findings(Parameters(SecurityFindingsParams {
                kinds: None,
                since: Some("garbage".to_string()),
                limit: None,
            }))
            .await
            .expect_err("bad since must error");
        let json = serde_json::to_value(err).unwrap();
        assert_eq!(json["code"], -32602);
    }

    /// A fired finding comes back with its rule name and source IP.
    #[tokio::test]
    async fn security_findings_with_engine_returns_recorded_finding() {
        let mut engine = AlertEngine::new(vec![], None);
        engine.fire(
            "scanner",
            localhost(),
            "probe from scanner",
            chrono::Utc::now(),
        );
        let engine = Arc::new(RwLock::new(engine));

        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let server = SipnabMcp::new(ds, ss).with_alert_engine(engine);

        let result = server
            .security_findings(Parameters(SecurityFindingsParams::default()))
            .await
            .expect("security_findings should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        let arr = v.as_array().expect("findings array");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["rule_name"], "scanner");
        assert_eq!(arr[0]["src_ip"], "127.0.0.1");
    }

    /// The kinds filter excludes findings from other rule names.
    #[tokio::test]
    async fn security_findings_kinds_filter_excludes_other_rules() {
        let mut engine = AlertEngine::new(vec![], None);
        engine.fire("scanner", localhost(), "scan", chrono::Utc::now());
        let engine = Arc::new(RwLock::new(engine));

        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let server = SipnabMcp::new(ds, ss).with_alert_engine(engine);

        let result = server
            .security_findings(Parameters(SecurityFindingsParams {
                kinds: Some(vec!["fraud".to_string()]),
                since: None,
                limit: None,
            }))
            .await
            .expect("security_findings should succeed");
        // Only "scanner" recorded; filtering on "fraud" yields none.
        assert!(text_of(&result).contains("[]"));
    }

    // ── diagnostic + analysis tools ──────────────────────────────────

    /// The registry lookup answers with a class, not a guess.
    #[tokio::test]
    async fn explain_response_code_uses_the_registry() {
        let server = empty_server();
        let r = server
            .explain_response_code(Parameters(ExplainCodeParams { code: 488 }))
            .await
            .expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["code"], 488);
        assert_eq!(v["class"], "failure");
        assert_eq!(v["registered"], true);
        assert!(v["explanation"].as_str().unwrap().contains("Codec"));
    }

    /// 401 is a challenge, not a failure — the distinction the dialog state
    /// machine was fixed for, and an agent must get it too.
    #[tokio::test]
    async fn explain_response_code_calls_401_a_challenge() {
        let r = empty_server()
            .explain_response_code(Parameters(ExplainCodeParams { code: 401 }))
            .await
            .expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["class"], "challenge");
    }

    /// An unregistered code is reported as unregistered rather than invented.
    #[tokio::test]
    async fn explain_response_code_admits_an_unknown_code() {
        let r = empty_server()
            .explain_response_code(Parameters(ExplainCodeParams { code: 699 }))
            .await
            .expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["registered"], false);
        assert!(v["explanation"].is_null());
    }

    /// Out of range is an error, not a shrug.
    #[tokio::test]
    async fn explain_response_code_rejects_a_non_sip_code() {
        assert!(
            empty_server()
                .explain_response_code(Parameters(ExplainCodeParams { code: 42 }))
                .await
                .is_err()
        );
    }

    /// An unknown Call-ID is invalid_params, not an empty result that reads
    /// like a healthy call.
    #[tokio::test]
    async fn triage_call_rejects_an_unknown_call_id() {
        assert!(
            empty_server()
                .triage_call(Parameters(CallIdParams {
                    call_id: "nope@example.com".into()
                }))
                .await
                .is_err()
        );
    }

    /// A dialog with no REGISTER says so rather than reporting healthy
    /// registration for a call that never attempted one.
    #[tokio::test]
    async fn diagnose_registration_declines_a_non_register_dialog() {
        let server = server_with_dialog("reg@x");
        let r = server
            .diagnose_registration(Parameters(CallIdParams {
                call_id: "reg@x".into(),
            }))
            .await
            .expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&r)).unwrap();
        assert_eq!(v["applicable"], false);
    }

    /// A malformed window is rejected before any scanning happens.
    #[tokio::test]
    async fn search_by_time_rejects_a_bad_timestamp() {
        assert!(
            empty_server()
                .search_by_time(Parameters(SearchByTimeParams {
                    start: "yesterday".into(),
                    end: None,
                    filter: None,
                    limit: None,
                }))
                .await
                .is_err()
        );
    }

    /// An end at or before the start is an error, not silently empty.
    #[tokio::test]
    async fn search_by_time_rejects_an_inverted_window() {
        assert!(
            empty_server()
                .search_by_time(Parameters(SearchByTimeParams {
                    start: "2026-01-02T00:00:00Z".into(),
                    end: Some("2026-01-01T00:00:00Z".into()),
                    filter: None,
                    limit: None,
                }))
                .await
                .is_err()
        );
    }

    // ── capture_status / server_capabilities ─────────────────────────

    /// A live capture with no output file must report `unsaved: true`.
    ///
    /// This is the field `shutdown_server` consults before agreeing to stop
    /// anything, and the one that separates "restart whenever" from "an
    /// afternoon of capture ends here". Getting it backwards would make the
    /// destructive tool confidently safe.
    #[tokio::test]
    async fn capture_status_live_without_output_is_unsaved() {
        let server = empty_server().with_capture_context(CaptureContext {
            live: true,
            name: "eth0".into(),
            started: std::time::Instant::now(),
            writing_to: None,
        });
        let result = server.capture_status().await.expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["source"], "live");
        assert_eq!(v["name"], "eth0");
        assert_eq!(
            v["unsaved"], true,
            "live packets held only in memory are unsaved"
        );
    }

    /// The same capture, writing to a file, is not unsaved.
    #[tokio::test]
    async fn capture_status_live_with_output_is_saved() {
        let server = empty_server().with_capture_context(CaptureContext {
            live: true,
            name: "eth0".into(),
            started: std::time::Instant::now(),
            writing_to: Some("/tmp/out.pcap".into()),
        });
        let result = server.capture_status().await.expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["unsaved"], false);
        assert_eq!(v["writing_to"], "/tmp/out.pcap");
    }

    /// A file replay is on disk by definition, so never unsaved.
    #[tokio::test]
    async fn capture_status_file_replay_is_never_unsaved() {
        let server = empty_server().with_capture_context(CaptureContext {
            live: false,
            name: "/caps/a.pcap".into(),
            started: std::time::Instant::now(),
            writing_to: None,
        });
        let result = server.capture_status().await.expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["source"], "file");
        assert_eq!(v["unsaved"], false);
    }

    /// With no context attached the tool says "unknown" rather than guessing.
    ///
    /// A wrong "live" here is worse than an admission of ignorance: it is what
    /// an agent consults to decide whether stopping destroys anything.
    #[tokio::test]
    async fn capture_status_without_context_reports_unknown() {
        let result = empty_server().capture_status().await.expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["source"], "unknown");
        assert_eq!(v["unsaved"], false);
        assert!(v["name"].is_null());
    }

    /// Capabilities are read from `cfg!`, so they cannot claim a feature the
    /// binary does not have. Under `--all-features` mcp is necessarily on,
    /// since this test only compiles when it is.
    #[tokio::test]
    async fn server_capabilities_reports_compiled_features() {
        let result = empty_server()
            .server_capabilities()
            .await
            .expect("succeeds");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        let feats: Vec<String> = serde_json::from_value(v["features"].clone()).unwrap();
        assert!(feats.contains(&"mcp".to_string()), "got {feats:?}");
        assert_eq!(v["can_decrypt"], cfg!(feature = "tls"));
        assert_eq!(v["can_plugins"], cfg!(feature = "plugins"));
    }

    // ── stats ────────────────────────────────────────────────────────

    /// Empty stores report schema_version 2 and all-zero counters.
    #[tokio::test]
    async fn stats_empty_store_all_zero() {
        let server = empty_server();
        let result = server.capture_status().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["schema_version"], 2);
        assert_eq!(v["dialog_count"], 0);
        assert_eq!(v["stream_count"], 0);
        assert_eq!(v["orphaned_stream_count"], 0);
        assert_eq!(v["active_dialog_count"], 0);
        assert_eq!(v["active_call_count"], 0);
    }

    /// `stats` publishes the two gauges as separate keys, and the version says
    /// the meaning of `active_call_count` moved.
    ///
    /// Both are zero on an empty store, so this asserts the KEYS exist and the
    /// version changed — a client reading `active_call_count` under
    /// `schema_version` 1 was handed the six-state number, and nothing but the
    /// version tells it otherwise. The values are proved to differ in
    /// `dialog_store::tests::active_call_count_excludes_setup_and_subscriptions`,
    /// which can build the mixed-state store this fixture cannot.
    #[tokio::test]
    async fn stats_separates_dialog_and_call_gauges() {
        let server = empty_server();
        let result = server.capture_status().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert!(
            v.get("active_dialog_count").is_some(),
            "the six-state number must be published under its own name: {v}"
        );
        assert!(
            v.get("active_call_count").is_some(),
            "the InCall-only gauge must be published: {v}"
        );
        assert!(
            v["schema_version"].as_u64().unwrap_or(0) >= 2,
            "narrowing active_call_count without bumping the version leaves \
             every existing dashboard silently reading a different quantity"
        );
    }

    /// `stats` reports the SIP that `--portrange` excluded, always.
    ///
    /// The CLI has printed this beside its summary since the skip accounting
    /// landed. The MCP surface did not, and returned a byte-identical key set
    /// whether a third of the capture had been dropped or none of it had — so
    /// a model driving the tools could answer questions about "the calls in
    /// this capture" from two thirds of them with full confidence, and had no
    /// way to learn otherwise. On one real capture that was 1,401 dialogs of
    /// 3,712, and 4,247 of 13,455 messages.
    ///
    /// The field is asserted present at ZERO, not merely present when
    /// something was skipped. A field that appears only when something went
    /// wrong is a field the reader never learns exists, and this reader cannot
    /// ask a follow-up question.
    #[tokio::test]
    async fn stats_reports_the_sip_left_outside_the_port_range() {
        crate::pipeline::reset_portrange_skips();
        let server = empty_server();
        let result = server.capture_status().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert!(
            v.get("unanalysed_sip_messages").is_some(),
            "the skipped-SIP count must be present even when it is zero, or a \
             model never learns the concept exists: {v}"
        );
        assert_eq!(v["unanalysed_sip_messages"], 0);
        assert!(
            v["unanalysed_busiest_ports"].is_array(),
            "the per-port breakdown must be an array, empty when nothing was \
             skipped: {v}"
        );
    }

    /// `stats` carries the capture-quality block, always, with the three
    /// losses named separately.
    ///
    /// The counters existed and were warned about on stderr; nothing put them
    /// where a machine could read them, so an agent reasoning over these
    /// counts had no way to learn the run was lossy. Asserted present at zero
    /// for the same reason as `unanalysed_sip_messages` above: a key that
    /// only appears when something is wrong is a key the reader never learns
    /// exists.
    ///
    /// The three counters are asserted to be three distinct keys. Summing
    /// them would name one problem where there are three, with three
    /// different remedies — and "raise the buffer" is the wrong answer to
    /// two of them.
    #[tokio::test]
    async fn stats_reports_capture_quality_with_the_three_losses_apart() {
        let server = empty_server();
        let result = server.capture_status().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        let q = &v["capture_quality"];
        assert!(q.is_object(), "capture_quality must always be present: {v}");
        for field in [
            "kernel_dropped_packets",
            "interface_dropped_packets",
            "invalid_timestamps",
            // The fourth channel: frames that arrived intact and that no
            // decoder here could read. Without it a reader cannot tell a
            // dialog_count of 0 that means "none" from one that means
            // "sipnab could not read this capture".
            "undecodable_frames",
        ] {
            assert!(
                q[field].is_u64(),
                "capture_quality.{field} must be a count even at zero: {q}"
            );
        }
        assert!(
            q["degraded"].is_boolean(),
            "capture_quality.degraded must be a boolean: {q}"
        );
    }

    /// The degraded flag follows the counters rather than being independent
    /// state, in both directions and for each of the three counters alone.
    #[test]
    fn capture_quality_degraded_tracks_each_counter() {
        use crate::output::prometheus::CaptureQuality;

        let clean: CaptureQualityJson = CaptureQuality::default().into();
        assert!(!clean.degraded);

        for quality in [
            CaptureQuality {
                kernel_dropped_packets: 1,
                ..Default::default()
            },
            CaptureQuality {
                interface_dropped_packets: 1,
                ..Default::default()
            },
            CaptureQuality {
                invalid_timestamps: 1,
                ..Default::default()
            },
        ] {
            let json: CaptureQualityJson = quality.into();
            assert!(json.degraded, "{quality:?} must serialize as degraded");
        }
    }

    /// A store with one dialog and no streams reports counts 1 and 0.
    #[tokio::test]
    async fn stats_counts_dialogs() {
        let server = server_with_dialog("stat@x");
        let result = server.capture_status().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["dialog_count"], 1);
        assert_eq!(v["stream_count"], 0);
    }

    // ── open_capture and capture identity ────────────────────────────

    /// A server whose source has already drained, which is what
    /// `open_capture` requires before it will replace anything.
    fn exhausted_server() -> SipnabMcp {
        empty_server()
            .with_source_exhausted(Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .with_capture_context(CaptureContext {
                live: false,
                name: "first.pcap".into(),
                started: std::time::Instant::now(),
                writing_to: None,
            })
    }

    /// A temp directory that is a valid `--mcp-file-root`, holding a copy of
    /// the G.711 fixture under `name`.
    fn root_with_capture(dir: &str, name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("sipnab-open-capture-{dir}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create the file root");
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/pcap-samples/sip-rtp-g711.pcap"),
            root.join(name),
        )
        .expect("stage the fixture");
        root
    }

    /// Without the flag the tool refuses and names the flag, so an agent
    /// learns what to ask the operator for rather than that sipnab is broken.
    #[tokio::test]
    async fn open_capture_is_refused_without_the_opt_in_flag() {
        let server = exhausted_server();
        let err = server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "other.pcap".into(),
            }))
            .await
            .expect_err("must refuse");
        assert!(
            err.message.contains("--mcp-allow-open-capture"),
            "the refusal must name the flag; got {err:?}"
        );
    }

    /// The refusal comes BEFORE any path handling: a server that did not opt
    /// in must not reveal whether the file exists, and must not report the
    /// file-root error instead of the one that actually applies.
    #[tokio::test]
    async fn the_opt_in_refusal_precedes_the_path_check() {
        let server = exhausted_server();
        let err = server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "../escape.pcap".into(),
            }))
            .await
            .expect_err("must refuse");
        assert!(
            err.message.contains("--mcp-allow-open-capture"),
            "the flag refusal must come first; got {err:?}"
        );
    }

    /// With the flag but no `--mcp-file-root`, the shared resolver refuses and
    /// names the missing flag — the same rule every file tool applies.
    #[tokio::test]
    async fn open_capture_needs_a_file_root() {
        let server = exhausted_server().with_open_capture();
        let err = server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "other.pcap".into(),
            }))
            .await
            .expect_err("must refuse");
        assert!(
            err.message.contains("--mcp-file-root"),
            "the refusal must name the root flag; got {err:?}"
        );
    }

    /// A path is refused exactly as it is for every other file tool, because
    /// this reuses `resolve_in_root` rather than resolving paths its own way.
    #[tokio::test]
    async fn open_capture_refuses_anything_that_is_not_a_bare_filename() {
        let root = root_with_capture("traversal", "ok.pcap");
        let server = exhausted_server().with_open_capture().with_file_root(&root);
        for bad in ["../escape.pcap", "/etc/passwd", "sub/dir.pcap", ".."] {
            let err = server
                .open_capture(Parameters(OpenCaptureParams {
                    filename: bad.to_string(),
                }))
                .await
                .expect_err("must refuse a path");
            assert!(
                err.message.contains("bare filename") || err.message.contains("resolves outside"),
                "'{bad}' must be refused for what it is; got {err:?}"
            );
        }
    }

    /// A live capture's writer never finishes, so a second writer would race
    /// it for the life of the process. That refusal has no opt-out.
    #[tokio::test]
    async fn open_capture_refuses_while_the_source_is_live() {
        let root = root_with_capture("live", "next.pcap");
        let server = empty_server()
            .with_open_capture()
            .with_file_root(&root)
            .with_source_exhausted(Arc::new(std::sync::atomic::AtomicBool::new(true)))
            .with_capture_context(CaptureContext {
                live: true,
                name: "eth0".into(),
                started: std::time::Instant::now(),
                writing_to: None,
            });
        let err = server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "next.pcap".into(),
            }))
            .await
            .expect_err("must refuse a live source");
        assert!(
            err.message.contains("capturing live"),
            "the refusal must say why; got {err:?}"
        );
    }

    /// While the original reader is still filling the stores it is the one
    /// writer, and the tool waits rather than joining it.
    #[tokio::test]
    async fn open_capture_refuses_while_the_source_is_still_reading() {
        let root = root_with_capture("unexhausted", "next.pcap");
        let server = empty_server()
            .with_open_capture()
            .with_file_root(&root)
            .with_source_exhausted(Arc::new(std::sync::atomic::AtomicBool::new(false)))
            .with_capture_context(CaptureContext {
                live: false,
                name: "first.pcap".into(),
                started: std::time::Instant::now(),
                writing_to: None,
            });
        let err = server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "next.pcap".into(),
            }))
            .await
            .expect_err("must refuse an unfinished source");
        assert!(
            err.message.contains("source_exhausted"),
            "the refusal must name the field to poll; got {err:?}"
        );
    }

    /// The swap must reach every clone, because HTTP clones the server per
    /// session. This is the defect the shared lock exists to prevent: the
    /// calling session saw the new capture and every other session kept
    /// reading the old name.
    #[tokio::test]
    async fn a_swap_is_visible_to_every_clone_of_the_server() {
        let root = root_with_capture("clone", "second.pcap");
        let server = exhausted_server().with_open_capture().with_file_root(&root);
        // The clone stands in for a second HTTP session.
        let other_session = server.clone();

        let before: serde_json::Value = serde_json::from_str(&text_of(
            &other_session.capture_status().await.expect("status"),
        ))
        .unwrap();
        assert_eq!(before["name"], "first.pcap");

        server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "second.pcap".into(),
            }))
            .await
            .expect("the swap should be accepted");

        let after: serde_json::Value = serde_json::from_str(&text_of(
            &other_session.capture_status().await.expect("status"),
        ))
        .unwrap();
        assert!(
            after["name"]
                .as_str()
                .unwrap_or_default()
                .ends_with("second.pcap"),
            "the other session still names {}; the swap did not reach it",
            after["name"]
        );
        assert_ne!(
            before["capture_identity"]["instance"], after["capture_identity"]["instance"],
            "the capture instance must change on a swap, in every session"
        );
    }

    /// Two loads at once would have two writers filling one store. The second
    /// call is refused while the first is running.
    #[tokio::test]
    async fn a_second_load_is_refused_while_one_is_running() {
        let root = root_with_capture("concurrent", "second.pcap");
        let server = exhausted_server().with_open_capture().with_file_root(&root);
        server
            .open_capture(Parameters(OpenCaptureParams {
                filename: "second.pcap".into(),
            }))
            .await
            .expect("the first swap should be accepted");

        // Racy by nature: the load may already have finished on a fast box,
        // in which case a second call is legitimately allowed. Assert the
        // refusal only when it is actually still running.
        let running = {
            let state = server.capture.read();
            let running = state.load.as_ref().is_some_and(|l| !l.finished());
            drop(state);
            running
        };
        if running {
            let err = server
                .open_capture(Parameters(OpenCaptureParams {
                    filename: "second.pcap".into(),
                }))
                .await
                .expect_err("a concurrent load must be refused");
            assert!(
                err.message.contains("still loading"),
                "the refusal must name the running load; got {err:?}"
            );
        }
    }

    /// Every response that describes the whole store carries the identity, so
    /// a consumer holding a cursor can tell a continuation from a new capture.
    #[tokio::test]
    async fn whole_store_responses_carry_the_capture_identity() {
        let server = server_with_dialog("ident@x");
        let calls: Vec<(&str, serde_json::Value)> = vec![
            (
                "capture_status",
                serde_json::from_str(&text_of(&server.capture_status().await.expect("status")))
                    .unwrap(),
            ),
            (
                "capture_status",
                serde_json::from_str(&text_of(&server.capture_status().await.expect("stats")))
                    .unwrap(),
            ),
            (
                "list_dialogs",
                serde_json::from_str(&text_of(
                    &server
                        .list_dialogs(Parameters(ListDialogsParams::default()))
                        .await
                        .expect("list"),
                ))
                .unwrap(),
            ),
            (
                "tail_dialogs",
                serde_json::from_str(&text_of(
                    &server
                        .tail_dialogs(Parameters(TailDialogsParams {
                            cursor: None,
                            limit: None,
                        }))
                        .await
                        .expect("tail"),
                ))
                .unwrap(),
            ),
        ];
        for (tool, v) in calls {
            let id = &v["capture_identity"];
            assert!(
                id["instance"].as_str().is_some_and(|s| !s.is_empty()),
                "{tool} carries no capture instance: {v}"
            );
            assert!(
                id["dialog_generation"].is_u64() && id["stream_generation"].is_u64(),
                "{tool} carries no store generations: {v}"
            );
        }
    }

    /// `capture_health` carries no `capture_identity`, and that is a decision.
    ///
    /// Pinned because the omission reads as an oversight and a later change
    /// would "fix" it: `capture_health` reads relaxed atomics and nothing
    /// else, so it can be polled against a live production capture, and a
    /// store generation costs the store locks that property exists to avoid.
    /// Asserted as an ABSENCE rather than left undocumented, so that adding
    /// the field has to be a deliberate act that deletes this test — which is
    /// the moment to re-argue the locking, not to discover it later from a
    /// health poll that started blocking.
    #[tokio::test]
    async fn capture_health_carries_no_capture_identity() {
        let server = server_with_dialog("health@x");
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                // One second, the smallest window the tool accepts: this test
                // is about the response SHAPE, and the window only decides how
                // long it sleeps first.
                .capture_health(Parameters(CaptureHealthParams { sample_seconds: 1 }))
                .await
                .expect("health"),
        ))
        .unwrap();
        assert!(
            v["capture_identity"].is_null(),
            "capture_health grew a capture_identity: {v}"
        );
        // Not a response that failed to serialise: it answered, with content.
        assert!(
            v["schema_version"].is_u64(),
            "capture_health did not answer at all: {v}"
        );
    }

    /// The generation must move when the store does, or the etag says
    /// "unchanged" about a store that changed.
    #[tokio::test]
    async fn the_generation_moves_when_the_store_does() {
        let server = server_with_dialog("gen@x");
        let before: serde_json::Value =
            serde_json::from_str(&text_of(&server.capture_status().await.expect("stats"))).unwrap();
        {
            let mut ds = server.dialog_store.write();
            ds.process_message(invite("gen2@x", base_ts()));
        }
        let after: serde_json::Value =
            serde_json::from_str(&text_of(&server.capture_status().await.expect("stats"))).unwrap();
        assert_eq!(
            before["capture_identity"]["instance"], after["capture_identity"]["instance"],
            "a new message is the same capture"
        );
        assert!(
            after["capture_identity"]["dialog_generation"]
                .as_u64()
                .unwrap_or(0)
                > before["capture_identity"]["dialog_generation"]
                    .as_u64()
                    .unwrap_or(0),
            "the dialog generation must move: {before} then {after}"
        );
    }

    /// The operator's opt-ins are reportable, so an agent can check before it
    /// is refused rather than after.
    #[tokio::test]
    async fn server_capabilities_reports_the_runtime_flags() {
        let plain: serde_json::Value = serde_json::from_str(&text_of(
            &empty_server().server_capabilities().await.expect("caps"),
        ))
        .unwrap();
        assert_eq!(plain["runtime"]["mcp_allow_open_capture"], false);
        assert_eq!(plain["runtime"]["mcp_allow_shutdown"], false);
        assert!(plain["runtime"]["mcp_file_root"].is_null());

        let opted: serde_json::Value = serde_json::from_str(&text_of(
            &empty_server()
                .with_open_capture()
                .with_shutdown()
                .with_file_root("/var/spool/sipnab-exports")
                .server_capabilities()
                .await
                .expect("caps"),
        ))
        .unwrap();
        assert_eq!(opted["runtime"]["mcp_allow_open_capture"], true);
        assert_eq!(opted["runtime"]["mcp_allow_shutdown"], true);
        assert_eq!(
            opted["runtime"]["mcp_file_root"],
            "/var/spool/sipnab-exports"
        );
    }

    // ── The conformance-linter tools ────────────────────────────────

    /// Every selector `rule_selector_names` advertises parses back, and it
    /// advertises every RFC the catalogue actually cites.
    ///
    /// The RFC half is derived from `RULES` rather than listed, so this is the
    /// gate that keeps the derivation honest: a rule citing a new RFC has to
    /// become selectable, and the refusal that names the vocabulary has to
    /// name it too.
    #[test]
    fn every_advertised_rule_selector_parses() {
        let names = rule_selector_names();
        for name in &names {
            assert!(
                RuleSelector::parse(name).is_some(),
                "{name} is advertised as a selector and does not parse"
            );
        }
        for rule in crate::sip::lint::RULES {
            let expected = format!("rfc{}", rule.rfc);
            assert!(
                names.contains(&expected),
                "{} cites RFC {} and no {expected} selector is offered",
                rule.id,
                rule.rfc
            );
        }
        assert!(RuleSelector::parse("observed").is_some(), "alias for basis");
        assert!(RuleSelector::parse("rfc").is_some(), "catalogue name");
        assert!(RuleSelector::parse("rfc99x").is_none(), "not a number");
        assert!(RuleSelector::parse("nonsense").is_none());
        // One keystroke from rfc3261, and nothing cites it. Accepting it would
        // return an empty finding list that reads as a clean call.
        assert!(RuleSelector::parse("rfc3621").is_none(), "uncited RFC");
    }

    /// `explain_rule` reports the selectors that would include the rule, and
    /// only those.
    ///
    /// The field exists to be passed straight back as `lint_dialog.rulesets`.
    /// A selector listed there that does not select the rule sends a caller
    /// away with an empty finding list and no reason for it.
    #[tokio::test]
    async fn explain_rule_lists_selectors_that_really_select_it() {
        for rule in crate::sip::lint::RULES {
            let result = empty_server()
                .explain_rule(Parameters(ExplainRuleParams {
                    rule_id: rule.id.to_string(),
                }))
                .await
                .expect("explain_rule");
            let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

            assert_eq!(v["rfc"], rule.rfc, "{}", rule.id);
            assert_eq!(v["section"], rule.section, "{}", rule.id);
            assert_eq!(v["url"], rule.url(), "{}", rule.id);

            let listed: Vec<String> = serde_json::from_value(v["rulesets"].clone()).unwrap();
            let expected: Vec<String> = rule_selector_names()
                .into_iter()
                .filter(|n| RuleSelector::parse(n).is_some_and(|s| s.contains(rule)))
                .collect();
            assert_eq!(listed, expected, "{}", rule.id);
            assert!(
                listed.contains(&"all".to_string()) && listed.contains(&format!("rfc{}", rule.rfc)),
                "{} must be reachable by `all` and by its own RFC: {listed:?}",
                rule.id
            );
        }
    }

    /// An unknown rule identifier is refused, and the refusal names the
    /// catalogue rather than returning an empty answer that reads as "clean".
    #[tokio::test]
    async fn explain_rule_refuses_an_unknown_identifier_by_name() {
        let err = empty_server()
            .explain_rule(Parameters(ExplainRuleParams {
                rule_id: "SIP-9999-1-INVENTED".to_string(),
            }))
            .await
            .expect_err("an unknown rule must not succeed");
        assert!(
            err.message.contains("SIP-9999-1-INVENTED")
                && err.message.contains(crate::sip::lint::BRANCH_COOKIE.id),
            "the refusal must name the bad identifier and the real ones: {}",
            err.message
        );
    }

    /// An unknown ruleset selector is refused by name.
    ///
    /// Ignoring it and running the whole catalogue is the dangerous
    /// alternative: the caller reads more findings than it selected and
    /// believes the filter worked.
    #[test]
    fn an_unknown_ruleset_is_refused_and_the_vocabulary_named() {
        let err = parse_rule_selectors(Some(&vec!["rfc3621".to_string()]))
            .expect_err("a typo'd RFC number must not silently widen the run");
        assert!(
            err.message.contains("rfc3621") && err.message.contains("observation"),
            "the refusal must name the bad selector and the valid ones: {}",
            err.message
        );
        assert!(
            parse_rule_selectors(None)
                .expect("omitted is legal")
                .is_empty(),
            "no selector means no filtering"
        );
    }

    /// An unknown severity is refused by name too.
    #[test]
    fn an_unknown_severity_is_refused_by_name() {
        let err = parse_min_severity(Some(&"catastrophe".to_string()))
            .expect_err("an unknown severity must not silently become info");
        assert!(err.message.contains("catastrophe"), "{}", err.message);
        assert_eq!(
            parse_min_severity(Some(&"WARN".to_string())).expect("alias"),
            crate::sip::lint::Severity::Warning
        );
    }

    /// The rules that could not run are reported, grouped by reason.
    ///
    /// A rule that did not run and a rule that found nothing produce identical
    /// finding lists, so without this an agent reads "no findings" as "clean".
    #[test]
    fn a_run_names_the_rules_it_could_not_evaluate() {
        let with_media = skipped_rules(LintRun::WholeDialog { media: true });
        let ids: Vec<&str> = with_media
            .iter()
            .flat_map(|g| g["rule_ids"].as_array().unwrap())
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [crate::sip::lint::RTCP_MUX_UNANSWERED.id],
            "with media in hand only the RTCP rule is out of reach"
        );

        let no_media = skipped_rules(LintRun::WholeDialog { media: false });
        let ids: Vec<&str> = no_media
            .iter()
            .flat_map(|g| g["rule_ids"].as_array().unwrap())
            .map(|v| v.as_str().unwrap())
            .collect();
        for rule in crate::sip::lint::RULES {
            if rule.scope() == crate::sip::lint::Scope::Media {
                assert!(ids.contains(&rule.id), "{} needs media", rule.id);
            }
        }

        // One message reaches neither the dialog rules nor the media ones, and
        // the reasons are grouped rather than repeated per rule.
        let one = skipped_rules(LintRun::OneMessage);
        assert_eq!(one.len(), 3, "three reasons, not twelve copies: {one:?}");
        let skipped: usize = one
            .iter()
            .map(|g| g["rule_ids"].as_array().unwrap().len())
            .sum();
        let message_scoped = crate::sip::lint::RULES
            .iter()
            .filter(|r| r.scope() == crate::sip::lint::Scope::Message)
            .count();
        assert_eq!(
            skipped + message_scoped,
            crate::sip::lint::RULES.len(),
            "every rule is either message-scoped or accounted for as skipped"
        );
    }

    /// `lint_dialog` returns the citation as data, not folded into prose.
    ///
    /// The whole reason `rfc` and `section` are fields is that an agent can
    /// cite RFC 3261 §8.1.1.6 instead of inventing a section that reads
    /// plausibly. Flattening them into the explanation would leave the tool
    /// working and the guarantee gone.
    #[tokio::test]
    async fn lint_dialog_returns_rfc_and_section_as_separate_fields() {
        // The stock INVITE fixture carries no Max-Forwards, which §8.1.1.6
        // makes a UAC insert into every request it originates.
        let server = server_with_dialog("lint-1@example.com");
        let result = server
            .lint_dialog(Parameters(LintDialogParams {
                call_id: "lint-1@example.com".to_string(),
                rulesets: None,
                severity_min: None,
                suppression_file: None,
            }))
            .await
            .expect("lint_dialog");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        let findings = v["findings"].as_array().expect("findings array");
        let hit = findings
            .iter()
            .find(|f| f["rule_id"] == crate::sip::lint::MAX_FORWARDS_MISSING.id)
            .unwrap_or_else(|| panic!("the INVITE has no Max-Forwards: {v}"));
        assert_eq!(hit["rfc"], 3261, "rfc is a number, not prose");
        assert_eq!(hit["section"], "8.1.1.6", "section is a string, not prose");
        assert_eq!(hit["severity"], "warning");
        assert_eq!(hit["basis"], "must");
        assert!(hit["observed"].is_string() && hit["expected"].is_string());
        assert_eq!(hit["message_index"], 0);
        assert_eq!(v["rtp_streams_observed"], 0);
    }

    /// A ruleset selector narrows the run, and an RFC selector that no rule
    /// cites returns nothing rather than everything.
    #[tokio::test]
    async fn lint_dialog_rulesets_narrow_the_findings() {
        let server = server_with_dialog("lint-2@example.com");
        let run = async |sets: Option<Vec<&str>>, min: Option<&str>| {
            let result = server
                .lint_dialog(Parameters(LintDialogParams {
                    call_id: "lint-2@example.com".to_string(),
                    rulesets: sets
                        .map(|s| s.into_iter().map(str::to_string).collect::<Vec<String>>()),
                    severity_min: min.map(str::to_string),
                    suppression_file: None,
                }))
                .await
                .expect("lint_dialog");
            serde_json::from_str::<serde_json::Value>(&text_of(&result)).unwrap()
        };

        let all = run(None, None).await;
        assert!(all["finding_count"].as_u64().unwrap_or(0) > 0);

        // Every finding here cites RFC 3261, so RFC 3264 must select none of
        // them — an empty answer, not the full catalogue.
        let other_rfc = run(Some(vec!["rfc3264"]), None).await;
        assert_eq!(other_rfc["finding_count"], 0, "{other_rfc}");
        assert_eq!(other_rfc["rulesets"][0], "rfc3264");

        let same_rfc = run(Some(vec!["rfc3261"]), None).await;
        assert_eq!(same_rfc["finding_count"], all["finding_count"]);

        // `severity_min` drops the quieter findings, and it is the engine's
        // own filter rather than a second implementation here.
        let loud = run(None, Some("error")).await;
        assert_eq!(loud["finding_count"], 0, "nothing here is an error: {loud}");
        assert_eq!(loud["severity_min"], "error");

        // An empty list runs everything, and the echo has to agree with that.
        // Reporting `rulesets: []` beside a full run describes a filter that
        // selected nothing, next to findings that came from every rule.
        let empty = run(Some(vec![]), None).await;
        assert_eq!(empty["finding_count"], all["finding_count"]);
        assert_eq!(
            empty["rulesets"],
            serde_json::json!(["all"]),
            "an empty selector list runs the whole catalogue and must say so: \
             {empty}"
        );
    }

    /// The suppression disclosure is present even when nothing was suppressed.
    ///
    /// A response with no field and a response with zero must not be the same
    /// bytes. The first says nothing about whether findings were hidden; the
    /// second says none were. Same reasoning as `stats` carrying
    /// `unanalysed_sip_messages` at zero.
    #[tokio::test]
    async fn a_run_with_no_suppressions_still_reports_the_disclosure() {
        let server = server_with_dialog("supp-0@example.com");
        let result = server
            .lint_dialog(Parameters(LintDialogParams {
                call_id: "supp-0@example.com".to_string(),
                rulesets: None,
                severity_min: None,
                suppression_file: None,
            }))
            .await
            .expect("lint_dialog");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert!(
            v.get("suppressions").is_some(),
            "the field must exist even with no .sipnablint in play: {v}"
        );
        assert_eq!(v["suppressions"]["file"], serde_json::Value::Null);
        assert_eq!(v["suppressions"]["patterns"], serde_json::json!([]));
        assert_eq!(v["suppressions"]["findings_suppressed"], 0);
        assert_eq!(
            v["findings_withheld"],
            serde_json::json!({"suppressed": 0, "below_severity": 0, "capped": 0}),
            "all three counters reported, at zero"
        );
    }

    /// An explicit suppression file applies, is named, and its effect is counted.
    #[tokio::test]
    async fn an_explicit_suppression_file_is_applied_named_and_counted() {
        let root =
            std::env::temp_dir().join(format!("sipnab-mcp-supp-explicit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(
            root.join(".sipnablint"),
            "# the carrier strips these\nSIP-3261-8.1.1.6-MAX-FORWARDS-MISSING\n",
        )
        .expect("write");

        let server = server_with_dialog("supp-1@example.com").with_file_root(&root);

        let before = {
            let r = server
                .lint_dialog(Parameters(LintDialogParams {
                    call_id: "supp-1@example.com".to_string(),
                    rulesets: None,
                    severity_min: None,
                    suppression_file: None,
                }))
                .await
                .expect("lint_dialog");
            serde_json::from_str::<serde_json::Value>(&text_of(&r)).unwrap()
        };
        let hits = before["finding_count"].as_u64().unwrap_or(0);
        assert!(hits > 0, "the fixture INVITE has no Max-Forwards: {before}");

        let after = {
            let r = server
                .lint_dialog(Parameters(LintDialogParams {
                    call_id: "supp-1@example.com".to_string(),
                    rulesets: None,
                    severity_min: None,
                    suppression_file: Some(".sipnablint".to_string()),
                }))
                .await
                .expect("lint_dialog");
            serde_json::from_str::<serde_json::Value>(&text_of(&r)).unwrap()
        };

        assert_eq!(
            after["finding_count"], 0,
            "the rule was suppressed: {after}"
        );
        assert_eq!(
            after["suppressions"]["findings_suppressed"], hits,
            "every finding the file silenced is counted, so a clean-looking \
             result cannot be mistaken for a clean call: {after}"
        );
        assert_eq!(after["findings_withheld"]["suppressed"], hits);
        assert!(
            after["suppressions"]["file"]
                .as_str()
                .is_some_and(|f| f.ends_with(".sipnablint")),
            "the response must name the file that did it: {after}"
        );
        assert_eq!(
            after["suppressions"]["patterns"],
            serde_json::json!(["SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING"])
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A named suppression file that cannot be read is an error.
    ///
    /// Falling back to a full-catalogue run would hand the caller findings
    /// their file was meant to silence, and they would read the difference as
    /// "my patterns matched nothing".
    #[tokio::test]
    async fn a_named_suppression_file_that_is_missing_is_refused() {
        let root =
            std::env::temp_dir().join(format!("sipnab-mcp-supp-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("root");
        let server = server_with_dialog("supp-2@example.com").with_file_root(&root);

        let err = server
            .lint_dialog(Parameters(LintDialogParams {
                call_id: "supp-2@example.com".to_string(),
                rulesets: None,
                severity_min: None,
                suppression_file: Some("absent.sipnablint".to_string()),
            }))
            .await
            .expect_err("a named file that is not there must not silently lint everything");
        assert!(
            err.message.contains("absent.sipnablint"),
            "the refusal names the file: {}",
            err.message
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `validate_message` carries the same disclosure as `lint_dialog`.
    #[tokio::test]
    async fn validate_message_reports_the_suppression_disclosure_too() {
        let server = server_with_dialog("supp-3@example.com");
        let result = server
            .validate_message(Parameters(ValidateMessageParams {
                call_id: "supp-3@example.com".to_string(),
                index: 0,
                suppression_file: None,
            }))
            .await
            .expect("validate_message");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert!(v.get("suppressions").is_some(), "{v}");
        assert_eq!(v["findings_withheld"]["suppressed"], 0);
        assert_eq!(v["findings_withheld"]["below_severity"], 0);
        assert_eq!(v["findings_withheld"]["capped"], 0);
    }

    /// A severity floor is reported as its own reason, not as suppression.
    #[tokio::test]
    async fn the_severity_floor_is_counted_apart_from_suppression() {
        let server = server_with_dialog("supp-4@example.com");
        let result = server
            .lint_dialog(Parameters(LintDialogParams {
                call_id: "supp-4@example.com".to_string(),
                rulesets: None,
                severity_min: Some("error".to_string()),
                suppression_file: None,
            }))
            .await
            .expect("lint_dialog");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["finding_count"], 0);
        assert!(
            v["findings_withheld"]["below_severity"]
                .as_u64()
                .unwrap_or(0)
                > 0,
            "the findings dropped by the floor are counted under the floor: {v}"
        );
        assert_eq!(
            v["findings_withheld"]["suppressed"], 0,
            "and not attributed to a suppression file nobody wrote"
        );
    }

    /// `validate_message` reads one message and says which rules it could not
    /// reach, so its shorter list is not read as a cleaner message.
    #[tokio::test]
    async fn validate_message_reports_the_rules_it_could_not_reach() {
        let server = server_with_dialog("lint-3@example.com");
        let result = server
            .validate_message(Parameters(ValidateMessageParams {
                call_id: "lint-3@example.com".to_string(),
                index: 0,
                suppression_file: None,
            }))
            .await
            .expect("validate_message");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();

        assert_eq!(v["message_index"], 0);
        assert_eq!(v["message_count"], 2);
        let ids: Vec<&str> = v["rules_not_evaluated"]
            .as_array()
            .expect("groups")
            .iter()
            .flat_map(|g| g["rule_ids"].as_array().unwrap())
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(
            ids.contains(&crate::sip::lint::PT_UNDECLARED.id)
                && ids.contains(&crate::sip::lint::ACK_CSEQ_MISMATCH.id),
            "a message-only run reaches neither the media nor the dialog \
             rules and has to say so: {ids:?}"
        );

        let err = server
            .validate_message(Parameters(ValidateMessageParams {
                call_id: "lint-3@example.com".to_string(),
                index: 99,
                suppression_file: None,
            }))
            .await
            .expect_err("out of range");
        assert!(err.message.contains("out of range"), "{}", err.message);
    }

    /// `validate_message` findings cite the frame they were drawn from — and
    /// stay silent when the message carries no pointer.
    ///
    /// `lint_dialog` ran its findings through `findings_with_refs` and this
    /// sibling serialized the same `Vec<Finding>` raw, so the identical
    /// finding was checkable from one tool and an unfollowable assertion from
    /// the other. The fix is one expression; what this test is really for is
    /// making it non-vacuous, which means a message that ACTUALLY trips a
    /// rule. A clean fixture asserts nothing: an empty `findings` array
    /// satisfies "every finding carries a pointer" without exercising a line
    /// of the projection.
    ///
    /// `BRANCH_COOKIE` (RFC 3261 §8.1.1.7) is the rule chosen because it is
    /// message-scoped — `validate_message` reads one message alone, so a
    /// dialog- or media-scoped rule would not run at all — and because a
    /// branch without the `z9hG4bK` prefix is a one-header edit that cannot
    /// accidentally stop firing.
    ///
    /// Three messages, not one, and the middle one is why. A finding carries
    /// the message's index WITHIN THE DIALOG, so the projection has to be
    /// handed the whole message list: a `slice::from_ref(msg)` would look
    /// right on message 0 and cite nothing from then on, and an index that
    /// slipped by one would cite a neighbouring frame — which is worse than
    /// citing none, because it resolves.
    ///
    /// The third message is the half that matters most. A finding on a message
    /// with no frame must emit NO `frame_ref` key: `""` and `"x#0"` both read
    /// as a real pointer, and a finding citing frame 0 of nothing is exactly
    /// the manufactured confidence #128 exists to prevent.
    #[tokio::test]
    async fn validate_message_findings_cite_their_frame_or_say_nothing() {
        use crate::capture::packet::{FrameOrigin, FrameRef};

        // Every request carries a pre-RFC-3261 branch, so BRANCH_COOKIE fires
        // on each; the CSeq differs so each is a new request rather than a
        // retransmission of the one before it.
        let pre_3261 = |cseq: u32| {
            build_sip(
                "INVITE sip:bob@example.com SIP/2.0",
                &[
                    &format!("Via: SIP/2.0/UDP 127.0.0.1:5060;branch=oldstack-{cseq}"),
                    "From: Alice <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.com>",
                    "Call-ID: vm-frame@example.com",
                    &format!("CSeq: {cseq} INVITE"),
                    "Content-Length: 0",
                ],
                b"",
            )
        };
        // Distinct ordinals AND distinct digests, so a pointer that came from
        // the wrong message cannot pass by coincidence.
        let framed = |cseq: u32, ordinal: u64, digest: u64| {
            let mut msg = parse_at(&pre_3261(cseq), base_ts());
            msg.frame = Some(FrameRef {
                source: "calls.pcap".into(),
                origin: FrameOrigin {
                    ordinal,
                    digest: Some(digest),
                },
            });
            msg
        };

        let mut unciteable = parse_at(&pre_3261(3), base_ts());
        unciteable.frame = None;

        let mut ds = DialogStore::new(100, false);
        ds.process_message(framed(1, 41, 0x6d1f_4c0a_9b2e_7a53));
        ds.process_message(framed(2, 77, 0x0b3c_8e19_54d7_a260));
        ds.process_message(unciteable);
        let server = SipnabMcp::new(
            Arc::new(RwLock::new(ds)),
            Arc::new(RwLock::new(StreamStore::new(100))),
        );

        let validate = async |index: u32| {
            let result = server
                .validate_message(Parameters(ValidateMessageParams {
                    call_id: "vm-frame@example.com".to_string(),
                    index,
                    suppression_file: None,
                }))
                .await
                .expect("validate_message");
            let v: serde_json::Value = serde_json::from_str(&text_of(&result)).expect("valid JSON");
            let findings = v["findings"].as_array().expect("findings").clone();
            // Without this the rest of the test is a property of an empty
            // list: "every finding carries a pointer" is satisfied by a clean
            // message, and not one line of the projection runs.
            assert!(
                findings
                    .iter()
                    .any(|f| f["rule_id"] == crate::sip::lint::BRANCH_COOKIE.id),
                "message {index} has to actually trip a message-scoped \
                 rule: {v}"
            );
            findings
        };

        for f in validate(0).await {
            assert_eq!(
                f["frame_ref"], "calls.pcap#41@6d1f4c0a9b2e7a53",
                "a finding on a message with a pointer must carry it, digest \
                 and all -- the same projection lint_dialog uses: {f:?}"
            );
        }
        for f in validate(1).await {
            assert_eq!(
                f["frame_ref"], "calls.pcap#77@0b3c8e1954d7a260",
                "and must cite ITS OWN frame: message 1 is where a projection \
                 handed one message, or an index off by one, stops agreeing \
                 with a projection handed the dialog: {f:?}"
            );
        }
        for f in validate(2).await {
            assert!(
                f.get("frame_ref").is_none(),
                "a finding on a message with NO pointer must omit the key \
                 entirely, not emit an empty or zero one: {f:?}"
            );
        }
    }

    // ── capture_health ──────────────────────────────────────────────────
    //
    // This tool is meant to run on a busy production server carrying other
    // people's calls, reached over MCP from somewhere else. Its response is
    // therefore the one place in this file where a leak of packet content
    // would be worst, and the design answer is structural rather than
    // documentary: the response type is integers and codes, so it cannot
    // represent a byte of a packet. The tests below are what hold that.

    /// Every value in a serialized `CaptureHealth` — at any depth.
    ///
    /// Object KEYS are skipped deliberately. A key is a field name written in
    /// this file and fixed at compile time; a VALUE is the only place a byte
    /// off the wire could ever land. Walking keys would flag every struct
    /// field and make the gate meaningless.
    fn json_leaves(value: &serde_json::Value, strings: &mut Vec<String>, leaves: &mut usize) {
        match value {
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    json_leaves(v, strings, leaves);
                }
            }
            serde_json::Value::Array(items) => {
                for v in items {
                    json_leaves(v, strings, leaves);
                }
            }
            serde_json::Value::String(s) => {
                strings.push(s.clone());
                *leaves += 1;
            }
            _ => *leaves += 1,
        }
    }

    /// The walker finds a string nested inside an array inside an object.
    ///
    /// Without this the no-string gate could pass because the walker never
    /// recursed, which is the way a recursive checker fails silently.
    #[test]
    fn the_json_leaf_walker_finds_a_string_nested_two_levels_down() {
        let v = serde_json::json!({"a": 1, "b": [{"c": "leaked"}, {"d": 2}]});
        let (mut strings, mut leaves) = (Vec::new(), 0usize);
        json_leaves(&v, &mut strings, &mut leaves);
        assert_eq!(strings, vec!["leaked".to_string()]);
        assert_eq!(leaves, 3);
    }

    /// A fully populated `CaptureHealth`, every enum variant represented.
    fn populated_health() -> CaptureHealth {
        CaptureHealth {
            schema_version: 1,
            attachment: CaptureAttachment::LiveInterface,
            window: CaptureHealthWindow {
                requested_seconds: 90,
                applied_seconds: MAX_SAMPLE_SECONDS,
                observed_ms: 30_004,
            },
            totals: CaptureCounters {
                packets: 1_000_000,
                kernel_dropped: 12,
                interface_dropped: 3,
                invalid_timestamps: 1,
                undecodable_frames: 250_000,
            },
            in_window: CaptureCounters {
                packets: 40_000,
                kernel_dropped: 2,
                interface_dropped: 1,
                invalid_timestamps: 0,
                undecodable_frames: 10_000,
            },
            undecoded_fraction: 0.25,
            undecoded_fraction_in_window: 0.25,
            undecodable_by_reason: vec![
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::NotIp,
                    number: Some(0x8847),
                    frames: 200_000,
                    frames_in_window: 8_000,
                },
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::UnsupportedLinkType,
                    number: Some(0),
                    frames: 40_000,
                    frames_in_window: 1_500,
                },
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::NoTransport,
                    number: Some(47),
                    frames: 8_000,
                    frames_in_window: 400,
                },
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::Truncated,
                    number: None,
                    frames: 1_500,
                    frames_in_window: 90,
                },
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::DecodeError,
                    number: None,
                    frames: 500,
                    frames_in_window: 10,
                },
            ],
            undecodable_reasons_dropped: 7,
            dialogs_tracked: 42,
            streams_tracked: 18,
            // Populated with a REAL-looking reading, not the unavailable
            // default: the no-strings gate below must see the fully-inhabited
            // shape, and a default that happened to be all zeros could hide a
            // string field added to this type later.
            clock: crate::clock::ClockDiscipline {
                synchronised: true,
                max_error_us: 16_000,
                est_error_us: 240,
                available: true,
            },
        }
    }

    /// No value anywhere in a populated `capture_health` response is a string.
    ///
    /// This test IS the confidentiality argument for the tool. Reviewer
    /// vigilance and a comment beside a field both rot; a type that cannot
    /// hold a string cannot leak one. If a `String` is ever added to
    /// `CaptureHealth` or anything nested in it, this fails.
    #[test]
    fn a_populated_capture_health_response_carries_no_string_value_anywhere() {
        let value = serde_json::to_value(populated_health()).expect("serialize CaptureHealth");
        let (mut strings, mut leaves) = (Vec::new(), 0usize);
        json_leaves(&value, &mut strings, &mut leaves);

        assert_eq!(
            strings,
            Vec::<String>::new(),
            "capture_health returned string value(s). This tool samples a live \
             production capture carrying other people's calls, and a response \
             type that can hold a string can hold a From: header. Carry the \
             number instead and put the label in docs/mcp.md."
        );
        // Pinned so the gate above cannot pass by walking nothing.
        //
        // Raised 40 -> 44 by `clock`: four leaves (synchronised, max_error_us,
        // est_error_us, available), all bools and integers, which is why the
        // string check above still passes with the field present.
        assert_eq!(
            leaves, 44,
            "the response shape changed: 44 leaf values were expected. Recount \
             deliberately — a drop here means the walker stopped reaching part \
             of the tree, which is how the string check goes quietly vacuous."
        );
    }

    /// Both enums travel as small integers, and no code is zero.
    ///
    /// Integers rather than names because a serde unit variant is a STRING on
    /// the wire, and one string field is the whole leak surface. No code is
    /// zero so a zeroed or defaulted struct can never be mistaken for a real
    /// answer — the same reason `attachment` exists at all.
    #[test]
    fn the_response_enums_travel_as_non_zero_integer_codes() {
        for (attachment, code) in [
            (CaptureAttachment::NotAttached, 1),
            (CaptureAttachment::LiveInterface, 2),
            (CaptureAttachment::ReplayedFile, 3),
        ] {
            assert_eq!(
                serde_json::to_value(attachment).expect("serialize"),
                serde_json::json!(code)
            );
        }
        for (reason, code) in [
            (UndecodableReasonCode::UnsupportedLinkType, 1),
            (UndecodableReasonCode::NotIp, 2),
            (UndecodableReasonCode::NoTransport, 3),
            (UndecodableReasonCode::Truncated, 4),
            (UndecodableReasonCode::DecodeError, 5),
        ] {
            assert_eq!(
                serde_json::to_value(reason).expect("serialize"),
                serde_json::json!(code)
            );
        }
    }

    /// Each `UndecodableReason` splits into its code and the number it carries.
    #[test]
    fn every_undecodable_reason_splits_into_a_code_and_its_number() {
        use crate::capture::UndecodableReason as R;
        let cases = [
            (
                R::UnsupportedLinkType(0),
                UndecodableReasonCode::UnsupportedLinkType,
                Some(0i64),
            ),
            (
                R::UnsupportedLinkType(113),
                UndecodableReasonCode::UnsupportedLinkType,
                Some(113),
            ),
            (
                R::NotIp(Some(0x8847)),
                UndecodableReasonCode::NotIp,
                Some(34_887),
            ),
            (R::NotIp(None), UndecodableReasonCode::NotIp, None),
            (
                R::NoTransport(Some(47)),
                UndecodableReasonCode::NoTransport,
                Some(47),
            ),
            (
                R::NoTransport(None),
                UndecodableReasonCode::NoTransport,
                None,
            ),
            (R::Truncated, UndecodableReasonCode::Truncated, None),
            (R::DecodeError, UndecodableReasonCode::DecodeError, None),
        ];
        for (reason, code, number) in cases {
            assert_eq!(UndecodableReasonCode::split(reason), (code, number));
        }
    }

    /// The sampling window is clamped to the cap, and zero is refused.
    #[test]
    fn the_sample_window_is_clamped_to_the_cap_and_zero_is_refused() {
        assert_eq!(MAX_SAMPLE_SECONDS, 30);
        assert_eq!(resolve_sample_seconds(1).expect("1 second"), 1);
        assert_eq!(resolve_sample_seconds(29).expect("29 seconds"), 29);
        assert_eq!(resolve_sample_seconds(30).expect("30 seconds"), 30);
        assert_eq!(resolve_sample_seconds(31).expect("31 clamps"), 30);
        assert_eq!(resolve_sample_seconds(u32::MAX).expect("MAX clamps"), 30);

        let err = resolve_sample_seconds(0).expect_err("zero must be refused");
        assert_eq!(
            err.message,
            "sample_seconds must be at least 1. A zero-second window observes \
             nothing, and a response of zero deltas reads as a quiet capture."
        );
    }

    /// Totals, deltas and both fractions, computed from two snapshots.
    #[test]
    fn capture_health_reports_totals_deltas_and_both_undecoded_fractions() {
        use crate::capture::{UndecodableReason as R, UndecodableTally};

        let before = HealthSample {
            counters: CaptureCounters {
                packets: 400,
                kernel_dropped: 1,
                interface_dropped: 2,
                invalid_timestamps: 3,
                undecodable_frames: 50,
            },
            reasons: vec![UndecodableTally {
                reason: R::NotIp(Some(0x8847)),
                frames: 50,
            }],
            reasons_dropped: 0,
        };
        let after = HealthSample {
            counters: CaptureCounters {
                packets: 800,
                kernel_dropped: 9,
                interface_dropped: 6,
                invalid_timestamps: 3,
                undecodable_frames: 200,
            },
            reasons: vec![
                UndecodableTally {
                    reason: R::NotIp(Some(0x8847)),
                    frames: 150,
                },
                UndecodableTally {
                    reason: R::UnsupportedLinkType(113),
                    frames: 50,
                },
            ],
            reasons_dropped: 4,
        };

        let health = build_health(
            CaptureAttachment::LiveInterface,
            CaptureHealthWindow {
                requested_seconds: 2,
                applied_seconds: 2,
                observed_ms: 2_001,
            },
            &before,
            &after,
            42,
            18,
        );

        assert_eq!(health.schema_version, 1);
        assert_eq!(health.attachment, CaptureAttachment::LiveInterface);
        assert_eq!(health.window.requested_seconds, 2);
        assert_eq!(health.window.applied_seconds, 2);
        assert_eq!(health.window.observed_ms, 2_001);

        assert_eq!(
            health.totals,
            CaptureCounters {
                packets: 800,
                kernel_dropped: 9,
                interface_dropped: 6,
                invalid_timestamps: 3,
                undecodable_frames: 200,
            }
        );
        assert_eq!(
            health.in_window,
            CaptureCounters {
                packets: 400,
                kernel_dropped: 8,
                interface_dropped: 4,
                invalid_timestamps: 0,
                undecodable_frames: 150,
            }
        );

        // 200/800 over the run, 150/400 across the window: both exact in
        // binary floating point, so these are equalities and not tolerances.
        assert_eq!(health.undecoded_fraction, 0.25);
        assert_eq!(health.undecoded_fraction_in_window, 0.375);

        assert_eq!(
            health.undecodable_by_reason,
            vec![
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::NotIp,
                    number: Some(34_887),
                    frames: 150,
                    frames_in_window: 100,
                },
                UndecodableReasonCount {
                    reason: UndecodableReasonCode::UnsupportedLinkType,
                    number: Some(113),
                    frames: 50,
                    frames_in_window: 50,
                },
            ],
            "each reason keeps its number, its run total and its window delta"
        );
        assert_eq!(health.undecodable_reasons_dropped, 4);
        assert_eq!(health.dialogs_tracked, 42);
        assert_eq!(health.streams_tracked, 18);
    }

    /// A capture with nothing on it reports a zero fraction, not a division by
    /// zero rendered as `null`.
    #[test]
    fn an_empty_window_reports_a_zero_undecoded_fraction() {
        let sample = HealthSample {
            counters: CaptureCounters::default(),
            reasons: Vec::new(),
            reasons_dropped: 0,
        };
        let health = build_health(
            CaptureAttachment::NotAttached,
            CaptureHealthWindow {
                requested_seconds: 1,
                applied_seconds: 1,
                observed_ms: 1_000,
            },
            &sample,
            &sample,
            0,
            0,
        );
        assert_eq!(health.undecoded_fraction, 0.0);
        assert_eq!(health.undecoded_fraction_in_window, 0.0);
        // A NaN would serialize as `null`, which an agent reads as "no answer"
        // rather than "nothing was undecodable".
        let value = serde_json::to_value(&health).expect("serialize");
        assert_eq!(value["undecoded_fraction"], serde_json::json!(0.0));
        assert_eq!(
            value["undecoded_fraction_in_window"],
            serde_json::json!(0.0)
        );
    }

    /// The attachment code names live, file, and nothing at all.
    #[test]
    fn the_attachment_code_distinguishes_live_file_and_nothing_attached() {
        assert_eq!(attachment_of(None), CaptureAttachment::NotAttached);
        let ctx = |live| CaptureContext {
            live,
            name: "eth0".to_string(),
            started: std::time::Instant::now(),
            writing_to: None,
        };
        assert_eq!(
            attachment_of(Some(&ctx(true))),
            CaptureAttachment::LiveInterface
        );
        assert_eq!(
            attachment_of(Some(&ctx(false))),
            CaptureAttachment::ReplayedFile
        );
    }

    /// A zero window is refused by the tool itself, before it sleeps.
    #[tokio::test]
    async fn capture_health_refuses_a_zero_second_window() {
        let server = empty_server();
        let err = server
            .capture_health(Parameters(CaptureHealthParams { sample_seconds: 0 }))
            .await
            .expect_err("a zero-second window must be refused");
        assert_eq!(
            err.message,
            "sample_seconds must be at least 1. A zero-second window observes \
             nothing, and a response of zero deltas reads as a quiet capture."
        );
    }

    /// End to end: the tool waits the window out and says nothing is attached.
    ///
    /// `empty_server()` has no `CaptureContext`, so the honest answer is
    /// "nothing attached" rather than a set of zeros that look like a silent
    /// but healthy wire.
    #[tokio::test]
    async fn capture_health_observes_a_real_window_and_reports_no_attachment() {
        let server = empty_server();
        let started = std::time::Instant::now();
        let result = server
            .capture_health(Parameters(CaptureHealthParams { sample_seconds: 1 }))
            .await
            .expect("capture_health");
        let elapsed = started.elapsed();
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).expect("json");

        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["attachment"], 1, "1 is 'no capture attached': {v}");
        assert_eq!(v["window"]["requested_seconds"], 1);
        assert_eq!(v["window"]["applied_seconds"], 1);
        assert_eq!(v["dialogs_tracked"], 0);
        assert_eq!(v["streams_tracked"], 0);

        // The COUNTERS are deliberately not asserted here, and the first draft
        // of this test asserting `in_window.packets == 0` is why. They are
        // process-global atomics that every other test in this binary also
        // moves, so any value pinned against them is a value another test can
        // change — the test failed on a full `cargo test` run and passed on a
        // filtered one, which is the worst failure mode a gate can have. Their
        // arithmetic is pinned exactly, against fixed inputs, in
        // `capture_health_reports_totals_deltas_and_both_undecoded_fractions`.
        //
        // What this test owns is the wiring, and the exact claim available for
        // that is the SHAPE that reached the wire.
        let keys = |value: &serde_json::Value| -> Vec<String> {
            value
                .as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(
            keys(&v),
            vec![
                "attachment",
                "clock",
                "dialogs_tracked",
                "in_window",
                "schema_version",
                "streams_tracked",
                "totals",
                "undecodable_by_reason",
                "undecodable_reasons_dropped",
                "undecoded_fraction",
                "undecoded_fraction_in_window",
                "window",
            ]
        );
        for block in ["totals", "in_window"] {
            assert_eq!(
                keys(&v[block]),
                vec![
                    "interface_dropped",
                    "invalid_timestamps",
                    "kernel_dropped",
                    "packets",
                    "undecodable_frames",
                ],
                "{block} lost or gained a counter"
            );
        }
        assert_eq!(
            keys(&v["window"]),
            vec!["applied_seconds", "observed_ms", "requested_seconds"]
        );

        // The wall clock is the one field no test can pin to a single value.
        // What IS exact is that the handler really waited: a tool that
        // returned instantly would report a window it never observed.
        assert!(
            elapsed >= std::time::Duration::from_secs(1),
            "the handler returned in {elapsed:?} without waiting out the window"
        );
        let observed = v["window"]["observed_ms"].as_u64().expect("observed_ms");
        assert!(
            (1_000..10_000).contains(&observed),
            "observed_ms was {observed}, which is not one second of wall clock"
        );
    }

    /// The tool is registered and annotated `readOnlyHint`.
    ///
    /// The annotation is a promise to the client, so it is checked on the
    /// registered tool rather than read off the attribute in the source.
    #[test]
    fn capture_health_is_registered_and_annotated_read_only() {
        let router = SipnabMcp::tool_router();
        let tool = router
            .get("capture_health")
            .expect("capture_health must be registered");
        let annotations = tool
            .annotations
            .as_ref()
            .expect("capture_health must carry tool annotations");
        assert_eq!(annotations.read_only_hint, Some(true));
    }

    /// Every registered tool is annotated, and the writes are exactly the
    /// five we expect.
    ///
    /// Annotations are a promise to the client: an agent host uses
    /// `readOnlyHint` to decide what it may call without asking, and
    /// `destructiveHint` to decide what needs confirmation. An UNANNOTATED tool
    /// carries no promise at all, so a cautious host must treat it as the worst
    /// case and a careless one treats it as harmless — and thirty of the
    /// thirty-one tools here were unannotated.
    ///
    /// Two properties, and the second is the one that makes this durable:
    ///
    /// 1. Every tool carries annotations with `read_only_hint` and
    ///    `open_world_hint` set explicitly. Absent is not the same as false;
    ///    absent means nobody decided.
    /// 2. The set of tools that are NOT read-only equals `WRITES` exactly. A new
    ///    write verb, or an existing tool quietly flipped to non-read-only,
    ///    fails here by name. Checking only "every tool has annotations" would
    ///    pass while a tool that deletes something claimed to be read-only.
    #[test]
    fn every_tool_is_annotated_and_the_writes_are_exactly_the_expected_five() {
        /// name, destructive_hint, idempotent_hint.
        ///
        /// Both hints are meaningful ONLY when `read_only_hint` is false (MCP
        /// spec), which is why they are pinned here and not on the query tools.
        /// `open_capture` and `shutdown_server` are destructive because each
        /// changes what every later answer describes; `save_findings` is
        /// additive but NOT idempotent, because each call records another
        /// annotation.
        const WRITES: &[(&str, bool, bool)] = &[
            ("export_audio", false, true),
            ("export_capture", false, true),
            ("open_capture", true, true),
            ("save_findings", false, false),
            ("shutdown_server", true, true),
        ];

        let router = SipnabMcp::tool_router();
        let tools = router.list_all();

        // A walk that finds nothing reports every tool annotated, which is
        // indistinguishable from a clean result.
        assert!(
            tools.len() >= 25,
            "router listed only {} tool(s) — the walk is broken and this gate \
             is not checking what it claims",
            tools.len()
        );

        let mut unannotated = Vec::new();
        let mut missing_open_world = Vec::new();
        let mut writes_found: Vec<String> = Vec::new();

        for tool in &tools {
            let name = tool.name.to_string();
            let Some(ann) = tool.annotations.as_ref() else {
                unannotated.push(name);
                continue;
            };
            match ann.read_only_hint {
                None => unannotated.push(name.clone()),
                Some(true) => {}
                Some(false) => writes_found.push(name.clone()),
            }
            if ann.open_world_hint.is_none() {
                missing_open_world.push(name);
            }
        }

        assert!(
            unannotated.is_empty(),
            "tool(s) {unannotated:?} carry no read_only_hint. An agent host \
             cannot tell whether calling them is safe, so it must either refuse \
             them or risk them. Annotate each one."
        );
        assert!(
            missing_open_world.is_empty(),
            "tool(s) {missing_open_world:?} carry no open_world_hint. sipnab \
             answers from a loaded capture and reaches no external service, so \
             this is false for every tool here — but it has to be SAID, because \
             absent means nobody decided."
        );

        writes_found.sort();
        let expected: Vec<String> = WRITES.iter().map(|(n, _, _)| n.to_string()).collect();
        assert_eq!(
            writes_found, expected,
            "the set of non-read-only tools changed. Either a new write verb \
             was added (annotate it and add it to WRITES, and check it belongs \
             on the MCP surface at all), or a tool that used to be read-only is \
             no longer — which is a change an agent host is entitled to be told \
             about."
        );

        for (name, destructive, idempotent) in WRITES {
            let tool = router
                .get(name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let ann = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must carry annotations"));
            assert_eq!(
                ann.destructive_hint,
                Some(*destructive),
                "{name}: destructive_hint"
            );
            assert_eq!(
                ann.idempotent_hint,
                Some(*idempotent),
                "{name}: idempotent_hint"
            );
        }
    }

    // ---- per-tool token scoping -------------------------------------------

    /// A read scope is refused by every non-read-only tool and accepted by
    /// every read-only one — over the REAL registered router, so the test
    /// walks the same annotations dispatch reads.
    ///
    /// Both directions in one walk, and each side is asserted non-empty:
    /// a build that refuses everything fails the accept half, a build that
    /// accepts everything fails the refuse half. That is the gate — either
    /// degenerate implementation is caught by name.
    #[test]
    fn a_read_scope_is_refused_by_exactly_the_non_read_only_tools() {
        let router = SipnabMcp::tool_router();
        let mut accepted = Vec::new();
        let mut refused = Vec::new();

        for tool in router.list_all() {
            let name = tool.name.to_string();
            let read_only = tool
                .annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
                .unwrap_or(false);
            match scope_refusal(crate::auth::SCOPE_READ, &name, router.get(&name)) {
                None => {
                    assert!(
                        read_only,
                        "{name} is NOT annotated read-only but a read scope \
                         reached it — this is the exact defect per-tool \
                         scoping exists to close"
                    );
                    accepted.push(name);
                }
                Some(err) => {
                    assert!(
                        !read_only,
                        "{name} IS annotated read-only but a read scope was \
                         refused — a read token that cannot read is useless"
                    );
                    // The refusal must tell the caller what to fix: which
                    // tool, which scope it presented, and what it needs.
                    assert!(
                        err.message.contains(&name) && err.message.contains("\"read\""),
                        "{name}: refusal must name the tool and the scope: {}",
                        err.message
                    );
                    refused.push(name);
                }
            }
        }

        assert!(
            !accepted.is_empty(),
            "no tool accepted the read scope — the check refuses everything"
        );
        assert!(
            !refused.is_empty(),
            "no tool refused the read scope — the check is not narrowing anything"
        );
        // The refused set is exactly the annotation-declared writes, pinned
        // by name so this test fails loudly when the write set changes.
        refused.sort();
        assert_eq!(
            refused,
            vec![
                "export_audio",
                "export_capture",
                "open_capture",
                "save_findings",
                "shutdown_server"
            ],
            "the tools a read token cannot call must be exactly the \
             non-read-only set"
        );
    }

    /// A full scope reaches every registered tool, writes included — adding
    /// per-tool scoping must not narrow any existing full-token deployment.
    #[test]
    fn a_full_scope_reaches_every_tool() {
        let router = SipnabMcp::tool_router();
        for tool in router.list_all() {
            let name = tool.name.to_string();
            assert!(
                scope_refusal(crate::auth::SCOPE_FULL, &name, router.get(&name)).is_none(),
                "{name}: a full scope must never be refused"
            );
        }
    }

    /// An unknown tool produces no scope refusal: dispatch's own "tool not
    /// found" is the accurate answer, and a scope error naming a nonexistent
    /// tool would misreport both what happened and what the token lacks.
    #[test]
    fn an_unknown_tool_is_left_for_dispatch_to_refuse() {
        assert!(scope_refusal(crate::auth::SCOPE_READ, "no_such_tool", None).is_none());
    }

    /// A tool with no annotations (or none that decide read-onlyness) is
    /// refused under a narrow scope. Absent means nobody decided, and a
    /// permission check must not guess in the caller's favor. Theoretical on
    /// this server — the annotation gate above forbids such a tool — but the
    /// fail-closed branch has to be pinned or a refactor could flip it.
    #[test]
    fn an_unannotated_tool_fails_closed_under_a_narrow_scope() {
        let mut tool = rmcp::model::Tool::default();
        // Assigned via an explicit Cow, NOT `name = "…"`: the docs drift gate
        // greps this file for that exact shape to enumerate registered tools,
        // and this hypothetical one must not show up in that census.
        tool.name = std::borrow::Cow::Borrowed("hypothetical");
        assert!(
            scope_refusal(crate::auth::SCOPE_READ, "hypothetical", Some(&tool)).is_some(),
            "no annotation must mean no access for a narrow scope"
        );
    }

    /// With no cap configured, the permit gate is a no-op that never refuses
    /// and hands out nothing to hold. Pinned so a future default cannot start
    /// silently bounding a deployment that asked for none.
    #[test]
    fn no_cap_never_refuses_a_call() {
        let none: Option<Arc<tokio::sync::Semaphore>> = None;
        for _ in 0..1000 {
            let permit = acquire_call_permit(&none).expect("no cap must never refuse");
            assert!(permit.is_none(), "no cap must hand out no permit to hold");
        }
    }

    /// `with_max_concurrent(0)` is the documented spelling of "unlimited" and
    /// must leave the cap off — not install a zero-permit semaphore that
    /// refuses the very first call and wedges the server shut.
    #[test]
    fn a_zero_cap_means_unlimited_not_a_dead_server() {
        let server = empty_server().with_max_concurrent(0);
        assert!(
            server.call_limiter.is_none(),
            "0 must mean unlimited, not a 0-permit cap that refuses everything"
        );
        assert!(
            acquire_call_permit(&server.call_limiter)
                .expect("a 0 cap must admit every call")
                .is_none()
        );
    }

    /// The cap actually bounds: with room for two, the third call is refused
    /// while the first two hold their permits, and a slot frees the instant
    /// one is dropped — the cap holds at two, it neither leaks nor widens.
    /// This drives the same function `call_tool` calls, so it tests the effect
    /// (a real refusal at the boundary), not a restatement of the predicate.
    #[test]
    fn the_cap_refuses_the_call_that_would_exceed_it() {
        let server = empty_server().with_max_concurrent(2);
        assert!(
            server.call_limiter.is_some(),
            "a positive cap must install a limiter"
        );

        let p1 = acquire_call_permit(&server.call_limiter)
            .expect("1st call admitted")
            .expect("a cap must hand out a permit to hold");
        let p2 = acquire_call_permit(&server.call_limiter)
            .expect("2nd call admitted")
            .expect("permit");

        let refusal = acquire_call_permit(&server.call_limiter)
            .expect_err("a third call over a cap of two must be refused");
        assert_eq!(
            refusal.code.0, AT_CAPACITY_CODE,
            "an at-capacity refusal must carry the retryable server-error code, \
             not invalid-params (a client error) or internal-error (reads as a bug)"
        );
        assert!(
            refusal.message.contains("cap") && refusal.message.contains("retry"),
            "the refusal must tell the caller it is a capacity limit to retry: {}",
            refusal.message
        );

        // Freeing one slot admits exactly one more call, then refuses again.
        drop(p1);
        let p3 = acquire_call_permit(&server.call_limiter)
            .expect("a freed slot must admit the next call")
            .expect("permit");
        acquire_call_permit(&server.call_limiter)
            .expect_err("with two permits held again, the cap must refuse once more");

        drop(p2);
        drop(p3);
    }

    /// With no rate limit configured, the per-peer gate is a no-op that never
    /// refuses — pinned so a future default cannot start silently throttling a
    /// deployment that asked for none.
    #[test]
    fn no_rate_limit_never_refuses_a_call() {
        let server = empty_server();
        assert!(
            server.rate_limiter.is_none(),
            "a server built without a rate limit must carry none"
        );
        let now = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(
                rate_limit_refusal(&server.rate_limiter, None, now).is_none(),
                "no rate limit must never refuse"
            );
        }
    }

    /// `with_rate_limit_per_peer(0)` is the documented spelling of "unlimited"
    /// and must leave the limit off — not install a zero-per-second limiter
    /// that refuses the very first call and wedges the server shut, which is
    /// the failure `--mcp-max-concurrent` documents for its own zero.
    #[test]
    fn a_zero_rate_limit_means_unlimited_not_a_dead_server() {
        let server = empty_server().with_rate_limit_per_peer(0);
        assert!(
            server.rate_limiter.is_none(),
            "0 must mean unlimited, not a 0/s limiter that refuses everything"
        );
        assert!(
            rate_limit_refusal(&server.rate_limiter, None, std::time::Instant::now()).is_none(),
            "a 0 rate limit must admit every call"
        );
    }

    /// The rate limit actually bounds arrivals: with three calls a second
    /// allowed, the fourth inside that window is refused, a second peer keeps
    /// its own allowance, and the next window admits again.
    ///
    /// This drives the same function `call_tool` calls, so it tests the effect
    /// — a real refusal at the boundary — not a restatement of the predicate.
    /// The window is stepped by passing `now`, never by sleeping: a limiter
    /// whose test sleeps for a second is a limiter nobody runs.
    #[test]
    fn the_rate_limit_refuses_the_call_that_exceeds_it() {
        let server = empty_server().with_rate_limit_per_peer(3);
        assert!(
            server.rate_limiter.is_some(),
            "a positive rate limit must install a limiter"
        );
        let peer: PeerKey = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        let other: PeerKey = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        let now = std::time::Instant::now();

        for i in 1..=3 {
            assert!(
                rate_limit_refusal(&server.rate_limiter, peer, now).is_none(),
                "call {i} of 3 is inside the allowance and must be admitted"
            );
        }

        let refusal = rate_limit_refusal(&server.rate_limiter, peer, now)
            .expect("a fourth call inside a 3/s window must be refused");
        assert_eq!(
            refusal.code.0, AT_CAPACITY_CODE,
            "a rate-limit refusal must carry the same retryable server-error \
             code the concurrency cap uses, not invalid-params (a client error) \
             or internal-error (reads as a bug)"
        );
        assert!(
            refusal.message.contains("rate limit") && refusal.message.contains("retry"),
            "the refusal must tell the caller it is a rate limit to retry: {}",
            refusal.message
        );
        assert_eq!(
            server.rate_limit_refusals(),
            1,
            "the refusal must be counted, or the audit line and any later \
             metric are quoting a number nobody maintains"
        );

        // One noisy peer must not spend another peer's allowance.
        assert!(
            rate_limit_refusal(&server.rate_limiter, other, now).is_none(),
            "a second peer keeps its own allowance while the first is throttled"
        );

        // A fresh window restores the throttled peer, and only then.
        let next = now + std::time::Duration::from_secs(1);
        assert!(
            rate_limit_refusal(&server.rate_limiter, peer, next).is_none(),
            "the next window must restore the peer's allowance"
        );
        assert_eq!(
            server.rate_limit_refusals(),
            1,
            "an admitted call must not count as a refusal"
        );
    }

    /// A caller refused because the peer table is full is told THAT, not that
    /// it exceeded an allowance it never used.
    ///
    /// The table fails closed once too many distinct peers have been seen in
    /// one second, so a well-behaved client's FIRST call can land here. Being
    /// told "you are over 100 calls/s" would send whoever debugs it hunting a
    /// loop that does not exist, which is why the two refusals do not share
    /// one sentence.
    #[test]
    fn a_full_peer_table_refuses_with_its_own_reason() {
        let server = empty_server().with_rate_limit_per_peer(1);
        let now = std::time::Instant::now();
        for i in 0..crate::rate_limit::MAX_TRACKED_PEERS as u32 {
            let peer: PeerKey = Some(IpAddr::V4(Ipv4Addr::from(i)));
            assert!(
                rate_limit_refusal(&server.rate_limiter, peer, now).is_none(),
                "the first call from fresh peer {i} is inside its own allowance"
            );
        }
        let newcomer: PeerKey = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        let refusal = rate_limit_refusal(&server.rate_limiter, newcomer, now)
            .expect("a peer the table cannot account for must be refused, not waved through");
        assert!(
            refusal.message.contains("distinct peers"),
            "the refusal must name the real cause, not an allowance this peer \
             never touched: {}",
            refusal.message
        );
    }

    /// Extensions carrying HTTP `Parts` stamped with `auth` (or nothing) —
    /// what `caller_of` and `scope_of` see for an HTTP call. No `ConnectInfo`
    /// is inserted, so the peer renders as `unknown-peer`; these tests are
    /// about the admission record, not the socket.
    #[cfg(feature = "mcp-http")]
    fn http_extensions(auth: Option<crate::mcp::transport::McpAuth>) -> rmcp::model::Extensions {
        let request = axum::http::Request::builder()
            .body(())
            .expect("build request");
        let (mut parts, ()) = request.into_parts();
        if let Some(auth) = auth {
            parts.extensions.insert(auth);
        }
        let mut extensions = rmcp::model::Extensions::default();
        extensions.insert(parts);
        extensions
    }

    /// The admission record maps to the scope dispatch enforces: a verified
    /// bearer token carries its claim; unauthenticated (loopback, no
    /// verifier), a missing stamp, and stdio are all full.
    #[cfg(feature = "mcp-http")]
    #[test]
    fn scope_of_maps_each_admission_record() {
        use crate::mcp::transport::McpAuth;

        assert_eq!(
            scope_of(&http_extensions(Some(McpAuth::BearerVerified {
                scope: crate::auth::SCOPE_READ.to_string(),
                token_id: Some("agent".to_string()),
            }))),
            crate::auth::SCOPE_READ,
            "a verified token's scope claim is the scope dispatch enforces"
        );
        assert_eq!(
            scope_of(&http_extensions(Some(McpAuth::Unauthenticated))),
            crate::auth::SCOPE_FULL,
            "loopback-without-verifier is full: the boundary is network position"
        );
        assert_eq!(
            scope_of(&http_extensions(None)),
            crate::auth::SCOPE_FULL,
            "a missing admission record stays full; the audit line already \
             flags it as no-admission-record"
        );
        assert_eq!(
            scope_of(&rmcp::model::Extensions::default()),
            crate::auth::SCOPE_FULL,
            "stdio is full: process ownership is the boundary"
        );
    }

    /// The caller field names WHICH token made the call, and says nothing at
    /// all when there is no token to name (PB10).
    ///
    /// The audit log's job is to answer "who read this capture", and until the
    /// id landed the answer stopped at "someone holding a valid token, from
    /// this socket". Two agents on one host present two tokens from the same
    /// address, so the socket does not separate them.
    ///
    /// The absence cases are the other half and are asserted as the ABSENCE of
    /// the key, not as a placeholder value. A `token=-` or `token=` would be
    /// indistinguishable from a token whose id is literally `-` or empty, and
    /// a reader who greps for `token=` would find lines that never carried
    /// one. Three different credentials have no id to give — stdio (there is
    /// no token), a loopback call admitted with no verifier configured, and a
    /// static shared secret, which carries no claims at all — and all three
    /// must produce no key.
    #[cfg(feature = "mcp-http")]
    #[test]
    fn the_caller_field_names_the_token_or_says_nothing() {
        use crate::mcp::transport::McpAuth;

        let named = caller_of(&http_extensions(Some(McpAuth::BearerVerified {
            scope: crate::auth::SCOPE_READ.to_string(),
            token_id: Some("ci-runner-1".to_string()),
        })));
        assert_eq!(
            named, "unknown-peer bearer-verified scope=read token=ci-runner-1",
            "a verified token must be named by the id it was minted with — the \
             same string the operator wrote in --token-id and would write in \
             --mcp-revoked-file"
        );

        // A static secret verifies but carries no claims, so there is no id.
        let static_secret = caller_of(&http_extensions(Some(McpAuth::BearerVerified {
            scope: crate::auth::SCOPE_FULL.to_string(),
            token_id: None,
        })));
        assert_eq!(
            static_secret, "unknown-peer bearer-verified scope=full",
            "a static secret has no id; the field must be absent, not blank"
        );

        for (what, caller) in [
            (
                "loopback with no verifier configured",
                caller_of(&http_extensions(Some(McpAuth::Unauthenticated))),
            ),
            (
                "a missing admission record",
                caller_of(&http_extensions(None)),
            ),
            ("stdio", caller_of(&rmcp::model::Extensions::default())),
            ("a static secret", static_secret.clone()),
        ] {
            assert!(
                !caller.contains("token="),
                "{what} has no token to name, so the audit line must carry no \
                 token key at all: {caller}"
            );
        }
        assert_eq!(
            caller_of(&rmcp::model::Extensions::default()),
            "stdio",
            "stdio names the boundary it can prove and nothing else"
        );
    }

    /// A token id cannot forge a field or a line on the audit record, and
    /// cannot run away with it.
    ///
    /// The id is read out of a signed payload, which makes it operator-chosen
    /// on the happy path — but an audit log is what gets read on the unhappy
    /// one, where a signing key is in the wrong hands and its holder chooses
    /// ids. The line is flat text, so `x" outcome=ok` closes the quoted caller
    /// field and `x outcome=ok` does not even need to: every reader of these
    /// lines, including this repo's own tests, matches substrings. A newline
    /// forges a whole line.
    ///
    /// So the assertion is the strong one — the rendered id contains no
    /// separator of any kind — rather than "it was escaped somehow", which a
    /// half-measure could satisfy.
    #[cfg(feature = "mcp-http")]
    #[test]
    fn a_hostile_token_id_cannot_forge_a_field_or_run_away_with_the_line() {
        use crate::mcp::transport::McpAuth;

        /// The rendered `token=` value from a bearer-verified call with `id`.
        fn token_field(id: &str) -> String {
            let caller = caller_of(&http_extensions(Some(McpAuth::BearerVerified {
                scope: crate::auth::SCOPE_FULL.to_string(),
                token_id: Some(id.to_string()),
            })));
            let rendered = caller
                .strip_prefix("unknown-peer bearer-verified scope=full token=")
                .unwrap_or_else(|| {
                    panic!("the id must render as the caller's token field: {caller}")
                });
            rendered.to_string()
        }

        let forged = token_field("x\" outcome=ok caller=\"10.0.0.1\nsecond line\r\t");
        assert!(
            !forged.contains(['"', '\n', '\r', ' ', '\t', '\\', '=']),
            "an id must not be able to close the quoted caller field, separate a \
             field, or start a line: {forged}"
        );
        assert!(
            !forged.contains("outcome=ok"),
            "a forged key=value must not survive into the line an operator greps: \
             {forged}"
        );

        let bounded = token_field(&"z".repeat(4096));
        assert!(
            bounded.len() < 128,
            "an unbounded id must not run away with the audit line ({} bytes)",
            bounded.len()
        );
        assert!(
            bounded.contains("truncated"),
            "a shortened id must READ as shortened — an operator must not take a \
             prefix for the whole id and then fail to find it: {bounded}"
        );

        // The common case is untouched: real ids are inside the safe set and
        // render verbatim, so the encoding never shows up on a real line.
        for id in ["tok-1754500000000000", "ci-runner-1", "alice@example.com"] {
            assert_eq!(
                token_field(id),
                id,
                "an ordinary id must survive verbatim; the encoding is for the \
                 hostile case only"
            );
        }
    }

    // ---- save_findings: the one write verb, and its dead end ----------------

    #[tokio::test]
    async fn save_findings_is_refused_on_a_stock_server() {
        // Off unless armed, like shutdown_server and open_capture. A default
        // install must accept no writes at all.
        let server = server_with_dialog("w1@x");
        let err = server
            .save_findings(Parameters(SaveFindingsParams {
                summary: "anything".into(),
                call_id: None,
                detail: None,
            }))
            .await
            .expect_err("a stock server must refuse to record");
        assert!(
            format!("{err:?}").contains("--mcp-allow-save-findings"),
            "the refusal must name the flag that would permit it: {err:?}"
        );
    }

    #[tokio::test]
    async fn an_armed_server_records_and_reports_what_it_did() {
        let server = server_with_dialog("w2@x").with_save_findings();
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .save_findings(Parameters(SaveFindingsParams {
                    summary: "the 488 was a codec mismatch".into(),
                    call_id: Some("w2@x".into()),
                    detail: None,
                }))
                .await
                .expect("armed server records"),
        ))
        .unwrap();
        assert_eq!(v["seq"], 0);
        assert_eq!(v["recorded_total"], 1);
        assert_eq!(v["truncated"], false);
        // Stated in the reply so an agent does not go hunting for a read tool.
        assert_eq!(v["readable_over_mcp"], false);
        // Provenance, same as every other response on this surface.
        assert!(v["capture_identity"]["dialog_generation"].is_u64());
    }

    #[tokio::test]
    async fn an_empty_summary_is_refused_rather_than_recorded() {
        let server = server_with_dialog("w3@x").with_save_findings();
        for blank in ["", "   ", "\t\n"] {
            assert!(
                server
                    .save_findings(Parameters(SaveFindingsParams {
                        summary: blank.into(),
                        call_id: None,
                        detail: None,
                    }))
                    .await
                    .is_err(),
                "a blank summary records nothing but takes a sequence number"
            );
        }
    }

    /// THE test for this feature. Everything else checks that the write works;
    /// this checks that the write goes NOWHERE, which is the whole safety
    /// argument for allowing a write verb on a surface an LLM drives while
    /// reading attacker-controlled text.
    ///
    /// Asserts the effect, not the predicate: it writes a marker no capture
    /// could contain and then reads back through every query tool that could
    /// plausibly surface it. A test that merely checked "no tool is named
    /// list_findings" would pass while the text leaked through search.
    #[tokio::test]
    async fn a_recorded_finding_is_reachable_from_no_read_tool() {
        const MARKER: &str = "ZZQX-agent-written-marker-never-on-any-wire";
        let server = server_with_dialog("w4@x").with_save_findings();
        server
            .save_findings(Parameters(SaveFindingsParams {
                summary: MARKER.into(),
                call_id: Some("w4@x".into()),
                detail: Some(MARKER.into()),
            }))
            .await
            .expect("recorded");

        let reads = vec![
            (
                "capture_status",
                text_of(&server.capture_status().await.expect("stats")),
            ),
            (
                "list_dialogs",
                text_of(
                    &server
                        .list_dialogs(Parameters(ListDialogsParams {
                            cursor: None,
                            limit: None,
                            filter: None,
                        }))
                        .await
                        .expect("list"),
                ),
            ),
            (
                "tail_dialogs",
                text_of(
                    &server
                        .tail_dialogs(Parameters(TailDialogsParams {
                            cursor: None,
                            limit: None,
                        }))
                        .await
                        .expect("tail"),
                ),
            ),
            (
                "get_dialog",
                text_of(
                    &server
                        .get_dialog(Parameters(GetDialogParams {
                            call_id: "w4@x".into(),
                            cursor: None,
                            max_messages: None,
                        }))
                        .await
                        .expect("get"),
                ),
            ),
        ];
        for (tool, body) in reads {
            assert!(
                !body.contains(MARKER),
                "{tool} returned agent-written text; the annotation is no longer a dead end"
            );
        }
    }

    // ---- find_correlated: the strategy name is the point --------------------

    /// A Session-ID match reports the STANDARD by name, flags itself as an
    /// identifier match, and carries no timing gap — because the gap is not
    /// why they matched, and attaching it would invite a reader to weigh it.
    #[tokio::test]
    async fn find_correlated_names_the_strategy_that_actually_matched() {
        const A: &str = "ab30317f1a784dc48ff824d0d3715d86";
        const B: &str = "47755a9de7794ba387653f2099600ef2";
        let ds = {
            let mut ds = DialogStore::new(100, false);
            ds.process_message(invite_with_header(
                "leg-a@access",
                "Session-ID",
                &format!("{A};remote={B}"),
                base_ts(),
            ));
            ds.process_message(invite_with_header(
                "leg-b@core",
                "Session-ID",
                &format!("{B};remote={A}"),
                base_ts(),
            ));
            Arc::new(RwLock::new(ds))
        };
        let server = SipnabMcp::new(ds, Arc::new(RwLock::new(StreamStore::new(100))));

        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "leg-a@access".into(),
                    limit: None,
                }))
                .await
                .expect("correlates"),
        ))
        .unwrap();

        assert_eq!(v["total_matched"], 1);
        assert_eq!(v["legs"][0]["call_id"], "leg-b@core");
        assert_eq!(v["legs"][0]["strategy"], "session_id");
        assert_eq!(v["legs"][0]["identifier_match"], true);
        assert!(
            v["legs"][0]["observed_gap_ms"].is_null(),
            "a timing gap is evidence for a guess, not for an identifier match"
        );
        assert_eq!(
            v["heuristic_only"], false,
            "an identifier match is not a hypothesis"
        );
    }

    /// Two isolated legs, three seconds and two subnets apart, carrying only
    /// the charging vector. Nothing else can answer for it.
    ///
    /// SYNTHETIC: `P-Charging-Vector` is in no fixture and no capture this
    /// repository can reach. RFC 2606 names, RFC 5737 addresses, invented
    /// sequence numbers.
    fn charging_vector_pair(a: &str, b: &str) -> Arc<RwLock<DialogStore>> {
        let mut ds = DialogStore::new(100, false);
        for (call_id, vector, host, ts) in [
            ("leg-a@access", a, "192.0.2.1", base_ts()),
            (
                "leg-b@core",
                b,
                "198.51.100.1",
                base_ts() + chrono::TimeDelta::seconds(3),
            ),
        ] {
            let raw = build_sip(
                "INVITE sip:bob@example.net SIP/2.0",
                &[
                    &format!("Via: SIP/2.0/UDP {host}:5060;branch=z9hG4bK{call_id}"),
                    "From: Alice <sip:alice@example.com>;tag=t1",
                    "To: <sip:bob@example.net>",
                    &format!("Call-ID: {call_id}"),
                    &format!("P-Charging-Vector: {vector}"),
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
                b"",
            );
            ds.process_message(parse_at(&raw, ts));
        }
        Arc::new(RwLock::new(ds))
    }

    /// RFC 7315's `related-icid` — the parameter that addresses a B2BUA —
    /// reports its own name, flags itself as an identifier match, and does NOT
    /// rank or read like the timing guess.
    ///
    /// The last assertion is the privacy one: RFC 7315 §4.6's own suggested
    /// construction embeds the generating proxy's hostname or address in the
    /// icid, so like every other strategy here the response carries the
    /// strategy's NAME and never the value it matched on.
    #[tokio::test]
    async fn find_correlated_reports_a_related_icid_match_as_an_identifier_match() {
        const A_ICID: &str = "P-CSCF1.example.net-1718452800-0001";
        let ds = charging_vector_pair(
            &format!("icid-value={A_ICID}"),
            &format!("icid-value=SBC1.example.net-1718452800-0002;related-icid={A_ICID}"),
        );
        let server = SipnabMcp::new(ds, Arc::new(RwLock::new(StreamStore::new(100))));

        let body = text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "leg-a@access".into(),
                    limit: None,
                }))
                .await
                .expect("correlates"),
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");

        assert_eq!(v["total_matched"], 1);
        assert_eq!(v["legs"][0]["call_id"], "leg-b@core");
        assert_eq!(v["legs"][0]["strategy"], "charging_vector_related_icid");
        assert_eq!(
            v["legs"][0]["identifier_match"], true,
            "the icid is compared, not guessed at"
        );
        assert_eq!(v["legs"][0]["score"], 95);
        assert!(
            v["legs"][0]["observed_gap_ms"].is_null(),
            "a timing gap is evidence for a guess, not for an identifier match"
        );
        assert_eq!(
            v["heuristic_only"], false,
            "an identifier match is not a hypothesis"
        );
        assert!(
            v["timing_clock"].is_null(),
            "the clock is not why these legs matched"
        );
        assert!(
            !body.contains(A_ICID),
            "the charging identifier must not reach the response; it is \
             operator-internal and the strategy NAME is the finding"
        );
    }

    /// Plain `icid-value` equality is a DIFFERENT strategy with a different
    /// name and a lower score, because it is a different claim — an
    /// intermediary copied a per-dialog identifier onto a second dialog, which
    /// no RFC grants.
    ///
    /// The two live in one test file precisely so a change that collapses them
    /// into one name fails here.
    #[tokio::test]
    async fn find_correlated_reports_a_plain_icid_match_under_its_own_name() {
        const ICID: &str = "P-CSCF1.example.net-1718452800-0001";
        let ds = charging_vector_pair(
            &format!("icid-value={ICID};icid-generated-at=192.0.2.1"),
            &format!("orig-ioi=home1.example.net;icid-value=\"{ICID}\""),
        );
        let server = SipnabMcp::new(ds, Arc::new(RwLock::new(StreamStore::new(100))));

        let body = text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "leg-a@access".into(),
                    limit: None,
                }))
                .await
                .expect("correlates"),
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");

        assert_eq!(v["total_matched"], 1);
        assert_eq!(v["legs"][0]["strategy"], "charging_vector_icid");
        assert_eq!(v["legs"][0]["identifier_match"], true);
        assert_eq!(v["legs"][0]["score"], 85);
        assert_eq!(v["heuristic_only"], false);
        assert!(
            !body.contains(ICID) && !body.contains("192.0.2.1"),
            "neither the icid nor the generating address may reach the response"
        );
    }

    /// The negative control on the same surface: one character apart is a
    /// different call, and the tool says so by answering with nothing.
    #[tokio::test]
    async fn find_correlated_reports_nothing_for_icids_one_character_apart() {
        let ds = charging_vector_pair(
            "icid-value=P-CSCF1.example.net-1718452800-0001",
            "icid-value=P-CSCF1.example.net-1718452800-0002",
        );
        let server = SipnabMcp::new(ds, Arc::new(RwLock::new(StreamStore::new(100))));
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "leg-a@access".into(),
                    limit: None,
                }))
                .await
                .expect("answers"),
        ))
        .expect("json");
        assert_eq!(v["total_matched"], 0);
        assert_eq!(
            v["heuristic_only"], false,
            "no legs is not the same as legs we guessed at"
        );
    }

    /// An unknown Call-ID correlates with nothing, and does NOT claim the
    /// answer was heuristic — there was no answer at all.
    #[tokio::test]
    async fn an_unknown_call_id_returns_nothing_and_claims_nothing() {
        let server = server_with_dialog("known@x");
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "never-seen@x".into(),
                    limit: None,
                }))
                .await
                .expect("answers"),
        ))
        .unwrap();
        assert_eq!(v["total_matched"], 0);
        assert_eq!(
            v["heuristic_only"], false,
            "no legs is not the same as legs we guessed at"
        );
        assert!(v["capture_identity"]["dialog_generation"].is_u64());
    }

    /// `capture_health` carries the clock state, and it stays counters-only.
    ///
    /// The whole point of that tool is that it can be sent off a production box
    /// without leaking packet data, so a new field has to be integers and
    /// booleans — never a daemon name, a server address or a hostname.
    #[tokio::test]
    async fn capture_health_reports_the_clock_without_leaking_anything() {
        let server = server_with_dialog("clk@x");
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .capture_health(Parameters(CaptureHealthParams { sample_seconds: 1 }))
                .await
                .expect("health"),
        ))
        .unwrap();

        let clock = &v["clock"];
        assert!(
            clock["synchronised"].is_boolean(),
            "clock state must be present"
        );
        assert!(clock["available"].is_boolean());
        assert!(clock["max_error_us"].is_i64());
        assert!(clock["est_error_us"].is_i64());

        // Counters-only: every value under `clock` is a number or a bool. A
        // string here would be an NTP server address or a daemon name, which is
        // exactly what this tool promises never to send.
        for (k, val) in clock.as_object().expect("clock is an object") {
            assert!(
                val.is_number() || val.is_boolean(),
                "clock.{k} is {val}, which is not a counter"
            );
        }
    }

    /// An identifier match carries NO clock, because the clock is not why the
    /// legs matched. Attaching it would invite a reader to weigh a number with
    /// no bearing on the answer.
    #[tokio::test]
    async fn an_identifier_match_carries_no_timing_clock() {
        const A: &str = "ab30317f1a784dc48ff824d0d3715d86";
        const B: &str = "47755a9de7794ba387653f2099600ef2";
        let ds = {
            let mut ds = DialogStore::new(100, false);
            ds.process_message(invite_with_header(
                "leg-a@access",
                "Session-ID",
                &format!("{A};remote={B}"),
                base_ts(),
            ));
            ds.process_message(invite_with_header(
                "leg-b@core",
                "Session-ID",
                &format!("{B};remote={A}"),
                base_ts(),
            ));
            Arc::new(RwLock::new(ds))
        };
        let server = SipnabMcp::new(ds, Arc::new(RwLock::new(StreamStore::new(100))));
        let v: serde_json::Value = serde_json::from_str(&text_of(
            &server
                .find_correlated(Parameters(FindCorrelatedParams {
                    call_id: "leg-a@access".into(),
                    limit: None,
                }))
                .await
                .expect("correlates"),
        ))
        .unwrap();

        assert_eq!(v["legs"][0]["strategy"], "session_id");
        assert!(
            v["timing_clock"].is_null(),
            "null means no time-based match was returned, not that the clock is fine"
        );
    }
}
