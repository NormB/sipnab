// SPDX-License-Identifier: MIT OR Apache-2.0

//! `SipnabMcp` server: the read-only MCP tools backed by the existing
//! dialog/stream stores (plus the optional alert engine).
//!
//! # Tool descriptions and prompt-injection defense (D22)
//!
//! Tool descriptions never instruct the LLM to "trust", "verify", or
//! "act on" returned content. They state what the tool returns and stop.
//! A CI lint enforces this — see `scripts/check-tool-descriptions.sh`.
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
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::output::{ReportFormat, generate_call_report};
use crate::rtp::diagnosis::{AsymmetryThresholds, diagnose_asymmetry, diagnose_media};
use crate::rtp::stream_store::StreamStore;
use crate::security::alerting::AlertEngine;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::{FilterExpr, expand_alias};

use super::shape::{HARD_LIMIT, resolve_limit};

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
    /// Directory the file tools are confined to. `None` disables them.
    file_root: Option<std::path::PathBuf>,
    /// Whether `shutdown_server` may stop this process.
    allow_shutdown: bool,
    /// What this server is attached to, and when it started.
    ///
    /// An agent had no way to ask whether it was reading a live interface or
    /// replaying a file — so it could not tell whether "stop the capture"
    /// would lose anything, nor whether a quiet capture meant a quiet network
    /// or a finished file. Every downstream misjudgement traced back to that.
    capture: Option<CaptureContext>,
    /// rmcp router mapping tool names to the handler methods below.
    tool_router: ToolRouter<Self>,
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
            file_root: None,
            allow_shutdown: false,
            capture: None,
            tool_router: Self::tool_router(),
        }
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
    pub fn with_capture_context(mut self, ctx: CaptureContext) -> Self {
        self.capture = Some(ctx);
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
        Ok(root.join(name))
    }
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
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Zero-based index of the message in the dialog.
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
    /// True once a file source has been read to the end.
    pub source_exhausted: bool,
    /// Where packets are being written, if anywhere.
    pub writing_to: Option<String>,
    /// True when stopping now would lose packets that exist only in memory.
    ///
    /// The most useful field here: the difference between "restart this
    /// whenever you like" and "an afternoon of capture ends with this process".
    pub unsaved: bool,
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
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
/// Aggregate counts returned by the `stats` tool.
pub struct StatsResponse {
    /// Version of this response schema.
    pub schema_version: u32,
    /// Number of dialogs currently tracked.
    pub dialog_count: usize,
    /// Number of RTP streams currently tracked.
    pub stream_count: usize,
    /// Streams not yet correlated to any dialog.
    pub orphaned_stream_count: usize,
    /// Dialogs currently in an active (non-terminated) state.
    pub active_call_count: usize,
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
        select: impl Fn(&crate::sip::dialog::SipDialog, &[&crate::rtp::stream::RtpStream]) -> bool,
    ) -> Result<DialogPage, rmcp::ErrorData> {
        let cursor = match cursor {
            Some(raw) => Some(
                super::shape::parse_cursor(raw)
                    .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?,
            ),
            None => None,
        };

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
        let mut matched: Vec<&crate::sip::dialog::SipDialog> = ds
            .iter()
            .filter(|d| {
                let streams = by_call
                    .get(d.call_id.as_str())
                    .map_or(NO_STREAMS, Vec::as_slice);
                select(d, streams)
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
        let dialogs: Vec<DialogSummary> = page.iter().map(|d| DialogSummary::from(*d)).collect();
        drop(ss);
        drop(ds);

        Ok(DialogPage {
            schema_version: 1,
            returned: dialogs.len(),
            dialogs,
            total_matched,
            truncated,
            next_cursor,
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
        let limit = resolve_limit(params.limit);
        let cursor = match params.cursor.as_deref() {
            Some(raw) => Some(
                super::shape::parse_cursor(raw)
                    .map_err(|e| rmcp::ErrorData::invalid_params(e, None))?,
            ),
            None => None,
        };
        let bounded = params.min_mos.is_some() || params.max_mos.is_some();

        let page = {
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
            drop(ss);

            StreamPage {
                schema_version: 1,
                returned: streams.len(),
                streams,
                total_matched,
                ungrounded_excluded,
                truncated,
                next_cursor,
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
                       flag, and next_cursor for the remaining dialogs."
    )]
    pub async fn list_dialogs(
        &self,
        Parameters(params): Parameters<ListDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
        let filter = Self::compile_filter(params.filter.as_deref())?;
        let page = self.dialog_page(params.cursor.as_deref(), limit, |d, streams| {
            filter
                .as_ref()
                .is_none_or(|expr| expr.matches_dialog(d, streams))
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
                       Call-ID is not found in the active store."
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

            let mut diag = diagnose_media(&dialog_streams, None);
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
        Ok(CallToolResult::success(vec![content]))
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
                       response carries total_matched, truncated and next_cursor."
    )]
    pub async fn find_problems(
        &self,
        Parameters(params): Parameters<FindProblemsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
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
        let page = self.dialog_page(params.cursor.as_deref(), limit, |d, streams| {
            compiled.iter().any(|expr| expr.matches_dialog(d, streams))
                && extra
                    .as_ref()
                    .is_none_or(|expr| expr.matches_dialog(d, streams))
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
                       (default 100, max 1000) and cursor (default 0)."
    )]
    pub async fn get_dialog(
        &self,
        Parameters(params): Parameters<GetDialogParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let max = match params.max_messages {
            None | Some(0) => 100usize,
            Some(n) => (n as usize).min(HARD_LIMIT),
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
            let summary = DialogSummary::from(dialog);
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
        description = "Returns a single SIP message at the given zero-based \
                       index of a dialog. Returns invalid_params when the \
                       Call-ID is unknown or the index is out of range."
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
            crate::output::json::message_to_json_value(msg)
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(parsed)?]))
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
                       byte-identical to `--call-report --markdown`."
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
            let mut diag = diagnose_media(&dialog_streams, None);
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
        Ok(CallToolResult::success(vec![ContentBlock::text(report)]))
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
                       to codecs with a published ITU-T G.113 impairment value."
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
            let mut diag = diagnose_media(&dialog_streams, None);
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
                       snippet) hits."
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
        let limit = resolve_limit(params.limit);
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
                        let snippet = super::shape::truncate_string(
                            &String::from_utf8_lossy(&msg.raw),
                            super::shape::MAX_BODY_BYTES,
                        );
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
        Ok(CallToolResult::success(vec![ContentBlock::json(hits)?]))
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
                       pcap source has been fully consumed."
    )]
    pub async fn tail_dialogs(
        &self,
        Parameters(params): Parameters<TailDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
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
            let summaries: Vec<DialogSummary> =
                changed.into_iter().map(DialogSummary::from).collect();
            drop(ds);
            TailDialogsResponse {
                dialogs: summaries,
                next_cursor,
                source_exhausted: self
                    .source_exhausted
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed)),
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
                       attached."
    )]
    pub async fn security_findings(
        &self,
        Parameters(params): Parameters<SecurityFindingsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
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

    /// Aggregate counters across the active stores, returned as a
    /// `StatsResponse` JSON object. Takes no parameters and never fails
    /// beyond JSON serialization.
    #[tool(
        name = "stats",
        description = "Returns aggregate counters: total dialogs, total \
                       streams, orphaned-stream count, active-call count."
    )]
    pub async fn stats(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let resp = StatsResponse {
                schema_version: 1,
                dialog_count: ds.len(),
                stream_count: ss.len(),
                orphaned_stream_count: ss.orphaned_count(),
                active_call_count: ds.active_count(),
            };
            drop(ss);
            drop(ds);
            resp
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// What this server is attached to: live interface or file, for how long,
    /// how much it holds, and whether stopping would lose anything.
    #[tool(
        name = "capture_status",
        description = "Returns what this server is capturing: live interface or \
                       replayed file, its name, uptime, how many dialogs and \
                       streams are held, whether a file source is exhausted, and \
                       whether stopping now would lose unsaved packets. Call this \
                       before reasoning about stopping or restarting a capture."
    )]
    pub async fn capture_status(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let exhausted = self
            .source_exhausted
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed));

        let (source, name, uptime_sec, writing_to, live) = match &self.capture {
            Some(c) => (
                if c.live { "live" } else { "file" }.to_string(),
                Some(c.name.clone()),
                Some(c.started.elapsed().as_secs()),
                c.writing_to.clone(),
                c.live,
            ),
            // Reported honestly rather than guessed. A wrong "live" here would
            // be worse than an admission of ignorance: it is the field an agent
            // consults before deciding whether stopping is destructive.
            None => ("unknown".to_string(), None, None, None, false),
        };

        let payload = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let resp = CaptureStatusResponse {
                schema_version: 1,
                source,
                name,
                uptime_sec,
                dialog_count: ds.len(),
                stream_count: ss.len(),
                source_exhausted: exhausted,
                writing_to: writing_to.clone(),
                // Only a live capture can hold packets that exist nowhere else.
                // A file replay is by definition already on disk.
                unsaved: live && writing_to.is_none(),
            };
            drop(ss);
            drop(ds);
            resp
        };
        Ok(CallToolResult::success(vec![ContentBlock::json(payload)?]))
    }

    /// Which optional features this binary was built with.
    #[tool(
        name = "server_capabilities",
        description = "Returns the sipnab version and which optional features \
                       this binary was compiled with (tls, hep, plugins, ...). \
                       Call this before asking for decryption or HEP: a build \
                       without the feature fails confusingly otherwise."
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
                       instead of recalling codes from memory."
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
                       'why did this call work and that one not?'."
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
                       or the two ends disagree about the codec."
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
                       total_matched and a truncated flag."
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
        let limit = crate::mcp::shape::resolve_limit(params.limit);
        let filter = Self::compile_filter(params.filter.as_deref())?;

        let payload = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
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
                        expr.matches_dialog(d, &streams)
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
                       different causes and different fixes."
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
            let mut media = crate::rtp::diagnosis::diagnose_media(&streams, None);
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
                       codec it accepts."
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
                       question from 'why did this call fail?'."
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

    /// List capture files in the configured root.
    #[tool(
        name = "list_captures",
        description = "Lists capture files (.pcap/.pcapng) in the server's \
                       configured file root, with sizes. Requires \
                       --mcp-file-root."
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
        description = "Writes the packets sipnab is holding to a pcap file in \
                       the configured file root and returns the path. Use it to \
                       preserve a live capture before stopping it — otherwise \
                       the packets end with the process."
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
                       decodable audio."
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

    /// Stop this sipnab process. Opt-in, dry-run by default.
    #[tool(
        name = "shutdown_server",
        description = "Stops this sipnab process. DESTRUCTIVE. Requires \
                       --mcp-allow-shutdown on the server. Defaults to a DRY \
                       RUN that only reports what would happen; pass \
                       dry_run=false to actually stop. Refuses to discard an \
                       unsaved live capture unless save_to is given or \
                       discard_unsaved=true."
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

        let (live, writing_to) = match &self.capture {
            Some(c) => (c.live, c.writing_to.clone()),
            None => (false, None),
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
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SipnabMcp {
    /// Advertise server capabilities (tools only) and the human-readable
    /// instructions string shown to MCP clients.
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build());
        info.instructions = Some(
            "sipnab MCP server — read-only access to captured SIP dialogs, \
             RTP streams, diagnostics, and security findings."
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
    let mut writer = PcapWriter::with_format(
        path,
        // DLT_EN10MB: the synthetic frames carry an Ethernet header.
        1,
        None,
        None,
        pcapng,
        // Raw: no key material embedded. An agent-triggered export must not
        // write decryption secrets into a file it just named.
        PcapExportMode::Raw,
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
                "Content-Length: 0",
            ],
            b"",
        );
        parse_at(&raw, ts)
    }

    /// A server whose dialog store holds one dialog (`call_id`) with an
    /// INVITE followed by a 200 OK (two messages).
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
    fn text_of(result: &CallToolResult) -> String {
        result.content[0]
            .as_text()
            .expect("content should be text-able")
            .text
            .clone()
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
        engine.fire("scanner", localhost(), "probe from scanner");
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
        engine.fire("scanner", localhost(), "scan");
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

    /// Empty stores report schema_version 1 and all-zero counters.
    #[tokio::test]
    async fn stats_empty_store_all_zero() {
        let server = empty_server();
        let result = server.stats().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["dialog_count"], 0);
        assert_eq!(v["stream_count"], 0);
        assert_eq!(v["orphaned_stream_count"], 0);
        assert_eq!(v["active_call_count"], 0);
    }

    /// A store with one dialog and no streams reports counts 1 and 0.
    #[tokio::test]
    async fn stats_counts_dialogs() {
        let server = server_with_dialog("stat@x");
        let result = server.stats().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["dialog_count"], 1);
        assert_eq!(v["stream_count"], 0);
    }
}
