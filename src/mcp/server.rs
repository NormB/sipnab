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
    /// rmcp router mapping tool names to the handler methods below.
    tool_router: ToolRouter<Self>,
}

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
            file_root: None,
            protected_inputs: Default::default(),
            allow_shutdown: false,
            allow_open_capture: false,
            capture: Arc::new(RwLock::new(CaptureState::default())),
            tool_router: Self::tool_router(),
        }
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
    /// SIP messages seen OUTSIDE `--portrange` and therefore analysed by
    /// nothing: they are in no dialog, no stream and no count above.
    ///
    /// Always present, including when it is zero. A field that appears only
    /// when something went wrong is a field the reader never learns exists,
    /// and this reader is a model that cannot ask a follow-up question. The
    /// CLI already prints this beside its summary; before this field the MCP
    /// surface returned a byte-identical key set whether a third of the
    /// capture had been dropped or none of it had.
    pub unanalysed_sip_messages: u64,
    /// The busiest ports carrying that unanalysed SIP, busiest first, capped
    /// at five. Empty when nothing was skipped.
    ///
    /// The service port — destination of a request, source of a response —
    /// never the ephemeral port, which differs per dialog and names nothing.
    pub unanalysed_busiest_ports: Vec<UnanalysedPort>,
    /// Which capture these counts describe, and which revision of its stores.
    ///
    /// Every number above is a whole-store aggregate, so a swap changes all of
    /// them at once with nothing else in the response to say why.
    pub capture_identity: crate::provenance::CaptureEtag,
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
        let dialogs: Vec<DialogSummary> = page.iter().map(|d| DialogSummary::from(*d)).collect();
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
                       flag, and next_cursor for the remaining dialogs."
    )]
    pub async fn list_dialogs(
        &self,
        Parameters(params): Parameters<ListDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
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
            let summaries: Vec<DialogSummary> =
                changed.into_iter().map(DialogSummary::from).collect();
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
                       streams, orphaned-stream count, active-call count, \
                       and the count of SIP messages seen outside \
                       --portrange that nothing analysed."
    )]
    pub async fn stats(&self) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload = {
            // Capture lock first, then the stores — see `CaptureState`.
            let state = self.capture.read();
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let skipped = crate::pipeline::portrange_skip_report();
            let resp = StatsResponse {
                capture_identity: state.identity.etag(ds.generation(), ss.generation()),
                schema_version: 1,
                dialog_count: ds.len(),
                stream_count: ss.len(),
                orphaned_stream_count: ss.orphaned_count(),
                active_call_count: ds.active_count(),
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
            };
            drop(ss);
            drop(ds);
            drop(state);
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
                capture_identity: state.identity.etag(ds.generation(), ss.generation()),
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
                       confusingly otherwise."
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
                       for a clean call."
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
                "findings": findings,
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
                       .sipnablint applied with the counts it silenced."
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
                "findings": findings,
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
                       returns invalid_params listing the whole catalogue."
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
        description = "Writes the SIP signalling sipnab is holding to a pcap file \
                       in the configured file root and returns the path. The \
                       file is NOT a copy of the capture: sipnab keeps parsed \
                       messages rather than the original frames, so each message \
                       is written as a re-synthesised Ethernet/IP/UDP frame with \
                       reconstructed link and IP headers. It contains no RTP, no \
                       RTCP and no non-SIP traffic, and a SIP-over-TCP message \
                       is written as UDP. Use it to preserve signalling before \
                       stopping a live capture — otherwise the messages end with \
                       the process."
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
                       with answers from this one."
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
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SipnabMcp {
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
        let base = std::env::temp_dir().join("sipnab-mcp-root-symlink");
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

    /// An ordinary name inside the root still resolves, so the check above is
    /// not simply refusing everything.
    #[cfg(unix)]
    #[test]
    fn a_plain_name_inside_the_file_root_still_resolves() {
        let root = std::env::temp_dir().join("sipnab-mcp-root-plain");
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
        let result = server.stats().await.expect("stats should succeed");
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

    /// A store with one dialog and no streams reports counts 1 and 0.
    #[tokio::test]
    async fn stats_counts_dialogs() {
        let server = server_with_dialog("stat@x");
        let result = server.stats().await.expect("stats should succeed");
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
        let root = std::env::temp_dir().join(format!("sipnab-open-capture-{dir}"));
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
                "stats",
                serde_json::from_str(&text_of(&server.stats().await.expect("stats"))).unwrap(),
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

    /// The generation must move when the store does, or the etag says
    /// "unchanged" about a store that changed.
    #[tokio::test]
    async fn the_generation_moves_when_the_store_does() {
        let server = server_with_dialog("gen@x");
        let before: serde_json::Value =
            serde_json::from_str(&text_of(&server.stats().await.expect("stats"))).unwrap();
        {
            let mut ds = server.dialog_store.write();
            ds.process_message(invite("gen2@x", base_ts()));
        }
        let after: serde_json::Value =
            serde_json::from_str(&text_of(&server.stats().await.expect("stats"))).unwrap();
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
        let root = std::env::temp_dir().join("sipnab-mcp-supp-explicit");
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
        let root = std::env::temp_dir().join("sipnab-mcp-supp-missing");
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
}
