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
    /// rmcp router mapping tool names to the handler methods below.
    tool_router: ToolRouter<Self>,
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
    /// Maximum dialogs to return (1..=1000, default 50).
    pub limit: Option<u32>,
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct RtpStatsParams {
    /// Call-ID identifying the dialog.
    pub call_id: String,
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

/// Separator between the timestamp and Call-ID halves of a compound
/// `tail_dialogs` cursor. `|` appears in neither an RFC 3339 timestamp
/// nor a valid Call-ID (RFC 3261 `word`), so the split is unambiguous.
const TAIL_CURSOR_SEP: char = '|';

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

// ── Tool implementations ────────────────────────────────────────────

#[tool_router(router = tool_router)]
impl SipnabMcp {
    /// Returns dialog summaries from the live store. Optional `filter` accepts
    /// named aliases (problems, slow-setup, short-calls, one-way, nat-issues,
    /// codec-asym, ptime-asym, payload-asym, duration-asym, late-media) or a
    /// raw DSL expression. Output is bounded by `limit` (default 50, max 1000).
    ///
    /// # Returns
    ///
    /// A JSON array of `DialogSummary` rows (empty when nothing matches).
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `filter` is neither a known alias nor a
    /// parseable DSL expression.
    #[tool(
        name = "list_dialogs",
        description = "Returns dialog summaries from the live capture store. \
                       Filter accepts a diagnostic alias name or a raw DSL expression. \
                       Output is paginated and capped at 1000 entries per call."
    )]
    pub async fn list_dialogs(
        &self,
        Parameters(params): Parameters<ListDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);

        // Compile the filter outside the lock so we don't hold it during
        // potentially-expensive DSL parsing.
        let compiled_filter = if let Some(ref f) = params.filter {
            let expr_str = expand_alias(f).unwrap_or(f);
            match FilterExpr::parse(expr_str) {
                Ok(expr) => Some(expr),
                Err(e) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("invalid filter '{f}': {e}"),
                        None,
                    ));
                }
            }
        } else {
            None
        };

        // Snapshot under the read lock, then drop before serializing.
        let summaries: Vec<DialogSummary> = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let mut out = Vec::with_capacity(limit.min(HARD_LIMIT));
            for d in ds.iter() {
                if let Some(ref expr) = compiled_filter {
                    let streams: Vec<&crate::rtp::stream::RtpStream> =
                        ss.streams_for(&d.call_id).collect();
                    if !expr.matches_dialog(d, &streams) {
                        continue;
                    }
                }
                out.push(DialogSummary::from(d));
                if out.len() >= limit {
                    break;
                }
            }
            drop(ss);
            drop(ds);
            out
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(
            summaries,
        )?]))
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
    /// `kinds` (default `["problems"]`) and ORs the matches together. Useful
    /// when you want "anything that looks problematic" in one call.
    ///
    /// # Returns
    ///
    /// A JSON array of `DialogSummary` rows matching any alias (empty when
    /// nothing matches).
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) for an unknown alias name or an alias whose
    /// expansion fails to parse.
    #[tool(
        name = "find_problems",
        description = "Returns dialogs that match any of the named diagnostic \
                       aliases (problems, slow-setup, short-calls, one-way, \
                       nat-issues, codec-asym, ptime-asym, payload-asym, \
                       duration-asym, late-media). Defaults to ['problems']."
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

        let summaries: Vec<DialogSummary> = {
            let ds = self.dialog_store.read();
            let ss = self.stream_store.read();
            let mut out = Vec::with_capacity(limit.min(HARD_LIMIT));
            for d in ds.iter() {
                let streams: Vec<&crate::rtp::stream::RtpStream> =
                    ss.streams_for(&d.call_id).collect();
                if compiled.iter().any(|expr| expr.matches_dialog(d, &streams)) {
                    out.push(DialogSummary::from(d));
                    if out.len() >= limit {
                        break;
                    }
                }
            }
            drop(ss);
            drop(ds);
            out
        };

        Ok(CallToolResult::success(vec![ContentBlock::json(
            summaries,
        )?]))
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

    /// Returns RTP quality stats for all streams associated with the dialog.
    ///
    /// # Returns
    ///
    /// A JSON object with the `call_id`, a `streams` array (empty when the
    /// dialog has no media), and the media `diagnosis`.
    ///
    /// # Errors
    ///
    /// `invalid_params` (-32602) when `call_id` is not found.
    #[tool(
        name = "rtp_stats",
        description = "Returns per-stream RTP quality (codec, MOS, jitter, \
                       loss%, packet count, SSRC) plus media diagnosis for \
                       every stream associated with the given Call-ID."
    )]
    pub async fn rtp_stats(
        &self,
        Parameters(params): Parameters<RtpStatsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let payload: serde_json::Value = {
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
            let stream_jsons: Vec<serde_json::Value> = dialog_streams
                .iter()
                .map(|s| {
                    let line = crate::output::json::stream_to_json(s);
                    serde_json::from_str(&line).unwrap_or(serde_json::Value::Null)
                })
                .collect();
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
                "call_id": params.call_id,
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
        let needle = params.query.to_lowercase();
        let hits: Vec<SearchHit> = {
            let ds = self.dialog_store.read();
            let mut out: Vec<SearchHit> = Vec::new();
            'outer: for d in ds.iter() {
                for (idx, msg) in d.messages.iter().enumerate() {
                    let haystack = format!(
                        "{} {} {} {} {} {}",
                        msg.method.as_ref().map(|m| m.as_str()).unwrap_or(""),
                        msg.status_code.map(|s| s.to_string()).unwrap_or_default(),
                        msg.from_header().unwrap_or(""),
                        msg.to_header().unwrap_or(""),
                        msg.user_agent().unwrap_or(""),
                        String::from_utf8_lossy(&msg.body),
                    )
                    .to_lowercase();
                    if haystack.contains(&needle) {
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
        // (compound, what next_cursor emits). `|` cannot appear in an
        // RFC 3339 timestamp or a valid Call-ID (RFC 3261 `word` has no
        // `|`), so splitting on the first `|` is unambiguous.
        let cursor: Option<(chrono::DateTime<chrono::Utc>, Option<String>)> = match params.cursor {
            Some(s) => {
                let (ts_part, id_part) = match s.split_once(TAIL_CURSOR_SEP) {
                    Some((ts, id)) => (ts, Some(id.to_string())),
                    None => (s.as_str(), None),
                };
                match chrono::DateTime::parse_from_rfc3339(ts_part) {
                    Ok(dt) => Some((dt.with_timezone(&chrono::Utc), id_part)),
                    Err(e) => {
                        return Err(rmcp::ErrorData::invalid_params(
                            format!("cursor must be RFC 3339: {e}"),
                            None,
                        ));
                    }
                }
            }
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
                .filter(|d| match &cursor {
                    None => true,
                    Some((ts, None)) => d.updated_at > *ts,
                    Some((ts, Some(id))) => {
                        d.updated_at > *ts || (d.updated_at == *ts && d.call_id > *id)
                    }
                })
                .collect();
            changed.sort_by(|a, b| {
                a.updated_at
                    .cmp(&b.updated_at)
                    .then_with(|| a.call_id.cmp(&b.call_id))
            });
            changed.truncate(limit);
            let next_cursor = changed.last().map(|d| {
                format!(
                    "{}{TAIL_CURSOR_SEP}{}",
                    d.updated_at.to_rfc3339(),
                    d.call_id
                )
            });
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
                limit: None,
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
                limit: None,
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
                call_id: "missing@x".to_string(),
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
                call_id: "rtp@x".to_string(),
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
