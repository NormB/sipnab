//! Phase 8.1 — `SipnabMcp` server: three v0.4.0 read-only tools backed
//! by the existing dialog/stream stores.
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
//! and only then awaits or builds the response. The module-level
//! `#![deny(clippy::await_holding_lock)]` (in `mod.rs`) catches violations
//! mechanically.

use std::sync::Arc;

use parking_lot::RwLock;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars::JsonSchema;
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::output::{ReportFormat, generate_call_report};
use crate::rtp::diagnosis::{AsymmetryThresholds, diagnose_asymmetry, diagnose_media};
use crate::rtp::stream_store::StreamStore;
use crate::security::alerting::AlertEngine;
use crate::sip::dialog::SipDialog;
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
            tool_router: Self::tool_router(),
        }
    }

    /// Attach a shared alert engine so the `security_findings` tool can
    /// read from its FindingsHistory ring buffer.
    pub fn with_alert_engine(mut self, alerts: Arc<RwLock<AlertEngine>>) -> Self {
        self.alert_engine = Some(alerts);
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

// ── Phase 8.3 parameter structs ─────────────────────────────────────

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

/// Parameters for `tail_dialogs`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TailDialogsParams {
    /// Cursor: an RFC 3339 timestamp; only dialogs updated strictly after
    /// this are returned. Omit on the first call to start from the
    /// beginning.
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
    /// Dialogs updated since the request cursor, oldest first.
    pub dialogs: Vec<DialogSummary>,
    /// Cursor to pass to the next call. Empty when no more updates exist
    /// at the moment.
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

/// Minimal per-dialog row — keeps response size predictable.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DialogSummary {
    /// Call-ID identifying the dialog.
    pub call_id: String,
    /// Current dialog state (e.g. "Confirmed", "Terminated").
    pub state: String,
    /// SIP method that initiated the dialog.
    pub method: String,
    /// User portion of the From URI, if present.
    pub from_user: Option<String>,
    /// User portion of the To URI, if present.
    pub to_user: Option<String>,
    /// RFC 3339 timestamp of the first message.
    pub created_at: String,
    /// RFC 3339 timestamp of the most recent message.
    pub updated_at: String,
    /// Number of SIP messages in the dialog.
    pub message_count: usize,
}

impl From<&SipDialog> for DialogSummary {
    fn from(d: &SipDialog) -> Self {
        Self {
            call_id: d.call_id.clone(),
            state: d.state().to_string(),
            method: format!("{:?}", d.method),
            from_user: d.from_user.clone(),
            to_user: d.to_user.clone(),
            created_at: d.created_at.to_rfc3339(),
            updated_at: d.updated_at.to_rfc3339(),
            message_count: d.messages.len(),
        }
    }
}

// ── Tool implementations ────────────────────────────────────────────

#[tool_router(router = tool_router)]
impl SipnabMcp {
    /// Returns dialog summaries from the live store. Optional `filter` accepts
    /// named aliases (problems, slow-setup, short-calls, one-way, nat-issues,
    /// codec-asym, ptime-asym, payload-asym, duration-asym, late-media) or a
    /// raw DSL expression. Output is bounded by `limit` (default 50, max 1000).
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
                    let streams: Vec<&crate::rtp::stream::RtpStream> = ss
                        .iter()
                        .filter(|s| s.associated_dialog.as_deref() == Some(d.call_id.as_str()))
                        .collect();
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

        Ok(CallToolResult::success(vec![Content::json(summaries)?]))
    }

    /// Returns a structured per-call report (timing, parties, RTP quality,
    /// diagnosis hints) for one Call-ID. Format defaults to JSON; "markdown"
    /// and "text" produce human-readable variants identical to
    /// `--call-report --markdown` and `--call-report` respectively.
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
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> = ss
                .iter()
                .filter(|s| s.associated_dialog.as_deref() == Some(params.call_id.as_str()))
                .collect();

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
                Ok(v) => Content::json(v)?,
                Err(_) => Content::text(report),
            }
        } else {
            Content::text(report)
        };
        Ok(CallToolResult::success(vec![content]))
    }

    /// Convenience wrapper over `list_dialogs` — runs each named alias from
    /// `kinds` (default `["problems"]`) and ORs the matches together. Useful
    /// when you want "anything that looks problematic" in one call.
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
                let streams: Vec<&crate::rtp::stream::RtpStream> = ss
                    .iter()
                    .filter(|s| s.associated_dialog.as_deref() == Some(d.call_id.as_str()))
                    .collect();
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

        Ok(CallToolResult::success(vec![Content::json(summaries)?]))
    }

    // ── Phase 8.3 tools ─────────────────────────────────────────────

    /// Returns a paginated dialog including its SIP messages.
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
                    .map(|m| {
                        let line = crate::output::json::message_to_json(m);
                        serde_json::from_str::<serde_json::Value>(line.trim_end())
                            .unwrap_or(serde_json::Value::String(line))
                    })
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

        Ok(CallToolResult::success(vec![Content::json(payload)?]))
    }

    /// Returns a single SIP message at the given index.
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
        let line: String = {
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
            crate::output::json::message_to_json(msg)
        };
        let parsed: serde_json::Value =
            serde_json::from_str(line.trim_end()).unwrap_or(serde_json::Value::String(line));
        Ok(CallToolResult::success(vec![Content::json(parsed)?]))
    }

    /// Renders a SIP call-flow ladder as markdown or text.
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
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> = ss
                .iter()
                .filter(|s| s.associated_dialog.as_deref() == Some(params.call_id.as_str()))
                .collect();
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
        Ok(CallToolResult::success(vec![Content::text(report)]))
    }

    /// Returns RTP quality stats for all streams associated with the dialog.
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
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> = ss
                .iter()
                .filter(|s| s.associated_dialog.as_deref() == Some(params.call_id.as_str()))
                .collect();
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
        Ok(CallToolResult::success(vec![Content::json(payload)?]))
    }

    /// Substring-search SIP messages across all dialogs.
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
        Ok(CallToolResult::success(vec![Content::json(hits)?]))
    }

    /// Incremental dialog fetch — returns dialogs updated strictly after the
    /// supplied cursor.
    #[tool(
        name = "tail_dialogs",
        description = "Returns dialogs whose updated_at is strictly after \
                       `cursor` (an RFC 3339 timestamp, omit for first call). \
                       Used for polling-based change tracking. The response \
                       carries source_exhausted=true after a pcap source has \
                       been fully consumed."
    )]
    pub async fn tail_dialogs(
        &self,
        Parameters(params): Parameters<TailDialogsParams>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let limit = resolve_limit(params.limit);
        let cursor: Option<chrono::DateTime<chrono::Utc>> = match params.cursor {
            Some(s) => match chrono::DateTime::parse_from_rfc3339(&s) {
                Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                Err(e) => {
                    return Err(rmcp::ErrorData::invalid_params(
                        format!("cursor must be RFC 3339: {e}"),
                        None,
                    ));
                }
            },
            None => None,
        };

        let response: TailDialogsResponse = {
            let ds = self.dialog_store.read();
            let mut summaries: Vec<DialogSummary> = Vec::new();
            for d in ds.iter() {
                if let Some(c) = cursor
                    && d.updated_at <= c
                {
                    continue;
                }
                summaries.push(DialogSummary::from(d));
                if summaries.len() >= limit {
                    break;
                }
            }
            // Sort ascending by updated_at so the next_cursor is the latest
            // updated_at returned, which establishes a clean "fetch >cursor"
            // contract.
            summaries.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
            let next_cursor = summaries.last().map(|s| s.updated_at.clone());
            drop(ds);
            TailDialogsResponse {
                dialogs: summaries,
                next_cursor,
                source_exhausted: false, // 8.3 stub; 8.5 sets this from capture state
            }
        };

        Ok(CallToolResult::success(vec![Content::json(response)?]))
    }

    /// Returns recent security findings (scanner/fraud/digest/reg-flood/etc.)
    /// from the in-memory ring buffer. When the AlertEngine isn't attached
    /// (e.g. running in a query-only mode without active detection rules),
    /// returns an empty list rather than erroring.
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
        Ok(CallToolResult::success(vec![Content::json(findings)?]))
    }

    /// Aggregate counters across the active stores.
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
        Ok(CallToolResult::success(vec![Content::json(payload)?]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SipnabMcp {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use crate::test_utils::build_sip_message as build_sip;
    use std::net::{IpAddr, Ipv4Addr};

    fn empty_server() -> SipnabMcp {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        SipnabMcp::new(ds, ss)
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    fn base_ts() -> chrono::DateTime<chrono::Utc> {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn parse_at(raw: &[u8], ts: chrono::DateTime<chrono::Utc>) -> crate::sip::SipMessage {
        parse_sip(raw, ts, localhost(), localhost(), 5060, 5060, TransportProto::Udp)
            .expect("should parse SIP")
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

    #[tokio::test]
    async fn list_dialogs_returns_summary_for_populated_store() {
        let server = server_with_dialog("call-list@x");
        let result = server
            .list_dialogs(Parameters(ListDialogsParams::default()))
            .await
            .expect("list_dialogs should succeed");
        let raw = text_of(&result);
        assert!(raw.contains("call-list@x"), "summary must name the dialog: {raw}");
        assert!(raw.contains("alice"), "from_user should appear: {raw}");
    }

    // ── get_dialog_report success paths ──────────────────────────────

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
        assert!(!text_of(&result).is_empty(), "ladder text must be non-empty");
    }

    // ── rtp_stats ────────────────────────────────────────────────────

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
        assert!(hits[0]["snippet"].as_str().unwrap().to_lowercase().contains("alice"));
    }

    // ── tail_dialogs ─────────────────────────────────────────────────

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

    #[tokio::test]
    async fn tail_dialogs_no_cursor_returns_all_with_next_cursor() {
        let server = server_with_dialog("tail@x");
        let result = server
            .tail_dialogs(Parameters(TailDialogsParams::default()))
            .await
            .expect("tail should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["dialogs"].as_array().unwrap().len(), 1);
        assert!(v["next_cursor"].is_string(), "next_cursor set when dialogs returned");
        assert_eq!(v["source_exhausted"], false);
    }

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

    // ── security_findings ────────────────────────────────────────────

    #[tokio::test]
    async fn security_findings_no_engine_returns_empty() {
        let server = empty_server();
        let result = server
            .security_findings(Parameters(SecurityFindingsParams::default()))
            .await
            .expect("no engine → empty list");
        assert!(text_of(&result).contains("[]"));
    }

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

    #[tokio::test]
    async fn stats_counts_dialogs() {
        let server = server_with_dialog("stat@x");
        let result = server.stats().await.expect("stats should succeed");
        let v: serde_json::Value = serde_json::from_str(&text_of(&result)).unwrap();
        assert_eq!(v["dialog_count"], 1);
        assert_eq!(v["stream_count"], 0);
    }
}
