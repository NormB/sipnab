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
use crate::sip::dialog::SipDialog;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::{FilterExpr, expand_alias};

use super::shape::{HARD_LIMIT, resolve_limit};

/// Holds the shared analysis state and the rmcp tool router.
#[derive(Clone)]
pub struct SipnabMcp {
    pub dialog_store: Arc<RwLock<DialogStore>>,
    pub stream_store: Arc<RwLock<StreamStore>>,
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
            tool_router: Self::tool_router(),
        }
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

// ── Compact summary returned by list_dialogs / find_problems ────────

/// Minimal per-dialog row — keeps response size predictable.
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DialogSummary {
    pub call_id: String,
    pub state: String,
    pub method: String,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub created_at: String,
    pub updated_at: String,
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
        let kinds = params
            .kinds
            .unwrap_or_else(|| vec!["problems".to_string()]);

        // Compile each kind individually so a bad alias is reported by name.
        let mut compiled: Vec<FilterExpr> = Vec::with_capacity(kinds.len());
        for k in &kinds {
            let expr_str = expand_alias(k).ok_or_else(|| {
                rmcp::ErrorData::invalid_params(
                    format!("unknown alias '{k}'"),
                    None,
                )
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

    fn empty_server() -> SipnabMcp {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        SipnabMcp::new(ds, ss)
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
        assert!(raw.contains("[]"), "empty store should return [], got: {raw}");
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
}
