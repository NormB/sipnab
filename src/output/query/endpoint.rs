// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Everything one endpoint did: dialogs by method and state, messages, call
//! outcomes, registration, banners, the signaling stack, media, and its most
//! recent dialogs.
//!
//! One answer, [`EndpointAnswer`], built by [`endpoint`]: `GET /v1/endpoints`
//! serializes it and `--endpoint-ip` and `--endpoint-user` print it. The scan
//! is [`crate::sip::endpoint::describe`], which the MCP `describe_endpoint`
//! tool also reads. The rollup covers every dialog the endpoint took part
//! in: no surface narrows it by a filter.

use serde_json::{Value, json};

use crate::output::ReportFormat;
use crate::output::model::DialogSummary;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::endpoint::{EndpointReport, Selector};

/// The rollup: the JSON REST returns, and the report and recent dialogs the
/// CLI's text is drawn from.
#[derive(Debug, Clone)]
pub struct EndpointAnswer {
    /// The REST answer, exactly.
    pub json: Value,
    /// The scan the answer was built from.
    pub report: EndpointReport,
    /// The most recent dialogs, newest first, as `recent_dialogs` lists them.
    pub recent: Vec<DialogSummary>,
}

impl serde::Serialize for EndpointAnswer {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.json.serialize(s)
    }
}

/// Describe the endpoint `selector` names, listing at most `limit` recent
/// dialogs; the counts describe every match.
#[must_use]
pub fn endpoint(
    ds: &DialogStore,
    ss: &StreamStore,
    selector: &Selector,
    limit: usize,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> EndpointAnswer {
    let report = crate::sip::endpoint::describe(ds, ss, selector, limit);
    let recent: Vec<DialogSummary> = report
        .recent_call_ids
        .iter()
        .filter_map(|id| ds.get(id))
        .map(DialogSummary::from)
        .collect();
    let user_agents: Vec<Value> = report
        .banners
        .iter()
        .map(|b| json!({ "header": b.header, "value": b.value, "count": b.count }))
        .collect();
    let recent_dialogs: Vec<Value> = recent
        .iter()
        .map(|d| {
            serde_json::to_value(d)
                .unwrap_or_else(|e| json!({"error": format!("serialization failed: {e}")}))
        })
        .collect();
    let calls = json!({
        "invites": report.calls.invites,
        "with_final_status": report.calls.with_final_status,
        "failed": report.calls.failed,
        "failure_rate_pct": report.calls.failure_rate_pct,
        "by_final_status": report.calls.by_final_status,
    });
    let registration = json!({
        "applicable": report.registration.applicable,
        "dialogs": report.registration.dialogs,
        "succeeded": report.registration.succeeded,
        "failed": report.registration.failed,
        "auth_loops": report.registration.auth_loops,
        "problem_call_ids": report.registration.problem_call_ids,
    });
    let streams = json!({
        "count": report.streams.count,
        "orphaned": report.streams.orphaned,
        "packets": report.streams.packets,
        "lost_packets": report.streams.lost_packets,
        "max_jitter_ms": report.streams.max_jitter_ms,
        "codecs": report.streams.codecs,
    });
    let json = json!({
        "schema_version": 1,
        "endpoint_kind": report.kind,
        "endpoint": report.value,
        "dialogs": report.dialogs,
        "by_method": report.by_method,
        "by_state": report.by_state,
        "messages_sent": report.messages_sent,
        "messages_received": report.messages_received,
        "calls": calls,
        "registration": registration,
        "user_agents": user_agents,
        "stack": report.stack,
        "contact_rewrite": report.contact_rewrite,
        "streams": streams,
        "recent_dialogs": recent_dialogs,
        "truncated": report.truncated,
        // Which capture this description came from; see `/v1/dialogs`.
        "capture_identity": capture_identity,
    });
    EndpointAnswer {
        json,
        report,
        recent,
    }
}

/// `counts` as `key n, key n`, or `none`.
fn listed(counts: &std::collections::BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_string();
    }
    counts
        .iter()
        .map(|(k, n)| format!("{} {n}", super::clean(k)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The rollup as text: one line per aspect of what the endpoint did, then
/// its most recent dialogs as a table. Values read off the wire (banners,
/// codecs, Call-IDs) are scrubbed of control characters.
#[must_use]
pub fn render(answer: &EndpointAnswer, format: ReportFormat) -> String {
    use std::fmt::Write as _;

    let r = &answer.report;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Endpoint {} {}: {}",
        r.kind,
        super::clean(&r.value),
        super::plural(r.dialogs as u64, "dialog")
    );
    let _ = writeln!(out, "Dialogs by method: {}", listed(&r.by_method));
    let _ = writeln!(out, "Dialogs by state: {}", listed(&r.by_state));
    if r.kind == "ip" {
        let _ = writeln!(
            out,
            "Messages: {} sent, {} received",
            r.messages_sent, r.messages_received
        );
    }
    let finals = if r.calls.by_final_status.is_empty() {
        "none".to_string()
    } else {
        r.calls
            .by_final_status
            .iter()
            .map(|(code, n)| format!("{code} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(
        out,
        "Calls: {}, {} with a final response, {} failed ({}); final responses: {finals}",
        super::plural(r.calls.invites as u64, "INVITE"),
        r.calls.with_final_status,
        r.calls.failed,
        r.calls.failure_rate_pct.map_or_else(
            || "-".to_string(),
            |p| format!("{}%", (p * 10.0).round() / 10.0)
        ),
    );
    if r.registration.applicable {
        let _ = writeln!(
            out,
            "Registration: {}, {} succeeded, {} failed, {}",
            super::plural(r.registration.dialogs as u64, "dialog"),
            r.registration.succeeded,
            r.registration.failed,
            super::plural(r.registration.auth_loops as u64, "authentication loop"),
        );
    }
    let banners = if r.banners.is_empty() {
        "none".to_string()
    } else {
        r.banners
            .iter()
            .map(|b| format!("{} {} ({})", b.header, super::clean(&b.value), b.count))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let _ = writeln!(out, "Banners: {banners}");
    let _ = writeln!(
        out,
        "Signaling stack: {}",
        r.stack.inference.map_or_else(
            || "not inferred".to_string(),
            |name| format!(
                "{name}, {} of 3 observations agree, from {}",
                r.stack.confidence,
                super::plural(r.stack.requests_read as u64, "request")
            )
        )
    );
    if let Some(rewrite) = &r.contact_rewrite {
        use crate::sip::contact_rewrite::RewriteVerdict;
        let _ = writeln!(
            out,
            "Private Contact: {}",
            match rewrite.verdict {
                RewriteVerdict::Rewritten => format!(
                    "rewritten by the registrar, {} sent to the source",
                    super::plural(rewrite.requests_to_source as u64, "later request")
                ),
                RewriteVerdict::NotRewritten => format!(
                    "not rewritten, {} sent to the private host",
                    super::plural(rewrite.requests_to_contact as u64, "later request")
                ),
                RewriteVerdict::NoLaterRequests => {
                    "no later request, so whether it was rewritten is unknown".to_string()
                }
            }
        );
    }
    let _ = writeln!(
        out,
        "Media: {} ({} orphaned), {} packets, {} lost, max jitter {}, codecs {}",
        super::plural(r.streams.count as u64, "stream"),
        r.streams.orphaned,
        r.streams.packets,
        r.streams.lost_packets,
        r.streams
            .max_jitter_ms
            .map_or_else(|| "-".to_string(), |j| format!("{:.2} ms", j)),
        if r.streams.codecs.is_empty() {
            "none".to_string()
        } else {
            super::clean(&r.streams.codecs.join(", "))
        },
    );
    let rows: Vec<Vec<String>> = answer
        .recent
        .iter()
        .map(|d| {
            vec![
                d.call_id.clone(),
                d.method.clone(),
                d.state.clone(),
                d.final_status_code
                    .map_or_else(|| "-".to_string(), |c| c.to_string()),
                d.created_at.clone(),
            ]
        })
        .collect();
    let _ = writeln!(
        out,
        "Most recent dialogs ({} of {}):",
        answer.recent.len(),
        r.dialogs
    );
    out.push_str(&super::table(
        format,
        &["Call-ID", "Method", "State", "Final", "Started"],
        &rows,
    ));
    out
}
