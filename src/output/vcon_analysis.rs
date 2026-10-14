// SPDX-License-Identifier: MIT OR Apache-2.0

//! The analysis of one stored vCon container handed over inline: what the MCP
//! `analyze_vcon` tool and `POST /v1/vcon/analyze` both answer.
//!
//! One function for both surfaces, so the two cannot disagree about one
//! container. The container is rebuilt by [`crate::capture::vcon_input`] into
//! a pair of stores of its own, analyzed there, and dropped: nothing touches
//! the server's capture, and no connection is made anywhere.

use serde::Serialize;
use serde_json::Value;

/// Version of [`VconAnalysis`]'s shape.
pub const VCON_ANALYSIS_SCHEMA_VERSION: u32 = 1;

/// One schema finding against an invalid container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct ContainerFinding {
    /// JSON Pointer to the offending value, `/dialog/2` shaped.
    pub instance_path: String,
    /// The schema keyword that refused it.
    pub keyword: String,
    /// What was wrong, in one sentence.
    pub detail: String,
}

/// One message of a dialog's ladder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct LadderRow {
    /// When the container says the message was sent or seen, RFC 3339.
    pub timestamp: String,
    /// `address:port` it came from, as the container stored it.
    pub src: String,
    /// `address:port` it went to, as the container stored it.
    pub dst: String,
    /// Transport the container stored.
    pub transport: String,
    /// The method of a request, or the status code and reason of a response.
    pub label: String,
}

/// One dialog rebuilt from the container.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct AnalyzedDialog {
    /// The dialog's Call-ID.
    pub call_id: String,
    /// The per-dialog object `--json-dialogs` and `GET /v1/dialogs/{call_id}`
    /// write, computed from the rebuilt messages. Its `streams` are empty: a
    /// vCon stores no RTP.
    #[cfg_attr(
        feature = "mcp",
        schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
    )]
    #[cfg_attr(feature = "api", schema(value_type = Object))]
    pub dialog: Value,
    /// The signaling diagnosis of the rebuilt messages.
    #[cfg_attr(
        feature = "mcp",
        schemars(with = "std::collections::BTreeMap<String, serde_json::Value>")
    )]
    #[cfg_attr(feature = "api", schema(value_type = Object))]
    pub signaling: Value,
    /// Every message, in time order.
    pub ladder: Vec<LadderRow>,
}

/// The analysis of one container.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct VconAnalysis {
    /// Version of this shape.
    pub schema_version: u32,
    /// `analyzed`, or `unreadable` when the container holds no SIP message
    /// sipnab could rebuild, or is not a vCon at all; `reason` says which.
    pub verdict: String,
    /// Why an `unreadable` container was not analyzed. Absent on `analyzed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Every place the container disagrees with the vendored
    /// draft-ietf-vcon-vcon-core-04 schema. Reported beside the analysis,
    /// never a reason to withhold one: a container a store reshaped, with
    /// `extensions` as an object, is still a record of the call.
    pub schema_findings: Vec<ContainerFinding>,
    /// The container's `uuid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// SIP messages rebuilt from it.
    pub messages_rebuilt: u64,
    /// Dialogs rebuilt from it, at most `limit`, in Call-ID order.
    pub dialogs: Vec<AnalyzedDialog>,
    /// How many dialogs it holds in all.
    pub total_dialogs: usize,
    /// Whether `limit` cut `dialogs` short.
    pub truncated: bool,
    /// What a rebuild cannot reproduce from this container, one sentence each.
    pub not_recomputed: Vec<String>,
    /// The producer's own caveat, verbatim, when the container carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub producer_note: Option<String>,
    /// The producer's `media_quality` rows, verbatim from its analysis. Its
    /// numbers, never recomputed: no RTP is stored to recompute them from.
    #[cfg_attr(
        feature = "mcp",
        schemars(with = "Vec<std::collections::BTreeMap<String, serde_json::Value>>")
    )]
    #[cfg_attr(feature = "api", schema(value_type = Vec<Object>))]
    pub stored_media_quality: Vec<Value>,
    /// The capture analysis of the rebuilt dialogs: the object
    /// `--json-analyze` and `GET /v1/report` write. Its first finding is
    /// `rebuilt_from_vcon`. Absent when the container is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "mcp",
        schemars(with = "Option<std::collections::BTreeMap<String, serde_json::Value>>")
    )]
    #[cfg_attr(feature = "api", schema(value_type = Option<Object>))]
    pub analysis: Option<Value>,
}

/// The request was not a container at all: the one case that is a caller
/// error rather than an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAContainer;

impl std::fmt::Display for NotAContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "a vCon container is a JSON object; this is not one, so there is nothing to \
             analyze. Pass the container itself, not a string or array holding it",
        )
    }
}

impl std::error::Error for NotAContainer {}

/// Analyze one container handed over inline.
///
/// # Arguments
///
/// * `container` — the container, as JSON.
/// * `limit` — the most dialogs to return; `total_dialogs` counts them all.
///
/// # Errors
///
/// [`NotAContainer`] when `container` is not a JSON object. A container with
/// no readable SIP is an answer, with `verdict: unreadable` and the reason,
/// and one that fails the schema is analyzed with `schema_findings` beside
/// the analysis.
pub fn analyze_container(container: &Value, limit: usize) -> Result<VconAnalysis, NotAContainer> {
    if !container.is_object() {
        return Err(NotAContainer);
    }
    let bytes = serde_json::to_vec(container).map_err(|_| NotAContainer)?;
    analyze_bytes(&bytes, limit)
}

/// Analyze one container handed over as bytes, in any form: unsigned,
/// signed, encrypted, or the gzip format of any of them. The one unwrap
/// step every reader runs ([`crate::capture::vcon_input::open_bytes`])
/// opens it first.
///
/// # Errors
///
/// [`NotAContainer`] when what is inside is not a JSON object. A container
/// that does not open (no key, a signature that does not verify) is an
/// answer, with `verdict: unreadable` and the reason.
pub fn analyze_bytes(bytes: &[u8], limit: usize) -> Result<VconAnalysis, NotAContainer> {
    use crate::capture::vcon_input::ContainerError;
    let (container, opened) = match crate::capture::vcon_input::open_bytes(bytes) {
        Ok(opened) => opened,
        Err(ContainerError::NotJson(_)) => return Err(NotAContainer),
        Err(e) => {
            return Ok(VconAnalysis {
                schema_version: VCON_ANALYSIS_SCHEMA_VERSION,
                verdict: "unreadable".to_string(),
                reason: Some(e.to_string()),
                ..VconAnalysis::default()
            });
        }
    };
    if !container.is_object() {
        return Err(NotAContainer);
    }
    analyze_unsigned(&container, opened, limit)
}

/// Analyze an unsigned container, `opened` naming the layers taken off it.
fn analyze_unsigned(
    container: &Value,
    opened: Vec<String>,
    limit: usize,
) -> Result<VconAnalysis, NotAContainer> {
    use crate::capture::vcon_input::{ContainerError, rebuild};
    // core-04 section 4.1.4: not even the schema check runs on a container
    // sipnab cannot interpret.
    if let Some(why) = crate::capture::vcon_input::critical_refusal(container) {
        return Ok(VconAnalysis {
            schema_version: VCON_ANALYSIS_SCHEMA_VERSION,
            verdict: "unreadable".to_string(),
            reason: Some(format!("a vCon container sipnab must not read: {why}")),
            uuid: container["uuid"].as_str().map(str::to_string),
            ..VconAnalysis::default()
        });
    }
    let schema_findings: Vec<ContainerFinding> = crate::output::vcon_schema::validate(container)
        .errors
        .into_iter()
        .map(|f| ContainerFinding {
            instance_path: f.instance_path,
            keyword: f.keyword.to_string(),
            detail: f.detail,
        })
        .collect();
    let rebuilt = match rebuild(container, "inline") {
        Ok(mut rebuilt) => {
            rebuilt.provenance.opened = opened;
            rebuilt
        }
        Err(ContainerError::NotObject) => return Err(NotAContainer),
        Err(e) => {
            return Ok(VconAnalysis {
                schema_version: VCON_ANALYSIS_SCHEMA_VERSION,
                verdict: "unreadable".to_string(),
                reason: Some(e.to_string()),
                schema_findings,
                uuid: container["uuid"].as_str().map(str::to_string),
                ..VconAnalysis::default()
            });
        }
    };

    // Stores of its own, sized to what one container can hold. The server's
    // capture is never touched, and neither is the run's vCon record: an
    // inline container is not part of this process's capture.
    let dialog_store = std::sync::Arc::new(parking_lot::RwLock::new(
        crate::sip::dialog_store::DialogStore::new(rebuilt.messages.len().max(1), false),
    ));
    let stream_store = std::sync::Arc::new(parking_lot::RwLock::new(
        crate::rtp::stream_store::StreamStore::new(1),
    ));
    let routed = crate::capture::vcon_input::into_stores(
        &rebuilt,
        &crate::pipeline::PipelineOptions::default(),
        &dialog_store,
        &stream_store,
    );

    let ds = dialog_store.read();
    let ss = stream_store.read();
    // The facts are this container's alone. The process-global tallies the
    // observed facts read describe the server's own capture, and would put
    // its undecodable frames and port-gate losses into an answer about a
    // document somebody handed over.
    let facts = crate::analysis::CaptureFacts {
        frames_read: routed,
        vcon_inputs: vec![rebuilt.provenance.clone()],
        ..crate::analysis::CaptureFacts::default()
    };
    let analysis = crate::analysis::analyze_with(&ds, &ss, None, &facts);

    let capture = crate::rtp::diagnosis::CaptureMedia::of_store(&ss);
    let delay = crate::rtp::quality::MosDelay::from_capture(&ss);
    let mut dialogs: Vec<&crate::sip::dialog::SipDialog> = ds.iter().collect();
    dialogs.sort_by(|a, b| a.call_id.cmp(&b.call_id));
    let total_dialogs = dialogs.len();
    let analyzed: Vec<AnalyzedDialog> = dialogs
        .into_iter()
        .take(limit)
        .map(|dialog| {
            let media = crate::rtp::diagnosis::MediaContext::for_dialog(dialog, capture);
            let diagnosis = crate::rtp::diagnosis::diagnose_media(&[], &media);
            let dialog_json = serde_json::from_str(&crate::output::json::dialog_to_json(
                dialog,
                &[],
                &diagnosis,
                delay,
            ))
            .unwrap_or(Value::Null);
            AnalyzedDialog {
                call_id: dialog.call_id.clone(),
                dialog: dialog_json,
                signaling: serde_json::to_value(crate::sip::diagnosis::diagnose_signaling(
                    &dialog.messages,
                ))
                .unwrap_or(Value::Null),
                ladder: dialog.messages.iter().map(ladder_row).collect(),
            }
        })
        .collect();

    Ok(VconAnalysis {
        schema_version: VCON_ANALYSIS_SCHEMA_VERSION,
        verdict: "analyzed".to_string(),
        reason: None,
        schema_findings,
        uuid: rebuilt.provenance.uuid.clone(),
        messages_rebuilt: routed,
        truncated: total_dialogs > analyzed.len(),
        dialogs: analyzed,
        total_dialogs,
        not_recomputed: rebuilt.provenance.not_recomputed.clone(),
        producer_note: rebuilt.provenance.producer_note.clone(),
        stored_media_quality: rebuilt.stored_media_quality,
        analysis: serde_json::to_value(&analysis).ok(),
    })
}

/// One message as a ladder row.
fn ladder_row(m: &crate::sip::SipMessage) -> LadderRow {
    let label = match (&m.method, m.status_code) {
        (Some(method), _) if m.is_request => method.as_str().to_string(),
        (_, Some(code)) => match m.reason.as_deref() {
            Some(reason) if !reason.is_empty() => format!("{code} {reason}"),
            _ => code.to_string(),
        },
        _ => String::new(),
    };
    LadderRow {
        timestamp: m.timestamp.to_rfc3339(),
        src: std::net::SocketAddr::new(m.src_addr, m.src_port).to_string(),
        dst: std::net::SocketAddr::new(m.dst_addr, m.dst_port).to_string(),
        transport: m.transport.as_str().to_string(),
        label,
    }
}

#[cfg(test)]
mod tests {
    use super::{NotAContainer, analyze_container};
    use serde_json::{Value, json};

    type TestError = Box<dyn std::error::Error>;

    /// A trace message from `src` to `dst` at second `at` of the minute.
    fn message(call_id: &str, at: u32, request: Option<&str>, status: Option<u16>) -> Value {
        let (src, dst) = if request.is_some() {
            ("192.0.2.1", "192.0.2.2")
        } else {
            ("192.0.2.2", "192.0.2.1")
        };
        let mut m = json!({
            "timestamp": format!("2026-10-09T12:00:{at:02}+00:00"),
            "src": src, "src_port": 5060, "dst": dst, "dst_port": 5060,
            "transport": "UDP",
            "is_request": request.is_some(),
            "call_id": call_id,
            "headers": {
                "Via": ["SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1"],
                "From": ["<sip:a@example.com>;tag=1"],
                "To": [if request.is_some() { "<sip:b@example.com>" } else { "<sip:b@example.com>;tag=2" }],
                "Call-ID": [call_id],
                "CSeq": ["1 INVITE"],
                "Content-Length": ["0"]
            }
        });
        if let Some(method) = request {
            m["method"] = json!(method);
        }
        if let Some(code) = status {
            m["status_code"] = json!(code);
            m["reason"] = json!("Busy Here");
        }
        m
    }

    /// A valid sipnab-shaped container with one trace per Call-ID.
    fn container(call_ids: &[&str]) -> Value {
        let attachments: Vec<Value> = call_ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let at = u32::try_from(i).unwrap_or(0) * 10;
                json!({
                    "purpose": "sip-message-trace",
                    "start": "2026-10-09T12:00:00Z",
                    "party": 0,
                    "dialog": 0,
                    "mediatype": "application/json",
                    "encoding": "json",
                    "body": json!({"version": 1, "call_id": id, "messages": [
                        message(id, at, Some("INVITE"), None),
                        message(id, at + 1, None, Some(486)),
                    ]}).to_string(),
                })
            })
            .collect();
        json!({
            "vcon": "0.4.0",
            "uuid": "01928e10-193e-8231-b9a2-279e0d16bc46",
            "created_at": "2026-10-09T12:00:00Z",
            "parties": [{"name": "observer"}],
            "attachments": attachments,
            "analysis": [{
                "type": "report", "dialog": 0, "vendor": "sipnab",
                "mediatype": "application/json", "encoding": "json",
                "body": json!({"media_quality": [{"ssrc": "0x1", "mos": 4.1}]}).to_string()
            }]
        })
    }

    #[test]
    fn a_container_analyzes_to_its_dialogs_ladder_and_findings() -> Result<(), TestError> {
        let a = analyze_container(&container(&["c1"]), 50)?;
        assert_eq!(a.schema_version, 1);
        assert_eq!(a.verdict, "analyzed");
        assert!(a.schema_findings.is_empty());
        assert_eq!(
            a.uuid.as_deref(),
            Some("01928e10-193e-8231-b9a2-279e0d16bc46")
        );
        assert_eq!(a.messages_rebuilt, 2);
        assert_eq!((a.total_dialogs, a.truncated), (1, false));
        let d = a.dialogs.first().ok_or("one dialog")?;
        assert_eq!(d.call_id, "c1");
        assert_eq!(d.dialog["final_status_code"], 486);
        assert_eq!(d.dialog["input_origin"], "vcon");
        let labels: Vec<&str> = d.ladder.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["INVITE", "486 Busy Here"]);
        assert_eq!(d.ladder[0].src, "192.0.2.1:5060");
        assert_eq!(d.ladder[0].timestamp, "2026-10-09T12:00:00+00:00");
        assert!(d.signaling.is_object(), "{}", d.signaling);
        let analysis = a.analysis.as_ref().ok_or("an analysis")?;
        assert_eq!(analysis["complete"], false);
        assert_eq!(analysis["findings"][0]["kind"], "rebuilt_from_vcon");
        let kinds: Vec<&str> = analysis["findings"]
            .as_array()
            .ok_or("findings")?
            .iter()
            .filter_map(|f| f["kind"].as_str())
            .collect();
        assert!(kinds.contains(&"request_failure"), "{kinds:?}");
        assert!(a.not_recomputed.iter().any(|s| s.contains("no RTP")));
        // The producer's numbers, verbatim and labeled as such.
        assert_eq!(
            a.stored_media_quality,
            vec![json!({"ssrc": "0x1", "mos": 4.1})]
        );
        Ok(())
    }

    /// A container listing a critical extension sipnab does not support is
    /// not analyzed, and the answer names the extension.
    ///
    /// [Section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4):
    /// "An implementation that does not recognize or support the extensions
    /// listed in the critical parameter MUST NOT attempt to process or operate
    /// on the vCon, except to reject it or report unsupported content."
    #[test]
    fn an_unsupported_critical_extension_is_not_analyzed() -> Result<(), TestError> {
        let mut c = container(&["c1"]);
        c["critical"] = json!(["x-redaction"]);
        // A schema finding the check would report, had it run: it must not.
        c.as_object_mut().map(|m| m.remove("created_at"));
        assert!(!crate::output::vcon_schema::validate(&c).errors.is_empty());
        let a = analyze_container(&c, 50)?;
        assert_eq!(a.verdict, "unreadable");
        assert!(
            a.reason
                .as_deref()
                .is_some_and(|r| r.contains("x-redaction") && r.contains("section 4.1.4")),
            "{:?}",
            a.reason
        );
        assert!(a.analysis.is_none());
        assert!(a.dialogs.is_empty());
        assert!(a.schema_findings.is_empty(), "{:?}", a.schema_findings);
        Ok(())
    }

    #[test]
    fn a_container_with_no_readable_sip_is_an_answer_with_the_reason() -> Result<(), TestError> {
        let a = analyze_container(&json!({"vcon": "0.4.0"}), 50)?;
        assert_eq!(a.verdict, "unreadable");
        assert!(
            a.reason
                .as_deref()
                .is_some_and(|r| r.contains("no SIP signaling")),
            "{:?}",
            a.reason
        );
        assert!(
            a.schema_findings.iter().any(|e| e.detail.contains("uuid")),
            "{:?}",
            a.schema_findings
        );
        assert!(a.analysis.is_none());
        assert!(a.dialogs.is_empty());
        Ok(())
    }

    #[test]
    fn a_schema_finding_rides_beside_an_analysis_it_did_not_stop() -> Result<(), TestError> {
        let mut c = container(&["c1"]);
        c["extensions"] = json!({"sip-signaling": true, "CC": true});
        let a = analyze_container(&c, 50)?;
        assert_eq!(a.verdict, "analyzed");
        assert_eq!(a.total_dialogs, 1);
        assert!(
            a.schema_findings
                .iter()
                .any(|f| f.instance_path == "/extensions"),
            "{:?}",
            a.schema_findings
        );
        assert!(a.reason.is_none());
        Ok(())
    }

    #[test]
    fn something_that_is_not_an_object_is_refused() {
        assert_eq!(analyze_container(&json!([1, 2]), 50), Err(NotAContainer));
        assert_eq!(analyze_container(&json!("{}"), 50), Err(NotAContainer));
    }

    #[test]
    fn the_limit_bounds_the_dialogs_and_says_so() -> Result<(), TestError> {
        let a = analyze_container(&container(&["c1", "c2"]), 1)?;
        assert_eq!(a.dialogs.len(), 1);
        assert_eq!((a.total_dialogs, a.truncated), (2, true));
        Ok(())
    }

    #[test]
    fn analyzing_a_container_leaves_the_runs_own_record_alone() -> Result<(), TestError> {
        let mut c = container(&["c9"]);
        c["uuid"] = json!("01928e10-193e-8231-b9a2-000000000009");
        analyze_container(&c, 50)?;
        assert!(
            !crate::capture::vcon_input::read_report()
                .iter()
                .any(|p| p.uuid.as_deref() == Some("01928e10-193e-8231-b9a2-000000000009")),
            "an inline container is not part of this process's capture"
        );
        Ok(())
    }
}
