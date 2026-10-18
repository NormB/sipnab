// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every REST answer about the loaded capture names the capture it describes.
//!
//! `capture_identity` pairs the capture's `instance` with the two store
//! generations the answer was built from. A client holding two answers compares
//! them to learn whether both describe one capture at one revision. Until this
//! test existed only `GET /v1/stats` carried it, while MCP stamped it on every
//! answer about the capture: an HTTP client reading `/v1/dialogs` could not tell
//! that a file had been swapped between two pages.
//!
//! # The rule
//!
//! A REST route carries `capture_identity` exactly when the MCP tool that
//! answers the same question does. [`WITH_IDENTITY`] pairs each carrying route
//! with its MCP counterpart, and [`WITHOUT_IDENTITY`] names every other GET
//! route with the reason it is exempt. Both lists are checked against the
//! published document, so a route added to the router without being classified
//! here fails [`every_get_route_is_classified`].
//!
//! # Why GET only
//!
//! The POST routes answer about a document the caller sent (`/v1/vcon/validate`,
//! `/v1/vcon/analyze`) or carry out an action (`/v1/persistence`,
//! `/v1/tfps/ban`, `/v1/tfps/unban`, `/v1/actions/revert`). None of them answers
//! a question about the loaded capture.

#![cfg(all(feature = "api", feature = "mcp", feature = "native"))]

use std::collections::BTreeSet;

use serde_json::Value;

#[path = "support/server.rs"]
mod server;

#[path = "support/mcp.rs"]
mod mcp;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// A capture with real dialogs and real media, so every collection route has a
/// row to answer with and every per-item route an identifier that exists.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// The node name both servers are started with, so the `node` key of the two
/// identities can be compared by value rather than only by presence.
const NODE: &str = "capture-01";

/// Routes that carry `capture_identity`: the request (with `{CALL}` and
/// `{SSRC}` filled in from the capture), the MCP tool that answers the same
/// question, and that tool's arguments.
const WITH_IDENTITY: &[(&str, &str, &str, &str)] = &[
    (
        "/v1/dialogs",
        "/v1/dialogs",
        "list_dialogs",
        r#"{"limit":5}"#,
    ),
    (
        "/v1/dialogs/compare",
        "/v1/dialogs/compare?a={CALL}&b={CALL}",
        "compare_dialogs",
        r#"{"call_id_a":"{CALL}","call_id_b":"{CALL}"}"#,
    ),
    (
        "/v1/dialogs/tail",
        "/v1/dialogs/tail",
        "tail_dialogs",
        r#"{}"#,
    ),
    (
        "/v1/dialogs/rates",
        "/v1/dialogs/rates?by=state",
        "group_dialogs",
        r#"{"by":"state"}"#,
    ),
    (
        "/v1/dialogs/{call_id}",
        "/v1/dialogs/{CALL}",
        "get_dialog",
        r#"{"call_id":"{CALL}"}"#,
    ),
    (
        "/v1/dialogs/{call_id}/report",
        "/v1/dialogs/{CALL}/report",
        "get_dialog_report",
        r#"{"call_id":"{CALL}"}"#,
    ),
    (
        "/v1/dialogs/{call_id}/correlated",
        "/v1/dialogs/{CALL}/correlated",
        "find_correlated",
        r#"{"call_id":"{CALL}"}"#,
    ),
    (
        "/v1/dialogs/{call_id}/tree",
        "/v1/dialogs/{CALL}/tree",
        "get_call_tree",
        r#"{"call_id":"{CALL}"}"#,
    ),
    (
        "/v1/dialogs/{call_id}/lint",
        "/v1/dialogs/{CALL}/lint",
        "lint_dialog",
        r#"{"call_id":"{CALL}"}"#,
    ),
    ("/v1/streams", "/v1/streams", "rtp_stats", r#"{"limit":5}"#),
    // One stream of the list `rtp_stats` answers; MCP has no single-stream
    // tool, and the question is the same one asked of fewer rows.
    (
        "/v1/streams/{id}",
        "/v1/streams/{SSRC}",
        "rtp_stats",
        r#"{"limit":5}"#,
    ),
    ("/v1/report", "/v1/report", "get_capture_report", r#"{}"#),
    ("/v1/stats", "/v1/stats", "capture_status", r#"{}"#),
    (
        "/v1/aggregate",
        "/v1/aggregate?by=state",
        "aggregate_dialogs",
        r#"{"group_by":"state"}"#,
    ),
    (
        "/v1/talkers",
        "/v1/talkers?by=ip",
        "top_talkers",
        r#"{"by":"ip"}"#,
    ),
    (
        "/v1/security/findings",
        "/v1/security/findings",
        "security_findings",
        r#"{}"#,
    ),
    ("/v1/timeline", "/v1/timeline", "timeline", r#"{}"#),
    // The fixture's caller, so the answer describes a real endpoint.
    (
        "/v1/endpoints",
        "/v1/endpoints?ip=10.0.2.15",
        "describe_endpoint",
        r#"{"ip":"10.0.2.15"}"#,
    ),
    // Occupancy: `dialogs.used` and `streams.used` count this capture's
    // stores, so the answer is about the capture.
    ("/v1/runtime", "/v1/runtime", "runtime_stats", r#"{}"#),
];

/// GET routes that do not carry `capture_identity`, each with the reason.
///
/// Where the reason is "the MCP counterpart carries none", the counterpart is
/// named in [`COUNTERPARTS_WITHOUT`] and checked over the wire, so a tool that
/// later gains the field moves its route out of this list.
const WITHOUT_IDENTITY: &[(&str, &str)] = &[
    ("/health", "answers text/plain, not a JSON object"),
    ("/metrics", "answers the Prometheus text format"),
    (
        "/v1/hep/senders",
        "the MCP `hep_senders` tool carries none, and the two answer the same \
         bytes: the listener's roster, not the capture's contents; checked \
         below",
    ),
    (
        "/v1/capabilities",
        "the MCP `server_capabilities` tool is source-independent: what this \
         build can do, not what the capture holds",
    ),
    (
        "/v1/captures/compare",
        "the MCP `compare_captures` tool is source-independent: it reads two \
         files off the file root, not the loaded capture",
    ),
    (
        "/v1/vcon/spool",
        "the MCP `vcon_spool_status` tool is source-independent: it counts \
         files another process drains",
    ),
    (
        "/v1/vcon/fetch/{uuid}",
        "the MCP `fetch_vcon` tool is source-independent: it reads a container \
         from the operator's vCon store",
    ),
    (
        "/v1/dialogs/{call_id}/vcon",
        "the body IS the vCon container, whose members draft-ietf-vcon-vcon-core \
         defines; a member added to it would make it a different document. MCP \
         `export_vcon` carries the identity on the envelope around its \
         containers, and this route has no envelope",
    ),
    (
        "/v1/dialogs/{call_id}/audio",
        "answers audio/wav, not a JSON object",
    ),
    (
        "/v1/calls/live",
        "no MCP counterpart: the live-audio calls a `live_audio` rule streams",
    ),
    (
        "/v1/calls/live/events",
        "answers text/event-stream, and has no MCP counterpart",
    ),
    (
        "/v1/calls/{call_id}/audio",
        "answers a live audio stream, not a JSON object",
    ),
    (
        "/v1/persistence",
        "no MCP counterpart: the state of a write gate, not of the capture",
    ),
    (
        "/v1/relay/stats",
        "the MCP `relay_stats` tool is source-independent: the relay's \
         statement about itself",
    ),
    (
        "/v1/relay/stats/names",
        "the MCP `relay_stats` tool is source-independent: the relay's \
         statement about itself",
    ),
    (
        "/v1/relay/stats/call/{call_id}",
        "the MCP `relay_stats` tool is source-independent: the relay's \
         statement about itself",
    ),
    (
        "/v1/relay/holdings",
        "the MCP `query_relay` tool is source-independent: what the relay holds",
    ),
    (
        "/v1/relay/holdings/{call_id}",
        "the MCP `query_relay` tool is source-independent: what the relay holds",
    ),
    (
        "/v1/relay/compare/{call_id}",
        "the MCP `relay_compare` tool carries none: its answer is the relay's \
         figure beside one call's bounded packet count",
    ),
    (
        "/v1/tfps/status",
        "the MCP `tfps_status` tool is source-independent: the TFPS peer's state",
    ),
    (
        "/v1/tfps/banned",
        "the MCP `tfps_banned` tool is source-independent: the TFPS peer's state",
    ),
    (
        "/v1/tfps/dropped",
        "the MCP `tfps_dropped` tool is source-independent: the TFPS peer's state",
    ),
    (
        "/v1/tfps/labels",
        "the MCP `tfps_labels` tool is source-independent: the TFPS peer's state",
    ),
];

/// The MCP counterparts [`WITHOUT_IDENTITY`] cites as carrying no identity,
/// with arguments that make each answer.
#[cfg(feature = "hep")]
const COUNTERPARTS_WITHOUT: &[(&str, &str)] = &[("hep_senders", r#"{}"#)];

/// Every GET path the published document declares, as the router serves it.
fn documented_gets() -> Result<BTreeSet<String>, TestError> {
    let doc: Value = serde_json::from_str(&sipnab::output::api::openapi_json())?;
    let paths = doc["paths"]
        .as_object()
        .ok_or("the document declares paths")?;
    Ok(paths
        .iter()
        .filter(|(_, item)| item.get("get").is_some())
        .map(|(p, _)| p.clone())
        .collect())
}

/// Percent-encode a path segment: Call-IDs carry `@` and may carry `/`.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The JSON payload of an MCP `tools/call` reply's first content block.
fn payload(reply: &Value) -> Result<Value, TestError> {
    let text = reply["result"]["content"][0]["text"]
        .as_str()
        .ok_or_else(|| format!("no text content block in {reply}"))?;
    Ok(serde_json::from_str(text).map_err(|e| format!("payload is not JSON: {e}\n{text}"))?)
}

/// The keys of an identity object, for comparing its shape across doors.
fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Every GET route is in exactly one list, and every listed route exists.
///
/// A route the document gains without a decision here fails, so the
/// classification cannot fall behind the router. Entries for routes absent
/// from this build (`/v1/dialogs/{call_id}/vcon` without the `vcon` feature,
/// `/v1/hep/senders` without `hep`) are allowed; an entry naming a route no
/// build serves is caught by the full-feature run.
#[test]
fn every_get_route_is_classified() -> Result<(), TestError> {
    let documented = documented_gets()?;
    let with: BTreeSet<&str> = WITH_IDENTITY.iter().map(|(r, ..)| *r).collect();
    let without: BTreeSet<&str> = WITHOUT_IDENTITY.iter().map(|(r, _)| *r).collect();

    let both: Vec<&&str> = with.intersection(&without).collect();
    assert!(both.is_empty(), "routes in both lists: {both:?}");

    let unclassified: Vec<&String> = documented
        .iter()
        .filter(|p| !with.contains(p.as_str()) && !without.contains(p.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "GET routes neither carrying capture_identity nor exempt with a \
         reason: {unclassified:?}"
    );

    if cfg!(all(feature = "vcon", feature = "hep")) {
        let stale: Vec<&&str> = with
            .iter()
            .chain(without.iter())
            .filter(|r| !documented.contains(**r))
            .collect();
        assert!(
            stale.is_empty(),
            "listed routes the document lacks: {stale:?}"
        );
    }
    Ok(())
}

/// Every REST answer about the loaded capture names it, with the same keys
/// the MCP counterpart's identity carries and the same node.
#[test]
fn every_rest_answer_about_the_capture_names_it() -> Result<(), TestError> {
    let srv = server::ApiServer::spawn_with_pcap(G711, &["--node-name", NODE])?;
    let dialogs = srv.get("/v1/dialogs")?.json()?;
    let call_id = dialogs["dialogs"][0]["call_id"]
        .as_str()
        .ok_or("the fixture must produce a dialog, or this test proves nothing")?
        .to_string();
    let streams = srv.get("/v1/streams")?.json()?;
    let ssrc = streams["streams"][0]["ssrc"]
        .as_str()
        .ok_or("the fixture must produce a stream, or this test proves nothing")?
        .to_string();

    let mut session = mcp::McpSession::start(G711, &["--node-name", NODE])?;

    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    for (route, request, tool, args) in WITH_IDENTITY {
        let url = request
            .replace("{CALL}", &encode(&call_id))
            .replace("{SSRC}", &encode(&ssrc));
        let resp = srv.get(&url)?;
        assert_eq!(resp.status, 200, "GET {url} answered {}", resp.status);
        let rest = resp.json()?;
        let rest_id = &rest["capture_identity"];
        if !rest_id["instance"].is_string() {
            missing.push(*route);
            continue;
        }

        let reply = session.call(
            tool,
            serde_json::from_str(&args.replace("{CALL}", &call_id))?,
        )?;
        let mcp_id = payload(&reply)?["capture_identity"].clone();
        assert!(
            mcp_id["instance"].is_string(),
            "MCP `{tool}` no longer carries capture_identity, so {route} is \
             paired with the wrong counterpart: {reply}"
        );
        if keys(rest_id) != keys(&mcp_id) || rest_id["node"] != mcp_id["node"] {
            mismatched.push(format!("{route}: {rest_id} against `{tool}` {mcp_id}"));
        }
        assert_eq!(rest_id["node"], NODE, "{route} names another node");
    }
    assert!(missing.is_empty(), "no capture_identity on: {missing:?}");
    assert!(
        mismatched.is_empty(),
        "REST and MCP identities differ in shape:\n  {}",
        mismatched.join("\n  ")
    );

    // One capture, one instance: every REST answer above came from one
    // process over one file, so they must all name the same instance.
    let instances: BTreeSet<String> = WITH_IDENTITY
        .iter()
        .map(|(_, request, ..)| {
            let url = request
                .replace("{CALL}", &encode(&call_id))
                .replace("{SSRC}", &encode(&ssrc));
            srv.get(&url)
                .and_then(|r| r.json())
                .map(|v| v["capture_identity"]["instance"].to_string())
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(
        instances.len(),
        1,
        "one capture answered under several instances: {instances:?}"
    );
    Ok(())
}

/// The MCP tools [`WITHOUT_IDENTITY`] cites as carrying no identity still
/// carry none. If one gains it, its REST route must too, and this says which.
#[cfg(feature = "hep")]
#[test]
fn the_exempt_routes_counterparts_carry_no_identity() -> Result<(), TestError> {
    let mut session = mcp::McpSession::start(G711, &[])?;
    for (tool, args) in COUNTERPARTS_WITHOUT {
        let reply = session.call(tool, serde_json::from_str(args)?)?;
        let body = payload(&reply)?;
        assert!(
            body.get("capture_identity").is_none(),
            "MCP `{tool}` now carries capture_identity; move its REST route \
             from WITHOUT_IDENTITY to WITH_IDENTITY"
        );
    }
    Ok(())
}
