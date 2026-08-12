// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every identifier a tool HANDS BACK must be accepted by the tool that takes it.
//!
//! # The gap this exists to close
//!
//! Every one of the 31 MCP tools is exercised by some test. Not one of them was
//! ever called with an argument that came out of another tool, and that is the
//! only way an operator or an agent ever calls them: you do not know a Call-ID,
//! a frame pointer or a cursor — you are GIVEN one and you follow it.
//!
//! `show_evidence` shipped unable to follow a `frame_ref` into the capture it
//! was analysing, which is the single reason frame pointers exist. It showed 1
//! integration reference and 7 unit references and read as covered. Every test
//! either built its arguments by hand or deliberately pointed at a file outside
//! the root; none took a pointer that `lint_dialog` had just produced and asked
//! for the bytes. The defect was found by trying to record a homepage demo,
//! which is not a test strategy.
//!
//! # What is asserted
//!
//! One property, applied everywhere: **an identifier produced by one tool is
//! valid input to the tool that consumes it, verbatim.** No reformatting, no
//! stripping, no re-deriving it from a fixture. If a tool returns it, another
//! tool must take it.
//!
//! The named flows below are the journeys an operator actually walks. The
//! sweep at the end is the generalisation — it harvests identifiers from the
//! whole surface and feeds each one back in, so a NEW tool that emits a
//! pointer nobody can follow fails here without anyone writing a test for it.
//!
//! Errors are the assertion. A JSON-RPC `error` on any hop means the chain is
//! broken for a real caller, whatever the tools do in isolation.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod mcp;

use mcp::McpSession;

/// 1334 dialogs, 127 failed: big enough that pagination and cursors are real.
const BRANCH: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";
/// Four findings across three dialogs, so the lint chain has something to chain.
const LINT: &str = "tests/pcap-samples/sip-lint-findings.pcap";
/// A complete call with media, for the dialog-to-media journeys.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Fail with the tool and arguments that broke, not just "assertion failed".
fn expect_ok(msg: &serde_json::Value, tool: &str, arg: &str) -> serde_json::Value {
    if let Some(err) = msg.get("error") {
        panic!(
            "{tool} refused an identifier another tool produced.\n  \
             argument: {arg}\n  error: {err}\n\n\
             An operator never invents these values — they follow what the \
             previous answer handed them. A tool that will not accept its own \
             surface's output is broken for every real caller."
        );
    }
    let text = msg["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{tool} returned no text payload: {msg}"));
    // Not every tool answers in JSON. `render_ladder` returns a rendered
    // markdown ladder, which is the right shape for what it is — the surface
    // is deliberately not uniform, and a chain test must accept that rather
    // than demand JSON everywhere. What matters is that the call SUCCEEDED
    // with the identifier it was handed; the payload shape is the tool's own
    // business.
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

/// Pull every string at `key`, at any depth.
fn harvest(v: &serde_json::Value, key: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if k == key
                    && let Some(s) = val.as_str()
                {
                    out.push(s.to_string());
                }
                harvest(val, key, out);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| harvest(x, key, out)),
        _ => {}
    }
}

/// **Triage a failed call.** The journey every operator starts with.
///
/// `find_problems` says which call is broken; everything after it takes that
/// Call-ID. Nothing here knows a Call-ID up front — that is the point.
#[test]
fn flow_find_a_broken_call_then_ask_every_question_about_it() {
    let mut s = McpSession::start(BRANCH, &[]);

    let problems = expect_ok(
        &s.call("find_problems", serde_json::json!({})),
        "find_problems",
        "{}",
    );
    let mut ids = Vec::new();
    harvest(&problems, "call_id", &mut ids);
    assert!(
        !ids.is_empty(),
        "the fixture must contain a failed call or this flow proves nothing: {problems}"
    );
    let call_id = ids[0].clone();

    // Everything an operator asks next, each taking the SAME id verbatim.
    for tool in [
        "get_dialog",
        "triage_call",
        "lint_dialog",
        "get_dialog_report",
        "render_ladder",
        "check_codec_negotiation",
        "get_sdp_timeline",
        "find_correlated",
        "rtp_stats",
    ] {
        let msg = s.call(tool, serde_json::json!({ "call_id": call_id }));
        expect_ok(&msg, tool, &call_id);
    }
}

/// **Follow a finding to the bytes.** The evidence chain, end to end.
///
/// This is the flow that was broken: `lint_dialog` returns a `frame_ref` into
/// the capture under analysis, and `show_evidence` refused it because a guard
/// written for output paths was applied to a read. Asserted on the DIGEST, not
/// on a status flag — resolving without verifying is not evidence.
#[test]
fn flow_a_finding_leads_to_the_captured_bytes() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pcap-samples");
    let mut s = McpSession::start(LINT, &["--mcp-file-root", root]);

    let dialogs = expect_ok(
        &s.call("list_dialogs", serde_json::json!({})),
        "list_dialogs",
        "{}",
    );
    let mut ids = Vec::new();
    harvest(&dialogs, "call_id", &mut ids);

    let mut refs = Vec::new();
    for id in &ids {
        let lint = expect_ok(
            &s.call("lint_dialog", serde_json::json!({ "call_id": id })),
            "lint_dialog",
            id,
        );
        harvest(&lint, "frame_ref", &mut refs);
    }
    assert!(
        !refs.is_empty(),
        "the lint fixture must produce a finding carrying a frame_ref, or this \
         flow cannot test the evidence chain at all"
    );

    let evidence = expect_ok(
        &s.call("show_evidence", serde_json::json!({ "refs": [refs[0]] })),
        "show_evidence",
        &refs[0],
    );
    assert_eq!(
        evidence["resolved"], 1,
        "a pointer lint_dialog just produced must resolve: {evidence}"
    );
    assert_eq!(
        evidence["verified"], 1,
        "resolving is not enough — the digest must verify, or the bytes are \
         not evidence that the capture is unchanged: {evidence}"
    );
    let hex = evidence["frames"][0]["hex"].as_str().unwrap_or_default();
    assert!(
        hex.split_whitespace().count() >= 8,
        "the frame bytes must come back: {evidence}"
    );
}

/// **Page through a big result set.** A cursor is only useful if it is accepted.
///
/// The failure this prevents is silent: a cursor that is rejected, or ignored
/// and treated as a fresh call, gives an agent the FIRST page twice and it
/// looks like a short capture rather than a broken loop.
#[test]
fn flow_a_cursor_advances_rather_than_repeating_the_first_page() {
    let mut s = McpSession::start(BRANCH, &[]);

    let p1 = expect_ok(
        &s.call("list_dialogs", serde_json::json!({ "limit": 5 })),
        "list_dialogs",
        "limit=5",
    );
    let cursor = p1["next_cursor"].as_str().unwrap_or_default().to_string();
    assert!(
        !cursor.is_empty(),
        "1334 dialogs against limit 5 must paginate, or this proves nothing: {p1}"
    );

    let p2 = expect_ok(
        &s.call(
            "list_dialogs",
            serde_json::json!({ "limit": 5, "cursor": cursor }),
        ),
        "list_dialogs",
        &cursor,
    );

    let (mut a, mut b) = (Vec::new(), Vec::new());
    harvest(&p1, "call_id", &mut a);
    harvest(&p2, "call_id", &mut b);
    assert!(
        !a.is_empty() && !b.is_empty(),
        "both pages must carry dialogs"
    );
    assert!(
        a.iter().all(|id| !b.contains(id)),
        "the second page repeated dialogs from the first — a cursor that is \
         ignored looks exactly like a capture that ended.\n  page 1: {a:?}\n  page 2: {b:?}"
    );
}

/// **A rule id from a finding explains itself.**
///
/// `lint_dialog` names a rule; `explain_rule` must accept that name. They are
/// written in different modules and nothing but this holds their vocabulary
/// together.
#[test]
fn flow_a_rule_a_finding_names_can_be_explained() {
    let mut s = McpSession::start(LINT, &[]);
    let dialogs = expect_ok(
        &s.call("list_dialogs", serde_json::json!({})),
        "list_dialogs",
        "{}",
    );
    let mut ids = Vec::new();
    harvest(&dialogs, "call_id", &mut ids);

    let mut rules = Vec::new();
    for id in &ids {
        let lint = expect_ok(
            &s.call("lint_dialog", serde_json::json!({ "call_id": id })),
            "lint_dialog",
            id,
        );
        harvest(&lint, "rule_id", &mut rules);
    }
    assert!(!rules.is_empty(), "the lint fixture must produce a rule_id");

    for rule in rules.iter().take(4) {
        let msg = s.call("explain_rule", serde_json::json!({ "rule_id": rule }));
        expect_ok(&msg, "explain_rule", rule);
    }
}

/// **A stream identifier from the media list is accepted by the media tools.**
#[test]
fn flow_a_stream_identifier_survives_the_hop_to_the_media_tools() {
    let mut s = McpSession::start(G711, &[]);
    let stats = expect_ok(
        &s.call("rtp_stats", serde_json::json!({})),
        "rtp_stats",
        "{}",
    );

    // The media surface names the owning dialog `associated_dialog`, where the
    // dialog surface calls the same thing `call_id`. Harvesting only `call_id`
    // finds nothing here — which is exactly the seam an agent author trips
    // over, so this test follows the real field rather than the expected one.
    let mut ids = Vec::new();
    harvest(&stats, "associated_dialog", &mut ids);
    harvest(&stats, "call_id", &mut ids);
    ids.retain(|s| !s.is_empty());
    assert!(
        !ids.is_empty(),
        "the media fixture must attribute at least one stream to a dialog: {stats}"
    );
    for id in ids.iter().take(2) {
        expect_ok(
            &s.call("rtp_stats", serde_json::json!({ "call_id": id })),
            "rtp_stats",
            id,
        );
        expect_ok(
            &s.call("get_dialog_report", serde_json::json!({ "call_id": id })),
            "get_dialog_report",
            id,
        );
    }
}

/// **The sweep.** Harvest identifiers from the whole surface, feed each back.
///
/// The named flows above encode journeys someone thought of. This one does not
/// depend on anyone thinking of it: it calls the read-only tools, collects
/// every `call_id` and `frame_ref` any of them emitted, and pushes each value
/// into every tool that accepts that kind of identifier.
///
/// So a tool added tomorrow that emits a Call-ID nobody can look up, or a
/// pointer nobody can follow, fails here with no new test written. That is the
/// property that was missing — not coverage of each tool, but coverage of the
/// SEAMS between them.
#[test]
fn sweep_every_identifier_the_surface_emits_is_accepted_where_it_is_consumed() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pcap-samples");
    let mut s = McpSession::start(LINT, &["--mcp-file-root", root]);

    // Producers: read-only, no arguments, safe to call blind.
    let producers = [
        "list_dialogs",
        "find_problems",
        "rtp_stats",
        "capture_status",
        "security_findings",
        "tail_dialogs",
    ];
    let (mut call_ids, mut frame_refs) = (Vec::new(), Vec::new());
    for tool in producers {
        let payload = expect_ok(&s.call(tool, serde_json::json!({})), tool, "{}");
        harvest(&payload, "call_id", &mut call_ids);
        // Same identifier, different name on the media surface.
        harvest(&payload, "associated_dialog", &mut call_ids);
        harvest(&payload, "frame_ref", &mut frame_refs);
        harvest(&payload, "frame", &mut frame_refs);
    }
    // lint_dialog is where frame_refs actually come from.
    for id in call_ids.clone().iter().take(3) {
        let lint = expect_ok(
            &s.call("lint_dialog", serde_json::json!({ "call_id": id })),
            "lint_dialog",
            id,
        );
        harvest(&lint, "frame_ref", &mut frame_refs);
    }

    call_ids.sort();
    call_ids.dedup();
    frame_refs.sort();
    frame_refs.dedup();
    assert!(
        !call_ids.is_empty() && !frame_refs.is_empty(),
        "the sweep harvested nothing ({} call_ids, {} frame_refs), so it is \
         asserting about an empty set — the response shapes changed and the \
         harvester no longer finds them",
        call_ids.len(),
        frame_refs.len()
    );

    let call_id_consumers = [
        "get_dialog",
        "triage_call",
        "lint_dialog",
        "get_dialog_report",
        "render_ladder",
        "check_codec_negotiation",
        "get_sdp_timeline",
        "find_correlated",
        "rtp_stats",
    ];
    for id in call_ids.iter().take(3) {
        for tool in call_id_consumers {
            expect_ok(
                &s.call(tool, serde_json::json!({ "call_id": id })),
                tool,
                id,
            );
        }
    }
    for r in frame_refs.iter().take(3) {
        let msg = s.call("show_evidence", serde_json::json!({ "refs": [r] }));
        let payload = expect_ok(&msg, "show_evidence", r);
        assert_eq!(
            payload["resolved"], 1,
            "a pointer this surface emitted must be followable: {r} -> {payload}"
        );
    }
}
