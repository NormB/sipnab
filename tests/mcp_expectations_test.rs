// SPDX-License-Identifier: MIT OR Apache-2.0

//! The CI gate and the repro generators, driven over the real MCP surface
//! against real captures.
//!
//! Unit tests over hand-built dialogs prove the code paths run. They cannot
//! prove the thing that matters about a gate: that it goes RED on traffic that
//! violates an expectation. A gate is only ever discovered to be broken when
//! somebody needed it to fail and it did not, which is after the release it was
//! guarding.
//!
//! So every expectation here is asserted in both directions where the fixtures
//! allow it — the same rule against a capture that satisfies it and one that
//! does not — and the numbers were read off the captures independently
//! (`sipnab -I <pcap> --json-dialogs`, and `rtp_stats` for the codecs), not off
//! what these tools returned.
//!
//! `#![cfg(feature = "mcp")]` because they drive the MCP surface.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod mcp;

use mcp::McpSession;

/// 4 dialogs: three OPTIONS pings and one INVITE that ends 488.
///
/// Verified against the capture: `codec-reject-synth` is the only INVITE and
/// the only dialog with a final status code, and that code is 488.
const REJECT: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";

/// The Call-ID of the rejected INVITE in [`REJECT`].
const REJECT_CALL: &str = "codec-reject-synth";

/// 1334 dialogs, every one of them a REGISTER — 1148 answered 403, 102 answered
/// 200, 84 still open.
///
/// The fixture this file most needs. It is a large, busy capture on which an
/// ASR gate has NOTHING to judge, because ASR is defined over INVITEs and there
/// are none. A gate that reported green here would be reporting green on 1334
/// dialogs it never looked at.
const REGISTERS: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";

/// 4 RTP streams and no dialogs at all: two PCMU, two G.722.
///
/// The codecs split exactly along the MOS grounding line — G.711 has a
/// published ITU-T G.113 impairment value and G.722 does not — so the same
/// percentile rule gives different answers depending on whether the placeholder
/// scores are admitted. Verified with `rtp_stats`: the PCMU streams score
/// ~4.3580 and are reported `published`, the G.722 streams score ~4.2229 and
/// are reported `unpublished`.
const CODECS: &str = "tests/pcap-samples/codec-negotiation.pcap";

/// A single-rule suite, as the tool takes it.
fn one(rule: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "rules": [rule] })
}

/// A capture holding a 488 fails a rule forbidding one, and passes the same
/// rule aimed at a code it does not hold.
///
/// Both halves against one capture and one session, so a verdict that ignored
/// the scope, or one wired to a constant, cannot satisfy both.
#[test]
fn the_gate_goes_red_on_the_capture_that_violates_it() {
    let mut s = McpSession::start(REJECT, &[]);

    let red = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "count", "op": "==", "value": 0,
            "scope": "filter:response_code == 488"
        })),
    );
    assert_eq!(red["verdict"], "fail", "{red}");
    assert_eq!(red["exit_code"], 1, "{red}");
    assert_eq!(red["results"][0]["observed"], 1.0, "{red}");
    assert_eq!(
        red["results"][0]["sample"], 4,
        "the population is the whole capture: {red}"
    );

    let green = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "count", "op": "==", "value": 0,
            "scope": "filter:response_code == 503"
        })),
    );
    assert_eq!(green["verdict"], "pass", "{green}");
    assert_eq!(green["exit_code"], 0, "{green}");
    assert_eq!(green["results"][0]["observed"], 0.0, "{green}");
}

/// An ASR gate on a capture with no INVITE fails as unevaluable, and declaring
/// `min_sample` is the only thing that turns that into a skip.
///
/// The skip is still not a pass: the suite reports `not_evaluated` with its own
/// exit code, because a file of rules that never ran is the shape a gate takes
/// when it has quietly stopped guarding anything.
#[test]
fn an_asr_gate_with_nothing_to_judge_fails_rather_than_reporting_green() {
    let mut s = McpSession::start(REGISTERS, &[]);

    let unevaluable = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({ "metric": "asr", "op": ">=", "value": 0.99 })),
    );
    assert_eq!(
        unevaluable["verdict"], "fail",
        "1334 dialogs and no INVITE among them: the threshold rests on nothing, \
         and must not pass: {unevaluable}"
    );
    assert_eq!(unevaluable["exit_code"], 1);
    assert_eq!(unevaluable["results"][0]["sample"], 0);
    assert!(
        unevaluable["results"][0]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("unevaluable")),
        "{unevaluable}"
    );
    assert_eq!(
        unevaluable["dialogs_in_capture"], 1334,
        "the answer must say how much traffic it had in front of it: \
         {unevaluable}"
    );

    let declared = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "asr", "op": ">=", "value": 0.99, "min_sample": 50
        })),
    );
    assert_eq!(declared["results"][0]["verdict"], "skipped", "{declared}");
    assert_eq!(declared["passed"], 0, "a skip is not a pass: {declared}");
    assert_eq!(declared["verdict"], "not_evaluated", "{declared}");
    assert_eq!(declared["exit_code"], 2, "{declared}");
}

/// `grounded_only` decides the answer, and the same rule flips verdict with it.
///
/// The PCMU streams score above 4.30 and the G.722 streams below it, so a rule
/// at 4.30 passes on the grounded population and fails once the placeholder
/// scores are admitted. A `grounded_only` that parsed and did nothing would
/// give the same verdict twice.
#[test]
fn grounded_only_changes_the_verdict_it_is_supposed_to_change() {
    let mut s = McpSession::start(CODECS, &[]);

    let grounded = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({ "metric": "mos_p0", "op": ">=", "value": 4.3 })),
    );
    assert_eq!(
        grounded["verdict"], "pass",
        "the two PCMU streams score ~4.358: {grounded}"
    );
    assert_eq!(
        grounded["results"][0]["sample"], 2,
        "only the grounded streams were scored: {grounded}"
    );
    assert_eq!(
        grounded["results"][0]["ungrounded_excluded"], 2,
        "and the answer says what it could not judge: {grounded}"
    );

    let everything = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "mos_p0", "op": ">=", "value": 4.3, "grounded_only": false
        })),
    );
    assert_eq!(
        everything["verdict"], "fail",
        "admitting the G.722 placeholder (~4.223) breaks the threshold: \
         {everything}"
    );
    assert_eq!(everything["results"][0]["sample"], 4, "{everything}");
}

/// A count rule on a capture holding no dialogs fails rather than passing on an
/// empty store.
#[test]
fn a_count_gate_on_a_capture_with_no_dialogs_is_unevaluable() {
    let mut s = McpSession::start(CODECS, &[]);
    let v = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "count", "op": "==", "value": 0,
            "scope": "filter:state == 'Failed'"
        })),
    );
    assert_eq!(
        v["verdict"], "fail",
        "no dialog was judged, so 'zero failures' is a claim about nothing: {v}"
    );
    assert_eq!(v["dialogs_in_capture"], 0, "{v}");
}

/// A malformed rule is refused outright, not evaluated in part.
#[test]
fn a_malformed_rule_refuses_the_whole_suite() {
    let mut s = McpSession::start(REJECT, &[]);
    let msg = s.call(
        "evaluate_expectations",
        serde_json::json!({ "rules": [
            { "metric": "count", "op": "==", "value": 0 },
            { "metric": "count", "op": "==", "value": 0, "scope": "filter:not a filter" }
        ]}),
    );
    assert_eq!(
        msg["error"]["code"], -32602,
        "one bad rule must refuse the run rather than let the good one report \
         green: {msg}"
    );
}

/// A `lint_errors` rule reads the linter and reports the severity floor it
/// counted from.
#[test]
fn a_lint_gate_counts_findings_at_the_declared_severity() {
    let mut s = McpSession::start(REJECT, &[]);
    let v = s.ok(
        "evaluate_expectations",
        one(serde_json::json!({
            "metric": "lint_errors", "op": ">=", "value": 0, "scope": "severity:info"
        })),
    );
    assert_eq!(v["results"][0]["verdict"], "pass", "{v}");
    assert_eq!(
        v["results"][0]["sample"], 4,
        "every dialog in the capture was linted: {v}"
    );
    assert!(
        v["results"][0]["notes"].as_array().is_some_and(|n| n
            .iter()
            .any(|s| s.as_str().is_some_and(|s| s.contains("severity info")))),
        "the answer must say which floor it counted from: {v}"
    );
    assert_eq!(
        v["suppressions_applied"], false,
        "no .sipnablint sits beside this fixture: {v}"
    );
}

/// The repro scenario for a real rejected call asserts the real rejection, and
/// pinning carries that call's own SDP into it.
#[test]
fn a_repro_for_a_real_rejected_call_asserts_the_rejection() {
    let mut s = McpSession::start(REJECT, &[]);

    let generic = s.ok(
        "generate_repro",
        serde_json::json!({ "call_id": REJECT_CALL }),
    );
    let xml = generic["scenario"].as_str().unwrap_or_default();
    assert!(
        xml.contains("<recv response=\"488\"/>"),
        "the scenario must assert the code the capture held: {xml}"
    );
    assert_eq!(generic["asserted"]["final"], 488, "{generic}");

    let pinned = s.ok(
        "generate_repro",
        serde_json::json!({ "call_id": REJECT_CALL, "pin": ["sdp"] }),
    );
    let pinned_xml = pinned["scenario"].as_str().unwrap_or_default();
    assert!(
        pinned_xml.contains("m=audio"),
        "a pinned SDP must reach the scenario: {pinned_xml}"
    );
    assert!(
        !generic["scenario"]
            .as_str()
            .unwrap_or_default()
            .contains("m=audio [media_port] RTP/AVP 0\na=rtpmap:0 PCMU/8000\nm=audio"),
        "and the generic one must not carry two offers: {generic}"
    );
    assert_eq!(
        pinned["hypothesis"]["pinned"],
        serde_json::json!(["sdp"]),
        "{pinned}"
    );
}

/// A repro for a Call-ID the capture does not hold is refused.
#[test]
fn a_repro_for_an_unknown_call_is_refused() {
    let mut s = McpSession::start(REJECT, &[]);
    let msg = s.call(
        "generate_repro",
        serde_json::json!({ "call_id": "not-in-this-capture" }),
    );
    assert_eq!(msg["error"]["code"], -32602, "{msg}");
}

/// The Wireshark filter names the call and, with media on this capture, nothing
/// else — there is no RTP attributed to a rejected INVITE.
#[test]
fn a_wireshark_filter_selects_the_call_and_says_when_there_is_no_media() {
    let mut s = McpSession::start(REJECT, &[]);
    let v = s.ok(
        "generate_wireshark_filter",
        serde_json::json!({ "call_id": REJECT_CALL }),
    );
    assert_eq!(
        v["display_filter"],
        format!("sip.Call-ID == \"{REJECT_CALL}\""),
        "{v}"
    );
    assert_eq!(v["streams_included"], 0, "{v}");
    assert!(
        v["tshark"]
            .as_str()
            .is_some_and(|t| t.contains("sip-488-codec-reject.pcapng")),
        "the command line must name the capture it applies to: {v}"
    );
}

/// All four tools are registered and reachable over the wire.
#[test]
fn the_gate_and_the_generators_are_registered() {
    let mut s = McpSession::start(REJECT, &[]);
    let tools = s.list_tools();
    for name in [
        "evaluate_expectations",
        "generate_fail2ban_rule",
        "generate_repro",
        "generate_wireshark_filter",
    ] {
        assert!(
            tools.iter().any(|t| t == name),
            "{name} is not registered: {tools:?}"
        );
    }
}

/// The published unit for a metric matches the unit the evaluator reports.
///
/// # The defect
///
/// `evaluate_expectations`'s tool description -- the only syntax documentation
/// an LLM client is ever handed -- described `asr` as "a RATIO from 0.0 to
/// 1.0". The evaluator reports `unit: "percent"`. Measured on
/// `sip-problem-call.pcap`: a rule of `asr >= 0.95` returned
/// `observed: 20.0, unit: "percent", verdict: "pass", exit_code: 0`, with the
/// reason reading "20 is >= 0.9500".
///
/// An agent following the description writes `0.95`, means 95%, and installs a
/// gate that passes any capture whose ASR is above 0.95 PERCENT. That is the
/// worst shape a defect can take in a monitoring tool: the alarm is installed
/// and switched off, and a gate that always passes is indistinguishable from a
/// healthy system. `exit_code: 0` carries it into CI.
///
/// The `unit()` doc comment was wrong in the same direction and three lines
/// above the code contradicting it -- it claimed `asr` is "a RATIO here and a
/// PERCENT in `group_dialogs`" while the match arm returned `"percent"`.
///
/// This pins the agreement rather than the wording: whatever unit the
/// evaluator reports for a metric, the description must not name a different
/// one.
#[test]
fn the_published_metric_units_match_what_the_evaluator_reports() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/mcp/tools/expectations.rs"
    ))
    .expect("read expectations.rs");
    let start = src
        .find("name = \"evaluate_expectations\"")
        .expect("the tool is still registered");
    let description = &src[start
        ..src[start..]
            .find("annotations(")
            .map_or(src.len(), |i| start + i)];
    assert!(
        description.contains("asr"),
        "the description no longer mentions asr; this gate is reading the \
         wrong text"
    );

    // `asr` is reported in PERCENT. The description must say so, and must not
    // say ratio -- the two readings differ by a factor of 100, which is the
    // whole defect.
    assert!(
        !description.to_ascii_uppercase().contains("RATIO"),
        "the evaluate_expectations description calls a metric a RATIO. The \
         evaluator reports asr in PERCENT, and a client that believes the \
         description writes 0.95 for a 95% gate -- which passes at 0.95 \
         percent. Description text:\n{description}"
    );
    assert!(
        description.contains("PERCENT") || description.contains("percent"),
        "the description states no unit for asr. It is a percent; saying \
         nothing leaves a client to guess, and the guess that reads naturally \
         from a 0.0-1.0 habit is off by a hundred."
    );
}
