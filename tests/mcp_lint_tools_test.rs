// SPDX-License-Identifier: MIT OR Apache-2.0

//! The conformance-linter MCP tools, driven against real captures.
//!
//! The library rules already have 83 unit tests over synthetic dialogs and a
//! corpus-asserted hit rate. What none of that could prove is that an agent can
//! reach them: for one release the whole engine shipped with no tool registered,
//! which is a capability nobody can call and therefore a capability that does
//! not exist. The same defect family as RTCP XR parsed and dropped, and metrics
//! declared and never incremented.
//!
//! So every test here spawns the real binary over a real capture, calls the
//! tool the way a client would, and asserts a value verified independently from
//! the packets rather than from what the tool returned.
//!
//! The declaration-versus-observation class gets the most attention, because it
//! is the class no other SIP linter can run and the one whose absence is
//! invisible: an `OBS-` rule that never fires produces the same empty list as a
//! conformant call.
//!
//! `#![cfg(feature = "mcp")]` because these drive the MCP surface.

#![cfg(feature = "mcp")]

#[path = "support/mcp.rs"]
mod support;
use support::{McpSession, call_tool_with_args, ok_payload};

/// A B2BUA capture whose SDP negotiates `sendrecv` in both directions while the
/// media only ever flows one way.
///
/// Verified independently of the linter, through two other tools on the same
/// capture: `get_sdp_timeline` reports `mode: "sendrecv"` on all six exchanges,
/// and `rtp_stats` reports exactly one stream — 355 packets,
/// 203.0.113.145:8000 -> 203.0.113.1:8000 — with nothing coming back. That is
/// the defect `OBS-3264-6.1-DIRECTION-UNMET` names, and no linter reading
/// message text can see it: both halves of the offer/answer are perfectly legal
/// SDP.
const B2BUA: &str = "tests/pcap-samples/b2bua-asterisk.pcapng";

/// The dialog in [`B2BUA`] carrying the one-way media.
const B2BUA_CALL: &str = "b2bua-leg-synth@203.0.113.101:5060";

/// A capture whose first `OPTIONS` ping carries neither a `Max-Forwards` header
/// field nor an RFC 3261 branch cookie.
///
/// Verified from the message itself: `get_message` on index 0 of this dialog
/// shows an `OPTIONS` request, and the two findings below name header fields
/// that request does not carry.
const OPTIONS_PING: &str = "tests/pcap-samples/sip-488-codec-reject.pcapng";

/// The dialog in [`OPTIONS_PING`] whose first message trips two message rules.
const OPTIONS_CALL: &str = "options-ping-c-synth@198.51.100.206";

/// Findings for one call, as `(rule_id, severity)` pairs.
fn rule_ids(payload: &serde_json::Value) -> Vec<String> {
    payload["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("findings must be an array: {payload}"))
        .iter()
        .map(|f| f["rule_id"].as_str().expect("rule_id").to_string())
        .collect()
}

/// Every rule identifier named in `rules_not_evaluated`, across all groups.
fn skipped_ids(payload: &serde_json::Value) -> Vec<String> {
    payload["rules_not_evaluated"]
        .as_array()
        .unwrap_or_else(|| panic!("rules_not_evaluated must be an array: {payload}"))
        .iter()
        .flat_map(|g| g["rule_ids"].as_array().expect("rule_ids").iter())
        .map(|v| v.as_str().expect("rule id").to_string())
        .collect()
}

/// The rule class that justifies putting a linter behind this tool at all must
/// actually fire through it.
///
/// `sendrecv` in both directions with media in one is invisible to a grammar:
/// every message here is legal SIP and legal SDP. Only a tool holding the
/// signaling and the RTP together can report it, and until this test existed
/// nothing proved the MCP surface reached that rule.
#[test]
fn lint_dialog_reports_a_defect_that_lives_between_signalling_and_media() {
    let payload = ok_payload(&call_tool_with_args(
        B2BUA,
        &[],
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL}),
    ));

    let ids = rule_ids(&payload);
    assert!(
        ids.iter().any(|id| id == "OBS-3264-6.1-DIRECTION-UNMET"),
        "sendrecv was negotiated in both directions and 355 RTP packets went \
         one way. An empty OBS- list here is the shape a linter that never \
         reads the media produces: {ids:?}"
    );
    assert_eq!(
        payload["rtp_streams_observed"], 1,
        "the rule needs the stream to have reached the linter: {payload}"
    );

    let finding = payload["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|f| f["rule_id"] == "OBS-3264-6.1-DIRECTION-UNMET")
        .expect("the direction finding");
    assert_eq!(finding["basis"], "observation");
    assert_eq!(finding["severity"], "warning");
    assert!(
        finding["observed"]
            .as_str()
            .is_some_and(|o| o.contains("355")),
        "the finding must carry the packet count it was drawn from: {finding}"
    );
}

/// The citation stays two typed fields, and the numbers are the RFC's.
///
/// This is the reason the finding has the shape it has. An agent handed
/// `rfc: 3264` and `section: "6.1"` quotes a citation a reader can follow. An
/// agent handed only prose invents one that reads exactly as plausible and
/// sends the reader to the wrong paragraph — which is how three separate
/// sources came to place the angle-bracket rule in RFC 3261 §20.10, where it
/// is not.
#[test]
fn a_finding_carries_the_citation_as_data_not_prose() {
    let payload = ok_payload(&call_tool_with_args(
        B2BUA,
        &[],
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL}),
    ));

    for finding in payload["findings"].as_array().expect("findings") {
        let id = finding["rule_id"].as_str().expect("rule_id");
        assert!(
            finding["rfc"].is_u64(),
            "{id}: rfc must stay a number, not prose: {finding}"
        );
        let section = finding["section"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: section must stay a string: {finding}"));
        assert!(
            !section.is_empty() && section.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "{id}: section must be a section number, got {section:?}"
        );
        // The identifier splices the same two values, so a citation that
        // disagrees with its own identifier is caught here as well as in the
        // library's own gate.
        let rfc = finding["rfc"].as_u64().expect("rfc");
        assert!(
            id.contains(&format!("-{rfc}-{section}-")),
            "{id} names a different citation from the one it carries \
             (RFC {rfc} §{section})"
        );
        for field in ["observed", "expected", "explanation"] {
            assert!(
                finding[field].as_str().is_some_and(|s| !s.is_empty()),
                "{id}: {field} must carry evidence: {finding}"
            );
        }
    }
}

/// A ruleset selector narrows the run, and one that matches nothing says so.
///
/// The dangerous alternative is a selector that quietly does nothing: the
/// caller then reads the whole catalog believing it read a subset.
#[test]
fn rulesets_and_severity_narrow_the_run() {
    let mut session = McpSession::start(B2BUA, &[]);

    let all = ok_payload(&session.call("lint_dialog", serde_json::json!({"call_id": B2BUA_CALL})));
    let observed = ok_payload(&session.call(
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "rulesets": ["observed"]}),
    ));
    let interop = ok_payload(&session.call(
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "rulesets": ["interop"]}),
    ));
    let rfc3261 = ok_payload(&session.call(
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "rulesets": ["rfc3261"]}),
    ));

    // This call trips one observation rule and three interop ones, all of them
    // citing RFC 3264. Verified against the unfiltered run below.
    assert!(
        rule_ids(&observed).iter().all(|id| id.starts_with("OBS-")),
        "the observed selector must return only observation rules: {observed}"
    );
    assert!(
        !rule_ids(&observed).is_empty() && !rule_ids(&interop).is_empty(),
        "both halves have findings on this call, so an empty one is a filter \
         bug rather than a clean capture"
    );
    assert_eq!(
        observed["finding_count"].as_u64().unwrap_or(0)
            + interop["finding_count"].as_u64().unwrap_or(0),
        all["finding_count"].as_u64().unwrap_or(0),
        "the two selectors partition this call's findings between them"
    );
    assert_eq!(
        rfc3261["finding_count"], 0,
        "every finding on this call cites RFC 3264, so RFC 3261 must select \
         none of them rather than falling back to the whole catalog: {rfc3261}"
    );

    // `severity_min` is the engine's own filter, so a threshold above every
    // finding present empties the list rather than reordering it.
    let loud = ok_payload(&session.call(
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "severity_min": "error"}),
    ));
    assert_eq!(loud["finding_count"], 0, "nothing here is an error: {loud}");
    assert_eq!(loud["severity_min"], "error");

    let warned = ok_payload(&session.call(
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "severity_min": "warning"}),
    ));
    assert_eq!(
        warned["finding_count"], observed["finding_count"],
        "the one warning on this call is the direction finding: {warned}"
    );
}

/// A typo'd selector is refused by name rather than widening the run.
///
/// `rfc3621` is one transposition from `rfc3261`. Accepting it would select no
/// rule and return an empty finding list, which reads as a conformant call —
/// the worst outcome available, because it is a confident wrong answer.
#[test]
fn an_unknown_selector_is_refused_rather_than_silently_ignored() {
    let msg = call_tool_with_args(
        B2BUA,
        &[],
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL, "rulesets": ["rfc3621"]}),
    );
    let error = msg
        .get("error")
        .unwrap_or_else(|| panic!("a typo'd selector must not succeed: {msg}"));
    assert_eq!(error["code"], -32602);
    let text = error["message"].as_str().expect("message");
    assert!(
        text.contains("rfc3621") && text.contains("rfc3261") && text.contains("observation"),
        "the refusal must name the bad selector and the vocabulary: {text}"
    );
}

/// A run that could not reach a rule says which rule and why.
///
/// A rule that found nothing and a rule that never ran leave identical finding
/// lists, so an agent counting findings answers "conformant" for both. This
/// field is the only thing separating them.
#[test]
fn a_run_names_the_rules_it_could_not_evaluate() {
    // A call with media: only the RTCP rule stays out of reach, because the
    // stream store keeps no record of the endpoint pairs RTCP landed on.
    let with_media = ok_payload(&call_tool_with_args(
        B2BUA,
        &[],
        "lint_dialog",
        serde_json::json!({"call_id": B2BUA_CALL}),
    ));
    assert_eq!(
        skipped_ids(&with_media),
        ["OBS-5761-5.1.1-RTCP-MUX-UNANSWERED"],
        "with one RTP stream attributed, every other observation rule ran: \
         {with_media}"
    );

    // A call with no media at all: every observation rule is unreachable, and
    // saying nothing would present that as a clean media path.
    let no_media = ok_payload(&call_tool_with_args(
        OPTIONS_PING,
        &[],
        "lint_dialog",
        serde_json::json!({"call_id": OPTIONS_CALL}),
    ));
    assert_eq!(no_media["rtp_streams_observed"], 0);
    let skipped = skipped_ids(&no_media);
    for id in [
        "OBS-3264-6.1-PT-UNDECLARED",
        "OBS-4566-5.14-MEDIA-PORT-MISMATCH",
        "OBS-3264-6.1-DIRECTION-UNMET",
        "OBS-4566-6-PTIME-MISMATCH",
        "OBS-3551-4.2-FRAME-SIZE-IMPOSSIBLE",
        "OBS-5761-5.1.1-RTCP-MUX-UNANSWERED",
    ] {
        assert!(
            skipped.contains(&id.to_string()),
            "{id} had no media to read and the response must say so: {skipped:?}"
        );
    }
}

/// `validate_message` reads the message the index names, and reports what it
/// could not reach.
///
/// The two findings were verified against the message itself: index 0 of this
/// dialog is an `OPTIONS` request carrying neither `Max-Forwards` nor a branch
/// beginning `z9hG4bK`.
#[test]
fn validate_message_checks_the_message_the_index_names() {
    let mut session = McpSession::start(OPTIONS_PING, &[]);

    let payload = ok_payload(&session.call(
        "validate_message",
        serde_json::json!({"call_id": OPTIONS_CALL, "index": 0}),
    ));
    let ids = rule_ids(&payload);
    assert!(
        ids.contains(&"SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING".to_string())
            && ids.contains(&"SIP-3261-8.1.1.7-BRANCH-COOKIE".to_string()),
        "this OPTIONS request carries neither header field: {ids:?}"
    );
    assert_eq!(payload["message_index"], 0);
    assert_eq!(payload["message_count"], 2);
    for finding in payload["findings"].as_array().expect("findings") {
        assert_eq!(
            finding["message_index"], 0,
            "a finding must name the message it came from: {finding}"
        );
    }

    // Reading one message reaches neither the dialog rules nor the media ones.
    let skipped = skipped_ids(&payload);
    for id in [
        "SIP-3261-17.1.1.3-ACK-CSEQ-MISMATCH",
        "SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT",
        "OBS-3264-6.1-DIRECTION-UNMET",
    ] {
        assert!(
            skipped.contains(&id.to_string()),
            "{id} needs more than one message and the response must say so: \
             {skipped:?}"
        );
    }

    // Out of range refuses and names the count, rather than returning the last
    // message or an empty finding list.
    let msg = session.call(
        "validate_message",
        serde_json::json!({"call_id": OPTIONS_CALL, "index": 99}),
    );
    let error = msg
        .get("error")
        .unwrap_or_else(|| panic!("index 99 of a 2-message dialog must refuse: {msg}"));
    assert_eq!(error["code"], -32602);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("out of range") && m.contains('2')),
        "the refusal must name the message count: {error}"
    );
}

/// `explain_rule` resolves an identifier to the citation the rule really cites.
///
/// The bracket rule is the one pinned here on purpose. Three separate sources
/// place it in RFC 3261 §20.10, and the sentence sits in the preamble of
/// Section 20, above §20.1. An agent that reads the section number out of this
/// tool cites the right paragraph. One that recalls it does not.
#[test]
fn explain_rule_resolves_an_identifier_to_its_real_citation() {
    let mut session = McpSession::start(OPTIONS_PING, &[]);

    let bracket = ok_payload(&session.call(
        "explain_rule",
        serde_json::json!({"rule_id": "SIP-3261-20-URI-BRACKETS"}),
    ));
    assert_eq!(bracket["rfc"], 3261);
    assert_eq!(
        bracket["section"], "20",
        "the sentence lives in the Section 20 preamble, not §20.10: {bracket}"
    );
    assert_eq!(bracket["citation"], "RFC 3261 §20");
    assert_eq!(
        bracket["url"], "https://www.rfc-editor.org/rfc/rfc3261#section-20",
        "the link must reach the section, not the document"
    );

    // The selectors reported have to work as `lint_dialog` arguments, which is
    // the only reason to report them at all.
    let observation = ok_payload(&session.call(
        "explain_rule",
        serde_json::json!({"rule_id": "OBS-3264-6.1-DIRECTION-UNMET"}),
    ));
    assert_eq!(observation["scope"], "media");
    assert_eq!(observation["basis"], "observation");
    let selectors: Vec<String> =
        serde_json::from_value(observation["rulesets"].clone()).expect("rulesets");
    assert!(
        selectors.contains(&"observed".to_string())
            && selectors.contains(&"rfc3264".to_string())
            && !selectors.contains(&"syntax".to_string()),
        "a media rule is reachable by observed and by rfc3264, and not by \
         syntax: {selectors:?}"
    );

    // An unknown identifier refuses and lists the catalog, because an empty
    // answer reads as "that rule found nothing".
    let msg = session.call(
        "explain_rule",
        serde_json::json!({"rule_id": "SIP-3261-20.10-URI-BRACKETS"}),
    );
    let error = msg
        .get("error")
        .unwrap_or_else(|| panic!("an invented identifier must refuse: {msg}"));
    assert_eq!(error["code"], -32602);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|m| m.contains("SIP-3261-20-URI-BRACKETS")),
        "the refusal must list the real identifiers: {error}"
    );
}

/// Every rule the catalog holds is explainable through the tool.
///
/// A rule reachable by the engine but not by `explain_rule` leaves an agent
/// holding an identifier it cannot resolve, which is where a hallucinated
/// citation comes from.
#[test]
fn every_catalogued_rule_is_explainable() {
    let mut session = McpSession::start(OPTIONS_PING, &[]);
    // Read out of the library so a rule added later has to appear here too.
    let ids: Vec<&'static str> = sipnab::sip::lint::RULES.iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), 32, "the catalog size moved: {}", ids.len());

    for id in ids {
        let payload = ok_payload(&session.call("explain_rule", serde_json::json!({"rule_id": id})));
        assert_eq!(payload["rule_id"], id);
        assert!(
            payload["title"].as_str().is_some_and(|t| !t.is_empty()),
            "{id} has no title: {payload}"
        );
        assert!(
            payload["url"]
                .as_str()
                .is_some_and(|u| u.starts_with("https://www.rfc-editor.org/rfc/rfc")),
            "{id} has no link to its section: {payload}"
        );
        let selectors: Vec<String> =
            serde_json::from_value(payload["rulesets"].clone()).expect("rulesets");
        assert!(
            selectors.contains(&"all".to_string()),
            "{id} must at least be reachable by `all`: {selectors:?}"
        );
    }
}
