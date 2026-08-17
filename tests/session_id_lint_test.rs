// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 7989 `Session-ID` deviation detector, read through the surface an
//! operator and an agent actually see.
//!
//! # Why this file exists at all
//!
//! `SessionId::deviations` was computed, unit-tested, and consumed by nothing.
//! A detector nobody can reach is indistinguishable from a detector that finds
//! nothing, and this repository has closed that same shape four times — config
//! parsed and never read, RTCP XR parsed and discarded, metrics declared and
//! never incremented, kill outcomes computed and dropped. The unit tests inside
//! `src/sip/session_id.rs` could not catch it: they proved the classification
//! and said nothing about whether anything asked for it.
//!
//! So these tests deliberately start outside the module. They put messages
//! through the dialog store the way the capture path does, ask the linter the
//! way `lint_dialog` over MCP does, and assert on the finding an operator reads.
//!
//! # What a deviating Session-ID actually costs
//!
//! Multi-leg correlation treats RFC 7989 as the key that survives an SBC,
//! because a B2BUA rewrites the Call-ID and issues a fresh Via branch and
//! nothing else crosses that boundary by design. It only survives if both ends
//! implement it correctly. When a match that plainly should have happened does
//! not, the deviation is the explanation — and before this wiring the agent was
//! left to guess at it.

use chrono::{DateTime, Utc};
use std::net::{IpAddr, Ipv4Addr};

use sipnab::net::TransportProto;
use sipnab::sip::dialog_store::{CorrelationReason, DialogStore};
use sipnab::sip::lint::finding::{SESSION_ID_MALFORMED, SESSION_ID_UPPERCASE};
use sipnab::sip::lint::{LintConfig, Linter, RULES, Severity, rule_by_id};
use sipnab::sip::parser::parse_sip;

/// One endpoint's conforming `sess-uuid`. RFC 7989 §5's own example value.
const UUID_A: &str = "ab30317f1a784dc48ff824d0d3715d86";

/// The far endpoint's half of the same session, also from §5's example.
const UUID_B: &str = "47755a9de7794ba387653f2099600ef2";

/// A fixed capture timestamp, so nothing here depends on when it runs.
fn ts() -> DateTime<Utc> {
    DateTime::from_timestamp(1_718_452_800, 0).unwrap_or_default()
}

/// Feed one INVITE carrying `session_id` under `call_id` into `store`.
///
/// RFC 5737 documentation addresses throughout: nothing in this file may carry
/// an address, a number or a Call-ID that belongs to anybody.
fn ingest_leg(store: &mut DialogStore, call_id: &str, session_id: &str) {
    let raw = format!(
        "INVITE sip:bob@example.net SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK{call_id}\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:bob@example.net>\r\n\
         From: <sip:alice@example.com>;tag=1928301774\r\n\
         Call-ID: {call_id}\r\n\
         Session-ID: {session_id}\r\n\
         CSeq: 314159 INVITE\r\n\
         Contact: <sip:alice@192.0.2.1>\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    let msg = parse_sip(
        raw.as_bytes(),
        ts(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .expect("the fixture must parse");
    store.process_message(msg);
}

/// Rule identifiers the default linter raises for the dialog under `call_id`.
fn dialog_rule_ids(store: &DialogStore, call_id: &str) -> Vec<&'static str> {
    let dialog = store.get(call_id).expect("the leg must be stored");
    Linter::new(LintConfig::new())
        .lint_dialog(dialog)
        .into_iter()
        .map(|f| f.rule_id)
        .collect()
}

/// THE GATE: a dialog carrying a `Session-ID` that breaks the RFC 7989 §5 ABNF
/// produces a finding an operator can see.
///
/// Not a unit test of the parser. The message goes through the dialog store,
/// the dialog goes through the linter, and the assertion is on the identifier
/// a carrier ticket quotes and a suppression file names.
#[test]
fn a_dialog_carrying_a_deviating_session_id_produces_a_visible_finding() {
    let mut store = DialogStore::new(100, false);
    ingest_leg(&mut store, "deviating-leg@example.net", "not-a-uuid");

    let ids = dialog_rule_ids(&store, "deviating-leg@example.net");
    assert!(
        ids.contains(&SESSION_ID_MALFORMED.id),
        "the deviation must reach the findings: {ids:?}"
    );
}

/// The finding carries the clause it enforces, as data rather than as prose.
///
/// A lint rule that cannot name its section is an opinion. `rfc` and `section`
/// are separate fields precisely so an agent can quote RFC 7989 §5 instead of
/// inventing a section that reads plausibly, and this asserts the whole record
/// an MCP client receives under `findings[]`.
#[test]
fn the_finding_cites_rfc_7989_section_5_and_quotes_the_abnf() {
    let mut store = DialogStore::new(100, false);
    ingest_leg(&mut store, "deviating-leg@example.net", "not-a-uuid");
    let dialog = store.get("deviating-leg@example.net").expect("stored");

    let finding = Linter::new(LintConfig::new())
        .lint_dialog(dialog)
        .into_iter()
        .find(|f| f.rule_id == SESSION_ID_MALFORMED.id)
        .expect("the malformed rule must fire");

    assert_eq!(finding.rfc, 7989);
    assert_eq!(finding.section, "5");
    assert_eq!(finding.citation(), "RFC 7989 §5");
    assert_eq!(finding.severity, Severity::Error);
    assert!(
        finding.expected.contains("32(DIGIT / %x61-66)"),
        "the expectation must quote the production it enforces: {}",
        finding.expected
    );
    assert!(
        finding.observed.contains("local-uuid"),
        "the finding must name which half deviated: {}",
        finding.observed
    );

    // The exact JSON an agent reads back from `lint_dialog` and
    // `validate_message`, both of which serialize `Finding` straight into
    // `findings[]`.
    let json = serde_json::to_value(&finding).expect("a finding must serialize");
    assert_eq!(json["rule_id"], SESSION_ID_MALFORMED.id);
    assert_eq!(json["rfc"], 7989);
    assert_eq!(json["section"], "5");
    assert_eq!(json["severity"], "error");
    assert_eq!(json["basis"], "must");
    for field in ["observed", "expected", "explanation"] {
        assert!(
            json[field].as_str().is_some_and(|s| !s.is_empty()),
            "{field} must reach the client: {json}"
        );
    }
}

/// RFC 7989 §5's `nil` — 32 zeros, "the far end has not contributed a UUID
/// yet", which is what every initial INVITE carries as its remote half.
const NIL: &str = "00000000000000000000000000000000";

/// The case the wiring exists for: two legs that should have correlated, did
/// not, and the linter says why.
///
/// Both captures hold the same INVITE either side of an SBC that rewrote the
/// Call-ID, so RFC 7989 is the only thing left tying them together. The far end
/// has not answered yet, so the remote half is `nil` on both — which leaves the
/// local half carrying the whole match. The SBC forwarded it 31 characters
/// long, correlation has nothing well formed left to intersect, and one call
/// reads as two unrelated ones.
///
/// A truncated half is only fatal because it is the LAST usable one: a broken
/// remote beside a good local still matches, since correlation intersects the
/// non-nil halves rather than comparing the pair. That is exactly why the
/// finding has to be raised on the deviation itself and not on a failed match.
#[test]
fn a_deviating_half_explains_a_correlation_that_should_have_matched_and_did_not() {
    let mut store = DialogStore::new(100, false);
    ingest_leg(
        &mut store,
        "access-leg@example.com",
        &format!("{UUID_A};remote={NIL}"),
    );
    ingest_leg(
        &mut store,
        "core-leg@example.net",
        &format!("{};remote={NIL}", &UUID_A[..31]),
    );

    let correlated = store.find_correlated_scored("access-leg@example.com");
    assert!(
        correlated
            .iter()
            .all(|r| r.reason != CorrelationReason::SessionId),
        "a truncated half cannot correlate — that is the failure being explained"
    );

    let ids = dialog_rule_ids(&store, "core-leg@example.net");
    assert!(
        ids.contains(&SESSION_ID_MALFORMED.id),
        "the leg holding the broken half must carry the explanation: {ids:?}"
    );
}

/// The mutation guard for the test above: the same two legs, conforming, match
/// on Session-ID and raise nothing.
///
/// Without this, a rule that fired on the presence of the header and a
/// correlation that never matched would both pass unnoticed. The `nil` remote
/// halves are here for the same reason — they are absence, not a value, and a
/// linter that reported them would fire on the first message of practically
/// every conformant call.
#[test]
fn the_same_two_legs_correlate_and_stay_silent_when_both_halves_conform() {
    let mut store = DialogStore::new(100, false);
    ingest_leg(
        &mut store,
        "access-leg@example.com",
        &format!("{UUID_A};remote={NIL}"),
    );
    ingest_leg(
        &mut store,
        "core-leg@example.net",
        &format!("{UUID_A};remote={UUID_B}"),
    );

    let correlated = store.find_correlated_scored("access-leg@example.com");
    assert!(
        correlated
            .iter()
            .any(|r| r.reason == CorrelationReason::SessionId),
        "conforming halves must still correlate across the B2BUA"
    );

    for call_id in ["access-leg@example.com", "core-leg@example.net"] {
        let ids = dialog_rule_ids(&store, call_id);
        assert!(
            !ids.contains(&SESSION_ID_MALFORMED.id) && !ids.contains(&SESSION_ID_UPPERCASE.id),
            "{call_id} is conformant and must raise nothing: {ids:?}"
        );
    }
}

/// Uppercase hex is reported even though sipnab still correlates on it.
///
/// This is the finding that would otherwise never be found: correlation
/// succeeds here, so nothing about the call tree looks wrong, while any peer
/// comparing the header byte for byte splits one session in two. Reporting it
/// only when it broke something would report it only after somebody else's
/// equipment had already been blamed.
#[test]
fn uppercase_hex_is_reported_even_though_correlation_still_succeeds() {
    let mut store = DialogStore::new(100, false);
    ingest_leg(
        &mut store,
        "access-leg@example.com",
        &format!("{UUID_A};remote={UUID_B}"),
    );
    ingest_leg(
        &mut store,
        "core-leg@example.net",
        &format!(
            "{};remote={}",
            UUID_B.to_ascii_uppercase(),
            UUID_A.to_ascii_uppercase()
        ),
    );

    assert!(
        store
            .find_correlated_scored("access-leg@example.com")
            .iter()
            .any(|r| r.reason == CorrelationReason::SessionId),
        "case must not split a session inside sipnab"
    );

    let ids = dialog_rule_ids(&store, "core-leg@example.net");
    assert!(
        ids.contains(&SESSION_ID_UPPERCASE.id),
        "the conformance fact is still worth reporting: {ids:?}"
    );
    assert!(
        !ids.contains(&SESSION_ID_MALFORMED.id),
        "an uppercase UUID is usable, not malformed: {ids:?}"
    );
}

/// Both rules are in the catalog and resolvable by identifier.
///
/// `explain_rule` over MCP answers out of `RULES` via `rule_by_id`, so a rule
/// that fires without being cataloged hands an agent an identifier it cannot
/// resolve — which is where a hallucinated citation comes from.
#[test]
fn both_session_id_rules_are_catalogued_and_resolvable_by_identifier() {
    for rule in [SESSION_ID_MALFORMED, SESSION_ID_UPPERCASE] {
        assert!(
            RULES.iter().any(|r| r.id == rule.id),
            "{} is not in the catalog, so the engine cannot report it",
            rule.id
        );
        let found = rule_by_id(rule.id).unwrap_or_else(|| panic!("{} does not resolve", rule.id));
        assert_eq!(found.rfc, 7989);
        assert_eq!(found.section, "5");
        assert_eq!(
            found.url(),
            "https://www.rfc-editor.org/rfc/rfc7989#section-5",
            "{}",
            rule.id
        );
    }
}
