// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST8: the relay-statistics TUI view's ask, tested at its pure core.
//!
//! The view TRANSMITS, so it cannot be driven end to end without a live relay
//! (the same reason `query_relay` sits in the MCP `SCHEMA_NOT_DRIVEN` list). The
//! CONVERSION it performs -- a relay reply plus this capture's side, rendered to
//! the text the view shows -- is pure, and is exercised here directly, along
//! with the invocation refusals the composition root resolves.

#![cfg(feature = "tui")]

use chrono::TimeZone;
use sipnab::output::relay_statistics::FetchOrigin;
use sipnab::relay::types::ControlReply;
use sipnab::stats_vocab::StatisticsOutcome;
use sipnab::tui::relay_stats::{
    RelayQueryState, compose_compare, compose_counters_or_names, compose_holdings,
    compose_outcome_text,
};

fn at() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap()
}

fn pairs(kv: &[(&str, &str)]) -> ControlReply {
    ControlReply::Statistics(
        kv.iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    )
}

/// A global counters answer carries the relay's values, tiered `relay_reported`,
/// with the label the view will show -- the SAME text the CLI renders, since it
/// is the same `format_relay_statistics`.
#[test]
fn global_counters_render_relay_reported_values() {
    let reply = pairs(&[("totals.RTP.packets", "9000"), ("totals.RTP.bytes", "0")]);
    let text = compose_counters_or_names(
        &reply,
        "relay X (127.0.0.1:22222)",
        at(),
        false,
        false,
        FetchOrigin::Asked,
    );
    assert!(text.contains("relay_reported"), "tier is named: {text}");
    assert!(
        text.contains("totals.RTP.packets"),
        "the key travels: {text}"
    );
    assert!(text.contains("9000"));
    // A counted zero is present, not dropped (ST-S1 / ST9).
    assert!(
        text.contains("totals.RTP.bytes"),
        "the zero counter survives: {text}"
    );
}

/// A holdings answer lists every Call-ID the relay is holding and flags a
/// truncated set, so an operator can tell "these are all of them" from "there
/// are more the relay did not return". The wire is unreachable without a live
/// relay (ST8); the conversion is pure and exercised here directly.
#[test]
fn holdings_lists_the_call_ids_and_flags_truncation() {
    use sipnab::relay::types::Enumeration;
    let reply = ControlReply::Calls(Enumeration {
        call_ids: vec!["aaa@h".to_string(), "bbb@h".to_string()],
        truncated: true,
    });
    let text = compose_holdings(&reply, "relay X (127.0.0.1:22222)", at());
    assert!(
        text.contains("aaa@h") && text.contains("bbb@h"),
        "both held call-ids are listed:\n{text}"
    );
    assert!(
        text.contains("Holding 2 call"),
        "the count is stated:\n{text}"
    );
    assert!(text.contains('…'), "the truncated set is flagged:\n{text}");
}

/// A relay that refuses the list is reported in its own words, classified
/// `refused` — the relay was reached and declined, not unreachable.
#[test]
fn holdings_renders_a_relay_refusal_verbatim() {
    let reply = ControlReply::Refused {
        reason: "list disabled by config".to_string(),
    };
    let text = compose_holdings(&reply, "relay X (addr)", at());
    assert!(
        text.contains("list disabled by config"),
        "the relay's words travel:\n{text}"
    );
    assert!(
        text.contains("refused"),
        "the refusal is classified:\n{text}"
    );
}

/// A names-only answer lists the names the relay knows and says the set was
/// `listed` (the relay enumerated it), never their values.
#[test]
fn names_only_lists_the_names_and_their_source() {
    let reply = pairs(&[("totals.RTP.packets", "9000"), ("totals.RTP.bytes", "12")]);
    let text = compose_counters_or_names(
        &reply,
        "relay X (addr)",
        at(),
        false,
        true,
        FetchOrigin::Asked,
    );
    assert!(
        text.contains("totals.RTP.packets"),
        "a name is listed: {text}"
    );
    assert!(text.contains("listed"), "the source is stated: {text}");
    // A names view carries no VALUE for the counter -- "9000" belongs to the
    // counters view, not this one.
    assert!(!text.contains("9000"), "names carry no values: {text}");
}

/// A per-call reply that is the relay's own no (`result: error`) is a `refused`
/// classification carrying the relay's words -- never rendered as counters.
#[test]
fn a_per_call_result_error_is_refused_with_the_reason() {
    let reply = pairs(&[("result", "error"), ("error-reason", "Unknown call-id")]);
    let text = compose_counters_or_names(
        &reply,
        "relay X, call c@h",
        at(),
        true,
        false,
        FetchOrigin::Asked,
    );
    assert!(text.contains("refused"), "classified refused: {text}");
    assert!(
        text.contains("Unknown call-id"),
        "the relay's reason travels: {text}"
    );
    assert!(
        text.contains("request"),
        "whose problem: the request: {text}"
    );
}

/// The per-call refusal rule is scoped to a per-call ask, matching REST and MCP:
/// a GLOBAL reply that happens to carry a `result` key is rendered as counters,
/// not read as a refusal.
#[test]
fn the_refusal_rule_is_scoped_to_a_per_call_ask() {
    let reply = pairs(&[("result", "error")]);
    let global =
        compose_counters_or_names(&reply, "relay X", at(), false, false, FetchOrigin::Asked);
    assert!(
        !global.contains("refused"),
        "a global ask does not apply it: {global}"
    );
    let per_call =
        compose_counters_or_names(&reply, "relay X", at(), true, false, FetchOrigin::Asked);
    assert!(
        per_call.contains("refused"),
        "a per-call ask does: {per_call}"
    );
}

/// A reply that is not statistics at all is `suspect`.
#[test]
fn a_non_statistics_reply_is_suspect() {
    let reply = ControlReply::Refused {
        reason: "unexpected".to_string(),
    };
    let text = compose_counters_or_names(&reply, "relay X", at(), false, false, FetchOrigin::Asked);
    assert!(text.contains("suspect"), "classified suspect: {text}");
    assert!(text.contains("answer"), "whose problem: the answer: {text}");
}

/// A comparison shows both figures with their tiers and a word verdict, keeping
/// zero and absent distinct (ST9): equal counts read `match`.
#[test]
fn a_comparison_shows_both_sides_and_a_word_verdict() {
    let reply = pairs(&[("totals.RTP.packets", "9000")]);
    let text = compose_compare(&reply, "c@h", Some(9000), "relay X, call c@h", at());
    assert!(text.contains("match"), "equal counts match: {text}");
    assert!(text.contains("9000"));
    assert!(
        text.contains("relay_reported") && text.contains("sipnab_measured"),
        "both tiers: {text}"
    );

    let reply2 = pairs(&[("totals.RTP.packets", "9000")]);
    let differ = compose_compare(&reply2, "c@h", Some(4500), "relay X, call c@h", at());
    assert!(differ.contains("differ"), "unequal counts differ: {differ}");
}

/// An absent side is never coerced to zero (ST9): a reply the relay answered
/// without an RTP count, beside a measured count, is "the relay does not hold
/// this call", not a zero-versus-N gap.
#[test]
fn an_absent_relay_side_is_not_a_zero() {
    // No totals.RTP.packets in the reply -> relay side absent.
    let reply = pairs(&[("totals.RTP.bytes", "12")]);
    let text = compose_compare(&reply, "c@h", Some(4500), "relay X, call c@h", at());
    assert!(
        text.contains("does not hold call"),
        "absent relay side, not a zero: {text}"
    );
    assert!(!text.contains("verdict"), "no comparison was made: {text}");
}

/// ST-S4 condition 11: a relay per-call total too large for u64 is SUSPECT,
/// carrying its digits -- not an absent side that would read as "does not hold
/// this call". The wire case is unreachable (no relay in reach wraps a 64-bit
/// packet counter), so it is driven from a recorded oversized value, which is
/// what the catalog says to test against.
#[test]
fn an_oversized_relay_count_is_suspect_not_absent() {
    let huge = "99999999999999999999999"; // 23 digits, past u64::MAX (20 digits)
    let reply = pairs(&[("totals.RTP.packets", huge)]);
    let text = compose_compare(&reply, "c@h", Some(4500), "relay X, call c@h", at());
    assert!(
        text.contains(StatisticsOutcome::Suspect.as_wire_str()),
        "an oversized count is a suspect answer: {text}"
    );
    assert!(text.contains(huge), "the digits travel, uncoerced: {text}");
    assert!(
        !text.contains("does not hold call"),
        "an oversized count is present, not an absent side: {text}"
    );
    assert!(!text.contains("verdict"), "no comparison was made: {text}");
}

/// Every ST-S4 classification renders its wire token and whose problem it is, so
/// a terminal reader is sent to the right place -- the same tokens REST puts in
/// JSON.
#[test]
fn every_outcome_text_names_its_token_and_responsibility() {
    for outcome in StatisticsOutcome::all() {
        let text = compose_outcome_text(outcome, "some detail");
        assert!(
            text.contains(outcome.as_wire_str()),
            "{outcome:?} names its token: {text}"
        );
        assert!(
            text.contains(outcome.responsibility().as_wire_str()),
            "{outcome:?} names whose problem it is: {text}"
        );
        assert!(text.contains("some detail"), "the detail travels: {text}");
    }
}

/// The two invocation refusals are told apart, never collapsed: no relay is
/// `not_configured`, a relay with no permit is `not_permitted`. A ready state
/// has no refusal.
#[test]
fn invocation_refusals_are_distinct() {
    let nc = RelayQueryState::NotConfigured.invocation_refusal();
    let np = RelayQueryState::NotPermitted.invocation_refusal();
    assert!(nc.as_deref().unwrap().contains("not_configured"));
    assert!(np.as_deref().unwrap().contains("not_permitted"));
    assert_ne!(nc, np, "the two must not render the same");
}

/// The C5 re-poll cadence is a pure decision, tested without a clock: no
/// interval never polls; an interval polls once immediately (nothing asked
/// yet), then only after it elapses.
#[test]
fn poll_due_respects_the_interval_deterministically() {
    use sipnab::tui::relay_stats::poll_due;
    use std::time::{Duration, Instant};
    let now = Instant::now();
    // No interval configured: a poll is never due.
    assert!(!poll_due(None, now, None));
    assert!(!poll_due(Some(now), now, None));
    // Interval set, nothing asked yet: due now.
    assert!(poll_due(None, now, Some(3)));
    // Asked just now: not due until the interval elapses.
    assert!(!poll_due(Some(now), now, Some(3)));
    // Asked long enough ago: due.
    let earlier = now.checked_sub(Duration::from_secs(5)).unwrap_or(now);
    assert!(poll_due(Some(earlier), now, Some(3)));
    // Asked within the interval: not due.
    let recent = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
    assert!(!poll_due(Some(recent), now, Some(3)));
}

/// The counters view labels itself `polled` with the interval when the run set
/// one (C5), and `asked` otherwise -- the interval shows in the header.
#[test]
fn fetch_origin_and_header_reflect_the_interval() {
    use sipnab::tui::relay_stats::fetch_origin;
    assert_eq!(fetch_origin(None), FetchOrigin::Asked);
    assert_eq!(
        fetch_origin(Some(30)),
        FetchOrigin::Polled { every_secs: 30 }
    );

    let reply = pairs(&[("totals.RTP.packets", "9000")]);
    let polled = compose_counters_or_names(
        &reply,
        "relay X",
        at(),
        false,
        false,
        fetch_origin(Some(30)),
    );
    assert!(
        polled.contains("polled"),
        "the header says polled: {polled}"
    );
    assert!(
        polled.contains("30"),
        "the interval shows in the header: {polled}"
    );
}
