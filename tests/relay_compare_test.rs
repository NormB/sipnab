// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7 / C4: compare a relay's own per-call count against sipnab's measurement.
//!
//! This is the ONE place two tiers appear in one answer, and ST-S1 fixes what
//! that answer may be: a comparison, never an aggregate. Both figures are
//! shown, both tiers are named, the verdict is a WORD rather than a number, and
//! the note explains that an ordinary difference is not a relay fault -- a
//! capture on a mirror port undercounts, a relay restart mid-call zeroes its
//! counters, a window that does not line up differs for neither's fault.
//!
//! The cross-tier difference is never itself a statistic: `blends_tiers` forbids
//! `relay - sipnab` as a value, so the two raw figures travel and the reader
//! reads both. These gates hold `compare_relay_and_sipnab` (the pure verdict)
//! and the CLI's rendering of it.

#![cfg(feature = "full")]

use chrono::{DateTime, TimeZone, Utc};

use sipnab::output::relay_statistics::format_relay_comparison;
use sipnab::stats_vocab::{
    CompareOutcome, ComparedFigure, ComparisonVerdict, StatisticTier, blends_tiers,
    compare_relay_and_sipnab, ready_comparison,
};

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 13, 4, 5, 6).unwrap()
}

fn relay(value: u64, name: &str) -> ComparedFigure {
    ComparedFigure {
        value,
        name: Some(name.to_string()),
        tier: StatisticTier::RelayReported,
    }
}

fn sipnab(value: u64) -> ComparedFigure {
    ComparedFigure {
        value,
        name: None,
        tier: StatisticTier::SipnabMeasured,
    }
}

// ── compare_relay_and_sipnab: the verdict ───────────────────────────────────

/// Equal counts are a match.
#[test]
fn equal_counts_match() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(9000));
    assert_eq!(c.verdict, ComparisonVerdict::Match);
}

/// Any inequality is a differ -- there is no tolerance band, because a band
/// would be a policy number sipnab does not have; both raw counts are shown and
/// the operator judges the six-packet gap themselves.
#[test]
fn unequal_counts_differ() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    assert_eq!(c.verdict, ComparisonVerdict::Differ);
}

/// Both raw figures survive into the comparison, unmodified: the relay's with
/// its own key name, sipnab's as measured. Neither is coerced toward the other.
#[test]
fn both_raw_figures_survive_unmodified() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    assert_eq!(c.relay.value, 9000);
    assert_eq!(c.relay.name.as_deref(), Some("totals.RTP.packets"));
    assert_eq!(c.relay.tier, StatisticTier::RelayReported);
    assert_eq!(c.sipnab.value, 8994);
    assert_eq!(c.sipnab.tier, StatisticTier::SipnabMeasured);
}

/// The two sides are DIFFERENT tiers, so `blends_tiers` forbids summing them --
/// which is exactly why C4 compares rather than aggregates. If this ever became
/// false, the two figures would be the same kind of claim and there would be
/// nothing to compare.
#[test]
fn the_two_sides_are_tiers_that_must_never_be_blended() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    assert!(
        blends_tiers(c.relay.tier, c.sipnab.tier),
        "relay_reported and sipnab_measured must never be summed; C4 compares them"
    );
}

/// When sipnab counted fewer (an UNDERcount), the note names the ordinary
/// undercount causes, so an operator handed "differ" does not go straight to
/// blaming the relay.
#[test]
fn a_sipnab_fewer_note_names_the_undercount_causes() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    let note = c.note.to_lowercase();
    // capture undercount on a mirror port
    assert!(
        note.contains("mirror") || note.contains("undercount") || note.contains("dropped"),
        "the note must name capture undercount as an ordinary cause: {note}"
    );
    // a relay restart mid-call
    assert!(
        note.contains("restart"),
        "the note must name a mid-call restart as an ordinary cause: {note}"
    );
    // capture_health is where the operator confirms a capture drop
    assert!(
        note.contains("capture_health") || note.contains("capture health"),
        "the note must point at capture_health: {note}"
    );
}

/// When sipnab counted MORE (the relay counted fewer -- an OVERcount), the note
/// must name the actual cause: a capture that sees both sides of a relay counts
/// each packet more than once. Listing only undercount causes here would
/// misexplain the common relay-segment case (observed live: ~2x the relay).
#[test]
fn a_relay_fewer_note_names_the_double_count_cause() {
    // sipnab saw ~2x, as a bridge capture of a relay hairpin does.
    let c = compare_relay_and_sipnab(relay(1998, "totals.RTP.packets"), sipnab(3980));
    let note = c.note.to_lowercase();
    assert!(
        note.contains("both sides") || note.contains("more than once") || note.contains("twice"),
        "an overcount note must explain seeing each packet more than once: {note}"
    );
    // And it must NOT reach for the undercount explanation, which is backwards.
    assert!(
        !note.contains("undercount"),
        "an overcount must not be explained as an undercount: {note}"
    );
}

/// The note states the DIRECTION of the gap in prose, but the difference is
/// never computed as a value -- both counts are shown and the reader subtracts
/// if they want to, which keeps the cross-tier arithmetic out of the data.
#[test]
fn a_differ_note_states_direction_without_a_computed_difference() {
    // sipnab counted fewer than the relay.
    let fewer = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    assert!(
        fewer.note.to_lowercase().contains("sipnab") && fewer.note.to_lowercase().contains("fewer"),
        "sipnab counted fewer is stated: {}",
        fewer.note
    );
    // The exact numeric difference (6) is not present as a standalone figure.
    assert!(
        !fewer.note.contains(" 6 ") && !fewer.note.contains("6 packets"),
        "the difference is not computed as a cross-tier number: {}",
        fewer.note
    );

    // The other direction: the relay counted fewer (sipnab saw more).
    let relay_fewer = compare_relay_and_sipnab(relay(8994, "totals.RTP.packets"), sipnab(9000));
    assert!(
        relay_fewer.note.to_lowercase().contains("relay")
            && relay_fewer.note.to_lowercase().contains("fewer"),
        "the relay counted fewer is stated: {}",
        relay_fewer.note
    );
}

/// A match note confirms agreement rather than leaving the reader to infer it.
#[test]
fn a_match_note_confirms_agreement() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(9000));
    assert!(
        c.note.to_lowercase().contains("agree"),
        "a match says the two agree: {}",
        c.note
    );
}

/// The verdict's wire spelling is stable and matches ST-S3's example (`differ`).
#[test]
fn the_verdict_wire_spelling_is_match_or_differ() {
    assert_eq!(ComparisonVerdict::Match.as_wire_str(), "match");
    assert_eq!(ComparisonVerdict::Differ.as_wire_str(), "differ");
}

// ── ready_comparison: zero versus absent (ST9) ──────────────────────────────

/// Both sides present: a comparison is made, carrying both figures.
#[test]
fn both_sides_present_yields_a_comparison() {
    match ready_comparison(Some(9000), Some(8994)) {
        CompareOutcome::Compared(c) => {
            assert_eq!(c.relay.value, 9000);
            assert_eq!(c.sipnab.value, 8994);
            assert_eq!(c.verdict, ComparisonVerdict::Differ);
        }
        other => panic!("both present should compare, got {other:?}"),
    }
}

/// The relay reports a total but sipnab captured no RTP for the call: this is
/// NOT "sipnab measured zero" -- it is absent, and must not render as `0` in a
/// comparison that then blames the relay. ST9: zero and absent are different.
#[test]
fn relay_present_sipnab_absent_is_not_a_zero_comparison() {
    match ready_comparison(Some(1796), None) {
        CompareOutcome::SipnabHasNoRtp { relay_value } => assert_eq!(relay_value, 1796),
        other => panic!("sipnab absent must not compare against 0, got {other:?}"),
    }
}

/// sipnab measured the call but the relay does not hold it: sipnab's count is
/// carried, and the relay side is reported absent rather than compared to 0.
#[test]
fn sipnab_present_relay_absent_reports_the_relay_does_not_hold_it() {
    match ready_comparison(None, Some(500)) {
        CompareOutcome::RelayDoesNotHoldCall { sipnab_value } => assert_eq!(sipnab_value, 500),
        other => panic!("relay absent must not compare against 0, got {other:?}"),
    }
}

/// Neither side has anything: no comparison, no invented zeroes.
#[test]
fn neither_side_present_is_neither() {
    assert!(matches!(
        ready_comparison(None, None),
        CompareOutcome::NeitherSide
    ));
}

/// A genuine measured zero is still absent here, because a stream that captured
/// packets always has at least one: the caller passes `None` for "no RTP for
/// this call", never `Some(0)`, so a `Some(0)` would be a real relay zero
/// versus a real sipnab zero -- which is a match, not a fabricated gap.
#[test]
fn two_real_zeroes_match_rather_than_read_as_absent() {
    // If both sides legitimately report zero (a call that carried no media and
    // a relay that agrees), that is a match, not "absent".
    match ready_comparison(Some(0), Some(0)) {
        CompareOutcome::Compared(c) => assert_eq!(c.verdict, ComparisonVerdict::Match),
        other => panic!("two real zeroes are a match, got {other:?}"),
    }
}

// ── format_relay_comparison: the CLI rendering ──────────────────────────────

/// The rendering names the call, both tiers, both raw values, and the verdict.
#[test]
fn the_rendering_shows_both_tiers_both_values_and_the_verdict() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    let text = format_relay_comparison(&c, "1-7@10.0.0.1", "rtpengine at 10.0.0.1:22222", at());

    assert!(text.contains("1-7@10.0.0.1"), "the call is named:\n{text}");
    assert!(
        text.contains("relay_reported") && text.contains("sipnab_measured"),
        "both tiers are named:\n{text}"
    );
    assert!(
        text.contains("9000") && text.contains("8994"),
        "both raw values are shown:\n{text}"
    );
    assert!(
        text.contains("totals.RTP.packets"),
        "the relay's own key name travels:\n{text}"
    );
    assert!(
        text.to_lowercase().contains("differ"),
        "the verdict word is shown:\n{text}"
    );
    assert!(
        text.contains("2026-09-13T04:05:06Z"),
        "when it was asked is shown:\n{text}"
    );
}

/// A match renders the verdict word "match" and does not falsely claim a
/// difference.
#[test]
fn a_match_renders_as_match() {
    let c = compare_relay_and_sipnab(relay(500, "totals.RTP.packets"), sipnab(500));
    let text = format_relay_comparison(&c, "call-x", "relay", at());
    assert!(
        text.to_lowercase().contains("match"),
        "a match renders as match:\n{text}"
    );
}

/// The rendering carries the note, so the caveat travels with the numbers
/// rather than being dropped at the CLI.
#[test]
fn the_rendering_carries_the_note() {
    let c = compare_relay_and_sipnab(relay(9000, "totals.RTP.packets"), sipnab(8994));
    let text = format_relay_comparison(&c, "call-x", "relay", at());
    assert!(
        text.to_lowercase().contains("restart") && text.to_lowercase().contains("capture_health"),
        "the note travels into the rendering:\n{text}"
    );
}
