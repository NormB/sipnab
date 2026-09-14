// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST1: three kinds of statistic, one vocabulary, never blended.
//!
//! The spec is `docs/design/relay-statistics-vocabulary.md`. This gate holds
//! the code to it: the three wire names, the cross-tier prohibition, and the
//! three-state presence model where missing is not zero and refused is not
//! absent. Getting this wrong makes every later number untrustworthy, which is
//! why it is built and tested before any statistic is fetched.

use std::collections::BTreeSet;

use sipnab::stats_vocab::{StatisticTier, StatisticValue};

/// The three tiers have the snake_case wire names the spec assigns, and they
/// are distinct.
#[test]
fn the_three_tiers_carry_the_wire_names_the_spec_assigns() {
    assert_eq!(StatisticTier::RelayReported.as_wire_str(), "relay_reported");
    assert_eq!(
        StatisticTier::SipnabMeasured.as_wire_str(),
        "sipnab_measured"
    );
    assert_eq!(
        StatisticTier::EndpointReported.as_wire_str(),
        "endpoint_reported"
    );
    let names: BTreeSet<&str> = StatisticTier::all()
        .iter()
        .map(|t| t.as_wire_str())
        .collect();
    assert_eq!(
        names.len(),
        3,
        "the three tiers must have three distinct names, got {names:?}"
    );
}

/// The names are snake_case, not hyphenated.
///
/// ST-S1 decided the tier vocabulary uses underscores, matching
/// `endpoint_reported` and `xr_voip_metrics`, while `relay_vocab`'s shipped
/// `media-relay` keeps its hyphen. A hyphen here would be a third convention.
#[test]
fn the_wire_names_are_snake_case_not_hyphenated() {
    for t in StatisticTier::all() {
        let name = t.as_wire_str();
        assert!(
            !name.contains('-'),
            "{name:?} is hyphenated; the tier vocabulary is snake_case"
        );
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{name:?} is not snake_case"
        );
    }
}

/// No aggregate spans two tiers. `blends_tiers` is true exactly when the tiers
/// differ, across all nine ordered pairs.
#[test]
fn combining_two_different_tiers_is_always_a_blend() {
    for a in StatisticTier::all() {
        for b in StatisticTier::all() {
            let expected = a != b;
            assert_eq!(
                sipnab::stats_vocab::blends_tiers(a, b),
                expected,
                "blends_tiers({a:?}, {b:?}) should be {expected}: a blend is \
                 exactly a pair of different tiers"
            );
        }
    }
}

/// A counted zero occupies a key; not-asked does not. They are different facts.
#[test]
fn a_counted_zero_is_present_and_not_asked_is_absent() {
    let zero = StatisticValue::Counted("0".to_owned());
    assert!(
        zero.is_present_on_the_wire(),
        "a relay that counted zero reported a fact; it must occupy its key"
    );
    assert!(
        !StatisticValue::NotAsked.is_present_on_the_wire(),
        "a statistic nobody asked for must be ABSENT, not a zero"
    );
    assert_ne!(
        StatisticValue::Counted("0".to_owned()),
        StatisticValue::NotAsked,
        "counted-zero and not-asked are different states and must not be equal"
    );
}

/// A refusal is not an absence. It does not occupy a value key, and it carries
/// the code the source gave so `E68` and `E50` stay distinguishable.
#[test]
fn a_refusal_is_neither_a_value_nor_a_plain_absence() {
    let refused = StatisticValue::Refused("E68".to_owned());
    assert!(
        !refused.is_present_on_the_wire(),
        "a refusal is reported in a refusals list, not as a value key"
    );
    assert_ne!(
        refused,
        StatisticValue::NotAsked,
        "refused (asked and said no) and not-asked are different facts"
    );
    // The code is retained, not discarded.
    let StatisticValue::Refused(code) = &refused else {
        panic!("expected a refusal");
    };
    assert_eq!(code, "E68", "the relay's own refusal code must travel");
    assert_ne!(
        StatisticValue::Refused("E68".to_owned()),
        StatisticValue::Refused("E50".to_owned()),
        "E68 (no such statistic) and E50 (no such session) must not be equal"
    );
}

/// The spec document names the same three wire strings this code produces.
///
/// The gate-reads-one-half-of-a-pair lesson: the vocabulary is written twice,
/// in the code and in the spec, and they must not drift. If the spec renames a
/// tier, this fails until the code follows, and vice versa.
#[test]
fn the_code_and_the_spec_name_the_same_three_tiers() {
    let spec = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/design/relay-statistics-vocabulary.md"
    ))
    .expect("the ST-S1 spec is readable");
    for t in StatisticTier::all() {
        let name = t.as_wire_str();
        assert!(
            spec.contains(name),
            "the code produces the tier {name:?}, which the ST-S1 spec never \
             names -- one of the two drifted"
        );
    }
}

// ── ST-S4: the five failure classifications ──────────────────────────────

use sipnab::stats_vocab::{Responsibility, StatisticsOutcome};

/// The five classifications carry the snake_case wire names ST-S4 assigns, all
/// distinct.
#[test]
fn the_five_outcomes_carry_the_wire_names_the_catalog_assigns() {
    use StatisticsOutcome::*;
    assert_eq!(NotConfigured.as_wire_str(), "not_configured");
    assert_eq!(NotPermitted.as_wire_str(), "not_permitted");
    assert_eq!(Unreachable.as_wire_str(), "unreachable");
    assert_eq!(Refused.as_wire_str(), "refused");
    assert_eq!(Suspect.as_wire_str(), "suspect");
    let names: BTreeSet<&str> = StatisticsOutcome::all()
        .iter()
        .map(|o| o.as_wire_str())
        .collect();
    assert_eq!(
        names.len(),
        5,
        "five outcomes, five distinct names: {names:?}"
    );
}

/// The outcome wire names are snake_case, not hyphenated, like the tiers.
#[test]
fn the_outcome_wire_names_are_snake_case() {
    for o in StatisticsOutcome::all() {
        let name = o.as_wire_str();
        assert!(!name.contains('-'), "{name:?} is hyphenated");
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{name:?} is not snake_case"
        );
    }
}

/// Each classification points at whose problem it is, per ST-S4's table.
#[test]
fn each_outcome_points_at_whose_problem_it_is() {
    use StatisticsOutcome::*;
    assert_eq!(NotConfigured.responsibility(), Responsibility::Invocation);
    assert_eq!(NotPermitted.responsibility(), Responsibility::Invocation);
    assert_eq!(Unreachable.responsibility(), Responsibility::RelayOrNetwork);
    assert_eq!(Refused.responsibility(), Responsibility::Request);
    assert_eq!(Suspect.responsibility(), Responsibility::Answer);
    // Not vacuous: the five map to more than one responsibility, so a surface
    // cannot satisfy this by blaming one thing for everything.
    let kinds: BTreeSet<Responsibility> = StatisticsOutcome::all()
        .iter()
        .map(|o| o.responsibility())
        .collect();
    assert_eq!(
        kinds.len(),
        4,
        "the five outcomes span four responsibilities"
    );
}

/// The code and the ST-S4 spec name the same five classifications.
#[test]
fn the_code_and_the_catalog_name_the_same_five_outcomes() {
    let spec = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/design/relay-statistics-failures.md"
    ))
    .expect("the ST-S4 catalog is readable");
    for o in StatisticsOutcome::all() {
        let name = o.as_wire_str();
        assert!(
            spec.contains(&format!("`{name}`")),
            "the code produces the outcome `{name}`, which the ST-S4 catalog \
             never names as a classification -- one of the two drifted"
        );
    }
}

// ── ST-S1 wire resolution: the three-state rule, single-sourced ──────────

use sipnab::stats_vocab::{TieredStatistic, resolve_for_wire};

fn counted(name: &str, v: &str) -> TieredStatistic {
    TieredStatistic {
        name: name.to_string(),
        value: StatisticValue::Counted(v.to_string()),
        tier: StatisticTier::RelayReported,
    }
}
fn not_asked(name: &str) -> TieredStatistic {
    TieredStatistic {
        name: name.to_string(),
        value: StatisticValue::NotAsked,
        tier: StatisticTier::RelayReported,
    }
}
fn refused(name: &str, code: &str) -> TieredStatistic {
    TieredStatistic {
        name: name.to_string(),
        value: StatisticValue::Refused(code.to_string()),
        tier: StatisticTier::RelayReported,
    }
}

/// A counted value occupies a key; a counted zero occupies a key too.
#[test]
fn a_counted_value_including_zero_is_present_on_the_wire() {
    let wire = resolve_for_wire(&[
        counted("npkts_relayed", "9000"),
        counted("npkts_discard", "0"),
    ]);
    assert_eq!(
        wire.present.len(),
        2,
        "both counted values, zero included, are present"
    );
    assert!(wire.refusals.is_empty());
    let discard = wire
        .present
        .iter()
        .find(|v| v.name == "npkts_discard")
        .expect("present");
    assert_eq!(
        discard.value, "0",
        "a counted zero keeps its value, not omitted"
    );
    assert_eq!(discard.tier, StatisticTier::RelayReported);
}

/// A not-asked statistic is omitted from BOTH lists -- never a zero.
#[test]
fn a_not_asked_statistic_is_omitted_not_zeroed() {
    let wire = resolve_for_wire(&[counted("a", "1"), not_asked("rtpa_nlost")]);
    assert!(
        wire.present.iter().all(|v| v.name != "rtpa_nlost"),
        "a not-asked statistic must not appear as a value: {:?}",
        wire.present
    );
    assert!(
        wire.refusals.iter().all(|r| r.name != "rtpa_nlost"),
        "a not-asked statistic is not a refusal either"
    );
    assert_eq!(wire.present.len(), 1, "only the counted one occupies a key");
}

/// A refusal is listed with its code, never as a value.
#[test]
fn a_refusal_is_listed_with_its_code_not_as_a_value() {
    let wire = resolve_for_wire(&[counted("a", "1"), refused("rtpa_nlost", "E68")]);
    assert!(
        wire.present.iter().all(|v| v.name != "rtpa_nlost"),
        "a refusal must not occupy a value key"
    );
    assert_eq!(wire.refusals.len(), 1, "the refusal is listed");
    assert_eq!(wire.refusals[0].name, "rtpa_nlost");
    assert_eq!(
        wire.refusals[0].code, "E68",
        "the relay's own code must travel"
    );
}

/// The three states partition cleanly: present + refusals, not-asked in
/// neither, and a refusal code is never confused with another.
#[test]
fn the_three_states_partition_without_collapsing() {
    let wire = resolve_for_wire(&[
        counted("counted_zero", "0"),
        not_asked("absent"),
        refused("refused_68", "E68"),
        refused("refused_50", "E50"),
    ]);
    assert_eq!(wire.present.len(), 1, "one counted");
    assert_eq!(wire.refusals.len(), 2, "two refusals");
    let codes: BTreeSet<&str> = wire.refusals.iter().map(|r| r.code.as_str()).collect();
    assert_eq!(
        codes,
        BTreeSet::from(["E68", "E50"]),
        "E68 and E50 must both survive, distinct"
    );
    // `absent` is in neither list -- the omit-not-zero rule.
    assert!(
        wire.present.iter().all(|v| v.name != "absent")
            && wire.refusals.iter().all(|r| r.name != "absent"),
        "the not-asked statistic must be omitted from the wire entirely"
    );
}

use sipnab::stats_vocab::{NameSource, relay_reply_refusal};

/// A relay reply carrying `result: error` is the relay's own no, and its
/// `error-reason` travels verbatim so the reader sees the relay's words, not a
/// paraphrase. This is the single rule REST and MCP both read; it lives here so
/// the two surfaces cannot drift.
#[test]
fn a_relay_reply_with_result_error_is_a_refusal_carrying_its_reason() {
    let refused = [
        ("result".to_string(), "error".to_string()),
        ("error-reason".to_string(), "Unknown call-id".to_string()),
    ];
    assert_eq!(
        relay_reply_refusal(&refused).as_deref(),
        Some("Unknown call-id"),
        "result:error must read as a refusal carrying the relay's own reason"
    );
}

/// A clean reply -- `result: ok`, or counters with no `result` key at all -- is
/// not a refusal, so it is never rendered as one.
#[test]
fn a_clean_relay_reply_is_not_a_refusal() {
    let clean = [
        ("result".to_string(), "ok".to_string()),
        ("totals.RTP.packets".to_string(), "42".to_string()),
    ];
    assert!(
        relay_reply_refusal(&clean).is_none(),
        "result:ok is not a refusal"
    );
    let counters = [("totals.RTP.packets".to_string(), "42".to_string())];
    assert!(
        relay_reply_refusal(&counters).is_none(),
        "a reply with no result key is not a refusal"
    );
}

/// `result: error` is matched without regard to case (a relay may answer
/// `Error`), and a refusal that gives no `error-reason` still reads as a
/// refusal, with a stand-in sentence rather than an empty string -- an empty
/// reason would render as a silent no.
#[test]
fn a_refusal_is_case_insensitive_and_never_reasonless() {
    let mixed_case = [("result".to_string(), "Error".to_string())];
    let reason = relay_reply_refusal(&mixed_case);
    assert!(
        reason.is_some(),
        "result:Error (mixed case) must still read as a refusal"
    );
    assert!(
        !reason.as_deref().unwrap_or("").is_empty(),
        "a reasonless refusal must carry a stand-in sentence, never an empty string"
    );
}

/// `NameSource` has a stable wire token, distinct per variant, so a surface can
/// report `listed` vs `probed` from one spelling rather than copying the two-arm
/// match. `probed` is the weaker claim, and the token says which was made.
#[test]
fn name_source_carries_a_distinct_wire_token() {
    assert_eq!(NameSource::Listed.as_wire_str(), "listed");
    assert_eq!(NameSource::Probed.as_wire_str(), "probed");
    assert_ne!(
        NameSource::Listed.as_wire_str(),
        NameSource::Probed.as_wire_str(),
        "listed and probed must not collapse to one token"
    );
}

// ── ST9 condition 4: a per-call refusal is a refusal on every surface ────────
//
// `classify_per_call_reply` is the single seam the CLI per-call and compare
// paths and REST all pass a per-call reply through. It is tested here, not in
// `report_relay_statistics`/`report_relay_comparison` (src/app/bootstrap.rs),
// because those transmit to a live rtpengine over a control socket and cannot
// be driven from a unit test -- so the CONVERSION they perform is tested
// directly, and the call sites are thin matches over this result. The bug this
// closes: the CLI per-call path tiered a `result: error` reply into counter
// rows, rendering the relay's own "no" as statistics (`result -> error`).

use sipnab::stats_vocab::{PerCallReply, classify_per_call_reply};

/// Pairs a real rtpengine sends when it declines a per-call query. The key fact
/// under test: this is a refusal, not two statistics named `result` and
/// `error-reason`.
fn refusal_pairs(reason: &str) -> Vec<(String, String)> {
    vec![
        ("result".to_string(), "error".to_string()),
        ("error-reason".to_string(), reason.to_string()),
    ]
}

/// A per-call `result: error` reply classifies as `Refused`, carrying the
/// relay's own reason -- never as statistics. This is the whole ST9 condition-4
/// gap on the CLI: the per-call path used to tier these pairs into counter rows.
#[test]
fn a_per_call_result_error_classifies_as_refused_with_its_reason() {
    match classify_per_call_reply(&refusal_pairs("Unknown call-id")) {
        PerCallReply::Refused(reason) => assert_eq!(
            reason, "Unknown call-id",
            "the relay's own reason must travel verbatim"
        ),
        PerCallReply::Statistics(stats) => {
            panic!("a result:error per-call reply must be a refusal, not statistics: {stats:?}")
        }
    }
}

/// The refusal never leaks onto the wire as counter values: `result` and
/// `error-reason` must not appear as present statistics. This is the failure
/// mode the classifier exists to stop -- the relay's "no" rendered as data.
#[test]
fn a_per_call_refusal_is_never_rendered_as_counter_rows() {
    let PerCallReply::Refused(_) = classify_per_call_reply(&refusal_pairs("No call-id in message"))
    else {
        panic!("a result:error reply must classify as Refused, so nothing tiers it into values");
    };
    // And to prove the hazard is real: tiering the same pairs directly (the old
    // path) WOULD have surfaced `result`/`error-reason` as counted values.
    let wire = resolve_for_wire(&sipnab::stats_vocab::relay_reported(&refusal_pairs(
        "No call-id in message",
    )));
    assert!(
        wire.present.iter().any(|v| v.name == "result"),
        "sanity: the un-classified path really does render the refusal as a value, \
         which is the bug classify_per_call_reply prevents"
    );
}

/// `E68` (no such statistic) and `E50` (no such session) analogues must not
/// share a message: the reason is carried through unchanged so two different
/// refusals stay two different answers.
#[test]
fn two_different_per_call_refusals_do_not_collapse() {
    let a = match classify_per_call_reply(&refusal_pairs("Unknown call-id")) {
        PerCallReply::Refused(r) => r,
        other => panic!("expected refusal, got {other:?}"),
    };
    let b = match classify_per_call_reply(&refusal_pairs("No call-id in message")) {
        PerCallReply::Refused(r) => r,
        other => panic!("expected refusal, got {other:?}"),
    };
    assert_ne!(
        a, b,
        "two distinct relay reasons must not be flattened into one message"
    );
}

/// A per-call reply with real statistics classifies as `Statistics`, tiered
/// `relay_reported`, with every pair present and uncoerced.
#[test]
fn a_per_call_statistics_reply_classifies_as_statistics() {
    let pairs = vec![
        ("result".to_string(), "ok".to_string()),
        ("totals.RTP.packets".to_string(), "9000".to_string()),
        ("totals.RTP.bytes".to_string(), "1440000".to_string()),
    ];
    match classify_per_call_reply(&pairs) {
        PerCallReply::Statistics(stats) => {
            assert!(
                stats.iter().any(|s| s.name == "totals.RTP.packets"
                    && s.value == StatisticValue::Counted("9000".to_string())),
                "the counted value must survive uncoerced: {stats:?}"
            );
            assert!(
                stats.iter().all(|s| s.tier == StatisticTier::RelayReported),
                "every relay-reported pair is tiered relay_reported"
            );
        }
        PerCallReply::Refused(reason) => {
            panic!("a result:ok reply is not a refusal, got Refused({reason:?})")
        }
    }
}

/// A `result: error` with no `error-reason` still refuses -- with a non-empty
/// stand-in, never an empty string that would render as a silent no.
#[test]
fn a_reasonless_per_call_refusal_still_refuses_with_a_stand_in() {
    match classify_per_call_reply(&[("result".to_string(), "error".to_string())]) {
        PerCallReply::Refused(reason) => assert!(
            !reason.is_empty(),
            "a reasonless refusal must carry a stand-in sentence, never an empty string"
        ),
        PerCallReply::Statistics(stats) => {
            panic!("a reasonless result:error is still a refusal, not statistics: {stats:?}")
        }
    }
}

/// The classifier agrees with the single refusal rule it is built on: it
/// refuses exactly when `relay_reply_refusal` sees a refusal, so the two cannot
/// drift into disagreeing about what a per-call "no" is.
#[test]
fn classify_per_call_reply_agrees_with_relay_reply_refusal() {
    for pairs in [
        refusal_pairs("Unknown call-id"),
        vec![("result".to_string(), "ok".to_string())],
        vec![("totals.RTP.packets".to_string(), "0".to_string())],
        vec![("result".to_string(), "Error".to_string())],
    ] {
        let refused_by_rule = relay_reply_refusal(&pairs).is_some();
        let refused_by_classifier =
            matches!(classify_per_call_reply(&pairs), PerCallReply::Refused(_));
        assert_eq!(
            refused_by_rule, refused_by_classifier,
            "classify_per_call_reply and relay_reply_refusal must agree for {pairs:?}"
        );
    }
}

// ── ST9 condition 11: an oversized relay count is suspect, not absent ─────────
//
// `relay_compare_value` resolves the relay's per-call figure for a C4
// comparison into three answers that must not collapse: a count that fits, an
// absent side, and a value that does not fit u64. The bug it closes: a value
// that failed `parse::<u64>()` became `None`, which every compare surface reads
// as "the relay does not hold the call" -- so an answer that is present and too
// large would be reported as a call the relay is not carrying.

use sipnab::stats_vocab::{RelayCompareValue, relay_compare_value};

/// A relay count that fits `u64` is `Counted`, ready to compare.
#[test]
fn a_relay_count_that_fits_is_counted() {
    assert_eq!(
        relay_compare_value(
            &[counted("totals.RTP.packets", "9000")],
            "totals.RTP.packets"
        ),
        RelayCompareValue::Counted(9000),
    );
}

/// A counted ZERO is `Counted(0)`, never `Absent` -- ST9's zero-versus-absent
/// distinction reaching the comparison: a relay that carried the call and
/// counted no packets is not a relay that does not hold the call.
#[test]
fn a_counted_zero_is_counted_not_absent() {
    assert_eq!(
        relay_compare_value(&[counted("totals.RTP.packets", "0")], "totals.RTP.packets"),
        RelayCompareValue::Counted(0),
        "a measured zero must not read as an absent side"
    );
}

/// A key the relay never sent (not asked) is an absent side, not a zero.
#[test]
fn a_not_asked_relay_side_is_absent() {
    assert_eq!(
        relay_compare_value(&[not_asked("totals.RTP.packets")], "totals.RTP.packets"),
        RelayCompareValue::Absent,
    );
}

/// A refused key is an absent side too -- the relay declined the figure, it did
/// not report a zero.
#[test]
fn a_refused_relay_side_is_absent() {
    assert_eq!(
        relay_compare_value(
            &[refused("totals.RTP.packets", "E50")],
            "totals.RTP.packets"
        ),
        RelayCompareValue::Absent,
    );
}

/// A value too large for `u64` is `Overflow`, carrying its digits -- NOT
/// `Absent`. This is the whole condition-11 gap: an oversized count used to fall
/// through to `None` and read as "the relay does not hold the call".
///
/// The wire case is unreachable in practice: no relay in reach has run long
/// enough to wrap a 64-bit packet counter, and manufacturing one on a relay
/// would test a fixture rather than a relay (ST-S4 condition 11). So the
/// behavior is driven from a recorded oversized value here, which is the value
/// the catalog says to test against.
#[test]
fn an_oversized_relay_count_is_overflow_not_absent() {
    let huge = "99999999999999999999999"; // 23 digits, past u64::MAX (20 digits)
    match relay_compare_value(&[counted("totals.RTP.packets", huge)], "totals.RTP.packets") {
        RelayCompareValue::Overflow(digits) => assert_eq!(
            digits, huge,
            "the oversized value is carried as its digits, uncoerced and untruncated"
        ),
        other => panic!("an oversized count must be Overflow, not {other:?}"),
    }
}

/// The boundary holds: `u64::MAX` itself still fits and compares.
#[test]
fn u64_max_still_fits() {
    assert_eq!(
        relay_compare_value(
            &[counted("totals.RTP.packets", "18446744073709551615")],
            "totals.RTP.packets"
        ),
        RelayCompareValue::Counted(u64::MAX),
    );
}

/// A present-but-non-numeric value is also `Overflow` (present, uncomparable),
/// not `Absent`: an answer that cannot be trusted is the answer's problem, not a
/// missing call.
#[test]
fn a_present_non_numeric_value_is_overflow_not_absent() {
    match relay_compare_value(
        &[counted("totals.RTP.packets", "not-a-number")],
        "totals.RTP.packets",
    ) {
        RelayCompareValue::Overflow(digits) => assert_eq!(digits, "not-a-number"),
        other => panic!("a present, uncomparable value must be Overflow, not {other:?}"),
    }
}

// ── ST9 condition 6: a polled counter that steps backwards is a restart ───────
//
// A relay's counters are cumulative, so a reading lower than the one before it
// cannot happen without a reset -- the relay probably restarted. rtpproxy
// publishes no uptime, so a decrease is the only in-band signal. The poll loop
// used to compare nothing across polls; `counter_stepped_backwards` is the pure
// detector the loop now runs, and it is tested here directly.

use sipnab::stats_vocab::{BackwardsStep, counter_stepped_backwards};

fn kv(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A counter that rose is not a step -- the ordinary case, every poll.
#[test]
fn a_rising_counter_is_not_a_backwards_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("npkts", "9000")]), &kv(&[("npkts", "9600")])),
        None,
    );
}

/// An unchanged counter is not a step: a quiet relay, not a restarted one.
#[test]
fn an_unchanged_counter_is_not_a_backwards_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("npkts", "9000")]), &kv(&[("npkts", "9000")])),
        None,
    );
}

/// A counter that decreased is a step, carrying its name and both values so a
/// surface can say which counter and by how much.
#[test]
fn a_decreased_counter_is_a_backwards_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("npkts", "9000")]), &kv(&[("npkts", "0")])),
        Some(BackwardsStep {
            name: "npkts".to_string(),
            previous: 9000,
            current: 0,
        }),
    );
}

/// rtpengine's own `uptime` dropping is the same signal, and the one rtpproxy
/// cannot give.
#[test]
fn uptime_dropping_is_a_backwards_step() {
    let step = counter_stepped_backwards(&kv(&[("uptime", "134")]), &kv(&[("uptime", "2")]))
        .expect("uptime fell, which means a restart");
    assert_eq!(step.name, "uptime");
    assert_eq!((step.previous, step.current), (134, 2));
}

/// A counter present only in the current reading has nothing to compare against,
/// so it is not a step -- a new key is not a decrease.
#[test]
fn a_newly_appeared_counter_is_not_a_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("a", "1")]), &kv(&[("a", "2"), ("b", "5")])),
        None,
    );
}

/// A counter that disappeared is not a step either: absence is not a decrease.
#[test]
fn a_disappeared_counter_is_not_a_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("a", "1"), ("b", "5")]), &kv(&[("a", "2")])),
        None,
    );
}

/// Non-numeric values are not counters and are never read as a step -- a string
/// like rtpengine's `uptime: "134"` is handled by parsing, and a genuinely
/// non-numeric field is skipped, not compared as text.
#[test]
fn non_numeric_values_are_not_a_step() {
    assert_eq!(
        counter_stepped_backwards(&kv(&[("version", "zed")]), &kv(&[("version", "aardvark")])),
        None,
    );
}

/// With more than one decrease, the first by sorted name is returned, so the
/// result does not depend on the reply's order.
#[test]
fn the_first_decrease_by_sorted_name_is_deterministic() {
    let prev = kv(&[("zeta", "9"), ("alpha", "9")]);
    let cur = kv(&[("zeta", "1"), ("alpha", "1")]);
    let step = counter_stepped_backwards(&prev, &cur).expect("both fell");
    assert_eq!(
        step.name, "alpha",
        "the alphabetically-first decreased counter is reported, deterministically"
    );
}
