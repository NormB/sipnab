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
