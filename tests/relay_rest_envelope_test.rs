// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST5: the REST envelope for relay statistics.
//!
//! Every relay-stats REST response carries a top-level `outcome`, so a client
//! reads one field to tell a clean answer from a classification. A refusal is
//! HTTP 200 with the classification in the body, never a 4xx (the route exists;
//! the relay is what did not answer) -- and the five ST-S4 classifications stay
//! distinct, each naming whose problem it is. The success payload is the same
//! the CLI `--json` forms emit, so REST and the CLI agree on the figures.

#![cfg(feature = "full")]

use serde_json::Value;

use sipnab::output::relay_statistics::{
    FetchOrigin, format_relay_statistics_json, relay_rest_ok, relay_rest_outcome,
};
use sipnab::stats_vocab::{
    StatisticTier, StatisticValue, StatisticsOutcome, TieredStatistic, relay_reported,
    resolve_for_wire,
};

fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("REST body must parse: {e}\n{s}"))
}

/// A success payload gains `outcome: "ok"` and keeps every figure it had, so a
/// client that sees `ok` reads the same numbers the CLI would show.
#[test]
fn a_clean_answer_is_ok_and_keeps_its_figures() {
    let wire = resolve_for_wire(&relay_reported(&[(
        "npkts_relayed".to_string(),
        "9000".to_string(),
    )]));
    let payload = format_relay_statistics_json(
        &wire,
        "rtpengine at r",
        chrono::Utc::now(),
        FetchOrigin::Asked,
    );
    let v = parse(&relay_rest_ok(&payload));
    assert_eq!(v["outcome"], "ok");
    assert_eq!(v["relay"], "rtpengine at r");
    let stats = v["statistics"]
        .as_array()
        .expect("statistics survive the wrap");
    assert!(
        stats
            .iter()
            .any(|s| s["name"] == "npkts_relayed" && s["value"] == "9000")
    );
}

/// Each of the five classifications renders as 200-body content, with its own
/// wire token and whose-problem-it-is -- none collapse into another.
#[test]
fn every_classification_has_a_distinct_token_and_owner() {
    let mut seen = std::collections::BTreeSet::new();
    for outcome in StatisticsOutcome::all() {
        let v = parse(&relay_rest_outcome(outcome, "a detail sentence"));
        let token = v["outcome"].as_str().expect("outcome token").to_string();
        assert!(
            seen.insert(token.clone()),
            "classification tokens must be distinct; {token} repeated"
        );
        assert!(
            v["responsibility"].as_str().is_some_and(|r| !r.is_empty()),
            "each classification names whose problem it is: {token}"
        );
        assert_eq!(v["detail"], "a detail sentence");
    }
    assert_eq!(
        seen.len(),
        5,
        "all five ST-S4 classifications are representable"
    );
}

/// `not_permitted` is its own outcome and is never rendered as `unreachable` --
/// the file-backed-run refusal and the down-relay case send an operator to
/// different places (ST-S4).
#[test]
fn not_permitted_is_not_unreachable() {
    let np = parse(&relay_rest_outcome(
        StatisticsOutcome::NotPermitted,
        "file run",
    ));
    let un = parse(&relay_rest_outcome(
        StatisticsOutcome::Unreachable,
        "no answer",
    ));
    assert_eq!(np["outcome"], "not_permitted");
    assert_eq!(un["outcome"], "unreachable");
    assert_ne!(np["outcome"], un["outcome"]);
    assert_ne!(
        np["responsibility"], un["responsibility"],
        "the invocation's fault and the network's fault are owned differently"
    );
}

/// A classification body is NOT a clean answer: it has no `statistics` array
/// and its outcome is never `ok`, so a client cannot mistake a refusal for
/// data.
#[test]
fn a_classification_is_not_mistaken_for_data() {
    let v = parse(&relay_rest_outcome(
        StatisticsOutcome::NotConfigured,
        "name a relay",
    ));
    assert_ne!(v["outcome"], "ok");
    assert!(
        v.get("statistics").is_none(),
        "a refusal carries no statistics array"
    );
}

/// One relay-reported statistic in each of the three wire states, for the two
/// tests below.
fn three_states() -> Vec<TieredStatistic> {
    vec![
        TieredStatistic {
            name: "npkts_relayed".to_string(),
            value: StatisticValue::Counted("9000".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "counted_zero".to_string(),
            value: StatisticValue::Counted("0".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "rtpa_nlost".to_string(),
            value: StatisticValue::Refused("E68".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "never_asked".to_string(),
            value: StatisticValue::NotAsked,
            tier: StatisticTier::RelayReported,
        },
    ]
}

/// ST-S4 conditions 5 and 8, at the REST envelope: a PARTIAL answer -- some
/// names answered, one refused -- renders both a populated `statistics` array
/// AND a populated `refusals` array in one `ok` body, so a caller sees which
/// name the relay declined beside the ones it gave, never a whole-request loss.
///
/// The shipped rtpengine wide path cannot itself produce a refusal (rtpengine's
/// `statistics` reply carries only counters, and sipnab never sends rtpproxy the
/// per-name `G` that a partial `E68` needs -- ST9), so this pins the RENDERING a
/// probed or per-name path relies on, driven directly because that wire is
/// unreachable here.
#[test]
fn a_partial_answer_shows_present_and_refused_side_by_side() {
    let wire = resolve_for_wire(&three_states());
    let v = parse(&relay_rest_ok(&format_relay_statistics_json(
        &wire,
        "relay at 192.0.2.7",
        chrono::Utc::now(),
        FetchOrigin::Asked,
    )));
    assert_eq!(v["outcome"], "ok");
    let stats = v["statistics"].as_array().expect("a statistics array");
    let refusals = v["refusals"].as_array().expect("a refusals array");
    assert!(
        stats.iter().any(|s| s["name"] == "npkts_relayed"),
        "the name that answered is present: {v}"
    );
    let refused = refusals
        .iter()
        .find(|r| r["name"] == "rtpa_nlost")
        .expect("the refused name is listed with its code");
    assert_eq!(
        refused["code"], "E68",
        "the refusal carries the relay's own code, not a collapsed 'unavailable': {v}"
    );
    assert!(
        !stats.iter().any(|s| s["name"] == "rtpa_nlost"),
        "a refused name is never also rendered as a value: {v}"
    );
}

/// ST-S4 condition 9 at the REST envelope: zero, not-asked and refused stay
/// three states. A counted zero occupies a value key (`\"0\"`, never omitted); a
/// not-asked name is absent from BOTH arrays (omitted, never a zero); a refused
/// name is in `refusals` with its code and never a value. Collapsing any pair
/// is the exact failure ST-S1 forbids.
#[test]
fn zero_absent_and_refused_are_three_states_in_the_envelope() {
    let wire = resolve_for_wire(&three_states());
    let v = parse(&relay_rest_ok(&format_relay_statistics_json(
        &wire,
        "relay at 192.0.2.7",
        chrono::Utc::now(),
        FetchOrigin::Asked,
    )));
    let stats = v["statistics"].as_array().expect("a statistics array");
    let refusals = v["refusals"].as_array().expect("a refusals array");

    let zero = stats
        .iter()
        .find(|s| s["name"] == "counted_zero")
        .expect("a counted zero occupies a key");
    assert_eq!(
        zero["value"], "0",
        "a counted zero is the digits 0, not omitted"
    );

    assert!(
        !stats.iter().any(|s| s["name"] == "never_asked")
            && !refusals.iter().any(|r| r["name"] == "never_asked"),
        "a not-asked name is omitted from both arrays, never rendered as a zero: {v}"
    );

    assert!(
        refusals.iter().any(|r| r["name"] == "rtpa_nlost"),
        "a refused name is in refusals, distinct from an absent one: {v}"
    );
}
