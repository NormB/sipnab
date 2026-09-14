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
use sipnab::stats_vocab::{StatisticsOutcome, relay_reported, resolve_for_wire};

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
