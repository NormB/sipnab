// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST2: every statistic rtpengine reports, tiered and kept by its own name.
//!
//! Driven against a REAL reply captured from the rtpengine in the harness
//! (12.5.1.31-1), not a hand-built dict, so the test exercises the names and
//! shape that version actually emits -- the ST-S2 inventory's "verify against
//! the harness, not from memory" carried into code.
//!
//! The fixture is a recorded control reply from a synthetic-call harness,
//! carrying no capture data and no PII; it is committed so the chain
//! `bencode -> parse_statistics_reply -> relay_reported` is proven without a
//! running relay.

#![cfg(feature = "full")]

use sipnab::relay::types::ControlReply;
use sipnab::rtpengine::control::parse_statistics_reply;
use sipnab::stats_vocab::{StatisticTier, StatisticValue, lookup, relay_reported};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/relay/rtpengine-statistics-12.5.1.bencode"
);

/// The fixture's pairs, as `parse_statistics_reply` produces them.
fn fixture_pairs() -> Vec<(String, String)> {
    let bytes = std::fs::read(FIXTURE).expect("the rtpengine statistics fixture is readable");
    match parse_statistics_reply(&bytes).expect("the fixture is a valid statistics reply") {
        ControlReply::Statistics(pairs) => pairs,
        other => panic!("the fixture did not parse as statistics: {other:?}"),
    }
}

/// Every pair a relay reports about itself is relay_reported, and counted.
#[test]
fn a_relays_own_statistics_are_every_one_relay_reported_and_counted() {
    let stats = relay_reported(&fixture_pairs());
    assert!(
        stats.len() >= 200,
        "the 12.5.1 fixture flattens to 251 leaf counters; got {} -- the \
         fixture or the flattener changed and this gate is reading the wrong \
         thing",
        stats.len()
    );
    for s in &stats {
        assert_eq!(
            s.tier,
            StatisticTier::RelayReported,
            "{} is a relay's own counter and must be relay_reported",
            s.name
        );
        assert!(
            matches!(s.value, StatisticValue::Counted(_)),
            "{} was reported by the relay, so it is a counted value, never \
             NotAsked or Refused",
            s.name
        );
    }
}

/// A known counter from this version resolves to a counted relay figure.
///
/// The name is the relay's own, flattened with dots, exactly as 12.5.1 emits
/// it. If rtpengine renames it, this fails rather than passing on a guess.
#[test]
fn a_known_counter_resolves_as_a_counted_relay_figure() {
    let stats = relay_reported(&fixture_pairs());
    let name = "statistics.totalstatistics.relayedpackets";
    match lookup(&stats, name) {
        StatisticValue::Counted(v) => {
            assert!(
                v.chars().all(|c| c.is_ascii_digit()),
                "{name} is a packet count; got {v:?}"
            );
        }
        other => panic!("{name} should be a counted relay figure, got {other:?}"),
    }
}

/// A name the relay did not report is NotAsked, not an invented value.
///
/// This is the three-state rule at the lookup: absent is absent, never a zero
/// and never the first value that happened to be in the set.
#[test]
fn a_name_the_relay_did_not_report_is_not_asked() {
    let stats = relay_reported(&fixture_pairs());
    assert_eq!(
        lookup(&stats, "statistics.totalstatistics.no_such_counter"),
        StatisticValue::NotAsked,
        "a counter this version does not emit must read as NotAsked"
    );
    // And the lookup is keyed on the NAME, not position: a real name and a
    // fake one must not return the same thing.
    assert_ne!(
        lookup(&stats, "statistics.totalstatistics.relayedpackets"),
        lookup(&stats, "statistics.totalstatistics.no_such_counter"),
        "lookup ignored the name -- a real and a fake counter answered alike"
    );
}

/// A value that is a string-typed integer survives uncoerced.
///
/// rtpengine sends `uptime` as a bencode STRING even though it is a whole
/// number. ST-S2 recorded this; the reading must carry the digits as text and
/// not have been parsed into a number and back.
#[test]
fn a_string_typed_integer_survives_as_its_digits() {
    let stats = relay_reported(&fixture_pairs());
    match lookup(&stats, "statistics.totalstatistics.uptime") {
        StatisticValue::Counted(v) => assert!(
            v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty(),
            "uptime should be digits carried as text, got {v:?}"
        ),
        other => panic!("uptime should be counted, got {other:?}"),
    }
}
