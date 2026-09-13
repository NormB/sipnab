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
    let datagram = std::fs::read(FIXTURE).expect("the rtpengine statistics fixture is readable");
    // The fixture is the raw datagram: `<cookie> <bencode>`. The transport
    // (`framed_reply_body`) strips and validates the cookie before the parser
    // sees it, so this mirrors that -- feeding the parser the bencode alone,
    // exactly what `ControlClient::statistics` passes it. Feeding the whole
    // datagram was the ST2 defect: it hid that the live path double-stripped.
    let space = datagram
        .iter()
        .position(|b| *b == b' ')
        .expect("the fixture datagram has a cookie separator");
    let bencode = &datagram[space + 1..];
    match parse_statistics_reply(bencode).expect("the fixture is a valid statistics reply") {
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

/// The parser decodes the bencode ALONE; the cookie is the transport's job.
///
/// The regression for the double-strip: `ControlClient::statistics` hands over
/// a body whose cookie is already stripped, and the parser must decode it as
/// is. Feeding it the raw datagram -- cookie still attached -- must now FAIL,
/// because the cookie is not bencode; a parser that still stripped would parse
/// it and hide the very defect this pins.
#[test]
fn the_parser_decodes_bencode_alone_not_a_framed_datagram() {
    let datagram = std::fs::read(FIXTURE).expect("fixture readable");
    let space = datagram
        .iter()
        .position(|b| *b == b' ')
        .expect("a cookie separator");
    let bencode = &datagram[space + 1..];

    // What the transport yields: bencode alone. Parses.
    assert!(
        parse_statistics_reply(bencode).is_ok(),
        "the parser must accept the cookie-stripped bencode the client passes it"
    );
    // The raw datagram, cookie attached: must be refused, proving no re-strip.
    assert!(
        parse_statistics_reply(&datagram).is_err(),
        "the parser must NOT strip a cookie itself; a framed datagram is the \
         transport's to unwrap, and accepting one would re-hide the double-strip"
    );
}

/// Round-trip framing to parse: build a framed reply, strip as the transport
/// does, parse -- the whole shape the live path takes, without a socket.
#[test]
fn a_framed_reply_stripped_as_the_transport_does_then_parses_and_tiers() {
    let datagram = std::fs::read(FIXTURE).expect("fixture readable");
    // Re-frame with a different cookie to prove the parser cares only about the
    // bencode, not which cookie framed it.
    let space = datagram
        .iter()
        .position(|b| *b == b' ')
        .expect("a cookie separator");
    let bencode = datagram[space + 1..].to_vec();
    let reframed = [b"reframed99 ".as_slice(), &bencode].concat();

    let strip_at = reframed.iter().position(|b| *b == b' ').expect("separator");
    let body = &reframed[strip_at + 1..];
    let pairs = match parse_statistics_reply(body).expect("parses") {
        ControlReply::Statistics(p) => p,
        other => panic!("not statistics: {other:?}"),
    };
    let tiered = relay_reported(&pairs);
    assert!(
        tiered.len() >= 200,
        "the reframed reply tiers to the same counters"
    );
    assert!(
        tiered
            .iter()
            .all(|s| s.tier == StatisticTier::RelayReported),
        "all relay_reported"
    );
}

// ── ST7/C2: the per-call query reply is tiered the same way ────────────────

const QUERY_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/relay/rtpengine-query-12.5.1.bencode"
);

/// The per-call `query` reply -- captured live for one call -- flattens and
/// tiers exactly as the relay-wide `statistics` does, through the same path.
///
/// `ControlClient::call_statistics` sends `query` and hands the reply to the
/// same flattener and tierer C1 uses, so this proves that path against a real
/// per-call reply: every counter `relay_reported`, and the `totals` the relay
/// keeps per call present and distinct for RTP and RTCP.
#[test]
fn a_per_call_query_reply_tiers_as_relay_reported() {
    let datagram = std::fs::read(QUERY_FIXTURE).expect("the query fixture is readable");
    let space = datagram
        .iter()
        .position(|b| *b == b' ')
        .expect("the query fixture has a cookie separator");
    let pairs =
        match parse_statistics_reply(&datagram[space + 1..]).expect("the query reply parses") {
            ControlReply::Statistics(pairs) => pairs,
            other => panic!("the query reply did not flatten to statistics: {other:?}"),
        };
    let tiered = relay_reported(&pairs);
    assert!(
        tiered.len() >= 100,
        "a two-party call flattens to ~144 leaves; got {}",
        tiered.len()
    );
    assert!(
        tiered
            .iter()
            .all(|s| s.tier == StatisticTier::RelayReported),
        "every per-call counter is the relay's own claim"
    );
    // The per-call totals the relay keeps, present and kept apart by transport.
    match lookup(&tiered, "totals.RTP.packets") {
        StatisticValue::Counted(v) => assert!(v.chars().all(|c| c.is_ascii_digit())),
        other => panic!("totals.RTP.packets should be a counted figure, got {other:?}"),
    }
    assert!(
        matches!(
            lookup(&tiered, "totals.RTCP.packets"),
            StatisticValue::Counted(_)
        ),
        "RTCP totals are their own keys, not folded into RTP"
    );
    assert_ne!(
        lookup(&tiered, "totals.RTP.packets"),
        lookup(&tiered, "totals.RTP.no_such_field"),
        "a real per-call key and a fake one must not resolve alike"
    );
}
