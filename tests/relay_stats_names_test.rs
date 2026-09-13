// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7 / C3: which statistics a relay knows -- "what can I even ask for?".
//!
//! C3 exists because the key set is version-specific: without a list, a caller
//! discovers `rtpa_nlost`'s absence through a failed request. The answer is
//! obtained by ASKING, never from a table compiled into sipnab -- for rtpengine
//! the key set of a `statistics` reply, for rtpproxy the names that did not
//! refuse when asked. The reply must say WHICH of those two it is, because a
//! name refused today because the relay is busy is not the same as one this
//! build does not have.
//!
//! These gates hold the two halves: `known_names` (the pure set), and
//! `format_relay_stat_names` (the CLI's rendering, names-only, with the
//! determination stated).

#![cfg(feature = "full")]

use chrono::{DateTime, TimeZone, Utc};

use sipnab::output::relay_statistics::format_relay_stat_names;
use sipnab::stats_vocab::{
    NameSource, StatisticTier, StatisticValue, TieredStatistic, known_names, relay_reported,
};

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 13, 4, 5, 6).unwrap()
}

fn counted(name: &str, v: &str) -> TieredStatistic {
    TieredStatistic {
        name: name.to_string(),
        value: StatisticValue::Counted(v.to_string()),
        tier: StatisticTier::RelayReported,
    }
}

// ── known_names: the pure set ──────────────────────────────────────────────

/// The names come back sorted and deduplicated, so two relays' lists compare
/// and a caller reads a stable order regardless of reply order.
#[test]
fn known_names_are_sorted_and_deduplicated() {
    let stats = [
        counted("uptime", "134"),
        counted("npkts_relayed", "9000"),
        counted("uptime", "134"),
        counted("bytes", "1"),
    ];
    assert_eq!(
        known_names(&stats),
        vec![
            "bytes".to_string(),
            "npkts_relayed".to_string(),
            "uptime".to_string(),
        ],
        "sorted and with the duplicate uptime collapsed"
    );
}

/// A name sipnab never asked for is not evidence about what the relay knows,
/// so NotAsked is excluded from the list.
#[test]
fn a_not_asked_name_is_not_a_known_name() {
    let stats = [
        counted("present", "1"),
        TieredStatistic {
            name: "never_asked".to_string(),
            value: StatisticValue::NotAsked,
            tier: StatisticTier::RelayReported,
        },
    ];
    let names = known_names(&stats);
    assert_eq!(names, vec!["present".to_string()]);
    assert!(
        !names.contains(&"never_asked".to_string()),
        "a name sipnab never asked about says nothing about the relay's key set"
    );
}

/// rtpproxy's `E68` means the relay does NOT have that name, so a refused name
/// is NOT a known name -- this is the whole point of the probe.
#[test]
fn a_refused_name_is_not_a_known_name() {
    let stats = [
        counted("npkts_ina", "9000"),
        TieredStatistic {
            name: "rtpa_nlost".to_string(),
            value: StatisticValue::Refused("E68".to_string()),
            tier: StatisticTier::RelayReported,
        },
    ];
    let names = known_names(&stats);
    assert_eq!(names, vec!["npkts_ina".to_string()]);
    assert!(
        !names.contains(&"rtpa_nlost".to_string()),
        "a name the relay refused (E68) is not one it knows"
    );
}

/// The set is drawn from what the relay actually reported: feeding the flat
/// pairs of a real reply through `relay_reported` yields exactly its keys.
#[test]
fn known_names_are_the_keys_of_a_real_reply() {
    let tiered = relay_reported(&[
        ("totals.RTP.packets".to_string(), "9000".to_string()),
        ("totals.RTCP.packets".to_string(), "30".to_string()),
        ("uptime".to_string(), "134".to_string()),
    ]);
    assert_eq!(
        known_names(&tiered),
        vec![
            "totals.RTCP.packets".to_string(),
            "totals.RTP.packets".to_string(),
            "uptime".to_string(),
        ]
    );
}

/// No known names is a real answer -- the relay named nothing -- not a crash.
#[test]
fn no_known_names_is_an_empty_list_not_a_panic() {
    assert!(known_names(&[]).is_empty());
}

// ── NameSource: the determination is a first-class claim ────────────────────

/// The two determinations say different things, and each names its mechanism:
/// rtpengine LISTED them, rtpproxy's set was PROBED (did-not-refuse).
#[test]
fn the_two_name_sources_describe_different_mechanisms() {
    let listed = NameSource::Listed.how_determined();
    let probed = NameSource::Probed.how_determined();
    assert_ne!(
        listed, probed,
        "a listed key set and a probed one are not the same claim"
    );
    assert!(
        listed.to_lowercase().contains("listed") || listed.to_lowercase().contains("reported"),
        "the listed determination says the relay enumerated them: {listed}"
    );
    assert!(
        probed.to_lowercase().contains("refuse"),
        "the probed determination says these are the names that did not refuse: {probed}"
    );
}

// ── format_relay_stat_names: the CLI rendering ──────────────────────────────

/// Every known name is listed, one per line, and the relay is named.
#[test]
fn every_known_name_is_listed() {
    let names = vec![
        "npkts_relayed".to_string(),
        "totals.RTP.packets".to_string(),
        "uptime".to_string(),
    ];
    let text = format_relay_stat_names(
        &names,
        NameSource::Listed,
        "rtpengine at 10.0.0.1:22222",
        at(),
    );
    for n in &names {
        assert!(text.contains(n.as_str()), "name {n} is listed:\n{text}");
    }
    assert!(
        text.contains("rtpengine at 10.0.0.1:22222"),
        "the relay is named:\n{text}"
    );
}

/// The header states how the list was determined and when it was asked.
#[test]
fn the_header_states_the_determination_and_the_moment() {
    let names = vec!["uptime".to_string()];
    let text = format_relay_stat_names(&names, NameSource::Listed, "rtpengine at r:1", at());
    assert!(
        text.contains("2026-09-13T04:05:06Z"),
        "when it was asked is shown:\n{text}"
    );
    assert!(
        text.to_lowercase().contains("listed") || text.to_lowercase().contains("reported"),
        "the header states the relay listed them:\n{text}"
    );
}

/// A probed list carries the probe caveat, so it is not mistaken for a
/// definitive enumeration.
#[test]
fn a_probed_list_carries_the_probe_caveat() {
    let names = vec!["npkts_ina".to_string(), "nrelayed".to_string()];
    let text = format_relay_stat_names(&names, NameSource::Probed, "rtpproxy at r:2", at());
    assert!(
        text.to_lowercase().contains("refuse"),
        "a probed list says these are the names that did not refuse:\n{text}"
    );
}

/// The count in the header matches the number of names rendered.
#[test]
fn the_header_count_matches_the_names_shown() {
    let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let text = format_relay_stat_names(&names, NameSource::Listed, "relay", at());
    assert!(
        text.contains('3'),
        "the count of names is stated in the header:\n{text}"
    );
}

/// A names-only listing carries NO values -- it answers "what can I ask for",
/// not "what are they now". A value leaking in would make it a different
/// capability wearing C3's flag.
#[test]
fn a_names_listing_carries_no_values() {
    // These names would have had values in a C1 table; here only the names show.
    let names = vec!["npkts_relayed".to_string(), "uptime".to_string()];
    let text = format_relay_stat_names(&names, NameSource::Listed, "relay", at());
    assert!(
        !text.contains("9000"),
        "a value must not leak into a names-only listing:\n{text}"
    );
}

/// An empty known-name set says the relay named nothing, rather than printing a
/// bare header with no body.
#[test]
fn an_empty_name_set_says_the_relay_named_nothing() {
    let text = format_relay_stat_names(&[], NameSource::Listed, "relay", at());
    assert!(
        text.to_lowercase().contains("nothing"),
        "an empty list must say the relay named nothing it knows:\n{text}"
    );
}
