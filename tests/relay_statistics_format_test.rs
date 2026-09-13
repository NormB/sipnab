// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7 / C1: the CLI's rendering of resolved relay statistics.
//!
//! The layout is the CLI's own, but the CONTENT is ST-S1's: the relay's own
//! name, the value uncoerced, the tier, when it was obtained, and refusals
//! carrying the relay's code. These gates hold the rendering to that content,
//! not to a byte-exact table -- a column width is not a contract.

#![cfg(feature = "full")]

use chrono::{DateTime, TimeZone, Utc};

use sipnab::output::relay_statistics::format_relay_statistics;
use sipnab::stats_vocab::{
    StatisticTier, StatisticValue, TieredStatistic, WireStatistics, relay_reported,
    resolve_for_wire,
};

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 13, 4, 5, 6).unwrap()
}

/// A counted figure renders with its name and value; the header names the
/// relay, the moment it was asked, and the tier once.
#[test]
fn a_counted_figure_renders_with_the_relays_own_name_and_value() {
    let wire = resolve_for_wire(&relay_reported(&[
        ("npkts_relayed".to_string(), "9000".to_string()),
        ("uptime".to_string(), "134".to_string()),
    ]));
    let text = format_relay_statistics(&wire, "rtpengine at 127.0.0.1:22222", at());

    assert!(
        text.contains("rtpengine at 127.0.0.1:22222"),
        "the relay is named:\n{text}"
    );
    assert!(
        text.contains("2026-09-13T04:05:06Z"),
        "the moment it was asked is shown:\n{text}"
    );
    assert!(
        text.contains("relay_reported"),
        "the tier is stated:\n{text}"
    );
    assert!(
        text.contains("npkts_relayed") && text.contains("9000"),
        "the counter and value:\n{text}"
    );
    assert!(
        text.contains("uptime") && text.contains("134"),
        "uptime survives as its digits:\n{text}"
    );
}

/// A uniform-tier table states the tier once, not on every row.
#[test]
fn a_uniform_tier_table_states_the_tier_once() {
    let wire = resolve_for_wire(&relay_reported(&[
        ("a".to_string(), "1".to_string()),
        ("b".to_string(), "2".to_string()),
        ("c".to_string(), "3".to_string()),
    ]));
    let text = format_relay_statistics(&wire, "rtpproxy at 127.0.0.1:22223", at());
    assert_eq!(
        text.matches("relay_reported").count(),
        1,
        "a table that is all one tier states it once, not per row:\n{text}"
    );
}

/// A mixed-tier table annotates each row, so no reading is unlabeled.
#[test]
fn a_mixed_tier_table_annotates_every_row() {
    let wire = resolve_for_wire(&[
        TieredStatistic {
            name: "relay_loss".to_string(),
            value: StatisticValue::Counted("5".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "capture_loss".to_string(),
            value: StatisticValue::Counted("3".to_string()),
            tier: StatisticTier::SipnabMeasured,
        },
    ]);
    let text = format_relay_statistics(&wire, "relay", at());
    assert!(
        text.contains("relay_reported"),
        "the relay tier is on its row:\n{text}"
    );
    assert!(
        text.contains("sipnab_measured"),
        "the measured tier is on its row:\n{text}"
    );
}

/// A refusal appears in a refusals section with its code, never as a value.
#[test]
fn a_refusal_is_shown_with_its_code_in_its_own_section() {
    let wire = resolve_for_wire(&[
        TieredStatistic {
            name: "npkts_rcvd".to_string(),
            value: StatisticValue::Counted("9000".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "rtpa_nlost".to_string(),
            value: StatisticValue::Refused("E68".to_string()),
            tier: StatisticTier::RelayReported,
        },
    ]);
    let text = format_relay_statistics(&wire, "relay", at());
    assert!(
        text.contains("Refused"),
        "there is a refusals section:\n{text}"
    );
    assert!(
        text.contains("rtpa_nlost") && text.contains("E68"),
        "the refused name and code:\n{text}"
    );
    // The refused name must not appear as a counted value line.
    let value_lines = text.lines().filter(|l| l.contains("rtpa_nlost")).count();
    assert_eq!(
        value_lines, 1,
        "the refused statistic appears once, in refusals only:\n{text}"
    );
}

/// A not-asked statistic appears nowhere -- omitted, never a zero.
#[test]
fn a_not_asked_statistic_is_absent_from_the_output() {
    let wire = resolve_for_wire(&[
        TieredStatistic {
            name: "present_one".to_string(),
            value: StatisticValue::Counted("1".to_string()),
            tier: StatisticTier::RelayReported,
        },
        TieredStatistic {
            name: "never_asked".to_string(),
            value: StatisticValue::NotAsked,
            tier: StatisticTier::RelayReported,
        },
    ]);
    let text = format_relay_statistics(&wire, "relay", at());
    assert!(
        !text.contains("never_asked"),
        "a not-asked statistic must not be rendered:\n{text}"
    );
    assert!(
        !text.contains(" 0"),
        "and it must not appear as a zero:\n{text}"
    );
}

/// An empty result says so rather than rendering an empty table.
#[test]
fn an_empty_result_says_the_relay_reported_nothing() {
    let text = format_relay_statistics(&WireStatistics::default(), "relay", at());
    assert!(
        text.to_lowercase().contains("nothing"),
        "an empty result must say the relay reported nothing:\n{text}"
    );
}
