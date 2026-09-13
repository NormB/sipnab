// SPDX-License-Identifier: MIT OR Apache-2.0

//! ST7: the machine-readable form of relay statistics agrees with the table.
//!
//! ST7 requires both a human-readable rendering and a machine-readable one that
//! AGREE -- a number that differs between `--json` and the table is a defect
//! nobody notices until it is quoted. These gates hold the JSON to the same
//! values the text renders, tier for tier, and hold the shape to ST-S1's rule:
//! a counted value carries its tier, a refusal is listed separately with the
//! relay's own code, and a comparison names both tiers and never sums them.

#![cfg(feature = "full")]

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use sipnab::output::relay_statistics::{
    FetchOrigin, format_relay_comparison_json, format_relay_stat_names_json,
    format_relay_statistics_json,
};
use sipnab::stats_vocab::{
    ComparedFigure, NameSource, StatisticTier, StatisticValue, TieredStatistic,
    compare_relay_and_sipnab, relay_reported, resolve_for_wire,
};

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 13, 4, 5, 6).unwrap()
}

fn parse(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("emitted JSON must parse: {e}\n{s}"))
}

// ── C1/C2: statistics ───────────────────────────────────────────────────────

/// The JSON names the relay, the moment, the tier, and every counted value --
/// the same figures the table shows.
#[test]
fn statistics_json_carries_the_same_values_as_the_table() {
    let wire = resolve_for_wire(&relay_reported(&[
        ("npkts_relayed".to_string(), "9000".to_string()),
        ("uptime".to_string(), "134".to_string()),
    ]));
    let v = parse(&format_relay_statistics_json(
        &wire,
        "rtpengine at 127.0.0.1:22222",
        at(),
        FetchOrigin::Asked,
    ));
    assert_eq!(v["relay"], "rtpengine at 127.0.0.1:22222");
    assert_eq!(v["obtained_at"], "2026-09-13T04:05:06Z");
    assert_eq!(v["origin"], "asked");
    let stats = v["statistics"].as_array().expect("statistics is an array");
    // Each counted figure appears with its name, value (uncoerced string) and tier.
    let relayed = stats
        .iter()
        .find(|s| s["name"] == "npkts_relayed")
        .expect("npkts_relayed present");
    assert_eq!(
        relayed["value"], "9000",
        "value uncoerced, as the relay gave it"
    );
    assert_eq!(relayed["tier"], "relay_reported");
    assert!(
        stats
            .iter()
            .any(|s| s["name"] == "uptime" && s["value"] == "134")
    );
}

/// A polled reading says so in the JSON and names the interval, mirroring the
/// table's `polled ... every Ns`.
#[test]
fn statistics_json_marks_a_poll_and_its_interval() {
    let wire = resolve_for_wire(&relay_reported(&[("a".to_string(), "1".to_string())]));
    let v = parse(&format_relay_statistics_json(
        &wire,
        "relay",
        at(),
        FetchOrigin::Polled { every_secs: 30 },
    ));
    assert_eq!(v["origin"], "polled");
    assert_eq!(v["interval_secs"], 30);
}

/// A refusal is listed separately with its code, never as a counted value
/// (ST-S1): `E68` and `E50` must not collapse into a number.
#[test]
fn statistics_json_lists_refusals_separately_with_their_code() {
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
    let v = parse(&format_relay_statistics_json(
        &wire,
        "relay",
        at(),
        FetchOrigin::Asked,
    ));
    let refusals = v["refusals"].as_array().expect("refusals array");
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["name"], "rtpa_nlost");
    assert_eq!(refusals[0]["code"], "E68");
    // And the refused name is NOT among the counted statistics.
    let stats = v["statistics"].as_array().unwrap();
    assert!(
        !stats.iter().any(|s| s["name"] == "rtpa_nlost"),
        "a refusal must not appear as a counted value"
    );
}

// ── C3: names ────────────────────────────────────────────────────────────────

/// The names JSON lists exactly the names, with the determination (listed vs
/// probed) and no values -- the machine form of C3's "what can I ask for".
#[test]
fn names_json_lists_names_with_the_source_and_no_values() {
    let names = vec!["npkts_relayed".to_string(), "uptime".to_string()];
    let v = parse(&format_relay_stat_names_json(
        &names,
        NameSource::Listed,
        "rtpengine at r:1",
        at(),
    ));
    assert_eq!(v["relay"], "rtpengine at r:1");
    assert_eq!(v["source"], "listed");
    let arr = v["names"].as_array().expect("names array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0], "npkts_relayed");
    // No values leaked: 9000 was a value in a stats table; here it must be absent.
    assert!(!format_relay_stat_names_json(&names, NameSource::Listed, "r", at()).contains("9000"));
}

/// A probed set says so, so it is not mistaken for a definitive enumeration.
#[test]
fn names_json_marks_a_probed_set() {
    let v = parse(&format_relay_stat_names_json(
        &["nrelayed".to_string()],
        NameSource::Probed,
        "rtpproxy at r:2",
        at(),
    ));
    assert_eq!(v["source"], "probed");
}

// ── C4: comparison ───────────────────────────────────────────────────────────

/// The comparison JSON shows both tiers, both raw values, a word verdict and
/// the note -- and never a summed or differenced figure (ST-S1).
#[test]
fn comparison_json_shows_both_tiers_and_a_word_verdict() {
    let c = compare_relay_and_sipnab(
        ComparedFigure {
            value: 9000,
            name: Some("totals.RTP.packets".to_string()),
            tier: StatisticTier::RelayReported,
        },
        ComparedFigure {
            value: 8994,
            name: None,
            tier: StatisticTier::SipnabMeasured,
        },
    );
    let v = parse(&format_relay_comparison_json(
        &c,
        "1-7@10.0.0.1",
        "rtpengine at r",
        at(),
    ));
    assert_eq!(v["call_id"], "1-7@10.0.0.1");
    let p = &v["packets"];
    assert_eq!(p["relay_reported"]["value"], 9000);
    assert_eq!(p["relay_reported"]["name"], "totals.RTP.packets");
    assert_eq!(p["sipnab_measured"]["value"], 8994);
    assert_eq!(p["verdict"], "differ");
    assert!(
        p["note"].as_str().is_some_and(|n| !n.is_empty()),
        "the caveat travels in the machine form too"
    );
    // No blended field: there is no single "difference"/"missed" number.
    assert!(p.get("difference").is_none() && p.get("missed").is_none());
}

/// A match renders the verdict word "match", agreeing with the table.
#[test]
fn comparison_json_match_agrees_with_the_table() {
    let c = compare_relay_and_sipnab(
        ComparedFigure {
            value: 500,
            name: Some("totals.RTP.packets".to_string()),
            tier: StatisticTier::RelayReported,
        },
        ComparedFigure {
            value: 500,
            name: None,
            tier: StatisticTier::SipnabMeasured,
        },
    );
    let v = parse(&format_relay_comparison_json(&c, "call-x", "relay", at()));
    assert_eq!(v["packets"]["verdict"], "match");
}
