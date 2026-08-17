// SPDX-License-Identifier: MIT OR Apache-2.0

//! Latency reaches a consumer, and "not measured" survives the trip.
//!
//! Jitter, packet loss and latency are the three numbers that decide whether a
//! call was acceptable. sipnab treated the first two as first-class and lost
//! the third: `round_trip_delay` was parsed out of the RTCP XR VoIP-metrics
//! block and never carried anywhere, so it reached the REST API not at all and
//! MCP barely. An operator asked "was this call acceptable?" could not answer
//! it without reading RTCP by hand.
//!
//! # The half that is easy to get wrong
//!
//! Adding the field is the easy half. The hard half is that **a missing
//! measurement and a measured zero are different facts**, and every surface
//! has to keep them different. A stream with clean jitter, no loss and no
//! round-trip figure is not a healthy stream — it is a stream with one
//! unanswered question, and 0 ms reads as the best possible network. That is
//! how a call which is unusable on delay alone (ITU-T G.114) gets reported as
//! fine.
//!
//! So these tests are mostly about ABSENCE: the key must be omitted, not
//! null, not zero.

//! # Why every item here is `native`-gated
//!
//! `StreamSummary` lives in `sipnab::output`, which is `#[cfg(feature =
//! "native")]`. The pre-push matrix builds combinations that EXCLUDE native
//! (`--no-default-features --features tls --tests`), and `--all-features`
//! cannot see those breaks because it always turns native on. This file caught
//! that the hard way: it compiled under every suite I ran and broke the tls arm
//! of the matrix, which is the same trap `tests/retention_limits_test.rs`
//! documents. Gate the ITEM, never the file — except where, as here, every item
//! genuinely needs the feature.

#![cfg(feature = "native")]

use sipnab::output::model::StreamSummary;
use sipnab::rtp::rtcp::RttSource;

/// Build a summary with no round trip, the way every consumer sees a stream
/// that nobody reported on.
fn unmeasured() -> serde_json::Value {
    let s = StreamSummary {
        ssrc: "0xDEADBEEF".into(),
        codec: Some("PCMU".into()),
        src: "10.0.0.1:20000".into(),
        dst: "10.0.0.2:30000".into(),
        packets: 500,
        jitter_ms: 2.0,
        loss_pct: 0.0,
        orphaned: false,
        associated_dialog: None,
        mos: 4.4,
        frame: None,
        round_trip_ms: None,
        round_trip_source: None,
    };
    serde_json::to_value(s).expect("serialize")
}

/// An unmeasured round trip is an ABSENT key, never zero.
///
/// The assertion is on the serialized JSON rather than the struct, because the
/// serialized form is what a client parses and `skip_serializing_if` is the
/// only thing standing between `None` and a `0` that would read as perfect.
#[test]
fn an_unmeasured_round_trip_is_absent_and_not_zero() {
    let v = unmeasured();

    assert!(
        v.get("round_trip_ms").is_none(),
        "an unmeasured round trip must omit the key entirely; a client reading \
         0 would score an unknown path as the best possible one: {v}"
    );
    assert!(
        v.get("round_trip_source").is_none(),
        "no measurement means no source to name: {v}"
    );

    // Anti-vacuity: the fields this is compared against ARE present, so the
    // absence above is about the round trip and not about a broken serialiser.
    assert!(v.get("jitter_ms").is_some() && v.get("loss_pct").is_some());
}

/// A measured round trip reaches the wire with its provenance attached.
///
/// The source travels beside the number because the two possible sources are
/// different measurements: an XR figure is the endpoint's own round trip
/// between the two RTP interfaces — the quantity G.114 is about — while an
/// SR-echo figure is anchored on the capture point and is the full round trip
/// only when the tap sits with the sender of the SR. An operator escalating on
/// 200 ms needs to know which they have.
#[test]
fn a_measured_round_trip_carries_its_provenance() {
    let base = StreamSummary {
        ssrc: "0xDEADBEEF".into(),
        codec: Some("PCMU".into()),
        src: "10.0.0.1:20000".into(),
        dst: "10.0.0.2:30000".into(),
        packets: 500,
        jitter_ms: 2.0,
        loss_pct: 0.0,
        orphaned: false,
        associated_dialog: None,
        mos: 4.4,
        frame: None,
        round_trip_ms: None,
        round_trip_source: None,
    };

    let xr = serde_json::to_value(
        base.clone()
            .with_round_trip(Some((90.0, RttSource::XrVoipMetrics))),
    )
    .expect("serialize");
    assert_eq!(xr["round_trip_ms"], 90.0);
    assert_eq!(xr["round_trip_source"], "xr_voip_metrics");

    let echo =
        serde_json::to_value(base.with_round_trip(Some((210.0, RttSource::SenderReportEcho))))
            .expect("serialize");
    assert_eq!(echo["round_trip_ms"], 210.0);
    assert_eq!(
        echo["round_trip_source"], "sender_report_echo",
        "the weaker derivation must not be reported under the name of the \
         endpoint's own measurement"
    );
}

/// A measured ZERO is reported as zero, not swallowed as "unknown".
///
/// The inverse of the first test and just as load-bearing. An endpoint that
/// reports 0 ms has told us something — on a loopback or a same-host leg it is
/// even plausible — and dropping it would put the key back in the state this
/// whole change exists to fix, only in the other direction.
#[test]
fn a_measured_zero_is_reported_rather_than_hidden() {
    let s = StreamSummary {
        ssrc: "0x1".into(),
        codec: None,
        src: "127.0.0.1:1".into(),
        dst: "127.0.0.1:2".into(),
        packets: 1,
        jitter_ms: 0.0,
        loss_pct: 0.0,
        orphaned: true,
        associated_dialog: None,
        mos: 4.4,
        frame: None,
        round_trip_ms: None,
        round_trip_source: None,
    }
    .with_round_trip(Some((0.0, RttSource::XrVoipMetrics)));

    let v = serde_json::to_value(s).expect("serialize");
    assert_eq!(
        v["round_trip_ms"], 0.0,
        "a reported 0 ms is a measurement and must survive: {v}"
    );
    assert!(v.get("round_trip_source").is_some());
}
