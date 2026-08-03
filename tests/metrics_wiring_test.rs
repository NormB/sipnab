// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `/metrics` counters must MOVE when the thing they name happens.
//!
//! `sipnab_capture_packets_total`, `sipnab_responses_total{code}` and
//! `sipnab_diagnosis_total{type}` were declared by the exposition formatter
//! and fed by nothing: the two scalars reported a hard `0` (indistinguishable
//! from a capture that has stopped receiving packets) and the labelled family
//! dropped out of the scrape entirely, so an alert rule over it went no-data.
//!
//! These tests scrape a live server after it has processed a fixture capture
//! and assert on the VALUES. Asserting that a metric name appears would have
//! passed against the unwired code — the names were always there.
#![cfg(feature = "api")]

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

/// The fixture with SIP signalling and RTP in both directions.
const RTP_PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Value of one exposition sample, looked up by its full `name{labels}` key.
///
/// # Arguments
/// * `body` — the raw `/metrics` exposition text.
/// * `key` — the sample key, e.g. `sipnab_responses_total{code="2xx"}`.
///
/// # Returns
/// The sample value, or `None` when the series is absent from the scrape.
fn sample(body: &str, key: &str) -> Option<f64> {
    body.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.trim().parse::<f64>().ok())
}

/// Same lookup, but fails the test with the surrounding family when the
/// series is missing — an absent series is the exact defect under test, so
/// the message has to say so rather than unwrapping an `Option`.
///
/// # Arguments
/// * `body` — the raw `/metrics` exposition text.
/// * `key` — the sample key to require.
///
/// # Returns
/// The sample value.
fn require(body: &str, key: &str) -> f64 {
    match sample(body, key) {
        Some(v) => v,
        None => {
            let family = key.split('{').next().unwrap_or(key);
            let seen: Vec<&str> = body.lines().filter(|l| l.contains(family)).collect();
            panic!(
                "series `{key}` is absent from the scrape — an alert rule over it \
                 goes no-data. Lines mentioning `{family}`: {seen:?}"
            );
        }
    }
}

/// `sipnab_capture_packets_total` counts the packets the capture actually
/// processed. A hard `0` here reads to an operator as "capture is dead".
#[test]
fn capture_packets_total_moves_with_the_capture() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    let packets = require(&body, "sipnab_capture_packets_total");
    assert!(
        packets > 0.0,
        "sipnab_capture_packets_total is {packets} after replaying {RTP_PCAP}: \
         the counter is not wired to the capture path, and an operator cannot \
         tell that from a capture that has genuinely stopped"
    );
}

/// `sipnab_responses_total{code}` counts SIP responses by class, and every
/// class is present even at zero so a rule over an unseen class has data.
#[test]
fn responses_total_counts_responses_by_class() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    let ok = require(&body, r#"sipnab_responses_total{code="2xx"}"#);
    assert!(
        ok > 0.0,
        "the fixture call completes, so the 2xx class must have counted \
         responses; got {ok}"
    );

    // Closed label set: every class is initialized, so `rate(...{code="5xx"})`
    // is 0 rather than no-data on a capture that saw no server errors.
    for class in ["1xx", "2xx", "3xx", "4xx", "5xx", "6xx"] {
        let key = format!(r#"sipnab_responses_total{{code="{class}"}}"#);
        require(&body, &key);
    }
}

/// `sipnab_diagnosis_total{type}` reports the media findings over the tracked
/// dialogs, with the full type set present so a panel is never blank.
#[test]
fn diagnosis_total_reports_media_findings() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    for kind in ["one_way_audio", "nat_mismatch", "no_media"] {
        let key = format!(r#"sipnab_diagnosis_total{{type="{kind}"}}"#);
        require(&body, &key);
    }

    let one_way = require(&body, r#"sipnab_diagnosis_total{type="one_way_audio"}"#);
    assert!(
        one_way > 0.0,
        "the fixture's dialog has media in one direction only (its other \
         stream is orphaned), so the one_way_audio finding must be counted; \
         got {one_way}"
    );
}

/// `sipnab_reassembly_timeouts_total` is exposed as a real counter reading
/// the process-wide reassembly-timeout total, not a literal zero.
///
/// The fixture cannot age an entry past the 30-second reassembly TTL inside a
/// test, so the value is legitimately `0` here; that the counter MOVES is
/// pinned in `metrics_counters_test.rs` against the sweep itself.
#[test]
fn reassembly_timeouts_total_is_exposed() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    assert!(
        body.contains("# TYPE sipnab_reassembly_timeouts_total counter"),
        "reassembly timeouts must stay declared as a counter"
    );
    let v = require(&body, "sipnab_reassembly_timeouts_total");
    assert_eq!(v, 0.0, "the fixture times out no reassembly");
}

/// The capture-quality block reaches the scrape as four separate series.
///
/// Before this the three counters existed as process globals and were warned
/// about on stderr, and no scrape carried them: a dashboard could show a
/// healthy `sipnab_capture_packets_total` for a run that had dropped a third
/// of the wire, with nothing on the same page to say so.
///
/// A file replay drops nothing, so the values are legitimately zero here.
/// Zero is the point: an absent series makes an alert rule no-data forever,
/// which reads the same as "fine" on a dashboard and is not.
#[test]
fn capture_quality_reaches_the_scrape_as_separate_series() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    for family in [
        "sipnab_capture_kernel_dropped_packets_total",
        "sipnab_capture_interface_dropped_packets_total",
        "sipnab_capture_invalid_timestamps_total",
    ] {
        assert!(
            body.contains(&format!("# TYPE {family} counter")),
            "{family} must be declared as a counter"
        );
        assert_eq!(
            require(&body, family),
            0.0,
            "{family} must read 0 for a file replay, which has no capture ring"
        );
    }

    assert!(
        body.contains("# TYPE sipnab_capture_quality_degraded gauge"),
        "the roll-up must be a gauge — it is a state, not a running total"
    );
    assert_eq!(
        require(&body, "sipnab_capture_quality_degraded"),
        0.0,
        "nothing was observed wrong replaying {RTP_PCAP}, so the roll-up must \
         be 0"
    );
}

/// The two drop counters are never collapsed into one series.
///
/// The remedies disagree — a bigger `-B`/`--buffer` answers a kernel-ring
/// drop and can do nothing at all about an interface drop — so a single
/// "dropped" series would send an operator to the wrong fix half the time.
/// This is a naming contract, asserted on the wire where an alert rule reads
/// it rather than in the struct.
#[test]
fn kernel_and_interface_drops_are_never_one_series() {
    let srv = ApiServer::spawn_with_pcap(RTP_PCAP, &[]);
    let body = srv.get("/metrics").body;

    assert!(
        sample(&body, "sipnab_capture_kernel_dropped_packets_total").is_some()
            && sample(&body, "sipnab_capture_interface_dropped_packets_total").is_some(),
        "both drop counters must be present under their own names"
    );
    for collapsed in [
        "sipnab_capture_dropped_packets_total",
        "sipnab_capture_drops_total",
        "sipnab_capture_lost_packets_total",
    ] {
        assert!(
            !body.contains(collapsed),
            "`{collapsed}` sums losses with different remedies into one series"
        );
    }
}
