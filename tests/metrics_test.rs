// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prometheus `/metrics` scrape tests (verification plan M3 — T3.4).
//!
//! Spawns the API against an RTP fixture (so RTP/MOS/jitter metrics are
//! populated) and asserts the exposition is well-formed: each expected metric
//! family declares the right `# TYPE`, sample lines parse, label sets are
//! correct, and every histogram has `_bucket`/`_count`/`_sum`.
#![cfg(feature = "api")]

use regex::Regex;

#[path = "support/server.rs"]
mod server;

use server::ApiServer;

/// One non-comment sample line: `name{labels}? value` (value may be -0, +Inf
/// handled within buckets). Validates the exposition grammar loosely.
///
/// # Returns
/// The compiled regex for a Prometheus sample line.
fn sample_re() -> Regex {
    Regex::new(r#"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+-?[0-9eE.+-]+(\s+[0-9]+)?$"#).unwrap()
}

/// Map of `family -> type` from the `# TYPE` lines.
///
/// # Arguments
/// * `body` — the raw `/metrics` exposition text.
///
/// # Returns
/// Metric family name mapped to its declared type string.
fn type_lines(body: &str) -> std::collections::HashMap<String, String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|rest| {
            let mut it = rest.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

/// The `/metrics` exposition declares every expected metric family with
/// the correct `# TYPE` (counter/gauge/histogram).
#[test]
fn metrics_expose_expected_families_with_types() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[]);
    let resp = srv.get("/metrics");
    assert_eq!(resp.status, 200);
    let body = resp.body;
    let types = type_lines(&body);

    let expected: &[(&str, &str)] = &[
        ("sipnab_dialogs_total", "counter"),
        ("sipnab_messages_total", "counter"),
        ("sipnab_rtp_streams_active", "gauge"),
        ("sipnab_rtp_streams_total", "counter"),
        ("sipnab_capture_packets_total", "counter"),
        ("sipnab_reassembly_timeouts_total", "counter"),
        // Capture quality: three losses with three different remedies, kept
        // under three names, plus the gauge that rolls them up for a
        // dashboard. Declared here so a rename cannot silently drop the one
        // block that says whether the rest of the scrape is complete.
        ("sipnab_capture_kernel_dropped_packets_total", "counter"),
        ("sipnab_capture_interface_dropped_packets_total", "counter"),
        ("sipnab_capture_invalid_timestamps_total", "counter"),
        // Frames a snaplen cut short. Not loss and not a decode failure: the
        // frames arrived, and the payload did not.
        ("sipnab_capture_snapped_frames_total", "counter"),
        // The only one here about the NETWORK rather than the capture: STUN
        // and TURN transactions that were sent and never answered, which is
        // the signal behind a one-way-audio complaint.
        ("sipnab_nat_unanswered_requests", "gauge"),
        // A relay torn down mid-call. A gauge for the same reason its
        // neighbour is: a late Refresh unsays it, which no counter could.
        ("sipnab_nat_lapsed_turn_allocations", "gauge"),
        // How much audio was on those relays when they were torn down. One
        // lapsed allocation carrying nothing and one carrying four calls read
        // identically without it.
        ("sipnab_nat_lapsed_turn_allocation_streams", "gauge"),
        // Two ICE agents that both claimed to be controlling. A gauge because
        // a later nomination on the same pair unsays the severity of it.
        ("sipnab_nat_ice_role_conflicts", "gauge"),
        ("sipnab_capture_quality_degraded", "gauge"),
        ("sipnab_pdd_seconds", "histogram"),
        ("sipnab_mos", "histogram"),
        ("sipnab_jitter_ms", "histogram"),
        ("sipnab_loss_percent", "histogram"),
    ];
    for (name, ty) in expected {
        assert_eq!(
            types.get(*name).map(String::as_str),
            Some(*ty),
            "metric family `{name}` should be declared as `{ty}`"
        );
    }
}

/// Every non-comment line matches the exposition grammar, and the expected
/// label sets (dialog state, method, stream status) appear for the RTP fixture.
#[test]
fn metrics_sample_lines_parse_and_labels_are_correct() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[]);
    let body = srv.get("/metrics").body;
    let re = sample_re();

    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(re.is_match(line), "malformed exposition line: {line:?}");
    }

    // Expected labels appear (RTP fixture has 2 streams, INVITEs, completed call).
    assert!(body.contains(r#"sipnab_dialogs_total{state="completed"}"#));
    assert!(body.contains(r#"sipnab_messages_total{method="INVITE"}"#));
    assert!(body.contains(r#"sipnab_rtp_streams_total{status="established"}"#));
    assert!(body.contains(r#"sipnab_rtp_streams_total{status="orphaned"}"#));
}

/// Each of the four histogram families carries `_bucket` lines (including
/// `+Inf`), `_count`, and `_sum`.
#[test]
fn histograms_have_bucket_count_and_sum() {
    let srv = ApiServer::spawn_with_pcap("tests/pcap-samples/sip-rtp-g711.pcap", &[]);
    let body = srv.get("/metrics").body;

    for h in [
        "sipnab_mos",
        "sipnab_jitter_ms",
        "sipnab_loss_percent",
        "sipnab_pdd_seconds",
    ] {
        assert!(
            body.contains(&format!("{h}_bucket{{le=")),
            "{h} missing buckets"
        );
        assert!(
            body.contains(&format!("{h}_bucket{{le=\"+Inf\"}}")),
            "{h} missing +Inf bucket"
        );
        assert!(body.contains(&format!("{h}_count")), "{h} missing _count");
        assert!(body.contains(&format!("{h}_sum")), "{h} missing _sum");
    }
}
