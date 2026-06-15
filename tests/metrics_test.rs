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
fn sample_re() -> Regex {
    Regex::new(r#"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})?\s+-?[0-9eE.+-]+(\s+[0-9]+)?$"#).unwrap()
}

/// Map of `family -> type` from the `# TYPE` lines.
fn type_lines(body: &str) -> std::collections::HashMap<String, String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("# TYPE "))
        .filter_map(|rest| {
            let mut it = rest.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .collect()
}

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
