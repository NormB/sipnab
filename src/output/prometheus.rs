//! Prometheus exposition format metrics.
//!
//! Collects and formats sipnab operational metrics in the
//! [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
//! The HTTP endpoint that serves these metrics will be wired in a future
//! phase (behind the `api` feature gate with axum/tokio). This module
//! provides the data model and formatting only.

use std::collections::HashMap;
use std::fmt::Write;

// ── Public types ─────────────────────────────────────────────────────

/// Collected metrics for Prometheus exposition.
///
/// All counters use monotonically increasing values. Histograms store
/// raw observation values that are bucketed during formatting.
#[derive(Debug, Clone, Default)]
pub struct PrometheusMetrics {
    /// SIP dialog counts by state (e.g., `"completed"`, `"failed"`).
    pub dialogs_total: HashMap<String, u64>,
    /// SIP message counts by method (e.g., `"INVITE"`, `"REGISTER"`).
    pub messages_total: HashMap<String, u64>,
    /// SIP response counts by code class (e.g., `"2xx"`, `"4xx"`).
    pub responses_total: HashMap<String, u64>,
    /// Number of currently active RTP streams.
    pub rtp_streams_active: u64,
    /// RTP stream counts by status (e.g., `"established"`, `"orphaned"`).
    pub rtp_streams_total: HashMap<String, u64>,
    /// Total captured packets.
    pub capture_packets_total: u64,
    /// Packets currently buffered in the capture→processing queue (gauge).
    pub capture_queue_depth_packets: u64,
    /// Times a capture send had to block because the queue cap was reached.
    pub capture_backpressure_blocks_total: u64,
    /// Security alert counts by type (e.g., `"reg_flood"`, `"scanner"`).
    pub security_alerts_total: HashMap<String, u64>,
    /// Post-dial delay observations in seconds for histogram bucketing.
    pub pdd_histogram: Vec<f64>,
    /// MOS score observations for histogram bucketing.
    pub mos_histogram: Vec<f64>,
    /// Jitter observations in milliseconds for histogram bucketing.
    pub jitter_histogram: Vec<f64>,
    /// Packet loss percentage observations for histogram bucketing.
    pub loss_histogram: Vec<f64>,
    /// TCP/SIP reassembly timeout count.
    pub reassembly_timeouts_total: u64,
    /// Media diagnosis counts by type (e.g., `"one_way_audio"`, `"nat_mismatch"`).
    pub diagnosis_total: HashMap<String, u64>,
}

// ── Formatting ───────────────────────────────────────────────────────

/// Format all collected metrics in Prometheus exposition format.
///
/// Produces a complete text block with `# HELP`, `# TYPE`, and metric
/// lines. All metric names are prefixed with `sipnab_`.
///
/// Histogram metrics use cumulative bucket format with `_bucket`,
/// `_count`, and `_sum` suffixes.
pub fn format_metrics(metrics: &PrometheusMetrics) -> String {
    let mut out = String::with_capacity(4096);

    // ── Counters ─────────────────────────────────────────────────
    format_labeled_counter(
        &mut out,
        "sipnab_dialogs_total",
        "Total SIP dialogs by state",
        "state",
        &metrics.dialogs_total,
    );

    format_labeled_counter(
        &mut out,
        "sipnab_messages_total",
        "Total SIP messages by method",
        "method",
        &metrics.messages_total,
    );

    format_labeled_counter(
        &mut out,
        "sipnab_responses_total",
        "Total SIP responses by code class",
        "code",
        &metrics.responses_total,
    );

    // Active streams (gauge)
    write_help_type(
        &mut out,
        "sipnab_rtp_streams_active",
        "Active RTP streams",
        "gauge",
    );
    let _ = writeln!(
        out,
        "sipnab_rtp_streams_active {}",
        metrics.rtp_streams_active
    );
    out.push('\n');

    format_labeled_counter(
        &mut out,
        "sipnab_rtp_streams_total",
        "Total RTP streams by status",
        "status",
        &metrics.rtp_streams_total,
    );

    // Capture packets
    write_help_type(
        &mut out,
        "sipnab_capture_packets_total",
        "Total captured packets",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_packets_total {}",
        metrics.capture_packets_total
    );
    out.push('\n');

    // Capture queue (the dynamic, capped capture→processing buffer)
    write_help_type(
        &mut out,
        "sipnab_capture_queue_depth_packets",
        "Packets currently buffered between capture and processing",
        "gauge",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_queue_depth_packets {}",
        metrics.capture_queue_depth_packets
    );
    out.push('\n');
    write_help_type(
        &mut out,
        "sipnab_capture_backpressure_blocks_total",
        "Times a capture send blocked because the queue cap was reached",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_backpressure_blocks_total {}",
        metrics.capture_backpressure_blocks_total
    );
    out.push('\n');

    format_labeled_counter(
        &mut out,
        "sipnab_security_alerts_total",
        "Total security alerts by type",
        "type",
        &metrics.security_alerts_total,
    );

    // Reassembly timeouts
    write_help_type(
        &mut out,
        "sipnab_reassembly_timeouts_total",
        "Total TCP/SIP reassembly timeouts",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_reassembly_timeouts_total {}",
        metrics.reassembly_timeouts_total
    );
    out.push('\n');

    format_labeled_counter(
        &mut out,
        "sipnab_diagnosis_total",
        "Total media diagnosis findings by type",
        "type",
        &metrics.diagnosis_total,
    );

    // ── Histograms ───────────────────────────────────────────────
    format_histogram(
        &mut out,
        "sipnab_pdd_seconds",
        "Post-dial delay in seconds",
        &metrics.pdd_histogram,
        &[0.5, 1.0, 2.0, 3.0, 5.0, 10.0],
    );

    format_histogram(
        &mut out,
        "sipnab_mos",
        "Mean Opinion Score",
        &metrics.mos_histogram,
        &[1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5],
    );

    format_histogram(
        &mut out,
        "sipnab_jitter_ms",
        "RTP jitter in milliseconds",
        &metrics.jitter_histogram,
        &[5.0, 10.0, 20.0, 50.0, 100.0, 200.0],
    );

    format_histogram(
        &mut out,
        "sipnab_loss_percent",
        "RTP packet loss percentage",
        &metrics.loss_histogram,
        &[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0],
    );

    out
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Write `# HELP` and `# TYPE` lines.
fn write_help_type(out: &mut String, name: &str, help: &str, metric_type: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

/// Format a labeled counter family (e.g., `sipnab_dialogs_total{state="completed"} 150`).
fn format_labeled_counter(
    out: &mut String,
    name: &str,
    help: &str,
    label: &str,
    values: &HashMap<String, u64>,
) {
    if values.is_empty() {
        return;
    }

    write_help_type(out, name, help, "counter");

    // Sort keys for deterministic output
    let mut keys: Vec<&String> = values.keys().collect();
    keys.sort();

    for key in keys {
        let val = values[key];
        let escaped_key = escape_label_value(key);
        let _ = writeln!(out, "{name}{{{label}=\"{escaped_key}\"}} {val}");
    }
    out.push('\n');
}

/// Escape a label value for Prometheus exposition format.
///
/// Replaces `\` with `\\`, `"` with `\"`, and `\n` with `\\n` as required
/// by the Prometheus exposition format specification.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

/// Format a histogram with cumulative buckets, `_count`, and `_sum`.
fn format_histogram(
    out: &mut String,
    name: &str,
    help: &str,
    observations: &[f64],
    buckets: &[f64],
) {
    write_help_type(out, name, help, "histogram");

    let count = observations.len() as u64;
    let sum: f64 = observations.iter().sum();

    // Cumulative bucket counts
    for &le in buckets {
        let bucket_count = observations.iter().filter(|&&v| v <= le).count() as u64;
        let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {bucket_count}");
    }
    // +Inf bucket always equals total count
    let _ = writeln!(out, "{name}_bucket{{le=\"+Inf\"}} {count}");
    let _ = writeln!(out, "{name}_count {count}");
    let _ = writeln!(out, "{name}_sum {sum}");
    out.push('\n');
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metrics() -> PrometheusMetrics {
        let mut m = PrometheusMetrics::default();
        m.dialogs_total.insert("completed".to_string(), 150);
        m.dialogs_total.insert("failed".to_string(), 23);
        m.messages_total.insert("INVITE".to_string(), 200);
        m.messages_total.insert("BYE".to_string(), 180);
        m.responses_total.insert("2xx".to_string(), 300);
        m.responses_total.insert("4xx".to_string(), 50);
        m.rtp_streams_active = 12;
        m.rtp_streams_total.insert("established".to_string(), 100);
        m.rtp_streams_total.insert("orphaned".to_string(), 5);
        m.capture_packets_total = 50000;
        m.security_alerts_total.insert("reg_flood".to_string(), 3);
        m.reassembly_timeouts_total = 7;
        m.diagnosis_total.insert("one_way_audio".to_string(), 4);
        m.pdd_histogram = vec![0.3, 0.8, 1.2, 2.5, 0.4, 3.1, 0.9, 1.5, 0.6, 4.0];
        m.mos_histogram = vec![4.3, 3.8, 2.1, 4.0, 3.5, 1.5, 4.2, 3.0, 3.9, 2.8];
        m.jitter_histogram = vec![5.0, 12.0, 3.0, 25.0, 8.0, 45.0, 2.0, 15.0];
        m.loss_histogram = vec![0.0, 0.5, 1.2, 0.0, 3.5, 0.1, 0.0, 0.8];
        m
    }

    #[test]
    fn format_produces_valid_output() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        // Should not be empty
        assert!(!output.is_empty());

        // Every line should be valid Prometheus format
        for line in output.lines() {
            if line.is_empty() {
                continue;
            }
            assert!(
                line.starts_with('#') || line.starts_with("sipnab_"),
                "Unexpected line format: {line}"
            );
        }
    }

    #[test]
    fn all_metric_names_prefixed() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        for line in output.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                line.starts_with("sipnab_"),
                "Metric line missing sipnab_ prefix: {line}"
            );
        }
    }

    #[test]
    fn help_and_type_lines_present() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("# HELP sipnab_dialogs_total"));
        assert!(output.contains("# TYPE sipnab_dialogs_total counter"));
        assert!(output.contains("# HELP sipnab_rtp_streams_active"));
        assert!(output.contains("# TYPE sipnab_rtp_streams_active gauge"));
        assert!(output.contains("# HELP sipnab_pdd_seconds"));
        assert!(output.contains("# TYPE sipnab_pdd_seconds histogram"));
    }

    #[test]
    fn counter_values_correct() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains(r#"sipnab_dialogs_total{state="completed"} 150"#));
        assert!(output.contains(r#"sipnab_dialogs_total{state="failed"} 23"#));
        assert!(output.contains("sipnab_capture_packets_total 50000"));
        assert!(output.contains("sipnab_reassembly_timeouts_total 7"));
    }

    #[test]
    fn gauge_value_correct() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("sipnab_rtp_streams_active 12"));
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        // 5 observations: 0.3, 0.8, 1.5, 2.5, 4.0
        let metrics = PrometheusMetrics {
            pdd_histogram: vec![0.3, 0.8, 1.5, 2.5, 4.0],
            ..Default::default()
        };
        let output = format_metrics(&metrics);

        // Buckets for PDD: 0.5, 1.0, 2.0, 3.0, 5.0, 10.0
        // le=0.5: 1 (0.3)
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="0.5"} 1"#));
        // le=1.0: 2 (0.3, 0.8) — cumulative!
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="1"} 2"#));
        // le=2.0: 3 (0.3, 0.8, 1.5)
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="2"} 3"#));
        // le=3.0: 4 (0.3, 0.8, 1.5, 2.5)
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="3"} 4"#));
        // le=5.0: 5 (all)
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="5"} 5"#));
        // +Inf: 5
        assert!(output.contains(r#"sipnab_pdd_seconds_bucket{le="+Inf"} 5"#));
        // count and sum
        assert!(output.contains("sipnab_pdd_seconds_count 5"));
    }

    #[test]
    fn histogram_sum_correct() {
        let metrics = PrometheusMetrics {
            pdd_histogram: vec![1.0, 2.0, 3.0],
            ..Default::default()
        };
        let output = format_metrics(&metrics);

        // Sum should be 6.0
        assert!(output.contains("sipnab_pdd_seconds_sum 6"));
    }

    #[test]
    fn empty_metrics_produce_valid_output() {
        let metrics = PrometheusMetrics::default();
        let output = format_metrics(&metrics);

        // Should still produce histogram sections (with 0 counts)
        assert!(output.contains("sipnab_pdd_seconds_count 0"));
        assert!(output.contains("sipnab_mos_count 0"));
        assert!(output.contains("sipnab_capture_packets_total 0"));
        assert!(output.contains("sipnab_rtp_streams_active 0"));
    }

    #[test]
    fn labeled_counters_sorted_by_key() {
        let mut metrics = PrometheusMetrics::default();
        metrics.dialogs_total.insert("zombie".to_string(), 1);
        metrics.dialogs_total.insert("active".to_string(), 2);
        metrics.dialogs_total.insert("completed".to_string(), 3);

        let output = format_metrics(&metrics);

        // Find positions of each label — they should be in sorted order
        let pos_active = output.find(r#"state="active""#).expect("active label");
        let pos_completed = output
            .find(r#"state="completed""#)
            .expect("completed label");
        let pos_zombie = output.find(r#"state="zombie""#).expect("zombie label");

        assert!(
            pos_active < pos_completed && pos_completed < pos_zombie,
            "Labels should be sorted: active({pos_active}) < completed({pos_completed}) < zombie({pos_zombie})"
        );
    }

    #[test]
    fn mos_histogram_present() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("# HELP sipnab_mos"));
        assert!(output.contains("# TYPE sipnab_mos histogram"));
        assert!(output.contains("sipnab_mos_count 10"));
    }

    #[test]
    fn jitter_and_loss_histograms_present() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("# HELP sipnab_jitter_ms"));
        assert!(output.contains("sipnab_jitter_ms_count 8"));
        assert!(output.contains("# HELP sipnab_loss_percent"));
        assert!(output.contains("sipnab_loss_percent_count 8"));
    }

    #[test]
    fn diagnosis_and_security_counters() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains(r#"sipnab_security_alerts_total{type="reg_flood"} 3"#));
        assert!(output.contains(r#"sipnab_diagnosis_total{type="one_way_audio"} 4"#));
    }

    #[test]
    fn empty_counter_maps_omitted() {
        let metrics = PrometheusMetrics::default();
        let output = format_metrics(&metrics);

        // Empty HashMap counters should not produce HELP/TYPE lines
        assert!(!output.contains("# HELP sipnab_dialogs_total"));
        assert!(!output.contains("# HELP sipnab_security_alerts_total"));
    }
}
