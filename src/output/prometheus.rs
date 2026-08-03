// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prometheus exposition format metrics.
//!
//! Collects and formats sipnab operational metrics in the
//! [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
//! This module provides the data model and formatting only; the metrics
//! are served over HTTP by the REST API's `/metrics` endpoint
//! (`super::api`, feature `api`) and by the standalone
//! `super::prometheus_server`.

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
    /// The three ways this run's analysis can be incomplete or mistimed.
    pub capture_quality: CaptureQuality,
}

/// How much of the wire the analysis actually saw, and whether its clock can
/// be believed.
///
/// Three separate counters rather than one "lost" total, because the three
/// have three different remedies and an operator who reads a sum is pushed
/// toward the wrong one:
///
/// * `kernel_dropped_packets` — the capture ring was full when the packet
///   arrived. Raise `-B`/`--buffer`, narrow the BPF filter, or cut
///   `--snaplen`.
/// * `interface_dropped_packets` — the NIC or its driver discarded the packet
///   before libpcap ever saw it. **A bigger buffer cannot recover these**;
///   the link is faster than the host can accept, so the answer is at the
///   NIC, the driver, or the mirror configuration.
/// * `invalid_timestamps` — the pcap timestamp was unusable and the packet
///   was stamped with the wall clock instead. Nothing was lost, but every
///   timing figure derived from that run (post-dial delay, RFC 3550 jitter,
///   MOS, call duration) is unreliable.
///
/// Reported on every machine-readable surface — `/v1/stats`, the MCP `stats`
/// tool and the Prometheus exposition. The three counters existed for some
/// time before that and reached only a `warn` line on stderr, which neither
/// an agent driving the MCP tools nor a dashboard ever reads: a run could
/// drop a third of the wire and every machine-readable answer about it looked
/// exactly like a clean one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptureQuality {
    /// Packets the kernel discarded because the capture ring was full
    /// (`ps_drop`). Non-zero means dialogs may be missing messages and RTP
    /// loss figures overstate what was on the wire.
    pub kernel_dropped_packets: u64,
    /// Packets the interface or its driver discarded before libpcap saw them
    /// (`ps_ifdrop`). Counted apart from the kernel drops because raising the
    /// buffer does nothing for these.
    pub interface_dropped_packets: u64,
    /// Packets whose pcap timestamp was corrupt and were stamped with the
    /// wall clock instead. Non-zero means the run's timing analysis is
    /// unreliable even where no packet was lost.
    pub invalid_timestamps: u64,
}

impl CaptureQuality {
    /// Read the process-global capture counters.
    ///
    /// Zero on a build without the `native` feature, which has no live
    /// capture and therefore no ring to overflow — reported as "nothing
    /// observed" rather than omitted, so the block's key set does not change
    /// between builds.
    #[must_use]
    pub fn current() -> Self {
        #[cfg(feature = "native")]
        {
            let (kernel_dropped_packets, interface_dropped_packets) =
                crate::capture::live::kernel_drop_counts();
            Self {
                kernel_dropped_packets,
                interface_dropped_packets,
                invalid_timestamps: crate::capture::live::INVALID_PCAP_TIMESTAMPS
                    .load(std::sync::atomic::Ordering::Relaxed),
            }
        }
        #[cfg(not(feature = "native"))]
        {
            Self::default()
        }
    }

    /// Whether anything was observed to be wrong with this capture: `true`
    /// when any of the three counters has moved.
    ///
    /// Deliberately not called "complete". `false` means **nothing was
    /// observed to go wrong**, not that the capture provably saw every
    /// packet: loss upstream of the capture point — an oversubscribed SPAN
    /// port, a tap that never mirrored one direction, a filter that excluded
    /// the traffic — is invisible to every counter here. The claim is only
    /// ever made in the `true` direction, which is the direction there is
    /// evidence for.
    #[must_use]
    pub fn degraded(&self) -> bool {
        self.kernel_dropped_packets > 0
            || self.interface_dropped_packets > 0
            || self.invalid_timestamps > 0
    }
}

/// SIP response classes, as label values for `sipnab_responses_total{code}`.
///
/// Closed set (RFC 3261 §7.2), so a scrape can initialize every one of them
/// to zero. That matters more than it looks: an empty labelled family is
/// omitted from the exposition entirely, and a rule over a series that does
/// not exist is no-data, not zero — an alert on "5xx responses appeared"
/// would never fire on a proxy that had been healthy up to that point.
pub const RESPONSE_CLASSES: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "6xx"];

/// Media-diagnosis findings counted by `sipnab_diagnosis_total{type}`, also
/// zero-initialized on every scrape for the reason above.
pub const DIAGNOSIS_TYPES: [&str; 3] = ["one_way_audio", "nat_mismatch", "no_media"];

impl PrometheusMetrics {
    /// Start a scrape: process-wide counters loaded, closed label sets
    /// initialized to zero.
    ///
    /// Every collector must build its metrics from here rather than from
    /// [`Default`]. The counters fed by the data plane — captured packets,
    /// reassembly timeouts, security alerts — live in the modules that own
    /// those events, and a collector that skipped this step would publish a
    /// literal `0` for a capture that was in fact running: the exact defect
    /// that made `sipnab_capture_packets_total` unusable.
    ///
    /// # Returns
    ///
    /// Metrics carrying the process counters, with the store-derived fields
    /// left empty for the caller to fill.
    pub fn for_scrape() -> Self {
        let mut m = Self {
            capture_packets_total: crate::capture::captured_packets(),
            reassembly_timeouts_total: crate::capture::reassembly::reassembly_timeouts(),
            capture_quality: CaptureQuality::current(),
            ..Self::default()
        };
        for class in RESPONSE_CLASSES {
            m.responses_total.insert(class.to_string(), 0);
        }
        for kind in DIAGNOSIS_TYPES {
            m.diagnosis_total.insert(kind.to_string(), 0);
        }
        for (kind, count) in crate::security::alerts_by_type() {
            m.security_alerts_total.insert(kind, count);
        }
        m
    }

    /// Count one SIP response under its class label.
    ///
    /// # Arguments
    ///
    /// * `status_code` — the response's status code (100–699).
    ///
    /// # Side effects
    ///
    /// Bumps `responses_total` for the class; a code outside 1xx–6xx (which
    /// the parser does not produce) is ignored rather than inventing a
    /// label.
    pub fn record_response(&mut self, status_code: u16) {
        let Some(class) = RESPONSE_CLASSES.get(usize::from(status_code / 100).wrapping_sub(1))
        else {
            return;
        };
        *self
            .responses_total
            .entry((*class).to_string())
            .or_insert(0) += 1;
    }

    /// Count one dialog's media diagnosis, one increment per finding.
    ///
    /// A dialog with two findings counts under both — the metric answers
    /// "how many calls show this problem", per problem.
    ///
    /// # Arguments
    ///
    /// * `diagnosis` — the media diagnosis computed for one dialog.
    ///
    /// # Side effects
    ///
    /// Bumps `diagnosis_total` for each flag the diagnosis raised.
    pub fn record_media_diagnosis(&mut self, diagnosis: &crate::rtp::diagnosis::MediaDiagnosis) {
        // Destructured rather than field-tested so that adding a flag to
        // `MediaDiagnosis` without deciding whether it is counted here fails
        // to compile, instead of quietly never appearing in the metric.
        let crate::rtp::diagnosis::MediaDiagnosis {
            one_way_audio,
            nat_mismatch,
            no_media,
            sdp_media: _,
            actual_media: _,
            hints: _,
            codec_asymmetry: _,
            ptime_asymmetry: _,
            payload_type_asymmetry: _,
            duration_asymmetry: _,
            late_media: _,
        } = diagnosis;
        for (raised, kind) in [
            (one_way_audio, "one_way_audio"),
            (nat_mismatch, "nat_mismatch"),
            (no_media, "no_media"),
        ] {
            if *raised {
                *self.diagnosis_total.entry(kind.to_string()).or_insert(0) += 1;
            }
        }
    }
}

// ── Formatting ───────────────────────────────────────────────────────

/// Format all collected metrics in Prometheus exposition format.
///
/// Produces a complete text block with `# HELP`, `# TYPE`, and metric
/// lines. All metric names are prefixed with `sipnab_`.
///
/// Histogram metrics use cumulative bucket format with `_bucket`,
/// `_count`, and `_sum` suffixes. Labeled counter families with no
/// entries are omitted entirely; scalar counters/gauges and histogram
/// sections are always emitted (with zero values). On native builds the
/// `sipnab_kill_responses_sent_total{mode=...}` counters are read from
/// the process-isolation module as a side input. Pure otherwise —
/// nothing is served or written here.
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

    // Capture quality. Three counters, never a sum: a bigger ring buffer
    // fixes kernel drops and does nothing for interface drops, and a corrupt
    // timestamp loses no packet at all — it invalidates the timing figures.
    // A single "lost" series would point an operator at the wrong remedy.
    write_help_type(
        &mut out,
        "sipnab_capture_kernel_dropped_packets_total",
        "Packets the kernel discarded because the capture ring was full",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_kernel_dropped_packets_total {}",
        metrics.capture_quality.kernel_dropped_packets
    );
    out.push('\n');
    write_help_type(
        &mut out,
        "sipnab_capture_interface_dropped_packets_total",
        "Packets the interface or driver discarded before libpcap saw them",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_interface_dropped_packets_total {}",
        metrics.capture_quality.interface_dropped_packets
    );
    out.push('\n');
    write_help_type(
        &mut out,
        "sipnab_capture_invalid_timestamps_total",
        "Packets whose pcap timestamp was unusable and were stamped with the wall clock",
        "counter",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_invalid_timestamps_total {}",
        metrics.capture_quality.invalid_timestamps
    );
    out.push('\n');
    // Derivable from the three counters above, and published anyway: this is
    // the single series a dashboard or an alert rule reads to know whether
    // the rest of the scrape describes the whole capture or part of it.
    write_help_type(
        &mut out,
        "sipnab_capture_quality_degraded",
        "1 when packets were dropped or timestamps were invalid, 0 when nothing was observed wrong",
        "gauge",
    );
    let _ = writeln!(
        out,
        "sipnab_capture_quality_degraded {}",
        u8::from(metrics.capture_quality.degraded())
    );
    out.push('\n');

    format_labeled_counter(
        &mut out,
        "sipnab_security_alerts_total",
        "Total security alerts by type",
        "type",
        &metrics.security_alerts_total,
    );

    // Scanner-kill responses sent, split by how the source was set: `raw`
    // (source-spoofed via a raw socket) vs `ephemeral` (sipnab's own port).
    // Alert on an unexpected `ephemeral` count to catch a silent fallback.
    #[cfg(all(not(target_arch = "wasm32"), feature = "native"))]
    {
        let (raw, ephemeral) = crate::process_isolation::kill_responses_sent();
        write_help_type(
            &mut out,
            "sipnab_kill_responses_sent_total",
            "Total scanner-kill responses sent, by source mode",
            "counter",
        );
        let _ = writeln!(
            out,
            "sipnab_kill_responses_sent_total{{mode=\"raw\"}} {raw}"
        );
        let _ = writeln!(
            out,
            "sipnab_kill_responses_sent_total{{mode=\"ephemeral\"}} {ephemeral}"
        );
        out.push('\n');
    }

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

/// Append `# HELP <name> <help>` and `# TYPE <name> <metric_type>` lines
/// to `out`.
fn write_help_type(out: &mut String, name: &str, help: &str, metric_type: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {metric_type}");
}

/// Format a labeled counter family (e.g., `sipnab_dialogs_total{state="completed"} 150`).
///
/// Appends nothing when `values` is empty; otherwise writes HELP/TYPE,
/// one line per key in sorted order (label values escaped), and a blank
/// separator line.
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
///
/// Each `le` bucket counts observations `<= le` (cumulative); the `+Inf`
/// bucket always equals the total count. Bucket boundaries render via
/// Rust float `Display`, so `1.0` appears as `le="1"`. Appends the
/// section to `out` followed by a blank line.
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

/// Tests for exposition-format output: prefixes, HELP/TYPE lines,
/// counter/gauge values, cumulative buckets, and label sorting/escaping.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a metrics struct with every field populated.
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

    /// Every non-empty line is a comment or a `sipnab_` metric line.
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

    /// Every metric line starts with the `sipnab_` prefix.
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

    /// HELP/TYPE pairs exist for counter, gauge, and histogram families.
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

    /// Labeled and scalar counters carry the exact sample values.
    #[test]
    fn counter_values_correct() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains(r#"sipnab_dialogs_total{state="completed"} 150"#));
        assert!(output.contains(r#"sipnab_dialogs_total{state="failed"} 23"#));
        assert!(output.contains("sipnab_capture_packets_total 50000"));
        assert!(output.contains("sipnab_reassembly_timeouts_total 7"));
    }

    /// The active-streams gauge carries its sample value.
    #[test]
    fn gauge_value_correct() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("sipnab_rtp_streams_active 12"));
    }

    /// PDD buckets count cumulatively up through `+Inf` == total count.
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

    /// The `_sum` line equals the sum of all observations.
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

    /// Default metrics still emit scalar counters and zero-count
    /// histograms.
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

    /// Label values render in sorted key order for deterministic output.
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

    /// The MOS histogram section is present with the sample count.
    #[test]
    fn mos_histogram_present() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("# HELP sipnab_mos"));
        assert!(output.contains("# TYPE sipnab_mos histogram"));
        assert!(output.contains("sipnab_mos_count 10"));
    }

    /// Jitter and loss histogram sections are present with sample counts.
    #[test]
    fn jitter_and_loss_histograms_present() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains("# HELP sipnab_jitter_ms"));
        assert!(output.contains("sipnab_jitter_ms_count 8"));
        assert!(output.contains("# HELP sipnab_loss_percent"));
        assert!(output.contains("sipnab_loss_percent_count 8"));
    }

    /// Security-alert and diagnosis counters carry their typed labels.
    #[test]
    fn diagnosis_and_security_counters() {
        let metrics = sample_metrics();
        let output = format_metrics(&metrics);

        assert!(output.contains(r#"sipnab_security_alerts_total{type="reg_flood"} 3"#));
        assert!(output.contains(r#"sipnab_diagnosis_total{type="one_way_audio"} 4"#));
    }

    /// Empty labeled-counter families emit no HELP/TYPE lines at all.
    #[test]
    fn empty_counter_maps_omitted() {
        let metrics = PrometheusMetrics::default();
        let output = format_metrics(&metrics);

        // Empty HashMap counters should not produce HELP/TYPE lines
        assert!(!output.contains("# HELP sipnab_dialogs_total"));
        assert!(!output.contains("# HELP sipnab_security_alerts_total"));
    }

    // ── capture quality ──────────────────────────────────────────────

    /// The three capture-quality counters are emitted under three distinct
    /// names carrying three distinct values.
    ///
    /// The point of the test is the separation. Kernel drops are fixed by a
    /// bigger `-B`, interface drops are not fixable that way at all, and an
    /// invalid timestamp loses no packet — it invalidates the timing. A
    /// collapsed total would read as one problem with one remedy.
    #[test]
    fn capture_quality_counters_stay_separately_named() {
        let metrics = PrometheusMetrics {
            capture_quality: CaptureQuality {
                kernel_dropped_packets: 11,
                interface_dropped_packets: 22,
                invalid_timestamps: 33,
            },
            ..Default::default()
        };
        let output = format_metrics(&metrics);

        assert!(output.contains("# TYPE sipnab_capture_kernel_dropped_packets_total counter"));
        assert!(output.contains("sipnab_capture_kernel_dropped_packets_total 11"));
        assert!(output.contains("# TYPE sipnab_capture_interface_dropped_packets_total counter"));
        assert!(output.contains("sipnab_capture_interface_dropped_packets_total 22"));
        assert!(output.contains("# TYPE sipnab_capture_invalid_timestamps_total counter"));
        assert!(output.contains("sipnab_capture_invalid_timestamps_total 33"));
    }

    /// A clean capture publishes all four series at zero rather than
    /// omitting them: a rule over an absent series is no-data, not "fine".
    #[test]
    fn capture_quality_is_published_even_when_clean() {
        let output = format_metrics(&PrometheusMetrics::default());

        assert!(output.contains("sipnab_capture_kernel_dropped_packets_total 0"));
        assert!(output.contains("sipnab_capture_interface_dropped_packets_total 0"));
        assert!(output.contains("sipnab_capture_invalid_timestamps_total 0"));
        assert!(output.contains("# TYPE sipnab_capture_quality_degraded gauge"));
        assert!(output.contains("sipnab_capture_quality_degraded 0"));
    }

    /// Any one of the three counters moving raises the degraded gauge.
    #[test]
    fn any_single_counter_raises_the_degraded_gauge() {
        for quality in [
            CaptureQuality {
                kernel_dropped_packets: 1,
                ..Default::default()
            },
            CaptureQuality {
                interface_dropped_packets: 1,
                ..Default::default()
            },
            CaptureQuality {
                invalid_timestamps: 1,
                ..Default::default()
            },
        ] {
            assert!(quality.degraded(), "{quality:?} must read as degraded");
            let output = format_metrics(&PrometheusMetrics {
                capture_quality: quality,
                ..Default::default()
            });
            assert!(
                output.contains("sipnab_capture_quality_degraded 1"),
                "{quality:?} did not raise the gauge"
            );
        }
    }

    /// A capture with nothing wrong observed is not degraded.
    #[test]
    fn a_clean_capture_is_not_degraded() {
        assert!(!CaptureQuality::default().degraded());
    }

    /// `for_scrape` loads the capture-quality block from the process
    /// counters, so a collector that builds from it cannot publish a
    /// hard-coded zero over a lossy run.
    #[test]
    fn for_scrape_loads_capture_quality() {
        let m = PrometheusMetrics::for_scrape();
        assert_eq!(m.capture_quality, CaptureQuality::current());
    }
}
