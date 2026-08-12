// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP stream detail view — full quality metrics for a single stream:
//! header, quality summary, MOS/jitter sparklines, per-interval table,
//! burst/gap analysis and silence detection.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::rtp::quality::estimate_mos;
use crate::rtp::stream::StreamKey;
use crate::rtp::stream_store::StreamStore;

use super::Theme;

/// Display parameters for the stream detail view.
pub struct StreamDetailDisplay<'a> {
    /// Color theme used for all styling.
    pub theme: &'a Theme,
    /// Resolver mapping endpoint addresses to user-assigned names.
    pub resolver: &'a crate::names::NameResolver,
    /// How endpoint names are displayed (off / name only / name+address).
    pub name_mode: crate::names::NameMode,
    /// One-way path delay the operator declared, if any.
    ///
    /// `None` means they declared nothing, which is NOT the same as declaring
    /// the default: the resolver then falls back to what the far end reported
    /// and, failing that, says the figure was assumed.
    pub declared_one_way_delay_ms: Option<f64>,
}

/// Render a full-screen scrollable detail view for a single RTP stream.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Main-pane area for the view (no border of its own).
/// * `key` - Key of the stream to show.
/// * `store` - Stream store snapshot the stream is read from.
/// * `scroll` - Requested vertical scroll offset in rows.
/// * `display` - Theme and name-resolution parameters.
///
/// # Returns
/// The effective (content-clamped) scroll so the caller can write it back —
/// otherwise Up appears dead after over-scrolling past the end. Returns `0`
/// when the stream is gone (a placeholder notice is drawn instead).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub fn render_stream_detail(
    frame: &mut ratatui::Frame,
    area: Rect,
    key: &StreamKey,
    store: &StreamStore,
    scroll: usize,
    display: &StreamDetailDisplay,
) -> usize {
    let StreamDetailDisplay {
        theme,
        resolver,
        name_mode,
        declared_one_way_delay_ms,
    } = *display;
    let stream = match store.get(key) {
        Some(s) => s,
        None => {
            let msg =
                Paragraph::new("Stream no longer available.").style(Style::default().fg(theme.bad));
            frame.render_widget(msg, area);
            return 0;
        }
    };

    let mut lines: Vec<Line<'_>> = Vec::with_capacity(60);

    // ── Header ──────────────────────────────────────────────────────
    let ssrc = format!("0x{:08X}", stream.key.ssrc);
    let codec_str = stream.codec.as_deref().unwrap_or("Unknown");
    let pt = stream.payload_type;
    let clock = stream.clock_rate;

    lines.push(Line::from(vec![
        Span::styled(
            "RTP Stream Detail",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  SSRC: "),
        Span::styled(&ssrc, Style::default().fg(theme.header)),
        Span::raw("  Codec: "),
        Span::styled(
            format!("{codec_str}/{clock}"),
            Style::default().fg(theme.header),
        ),
        Span::raw(format!("  PT: {pt}")),
    ]));

    lines.push(Line::from(vec![
        Span::styled(
            resolver.label_socket(stream.key.src, name_mode),
            Style::default().fg(theme.accent),
        ),
        Span::raw(" → "),
        Span::styled(
            resolver.label_socket(stream.key.dst, name_mode),
            Style::default().fg(theme.accent),
        ),
        Span::raw("  Dialog: "),
        Span::raw(stream.associated_dialog.as_deref().unwrap_or("(orphaned)")),
    ]));

    lines.push(Line::raw(""));

    // ── Quality Metrics ─────────────────────────────────────────────
    let loss_pct = stream.loss_percent();
    // MOS rests on a one-way delay sipnab cannot measure. Take the operator's
    // figure first, then the far end's reported round trip, then say it was
    // assumed — and show WHICH, because the remedy differs: a wrong declared
    // value is the operator's to fix, a wrong reported one means suspecting
    // the endpoint, and an assumed one means the delay was never known.
    let (one_way, delay_src) = crate::rtp::quality::resolve_one_way_delay(
        declared_one_way_delay_ms,
        store
            .remote_voip_metrics(key)
            .map(|xr| xr.metrics.round_trip_delay),
    );
    let mos = crate::rtp::quality::estimate_mos_with_delay(
        stream.jitter,
        loss_pct,
        stream.codec.as_deref(),
        one_way,
    );

    // Say where the delay came from. An operator seeing a bad MOS needs to
    // know whether to check their own declared figure, suspect the far end, or
    // recognise that nothing measured it at all — the three remedies differ.
    let delay_note = match delay_src {
        crate::rtp::quality::DelaySource::Declared => {
            format!("delay {one_way:.0}ms declared")
        }
        crate::rtp::quality::DelaySource::ReportedByEndpoint => {
            format!("delay {one_way:.0}ms per far end")
        }
        crate::rtp::quality::DelaySource::Assumed => {
            format!("delay {one_way:.0}ms assumed")
        }
    };

    let mos_band = MosBand::of(mos);
    let mos_style = Style::default()
        .fg(mos_band.color(theme))
        .add_modifier(Modifier::BOLD);
    let mos_label = mos_band.label();

    lines.push(section_header("Quality", theme));

    lines.push(Line::from(vec![
        Span::raw("  MOS: "),
        Span::styled(format!("{mos:.1} ({mos_label})"), mos_style),
        Span::raw("    Jitter: "),
        Span::styled(
            format!("{:.1}ms", stream.jitter),
            jitter_style(stream.jitter, theme),
        ),
        Span::raw("    Loss: "),
        Span::styled(format!("{loss_pct:.2}%"), loss_style(loss_pct, theme)),
        Span::raw("    RTT: "),
        // The third number of the triage row, beside the two it belongs with.
        // It used to appear only inside the XR block far below, which most
        // calls never carry — so the row an operator reads to decide "was this
        // acceptable?" showed two of the three numbers that decide it, with
        // nothing saying the third was missing rather than fine.
        match store.round_trip_for(stream) {
            Some((ms, src)) => Span::styled(
                format!(
                    "{ms:.0}ms{}",
                    match src {
                        crate::rtp::rtcp::RttSource::XrVoipMetrics => "",
                        // Marked, because it is anchored on the capture point:
                        // the full round trip only when the tap sits with the
                        // SR sender, a lower bound otherwise.
                        crate::rtp::rtcp::RttSource::SenderReportEcho => "~",
                    }
                ),
                rtt_style(ms, theme),
            ),
            // Not "0ms", and not blank. An operator scanning this row has to
            // be able to tell "nobody measured it" from "it is fine".
            None => Span::styled("n/a", Style::default().fg(theme.muted)),
        },
        Span::raw("    "),
        Span::styled(format!("({delay_note})"), Style::default().fg(theme.muted)),
    ]));

    let duration_secs = stream
        .last_seen
        .signed_duration_since(stream.first_seen)
        .num_milliseconds() as f64
        / 1000.0;
    let bitrate = if duration_secs > 0.0 {
        (stream.octet_count as f64 * 8.0) / duration_secs / 1000.0
    } else {
        0.0
    };

    lines.push(Line::from(vec![
        Span::raw("  Packets: "),
        Span::styled(
            stream.packet_count.to_string(),
            Style::default().fg(theme.header),
        ),
        Span::raw("    Octets: "),
        Span::raw(stream.octet_count.to_string()),
        Span::raw("    Duration: "),
        Span::raw(format!("{duration_secs:.1}s")),
    ]));

    lines.push(Line::from(vec![
        Span::raw("  Bitrate: "),
        Span::raw(format!("{bitrate:.1} kbps")),
        Span::raw("    Clock: "),
        Span::raw(format!("{clock} Hz")),
        Span::raw("    CN Frames: "),
        Span::raw(stream.cn_frames.to_string()),
    ]));

    lines.push(Line::from(vec![
        Span::raw("  First: "),
        Span::raw(stream.first_seen.format("%H:%M:%S%.3f").to_string()),
        Span::raw("    Last: "),
        Span::raw(stream.last_seen.format("%H:%M:%S%.3f").to_string()),
        Span::raw("    Lost pkts: "),
        Span::styled(
            stream.lost_packets.to_string(),
            if stream.lost_packets > 0 {
                Style::default().fg(theme.bad)
            } else {
                Style::default().fg(theme.good)
            },
        ),
    ]));

    let flags = format!(
        "  Orphaned: {}    Heuristic: {}",
        if stream.orphaned { "Yes" } else { "No" },
        if stream.heuristic { "Yes" } else { "No" },
    );
    lines.push(Line::raw(flags));

    lines.push(Line::raw(""));

    // ── Quality Over Time ───────────────────────────────────────────
    if !stream.quality_intervals.is_empty() {
        lines.push(section_header("Quality Over Time", theme));

        // Cap the number of sparkline glyphs to the pane width: reserve room
        // for the row label and the trailing "(avg: …)" annotation, then draw
        // only the most recent intervals. Without this a long history emits one
        // glyph per interval and overflows (and truncates) the pane, hiding the
        // newest data and the average.
        const SPARK_LABEL_W: usize = 13; // "  MOS Trend: " / "  Jitter:    "
        const SPARK_SUFFIX_W: usize = 18; // worst-case "  (avg: 1234.5ms)"
        let spark_budget = (area.width as usize)
            .saturating_sub(SPARK_LABEL_W + SPARK_SUFFIX_W)
            .max(1);

        // Sparkline: MOS trend
        let mos_values: Vec<f64> = stream
            .quality_intervals
            .iter()
            .map(|qi| estimate_mos(qi.jitter_ms, qi.loss_pct, stream.codec.as_deref()))
            .collect();
        let mos_avg = mos_values.iter().sum::<f64>() / mos_values.len() as f64;
        let mut mos_spans: Vec<Span<'_>> = vec![Span::styled(
            "  MOS Trend: ",
            Style::default().fg(theme.muted),
        )];
        let mos_start = mos_values.len().saturating_sub(spark_budget);
        for &m in &mos_values[mos_start..] {
            let ch = mos_to_block(m);
            let color = MosBand::of(m).color(theme);
            mos_spans.push(Span::styled(String::from(ch), Style::default().fg(color)));
        }
        mos_spans.push(Span::styled(
            format!("  (avg: {mos_avg:.1})"),
            Style::default().fg(theme.muted),
        ));
        lines.push(Line::from(mos_spans));

        // Sparkline: Jitter trend
        let jitter_values: Vec<f64> = stream
            .quality_intervals
            .iter()
            .map(|qi| qi.jitter_ms)
            .collect();
        let jitter_avg = jitter_values.iter().sum::<f64>() / jitter_values.len() as f64;
        let mut jitter_spans: Vec<Span<'_>> = vec![Span::styled(
            "  Jitter:    ",
            Style::default().fg(theme.muted),
        )];
        let jitter_start = jitter_values.len().saturating_sub(spark_budget);
        for &j in &jitter_values[jitter_start..] {
            let ch = jitter_to_block(j);
            let color = if j < 20.0 {
                theme.good
            } else if j < 50.0 {
                theme.warning
            } else {
                theme.bad
            };
            jitter_spans.push(Span::styled(String::from(ch), Style::default().fg(color)));
        }
        jitter_spans.push(Span::styled(
            format!("  (avg: {jitter_avg:.1}ms)"),
            Style::default().fg(theme.muted),
        ));
        lines.push(Line::from(jitter_spans));

        lines.push(Line::raw(""));

        lines.push(Line::from(vec![
            Span::styled("  Time       ", Style::default().fg(theme.muted)),
            Span::styled("Jitter     ", Style::default().fg(theme.muted)),
            Span::styled("Loss       ", Style::default().fg(theme.muted)),
            Span::styled("Packets    ", Style::default().fg(theme.muted)),
            Span::styled("MOS", Style::default().fg(theme.muted)),
        ]));

        let first_ts = stream.quality_intervals.first().map(|q| q.timestamp);
        for qi in &stream.quality_intervals {
            let offset = first_ts
                .map(|ft| qi.timestamp.signed_duration_since(ft).num_seconds())
                .unwrap_or(0);
            let qi_mos = estimate_mos(qi.jitter_ms, qi.loss_pct, stream.codec.as_deref());

            lines.push(Line::from(vec![
                Span::raw(format!("  +{offset:<8}s ")),
                Span::styled(
                    format!("{:<10.1}ms ", qi.jitter_ms),
                    jitter_style(qi.jitter_ms, theme),
                ),
                Span::styled(
                    format!("{:<10.2}% ", qi.loss_pct),
                    loss_style(qi.loss_pct, theme),
                ),
                Span::raw(format!("{:<10} ", qi.packets)),
                Span::styled(
                    format!("{qi_mos:.1}"),
                    Style::default().fg(MosBand::of(qi_mos).color(theme)),
                ),
            ]));
        }
        lines.push(Line::raw(""));
    }

    // ── Burst/Gap Analysis ──────────────────────────────────────────
    if stream.lost_packets > 0
        && let Some(bga) = stream.burst_gap_analysis()
    {
        lines.push(section_header("Burst/Gap Analysis", theme));
        lines.push(Line::from(vec![
            Span::raw("  Bursts: "),
            Span::styled(
                bga.burst_count.to_string(),
                Style::default().fg(theme.warning),
            ),
            Span::raw("    Burst duration: "),
            Span::raw(format!("{:.0}ms", bga.burst_duration_ms)),
            Span::raw("    Gap duration: "),
            Span::raw(format!("{:.1}s", bga.gap_duration_ms / 1000.0)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Burst loss rate: "),
            Span::styled(
                format!("{:.1}%", bga.burst_loss_rate * 100.0),
                Style::default().fg(theme.bad),
            ),
            Span::raw("    Gap loss rate: "),
            Span::raw(format!("{:.1}%", bga.gap_loss_rate * 100.0)),
            Span::raw("    Pattern: "),
            Span::styled(
                if bga.is_bursty { "Bursty" } else { "Random" },
                if bga.is_bursty {
                    Style::default()
                        .fg(theme.warning)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.muted)
                },
            ),
        ]));
        lines.push(Line::raw(""));
    }

    // ── Silence Detection ───────────────────────────────────────────
    if stream.cn_frames > 0 || !stream.silence_periods.is_empty() {
        lines.push(section_header("Silence Detection", theme));
        lines.push(Line::from(vec![
            Span::raw("  CN Frames: "),
            Span::raw(stream.cn_frames.to_string()),
            Span::raw("    Silence periods: "),
            Span::raw(stream.silence_periods.len().to_string()),
        ]));

        for sp in stream.silence_periods.iter().take(20) {
            lines.push(Line::from(vec![
                Span::raw("  Seq "),
                Span::styled(
                    format!("{}-{}", sp.start_seq, sp.end_seq),
                    Style::default().fg(theme.muted),
                ),
                Span::raw(format!("    Duration: {}ms", sp.duration_ms)),
            ]));
        }
        if stream.silence_periods.len() > 20 {
            lines.push(Line::styled(
                format!("  ... and {} more", stream.silence_periods.len() - 20),
                Style::default().fg(theme.muted),
            ));
        }
        lines.push(Line::raw(""));
    }

    // ── Reported by the far end (RTCP XR) ───────────────────────────
    // Everything above this point is what sipnab measured from the media it
    // saw. Everything below is what an endpoint asserted in an RTCP XR VoIP
    // Metrics block (RFC 3611 §4.7) — a different kind of fact, on a
    // different path segment, over an unauthenticated datagram. The section
    // header says so, and no value from here is folded into anything above.
    if let Some(xr) = store.remote_voip_metrics(key) {
        let m = &xr.metrics;
        lines.push(section_header("Reported by Far End (RTCP XR)", theme));
        lines.push(Line::styled(
            format!(
                "  Endpoint's own claim, not sipnab's measurement \
                 (reporter SSRC 0x{:08X}, {} report{})",
                xr.reporter_ssrc,
                xr.reports_seen,
                if xr.reports_seen == 1 { "" } else { "s" },
            ),
            Style::default()
                .fg(theme.muted)
                .add_modifier(Modifier::ITALIC),
        ));

        lines.push(Line::from(vec![
            Span::raw("  MOS-LQ: "),
            Span::styled(reported_mos(m.mos_lq()), Style::default().fg(theme.header)),
            Span::raw("    MOS-CQ: "),
            Span::styled(reported_mos(m.mos_cq()), Style::default().fg(theme.header)),
            Span::raw("    R factor: "),
            Span::styled(reported_u8(m.r_factor()), Style::default().fg(theme.header)),
            Span::raw("    Ext R: "),
            Span::raw(reported_u8(m.ext_r_factor())),
        ]));

        lines.push(Line::from(vec![
            Span::raw("  Loss: "),
            Span::raw(format!("{:.2}%", m.loss_rate_pct())),
            Span::raw("    Discard: "),
            Span::raw(format!("{:.2}%", m.discard_rate_pct())),
            Span::raw("    Burst density: "),
            Span::raw(format!("{:.1}%", m.burst_density_pct())),
            Span::raw("    Gap density: "),
            Span::raw(format!("{:.1}%", m.gap_density_pct())),
        ]));

        lines.push(Line::from(vec![
            Span::raw("  Burst duration: "),
            Span::raw(format!("{}ms", m.burst_duration)),
            Span::raw("    Gap duration: "),
            Span::raw(format!("{}ms", m.gap_duration)),
            Span::raw("    Round-trip: "),
            Span::raw(format!("{}ms", m.round_trip_delay)),
            Span::raw("    End-system: "),
            Span::raw(format!("{}ms", m.end_system_delay)),
        ]));

        lines.push(Line::from(vec![
            Span::raw("  Signal: "),
            Span::raw(reported_dbm0(m.signal_level_dbm0())),
            Span::raw("    Noise: "),
            Span::raw(reported_dbm0(m.noise_level_dbm0())),
            Span::raw("    RERL: "),
            Span::raw(match m.rerl_db() {
                Some(v) => format!("{v} dB"),
                None => "n/a".to_string(),
            }),
            Span::raw("    Gmin: "),
            Span::raw(m.gmin.to_string()),
        ]));

        lines.push(Line::from(vec![
            Span::raw("  Jitter buffer nominal: "),
            Span::raw(format!("{}ms", m.jb_nominal)),
            Span::raw("    max: "),
            Span::raw(format!("{}ms", m.jb_maximum)),
            Span::raw("    absolute max: "),
            Span::raw(if m.jb_abs_max_is_capped() {
                format!("{}ms or more", m.jb_abs_max)
            } else {
                format!("{}ms", m.jb_abs_max)
            }),
        ]));

        lines.push(Line::raw(""));
    }

    // ── Render with scroll ──────────────────────────────────────────
    let visible_height = area.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let effective_scroll = scroll.min(max_scroll);

    let para = Paragraph::new(lines).scroll((effective_scroll as u16, 0));
    frame.render_widget(para, area);
    effective_scroll
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Render an endpoint-reported MOS, or `n/a` when the endpoint marked it
/// unavailable.
///
/// Deliberately not styled by [`MosBand`]: that colouring belongs to the MOS
/// sipnab estimated, and painting an endpoint's claim in the same green would
/// invite reading the two as one number. The band's remedy is also wrong here
/// — a bad score from the far end points at the far end, not at the capture.
fn reported_mos(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{v:.1}"))
}

/// Render an endpoint-reported R factor, or `n/a` when marked unavailable.
fn reported_u8(value: Option<u8>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| v.to_string())
}

/// Render an endpoint-reported level in dBm0, or `n/a` when marked
/// unavailable. Negative by nature — RFC 3611 puts these on 0 to -127 dBm0.
fn reported_dbm0(value: Option<i8>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{v} dBm0"))
}

/// Perceptual quality band for a MOS score.
///
/// Boundaries use closed lower bounds (`>=`), so a score sits in the
/// highest band it reaches:
///
/// | Band | MOS range |
/// |------|-----------|
/// | Good | `>= 4.0`  |
/// | Fair | `>= 3.5`  |
/// | Poor | `>= 3.0`  |
/// | Bad  | `<  3.0`  |
///
/// This single classification backs both the textual label and the color
/// for every MOS the detail view renders (summary line, MOS-trend
/// sparkline and per-interval table), so the label and its color can never
/// drift out of agreement at a band boundary.
#[derive(Clone, Copy)]
enum MosBand {
    Good,
    Fair,
    Poor,
    Bad,
}

impl MosBand {
    /// Classify a MOS score into its band (closed lower bounds).
    ///
    /// Four labels where the colour views use three, and that is deliberate: a
    /// detail pane can afford to separate Fair from Poor where a colour column
    /// cannot. Only the OUTER boundaries are shared, so this stays finer
    /// without being able to disagree — a score this view calls Good can never
    /// be one the dashboard colours yellow.
    fn of(mos: f64) -> Self {
        let bands = crate::rtp::bands::QualityBands::default();
        if mos >= bands.mos_warn {
            Self::Good
        } else if mos >= (bands.mos_warn + bands.mos_bad) / 2.0 {
            Self::Fair
        } else if mos >= bands.mos_bad {
            Self::Poor
        } else {
            Self::Bad
        }
    }

    /// Short human-readable label for the band.
    fn label(self) -> &'static str {
        match self {
            Self::Good => "Good",
            Self::Fair => "Fair",
            Self::Poor => "Poor",
            Self::Bad => "Bad",
        }
    }

    /// Theme color for the band. Only three severity colors exist, so the
    /// adjacent Fair and Poor bands share the warning color; the textual
    /// label still tells them apart.
    fn color(self, theme: &Theme) -> ratatui::style::Color {
        match self {
            Self::Good => theme.good,
            Self::Fair | Self::Poor => theme.warning,
            Self::Bad => theme.bad,
        }
    }
}

/// Build a section header line: `── <title> ` in bold accent followed by a
/// horizontal rule in the border color. Pure.
fn section_header<'a>(title: &'a str, theme: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("── {title} "),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("─".repeat(50), Style::default().fg(theme.border)),
    ])
}

/// Style for a jitter value: < 20ms good, 20–50ms warning, >= 50ms bad.
/// Pure.
fn jitter_style(jitter_ms: f64, theme: &Theme) -> Style {
    // Was 20/50 here against the stream list's 30/50, which is the pair that
    // made one stream green in the list and yellow in its own detail view.
    match crate::rtp::bands::QualityBands::default().jitter(jitter_ms) {
        crate::rtp::bands::Band::Good => Style::default().fg(theme.good),
        crate::rtp::bands::Band::Warning => Style::default().fg(theme.warning),
        crate::rtp::bands::Band::Bad => Style::default().fg(theme.bad),
    }
}

/// Style for a round-trip figure, using the shared bands. Pure.
///
/// Takes a measured value only. There is no style for "not measured" because
/// that is not a quality verdict — the caller renders it as `n/a` in the muted
/// colour, which is neither green nor red on purpose.
fn rtt_style(rtt_ms: f64, theme: &Theme) -> Style {
    match crate::rtp::bands::QualityBands::default().rtt(rtt_ms) {
        crate::rtp::bands::Band::Good => Style::default().fg(theme.good),
        crate::rtp::bands::Band::Warning => Style::default().fg(theme.warning),
        crate::rtp::bands::Band::Bad => Style::default().fg(theme.bad),
    }
}

/// Style for a packet-loss percentage, using the shared bands. Pure.
///
/// The sixth and last copy: 0.5/2.0 here against the stream list's 1.0/5.0.
/// The gate that found it is `no_view_carries_its_own_quality_bands`.
fn loss_style(loss_pct: f64, theme: &Theme) -> Style {
    match crate::rtp::bands::QualityBands::default().loss(loss_pct) {
        crate::rtp::bands::Band::Good => Style::default().fg(theme.good),
        crate::rtp::bands::Band::Warning => Style::default().fg(theme.warning),
        crate::rtp::bands::Band::Bad => Style::default().fg(theme.bad),
    }
}

/// Map a MOS value (1.0–4.5) to a Unicode block character.
/// Scale: < 1.5 = ▁, 1.5–2.0 = ▂, 2.0–2.5 = ▃, 2.5–3.0 = ▄,
///        3.0–3.5 = ▅, 3.5–4.0 = ▆, 4.0–4.3 = ▇, 4.3+ = █
pub(in crate::tui) fn mos_to_block(mos: f64) -> char {
    match mos {
        m if m >= 4.3 => '\u{2588}', // █
        m if m >= 4.0 => '\u{2587}', // ▇
        m if m >= 3.5 => '\u{2586}', // ▆
        m if m >= 3.0 => '\u{2585}', // ▅
        m if m >= 2.5 => '\u{2584}', // ▄
        m if m >= 2.0 => '\u{2583}', // ▃
        m if m >= 1.5 => '\u{2582}', // ▂
        _ => '\u{2581}',             // ▁
    }
}

/// Map a jitter value (ms) to a Unicode block character.
/// Scale: 0–5ms = ▁, 5–10 = ▂, 10–15 = ▃, 15–20 = ▄,
///        20–25 = ▅, 25–30 = ▆, 30–35 = ▇, 35+ = █
pub(in crate::tui) fn jitter_to_block(jitter_ms: f64) -> char {
    match jitter_ms {
        j if j >= 35.0 => '\u{2588}', // █
        j if j >= 30.0 => '\u{2587}', // ▇
        j if j >= 25.0 => '\u{2586}', // ▆
        j if j >= 20.0 => '\u{2585}', // ▅
        j if j >= 15.0 => '\u{2584}', // ▄
        j if j >= 10.0 => '\u{2583}', // ▃
        j if j >= 5.0 => '\u{2582}',  // ▂
        _ => '\u{2581}',              // ▁
    }
}

/// Unit tests for the block-glyph mappers, style threshold bands and the
/// full stream-detail render across quality levels.
#[cfg(test)]
mod tests {
    use super::*;

    /// Every MOS band maps to its block glyph, including exact boundaries
    /// and below-minimum values.
    #[test]
    fn mos_to_block_boundaries() {
        // Top of scale: excellent MOS
        assert_eq!(mos_to_block(4.5), '\u{2588}'); // █
        assert_eq!(mos_to_block(4.3), '\u{2588}'); // █ (boundary)
        // Good
        assert_eq!(mos_to_block(4.0), '\u{2587}'); // ▇
        // Fair
        assert_eq!(mos_to_block(3.5), '\u{2586}'); // ▆
        // Acceptable
        assert_eq!(mos_to_block(3.0), '\u{2585}'); // ▅
        // Poor
        assert_eq!(mos_to_block(2.5), '\u{2584}'); // ▄
        // Bad
        assert_eq!(mos_to_block(2.0), '\u{2583}'); // ▃
        // Very bad
        assert_eq!(mos_to_block(1.5), '\u{2582}'); // ▂
        // Minimum
        assert_eq!(mos_to_block(1.0), '\u{2581}'); // ▁
        // Below minimum
        assert_eq!(mos_to_block(0.5), '\u{2581}'); // ▁
    }

    /// Every jitter band maps to its block glyph, including exact
    /// boundaries and values far above the top band.
    #[test]
    fn jitter_to_block_boundaries() {
        // Minimal jitter
        assert_eq!(jitter_to_block(0.0), '\u{2581}'); // ▁
        assert_eq!(jitter_to_block(4.9), '\u{2581}'); // ▁ (just under 5ms boundary)
        // Rising jitter levels
        assert_eq!(jitter_to_block(5.0), '\u{2582}'); // ▂ (boundary)
        assert_eq!(jitter_to_block(10.0), '\u{2583}'); // ▃
        assert_eq!(jitter_to_block(15.0), '\u{2584}'); // ▄
        assert_eq!(jitter_to_block(20.0), '\u{2585}'); // ▅
        assert_eq!(jitter_to_block(25.0), '\u{2586}'); // ▆
        assert_eq!(jitter_to_block(30.0), '\u{2587}'); // ▇
        // Severe jitter
        assert_eq!(jitter_to_block(35.0), '\u{2588}'); // █ (boundary)
        assert_eq!(jitter_to_block(100.0), '\u{2588}'); // █ (well above max)
    }

    // ── Style helper threshold tests ─────────────────────────────────

    use ratatui::style::Color;

    /// `jitter_style` colours at the SHARED boundaries, not its own.
    ///
    /// This asserted 20/50 while the stream list used 30/50, and passed —
    /// which is how a stream stayed green in the list and yellow in its own
    /// detail view for as long as it did. Both tests were correct about the
    /// code and silent about the contradiction, so they now read the
    /// boundaries from the shared band set rather than restating numbers.
    #[test]
    fn jitter_style_follows_the_shared_bands() {
        let theme = Theme::default();
        let b = crate::rtp::bands::QualityBands::default();
        assert_eq!(jitter_style(0.0, &theme).fg, Some(theme.good));
        assert_eq!(
            jitter_style(b.jitter_warn_ms - 0.1, &theme).fg,
            Some(theme.good)
        );
        assert_eq!(
            jitter_style(b.jitter_warn_ms, &theme).fg,
            Some(theme.warning)
        );
        assert_eq!(
            jitter_style(b.jitter_bad_ms - 0.1, &theme).fg,
            Some(theme.warning)
        );
        assert_eq!(jitter_style(b.jitter_bad_ms, &theme).fg, Some(theme.bad));
        assert_eq!(
            jitter_style(b.jitter_bad_ms * 3.0, &theme).fg,
            Some(theme.bad)
        );
    }

    /// The same stream gets the same verdict here as in the stream list.
    ///
    /// The contradiction this pins is the reported one: a value that one pane
    /// called healthy and another called a warning, in the same session.
    #[test]
    fn this_view_agrees_with_the_stream_list() {
        let theme = Theme::default();
        let b = crate::rtp::bands::QualityBands::default();
        for jitter in [0.0, 25.0, 29.9, 30.0, 49.9, 50.0, 100.0] {
            let detail_good = jitter_style(jitter, &theme).fg == Some(theme.good);
            let list_good = b.jitter(jitter) == crate::rtp::bands::Band::Good;
            assert_eq!(
                detail_good, list_good,
                "{jitter} ms: detail view and stream list disagree again"
            );
        }
        for loss in [0.0, 0.4, 0.8, 1.0, 4.9, 5.0, 90.0] {
            let detail_good = loss_style(loss, &theme).fg == Some(theme.good);
            let list_good = b.loss(loss) == crate::rtp::bands::Band::Good;
            assert_eq!(
                detail_good, list_good,
                "{loss}% loss: detail view and stream list disagree again"
            );
        }
    }

    /// `loss_style` colours at the SHARED boundaries.
    #[test]
    fn loss_style_follows_the_shared_bands() {
        let theme = Theme::default();
        let b = crate::rtp::bands::QualityBands::default();
        assert_eq!(loss_style(0.0, &theme).fg, Some(theme.good));
        assert_eq!(
            loss_style(b.loss_warn_pct - 0.01, &theme).fg,
            Some(theme.good)
        );
        assert_eq!(loss_style(b.loss_warn_pct, &theme).fg, Some(theme.warning));
        assert_eq!(loss_style(b.loss_bad_pct, &theme).fg, Some(theme.bad));
        assert_eq!(loss_style(90.0, &theme).fg, Some(theme.bad));
    }

    /// A section header carries the bold accented title span followed by
    /// a border-colored rule span.
    #[test]
    fn section_header_has_title_and_accent() {
        let theme = Theme::default();
        let line = section_header("Quality", &theme);
        // First span carries the bolded, accented title text.
        let first = &line.spans[0];
        assert!(first.content.contains("Quality"));
        assert!(first.content.starts_with("\u{2500}\u{2500} ")); // "── "
        assert_eq!(first.style.fg, Some(theme.accent));
        assert!(
            first
                .style
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
        // Trailing rule uses the border color.
        let rule = &line.spans[1];
        assert_eq!(rule.style.fg, Some(theme.border));
    }

    // ── render_stream_detail integration tests ───────────────────────

    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{DateTime, TimeDelta, Utc};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::capture::ParsedPacket;
    use crate::capture::parse::TransportProto;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::rtcp::{ReceiverReport, ReceptionReport, RtcpPacket};

    /// Build a minimal fixture RTP header for `ssrc` at sequence `seq`
    /// with payload type `pt` (8kHz 20ms timestamp spacing).
    fn rtp_header(ssrc: u32, seq: u16, pt: u8) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: pt,
            sequence: seq,
            timestamp: u32::from(seq) * 160,
            ssrc,
            payload_offset: 12,
        }
    }

    /// Build a fixture UDP packet 10.0.0.1 → 10.0.0.2 with the given ports
    /// and timestamp, carrying a 172-byte zeroed payload.
    fn parsed(src_port: u16, dst_port: u16, ts: DateTime<Utc>) -> ParsedPacket {
        ParsedPacket {
            frame: None,
            timestamp: ts,
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            transport: TransportProto::Udp,
            payload: vec![0u8; 172].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        }
    }

    /// Build a store holding one PCMU stream, then inject RTCP-reported
    /// jitter/loss so the render path exercises the chosen style branch.
    /// Returns the store and the key of the inserted stream.
    fn store_with_stream(ssrc: u32, jitter: u32, lost: i32) -> (StreamStore, StreamKey) {
        let mut store = StreamStore::new(16);
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // A few packets so packet_count > 0 and a duration exists.
        store.process_rtp(&parsed(20000, 30000, t0), &rtp_header(ssrc, 1, 0), t0);
        store.process_rtp(
            &parsed(20000, 30000, t0 + TimeDelta::milliseconds(20)),
            &rtp_header(ssrc, 2, 0),
            t0 + TimeDelta::milliseconds(20),
        );
        store.process_rtp(
            &parsed(20000, 30000, t0 + TimeDelta::milliseconds(40)),
            &rtp_header(ssrc, 3, 0),
            t0 + TimeDelta::milliseconds(40),
        );
        // Inject authoritative jitter + cumulative loss via an RTCP RR.
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0x9999_9999,
            reports: vec![ReceptionReport {
                ssrc,
                fraction_lost: 0,
                cumulative_lost: lost,
                highest_seq: 3,
                jitter,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        });
        store.process_rtcp(&[rr], chrono::Utc::now());

        let key = StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        (store, key)
    }

    /// Render the stream detail for `key` into a 100x40 test terminal and
    /// return the buffer contents as one string.
    fn render_to_string(store: &StreamStore, key: &StreamKey) -> String {
        let theme = Theme::default();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_stream_detail(
                    frame,
                    area,
                    key,
                    store,
                    0,
                    &StreamDetailDisplay {
                        declared_one_way_delay_ms: None,
                        theme: &theme,
                        resolver: &crate::names::NameResolver::new(),
                        name_mode: crate::names::NameMode::Off,
                    },
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            out.push('\n');
        }
        out
    }

    /// A key absent from the store renders the "Stream no longer
    /// available." placeholder.
    #[test]
    fn render_stream_detail_missing_key_shows_placeholder() {
        let theme = Theme::default();
        let store = StreamStore::new(4);
        // Key that was never inserted.
        let key = StreamKey {
            ssrc: 0xDEAD_BEEF,
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1000),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2000),
        };
        let backend = TestBackend::new(60, 5);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_stream_detail(
                    frame,
                    area,
                    &key,
                    &store,
                    0,
                    &StreamDetailDisplay {
                        declared_one_way_delay_ms: None,
                        theme: &theme,
                        resolver: &crate::names::NameResolver::new(),
                        name_mode: crate::names::NameMode::Off,
                    },
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(out.contains("Stream no longer available."), "got: {out}");
    }

    /// Low jitter and no loss render the "Good" MOS label and all summary
    /// lines.
    #[test]
    fn render_stream_detail_good_quality() {
        // Low jitter, no loss → "Good" MOS path, good-colored styles.
        let (store, key) = store_with_stream(0x1111_1111, /*jitter*/ 0, /*lost*/ 0);
        let out = render_to_string(&store, &key);
        assert!(out.contains("RTP Stream Detail"), "header missing: {out}");
        assert!(out.contains("SSRC: 0x11111111"), "ssrc missing: {out}");
        assert!(out.contains("PCMU"), "codec missing: {out}");
        assert!(out.contains("Quality"), "quality section missing: {out}");
        assert!(out.contains("MOS:"), "MOS line missing: {out}");
        assert!(out.contains("Jitter:"), "jitter line missing: {out}");
        assert!(out.contains("Loss:"), "loss line missing: {out}");
        assert!(out.contains("(Good)"), "expected Good MOS label: {out}");
        // No loss → "Orphaned" flag line present, lost pkts 0.
        assert!(out.contains("Orphaned:"), "flags line missing: {out}");
    }

    /// Moderate jitter with some loss renders the warning-band styles and
    /// the lost-packets line.
    #[test]
    fn render_stream_detail_warn_quality() {
        // Moderate jitter (30ms) and some loss → warning-band styles.
        let (store, key) = store_with_stream(0x2222_2222, /*jitter*/ 30, /*lost*/ 1);
        let out = render_to_string(&store, &key);
        assert!(out.contains("RTP Stream Detail"));
        assert!(out.contains("MOS:"));
        // Lost packets > 0 surfaces the burst/gap analysis section.
        assert!(out.contains("Lost pkts:"), "lost pkts line missing: {out}");
    }

    /// High jitter with a real RTP sequence gap (loss) renders the
    /// bad-band styles and reaches the burst/gap section.
    #[test]
    fn render_stream_detail_bad_quality() {
        // High jitter (80ms) and heavy loss → bad-band styles and low MOS.
        // Loss is produced via a real RTP sequence gap so lost_packets > 0
        // (and the burst/gap section becomes reachable), then jitter is
        // overridden authoritatively via RTCP.
        let mut store = StreamStore::new(16);
        let ssrc = 0x3333_3333u32;
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        store.process_rtp(&parsed(20000, 30000, t0), &rtp_header(ssrc, 1, 0), t0);
        // Jump the sequence number forward to manufacture a loss gap.
        store.process_rtp(
            &parsed(20000, 30000, t0 + TimeDelta::milliseconds(60)),
            &rtp_header(ssrc, 60, 0),
            t0 + TimeDelta::milliseconds(60),
        );
        let rr = RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0x9999_9999,
            reports: vec![ReceptionReport {
                ssrc,
                fraction_lost: 200,
                cumulative_lost: 50,
                highest_seq: 60,
                jitter: 80,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        });
        store.process_rtcp(&[rr], chrono::Utc::now());
        let key = StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let out = render_to_string(&store, &key);
        assert!(out.contains("RTP Stream Detail"));
        assert!(out.contains("MOS:"));
        assert!(out.contains("Loss:"));
        assert!(out.contains("Lost pkts:"), "lost pkts line missing: {out}");
        let _ = Color::Reset; // keep Color import used regardless of assertions
    }

    /// Attach an XR VoIP Metrics block reporting the far end's own figures to
    /// the stream in `store`. The values are chosen to be unmistakable if any
    /// of them leaks into a sipnab-measured field.
    fn attach_xr(store: &mut StreamStore, ssrc: u32, mos_lq: u8, r_factor: u8) {
        use crate::rtp::rtcp::{ExtendedReport, VoipMetrics, XrBlock};
        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x7777_7777,
                blocks: vec![XrBlock::VoipMetrics(VoipMetrics {
                    ssrc,
                    loss_rate: 128,
                    discard_rate: 64,
                    burst_density: 200,
                    gap_density: 8,
                    burst_duration: 3_000,
                    gap_duration: 250,
                    round_trip_delay: 450,
                    end_system_delay: 90,
                    signal_level: 0xEC, // -20 dBm0
                    noise_level: 127,   // unavailable
                    rerl: 30,
                    gmin: 16,
                    r_factor,
                    ext_r_factor: 127, // unavailable
                    mos_lq,
                    mos_cq: 13,
                    jb_nominal: 40,
                    jb_maximum: 120,
                    jb_abs_max: 65_535,
                })],
            })],
            chrono::Utc::now(),
        );
    }

    /// A stream carrying an XR VoIP Metrics block renders the far end's own
    /// figures, attributed to the far end.
    ///
    /// Before this the block was fully decoded and then dropped, so the one
    /// place an endpoint tells you what it measured showed nothing at all.
    #[test]
    fn render_stream_detail_shows_far_end_xr_report() {
        let (mut store, key) = store_with_stream(0x5151_5151, 5, 0);
        attach_xr(&mut store, 0x5151_5151, 15, 32);

        let out = render_to_string(&store, &key);
        assert!(
            out.contains("Reported by Far End"),
            "the XR section must appear: {out}"
        );
        assert!(
            out.contains("not sipnab's measurement"),
            "the section must say whose number this is: {out}"
        );
        assert!(out.contains("MOS-LQ: 1.5"), "MOS x10 decodes to 1.5: {out}");
        assert!(out.contains("R factor: 32"), "R factor rendered: {out}");
        assert!(
            out.contains("Discard: 25.00%"),
            "discard rate is the impairment a capture cannot see: {out}"
        );
        assert!(
            out.contains("Round-trip: 450ms"),
            "round-trip delay rendered: {out}"
        );
    }

    /// Fields the endpoint marked unavailable render as `n/a`, never as the
    /// sentinel. RFC 3611 reserves 127, so a raw render publishes an R factor
    /// of 127 on a 0-to-100 scale and a MOS of 12.7 on a 1-to-5 one.
    #[test]
    fn render_stream_detail_xr_unavailable_fields_are_not_numbers() {
        let (mut store, key) = store_with_stream(0x5252_5252, 5, 0);
        attach_xr(&mut store, 0x5252_5252, 127, 127);

        let out = render_to_string(&store, &key);
        assert!(
            out.contains("MOS-LQ: n/a"),
            "an unavailable MOS must not render as 12.7: {out}"
        );
        assert!(
            out.contains("R factor: n/a"),
            "an unavailable R factor must not render as 127: {out}"
        );
        assert!(
            !out.contains("12.7"),
            "the MOS sentinel must never reach the screen as a value: {out}"
        );
    }

    /// A stream with no XR renders no far-end section at all, rather than a
    /// row of zeroes that reads as an endpoint reporting perfect silence.
    #[test]
    fn render_stream_detail_without_xr_omits_the_far_end_section() {
        let (store, key) = store_with_stream(0x5353_5353, 5, 0);
        let out = render_to_string(&store, &key);
        assert!(
            !out.contains("Reported by Far End"),
            "no XR means no far-end section: {out}"
        );
    }

    /// The far end's claimed MOS must not displace the MOS sipnab estimated.
    ///
    /// Both appear, in separate sections, with separate labels. This is the
    /// #61 rule at the render layer: an XR claiming MOS 1.5 on a clean stream
    /// leaves the estimated MOS where it was.
    #[test]
    fn render_stream_detail_far_end_mos_does_not_replace_the_estimate() {
        let (mut store, key) = store_with_stream(0x5454_5454, 5, 0);
        let before = render_to_string(&store, &key);
        let estimated = before
            .lines()
            .find(|l| l.contains("  MOS: "))
            .expect("estimated MOS line")
            .to_string();

        attach_xr(&mut store, 0x5454_5454, 15, 32);
        let after = render_to_string(&store, &key);
        let still = after
            .lines()
            .find(|l| l.contains("  MOS: "))
            .expect("estimated MOS line survives");

        // The invariant this test was written for still holds, and is now
        // stated precisely. An endpoint's ASSERTED MOS (1.5 here) must never
        // become the number sipnab shows — that is MosProvenance's whole
        // point. What the far end reports about the PATH is different: with no
        // operator-declared delay, its round trip is better evidence than a
        // build-time guess, so the estimate is recomputed and the line says
        // where the delay came from.
        assert!(
            !still.contains("1.5"),
            "the endpoint's asserted MOS must not become the displayed \
             estimate; got: {still}"
        );
        assert!(
            still.contains("per far end"),
            "when the estimate moves because the far end reported a round \
             trip, the line must say so — an operator cannot otherwise tell \
             a number resting on their own figure from one resting on a \
             remote claim; got: {still}"
        );
        assert!(
            estimated.contains("assumed"),
            "before any report arrives the delay is assumed, and saying so is \
             the difference between an estimate and a measurement; got: {estimated}"
        );
        assert!(
            after.contains("MOS-LQ: 1.5"),
            "and the endpoint's claim is still shown, separately: {after}"
        );
    }

    /// Edge case: a long quality history must not emit one sparkline glyph per
    /// interval — that overflows the pane, truncating both the newest glyphs
    /// and the trailing "(avg: …)" annotation off-screen. Downsampling to the
    /// most recent, pane-width-bounded intervals keeps the full row (label +
    /// glyphs + average) inside the pane, so the average stays visible.
    #[test]
    fn long_history_sparkline_stays_within_pane_width() {
        use crate::rtp::stream::{QualityInterval, RtpStream};

        let ssrc = 0x4444_4444u32;
        let key = StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let mut stream = RtpStream::new(key.clone(), &rtp_header(ssrc, 1, 0), t0);
        // Far more intervals than any terminal is wide.
        for i in 0..500u32 {
            stream.quality_intervals.push(QualityInterval {
                timestamp: t0 + TimeDelta::seconds(5 * i64::from(i)),
                jitter_ms: 10.0,
                loss_pct: 1.0,
                packets: 250,
            });
        }
        let mut store = StreamStore::new(16);
        store.insert_for_test(stream);

        let width: u16 = 100;
        let theme = Theme::default();
        let backend = TestBackend::new(width, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_stream_detail(
                    frame,
                    area,
                    &key,
                    &store,
                    0,
                    &StreamDetailDisplay {
                        declared_one_way_delay_ms: None,
                        theme: &theme,
                        resolver: &crate::names::NameResolver::new(),
                        name_mode: crate::names::NameMode::Off,
                    },
                );
            })
            .unwrap();

        let buf = terminal.backend().buffer();
        let area = buf.area;
        let find_row = |pred: &dyn Fn(&str) -> bool| -> Option<String> {
            for y in 0..area.height {
                let mut line = String::new();
                for x in 0..area.width {
                    line.push_str(buf.cell((x, y)).unwrap().symbol());
                }
                if pred(&line) {
                    return Some(line);
                }
            }
            None
        };

        // The MOS sparkline row keeps its trailing average visible — only
        // possible if the glyph run was bounded to the pane width.
        let mos_row =
            find_row(&|l| l.contains("MOS Trend:")).expect("MOS trend sparkline row missing");
        assert!(
            mos_row.contains("avg:"),
            "MOS trend average pushed off-pane by an unbounded sparkline: {mos_row:?}"
        );
        // The jitter sparkline row carries the only "(avg: …ms)" annotation;
        // its presence proves the jitter average also stayed within the pane.
        let jitter_row = find_row(&|l| l.contains("avg:") && l.contains("ms)"))
            .expect("jitter trend average pushed off-pane by an unbounded sparkline");
        assert!(jitter_row.contains("avg:"));
    }
}
