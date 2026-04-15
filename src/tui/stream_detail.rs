//! RTP stream detail view — full quality metrics for a single stream.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::rtp::quality::estimate_mos;
use crate::rtp::stream::StreamKey;
use crate::rtp::stream_store::StreamStore;

use super::Theme;

/// Render a full-screen scrollable detail view for a single RTP stream.
pub fn render_stream_detail(
    frame: &mut ratatui::Frame,
    area: Rect,
    key: &StreamKey,
    store: &StreamStore,
    scroll: usize,
    theme: &Theme,
) {
    let stream = match store.get(key) {
        Some(s) => s,
        None => {
            let msg = Paragraph::new("Stream no longer available.")
                .style(Style::default().fg(theme.bad));
            frame.render_widget(msg, area);
            return;
        }
    };

    let mut lines: Vec<Line<'_>> = Vec::with_capacity(60);

    // ── Header ──────────────────────────────────────────────────────
    let ssrc = format!("0x{:08X}", stream.key.ssrc);
    let codec_str = stream.codec.as_deref().unwrap_or("Unknown");
    let pt = stream.payload_type;
    let clock = stream.clock_rate;

    lines.push(Line::from(vec![
        Span::styled("RTP Stream Detail", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::raw("  SSRC: "),
        Span::styled(&ssrc, Style::default().fg(theme.header)),
        Span::raw("  Codec: "),
        Span::styled(format!("{codec_str}/{clock}"), Style::default().fg(theme.header)),
        Span::raw(format!("  PT: {pt}")),
    ]));

    lines.push(Line::from(vec![
        Span::styled(stream.key.src.to_string(), Style::default().fg(theme.accent)),
        Span::raw(" → "),
        Span::styled(stream.key.dst.to_string(), Style::default().fg(theme.accent)),
        Span::raw("  Dialog: "),
        Span::raw(
            stream
                .associated_dialog
                .as_deref()
                .unwrap_or("(orphaned)"),
        ),
    ]));

    lines.push(Line::raw(""));

    // ── Quality Metrics ─────────────────────────────────────────────
    let total = stream.packet_count + stream.lost_packets;
    let loss_pct = if total > 0 {
        (stream.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let mos = estimate_mos(stream.jitter, loss_pct, stream.codec.as_deref());

    let mos_style = if mos >= 4.0 {
        Style::default().fg(theme.good).add_modifier(Modifier::BOLD)
    } else if mos >= 3.0 {
        Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.bad).add_modifier(Modifier::BOLD)
    };

    let mos_label = if mos >= 4.0 {
        "Good"
    } else if mos >= 3.5 {
        "Fair"
    } else if mos >= 3.0 {
        "Poor"
    } else {
        "Bad"
    };

    lines.push(section_header("Quality", theme));

    lines.push(Line::from(vec![
        Span::raw("  MOS: "),
        Span::styled(format!("{mos:.1} ({mos_label})"), mos_style),
        Span::raw("    Jitter: "),
        Span::styled(format!("{:.1}ms", stream.jitter), jitter_style(stream.jitter, theme)),
        Span::raw("    Loss: "),
        Span::styled(format!("{loss_pct:.2}%"), loss_style(loss_pct, theme)),
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
        Span::styled(stream.packet_count.to_string(), Style::default().fg(theme.header)),
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
                Span::styled(format!("{:<10.1}ms ", qi.jitter_ms), jitter_style(qi.jitter_ms, theme)),
                Span::styled(format!("{:<10.2}% ", qi.loss_pct), loss_style(qi.loss_pct, theme)),
                Span::raw(format!("{:<10} ", qi.packets)),
                Span::styled(
                    format!("{qi_mos:.1}"),
                    if qi_mos >= 4.0 {
                        Style::default().fg(theme.good)
                    } else if qi_mos >= 3.0 {
                        Style::default().fg(theme.warning)
                    } else {
                        Style::default().fg(theme.bad)
                    },
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
                Span::styled(bga.burst_count.to_string(), Style::default().fg(theme.warning)),
                Span::raw("    Burst duration: "),
                Span::raw(format!("{:.0}ms", bga.burst_duration_ms)),
                Span::raw("    Gap duration: "),
                Span::raw(format!("{:.1}s", bga.gap_duration_ms / 1000.0)),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  Burst loss rate: "),
                Span::styled(format!("{:.1}%", bga.burst_loss_rate * 100.0), Style::default().fg(theme.bad)),
                Span::raw("    Gap loss rate: "),
                Span::raw(format!("{:.1}%", bga.gap_loss_rate * 100.0)),
                Span::raw("    Pattern: "),
                Span::styled(
                    if bga.is_bursty { "Bursty" } else { "Random" },
                    if bga.is_bursty {
                        Style::default().fg(theme.warning).add_modifier(Modifier::BOLD)
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

    // ── Render with scroll ──────────────────────────────────────────
    let visible_height = area.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let effective_scroll = scroll.min(max_scroll);

    let para = Paragraph::new(lines).scroll((effective_scroll as u16, 0));
    frame.render_widget(para, area);
}

// ── Helpers ─────────────────────────────────────────────────────────

fn section_header<'a>(title: &'a str, theme: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("── {title} "),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "─".repeat(50),
            Style::default().fg(theme.border),
        ),
    ])
}

fn jitter_style(jitter_ms: f64, theme: &Theme) -> Style {
    if jitter_ms < 20.0 {
        Style::default().fg(theme.good)
    } else if jitter_ms < 50.0 {
        Style::default().fg(theme.warning)
    } else {
        Style::default().fg(theme.bad)
    }
}

fn loss_style(loss_pct: f64, theme: &Theme) -> Style {
    if loss_pct < 0.5 {
        Style::default().fg(theme.good)
    } else if loss_pct < 2.0 {
        Style::default().fg(theme.warning)
    } else {
        Style::default().fg(theme.bad)
    }
}
