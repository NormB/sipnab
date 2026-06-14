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
            let msg =
                Paragraph::new("Stream no longer available.").style(Style::default().fg(theme.bad));
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
            stream.key.src.to_string(),
            Style::default().fg(theme.accent),
        ),
        Span::raw(" → "),
        Span::styled(
            stream.key.dst.to_string(),
            Style::default().fg(theme.accent),
        ),
        Span::raw("  Dialog: "),
        Span::raw(stream.associated_dialog.as_deref().unwrap_or("(orphaned)")),
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
        Style::default()
            .fg(theme.warning)
            .add_modifier(Modifier::BOLD)
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
        Span::styled(
            format!("{:.1}ms", stream.jitter),
            jitter_style(stream.jitter, theme),
        ),
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
        for &m in &mos_values {
            let ch = mos_to_block(m);
            let color = if m >= 4.0 {
                theme.good
            } else if m >= 3.0 {
                theme.warning
            } else {
                theme.bad
            };
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
        for &j in &jitter_values {
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
        Span::styled("─".repeat(50), Style::default().fg(theme.border)),
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

/// Map a MOS value (1.0–4.5) to a Unicode block character.
fn mos_to_block(mos: f64) -> char {
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
fn jitter_to_block(jitter_ms: f64) -> char {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn jitter_style_thresholds() {
        let theme = Theme::default();
        // < 20ms → good
        assert_eq!(jitter_style(0.0, &theme).fg, Some(theme.good));
        assert_eq!(jitter_style(19.9, &theme).fg, Some(theme.good));
        // 20..50ms → warning
        assert_eq!(jitter_style(20.0, &theme).fg, Some(theme.warning));
        assert_eq!(jitter_style(49.9, &theme).fg, Some(theme.warning));
        // >= 50ms → bad
        assert_eq!(jitter_style(50.0, &theme).fg, Some(theme.bad));
        assert_eq!(jitter_style(120.0, &theme).fg, Some(theme.bad));
    }

    #[test]
    fn loss_style_thresholds() {
        let theme = Theme::default();
        // < 0.5% → good
        assert_eq!(loss_style(0.0, &theme).fg, Some(theme.good));
        assert_eq!(loss_style(0.49, &theme).fg, Some(theme.good));
        // 0.5..2.0% → warning
        assert_eq!(loss_style(0.5, &theme).fg, Some(theme.warning));
        assert_eq!(loss_style(1.99, &theme).fg, Some(theme.warning));
        // >= 2.0% → bad
        assert_eq!(loss_style(2.0, &theme).fg, Some(theme.bad));
        assert_eq!(loss_style(75.0, &theme).fg, Some(theme.bad));
    }

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

    fn parsed(src_port: u16, dst_port: u16, ts: DateTime<Utc>) -> ParsedPacket {
        ParsedPacket {
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
        }
    }

    /// Build a store holding one PCMU stream, then inject RTCP-reported
    /// jitter/loss so the render path exercises the chosen style branch.
    /// Returns the store and the key of the inserted stream.
    fn store_with_stream(ssrc: u32, jitter: u32, lost: u32) -> (StreamStore, StreamKey) {
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
        store.process_rtcp(&[rr]);

        let key = StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        (store, key)
    }

    fn render_to_string(store: &StreamStore, key: &StreamKey) -> String {
        let theme = Theme::default();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_stream_detail(frame, area, key, store, 0, &theme);
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
                render_stream_detail(frame, area, &key, &store, 0, &theme);
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
        store.process_rtcp(&[rr]);
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
}
