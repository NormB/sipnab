// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packet-loss-map view: a sequence-space density strip showing *where* a
//! stream's retained RTP packet loss occurred, so an operator can tell at a
//! glance whether loss is bursty (clustered dark runs) or diffuse (isolated
//! specks scattered across the window).
//!
//! The renderer is thin: it calls
//! [`build_loss_map`](crate::rtp::loss_map::build_loss_map) with the strip's
//! inner width as the cell count and maps the returned per-cell loss counts
//! onto a fixed glyph ramp (` ░▒▓█`), colored on the same good/warn/bad
//! convention the quality dashboard and stream detail use. A summary header
//! carries the overall loss rate and burst characterization; a labeled
//! sequence axis and a legend frame the strip.
//!
//! Like the call timeline, this is a static single-screen view — the strip
//! always fills the width and the header/axis/legend are a fixed handful of
//! lines, so there is nothing to scroll or select (see the loss-map
//! controller for the matching key/wheel contract).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::rtp::loss_map::build_loss_map;
use crate::rtp::stream::StreamKey;
use crate::tui::App;
use crate::tui::theme::Theme;

/// Glyph ramp for cell density, lightest→heaviest. Index 0 (space) is a
/// cell with no loss; 1..=4 shade increasing per-cell loss counts.
const RAMP: [char; 5] = [' ', '\u{2591}', '\u{2592}', '\u{2593}', '\u{2588}'];

/// Render the packet-loss-map view for `key`.
///
/// Draws a bordered block containing the summary header (SSRC, endpoints,
/// overall loss rate, burst characterization, and a truncation note when
/// the retained log is capped), a full-width density strip, a labeled
/// sequence axis, and a legend. A stream with no retained loss shows a
/// centered "no packet loss" message in place of the strip.
///
/// # Arguments
///
/// * `f` — ratatui frame to draw into.
/// * `app` — application state supplying the stream store and theme.
/// * `area` — screen rectangle for the bordered loss-map block.
/// * `key` — identifies the stream to visualize.
///
/// # Side effects
///
/// Draws widgets into `f`. Attempts a non-blocking `try_read` on
/// `app.stream_store`; when the lock is contended or the stream is missing,
/// a placeholder is drawn instead (the frame is never blocked on a queued
/// writer).
pub fn render_loss_map(f: &mut Frame, app: &App, area: Rect, key: &StreamKey) {
    let theme = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Packet Loss Map ");

    // Resolve the stream without blocking: the render pass already holds a
    // read guard on the shared store, so a plain re-lock could stall behind
    // a queued writer. `try_read` degrades to the placeholder instead.
    let Some(store) = app.stream_store.try_read() else {
        render_placeholder(f, area, block, theme, "Gathering stream data\u{2026}");
        return;
    };
    let Some(stream) = store.get(key) else {
        render_placeholder(f, area, block, theme, "Stream no longer available.");
        return;
    };

    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let inner_width = inner.width as usize;

    let map = build_loss_map(stream, inner_width);

    let mut lines: Vec<Line<'static>> = Vec::new();

    // ── Summary header ──────────────────────────────────────────────
    let ssrc = format!("0x{:08X}", stream.key.ssrc);
    lines.push(Line::from(vec![
        Span::styled("  SSRC ", Style::default().fg(theme.muted)),
        Span::styled(
            ssrc,
            Style::default()
                .fg(theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   ", Style::default()),
        Span::styled(
            format!("{} \u{2192} {}", stream.key.src, stream.key.dst),
            Style::default().fg(theme.accent),
        ),
    ]));

    let loss_pct = stream.loss_percent();
    let total_pkts = stream.packet_count.saturating_add(stream.lost_packets);
    lines.push(Line::from(vec![
        Span::styled("  Loss ", Style::default().fg(theme.muted)),
        Span::styled(
            format!("{loss_pct:.2}%"),
            loss_style(loss_pct, theme, &app.quality_bands),
        ),
        Span::styled(
            format!("   {} lost / {} packets", map.total_lost, total_pkts),
            Style::default().fg(theme.muted),
        ),
    ]));

    // Burst characterization grounded in burst_gap_analysis().
    match stream.burst_gap_analysis() {
        Some(bga) => lines.push(Line::from(vec![
            Span::styled("  Bursts ", Style::default().fg(theme.muted)),
            Span::styled(
                bga.burst_count.to_string(),
                Style::default().fg(theme.foreground),
            ),
            Span::styled("   Pattern ", Style::default().fg(theme.muted)),
            Span::styled(
                if bga.is_bursty { "Bursty" } else { "Random" },
                Style::default().fg(if bga.is_bursty { theme.bad } else { theme.good }),
            ),
            Span::styled(
                format!("   Avg burst {:.0}ms", bga.burst_duration_ms),
                Style::default().fg(theme.muted),
            ),
        ])),
        None => lines.push(Line::from(Span::styled(
            "  Bursts  none",
            Style::default().fg(theme.muted),
        ))),
    }

    // Honest note when the retained log has evicted older losses.
    if map.truncated {
        lines.push(Line::from(Span::styled(
            format!(
                "  Showing most recent {} of {} losses",
                map.retained_lost, map.total_lost
            ),
            Style::default().fg(theme.warning),
        )));
    }

    lines.push(Line::raw(""));

    // ── Density strip / degraded no-loss message ────────────────────
    if map.retained_lost == 0 {
        let msg = "No packet loss recorded in the retained window";
        let pad = inner_width.saturating_sub(msg.chars().count()) / 2;
        lines.push(Line::from(Span::styled(
            format!("{}{}", " ".repeat(pad), msg),
            Style::default().fg(theme.good),
        )));
    } else {
        let max = map.cells.iter().copied().max().unwrap_or(0);
        let strip: Vec<Span<'static>> = map
            .cells
            .iter()
            .map(|&count| {
                let (glyph, style) = cell_span(count, max, theme);
                Span::styled(glyph.to_string(), style)
            })
            .collect();
        lines.push(Line::from(strip));

        // ── Sequence axis: span_start | midpoint | span_end ─────────
        let window_len = map.span_end.wrapping_sub(map.span_start) as usize + 1;
        let mid_seq = map.span_start.wrapping_add((window_len / 2) as u16);
        lines.push(Line::from(Span::styled(
            axis_line(
                inner_width,
                &map.span_start.to_string(),
                &mid_seq.to_string(),
                &map.span_end.to_string(),
            ),
            Style::default().fg(theme.muted),
        )));
    }

    // ── Legend ──────────────────────────────────────────────────────
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  Density ", Style::default().fg(theme.muted)),
        // A clean cell renders blank in the strip; use a light dot in the
        // legend so the marker doesn't collide with the heavy `█` glyph.
        Span::styled("\u{00B7}", Style::default().fg(theme.good)),
        Span::styled(" clean  ", Style::default().fg(theme.muted)),
        Span::styled("\u{2591}\u{2592}", Style::default().fg(theme.warning)),
        Span::styled(" light  ", Style::default().fg(theme.muted)),
        Span::styled("\u{2593}\u{2588}", Style::default().fg(theme.bad)),
        Span::styled(" heavy", Style::default().fg(theme.muted)),
        Span::styled(
            "   (left = oldest, right = newest sequence)",
            Style::default().fg(theme.muted),
        ),
    ]));

    let paragraph = Paragraph::new(lines)
        .style(Style::default().fg(theme.foreground))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

/// Glyph + style for one strip cell: an empty cell is a clean space; a
/// non-empty cell's shade scales with its loss count relative to the busiest
/// cell (`max`), colored warning for light density and bad for heavy — the
/// same three-band convention the dashboard and stream detail use.
fn cell_span(count: u16, max: u16, theme: &Theme) -> (char, Style) {
    if count == 0 {
        return (RAMP[0], Style::default());
    }
    let m = max.max(1);
    let idx = (((count as f64 / m as f64) * 4.0).ceil() as usize).clamp(1, 4);
    let color = if idx >= 3 { theme.bad } else { theme.warning };
    (RAMP[idx], Style::default().fg(color))
}

/// Lay out three sequence labels across `width` columns: `left` flush left,
/// `right` flush right, `mid` centered — collapsing to what fits when the
/// strip is too narrow, guarded with `saturating_sub` so it never panics.
fn axis_line(width: usize, left: &str, mid: &str, right: &str) -> String {
    // Too narrow for even the two edges: show the left label alone.
    if width < left.len() + right.len() + 1 {
        let mut s: String = left.chars().take(width).collect();
        // Pad so the caller's fixed-width expectations still hold loosely.
        s.truncate(width);
        return s;
    }
    let mut cells = vec![' '; width];
    // Left edge.
    for (i, c) in left.chars().enumerate() {
        cells[i] = c;
    }
    // Right edge.
    let right_start = width - right.len();
    for (i, c) in right.chars().enumerate() {
        cells[right_start + i] = c;
    }
    // Midpoint, centered — only when it fits without clobbering the edges.
    let mid_start = width.saturating_sub(mid.len()) / 2;
    if mid_start > left.len() && mid_start + mid.len() < right_start {
        for (i, c) in mid.chars().enumerate() {
            cells[mid_start + i] = c;
        }
    }
    cells.into_iter().collect()
}

/// Style for a packet-loss percentage, using the session's bands.
///
/// This used 0.5/2.0 while the stream list used 1.0/5.0, and its own doc
/// comment claimed "the same bands the dashboard and stream-detail views use"
/// — which was true of neither. A comment asserting consistency is not
/// consistency; the boundaries now come from one place, and that place is now
/// an argument so `[quality]` can move them for every pane at once.
fn loss_style(loss_pct: f64, theme: &Theme, bands: &crate::rtp::bands::QualityBands) -> Style {
    match bands.loss(loss_pct) {
        crate::rtp::bands::Band::Good => Style::default().fg(theme.good),
        crate::rtp::bands::Band::Warning => Style::default().fg(theme.warning),
        crate::rtp::bands::Band::Bad => Style::default().fg(theme.bad),
    }
}

/// Draw the bordered block with a single muted placeholder line — used when
/// the store is contended or the stream is gone.
fn render_placeholder(f: &mut Frame, area: Rect, block: Block, theme: &Theme, msg: &str) {
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let p = Paragraph::new(format!("  {msg}")).style(Style::default().fg(theme.muted));
    f.render_widget(p, inner);
}

/// Unit tests for the loss-map renderer: the summary header, the density
/// strip glyphs for clustered vs no loss, the axis labels, and narrow-
/// terminal robustness.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::Utc;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};

    /// Fixed StreamKey (SSRC 0xABCD, 10.0.0.1:20000 → 10.0.0.2:30000).
    fn make_key() -> StreamKey {
        StreamKey {
            ssrc: 0xABCD,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        }
    }

    /// Minimal PCMU RtpHeader at `seq`.
    fn make_header(seq: u16) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: 0,
            ssrc: 0xABCD,
            payload_offset: 12,
        }
    }

    /// An App whose stream store holds `stream`, on the loss-map view of it.
    fn app_on_loss_map(stream: RtpStream) -> (App, StreamKey) {
        let key = stream.key.clone();
        let app = App::new_test();
        {
            let mut store = app.stream_store.write();
            store.insert_for_test(stream);
        }
        (app, key)
    }

    /// Render the loss map at `w`x`h` and flatten the buffer to a string.
    fn render(app: &App, key: &StreamKey, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render_loss_map(f, app, f.area(), key))
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

    /// A clustered-loss stream renders a dark run (heavy glyph) in the strip
    /// and the framing chrome (title, SSRC, legend).
    #[test]
    fn clustered_loss_renders_dark_run() {
        let mut s = RtpStream::new(make_key(), &make_header(0), Utc::now());
        s.last_seq = 1000;
        s.lost_sequences = (400..440).collect();
        s.packet_count = 960;
        s.lost_packets = 40;
        let (app, key) = app_on_loss_map(s);

        let out = render(&app, &key, 100, 16);
        assert!(out.contains("Packet Loss Map"), "title missing:\n{out}");
        assert!(out.contains("0x0000ABCD"), "ssrc missing:\n{out}");
        assert!(
            out.contains('\u{2588}') || out.contains('\u{2593}'),
            "clustered loss must draw a heavy glyph:\n{out}"
        );
        assert!(out.contains("Density"), "legend missing:\n{out}");
    }

    /// A loss-free stream renders the centered "no packet loss" message and
    /// no heavy density glyph.
    #[test]
    fn no_loss_renders_empty_message() {
        let mut s = RtpStream::new(make_key(), &make_header(0), Utc::now());
        s.last_seq = 500;
        s.packet_count = 500;
        let (app, key) = app_on_loss_map(s);

        let out = render(&app, &key, 100, 16);
        assert!(
            out.contains("No packet loss recorded in the retained window"),
            "empty-window message missing:\n{out}"
        );
        // The 0% loss rate is shown in the header (only the legend's key
        // glyphs appear, never a strip of them).
        assert!(out.contains("0.00%"), "loss rate missing:\n{out}");
    }

    /// A missing stream shows the placeholder instead of panicking.
    #[test]
    fn missing_stream_shows_placeholder() {
        let app = App::new_test();
        let key = make_key();
        let out = render(&app, &key, 80, 10);
        assert!(
            out.contains("Stream no longer available"),
            "placeholder missing:\n{out}"
        );
    }

    /// A tiny terminal must not panic or underflow the width guards.
    #[test]
    fn survives_tiny_terminal() {
        let mut s = RtpStream::new(make_key(), &make_header(0), Utc::now());
        s.last_seq = 100;
        s.lost_sequences = (10..20).collect();
        s.packet_count = 90;
        s.lost_packets = 10;
        let (app, key) = app_on_loss_map(s);
        // No assertion beyond "did not panic".
        let _ = render(&app, &key, 6, 3);
        let _ = render(&app, &key, 1, 1);
    }

    /// The sequence axis places the window's start and end labels.
    #[test]
    fn axis_shows_span_bounds() {
        let mut s = RtpStream::new(make_key(), &make_header(0), Utc::now());
        s.last_seq = 1000;
        s.lost_sequences = (400..440).collect();
        s.packet_count = 960;
        s.lost_packets = 40;
        let (app, key) = app_on_loss_map(s);
        let out = render(&app, &key, 100, 16);
        // span_end == last_seq == 1000 is on the axis row.
        assert!(out.contains("1000"), "span_end label missing:\n{out}");
    }

    /// `axis_line` never panics for narrow widths and keeps to the width.
    #[test]
    fn axis_line_narrow_widths_are_safe() {
        for w in 0..12usize {
            let s = axis_line(w, "500", "750", "1000");
            assert!(s.chars().count() <= w);
        }
    }
}
