// SPDX-License-Identifier: MIT OR Apache-2.0

//! Aggregation core for the live call-quality dashboard.
//!
//! Pure data layer: ranks every tracked RTP stream by current MOS and
//! precomputes the per-stream trend series the dashboard view draws.
//! No locking and no rendering here — the renderer receives an
//! already-built `DashboardSnapshot` so the draw pass stays read-only
//! (skip-tick contract). Also home to `render_dashboard`, which draws
//! the summary strip, worst-first stream table, per-stream trend rows,
//! and legend from that cached snapshot.

use crate::rtp::quality::estimate_mos;
use crate::rtp::stream::{RtpStream, StreamKey};
use crate::rtp::stream_store::StreamStore;
use crate::tui::App;

/// One point of a per-stream quality trend (one 5 s quality interval).
#[derive(Debug, Clone, PartialEq)]
pub struct TrendPoint {
    /// Estimated MOS for the interval.
    pub mos: f64,
    /// Average jitter during the interval (milliseconds).
    pub jitter_ms: f64,
    /// Packet loss percentage during the interval.
    pub loss_pct: f64,
}

/// Current health of a single RTP stream, ready for table display.
#[derive(Debug, Clone)]
pub struct StreamHealth {
    /// Identity of the stream.
    pub key: StreamKey,
    /// SIP Call-ID when the stream is linked to a dialog.
    pub call_id: Option<String>,
    /// Codec name, if known.
    pub codec: Option<String>,
    /// Current estimated MOS from running jitter/loss.
    pub mos: f64,
    /// Running RFC 3550 jitter (milliseconds).
    pub jitter_ms: f64,
    /// Cumulative packet loss percentage.
    pub loss_pct: f64,
    /// Total packets received.
    pub packets: u64,
    /// `true` if the stream saw traffic in the last 30 s.
    pub active: bool,
    /// Per-interval trend, oldest first.
    pub trend: Vec<TrendPoint>,
}

/// Aggregate view over every stream in the store, worst quality first.
#[derive(Debug, Clone, Default)]
pub struct DashboardSnapshot {
    /// Total streams tracked.
    pub total_streams: usize,
    /// Streams active within the last 30 s.
    pub active_streams: usize,
    /// Mean MOS across all streams (`None` when empty).
    pub avg_mos: Option<f64>,
    /// Lowest MOS across all streams (`None` when empty).
    pub worst_mos: Option<f64>,
    /// Streams with any recorded packet loss.
    pub streams_with_loss: usize,
    /// Per-stream health rows, ascending MOS (worst first); ties broken
    /// by higher loss first, then by stream key for determinism.
    pub rows: Vec<StreamHealth>,
}

/// Cumulative loss percentage of a stream; `0.0` for an empty stream.
fn stream_loss_pct(s: &RtpStream) -> f64 {
    let total = s.packet_count + s.lost_packets;
    if total > 0 {
        (s.lost_packets as f64 / total as f64) * 100.0
    } else {
        0.0
    }
}

impl DashboardSnapshot {
    /// Build a snapshot from the stream store.
    ///
    /// Runs under the store read guard on the render path — O(streams)
    /// with no allocation beyond the output itself.
    ///
    /// # Arguments
    ///
    /// * `store` — stream store to aggregate; not mutated.
    ///
    /// # Returns
    ///
    /// A snapshot with one `StreamHealth` row per stream, sorted worst
    /// MOS first (ties: higher loss, then stream key), plus the derived
    /// totals; `avg_mos`/`worst_mos` are `None` when the store is empty.
    pub fn from_streams(store: &StreamStore) -> Self {
        let mut rows: Vec<StreamHealth> = store
            .iter()
            .map(|s| {
                let loss_pct = stream_loss_pct(s);
                let codec = s.codec.clone();
                let mos = estimate_mos(s.jitter, loss_pct, codec.as_deref());
                let trend = s
                    .quality_intervals
                    .iter()
                    .map(|qi| TrendPoint {
                        mos: estimate_mos(qi.jitter_ms, qi.loss_pct, codec.as_deref()),
                        jitter_ms: qi.jitter_ms,
                        loss_pct: qi.loss_pct,
                    })
                    .collect();
                StreamHealth {
                    key: s.key.clone(),
                    call_id: s.associated_dialog.clone(),
                    codec,
                    mos,
                    jitter_ms: s.jitter,
                    loss_pct,
                    packets: s.packet_count,
                    active: s.is_active(),
                    trend,
                }
            })
            .collect();

        rows.sort_by(|a, b| {
            a.mos
                .total_cmp(&b.mos)
                .then(b.loss_pct.total_cmp(&a.loss_pct))
                .then_with(|| {
                    (a.key.ssrc, a.key.src, a.key.dst).cmp(&(b.key.ssrc, b.key.src, b.key.dst))
                })
        });

        let total_streams = rows.len();
        let active_streams = rows.iter().filter(|r| r.active).count();
        let streams_with_loss = rows.iter().filter(|r| r.loss_pct > 0.0).count();
        let avg_mos = (total_streams > 0)
            .then(|| rows.iter().map(|r| r.mos).sum::<f64>() / total_streams as f64);
        let worst_mos = rows.first().map(|r| r.mos);

        Self {
            total_streams,
            active_streams,
            avg_mos,
            worst_mos,
            streams_with_loss,
            rows,
        }
    }
}

/// Map a packet-loss percentage to a Unicode block character.
///
/// Input is clamped to `[0, 100]`; NaN and negatives read as `0`
/// (baseline glyph ▁) and `100` (or above) saturates at the full block █.
/// Scale: 0 = ▁, ≥0.5 = ▂, ≥1 = ▃, ≥2 = ▄, ≥5 = ▅, ≥10 = ▆, ≥20 = ▇, ≥50 = █.
fn loss_to_block(loss_pct: f64) -> char {
    let clamped = if loss_pct.is_nan() || loss_pct < 0.0 {
        0.0
    } else if loss_pct > 100.0 {
        100.0
    } else {
        loss_pct
    };
    match clamped {
        l if l >= 50.0 => '\u{2588}', // █
        l if l >= 20.0 => '\u{2587}', // ▇
        l if l >= 10.0 => '\u{2586}', // ▆
        l if l >= 5.0 => '\u{2585}',  // ▅
        l if l >= 2.0 => '\u{2584}',  // ▄
        l if l >= 1.0 => '\u{2583}',  // ▃
        l if l >= 0.5 => '\u{2582}',  // ▂
        _ => '\u{2581}',              // ▁
    }
}

/// Render the live call-quality dashboard from the snapshot cached by
/// `sync_caches` (read-only pass — no store access, no locking).
///
/// Draws the summary strip, the worst-first stream table scrolled to
/// keep `app.dashboard_selected` visible, and — when a row is selected —
/// its MOS/jitter/loss trend sparklines plus a color legend. Before the
/// first snapshot exists, a "Gathering stream quality data" placeholder
/// is shown instead.
///
/// # Arguments
///
/// * `frame` — ratatui frame to draw into.
/// * `area` — screen rectangle for the bordered dashboard block.
/// * `app` — application state supplying `dashboard_snapshot`,
///   `dashboard_selected`, and the theme; not mutated.
///
/// # Side effects
///
/// Draws widgets into `frame` only.
pub fn render_dashboard(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    use crate::tui::stream_detail::{jitter_to_block, mos_to_block};
    use ratatui::style::{Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    let theme = &app.theme;
    let mut lines: Vec<Line<'_>> = Vec::new();

    let Some(snap) = app.dashboard_snapshot.as_ref() else {
        lines.push(Line::raw(""));
        lines.push(Line::raw("  Gathering stream quality data..."));
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Quality Dashboard ");
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    };

    let mos_style = |m: f64| {
        if m >= 4.0 {
            Style::default().fg(theme.good)
        } else if m >= 3.0 {
            Style::default().fg(theme.warning)
        } else {
            Style::default().fg(theme.bad)
        }
    };
    // Loss color bands mirror the stream-detail view: <0.5% good,
    // <2% warning, otherwise bad.
    let loss_color = |l: f64| {
        if l < 0.5 {
            theme.good
        } else if l < 2.0 {
            theme.warning
        } else {
            theme.bad
        }
    };

    // ── summary strip ───────────────────────────────────────────────
    let mut summary = vec![Span::raw(format!(
        "  Streams: {} ({} active)   ",
        snap.total_streams, snap.active_streams
    ))];
    match (snap.avg_mos, snap.worst_mos) {
        (Some(avg), Some(worst)) => {
            summary.push(Span::raw("Avg MOS: "));
            summary.push(Span::styled(format!("{avg:.1}"), mos_style(avg)));
            summary.push(Span::raw("   Worst: "));
            summary.push(Span::styled(format!("{worst:.1}"), mos_style(worst)));
        }
        _ => summary.push(Span::styled(
            "No RTP streams yet",
            Style::default().fg(theme.muted),
        )),
    }
    summary.push(Span::raw(format!(
        "   With loss: {}",
        snap.streams_with_loss
    )));
    lines.push(Line::raw(""));
    lines.push(Line::from(summary));
    lines.push(Line::raw(""));

    // ── worst-streams table ─────────────────────────────────────────
    lines.push(Line::styled(
        format!(
            "    {:<5} {:>8} {:>7} {:>9}  {:<8} {}",
            "MOS", "Jitter", "Loss%", "Packets", "Codec", "Stream"
        ),
        Style::default().fg(theme.muted),
    ));

    // Fixed overhead: 4 lines above + MOS/jitter/loss trend + legend + borders.
    let visible = (area.height as usize).saturating_sub(13).max(1);
    // Keep the selection in view with context above and below rather than
    // pinning it to the bottom row: center it in the window, clamped so the
    // window stays within the row range.
    let total = snap.rows.len();
    let first = if total <= visible {
        0
    } else {
        app.dashboard_selected
            .saturating_sub(visible / 2)
            .min(total - visible)
    };
    for (i, row) in snap.rows.iter().enumerate().skip(first).take(visible) {
        let selected = i == app.dashboard_selected;
        let marker = if selected { "▶ " } else { "  " };
        let activity = if row.active { "●" } else { "·" };
        let who = row
            .call_id
            .clone()
            .unwrap_or_else(|| format!("{} → {}", row.key.src, row.key.dst));
        let text = format!(
            "{marker}{activity} {:<5.1} {:>6.1}ms {:>6.2} {:>9}  {:<8} {}",
            row.mos,
            row.jitter_ms,
            row.loss_pct,
            row.packets,
            row.codec.as_deref().unwrap_or("?"),
            who,
        );
        let style = if selected {
            mos_style(row.mos).add_modifier(Modifier::REVERSED)
        } else {
            mos_style(row.mos)
        };
        lines.push(Line::styled(text, style));
    }

    // ── trend for the selected stream ───────────────────────────────
    if let Some(row) = snap.rows.get(app.dashboard_selected) {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "  Trend (selected, 5s intervals, oldest → newest)",
            Style::default().fg(theme.muted),
        ));
        let mut mos_spans = vec![Span::styled("  MOS:    ", Style::default().fg(theme.muted))];
        let mut jit_spans = vec![Span::styled("  Jitter: ", Style::default().fg(theme.muted))];
        let mut loss_spans = vec![Span::styled("  Loss:   ", Style::default().fg(theme.muted))];
        for p in &row.trend {
            mos_spans.push(Span::styled(
                String::from(mos_to_block(p.mos)),
                mos_style(p.mos),
            ));
            let jcolor = if p.jitter_ms < 20.0 {
                theme.good
            } else if p.jitter_ms < 50.0 {
                theme.warning
            } else {
                theme.bad
            };
            jit_spans.push(Span::styled(
                String::from(jitter_to_block(p.jitter_ms)),
                Style::default().fg(jcolor),
            ));
            loss_spans.push(Span::styled(
                String::from(loss_to_block(p.loss_pct)),
                Style::default().fg(loss_color(p.loss_pct)),
            ));
        }
        if row.trend.is_empty() {
            let none = Span::styled(
                "(no completed intervals yet)",
                Style::default().fg(theme.muted),
            );
            mos_spans.push(none.clone());
            jit_spans.push(none.clone());
            loss_spans.push(none);
        }
        lines.push(Line::from(mos_spans));
        lines.push(Line::from(jit_spans));
        lines.push(Line::from(loss_spans));

        // Legend: metric names with units and the good/warn/bad color keys.
        // Rendered as a single line so a narrow terminal clips it rather
        // than wrapping or overflowing.
        lines.push(Line::from(vec![
            Span::styled("  Legend: ", Style::default().fg(theme.muted)),
            Span::styled("MOS 1–5", Style::default().fg(theme.muted)),
            Span::raw("  "),
            Span::styled("Jitter ms", Style::default().fg(theme.muted)),
            Span::raw("  "),
            Span::styled("Loss %", Style::default().fg(theme.muted)),
            Span::raw("   "),
            Span::styled("\u{2588}", Style::default().fg(theme.good)),
            Span::styled(" good  ", Style::default().fg(theme.muted)),
            Span::styled("\u{2588}", Style::default().fg(theme.warning)),
            Span::styled(" warn  ", Style::default().fg(theme.muted)),
            Span::styled("\u{2588}", Style::default().fg(theme.bad)),
            Span::styled(" bad", Style::default().fg(theme.muted)),
        ]));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Quality Dashboard ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

/// Tests for snapshot aggregation (ranking, totals, trend building),
/// the loss-glyph mapping, and rendering against a test backend.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::parser::RtpHeader;
    use chrono::{Duration, Utc};
    use std::net::SocketAddr;

    /// Minimal PCMU RTP header with the given sequence and RTP timestamp.
    fn header(seq: u16, ts: u32) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0, // PCMU
            sequence: seq,
            timestamp: ts,
            ssrc: 0xABCD,
            payload_offset: 12,
        }
    }

    /// Test socket address 192.0.2.10 with the given port.
    fn addr(port: u16) -> SocketAddr {
        format!("192.0.2.10:{port}").parse().unwrap()
    }

    /// A stream with `n` clean packets ending "now" (active).
    fn clean_stream(ssrc: u32, n: u16) -> RtpStream {
        let start = Utc::now();
        let key = StreamKey {
            ssrc,
            src: addr(10000),
            dst: addr(20000),
        };
        let mut s = RtpStream::new(key, &header(0, 0), start);
        for i in 1..n {
            s.update(
                &header(i, u32::from(i) * 160),
                start + Duration::milliseconds(i64::from(i) * 20),
                160,
            );
        }
        s
    }

    /// Stream store preloaded with the given streams.
    fn store_with(streams: Vec<RtpStream>) -> StreamStore {
        let mut store = StreamStore::new(64);
        for s in streams {
            store.insert_for_test(s);
        }
        store
    }

    /// An empty store yields zeroed totals, `None` MOS aggregates, and
    /// no rows.
    #[test]
    fn empty_store_yields_empty_snapshot() {
        let snap = DashboardSnapshot::from_streams(&StreamStore::new(64));
        assert_eq!(snap.total_streams, 0);
        assert_eq!(snap.active_streams, 0);
        assert_eq!(snap.avg_mos, None);
        assert_eq!(snap.worst_mos, None);
        assert_eq!(snap.streams_with_loss, 0);
        assert!(snap.rows.is_empty());
    }

    /// One clean PCMU stream scores MOS > 4.0 and its row equals both
    /// the average and worst aggregates.
    #[test]
    fn single_clean_stream_scores_high_and_matches_aggregates() {
        let snap = DashboardSnapshot::from_streams(&store_with(vec![clean_stream(1, 50)]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.active_streams, 1);
        assert_eq!(snap.streams_with_loss, 0);
        assert_eq!(snap.rows.len(), 1);
        let row = &snap.rows[0];
        assert!(
            row.mos > 4.0,
            "clean PCMU stream must score >4.0, got {}",
            row.mos
        );
        assert_eq!(row.loss_pct, 0.0);
        assert_eq!(snap.avg_mos, Some(row.mos));
        assert_eq!(snap.worst_mos, Some(row.mos));
        assert!(row.active);
        assert_eq!(row.call_id, None);
    }

    /// A ~33%-loss stream ranks ahead of a clean one, is counted in
    /// streams_with_loss, and drives worst_mos and the average.
    #[test]
    fn lossy_stream_ranks_first_and_is_counted() {
        let clean = clean_stream(1, 50);
        let mut lossy = clean_stream(2, 50);
        lossy.lost_packets = 25; // ~33% loss
        let snap = DashboardSnapshot::from_streams(&store_with(vec![clean, lossy]));
        assert_eq!(snap.total_streams, 2);
        assert_eq!(snap.streams_with_loss, 1);
        assert_eq!(snap.rows.len(), 2);
        assert_eq!(
            snap.rows[0].key.ssrc, 2,
            "worst (lossy) stream must rank first"
        );
        assert!(snap.rows[0].mos < snap.rows[1].mos);
        assert!(snap.rows[0].loss_pct > 30.0 && snap.rows[0].loss_pct < 35.0);
        assert_eq!(snap.worst_mos, Some(snap.rows[0].mos));
        let avg = (snap.rows[0].mos + snap.rows[1].mos) / 2.0;
        assert!((snap.avg_mos.unwrap() - avg).abs() < 1e-9);
    }

    /// A stream where everything was lost reports 100% loss with MOS
    /// still clamped at >= 1.0, without panicking.
    #[test]
    fn all_lost_stream_reports_full_loss_without_panicking() {
        // adversarial: every packet after the first was lost
        let mut s = clean_stream(3, 1);
        s.packet_count = 0; // hypothetical: nothing received
        s.lost_packets = 100;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        assert_eq!(snap.rows[0].loss_pct, 100.0);
        assert!(snap.rows[0].mos >= 1.0, "MOS stays clamped at >=1.0");
    }

    /// A stream object with no traffic at all yields 0% loss (no
    /// divide-by-zero).
    #[test]
    fn zero_packet_stream_is_handled() {
        // adversarial: a stream object with no traffic at all
        let mut s = clean_stream(4, 1);
        s.packet_count = 0;
        s.lost_packets = 0;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.rows[0].loss_pct, 0.0);
    }

    /// A dialog-linked stream carries its Call-ID into the row; an
    /// orphaned stream carries `None`.
    #[test]
    fn associated_dialog_and_orphan_flow_through() {
        let mut linked = clean_stream(5, 10);
        linked.associated_dialog = Some("call-1@example.com".into());
        let mut orphan = clean_stream(6, 10);
        orphan.orphaned = true;
        let snap = DashboardSnapshot::from_streams(&store_with(vec![linked, orphan]));
        let linked_row = snap.rows.iter().find(|r| r.key.ssrc == 5).unwrap();
        let orphan_row = snap.rows.iter().find(|r| r.key.ssrc == 6).unwrap();
        assert_eq!(linked_row.call_id.as_deref(), Some("call-1@example.com"));
        assert_eq!(orphan_row.call_id, None);
    }

    /// A stream idle for two minutes is still totaled but not counted
    /// (or flagged) as active.
    #[test]
    fn inactive_stream_is_counted_but_not_active() {
        let mut old = clean_stream(7, 10);
        old.last_seen = Utc::now() - Duration::seconds(120);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![old]));
        assert_eq!(snap.total_streams, 1);
        assert_eq!(snap.active_streams, 0);
        assert!(!snap.rows[0].active);
    }

    /// Trend points mirror the quality intervals oldest-first, and their
    /// MOS agrees with the canonical estimator.
    #[test]
    fn trend_is_built_from_quality_intervals_oldest_first() {
        let start = Utc::now();
        let mut s = clean_stream(8, 2);
        // two intervals: first clean, second degraded
        s.quality_intervals.clear();
        s.quality_intervals
            .push(crate::rtp::stream::QualityInterval {
                timestamp: start,
                jitter_ms: 1.0,
                loss_pct: 0.0,
                packets: 250,
            });
        s.quality_intervals
            .push(crate::rtp::stream::QualityInterval {
                timestamp: start + Duration::seconds(5),
                jitter_ms: 80.0,
                loss_pct: 20.0,
                packets: 200,
            });
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let trend = &snap.rows[0].trend;
        assert_eq!(trend.len(), 2);
        assert!(
            trend[0].mos > trend[1].mos,
            "clean interval first, degraded second"
        );
        assert_eq!(trend[0].loss_pct, 0.0);
        assert_eq!(trend[1].jitter_ms, 80.0);
        assert_eq!(trend[1].loss_pct, 20.0);
        // trend MOS must agree with the canonical estimator
        let expect = estimate_mos(80.0, 20.0, snap.rows[0].codec.as_deref());
        assert!((trend[1].mos - expect).abs() < 1e-9);
    }

    // ── loss_to_block glyph mapping ─────────────────────────────────

    /// Ascending loss climbs the eight-glyph block ramp; values just
    /// below a boundary stay in the lower band.
    #[test]
    fn loss_to_block_across_range() {
        // Ascending loss climbs the eight-glyph block ramp; the lowest
        // glyph is the flat baseline and the highest is a full block.
        assert_eq!(loss_to_block(0.0), '\u{2581}'); // ▁ baseline
        assert_eq!(loss_to_block(0.5), '\u{2582}'); // ▂
        assert_eq!(loss_to_block(1.0), '\u{2583}'); // ▃
        assert_eq!(loss_to_block(2.0), '\u{2584}'); // ▄
        assert_eq!(loss_to_block(5.0), '\u{2585}'); // ▅
        assert_eq!(loss_to_block(10.0), '\u{2586}'); // ▆
        assert_eq!(loss_to_block(20.0), '\u{2587}'); // ▇
        assert_eq!(loss_to_block(50.0), '\u{2588}'); // █
        assert_eq!(loss_to_block(100.0), '\u{2588}'); // █ full loss
        // Just below a boundary stays in the lower band.
        assert_eq!(loss_to_block(0.4), '\u{2581}'); // ▁
        assert_eq!(loss_to_block(49.9), '\u{2587}'); // ▇
    }

    /// NaN and negatives clamp to the baseline glyph; values above 100
    /// (including infinity) clamp to the full block.
    #[test]
    fn loss_to_block_clamps_invalid_input() {
        // NaN, negatives and sub-zero all clamp to the baseline glyph.
        assert_eq!(loss_to_block(f64::NAN), '\u{2581}'); // ▁
        assert_eq!(loss_to_block(-1.0), '\u{2581}'); // ▁
        assert_eq!(loss_to_block(-100.0), '\u{2581}'); // ▁
        // Anything above 100 clamps down to the full block.
        assert_eq!(loss_to_block(150.0), '\u{2588}'); // █
        assert_eq!(loss_to_block(f64::INFINITY), '\u{2588}'); // █
    }

    // ── render_dashboard loss trend + legend ────────────────────────

    use crate::rtp::stream::QualityInterval;
    use crate::tui::App;

    /// Build a stream whose completed quality intervals carry the given
    /// `(jitter_ms, loss_pct)` pairs, oldest first.
    fn stream_with_intervals(ssrc: u32, intervals: &[(f64, f64)]) -> RtpStream {
        let start = Utc::now();
        let mut s = clean_stream(ssrc, 3);
        s.quality_intervals.clear();
        for (i, &(jitter_ms, loss_pct)) in intervals.iter().enumerate() {
            s.quality_intervals.push(QualityInterval {
                timestamp: start + Duration::seconds(5 * i as i64),
                jitter_ms,
                loss_pct,
                packets: 250,
            });
        }
        s
    }

    /// Render the dashboard from a prebuilt snapshot into a fixed-size test
    /// backend and flatten the buffer to newline-joined rows.
    fn render_snapshot(snap: DashboardSnapshot, selected: usize, w: u16, h: u16) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut app = App::new_test();
        app.dashboard_snapshot = Some(snap);
        app.dashboard_selected = selected;
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, frame.area(), &app))
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

    /// The trend loss row is the one carrying the "Loss:" label (the table
    /// header uses "Loss%", so it never collides).
    fn loss_row(out: &str) -> &str {
        out.lines()
            .find(|l| l.contains("Loss:"))
            .expect("loss trend row must be rendered")
    }

    /// A 100%-loss interval renders a full-block glyph on the loss row,
    /// and the legend names every metric with units.
    #[test]
    fn render_shows_loss_spike_and_legend() {
        let s = stream_with_intervals(1, &[(1.0, 0.0), (2.0, 100.0)]);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let out = render_snapshot(snap, 0, 100, 30);
        // The legend names the metrics, their units, and the color keys.
        assert!(out.contains("Legend"), "legend missing: {out}");
        assert!(out.contains("MOS 1"), "MOS unit missing: {out}");
        assert!(out.contains("Jitter ms"), "jitter unit missing: {out}");
        assert!(out.contains("Loss %"), "loss unit missing: {out}");
        // A 100% loss interval drives the loss row to the full block.
        assert!(
            loss_row(&out).contains('\u{2588}'),
            "loss spike glyph missing: {out}"
        );
    }

    /// All-lost intervals render only full blocks on the loss row — no
    /// baseline glyph.
    #[test]
    fn render_full_loss_is_max_glyph() {
        let s = stream_with_intervals(1, &[(1.0, 100.0), (1.0, 100.0)]);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let out = render_snapshot(snap, 0, 100, 30);
        let row = loss_row(&out);
        assert!(row.contains('\u{2588}'), "expected full block: {row}");
        assert!(
            !row.contains('\u{2581}'),
            "no baseline glyph when fully lost: {row}"
        );
    }

    /// Loss-free intervals render the flat baseline glyph — never a
    /// full block.
    #[test]
    fn render_zero_loss_is_flat_baseline() {
        let s = stream_with_intervals(1, &[(1.0, 0.0), (1.0, 0.0), (1.0, 0.0)]);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let out = render_snapshot(snap, 0, 100, 30);
        let row = loss_row(&out);
        assert!(row.contains('\u{2581}'), "expected baseline glyph: {row}");
        assert!(
            !row.contains('\u{2588}'),
            "no full block when loss-free: {row}"
        );
    }

    /// With no completed intervals, the loss row, legend, and an
    /// empty-history placeholder still render without panicking.
    #[test]
    fn render_empty_history_degrades_gracefully() {
        // A stream with no completed intervals must still render the loss
        // row and legend without panicking.
        let mut s = clean_stream(1, 3);
        s.quality_intervals.clear();
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let out = render_snapshot(snap, 0, 100, 30);
        assert!(out.contains("Loss:"), "loss row label missing: {out}");
        assert!(out.contains("Legend"), "legend missing: {out}");
        assert!(
            out.contains("(no completed intervals yet)"),
            "empty-history placeholder missing: {out}"
        );
    }

    /// An 8x4 terminal clips the dashboard instead of panicking.
    #[test]
    fn render_narrow_terminal_does_not_panic() {
        // Robustness: a very narrow, short terminal must clip, not overflow.
        let s = stream_with_intervals(1, &[(1.0, 50.0)]);
        let snap = DashboardSnapshot::from_streams(&store_with(vec![s]));
        let _ = render_snapshot(snap, 0, 8, 4);
    }

    /// Build a snapshot with `n` synthetic rows labelled `row-{i}` so the
    /// rendered worst-streams table can be searched by row identity.
    fn snapshot_with_rows(n: usize) -> DashboardSnapshot {
        let rows = (0..n)
            .map(|i| StreamHealth {
                key: StreamKey {
                    ssrc: i as u32,
                    src: addr(10000),
                    dst: addr(20000),
                },
                call_id: Some(format!("row-{i}")),
                codec: Some("PCMU".to_string()),
                mos: 4.0,
                jitter_ms: 1.0,
                loss_pct: 0.0,
                packets: 100,
                active: true,
                trend: Vec::new(),
            })
            .collect();
        DashboardSnapshot {
            total_streams: n,
            active_streams: n,
            avg_mos: Some(4.0),
            worst_mos: Some(4.0),
            rows,
            ..Default::default()
        }
    }

    /// Edge case: the scroll window must keep the selection in view with
    /// context, not pin it to the bottom row. With a mid-list selection there
    /// must be rendered rows BELOW it — impossible under the old bottom-anchor.
    #[test]
    fn scroll_window_keeps_selection_in_view_with_context() {
        // height 25 → visible window = 25 - 13 = 12 rows out of 30.
        let out = render_snapshot(snapshot_with_rows(30), 15, 130, 25);

        // The selected row is rendered with its marker (▶).
        let selected_line = out
            .lines()
            .find(|l| l.contains("row-15") && l.contains('\u{25b6}'))
            .unwrap_or_else(|| panic!("selected row-15 not rendered with marker:\n{out}"));
        assert!(selected_line.contains('\u{25b6}'));

        // Context below the selection is visible (row-16) — the old
        // bottom-anchored window rendered nothing past the selection.
        assert!(
            out.contains("row-16"),
            "no context below the selection — window still bottom-anchored:\n{out}"
        );
        // Context above the selection is visible too (row-12).
        assert!(
            out.contains("row-12"),
            "no context above the selection:\n{out}"
        );
    }
}
