// SPDX-License-Identifier: MIT OR Apache-2.0

//! Call-timeline view: a horizontal, left-to-right rendering of one
//! dialog's signaling phases (setup, ringing, in-call, teardown) laid out
//! proportionally to their real durations.
//!
//! The milestone timestamps captured in `DialogTiming` are turned into an
//! ordered list of colored phase segments; the renderer draws a proportional
//! bar, per-phase labels with units, a derived-metric summary, a color legend
//! and the total call duration, degrading gracefully in narrow terminals.
//!
//! This is a static, single-screen view of one call: the bar is scaled to
//! the available width (no horizontal overflow), the labels always list
//! every phase with its exact duration (no information is hidden behind
//! proportions), and the whole view is a fixed handful of lines. There is
//! nothing to scroll and no list to select, so the view is intentionally
//! non-navigable — see the timeline controller for the matching key/wheel
//! contract.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::sip::dialog::{DialogState, SipDialog};
use crate::tui::App;
use crate::tui::theme::Theme;

/// Coarse phase classification for a timeline segment. Each kind maps to one
/// stable color so the bar, the labels and the legend agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseKind {
    /// From the initial INVITE up to alerting (waiting for a provisional or
    /// final answer): trying / session-progress window.
    Setup,
    /// Alerting: 180 Ringing until the call is answered.
    Ringing,
    /// Media established: 200 OK to the INVITE until teardown begins.
    InCall,
    /// BYE sent until its 200 OK — the call winding down.
    Teardown,
    /// Terminal marker for a call that failed before it was answered.
    Failed,
    /// Terminal marker for a call canceled before it was answered.
    Canceled,
}

/// One labeled phase on the horizontal timeline.
///
/// `start_ms` is the offset from the call's first milestone; `duration_ms`
/// is the wall-clock length of the phase (never negative). A zero-length
/// phase is legal (simultaneous timestamps) and renders at minimal width.
#[derive(Debug, Clone, PartialEq)]
pub struct TimelineSegment {
    /// Human-readable phase name (e.g. `"In-Call"`).
    pub label: String,
    /// Offset from the call start, in milliseconds.
    pub start_ms: i64,
    /// Phase duration, in milliseconds (>= 0).
    pub duration_ms: i64,
    /// Phase classification driving the color.
    pub kind: PhaseKind,
}

/// Turn a dialog's captured milestones into ordered, labeled phase segments.
///
/// Returns an empty vector when the dialog carries no usable timing (no
/// milestone timestamps at all) — the renderer shows a placeholder in that
/// case. Missing intermediate milestones are simply skipped, so a call that
/// was never answered yields only its setup/ringing phases plus a terminal
/// failed/canceled marker, with no in-call segment.
///
/// # Arguments
///
/// * `dialog` — the dialog whose timing milestones and messages are read.
///
/// # Returns
///
/// Segments in chronological order with `start_ms` offsets relative to
/// the first milestone; empty when no milestone was ever recorded.
/// Terminal failed/canceled markers appear as zero-length segments at
/// the end of the bar.
pub fn timeline_segments(dialog: &SipDialog) -> Vec<TimelineSegment> {
    let t = &dialog.timing;

    // Canonical milestone order. Each present milestone opens a phase that
    // runs until the next present milestone (or the call's end).
    let ordered: [(Option<chrono::DateTime<chrono::Utc>>, &str, PhaseKind); 5] = [
        (t.invite_sent, "Setup", PhaseKind::Setup),
        (t.trying_at, "Proceeding", PhaseKind::Setup),
        (t.ringing_at, "Ringing", PhaseKind::Ringing),
        (t.answered_at, "In-Call", PhaseKind::InCall),
        (t.bye_sent, "Teardown", PhaseKind::Teardown),
    ];

    // Present (timestamp, label, kind) points in chronological/canonical order.
    let mut points: Vec<(chrono::DateTime<chrono::Utc>, &str, PhaseKind)> = Vec::new();
    for (ts, label, kind) in ordered {
        if let Some(ts) = ts {
            points.push((ts, label, kind));
        }
    }

    if points.is_empty() {
        return Vec::new();
    }

    let start = points[0].0;

    // The call's end bound: the BYE's 200 OK if present, else the last
    // message seen (an in-progress or never-torn-down call extends to the
    // last captured packet), else the last milestone itself.
    let last_msg = dialog.messages.iter().map(|m| m.timestamp).max();
    let mut call_end = points[points.len() - 1].0;
    if let Some(bye_ok) = t.bye_answered {
        call_end = call_end.max(bye_ok);
    }
    if let Some(last) = last_msg {
        call_end = call_end.max(last);
    }

    let mut segments = Vec::with_capacity(points.len() + 1);
    for i in 0..points.len() {
        let (seg_start, label, kind) = points[i];
        let seg_end = points.get(i + 1).map(|p| p.0).unwrap_or(call_end);
        let duration_ms = (seg_end - seg_start).num_milliseconds().max(0);
        segments.push(TimelineSegment {
            label: label.to_string(),
            start_ms: (seg_start - start).num_milliseconds().max(0),
            duration_ms,
            kind,
        });
    }

    // A call that never reached the answered milestone gets a terminal
    // marker so the failed/canceled outcome is visible without an in-call
    // phase. Markers are zero-length: they annotate the end of the bar.
    if t.answered_at.is_none() {
        let marker = match dialog.state() {
            DialogState::Canceled => Some(("Canceled", PhaseKind::Canceled)),
            DialogState::Failed | DialogState::Expired | DialogState::Terminated => {
                Some(("Failed", PhaseKind::Failed))
            }
            _ => None,
        };
        if let Some((label, kind)) = marker {
            segments.push(TimelineSegment {
                label: label.to_string(),
                start_ms: (call_end - start).num_milliseconds().max(0),
                duration_ms: 0,
                kind,
            });
        }
    }

    segments
}

/// Render the call-timeline view for `call_id`.
///
/// Draws a bordered block containing the total/state header, the
/// proportional phase bar, per-phase duration labels, the derived-metric
/// summary, and a legend of the present phase kinds.
///
/// # Arguments
///
/// * `f` — ratatui frame to draw into.
/// * `app` — application state supplying the dialog store and theme.
/// * `area` — screen rectangle for the bordered timeline block.
/// * `call_id` — Call-ID of the dialog to visualize.
///
/// # Side effects
///
/// Draws widgets into `f`. Attempts a non-blocking `try_read` on
/// `app.dialog_store`; when the lock is contended, the dialog is
/// missing, or it has no usable timing, a placeholder is drawn instead
/// (the frame is never blocked on a queued writer).
pub fn render_timeline(f: &mut Frame, app: &App, area: Rect, call_id: &str) {
    let theme = &app.theme;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Call Timeline — {call_id} "));

    // Resolve the dialog without blocking: the render pass already holds a
    // read guard on the shared store, so a plain re-lock could stall behind
    // a queued writer. `try_read` degrades to the placeholder instead.
    let Some(store) = app.dialog_store.try_read() else {
        render_placeholder(f, area, block, theme);
        return;
    };
    let Some(dialog) = store.get(call_id) else {
        render_placeholder(f, area, block, theme);
        return;
    };

    let segments = timeline_segments(dialog);
    if segments.is_empty() {
        render_placeholder(f, area, block, theme);
        return;
    }

    let total_ms = timeline_total_ms(&segments);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Header: total duration and the terminal dialog state.
    lines.push(Line::from(vec![
        Span::styled("  Total ", Style::default().fg(theme.muted)),
        Span::styled(
            format_duration_ms(total_ms),
            Style::default()
                .fg(theme.foreground)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   State ", Style::default().fg(theme.muted)),
        Span::styled(
            state_label(dialog.state()).to_string(),
            Style::default().fg(state_color(dialog.state(), theme)),
        ),
    ]));
    lines.push(Line::raw(""));

    // Proportional phase bar. In very narrow terminals it simply shrinks; the
    // labels below still carry the full detail.
    let bar_width = inner.width as usize;
    lines.push(Line::from(segment_bar_spans(
        &segments, total_ms, bar_width, theme,
    )));
    lines.push(Line::raw(""));

    // Per-phase labels with units, colored to match the bar.
    for seg in &segments {
        let color = phase_color(seg.kind, theme);
        let mut spans = vec![
            Span::styled("  ", Style::default()),
            Span::styled("\u{2588} ", Style::default().fg(color)),
            Span::styled(
                format!("{:<11}", seg.label),
                Style::default().fg(theme.foreground),
            ),
        ];
        if is_marker(seg.kind) {
            spans.push(Span::styled("—", Style::default().fg(theme.muted)));
        } else {
            spans.push(Span::styled(
                format_duration_ms(seg.duration_ms),
                Style::default().fg(color),
            ));
        }
        lines.push(Line::from(spans));
    }

    // Derived-metric summary, grounded in the timing accessors.
    if let Some(metrics) = metric_summary_line(dialog, theme) {
        lines.push(Line::raw(""));
        lines.push(metrics);
    }

    // Legend: only the phase kinds actually present.
    lines.push(Line::raw(""));
    lines.push(legend_line(&segments, theme));

    let paragraph = Paragraph::new(lines)
        .style(Style::default().fg(theme.foreground))
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

/// Total span of the timeline: the furthest segment end, floored at 1ms so
/// proportional layout never divides by zero.
fn timeline_total_ms(segments: &[TimelineSegment]) -> i64 {
    segments
        .iter()
        .map(|s| s.start_ms + s.duration_ms)
        .max()
        .unwrap_or(0)
        .max(1)
}

/// Build the colored, proportional phase bar as styled spans. Every
/// non-marker segment claims at least one cell so short phases stay visible;
/// the last segment absorbs any rounding slack to exactly fill `width`.
///
/// # Arguments
///
/// * `segments` — timeline segments; zero-length markers are skipped.
/// * `total_ms` — total timeline span the widths are scaled against.
/// * `width` — target bar width in terminal cells.
/// * `theme` — color theme for the per-kind colors.
///
/// # Returns
///
/// One block-character span per drawn segment summing to exactly
/// `width` cells; a single blank span when only markers exist; empty
/// when `width` is zero.
fn segment_bar_spans(
    segments: &[TimelineSegment],
    total_ms: i64,
    width: usize,
    theme: &Theme,
) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let bars: Vec<&TimelineSegment> = segments.iter().filter(|s| !is_marker(s.kind)).collect();
    if bars.is_empty() {
        return vec![Span::raw(" ".repeat(width))];
    }

    let total = total_ms.max(1) as f64;
    let mut widths: Vec<usize> = bars
        .iter()
        .map(|s| {
            let raw = (s.duration_ms.max(0) as f64 / total * width as f64).round() as usize;
            raw.max(1)
        })
        .collect();

    // Reconcile to exactly `width`: trim widest first, or pad the last cell.
    let mut sum: usize = widths.iter().sum();
    while sum > width {
        if let Some(idx) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > 1)
            .max_by_key(|(_, w)| **w)
            .map(|(i, _)| i)
        {
            widths[idx] -= 1;
            sum -= 1;
        } else {
            break;
        }
    }
    if sum < width
        && let Some(last) = widths.last_mut()
    {
        *last += width - sum;
    }

    bars.iter()
        .zip(widths)
        .map(|(seg, w)| {
            Span::styled(
                "\u{2588}".repeat(w),
                Style::default().fg(phase_color(seg.kind, theme)),
            )
        })
        .collect()
}

/// One-line derived-metric summary using the timing accessors, e.g.
/// `PDD 120ms · ring 3.2s · setup 3.3s · teardown 200ms`.
///
/// # Returns
///
/// A styled line listing only the metrics whose accessor produced a
/// value; `None` when no metric is available at all.
fn metric_summary_line(dialog: &SipDialog, theme: &Theme) -> Option<Line<'static>> {
    let t = &dialog.timing;
    let parts: [(&str, Option<i64>); 4] = [
        ("PDD", t.pdd_ms()),
        ("ring", t.ring_ms()),
        ("setup", t.setup_ms()),
        ("teardown", t.teardown_ms()),
    ];
    let mut spans: Vec<Span<'static>> = vec![Span::styled("  ", Style::default())];
    let mut first = true;
    for (name, value) in parts {
        if let Some(ms) = value {
            if !first {
                spans.push(Span::styled(" · ", Style::default().fg(theme.muted)));
            }
            first = false;
            spans.push(Span::styled(
                format!("{name} "),
                Style::default().fg(theme.muted),
            ));
            spans.push(Span::styled(
                format_duration_ms(ms),
                Style::default().fg(theme.foreground),
            ));
        }
    }
    if first {
        return None;
    }
    Some(Line::from(spans))
}

/// Legend mapping each present phase kind to its color swatch and name,
/// deduplicated in first-appearance order.
fn legend_line(segments: &[TimelineSegment], theme: &Theme) -> Line<'static> {
    let mut spans: Vec<Span<'static>> =
        vec![Span::styled("  Legend ", Style::default().fg(theme.muted))];
    let mut seen: Vec<PhaseKind> = Vec::new();
    for seg in segments {
        if seen.contains(&seg.kind) {
            continue;
        }
        seen.push(seg.kind);
        let color = phase_color(seg.kind, theme);
        spans.push(Span::styled("\u{2588} ", Style::default().fg(color)));
        spans.push(Span::styled(
            format!("{}  ", kind_name(seg.kind)),
            Style::default().fg(theme.foreground),
        ));
    }
    Line::from(spans)
}

/// Bordered placeholder for a call with no usable timeline data.
///
/// # Side effects
///
/// Draws the titled block with a muted "No timeline data" message
/// into `f`.
fn render_placeholder(f: &mut Frame, area: Rect, block: Block<'static>, theme: &Theme) {
    let paragraph = Paragraph::new("  No timeline data for this call.")
        .block(block)
        .style(Style::default().fg(theme.muted))
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

/// Whether a phase kind is a zero-length terminal annotation rather than a
/// real interval on the bar.
fn is_marker(kind: PhaseKind) -> bool {
    matches!(kind, PhaseKind::Failed | PhaseKind::Canceled)
}

/// Stable color for each phase kind, shared by the bar, labels and legend.
fn phase_color(kind: PhaseKind, theme: &Theme) -> ratatui::style::Color {
    match kind {
        PhaseKind::Setup => theme.accent,
        PhaseKind::Ringing => theme.warning,
        PhaseKind::InCall => theme.good,
        PhaseKind::Teardown => theme.muted,
        PhaseKind::Failed => theme.bad,
        PhaseKind::Canceled => theme.header,
    }
}

/// Legend display name for a phase kind.
fn kind_name(kind: PhaseKind) -> &'static str {
    match kind {
        PhaseKind::Setup => "Setup",
        PhaseKind::Ringing => "Ringing",
        PhaseKind::InCall => "In-Call",
        PhaseKind::Teardown => "Teardown",
        PhaseKind::Failed => "Failed",
        PhaseKind::Canceled => "Canceled",
    }
}

/// Short display label for the dialog's terminal state (delegates to
/// the call list's `state_display_str`).
fn state_label(state: &DialogState) -> &'static str {
    crate::tui::call_list::state_display_str(state)
}

/// Color for the dialog state summary.
fn state_color(state: &DialogState, theme: &Theme) -> ratatui::style::Color {
    match state {
        DialogState::InCall | DialogState::Completed | DialogState::Active => theme.good,
        DialogState::Ringing | DialogState::Trying | DialogState::Pending => theme.warning,
        DialogState::Failed | DialogState::Canceled | DialogState::Expired => theme.bad,
        _ => theme.foreground,
    }
}

/// Format a phase duration with units: sub-second in ms, under a minute in
/// seconds with one decimal, else `MmSs`. Negative input is floored to 0.
fn format_duration_ms(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let secs = ms / 1000;
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for segment derivation across call outcomes (completed,
/// unanswered, failed, zero-length) and rendering robustness.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::{
        base_ts, make_invite, make_request, make_response,
    };
    use chrono::TimeDelta;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Build an app whose store holds exactly the given messages for one call.
    fn app_with(messages: Vec<crate::sip::SipMessage>) -> App {
        App::with_processed_messages(messages)
    }

    /// Render `render_timeline` for `call_id` into a plain string buffer.
    fn render_to_string(app: &App, call_id: &str, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).expect("backend");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_timeline(frame, app, area, call_id);
            })
            .expect("draw");
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                if let Some(cell) = buf.cell((x, y)) {
                    out.push_str(cell.symbol());
                }
            }
            out.push('\n');
        }
        out
    }

    /// A fully-completed call: INVITE, 100, 180, 200, BYE, 200-to-BYE.
    fn completed_call(call_id: &str) -> Vec<crate::sip::SipMessage> {
        let t0 = base_ts();
        vec![
            make_invite(call_id, "alice", "bob", t0),
            make_response(
                "100 Trying",
                call_id,
                "INVITE",
                t0 + TimeDelta::milliseconds(50),
            ),
            make_response(
                "180 Ringing",
                call_id,
                "INVITE",
                t0 + TimeDelta::milliseconds(1500),
            ),
            make_response(
                "200 OK",
                call_id,
                "INVITE",
                t0 + TimeDelta::milliseconds(4500),
            ),
            make_request(
                "BYE",
                call_id,
                "alice",
                "bob",
                t0 + TimeDelta::milliseconds(20000),
            ),
            make_response(
                "200 OK",
                call_id,
                "BYE",
                t0 + TimeDelta::milliseconds(20200),
            ),
        ]
    }

    /// A fully-completed call yields the five canonical phases in order
    /// with exact per-phase durations, offsets, and total.
    #[test]
    fn completed_call_yields_ordered_segments_with_durations() {
        let app = app_with(completed_call("done@test"));
        let store = app.dialog_store.read();
        let dialog = store.get("done@test").expect("dialog present");
        let segs = timeline_segments(dialog);

        let kinds: Vec<PhaseKind> = segs.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            vec![
                PhaseKind::Setup,    // invite → trying
                PhaseKind::Setup,    // trying → ringing
                PhaseKind::Ringing,  // ringing → answered
                PhaseKind::InCall,   // answered → bye
                PhaseKind::Teardown  // bye → bye-ok
            ]
        );
        assert_eq!(segs[0].duration_ms, 50); // invite → trying
        assert_eq!(segs[1].duration_ms, 1450); // trying → ringing
        assert_eq!(segs[2].duration_ms, 3000); // ring
        assert_eq!(segs[3].duration_ms, 15500); // in-call
        assert_eq!(segs[4].duration_ms, 200); // teardown
        assert_eq!(segs[0].start_ms, 0);
        assert_eq!(segs[4].start_ms, 20000);
        assert_eq!(timeline_total_ms(&segs), 20200);
    }

    /// Rendering a completed call shows phase labels, a unit-bearing
    /// duration, the PDD metric, the legend, and the total.
    #[test]
    fn completed_call_renders_labels_metrics_and_legend() {
        let app = app_with(completed_call("done@test"));
        let text = render_to_string(&app, "done@test", 100, 24);

        // Phase labels.
        assert!(text.contains("In-Call"), "missing In-Call label:\n{text}");
        assert!(text.contains("Ringing"), "missing Ringing label:\n{text}");
        assert!(text.contains("Teardown"), "missing Teardown label:\n{text}");
        // A duration with units.
        assert!(text.contains("3.0s"), "missing ring duration:\n{text}");
        // Derived-metric summary (grounded units).
        assert!(text.contains("PDD"), "missing PDD metric:\n{text}");
        // Legend.
        assert!(text.contains("Legend"), "missing legend:\n{text}");
        // Total.
        assert!(text.contains("Total"), "missing total:\n{text}");
    }

    /// An INVITE with no responses yields a setup phase but never an
    /// in-call segment.
    #[test]
    fn invite_only_call_has_setup_but_no_in_call() {
        let t0 = base_ts();
        let app = app_with(vec![make_invite("ringing@test", "alice", "bob", t0)]);
        let store = app.dialog_store.read();
        let dialog = store.get("ringing@test").expect("dialog present");
        let segs = timeline_segments(dialog);

        assert!(!segs.is_empty(), "invite-only must still yield setup");
        assert!(
            segs.iter().all(|s| s.kind != PhaseKind::InCall),
            "invite-only must have no in-call segment"
        );
        assert_eq!(segs[0].kind, PhaseKind::Setup);
    }

    /// A 486-rejected call gets a Failed marker, no in-call segment, and
    /// renders the marker without panicking.
    #[test]
    fn failed_call_appends_marker_without_in_call() {
        let t0 = base_ts();
        let app = app_with(vec![
            make_invite("busy@test", "alice", "bob", t0),
            make_response(
                "100 Trying",
                "busy@test",
                "INVITE",
                t0 + TimeDelta::milliseconds(40),
            ),
            make_response(
                "180 Ringing",
                "busy@test",
                "INVITE",
                t0 + TimeDelta::milliseconds(900),
            ),
            make_response(
                "486 Busy Here",
                "busy@test",
                "INVITE",
                t0 + TimeDelta::milliseconds(2000),
            ),
        ]);
        let store = app.dialog_store.read();
        let dialog = store.get("busy@test").expect("dialog present");
        let segs = timeline_segments(dialog);

        assert!(
            segs.iter().all(|s| s.kind != PhaseKind::InCall),
            "failed call must have no in-call segment"
        );
        assert!(
            segs.iter().any(|s| s.kind == PhaseKind::Failed),
            "failed call must carry a Failed marker: {segs:?}"
        );
        // Rendering the failed call must not panic and shows the marker.
        drop(store);
        let text = render_to_string(&app, "busy@test", 90, 20);
        assert!(text.contains("Failed"), "missing Failed marker:\n{text}");
    }

    /// All milestones at the same instant yield zero-length segments, a
    /// total floored to 1 ms, and a panic-free render.
    #[test]
    fn simultaneous_timestamps_do_not_divide_by_zero() {
        let t0 = base_ts();
        // All milestones at the same instant.
        let app = app_with(vec![
            make_invite("zero@test", "alice", "bob", t0),
            make_response("180 Ringing", "zero@test", "INVITE", t0),
            make_response("200 OK", "zero@test", "INVITE", t0),
        ]);
        let store = app.dialog_store.read();
        let dialog = store.get("zero@test").expect("dialog present");
        let segs = timeline_segments(dialog);
        assert!(segs.iter().all(|s| s.duration_ms == 0));
        assert_eq!(timeline_total_ms(&segs), 1, "total floored to avoid /0");
        drop(store);
        // Must render without panic even though every phase is zero-length.
        let text = render_to_string(&app, "zero@test", 80, 20);
        assert!(
            text.contains("In-Call"),
            "zero-duration still labeled:\n{text}"
        );
    }

    /// A milestone-free (OPTIONS) dialog yields no segments and renders
    /// the "No timeline data" placeholder.
    #[test]
    fn dialog_without_timing_shows_placeholder() {
        let t0 = base_ts();
        // A non-INVITE dialog: exists in the store but records no milestones.
        let app = app_with(vec![make_request(
            "OPTIONS", "opt@test", "alice", "bob", t0,
        )]);
        let store = app.dialog_store.read();
        let dialog = store.get("opt@test").expect("dialog present");
        assert!(timeline_segments(dialog).is_empty());
        drop(store);
        let text = render_to_string(&app, "opt@test", 80, 20);
        assert!(
            text.contains("No timeline data"),
            "expected placeholder:\n{text}"
        );
    }

    /// An unknown Call-ID renders the placeholder instead of panicking.
    #[test]
    fn missing_call_shows_placeholder_without_panic() {
        let app = App::new_test();
        let text = render_to_string(&app, "nope@test", 80, 20);
        assert!(
            text.contains("No timeline data"),
            "expected placeholder:\n{text}"
        );
    }

    /// A 12x16 terminal shrinks the bar and clips content, not panics.
    #[test]
    fn narrow_terminal_still_renders_without_panic() {
        let app = app_with(completed_call("done@test"));
        // Extremely narrow: bar must degrade, not panic.
        let text = render_to_string(&app, "done@test", 12, 16);
        assert!(text.contains("Total") || text.contains("In-Call"));
    }
}
