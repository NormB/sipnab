// SPDX-License-Identifier: MIT OR Apache-2.0

//! Rendering functions for call flow ladder diagrams.
//!
//! Contains both the direct buffer-painting path (used by the TUI) and
//! the Paragraph-based rendering path (used for non-interactive output).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::sip::SipMessage;
use crate::sip::dialog::SipDialog;
use crate::sip::dialog_store::DialogStore;

use crate::tui::ColorMode;
use crate::tui::SdpDisplayMode;
use crate::tui::Theme;
use crate::tui::TimestampMode;

use super::FlowDisplayOptions;
use super::arrows::{format_arrow, format_arrow_left, format_arrow_right, truncate};
use super::prepare::{delta_style, format_message_label, format_sdp_codecs, message_style};
use super::{
    ENDPOINT_COL_WIDTH, FormattedMessage, MIN_ARROW_WIDTH, Participant, SelectionState,
    TS_COL_WIDTH,
};

/// Background applied across the full width of the current (selected) message
/// row — a subtle highlight that marks the cursor without shifting content.
const SELECTION_BG: Color = Color::Rgb(40, 40, 60);

/// Column span available for each ladder arrow at a given terminal width.
///
/// Subtracts the timestamp and both endpoint columns (plus fixed inter-column
/// padding) from `term_width`, floored at `MIN_ARROW_WIDTH`. Single source of
/// truth for the arrow sizing shared by all the line builders.
fn arrow_width_for(term_width: usize) -> usize {
    term_width
        .saturating_sub(TS_COL_WIDTH + ENDPOINT_COL_WIDTH * 2 + 15)
        .max(MIN_ARROW_WIDTH)
}

/// Append the "Correlated Legs" section for `correlated` to `lines`.
///
/// No-op when `correlated` is empty; otherwise emits a blank spacer, a bold
/// " Correlated Legs:" header, and one `↔ Call-ID: … (METHOD)` row per leg,
/// all in the theme accent color.
fn push_correlated_legs(lines: &mut Vec<Line<'static>>, correlated: &[&SipDialog], theme: &Theme) {
    if correlated.is_empty() {
        return;
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " Correlated Legs:",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )));
    for leg in correlated {
        lines.push(Line::from(Span::styled(
            format!(
                "   \u{2194} Call-ID: {} ({})",
                truncate(&leg.call_id, 40),
                leg.method
            ),
            Style::default().fg(theme.accent),
        )));
    }
}

/// Build the ladder header row: the left endpoint label ending at
/// `left_pipe_col` and the right label ending at `right_pipe_col`, styled with
/// the theme header color. Shared by both `format_ladder` variants.
fn ladder_header(
    left_label: &str,
    right_label: &str,
    left_pipe_col: usize,
    right_pipe_col: usize,
    theme: &Theme,
) -> Line<'static> {
    let mut header = String::new();
    header.push_str(&format!(
        "{:>width$}",
        left_label,
        width = left_pipe_col + left_label.len() / 2
    ));
    let gap = right_pipe_col.saturating_sub(header.len() + right_label.len() / 2);
    header.push_str(&" ".repeat(gap));
    header.push_str(right_label);
    Line::from(Span::styled(
        header,
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    ))
}

/// Build a ladder pipe row: `prefix`, padding to `left_pipe_col`, a `│`, more
/// padding to `right_pipe_col`, and a closing `│`. Shared by both
/// `format_ladder` variants.
fn ladder_pipe(prefix: &str, left_pipe_col: usize, right_pipe_col: usize) -> String {
    let mut s = String::new();
    s.push_str(prefix);
    let mut col = prefix.chars().count();
    while col < left_pipe_col {
        s.push(' ');
        col += 1;
    }
    s.push('\u{2502}');
    col += 1;
    while col < right_pipe_col {
        s.push(' ');
        col += 1;
    }
    s.push('\u{2502}');
    s
}

// ── Paragraph-based rendering (legacy path) ────────────────────────

/// Build the formatted lines for a call flow ladder diagram.
///
/// Convenience wrapper over `build_call_flow_lines_with_width` at a fixed
/// 120-column terminal width.
///
/// # Arguments
/// * `store` — dialog store to look `call_id` up in.
/// * `call_id` — Call-ID of the dialog to render.
/// * `theme` — color theme for the ladder styling.
///
/// # Returns
/// `None` if the dialog is not found or has no messages.
/// `Some((msg_count, lines))` on success, where `msg_count` can be
/// used as a cache invalidation key.
pub fn build_call_flow_lines(
    store: &DialogStore,
    call_id: &str,
    theme: &Theme,
) -> Option<(usize, Vec<Line<'static>>)> {
    build_call_flow_lines_with_width(store, call_id, 120, theme)
}

/// Build call flow lines with a specific terminal width for arrow sizing.
///
/// The arrow span is `term_width` minus the timestamp and endpoint columns,
/// floored at `MIN_ARROW_WIDTH`. Appends a "Correlated Legs" section when
/// the store knows other dialogs correlated with this one.
///
/// # Arguments
/// * `store` — dialog store to look `call_id` up in.
/// * `call_id` — Call-ID of the dialog to render.
/// * `term_width` — terminal width in columns, used to size the arrows.
/// * `theme` — color theme for the ladder styling.
///
/// # Returns
/// `None` if the dialog is not found or has no messages; otherwise
/// `Some((msg_count, lines))` with `msg_count` usable as a cache key.
pub fn build_call_flow_lines_with_width(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    theme: &Theme,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }

    let arrow_width = arrow_width_for(term_width);

    let msg_count = dialog.messages.len();
    let mut lines = format_ladder(&dialog.messages, dialog.timing.pdd_ms(), arrow_width, theme);

    // Show correlated dialogs (multi-leg)
    let correlated = store.find_correlated(call_id);
    push_correlated_legs(&mut lines, &correlated, theme);

    Some((msg_count, lines))
}

/// Build call flow lines with display options (SDP mode, timestamp mode, color mode, etc.).
///
/// Same shape as `build_call_flow_lines_with_width` but rendering through
/// `format_ladder_with_options`, so all `FlowDisplayOptions` display modes
/// apply. Appends the "Correlated Legs" section when present.
///
/// # Arguments
/// * `store` — dialog store to look `call_id` up in.
/// * `call_id` — Call-ID of the dialog to render.
/// * `term_width` — terminal width in columns, used to size the arrows.
/// * `opts` — full display options (SDP/timestamp/color modes, theme, ...).
///
/// # Returns
/// `None` if the dialog is not found or has no messages; otherwise
/// `Some((msg_count, lines))` with `msg_count` usable as a cache key.
pub fn build_call_flow_lines_with_options(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }
    let aw = arrow_width_for(term_width);
    let mc = dialog.messages.len();
    let ft = dialog.messages[0].timestamp;
    let mut lines =
        format_ladder_with_options(&dialog.messages, ft, dialog.timing.pdd_ms(), aw, opts);
    let correlated = store.find_correlated(call_id);
    push_correlated_legs(&mut lines, &correlated, opts.theme);
    Some((mc, lines))
}

/// Build extended (multi-leg) flow lines merging correlated dialogs.
///
/// Collects the dialog's messages plus every correlated leg's, sorts them by
/// timestamp, and renders one merged ladder under an "Extended Flow" header.
/// RTP bars and selection are disabled in this merged view (the row indices
/// would not match the single-dialog selection).
///
/// # Arguments
/// * `store` — dialog store; supplies the dialog and its correlated legs.
/// * `call_id` — Call-ID of the primary dialog.
/// * `term_width` — terminal width in columns, used to size the arrows.
/// * `opts` — display options; cloned with `show_rtp`/`selected_msg` off.
///
/// # Returns
/// `None` if the dialog is not found or has no messages; otherwise
/// `Some((merged_msg_count, lines))`.
pub fn build_extended_flow_lines(
    store: &DialogStore,
    call_id: &str,
    term_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Option<(usize, Vec<Line<'static>>)> {
    let dialog = store.get(call_id)?;
    if dialog.messages.is_empty() {
        return None;
    }
    let mut all: Vec<&SipMessage> = dialog.messages.iter().collect();
    let correlated = store.find_correlated(call_id);
    for leg in &correlated {
        all.extend(leg.messages.iter());
    }
    all.sort_by_key(|m| m.timestamp);
    let owned: Vec<SipMessage> = all.into_iter().cloned().collect();
    if owned.is_empty() {
        return None;
    }
    let aw = arrow_width_for(term_width);
    let mc = owned.len();
    let ft = owned[0].timestamp;
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                " Extended Flow: {} + {} correlated leg(s)",
                truncate(call_id, 40),
                correlated.len()
            ),
            Style::default()
                .fg(opts.theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    let ext_opts = FlowDisplayOptions {
        show_rtp: false,
        selected_msg: None,
        ..opts.clone()
    };
    lines.extend(format_ladder_with_options(&owned, ft, None, aw, &ext_opts));
    Some((mc, lines))
}

/// Render the call flow ladder diagram for a dialog identified by Call-ID.
///
/// Thin wrapper: builds the lines via `build_call_flow_lines_with_width` at
/// the area's width and hands them to `render_call_flow_lines`.
///
/// # Arguments
/// * `frame` — frame to draw into.
/// * `area` — target region; its width sizes the arrows.
/// * `store` — dialog store to look `call_id` up in.
/// * `call_id` — Call-ID of the dialog to render.
/// * `scroll_offset` — number of lines scrolled off the top.
/// * `theme` — color theme for the ladder styling.
///
/// # Side effects
/// Draws the ladder (or a fallback message) into `frame` over `area`.
pub fn render_call_flow(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    call_id: &str,
    scroll_offset: usize,
    theme: &Theme,
) {
    let term_width = area.width as usize;
    render_call_flow_lines(frame, area, scroll_offset, theme, || {
        build_call_flow_lines_with_width(store, call_id, term_width, theme)
    });
}

/// Render call flow from pre-built lines or a builder closure.
///
/// # Arguments
/// * `frame` — frame to draw into.
/// * `area` — target region for the paragraph.
/// * `scroll_offset` — vertical paragraph scroll in lines.
/// * `theme` — theme for the fallback message styling.
/// * `build` — closure producing `(msg_count, lines)`; `None` means the
///   dialog is missing or empty.
///
/// # Side effects
/// Draws a wrapping, scrolled `Paragraph` of the built lines into `frame`;
/// when `build` returns `None`, draws "Dialog not found or empty." instead.
pub fn render_call_flow_lines(
    frame: &mut Frame,
    area: Rect,
    scroll_offset: usize,
    theme: &Theme,
    build: impl FnOnce() -> Option<(usize, Vec<Line<'static>>)>,
) {
    let lines = match build() {
        Some((_count, lines)) => lines,
        None => {
            let para = Paragraph::new("Dialog not found or empty.")
                .style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return;
        }
    };

    let para = Paragraph::new(lines)
        .scroll((scroll_offset as u16, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(para, area);
}

// ── Direct buffer painting (TUI path) ───────────────────────────────

/// Build an RTP-in-flow channel bar: center `label` within `width` columns and
/// fill both sides with the double rail `═` (U+2550) so a live media stream
/// reads as a continuous channel between the two endpoints — visually distinct
/// from the single-line (`─`) SIP signaling arrows. The double rail looks like
/// an elongated `=`, evoking a sustained two-way pipe rather than a one-shot
/// message.
///
/// `label` is the bare text (e.g. ` RTP · PCMU `); the rails are owned
/// here, not baked into the label, so the bar is always centered regardless of
/// label width. If the label is as wide as or wider than `width` it is truncated
/// to `width` columns (rails dropped) so it never overflows past the right pipe
/// and never falls back to left-alignment. Width is counted in characters, not
/// bytes, so multi-byte glyphs like `·` (U+00B7) don't skew the centering.
pub(crate) fn rtp_channel_bar(label: &str, width: usize) -> String {
    let lw = label.chars().count();
    if lw >= width {
        return label.chars().take(width).collect();
    }
    let pad = width - lw;
    let left = pad / 2;
    let right = pad - left;
    let mut s = String::with_capacity(label.len() + (pad * 3));
    for _ in 0..left {
        s.push('\u{2550}');
    }
    s.push_str(label);
    for _ in 0..right {
        s.push('\u{2550}');
    }
    s
}

/// Navigation state for the call flow direct renderer.
pub struct FlowNavigation {
    /// Logical ladder rows scrolled off the top of the viewport.
    pub scroll_offset: usize,
    /// Marked row for the mark/delta badge (Δ to the selected row), if any.
    pub mark_index: Option<usize>,
    /// Index of the currently selected row in the messages slice.
    pub selected_index: usize,
}

/// Render a call flow ladder diagram by painting directly into the terminal buffer.
///
/// Instead of building `Line`/`Span` objects and rendering via `Paragraph`,
/// this writes characters at exact `(x, y)` coordinates in the buffer,
/// guaranteeing perfect column alignment regardless of character widths.
///
/// Geometry: row 0 holds participant labels, row 1 the pipe tops; rows 2
/// through `height - 3` are the scrollable message window; the last two
/// rows are the pinned footer (pipes + labels). Participant pipes are
/// spread evenly across the width after the timestamp column, and the
/// area's last column is reserved for the ladder scrollbar. Annotations
/// (PDD, SDP badge, fold label) are clipped at the area's right edge so
/// nothing bleeds under a split detail pane.
///
/// # Arguments
/// * `frame` — frame whose buffer is painted directly.
/// * `area` — target region; also the clip bounds for annotations.
/// * `participants` — swimlane endpoints, one pipe per entry.
/// * `messages` — prepared rows to draw (arrows, RTP bars, spacers).
/// * `nav` — scroll offset, selection index and optional mark.
/// * `theme` — color theme for pipes, labels and fallback text.
///
/// # Side effects
/// Writes directly into the frame's buffer: labels, pipes, arrows, RTP
/// bars, annotations, the mark/delta badge, and a full-row background
/// highlight on the selected row. Degenerate geometry (< 30x5, no
/// participants, or a sub-10-column pipe gap) paints a short notice and
/// returns without drawing the ladder.
pub fn render_call_flow_direct(
    frame: &mut Frame,
    area: Rect,
    participants: &[Participant],
    messages: &[FormattedMessage],
    nav: &FlowNavigation,
    theme: &Theme,
) {
    let scroll_offset = nav.scroll_offset;
    let mark_index = nav.mark_index;
    let selected_index = nav.selected_index;
    let buf = frame.buffer_mut();
    let width = area.width;
    let height = area.height;

    if width < 30 || height < 5 {
        buf.set_string(
            area.x,
            area.y,
            "Terminal too small",
            Style::default().fg(theme.muted),
        );
        return;
    }

    let n = participants.len();
    if n == 0 {
        buf.set_string(
            area.x,
            area.y,
            "No participants",
            Style::default().fg(theme.muted),
        );
        return;
    }

    let ts_col = area.x;
    let ts_width = TS_COL_WIDTH as u16;

    // Calculate pipe positions for each participant
    let pipe_positions: Vec<u16> = if n <= 1 {
        vec![area.x + ts_width]
    } else {
        let usable = width.saturating_sub(ts_width + 2);
        (0..n)
            .map(|i| area.x + ts_width + (i as u16 * usable / (n as u16 - 1)))
            .collect()
    };

    // Verify minimum arrow width between adjacent pipes
    if n >= 2 {
        let min_gap = pipe_positions
            .windows(2)
            .map(|w| w[1].saturating_sub(w[0]))
            .min()
            .unwrap_or(0);
        if min_gap < 10 {
            buf.set_string(
                area.x,
                area.y,
                "Terminal too narrow for ladder",
                Style::default().fg(theme.muted),
            );
            return;
        }
    }

    let label_style = Style::default()
        .fg(theme.header)
        .add_modifier(Modifier::BOLD);
    let pipe_style = Style::default().fg(theme.muted);

    // Row 0: Labels above each pipe. Each label is confined to its own
    // non-overlapping cell so packed multi-leg columns can never overwrite
    // each other into garbage like "172.16.98172.16.98.101:5060". The
    // area's last column is reserved: the ladder scrollbar renders there.
    let area_right = area.x + area.width;
    let label_cells =
        participant_label_cells(&pipe_positions, area.x, area_right.saturating_sub(1));
    draw_participant_labels(
        buf,
        area.y,
        participants,
        &pipe_positions,
        &label_cells,
        22,
        label_style,
    );

    // Row 1: Pipes
    for &px in &pipe_positions {
        buf.set_string(px, area.y + 1, "\u{2502}", pipe_style); // │
    }

    // Mark + Delta badge (Feature 1): render in the top-right corner
    use unicode_width::UnicodeWidthStr;
    if let Some(mi) = mark_index
        && mi != selected_index
        && mi < messages.len()
        && selected_index < messages.len()
    {
        let mark_ts = messages[mi].raw_timestamp;
        let sel_ts = messages[selected_index].raw_timestamp;
        let delta_ms = sel_ts.signed_duration_since(mark_ts).num_milliseconds();
        let badge = if delta_ms.abs() >= 1000 {
            format!("\u{0394} {:+.3}s", delta_ms as f64 / 1000.0)
        } else {
            format!("\u{0394} {:+}ms", delta_ms)
        };
        // Display width, not byte length: the leading `Δ` (U+0394) is 2 bytes
        // but occupies a single column, so byte length would shove the badge
        // one column left of its flush-right position.
        let badge_len = UnicodeWidthStr::width(badge.as_str()) as u16;
        let badge_x = (area.x + width).saturating_sub(badge_len + 1);
        let badge_style = Style::default()
            .fg(theme.accent)
            .bg(Color::Rgb(40, 35, 20))
            .add_modifier(Modifier::BOLD);
        // Render on row 1 (pipe row) at the far right — avoids overlapping endpoint labels
        buf.set_string(badge_x, area.y + 1, &badge, badge_style);
    }

    // Message rows: we expand each FormattedMessage into 1 + extra_lines rows
    // Scrollable area starts at row 2, ends 2 rows before bottom (footer pipe + labels)
    let mut row: usize = 2;
    let mut logical_row: usize = 0;
    let max_row = (height as usize).saturating_sub(2); // leave room for footer

    for msg in messages {
        let msg_rows = 1 + msg.extra_lines.len();

        // Skip if entirely before the scroll window
        if logical_row + msg_rows <= scroll_offset {
            logical_row += msg_rows;
            continue;
        }

        // Render the main arrow row (may be partially scrolled)
        if logical_row >= scroll_offset && row < max_row {
            let y = area.y + row as u16;

            // Spacer rows: only render pipes and optional gap timestamp
            if msg.is_spacer {
                let spacer_style = Style::default().fg(theme.muted).add_modifier(Modifier::DIM);
                // Timestamp (gap label on first spacer, blank otherwise)
                if !msg.timestamp.trim().is_empty() {
                    buf.set_string(ts_col, y, &msg.timestamp, spacer_style);
                }
                // Dotted pipes at all column positions
                for &px in &pipe_positions {
                    buf.set_string(px, y, "\u{250A}", spacer_style); // ┊
                }
                row += 1;
                logical_row += msg_rows;
                if row >= max_row {
                    break;
                }
                continue;
            }

            // Timestamp column. The current row is shown by a full-row
            // background highlight applied after all content is drawn (see
            // below) — never a leading marker glyph, which would shift the
            // whole row's content right by one column as the cursor moves.
            match msg.selection_state {
                SelectionState::Selected => {
                    if !msg.timestamp.is_empty() {
                        buf.set_string(ts_col, y, &msg.timestamp, msg.timestamp_style);
                    }
                }
                SelectionState::Normal => {
                    if !msg.timestamp.is_empty() {
                        let dim_ts = msg.timestamp_style.add_modifier(Modifier::DIM);
                        buf.set_string(ts_col, y, &msg.timestamp, dim_ts);
                    }
                }
                SelectionState::Related => {
                    if !msg.timestamp.is_empty() {
                        buf.set_string(ts_col, y, &msg.timestamp, msg.timestamp_style);
                    }
                }
            }

            // Pipes at ALL positions
            for &px in &pipe_positions {
                buf.set_string(px, y, "\u{2502}", pipe_style); // │
            }

            // Clamp src_col and dst_col to valid range
            let src_col = msg.src_col.min(n.saturating_sub(1));
            let dst_col = msg.dst_col.min(n.saturating_sub(1));

            // RTP bar: render as a full-width label between the pipes
            if msg.is_rtp_bar {
                let left_pipe = pipe_positions.first().copied().unwrap_or(ts_width);
                let right_pipe = pipe_positions.last().copied().unwrap_or(area.right());
                let bar_x = left_pipe + 1;
                let bar_width = right_pipe.saturating_sub(left_pipe).saturating_sub(1) as usize;
                let padded = rtp_channel_bar(&msg.label, bar_width);
                let bar_style = match msg.selection_state {
                    SelectionState::Selected => {
                        msg.style.bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                    }
                    _ => msg.style,
                };
                buf.set_string(bar_x, y, &padded, bar_style);
            } else {
                // Arrow between source and destination pipes
                let src_x = pipe_positions[src_col];
                let dst_x = pipe_positions[dst_col];
                if src_x == dst_x {
                    // ONE endpoint: the message leaves and arrives at the same
                    // pipe. There is no span between columns to draw an arrow
                    // in, and the old code simply skipped the row — so a PBX
                    // talking to itself (every message
                    // `100.127.26.27:5060 -> 100.127.26.27:5060`) rendered a
                    // pipe and nothing else. The detail pane does not use
                    // endpoints, so it showed the whole message beside an empty
                    // ladder, which reads as a broken tool rather than as a
                    // one-sided capture.
                    //
                    // Drawn the way a sequence diagram shows a self-message: a
                    // loop glyph against the pipe, then the label.
                    let mut label = match &msg.fold_label {
                        Some(fl) if msg.folded_count > 0 && fl.starts_with("(+") => {
                            format!("{} (+{} retx)", msg.label, msg.folded_count)
                        }
                        _ => msg.label.clone(),
                    };
                    if let Some(ref note) = msg.diagnosis_note {
                        label.push_str(&format!(" [{note}]"));
                    }
                    let style = match msg.selection_state {
                        SelectionState::Selected => {
                            msg.style.bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                        }
                        _ => msg.style,
                    };
                    let start = src_x.saturating_add(1);
                    let room = area.right().saturating_sub(start) as usize;
                    if room > 2 {
                        let text = format!("\u{21ba} {label}");
                        buf.set_string(start, y, truncate(&text, room), style);
                    }
                } else {
                    // Retx fold headers carry their count ON the arrow: the
                    // annotation zone right of the ladder may be covered by
                    // the split detail pane, and a hidden fold reads as data
                    // loss. (Auth fold headers already say so in the label.)
                    let mut arrow_label = match &msg.fold_label {
                        Some(fl) if msg.folded_count > 0 && fl.starts_with("(+") => {
                            format!("{} (+{} retx)", msg.label, msg.folded_count)
                        }
                        _ => msg.label.clone(),
                    };
                    // Evidence tags ride on the arrow for the same reason the retx
                    // count above does. The annotation zone right of the ladder
                    // starts one column left of the rightmost pipe, so at 80
                    // columns there is room for a single character before the
                    // clip — a tag drawn there is invisible in practice, and an
                    // invisible "this is the message your problem came from" is
                    // worse than none, because the reader trusts the ladder to be
                    // showing them everything.
                    if let Some(ref note) = msg.diagnosis_note {
                        arrow_label.push_str(&format!(" [{note}]"));
                    }
                    let (arrow_str, arrow_x) =
                        format_arrow(&arrow_label, src_x, dst_x, msg.is_response);
                    let arrow_style = match msg.selection_state {
                        SelectionState::Selected => {
                            msg.style.bg(SELECTION_BG).add_modifier(Modifier::BOLD)
                        }
                        SelectionState::Related => msg.style,
                        SelectionState::Normal => msg.style.add_modifier(Modifier::DIM),
                    };
                    buf.set_string(arrow_x, y, &arrow_str, arrow_style);
                }
            }

            // Annotations after the rightmost pipe. Clipped to the ladder
            // area: anything written past it lands under the split detail
            // pane (rendered later), so it would either vanish or corrupt
            // that pane.
            let right_edge = area.x + area.width;
            let mut annotation_x = {
                let rightmost = pipe_positions.last().copied().unwrap_or(0);
                rightmost + 1
            };
            let draw_annotation =
                |buf: &mut ratatui::buffer::Buffer, x: u16, s: &str, style: Style| -> u16 {
                    if x >= right_edge {
                        return 0;
                    }
                    let avail = (right_edge - x) as usize;
                    let clipped: String = s.chars().take(avail).collect();
                    buf.set_string(x, y, &clipped, style);
                    clipped.chars().count() as u16
                };
            // PDD annotation
            if let Some(ref pdd) = msg.pdd_note {
                let w = draw_annotation(buf, annotation_x, pdd, Style::default().fg(theme.accent));
                annotation_x += w + 1;
            }

            // SDP delta badge (Feature 4)
            if let Some(ref badge) = msg.sdp_badge {
                let badge_str = format!(" [{badge}]");
                let badge_style = Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD);
                let w = draw_annotation(buf, annotation_x, &badge_str, badge_style);
                annotation_x += w;
            }

            // The signaling-diagnosis tag is NOT drawn here. It rides on the
            // arrow label above instead — see the comment there: this zone has
            // about one usable column at 80 wide, so an evidence tag placed here
            // would be clipped away and the reader would never know a message had
            // been cited.

            // Fold label (Feature 3)
            if let Some(ref fl) = msg.fold_label {
                let fold_str = format!(" {fl}");
                let fold_style = Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC);
                draw_annotation(buf, annotation_x, &fold_str, fold_style);
            }

            // Full-row highlight for the current message: patch a background
            // across the whole row (content keeps its own fg). This marks the
            // cursor without shifting any content horizontally.
            if msg.selection_state == SelectionState::Selected {
                buf.set_style(
                    Rect::new(area.x, y, area.width, 1),
                    Style::default().bg(SELECTION_BG),
                );
            }

            row += 1;
        } else if logical_row < scroll_offset {
            // This main row is scrolled off; advance logical but not visual
        }

        // Render extra lines (SDP, RTP markers)
        for (ei, (text, style)) in msg.extra_lines.iter().enumerate() {
            let extra_logical = logical_row + 1 + ei;
            if extra_logical >= scroll_offset && row < max_row {
                let y = area.y + row as u16;
                buf.set_string(area.x, y, text, *style);
                row += 1;
            }
        }

        logical_row += msg_rows;

        if row >= max_row {
            break;
        }
    }

    // Pinned footer: pipe line + abbreviated labels at bottom rows
    let footer_pipe_y = area.y + height.saturating_sub(2);
    let footer_label_y = area.y + height.saturating_sub(1);
    if height >= 4 {
        for &px in &pipe_positions {
            buf.set_string(px, footer_pipe_y, "\u{2502}", pipe_style); // │
        }

        // Footer labels — same non-overlapping cells as the header row.
        draw_participant_labels(
            buf,
            footer_label_y,
            participants,
            &pipe_positions,
            &label_cells,
            20,
            label_style,
        );
    }
}

/// The horizontal cell each participant label may occupy: half-open column
/// ranges bounded by the midpoints between neighboring pipes. The midpoint
/// column itself belongs to neither cell, so adjacent labels always keep at
/// least one blank column between them — at any terminal width.
fn participant_label_cells(pipes: &[u16], area_x: u16, area_right: u16) -> Vec<(u16, u16)> {
    let n = pipes.len();
    (0..n)
        .map(|i| {
            let left = if i == 0 {
                area_x
            } else {
                (pipes[i - 1] + pipes[i]) / 2 + 1
            };
            let right = if i == n - 1 {
                area_right
            } else {
                (pipes[i] + pipes[i + 1]) / 2
            };
            (left, right.max(left))
        })
        .collect()
}

/// Paint one participant label per pipe, each truncated (with ellipsis) to
/// its own cell so labels can never collide. Anchoring preserves the classic
/// ladder look: the first label left-aligned on its pipe, the last
/// right-aligned ending on its pipe, middle labels centered on theirs —
/// then clamped into the cell.
///
/// # Arguments
/// * `buf` — buffer to paint into.
/// * `y` — buffer row for the labels (header or footer).
/// * `participants` — one label per pipe.
/// * `pipes` — pipe column per participant, parallel to `participants`.
/// * `cells` — allowed column range per label (from
///   `participant_label_cells`).
/// * `max_label` — additional per-label truncation cap in characters.
/// * `style` — style applied to every label.
///
/// # Side effects
/// Writes the truncated labels into `buf` at row `y`; zero-width cells and
/// empty labels are skipped.
fn draw_participant_labels(
    buf: &mut ratatui::buffer::Buffer,
    y: u16,
    participants: &[Participant],
    pipes: &[u16],
    cells: &[(u16, u16)],
    max_label: usize,
    style: Style,
) {
    let n = participants.len();
    for (i, p) in participants.iter().enumerate() {
        let (cell_l, cell_r) = cells[i];
        let cell_w = cell_r.saturating_sub(cell_l) as usize;
        if cell_w == 0 {
            continue;
        }
        let lbl = truncate(&p.label, cell_w.min(max_label));
        let lbl_len = lbl.chars().count() as u16;
        if lbl_len == 0 {
            continue;
        }
        let pipe_x = pipes[i];
        let desired = if i == 0 {
            pipe_x
        } else if i == n - 1 {
            (pipe_x + 1).saturating_sub(lbl_len)
        } else {
            pipe_x.saturating_sub(lbl_len / 2)
        };
        // lbl_len <= cell_w, so cell_r - lbl_len >= cell_l: clamp is sound.
        let lbl_x = desired.clamp(cell_l, cell_r - lbl_len);
        buf.set_string(lbl_x, y, &lbl, style);
    }
}

/// Render call flow with a fallback "not found" message using direct buffer painting.
///
/// This is the TUI entry point that replaces the Paragraph-based
/// `render_call_flow_lines`. `prepared` is the cached
/// (participants, messages) pair from `prepare_messages`; `None` paints
/// "Dialog not found or empty." into the frame instead of a ladder.
pub fn render_call_flow_direct_or_empty(
    frame: &mut Frame,
    area: Rect,
    prepared: Option<&(Vec<Participant>, Vec<FormattedMessage>)>,
    nav: &FlowNavigation,
    theme: &Theme,
) {
    match prepared {
        Some((participants, msgs)) => {
            render_call_flow_direct(frame, area, participants, msgs, nav, theme);
        }
        None => {
            let buf = frame.buffer_mut();
            buf.set_string(
                area.x,
                area.y,
                "Dialog not found or empty.",
                Style::default().fg(theme.muted),
            );
        }
    }
}

/// Parameters for the message detail panel (right side of the split view).
pub struct MessageDetailView<'a> {
    /// Call-ID of the dialog holding the message to detail.
    pub call_id: &'a str,
    /// Index of the message to detail (raw index into the dialog).
    pub selected_msg: usize,
    /// Active transaction filter, if the ladder is narrowed to one
    /// transaction. When set, the `[N/M]` header counts the selected
    /// message's position WITHIN that transaction and the transaction's
    /// message count — not the whole dialog (which made the counter look
    /// stuck on a filtered page). `None` = whole-dialog counts.
    pub transaction_filter: Option<&'a (u32, String)>,
    /// Vertical scroll offset in display rows (clamped during render).
    pub scroll_offset: u16,
    /// Highlights the border when the detail pane holds keyboard focus
    /// (Tab toggles it).
    pub focused: bool,
    /// Header-name display form (as captured / expanded / compact).
    pub header_form: crate::tui::header_form::HeaderFormMode,
    /// Wrap long lines at the pane width; when off, lines truncate and
    /// `hscroll` shifts the view horizontally.
    pub wrap: bool,
    /// Horizontal scroll offset (display columns); ignored while `wrap`
    /// is on.
    pub hscroll: u16,
    /// Color theme for the border, title, and SIP highlighting.
    pub theme: &'a Theme,
}

/// What one detail-pane render actually used — visual geometry plus the
/// clamped scroll offsets. The event loop persists the clamps via
/// `RenderFeedback` so stale offsets self-correct on the next frame,
/// and tests assert the scrollbar/scroll math on it directly.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DetailMetrics {
    /// Visual rows of the whole message at the rendered width — WRAPPED
    /// rows when wrapping is on, logical lines otherwise.
    pub total_rows: usize,
    /// Widest line in display columns (pre-wrap).
    pub max_width: usize,
    /// Vertical scroll after clamping to `total_rows - viewport`.
    pub scroll: u16,
    /// Horizontal scroll after clamping (always 0 while wrapping).
    pub hscroll: u16,
    /// Horizontal headroom this geometry leaves: `max_width - pane width`,
    /// and `0` when the widest line already fits the pane. Measured
    /// whether or not wrapping is on — it describes what h-scrolling
    /// *would* have to work with, so the wrapped frame that precedes a `w`
    /// press already carries the answer.
    ///
    /// Reported back so the *controller* can answer "←/→ can't move this"
    /// with a reason instead of silence. Only the render knows the pane
    /// width, so before this existed the controller had no way to tell a
    /// press that scrolled from a press that was clamped to nothing — and
    /// the clamped press said nothing at all (#188).
    pub max_hscroll: u16,
}

/// Render the message detail panel (right side of the split view).
///
/// Draws a bordered pane titled `[pos/count] <method-or-status>` holding the
/// syntax-highlighted raw SIP message, wrapped or h-scrollable per
/// `view.wrap`, with vertical/horizontal scrollbars when content overflows.
///
/// # Arguments
/// * `frame` — frame to draw into.
/// * `area` — target region including the border.
/// * `store` — dialog store to look the message up in.
/// * `view` — all panel parameters (selection, scrolls, wrap, focus, theme).
///
/// # Returns
/// The `DetailMetrics` this render actually used — total display rows,
/// widest line, and both scroll offsets after clamping — so the caller can
/// persist the clamps and drive scroll keys. Zeroed (`default`) when the
/// dialog or message is missing or the inner area is empty.
///
/// # Side effects
/// Draws the block, content paragraph and any scrollbars into `frame`;
/// paints a fallback notice when the dialog or message is missing.
pub fn render_message_detail(
    frame: &mut Frame,
    area: Rect,
    store: &DialogStore,
    view: &MessageDetailView,
) -> DetailMetrics {
    let MessageDetailView {
        call_id,
        selected_msg,
        transaction_filter: _, // read via `view.transaction_filter` below
        scroll_offset,
        focused,
        header_form,
        wrap,
        hscroll,
        theme,
    } = *view;
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return DetailMetrics::default();
        }
    };

    let msg = match dialog.messages.get(selected_msg) {
        Some(m) => m,
        None => {
            let para =
                Paragraph::new("No message selected.").style(Style::default().fg(theme.muted));
            frame.render_widget(para, area);
            return DetailMetrics::default();
        }
    };

    // Header counts follow the ladder: a transaction filter narrows the
    // visible rows, so the counter must count within the transaction, not
    // the whole dialog (else it starts high and barely moves — looking
    // stuck). Unfiltered keeps whole-dialog counts.
    let (pos, count) = match view.transaction_filter {
        Some(key) => {
            let filtered: Vec<usize> = dialog
                .messages
                .iter()
                .enumerate()
                .filter(|(_, m)| crate::tui::call_flow::transaction_key(m).as_ref() == Some(key))
                .map(|(i, _)| i)
                .collect();
            let pos = filtered
                .iter()
                .position(|&i| i == selected_msg)
                .map_or(selected_msg + 1, |p| p + 1);
            (pos, filtered.len().max(1))
        }
        None => (selected_msg + 1, dialog.messages.len()),
    };
    let title = format!(
        " [{}/{}] {} ",
        pos,
        count,
        if msg.is_request {
            msg.method
                .as_ref()
                .map(|m| m.as_str())
                .unwrap_or("?")
                .to_string()
        } else {
            format!(
                "{} {}",
                msg.status_code.unwrap_or(0),
                msg.reason.as_deref().unwrap_or("")
            )
        },
    );

    // A focused pane gets a bright, bold border so the user can see which side
    // the arrow keys are driving.
    let border_style = if focused {
        Style::default()
            .fg(theme.selected)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.border)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(border_style);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_bytes = String::from_utf8_lossy(&msg.raw);
    let raw_text = crate::tui::header_form::reformat_headers(&raw_bytes, header_form);
    let lines = highlight_sip_detail(&raw_text, theme);
    // Widest logical line in display columns — drives the h-scroll clamp
    // and its scrollbar in unwrapped mode.
    let max_width = lines.iter().map(Line::width).max().unwrap_or(0);

    if inner.width == 0 || inner.height == 0 {
        return DetailMetrics {
            total_rows: lines.len(),
            max_width,
            scroll: 0,
            hscroll: 0,
            // A zero-sized pane shows nothing, so nothing can be scrolled
            // into view — the same "no room to move" the controller reports.
            max_hscroll: 0,
        };
    }

    // Wrapping happens HERE, not in the Paragraph: the scrollbar and the
    // scroll clamp must count the same rows that render. Comparing
    // logical lines against a wrapped viewport hid the scrollbar and
    // pinned the scroll to 0 whenever long headers wrapped.
    let display = if wrap {
        wrap_styled_lines(lines, inner.width)
    } else {
        lines
    };
    let total_rows = display.len();

    // Clamp both scrolls so the End key (which sets a large value) and
    // any stale offset never scroll the content entirely out of view.
    let viewport = inner.height as usize;
    let max_scroll = total_rows.saturating_sub(viewport);
    let eff_scroll = (scroll_offset as usize).min(max_scroll) as u16;
    // Headroom is a property of the content and the pane, not of the wrap
    // mode, so it is measured even while wrapping: the frame drawn BEFORE
    // the operator presses `w` is then already able to answer "will ←/→
    // move anything once wrapping is off?". Measuring it as 0 whenever
    // wrapping was on made the first press after `w` — the exact sequence
    // in the field report — decide from a reading that described the
    // wrapped pane rather than the unwrapped one (#188).
    let max_hscroll = max_width.saturating_sub(inner.width as usize);
    // Wrapping has no horizontal offset to apply, however wide the content.
    let eff_hscroll = if wrap {
        0
    } else {
        (hscroll as usize).min(max_hscroll) as u16
    };

    let para = Paragraph::new(display).scroll((eff_scroll, eff_hscroll));
    frame.render_widget(para, inner);

    // Vertical scrollbar on the right border when the message overflows.
    if total_rows > viewport {
        let mut sb_state = ScrollbarState::new(total_rows)
            .viewport_content_length(viewport)
            .position(eff_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(theme.selected))
            .track_style(Style::default().fg(theme.muted));
        frame.render_stateful_widget(scrollbar, area, &mut sb_state);
    }

    // Horizontal scrollbar on the bottom border when unwrapped lines are
    // wider than the pane. Wrapped lines never overflow horizontally, so
    // the wrap check is explicit now that `max_hscroll` no longer folds it in.
    if !wrap && max_hscroll > 0 {
        let mut sb_state = ScrollbarState::new(max_width)
            .viewport_content_length(inner.width as usize)
            .position(eff_hscroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::HorizontalBottom)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(theme.selected))
            .track_style(Style::default().fg(theme.muted));
        frame.render_stateful_widget(scrollbar, area, &mut sb_state);
    }

    DetailMetrics {
        total_rows,
        max_width,
        scroll: eff_scroll,
        hscroll: eff_hscroll,
        // Saturating rather than truncating: a line wider than 65535
        // columns must still report "there is room to the right", and a
        // wrapping cast would report the opposite.
        max_hscroll: u16::try_from(max_hscroll).unwrap_or(u16::MAX),
    }
}

/// Split styled lines at `width` display columns — character wrapping,
/// display-width aware. A wide glyph (CJK, emoji) that would straddle the
/// boundary moves wholly to the next row; zero-width characters attach to
/// the current row. Every input line yields at least one output row, so
/// row indices stay meaningful for empty lines.
fn wrap_styled_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    use unicode_width::UnicodeWidthChar;
    let max = width as usize;
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        let mut row: Vec<Span<'static>> = Vec::new();
        let mut cols = 0usize;
        for span in line.spans {
            let style = span.style;
            let mut frag = String::new();
            for ch in span.content.chars() {
                let w = ch.width().unwrap_or(0);
                if w > 0 && cols + w > max {
                    if !frag.is_empty() {
                        row.push(Span::styled(std::mem::take(&mut frag), style));
                    }
                    out.push(Line::from(std::mem::take(&mut row)));
                    cols = 0;
                }
                frag.push(ch);
                cols += w;
            }
            if !frag.is_empty() {
                row.push(Span::styled(frag, style));
            }
        }
        out.push(Line::from(row));
    }
    out
}

/// Total logical rows the ladder occupies. Each message paints `1 + extra_lines`
/// rows; this matches the row accounting in `render_call_flow_direct` and so
/// is the correct content length for the ladder scrollbar.
pub fn ladder_total_rows(messages: &[FormattedMessage]) -> usize {
    messages.iter().map(|m| 1 + m.extra_lines.len()).sum()
}

/// Ladder row (in `ladder_total_rows` units) where the `visible_idx`-th
/// non-spacer entry starts — the geometry needed to keep the keyboard
/// selection inside the viewport regardless of spacers and extra lines.
pub fn ladder_row_of_visible(messages: &[FormattedMessage], visible_idx: usize) -> usize {
    let mut row = 0;
    let mut vis = 0;
    for m in messages {
        if !m.is_spacer {
            if vis == visible_idx {
                return row;
            }
            vis += 1;
        }
        row += 1 + m.extra_lines.len();
    }
    row
}

/// Number of ladder rows visible at once for a given pane height. The ladder
/// reserves two rows at the top (participant labels + pipes) and two at the
/// bottom (footer), so the scrollable window is `height - 4`.
pub fn ladder_visible_rows(height: u16) -> usize {
    (height as usize).saturating_sub(4)
}

/// Render a vertical scrollbar on the right edge of the ladder pane when the
/// flow is taller than the pane. No-op when everything already fits (or the
/// pane is under 5 rows).
///
/// # Arguments
/// * `frame` — frame to draw into.
/// * `area` — the ladder pane; the scrollbar rides its right edge.
/// * `total_rows` — ladder content length (from `ladder_total_rows`).
/// * `position` — current scroll position in ladder rows.
/// * `theme` — colors for the thumb and track.
///
/// # Side effects
/// Draws the stateful scrollbar widget into `frame` when overflowing.
pub fn render_ladder_scrollbar(
    frame: &mut Frame,
    area: Rect,
    total_rows: usize,
    position: usize,
    theme: &Theme,
) {
    let visible = ladder_visible_rows(area.height);
    if total_rows <= visible || area.height < 5 {
        return;
    }
    let mut sb_state = ScrollbarState::new(total_rows)
        .viewport_content_length(visible)
        .position(position);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .thumb_style(Style::default().fg(theme.selected))
        .track_style(Style::default().fg(theme.muted));
    frame.render_stateful_widget(scrollbar, area, &mut sb_state);
}

/// Highlight a raw SIP message for the detail panel.
///
/// Styles `raw_text` line by line: the first line (request/status line)
/// bold, header lines split at the first `:` into a colored name and plain
/// value, and everything after the first blank line (the body) muted +
/// italic. Returns the styled lines; an empty input yields a single
/// "(empty message)" placeholder line.
fn highlight_sip_detail(raw_text: &str, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut in_body = false;
    let mut is_first = true;

    for raw_line in raw_text.lines() {
        if !in_body && raw_line.trim().is_empty() {
            in_body = true;
            lines.push(Line::from(""));
            continue;
        }

        if in_body {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(theme.muted)
                    .add_modifier(Modifier::ITALIC),
            )));
        } else if is_first {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default()
                    .fg(theme.foreground)
                    .add_modifier(Modifier::BOLD),
            )));
            is_first = false;
        } else if let Some(colon_pos) = raw_line.find(':') {
            let name = &raw_line[..colon_pos];
            let value = &raw_line[colon_pos..];
            lines.push(Line::from(vec![
                Span::styled(name.to_string(), Style::default().fg(theme.header)),
                Span::styled(value.to_string(), Style::default().fg(theme.foreground)),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                raw_line.to_string(),
                Style::default().fg(theme.foreground),
            )));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "(empty message)",
            Style::default().fg(theme.muted),
        )));
    }

    lines
}

// ── Ladder formatting (Paragraph path) ─────────────────────────────

/// Format all messages in a dialog as ladder diagram lines.
///
/// Two-column Paragraph-path ladder: the left pipe is the first message's
/// source, the right pipe its destination, and every arrow points by
/// whether a message's source matches the left address. Emits a header
/// row with both endpoint labels, pipe rows top and bottom, and one arrow
/// line per message (with a PDD annotation on the first 180).
///
/// # Arguments
/// * `messages` — the dialog's messages in capture order.
/// * `pdd_ms` — post-dial delay to annotate on the first 180, if known.
/// * `arrow_width` — column span available for each arrow.
/// * `theme` — color theme for timestamps, pipes and arrows.
///
/// # Returns
/// The styled lines; a single "(no messages)" line when `messages` is
/// empty.
pub fn format_ladder(
    messages: &[SipMessage],
    pdd_ms: Option<i64>,
    arrow_width: usize,
    theme: &Theme,
) -> Vec<Line<'static>> {
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let left_pipe_col = TS_COL_WIDTH;
    let right_pipe_col = left_pipe_col + 1 + arrow_width;

    let mut lines: Vec<Line<'static>> = Vec::new();

    let left_label = truncate(&left_addr, 25);
    let right_label = truncate(&right_addr, 25);

    lines.push(ladder_header(
        &left_label,
        &right_label,
        left_pipe_col,
        right_pipe_col,
        theme,
    ));

    lines.push(Line::from(ladder_pipe(
        &" ".repeat(TS_COL_WIDTH),
        left_pipe_col,
        right_pipe_col,
    )));

    let mut pdd_annotated = false;

    for msg in messages {
        let ts_str = msg.timestamp.format("%H:%M:%S%.3f").to_string();
        let label = format_message_label(msg);
        let msg_style = message_style(msg, theme);

        let this_src = format!("{}:{}", msg.src_addr, msg.src_port);
        let is_left_to_right = this_src == left_addr;

        let ts_part = format!("{:<width$}", ts_str, width = TS_COL_WIDTH);

        let is_response = !msg.is_request;
        let arrow_span = arrow_width.saturating_sub(1);
        let arrow_line = if is_left_to_right {
            format_arrow_right(&label, arrow_span, is_response)
        } else {
            format_arrow_left(&label, arrow_span, is_response)
        };

        let mut pdd_note = String::new();
        if !pdd_annotated
            && let Some(pdd) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pdd_note = format!("  PDD: {}ms", pdd);
            pdd_annotated = true;
        }

        lines.push(Line::from(vec![
            Span::styled(ts_part, Style::default().fg(theme.muted)),
            Span::styled("\u{2502}", Style::default().fg(theme.muted)),
            Span::styled(arrow_line, msg_style),
            Span::styled("\u{2502}", Style::default().fg(theme.muted)),
            Span::styled(pdd_note, Style::default().fg(theme.accent)),
        ]));
    }

    lines.push(Line::from(ladder_pipe(
        &" ".repeat(TS_COL_WIDTH),
        left_pipe_col,
        right_pipe_col,
    )));

    lines
}

/// Format ladder with full display options (SDP mode, timestamp mode, color, etc.).
///
/// The options-aware variant of `format_ladder` for the Paragraph path:
/// timestamps follow `opts.ts_mode` (Scaled falls back to delta-prev — no
/// spacer rows here), arrows are colored per `opts.color_mode`, SDP info
/// lines follow `opts.sdp_mode`, the selected message gains a
/// `[SELECTED]` marker, and `show_rtp` draws an "RTP stream active" line
/// when a BYE ends an established call.
///
/// # Arguments
/// * `messages` — the dialog's messages in capture order.
/// * `first_ts` — reference timestamp for the delta timestamp modes.
/// * `pdd_ms` — post-dial delay to annotate on the first 180, if known.
/// * `arrow_width` — column span available for each arrow.
/// * `opts` — full display options.
///
/// # Returns
/// The styled lines; a single "(no messages)" line when `messages` is
/// empty.
fn format_ladder_with_options(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    arrow_width: usize,
    opts: &FlowDisplayOptions<'_>,
) -> Vec<Line<'static>> {
    let sdp_mode = opts.sdp_mode;
    let ts_mode = opts.ts_mode;
    let color_mode = opts.color_mode;
    let show_rtp = opts.show_rtp;
    let selected_msg = opts.selected_msg;
    let theme = opts.theme;
    if messages.is_empty() {
        return vec![Line::from("(no messages)")];
    }

    let left_addr = format!("{}:{}", messages[0].src_addr, messages[0].src_port);
    let right_addr = format!("{}:{}", messages[0].dst_addr, messages[0].dst_port);

    let ts_width = TS_COL_WIDTH;
    let left_pipe_col = ts_width;
    let right_pipe_col = left_pipe_col + 1 + arrow_width;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let left_label = truncate(&left_addr, 25);
    let right_label = truncate(&right_addr, 25);

    lines.push(ladder_header(
        &left_label,
        &right_label,
        left_pipe_col,
        right_pipe_col,
        theme,
    ));

    let ts_prefix = " ".repeat(ts_width);
    lines.push(Line::from(ladder_pipe(
        &ts_prefix,
        left_pipe_col,
        right_pipe_col,
    )));

    let mut pdd_done = false;
    let mut in_call = false;
    let mut prev_ts = first_ts;
    let cid_colors = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    for (mi, msg) in messages.iter().enumerate() {
        let (ts_str, ts_style) = match ts_mode {
            TimestampMode::Absolute => {
                let s = format!(
                    "{:<width$}",
                    msg.timestamp.format("%H:%M:%S%.3f"),
                    width = ts_width
                );
                (s, Style::default().fg(theme.muted))
            }
            TimestampMode::DeltaPrev => {
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (s, sty)
            }
            TimestampMode::DeltaFirst => {
                let d = msg
                    .timestamp
                    .signed_duration_since(first_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                (s, sty)
            }
            TimestampMode::Scaled => {
                // Scaled mode uses delta-prev formatting in the legacy path
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let s = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (s, sty)
            }
        };
        let label = format_message_label(msg);
        let sty = match color_mode {
            ColorMode::Method => message_style(msg, theme),
            ColorMode::CallId => {
                let ci = msg.call_id().unwrap_or("");
                let i =
                    ci.bytes().fold(0usize, |a, b| a.wrapping_add(b as usize)) % cid_colors.len();
                Style::default().fg(cid_colors[i])
            }
            ColorMode::CSeq => {
                let cn = msg.cseq().map(|(n, _)| n).unwrap_or(0);
                Style::default().fg(cid_colors[(cn as usize) % cid_colors.len()])
            }
        };
        let sel = selected_msg == Some(mi);

        let src = format!("{}:{}", msg.src_addr, msg.src_port);
        let ltr = src == left_addr;
        let is_response = !msg.is_request;
        let as_ = arrow_width.saturating_sub(1);
        let al = if ltr {
            format_arrow_right(&label, as_, is_response)
        } else {
            format_arrow_left(&label, as_, is_response)
        };

        let mut pn = String::new();
        if !pdd_done
            && let Some(p) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pn = format!("  PDD: {p}ms");
            pdd_done = true;
        }

        let mut sp = Vec::new();
        if !ts_str.is_empty() {
            sp.push(Span::styled(ts_str, ts_style));
        }
        sp.push(Span::styled("\u{2502}", Style::default().fg(theme.muted)));
        sp.push(Span::styled(al, sty));
        sp.push(Span::styled("\u{2502}", Style::default().fg(theme.muted)));
        if !pn.is_empty() {
            sp.push(Span::styled(pn, Style::default().fg(theme.accent)));
        }
        if sel {
            sp.push(Span::styled(
                "  [SELECTED]",
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        lines.push(Line::from(sp));

        if sdp_mode != SdpDisplayMode::None
            && let Some(ss) = msg.sdp()
        {
            let ind = " ".repeat(ts_width + 1);
            match sdp_mode {
                SdpDisplayMode::Summary => {
                    let c = format_sdp_codecs(&ss);
                    if !c.is_empty() {
                        lines.push(Line::from(Span::styled(
                            format!("{ind} Codecs: {c}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                }
                SdpDisplayMode::Full => {
                    let bt = String::from_utf8_lossy(&msg.body);
                    for sl in bt.lines() {
                        lines.push(Line::from(Span::styled(
                            format!("{ind}  {sl}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        )));
                    }
                }
                SdpDisplayMode::None => {}
            }
        }

        if show_rtp {
            if !msg.is_request && msg.status_code == Some(200) {
                in_call = true;
            }
            if msg.is_request && msg.method.as_ref() == Some(&crate::sip::SipMethod::Bye) && in_call
            {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{}\u{2500}\u{2500}\u{2500}\u{2500} RTP stream active \u{2500}\u{2500}\u{2500}\u{2500}",
                        " ".repeat(ts_width + 1)
                    ),
                    Style::default().fg(theme.muted),
                )));
                in_call = false;
            }
        }
    }

    lines.push(Line::from(ladder_pipe(
        &ts_prefix,
        left_pipe_col,
        right_pipe_col,
    )));
    lines
}

// ── Tests ───────────────────────────────────────────────────────────

/// Tests for both render paths: RTP channel bars, ladder building, direct
/// buffer painting, label cells, and the detail-pane scroll geometry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;

    // ── rtp_channel_bar: double-rail centered media channel ───────────

    /// The `═` double-rail glyph the RTP channel bar is built from.
    const RAIL: char = '\u{2550}'; // ═

    /// The bar fills exactly `width` columns, rails on both ends, label
    /// centered, using `═` — never the SIP arrows' single line.
    #[test]
    fn rtp_bar_centers_with_double_rail() {
        let bar = rtp_channel_bar(" RTP \u{00B7} PCMU ", 40);
        // Exactly `width` display columns, rails on both ends, label intact.
        assert_eq!(bar.chars().count(), 40);
        assert_eq!(bar.chars().next(), Some(RAIL), "left rail missing");
        assert_eq!(bar.chars().last(), Some(RAIL), "right rail missing");
        assert!(bar.contains("RTP \u{00B7} PCMU"), "label lost");
        // Centered: left/right rail runs differ by at most one (odd padding).
        let left = bar.chars().take_while(|&c| c == RAIL).count();
        let right = bar.chars().rev().take_while(|&c| c == RAIL).count();
        assert!(
            left.abs_diff(right) <= 1,
            "not centered: {left} left vs {right} right rails"
        );
        // The rail must NOT be the single-line `─` used by SIP arrows.
        assert!(
            !bar.contains('\u{2500}'),
            "used single line, not double rail"
        );
    }

    /// A label wider than the gap clamps to `width` instead of overflowing.
    #[test]
    fn rtp_bar_truncates_instead_of_overflowing() {
        // Label wider than the gap → truncated to width, never left-aligned
        // overflow past the pipe. (This was the original bug.)
        let bar = rtp_channel_bar(" RTP \u{00B7} PCMA, PCMU, G722, opus \u{00B7} active ", 8);
        assert_eq!(bar.chars().count(), 8, "must clamp to width");
    }

    /// A label exactly as wide as the bar gets no rails.
    #[test]
    fn rtp_bar_exact_width_is_label_only() {
        let label = "RTP active"; // 10 chars
        let bar = rtp_channel_bar(label, 10);
        assert_eq!(bar, label, "exact fit should not add rails");
    }

    /// Empty labels, zero width, special/NUL chars and width 1 all render
    /// without panic or overflow.
    #[test]
    fn rtp_bar_adversarial_inputs() {
        // Empty label → pure rail.
        let b = rtp_channel_bar("", 6);
        assert_eq!(b, "\u{2550}".repeat(6));
        // Zero width → empty, no panic.
        assert_eq!(rtp_channel_bar(" RTP ", 0), "");
        // Backslash / special chars in the label survive intact.
        let b = rtp_channel_bar(r" a\b\c ", 20);
        assert!(b.contains(r"a\b\c"), "backslashes mangled: {b}");
        assert_eq!(b.chars().count(), 20);
        // Embedded NUL is carried through without truncating the string.
        let b = rtp_channel_bar(" a\0b ", 10);
        assert!(b.contains('\0'), "NUL dropped");
        assert_eq!(b.chars().count(), 10);
        // Width 1, multi-char label → single truncated char, no panic.
        assert_eq!(rtp_channel_bar("xyz", 1).chars().count(), 1);
    }

    /// An empty dialog formats to the single "(no messages)" line.
    #[test]
    fn format_ladder_empty_messages() {
        let theme = crate::tui::Theme::default();
        let lines = format_ladder(&[], None, 40, &theme);
        assert_eq!(lines.len(), 1);
    }

    // ── Arrow DIRECTION: requests and responses point opposite ways ────

    /// A request travels A→B (arrowhead ▶ on the right); its response
    /// travels B→A (arrowhead ◀ on the left). Regression guard for the gap
    /// where the ladder direction was never asserted end to end — only the
    /// request/response *src↔dst* swap makes the arrow flip, so this
    /// exercises real A→B / B→A messages, not the glyph helper in isolation.
    #[test]
    fn ladder_request_points_right_response_points_left() {
        let theme = crate::tui::Theme::default();
        // req() is A→B, resp() is B→A (src/dst swapped), as on a real wire.
        let msgs = vec![
            req("INVITE", "1 INVITE", "dir-call", base_ts()),
            resp(200, "OK", "1 INVITE", "dir-call", base_ts()),
        ];
        let lines = format_ladder(&msgs, None, 48, &theme);
        let text: Vec<String> = lines.iter().map(line_to_string).collect();
        let invite = text
            .iter()
            .find(|l| l.contains("INVITE"))
            .expect("INVITE row");
        let ok = text.iter().find(|l| l.contains("200")).expect("200 OK row");

        // Request: rightward only.
        assert!(
            invite.contains('\u{25B6}') && !invite.contains('\u{25C0}'),
            "request must point right (▶), got: {invite:?}"
        );
        // Response: leftward only — the bug the perf.pcap capture *looked* like
        // (it was actually one-directional synthetic data; here the response is
        // genuinely B→A and must reverse).
        assert!(
            ok.contains('\u{25C0}') && !ok.contains('\u{25B6}'),
            "response must point left (◀), got: {ok:?}"
        );
    }

    /// Faithful rendering: when a (malformed/synthetic) response carries the
    /// SAME src→dst as the request — e.g. a one-directional load corpus —
    /// the arrow follows the actual packet addresses (forward), it is NOT
    /// force-flipped by status code. This documents that arrow direction is
    /// wire-driven.
    #[test]
    fn ladder_arrow_follows_actual_src_dst_not_status() {
        let theme = crate::tui::Theme::default();
        // Build a 200 OK that (wrongly) travels A→B, like perf.pcap's responses.
        let raw = build_raw(
            "SIP/2.0 200 OK",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfwd",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>;tag=t2",
                "Call-ID: fwd-call",
                "CSeq: 1 INVITE",
            ],
            "",
        );
        let fwd_resp = crate::sip::parser::parse_sip(
            &raw,
            base_ts(),
            ip_a(),
            ip_b(), // A→B, NOT swapped
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        let msgs = vec![req("INVITE", "1 INVITE", "fwd-call", base_ts()), fwd_resp];
        let lines = format_ladder(&msgs, None, 48, &theme);
        let text: Vec<String> = lines.iter().map(line_to_string).collect();
        let ok = text.iter().find(|l| l.contains("200")).expect("200 OK row");
        // Same src→dst as the request ⇒ same (rightward) direction. Faithful to
        // the wire, not flipped by the 2xx status.
        assert!(
            ok.contains('\u{25B6}') && !ok.contains('\u{25C0}'),
            "a response that travels A→B on the wire must render forward, got: {ok:?}"
        );
    }

    /// A parsed single-message dialog yields header + bars + message lines.
    #[test]
    fn format_ladder_produces_lines() {
        use crate::sip::parser::parse_sip;
        use std::net::{IpAddr, Ipv4Addr};

        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                     From: <sip:alice@example.com>;tag=t1\r\n\
                     To: <sip:bob@example.com>\r\n\
                     Call-ID: ladder-test@example.com\r\n\
                     CSeq: 1 INVITE\r\n\
                     Content-Length: 0\r\n\r\n";

        let ts = chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2024, 1, 1, 0, 0, 0).unwrap();
        let msg = parse_sip(
            raw,
            ts,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse ok");

        let theme = crate::tui::Theme::default();
        let lines = format_ladder(&[msg], None, 50, &theme);
        // Should have header + bar + message + closing bar
        assert!(lines.len() >= 4);
    }

    // ── Shared helpers for the builder/render coverage tests ───────────

    use crate::sip::dialog_store::DialogStore;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, Utc};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixture endpoint A (10.0.0.1), the request originator.
    fn ip_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    /// Fixture endpoint B (10.0.0.2), the request target.
    fn ip_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    /// Fixed base timestamp all fixture dialogs are built from.
    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Assemble raw SIP bytes from `first_line`, `headers` and `body`,
    /// appending a computed Content-Length header.
    fn build_raw(first_line: &str, headers: &[&str], body: &str) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(first_line);
        s.push_str("\r\n");
        for h in headers {
            s.push_str(h);
            s.push_str("\r\n");
        }
        s.push_str(&format!("Content-Length: {}\r\n", body.len()));
        s.push_str("\r\n");
        s.push_str(body);
        s.into_bytes()
    }

    /// A->B request message.
    fn req(method: &str, cseq: &str, call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_raw(
            &format!("{method} sip:bob@10.0.0.2 SIP/2.0"),
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKreq",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
            ],
            "",
        );
        parse_sip(&raw, ts, ip_a(), ip_b(), 5060, 5060, TransportProto::Udp).expect("parse request")
    }

    /// B->A response message.
    fn resp(status: u16, reason: &str, cseq: &str, call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_raw(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKreq",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq}"),
            ],
            "",
        );
        parse_sip(&raw, ts, ip_b(), ip_a(), 5060, 5060, TransportProto::Udp)
            .expect("parse response")
    }

    /// INVITE A->B carrying an SDP offer.
    fn invite_with_sdp(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let sdp = "v=0\r\n\
                   o=- 1 1 IN IP4 10.0.0.1\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 20000 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";
        let raw = build_raw(
            "INVITE sip:bob@10.0.0.2 SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsdp",
                "From: \"Alice\" <sip:alice@10.0.0.1>;tag=t1",
                "To: \"Bob\" <sip:bob@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
            ],
            sdp,
        );
        parse_sip(&raw, ts, ip_a(), ip_b(), 5060, 5060, TransportProto::Udp)
            .expect("parse INVITE+SDP")
    }

    /// Baseline `FlowDisplayOptions`: SDP off, absolute timestamps, method
    /// coloring, no RTP, no selection — tests override individual fields.
    fn opts<'a>(theme: &'a Theme) -> FlowDisplayOptions<'a> {
        let resolver: &'static crate::names::NameResolver =
            Box::leak(Box::new(crate::names::NameResolver::new()));
        FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::Absolute,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg: None,
            theme,
            resolver,
            name_mode: crate::names::NameMode::Off,
            rtp_segments: &[],
        }
    }

    /// Flatten a styled line to its plain text.
    fn line_to_string(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    /// Flatten styled lines to newline-joined plain text.
    fn lines_to_string(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Store with a complete INVITE/180/200/ACK/BYE/200 dialog.
    fn store_full_dialog(call_id: &str) -> DialogStore {
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", call_id, t));
        store.process_message(resp(
            180,
            "Ringing",
            "1 INVITE",
            call_id,
            t + TimeDelta::seconds(1),
        ));
        store.process_message(resp(
            200,
            "OK",
            "1 INVITE",
            call_id,
            t + TimeDelta::seconds(2),
        ));
        store.process_message(req(
            "ACK",
            "1 ACK",
            call_id,
            t + TimeDelta::milliseconds(2100),
        ));
        store.process_message(req("BYE", "2 BYE", call_id, t + TimeDelta::seconds(30)));
        store.process_message(resp(
            200,
            "OK",
            "2 BYE",
            call_id,
            t + TimeDelta::seconds(30),
        ));
        store
    }

    /// A `TestBackend` terminal of the given size.
    fn terminal(w: u16, h: u16) -> Terminal<TestBackend> {
        Terminal::new(TestBackend::new(w, h)).unwrap()
    }

    /// Dump the terminal buffer as newline-separated rows of symbols.
    fn buffer_text(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
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

    // ── direct-path selection highlight (R2: no shifting marker) ────────

    /// A minimal INVITE `FormattedMessage` with the given timestamp text,
    /// selection state and columns; all other fields defaulted.
    fn fmt_msg(
        ts: &str,
        state: SelectionState,
        src_col: usize,
        dst_col: usize,
    ) -> FormattedMessage {
        FormattedMessage {
            timestamp: ts.to_string(),
            timestamp_style: Style::default(),
            label: "INVITE".to_string(),
            style: Style::default(),
            src_col,
            dst_col,
            pdd_note: None,
            extra_lines: Vec::new(),
            selected: matches!(state, SelectionState::Selected),
            call_id: "c@test".to_string(),
            selection_state: state,
            is_response: false,
            raw_timestamp: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
            folded_count: 0,
            fold_label: None,
            is_spacer: false,
            sdp_badge: None,
            is_retransmission: false,
            is_rtp_bar: false,
            raw_index: None,
            diagnosis_note: None,
        }
    }

    /// A dialog with ONE endpoint still shows its messages.
    ///
    /// Reported from a real Asterisk capture: selecting the first INVITE, and
    /// the CANCELs, showed full message detail beside an EMPTY ladder. Four of
    /// that capture's eight dialogs were the PBX talking to ITSELF — every
    /// message `100.127.26.27:5060 -> 100.127.26.27:5060` — which collapses to
    /// a single participant, so `src_x == dst_x` and the arrow branch was
    /// skipped entirely. The pipe glyph still painted, so the pane looked
    /// present and empty rather than obviously broken.
    ///
    /// A PBX looping through itself is ordinary, as is any hairpinned leg
    /// captured on one interface.
    #[test]
    fn a_single_endpoint_dialog_still_paints_its_messages() {
        let theme = Theme::default();
        let parts = vec![Participant {
            addr: "100.127.26.27:5060".into(),
            label: "100.127.26.27:5060".into(),
        }];
        // Every message leaves and arrives at the same column, as the capture does.
        let msgs = vec![fmt_msg("11:58:49.000", SelectionState::Selected, 0, 0), {
            let mut m = fmt_msg("11:58:49.100", SelectionState::Normal, 0, 0);
            m.label = "CANCEL".into();
            m
        }];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: None,
            selected_index: 0,
        };
        let mut term = terminal(80, 24);
        term.draw(|f| {
            let a = f.area();
            render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            text.contains("INVITE"),
            "a self-addressed INVITE must still appear in the ladder; got:\n{text}"
        );
        assert!(
            text.contains("CANCEL"),
            "a self-addressed CANCEL must still appear in the ladder; got:\n{text}"
        );
    }

    /// The current row is marked by a full-width background highlight, never
    /// a leading glyph: no '▎'/'>' anywhere, and content is NOT shifted
    /// right — the selected row's timestamp still begins in column 0 (SNB UX
    /// fix R2).
    #[test]
    fn direct_render_selection_highlights_row_without_shifting() {
        let theme = Theme::default();
        let parts = vec![
            Participant {
                addr: "10.0.0.1:5060".into(),
                label: "10.0.0.1:5060".into(),
            },
            Participant {
                addr: "10.0.0.2:5060".into(),
                label: "10.0.0.2:5060".into(),
            },
        ];
        let msgs = vec![
            fmt_msg("12:00:00.000", SelectionState::Selected, 0, 1),
            fmt_msg("12:00:00.100", SelectionState::Normal, 1, 0),
        ];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: None,
            selected_index: 0,
        };
        let mut term = terminal(80, 24);
        term.draw(|f| {
            let a = f.area();
            render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();

        // No leading marker glyph survived anywhere.
        assert!(
            !buffer_text(&term).contains('\u{258E}'),
            "marker '▎' must be gone"
        );

        // Exactly one row carries the selection background, and on that row the
        // selected timestamp starts at column 0 (not shifted to column 1).
        let mut highlit_rows = Vec::new();
        for y in 0..buf.area.height {
            if buf.cell((0, y)).unwrap().style().bg == Some(SELECTION_BG) {
                highlit_rows.push(y);
            }
        }
        assert_eq!(
            highlit_rows.len(),
            1,
            "exactly one highlighted (selected) row"
        );
        let y = highlit_rows[0];
        let row: String = (0..buf.area.width)
            .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
            .collect();
        assert!(
            row.starts_with("12:00:00.000"),
            "ts at col 0, unshifted: {row:?}"
        );
    }

    /// The mark/delta badge is right-aligned against the ladder's reserved
    /// last column. Its leading glyph is the multibyte `Δ` (U+0394, 1 display
    /// column but 2 bytes); positioning by byte length shoves the whole badge
    /// one column left. The badge "Δ +100ms" is 8 display columns, so on an
    /// 80-column area the `Δ` must sit at column 71 (= width - 9), landing the
    /// badge's last glyph in the penultimate column.
    #[test]
    fn direct_render_delta_badge_right_aligned_with_multibyte_glyph() {
        let theme = Theme::default();
        let parts = vec![
            Participant {
                addr: "10.0.0.1:5060".into(),
                label: "10.0.0.1:5060".into(),
            },
            Participant {
                addr: "10.0.0.2:5060".into(),
                label: "10.0.0.2:5060".into(),
            },
        ];
        let mut m0 = fmt_msg("12:00:00.000", SelectionState::Normal, 0, 1);
        m0.raw_timestamp = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000).unwrap();
        let mut m1 = fmt_msg("12:00:00.100", SelectionState::Selected, 1, 0);
        m1.raw_timestamp = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_100).unwrap();
        let msgs = vec![m0, m1];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: Some(0),
            selected_index: 1,
        };
        let w = 80u16;
        let mut term = terminal(w, 24);
        term.draw(|f| {
            let a = f.area();
            render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();

        // The badge lives on the pipe row (area.y + 1 == row 1).
        let dcol = (0..w)
            .find(|&x| buf.cell((x, 1)).unwrap().symbol() == "\u{0394}")
            .expect("Δ badge must be present on the pipe row");
        assert_eq!(
            dcol,
            w - 9,
            "badge must be flush-right (Δ at width-9), got column {dcol}"
        );
    }

    /// The evidence annotation actually reaches the drawn buffer.
    ///
    /// `prepare` has tests for which messages get a note; this covers the other
    /// half, that the note is drawn. Without it the field could be populated
    /// correctly and never rendered, and every test would still pass — the same
    /// unwired-code trap the JSON surface has a test for.
    #[test]
    fn direct_render_draws_the_diagnosis_note() {
        let theme = Theme::default();
        let parts = vec![
            Participant {
                addr: "10.0.0.1:5060".into(),
                label: "10.0.0.1:5060".into(),
            },
            Participant {
                addr: "10.0.0.2:5060".into(),
                label: "10.0.0.2:5060".into(),
            },
        ];
        let mut m0 = fmt_msg("12:00:00.000", SelectionState::Normal, 0, 1);
        m0.raw_timestamp = DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000).unwrap();
        m0.sdp_badge = None;
        m0.diagnosis_note = Some("FAILURE".to_string());
        let msgs = vec![m0];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: None,
            selected_index: 0,
        };
        let w = 80u16;
        let mut term = terminal(w, 24);
        term.draw(|f| {
            let a = f.area();
            render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();

        // Search every row: which row the annotation lands on depends on the
        // ladder layout, and pinning the row number here would test the layout
        // rather than the annotation.
        let mut all = String::new();
        for y in 0..8u16 {
            let row: String = (0..w)
                .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
                .collect();
            all.push_str(&format!("{y}: {row}\n"));
        }
        assert!(
            all.contains("[FAILURE]"),
            "the evidence annotation must be drawn; buffer was:\n{all}"
        );
    }

    // ── participant label cells (multi-leg header/footer collisions) ────

    /// Pipes exactly as `render_call_flow_direct` computes them.
    fn pipes_for(n: usize, width: u16) -> Vec<u16> {
        let ts = TS_COL_WIDTH as u16;
        if n <= 1 {
            vec![ts]
        } else {
            let usable = width.saturating_sub(ts + 2);
            (0..n)
                .map(|i| ts + (i as u16 * usable / (n as u16 - 1)))
                .collect()
        }
    }

    /// Cells are pairwise disjoint AND keep at least one blank column
    /// between neighbors, for every participant count and width the ladder
    /// can render — the invariant that makes label collisions impossible.
    #[test]
    fn label_cells_disjoint_with_a_separator_at_any_geometry() {
        for n in 1..=6usize {
            for width in [30u16, 45, 58, 80, 98, 200] {
                let pipes = pipes_for(n, width);
                let cells = participant_label_cells(&pipes, 0, width);
                assert_eq!(cells.len(), n);
                for (l, r) in &cells {
                    assert!(l <= r, "n={n} w={width}: inverted cell ({l},{r})");
                    assert!(*r <= width, "n={n} w={width}: cell past edge");
                }
                for w in cells.windows(2) {
                    assert!(
                        w[0].1 < w[1].0,
                        "n={n} w={width}: cells {:?} and {:?} touch/overlap",
                        w[0],
                        w[1]
                    );
                }
            }
        }
    }

    /// Every header/footer token must reconstruct to exactly one participant
    /// label (verbatim or an ellipsis truncation of it) — the shipped defect
    /// rendered "172.16.98172.16.98.101:5060" garbage instead.
    fn assert_labels_reconstruct(row: &str, labels: &[&str]) {
        let tokens: Vec<&str> = row.split_whitespace().collect();
        assert_eq!(
            tokens.len(),
            labels.len(),
            "one token per participant, got {tokens:?} for {labels:?}"
        );
        let mut used = vec![false; labels.len()];
        for tok in &tokens {
            let hit = labels.iter().enumerate().find(|(i, l)| {
                !used[*i]
                    && (*l == tok
                        || (tok.ends_with("...")
                            && tok.len() > 3
                            && l.starts_with(&tok[..tok.len() - 3]))
                        || (tok.len() <= 3 && l.starts_with(*tok)))
            });
            match hit {
                Some((i, _)) => used[i] = true,
                None => panic!("token {tok:?} matches no label of {labels:?} in {row:?}"),
            }
        }
    }

    /// Six packed B2BUA participants with long ip:port and resolved-name
    /// labels: the header and footer rows must never paint colliding
    /// garbage, at the demo width and at much tighter ones.
    #[test]
    fn packed_multileg_labels_never_collide() {
        let theme = Theme::default();
        let labels = [
            "172.16.98.1:44285",
            "172.16.98.101:5060",
            "172.16.98.145:40216",
            "b2bua-core.example.co",
            "10.255.255.254:65535",
            "sbc-edge.example.com",
        ];
        for n in [3usize, 4, 6] {
            for width in [58u16, 69, 98] {
                let parts: Vec<Participant> = labels[..n]
                    .iter()
                    .map(|l| Participant {
                        addr: l.to_string(),
                        label: truncate(l, 20),
                    })
                    .collect();
                let msgs = vec![fmt_msg("12:00:00.000", SelectionState::Normal, 0, 1)];
                let nav = FlowNavigation {
                    scroll_offset: 0,
                    mark_index: None,
                    selected_index: 0,
                };
                let mut term = terminal(width, 12);
                term.draw(|f| {
                    let a = f.area();
                    render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
                })
                .unwrap();
                let text = buffer_text(&term);
                let rows: Vec<&str> = text.lines().collect();
                if text.contains("Terminal too narrow") {
                    continue; // legitimately refused, nothing painted
                }
                let truncated: Vec<String> = parts.iter().map(|p| p.label.clone()).collect();
                let refs: Vec<&str> = truncated.iter().map(String::as_str).collect();
                assert_labels_reconstruct(rows[0], &refs);
                assert_labels_reconstruct(rows[11], &refs);
            }
        }
    }

    /// A single participant keeps its label at the pipe, and adversarial
    /// labels (multibyte, empty) never panic or collide at tiny widths.
    #[test]
    fn label_cells_adversarial_inputs() {
        let theme = Theme::default();
        for (label, width) in [
            ("übérlöng-nämé-øn-a-b2büa-lég.example.com", 34u16),
            ("", 40),
            ("x", 30),
            ("no-spaces-very-long-label-overflowing", 31),
        ] {
            let parts = vec![Participant {
                addr: "10.0.0.1:5060".into(),
                label: label.to_string(),
            }];
            let msgs = vec![fmt_msg("12:00:00.000", SelectionState::Normal, 0, 0)];
            let nav = FlowNavigation {
                scroll_offset: 0,
                mark_index: None,
                selected_index: 0,
            };
            let mut term = terminal(width, 8);
            term.draw(|f| {
                let a = f.area();
                render_call_flow_direct(f, a, &parts, &msgs, &nav, &theme);
            })
            .unwrap();
            // Nothing may bleed past the area (set_string would have
            // clipped, but the cells must already bound it).
            let text = buffer_text(&term);
            assert!(!text.is_empty());
        }
    }

    /// Fold info must be visible INSIDE the ladder area: the retx count
    /// rides on the arrow label itself, and no annotation may bleed past the
    /// area's right edge — the split detail pane renders there and covers
    /// anything written into that region (which made folds look like silent
    /// data loss).
    #[test]
    fn fold_count_visible_in_ladder_and_no_bleed_past_area() {
        let theme = Theme::default();
        let parts = vec![
            Participant {
                addr: "10.0.0.1:5060".into(),
                label: "10.0.0.1:5060".into(),
            },
            Participant {
                addr: "10.0.0.2:5060".into(),
                label: "10.0.0.2:5060".into(),
            },
        ];
        let mut hdr = fmt_msg("12:00:00.000", SelectionState::Normal, 0, 1);
        hdr.folded_count = 2;
        hdr.fold_label = Some("(+2 retx) - press e to expand".to_string());
        let msgs = vec![hdr];
        let nav = FlowNavigation {
            scroll_offset: 0,
            mark_index: None,
            selected_index: 99,
        };
        let mut term = terminal(120, 24);
        term.draw(|f| {
            let ladder = Rect::new(0, 0, 60, 24);
            render_call_flow_direct(f, ladder, &parts, &msgs, &nav, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let mut ladder_text = String::new();
        for y in 0..24u16 {
            for x in 0..60u16 {
                ladder_text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            ladder_text.push('\n');
        }
        assert!(
            ladder_text.contains("INVITE (+2 retx)"),
            "retx count must ride on the arrow inside the ladder:\n{ladder_text}"
        );
        for y in 0..24u16 {
            for x in 60..120u16 {
                assert_eq!(
                    buf.cell((x, y)).unwrap().symbol(),
                    " ",
                    "annotation bled outside the ladder area at ({x},{y}):\n{ladder_text}"
                );
            }
        }
    }

    // ── build_call_flow_lines / _with_width ────────────────────────────

    /// A full dialog builds one line per message plus header and bars, and
    /// names every method/status.
    #[test]
    fn build_lines_full_dialog_has_methods_and_status() {
        let theme = Theme::default();
        let store = store_full_dialog("full@test");
        let (count, lines) = build_call_flow_lines(&store, "full@test", &theme).expect("some");
        let stored = store.get("full@test").unwrap().messages.len();
        assert_eq!(count, stored);
        // header + top bar + N messages + bottom bar
        assert_eq!(lines.len(), stored + 3);
        let text = lines_to_string(&lines);
        for needle in ["10.0.0.1:5060", "INVITE", "180", "200", "ACK", "BYE"] {
            assert!(text.contains(needle), "missing {needle} in:\n{text}");
        }
    }

    /// An unknown Call-ID yields `None`.
    #[test]
    fn build_lines_missing_dialog_returns_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        assert!(build_call_flow_lines(&store, "nope@test", &theme).is_none());
    }

    /// The PDD annotation lands on the 180 Ringing line.
    #[test]
    fn build_lines_pdd_annotation_on_180() {
        let theme = Theme::default();
        let store = store_full_dialog("pdd@test");
        // 120-wide default => PDD annotated against the 180 Ringing.
        let (_c, lines) = build_call_flow_lines(&store, "pdd@test", &theme).expect("some");
        let text = lines_to_string(&lines);
        assert!(text.contains("PDD:"), "expected PDD annotation in:\n{text}");
    }

    /// A too-narrow width clamps to `MIN_ARROW_WIDTH` without changing the
    /// logical line count.
    #[test]
    fn build_lines_narrow_width_clamps_arrow() {
        let theme = Theme::default();
        let store = store_full_dialog("narrow@test");
        // width 20 forces saturating_sub to 0 -> MIN_ARROW_WIDTH path.
        let narrow = build_call_flow_lines_with_width(&store, "narrow@test", 20, &theme)
            .expect("some")
            .1;
        let wide = build_call_flow_lines_with_width(&store, "narrow@test", 200, &theme)
            .expect("some")
            .1;
        // Same logical line count regardless of width.
        assert_eq!(narrow.len(), wide.len());
        // Narrow header should be shorter than the wide one (smaller arrow span).
        let nh = line_to_string(&narrow[0]).chars().count();
        let wh = line_to_string(&wide[0]).chars().count();
        assert!(nh < wh, "narrow header {nh} should be < wide {wh}");
    }

    /// A one-message dialog builds header + bar + message + bar.
    #[test]
    fn build_lines_single_message_dialog() {
        let theme = Theme::default();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", "one@test", base_ts()));
        let (count, lines) = build_call_flow_lines(&store, "one@test", &theme).expect("some");
        assert_eq!(count, 1);
        // header + bar + 1 message + bar
        assert_eq!(lines.len(), 4);
        assert!(lines_to_string(&lines).contains("INVITE"));
    }

    /// Provisional (100) and error-final (480) responses both render.
    #[test]
    fn build_lines_provisional_then_error_final() {
        let theme = Theme::default();
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(req("INVITE", "1 INVITE", "err@test", t));
        store.process_message(resp(
            100,
            "Trying",
            "1 INVITE",
            "err@test",
            t + TimeDelta::milliseconds(50),
        ));
        store.process_message(resp(
            480,
            "Temporarily Unavailable",
            "1 INVITE",
            "err@test",
            t + TimeDelta::seconds(1),
        ));
        let (count, lines) = build_call_flow_lines(&store, "err@test", &theme).expect("some");
        assert_eq!(count, 3);
        let text = lines_to_string(&lines);
        assert!(text.contains("100"));
        assert!(text.contains("480"));
    }

    // ── build_call_flow_lines_with_options ─────────────────────────────

    /// A selected message gains the `[SELECTED]` marker in the options path.
    #[test]
    fn build_lines_with_options_selected_marker() {
        let theme = Theme::default();
        let store = store_full_dialog("opt@test");
        let mut o = opts(&theme);
        o.selected_msg = Some(2);
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "opt@test", 120, &o).expect("some");
        assert!(lines_to_string(&lines).contains("[SELECTED]"));
    }

    /// Summary SDP mode lists codecs and `show_rtp` draws the legacy
    /// "RTP stream active" line at the BYE.
    #[test]
    fn build_lines_with_options_sdp_summary_and_rtp() {
        let theme = Theme::default();
        let t = base_ts();
        let mut store = DialogStore::new(100, false);
        store.process_message(invite_with_sdp("sdp@test", t));
        store.process_message(resp(
            200,
            "OK",
            "1 INVITE",
            "sdp@test",
            t + TimeDelta::seconds(1),
        ));
        store.process_message(req(
            "ACK",
            "1 ACK",
            "sdp@test",
            t + TimeDelta::milliseconds(1100),
        ));
        store.process_message(req("BYE", "2 BYE", "sdp@test", t + TimeDelta::seconds(10)));
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Summary;
        o.show_rtp = true;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "sdp@test", 120, &o).expect("some");
        let text = lines_to_string(&lines);
        // SDP summary lists codecs; show_rtp draws an "RTP stream active" bar at BYE.
        assert!(
            text.contains("Codecs:"),
            "expected codec summary in:\n{text}"
        );
        assert!(
            text.contains("RTP stream active"),
            "expected RTP bar in:\n{text}"
        );
    }

    /// Full SDP mode emits the raw SDP body lines.
    #[test]
    fn build_lines_with_options_sdp_full_emits_body_lines() {
        let theme = Theme::default();
        let mut store = DialogStore::new(100, false);
        store.process_message(invite_with_sdp("sdpfull@test", base_ts()));
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Full;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "sdpfull@test", 120, &o).expect("some");
        let text = lines_to_string(&lines);
        assert!(
            text.contains("m=audio 20000"),
            "expected raw SDP body in:\n{text}"
        );
        assert!(text.contains("a=rtpmap:0 PCMU/8000"));
    }

    /// DeltaPrev mode renders relative "+n.nnns" timestamps.
    #[test]
    fn build_lines_with_options_delta_prev_timestamps() {
        let theme = Theme::default();
        let store = store_full_dialog("delta@test");
        let mut o = opts(&theme);
        o.ts_mode = TimestampMode::DeltaPrev;
        let (_c, lines) =
            build_call_flow_lines_with_options(&store, "delta@test", 120, &o).expect("some");
        // Delta-prev renders "+<n>s" relative timestamps.
        assert!(lines_to_string(&lines).contains("+"));
    }

    /// The options path also yields `None` for an unknown Call-ID.
    #[test]
    fn build_lines_with_options_missing_dialog_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let o = opts(&theme);
        assert!(build_call_flow_lines_with_options(&store, "absent@test", 120, &o).is_none());
    }

    // ── build_extended_flow_lines ──────────────────────────────────────

    /// The extended view carries the "Extended Flow" header even without
    /// correlated legs.
    #[test]
    fn extended_flow_single_leg_header() {
        let theme = Theme::default();
        let store = store_full_dialog("ext@test");
        let o = opts(&theme);
        let (count, lines) = build_extended_flow_lines(&store, "ext@test", 120, &o).expect("some");
        assert_eq!(count, 6);
        let text = lines_to_string(&lines);
        assert!(
            text.contains("Extended Flow:"),
            "missing header in:\n{text}"
        );
        assert!(text.contains("correlated leg(s)"));
        assert!(text.contains("INVITE"));
    }

    /// The extended view yields `None` for an unknown Call-ID.
    #[test]
    fn extended_flow_missing_dialog_none() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let o = opts(&theme);
        assert!(build_extended_flow_lines(&store, "gone@test", 120, &o).is_none());
    }

    // ── render_call_flow / render_call_flow_lines ──────────────────────

    /// `render_call_flow` paints the dialog's methods into the buffer.
    #[test]
    fn render_call_flow_paints_buffer() {
        let theme = Theme::default();
        let store = store_full_dialog("render@test");
        let mut term = terminal(100, 30);
        let area = Rect::new(0, 0, 100, 30);
        term.draw(|f| render_call_flow(f, area, &store, "render@test", 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("INVITE"), "buffer:\n{text}");
        assert!(text.contains("BYE"));
        assert!(!text.contains("Dialog not found"));
    }

    /// A missing dialog paints the "Dialog not found or empty" fallback.
    #[test]
    fn render_call_flow_missing_shows_fallback() {
        let theme = Theme::default();
        let store = DialogStore::new(100, false);
        let mut term = terminal(80, 10);
        let area = Rect::new(0, 0, 80, 10);
        term.draw(|f| render_call_flow(f, area, &store, "missing@test", 0, &theme))
            .unwrap();
        assert!(buffer_text(&term).contains("Dialog not found or empty"));
    }

    /// A 40-column terminal still renders (wrapped) without panicking.
    #[test]
    fn render_call_flow_narrow_width() {
        let theme = Theme::default();
        let store = store_full_dialog("rnarrow@test");
        let mut term = terminal(40, 20);
        let area = Rect::new(0, 0, 40, 20);
        term.draw(|f| render_call_flow(f, area, &store, "rnarrow@test", 0, &theme))
            .unwrap();
        // Still renders the wrapped ladder without panicking; some content present.
        let text = buffer_text(&term);
        assert!(
            text.contains("INVITE") || text.contains("10.0.0.1"),
            "buffer:\n{text}"
        );
    }

    /// Scrolling past the header rows brings later messages into view.
    #[test]
    fn render_call_flow_lines_scroll_offset() {
        let theme = Theme::default();
        let store = store_full_dialog("scroll@test");
        let mut term = terminal(100, 6);
        let area = Rect::new(0, 0, 100, 6);
        // Scroll past the header rows so later messages appear at the top.
        term.draw(|f| {
            render_call_flow_lines(f, area, 4, &theme, || {
                build_call_flow_lines_with_width(&store, "scroll@test", 100, &theme)
            })
        })
        .unwrap();
        let text = buffer_text(&term);
        // With offset 4 (header+bar+INVITE+180 scrolled away) the 200/ACK/BYE show.
        assert!(
            text.contains("BYE") || text.contains("ACK") || text.contains("200"),
            "buffer:\n{text}"
        );
    }

    /// A builder returning `None` paints the fallback message.
    #[test]
    fn render_call_flow_lines_builder_returns_none() {
        let theme = Theme::default();
        let mut term = terminal(60, 8);
        let area = Rect::new(0, 0, 60, 8);
        term.draw(|f| render_call_flow_lines(f, area, 0, &theme, || None))
            .unwrap();
        assert!(buffer_text(&term).contains("Dialog not found or empty"));
    }

    // ── scrollbar / focus helpers ──────────────────────────────────────

    /// The viewport is the pane height minus the 4 header/footer rows,
    /// saturating at 0.
    #[test]
    fn ladder_visible_rows_reserves_header_footer() {
        // 2 rows for participant labels + pipes, 2 for footer.
        assert_eq!(ladder_visible_rows(30), 26);
        assert_eq!(ladder_visible_rows(4), 0);
        assert_eq!(ladder_visible_rows(0), 0);
    }

    /// An overflowing message reports its row count and paints the vertical
    /// scrollbar thumb.
    #[test]
    fn message_detail_reports_lines_and_renders_scrollbar() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // A short pane forces the SIP message to overflow → scrollbar path.
        let mut term = terminal(40, 6);
        let area = Rect::new(0, 0, 40, 6);
        let mut lines = DetailMetrics::default();
        term.draw(|f| {
            lines = render_message_detail(
                f,
                area,
                &store,
                &MessageDetailView {
                    call_id: "detail@test",
                    selected_msg: 0,
                    transaction_filter: None,
                    scroll_offset: 0,
                    focused: true,
                    header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
                    wrap: true,
                    hscroll: 0,
                    theme: &theme,
                },
            );
        })
        .unwrap();
        assert!(
            lines.total_rows > 0,
            "detail panel should report its content line count"
        );
        // The thumb glyph '█' is unique to the scrollbar (the block border uses
        // box-drawing chars), so its presence proves the scrollbar painted.
        let text = buffer_text(&term);
        assert!(
            text.contains('\u{2588}'),
            "scrollbar thumb not painted:\n{text}"
        );
    }

    /// No scrollbar is painted when the whole message fits the pane.
    #[test]
    fn message_detail_no_scrollbar_when_it_fits() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // A tall pane fits the whole message → no scrollbar.
        let mut term = terminal(60, 40);
        let area = Rect::new(0, 0, 60, 40);
        term.draw(|f| {
            render_message_detail(
                f,
                area,
                &store,
                &MessageDetailView {
                    call_id: "detail@test",
                    selected_msg: 0,
                    transaction_filter: None,
                    scroll_offset: 0,
                    focused: false,
                    header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
                    wrap: true,
                    hscroll: 0,
                    theme: &theme,
                },
            );
        })
        .unwrap();
        let text = buffer_text(&term);
        assert!(
            !text.contains('\u{2588}'),
            "scrollbar should be absent when content fits:\n{text}"
        );
    }

    // ── Detail-pane geometry: wrap accounting, off-by-one boundaries,
    //    horizontal scrolling (field report: long wrapping headers showed
    //    no scrollbar and Up/Down did nothing — logical lines were
    //    compared against a wrapped viewport) ──────────────────────────

    /// Store holding ONE request with the given extra headers and body.
    fn store_with_message(call_id: &str, extra_headers: &[&str], body: &str) -> DialogStore {
        let mut headers: Vec<String> = vec![
            "From: <sip:a@example.com>;tag=t1".into(),
            "To: <sip:b@example.com>".into(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".into(),
        ];
        headers.extend(extra_headers.iter().map(|h| h.to_string()));
        let hdr_refs: Vec<&str> = headers.iter().map(String::as_str).collect();
        let raw = build_raw("INVITE sip:b@example.com SIP/2.0", &hdr_refs, body);
        let msg = parse_sip(
            &raw,
            base_ts(),
            ip_a(),
            ip_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse custom INVITE");
        let mut store = DialogStore::new(100, false);
        store.process_message(msg);
        store
    }

    /// A `MessageDetailView` for message 0 of `call_id` with the given
    /// scroll/wrap/hscroll and a shared default theme.
    fn detail_view(call_id: &str, scroll: u16, wrap: bool, hscroll: u16) -> MessageDetailView<'_> {
        // Shared default theme so the returned view can borrow it 'static.
        static THEME: std::sync::OnceLock<Theme> = std::sync::OnceLock::new();
        MessageDetailView {
            call_id,
            selected_msg: 0,
            transaction_filter: None,
            scroll_offset: scroll,
            focused: true,
            header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
            wrap,
            hscroll,
            theme: THEME.get_or_init(Theme::default),
        }
    }

    /// The `[N/M]` header counts must be RELATIVE TO THE TRANSACTION FILTER
    /// when one is active. store_full_dialog is INVITE/180/200/ACK (txn 1,
    /// indices 0-3) then BYE/200 (txn 2, indices 4-5). Filtering to the BYE
    /// transaction and selecting its 200 (dialog index 5) must read [2/2],
    /// not [6/6] — the whole-dialog denominator made the counter look stuck
    /// on a filtered page.
    #[test]
    fn detail_header_counts_are_relative_to_the_transaction_filter() {
        let theme = Theme::default();
        let store = store_full_dialog("f@test");
        let bye_key = (2u32, "BYE".to_string());

        let header = |sel: usize, filter: Option<&(u32, String)>| -> String {
            let mut term = terminal(80, 30);
            let area = Rect::new(0, 0, 80, 30);
            term.draw(|f| {
                render_message_detail(
                    f,
                    area,
                    &store,
                    &MessageDetailView {
                        call_id: "f@test",
                        selected_msg: sel,
                        transaction_filter: filter,
                        scroll_offset: 0,
                        focused: false,
                        header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
                        wrap: true,
                        hscroll: 0,
                        theme: &theme,
                    },
                );
            })
            .unwrap();
            // The title sits on the top border row.
            buffer_text(&term).lines().next().unwrap_or("").to_string()
        };

        // Filtered to the BYE transaction: BYE (idx 4) is 1/2, its 200 (idx 5) is 2/2.
        assert!(
            header(4, Some(&bye_key)).contains("[1/2]"),
            "BYE should read [1/2] under the BYE filter, got: {}",
            header(4, Some(&bye_key))
        );
        assert!(
            header(5, Some(&bye_key)).contains("[2/2]"),
            "BYE's 200 should read [2/2] under the BYE filter, got: {}",
            header(5, Some(&bye_key))
        );
        // Unfiltered: whole-dialog counts are unchanged.
        assert!(
            header(5, None).contains("[6/6]"),
            "unfiltered, the BYE 200 is message 6/6, got: {}",
            header(5, None)
        );
    }

    /// Render the detail pane at `w`x`h` and return the metrics plus the
    /// buffer text.
    fn draw_detail(
        w: u16,
        h: u16,
        store: &DialogStore,
        view: &MessageDetailView,
    ) -> (DetailMetrics, String) {
        let mut term = terminal(w, h);
        let area = Rect::new(0, 0, w, h);
        let mut m = DetailMetrics::default();
        term.draw(|f| m = render_message_detail(f, area, store, view))
            .unwrap();
        (m, buffer_text(&term))
    }

    /// Bottom border row of the buffer (where the h-scrollbar paints).
    fn bottom_row(text: &str, h: u16) -> String {
        text.lines().nth(h as usize - 1).unwrap_or("").to_string()
    }

    /// Logical (unwrapped) row count of the store's first message, learned
    /// by rendering into a pane far wider than any line.
    fn logical_rows(call_id: &str, store: &DialogStore) -> usize {
        let (m, _) = draw_detail(200, 50, store, &detail_view(call_id, 0, true, 0));
        assert!(m.total_rows > 0, "sanity: message renders");
        m.total_rows
    }

    /// Content exactly filling the pane clamps a stale scroll to 0 and
    /// paints no scrollbar.
    #[test]
    fn detail_exact_fit_has_no_scrollbar_and_clamps_stale_scroll_to_zero() {
        let store = store_with_message("fit@test", &[], "LASTBODY");
        let rows = logical_rows("fit@test", &store);
        // Pane inner height == content rows: nothing to scroll.
        let h = rows as u16 + 2;
        let (m, text) = draw_detail(60, h, &store, &detail_view("fit@test", 5, true, 0));
        assert_eq!(m.total_rows, rows);
        assert_eq!(m.scroll, 0, "stale offset must clamp to 0 on exact fit");
        assert!(
            !text.contains('\u{2588}'),
            "no scrollbar on exact fit:\n{text}"
        );
        assert!(
            text.contains("LASTBODY"),
            "last row visible unscrolled:\n{text}"
        );
    }

    /// One row of overflow shows a scrollbar and End clamps to exactly one
    /// row of scroll, revealing the last line.
    #[test]
    fn detail_single_row_overflow_scrolls_exactly_one() {
        let store = store_with_message("plus1@test", &[], "LASTBODY");
        let rows = logical_rows("plus1@test", &store);
        // Pane one row SHORTER than the content: max scroll is exactly 1.
        let h = rows as u16 + 1;
        let (m0, t0) = draw_detail(60, h, &store, &detail_view("plus1@test", 0, true, 0));
        assert!(
            t0.contains('\u{2588}'),
            "one-row overflow needs a scrollbar:\n{t0}"
        );
        assert!(
            !t0.contains("LASTBODY"),
            "unscrolled, the last row is just off-screen:\n{t0}"
        );
        let (m1, t1) = draw_detail(60, h, &store, &detail_view("plus1@test", u16::MAX, true, 0));
        assert_eq!(m1.scroll, 1, "End must clamp to exactly one row of scroll");
        assert!(
            t1.contains("LASTBODY"),
            "scrolled to bottom, the last row is visible:\n{t1}"
        );
        assert_eq!(m0.total_rows, m1.total_rows);
    }

    /// Wrapped row accounting counts continuation rows, not logical lines.
    #[test]
    fn wrapped_long_header_counts_visual_rows_not_logical_lines() {
        let long = format!("X-A: {}", "a".repeat(95)); // 100 cols
        let store = store_with_message("wrapcount@test", &[&long], "LASTBODY");
        let logical = logical_rows("wrapcount@test", &store);
        // Inner width 33 — wider than every standard header (≤32 cols),
        // so ONLY the 100-col header wraps: 33+33+33+1 → 4 rows (+3).
        let (m, _) = draw_detail(35, 40, &store, &detail_view("wrapcount@test", 0, true, 0));
        assert_eq!(
            m.total_rows,
            logical + 3,
            "wrapped row accounting must count continuation rows"
        );
    }

    /// Wrap-induced overflow shows the scrollbar and keeps a nonzero scroll
    /// even when the logical line count fits the viewport.
    #[test]
    fn wrapped_overflow_shows_scrollbar_even_when_logical_lines_fit() {
        let long = format!("X-A: {}", "a".repeat(60));
        let store = store_with_message("wrapbar@test", &[&long], "LASTBODY");
        let logical = logical_rows("wrapbar@test", &store);
        // Inner height exactly == LOGICAL rows, but wrapping adds 2 more:
        // the old logical-vs-viewport comparison hid the scrollbar here.
        let h = logical as u16 + 2;
        let (m, text) = draw_detail(26, h, &store, &detail_view("wrapbar@test", 1, true, 0));
        assert!(
            text.contains('\u{2588}'),
            "wrapped overflow must show a scrollbar:\n{text}"
        );
        assert_eq!(
            m.scroll, 1,
            "scroll must not clamp to 0 while wrapped rows overflow"
        );
    }

    /// Under wrapping, End clamps to wrapped-rows-minus-viewport and the
    /// last row is reachable.
    #[test]
    fn wrapped_scroll_reaches_the_last_row() {
        let long = format!("X-A: {}", "a".repeat(60));
        let store = store_with_message("wrapbottom@test", &[&long], "LASTBODY");
        let logical = logical_rows("wrapbottom@test", &store);
        let h = logical as u16 + 2; // viewport == logical rows, content == logical+2
        let (m, text) = draw_detail(
            26,
            h,
            &store,
            &detail_view("wrapbottom@test", u16::MAX, true, 0),
        );
        assert_eq!(
            m.scroll as usize,
            m.total_rows - logical,
            "End clamps to total wrapped rows minus viewport"
        );
        assert!(
            text.contains("LASTBODY"),
            "the last row must be reachable under wrapping:\n{text}"
        );
    }

    /// Unwrapped mode truncates long lines (no continuation rows) and
    /// reports the widest line in display columns.
    #[test]
    fn unwrapped_lines_truncate_and_report_max_width() {
        let long = format!("X-A: {}", "a".repeat(60)); // 65 cols
        let store = store_with_message("nowrap@test", &[&long], "LASTBODY");
        let logical = logical_rows("nowrap@test", &store);
        let (m, text) = draw_detail(26, 40, &store, &detail_view("nowrap@test", 0, false, 0));
        assert_eq!(m.total_rows, logical, "no wrap: rows == logical lines");
        assert_eq!(m.max_width, 65, "widest line in display columns");
        // The row after the long header must hold the NEXT line, not a
        // wrapped continuation of 'a's.
        let lines: Vec<&str> = text.lines().collect();
        let long_row = lines
            .iter()
            .position(|l| l.contains("X-A: aaa"))
            .expect("long header row rendered");
        assert!(
            !lines[long_row + 1].contains("aaaa"),
            "line must truncate, not wrap:\n{text}"
        );
    }

    /// H-scroll shifts unwrapped content and clamps so the widest line's
    /// tail lands on the last column.
    #[test]
    fn unwrapped_hscroll_shifts_content_and_clamps_at_the_widest_line() {
        let long = format!("X-A: {}", "a".repeat(60)); // 65 cols, inner width 24
        let store = store_with_message("hscroll@test", &[&long], "LASTBODY");
        let (m, text) = draw_detail(
            26,
            40,
            &store,
            &detail_view("hscroll@test", 0, false, u16::MAX),
        );
        assert_eq!(
            m.hscroll as usize,
            65 - 24,
            "h-scroll clamps so the line's tail lands on the last column"
        );
        assert!(
            text.contains("aaaa"),
            "tail of the long line visible at max h-scroll:\n{text}"
        );
        assert!(
            !text.contains("X-A:"),
            "line beginnings scrolled out of view:\n{text}"
        );
        let (m0, t0) = draw_detail(26, 40, &store, &detail_view("hscroll@test", 0, false, 0));
        assert_eq!(m0.hscroll, 0);
        assert!(t0.contains("X-A:"), "unscrolled shows line starts:\n{t0}");
    }

    /// The bottom h-scrollbar appears only for unwrapped horizontal
    /// overflow — never while wrapping or when lines fit.
    #[test]
    fn horizontal_scrollbar_only_for_unwrapped_overflow() {
        let long = format!("X-A: {}", "a".repeat(60));
        let store = store_with_message("hbar@test", &[&long], "LASTBODY");
        let h = 40u16;
        // Unwrapped + overflowing → thumb on the bottom border row.
        let (_, t_off) = draw_detail(26, h, &store, &detail_view("hbar@test", 0, false, 0));
        assert!(
            bottom_row(&t_off, h).contains('\u{2588}'),
            "h-scrollbar expected on bottom border:\n{t_off}"
        );
        // Wrapped → no horizontal overflow by definition.
        let (_, t_on) = draw_detail(26, h, &store, &detail_view("hbar@test", 0, true, 0));
        assert!(
            !bottom_row(&t_on, h).contains('\u{2588}'),
            "no h-scrollbar while wrapping:\n{t_on}"
        );
        // Unwrapped but everything fits → no h-scrollbar either.
        let (_, t_wide) = draw_detail(100, h, &store, &detail_view("hbar@test", 0, false, 0));
        assert!(
            !bottom_row(&t_wide, h).contains('\u{2588}'),
            "no h-scrollbar when lines fit:\n{t_wide}"
        );
    }

    /// Wide (CJK) glyphs wrap and h-scroll by display columns, not chars.
    #[test]
    fn multibyte_wide_chars_wrap_and_hscroll_by_display_width() {
        // "X-U: " (5 cols) + 30 CJK chars (60 cols) = 65 display columns
        // in only 35 chars — the width-vs-chars distinction under test.
        let cjk = format!("X-U: {}", "好".repeat(30));
        let store = store_with_message("cjk@test", &[&cjk], "LASTBODY");
        let logical = logical_rows("cjk@test", &store);
        // Inner width 33 — only the CJK line wraps: 5+14 glyphs (33 cols
        // exactly), then 16 glyphs (32 cols) → 2 rows (+1 vs logical).
        let (m, _) = draw_detail(35, 40, &store, &detail_view("cjk@test", 0, true, 0));
        assert_eq!(
            m.total_rows,
            logical + 1,
            "wide-char wrapping must count display columns, not chars"
        );
        // Unwrapped: max_width in display columns; hscroll clamps against
        // it (65 - 33 = 32, impossible if widths were counted in chars).
        let (mh, th) = draw_detail(35, 40, &store, &detail_view("cjk@test", 0, false, u16::MAX));
        assert_eq!(mh.max_width, 65);
        assert_eq!(mh.hscroll as usize, 65 - 33);
        assert!(th.contains('好'), "CJK tail renders at max h-scroll:\n{th}");
    }

    /// Degenerate pane sizes (down to 1x1) render without panicking and keep
    /// the clamped scroll within the content.
    #[test]
    fn detail_tiny_panes_never_panic() {
        let long = format!("X-A: {}", "a".repeat(60));
        let store = store_with_message("tiny@test", &[&long], "LASTBODY");
        for (w, h) in [(2u16, 2u16), (3, 3), (1, 1), (4, 2)] {
            for wrap in [true, false] {
                let (m, _) = draw_detail(
                    w,
                    h,
                    &store,
                    &detail_view("tiny@test", u16::MAX, wrap, u16::MAX),
                );
                assert!(
                    (m.scroll as usize) <= m.total_rows,
                    "{w}x{h} wrap={wrap}: clamped scroll within content"
                );
            }
        }
    }

    /// The ladder scrollbar thumb paints when rows exceed the viewport.
    #[test]
    fn ladder_scrollbar_paints_when_overflowing() {
        let theme = Theme::default();
        // viewport rows = 9 - 4 = 5; 20 logical rows overflow it.
        let mut term = terminal(60, 9);
        let area = Rect::new(0, 0, 60, 9);
        term.draw(|f| render_ladder_scrollbar(f, area, 20, 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains('\u{2588}'),
            "ladder scrollbar thumb not painted:\n{text}"
        );
    }

    /// No ladder scrollbar is painted when the flow fits the pane.
    #[test]
    fn ladder_scrollbar_absent_when_fits() {
        let theme = Theme::default();
        let mut term = terminal(60, 30);
        let area = Rect::new(0, 0, 60, 30);
        // 3 rows into a 26-row viewport → nothing to scroll.
        term.draw(|f| render_ladder_scrollbar(f, area, 3, 0, &theme))
            .unwrap();
        let text = buffer_text(&term);
        assert!(text.trim().is_empty(), "no scrollbar expected:\n{text}");
    }

    /// Focus only changes border styling: focused and unfocused renders
    /// report identical metrics.
    #[test]
    fn message_detail_focus_highlights_border() {
        let theme = Theme::default();
        let store = store_full_dialog("detail@test");
        // Render focused vs unfocused; both must paint without panicking and
        // report the same line count (focus only changes styling).
        let area = Rect::new(0, 0, 50, 20);
        let mut a = DetailMetrics::default();
        let mut b = DetailMetrics::default();
        let mut term = terminal(50, 20);
        term.draw(|f| {
            a = render_message_detail(
                f,
                area,
                &store,
                &MessageDetailView {
                    call_id: "detail@test",
                    selected_msg: 0,
                    transaction_filter: None,
                    scroll_offset: 0,
                    focused: true,
                    header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
                    wrap: true,
                    hscroll: 0,
                    theme: &theme,
                },
            )
        })
        .unwrap();
        term.draw(|f| {
            b = render_message_detail(
                f,
                area,
                &store,
                &MessageDetailView {
                    call_id: "detail@test",
                    selected_msg: 0,
                    transaction_filter: None,
                    scroll_offset: 0,
                    focused: false,
                    header_form: crate::tui::header_form::HeaderFormMode::AsCaptured,
                    wrap: true,
                    hscroll: 0,
                    theme: &theme,
                },
            )
        })
        .unwrap();
        assert_eq!(a, b);
    }
}
