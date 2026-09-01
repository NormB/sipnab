// SPDX-License-Identifier: MIT OR Apache-2.0

//! Modal popup rendering: save, name-address, file-open (browser +
//! manual path), filter and settings dialogs.

use crate::tui::*;

/// Compute a centered popup rectangle within the given area, clamping the
/// requested `width`/`height` to the area's size. Pure.
pub(in crate::tui) fn centered_popup(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

/// Build the styled spans for an editable path line: a header-colored label
/// followed by the path text with a reverse-video block cursor.
///
/// `cursor` is clamped into `path` and backed up to a `char` boundary, and
/// the cursor cell spans the whole (possibly multibyte) character under it,
/// so no byte offset used here can split a UTF-8 sequence. Shared by the
/// save dialog and the file-open manual-path dialog.
fn path_with_cursor_spans<'a>(
    label: &'a str,
    path: &'a str,
    cursor: usize,
    theme: &Theme,
) -> Vec<Span<'a>> {
    let cursor_style = Style::default().bg(Color::White).fg(Color::Black);
    let text_style = Style::default()
        .fg(theme.foreground)
        .add_modifier(Modifier::BOLD);
    let mut spans: Vec<Span<'a>> = vec![Span::styled(label, Style::default().fg(theme.header))];
    if path.is_empty() {
        spans.push(Span::styled(" ", cursor_style));
        return spans;
    }
    let cursor = crate::text::floor_char_boundary(path, cursor);
    if cursor > 0 {
        spans.push(Span::styled(&path[..cursor], text_style));
    }
    match path[cursor..].chars().next() {
        Some(c) => {
            let cursor_end = cursor + c.len_utf8();
            spans.push(Span::styled(&path[cursor..cursor_end], cursor_style));
            if cursor_end < path.len() {
                spans.push(Span::styled(&path[cursor_end..], text_style));
            }
        }
        // Cursor at end — show a trailing block cursor.
        None => spans.push(Span::styled(" ", cursor_style)),
    }
    spans
}

/// Render the save dialog as a centered popup overlay: the editable path
/// (with a block cursor), the category-grouped format list with the current
/// selection marked, the dialog/message counts and the controls line. The
/// popup is sized to its content and, on short terminals, scrolled so the
/// selected format stays visible.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full frame area the popup is centered within.
/// * `app` - Application state (save dialog state, theme).
///
/// # Side effects
/// Draws to `frame` (clearing the cells behind the popup); no state is
/// mutated.
/// `set_string` that declines to draw outside `area` instead of panicking.
///
/// `Buffer::set_string` panics on an out-of-bounds index. A popup whose rows
/// are computed from a constant height indexes past the bottom as soon as the
/// terminal is shorter than that constant, and on 2026-09-01 two of them did:
/// the settings popup below 6 rows, and the filter popup at sizes as ordinary
/// as 66x12. A panic takes the whole TUI with it, and resizing a terminal is
/// not an error case.
///
/// Also truncates to the remaining columns, so a long value cannot run past
/// the right edge into the border.
pub(in crate::tui) fn set_string_clipped(
    buf: &mut ratatui::buffer::Buffer,
    area: Rect,
    x: u16,
    y: u16,
    text: impl AsRef<str>,
    style: Style,
) {
    if y < area.y || y >= area.y.saturating_add(area.height) {
        return;
    }
    if x < area.x || x >= area.x.saturating_add(area.width) {
        return;
    }
    let remaining = area.x.saturating_add(area.width).saturating_sub(x);
    buf.set_stringn(x, y, text.as_ref(), remaining as usize, style);
}

pub(in crate::tui) fn render_save_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 72.min(area.width.saturating_sub(4));

    // Build vertical format list grouped by category.
    let all_formats = [
        SaveFormat::Pcap,
        SaveFormat::PcapNg, // Packet Capture
        SaveFormat::Txt,
        SaveFormat::SippXml, // SIP-Specific
        SaveFormat::Json,
        SaveFormat::Ndjson,
        SaveFormat::Csv, // Structured
        SaveFormat::Html,
        SaveFormat::Markdown, // Reporting
        SaveFormat::Wav,
        SaveFormat::RtpJson, // RTP/Media
    ];
    let mut fmt_lines: Vec<Line<'_>> = Vec::new();
    let mut selected_fmt_line = 0usize;
    let mut last_cat = "";
    for fmt in &all_formats {
        let cat = fmt.category();
        if cat != last_cat {
            // Category header
            if !last_cat.is_empty() {
                fmt_lines.push(Line::from("")); // spacer between categories
            }
            fmt_lines.push(Line::from(Span::styled(
                format!("  {cat}"),
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD),
            )));
            last_cat = cat;
        }
        let is_selected = *fmt == app.save.format;
        if is_selected {
            selected_fmt_line = fmt_lines.len();
        }
        let marker = if is_selected { "\u{25B8} " } else { "  " }; // ▸ or space
        let label_style = if is_selected {
            Style::default()
                .fg(app.theme.foreground)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.muted)
        };
        let desc_style = if is_selected {
            Style::default().fg(app.theme.foreground)
        } else {
            Style::default().fg(app.theme.muted)
        };
        fmt_lines.push(Line::from(vec![
            Span::styled(format!("    {marker}"), label_style),
            Span::styled(format!("{:<7}", fmt.label()), label_style),
            Span::styled(format!(" {}", fmt.description()), desc_style),
        ]));
    }

    let info_line = format!(
        "  Dialogs: {} ({} selected) \u{00B7} Messages: {}",
        app.save.dialog_count, app.save.selected_count, app.save.message_count
    );

    // Build the path display with a visible cursor (reverse video at cursor position)
    let path_spans =
        path_with_cursor_spans("  Save to: ", &app.save.path, app.save.cursor, &app.theme);

    let mut lines: Vec<Line<'_>> = vec![Line::from(""), Line::from(path_spans), Line::from("")];
    lines.extend(fmt_lines);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        info_line,
        Style::default().fg(app.theme.muted),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  [Enter]",
            Style::default()
                .fg(app.theme.good)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Save  "),
        Span::styled(
            "[Tab/\u{21E7}Tab]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Format  "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Cancel"),
    ]));

    // Size the popup to its content (the old fixed 20 rows clipped the
    // last format category — WAV/RTP JSON — off the bottom), clamped to
    // the terminal by centered_popup.
    let needed_height = lines.len() as u16 + 2;
    let popup_area = centered_popup(area, popup_width, needed_height);
    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Save Capture ")
        .style(Style::default().bg(app.theme.background));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // On a terminal too short for everything, scroll so the SELECTED
    // format row stays visible (stream views default to WAV, which lived
    // in the clipped tail).
    let selected_line = 3 + selected_fmt_line as u16; // blank + path + blank
    let scroll = (selected_line + 1).saturating_sub(inner.height);
    let para = Paragraph::new(lines)
        .scroll((scroll, 0))
        .style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render the "Name Address" popup: a row of the view's endpoints (Tab to
/// switch), the active IP (read-only), and that IP's editable name with a
/// block cursor. A validation error, when present, is shown inline so the
/// typed name can be corrected without closing the popup.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full frame area the popup is centered within.
/// * `app` - Application state (name dialog state, theme).
///
/// # Side effects
/// Draws to `frame` (clearing the cells behind the popup); no state is
/// mutated.
pub(in crate::tui) fn render_name_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let multi = app.name_dialog.targets.len() > 1;
    let mut lines: Vec<Line<'_>> = Vec::new();
    // Endpoint selector row (only when more than one endpoint is offered).
    if multi {
        let mut spans: Vec<Span<'_>> = vec![Span::styled(
            "  Endpoint: ",
            Style::default().fg(app.theme.muted),
        )];
        for (i, t) in app.name_dialog.targets.iter().enumerate() {
            let style = if i == app.name_dialog.active {
                Style::default()
                    .bg(app.theme.selected)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.muted)
            };
            spans.push(Span::styled(format!(" {} ", t.ip), style));
            spans.push(Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(vec![
        Span::styled("  IP:   ", Style::default().fg(app.theme.muted)),
        Span::styled(
            app.name_dialog.active_ip().to_string(),
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    // Name field with a visible cursor block at the edit position.
    let name = app.name_dialog.active_name();
    let cursor = app.name_dialog.cursor.min(name.len());
    let (before, after) = name.split_at(cursor);
    let mut field: Vec<Span<'_>> = vec![
        Span::styled("  Name: ", Style::default().fg(app.theme.muted)),
        Span::raw(before.to_string()),
    ];
    let mut rest = after.chars();
    match rest.next() {
        Some(c) => {
            field.push(Span::styled(
                c.to_string(),
                Style::default().bg(app.theme.selected).fg(Color::Black),
            ));
            field.push(Span::raw(rest.as_str().to_string()));
        }
        None => field.push(Span::styled(" ", Style::default().bg(app.theme.selected))),
    }
    lines.push(Line::from(field));
    // Inline validation error: the popup stays open on failure so the typed
    // name can be corrected.
    if let Some(err) = &app.name_dialog.error {
        lines.push(Line::from(Span::styled(
            format!("  \u{26a0} {err}"),
            Style::default().fg(app.theme.warning),
        )));
    } else {
        lines.push(Line::from(""));
    }
    let hint = if multi {
        "  Tab switch endpoint · Enter save all · empty clears · Esc cancel"
    } else {
        "  Enter save · empty name clears · Esc cancel"
    };
    lines.push(Line::from(Span::styled(
        hint,
        Style::default().fg(app.theme.muted),
    )));

    // Sized to what it SAYS, not to a constant. The width was 60 and the
    // two-endpoint hint is 66 columns, so `Esc cancel` -- the only exit the
    // popup names -- fell off the right edge. `Paragraph` does not wrap here,
    // so an overlong line truncates in silence: nothing failed, and the one
    // line a stuck user needs was the one that went.
    //
    // Measuring the built lines also covers what a constant could not: an
    // IPv6 endpoint row, a long name, or an inline validation error, each of
    // which is longer than anything the original 60 was chosen for.
    let title = " Name Address ";
    let content = lines
        .iter()
        .map(ratatui::text::Line::width)
        .max()
        .unwrap_or(0);
    // +2 for the borders, +1 so the longest line is not flush against the
    // right edge; the title has to fit between the corners too.
    let desired = u16::try_from(content.max(title.len()).saturating_add(3)).unwrap_or(u16::MAX);
    let popup_width = desired.clamp(20, area.width.saturating_sub(4).max(20));
    let rows = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    let popup_height = rows
        .saturating_add(2)
        .min(area.height.saturating_sub(2))
        .max(3);
    let popup_area = centered_popup(area, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().bg(app.theme.background));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Render the file-open dialog as a centered popup overlay.
///
/// Two modes: a directory browser (default) that lists subdirectories and
/// pcap/pcapng/cap files, or a manual-path text input (toggled with Tab);
/// the active mode's body renderer is dispatched from here.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full frame area the popup is centered within.
/// * `app` - Application state (file-open dialog state, theme).
///
/// # Side effects
/// Draws to `frame` (clearing the cells behind the popup); no state is
/// mutated.
pub(in crate::tui) fn render_file_open_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width = 80.min(area.width.saturating_sub(4));
    let popup_height = 22.min(area.height.saturating_sub(2));
    let popup_area = centered_popup(area, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Open PCAP File ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    if app.file_open.manual_mode {
        render_file_open_manual(frame, inner, app);
    } else {
        render_file_open_browser(frame, inner, app);
    }
}

/// Word-wrap `text` to `width` columns (best-effort, on whitespace). Used for
/// the file-browser error message, since the dialog Paragraph does not wrap.
/// Returns at least one (possibly empty) line; a zero `width` returns the
/// text unwrapped. Pure.
fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.is_empty() {
            cur.push_str(word);
        } else if cur.chars().count() + 1 + word.chars().count() <= width {
            cur.push(' ');
            cur.push_str(word);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Render the directory-browser variant of the Open dialog: current
/// directory, filter line, the scrolled entry list (or an error / empty
/// notice) and the controls footer pinned to the bottom.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `inner` - The popup's inner area (inside the border block).
/// * `app` - Application state (file-open dialog state, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_file_open_browser(frame: &mut ratatui::Frame, inner: Rect, app: &App) {
    let header = format!("  Dir: {}", app.file_open.dir.display());
    let filter_label = if app.file_open.filter.is_empty() {
        "  (type to filter — Backspace: up dir  Tab: type path)".to_string()
    } else {
        format!("  Filter: {}", app.file_open.filter)
    };

    let mut lines: Vec<Line<'_>> = Vec::with_capacity(inner.height as usize);
    lines.push(Line::from(Span::styled(
        header,
        Style::default()
            .fg(app.theme.header)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        filter_label,
        Style::default().fg(app.theme.muted),
    )));
    lines.push(Line::from(""));

    // If the directory couldn't be read, show why (e.g. privileges dropped to
    // 'nobody' under sudo) instead of a blank list.
    if let Some(err) = &app.file_open.error {
        let wrap_width = (inner.width as usize).saturating_sub(4).max(10);
        for chunk in wrap_to_width(err, wrap_width) {
            lines.push(Line::from(Span::styled(
                format!("  {chunk}"),
                Style::default()
                    .fg(app.theme.bad)
                    .add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(""));
    }

    let list_rows = (inner.height as usize).saturating_sub(5);
    if app.file_open.entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no matching pcap files)",
            Style::default().fg(app.theme.muted),
        )));
    } else {
        let scroll_offset = app
            .file_open
            .selected
            .saturating_sub(list_rows.saturating_sub(1));
        for (idx, entry) in app
            .file_open
            .entries
            .iter()
            .enumerate()
            .skip(scroll_offset)
            .take(list_rows)
        {
            let selected = idx == app.file_open.selected;
            let prefix = if entry.is_dir { "  [DIR] " } else { "        " };
            let style = if selected {
                Style::default()
                    .bg(app.theme.selected)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD)
            } else if entry.is_dir {
                Style::default()
                    .fg(app.theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(app.theme.foreground)
            };
            let pad_to = (inner.width as usize).saturating_sub(prefix.len());
            let display = format!("{:<width$}", entry.name, width = pad_to);
            lines.push(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(display, style),
            ]));
        }
    }

    // Pad so the footer sits at the bottom
    while lines.len() + 1 < inner.height as usize {
        lines.push(Line::from(""));
    }

    lines.push(Line::from(vec![
        Span::styled(
            "  [Enter]",
            Style::default()
                .fg(app.theme.good)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Open/Cd  "),
        Span::styled(
            "[\u{21E7}\u{21E9}]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Nav  "),
        Span::styled(
            "[Backspace]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Up  "),
        Span::styled(
            "[Tab]",
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Path  "),
        Span::styled(
            "[Esc]",
            Style::default()
                .fg(app.theme.warning)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Cancel"),
    ]));

    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// Render the manual path-input variant of the Open dialog: the editable
/// path with a block cursor, the supported-extensions hint and the
/// controls line.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `inner` - The popup's inner area (inside the border block).
/// * `app` - Application state (file-open dialog state, theme).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_file_open_manual(frame: &mut ratatui::Frame, inner: Rect, app: &App) {
    let path_spans = path_with_cursor_spans(
        "  Path: ",
        &app.file_open.path,
        app.file_open.cursor,
        &app.theme,
    );

    let lines: Vec<Line<'_>> = vec![
        Line::from(""),
        Line::from(path_spans),
        Line::from(""),
        Line::from(Span::styled(
            "  Supports .pcap, .pcapng, .cap files (~ expands to $HOME)",
            Style::default().fg(app.theme.muted),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "  [Enter]",
                Style::default()
                    .fg(app.theme.good)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Open  "),
            Span::styled(
                "[Tab]",
                Style::default()
                    .fg(app.theme.header)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Browse  "),
            Span::styled(
                "[Esc]",
                Style::default()
                    .fg(app.theme.warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" Cancel"),
        ]),
    ];

    let visible_lines: Vec<Line<'_>> = lines.into_iter().take(inner.height as usize).collect();
    let para = Paragraph::new(visible_lines).style(Style::default().bg(app.theme.background));
    frame.render_widget(para, inner);
}

/// State for a single filter text input field.
pub(in crate::tui) struct FilterTextField<'a> {
    /// Label painted before the bracketed field (e.g. "  SIP From:    ").
    label: &'a str,
    /// Current text content of the field.
    value: &'a str,
    /// Total field width in columns, brackets included.
    field_width: u16,
    /// Whether this field has keyboard focus (shows the block cursor).
    focused: bool,
    /// Cursor position within `value` (bytes); only used when focused.
    cursor_pos: usize,
}

/// Render a text input field with cursor for the filter dialog.
///
/// Paints: `label [content_with_cursor_________________]`
/// The field content is rendered with a block cursor at `cursor_pos` when focused.
///
/// # Arguments
/// * `buf` - Buffer to paint into directly.
/// * `x` - Column of the label's first character.
/// * `y` - Row to paint on.
/// * `field` - Field label, value, width, focus and cursor state.
/// * `theme` - Color theme for label/bracket/content styling.
///
/// # Side effects
/// Writes cells into `buf` only; no state is mutated.
pub(in crate::tui) fn render_filter_text_field(
    buf: &mut ratatui::buffer::Buffer,
    x: u16,
    y: u16,
    field: &FilterTextField<'_>,
    theme: &Theme,
) {
    // The field is handed a buffer and a position, not an area, so its only
    // honest bound is the buffer itself. Copied before the mutable borrow.
    let bounds = buf.area;
    let label = field.label;
    let value = field.value;
    let field_width = field.field_width;
    let focused = field.focused;
    let cursor_pos = field.cursor_pos;
    let label_style = Style::default().fg(theme.header);
    let bracket_style = if focused {
        Style::default().fg(theme.foreground)
    } else {
        Style::default().fg(theme.muted)
    };

    // Paint label
    let label_area = Rect::new(x, y, label.len() as u16, 1);
    set_string_clipped(buf, bounds, label_area.x, label_area.y, label, label_style);

    // Paint opening bracket
    let field_x = x + label.len() as u16;
    set_string_clipped(buf, bounds, field_x, y, "[", bracket_style);

    // Paint field content with cursor. All byte offsets below are kept on
    // char boundaries so no slice can split a multibyte UTF-8 sequence.
    let content_x = field_x + 1;
    // On a very narrow field the bracket pair alone can exceed the width;
    // saturating keeps `inner_width` at 0 instead of underflowing (which
    // panics in debug builds and wraps to a huge value in release).
    let inner_width = field_width.saturating_sub(2) as usize; // subtract brackets
    let cursor = crate::text::floor_char_boundary(value, cursor_pos);
    // End of the display window, backed up to a boundary.
    let visible_end = crate::text::floor_char_boundary(value, inner_width);

    if focused {
        // Before cursor (clipped to the visible window)
        let before = &value[..cursor.min(visible_end)];
        set_string_clipped(
            buf,
            bounds,
            content_x,
            y,
            before,
            Style::default()
                .fg(theme.foreground)
                .add_modifier(Modifier::BOLD),
        );
        // Cursor cell: the whole char under the cursor, or a trailing space.
        let cursor_end = match value[cursor..].chars().next() {
            Some(c) => cursor + c.len_utf8(),
            None => cursor,
        };
        let cursor_char = if cursor < value.len() {
            &value[cursor..cursor_end]
        } else {
            " "
        };
        set_string_clipped(
            buf,
            bounds,
            content_x + cursor as u16,
            y,
            cursor_char,
            Style::default().bg(Color::White).fg(Color::Black),
        );
        // After cursor (clipped; the window may end before the cursor does)
        if cursor_end < visible_end {
            let after = &value[cursor_end..visible_end];
            set_string_clipped(
                buf,
                bounds,
                content_x + cursor_end as u16,
                y,
                after,
                Style::default()
                    .fg(theme.foreground)
                    .add_modifier(Modifier::BOLD),
            );
        }
        // Fill remaining with spaces
        let filled = value.len().max(cursor + 1).min(inner_width);
        if filled < inner_width {
            let pad = " ".repeat(inner_width - filled);
            set_string_clipped(
                buf,
                bounds,
                content_x + filled as u16,
                y,
                &pad,
                Style::default(),
            );
        }
    } else {
        // Not focused: just show value dimmed
        let display = &value[..visible_end];
        set_string_clipped(
            buf,
            bounds,
            content_x,
            y,
            display,
            Style::default().fg(theme.foreground),
        );
        // Fill remaining
        if display.len() < inner_width {
            let pad = " ".repeat(inner_width - display.len());
            set_string_clipped(
                buf,
                bounds,
                content_x + display.len() as u16,
                y,
                &pad,
                Style::default(),
            );
        }
    }

    // Closing bracket (saturating so a zero-width field cannot underflow)
    set_string_clipped(
        buf,
        bounds,
        field_x + field_width.saturating_sub(1),
        y,
        "]",
        bracket_style,
    );
}

/// Render the filter dialog as a centered popup overlay (sngrep-style).
///
/// Layout, drawn to scale at the fixed 56-column by 20-row popup size set
/// below, so every column stop in the figure is the one the code paints:
///
/// ```text
/// + Filter ----------------------------------------------+
/// |                                                      |
/// |  SIP From:    [                                   ]  |
/// |  SIP To:      [                                   ]  |
/// |  Source:      [                                   ]  |
/// |  Destination: [                                   ]  |
/// |  Payload:     [                                   ]  |
/// |  ──────────────────────────────────────────────────  |
/// |  All       [ ]                                       |
/// |  REGISTER  [*]             OPTIONS   [ ]             |
/// |  INVITE    [*]             PUBLISH   [ ]             |
/// |  SUBSCRIBE [ ]             MESSAGE   [ ]             |
/// |  NOTIFY    [ ]             REFER     [ ]             |
/// |  INFO      [ ]             UPDATE    [ ]             |
/// |                                                      |
/// |     [ Filter ]                 [ Cancel ]            |
/// |  (inline parse error appears here)                   |
/// |                                                      |
/// |                                                      |
/// +------------------------------------------------------+
/// ```
///
/// The method grid is filled a row at a time, left cell then right, in
/// `FILTER_METHODS` order. The `All` master checkbox sits above the grid it
/// governs and shows checked only while every method is checked, so the
/// mixed selection drawn here leaves it clear; by default every method is
/// checked and every marker reads `[*]`. The last painted row appears only
/// when Enter fails to parse the typed values, and the live version is
/// prefixed with a warning sign.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full frame area the popup is centered within.
/// * `state` - Filter dialog state (field texts, focus, checkboxes, error).
/// * `theme` - Color theme for all styling.
///
/// # Side effects
/// Draws to `frame` (clearing the cells behind the popup) via direct
/// buffer painting; no state is mutated. A parse error is shown inline
/// below the buttons.
pub(in crate::tui) fn render_filter_popup(
    frame: &mut ratatui::Frame,
    area: Rect,
    state: &FilterDialogState,
    theme: &Theme,
) {
    let popup_width: u16 = 56;
    let popup_height: u16 = 20;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter ")
        .style(Style::default().bg(theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;
    let iw = inner.width;

    // ── Text input fields ──────────────────────────────────────────
    let labels = [
        "  SIP From:    ",
        "  SIP To:      ",
        "  Source:      ",
        "  Destination: ",
        "  Payload:     ",
    ];
    let field_width = iw.saturating_sub(labels[0].len() as u16 + 2); // +2 for margin

    for (i, label) in labels.iter().enumerate() {
        let focused = state.focused_field == i;
        let cursor = if focused { state.cursor_pos } else { 0 };
        render_filter_text_field(
            buf,
            ix,
            iy + 1 + i as u16,
            &FilterTextField {
                label,
                value: state.text_field(i),
                field_width,
                focused,
                cursor_pos: cursor,
            },
            theme,
        );
    }

    // ── Separator line ─────────────────────────────────────────────
    let sep_y = iy + 1 + labels.len() as u16;
    // Saturating: on a sub-6-column popup the 4-column margin exceeds `iw`
    // and a plain `iw - 4` would underflow (debug panic / release wrap).
    let sep = "\u{2500}".repeat(iw.saturating_sub(4) as usize);
    set_string_clipped(
        buf,
        inner,
        ix + 2,
        sep_y,
        &sep,
        Style::default().fg(theme.muted),
    );

    // ── "All" master checkbox — ABOVE the method grid it governs ──
    let all_y = sep_y + 1;
    let col1_x = ix + 2;
    let col2_x = ix + (iw / 2) + 1;
    let all_focused = state.focused_field == ALL_METHODS_IDX;
    let all_marker = if state.all_methods_checked() {
        "[*]"
    } else {
        "[ ]"
    };
    let all_style = if all_focused {
        Style::default()
            .fg(theme.selected)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };
    set_string_clipped(
        buf,
        inner,
        col1_x,
        all_y,
        format!("{:<10}", "All"),
        all_style,
    );
    set_string_clipped(buf, inner, col1_x + 10, all_y, all_marker, all_style);

    // ── Method checkboxes (two columns, 5 rows) ───────────────────
    let cb_y = all_y + 1;

    for row in 0..5u16 {
        let left_idx = (row * 2) as usize;
        let right_idx = left_idx + 1;

        // Left column
        if left_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[left_idx];
            let checked = state.methods[left_idx];
            let focused = state.focused_field == METHOD_CHECKBOX_BASE + left_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            set_string_clipped(buf, inner, col1_x, cb_y + row, &name, style);
            set_string_clipped(buf, inner, col1_x + 10, cb_y + row, marker, style);
        }

        // Right column
        if right_idx < FILTER_METHODS.len() {
            let method = FILTER_METHODS[right_idx];
            let checked = state.methods[right_idx];
            let focused = state.focused_field == METHOD_CHECKBOX_BASE + right_idx;
            let marker = if checked { "[*]" } else { "[ ]" };
            let name = format!("{:<10}", method);
            let style = if focused {
                Style::default()
                    .fg(theme.selected)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.foreground)
            };
            set_string_clipped(buf, inner, col2_x, cb_y + row, &name, style);
            set_string_clipped(buf, inner, col2_x + 10, cb_y + row, marker, style);
        }
    }

    // ── Buttons ────────────────────────────────────────────────────
    let btn_y = cb_y + 6;
    let filter_focused = state.focused_field == FILTER_BUTTON_IDX;
    let cancel_focused = state.focused_field == CANCEL_BUTTON_IDX;

    let filter_style = if filter_focused {
        Style::default().fg(theme.good).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };
    let cancel_style = if cancel_focused {
        Style::default()
            .fg(theme.warning)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.foreground)
    };

    let btn_col1 = ix + 5;
    let btn_col2 = ix + iw / 2 + 5;
    set_string_clipped(buf, inner, btn_col1, btn_y, "[ Filter ]", filter_style);
    set_string_clipped(buf, inner, btn_col2, btn_y, "[ Cancel ]", cancel_style);
    // A button a user can SEE is not a key they can PRESS. `Esc` has always
    // canceled this dialog and it was never written down, so the only way to
    // learn it was to guess -- the same defect as a hint truncated off the
    // right edge, and indistinguishable from one at the keyboard.
    let footer_hint = "Tab move \u{b7} Enter apply \u{b7} Esc cancel";
    if btn_y + 2 < inner.y + inner.height {
        set_string_clipped(
            buf,
            inner,
            ix + 2,
            btn_y + 2,
            footer_hint,
            Style::default().fg(theme.muted),
        );
    }

    // ── Inline parse error (dialog stays open on failure) ─────────
    if let Some(err) = &state.error {
        let msg: String = format!("\u{26a0} {err}")
            .chars()
            .take((iw as usize).saturating_sub(4))
            .collect();
        set_string_clipped(
            buf,
            inner,
            ix + 2,
            btn_y + 1,
            &msg,
            Style::default().fg(theme.warning),
        );
    }
}

/// Render the settings popup as a centered overlay: one row per setting
/// (color mode, timestamp mode, autoscroll, raw preview, SDP display,
/// syntax highlight) with the focused row emphasized.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Full frame area the popup is centered within.
/// * `app` - Application state (current mode values, focused item, theme).
///
/// # Side effects
/// Draws to `frame` (clearing the cells behind the popup) via direct
/// buffer painting; no state is mutated.
pub(in crate::tui) fn render_settings_popup(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let popup_width: u16 = 50;
    let popup_height: u16 = 12;
    let popup_area = centered_popup(area, popup_width, popup_height);

    // Clear the area behind the popup
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings ")
        .style(Style::default().bg(app.theme.background));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let buf = frame.buffer_mut();
    let ix = inner.x;
    let iy = inner.y;

    let labels = [
        "Color Mode:",
        "Timestamp Mode:",
        "Autoscroll:",
        "Raw Preview:",
        "SDP Display:",
        "Syntax Highlight:",
    ];

    let values = [
        match app.color_mode {
            ColorMode::Method => "Method",
            ColorMode::CallId => "CallId",
            ColorMode::CSeq => "CSeq",
        },
        match app.timestamp_mode {
            TimestampMode::Absolute => "Absolute",
            TimestampMode::DeltaPrev => "DeltaPrev",
            TimestampMode::DeltaFirst => "DeltaFirst",
            TimestampMode::Scaled => "Scaled",
        },
        if app.call_list.autoscroll {
            "ON"
        } else {
            "OFF"
        },
        if app.flow.raw_preview { "ON" } else { "OFF" },
        match app.sdp_display_mode {
            SdpDisplayMode::None => "None",
            SdpDisplayMode::Summary => "Summary",
            SdpDisplayMode::Full => "Full",
        },
        if app.syntax_highlight { "ON" } else { "OFF" },
    ];

    for (i, (label, value)) in labels.iter().zip(values.iter()).enumerate() {
        let focused = app.settings_dialog.focused_item == i;
        let style = if focused {
            Style::default()
                .fg(app.theme.selected)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.foreground)
        };
        let value_style = if focused {
            Style::default()
                .fg(app.theme.header)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.theme.good)
        };

        let row_y = iy + 1 + i as u16;
        set_string_clipped(buf, inner, ix + 2, row_y, format!("{:<18}", label), style);
        set_string_clipped(
            buf,
            inner,
            ix + 20,
            row_y,
            format!("[{}]", value),
            value_style,
        );
    }

    // The keys this popup answers to. `Esc` closes it -- the controller has
    // always accepted it -- and until 2026-09-01 the popup never said so, so
    // the only way to learn it was to guess or read the source. A dialog that
    // does not name its own exit is the same defect as one that names it and
    // truncates it: from the user's side they are identical.
    let hint_y = iy + labels.len() as u16 + 2;
    if hint_y < iy + inner.height {
        set_string_clipped(
            buf,
            inner,
            ix + 2,
            hint_y,
            "\u{2191}/\u{2193} move \u{b7} Enter toggle \u{b7} Esc close",
            Style::default().fg(app.theme.muted),
        );
    }
}

/// Unit tests for the popup renderers: cursor branches, empty/populated
/// browser lists, field truncation and popup geometry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::render::test_support::*;

    /// Flatten a rendered frame to text, one line per row.
    fn frame_text(buf: &ratatui::buffer::Buffer) -> String {
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        text
    }

    /// An `App` whose Name Address popup offers two endpoints.
    fn app_naming_two() -> App {
        let mut app = App::new_test();
        app.name_dialog.targets = vec![
            NameTarget {
                ip: "192.0.2.10".to_string(),
                name: String::new(),
            },
            NameTarget {
                ip: "192.0.2.20".to_string(),
                name: String::new(),
            },
        ];
        app.name_dialog.active = 0;
        app
    }

    /// The Name Address popup shows its whole hint, including how to cancel.
    ///
    /// Reported from the UI on 2026-09-01: pressing `N` opened a popup whose
    /// last hint was cut off mid-word. The width was a constant 60 and the
    /// two-endpoint hint is 66 columns, so `Esc cancel` -- the only way out
    /// that the popup names -- fell off the right edge. `Paragraph` has no
    /// `wrap` here, so an overlong line truncates silently rather than
    /// flowing, which is why nothing failed.
    ///
    /// A popup that does not say how to close it is the worst line to lose.
    #[test]
    fn name_popup_shows_its_whole_hint_including_how_to_cancel() {
        let app = app_naming_two();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_name_popup(frame, area, &app);
            })
            .unwrap();
        let text = frame_text(terminal.backend().buffer());

        for fragment in [
            "Tab switch endpoint",
            "Enter save all",
            "empty clears",
            "Esc cancel",
        ] {
            assert!(
                text.contains(fragment),
                "the Name Address popup truncated {fragment:?} off its hint. \
                 The popup must be wide enough for what it says, and the \
                 cancel key is the one line a user needs when they are \
                 stuck.\n{text}"
            );
        }
    }

    /// The single-endpoint hint fits too.
    ///
    /// The other arm of the same branch. It happened to fit at width 60, which
    /// is exactly why the bug survived: the common case looked right.
    #[test]
    fn name_popup_single_endpoint_shows_its_whole_hint() {
        let mut app = App::new_test();
        app.name_dialog.targets = vec![NameTarget {
            ip: "192.0.2.10".to_string(),
            name: String::new(),
        }];
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_name_popup(frame, area, &app);
            })
            .unwrap();
        let text = frame_text(terminal.backend().buffer());
        for fragment in ["Enter save", "empty name clears", "Esc cancel"] {
            assert!(
                text.contains(fragment),
                "the single-endpoint popup truncated {fragment:?}\n{text}"
            );
        }
    }

    /// Every popup entry point, rendered, with the text it must not lose.
    ///
    /// A popup that truncates the line naming its exit key leaves a user with
    /// no visible way out, which is what `N` did on 2026-09-01. `Paragraph`
    /// does not wrap here, so an overlong line vanishes off the right edge in
    /// silence -- no panic, no warning, nothing to fail.
    ///
    /// Rendered at 120x40: wide enough that any truncation is the POPUP's own
    /// sizing rather than the terminal's, which is the distinction that
    /// matters. A popup free to be as wide as it likes and still cutting its
    /// own text is a bug; one squeezed by an 80-column terminal is a
    /// trade-off.
    /// One overlay: its name, and the call that draws it into a frame.
    type Overlay = (&'static str, fn(&mut ratatui::Frame, Rect, &App));

    fn popup_renders() -> Vec<Overlay> {
        vec![
            ("save", |f, a, app| render_save_popup(f, a, app)),
            ("name", |f, a, app| render_name_popup(f, a, app)),
            ("file_open", |f, a, app| render_file_open_popup(f, a, app)),
            ("settings", |f, a, app| render_settings_popup(f, a, app)),
            ("filter", |f, a, app| {
                render_filter_popup(f, a, &app.filter_dialog, &app.theme)
            }),
        ]
    }

    /// Every popup shows how to leave it.
    ///
    /// The generalized form of the `N` defect. The exit key is the one piece
    /// of text a stuck user needs, and it is always last in the hint -- which
    /// makes it the first thing a too-narrow popup drops.
    #[test]
    fn every_popup_renders_its_exit_key_in_full() {
        let mut app = app_naming_two();
        app.filter_dialog = FilterDialogState::default();
        let mut checked = 0;

        for (name, render) in popup_renders() {
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render(frame, area, &app);
                })
                .unwrap();
            let text = frame_text(terminal.backend().buffer());
            checked += 1;
            assert!(
                text.contains("Esc"),
                "the {name} popup does not render `Esc` anywhere, so it never \
                 tells a user how to close it -- or it named the key and cut \
                 it off the right edge, which looks identical to a \
                 user.\n{text}"
            );
        }
        assert!(
            checked >= 5,
            "only {checked} popup(s) exercised; the table is not covering the \
             module and this gate proves little"
        );
    }

    /// The table covers every popup the module exposes.
    ///
    /// Without this, a popup added later is simply absent from the gate --
    /// and an uncovered popup looks exactly like a covered one that passes.
    #[test]
    fn the_popup_table_covers_every_popup_entry_point() {
        let src = include_str!("popups.rs");
        let exposed: Vec<&str> = src
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub(in crate::tui) fn render_"))
            .filter_map(|l| l.split(['(', '<']).next())
            // Excluded, each with the reason it is not a popup entry point:
            //   file_open_*       bodies dispatched from render_file_open_popup,
            //                     drawn into its inner area rather than
            //                     centering themselves;
            //   filter_text_field one field inside the filter popup, with no
            //                     border, no exit and nothing to close.
            .filter(|n| {
                !matches!(
                    *n,
                    "file_open_browser" | "file_open_manual" | "filter_text_field"
                )
            })
            .collect();
        let covered: Vec<&str> = popup_renders().iter().map(|(n, _)| *n).collect();

        assert!(
            exposed.len() >= 5,
            "only {} popup entry point(s) found; the scan is wrong: \
             {exposed:?}",
            exposed.len()
        );
        for name in &exposed {
            let stem = name.trim_end_matches("_popup");
            assert!(
                covered.contains(&stem),
                "render_{name} is a popup and no row of the table renders it, \
                 so nothing checks that it shows its exit key. Covered: \
                 {covered:?}"
            );
        }
    }

    /// The name popup grows for content a constant width could not have known.
    ///
    /// The fix is content-driven sizing, not a bigger constant. An IPv6
    /// endpoint row plus an inline validation error is longer than anything
    /// the original 60 was chosen for, and a wider constant would fail the
    /// same way one address later.
    #[test]
    fn name_popup_grows_for_long_addresses_and_an_error() {
        let mut app = App::new_test();
        app.name_dialog.targets = vec![
            NameTarget {
                ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
                name: "edge-proxy-frankfurt".to_string(),
            },
            NameTarget {
                ip: "2001:0db8:85a3:0000:0000:8a2e:0370:99ff".to_string(),
                name: String::new(),
            },
        ];
        app.name_dialog.error = Some("a name may not contain a space".to_string());

        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_name_popup(frame, area, &app);
            })
            .unwrap();
        let text = frame_text(terminal.backend().buffer());

        for fragment in [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "a name may not contain a space",
            "Esc cancel",
        ] {
            assert!(
                text.contains(fragment),
                "the popup cut off {fragment:?}; sizing must follow the \
                 content, because a constant cannot know how long an address \
                 or an error will be\n{text}"
            );
        }
    }

    /// A terminal too narrow for the popup does not panic.
    ///
    /// The other end. Content-driven sizing must still clamp: a popup wider
    /// than the frame is an arithmetic underflow away from a crash, and the
    /// user resizing their terminal is not an error case.
    #[test]
    fn name_popup_survives_a_terminal_narrower_than_its_content() {
        let app = app_naming_two();
        for w in [10u16, 20, 30, 40, 66, 70] {
            let mut terminal = Terminal::new(TestBackend::new(w, 12)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render_name_popup(frame, area, &app);
                })
                .unwrap_or_else(|e| panic!("width {w} panicked: {e}"));
        }
    }

    /// The text a rendered frame actually shows, borders and blanks stripped.
    ///
    /// Only rows carrying a letter or digit survive, so a box-drawing border
    /// -- whose width changes with the popup -- cannot make two renderings of
    /// the same content look different.
    fn content_lines(buf: &ratatui::buffer::Buffer) -> Vec<String> {
        frame_text(buf)
            .lines()
            .map(|l| {
                l.chars()
                    .filter(|c| !"\u{2500}\u{2502}\u{250c}\u{2510}\u{2514}\u{2518}".contains(*c))
                    .collect::<String>()
                    .trim()
                    .to_string()
            })
            .filter(|l| l.chars().any(|c| c.is_alphanumeric()))
            .collect()
    }

    /// Every overlay, including the one that does not live in this module.
    fn every_overlay() -> Vec<Overlay> {
        let mut all = popup_renders();
        all.push(("column_selector", |f, a, app| {
            crate::tui::call_list::render_column_selector(f, a, &app.call_list, &app.theme)
        }));
        all
    }

    /// No popup shows MORE text when the terminal grows.
    ///
    /// The general detector, and the one that needs no knowledge of any
    /// popup's strings. If a popup is complete at 100 columns, widening the
    /// terminal to 240 cannot reveal anything new; if widening does reveal
    /// something, the popup was clipping its own content at 100 and a user on
    /// an ordinary terminal was reading a truncated dialog.
    ///
    /// This is what would have caught `N` without anyone knowing the hint's
    /// length, and it catches the next one the same way.
    #[test]
    fn no_popup_shows_more_text_when_the_terminal_grows() {
        let app = app_naming_two();
        for (name, render) in every_overlay() {
            let mut small = Terminal::new(TestBackend::new(100, 40)).unwrap();
            small
                .draw(|f| {
                    let a = f.area();
                    render(f, a, &app);
                })
                .unwrap();
            let at_100 = content_lines(small.backend().buffer());

            let mut large = Terminal::new(TestBackend::new(240, 60)).unwrap();
            large
                .draw(|f| {
                    let a = f.area();
                    render(f, a, &app);
                })
                .unwrap();
            let at_240 = content_lines(large.backend().buffer());

            assert_eq!(
                at_100, at_240,
                "the {name} popup renders different text at 100 columns than \
                 at 240, which means it was CLIPPING its own content on the \
                 narrower one. Size the popup to what it draws rather than to \
                 a constant.\nat 100: {at_100:#?}\nat 240: {at_240:#?}"
            );
        }
    }

    /// Every overlay in the TUI is covered by these gates.
    ///
    /// `render_widget(Clear, ..)` is what makes something an overlay, so it is
    /// the honest way to enumerate them — a new popup anywhere in `src/tui/`
    /// is caught here rather than quietly going ungated. `render_column_
    /// selector` lives in `call_list.rs` and was missed by a table that only
    /// read this module.
    #[test]
    fn every_tui_overlay_is_covered_by_these_gates() {
        let sources = [
            ("popups", include_str!("popups.rs")),
            ("call_list", include_str!("../call_list.rs")),
        ];
        let mut overlays = 0;
        for (_where, src) in sources {
            // The CALL form, not the bare substring: prose in this file that
            // explains the rule would otherwise count as an overlay, and a
            // scanner that counts its own documentation is measuring itself.
            // Production code only: the tests below render overlays too, and
            // a scanner that counts its own fixtures is measuring itself.
            let production = src.split("\nmod tests {").next().unwrap_or(src);
            overlays += production.matches("frame.render_widget(Clear").count();
        }
        let covered = every_overlay().len();
        assert!(
            overlays >= 6,
            "only {overlays} overlay(s) found by scanning for \
             `render_widget(Clear`; the scan is wrong and this gate proves \
             nothing"
        );
        assert_eq!(
            covered, overlays,
            "the TUI draws {overlays} overlay(s) and these gates cover \
             {covered}. An uncovered popup looks exactly like a covered one \
             that passes."
        );
    }

    /// Every overlay names the key that closes it.
    ///
    /// Four popups had a working `Esc` their controller accepted and their
    /// rendering never mentioned: settings, filter, the column selector, and
    /// the name popup, which named it and then cut it off. From the keyboard
    /// those are the same defect.
    #[test]
    fn every_overlay_names_the_key_that_closes_it() {
        let app = app_naming_two();
        for (name, render) in every_overlay() {
            let mut terminal = Terminal::new(TestBackend::new(140, 44)).unwrap();
            terminal
                .draw(|f| {
                    let a = f.area();
                    render(f, a, &app);
                })
                .unwrap();
            let text = frame_text(terminal.backend().buffer());
            assert!(
                text.contains("Esc"),
                "the {name} overlay never names `Esc`, so a user has no way \
                 to learn how to leave it short of reading the source\n{text}"
            );
        }
    }

    /// Every overlay survives a terminal far too small for it.
    ///
    /// Content-driven sizing must still clamp. A popup wider than the frame is
    /// one subtraction away from a panic, and resizing a terminal is not an
    /// error case.
    #[test]
    fn every_overlay_survives_a_tiny_terminal() {
        let app = app_naming_two();
        let mut crashed = Vec::new();
        for (name, render) in every_overlay() {
            for (w, h) in [(1u16, 1u16), (4, 3), (10, 5), (20, 8), (40, 10), (66, 12)] {
                // Each caught separately: a panic escaping `draw` is a real
                // panic, not an `Err`, so without this the first crash hides
                // every other one AND the message cannot say which overlay it
                // was.
                let app_ref = &app;
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                    terminal
                        .draw(|f| {
                            let a = f.area();
                            render(f, a, app_ref);
                        })
                        .unwrap();
                }));
                if ok.is_err() {
                    crashed.push(format!("  {name} at {w}x{h}"));
                }
            }
        }
        assert!(
            crashed.is_empty(),
            "these overlays panic on a terminal too small for them. Resizing \
             a terminal is not an error case, and a panic takes the whole TUI \
             with it:\n{}",
            crashed.join("\n")
        );
    }

    /// Every overlay draws inside the frame it was given.
    ///
    /// A centered popup computed from a constant can start past the right edge
    /// on a narrow frame. ratatui clips rather than crashing, so the symptom
    /// is a dialog that is simply not there — which reads as the key having
    /// done nothing.
    #[test]
    fn every_overlay_draws_something_inside_the_frame() {
        let app = app_naming_two();
        for (name, render) in every_overlay() {
            let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
            terminal
                .draw(|f| {
                    let a = f.area();
                    render(f, a, &app);
                })
                .unwrap();
            let drawn = content_lines(terminal.backend().buffer());
            assert!(
                !drawn.is_empty(),
                "the {name} overlay drew no text at all inside a 100x40 \
                 frame; a popup that renders nothing reads as a key that did \
                 nothing"
            );
        }
    }

    // ── crashes ────────────────────────────────────────────────────
    //
    // A panic takes the entire TUI down mid-capture. On 2026-09-01 two
    // popups did exactly that -- the settings popup below six rows, and the
    // filter popup at sizes as ordinary as 66x12 -- because their rows were
    // computed from a constant height and `Buffer::set_string` panics on an
    // out-of-bounds index. Nothing caught it: the popups rendered fine at the
    // sizes anyone happened to test, and resizing a terminal is not something
    // a test does unless it is told to.
    //
    // Every write in `src/tui/` now goes through `set_string_clipped`, and
    // these gates hold that in place from three directions: the helper itself
    // is correct, nothing bypasses it, and every overlay survives every size.

    /// The guard declines every write that starts outside its area.
    ///
    /// Each case is a different way to be out of bounds, and the answer to
    /// all of them is to draw nothing rather than to panic.
    #[test]
    fn set_string_clipped_declines_every_out_of_bounds_write() {
        let area = Rect::new(2, 2, 6, 3); // x 2..8, y 2..5
        for (x, y, what) in [
            (2u16, 5u16, "one row below"),
            (2, 99, "far below"),
            (8, 2, "one column past the right"),
            (99, 2, "far right"),
            (1, 2, "one column left of the area"),
            (2, 1, "one row above"),
            (0, 0, "the origin, outside this area"),
            (u16::MAX, u16::MAX, "the far corner"),
        ] {
            let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 20, 10));
            set_string_clipped(&mut buf, area, x, y, "XXXX", Style::default());
            let painted: String = (0..10)
                .flat_map(|yy| (0..20).map(move |xx| (xx, yy)))
                .filter_map(|(xx, yy)| buf.cell((xx, yy)).map(|c| c.symbol().to_string()))
                .collect();
            assert!(
                !painted.contains('X'),
                "a write {what} was drawn anyway; the guard must decline \
                 rather than panic OR paint"
            );
        }
    }

    /// A write that starts inside is truncated at the right edge.
    ///
    /// The other half. Declining an out-of-bounds START is not enough: a long
    /// value beginning one column inside would run through the border and out
    /// of the buffer.
    #[test]
    fn set_string_clipped_truncates_at_the_right_edge() {
        let area = Rect::new(2, 2, 6, 3);
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 20, 10));
        set_string_clipped(&mut buf, area, 6, 3, "ABCDEFGHIJ", Style::default());

        // Columns 6 and 7 are the last two inside the area.
        assert_eq!(buf.cell((6, 3)).unwrap().symbol(), "A");
        assert_eq!(buf.cell((7, 3)).unwrap().symbol(), "B");
        // Column 8 is outside it and must be untouched.
        assert_eq!(
            buf.cell((8, 3)).unwrap().symbol(),
            " ",
            "the write ran past the right edge of its area and into whatever \
             is drawn there -- a border, or another widget"
        );
    }

    /// A zero-sized area accepts nothing.
    ///
    /// The degenerate case a saturating subtraction produces on a 1x1
    /// terminal, where `inner` of a bordered block has no cells at all.
    #[test]
    fn set_string_clipped_accepts_nothing_into_a_zero_sized_area() {
        for area in [
            Rect::new(0, 0, 0, 0),
            Rect::new(3, 3, 0, 5),
            Rect::new(3, 3, 5, 0),
        ] {
            let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 20, 10));
            set_string_clipped(&mut buf, area, area.x, area.y, "XXXX", Style::default());
            let painted: String = (0..10)
                .flat_map(|yy| (0..20).map(move |xx| (xx, yy)))
                .filter_map(|(xx, yy)| buf.cell((xx, yy)).map(|c| c.symbol().to_string()))
                .collect();
            assert!(
                !painted.contains('X'),
                "an area of {}x{} has no cells and accepted a write",
                area.width,
                area.height
            );
        }
    }

    /// Multibyte text is truncated on a character boundary.
    ///
    /// Truncating a UTF-8 string by BYTES panics on a boundary. Every SIP
    /// capture this tool is pointed at can carry a non-ASCII display name, so
    /// this is a routine input, not an exotic one.
    #[test]
    fn set_string_clipped_truncates_multibyte_without_panicking() {
        let area = Rect::new(0, 0, 4, 1);
        for text in [
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            "\u{4f60}\u{597d}\u{4e16}\u{754c}",
            "a\u{e9}b\u{4f60}c",
        ] {
            let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 10, 2));
            set_string_clipped(&mut buf, area, 0, 0, text, Style::default());
        }
    }

    /// Nothing in the TUI writes through the unguarded call.
    ///
    /// The source gate. The helper being correct is worthless if a renderer
    /// added next month calls `Buffer::set_string` directly -- which is the
    /// obvious thing to reach for, and what all 42 existing call sites did.
    #[test]
    fn no_tui_code_writes_through_the_unguarded_set_string() {
        let mut offenders = Vec::new();
        let mut scanned = 0;
        for (name, src) in [
            ("render/popups.rs", include_str!("popups.rs")),
            ("call_list.rs", include_str!("../call_list.rs")),
            (
                "call_flow/render.rs",
                include_str!("../call_flow/render.rs"),
            ),
        ] {
            scanned += 1;
            for (n, line) in src.lines().enumerate() {
                let l = line.trim();
                if l.starts_with("//") {
                    continue;
                }
                // `set_stringn` takes a max width and is bounded already; the
                // helper's own body is where the guarded call lives.
                if l.contains(".set_string(") && !l.contains("set_stringn") {
                    offenders.push(format!("  {name}:{}: {l}", n + 1));
                }
            }
        }
        assert!(scanned >= 3, "the scan read {scanned} file(s); it is wrong");
        assert!(
            offenders.is_empty(),
            "these write through `Buffer::set_string`, which PANICS on an \
             out-of-bounds index and took the TUI down on 2026-09-01. Use \
             `set_string_clipped`, which declines instead:\n{}",
            offenders.join("\n")
        );
    }

    /// Every overlay survives every terminal size worth having.
    ///
    /// An exhaustive sweep rather than a handful of sizes, because the two
    /// crashes found here appeared at 4x3 and at 66x12 -- one absurd, one
    /// completely ordinary -- and no sampled list would have contained both.
    #[test]
    fn every_overlay_survives_an_exhaustive_size_sweep() {
        let app = app_naming_two();
        let mut crashed = Vec::new();
        for (name, render) in every_overlay() {
            for w in 1u16..=90 {
                for h in [1u16, 2, 3, 5, 8, 12, 20, 30] {
                    let app_ref = &app;
                    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
                        t.draw(|f| {
                            let a = f.area();
                            render(f, a, app_ref);
                        })
                        .unwrap();
                    }));
                    if ok.is_err() {
                        crashed.push(format!("  {name} at {w}x{h}"));
                    }
                }
            }
        }
        assert!(
            crashed.is_empty(),
            "{} overlay/size combination(s) panic. A panic takes the whole \
             TUI down, and resizing a terminal is not an error case:\n{}",
            crashed.len(),
            crashed
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// Overlays survive content far longer than anything they were sized for.
    ///
    /// The other axis. A popup can be given a 39-character IPv6 address, a
    /// long validation error and a long name at once, on a small terminal --
    /// which is the combination a constant width was never chosen for.
    #[test]
    fn overlays_survive_extreme_content_on_a_small_terminal() {
        let mut app = App::new_test();
        app.name_dialog.targets = (0..8)
            .map(|i| NameTarget {
                ip: format!("2001:0db8:85a3:0000:0000:8a2e:0370:{i:04x}"),
                name: "x".repeat(200),
            })
            .collect();
        app.name_dialog.error = Some("e".repeat(300));
        app.save.path = "/".to_string() + &"deep/".repeat(60);

        let mut crashed = Vec::new();
        for (name, render) in every_overlay() {
            for (w, h) in [(1u16, 1u16), (8, 4), (20, 6), (40, 10), (80, 24), (120, 40)] {
                let app_ref = &app;
                let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
                    t.draw(|f| {
                        let a = f.area();
                        render(f, a, app_ref);
                    })
                    .unwrap();
                }));
                if ok.is_err() {
                    crashed.push(format!("  {name} at {w}x{h}"));
                }
            }
        }
        assert!(
            crashed.is_empty(),
            "overlays panic on oversized content:\n{}",
            crashed.join("\n")
        );
    }

    /// The sweep is actually drawing something.
    ///
    /// Anti-vacuity for every crash gate above. A render that silently drew
    /// nothing would survive every size in the sweep and prove nothing at all
    /// -- which is the same shape as the bug the sweep is looking for.
    #[test]
    fn the_crash_sweep_renders_real_content() {
        let app = app_naming_two();
        for (name, render) in every_overlay() {
            let mut t = Terminal::new(TestBackend::new(120, 40)).unwrap();
            t.draw(|f| {
                let a = f.area();
                render(f, a, &app);
            })
            .unwrap();
            let drawn = content_lines(t.backend().buffer());
            assert!(
                drawn.len() >= 2,
                "the {name} overlay drew {} line(s) of content at 120x40, so \
                 the size sweep is exercising almost nothing",
                drawn.len()
            );
        }
    }

    /// An empty save path renders the popup (block cursor branch) without
    /// panicking.
    #[test]
    fn render_save_popup_empty_path_shows_cursor() {
        let mut app = App::new_test();
        app.save.path.clear();
        app.save.cursor = 0;
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_save_popup(frame, area, &app);
            })
            .unwrap();
        // Should not panic with empty path; popup title present.
        let buf = terminal.backend().buffer();
        let mut found = false;
        for y in 0..buf.area.height {
            let mut row = String::new();
            for x in 0..buf.area.width {
                row.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            if row.contains("Save Capture") {
                found = true;
            }
        }
        assert!(found);
    }

    /// A cursor in the middle of the path exercises the split-span
    /// (before/cursor/after) branch without panicking.
    #[test]
    fn render_save_popup_cursor_mid_string() {
        let mut app = App::new_test();
        app.save.path = "abcdef".to_string();
        app.save.cursor = 3; // cursor in the middle
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_save_popup(frame, area, &app);
            })
            .unwrap();
        // Renders without panic; reaches the mid-string cursor branch.
    }

    /// An empty entry list shows the "(no matching pcap files)" notice.
    #[test]
    fn render_file_open_browser_empty_and_populated() {
        // Empty entries → "(no matching pcap files)" path.
        let mut app = App::new_test();
        app.file_open.entries.clear();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_browser(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("no matching pcap files"));
    }

    /// A typed filter replaces the hint line with "Filter: <text>".
    #[test]
    fn render_file_open_browser_with_filter() {
        let mut app = App::new_test();
        app.file_open.filter = "abc".to_string();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_browser(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Filter: abc"));
    }

    /// The manual variant renders both the empty-path and mid-path cursor
    /// branches and shows the Path label.
    #[test]
    fn render_file_open_manual_empty_and_with_path() {
        // Empty path branch.
        let mut app = App::new_test();
        app.file_open.path.clear();
        app.file_open.cursor = 0;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_manual(frame, inner, &app);
            })
            .unwrap();

        // Cursor mid-path branch.
        app.file_open.path = "/tmp/a.pcap".to_string();
        app.file_open.cursor = 4;
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_manual(frame, inner, &app);
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("Path:"));
    }

    // ── render_status_line2/3 direct (non-call-flow branch) ────────

    /// A focused field shows label, value and cursor; an unfocused field
    /// truncates a value longer than the field width.
    #[test]
    fn render_filter_text_field_focused_and_unfocused() {
        let theme = Theme::default();

        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "From: ",
            value: "alice",
            field_width: 20,
            focused: true,
            cursor_pos: 2,
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains("From:"));
        assert!(row.contains("alice"));

        // Unfocused branch with value longer than the field (truncation).
        let mut buf2 = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field2 = FilterTextField {
            label: "To: ",
            value: "averylongvaluethatexceedsthefieldwidth",
            field_width: 12,
            focused: false,
            cursor_pos: 0,
        };
        render_filter_text_field(&mut buf2, 0, 0, &field2, &theme);
        let mut row2 = String::new();
        for x in 0..buf2.area.width {
            row2.push_str(buf2.cell((x, 0)).unwrap().symbol());
        }
        assert!(row2.contains("To:"));
    }

    /// A block cursor sitting on a multibyte character renders that whole
    /// character without panicking on a `cursor..cursor + 1` byte slice.
    #[test]
    fn render_filter_text_field_multibyte_cursor_no_panic() {
        let theme = Theme::default();
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "F: ",
            value: "héllo",
            field_width: 20,
            focused: true,
            cursor_pos: 1, // on the two-byte 'é'
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
        let mut row = String::new();
        for x in 0..buf.area.width {
            row.push_str(buf.cell((x, 0)).unwrap().symbol());
        }
        assert!(row.contains('h'), "field content missing: {row}");
    }

    /// A cursor past the visible field width must not build an inverted
    /// (start > end) slice range for the after-cursor text.
    #[test]
    fn render_filter_text_field_cursor_beyond_inner_width_no_panic() {
        let theme = Theme::default();
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "F: ",
            value: "abcdefghijklmnopqrst",
            field_width: 10, // inner width 8, cursor well beyond it
            focused: true,
            cursor_pos: 10,
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
    }

    /// Unfocused truncation of a value whose display cut lands inside a
    /// multibyte character backs up to the previous boundary, not a panic.
    #[test]
    fn render_filter_text_field_unfocused_multibyte_truncation_no_panic() {
        let theme = Theme::default();
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "F: ",
            value: "éééééééééé", // 10 chars, 20 bytes
            field_width: 11,     // inner width 9 — mid-character in bytes
            focused: false,
            cursor_pos: 0,
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
    }

    /// The file-open manual path renders a block cursor on a multibyte
    /// character without panicking on a `cursor..cursor + 1` byte slice.
    #[test]
    fn render_file_open_manual_multibyte_cursor_no_panic() {
        let mut app = App::new_test();
        app.file_open.path = "/tmp/café.pcap".to_string();
        app.file_open.cursor = app.file_open.path.find('é').unwrap();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                let inner = centered_popup(area, 80, 22);
                render_file_open_manual(frame, inner, &app);
            })
            .unwrap();
    }

    /// The save-dialog path renders a block cursor on a multibyte character
    /// without panicking on a `cursor..cursor + 1` byte slice.
    #[test]
    fn render_save_popup_multibyte_cursor_no_panic() {
        let mut app = App::new_test();
        app.save.path = "/tmp/café.pcap".to_string();
        app.save.cursor = app.save.path.find('é').unwrap();
        let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_save_popup(frame, area, &app);
            })
            .unwrap();
    }

    /// A cursor at `value.len()` paints the trailing block cursor without
    /// panicking.
    #[test]
    fn render_filter_text_field_cursor_at_end() {
        let theme = Theme::default();
        let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 60, 1));
        let field = FilterTextField {
            label: "F: ",
            value: "ab",
            field_width: 20,
            focused: true,
            cursor_pos: 2, // at end == value.len()
        };
        render_filter_text_field(&mut buf, 0, 0, &field, &theme);
        // Renders block cursor at end without panic.
    }

    /// A field narrower than its two brackets must not underflow
    /// `field_width - 2` (which panics in debug, wraps in release). Covers
    /// `field_width` values below 2, including a focused zero-width field
    /// that also exercises the closing-bracket position arithmetic.
    #[test]
    fn render_filter_text_field_narrow_no_underflow() {
        let theme = Theme::default();
        for field_width in [0u16, 1, 2] {
            for focused in [false, true] {
                let mut buf = ratatui::buffer::Buffer::empty(Rect::new(0, 0, 20, 1));
                let field = FilterTextField {
                    label: "F: ",
                    value: "abc",
                    field_width,
                    focused,
                    cursor_pos: 1,
                };
                // Would panic with "attempt to subtract with overflow" before
                // the saturating guard.
                render_filter_text_field(&mut buf, 0, 0, &field, &theme);
            }
        }
    }

    /// The whole filter popup must render without underflowing `iw - 4`
    /// (the separator width) on a sub-6-column terminal, where
    /// `centered_popup` clamps the popup to a tiny inner width.
    #[test]
    fn render_filter_popup_narrow_terminal_no_underflow() {
        let theme = Theme::default();
        let state = FilterDialogState::default();
        for w in [1u16, 3, 5, 6] {
            let mut terminal = Terminal::new(TestBackend::new(w, 24)).unwrap();
            // Would panic in `iw - 4` (and the text fields' `field_width - 2`)
            // before the saturating guards.
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render_filter_popup(frame, area, &state, &theme);
                })
                .unwrap();
        }
    }

    // ── centered_popup geometry ────────────────────────────────────

    /// Oversized requests clamp to the area; smaller ones center inside it.
    #[test]
    fn centered_popup_clamps_to_area() {
        let area = Rect::new(0, 0, 40, 20);
        let r = centered_popup(area, 100, 100);
        assert_eq!(r.width, 40);
        assert_eq!(r.height, 20);
        let r2 = centered_popup(area, 20, 10);
        assert_eq!(r2.width, 20);
        assert_eq!(r2.height, 10);
        assert_eq!(r2.x, 10);
        assert_eq!(r2.y, 5);
    }

    // ── message diff edge cases ────────────────────────────────────
}
