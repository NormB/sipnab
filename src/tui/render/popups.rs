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
    let popup_width = 60.min(area.width.saturating_sub(4));
    let popup_height = (if multi { 10 } else { 8 }).min(area.height.saturating_sub(2));
    let popup_area = centered_popup(area, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Name Address ")
        .style(Style::default().bg(app.theme.background));
    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

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
    buf.set_string(label_area.x, label_area.y, label, label_style);

    // Paint opening bracket
    let field_x = x + label.len() as u16;
    buf.set_string(field_x, y, "[", bracket_style);

    // Paint field content with cursor. All byte offsets below are kept on
    // char boundaries so no slice can split a multibyte UTF-8 sequence.
    let content_x = field_x + 1;
    let inner_width = (field_width - 2) as usize; // subtract brackets
    let cursor = crate::text::floor_char_boundary(value, cursor_pos);
    // End of the display window, backed up to a boundary.
    let visible_end = crate::text::floor_char_boundary(value, inner_width);

    if focused {
        // Before cursor (clipped to the visible window)
        let before = &value[..cursor.min(visible_end)];
        buf.set_string(
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
        buf.set_string(
            content_x + cursor as u16,
            y,
            cursor_char,
            Style::default().bg(Color::White).fg(Color::Black),
        );
        // After cursor (clipped; the window may end before the cursor does)
        if cursor_end < visible_end {
            let after = &value[cursor_end..visible_end];
            buf.set_string(
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
            buf.set_string(content_x + filled as u16, y, &pad, Style::default());
        }
    } else {
        // Not focused: just show value dimmed
        let display = &value[..visible_end];
        buf.set_string(content_x, y, display, Style::default().fg(theme.foreground));
        // Fill remaining
        if display.len() < inner_width {
            let pad = " ".repeat(inner_width - display.len());
            buf.set_string(content_x + display.len() as u16, y, &pad, Style::default());
        }
    }

    // Closing bracket
    buf.set_string(field_x + field_width - 1, y, "]", bracket_style);
}

/// Render the filter dialog as a centered popup overlay (sngrep-style).
///
/// Layout:
/// ```text
/// +- Filter -----------------------------------------+
/// |                                                    |
/// |  SIP From:    [                             ]      |
/// |  SIP To:      [                             ]      |
/// |  Source:      [                             ]      |
/// |  Destination: [                             ]      |
/// |  Payload:     [                             ]      |
/// |  ──────────────────────────────────────────────    |
/// |  REGISTER [*]          OPTIONS  [ ]                |
/// |  INVITE   [*]          PUBLISH  [ ]                |
/// |  SUBSCRIBE[ ]          MESSAGE  [ ]                |
/// |  NOTIFY   [ ]          REFER    [ ]                |
/// |  INFO     [ ]          UPDATE   [ ]                |
/// |                                                    |
/// |     [ Filter ]              [ Cancel ]             |
/// |                                                    |
/// +----------------------------------------------------+
/// ```
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
    let sep = "\u{2500}".repeat((iw - 4) as usize);
    buf.set_string(ix + 2, sep_y, &sep, Style::default().fg(theme.muted));

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
    buf.set_string(col1_x, all_y, format!("{:<10}", "All"), all_style);
    buf.set_string(col1_x + 10, all_y, all_marker, all_style);

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
            buf.set_string(col1_x, cb_y + row, &name, style);
            buf.set_string(col1_x + 10, cb_y + row, marker, style);
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
            buf.set_string(col2_x, cb_y + row, &name, style);
            buf.set_string(col2_x + 10, cb_y + row, marker, style);
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
    buf.set_string(btn_col1, btn_y, "[ Filter ]", filter_style);
    buf.set_string(btn_col2, btn_y, "[ Cancel ]", cancel_style);

    // ── Inline parse error (dialog stays open on failure) ─────────
    if let Some(err) = &state.error {
        let msg: String = format!("\u{26a0} {err}")
            .chars()
            .take((iw as usize).saturating_sub(4))
            .collect();
        buf.set_string(ix + 2, btn_y + 1, &msg, Style::default().fg(theme.warning));
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
        buf.set_string(ix + 2, row_y, format!("{:<18}", label), style);
        buf.set_string(ix + 20, row_y, format!("[{}]", value), value_style);
    }
}

/// Unit tests for the popup renderers: cursor branches, empty/populated
/// browser lists, field truncation and popup geometry.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::render::test_support::*;

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
