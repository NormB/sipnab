// SPDX-License-Identifier: MIT OR Apache-2.0

//! The structured filter dialog popup.

use crate::tui::*;

/// Apply the filter dialog state: build a DSL expression, parse it, and set the active filter.
///
/// # Arguments
/// * `app` - the application state; the expression is built from
///   `app.filter_dialog` and applied via `apply_filter_expression`.
///
/// # Side effects
/// Everything `apply_filter_expression` does: sets or clears
/// `app.active_filter`/`active_filter_text`, and closes or keeps the
/// popup depending on parse success.
pub(in crate::tui) fn apply_filter_dialog(app: &mut App) {
    // The time bounds are parsed first because the DSL cannot check them. A
    // malformed timestamp keeps the dialog open with the error shown, the way a
    // bad DSL expression does, so the typed text is corrected, not discarded.
    // The other text fields are regex-escaped into the DSL and cannot fail —
    // except the Header field's NAME, which the DSL checks against the RFC 3261
    // token rule and which comes back as a parse error below.
    let window = match app.filter_dialog.parse_time_window() {
        Ok(w) => w,
        Err(msg) => {
            app.filter_dialog.error = Some(msg);
            return;
        }
    };
    let expr_text = app.filter_dialog.build_filter_expression();
    apply_filter_expression(app, expr_text, window);
}

/// Human-readable text of a filter: the DSL expression, the time window, or
/// both. Feeds the status bar AND the displayed-list cache key, so it must
/// change whenever the DSL or either bound changes.
fn describe_filter(expr_text: Option<&str>, window: crate::tui::state::TimeWindow) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(text) = expr_text {
        parts.push(text.to_string());
    }
    if let Some(a) = window.0 {
        parts.push(format!("after {}", a.to_rfc3339()));
    }
    if let Some(b) = window.1 {
        parts.push(format!("before {}", b.to_rfc3339()));
    }
    parts.join(" | ")
}

/// Parse and apply `expr_text`. On a parse error the dialog STAYS OPEN with
/// the error shown inline (mirroring the file-open dialog), so the typed
/// values can be corrected instead of being discarded with the popup.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `expr_text` - the DSL expression to parse; `None` means every field
///   was empty and clears any active filter.
///
/// # Side effects
/// With no method checked, installs the match-nothing filter and closes
/// the popup. On a successful parse, sets `app.active_filter` and
/// `active_filter_text` and closes the popup; on a parse error, sets
/// `app.filter_dialog.error` and leaves the popup open. Clears
/// `app.status_error` on every path that applies.
pub(in crate::tui) fn apply_filter_expression(
    app: &mut App,
    expr_text: Option<String>,
    window: crate::tui::state::TimeWindow,
) {
    // No SIP methods selected => show nothing. This is the explicit "mute
    // everything" state (distinct from all-checked, which shows everything).
    // The time window is moot here — nothing shows regardless — but it is
    // stored so reopening the dialog reflects it.
    if !app.filter_dialog.any_method_checked() {
        app.active_filter = Some(FilterExpr::never());
        app.active_filter_text = "(no methods selected)".to_string();
        app.active_time_after = window.0;
        app.active_time_before = window.1;
        app.status_error = None;
        app.filter_dialog.error = None;
        app.active_popup = None;
        app.record_action("filter_applied", "(no methods selected)", "", "ok", "");
        return;
    }

    // Parse the DSL first. Regex-escaped dialog text cannot fail it, but a
    // Header field whose name is not a header name does, and so does a
    // hand-built expression; either keeps the dialog open with the error.
    let filter = match &expr_text {
        Some(text) => match FilterExpr::parse(text) {
            Ok(expr) => Some(expr),
            Err(e) => {
                app.filter_dialog.error = Some(format!("Filter error: {e}"));
                return;
            }
        },
        None => None,
    };

    // Nothing at all — no DSL and no time bound — is a true clear. A cleared
    // filter is a state change of its own: after it the operator can see and
    // export everything again, so `clear_active_filter` records it.
    if filter.is_none() && window.0.is_none() && window.1.is_none() {
        app.status_error = None;
        app.filter_dialog.error = None;
        app.clear_active_filter();
        app.active_popup = None;
        return;
    }

    // A DSL filter, a time window, or both. The window is applied beside the
    // DSL in `displayed_dialogs`, and folded into the text so the status bar
    // shows it and the displayed-list cache key covers a window change.
    app.active_filter = filter;
    app.active_time_after = window.0;
    app.active_time_before = window.1;
    app.active_filter_text = describe_filter(expr_text.as_deref(), window);
    app.status_error = None;
    app.filter_dialog.error = None;
    // The applied filter IS recorded, unlike the search query -- see
    // `crate::tui::action_trail` for why the two are not the same question. A
    // filter decides what the operator could see and therefore export; a search
    // only moves a cursor inside what is already on screen.
    let applied = app.active_filter_text.clone();
    app.record_action("filter_applied", &applied, "", "ok", "");
    app.active_popup = None;
}

/// Handle keys in the filter dialog popup.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (this popup has no keymap
///   bindings); Shift-Tab and arrow keys move focus, Space toggles
///   checkboxes or presses the focused button, and text-editing keys
///   apply only while a text field is focused.
///
/// # Side effects
/// Esc (or Enter/Space on Cancel) closes the popup without applying.
/// Enter elsewhere (or Space on Filter) applies the dialog via
/// `apply_filter_dialog`. F9 clears the dialog fields, the active filter,
/// and the status line, then closes. Focus and checkbox keys mutate
/// `app.filter_dialog` focus/checkbox state; editing keys mutate the
/// focused text field and `cursor_pos`.
pub(in crate::tui) fn handle_filter_popup_key(app: &mut App, key: KeyEvent) {
    let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);

    match key.code {
        KeyCode::Esc => {
            // Cancel without applying
            app.active_popup = None;
        }
        KeyCode::Enter => {
            if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX {
                // Cancel button
                app.active_popup = None;
            } else {
                // Apply filter (from Filter button or any other field)
                apply_filter_dialog(app);
            }
        }
        KeyCode::Tab => {
            if is_shift {
                app.filter_dialog.focus_prev();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::BackTab => {
            app.filter_dialog.focus_prev();
        }
        KeyCode::Down => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_down();
            } else {
                app.filter_dialog.focus_next();
            }
        }
        KeyCode::Up => {
            if app.filter_dialog.is_checkbox_focused() {
                app.filter_dialog.checkbox_up();
            } else {
                app.filter_dialog.focus_prev();
            }
        }
        KeyCode::Right if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_right();
        }
        KeyCode::Left if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.checkbox_left();
        }
        KeyCode::F(9) => {
            // F9 clears all fields and the active filter, closes popup
            app.filter_dialog.clear();
            app.status_error = None;
            app.active_popup = None;
            app.clear_active_filter();
        }
        KeyCode::Char(' ') if app.filter_dialog.is_checkbox_focused() => {
            app.filter_dialog.toggle_checkbox();
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == FILTER_BUTTON_IDX => {
            apply_filter_dialog(app);
        }
        KeyCode::Char(' ') if app.filter_dialog.focused_field == CANCEL_BUTTON_IDX => {
            app.active_popup = None;
        }
        // Text editing (only when a text field is focused)
        KeyCode::Backspace if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if cursor > 0
                && let Some(field) = app.filter_dialog.text_field_mut(idx)
            {
                // Remove the whole (possibly multibyte) char before the cursor.
                let prev = field[..cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                field.remove(prev);
                app.filter_dialog.cursor_pos = prev;
            }
        }
        KeyCode::Delete if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx)
                && cursor < field.len()
            {
                field.remove(cursor);
            }
        }
        KeyCode::Left if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            let field = app.filter_dialog.text_field(idx);
            // Step back one whole char, not one byte.
            app.filter_dialog.cursor_pos = field[..cursor.min(field.len())]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
        KeyCode::Right if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            let field = app.filter_dialog.text_field(idx);
            // Step forward by the width of the char under the cursor.
            if let Some(c) = field[cursor.min(field.len())..].chars().next() {
                app.filter_dialog.cursor_pos = cursor + c.len_utf8();
            }
        }
        KeyCode::Home if app.filter_dialog.is_text_field_focused() => {
            app.filter_dialog.cursor_pos = 0;
        }
        KeyCode::End if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            app.filter_dialog.cursor_pos = app.filter_dialog.text_field(idx).len();
        }
        KeyCode::Char(c) if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let cursor = app.filter_dialog.cursor_pos;
            if let Some(field) = app.filter_dialog.text_field_mut(idx) {
                field.insert(cursor, c);
                app.filter_dialog.cursor_pos += c.len_utf8();
            }
        }
        _ => {}
    }
}

/// Unit tests for filter application and its inline error handling.
#[cfg(test)]
mod tests {
    use super::*;

    /// A filter expression that fails to parse must keep the dialog open
    /// with an inline error (mirroring the file-open dialog) instead of
    /// closing and discarding the user's typed values.
    #[test]
    fn invalid_filter_expression_keeps_dialog_open_with_inline_error() {
        let mut app = App::new_test();
        app.filter_dialog.sip_from = "alice".to_string();
        app.active_popup = Some(Popup::FilterDialog);

        // Unquoted value — the classic DSL parse error.
        apply_filter_expression(&mut app, Some("method == INVITE".to_string()), (None, None));

        assert!(
            matches!(app.active_popup, Some(Popup::FilterDialog)),
            "dialog must stay open on a parse error"
        );
        assert!(
            app.filter_dialog
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Filter error"),
            "inline error expected, got: {:?}",
            app.filter_dialog.error
        );
        assert_eq!(
            app.filter_dialog.sip_from, "alice",
            "typed input must be preserved"
        );

        // Fixing the expression applies, clears the error, and closes.
        apply_filter_expression(
            &mut app,
            Some("method == 'INVITE'".to_string()),
            (None, None),
        );
        assert!(app.active_popup.is_none(), "valid filter closes the dialog");
        assert!(app.filter_dialog.error.is_none());
        assert!(app.active_filter.is_some());
    }

    /// The time bounds parse through `apply_filter_dialog`: a malformed
    /// timestamp keeps the dialog open with an inline error naming the field
    /// and applies nothing, while a good pair sets the active window and closes
    /// — even with no DSL filter, since the DSL has no wall-clock field.
    #[test]
    fn apply_filter_dialog_applies_a_time_window_and_flags_a_bad_one() {
        let at =
            |h: u32| chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 7, 7, h, 0, 0).unwrap();
        let mut app = App::new_test();
        app.active_popup = Some(Popup::FilterDialog);

        // A malformed upper bound: the dialog stays open, nothing is applied.
        app.filter_dialog.time_after = "2026-07-07T08:00:00Z".to_string();
        app.filter_dialog.time_before = "not a timestamp".to_string();
        apply_filter_dialog(&mut app);
        assert!(
            matches!(app.active_popup, Some(Popup::FilterDialog)),
            "a bad timestamp keeps the dialog open"
        );
        assert!(
            app.filter_dialog
                .error
                .as_deref()
                .unwrap_or("")
                .contains("Before"),
            "the error names the offending field: {:?}",
            app.filter_dialog.error
        );
        assert!(
            app.active_time_after.is_none() && app.active_time_before.is_none(),
            "nothing is applied while a bound is malformed"
        );

        // Fix the upper bound: the window applies and the dialog closes, with
        // no DSL filter — only a window.
        app.filter_dialog.time_before = "2026-07-07T09:00:00Z".to_string();
        apply_filter_dialog(&mut app);
        assert!(
            app.active_popup.is_none(),
            "a valid window closes the dialog"
        );
        assert!(app.filter_dialog.error.is_none());
        assert_eq!(app.active_time_after, Some(at(8)));
        assert_eq!(app.active_time_before, Some(at(9)));
        assert!(
            app.active_filter.is_none(),
            "no DSL filter was set, only a window"
        );
        assert!(
            app.active_filter_text.contains("after") && app.active_filter_text.contains("before"),
            "the status text names the window: {}",
            app.active_filter_text
        );
    }
}

/// Tests for the dialog's focus order after the "All" checkbox was moved
/// above the method grid.
#[cfg(test)]
mod all_checkbox_order_tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// Build an unmodified `KeyEvent` for `code`.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Reset the filter dialog to defaults and open it as the active popup.
    fn open_filter(app: &mut App) {
        app.filter_dialog = FilterDialogState::default();
        app.active_popup = Some(Popup::FilterDialog);
    }

    /// Typing, arrowing over, and deleting multibyte characters keeps the
    /// cursor on char boundaries — no mid-character `String::insert`/`remove`
    /// panics.
    #[test]
    fn multibyte_text_editing_is_char_boundary_safe() {
        let mut app = App::new_test();
        open_filter(&mut app);

        handle_filter_popup_key(&mut app, key(KeyCode::Char('é')));
        handle_filter_popup_key(&mut app, key(KeyCode::Char('x')));
        assert_eq!(app.filter_dialog.text_field(0), "éx");

        handle_filter_popup_key(&mut app, key(KeyCode::Left)); // before 'x'
        handle_filter_popup_key(&mut app, key(KeyCode::Left)); // before 'é'
        assert_eq!(app.filter_dialog.cursor_pos, 0);
        handle_filter_popup_key(&mut app, key(KeyCode::Right)); // after 'é'
        assert_eq!(app.filter_dialog.cursor_pos, 'é'.len_utf8());

        handle_filter_popup_key(&mut app, key(KeyCode::Backspace)); // drop 'é'
        assert_eq!(app.filter_dialog.text_field(0), "x");
        handle_filter_popup_key(&mut app, key(KeyCode::Delete)); // drop 'x'
        assert_eq!(app.filter_dialog.text_field(0), "");
    }

    /// Tab order after the reorder: text fields → All → methods (REGISTER
    /// first) → Filter → Cancel → wrap. Space on All toggles every method.
    #[test]
    fn tab_traversal_visits_all_before_methods_and_wraps() {
        let mut app = App::new_test();
        open_filter(&mut app);
        assert_eq!(app.filter_dialog.focused_field, 0);

        // Tab through the text fields lands on the All checkbox.
        for _ in 0..FILTER_TEXT_FIELD_COUNT {
            handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        }
        assert_eq!(
            app.filter_dialog.focused_field, ALL_METHODS_IDX,
            "All comes right after the text fields"
        );

        // Space on All (from all-checked) unchecks every method.
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(
            app.filter_dialog.methods.iter().all(|&m| !m),
            "All toggles every method"
        );

        // Next Tab enters the method grid at REGISTER (method 0).
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(
            app.filter_dialog.checkbox_index(),
            Some(0),
            "REGISTER is the first method after All"
        );

        // Tab across the 10 methods reaches Filter, then Cancel, then wraps.
        for _ in 0..10 {
            handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        }
        assert_eq!(app.filter_dialog.focused_field, FILTER_BUTTON_IDX);
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.filter_dialog.focused_field, CANCEL_BUTTON_IDX);
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(
            app.filter_dialog.focused_field, 0,
            "wraps to the first field"
        );

        // Shift-Tab walks backward to Cancel.
        handle_filter_popup_key(&mut app, key(KeyCode::BackTab));
        assert_eq!(app.filter_dialog.focused_field, CANCEL_BUTTON_IDX);
    }

    /// Arrow navigation through the reordered rows: Down from All lands on
    /// REGISTER; Up from REGISTER returns to All; Down from the bottom-right
    /// method reaches the buttons; Up from All returns to the text fields.
    #[test]
    fn arrow_navigation_respects_all_above_methods() {
        let mut app = App::new_test();
        open_filter(&mut app);
        app.filter_dialog.focused_field = ALL_METHODS_IDX;

        handle_filter_popup_key(&mut app, key(KeyCode::Down));
        assert_eq!(
            app.filter_dialog.checkbox_index(),
            Some(0),
            "Down from All lands on REGISTER"
        );

        handle_filter_popup_key(&mut app, key(KeyCode::Up));
        assert_eq!(
            app.filter_dialog.focused_field, ALL_METHODS_IDX,
            "Up from REGISTER returns to All"
        );

        handle_filter_popup_key(&mut app, key(KeyCode::Up));
        assert!(
            app.filter_dialog.is_text_field_focused(),
            "Up from All returns to the text fields"
        );

        // Bottom-right method (odd index, last) → buttons.
        app.filter_dialog.focused_field = METHOD_CHECKBOX_BASE + FILTER_METHODS.len() - 1;
        handle_filter_popup_key(&mut app, key(KeyCode::Down));
        assert_eq!(
            app.filter_dialog.focused_field, FILTER_BUTTON_IDX,
            "Down from the bottom-right method reaches the buttons"
        );
    }

    /// Space still applies/cancels on the buttons and toggles single
    /// methods after the index reshuffle.
    #[test]
    fn space_semantics_survive_the_reorder() {
        let mut app = App::new_test();
        open_filter(&mut app);
        app.filter_dialog.focused_field = METHOD_CHECKBOX_BASE; // REGISTER
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(!app.filter_dialog.methods[0], "single method toggled");
        assert!(app.filter_dialog.methods[1], "others untouched");

        app.filter_dialog.focused_field = CANCEL_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(app.active_popup.is_none(), "Space on Cancel closes");
    }
}

/// Tests for the dialog's remaining keys: Enter/Space on the buttons, the
/// backward and vertical focus moves outside the method grid, F9, and the
/// cursor keys at the edges of a text field.
#[cfg(test)]
mod key_handling_tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// Build an unmodified `KeyEvent` for `code`.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// An app with the filter dialog open at its defaults.
    fn app_with_open_filter() -> App {
        let mut app = App::new_test();
        app.filter_dialog = FilterDialogState::default();
        app.active_popup = Some(Popup::FilterDialog);
        app
    }

    /// Enter on Cancel closes the dialog WITHOUT applying what was typed;
    /// Enter on any other element applies it and closes.
    #[test]
    fn enter_on_cancel_discards_and_enter_elsewhere_applies() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_from = "alice".to_string();
        app.filter_dialog.focused_field = CANCEL_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Enter));
        assert!(app.active_popup.is_none(), "Cancel closes");
        assert!(app.active_filter.is_none(), "Cancel applies nothing");

        app.active_popup = Some(Popup::FilterDialog);
        app.filter_dialog.focused_field = 0;
        handle_filter_popup_key(&mut app, key(KeyCode::Enter));
        assert!(app.active_popup.is_none(), "applying closes");
        assert!(app.active_filter.is_some(), "the typed From was applied");
        assert!(
            app.active_filter_text.contains("alice"),
            "status text: {}",
            app.active_filter_text
        );
    }

    /// Space on the Filter button applies, exactly as Enter does.
    #[test]
    fn space_on_the_filter_button_applies() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_to = "bob".to_string();
        app.filter_dialog.focused_field = FILTER_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(app.active_popup.is_none());
        assert!(
            app.active_filter_text.contains("bob"),
            "status text: {}",
            app.active_filter_text
        );
    }

    /// Shift-Tab (as terminals that report the modifier send it) walks focus
    /// backward like BackTab, and landing on a text field puts the cursor at
    /// the end of its text.
    #[test]
    fn shift_tab_walks_focus_backward_and_parks_the_cursor_at_the_end() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_from = "abc".to_string();
        app.filter_dialog.focused_field = 2;
        handle_filter_popup_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
        assert_eq!(app.filter_dialog.focused_field, 1, "Shift-Tab goes back");
        handle_filter_popup_key(&mut app, key(KeyCode::BackTab));
        assert_eq!(app.filter_dialog.focused_field, 0);
        assert_eq!(app.filter_dialog.cursor_pos, 3, "cursor at end of 'abc'");
    }

    /// Outside the method grid, Down and Up move focus to the next and
    /// previous element rather than navigating checkboxes.
    #[test]
    fn arrows_outside_the_method_grid_move_between_fields() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_to = "xy".to_string();
        handle_filter_popup_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.filter_dialog.focused_field, 1);
        assert_eq!(app.filter_dialog.cursor_pos, 2, "cursor at end of 'xy'");
        handle_filter_popup_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.filter_dialog.focused_field, 0);

        app.filter_dialog.focused_field = FILTER_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.filter_dialog.focused_field, CANCEL_BUTTON_IDX);
        handle_filter_popup_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.filter_dialog.focused_field, FILTER_BUTTON_IDX);
    }

    /// F9 empties every field, re-checks every method, drops the active
    /// filter and the status error, and closes the dialog.
    #[test]
    fn f9_clears_the_fields_and_the_active_filter_and_closes() {
        let mut app = app_with_open_filter();
        app.filter_dialog.payload = "needle".to_string();
        app.filter_dialog.methods[0] = false;
        apply_filter_dialog(&mut app);
        assert!(app.active_filter.is_some(), "precondition: a filter is on");

        app.active_popup = Some(Popup::FilterDialog);
        app.status_error = Some("stale".to_string());
        handle_filter_popup_key(&mut app, key(KeyCode::F(9)));
        assert!(app.active_popup.is_none(), "F9 closes");
        assert!(app.status_error.is_none(), "F9 clears the status line");
        assert!(app.active_filter.is_none(), "F9 drops the filter");
        assert!(app.active_filter_text.is_empty());
        assert_eq!(app.filter_dialog.payload, "", "fields emptied");
        assert!(
            app.filter_dialog.methods.iter().all(|&m| m),
            "every method re-checked"
        );
    }

    /// Home and End jump to the ends of the focused text field, and typing
    /// inserts at the cursor rather than appending.
    #[test]
    fn home_and_end_jump_within_the_field_and_typing_inserts_at_the_cursor() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_from = "hello".to_string();
        app.filter_dialog.cursor_pos = 2;
        handle_filter_popup_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.filter_dialog.cursor_pos, 0);
        handle_filter_popup_key(&mut app, key(KeyCode::Char('X')));
        assert_eq!(app.filter_dialog.sip_from, "Xhello");
        assert_eq!(app.filter_dialog.cursor_pos, 1);
        handle_filter_popup_key(&mut app, key(KeyCode::End));
        assert_eq!(app.filter_dialog.cursor_pos, "Xhello".len());
    }

    /// At the edges of a field, Backspace at the start, Delete and Right at
    /// the end change nothing; a key the dialog does not bind changes
    /// nothing; and text keys on a button type nowhere.
    #[test]
    fn edits_past_the_field_edges_and_text_keys_on_a_button_are_no_ops() {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_from = "ab".to_string();
        app.filter_dialog.cursor_pos = 0;
        handle_filter_popup_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.filter_dialog.sip_from, "ab");
        assert_eq!(app.filter_dialog.cursor_pos, 0);

        app.filter_dialog.cursor_pos = 2;
        handle_filter_popup_key(&mut app, key(KeyCode::Delete));
        handle_filter_popup_key(&mut app, key(KeyCode::Right));
        assert_eq!(app.filter_dialog.sip_from, "ab");
        assert_eq!(app.filter_dialog.cursor_pos, 2);

        handle_filter_popup_key(&mut app, key(KeyCode::F(3)));
        assert_eq!(app.filter_dialog.sip_from, "ab");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog));

        app.filter_dialog.focused_field = FILTER_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Char('z')));
        handle_filter_popup_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(app.filter_dialog.sip_from, "ab", "a button is not a field");
        assert_eq!(app.filter_dialog.focused_field, FILTER_BUTTON_IDX);
        assert_eq!(app.active_popup, Some(Popup::FilterDialog));
    }
}
