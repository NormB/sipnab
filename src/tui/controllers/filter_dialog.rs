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
    let expr_text = app.filter_dialog.build_filter_expression();
    apply_filter_expression(app, expr_text);
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
pub(in crate::tui) fn apply_filter_expression(app: &mut App, expr_text: Option<String>) {
    // No SIP methods selected => show nothing. This is the explicit "mute
    // everything" state (distinct from all-checked, which shows everything).
    if !app.filter_dialog.any_method_checked() {
        app.active_filter = Some(FilterExpr::never());
        app.active_filter_text = "(no methods selected)".to_string();
        app.status_error = None;
        app.filter_dialog.error = None;
        app.active_popup = None;
        return;
    }
    match expr_text {
        Some(expr_text) => match FilterExpr::parse(&expr_text) {
            Ok(expr) => {
                app.active_filter = Some(expr);
                app.active_filter_text = expr_text;
                app.status_error = None;
                app.filter_dialog.error = None;
            }
            Err(e) => {
                app.filter_dialog.error = Some(format!("Filter error: {e}"));
                return;
            }
        },
        None => {
            // All fields empty — clear any active filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
            app.filter_dialog.error = None;
        }
    }
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
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
            app.active_popup = None;
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
                field.remove(cursor - 1);
                app.filter_dialog.cursor_pos -= 1;
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
            app.filter_dialog.cursor_pos = app.filter_dialog.cursor_pos.saturating_sub(1);
        }
        KeyCode::Right if app.filter_dialog.is_text_field_focused() => {
            let idx = app.filter_dialog.focused_field;
            let len = app.filter_dialog.text_field(idx).len();
            if app.filter_dialog.cursor_pos < len {
                app.filter_dialog.cursor_pos += 1;
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
                app.filter_dialog.cursor_pos += 1;
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
        apply_filter_expression(&mut app, Some("method == INVITE".to_string()));

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
        apply_filter_expression(&mut app, Some("method == 'INVITE'".to_string()));
        assert!(app.active_popup.is_none(), "valid filter closes the dialog");
        assert!(app.filter_dialog.error.is_none());
        assert!(app.active_filter.is_some());
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

    /// Tab order after the reorder: text fields → All → methods (REGISTER
    /// first) → Filter → Cancel → wrap. Space on All toggles every method.
    #[test]
    fn tab_traversal_visits_all_before_methods_and_wraps() {
        let mut app = App::new_test();
        open_filter(&mut app);
        assert_eq!(app.filter_dialog.focused_field, 0);

        // Tab through the 5 text fields lands on the All checkbox.
        for _ in 0..5 {
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
