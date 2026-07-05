//! The structured filter dialog popup.

use crate::tui::*;

/// Apply the filter dialog state: build a DSL expression, parse it, and set the active filter.
pub(in crate::tui) fn apply_filter_dialog(app: &mut App) {
    // No SIP methods selected => show nothing. This is the explicit "mute
    // everything" state (distinct from all-checked, which shows everything).
    if !app.filter_dialog.any_method_checked() {
        app.active_filter = Some(FilterExpr::never());
        app.active_filter_text = "(no methods selected)".to_string();
        app.status_error = None;
        app.active_popup = None;
        return;
    }
    match app.filter_dialog.build_filter_expression() {
        Some(expr_text) => match FilterExpr::parse(&expr_text) {
            Ok(expr) => {
                app.active_filter = Some(expr);
                app.active_filter_text = expr_text;
                app.status_error = None;
            }
            Err(e) => {
                app.status_error = Some(format!("Filter error: {e}"));
            }
        },
        None => {
            // All fields empty — clear any active filter
            app.active_filter = None;
            app.active_filter_text.clear();
            app.status_error = None;
        }
    }
    app.active_popup = None;
}

/// Handle keys in the filter dialog popup.
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
