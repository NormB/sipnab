// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The structured filter dialog popup.

use crate::tui::{
    App, CANCEL_BUTTON_IDX, EXPRESSION_FIELD_IDX, FILTER_BUTTON_IDX, FilterExpr, KeyCode, KeyEvent,
    KeyModifiers,
};

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
    // The Expression field is checked on its own first, so its error names
    // the field and its position is a place in the text the operator typed,
    // not in the expression the whole dialog builds.
    let typed = match resolve_expression_field(
        &app.filter_dialog.expression,
        &app.named_filters,
        &app.alias_thresholds,
    ) {
        Ok(typed) => typed,
        Err(refusal) => {
            refuse_expression(app, refusal);
            return;
        }
    };
    let expr_text = and_typed_expression(app.filter_dialog.build_filter_expression(), typed);
    apply_filter_expression(app, expr_text, window);
    // Applied: the filter now in force is the dialog's, so status line 3 may
    // show it as the dialog's summary. Refused: the dialog stays open with its
    // error, and the filter in force keeps its own summary.
    if app.filter_dialog.error.is_none() {
        app.active_filter_summary = app.filter_dialog.summary();
        // Applied, so it parsed: the Expression, as typed, joins the history
        // Up recalls. A blank field records nothing.
        let typed = app.filter_dialog.expression.clone();
        app.expression_history.record(&typed);
    }
}

/// Why the Expression field was refused.
#[derive(Debug)]
struct ExpressionRefusal {
    /// The line for the dialog: the field's name and the message of the rule
    /// that refused it, the parser's own when the parser did.
    message: String,
    /// Byte offset in the field where the parser stopped, when that place is
    /// in the text as typed; `None` when it is not (an error inside an
    /// `@name` expansion) or the refusal has no place.
    cursor: Option<usize>,
}

/// The Expression field resolved and checked the way `--filter` is.
///
/// # Returns
/// `Ok(None)` for a blank field; `Ok(Some(text))` with the resolved text
/// (`@name` references and a whole-text alias expanded) when it parses.
///
/// # Errors
/// An [`ExpressionRefusal`] for an undefined `@name` or a parse error.
fn resolve_expression_field(
    field: &str,
    filters: &crate::sip::named_filters::NamedFilters,
    thresholds: &crate::sip::dsl::AliasThresholds,
) -> Result<Option<String>, ExpressionRefusal> {
    let typed = field.trim();
    if typed.is_empty() {
        return Ok(None);
    }
    let refused = |message: String, cursor| ExpressionRefusal {
        message: format!("Expression error: {message}"),
        cursor,
    };
    let resolved = crate::sip::dsl::resolve_typed_filter(typed, filters, thresholds)
        .map_err(|m| refused(m, None))?;
    match FilterExpr::parse(&resolved) {
        Ok(_) => Ok(Some(resolved)),
        Err(e) => {
            // The parser's offset is into the text it read, so it is a place
            // in the field only when nothing was expanded.
            let leading = field.len() - field.trim_start().len();
            let cursor = e
                .downcast_ref::<crate::sip::dsl::SyntaxError>()
                .filter(|_| resolved == typed)
                .map(|s| leading + s.offset());
            Err(refused(e.to_string(), cursor))
        }
    }
}

/// Keep the dialog open on a refused Expression: the message shown, the
/// focus on the field, and the cursor where the parser stopped when that is
/// known. The filter in force is not touched.
fn refuse_expression(app: &mut App, refusal: ExpressionRefusal) {
    let dialog = &mut app.filter_dialog;
    if dialog.focused_field != EXPRESSION_FIELD_IDX {
        dialog.focused_field = EXPRESSION_FIELD_IDX;
        dialog.sync_cursor();
    }
    if let Some(cursor) = refusal.cursor {
        dialog.cursor_pos = cursor;
    }
    dialog.error = Some(refusal.message);
}

/// The dialog's own expression ANDed with the typed one.
///
/// The typed text is grouped, so an `OR` in it stays inside it: the dialog's
/// fields narrow the whole expression, not only its last term. Alone, it is
/// applied as typed.
fn and_typed_expression(dialog: Option<String>, typed: Option<String>) -> Option<String> {
    match (dialog, typed) {
        (Some(dialog), Some(typed)) => Some(format!("{dialog} AND ({typed})")),
        (dialog, None) => dialog,
        (None, typed) => typed,
    }
}

/// Open the filter dialog, from any view: focus on the first field, no error
/// shown, the run's `[filters]` names listed beside Named filter, the field
/// help off and no history recall under way. The fields keep what they held.
pub(in crate::tui) fn open_filter_dialog(app: &mut App) {
    app.filter_dialog.focused_field = 0;
    app.filter_dialog.sync_cursor();
    app.filter_dialog.error = None;
    app.filter_dialog.save_name = None;
    app.filter_dialog.notice = None;
    app.filter_dialog.session_note = None;
    app.filter_dialog.known_names = app.named_filters.names().map(str::to_owned).collect();
    app.filter_dialog.show_help = false;
    app.expression_history.end_walk();
    app.active_popup = Some(crate::tui::Popup::FilterDialog);
}

/// The text `F2` saves as a named filter: the dialog's own fields ANDed with
/// the Expression field as typed, `@name` references kept, so a saved entry
/// follows the entries it names. A built-in alias typed as the whole
/// Expression is saved as `@alias`, the form a `[filters]` entry reads.
///
/// # Errors
/// A sentence for the dialog when there is nothing a `[filters]` entry can
/// hold: no SIP method checked, a time window set (an entry is an
/// expression only), or every field empty.
fn expression_to_save(
    dialog: &crate::tui::state::FilterDialogState,
    thresholds: &crate::sip::dsl::AliasThresholds,
) -> Result<String, String> {
    if !dialog.any_method_checked() {
        return Err("Nothing to save: no SIP method is checked".to_owned());
    }
    if !dialog.time_after.trim().is_empty() || !dialog.time_before.trim().is_empty() {
        return Err(
            "A named filter holds no time window: clear After and Before to save".to_owned(),
        );
    }
    let typed = dialog.expression.trim();
    let typed = (!typed.is_empty()).then(|| {
        if crate::sip::dsl::expand_alias(typed, thresholds).is_some() {
            format!("@{typed}")
        } else {
            typed.to_owned()
        }
    });
    and_typed_expression(dialog.build_filter_expression(), typed)
        .ok_or_else(|| "Nothing to save: every field is empty".to_owned())
}

/// `F2`: open the "Save as" prompt, or show why the dialog's filter cannot
/// be saved.
fn start_save_prompt(app: &mut App) {
    app.filter_dialog.notice = None;
    app.filter_dialog.session_note = None;
    match expression_to_save(&app.filter_dialog, &app.alias_thresholds) {
        Ok(_) => {
            app.filter_dialog.error = None;
            app.filter_dialog.save_name = Some(String::new());
        }
        Err(why) => app.filter_dialog.error = Some(why),
    }
}

/// Where an `F2` save put the name.
#[derive(Debug)]
enum Saved {
    /// Written to this config file.
    File(std::path::PathBuf),
    /// In the run's table only: no config file may be written.
    Session(crate::tui::state::SessionNote),
}

/// Save the dialog's filter under `typed` (one leading `@` and surrounding
/// spaces dropped): the new table is built and checked first, then the
/// config file is written, and only then does the run's table change.
///
/// When no file may be written (no save target, or a permission failure
/// at any step), the name still goes into the run's table, for this
/// session only, and the note says why and what line to add to a file.
///
/// # Returns
/// The name saved and where it went.
///
/// # Errors
/// The reason, for the dialog: the filter cannot be saved, the name is not
/// usable or already defined (in the run or in the file), the expression
/// does not resolve or parse, the file is not valid TOML or its `[filters]`
/// is not a table, or the file cannot be read or written for a reason that
/// is not permission. Nothing changes on an error.
fn save_named_filter(app: &mut App, typed: &str) -> Result<(String, Saved), String> {
    let name = typed.trim();
    let name = name.strip_prefix('@').unwrap_or(name);
    let expr = expression_to_save(&app.filter_dialog, &app.alias_thresholds)?;
    let table = app
        .named_filters
        .with_added(name, &expr, &app.alias_thresholds)
        .map_err(|e| e.to_string())?;
    let saved = match app.column_config_path.clone() {
        Err(why) => Saved::Session(session_note(name, &expr, &[capitalized(&why)])?),
        Ok(path) => match crate::config::write_named_filter_file(&path, name, &expr) {
            Ok(()) => Saved::File(path),
            Err(crate::Error::ConfigUnwritable {
                action,
                path,
                source,
            }) => {
                let mut why = vec![format!("Not saved: cannot {action} {path}: {source}.")];
                if action == "read" {
                    why.push(
                        "An entry of the same name in that file could not be checked.".to_owned(),
                    );
                }
                Saved::Session(session_note(name, &expr, &why)?)
            }
            Err(e) => return Err(format!("Save failed: {e}")),
        },
    };
    if let Some(publish) = app.filter_publisher {
        publish(table.clone());
    }
    app.named_filters = table;
    app.filter_dialog.known_names = app.named_filters.names().map(str::to_owned).collect();
    Ok((name.to_owned(), saved))
}

/// `text` with its first letter in upper case, for a reason that starts a
/// line.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// The note for `name` kept for this session only: what happened, `why`,
/// what to do, and the `[filters]` entry to add.
///
/// # Errors
/// The entry line cannot be built (see
/// [`crate::config::named_filter_entry_line`]).
fn session_note(
    name: &str,
    definition: &str,
    why: &[String],
) -> Result<crate::tui::state::SessionNote, String> {
    let entry =
        crate::config::named_filter_entry_line(name, definition).map_err(|e| e.to_string())?;
    let mut lines = vec![format!(
        "Kept @{name} for this session only: it is in no config file."
    )];
    lines.extend(why.iter().cloned());
    lines.push(format!(
        "{}, and add this entry to that file:",
        crate::config::SAVE_ADVICE
    ));
    lines.push("[filters]".to_owned());
    lines.extend(entry.lines().map(str::to_owned));
    Ok(crate::tui::state::SessionNote { lines, entry })
}

/// `F3` with a session-only note shown: copy its `[filters]` entry line,
/// with `copy` doing the copy (tests pass one that never reaches a
/// clipboard). Without a note, nothing happens.
fn copy_session_entry_with(app: &mut App, copy: fn(&str) -> crate::tui::StatusMessage) {
    let Some(note) = app.filter_dialog.session_note.as_ref() else {
        return;
    };
    crate::tui::clipboard::spawn_copy_worker(
        note.entry.clone(),
        std::sync::Arc::clone(&app.async_messages),
        copy,
    );
    app.status_error = Some("Copying the [filters] entry to the clipboard\u{2026}".to_owned());
}

/// The notice a save into a file shows: the name and the file, the file
/// under `home` (the `$HOME` value) written from `~`.
fn saved_notice(name: &str, path: &std::path::Path, home: Option<&std::ffi::OsStr>) -> String {
    format!("Saved @{name} to {}", home_relative(path, home))
}

/// `path` for display, with `home` written as `~` when `path` is inside it
/// (whole components, so `/home/ex` is not a prefix of `/home/example`).
/// A home that is empty, relative or `/` is not used: `~` would hide where
/// the file is rather than shorten it.
fn home_relative(path: &std::path::Path, home: Option<&std::ffi::OsStr>) -> String {
    let home = home
        .map(std::path::Path::new)
        .filter(|home| home.is_absolute() && home.components().ne([std::path::Component::RootDir]));
    match home.and_then(|home| path.strip_prefix(home).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Some(rest) => format!("~/{}", rest.display()),
        None => path.display().to_string(),
    }
}

/// Keys while the "Save as" prompt is open: text edits the name, Enter
/// saves, Esc closes the prompt; every other key waits.
fn handle_save_prompt_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.filter_dialog.save_name = None;
            app.filter_dialog.error = None;
        }
        KeyCode::Enter => {
            let typed = app.filter_dialog.save_name.clone().unwrap_or_default();
            match save_named_filter(app, &typed) {
                Ok((name, saved)) => {
                    app.filter_dialog.save_name = None;
                    app.filter_dialog.error = None;
                    match saved {
                        Saved::File(path) => {
                            app.filter_dialog.notice = Some(saved_notice(
                                &name,
                                &path,
                                std::env::var_os("HOME").as_deref(),
                            ));
                        }
                        Saved::Session(note) => app.filter_dialog.session_note = Some(note),
                    }
                }
                Err(why) => app.filter_dialog.error = Some(why),
            }
        }
        KeyCode::Backspace => {
            if let Some(name) = app.filter_dialog.save_name.as_mut() {
                name.pop();
            }
        }
        KeyCode::Char(c) => {
            if let Some(name) = app.filter_dialog.save_name.as_mut() {
                name.push(c);
            }
        }
        _ => {}
    }
}

/// Up in the Expression field: the next older applied expression into the
/// field, the cursor at its end.
///
/// # Returns
/// `false`, changing nothing, when another field has focus or there is no
/// older expression; Up then moves focus as in every other field.
fn recall_older(app: &mut App) -> bool {
    if app.filter_dialog.focused_field != EXPRESSION_FIELD_IDX {
        return false;
    }
    let Some(text) = app
        .expression_history
        .older(&app.filter_dialog.expression)
        .map(str::to_owned)
    else {
        return false;
    };
    show_recalled(app, text);
    true
}

/// Down in the Expression field during a recall: the next newer expression,
/// or past the newest the text the field held before the recall.
///
/// # Returns
/// `false`, changing nothing, when another field has focus or no recall is
/// under way; Down then moves focus as in every other field.
fn recall_newer(app: &mut App) -> bool {
    if app.filter_dialog.focused_field != EXPRESSION_FIELD_IDX {
        return false;
    }
    let Some(text) = app.expression_history.newer() else {
        return false;
    };
    show_recalled(app, text);
    true
}

/// End a history recall on every key but Up/Down and the cursor moves: from
/// then on the field's text, edited or not, is the text Down returns to.
fn end_recall_on_other_keys(app: &mut App, code: KeyCode) {
    if !matches!(
        code,
        KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right | KeyCode::Home | KeyCode::End
    ) {
        app.expression_history.end_walk();
    }
}

/// Down in the dialog: the next method box in the grid; in the Expression
/// field during a recall, the next newer expression; else the next field,
/// which ends any recall.
fn arrow_down(app: &mut App) {
    if app.filter_dialog.is_checkbox_focused() {
        app.filter_dialog.checkbox_down();
    } else if !recall_newer(app) {
        app.expression_history.end_walk();
        app.filter_dialog.focus_next();
    }
}

/// Up in the dialog: the previous method box in the grid; in the Expression
/// field, the next older applied expression; else the previous field, which
/// ends any recall.
fn arrow_up(app: &mut App) {
    if app.filter_dialog.is_checkbox_focused() {
        app.filter_dialog.checkbox_up();
    } else if !recall_older(app) {
        app.expression_history.end_walk();
        app.filter_dialog.focus_prev();
    }
}

/// Put `text` in the Expression field with the cursor at its end. The field
/// holds a copy: editing it never changes the history.
fn show_recalled(app: &mut App, text: String) {
    app.filter_dialog.expression = text;
    app.filter_dialog.cursor_pos = app.filter_dialog.expression.len();
}

/// Start the session the way `-c` / `--calls-only` asks: only INVITE checked
/// in the filter dialog, and that filter applied, so the call list shows
/// calls and the operator can open the dialog (`F7`/`f`) to change it.
///
/// The same path as the dialog's Apply, so the status bar, the displayed
/// list and the action trail read exactly as if the boxes had been ticked by
/// hand (#474).
pub(crate) fn start_calls_only(app: &mut App) {
    app.filter_dialog.methods = crate::tui::state::FILTER_METHODS.map(|m| m == "INVITE");
    apply_filter_dialog(app);
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

/// `text` with each `@name` expanded through the app's `[filters]` table, or
/// the message for a name nothing defines.
fn resolve_dialog_text(app: &App, text: &str) -> Result<String, String> {
    let resolved =
        crate::sip::dsl::resolve_references(text, &app.named_filters, &app.alias_thresholds);
    if let Some(name) = crate::sip::named_filters::first_reference(&resolved) {
        return Err(crate::sip::named_filters::unknown_reference_message(
            name,
            &app.named_filters,
        ));
    }
    Ok(resolved.into_owned())
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
/// `app.status_error` and `app.active_filter_summary` on every path that
/// applies.
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
        app.active_filter_summary = None;
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
    // `@name` resolves through the app's `[filters]` table and the run's
    // alias thresholds, the rule every other surface applies.
    let filter = match &expr_text {
        Some(text) => match resolve_dialog_text(app, text)
            .and_then(|t| FilterExpr::parse(&t).map_err(|e| e.to_string()))
        {
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
    // An expression applied here is shown as it is; only the dialog, which
    // knows its own selections, attaches a summary afterwards.
    app.active_filter_summary = None;
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
/// Esc (or Enter/Space on Cancel) closes the popup without applying; with
/// the field help shown, Esc hides the help first. F1 shows or hides the
/// field help. F2 opens the "Save as" prompt, which takes every key until
/// Enter saves or Esc closes it (see [`handle_save_prompt_key`]). In the
/// Expression field, Up and Down walk the expression history before they
/// move focus.
/// Enter elsewhere (or Space on Filter) applies the dialog via
/// `apply_filter_dialog`. F9 clears the dialog fields, the active filter,
/// and the status line, then closes. Focus and checkbox keys mutate
/// `app.filter_dialog` focus/checkbox state; editing keys mutate the
/// focused text field and `cursor_pos`.
pub(in crate::tui) fn handle_filter_popup_key(app: &mut App, key: KeyEvent) {
    if app.filter_dialog.save_name.is_some() {
        handle_save_prompt_key(app, key.code);
        return;
    }
    let is_shift = key.modifiers.contains(KeyModifiers::SHIFT);
    end_recall_on_other_keys(app, key.code);

    match key.code {
        KeyCode::F(2) => start_save_prompt(app),
        // The clipboard transmits, so tests drive `copy_session_entry_with`.
        KeyCode::F(3) => copy_session_entry_with(app, crate::tui::clipboard::copy_to_clipboard),
        KeyCode::Esc if app.filter_dialog.show_help => {
            // The help goes first; a second Esc cancels the dialog.
            app.filter_dialog.show_help = false;
        }
        KeyCode::Esc if app.filter_dialog.session_note.is_some() => {
            // A session-only note goes before the dialog.
            app.filter_dialog.session_note = None;
        }
        KeyCode::Esc => {
            // Cancel without applying
            app.active_popup = None;
        }
        KeyCode::F(1) => {
            app.filter_dialog.show_help = !app.filter_dialog.show_help;
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
        KeyCode::Down => arrow_down(app),
        KeyCode::Up => arrow_up(app),
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
    use crate::tui::Popup;

    type TestError = Box<dyn std::error::Error>;

    /// `-c` / `--calls-only` opens the TUI with only INVITE checked in the
    /// filter dialog and that filter applied, so the call list shows calls
    /// and the operator can see and change the choice (#474).
    #[test]
    fn calls_only_start_checks_only_invite_and_lists_only_calls() -> Result<(), TestError> {
        use crate::tui::controllers::test_support::{base_ts, make_invite, make_request};
        let mut app = App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", base_ts())?,
            make_request("OPTIONS", "ping-1@test", "probe", "proxy", base_ts())?,
            make_request("REGISTER", "reg-1@test", "1003", "1003", base_ts())?,
        ]);
        app.sync_caches();
        assert_eq!(app.cached_displayed_count, 3, "every dialog before -c");

        start_calls_only(&mut app);
        app.sync_caches();
        let checked: Vec<&str> = crate::tui::state::FILTER_METHODS
            .iter()
            .zip(app.filter_dialog.methods.iter())
            .filter(|(_, on)| **on)
            .map(|(m, _)| *m)
            .collect();
        assert_eq!(checked, vec!["INVITE"]);
        assert_eq!(app.cached_displayed_count, 1, "only the call is listed");
        assert!(app.active_popup.is_none(), "no dialog is left open");
        assert!(
            app.active_filter_text.contains("method == 'INVITE'"),
            "the status bar names the filter: {}",
            app.active_filter_text
        );
        Ok(())
    }

    /// A filter expression that fails to parse must keep the dialog open
    /// with an inline error (mirroring the file-open dialog) instead of
    /// closing and discarding the user's typed values.
    #[test]
    fn invalid_filter_expression_keeps_dialog_open_with_inline_error() -> Result<(), TestError> {
        let mut app = App::new_test();
        app.filter_dialog.sip_from = "alice".to_string();
        app.active_popup = Some(Popup::FilterDialog);

        // A value with a space, unquoted: a DSL parse error.
        apply_filter_expression(
            &mut app,
            Some("ua == Friendly Scanner".to_string()),
            (None, None),
        );

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
        Ok(())
    }

    /// The time bounds parse through `apply_filter_dialog`: a malformed
    /// timestamp keeps the dialog open with an inline error naming the field
    /// and applies nothing, while a good pair sets the active window and closes
    /// — even with no DSL filter, since the DSL has no wall-clock field.
    #[test]
    fn apply_filter_dialog_applies_a_time_window_and_flags_a_bad_one() -> Result<(), TestError> {
        let at = |h: u32| -> Result<chrono::DateTime<chrono::Utc>, TestError> {
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 7, 7, h, 0, 0)
                .single()
                .ok_or_else(|| format!("hour {h} is not a valid timestamp").into())
        };
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
        assert_eq!(app.active_time_after, Some(at(8)?));
        assert_eq!(app.active_time_before, Some(at(9)?));
        assert!(
            app.active_filter.is_none(),
            "no DSL filter was set, only a window"
        );
        assert!(
            app.active_filter_text.contains("after") && app.active_filter_text.contains("before"),
            "the status text names the window: {}",
            app.active_filter_text
        );
        Ok(())
    }
}

/// Tests for the dialog's focus order after the "All" checkbox was moved
/// above the method grid.
#[cfg(test)]
mod all_checkbox_order_tests {
    use super::*;
    use crate::tui::{
        ALL_METHODS_IDX, FILTER_METHODS, FILTER_TEXT_FIELD_COUNT, FilterDialogState,
        METHOD_CHECKBOX_BASE, Popup,
    };
    use crossterm::event::KeyModifiers;

    type TestError = Box<dyn std::error::Error>;

    /// Build an unmodified `KeyEvent` for `code`.
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Reset the filter dialog to defaults and open it as the active popup.
    /// A named filter in the dialog applies its expansion through the app's
    /// `[filters]` table, a built-in alias works as `@name` too, and an
    /// undefined name keeps the dialog open naming what is defined.
    #[test]
    fn a_named_filter_applies_its_expansion_and_an_undefined_one_is_refused()
    -> Result<(), TestError> {
        let mut app = App::new_test();
        let mut defs = std::collections::BTreeMap::new();
        defs.insert("sales".to_string(), "to.user == '7000'".to_string());
        app.named_filters = crate::sip::named_filters::NamedFilters::resolve(
            &defs,
            &crate::sip::dsl::AliasThresholds::default(),
        )?;
        for (text, source) in [
            ("@sales", "(to.user == '7000')"),
            ("@one-way", "(one_way == true)"),
        ] {
            app.active_popup = Some(Popup::FilterDialog);
            apply_filter_expression(&mut app, Some(text.to_string()), (None, None));
            assert_eq!(
                app.active_filter.as_ref().map(FilterExpr::source),
                Some(source),
                "{text}: {:?}",
                app.filter_dialog.error
            );
        }
        app.active_popup = Some(Popup::FilterDialog);
        apply_filter_expression(&mut app, Some("@nope".to_string()), (None, None));
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(error.contains("'@nope' is not a defined filter"), "{error}");
        assert!(error.contains("sales"), "names what is defined: {error}");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "stays open");
        Ok(())
    }

    fn open_filter(app: &mut App) {
        app.filter_dialog = FilterDialogState::default();
        app.active_popup = Some(Popup::FilterDialog);
    }

    /// Typing, arrowing over, and deleting multibyte characters keeps the
    /// cursor on char boundaries — no mid-character `String::insert`/`remove`
    /// panics.
    #[test]
    fn multibyte_text_editing_is_char_boundary_safe() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Tab order after the reorder: text fields → All → methods (REGISTER
    /// first) → Filter → Cancel → wrap. Space on All toggles every method.
    #[test]
    fn tab_traversal_visits_all_before_methods_and_wraps() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Arrow navigation through the reordered rows: Down from All lands on
    /// REGISTER; Up from REGISTER returns to All; Down from the bottom-right
    /// method reaches the buttons; Up from All returns to the text fields.
    #[test]
    fn arrow_navigation_respects_all_above_methods() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Space still applies/cancels on the buttons and toggles single
    /// methods after the index reshuffle.
    #[test]
    fn space_semantics_survive_the_reorder() -> Result<(), TestError> {
        let mut app = App::new_test();
        open_filter(&mut app);
        app.filter_dialog.focused_field = METHOD_CHECKBOX_BASE; // REGISTER
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(!app.filter_dialog.methods[0], "single method toggled");
        assert!(app.filter_dialog.methods[1], "others untouched");

        app.filter_dialog.focused_field = CANCEL_BUTTON_IDX;
        handle_filter_popup_key(&mut app, key(KeyCode::Char(' ')));
        assert!(app.active_popup.is_none(), "Space on Cancel closes");
        Ok(())
    }
}

/// Tests for the dialog's remaining keys: Enter/Space on the buttons, the
/// backward and vertical focus moves outside the method grid, F9, and the
/// cursor keys at the edges of a text field.
#[cfg(test)]
mod key_handling_tests {
    use super::*;
    use crate::tui::{FilterDialogState, Popup};
    use crossterm::event::KeyModifiers;

    type TestError = Box<dyn std::error::Error>;

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
    fn enter_on_cancel_discards_and_enter_elsewhere_applies() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Space on the Filter button applies, exactly as Enter does.
    #[test]
    fn space_on_the_filter_button_applies() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Shift-Tab (as terminals that report the modifier send it) walks focus
    /// backward like BackTab, and landing on a text field puts the cursor at
    /// the end of its text.
    #[test]
    fn shift_tab_walks_focus_backward_and_parks_the_cursor_at_the_end() -> Result<(), TestError> {
        let mut app = app_with_open_filter();
        app.filter_dialog.sip_from = "abc".to_string();
        app.filter_dialog.focused_field = 2;
        handle_filter_popup_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
        assert_eq!(app.filter_dialog.focused_field, 1, "Shift-Tab goes back");
        handle_filter_popup_key(&mut app, key(KeyCode::BackTab));
        assert_eq!(app.filter_dialog.focused_field, 0);
        assert_eq!(app.filter_dialog.cursor_pos, 3, "cursor at end of 'abc'");
        Ok(())
    }

    /// Outside the method grid, Down and Up move focus to the next and
    /// previous element rather than navigating checkboxes.
    #[test]
    fn arrows_outside_the_method_grid_move_between_fields() -> Result<(), TestError> {
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
        Ok(())
    }

    /// F9 empties every field, re-checks every method, drops the active
    /// filter and the status error, and closes the dialog.
    #[test]
    fn f9_clears_the_fields_and_the_active_filter_and_closes() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Home and End jump to the ends of the focused text field, and typing
    /// inserts at the cursor rather than appending.
    #[test]
    fn home_and_end_jump_within_the_field_and_typing_inserts_at_the_cursor() -> Result<(), TestError>
    {
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
        Ok(())
    }

    /// At the edges of a field, Backspace at the start, Delete and Right at
    /// the end change nothing; a key the dialog does not bind changes
    /// nothing; and text keys on a button type nowhere.
    #[test]
    fn edits_past_the_field_edges_and_text_keys_on_a_button_are_no_ops() -> Result<(), TestError> {
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
        Ok(())
    }
}

/// Tests for the dialog's summary: the few words status line 3 shows in place
/// of the expression the dialog built.
#[cfg(test)]
mod summary_tests {
    use super::*;
    use crate::tui::FilterDialogState;

    type TestError = Box<dyn std::error::Error>;

    /// A dialog with seven methods checked and every text field set.
    fn heavy_dialog() -> FilterDialogState {
        let mut d = FilterDialogState::default();
        // REGISTER, OPTIONS and NOTIFY off: seven of ten methods stay checked.
        d.methods[0] = false;
        d.methods[1] = false;
        d.methods[6] = false;
        d.sip_from = "alice".to_string();
        d.sip_to = "bob".to_string();
        d.source = "10.0.0.5".to_string();
        d.destination = "10.0.0.9".to_string();
        d.payload = "m=audio".to_string();
        d.header = "X-Tenant: acme".to_string();
        d.named = "@scanners".to_string();
        d.time_after = "2026-07-07T08:00:00Z".to_string();
        d
    }

    /// Each field that is set is one token, in the dialog's order, with the
    /// typed text kept as typed; the checked methods are a count.
    #[test]
    fn the_summary_names_each_selection_in_a_few_words() -> Result<(), TestError> {
        let summary = heavy_dialog()
            .summary()
            .ok_or("a set dialog has a summary")?;
        assert_eq!(
            summary,
            "7 methods, From~alice, To~bob, Src~10.0.0.5, Dst~10.0.0.9, \
             Payload~m=audio, Header~X-Tenant: acme, @scanners, \
             after 2026-07-07T08:00:00Z"
        );
        Ok(())
    }

    /// An untouched dialog narrows nothing, so it has nothing to summarize.
    #[test]
    fn an_untouched_dialog_has_no_summary() {
        assert_eq!(FilterDialogState::default().summary(), None);
    }

    /// One checked method is named, since the name is as short as a count;
    /// every method checked adds no token; none checked says so.
    #[test]
    fn the_method_token_follows_how_many_are_checked() -> Result<(), TestError> {
        let mut d = FilterDialogState {
            methods: crate::tui::state::FILTER_METHODS.map(|m| m == "INVITE"),
            ..FilterDialogState::default()
        };
        assert_eq!(d.summary().as_deref(), Some("INVITE"));
        d.methods = [false; 10];
        assert_eq!(d.summary().as_deref(), Some("no methods"));
        d.methods = [true; 10];
        d.time_before = "2026-07-07T09:00:00Z".to_string();
        assert_eq!(d.summary().as_deref(), Some("before 2026-07-07T09:00:00Z"));
        d.named = "a @b".to_string();
        assert_eq!(
            d.summary().as_deref(),
            Some("@a, @b, before 2026-07-07T09:00:00Z")
        );
        Ok(())
    }

    /// Applying the dialog stores its summary beside the expression, and a
    /// filter applied as an expression drops it, so a typed expression is
    /// never shown abbreviated.
    #[test]
    fn applying_the_dialog_stores_its_summary_and_an_expression_drops_it() -> Result<(), TestError>
    {
        let mut app = App::new_test();
        app.filter_dialog = heavy_dialog();
        app.filter_dialog.named.clear();
        apply_filter_dialog(&mut app);
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(app.active_filter_text.contains("method == 'INVITE'"));
        assert_eq!(app.active_filter_summary, app.filter_dialog.summary());
        assert!(app.active_filter_summary.is_some());

        apply_filter_expression(&mut app, Some("method == 'BYE'".to_string()), (None, None));
        assert_eq!(app.active_filter_text, "method == 'BYE'");
        assert_eq!(app.active_filter_summary, None);
        Ok(())
    }

    /// No method checked is applied on its own path; it still carries a
    /// summary, and clearing the filter drops it.
    #[test]
    fn the_no_methods_filter_is_summarized_and_a_clear_drops_it() -> Result<(), TestError> {
        let mut app = App::new_test();
        app.filter_dialog.methods = [false; 10];
        apply_filter_dialog(&mut app);
        assert_eq!(app.active_filter_summary.as_deref(), Some("no methods"));
        app.filter_dialog.methods = [true; 10];
        apply_filter_dialog(&mut app);
        assert!(app.active_filter.is_none(), "an empty dialog clears");
        assert_eq!(app.active_filter_summary, None);
        Ok(())
    }

    /// Every path that applies an expression drops the summary, including the
    /// one for a dialog with no method checked.
    #[test]
    fn the_no_methods_path_drops_a_stale_summary() -> Result<(), TestError> {
        let mut app = App::new_test();
        app.active_filter_summary = Some("From~alice".to_string());
        app.filter_dialog.methods = [false; 10];
        apply_filter_expression(&mut app, Some("method == 'BYE'".to_string()), (None, None));
        assert_eq!(app.active_filter_text, "(no methods selected)");
        assert_eq!(app.active_filter_summary, None);
        Ok(())
    }

    /// Clearing the filter drops its summary with it.
    #[test]
    fn clearing_the_active_filter_drops_its_summary() -> Result<(), TestError> {
        let mut app = App::new_test();
        app.filter_dialog.sip_from = "alice".to_string();
        apply_filter_dialog(&mut app);
        assert_eq!(app.active_filter_summary.as_deref(), Some("From~alice"));
        app.clear_active_filter();
        assert_eq!(app.active_filter_summary, None);
        Ok(())
    }

    /// A typed expression is one token of the summary, kept as typed, after
    /// the named filters and before the time bounds.
    #[test]
    fn the_summary_names_a_typed_expression() -> Result<(), TestError> {
        let d = FilterDialogState {
            named: "@scanners".to_string(),
            expression: "msg_count > 5".to_string(),
            time_after: "2026-07-07T08:00:00Z".to_string(),
            ..FilterDialogState::default()
        };
        assert_eq!(
            d.summary().as_deref(),
            Some("@scanners, expr msg_count > 5, after 2026-07-07T08:00:00Z"),
            "the expression token sits between the names and the time"
        );
        Ok(())
    }

    /// A dialog the DSL refuses keeps the filter that was in force, and that
    /// filter's summary with it.
    #[test]
    fn a_refused_dialog_keeps_the_summary_in_force() -> Result<(), TestError> {
        let mut app = App::new_test();
        app.filter_dialog.sip_from = "alice".to_string();
        apply_filter_dialog(&mut app);
        assert_eq!(app.active_filter_summary.as_deref(), Some("From~alice"));
        app.filter_dialog.header = "bad name: x".to_string();
        apply_filter_dialog(&mut app);
        assert!(
            app.filter_dialog.error.is_some(),
            "the header name is refused"
        );
        assert_eq!(app.active_filter_summary.as_deref(), Some("From~alice"));
        Ok(())
    }
}

/// Tests for the Expression field (#841): a Filter DSL expression typed in
/// the dialog, resolved and parsed by the rule `--filter` uses, ANDed with
/// the other fields, on whole dialogs.
///
/// The fixture is five dialogs, each named for what tells it apart:
///
/// | Call-ID      | first request | carries     | messages | From  |
/// |--------------|---------------|-------------|----------|-------|
/// | `foo-big`    | INVITE        | `X-Foo`     | 7        | alice |
/// | `foo-small`  | INVITE        | `X-Foo`     | 2        | alice |
/// | `foo-opts`   | OPTIONS       | `X-Foo`     | 7        | carol |
/// | `plain-big`  | INVITE        | nothing     | 7        | bob   |
/// | `lower-foo`  | INVITE        | `x-foo`     | 7        | bob   |
#[cfg(test)]
pub(super) mod expression_tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use crate::tui::controllers::test_support::{addr_a, addr_b, base_ts, raw_sip};
    use crate::tui::{
        ALL_METHODS_IDX, EXPRESSION_FIELD_IDX, FILTER_METHODS, FilterDialogState, Popup, TuiOptions,
    };
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    type TestError = Box<dyn std::error::Error>;

    /// The reporter's expression from #841.
    const REPORTED: &str = "payload =~ 'X-Foo' AND NOT payload =~ 'OPTIONS' AND msg_count > 5";

    /// Six responses: with the request, a dialog of seven messages.
    const SIX: [&str; 6] = [
        "100 Trying",
        "180 Ringing",
        "181 Forwarded",
        "182 Queued",
        "183 Progress",
        "200 OK",
    ];

    /// Build an unmodified `KeyEvent` for `code`.
    pub(in crate::tui::controllers) fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// One parsed message of `call_id`, `n` ms after the base time.
    fn message(
        first_line: &str,
        call_id: &str,
        method: &str,
        from: &str,
        extra: &[&str],
        n: i64,
    ) -> Result<SipMessage, TestError> {
        let from_h = format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1");
        let cid = format!("Call-ID: {call_id}");
        let cseq = format!("CSeq: 1 {method}");
        let mut headers: Vec<&str> = vec![&from_h, "To: <sip:bob@example.com>", &cid, &cseq];
        headers.extend_from_slice(extra);
        headers.push("Content-Length: 0");
        let raw = raw_sip(first_line, &headers);
        let request = !first_line.starts_with("SIP/2.0");
        let (src, dst) = if request {
            (addr_a(), addr_b())
        } else {
            (addr_b(), addr_a())
        };
        let ts = base_ts() + chrono::TimeDelta::milliseconds(n);
        Ok(
            parse_sip(&raw, ts, src, dst, 5060, 5060, TransportProto::Udp)
                .map_err(|e| format!("parse {first_line}: {e:?}"))?,
        )
    }

    /// A dialog: `method` from `from` carrying `extra`, then `responses`.
    fn dialog(
        method: &str,
        call_id: &str,
        from: &str,
        extra: &[&str],
        responses: &[&str],
        start: i64,
    ) -> Result<Vec<SipMessage>, TestError> {
        let mut out = vec![message(
            &format!("{method} sip:bob@example.com SIP/2.0"),
            call_id,
            method,
            from,
            extra,
            start,
        )?];
        for (i, status) in responses.iter().enumerate() {
            out.push(message(
                &format!("SIP/2.0 {status}"),
                call_id,
                method,
                from,
                &[],
                start + 1 + i as i64,
            )?);
        }
        Ok(out)
    }

    /// The five fixture dialogs' messages.
    pub(in crate::tui::controllers) fn fixture_messages() -> Result<Vec<SipMessage>, TestError> {
        let mut all = Vec::new();
        all.extend(dialog(
            "INVITE",
            "foo-big",
            "alice",
            &["X-Foo: 1"],
            &SIX,
            0,
        )?);
        all.extend(dialog(
            "INVITE",
            "foo-small",
            "alice",
            &["X-Foo: 1"],
            &["200 OK"],
            100,
        )?);
        all.extend(dialog(
            "OPTIONS",
            "foo-opts",
            "carol",
            &["X-Foo: 1"],
            &SIX,
            200,
        )?);
        all.extend(dialog("INVITE", "plain-big", "bob", &[], &SIX, 300)?);
        all.extend(dialog(
            "INVITE",
            "lower-foo",
            "bob",
            &["x-foo: 1"],
            &SIX,
            400,
        )?);
        Ok(all)
    }

    /// An app holding the fixture with the filter dialog open.
    pub(in crate::tui::controllers) fn fixture_app() -> Result<App, TestError> {
        let mut app = App::with_processed_messages(fixture_messages()?);
        app.sync_caches();
        app.active_popup = Some(Popup::FilterDialog);
        Ok(app)
    }

    /// The Call-IDs the call list shows, sorted.
    pub(in crate::tui::controllers) fn shown(app: &mut App) -> Vec<String> {
        app.sync_caches();
        let mut ids = app.displayed.ids.clone();
        ids.sort();
        ids
    }

    /// Type `text` into the Expression field and apply the dialog.
    pub(in crate::tui::controllers) fn apply_typed(app: &mut App, text: &str) {
        app.filter_dialog.expression = text.to_string();
        app.active_popup = Some(Popup::FilterDialog);
        apply_filter_dialog(app);
    }

    /// The Call-IDs `text` selects on the fixture, failing on a refusal.
    fn selects(text: &str) -> Result<Vec<String>, TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, text);
        if let Some(e) = &app.filter_dialog.error {
            return Err(format!("{text:?} was refused: {e}").into());
        }
        Ok(shown(&mut app))
    }

    /// `ids` as owned, sorted strings, to compare with [`shown`].
    pub(in crate::tui::controllers) fn ids(list: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = list.iter().map(|s| (*s).to_string()).collect();
        v.sort();
        v
    }

    /// A `[filters]` table defining `big` as `msg_count > 5`.
    pub(in crate::tui::controllers) fn big_table()
    -> Result<crate::sip::named_filters::NamedFilters, TestError> {
        let mut defs = std::collections::BTreeMap::new();
        defs.insert("big".to_string(), "msg_count > 5".to_string());
        Ok(crate::sip::named_filters::NamedFilters::resolve(
            &defs,
            &crate::sip::dsl::AliasThresholds::default(),
        )?)
    }

    /// The whole screen of `app`, drawn at `w` x `h`, one line per row.
    pub(in crate::tui::controllers) fn screen(
        app: &mut App,
        w: u16,
        h: u16,
    ) -> Result<String, TestError> {
        let mut terminal = Terminal::new(TestBackend::new(w, h))?;
        terminal.draw(|frame| app.render(frame))?;
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf.cell((x, y)).map_or(" ", |c| c.symbol()));
            }
            out.push('\n');
        }
        Ok(out)
    }

    /// The row of `text` that contains `needle`.
    pub(in crate::tui::controllers) fn row_with<'a>(
        text: &'a str,
        needle: &str,
    ) -> Option<&'a str> {
        text.lines().find(|l| l.contains(needle))
    }

    // ── The reporter's cases (success) ─────────────────────────────

    /// The issue's expression selects the one dialog with `X-Foo`, no
    /// `OPTIONS` anywhere in it, and more than five messages.
    #[test]
    fn the_reported_expression_selects_on_whole_dialogs() -> Result<(), TestError> {
        assert_eq!(
            selects(REPORTED)?,
            ids(&["foo-big"]),
            "X-Foo, not OPTIONS, more than 5 messages"
        );
        Ok(())
    }

    /// `msg_count <` counts a dialog's messages.
    #[test]
    fn msg_count_less_than() -> Result<(), TestError> {
        assert_eq!(selects("msg_count < 3")?, ids(&["foo-small"]), "2 < 3");
        Ok(())
    }

    /// `msg_count >` counts a dialog's messages.
    #[test]
    fn msg_count_greater_than() -> Result<(), TestError> {
        assert_eq!(
            selects("msg_count > 5")?,
            ids(&["foo-big", "foo-opts", "lower-foo", "plain-big"]),
            "every dialog of seven messages"
        );
        Ok(())
    }

    /// The DSL spells equality `==`.
    #[test]
    fn msg_count_equals() -> Result<(), TestError> {
        assert_eq!(selects("msg_count == 2")?, ids(&["foo-small"]), "exactly 2");
        Ok(())
    }

    /// `(?i)` makes a regex case-insensitive, so `x-foo` and `X-Foo` both
    /// match.
    #[test]
    fn case_insensitive_regex() -> Result<(), TestError> {
        assert_eq!(
            selects("payload =~ '(?i)x-foo'")?,
            ids(&["foo-big", "foo-opts", "foo-small", "lower-foo"]),
            "either case"
        );
        Ok(())
    }

    /// Without `(?i)` a regex is case-sensitive.
    #[test]
    fn a_regex_is_case_sensitive_by_default() -> Result<(), TestError> {
        assert_eq!(
            selects("payload =~ 'x-foo'")?,
            ids(&["lower-foo"]),
            "only the lower-case header"
        );
        Ok(())
    }

    /// `OR` admits a dialog that either side admits.
    #[test]
    fn or_admits_either_side() -> Result<(), TestError> {
        assert_eq!(
            selects("msg_count < 3 OR payload =~ 'OPTIONS'")?,
            ids(&["foo-opts", "foo-small"]),
            "the short dialog and the OPTIONS dialog"
        );
        Ok(())
    }

    /// Parentheses group an `OR` under an `AND`.
    #[test]
    fn parentheses_group_an_or_under_an_and() -> Result<(), TestError> {
        assert_eq!(
            selects("payload =~ 'X-Foo' AND (msg_count < 3 OR NOT payload =~ 'OPTIONS')")?,
            ids(&["foo-big", "foo-small"]),
            "X-Foo, and short or not OPTIONS"
        );
        Ok(())
    }

    /// Without the parentheses `AND` binds first, so the same words select
    /// a different set: the parentheses are what made the case above.
    #[test]
    fn without_parentheses_and_binds_before_or() -> Result<(), TestError> {
        assert_eq!(
            selects("payload =~ 'X-Foo' AND msg_count < 3 OR NOT payload =~ 'OPTIONS'")?,
            ids(&["foo-big", "foo-small", "lower-foo", "plain-big"]),
            "(X-Foo AND short) OR not OPTIONS"
        );
        Ok(())
    }

    // ── AND-combined with the rest of the dialog (success) ─────────

    /// The From field and the expression must both hold.
    #[test]
    fn the_expression_ands_with_a_text_field() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.sip_from = "alice".to_string();
        apply_typed(&mut app, "msg_count > 5");
        assert_eq!(shown(&mut app), ids(&["foo-big"]), "alice AND 7 messages");
        Ok(())
    }

    /// A top-level `OR` in the expression stays inside it: the dialog's
    /// fields narrow the whole expression, not only its last term.
    #[test]
    fn an_or_in_the_expression_stays_grouped_under_the_fields() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.sip_from = "alice".to_string();
        apply_typed(&mut app, "msg_count > 5 OR payload =~ 'OPTIONS'");
        assert_eq!(
            shown(&mut app),
            ids(&["foo-big"]),
            "alice AND (7 messages OR OPTIONS); carol's OPTIONS dialog stays out"
        );
        Ok(())
    }

    /// The method checkboxes and the expression must both hold.
    #[test]
    fn the_expression_ands_with_the_method_checkboxes() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.methods = FILTER_METHODS.map(|m| m == "INVITE");
        apply_typed(&mut app, "payload =~ 'X-Foo'");
        assert_eq!(
            shown(&mut app),
            ids(&["foo-big", "foo-small"]),
            "INVITE AND X-Foo"
        );
        Ok(())
    }

    /// The Named filter field and the expression must both hold.
    #[test]
    fn the_expression_ands_with_the_named_filter() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        app.filter_dialog.named = "big".to_string();
        apply_typed(&mut app, "payload =~ 'X-Foo'");
        assert_eq!(
            shown(&mut app),
            ids(&["foo-big", "foo-opts"]),
            "@big AND X-Foo"
        );
        Ok(())
    }

    /// An `@name` inside the expression resolves through the run's
    /// `[filters]`, as it does in `--filter`.
    #[test]
    fn a_reference_in_the_expression_resolves() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        apply_typed(&mut app, "@big AND NOT payload =~ 'X-Foo'");
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert_eq!(
            shown(&mut app),
            ids(&["lower-foo", "plain-big"]),
            "7 messages and no X-Foo"
        );
        Ok(())
    }

    /// A diagnostic alias name alone is expanded, as `--filter one-way` is.
    #[test]
    fn a_bare_alias_name_is_expanded() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "one-way");
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert_eq!(
            app.active_filter.as_ref().map(FilterExpr::source),
            Some("one_way == true"),
            "the alias's expansion is what runs"
        );
        Ok(())
    }

    /// The expression alone is applied as typed, not wrapped.
    #[test]
    fn an_expression_alone_is_applied_as_typed() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, REPORTED);
        assert_eq!(
            app.active_filter_text, REPORTED,
            "the status text is the expression"
        );
        assert!(
            app.active_popup.is_none(),
            "a valid expression closes the dialog"
        );
        Ok(())
    }

    /// Typed through the keys: Tab from the Named field reaches the
    /// Expression field, the text goes in, and Enter applies it.
    #[test]
    fn typing_the_expression_through_the_keys_applies_it() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = 8;
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "Tab from Named filter"
        );
        for c in "msg_count == 2".chars() {
            handle_filter_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        assert_eq!(
            app.filter_dialog.expression, "msg_count == 2",
            "typed into the field"
        );
        handle_filter_popup_key(&mut app, key(KeyCode::Enter));
        assert!(app.active_popup.is_none(), "{:?}", app.filter_dialog.error);
        assert_eq!(shown(&mut app), ids(&["foo-small"]), "Enter applied it");
        Ok(())
    }

    /// The filter is applied live: a dialog that arrives after Enter is
    /// shown or hidden by the expression too.
    #[test]
    fn a_dialog_arriving_later_is_filtered_too() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "payload =~ 'X-Late'");
        assert!(shown(&mut app).is_empty(), "nothing carries X-Late yet");
        {
            let mut store = app.dialog_store.write();
            for m in dialog("INVITE", "late", "dave", &["X-Late: 1"], &["200 OK"], 900)? {
                store.process_message(m);
            }
            for m in dialog("INVITE", "late-plain", "dave", &[], &["200 OK"], 950)? {
                store.process_message(m);
            }
        }
        // The rebuild a store change waits for: the churn floor passing.
        app.displayed.floor.elapse_for_test();
        assert_eq!(
            shown(&mut app),
            ids(&["late"]),
            "the new match, not the new miss"
        );
        Ok(())
    }

    /// The summary on status line 3 says an expression is active.
    #[test]
    fn the_status_line_says_an_expression_is_active() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count > 5");
        let text = screen(&mut app, 100, 24)?;
        let row = row_with(&text, "View filter:").ok_or("status line 3")?;
        assert!(
            row.contains("F7: expr msg_count > 5"),
            "the summary names the expression: {row:?}"
        );
        Ok(())
    }

    /// In full mode status line 3 shows the expression that runs, with the
    /// fields it was ANDed with.
    #[test]
    fn full_mode_shows_the_combined_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.view_filter_detail = crate::tui::ViewFilterDetail::Full;
        app.filter_dialog.sip_from = "alice".to_string();
        apply_typed(&mut app, "msg_count > 5");
        assert_eq!(
            app.active_filter_text, "from.user =~ 'alice' AND (msg_count > 5)",
            "fields first, the expression grouped"
        );
        let text = screen(&mut app, 120, 24)?;
        let row = row_with(&text, "View filter:").ok_or("status line 3")?;
        assert!(row.contains("AND (msg_count > 5)"), "{row:?}");
        Ok(())
    }

    /// The dialog draws the Expression field after Named filter, with the
    /// text in it.
    #[test]
    fn the_dialog_draws_the_expression_field() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.expression = "msg_count > 5".to_string();
        let text = screen(&mut app, 80, 24)?;
        let named = text
            .lines()
            .position(|l| l.contains("Named filter:"))
            .ok_or("the Named row")?;
        let expr = text
            .lines()
            .position(|l| l.contains("Expression:"))
            .ok_or_else(|| format!("no Expression row:\n{text}"))?;
        assert_eq!(expr, named + 1, "Expression sits right under Named filter");
        let row = text.lines().nth(expr).unwrap_or_default();
        assert!(row.contains("[msg_count > 5"), "{row:?}");
        Ok(())
    }

    // ── Refusals (failure) ─────────────────────────────────────────

    /// A parse error keeps the dialog open with the parser's own message and
    /// position, prefixed with the field's name.
    #[test]
    fn a_parse_error_is_shown_inline_with_its_position() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count > 5 garbage");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "stays open");
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(
            error.starts_with("Expression error: a value containing whitespace"),
            "names the field: {error}"
        );
        // The parser stops at the value: an unquoted `5 garbage` reads as a
        // value with a space in it, or a missing AND/OR.
        assert!(
            error.contains("at position 12: '5'"),
            "the parser's position: {error}"
        );
        Ok(())
    }

    /// The filter in force before a refused expression stays in force.
    #[test]
    fn a_refused_expression_keeps_the_previous_filter() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count == 2");
        assert_eq!(shown(&mut app), ids(&["foo-small"]), "the first filter");
        let before = app.active_filter_text.clone();
        apply_typed(&mut app, "msg_count == ");
        assert!(app.filter_dialog.error.is_some(), "refused");
        assert_eq!(app.active_filter_text, before, "the old filter text");
        assert_eq!(shown(&mut app), ids(&["foo-small"]), "the old selection");
        Ok(())
    }

    /// A refusal puts the focus on the Expression field and the cursor
    /// where the parser stopped.
    #[test]
    fn a_refusal_puts_the_cursor_where_the_parser_stopped() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = 0;
        apply_typed(&mut app, "msg_count > 5 garbage");
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "focus moved from From user to Expression"
        );
        assert_eq!(
            app.filter_dialog.cursor_pos, 12,
            "on the '5' the parser names"
        );
        Ok(())
    }

    /// The cursor allows for the whitespace the parser trimmed off the
    /// front of the field.
    #[test]
    fn the_cursor_allows_for_leading_whitespace() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "   msg_count > 5 garbage");
        assert_eq!(app.filter_dialog.cursor_pos, 15, "3 spaces + 12");
        Ok(())
    }

    /// `=` alone is not an operator: refused, as `--filter` refuses it.
    #[test]
    fn a_single_equals_sign_is_refused() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count = 5");
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(error.starts_with("Expression error:"), "{error}");
        assert!(error.contains("position"), "{error}");
        assert!(app.active_filter.is_none(), "nothing applied");
        Ok(())
    }

    /// An unclosed parenthesis is refused.
    #[test]
    fn an_unclosed_parenthesis_is_refused() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "(msg_count > 5 OR msg_count < 3");
        assert!(
            app.filter_dialog
                .error
                .as_deref()
                .unwrap_or_default()
                .starts_with("Expression error:"),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(app.active_filter.is_none(), "nothing applied");
        Ok(())
    }

    /// A misspelled field is refused with the parser's hint naming the field
    /// it meant.
    #[test]
    fn a_misspelled_field_is_refused_with_the_parsers_hint() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msgcount > 5");
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(error.contains("did you mean 'msg_count'"), "{error}");
        Ok(())
    }

    /// A regex that does not compile is refused.
    #[test]
    fn an_invalid_regex_is_refused() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "payload =~ '('");
        assert!(
            app.filter_dialog
                .error
                .as_deref()
                .unwrap_or_default()
                .starts_with("Expression error:"),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(app.active_filter.is_none(), "nothing applied");
        Ok(())
    }

    /// An `@name` the run does not define is refused, naming the defined
    /// ones, and the filter in force stays.
    #[test]
    fn an_undefined_reference_is_refused() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        apply_typed(&mut app, "@nope AND msg_count > 1");
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(error.contains("'@nope' is not a defined filter"), "{error}");
        assert!(error.contains("big"), "names what is defined: {error}");
        assert!(app.active_filter.is_none(), "nothing applied");
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "focus on the refused field"
        );
        Ok(())
    }

    /// Correcting the refused text applies it and clears the error.
    #[test]
    fn correcting_a_refused_expression_applies_it() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count = 2");
        assert!(app.filter_dialog.error.is_some(), "refused first");
        apply_typed(&mut app, "msg_count == 2");
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(app.active_popup.is_none(), "closed");
        assert_eq!(shown(&mut app), ids(&["foo-small"]), "the corrected filter");
        Ok(())
    }

    /// The refusal is drawn in the dialog: the parser's headline on one
    /// row, its hint on another, never the raw multi-line text on one.
    #[test]
    fn the_refusal_is_drawn_in_the_dialog() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msgcount > 5");
        let text = screen(&mut app, 80, 24)?;
        let headline =
            row_with(&text, "Expression error:").ok_or_else(|| format!("no error row:\n{text}"))?;
        assert!(headline.contains("at position 0"), "{headline:?}");
        let hint = row_with(&text, "hint: unknown field 'msgcount'")
            .ok_or_else(|| format!("no hint row:\n{text}"))?;
        assert!(hint.contains("did you mean 'msg_count'"), "{hint:?}");
        Ok(())
    }

    /// A valid expression does not get a bad Header name through: the
    /// Header is still refused, and nothing is applied.
    #[test]
    fn a_valid_expression_does_not_excuse_a_bad_header() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.header = "bad name: x".to_string();
        apply_typed(&mut app, "msg_count > 5");
        let error = app.filter_dialog.error.clone().unwrap_or_default();
        assert!(
            error.starts_with("Filter error:"),
            "the Header is refused: {error}"
        );
        assert!(app.active_filter.is_none(), "nothing applied");
        Ok(())
    }

    /// A refused expression on an unfiltered list leaves it unfiltered:
    /// every dialog stays shown and no filter text appears.
    #[test]
    fn a_refused_expression_changes_nothing_on_screen() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        let all = shown(&mut app);
        apply_typed(&mut app, "msg_count >");
        assert!(app.filter_dialog.error.is_some(), "refused");
        assert_eq!(shown(&mut app), all, "every dialog still shown");
        assert!(app.active_filter_text.is_empty(), "no filter text");
        Ok(())
    }

    // ── Edges ──────────────────────────────────────────────────────

    /// An empty Expression field adds nothing: the dialog clears.
    #[test]
    fn an_empty_expression_adds_nothing() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "");
        assert!(app.active_filter.is_none(), "no filter");
        assert_eq!(shown(&mut app).len(), 5, "every dialog");
        Ok(())
    }

    /// Whitespace alone is an empty field, not a parse error.
    #[test]
    fn whitespace_alone_is_an_empty_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "   ");
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(app.active_filter.is_none(), "no filter");
        Ok(())
    }

    /// Clearing the field and applying removes the expression.
    #[test]
    fn clearing_the_field_removes_the_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count == 2");
        assert_eq!(shown(&mut app).len(), 1, "the expression narrows");
        apply_typed(&mut app, "");
        assert!(app.active_filter.is_none(), "the expression is gone");
        assert_eq!(shown(&mut app).len(), 5, "every dialog again");
        assert_eq!(app.active_filter_summary, None, "nothing to summarize");
        Ok(())
    }

    /// F9 empties the Expression field with the others.
    #[test]
    fn f9_empties_the_expression_field() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count == 2");
        app.active_popup = Some(Popup::FilterDialog);
        handle_filter_popup_key(&mut app, key(KeyCode::F(9)));
        assert_eq!(app.filter_dialog.expression, "", "emptied");
        assert!(app.active_filter.is_none(), "dropped");
        assert_eq!(shown(&mut app).len(), 5, "every dialog again");
        Ok(())
    }

    /// Only the expression set is still a dialog that filters.
    #[test]
    fn a_dialog_with_only_an_expression_is_not_empty() -> Result<(), TestError> {
        let mut d = FilterDialogState {
            expression: "msg_count > 5".to_string(),
            ..FilterDialogState::default()
        };
        assert!(!d.is_empty(), "an expression is a filter");
        d.clear();
        assert!(d.expression.is_empty(), "clear() empties it");
        assert!(d.is_empty(), "nothing left to filter on");
        Ok(())
    }

    /// With no method checked nothing shows, whatever the expression says.
    #[test]
    fn no_method_checked_wins_over_the_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.methods = [false; 10];
        apply_typed(&mut app, "msg_count > 0");
        assert!(
            shown(&mut app).is_empty(),
            "the explicit show-nothing state"
        );
        Ok(())
    }

    /// Esc closes the dialog without applying the typed expression.
    #[test]
    fn esc_does_not_apply_the_typed_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.expression = "msg_count == 2".to_string();
        handle_filter_popup_key(&mut app, key(KeyCode::Esc));
        assert!(app.active_popup.is_none(), "closed");
        assert!(app.active_filter.is_none(), "nothing applied");
        assert_eq!(
            app.filter_dialog.expression, "msg_count == 2",
            "the text stays for the next open"
        );
        Ok(())
    }

    /// The field keeps its text when the dialog is opened again with F7.
    #[test]
    fn reopening_the_dialog_keeps_the_expression() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count == 2");
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "reopened");
        assert_eq!(
            app.filter_dialog.expression, "msg_count == 2",
            "the text survives a reopen"
        );
        Ok(())
    }

    /// Tab order: Named filter, Expression, then the All checkbox; Up from
    /// All comes back to Expression.
    #[test]
    fn the_expression_field_sits_between_named_and_all() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = 8;
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "Named filter, then Expression"
        );
        handle_filter_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(
            app.filter_dialog.focused_field, ALL_METHODS_IDX,
            "Expression, then All"
        );
        handle_filter_popup_key(&mut app, key(KeyCode::Up));
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "Up from All"
        );
        Ok(())
    }

    /// Multibyte text edits safely in the Expression field.
    #[test]
    fn multibyte_text_in_the_expression_edits_safely() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        app.filter_dialog.sync_cursor();
        for c in "payload =~ 'é'".chars() {
            handle_filter_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_filter_popup_key(&mut app, key(KeyCode::Left));
        handle_filter_popup_key(&mut app, key(KeyCode::Backspace));
        assert_eq!(
            app.filter_dialog.expression, "payload =~ ''",
            "the whole 'é' removed"
        );
        Ok(())
    }

    /// An error inside text an `@name` expanded to cannot be placed in the
    /// field, so the cursor stays where it was; the message still shows.
    #[test]
    fn an_error_inside_an_expansion_leaves_the_cursor() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        app.filter_dialog.expression = "@big garbage".to_string();
        app.filter_dialog.cursor_pos = 4;
        apply_filter_dialog(&mut app);
        assert!(
            app.filter_dialog
                .error
                .as_deref()
                .unwrap_or_default()
                .starts_with("Expression error:"),
            "{:?}",
            app.filter_dialog.error
        );
        assert_eq!(
            app.filter_dialog.cursor_pos, 4,
            "not moved into the expansion"
        );
        Ok(())
    }

    /// An expression longer than the field scrolls, so the cursor and the
    /// text before it stay in view while typing.
    #[test]
    fn a_long_expression_scrolls_to_keep_the_cursor_in_view() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        let long = format!("{REPORTED} AND payload =~ 'TAIL-END'");
        app.filter_dialog.expression = long.clone();
        app.filter_dialog.cursor_pos = long.len();
        let text = screen(&mut app, 80, 24)?;
        let row = row_with(&text, "Expression:").ok_or("the Expression row")?;
        assert!(row.contains("'TAIL-END'"), "the end is in view: {row:?}");
        // The cursor cell after the text, inside the closing bracket: one
        // byte further and the bracket would be painted over it.
        assert!(
            row.contains("'TAIL-END' ]"),
            "the cursor cell sits between the text and the bracket: {row:?}"
        );
        assert!(
            !row.contains("payload =~ 'X-Foo'"),
            "the start scrolled off: {row:?}"
        );
        Ok(())
    }

    /// Unfocused, a long expression shows its start.
    #[test]
    fn an_unfocused_long_expression_shows_its_start() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.focused_field = 0;
        app.filter_dialog.expression = format!("{REPORTED} AND payload =~ 'TAIL-END'");
        let text = screen(&mut app, 80, 24)?;
        let row = row_with(&text, "Expression:").ok_or("the Expression row")?;
        assert!(row.contains("[payload =~ 'X-Foo'"), "the start: {row:?}");
        assert!(!row.contains("TAIL-END"), "the end is cut: {row:?}");
        Ok(())
    }

    // ── Started with --filter / [filter] expression ────────────────

    /// The session opens with the run's typed filter in the field, applied.
    #[test]
    fn the_run_filter_is_prefilled_and_applied() -> Result<(), TestError> {
        let fixture = App::with_processed_messages(fixture_messages()?);
        let mut app = TuiOptions {
            filter_expression: Some(REPORTED.to_string()),
            ..TuiOptions::default()
        }
        .into_app(
            std::sync::Arc::clone(&fixture.dialog_store),
            std::sync::Arc::clone(&fixture.stream_store),
        );
        assert_eq!(app.filter_dialog.expression, REPORTED, "prefilled as typed");
        assert_eq!(shown(&mut app), ids(&["foo-big"]), "and applied");
        assert!(app.active_popup.is_none(), "no dialog left open");
        Ok(())
    }

    /// With `-c` as well, both apply: calls only AND the expression.
    #[test]
    fn the_run_filter_and_calls_only_both_apply() -> Result<(), TestError> {
        let fixture = App::with_processed_messages(fixture_messages()?);
        let mut app = TuiOptions {
            filter_expression: Some("payload =~ 'X-Foo'".to_string()),
            calls_only: true,
            ..TuiOptions::default()
        }
        .into_app(
            std::sync::Arc::clone(&fixture.dialog_store),
            std::sync::Arc::clone(&fixture.stream_store),
        );
        assert_eq!(
            shown(&mut app),
            ids(&["foo-big", "foo-small"]),
            "INVITE AND X-Foo; the OPTIONS dialog stays out"
        );
        Ok(())
    }

    /// A startup notice survives the run's filter being applied: applying a
    /// filter clears the status line, so the notice is set after it. Before
    /// #841 `-c` dropped it the same way.
    #[test]
    fn a_startup_notice_survives_the_run_filter() -> Result<(), TestError> {
        for calls_only in [false, true] {
            let fixture = App::with_processed_messages(fixture_messages()?);
            let app = TuiOptions {
                filter_expression: Some("msg_count > 5".to_string()),
                calls_only,
                startup_notice: Some("Config: example.toml".to_string()),
                ..TuiOptions::default()
            }
            .into_app(
                std::sync::Arc::clone(&fixture.dialog_store),
                std::sync::Arc::clone(&fixture.stream_store),
            );
            assert!(app.active_filter.is_some(), "-c {calls_only}: applied");
            assert_eq!(
                app.status_error.as_deref(),
                Some("Config: example.toml"),
                "-c {calls_only}: the notice is kept"
            );
        }
        Ok(())
    }

    /// A run filter the session cannot apply is said on the status line,
    /// not left in a dialog nobody opened, and nothing is applied.
    #[test]
    fn a_run_filter_the_session_refuses_is_said_on_the_status_line() -> Result<(), TestError> {
        let fixture = App::with_processed_messages(fixture_messages()?);
        let app = TuiOptions {
            filter_expression: Some("@undefined".to_string()),
            ..TuiOptions::default()
        }
        .into_app(
            std::sync::Arc::clone(&fixture.dialog_store),
            std::sync::Arc::clone(&fixture.stream_store),
        );
        let status = app.status_error.clone().unwrap_or_default();
        assert!(status.contains("Expression error:"), "{status:?}");
        assert!(status.contains("'@undefined'"), "{status:?}");
        assert!(app.filter_dialog.error.is_none(), "not left in the dialog");
        assert!(app.active_filter.is_none(), "nothing applied");
        Ok(())
    }

    /// A run with no typed filter opens with the field empty and no filter.
    #[test]
    fn no_run_filter_leaves_the_field_empty() -> Result<(), TestError> {
        let fixture = App::with_processed_messages(fixture_messages()?);
        let app = TuiOptions::default().into_app(
            std::sync::Arc::clone(&fixture.dialog_store),
            std::sync::Arc::clone(&fixture.stream_store),
        );
        assert_eq!(app.filter_dialog.expression, "", "nothing prefilled");
        assert!(app.active_filter.is_none(), "no filter");
        Ok(())
    }
}

/// The Expression field's history (Up/Down) and the dialog's field help
/// (`F1`), driven through the dialog's keys.
#[cfg(test)]
mod history_and_help_tests {
    use super::expression_tests::{
        apply_typed, fixture_app, fixture_messages, key, row_with, screen, shown,
    };
    use super::*;
    use crate::tui::expression_history::EXPRESSION_HISTORY_MAX;
    use crate::tui::{ALL_METHODS_IDX, Popup, TuiOptions};

    type TestError = Box<dyn std::error::Error>;

    /// The fixture with each of `texts` applied from the Expression field in
    /// turn, then the dialog opened again with the Expression field focused
    /// and empty.
    fn with_history(texts: &[&str]) -> Result<App, TestError> {
        let mut app = fixture_app()?;
        for text in texts {
            apply_typed(&mut app, text);
            if let Some(e) = &app.filter_dialog.error {
                return Err(format!("{text:?} was refused: {e}").into());
            }
        }
        open_filter_dialog(&mut app);
        app.filter_dialog.expression.clear();
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        app.filter_dialog.sync_cursor();
        Ok(app)
    }

    /// Press `code` in the dialog.
    fn press(app: &mut App, code: KeyCode) {
        handle_filter_popup_key(app, key(code));
    }

    /// The history, newest first.
    fn history(app: &App) -> Vec<String> {
        app.expression_history
            .entries()
            .map(str::to_owned)
            .collect()
    }

    // ── History ────────────────────────────────────────────────────

    /// An applied expression enters the history.
    #[test]
    fn an_applied_expression_enters_the_history() -> Result<(), TestError> {
        let app = with_history(&["msg_count > 5"])?;
        assert_eq!(history(&app), ["msg_count > 5"], "recorded on apply");
        Ok(())
    }

    /// Up in the Expression field recalls the newest applied expression,
    /// with the cursor at its end.
    #[test]
    fn up_recalls_the_newest_expression() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5", "method == 'BYE'"])?;
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.expression, "method == 'BYE'",
            "the newest"
        );
        assert_eq!(
            app.filter_dialog.cursor_pos,
            app.filter_dialog.expression.len(),
            "the cursor at the end"
        );
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "focus stays"
        );
        Ok(())
    }

    /// Up again recalls the one before it.
    #[test]
    fn up_again_recalls_the_older_one() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5", "method == 'BYE'"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(app.filter_dialog.expression, "msg_count > 5", "older");
        Ok(())
    }

    /// Down walks forward and, past the newest, restores what was typed.
    #[test]
    fn down_walks_forward_to_the_typed_text() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5", "method == 'BYE'"])?;
        app.filter_dialog.expression = "ua =~ 'half".into();
        app.filter_dialog.sync_cursor();
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Down);
        assert_eq!(app.filter_dialog.expression, "method == 'BYE'", "forward");
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.filter_dialog.expression, "ua =~ 'half",
            "the typed text is back"
        );
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "focus stays"
        );
        Ok(())
    }

    /// Up at the oldest entry moves focus on to Named filter, as Up does in
    /// every other field.
    #[test]
    fn up_past_the_oldest_moves_to_the_named_field() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.focused_field,
            EXPRESSION_FIELD_IDX - 1,
            "Named filter"
        );
        assert_eq!(
            app.filter_dialog.expression, "msg_count > 5",
            "the recall stays in the field"
        );
        assert!(
            !app.expression_history.is_walking(),
            "leaving the field ends the recall"
        );
        Ok(())
    }

    /// Down with no recall under way moves focus on to All, as before.
    #[test]
    fn down_without_a_recall_moves_to_all() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5"])?;
        press(&mut app, KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field, ALL_METHODS_IDX, "All");
        Ok(())
    }

    /// With no history, Up and Down move focus exactly as they did before.
    #[test]
    fn with_no_history_up_and_down_move_focus() -> Result<(), TestError> {
        let mut app = with_history(&[])?;
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.focused_field,
            EXPRESSION_FIELD_IDX - 1,
            "up to Named"
        );
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "back down"
        );
        press(&mut app, KeyCode::Down);
        assert_eq!(
            app.filter_dialog.focused_field, ALL_METHODS_IDX,
            "on to All"
        );
        Ok(())
    }

    /// Up in another text field moves focus, and recalls nothing there.
    #[test]
    fn up_in_another_field_recalls_nothing() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5"])?;
        app.filter_dialog.focused_field = 1;
        app.filter_dialog.sync_cursor();
        press(&mut app, KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field, 0, "Up moved focus");
        assert_eq!(app.filter_dialog.sip_from, "", "no recall into From user");
        assert_eq!(app.filter_dialog.expression, "", "nor into Expression");
        assert!(!app.expression_history.is_walking(), "no recall started");
        Ok(())
    }

    /// A refused expression does not enter the history.
    #[test]
    fn a_refused_expression_is_not_recorded() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        apply_typed(&mut app, "msg_count = 5");
        assert!(app.filter_dialog.error.is_some(), "refused");
        assert_eq!(history(&app), Vec::<String>::new(), "not recorded");
        Ok(())
    }

    /// An expression refused because another field failed does not enter
    /// the history: only an applied dialog records.
    #[test]
    fn an_expression_beside_a_bad_time_bound_is_not_recorded() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.time_after = "yesterday".into();
        apply_typed(&mut app, "msg_count > 5");
        assert!(
            app.filter_dialog.error.is_some(),
            "the time bound refused it"
        );
        assert_eq!(history(&app), Vec::<String>::new(), "not recorded");
        Ok(())
    }

    /// A dialog applied with an empty Expression records nothing.
    #[test]
    fn an_empty_expression_is_not_recorded() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.filter_dialog.sip_from = "alice".into();
        apply_typed(&mut app, "");
        assert_eq!(app.filter_dialog.error, None, "applied");
        assert_eq!(history(&app), Vec::<String>::new(), "nothing recorded");
        Ok(())
    }

    /// The history records the text as typed, not its `@name` expansion.
    #[test]
    fn the_history_keeps_the_text_as_typed() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.named_filters = super::expression_tests::big_table()?;
        apply_typed(&mut app, "  @big  ");
        assert_eq!(app.filter_dialog.error, None, "applied");
        assert_eq!(history(&app), ["@big"], "trimmed, not expanded");
        Ok(())
    }

    /// Applying the same expression twice keeps one entry.
    #[test]
    fn applying_twice_keeps_one_entry() -> Result<(), TestError> {
        let app = with_history(&["msg_count > 5", "method == 'BYE'", "msg_count > 5"])?;
        assert_eq!(
            history(&app),
            ["msg_count > 5", "method == 'BYE'"],
            "collapsed"
        );
        Ok(())
    }

    /// The dialog's history holds at most the bound.
    #[test]
    fn the_dialog_history_is_bounded() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        for n in 0..EXPRESSION_HISTORY_MAX + 5 {
            apply_typed(&mut app, &format!("msg_count > {n}"));
        }
        assert_eq!(history(&app).len(), EXPRESSION_HISTORY_MAX, "bounded");
        Ok(())
    }

    /// Typing after a recall edits the field's copy; the history entry is
    /// unchanged, and applying the edit adds it as a new entry.
    #[test]
    fn typing_after_a_recall_edits_a_copy() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5"])?;
        press(&mut app, KeyCode::Up);
        for c in " AND ua =~ 'x'".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(
            app.filter_dialog.expression, "msg_count > 5 AND ua =~ 'x'",
            "edited"
        );
        assert_eq!(history(&app), ["msg_count > 5"], "the entry is unchanged");
        press(&mut app, KeyCode::Enter);
        assert_eq!(
            history(&app),
            ["msg_count > 5 AND ua =~ 'x'", "msg_count > 5"],
            "the edit is its own entry"
        );
        Ok(())
    }

    /// After an edit, Up starts again from the newest entry and Down brings
    /// the edited text back.
    #[test]
    fn an_edit_ends_the_recall() -> Result<(), TestError> {
        let mut app = with_history(&["ua == 'a'", "ua == 'b'"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Backspace);
        assert_eq!(
            app.filter_dialog.expression, "ua == 'a",
            "edited the older one"
        );
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.expression, "ua == 'b'",
            "from the newest again"
        );
        press(&mut app, KeyCode::Down);
        assert_eq!(app.filter_dialog.expression, "ua == 'a", "the edit is back");
        Ok(())
    }

    /// Moving the cursor inside a recalled entry does not end the recall.
    #[test]
    fn moving_the_cursor_keeps_the_recall() -> Result<(), TestError> {
        let mut app = with_history(&["ua == 'a'", "ua == 'b'"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Left);
        press(&mut app, KeyCode::Home);
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.expression, "ua == 'a'",
            "still walking back"
        );
        Ok(())
    }

    /// Leaving the field with Tab ends the recall: back in the field, Up
    /// starts from the newest entry.
    #[test]
    fn tab_ends_the_recall() -> Result<(), TestError> {
        let mut app = with_history(&["ua == 'a'", "ua == 'b'"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::BackTab);
        assert_eq!(
            app.filter_dialog.focused_field, EXPRESSION_FIELD_IDX,
            "back"
        );
        press(&mut app, KeyCode::Up);
        assert_eq!(app.filter_dialog.expression, "ua == 'b'", "from the newest");
        Ok(())
    }

    /// The history outlives `F9`, which clears the fields and the filter.
    #[test]
    fn the_history_outlives_a_clear() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5"])?;
        press(&mut app, KeyCode::F(9));
        assert_eq!(app.active_popup, None, "F9 closed the dialog");
        open_filter_dialog(&mut app);
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        app.filter_dialog.sync_cursor();
        press(&mut app, KeyCode::Up);
        assert_eq!(
            app.filter_dialog.expression, "msg_count > 5",
            "still recalled"
        );
        Ok(())
    }

    /// The expression a session started with (`--filter`) is applied, so it
    /// is in the history.
    #[test]
    fn the_run_filter_is_in_the_history() -> Result<(), TestError> {
        let fixture = App::with_processed_messages(fixture_messages()?);
        let app = TuiOptions {
            filter_expression: Some("msg_count > 5".to_string()),
            ..TuiOptions::default()
        }
        .into_app(
            std::sync::Arc::clone(&fixture.dialog_store),
            std::sync::Arc::clone(&fixture.stream_store),
        );
        assert_eq!(
            history(&app),
            ["msg_count > 5"],
            "applied at start, recorded"
        );
        Ok(())
    }

    /// A recalled expression applies like a typed one.
    #[test]
    fn a_recalled_expression_applies() -> Result<(), TestError> {
        let mut app = with_history(&["msg_count > 5", "msg_count < 3"])?;
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Up);
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, None, "applied");
        assert_eq!(
            shown(&mut app),
            super::expression_tests::ids(&["foo-big", "foo-opts", "lower-foo", "plain-big"]),
            "the recalled msg_count > 5"
        );
        Ok(())
    }

    // ── Field help (F1) ────────────────────────────────────────────

    /// `F1` shows the field help in the dialog, and `F1` again hides it.
    #[test]
    fn f1_toggles_the_field_help() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        press(&mut app, KeyCode::F(1));
        assert!(app.filter_dialog.show_help, "shown");
        assert_eq!(
            app.active_popup,
            Some(Popup::FilterDialog),
            "the dialog stays"
        );
        press(&mut app, KeyCode::F(1));
        assert!(!app.filter_dialog.show_help, "hidden");
        Ok(())
    }

    /// `Esc` with the help shown hides the help and keeps the dialog.
    #[test]
    fn esc_hides_the_help_first() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        press(&mut app, KeyCode::F(1));
        press(&mut app, KeyCode::Esc);
        assert!(!app.filter_dialog.show_help, "help hidden");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "dialog open");
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, None, "the second Esc cancels");
        Ok(())
    }

    /// Typing goes on with the help shown: the field still takes keys and
    /// Enter still applies.
    #[test]
    fn typing_goes_on_with_the_help_shown() -> Result<(), TestError> {
        let mut app = with_history(&[])?;
        press(&mut app, KeyCode::F(1));
        for c in "msg_count > 5".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.filter_dialog.expression, "msg_count > 5", "typed");
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.active_popup, None, "applied");
        Ok(())
    }

    /// The help is off each time the dialog opens.
    #[test]
    fn the_help_is_off_when_the_dialog_opens() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        press(&mut app, KeyCode::F(1));
        press(&mut app, KeyCode::Enter);
        open_filter_dialog(&mut app);
        assert!(!app.filter_dialog.show_help, "off");
        Ok(())
    }

    /// With the help shown, the dialog draws every field name and operator
    /// and the key that closes it, in place of the method boxes.
    #[test]
    fn the_dialog_draws_the_help() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        press(&mut app, KeyCode::F(1));
        let text = screen(&mut app, 80, 24)?;
        for name in crate::sip::dsl::FIELD_NAMES {
            assert!(
                text.split(|c: char| c.is_whitespace() || c == '\u{2502}')
                    .any(|w| w == *name),
                "'{name}' is not drawn:\n{text}"
            );
        }
        for op in crate::sip::dsl::operator_tokens() {
            assert!(text.contains(op), "'{op}' is not drawn:\n{text}");
        }
        assert!(
            row_with(&text, "F1 or Esc").is_some(),
            "how to close it:\n{text}"
        );
        assert!(
            row_with(&text, "REGISTER").is_none(),
            "the boxes are covered:\n{text}"
        );
        assert!(
            row_with(&text, "Expression:").is_some(),
            "the fields stay:\n{text}"
        );
        Ok(())
    }

    /// The dialog's key line names F1.
    #[test]
    fn the_key_line_names_f1() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        let text = screen(&mut app, 80, 24)?;
        let row = row_with(&text, "Tab move").ok_or("the key line")?;
        assert!(row.contains("F1 fields"), "{row:?}");
        Ok(())
    }

    /// Opening the dialog from the RTP streams view lists the run's named
    /// filters too, as opening it from the call list does.
    #[test]
    fn opening_from_the_stream_list_lists_the_named_filters() -> Result<(), TestError> {
        let mut app = fixture_app()?;
        app.active_popup = None;
        app.named_filters = super::expression_tests::big_table()?;
        app.current_view = crate::tui::View::StreamList;
        crate::tui::controllers::handle_key_event(&mut app, key(KeyCode::F(7)));
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "opened");
        assert_eq!(
            app.filter_dialog.known_names,
            ["big"],
            "the names are listed"
        );
        Ok(())
    }
}

/// `F2` in the filter dialog: save the dialog's filter under a name in the
/// config's `[filters]` table.
#[cfg(test)]
mod save_named_tests {
    use super::expression_tests::{big_table, fixture_app, ids, key, row_with, screen, shown};
    use super::*;
    use crate::tui::Popup;

    type TestError = Box<dyn std::error::Error>;

    /// The fixture with `big` defined, the dialog open, and saves going to
    /// `sipnab.toml` in a fresh directory, which the caller keeps alive.
    fn saving_app() -> Result<(App, tempfile::TempDir, std::path::PathBuf), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        let mut app = fixture_app()?;
        app.named_filters = big_table()?;
        app.column_config_path = Ok(path.clone());
        open_filter_dialog(&mut app);
        Ok((app, dir, path))
    }

    fn press(app: &mut App, code: KeyCode) {
        handle_filter_popup_key(app, key(code));
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            press(app, KeyCode::Char(c));
        }
    }

    /// F2, the name typed, Enter.
    fn save_as(app: &mut App, name: &str) {
        press(app, KeyCode::F(2));
        type_text(app, name);
        press(app, KeyCode::Enter);
    }

    /// The `[filters]` table of the file at `path`.
    fn saved(
        path: &std::path::Path,
    ) -> Result<std::collections::BTreeMap<String, String>, TestError> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str::<crate::config::Config>(&text)?.filters)
    }

    // ── success ────────────────────────────────────────────────────────

    /// F2 with an expression typed opens the name prompt, empty.
    #[test]
    fn f2_opens_the_name_prompt() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        assert_eq!(
            app.filter_dialog.save_name.as_deref(),
            Some(""),
            "prompt open"
        );
        assert!(app.filter_dialog.error.is_none(), "no error");
        Ok(())
    }

    /// Typed characters go to the prompt, not to a field.
    #[test]
    fn typing_fills_the_prompt_not_the_field() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        app.filter_dialog.focused_field = EXPRESSION_FIELD_IDX;
        app.filter_dialog.sync_cursor();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "large");
        assert_eq!(
            app.filter_dialog.save_name.as_deref(),
            Some("large"),
            "prompt"
        );
        assert_eq!(
            app.filter_dialog.expression, "msg_count > 5",
            "field untouched"
        );
        Ok(())
    }

    /// Enter writes the entry to the config file.
    #[test]
    fn enter_writes_the_entry() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert_eq!(
            saved(&path)?.get("large").map(String::as_str),
            Some("msg_count > 5"),
            "written to [filters]"
        );
        Ok(())
    }

    /// The saved name is listed beside Named filter at once.
    #[test]
    fn the_saved_name_is_listed_at_once() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert_eq!(app.filter_dialog.known_names, ["big", "large"], "listed");
        Ok(())
    }

    /// The run's table holds the new name, so `@large` resolves.
    #[test]
    fn the_run_table_holds_the_new_name() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert_eq!(
            app.named_filters.expansion("large"),
            Some("msg_count > 5"),
            "in the table"
        );
        Ok(())
    }

    /// The dialog says where the name was saved.
    #[test]
    fn the_notice_names_the_filter_and_the_file() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        let notice = app.filter_dialog.notice.clone().ok_or("no notice")?;
        assert!(
            notice.contains("@large") && notice.contains(&path.display().to_string()),
            "notice: {notice}"
        );
        Ok(())
    }

    /// After a save the prompt is closed and the dialog stays open.
    #[test]
    fn the_prompt_closes_and_the_dialog_stays() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert!(app.filter_dialog.save_name.is_none(), "prompt closed");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "dialog open");
        Ok(())
    }

    /// The dialog's own fields and the Expression are saved together.
    #[test]
    fn fields_and_expression_are_saved_together() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.sip_from = "alice".into();
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "alice-big");
        assert_eq!(
            saved(&path)?.get("alice-big").map(String::as_str),
            Some("from.user =~ 'alice' AND (msg_count > 5)"),
            "both parts saved"
        );
        Ok(())
    }

    /// A typed `@name` is saved as written, so it follows that entry.
    #[test]
    fn a_typed_reference_is_saved_as_written() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "@big AND from.user == 'bob'".into();
        save_as(&mut app, "bob-big");
        assert_eq!(
            saved(&path)?.get("bob-big").map(String::as_str),
            Some("@big AND from.user == 'bob'"),
            "the reference kept"
        );
        Ok(())
    }

    /// A built-in alias typed as the whole Expression is saved as `@alias`.
    #[test]
    fn a_typed_alias_is_saved_as_a_reference() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "problems".into();
        save_as(&mut app, "trouble");
        assert_eq!(
            saved(&path)?.get("trouble").map(String::as_str),
            Some("@problems"),
            "the alias as a reference"
        );
        Ok(())
    }

    /// The Named filter field is saved as its references.
    #[test]
    fn the_named_field_is_saved_as_references() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.named = "big".into();
        save_as(&mut app, "big2");
        assert_eq!(
            saved(&path)?.get("big2").map(String::as_str),
            Some("@big"),
            "ref"
        );
        Ok(())
    }

    /// The saved name, applied from Named filter, selects what the dialog's
    /// filter selected.
    #[test]
    fn the_saved_name_applies_the_same_selection() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.sip_from = "alice".into();
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "alice-big");
        app.filter_dialog.clear();
        app.filter_dialog.named = "alice-big".into();
        apply_filter_dialog(&mut app);
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert_eq!(shown(&mut app), ids(&["foo-big"]), "alice's big call");
        Ok(())
    }

    /// A save keeps the comments and other settings of the file.
    #[test]
    fn a_save_keeps_the_file() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        std::fs::write(&path, "# my settings\n[capture]\ninterface = \"eth0\"\n")?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        let text = std::fs::read_to_string(&path)?;
        assert!(
            text.starts_with("# my settings\n[capture]\ninterface = \"eth0\"\n"),
            "kept:\n{text}"
        );
        Ok(())
    }

    /// The dialog's key line names F2.
    #[test]
    fn the_key_line_names_f2() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        let text = screen(&mut app, 80, 24)?;
        let row = row_with(&text, "Tab move").ok_or("the key line")?;
        assert!(row.contains("F2 save"), "{row:?}");
        Ok(())
    }

    /// The open prompt is drawn with the typed name.
    #[test]
    fn the_prompt_is_drawn() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "large");
        let text = screen(&mut app, 80, 24)?;
        assert!(
            row_with(&text, "Save as: @large").is_some(),
            "the prompt row:\n{text}"
        );
        Ok(())
    }

    /// The notice is drawn after a save.
    #[test]
    fn the_notice_is_drawn() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        let text = screen(&mut app, 80, 24)?;
        assert!(
            row_with(&text, "Saved @large").is_some(),
            "notice row:\n{text}"
        );
        Ok(())
    }

    // ── The notice and refusal are whole in the dialog ─────────────────

    /// The rows inside the filter dialog's border, drawn at `w` x `h`.
    fn dialog_rows(app: &mut App, w: u16, h: u16) -> Result<Vec<String>, TestError> {
        let text = screen(app, w, h)?;
        let popup =
            crate::tui::render::centered_popup(ratatui::layout::Rect::new(0, 0, w, h), 76, 23);
        let (left, right) = (
            usize::from(popup.x) + 1,
            usize::from(popup.x + popup.width) - 1,
        );
        Ok(text
            .lines()
            .skip(usize::from(popup.y) + 1)
            .take(usize::from(popup.height.saturating_sub(2)))
            .map(|line| {
                let row: String = line.chars().skip(left).take(right - left).collect();
                row.trim_end().to_owned()
            })
            .collect())
    }

    /// `text` without its white space, to find a wrapped message whole.
    fn squash(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// An app whose save target is a path longer than the dialog is wide.
    fn long_path_app() -> Result<(App, tempfile::TempDir, std::path::PathBuf), TestError> {
        let (mut app, dir, _) = saving_app()?;
        let path = dir
            .path()
            .join("voice-operations-shared-configuration")
            .join("site-a-primary-and-secondary-proxies")
            .join("sipnab.toml");
        app.column_config_path = Ok(path.clone());
        Ok((app, dir, path))
    }

    // success

    /// The live case at the 76-column default: the saved notice holds the
    /// whole path, however long.
    #[test]
    fn the_saved_path_is_whole_at_76_columns() -> Result<(), TestError> {
        let (mut app, _dir, path) = long_path_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "bigcalls");
        assert!(path.is_file(), "saved");
        let rows = dialog_rows(&mut app, 80, 24)?;
        let want = format!("Saved @bigcalls to {}", path.display());
        assert!(
            squash(&rows.join("")).contains(&squash(&want)),
            "the whole notice {want:?}:\n{}",
            rows.join("\n")
        );
        Ok(())
    }

    /// The same at the dialog's minimum size, 40 columns.
    #[test]
    fn the_saved_path_is_whole_at_the_minimum_size() -> Result<(), TestError> {
        let (mut app, _dir, path) = long_path_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "bigcalls");
        let rows = dialog_rows(&mut app, 40, 24)?;
        let want = format!("Saved @bigcalls to {}", path.display());
        assert!(
            squash(&rows.join("")).contains(&squash(&want)),
            "the whole notice {want:?}:\n{}",
            rows.join("\n")
        );
        Ok(())
    }

    /// The live test's 160 x 45 terminal: the notice is whole.
    #[test]
    fn the_saved_path_is_whole_at_160_columns() -> Result<(), TestError> {
        let (mut app, _dir, path) = long_path_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "bigcalls");
        let rows = dialog_rows(&mut app, 160, 45)?;
        let want = format!("Saved @bigcalls to {}", path.display());
        assert!(
            squash(&rows.join("")).contains(&squash(&want)),
            "the whole notice {want:?}:\n{}",
            rows.join("\n")
        );
        Ok(())
    }

    /// The live case's refusal of a name the file already holds is whole
    /// at the minimum size, and the prompt with the typed name stays.
    #[test]
    fn the_duplicate_refusal_is_whole_with_its_prompt() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        std::fs::write(&path, "[filters]\nbigcalls = \"msg_count > 9\"\n")?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "bigcalls");
        let err = app.filter_dialog.error.clone().ok_or("refused")?;
        let rows = dialog_rows(&mut app, 40, 24)?;
        assert!(
            squash(&rows.join("")).contains(&squash(&format!("\u{26a0} {err}"))),
            "the whole refusal {err:?}:\n{}",
            rows.join("\n")
        );
        assert!(
            rows.iter().any(|r| r.contains("Save as: @bigcalls")),
            "the prompt stays:\n{}",
            rows.join("\n")
        );
        Ok(())
    }

    /// A file under `$HOME` is written from `~`.
    #[test]
    fn a_path_under_home_starts_with_a_tilde() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/example");
        let path = std::path::Path::new("/home/example/.config/sipnab/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(home)),
            "~/.config/sipnab/sipnab.toml",
            "home as ~"
        );
        Ok(())
    }

    /// The notice reads "Saved @name to ~/…".
    #[test]
    fn the_saved_notice_uses_the_tilde() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/example");
        let path = std::path::Path::new("/home/example/.config/sipnab/sipnab.toml");
        assert_eq!(
            saved_notice("bigcalls", path, Some(home)),
            "Saved @bigcalls to ~/.config/sipnab/sipnab.toml",
            "the notice"
        );
        Ok(())
    }

    /// A deep path under home keeps every component after the `~`.
    #[test]
    fn a_deep_path_under_home_keeps_its_components() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/srv/users/example");
        let path = std::path::Path::new("/srv/users/example/a/b/c/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(home)),
            "~/a/b/c/sipnab.toml",
            "every component kept"
        );
        Ok(())
    }

    // failure

    /// A path outside home is shown whole, unchanged.
    #[test]
    fn a_path_outside_home_is_unchanged() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/example");
        let path = std::path::Path::new("/etc/sipnab/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(home)),
            "/etc/sipnab/sipnab.toml",
            "unchanged"
        );
        Ok(())
    }

    /// A sibling whose name starts with home's is not inside home.
    #[test]
    fn a_sibling_of_home_is_unchanged() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/ex");
        let path = std::path::Path::new("/home/example/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(home)),
            "/home/example/sipnab.toml",
            "a component boundary, not a string prefix"
        );
        Ok(())
    }

    /// A home of `/` would turn every path into `~/…`: it is not used.
    #[test]
    fn a_root_home_is_not_used() -> Result<(), TestError> {
        let path = std::path::Path::new("/etc/sipnab/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(std::ffi::OsStr::new("/"))),
            "/etc/sipnab/sipnab.toml",
            "unchanged"
        );
        Ok(())
    }

    /// A relative home is not a place: it is not used.
    #[test]
    fn a_relative_home_is_not_used() -> Result<(), TestError> {
        let path = std::path::Path::new("example/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(std::ffi::OsStr::new("example"))),
            "example/sipnab.toml",
            "unchanged"
        );
        Ok(())
    }

    /// An empty home is not used.
    #[test]
    fn an_empty_home_is_not_used() -> Result<(), TestError> {
        let path = std::path::Path::new("/home/example/sipnab.toml");
        assert_eq!(
            home_relative(path, Some(std::ffi::OsStr::new(""))),
            "/home/example/sipnab.toml",
            "unchanged"
        );
        Ok(())
    }

    /// No home at all: the path is shown whole.
    #[test]
    fn no_home_leaves_the_path() -> Result<(), TestError> {
        let path = std::path::Path::new("/home/example/sipnab.toml");
        assert_eq!(
            home_relative(path, None),
            "/home/example/sipnab.toml",
            "unchanged"
        );
        Ok(())
    }

    /// Esc after a refusal clears it, and the buttons are drawn again in
    /// the rows it took.
    #[test]
    fn esc_after_a_refusal_gives_the_rows_back() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        std::fs::write(&path, "[filters]\nbigcalls = \"msg_count > 9\"\n")?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "bigcalls");
        assert!(app.filter_dialog.error.is_some(), "refused");
        press(&mut app, KeyCode::Esc);
        let rows = dialog_rows(&mut app, 40, 24)?;
        assert!(
            rows.iter().any(|r| r.contains("[ Filter ]")),
            "the buttons are back:\n{}",
            rows.join("\n")
        );
        assert!(
            !rows.iter().any(|r| r.contains("already defines")),
            "the refusal is gone:\n{}",
            rows.join("\n")
        );
        Ok(())
    }

    // edge

    /// The home directory itself is `~`.
    #[test]
    fn home_itself_is_a_tilde() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/example");
        assert_eq!(
            home_relative(std::path::Path::new("/home/example"), Some(home)),
            "~",
            "home alone"
        );
        Ok(())
    }

    /// A home given with a trailing slash still matches.
    #[test]
    fn a_home_with_a_trailing_slash_matches() -> Result<(), TestError> {
        let home = std::ffi::OsStr::new("/home/example/");
        let path = std::path::Path::new("/home/example/sipnab.toml");
        assert_eq!(home_relative(path, Some(home)), "~/sipnab.toml", "matched");
        Ok(())
    }

    /// A file name that is not UTF-8 is shown with replacement characters
    /// after the `~`, as the full path would be.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_name_under_home_is_shown() -> Result<(), TestError> {
        use std::os::unix::ffi::OsStrExt as _;
        let home = std::ffi::OsStr::new("/home/example");
        let path = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/home/example/s\xffp.toml"));
        assert_eq!(
            home_relative(path, Some(home)),
            "~/s\u{fffd}p.toml",
            "lossy, as display"
        );
        Ok(())
    }

    // ── failure ────────────────────────────────────────────────────────

    /// F2 with every field empty refuses and opens no prompt.
    #[test]
    fn nothing_to_save_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.save_name.is_none(), "no prompt");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("Nothing to save"), "reason: {err}");
        Ok(())
    }

    /// A time window cannot be part of a named filter.
    #[test]
    fn a_time_window_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        app.filter_dialog.time_after = "2026-01-01T00:00:00Z".into();
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.save_name.is_none(), "no prompt");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("After and Before"), "reason: {err}");
        Ok(())
    }

    /// With no method checked there is no expression to save.
    #[test]
    fn no_method_checked_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        app.filter_dialog.methods = [false; 10];
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.save_name.is_none(), "no prompt");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("no SIP method"), "reason: {err}");
        Ok(())
    }

    /// A name the run already defines is refused; the prompt stays open
    /// and nothing is written.
    #[test]
    fn a_duplicate_name_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "big");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("already defines 'big'"), "reason: {err}");
        assert_eq!(
            app.filter_dialog.save_name.as_deref(),
            Some("big"),
            "prompt kept"
        );
        assert!(!path.exists(), "nothing written");
        Ok(())
    }

    /// A name with a space is refused with the naming rule.
    #[test]
    fn a_name_with_a_space_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "my calls");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("not usable"), "reason: {err}");
        assert!(!path.exists(), "nothing written");
        Ok(())
    }

    /// A built-in alias name is refused.
    #[test]
    fn a_built_in_alias_name_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "problems");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("built-in alias"), "reason: {err}");
        assert!(!path.exists(), "nothing written");
        Ok(())
    }

    /// An empty name is refused.
    #[test]
    fn an_empty_name_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "");
        assert!(app.filter_dialog.error.is_some(), "refused");
        assert!(!path.exists(), "nothing written");
        Ok(())
    }

    /// An Expression that does not parse is refused with the parser's
    /// message, and nothing is written.
    #[test]
    fn an_invalid_expression_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count >> 5".into();
        save_as(&mut app, "large");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(
            err.contains("not a valid filter expression"),
            "reason: {err}"
        );
        assert!(!path.exists(), "nothing written");
        assert!(
            app.named_filters.expansion("large").is_none(),
            "not in the table"
        );
        Ok(())
    }

    /// With no file to save to, the name is kept for this session, and the
    /// note gives the reason.
    #[test]
    fn no_save_target_keeps_the_name_for_the_session() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.column_config_path = Err("not saved: no config file for this session".into());
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert!(app.filter_dialog.error.is_none(), "not refused");
        let note = app.filter_dialog.session_note.clone().ok_or("no note")?;
        assert!(
            note.lines
                .join("\n")
                .contains("no config file for this session"),
            "reason: {note:?}"
        );
        assert_eq!(
            app.named_filters.expansion("large"),
            Some("msg_count > 5"),
            "in the table"
        );
        Ok(())
    }

    /// A file that gained the name since the run started is not
    /// overwritten, and the run's table is unchanged.
    #[test]
    fn a_name_added_to_the_file_meanwhile_is_refused() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        let before = "[filters]\nlarge = \"msg_count > 9\"\n";
        std::fs::write(&path, before)?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("already defines 'large'"), "reason: {err}");
        assert_eq!(std::fs::read_to_string(&path)?, before, "file untouched");
        assert!(
            app.named_filters.expansion("large").is_none(),
            "not in the table"
        );
        Ok(())
    }

    /// A save target that cannot be read is refused, and nothing changes.
    #[test]
    fn an_unreadable_target_is_refused() -> Result<(), TestError> {
        let (mut app, dir, _) = saving_app()?;
        app.column_config_path = Ok(dir.path().to_path_buf());
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        let err = app.filter_dialog.error.clone().ok_or("no error")?;
        assert!(err.contains("Refusing to save"), "reason: {err}");
        assert!(
            app.named_filters.expansion("large").is_none(),
            "not in the table"
        );
        Ok(())
    }

    /// A refused save shows no success notice.
    #[test]
    fn a_refused_save_shows_no_notice() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "big");
        assert!(app.filter_dialog.notice.is_none(), "no notice");
        Ok(())
    }

    // ── edge ───────────────────────────────────────────────────────────

    /// Esc closes the prompt only; the dialog and its fields stay.
    #[test]
    fn esc_closes_only_the_prompt() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "large");
        press(&mut app, KeyCode::Esc);
        assert!(app.filter_dialog.save_name.is_none(), "prompt closed");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "dialog open");
        assert_eq!(app.filter_dialog.expression, "msg_count > 5", "field kept");
        assert!(!path.exists(), "nothing written");
        Ok(())
    }

    /// A second Esc closes the dialog as before.
    #[test]
    fn a_second_esc_closes_the_dialog() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.active_popup, None, "dialog closed");
        Ok(())
    }

    /// Backspace removes the last character, a multibyte one whole.
    #[test]
    fn backspace_removes_one_character() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        type_text(&mut app, "ab\u{e9}");
        press(&mut app, KeyCode::Backspace);
        assert_eq!(
            app.filter_dialog.save_name.as_deref(),
            Some("ab"),
            "one char"
        );
        press(&mut app, KeyCode::Backspace);
        press(&mut app, KeyCode::Backspace);
        press(&mut app, KeyCode::Backspace);
        assert_eq!(
            app.filter_dialog.save_name.as_deref(),
            Some(""),
            "empty, no panic"
        );
        Ok(())
    }

    /// A name typed with its `@` is saved without it.
    #[test]
    fn a_leading_at_sign_is_dropped() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "@large");
        assert!(saved(&path)?.contains_key("large"), "saved as large");
        Ok(())
    }

    /// Spaces around the name are dropped.
    #[test]
    fn surrounding_spaces_are_dropped() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "  large ");
        assert!(saved(&path)?.contains_key("large"), "saved as large");
        Ok(())
    }

    /// Tab and F9 do nothing while the prompt is open.
    #[test]
    fn other_dialog_keys_wait_for_the_prompt() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        let focus = app.filter_dialog.focused_field;
        press(&mut app, KeyCode::F(2));
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::F(9));
        assert_eq!(app.filter_dialog.focused_field, focus, "focus kept");
        assert_eq!(app.filter_dialog.expression, "msg_count > 5", "not cleared");
        assert_eq!(app.active_popup, Some(Popup::FilterDialog), "dialog open");
        Ok(())
    }

    /// Opening the dialog again starts with no prompt and no notice.
    #[test]
    fn reopening_clears_prompt_and_notice() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        press(&mut app, KeyCode::F(2));
        open_filter_dialog(&mut app);
        assert!(app.filter_dialog.save_name.is_none(), "no prompt");
        assert!(app.filter_dialog.notice.is_none(), "no notice");
        Ok(())
    }

    /// Two saves in a row are both listed and both written.
    #[test]
    fn two_saves_in_a_row_are_both_kept() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        app.filter_dialog.expression = "msg_count > 2".into();
        save_as(&mut app, "medium");
        assert_eq!(
            app.filter_dialog.known_names,
            ["big", "large", "medium"],
            "listed"
        );
        assert_eq!(saved(&path)?.len(), 2, "both written");
        Ok(())
    }

    /// The new name may be used by the next save at once.
    #[test]
    fn a_saved_name_can_be_referenced_at_once() -> Result<(), TestError> {
        let (mut app, _dir, path) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        app.filter_dialog.expression = "@large AND from.user == 'bob'".into();
        save_as(&mut app, "bob-large");
        assert!(
            app.filter_dialog.error.is_none(),
            "{:?}",
            app.filter_dialog.error
        );
        assert!(saved(&path)?.contains_key("bob-large"), "written");
        Ok(())
    }

    /// F2 again after a refusal clears the old error when the prompt opens.
    #[test]
    fn f2_clears_an_earlier_error() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.error.is_some(), "refused first");
        app.filter_dialog.expression = "msg_count > 5".into();
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.error.is_none(), "error cleared");
        assert!(app.filter_dialog.save_name.is_some(), "prompt open");
        Ok(())
    }

    /// Blank time fields do not count as a window.
    #[test]
    fn blank_time_fields_are_no_window() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        app.filter_dialog.expression = "msg_count > 5".into();
        app.filter_dialog.time_before = "   ".into();
        press(&mut app, KeyCode::F(2));
        assert!(app.filter_dialog.save_name.is_some(), "prompt open");
        Ok(())
    }

    /// A save does not apply the filter: the call list is unchanged.
    #[test]
    fn a_save_does_not_apply_the_filter() -> Result<(), TestError> {
        let (mut app, _dir, _) = saving_app()?;
        let before = shown(&mut app);
        app.filter_dialog.expression = "msg_count > 5".into();
        save_as(&mut app, "large");
        assert_eq!(shown(&mut app), before, "list unchanged");
        assert!(app.active_filter.is_none(), "no filter in force");
        Ok(())
    }

    /// `F2` where no config file may be written: the name is kept for this
    /// session only, the note says why and how to keep it, and every refusal
    /// that is not about where to write still refuses with nothing added.
    #[cfg(unix)]
    mod session_only {
        use super::*;
        use crate::config::save_permission_tests::{Locked, chmod_probe, temp_files};
        use crate::tui::StatusMessage;

        /// `true` to run: a mode the case sets denies this process (see
        /// `chmod_probe`; CI requires `non-root`, so it never skips there).
        fn denied() -> bool {
            crate::test_prereq::present("non-root", crate::test_prereq::NON_ROOT, chmod_probe())
        }

        /// [`saving_app`] saving into a directory of mode 0500: the file
        /// cannot be made. The guard restores the mode on drop.
        fn locked_app() -> Result<(App, tempfile::TempDir, Locked, std::path::PathBuf), TestError> {
            let (mut app, dir, _) = saving_app()?;
            let locked = Locked::new(dir.path().join("conf"), 0o500, true)?;
            let path = locked.path.join("sipnab.toml");
            app.column_config_path = Ok(path.clone());
            Ok((app, dir, locked, path))
        }

        /// [`saving_app`] with `text` in a read-only file.
        fn read_only_app(
            text: &str,
        ) -> Result<(App, tempfile::TempDir, Locked, std::path::PathBuf), TestError> {
            let (app, dir, path) = saving_app()?;
            std::fs::write(&path, text)?;
            let locked = Locked::new(path.clone(), 0o444, false)?;
            Ok((app, dir, locked, path))
        }

        /// The note's lines, joined, or a test error.
        fn note_text(app: &App) -> Result<String, TestError> {
            Ok(app
                .filter_dialog
                .session_note
                .as_ref()
                .ok_or("no session note")?
                .lines
                .join("\n"))
        }

        /// Asserts a refusal: the reason shown, nothing added, no note, no
        /// notice.
        fn assert_refused(app: &App, name: &str, reason: &str) -> Result<(), TestError> {
            let err = app.filter_dialog.error.clone().ok_or("no error")?;
            assert!(err.contains(reason), "reason {reason:?}: {err}");
            assert!(
                app.named_filters.expansion(name).is_none(),
                "{name} not in the table"
            );
            assert!(
                !app.filter_dialog.known_names.iter().any(|n| n == name),
                "{name} not listed"
            );
            assert!(app.filter_dialog.session_note.is_none(), "no session note");
            assert!(app.filter_dialog.notice.is_none(), "no notice");
            Ok(())
        }

        static COPIED: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

        /// A copy that records the text, never touching a clipboard.
        fn fake_copy(text: &str) -> StatusMessage {
            COPIED.lock().push(text.to_owned());
            StatusMessage::info(format!("Copied {} bytes (test)", text.len()))
        }

        // ── success ────────────────────────────────────────────────────

        /// A directory that cannot be created: the name is in the run's
        /// table.
        #[test]
        fn an_unwritable_ancestor_keeps_the_name() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, dir, _) = saving_app()?;
            let _locked = Locked::new(dir.path().join("home"), 0o500, true)?;
            let path = dir.path().join("home/.config/sipnab/sipnab.toml");
            app.column_config_path = Ok(path.clone());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert!(
                app.filter_dialog.error.is_none(),
                "not refused: {:?}",
                app.filter_dialog.error
            );
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "in the table"
            );
            assert!(!dir.path().join("home/.config").exists(), "nothing created");
            Ok(())
        }

        /// The kept name is listed beside Named filter at once.
        #[test]
        fn the_kept_name_is_listed_at_once() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, _) = locked_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(app.filter_dialog.known_names, ["big", "large"], "listed");
            Ok(())
        }

        /// The kept name works as `@large`, selecting what its definition
        /// selects.
        #[test]
        fn the_kept_name_works_as_a_reference() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, _) = locked_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            super::super::expression_tests::apply_typed(&mut app, "msg_count > 5");
            let want = shown(&mut app);
            super::super::expression_tests::apply_typed(&mut app, "@large");
            assert!(
                app.filter_dialog.error.is_none(),
                "resolved: {:?}",
                app.filter_dialog.error
            );
            assert_eq!(shown(&mut app), want, "same calls as the definition");
            Ok(())
        }

        /// A directory that exists but may not be written: kept, no file,
        /// no temp file.
        #[test]
        fn an_unwritable_directory_keeps_the_name_and_leaves_nothing() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, locked, path) = locked_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "kept"
            );
            assert!(!path.exists(), "no file");
            assert!(temp_files(&locked.path)?.is_empty(), "no temp file");
            Ok(())
        }

        /// A read-only file: kept for the session, the file byte-for-byte
        /// as it was.
        #[test]
        fn a_read_only_file_is_unchanged_and_the_name_kept() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, dir, _locked, path) = read_only_app("# mine\n")?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(
                std::fs::read_to_string(&path)?,
                "# mine\n",
                "file unchanged"
            );
            assert!(temp_files(dir.path())?.is_empty(), "no temp file");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "kept"
            );
            Ok(())
        }

        /// A symlink to a read-only file: kept, the link and its target as
        /// they were.
        #[test]
        fn a_symlink_to_a_read_only_file_is_unchanged() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, dir, _) = saving_app()?;
            let target = dir.path().join("shared.toml");
            std::fs::write(&target, "# shared\n")?;
            let _locked = Locked::new(target.clone(), 0o444, false)?;
            let link = dir.path().join("link.toml");
            std::os::unix::fs::symlink(&target, &link)?;
            app.column_config_path = Ok(link.clone());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert!(
                std::fs::symlink_metadata(&link)?.file_type().is_symlink(),
                "still a link"
            );
            assert_eq!(
                std::fs::read_to_string(&target)?,
                "# shared\n",
                "target unchanged"
            );
            assert!(
                app.filter_dialog.session_note.is_some(),
                "kept for the session"
            );
            Ok(())
        }

        /// A file that cannot be read for permission: kept, and the note
        /// says a same-named entry there could not be checked.
        #[test]
        fn an_unreadable_file_keeps_the_name_with_a_warning() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, path) = saving_app()?;
            std::fs::write(&path, "")?;
            let _locked = Locked::new(path.clone(), 0o000, false)?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = note_text(&app)?;
            assert!(text.contains("could not be checked"), "{text}");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "kept"
            );
            Ok(())
        }

        /// The note says plainly that the name is kept for this session
        /// only, with the path and the cause.
        #[test]
        fn the_note_names_the_session_the_path_and_the_cause() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, path) = locked_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = note_text(&app)?;
            assert!(text.contains("Kept @large for this session only"), "{text}");
            assert!(text.contains(&path.display().to_string()), "path: {text}");
            assert!(
                text.to_lowercase().contains("permission denied"),
                "cause: {text}"
            );
            assert!(!text.contains(".sipnab-tmp-"), "no temp name: {text}");
            Ok(())
        }

        /// The note says how to keep it.
        #[test]
        fn the_note_says_how_to_keep_it() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, _) = locked_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = note_text(&app)?;
            for needle in [
                "--config <writable file>",
                "$SIPNAB_CONFIG",
                "fix the permissions",
            ] {
                assert!(text.contains(needle), "{needle}: {text}");
            }
            Ok(())
        }

        /// The note shows the exact `[filters]` entry to add.
        #[test]
        fn the_note_shows_the_entry_to_add() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, _) = locked_app()?;
            app.filter_dialog.expression = "to.user == '7000'".into();
            save_as(&mut app, "sales");
            let note = app.filter_dialog.session_note.clone().ok_or("no note")?;
            assert!(note.lines.iter().any(|l| l == "[filters]"), "{note:?}");
            assert!(
                note.lines
                    .iter()
                    .any(|l| l == "sales = \"to.user == '7000'\""),
                "{note:?}"
            );
            assert_eq!(note.entry, "sales = \"to.user == '7000'\"", "the entry");
            Ok(())
        }

        /// The system file refusal keeps the name and gives its reason.
        #[test]
        fn the_system_file_keeps_the_name_for_the_session() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = crate::config::save_target(
                Some(std::path::Path::new(crate::config::SYSTEM_CONFIG_PATH)),
                None,
            );
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = note_text(&app)?;
            assert!(text.contains(crate::config::SYSTEM_CONFIG_PATH), "{text}");
            assert!(text.contains("--config <writable file>"), "{text}");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "kept"
            );
            Ok(())
        }

        /// No `$HOME`: kept, and the note says why.
        #[test]
        fn no_home_keeps_the_name_for_the_session() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = crate::config::save_target(None, None);
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = note_text(&app)?;
            assert!(text.contains("$HOME"), "{text}");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "kept"
            );
            Ok(())
        }

        /// `F3` copies the entry line, and the status line says so.
        #[test]
        fn f3_copies_the_entry_line() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "to.user == '7001'".into();
            save_as(&mut app, "copyme");
            copy_session_entry_with(&mut app, fake_copy);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while app.async_messages.lock().is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the copy worker never reported"
                );
                std::thread::yield_now();
            }
            assert!(
                COPIED
                    .lock()
                    .iter()
                    .any(|t| t == "copyme = \"to.user == '7001'\""),
                "copied: {:?}",
                COPIED.lock()
            );
            let status = app.status_error.clone().unwrap_or_default();
            assert!(status.contains("Copying"), "status: {status}");
            Ok(())
        }

        /// The note is drawn in the dialog.
        #[test]
        fn the_note_is_drawn() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let text = screen(&mut app, 100, 40)?;
            assert!(
                row_with(&text, "Kept @large for this session only").is_some(),
                "{text}"
            );
            assert!(
                row_with(&text, "large = \"msg_count > 5\"").is_some(),
                "{text}"
            );
            assert!(row_with(&text, "F3 copies").is_some(), "{text}");
            Ok(())
        }

        /// A writable file still saves to the file, with no session note.
        #[test]
        fn a_writable_file_still_saves_without_a_note() -> Result<(), TestError> {
            let (mut app, _dir, path) = saving_app()?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert!(app.filter_dialog.session_note.is_none(), "no note");
            assert_eq!(
                saved(&path)?.get("large").map(String::as_str),
                Some("msg_count > 5"),
                "written to the file"
            );
            Ok(())
        }

        // ── failure ────────────────────────────────────────────────────

        /// A session-only save is not a success: no "Saved" notice.
        #[test]
        fn a_session_only_save_shows_no_success_notice() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert!(
                app.filter_dialog.notice.is_none(),
                "no notice: {:?}",
                app.filter_dialog.notice
            );
            assert!(app.filter_dialog.session_note.is_some(), "the note instead");
            Ok(())
        }

        /// A name that is not usable is refused even with nowhere to write.
        #[test]
        fn an_unusable_name_is_refused() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "my calls");
            assert_refused(&app, "my calls", "not usable")
        }

        /// A name the run defines is refused with nowhere to write.
        #[test]
        fn a_duplicate_is_refused_with_nowhere_to_write() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "big");
            let err = app.filter_dialog.error.clone().ok_or("no error")?;
            assert!(err.contains("already defines 'big'"), "{err}");
            assert_eq!(
                app.named_filters.expansion("big"),
                Some("msg_count > 5"),
                "big unchanged"
            );
            assert!(app.filter_dialog.session_note.is_none(), "no note");
            Ok(())
        }

        /// A second save of a session-only name is a duplicate.
        #[test]
        fn a_second_save_of_a_kept_name_is_a_duplicate() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            app.filter_dialog.expression = "msg_count > 1".into();
            save_as(&mut app, "large");
            let err = app.filter_dialog.error.clone().ok_or("no error")?;
            assert!(err.contains("already defines 'large'"), "{err}");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "first kept"
            );
            Ok(())
        }

        /// An expression that does not parse is refused with nowhere to
        /// write.
        #[test]
        fn a_bad_expression_is_refused() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count >".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "not a valid filter expression")
        }

        /// Nothing to save is refused with nowhere to write.
        #[test]
        fn nothing_to_save_is_refused_with_nowhere_to_write() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            press(&mut app, KeyCode::F(2));
            assert!(app.filter_dialog.save_name.is_none(), "no prompt");
            assert!(app.filter_dialog.session_note.is_none(), "no note");
            Ok(())
        }

        /// A config file that is not valid TOML is refused: nothing kept.
        #[test]
        fn an_invalid_file_is_refused() -> Result<(), TestError> {
            let (mut app, _dir, path) = saving_app()?;
            std::fs::write(&path, "[filters\n")?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "not valid TOML")?;
            assert_eq!(
                std::fs::read_to_string(&path)?,
                "[filters\n",
                "file unchanged"
            );
            Ok(())
        }

        /// `filters` that is not a table is refused: nothing kept.
        #[test]
        fn filters_not_a_table_is_refused() -> Result<(), TestError> {
            let (mut app, _dir, path) = saving_app()?;
            std::fs::write(&path, "filters = 3\n")?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "[filters] is not a table")
        }

        /// A read-only file that already holds the name is a duplicate, not
        /// a session-only save.
        #[test]
        fn a_read_only_file_holding_the_name_is_refused() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, path) =
                read_only_app("[filters]\nlarge = \"msg_count > 9\"\n")?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "already defines 'large'")?;
            assert_eq!(
                std::fs::read_to_string(&path)?,
                "[filters]\nlarge = \"msg_count > 9\"\n",
                "file unchanged"
            );
            Ok(())
        }

        /// A read-only invalid file is refused as invalid, not kept.
        #[test]
        fn a_read_only_invalid_file_is_refused() -> Result<(), TestError> {
            if !denied() {
                return Ok(());
            }
            let (mut app, _dir, _locked, _) = read_only_app("[filters\n")?;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "not valid TOML")
        }

        /// A time window is refused with nowhere to write.
        #[test]
        fn a_time_window_is_refused_with_nowhere_to_write() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            app.filter_dialog.time_before = "2026-01-01T00:00:00Z".into();
            press(&mut app, KeyCode::F(2));
            let err = app.filter_dialog.error.clone().ok_or("no error")?;
            assert!(err.contains("After and Before"), "{err}");
            assert!(app.filter_dialog.session_note.is_none(), "no note");
            Ok(())
        }

        /// A refusal keeps the expression as typed and the prompt open.
        #[test]
        fn a_refusal_keeps_the_expression_and_the_prompt() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count >".into();
            save_as(&mut app, "large");
            assert_eq!(app.filter_dialog.expression, "msg_count >", "as typed");
            assert_eq!(
                app.filter_dialog.save_name.as_deref(),
                Some("large"),
                "prompt kept"
            );
            Ok(())
        }

        /// A directory at the path is still refused, not kept.
        #[test]
        fn a_directory_at_the_path_is_refused() -> Result<(), TestError> {
            let (mut app, dir, _) = saving_app()?;
            app.column_config_path = Ok(dir.path().to_path_buf());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_refused(&app, "large", "Refusing to save")
        }

        // ── edge ───────────────────────────────────────────────────────

        /// The expression stays as typed after a session-only save.
        #[test]
        fn the_expression_stays_as_typed() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(app.filter_dialog.expression, "msg_count > 5", "as typed");
            Ok(())
        }

        /// The prompt closes after a session-only save.
        #[test]
        fn the_prompt_closes() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert!(app.filter_dialog.save_name.is_none(), "prompt closed");
            Ok(())
        }

        /// Esc closes the note first; a second Esc cancels the dialog.
        #[test]
        fn esc_closes_the_note_first() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            press(&mut app, KeyCode::Esc);
            assert!(app.filter_dialog.session_note.is_none(), "note closed");
            assert_eq!(app.active_popup, Some(Popup::FilterDialog), "dialog open");
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.active_popup, None, "then the dialog closes");
            Ok(())
        }

        /// Opening the dialog again drops the note; the name stays listed.
        #[test]
        fn reopening_drops_the_note_and_keeps_the_name() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            open_filter_dialog(&mut app);
            assert!(app.filter_dialog.session_note.is_none(), "note dropped");
            assert_eq!(
                app.filter_dialog.known_names,
                ["big", "large"],
                "still listed"
            );
            Ok(())
        }

        /// A kept name is not written by a later save that can write.
        #[test]
        fn a_kept_name_is_not_written_later() -> Result<(), TestError> {
            let (mut app, _dir, path) = saving_app()?;
            let reachable = app.column_config_path.clone();
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            app.column_config_path = reachable;
            app.filter_dialog.expression = "msg_count > 2".into();
            save_as(&mut app, "medium");
            let file = saved(&path)?;
            assert_eq!(
                file.keys().collect::<Vec<_>>(),
                ["medium"],
                "only the new name: {file:?}"
            );
            Ok(())
        }

        /// A save that writes after a session-only one drops the note and
        /// shows the success notice.
        #[test]
        fn a_later_written_save_replaces_the_note() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            let reachable = app.column_config_path.clone();
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            app.column_config_path = reachable;
            app.filter_dialog.expression = "msg_count > 2".into();
            save_as(&mut app, "medium");
            assert!(app.filter_dialog.session_note.is_none(), "note dropped");
            assert!(
                app.filter_dialog
                    .notice
                    .as_deref()
                    .is_some_and(|n| n.contains("@medium")),
                "the success notice: {:?}",
                app.filter_dialog.notice
            );
            Ok(())
        }

        /// F2 again drops the note while the prompt is open.
        #[test]
        fn f2_drops_the_note() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            press(&mut app, KeyCode::F(2));
            assert!(app.filter_dialog.session_note.is_none(), "note dropped");
            assert_eq!(
                app.filter_dialog.save_name.as_deref(),
                Some(""),
                "prompt open"
            );
            Ok(())
        }

        /// F3 with no note copies nothing and queues no message.
        #[test]
        fn f3_without_a_note_copies_nothing() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            copy_session_entry_with(&mut app, fake_copy);
            assert!(app.async_messages.lock().is_empty(), "no copy started");
            assert!(
                app.status_error.is_none(),
                "no status: {:?}",
                app.status_error
            );
            Ok(())
        }

        /// The entry line round-trips a definition with both quote kinds.
        #[test]
        fn the_entry_round_trips_quotes() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            let def = r#"from.user == "it's" OR to.user == 'say "hi"'"#;
            app.filter_dialog.expression = def.into();
            save_as(&mut app, "quoted");
            let note = app
                .filter_dialog
                .session_note
                .clone()
                .ok_or_else(|| format!("no note; error {:?}", app.filter_dialog.error))?;
            let doc: toml::Table = toml::from_str(&note.entry)?;
            let back = doc.get("quoted").and_then(toml::Value::as_str);
            assert_eq!(
                back,
                app.named_filters.expansion("quoted"),
                "{}",
                note.entry
            );
            Ok(())
        }

        /// The note's entry is the line a config file would hold.
        #[test]
        fn the_entry_is_the_config_line() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            let note = app.filter_dialog.session_note.clone().ok_or("no note")?;
            assert_eq!(
                note.entry,
                crate::config::named_filter_entry_line("large", "msg_count > 5")?,
                "one rule"
            );
            Ok(())
        }

        /// A session-only save does not apply the filter.
        #[test]
        fn a_session_only_save_does_not_apply_the_filter() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            let before = shown(&mut app);
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(shown(&mut app), before, "list unchanged");
            assert!(app.active_filter.is_none(), "no filter in force");
            Ok(())
        }

        static PUBLISHED: parking_lot::Mutex<Vec<Vec<String>>> =
            parking_lot::Mutex::new(Vec::new());

        /// A publisher that records the names of each table it is handed,
        /// never touching the process's live table.
        fn fake_publish(table: crate::sip::named_filters::NamedFilters) {
            PUBLISHED
                .lock()
                .push(table.names().map(str::to_owned).collect());
        }

        /// Whether some recorded publish held exactly `names`.
        fn was_published(names: &[&str]) -> bool {
            PUBLISHED
                .lock()
                .iter()
                .any(|t| t.iter().map(String::as_str).eq(names.iter().copied()))
        }

        /// A save to the file publishes the run's new table.
        #[test]
        fn a_file_save_publishes_the_table() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.filter_publisher = Some(fake_publish);
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "pubfile");
            assert!(
                was_published(&["big", "pubfile"]),
                "published: {:?}",
                PUBLISHED.lock()
            );
            Ok(())
        }

        /// A session-only save publishes the run's new table too.
        #[test]
        fn a_session_only_save_publishes_the_table() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_publisher = Some(fake_publish);
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "pubsession");
            assert!(
                was_published(&["big", "pubsession"]),
                "published: {:?}",
                PUBLISHED.lock()
            );
            Ok(())
        }

        /// A refused save publishes nothing.
        #[test]
        fn a_refused_save_publishes_nothing() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.filter_publisher = Some(fake_publish);
            app.filter_dialog.expression = "msg_count >".into();
            save_as(&mut app, "pubrefused");
            assert!(
                !PUBLISHED
                    .lock()
                    .iter()
                    .any(|t| t.iter().any(|n| n == "pubrefused")),
                "not published: {:?}",
                PUBLISHED.lock()
            );
            Ok(())
        }

        /// With no publisher (a test app) a save still works.
        #[test]
        fn a_save_without_a_publisher_still_works() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.filter_publisher = None;
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            assert_eq!(
                app.named_filters.expansion("large"),
                Some("msg_count > 5"),
                "saved"
            );
            Ok(())
        }

        /// Two session-only saves are both kept; the note is the second's.
        #[test]
        fn two_session_only_saves_are_both_kept() -> Result<(), TestError> {
            let (mut app, _dir, _) = saving_app()?;
            app.column_config_path = Err("not saved: test".into());
            app.filter_dialog.expression = "msg_count > 5".into();
            save_as(&mut app, "large");
            app.filter_dialog.expression = "msg_count > 2".into();
            save_as(&mut app, "medium");
            assert_eq!(
                app.filter_dialog.known_names,
                ["big", "large", "medium"],
                "both"
            );
            assert!(note_text(&app)?.contains("@medium"), "the second's note");
            Ok(())
        }
    }
}
