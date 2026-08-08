// SPDX-License-Identifier: MIT OR Apache-2.0

//! The "Name Address" popup: manual IP-to-name mappings.

use crate::tui::*;

/// Source + destination IPs of the selected dialog (for the Name Address
/// popup). Resolved against the same displayed list as the renderer.
///
/// # Returns
/// `(src_addr, dst_addr)` of the highlighted row, or `None` when the
/// displayed list is empty or the selection is out of range. Briefly
/// holds the dialog-store read lock.
pub(in crate::tui) fn get_selected_dialog_endpoints(
    app: &App,
) -> Option<(std::net::IpAddr, std::net::IpAddr)> {
    let store = app.dialog_store.read();
    let dialogs = crate::tui::call_list::displayed_dialogs(
        &store,
        app.active_filter.as_ref(),
        &app.search_query,
        app.call_list.sort_column(),
        app.call_list.sort_ascending(),
    );
    dialogs
        .get(app.call_list.selected())
        .map(|d| (d.src_addr, d.dst_addr))
}

/// Open the "Name Address" popup offering every endpoint in `ips` (de-duplicated,
/// order preserved), with `active` initially focused. Each target is pre-filled
/// with its existing manual name. `Tab`/`Shift-Tab` switch between them.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `ips` - the endpoint addresses to offer; duplicates are dropped.
/// * `active` - index of the target to focus first (clamped to the list).
///
/// # Side effects
/// Populates `app.name_dialog` (targets, active index, cursor at the end
/// of the active name, error cleared) and sets `app.active_popup` to the
/// Name Address popup. A no-op when `ips` de-duplicates to nothing.
pub(in crate::tui) fn open_name_dialog_for(
    app: &mut App,
    ips: Vec<std::net::IpAddr>,
    active: usize,
) {
    let manual = app.resolver.manual_entries();
    let mut targets: Vec<super::NameTarget> = Vec::new();
    // De-dupe on the parsed address (which hashes without allocating) rather
    // than formatting every existing target's IP back into a String on each
    // comparison — the old `t.ip == ip.to_string()` allocated once per
    // (target × ip) and scanned quadratically.
    let mut seen: std::collections::HashSet<std::net::IpAddr> = std::collections::HashSet::new();
    for ip in ips {
        if !seen.insert(ip) {
            continue; // de-dupe (e.g. loopback src == dst)
        }
        let existing = manual
            .iter()
            .find(|(i, _)| *i == ip)
            .map(|(_, n)| n.clone())
            .unwrap_or_default();
        targets.push(super::NameTarget {
            ip: ip.to_string(),
            name: existing,
        });
    }
    if targets.is_empty() {
        return;
    }
    let active = active.min(targets.len() - 1);
    app.name_dialog.cursor = targets[active].name.len();
    app.name_dialog.targets = targets;
    app.name_dialog.active = active;
    app.name_dialog.error = None;
    app.active_popup = Some(Popup::NameAddress);
}

/// Handle keys in the "Name Address" popup. `Tab`/`Shift-Tab` move between the
/// offered endpoints; the other keys edit the active endpoint's name.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (this popup has no keymap
///   bindings).
///
/// # Side effects
/// Esc closes the popup without applying. Enter applies every target via
/// `apply_name_dialog` and closes only on success (a validation failure
/// keeps the popup open with an inline error). The editing keys mutate
/// the active target's name and `app.name_dialog.cursor` on char
/// boundaries.
pub(in crate::tui) fn handle_name_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            // Close only when everything applied: a validation failure keeps
            // the popup open with an inline error so the typed name isn't
            // discarded.
            if apply_name_dialog(app) {
                app.active_popup = None;
            }
        }
        KeyCode::Tab => app.name_dialog.focus_next(),
        KeyCode::BackTab => app.name_dialog.focus_prev(),
        KeyCode::Backspace => {
            let cur = app.name_dialog.cursor;
            if cur > 0
                && let Some(name) = app.name_dialog.active_name_mut()
            {
                let prev = name[..cur]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                name.remove(prev);
                app.name_dialog.cursor = prev;
            }
        }
        KeyCode::Left => {
            let name = app.name_dialog.active_name();
            let cur = app.name_dialog.cursor;
            if cur > 0 {
                app.name_dialog.cursor = name[..cur]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            let name = app.name_dialog.active_name();
            let cur = app.name_dialog.cursor;
            if cur < name.len() {
                app.name_dialog.cursor = name[cur..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| cur + i)
                    .unwrap_or(name.len());
            }
        }
        KeyCode::Home => app.name_dialog.cursor = 0,
        KeyCode::End => app.name_dialog.cursor = app.name_dialog.active_name().len(),
        KeyCode::Char(c) => {
            let cur = app.name_dialog.cursor;
            if let Some(name) = app.name_dialog.active_name_mut() {
                name.insert(cur, c);
                app.name_dialog.cursor += c.len_utf8();
            }
        }
        _ => {}
    }
}

/// Apply the Name Address popup: set or clear the manual mapping for every
/// offered endpoint, persist the table, and turn name resolution on so the
/// changes are visible immediately.
///
/// # Returns
/// `false` on a validation failure — the error is shown inline in the
/// popup (which stays open) and NOTHING is applied, so a multi-endpoint
/// edit is never left half-saved. `true` once every target has been
/// applied.
///
/// # Side effects
/// Non-empty names are set on the resolver's manual table (empty names
/// clear existing mappings); the first set flips `app.name_mode` on when
/// it was `Off`. Writes the manual table to `app.names_save_path` and,
/// when configured, into the user's sipnabrc via `names_config_path` —
/// write failures are reported on the status line. Sets `app.status_error`
/// to a named/cleared summary.
/// Say which rule the name broke, and for length, by how much.
///
/// The old text was `"Invalid name (control characters or too long); not
/// saved"` — it named both possible causes and committed to neither, and gave
/// no length. That mattered: this dialog seeds the field with the name already
/// stored for the address, so an operator who types rather than clears is
/// EXTENDING an existing name. Once the result crosses the limit every save
/// fails, and a message that will not say "too long, by this much" leaves the
/// only visible symptom as a dialog that refuses to close.
///
/// Found because an end-to-end test did exactly that on every run and grew a
/// stored name to 250 bytes, at which point the test could never pass again on
/// that machine.
fn name_rejection_reason(name: &str) -> String {
    if name.chars().any(|c| c.is_control()) {
        "Name contains control characters; not saved".to_string()
    } else if name.len() > crate::names::MAX_NAME_LEN {
        format!(
            "Name is {} bytes, over the {} limit — clear the field or shorten it; not saved",
            name.len(),
            crate::names::MAX_NAME_LEN
        )
    } else {
        // is_valid_name also rejects an interior NUL, which cannot be typed but
        // can arrive from a config file.
        "Name is not storable (embedded NUL); not saved".to_string()
    }
}

fn apply_name_dialog(app: &mut App) -> bool {
    let mut set = 0usize;
    let mut cleared = 0usize;
    let mut last: Option<String> = None;
    // Snapshot targets so we don't borrow name_dialog across resolver calls.
    let targets: Vec<(String, String)> = app
        .name_dialog
        .targets
        .iter()
        .map(|t| (t.ip.clone(), t.name.trim().to_string()))
        .collect();
    // Validate everything BEFORE applying anything.
    for (_, name) in &targets {
        if !name.is_empty() && !crate::names::is_valid_name(name) {
            app.name_dialog.error = Some(name_rejection_reason(name));
            return false;
        }
    }
    app.name_dialog.error = None;
    for (ip_str, name) in targets {
        let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
            continue;
        };
        if name.is_empty() {
            if app.resolver.remove_manual(&ip).is_some() {
                cleared += 1;
            }
        } else {
            app.resolver.set_manual(ip, name.clone());
            set += 1;
            last = Some(format!("{ip} \u{2192} {name}"));
        }
    }
    if set > 0 && app.name_mode == crate::names::NameMode::Off {
        app.name_mode = crate::names::NameMode::Names;
    }
    app.status_error = match (set, cleared) {
        (0, 0) => None,
        (1, 0) => last,
        (s, 0) => Some(format!("Named {s} endpoints")),
        (0, c) => Some(format!("Cleared {c} name(s)")),
        (s, c) => Some(format!("Named {s}, cleared {c}")),
    };
    // Collect every write failure instead of letting a later one overwrite an
    // earlier one on the status line: when both the names file and the
    // sipnabrc write fail, the operator must see both — otherwise the first
    // failure (e.g. the names file the changes were meant to persist to)
    // silently vanishes behind the second.
    let mut write_errors: Vec<String> = Vec::new();
    if let Some(path) = app.names_save_path.clone()
        && let Err(e) = app.resolver.save_manual_file(&path)
    {
        write_errors.push(format!("couldn't save {}: {e}", path.display()));
    }
    // Opt-in: also persist the full manual table into the user's sipnabrc,
    // preserving comments and other sections.
    if let Some(path) = app.names_config_path.clone() {
        let entries: Vec<(String, String)> = app
            .resolver
            .manual_entries()
            .into_iter()
            .map(|(ip, n)| (ip.to_string(), n))
            .collect();
        if let Err(e) = crate::config::write_manual_mappings_file(&path, &entries) {
            write_errors.push(format!("couldn't update {}: {e}", path.display()));
        }
    }
    if !write_errors.is_empty() {
        app.status_error = Some(format!("Named, but {}", write_errors.join("; ")));
    }
    true
}

/// Unit tests for the Name Address popup's edit/apply flow.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// Typing a name and pressing Enter stores the manual mapping and
    /// turns name resolution on so the change is visible.
    #[test]
    fn name_dialog_sets_mapping_and_enables_resolution() {
        let mut app = app_with_dialogs();
        open_name_dialog_for(&mut app, vec![addr_a()], 0);
        for c in "sbc-edge".chars() {
            handle_name_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_name_popup_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.active_popup, None);
        // Naming an address turns resolution on so the change is visible.
        assert_eq!(app.name_mode(), crate::names::NameMode::Names);
        assert_eq!(
            app.resolver()
                .label_ip(addr_a(), crate::names::NameMode::Names),
            "sbc-edge"
        );
    }

    /// The popup offers every endpoint; Tab/Shift-Tab switch between them,
    /// each keeps its own edited name, and Enter applies them all.
    #[test]
    fn name_dialog_tab_edits_multiple_endpoints() {
        let mut app = app_with_dialogs();
        open_name_dialog_for(&mut app, vec![addr_a(), addr_b()], 0);
        assert_eq!(app.name_dialog.active_ip(), addr_a().to_string());
        for c in "alice".chars() {
            handle_name_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        // Tab to the second endpoint and name it.
        handle_name_popup_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.name_dialog.active_ip(), addr_b().to_string());
        for c in "bob".chars() {
            handle_name_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        // Shift-Tab back: the first endpoint's edit is preserved (not clobbered).
        handle_name_popup_key(&mut app, key(KeyCode::BackTab));
        assert_eq!(app.name_dialog.active_ip(), addr_a().to_string());
        assert_eq!(app.name_dialog.active_name(), "alice");
        // Enter applies BOTH endpoints.
        handle_name_popup_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.active_popup, None);
        assert_eq!(
            app.resolver()
                .label_ip(addr_a(), crate::names::NameMode::Names),
            "alice"
        );
        assert_eq!(
            app.resolver()
                .label_ip(addr_b(), crate::names::NameMode::Names),
            "bob"
        );
    }

    /// When BOTH the names-file save and the sipnabrc update fail, the
    /// status line must report both — a second failure used to overwrite the
    /// first, silently hiding the names-file error the operator most needs.
    #[test]
    fn both_write_failures_are_reported_together() {
        let mut app = app_with_dialogs();
        // A regular file used as a fake parent directory: any write beneath
        // it fails (create_dir_all / open both refuse to treat a file as a
        // directory), so both persistence paths error out.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        app.names_save_path = Some(blocker.join("names.txt"));
        app.names_config_path = Some(blocker.join("sipnabrc"));

        open_name_dialog_for(&mut app, vec![addr_a()], 0);
        for c in "sbc".chars() {
            handle_name_popup_key(&mut app, key(KeyCode::Char(c)));
        }
        handle_name_popup_key(&mut app, key(KeyCode::Enter));

        let status = app.status_error.clone().unwrap_or_default();
        assert!(
            status.contains("couldn't save"),
            "names-file failure must survive, got: {status}"
        );
        assert!(
            status.contains("couldn't update"),
            "sipnabrc failure must be reported too, got: {status}"
        );
    }

    /// Deleting an existing name and pressing Enter clears the manual
    /// mapping (the plain IP shows again).
    #[test]
    fn name_dialog_empty_clears_mapping() {
        let mut app = app_with_dialogs();
        app.resolver().set_manual(addr_a(), "old".into());
        open_name_dialog_for(&mut app, vec![addr_a()], 0);
        for _ in 0.."old".len() {
            handle_name_popup_key(&mut app, key(KeyCode::Backspace));
        }
        handle_name_popup_key(&mut app, key(KeyCode::Enter));
        assert_eq!(
            app.resolver()
                .label_ip(addr_a(), crate::names::NameMode::Names),
            "10.0.0.1"
        );
    }
}

/// Tests for name validation keeping the popup open on invalid input.
#[cfg(test)]
mod validation_tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    /// An over-length name must say it is over-length, and by how much.
    ///
    /// This is the regression guard for a defect that hid for a long time: the
    /// dialog seeds its field with the name already stored for the address, so
    /// an operator who types rather than clears EXTENDS it. Once the result
    /// crosses `MAX_NAME_LEN` every save is refused, and the old message —
    /// "Invalid name (control characters or too long)" — named both causes and
    /// committed to neither. The only visible symptom was a dialog that would
    /// not close. An end-to-end test drove a stored name to 250 bytes this way
    /// and could then never pass again on that machine.
    #[test]
    fn an_over_length_name_says_so_and_gives_the_numbers() {
        let too_long = "a".repeat(crate::names::MAX_NAME_LEN + 1);
        let msg = name_rejection_reason(&too_long);
        assert!(
            msg.contains(&format!("{}", crate::names::MAX_NAME_LEN + 1)),
            "the message must state the actual length: {msg}"
        );
        assert!(
            msg.contains(&format!("{}", crate::names::MAX_NAME_LEN)),
            "the message must state the limit: {msg}"
        );
        assert!(
            !msg.contains("control characters"),
            "a length failure must not also blame control characters: {msg}"
        );
    }

    /// A control character is reported as a control character, not as a length
    /// problem — the two rules must not be conflated in either direction.
    #[test]
    fn a_control_character_is_not_reported_as_a_length_problem() {
        let msg = name_rejection_reason("bad\u{7}name");
        assert!(msg.contains("control characters"), "got: {msg}");
        assert!(
            !msg.contains("limit"),
            "a control-character failure must not blame length: {msg}"
        );
    }

    /// An invalid name must keep the popup open with an inline error and
    /// preserve the typed text — it used to close the dialog and discard
    /// the input, leaving only a status-bar message.
    #[test]
    fn invalid_name_keeps_dialog_open_and_preserves_input() {
        let mut app = App::new_test();
        app.name_dialog.targets = vec![NameTarget {
            ip: "10.0.0.1".to_string(),
            name: "bad\u{7}name".to_string(),
        }];
        app.name_dialog.active = 0;
        app.name_dialog.cursor = 0;
        app.active_popup = Some(Popup::NameAddress);

        handle_name_popup_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(
            matches!(app.active_popup, Some(Popup::NameAddress)),
            "popup must stay open on validation failure"
        );
        // Assert the CAUSE, not the wording. This used to require the literal
        // "Invalid name", which the message could satisfy while telling the
        // operator nothing about which of two rules it broke.
        assert!(
            app.name_dialog
                .error
                .as_deref()
                .unwrap_or("")
                .contains("control characters"),
            "the error must name the rule that was broken, got: {:?}",
            app.name_dialog.error
        );
        assert_eq!(
            app.name_dialog.targets[0].name, "bad\u{7}name",
            "typed input must be preserved for correction"
        );

        // Correcting the name applies and closes.
        app.name_dialog.targets[0].name = "sbc-edge".to_string();
        handle_name_popup_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.active_popup.is_none(), "valid name closes the popup");
        assert!(app.name_dialog.error.is_none());
    }
}
