//! The "Name Address" popup: manual IP-to-name mappings.

use crate::tui::*;

/// Source + destination IPs of the selected dialog (for the Name Address
/// popup). Resolved against the same displayed list as the renderer.
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
pub(in crate::tui) fn open_name_dialog_for(
    app: &mut App,
    ips: Vec<std::net::IpAddr>,
    active: usize,
) {
    let manual = app.resolver.manual_entries();
    let mut targets: Vec<super::NameTarget> = Vec::new();
    for ip in ips {
        if targets.iter().any(|t| t.ip == ip.to_string()) {
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
    app.active_popup = Some(Popup::NameAddress);
}

/// Handle keys in the "Name Address" popup. `Tab`/`Shift-Tab` move between the
/// offered endpoints; the other keys edit the active endpoint's name.
pub(in crate::tui) fn handle_name_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            apply_name_dialog(app);
            app.active_popup = None;
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
fn apply_name_dialog(app: &mut App) {
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
    for (ip_str, name) in targets {
        let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
            continue;
        };
        if name.is_empty() {
            if app.resolver.remove_manual(&ip).is_some() {
                cleared += 1;
            }
        } else if !crate::names::is_valid_name(&name) {
            app.status_error =
                Some("Invalid name (control characters or too long); not saved".to_string());
            return;
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
    if let Some(path) = app.names_save_path.clone()
        && let Err(e) = app.resolver.save_manual_file(&path)
    {
        app.status_error = Some(format!("Named, but couldn't save {}: {e}", path.display()));
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
            app.status_error = Some(format!(
                "Named, but couldn't update {}: {e}",
                path.display()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

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

    // R1: the popup offers every endpoint; Tab/Shift-Tab switch between them,
    // each keeps its own edited name, and Enter applies them all.
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
