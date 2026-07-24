// SPDX-License-Identifier: MIT OR Apache-2.0

//! Guard against drift between the keybindings sipnab actually HANDLES and the
//! in-TUI F1 help (`HELP_TEXT`). The help is the primary discovery surface, so a
//! handled key that isn't documented there is a real bug.
//!
//! This is intentionally a conservative, source-scraping guard (the alternative
//! — a single keybinding registry driving dispatch + help + this test — is a
//! larger refactor). It catches the common regression: adding a `KeyCode::Char`
//! command handler without documenting it. Truly new keys must be either added
//! to the help or added to `ALLOWED_UNDOCUMENTED` with a reason.
#![cfg(feature = "tui")]

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sipnab::tui::help::HELP_TEXT;
use sipnab::tui::{
    Keymap, call_flow_action, call_list_action, combined_detail_action, dashboard_action,
    help_action, message_diff_action, raw_message_action, statistics_action, stream_detail_action,
    stream_list_action,
};

/// Display token for a key as it appears in the help's key column.
fn token_for(kc: KeyCode) -> String {
    match kc {
        KeyCode::Char(c) => c.to_string(),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    }
}

/// Collect the set of key tokens documented in `HELP_TEXT`.
///
/// Binding lines look like `  Esc, q           Quit` — the key column is
/// everything before the first run of 2+ spaces. Keys are separated by `/` or
/// `,` (e.g. `↑/↓, j/k`, `F4, x`), so split on those plus whitespace.
fn documented_tokens() -> HashSet<String> {
    let mut set = HashSet::new();
    for line in HELP_TEXT.lines() {
        let t = line.trim_start();
        let Some(gap) = t.find("  ") else { continue };
        let key_part = &t[..gap];
        // Split on whitespace/comma into chunks, then split each chunk on '/'
        // (e.g. "↑/↓", "9/0") — but keep a lone "/" (the search key) intact.
        for chunk in key_part.split([',', ' ', '\t']) {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                continue;
            }
            if chunk == "/" {
                set.insert("/".to_string());
                continue;
            }
            for tok in chunk.split('/') {
                if !tok.is_empty() {
                    set.insert(tok.to_string());
                }
            }
        }
    }
    set
}

/// Literal single-character command keys handled in the controller layer,
/// scraped from the source. `KeyCode::Char('x')` matches; the catch-all
/// `KeyCode::Char(c)` text-entry handlers (no quote) do not.
fn scraped_char_keys() -> HashSet<char> {
    const SOURCES: &[&str] = &[
        include_str!("../src/tui/controllers/mod.rs"),
        include_str!("../src/tui/controllers/call_flow.rs"),
        include_str!("../src/tui/controllers/call_list.rs"),
        include_str!("../src/tui/controllers/file_open.rs"),
        include_str!("../src/tui/controllers/filter_dialog.rs"),
        include_str!("../src/tui/controllers/name_dialog.rs"),
        include_str!("../src/tui/controllers/save_dialog.rs"),
        include_str!("../src/tui/controllers/stream.rs"),
    ];
    let mut keys = HashSet::new();
    for full in SOURCES {
        // Only scan production code, not the `#[cfg(test)]` modules (whose
        // tests use arbitrary keys like 'z'/'Q' to assert unknown keys are
        // ignored).
        let src = full.split("#[cfg(test)]").next().unwrap_or(full);
        let pat = "KeyCode::Char('";
        let mut idx = 0;
        while let Some(p) = src[idx..].find(pat) {
            let start = idx + p + pat.len();
            if let Some(ch) = src[start..].chars().next() {
                let after = src[start + ch.len_utf8()..].chars().next();
                if after == Some('\'') {
                    keys.insert(ch);
                }
            }
            idx = start + 1;
        }
    }
    keys
}

/// Char keys that are intentionally NOT documented as their own help line, with
/// the reason. Navigation/scroll/resize keys are covered by combined lines
/// (`↑/↓, j/k`, `9/0, +/-`), and a few are aliases or modifier combos.
fn allowed_undocumented(ch: char) -> Option<&'static str> {
    match ch {
        ' ' => Some("documented as 'Space'"),
        '=' => Some("resize alias of '+', documented as '9/0, +/-'"),
        'V' => Some("uppercase alias of 'v' (show version)"),
        'P' => Some("audio playback, documented as 'Shift+P' (audio feature)"),
        'l' => Some("Ctrl+L, documented as 'Ctrl+L' (clear calls)"),
        'h' => Some("vi-style left nav alias"),
        _ => None,
    }
}

/// Every action key in the default `Keymap` (quit/help/save/…) appears as a
/// token in the F1 `HELP_TEXT`.
#[test]
fn keymap_default_keys_are_documented() {
    let docs = documented_tokens();
    let km = Keymap::default();
    for (action, kc) in [
        ("quit", km.quit),
        ("help", km.help),
        ("save", km.save),
        ("search", km.search),
        ("filter", km.filter),
        ("settings", km.settings),
        ("pause", km.pause),
        ("autoscroll", km.autoscroll),
        ("extended_flow", km.extended_flow),
        ("clear_calls", km.clear_calls),
        ("column_selector", km.column_selector),
    ] {
        let tok = token_for(kc);
        assert!(
            docs.contains(&tok),
            "keymap action '{action}' (key {tok}) is not documented in the F1 help"
        );
    }
}

/// A fixed roster of must-discover command keys (n/N/O/s/u/r/v/t/c/d,
/// Shift+P, Ctrl+L) is present in the F1 help.
#[test]
fn important_command_keys_are_documented() {
    let docs = documented_tokens();
    // Keys the user must be able to discover from F1 (the ones the drift fix
    // added, plus the long-standing display/command keys).
    for tok in [
        "n",       // cycle name resolution
        "N",       // name selected address (IP -> host/FQDN)
        "O",       // open pcap
        "s",       // statistics
        "u",       // From/To display mode
        "r",       // raw message / jump to RTP (section-specific)
        "v",       // version
        "t",       // timestamps
        "c",       // colors
        "d",       // SDP display
        "Shift+P", // audio playback
        "Ctrl+L",  // clear calls
    ] {
        assert!(
            docs.contains(tok),
            "expected key '{tok}' to be documented in the F1 help; have: {docs:?}"
        );
    }
}

/// Every converted view has a real key→action mapping table — probe each
/// directly instead of scraping source: any printable char a mapper binds
/// must be documented in the F1 help or allow-listed. The scrape test
/// below still covers what has no mapping table (the global dispatcher
/// fallbacks and the text-entry popups).
#[test]
fn mapped_char_keys_are_documented_or_allowlisted() {
    let docs = documented_tokens();
    let km = Keymap::default();
    type Probe = (&'static str, fn(&Keymap, KeyEvent) -> bool);
    let probes: [Probe; 10] = [
        ("call_list", |km, k| call_list_action(km, k).is_some()),
        ("stream_list", |km, k| stream_list_action(km, k).is_some()),
        ("stream_detail", |km, k| {
            stream_detail_action(km, k).is_some()
        }),
        ("call_flow", |km, k| call_flow_action(km, k).is_some()),
        ("raw_message", |km, k| raw_message_action(km, k).is_some()),
        ("message_diff", |km, k| message_diff_action(km, k).is_some()),
        ("combined_detail", |km, k| {
            combined_detail_action(km, k).is_some()
        }),
        ("help", |km, k| help_action(km, k).is_some()),
        ("statistics", |km, k| statistics_action(km, k).is_some()),
        ("dashboard", |km, k| dashboard_action(km, k).is_some()),
    ];
    let mut undocumented = Vec::new();
    for (view, probe) in probes {
        for c in (32u8..127).map(|b| b as char) {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
            if !probe(&km, key) {
                continue;
            }
            let tok = c.to_string();
            if docs.contains(&tok) || allowed_undocumented(c).is_some() {
                continue;
            }
            undocumented.push((view, c));
        }
    }
    undocumented.sort_unstable();
    undocumented.dedup();
    assert!(
        undocumented.is_empty(),
        "these view mappers bind chars the F1 help doesn't document: {undocumented:?}\n\
         Document them in src/tui/help.rs HELP_TEXT, or add them to allowed_undocumented() with a reason."
    );
}

/// Every `KeyCode::Char('x')` literal scraped from the controller sources is
/// either documented in the F1 help or allow-listed with a reason.
#[test]
fn every_handled_char_key_is_documented_or_allowlisted() {
    let docs = documented_tokens();
    let mut undocumented = Vec::new();
    for ch in scraped_char_keys() {
        let tok = ch.to_string();
        if docs.contains(&tok) || allowed_undocumented(ch).is_some() {
            continue;
        }
        undocumented.push(ch);
    }
    undocumented.sort_unstable();
    assert!(
        undocumented.is_empty(),
        "these handled KeyCode::Char keys are neither in the F1 help nor allow-listed: {undocumented:?}\n\
         Document them in src/tui/help.rs HELP_TEXT, or add them to allowed_undocumented() with a reason."
    );
}

/// (section heading, token) pairs the reverse check must skip, with reasons.
fn reverse_allowed(section: &str, tok: &str) -> Option<&'static str> {
    match (section, tok) {
        // "[ / ]  Scroll detail panel" — the middle "/" is a visual
        // separator between the bracket keys, not the search key.
        ("CALL FLOW:", "/") => Some("separator in the '[ / ]' key column"),
        _ => None,
    }
}

/// Reverse guard: every key the F1 help DOCUMENTS for a view must actually
/// be handled by that view's key→action mapping. Regression context: the
/// raw message view's help claimed Home/End while only Home was bound —
/// the one-way check above (handled ⇒ documented) can never catch a
/// documented-but-missing key.
#[test]
fn every_documented_view_key_is_handled() {
    let km = Keymap::default();
    type Checker = fn(&Keymap, KeyEvent) -> bool;
    let sections: &[(&str, Checker)] = &[
        ("CALL LIST:", |km, k| call_list_action(km, k).is_some()),
        ("CALL FLOW:", |km, k| call_flow_action(km, k).is_some()),
        ("RAW MESSAGE:", |km, k| raw_message_action(km, k).is_some()),
        ("MESSAGE DIFF / COMBINED DETAIL / STATISTICS:", |km, k| {
            message_diff_action(km, k).is_some()
                || combined_detail_action(km, k).is_some()
                || statistics_action(km, k).is_some()
        }),
        ("RTP STREAMS (Tab):", |km, k| {
            stream_list_action(km, k).is_some()
        }),
        ("QUALITY DASHBOARD:", |km, k| {
            dashboard_action(km, k).is_some()
        }),
        ("STREAM DETAIL:", |km, k| {
            stream_detail_action(km, k).is_some()
        }),
    ];
    /// Keys handled globally in handle_key_event, valid in every view.
    fn is_global(kc: KeyCode) -> bool {
        // '?' re-dispatches as the help key from any view.
        matches!(kc, KeyCode::Char('v' | 'V' | 'n' | '?'))
    }

    /// Map a help token to the KeyCode it advertises. `None` = not a plain
    /// key (modifier combos like Ctrl-R / Shift+P, or prose).
    fn token_to_key(tok: &str) -> Option<KeyCode> {
        Some(match tok {
            "\u{2191}" => KeyCode::Up,
            "\u{2193}" => KeyCode::Down,
            "\u{2190}" => KeyCode::Left,
            "\u{2192}" => KeyCode::Right,
            "PgUp" => KeyCode::PageUp,
            "PgDn" => KeyCode::PageDown,
            "Home" => KeyCode::Home,
            "End" => KeyCode::End,
            "Enter" => KeyCode::Enter,
            "Esc" => KeyCode::Esc,
            "Tab" => KeyCode::Tab,
            "Space" => KeyCode::Char(' '),
            t if t.len() >= 2
                && t.starts_with('F')
                && t[1..].chars().all(|c| c.is_ascii_digit()) =>
            {
                KeyCode::F(t[1..].parse().ok()?)
            }
            t => {
                let mut chars = t.chars();
                let (Some(c), None) = (chars.next(), chars.next()) else {
                    return None;
                };
                KeyCode::Char(c)
            }
        })
    }

    let mut current: Option<(&str, Checker)> = None;
    let mut failures: Vec<String> = Vec::new();
    for line in HELP_TEXT.lines() {
        let trimmed = line.trim();
        if let Some((h, chk)) = sections.iter().find(|(h, _)| trimmed == *h) {
            current = Some((h, *chk));
            continue;
        }
        if !line.starts_with(' ') && trimmed.ends_with(':') {
            current = None; // section this test does not know
            continue;
        }
        let Some((heading, chk)) = current else {
            continue;
        };
        let t = line.trim_start();
        let Some(gap) = t.find("  ") else { continue };
        for chunk in t[..gap].split([',', ' ', '\t']) {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                continue;
            }
            let toks: Vec<&str> = if chunk == "/" {
                vec!["/"]
            } else {
                chunk.split('/').filter(|s| !s.is_empty()).collect()
            };
            for tok in toks {
                if reverse_allowed(heading, tok).is_some() {
                    continue;
                }
                let Some(kc) = token_to_key(tok) else {
                    continue;
                };
                let ev = KeyEvent::new(kc, KeyModifiers::NONE);
                if !(chk(&km, ev) || is_global(kc)) {
                    failures.push(format!(
                        "help section '{heading}' documents key '{tok}' but the view does not handle it"
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "documented-but-unhandled keys:\n{}",
        failures.join("\n")
    );
}

/// Description-level drift the token-based checks above cannot catch: the
/// help overlay once listed three From/To modes including an invented
/// "both" while the real enum has four.
#[test]
fn help_documents_all_four_from_to_modes() {
    let u_line = sipnab::tui::help::HELP_TEXT
        .lines()
        .find(|l| l.trim_start().starts_with("u "))
        .expect("help must document the u key");
    for mode in ["default", "host:port", "user", "user@host:port"] {
        assert!(
            u_line.contains(mode),
            "u-line must name mode '{mode}': {u_line}"
        );
    }
    assert!(
        !u_line.contains("both"),
        "stale invented 'both' mode: {u_line}"
    );
}

/// The F2 save dialog cycles many formats (incl. Mermaid); the help line
/// must not pretend it is PCAP/PCAP-NG/TXT only.
#[test]
fn help_f2_line_mentions_mermaid() {
    let f2_line = sipnab::tui::help::HELP_TEXT
        .lines()
        .find(|l| l.trim_start().starts_with("F2 ") && l.contains("Save capture"))
        .expect("help must document F2 save");
    assert!(
        f2_line.contains("Mermaid"),
        "F2 line must mention the full format cycle: {f2_line}"
    );
}

/// Statistics can be closed with q and s, not just Esc; the help section
/// covering it must say so.
#[test]
fn help_documents_statistics_close_keys() {
    let section = sipnab::tui::help::HELP_TEXT
        .split("MESSAGE DIFF / COMBINED DETAIL / STATISTICS:")
        .nth(1)
        .expect("statistics section present")
        .split("\n\n")
        .next()
        .unwrap()
        .to_string();
    assert!(
        section.contains("q, s") || section.contains("q / s"),
        "statistics close keys must be documented: {section}"
    );
}

/// v/V and n work in EVERY view (global fallback keys) but were documented
/// only under CALL LIST.
#[test]
fn help_marks_global_keys_as_global() {
    for key in ["n ", "v "] {
        let line = sipnab::tui::help::HELP_TEXT
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("help must document the {key}key"));
        assert!(
            line.contains("every view") || line.contains("global"),
            "'{key}' is global and must say so: {line}"
        );
    }
}
