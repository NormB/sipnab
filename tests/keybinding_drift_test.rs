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

use crossterm::event::KeyCode;
use sipnab::tui::Keymap;
use sipnab::tui::help::HELP_TEXT;

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

/// Literal single-character command keys handled in the event dispatcher,
/// scraped from the source. `KeyCode::Char('x')` matches; the catch-all
/// `KeyCode::Char(c)` text-entry handlers (no quote) do not.
fn scraped_char_keys() -> HashSet<char> {
    let full = include_str!("../src/tui/events.rs");
    // Only scan production code, not the `#[cfg(test)]` module (whose tests use
    // arbitrary keys like 'z'/'Q' to assert unknown keys are ignored).
    let src = full.split("#[cfg(test)]").next().unwrap_or(full);
    let pat = "KeyCode::Char('";
    let mut keys = HashSet::new();
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
