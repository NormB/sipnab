//! Resolved theme and keymap types plus adaptive refresh constants.

use super::*;

// ── Resolved theme and keymap ──────────────────────────────────────

/// Resolved TUI color theme — all fields are concrete `Color` values.
#[derive(Debug, Clone)]
pub struct Theme {
    pub background: Color,
    pub foreground: Color,
    pub header: Color,
    pub selected: Color,
    pub accent: Color,
    pub good: Color,
    pub warning: Color,
    pub bad: Color,
    pub muted: Color,
    pub border: Color,
    /// Status bar background — distinct from terminal bg for visibility.
    pub status_bg: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: Color::Reset,
            foreground: Color::White,
            header: Color::Cyan,
            selected: Color::Yellow,
            accent: Color::Magenta,
            good: Color::Green,
            warning: Color::Yellow,
            bad: Color::Red,
            muted: Color::DarkGray,
            border: Color::White,
            status_bg: Color::Rgb(48, 48, 64), // Dark blue-gray, readable on both dark and light
        }
    }
}

/// Apply an optional config color string to a theme field.
pub(super) fn apply_color(field: &mut Color, value: &Option<String>) {
    if let Some(s) = value
        && let Some(c) = parse_color(s)
    {
        *field = c;
    }
}

/// Apply an optional config key string to a keymap field.
pub(super) fn apply_key(field: &mut KeyCode, value: &Option<String>) {
    if let Some(s) = value
        && let Some(k) = parse_keycode(s)
    {
        *field = k;
    }
}

impl Theme {
    /// Build a resolved theme from config, falling back to defaults.
    pub fn from_config(config: &ThemeConfig) -> Self {
        let mut t = Self::default();
        apply_color(&mut t.background, &config.background);
        apply_color(&mut t.foreground, &config.foreground);
        apply_color(&mut t.header, &config.header);
        // "highlight" is a legacy alias for "selected"
        apply_color(&mut t.selected, &config.highlight);
        apply_color(&mut t.selected, &config.selected);
        apply_color(&mut t.accent, &config.accent);
        apply_color(&mut t.good, &config.good);
        apply_color(&mut t.warning, &config.warning);
        apply_color(&mut t.bad, &config.bad);
        apply_color(&mut t.muted, &config.muted);
        apply_color(&mut t.border, &config.border);
        t
    }
}

/// Resolved keymap — all fields are concrete `KeyCode` values.
#[derive(Debug, Clone)]
pub struct Keymap {
    pub quit: KeyCode,
    pub help: KeyCode,
    pub save: KeyCode,
    pub search: KeyCode,
    pub filter: KeyCode,
    pub settings: KeyCode,
    pub pause: KeyCode,
    pub autoscroll: KeyCode,
    pub extended_flow: KeyCode,
    pub clear_calls: KeyCode,
    pub column_selector: KeyCode,
}

impl Default for Keymap {
    fn default() -> Self {
        Self {
            quit: KeyCode::Char('q'),
            help: KeyCode::F(1),
            save: KeyCode::F(2),
            search: KeyCode::Char('/'),
            filter: KeyCode::F(7),
            settings: KeyCode::F(8),
            pause: KeyCode::Char('p'),
            autoscroll: KeyCode::Char('A'),
            extended_flow: KeyCode::F(4),
            clear_calls: KeyCode::F(5),
            column_selector: KeyCode::F(10),
        }
    }
}

impl Keymap {
    /// Build a resolved keymap from config, falling back to defaults.
    pub fn from_config(config: &KeybindingsConfig) -> Self {
        let mut km = Self::default();
        apply_key(&mut km.quit, &config.quit);
        apply_key(&mut km.help, &config.help);
        apply_key(&mut km.save, &config.save);
        apply_key(&mut km.search, &config.search);
        apply_key(&mut km.filter, &config.filter);
        apply_key(&mut km.settings, &config.settings);
        apply_key(&mut km.pause, &config.pause);
        apply_key(&mut km.autoscroll, &config.autoscroll);
        apply_key(&mut km.extended_flow, &config.extended_flow);
        apply_key(&mut km.clear_calls, &config.clear_calls);
        apply_key(&mut km.column_selector, &config.column_selector);
        km
    }
}

// ── Adaptive refresh constants ──────────────────────────────────────

/// Poll timeout when data was recently updated.
pub(super) const ACTIVE_POLL_MS: u64 = 100;
/// Poll timeout when idle (no recent updates).
pub(super) const IDLE_POLL_MS: u64 = 500;
/// Duration after the last data update before switching to idle polling.
pub(super) const IDLE_THRESHOLD: Duration = Duration::from_secs(2);
