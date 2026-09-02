// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resolved theme and keymap types plus adaptive refresh constants.

use super::*;

// ── Resolved theme and keymap ──────────────────────────────────────

/// Resolved TUI color theme — all fields are concrete `Color` values.
#[derive(Debug, Clone)]
pub struct Theme {
    /// Main pane background.
    pub background: Color,
    /// Default text color.
    pub foreground: Color,
    /// Table headers and titles.
    pub header: Color,
    /// Selected-row highlight (config `selected`, legacy alias `highlight`).
    pub selected: Color,
    /// Accent for emphasis (marks, active elements).
    pub accent: Color,
    /// Positive/healthy values (e.g. good MOS, answered calls).
    pub good: Color,
    /// Cautionary values (e.g. degraded quality).
    pub warning: Color,
    /// Errors and failed/poor values.
    pub bad: Color,
    /// De-emphasized text (hints, secondary detail).
    pub muted: Color,
    /// Widget borders.
    pub border: Color,
    /// Status bar background — distinct from terminal bg for visibility.
    pub status_bg: Color,
}

impl Default for Theme {
    /// Built-in color scheme: terminal-default background, an RGB
    /// status-bar band readable on dark and light terminals.
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
    /// Honors NO_COLOR (<https://no-color.org>): when set non-empty, the
    /// theme collapses to [`Self::monochrome`] and config colors are
    /// ignored — the user asked for no color, full stop.
    pub fn from_config(config: &ThemeConfig) -> Self {
        Self::from_config_with_no_color(config, no_color_requested())
    }

    /// [`Self::from_config`] with the NO_COLOR decision passed in, so tests
    /// don't depend on process-global environment state.
    pub fn from_config_with_no_color(config: &ThemeConfig, no_color: bool) -> Self {
        if no_color {
            return Self::monochrome();
        }
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
        apply_color(&mut t.status_bg, &config.status_bg);
        t
    }

    /// NO_COLOR theme: every color collapses to the terminal default.
    /// `selected` keeps a gray band so the selection highlight stays
    /// visible without emitting real colors.
    pub fn monochrome() -> Self {
        Self {
            background: Color::Reset,
            foreground: Color::Reset,
            header: Color::Reset,
            selected: Color::Gray,
            accent: Color::Reset,
            good: Color::Reset,
            warning: Color::Reset,
            bad: Color::Reset,
            muted: Color::Reset,
            border: Color::Reset,
            status_bg: Color::Reset,
        }
    }
}

/// NO_COLOR is honored when set to a non-empty value (<https://no-color.org>).
fn no_color_requested() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// Resolved keymap — all fields are concrete `KeyCode` values.
#[derive(Debug, Clone)]
pub struct Keymap {
    /// Quit the TUI (default `q`).
    pub quit: KeyCode,
    /// Open the help overlay (default F1).
    pub help: KeyCode,
    /// Open the save dialog (default F2).
    pub save: KeyCode,
    /// Enter search mode (default `/`).
    pub search: KeyCode,
    /// Open the filter dialog (default F7).
    pub filter: KeyCode,
    /// Open the settings popup (default F8).
    pub settings: KeyCode,
    /// Pause/resume packet processing (default `p`).
    pub pause: KeyCode,
    /// Toggle sticky-bottom autoscroll (default `A`).
    pub autoscroll: KeyCode,
    /// Toggle extended multi-leg call flow (default F4).
    pub extended_flow: KeyCode,
    /// Clear all captured calls (default F5).
    pub clear_calls: KeyCode,
    /// Open the column selector (default F10).
    pub column_selector: KeyCode,
}

impl Default for Keymap {
    /// The built-in default bindings listed on each field.
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

    /// `(name, key)` pairs for every rebindable action.
    fn fields(&self) -> [(&'static str, KeyCode); 11] {
        [
            ("quit", self.quit),
            ("help", self.help),
            ("save", self.save),
            ("search", self.search),
            ("filter", self.filter),
            ("settings", self.settings),
            ("pause", self.pause),
            ("autoscroll", self.autoscroll),
            ("extended_flow", self.extended_flow),
            ("clear_calls", self.clear_calls),
            ("column_selector", self.column_selector),
        ]
    }

    /// Set the field named `name` to `code` (probe helper for collision
    /// detection; names come from [`Self::fields`]).
    fn set_field(&mut self, name: &str, code: KeyCode) {
        match name {
            "quit" => self.quit = code,
            "help" => self.help = code,
            "save" => self.save = code,
            "search" => self.search = code,
            "filter" => self.filter = code,
            "settings" => self.settings = code,
            "pause" => self.pause = code,
            "autoscroll" => self.autoscroll = code,
            "extended_flow" => self.extended_flow = code,
            "clear_calls" => self.clear_calls = code,
            "column_selector" => self.column_selector = code,
            _ => unreachable!("unknown keymap field {name}"),
        }
    }

    /// Detect user rebinds that can never fire: two actions bound to the
    /// same key, and rebinds shadowed by a view's hardcoded literal key
    /// (an earlier match arm wins, so the rebind is silently dead — the
    /// exact footgun `call_list_action_literal_precedes_later_keymap_arm`
    /// pins). Probes the real per-view action mappers, so a new literal or
    /// mapper automatically participates. Returns human-readable warnings
    /// for startup; empty when the keymap is sound.
    pub fn collisions(&self) -> Vec<String> {
        use crossterm::event::{KeyEvent, KeyModifiers};

        /// A view's key→action mapper, type-erased to the action's Debug
        /// string so mappers with different action enums are comparable.
        type Probe = fn(&Keymap, KeyEvent) -> Option<String>;
        /// Probe the call-list view's action mapper with key `k`.
        fn p_call_list(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::call_list_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the call-flow view's action mapper with key `k`.
        fn p_call_flow(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::call_flow_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the raw-message view's action mapper with key `k`.
        fn p_raw_message(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::raw_message_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the message-diff view's action mapper with key `k`.
        fn p_message_diff(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::message_diff_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the combined-detail view's action mapper with key `k`.
        fn p_combined_detail(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::combined_detail_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the stream-list view's action mapper with key `k`.
        fn p_stream_list(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::stream_list_action(km, k).map(|a| format!("{a:?}"))
        }
        /// Probe the stream-detail view's action mapper with key `k`.
        fn p_stream_detail(km: &Keymap, k: KeyEvent) -> Option<String> {
            crate::tui::controllers::stream_detail_action(km, k).map(|a| format!("{a:?}"))
        }
        let mappers: [(&'static str, Probe); 7] = [
            ("call list", p_call_list),
            ("call flow", p_call_flow),
            ("raw message", p_raw_message),
            ("message diff", p_message_diff),
            ("combined detail", p_combined_detail),
            ("stream list", p_stream_list),
            ("stream detail", p_stream_detail),
        ];

        let mut out = Vec::new();
        let fields = self.fields();

        // Two actions on the same key: only the first-checked arm can win.
        for i in 0..fields.len() {
            for j in (i + 1)..fields.len() {
                if fields[i].1 == fields[j].1 {
                    out.push(format!(
                        "keybinding '{}' and '{}' are both {} — only one can fire",
                        fields[i].0,
                        fields[j].0,
                        key_label(fields[i].1)
                    ));
                }
            }
        }

        // A private-use char no view maps as a literal: binding a field to it
        // and probing reveals which mappers consult that field at all.
        const PROBE_KEY: KeyCode = KeyCode::Char('\u{e000}');
        for (name, code) in fields {
            for (view, mapper) in mappers {
                let mut probe_km = self.clone();
                probe_km.set_field(name, PROBE_KEY);
                if mapper(&probe_km, KeyEvent::new(PROBE_KEY, KeyModifiers::NONE)).is_none() {
                    continue; // this view does not consult this action
                }
                let mut unbound_km = self.clone();
                unbound_km.set_field(name, KeyCode::Null);
                let key = KeyEvent::new(code, KeyModifiers::NONE);
                let bound = mapper(self, key);
                let unbound = mapper(&unbound_km, key);
                // Same non-None action with the binding removed ⇒ a literal
                // arm matched first and the rebind can never fire.
                if unbound.is_some() && bound == unbound {
                    out.push(format!(
                        "keybinding '{name}' = {} is shadowed by a built-in key in the \
                         {view} view and will never fire there",
                        key_label(code)
                    ));
                    break;
                }
            }
        }
        out
    }
}

/// Human-readable label for a key in collision warnings.
fn key_label(code: KeyCode) -> String {
    match code {
        KeyCode::Char(c) => format!("'{c}'"),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    }
}

// ── Adaptive refresh constants ──────────────────────────────────────

/// Poll timeout when data was recently updated.
///
/// A property of the person watching, not of the wire: 100 ms is roughly where
/// a redraw stops reading as a response and starts reading as a delay, and
/// nothing about SIP or RTP argues for a different number. This timeout also
/// bounds how long a keypress waits before the TUI notices it, so raising it
/// makes the whole interface feel late — the arrow key, not just the counters.
/// Lowering it spends CPU redrawing frames nobody perceives, and on a busy
/// capture that CPU competes with the ingest thread this view exists to watch.
///
/// An operator who wants fresher NUMBERS wants a shorter capture or export
/// interval. This constant only decides how often the TUI looks, never how
/// often the data underneath it changes.
pub(super) const ACTIVE_POLL_MS: u64 = 100;
/// Poll timeout when idle (no recent updates).
///
/// The same perception argument, pointed at the case where nothing is
/// happening: at 500 ms an idle session wakes a fifth as often as an active
/// one, and no input feels stuck, because the first keypress ends the poll
/// early rather than waiting it out. Raising it stretches how long the TUI
/// takes to notice that traffic resumed, so the view stays visibly stale after
/// the wire is not. Lowering it hands back the idle saving that having a
/// second constant buys at all — set equal to `ACTIVE_POLL_MS` and the
/// adaptive tier stops existing.
pub(super) const IDLE_POLL_MS: u64 = 500;
/// Duration after the last data update before switching to idle polling.
pub(super) const IDLE_THRESHOLD: Duration = Duration::from_secs(2);
/// Floor between generation-driven rebuilds of the per-view UI caches
/// (call-list displayed rows, stream-list displayed rows, statistics
/// text, dashboard snapshot, call-flow ladder generations). On a busy
/// capture the store generations bump on every ingest, so each tick —
/// including the one after every arrow keypress — re-derived these from
/// scratch (filter-DSL passes, sorts, full-store aggregation) and the UI
/// crawled. Data churn alone refreshes each cache at most once per
/// floor; user inputs (filter/search/sort/view changes) bypass it.
/// 300 ms ≈ 3 refreshes/s, above what a human tracks in a monitoring
/// view.
///
/// Fixed against the eye rather than the traffic. Raising it makes a busy
/// capture's lists visibly lag the counters beside them, and the two
/// disagreeing is worse than either being slow. Lowering it walks back toward
/// the defect this floor exists to fix, where every ingest re-derives every
/// cache and the UI crawls exactly when the capture is most worth watching.
/// An operator who wants a specific view refreshed sooner presses the key for
/// it, since user input bypasses this floor by design.
pub(super) const CHURN_REBUILD_MIN: Duration = Duration::from_millis(300);
/// Consecutive render ticks allowed to skip on store-lock contention
/// before the next tick takes blocking reads instead. Bounds staleness
/// to ~FORCED_DRAW_AFTER_SKIPS × ACTIVE_POLL_MS on a write-saturated
/// capture without ever flushing a half-rendered frame.
///
/// Three is what keeps that staleness ceiling inside human tolerance at the
/// active poll rate. Raise it and a write-saturated capture shows a frozen
/// screen for longer with no sign that anything is wrong — the worst reading
/// of a monitoring view, because a stopped display and a quiet wire look
/// identical. Lower it to zero and every tick takes blocking reads, so the TUI
/// contends with the ingest path it is there to observe. The remedy for
/// persistent contention is a cheaper view or a narrower filter, not a
/// different number here.
pub(super) const FORCED_DRAW_AFTER_SKIPS: u32 = 3;

/// Tests for `Keymap::collisions`: duplicate bindings, rebinds shadowed
/// by view-literal keys, and clean rebinds staying silent.
#[cfg(test)]
mod keymap_collision_tests {
    use super::*;

    /// A rebind onto a hardcoded view literal silently never fires (the
    /// literal match arm wins). from_config callers surface these warnings
    /// at startup instead of leaving the user with a dead binding.
    #[test]
    fn rebind_shadowed_by_view_literal_is_reported() {
        // 't' is the call list's hardcoded CycleTimestampMode key.
        let km = Keymap {
            save: KeyCode::Char('t'),
            ..Default::default()
        };
        let collisions = km.collisions();
        assert!(
            collisions
                .iter()
                .any(|c| c.contains("save") && c.contains('t')),
            "expected a shadowing warning for save='t', got: {collisions:?}"
        );
    }

    /// The shipped default keymap must produce zero collision warnings.
    #[test]
    fn default_keymap_has_no_collisions() {
        let collisions = Keymap::default().collisions();
        assert!(
            collisions.is_empty(),
            "defaults must be collision-free: {collisions:?}"
        );
    }

    /// Two actions bound to the same key produce a duplicate warning
    /// naming both actions.
    #[test]
    fn duplicate_bindings_between_actions_are_reported() {
        let km = Keymap {
            quit: KeyCode::Char('/'), // duplicates the default search key
            ..Default::default()
        };
        let collisions = km.collisions();
        assert!(
            collisions
                .iter()
                .any(|c| c.contains("quit") && c.contains("search")),
            "expected a duplicate-binding warning, got: {collisions:?}"
        );
    }

    /// A rebind onto a free key must NOT be reported. ('w' stopped being
    /// free when the call flow view gained the wrap toggle; 'z' is bound
    /// nowhere.)
    #[test]
    fn clean_rebind_is_not_reported() {
        let km = Keymap {
            save: KeyCode::Char('z'),
            ..Default::default()
        };
        let collisions = km.collisions();
        assert!(
            collisions.is_empty(),
            "save='z' is a clean rebind: {collisions:?}"
        );
    }

    /// The wrap toggle is a call-flow built-in: rebinding onto 'w' must
    /// warn that it is shadowed there.
    #[test]
    fn rebind_onto_wrap_toggle_key_is_reported() {
        let km = Keymap {
            save: KeyCode::Char('w'),
            ..Default::default()
        };
        assert!(
            km.collisions()
                .iter()
                .any(|c| c.contains("'save' = 'w'") && c.contains("call flow")),
            "expected a shadowed-by-built-in warning for 'w'"
        );
    }
}

/// Tests for the NO_COLOR handling in `Theme::from_config_with_no_color`.
#[cfg(test)]
mod no_color_tests {
    use super::*;

    /// NO_COLOR (<https://no-color.org>) must collapse the theme — including
    /// the hardcoded RGB status-bar background, which ignored both the
    /// terminal palette and the user's no-color request.
    #[test]
    fn no_color_collapses_theme_to_monochrome() {
        let config = crate::config::ThemeConfig {
            good: Some("green".to_string()),
            ..Default::default()
        };
        let t = Theme::from_config_with_no_color(&config, true);
        assert_eq!(t.good, Color::Reset, "config colors ignored under NO_COLOR");
        assert_eq!(t.bad, Color::Reset);
        assert_eq!(t.header, Color::Reset);
        assert_eq!(t.status_bg, Color::Reset, "RGB status bg must collapse");

        let t = Theme::from_config_with_no_color(&config, false);
        assert_eq!(t.good, Color::Green, "without NO_COLOR config still wins");
        assert_eq!(t.status_bg, Color::Rgb(48, 48, 64));
    }
}

#[cfg(test)]
mod status_bg_config_tests {
    use super::*;

    /// `status_bg` must be user-configurable like every sibling color: a
    /// value set in `[theme]` has to survive a TOML serialize→deserialize
    /// round trip AND reach the resolved [`Theme`] via
    /// [`Theme::from_config`]. Guards against a future config refactor
    /// silently dropping the one theme color that used to be hardcoded.
    #[test]
    fn status_bg_round_trips_through_config() {
        let config = crate::config::ThemeConfig {
            status_bg: Some("#0a1e28".to_string()),
            ..Default::default()
        };
        // Serialize to TOML and read it back: the field must survive both.
        let serialized = toml::to_string(&config).expect("serialize ThemeConfig");
        assert!(
            serialized.contains("status_bg"),
            "status_bg must serialize into config TOML, got:\n{serialized}"
        );
        let restored: crate::config::ThemeConfig =
            toml::from_str(&serialized).expect("deserialize ThemeConfig");
        assert_eq!(restored.status_bg.as_deref(), Some("#0a1e28"));

        // And the parsed config must reach the resolved theme.
        let theme = Theme::from_config_with_no_color(&restored, false);
        assert_eq!(theme.status_bg, Color::Rgb(10, 30, 40));
    }
}
