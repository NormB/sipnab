// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Resolved theme and keymap types plus adaptive refresh constants.

use super::{Color, Duration, KeyCode, KeybindingsConfig, ThemeConfig, parse_color, parse_keycode};

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
    /// NO_COLOR was requested: this is [`Self::monochrome`]. A view that
    /// draws a color of its own, one that is not a slot above, leaves it out
    /// when this is set and marks state with a text attribute instead.
    pub no_color: bool,
}

impl Default for Theme {
    /// Built-in color scheme: terminal-default background, an RGB
    /// status-bar band readable on dark and light terminals.
    fn default() -> Self {
        Self {
            background: Color::Reset,
            // The terminal's own text color: white was near-invisible on a
            // light terminal. The status band sets its own contrasting text
            // (`render::status::status_bar_style`), so nothing drawn on a
            // background this theme paints relies on this being white.
            foreground: Color::Reset,
            header: Color::Cyan,
            selected: Color::Yellow,
            accent: Color::Magenta,
            good: Color::Green,
            warning: Color::Yellow,
            bad: Color::Red,
            muted: Color::DarkGray,
            border: Color::White,
            status_bg: Color::Rgb(48, 48, 64), // Dark blue-gray, readable on both dark and light
            no_color: false,
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
    /// Nothing here is a color, `selected` included: gray is a color, and
    /// it was drawn as gray text and a gray band. A selection is marked
    /// with reverse video where [`Self::no_color`] is set.
    pub fn monochrome() -> Self {
        Self {
            background: Color::Reset,
            foreground: Color::Reset,
            header: Color::Reset,
            selected: Color::Reset,
            accent: Color::Reset,
            good: Color::Reset,
            warning: Color::Reset,
            bad: Color::Reset,
            muted: Color::Reset,
            border: Color::Reset,
            status_bg: Color::Reset,
            no_color: true,
        }
    }
}

/// NO_COLOR is honored when set to a non-empty value (<https://no-color.org>).
fn no_color_requested() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

// ── Contrast ───────────────────────────────────────────────────────

/// The WCAG 2.2 level AA minimum contrast ratio for normal-size text
/// (success criterion 1.4.3).
pub(crate) const AA_TEXT_CONTRAST: f64 = 4.5;

/// The sRGB value of `color`, or `None` when it has no portable one.
///
/// The named ANSI colors map to their conventional sRGB values. `Reset` is
/// whatever the terminal uses and an indexed color depends on the terminal's
/// palette, so neither can be measured.
pub(crate) fn srgb(color: Color) -> Option<(u8, u8, u8)> {
    Some(match color {
        Color::Reset | Color::Indexed(_) => return None,
        Color::Black => (0, 0, 0),
        Color::Red => (170, 0, 0),
        Color::Green => (0, 170, 0),
        Color::Yellow => (170, 85, 0),
        Color::Blue => (0, 0, 170),
        Color::Magenta => (170, 0, 170),
        Color::Cyan => (0, 170, 170),
        Color::Gray => (170, 170, 170),
        Color::DarkGray => (85, 85, 85),
        Color::LightRed => (255, 85, 85),
        Color::LightGreen => (85, 255, 85),
        Color::LightYellow => (255, 255, 85),
        Color::LightBlue => (85, 85, 255),
        Color::LightMagenta => (255, 85, 255),
        Color::LightCyan => (85, 255, 255),
        Color::White => (255, 255, 255),
        Color::Rgb(r, g, b) => (r, g, b),
    })
}

/// WCAG 2 relative luminance of an sRGB value: linearize each channel, then
/// weight. 0.0 is black and 1.0 is white.
pub(crate) fn relative_luminance((r, g, b): (u8, u8, u8)) -> f64 {
    let channel = |c: u8| {
        let v = f64::from(c) / 255.0;
        if v <= 0.040_45 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

/// WCAG 2 contrast ratio of two luminances, from 1.0 to 21.0.
fn luminance_ratio(a: f64, b: f64) -> f64 {
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// WCAG 2 contrast ratio between two colors, from 1.0 (identical) to 21.0
/// (black and white), or `None` when either has no sRGB value (see [`srgb`]).
pub(crate) fn contrast_ratio(a: Color, b: Color) -> Option<f64> {
    Some(luminance_ratio(
        relative_luminance(srgb(a)?),
        relative_luminance(srgb(b)?),
    ))
}

/// The color to draw `fg`-colored text in on a background painted `bg`, so
/// that the pair meets [`AA_TEXT_CONTRAST`].
///
/// A pair that already passes is returned unchanged. One that fails is mixed
/// toward black or white, whichever contrasts more with `bg`, in eighths, and
/// the first mix that passes is used: the hue survives and only the lightness
/// moves. The last step is black or white itself, which always passes (the
/// better of the two is never below about 4.58:1).
///
/// When `bg` cannot be measured (`Reset`, the NO_COLOR theme, or an indexed
/// color) `fg` is returned unchanged, so no color is introduced. When only
/// `fg` cannot be measured, the black-or-white pick is returned: the terminal
/// default is dark on a light terminal and must not be drawn on a dark band.
///
/// Pure arithmetic; allocates nothing.
pub(crate) fn legible_on(fg: Color, bg: Color) -> Color {
    let Some(bg_rgb) = srgb(bg) else {
        return fg;
    };
    let bg_l = relative_luminance(bg_rgb);
    let toward_white = luminance_ratio(1.0, bg_l) >= luminance_ratio(0.0, bg_l);
    let (target, pick) = if toward_white {
        (255_u16, Color::White)
    } else {
        (0_u16, Color::Black)
    };
    let Some((r, g, b)) = srgb(fg) else {
        return pick;
    };
    if contrast_ratio(fg, bg).is_some_and(|ratio| ratio >= AA_TEXT_CONTRAST) {
        return fg;
    }
    for step in 1..8_u16 {
        // Each channel moves `step` eighths of the way to the target. The
        // result is between the channel and the target, so it fits a `u8`.
        let mix = |c: u8| {
            let c = u16::from(c);
            u8::try_from((c * (8 - step) + target * step) / 8).unwrap_or(u8::MAX)
        };
        let mixed = (mix(r), mix(g), mix(b));
        if luminance_ratio(relative_luminance(mixed), bg_l) >= AA_TEXT_CONTRAST {
            return Color::Rgb(mixed.0, mixed.1, mixed.2);
        }
    }
    pick
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
    /// Switch status line 3 between the summary and the full expression of
    /// the F7 dialog's filter (default `F`). Answered in every view, ahead of
    /// the view's own keys.
    pub filter_detail: KeyCode,
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
            filter_detail: KeyCode::Char('F'),
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
        apply_key(&mut km.filter_detail, &config.filter_detail);
        km
    }

    /// `(name, key)` pairs for every rebindable action.
    fn fields(&self) -> [(&'static str, KeyCode); 12] {
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
            ("filter_detail", self.filter_detail),
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
            "filter_detail" => self.filter_detail = code,
            // gate: unreachable because every caller iterates `Self::fields`,
            // and `set_field_accepts_every_name_fields_produces` holds the
            // two lists together.
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

        // The filter-detail key is answered before any view sees the key
        // (`controllers::handle_key_event`), so a view key it lands on can no
        // longer fire in that view.
        let detail = KeyEvent::new(self.filter_detail, KeyModifiers::NONE);
        for (view, mapper) in mappers {
            if mapper(self, detail).is_some() {
                out.push(format!(
                    "keybinding 'filter_detail' = {} takes that key from the {view} \
                     view, where its own action will never fire",
                    key_label(self.filter_detail)
                ));
                break;
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

    /// Every name `fields` produces is one `set_field` accepts, and sets
    /// the field `fields` reports under that name.
    ///
    /// The two are one list written twice, and `set_field`'s fallthrough
    /// arm is an `unreachable!` resting on their agreement. A field added
    /// to one and not the other used to be a panic inside the startup
    /// collision probe; here it is a failing test.
    #[test]
    fn set_field_accepts_every_name_fields_produces() {
        let km = Keymap::default();
        for (name, _) in km.fields() {
            let mut probe = km.clone();
            probe.set_field(name, KeyCode::Null);
            let now = probe
                .fields()
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, code)| *code);
            assert_eq!(
                now,
                Some(KeyCode::Null),
                "set_field({name:?}) did not set the field fields() reports under that name"
            );
        }
    }

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

    /// The filter-detail key is `F` by default, a letter no view uses.
    #[test]
    fn the_filter_detail_key_defaults_to_shift_f() {
        assert_eq!(Keymap::default().filter_detail, KeyCode::Char('F'));
    }

    /// `[keybindings] filter_detail` rebinds the key.
    #[test]
    fn the_filter_detail_key_is_rebound_from_config() {
        let config = KeybindingsConfig {
            filter_detail: Some("W".to_string()),
            ..Default::default()
        };
        assert_eq!(
            Keymap::from_config(&config).filter_detail,
            KeyCode::Char('W')
        );
    }

    /// The filter-detail key is answered before any view sees the key, so
    /// binding it to a view's own key takes that key from the view. The
    /// warning says so and names the view.
    #[test]
    fn a_filter_detail_key_that_takes_a_view_key_is_reported() {
        // 'r' opens the raw message in the call list.
        let km = Keymap {
            filter_detail: KeyCode::Char('r'),
            ..Default::default()
        };
        let collisions = km.collisions();
        assert!(
            collisions
                .iter()
                .any(|c| c.contains("'filter_detail' = 'r'") && c.contains("call list")),
            "expected a warning that filter_detail takes 'r', got: {collisions:?}"
        );
        // One warning names the first view; several views using the key do
        // not repeat it.
        assert_eq!(
            collisions
                .iter()
                .filter(|c| c.contains("'filter_detail'"))
                .count(),
            1,
            "{collisions:?}"
        );
        // 'W' is used by no view: nothing to report.
        let free = Keymap {
            filter_detail: KeyCode::Char('W'),
            ..Default::default()
        };
        assert!(free.collisions().is_empty(), "{:?}", free.collisions());
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

    /// Failure: the NO_COLOR theme holds no color in any slot. `selected`
    /// was gray, which drew gray text and a gray band under NO_COLOR.
    #[test]
    fn the_no_color_theme_holds_no_color_in_any_slot() {
        let t = Theme::monochrome();
        for (name, color) in [
            ("background", t.background),
            ("foreground", t.foreground),
            ("header", t.header),
            ("selected", t.selected),
            ("accent", t.accent),
            ("good", t.good),
            ("warning", t.warning),
            ("bad", t.bad),
            ("muted", t.muted),
            ("border", t.border),
            ("status_bg", t.status_bg),
        ] {
            assert_eq!(color, Color::Reset, "{name}");
        }
    }

    /// Failure: a `selected` color in the config is ignored under NO_COLOR,
    /// like every other configured color.
    #[test]
    fn a_configured_selected_color_is_ignored_under_no_color() {
        let config = crate::config::ThemeConfig {
            selected: Some("yellow".to_string()),
            ..Default::default()
        };
        let t = Theme::from_config_with_no_color(&config, true);
        assert_eq!(t.selected, Color::Reset, "config ignored");
    }

    /// Edge: the legacy `highlight` alias is ignored under NO_COLOR too.
    #[test]
    fn the_highlight_alias_is_ignored_under_no_color() {
        let config = crate::config::ThemeConfig {
            highlight: Some("yellow".to_string()),
            ..Default::default()
        };
        let t = Theme::from_config_with_no_color(&config, true);
        assert_eq!(t.selected, Color::Reset, "alias ignored");
    }

    /// Success: a color theme keeps its yellow `selected`; only the
    /// NO_COLOR theme changed.
    #[test]
    fn the_default_theme_keeps_its_selected_color() {
        assert_eq!(Theme::default().selected, Color::Yellow, "unchanged");
    }

    /// The NO_COLOR theme says so, so a view with colors of its own (not
    /// theme slots) can leave them out. The default theme does not.
    #[test]
    fn only_the_no_color_theme_reports_no_color() {
        assert!(Theme::monochrome().no_color, "monochrome is NO_COLOR");
        assert!(!Theme::default().no_color, "the default theme has color");
        let config = crate::config::ThemeConfig::default();
        assert!(
            Theme::from_config_with_no_color(&config, true).no_color,
            "NO_COLOR requested"
        );
        assert!(
            !Theme::from_config_with_no_color(&config, false).no_color,
            "NO_COLOR not requested"
        );
    }

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

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// `status_bg` must be user-configurable like every sibling color: a
    /// value set in `[theme]` has to survive a TOML serialize→deserialize
    /// round trip AND reach the resolved [`Theme`] via
    /// [`Theme::from_config`]. Guards against a future config refactor
    /// silently dropping the one theme color that used to be hardcoded.
    #[test]
    fn status_bg_round_trips_through_config() -> Result<(), TestError> {
        let config = crate::config::ThemeConfig {
            status_bg: Some("#0a1e28".to_string()),
            ..Default::default()
        };
        // Serialize to TOML and read it back: the field must survive both.
        let serialized =
            toml::to_string(&config).map_err(|e| format!("serialize ThemeConfig: {e:?}"))?;
        assert!(
            serialized.contains("status_bg"),
            "status_bg must serialize into config TOML, got:\n{serialized}"
        );
        let restored: crate::config::ThemeConfig =
            toml::from_str(&serialized).map_err(|e| format!("deserialize ThemeConfig: {e:?}"))?;
        assert_eq!(restored.status_bg.as_deref(), Some("#0a1e28"));

        // And the parsed config must reach the resolved theme.
        let theme = Theme::from_config_with_no_color(&restored, false);
        assert_eq!(theme.status_bg, Color::Rgb(10, 30, 40));
        Ok(())
    }
}

/// Tests for the WCAG contrast functions and [`legible_on`].
#[cfg(test)]
mod contrast_tests {
    use super::*;

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// The default status band every status row paints.
    const BAND: Color = Color::Rgb(48, 48, 64);

    fn ratio(a: Color, b: Color) -> Result<f64, TestError> {
        Ok(contrast_ratio(a, b).ok_or("both colors have an sRGB value")?)
    }

    /// Success: white on black is the WCAG maximum, 21:1.
    #[test]
    fn white_on_black_is_twenty_one_to_one() -> Result<(), TestError> {
        let r = ratio(Color::White, Color::Black)?;
        assert!((r - 21.0).abs() < 1e-9, "{r}");
        Ok(())
    }

    /// Success: the ratio does not depend on which color is the text.
    #[test]
    fn the_ratio_is_symmetric() -> Result<(), TestError> {
        let a = ratio(Color::Red, BAND)?;
        let b = ratio(BAND, Color::Red)?;
        assert!((a - b).abs() < 1e-12, "{a} vs {b}");
        Ok(())
    }

    /// Success: a pair that already meets AA is returned untouched, so a
    /// theme that is already legible is drawn exactly as configured.
    #[test]
    fn a_color_that_already_passes_is_unchanged() -> Result<(), TestError> {
        assert!(
            ratio(Color::LightYellow, BAND)? >= AA_TEXT_CONTRAST,
            "light yellow passes on the band"
        );
        assert_eq!(
            legible_on(Color::LightYellow, BAND),
            Color::LightYellow,
            "a passing color is kept"
        );
        Ok(())
    }

    /// Success: the default error color is lifted to AA on the status band.
    #[test]
    fn the_error_color_is_lifted_to_aa_on_the_status_band() -> Result<(), TestError> {
        let fixed = legible_on(Color::Red, BAND);
        let r = ratio(fixed, BAND)?;
        assert!(r >= AA_TEXT_CONTRAST, "{fixed:?} is {r}:1");
        Ok(())
    }

    /// Success: every text color of the default theme, drawn through
    /// `legible_on`, meets AA on the default status band.
    #[test]
    fn every_default_theme_color_meets_aa_on_the_status_band() -> Result<(), TestError> {
        let t = Theme::default();
        for (name, c) in [
            ("header", t.header),
            ("selected", t.selected),
            ("accent", t.accent),
            ("good", t.good),
            ("warning", t.warning),
            ("bad", t.bad),
            ("muted", t.muted),
            ("border", t.border),
        ] {
            let r = ratio(legible_on(c, t.status_bg), t.status_bg)?;
            assert!(r >= AA_TEXT_CONTRAST, "{name} is {r}:1");
        }
        Ok(())
    }

    /// Failure: the defect this guards. Unadjusted, the default error color
    /// is far below AA on the default status band (about 1.7:1).
    #[test]
    fn the_raw_error_color_fails_aa_on_the_status_band() -> Result<(), TestError> {
        let r = ratio(Color::Red, BAND)?;
        assert!(r < 2.0, "{r}");
        Ok(())
    }

    /// Failure: the terminal default has no known sRGB value, so no ratio.
    #[test]
    fn reset_has_no_ratio() {
        assert_eq!(
            contrast_ratio(Color::Reset, Color::Black),
            None,
            "reset as text"
        );
        assert_eq!(
            contrast_ratio(Color::Black, Color::Reset),
            None,
            "reset as background"
        );
    }

    /// Failure: an indexed color has no portable sRGB value, so no ratio.
    #[test]
    fn an_indexed_color_has_no_ratio() {
        assert_eq!(
            contrast_ratio(Color::Indexed(100), Color::Black),
            None,
            "an indexed color is unmeasured"
        );
    }

    /// Failure: on an unpainted background (the NO_COLOR theme) nothing can
    /// be computed and nothing is changed: no color is introduced.
    #[test]
    fn nothing_changes_on_an_unpainted_background() {
        assert_eq!(
            legible_on(Color::Reset, Color::Reset),
            Color::Reset,
            "default text stays default"
        );
        assert_eq!(
            legible_on(Color::Red, Color::Reset),
            Color::Red,
            "a color on no band is kept"
        );
    }

    /// Failure: default-colored text on a painted band cannot be measured
    /// (it is dark on a light terminal), so it takes the black-or-white pick.
    #[test]
    fn default_text_on_a_painted_band_takes_the_black_or_white_pick() {
        assert_eq!(
            legible_on(Color::Reset, BAND),
            Color::White,
            "white on the dark band"
        );
        assert_eq!(
            legible_on(Color::Reset, Color::Cyan),
            Color::Black,
            "black on a cyan band"
        );
    }

    /// Edge: a color against itself is 1:1.
    #[test]
    fn a_color_against_itself_is_one_to_one() -> Result<(), TestError> {
        let r = ratio(BAND, BAND)?;
        assert!((r - 1.0).abs() < 1e-12, "{r}");
        Ok(())
    }

    /// Edge: on the mid-gray where black and white are nearly tied (the
    /// worst case for any text), the result still meets AA.
    #[test]
    fn the_worst_case_gray_background_still_reaches_aa() -> Result<(), TestError> {
        let bg = Color::Rgb(118, 118, 118);
        let r = ratio(legible_on(bg, bg), bg)?;
        assert!(r >= AA_TEXT_CONTRAST, "{r}");
        Ok(())
    }

    /// Edge: an indexed background cannot be measured; the text is unchanged.
    #[test]
    fn text_on_an_indexed_background_is_unchanged() {
        assert_eq!(
            legible_on(Color::Red, Color::Indexed(17)),
            Color::Red,
            "an indexed band cannot be measured"
        );
    }

    /// Edge: lifting keeps the hue. Red stays red-dominant, so "bad" still
    /// reads as red after the adjustment.
    #[test]
    fn lifting_keeps_the_hue() -> Result<(), TestError> {
        let Color::Rgb(r, g, b) = legible_on(Color::Red, BAND) else {
            return Err("a lifted color is an RGB value".into());
        };
        assert!(r > g && r > b, "({r}, {g}, {b})");
        Ok(())
    }

    /// Edge: on a light band the adjustment darkens the text.
    #[test]
    fn a_light_background_darkens_the_text() -> Result<(), TestError> {
        let fixed = legible_on(Color::LightYellow, Color::White);
        assert!(
            ratio(fixed, Color::White)? >= AA_TEXT_CONTRAST,
            "{fixed:?} on white"
        );
        assert!(
            ratio(fixed, Color::Black)? < ratio(Color::LightYellow, Color::Black)?,
            "{fixed:?} is darker than light yellow"
        );
        Ok(())
    }
}
