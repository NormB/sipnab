// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key handling for the call-timeline view.
//!
//! The timeline is a single-screen view of one dialog: the proportional
//! phase bar always fills the available width and the per-phase labels,
//! metric summary and legend fit in a fixed handful of lines, so there is
//! nothing to scroll and no list to select. `Close` is therefore the only
//! action by design — the view is intentionally non-navigable, not a
//! placeholder awaiting navigation.

use crate::tui::*;

/// Everything the call-timeline view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimelineAction {
    /// Esc or the configured quit key — leave the timeline and return to
    /// the call list.
    Close,
}

/// Pure key→action mapping for the call-timeline view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `TimelineAction`, or `None` when the key is not bound in
/// this view.
pub fn timeline_action(km: &Keymap, key: KeyEvent) -> Option<TimelineAction> {
    use TimelineAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit => Close,
        _ => return None,
    })
}

/// Handle keys in the call-timeline view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `timeline_action`.
///
/// # Side effects
/// `Close` switches `app.current_view` back to the call list. Unbound
/// keys are ignored.
pub(in crate::tui) fn handle_timeline_key(app: &mut App, key: KeyEvent) {
    let Some(action) = timeline_action(&app.keymap, key) else {
        return;
    };
    match action {
        TimelineAction::Close => {
            app.current_view = View::CallList;
        }
    }
}

/// Unit tests for the timeline key mapping and the open/close round trip.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// Esc and the default quit key map to `Close`; unbound keys map to `None`.
    #[test]
    fn timeline_action_maps_close() {
        let km = Keymap::default();
        assert_eq!(
            timeline_action(&km, key(KeyCode::Esc)),
            Some(TimelineAction::Close)
        );
        assert_eq!(
            timeline_action(&km, key(KeyCode::Char('q'))),
            Some(TimelineAction::Close)
        );
        assert_eq!(timeline_action(&km, key(KeyCode::Char('z'))), None);
    }

    /// Shift+T on a selected call opens the timeline; Esc returns to the
    /// call list.
    #[test]
    fn timeline_opens_from_call_list_and_esc_returns() {
        let mut app = app_with_dialogs();
        app.handle_key(KeyCode::Char('T'));
        assert!(matches!(app.current_view, View::CallTimeline(_)));
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.current_view, View::CallList);
    }

    /// The quit key closes the timeline (back to the call list) rather
    /// than quitting the app.
    #[test]
    fn timeline_q_also_returns_to_call_list() {
        let mut app = app_with_dialogs();
        app.handle_key(KeyCode::Char('T'));
        assert!(matches!(app.current_view, View::CallTimeline(_)));
        app.handle_key(KeyCode::Char('q'));
        assert_eq!(app.current_view, View::CallList);
    }

    /// A rebound quit key maps to `Close` and the old key unbinds.
    #[test]
    fn timeline_action_honors_remapped_quit() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            timeline_action(&km, key(KeyCode::Char('x'))),
            Some(TimelineAction::Close)
        );
        assert_eq!(timeline_action(&km, key(KeyCode::Char('q'))), None);
    }

    /// The timeline is a single-screen, single-call view: it has no
    /// scrollable or selectable content, so every navigation key (arrows,
    /// vi keys, paging, jumps, Enter) is intentionally unbound. This pins
    /// the static contract so the absence of navigation reads as deliberate
    /// rather than forgotten.
    #[test]
    fn timeline_action_leaves_navigation_keys_unbound() {
        let km = Keymap::default();
        for code in [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Char('j'),
            KeyCode::Char('k'),
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::PageUp,
            KeyCode::PageDown,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Enter,
        ] {
            assert_eq!(
                timeline_action(&km, key(code)),
                None,
                "{code:?} must stay unbound: the timeline is a static view"
            );
        }
    }
}
