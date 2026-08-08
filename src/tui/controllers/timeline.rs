// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key handling for the call-timeline view.
//!
//! The timeline is a single-screen view of one dialog: the proportional
//! phase bar always fills the available width and the per-phase labels,
//! metric summary and legend fit in a fixed handful of lines, so there is
//! nothing to scroll and no list to select. `Close` is therefore the only
//! action by design — the view is intentionally non-navigable, not a
//! placeholder awaiting navigation.
//!
//! Both halves of that are tested, and they are tested in different places
//! because the input takes different paths. Keys go through
//! [`timeline_action`], which
//! `timeline_action_leaves_navigation_keys_unbound` pins. The WHEEL does not
//! reach this file at all — it goes to the mouse dispatcher in the parent
//! module, whose `View::CallTimeline(_) => {}` arm is what makes the contract
//! true, and `timeline_wheel_moves_no_selection_and_no_scroll_offset` is what
//! makes that arm observable.

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

    /// The wheel is inert in the timeline, and no other view's state moves
    /// behind it either.
    ///
    /// The sibling above covers the KEYBOARD half of the static contract and
    /// was for a while described as covering both. It does not: the wheel does
    /// not go through `timeline_action` at all. It goes through the mouse
    /// dispatcher, where the whole of the contract is `View::CallTimeline(_)
    /// => {}` — an arm whose correctness nothing observed, which is the one
    /// kind of code that can be deleted without a single test noticing.
    ///
    /// Asserting "the timeline did not scroll" alone would be weak, because
    /// the timeline has no scroll offset of its own to check. So this snapshots
    /// every field a wheel arm in that dispatcher can write — the four
    /// selections and the five scroll offsets — and requires all of them
    /// unmoved. That is what makes it catch the realistic regression: the arm
    /// being folded into a neighbour's, or replaced by a `_ =>` catch-all,
    /// scrolls SOMETHING, and it would be another view's state that moved.
    ///
    /// The call-list selection is deliberately moved off row 0 first. Left at
    /// 0, a stray `move_up()` clamps to 0 and reads as inert.
    #[test]
    fn timeline_wheel_moves_no_selection_and_no_scroll_offset() {
        use crossterm::event::MouseEventKind as MK;

        let mut app = app_with_dialogs();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Char('T'));
        assert!(
            matches!(app.current_view, View::CallTimeline(_)),
            "the fixture has to actually be in the timeline, or this test \
             pins some other view's wheel arm"
        );
        assert_ne!(
            app.call_list.selected(),
            0,
            "the selection must start off row 0, or a stray move_up() clamps \
             to 0 and is indistinguishable from doing nothing"
        );

        // Every field `handle_mouse_event` writes in some view, in one tuple:
        // the four selections and the five scroll offsets.
        let snapshot = |a: &App| {
            (
                a.call_list.selected(),
                a.stream_list.selected(),
                a.dashboard_selected,
                a.flow.selected,
                a.flow.detail_scroll,
                a.raw_msg_scroll,
                a.diff_scroll,
                a.stream_detail_scroll,
                a.help_scroll,
                a.stats_scroll,
            )
        };
        let before = snapshot(&app);
        let view_before = app.current_view.clone();

        // Several of each, in both directions: one step of a saturating
        // offset already at 0 can be invisible, and a wheel arm that only
        // moves on the way down would survive a single ScrollUp.
        for _ in 0..3 {
            app.handle_mouse_kind(MK::ScrollDown);
            app.handle_mouse_kind(MK::ScrollUp);
        }
        for _ in 0..3 {
            app.handle_mouse_kind(MK::ScrollDown);
        }

        assert_eq!(
            snapshot(&app),
            before,
            "the wheel is inert in the timeline: it has nothing to scroll and \
             nothing to select, so no selection and no scroll offset anywhere \
             in the app may move. Tuple order: call_list, stream_list, \
             dashboard, flow.selected, flow.detail_scroll, raw_msg, diff, \
             stream_detail, help, stats"
        );
        assert_eq!(
            app.current_view, view_before,
            "and the wheel must not navigate out of the view either"
        );
    }
}
