// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key handling for the packet-loss-map view.
//!
//! The loss map is a single-screen view of one stream: the density strip
//! always fills the available width and the summary header, sequence axis
//! and legend fit in a fixed handful of lines, so there is nothing to
//! scroll and no list to select. `Close` is therefore the only action by
//! design — the view is intentionally non-navigable, not a placeholder
//! awaiting navigation. Closing returns to the stream's detail view.

use crate::tui::*;

/// Everything the packet-loss-map view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossMapAction {
    /// Esc or the configured quit key — leave the loss map and return to
    /// the stream detail view.
    Close,
}

/// Pure key→action mapping for the packet-loss-map view (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `LossMapAction`, or `None` when the key is not bound in this
/// view.
pub fn loss_map_action(km: &Keymap, key: KeyEvent) -> Option<LossMapAction> {
    use LossMapAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit => Close,
        _ => return None,
    })
}

/// Handle keys in the packet-loss-map view: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `loss_map_action`.
///
/// # Side effects
/// `Close` switches `app.current_view` back to the stream's detail view
/// (`View::StreamDetail(key)`). Unbound keys are ignored.
pub(in crate::tui) fn handle_loss_map_key(app: &mut App, key: KeyEvent) {
    let Some(action) = loss_map_action(&app.keymap, key) else {
        return;
    };
    match action {
        LossMapAction::Close => {
            if let View::StreamLossMap(k) = &app.current_view {
                app.current_view = View::StreamDetail(k.clone());
            }
        }
    }
}

/// Unit tests for the loss-map key mapping and the open/close round trip.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// A synthetic stream key for constructing the loss-map view directly.
    fn stream_key() -> crate::rtp::stream::StreamKey {
        crate::rtp::stream::StreamKey {
            ssrc: 7,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        }
    }

    /// Esc and the default quit key map to `Close`; unbound keys map to `None`.
    #[test]
    fn loss_map_action_maps_close() {
        let km = Keymap::default();
        assert_eq!(
            loss_map_action(&km, key(KeyCode::Esc)),
            Some(LossMapAction::Close)
        );
        assert_eq!(
            loss_map_action(&km, key(KeyCode::Char('q'))),
            Some(LossMapAction::Close)
        );
        assert_eq!(loss_map_action(&km, key(KeyCode::Char('z'))), None);
    }

    /// A rebound quit key maps to `Close` and the old key unbinds.
    #[test]
    fn loss_map_action_honors_remapped_quit() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            loss_map_action(&km, key(KeyCode::Char('x'))),
            Some(LossMapAction::Close)
        );
        assert_eq!(loss_map_action(&km, key(KeyCode::Char('q'))), None);
    }

    /// Esc returns to the stream's detail view (same key), not the stream
    /// list — the loss map is drilled into from detail.
    #[test]
    fn loss_map_esc_returns_to_stream_detail() {
        let mut app = App::new_test();
        let k = stream_key();
        app.current_view = View::StreamLossMap(k.clone());
        handle_loss_map_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamDetail(k));
    }

    /// The quit key closes the loss map (back to stream detail) rather than
    /// quitting the app.
    #[test]
    fn loss_map_q_returns_to_stream_detail() {
        let mut app = App::new_test();
        let k = stream_key();
        app.current_view = View::StreamLossMap(k.clone());
        handle_loss_map_key(&mut app, key(KeyCode::Char('q')));
        assert_eq!(app.current_view, View::StreamDetail(k));
        assert!(!app.should_quit);
    }

    /// The loss map is a single-screen view: every navigation key (arrows,
    /// vi keys, paging, jumps, Enter) is intentionally unbound. This pins
    /// the static contract so the absence of navigation reads as deliberate.
    #[test]
    fn loss_map_action_leaves_navigation_keys_unbound() {
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
                loss_map_action(&km, key(code)),
                None,
                "{code:?} must stay unbound: the loss map is a static view"
            );
        }
    }
}
