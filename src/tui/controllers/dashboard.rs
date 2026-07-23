//! Key handling for the live call-quality dashboard view.

use crate::tui::*;

/// Everything the quality dashboard view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardAction {
    /// Esc, the quit key, or `D` — return to the view the dashboard was
    /// opened from.
    Close,
    /// Move the row selection up one row (saturating at the top).
    Up,
    /// Move the row selection down one row (clamped to the last row).
    Down,
    /// Move the row selection up ten rows (saturating at the top).
    PageUp,
    /// Move the row selection down ten rows (clamped to the last row).
    PageDown,
    /// Jump the row selection to the first row.
    Top,
    /// Jump the row selection to the last row.
    Bottom,
    /// Enter — open the stream detail view of the selected row's stream.
    OpenStreamDetail,
}

/// Pure key→action mapping for the quality dashboard (keymap-aware).
///
/// # Arguments
/// * `km` - the active keymap; the rebindable quit key is honored.
/// * `key` - the key event whose code is matched against the bindings.
///
/// # Returns
/// The mapped `DashboardAction`, or `None` when the key is not bound in
/// this view.
pub fn dashboard_action(km: &Keymap, key: KeyEvent) -> Option<DashboardAction> {
    use DashboardAction::*;
    Some(match key.code {
        k if k == KeyCode::Esc || k == km.quit || k == KeyCode::Char('D') => Close,
        KeyCode::Up | KeyCode::Char('k') => Up,
        KeyCode::Down | KeyCode::Char('j') => Down,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => Top,
        KeyCode::End => Bottom,
        KeyCode::Enter => OpenStreamDetail,
        _ => return None,
    })
}

/// Handle keys in the quality dashboard: map, then execute.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, mapped via `dashboard_action`.
///
/// # Side effects
/// Navigation actions move `app.dashboard_selected`, clamped to the row
/// count of the current `dashboard_snapshot`. `Close` restores
/// `app.current_view` from `dashboard_return_view` (call list fallback).
/// `OpenStreamDetail` resets `stream_detail_scroll`, records the dashboard
/// as the return view, and switches to the selected row's stream detail.
pub(in crate::tui) fn handle_dashboard_key(app: &mut App, key: KeyEvent) {
    let Some(action) = dashboard_action(&app.keymap, key) else {
        return;
    };
    let rows = app.dashboard_snapshot.as_ref().map_or(0, |s| s.rows.len());
    let clamp = |i: usize| if rows > 0 { i.min(rows - 1) } else { 0 };
    match action {
        DashboardAction::Close => {
            app.current_view = app.dashboard_return_view.take().unwrap_or(View::CallList);
        }
        DashboardAction::Up => {
            app.dashboard_selected = app.dashboard_selected.saturating_sub(1);
        }
        DashboardAction::Down => {
            app.dashboard_selected = clamp(app.dashboard_selected + 1);
        }
        DashboardAction::PageUp => {
            app.dashboard_selected = app.dashboard_selected.saturating_sub(10);
        }
        DashboardAction::PageDown => {
            app.dashboard_selected = clamp(app.dashboard_selected + 10);
        }
        DashboardAction::Top => app.dashboard_selected = 0,
        DashboardAction::Bottom => {
            app.dashboard_selected = rows.saturating_sub(1);
        }
        DashboardAction::OpenStreamDetail => {
            let key = app
                .dashboard_snapshot
                .as_ref()
                .and_then(|s| s.rows.get(app.dashboard_selected))
                .map(|r| r.key.clone());
            if let Some(k) = key {
                app.stream_detail_scroll = 0;
                app.stream_detail_return_view = Some(View::QualityDashboard);
                app.current_view = View::StreamDetail(k);
            }
        }
    }
}

/// Unit tests for the dashboard key mapping and open/close navigation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// The default keymap maps every navigation, close, and Enter binding;
    /// unbound keys map to `None`.
    #[test]
    fn dashboard_action_maps_nav_and_close() {
        let km = Keymap::default();
        use DashboardAction::*;
        assert_eq!(dashboard_action(&km, key(KeyCode::Esc)), Some(Close));
        assert_eq!(dashboard_action(&km, key(KeyCode::Char('D'))), Some(Close));
        assert_eq!(dashboard_action(&km, key(KeyCode::Up)), Some(Up));
        assert_eq!(dashboard_action(&km, key(KeyCode::Char('k'))), Some(Up));
        assert_eq!(dashboard_action(&km, key(KeyCode::Down)), Some(Down));
        assert_eq!(dashboard_action(&km, key(KeyCode::Char('j'))), Some(Down));
        assert_eq!(dashboard_action(&km, key(KeyCode::Home)), Some(Top));
        assert_eq!(dashboard_action(&km, key(KeyCode::End)), Some(Bottom));
        assert_eq!(
            dashboard_action(&km, key(KeyCode::Enter)),
            Some(OpenStreamDetail)
        );
        assert_eq!(dashboard_action(&km, key(KeyCode::Char('z'))), None);
    }

    /// A rebound quit key maps to `Close` and the old key unbinds.
    #[test]
    fn dashboard_action_honors_remapped_quit() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            dashboard_action(&km, key(KeyCode::Char('x'))),
            Some(DashboardAction::Close)
        );
        assert_eq!(dashboard_action(&km, key(KeyCode::Char('q'))), None);
    }

    /// `D` from the call list opens the dashboard; Esc returns to the
    /// call list.
    #[test]
    fn dashboard_opens_from_call_list_and_returns_on_close() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('D'));
        assert_eq!(app.current_view, View::QualityDashboard);
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.current_view, View::CallList);
    }

    /// The dashboard remembers its opener: opened from the stream list,
    /// closing returns to the stream list rather than the call list.
    #[test]
    fn dashboard_opens_from_stream_list_and_returns_there() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        app.handle_key(KeyCode::Char('D'));
        assert_eq!(app.current_view, View::QualityDashboard);
        app.handle_key(KeyCode::Char('D'));
        assert_eq!(app.current_view, View::StreamList);
    }
}
