// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// `L` — open the packet loss map of the selected row's stream.
    OpenLossMap,
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
        KeyCode::Char('L') => OpenLossMap,
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
        DashboardAction::OpenLossMap => {
            let key = app
                .dashboard_snapshot
                .as_ref()
                .and_then(|s| s.rows.get(app.dashboard_selected))
                .map(|r| r.key.clone());
            if let Some(k) = key {
                // Esc in the loss map returns to this stream's detail; seed
                // that detail's return view so a further Esc lands back on
                // the dashboard the user opened it from.
                app.stream_detail_scroll = 0;
                app.stream_detail_return_view = Some(View::QualityDashboard);
                app.current_view = View::StreamLossMap(k);
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

    /// `L` on a selected dashboard row opens that stream's packet loss map;
    /// Esc from the loss map returns to the stream's detail view.
    #[test]
    fn dashboard_l_opens_loss_map_of_selected_stream() {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use crate::rtp::stream_store::StreamStore;

        let skey = StreamKey {
            ssrc: 0x5151,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 1,
            timestamp: 0,
            ssrc: 0x5151,
            payload_offset: 12,
        };
        let mut store = StreamStore::new(16);
        store.insert_for_test(RtpStream::new(skey.clone(), &hdr, chrono::Utc::now()));

        let mut app = App::new_test();
        app.current_view = View::QualityDashboard;
        app.dashboard_snapshot = Some(crate::tui::dashboard::DashboardSnapshot::from_streams(
            &store, None,
        ));
        app.dashboard_selected = 0;

        handle_dashboard_key(&mut app, key(KeyCode::Char('L')));
        assert_eq!(app.current_view, View::StreamLossMap(skey.clone()));

        crate::tui::controllers::loss_map::handle_loss_map_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamDetail(skey));
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

/// Tests for row navigation and its clamp, and for what Enter, `L`, and a
/// close do, against a snapshot with a known number of rows.
#[cfg(test)]
mod navigation_tests {
    use super::*;
    use crate::tui::controllers::test_support::*;
    use crate::tui::dashboard::{DashboardSnapshot, StreamHealth};

    /// A stream key distinguished by its SSRC.
    fn skey(ssrc: u32) -> crate::rtp::stream::StreamKey {
        crate::rtp::stream::StreamKey {
            ssrc,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        }
    }

    /// The dashboard view over `n` rows, row `i` carrying SSRC `i`.
    fn app_with_rows(n: u32) -> App {
        let row = |ssrc| StreamHealth {
            key: skey(ssrc),
            call_id: None,
            codec: None,
            mos: 4.0,
            jitter_ms: 0.0,
            loss_pct: 0.0,
            packets: 1,
            active: true,
            trend: Vec::new(),
        };
        let mut app = App::new_test();
        app.current_view = View::QualityDashboard;
        app.dashboard_snapshot = Some(DashboardSnapshot {
            rows: (0..n).map(row).collect(),
            ..Default::default()
        });
        app
    }

    /// PgUp/PgDn and `L` are bound (the other bindings are pinned above).
    #[test]
    fn paging_and_the_loss_map_key_are_bound() {
        use DashboardAction::*;
        let km = Keymap::default();
        assert_eq!(dashboard_action(&km, key(KeyCode::PageUp)), Some(PageUp));
        assert_eq!(
            dashboard_action(&km, key(KeyCode::PageDown)),
            Some(PageDown)
        );
        assert_eq!(
            dashboard_action(&km, key(KeyCode::Char('L'))),
            Some(OpenLossMap)
        );
    }

    /// Down/`j` and Up/`k` move one row and PgDn/PgUp ten, clamped to the
    /// last row and saturating at the first; Home and End jump to the ends.
    #[test]
    fn row_selection_moves_by_one_and_by_ten_and_clamps_to_the_rows() {
        let mut app = app_with_rows(12);
        let steps: [(KeyCode, usize); 11] = [
            (KeyCode::Down, 1),
            (KeyCode::Char('j'), 2),
            (KeyCode::PageDown, 11),
            (KeyCode::Down, 11),
            (KeyCode::PageUp, 1),
            (KeyCode::Char('k'), 0),
            (KeyCode::Up, 0),
            (KeyCode::PageUp, 0),
            (KeyCode::End, 11),
            (KeyCode::Home, 0),
            (KeyCode::PageDown, 10),
        ];
        for (code, want) in steps {
            handle_dashboard_key(&mut app, key(code));
            assert_eq!(app.dashboard_selected, want, "after {code:?}");
            assert_eq!(app.current_view, View::QualityDashboard);
        }
    }

    /// With no snapshot yet, navigation pins the selection to row 0 and
    /// neither Enter nor `L` opens anything.
    #[test]
    fn with_no_rows_navigation_stays_on_row_zero_and_opens_nothing() {
        let mut app = App::new_test();
        app.current_view = View::QualityDashboard;
        for code in [KeyCode::Down, KeyCode::PageDown, KeyCode::End] {
            handle_dashboard_key(&mut app, key(code));
            assert_eq!(app.dashboard_selected, 0, "after {code:?}");
        }
        handle_dashboard_key(&mut app, key(KeyCode::Enter));
        handle_dashboard_key(&mut app, key(KeyCode::Char('L')));
        assert_eq!(app.current_view, View::QualityDashboard);
        assert_eq!(app.stream_detail_return_view, None);
    }

    /// Enter opens the SELECTED row's stream detail at the top, recording the
    /// dashboard as the view its Esc returns to.
    #[test]
    fn enter_opens_the_selected_rows_stream_detail_and_remembers_the_dashboard() {
        let mut app = app_with_rows(3);
        app.dashboard_selected = 2;
        app.stream_detail_scroll = 9;
        handle_dashboard_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.current_view, View::StreamDetail(skey(2)));
        assert_eq!(app.stream_detail_scroll, 0, "the detail opens at the top");
        assert_eq!(
            app.stream_detail_return_view,
            Some(View::QualityDashboard),
            "Esc from the detail comes back here"
        );
    }

    /// `L` resets the detail scroll it seeds, like Enter does, so the detail
    /// the loss map returns to starts at the top.
    #[test]
    fn the_loss_map_seeds_a_detail_that_starts_at_the_top() {
        let mut app = app_with_rows(2);
        app.dashboard_selected = 1;
        app.stream_detail_scroll = 4;
        handle_dashboard_key(&mut app, key(KeyCode::Char('L')));
        assert_eq!(app.current_view, View::StreamLossMap(skey(1)));
        assert_eq!(app.stream_detail_scroll, 0);
        assert_eq!(app.stream_detail_return_view, Some(View::QualityDashboard));
    }

    /// A key the dashboard does not bind changes nothing; the quit key closes
    /// and, with no recorded opener, falls back to the call list.
    #[test]
    fn unbound_keys_are_ignored_and_close_without_an_opener_goes_to_the_call_list() {
        let mut app = app_with_rows(2);
        app.dashboard_selected = 1;
        handle_dashboard_key(&mut app, key(KeyCode::Char('z')));
        assert_eq!(app.current_view, View::QualityDashboard);
        assert_eq!(app.dashboard_selected, 1);

        assert_eq!(app.dashboard_return_view, None);
        handle_dashboard_key(&mut app, key(KeyCode::Char('q')));
        assert_eq!(app.current_view, View::CallList);
    }
}
