//! Key handling for the RTP stream list and stream detail views.

use crate::tui::*;

/// Everything the stream list view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamListAction {
    Quit,
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    MoveTop,
    MoveBottom,
    SwitchToCallList,
    Search,
    Help,
    OpenSaveDialog,
    OpenFilterDialog,
    OpenDetail,
    NameEndpoints,
    BackToCallList,
}

/// Pure key→action mapping for the stream list (keymap-aware); arm order
/// mirrors the old handler so rebind precedence is unchanged.
pub fn stream_list_action(km: &Keymap, key: KeyEvent) -> Option<StreamListAction> {
    use StreamListAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        KeyCode::Up | KeyCode::Char('k') => MoveUp,
        KeyCode::Down | KeyCode::Char('j') => MoveDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => MoveTop,
        KeyCode::End => MoveBottom,
        KeyCode::Tab => SwitchToCallList,
        k if k == km.search => Search,
        k if k == km.help => Help,
        k if k == km.save => OpenSaveDialog,
        k if k == km.filter => OpenFilterDialog,
        KeyCode::Enter => OpenDetail,
        KeyCode::Char('N') => NameEndpoints,
        KeyCode::Esc => BackToCallList,
        _ => return None,
    })
}

/// Handle keys in the stream list view: map, then execute.
pub(in crate::tui) fn handle_stream_list_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = stream_list_action(&app.keymap, key) {
        execute_stream_list_action(app, action);
    }
}

/// Apply one [`StreamListAction`] to the application state.
fn execute_stream_list_action(app: &mut App, action: StreamListAction) {
    // Navigate over exactly the rows the table displays (search + filter).
    let stream_count = {
        let ss = app.stream_store.read();
        let ds = app.dialog_store.try_read();
        crate::tui::stream_list::displayed_streams(
            ss.iter(),
            ds.as_deref(),
            app.active_filter.as_ref(),
            &app.search_query,
        )
        .len()
    };

    match action {
        StreamListAction::Quit => app.should_quit = true,
        StreamListAction::MoveUp => app.stream_list.move_up(),
        StreamListAction::MoveDown => app.stream_list.move_down(stream_count),
        StreamListAction::PageUp => app.stream_list.page_up(),
        StreamListAction::PageDown => app.stream_list.page_down(stream_count),
        StreamListAction::MoveTop => app.stream_list.move_to_top(),
        StreamListAction::MoveBottom => app.stream_list.move_to_bottom(stream_count),
        StreamListAction::SwitchToCallList => {
            app.current_view = View::CallList;
        }
        StreamListAction::Search => {
            // Keep the existing query so it can be refined.
            app.search_active = true;
        }
        StreamListAction::Help => app.current_view = View::Help,
        StreamListAction::OpenSaveDialog => open_save_popup(app),
        StreamListAction::OpenFilterDialog => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.filter_dialog.error = None;
            app.active_popup = Some(Popup::FilterDialog);
        }
        StreamListAction::OpenDetail => {
            if let Some(key) = get_selected_stream_key(app) {
                app.stream_detail_scroll = 0;
                app.stream_detail_return_view = Some(View::StreamList);
                app.current_view = View::StreamDetail(key);
            }
        }
        StreamListAction::NameEndpoints => {
            // Name the selected stream's endpoints (source focused; Tab -> dest).
            if let Some(key) = get_selected_stream_key(app) {
                open_name_dialog_for(app, vec![key.src.ip(), key.dst.ip()], 0);
            }
        }
        StreamListAction::BackToCallList => app.current_view = View::CallList,
    }
}

/// Everything the stream detail view can do for a single key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDetailAction {
    Quit,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    ScrollBottom,
    Help,
    OpenSaveDialog,
    Back,
    #[cfg(feature = "audio")]
    TogglePlayback,
}

/// Pure key→action mapping for the stream detail view (keymap-aware).
pub fn stream_detail_action(km: &Keymap, key: KeyEvent) -> Option<StreamDetailAction> {
    use StreamDetailAction::*;
    Some(match key.code {
        k if k == km.quit => Quit,
        KeyCode::Up | KeyCode::Char('k') => ScrollUp,
        KeyCode::Down | KeyCode::Char('j') => ScrollDown,
        KeyCode::PageUp => PageUp,
        KeyCode::PageDown => PageDown,
        KeyCode::Home => ScrollTop,
        KeyCode::End => ScrollBottom,
        k if k == km.help => Help,
        k if k == km.save => OpenSaveDialog,
        KeyCode::Esc => Back,
        #[cfg(feature = "audio")]
        KeyCode::Char('P') => TogglePlayback,
        _ => return None,
    })
}

/// Handle keys in the RTP stream detail view: map, then execute.
pub(in crate::tui) fn handle_stream_detail_key(app: &mut App, key: KeyEvent) {
    if let Some(action) = stream_detail_action(&app.keymap, key) {
        execute_stream_detail_action(app, action);
    }
}

/// Apply one [`StreamDetailAction`] to the application state.
fn execute_stream_detail_action(app: &mut App, action: StreamDetailAction) {
    match action {
        StreamDetailAction::Quit => app.should_quit = true,
        StreamDetailAction::ScrollUp => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(1);
        }
        StreamDetailAction::ScrollDown => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_add(1);
        }
        StreamDetailAction::PageUp => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(20);
        }
        StreamDetailAction::PageDown => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_add(20);
        }
        StreamDetailAction::ScrollTop => app.stream_detail_scroll = 0,
        // Clamped to the content height by the render pass.
        StreamDetailAction::ScrollBottom => app.stream_detail_scroll = usize::MAX,
        StreamDetailAction::Help => app.current_view = View::Help,
        StreamDetailAction::OpenSaveDialog => open_save_popup(app),
        StreamDetailAction::Back => {
            app.current_view = match app.stream_detail_return_view.take() {
                Some(v) => v,
                None => View::StreamList,
            };
        }
        #[cfg(feature = "audio")]
        StreamDetailAction::TogglePlayback => handle_stream_detail_play(app),
    }
}

/// Handle Shift+P audio playback toggle in stream detail view.
#[cfg(feature = "audio")]
pub(in crate::tui) fn handle_stream_detail_play(app: &mut App) {
    // Don't re-attempt init if it already failed — retrying would
    // re-trigger libasound's stderr spam each keypress.
    if let Some(msg) = app.audio_init_error.as_deref() {
        app.status_error = Some(msg.to_string());
        return;
    }

    // Toggle off immediately when already playing (fast plugin call).
    if let Some(player) = &app.audio_player
        && player.is_playing()
    {
        player.stop();
        app.status_error = Some("Playback stopped".to_string());
        return;
    }

    // Defer init + decode + play one tick (App::run_pending_audio) so the
    // "Decoding…" status paints first — decoding/resampling a long stream
    // on the keypress stalled the UI with no feedback.
    app.pending_audio_play = true;
    app.status_error = Some("Decoding audio\u{2026}".to_string());
}

/// Get the StreamKey for the currently selected row in the stream list.
pub(in crate::tui) fn get_selected_stream_key(app: &App) -> Option<crate::rtp::stream::StreamKey> {
    let store = app.stream_store.read();
    let ds = app.dialog_store.try_read();
    let streams = crate::tui::stream_list::displayed_streams(
        store.iter(),
        ds.as_deref(),
        app.active_filter.as_ref(),
        &app.search_query,
    );
    let idx = app.stream_list.selected();
    streams.get(idx).map(|s| s.key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::controllers::test_support::*;

    /// The mapping is pure and keymap-aware: a rebound quit key maps and
    /// the old key unbinds, without touching any App state.
    #[test]
    fn stream_list_action_honors_remapped_quit_key() {
        let km = Keymap {
            quit: KeyCode::Char('x'),
            ..Default::default()
        };
        assert_eq!(
            stream_list_action(&km, key(KeyCode::Char('x'))),
            Some(StreamListAction::Quit)
        );
        assert_eq!(stream_list_action(&km, key(KeyCode::Char('q'))), None);
        // Esc leaves to the call list regardless of the keymap.
        assert_eq!(
            stream_list_action(&km, key(KeyCode::Esc)),
            Some(StreamListAction::BackToCallList)
        );
    }

    #[test]
    fn stream_detail_action_honors_remapped_help_key() {
        let km = Keymap {
            help: KeyCode::Char('?'),
            ..Default::default()
        };
        assert_eq!(
            stream_detail_action(&km, key(KeyCode::Char('?'))),
            Some(StreamDetailAction::Help)
        );
        assert_eq!(
            stream_detail_action(&km, key(KeyCode::Up)),
            Some(StreamDetailAction::ScrollUp)
        );
        assert_eq!(stream_detail_action(&km, key(KeyCode::Char('z'))), None);
    }

    #[test]
    fn stream_list_tab_back_to_call_list() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Tab));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn stream_list_esc_to_call_list() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::CallList);
    }

    #[test]
    fn stream_list_quit_help_search_filter_save() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Char('/')));
        assert!(app.search_active);

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(7)));
        assert_eq!(app.active_popup, Some(Popup::FilterDialog));

        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }

    #[test]
    fn stream_list_nav_noop_when_empty() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        handle_stream_list_key(&mut app, key(KeyCode::Down));
        handle_stream_list_key(&mut app, key(KeyCode::Up));
        handle_stream_list_key(&mut app, key(KeyCode::Home));
        handle_stream_list_key(&mut app, key(KeyCode::End));
        // Enter with no streams: stays in stream list
        handle_stream_list_key(&mut app, key(KeyCode::Enter));
        assert_eq!(app.current_view, View::StreamList);
    }

    // ── handle_stream_detail_key ─────────────────────────────────────

    fn app_in_stream_detail() -> App {
        let mut app = App::new_test();
        let k = crate::rtp::stream::StreamKey {
            ssrc: 1,
            src: std::net::SocketAddr::new(addr_a(), 20000),
            dst: std::net::SocketAddr::new(addr_b(), 30000),
        };
        app.stream_detail_return_view = Some(View::StreamList);
        app.current_view = View::StreamDetail(k);
        app
    }

    #[test]
    fn stream_detail_scroll() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Down));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::Char('j')));
        assert_eq!(app.stream_detail_scroll, 2);
        handle_stream_detail_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::PageDown));
        assert_eq!(app.stream_detail_scroll, 21);
        handle_stream_detail_key(&mut app, key(KeyCode::PageUp));
        assert_eq!(app.stream_detail_scroll, 1);
        handle_stream_detail_key(&mut app, key(KeyCode::Home));
        assert_eq!(app.stream_detail_scroll, 0);
    }

    #[test]
    fn stream_detail_up_saturates() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Up));
        assert_eq!(app.stream_detail_scroll, 0);
    }

    #[test]
    fn stream_detail_esc_returns() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn stream_detail_esc_default_stream_list() {
        let mut app = app_in_stream_detail();
        app.stream_detail_return_view = None;
        handle_stream_detail_key(&mut app, key(KeyCode::Esc));
        assert_eq!(app.current_view, View::StreamList);
    }

    #[test]
    fn stream_detail_quit_help_save() {
        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::Char('q')));
        assert!(app.should_quit);

        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::F(1)));
        assert_eq!(app.current_view, View::Help);

        let mut app = app_in_stream_detail();
        handle_stream_detail_key(&mut app, key(KeyCode::F(2)));
        assert_eq!(app.active_popup, Some(Popup::SaveDialog));
    }
}

#[cfg(all(test, feature = "audio"))]
mod deferred_audio_tests {
    use super::*;

    /// Shift+P must not decode on the keypress: a long Opus stream stalls
    /// the UI noticeably. The toggle defers one event-loop tick so the
    /// "Decoding…" status paints first (same pattern as the save dialog).
    #[test]
    fn toggle_playback_defers_decode_one_tick() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;

        handle_stream_detail_play(&mut app);

        assert!(
            app.pending_audio_play,
            "decode+play must be deferred, not run on the keypress"
        );
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("Decoding"),
            "got: {:?}",
            app.status_error
        );

        app.run_pending_audio();
        assert!(!app.pending_audio_play, "deferred work consumed");
        assert!(
            !app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("Decoding"),
            "status resolved to a result (playing or an init error): {:?}",
            app.status_error
        );
    }

    /// A cached init failure still short-circuits without deferring.
    #[test]
    fn cached_init_failure_short_circuits() {
        let mut app = App::new_test();
        app.audio_init_error = Some("Audio init failed: nope".to_string());
        handle_stream_detail_play(&mut app);
        assert!(!app.pending_audio_play);
        assert_eq!(app.status_error.as_deref(), Some("Audio init failed: nope"));
    }
}
