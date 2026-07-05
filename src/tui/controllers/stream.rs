//! Key handling for the RTP stream list and stream detail views.

use crate::tui::*;

/// Handle keys in the stream list view.
pub(in crate::tui) fn handle_stream_list_key(app: &mut App, key: KeyEvent) {
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

    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.stream_list.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.stream_list.move_down(stream_count),
        KeyCode::PageUp => app.stream_list.page_up(),
        KeyCode::PageDown => app.stream_list.page_down(stream_count),
        KeyCode::Home => app.stream_list.move_to_top(),
        KeyCode::End => app.stream_list.move_to_bottom(stream_count),
        KeyCode::Tab => {
            app.current_view = View::CallList;
        }
        k if k == app.keymap.search => {
            // Keep the existing query so it can be refined.
            app.search_active = true;
        }
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        k if k == app.keymap.filter => {
            app.filter_dialog.focused_field = 0;
            app.filter_dialog.sync_cursor();
            app.active_popup = Some(Popup::FilterDialog);
        }
        KeyCode::Enter => {
            if let Some(key) = get_selected_stream_key(app) {
                app.stream_detail_scroll = 0;
                app.stream_detail_return_view = Some(View::StreamList);
                app.current_view = View::StreamDetail(key);
            }
        }
        // N — Name the selected stream's endpoints (source focused; Tab → dest).
        KeyCode::Char('N') => {
            if let Some(key) = get_selected_stream_key(app) {
                open_name_dialog_for(app, vec![key.src.ip(), key.dst.ip()], 0);
            }
        }
        KeyCode::Esc => app.current_view = View::CallList,
        _ => {}
    }
}

/// Handle keys in the RTP stream detail view.
pub(in crate::tui) fn handle_stream_detail_key(app: &mut App, key: KeyEvent) {
    match key.code {
        k if k == app.keymap.quit => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_add(1);
        }
        KeyCode::PageUp => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_sub(20);
        }
        KeyCode::PageDown => {
            app.stream_detail_scroll = app.stream_detail_scroll.saturating_add(20);
        }
        KeyCode::Home => app.stream_detail_scroll = 0,
        // Clamped to the content height by the render pass.
        KeyCode::End => app.stream_detail_scroll = usize::MAX,
        k if k == app.keymap.help => app.current_view = View::Help,
        k if k == app.keymap.save => {
            open_save_popup(app);
        }
        KeyCode::Esc => {
            app.current_view = match app.stream_detail_return_view.take() {
                Some(v) => v,
                None => View::StreamList,
            };
        }
        #[cfg(feature = "audio")]
        KeyCode::Char('P') => {
            handle_stream_detail_play(app);
        }
        _ => {}
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

    // Initialize player lazily on first use
    if app.audio_player.is_none() {
        match crate::rtp::playback::AudioPlayer::new() {
            Ok(player) => app.audio_player = Some(player),
            Err(e) => {
                let msg = format!("Audio init failed: {e}");
                app.status_error = Some(msg.clone());
                app.audio_init_error = Some(msg);
                return;
            }
        }
    }

    if let Some(player) = &app.audio_player {
        if player.is_playing() {
            player.stop();
            app.status_error = Some("Playback stopped".to_string());
        } else if let View::StreamDetail(ref key) = app.current_view {
            let store = app.stream_store.read();
            if let Some(stream) = store.get(key) {
                match player.play_stream(stream) {
                    Ok(msg) => app.status_error = Some(msg),
                    Err(e) => app.status_error = Some(format!("Playback error: {e}")),
                }
            }
        }
    }
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
