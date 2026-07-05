//! The save dialog popup: opening and key handling.

use crate::tui::*;

/// Open the save popup, pre-populating path and counts.
///
/// From a stream view, defaults to WAV export; otherwise defaults to PCAP.
pub(in crate::tui) fn open_save_popup(app: &mut App) {
    app.save.format = match app.current_view {
        View::StreamList | View::StreamDetail(_) => SaveFormat::Wav,
        _ => SaveFormat::default(),
    };

    let now = chrono::Local::now();
    let ext = app.save.format.extension();
    app.save.path = format!("/tmp/sipnab_{}.{ext}", now.format("%Y%m%d_%H%M%S"));
    app.save.cursor = app.save.path.len();

    // Cache counts for display
    let store = app.dialog_store.read();
    app.save.dialog_count = store.len();
    app.save.selected_count = app.call_list.selected_rows_count();
    app.save.message_count = store.iter().map(|d| d.messages.len()).sum();
    drop(store);

    app.active_popup = Some(Popup::SaveDialog);
}

/// Handle keys in the save dialog popup.
pub(in crate::tui) fn handle_save_popup_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Enter => {
            let path = app.save.path.clone();
            let msg = match app.save.format {
                SaveFormat::Pcap => save_to_pcap_path(app, &path, false),
                SaveFormat::PcapNg => save_to_pcap_path(app, &path, true),
                SaveFormat::Txt => save_to_txt_path(app, &path),
                SaveFormat::Json => save_to_json_path(app, &path),
                SaveFormat::Ndjson => save_to_ndjson_path(app, &path),
                SaveFormat::Csv => save_to_csv_path(app, &path),
                SaveFormat::Html => save_to_mermaid_path(app, &path),
                SaveFormat::Markdown => save_to_markdown_path(app, &path),
                SaveFormat::Wav => save_to_wav_path(app, &path),
                SaveFormat::SippXml => save_to_sipp_path(app, &path),
                SaveFormat::RtpJson => save_to_rtp_json_path(app, &path),
            };
            app.status_error = Some(msg);
            app.active_popup = None;
        }
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Down | KeyCode::Up => {
            // Cycle save format and update file extension
            let old_ext = app.save.format.extension();
            app.save.format = if key.code == KeyCode::BackTab || key.code == KeyCode::Up {
                app.save.format.prev()
            } else {
                app.save.format.next()
            };
            let new_ext = app.save.format.extension();
            // Update the file extension in the path
            if let Some(dot_pos) = app.save.path.rfind('.') {
                let after_dot = &app.save.path[dot_pos + 1..];
                if after_dot == old_ext {
                    app.save.path.truncate(dot_pos + 1);
                    app.save.path.push_str(new_ext);
                    app.save.cursor = app.save.path.len();
                }
            }
        }
        KeyCode::Backspace => {
            if app.save.cursor > 0 {
                // Find the previous char boundary
                let prev = app.save.path[..app.save.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.save.path.remove(prev);
                app.save.cursor = prev;
            }
        }
        KeyCode::Left => {
            if app.save.cursor > 0 {
                app.save.cursor = app.save.path[..app.save.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.save.cursor < app.save.path.len() {
                app.save.cursor = app.save.path[app.save.cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.save.cursor + i)
                    .unwrap_or(app.save.path.len());
            }
        }
        KeyCode::Home => {
            app.save.cursor = 0;
        }
        KeyCode::End => {
            app.save.cursor = app.save.path.len();
        }
        KeyCode::Char(c) => {
            app.save.path.insert(app.save.cursor, c);
            app.save.cursor += c.len_utf8();
        }
        _ => {}
    }
}
