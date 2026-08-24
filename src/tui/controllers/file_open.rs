// SPDX-License-Identifier: MIT OR Apache-2.0

//! The file-open dialog: directory browsing, manual path entry and
//! pcap loading.

use crate::tui::*;

/// Open the file-open dialog, seeding it with a directory listing rooted at
/// the last-browsed directory (or the current working directory on first use).
///
/// # Side effects
/// Resets the dialog's filter, manual-path buffer, and cursor, rebuilds
/// the directory listing from the filesystem via `refresh_file_entries`,
/// and sets `app.active_popup` to the file-open dialog.
pub(in crate::tui) fn open_file_dialog(app: &mut App) {
    if !app.file_open.dir.is_dir() {
        app.file_open.dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    }
    app.file_open.filter.clear();
    app.file_open.manual_mode = false;
    app.file_open.path.clear();
    app.file_open.cursor = 0;
    refresh_file_entries(app);
    app.active_popup = Some(Popup::FileOpenDialog);
}

/// Extensions recognized as pcap/pcapng files by the file browser.
pub(in crate::tui) const PCAP_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

/// True if `name` is a capture file the browser should list: a bare
/// pcap/pcapng/cap file, or a gzip-compressed one (`*.pcap.gz`, `*.cap.gz`…).
///
/// `crate::capture::file::open_offline` transparently decompresses gzip
/// captures (it sniffs the `1f 8b` magic), so hiding `*.gz` here would let the
/// browser refuse files the loader can actually open. Case-insensitive.
pub(in crate::tui) fn is_browsable_capture(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Peel an optional `.gz` so `foo.pcap.gz` is judged by its `.pcap` stem.
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    std::path::Path::new(stem)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| PCAP_EXTENSIONS.iter().any(|p| p == &e))
        .unwrap_or(false)
}

/// Rebuild `app.file_open.entries` from the current `app.file_open.dir`,
/// applying the name filter and sorting dirs-first / alphabetical.
///
/// # Side effects
/// Reads the directory from the filesystem. On failure sets
/// `app.file_open.error` (with a privilege-drop hint for permission
/// errors) and leaves the previous entries; on success clears the error,
/// replaces the entries (`..` first, hidden files skipped unless the
/// filter starts with a dot, non-capture files skipped), and clamps
/// `app.file_open.selected` to the new length.
pub(in crate::tui) fn refresh_file_entries(app: &mut App) {
    let mut entries: Vec<FileEntry> = Vec::new();

    if let Some(parent) = app.file_open.dir.parent() {
        entries.push(FileEntry {
            name: "..".to_string(),
            path: parent.to_path_buf(),
            is_dir: true,
        });
    }

    match std::fs::read_dir(&app.file_open.dir) {
        Err(e) => {
            // Surface the failure instead of showing a blank list. The most
            // common cause is running under sudo: the capture process drops
            // privileges to an unprivileged user that can't read the (0700)
            // home directory.
            let hint = if e.kind() == std::io::ErrorKind::PermissionDenied {
                " — the capture process dropped privileges to an unprivileged \
                 user; run sipnab without sudo to browse your own files"
            } else {
                ""
            };
            app.file_open.error = Some(format!(
                "Cannot read {}: {}{}",
                app.file_open.dir.display(),
                e,
                hint
            ));
        }
        Ok(read_dir) => {
            app.file_open.error = None;
            let filter_lc = app.file_open.filter.to_lowercase();
            for entry in read_dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && !filter_lc.starts_with('.') {
                    continue;
                }
                let is_dir = match entry.file_type() {
                    // `file_type()` does not follow symlinks, so a symlinked
                    // directory reports `is_dir() == false`. Resolve via
                    // `metadata()` (which does follow) so directory symlinks
                    // still appear in the browser. Broken or unreadable links
                    // fall through as non-directories.
                    Ok(ft) if ft.is_symlink() => std::fs::metadata(entry.path())
                        .map(|m| m.is_dir())
                        .unwrap_or(false),
                    Ok(ft) => ft.is_dir(),
                    Err(_) => false,
                };

                if !is_dir && !is_browsable_capture(&name) {
                    continue;
                }

                if !filter_lc.is_empty() && !name.to_lowercase().contains(&filter_lc) {
                    continue;
                }

                entries.push(FileEntry {
                    name,
                    path: entry.path(),
                    is_dir,
                });
            }
        }
    }

    crate::sort::sort_by_dyn(
        &mut entries,
        &mut |a, b| match (a.name.as_str(), b.name.as_str()) {
            ("..", _) => std::cmp::Ordering::Less,
            (_, "..") => std::cmp::Ordering::Greater,
            _ => match (a.is_dir, b.is_dir) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            },
        },
    );

    app.file_open.entries = entries;
    if app.file_open.selected >= app.file_open.entries.len() {
        app.file_open.selected = app.file_open.entries.len().saturating_sub(1);
    }
}

/// Handle keys in the file-open dialog popup (browser mode).
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly (this popup has no keymap
///   bindings). Routed to `handle_file_open_manual_key` while manual-path
///   mode is active.
///
/// # Side effects
/// Esc closes the popup. Tab switches to manual-path mode (seeding the
/// path with the browsed directory). Navigation keys move
/// `app.file_open.selected`. Enter descends into a directory (refreshing
/// the listing) or starts loading the selected capture via
/// `begin_pcap_load` and closes the popup. Typed characters extend the
/// name filter; Backspace trims the filter or ascends to the parent
/// directory — both refresh the listing from the filesystem.
pub(in crate::tui) fn handle_file_open_popup_key(app: &mut App, key: KeyEvent) {
    if app.file_open.manual_mode {
        handle_file_open_manual_key(app, key);
        return;
    }

    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Tab => {
            app.file_open.manual_mode = true;
            if app.file_open.path.is_empty() {
                app.file_open.path = app.file_open.dir.to_string_lossy().into_owned();
                if !app.file_open.path.ends_with(std::path::MAIN_SEPARATOR) {
                    app.file_open.path.push(std::path::MAIN_SEPARATOR);
                }
            }
            app.file_open.cursor = app.file_open.path.len();
        }
        KeyCode::Up => {
            if app.file_open.selected > 0 {
                app.file_open.selected -= 1;
            }
        }
        KeyCode::Down => {
            if app.file_open.selected + 1 < app.file_open.entries.len() {
                app.file_open.selected += 1;
            }
        }
        KeyCode::PageUp => {
            app.file_open.selected = app.file_open.selected.saturating_sub(10);
        }
        KeyCode::PageDown => {
            app.file_open.selected =
                (app.file_open.selected + 10).min(app.file_open.entries.len().saturating_sub(1));
        }
        KeyCode::Home => app.file_open.selected = 0,
        KeyCode::End => {
            app.file_open.selected = app.file_open.entries.len().saturating_sub(1);
        }
        KeyCode::Enter => {
            let entry = match app.file_open.entries.get(app.file_open.selected).cloned() {
                Some(e) => e,
                None => return,
            };
            if entry.is_dir {
                app.file_open.dir = entry.path;
                app.file_open.filter.clear();
                app.file_open.selected = 0;
                refresh_file_entries(app);
            } else {
                let path = entry.path.to_string_lossy().into_owned();
                begin_pcap_load(app, &path);
                app.active_popup = None;
            }
        }
        KeyCode::Backspace => {
            if !app.file_open.filter.is_empty() {
                app.file_open.filter.pop();
                app.file_open.selected = 0;
                refresh_file_entries(app);
            } else if let Some(parent) = app.file_open.dir.parent() {
                app.file_open.dir = parent.to_path_buf();
                app.file_open.selected = 0;
                refresh_file_entries(app);
            }
        }
        KeyCode::Char(c) => {
            app.file_open.filter.push(c);
            app.file_open.selected = 0;
            refresh_file_entries(app);
        }
        _ => {}
    }
}

/// Manual-path edit mode within the file-open dialog.
/// Tab toggles back to browser mode; Enter loads the typed path.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `key` - the key event, matched directly.
///
/// # Side effects
/// Esc closes the popup. Enter expands a leading `~`, starts the load
/// via `begin_pcap_load` (or reports an empty path on the status line),
/// and closes the popup. The remaining keys edit `app.file_open.path`
/// and move `app.file_open.cursor` on char boundaries.
pub(in crate::tui) fn handle_file_open_manual_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.active_popup = None;
        }
        KeyCode::Tab => {
            app.file_open.manual_mode = false;
        }
        KeyCode::Enter => {
            let path = expand_tilde(&app.file_open.path);
            if path.is_empty() {
                app.status_error = Some("No file path specified".to_string());
                app.active_popup = None;
                return;
            }
            begin_pcap_load(app, &path);
            app.active_popup = None;
        }
        KeyCode::Backspace => {
            if app.file_open.cursor > 0 {
                let prev = app.file_open.path[..app.file_open.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                app.file_open.path.remove(prev);
                app.file_open.cursor = prev;
            }
        }
        KeyCode::Delete => {
            // Remove the whole char at the cursor (the cursor is kept on a
            // char boundary), leaving the cursor put — the forward-delete
            // counterpart to Backspace, matching the filter dialog.
            if app.file_open.cursor < app.file_open.path.len() {
                app.file_open.path.remove(app.file_open.cursor);
            }
        }
        KeyCode::Left => {
            if app.file_open.cursor > 0 {
                app.file_open.cursor = app.file_open.path[..app.file_open.cursor]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
            }
        }
        KeyCode::Right => {
            if app.file_open.cursor < app.file_open.path.len() {
                app.file_open.cursor = app.file_open.path[app.file_open.cursor..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| app.file_open.cursor + i)
                    .unwrap_or(app.file_open.path.len());
            }
        }
        KeyCode::Home => {
            app.file_open.cursor = 0;
        }
        KeyCode::End => {
            app.file_open.cursor = app.file_open.path.len();
        }
        KeyCode::Char(c) => {
            app.file_open.path.insert(app.file_open.cursor, c);
            app.file_open.cursor += c.len_utf8();
        }
        _ => {}
    }
}

/// Expand a leading `~` to the user's home directory (`$HOME`); paths
/// without a leading `~`, or with no `HOME` set, are returned unchanged.
pub(in crate::tui) fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~')
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}{rest}");
    }
    path.to_string()
}

/// Reset stores and per-capture TUI state before (re)loading a pcap,
/// preserving column-visibility preferences.
///
/// # Side effects
/// Clears the dialog and stream stores (write locks), rebuilds the call
/// and stream list states, drops the active filter, resets the call-flow
/// selection/scroll/fold/mark state, and returns to the call list view.
fn reset_for_load(app: &mut App) {
    {
        let mut ds = app.dialog_store.write();
        ds.clear();
    }
    {
        let mut ss = app.stream_store.write();
        ss.clear();
    }
    let saved_columns = app.call_list.visible_columns;
    app.call_list = CallListState::new();
    app.call_list.visible_columns = saved_columns;
    app.stream_list = StreamListState::new();
    app.active_filter = None;
    app.active_filter_text.clear();
    app.flow.selected = 0;
    app.flow.scroll = 0;
    app.flow.cached_msg_count = 0;
    app.flow.cached_rtp_bar_indices.clear();
    app.flow.fold_expanded.clear();
    app.flow.mark_index = None;
    app.current_view = View::CallList;
}

/// Parse `path` into the shared stores and build the load outcome. Runs on
/// a worker thread (the stores are the same `Arc<RwLock>`s live capture
/// writes through, so the UI renders the data progressively); the unit
/// tests call it inline.
///
/// Routes every packet through the shared `crate::pipeline::classify_packet`
/// core — the same router as live capture — so RTP-only pcaps populate the
/// stream store for playback and WAV export, and WebSocket-wrapped SIP is
/// unwrapped.
///
/// # Arguments
/// * `path` - the capture file to read (gzip handled transparently).
/// * `dialog_store` / `stream_store` - shared stores the parsed SIP/RTP/
///   RTCP data is written into under brief per-packet write locks.
/// * `progress` - live packet counter the UI polls while the load runs.
///
/// # Returns
/// A `PcapLoadOutcome` carrying the status-line message, the SIP message
/// count, the "Offline (file)" capture-mode label, and any embedded
/// pcapng Name Resolution Block names.
fn run_pcap_load(
    path: &std::path::Path,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    progress: &PcapLoadProgress,
) -> PcapLoadOutcome {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&progress.filename)
        .to_string();
    let capture_mode = format!("Offline ({filename})");

    // Transparently handles gzip-compressed captures (libpcap cannot). The
    // guard owns any decompressed temp file and must outlive the read loop
    // below, so keep it bound for the rest of the function.
    let (mut cap, _gz_guard) = match crate::capture::file::open_offline(path) {
        Ok(opened) => opened,
        Err(e) => {
            return PcapLoadOutcome {
                message: format!("Failed to open: {e:#}"),
                sip_count: 0,
                capture_mode,
                file_names: Vec::new(),
            };
        }
    };

    let mut packet_count = 0u64;
    let mut sip_count = 0u64;
    let mut rtp_count = 0u64;
    let mut rtcp_count = 0u64;
    let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
    let link_type = cap.get_datalink().0;

    while let Ok(pkt) = cap.next_packet() {
        packet_count += 1;
        progress
            .packets
            .store(packet_count, std::sync::atomic::Ordering::Relaxed);

        // Route through the shared, hardened converter: an out-of-range or
        // unrepresentable tv_usec (crafted or nanosecond-precision capture)
        // is rejected, counted, and warned rather than overflowing u32 here.
        let ts = crate::capture::file::pcap_ts_to_chrono(pkt.header.ts);

        let capture_pkt = crate::capture::Packet::new(
            ts,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            None,
            link_type,
        );

        // Count the frames this path cannot read, exactly as the batch path
        // does. Opening a capture in the TUI is the same question as running
        // it headless, so "sipnab could not decode any of this" must not be a
        // fact only the headless run gets told.
        let parsed = match crate::capture::parse::parse_packet(&capture_pkt) {
            Ok(p) => p,
            Err(e) => {
                crate::capture::record_undecodable(&e, crate::capture::FrameFacts::UNRECORDED);
                continue;
            }
        };
        if parsed.payload.is_empty() {
            continue;
        }

        // Classify via the shared pipeline core, then apply to the app
        // stores (brief per-store write locks, as in live capture).
        let mut decrypt = crate::pipeline::MediaDecrypt::default();
        match crate::pipeline::classify_packet(
            &parsed,
            &mut rtp_heuristic,
            &crate::pipeline::PipelineOptions::default(),
            &mut decrypt,
        ) {
            crate::pipeline::PacketAction::None => {}
            crate::pipeline::PacketAction::Sip { msg, sdp_links } => {
                dialog_store.write().process_message(msg);
                sip_count += 1;
                if !sdp_links.is_empty() {
                    let mut ss = stream_store.write();
                    // As on the batch and `--cores` routers: opening a file in
                    // the TUI must reach the same endpoint provenance a batch
                    // run over the same file reaches.
                    let provenance = crate::rtp::stream_store::SdpProvenance::observed(
                        parsed.input_origin,
                        parsed.timestamp,
                    );
                    for (ip, port, call_id, media) in &sdp_links {
                        ss.link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
                    }
                }
            }
            crate::pipeline::PacketAction::RelayControl { sdp_links } => {
                if !sdp_links.is_empty() {
                    crate::pipeline::apply_relay_control_links(
                        &mut stream_store.write(),
                        &sdp_links,
                        parsed.input_origin,
                        parsed.timestamp,
                    );
                }
            }
            crate::pipeline::PacketAction::Rtcp(rtcp_packets) => {
                stream_store
                    .write()
                    .process_rtcp(&rtcp_packets, parsed.timestamp);
                rtcp_count += rtcp_packets.len() as u64;
            }
            crate::pipeline::PacketAction::Rtp { hdr, .. } => {
                // No decryption keys on the file-open path, so there is never
                // a substituted plaintext payload.
                stream_store
                    .write()
                    .process_rtp(&parsed, &hdr, parsed.timestamp);
                rtp_count += 1;
            }
        }
    }

    // Read pcapng metadata blocks that the libpcap reader ignores: embedded
    // Name Resolution Block names (applied to the resolver on the UI thread)
    // and any Decryption Secrets Block so the operator is alerted the file
    // carries keys.
    let mut file_names = Vec::new();
    let mut secrets_present = 0;
    if let Ok(meta) = crate::capture::pcapng_meta::read_pcapng_metadata(path) {
        file_names = meta.names;
        secrets_present = meta.tls_secrets.len();
    }

    let stream_count = stream_store.read().len();
    let rtcp_suffix = if rtcp_count > 0 {
        format!(", {rtcp_count} RTCP")
    } else {
        String::new()
    };
    let names_suffix = if !file_names.is_empty() {
        format!(", {} name(s)", file_names.len())
    } else {
        String::new()
    };
    let secrets_suffix = if secrets_present > 0 {
        format!(" \u{26a0} file contains {secrets_present} embedded decryption secret(s)")
    } else {
        String::new()
    };
    PcapLoadOutcome {
        message: format!(
            "Loaded {sip_count} SIP, {rtp_count} RTP{rtcp_suffix}{names_suffix} from {packet_count} packets across {stream_count} stream(s) ({filename}){secrets_suffix}"
        ),
        sip_count,
        capture_mode,
        file_names,
    }
}

/// Apply a finished load's outcome to the app: capture-mode label, embedded
/// names into the resolver, and the RTP-only jump to the stream list.
///
/// # Side effects
/// Sets the capture-mode label and marks data updated. Loads embedded
/// file names into the resolver, flipping `app.name_mode` on when names
/// arrived while it was `Off`. When the capture had no SIP but has RTP
/// streams, switches `app.current_view` to the stream list.
fn apply_load_outcome(app: &mut App, outcome: PcapLoadOutcome) {
    app.set_capture_mode(outcome.capture_mode);
    // The label now reads `Offline (...)` while the BPF slot still shows the
    // filter the LIVE capture was compiled with — which keeps running behind
    // this and keeps writing to the same stores. Unmarked, the two rows read
    // as one statement about one source (#190).
    app.mark_bpf_live_only();
    app.mark_data_updated();

    if !outcome.file_names.is_empty() {
        let names_loaded = app.resolver.load_file_names(outcome.file_names);
        if names_loaded > 0 && app.name_mode == crate::names::NameMode::Off {
            app.name_mode = crate::names::NameMode::Names;
        }
    }

    // If the pcap had no SIP but did have RTP streams, jump straight to the
    // stream list so playback / WAV export are immediately reachable.
    let stream_count = app.stream_store.read().len();
    if outcome.sip_count == 0 && stream_count > 0 {
        app.current_view = View::StreamList;
    }
}

/// Start loading a pcap on a background worker so the event loop keeps
/// running — parsing a large capture on the UI thread froze the TUI for the
/// whole load. Progress and the final result are applied by
/// `poll_pcap_load` each tick.
///
/// # Arguments
/// * `app` - the application state to mutate.
/// * `path_str` - the capture file path.
///
/// # Side effects
/// Refuses (status line only) when a load is already in flight or the
/// file does not exist. Otherwise resets the stores/TUI state via
/// `reset_for_load`, spawns the "pcap-load" worker thread writing into
/// the shared stores, stores the progress handle in `app.pcap_load`, and
/// paints a "Loading…" status. A failed thread spawn is reported on the
/// status line.
pub(in crate::tui) fn begin_pcap_load(app: &mut App, path_str: &str) {
    if app.pcap_load.is_some() {
        app.status_error = Some("A pcap load is already in progress".to_string());
        return;
    }
    let path = std::path::Path::new(path_str);
    if !path.exists() {
        app.status_error = Some(format!("File not found: {path_str}"));
        return;
    }
    // Same reason as `load_pcap_file`: this file is now an input.
    app.protect_input_file(path);

    reset_for_load(app);

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path_str)
        .to_string();
    let progress = Arc::new(PcapLoadProgress::new(&filename));
    let worker_progress = Arc::clone(&progress);
    let dialog_store = Arc::clone(&app.dialog_store);
    let stream_store = Arc::clone(&app.stream_store);
    let path_owned = path.to_path_buf();
    let spawned = std::thread::Builder::new()
        .name("pcap-load".to_string())
        .spawn(move || {
            let outcome =
                run_pcap_load(&path_owned, &dialog_store, &stream_store, &worker_progress);
            *worker_progress.result.lock() = Some(outcome);
            worker_progress
                .done
                .store(true, std::sync::atomic::Ordering::Release);
        });
    match spawned {
        Ok(_) => {
            app.status_error = Some(format!("Loading {filename}…"));
            app.pcap_load = Some(progress);
        }
        Err(e) => {
            app.status_error = Some(format!("Failed to start the load worker: {e}"));
        }
    }
}

/// Event-loop tick hook: refresh the "Loading…" progress line while a
/// background load runs, and apply its outcome once it finishes.
///
/// # Side effects
/// No-op without an in-flight load. While running, updates the status
/// line with the live packet count and keeps the adaptive refresh cadence
/// active. On completion, clears `app.pcap_load`, sets the final status
/// message, applies the outcome via `apply_load_outcome`, and clears the
/// churn floors so every view reflects the new stores immediately.
pub(in crate::tui) fn poll_pcap_load(app: &mut App) {
    let Some(progress) = app.pcap_load.clone() else {
        return;
    };
    if progress.done.load(std::sync::atomic::Ordering::Acquire) {
        app.pcap_load = None;
        if let Some(outcome) = progress.result.lock().take() {
            app.status_error = Some(outcome.message.clone());
            apply_load_outcome(app, outcome);
            // A completed load is a discrete event, not churn: every view
            // must reflect the new stores on the next tick, floor or not.
            app.clear_churn_floors();
        }
    } else {
        let packets = progress.packets.load(std::sync::atomic::Ordering::Relaxed);
        app.status_error = Some(format!("Loading {}… {packets} packets", progress.filename));
        // Keep the adaptive refresh cadence active while data streams in.
        app.mark_data_updated();
    }
}

/// Unit tests for the file browser, tilde expansion, and pcap loading
/// (synchronous and background).
#[cfg(test)]
mod tests {
    use super::*;

    /// Drive a load to completion on the calling thread and return the final
    /// status message.
    ///
    /// A TEST HELPER, not a second loading path: the only production loader is
    /// `begin_pcap_load` + `poll_pcap_load`. It exists because a test wants the
    /// finished message in one call rather than pumping a worker, and it is
    /// built from the same three units the worker runs — so what it exercises
    /// is production code, in production order.
    ///
    /// It lived in the production section behind
    /// `#[cfg_attr(not(test), allow(dead_code))]`, which read as a second
    /// supported way to open a capture. It was never one.
    fn load_pcap_file(app: &mut App, path_str: &str) -> String {
        let path = std::path::Path::new(path_str);
        if !path.exists() {
            return format!("File not found: {path_str}");
        }
        // A capture opened here is an input for the rest of the session,
        // exactly as `-I` was, so the save dialog must refuse to write over it
        // too.
        app.protect_input_file(path);
        reset_for_load(app);
        let progress = PcapLoadProgress::new(path_str);
        let outcome = run_pcap_load(path, &app.dialog_store, &app.stream_store, &progress);
        let message = outcome.message.clone();
        apply_load_outcome(app, outcome);
        message
    }

    /// A capture whose packet record carries an out-of-range microsecond
    /// field (as a crafted or nanosecond-precision file can) must not
    /// overflow the timestamp conversion (which panics in debug builds)
    /// while loading.
    #[test]
    #[serial_test::serial(invalid_timestamps, undecodable_tally)]
    fn load_pcap_with_out_of_range_usec_does_not_panic() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_ts.pcap");
        let mut f = std::fs::File::create(&path).unwrap();
        // Classic pcap global header: LE microsecond magic, v2.4, EN10MB.
        f.write_all(&0xa1b2_c3d4u32.to_le_bytes()).unwrap();
        f.write_all(&2u16.to_le_bytes()).unwrap();
        f.write_all(&4u16.to_le_bytes()).unwrap();
        f.write_all(&0i32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&65535u32.to_le_bytes()).unwrap();
        f.write_all(&1u32.to_le_bytes()).unwrap(); // LINKTYPE_ETHERNET
        // One record whose ts_usec is far outside [0, 1_000_000): the old
        // `(tv_usec as u32) * 1000` overflows u32 here.
        let payload = [0u8; 14];
        f.write_all(&1_000u32.to_le_bytes()).unwrap(); // ts_sec
        f.write_all(&2_000_000_000u32.to_le_bytes()).unwrap(); // ts_usec (corrupt)
        f.write_all(&(payload.len() as u32).to_le_bytes()).unwrap(); // incl_len
        f.write_all(&(payload.len() as u32).to_le_bytes()).unwrap(); // orig_len
        f.write_all(&payload).unwrap();
        drop(f);

        let mut app = App::new_test();
        // Must return an outcome message rather than panicking.
        let _ = load_pcap_file(&mut app, path.to_str().unwrap());
    }

    /// Extension matrix for the browser filter: pcap/pcapng/cap in any
    /// case, optionally gzipped, are browsable; everything else is not.
    #[test]
    fn is_browsable_capture_matrix() {
        // Plain captures, any case.
        assert!(is_browsable_capture("a.pcap"));
        assert!(is_browsable_capture("a.pcapng"));
        assert!(is_browsable_capture("a.cap"));
        assert!(is_browsable_capture("A.PCAP"));
        assert!(is_browsable_capture("UPPER.PcApNg"));
        // Dotted/UUID stems keep working (extension is the final component).
        assert!(is_browsable_capture("9bbc-71.62.x.pcap"));
        // Gzip-compressed captures — loadable, so listable.
        assert!(is_browsable_capture("a.pcap.gz"));
        assert!(is_browsable_capture("a.cap.GZ"));
        assert!(is_browsable_capture("a.pcapng.gz"));
        // Non-captures and traps.
        assert!(!is_browsable_capture("notes.txt"));
        assert!(!is_browsable_capture("archive.gz")); // bare .gz isn't a capture
        assert!(!is_browsable_capture("notes.txt.gz"));
        assert!(!is_browsable_capture("pcap")); // no extension
        assert!(!is_browsable_capture(""));
        assert!(!is_browsable_capture(".pcap")); // dotfile, extension-less stem
    }

    /// The browser lists every capture flavor (including dotted stems and
    /// gzipped files) plus directories, and hides non-capture files.
    #[test]
    fn refresh_file_entries_repro() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("9bbc7162-978d-4456-b81c-496ccb2b1200.pcap"), b"x").unwrap();
        std::fs::write(p.join("plain.pcap"), b"x").unwrap();
        std::fs::write(p.join("ng.pcapng"), b"x").unwrap();
        std::fs::write(p.join("legacy.cap"), b"x").unwrap();
        std::fs::write(p.join("gz.pcap.gz"), b"x").unwrap();
        std::fs::write(p.join("upper.PCAP"), b"x").unwrap();
        std::fs::write(p.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir(p.join("subdir")).unwrap();

        let mut app = App::new_test();
        app.set_open_dir_for_test(p.to_path_buf());
        refresh_file_entries(&mut app);

        let names: Vec<&str> = app
            .file_open
            .entries
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        // Diagnostic: surface exactly what the browser would show.
        assert!(names.contains(&"plain.pcap"), "listed: {names:?}");
        assert!(names.contains(&"ng.pcapng"), "listed: {names:?}");
        assert!(names.contains(&"legacy.cap"), "listed: {names:?}");
        assert!(names.contains(&"upper.PCAP"), "listed: {names:?}");
        assert!(names.contains(&"subdir"), "listed: {names:?}");
        assert!(!names.contains(&"notes.txt"), "listed: {names:?}");
        // Gzipped captures are loadable, so the browser must list them too.
        assert!(names.contains(&"gz.pcap.gz"), "listed: {names:?}");
        // A readable directory produces no error.
        assert!(app.file_open.error.is_none());
    }

    /// An unreadable directory surfaces a "Cannot read" error with the
    /// privilege-drop hint instead of a silently blank list.
    #[cfg(unix)]
    #[test]
    fn refresh_file_entries_reports_unreadable_dir() {
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses directory permissions, so this scenario (the sudo /
        // privilege-drop case) only reproduces for an unprivileged user.
        if crate::privilege::is_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("a.pcap"), b"x").unwrap();
        // Strip all permissions so read_dir fails with PermissionDenied.
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        let mut app = App::new_test();
        app.set_open_dir_for_test(locked.clone());
        refresh_file_entries(&mut app);
        let err = app.file_open.error.clone();

        // Restore perms so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));

        let err = err.expect("unreadable dir should set open_error");
        assert!(err.contains("Cannot read"), "got: {err}");
        assert!(
            err.contains("without sudo"),
            "missing privilege-drop hint: {err}"
        );
    }

    /// Refreshing a readable directory clears a stale error from an
    /// earlier failed refresh.
    #[test]
    fn refresh_file_entries_clears_stale_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.pcap"), b"x").unwrap();
        let mut app = App::new_test();
        app.file_open.error = Some("stale".to_string());
        app.set_open_dir_for_test(dir.path().to_path_buf());
        refresh_file_entries(&mut app);
        assert!(
            app.file_open.error.is_none(),
            "readable dir must clear the error"
        );
        assert!(app.file_open.entries.iter().any(|e| e.name == "a.pcap"));
    }

    /// The offline load path shares `pipeline::is_rtcp_packet` with live
    /// capture — spot-checks its port/version/payload-type gates.
    #[test]
    fn offline_rtcp_detection_uses_the_pipeline_check() {
        // The offline TUI load path routes RTCP through the same
        // `pipeline::is_rtcp_packet` as live capture (no private copy).
        use crate::pipeline::is_rtcp_packet;
        // even port -> false
        assert!(!is_rtcp_packet(&[0x80, 200, 0, 0, 0, 0, 0, 0], 5000));
        // odd port, version 2, pt 200 -> true
        assert!(is_rtcp_packet(&[0x80, 200, 0, 0, 0, 0, 0, 0], 5001));
        // too short -> false
        assert!(!is_rtcp_packet(&[0x80, 200], 5001));
        // wrong version -> false
        assert!(!is_rtcp_packet(&[0x00, 200, 0, 0, 0, 0, 0, 0], 5001));
        // pt out of range -> false
        assert!(!is_rtcp_packet(&[0x80, 100, 0, 0, 0, 0, 0, 0], 5001));
    }

    /// Manual-path mode: Delete removes the char AT the cursor (leaving the
    /// cursor put), and Delete at end-of-line is a no-op — the forward-delete
    /// counterpart to Backspace that the filter dialog already had.
    #[test]
    fn manual_path_delete_removes_char_at_cursor() {
        use crossterm::event::{KeyEvent, KeyModifiers};
        let del = || KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE);

        let mut app = App::new_test();
        app.file_open.manual_mode = true;
        app.file_open.path = "/tmp/x".to_string();
        app.file_open.cursor = 0; // before the leading '/'

        handle_file_open_manual_key(&mut app, del());
        assert_eq!(
            app.file_open.path, "tmp/x",
            "Delete drops the char at cursor"
        );
        assert_eq!(
            app.file_open.cursor, 0,
            "cursor stays put on forward-delete"
        );

        // Delete at end-of-line changes nothing.
        app.file_open.cursor = app.file_open.path.len();
        handle_file_open_manual_key(&mut app, del());
        assert_eq!(app.file_open.path, "tmp/x", "Delete at EOL is a no-op");
    }

    /// Manual-path Delete stays on char boundaries for multibyte input (no
    /// mid-character `String::remove` panic).
    #[test]
    fn manual_path_delete_is_char_boundary_safe() {
        use crossterm::event::{KeyEvent, KeyModifiers};
        let mut app = App::new_test();
        app.file_open.manual_mode = true;
        app.file_open.path = "éx".to_string();
        app.file_open.cursor = 0; // before 'é' (2 bytes)
        handle_file_open_manual_key(&mut app, KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        assert_eq!(app.file_open.path, "x");
    }

    /// `~` expands to `$HOME`; absolute paths pass through unchanged.
    #[test]
    fn expand_tilde_expands_home() {
        // SAFETY: test-only env mutation
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        assert_eq!(expand_tilde("~/foo"), "/home/testuser/foo");
        assert_eq!(expand_tilde("/abs/path"), "/abs/path");
    }

    /// Loading a nonexistent path returns "File not found" immediately.
    #[test]
    fn load_pcap_file_missing_returns_error() {
        let mut app = App::new_test();
        let msg = load_pcap_file(&mut app, "/nonexistent/path/file.pcap");
        assert!(msg.contains("File not found"), "got: {msg}");
    }

    /// Absolute path of the repo's `sip_call.pcap` test fixture.
    fn fixture_pcap() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sip_call.pcap")
    }

    /// The dialog's Enter path must NOT parse the file on the UI thread —
    /// a large pcap froze the TUI for the whole load with no feedback.
    /// begin starts a worker; poll applies progress and the final outcome.
    #[test]
    fn begin_pcap_load_populates_stores_in_background_and_poll_applies_result() {
        let mut app = App::new_test();
        let fixture = fixture_pcap();
        begin_pcap_load(&mut app, fixture.to_str().unwrap());
        assert!(app.pcap_load.is_some(), "a load worker must be in flight");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while app.pcap_load.is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "background load never completed"
            );
            poll_pcap_load(&mut app);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            !app.dialog_store.read().is_empty(),
            "fixture dialogs must be loaded"
        );
        let msg = app.status_error.clone().unwrap_or_default();
        assert!(msg.contains("Loaded"), "final status, got: {msg}");
        assert!(
            app.capture_mode.contains("Offline"),
            "got: {}",
            app.capture_mode
        );
    }

    /// A missing file is reported on the status line without spawning a
    /// load worker.
    #[test]
    fn begin_pcap_load_missing_file_reports_immediately() {
        let mut app = App::new_test();
        begin_pcap_load(&mut app, "/nonexistent/path/file.pcap");
        assert!(app.pcap_load.is_none(), "no worker for a missing file");
        assert!(
            app.status_error
                .as_deref()
                .unwrap_or("")
                .contains("File not found"),
            "got: {:?}",
            app.status_error
        );
    }

    /// A second load while one is in flight is refused and the running
    /// load's progress handle is untouched.
    #[test]
    fn begin_pcap_load_rejects_concurrent_load() {
        let mut app = App::new_test();
        app.pcap_load = Some(std::sync::Arc::new(PcapLoadProgress::new("other.pcap")));
        let fixture = fixture_pcap();
        begin_pcap_load(&mut app, fixture.to_str().unwrap());
        let msg = app.status_error.clone().unwrap_or_default();
        assert!(msg.contains("in progress"), "busy guard, got: {msg}");
        assert_eq!(
            app.pcap_load.as_ref().map(|p| p.filename.as_str()),
            Some("other.pcap"),
            "the in-flight load must not be replaced"
        );
    }

    /// Names from an embedded pcapng Name Resolution Block become
    /// resolvable after the load (libpcap itself ignores the block).
    #[test]
    fn load_pcap_file_reads_embedded_nrb_names() {
        use crate::capture::{PcapExportMode, PcapWriter};
        use std::net::IpAddr;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("named.pcapng");
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        {
            let mut w =
                PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw).unwrap();
            w.write_name_resolution_block(&[(ip, vec!["sbc-edge".to_string()])])
                .unwrap();
            w.finish().unwrap();
        }
        let mut app = App::new_test();
        load_pcap_file(&mut app, path.to_str().unwrap());
        // The embedded NRB name is now resolvable (libpcap ignores the block;
        // our metadata pass loads it).
        assert_eq!(
            app.resolver()
                .name(ip, crate::names::NameMode::Names)
                .as_deref(),
            Some("sbc-edge")
        );
    }

    /// A capture carrying a Decryption Secrets Block makes the final
    /// status message warn about the embedded secrets.
    #[test]
    fn load_pcap_file_alerts_on_embedded_secrets() {
        use crate::capture::{PcapExportMode, PcapWriter};
        let dir = tempfile::tempdir().unwrap();
        let keylog = dir.path().join("keys.txt");
        std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();
        // Filename deliberately free of "secret" so the assertion can't pass
        // trivially on the path.
        let path = dir.path().join("withkeys.pcapng");
        {
            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true,
                PcapExportMode::EncryptedWithDsb,
            )
            .unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();
            w.finish().unwrap();
        }
        let mut app = App::new_test();
        let msg = load_pcap_file(&mut app, path.to_str().unwrap());
        assert!(
            msg.to_lowercase().contains("decryption secret"),
            "status should warn about embedded secrets: {msg}"
        );
    }

    /// File-open must route through the same pipeline core as live capture:
    /// a SIP INVITE wrapped in a WebSocket data frame on a WS port (SIP over
    /// WS, RFC 7118) must be unwrapped and land in the dialog store.
    #[test]
    fn load_pcap_file_unwraps_websocket_sip() {
        use crate::capture::packet::Packet;
        use crate::capture::{PcapExportMode, PcapWriter};

        /// Unmasked FIN+text WebSocket frame wrapping `payload`.
        fn ws_frame(payload: &[u8]) -> Vec<u8> {
            let mut f = vec![0x81];
            if payload.len() < 126 {
                f.push(payload.len() as u8);
            } else {
                f.push(126);
                f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            f.extend_from_slice(payload);
            f
        }

        /// Minimal Ethernet + IPv4 + TCP frame (PSH|ACK) carrying `payload`.
        fn eth_ipv4_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
            let ip_total = 20 + 20 + payload.len() as u16;
            let mut p = Vec::new();
            p.extend_from_slice(&[0xAA; 6]); // dst MAC
            p.extend_from_slice(&[0xBB; 6]); // src MAC
            p.extend_from_slice(&[0x08, 0x00]); // IPv4
            p.push(0x45);
            p.push(0x00);
            p.extend_from_slice(&ip_total.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x01]); // id
            p.extend_from_slice(&[0x40, 0x00]); // DF
            p.push(64); // ttl
            p.push(6); // TCP
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(&[10, 0, 0, 1]); // src ip
            p.extend_from_slice(&[10, 0, 0, 2]); // dst ip
            p.extend_from_slice(&src_port.to_be_bytes());
            p.extend_from_slice(&dst_port.to_be_bytes());
            p.extend_from_slice(&1u32.to_be_bytes()); // seq
            p.extend_from_slice(&1u32.to_be_bytes()); // ack
            p.push(0x50); // data offset 5
            p.push(0x18); // PSH|ACK
            p.extend_from_slice(&[0xFF, 0xFF]); // window
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(&[0x00, 0x00]); // urgent
            p.extend_from_slice(payload);
            p
        }

        let invite = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/WS df7j.invalid;branch=z9hG4bKwsopen\r\n\
                       From: <sip:alice@example.com>;tag=ws1\r\n\
                       To: <sip:bob@example.com>\r\n\
                       Call-ID: ws-open@test\r\n\
                       CSeq: 1 INVITE\r\n\
                       Content-Length: 0\r\n\r\n";

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws-sip.pcap");
        {
            let mut w =
                PcapWriter::with_format(&path, 1, None, None, false, PcapExportMode::Raw).unwrap();
            let frame = eth_ipv4_tcp(51000, 8080, &ws_frame(invite));
            let n = frame.len();
            w.write(&Packet::new(chrono::Utc::now(), frame, n, n, None, 1))
                .unwrap();
            w.finish().unwrap();
        }

        let mut app = App::new_test();
        load_pcap_file(&mut app, path.to_str().unwrap());
        assert!(
            app.dialog_store.read().get("ws-open@test").is_some(),
            "WS-wrapped SIP must be unwrapped into the dialog store on file open"
        );
    }
}
