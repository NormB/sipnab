// SPDX-License-Identifier: MIT OR Apache-2.0

//! Save/export: pcap, txt, mermaid, json, ndjson, csv, markdown,
//! wav, sipp scenario, rtp-json.
//!
//! Each `save_to_*_path` function takes the shared `App`, resolves which
//! dialogs or streams to export (multi-select checkboxes, the current call
//! flow, or everything), writes one output file at the given path, and
//! returns a human-readable status string for the TUI status line —
//! `"Saved ..."` on success, or a `"No ... to save"` / `"Save failed ..."`
//! style message otherwise. None of these functions return `Result`; all
//! error conditions are folded into the returned status text. Existing
//! files at the target path are overwritten without prompting.

use super::*;

// ── Save functionality ─────────────────────────────────────────────

/// Save all dialogs to a pcap or pcap-ng file.
///
/// Re-synthesizes an Ethernet/IP/UDP-or-TCP packet for every SIP message
/// of every exported dialog (checked rows, or all when none are checked).
/// In pcapng mode, when name resolution is active, a Name Resolution
/// Block with the resolver's validated names is written before the
/// packets (DNS-derived names only in DNS mode).
///
/// # Arguments
///
/// * `app` — application state (dialog store, resolver, selection).
/// * `path_str` — destination file path.
/// * `pcapng` — `true` writes pcap-ng, `false` writes classic pcap.
///
/// # Returns
///
/// `"Saved N packets (fmt) to path"` on success; `"No messages to
/// save"` when nothing is exportable; `"Save failed ..."` when the
/// writer cannot be created or the NRB write fails; `"Write error after
/// N packets ..."` when a packet write fails partway.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store` for the whole export.
/// Creates or truncates the file at `path_str`; on a mid-stream write
/// error the partially written file is left on disk.
pub(super) fn save_to_pcap_path(app: &App, path_str: &str, pcapng: bool) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect all messages across all dialogs
    let messages: Vec<&crate::sip::SipMessage> = app
        .dialogs_to_export(&store)
        .into_iter()
        .flat_map(|d| d.messages.iter())
        .collect();

    if messages.is_empty() {
        return "No messages to save".to_string();
    }

    // Create writer (DLT_EN10MB = 1)
    let mut writer = match crate::capture::PcapWriter::with_format(
        &path,
        1,
        None,
        None,
        pcapng,
        crate::capture::PcapExportMode::Raw,
    ) {
        Ok(w) => w,
        Err(e) => return format!("Save failed: {e}"),
    };

    // Embed name resolution (NRB) before the packets, when name resolution is
    // active (opt-in via the mode). DNS-derived names are included only in DNS
    // mode. No-op for plain pcap or when there are no validated names.
    if pcapng && app.name_mode() != crate::names::NameMode::Off {
        let include_dns = app.name_mode() == crate::names::NameMode::Dns;
        let entries = app.resolver().nrb_entries(include_dns);
        if let Err(e) = writer.write_name_resolution_block(&entries) {
            return format!("Save failed writing name resolution: {e}");
        }
    }

    let fmt_label = if pcapng { "pcapng" } else { "pcap" };
    let mut count = 0;
    for msg in &messages {
        let pkt = crate::output::synthetic::build_synthetic_packet(msg);
        if let Err(e) = writer.write(&pkt) {
            return format!("Write error after {count} packets: {e}");
        }
        count += 1;
    }

    format!("Saved {count} packets ({fmt_label}) to {}", path.display())
}

/// Save all dialogs as plain text SIP messages.
///
/// Each exported message is preceded by a `# Message N | timestamp |
/// transport src -> dst` header line and separated by `---` dividers;
/// non-UTF-8 bodies are replaced with a `(binary: N bytes)` note.
///
/// # Arguments
///
/// * `app` — application state (dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N messages (txt) to path"` on success; `"No messages to
/// save"` when nothing is exportable; `"Save failed ..."` when the
/// single `std::fs::write` fails.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_txt_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    let messages: Vec<&crate::sip::SipMessage> = app
        .dialogs_to_export(&store)
        .into_iter()
        .flat_map(|d| d.messages.iter())
        .collect();

    if messages.is_empty() {
        return "No messages to save".to_string();
    }

    let mut output = String::new();
    for (i, msg) in messages.iter().enumerate() {
        if i > 0 {
            output.push_str("\n---\n\n");
        }
        // Header with timestamp, source, destination, and transport
        output.push_str(&format!(
            "# Message {} | {} | {} {}:{} -> {}:{}\n",
            i + 1,
            msg.timestamp.format("%Y-%m-%d %H:%M:%S%.3f UTC"),
            msg.transport,
            msg.src_addr,
            msg.src_port,
            msg.dst_addr,
            msg.dst_port,
        ));
        // Raw SIP message
        match std::str::from_utf8(&msg.raw) {
            Ok(text) => output.push_str(text),
            Err(_) => output.push_str(&format!("(binary: {} bytes)", msg.raw.len())),
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} messages (txt) to {}",
            messages.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Save current call flow as a Mermaid sequence diagram.
///
/// In the call-flow view, exports that dialog (plus correlated legs when
/// extended mode is on, merged in timestamp order); in the call list,
/// exports the checked dialogs (or all when none are checked). The
/// output is a self-contained HTML page embedding the Mermaid diagram.
///
/// # Arguments
///
/// * `app` — application state (current view, dialog store, flow options).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved Mermaid diagram (N messages) to path"` on success (N counts
/// real messages, not spacers); `"No messages to export"` when nothing
/// is exportable; `"Save failed ..."` when the write fails.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Clones the exported
/// messages out of the store, then creates or truncates the file at
/// `path_str` in one write.
pub(super) fn save_to_mermaid_path(app: &App, path_str: &str) -> String {
    let path = std::path::PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect messages based on current view
    let messages: Vec<crate::sip::SipMessage> =
        if let View::CallFlow(ref call_id) = app.current_view {
            // In call flow: export just this dialog (+ correlated if extended)
            if app.flow.extended {
                if let Some(dialog) = store.get(call_id) {
                    let mut all: Vec<&crate::sip::SipMessage> = dialog.messages.iter().collect();
                    let correlated = store.find_correlated(call_id);
                    for leg in &correlated {
                        all.extend(leg.messages.iter());
                    }
                    all.sort_by_key(|m| m.timestamp);
                    all.into_iter().cloned().collect()
                } else {
                    Vec::new()
                }
            } else if let Some(dialog) = store.get(call_id) {
                dialog.messages.clone()
            } else {
                Vec::new()
            }
        } else {
            // In call list: export the selected dialogs (or all if none checked)
            app.dialogs_to_export(&store)
                .into_iter()
                .flat_map(|d| d.messages.clone())
                .collect()
        };

    if messages.is_empty() {
        return "No messages to export".to_string();
    }

    let ft = messages[0].timestamp;
    let flow_opts = call_flow::FlowDisplayOptions {
        sdp_mode: SdpDisplayMode::None,
        ts_mode: TimestampMode::Absolute,
        color_mode: ColorMode::Method,
        show_rtp: false,
        selected_msg: None,
        theme: &app.theme,
        resolver: app.resolver.as_ref(),
        name_mode: app.name_mode,
        rtp_segments: &[],
    };
    let (participants, msgs) = call_flow::prepare_messages(
        &messages,
        ft,
        None,
        &flow_opts,
        &std::collections::HashSet::new(),
    );

    let mermaid = call_flow::export::export_mermaid_html(&participants, &msgs);

    match std::fs::write(&path, &mermaid) {
        Ok(()) => format!(
            "Saved Mermaid diagram ({} messages) to {}",
            msgs.iter().filter(|m| !m.is_spacer).count(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Format a `DialogState` as a display string for export (pure mapping
/// to a `&'static str`; unlike the call list it renders Failed as
/// `"Failed"`, not `"FAILED"`).
pub(super) fn format_dialog_state(state: &crate::sip::dialog::DialogState) -> &'static str {
    use crate::sip::dialog::DialogState;
    match state {
        DialogState::Trying => "Trying",
        DialogState::Ringing => "Ringing",
        DialogState::InCall => "InCall",
        DialogState::Completed => "Completed",
        DialogState::Cancelled => "Cancelled",
        DialogState::Failed => "Failed",
        DialogState::Registered => "Registered",
        DialogState::Expired => "Expired",
        DialogState::Pending => "Pending",
        DialogState::Active => "Active",
        DialogState::Terminated => "Terminated",
        DialogState::Transferring => "Transferring",
    }
}

/// Escape a field for CSV output: if it contains commas, quotes, or newlines,
/// wrap in double quotes and double any existing quotes.
pub(super) fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Export all dialogs as pretty-printed JSON with parsed headers, timing, and state.
///
/// Each dialog serializes as the canonical `DialogSummary` object
/// extended with `src_addr`, `dst_addr`, and a `messages` array of
/// per-message metadata (timestamp, direction, method/status,
/// endpoints, retransmission flag); the file holds one JSON array.
///
/// # Arguments
///
/// * `app` — application state (dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N dialogs (JSON) to path"` on success; `"No dialogs to
/// save"` when nothing is exportable; `"JSON serialization failed ..."`
/// or `"Save failed ..."` on serialization or write errors.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_json_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = app.dialogs_to_export(&store);

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let json_dialogs: Vec<serde_json::Value> = dialogs
        .iter()
        .map(|d| {
            let messages: Vec<serde_json::Value> = d
                .messages
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "timestamp": m.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                        "is_request": m.is_request,
                        "method": m.method.as_ref().map(|m| m.as_str()),
                        "status_code": m.status_code,
                        "src": format!("{}:{}", m.src_addr, m.src_port),
                        "dst": format!("{}:{}", m.dst_addr, m.dst_port),
                        "is_retransmission": m.is_retransmission,
                    })
                })
                .collect();

            // Canonical summary (WS3: `msg_count`, not `message_count`) plus
            // the save-specific extras (addresses and the full message list).
            let mut obj =
                match serde_json::to_value(crate::output::model::DialogSummary::from(*d)) {
                    Ok(serde_json::Value::Object(map)) => map,
                    _ => serde_json::Map::new(),
                };
            obj.insert("src_addr".into(), d.src_addr.to_string().into());
            obj.insert("dst_addr".into(), d.dst_addr.to_string().into());
            obj.insert("messages".into(), serde_json::Value::Array(messages));
            serde_json::Value::Object(obj)
        })
        .collect();

    match serde_json::to_string_pretty(&json_dialogs) {
        Ok(json_str) => match std::fs::write(&path, &json_str) {
            Ok(()) => format!(
                "Saved {} dialogs (JSON) to {}",
                dialogs.len(),
                path.display()
            ),
            Err(e) => format!("Save failed: {e}"),
        },
        Err(e) => format!("JSON serialization failed: {e}"),
    }
}

/// Export all dialogs as newline-delimited JSON (one JSON object per line).
///
/// Each line carries the dialog identity, endpoints, state, a `timing`
/// object (`pdd_ms`, `setup_ms`, `duration_ms` where `duration_ms` is
/// answered-to-BYE), and a compact `messages` array.
///
/// # Arguments
///
/// * `app` — application state (dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N dialogs (NDJSON) to path"` on success; `"No dialogs to
/// save"` when nothing is exportable; `"JSON serialization failed ..."`
/// (aborting before any file is created) or `"Save failed ..."` on a
/// write error.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write after all lines serialize cleanly.
pub(super) fn save_to_ndjson_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = app.dialogs_to_export(&store);

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut output = String::new();
    for d in &dialogs {
        let messages: Vec<serde_json::Value> = d
            .messages
            .iter()
            .map(|m| {
                serde_json::json!({
                    "timestamp": m.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "is_request": m.is_request,
                    "method": m.method.as_ref().map(|m| m.as_str()),
                    "status_code": m.status_code,
                    "src": format!("{}:{}", m.src_addr, m.src_port),
                    "dst": format!("{}:{}", m.dst_addr, m.dst_port),
                })
            })
            .collect();

        let duration_ms = d.timing.bye_sent.and_then(|bye| {
            d.timing
                .answered_at
                .map(|ans| (bye - ans).num_milliseconds())
        });
        let timing = serde_json::json!({
            "pdd_ms": d.timing.pdd_ms(),
            "setup_ms": d.timing.setup_ms(),
            "duration_ms": duration_ms,
        });

        let obj = serde_json::json!({
            "call_id": d.call_id,
            "method": d.method.as_str(),
            "state": format_dialog_state(d.state()),
            "from_user": d.from_user,
            "to_user": d.to_user,
            "src_addr": d.src_addr.to_string(),
            "dst_addr": d.dst_addr.to_string(),
            "created_at": d.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "message_count": d.messages.len(),
            "timing": timing,
            "messages": messages,
        });

        match serde_json::to_string(&obj) {
            Ok(line) => {
                output.push_str(&line);
                output.push('\n');
            }
            Err(e) => return format!("JSON serialization failed: {e}"),
        }
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} dialogs (NDJSON) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export dialog summaries as CSV (one row per dialog).
///
/// Columns: `call_id,method,state,from,to,src_ip,dst_ip,messages,
/// pdd_ms,setup_ms,created_at`. Text fields go through `csv_escape`;
/// missing PDD/setup values render as empty cells.
///
/// # Arguments
///
/// * `app` — application state (dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N dialogs (CSV) to path"` on success; `"No dialogs to
/// save"` when nothing is exportable; `"Save failed ..."` when the
/// write fails.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_csv_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = app.dialogs_to_export(&store);

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut output = String::from(
        "call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,setup_ms,created_at\n",
    );

    for d in &dialogs {
        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&d.call_id),
            csv_escape(d.method.as_str()),
            csv_escape(format_dialog_state(d.state())),
            csv_escape(d.from_user.as_deref().unwrap_or("")),
            csv_escape(d.to_user.as_deref().unwrap_or("")),
            csv_escape(&d.src_addr.to_string()),
            csv_escape(&d.dst_addr.to_string()),
            d.messages.len(),
            d.timing.pdd_ms().map_or(String::new(), |v| v.to_string()),
            d.timing.setup_ms().map_or(String::new(), |v| v.to_string()),
            d.created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
        output.push_str(&row);
    }

    match std::fs::write(&path, &output) {
        Ok(()) => format!(
            "Saved {} dialogs (CSV) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export a Markdown call summary suitable for tickets and incident docs.
///
/// Writes one `## Dialog:` section per exported dialog: a field/value
/// table (state, From/To, endpoints from the first message, counts,
/// PDD/setup when known, creation time) followed by a numbered
/// message-flow table with direction arrows.
///
/// # Arguments
///
/// * `app` — application state (dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N dialogs (Markdown) to path"` on success; `"No dialogs to
/// save"` when nothing is exportable; `"Save failed ..."` when the
/// write fails.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_markdown_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = app.dialogs_to_export(&store);

    if dialogs.is_empty() {
        return "No dialogs to save".to_string();
    }

    let mut md = String::from("# Call Summary\n\nGenerated by sipnab v0.3.1\n\n");

    for d in &dialogs {
        md.push_str(&format!(
            "## Dialog: {} ({})\n\n",
            d.call_id,
            d.method.as_str(),
        ));

        md.push_str("| Field | Value |\n|-------|-------|\n");
        md.push_str(&format!("| State | {} |\n", format_dialog_state(d.state())));
        md.push_str(&format!(
            "| From | {} |\n",
            d.from_user.as_deref().unwrap_or("-")
        ));
        md.push_str(&format!(
            "| To | {} |\n",
            d.to_user.as_deref().unwrap_or("-")
        ));

        // Source/destination from first message if available
        if let Some(first) = d.messages.first() {
            md.push_str(&format!(
                "| Source | {}:{} |\n",
                first.src_addr, first.src_port
            ));
            md.push_str(&format!(
                "| Destination | {}:{} |\n",
                first.dst_addr, first.dst_port
            ));
        }

        md.push_str(&format!("| Messages | {} |\n", d.messages.len()));

        if let Some(pdd) = d.timing.pdd_ms() {
            md.push_str(&format!("| PDD | {pdd}ms |\n"));
        }
        if let Some(setup) = d.timing.setup_ms() {
            md.push_str(&format!("| Setup | {setup}ms |\n"));
        }

        md.push_str(&format!(
            "| Created | {} |\n\n",
            d.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Message flow table
        if !d.messages.is_empty() {
            md.push_str("### Message Flow\n\n");
            md.push_str("| # | Time | Direction | Method/Status |\n");
            md.push_str("|---|------|-----------|---------------|\n");

            for (i, m) in d.messages.iter().enumerate() {
                let direction = if m.is_request {
                    "\u{2192}" // →
                } else {
                    "\u{2190}" // ←
                };
                let label = if m.is_request {
                    m.method
                        .as_ref()
                        .map(|m| m.as_str())
                        .unwrap_or("?")
                        .to_string()
                } else {
                    match (m.status_code, m.reason.as_deref()) {
                        (Some(code), Some(reason)) => format!("{code} {reason}"),
                        (Some(code), None) => code.to_string(),
                        _ => "?".to_string(),
                    }
                };
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    i + 1,
                    m.timestamp.format("%H:%M:%S%.3f"),
                    direction,
                    label,
                ));
            }
            md.push('\n');
        }
    }

    match std::fs::write(&path, &md) {
        Ok(()) => format!(
            "Saved {} dialogs (Markdown) to {}",
            dialogs.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export captured RTP audio to a WAV file.
///
/// Finds G.711 streams associated with the current dialog (or all streams
/// if no dialog is in focus) and exports them via `crate::rtp::audio_export`.
/// Outside the call-flow view, the dialog is picked by the call list's
/// selected index over the store's raw iteration order.
///
/// # Arguments
///
/// * `app` — application state (current view, dialog and stream stores).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// The status message from the audio exporter on success; `"No RTP
/// streams associated with this dialog"` / `"No RTP streams captured"`
/// when there is nothing to export; `"WAV export failed ..."` on error.
///
/// # Side effects
///
/// May take a read lock on `app.dialog_store` (call-list path) and
/// always takes a read lock on `app.stream_store`. The audio exporter
/// creates or truncates the file at `path_str`.
pub(super) fn save_to_wav_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);

    // Determine the current dialog's Call-ID (if viewing a call flow)
    let call_id = match &app.current_view {
        View::CallFlow(cid) => Some(cid.clone()),
        // Resolve the call-list selection against the DISPLAYED order (filter
        // + search + sort), the same list the renderer draws, so an export
        // under an active filter/sort saves the highlighted row's audio and
        // not a wrong dialog picked by raw store order.
        _ => crate::tui::controllers::get_selected_call_id(app),
    };

    let stream_store = app.stream_store.read();

    // Collect streams: filter by dialog if we have one, otherwise use all
    let streams: Vec<&crate::rtp::stream::RtpStream> = if let Some(ref cid) = call_id {
        stream_store.streams_for(cid).collect()
    } else {
        stream_store.iter().collect()
    };

    if streams.is_empty() {
        return if call_id.is_some() {
            "No RTP streams associated with this dialog".to_string()
        } else {
            "No RTP streams captured".to_string()
        };
    }

    match crate::rtp::audio_export::export_dialog_to_wav(&streams, &path) {
        Ok(msg) => msg,
        Err(e) => format!("WAV export failed: {e}"),
    }
}

/// Map the structural host and port of a SIP request-URI to the SIPp
/// `[remote_ip]` / `[remote_port]` placeholders.
///
/// Substitutes only the structural host and port components of the URI
/// (never digits that merely appear in the user part, parameters, or
/// headers): the host is replaced when it equals `dst_addr`, the port
/// when it equals `dst_port`. URI parameters/headers after the hostport
/// and non-SIP(S) URIs are returned unchanged.
fn sipp_placeholder_uri(ruri: &str, dst_addr: std::net::IpAddr, dst_port: u16) -> String {
    // scheme ":" — only sip/sips URIs have the user@host:port shape we map.
    let Some((scheme, rest)) = ruri.split_once(':') else {
        return ruri.to_string();
    };
    if !scheme.eq_ignore_ascii_case("sip") && !scheme.eq_ignore_ascii_case("sips") {
        return ruri.to_string();
    }

    // userinfo "@" hostport — '@' is not valid unescaped in userinfo or
    // hostport, so the last '@' (if any) is the separator.
    let (userinfo, hostpart) = match rest.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, rest),
    };

    // hostport ends at the first ';' (uri-parameters) or '?' (headers).
    let hostport_end = hostpart.find([';', '?']).unwrap_or(hostpart.len());
    let (hostport, tail) = hostpart.split_at(hostport_end);

    // host [":" port], with IPv6 references in brackets.
    let (host, port) = if hostport.starts_with('[') {
        match hostport.find(']') {
            Some(close) => match hostport[close + 1..].strip_prefix(':') {
                Some(p) => (&hostport[..=close], Some(p)),
                None => (hostport, None),
            },
            None => (hostport, None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };

    let host_matches = host.trim_start_matches('[').trim_end_matches(']') == dst_addr.to_string();

    let mut out = String::with_capacity(ruri.len() + 24);
    out.push_str(scheme);
    out.push(':');
    if let Some(user) = userinfo {
        out.push_str(user);
        out.push('@');
    }
    out.push_str(if host_matches { "[remote_ip]" } else { host });
    if let Some(p) = port {
        out.push(':');
        if p.parse::<u16>() == Ok(dst_port) {
            out.push_str("[remote_port]");
        } else {
            out.push_str(p);
        }
    }
    out.push_str(tail);
    out
}

/// Export a SIPp scenario XML from the current dialog's call flow.
///
/// Exports exactly one dialog: the current call-flow dialog, else the
/// first checked (or first overall) call-list dialog. The caller side is
/// inferred from the first message's source; caller messages become
/// `<send>` blocks with SIPp placeholder substitution (`[remote_ip]`,
/// `[call_id]`, `[branch]`, ...), remote messages become `<recv>` blocks
/// (provisional responses marked optional), and inter-message gaps over
/// 500 ms become `<pause>` elements.
///
/// # Arguments
///
/// * `app` — application state (current view, dialog store, selection).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved SIPp scenario (N messages) to path"` on success; `"No dialog
/// to export"` / `"No messages in dialog"` when there is nothing usable;
/// `"Save failed ..."` when the write fails.
///
/// # Side effects
///
/// Takes a read lock on `app.dialog_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_sipp_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Pick dialog: current call flow view, else the first selected dialog
    // (or the first overall when nothing is checked).
    let dialog = if let View::CallFlow(ref call_id) = app.current_view {
        store.get(call_id)
    } else {
        app.dialogs_to_export(&store).into_iter().next()
    };

    let dialog = match dialog {
        Some(d) => d,
        None => return "No dialog to export".to_string(),
    };

    if dialog.messages.is_empty() {
        return "No messages in dialog".to_string();
    }

    // Determine the "caller" side from the first request
    let caller_addr = dialog.messages.first().map(|m| (m.src_addr, m.src_port));

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!-- Generated by sipnab v0.3.1 -->\n");
    xml.push_str(&format!(
        "<scenario name=\"sipnab_{}\">\n",
        dialog.method.as_str().to_lowercase()
    ));

    let mut prev_ts = dialog.messages[0].timestamp;
    for m in &dialog.messages {
        // Insert pause for gaps > 500ms
        let gap_ms = (m.timestamp - prev_ts).num_milliseconds();
        if gap_ms > 500 {
            xml.push_str(&format!("\n  <pause milliseconds=\"{}\"/>\n", gap_ms));
        }
        prev_ts = m.timestamp;

        let is_from_caller = caller_addr
            .map(|(addr, port)| m.src_addr == addr && m.src_port == port)
            .unwrap_or(false);

        if m.is_request {
            if is_from_caller {
                // Caller sends request
                let method = m.method.as_ref().map(|m| m.as_str()).unwrap_or("UNKNOWN");
                let ruri = m
                    .request_uri
                    .as_deref()
                    .unwrap_or("sip:[service]@[remote_ip]:[remote_port]");
                let ruri_sipp = sipp_placeholder_uri(ruri, m.dst_addr, m.dst_port);

                xml.push_str("\n  <send>\n    <![CDATA[\n");
                xml.push_str(&format!("      {} {} SIP/2.0\r\n", method, ruri_sipp));
                xml.push_str(
                    "      Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]\r\n",
                );
                xml.push_str(&format!(
                    "      From: <sip:{}@[local_ip]>;tag=[call_number]\r\n",
                    dialog.from_user.as_deref().unwrap_or("user")
                ));
                xml.push_str(&format!(
                    "      To: <sip:{}@[remote_ip]>\r\n",
                    dialog.to_user.as_deref().unwrap_or("service")
                ));
                xml.push_str("      Call-ID: [call_id]\r\n");
                // Derive CSeq from the original message
                let cseq = m.cseq().map_or_else(
                    || format!("1 {method}"),
                    |(num, meth)| format!("{num} {meth}"),
                );
                xml.push_str(&format!("      CSeq: {cseq}\r\n"));
                xml.push_str("      Max-Forwards: 70\r\n");
                xml.push_str("      Content-Length: [len]\r\n");
                xml.push_str("    ]]>\n  </send>\n");
            } else {
                // Callee sends request (e.g., BYE from remote) — receive it
                let method = m.method.as_ref().map(|m| m.as_str()).unwrap_or("UNKNOWN");
                xml.push_str(&format!("\n  <recv request=\"{method}\"/>\n"));
            }
        } else {
            // Response
            let code = m.status_code.unwrap_or(0);
            if is_from_caller {
                // Caller sending a response (unusual, but handle it)
                xml.push_str(&format!(
                    "\n  <send>\n    <![CDATA[\n      SIP/2.0 {} {}\r\n      [last_Via:]\r\n      [last_From:]\r\n      [last_To:]\r\n      [last_Call-ID:]\r\n      [last_CSeq:]\r\n      Content-Length: 0\r\n\n    ]]>\n  </send>\n",
                    code,
                    m.reason.as_deref().unwrap_or("OK"),
                ));
            } else {
                // Receive response from remote
                let optional = if (100..200).contains(&code) {
                    " optional=\"true\""
                } else {
                    ""
                };
                xml.push_str(&format!("\n  <recv response=\"{code}\"{optional}/>\n"));
            }
        }
    }

    xml.push_str("\n</scenario>\n");

    match std::fs::write(&path, &xml) {
        Ok(()) => format!(
            "Saved SIPp scenario ({} messages) to {}",
            dialog.messages.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    }
}

/// Export RTP/RTCP stream quality data as JSON.
///
/// Serializes every tracked stream (no dialog filtering) as the
/// canonical `StreamSummary` object extended with `duration_secs`
/// (rounded to one decimal), `cn_frames`, and `silence_periods`; the
/// file holds one JSON array.
///
/// # Arguments
///
/// * `app` — application state (stream store).
/// * `path_str` — destination file path.
///
/// # Returns
///
/// `"Saved N RTP streams (JSON) to path"` on success; `"No RTP streams
/// to save"` when the store is empty; `"JSON serialization failed ..."`
/// or `"Save failed ..."` on serialization or write errors.
///
/// # Side effects
///
/// Takes a read lock on `app.stream_store`. Creates or truncates the
/// file at `path_str` in one write.
pub(super) fn save_to_rtp_json_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let stream_store = app.stream_store.read();
    let streams: Vec<&crate::rtp::stream::RtpStream> = stream_store.iter().collect();

    if streams.is_empty() {
        return "No RTP streams to save".to_string();
    }

    let json_streams: Vec<serde_json::Value> = streams
        .iter()
        .map(|s| {
            let duration_secs = s
                .last_seen
                .signed_duration_since(s.first_seen)
                .num_milliseconds() as f64
                / 1000.0;

            // Canonical summary (WS3) — MOS comes from the single E-model in
            // rtp::quality (this path used to carry its own divergent copy) —
            // plus the save-specific media extras.
            let mut obj = match serde_json::to_value(crate::output::model::StreamSummary::from(*s))
            {
                Ok(serde_json::Value::Object(map)) => map,
                _ => serde_json::Map::new(),
            };
            obj.insert(
                "duration_secs".into(),
                ((duration_secs * 10.0).round() / 10.0).into(),
            );
            obj.insert("cn_frames".into(), s.cn_frames.into());
            obj.insert("silence_periods".into(), s.silence_periods.len().into());
            serde_json::Value::Object(obj)
        })
        .collect();

    match serde_json::to_string_pretty(&json_streams) {
        Ok(json_str) => match std::fs::write(&path, &json_str) {
            Ok(()) => format!(
                "Saved {} RTP streams (JSON) to {}",
                streams.len(),
                path.display()
            ),
            Err(e) => format!("Save failed: {e}"),
        },
        Err(e) => format!("JSON serialization failed: {e}"),
    }
}

// ── Tests ───────────────────────────────────────────────────────────

/// Tests for every export format: happy paths that verify file content,
/// empty-store status messages, and write failures on unwritable paths.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::{ParsedPacket, TransportProto};
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixed caller-side test address 10.0.0.1.
    fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    /// Fixed callee-side test address 10.0.0.2.
    fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    /// Fixed deterministic base timestamp shared by all fixtures.
    fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Assemble a raw SIP message from a first line and header lines,
    /// CRLF-terminated with an empty body.
    fn raw_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg
    }

    /// Build a parsed INVITE from `from` to `to` at `ts`, sent A→B.
    fn make_invite(call_id: &str, from: &str, to: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = raw_sip(
            &format!("INVITE sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
                &format!("To: \"{to}\" <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            addr_a(),
            addr_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse INVITE")
    }

    /// Build a parsed 200 OK to the INVITE at `ts`, sent B→A.
    fn make_ok(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = raw_sip(
            "SIP/2.0 200 OK",
            &[
                "From: \"a\" <sip:a@example.com>;tag=t1",
                "To: \"b\" <sip:b@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            addr_b(),
            addr_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 200")
    }

    /// App fixture holding two answered dialogs (call-1, call-2).
    fn app_with_dialogs() -> App {
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_ok("call-1@test", t0 + TimeDelta::seconds(1)),
            make_invite("call-2@test", "1003", "1004", t0 + TimeDelta::seconds(5)),
            make_ok("call-2@test", t0 + TimeDelta::seconds(6)),
        ])
    }

    /// Scan a pcapng file's Name Resolution Blocks for the names mapped to `ip`.
    fn nrb_names_for(path: &std::path::Path, ip: [u8; 4]) -> Vec<String> {
        use pcap_file::pcapng::PcapNgReader;
        use pcap_file::pcapng::blocks::name_resolution::Record;
        let bytes = std::fs::read(path).unwrap();
        let mut reader = PcapNgReader::new(&bytes[..]).unwrap();
        let mut names = Vec::new();
        while let Some(Ok(block)) = reader.next_block() {
            if let Some(nrb) = block.into_name_resolution() {
                for rec in &nrb.records {
                    if let Record::Ipv4(r) = rec
                        && r.ip_addr.as_ref() == ip
                    {
                        names = r.names.iter().map(|n| n.to_string()).collect();
                    }
                }
            }
        }
        names
    }

    /// Name resolution on + a manual mapping: the saved pcapng carries an
    /// NRB mapping the source IP to the operator name.
    #[test]
    fn pcapng_save_includes_name_resolution_block() {
        // SUCCESS case: name resolution on + a mapping → the saved pcapng
        // carries an NRB that maps the source IP to the operator's name.
        let mut app = app_with_dialogs();
        app.resolver().set_manual(addr_a(), "sbc-edge".into());
        app.set_name_mode(crate::names::NameMode::Names);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("named.pcapng");
        let msg = save_to_pcap_path(&app, path.to_str().unwrap(), true);
        assert!(msg.starts_with("Saved"), "save failed: {msg}");

        assert_eq!(
            nrb_names_for(&path, [10, 0, 0, 1]),
            vec!["sbc-edge".to_string()]
        );
    }

    /// Name resolution Off: no NRB is written even when a mapping exists.
    #[test]
    fn pcapng_save_without_resolution_writes_no_nrb() {
        // FAILURE/negative case: name resolution Off (default) → no NRB at all,
        // even if a mapping happens to exist.
        let mut app = app_with_dialogs();
        app.resolver().set_manual(addr_a(), "sbc-edge".into());
        app.set_name_mode(crate::names::NameMode::Off);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.pcapng");
        save_to_pcap_path(&app, path.to_str().unwrap(), true);

        assert!(
            nrb_names_for(&path, [10, 0, 0, 1]).is_empty(),
            "no NRB expected when name resolution is Off"
        );
    }

    /// Build a minimal RTP packet (12-byte header + payload) and feed it to
    /// the app's stream store so RTP exports have something to serialize.
    fn add_rtp_stream(app: &App) {
        let mut data = vec![
            0x80, 0x00, // V=2, PT=0 (PCMU)
            0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // timestamp
            0x12, 0x34, 0x56, 0x78, // ssrc
        ];
        data.extend_from_slice(&[0xAA; 160]); // payload
        let rtp = crate::rtp::parser::parse_rtp_header(&data).expect("rtp header");
        let parsed = ParsedPacket {
            timestamp: base_ts(),
            src_addr: addr_a(),
            dst_addr: addr_b(),
            src_port: 20000,
            dst_port: 30000,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(data),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        app.stream_store
            .write()
            .process_rtp(&parsed, &rtp, base_ts());
    }

    /// Path to `name` inside a fresh (leaked) temp directory, so the
    /// destination stays valid for the whole test.
    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = tempfile::tempdir().expect("tempdir");
        // leak the dir so the path stays valid for the test duration
        let p = dir.keep();
        p.join(name)
    }

    // ── Happy-path: each format writes a file ────────────────────────

    /// pcap export reports success and creates the file.
    #[test]
    fn pcap_saves_packets() {
        let app = app_with_dialogs();
        let p = tmp_path("out.pcap");
        let msg = save_to_pcap_path(&app, p.to_str().unwrap(), false);
        assert!(msg.contains("Saved"), "got: {msg}");
        assert!(p.exists());
    }

    /// pcapng export reports the pcapng format label and creates the file.
    #[test]
    fn pcapng_saves_packets() {
        let app = app_with_dialogs();
        let p = tmp_path("out.pcapng");
        let msg = save_to_pcap_path(&app, p.to_str().unwrap(), true);
        assert!(msg.contains("pcapng"), "got: {msg}");
        assert!(p.exists());
    }

    /// txt export writes per-message headers and the raw INVITE text.
    #[test]
    fn txt_saves_and_content_has_message_header() {
        let app = app_with_dialogs();
        let p = tmp_path("out.txt");
        let msg = save_to_txt_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("# Message 1"));
        assert!(content.contains("INVITE"));
    }

    /// JSON export round-trips: the file parses back as a 2-dialog array.
    #[test]
    fn json_saves_and_parses_back() {
        let app = app_with_dialogs();
        let p = tmp_path("out.json");
        let msg = save_to_json_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 2);
    }

    /// Checking one row limits the JSON export to that dialog only.
    #[test]
    fn json_save_honors_selection() {
        // sngrep parity: checking rows limits the export to the selected
        // dialogs (the [*] checkbox group). Here only call-1 is checked.
        let mut app = app_with_dialogs();
        app.call_list.move_to_top(); // cursor on row 0 (call-1)
        app.call_list.toggle_selection("call-1@test"); // check it
        let p = tmp_path("sel.json");
        let msg = save_to_json_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            v.as_array().unwrap().len(),
            1,
            "only the selected dialog should be exported"
        );
        assert!(content.contains("call-1@test"), "selected dialog present");
        assert!(
            !content.contains("call-2@test"),
            "unselected dialog must be excluded"
        );
    }

    /// With no checkboxes set, the export includes every dialog.
    #[test]
    fn save_with_no_selection_exports_all() {
        // No checkboxes set -> export everything (current default behavior).
        let app = app_with_dialogs();
        let p = tmp_path("all.json");
        save_to_json_path(&app, p.to_str().unwrap());
        let content = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2, "all dialogs exported");
    }

    /// NDJSON export writes exactly one valid JSON object per line.
    #[test]
    fn ndjson_saves_one_object_per_line() {
        let app = app_with_dialogs();
        let p = tmp_path("out.ndjson");
        let msg = save_to_ndjson_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let _: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        }
    }

    /// CSV export pins the exact header column set plus one row per dialog.
    #[test]
    fn csv_saves_with_header() {
        let app = app_with_dialogs();
        let p = tmp_path("out.csv");
        let msg = save_to_csv_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        // M2/T2.5: pin the exact column set, not just a prefix.
        let header = content.lines().next().unwrap();
        assert_eq!(
            header,
            "call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,setup_ms,created_at"
        );
        // header + 2 dialog rows
        assert_eq!(content.lines().count(), 3);
    }

    /// Markdown export writes the summary title and per-dialog sections.
    #[test]
    fn markdown_saves_with_summary() {
        let app = app_with_dialogs();
        let p = tmp_path("out.md");
        let msg = save_to_markdown_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("# Call Summary"));
        assert!(content.contains("## Dialog:"));
    }

    /// Mermaid export produces a real sequenceDiagram with participants
    /// and the embedded renderer, not just any file.
    #[test]
    fn mermaid_saves_diagram() {
        let app = app_with_dialogs();
        let p = tmp_path("out.html");
        let msg = save_to_mermaid_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved Mermaid"), "got: {msg}");
        assert!(p.exists());
        // M2/T2.10: validate the CONTENT, not just that a file was written —
        // a valid Mermaid `sequenceDiagram` with participants and the renderer.
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(
            content.contains("sequenceDiagram"),
            "missing mermaid sequenceDiagram keyword"
        );
        assert!(content.contains("participant "), "missing participants");
        assert!(
            content.contains("class=\"mermaid\""),
            "missing mermaid render container"
        );
        assert!(
            content.contains("mermaid.min.js"),
            "missing mermaid renderer script"
        );
    }

    /// SIPp export writes a well-formed scenario element pair.
    #[test]
    fn sipp_saves_scenario_xml() {
        let app = app_with_dialogs();
        let p = tmp_path("out.xml");
        let msg = save_to_sipp_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved SIPp"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(content.contains("<scenario"));
        assert!(content.contains("</scenario>"));
    }

    /// SIPp export substitutes only the structural host:port of the
    /// request-URI: a user part that happens to contain the destination
    /// port digits (user "15080", port 5080) must survive unchanged.
    #[test]
    fn sipp_port_substitution_leaves_user_part_intact() {
        let raw = raw_sip(
            "INVITE sip:15080@10.0.0.2:5080 SIP/2.0",
            &[
                "From: \"a\" <sip:a@example.com>;tag=t1",
                "To: \"b\" <sip:15080@example.com>",
                "Call-ID: call-port@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        let invite = parse_sip(
            &raw,
            base_ts(),
            addr_a(),
            addr_b(),
            5060,
            5080,
            TransportProto::Udp,
        )
        .expect("parse INVITE");
        let app = App::with_processed_messages(vec![invite]);

        let p = tmp_path("port.xml");
        let msg = save_to_sipp_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved SIPp"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        assert!(
            content.contains("INVITE sip:15080@[remote_ip]:[remote_port] SIP/2.0"),
            "request-URI corrupted by port substitution:\n{content}"
        );
    }

    /// RTP JSON export serializes the injected stream with its codec.
    #[test]
    fn rtp_json_saves_streams() {
        let app = app_with_dialogs();
        add_rtp_stream(&app);
        let p = tmp_path("rtp.json");
        let msg = save_to_rtp_json_path(&app, p.to_str().unwrap());
        assert!(msg.contains("Saved 1 RTP"), "got: {msg}");
        let content = std::fs::read_to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["codec"], "PCMU");
    }

    // ── Empty-store paths ────────────────────────────────────────────

    /// Message-based exports on an empty store report "No messages".
    #[test]
    fn empty_store_messages() {
        let app = App::new_test();
        assert_eq!(
            save_to_pcap_path(&app, "/tmp/x.pcap", false),
            "No messages to save"
        );
        assert_eq!(save_to_txt_path(&app, "/tmp/x.txt"), "No messages to save");
        assert_eq!(
            save_to_mermaid_path(&app, "/tmp/x.html"),
            "No messages to export"
        );
    }

    /// Dialog-based exports on an empty store report "No dialogs".
    #[test]
    fn empty_store_dialogs() {
        let app = App::new_test();
        assert_eq!(save_to_json_path(&app, "/tmp/x.json"), "No dialogs to save");
        assert_eq!(
            save_to_ndjson_path(&app, "/tmp/x.ndjson"),
            "No dialogs to save"
        );
        assert_eq!(save_to_csv_path(&app, "/tmp/x.csv"), "No dialogs to save");
        assert_eq!(
            save_to_markdown_path(&app, "/tmp/x.md"),
            "No dialogs to save"
        );
        assert_eq!(save_to_sipp_path(&app, "/tmp/x.xml"), "No dialog to export");
    }

    /// RTP/WAV exports with no captured streams report "No RTP streams".
    #[test]
    fn empty_store_rtp_and_wav() {
        let app = App::new_test();
        assert_eq!(
            save_to_rtp_json_path(&app, "/tmp/x.json"),
            "No RTP streams to save"
        );
        // No call flow + no selected dialog -> "No RTP streams captured"
        let msg = save_to_wav_path(&app, "/tmp/x.wav");
        assert!(msg.contains("No RTP streams"), "got: {msg}");
    }

    /// Under a sort that reorders the call list, the WAV export must target
    /// the DISPLAYED selected dialog, not the dialog at the same index in raw
    /// store order.
    #[test]
    fn wav_export_follows_displayed_selection_not_store_order() {
        // Store order: call-1, call-2. Default selection is row 0.
        let mut app = app_with_dialogs();
        add_rtp_stream(&app);
        // Associate the one stream with call-2 (its media endpoint is
        // 10.0.0.2:30000, matching add_rtp_stream's destination).
        app.stream_store
            .write()
            .link_to_dialog(addr_b(), 30000, "call-2@test");

        // Descending sort by index reverses the display to [call-2, call-1],
        // so displayed row 0 is call-2 — the dialog that HAS the stream.
        app.call_list
            .set_sort(crate::tui::call_list::SortColumn::Index);
        assert!(
            !app.call_list.sort_ascending(),
            "sort should now be descending"
        );

        let msg = save_to_wav_path(&app, tmp_path("out.wav").to_str().unwrap());
        // Fixed: selects displayed row 0 = call-2 (has a stream) → export runs.
        // Buggy: selects raw row 0 = call-1 (no stream) → "No RTP streams...".
        assert!(
            !msg.contains("No RTP streams"),
            "WAV export must target the displayed selection (call-2, which has \
             a stream), not raw store order; got: {msg}"
        );
    }

    // ── Error paths: unwritable destinations ─────────────────────────

    /// A path whose parent directory does not exist forces std::fs::write
    /// (and the pcap writer) to fail.
    const BAD_PATH: &str = "/nonexistent_dir_xyz/sub/out";

    /// txt save into a missing directory surfaces "Save failed".
    #[test]
    fn txt_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_txt_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// JSON save into a missing directory surfaces "Save failed".
    #[test]
    fn json_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_json_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// NDJSON save into a missing directory surfaces "Save failed".
    #[test]
    fn ndjson_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_ndjson_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// CSV save into a missing directory surfaces "Save failed".
    #[test]
    fn csv_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_csv_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// Markdown save into a missing directory surfaces "Save failed".
    #[test]
    fn markdown_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_markdown_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// Mermaid save into a missing directory surfaces "Save failed".
    #[test]
    fn mermaid_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_mermaid_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// SIPp save into a missing directory surfaces "Save failed".
    #[test]
    fn sipp_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_sipp_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    /// pcap save into a missing directory surfaces a save or write error.
    #[test]
    fn pcap_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_pcap_path(&app, BAD_PATH, false);
        assert!(
            msg.starts_with("Save failed") || msg.starts_with("Write error"),
            "got: {msg}"
        );
    }

    /// RTP JSON save into a missing directory surfaces "Save failed".
    #[test]
    fn rtp_json_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        add_rtp_stream(&app);
        let msg = save_to_rtp_json_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    // ── Pure helpers ─────────────────────────────────────────────────

    /// csv_escape leaves plain text alone and quote-wraps commas,
    /// embedded quotes (doubled), and newlines.
    #[test]
    fn csv_escape_quotes_special_chars() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("he said \"hi\""), "\"he said \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    /// Dialog states map to their expected export display strings.
    #[test]
    fn format_dialog_state_maps_variants() {
        use crate::sip::dialog::DialogState;
        assert_eq!(format_dialog_state(&DialogState::InCall), "InCall");
        assert_eq!(format_dialog_state(&DialogState::Completed), "Completed");
        assert_eq!(format_dialog_state(&DialogState::Failed), "Failed");
        assert_eq!(format_dialog_state(&DialogState::Terminated), "Terminated");
    }
}
