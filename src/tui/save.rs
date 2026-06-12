//! Save/export: pcap, txt, mermaid, json, ndjson, csv, markdown,
//! wav, sipp scenario, rtp-json.

use super::*;

// ── Save functionality ─────────────────────────────────────────────

/// Save all dialogs to a pcap or pcap-ng file.
pub(super) fn save_to_pcap_path(app: &App, path_str: &str, pcapng: bool) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect all messages across all dialogs
    let messages: Vec<&crate::sip::SipMessage> =
        store.iter().flat_map(|d| d.messages.iter()).collect();

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
pub(super) fn save_to_txt_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    let messages: Vec<&crate::sip::SipMessage> =
        store.iter().flat_map(|d| d.messages.iter()).collect();

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
pub(super) fn save_to_mermaid_path(app: &App, path_str: &str) -> String {
    let path = std::path::PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Collect messages based on current view
    let messages: Vec<crate::sip::SipMessage> =
        if let View::CallFlow(ref call_id) = app.current_view {
            // In call flow: export just this dialog (+ correlated if extended)
            if app.extended_flow {
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
            // In call list: export all dialogs
            store.iter().flat_map(|d| d.messages.clone()).collect()
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

/// Format a [`DialogState`] as a display string for export.
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
pub(super) fn save_to_json_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

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

            let duration_ms = d.timing.bye_sent.and_then(|bye| {
                d.timing.answered_at.map(|ans| (bye - ans).num_milliseconds())
            });
            let timing = serde_json::json!({
                "pdd_ms": d.timing.pdd_ms(),
                "setup_ms": d.timing.setup_ms(),
                "duration_ms": duration_ms,
            });

            serde_json::json!({
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
            })
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
pub(super) fn save_to_ndjson_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

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
pub(super) fn save_to_csv_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

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
pub(super) fn save_to_markdown_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();
    let dialogs: Vec<&crate::sip::dialog::SipDialog> = store.iter().collect();

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
/// if no dialog is in focus) and exports them via [`crate::rtp::audio_export`].
pub(super) fn save_to_wav_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);

    // Determine the current dialog's Call-ID (if viewing a call flow)
    let call_id = match &app.current_view {
        View::CallFlow(cid) => Some(cid.clone()),
        _ => {
            // Try to get the selected dialog from the call list
            let store = app.dialog_store.read();
            let dialogs: Vec<_> = store.iter().collect();
            let idx = app.call_list.selected();
            dialogs.get(idx).map(|d| d.call_id.clone())
        }
    };

    let stream_store = app.stream_store.read();

    // Collect streams: filter by dialog if we have one, otherwise use all
    let streams: Vec<&crate::rtp::stream::RtpStream> = if let Some(ref cid) = call_id {
        stream_store
            .iter()
            .filter(|s| s.associated_dialog.as_deref() == Some(cid.as_str()))
            .collect()
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

/// Export a SIPp scenario XML from the current dialog's call flow.
pub(super) fn save_to_sipp_path(app: &App, path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    let store = app.dialog_store.read();

    // Pick dialog: current call flow view or first dialog
    let dialog = if let View::CallFlow(ref call_id) = app.current_view {
        store.get(call_id)
    } else {
        store.iter().next()
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
                let ruri_sipp = ruri
                    .replace(&m.dst_addr.to_string(), "[remote_ip]")
                    .replace(&m.dst_port.to_string(), "[remote_port]");

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
            let total = s.packet_count + s.lost_packets;
            let loss_pct = if total > 0 {
                (s.lost_packets as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let duration_secs = s
                .last_seen
                .signed_duration_since(s.first_seen)
                .num_milliseconds() as f64
                / 1000.0;

            // Simplified E-model R-factor → MOS estimate
            // R = 93.2 - loss% * 2.5 - jitter_ms * 0.1
            let r_factor = (93.2 - loss_pct * 2.5 - s.jitter * 0.1).clamp(0.0, 100.0);
            let mos = if r_factor < 6.5 {
                1.0
            } else {
                1.0 + 0.035 * r_factor + r_factor * (r_factor - 60.0) * (100.0 - r_factor) * 7e-6
            };
            let mos = (mos * 10.0).round() / 10.0; // Round to 1 decimal

            serde_json::json!({
                "ssrc": format!("0x{:08x}", s.key.ssrc),
                "src": s.key.src.to_string(),
                "dst": s.key.dst.to_string(),
                "codec": s.codec.as_deref().unwrap_or("unknown"),
                "packets": s.packet_count,
                "jitter_ms": (s.jitter * 10.0).round() / 10.0,
                "loss_pct": (loss_pct * 10.0).round() / 10.0,
                "mos": mos,
                "duration_secs": (duration_secs * 10.0).round() / 10.0,
                "cn_frames": s.cn_frames,
                "silence_periods": s.silence_periods.len(),
            })
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
