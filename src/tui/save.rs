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

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::{ParsedPacket, TransportProto};
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

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

    fn app_with_dialogs() -> App {
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_ok("call-1@test", t0 + TimeDelta::seconds(1)),
            make_invite("call-2@test", "1003", "1004", t0 + TimeDelta::seconds(5)),
            make_ok("call-2@test", t0 + TimeDelta::seconds(6)),
        ])
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
        };
        app.stream_store
            .write()
            .process_rtp(&parsed, &rtp, base_ts());
    }

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let dir = tempfile::tempdir().expect("tempdir");
        // leak the dir so the path stays valid for the test duration
        let p = dir.keep();
        p.join(name)
    }

    // ── Happy-path: each format writes a file ────────────────────────

    #[test]
    fn pcap_saves_packets() {
        let app = app_with_dialogs();
        let p = tmp_path("out.pcap");
        let msg = save_to_pcap_path(&app, p.to_str().unwrap(), false);
        assert!(msg.contains("Saved"), "got: {msg}");
        assert!(p.exists());
    }

    #[test]
    fn pcapng_saves_packets() {
        let app = app_with_dialogs();
        let p = tmp_path("out.pcapng");
        let msg = save_to_pcap_path(&app, p.to_str().unwrap(), true);
        assert!(msg.contains("pcapng"), "got: {msg}");
        assert!(p.exists());
    }

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

    // ── Error paths: unwritable destinations ─────────────────────────

    /// A path whose parent directory does not exist forces std::fs::write
    /// (and the pcap writer) to fail.
    const BAD_PATH: &str = "/nonexistent_dir_xyz/sub/out";

    #[test]
    fn txt_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_txt_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn json_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_json_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn ndjson_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_ndjson_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn csv_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_csv_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn markdown_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_markdown_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn mermaid_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_mermaid_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn sipp_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_sipp_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    #[test]
    fn pcap_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        let msg = save_to_pcap_path(&app, BAD_PATH, false);
        assert!(
            msg.starts_with("Save failed") || msg.starts_with("Write error"),
            "got: {msg}"
        );
    }

    #[test]
    fn rtp_json_write_failure_surfaces_error() {
        let app = app_with_dialogs();
        add_rtp_stream(&app);
        let msg = save_to_rtp_json_path(&app, BAD_PATH);
        assert!(msg.starts_with("Save failed"), "got: {msg}");
    }

    // ── Pure helpers ─────────────────────────────────────────────────

    #[test]
    fn csv_escape_quotes_special_chars() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("he said \"hi\""), "\"he said \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn format_dialog_state_maps_variants() {
        use crate::sip::dialog::DialogState;
        assert_eq!(format_dialog_state(&DialogState::InCall), "InCall");
        assert_eq!(format_dialog_state(&DialogState::Completed), "Completed");
        assert_eq!(format_dialog_state(&DialogState::Failed), "Failed");
        assert_eq!(format_dialog_state(&DialogState::Terminated), "Terminated");
    }
}
