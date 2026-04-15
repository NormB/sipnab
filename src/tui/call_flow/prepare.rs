//! Data preparation for call flow ladder diagrams.
//!
//! Converts raw SIP messages into `FormattedMessage` structs with all
//! display options applied (SDP, timestamp mode, color mode, etc.).

use std::collections::{HashMap, HashSet};

use ratatui::style::{Color, Modifier, Style};

use crate::sip::SipMessage;
use crate::sip::sdp::{self, SdpDirection};

use crate::tui::ColorMode;
use crate::tui::SdpDisplayMode;
use crate::tui::TimestampMode;
use crate::tui::Theme;

use super::FlowDisplayOptions;
use super::arrows::truncate;
use super::{FormattedMessage, Participant, SelectionState, TS_COL_WIDTH};

/// Compute a color-coded style for a delta timestamp based on its magnitude.
///
/// - Green: <100ms (fast / normal)
/// - Yellow: 100ms-1s (moderate delay)
/// - Red: 1s-5s (slow)
/// - Bold red: >5s (very slow / timeout risk)
pub fn delta_style(delta_ms: i64, theme: &Theme) -> Style {
    if delta_ms < 100 {
        Style::default().fg(theme.good)
    } else if delta_ms < 1000 {
        Style::default().fg(theme.warning)
    } else if delta_ms < 5000 {
        Style::default().fg(theme.bad)
    } else {
        Style::default().fg(theme.bad).add_modifier(Modifier::BOLD)
    }
}

/// Prepare formatted messages from a dialog's SIP messages.
///
/// Applies all display modes (SDP, timestamp, color, RTP) and returns
/// a list of `Participant`s and `FormattedMessage`s.
pub fn prepare_messages(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    opts: &FlowDisplayOptions<'_>,
    fold_expanded: &HashSet<usize>,
) -> (Vec<Participant>, Vec<FormattedMessage>) {
    let sdp_mode = opts.sdp_mode;
    let ts_mode = opts.ts_mode;
    let color_mode = opts.color_mode;
    let show_rtp = opts.show_rtp;
    let selected_msg = opts.selected_msg;
    let theme = opts.theme;
    if messages.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Discover all unique endpoints
    let mut endpoint_addrs: Vec<String> = Vec::new();
    for msg in messages {
        let src = format!("{}:{}", msg.src_addr, msg.src_port);
        let dst = format!("{}:{}", msg.dst_addr, msg.dst_port);
        if !endpoint_addrs.contains(&src) {
            endpoint_addrs.push(src);
        }
        if !endpoint_addrs.contains(&dst) {
            endpoint_addrs.push(dst);
        }
    }
    // Cap at 6 to prevent layout overflow
    if endpoint_addrs.len() > 6 {
        endpoint_addrs.truncate(6);
    }

    let participants: Vec<Participant> = endpoint_addrs
        .iter()
        .map(|addr| Participant {
            addr: addr.clone(),
            label: truncate(addr, 20),
        })
        .collect();

    let ts_width = TS_COL_WIDTH;

    let cid_colors = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    // Swimlane-aware selection: match on endpoint pair rather than Call-ID
    let sel_endpoints: Option<(String, String)> = selected_msg.and_then(|idx| {
        messages.get(idx).map(|m| {
            (
                format!("{}:{}", m.src_addr, m.src_port),
                format!("{}:{}", m.dst_addr, m.dst_port),
            )
        })
    });

    let mut pdd_done = false;
    let mut in_call = false;
    let mut pending_rtp_codec: Option<String> = None;
    let mut deferred_rtp_bar: Option<(chrono::DateTime<chrono::Utc>, String)> = None;
    let mut result = Vec::with_capacity(messages.len());
    let mut prev_ts = first_ts;
    let mut fmt_idx: usize = 0; // running index in the formatted (non-spacer) output

    for (mi, msg) in messages.iter().enumerate() {
        let _ = mi; // raw message index — not used for selection
        let (timestamp, timestamp_style) = match ts_mode {
            TimestampMode::Absolute => {
                let ts_str = format!(
                    "{:<width$}",
                    msg.timestamp.format("%H:%M:%S%.3f"),
                    width = ts_width
                );
                (ts_str, Style::default().fg(theme.muted))
            }
            TimestampMode::DeltaPrev => {
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let ts_str = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (ts_str, sty)
            }
            TimestampMode::DeltaFirst => {
                let d = msg
                    .timestamp
                    .signed_duration_since(first_ts)
                    .num_milliseconds();
                let ts_str = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                (ts_str, sty)
            }
            TimestampMode::Scaled => {
                let d = msg
                    .timestamp
                    .signed_duration_since(prev_ts)
                    .num_milliseconds();
                let ts_str = format!(
                    "{:>width$}",
                    format!("+{:.3}s", d as f64 / 1000.0),
                    width = ts_width - 1
                ) + " ";
                let sty = delta_style(d, theme);
                prev_ts = msg.timestamp;
                (ts_str, sty)
            }
        };

        let label = format_message_label(msg);

        let sty = match color_mode {
            ColorMode::Method => message_style(msg, theme),
            ColorMode::CallId => {
                let ci = msg.call_id().unwrap_or("");
                let i =
                    ci.bytes().fold(0usize, |a, b| a.wrapping_add(b as usize)) % cid_colors.len();
                Style::default().fg(cid_colors[i])
            }
            ColorMode::CSeq => {
                let cn = msg.cseq().map(|(n, _)| n).unwrap_or(0);
                Style::default().fg(cid_colors[(cn as usize) % cid_colors.len()])
            }
        };

        let sel = selected_msg == Some(fmt_idx);
        let selection_state = if sel {
            SelectionState::Selected
        } else if let Some((ref sel_src, ref sel_dst)) = sel_endpoints {
            let msg_src = format!("{}:{}", msg.src_addr, msg.src_port);
            let msg_dst = format!("{}:{}", msg.dst_addr, msg.dst_port);
            let same_leg = (msg_src == *sel_src && msg_dst == *sel_dst)
                || (msg_src == *sel_dst && msg_dst == *sel_src);
            if same_leg {
                SelectionState::Related
            } else {
                SelectionState::Normal
            }
        } else {
            SelectionState::Normal
        };

        let style = sty;

        let src_addr = format!("{}:{}", msg.src_addr, msg.src_port);
        let dst_addr = format!("{}:{}", msg.dst_addr, msg.dst_port);
        let src_col = endpoint_addrs
            .iter()
            .position(|a| a == &src_addr)
            .unwrap_or(0);
        let dst_col = endpoint_addrs
            .iter()
            .position(|a| a == &dst_addr)
            .unwrap_or(1.min(endpoint_addrs.len().saturating_sub(1)));

        let mut pdd_note = None;
        if !pdd_done
            && let Some(p) = pdd_ms
            && !msg.is_request
            && msg.status_code == Some(180)
        {
            pdd_note = Some(format!("  PDD: {p}ms"));
            pdd_done = true;
        }

        let mut extra_lines = Vec::new();

        // SDP info lines
        if sdp_mode != SdpDisplayMode::None
            && let Some(ss) = msg.sdp()
        {
            let ind = " ".repeat(ts_width + 1);
            match sdp_mode {
                SdpDisplayMode::Summary => {
                    let c = format_sdp_codecs(&ss);
                    if !c.is_empty() {
                        extra_lines.push((
                            format!("{ind} Codecs: {c}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        ));
                    }
                }
                SdpDisplayMode::Full => {
                    let bt = String::from_utf8_lossy(&msg.body);
                    for sl in bt.lines() {
                        extra_lines.push((
                            format!("{ind}  {sl}"),
                            Style::default()
                                .fg(theme.muted)
                                .add_modifier(Modifier::ITALIC),
                        ));
                    }
                }
                SdpDisplayMode::None => {}
            }
        }

        // RTP marker: placed on ACK to INVITE (media starts after ACK, not on 200 OK)
        if show_rtp {
            // Track the codec from 200 OK SDP for display on the ACK bar
            let is_invite_200 = !msg.is_request
                && msg.status_code == Some(200)
                && msg.cseq().is_some_and(|(_, method)| method == "INVITE");
            if is_invite_200 && !in_call {
                pending_rtp_codec = msg.sdp().and_then(|ss| {
                    let codecs = format_sdp_codecs(&ss);
                    if codecs.is_empty() { None } else { Some(codecs) }
                });
            }

            // Place RTP bar after ACK (media starts flowing after ACK completes handshake)
            // Created as a deferred entry — pushed as a separate FormattedMessage
            // AFTER the ACK so it's independently selectable with j/k navigation.
            let is_invite_ack = msg.is_request
                && msg.method.as_ref() == Some(&crate::sip::SipMethod::Ack)
                && !in_call;
            if is_invite_ack {
                in_call = true;
                let rtp_label = if let Some(ref codec) = pending_rtp_codec {
                    format!("\u{2500}\u{2500} RTP \u{00B7} {codec} \u{00B7} active \u{2500}\u{2500}")
                } else {
                    "\u{2500}\u{2500} RTP \u{00B7} active \u{2500}\u{2500}".to_string()
                };
                deferred_rtp_bar = Some((msg.timestamp, rtp_label));
                pending_rtp_codec = None;
            }
            if msg.is_request && msg.method.as_ref() == Some(&crate::sip::SipMethod::Bye) && in_call {
                in_call = false;
            }
        }

        result.push(FormattedMessage {
            timestamp,
            timestamp_style,
            label,
            style,
            src_col,
            dst_col,
            pdd_note,
            extra_lines,
            selected: sel,
            call_id: msg.call_id().unwrap_or("").to_string(),
            selection_state,
            is_response: !msg.is_request,
            raw_timestamp: msg.timestamp,
            folded_count: 0,
            fold_label: None,
            is_spacer: false,
            sdp_badge: None,
            is_retransmission: msg.is_retransmission,
            is_rtp_bar: false,
        });
        fmt_idx += 1;

        // Push the deferred RTP bar as a separate selectable entry
        if let Some((rtp_ts, rtp_label)) = deferred_rtp_bar.take() {
            let rtp_sel = selected_msg == Some(fmt_idx);
            // Format timestamp using the same mode as all other messages
            let (rtp_timestamp, rtp_ts_style) = match ts_mode {
                TimestampMode::Absolute => {
                    let s = format!("{:<width$}", rtp_ts.format("%H:%M:%S%.3f"), width = ts_width);
                    (s, Style::default().fg(theme.accent))
                }
                TimestampMode::DeltaPrev => {
                    let d = rtp_ts.signed_duration_since(prev_ts).num_milliseconds();
                    let s = format!("{:>width$}", format!("+{:.3}s", d as f64 / 1000.0), width = ts_width - 1) + " ";
                    prev_ts = rtp_ts;
                    (s, delta_style(d, theme))
                }
                TimestampMode::DeltaFirst => {
                    let d = rtp_ts.signed_duration_since(first_ts).num_milliseconds();
                    let s = format!("{:>width$}", format!("+{:.3}s", d as f64 / 1000.0), width = ts_width - 1) + " ";
                    (s, delta_style(d, theme))
                }
                TimestampMode::Scaled => {
                    let d = rtp_ts.signed_duration_since(prev_ts).num_milliseconds();
                    let s = format!("{:>width$}", format!("+{:.3}s", d as f64 / 1000.0), width = ts_width - 1) + " ";
                    prev_ts = rtp_ts;
                    (s, delta_style(d, theme))
                }
            };
            result.push(FormattedMessage {
                timestamp: rtp_timestamp,
                timestamp_style: rtp_ts_style,
                label: rtp_label,
                style: Style::default().fg(theme.accent),
                src_col: 0,
                dst_col: 0,
                pdd_note: None,
                extra_lines: vec![],
                selected: rtp_sel,
                call_id: msg.call_id().unwrap_or("").to_string(),
                selection_state: if rtp_sel { SelectionState::Selected } else { SelectionState::Normal },
                is_response: false,
                raw_timestamp: rtp_ts,
                folded_count: 0,
                fold_label: None,
                is_spacer: false,
                sdp_badge: None,
                is_retransmission: false,
                is_rtp_bar: true,
            });
            fmt_idx += 1;
        }
    }

    // ── SDP delta badges (Feature 4) ──────────────────────────────
    // Track previous SDP state per call_id to compute change badges.
    {
        let mut last_codecs: HashMap<String, Vec<String>> = HashMap::new();
        let mut last_direction: HashMap<String, SdpDirection> = HashMap::new();
        for (ri, msg) in messages.iter().enumerate() {
            let cid = msg.call_id().unwrap_or("").to_string();
            if let Some(ss) = msg.sdp() {
                let codecs = extract_codec_list(&ss);
                let dir = ss.media.first().map(|m| m.direction.clone()).unwrap_or(SdpDirection::SendRecv);
                if let Some(prev_codecs) = last_codecs.get(&cid) {
                    let mut badge_parts: Vec<String> = Vec::new();
                    // Codec additions
                    for c in &codecs {
                        if !prev_codecs.contains(c) {
                            badge_parts.push(format!("+{c}"));
                        }
                    }
                    // Codec removals (use minus sign U+2212)
                    for c in prev_codecs {
                        if !codecs.contains(c) {
                            badge_parts.push(format!("\u{2212}{c}"));
                        }
                    }
                    // Direction changes
                    if let Some(prev_dir) = last_direction.get(&cid) {
                        match (&dir, prev_dir) {
                            (SdpDirection::SendOnly | SdpDirection::Inactive, SdpDirection::SendRecv) => {
                                badge_parts.push("HOLD".to_string());
                            }
                            (SdpDirection::SendRecv, SdpDirection::SendOnly | SdpDirection::Inactive) => {
                                badge_parts.push("UNHOLD".to_string());
                            }
                            _ => {}
                        }
                    }
                    if !badge_parts.is_empty()
                        && let Some(fm) = result.get_mut(ri)
                    {
                        fm.sdp_badge = Some(badge_parts.join(" "));
                    }
                }
                last_codecs.insert(cid.clone(), codecs);
                last_direction.insert(cid, dir);
            }
        }
    }

    // ── Time-proportional spacer insertion (Feature 6) ─────────────
    if ts_mode == TimestampMode::Scaled && result.len() >= 2 {
        let spacer_style = Style::default().fg(theme.muted).add_modifier(Modifier::DIM);
        let mut scaled = Vec::with_capacity(result.len() * 2);
        let mut drain = result.into_iter();
        if let Some(first) = drain.next() {
            let mut prev_ts_raw = first.raw_timestamp;
            scaled.push(first);
            for msg in drain {
                let delta_ms = msg
                    .raw_timestamp
                    .signed_duration_since(prev_ts_raw)
                    .num_milliseconds()
                    .unsigned_abs();
                // log2 scale, capped at 8 spacer rows
                let gap = if delta_ms > 0 {
                    ((delta_ms as f64 / 50.0).ln().max(0.0) / 0.693).min(8.0) as usize
                } else {
                    0
                };
                for si in 0..gap {
                    let spacer_ts = if si == 0 {
                        format!(
                            "{:>width$}",
                            format!("({:.0}ms)", delta_ms as f64),
                            width = ts_width - 1,
                        ) + " "
                    } else {
                        " ".repeat(ts_width)
                    };
                    scaled.push(FormattedMessage {
                        timestamp: spacer_ts,
                        timestamp_style: spacer_style,
                        label: String::new(),
                        style: spacer_style,
                        src_col: 0,
                        dst_col: 0,
                        pdd_note: None,
                        extra_lines: Vec::new(),
                        selected: false,
                        call_id: String::new(),
                        selection_state: SelectionState::Normal,
                        is_response: false,
                        raw_timestamp: prev_ts_raw,
                        folded_count: 0,
                        fold_label: None,
                        is_spacer: true,
                        sdp_badge: None,
                        is_retransmission: false,
                        is_rtp_bar: false,
                    });
                }
                prev_ts_raw = msg.raw_timestamp;
                scaled.push(msg);
            }
        }
        result = scaled;
    }

    // ── Retransmit folding + Auth collapse (Feature 3) ────────────
    let result = fold_messages(messages, result, fold_expanded);

    (participants, result)
}

/// Extract a list of codec names from an SDP session.
fn extract_codec_list(session: &sdp::SdpSession) -> Vec<String> {
    let mut codecs = Vec::new();
    for media in &session.media {
        for rm in &media.rtpmap {
            codecs.push(rm.encoding.clone());
        }
        if media.rtpmap.is_empty() {
            for f in &media.formats {
                let name = match f.as_str() {
                    "0" => "PCMU",
                    "8" => "PCMA",
                    "9" => "G722",
                    "18" => "G729",
                    "4" => "G723",
                    "3" => "GSM",
                    "101" => "telephone-event",
                    o => o,
                };
                codecs.push(name.to_string());
            }
        }
    }
    codecs
}

/// Fold retransmissions and auth retry sequences in the formatted message list.
///
/// - **Retransmit folding**: consecutive messages with `is_retransmission == true`
///   are collapsed into the original message with a count badge, unless the fold
///   is expanded.
/// - **Auth collapse**: sequences like `request(N) -> 401/407(N) -> ACK(N) -> request(N+1 with Auth)`
///   are collapsed into a single row, unless expanded.
fn fold_messages(
    raw_msgs: &[SipMessage],
    formatted: Vec<FormattedMessage>,
    fold_expanded: &HashSet<usize>,
) -> Vec<FormattedMessage> {
    if formatted.is_empty() {
        return formatted;
    }

    let mut result: Vec<FormattedMessage> = Vec::with_capacity(formatted.len());
    // Own the elements so we can move them selectively
    let mut source: Vec<Option<FormattedMessage>> = formatted.into_iter().map(Some).collect();
    let mut i = 0;

    while i < source.len() {
        // --- Auth collapse detection ---
        if !fold_expanded.contains(&i)
            && let Some(fold_len) = detect_auth_sequence(raw_msgs, i)
        {
            // Take the first message as the fold header
            if let Some(mut fm) = source[i].take() {
                fm.folded_count = fold_len;
                fm.fold_label = Some(format!(
                    "{} msgs folded (auth retry) - press e to expand",
                    fold_len
                ));
                fm.label = format!("{} (auth retry)", fm.label);
                result.push(fm);
            }
            // Skip the folded messages
            for j in (i + 1)..(i + fold_len).min(source.len()) {
                source[j].take();
            }
            i += fold_len;
            continue;
        }

        // --- Retransmit folding ---
        if !fold_expanded.contains(&i) && i < raw_msgs.len() && raw_msgs[i].is_retransmission {
            // Fold retransmission into the previous non-retransmission message
            if let Some(_fm) = source[i].take() {
                if let Some(prev) = result.last_mut() {
                    prev.folded_count += 1;
                    prev.fold_label = Some(format!(
                        "(+{} retx) - press e to expand",
                        prev.folded_count
                    ));
                } else {
                    // No previous message to fold into — re-insert and emit
                    source[i] = Some(_fm);
                    if let Some(fm) = source[i].take() {
                        result.push(fm);
                    }
                }
            }
            i += 1;
            continue;
        }

        // Not folded — emit normally
        if let Some(fm) = source[i].take() {
            result.push(fm);
        }
        i += 1;
    }

    result
}

/// Detect an auth retry sequence starting at index `start`.
///
/// Pattern: request(CSeq N) -> 401/407(CSeq N) -> ACK(CSeq N) -> request(same method, CSeq N+1)
/// with an Authorization or Proxy-Authorization header.
///
/// Returns the number of messages in the sequence (typically 4), or None if not detected.
fn detect_auth_sequence(messages: &[SipMessage], start: usize) -> Option<usize> {
    if start + 3 >= messages.len() {
        return None;
    }

    let msg0 = &messages[start];
    let msg1 = &messages[start + 1];
    let msg2 = &messages[start + 2];
    let msg3 = &messages[start + 3];

    // msg0: request
    if !msg0.is_request {
        return None;
    }
    let (seq0, method0) = msg0.cseq()?;

    // msg1: 401 or 407 response with same CSeq
    if msg1.is_request {
        return None;
    }
    let status = msg1.status_code?;
    if status != 401 && status != 407 {
        return None;
    }
    let (seq1, _) = msg1.cseq()?;
    if seq1 != seq0 {
        return None;
    }

    // msg2: ACK with same CSeq
    if !msg2.is_request || msg2.method.as_ref() != Some(&crate::sip::SipMethod::Ack) {
        return None;
    }
    let (seq2, _) = msg2.cseq()?;
    if seq2 != seq0 {
        return None;
    }

    // msg3: same method request with CSeq N+1 and Authorization header
    if !msg3.is_request || msg3.method.as_ref().map(|m| m.as_str()) != Some(method0) {
        return None;
    }
    let (seq3, _) = msg3.cseq()?;
    if seq3 != seq0.wrapping_add(1) {
        return None;
    }
    // Must have Authorization or Proxy-Authorization header
    if msg3.header("Authorization").is_none() && msg3.header("Proxy-Authorization").is_none() {
        return None;
    }

    Some(4)
}

/// Build a label string for a message (e.g., "INVITE (SDP)" or "200 OK").
///
/// Appends "(SDP)" when the message body contains SDP, matching sngrep style.
pub fn format_message_label(msg: &SipMessage) -> String {
    let has_sdp = msg
        .content_type()
        .is_some_and(|ct| ct.contains("application/sdp"))
        || (!msg.body.is_empty()
            && std::str::from_utf8(&msg.body)
                .ok()
                .is_some_and(|b| b.starts_with("v=")));

    let sdp_suffix = if has_sdp { " (SDP)" } else { "" };

    if msg.is_request {
        format!("{}{}", msg.method.as_ref().map(|m| m.as_str()).unwrap_or("?"), sdp_suffix)
    } else {
        let code = msg.status_code.unwrap_or(0);
        let reason = msg.reason.as_deref().unwrap_or("");
        format!("{} {}{}", code, reason, sdp_suffix)
    }
}

/// Choose a style based on message type with semantic colors.
///
/// Requests: teal for session-creating (INVITE/SUBSCRIBE), coral for teardown
/// (BYE/CANCEL), gray for acks, blue for registration/options.
/// Responses: amber for provisional, green for success, yellow for redirect,
/// orange for client error, bold red for server error.
pub fn message_style(msg: &SipMessage, theme: &Theme) -> Style {
    if msg.is_request {
        let method = msg.method.as_ref().map(|m| m.as_str()).unwrap_or("");
        match method {
            "INVITE" | "SUBSCRIBE" => Style::default().fg(Color::Rgb(95, 175, 175)), // Teal
            "BYE" | "CANCEL" => Style::default().fg(Color::Rgb(215, 95, 95)),         // Coral
            "ACK" | "PRACK" => Style::default().fg(theme.muted),                      // Gray
            "REGISTER" | "OPTIONS" => Style::default().fg(Color::Rgb(95, 135, 215)),  // Blue
            _ => Style::default().fg(theme.foreground),
        }
    } else {
        let code = msg.status_code.unwrap_or(0);
        match code {
            100..=199 => Style::default().fg(Color::Rgb(215, 175, 95)), // Amber (provisional)
            200..=299 => Style::default().fg(theme.good),                // Green (success)
            300..=399 => Style::default().fg(theme.warning),             // Yellow (redirect)
            400..=499 => Style::default().fg(Color::Rgb(215, 135, 0)),  // Orange (client error)
            500..=699 => Style::default().fg(theme.bad).add_modifier(Modifier::BOLD), // Red (server error)
            _ => Style::default().fg(theme.foreground),
        }
    }
}

/// Format SDP codec list from an SDP session for the summary display.
pub fn format_sdp_codecs(session: &sdp::SdpSession) -> String {
    let mut codecs = Vec::new();
    for media in &session.media {
        for rm in &media.rtpmap {
            codecs.push(rm.encoding.clone());
        }
        if media.rtpmap.is_empty() {
            for f in &media.formats {
                codecs.push(
                    match f.as_str() {
                        "0" => "PCMU",
                        "8" => "PCMA",
                        "9" => "G722",
                        "18" => "G729",
                        "4" => "G723",
                        "3" => "GSM",
                        "101" => "telephone-event",
                        o => o,
                    }
                    .to_string(),
                );
            }
        }
    }
    codecs.join(", ")
}
