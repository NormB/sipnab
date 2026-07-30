// SPDX-License-Identifier: MIT OR Apache-2.0

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
use crate::tui::Theme;
use crate::tui::TimestampMode;

use super::FlowDisplayOptions;
use super::arrows::truncate;
use super::{FormattedMessage, Participant, RtpCodecSegment, SelectionState, TS_COL_WIDTH};

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
/// a list of `Participant`s and `FormattedMessage`s. Composed of the two
/// split stages: theme-free `layout` (the expensive, cacheable part)
/// followed by `style` (cheap per-frame theming + selection).
///
/// # Arguments
/// * `messages` — the dialog's SIP messages in capture order.
/// * `first_ts` — reference timestamp for delta-first/delta-prev formatting.
/// * `pdd_ms` — post-dial delay to annotate on the first 180, if known.
/// * `opts` — full display options (split internally into layout vs style).
/// * `fold_expanded` — raw indices of fold headers the user has expanded.
///
/// # Returns
/// `(participants, formatted)`: swimlane endpoints in column order and the
/// fully styled ladder rows. Both empty when `messages` is empty.
pub fn prepare_messages(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    opts: &FlowDisplayOptions<'_>,
    fold_expanded: &HashSet<usize>,
) -> (Vec<Participant>, Vec<FormattedMessage>) {
    let (participants, rows) = layout(
        messages,
        first_ts,
        pdd_ms,
        &LayoutOptions::from(opts),
        fold_expanded,
    );
    let styled = style(&rows, &StyleOptions::from(opts));
    (participants, styled)
}

/// Theme-free inputs to `layout` — everything that shapes which rows
/// exist and their text. Anything here changing invalidates a cached
/// layout; anything in `StyleOptions` does not.
#[derive(Debug, Clone)]
pub struct LayoutOptions<'a> {
    /// How SDP bodies are shown below their message row (none/summary/full).
    pub sdp_mode: SdpDisplayMode,
    /// Timestamp column format; `Scaled` also inserts spacer rows.
    pub ts_mode: TimestampMode,
    /// Whether to insert RTP-in-flow channel bars for media segments.
    pub show_rtp: bool,
    /// Resolver mapping endpoint addresses to display names.
    pub resolver: &'a crate::names::NameResolver,
    /// How endpoint labels are displayed (raw address vs resolved name).
    pub name_mode: crate::names::NameMode,
    /// Observed RTP codec segments (authoritative "used" codec per phase).
    pub rtp_segments: &'a [RtpCodecSegment],
}

impl<'a> From<&FlowDisplayOptions<'a>> for LayoutOptions<'a> {
    /// Project the layout-affecting subset out of full display options.
    fn from(o: &FlowDisplayOptions<'a>) -> Self {
        Self {
            sdp_mode: o.sdp_mode,
            ts_mode: o.ts_mode,
            show_rtp: o.show_rtp,
            resolver: o.resolver,
            name_mode: o.name_mode,
            rtp_segments: o.rtp_segments,
        }
    }
}

/// Presentation-only inputs to `style`: theming, arrow color mode and
/// the current selection. Varying these re-styles a cached layout without
/// recomputing it.
#[derive(Debug, Clone)]
pub struct StyleOptions<'a> {
    /// What drives arrow coloring (method class, Call-ID, or CSeq rotation).
    pub color_mode: ColorMode,
    /// Index of the selected row among visible (non-spacer) rows, if any.
    pub selected_msg: Option<usize>,
    /// Color theme used for all styling decisions.
    pub theme: &'a Theme,
}

impl<'a> From<&FlowDisplayOptions<'a>> for StyleOptions<'a> {
    /// Project the presentation-only subset out of full display options.
    fn from(o: &FlowDisplayOptions<'a>) -> Self {
        Self {
            color_mode: o.color_mode,
            selected_msg: o.selected_msg,
            theme: o.theme,
        }
    }
}

/// Theme-free semantic class of a SIP message, derived once in `layout`;
/// `class_style` maps it to concrete colors in `style`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// INVITE / SUBSCRIBE (session-creating).
    SessionRequest,
    /// BYE / CANCEL (teardown).
    TeardownRequest,
    /// ACK / PRACK.
    AckRequest,
    /// REGISTER / OPTIONS.
    RegisterRequest,
    /// Any other request.
    OtherRequest,
    /// 1xx response.
    Provisional,
    /// 2xx response.
    Success,
    /// 3xx response.
    Redirect,
    /// 4xx response.
    ClientError,
    /// 5xx/6xx response.
    ServerError,
    /// Anything else (e.g. an unparseable status).
    Other,
}

/// What a ladder row is, carrying the theme-free style inputs `style`
/// needs to color its arrow under every `ColorMode`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKind {
    /// A real SIP message row.
    Message {
        /// Semantic class for `ColorMode::Method` coloring.
        class: MessageClass,
        /// Precomputed Call-ID byte-sum index into the rotation palette
        /// (`ColorMode::CallId`).
        cid_idx: usize,
        /// Precomputed CSeq-number index into the rotation palette
        /// (`ColorMode::CSeq`).
        cseq_idx: usize,
    },
    /// A synthetic RTP-in-flow channel bar.
    RtpBar,
    /// A synthetic time-proportional spacer row (Scaled mode).
    Spacer,
}

/// Theme-free style class of a row's timestamp column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsClass {
    /// Absolute-mode message timestamp (muted).
    Muted,
    /// Absolute-mode RTP-bar timestamp (accent).
    Accent,
    /// Delta-mode timestamp; the magnitude drives `delta_style`.
    Delta(i64),
    /// Spacer row (muted + dim, same as its arrow style).
    SpacerDim,
}

/// One ladder row as produced by `layout`: every string and structural
/// decision made, no colors chosen. The cacheable half of a prepared
/// ladder — see `FormattedMessage` for the field semantics it maps onto.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutRow {
    /// Formatted timestamp text (padded to the timestamp column width).
    pub timestamp: String,
    /// Theme-free class of the timestamp; mapped to a style by `style`.
    pub ts_class: TsClass,
    /// Arrow label text (e.g. `INVITE (SDP)`, `200 OK`, RTP-bar label).
    pub label: String,
    /// What the row is (message / RTP bar / spacer) plus arrow-color inputs.
    pub kind: RowKind,
    /// Index into the participants array for the source endpoint.
    pub src_col: usize,
    /// Index into the participants array for the destination endpoint.
    pub dst_col: usize,
    /// Optional PDD annotation (e.g. `  PDD: 1234ms`) on the first 180.
    pub pdd_note: Option<String>,
    /// SDP info line texts; styled muted+italic by `style`.
    pub extra_lines: Vec<String>,
    /// Call-ID of the source message (empty for spacers).
    pub call_id: String,
    /// Whether the row renders as a response (dashed arrow).
    pub is_response: bool,
    /// Raw timestamp for mark/delta computation and spacer sizing.
    pub raw_timestamp: chrono::DateTime<chrono::Utc>,
    /// Number of folded messages (0 = not a fold header).
    pub folded_count: usize,
    /// Fold annotation (e.g. `(+2 retx) - press e to expand`).
    pub fold_label: Option<String>,
    /// SDP change badge for re-INVITEs (e.g. `+G722`, `HOLD`).
    pub sdp_badge: Option<String>,
    /// Whether the underlying message is a retransmission.
    pub is_retransmission: bool,
    /// Index into the raw message slice (`None` for synthetic rows).
    pub raw_index: Option<usize>,
    /// Signalling-diagnosis annotation when this message is cited as evidence
    /// for a detection — the surface that makes "evidence, not verdicts" visible,
    /// by marking the exact messages a finding was drawn from rather than
    /// asserting the finding somewhere else and leaving the reader to locate them.
    pub diagnosis_note: Option<String>,
}

/// The arrow color rotation used by `ColorMode::CallId` / `ColorMode::CSeq`.
const CID_COLORS: [Color; 6] = [
    Color::Green,
    Color::Blue,
    Color::Yellow,
    Color::Magenta,
    Color::Cyan,
    Color::Red,
];

#[cfg(test)]
thread_local! {
    /// Per-thread call counter for `layout`, test-only: pins the WS4.3c
    /// "laid out at most once per tick, cached across ticks" property
    /// (thread-local so the parallel test runner cannot cross-talk).
    pub(crate) static LAYOUT_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Lay out a dialog's ladder: participants, row order (folding, RTP bars,
/// Scaled-mode spacers), timestamp/label/SDP texts — everything except
/// colors and selection, which `style` applies. Pure and theme-free, so
/// the result is cacheable across frames.
///
/// Endpoints are discovered in first-appearance order and every endpoint
/// gets its own column, so a message is always attributed to its true
/// participants. The renderer owns the geometry limit: when the columns
/// cannot fit the available width it paints an explicit "Terminal too
/// narrow for ladder" notice instead of drawing a misleading ladder.
///
/// # Arguments
/// * `messages` — the dialog's SIP messages in capture order.
/// * `first_ts` — reference timestamp for delta-first/delta-prev formatting.
/// * `pdd_ms` — post-dial delay to annotate on the first 180, if known.
/// * `opts` — layout-affecting display options (theme-free).
/// * `fold_expanded` — raw indices of fold headers the user has expanded.
///
/// # Returns
/// `(participants, rows)`: swimlane endpoints in column order and the
/// laid-out rows (real messages plus synthetic RTP bars and spacers).
/// Both empty when `messages` is empty.
///
/// # Side effects
/// In test builds only, increments the thread-local `LAYOUT_CALLS` counter
/// used to pin the ladder-cache property. Otherwise pure.
pub fn layout(
    messages: &[SipMessage],
    first_ts: chrono::DateTime<chrono::Utc>,
    pdd_ms: Option<i64>,
    opts: &LayoutOptions<'_>,
    fold_expanded: &HashSet<usize>,
) -> (Vec<Participant>, Vec<LayoutRow>) {
    #[cfg(test)]
    LAYOUT_CALLS.with(|c| c.set(c.get() + 1));
    let sdp_mode = opts.sdp_mode;
    let ts_mode = opts.ts_mode;
    let show_rtp = opts.show_rtp;
    let rtp_segments = opts.rtp_segments;
    if messages.is_empty() {
        return (Vec::new(), Vec::new());
    }

    // Discover all unique endpoints, keyed by (ip, port). The raw `ip:port`
    // string remains the matching key; the displayed label may be a resolved
    // name when name resolution is active.
    let mut endpoints: Vec<(std::net::IpAddr, u16)> = Vec::new();
    for msg in messages {
        for ep in [(msg.src_addr, msg.src_port), (msg.dst_addr, msg.dst_port)] {
            if !endpoints.contains(&ep) {
                endpoints.push(ep);
            }
        }
    }
    let participants: Vec<Participant> = endpoints
        .iter()
        .map(|&(ip, port)| {
            let addr = format!("{ip}:{port}");
            let display = opts.resolver.label(ip, port, opts.name_mode);
            Participant {
                addr,
                label: truncate(&display, 20),
            }
        })
        .collect();

    let ts_width = TS_COL_WIDTH;

    let mut pdd_done = false;
    let mut in_call = false;
    // Negotiated codec from the most recent INVITE 200 OK answer (single,
    // preferred), pending display on the ACK bar. `last_bar_cseq` is the CSeq
    // number of the INVITE transaction whose media bar we last drew, so each
    // distinct (re-)INVITE draws its own bar but a single transaction (e.g. early
    // media then its confirming ACK) does not draw two.
    let mut pending_answer_codec: Option<String> = None;
    let mut last_bar_cseq: Option<u32> = None;
    let mut deferred_rtp_bar: Option<(chrono::DateTime<chrono::Utc>, String)> = None;
    let mut result = Vec::with_capacity(messages.len());
    // Each message's parsed SDP, indexed by message position, retained so the
    // SDP-delta-badge pass below reuses this parse instead of re-parsing every
    // body a second time.
    let mut msg_sdps: Vec<Option<sdp::SdpSession>> = Vec::with_capacity(messages.len());
    let mut prev_ts = first_ts;

    for (mi, msg) in messages.iter().enumerate() {
        // Parse this message's SDP once per iteration — the SDP-info line, the
        // early-media probe, and both codec lookups below all need it, and
        // `SipMessage::sdp()` re-parses the body on every call. The parse is
        // also stashed in `msg_sdps` for the delta-badge pass.
        let msg_sdp = msg.sdp();
        let (timestamp, ts_class) = match ts_mode {
            TimestampMode::Absolute => {
                let ts_str = format!(
                    "{:<width$}",
                    msg.timestamp.format("%H:%M:%S%.3f"),
                    width = ts_width
                );
                (ts_str, TsClass::Muted)
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
                prev_ts = msg.timestamp;
                (ts_str, TsClass::Delta(d))
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
                (ts_str, TsClass::Delta(d))
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
                prev_ts = msg.timestamp;
                (ts_str, TsClass::Delta(d))
            }
        };

        let label = format_message_label(msg);

        // Arrow coloring is applied in style(); here only its theme-free
        // inputs are derived (class + palette indices). Selection is
        // assigned there too, after folding, over visible rows.
        let kind = RowKind::Message {
            class: classify_message(msg),
            cid_idx: msg
                .call_id()
                .unwrap_or("")
                .bytes()
                .fold(0usize, |a, b| a.wrapping_add(b as usize))
                % CID_COLORS.len(),
            cseq_idx: msg.cseq().map(|(n, _)| n).unwrap_or(0) as usize % CID_COLORS.len(),
        };

        let src_addr = format!("{}:{}", msg.src_addr, msg.src_port);
        let dst_addr = format!("{}:{}", msg.dst_addr, msg.dst_port);
        let src_col = participants
            .iter()
            .position(|p| p.addr == src_addr)
            .unwrap_or(0);
        let dst_col = participants
            .iter()
            .position(|p| p.addr == dst_addr)
            .unwrap_or(1.min(participants.len().saturating_sub(1)));

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

        // SDP info lines (text only; style() renders them muted+italic)
        if sdp_mode != SdpDisplayMode::None
            && let Some(ss) = msg_sdp.as_ref()
        {
            let ind = " ".repeat(ts_width + 1);
            match sdp_mode {
                SdpDisplayMode::Summary => {
                    let c = format_sdp_codecs(ss);
                    if !c.is_empty() {
                        extra_lines.push(format!("{ind} Codecs: {c}"));
                    }
                }
                SdpDisplayMode::Full => {
                    let bt = String::from_utf8_lossy(&msg.body);
                    for sl in bt.lines() {
                        extra_lines.push(format!("{ind}  {sl}"));
                    }
                }
                SdpDisplayMode::None => {}
            }
        }

        // RTP-in-flow bar. One bar per INVITE transaction that carries media —
        // the initial call AND each re-INVITE that (re)establishes the stream —
        // so RTP is shown flowing in every media segment, not just the first.
        // The codec is the one ACTUALLY USED (observed RTP segment, falling back
        // to the single negotiated SDP answer codec), so a re-INVITE that
        // switches PCMU → G722 shows the new codec while one that keeps it still
        // shows the continuing stream.
        if show_rtp {
            let cseq_num = msg.cseq().map(|(n, _)| n);

            // Early media: a provisional (1xx) response to the INVITE that
            // carries SDP means media (ringback / IVR / announcement) flows
            // BEFORE the 200 OK and ACK. The channel opens here, at the
            // provisional, and this transaction's confirming ACK won't redraw it.
            let is_invite_early_media = !msg.is_request
                && msg.status_code.is_some_and(|s| (100..200).contains(&s))
                && msg.cseq().is_some_and(|(_, method)| method == "INVITE")
                && msg_sdp.is_some()
                && last_bar_cseq != cseq_num;
            if is_invite_early_media {
                in_call = true;
                let codec = segment_codec_at(rtp_segments, msg.timestamp)
                    .or_else(|| msg_sdp.as_ref().and_then(first_sdp_codec));
                last_bar_cseq = cseq_num;
                deferred_rtp_bar = Some((msg.timestamp, rtp_flow_label(codec.as_deref())));
            }

            // Remember the negotiated (single, preferred) codec from a 200 OK to
            // an INVITE — initial OR re-INVITE — to label the following ACK bar.
            let is_invite_200 = !msg.is_request
                && msg.status_code == Some(200)
                && msg.cseq().is_some_and(|(_, method)| method == "INVITE");
            if is_invite_200 {
                pending_answer_codec = msg_sdp.as_ref().and_then(first_sdp_codec);
            }

            // The ACK completes an INVITE transaction and (re)opens the media
            // channel. The label is bare text — the renderer owns the `═` rails
            // and centers it (render::rtp_channel_bar). Emitted as a separate
            // deferred FormattedMessage after the ACK so it's independently
            // selectable. Drawn once per transaction (keyed on CSeq): the first
            // call always shows a bar; each re-INVITE that carries media shows
            // another; early media already drew this transaction's bar so its ACK
            // does not duplicate it.
            let is_invite_ack =
                msg.is_request && msg.method.as_ref() == Some(&crate::sip::SipMethod::Ack);
            if is_invite_ack {
                let codec = segment_codec_at(rtp_segments, msg.timestamp)
                    .or_else(|| pending_answer_codec.clone());
                let already_drawn = last_bar_cseq.is_some() && last_bar_cseq == cseq_num;
                if !already_drawn && (!in_call || codec.is_some()) {
                    in_call = true;
                    last_bar_cseq = cseq_num;
                    deferred_rtp_bar = Some((msg.timestamp, rtp_flow_label(codec.as_deref())));
                }
                pending_answer_codec = None;
            }
            if msg.is_request && msg.method.as_ref() == Some(&crate::sip::SipMethod::Bye) && in_call
            {
                in_call = false;
                last_bar_cseq = None;
            }
        }

        result.push(LayoutRow {
            timestamp,
            ts_class,
            label,
            kind,
            src_col,
            dst_col,
            pdd_note,
            extra_lines,
            call_id: msg.call_id().unwrap_or("").to_string(),
            is_response: !msg.is_request,
            raw_timestamp: msg.timestamp,
            folded_count: 0,
            fold_label: None,
            sdp_badge: None,
            is_retransmission: msg.is_retransmission,
            raw_index: Some(mi),
            diagnosis_note: None,
        });

        // Push the deferred RTP bar as a separate selectable entry
        if let Some((rtp_ts, rtp_label)) = deferred_rtp_bar.take() {
            // Format timestamp using the same mode as all other messages
            let (rtp_timestamp, rtp_ts_class) = match ts_mode {
                TimestampMode::Absolute => {
                    let s = format!(
                        "{:<width$}",
                        rtp_ts.format("%H:%M:%S%.3f"),
                        width = ts_width
                    );
                    (s, TsClass::Accent)
                }
                TimestampMode::DeltaPrev => {
                    let d = rtp_ts.signed_duration_since(prev_ts).num_milliseconds();
                    let s = format!(
                        "{:>width$}",
                        format!("+{:.3}s", d as f64 / 1000.0),
                        width = ts_width - 1
                    ) + " ";
                    prev_ts = rtp_ts;
                    (s, TsClass::Delta(d))
                }
                TimestampMode::DeltaFirst => {
                    let d = rtp_ts.signed_duration_since(first_ts).num_milliseconds();
                    let s = format!(
                        "{:>width$}",
                        format!("+{:.3}s", d as f64 / 1000.0),
                        width = ts_width - 1
                    ) + " ";
                    (s, TsClass::Delta(d))
                }
                TimestampMode::Scaled => {
                    let d = rtp_ts.signed_duration_since(prev_ts).num_milliseconds();
                    let s = format!(
                        "{:>width$}",
                        format!("+{:.3}s", d as f64 / 1000.0),
                        width = ts_width - 1
                    ) + " ";
                    prev_ts = rtp_ts;
                    (s, TsClass::Delta(d))
                }
            };
            result.push(LayoutRow {
                timestamp: rtp_timestamp,
                ts_class: rtp_ts_class,
                label: rtp_label,
                kind: RowKind::RtpBar,
                src_col: 0,
                dst_col: 0,
                pdd_note: None,
                extra_lines: vec![],
                call_id: msg.call_id().unwrap_or("").to_string(),
                is_response: false,
                raw_timestamp: rtp_ts,
                folded_count: 0,
                fold_label: None,
                sdp_badge: None,
                is_retransmission: false,
                raw_index: None,
                diagnosis_note: None,
            });
        }

        // Retain the parse for the delta-badge pass (one entry per message).
        msg_sdps.push(msg_sdp);
    }

    // ── SDP delta badges (Feature 4) ──────────────────────────────
    // Track previous SDP state per call_id to compute change badges.
    {
        let mut last_codecs: HashMap<String, Vec<String>> = HashMap::new();
        let mut last_direction: HashMap<String, SdpDirection> = HashMap::new();
        for (ri, msg) in messages.iter().enumerate() {
            let cid = msg.call_id().unwrap_or("").to_string();
            // Reuse the parse from the main loop instead of re-parsing.
            if let Some(ss) = msg_sdps[ri].as_ref() {
                let codecs = extract_codec_list(ss);
                let dir = ss
                    .media
                    .first()
                    .map(|m| m.direction.clone())
                    .unwrap_or(SdpDirection::SendRecv);
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
                            (
                                SdpDirection::SendOnly | SdpDirection::Inactive,
                                SdpDirection::SendRecv,
                            ) => {
                                badge_parts.push("HOLD".to_string());
                            }
                            (
                                SdpDirection::SendRecv,
                                SdpDirection::SendOnly | SdpDirection::Inactive,
                            ) => {
                                badge_parts.push("UNHOLD".to_string());
                            }
                            _ => {}
                        }
                    }
                    if !badge_parts.is_empty()
                        && let Some(fm) = result.iter_mut().find(|fm| fm.raw_index == Some(ri))
                    {
                        fm.sdp_badge = Some(badge_parts.join(" "));
                    }
                }
                last_codecs.insert(cid.clone(), codecs);
                last_direction.insert(cid, dir);
            }
        }
    }

    // ── Signalling-diagnosis evidence annotation ──────────────────
    //
    // Marks the exact messages a detection was drawn from. This is the surface
    // where the spec's "evidence, not verdicts" rule stops being a data-model
    // decision and becomes something a reader sees: the JSON carries indices, the
    // report names the messages, and here the ladder points at them in place.
    //
    // Computed from `messages` — the same slice being annotated — rather than
    // from a dialog passed in alongside. The evidence indices are then
    // definitionally consistent with the rows they land on, so a caller that
    // hands in a filtered view gets an annotation of that view instead of
    // indices silently pointing at the wrong rows. `raw_index` is the join, the
    // same one the SDP badge above uses; synthetic rows carry `None` and are
    // skipped by construction.
    {
        let diag = crate::sip::diagnosis::diagnose_signaling(messages);
        let mut notes: Vec<(usize, &'static str)> = Vec::new();
        if let Some(f) = &diag.final_failure {
            notes.extend(f.evidence.iter().map(|&i| (i, "FAILURE")));
        }
        if let Some(a) = &diag.auth_loop {
            notes.extend(a.evidence.iter().map(|&i| (i, "AUTH")));
        }
        if let Some(r) = &diag.retransmissions {
            notes.extend(r.evidence.iter().map(|&i| (i, "NO-RSP")));
        }
        if let Some(a) = &diag.ack_missing {
            notes.extend(a.evidence.iter().map(|&i| (i, "NO-ACK")));
        }
        if let Some(a) = &diag.abandoned {
            // The two shapes get different tags: `CANCELLED` is a thing that
            // happened, `NO-FINAL` is a thing that was not recorded. A shared
            // tag would put a verdict on the ladder that the capture cannot
            // support.
            let tag = match a.kind {
                crate::sip::diagnosis::AbandonedKind::Cancelled => "CANCELLED",
                crate::sip::diagnosis::AbandonedKind::NoFinalResponse => "NO-FINAL",
            };
            notes.extend(a.evidence.iter().map(|&i| (i, tag)));
        }
        if let Some(p) = &diag.post_dial_delay {
            notes.extend(p.evidence.iter().map(|&i| (i, "SLOW-PDD")));
        }
        if let Some(r) = &diag.registration_failure {
            notes.extend(r.evidence.iter().map(|&i| (i, "REG")));
        }
        for (idx, tag) in notes {
            if let Some(fm) = result.iter_mut().find(|fm| fm.raw_index == Some(idx)) {
                // One message can be evidence for more than one detection — a
                // retransmitted INVITE that also ends in failure. Join rather
                // than overwrite, so the last detection to run does not erase
                // what the earlier ones found.
                match &mut fm.diagnosis_note {
                    Some(existing) => {
                        if !existing.split(' ').any(|t| t == tag) {
                            existing.push(' ');
                            existing.push_str(tag);
                        }
                    }
                    None => fm.diagnosis_note = Some(tag.to_string()),
                }
            }
        }
    }

    // ── Retransmit folding + Auth collapse (Feature 3) ────────────
    // Folding runs BEFORE spacer insertion so that which rows exist is
    // identical in every timestamp mode; synthetic rows (raw_index == None)
    // are never folded.
    let mut result = fold_messages(messages, result, fold_expanded);

    // ── Time-proportional spacer insertion (Feature 6) ─────────────
    if ts_mode == TimestampMode::Scaled && result.len() >= 2 {
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
                    scaled.push(LayoutRow {
                        timestamp: spacer_ts,
                        ts_class: TsClass::SpacerDim,
                        label: String::new(),
                        kind: RowKind::Spacer,
                        src_col: 0,
                        dst_col: 0,
                        pdd_note: None,
                        extra_lines: Vec::new(),
                        call_id: String::new(),
                        is_response: false,
                        raw_timestamp: prev_ts_raw,
                        folded_count: 0,
                        fold_label: None,
                        sdp_badge: None,
                        is_retransmission: false,
                        raw_index: None,
                        diagnosis_note: None,
                    });
                }
                prev_ts_raw = msg.raw_timestamp;
                scaled.push(msg);
            }
        }
        result = scaled;
    }

    (participants, result)
}

/// Style a laid-out ladder: map each `LayoutRow` to a `FormattedMessage`
/// by choosing concrete colors (theme + `ColorMode`) and assigning the
/// selection highlight. Cheap and pure — safe to re-run every frame over a
/// cached layout.
///
/// # Arguments
/// * `rows` — laid-out ladder rows from `layout`.
/// * `opts` — presentation inputs: color mode, selection, theme.
///
/// # Returns
/// One `FormattedMessage` per row, in order. The row at visible (non-spacer)
/// index `opts.selected_msg` is marked `Selected`; non-bar rows sharing its
/// endpoint pair are marked `Related`. An out-of-range selection selects
/// nothing.
pub fn style(rows: &[LayoutRow], opts: &StyleOptions<'_>) -> Vec<FormattedMessage> {
    let theme = opts.theme;
    let spacer_style = Style::default().fg(theme.muted).add_modifier(Modifier::DIM);
    let sdp_line_style = Style::default()
        .fg(theme.muted)
        .add_modifier(Modifier::ITALIC);

    let mut result: Vec<FormattedMessage> = rows
        .iter()
        .map(|row| {
            let timestamp_style = match row.ts_class {
                TsClass::Muted => Style::default().fg(theme.muted),
                TsClass::Accent => Style::default().fg(theme.accent),
                TsClass::Delta(d) => delta_style(d, theme),
                TsClass::SpacerDim => spacer_style,
            };
            let style = match &row.kind {
                RowKind::Spacer => spacer_style,
                RowKind::RtpBar => Style::default().fg(theme.accent),
                RowKind::Message {
                    class,
                    cid_idx,
                    cseq_idx,
                } => match opts.color_mode {
                    ColorMode::Method => class_style(*class, theme),
                    ColorMode::CallId => Style::default().fg(CID_COLORS[*cid_idx]),
                    ColorMode::CSeq => Style::default().fg(CID_COLORS[*cseq_idx]),
                },
            };
            FormattedMessage {
                timestamp: row.timestamp.clone(),
                timestamp_style,
                label: row.label.clone(),
                style,
                src_col: row.src_col,
                dst_col: row.dst_col,
                pdd_note: row.pdd_note.clone(),
                extra_lines: row
                    .extra_lines
                    .iter()
                    .map(|l| (l.clone(), sdp_line_style))
                    .collect(),
                selected: false,
                call_id: row.call_id.clone(),
                selection_state: SelectionState::Normal,
                is_response: row.is_response,
                raw_timestamp: row.raw_timestamp,
                folded_count: row.folded_count,
                fold_label: row.fold_label.clone(),
                is_spacer: row.kind == RowKind::Spacer,
                sdp_badge: row.sdp_badge.clone(),
                is_retransmission: row.is_retransmission,
                is_rtp_bar: row.kind == RowKind::RtpBar,
                raw_index: row.raw_index,
                diagnosis_note: row.diagnosis_note.clone(),
            }
        })
        .collect();

    // ── Selection: assign over VISIBLE rows ────────────────────────
    // `selected_msg` is the index the user navigated to among rendered,
    // non-spacer rows (post-fold), so highlighting always matches what the
    // keys move over, in every timestamp mode. Rows sharing the selected
    // message's endpoint pair are marked Related (same leg).
    if let Some(sel) = opts.selected_msg {
        let mut sel_pair: Option<(usize, usize)> = None;
        let mut vis = 0usize;
        for fm in result.iter_mut() {
            if fm.is_spacer {
                continue;
            }
            if vis == sel {
                fm.selected = true;
                fm.selection_state = SelectionState::Selected;
                if !fm.is_rtp_bar {
                    sel_pair = Some((fm.src_col, fm.dst_col));
                }
                break;
            }
            vis += 1;
        }
        if let Some((s, d)) = sel_pair {
            for fm in result.iter_mut() {
                if fm.selected || fm.is_spacer || fm.is_rtp_bar {
                    continue;
                }
                let same_leg =
                    (fm.src_col == s && fm.dst_col == d) || (fm.src_col == d && fm.dst_col == s);
                if same_leg {
                    fm.selection_state = SelectionState::Related;
                }
            }
        }
    }

    result
}

/// Extract a list of codec names from an SDP session, across all media
/// sections. Prefers `a=rtpmap` encoding names; a media section without any
/// rtpmap falls back to mapping well-known static payload-type numbers
/// (0/8/9/18/4/3/101), passing unknown formats through verbatim. Returns the
/// names in appearance order (may be empty).
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

/// Fold retransmissions and auth retry sequences in the laid-out row list.
///
/// - **Retransmit folding**: consecutive messages with `is_retransmission == true`
///   are collapsed into the original message with a count badge, unless the fold
///   is expanded.
/// - **Auth collapse**: sequences like `request(N) -> 401/407(N) -> ACK(N) -> request(N+1 with Auth)`
///   are collapsed into a single row, unless expanded.
///
/// Runs before spacer insertion so row visibility is identical in every
/// timestamp mode; synthetic rows (`raw_index == None`) pass through
/// untouched and are never fold headers or members.
///
/// # Arguments
/// * `raw_msgs` — the raw SIP messages, indexed by each row's `raw_index`.
/// * `formatted` — laid-out rows to fold (consumed).
/// * `fold_expanded` — raw indices of fold headers the user has expanded;
///   expanded headers keep their members visible and carry a re-collapse
///   hint in `fold_label`.
///
/// # Returns
/// The folded row list: fold headers gain `folded_count`, `fold_label` and
/// (for auth) a ` (+auth)` label suffix; folded member rows are dropped.
fn fold_messages(
    raw_msgs: &[SipMessage],
    formatted: Vec<LayoutRow>,
    fold_expanded: &HashSet<usize>,
) -> Vec<LayoutRow> {
    if formatted.is_empty() {
        return formatted;
    }

    let mut result: Vec<LayoutRow> = Vec::with_capacity(formatted.len());
    // Own the elements so we can move them selectively
    let mut source: Vec<Option<LayoutRow>> = formatted.into_iter().map(Some).collect();
    let mut i = 0;

    // Index into `result` of the most recently emitted row that can act as a
    // retransmission fold header — a real (non-synthetic) row whose raw
    // message is itself NOT a retransmission. Maintained as rows are pushed
    // (`push_row`) so a retransmission storm folds in a single forward pass:
    // the old code re-scanned the whole emitted prefix per retransmission
    // (O(n²) when a long retx run is expanded and visible), this is O(n).
    let mut last_header_idx: Option<usize> = None;

    // Push a row and, if it qualifies as a retx fold header, record its index.
    fn push_row(
        result: &mut Vec<LayoutRow>,
        last_header_idx: &mut Option<usize>,
        raw_msgs: &[SipMessage],
        row: LayoutRow,
    ) {
        let is_header = row
            .raw_index
            .is_some_and(|h| raw_msgs.get(h).is_some_and(|m| !m.is_retransmission));
        if is_header {
            *last_header_idx = Some(result.len());
        }
        result.push(row);
    }

    while i < source.len() {
        // Synthetic rows (RTP bars) pass through untouched and are never
        // fold headers or fold members.
        let Some(ri) = source[i].as_ref().and_then(|fm| fm.raw_index) else {
            if let Some(fm) = source[i].take() {
                push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
            }
            i += 1;
            continue;
        };

        // --- Auth collapse detection (keyed on the header's raw index) ---
        if let Some(fold_len) = detect_auth_sequence(raw_msgs, ri) {
            if fold_expanded.contains(&ri) {
                // Expanded: emit the header with a re-collapse hint; the
                // member rows follow normally on later iterations.
                if let Some(mut fm) = source[i].take() {
                    fm.fold_label = Some("(auth retry expanded - press e to collapse)".to_string());
                    push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
                }
                i += 1;
                continue;
            }
            // Take the first message as the fold header
            if let Some(mut fm) = source[i].take() {
                fm.folded_count = fold_len;
                fm.fold_label = Some(format!(
                    "{} msgs folded (auth retry) - press e to expand",
                    fold_len
                ));
                // On-arrow badge, kept short like "(+N retx)": it must fit
                // the pipe gap in the split multi-leg view (the verbose
                // wording lives in fold_label). " (auth retry)" pushed the
                // demo's widest label to 25 chars, an un-satisfiable 30-col
                // gap demand at the 98-col demo geometry.
                fm.label = format!("{} (+auth)", fm.label);
                push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
            }
            // Drop the member rows: every following row whose raw index is
            // inside the sequence.
            let end_raw = ri + fold_len;
            let mut j = i + 1;
            while j < source.len() {
                match source[j].as_ref().and_then(|fm| fm.raw_index) {
                    Some(rj) if rj < end_raw => {
                        source[j].take();
                        j += 1;
                    }
                    _ => break,
                }
            }
            i = j;
            continue;
        }

        // --- Retransmit folding ---
        if raw_msgs.get(ri).is_some_and(|m| m.is_retransmission) {
            // The fold header is the last emitted NON-retransmission row: a
            // whole retx run belongs to one header, even when earlier retx
            // rows of the run are visible because the fold is expanded. That
            // header's index in `result` is tracked in `last_header_idx`, so
            // no back-scan is needed (the retx row itself never becomes a
            // header, so pushing it leaves `last_header_idx` pointing at the
            // run's header for every subsequent retx in the run).
            match last_header_idx {
                Some(idx) => {
                    let header_raw = result[idx].raw_index.unwrap_or(usize::MAX);
                    if fold_expanded.contains(&header_raw) {
                        // Expanded: keep the retransmission visible; label
                        // the header so the fold can be re-collapsed.
                        result[idx].fold_label =
                            Some("(retx expanded - press e to collapse)".to_string());
                        if let Some(fm) = source[i].take() {
                            push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
                        }
                    } else {
                        result[idx].folded_count += 1;
                        let n = result[idx].folded_count;
                        result[idx].fold_label = Some(format!("(+{n} retx) - press e to expand"));
                        source[i].take();
                    }
                }
                None => {
                    // No previous message to fold into — emit normally.
                    if let Some(fm) = source[i].take() {
                        push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
                    }
                }
            }
            i += 1;
            continue;
        }

        // Not folded — emit normally
        if let Some(fm) = source[i].take() {
            push_row(&mut result, &mut last_header_idx, raw_msgs, fm);
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
        format!(
            "{}{}",
            msg.method.as_ref().map(|m| m.as_str()).unwrap_or("?"),
            sdp_suffix
        )
    } else {
        let code = msg.status_code.unwrap_or(0);
        let reason = msg.reason.as_deref().unwrap_or("");
        format!("{} {}{}", code, reason, sdp_suffix)
    }
}

/// Derive the theme-free `MessageClass` of a message — the layout-stage
/// half of `message_style`.
pub fn classify_message(msg: &SipMessage) -> MessageClass {
    if msg.is_request {
        let method = msg.method.as_ref().map(|m| m.as_str()).unwrap_or("");
        match method {
            "INVITE" | "SUBSCRIBE" => MessageClass::SessionRequest,
            "BYE" | "CANCEL" => MessageClass::TeardownRequest,
            "ACK" | "PRACK" => MessageClass::AckRequest,
            "REGISTER" | "OPTIONS" => MessageClass::RegisterRequest,
            _ => MessageClass::OtherRequest,
        }
    } else {
        let code = msg.status_code.unwrap_or(0);
        match code {
            100..=199 => MessageClass::Provisional,
            200..=299 => MessageClass::Success,
            300..=399 => MessageClass::Redirect,
            400..=499 => MessageClass::ClientError,
            500..=699 => MessageClass::ServerError,
            _ => MessageClass::Other,
        }
    }
}

/// Map a `MessageClass` to its semantic color — the style-stage half of
/// `message_style`.
///
/// Requests: teal for session-creating (INVITE/SUBSCRIBE), coral for teardown
/// (BYE/CANCEL), gray for acks, blue for registration/options.
/// Responses: amber for provisional, green for success, yellow for redirect,
/// orange for client error, bold red for server error.
pub fn class_style(class: MessageClass, theme: &Theme) -> Style {
    match class {
        MessageClass::SessionRequest => Style::default().fg(Color::Rgb(95, 175, 175)), // Teal
        MessageClass::TeardownRequest => Style::default().fg(Color::Rgb(215, 95, 95)), // Coral
        MessageClass::AckRequest => Style::default().fg(theme.muted),                  // Gray
        MessageClass::RegisterRequest => Style::default().fg(Color::Rgb(95, 135, 215)), // Blue
        MessageClass::Provisional => Style::default().fg(Color::Rgb(215, 175, 95)),    // Amber
        MessageClass::Success => Style::default().fg(theme.good),                      // Green
        MessageClass::Redirect => Style::default().fg(theme.warning),                  // Yellow
        MessageClass::ClientError => Style::default().fg(Color::Rgb(215, 135, 0)),     // Orange
        MessageClass::ServerError => Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
        MessageClass::OtherRequest | MessageClass::Other => Style::default().fg(theme.foreground),
    }
}

/// Choose a style based on message type with semantic colors — see
/// `class_style` for the palette.
pub fn message_style(msg: &SipMessage, theme: &Theme) -> Style {
    class_style(classify_message(msg), theme)
}

/// The bare text for an RTP-in-flow channel bar, e.g. ` RTP · PCMU ` (or ` RTP `
/// when the codec is unknown). The surrounding `═` channel rails are added by the
/// renderer (see `render::rtp_channel_bar`), so this is just the centered label
/// with a space on each side to keep the rails off the text.
fn rtp_flow_label(codec: Option<&str>) -> String {
    match codec {
        Some(c) => format!(" RTP \u{00B7} {c} "),
        None => " RTP ".to_string(),
    }
}

/// Format an SDP session's codecs as a comma-separated display string (e.g.
/// `PCMU, PCMA, opus`). Same extraction rules as `extract_codec_list`:
/// rtpmap encoding names preferred, static payload-type numbers mapped as a
/// fallback, unknown formats passed through. Empty string when the SDP
/// carries no codec.
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

/// The single negotiated/preferred codec from an SDP body — the first codec of
/// the first media line. For an SDP *answer* this is the codec the call will
/// actually use, so the RTP-in-flow bar prefers it over the full offer list.
/// `None` when the SDP carries no codec.
fn first_sdp_codec(session: &sdp::SdpSession) -> Option<String> {
    extract_codec_list(session)
        .into_iter()
        .next()
        .filter(|s| !s.is_empty())
}

/// The codec carried by the RTP segment that flows *from* ladder time `ts` — the
/// segment whose start is closest to `ts`. A media bar is emitted at an ACK (or
/// early-media provisional), and that phase's RTP begins right after, so the
/// nearest-starting segment is the media for this phase: the initial ACK maps to
/// the first segment, and a re-INVITE ACK that renegotiates the codec maps to
/// the later segment (PCMU → G722). Returns `None` only when no RTP is linked to
/// the dialog, in which case the caller falls back to the negotiated SDP codec.
fn segment_codec_at(
    segments: &[RtpCodecSegment],
    ts: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    segments
        .iter()
        .min_by_key(|s| (s.start - ts).num_milliseconds().abs())
        .map(|s| s.codec.clone())
}

/// Tests for the data-preparation stage: layout/style split, folding,
/// RTP bars, SDP badges, selection, and codec extraction.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{DateTime, TimeDelta, Utc};

    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use crate::tui::{ColorMode, SdpDisplayMode, Theme, TimestampMode};

    use super::*;

    // ── Construction helpers ─────────────────────────────────────────

    /// Fixture endpoint A (10.0.0.1), the request originator.
    fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    /// Fixture endpoint B (10.0.0.2), the request target.
    fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }
    /// Fixed base timestamp all fixture dialogs are built from.
    fn t0() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Assemble raw SIP bytes from `first_line`, `headers` and `body`
    /// (CRLF line endings, blank line before the body).
    fn build_raw(first_line: &str, headers: &[&str], body: &str) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(first_line.as_bytes());
        m.extend_from_slice(b"\r\n");
        for h in headers {
            m.extend_from_slice(h.as_bytes());
            m.extend_from_slice(b"\r\n");
        }
        m.extend_from_slice(b"\r\n");
        m.extend_from_slice(body.as_bytes());
        m
    }

    /// Parse `raw` as an A→B request captured at `ts`.
    fn parse_req(raw: &[u8], ts: DateTime<Utc>) -> SipMessage {
        parse_sip(raw, ts, addr_a(), addr_b(), 5060, 5060, TransportProto::Udp).expect("parse req")
    }

    /// Parse `raw` as a B→A response captured at `ts`.
    fn parse_resp(raw: &[u8], ts: DateTime<Utc>) -> SipMessage {
        parse_sip(raw, ts, addr_b(), addr_a(), 5060, 5060, TransportProto::Udp).expect("parse resp")
    }

    /// A→B INVITE with Call-ID `cid` and CSeq `cseq`, no body.
    fn invite(cid: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        parse_req(
            &build_raw(
                "INVITE sip:bob@10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} INVITE"),
                    "Content-Length: 0",
                ],
                "",
            ),
            ts,
        )
    }

    /// A→B INVITE carrying an SDP offer built from `codecs_line` (the `m=`
    /// line) and `rtpmaps` (`a=rtpmap` attribute lines).
    fn invite_with_sdp(
        cid: &str,
        cseq: u32,
        codecs_line: &str,
        rtpmaps: &[&str],
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let mut sdp = String::from(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n",
        );
        sdp.push_str(codecs_line);
        sdp.push_str("\r\n");
        for rm in rtpmaps {
            sdp.push_str(rm);
            sdp.push_str("\r\n");
        }
        parse_req(
            &build_raw(
                "INVITE sip:bob@10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} INVITE"),
                    "Content-Type: application/sdp",
                    &format!("Content-Length: {}", sdp.len()),
                ],
                &sdp,
            ),
            ts,
        )
    }

    /// A→B REGISTER; `auth` adds an `Authorization` header (the retry leg of
    /// an auth sequence).
    fn register(cid: &str, cseq: u32, auth: Option<&str>, ts: DateTime<Utc>) -> SipMessage {
        let mut headers = vec![
            "From: <sip:alice@10.0.0.1>;tag=t1".to_string(),
            "To: <sip:alice@10.0.0.1>".to_string(),
            format!("Call-ID: {cid}"),
            format!("CSeq: {cseq} REGISTER"),
            "Content-Length: 0".to_string(),
        ];
        if let Some(a) = auth {
            headers.push(format!("Authorization: {a}"));
        }
        let hdr_refs: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
        parse_req(
            &build_raw("REGISTER sip:10.0.0.2 SIP/2.0", &hdr_refs, ""),
            ts,
        )
    }

    /// A→B ACK completing an INVITE transaction.
    fn ack(cid: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        parse_req(
            &build_raw(
                "ACK sip:bob@10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>;tag=t2",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} ACK"),
                    "Content-Length: 0",
                ],
                "",
            ),
            ts,
        )
    }

    /// A→B ACK aimed at the registrar (the ACK leg of a REGISTER auth
    /// sequence).
    fn ack_register(cid: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        parse_req(
            &build_raw(
                "ACK sip:10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:alice@10.0.0.1>;tag=t2",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} ACK"),
                    "Content-Length: 0",
                ],
                "",
            ),
            ts,
        )
    }

    /// B→A response with the given status/reason for CSeq `cseq method`.
    fn response(
        cid: &str,
        status: u16,
        reason: &str,
        cseq: u32,
        method: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        parse_resp(
            &build_raw(
                &format!("SIP/2.0 {status} {reason}"),
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>;tag=t2",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} {method}"),
                    "Content-Length: 0",
                ],
                "",
            ),
            ts,
        )
    }

    /// A response carrying an SDP answer (e.g. a 183 Session Progress that
    /// signals early media).
    // A test fixture builder: each field maps to a distinct SIP/SDP element, so
    // the argument count is inherent rather than a design smell.
    #[expect(clippy::too_many_arguments)]
    fn response_with_sdp(
        cid: &str,
        status: u16,
        reason: &str,
        cseq: u32,
        method: &str,
        codecs_line: &str,
        rtpmaps: &[&str],
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let mut sdp = String::from(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.2\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.2\r\n\
             t=0 0\r\n",
        );
        sdp.push_str(codecs_line);
        sdp.push_str("\r\n");
        for rm in rtpmaps {
            sdp.push_str(rm);
            sdp.push_str("\r\n");
        }
        parse_resp(
            &build_raw(
                &format!("SIP/2.0 {status} {reason}"),
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>;tag=t2",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} {method}"),
                    "Content-Type: application/sdp",
                    &format!("Content-Length: {}", sdp.len()),
                ],
                &sdp,
            ),
            ts,
        )
    }

    /// A→B BYE ending the dialog.
    fn bye(cid: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        parse_req(
            &build_raw(
                "BYE sip:bob@10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.2>;tag=t2",
                    &format!("Call-ID: {cid}"),
                    &format!("CSeq: {cseq} BYE"),
                    "Content-Length: 0",
                ],
                "",
            ),
            ts,
        )
    }

    /// Baseline `FlowDisplayOptions`: SDP off, absolute timestamps, method
    /// coloring, no RTP, no selection — tests override individual fields.
    fn opts<'a>(theme: &'a Theme) -> FlowDisplayOptions<'a> {
        // Leak a default resolver so it satisfies the borrow without threading
        // a separate owner through every test caller (test-only).
        let resolver: &'static crate::names::NameResolver =
            Box::leak(Box::new(crate::names::NameResolver::new()));
        FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::Absolute,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg: None,
            theme,
            resolver,
            name_mode: crate::names::NameMode::Off,
            rtp_segments: &[],
        }
    }

    // ── delta_style ──────────────────────────────────────────────────

    /// Delta magnitudes map to good/warning/bad/bold-bad at the documented
    /// 100ms/1s/5s boundaries; negative deltas count as good.
    #[test]
    fn delta_style_buckets() {
        let theme = Theme::default();
        assert_eq!(delta_style(0, &theme).fg, Some(theme.good));
        assert_eq!(delta_style(99, &theme).fg, Some(theme.good));
        assert_eq!(delta_style(100, &theme).fg, Some(theme.warning));
        assert_eq!(delta_style(999, &theme).fg, Some(theme.warning));
        assert_eq!(delta_style(1000, &theme).fg, Some(theme.bad));
        assert_eq!(delta_style(4999, &theme).fg, Some(theme.bad));
        // > 5s → bold red
        let slow = delta_style(5000, &theme);
        assert_eq!(slow.fg, Some(theme.bad));
        assert!(slow.add_modifier.contains(Modifier::BOLD));
        // negative deltas count as fast/good
        assert_eq!(delta_style(-10, &theme).fg, Some(theme.good));
    }

    // ── format_message_label ─────────────────────────────────────────

    /// Requests label as their method, responses as "code reason".
    #[test]
    fn label_request_and_response() {
        assert_eq!(format_message_label(&invite("c1", 1, t0())), "INVITE");
        let r = response("c1", 200, "OK", 1, "INVITE", t0());
        assert_eq!(format_message_label(&r), "200 OK");
        let r180 = response("c1", 180, "Ringing", 1, "INVITE", t0());
        assert_eq!(format_message_label(&r180), "180 Ringing");
    }

    /// A message carrying an SDP body gets the " (SDP)" label suffix.
    #[test]
    fn label_appends_sdp_suffix() {
        let m = invite_with_sdp(
            "csdp",
            1,
            "m=audio 20000 RTP/AVP 0 8",
            &["a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000"],
            t0(),
        );
        assert_eq!(format_message_label(&m), "INVITE (SDP)");
    }

    // ── prepare_messages: empty ──────────────────────────────────────

    /// An empty message slice yields empty participants and rows.
    #[test]
    fn prepare_empty_returns_empty() {
        let theme = Theme::default();
        let o = opts(&theme);
        let (parts, msgs) = prepare_messages(&[], t0(), None, &o, &HashSet::new());
        assert!(parts.is_empty());
        assert!(msgs.is_empty());
    }

    // ── prepare_messages: basic dialog + participants + PDD ───────────

    /// A basic dialog discovers both endpoints and attaches exactly one PDD
    /// note, on the 180 Ringing row.
    #[test]
    fn prepare_basic_dialog_with_pdd() {
        let theme = Theme::default();
        let o = opts(&theme);
        let msgs = vec![
            invite("c1", 1, t0()),
            response(
                "c1",
                180,
                "Ringing",
                1,
                "INVITE",
                t0() + TimeDelta::milliseconds(500),
            ),
            response("c1", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
            ack("c1", 1, t0() + TimeDelta::seconds(1)),
            bye("c1", 2, t0() + TimeDelta::seconds(30)),
        ];
        let (parts, prepared) = prepare_messages(&msgs, t0(), Some(500), &o, &HashSet::new());
        // Two endpoints discovered (A↔B).
        assert_eq!(parts.len(), 2);
        assert_eq!(prepared.len(), 5);
        // PDD note attached to the 180 Ringing row.
        let pdd_row = prepared.iter().find(|m| m.label == "180 Ringing").unwrap();
        assert_eq!(pdd_row.pdd_note.as_deref(), Some("  PDD: 500ms"));
        // Only one PDD note total.
        assert_eq!(prepared.iter().filter(|m| m.pdd_note.is_some()).count(), 1);
    }

    /// A call crossing seven distinct endpoints keeps every message on its
    /// true participant columns. The old 6-endpoint cap silently remapped
    /// messages touching the 7th endpoint onto columns 0/1 — drawn between
    /// the WRONG participants. All endpoints become columns and no row is
    /// dropped; when the geometry cannot fit them the renderer paints its
    /// explicit "Terminal too narrow for ladder" notice instead.
    #[test]
    fn prepare_seven_endpoints_never_misattributes_columns() {
        let theme = Theme::default();
        let o = opts(&theme);
        // A proxied chain: hop i goes 10.0.0.i -> 10.0.0.(i+1), i = 1..=6,
        // touching seven distinct endpoints in first-appearance order.
        let msgs: Vec<SipMessage> = (1u8..=6)
            .map(|i| {
                let raw = build_raw(
                    "INVITE sip:bob@10.0.0.7 SIP/2.0",
                    &[
                        "From: <sip:alice@10.0.0.1>;tag=t1",
                        "To: <sip:bob@10.0.0.7>",
                        "Call-ID: c7hops",
                        "CSeq: 1 INVITE",
                        "Content-Length: 0",
                    ],
                    "",
                );
                parse_sip(
                    &raw,
                    t0() + TimeDelta::milliseconds(i64::from(i) * 10),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, i + 1)),
                    5060,
                    5060,
                    TransportProto::Udp,
                )
                .expect("parse hop")
            })
            .collect();
        let (parts, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(parts.len(), 7, "every endpoint gets its own column");
        assert_eq!(prepared.len(), msgs.len(), "no row may be dropped");
        for row in &prepared {
            let ri = row.raw_index.expect("no synthetic rows in this fixture");
            let m = &msgs[ri];
            assert_eq!(
                parts[row.src_col].addr,
                format!("{}:{}", m.src_addr, m.src_port),
                "row {ri} src column points at the wrong participant"
            );
            assert_eq!(
                parts[row.dst_col].addr,
                format!("{}:{}", m.dst_addr, m.dst_port),
                "row {ri} dst column points at the wrong participant"
            );
        }
    }

    // ── prepare_messages: SDP summary → extract_codec_list path ───────

    /// Summary SDP mode adds a "Codecs:" extra line naming the offer codecs.
    #[test]
    fn prepare_sdp_summary_lists_codecs() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Summary;
        let msgs = vec![invite_with_sdp(
            "csdp",
            1,
            "m=audio 20000 RTP/AVP 0 8",
            &["a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000"],
            t0(),
        )];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(prepared.len(), 1);
        let codec_line = prepared[0]
            .extra_lines
            .iter()
            .find(|(s, _)| s.contains("Codecs:"))
            .map(|(s, _)| s.clone())
            .expect("codec summary line");
        assert!(codec_line.contains("PCMU"), "got: {codec_line}");
        assert!(codec_line.contains("PCMA"), "got: {codec_line}");
    }

    /// Full SDP mode emits the raw SDP body as indented extra lines.
    #[test]
    fn prepare_sdp_full_emits_body_lines() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.sdp_mode = SdpDisplayMode::Full;
        let msgs = vec![invite_with_sdp(
            "csdp",
            1,
            "m=audio 20000 RTP/AVP 0",
            &["a=rtpmap:0 PCMU/8000"],
            t0(),
        )];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let joined: String = prepared[0]
            .extra_lines
            .iter()
            .map(|(s, _)| s.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("v=0"), "full SDP body missing: {joined}");
        assert!(joined.contains("m=audio"), "media line missing: {joined}");
    }

    // ── prepare_messages: SDP delta badge (re-INVITE codec change) ────

    /// A re-INVITE that changes codecs gets a badge with +added and -removed
    /// names, independent of the SDP display mode.
    #[test]
    fn prepare_sdp_badge_on_codec_change() {
        let theme = Theme::default();
        let o = opts(&theme); // sdp_mode None is fine; badges are independent
        let msgs = vec![
            invite_with_sdp(
                "cbadge",
                1,
                "m=audio 20000 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0(),
            ),
            // re-INVITE adds G722, removes PCMU.
            invite_with_sdp(
                "cbadge",
                2,
                "m=audio 20000 RTP/AVP 9",
                &["a=rtpmap:9 G722/8000"],
                t0() + TimeDelta::seconds(5),
            ),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let badge = prepared[1]
            .sdp_badge
            .as_deref()
            .expect("badge on re-INVITE");
        assert!(badge.contains("+G722"), "expected codec add: {badge}");
        assert!(badge.contains("PCMU"), "expected codec removal: {badge}");
    }

    // ── Signalling-diagnosis evidence annotation ──────────────────

    /// The failure response carries the note; the INVITE that provoked it does
    /// not. Only the messages the detection actually cited are marked.
    #[test]
    fn prepare_annotates_the_failure_response_only() {
        let theme = Theme::default();
        let o = opts(&theme);
        let msgs = vec![
            invite("failnote", 1, t0()),
            response(
                "failnote",
                503,
                "Service Unavailable",
                1,
                "INVITE",
                t0() + TimeDelta::seconds(1),
            ),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());

        let note_for = |raw: usize| -> Option<String> {
            prepared
                .iter()
                .find(|fm| fm.raw_index == Some(raw))
                .and_then(|fm| fm.diagnosis_note.clone())
        };

        assert_eq!(note_for(1).as_deref(), Some("FAILURE"));
        assert!(
            note_for(0).is_none(),
            "the INVITE was not cited as evidence and must not be marked"
        );
    }

    /// An auth loop marks each challenge it counted.
    #[test]
    fn prepare_annotates_every_auth_challenge() {
        let theme = Theme::default();
        let o = opts(&theme);
        let mut msgs = Vec::new();
        for i in 0..3u32 {
            msgs.push(register(
                "authnote",
                i + 1,
                None,
                t0() + TimeDelta::seconds(i as i64 * 2),
            ));
            msgs.push(response(
                "authnote",
                401,
                "Unauthorized",
                i + 1,
                "REGISTER",
                t0() + TimeDelta::seconds(i as i64 * 2 + 1),
            ));
        }
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());

        // The three 401s are raw indices 1, 3, 5.
        for raw in [1usize, 3, 5] {
            let note = prepared
                .iter()
                .find(|fm| fm.raw_index == Some(raw))
                .and_then(|fm| fm.diagnosis_note.clone());
            assert_eq!(
                note.as_deref(),
                Some("AUTH"),
                "challenge at raw index {raw} should be marked"
            );
        }
        // The REGISTERs themselves are not the evidence.
        for raw in [0usize, 2, 4] {
            assert!(
                prepared
                    .iter()
                    .find(|fm| fm.raw_index == Some(raw))
                    .and_then(|fm| fm.diagnosis_note.clone())
                    .is_none(),
                "request at raw index {raw} must not be marked"
            );
        }
    }

    /// A message cited by two detections keeps both tags rather than the last
    /// one written winning.
    #[test]
    fn prepare_joins_notes_when_one_message_is_evidence_twice() {
        let theme = Theme::default();
        let o = opts(&theme);
        // Three identical INVITEs (same CSeq and branch) with no response is a
        // no-response storm; a later failure on a different transaction keeps the
        // storm unanswered, and both detections fire on the same dialog.
        //
        // Built here rather than with the `invite` helper because that helper
        // emits no Via header, and retransmission detection needs the top-Via
        // branch to prove two requests are the same transaction — without it the
        // messages are skipped, which is correct and made this test fail first
        // time round.
        let retx = |ts: DateTime<Utc>| {
            parse_req(
                &build_raw(
                    "INVITE sip:bob@10.0.0.2 SIP/2.0",
                    &[
                        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKboth",
                        "From: <sip:alice@10.0.0.1>;tag=t1",
                        "To: <sip:bob@10.0.0.2>",
                        "Call-ID: bothnote",
                        "CSeq: 1 INVITE",
                        "Content-Length: 0",
                    ],
                    "",
                ),
                ts,
            )
        };
        let mut msgs = vec![
            retx(t0()),
            retx(t0() + TimeDelta::seconds(1)),
            retx(t0() + TimeDelta::seconds(3)),
        ];
        msgs.push(response(
            "bothnote",
            503,
            "Service Unavailable",
            2,
            "INVITE",
            t0() + TimeDelta::seconds(4),
        ));
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());

        let notes: Vec<Option<String>> = (0..4)
            .map(|raw| {
                prepared
                    .iter()
                    .find(|fm| fm.raw_index == Some(raw))
                    .and_then(|fm| fm.diagnosis_note.clone())
            })
            .collect();

        // The three INVITEs are the storm evidence.
        for (raw, note) in notes.iter().enumerate().take(3) {
            assert!(
                note.as_deref().is_some_and(|n| n.contains("NO-RSP")),
                "INVITE {raw} should be marked NO-RSP, got {note:?}"
            );
        }
        // The 503 is the failure evidence.
        assert!(
            notes[3].as_deref().is_some_and(|n| n.contains("FAILURE")),
            "the 503 should be marked FAILURE, got {:?}",
            notes[3]
        );
    }

    /// A clean dialog gets no annotations at all.
    #[test]
    fn prepare_leaves_a_healthy_dialog_unannotated() {
        let theme = Theme::default();
        let o = opts(&theme);
        let msgs = vec![
            invite("oknote", 1, t0()),
            response(
                "oknote",
                200,
                "OK",
                1,
                "INVITE",
                t0() + TimeDelta::seconds(1),
            ),
            ack("oknote", 1, t0() + TimeDelta::seconds(1)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert!(
            prepared.iter().all(|fm| fm.diagnosis_note.is_none()),
            "a successful call must carry no evidence annotations"
        );
    }

    // ── prepare_messages: RTP bar insertion on ACK ────────────────────

    /// With `show_rtp`, exactly one RTP bar appears, directly after the ACK,
    /// with bare label text (no rail glyphs baked in).
    #[test]
    fn prepare_rtp_bar_inserted_after_ack() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.show_rtp = true;
        let msgs = vec![
            invite("crtp", 1, t0()),
            response("crtp", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
            ack("crtp", 1, t0() + TimeDelta::seconds(1)),
            bye("crtp", 2, t0() + TimeDelta::seconds(10)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        // Exactly one RTP bar, and it sits immediately AFTER the ACK row.
        let bar_idxs: Vec<usize> = prepared
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_rtp_bar)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(bar_idxs.len(), 1, "expected exactly one RTP bar");
        let bar_i = bar_idxs[0];
        assert_eq!(
            prepared[bar_i - 1].label,
            "ACK",
            "RTP bar must directly follow the ACK"
        );
        let bar = &prepared[bar_i];
        assert!(bar.label.contains("RTP"), "RTP label missing");
        // The label is bare text — the renderer owns the channel rails, so no
        // line glyphs are baked into the label.
        assert!(
            !bar.label.contains('\u{2500}') && !bar.label.contains('\u{2550}'),
            "rails must not be baked into the label: {:?}",
            bar.label
        );
    }

    /// A 183 with SDP (early media) opens the channel at the provisional —
    /// one bar after the 183, none duplicated at the ACK, codec from the 183.
    #[test]
    fn prepare_rtp_bar_early_media_after_provisional() {
        // A 183 Session Progress carrying SDP = early media: the channel opens
        // at the 183, BEFORE the 200 OK / ACK, and only one bar is emitted.
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.show_rtp = true;
        let msgs = vec![
            invite("cem", 1, t0()),
            response_with_sdp(
                "cem",
                183,
                "Session Progress",
                1,
                "INVITE",
                "m=audio 20000 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::milliseconds(200),
            ),
            response("cem", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
            ack("cem", 1, t0() + TimeDelta::seconds(1)),
            bye("cem", 2, t0() + TimeDelta::seconds(10)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bar_idxs: Vec<usize> = prepared
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_rtp_bar)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            bar_idxs.len(),
            1,
            "early media must still emit exactly one bar, not two"
        );
        // The bar follows the 183, not the ACK.
        let prev = &prepared[bar_idxs[0] - 1];
        assert!(
            prev.label.contains("183") || prev.label.contains("Session Progress"),
            "early-media bar should follow the 183, got prev label {:?}",
            prev.label
        );
        // Codec from the 183 SDP is shown.
        assert!(
            prepared[bar_idxs[0]].label.contains("PCMU"),
            "early-media codec missing: {:?}",
            prepared[bar_idxs[0]].label
        );
    }

    // ── prepare_messages: RTP bar shows the USED codec, not the offer ──

    /// Offer lists three codecs; the answer narrows to one. The RTP-in-flow bar
    /// must show the single negotiated codec (PCMU), not the whole offer list.
    #[test]
    fn prepare_rtp_bar_shows_negotiated_codec_not_offer_list() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.show_rtp = true;
        let msgs = vec![
            invite_with_sdp(
                "cneg",
                1,
                "m=audio 20000 RTP/AVP 0 8 9",
                &[
                    "a=rtpmap:0 PCMU/8000",
                    "a=rtpmap:8 PCMA/8000",
                    "a=rtpmap:9 G722/8000",
                ],
                t0(),
            ),
            response_with_sdp(
                "cneg",
                200,
                "OK",
                1,
                "INVITE",
                "m=audio 20002 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::seconds(1),
            ),
            ack("cneg", 1, t0() + TimeDelta::seconds(1)),
            bye("cneg", 2, t0() + TimeDelta::seconds(10)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bars: Vec<&FormattedMessage> = prepared.iter().filter(|m| m.is_rtp_bar).collect();
        assert_eq!(bars.len(), 1, "expected exactly one media bar");
        let label = &bars[0].label;
        assert!(
            label.contains("PCMU"),
            "should show negotiated PCMU: {label:?}"
        );
        assert!(
            !label.contains("PCMA") && !label.contains("G722"),
            "must not show offered-but-unused codecs: {label:?}"
        );
    }

    /// A re-INVITE that renegotiates the codec (PCMU → G722) draws a second bar
    /// showing the new codec; subsequent RTP uses it.
    #[test]
    fn prepare_rtp_bar_reinvite_switches_codec() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.show_rtp = true;
        let msgs = vec![
            invite_with_sdp(
                "crei",
                1,
                "m=audio 20000 RTP/AVP 0 8",
                &["a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000"],
                t0(),
            ),
            response_with_sdp(
                "crei",
                200,
                "OK",
                1,
                "INVITE",
                "m=audio 20002 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::seconds(1),
            ),
            ack("crei", 1, t0() + TimeDelta::seconds(1)),
            // re-INVITE renegotiates to G722.
            invite_with_sdp(
                "crei",
                2,
                "m=audio 20000 RTP/AVP 9 0",
                &["a=rtpmap:9 G722/8000", "a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::seconds(5),
            ),
            response_with_sdp(
                "crei",
                200,
                "OK",
                2,
                "INVITE",
                "m=audio 20002 RTP/AVP 9",
                &["a=rtpmap:9 G722/8000"],
                t0() + TimeDelta::seconds(6),
            ),
            ack("crei", 2, t0() + TimeDelta::seconds(6)),
            bye("crei", 3, t0() + TimeDelta::seconds(20)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bars: Vec<&FormattedMessage> = prepared.iter().filter(|m| m.is_rtp_bar).collect();
        assert_eq!(bars.len(), 2, "expected a bar per codec segment");
        assert!(
            bars[0].label.contains("PCMU"),
            "first segment is PCMU: {:?}",
            bars[0].label
        );
        assert!(
            bars[1].label.contains("G722"),
            "second segment is G722 after the re-INVITE: {:?}",
            bars[1].label
        );
    }

    /// A re-INVITE that keeps the same codec (a session refresh — the homepage
    /// hero flow) still re-establishes media, so RTP is shown flowing in BOTH
    /// segments: one bar after the initial ACK, one after the re-INVITE's ACK.
    /// And the label carries no redundant "active".
    #[test]
    fn prepare_rtp_bar_reinvite_same_codec_shows_both_segments() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.show_rtp = true;
        let sdp = ("m=audio 20000 RTP/AVP 8", ["a=rtpmap:8 PCMA/8000"]);
        let msgs = vec![
            invite_with_sdp("crf", 1, sdp.0, &sdp.1, t0()),
            response_with_sdp(
                "crf",
                200,
                "OK",
                1,
                "INVITE",
                sdp.0,
                &sdp.1,
                t0() + TimeDelta::seconds(1),
            ),
            ack("crf", 1, t0() + TimeDelta::seconds(1)),
            invite_with_sdp("crf", 2, sdp.0, &sdp.1, t0() + TimeDelta::seconds(5)),
            response_with_sdp(
                "crf",
                200,
                "OK",
                2,
                "INVITE",
                sdp.0,
                &sdp.1,
                t0() + TimeDelta::seconds(6),
            ),
            ack("crf", 2, t0() + TimeDelta::seconds(6)),
            bye("crf", 3, t0() + TimeDelta::seconds(20)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bars: Vec<&FormattedMessage> = prepared.iter().filter(|m| m.is_rtp_bar).collect();
        assert_eq!(
            bars.len(),
            2,
            "media must be shown in both segments, not suppressed"
        );
        assert!(
            bars[0].label.contains("PCMA") && bars[1].label.contains("PCMA"),
            "both bars PCMA: {:?} / {:?}",
            bars[0].label,
            bars[1].label
        );
        assert!(
            !bars[0].label.contains("active"),
            "label should drop the redundant 'active': {:?}",
            bars[0].label
        );
    }

    /// When the answer non-conformantly lists several codecs but RTP actually
    /// carries one, the observed RTP segment wins over the SDP-first codec.
    #[test]
    fn prepare_rtp_bar_prefers_observed_rtp_over_sdp() {
        let theme = Theme::default();
        // Observed RTP is PCMU, active across the call.
        let segs = vec![RtpCodecSegment {
            codec: "PCMU".to_string(),
            start: t0() + TimeDelta::seconds(1),
            end: t0() + TimeDelta::seconds(9),
        }];
        let mut o = opts(&theme);
        o.show_rtp = true;
        o.rtp_segments = &segs;
        let msgs = vec![
            invite_with_sdp(
                "crtpwin",
                1,
                "m=audio 20000 RTP/AVP 8 0",
                &["a=rtpmap:8 PCMA/8000", "a=rtpmap:0 PCMU/8000"],
                t0(),
            ),
            // Answer lists PCMA first (would be the SDP-derived pick) then PCMU.
            response_with_sdp(
                "crtpwin",
                200,
                "OK",
                1,
                "INVITE",
                "m=audio 20002 RTP/AVP 8 0",
                &["a=rtpmap:8 PCMA/8000", "a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::seconds(1),
            ),
            ack("crtpwin", 1, t0() + TimeDelta::seconds(1)),
            bye("crtpwin", 2, t0() + TimeDelta::seconds(10)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bar = prepared.iter().find(|m| m.is_rtp_bar).expect("a media bar");
        assert!(
            bar.label.contains("PCMU"),
            "observed RTP PCMU should win over SDP-first PCMA: {:?}",
            bar.label
        );
        assert!(
            !bar.label.contains("PCMA"),
            "must not show SDP-first PCMA when RTP is PCMU: {:?}",
            bar.label
        );
    }

    // ── Arrow direction: response reverses the request's swimlanes ────

    /// The direct-buffer (TUI) renderer draws each arrow from src_col→dst_col,
    /// so direction is decided here. A request is A→B; its response is B→A, so
    /// the response's (src_col, dst_col) must be the request's reversed. This
    /// is the end-to-end guard the UI tests previously lacked.
    #[test]
    fn prepare_response_reverses_request_columns() {
        let theme = Theme::default();
        let o = opts(&theme);
        let msgs = vec![
            invite("cdir", 1, t0()), // request  A→B
            response("cdir", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)), // response B→A
        ];
        let (parts, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(parts.len(), 2, "two distinct endpoints expected");
        let reqm = prepared.iter().find(|m| !m.is_response).expect("request");
        let respm = prepared.iter().find(|m| m.is_response).expect("response");
        assert_ne!(
            reqm.src_col, reqm.dst_col,
            "request must span the two swimlanes"
        );
        assert_eq!(
            (respm.src_col, respm.dst_col),
            (reqm.dst_col, reqm.src_col),
            "response columns must be the reverse of the request — i.e. the arrow points the other way"
        );
    }

    // ── prepare_messages: scaled spacer insertion ─────────────────────

    /// Scaled mode inserts spacer rows for large inter-message gaps.
    #[test]
    fn prepare_scaled_inserts_spacers() {
        let theme = Theme::default();
        let mut o = opts(&theme);
        o.ts_mode = TimestampMode::Scaled;
        // Large gaps between messages → spacer rows inserted.
        let msgs = vec![
            invite("cscale", 1, t0()),
            response(
                "cscale",
                200,
                "OK",
                1,
                "INVITE",
                t0() + TimeDelta::seconds(5),
            ),
            bye("cscale", 2, t0() + TimeDelta::seconds(30)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert!(prepared.iter().any(|m| m.is_spacer), "no spacers inserted");
        // More rows than raw messages because of spacers.
        assert!(
            prepared.len() > 3,
            "expected spacer expansion, got {}",
            prepared.len()
        );
    }

    // ── fold_messages: retransmit folding ─────────────────────────────

    /// A retransmission folds into the prior original (count + label) when
    /// collapsed, and stays visible when the header is expanded.
    #[test]
    fn prepare_folds_retransmissions() {
        let theme = Theme::default();
        let o = opts(&theme);
        let mut retx = response(
            "cretx",
            200,
            "OK",
            1,
            "INVITE",
            t0() + TimeDelta::seconds(2),
        );
        retx.is_retransmission = true;
        let msgs = vec![
            invite("cretx", 1, t0()),
            response(
                "cretx",
                200,
                "OK",
                1,
                "INVITE",
                t0() + TimeDelta::seconds(1),
            ),
            retx,
        ];
        // Not expanded → the retransmission folds into the prior 200 OK.
        let (_p, folded) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(folded.len(), 2, "retx should fold away one row");
        let ok = folded.iter().find(|m| m.label == "200 OK").unwrap();
        assert_eq!(ok.folded_count, 1);
        assert!(ok.fold_label.as_deref().unwrap().contains("retx"));

        // Expanded at the fold header (the 200 OK, raw index 1) → no folding.
        let mut expanded = HashSet::new();
        expanded.insert(1usize);
        let (_p2, unfolded) = prepare_messages(&msgs, t0(), None, &o, &expanded);
        assert_eq!(unfolded.len(), 3, "expanded retx should remain visible");
    }

    /// A dialog whose retransmission sits 30s+ after its original, so Scaled
    /// mode inserts spacer rows around it.
    fn retx_msgs_with_gaps(cid: &str) -> Vec<SipMessage> {
        let mut retx = response(cid, 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(60));
        retx.is_retransmission = true;
        vec![
            invite(cid, 1, t0()),
            response(cid, 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(30)),
            retx,
        ]
    }

    /// Every timestamp mode, for mode-independence sweeps.
    const ALL_TS_MODES: [TimestampMode; 4] = [
        TimestampMode::Absolute,
        TimestampMode::DeltaPrev,
        TimestampMode::DeltaFirst,
        TimestampMode::Scaled,
    ];

    /// Message visibility must never depend on the time-unit display setting:
    /// the fold result (which rows exist) has to be identical in every
    /// TimestampMode, spacers aside.
    #[test]
    fn folding_is_identical_across_all_timestamp_modes() {
        let theme = Theme::default();
        let msgs = retx_msgs_with_gaps("cmode");
        for mode in ALL_TS_MODES {
            let mut o = opts(&theme);
            o.ts_mode = mode;
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
            let visible: Vec<_> = prepared.iter().filter(|m| !m.is_spacer).collect();
            assert_eq!(
                visible.len(),
                2,
                "{mode:?}: retx must fold to 2 visible rows"
            );
            let header = visible
                .iter()
                .find(|m| m.folded_count > 0)
                .unwrap_or_else(|| panic!("{mode:?}: fold header missing"));
            assert_eq!(header.folded_count, 1, "{mode:?}");
            assert!(
                header.fold_label.as_deref().unwrap_or("").contains("retx"),
                "{mode:?}: fold label missing"
            );
        }
    }

    /// The auth-retry collapse must also be timestamp-mode independent.
    #[test]
    fn auth_collapse_is_identical_across_all_timestamp_modes() {
        let theme = Theme::default();
        let cid = "cauthmode";
        let msgs = vec![
            register(cid, 1, None, t0()),
            response(
                cid,
                401,
                "Unauthorized",
                1,
                "REGISTER",
                t0() + TimeDelta::seconds(30),
            ),
            ack_register(cid, 1, t0() + TimeDelta::seconds(60)),
            register(
                cid,
                2,
                Some("Digest username=\"alice\""),
                t0() + TimeDelta::seconds(90),
            ),
        ];
        for mode in ALL_TS_MODES {
            let mut o = opts(&theme);
            o.ts_mode = mode;
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
            let visible: Vec<_> = prepared.iter().filter(|m| !m.is_spacer).collect();
            assert_eq!(
                visible.len(),
                1,
                "{mode:?}: auth sequence must collapse to one row"
            );
            assert_eq!(visible[0].folded_count, 4, "{mode:?}");
        }
    }

    /// `selected_msg` addresses VISIBLE rows (what the user navigates), not
    /// raw or pre-fold positions. With a fold present, visible row 1 is the
    /// 200 OK that FOLLOWS the folded retransmission; out-of-range selects
    /// nothing.
    #[test]
    fn selection_indexes_visible_rows_in_every_mode() {
        let theme = Theme::default();
        let mut retx = invite("csel", 1, t0() + TimeDelta::seconds(30));
        retx.is_retransmission = true;
        let msgs = vec![
            invite("csel", 1, t0()),
            retx,
            response(
                "csel",
                200,
                "OK",
                1,
                "INVITE",
                t0() + TimeDelta::seconds(60),
            ),
        ];
        for mode in ALL_TS_MODES {
            let mut o = opts(&theme);
            o.ts_mode = mode;
            o.selected_msg = Some(1);
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
            let selected: Vec<_> = prepared.iter().filter(|m| m.selected).collect();
            assert_eq!(selected.len(), 1, "{mode:?}: exactly one selected row");
            assert_eq!(
                selected[0].label, "200 OK",
                "{mode:?}: visible row 1 is the 200 OK (row 0 holds the fold)"
            );
        }
        // Out-of-range selection: no panic, nothing selected.
        let mut o = opts(&theme);
        o.selected_msg = Some(99);
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert!(prepared.iter().all(|m| !m.selected));
    }

    /// Every non-spacer row must carry the index of the raw message it
    /// renders, so the detail pane / Enter / diff open the message the user
    /// actually selected (RTP bars and spacers carry None).
    #[test]
    fn visible_rows_carry_raw_indices() {
        let theme = Theme::default();
        let msgs = retx_msgs_with_gaps("craw");
        for mode in ALL_TS_MODES {
            let mut o = opts(&theme);
            o.ts_mode = mode;
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
            let raw: Vec<Option<usize>> = prepared
                .iter()
                .filter(|m| !m.is_spacer)
                .map(|m| m.raw_index)
                .collect();
            assert_eq!(
                raw,
                vec![Some(0), Some(1)],
                "{mode:?}: visible rows map to raw messages 0 and 1"
            );
        }
    }

    /// Expanding a fold must reveal ALL of its retransmissions: a retx run
    /// folds into the first non-retransmission ancestor, never into an
    /// already-revealed retransmission.
    #[test]
    fn expansion_reveals_every_retransmission_in_a_run() {
        let theme = Theme::default();
        let o = opts(&theme);
        let mk_retx = |secs: i64| {
            let mut m = invite("crun", 1, t0() + TimeDelta::seconds(secs));
            m.is_retransmission = true;
            m
        };
        let msgs = vec![
            invite("crun", 1, t0()),
            mk_retx(1),
            mk_retx(2),
            response("crun", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(3)),
        ];
        // Collapsed: header shows both retransmissions folded.
        let (_p, folded) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].folded_count, 2);
        // Expanded at the header (raw 0): all four rows visible.
        let mut expanded = HashSet::new();
        expanded.insert(0usize);
        let (_p2, shown) = prepare_messages(&msgs, t0(), None, &o, &expanded);
        assert_eq!(
            shown.len(),
            4,
            "both retransmissions must be revealed, got labels: {:?}",
            shown.iter().map(|m| &m.label).collect::<Vec<_>>()
        );
    }

    /// Expansion is keyed by the fold HEADER's raw index and works in every
    /// timestamp mode; the expanded header is labelled so it can be
    /// re-collapsed.
    #[test]
    fn expansion_keyed_by_header_raw_index_across_modes() {
        let theme = Theme::default();
        let msgs = retx_msgs_with_gaps("cexp");
        let mut expanded = HashSet::new();
        expanded.insert(1usize); // raw index of the 200 OK fold header
        for mode in ALL_TS_MODES {
            let mut o = opts(&theme);
            o.ts_mode = mode;
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &expanded);
            let visible: Vec<_> = prepared.iter().filter(|m| !m.is_spacer).collect();
            assert_eq!(visible.len(), 3, "{mode:?}: expanded retx must be visible");
            let header = &visible[1];
            assert!(
                header
                    .fold_label
                    .as_deref()
                    .unwrap_or("")
                    .contains("collapse"),
                "{mode:?}: expanded header must offer re-collapse, got {:?}",
                header.fold_label
            );
        }
    }

    // ── detect_auth_sequence + fold (auth collapse) ───────────────────

    /// The REGISTER/401/ACK/REGISTER+Auth pattern is detected as a 4-message
    /// sequence; missing Authorization or too few messages is no match.
    #[test]
    fn detect_auth_sequence_register_flow() {
        let cid = "cauth";
        let msgs = vec![
            register(cid, 1, None, t0()),
            response(
                cid,
                401,
                "Unauthorized",
                1,
                "REGISTER",
                t0() + TimeDelta::milliseconds(10),
            ),
            ack_register(cid, 1, t0() + TimeDelta::milliseconds(20)),
            register(
                cid,
                2,
                Some("Digest username=\"alice\""),
                t0() + TimeDelta::milliseconds(30),
            ),
        ];
        assert_eq!(detect_auth_sequence(&msgs, 0), Some(4));

        // Without the Authorization header on the retry, it is not an auth seq.
        let no_auth = vec![
            register(cid, 1, None, t0()),
            response(
                cid,
                401,
                "Unauthorized",
                1,
                "REGISTER",
                t0() + TimeDelta::milliseconds(10),
            ),
            ack_register(cid, 1, t0() + TimeDelta::milliseconds(20)),
            register(cid, 2, None, t0() + TimeDelta::milliseconds(30)),
        ];
        assert_eq!(detect_auth_sequence(&no_auth, 0), None);

        // Too few messages.
        assert_eq!(detect_auth_sequence(&msgs[..3], 0), None);
    }

    /// The 4-message auth handshake collapses to one "(+auth)" header row,
    /// and expanding at the header shows all four rows again.
    #[test]
    fn prepare_collapses_auth_sequence() {
        let theme = Theme::default();
        let o = opts(&theme);
        let cid = "cauth2";
        let msgs = vec![
            register(cid, 1, None, t0()),
            response(
                cid,
                401,
                "Unauthorized",
                1,
                "REGISTER",
                t0() + TimeDelta::milliseconds(10),
            ),
            ack_register(cid, 1, t0() + TimeDelta::milliseconds(20)),
            register(
                cid,
                2,
                Some("Digest username=\"alice\""),
                t0() + TimeDelta::milliseconds(30),
            ),
        ];
        // Collapsed: the 4-message auth handshake folds into one header row.
        let (_p, folded) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(folded.len(), 1, "auth sequence should collapse to one row");
        assert_eq!(folded[0].folded_count, 4);
        assert!(
            folded[0].label.contains("(+auth)"),
            "got: {}",
            folded[0].label
        );
        assert!(
            folded[0]
                .fold_label
                .as_deref()
                .unwrap()
                .contains("auth retry"),
            "missing auth fold label"
        );

        // Expanded at index 0 → all four rows shown.
        let mut expanded = HashSet::new();
        expanded.insert(0usize);
        let (_p2, shown) = prepare_messages(&msgs, t0(), None, &o, &expanded);
        assert_eq!(
            shown.len(),
            4,
            "expanded auth sequence should show all rows"
        );
    }

    // ── extract_codec_list: rtpmap and static-PT fallback ─────────────

    /// Codec names come from `a=rtpmap` when present, else from the static
    /// payload-type number table.
    #[test]
    fn extract_codec_list_uses_rtpmap_then_static_fallback() {
        // With rtpmap entries → encoding names taken verbatim.
        let with_map = invite_with_sdp(
            "ccodec",
            1,
            "m=audio 20000 RTP/AVP 0 8",
            &["a=rtpmap:0 PCMU/8000", "a=rtpmap:8 PCMA/8000"],
            t0(),
        );
        let session = with_map.sdp().expect("sdp");
        let codecs = extract_codec_list(&session);
        assert_eq!(codecs, vec!["PCMU".to_string(), "PCMA".to_string()]);

        // No rtpmap → static payload-type number mapping.
        let no_map = invite_with_sdp("ccodec2", 1, "m=audio 20000 RTP/AVP 0 9 18 101", &[], t0());
        let session2 = no_map.sdp().expect("sdp2");
        let codecs2 = extract_codec_list(&session2);
        assert_eq!(
            codecs2,
            vec![
                "PCMU".to_string(),
                "G722".to_string(),
                "G729".to_string(),
                "telephone-event".to_string()
            ]
        );
    }

    // ── color modes / selection state ─────────────────────────────────

    /// CallId mode marks the selected row and its same-leg peer Related;
    /// CSeq mode with DeltaPrev timestamps renders without panicking.
    #[test]
    fn prepare_color_modes_and_selection() {
        let theme = Theme::default();
        let msgs = vec![
            invite("csel", 1, t0()),
            response("csel", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
        ];

        // CallId color mode + a selection on row 0.
        let mut o = opts(&theme);
        o.color_mode = ColorMode::CallId;
        o.selected_msg = Some(0);
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert!(prepared[0].selected);
        assert_eq!(prepared[0].selection_state, SelectionState::Selected);
        // Row 1 shares the same endpoint pair → Related.
        assert_eq!(prepared[1].selection_state, SelectionState::Related);

        // CSeq color mode just needs to run without panicking.
        let mut o2 = opts(&theme);
        o2.color_mode = ColorMode::CSeq;
        o2.ts_mode = TimestampMode::DeltaPrev;
        let (_p2, prepared2) = prepare_messages(&msgs, t0(), None, &o2, &HashSet::new());
        assert_eq!(prepared2.len(), 2);
        // DeltaPrev timestamps are right-aligned "+x.xxxs" strings.
        assert!(prepared2[1].timestamp.contains('+'));
    }

    // ── Style pinning ────────────────────────────────────────────────
    // Characterization net for the layout/style split (WS5f) and the
    // ladder memoization (WS4.3): pins the STYLE outputs, which the
    // text-only snapshot tests cannot see.

    /// The `cid_colors` rotation used for CallId/CSeq arrow coloring.
    /// Mirrored here so a silent change to the table or its indexing
    /// breaks a test rather than shipping unnoticed.
    const CID_COLORS: [Color; 6] = [
        Color::Green,
        Color::Blue,
        Color::Yellow,
        Color::Magenta,
        Color::Cyan,
        Color::Red,
    ];

    /// Absolute-mode timestamps render muted and Method-mode arrows match
    /// `message_style`.
    #[test]
    fn styles_absolute_timestamps_muted_and_method_arrows() {
        let theme = Theme::default();
        let msgs = vec![
            invite("sty1", 1, t0()),
            response("sty1", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
        ];
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &opts(&theme), &HashSet::new());
        assert_eq!(prepared.len(), 2);
        for (fm, msg) in prepared.iter().zip(&msgs) {
            assert_eq!(
                fm.timestamp_style.fg,
                Some(theme.muted),
                "absolute timestamps render muted"
            );
            assert_eq!(
                fm.style,
                message_style(msg, &theme),
                "Method color mode arrows use message_style"
            );
        }
    }

    /// DeltaPrev timestamps carry the color of their delta-magnitude bucket.
    #[test]
    fn styles_delta_prev_timestamps_use_delta_buckets() {
        let theme = Theme::default();
        let msgs = vec![
            invite("sty2", 1, t0()),
            // +50ms → good bucket; +500ms → warning; +2s → bad.
            response(
                "sty2",
                180,
                "Ringing",
                1,
                "INVITE",
                t0() + TimeDelta::milliseconds(50),
            ),
            response(
                "sty2",
                200,
                "OK",
                1,
                "INVITE",
                t0() + TimeDelta::milliseconds(550),
            ),
            ack("sty2", 1, t0() + TimeDelta::milliseconds(2550)),
        ];
        let mut o = opts(&theme);
        o.ts_mode = TimestampMode::DeltaPrev;
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(prepared[1].timestamp_style, delta_style(50, &theme));
        assert_eq!(prepared[2].timestamp_style, delta_style(500, &theme));
        assert_eq!(prepared[3].timestamp_style, delta_style(2000, &theme));
    }

    /// CallId mode colors every row of a dialog identically, indexed by the
    /// Call-ID byte sum into the rotation palette.
    #[test]
    fn styles_callid_mode_color_is_callid_byte_sum() {
        let theme = Theme::default();
        let cid = "sty3@test";
        let msgs = vec![
            invite(cid, 1, t0()),
            response(cid, 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(1)),
        ];
        let mut o = opts(&theme);
        o.color_mode = ColorMode::CallId;
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let i = cid.bytes().fold(0usize, |a, b| a.wrapping_add(b as usize)) % CID_COLORS.len();
        for fm in &prepared {
            assert_eq!(
                fm.style.fg,
                Some(CID_COLORS[i]),
                "CallId mode colors every row of a dialog identically by call-id byte sum"
            );
        }
    }

    /// CSeq mode indexes the rotation palette by the CSeq number.
    #[test]
    fn styles_cseq_mode_color_indexes_by_cseq_number() {
        let theme = Theme::default();
        let msgs = vec![
            invite("sty4", 1, t0()),
            invite("sty4", 2, t0() + TimeDelta::seconds(1)),
        ];
        let mut o = opts(&theme);
        o.color_mode = ColorMode::CSeq;
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        assert_eq!(prepared[0].style.fg, Some(CID_COLORS[1]));
        assert_eq!(prepared[1].style.fg, Some(CID_COLORS[2]));
    }

    /// SDP extra lines render muted + italic in both Summary and Full modes.
    #[test]
    fn styles_sdp_lines_muted_italic_in_summary_and_full() {
        let theme = Theme::default();
        let msgs = vec![invite_with_sdp(
            "sty5",
            1,
            "m=audio 5004 RTP/AVP 0",
            &["a=rtpmap:0 PCMU/8000"],
            t0(),
        )];
        for mode in [SdpDisplayMode::Summary, SdpDisplayMode::Full] {
            let mut o = opts(&theme);
            o.sdp_mode = mode;
            let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
            assert!(
                !prepared[0].extra_lines.is_empty(),
                "{mode:?} must add SDP info lines"
            );
            for (text, style) in &prepared[0].extra_lines {
                assert_eq!(style.fg, Some(theme.muted), "SDP line muted: {text:?}");
                assert!(
                    style.add_modifier.contains(Modifier::ITALIC),
                    "SDP line italic: {text:?}"
                );
            }
        }
    }

    /// An RTP bar row and its absolute-mode timestamp both use the accent
    /// color.
    #[test]
    fn styles_rtp_bar_row_accent() {
        let theme = Theme::default();
        let msgs = vec![
            invite_with_sdp(
                "sty6",
                1,
                "m=audio 5004 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0(),
            ),
            response_with_sdp(
                "sty6",
                200,
                "OK",
                1,
                "INVITE",
                "m=audio 5006 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::seconds(1),
            ),
            ack("sty6", 1, t0() + TimeDelta::seconds(2)),
        ];
        let mut o = opts(&theme);
        o.show_rtp = true;
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let bar = prepared
            .iter()
            .find(|fm| fm.is_rtp_bar)
            .expect("INVITE/200/ACK with media must draw an RTP bar");
        assert_eq!(bar.style.fg, Some(theme.accent));
        assert_eq!(
            bar.timestamp_style.fg,
            Some(theme.accent),
            "absolute-mode RTP bar timestamp uses accent, not muted"
        );
    }

    /// Scaled-mode spacer rows render muted + dim, timestamp included.
    #[test]
    fn styles_scaled_spacers_muted_dim() {
        let theme = Theme::default();
        let msgs = vec![
            invite("sty7", 1, t0()),
            response("sty7", 200, "OK", 1, "INVITE", t0() + TimeDelta::seconds(2)),
        ];
        let mut o = opts(&theme);
        o.ts_mode = TimestampMode::Scaled;
        let (_p, prepared) = prepare_messages(&msgs, t0(), None, &o, &HashSet::new());
        let spacers: Vec<_> = prepared.iter().filter(|fm| fm.is_spacer).collect();
        assert!(!spacers.is_empty(), "a 2s gap must insert spacer rows");
        for sp in spacers {
            assert_eq!(sp.style.fg, Some(theme.muted));
            assert!(sp.style.add_modifier.contains(Modifier::DIM));
            assert_eq!(sp.timestamp_style, sp.style);
        }
    }

    // ── WS5f layout/style split ──────────────────────────────────────

    /// `layout()` is theme-free and `style()` is pure over (layout rows,
    /// style inputs): styling ONE cached layout must reproduce the one-shot
    /// `prepare_messages` output exactly — for every timestamp mode, color
    /// mode, theme and selection. This is the contract the WS4.3c ladder
    /// cache stands on: layout computed once, style re-run per frame.
    #[test]
    fn style_over_one_layout_reproduces_prepare_messages() {
        // A scenario touching every styled surface: SDP info lines, an RTP
        // bar (INVITE/200/ACK with media), a PDD note on the 180, delta
        // buckets, and a 3s gap for Scaled-mode spacers.
        let msgs = vec![
            invite_with_sdp(
                "split@t",
                1,
                "m=audio 5004 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0(),
            ),
            response(
                "split@t",
                180,
                "Ringing",
                1,
                "INVITE",
                t0() + TimeDelta::milliseconds(80),
            ),
            response_with_sdp(
                "split@t",
                200,
                "OK",
                1,
                "INVITE",
                "m=audio 5006 RTP/AVP 0",
                &["a=rtpmap:0 PCMU/8000"],
                t0() + TimeDelta::milliseconds(650),
            ),
            ack("split@t", 1, t0() + TimeDelta::milliseconds(700)),
            bye("split@t", 2, t0() + TimeDelta::seconds(3)),
        ];
        let alt = Theme {
            accent: Color::Rgb(1, 2, 3),
            muted: Color::Rgb(4, 5, 6),
            good: Color::Rgb(7, 8, 9),
            warning: Color::Rgb(10, 11, 12),
            bad: Color::Rgb(13, 14, 15),
            foreground: Color::Rgb(16, 17, 18),
            ..Theme::default()
        };
        let themes = [Theme::default(), alt];

        for ts_mode in [
            TimestampMode::Absolute,
            TimestampMode::DeltaPrev,
            TimestampMode::DeltaFirst,
            TimestampMode::Scaled,
        ] {
            // ONE layout per timestamp mode; nothing varied below may
            // require re-layout.
            let base = {
                let mut o = opts(&themes[0]);
                o.ts_mode = ts_mode;
                o.sdp_mode = SdpDisplayMode::Summary;
                o.show_rtp = true;
                o
            };
            let (lp, rows) = layout(
                &msgs,
                t0(),
                Some(80),
                &LayoutOptions::from(&base),
                &HashSet::new(),
            );
            for theme in &themes {
                for color_mode in [ColorMode::Method, ColorMode::CallId, ColorMode::CSeq] {
                    for selected_msg in [None, Some(2)] {
                        let mut o = opts(theme);
                        o.ts_mode = ts_mode;
                        o.sdp_mode = SdpDisplayMode::Summary;
                        o.show_rtp = true;
                        o.color_mode = color_mode;
                        o.selected_msg = selected_msg;
                        let (pp, full) =
                            prepare_messages(&msgs, t0(), Some(80), &o, &HashSet::new());
                        let styled = style(&rows, &StyleOptions::from(&o));
                        assert_eq!(lp, pp, "participants must match (ts={ts_mode:?})");
                        assert_eq!(
                            styled, full,
                            "style(layout) must equal prepare_messages \
                             (ts={ts_mode:?} color={color_mode:?} sel={selected_msg:?})"
                        );
                    }
                }
            }
        }
    }

    // ── format_sdp_codecs ────────────────────────────────────────────

    /// With `a=rtpmap` present, encoding names are used verbatim.
    #[test]
    fn format_sdp_codecs_prefers_rtpmap_encodings() {
        // When a=rtpmap is present, the encoding names are used verbatim.
        let body = b"v=0\r\n\
            m=audio 5004 RTP/AVP 0 8 96\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=rtpmap:96 opus/48000/2\r\n";
        let session = sdp::parse_sdp(body).expect("valid sdp");
        assert_eq!(format_sdp_codecs(&session), "PCMU, PCMA, opus");
    }

    /// Without `a=rtpmap`, static payload types map to names and unknown
    /// dynamic types pass through as numbers.
    #[test]
    fn format_sdp_codecs_maps_bare_payload_types_and_passes_through_unknown() {
        // No a=rtpmap → fall back to static payload-type numbers. This is the
        // branch covering the numeric→name table and the `o => o` pass-through
        // for an unrecognised dynamic type (99).
        let body = b"v=0\r\n\
            m=audio 5004 RTP/AVP 0 8 9 18 4 3 101 99\r\n";
        let session = sdp::parse_sdp(body).expect("valid sdp");
        assert_eq!(
            format_sdp_codecs(&session),
            "PCMU, PCMA, G722, G729, G723, GSM, telephone-event, 99"
        );
    }
}
