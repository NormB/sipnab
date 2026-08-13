// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP stream list view — color-coded stream table.
//!
//! Displays all tracked RTP streams with columns for SSRC, codec, source,
//! destination, packets, jitter, loss, duration, associated dialog, and
//! health status. Rows are color-coded by quality thresholds.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Cell, Row, Table, TableState};

use crate::rtp::stream::RtpStream;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::FilterExpr;

// ── Quality thresholds ──────────────────────────────────────────────

// The bands moved to [`crate::rtp::bands::QualityBands`]. Four views banded
// these numbers independently and disagreed — 25 ms jitter rendered Good here
// and Warning on the dashboard, for the same stream in the same session — so
// the boundaries now live in one place that every view reads.

// ── Stream health ───────────────────────────────────────────────────

/// Quality classification for an RTP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamHealth {
    /// Jitter < 30ms, loss < 1%.
    Good,
    /// Jitter < 50ms, loss < 5%.
    Warning,
    /// Above warning thresholds.
    Bad,
    /// No associated dialog after orphan timeout.
    Orphaned,
}

/// Classify stream health based on jitter and loss metrics.
///
/// Orphaned streams win outright; otherwise the loss percentage
/// ([`RtpStream::loss_percent`] — lost over received plus lost) and the jitter
/// are compared against the SESSION's bands, the worse classification
/// winning. Pure.
///
/// The bands arrive as an argument rather than as a `::default()` built here.
/// A view that constructs its own band set is a view that can disagree with
/// the pane beside it, and the operator's `[quality]` settings would reach
/// only the call sites that remembered to ask.
///
/// The loss arithmetic itself is deliberately NOT here. A `loss_percent` free
/// function used to sit in this file calling itself the single source of truth
/// while two byte-identical copies lived elsewhere; it is now
/// [`RtpStream::loss_percent`], on the type that owns the two counters, where
/// `src/output/` can reach it without a `pub(in crate::tui)` carve-out.
pub fn classify_stream(
    stream: &RtpStream,
    bands: &crate::rtp::bands::QualityBands,
) -> StreamHealth {
    if stream.orphaned {
        return StreamHealth::Orphaned;
    }
    let loss_pct = stream.loss_percent();
    // Worst of the two dimensions wins: a stream with clean jitter and 6% loss
    // is not a healthy stream.
    use crate::rtp::bands::Band;
    match (bands.jitter(stream.jitter), bands.loss(loss_pct)) {
        (Band::Bad, _) | (_, Band::Bad) => StreamHealth::Bad,
        (Band::Warning, _) | (_, Band::Warning) => StreamHealth::Warning,
        _ => StreamHealth::Good,
    }
}

// ── Stream list state ───────────────────────────────────────────────

/// Persistent state for the stream list view.
pub struct StreamListState {
    /// ratatui table widget state.
    table_state: TableState,
}

impl StreamListState {
    /// Create a new stream list state.
    pub fn new() -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self { table_state }
    }

    /// Return the currently selected row index.
    pub fn selected(&self) -> usize {
        self.table_state.selected().unwrap_or(0)
    }

    /// Move selection up by one row.
    pub fn move_up(&mut self) {
        let current = self.selected();
        if current > 0 {
            self.table_state.select(Some(current - 1));
        }
    }

    /// Move selection down by one row, clamped to the last item.
    pub fn move_down(&mut self, item_count: usize) {
        if item_count == 0 {
            return;
        }
        let current = self.selected();
        if current + 1 < item_count {
            self.table_state.select(Some(current + 1));
        }
    }

    /// Move selection to the first row.
    pub fn move_to_top(&mut self) {
        self.table_state.select(Some(0));
    }

    /// Move selection up by a page (20 rows).
    pub fn page_up(&mut self) {
        let current = self.selected();
        self.table_state.select(Some(current.saturating_sub(20)));
    }

    /// Move selection down by a page (20 rows), clamped to the last item.
    pub fn page_down(&mut self, item_count: usize) {
        if item_count == 0 {
            return;
        }
        let current = self.selected();
        self.table_state
            .select(Some((current + 20).min(item_count - 1)));
    }

    /// Move selection to the last row.
    pub fn move_to_bottom(&mut self, item_count: usize) {
        if item_count > 0 {
            self.table_state.select(Some(item_count - 1));
        }
    }
}

impl Default for StreamListState {
    /// Equivalent to `StreamListState::new()`: first row selected.
    fn default() -> Self {
        Self::new()
    }
}

// ── Rendering ───────────────────────────────────────────────────────

/// Display parameters for the stream list view (mirrors
/// `crate::tui::call_list::CallListDisplay`).
pub struct StreamListDisplay<'a> {
    /// Color theme used for all styling.
    pub theme: &'a super::Theme,
    /// Resolver mapping endpoint addresses to user-assigned names.
    pub resolver: &'a crate::names::NameResolver,
    /// How endpoint names are displayed (off / name only / name+address).
    pub name_mode: crate::names::NameMode,
    /// Stream keys in display order, derived once per tick by
    /// `App::sync_caches` — the render must not re-filter the store.
    pub displayed: &'a [crate::rtp::stream::StreamKey],
    /// The session's quality bands, resolved once at startup.
    pub quality_bands: &'a crate::rtp::bands::QualityBands,
}

// Same "derived once per tick" property as the call list (thread-local so
// the parallel test runner cannot cross-talk).
#[cfg(test)]
thread_local! {
    /// Test-only invocation counter for `displayed_streams`, used to assert
    /// the list is derived once per tick rather than once per render.
    pub(crate) static DISPLAYED_STREAMS_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Case-insensitive substring match over the fields the stream table shows:
/// SSRC (hex, as displayed), codec, source/destination `ip:port`, and the
/// associated dialog Call-ID.
///
/// # Arguments
/// * `stream` - Stream whose displayed fields are tested.
/// * `query_lower` - Search query, already lowercased by the caller.
///
/// # Returns
/// `true` when any displayed field contains the query (or the query is
/// empty). Pure.
pub fn stream_matches_search(stream: &RtpStream, query_lower: &str) -> bool {
    if query_lower.is_empty() {
        return true;
    }
    let ssrc = format!("{:08X}", stream.key.ssrc).to_ascii_lowercase();
    if ssrc.contains(query_lower) {
        return true;
    }
    if let Some(c) = &stream.codec
        && c.to_ascii_lowercase().contains(query_lower)
    {
        return true;
    }
    if stream
        .key
        .src
        .to_string()
        .to_ascii_lowercase()
        .contains(query_lower)
        || stream
            .key
            .dst
            .to_string()
            .to_ascii_lowercase()
            .contains(query_lower)
    {
        return true;
    }
    if let Some(cid) = &stream.associated_dialog
        && cid.to_ascii_lowercase().contains(query_lower)
    {
        return true;
    }
    false
}

/// The stream rows the table displays: search-narrowed and — when the SIP
/// display filter is active — restricted through each stream's associated
/// dialog. Streams with no (or a vanished) dialog association are kept: a
/// SIP filter cannot judge them.
///
/// Single source of truth for rendering, navigation clamping and selection
/// resolution, mirroring `call_list::displayed_dialogs`.
///
/// # Arguments
/// * `streams` - Candidate streams in store iteration order.
/// * `dialog_store` - Dialog store for filter evaluation, if available.
/// * `filter` - Active SIP display filter, if any.
/// * `search_query` - Raw (not yet lowercased) search text.
///
/// # Returns
/// References to the streams that pass both the search and the filter, in
/// input order.
///
/// # Side effects
/// In test builds, increments the `DISPLAYED_STREAMS_CALLS` counter.
pub fn displayed_streams<'a>(
    streams: impl IntoIterator<Item = &'a RtpStream>,
    dialog_store: Option<&DialogStore>,
    filter: Option<&FilterExpr>,
    search_query: &str,
) -> Vec<&'a RtpStream> {
    #[cfg(test)]
    DISPLAYED_STREAMS_CALLS.with(|c| c.set(c.get() + 1));
    let q = search_query.to_ascii_lowercase();
    streams
        .into_iter()
        .filter(|s| stream_matches_search(s, &q))
        .filter(|s| {
            let (Some(f), Some(ds)) = (filter, dialog_store) else {
                return true;
            };
            let Some(cid) = &s.associated_dialog else {
                return true;
            };
            match ds.get(cid) {
                // Holding a stream IS the capture having observed RTP.
                Some(dialog) => {
                    f.matches_dialog(dialog, &[s], crate::rtp::diagnosis::CaptureMedia::Observed)
                }
                None => true,
            }
        })
        .collect()
}

/// Render the RTP stream list table into the given area.
///
/// Uses sngrep-style: borderless, bold-on-cyan header, reverse-video highlight.
/// No title line -- status is rendered separately at the top of the screen.
/// Only the visible viewport window is formatted (placeholder rows keep the
/// stateful selection index correct); keys whose streams were evicted from
/// the store drop out silently.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Main-pane area for the table.
/// * `state` - Stream list state; the table's inner offset is updated.
/// * `store` - Stream store snapshot the displayed keys resolve against.
/// * `display` - Theme, name resolution and the pre-derived key order.
///
/// # Side effects
/// Draws to `frame` and mutates `state.table_state` (stateful widget
/// offset/selection bookkeeping) during rendering.
pub fn render_stream_list(
    frame: &mut Frame,
    area: Rect,
    state: &mut StreamListState,
    store: &StreamStore,
    display: &StreamListDisplay,
) {
    let StreamListDisplay {
        theme,
        resolver,
        name_mode,
        displayed,
        quality_bands,
    } = *display;
    // The entire area is used for the table (no title line)
    let table_area = area;

    // sngrep header style: bold on header-color background
    let header_style = Style::default()
        .bg(theme.header)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from("SSRC"),
        Cell::from("Codec"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Pkts"),
        Cell::from("Jitter"),
        Cell::from("Loss"),
        Cell::from("Duration"),
        Cell::from("Dialog"),
        Cell::from("Status"),
    ])
    .style(header_style)
    .bottom_margin(0);

    // Same displayed list the navigation and selection resolution use,
    // derived once per tick in sync_caches — resolve keys, don't re-filter.
    let total_streams = displayed.len();

    // Viewport windowing: only format visible rows to avoid O(N) formatting
    // at 50K streams. Compute scroll offset from table state.
    let visible_height = table_area.height.saturating_sub(2) as usize; // header + margin
    let selected = state.table_state.selected().unwrap_or(0);
    // Clamp: `selected` may be stale from before the displayed list shrank
    // (narrowed search, evicted streams), and a zero-height viewport would
    // otherwise push the window start past the end of `streams`.
    let scroll_offset = if visible_height > 0 && selected >= visible_height {
        selected - visible_height + 1
    } else {
        0
    }
    .min(total_streams.saturating_sub(1));
    let visible_end = (scroll_offset + visible_height).min(total_streams);
    // Resolve only the visible window's keys (evicted keys drop out).
    let visible_streams: Vec<&RtpStream> = displayed[scroll_offset..visible_end]
        .iter()
        .filter_map(|k| store.get(k))
        .collect();

    // Build placeholder rows for items above the viewport (needed for
    // ratatui's StatefulWidget to keep selection index correct)
    let mut rows: Vec<Row> = Vec::with_capacity(total_streams.min(scroll_offset + visible_height));
    for _ in 0..scroll_offset {
        rows.push(Row::new(vec![Cell::from("")]));
    }

    // Format only the visible rows
    for stream in visible_streams {
        let health = classify_stream(stream, quality_bands);
        let loss_pct = stream.loss_percent();

        let duration = {
            let diff = stream.last_seen.signed_duration_since(stream.first_seen);
            let secs = diff.num_seconds();
            if secs < 60 {
                format!("{}s", secs)
            } else {
                format!("{}m{}s", secs / 60, secs % 60)
            }
        };

        let dialog_id = stream
            .associated_dialog
            .as_deref()
            .unwrap_or("-")
            .chars()
            .take(16)
            .collect::<String>();

        let status_label = match health {
            StreamHealth::Good => "OK",
            StreamHealth::Warning => "WARN",
            StreamHealth::Bad => "BAD",
            StreamHealth::Orphaned => "ORPHAN",
        };

        let row = Row::new(vec![
            Cell::from(Span::raw(format!("{:08X}", stream.key.ssrc))),
            Cell::from(Span::raw(stream.codec.as_deref().unwrap_or("?"))),
            Cell::from(Span::raw(resolver.label_socket(stream.key.src, name_mode))),
            Cell::from(Span::raw(resolver.label_socket(stream.key.dst, name_mode))),
            Cell::from(Span::raw(stream.packet_count.to_string())),
            Cell::from(Span::raw(format!("{:.1}ms", stream.jitter))),
            Cell::from(Span::raw(format!("{:.1}%", loss_pct))),
            Cell::from(Span::raw(duration)),
            Cell::from(Span::raw(dialog_id)),
            Cell::from(Span::styled(status_label, health_style(health, theme))),
        ]);

        rows.push(row.style(health_row_style(health, theme)));
    }

    let widths = [
        Constraint::Length(10), // SSRC
        Constraint::Length(8),  // Codec
        Constraint::Length(22), // Source
        Constraint::Length(22), // Destination
        Constraint::Length(8),  // Pkts
        Constraint::Length(9),  // Jitter
        Constraint::Length(7),  // Loss
        Constraint::Length(9),  // Duration
        Constraint::Length(18), // Dialog
        Constraint::Length(7),  // Status
    ];

    // sngrep-style: no borders, reverse video for selected row
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    frame.render_stateful_widget(table, table_area, &mut state.table_state);
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Return a style for the health status label: good/warning/bad/muted per
/// health, with warning and bad additionally bold. Pure.
fn health_style(health: StreamHealth, theme: &super::Theme) -> Style {
    match health {
        StreamHealth::Good => Style::default().fg(theme.good),
        StreamHealth::Warning => Style::default()
            .fg(theme.warning)
            .add_modifier(Modifier::BOLD),
        StreamHealth::Bad => Style::default().fg(theme.bad).add_modifier(Modifier::BOLD),
        StreamHealth::Orphaned => Style::default().fg(theme.muted),
    }
}

/// Return a whole-row style for the given stream health (same colors as
/// `health_style` but never bold). Pure.
fn health_row_style(health: StreamHealth, theme: &super::Theme) -> Style {
    match health {
        StreamHealth::Good => Style::default().fg(theme.good),
        StreamHealth::Warning => Style::default().fg(theme.warning),
        StreamHealth::Bad => Style::default().fg(theme.bad),
        StreamHealth::Orphaned => Style::default().fg(theme.muted),
    }
}

/// Unit tests for stream-list navigation, display derivation and health
/// classification.
#[cfg(test)]
mod tests {
    use super::*;

    /// Up/down/top/bottom navigation moves and clamps the selection.
    #[test]
    fn stream_list_state_navigation() {
        let mut state = StreamListState::new();
        assert_eq!(state.selected(), 0);

        state.move_down(10);
        assert_eq!(state.selected(), 1);

        state.move_up();
        assert_eq!(state.selected(), 0);

        state.move_to_bottom(10);
        assert_eq!(state.selected(), 9);

        state.move_to_top();
        assert_eq!(state.selected(), 0);
    }

    /// Page up/down move by 20 rows, clamp to the last row, and no-op on
    /// an empty list.
    #[test]
    fn stream_list_paging_clamps() {
        let mut state = StreamListState::new();
        state.page_down(50);
        assert_eq!(state.selected(), 20);
        state.page_down(25);
        assert_eq!(state.selected(), 24, "clamps to last row");
        state.page_up();
        assert_eq!(state.selected(), 4);
        state.page_down(0); // empty list: no-op
        assert_eq!(state.selected(), 4);
    }

    /// Moving down on an empty list keeps the selection at 0.
    #[test]
    fn stream_list_state_empty() {
        let mut state = StreamListState::new();
        state.move_down(0); // no items
        assert_eq!(state.selected(), 0);
    }

    /// Build a fixture stream 10.0.0.1:`sport` → 10.0.0.2:30000 with the
    /// given SSRC and optional codec / associated-dialog Call-ID.
    fn mk_stream(ssrc: u32, sport: u16, codec: Option<&str>, dialog: Option<&str>) -> RtpStream {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::StreamKey;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let key = StreamKey {
            ssrc,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), sport),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
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
            ssrc,
            payload_offset: 12,
        };
        let mut st = RtpStream::new(key, &hdr, chrono::Utc::now());
        st.codec = codec.map(str::to_string);
        st.associated_dialog = dialog.map(str::to_string);
        st
    }

    /// Search narrows by the fields the table shows (codec, SSRC hex,
    /// dialog); adversarial input must not panic and simply matches
    /// nothing.
    #[test]
    fn displayed_streams_honors_search() {
        let a = mk_stream(0xAABBCCDD, 20000, Some("PCMU"), None);
        let b = mk_stream(0x11223344, 20002, Some("G722"), Some("call-x@test"));
        let all = [&a, &b];

        let by_codec = displayed_streams(all, None, None, "g722");
        assert_eq!(by_codec.len(), 1);
        assert_eq!(by_codec[0].key.ssrc, 0x11223344);

        let by_ssrc = displayed_streams(all, None, None, "aabbccdd");
        assert_eq!(by_ssrc.len(), 1, "SSRC hex must be searchable");

        let by_dialog = displayed_streams(all, None, None, "call-x");
        assert_eq!(by_dialog.len(), 1);

        let none = displayed_streams(all, None, None, "no-match");
        assert!(none.is_empty());

        // Adversarial: backslashes / quotes / empty never panic.
        for q in ["a\\b", "'\"", ""] {
            let _ = displayed_streams(all, None, None, q);
        }
        assert_eq!(displayed_streams(all, None, None, "").len(), 2);
    }

    /// A SIP display filter restricts streams via their associated dialog;
    /// unassociated streams and streams whose dialog vanished are kept (a
    /// SIP filter cannot judge them).
    #[test]
    fn displayed_streams_honors_sip_filter() {
        use crate::capture::parse::TransportProto;
        use crate::sip::dialog_store::DialogStore;
        use crate::sip::dsl::FilterExpr;
        use crate::sip::parser::parse_sip;
        use std::net::{IpAddr, Ipv4Addr};

        let raw = crate::test_utils::build_sip_message(
            "INVITE sip:2002@example.com SIP/2.0",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:2002@example.com>",
                "Call-ID: call-x@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let msg = parse_sip(
            &raw,
            chrono::Utc::now(),
            lo,
            lo,
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse");
        let mut ds = DialogStore::new(10, false);
        ds.process_message(msg);

        let matching = mk_stream(1, 20000, Some("PCMU"), Some("call-x@test"));
        let other = mk_stream(2, 20002, Some("PCMU"), Some("unknown@test"));
        let orphan = mk_stream(3, 20004, Some("PCMU"), None);
        let all = [&matching, &other, &orphan];

        let f = FilterExpr::parse("from.user == '1001'").expect("parse filter");
        let shown = displayed_streams(all, Some(&ds), Some(&f), "");
        let ssrcs: Vec<u32> = shown.iter().map(|s| s.key.ssrc).collect();
        assert!(ssrcs.contains(&1), "stream of the matching dialog stays");
        assert!(ssrcs.contains(&3), "unassociated stream stays");
        assert!(
            ssrcs.contains(&2),
            "a stream pointing at a vanished dialog cannot be judged -> kept"
        );

        let f2 = FilterExpr::parse("from.user == '9999'").expect("parse filter");
        let shown = displayed_streams(all, Some(&ds), Some(&f2), "");
        let ssrcs: Vec<u32> = shown.iter().map(|s| s.key.ssrc).collect();
        assert!(!ssrcs.contains(&1), "dialog fails the filter -> hidden");
        assert!(ssrcs.contains(&3), "unassociated stream still shown");
    }

    /// A fresh stream with no jitter or loss classifies as Good.
    #[test]
    fn classify_stream_good() {
        use crate::rtp::parser::RtpHeader;
        use crate::rtp::stream::{RtpStream, StreamKey};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let key = StreamKey {
            ssrc: 0x1234,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30000),
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
            ssrc: 0x1234,
            payload_offset: 12,
        };
        let stream = RtpStream::new(key, &hdr, chrono::Utc::now());
        assert_eq!(
            classify_stream(&stream, &crate::rtp::bands::QualityBands::default()),
            StreamHealth::Good
        );
    }
}
