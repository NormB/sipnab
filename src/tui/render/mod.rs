// SPDX-License-Identifier: MIT OR Apache-2.0

//! All TUI rendering: the main view dispatch plus the per-view renderers
//! it owns (statistics, message diff). Status lines / f-key bar and popup
//! rendering live in the submodules.

use super::*;

/// Modal popup rendering (save, filter, settings, file-open, name-address).
mod popups;
/// Status lines and the context-sensitive F-key bar.
mod status;

pub(in crate::tui) use popups::*;
pub(in crate::tui) use status::*;

/// Geometry- and content-dependent values computed during a render pass:
/// clamped scroll offsets and the call-flow row caches. The renderer draws
/// with the corrected values immediately but does not write App state; the
/// event loop persists them via `App::apply_render_feedback` right after
/// the frame. `None` fields (views that didn't render) leave state as is.
#[derive(Debug, Default)]
pub(in crate::tui) struct RenderFeedback {
    /// Content-clamped scroll of the stream detail view (rows).
    pub(in crate::tui) stream_detail_scroll: Option<usize>,
    /// Selection-following, content-clamped ladder scroll (ladder rows).
    pub(in crate::tui) flow_scroll: Option<usize>,
    /// Clamped vertical scroll of the call-flow detail pane.
    pub(in crate::tui) flow_detail_scroll: Option<u16>,
    /// Clamped horizontal scroll of the call-flow detail pane.
    pub(in crate::tui) flow_detail_hscroll: Option<u16>,
    /// `(cached_msg_count, cached_rtp_bar_indices, cached_raw_indices)`.
    pub(in crate::tui) flow_caches:
        Option<(usize, std::collections::HashSet<usize>, Vec<Option<usize>>)>,
    /// Clamped scroll of the raw-message / combined-detail views.
    pub(in crate::tui) raw_msg_scroll: Option<u16>,
    /// Clamped scroll of the message diff view.
    pub(in crate::tui) diff_scroll: Option<u16>,
    /// Clamped scroll of the help view.
    pub(in crate::tui) help_scroll: Option<u16>,
    /// Clamped scroll of the statistics view.
    pub(in crate::tui) stats_scroll: Option<u16>,
}

/// Render the entire application frame based on the current view.
///
/// The caller (`draw_frame`) already holds read guards on both stores for
/// the whole frame, passed in as `ds`/`ss` — a consistent snapshot, no
/// per-arm lock acquisition. Locking (and skipping the tick on
/// contention, BEFORE anything is flushed) is the caller's job: a frame
/// that rendered with a missing store used to flush a blank main pane,
/// which the next frame repainted — a visible flicker on busy captures.
///
/// Takes `&mut App` only because the call/stream list tables are ratatui
/// stateful widgets (their inner offset state updates during render);
/// everything else is read-only. State writes are returned as
/// `RenderFeedback`, never applied here — `App::sync_caches` (pre-draw)
/// and `App::apply_render_feedback` (post-draw) are the writers.
///
/// # Arguments
/// * `frame` - Frame covering the whole terminal.
/// * `app` - Application state; mutable only for stateful table widgets.
/// * `ds` - Dialog store read guard held by the caller for the frame.
/// * `ss` - Stream store read guard held by the caller for the frame.
///
/// # Returns
/// The `RenderFeedback` collected from the view that rendered (clamped
/// scrolls, flow caches); default-`None` fields for views that did not.
///
/// # Side effects
/// Draws the full frame (status lines, current view, f-key bar, popup
/// overlays) and updates the inner offsets of the call/stream list table
/// states during stateful rendering.
pub(in crate::tui) fn render_app(
    frame: &mut ratatui::Frame,
    app: &mut App,
    ds: &DialogStore,
    ss: &StreamStore,
) -> RenderFeedback {
    let mut fb = RenderFeedback::default();
    let area = frame.area();

    // Below this the fixed chrome (3 status lines + f-key bar) leaves no
    // usable main area — show an explicit notice instead of a garbled screen.
    /// Minimum terminal width (columns) the layout can render in.
    const MIN_WIDTH: u16 = 40;
    /// Minimum terminal height (rows) the layout can render in.
    const MIN_HEIGHT: u16 = 6;
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        frame.render_widget(
            ratatui::widgets::Paragraph::new(format!(
                "Terminal too small ({}x{}) — sipnab needs at least {MIN_WIDTH}x{MIN_HEIGHT}",
                area.width, area.height
            ))
            .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
        return fb;
    }

    // Layout: 3 status lines at top (sngrep-style), main content, F-key bar at bottom
    let [
        status1_area,
        status2_area,
        status3_area,
        main_area,
        fkey_area,
    ] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // Status lines at top (sngrep-style) — use cached counts
    render_status_line1(frame, status1_area, app);
    render_status_line2(frame, status2_area, app);
    render_status_line3(frame, status3_area, app);

    // Render the current view from the store snapshot held by the caller
    // for this whole frame (see `draw_frame` — contended ticks were
    // skipped before we got here, so nothing below can half-render).
    match &app.current_view {
        View::CallList => {
            let store = ds;
            call_list::render_call_list(
                frame,
                main_area,
                &mut app.call_list,
                store,
                &call_list::CallListDisplay {
                    rows: &app.displayed.ids,
                    timestamp_mode: app.timestamp_mode,
                    from_to_mode: app.from_to_mode,
                    theme: &app.theme,
                    resolver: app.resolver.as_ref(),
                    name_mode: app.name_mode,
                    offline: app.capture_mode.starts_with("Offline"),
                },
            );
        }
        View::StreamList => {
            let store = ss;
            stream_list::render_stream_list(
                frame,
                main_area,
                &mut app.stream_list,
                store,
                &stream_list::StreamListDisplay {
                    theme: &app.theme,
                    resolver: app.resolver.as_ref(),
                    name_mode: app.name_mode,
                    displayed: &app.stream_displayed.keys,
                },
            );
        }
        View::StreamDetail(key) => {
            {
                let store = ss;
                let effective = stream_detail::render_stream_detail(
                    frame,
                    main_area,
                    key,
                    store,
                    app.stream_detail_scroll,
                    &stream_detail::StreamDetailDisplay {
                        theme: &app.theme,
                        resolver: app.resolver.as_ref(),
                        name_mode: app.name_mode,
                    },
                );
                // Report the clamped scroll back: over-scrolling past the
                // end must not strand Up presses on a phantom offset.
                fb.stream_detail_scroll = Some(effective);
            }
        }
        View::CallFlow(call_id) => {
            {
                let store = ds;
                let cid = call_id.clone();
                let sel = app.flow.selected;

                // Horizontal split: ladder on left, raw detail on right (sngrep
                // style). The ladder width is widened past the configured split
                // when a multi-leg (B2BUA) flow needs it, so packed participant
                // columns don't truncate their method/status arrow labels.
                let (ladder_area, detail_area) = if app.flow.raw_preview {
                    // Widest per-gap demand of the arrow labels actually on
                    // screen (a retx fold header carries its "(+N retx)"
                    // count on the arrow; an arrow spanning several columns
                    // divides its demand across them).
                    let required_gap = app
                        .flow
                        .ladder
                        .rows
                        .iter()
                        .filter(|r| {
                            matches!(r.kind, call_flow::prepare::RowKind::Message { .. })
                                && r.src_col != r.dst_col
                        })
                        .map(|r| {
                            // Width of the arrow label exactly as
                            // call_flow::render draws it: a collapsed retx fold
                            // header appends its "(+N retx)" badge on the arrow.
                            // Take that badge straight from prepare's fold_label
                            // (dropping the trailing " - press e to expand" hint)
                            // rather than re-encoding the retx format here, so
                            // the wording lives in exactly one place.
                            let mut len = r.label.chars().count();
                            if r.folded_count > 0
                                && let Some(fold_label) = r.fold_label.as_deref()
                                && fold_label.starts_with("(+")
                            {
                                let badge = fold_label.split(" - ").next().unwrap_or(fold_label);
                                len += 1 + badge.chars().count(); // leading space + badge
                            }
                            call_flow::arrow_gap_for_label(len, r.src_col.abs_diff(r.dst_col))
                        })
                        .max()
                        .unwrap_or(0);
                    let ladder_w = call_flow::ladder_split_width(
                        app.flow.ladder.participants.len(),
                        required_gap,
                        app.flow.raw_preview_pct,
                        main_area.width,
                    );
                    let [left, right] =
                        Layout::horizontal([Constraint::Length(ladder_w), Constraint::Min(0)])
                            .areas(main_area);
                    (left, Some(right))
                } else {
                    (main_area, None)
                };

                // The theme-free ladder layout was derived (at most) once by
                // App::sync_caches (WS4.3c) and arrives as cached rows; the
                // render pass only runs the cheap style stage — theme, color
                // mode and the current selection.
                let prepared = if app.flow.ladder.rows.is_empty() {
                    None
                } else {
                    let msgs = call_flow::style(
                        &app.flow.ladder.rows,
                        &call_flow::StyleOptions {
                            color_mode: app.color_mode,
                            selected_msg: Some(sel),
                            theme: &app.theme,
                        },
                    );
                    Some((app.flow.ladder.participants.clone(), msgs))
                };

                // Rebuild the rendered message count (excluding spacers), the
                // RTP-bar indices for Enter drill-down and the visible-row ->
                // raw-message mapping. Used below for the detail pane and
                // reported back for the key handlers to consume next tick.
                let raw_indices: Vec<Option<usize>> = prepared
                    .as_ref()
                    .map(|(_, msgs)| {
                        msgs.iter()
                            .filter(|m| !m.is_spacer)
                            .map(|m| m.raw_index)
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some((_, ref msgs)) = prepared {
                    let msg_count = msgs.iter().filter(|m| !m.is_spacer).count();
                    // RTP bar indices in terms of non-spacer message index
                    // (matching flow.selected, which skips spacers).
                    let rtp_bars = msgs
                        .iter()
                        .filter(|m| !m.is_spacer)
                        .enumerate()
                        .filter(|(_, m)| m.is_rtp_bar)
                        .map(|(i, _)| i)
                        .collect();
                    fb.flow_caches = Some((msg_count, rtp_bars, raw_indices.clone()));
                }

                // Selection-follow + clamp, authoritative here where the
                // real viewport geometry is known: keep the selected row
                // visible and never scroll past the ladder content.
                let mut scroll = app.flow.scroll;
                if let Some((_, ref msgs)) = prepared {
                    let viewport = call_flow::ladder_visible_rows(ladder_area.height);
                    let total_rows = call_flow::ladder_total_rows(msgs);
                    let sel_row = call_flow::ladder_row_of_visible(msgs, sel);
                    if sel_row < scroll {
                        scroll = sel_row;
                    } else if viewport > 0 && sel_row >= scroll + viewport {
                        scroll = sel_row + 1 - viewport;
                    }
                    scroll = scroll.min(total_rows.saturating_sub(viewport));
                    fb.flow_scroll = Some(scroll);
                }

                // Render ladder using direct buffer painting
                call_flow::render_call_flow_direct_or_empty(
                    frame,
                    ladder_area,
                    prepared.as_ref(),
                    &call_flow::render::FlowNavigation {
                        scroll_offset: scroll,
                        mark_index: app.flow.mark_index,
                        selected_index: sel,
                    },
                    &app.theme,
                );

                // Ladder scrollbar when the flow is taller than the pane.
                if let Some((_, ref msgs)) = prepared {
                    let total_rows = call_flow::ladder_total_rows(msgs);
                    call_flow::render_ladder_scrollbar(
                        frame,
                        ladder_area,
                        total_rows,
                        scroll,
                        &app.theme,
                    );
                }

                // Render message detail panel (right side) if split is active
                if let Some(detail_area) = detail_area {
                    // The ladder selection is a VISIBLE-row index; map it to
                    // the message it renders (folds hide rows; a transaction
                    // filter renders a subset of the dialog; merged/extended
                    // ladders interleave dialogs, resolved by the index map).
                    let provenance = raw_indices
                        .get(sel)
                        .copied()
                        .flatten()
                        .and_then(|raw| app.flow.ladder.index_map.get(raw).cloned());
                    let detail_sel = raw_indices
                        .get(sel)
                        .copied()
                        .flatten()
                        .map(|filtered_idx| {
                            app.flow
                                .transaction_filter
                                .as_ref()
                                .and_then(|key| {
                                    store.get(&cid).map(|d| {
                                        d.messages
                                            .iter()
                                            .enumerate()
                                            .filter(|(_, m)| {
                                                call_flow::transaction_key(m).as_ref() == Some(key)
                                            })
                                            .map(|(i, _)| i)
                                            .nth(filtered_idx)
                                            .unwrap_or(filtered_idx)
                                    })
                                })
                                .unwrap_or(filtered_idx)
                        })
                        .unwrap_or(sel);
                    let (detail_cid, detail_sel) = match &provenance {
                        Some((row_cid, idx)) => (row_cid.as_str(), *idx),
                        None => (cid.as_str(), detail_sel),
                    };
                    let metrics = call_flow::render_message_detail(
                        frame,
                        detail_area,
                        store,
                        &call_flow::render::MessageDetailView {
                            call_id: detail_cid,
                            selected_msg: detail_sel,
                            // The transaction filter frames a single dialog;
                            // a merged/extended row (provenance set) belongs
                            // to another dialog, so don't apply it there.
                            transaction_filter: if provenance.is_none() {
                                app.flow.transaction_filter.as_ref()
                            } else {
                                None
                            },
                            scroll_offset: app.flow.detail_scroll,
                            focused: app.flow.detail_focused,
                            header_form: app.header_form,
                            wrap: app.flow.detail_wrap,
                            hscroll: app.flow.detail_hscroll,
                            theme: &app.theme,
                        },
                    );
                    // Persist the render's clamped offsets so End / repeated
                    // Down/Right never strand the view past the content; the
                    // renderer clamps against the real (wrapped) geometry.
                    fb.flow_detail_scroll = Some(metrics.scroll);
                    fb.flow_detail_hscroll = Some(metrics.hscroll);
                }
            }
        }
        View::RawMessage {
            call_id,
            message_index,
        } => {
            {
                let store = ds;
                let total_rows = msg_raw::render_raw_message(
                    frame,
                    main_area,
                    store,
                    &msg_raw::RawMessageView {
                        call_id,
                        message_index: *message_index,
                        scroll_offset: app.raw_msg_scroll,
                        search_query: &app.search_query,
                        syntax_highlight: app.syntax_highlight,
                        header_form: app.header_form,
                        theme: &app.theme,
                    },
                );
                // Clamp to content so End / over-eager PgDn self-correct.
                let viewport = main_area.height.saturating_sub(2);
                fb.raw_msg_scroll =
                    Some(app.raw_msg_scroll.min(total_rows.saturating_sub(viewport)));
            }
        }
        View::MessageDiff {
            call_id,
            msg1_idx,
            msg2_idx,
        } => {
            let store = ds;
            let total_rows = render_message_diff(
                frame,
                main_area,
                store,
                &MessageDiffView {
                    call_id,
                    msg1_idx: *msg1_idx,
                    msg2_idx: *msg2_idx,
                    scroll: app.diff_scroll,
                    header_form: app.header_form,
                    theme: &app.theme,
                },
            );
            let viewport = main_area.height.saturating_sub(2);
            fb.diff_scroll = Some(app.diff_scroll.min(total_rows.saturating_sub(viewport)));
        }
        View::CombinedDetail {
            call_id,
            indices,
            scope,
        } => {
            {
                let store = ds;
                let total_rows = msg_raw::render_combined_detail(
                    frame,
                    main_area,
                    store,
                    &msg_raw::CombinedDetailView {
                        call_id,
                        indices,
                        scope,
                        scroll_offset: app.raw_msg_scroll,
                        syntax_highlight: app.syntax_highlight,
                        header_form: app.header_form,
                        theme: &app.theme,
                    },
                );
                // Clamp to content so End (u16::MAX) lands on the last page
                // instead of a blank screen.
                let viewport = main_area.height.saturating_sub(2);
                fb.raw_msg_scroll =
                    Some(app.raw_msg_scroll.min(total_rows.saturating_sub(viewport)));
            }
        }
        View::Help => {
            // Clamp the scroll to the content height so you can't scroll past
            // the end (self-corrects an over-eager PgDn on the next frame).
            let visible = main_area.height.saturating_sub(2) as usize;
            let max_scroll = help::help_line_count().saturating_sub(visible) as u16;
            let clamped = app.help_scroll.min(max_scroll);
            fb.help_scroll = Some(clamped);
            help::render_help(frame, main_area, &app.theme, &app.version, clamped);
        }
        View::Statistics => {
            fb.stats_scroll = Some(render_statistics(frame, main_area, app, ds, ss));
        }
        View::QualityDashboard => {
            crate::tui::dashboard::render_dashboard(frame, main_area, app);
        }
        View::CallTimeline(call_id) => {
            crate::tui::timeline::render_timeline(frame, app, main_area, call_id);
        }
        View::StreamLossMap(key) => {
            crate::tui::loss_map::render_loss_map(frame, app, main_area, key);
        }
    }

    // F-key bar (sngrep-style, context-sensitive) at bottom
    render_fkey_bar(
        frame,
        fkey_area,
        &app.current_view,
        &app.active_popup,
        &app.theme,
    );

    // Render popup overlay on top of everything (if active)
    if let Some(popup) = &app.active_popup {
        match popup {
            Popup::SaveDialog => {
                render_save_popup(frame, area, app);
            }
            Popup::FilterDialog => {
                render_filter_popup(frame, area, &app.filter_dialog, &app.theme);
            }
            Popup::SettingsDialog => {
                render_settings_popup(frame, area, app);
            }
            Popup::FileOpenDialog => {
                render_file_open_popup(frame, area, app);
            }
            Popup::NameAddress => {
                render_name_popup(frame, area, app);
            }
        }
    }

    // Render column selector popup (not a Popup variant — it's call_list internal state)
    if app.call_list.column_selector_open {
        call_list::render_column_selector(frame, area, &app.call_list, &app.theme);
    }

    fb
}

/// Compose the statistics view's aggregate text — a full pass over every
/// dialog, so it is derived in `App::sync_caches` (churn-floored) and
/// cached, never recomputed per frame.
///
/// # Arguments
/// * `ds` - Dialog store snapshot to aggregate.
/// * `ss` - Stream store snapshot to aggregate.
///
/// # Returns
/// The full multi-line statistics text: totals, per-state counts and the
/// method distribution (both sorted by count descending, then name). Pure.
pub(in crate::tui) fn statistics_text(ds: &DialogStore, ss: &StreamStore) -> String {
    use crate::sip::dialog::DialogState;
    use std::collections::HashMap;

    let dialog_count = ds.len();
    let active_count = ds.active_count();
    let stream_count = ss.len();
    let orphaned = ss.orphaned_count();

    // Per-state counts
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    let mut method_counts: HashMap<&str, usize> = HashMap::new();
    let mut total_messages: usize = 0;

    for dialog in ds.iter() {
        let state_name = match dialog.state() {
            DialogState::Trying => "Trying",
            DialogState::Ringing => "Ringing",
            DialogState::InCall => "InCall",
            DialogState::Completed => "Completed",
            DialogState::Cancelled => "Cancelled",
            DialogState::Failed => "Failed",
            DialogState::Redirected => "Redirected",
            DialogState::Registered => "Registered",
            DialogState::Expired => "Expired",
            DialogState::Pending => "Pending",
            DialogState::Active => "Active",
            DialogState::Terminated => "Terminated",
            DialogState::Transferring => "Transferring",
        };
        *state_counts.entry(state_name).or_insert(0) += 1;
        *method_counts.entry(dialog.method.as_str()).or_insert(0) += 1;
        total_messages += dialog.messages.len();
    }

    // Sort methods by count descending, then alphabetically
    let mut methods: Vec<(&&str, &usize)> = method_counts.iter().collect();
    methods.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

    let mut text = format!(
        "sipnab Statistics\n\n\
         Dialogs:           {dialog_count}\n\
         Active Calls:      {active_count}\n\
         Total Messages:    {total_messages}\n\
         RTP Streams:       {stream_count}\n\
         Orphaned Streams:  {orphaned}\n"
    );

    // State breakdown
    if !state_counts.is_empty() {
        text.push_str("\nDialog States:\n");
        let mut states: Vec<(&&str, &usize)> = state_counts.iter().collect();
        states.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (state, count) in states {
            text.push_str(&format!("  {:<16} {count}\n", state));
        }
    }

    // Method distribution
    if !methods.is_empty() {
        text.push_str("\nMethod Distribution:\n");
        for (method, count) in methods {
            text.push_str(&format!("  {:<16} {count}\n", method));
        }
    }

    text.push_str("\nPress Esc to return.");
    text
}

/// Render the statistics view: the cached `app.stats.text` (or a direct
/// recomputation on the first frame before the cache exists) inside a
/// bordered, scrollable paragraph.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Main-pane area for the view.
/// * `app` - Application state (cached text, scroll, theme).
/// * `ds` - Dialog store snapshot for the cache-miss fallback.
/// * `ss` - Stream store snapshot for the cache-miss fallback.
///
/// # Returns
/// The content-clamped scroll offset, reported back via `RenderFeedback`.
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_statistics(
    frame: &mut ratatui::Frame,
    area: ratatui::layout::Rect,
    app: &App,
    ds: &DialogStore,
    ss: &StreamStore,
) -> u16 {
    // Serve the sync_caches-derived text; fall back to a direct pass only
    // when no cache exists yet (first frame lost the sync try_read race).
    let fallback;
    let text: &str = if app.stats.text.is_empty() {
        fallback = statistics_text(ds, ss);
        &fallback
    } else {
        &app.stats.text
    };

    // Clamp the scroll to the content height (End jumps to the last page).
    let total_rows = text.lines().count() as u16;
    let viewport = area.height.saturating_sub(2);
    let stats_scroll = app.stats_scroll.min(total_rows.saturating_sub(viewport));

    let block = Block::default().borders(Borders::ALL).title(" Statistics ");

    let paragraph = Paragraph::new(text)
        .block(block)
        .style(Style::default().fg(app.theme.foreground))
        .scroll((stats_scroll, 0));

    frame.render_widget(paragraph, area);
    stats_scroll
}

/// Estimated rendered rows for `lines` wrapped to `width` columns: the
/// ceil of each line's display width (the same accounting as the raw
/// message view's `estimated_rows`). Word-wrap can add a stray row;
/// close enough to clamp the scroll near the true bottom. Pure.
fn estimated_wrapped_rows(lines: &[Line<'_>], width: u16) -> u16 {
    let w = (width.max(1)) as usize;
    lines
        .iter()
        .map(|l| {
            let lw = l.width();
            if lw == 0 { 1 } else { lw.div_ceil(w) }
        })
        .sum::<usize>()
        .min(u16::MAX as usize) as u16
}

/// Align two line sequences by their longest common subsequence, yielding
/// side-by-side rows in order: `(Some, Some)` is a shared (unchanged) line,
/// `(Some, None)` a line only on the left (removed), `(None, Some)` a line
/// only on the right (inserted).
///
/// A positional diff pairs `left[i]` with `right[i]`, so a single inserted
/// line shifts the whole tail out of alignment and flags every following
/// line as changed. LCS alignment instead pairs the shared lines and emits
/// the lone insertion/removal as a one-sided gap, so only that row differs.
/// `O(n·m)` time and space — bounded by the two messages' line counts. Pure.
fn lcs_line_alignment<'a>(
    left: &[&'a str],
    right: &[&'a str],
) -> Vec<(Option<&'a str>, Option<&'a str>)> {
    let (n, m) = (left.len(), right.len());
    // lcs[i][j] = length of the LCS of left[i..] and right[j..].
    let mut lcs = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if left[i] == right[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }

    // Walk both sequences, preferring the shared line; otherwise advance the
    // side whose skip keeps the longer remaining common subsequence.
    let mut out = Vec::with_capacity(n.max(m));
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if left[i] == right[j] {
            out.push((Some(left[i]), Some(right[j])));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push((Some(left[i]), None));
            i += 1;
        } else {
            out.push((None, Some(right[j])));
            j += 1;
        }
    }
    while i < n {
        out.push((Some(left[i]), None));
        i += 1;
    }
    while j < m {
        out.push((None, Some(right[j])));
        j += 1;
    }
    out
}

/// Parameters for the side-by-side message diff view.
pub(in crate::tui) struct MessageDiffView<'a> {
    /// Call-ID of the dialog holding both messages.
    pub(in crate::tui) call_id: &'a str,
    /// Index of the left-hand message in the dialog's message list.
    pub(in crate::tui) msg1_idx: usize,
    /// Index of the right-hand message in the dialog's message list.
    pub(in crate::tui) msg2_idx: usize,
    /// Vertical scroll offset shared by both panes (rows).
    pub(in crate::tui) scroll: u16,
    /// Header-name display form (as captured / expanded / compact).
    pub(in crate::tui) header_form: header_form::HeaderFormMode,
    /// Color theme used for all styling.
    pub(in crate::tui) theme: &'a Theme,
}

/// Render a side-by-side diff of two SIP messages: both texts split into
/// halves and aligned by their longest common subsequence (see
/// `lcs_line_alignment`), so a lone inserted/removed line highlights only
/// that row instead of the whole shifted tail. Both panes always emit the
/// same number of rows (one per aligned pair), keeping the shared scroll in
/// step.
///
/// # Arguments
/// * `frame` - Frame to draw into.
/// * `area` - Main-pane area, split into equal left/right halves.
/// * `store` - Dialog store snapshot the messages are read from.
/// * `view` - Diff parameters (see `MessageDiffView`).
///
/// # Returns
/// The content height in rendered (wrapped) rows of the taller pane —
/// header line included — so the caller can clamp its stored scroll
/// offset to the true bottom; `0` when the dialog or either message is
/// missing (a placeholder notice is drawn instead).
///
/// # Side effects
/// Draws to `frame` only; no state is mutated.
pub(in crate::tui) fn render_message_diff(
    frame: &mut ratatui::Frame,
    area: Rect,
    store: &DialogStore,
    view: &MessageDiffView,
) -> u16 {
    let MessageDiffView {
        call_id,
        msg1_idx,
        msg2_idx,
        scroll,
        header_form: form,
        theme,
    } = *view;
    let dialog = match store.get(call_id) {
        Some(d) => d,
        None => {
            let para = Paragraph::new("Dialog not found.").style(Style::default().fg(theme.bad));
            frame.render_widget(para, area);
            return 0;
        }
    };

    let msg1 = dialog.messages.get(msg1_idx);
    let msg2 = dialog.messages.get(msg2_idx);

    let (Some(msg1), Some(msg2)) = (msg1, msg2) else {
        let para = Paragraph::new("Message not found.").style(Style::default().fg(theme.bad));
        frame.render_widget(para, area);
        return 0;
    };

    let raw1_bytes = String::from_utf8_lossy(&msg1.raw);
    let raw2_bytes = String::from_utf8_lossy(&msg2.raw);
    let raw1 = header_form::reformat_headers(&raw1_bytes, form);
    let raw2 = header_form::reformat_headers(&raw2_bytes, form);

    let lines1: Vec<&str> = raw1.lines().collect();
    let lines2: Vec<&str> = raw2.lines().collect();

    // Split area into two halves
    let half_width = area.width / 2;
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Length(half_width), Constraint::Fill(1)]).areas(area);

    let mut left_lines: Vec<Line<'static>> = Vec::new();
    let mut right_lines: Vec<Line<'static>> = Vec::new();

    // Header lines
    left_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg1_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));
    right_lines.push(Line::from(Span::styled(
        format!(" Message {} ", msg2_idx + 1),
        Style::default()
            .fg(theme.header)
            .add_modifier(Modifier::BOLD),
    )));

    let diff_style = Style::default()
        .fg(theme.warning)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default();

    // LCS alignment pairs shared lines and isolates insertions/removals as
    // one-sided gaps; a paired row (both sides present) is always equal, so
    // any differing pair is a gap and highlights only that single line.
    for (l1, l2) in lcs_line_alignment(&lines1, &lines2) {
        let is_diff = l1 != l2;
        let style = if is_diff { diff_style } else { normal_style };

        left_lines.push(Line::from(Span::styled(
            l1.unwrap_or("").to_string(),
            style,
        )));
        right_lines.push(Line::from(Span::styled(
            l2.unwrap_or("").to_string(),
            style,
        )));
    }

    let left_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg1_idx + 1));
    let right_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Message {} ", msg2_idx + 1));

    // Both panes wrap, so the scroll clamp must count rendered (wrapped)
    // rows — the unwrapped line count strands the wrapped tail of long
    // headers below an unreachable bottom. Taller pane governs.
    let left_rows = estimated_wrapped_rows(&left_lines, half_width.saturating_sub(2));
    let right_rows = estimated_wrapped_rows(
        &right_lines,
        area.width.saturating_sub(half_width).saturating_sub(2),
    );
    let total_rows = left_rows.max(right_rows);
    let left_para = Paragraph::new(left_lines)
        .block(left_block)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    let right_para = Paragraph::new(right_lines)
        .block(right_block)
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });

    frame.render_widget(left_para, left_area);
    frame.render_widget(right_para, right_area);
    total_rows
}

/// Construction and render helpers shared by the render unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::SipMessage;
    use crate::sip::parser::parse_sip;
    use chrono::{DateTime, TimeDelta, TimeZone, Utc};
    pub(crate) use ratatui::Terminal;
    pub(crate) use ratatui::backend::TestBackend;
    use std::net::{IpAddr, Ipv4Addr};

    /// Fixture caller address (10.0.0.1).
    pub(crate) fn addr_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    /// Fixture callee address (10.0.0.2).
    pub(crate) fn addr_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    /// Fixed fixture timestamp (2024-06-15 12:00:00 UTC).
    pub(crate) fn base_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 6, 15, 12, 0, 0).unwrap()
    }

    /// Assemble raw SIP bytes from a start line and header lines, with
    /// CRLF endings and the blank header/body separator.
    pub(crate) fn build_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
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

    /// Build and parse a fixture INVITE from `from` to `to` (A → B) with
    /// the given Call-ID and timestamp.
    pub(crate) fn make_invite(
        call_id: &str,
        from: &str,
        to: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
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

    /// Build and parse a fixture response (B → A) to the INVITE with the
    /// given status code, reason and timestamp.
    pub(crate) fn make_response(
        call_id: &str,
        status: u16,
        reason: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
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
        .expect("parse response")
    }

    /// Build and parse a fixture BYE (A → B) ending the dialog.
    pub(crate) fn make_bye(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
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
        .expect("parse BYE")
    }

    /// App with one populated, completed dialog (INVITE/180/200/BYE).
    pub(crate) fn app_with_dialog() -> App {
        let t0 = base_ts();
        App::with_processed_messages(vec![
            make_invite("call-1@test", "1001", "1002", t0),
            make_response("call-1@test", 180, "Ringing", t0 + TimeDelta::seconds(1)),
            make_response("call-1@test", 200, "OK", t0 + TimeDelta::seconds(2)),
            make_bye("call-1@test", t0 + TimeDelta::seconds(62)),
        ])
    }

    /// Below the minimum size the layout collapses to nothing usable; the
    /// user must get an explicit notice instead of a blank/garbled screen.
    #[test]
    fn tiny_terminal_shows_min_size_notice() {
        let mut app = App::new_test();
        let text = render_to_string(&mut app, 30, 4);
        assert!(
            text.contains("too small"),
            "expected a terminal-too-small notice, got: {text}"
        );
    }

    /// The empty-state hint must match the capture source: "may not
    /// contain SIP traffic" only makes sense for a pcap file, not for a
    /// live capture waiting for its first packet.
    #[test]
    fn empty_state_hint_matches_capture_source() {
        let mut app = App::new_test(); // capture mode defaults to Online
        let text = render_to_string(&mut app, 80, 20);
        assert!(
            text.contains("Waiting for SIP traffic"),
            "live empty state must say it is waiting: {text}"
        );
        assert!(
            !text.contains("pcap file"),
            "live empty state must not talk about pcap files: {text}"
        );

        app.set_capture_mode("Offline (foo.pcap)".to_string());
        let text = render_to_string(&mut app, 80, 20);
        assert!(
            text.contains("may not contain SIP traffic"),
            "offline empty state keeps the pcap hint: {text}"
        );
    }

    /// Render one full tick of `app` (cache sync, render, feedback
    /// write-back — the event loop's sequence) at the given size and
    /// return the buffer as a string.
    pub(crate) fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        app.sync_caches();
        let mut fb = RenderFeedback::default();
        let dialogs = app.dialog_store.clone();
        let streams = app.stream_store.clone();
        let (ds, ss) = (dialogs.read(), streams.read());
        terminal
            .draw(|frame| fb = render_app(frame, app, &ds, &ss))
            .unwrap();
        drop((ds, ss));
        app.apply_render_feedback(fb);
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf.cell((x, y)).unwrap().symbol());
            }
            out.push('\n');
        }
        out
    }

    // ── render_app dispatch across views & widths ──────────────────
}

/// Full-frame `render_app` dispatch tests: every view, status line
/// variants, popup overlays, and direct diff edge cases.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::render::test_support::*;

    /// Empty app renders the chrome; a populated one shows "Dialogs: 1".
    #[test]
    fn render_app_call_list_empty_and_populated() {
        let mut empty = App::new_test();
        let out = render_to_string(&mut empty, 80, 24);
        assert!(out.contains("Current Mode"));
        assert!(out.contains("Dialogs:"));

        let mut app = app_with_dialog();
        let out = render_to_string(&mut app, 80, 24);
        // The dialog count should reflect one dialog.
        assert!(out.contains("Dialogs: 1"));
    }

    /// The call-list f-key bar drops low-priority items when narrow and
    /// advertises the Open hotkey when wide.
    #[test]
    fn render_app_call_list_narrow_and_wide() {
        let mut app = app_with_dialog();
        let narrow = render_to_string(&mut app, 60, 12);
        assert!(narrow.contains("Esc"));
        let wide = render_to_string(&mut app, 130, 40);
        // Wide call list f-key bar advertises the Open hotkey.
        assert!(wide.contains("Open"));
    }

    /// The stream-list view renders with its Tab-to-Calls f-key hint.
    #[test]
    fn render_app_stream_list_view() {
        let mut app = App::new_test();
        app.current_view = View::StreamList;
        let out = render_to_string(&mut app, 100, 24);
        // Stream-list f-key bar advertises Calls (Tab to switch back).
        assert!(out.contains("Calls"));
    }

    /// Call flow renders in both split (raw preview) and full-width
    /// layouts, with the mode hints on status line 3.
    #[test]
    fn render_app_call_flow_view_split_and_nosplit() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        // Default raw_preview = true → split layout; renders detail panel.
        let split = render_to_string(&mut app, 120, 30);
        assert!(split.contains("Back"));
        // status line 3 shows the call-flow mode hints
        assert!(split.contains("Time:") || split.contains("SDP:"));

        // No split.
        app.flow.raw_preview = false;
        let nosplit = render_to_string(&mut app, 120, 30);
        assert!(nosplit.contains("Back"));
    }

    /// Extended (merged multi-dialog) call flow renders without panic.
    #[test]
    fn render_app_call_flow_extended_flow() {
        let mut app = app_with_dialog();
        app.current_view = View::CallFlow("call-1@test".to_string());
        app.flow.extended = true;
        let out = render_to_string(&mut app, 120, 30);
        assert!(out.contains("Back"));
    }

    /// The raw-message view renders with its Highlight f-key hint.
    #[test]
    fn render_app_raw_message_view() {
        let mut app = app_with_dialog();
        app.current_view = View::RawMessage {
            call_id: "call-1@test".to_string(),
            message_index: 0,
        };
        let out = render_to_string(&mut app, 90, 30);
        // Raw message f-key bar advertises Highlight.
        assert!(out.contains("Highlight"));
    }

    /// The diff view shows both message panes with their index titles.
    #[test]
    fn render_app_message_diff_view() {
        let mut app = app_with_dialog();
        app.current_view = View::MessageDiff {
            call_id: "call-1@test".to_string(),
            msg1_idx: 0,
            msg2_idx: 1,
        };
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Message 1"));
        assert!(out.contains("Message 2"));
    }

    /// Help renders non-empty; statistics shows its title and counts.
    #[test]
    fn render_app_help_and_statistics_views() {
        let mut app = app_with_dialog();
        app.current_view = View::Help;
        let help = render_to_string(&mut app, 80, 30);
        assert!(!help.is_empty());

        app.current_view = View::Statistics;
        let stats = render_to_string(&mut app, 80, 30);
        assert!(stats.contains("Statistics"));
        assert!(stats.contains("Dialogs:"));
    }

    // ── Status line variants ───────────────────────────────────────

    /// Status line 1 shows PAUSED and the [A] autoscroll indicator.
    #[test]
    fn render_app_status_line1_paused_and_autoscroll() {
        let mut app = app_with_dialog();
        app.paused = true;
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("PAUSED"));
        // autoscroll indicator [A] (default autoscroll on for call list)
        assert!(out.contains("[A]"));
    }

    /// Status line 1 shows the Offline capture mode text.
    #[test]
    fn render_app_status_line1_offline_mode() {
        let mut app = app_with_dialog();
        app.capture_mode = "Offline (capture.pcap)".to_string();
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("Offline"));
    }

    /// With search active, status line 3 shows the `/query` overlay.
    #[test]
    fn render_app_status_line3_search_active() {
        let mut app = app_with_dialog();
        app.search_active = true;
        app.search_query = "invite".to_string();
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("/invite"));
    }

    /// A status message containing "fail"/"error" renders on line 3 via
    /// the error color path.
    #[test]
    fn render_app_status_line3_error_message() {
        let mut app = app_with_dialog();
        app.status_error = Some("save failed: disk full".to_string());
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("save failed"));
    }

    /// A neutral status message renders on line 3 via the info
    /// (foreground) color path.
    #[test]
    fn render_app_status_line3_info_message() {
        let mut app = app_with_dialog();
        // No "error"/"fail" → uses foreground color path.
        app.status_error = Some("saved 3 dialogs".to_string());
        let out = render_to_string(&mut app, 100, 24);
        assert!(out.contains("saved 3 dialogs"));
    }

    /// Status line 2 shows both the match expression and the BPF filter.
    #[test]
    fn render_app_status_line2_filter_and_bpf() {
        let mut app = app_with_dialog();
        app.active_filter_text = "method == 'INVITE'".to_string();
        app.bpf_filter = "udp port 5060".to_string();
        let out = render_to_string(&mut app, 120, 24);
        assert!(out.contains("Match Expression"));
        assert!(out.contains("udp port 5060"));
    }

    // ── Popups via render_app overlay ──────────────────────────────

    /// The save popup overlays the frame with title and typed path.
    #[test]
    fn render_app_save_popup_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SaveDialog);
        app.set_save_path("/tmp/out.pcap");
        let out = render_to_string(&mut app, 90, 30);
        assert!(out.contains("Save Capture"));
        assert!(out.contains("/tmp/out.pcap"));
    }

    /// Field report: the save popup was fixed at 20 rows, so the last
    /// format category (RTP/Media: WAV + RTP JSON) was clipped — the
    /// "save the stream as a WAV file" hint pointed at an option the
    /// popup never showed. On a tall terminal every format must render.
    #[test]
    fn render_app_save_popup_shows_every_format() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SaveDialog);
        app.set_save_path("/tmp/out.pcap");
        let out = render_to_string(&mut app, 90, 40);
        for label in [
            "PCAP", "TXT", "SIPp", "JSON", "CSV", "HTML", "MD", "WAV", "RTP",
        ] {
            assert!(out.contains(label), "format {label} missing:\n{out}");
        }
        // The Enter/Tab/Esc controls line must also survive.
        assert!(out.contains("Cancel"), "controls line missing:\n{out}");
    }

    /// On a terminal too short for the whole list, the SELECTED format
    /// must be scrolled into view — stream views default to WAV, which
    /// lived in the clipped tail.
    #[test]
    fn render_app_save_popup_selected_format_visible_when_short() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SaveDialog);
        app.save.format = SaveFormat::Wav;
        app.set_save_path("/tmp/out.wav");
        let out = render_to_string(&mut app, 90, 18);
        assert!(
            out.contains("WAV"),
            "selected WAV must be scrolled into view:\n{out}"
        );
    }

    /// The file-open popup in browser mode shows the directory header.
    #[test]
    fn render_app_file_open_browser_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::FileOpenDialog);
        app.file_open.manual_mode = false;
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Open PCAP File"));
        assert!(out.contains("Dir:"));
    }

    /// The file-open popup in manual mode shows the Path input.
    #[test]
    fn render_app_file_open_manual_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::FileOpenDialog);
        app.file_open.manual_mode = true;
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Open PCAP File"));
        assert!(out.contains("Path:"));
    }

    /// The settings popup overlays with its title and first setting row.
    #[test]
    fn render_app_settings_popup_overlay() {
        let mut app = app_with_dialog();
        app.active_popup = Some(Popup::SettingsDialog);
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Settings"));
        assert!(out.contains("Color Mode"));
    }

    /// The filter popup overlays with its title and SIP From field.
    #[test]
    fn render_app_filter_popup_overlay() {
        let mut app = App::new_test();
        app.active_popup = Some(Popup::FilterDialog);
        let out = render_to_string(&mut app, 100, 30);
        assert!(out.contains("Filter"));
        assert!(out.contains("SIP From"));
    }

    // ── Direct popup function tests ────────────────────────────────

    /// A missing Call-ID renders the "Dialog not found" placeholder.
    #[test]
    fn render_message_diff_dialog_not_found() {
        let app = App::new_test();
        let store = app.dialog_store.read();
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_message_diff(
                    frame,
                    area,
                    &store,
                    &MessageDiffView {
                        call_id: "missing",
                        msg1_idx: 0,
                        msg2_idx: 1,
                        scroll: 0,
                        header_form: header_form::HeaderFormMode::AsCaptured,
                        theme: &theme,
                    },
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(text.contains("Dialog not found"));
    }

    /// The diff panes wrap long lines (`Wrap { trim: false }`), but the
    /// returned content height used to count UNWRAPPED lines — so the
    /// caller's scroll clamp could never reach the true (wrapped) bottom
    /// when a long header wraps to multiple rows.
    #[test]
    fn render_message_diff_scroll_reaches_the_wrapped_bottom() {
        use crate::capture::parse::TransportProto;
        use crate::sip::parser::parse_sip;

        let t0 = base_ts();
        // The long header is one unbroken token so word-wrap and the
        // ceil-of-width row estimate agree exactly.
        let long = format!("X-Long:{}ZZZEND", "a".repeat(120));
        let raw1 = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                "Call-ID: wrap@test",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        let raw2 = build_sip(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:1001@example.com>;tag=t1",
                "To: <sip:1002@example.com>",
                "Call-ID: wrap@test",
                "CSeq: 1 INVITE",
                &long,
            ],
        );
        let unwrapped_max = String::from_utf8_lossy(&raw1)
            .lines()
            .count()
            .max(String::from_utf8_lossy(&raw2).lines().count()) as u16;
        let msg1 = parse_sip(
            &raw1,
            t0,
            addr_a(),
            addr_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse INVITE");
        let msg2 = parse_sip(
            &raw2,
            t0 + chrono::TimeDelta::seconds(1),
            addr_b(),
            addr_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse 200 OK");
        let app = App::with_processed_messages(vec![msg1, msg2]);
        let store = app.dialog_store.read();
        let theme = Theme::default();

        // 64 cols → 32-wide panes (30 inner): the long header wraps to 5
        // rows, so the content is taller than its unwrapped line count.
        let mut terminal = Terminal::new(TestBackend::new(64, 12)).unwrap();
        let view = |scroll| MessageDiffView {
            call_id: "wrap@test",
            msg1_idx: 0,
            msg2_idx: 1,
            scroll,
            header_form: header_form::HeaderFormMode::AsCaptured,
            theme: &theme,
        };
        let mut total_rows = 0;
        terminal
            .draw(|frame| {
                total_rows = render_message_diff(frame, frame.area(), &store, &view(0));
            })
            .unwrap();
        assert!(
            total_rows > unwrapped_max + 1,
            "content height must count wrapped rows: got {total_rows}, \
             unwrapped max+header is {}",
            unwrapped_max + 1
        );

        // The caller clamps to total_rows − viewport; at that offset the
        // tail of the wrapped long header must actually be on screen.
        let viewport = 12u16.saturating_sub(2);
        let clamped = total_rows.saturating_sub(viewport);
        terminal
            .draw(|frame| {
                render_message_diff(frame, frame.area(), &store, &view(clamped));
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(
            text.contains("ZZZEND"),
            "clamped scroll must reach the wrapped bottom:\n{text}"
        );
    }

    /// An out-of-range message index renders "Message not found".
    #[test]
    fn render_message_diff_message_index_out_of_range() {
        let app = app_with_dialog();
        let store = app.dialog_store.read();
        let theme = Theme::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                // msg index way past the end.
                render_message_diff(
                    frame,
                    area,
                    &store,
                    &MessageDiffView {
                        call_id: "call-1@test",
                        msg1_idx: 0,
                        msg2_idx: 999,
                        scroll: 0,
                        header_form: header_form::HeaderFormMode::AsCaptured,
                        theme: &theme,
                    },
                );
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf.cell((x, y)).unwrap().symbol());
            }
        }
        assert!(text.contains("Message not found"));
    }

    /// A positional diff highlights every line after a single inserted
    /// header (the tail all shifts by one), which is wrong: only the
    /// inserted line actually changed. An LCS-based diff aligns the shared
    /// lines so the lone insertion is the ONLY highlighted row.
    #[test]
    fn render_message_diff_single_insert_highlights_only_that_line() {
        use crate::capture::parse::TransportProto;
        use crate::sip::parser::parse_sip;

        let t0 = base_ts();
        // msg2 is msg1 with one extra header inserted after Via; every
        // other line is byte-identical so an LCS diff isolates the insert.
        let common_tail: &[&str] = &[
            "From: <sip:1001@example.com>;tag=t1",
            "To: <sip:1002@example.com>",
            "Call-ID: diffins@test",
            "CSeq: 1 INVITE",
            "Content-Length: 0",
        ];
        let mut h1 = vec!["Via: SIP/2.0/UDP host:5060"];
        h1.extend_from_slice(common_tail);
        let mut h2 = vec!["Via: SIP/2.0/UDP host:5060", "X-Inserted: marker-line"];
        h2.extend_from_slice(common_tail);
        let raw1 = build_sip("INVITE sip:1002@example.com SIP/2.0", &h1);
        let raw2 = build_sip("INVITE sip:1002@example.com SIP/2.0", &h2);

        let msg1 = parse_sip(
            &raw1,
            t0,
            addr_a(),
            addr_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse msg1");
        let msg2 = parse_sip(
            &raw2,
            t0 + chrono::TimeDelta::seconds(1),
            addr_a(),
            addr_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse msg2");
        let app = App::with_processed_messages(vec![msg1, msg2]);
        let store = app.dialog_store.read();
        let theme = Theme::default();

        // Wide enough that no line wraps (one row per display line).
        let mut terminal = Terminal::new(TestBackend::new(120, 20)).unwrap();
        terminal
            .draw(|frame| {
                render_message_diff(
                    frame,
                    frame.area(),
                    &store,
                    &MessageDiffView {
                        call_id: "diffins@test",
                        msg1_idx: 0,
                        msg2_idx: 1,
                        scroll: 0,
                        header_form: header_form::HeaderFormMode::AsCaptured,
                        theme: &theme,
                    },
                );
            })
            .unwrap();

        // A diff-highlighted content row carries the warning fg + BOLD; the
        // pane-title rows use the (cyan) header fg, so they don't count.
        let buf = terminal.backend().buffer();
        let mut highlighted_rows = 0usize;
        let mut marker_row_highlighted = false;
        for y in 0..buf.area.height {
            let mut row_highlighted = false;
            let mut row_text = String::new();
            for x in 0..buf.area.width {
                let cell = buf.cell((x, y)).unwrap();
                row_text.push_str(cell.symbol());
                if cell.fg == theme.warning && cell.modifier.contains(Modifier::BOLD) {
                    row_highlighted = true;
                }
            }
            if row_highlighted {
                highlighted_rows += 1;
                if row_text.contains("X-Inserted") {
                    marker_row_highlighted = true;
                }
            }
        }

        assert_eq!(
            highlighted_rows, 1,
            "only the inserted line must be highlighted, not the shifted tail"
        );
        assert!(
            marker_row_highlighted,
            "the highlighted row must be the inserted X-Inserted header"
        );
    }
}
