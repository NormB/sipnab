# Packet Loss Map — Design (P5.1)

Date: 2026-07-24
Status: approved (design), pending implementation

## Goal

A TUI view that shows **where** RTP packet loss occurred across a stream's
retained sequence window, so an operator can tell at a glance whether loss is
**bursty** (clustered — a handoff, a microburst) or **diffuse** (scattered —
steady congestion). That distinction drives diagnosis: bursty loss is
perceptually worse and points at a transient event; diffuse loss points at
sustained network pressure. The Quality Dashboard already trends loss *over
time*; this view adds the complementary *sequence-position* picture the backlog
item ("visual representation of RTP loss patterns") asks for.

## Data source (already computed; hardened in P2/P3)

Per `RtpStream` (`src/rtp/stream.rs`):

- `lost_sequences: VecDeque<u16>` — the actual lost RTP sequence numbers, most
  recent `LOST_SEQ_LOG_CAP` (1000), oldest-out. This is the ground truth for
  position.
- `last_seq: u16`, `packet_count: u64`, `lost_packets: u64` — used to derive the
  retained span the map covers.
- `burst_gap_analysis() -> Option<BurstGapAnalysis>` — `burst_count`,
  `burst_duration_ms`, `is_bursty`, burst/gap loss rates. Feeds the summary
  header.

No new fields, no new persisted state.

## Component 1 — pure loss-binning function (the testable core)

A free function in a new `src/rtp/loss_map.rs`, independent of any rendering:

```
pub struct LossMap {
    pub cells: Vec<u16>,     // loss count per cell, left→right = oldest→newest seq
    pub span_start: u16,     // first retained sequence number in the window
    pub span_end: u16,       // last (== stream.last_seq)
    pub total_lost: u64,     // stream.lost_packets (may exceed retained window)
    pub retained_lost: usize,// losses actually placed (== lost_sequences.len())
    pub truncated: bool,     // true if total_lost > retained_lost (log capped)
}

pub fn build_loss_map(stream: &RtpStream, cell_count: usize) -> LossMap
```

Semantics:

- The window spans the retained losses: `span_start` = the oldest sequence the
  map can meaningfully cover, computed from `last_seq` back over
  `min(packet_count + lost_packets, LOST_SEQ_LOG_span)` positions, clamped so it
  always contains every entry in `lost_sequences`. Sequence **wraparound** is
  handled with serial (wrapping) arithmetic — a window may cross 65535→0.
- Each lost sequence is mapped to a cell by its serial offset from `span_start`,
  scaled to `cell_count`. Multiple losses in one cell increment its count.
- `cell_count == 0` → empty `cells`. A stream with no losses → all-zero cells,
  `retained_lost == 0`. A summary-only stream (`packet_count <= 1`) → empty/flat
  map with `truncated`/`total_lost` reflecting what's known.
- `truncated` is set when `lost_packets` exceeds the retained log, so the view
  can honestly say "showing the most recent N of M losses".

This is a pure function of `(stream, cell_count)` → `LossMap`; it is unit-tested
exhaustively (clustered vs spread inputs, wrap, zero-loss, single-cell,
truncation) with no TUI involved.

## Component 2 — the view

New `View::StreamLossMap(StreamKey)` (`src/tui/state.rs`), wired exactly like
`View::CallTimeline`:

- **Opening:** key `L` from Stream Detail (`controllers/stream_detail.rs`) and
  from the Quality Dashboard (`controllers/dashboard.rs`), each setting
  `app.current_view = View::StreamLossMap(key)`.
- **Controller:** `controllers/loss_map.rs` — `handle_loss_map_key`: `Esc`/`q`
  returns to the previous view (Stream Detail); no other navigation (single
  screen). Dispatched from `controllers/mod.rs` and the mouse no-op arm, mirror
  of the timeline wiring.
- **Render:** `src/tui/loss_map.rs` — `render_loss_map(f, app, area, key)`.

## Component 3 — rendering (approach A: sequence-space density strip)

Layout, top to bottom in a bordered block titled `Packet Loss Map`:

1. **Summary header** (2–3 lines): stream label (ssrc, src→dst), total loss %
   (`lost_packets / (packet_count + lost_packets)`), `burst_count` and
   `is_bursty`/avg burst duration from `burst_gap_analysis()`, and a
   "showing most recent N of M losses" note when `truncated`.
2. **Density strip:** one full-width row (cell per terminal column, so
   `cell_count = inner_width`). Each cell is a block glyph whose shade encodes
   its loss count via a fixed ramp: ` ` (0) `░` (light) `▒` (medium) `▓` (heavy)
   `█` (max), colored on the same good/warn/bad thresholds the dashboard uses.
   Bursts render as contiguous dark runs; random loss as isolated specks.
3. **Sequence axis:** a labeled row under the strip showing `span_start` at the
   left, `span_end` at the right, and a midpoint — so a cluster's position is
   readable.
4. **Legend:** the glyph→density mapping and the color bands.

Degrades gracefully: zero retained loss → the strip is blank with a centered
"No packet loss recorded in the retained window" line; a narrow terminal reuses
the existing `saturating_sub` width guards.

The renderer is thin: it calls `build_loss_map(stream, inner_width)` and maps
cells→glyphs. Snapshot tests (`tests/tui_snapshot_test.rs`) pin the rendered
output for a clustered-loss and a no-loss fixture.

## Help + docs

- `src/tui/help.rs`: add `L  Packet loss map (RTP loss pattern)` under Stream
  Detail and Quality Dashboard.
- `docs/keybindings.md` + website mirror: same entry.

## Testing plan

- **Unit (loss_map.rs):** clustered input → losses land in adjacent cells;
  spread input → losses spread across cells; wraparound window; zero loss;
  `cell_count == 0`/`1`; truncation flag; every `lost_sequences` entry lands in
  `[0, cell_count)`.
- **Controller (loss_map.rs tests):** `L` from Stream Detail/Dashboard opens the
  view; `Esc` returns; nav keys inert.
- **Snapshot (tui_snapshot_test.rs):** clustered-loss fixture and no-loss
  fixture render deterministically.

## Out of scope (YAGNI)

- Scrolling/zooming the map, selecting cells, cross-stream comparison.
- Loss-over-time bars (approach B) — the dashboard already trends loss over time.
- Persisting or exporting the map.
- Reconstructing losses older than the retained `lost_sequences` log.

## Files

New: `src/rtp/loss_map.rs`, `src/tui/loss_map.rs`,
`src/tui/controllers/loss_map.rs`.
Touched: `src/rtp/mod.rs` (mod), `src/tui/mod.rs` (mod), `src/tui/state.rs`
(View variant), `src/tui/controllers/mod.rs` (dispatch),
`src/tui/controllers/stream_detail.rs` + `dashboard.rs` (open key),
`src/tui/help.rs`, `docs/keybindings.md` (+ website mirror),
`tests/tui_snapshot_test.rs`.
