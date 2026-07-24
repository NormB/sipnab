// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pure loss-binning for the Packet Loss Map view.
//!
//! [`build_loss_map`] projects a stream's retained lost-sequence log onto a
//! fixed number of cells laid out oldest→newest across the sequence window
//! the map covers. It is a pure function of `(stream, cell_count)` with no
//! rendering: the TUI renderer maps the returned per-cell loss counts onto a
//! density strip, and the same output is unit-tested exhaustively here.
//!
//! The map's window ends at `last_seq` and reaches back over the stream's
//! observed sequence span (`packet_count + lost_packets` positions), always
//! widened enough to contain every retained lost sequence. Sequence
//! **wraparound** is handled with serial (wrapping `u16`) arithmetic, so a
//! window that crosses 65535→0 bins its losses correctly. Every entry in
//! `lost_sequences` lands in exactly one cell in `[0, cell_count)`.

use super::stream::RtpStream;

/// Widest sequence window the map covers: the full `u16` sequence space.
/// Serial arithmetic means the window can never usefully exceed one lap of
/// the 16-bit sequence counter, so both the packet-count-derived base and
/// the retained-loss span are capped here.
const MAX_WINDOW: u64 = 65_536;

/// A binned projection of a stream's retained packet loss across its
/// sequence window, ready for the density-strip renderer.
///
/// `cells` runs left→right as oldest→newest sequence. Each entry counts the
/// retained lost sequences that fall in that cell; a summed count equal to
/// [`retained_lost`](LossMap::retained_lost) means every retained loss was
/// placed (the core in-range invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossMap {
    /// Per-cell loss count, left→right = oldest→newest sequence. Length is
    /// exactly `cell_count` (empty when `cell_count == 0`).
    pub cells: Vec<u16>,
    /// First retained sequence number the window covers (its left edge).
    pub span_start: u16,
    /// Last sequence number the window covers (`== stream.last_seq`).
    pub span_end: u16,
    /// Total packets the stream estimated lost (`stream.lost_packets`); may
    /// exceed `retained_lost` once the retained log has evicted old entries.
    pub total_lost: u64,
    /// Losses actually placed into cells (`== stream.lost_sequences.len()`).
    pub retained_lost: usize,
    /// `true` when `total_lost` exceeds the retained log, so the map only
    /// shows the most recent `retained_lost` of `total_lost` losses.
    pub truncated: bool,
}

/// Bin a stream's retained lost sequences into `cell_count` cells across the
/// sequence window ending at `last_seq`.
///
/// The window reaches back from `last_seq` over the stream's observed
/// sequence span (`packet_count + lost_packets` positions, capped at one
/// 16-bit lap) and is always widened to contain every retained lost
/// sequence. Each lost sequence is placed by its serial offset from
/// `span_start`, scaled to `cell_count`; wraparound across 65535→0 is
/// handled with wrapping arithmetic. Multiple losses in one cell increment
/// its count.
///
/// # Arguments
///
/// * `stream` — the stream whose `lost_sequences`, `last_seq`,
///   `packet_count` and `lost_packets` drive the window and binning.
/// * `cell_count` — number of cells (the render strip's inner width). `0`
///   yields empty `cells`.
///
/// # Returns
///
/// A [`LossMap`] whose `cells` has length `cell_count`, with every retained
/// lost sequence placed in exactly one cell in `[0, cell_count)`. A stream
/// with no retained losses yields all-zero cells and `retained_lost == 0`;
/// a summary-only stream (`packet_count <= 1`, no losses) yields a flat
/// window at `last_seq`.
pub fn build_loss_map(stream: &RtpStream, cell_count: usize) -> LossMap {
    let span_end = stream.last_seq;
    let total_lost = stream.lost_packets;
    let retained_lost = stream.lost_sequences.len();
    let truncated = total_lost as usize > retained_lost;

    // Base window: the sequence positions the stream has spanned, back from
    // last_seq. Capped at one full lap of the 16-bit counter.
    let base = stream
        .packet_count
        .saturating_add(stream.lost_packets)
        .clamp(1, MAX_WINDOW);

    // Widen so the oldest retained loss (serially furthest back from
    // last_seq) is always inside the window — otherwise a loss could fall
    // outside [0, cell_count).
    let max_back = stream
        .lost_sequences
        .iter()
        .map(|&s| span_end.wrapping_sub(s) as u64)
        .max();
    let window_len = match max_back {
        Some(mb) => base.max(mb + 1),
        None => base,
    }
    .clamp(1, MAX_WINDOW);

    let span_start = span_end.wrapping_sub((window_len - 1) as u16);

    let mut cells = vec![0u16; cell_count];
    if cell_count > 0 {
        for &s in &stream.lost_sequences {
            // Serial offset from the window's left edge, in [0, window_len).
            let offset = s.wrapping_sub(span_start) as u64;
            // Scale to a cell; floor keeps it strictly below cell_count.
            let cell = (offset * cell_count as u64 / window_len) as usize;
            let cell = cell.min(cell_count - 1);
            cells[cell] = cells[cell].saturating_add(1);
        }
    }

    LossMap {
        cells,
        span_start,
        span_end,
        total_lost,
        retained_lost,
        truncated,
    }
}

/// Unit tests for the pure loss-binning core: clustered vs spread inputs,
/// sequence wraparound, zero loss, degenerate cell counts, the truncation
/// flag, and the every-loss-in-range invariant.
#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::StreamKey;

    /// Fixed test StreamKey (SSRC 0x1234, 10.0.0.1:20000 → 10.0.0.2:30000).
    fn make_key() -> StreamKey {
        StreamKey {
            ssrc: 0x1234,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        }
    }

    /// Minimal RtpHeader at `seq` (PCMU, ts 0).
    fn make_header(seq: u16) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: 0,
            ssrc: 0x1234,
            payload_offset: 12,
        }
    }

    /// Fixed epoch instant.
    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp")
    }

    /// Build a stream whose loss accounting is set directly, mirroring the
    /// stream-store's fields: `last_seq`, the retained `lost_sequences` log,
    /// `packet_count` and `lost_packets`.
    fn stream_with_losses(
        last_seq: u16,
        losses: &[u16],
        packet_count: u64,
        lost_packets: u64,
    ) -> RtpStream {
        let mut s = RtpStream::new(make_key(), &make_header(0), ts());
        s.last_seq = last_seq;
        s.lost_sequences = losses.iter().copied().collect::<VecDeque<u16>>();
        s.packet_count = packet_count;
        s.lost_packets = lost_packets;
        s
    }

    /// Clustered loss (a contiguous run of sequence numbers) lands in a small
    /// number of adjacent cells — the bursty signature the view exists to show.
    #[test]
    fn clustered_losses_land_in_adjacent_cells() {
        // 20 consecutive losses at seq 100..120, window ~1000 wide, 50 cells
        // (20 sequences per cell) → they fall in two adjacent cells.
        let losses: Vec<u16> = (100..120).collect();
        let s = stream_with_losses(1000, &losses, 980, 20);
        let map = build_loss_map(&s, 50);

        assert_eq!(map.cells.len(), 50);
        let nonzero: Vec<usize> = map
            .cells
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c > 0)
            .map(|(i, _)| i)
            .collect();
        assert!(
            nonzero.len() <= 2,
            "clustered losses must occupy few cells, got {nonzero:?}"
        );
        // Adjacent: the occupied cells span a contiguous range.
        if let (Some(&first), Some(&last)) = (nonzero.first(), nonzero.last()) {
            assert_eq!(
                last - first,
                nonzero.len() - 1,
                "occupied cells must be contiguous, got {nonzero:?}"
            );
        }
        // Every loss was placed.
        let placed: u32 = map.cells.iter().map(|&c| c as u32).sum();
        assert_eq!(placed, 20);
    }

    /// Diffuse loss (every Nth sequence over the window) spreads across many
    /// cells — the scattered-congestion signature, distinct from a burst.
    #[test]
    fn spread_losses_spread_across_cells() {
        // 20 losses stepping by 40 over the same ~1000-wide, 50-cell window
        // (20 seq/cell) → each pair of losses is two cells apart.
        let losses: Vec<u16> = (0..20).map(|i| 100 + i * 40).collect();
        let s = stream_with_losses(1000, &losses, 980, 20);
        let map = build_loss_map(&s, 50);

        let nonzero = map.cells.iter().filter(|&&c| c > 0).count();
        assert!(
            nonzero >= 15,
            "spread losses must occupy many cells, got {nonzero} of 50"
        );
        let placed: u32 = map.cells.iter().map(|&c| c as u32).sum();
        assert_eq!(placed, 20);
    }

    /// A window that crosses the 16-bit wrap (65535→0) bins every loss into a
    /// valid cell using serial arithmetic; the summed counts equal the
    /// retained losses (nothing fell outside the strip).
    #[test]
    fn wraparound_window_bins_all_losses() {
        // last_seq=5; losses straddle the wrap: 65533, 65534, 65535, 0, 1, 2.
        let losses: [u16; 6] = [65533, 65534, 65535, 0, 1, 2];
        let s = stream_with_losses(5, &losses, 4, 6);
        let map = build_loss_map(&s, 12);

        assert_eq!(map.cells.len(), 12);
        assert_eq!(map.span_end, 5);
        // span_start is serially before last_seq across the wrap.
        assert!(map.span_start > 60_000, "span_start={}", map.span_start);
        let placed: u32 = map.cells.iter().map(|&c| c as u32).sum();
        assert_eq!(placed, 6, "every wrapped loss must be binned");
        assert_eq!(map.retained_lost, 6);
    }

    /// A loss-free stream yields all-zero cells and no retained losses; the
    /// window still ends at last_seq.
    #[test]
    fn zero_loss_yields_flat_map() {
        let s = stream_with_losses(500, &[], 500, 0);
        let map = build_loss_map(&s, 40);
        assert_eq!(map.cells.len(), 40);
        assert!(map.cells.iter().all(|&c| c == 0));
        assert_eq!(map.retained_lost, 0);
        assert_eq!(map.total_lost, 0);
        assert!(!map.truncated);
        assert_eq!(map.span_end, 500);
    }

    /// `cell_count == 0` yields an empty strip without panicking, while the
    /// summary counters still report the retained losses.
    #[test]
    fn cell_count_zero_is_empty() {
        let losses: Vec<u16> = (100..110).collect();
        let s = stream_with_losses(1000, &losses, 990, 10);
        let map = build_loss_map(&s, 0);
        assert!(map.cells.is_empty());
        assert_eq!(map.retained_lost, 10);
    }

    /// A single cell collects every retained loss (the whole window is one
    /// bucket).
    #[test]
    fn cell_count_one_collects_all() {
        let losses: Vec<u16> = (100..110).collect();
        let s = stream_with_losses(1000, &losses, 990, 10);
        let map = build_loss_map(&s, 1);
        assert_eq!(map.cells, vec![10]);
    }

    /// `truncated` is set exactly when the total loss count exceeds the
    /// retained log — the view then says "most recent N of M".
    #[test]
    fn truncation_flag_reflects_evicted_log() {
        // 5 retained, but 2000 total lost → the log was capped.
        let losses: Vec<u16> = (0..5).collect();
        let s = stream_with_losses(3000, &losses, 1000, 2000);
        let map = build_loss_map(&s, 20);
        assert!(map.truncated);
        assert_eq!(map.total_lost, 2000);
        assert_eq!(map.retained_lost, 5);

        // Fully retained → not truncated.
        let s2 = stream_with_losses(3000, &losses, 1000, 5);
        let map2 = build_loss_map(&s2, 20);
        assert!(!map2.truncated);
    }

    /// Invariant: every retained lost sequence lands in exactly one cell in
    /// `[0, cell_count)`, across a range of window shapes and cell counts —
    /// verified by the summed cell counts equaling the retained-loss count.
    #[test]
    fn every_loss_lands_in_range() {
        let cases: [(u16, Vec<u16>, u64, u64); 4] = [
            (1000, (100..130).collect(), 970, 30),
            (5, vec![65530, 65531, 65532, 0, 1, 2, 3], 3, 7),
            (
                200,
                (0..200).step_by(3).map(|v| v as u16).collect(),
                133,
                67,
            ),
            (0, vec![65535, 0], 1, 2),
        ];
        for (last_seq, losses, pkts, lost) in cases {
            let s = stream_with_losses(last_seq, &losses, pkts, lost);
            for cell_count in [1usize, 3, 8, 50, 200] {
                let map = build_loss_map(&s, cell_count);
                assert_eq!(map.cells.len(), cell_count);
                let placed: u32 = map.cells.iter().map(|&c| c as u32).sum();
                assert_eq!(
                    placed as usize,
                    losses.len(),
                    "last_seq={last_seq} cells={cell_count}: every loss must be placed"
                );
            }
        }
    }

    /// A summary-only stream (`packet_count <= 1`, no losses) yields a flat,
    /// empty map anchored at last_seq without panicking.
    #[test]
    fn summary_only_stream_is_flat() {
        let s = stream_with_losses(42, &[], 1, 0);
        let map = build_loss_map(&s, 16);
        assert!(map.cells.iter().all(|&c| c == 0));
        assert_eq!(map.span_end, 42);
        assert_eq!(map.retained_lost, 0);
    }
}
