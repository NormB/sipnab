// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP stream state tracking.
//!
//! An `RtpStream` represents a single media flow identified by its
//! `StreamKey` (SSRC + source/destination socket addresses). It tracks
//! packet counts, jitter (RFC 3550 algorithm), sequence-gap loss detection,
//! and periodic quality intervals for trend analysis.

use std::net::SocketAddr;

use chrono::{DateTime, Duration, Utc};

use super::parser::RtpHeader;

// ── Quality interval period ──────────────────────────────────────────

/// How often to snapshot quality metrics into a `QualityInterval`.
const QUALITY_INTERVAL_SECS: i64 = 5;

/// Cap on the per-stream quality trend history. One interval per
/// `QUALITY_INTERVAL_SECS` means 720 entries cover a full hour of call
/// time; without a cap a day-long stream would hold ~17k entries.
/// Oldest-out when full.
const MAX_QUALITY_INTERVALS: usize = 720;

/// Cap on the retained `lost_sequences` log (oldest-out when full). This is
/// the only window over which loss/no-loss is known reliably, so burst/gap
/// analysis must not reason about a wider span (see [`BURST_WINDOW_CAP`]).
const LOST_SEQ_LOG_CAP: usize = 1000;

/// Allocation ceiling for the burst/gap reconstruction bitmap. The analysis
/// window is additionally bounded by the span the `lost_sequences` log
/// actually covers, so it never exceeds `LOST_SEQ_LOG_CAP` losses' worth of
/// reliable data.
const BURST_WINDOW_CAP: usize = 10_000;

/// Nominal duration charged for a single Comfort Noise frame when its true
/// extent is not observable (the opening/closing frame of a silence period).
/// Interior frames are measured from actual RTP-timestamp spacing instead.
const NOMINAL_CN_FRAME_MS: u32 = 20;

// ── Public types ─────────────────────────────────────────────────────

/// Unique key for an RTP stream: SSRC combined with the 5-tuple direction.
///
/// Two streams with the same SSRC but different source/destination addresses
/// are treated as distinct (this is common in conferencing topologies).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    /// Synchronization source identifier from the RTP header.
    pub ssrc: u32,
    /// Source socket address (IP + port) of the RTP sender.
    pub src: SocketAddr,
    /// Destination socket address (IP + port) of the RTP receiver.
    pub dst: SocketAddr,
}

/// A periodic quality snapshot for trend analysis.
#[derive(Debug, Clone)]
pub struct QualityInterval {
    /// When this interval was recorded.
    pub timestamp: DateTime<Utc>,
    /// Average jitter during this interval (milliseconds).
    pub jitter_ms: f64,
    /// Estimated packet loss percentage during this interval.
    pub loss_pct: f64,
    /// Number of packets received during this interval.
    pub packets: u64,
}

/// Bounded, oldest-first log of [`QualityInterval`] snapshots.
///
/// Backed by a [`VecDeque`](std::collections::VecDeque) so evicting the
/// oldest entry once the history reaches its cap is O(1) (`pop_front`),
/// rather than the O(n) element shift a `Vec::remove(0)` incurs. The public
/// surface mirrors the slice of `Vec` methods consumers rely on (`push`,
/// `iter`, `first`, `last`, `len`, `is_empty`, `clear`, and by-reference
/// iteration) so existing call sites are unaffected.
#[derive(Debug, Clone, Default)]
pub struct QualityHistory {
    /// Snapshots in arrival order; `front` is oldest, `back` is newest.
    inner: std::collections::VecDeque<QualityInterval>,
}

impl QualityHistory {
    /// Append `interval` as the newest entry.
    ///
    /// Does not itself enforce the history cap; callers that need the bound
    /// evict via [`pop_front`](QualityHistory::pop_front) first (see
    /// `RtpStream::record_quality_interval`).
    pub fn push(&mut self, interval: QualityInterval) {
        self.inner.push_back(interval);
    }

    /// Remove and return the oldest entry, or `None` if empty. O(1).
    pub fn pop_front(&mut self) -> Option<QualityInterval> {
        self.inner.pop_front()
    }

    /// Number of snapshots currently retained.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` when no snapshots are retained.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// The oldest retained snapshot, or `None` if empty.
    pub fn first(&self) -> Option<&QualityInterval> {
        self.inner.front()
    }

    /// The newest retained snapshot, or `None` if empty.
    pub fn last(&self) -> Option<&QualityInterval> {
        self.inner.back()
    }

    /// Iterate over retained snapshots, oldest first.
    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, QualityInterval> {
        self.inner.iter()
    }

    /// Drop all retained snapshots.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<'a> IntoIterator for &'a QualityHistory {
    type Item = &'a QualityInterval;
    type IntoIter = std::collections::vec_deque::Iter<'a, QualityInterval>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

/// A detected silence period from Comfort Noise packets.
#[derive(Debug, Clone)]
pub struct SilencePeriod {
    /// First sequence number in the silence period.
    pub start_seq: u16,
    /// Last sequence number in the silence period.
    pub end_seq: u16,
    /// Silence duration in milliseconds.
    ///
    /// Derived from the observed RTP-timestamp span between the first and
    /// last Comfort Noise packet (converted to milliseconds via the stream
    /// clock rate) plus one nominal final-frame interval
    /// (`NOMINAL_CN_FRAME_MS`). This tracks the *actual* CN packet spacing
    /// — including discontinuous transmission, where CN frames arrive far
    /// more than 20 ms apart — rather than assuming a fixed 20 ms cadence.
    /// It remains a slight lower bound: the final frame's true extent is not
    /// observable, so it is charged one nominal frame.
    pub duration_ms: u32,
}

/// An RTP media stream tracked as a first-class entity.
///
/// Streams are top-level objects that peer with SIP dialogs via
/// cross-references rather than being children of dialogs (design
/// decision D13). Orphaned streams (no matching dialog) remain visible.
#[derive(Debug, Clone)]
pub struct RtpStream {
    /// Unique identifier for this stream.
    pub key: StreamKey,
    /// Codec name derived from SDP rtpmap or the static PT table.
    pub codec: Option<String>,
    /// RTP clock rate in Hz (from SDP or static PT table, default 8000).
    pub clock_rate: u32,
    /// RTP payload type number.
    pub payload_type: u8,
    /// Timestamp of the first packet seen for this stream.
    pub first_seen: DateTime<Utc>,
    /// Timestamp of the most recent packet.
    pub last_seen: DateTime<Utc>,
    /// Total number of RTP packets received.
    pub packet_count: u64,
    /// Total payload octets received.
    pub octet_count: u64,
    /// Last observed RTP sequence number.
    pub last_seq: u16,
    /// Last observed RTP timestamp.
    pub last_timestamp: u32,
    /// Running interarrival jitter estimate (RFC 3550 algorithm) in
    /// milliseconds: `update` converts the RTP timestamp delta to ms via
    /// `clock_rate` before folding it in. Note `process_rtcp` may
    /// overwrite this with a report's jitter value, which is in RTP
    /// timestamp units.
    pub jitter: f64,
    /// Estimated lost packets from sequence number gaps.
    pub lost_packets: u64,
    /// SIP Call-ID if this stream has been linked to a dialog.
    pub associated_dialog: Option<String>,
    /// `true` if no dialog has been associated after the orphan timeout.
    pub orphaned: bool,
    /// `true` if this stream was discovered via heuristic (no SDP).
    pub heuristic: bool,
    /// Periodic quality snapshots for trend analysis (bounded, oldest-out).
    pub quality_intervals: QualityHistory,
    /// Sequence numbers of lost packets, capped at `LOST_SEQ_LOG_CAP` most
    /// recent entries (oldest-out). Used for burst/gap analysis.
    pub lost_sequences: std::collections::VecDeque<u16>,
    /// Count of Comfort Noise (PT=13) frames received.
    pub cn_frames: u32,
    /// Detected silence periods (capped at 100).
    pub silence_periods: Vec<SilencePeriod>,
    /// Ring buffer of raw RTP payloads for audio export (G.711 and Opus).
    /// Each entry: (RTP timestamp, raw payload bytes).
    pub payload_buffer: std::collections::VecDeque<(u32, Vec<u8>)>,

    // ── Private state for jitter/interval tracking ───────────────────
    /// Wall-clock arrival time of the previous packet (for jitter calc).
    prev_arrival: Option<DateTime<Utc>>,
    /// RTP timestamp of the previous packet (for jitter calc).
    prev_rtp_ts: Option<u32>,
    /// Start of the current quality measurement interval.
    interval_start: DateTime<Utc>,
    /// Packets in the current interval.
    interval_packets: u64,
    /// Lost packets in the current interval.
    interval_lost: u64,
}

impl RtpStream {
    /// Returns `true` if the stream has been active within the last 30 seconds
    /// (relative to the current wall clock).
    ///
    /// Thin wrapper over [`is_active_at`](Self::is_active_at) that supplies
    /// `Utc::now()`; the `_at` form takes the reference instant explicitly so
    /// offline replay and tests can evaluate activity deterministically.
    pub fn is_active(&self) -> bool {
        self.is_active_at(Utc::now())
    }

    /// Returns `true` if the stream was active within the 30 seconds preceding
    /// `now`.
    ///
    /// The reference instant is injected rather than read from the wall clock,
    /// so replaying a captured stream (whose `last_seen` is historical) and
    /// unit tests can both get a deterministic answer.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.last_seen > now - chrono::Duration::seconds(30)
    }

    /// Create a new stream from its first observed RTP packet.
    ///
    /// # Arguments
    ///
    /// * `key` — the SSRC + 5-tuple identity of the new stream.
    /// * `header` — parsed header of the first packet; supplies the payload
    ///   type (used to seed codec and clock rate from the static PT table,
    ///   defaulting to 8000 Hz for dynamic types) and the initial
    ///   sequence/timestamp state.
    /// * `timestamp` — wall-clock arrival time of the first packet.
    ///
    /// # Returns
    ///
    /// A stream with `packet_count == 1`, zeroed jitter/loss counters, and
    /// the jitter/interval trackers primed with this packet so the next
    /// `update` produces the first jitter sample.
    pub fn new(key: StreamKey, header: &RtpHeader, timestamp: DateTime<Utc>) -> Self {
        let codec = codec_from_pt(header.payload_type).map(String::from);
        let clock_rate = clock_rate_from_pt(header.payload_type).unwrap_or(8000);
        Self {
            key,
            codec,
            clock_rate,
            payload_type: header.payload_type,
            first_seen: timestamp,
            last_seen: timestamp,
            packet_count: 1,
            octet_count: 0,
            last_seq: header.sequence,
            last_timestamp: header.timestamp,
            jitter: 0.0,
            lost_packets: 0,
            associated_dialog: None,
            orphaned: false,
            heuristic: false,
            quality_intervals: QualityHistory::default(),
            lost_sequences: std::collections::VecDeque::new(),
            cn_frames: 0,
            silence_periods: Vec::new(),
            payload_buffer: std::collections::VecDeque::new(),
            prev_arrival: Some(timestamp),
            prev_rtp_ts: Some(header.timestamp),
            interval_start: timestamp,
            interval_packets: 1,
            interval_lost: 0,
        }
    }

    /// Update stream state with a new RTP packet.
    ///
    /// Calculates RFC 3550 interarrival jitter, detects sequence gaps for
    /// loss estimation, and records quality intervals at fixed periods.
    ///
    /// # Arguments
    ///
    /// * `header` — parsed header of the arriving packet.
    /// * `timestamp` — wall-clock arrival time of the packet.
    /// * `payload_len` — media payload length in bytes (added to
    ///   `octet_count`).
    ///
    /// # Side effects
    ///
    /// * Increments `packet_count`/`octet_count` and refreshes `last_seen`,
    ///   `last_seq`, and `last_timestamp`.
    /// * On a forward sequence gap smaller than 32768 (larger gaps are
    ///   treated as reordering), adds the gap to `lost_packets` and
    ///   `interval_lost` and appends the missing sequence numbers to
    ///   `lost_sequences` (oldest-out, capped at 1000).
    /// * For Comfort Noise packets (PT 13), increments `cn_frames` and
    ///   extends or opens a `SilencePeriod` (list capped at 100).
    /// * Folds the new interarrival delta into `jitter` using the RFC 3550
    ///   Section 6.4.1 estimator `J += (|D| - J) / 16`, in milliseconds.
    /// * Once `QUALITY_INTERVAL_SECS` have elapsed, snapshots and resets
    ///   the current interval via `record_quality_interval`.
    pub fn update(&mut self, header: &RtpHeader, timestamp: DateTime<Utc>, payload_len: usize) {
        self.packet_count += 1;
        self.octet_count += payload_len as u64;
        self.last_seen = timestamp;

        // Detect packet loss from sequence number gaps.
        // Handle wraparound: expected next is last_seq + 1 (mod 65536).
        let expected = self.last_seq.wrapping_add(1);
        if header.sequence != expected {
            // Calculate gap accounting for wraparound
            let gap = header.sequence.wrapping_sub(expected) as u64;
            // Sanity check: if gap is huge (>= 32768), it's likely reordering, not loss
            if gap < 32768 {
                self.lost_packets += gap;
                self.interval_lost += gap;
                // Record lost sequence numbers for burst/gap analysis
                // (per-gap and total both capped at LOST_SEQ_LOG_CAP).
                for offset in 0..gap.min(LOST_SEQ_LOG_CAP as u64) {
                    if self.lost_sequences.len() >= LOST_SEQ_LOG_CAP {
                        self.lost_sequences.pop_front();
                    }
                    self.lost_sequences
                        .push_back(expected.wrapping_add(offset as u16));
                }
            }
        }
        self.last_seq = header.sequence;

        // Comfort Noise (PT=13) tracking for silence detection.
        //
        // A silence period's duration is measured from the actual spacing of
        // its CN packets rather than assuming a fixed 20 ms cadence: when a
        // CN packet continues the current period, it extends the duration by
        // the observed RTP-timestamp delta from the previous packet. This
        // stays honest under discontinuous transmission, where CN frames can
        // be many frames apart. `prev_rtp_ts` is the previous packet's RTP
        // timestamp (still unmodified at this point in `update`).
        if header.payload_type == 13 {
            self.cn_frames += 1;
            let prev_rtp_ts = self.last_timestamp;
            let clock_rate = self.clock_rate;
            if let Some(last) = self.silence_periods.last_mut() {
                if header.sequence == last.end_seq.wrapping_add(1) {
                    last.end_seq = header.sequence;
                    last.duration_ms += cn_gap_ms(prev_rtp_ts, header.timestamp, clock_rate);
                } else if self.silence_periods.len() < 100 {
                    self.silence_periods.push(SilencePeriod {
                        start_seq: header.sequence,
                        end_seq: header.sequence,
                        duration_ms: NOMINAL_CN_FRAME_MS,
                    });
                }
            } else {
                self.silence_periods.push(SilencePeriod {
                    start_seq: header.sequence,
                    end_seq: header.sequence,
                    duration_ms: NOMINAL_CN_FRAME_MS,
                });
            }
        }

        // RFC 3550 jitter calculation (Section 6.4.1, A.8)
        if let (Some(prev_arrival), Some(prev_rtp_ts)) = (self.prev_arrival, self.prev_rtp_ts) {
            // Microseconds, not milliseconds: on a 20 ms stream the interarrival
            // variation being measured is itself sub-millisecond, so truncating
            // to whole milliseconds quantises away the entire signal and reports
            // jitter far above what the packets show. `num_microseconds` returns
            // None only past ~292,000 years, where the old behaviour is fine.
            let since = timestamp.signed_duration_since(prev_arrival);
            let arrival_diff = since
                .num_microseconds()
                .map_or_else(|| since.num_milliseconds() as f64, |us| us as f64 / 1000.0);
            // Convert RTP timestamp difference to milliseconds. Wrapping
            // subtraction handles rollover; the result is interpreted as a
            // *signed* (i32) transit delta per RFC 3550, so a reordered
            // packet (timestamp lower than its predecessor) yields a small
            // negative delta rather than a ~4.29e9 unsigned spike.
            let rtp_diff = header.timestamp.wrapping_sub(prev_rtp_ts) as i32 as f64;
            let rtp_diff_ms = rtp_diff / (self.clock_rate as f64 / 1000.0);
            let d = (arrival_diff - rtp_diff_ms).abs();
            // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.prev_arrival = Some(timestamp);
        self.prev_rtp_ts = Some(header.timestamp);
        self.last_timestamp = header.timestamp;

        // Quality interval recording
        self.interval_packets += 1;
        let elapsed = timestamp.signed_duration_since(self.interval_start);
        if elapsed >= Duration::seconds(QUALITY_INTERVAL_SECS) {
            self.record_quality_interval(timestamp);
        }
    }

    /// Force-record a quality interval snapshot.
    ///
    /// # Arguments
    ///
    /// * `timestamp` — wall-clock time stamped onto the snapshot and used
    ///   as the start of the next interval.
    ///
    /// # Side effects
    ///
    /// Appends a `QualityInterval` (current jitter, interval loss
    /// percentage, interval packet count) to `quality_intervals`, evicting
    /// the oldest entry when at `MAX_QUALITY_INTERVALS`, then resets
    /// `interval_start`, `interval_packets`, and `interval_lost`.
    fn record_quality_interval(&mut self, timestamp: DateTime<Utc>) {
        let total_in_interval = self.interval_packets + self.interval_lost;
        let loss_pct = if total_in_interval > 0 {
            (self.interval_lost as f64 / total_in_interval as f64) * 100.0
        } else {
            0.0
        };

        if self.quality_intervals.len() >= MAX_QUALITY_INTERVALS {
            // O(1) oldest-out eviction: QualityHistory is VecDeque-backed, so
            // this is a pop_front rather than an O(n) Vec front-removal.
            self.quality_intervals.pop_front();
        }
        self.quality_intervals.push(QualityInterval {
            timestamp,
            jitter_ms: self.jitter,
            loss_pct,
            packets: self.interval_packets,
        });

        self.interval_start = timestamp;
        self.interval_packets = 0;
        self.interval_lost = 0;
    }

    /// Compute burst/gap analysis from recorded lost sequences.
    ///
    /// Reconstructs a received/lost bitmap over the sequence range the
    /// `lost_sequences` log actually covers — from its oldest to its newest
    /// retained entry — and delegates to `super::quality::analyze_burst_gap`
    /// (assuming a 20 ms packet interval).
    ///
    /// The window is deliberately bounded to that retained range rather than
    /// to `last_seq` and the total packet count. The log keeps only its most
    /// recent `LOST_SEQ_LOG_CAP` entries, so a wider window would mark
    /// already-evicted losses as "received" and silently understate
    /// burstiness once the log is full — for example, a long clean tail that
    /// advances `last_seq` far past the loss region. Anchoring at the newest
    /// retained loss keeps every loss inside the window known, so bursts are
    /// not undercounted. Allocation is additionally capped at
    /// `BURST_WINDOW_CAP`; if the retained span is wider, the most recent
    /// `BURST_WINDOW_CAP` sequence numbers are analyzed.
    ///
    /// Note: a single gap larger than `LOST_SEQ_LOG_CAP` is itself
    /// truncated at capture time, so an extreme lone burst remains a lower
    /// bound; the eviction-driven undercount above is the case fixed here.
    ///
    /// Returns `None` if there are no lost packets to analyze.
    pub fn burst_gap_analysis(&self) -> Option<super::quality::BurstGapAnalysis> {
        // Default ptime for common audio codecs (ms).
        let ptime_ms = 20.0;

        let lost_set: std::collections::HashSet<u16> =
            self.lost_sequences.iter().copied().collect();

        // The retained log bounds the region we can reason about reliably.
        // `front`/`back` are the oldest and newest retained lost sequences.
        let (front, back) = match (self.lost_sequences.front(), self.lost_sequences.back()) {
            (Some(&front), Some(&back)) => (front, back),
            _ => return None,
        };

        // Reliable span [front, back], capped for allocation. When capped,
        // keep the most recent losses (anchored at `back`).
        let span = back.wrapping_sub(front) as usize + 1;
        let window_size = span.min(BURST_WINDOW_CAP);

        // Walk ascending from (back - window_size + 1) up to and including
        // `back`. Every lost sequence in this range is still in the log, so
        // the bitmap is accurate.
        let mut received = Vec::with_capacity(window_size);
        for i in 0..window_size {
            let seq = back.wrapping_sub((window_size - 1 - i) as u16);
            received.push(!lost_set.contains(&seq));
        }

        Some(super::quality::analyze_burst_gap(&received, ptime_ms))
    }
}

/// Milliseconds a Comfort Noise frame covers, from the RTP-timestamp delta
/// between consecutive CN packets and the stream clock rate.
///
/// The wrapped subtraction is read as a signed (i32) delta per RFC 3550, so
/// a reordered packet yields a small negative value; such deltas (and a zero
/// clock rate) are clamped to `0` rather than corrupting the duration.
fn cn_gap_ms(prev_rtp_ts: u32, rtp_ts: u32, clock_rate: u32) -> u32 {
    if clock_rate == 0 {
        return 0;
    }
    let delta_ts = rtp_ts.wrapping_sub(prev_rtp_ts) as i32;
    let ms = (delta_ts as f64) * 1000.0 / clock_rate as f64;
    ms.round().max(0.0) as u32
}

/// Map a static RTP payload type number to its codec name (RFC 3551).
///
/// Returns `None` for dynamic payload types (96-127) — those require SDP
/// `a=rtpmap` for identification.
pub fn codec_from_pt(pt: u8) -> Option<&'static str> {
    match pt {
        0 => Some("PCMU"),
        3 => Some("GSM"),
        4 => Some("G723"),
        8 => Some("PCMA"),
        9 => Some("G722"),
        13 => Some("CN"), // Comfort Noise
        18 => Some("G729"),
        34 => Some("H263"),
        _ => None,
    }
}

/// RTP clock rate in Hz for well-known static payload types (RFC 3551).
/// Returns `None` for dynamic types (96-127) — caller must derive from SDP.
pub fn clock_rate_from_pt(pt: u8) -> Option<u32> {
    match pt {
        0 => Some(8000),   // PCMU
        3 => Some(8000),   // GSM
        4 => Some(8000),   // G723
        8 => Some(8000),   // PCMA
        9 => Some(8000),   // G722 (RFC 3551: 8000 Hz clock despite 16kHz audio)
        13 => Some(8000),  // CN
        18 => Some(8000),  // G729
        34 => Some(90000), // H263 (video)
        _ => None,
    }
}

/// Unit tests for stream state tracking: initialization, jitter and loss
/// accounting, payload-type tables, sequence wraparound, and history caps.
#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::rtp::parser::RtpHeader;

    /// Build a fixed test StreamKey (SSRC 0x12345678, 10.0.0.1:20000 →
    /// 10.0.0.2:30000).
    fn make_key() -> StreamKey {
        StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        }
    }

    /// Build a minimal RtpHeader with the given sequence, RTP timestamp,
    /// and payload type.
    fn make_header(seq: u16, ts: u32, pt: u8) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: pt,
            sequence: seq,
            timestamp: ts,
            ssrc: 0x12345678,
            payload_offset: 12,
        }
    }

    /// Recording more than MAX_QUALITY_INTERVALS snapshots caps the trend
    /// history and evicts the oldest entries first.
    #[test]
    fn quality_intervals_are_bounded_oldest_out() {
        // A long-lived stream must not grow its trend history without
        // bound: one interval per 5 s means a day-long call is 17k
        // entries per stream. The history is a ring capped at
        // MAX_QUALITY_INTERVALS with the oldest entry evicted first.
        let mut s = RtpStream::new(make_key(), &make_header(0, 0, 0), ts(0));
        let n = MAX_QUALITY_INTERVALS + 10;
        for i in 1..=n {
            // one packet every QUALITY_INTERVAL_SECS closes an interval
            s.update(
                &make_header(i as u16, i as u32 * 160, 0),
                ts(i as i64 * QUALITY_INTERVAL_SECS),
                160,
            );
        }
        assert_eq!(
            s.quality_intervals.len(),
            MAX_QUALITY_INTERVALS,
            "history must be capped at MAX_QUALITY_INTERVALS"
        );
        // oldest evicted: the first surviving interval is the 11th
        // recorded one, and order stays oldest-first.
        let first = s.quality_intervals.first().expect("non-empty");
        let last = s.quality_intervals.last().expect("non-empty");
        assert!(first.timestamp < last.timestamp, "oldest-first order");
        assert!(
            first.timestamp >= ts(10 * QUALITY_INTERVAL_SECS),
            "the ten oldest intervals were evicted"
        );
    }

    /// Fixed-epoch test clock: `secs` seconds past 1_700_000_000 UTC.
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
    }

    /// Burst/gap analysis must bound its window to the sequence range the
    /// `lost_sequences` log still retains. When the log is full and a long
    /// clean tail has advanced `last_seq` far past the loss region, the old
    /// `last_seq`-anchored window walked past every retained loss and
    /// reported NO burstiness — a silent undercount. Anchoring at the newest
    /// retained loss keeps the retained bursts visible.
    #[test]
    fn burst_gap_window_bounded_to_retained_log() {
        let mut stream = RtpStream::new(make_key(), &make_header(0, 0, 0), ts(0));

        // Retained log: 250 bursts of 4 consecutive losses, each separated by
        // a single received sequence — lost {1,2,3,4, 6,7,8,9, ...}. front=1,
        // back=1249, exactly LOST_SEQ_LOG_CAP entries.
        stream.lost_sequences.clear();
        for g in 0..250u16 {
            let base = g * 5 + 1;
            for j in 0..4u16 {
                stream.lost_sequences.push_back(base + j);
            }
        }
        assert_eq!(stream.lost_sequences.len(), LOST_SEQ_LOG_CAP);
        assert_eq!(stream.lost_sequences.front().copied(), Some(1));
        assert_eq!(stream.lost_sequences.back().copied(), Some(1249));
        stream.lost_packets = LOST_SEQ_LOG_CAP as u64;

        // A long clean tail pushes last_seq past back + BURST_WINDOW_CAP, so a
        // last_seq-anchored window of BURST_WINDOW_CAP would exclude the loss
        // region entirely.
        stream.last_seq = 1249 + BURST_WINDOW_CAP as u16 + 100;
        stream.packet_count = 20_000;

        let bga = stream.burst_gap_analysis().expect("losses present");
        assert!(
            bga.is_bursty,
            "retained bursts must stay visible, not undercount to zero"
        );
        assert!(
            bga.burst_count >= 100,
            "expected the ~250 retained bursts, got {}",
            bga.burst_count
        );
    }

    /// Silence duration is derived from observed CN packet spacing, not a
    /// fixed 20 ms cadence. Under discontinuous transmission the RTP
    /// timestamp jumps between sparse CN frames, and the duration must follow
    /// it rather than assuming one 20 ms frame per packet.
    #[test]
    fn silence_duration_derived_from_cn_spacing() {
        // PCMU (8 kHz). CN frames arrive one sequence apart but 1600 RTP
        // timestamp units (200 ms) apart.
        let mut stream = RtpStream::new(make_key(), &make_header(100, 0, 0), ts(0));
        for k in 0..4u32 {
            let seq = 101 + k as u16;
            let rtp_ts = 1600 * (k + 1);
            stream.update(&make_header(seq, rtp_ts, 13), ts(1 + k as i64), 1);
        }
        let sp = stream.silence_periods.last().expect("a silence period");
        // Span first→last = 3 × 200 ms = 600 ms, plus one nominal 20 ms
        // frame. The old fixed-20 ms-per-frame estimate reported only 80 ms.
        assert!(
            sp.duration_ms >= 600,
            "duration must track observed CN spacing, got {}ms",
            sp.duration_ms
        );
        assert_eq!(sp.start_seq, 101);
        assert_eq!(sp.end_seq, 104);
    }

    /// A fresh stream starts with packet_count 1, resolved PCMU codec, and
    /// zeroed jitter/loss/orphan state.
    #[test]
    fn new_stream_initial_values() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        let stream = RtpStream::new(key.clone(), &hdr, ts(0));

        assert_eq!(stream.key, key);
        assert_eq!(stream.payload_type, 0);
        assert_eq!(stream.codec.as_deref(), Some("PCMU"));
        assert_eq!(stream.packet_count, 1);
        assert_eq!(stream.octet_count, 0);
        assert_eq!(stream.last_seq, 100);
        assert_eq!(stream.jitter, 0.0);
        assert_eq!(stream.lost_packets, 0);
        assert!(!stream.orphaned);
        assert!(!stream.heuristic);
        assert!(stream.associated_dialog.is_none());
    }

    /// `is_active_at` decides activity relative to an injected instant, so it
    /// is deterministic for offline replay: a stream is active within 30 s of
    /// its `last_seen` and inactive once the reference instant moves past that
    /// window. The 30 s boundary is exclusive.
    #[test]
    fn is_active_at_is_deterministic() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        // last_seen is seeded to ts(0) by RtpStream::new.
        let stream = RtpStream::new(key, &hdr, ts(0));

        // Within the 30 s window (and at last_seen itself) → active.
        assert!(stream.is_active_at(ts(0)));
        assert!(stream.is_active_at(ts(29)));
        // Exactly 30 s later is the exclusive boundary → inactive.
        assert!(!stream.is_active_at(ts(30)));
        // Well past the window → inactive.
        assert!(!stream.is_active_at(ts(120)));
    }

    /// Nine sequential updates accumulate packet, octet, and sequence
    /// state correctly.
    #[test]
    fn update_ten_packets() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        for i in 1..10 {
            let h = make_header(100 + i, (i as u32) * 160, 0);
            stream.update(&h, ts(i as i64 * 20 / 1000), 160);
        }

        assert_eq!(stream.packet_count, 10);
        assert_eq!(stream.octet_count, 160 * 9); // 9 updates
        assert_eq!(stream.last_seq, 109);
    }

    /// A reordered packet (RTP timestamp lower than its predecessor) must not
    /// blow up the jitter estimate: the wrapped timestamp difference is a
    /// signed (i32) transit delta per RFC 3550, not a ~4.29e9 unsigned spike.
    #[test]
    fn reordered_packet_does_not_inflate_jitter() {
        let key = make_key();
        // 8 kHz PCMU, first packet at RTP ts 16000.
        let hdr = make_header(100, 16_000, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // Second packet arrives 20 ms later but carries an EARLIER RTP
        // timestamp (reordered), one 20 ms frame back: 16000 - 160.
        let reordered = make_header(101, 15_840, 0);
        let arrival = ts(0) + chrono::Duration::milliseconds(20);
        stream.update(&reordered, arrival, 160);

        // Signed semantics keep the transit delta tiny; the old unsigned cast
        // produced a jitter estimate in the tens of millions of ms.
        assert!(
            stream.jitter < 1000.0,
            "reordered packet must not inflate jitter, got {}",
            stream.jitter
        );
    }

    /// Skipping sequence numbers 101-103 registers exactly 3 lost packets.
    #[test]
    fn sequence_gap_increments_lost() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // Skip seq 101-103 (gap of 3)
        let h = make_header(104, 640, 0);
        stream.update(&h, ts(1), 160);

        assert_eq!(stream.lost_packets, 3);
        assert_eq!(stream.packet_count, 2);
    }

    /// The jitter estimator runs on every update and stays finite.
    #[test]
    fn jitter_calculated_on_update() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // Send packets with consistent 20ms intervals and 160-sample RTP timestamps
        // (8kHz * 20ms = 160). Perfect timing → jitter stays near 0.
        for i in 1..5 {
            let h = make_header(100 + i, (i as u32) * 160, 0);
            // Exactly 20ms apart in wall-clock (but our timestamp resolution is seconds,
            // so jitter will be non-zero due to granularity; the algorithm still runs)
            stream.update(&h, ts(i as i64), 160);
        }

        // Jitter should be calculated (non-NaN, finite)
        assert!(stream.jitter.is_finite());
    }

    /// Well-known static payload types map to their RFC 3551 codec names.
    #[test]
    fn codec_from_pt_static_types() {
        assert_eq!(codec_from_pt(0), Some("PCMU"));
        assert_eq!(codec_from_pt(8), Some("PCMA"));
        assert_eq!(codec_from_pt(9), Some("G722"));
        assert_eq!(codec_from_pt(18), Some("G729"));
        assert_eq!(codec_from_pt(3), Some("GSM"));
        assert_eq!(codec_from_pt(13), Some("CN"));
    }

    /// Dynamic payload types (96-127) have no static codec mapping.
    #[test]
    fn codec_from_pt_dynamic_returns_none() {
        assert_eq!(codec_from_pt(96), None);
        assert_eq!(codec_from_pt(111), None);
        assert_eq!(codec_from_pt(127), None);
    }

    /// Packets spanning more than 5 seconds produce at least one quality
    /// interval snapshot.
    #[test]
    fn quality_interval_recorded() {
        let key = make_key();
        let hdr = make_header(100, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // Send packets spanning >5 seconds
        for i in 1..=10 {
            let h = make_header(100 + i, (i as u32) * 160, 0);
            stream.update(&h, ts(i as i64), 160);
        }

        // After 10 seconds of packets with 5s intervals, we should have at least 1 interval
        assert!(
            !stream.quality_intervals.is_empty(),
            "Expected at least one quality interval after 10s"
        );
    }

    /// Static audio payload types report 8000 Hz; H263 video reports
    /// 90000 Hz.
    #[test]
    fn clock_rate_from_pt_static_types() {
        // PCMU and other narrowband audio codecs use 8000 Hz
        assert_eq!(clock_rate_from_pt(0), Some(8000));
        assert_eq!(clock_rate_from_pt(3), Some(8000));
        assert_eq!(clock_rate_from_pt(4), Some(8000));
        assert_eq!(clock_rate_from_pt(8), Some(8000));
        assert_eq!(clock_rate_from_pt(9), Some(8000)); // G722: 8000 per RFC 3551
        assert_eq!(clock_rate_from_pt(13), Some(8000));
        assert_eq!(clock_rate_from_pt(18), Some(8000));
        // H263 video uses 90000 Hz
        assert_eq!(clock_rate_from_pt(34), Some(90000));
    }

    /// Dynamic payload types have no static clock rate.
    #[test]
    fn clock_rate_from_pt_dynamic_returns_none() {
        assert_eq!(clock_rate_from_pt(96), None);
        assert_eq!(clock_rate_from_pt(111), None);
        assert_eq!(clock_rate_from_pt(127), None);
    }

    /// A new PCMU (PT 0) stream resolves its clock rate to 8000 Hz.
    #[test]
    fn new_stream_clock_rate_pcmu() {
        let key = make_key();
        let hdr = make_header(100, 0, 0); // PT 0 = PCMU
        let stream = RtpStream::new(key, &hdr, ts(0));
        assert_eq!(stream.clock_rate, 8000);
    }

    /// A new H263 (PT 34) stream resolves its clock rate to 90000 Hz.
    #[test]
    fn new_stream_clock_rate_h263() {
        let key = make_key();
        let hdr = make_header(100, 0, 34); // PT 34 = H263 (video)
        let stream = RtpStream::new(key, &hdr, ts(0));
        assert_eq!(stream.clock_rate, 90000);
    }

    /// A new stream on a dynamic PT falls back to the 8000 Hz default.
    #[test]
    fn new_stream_clock_rate_dynamic_defaults_to_8000() {
        let key = make_key();
        let hdr = make_header(100, 0, 96); // PT 96 = dynamic
        let stream = RtpStream::new(key, &hdr, ts(0));
        // Dynamic types return None from clock_rate_from_pt; RtpStream::new
        // falls back to 8000 via unwrap_or(8000).
        assert_eq!(stream.clock_rate, 8000);
    }

    /// The jitter calculation scales RTP timestamp deltas by the stream's
    /// own clock rate (90 kHz for H263).
    #[test]
    fn jitter_uses_correct_clock_rate() {
        // Verify jitter calculation uses the stream's clock_rate.
        // With H263 (90000 Hz), 1 second = 90000 timestamp units.
        let key = make_key();
        let hdr = make_header(100, 0, 34); // H263
        let mut stream = RtpStream::new(key, &hdr, ts(0));
        assert_eq!(stream.clock_rate, 90000);

        // Send a second packet: 1 second later in wall-clock, 90000 ts units later
        // (perfect timing for 90 kHz clock -> jitter stays low).
        let h = make_header(101, 90000, 34);
        stream.update(&h, ts(1), 1000);
        assert!(stream.jitter.is_finite());
    }

    /// A 65535 → 0 sequence wrap registers no false packet loss.
    #[test]
    fn sequence_wraparound_no_false_loss() {
        let key = make_key();
        let hdr = make_header(65534, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // seq 65535 (normal increment)
        let h = make_header(65535, 160, 0);
        stream.update(&h, ts(1), 160);
        assert_eq!(stream.lost_packets, 0);

        // seq 0 (wraparound)
        let h = make_header(0, 320, 0);
        stream.update(&h, ts(2), 160);
        assert_eq!(stream.lost_packets, 0);

        // seq 1 (normal after wrap)
        let h = make_header(1, 480, 0);
        stream.update(&h, ts(3), 160);
        assert_eq!(stream.lost_packets, 0);
    }

    /// The lost-sequence log caps at 1000 entries with correct oldest-out
    /// eviction across successive gaps.
    #[test]
    fn lost_sequences_vecdeque_pop_front_over_1000() {
        // Fill lost_sequences beyond the 1000-entry cap and verify
        // pop_front eviction works correctly (no panic, correct count).
        let key = make_key();
        let hdr = make_header(0, 0, 0);
        let mut stream = RtpStream::new(key, &hdr, ts(0));

        // Create a huge gap: jump from seq 0 to seq 2001 (gap of 2000).
        // The update loop caps recording at 1000 entries per gap.
        let h = make_header(2001, 2001 * 160, 0);
        stream.update(&h, ts(1), 160);

        assert_eq!(stream.lost_packets, 2000, "should detect 2000 lost packets");
        assert_eq!(
            stream.lost_sequences.len(),
            1000,
            "lost_sequences should be capped at 1000"
        );

        // The oldest entry should be seq 1 (first lost), and the deque should
        // contain the first 1000 lost seqs: 1..=1000
        assert_eq!(
            stream.lost_sequences.front().copied(),
            Some(1),
            "first entry should be seq 1"
        );
        assert_eq!(
            stream.lost_sequences.back().copied(),
            Some(1000),
            "last entry should be seq 1000"
        );

        // Now create another gap that forces pop_front evictions.
        // Jump from 2001 to 2502 (gap of 500). This should evict the
        // 500 oldest entries and push 500 new ones.
        let h = make_header(2502, 2502 * 160, 0);
        stream.update(&h, ts(2), 160);

        assert_eq!(stream.lost_packets, 2500, "total lost should be 2500");
        assert_eq!(
            stream.lost_sequences.len(),
            1000,
            "still capped at 1000 after second gap"
        );

        // After evicting 500 oldest (1..=500) and adding 500 new (2002..=2501),
        // the deque should now span 501..=1000 ++ 2002..=2501
        assert_eq!(
            stream.lost_sequences.front().copied(),
            Some(501),
            "oldest should now be seq 501"
        );
        assert_eq!(
            stream.lost_sequences.back().copied(),
            Some(2501),
            "newest should be seq 2501"
        );
    }
}
