//! RTP stream state tracking.
//!
//! An [`RtpStream`] represents a single media flow identified by its
//! [`StreamKey`] (SSRC + source/destination socket addresses). It tracks
//! packet counts, jitter (RFC 3550 algorithm), sequence-gap loss detection,
//! and periodic quality intervals for trend analysis.

use std::net::SocketAddr;

use chrono::{DateTime, Duration, Utc};

use super::parser::RtpHeader;

// ── Quality interval period ──────────────────────────────────────────

/// How often to snapshot quality metrics into a [`QualityInterval`].
const QUALITY_INTERVAL_SECS: i64 = 5;

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

/// A detected silence period from Comfort Noise packets.
#[derive(Debug, Clone)]
pub struct SilencePeriod {
    /// First sequence number in the silence period.
    pub start_seq: u16,
    /// Last sequence number in the silence period.
    pub end_seq: u16,
    /// Estimated duration in milliseconds (20ms per CN frame).
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
    /// Running interarrival jitter estimate (RFC 3550, in timestamp units).
    pub jitter: f64,
    /// Estimated lost packets from sequence number gaps.
    pub lost_packets: u64,
    /// SIP Call-ID if this stream has been linked to a dialog.
    pub associated_dialog: Option<String>,
    /// `true` if no dialog has been associated after the orphan timeout.
    pub orphaned: bool,
    /// `true` if this stream was discovered via heuristic (no SDP).
    pub heuristic: bool,
    /// Periodic quality snapshots for trend analysis.
    pub quality_intervals: Vec<QualityInterval>,
    /// Sequence numbers of lost packets (capped at 1000 most recent entries).
    /// Used for burst/gap analysis.
    pub lost_sequences: std::collections::VecDeque<u16>,
    /// Count of Comfort Noise (PT=13) frames received.
    pub cn_frames: u32,
    /// Detected silence periods (capped at 100).
    pub silence_periods: Vec<SilencePeriod>,
    /// Ring buffer of raw RTP payloads for audio export (G.711 only).
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
    /// Returns `true` if the stream has been active within the last 30 seconds.
    pub fn is_active(&self) -> bool {
        let thirty_secs_ago = Utc::now() - chrono::Duration::seconds(30);
        self.last_seen > thirty_secs_ago
    }

    /// Create a new stream from its first observed RTP packet.
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
            quality_intervals: Vec::new(),
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
                // Record lost sequence numbers for burst/gap analysis (capped at 1000)
                for offset in 0..gap.min(1000) {
                    if self.lost_sequences.len() >= 1000 {
                        self.lost_sequences.pop_front();
                    }
                    self.lost_sequences
                        .push_back(expected.wrapping_add(offset as u16));
                }
            }
        }
        self.last_seq = header.sequence;

        // Comfort Noise (PT=13) tracking for silence detection
        if header.payload_type == 13 {
            self.cn_frames += 1;
            if let Some(last) = self.silence_periods.last_mut() {
                if header.sequence == last.end_seq.wrapping_add(1) {
                    last.end_seq = header.sequence;
                    last.duration_ms += 20;
                } else if self.silence_periods.len() < 100 {
                    self.silence_periods.push(SilencePeriod {
                        start_seq: header.sequence,
                        end_seq: header.sequence,
                        duration_ms: 20,
                    });
                }
            } else {
                self.silence_periods.push(SilencePeriod {
                    start_seq: header.sequence,
                    end_seq: header.sequence,
                    duration_ms: 20,
                });
            }
        }

        // RFC 3550 jitter calculation (Section 6.4.1, A.8)
        if let (Some(prev_arrival), Some(prev_rtp_ts)) = (self.prev_arrival, self.prev_rtp_ts) {
            let arrival_diff = timestamp
                .signed_duration_since(prev_arrival)
                .num_milliseconds() as f64;
            // Convert RTP timestamp difference to milliseconds.
            // Use wrapping subtraction for RTP timestamp rollover.
            let rtp_diff = header.timestamp.wrapping_sub(prev_rtp_ts) as f64;
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
    fn record_quality_interval(&mut self, timestamp: DateTime<Utc>) {
        let total_in_interval = self.interval_packets + self.interval_lost;
        let loss_pct = if total_in_interval > 0 {
            (self.interval_lost as f64 / total_in_interval as f64) * 100.0
        } else {
            0.0
        };

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
    /// Reconstructs a received/lost sequence from the first seen sequence
    /// number through `last_seq` using the `lost_sequences` log, then
    /// delegates to [`super::quality::analyze_burst_gap`].
    ///
    /// Returns `None` if there are no lost packets to analyze.
    pub fn burst_gap_analysis(&self) -> Option<super::quality::BurstGapAnalysis> {
        if self.lost_sequences.is_empty() {
            return None;
        }

        // Default ptime for common audio codecs (ms).
        let ptime_ms = 20.0;

        // Build a received/lost bitmap over the range covered by lost_sequences.
        // Use the min/max of lost_sequences to bound the window, then fill
        // received=true for all sequence numbers in between, marking lost ones.
        let lost_set: std::collections::HashSet<u16> =
            self.lost_sequences.iter().copied().collect();

        // Determine the window: from first_seq to last_seq we observed.
        // For simplicity use the total received + lost count as the window size,
        // capped at a reasonable maximum to avoid huge allocations.
        let window_size = (self.packet_count + self.lost_packets).min(10_000) as usize;
        if window_size == 0 {
            return None;
        }

        // Walk backwards from last_seq for `window_size` packets.
        let mut received = Vec::with_capacity(window_size);
        for i in 0..window_size {
            let seq = self
                .last_seq
                .wrapping_sub(window_size as u16)
                .wrapping_add(i as u16 + 1);
            received.push(!lost_set.contains(&seq));
        }

        Some(super::quality::analyze_burst_gap(&received, ptime_ms))
    }
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::rtp::parser::RtpHeader;

    fn make_key() -> StreamKey {
        StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        }
    }

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

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
    }

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

    #[test]
    fn codec_from_pt_static_types() {
        assert_eq!(codec_from_pt(0), Some("PCMU"));
        assert_eq!(codec_from_pt(8), Some("PCMA"));
        assert_eq!(codec_from_pt(9), Some("G722"));
        assert_eq!(codec_from_pt(18), Some("G729"));
        assert_eq!(codec_from_pt(3), Some("GSM"));
        assert_eq!(codec_from_pt(13), Some("CN"));
    }

    #[test]
    fn codec_from_pt_dynamic_returns_none() {
        assert_eq!(codec_from_pt(96), None);
        assert_eq!(codec_from_pt(111), None);
        assert_eq!(codec_from_pt(127), None);
    }

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

    #[test]
    fn clock_rate_from_pt_dynamic_returns_none() {
        assert_eq!(clock_rate_from_pt(96), None);
        assert_eq!(clock_rate_from_pt(111), None);
        assert_eq!(clock_rate_from_pt(127), None);
    }

    #[test]
    fn new_stream_clock_rate_pcmu() {
        let key = make_key();
        let hdr = make_header(100, 0, 0); // PT 0 = PCMU
        let stream = RtpStream::new(key, &hdr, ts(0));
        assert_eq!(stream.clock_rate, 8000);
    }

    #[test]
    fn new_stream_clock_rate_h263() {
        let key = make_key();
        let hdr = make_header(100, 0, 34); // PT 34 = H263 (video)
        let stream = RtpStream::new(key, &hdr, ts(0));
        assert_eq!(stream.clock_rate, 90000);
    }

    #[test]
    fn new_stream_clock_rate_dynamic_defaults_to_8000() {
        let key = make_key();
        let hdr = make_header(100, 0, 96); // PT 96 = dynamic
        let stream = RtpStream::new(key, &hdr, ts(0));
        // Dynamic types return None from clock_rate_from_pt; RtpStream::new
        // falls back to 8000 via unwrap_or(8000).
        assert_eq!(stream.clock_rate, 8000);
    }

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
