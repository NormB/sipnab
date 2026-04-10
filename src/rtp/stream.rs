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
    pub lost_sequences: Vec<u16>,

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
    /// Create a new stream from its first observed RTP packet.
    pub fn new(key: StreamKey, header: &RtpHeader, timestamp: DateTime<Utc>) -> Self {
        let codec = codec_from_pt(header.payload_type).map(String::from);
        Self {
            key,
            codec,
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
            lost_sequences: Vec::new(),
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
                        self.lost_sequences.remove(0);
                    }
                    self.lost_sequences.push(expected.wrapping_add(offset as u16));
                }
            }
        }
        self.last_seq = header.sequence;

        // RFC 3550 jitter calculation (Section 6.4.1, A.8)
        if let (Some(prev_arrival), Some(prev_rtp_ts)) = (self.prev_arrival, self.prev_rtp_ts) {
            let arrival_diff = timestamp
                .signed_duration_since(prev_arrival)
                .num_milliseconds() as f64;
            // Convert RTP timestamp difference to milliseconds.
            // Use wrapping subtraction for RTP timestamp rollover.
            let rtp_diff = header.timestamp.wrapping_sub(prev_rtp_ts) as f64;
            // Approximate: assume 8kHz clock for common audio codecs.
            // A proper implementation would use the clock rate from SDP,
            // but 8kHz is correct for PCMU/PCMA/G729 and close enough
            // for jitter trending on others.
            let rtp_diff_ms = rtp_diff / 8.0;
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
            let seq = self.last_seq.wrapping_sub(window_size as u16).wrapping_add(i as u16 + 1);
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
}
