//! RTP stream storage and lifecycle management.
//!
//! [`StreamStore`] maintains an indexed collection of [`RtpStream`]s,
//! creating or updating streams as RTP/RTCP packets arrive. It handles
//! dialog linking (from SDP), orphan detection, and capacity eviction.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use indexmap::IndexMap;

use chrono::{DateTime, Utc};

use super::parser::RtpHeader;
use super::rtcp::{ReceptionReport, RtcpPacket};
use super::stream::{RtpStream, StreamKey};
use crate::capture::ParsedPacket;
use crate::sip::sdp::SdpMedia;

/// Central store for all tracked RTP streams.
///
/// Streams are indexed by [`StreamKey`] for O(1) lookup. When the store
/// reaches its capacity limit, the oldest stream (by insertion order) is
/// evicted to make room.
pub struct StreamStore {
    /// All tracked streams, keyed by [`StreamKey`] in insertion order.
    streams: IndexMap<StreamKey, RtpStream>,
    /// SSRC → keys of streams carrying it, in insertion order. RTCP
    /// reports identify streams by SSRC only; without this, every report
    /// block linear-scanned the whole store. Kept consistent on
    /// insert/evict/clear.
    ssrc_index: std::collections::HashMap<u32, Vec<StreamKey>>,
    /// Maximum number of concurrent streams before eviction.
    max_streams: usize,
    /// Maximum number of audio frames to retain per stream for WAV export.
    max_audio_frames: usize,
    /// Whether G.711/Opus payloads are cloned into per-stream buffers for
    /// WAV export / playback. On by default (the TUI exports on demand);
    /// batch mode turns it off — nothing there ever reads the buffers, so
    /// buffering was a per-packet allocation for nothing.
    audio_capture: bool,
}

impl StreamStore {
    /// Create a new store with the given stream capacity limit.
    pub fn new(max_streams: usize) -> Self {
        Self {
            streams: IndexMap::with_capacity(max_streams.min(1024)),
            ssrc_index: std::collections::HashMap::new(),
            max_streams,
            max_audio_frames: 1500,
            audio_capture: true,
        }
    }

    /// Enable or disable audio payload buffering (see the field docs).
    pub fn set_audio_capture(&mut self, enabled: bool) {
        self.audio_capture = enabled;
    }

    /// Set the maximum number of audio frames retained per stream for WAV export.
    pub fn set_max_audio_frames(&mut self, max: usize) {
        self.max_audio_frames = max;
    }

    /// Process an RTP packet: create a new stream or update an existing one.
    ///
    /// Uses the packet's 5-tuple (src/dst addresses and ports) combined with
    /// the RTP SSRC to form the stream key.
    pub fn process_rtp(
        &mut self,
        parsed: &ParsedPacket,
        rtp: &RtpHeader,
        timestamp: DateTime<Utc>,
    ) {
        let key = StreamKey {
            ssrc: rtp.ssrc,
            src: SocketAddr::new(parsed.src_addr, parsed.src_port),
            dst: SocketAddr::new(parsed.dst_addr, parsed.dst_port),
        };

        let payload_len = parsed.payload.len().saturating_sub(rtp.payload_offset);

        if let Some(stream) = self.streams.get_mut(&key) {
            stream.update(rtp, timestamp, payload_len);
            // Capture G.711 payload for audio export (ring buffer, capped)
            if self.audio_capture && is_audio_capturable(stream.codec.as_deref()) {
                let payload_start = rtp.payload_offset;
                if payload_start < parsed.payload.len() {
                    let audio = parsed.payload[payload_start..].to_vec();
                    if stream.payload_buffer.len() >= self.max_audio_frames {
                        stream.payload_buffer.pop_front();
                    }
                    stream.payload_buffer.push_back((rtp.timestamp, audio));
                }
            }
        } else {
            self.ensure_capacity();
            let mut stream = RtpStream::new(key.clone(), rtp, timestamp);
            stream.octet_count = payload_len as u64;
            // Capture G.711 payload for audio export (first packet)
            if self.audio_capture && is_audio_capturable(stream.codec.as_deref()) {
                let payload_start = rtp.payload_offset;
                if payload_start < parsed.payload.len() {
                    let audio = parsed.payload[payload_start..].to_vec();
                    stream.payload_buffer.push_back((rtp.timestamp, audio));
                }
            }
            self.ssrc_index
                .entry(key.ssrc)
                .or_default()
                .push(key.clone());
            self.streams.insert(key, stream);
        }
    }

    /// Update streams from RTCP reception reports.
    ///
    /// Matches report SSRCs against known streams to incorporate
    /// authoritative loss/jitter data from receivers.
    pub fn process_rtcp(&mut self, packets: &[RtcpPacket]) {
        for pkt in packets {
            let reports: &[ReceptionReport] = match pkt {
                RtcpPacket::SenderReport(sr) => &sr.reports,
                RtcpPacket::ReceiverReport(rr) => &rr.reports,
                _ => continue,
            };

            for report in reports {
                // O(1) via the SSRC index; first key = earliest surviving
                // stream, matching the previous insertion-order scan.
                if let Some(stream) = self
                    .ssrc_index
                    .get(&report.ssrc)
                    .and_then(|keys| keys.first())
                    .and_then(|key| self.streams.get_mut(key))
                {
                    stream.jitter = report.jitter as f64;
                    stream.lost_packets = u64::from(report.cumulative_lost);
                }
            }
        }
    }

    /// Link streams to a SIP dialog by matching the SDP media endpoint.
    ///
    /// When SDP is parsed from a SIP message, call this with the negotiated
    /// media address and port plus the dialog's Call-ID. Any stream whose
    /// source or destination matches the media endpoint gets linked.
    pub fn link_to_dialog(&mut self, media_addr: IpAddr, media_port: u16, call_id: &str) {
        for stream in self.streams.values_mut() {
            let src_match =
                stream.key.src.ip() == media_addr && stream.key.src.port() == media_port;
            let dst_match =
                stream.key.dst.ip() == media_addr && stream.key.dst.port() == media_port;

            if (src_match || dst_match) && stream.associated_dialog.is_none() {
                stream.associated_dialog = Some(call_id.to_string());
                stream.orphaned = false;
            }
        }
    }

    /// Link streams to a SIP dialog and enrich codec/clock_rate from SDP.
    ///
    /// Like [`link_to_dialog`], but also propagates codec name and clock rate
    /// from SDP `a=rtpmap` entries to streams with dynamic payload types.
    /// This enables audio capture and export for codecs like Opus that use
    /// dynamic PT numbers (96-127).
    pub fn link_to_dialog_with_sdp(
        &mut self,
        media_addr: IpAddr,
        media_port: u16,
        call_id: &str,
        media: &SdpMedia,
    ) {
        for stream in self.streams.values_mut() {
            let src_match =
                stream.key.src.ip() == media_addr && stream.key.src.port() == media_port;
            let dst_match =
                stream.key.dst.ip() == media_addr && stream.key.dst.port() == media_port;

            if src_match || dst_match {
                if stream.associated_dialog.is_none() {
                    stream.associated_dialog = Some(call_id.to_string());
                    stream.orphaned = false;
                }

                // Enrich codec info from SDP rtpmap for dynamic payload types.
                // Only update if the stream's codec is unknown (dynamic PT with
                // no static mapping).
                if stream.codec.is_none()
                    && let Some(rtpmap) = media
                        .rtpmap
                        .iter()
                        .find(|rm| rm.payload_type == stream.payload_type)
                {
                    stream.codec = Some(rtpmap.encoding.clone());
                    stream.clock_rate = rtpmap.clock_rate;
                }
            }
        }
    }

    /// Mark unlinked streams as orphaned if they have been active longer
    /// than the given timeout without being associated to a dialog.
    pub fn mark_orphaned(&mut self, timeout: Duration) {
        let now = Utc::now();
        let timeout_chrono = match chrono::Duration::from_std(timeout) {
            Ok(d) => d,
            Err(_) => chrono::Duration::days(365),
        };

        for stream in self.streams.values_mut() {
            if stream.associated_dialog.is_none()
                && !stream.orphaned
                && now.signed_duration_since(stream.first_seen) >= timeout_chrono
            {
                stream.orphaned = true;
            }
        }
    }

    /// Look up a stream by its key.
    pub fn get(&self, key: &StreamKey) -> Option<&RtpStream> {
        self.streams.get(key)
    }

    /// Iterate over all tracked streams.
    pub fn iter(&self) -> impl Iterator<Item = &RtpStream> {
        self.streams.values()
    }

    /// Total number of tracked streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether the store contains no streams.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Remove all streams from the store.
    pub fn clear(&mut self) {
        self.streams.clear();
        self.ssrc_index.clear();
    }

    /// Count of streams flagged as orphaned.
    pub fn orphaned_count(&self) -> usize {
        self.streams.values().filter(|s| s.orphaned).count()
    }

    /// Evict the oldest stream (first entry in insertion order) if at capacity.
    fn ensure_capacity(&mut self) {
        if self.streams.len() >= self.max_streams
            && !self.streams.is_empty()
            && let Some((evicted, _)) = self.streams.shift_remove_index(0)
            && let Some(keys) = self.ssrc_index.get_mut(&evicted.ssrc)
        {
            keys.retain(|k| k != &evicted);
            if keys.is_empty() {
                self.ssrc_index.remove(&evicted.ssrc);
            }
        }
    }
}

/// Check if a codec supports audio payload capture for playback/export.
///
/// G.711 (PCMU/PCMA) and Opus are supported. Opus codec names are
/// case-insensitive per SDP convention (`opus`, `OPUS`, `Opus`).
fn is_audio_capturable(codec: Option<&str>) -> bool {
    matches!(
        codec,
        Some("PCMU") | Some("PCMA") | Some("opus") | Some("OPUS") | Some("Opus")
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::rtp::parser::RtpHeader;

    fn make_parsed(src_port: u16, dst_port: u16, payload_len: usize) -> ParsedPacket {
        ParsedPacket {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            transport: TransportProto::Udp,
            payload: vec![0u8; 12 + payload_len].into(), // 12 for RTP header
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
        }
    }

    fn make_rtp_header(ssrc: u32, seq: u16) -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: seq as u32 * 160,
            ssrc,
            payload_offset: 12,
        }
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid")
    }

    #[test]
    fn process_rtp_creates_stream() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xAAAA, 1);

        store.process_rtp(&parsed, &rtp, ts(0));
        assert_eq!(store.len(), 1);

        let key = StreamKey {
            ssrc: 0xAAAA,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(stream.packet_count, 1);
        assert_eq!(stream.payload_type, 0);
    }

    #[test]
    fn process_same_ssrc_updates_not_duplicates() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp1 = make_rtp_header(0xBBBB, 1);
        let rtp2 = make_rtp_header(0xBBBB, 2);

        store.process_rtp(&parsed, &rtp1, ts(0));
        store.process_rtp(&parsed, &rtp2, ts(1));

        assert_eq!(store.len(), 1);
        let key = StreamKey {
            ssrc: 0xBBBB,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(stream.packet_count, 2);
    }

    #[test]
    fn max_streams_evicts_oldest() {
        let mut store = StreamStore::new(2);

        // Stream 1: ts=0
        let p1 = make_parsed(20000, 30000, 160);
        let r1 = make_rtp_header(0x1111, 1);
        store.process_rtp(&p1, &r1, ts(0));

        // Stream 2: ts=1
        let p2 = make_parsed(20001, 30001, 160);
        let r2 = make_rtp_header(0x2222, 1);
        store.process_rtp(&p2, &r2, ts(1));

        assert_eq!(store.len(), 2);

        // Stream 3: should evict stream 1 (oldest)
        let p3 = make_parsed(20002, 30002, 160);
        let r3 = make_rtp_header(0x3333, 1);
        store.process_rtp(&p3, &r3, ts(2));

        assert_eq!(store.len(), 2);

        // Stream 1 should be gone
        let key1 = StreamKey {
            ssrc: 0x1111,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert!(
            store.get(&key1).is_none(),
            "oldest stream should be evicted"
        );
    }

    #[test]
    fn link_to_dialog_sets_call_id() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xCCCC, 1);
        store.process_rtp(&parsed, &rtp, ts(0));

        store.link_to_dialog(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            30000,
            "call-123@example.com",
        );

        let key = StreamKey {
            ssrc: 0xCCCC,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(
            stream.associated_dialog.as_deref(),
            Some("call-123@example.com")
        );
        assert!(!stream.orphaned);
    }

    #[test]
    fn mark_orphaned_flags_unlinked_streams() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xDDDD, 1);
        store.process_rtp(&parsed, &rtp, ts(0));

        // Not enough time → not orphaned
        store.mark_orphaned(Duration::from_secs(30));
        // Stream was created at ts(0) = 1_700_000_000 and "now" is current wall-clock.
        // Since ts(0) is in the past and mark_orphaned uses Utc::now(), it will be orphaned.
        // Let's verify the stream count.
        assert_eq!(store.orphaned_count(), 1);
    }

    #[test]
    fn linked_streams_not_orphaned() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xEEEE, 1);
        store.process_rtp(&parsed, &rtp, ts(0));

        store.link_to_dialog(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000, "call-456");

        store.mark_orphaned(Duration::from_secs(0));
        assert_eq!(
            store.orphaned_count(),
            0,
            "linked streams should not be orphaned"
        );
    }

    #[test]
    fn process_rtcp_updates_stream() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xFFFF, 1);
        store.process_rtp(&parsed, &rtp, ts(0));

        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};
        let rtcp_packets = vec![RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0x1111,
            reports: vec![ReceptionReport {
                ssrc: 0xFFFF, // matches our stream
                fraction_lost: 25,
                cumulative_lost: 10,
                highest_seq: 500,
                jitter: 42,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        })];

        store.process_rtcp(&rtcp_packets);

        let key = StreamKey {
            ssrc: 0xFFFF,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(stream.jitter, 42.0);
        assert_eq!(stream.lost_packets, 10);
    }

    /// With audio capture disabled (batch mode: nothing ever reads the
    /// buffer), G.711 payloads must not be cloned into payload_buffer.
    #[test]
    fn no_audio_buffering_when_capture_disabled() {
        let mut store = StreamStore::new(100);
        store.set_audio_capture(false);
        let parsed = make_parsed(20000, 30000, 160);
        // PT=0 (PCMU): codec is known from the static payload type, so
        // this is exactly the packet that would otherwise be buffered.
        store.process_rtp(&parsed, &make_rtp_header(0xA0D1, 1), ts(0));
        store.process_rtp(&parsed, &make_rtp_header(0xA0D1, 2), ts(1));
        let stream = store.iter().next().expect("stream exists");
        assert!(
            stream.payload_buffer.is_empty(),
            "audio payloads must not be buffered when capture is disabled"
        );
        assert_eq!(stream.packet_count, 2, "stats still update normally");
    }

    /// Default (TUI / library use): G.711 payloads ARE buffered so
    /// on-demand WAV export and playback keep working.
    #[test]
    fn audio_buffering_on_by_default_for_g711() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        store.process_rtp(&parsed, &make_rtp_header(0xA0D2, 1), ts(0));
        let stream = store.iter().next().expect("stream exists");
        assert_eq!(
            stream.payload_buffer.len(),
            1,
            "default behaviour must keep buffering for TUI export/playback"
        );
    }

    fn rr_for(ssrc: u32, jitter: u32) -> Vec<RtcpPacket> {
        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};
        vec![RtcpPacket::ReceiverReport(ReceiverReport {
            ssrc: 0x9999,
            reports: vec![ReceptionReport {
                ssrc,
                fraction_lost: 0,
                cumulative_lost: 3,
                highest_seq: 100,
                jitter,
                last_sr: 0,
                delay_since_sr: 0,
            }],
        })]
    }

    /// Two streams can share an SSRC (same source re-keyed by 5-tuple).
    /// An RTCP report updates the FIRST-inserted matching stream only —
    /// pins the insertion-order semantics any SSRC index must preserve.
    #[test]
    fn rtcp_updates_first_inserted_stream_for_shared_ssrc() {
        let mut store = StreamStore::new(100);
        let p1 = make_parsed(20000, 30000, 160);
        let p2 = make_parsed(21000, 30000, 160);
        let rtp = make_rtp_header(0xCAFE, 1);
        store.process_rtp(&p1, &rtp, ts(0));
        store.process_rtp(&p2, &rtp, ts(1));

        store.process_rtcp(&rr_for(0xCAFE, 77));

        let first = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let second = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 21000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(store.get(&first).unwrap().jitter, 77.0);
        assert_eq!(
            store.get(&second).unwrap().jitter,
            0.0,
            "only the first-inserted stream receives the RTCP update"
        );
    }

    /// After the first-inserted stream with a shared SSRC is evicted, an
    /// RTCP report must update the earliest SURVIVING stream — a stale
    /// SSRC index would miss or update a ghost.
    #[test]
    fn rtcp_after_eviction_updates_surviving_stream() {
        let mut store = StreamStore::new(2);
        let p1 = make_parsed(20000, 30000, 160);
        let p2 = make_parsed(21000, 30000, 160);
        let p3 = make_parsed(22000, 30000, 160);
        store.process_rtp(&p1, &make_rtp_header(0xCAFE, 1), ts(0));
        store.process_rtp(&p2, &make_rtp_header(0xCAFE, 1), ts(1));
        // Third stream evicts the first (cap 2).
        store.process_rtp(&p3, &make_rtp_header(0xBEEF, 1), ts(2));
        assert_eq!(store.len(), 2);

        store.process_rtcp(&rr_for(0xCAFE, 55));

        let survivor = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 21000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(
            store.get(&survivor).unwrap().jitter,
            55.0,
            "RTCP must reach the earliest surviving stream after eviction"
        );
    }

    #[test]
    fn rtcp_after_clear_is_noop() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        store.process_rtp(&p, &make_rtp_header(0xCAFE, 1), ts(0));
        store.clear();
        store.process_rtcp(&rr_for(0xCAFE, 11)); // must not panic
        assert!(store.is_empty());
    }

    #[test]
    fn rtcp_unknown_ssrc_is_noop() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        store.process_rtp(&p, &make_rtp_header(0xCAFE, 1), ts(0));
        store.process_rtcp(&rr_for(0xD00D, 99));
        let key = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(store.get(&key).unwrap().jitter, 0.0);
    }

    #[test]
    fn is_empty_and_len() {
        let store = StreamStore::new(100);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn iter_yields_all_streams() {
        let mut store = StreamStore::new(100);
        for i in 0..5u16 {
            let parsed = make_parsed(20000 + i, 30000, 160);
            let rtp = make_rtp_header(i as u32, 1);
            store.process_rtp(&parsed, &rtp, ts(i as i64));
        }

        assert_eq!(store.iter().count(), 5);
    }
}
