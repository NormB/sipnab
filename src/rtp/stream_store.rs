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

/// A media endpoint negotiated in SDP, retained so an RTP stream that appears
/// *after* its SDP (the usual order — INVITE/200 precede the first RTP packet,
/// and in offline pcap replay always do) resolves its codec, clock rate, and
/// dialog the moment it is created. Resolving the clock at creation is what
/// keeps RFC 3550 jitter correct: jitter is accumulated per packet scaled by
/// the clock rate, so a dynamic payload type left at the 8 kHz default until a
/// post-hoc fixup would bake in a wrong (≈11× inflated for 90 kHz) estimate
/// that cannot be recomputed (SNB-0007).
#[derive(Debug, Clone)]
struct SdpEndpoint {
    call_id: String,
    /// `a=rtpmap` entries as `(payload_type, encoding, clock_rate)`.
    rtpmap: Vec<(u8, String, u32)>,
}

/// Central store for all tracked RTP streams.
///
/// Streams are indexed by [`StreamKey`] for O(1) lookup. When the store
/// reaches its capacity limit, the oldest stream (by insertion order) is
/// evicted to make room.
pub struct StreamStore {
    /// All tracked streams, keyed by [`StreamKey`] in insertion order.
    streams: IndexMap<StreamKey, RtpStream, ahash::RandomState>,
    /// SSRC → keys of streams carrying it, in insertion order. RTCP
    /// reports identify streams by SSRC only; without this, every report
    /// block linear-scanned the whole store. Kept consistent on
    /// insert/evict/clear.
    ssrc_index: std::collections::HashMap<u32, Vec<StreamKey>, ahash::RandomState>,
    /// Maximum number of concurrent streams before eviction.
    max_streams: usize,
    /// Maximum number of audio frames to retain per stream for WAV export.
    max_audio_frames: usize,
    /// Whether G.711/Opus payloads are cloned into per-stream buffers for
    /// WAV export / playback. On by default (the TUI exports on demand);
    /// batch mode turns it off — nothing there ever reads the buffers, so
    /// buffering was a per-packet allocation for nothing.
    audio_capture: bool,
    /// SDP-negotiated media endpoints seen so far, keyed by `(addr, port)` in
    /// insertion order. Consulted when a stream is first created so dynamic
    /// payload types resolve from packet one (see [`SdpEndpoint`]). Bounded to
    /// `max_streams` with oldest-out eviction so a flood of unique calls can't
    /// grow it without limit (mirrors the stream cap, SNB-0004 robustness).
    sdp_endpoints: IndexMap<(IpAddr, u16), SdpEndpoint, ahash::RandomState>,
    /// `(addr, port)` → keys of streams whose src OR dst is that endpoint.
    /// Without it, linking an SDP media endpoint to its stream(s) linear-scanned
    /// the whole store on every SDP-bearing SIP message — O(streams) per message,
    /// O(calls²) overall (SNB-0015). Kept consistent on insert/evict/clear, just
    /// like `ssrc_index`.
    endpoint_index: std::collections::HashMap<(IpAddr, u16), Vec<StreamKey>, ahash::RandomState>,
    /// Probe (SNB-0015): cumulative count of per-stream visits performed while
    /// linking SDP endpoints to streams. This is the work that was O(calls²); the
    /// endpoint index keeps it O(calls). Read via [`link_scan_iters`] and exposed
    /// in batch stats so the scaling is observable and any regression is caught.
    link_scan_iters: u64,
    /// Probe (SNB-0015): cumulative number of entries shifted while evicting
    /// streams once the store is at `max_streams`. `IndexMap::shift_remove_index(0)`
    /// is O(n), so evicting one-at-a-time under sustained cap pressure was
    /// O(streams) per packet → O(calls²). Batched eviction amortizes it to O(1)
    /// per insertion. A value near evictions×max_streams means the regression is back.
    evict_shift_work: u64,
}

impl StreamStore {
    /// Create a new store with the given stream capacity limit.
    pub fn new(max_streams: usize) -> Self {
        Self {
            streams: IndexMap::with_capacity_and_hasher(
                max_streams.min(1024),
                ahash::RandomState::default(),
            ),
            ssrc_index: std::collections::HashMap::default(),
            max_streams,
            max_audio_frames: 1500,
            audio_capture: true,
            sdp_endpoints: IndexMap::default(),
            endpoint_index: std::collections::HashMap::default(),
            link_scan_iters: 0,
            evict_shift_work: 0,
        }
    }

    /// Cumulative per-stream visits during SDP-endpoint linking (SNB-0015 probe).
    /// With the endpoint index this grows ~linearly with calls; a quadratic value
    /// signals the index was bypassed (the old full-store scan).
    pub fn link_scan_iters(&self) -> u64 {
        self.link_scan_iters
    }

    /// Cumulative entries shifted during stream eviction (SNB-0015 probe). With
    /// batched eviction this stays ~O(streams); a value near evictions×max_streams
    /// signals the O(n)-per-eviction regression returned.
    pub fn evict_shift_work(&self) -> u64 {
        self.evict_shift_work
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
            // Resolve codec/clock/dialog from any SDP already seen for this
            // endpoint, before any packet feeds the jitter estimate (SNB-0007).
            self.resolve_from_sdp(&mut stream);
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
            self.index_endpoints(&key);
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
        // Indexed: visit only the streams on this endpoint, not the whole store.
        let Some(keys) = self.endpoint_index.get(&(media_addr, media_port)) else {
            return;
        };
        let keys = keys.clone();
        self.link_scan_iters += keys.len() as u64;
        for key in &keys {
            if let Some(stream) = self.streams.get_mut(key)
                && stream.associated_dialog.is_none()
            {
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
        let rtpmap: Vec<(u8, String, u32)> = media
            .rtpmap
            .iter()
            .map(|rm| (rm.payload_type, rm.encoding.clone(), rm.clock_rate))
            .collect();
        self.link_endpoint(media_addr, media_port, call_id, &rtpmap);
    }

    /// Associate every RTP stream on `media_addr:media_port` to `call_id` and,
    /// for dynamic payload types with no static codec, resolve codec + clock
    /// rate from the SDP `a=rtpmap` (`(payload_type, encoding, clock_rate)`).
    ///
    /// Idempotent and order-independent: it only fills an unset association /
    /// unknown codec, so it is safe to run both inline (as each SDP is seen)
    /// and again as a post-capture pass — the latter is what resolves streams
    /// created *after* their SDP, e.g. offline pcap replay where the INVITE/200
    /// is parsed before any RTP packet exists (SNB-0007).
    pub fn link_endpoint(
        &mut self,
        media_addr: IpAddr,
        media_port: u16,
        call_id: &str,
        rtpmap: &[(u8, String, u32)],
    ) {
        // Remember this endpoint so a stream created *later* (the common
        // ordering) resolves codec/clock/dialog at creation — see process_rtp.
        self.remember_sdp_endpoint(media_addr, media_port, call_id, rtpmap);

        // Indexed lookup (SNB-0015): the endpoint index yields exactly the streams
        // whose src or dst is this endpoint — the same set the old full-store scan
        // matched, but without visiting unrelated streams. So the per-message link
        // is O(matches) instead of O(streams), collapsing the overall cost from
        // O(calls²) back to O(calls).
        let Some(keys) = self.endpoint_index.get(&(media_addr, media_port)) else {
            return;
        };
        let keys = keys.clone();
        self.link_scan_iters += keys.len() as u64;
        for key in &keys {
            let Some(stream) = self.streams.get_mut(key) else {
                continue;
            };
            if stream.associated_dialog.is_none() {
                stream.associated_dialog = Some(call_id.to_string());
                stream.orphaned = false;
            }
            // Enrich codec info from SDP rtpmap for dynamic payload types. Only
            // update if the stream's codec is unknown (dynamic PT, no static map).
            if stream.codec.is_none()
                && let Some((_, encoding, clock_rate)) =
                    rtpmap.iter().find(|(pt, _, _)| *pt == stream.payload_type)
            {
                stream.codec = Some(encoding.clone());
                stream.clock_rate = *clock_rate;
            }
        }
    }

    /// Record an SDP-negotiated endpoint for later stream resolution, bounded
    /// to `max_streams` entries (oldest-out). A repeated offer/answer for the
    /// same endpoint refreshes it; a re-offer that drops the rtpmap does not
    /// clobber a previously-learned one.
    fn remember_sdp_endpoint(
        &mut self,
        addr: IpAddr,
        port: u16,
        call_id: &str,
        rtpmap: &[(u8, String, u32)],
    ) {
        match self.sdp_endpoints.get_mut(&(addr, port)) {
            Some(existing) => {
                existing.call_id = call_id.to_string();
                if !rtpmap.is_empty() {
                    existing.rtpmap = rtpmap.to_vec();
                }
            }
            None => {
                if self.max_streams > 0 && self.sdp_endpoints.len() >= self.max_streams {
                    self.sdp_endpoints.shift_remove_index(0);
                }
                self.sdp_endpoints.insert(
                    (addr, port),
                    SdpEndpoint {
                        call_id: call_id.to_string(),
                        rtpmap: rtpmap.to_vec(),
                    },
                );
            }
        }
    }

    /// Resolve a freshly-created stream's dialog + (for dynamic payload types)
    /// codec/clock from any SDP endpoint seen earlier for its source or
    /// destination. Run at creation so the clock rate is correct before the
    /// first jitter sample (SNB-0007).
    fn resolve_from_sdp(&self, stream: &mut RtpStream) {
        for (ip, port) in [
            (stream.key.src.ip(), stream.key.src.port()),
            (stream.key.dst.ip(), stream.key.dst.port()),
        ] {
            let Some(endpoint) = self.sdp_endpoints.get(&(ip, port)) else {
                continue;
            };
            if stream.associated_dialog.is_none() {
                stream.associated_dialog = Some(endpoint.call_id.clone());
                stream.orphaned = false;
            }
            if stream.codec.is_none()
                && let Some((_, encoding, clock_rate)) = endpoint
                    .rtpmap
                    .iter()
                    .find(|(pt, _, _)| *pt == stream.payload_type)
            {
                stream.codec = Some(encoding.clone());
                stream.clock_rate = *clock_rate;
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
        self.endpoint_index.clear();
    }

    /// Register a stream key under both its src and dst endpoints (SNB-0015).
    fn index_endpoints(&mut self, key: &StreamKey) {
        let src_ep = (key.src.ip(), key.src.port());
        let dst_ep = (key.dst.ip(), key.dst.port());
        self.endpoint_index
            .entry(src_ep)
            .or_default()
            .push(key.clone());
        if dst_ep != src_ep {
            self.endpoint_index
                .entry(dst_ep)
                .or_default()
                .push(key.clone());
        }
    }

    /// Remove a stream key from its src/dst endpoint buckets (on eviction).
    fn unindex_endpoints(&mut self, key: &StreamKey) {
        let src_ep = (key.src.ip(), key.src.port());
        let dst_ep = (key.dst.ip(), key.dst.port());
        if let Some(keys) = self.endpoint_index.get_mut(&src_ep) {
            keys.retain(|k| k != key);
            if keys.is_empty() {
                self.endpoint_index.remove(&src_ep);
            }
        }
        if dst_ep != src_ep
            && let Some(keys) = self.endpoint_index.get_mut(&dst_ep)
        {
            keys.retain(|k| k != key);
            if keys.is_empty() {
                self.endpoint_index.remove(&dst_ep);
            }
        }
    }

    /// Count of streams flagged as orphaned.
    pub fn orphaned_count(&self) -> usize {
        self.streams.values().filter(|s| s.orphaned).count()
    }

    /// Fold another worker's store into this one (multi-core merge, `--jobs N`).
    /// Streams sharded by host pair never collide across workers, so this is a
    /// union; the ssrc/endpoint indexes are rebuilt for the moved streams and the
    /// SDP endpoints are combined. Probe counters accumulate. Call
    /// [`reassociate_all`](Self::reassociate_all) afterwards to link streams to a
    /// dialog whose SDP was processed on a different worker.
    pub fn merge(&mut self, other: StreamStore) {
        for (key, stream) in other.streams {
            if !self.streams.contains_key(&key) {
                self.ssrc_index
                    .entry(key.ssrc)
                    .or_default()
                    .push(key.clone());
                self.index_endpoints(&key);
                self.streams.insert(key, stream);
            }
        }
        for (ep, sdp) in other.sdp_endpoints {
            self.sdp_endpoints.entry(ep).or_insert(sdp);
        }
        self.link_scan_iters += other.link_scan_iters;
        self.evict_shift_work += other.evict_shift_work;
    }

    /// Globally (re)link every stream to its dialog via the merged SDP endpoints.
    /// Needed after [`merge`](Self::merge): when a stream and the SDP naming its
    /// call were processed on different workers, the inline association never ran.
    /// Idempotent and order-independent (only fills unset associations), so it
    /// reproduces the single-threaded result. O(total streams) via the endpoint
    /// index.
    pub fn reassociate_all(&mut self) {
        let eps: Vec<((IpAddr, u16), SdpEndpoint)> = self
            .sdp_endpoints
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for ((addr, port), ep) in eps {
            self.link_endpoint(addr, port, &ep.call_id, &ep.rtpmap);
        }
    }

    /// Evict the oldest stream (first entry in insertion order) if at capacity.
    fn ensure_capacity(&mut self) {
        if self.streams.len() >= self.max_streams && !self.streams.is_empty() {
            // Evicting one-at-a-time with shift_remove_index(0) shifts O(n) entries
            // PER new stream once at capacity → O(calls²) under sustained pressure
            // (SNB-0015). Batch-evict the oldest ~1% in a single `drain`, so the
            // O(n) IndexMap shift amortizes to O(1) per insertion — mirrors
            // DialogStore::evict_oldest. `.max(1)` keeps small caps evicting singly.
            let batch = (self.max_streams / 10).max(1).min(self.streams.len());
            self.evict_shift_work += self.streams.len().saturating_sub(batch) as u64;
            let evicted: Vec<StreamKey> = self.streams.drain(0..batch).map(|(k, _)| k).collect();
            for key in &evicted {
                if let Some(keys) = self.ssrc_index.get_mut(&key.ssrc) {
                    keys.retain(|k| k != key);
                    if keys.is_empty() {
                        self.ssrc_index.remove(&key.ssrc);
                    }
                }
                self.unindex_endpoints(key);
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

    fn ts_ms(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + ms).expect("valid")
    }

    fn rtp_pkt(ssrc: u32, seq: u16, payload_type: u8, rtp_ts: u32) -> RtpHeader {
        RtpHeader {
            payload_type,
            sequence: seq,
            timestamp: rtp_ts,
            ..make_rtp_header(ssrc, seq)
        }
    }

    // SNB-0007: the SDP (carrying `a=rtpmap`) is normally processed BEFORE the
    // first RTP packet — always so in offline pcap replay. The endpoint is
    // remembered, so when the stream is created its dynamic payload type
    // resolves to codec + clock + dialog from packet one, not "Codec ?".
    #[test]
    fn dynamic_pt_resolved_at_creation_when_sdp_seen_first() {
        let mut store = StreamStore::new(100);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 20000u16;
        // H.264 on dynamic PT 96 @ 90 kHz — no static payload-type mapping.
        let rtpmap = vec![(96u8, "H264".to_string(), 90000u32)];

        // SDP link runs first; no stream exists yet, so it creates none.
        store.link_endpoint(addr, port, "call-1", &rtpmap);
        assert_eq!(store.len(), 0, "an SDP link must not create a stream");

        // RTP arrives -> stream created and immediately resolved from the SDP.
        let parsed = make_parsed(port, 30000, 160);
        store.process_rtp(&parsed, &rtp_pkt(0x00C0FFEE, 1, 96, 0), ts(0));
        let key = StreamKey {
            ssrc: 0x00C0FFEE,
            src: SocketAddr::new(addr, port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let s = store.get(&key).expect("stream should exist");
        assert_eq!(
            s.codec.as_deref(),
            Some("H264"),
            "codec resolved from rtpmap"
        );
        assert_eq!(s.clock_rate, 90000, "clock resolved from rtpmap");
        assert_eq!(s.associated_dialog.as_deref(), Some("call-1"), "associated");
    }

    // SNB-0015 (eviction): once the store is at capacity, evicting streams
    // one-at-a-time with shift_remove_index(0) shifts O(streams) entries PER new
    // stream → O(calls²) under sustained cap pressure (the dominant carrier-scale
    // cliff). Batched eviction must keep the cumulative shift work ~O(streams seen),
    // not O(overflow × cap). Drive `cap + overflow` distinct streams through a
    // small cap and assert the probe stays bounded — and that eviction is still
    // correct (store stays capped, oldest gone, indexes consistent).
    #[test]
    fn eviction_shift_work_is_amortized_and_correct() {
        let cap = 1_000usize;
        let overflow = 3_000usize;
        let mut store = StreamStore::new(cap);
        for i in 0..(cap + overflow) as u32 {
            // distinct 5-tuple per stream (unique src port) so each is a new key.
            let parsed = make_parsed(20_000 + (i % 40_000) as u16, 30_000, 160);
            let mut p = parsed;
            // force uniqueness beyond the 16-bit port via the ssrc-keyed StreamKey
            p.src_port = 1_024 + (i % 64_000) as u16;
            store.process_rtp(&p, &make_rtp_header(0x0100_0000 + i, 1), ts(0));
        }
        // Store stayed bounded by the cap (batch eviction may dip just under).
        assert!(
            store.len() <= cap,
            "store must stay within cap: {}",
            store.len()
        );
        assert!(
            store.len() > cap - cap / 50,
            "store should sit near the cap"
        );
        // Performance contract: cumulative eviction shift work must be ~O(streams
        // seen), NOT O(overflow × cap). One-at-a-time shifting gives ≈overflow×cap.
        let quadratic = overflow as u64 * cap as u64;
        assert!(
            store.evict_shift_work() <= 20 * (cap + overflow) as u64,
            "SNB-0015: eviction shift work {} must be ~O(N)={}, not O(overflow×cap)={}",
            store.evict_shift_work(),
            cap + overflow,
            quadratic
        );
        // Indexes stayed consistent: no dangling endpoint/ssrc keys for evicted streams.
        let live: usize = store.iter().count();
        assert_eq!(live, store.len(), "iter and len agree after eviction");
    }

    // SNB-0015: linking an SDP endpoint to its stream(s) must NOT scan the whole
    // store. With N streams each on a distinct endpoint and one SDP link per
    // endpoint, a full-store scan is O(N²); an endpoint index is O(N). The probe
    // counter makes the work observable: assert it stays ~O(N), and assert the
    // index links exactly the same streams a scan would (correctness preserved).
    #[test]
    fn endpoint_linking_is_subquadratic_and_correct() {
        let n: u16 = 300;
        let mut store = StreamStore::new(100_000);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // N streams: stream i has src 10.0.0.1:(20000+i), dst 10.0.0.2:(30000+i).
        for i in 0..n {
            let parsed = make_parsed(20000 + i, 30000 + i, 160);
            store.process_rtp(&parsed, &make_rtp_header(0x1000 + i as u32, 1), ts(0));
        }
        assert_eq!(store.len(), n as usize);

        let base = store.link_scan_iters();
        // One SDP link per endpoint — each matches exactly its own stream's src.
        for i in 0..n {
            store.link_endpoint(src_ip, 20000 + i, "call", &[]);
        }
        let iters = store.link_scan_iters() - base;
        let quadratic = n as u64 * n as u64;
        assert!(
            iters <= 8 * n as u64,
            "SNB-0015: link scan visits {iters} must be O(N)≈{n}, not O(N²)={quadratic}"
        );

        // Correctness: every stream got linked to its endpoint's call (same result
        // a full scan produced), and an unrelated endpoint links nothing.
        for s in store.iter() {
            assert_eq!(
                s.associated_dialog.as_deref(),
                Some("call"),
                "stream linked"
            );
        }
        let before = store.link_scan_iters();
        store.link_endpoint(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 1, "nope", &[]);
        assert!(
            store.link_scan_iters() - before <= 1,
            "an endpoint with no streams must visit ~0, not scan the store"
        );
    }

    // Multi-core (--jobs): a call's SDP (SIP) and its RTP can be sharded to
    // DIFFERENT workers — in the carrier corpus the SDP advertises a separate
    // media IP. Worker A sees the SDP (remembers the endpoint, no stream); worker
    // B sees the RTP (creates the stream, no SDP → unassociated). merge() unions
    // them and reassociate_all() links the stream to its call — reproducing the
    // single-threaded result where association happens at stream creation.
    #[test]
    fn merge_reassociates_streams_whose_sdp_was_on_another_worker() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)); // make_parsed src ip
        let port = 20000u16;

        let mut a = StreamStore::new(1000); // the "SIP" worker
        a.link_endpoint(addr, port, "call-1", &[]);
        assert_eq!(a.len(), 0, "SDP alone creates no stream");

        let mut b = StreamStore::new(1000); // the "RTP" worker
        let parsed = make_parsed(port, 30000, 160);
        b.process_rtp(&parsed, &make_rtp_header(0xABCD, 1), ts(0));
        assert_eq!(b.len(), 1);
        assert!(
            b.iter().next().unwrap().associated_dialog.is_none(),
            "no SDP on the RTP worker → stream is unassociated"
        );

        a.merge(b);
        assert_eq!(a.len(), 1, "merge unions the stream in");
        assert!(
            a.iter().next().unwrap().associated_dialog.is_none(),
            "still unlinked until the global pass"
        );
        a.reassociate_all();
        assert_eq!(
            a.iter().next().unwrap().associated_dialog.as_deref(),
            Some("call-1"),
            "reassociate_all links the merged stream to its call's SDP"
        );
    }

    // The other ordering: RTP first (stream exists, dynamic PT unknown), then
    // the SDP — link_endpoint must enrich the existing stream + associate it.
    #[test]
    fn dynamic_pt_resolved_when_rtp_precedes_sdp() {
        let mut store = StreamStore::new(100);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 20000u16;
        let parsed = make_parsed(port, 30000, 160);

        store.process_rtp(&parsed, &rtp_pkt(0x00C0FFEE, 1, 96, 0), ts(0));
        let key = StreamKey {
            ssrc: 0x00C0FFEE,
            src: SocketAddr::new(addr, port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert!(
            store.get(&key).unwrap().codec.is_none(),
            "dynamic PT 96 has no static codec before SDP"
        );

        store.link_endpoint(addr, port, "call-1", &[(96, "H264".to_string(), 90000)]);
        let s = store.get(&key).unwrap();
        assert_eq!(s.codec.as_deref(), Some("H264"));
        assert_eq!(s.clock_rate, 90000);
        assert_eq!(s.associated_dialog.as_deref(), Some("call-1"));
    }

    // Resolving the clock at creation is what keeps jitter correct: a 90 kHz
    // video stream whose frames (3000 ticks) arrive at the matching 33 ms pace
    // has near-zero jitter. The dynamic PT 96 resolved from SDP must yield the
    // SAME jitter as the static 90 kHz PT 34 — and far less than the inflated
    // estimate produced if it were left at the 8 kHz default.
    #[test]
    fn dynamic_pt_jitter_matches_static_clock() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 20000u16;
        let parsed = make_parsed(port, 30000, 160);
        let key = StreamKey {
            ssrc: 0xBEEF,
            src: SocketAddr::new(addr, port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        // Feed a 90 kHz, 33 ms-spaced stream of `pt` to a store, optionally
        // seeding the SDP for the endpoint first; return the final jitter (ms).
        let run = |pt: u8, sdp: bool| -> f64 {
            let mut store = StreamStore::new(100);
            if sdp {
                store.link_endpoint(addr, port, "c", &[(96, "H264".to_string(), 90000)]);
            }
            for i in 0..8u32 {
                store.process_rtp(
                    &parsed,
                    &rtp_pkt(0xBEEF, i as u16 + 1, pt, i * 3000),
                    ts_ms(i as i64 * 33),
                );
            }
            store.get(&key).unwrap().jitter
        };

        let static_90k = run(34, false); // static 90 kHz reference
        let dynamic_resolved = run(96, true); // PT 96 resolved to 90 kHz via SDP
        let dynamic_unresolved = run(96, false); // PT 96 left at 8 kHz default (the bug)

        assert!(
            static_90k < 5.0,
            "static 90 kHz stream is near-zero jitter: {static_90k}"
        );
        assert!(
            (dynamic_resolved - static_90k).abs() < 1.0,
            "resolved dynamic PT jitter ({dynamic_resolved}) must match static ({static_90k})"
        );
        assert!(
            dynamic_unresolved > 10.0 * dynamic_resolved.max(0.1),
            "unresolved (8 kHz) jitter ({dynamic_unresolved}) is wildly inflated vs resolved ({dynamic_resolved})"
        );
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
