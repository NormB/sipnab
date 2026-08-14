// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP stream storage and lifecycle management.
//!
//! `StreamStore` maintains an indexed collection of `RtpStream`s,
//! creating or updating streams as RTP/RTCP packets arrive. It handles
//! dialog linking (from SDP), orphan detection, and capacity eviction.

use std::net::{IpAddr, SocketAddr};

use indexmap::IndexMap;

use chrono::{DateTime, Utc};

use super::parser::RtpHeader;
use super::rtcp::{ExtendedReport, ReceptionReport, RtcpPacket, RttSource, VoipMetrics, XrBlock};
use super::stream::{RtpStream, StreamKey};
use crate::capture::ParsedPacket;
use crate::sip::sdp::SdpMedia;

/// How an ICMP error's quoted datagram was tied to tracked media.
///
/// Ordered by how much the tie proves, strongest first. The variant is carried
/// into every surface rather than collapsed to a boolean because the tiers are
/// not equally strong: [`Flow`](Self::Flow) means sipnab watched that exact
/// datagram's stream, while [`SdpEndpoint`](Self::SdpEndpoint) means only that
/// a call negotiated that address. A reader deciding whether to act on a
/// finding needs to know which of those they have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaMatch {
    /// The quoted datagram's directed 5-tuple is exactly a tracked stream.
    Flow,
    /// The SSRC in the quoted payload names a tracked stream. The tie that
    /// carries RTCP, which runs on a port no stream is keyed on.
    Ssrc,
    /// One of the two sockets is an endpoint of a tracked stream.
    Endpoint,
    /// One of the two sockets was advertised in SDP, or is the RTCP companion
    /// port of one. Works when no media was captured at all.
    SdpEndpoint,
    /// Nothing matched. The evidence is still real — only the stream is
    /// unknown — so callers count it rather than dropping it.
    #[default]
    None,
}

/// What a media ICMP quote was tied to, and by which rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaAttribution {
    /// The strongest tier that matched.
    pub matched: MediaMatch,
    /// How many tracked streams the tier matched. Zero for an SDP-only match,
    /// which by definition has no stream behind it.
    pub streams: usize,
    /// `Call-ID`s of the dialogs the matched media belongs to, deduplicated.
    /// Empty when the streams matched were never linked to a dialog.
    pub call_ids: Vec<String>,
}

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
    /// Call-ID of the SIP dialog whose SDP negotiated this endpoint.
    call_id: String,
    /// `a=rtpmap` entries as `(payload_type, encoding, clock_rate)`.
    rtpmap: Vec<(u8, String, u32)>,
    /// `a=ptime` in milliseconds, when the media description declared one.
    ///
    /// Kept beside the rtpmap because it answers the same kind of question —
    /// what the endpoints agreed the media would look like — and reaches the
    /// stream by the same two routes (an endpoint learned before its RTP, and
    /// one learned after). `RtpStream::ptime_ms` prefers a measurement, and
    /// falls back to this on the streams too short to measure.
    ptime: Option<u32>,
}

/// How a stream's RTP clock rate — the divisor every jitter figure depends on
/// — came to be known.
///
/// Jitter is an RTP-timestamp difference converted to milliseconds by the
/// clock rate, so a wrong clock rate does not make the answer imprecise, it
/// makes it meaningless: at 8 kHz assumed for a 90 kHz stream every sample is
/// 11.25x too large. The three cases are worth distinguishing because only the
/// first two are measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockGrounding {
    /// A static payload type with a clock rate fixed by RFC 3551 Tables 4/5.
    Rfc3551,
    /// A dynamic payload type resolved from an SDP `a=rtpmap`.
    Rtpmap,
    /// Neither: a payload type outside RFC 3551 with no `a=rtpmap` for it.
    /// The clock rate is a placeholder and any jitter derived from it is not a
    /// measurement — see [`StreamStore::measured_jitter_ms`].
    Assumed,
}

/// A reception report a **remote** endpoint asserted about a stream.
///
/// Kept beside sipnab's own measurement rather than replacing it, for two
/// reasons that are easy to lose sight of once the numbers are in the same
/// field:
///
/// - **Provenance.** RTCP is unauthenticated and trivially spoofable. A number
///   that arrived in a datagram and a number sipnab computed from the media it
///   observed cannot be shown to an operator as the same kind of fact.
/// - **Vantage.** The report describes the path from the source to *the
///   reporter*. On a mid-path capture that is a different segment than the one
///   sipnab is watching, so the two disagreeing is normal and informative —
///   overwriting one with the other destroys exactly that signal.
///
/// Nothing here feeds MOS. MOS is scored from sipnab's own jitter and loss, so
/// a forged RTCP report cannot move it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct RemoteReceptionReport {
    /// SSRC of the endpoint that sent the report (the receiver, not the
    /// source being reported on).
    pub reporter_ssrc: u32,
    /// Loss fraction over the reporting interval, times 256 (RFC 3550
    /// §6.4.1). See [`Self::fraction_lost_pct`].
    pub fraction_lost: u8,
    /// Packets lost since the reporter began receiving — a cumulative count
    /// over the reporter's whole session, not a rate and not scoped to the
    /// capture window. See
    /// [`ReceptionReport::cumulative_lost`](crate::rtp::rtcp::ReceptionReport::cumulative_lost).
    pub cumulative_lost: i32,
    /// Extended highest sequence number the reporter received.
    pub highest_seq: u32,
    /// Interarrival jitter as it appears on the wire: RTP timestamp units.
    pub jitter_timestamp_units: u32,
    /// The same jitter in milliseconds, or `None` when the stream's clock rate
    /// is [`ClockGrounding::Assumed`] — the conversion needs a clock rate, and
    /// a guessed one produces a number that only looks like milliseconds.
    pub jitter_ms: Option<f64>,
    /// Round trip derived from this block's SR echo
    /// ([`rtt_from_sender_report_echo`](crate::rtp::rtcp::rtt_from_sender_report_echo)),
    /// or `None` when none can be — the reporter had seen no SR, or the two
    /// clocks disagree by more than the quantity being measured.
    ///
    /// `None` is not zero and must not become zero on the way to an operator:
    /// latency is the third of the three numbers that decide whether a call was
    /// acceptable, and a call with clean jitter and no loss can still be
    /// unusable on delay alone. Reporting "no measurement" as 0 ms turns the
    /// one unanswered question into a passing grade.
    pub round_trip_ms: Option<f64>,
    /// How many report blocks about this stream have been folded in. The other
    /// fields hold the most recent; this says whether that is one sample or a
    /// long-running exchange.
    pub reports_seen: u64,
}

impl RemoteReceptionReport {
    /// [`Self::fraction_lost`] as a percentage over the reporting interval.
    ///
    /// This, not `cumulative_lost`, is the report's rate quantity — though it
    /// is still the *reporter's* rate on the *reporter's* path segment.
    #[must_use]
    pub fn fraction_lost_pct(&self) -> f64 {
        f64::from(self.fraction_lost) * 100.0 / 256.0
    }
}

/// What an endpoint asserted about a stream in an RTCP XR VoIP Metrics block
/// (RFC 3611 Section 4.7) — never sipnab's own measurement.
///
/// This is the far end telling you what *it* experienced: its own R factor,
/// its own MOS-LQ and MOS-CQ, its burst and gap loss densities, its round-trip
/// and end-system delay, its jitter buffer sizing. Some of that sipnab cannot
/// measure from a capture at any vantage point — discard rate counts packets
/// that arrived and were then thrown away by the jitter buffer, and end-system
/// delay is entirely inside the endpoint.
///
/// Kept beside sipnab's own figures for the same two reasons
/// [`RemoteReceptionReport`] is:
///
/// - **Provenance.** RTCP is unauthenticated. An endpoint-asserted MOS of 4.4
///   and a sipnab-estimated MOS of 2.1 are different kinds of fact, and an
///   operator has to be able to tell which they are reading.
/// - **Vantage.** These metrics describe the path as far as *the reporter*. On
///   a mid-path capture that is a different segment, so the two disagreeing is
///   the finding, not a problem to resolve by overwrite.
///
/// Nothing here feeds [`estimate_mos`](crate::rtp::quality::estimate_mos), the
/// stream's `jitter`, its `lost_packets`, or any quality interval. A forged XR
/// cannot move a single number sipnab computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RemoteVoipMetrics {
    /// SSRC of the endpoint that sent the XR — the reporter, not the source
    /// being reported on.
    pub reporter_ssrc: u32,
    /// The block exactly as it arrived. Read it through the accessors on
    /// [`VoipMetrics`], which apply RFC 3611's "unavailable" sentinels and the
    /// two's-complement signal and noise levels.
    pub metrics: VoipMetrics,
    /// How many VoIP Metrics blocks about this stream have been folded in.
    /// [`Self::metrics`] holds the most recent; this says whether that is a
    /// single sample or a long-running report.
    pub reports_seen: u64,
}

/// Per-stream facts that are about the *provenance* of a stream's numbers
/// rather than about the media, kept in the store so `RtpStream` stays a
/// record of what was observed.
#[derive(Debug, Clone, Default)]
struct StreamProvenance {
    /// The most recent RTCP reception report about this stream, if any.
    remote: Option<RemoteReceptionReport>,
    /// The most recent RTCP XR VoIP Metrics block about this stream, if any.
    voip_metrics: Option<RemoteVoipMetrics>,
    /// `packet_count` at which the jitter estimator was restarted because the
    /// clock rate was corrected after packets had already been folded in at
    /// the wrong one. `None` means it was never restarted.
    jitter_restart_at: Option<u64>,
}

/// Packets the RFC 3550 jitter estimator needs to forget a restart.
///
/// `J += (|D| - J) / 16` has a 16-sample time constant, so after a restart the
/// estimate is dominated by the seed (zero) until roughly that many samples
/// have been folded in. Reporting it before then would publish "no jitter" for
/// a stream that has simply not been measured yet.
const JITTER_CONVERGENCE_PACKETS: u64 = 16;

/// RTP clock rate in Hz for a static payload type, per RFC 3551 Tables 4 and 5.
///
/// `None` for every payload type RFC 3551 leaves unassigned or reserved,
/// including the dynamic range 96-127 — those are knowable only from an SDP
/// `a=rtpmap`, and there is no defensible default. Mirrors
/// [`crate::sip::sdp::static_payload_name`], which answers the same question
/// for the codec name.
///
/// Note this is a superset of [`crate::rtp::stream::clock_rate_from_pt`], which
/// knows eight of the twenty-four assigned types and answers 8000 Hz for the
/// rest by way of its caller's `unwrap_or`. Every video type in Table 5 is
/// 90 kHz, so that default was wrong by a factor of 11.25 for JPEG, H.261,
/// MPV and MP2T, and by 11.25 / 5.5 / 2.75 / 1.4 for MPA, L16, DVI4/22050 and
/// DVI4/11025.
fn rfc3551_clock_rate(payload_type: u8) -> Option<u32> {
    Some(match payload_type {
        // Table 4 — audio.
        0 => 8000,        // PCMU
        3 => 8000,        // GSM
        4 => 8000,        // G723
        5 => 8000,        // DVI4
        6 => 16000,       // DVI4
        7 => 8000,        // LPC
        8 => 8000,        // PCMA
        9 => 8000,        // G722 (8 kHz RTP clock despite 16 kHz audio)
        10 | 11 => 44100, // L16 stereo / mono
        12 => 8000,       // QCELP
        13 => 8000,       // CN
        14 => 90000,      // MPA
        15 => 8000,       // G728
        16 => 11025,      // DVI4
        17 => 22050,      // DVI4
        18 => 8000,       // G729
        // Table 5 — video and one audio/video multiplex, all 90 kHz.
        25 | 26 | 28 | 31 | 32 | 33 | 34 => 90000,
        // 1-2 reserved, 19-24/27/29-30/35-95 unassigned, 96-127 dynamic.
        _ => return None,
    })
}

/// Central store for all tracked RTP streams.
///
/// Streams are indexed by `StreamKey` for O(1) lookup. When the store
/// reaches its capacity limit, the oldest stream (by insertion order) is
/// evicted to make room.
///
/// # Examples
///
/// ```
/// use sipnab::StreamStore;
/// use sipnab::rtp::parser::parse_rtp_header;
///
/// let mut store = StreamStore::new(4096);
/// assert!(store.is_empty());
///
/// // Streams are created by feeding parsed RTP packets to
/// // `process_rtp` and linked to SIP dialogs via the SDP linkers;
/// // `streams_for` then yields exactly one call's media:
/// assert_eq!(store.streams_for("no-such-call@example.com").count(), 0);
/// ```
#[derive(Debug)]
pub struct StreamStore {
    /// All tracked streams, keyed by `StreamKey` in insertion order.
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
    /// payload types resolve from packet one (see `SdpEndpoint`). Bounded to
    /// `max_streams` with oldest-out eviction so a flood of unique calls can't
    /// grow it without limit (mirrors the stream cap, SNB-0004 robustness).
    sdp_endpoints: IndexMap<(IpAddr, u16), SdpEndpoint, ahash::RandomState>,
    /// `(addr, port)` → keys of streams whose src OR dst is that endpoint.
    /// Without it, linking an SDP media endpoint to its stream(s) linear-scanned
    /// the whole store on every SDP-bearing SIP message — O(streams) per message,
    /// O(calls²) overall (SNB-0015). Kept consistent on insert/evict/clear, just
    /// like `ssrc_index`.
    endpoint_index: std::collections::HashMap<(IpAddr, u16), Vec<StreamKey>, ahash::RandomState>,
    /// Provenance side-table: what the far end asserted about a stream, and
    /// whether its jitter estimator was restarted. Separate from `streams` so
    /// a remote assertion can never be mistaken for a local measurement by a
    /// caller reading `RtpStream`. Kept consistent on evict/clear/merge, like
    /// the other indexes.
    provenance: std::collections::HashMap<StreamKey, StreamProvenance, ahash::RandomState>,
    /// Probe (SNB-0015): cumulative count of per-stream visits performed while
    /// linking SDP endpoints to streams. This is the work that was O(calls²); the
    /// endpoint index keeps it O(calls). Read via `link_scan_iters` and exposed
    /// in batch stats so the scaling is observable and any regression is caught.
    link_scan_iters: u64,
    /// Probe (SNB-0015): cumulative number of entries shifted while evicting
    /// streams once the store is at `max_streams`. `IndexMap::shift_remove_index(0)`
    /// is O(n), so evicting one-at-a-time under sustained cap pressure was
    /// O(streams) per packet → O(calls²). Batched eviction amortizes it to O(1)
    /// per insertion. A value near evictions×max_streams means the regression is back.
    evict_shift_work: u64,
    /// Structural-change counter for cache invalidation — see
    /// `Self::generation`.
    generation: u64,
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
            provenance: std::collections::HashMap::default(),
            link_scan_iters: 0,
            evict_shift_work: 0,
            generation: 0,
        }
    }

    /// Monotonic structural-change counter: bumped when the stream SET, a
    /// stream's dialog association or its resolved codec changes (new
    /// stream, link, merge, clear) — NOT by per-packet counter/last-seen
    /// updates. The TUI keys its cached per-dialog codec segments (and the
    /// ladder layout derived from them) on this, so live RTP on an
    /// established call keeps hitting the cache while anything that could
    /// change what `streams_for` yields invalidates it.
    pub fn generation(&self) -> u64 {
        self.generation
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

    /// Whether this store is buffering audio payloads.
    ///
    /// Exposed so a caller's retention decision can be asserted against the
    /// store it configured, without routing RTP through it first. The setter
    /// alone left the resulting state unobservable, so a caller that computed
    /// the right answer and failed to apply it read exactly like one that
    /// applied it — which is how `app::batch` shipped a run that retained
    /// audio nothing in it could read.
    pub fn audio_capture(&self) -> bool {
        self.audio_capture
    }

    /// Set the maximum number of audio frames retained per stream for WAV export.
    pub fn set_max_audio_frames(&mut self, max: usize) {
        self.max_audio_frames = max;
    }

    /// Process an RTP packet: create a new stream or update an existing one.
    ///
    /// Uses the packet's 5-tuple (src/dst addresses and ports) combined with
    /// the RTP SSRC to form the stream key.
    ///
    /// # Arguments
    ///
    /// * `parsed` — the captured packet (addresses, ports, raw payload).
    /// * `rtp` — the already-parsed RTP header for that payload.
    /// * `timestamp` — wall-clock arrival time fed to the stream trackers.
    ///
    /// # Side effects
    ///
    /// * Existing stream: delegates to `RtpStream::update` (jitter, loss,
    ///   interval accounting) and, when audio capture is on and the codec
    ///   is capturable, appends the payload to the stream's ring buffer
    ///   (oldest-out at `max_audio_frames`). No generation bump.
    /// * New stream: may batch-evict the oldest streams via
    ///   `ensure_capacity`, resolves codec/clock/dialog from any
    ///   previously seen SDP endpoint, registers the key in the SSRC and
    ///   endpoint indexes, inserts the stream, and bumps the generation.
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
            // Latest marking, so a mid-stream re-marking becomes visible
            // against `dscp_first`. Guarded on `is_some` rather than assigned
            // unconditionally: a stream that mixes observed frames with
            // HEP-fed ones must not have its last known marking erased by a
            // packet that carried none.
            if parsed.dscp.is_some() {
                stream.dscp_last = parsed.dscp;
            }
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
            // Where this stream began, recorded once and never again (#128).
            // This branch runs only for a key the store has not seen, so it is
            // by construction the first packet of the stream — writing it in
            // the `get_mut` branch above instead would leave every stream
            // citing its most recent frame rather than its first.
            //
            // Cloning an `Option<FrameRef>` is a refcount bump on an `Arc<str>`
            // already interned once per source, plus two words. Paid per
            // STREAM, not per packet: a 425-packet call pays it once.
            //
            // `None` when the packet had no origin (live capture, HEP, a
            // synthetic packet). Left `None` rather than filled in from a
            // neighbour — a stream with no provenance must say so.
            // STREAM, not per packet -- and now the refcount is paid here
            // too, once per stream, rather than once per parsed frame.
            stream.first_frame = parsed.frame.map(|l| l.to_frame_ref());
            // The marking this stream started with, stamped in the same branch
            // and for the same reason as `first_frame`: this is by
            // construction the first packet of the key. `dscp_last` starts
            // equal, so `dscp_remarked()` is false for a one-packet stream
            // rather than reading an absent second value as a change.
            stream.dscp_first = parsed.dscp;
            stream.dscp_last = parsed.dscp;
            // RFC 3551 knows the clock rate for twenty-four static payload
            // types; `RtpStream::new` knows eight of them and answers 8000 Hz
            // for the rest. Correct it here, before the first packet feeds the
            // jitter estimate — the same reason the SDP resolution below runs
            // at creation (SNB-0007): a jitter sample folded in at the wrong
            // clock cannot be recomputed later.
            if let Some(hz) = rfc3551_clock_rate(rtp.payload_type) {
                stream.clock_rate = hz;
            }
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
            self.generation += 1;
        }
    }

    /// Record what RTCP asserted **beside** each stream's own measurement.
    ///
    /// Reception reports (SR/RR) are filed in the provenance side-table,
    /// readable via [`Self::remote_report`]; XR VoIP Metrics blocks are filed
    /// alongside them, readable via [`Self::remote_voip_metrics`]. Neither
    /// touches `RtpStream::jitter` or `RtpStream::lost_packets`, which stay
    /// what sipnab measured from the media it observed, and neither can
    /// therefore move MOS.
    ///
    /// This used to assign `stream.lost_packets = report.cumulative_lost` and
    /// `stream.jitter` from the report. Both were wrong twice over:
    ///
    /// - **The value.** `cumulative_lost` counts losses since the *reporter*
    ///   began receiving, on the *reporter's* path segment. Combining it with
    ///   a locally observed `packet_count` — which is what every loss
    ///   percentage in sipnab does — divides one endpoint's session-long count
    ///   by another observer's capture-window count. On real traffic that
    ///   turned streams with zero measured loss into streams reported at up to
    ///   50% loss with a MOS near the 1.0 floor, and no arithmetic recovers a
    ///   rate from those two numbers.
    /// - **The provenance.** RTCP is unauthenticated. Once the far end's claim
    ///   is written into the same field as sipnab's measurement, an operator
    ///   cannot tell which they are reading, a spoofed report moves the quality
    ///   score, and on a mid-path capture the two legitimately describe
    ///   different path segments — a disagreement worth seeing, not resolving
    ///   by overwrite.
    ///
    /// # Side effects
    ///
    /// For every reception report block inside an SR or RR, records the block
    /// against **every** tracked stream carrying the reported SSRC (a source
    /// relayed through the capture point appears under more than one 5-tuple;
    /// filing the report against an arbitrary one of them was itself a
    /// misattribution), incrementing that stream's `reports_seen`. For every
    /// VoIP Metrics block inside an XR, the same treatment against the same
    /// index, readable via [`Self::remote_voip_metrics`]. Other RTCP packet
    /// types and unknown SSRCs are ignored. Does not bump the generation — no
    /// stream's identity, dialog or codec changes.
    pub fn process_rtcp(&mut self, packets: &[RtcpPacket], observed_at: DateTime<Utc>) {
        for pkt in packets {
            if let RtcpPacket::ExtendedReport(xr) = pkt {
                self.record_extended_report(xr);
                continue;
            }
            let reports: &[ReceptionReport] = match pkt {
                RtcpPacket::SenderReport(sr) => &sr.reports,
                RtcpPacket::ReceiverReport(rr) => &rr.reports,
                _ => continue,
            };
            let reporter_ssrc = match pkt {
                RtcpPacket::SenderReport(sr) => sr.ssrc,
                RtcpPacket::ReceiverReport(rr) => rr.ssrc,
                _ => continue,
            };

            for report in reports {
                // O(1) via the SSRC index. Every matching stream is recorded,
                // not just the first: the index exists because one SSRC can
                // legitimately appear on several 5-tuples.
                let Some(keys) = self.ssrc_index.get(&report.ssrc) else {
                    continue;
                };
                let keys = keys.clone();
                for key in &keys {
                    let Some(stream) = self.streams.get(key) else {
                        continue;
                    };
                    // Milliseconds only when the clock rate is a fact. An
                    // assumed clock produces a number that looks like
                    // milliseconds and is not; the wire value is kept either
                    // way so nothing is lost.
                    let jitter_ms = (Self::grounding_of(stream) != ClockGrounding::Assumed
                        && stream.clock_rate > 0)
                        .then(|| f64::from(report.jitter) * 1000.0 / f64::from(stream.clock_rate));
                    let entry = self.provenance.entry(key.clone()).or_default();
                    let reports_seen = entry.remote.map_or(0, |r| r.reports_seen).saturating_add(1);
                    // Anchored on when sipnab SAW this report, which is what a
                    // passive tap has. `rtt_from_sender_report_echo` documents
                    // what that anchor costs; the short version is that it is
                    // the real round trip when the tap sits with the SR sender
                    // and a lower bound otherwise.
                    let round_trip_ms = crate::rtp::rtcp::rtt_from_sender_report_echo(
                        observed_at,
                        report.last_sr,
                        report.delay_since_sr,
                    );
                    entry.remote = Some(RemoteReceptionReport {
                        reporter_ssrc,
                        fraction_lost: report.fraction_lost,
                        cumulative_lost: report.cumulative_lost,
                        highest_seq: report.highest_seq,
                        jitter_timestamp_units: report.jitter,
                        jitter_ms,
                        round_trip_ms,
                        reports_seen,
                    });
                }
            }
        }
    }

    /// File an XR's VoIP Metrics blocks in the provenance side-table.
    ///
    /// The same rule as [`Self::process_rtcp`]: filed **beside** the stream's
    /// own numbers, never into them. RFC 3611 lets one XR carry several block
    /// types; only VoIP Metrics (BT=7) names a source SSRC whose reception it
    /// describes in figures comparable with sipnab's own, so it is the only
    /// one recorded here. The rest are decoded by
    /// [`parse_rtcp`](crate::rtp::rtcp::parse_rtcp) and go unrecorded, which
    /// is the honest state until something consumes them.
    ///
    /// # Side effects
    ///
    /// Records each block against **every** tracked stream carrying the
    /// reported SSRC — one source relayed through the capture point appears
    /// under more than one 5-tuple, and picking an arbitrary one of them is a
    /// misattribution. Unknown SSRCs are ignored. Does not bump the
    /// generation: no stream's identity, dialog or codec changes.
    fn record_extended_report(&mut self, xr: &ExtendedReport) {
        for block in &xr.blocks {
            let XrBlock::VoipMetrics(metrics) = block else {
                continue;
            };
            let Some(keys) = self.ssrc_index.get(&metrics.ssrc) else {
                continue;
            };
            let keys = keys.clone();
            for key in &keys {
                if !self.streams.contains_key(key) {
                    continue;
                }
                let entry = self.provenance.entry(key.clone()).or_default();
                let reports_seen = entry
                    .voip_metrics
                    .map_or(0, |m| m.reports_seen)
                    .saturating_add(1);
                entry.voip_metrics = Some(RemoteVoipMetrics {
                    reporter_ssrc: xr.ssrc,
                    metrics: *metrics,
                    reports_seen,
                });
            }
        }
    }

    /// What a remote endpoint most recently asserted about this stream, if
    /// anything — never sipnab's own measurement. See
    /// [`RemoteReceptionReport`] for why the two are kept apart.
    pub fn remote_report(&self, key: &StreamKey) -> Option<&RemoteReceptionReport> {
        self.provenance.get(key).and_then(|p| p.remote.as_ref())
    }

    /// What an endpoint most recently asserted about this stream in an RTCP XR
    /// VoIP Metrics block, if anything — never sipnab's own measurement. See
    /// [`RemoteVoipMetrics`] for why the two are kept apart.
    pub fn remote_voip_metrics(&self, key: &StreamKey) -> Option<&RemoteVoipMetrics> {
        self.provenance
            .get(key)
            .and_then(|p| p.voip_metrics.as_ref())
    }

    /// The best round-trip figure available for this stream, and where it came
    /// from — or `None` when nothing reported one.
    ///
    /// # Why this needs a resolver at all
    ///
    /// Latency is the third of the three numbers that decide whether a call was
    /// acceptable, and it is the one sipnab cannot measure for itself: a
    /// passive tap sees one point on the path, and a round trip is by
    /// definition about two. So every figure here is somebody else's, and the
    /// two possible somebodies disagree in kind:
    ///
    /// - An XR VoIP Metrics block carries the reporting endpoint's OWN round
    ///   trip between the two RTP interfaces. That is the quantity ITU-T G.114
    ///   sets its ~150 ms guidance against, and it describes the call.
    /// - An RR's SR echo yields a figure anchored on the capture point, which
    ///   is the whole round trip only when the tap sits with the SR sender.
    ///
    /// XR therefore wins whenever one exists, and the source is returned beside
    /// the number rather than folded away, because an operator escalating on
    /// 200 ms needs to know whether that is the call or a path segment.
    ///
    /// XR is also rare — most stacks never emit one — which is why the echo
    /// path exists at all. Before it, `round_trip_delay` was parsed out of the
    /// XR block and dropped, so the answer to "was this call acceptable?" was
    /// unavailable on essentially every capture.
    ///
    /// # The cost of preferring evidence quality over recency
    ///
    /// This ranks by KIND, not by age, and that has a failure mode worth
    /// naming: an endpoint that sends one XR early and then only RRs leaves
    /// this reporting the opening figure for the rest of the call, while
    /// fresher echo-derived numbers go unused. On a path that degrades
    /// mid-call, the reported round trip is then the one from before it
    /// degraded.
    ///
    /// It is still the right ranking — the echo figure is anchored on the
    /// capture point and is a lower bound on most topologies, so a fresh weak
    /// measurement is not obviously better than a stale strong one — but the
    /// choice is a judgement, not a fact, and neither entry currently records
    /// WHEN it was filed, so nothing here could compare ages even if it wanted
    /// to. Fixing that means timestamping the provenance entries.
    ///
    /// # Returns
    ///
    /// `None` means NOT MEASURED, and callers must keep that distinct from a
    /// measured zero all the way to their own output. A stream with clean
    /// jitter, no loss and an unknown round trip is not a healthy stream; it is
    /// a stream with one unanswered question.
    pub fn round_trip(&self, key: &StreamKey) -> Option<(f64, RttSource)> {
        let p = self.provenance.get(key)?;
        // An XR that reports 0 ms is reported as 0 ms: that is the endpoint's
        // measurement, and second-guessing it here would be sipnab overwriting
        // a remote figure, which is the thing this whole side-table exists to
        // avoid.
        if let Some(xr) = p.voip_metrics.as_ref() {
            return Some((
                f64::from(xr.metrics.round_trip_delay),
                RttSource::XrVoipMetrics,
            ));
        }
        p.remote
            .as_ref()
            .and_then(|r| r.round_trip_ms)
            .map(|ms| (ms, RttSource::SenderReportEcho))
    }

    /// [`Self::round_trip`] for a stream you already hold.
    ///
    /// Every surface iterates `&RtpStream` rather than keys, and a stream
    /// carries its own key, so this saves each of them reaching into the key to
    /// ask a question about the stream in front of them.
    pub fn round_trip_for(&self, stream: &RtpStream) -> Option<(f64, RttSource)> {
        self.round_trip(&stream.key)
    }

    /// How a stream's RTP clock rate came to be known, or `None` if the stream
    /// is not tracked.
    pub fn clock_grounding(&self, key: &StreamKey) -> Option<ClockGrounding> {
        self.streams.get(key).map(Self::grounding_of)
    }

    /// A stream's measured interarrival jitter in milliseconds, or `None` when
    /// there is no honest number to give.
    ///
    /// `None` in two cases, both of which the bare `RtpStream::jitter` field
    /// reports as a plain `f64` that reads like a measurement:
    ///
    /// - The clock rate is [`ClockGrounding::Assumed`]. Jitter is an RTP
    ///   timestamp difference divided by the clock rate; with the wrong
    ///   divisor the result is not an imprecise measurement but a different
    ///   quantity. A dynamic payload type with no `a=rtpmap` gives no basis to
    ///   pick one, and the 8 kHz that gets assumed anyway produced jitter
    ///   figures in the millions of milliseconds on captured video.
    /// - The clock rate was corrected *after* packets had been folded in at
    ///   the wrong one, and the estimator has not yet re-converged
    ///   (`JITTER_CONVERGENCE_PACKETS` samples).
    ///
    /// Callers that must print something can still read `RtpStream::jitter`;
    /// this is the accessor for callers that would rather say "unknown".
    pub fn measured_jitter_ms(&self, key: &StreamKey) -> Option<f64> {
        let stream = self.streams.get(key)?;
        if Self::grounding_of(stream) == ClockGrounding::Assumed {
            return None;
        }
        if let Some(restart) = self.provenance.get(key).and_then(|p| p.jitter_restart_at)
            && stream.packet_count.saturating_sub(restart) < JITTER_CONVERGENCE_PACKETS
        {
            return None;
        }
        Some(stream.jitter)
    }

    /// Classify a stream's clock rate without borrowing the whole store.
    ///
    /// A dynamic payload type carries a codec name only because an SDP
    /// `a=rtpmap` supplied one, and the rtpmap that named the codec is the
    /// same line that supplied the clock rate — so `codec.is_some()` on a
    /// non-RFC-3551 payload type is exactly "resolved from rtpmap".
    fn grounding_of(stream: &RtpStream) -> ClockGrounding {
        if rfc3551_clock_rate(stream.payload_type).is_some() {
            ClockGrounding::Rfc3551
        } else if stream.codec.is_some() {
            ClockGrounding::Rtpmap
        } else {
            ClockGrounding::Assumed
        }
    }

    /// All streams linked (via SDP or heuristics) to the given dialog's
    /// Call-ID. The one sanctioned way to answer "which streams belong to
    /// this call" — callers used to hand-roll this filter at ten sites.
    pub fn streams_for<'a>(&'a self, call_id: &'a str) -> impl Iterator<Item = &'a RtpStream> {
        self.iter()
            .filter(move |s| s.associated_dialog.as_deref() == Some(call_id))
    }

    /// Link streams to a SIP dialog by matching the SDP media endpoint.
    ///
    /// When SDP is parsed from a SIP message, call this with the negotiated
    /// media address and port plus the dialog's Call-ID. Any stream whose
    /// source or destination matches the media endpoint gets linked.
    ///
    /// # Side effects
    ///
    /// Sets `associated_dialog` on each matching stream that is not yet
    /// linked -- which is what makes it no longer an orphan, since
    /// [`RtpStream::orphaned`] is derived from that field -- bumping the
    /// generation per newly linked stream; already-linked streams are left untouched. Also
    /// advances the `link_scan_iters` probe counter.
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
                self.generation += 1;
            }
        }
    }

    /// Link streams to a SIP dialog and enrich codec/clock_rate from SDP.
    ///
    /// Like `Self::link_to_dialog`, but also propagates codec name and clock rate
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
        self.link_endpoint_with_ptime(media_addr, media_port, call_id, &rtpmap, media.ptime);
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
    ///
    /// # Side effects
    ///
    /// Records/refreshes the endpoint in `sdp_endpoints` (for streams
    /// created later), then for each already-existing matching stream
    /// fills an unset `associated_dialog` and/or resolves an unknown
    /// codec + clock rate from the rtpmap, bumping the generation for
    /// each change. Advances the `link_scan_iters` probe counter.
    pub fn link_endpoint(
        &mut self,
        media_addr: IpAddr,
        media_port: u16,
        call_id: &str,
        rtpmap: &[(u8, String, u32)],
    ) {
        self.link_endpoint_with_ptime(media_addr, media_port, call_id, rtpmap, None);
    }

    /// [`link_endpoint`](Self::link_endpoint) plus the media description's
    /// `a=ptime`, which reaches `RtpStream::sdp_ptime_ms`.
    ///
    /// Split from `link_endpoint` rather than added to it so the callers that
    /// genuinely have no media description — the post-capture re-link sweep and
    /// the tests that build an rtpmap by hand — say `None` by not saying
    /// anything, instead of every call site growing a trailing argument it has
    /// no answer for.
    ///
    /// # Side effects
    ///
    /// As [`link_endpoint`](Self::link_endpoint), and additionally writes
    /// `sdp_ptime_ms` on every already-existing matching stream that has none.
    pub fn link_endpoint_with_ptime(
        &mut self,
        media_addr: IpAddr,
        media_port: u16,
        call_id: &str,
        rtpmap: &[(u8, String, u32)],
        ptime: Option<u32>,
    ) {
        // Remember this endpoint so a stream created *later* (the common
        // ordering) resolves codec/clock/dialog at creation — see process_rtp.
        self.remember_sdp_endpoint(media_addr, media_port, call_id, rtpmap, ptime);

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
                self.generation += 1;
            }
            // Only fills an unset one, for the same reason the codec branch
            // below does: a re-offer that drops `a=ptime` must not erase what
            // the original exchange declared.
            if stream.sdp_ptime_ms.is_none()
                && let Some(ms) = ptime
            {
                stream.sdp_ptime_ms = Some(ms);
                self.generation += 1;
            }
            // Enrich codec info from SDP rtpmap for dynamic payload types. Only
            // update if the stream's codec is unknown (dynamic PT, no static map).
            if stream.codec.is_none()
                && let Some((_, encoding, clock_rate)) =
                    rtpmap.iter().find(|(pt, _, _)| *pt == stream.payload_type)
            {
                let was = stream.clock_rate;
                stream.codec = Some(encoding.clone());
                stream.clock_rate = *clock_rate;
                self.generation += 1;
                // A stream created before its SDP accumulated jitter against
                // the placeholder clock, and RFC 3550's estimator is a running
                // average with no history to rescale — the samples already
                // folded in cannot be recovered. Restart it rather than leave a
                // permanently wrong figure (an 8 kHz assumption on a 90 kHz
                // stream is 11.25x too large), and remember where, so
                // `measured_jitter_ms` withholds the estimate until it has
                // re-converged instead of publishing the zero seed.
                if was != *clock_rate && stream.packet_count > 1 {
                    stream.jitter = 0.0;
                    let at = stream.packet_count;
                    self.provenance
                        .entry(key.clone())
                        .or_default()
                        .jitter_restart_at = Some(at);
                }
            }
        }
    }

    /// Record an SDP-negotiated endpoint for later stream resolution, bounded
    /// to `max_streams` entries (oldest-out). A repeated offer/answer for the
    /// same endpoint refreshes it; a re-offer that drops the rtpmap or the
    /// `a=ptime` does not clobber a previously-learned one.
    fn remember_sdp_endpoint(
        &mut self,
        addr: IpAddr,
        port: u16,
        call_id: &str,
        rtpmap: &[(u8, String, u32)],
        ptime: Option<u32>,
    ) {
        match self.sdp_endpoints.get_mut(&(addr, port)) {
            Some(existing) => {
                existing.call_id = call_id.to_string();
                if !rtpmap.is_empty() {
                    existing.rtpmap = rtpmap.to_vec();
                }
                if ptime.is_some() {
                    existing.ptime = ptime;
                }
            }
            None => {
                // Batched oldest-out eviction (SNB-0015 pattern): `shift_remove_index(0)`
                // is O(n), so evicting one entry per insert under a unique-endpoint flood
                // paid a full-map shift on every insert → O(calls²) — the same cliff the
                // stream and dialog caps already fixed. Drain the oldest ~10% in a single
                // shift so the O(n) cost amortizes to O(1) per insertion (mirrors
                // `ensure_capacity` and `DialogStore::evict_oldest`). `.max(1)` keeps small
                // caps evicting singly; the cap stays a hard upper bound, though the map may
                // briefly sit just under it.
                if self.max_streams > 0 && self.sdp_endpoints.len() >= self.max_streams {
                    let batch = (self.max_streams / 10).max(1).min(self.sdp_endpoints.len());
                    self.sdp_endpoints.drain(0..batch);
                }
                self.sdp_endpoints.insert(
                    (addr, port),
                    SdpEndpoint {
                        call_id: call_id.to_string(),
                        rtpmap: rtpmap.to_vec(),
                        ptime,
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
            }
            if stream.sdp_ptime_ms.is_none() {
                stream.sdp_ptime_ms = endpoint.ptime;
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

    /// Look up a stream by its key.
    pub fn get(&self, key: &StreamKey) -> Option<&RtpStream> {
        self.streams.get(key)
    }

    /// Tie an ICMP error's quoted datagram to the media this store tracked.
    ///
    /// An ICMP error about media carries no `Call-ID` — a media datagram has
    /// none to carry — so the signalling side's association key does not exist
    /// here. What the quote does carry is the failed datagram's own 5-tuple
    /// and, when the router quoted more than RFC 792's 8-byte minimum, an RTP
    /// or RTCP header with an SSRC. Those are matched here, most specific
    /// first, and the tier that succeeded is returned so a reader can see how
    /// strong the tie is rather than being handed a bare "matched".
    ///
    /// The tiers, and why each exists:
    ///
    /// 1. [`MediaMatch::Flow`] — the quoted directed 5-tuple is exactly a
    ///    tracked stream. The quote describes a datagram sipnab itself saw as
    ///    RTP; nothing weaker is needed and nothing stronger exists.
    /// 2. [`MediaMatch::Ssrc`] — the quoted payload named a tracked stream's
    ///    SSRC. This is what carries the commonest real case: RTCP runs one
    ///    port above RTP (RFC 3550 §11), so an error about RTCP can never
    ///    match a stream's 5-tuple, and in one real corpus the media errors
    ///    were predominantly RTCP.
    /// 3. [`MediaMatch::Endpoint`] — one of the two sockets is an endpoint of
    ///    a tracked stream, in either direction. Covers a capture that saw
    ///    only one half of the media.
    /// 4. [`MediaMatch::SdpEndpoint`] — the socket was advertised in SDP, or
    ///    is the RTCP companion (one port above) of one. This is the only tier
    ///    that works when no media was captured at all, which is exactly the
    ///    case an operator asks about when they say "the call connected and
    ///    there was no audio".
    /// 5. [`MediaMatch::None`] — nothing matched. The caller counts it as
    ///    unattributed; it is never discarded, because the endpoint it names
    ///    is real whether or not this capture holds its stream.
    ///
    /// Both sockets are tried at tiers 3 and 4, destination first: the ICMP
    /// error is *about* the destination, but the source is our own media port
    /// and identifies the call just as well when the destination is unknown.
    ///
    /// # Arguments
    ///
    /// * `src` — the quoted datagram's source: the socket that sent the media.
    /// * `dst` — the quoted datagram's destination: the socket that did not
    ///   answer.
    /// * `ssrc` — SSRC read out of the quoted payload, when the quote reached
    ///   it. `None` is the RFC 792 case, not a failure.
    ///
    /// # Returns
    ///
    /// The strongest tier that matched, with the `Call-ID`s it named
    /// (deduplicated, in stream insertion order). `MediaMatch::None` with no
    /// call IDs when nothing matched.
    pub fn attribute_media_quote(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        ssrc: Option<u32>,
    ) -> MediaAttribution {
        let dst_ep = (dst.ip(), dst.port());
        let src_ep = (src.ip(), src.port());

        // 1. The quoted 5-tuple is a stream, exactly and directionally.
        if let Some(keys) = self.endpoint_index.get(&dst_ep) {
            let exact: Vec<&StreamKey> = keys
                .iter()
                .filter(|k| k.src == src && k.dst == dst)
                .collect();
            if !exact.is_empty() {
                return self.attribution(MediaMatch::Flow, exact.into_iter());
            }
        }

        // 2. The quoted payload named a tracked SSRC.
        if let Some(keys) = ssrc.and_then(|s| self.ssrc_index.get(&s))
            && !keys.is_empty()
        {
            return self.attribution(MediaMatch::Ssrc, keys.iter());
        }

        // 3. Either socket is an endpoint of a tracked stream.
        for ep in [&dst_ep, &src_ep] {
            if let Some(keys) = self.endpoint_index.get(ep)
                && !keys.is_empty()
            {
                return self.attribution(MediaMatch::Endpoint, keys.iter());
            }
        }

        // 4. Either socket was advertised in SDP, or is its RTCP companion.
        //    RFC 3550 §11: when the media port is even, RTCP uses the next
        //    port up, and no SDP line ever mentions it.
        for sock in [dst, src] {
            let companion = sock.port().checked_sub(1).filter(|p| p % 2 == 0);
            for port in [Some(sock.port()), companion].into_iter().flatten() {
                if let Some(ep) = self.sdp_endpoints.get(&(sock.ip(), port)) {
                    return MediaAttribution {
                        matched: MediaMatch::SdpEndpoint,
                        streams: 0,
                        call_ids: vec![ep.call_id.clone()],
                    };
                }
            }
        }

        MediaAttribution::default()
    }

    /// Collect the dialogs behind a set of matched stream keys.
    ///
    /// Split out so each tier above states only its own matching rule; the
    /// answer they all produce — how many streams, and which calls — is built
    /// once here and cannot drift between tiers.
    fn attribution<'a>(
        &self,
        matched: MediaMatch,
        keys: impl Iterator<Item = &'a StreamKey>,
    ) -> MediaAttribution {
        let mut streams = 0usize;
        let mut call_ids: Vec<String> = Vec::new();
        for key in keys {
            let Some(stream) = self.streams.get(key) else {
                continue;
            };
            streams += 1;
            if let Some(id) = &stream.associated_dialog
                && !call_ids.iter().any(|c| c == id)
            {
                call_ids.push(id.clone());
            }
        }
        // Every key came from an index this store maintains, so a zero here
        // would mean the index outlived its streams. Report no match rather
        // than a match onto nothing.
        if streams == 0 {
            return MediaAttribution::default();
        }
        MediaAttribution {
            matched,
            streams,
            call_ids,
        }
    }

    /// Insert a pre-built stream directly (unit tests only) — bypasses
    /// packet processing but keeps the SSRC index and generation honest.
    /// Gated on `tui` alongside its only consumer (the dashboard tests),
    /// so no-`tui` test builds don't see it as dead code.
    #[cfg(all(test, feature = "tui"))]
    pub(crate) fn insert_for_test(&mut self, s: RtpStream) {
        self.ssrc_index
            .entry(s.key.ssrc)
            .or_default()
            .push(s.key.clone());
        self.streams.insert(s.key.clone(), s);
        self.generation += 1;
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

    /// Remove all streams from the store, clearing the SSRC and endpoint
    /// indexes AND the remembered SDP endpoints with them, and bumping the
    /// generation. Dropping `sdp_endpoints` matters: a stream created after
    /// a clear must not resolve its dialog from a pre-clear endpoint,
    /// resurrecting a dead association.
    pub fn clear(&mut self) {
        self.streams.clear();
        self.ssrc_index.clear();
        self.endpoint_index.clear();
        self.sdp_endpoints.clear();
        self.provenance.clear();
        self.generation += 1;
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

    /// Count of streams no dialog claims, per [`RtpStream::orphaned`].
    pub fn orphaned_count(&self) -> usize {
        self.streams.values().filter(|s| s.orphaned()).count()
    }

    /// Fold another worker's store into this one (multi-core merge, `--cores N`).
    /// Streams sharded by host pair never collide across workers, so this is a
    /// union; the ssrc/endpoint indexes are rebuilt for the moved streams and the
    /// SDP endpoints are combined. Probe counters accumulate. Call
    /// `reassociate_all` afterwards to link streams to a
    /// dialog whose SDP was processed on a different worker.
    pub fn merge(&mut self, other: StreamStore) {
        for (key, stream) in other.streams {
            if !self.streams.contains_key(&key) {
                self.ssrc_index
                    .entry(key.ssrc)
                    .or_default()
                    .push(key.clone());
                self.index_endpoints(&key);
                // Carry the stream's provenance across with it: dropping it
                // would silently turn "the far end claimed X" into "nobody
                // reported anything" on every multi-core run.
                if let Some(p) = other.provenance.get(&key) {
                    self.provenance.insert(key.clone(), p.clone());
                }
                self.streams.insert(key, stream);
                self.generation += 1;
            }
        }
        for (ep, sdp) in other.sdp_endpoints {
            self.sdp_endpoints.entry(ep).or_insert(sdp);
        }
        self.link_scan_iters += other.link_scan_iters;
        self.evict_shift_work += other.evict_shift_work;
    }

    /// Globally (re)link every stream to its dialog via the merged SDP endpoints.
    /// Needed after `merge`: when a stream and the SDP naming its
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
            self.link_endpoint_with_ptime(addr, port, &ep.call_id, &ep.rtpmap, ep.ptime);
        }
    }

    /// Make room for one new stream if the store is at capacity.
    ///
    /// # Side effects
    ///
    /// When at `max_streams`, batch-evicts the oldest ~10% of streams
    /// (at least one) in insertion order, removing their SSRC and
    /// endpoint index entries and advancing the `evict_shift_work` probe
    /// counter. Does not bump the generation.
    fn ensure_capacity(&mut self) {
        if self.streams.len() >= self.max_streams && !self.streams.is_empty() {
            // Evicting one-at-a-time with shift_remove_index(0) shifts O(n) entries
            // PER new stream once at capacity → O(calls²) under sustained pressure
            // (SNB-0015). Batch-evict the oldest ~10% in a single `drain`, so the
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
                // The provenance table is keyed by StreamKey and must not
                // outlive the stream, or a later stream reusing the same
                // 5-tuple + SSRC would inherit a stranger's RTCP report.
                self.provenance.remove(key);
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

/// Unit tests for the stream store: creation/update, SDP linking in both
/// orderings, RTCP matching, eviction and index consistency, multi-worker
/// merge, and the SNB-0015 performance probes.
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::net::TransportProto;
    use crate::rtp::parser::RtpHeader;

    /// Build a UDP ParsedPacket from 10.0.0.1:`src_port` to
    /// 10.0.0.2:`dst_port` with a zeroed 12-byte-header + `payload_len`
    /// payload.
    fn make_parsed(src_port: u16, dst_port: u16, payload_len: usize) -> ParsedPacket {
        ParsedPacket {
            frame: None,
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
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        }
    }

    /// WS4.3c: the TUI keys its cached RTP codec segments (and hence the
    /// cached ladder layout) on this generation — structural changes (new
    /// stream, dialog link, codec resolution, clear) must bump it, while a
    /// per-packet update to an existing stream must NOT, or the cache
    /// would miss on every RTP packet of a live call.
    #[test]
    fn generation_bumps_on_structural_changes_not_per_packet_updates() {
        let mut store = StreamStore::new(16);
        let g0 = store.generation();

        // New stream → bump.
        store.process_rtp(
            &make_parsed(40000, 30000, 160),
            &make_rtp_header(0xCCCC, 1),
            ts(0),
        );
        let g1 = store.generation();
        assert!(g1 > g0, "new stream must bump the generation");

        // Same stream, next packet → counters/last_seen only, NO bump.
        store.process_rtp(
            &make_parsed(40000, 30000, 160),
            &make_rtp_header(0xCCCC, 2),
            ts(1),
        );
        assert_eq!(
            store.generation(),
            g1,
            "a per-packet update must not bump the generation"
        );

        // Linking the stream's media endpoint to a dialog → bump (the
        // stream now appears in streams_for("gen-call@test")).
        store.link_to_dialog(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            30000,
            "gen-call@test",
        );
        let g2 = store.generation();
        assert!(g2 > g1, "a dialog link must bump the generation");

        // Re-linking the same (already linked) endpoint is a no-op → no bump.
        store.link_to_dialog(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            30000,
            "other-call@test",
        );
        assert_eq!(
            store.generation(),
            g2,
            "an idempotent re-link must not bump the generation"
        );

        // clear() → bump.
        store.clear();
        assert!(store.generation() > g2, "clear must bump the generation");
    }

    /// One INVITE offering audio (static PT) and video (dynamic PT) yields
    /// two codec-resolved streams linked to the same dialog.
    #[test]
    fn multi_mline_audio_and_video_both_link_and_resolve_codecs() {
        // A single INVITE offering audio (m=audio, PCMU) AND video (m=video,
        // dynamic PT 96 = H264) must produce two independently-tracked,
        // codec-resolved streams associated with the same dialog.
        let sdp_body = b"v=0\r\n\
o=- 1 1 IN IP4 10.0.0.2\r\n\
s=call\r\n\
c=IN IP4 10.0.0.2\r\n\
t=0 0\r\n\
m=audio 30000 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n\
m=video 30002 RTP/AVP 96\r\n\
a=rtpmap:96 H264/90000\r\n";
        let sdp = crate::sip::sdp::parse_sdp(sdp_body).expect("SDP parses");
        assert_eq!(sdp.media.len(), 2, "both m= lines must be parsed");

        let mut store = StreamStore::new(16);
        // Link every media description (mirrors the pipeline loop).
        for media in &sdp.media {
            let addr = crate::sip::sdp::effective_address(media, &sdp)
                .and_then(|a| a.parse::<IpAddr>().ok())
                .expect("media address");
            store.link_to_dialog_with_sdp(addr, media.port, "av-call@test", media);
        }

        // Audio RTP: PT 0 (PCMU) to :30000.
        store.process_rtp(
            &make_parsed(40000, 30000, 160),
            &make_rtp_header(0xAAAA, 1),
            ts(0),
        );
        // Video RTP: dynamic PT 96 to :30002.
        let mut video_hdr = make_rtp_header(0xBBBB, 1);
        video_hdr.payload_type = 96;
        store.process_rtp(&make_parsed(40002, 30002, 900), &video_hdr, ts(0));

        let linked: Vec<_> = store.streams_for("av-call@test").collect();
        assert_eq!(linked.len(), 2, "audio and video must both be tracked");

        let audio = linked
            .iter()
            .find(|s| s.key.dst.port() == 30000)
            .expect("audio stream linked");
        let video = linked
            .iter()
            .find(|s| s.key.dst.port() == 30002)
            .expect("video stream linked");
        assert_eq!(audio.codec.as_deref(), Some("PCMU"));
        assert_eq!(
            video.codec.as_deref(),
            Some("H264"),
            "dynamic video PT must resolve from the second m= line's rtpmap"
        );
    }

    /// streams_for yields only streams linked to the requested Call-ID.
    #[test]
    fn streams_for_returns_only_linked_streams() {
        let mut store = StreamStore::new(16);
        // Two streams on different endpoints.
        store.process_rtp(
            &make_parsed(20000, 30000, 160),
            &make_rtp_header(0x1111, 1),
            DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
        );
        store.process_rtp(
            &make_parsed(22000, 32000, 160),
            &make_rtp_header(0x2222, 1),
            DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
        );
        // Link only the first to a dialog.
        store.link_to_dialog(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000, "call-a");

        let linked: Vec<_> = store.streams_for("call-a").collect();
        assert_eq!(linked.len(), 1);
        assert_eq!(linked[0].key.ssrc, 0x1111);
        assert!(store.streams_for("call-b").next().is_none());
    }

    /// Build a PT 0 (PCMU) RtpHeader with a 160-ticks-per-packet timestamp.
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

    /// Fixed-epoch test clock: `secs` seconds past 1_700_000_000 UTC.
    fn ts(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid")
    }

    /// Fixed-epoch test clock with millisecond resolution.
    fn ts_ms(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(1_700_000_000_000 + ms).expect("valid")
    }

    /// Build an RtpHeader with explicit payload type and RTP timestamp.
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
    /// SDP-before-RTP ordering: a stream created after its SDP resolves
    /// codec, clock rate, and dialog at creation (SNB-0007).
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

    /// clear() must drop remembered SDP endpoints along with the streams:
    /// a stream created *after* a clear must not resolve its dialog from an
    /// endpoint learned before the clear, resurrecting a dead association.
    #[test]
    fn clear_drops_remembered_sdp_endpoints() {
        let mut store = StreamStore::new(100);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 20000u16;

        // SDP endpoint learned for a dialog, then the session is cleared.
        store.link_endpoint(addr, port, "old-call@test", &[]);
        store.clear();

        // A matching stream appearing after the clear must start unlinked.
        store.process_rtp(
            &make_parsed(port, 30000, 160),
            &make_rtp_header(0xDEAD, 1),
            ts(0),
        );
        let s = store.iter().next().expect("stream should exist");
        assert_eq!(
            s.associated_dialog, None,
            "a post-clear stream must not re-link to a pre-clear dialog via a stale SDP endpoint"
        );
    }

    /// Under a unique-endpoint flood, the `sdp_endpoints` cap must evict the
    /// OLDEST endpoints and keep the NEWEST — a stream created for a
    /// recently-seen endpoint still resolves its dialog, while one for an
    /// evicted (oldest) endpoint does not. Guards the batched-eviction rewrite:
    /// batching amortizes the O(n) `shift_remove_index(0)` but must not change
    /// which endpoints survive (newest-in, oldest-out).
    #[test]
    fn sdp_endpoint_eviction_keeps_newest_drops_oldest() {
        let cap = 100usize;
        let flood = 300u16;
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)); // make_parsed src ip
        let mut store = StreamStore::new(cap);

        // Remember `flood` distinct endpoints (port i → "call-i"), overflowing
        // the sdp_endpoints cap many times over. No streams exist yet, so
        // link_endpoint only records the endpoint (its linking loop is a no-op).
        for i in 0..flood {
            store.link_endpoint(addr, 20_000 + i, &format!("call-{i}"), &[]);
        }

        // Newest endpoint (last inserted) must survive: a stream on it resolves
        // its dialog at creation via resolve_from_sdp.
        let newest = flood - 1;
        store.process_rtp(
            &make_parsed(20_000 + newest, 30_000, 160),
            &make_rtp_header(0x0000_0001, 1),
            ts(0),
        );
        let s_new = store
            .iter()
            .find(|s| s.key.src.port() == 20_000 + newest)
            .expect("newest-endpoint stream exists");
        assert_eq!(
            s_new.associated_dialog.as_deref(),
            Some(format!("call-{newest}").as_str()),
            "the newest remembered endpoint must survive eviction and resolve its dialog"
        );

        // Oldest endpoint (first inserted) must have been evicted: a stream on
        // it stays unassociated.
        store.process_rtp(
            &make_parsed(20_000, 31_000, 160),
            &make_rtp_header(0x0000_0002, 1),
            ts(0),
        );
        let s_old = store
            .iter()
            .find(|s| s.key.src.port() == 20_000 && s.key.dst.port() == 31_000)
            .expect("oldest-endpoint stream exists");
        assert_eq!(
            s_old.associated_dialog, None,
            "the oldest remembered endpoint must have been evicted (no stale resolution)"
        );
    }

    // SNB-0015 (eviction): once the store is at capacity, evicting streams
    // one-at-a-time with shift_remove_index(0) shifts O(streams) entries PER new
    // stream → O(calls²) under sustained cap pressure (the dominant carrier-scale
    // cliff). Batched eviction must keep the cumulative shift work ~O(streams seen),
    // not O(overflow × cap). Drive `cap + overflow` distinct streams through a
    // small cap and assert the probe stays bounded — and that eviction is still
    // correct (store stays capped, oldest gone, indexes consistent).
    /// Sustained cap pressure keeps cumulative eviction shift work ~O(N)
    /// (batched eviction), with the store bounded and indexes consistent.
    #[test]
    fn eviction_shift_work_is_amortized_and_correct() {
        let cap = 1_000usize;
        let overflow = 3_000usize;
        let mut store = StreamStore::new(cap);
        for i in 0..(cap + overflow) as u32 {
            // Each iteration is a genuinely new stream: a unique ssrc AND a
            // unique src port, so no two iterations collide onto one StreamKey
            // (which would UPDATE rather than insert, understating cap
            // pressure). i < cap + overflow (= 4_000 < 64_512), so 1_024 + i
            // neither aliases another iteration nor overflows u16.
            let mut p = make_parsed(20_000, 30_000, 160);
            p.src_port = 1_024 + i as u16;
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
    /// SDP-endpoint linking visits O(N) streams via the endpoint index
    /// (not O(N²)) while linking exactly the streams a full scan would.
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

    // Multi-core (--cores): a call's SDP (SIP) and its RTP can be sharded to
    // DIFFERENT workers — in the carrier corpus the SDP advertises a separate
    // media IP. Worker A sees the SDP (remembers the endpoint, no stream); worker
    // B sees the RTP (creates the stream, no SDP → unassociated). merge() unions
    // them and reassociate_all() links the stream to its call — reproducing the
    // single-threaded result where association happens at stream creation.
    /// merge + reassociate_all links a stream whose SDP was processed on a
    /// different worker, matching the single-threaded result.
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
    /// RTP-before-SDP ordering: link_endpoint enriches and associates the
    /// already-existing stream.
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
    /// An SDP-resolved dynamic PT produces the same near-zero jitter as
    /// the static 90 kHz PT, unlike the inflated 8 kHz-default estimate.
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

    /// The first packet of a new 5-tuple+SSRC creates a tracked stream.
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

    /// A stream cites the frame it began in, and never moves that pointer.
    ///
    /// The failure this rules out is the cheap implementation: assigning the
    /// pointer on every `process_rtp` rather than only at creation. A stream
    /// updated by ten thousand packets would then cite whichever frame arrived
    /// last, which is a real frame that is not the one the stream began in —
    /// the confident wrong answer this mechanism exists to prevent, and one
    /// that `is_some()` cannot tell apart from the right answer.
    ///
    /// Asserted against a SECOND packet carrying a DIFFERENT pointer, so the
    /// two implementations genuinely disagree here. With both packets carrying
    /// the same frame the test would pass either way and prove nothing.
    #[test]
    fn a_stream_cites_the_frame_it_began_in_not_its_latest() {
        use crate::capture::packet::FrameOrigin;

        // A parsed packet now carries the Copy locator, so the fixture builds
        // that; the store materialises the owned FrameRef when it keeps one.
        let pointer = |ordinal: u64| {
            Some(crate::capture::packet::FrameLocator {
                source: "calls.pcap",
                origin: FrameOrigin {
                    ordinal,
                    digest: Some(0x0102_0304_0506_0708),
                },
            })
        };

        let mut store = StreamStore::new(100);
        let mut first = make_parsed(20000, 30000, 160);
        first.frame = pointer(7);
        let mut later = make_parsed(20000, 30000, 160);
        later.frame = pointer(4211);

        store.process_rtp(&first, &make_rtp_header(0xDDDD, 1), ts(0));
        store.process_rtp(&later, &make_rtp_header(0xDDDD, 2), ts(1));

        let key = StreamKey {
            ssrc: 0xDDDD,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(stream.packet_count, 2, "both packets must reach the stream");
        assert_eq!(
            stream.first_frame,
            pointer(7).map(|l| l.to_frame_ref()),
            "the stream must cite the frame its FIRST packet arrived in; \
             citing frame 4211 means the pointer is reassigned per packet and \
             every long stream names the wrong frame"
        );

        // A source that cannot number its frames must leave the stream with no
        // pointer rather than a default. This is the live-capture path.
        let mut anonymous = make_parsed(20000, 30001, 160);
        anonymous.frame = None;
        store.process_rtp(&anonymous, &make_rtp_header(0xDDDD, 1), ts(2));
        let orphan_key = StreamKey {
            ssrc: 0xDDDD,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30001),
        };
        assert!(
            store
                .get(&orphan_key)
                .expect("second stream should exist")
                .first_frame
                .is_none(),
            "a packet with no pointer must not yield a stream that claims one"
        );
    }

    /// A second packet on the same key updates the stream instead of
    /// creating a duplicate.
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

    /// Exceeding the capacity of 2 evicts the oldest stream.
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

    /// Linking a media endpoint sets the stream's Call-ID and clears
    /// orphaned.
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
        assert!(!stream.orphaned());
    }

    /// An unclaimed stream counts as an orphan from its FIRST packet.
    ///
    /// This replaces `mark_orphaned_flags_unlinked_streams`, which pinned the
    /// behaviour being fixed: the sweep left a stream unflagged for its first
    /// 30 seconds of capture time, so every consumer of `orphaned` reported
    /// `false` for a stream no dialog would ever claim. A three-second capture
    /// of nothing but unclaimed media reported no orphans at all.
    ///
    /// The age is asserted alongside the count, because "0 seconds old and
    /// orphaned" is the whole claim — a test that only counted would still pass
    /// against a 30-second rule.
    #[test]
    fn an_unclaimed_stream_is_orphaned_from_its_first_packet() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xDDDD, 1);
        store.process_rtp(&parsed, &rtp, ts(0));

        let stream = store.iter().next().expect("one stream");
        assert_eq!(
            stream.first_seen, stream.last_seen,
            "the fixture must be a stream of exactly one packet, or this test \
             is not about a young stream at all"
        );
        assert!(
            stream.orphaned(),
            "a stream no dialog claims is an orphan the moment it exists; \
             waiting 30 s to say so is what made a short NAT-broken stream \
             invisible"
        );
        assert_eq!(store.orphaned_count(), 1);
    }

    /// A dialog-linked stream is never an orphan, however young or old.
    #[test]
    fn linked_streams_not_orphaned() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        let rtp = make_rtp_header(0xEEEE, 1);
        store.process_rtp(&parsed, &rtp, ts(0));
        assert_eq!(
            store.orphaned_count(),
            1,
            "unclaimed before the SDP arrives"
        );

        store.link_to_dialog(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000, "call-456");

        assert_eq!(
            store.orphaned_count(),
            0,
            "linking to a dialog is what ends orphan status, and nothing else \
             has to happen for the answer to change"
        );
    }

    /// An RR block is recorded beside the stream, never over it.
    ///
    /// The measurement and the assertion stay separately addressable: the
    /// stream keeps what sipnab observed, `remote_report` holds what the far
    /// end claimed, and each carries its units.
    #[test]
    fn process_rtcp_records_the_report_without_touching_the_measurement() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        store.process_rtp(&parsed, &make_rtp_header(0xFFFF, 1), ts(0));
        store.process_rtp(&parsed, &make_rtp_header(0xFFFF, 2), ts(1));

        let key = StreamKey {
            ssrc: 0xFFFF,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let measured_jitter = store.get(&key).unwrap().jitter;
        let measured_lost = store.get(&key).unwrap().lost_packets;
        assert_eq!(measured_lost, 0, "the fixture stream has no sequence gaps");

        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};
        store.process_rtcp(
            &[RtcpPacket::ReceiverReport(ReceiverReport {
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
            })],
            chrono::Utc::now(),
        );

        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(
            stream.lost_packets, measured_lost,
            "a stream with no observed gaps must not acquire loss from a \
             datagram; cumulative_lost counts the reporter's whole session on \
             the reporter's path, and dividing it by a locally observed packet \
             count is not a loss rate"
        );
        assert_eq!(
            stream.jitter, measured_jitter,
            "the far end's jitter must not replace the measured estimate"
        );

        let remote = store.remote_report(&key).expect("report recorded");
        assert_eq!(remote.reporter_ssrc, 0x1111);
        assert_eq!(remote.cumulative_lost, 10);
        assert_eq!(remote.jitter_timestamp_units, 42);
        // PCMU is 8 kHz, so 42 timestamp units is 5.25 ms — kept as the
        // reporter's figure, in the reporter's units and sipnab's.
        assert_eq!(remote.jitter_ms, Some(5.25));
        assert_eq!(remote.reports_seen, 1);
        assert!((remote.fraction_lost_pct() - 25.0 * 100.0 / 256.0).abs() < 1e-9);
    }

    /// A VoIP Metrics block whose every field disagrees with the fixture, so
    /// any leak into a measured field is unmistakable.
    fn hostile_metrics(ssrc: u32) -> VoipMetrics {
        VoipMetrics {
            ssrc,
            loss_rate: 128,   // "50% of my packets are gone"
            discard_rate: 64, // "and I threw away another 25%"
            burst_density: 200,
            gap_density: 4,
            burst_duration: 3_000,
            gap_duration: 100,
            round_trip_delay: 450,
            end_system_delay: 90,
            signal_level: 0xEC, // -20 dBm0
            noise_level: 0xB0,  // -80 dBm0
            rerl: 30,
            gmin: 16,
            r_factor: 32,
            ext_r_factor: 127, // unavailable
            mos_lq: 15,        // 1.5
            mos_cq: 13,        // 1.3
            jb_nominal: 40,
            jb_maximum: 120,
            jb_abs_max: 65_535,
        }
    }

    /// Build a two-packet PCMU stream and return its key, for the XR tests.
    fn xr_fixture(store: &mut StreamStore, ssrc: u32) -> StreamKey {
        let parsed = make_parsed(20000, 30000, 160);
        store.process_rtp(&parsed, &make_rtp_header(ssrc, 1), ts(0));
        store.process_rtp(&parsed, &make_rtp_header(ssrc, 2), ts(1));
        StreamKey {
            ssrc,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        }
    }

    /// An XR VoIP Metrics block is retained, not discarded.
    ///
    /// The whole of RTCP XR used to reach `process_rtcp` fully decoded and fall
    /// through its `_ => continue`, so the far end's own R factor, MOS and
    /// burst/gap densities were parsed and then dropped on the floor.
    #[test]
    fn process_rtcp_retains_xr_voip_metrics() {
        let mut store = StreamStore::new(100);
        let key = xr_fixture(&mut store, 0xABCD);

        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x2222,
                blocks: vec![XrBlock::VoipMetrics(hostile_metrics(0xABCD))],
            })],
            chrono::Utc::now(),
        );

        let xr = store
            .remote_voip_metrics(&key)
            .expect("XR VoIP Metrics must be retained, not dropped");
        assert_eq!(xr.reporter_ssrc, 0x2222);
        assert_eq!(xr.reports_seen, 1);
        assert_eq!(xr.metrics.r_factor(), Some(32));
        assert_eq!(xr.metrics.mos_lq(), Some(1.5));
        assert_eq!(xr.metrics.mos_cq(), Some(1.3));
        assert_eq!(xr.metrics.ext_r_factor(), None, "127 means unavailable");
        assert_eq!(xr.metrics.signal_level_dbm0(), Some(-20));
        assert_eq!(xr.metrics.round_trip_delay, 450);
    }

    /// The far end's XR figures never become sipnab's.
    ///
    /// This is the #61 rule applied to XR: a block claiming 50% loss, 25%
    /// discard and a MOS of 1.5 must leave the stream's measured jitter, its
    /// measured loss and the MOS scored from them exactly where they were.
    /// Merging the two would replace a measurement with a claim, and an
    /// unauthenticated one.
    #[test]
    fn xr_voip_metrics_never_overwrite_the_measurement() {
        let mut store = StreamStore::new(100);
        let key = xr_fixture(&mut store, 0xBEEF);

        let mos_of = |store: &StreamStore| {
            let s = store.get(&key).unwrap();
            let total = s.packet_count + s.lost_packets;
            let loss_pct = s.lost_packets as f64 / total as f64 * 100.0;
            crate::rtp::quality::estimate_mos(s.jitter, loss_pct, s.codec.as_deref())
        };
        let measured_jitter = store.get(&key).unwrap().jitter;
        let measured_lost = store.get(&key).unwrap().lost_packets;
        let measured_mos = mos_of(&store);
        assert_eq!(measured_lost, 0, "the fixture stream has no sequence gaps");

        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x2222,
                blocks: vec![XrBlock::VoipMetrics(hostile_metrics(0xBEEF))],
            })],
            chrono::Utc::now(),
        );

        let stream = store.get(&key).expect("stream should exist");
        assert_eq!(
            stream.lost_packets, measured_lost,
            "an endpoint's claimed loss rate must not become sipnab's loss count"
        );
        assert!(
            (stream.jitter - measured_jitter).abs() < f64::EPSILON,
            "an endpoint's claimed delay must not become sipnab's jitter"
        );
        assert!(
            (mos_of(&store) - measured_mos).abs() < f64::EPSILON,
            "an endpoint asserting MOS 1.5 must not move the MOS sipnab scored"
        );
    }

    /// Successive XRs replace the figures and count up, so a reader can tell a
    /// single sample from a long-running report.
    #[test]
    fn xr_voip_metrics_count_reports_and_keep_the_latest() {
        let mut store = StreamStore::new(100);
        let key = xr_fixture(&mut store, 0xC0DE);

        for r in [40u8, 80u8] {
            let mut m = hostile_metrics(0xC0DE);
            m.r_factor = r;
            store.process_rtcp(
                &[RtcpPacket::ExtendedReport(ExtendedReport {
                    ssrc: 0x2222,
                    blocks: vec![XrBlock::VoipMetrics(m)],
                })],
                chrono::Utc::now(),
            );
        }

        let xr = store.remote_voip_metrics(&key).expect("XR recorded");
        assert_eq!(xr.reports_seen, 2, "both blocks counted");
        assert_eq!(xr.metrics.r_factor(), Some(80), "the latest block wins");
    }

    /// An XR about an SSRC no stream carries is ignored rather than filed
    /// against an arbitrary stream.
    #[test]
    fn xr_for_an_unknown_ssrc_is_ignored() {
        let mut store = StreamStore::new(100);
        let key = xr_fixture(&mut store, 0x1234);

        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x2222,
                blocks: vec![XrBlock::VoipMetrics(hostile_metrics(0x9999))],
            })],
            chrono::Utc::now(),
        );

        assert!(
            store.remote_voip_metrics(&key).is_none(),
            "a report about another SSRC must not attach to this stream"
        );
    }

    /// An XR carrying only block types sipnab does not record leaves no trace,
    /// and does not invent an empty entry that reads as "the far end reported".
    #[test]
    fn xr_without_voip_metrics_records_nothing() {
        let mut store = StreamStore::new(100);
        let key = xr_fixture(&mut store, 0x4321);

        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x2222,
                blocks: vec![
                    XrBlock::ReceiverReferenceTime { ntp_timestamp: 7 },
                    XrBlock::Unknown { block_type: 6 },
                ],
            })],
            chrono::Utc::now(),
        );

        assert!(store.remote_voip_metrics(&key).is_none());
    }

    /// MOS is scored from sipnab's own measurement, so a forged RTCP report
    /// cannot move it. RTCP is unauthenticated; before this, a single spoofed
    /// datagram claiming heavy loss dropped a clean stream to the MOS floor.
    #[test]
    fn a_spoofed_rtcp_report_cannot_move_mos() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        for seq in 1..=40u16 {
            store.process_rtp(
                &parsed,
                &make_rtp_header(0x5EED, seq),
                ts_ms(i64::from(seq) * 20),
            );
        }
        let key = StreamKey {
            ssrc: 0x5EED,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let mos_of = |store: &StreamStore| {
            let s = store.get(&key).unwrap();
            let total = s.packet_count + s.lost_packets;
            let loss_pct = s.lost_packets as f64 / total as f64 * 100.0;
            crate::rtp::quality::estimate_mos(s.jitter, loss_pct, s.codec.as_deref())
        };
        let before = mos_of(&store);
        assert!(before > 4.0, "clean fixture stream scores well: {before}");

        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};
        store.process_rtcp(
            &[RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 0xDEAD,
                reports: vec![ReceptionReport {
                    ssrc: 0x5EED,
                    fraction_lost: 255,
                    cumulative_lost: 100_000, // "since the beginning of reception"
                    highest_seq: 100_000,
                    jitter: 800_000,
                    last_sr: 0,
                    delay_since_sr: 0,
                }],
            })],
            chrono::Utc::now(),
        );

        assert_eq!(
            mos_of(&store),
            before,
            "MOS must be computed from what sipnab measured, not from what a \
             datagram asserted"
        );
        // The claim is not discarded — it is just labelled.
        let remote = store.remote_report(&key).expect("claim recorded");
        assert_eq!(remote.cumulative_lost, 100_000);
    }

    /// One SSRC on two 5-tuples is one source seen at two points; a report
    /// about it is recorded against both, not against whichever happened to be
    /// inserted first.
    #[test]
    fn rtcp_reaches_every_stream_carrying_the_reported_ssrc() {
        let mut store = StreamStore::new(100);
        let p1 = make_parsed(20000, 30000, 160);
        let p2 = make_parsed(21000, 30000, 160);
        let rtp = make_rtp_header(0xCAFE, 1);
        store.process_rtp(&p1, &rtp, ts(0));
        store.process_rtp(&p2, &rtp, ts(1));

        store.process_rtcp(&rr_for(0xCAFE, 77), chrono::Utc::now());

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
        for key in [&first, &second] {
            let r = store
                .remote_report(key)
                .unwrap_or_else(|| panic!("report missing for {key:?}"));
            // 77 RTP-ts units at 8 kHz → 9.625 ms.
            assert_eq!(r.jitter_ms, Some(9.625));
            assert_eq!(r.cumulative_lost, 3);
        }
        // And neither measurement moved.
        for (label, key) in [("first-inserted", &first), ("second-inserted", &second)] {
            assert_eq!(
                store.get(key).unwrap().lost_packets,
                0,
                "the {label} stream observed no sequence gap, so it has no loss \
                 to report whatever the far end claims"
            );
        }
    }

    /// Repeated reports about one stream update in place and count.
    #[test]
    fn repeated_reports_keep_the_latest_and_count_them() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        store.process_rtp(&p, &make_rtp_header(0xCAFE, 1), ts(0));
        let key = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        store.process_rtcp(&rr_for(0xCAFE, 8), chrono::Utc::now());
        store.process_rtcp(&rr_for(0xCAFE, 16), chrono::Utc::now());
        let r = store.remote_report(&key).expect("recorded");
        assert_eq!(r.jitter_timestamp_units, 16, "latest report wins");
        assert_eq!(r.reports_seen, 2);
    }

    /// A stream whose clock rate is assumed must not have the report's jitter
    /// dressed up as milliseconds — the conversion needs a clock rate, and
    /// there is not one.
    #[test]
    fn remote_jitter_has_no_millisecond_form_without_a_clock_rate() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        // PT 100: outside RFC 3551, no rtpmap ever seen.
        store.process_rtp(&p, &rtp_pkt(0xB0B0, 1, 100, 0), ts(0));
        let key = StreamKey {
            ssrc: 0xB0B0,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(
            store.clock_grounding(&key),
            Some(ClockGrounding::Assumed),
            "a dynamic PT with no rtpmap has no knowable clock rate"
        );
        store.process_rtcp(&rr_for(0xB0B0, 77), chrono::Utc::now());
        let r = store.remote_report(&key).expect("recorded");
        assert_eq!(r.jitter_timestamp_units, 77, "the wire value is kept");
        assert_eq!(
            r.jitter_ms, None,
            "no clock rate, no milliseconds — 9.625 would be a fabrication"
        );
    }

    /// Evicting a stream drops its provenance with it, so a later stream that
    /// reuses the same 5-tuple + SSRC does not inherit a stranger's report.
    #[test]
    fn eviction_drops_provenance() {
        let mut store = StreamStore::new(2);
        let p1 = make_parsed(20000, 30000, 160);
        store.process_rtp(&p1, &make_rtp_header(0xCAFE, 1), ts(0));
        store.process_rtcp(&rr_for(0xCAFE, 77), chrono::Utc::now());
        let key = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert!(store.remote_report(&key).is_some());

        // Two more streams evict the first (cap 2).
        store.process_rtp(
            &make_parsed(21000, 30000, 160),
            &make_rtp_header(0xBEEF, 1),
            ts(1),
        );
        store.process_rtp(
            &make_parsed(22000, 30000, 160),
            &make_rtp_header(0xF00D, 1),
            ts(2),
        );
        assert!(store.get(&key).is_none(), "evicted");
        assert!(
            store.remote_report(&key).is_none(),
            "provenance must not outlive its stream"
        );

        // Re-create the same key: it starts with no remote claim.
        store.process_rtp(&p1, &make_rtp_header(0xCAFE, 1), ts(3));
        assert!(store.remote_report(&key).is_none());
    }

    /// RFC 3551 fixes a clock rate for every assigned static payload type, and
    /// every video type in Table 5 is 90 kHz. Defaulting those to 8 kHz makes
    /// each jitter sample 11.25x too large — not an approximation, a different
    /// quantity.
    #[test]
    fn static_payload_types_get_their_rfc3551_clock_rate() {
        let cases = [
            (0u8, 8000u32), // PCMU
            (6, 16000),     // DVI4 16 kHz
            (9, 8000),      // G722 — 8 kHz RTP clock despite 16 kHz audio
            (10, 44100),    // L16
            (14, 90000),    // MPA
            (16, 11025),    // DVI4
            (17, 22050),    // DVI4
            (26, 90000),    // JPEG
            (31, 90000),    // H261
            (33, 90000),    // MP2T
            (34, 90000),    // H263
        ];
        for (i, (pt, want)) in cases.into_iter().enumerate() {
            let mut store = StreamStore::new(100);
            let port = 20000 + i as u16;
            store.process_rtp(
                &make_parsed(port, 30000, 160),
                &rtp_pkt(0x600D, 1, pt, 0),
                ts(0),
            );
            let key = StreamKey {
                ssrc: 0x600D,
                src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
            };
            assert_eq!(
                store.get(&key).unwrap().clock_rate,
                want,
                "PT {pt} is {want} Hz in RFC 3551"
            );
            assert_eq!(store.clock_grounding(&key), Some(ClockGrounding::Rfc3551));
        }
    }

    /// A payload type RFC 3551 does not assign, with no rtpmap to resolve it,
    /// has no knowable clock rate — so there is no jitter measurement to
    /// report, and `measured_jitter_ms` says so instead of returning the
    /// number the 8 kHz placeholder produced.
    #[test]
    fn jitter_is_withheld_when_the_clock_rate_is_a_guess() {
        let mut store = StreamStore::new(100);
        let parsed = make_parsed(20000, 30000, 160);
        // A 90 kHz video stream at 33 ms per frame, payload type 96, no SDP.
        for i in 0..40u32 {
            store.process_rtp(
                &parsed,
                &rtp_pkt(0x1DEA, i as u16 + 1, 96, i * 3000),
                ts_ms(i64::from(i) * 33),
            );
        }
        let key = StreamKey {
            ssrc: 0x1DEA,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(store.clock_grounding(&key), Some(ClockGrounding::Assumed));
        assert!(
            store.get(&key).unwrap().jitter > 100.0,
            "the 8 kHz placeholder inflates this stream's jitter by 11.25x — \
             the number the field still carries"
        );
        assert_eq!(
            store.measured_jitter_ms(&key),
            None,
            "with no basis for the clock rate there is no jitter measurement"
        );
    }

    /// An SDP that arrives after the media resolves the clock rate, but the
    /// jitter already folded in at the placeholder cannot be rescaled — RFC
    /// 3550's estimator is a running average with no history. The estimate is
    /// restarted, and withheld until it has re-converged rather than published
    /// as the zero it was seeded with.
    #[test]
    fn late_sdp_restarts_the_jitter_estimate_and_withholds_it_until_converged() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let port = 20000u16;
        let parsed = make_parsed(port, 30000, 160);
        let key = StreamKey {
            ssrc: 0x1DEA,
            src: SocketAddr::new(addr, port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        let mut store = StreamStore::new(100);
        for i in 0..40u32 {
            store.process_rtp(
                &parsed,
                &rtp_pkt(0x1DEA, i as u16 + 1, 96, i * 3000),
                ts_ms(i64::from(i) * 33),
            );
        }
        let stale = store.get(&key).unwrap().jitter;
        assert!(stale > 100.0, "accumulated at 8 kHz: {stale}");

        store.link_endpoint(addr, port, "late@call", &[(96, "H264".to_string(), 90000)]);
        assert_eq!(store.get(&key).unwrap().clock_rate, 90000);
        assert_eq!(store.clock_grounding(&key), Some(ClockGrounding::Rtpmap));
        assert_eq!(
            store.get(&key).unwrap().jitter,
            0.0,
            "the estimate accumulated at the wrong clock is discarded, not kept"
        );
        assert_eq!(
            store.measured_jitter_ms(&key),
            None,
            "a freshly restarted estimator has measured nothing yet — \
             publishing its zero seed would read as a perfect stream"
        );

        // Feed enough packets for the 16-sample estimator to re-converge.
        for i in 40..60u32 {
            store.process_rtp(
                &parsed,
                &rtp_pkt(0x1DEA, i as u16 + 1, 96, i * 3000),
                ts_ms(i64::from(i) * 33),
            );
        }
        let j = store
            .measured_jitter_ms(&key)
            .expect("re-converged, so reportable again");
        assert!(
            j < 5.0,
            "at the true 90 kHz clock this evenly paced stream is near-zero \
             jitter, got {j}"
        );
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

    /// Build a one-block Receiver Report targeting `ssrc` with the given
    /// jitter.
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

    /// After a stream sharing an SSRC is evicted, a report must still reach
    /// the survivor — a stale SSRC index would miss it or address a ghost.
    #[test]
    fn rtcp_after_eviction_reaches_surviving_stream() {
        let mut store = StreamStore::new(2);
        let p1 = make_parsed(20000, 30000, 160);
        let p2 = make_parsed(21000, 30000, 160);
        let p3 = make_parsed(22000, 30000, 160);
        store.process_rtp(&p1, &make_rtp_header(0xCAFE, 1), ts(0));
        store.process_rtp(&p2, &make_rtp_header(0xCAFE, 1), ts(1));
        // Third stream evicts the first (cap 2).
        store.process_rtp(&p3, &make_rtp_header(0xBEEF, 1), ts(2));
        assert_eq!(store.len(), 2);

        store.process_rtcp(&rr_for(0xCAFE, 55), chrono::Utc::now());

        let survivor = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 21000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(
            store.remote_report(&survivor).map(|r| r.jitter_ms),
            // 55 RTP-ts units at 8 kHz → 55 * 1000 / 8000 = 6.875 ms.
            Some(Some(6.875)),
            "RTCP must reach the surviving stream after eviction"
        );
    }

    /// RTCP arriving after clear() must be a safe no-op.
    #[test]
    fn rtcp_after_clear_is_noop() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        store.process_rtp(&p, &make_rtp_header(0xCAFE, 1), ts(0));
        store.clear();
        store.process_rtcp(&rr_for(0xCAFE, 11), chrono::Utc::now()); // must not panic
        assert!(store.is_empty());
    }

    /// An RTCP report for an untracked SSRC leaves existing streams
    /// untouched and records nothing.
    #[test]
    fn rtcp_unknown_ssrc_is_noop() {
        let mut store = StreamStore::new(100);
        let p = make_parsed(20000, 30000, 160);
        store.process_rtp(&p, &make_rtp_header(0xCAFE, 1), ts(0));
        store.process_rtcp(&rr_for(0xD00D, 99), chrono::Utc::now());
        let key = StreamKey {
            ssrc: 0xCAFE,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
        };
        assert_eq!(store.get(&key).unwrap().jitter, 0.0);
        assert!(store.remote_report(&key).is_none());
    }

    /// A fresh store reports empty with zero length.
    #[test]
    fn is_empty_and_len() {
        let store = StreamStore::new(100);
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    /// iter() visits every tracked stream exactly once.
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

    // -- attributing an ICMP quote to media ------------------------------

    /// The sender of the media in `make_parsed`.
    fn a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }
    /// The receiver in `make_parsed` — the one an ICMP error is about.
    fn b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    /// A store holding one stream `a:20000 -> b:30000` with SSRC `0xC0FFEE`,
    /// linked to `call-1`.
    fn store_with_one_stream() -> StreamStore {
        let mut store = StreamStore::new(100);
        store.link_endpoint(b(), 30000, "call-1", &[]);
        store.process_rtp(
            &make_parsed(20000, 30000, 160),
            &make_rtp_header(0x00C0_FFEE, 1),
            ts(0),
        );
        store
    }

    /// Tier 1: the quoted 5-tuple is exactly a tracked stream. Strongest tie
    /// available, and it names the call.
    #[test]
    fn an_exact_five_tuple_matches_the_stream_it_names() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20000),
            SocketAddr::new(b(), 30000),
            None,
        );
        assert_eq!(att.matched, MediaMatch::Flow);
        assert_eq!(att.streams, 1);
        assert_eq!(att.call_ids, vec!["call-1".to_string()]);
    }

    /// Both halves of the 5-tuple are part of the key. Two senders can be
    /// aiming at one media port — a re-INVITE, a second leg, a stray sender —
    /// and only the one whose source socket matches is the tracked flow.
    /// Matching on the destination alone would report the wrong stream, and
    /// with it the wrong call, for the other.
    #[test]
    fn a_different_sender_to_the_same_socket_is_not_the_same_flow() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            // Same destination socket, a different source port.
            SocketAddr::new(a(), 20002),
            SocketAddr::new(b(), 30000),
            None,
        );
        assert_ne!(
            att.matched,
            MediaMatch::Flow,
            "the source socket is half the key: this is not that stream's flow"
        );
        assert_eq!(att.matched, MediaMatch::Endpoint);
    }

    /// The same, the other way round: the tracked source socket aiming at a
    /// destination no stream ever used is not the tracked flow either.
    #[test]
    fn the_same_sender_to_a_different_socket_is_not_the_same_flow() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20000),
            SocketAddr::new(b(), 30002),
            None,
        );
        assert_ne!(
            att.matched,
            MediaMatch::Flow,
            "the destination socket is the other half of the key"
        );
        assert_eq!(att.matched, MediaMatch::Endpoint);
    }

    /// Direction is part of the key. A quote of the reverse datagram describes
    /// a different flow, and reporting it as the same one would claim the
    /// wrong socket failed. It still matches — both sockets belong to the same
    /// media — but at the weaker endpoint tier, which says so.
    #[test]
    fn the_reverse_direction_is_not_an_exact_flow_match() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            SocketAddr::new(b(), 30000),
            SocketAddr::new(a(), 20000),
            None,
        );
        assert_eq!(att.matched, MediaMatch::Endpoint);
    }

    /// Tier 2: RTCP runs one port above RTP, so its 5-tuple can never be a
    /// stream's. The SSRC in the quoted report is the tie that survives, and
    /// it is what carries the commonest real case.
    #[test]
    fn an_rtcp_port_pair_matches_on_ssrc_alone() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20001),
            SocketAddr::new(b(), 30001),
            Some(0x00C0_FFEE),
        );
        assert_eq!(att.matched, MediaMatch::Ssrc);
        assert_eq!(att.call_ids, vec!["call-1".to_string()]);
    }

    /// Tier 4: with no media captured at all, the SDP-advertised port one
    /// below still places an RTCP failure on the call. This is the case an
    /// operator is describing when they say the call connected silently.
    #[test]
    fn an_rtcp_port_falls_back_to_the_sdp_port_one_below() {
        let mut store = StreamStore::new(100);
        store.link_endpoint(b(), 30000, "call-2", &[]);
        assert_eq!(store.len(), 0, "an SDP link creates no stream");

        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20001),
            SocketAddr::new(b(), 30001),
            None,
        );
        assert_eq!(att.matched, MediaMatch::SdpEndpoint);
        assert_eq!(att.streams, 0, "an SDP match has no stream behind it");
        assert_eq!(att.call_ids, vec!["call-2".to_string()]);
    }

    /// The companion rule is one port up from an EVEN media port, per RFC 3550
    /// §11. Reading it as "any port, minus one" would attach an error on an
    /// even port to whatever odd port happened to be advertised below it.
    #[test]
    fn the_rtcp_companion_rule_only_applies_above_an_even_port() {
        let mut store = StreamStore::new(100);
        // An odd advertised port: nothing may be inferred one above it.
        store.link_endpoint(b(), 30001, "call-3", &[]);
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20002),
            SocketAddr::new(b(), 30002),
            None,
        );
        assert_eq!(att.matched, MediaMatch::None);
    }

    /// Nothing matched is a real answer, not a failure: the caller counts it
    /// as unattributed and still reports the endpoint.
    #[test]
    fn an_unrelated_flow_matches_nothing() {
        let store = store_with_one_stream();
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 41000),
            SocketAddr::new(b(), 51000),
            Some(0xDEAD_BEEF),
        );
        assert_eq!(att.matched, MediaMatch::None);
        assert_eq!(att.streams, 0);
        assert!(att.call_ids.is_empty());
    }

    /// A stream never linked to a dialog still matches — the flow is real —
    /// but names no call, and must not invent one.
    #[test]
    fn a_stream_without_a_dialog_matches_but_names_no_call() {
        let mut store = StreamStore::new(100);
        store.process_rtp(
            &make_parsed(20000, 30000, 160),
            &make_rtp_header(0x00C0_FFEE, 1),
            ts(0),
        );
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20000),
            SocketAddr::new(b(), 30000),
            None,
        );
        assert_eq!(att.matched, MediaMatch::Flow);
        assert_eq!(att.streams, 1);
        assert!(
            att.call_ids.is_empty(),
            "an unlinked stream has no call to name"
        );
    }

    /// An empty store matches nothing, which is the answer for a capture that
    /// holds no media — and it must not panic reaching for indexes that are
    /// empty.
    #[test]
    fn an_empty_store_matches_nothing() {
        let store = StreamStore::new(100);
        let att = store.attribute_media_quote(
            SocketAddr::new(a(), 20000),
            SocketAddr::new(b(), 30000),
            Some(1),
        );
        assert_eq!(att, MediaAttribution::default());
    }

    /// An RR carrying an SR echo yields a round trip on the stream.
    ///
    /// Latency is the third of the three numbers that decide whether a call was
    /// acceptable, and before this it was parsed out of RTCP and dropped: an
    /// operator asking "was this call acceptable?" could not answer it from
    /// sipnab at all without reading RTCP by hand.
    ///
    /// The observation time is the CAPTURE clock, not the wall clock. That is
    /// what makes the figure right on an offline pcap, where every LSR was
    /// stamped whenever the capture was taken — anchoring on `Utc::now()` would
    /// compute the age of the capture instead of the round trip.
    #[test]
    fn an_sr_echo_yields_a_round_trip_on_the_stream() {
        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};

        let mut store = StreamStore::new(10);
        let key = xr_fixture(&mut store, 0xCAFE);

        // The SR went out 250 ms before we saw this RR, and the reporter sat on
        // it for 50 ms: a 200 ms round trip, which is past G.114's guidance and
        // exactly the case an operator needs to see.
        let seen_at = ts(10);
        let sr_sent_at = seen_at - chrono::TimeDelta::milliseconds(250);
        store.process_rtcp(
            &[RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 0x9999,
                reports: vec![ReceptionReport {
                    ssrc: 0xCAFE,
                    fraction_lost: 0,
                    cumulative_lost: 0,
                    highest_seq: 100,
                    jitter: 10,
                    last_sr: crate::rtp::rtcp::compact_ntp_for_test(sr_sent_at),
                    delay_since_sr: (50.0 * 65536.0 / 1000.0) as u32,
                }],
            })],
            seen_at,
        );

        let (ms, source) = store.round_trip(&key).expect("an SR echo is a round trip");
        assert!(
            (ms - 200.0).abs() < 2.0,
            "expected ~200 ms (250 ms elapsed less 50 ms of reporter delay), got {ms}"
        );
        assert_eq!(source, RttSource::SenderReportEcho);
    }

    /// No report is NOT a round trip of zero.
    ///
    /// A stream with clean jitter, no loss and no latency figure is a stream
    /// with one unanswered question, not a healthy one. Reporting the unknown
    /// as 0 ms is how a call that is unusable on delay alone reads as fine.
    #[test]
    fn a_stream_nobody_reported_on_has_no_round_trip_rather_than_zero() {
        let mut store = StreamStore::new(10);
        let key = xr_fixture(&mut store, 0xCAFE);

        assert_eq!(store.round_trip(&key), None, "no RTCP means no measurement");

        // An RR whose reporter has seen no SR (last_sr = 0, the RFC 3550
        // sentinel) is still no measurement — it is the most common shape on
        // the wire and the easiest one to accidentally read as 0 ms.
        store.process_rtcp(&rr_for(0xCAFE, 77), ts(5));
        assert_eq!(
            store.round_trip(&key),
            None,
            "last_sr = 0 means the reporter had heard no SR, not a 0 ms path"
        );
        // Anti-vacuity: the report DID land, so this is about the round trip
        // and not about the report being dropped.
        assert!(store.remote_report(&key).is_some());
    }

    /// An endpoint's own XR figure beats one derived here.
    ///
    /// The XR number is the round trip between the two RTP interfaces — what
    /// G.114 is about. The echo derivation is anchored on the capture point and
    /// is the whole round trip only when the tap sits with the SR sender, so it
    /// loses whenever a real measurement exists.
    #[test]
    fn an_endpoints_own_xr_figure_beats_one_derived_here() {
        use crate::rtp::rtcp::{ReceiverReport, ReceptionReport};

        let mut store = StreamStore::new(10);
        let key = xr_fixture(&mut store, 0xCAFE);

        let seen_at = ts(10);
        store.process_rtcp(
            &[RtcpPacket::ReceiverReport(ReceiverReport {
                ssrc: 0x9999,
                reports: vec![ReceptionReport {
                    ssrc: 0xCAFE,
                    fraction_lost: 0,
                    cumulative_lost: 0,
                    highest_seq: 100,
                    jitter: 10,
                    last_sr: crate::rtp::rtcp::compact_ntp_for_test(
                        seen_at - chrono::TimeDelta::milliseconds(600),
                    ),
                    delay_since_sr: 0,
                }],
            })],
            seen_at,
        );
        let (echo_ms, echo_src) = store.round_trip(&key).expect("echo present");
        assert_eq!(echo_src, RttSource::SenderReportEcho);
        assert!((echo_ms - 600.0).abs() < 2.0, "got {echo_ms}");

        let mut metrics = hostile_metrics(0xCAFE);
        metrics.round_trip_delay = 90;
        store.process_rtcp(
            &[RtcpPacket::ExtendedReport(ExtendedReport {
                ssrc: 0x7777,
                blocks: vec![XrBlock::VoipMetrics(metrics)],
            })],
            seen_at,
        );

        let (ms, source) = store.round_trip(&key).expect("xr present");
        assert_eq!(source, RttSource::XrVoipMetrics);
        assert!(
            (ms - 90.0).abs() < f64::EPSILON,
            "the endpoint's own 90 ms must win over the derived 600 ms, got {ms}"
        );
    }
}
