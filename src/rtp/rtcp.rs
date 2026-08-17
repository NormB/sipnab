// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTCP packet parser (RFC 3550).
//!
//! Parses compound RTCP packets from a single UDP payload. Handles
//! Sender Reports (SR, PT=200), Receiver Reports (RR, PT=201), and
//! BYE (PT=203). An unrecognized packet *type* is preserved as
//! `RtcpPacket::Unknown` rather than dropped.
//!
//! Identification lives here too: [`looks_like_rtcp`] and
//! [`is_rtcp_packet_type`] answer "is this datagram RTCP" from its content,
//! covering the whole RFC 5761 packet-type range rather than the subset this
//! module happens to decode. Callers that instead enumerate decodable types
//! send everything else down the RTP path, where it becomes a stream that does
//! not exist.
//!
//! One class of data is dropped, however: a sub-packet whose type is known
//! but whose body fails to parse (e.g. a truncated SR) is skipped — it is
//! neither returned as its typed variant nor as `Unknown`. This is a silent
//! drop; `parse_rtcp` does not count or surface it. See [`parse_rtcp`] for the
//! per-type behavior.

use anyhow::{Result, ensure};

// ── RTCP packet types ────────────────────────────────────────────────

/// RTCP packet type: Sender Report.
const RTCP_PT_SR: u8 = 200;
/// RTCP packet type: Receiver Report.
const RTCP_PT_RR: u8 = 201;
/// RTCP packet type: BYE.
const RTCP_PT_BYE: u8 = 203;
/// RTCP Extended Report (RFC 3611).
const RTCP_PT_XR: u8 = 207;

/// Lowest packet-type byte reserved for RTCP by RFC 5761 Section 4.
pub const RTCP_PT_MIN: u8 = 192;
/// Highest packet-type byte reserved for RTCP by RFC 5761 Section 4.
pub const RTCP_PT_MAX: u8 = 223;

/// Whether `pt` is an RTCP packet-type byte.
///
/// RFC 5761 Section 4 reserves 192-223 for RTCP so that RTP and RTCP can share
/// one port: RTP payload types are chosen to avoid the range, which is why the
/// range — not the port's parity, and not the handful of types a given parser
/// happens to decode — is what identifies RTCP on the wire.
///
/// Enumerating only the types with a decoder (200-204) is a different question
/// and a costly one to confuse with this: an unrecognized *type* is still
/// RTCP, and treating it as "not RTCP" hands a control packet to the RTP path,
/// where the version bits and a payload-type byte of `pt & 0x7F` are enough for
/// it to be accepted as media and registered as a stream that does not exist.
/// XR (207), RTPFB (205) and PSFB (206) all land outside 200-204 and all fold
/// into RTP payload types 77-79.
///
/// # Examples
///
/// ```
/// use sipnab::rtp::rtcp::is_rtcp_packet_type;
///
/// assert!(is_rtcp_packet_type(200)); // SR
/// assert!(is_rtcp_packet_type(207)); // XR — RFC 3611, outside SR..APP
/// assert!(!is_rtcp_packet_type(0)); // PCMU
/// assert!(!is_rtcp_packet_type(96)); // dynamic RTP
/// ```
#[must_use]
pub fn is_rtcp_packet_type(pt: u8) -> bool {
    (RTCP_PT_MIN..=RTCP_PT_MAX).contains(&pt)
}

/// Whether a UDP payload is RTCP, judged by content alone.
///
/// Three conditions, all from RFC 3550 Section 6.1 / RFC 5761 Section 4:
/// version 2, a packet-type byte in the RTCP range (see
/// [`is_rtcp_packet_type`]), and a length field that frames the first
/// sub-packet inside the datagram. The length check is what keeps an RTP
/// packet whose marker+payload-type byte happens to land in 192-223 from being
/// swallowed — its sequence number would have to equal the datagram's word
/// count minus one.
///
/// Deliberately independent of the destination port. Port parity says where
/// RTCP is *conventionally* found (RTP+1), never what a datagram *is*, and a
/// parity test that also narrows the accepted packet types turns "arrived on
/// the RTCP port" into "not RTCP" for every type outside that list.
///
/// A header-only packet (length field 0, e.g. a BYE naming no SSRC) is not
/// recognized: it carries nothing, and accepting a 4-byte frame would make the
/// length check vacuous for RTP.
///
/// # Examples
///
/// ```
/// use sipnab::rtp::rtcp::looks_like_rtcp;
///
/// // An XR (PT=207) whose length field frames the datagram.
/// let xr = [0x80, 207, 0, 2, 1, 2, 3, 4, 4, 0, 0, 1];
/// assert!(looks_like_rtcp(&xr));
///
/// // A 12-byte PCMU RTP packet is not RTCP.
/// let rtp = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0, 0, 0x12, 0x34];
/// assert!(!looks_like_rtcp(&rtp));
/// ```
#[must_use]
pub fn looks_like_rtcp(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    if (data[0] >> 6) & 0x03 != 2 {
        return false;
    }
    if !is_rtcp_packet_type(data[1]) {
        return false;
    }
    // The header length counts 32-bit words minus one, so the first
    // sub-packet occupies `(len + 1) * 4` bytes and must fit.
    let word_len = ((data[2] as usize) << 8) | data[3] as usize;
    word_len != 0 && (word_len + 1) * 4 <= data.len()
}

// ── Public types ─────────────────────────────────────────────────────

/// A single RTCP packet within a compound RTCP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpPacket {
    /// Sender Report (PT=200).
    SenderReport(SenderReport),
    /// Receiver Report (PT=201).
    ReceiverReport(ReceiverReport),
    /// BYE (PT=203).
    Bye(RtcpBye),
    /// Extended Report (PT=207, RFC 3611).
    ExtendedReport(ExtendedReport),
    /// Unrecognized RTCP packet type, preserved for completeness.
    Unknown {
        /// The unrecognized packet type value.
        packet_type: u8,
    },
}

/// RTCP Sender Report (RFC 3550 Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    /// SSRC of the sender.
    pub ssrc: u32,
    /// NTP timestamp (64-bit wallclock time).
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to the NTP timestamp.
    pub rtp_timestamp: u32,
    /// Total number of RTP data packets sent.
    pub packet_count: u32,
    /// Total number of payload octets sent.
    pub octet_count: u32,
    /// Reception report blocks from this sender.
    pub reports: Vec<ReceptionReport>,
}

/// RTCP Receiver Report (RFC 3550 Section 6.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    /// SSRC of the receiver generating this report.
    pub ssrc: u32,
    /// Reception report blocks.
    pub reports: Vec<ReceptionReport>,
}

/// A single reception report block (shared by SR and RR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReport {
    /// SSRC of the source being reported about.
    pub ssrc: u32,
    /// Packets lost since the previous report, as an 8-bit binary fraction:
    /// the loss rate times 256, per RFC 3550 §6.4.1. This — not
    /// [`Self::cumulative_lost`] — is the field that expresses a *rate*, and
    /// even then it is the rate over the reporting interval, on the path from
    /// the source to whoever sent the report.
    pub fraction_lost: u8,
    /// Cumulative number of packets lost — a 24-bit *signed* value per
    /// RFC 3550 §6.4.1 (negative when duplicates outnumber losses),
    /// sign-extended into an `i32`.
    ///
    /// Three properties make this number dangerous to reuse as if it were a
    /// local measurement:
    ///
    /// - It counts **since the beginning of reception at the reporter**, not
    ///   since the start of a capture. A capture that joins a call mid-session
    ///   sees a count covering packets it never observed.
    /// - It describes **the reporter's path segment**. A mid-path capture (a
    ///   proxy, a SPAN port) sits on a different segment, so this is evidence
    ///   about somewhere else.
    /// - It is a **count, not a rate**. Dividing it by a locally observed
    ///   packet count mixes two populations over two different windows.
    ///
    /// RFC 3550 also defines it as *expected minus received*, where received
    /// includes late and duplicate packets — so reordering is explicitly not
    /// loss here, which a naive sequence-gap estimator does not match either.
    pub cumulative_lost: i32,
    /// Extended highest sequence number received.
    pub highest_seq: u32,
    /// Interarrival jitter estimate.
    pub jitter: u32,
    /// Last SR timestamp (middle 32 bits of NTP from last SR received).
    pub last_sr: u32,
    /// Delay since last SR in 1/65536 second units.
    pub delay_since_sr: u32,
}

/// Where a round-trip figure came from, because the two are not the same
/// measurement and an operator acting on one must know which they have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttSource {
    /// RFC 3611 XR VoIP Metrics: the reporting ENDPOINT's own round-trip
    /// figure, between the two RTP interfaces. This is the number G.114 talks
    /// about, and the only one that describes the call rather than a path
    /// segment. Rare on real traffic — most stacks never emit an XR.
    XrVoipMetrics,
    /// Derived here from an RR's `last_sr`/`delay_since_sr` per RFC 3550
    /// §6.4.1, anchored on when SIPNAB SAW the report. See
    /// [`rtt_from_sender_report_echo`] for what that does and does not measure.
    /// Available on almost every call, because plain RRs are mandatory.
    SenderReportEcho,
}

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_EPOCH_DELTA_SECS: u64 = 2_208_988_800;

/// Convert a capture timestamp to RFC 3550's compact NTP form: the middle 32
/// bits of a 64-bit NTP timestamp, which is simply the time in units of
/// 1/65536 second, truncated to 32 bits.
fn compact_ntp(at: chrono::DateTime<chrono::Utc>) -> u32 {
    let secs = at.timestamp();
    if secs < 0 {
        return 0;
    }
    let ntp_secs = (secs as u64).wrapping_add(NTP_UNIX_EPOCH_DELTA_SECS);
    let frac = (u64::from(at.timestamp_subsec_nanos()) << 16) / 1_000_000_000;
    (((ntp_secs & 0xFFFF) << 16) | (frac & 0xFFFF)) as u32
}

/// [`compact_ntp`] for tests in sibling modules, which need to build the `LSR`
/// an endpoint WOULD have stamped in order to state a round trip and read it
/// back. Hand-computing 1/65536ths in each test would be a second, unverified
/// implementation of the conversion under test.
#[doc(hidden)]
#[must_use]
pub fn compact_ntp_for_test(at: chrono::DateTime<chrono::Utc>) -> u32 {
    compact_ntp(at)
}

/// Round-trip time derived from an RR's SR echo, per RFC 3550 §6.4.1.
///
/// # What this measures, and what it does not
///
/// RFC 3550 defines the computation for the SR's SENDER: on receiving an RR it
/// computes `A - LSR - DLSR`, where `A` is the arrival time on ITS clock, and
/// gets a true round trip between the two endpoints.
///
/// sipnab is not that sender. It is a passive tap, so `A` here is when the
/// capture point saw the RR. What comes out is the time from the SR leaving
/// the sender to the RR reaching SIPNAB, minus the reporter's own delay — one
/// full leg plus one partial leg, not a clean round trip. Two consequences an
/// operator has to know:
///
/// - **It mixes two clocks.** `LSR` is stamped on the SR sender's clock; `A` is
///   the capture host's. Skew between them lands directly in the result. On a
///   tap co-located with the SR sender the two are the same clock and the
///   figure is the real round trip; the further the tap sits from that sender,
///   the more of the path it silently omits.
/// - **It is a lower bound on the endpoint-to-endpoint RTT** for any tap
///   between the two parties, because the leg from the capture point onward is
///   not in it.
///
/// Both are why the result is labeled [`RttSource::SenderReportEcho`] rather
/// than reported as "the" RTT, and why an XR figure wins when one exists.
///
/// # Returns
///
/// `None` when no round trip can be derived — which is a different fact from
/// zero and must stay different all the way to the operator:
///
/// - `last_sr == 0`: the reporter has received no SR yet, so there is nothing
///   to measure against. RFC 3550 §6.4.1 makes this explicit.
/// - The subtraction runs backwards, or exceeds [`MAX_PLAUSIBLE_RTT_MS`]. Both
///   mean the two clocks disagree by more than the quantity being measured, so
///   the arithmetic produced a number rather than a measurement.
#[must_use]
pub fn rtt_from_sender_report_echo(
    observed_at: chrono::DateTime<chrono::Utc>,
    last_sr: u32,
    delay_since_sr: u32,
) -> Option<f64> {
    if last_sr == 0 {
        return None;
    }
    // Wrapping is correct, not a shortcut: the compact form is the low 32 bits
    // of a counter that rolls over every 65536 seconds (~18 hours), and a
    // measurement spanning a rollover is still a valid small difference.
    let elapsed = compact_ntp(observed_at)
        .wrapping_sub(last_sr)
        .wrapping_sub(delay_since_sr);
    // `elapsed` is unsigned, so a "negative" round trip — an SR stamped in the
    // future, which means the two clocks disagree — does not appear as a
    // negative here. It wraps to an enormous value and is caught by the
    // plausibility bound below. That is the ONLY thing rejecting it, which is
    // why the bound is not optional tidiness.
    let ms = f64::from(elapsed) * 1000.0 / 65536.0;
    (ms <= MAX_PLAUSIBLE_RTT_MS).then_some(ms)
}

/// Above this, the figure is clock disagreement rather than network delay.
///
/// Ten seconds is far beyond any interactive call anyone would still be on —
/// G.114 calls 400 ms unacceptable — while staying well clear of the ~18-hour
/// wrap, so a genuinely awful satellite or congested path is still reported
/// rather than silently discarded.
pub const MAX_PLAUSIBLE_RTT_MS: f64 = 10_000.0;

/// RTCP BYE packet (RFC 3550 Section 6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpBye {
    /// List of SSRCs leaving the session.
    pub ssrc_list: Vec<u32>,
}

/// RTCP Extended Report (RFC 3611).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReport {
    /// SSRC of the XR originator.
    pub ssrc: u32,
    /// Report blocks.
    pub blocks: Vec<XrBlock>,
}

/// RTCP XR report block types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum XrBlock {
    /// VoIP Metrics Report Block (BT=7, RFC 3611 Section 4.7).
    VoipMetrics(VoipMetrics),
    /// Receiver Reference Time (BT=4).
    ReceiverReferenceTime {
        /// NTP timestamp (64-bit).
        ntp_timestamp: u64,
    },
    /// Loss RLE (BT=1).
    LossRle {
        /// SSRC of the source being reported.
        ssrc: u32,
        /// Raw RLE data.
        data: Vec<u8>,
    },
    /// Duplicate RLE (BT=2).
    DuplicateRle {
        /// SSRC of the source being reported.
        ssrc: u32,
        /// Raw RLE data.
        data: Vec<u8>,
    },
    /// Unknown block type.
    Unknown {
        /// The unrecognized block type value.
        block_type: u8,
    },
}

/// VoIP Metrics Report Block (RFC 3611 Section 4.7).
///
/// Every field here is the *reporting endpoint's* claim about its own
/// reception, carried on an unauthenticated datagram. None of it is a sipnab
/// measurement, and nothing in this struct feeds MOS or any other figure
/// sipnab computes — see
/// [`RemoteVoipMetrics`](crate::rtp::stream_store::RemoteVoipMetrics) for why
/// the two are kept apart.
///
/// The fields below are the wire values, byte for byte. Prefer the accessors
/// ([`Self::mos_lq`], [`Self::r_factor`], [`Self::signal_level_dbm0`], …):
/// RFC 3611 gives several of these fields a sentinel meaning "unavailable",
/// and two of them are two's-complement signed while the wire type is not.
/// Reading the raw field and formatting it publishes 127 as an R factor and
/// 12.7 as a MOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoipMetrics {
    /// SSRC of the source being reported.
    pub ssrc: u32,
    /// Fraction of RTP data packets lost (0-255).
    pub loss_rate: u8,
    /// Fraction of RTP data packets discarded (0-255).
    pub discard_rate: u8,
    /// Fraction of RTP data packets within burst periods (0-255).
    pub burst_density: u8,
    /// Fraction of RTP data packets within gap periods (0-255).
    pub gap_density: u8,
    /// Mean duration of burst periods (ms).
    pub burst_duration: u16,
    /// Mean duration of gap periods (ms).
    pub gap_duration: u16,
    /// Round trip delay (ms).
    pub round_trip_delay: u16,
    /// End system delay (ms).
    pub end_system_delay: u16,
    /// Voice signal relative level (dBm0).
    pub signal_level: u8,
    /// Noise level (dBm0).
    pub noise_level: u8,
    /// Residual echo return loss (dB).
    pub rerl: u8,
    /// Gap threshold.
    pub gmin: u8,
    /// Voice quality R factor.
    pub r_factor: u8,
    /// External R factor.
    pub ext_r_factor: u8,
    /// MOS for listening quality (x10).
    pub mos_lq: u8,
    /// MOS for conversational quality (x10).
    pub mos_cq: u8,
    /// Nominal jitter buffer delay (ms).
    pub jb_nominal: u16,
    /// Maximum jitter buffer delay (ms).
    pub jb_maximum: u16,
    /// Absolute maximum jitter buffer delay (ms).
    ///
    /// RFC 3611 Section 4.7 caps the field: "If this value exceeds 65535
    /// milliseconds, then this field SHALL convey the value 65535." So 65535
    /// is a floor, not a measurement — see [`Self::jb_abs_max_is_capped`].
    pub jb_abs_max: u16,
}

/// The value RFC 3611 Section 4.7 reserves for "this parameter is unavailable"
/// on the seven single-byte fields that define one: signal level, noise level,
/// RERL, R factor, ext. R factor, MOS-LQ and MOS-CQ.
const XR_UNAVAILABLE: u8 = 127;

/// Lowest MOS x10 RFC 3611 Section 4.7 admits ("an integer in the range 10 to
/// 50, corresponding to MOS x 10").
const XR_MOS_MIN: u8 = 10;

/// Highest MOS x10 RFC 3611 Section 4.7 admits.
const XR_MOS_MAX: u8 = 50;

/// Highest R factor RFC 3611 Section 4.7 admits (0 to 100).
const XR_R_MAX: u8 = 100;

impl VoipMetrics {
    /// [`Self::loss_rate`] as a percentage.
    ///
    /// RFC 3611 defines the field as the loss fraction "expressed as a fixed
    /// point number with the binary point at the left edge", so the divisor is
    /// 256 and not 255. No sentinel: the RFC caps the computation at 255
    /// rather than reserving a value, so every byte here is a rate.
    #[must_use]
    pub fn loss_rate_pct(&self) -> f64 {
        f64::from(self.loss_rate) * 100.0 / 256.0
    }

    /// [`Self::discard_rate`] as a percentage, on the same fixed-point scale
    /// as [`Self::loss_rate_pct`].
    ///
    /// Discards are packets that arrived and were thrown away — late, early or
    /// buffer-overflowing. They are invisible to a capture, which sees them
    /// arrive, so this is the one impairment sipnab cannot measure for itself
    /// at any vantage point.
    #[must_use]
    pub fn discard_rate_pct(&self) -> f64 {
        f64::from(self.discard_rate) * 100.0 / 256.0
    }

    /// [`Self::burst_density`] as a percentage, on the same fixed-point scale
    /// as [`Self::loss_rate_pct`].
    #[must_use]
    pub fn burst_density_pct(&self) -> f64 {
        f64::from(self.burst_density) * 100.0 / 256.0
    }

    /// [`Self::gap_density`] as a percentage, on the same fixed-point scale as
    /// [`Self::loss_rate_pct`].
    #[must_use]
    pub fn gap_density_pct(&self) -> f64 {
        f64::from(self.gap_density) * 100.0 / 256.0
    }

    /// Voice quality R factor, or `None` when the endpoint marked it
    /// unavailable.
    ///
    /// RFC 3611 puts the R factor in 0 to 100 and reserves 127 for "this
    /// parameter is unavailable". Anything above 100 is outside the scale, so
    /// it is reported as absent rather than as a very good call.
    #[must_use]
    pub fn r_factor(&self) -> Option<u8> {
        (self.r_factor <= XR_R_MAX).then_some(self.r_factor)
    }

    /// External R factor — the R factor for the network segment *beyond* the
    /// reporting endpoint — or `None` when marked unavailable.
    #[must_use]
    pub fn ext_r_factor(&self) -> Option<u8> {
        (self.ext_r_factor <= XR_R_MAX).then_some(self.ext_r_factor)
    }

    /// Listening-quality MOS on the 1.0 to 5.0 scale, or `None` when the
    /// endpoint marked it unavailable.
    ///
    /// RFC 3611 carries it as "an integer in the range 10 to 50, corresponding
    /// to MOS x 10", with 127 meaning unavailable. Both the sentinel and any
    /// other out-of-range byte give `None`: a 0 in this field is an endpoint
    /// that never scored the call, and publishing it as a MOS of 0.0 would put
    /// a worse-than-worst-case score beside a healthy stream.
    #[must_use]
    pub fn mos_lq(&self) -> Option<f64> {
        Self::decode_mos(self.mos_lq)
    }

    /// Conversational-quality MOS on the 1.0 to 5.0 scale, or `None` when the
    /// endpoint marked it unavailable. Unlike [`Self::mos_lq`] this one folds
    /// in round-trip delay, so it is the number that moves when a call is
    /// clear but hard to hold a conversation on.
    #[must_use]
    pub fn mos_cq(&self) -> Option<f64> {
        Self::decode_mos(self.mos_cq)
    }

    /// Shared MOS-x10 decode for [`Self::mos_lq`] and [`Self::mos_cq`], so the
    /// two cannot drift apart on the range check.
    fn decode_mos(raw: u8) -> Option<f64> {
        (XR_MOS_MIN..=XR_MOS_MAX)
            .contains(&raw)
            .then(|| f64::from(raw) / 10.0)
    }

    /// Voice signal relative level in dBm0, or `None` when marked unavailable.
    ///
    /// RFC 3611 carries this as a "signed integer in two's complement form"
    /// over a range of 0 to -127 dBm0, so reading the wire byte as the `u8` it
    /// is declared as turns every real speech level into a number in the 130s.
    #[must_use]
    pub fn signal_level_dbm0(&self) -> Option<i8> {
        (self.signal_level != XR_UNAVAILABLE).then_some(self.signal_level as i8)
    }

    /// Noise level in dBm0, or `None` when marked unavailable. Two's
    /// complement on the wire, exactly as [`Self::signal_level_dbm0`].
    #[must_use]
    pub fn noise_level_dbm0(&self) -> Option<i8> {
        (self.noise_level != XR_UNAVAILABLE).then_some(self.noise_level as i8)
    }

    /// Residual echo return loss in dB, or `None` when marked unavailable.
    #[must_use]
    pub fn rerl_db(&self) -> Option<u8> {
        (self.rerl != XR_UNAVAILABLE).then_some(self.rerl)
    }

    /// Whether [`Self::jb_abs_max`] hit the field's ceiling, in which case the
    /// real absolute maximum is 65535 ms *or more* and the number is a floor.
    #[must_use]
    pub fn jb_abs_max_is_capped(&self) -> bool {
        self.jb_abs_max == u16::MAX
    }
}

// ── Parser ───────────────────────────────────────────────────────────

/// Minimum RTCP packet header: version/padding/count(1) + PT(1) + length(2).
const RTCP_HEADER_LEN: usize = 4;

/// Parse a compound RTCP payload into individual packets.
///
/// RTCP packets are compound: a single UDP datagram may contain multiple
/// RTCP packets concatenated back-to-back. This function iterates through
/// the payload, parsing each sub-packet. Malformed trailing bytes are
/// silently skipped (real-world RTCP sometimes has padding).
///
/// # Arguments
///
/// * `data` — the full UDP payload, network (big-endian) byte order.
///
/// # Returns
///
/// The successfully parsed packets in wire order. Unrecognized packet
/// types become `RtcpPacket::Unknown`; a sub-packet of a known type whose
/// body fails to parse is skipped. Iteration stops at the first non-v2 or
/// truncated packet. Returns an empty `Vec` if no valid RTCP packets are
/// found. Pure function — no side effects.
pub fn parse_rtcp(data: &[u8]) -> Vec<RtcpPacket> {
    let mut packets = Vec::new();
    let mut offset = 0;

    while offset + RTCP_HEADER_LEN <= data.len() {
        let byte0 = data[offset];
        let version = (byte0 >> 6) & 0x03;
        if version != 2 {
            break; // Not RTCP or corrupt — stop iteration
        }
        let count = (byte0 & 0x1F) as usize;
        let packet_type = data[offset + 1];
        let length_field = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let packet_len = (length_field + 1) * 4; // length is in 32-bit words minus one

        if offset + packet_len > data.len() {
            break; // Truncated — stop
        }

        let pkt_data = &data[offset..offset + packet_len];

        match packet_type {
            RTCP_PT_SR => {
                if let Ok(sr) = parse_sender_report(pkt_data, count) {
                    packets.push(RtcpPacket::SenderReport(sr));
                }
            }
            RTCP_PT_RR => {
                if let Ok(rr) = parse_receiver_report(pkt_data, count) {
                    packets.push(RtcpPacket::ReceiverReport(rr));
                }
            }
            RTCP_PT_BYE => {
                if let Ok(bye) = parse_bye(pkt_data, count) {
                    packets.push(RtcpPacket::Bye(bye));
                }
            }
            RTCP_PT_XR => {
                if let Ok(xr) = parse_extended_report(pkt_data) {
                    packets.push(RtcpPacket::ExtendedReport(xr));
                }
            }
            _ => {
                packets.push(RtcpPacket::Unknown { packet_type });
            }
        }

        offset += packet_len;
    }

    packets
}

/// Parse reception report blocks starting at the given offset.
///
/// # Arguments
///
/// * `data` — the full RTCP sub-packet bytes (big-endian fields).
/// * `offset` — byte offset of the first 24-byte report block.
/// * `count` — number of blocks to read (the header RC field).
///
/// # Returns
///
/// The parsed blocks in wire order (empty when `count` is 0).
///
/// # Errors
///
/// Fails if `data` ends before `count` full 24-byte blocks.
fn parse_report_blocks(data: &[u8], offset: usize, count: usize) -> Result<Vec<ReceptionReport>> {
    let mut reports = Vec::with_capacity(count);
    let mut pos = offset;

    for _ in 0..count {
        ensure!(
            pos + 24 <= data.len(),
            "Reception report block truncated at offset {pos}"
        );

        let ssrc = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let fraction_lost = data[pos + 4];
        // Cumulative lost is 24-bit signed, stored in bytes 5..8. Place the
        // 24-bit value in the high bits then arithmetic-shift back down so the
        // sign bit (bit 23) is extended into a proper negative i32.
        let raw24 = u32::from_be_bytes([0, data[pos + 5], data[pos + 6], data[pos + 7]]);
        let cumulative_lost = ((raw24 << 8) as i32) >> 8;
        let highest_seq =
            u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
        let jitter = u32::from_be_bytes([
            data[pos + 12],
            data[pos + 13],
            data[pos + 14],
            data[pos + 15],
        ]);
        let last_sr = u32::from_be_bytes([
            data[pos + 16],
            data[pos + 17],
            data[pos + 18],
            data[pos + 19],
        ]);
        let delay_since_sr = u32::from_be_bytes([
            data[pos + 20],
            data[pos + 21],
            data[pos + 22],
            data[pos + 23],
        ]);

        reports.push(ReceptionReport {
            ssrc,
            fraction_lost,
            cumulative_lost,
            highest_seq,
            jitter,
            last_sr,
            delay_since_sr,
        });

        pos += 24;
    }

    Ok(reports)
}

/// Parse Sender Report body (after the 4-byte RTCP header).
///
/// # Arguments
///
/// * `data` — the full SR packet including its 4-byte header.
/// * `report_count` — reception report block count from the header RC
///   field.
///
/// # Returns
///
/// The parsed `SenderReport` with the 64-bit NTP timestamp reassembled
/// from its two big-endian words.
///
/// # Errors
///
/// Fails if `data` is shorter than the 28-byte sender info plus
/// `report_count` 24-byte blocks.
fn parse_sender_report(data: &[u8], report_count: usize) -> Result<SenderReport> {
    // SR: 4 header + 4 SSRC + 20 sender info + N*24 report blocks
    let min_len = 4 + 4 + 20 + report_count * 24;
    ensure!(
        data.len() >= min_len,
        "SR too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ntp_hi = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let ntp_lo = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let ntp_timestamp = ((ntp_hi as u64) << 32) | (ntp_lo as u64);
    let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

    let reports = parse_report_blocks(data, 28, report_count)?;

    Ok(SenderReport {
        ssrc,
        ntp_timestamp,
        rtp_timestamp,
        packet_count,
        octet_count,
        reports,
    })
}

/// Parse Receiver Report body (after the 4-byte RTCP header).
///
/// # Arguments
///
/// * `data` — the full RR packet including its 4-byte header.
/// * `report_count` — reception report block count from the header RC
///   field.
///
/// # Returns
///
/// The parsed `ReceiverReport` (reporter SSRC plus its blocks).
///
/// # Errors
///
/// Fails if `data` is shorter than the 8-byte prefix plus `report_count`
/// 24-byte blocks.
fn parse_receiver_report(data: &[u8], report_count: usize) -> Result<ReceiverReport> {
    // RR: 4 header + 4 SSRC + N*24 report blocks
    let min_len = 4 + 4 + report_count * 24;
    ensure!(
        data.len() >= min_len,
        "RR too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let reports = parse_report_blocks(data, 8, report_count)?;

    Ok(ReceiverReport { ssrc, reports })
}

/// Parse BYE packet body (after the 4-byte RTCP header).
///
/// # Arguments
///
/// * `data` — the full BYE packet including its 4-byte header.
/// * `ssrc_count` — number of departing SSRCs (the header SC field).
///
/// # Returns
///
/// The parsed `RtcpBye`. Any optional trailing reason text is ignored.
///
/// # Errors
///
/// Fails if `data` is shorter than the header plus `ssrc_count` 4-byte
/// SSRC entries.
fn parse_bye(data: &[u8], ssrc_count: usize) -> Result<RtcpBye> {
    let min_len = 4 + ssrc_count * 4;
    ensure!(
        data.len() >= min_len,
        "BYE too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let mut ssrc_list = Vec::with_capacity(ssrc_count);
    for i in 0..ssrc_count {
        let pos = 4 + i * 4;
        let ssrc = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        ssrc_list.push(ssrc);
    }

    Ok(RtcpBye { ssrc_list })
}

/// Parse Extended Report body (RFC 3611).
///
/// Walks the XR report blocks after the 8-byte header, decoding VoIP
/// Metrics (BT=7), Receiver Reference Time (BT=4), and Loss/Duplicate RLE
/// (BT=1/2); anything else — including a block whose body fails its own
/// parse — is preserved as `XrBlock::Unknown`. Iteration stops at the
/// first truncated block.
///
/// # Arguments
///
/// * `data` — the full XR packet including its 4-byte header (big-endian
///   fields).
///
/// # Returns
///
/// The originator SSRC and the decoded blocks in wire order.
///
/// # Errors
///
/// Fails only if `data` is shorter than the 8 bytes needed for the header
/// and originator SSRC.
fn parse_extended_report(data: &[u8]) -> Result<ExtendedReport> {
    ensure!(data.len() >= 8, "XR too short: {} bytes", data.len());

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let mut blocks = Vec::new();
    let mut pos = 8;

    while pos + 4 <= data.len() {
        let block_type = data[pos];
        let block_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize * 4;

        if pos + 4 + block_length > data.len() {
            break;
        }

        let block_data = &data[pos + 4..pos + 4 + block_length];

        let block = match block_type {
            7 if block_length >= 32 => match parse_voip_metrics(block_data) {
                Ok(vm) => XrBlock::VoipMetrics(vm),
                Err(_) => XrBlock::Unknown { block_type },
            },
            4 if block_length >= 8 => {
                let ntp = u64::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                    block_data[4],
                    block_data[5],
                    block_data[6],
                    block_data[7],
                ]);
                XrBlock::ReceiverReferenceTime { ntp_timestamp: ntp }
            }
            1 if block_length >= 4 => {
                let rle_ssrc = u32::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                ]);
                XrBlock::LossRle {
                    ssrc: rle_ssrc,
                    data: block_data[4..].to_vec(),
                }
            }
            2 if block_length >= 4 => {
                let rle_ssrc = u32::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                ]);
                XrBlock::DuplicateRle {
                    ssrc: rle_ssrc,
                    data: block_data[4..].to_vec(),
                }
            }
            _ => XrBlock::Unknown { block_type },
        };

        blocks.push(block);
        pos += 4 + block_length;
    }

    Ok(ExtendedReport { ssrc, blocks })
}

/// Parse VoIP Metrics report block data (RFC 3611 Section 4.7).
///
/// # Arguments
///
/// * `data` — the block body (after the 4-byte block header), big-endian
///   multi-byte fields.
///
/// # Returns
///
/// The fully decoded `VoipMetrics` block.
///
/// # Errors
///
/// Fails if `data` is shorter than the 32-byte block body.
fn parse_voip_metrics(data: &[u8]) -> Result<VoipMetrics> {
    ensure!(
        data.len() >= 32,
        "VoIP Metrics block too short: {} bytes",
        data.len()
    );
    Ok(VoipMetrics {
        ssrc: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        loss_rate: data[4],
        discard_rate: data[5],
        burst_density: data[6],
        gap_density: data[7],
        burst_duration: u16::from_be_bytes([data[8], data[9]]),
        gap_duration: u16::from_be_bytes([data[10], data[11]]),
        round_trip_delay: u16::from_be_bytes([data[12], data[13]]),
        end_system_delay: u16::from_be_bytes([data[14], data[15]]),
        signal_level: data[16],
        noise_level: data[17],
        rerl: data[18],
        gmin: data[19],
        r_factor: data[20],
        ext_r_factor: data[21],
        mos_lq: data[22],
        mos_cq: data[23],
        jb_nominal: u16::from_be_bytes([data[24], data[25]]),
        jb_maximum: u16::from_be_bytes([data[26], data[27]]),
        jb_abs_max: u16::from_be_bytes([data[28], data[29]]),
    })
}

/// Unit tests for compound RTCP parsing: SR/RR/BYE/XR decoding, unknown
/// packet-type preservation, and truncation handling.
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Sender Report RTCP packet.
    fn build_sr(ssrc: u32, ntp: u64, rtp_ts: u32, pkt_count: u32, oct_count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        // Header: V=2, P=0, RC=0, PT=200
        data.push(0x80); // V=2, P=0, RC=0
        data.push(200); // PT=SR
        // Length: (28 - 4) / 4 = 6
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&ssrc.to_be_bytes());
        data.extend_from_slice(&((ntp >> 32) as u32).to_be_bytes());
        data.extend_from_slice(&((ntp & 0xFFFFFFFF) as u32).to_be_bytes());
        data.extend_from_slice(&rtp_ts.to_be_bytes());
        data.extend_from_slice(&pkt_count.to_be_bytes());
        data.extend_from_slice(&oct_count.to_be_bytes());
        data
    }

    /// Build a Receiver Report RTCP packet with one report block.
    fn build_rr_with_report(
        reporter_ssrc: u32,
        source_ssrc: u32,
        fraction_lost: u8,
        jitter: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        // Header: V=2, P=0, RC=1, PT=201
        data.push(0x81); // V=2, P=0, RC=1
        data.push(201); // PT=RR
        // Length: (8 + 24 - 4) / 4 = 7
        data.extend_from_slice(&7u16.to_be_bytes());
        data.extend_from_slice(&reporter_ssrc.to_be_bytes());
        // Report block
        data.extend_from_slice(&source_ssrc.to_be_bytes());
        data.push(fraction_lost);
        data.extend_from_slice(&[0x00, 0x00, 0x05]); // cumulative lost = 5
        data.extend_from_slice(&1000u32.to_be_bytes()); // highest seq
        data.extend_from_slice(&jitter.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // last SR
        data.extend_from_slice(&0u32.to_be_bytes()); // delay since SR
        data
    }

    /// Build a BYE RTCP packet.
    fn build_bye(ssrcs: &[u32]) -> Vec<u8> {
        let mut data = Vec::new();
        let rc = ssrcs.len() as u8;
        data.push(0x80 | rc); // V=2, P=0, RC
        data.push(203); // PT=BYE
        let length = ssrcs.len() as u16; // (4 + N*4 - 4) / 4 = N
        data.extend_from_slice(&length.to_be_bytes());
        for ssrc in ssrcs {
            data.extend_from_slice(&ssrc.to_be_bytes());
        }
        data
    }

    /// A minimal SR decodes SSRC, NTP/RTP timestamps, and counters with no
    /// report blocks.
    #[test]
    fn parse_sender_report_basic() {
        let data = build_sr(0xAABBCCDD, 0x1122334455667788, 160000, 100, 16000);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::SenderReport(sr) => {
                assert_eq!(sr.ssrc, 0xAABBCCDD);
                assert_eq!(sr.ntp_timestamp, 0x1122334455667788);
                assert_eq!(sr.rtp_timestamp, 160000);
                assert_eq!(sr.packet_count, 100);
                assert_eq!(sr.octet_count, 16000);
                assert!(sr.reports.is_empty());
            }
            other => panic!("Expected SenderReport, got {other:?}"),
        }
    }

    /// An RR with one reception report block decodes every block field.
    #[test]
    fn parse_receiver_report_with_block() {
        let data = build_rr_with_report(0x11111111, 0x22222222, 25, 320);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::ReceiverReport(rr) => {
                assert_eq!(rr.ssrc, 0x11111111);
                assert_eq!(rr.reports.len(), 1);
                let r = &rr.reports[0];
                assert_eq!(r.ssrc, 0x22222222);
                assert_eq!(r.fraction_lost, 25);
                assert_eq!(r.jitter, 320);
                assert_eq!(r.cumulative_lost, 5);
                assert_eq!(r.highest_seq, 1000);
            }
            other => panic!("Expected ReceiverReport, got {other:?}"),
        }
    }

    /// A 24-bit cumulative-lost field with its sign bit set (net duplicates)
    /// decodes as a negative `i32` per RFC 3550, not a huge positive count
    /// from zero-extension.
    #[test]
    fn parse_report_block_negative_cumulative_lost() {
        let mut data = Vec::new();
        data.push(0x81); // V=2, P=0, RC=1
        data.push(201); // PT=RR
        data.extend_from_slice(&7u16.to_be_bytes());
        data.extend_from_slice(&0x1111_1111u32.to_be_bytes()); // reporter SSRC
        // Report block
        data.extend_from_slice(&0x2222_2222u32.to_be_bytes()); // source SSRC
        data.push(0); // fraction lost
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // cumulative lost = -1 (24-bit signed)
        data.extend_from_slice(&1000u32.to_be_bytes()); // highest seq
        data.extend_from_slice(&0u32.to_be_bytes()); // jitter
        data.extend_from_slice(&0u32.to_be_bytes()); // last SR
        data.extend_from_slice(&0u32.to_be_bytes()); // delay since SR

        let packets = parse_rtcp(&data);
        match &packets[0] {
            RtcpPacket::ReceiverReport(rr) => {
                assert_eq!(
                    rr.reports[0].cumulative_lost, -1,
                    "0xFFFFFF must sign-extend to -1, not 16777215"
                );
            }
            other => panic!("expected ReceiverReport, got {other:?}"),
        }
    }

    /// A BYE listing two SSRCs yields both in order.
    #[test]
    fn parse_bye_multiple_ssrcs() {
        let data = build_bye(&[0xAAAAAAAA, 0xBBBBBBBB]);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::Bye(bye) => {
                assert_eq!(bye.ssrc_list, vec![0xAAAAAAAA, 0xBBBBBBBB]);
            }
            other => panic!("Expected Bye, got {other:?}"),
        }
    }

    /// A compound datagram (SR followed by RR) parses into two packets in
    /// wire order.
    #[test]
    fn parse_compound_sr_plus_rr() {
        let mut data = build_sr(0x10, 0, 0, 50, 8000);
        data.extend_from_slice(&build_rr_with_report(0x20, 0x10, 10, 100));
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 2);

        assert!(matches!(&packets[0], RtcpPacket::SenderReport(_)));
        assert!(matches!(&packets[1], RtcpPacket::ReceiverReport(_)));
    }

    /// An empty payload yields an empty packet list.
    #[test]
    fn empty_data_returns_empty() {
        let packets = parse_rtcp(&[]);
        assert!(packets.is_empty());
    }

    /// A header whose declared length exceeds the data stops parsing
    /// without panicking or emitting a packet.
    #[test]
    fn truncated_packet_stops_cleanly() {
        // Valid SR header but truncated body
        let data = [0x80, 200, 0x00, 0x06, 0x00]; // Length says 28 bytes but only 5
        let packets = parse_rtcp(&data);
        assert!(packets.is_empty());
    }

    /// An unrecognized packet type (210) is preserved as
    /// `RtcpPacket::Unknown`, not dropped.
    #[test]
    fn unknown_packet_type_preserved() {
        let mut data = Vec::new();
        data.push(0x80); // V=2
        data.push(210); // Unknown PT
        data.extend_from_slice(&0u16.to_be_bytes()); // length=0 → 4 bytes total
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);
        assert!(matches!(
            &packets[0],
            RtcpPacket::Unknown { packet_type: 210 }
        ));
    }

    /// A VoIP Metrics block with every field set to a plain in-range value,
    /// for the accessor tests to mutate one field at a time.
    fn plain_metrics() -> VoipMetrics {
        VoipMetrics {
            ssrc: 1,
            loss_rate: 0,
            discard_rate: 0,
            burst_density: 0,
            gap_density: 0,
            burst_duration: 0,
            gap_duration: 0,
            round_trip_delay: 0,
            end_system_delay: 0,
            signal_level: 0,
            noise_level: 0,
            rerl: 0,
            gmin: 16,
            r_factor: 90,
            ext_r_factor: 90,
            mos_lq: 40,
            mos_cq: 40,
            jb_nominal: 0,
            jb_maximum: 0,
            jb_abs_max: 0,
        }
    }

    /// The four fixed-point fraction fields divide by 256, not 255: RFC 3611
    /// puts the binary point at the left edge of the byte. Dividing by 255
    /// would report 100% for a value that means 99.6%.
    #[test]
    fn xr_fraction_fields_use_the_binary_point_scale() {
        let mut m = plain_metrics();
        m.loss_rate = 128;
        m.discard_rate = 64;
        m.burst_density = 32;
        m.gap_density = 255;
        assert!((m.loss_rate_pct() - 50.0).abs() < 1e-9);
        assert!((m.discard_rate_pct() - 25.0).abs() < 1e-9);
        assert!((m.burst_density_pct() - 12.5).abs() < 1e-9);
        assert!(
            m.gap_density_pct() < 100.0,
            "255/256 is not 100%: {}",
            m.gap_density_pct()
        );
    }

    /// 127 is RFC 3611's "this parameter is unavailable" on all seven
    /// single-byte fields that define it. Publishing it raw puts an R factor
    /// of 127 and a MOS of 12.7 on screen, both off their own scales.
    #[test]
    fn xr_unavailable_sentinel_reads_as_absent() {
        let mut m = plain_metrics();
        m.r_factor = 127;
        m.ext_r_factor = 127;
        m.mos_lq = 127;
        m.mos_cq = 127;
        m.signal_level = 127;
        m.noise_level = 127;
        m.rerl = 127;
        assert_eq!(m.r_factor(), None);
        assert_eq!(m.ext_r_factor(), None);
        assert_eq!(m.mos_lq(), None);
        assert_eq!(m.mos_cq(), None);
        assert_eq!(m.signal_level_dbm0(), None);
        assert_eq!(m.noise_level_dbm0(), None);
        assert_eq!(m.rerl_db(), None);
    }

    /// MOS is carried as MOS x 10 over 10..=50. A byte outside that range is
    /// not a low MOS, it is not a MOS — an endpoint that never scored the call
    /// commonly sends 0, and rendering that as 0.0 puts a below-floor score
    /// beside a healthy stream.
    #[test]
    fn xr_mos_outside_the_rfc_range_is_absent() {
        let mut m = plain_metrics();
        m.mos_lq = 0;
        m.mos_cq = 51;
        assert_eq!(m.mos_lq(), None, "0 is below the RFC 3611 floor of 10");
        assert_eq!(m.mos_cq(), None, "51 is above the RFC 3611 ceiling of 50");

        m.mos_lq = XR_MOS_MIN;
        m.mos_cq = XR_MOS_MAX;
        assert_eq!(m.mos_lq(), Some(1.0), "the range is inclusive at the floor");
        assert_eq!(
            m.mos_cq(),
            Some(5.0),
            "the range is inclusive at the ceiling"
        );
    }

    /// R factor runs 0 to 100. 101 through 126 are off the scale and are
    /// reported absent rather than as a better-than-perfect call.
    #[test]
    fn xr_r_factor_above_the_scale_is_absent() {
        let mut m = plain_metrics();
        m.r_factor = 100;
        m.ext_r_factor = 101;
        assert_eq!(m.r_factor(), Some(100), "100 is the top of the scale");
        assert_eq!(m.ext_r_factor(), None, "101 is off the scale");
    }

    /// Signal and noise levels are two's complement on the wire, over 0 to
    /// -127 dBm0. Read as the declared `u8` a normal speech level of -20 dBm0
    /// prints as 236.
    #[test]
    fn xr_levels_decode_as_twos_complement() {
        let mut m = plain_metrics();
        m.signal_level = 0xEC; // -20 dBm0
        m.noise_level = 0xB0; // -80 dBm0
        assert_eq!(m.signal_level_dbm0(), Some(-20));
        assert_eq!(m.noise_level_dbm0(), Some(-80));
    }

    /// RFC 3611 clamps `jb_abs_max` at 65535, so that value is a floor rather
    /// than a measurement and must be flagged as such.
    #[test]
    fn xr_jb_abs_max_ceiling_is_flagged() {
        let mut m = plain_metrics();
        m.jb_abs_max = 65_534;
        assert!(!m.jb_abs_max_is_capped());
        m.jb_abs_max = 65_535;
        assert!(m.jb_abs_max_is_capped());
    }

    /// An XR carrying a VoIP Metrics block (BT=7) decodes its SSRC and
    /// quality fields.
    #[test]
    fn parse_xr_voip_metrics() {
        // Build a minimal XR packet with VoIP Metrics block
        let mut data = Vec::new();
        // RTCP header: V=2, P=0, reserved=0, PT=207, length=10 (44 bytes total)
        data.push(0x80); // V=2, P=0, count=0
        data.push(207); // PT=XR
        data.extend_from_slice(&10u16.to_be_bytes()); // length in 32-bit words minus 1
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // SSRC

        // XR block: BT=7 (VoIP Metrics), type-specific=0, length=8 (32 bytes)
        data.push(7); // block type
        data.push(0); // type-specific
        data.extend_from_slice(&8u16.to_be_bytes()); // block length in 32-bit words

        // VoIP Metrics data (32 bytes)
        data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // SSRC
        data.push(10); // loss_rate
        data.push(5); // discard_rate
        data.push(20); // burst_density
        data.push(15); // gap_density
        data.extend_from_slice(&100u16.to_be_bytes()); // burst_duration
        data.extend_from_slice(&200u16.to_be_bytes()); // gap_duration
        data.extend_from_slice(&50u16.to_be_bytes()); // round_trip_delay
        data.extend_from_slice(&25u16.to_be_bytes()); // end_system_delay
        data.push(128); // signal_level
        data.push(64); // noise_level
        data.push(32); // rerl
        data.push(16); // gmin
        data.push(80); // r_factor
        data.push(70); // ext_r_factor
        data.push(35); // mos_lq
        data.push(40); // mos_cq
        data.extend_from_slice(&60u16.to_be_bytes()); // jb_nominal
        data.extend_from_slice(&80u16.to_be_bytes()); // jb_maximum
        data.extend_from_slice(&120u16.to_be_bytes()); // jb_abs_max
        // Pad to full block (30 bytes of metrics data + 2 padding = 32)
        data.extend_from_slice(&[0, 0]);

        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);
        match &packets[0] {
            RtcpPacket::ExtendedReport(xr) => {
                assert_eq!(xr.ssrc, 0x12345678);
                assert_eq!(xr.blocks.len(), 1);
                match &xr.blocks[0] {
                    XrBlock::VoipMetrics(vm) => {
                        assert_eq!(vm.ssrc, 0xAABBCCDD);
                        assert_eq!(vm.loss_rate, 10);
                        assert_eq!(vm.r_factor, 80);
                        assert_eq!(vm.mos_lq, 35);
                    }
                    other => panic!("Expected VoipMetrics, got {:?}", other),
                }
            }
            other => panic!("Expected ExtendedReport, got {:?}", other),
        }
    }

    /// Every RTCP packet type sipnab can meet must be recognized as RTCP,
    /// including the ones it has no decoder for.
    ///
    /// The XR case is the one that bit: 207 sits outside SR..APP (200-204),
    /// so a classifier enumerating only decodable types calls it "not RTCP",
    /// and `207 & 0x7F` is RTP payload type 79 — a real media stream that
    /// never existed.
    #[test]
    fn rtcp_types_outside_sr_to_app_are_still_rtcp() {
        for pt in [200u8, 201, 202, 203, 204, 205, 206, 207, 210, 213] {
            assert!(
                is_rtcp_packet_type(pt),
                "RTCP packet type {pt} must be recognized as RTCP; as RTP it \
                 would read as payload type {}",
                pt & 0x7F
            );
        }
        assert!(is_rtcp_packet_type(RTCP_PT_MIN));
        assert!(is_rtcp_packet_type(RTCP_PT_MAX));
        // RTP payload types must stay out.
        for pt in [0u8, 8, 9, 18, 34, 96, 111, 127, 191, 224, 255] {
            assert!(!is_rtcp_packet_type(pt), "{pt} is not an RTCP packet type");
        }
    }

    /// The content test recognizes a real XR datagram — the byte shape that
    /// appears on the conventional odd RTCP port in captured traffic — and
    /// rejects RTP.
    #[test]
    fn looks_like_rtcp_accepts_xr_and_rejects_rtp() {
        // V=2, PT=207 (XR), length=0xF8 words → (0xF8 + 1) * 4 = 996 bytes,
        // then the originator SSRC and a Receiver Reference Time block
        // (BT=4, length 2). Framed exactly like the real thing.
        let mut xr = vec![0x80, 207, 0x00, 0xF8];
        xr.extend_from_slice(&0x44B6_2E0Au32.to_be_bytes());
        xr.extend_from_slice(&[4, 0, 0, 2]);
        xr.resize(1000, 0);
        assert!(
            looks_like_rtcp(&xr),
            "an XR that frames its own datagram is RTCP"
        );
        // Read as RTP this is payload type 79 with SSRC 0x04000002 — the
        // phantom stream this test exists to prevent.
        assert_eq!(xr[1] & 0x7F, 79);

        // A 12-byte PCMU packet: version 2, but PT 0 is not in the RTCP range.
        let rtp = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0, 0, 0x12, 0x34];
        assert!(!looks_like_rtcp(&rtp));

        // An RTP packet with the marker bit set and payload type 79 puts 207
        // in byte 1; the length field (its sequence number) must not frame it.
        let mut muxed_rtp = vec![0x80, 207];
        muxed_rtp.extend_from_slice(&40_000u16.to_be_bytes()); // sequence
        muxed_rtp.extend_from_slice(&[0u8; 168]);
        assert!(
            !looks_like_rtcp(&muxed_rtp),
            "the length check must reject RTP whose byte 1 lands in the RTCP range"
        );
    }

    /// Compound RTCP is recognized from its first sub-packet, and short or
    /// wrong-version input is not.
    #[test]
    fn looks_like_rtcp_edges() {
        let mut compound = build_sr(0x10, 0, 0, 50, 8000);
        compound.extend_from_slice(&build_rr_with_report(0x20, 0x10, 10, 100));
        assert!(looks_like_rtcp(&compound));
        assert!(looks_like_rtcp(&build_rr_with_report(1, 2, 0, 0)));
        assert!(looks_like_rtcp(&build_bye(&[0xAAAA_AAAA])));

        assert!(!looks_like_rtcp(&[]));
        assert!(!looks_like_rtcp(&[0x80, 200, 0, 1]), "4 bytes is too short");
        // Version 1.
        assert!(!looks_like_rtcp(&[0x40, 200, 0, 1, 0, 0, 0, 1]));
        // Length field claims 28 bytes but only 8 are present.
        assert!(!looks_like_rtcp(&[0x80, 200, 0, 6, 0, 0, 0, 1]));
        // Header-only (length field 0) carries nothing.
        assert!(!looks_like_rtcp(&[0x80, 203, 0, 0, 0, 0, 0, 0]));
    }

    /// An XR arriving as the FIRST sub-packet of a datagram parses into its
    /// blocks. This is the payload shape that the port-parity classifier
    /// dropped: a compound starting with SR is recognized, one starting with
    /// XR was not, so the metrics were lost as well as misfiled.
    #[test]
    fn xr_first_in_datagram_parses() {
        let mut data = vec![0x80, 207];
        data.extend_from_slice(&4u16.to_be_bytes()); // (4 + 1) * 4 = 20 bytes
        data.extend_from_slice(&0x44B6_2E0Au32.to_be_bytes()); // originator
        data.extend_from_slice(&[4, 0, 0, 2]); // BT=4, 2 words
        data.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        assert!(looks_like_rtcp(&data));

        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1, "got {packets:?}");
        match &packets[0] {
            RtcpPacket::ExtendedReport(xr) => {
                assert_eq!(xr.ssrc, 0x44B6_2E0A);
                assert_eq!(
                    xr.blocks,
                    vec![XrBlock::ReceiverReferenceTime {
                        ntp_timestamp: 0x1122_3344_5566_7788
                    }]
                );
            }
            other => panic!("expected ExtendedReport, got {other:?}"),
        }
    }

    /// An XR truncated before its originator SSRC produces no
    /// ExtendedReport.
    #[test]
    fn parse_xr_truncated() {
        // XR with header but SSRC field would be at bytes 4..8, which is missing
        // Length=0 means total packet = 4 bytes (just the header)
        let data = vec![0x80, 207, 0, 0];
        let packets = parse_rtcp(&data);
        // parse_extended_report requires >= 8 bytes, so this should fail silently
        assert!(
            packets.is_empty()
                || packets
                    .iter()
                    .all(|p| !matches!(p, RtcpPacket::ExtendedReport(_)))
        );
    }

    /// Build the compact-NTP stamp an endpoint would put in an SR sent
    /// `ago_ms` before `now`, so a test can state a round trip and read it
    /// back rather than hand-computing 1/65536ths.
    fn lsr_sent_ago(now: chrono::DateTime<chrono::Utc>, ago_ms: i64) -> u32 {
        super::compact_ntp(now - chrono::TimeDelta::milliseconds(ago_ms))
    }

    /// A stated round trip comes back out, within the wire format's own
    /// resolution.
    ///
    /// The arithmetic is the whole feature, so it is asserted against numbers
    /// chosen for what they mean: 180 ms is past G.114's 150 ms guidance for
    /// interactive speech, and 20 ms of it is the reporter sitting on the SR
    /// before answering — which RFC 3550 subtracts out and so must we.
    #[test]
    fn a_stated_round_trip_survives_the_wire_format() {
        let now = chrono::Utc::now();
        let dlsr = (20.0 * 65536.0 / 1000.0) as u32;
        let rtt = rtt_from_sender_report_echo(now, lsr_sent_ago(now, 200), dlsr)
            .expect("a normal report yields a round trip");
        assert!(
            (rtt - 180.0).abs() < 1.0,
            "expected ~180 ms (200 ms elapsed less 20 ms of reporter delay), got {rtt}"
        );
    }

    /// No SR seen by the reporter is NOT a round trip of zero.
    ///
    /// RFC 3550 §6.4.1 says `last_sr` is zero when no SR has arrived. Reporting
    /// that as 0 ms would make the worst case — a reporter that has heard
    /// nothing — read as the best possible network.
    #[test]
    fn a_reporter_that_has_seen_no_sr_yields_no_measurement() {
        let now = chrono::Utc::now();
        assert_eq!(rtt_from_sender_report_echo(now, 0, 0), None);
        // Anti-vacuity: the same call with a real LSR does measure something.
        assert!(rtt_from_sender_report_echo(now, lsr_sent_ago(now, 50), 0).is_some());
    }

    /// Clock disagreement is refused, not rounded into a plausible number.
    #[test]
    fn a_figure_that_can_only_be_clock_skew_is_refused() {
        let now = chrono::Utc::now();
        // An SR stamped in the future: the subtraction runs backwards.
        assert_eq!(
            rtt_from_sender_report_echo(now, lsr_sent_ago(now, -5_000), 0),
            None,
            "an SR from the future is skew, not a negative round trip"
        );
        // Beyond MAX_PLAUSIBLE_RTT_MS.
        assert_eq!(
            rtt_from_sender_report_echo(now, lsr_sent_ago(now, 30_000), 0),
            None,
            "30 s is two clocks disagreeing, not a call"
        );
        // A genuinely bad path is still REPORTED — the guard must not swallow
        // the satellite case it exists to sit above.
        let bad = rtt_from_sender_report_echo(now, lsr_sent_ago(now, 900), 0)
            .expect("900 ms is terrible and real");
        assert!((bad - 900.0).abs() < 2.0, "got {bad}");
    }

    /// The reporter's own delay is subtracted, or every busy endpoint looks
    /// like a slow network.
    #[test]
    fn the_reporters_own_delay_does_not_count_as_network_time() {
        let now = chrono::Utc::now();
        let elapsed_ms = 500;
        let no_delay =
            rtt_from_sender_report_echo(now, lsr_sent_ago(now, elapsed_ms), 0).expect("some rtt");
        let with_delay = rtt_from_sender_report_echo(
            now,
            lsr_sent_ago(now, elapsed_ms),
            (400.0 * 65536.0 / 1000.0) as u32,
        )
        .expect("some rtt");
        assert!(
            (no_delay - 500.0).abs() < 2.0 && (with_delay - 100.0).abs() < 2.0,
            "400 ms of reporter delay must come off: {no_delay} vs {with_delay}"
        );
    }
}
