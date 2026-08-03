// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declaration against observation — the rules no text linter can run.
//!
//! Every other SIP linter reads messages against a grammar. Give one a capture
//! where the SDP offers PCMU on payload type 0 and the far end then sends
//! payload type 8, and it reports a clean call: both messages are perfect SIP.
//! The defect is not in either message. It is in the disagreement between the
//! signalling and the media, and reading it needs both in one process, which is
//! what sipnab already is.
//!
//! # What "observed" means here
//!
//! [`ObservedMedia`] is a small view over what the capture actually carried,
//! built from [`crate::rtp::stream::RtpStream`] or assembled directly in a
//! test. It deliberately does not borrow the stream store: a rule that can only
//! run against live capture state is a rule nobody can write a fixture for.
//!
//! # One-sided thresholds
//!
//! Three of these rules compare a duration against another duration, and every
//! comparison is one-sided on purpose. Silence suppression, comfort noise and a
//! congested path all *stretch* the gap between packets and none of them
//! compresses it, so a rule that fires on "slower than declared" fires on half
//! the traffic in existence while a rule that fires on "carrying more media than
//! time elapsed" fires only on the impossible. See
//! [`FRAME_SIZE_IMPOSSIBLE`].

use std::net::{IpAddr, SocketAddr};

use chrono::{DateTime, Utc};

use crate::sip::dialog::SipDialog;
use crate::sip::sdp::{SdpDirection, effective_address};

use super::FindingSink;
use super::finding::{
    DIRECTION_UNMET, FRAME_SIZE_IMPOSSIBLE, MEDIA_PORT_MISMATCH, PT_UNDECLARED, PTIME_MISMATCH,
    RTCP_MUX_UNANSWERED,
};

/// Comfort noise, RFC 3389. Sent without ever appearing in an `m=` line by
/// equipment that treats it as part of the codec rather than a format of its
/// own, so an undeclared payload type of 13 says nothing about conformance.
const COMFORT_NOISE_PT: u8 = 13;

/// The RFC 3551 §6 reserved payload type earlier profiles used for comfort
/// noise. Same exemption, same reason.
const RESERVED_CN_PT: u8 = 19;

/// Packets a stream needs before a duration derived from it means anything.
///
/// Below this the mean is dominated by whichever packet the capture happened to
/// start and end on. Fifty packets is one second of media at the RFC 3551 §4.2
/// default packetization.
const MIN_PACKETS_FOR_TIMING: u64 = 50;

/// The longest packet RFC 3551 §4.2 asks a receiver to accept, in milliseconds:
/// "A receiver SHOULD accept packets representing between 0 and 200 ms of audio
/// data."
const MAX_PACKET_MS: f64 = 200.0;

/// How far the observed packetization may drift from `a=ptime` before it counts
/// as a different answer rather than jitter.
///
/// Half again, in either direction: 20 ms declared against 30 ms observed is a
/// different packetization, and 20 against 25 is a rounding argument.
const PTIME_TOLERANCE: f64 = 0.5;

/// How much media a packet may claim relative to the time between packets
/// before the claim becomes impossible.
///
/// A stream cannot deliver more media than has elapsed. Two is the slack for a
/// capture whose first or last packet fell outside the window.
const IMPOSSIBLE_RATE_FACTOR: f64 = 2.0;

/// A codec's fixed relationship between payload octets and milliseconds.
///
/// Only the constant-rate codecs of RFC 3551 Table 1 appear here, because only
/// they let a payload size be converted to a duration. A variable-rate codec
/// (Opus, AMR) has no such number, and inventing one would produce findings
/// grounded in nothing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodecShape {
    /// Encoding name as it appears in `a=rtpmap`.
    pub name: &'static str,
    /// Payload octets per millisecond of media.
    pub octets_per_ms: f64,
    /// Frame length in octets, for frame-based codecs.
    pub frame_octets: Option<u32>,
    /// Frame duration in milliseconds, for frame-based codecs.
    pub frame_ms: Option<f64>,
}

/// The constant-rate codecs of RFC 3551 Table 1, with the numbers that table
/// gives.
///
/// `codec_shapes_are_self_consistent` holds each frame-based entry to its own
/// octet rate, so a transcription slip cannot survive.
const CODEC_SHAPES: &[CodecShape] = &[
    // §4.5.14: 8000 samples/s, one octet per sample.
    CodecShape {
        name: "PCMU",
        octets_per_ms: 8.0,
        frame_octets: None,
        frame_ms: None,
    },
    CodecShape {
        name: "PCMA",
        octets_per_ms: 8.0,
        frame_octets: None,
        frame_ms: None,
    },
    // §4.5.2: 16 kHz sampled, 64 kbit/s — still 8 octets per millisecond.
    CodecShape {
        name: "G722",
        octets_per_ms: 8.0,
        frame_octets: None,
        frame_ms: None,
    },
    // §4.5.6: 8 kbit/s, 10 octets per 10 ms frame.
    CodecShape {
        name: "G729",
        octets_per_ms: 1.0,
        frame_octets: Some(10),
        frame_ms: Some(10.0),
    },
    // §4.5.8: 13 kbit/s, 33 octets per 20 ms frame.
    CodecShape {
        name: "GSM",
        octets_per_ms: 1.65,
        frame_octets: Some(33),
        frame_ms: Some(20.0),
    },
];

/// The shape of a codec named in `a=rtpmap`, or `None` for a variable-rate one.
#[must_use]
pub fn codec_shape(name: &str) -> Option<&'static CodecShape> {
    CODEC_SHAPES
        .iter()
        .find(|c| c.name.eq_ignore_ascii_case(name))
}

/// One RTP stream as the capture saw it.
///
/// A projection of [`crate::rtp::stream::RtpStream`] carrying only what the
/// observation rules read, so a fixture can state a stream in six lines instead
/// of replaying packets through the store.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedStream {
    /// Where the packets came from.
    pub src: SocketAddr,
    /// Where the packets went.
    pub dst: SocketAddr,
    /// Synchronization source from the RTP header.
    pub ssrc: u32,
    /// Payload type carried by the stream's first packet.
    pub payload_type: u8,
    /// Packets seen.
    pub packet_count: u64,
    /// Payload octets seen, headers excluded.
    pub octet_count: u64,
    /// Arrival of the first packet.
    pub first_seen: DateTime<Utc>,
    /// Arrival of the last packet.
    pub last_seen: DateTime<Utc>,
    /// Codec resolved from SDP or the RFC 3551 static table.
    pub codec: Option<String>,
}

impl ObservedStream {
    /// Mean milliseconds between packets, or `None` when too few arrived to
    /// mean anything.
    #[must_use]
    pub fn mean_interarrival_ms(&self) -> Option<f64> {
        if self.packet_count < MIN_PACKETS_FOR_TIMING {
            return None;
        }
        let span = (self.last_seen - self.first_seen).num_milliseconds() as f64;
        let gaps = (self.packet_count - 1) as f64;
        (span > 0.0).then(|| span / gaps)
    }

    /// Mean payload octets per packet, or `None` for an empty stream.
    #[must_use]
    pub fn mean_payload_octets(&self) -> Option<f64> {
        (self.packet_count > 0).then(|| self.octet_count as f64 / self.packet_count as f64)
    }

    /// Milliseconds of media each packet carries, derived from its size.
    ///
    /// Immune to silence suppression and to a congested path, both of which move
    /// arrival times and neither of which changes how much media a packet holds.
    /// `None` unless the codec has a fixed octet rate.
    #[must_use]
    pub fn implied_packet_ms(&self) -> Option<f64> {
        let shape = codec_shape(self.codec.as_deref()?)?;
        let octets = self.mean_payload_octets()?;
        (shape.octets_per_ms > 0.0).then(|| octets / shape.octets_per_ms)
    }

    /// Project an [`RtpStream`](crate::rtp::stream::RtpStream) into this view.
    #[must_use]
    pub fn from_stream(stream: &crate::rtp::stream::RtpStream) -> Self {
        Self {
            src: stream.key.src,
            dst: stream.key.dst,
            ssrc: stream.key.ssrc,
            payload_type: stream.payload_type,
            packet_count: stream.packet_count,
            octet_count: stream.octet_count,
            first_seen: stream.first_seen,
            last_seen: stream.last_seen,
            codec: stream.codec.clone(),
        }
    }
}

/// RTCP seen between one pair of endpoints.
///
/// Separate from [`ObservedStream`] because the question RFC 5761 asks is about
/// the port RTCP arrived on, and the RTP stream store folds reception reports
/// into the stream they describe rather than recording where they landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedRtcp {
    /// Where the RTCP came from.
    pub src: SocketAddr,
    /// Where the RTCP went.
    pub dst: SocketAddr,
    /// How many RTCP packets arrived.
    pub packets: u64,
}

/// Everything the capture carried for one dialog's media.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservedMedia {
    /// RTP streams attributed to the dialog.
    streams: Vec<ObservedStream>,
    /// RTCP endpoint pairs attributed to the dialog.
    rtcp: Vec<ObservedRtcp>,
}

impl ObservedMedia {
    /// Nothing observed.
    ///
    /// Not the same as "no media rules ran": a dialog that negotiated `sendrecv`
    /// and carried nothing is exactly what [`DIRECTION_UNMET`] reports.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one RTP stream.
    #[must_use]
    pub fn with_stream(mut self, stream: ObservedStream) -> Self {
        self.streams.push(stream);
        self
    }

    /// Add one RTCP endpoint pair.
    #[must_use]
    pub fn with_rtcp(mut self, rtcp: ObservedRtcp) -> Self {
        self.rtcp.push(rtcp);
        self
    }

    /// Project a dialog's RTP streams, typically
    /// [`StreamStore::streams_for`](crate::rtp::stream_store::StreamStore::streams_for).
    ///
    /// RTCP is not carried by the stream store's per-stream view, so a caller
    /// that wants [`RTCP_MUX_UNANSWERED`] adds it with [`Self::with_rtcp`].
    #[must_use]
    pub fn from_streams<'a>(
        streams: impl IntoIterator<Item = &'a crate::rtp::stream::RtpStream>,
    ) -> Self {
        Self {
            streams: streams
                .into_iter()
                .map(ObservedStream::from_stream)
                .collect(),
            rtcp: Vec::new(),
        }
    }

    /// The RTP streams observed.
    #[must_use]
    pub fn streams(&self) -> &[ObservedStream] {
        &self.streams
    }

    /// The RTCP endpoint pairs observed.
    #[must_use]
    pub fn rtcp(&self) -> &[ObservedRtcp] {
        &self.rtcp
    }
}

/// One media description as the signalling declared it.
#[derive(Debug, Clone)]
struct Declared {
    /// Index into the dialog's message list of the body that declared it.
    index: usize,
    /// Address media was promised to arrive at.
    addr: IpAddr,
    /// Port media was promised to arrive at.
    port: u16,
    /// Media type from the `m=` line.
    media_type: String,
    /// Payload type numbers listed on the `m=` line.
    formats: Vec<u8>,
    /// Direction attribute in force for this description.
    direction: SdpDirection,
    /// `a=ptime`, when declared.
    ptime: Option<u32>,
    /// Whether `a=rtcp-mux` appeared.
    rtcp_mux: bool,
    /// Whether the body came from a request. Offers usually do, and the RTCP
    /// multiplexing rule needs to tell an offer from an answer.
    from_request: bool,
}

/// Every media description the dialog declared, in message order.
fn declared_media(dialog: &SipDialog) -> Vec<Declared> {
    let mut out = Vec::new();
    for (index, msg) in dialog.messages.iter().enumerate() {
        let Some(sdp) = msg.sdp() else {
            continue;
        };
        for media in &sdp.media {
            if media.port == 0 {
                continue;
            }
            let Some(addr) = effective_address(media, &sdp).and_then(|a| a.parse::<IpAddr>().ok())
            else {
                continue;
            };
            out.push(Declared {
                index,
                addr,
                port: media.port,
                media_type: media.media_type.clone(),
                formats: media
                    .formats
                    .iter()
                    .filter_map(|f| f.parse().ok())
                    .collect(),
                direction: media.direction,
                ptime: media.ptime,
                rtcp_mux: media.rtcp_mux,
                from_request: msg.is_request,
            });
        }
    }
    out
}

/// The declaration whose address and port the stream's destination matches.
fn declaration_for<'a>(declared: &'a [Declared], stream: &ObservedStream) -> Option<&'a Declared> {
    declared
        .iter()
        .find(|d| d.addr == stream.dst.ip() && d.port == stream.dst.port())
}

/// Run every observation rule.
pub(crate) fn lint(dialog: &SipDialog, media: &ObservedMedia, sink: &mut FindingSink<'_>) {
    let declared = declared_media(dialog);
    if declared.is_empty() {
        return;
    }

    payload_type_undeclared(&declared, media, sink);
    media_port_mismatch(&declared, media, sink);
    direction_unmet(&declared, media, sink);
    packetization(&declared, media, sink);
    rtcp_mux_unanswered(&declared, media, sink);
}

/// RFC 3264 §6.1 — the wire carries a payload type nobody declared.
///
/// The headline case: SDP names PCMU on payload type 0, the far end sends
/// payload type 8, and every text linter in existence reports a clean call.
///
/// Compared against the union of every payload type the dialog declared, in
/// either direction. A narrower comparison — this endpoint's own `m=` line —
/// would report the perfectly ordinary case of an answerer sending the offerer's
/// second choice.
fn payload_type_undeclared(
    declared: &[Declared],
    media: &ObservedMedia,
    sink: &mut FindingSink<'_>,
) {
    if !sink.wants(&PT_UNDECLARED) {
        return;
    }
    let mut all: Vec<u8> = declared.iter().flat_map(|d| d.formats.clone()).collect();
    all.sort_unstable();
    all.dedup();
    if all.is_empty() {
        return;
    }

    for stream in media.streams() {
        let pt = stream.payload_type;
        if all.contains(&pt) || pt == COMFORT_NOISE_PT || pt == RESERVED_CN_PT {
            continue;
        }
        let Some(decl) = declaration_for(declared, stream) else {
            continue;
        };
        sink.push(
            &PT_UNDECLARED,
            decl.index,
            format!(
                "RTP payload type {pt} on {} packets to the declared {} port",
                stream.packet_count, decl.media_type
            ),
            format!("one of the declared payload types {all:?}"),
            format!(
                "The signalling declared {all:?} and the wire carried {pt}. §6.1 binds what \
                 either end may send to what the offer listed, so the receiver is decoding \
                 with a codec nobody agreed to — or discarding the stream and reporting \
                 silence while the sender's own counters climb."
            ),
        );
    }
}

/// RFC 4566 §5.14 — RTP arrived at an address that was declared, on a port that
/// was not.
///
/// Only fires when the destination address itself was declared. A stream to some
/// other address is a relay, a media gateway or a NAT rewrite, which is a
/// different question and one [`crate::rtp::diagnosis`] already answers.
fn media_port_mismatch(declared: &[Declared], media: &ObservedMedia, sink: &mut FindingSink<'_>) {
    if !sink.wants(&MEDIA_PORT_MISMATCH) {
        return;
    }
    for stream in media.streams() {
        let dst = stream.dst;
        let at_address: Vec<&Declared> = declared.iter().filter(|d| d.addr == dst.ip()).collect();
        if at_address.is_empty() {
            continue;
        }
        // The RTP port itself, and the port one higher that RFC 3264 §6.1
        // reserves for RTCP, are both expected traffic.
        if at_address
            .iter()
            .any(|d| d.port == dst.port() || d.port.saturating_add(1) == dst.port())
        {
            continue;
        }
        let ports: Vec<u16> = at_address.iter().map(|d| d.port).collect();
        sink.push(
            &MEDIA_PORT_MISMATCH,
            at_address[0].index,
            format!(
                "{} RTP packets to port {} at a declared media address",
                stream.packet_count,
                dst.port()
            ),
            format!("one of the advertised ports {ports:?}"),
            "§5.14 makes the m= port the port media is sent to, and the far end opened its \
             socket there. Media on another port reaches a firewall pinhole nobody opened, \
             so the call connects and one side hears nothing.",
        );
    }
}

/// RFC 3264 §6.1 — `sendrecv` was negotiated and the media went one way.
///
/// Needs both sides declared and at least one of them carrying media: a dialog
/// with no media at all is a call that never started, not a one-way call.
/// Matching is by address rather than by port, so a NAT rewriting the source
/// port does not read as a missing direction.
fn direction_unmet(declared: &[Declared], media: &ObservedMedia, sink: &mut FindingSink<'_>) {
    if !sink.wants(&DIRECTION_UNMET) {
        return;
    }
    let sendrecv: Vec<&Declared> = declared
        .iter()
        .filter(|d| d.direction == SdpDirection::SendRecv)
        .collect();

    let mut addresses: Vec<IpAddr> = sendrecv.iter().map(|d| d.addr).collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.len() < 2 {
        return;
    }

    let received: Vec<(IpAddr, u64)> = addresses
        .iter()
        .map(|addr| {
            let packets = media
                .streams()
                .iter()
                .filter(|s| s.dst.ip() == *addr)
                .map(|s| s.packet_count)
                .sum();
            (*addr, packets)
        })
        .collect();

    let total: u64 = received.iter().map(|(_, n)| n).sum();
    if total == 0 {
        return;
    }
    let Some((silent, _)) = received.iter().find(|(_, n)| *n == 0) else {
        return;
    };
    let index = sendrecv
        .iter()
        .find(|d| d.addr == *silent)
        .map_or(0, |d| d.index);

    sink.push(
        &DIRECTION_UNMET,
        index,
        format!("{total} RTP packets observed, none of them toward one negotiated endpoint"),
        "media in both directions, as a=sendrecv promised",
        "§6.1 makes sendrecv a promise to send as well as receive. One endpoint kept it and \
         the other did not, which the far end hears as dead air on an answered call. The \
         usual causes are a NAT with no inbound pinhole, a firewall dropping the return \
         path, and an endpoint that answered sendrecv while muting locally.",
    );
}

/// RFC 4566 §6 and RFC 3551 §4.2 — how much media each packet actually carries.
///
/// Two findings from one measurement, because they answer different questions.
/// [`PTIME_MISMATCH`] says the far end packetized differently from what it
/// asked for, which costs bandwidth and jitter-buffer depth.
/// [`FRAME_SIZE_IMPOSSIBLE`] says the packets cannot be the codec that was
/// negotiated at all.
///
/// Both read the payload size rather than the arrival times wherever the codec
/// allows it. Arrival times move with silence suppression and with the network;
/// the number of octets in a packet does not.
fn packetization(declared: &[Declared], media: &ObservedMedia, sink: &mut FindingSink<'_>) {
    for stream in media.streams() {
        let Some(decl) = declaration_for(declared, stream) else {
            continue;
        };
        let Some(implied) = stream.implied_packet_ms() else {
            continue;
        };
        let codec = stream.codec.as_deref().unwrap_or("the negotiated codec");

        // Impossible, half one: more media per packet than RFC 3551 §4.2 asks
        // any receiver to accept.
        if implied > MAX_PACKET_MS {
            sink.push(
                &FRAME_SIZE_IMPOSSIBLE,
                decl.index,
                format!("{implied:.0} ms of {codec} per packet"),
                format!("at most {MAX_PACKET_MS:.0} ms per packet"),
                "§4.2 asks a receiver to accept packets of 0 to 200 ms. A payload this size \
                 is either a different codec than the one negotiated or a packet the far end \
                 will drop unread.",
            );
            continue;
        }

        // Impossible, half two: more media delivered than time elapsed. Silence
        // suppression and congestion both stretch the gap between packets, so
        // this comparison only ever fires on the impossible direction.
        if let Some(spacing) = stream.mean_interarrival_ms()
            && spacing > 0.0
            && implied > spacing * IMPOSSIBLE_RATE_FACTOR
        {
            sink.push(
                &FRAME_SIZE_IMPOSSIBLE,
                decl.index,
                format!("{implied:.0} ms of {codec} per packet, {spacing:.0} ms apart"),
                format!("at most {spacing:.0} ms of media per packet at that spacing"),
                "A stream cannot deliver more media than has elapsed. The payload size and \
                 the packet rate agree on one thing only: the codec on the wire is not the \
                 codec the SDP named.",
            );
            continue;
        }

        // Possible, but not what was asked for.
        let Some(ptime) = decl.ptime.filter(|p| *p > 0) else {
            continue;
        };
        let declared_ms = f64::from(ptime);
        let drift = (implied - declared_ms).abs() / declared_ms;
        if drift > PTIME_TOLERANCE {
            sink.push(
                &PTIME_MISMATCH,
                decl.index,
                format!("{implied:.0} ms of {codec} per packet"),
                format!("a=ptime:{ptime}"),
                "The far end asked for one packetization and sent another. Longer packets \
                 add end-to-end delay and make each loss more audible; shorter ones multiply \
                 the header overhead. Either way the jitter buffer was sized for the number \
                 in the SDP.",
            );
        }
    }
}

/// RFC 5761 §5.1.1 — multiplexing used after the answer declined to agree.
///
/// "If the answer does not contain an 'a=rtcp-mux' attribute, the offerer MUST
/// NOT multiplex RTP and RTCP packets on a single port." The evidence is RTCP
/// observed arriving on the RTP port itself, which no capture-free tool can see
/// and no grammar can infer.
fn rtcp_mux_unanswered(declared: &[Declared], media: &ObservedMedia, sink: &mut FindingSink<'_>) {
    if !sink.wants(&RTCP_MUX_UNANSWERED) || media.rtcp().is_empty() {
        return;
    }
    let offered = declared.iter().any(|d| d.rtcp_mux && d.from_request);
    if !offered {
        return;
    }
    // The answer is the SDP that came back. If any of it agreed, multiplexing
    // was negotiated and there is nothing to report.
    let answered = declared.iter().any(|d| d.rtcp_mux && !d.from_request);
    if answered {
        return;
    }

    for rtcp in media.rtcp() {
        let Some(decl) = declared
            .iter()
            .find(|d| d.addr == rtcp.dst.ip() && d.port == rtcp.dst.port())
        else {
            continue;
        };
        sink.push(
            &RTCP_MUX_UNANSWERED,
            decl.index,
            format!(
                "{} RTCP packets to port {}, the RTP port",
                rtcp.packets,
                rtcp.dst.port()
            ),
            format!("RTCP to port {}", decl.port.saturating_add(1)),
            "§5.1.1 makes an unanswered rtcp-mux offer mean no multiplexing, so the far end \
             is listening for RTCP one port up and never hears a report. Reception quality \
             stops being visible to the sender, and any adaptive codec loses its feedback.",
        );
    }
}

/// Tests for the observation rules.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::TransportProto;
    use crate::sip::dialog_store::DialogStore;
    use crate::sip::lint::{Basis, LintConfig, Linter};
    use crate::sip::message::SipMessage;
    use crate::sip::parser::parse_sip;
    use std::net::Ipv4Addr;

    /// Caller media address, RFC 5737 documentation range.
    const CALLER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// Callee media address.
    const CALLEE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    /// Caller RTP port.
    const CALLER_PORT: u16 = 40000;
    /// Callee RTP port.
    const CALLEE_PORT: u16 = 41000;

    /// Fixed capture timestamp, advanced by `offset` seconds.
    fn ts(offset: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_718_452_800 + offset, 0).unwrap_or_default()
    }

    /// Parse one message of the fixture dialog.
    fn msg(raw: &str, offset: i64) -> SipMessage {
        parse_sip(
            raw.as_bytes(),
            ts(offset),
            IpAddr::V4(CALLER),
            IpAddr::V4(CALLEE),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("test fixture must parse")
    }

    /// An SDP body with the given media line and attributes.
    fn sdp(addr: Ipv4Addr, port: u16, formats: &str, attrs: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 {addr}\r\n\
             s=-\r\n\
             c=IN IP4 {addr}\r\n\
             t=0 0\r\n\
             m=audio {port} RTP/AVP {formats}\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:18 G729/8000\r\n\
             {attrs}"
        )
    }

    /// An INVITE carrying `body`.
    fn invite(body: &str) -> String {
        format!(
            "INVITE sip:bob@example.net SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
             Max-Forwards: 70\r\n\
             To: <sip:bob@example.net>\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: media-fixture-1\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:bob@192.0.2.2>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n{body}",
            body.len()
        )
    }

    /// A 200 OK carrying `body`.
    fn ok(body: &str) -> String {
        format!(
            "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
             To: <sip:bob@example.net>;tag=a6c85cf\r\n\
             From: <sip:alice@example.com>;tag=1928301774\r\n\
             Call-ID: media-fixture-1\r\n\
             CSeq: 1 INVITE\r\n\
             Contact: <sip:bob@192.0.2.2>\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n{body}",
            body.len()
        )
    }

    /// A store holding one dialog that offered and answered `formats`.
    ///
    /// `SipDialog` is not `Clone`, so the store outlives the borrow rather than
    /// the dialog being lifted out of it.
    fn negotiated(formats: &str, attrs: &str, answer_attrs: &str) -> DialogStore {
        let mut store = DialogStore::new(16, false);
        store.process_message(msg(&invite(&sdp(CALLER, CALLER_PORT, formats, attrs)), 0));
        store.process_message(msg(
            &ok(&sdp(CALLEE, CALLEE_PORT, formats, answer_attrs)),
            1,
        ));
        store
    }

    /// The single dialog a fixture store holds.
    fn only(store: &DialogStore) -> &SipDialog {
        store
            .iter()
            .next()
            .expect("fixture must produce one dialog")
    }

    /// A stream of `packets` packets of `payload` octets each, `spacing_ms`
    /// apart, from `src` to `dst`.
    fn stream(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        pt: u8,
        codec: &str,
        packets: u64,
        payload: u64,
        spacing_ms: i64,
    ) -> ObservedStream {
        ObservedStream {
            src: SocketAddr::new(IpAddr::V4(src.0), src.1),
            dst: SocketAddr::new(IpAddr::V4(dst.0), dst.1),
            ssrc: 0x1234_5678,
            payload_type: pt,
            packet_count: packets,
            octet_count: packets * payload,
            first_seen: ts(0),
            last_seen: ts(0) + chrono::Duration::milliseconds(spacing_ms * (packets as i64 - 1)),
            codec: Some(codec.to_string()),
        }
    }

    /// A conformant G.711 call in both directions.
    fn conformant_media() -> ObservedMedia {
        ObservedMedia::new()
            .with_stream(stream(
                (CALLER, CALLER_PORT),
                (CALLEE, CALLEE_PORT),
                0,
                "PCMU",
                500,
                160,
                20,
            ))
            .with_stream(stream(
                (CALLEE, CALLEE_PORT),
                (CALLER, CALLER_PORT),
                0,
                "PCMU",
                500,
                160,
                20,
            ))
    }

    /// Rule identifiers raised for a dialog and its media.
    fn ids(store: &DialogStore, media: &ObservedMedia) -> Vec<&'static str> {
        Linter::new(LintConfig::new())
            .lint_dialog_with_media(only(store), media)
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }

    /// A call whose media matches its declaration raises nothing.
    #[test]
    fn media_matching_the_declaration_raises_nothing() {
        let dialog = negotiated(
            "0",
            "a=sendrecv\r\na=ptime:20\r\n",
            "a=sendrecv\r\na=ptime:20\r\n",
        );
        assert_eq!(ids(&dialog, &conformant_media()), Vec::<&str>::new());
    }

    /// The headline case: PCMU declared on payload type 0, payload type 8 on
    /// the wire.
    ///
    /// Both messages are flawless SIP. Only a tool holding the media can see it.
    #[test]
    fn payload_type_the_sdp_never_declared_is_reported() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new()
            .with_stream(stream(
                (CALLER, CALLER_PORT),
                (CALLEE, CALLEE_PORT),
                8,
                "PCMA",
                500,
                160,
                20,
            ))
            .with_stream(stream(
                (CALLEE, CALLEE_PORT),
                (CALLER, CALLER_PORT),
                0,
                "PCMU",
                500,
                160,
                20,
            ));
        let findings = Linter::new(LintConfig::new()).lint_dialog_with_media(only(&dialog), &media);
        let f = findings
            .iter()
            .find(|f| f.rule_id == PT_UNDECLARED.id)
            .expect("undeclared payload type must be reported");
        assert_eq!(f.basis, Basis::Observation);
        assert!(f.observed.contains("payload type 8"), "{}", f.observed);
        assert!(f.expected.contains('0'), "{}", f.expected);
    }

    /// A payload type the offer listed but the answer did not is silent.
    ///
    /// Sending the offerer's second choice is ordinary. A rule comparing against
    /// one endpoint's own m= line would report most answered calls.
    #[test]
    fn a_declared_alternative_payload_type_is_silent() {
        let dialog = negotiated("0 8", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            8,
            "PCMA",
            500,
            160,
            20,
        ));
        assert!(!ids(&dialog, &media).contains(&PT_UNDECLARED.id));
    }

    /// Comfort noise is exempt.
    ///
    /// RFC 3389 comfort noise arrives on payload type 13 from equipment that
    /// never lists it, so firing here would report a large share of real calls.
    ///
    /// The payload type is written out rather than read from
    /// `COMFORT_NOISE_PT`: a test that names the constant it guards moves with
    /// it, so changing 13 to anything else leaves the test passing and the
    /// exemption silently pointed at the wrong number. Mutation testing found
    /// exactly that.
    #[test]
    fn comfort_noise_is_not_an_undeclared_payload_type() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            13,
            "CN",
            60,
            2,
            20,
        ));
        assert!(!ids(&dialog, &media).contains(&PT_UNDECLARED.id));
        assert_eq!(
            COMFORT_NOISE_PT, 13,
            "RFC 3389 comfort noise is payload type 13"
        );
    }

    /// RTP arriving at a declared address on an undeclared port is reported.
    #[test]
    fn rtp_on_an_unadvertised_port_is_reported() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT + 500),
            0,
            "PCMU",
            500,
            160,
            20,
        ));
        let findings = Linter::new(LintConfig::new()).lint_dialog_with_media(only(&dialog), &media);
        let f = findings
            .iter()
            .find(|f| f.rule_id == MEDIA_PORT_MISMATCH.id)
            .expect("unadvertised port must be reported");
        assert!(f.observed.contains(&(CALLEE_PORT + 500).to_string()));
    }

    /// The RTCP port one above the RTP port is expected traffic.
    #[test]
    fn the_rtcp_port_is_not_a_port_mismatch() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT + 1),
            0,
            "PCMU",
            60,
            160,
            20,
        ));
        assert!(!ids(&dialog, &media).contains(&MEDIA_PORT_MISMATCH.id));
    }

    /// Media to an address nobody declared is somebody else's question.
    #[test]
    fn media_to_an_undeclared_address_is_silent() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let relay = Ipv4Addr::new(198, 51, 100, 7);
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (relay, 30000),
            0,
            "PCMU",
            500,
            160,
            20,
        ));
        assert!(!ids(&dialog, &media).contains(&MEDIA_PORT_MISMATCH.id));
    }

    /// `sendrecv` negotiated, media one way only.
    #[test]
    fn one_way_media_against_a_sendrecv_negotiation_is_reported() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            0,
            "PCMU",
            500,
            160,
            20,
        ));
        assert!(ids(&dialog, &media).contains(&DIRECTION_UNMET.id));
    }

    /// A call that carried no media at all raises no direction finding.
    ///
    /// A dialog with nothing on the wire is a call that never started, an
    /// unanswered INVITE, or a capture filtered to signalling. None of those is
    /// a one-way call.
    #[test]
    fn a_silent_call_is_not_a_one_way_call() {
        let dialog = negotiated("0", "a=sendrecv\r\n", "a=sendrecv\r\n");
        assert!(!ids(&dialog, &ObservedMedia::new()).contains(&DIRECTION_UNMET.id));
    }

    /// A `sendonly` negotiation carrying media one way is correct and silent.
    #[test]
    fn one_way_media_against_a_sendonly_negotiation_is_silent() {
        let dialog = negotiated("0", "a=sendonly\r\n", "a=recvonly\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            0,
            "PCMU",
            500,
            160,
            20,
        ));
        assert!(!ids(&dialog, &media).contains(&DIRECTION_UNMET.id));
    }

    /// `a=ptime:20` declared, 40 ms packets on the wire.
    #[test]
    fn packetization_differing_from_ptime_is_reported() {
        let dialog = negotiated(
            "0",
            "a=sendrecv\r\na=ptime:20\r\n",
            "a=sendrecv\r\na=ptime:20\r\n",
        );
        let media = conformant_media().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            0,
            "PCMU",
            500,
            320,
            40,
        ));
        let findings = Linter::new(LintConfig::new()).lint_dialog_with_media(only(&dialog), &media);
        let f = findings
            .iter()
            .find(|f| f.rule_id == PTIME_MISMATCH.id)
            .expect("ptime drift must be reported");
        assert!(f.observed.contains("40 ms"), "{}", f.observed);
        assert_eq!(f.expected, "a=ptime:20");
    }

    /// Silence suppression stretches the gaps and must not trip the ptime rule.
    ///
    /// The measurement reads payload size rather than arrival times exactly so
    /// this case stays quiet: 20 ms packets are 20 ms packets however far apart
    /// they arrive.
    #[test]
    fn silence_suppression_does_not_trip_the_ptime_rule() {
        let dialog = negotiated(
            "0",
            "a=sendrecv\r\na=ptime:20\r\n",
            "a=sendrecv\r\na=ptime:20\r\n",
        );
        // 160-octet PCMU packets — 20 ms each — arriving 200 ms apart because
        // the sender transmits only during speech.
        let media = conformant_media().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            0,
            "PCMU",
            500,
            160,
            200,
        ));
        assert!(!ids(&dialog, &media).contains(&PTIME_MISMATCH.id));
    }

    /// G.729 negotiated, G.711-sized packets on the wire.
    ///
    /// 160 octets of G.729 is 160 ms of media arriving every 20 ms, which is
    /// eight times more media than time. No network does that.
    #[test]
    fn a_payload_the_codec_cannot_produce_is_reported() {
        let dialog = negotiated("18", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new().with_stream(stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            18,
            "G729",
            500,
            160,
            20,
        ));
        let findings = Linter::new(LintConfig::new()).lint_dialog_with_media(only(&dialog), &media);
        let f = findings
            .iter()
            .find(|f| f.rule_id == FRAME_SIZE_IMPOSSIBLE.id)
            .expect("impossible frame size must be reported");
        assert!(f.observed.contains("G729"), "{}", f.observed);
    }

    /// A conformant G.729 stream is silent.
    #[test]
    fn conformant_g729_is_silent() {
        let dialog = negotiated("18", "a=sendrecv\r\n", "a=sendrecv\r\n");
        let media = ObservedMedia::new()
            .with_stream(stream(
                (CALLER, CALLER_PORT),
                (CALLEE, CALLEE_PORT),
                18,
                "G729",
                500,
                20,
                20,
            ))
            .with_stream(stream(
                (CALLEE, CALLEE_PORT),
                (CALLER, CALLER_PORT),
                18,
                "G729",
                500,
                20,
                20,
            ));
        assert_eq!(ids(&dialog, &media), Vec::<&str>::new());
    }

    /// A variable-rate codec raises no size finding at all.
    ///
    /// Opus has no octets-per-millisecond, so any threshold applied to it would
    /// be invented rather than cited.
    #[test]
    fn a_variable_rate_codec_raises_no_size_finding() {
        let dialog = negotiated(
            "111",
            "a=sendrecv\r\na=ptime:20\r\n",
            "a=sendrecv\r\na=ptime:20\r\n",
        );
        let media = ObservedMedia::new()
            .with_stream(stream(
                (CALLER, CALLER_PORT),
                (CALLEE, CALLEE_PORT),
                111,
                "opus",
                500,
                900,
                20,
            ))
            .with_stream(stream(
                (CALLEE, CALLEE_PORT),
                (CALLER, CALLER_PORT),
                111,
                "opus",
                500,
                900,
                20,
            ));
        let raised = ids(&dialog, &media);
        assert!(!raised.contains(&FRAME_SIZE_IMPOSSIBLE.id), "{raised:?}");
        assert!(!raised.contains(&PTIME_MISMATCH.id), "{raised:?}");
    }

    /// `a=rtcp-mux` offered, unanswered, and RTCP arriving on the RTP port.
    #[test]
    fn unanswered_rtcp_mux_used_anyway_is_reported() {
        let dialog = negotiated("0", "a=sendrecv\r\na=rtcp-mux\r\n", "a=sendrecv\r\n");
        let media = conformant_media().with_rtcp(ObservedRtcp {
            src: SocketAddr::new(IpAddr::V4(CALLER), CALLER_PORT),
            dst: SocketAddr::new(IpAddr::V4(CALLEE), CALLEE_PORT),
            packets: 12,
        });
        let findings = Linter::new(LintConfig::new()).lint_dialog_with_media(only(&dialog), &media);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RTCP_MUX_UNANSWERED.id)
            .expect("unanswered mux must be reported");
        assert_eq!(f.citation(), "RFC 5761 §5.1.1");
        assert_eq!(f.expected, format!("RTCP to port {}", CALLEE_PORT + 1));
    }

    /// An answered `a=rtcp-mux` is silent — multiplexing was negotiated.
    #[test]
    fn answered_rtcp_mux_is_silent() {
        let dialog = negotiated(
            "0",
            "a=sendrecv\r\na=rtcp-mux\r\n",
            "a=sendrecv\r\na=rtcp-mux\r\n",
        );
        let media = conformant_media().with_rtcp(ObservedRtcp {
            src: SocketAddr::new(IpAddr::V4(CALLER), CALLER_PORT),
            dst: SocketAddr::new(IpAddr::V4(CALLEE), CALLEE_PORT),
            packets: 12,
        });
        assert!(!ids(&dialog, &media).contains(&RTCP_MUX_UNANSWERED.id));
    }

    /// RTCP on the separate port after an unanswered offer is correct and
    /// silent — the offerer did what §5.1.1 requires.
    #[test]
    fn rtcp_on_the_separate_port_is_silent() {
        let dialog = negotiated("0", "a=sendrecv\r\na=rtcp-mux\r\n", "a=sendrecv\r\n");
        let media = conformant_media().with_rtcp(ObservedRtcp {
            src: SocketAddr::new(IpAddr::V4(CALLER), CALLER_PORT + 1),
            dst: SocketAddr::new(IpAddr::V4(CALLEE), CALLEE_PORT + 1),
            packets: 12,
        });
        assert!(!ids(&dialog, &media).contains(&RTCP_MUX_UNANSWERED.id));
    }

    /// Every frame-based codec shape agrees with its own octet rate.
    ///
    /// A transcription slip in the table would move every duration the rules
    /// derive, and both findings that read it would be wrong in the same
    /// direction and look consistent.
    #[test]
    fn codec_shapes_are_self_consistent() {
        for shape in CODEC_SHAPES {
            let (Some(octets), Some(ms)) = (shape.frame_octets, shape.frame_ms) else {
                continue;
            };
            let derived = f64::from(octets) / ms;
            assert!(
                (derived - shape.octets_per_ms).abs() < 0.01,
                "{}: {octets} octets per {ms} ms is {derived} octets/ms, table says {}",
                shape.name,
                shape.octets_per_ms
            );
        }
    }

    /// Codec lookup is case-insensitive, and unknown codecs stay unknown.
    #[test]
    fn codec_lookup_ignores_case() {
        assert_eq!(codec_shape("pcmu").map(|c| c.name), Some("PCMU"));
        assert_eq!(codec_shape("G729").map(|c| c.octets_per_ms), Some(1.0));
        assert!(codec_shape("opus").is_none());
    }

    /// A stream with too few packets yields no timing, rather than a number
    /// derived from two arrivals.
    #[test]
    fn short_streams_yield_no_timing() {
        let short = stream(
            (CALLER, CALLER_PORT),
            (CALLEE, CALLEE_PORT),
            0,
            "PCMU",
            4,
            160,
            20,
        );
        assert_eq!(short.mean_interarrival_ms(), None);
        assert_eq!(short.mean_payload_octets(), Some(160.0));
        assert_eq!(short.implied_packet_ms(), Some(20.0));
    }
}
