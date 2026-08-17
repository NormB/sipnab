// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network header parsing for raw captured packets.
//!
//! Parses raw packet bytes through the link, network, and transport layers
//! using [`etherparse`] for zero-copy header parsing, and produces
//! [`ParsedPacket`] structs ready for reassembly or direct consumption by
//! upper-layer parsers.
//!
//! # Encapsulation
//!
//! This module owns the walk; `capture::tunnel` owns the individual
//! decapsulators and the reasoning about when it is safe to trust one. What is
//! stripped, in the order a frame meets it:
//!
//! * **Link layer** — 802.1Q / 802.1ad / legacy-0x9100 VLAN tags, PPPoE
//!   Session (RFC 2516) behind Ethernet *and* inside Linux cooked capture
//!   (SLL / SLL2, what `-i any` on a BNG writes), MPLS (RFC 3032 / RFC 5332),
//!   NSH (RFC 8300), MACsec (IEEE Std 802.1AE) and the Provider Backbone
//!   Bridge I-TAG (IEEE Std 802.1Q §9.7).
//! * **Network layer** — IP-in-IP (protocol 4), 6in4 (41), GRE (47) including
//!   Transparent Ethernet Bridging, MPLS-in-IP (137, RFC 4023) and the
//!   Authentication Header (51, RFC 4302), which authenticates without
//!   encrypting. ESP (50) is not traversed: its payload is ciphertext.
//! * **Transport layer** — the UDP tunnels claimed by destination port:
//!   VXLAN, GTP-U, Geneve, Teredo, L2TP and UDP-encapsulated ESP.
//!
//! Every one of those layers spends from a single per-frame budget, so
//! attacker-controlled nesting terminates no matter how the layers are mixed.

use std::net::{IpAddr, SocketAddr};

use crate::error::CaptureError;
use ahash::RandomState;
use chrono::{DateTime, Utc};
use etherparse::{
    IpNumber, Ipv6ExtensionSlice, NetSlice, SlicedPacket, TcpSlice, TransportSlice, UdpSlice,
};
use indexmap::IndexMap;

use super::packet::Packet;
use super::tunnel::{self, Inner};

// ── Public types ──────────────────────────────────────────────────────

// The transport vocabulary type lives in the dependency-free `crate::net`
// leaf module (sip/rtp/security need it without depending on capture);
// re-exported here for backward compatibility.
pub use crate::net::TransportProto;

/// TCP header flags relevant for reassembly and connection tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    /// SYN: connection initiation.
    pub syn: bool,
    /// ACK: acknowledgment.
    pub ack: bool,
    /// FIN: connection teardown.
    pub fin: bool,
    /// RST: connection reset.
    pub rst: bool,
    /// PSH: push data to application.
    pub psh: bool,
}

/// A parsed network packet with extracted header fields and transport payload.
///
/// Produced by [`parse_packet`] after walking through link, network, and
/// transport headers. Contains everything needed for reassembly and
/// Where a packet's addressing came from, which decides whether sipnab may
/// transmit in response to it.
///
/// This is a security control, not bookkeeping. Scanner-kill sends a packet to
/// the address it believes a scanner is at, so the trustworthiness of that
/// address is the whole question, and the three cases differ:
///
/// - [`Wire`](Self::Wire) — read from an observed IP header, on a device or in
///   a capture file. sipnab saw the addressing itself, so a response goes where
///   the traffic came from.
/// - [`Hep`](Self::Hep) — asserted by a remote HEP sender in chunks. Absent
///   `--hep-auth` an attacker chooses those bytes and could steer a response at
///   a victim of their choosing, so this is ineligible unless the operator opts
///   in with `--hep-allow-kill` (SN-01).
/// - [`Uprobe`](Self::Uprobe) — read out of a process's TLS library, where
///   **there is no addressing at all**. sipnab never observed a socket, so there
///   is no address a response could honestly be sent to. Ineligible always,
///   with no opt-in, because the opt-in would be an invitation to transmit at a
///   guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputOrigin {
    /// Addressing observed in an IP header.
    #[default]
    Wire,
    /// Addressing asserted by a remote HEP sender.
    Hep,
    /// No addressing observed; bytes lifted from a process.
    Uprobe,
}

/// upper-layer parsing.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Timestamp from the original capture.
    pub timestamp: DateTime<Utc>,
    /// Source IP address (innermost, after encapsulation stripping).
    pub src_addr: IpAddr,
    /// Destination IP address (innermost, after encapsulation stripping).
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// Transport-layer protocol.
    pub transport: TransportProto,
    /// Transport-layer payload bytes (e.g., SIP message body, RTP packet).
    pub payload: bytes::Bytes,
    /// Pointer back to the frame this was parsed out of, when it has one.
    ///
    /// Carried across the parse boundary because it dies here otherwise: the
    /// [`crate::capture::packet::Packet`] knows its source and ordinal, and
    /// everything downstream — dialogs, streams, findings, reports — is built
    /// from `ParsedPacket` and never sees the `Packet` again. A fact with no
    /// route back to its bytes is an assertion, which is the whole of #128.
    ///
    /// `None` for synthetic packets, which is most of the ones built by hand
    /// in tests. That is the honest value: a packet nobody read from anything
    /// has no provenance, and a downstream guess would be worse than the gap.
    /// Where this frame sat, carried as `Copy` so the parser touches no
    /// refcount. Materialise it with `FrameLocator::to_frame_ref()` at the
    /// point a fact actually keeps the pointer — see the type's docs for why
    /// building one per packet cost ~40% of the packet path in atomics.
    pub frame: Option<crate::capture::packet::FrameLocator>,
    /// IP fragment identification (IPv4 16-bit `Identification`, or the IPv6
    /// Fragment extension header's 32-bit `Identification`) for reassembly
    /// keying. `None` when the packet is not fragmented.
    pub ip_id: Option<u32>,
    /// TCP sequence number (present only for TCP packets).
    pub tcp_seq: Option<u32>,
    /// TCP flags (present only for TCP packets).
    pub tcp_flags: Option<TcpFlags>,
    /// IPv4 fragment offset in 8-byte units (`None` if not fragmented or IPv6).
    pub fragment_offset: Option<u16>,
    /// Whether the More Fragments (MF) flag is set.
    pub more_fragments: bool,
    /// The IP protocol number of the payload (for fragment reassembly key).
    pub ip_protocol: u8,
    /// The six-bit Differentiated Services Code Point of the innermost IP
    /// header ([RFC 2474](https://www.rfc-editor.org/rfc/rfc2474) §3): the
    /// IPv4 `TOS` byte or the IPv6 `Traffic Class` byte, shifted past the two
    /// ECN bits.
    ///
    /// Read from the header the packet actually carried, and read innermost,
    /// so a tunneled call reports the marking its own operator set rather
    /// than the carrier's outer marking.
    ///
    /// `None` is not "unmarked" — 0 is unmarked, and it is the default PHB
    /// that most misconfigurations produce, so the two must not collapse into
    /// one value. `None` means NO IP HEADER WAS OBSERVED: the HEP path, whose
    /// addressing arrives in chunks a remote sender asserted rather than from
    /// a header sipnab read, and synthetic packets built by hand. Reporting 0
    /// there would state "this call is unmarked" about a call sipnab never saw
    /// the marking of, which is the failure this feature exists to prevent in
    /// the other direction.
    pub dscp: Option<u8>,
    /// Where this packet's addressing came from.
    ///
    /// Load-bearing for active responses: see [`InputOrigin`]. This replaced a
    /// bare `from_hep: bool`, which could describe only two of the three real
    /// cases and would have had to call a uprobe read "HEP" to make it safe.
    pub input_origin: InputOrigin,
}

// ── ICMP error quotes ─────────────────────────────────────────────────
//
// An ICMP error is the only packet in a SIP capture that states a cause
// instead of implying one. A port-unreachable quoting an INVITE says the far
// end was not listening on that port — categorically, from the network itself
// — where the surrounding traffic says only that nothing came back. sipnab
// dropped every ICMP packet at the transport switch, so a capture that
// contained the answer produced a report that said "unanswered".
//
// Two facts govern everything below.
//
// **The quote is truncated by design.** RFC 792 obliges a router to return the
// original IP header plus 8 bytes and nothing more; RFC 1812 §4.3.2.3 asks for
// as much as will fit in 576 octets, and most stacks oblige, but nothing
// guarantees it. So the quoted bytes are a PREFIX of a request. They are
// evidence ABOUT a message, never a message: they are not parsed as SIP here,
// never become a `ParsedPacket`, and can never reach a message count or a
// dialog's message ladder. `parse_packet` still returns `CaptureError::Icmp`
// for these packets, exactly as before.
//
// **There are two addresses and they mean opposite things.** The ICMP header's
// own source is the router or host REPORTING the failure. The quoted
// datagram's destination is the endpoint that DID NOT ANSWER. They are
// frequently different hosts — a "host unreachable" comes from the last router
// that could still forward — and naming the reporter as the failure would
// send an operator to debug a device that is working. `IcmpQuote` keeps all
// four addresses under names that cannot be confused.

/// Which RFC 792 / RFC 4443 error an ICMP message reports.
///
/// Only the types that quote the datagram that provoked them are represented.
/// ICMPv4 Redirect (type 5) quotes one too, but it reports a better route
/// rather than a failure, and reading it as a failure would turn a working
/// path into a reported fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// ICMPv4 type 3 / ICMPv6 type 1 — the datagram could not be delivered.
    DestinationUnreachable,
    /// ICMPv4 type 11 / ICMPv6 type 3 — TTL or reassembly time exceeded.
    TimeExceeded,
    /// ICMPv4 type 12 / ICMPv6 type 4 — a malformed header field.
    ParameterProblem,
    /// ICMPv4 type 4 — congestion. Deprecated by RFC 6633, still seen.
    SourceQuench,
    /// ICMPv6 type 2 — the datagram exceeded a link MTU. The PMTU black hole
    /// behind "large INVITEs vanish, small requests work".
    PacketTooBig,
}

/// An ICMP or ICMPv6 error and the datagram it quotes.
///
/// Produced by [`parse_icmp_error`]. Every field beginning `quoted_` describes
/// the ORIGINAL datagram that failed; `reporter` / `reported_to` describe the
/// ICMP message carrying the news. See the module-level note above for why
/// that distinction is enforced by naming rather than left to the reader.
#[derive(Debug, Clone)]
pub struct IcmpQuote {
    /// Capture time of the ICMP error itself.
    pub timestamp: DateTime<Utc>,
    /// Source of the ICMP message: the router or host REPORTING the failure.
    /// Not necessarily — and for `host unreachable` usually not — the endpoint
    /// that failed to answer.
    pub reporter: IpAddr,
    /// Destination of the ICMP message: the sender of the failed datagram,
    /// being told that it failed.
    pub reported_to: IpAddr,
    /// Which error class this is.
    pub kind: IcmpErrorKind,
    /// Raw ICMP type byte, kept so an unrecognised code is still reportable.
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    /// Source address of the quoted datagram — who sent the request that
    /// failed.
    pub quoted_src: IpAddr,
    /// Destination address of the quoted datagram — THE ENDPOINT THAT DID NOT
    /// ANSWER. This is the address a finding should name.
    pub quoted_dst: IpAddr,
    /// IP protocol number of the quoted datagram.
    pub quoted_protocol: u8,
    /// Transport of the quoted datagram, when it is one sipnab carries SIP
    /// over. `None` for anything else, and for a quoted non-first fragment,
    /// which has no transport header at all.
    pub quoted_transport: Option<TransportProto>,
    /// Source port of the quoted datagram. `None` when the quote stopped
    /// before the transport header.
    pub quoted_src_port: Option<u16>,
    /// Destination port of the quoted datagram — the port that was not
    /// listening. `None` when the quote stopped before the transport header.
    pub quoted_dst_port: Option<u16>,
    /// A PREFIX of the original transport payload. May be empty (RFC 792's
    /// 8-byte minimum covers only the UDP header) and may stop mid-header.
    /// Never a complete message unless [`Self::quoted_truncated`] is false,
    /// and not certainly one even then.
    pub quoted_payload: bytes::Bytes,
    /// True when the quoted datagram's own IP length field declares more bytes
    /// than the quote carries. False means the quote is NOT KNOWN to be
    /// truncated — for a zero or unreadable length field sipnab cannot tell,
    /// and reporting "complete" on that basis would be a guess.
    pub quoted_truncated: bool,
}

impl IcmpQuote {
    /// Plain-language rendering of this error's type and code.
    ///
    /// Static strings from RFC 792 §Destination Unreachable / RFC 4443 §3, so
    /// a finding can quote the network's own words instead of a bare `3/1`.
    pub fn description(&self) -> &'static str {
        let (t, c) = (self.icmp_type, self.icmp_code);
        if self.reporter.is_ipv6() {
            return match (t, c) {
                (1, 0) => "no route to destination",
                (1, 1) => "communication with destination administratively prohibited",
                (1, 2) => "beyond scope of source address",
                (1, 3) => "address unreachable",
                (1, 4) => "port unreachable",
                (1, 5) => "source address failed ingress/egress policy",
                (1, 6) => "reject route to destination",
                (1, _) => "destination unreachable",
                (2, _) => "packet too big",
                (3, 0) => "hop limit exceeded in transit",
                (3, 1) => "fragment reassembly time exceeded",
                (3, _) => "time exceeded",
                (4, _) => "parameter problem",
                _ => "ICMPv6 error",
            };
        }
        match (t, c) {
            (3, 0) => "network unreachable",
            (3, 1) => "host unreachable",
            (3, 2) => "protocol unreachable",
            (3, 3) => "port unreachable",
            (3, 4) => "fragmentation needed and DF set",
            (3, 5) => "source route failed",
            (3, 9) => "network administratively prohibited",
            (3, 10) => "host administratively prohibited",
            (3, 13) => "communication administratively prohibited",
            (3, _) => "destination unreachable",
            (4, _) => "source quench",
            (11, 0) => "TTL exceeded in transit",
            (11, 1) => "fragment reassembly time exceeded",
            (11, _) => "time exceeded",
            (12, _) => "parameter problem",
            _ => "ICMP error",
        }
    }
}

/// Fields recovered from the quoted (original, failed) datagram.
///
/// Borrows the quote so the payload stays zero-copy; the caller turns it into
/// refcounted [`bytes::Bytes`] against the capture buffer.
struct QuotedDatagram<'a> {
    /// Sender of the failed datagram.
    src: IpAddr,
    /// Intended recipient of the failed datagram: the endpoint that did not
    /// answer.
    dst: IpAddr,
    /// IP protocol number.
    protocol: u8,
    /// Transport, when recognized.
    transport: Option<TransportProto>,
    /// Source port, when the quote reached it.
    src_port: Option<u16>,
    /// Destination port, when the quote reached it.
    dst_port: Option<u16>,
    /// Whatever of the transport payload the quote carried.
    payload: &'a [u8],
    /// The IP length field declared more than the quote carries.
    truncated: bool,
}

/// Map an ICMP type to the error class it reports, or `None` when the message
/// is not an error that quotes a datagram (echo, router advertisement,
/// neighbor discovery, redirect).
fn icmp_error_kind(icmp_type: u8, v6: bool) -> Option<IcmpErrorKind> {
    if v6 {
        return match icmp_type {
            1 => Some(IcmpErrorKind::DestinationUnreachable),
            2 => Some(IcmpErrorKind::PacketTooBig),
            3 => Some(IcmpErrorKind::TimeExceeded),
            4 => Some(IcmpErrorKind::ParameterProblem),
            _ => None,
        };
    }
    match icmp_type {
        3 => Some(IcmpErrorKind::DestinationUnreachable),
        4 => Some(IcmpErrorKind::SourceQuench),
        11 => Some(IcmpErrorKind::TimeExceeded),
        12 => Some(IcmpErrorKind::ParameterProblem),
        _ => None,
    }
}

/// Ports and payload from a quoted transport header, tolerating truncation.
///
/// Returns `(transport, src_port, dst_port, payload)`. Every step is
/// length-checked separately: RFC 792's 8-byte minimum yields ports but no
/// payload for UDP, and ports but no payload for TCP (whose data offset lives
/// at byte 12). Reading past what is present is exactly how a header prefix
/// gets mistaken for a message.
fn quoted_transport_fields(
    protocol: u8,
    t: &[u8],
) -> (Option<TransportProto>, Option<u16>, Option<u16>, &[u8]) {
    let ports = if t.len() >= 4 {
        (
            Some(u16::from_be_bytes([t[0], t[1]])),
            Some(u16::from_be_bytes([t[2], t[3]])),
        )
    } else {
        (None, None)
    };
    let empty = &t[..0];
    match protocol {
        // UDP: fixed 8-byte header. The length field bounds the payload, but a
        // truncated quote holds less than it claims, so take the smaller.
        17 => {
            let payload = if t.len() >= 8 {
                let declared = usize::from(u16::from_be_bytes([t[4], t[5]])).saturating_sub(8);
                &t[8..(8 + declared).min(t.len())]
            } else {
                empty
            };
            (Some(TransportProto::Udp), ports.0, ports.1, payload)
        }
        // TCP: variable header; the data offset is at byte 12, so a quote
        // shorter than 20 bytes yields ports and nothing else.
        6 => {
            let payload = if t.len() >= 20 {
                let off = usize::from(t[12] >> 4) * 4;
                if off >= 20 && off <= t.len() {
                    &t[off..]
                } else {
                    empty
                }
            } else {
                empty
            };
            (Some(TransportProto::Tcp), ports.0, ports.1, payload)
        }
        // SCTP: the payload lives in a DATA chunk. `find_sctp_data_chunk`
        // requires a complete chunk, so a truncated quote yields ports only —
        // which is the honest answer.
        132 => {
            let payload = find_sctp_data_chunk(t, true)
                .and_then(|c| t.get(c.payload))
                .unwrap_or(empty);
            (Some(TransportProto::Sctp), ports.0, ports.1, payload)
        }
        _ => (None, None, None, empty),
    }
}

/// Parse the IPv4 datagram an ICMP error quotes, tolerating truncation.
fn parse_quoted_ipv4(q: &[u8]) -> Option<QuotedDatagram<'_>> {
    if q.len() < 20 {
        return None;
    }
    let ihl = usize::from(q[0] & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([q[2], q[3]]));
    let frag_offset = u16::from_be_bytes([q[6], q[7]]) & 0x1fff;
    let protocol = q[9];
    let src = IpAddr::from([q[12], q[13], q[14], q[15]]);
    let dst = IpAddr::from([q[16], q[17], q[18], q[19]]);

    // A zero Total Length says nothing (segmentation offload writes it), so it
    // is reported as "not known to be truncated" rather than as complete.
    let truncated = total_len > q.len() || ihl > q.len();
    // Never read past what the datagram declared, even if the ICMP message
    // carried trailing padding.
    let end = if total_len >= ihl {
        total_len.min(q.len())
    } else {
        q.len()
    };
    let after_ip = q.get(ihl.min(end)..end).unwrap_or(&q[..0]);

    // A non-first fragment carries no transport header: its ports live in the
    // first fragment, which this ICMP error is not about.
    let (transport, src_port, dst_port, payload) = if frag_offset != 0 {
        (None, None, None, &q[..0])
    } else {
        quoted_transport_fields(protocol, after_ip)
    };

    Some(QuotedDatagram {
        src,
        dst,
        protocol,
        transport,
        src_port,
        dst_port,
        payload,
        truncated,
    })
}

/// IPv6 extension headers that use the `(next header, length in 8-octet units
/// minus one)` shape, so they can be skipped without understanding them.
const IPV6_EXT_SKIPPABLE: [u8; 6] = [
    0,   // Hop-by-Hop Options
    43,  // Routing
    60,  // Destination Options
    135, // Mobility
    139, // Host Identity Protocol
    140, // Shim6
];

/// Walk past IPv6 extension headers to the transport header.
///
/// Returns `(protocol, transport bytes)`, or `None` when the chain runs off
/// the end of a truncated quote or reaches a header whose payload cannot be
/// read (ESP, or a fragment that is not the first). Bounded at eight headers:
/// a longer chain in an ICMP quote is a malformed packet, not a SIP call.
fn skip_ipv6_extensions(first: u8, mut body: &[u8]) -> Option<(u8, &[u8])> {
    let mut next = first;
    for _ in 0..8 {
        if IPV6_EXT_SKIPPABLE.contains(&next) {
            let len = 8 + usize::from(*body.get(1)?) * 8;
            next = *body.first()?;
            body = body.get(len..)?;
        } else if next == 44 {
            // Fragment header: fixed 8 bytes. Only the first fragment carries
            // the transport header the ports would come from.
            let offset = u16::from_be_bytes([*body.get(2)?, *body.get(3)?]) & 0xfff8;
            if offset != 0 {
                return None;
            }
            next = *body.first()?;
            body = body.get(8..)?;
        } else if next == 51 {
            // Authentication Header: length is in 4-octet units minus two.
            let len = (usize::from(*body.get(1)?) + 2) * 4;
            next = *body.first()?;
            body = body.get(len..)?;
        } else {
            return Some((next, body));
        }
    }
    None
}

/// Parse the IPv6 datagram an ICMPv6 error quotes, tolerating truncation.
fn parse_quoted_ipv6(q: &[u8]) -> Option<QuotedDatagram<'_>> {
    if q.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([q[4], q[5]]));
    let next_header = q[6];
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&q[8..24]);
    dst_octets.copy_from_slice(&q[24..40]);

    let truncated = 40 + payload_len > q.len();
    let end = (40 + payload_len).min(q.len()).max(40);
    let body = &q[40..end];

    let (transport, src_port, dst_port, payload) = match skip_ipv6_extensions(next_header, body) {
        Some((protocol, t)) => quoted_transport_fields(protocol, t),
        None => (None, None, None, &q[..0]),
    };

    Some(QuotedDatagram {
        src: IpAddr::from(src_octets),
        dst: IpAddr::from(dst_octets),
        protocol: next_header,
        transport,
        src_port,
        dst_port,
        payload,
        truncated,
    })
}

/// An ICMP message's own header fields and payload, read from either an
/// [`etherparse::Icmpv4Slice`] or an [`etherparse::Icmpv6Slice`].
///
/// The two slices carry the same three facts under different types, and the
/// decoder needs the same three from both; keeping them together is also what
/// lets `icmp_quote` stay inside a readable argument count.
struct IcmpMessage<'a> {
    /// Raw ICMP type byte.
    icmp_type: u8,
    /// Raw ICMP code byte.
    icmp_code: u8,
    /// Bytes past the 8-byte ICMP header: the quoted datagram, for an error.
    payload: &'a [u8],
    /// ICMPv6 rather than ICMPv4 — the type numbers mean different things.
    v6: bool,
}

/// Build an [`IcmpQuote`] from an ICMP message's own addresses and payload.
///
/// The single decoder behind both the public [`parse_icmp_error`] and the
/// recording hook in [`extract_parsed_packet`], so the evidence sipnab records
/// during a capture and the evidence a test reads back are produced by the
/// same code.
///
/// Returns `None` when the message is not an error that quotes a datagram, or
/// when the quote is too short to name both endpoints — an ICMP error that
/// cannot say WHICH host failed is not evidence about anything.
fn icmp_quote(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    reporter: IpAddr,
    reported_to: IpAddr,
    msg: &IcmpMessage<'_>,
) -> Option<IcmpQuote> {
    let kind = icmp_error_kind(msg.icmp_type, msg.v6)?;
    let q = if msg.v6 {
        parse_quoted_ipv6(msg.payload)
    } else {
        parse_quoted_ipv4(msg.payload)
    }?;
    Some(IcmpQuote {
        timestamp,
        reporter,
        reported_to,
        kind,
        icmp_type: msg.icmp_type,
        icmp_code: msg.icmp_code,
        quoted_src: q.src,
        quoted_dst: q.dst,
        quoted_protocol: q.protocol,
        quoted_transport: q.transport,
        quoted_src_port: q.src_port,
        quoted_dst_port: q.dst_port,
        quoted_payload: slice_of(data, q.payload),
        quoted_truncated: q.truncated,
    })
}

/// The outer IP addresses of a sliced packet, or `None` for ARP.
fn net_addresses(net: &NetSlice<'_>) -> Option<(IpAddr, IpAddr)> {
    match net {
        NetSlice::Ipv4(v4) => Some((
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        )),
        NetSlice::Ipv6(v6) => Some((
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        )),
        NetSlice::Arp(_) => None,
    }
}

/// Read the ICMP/ICMPv6 error in a raw captured packet, with the datagram it
/// quotes.
///
/// The read-only counterpart to [`parse_packet`], which still rejects these
/// packets with [`CaptureError::Icmp`]: an ICMP error is evidence ABOUT a
/// message, so it must never become a `ParsedPacket` and inflate a message
/// count. Encapsulation (IP-in-IP, 6in4, GRE) is stripped the same way
/// `parse_packet` strips it, so a tunneled ICMP error is read too.
///
/// # Returns
///
/// `None` for a non-ICMP packet, for an ICMP message that is not an error
/// (echo, neighbor discovery), for ICMPv4 Redirect (a routing hint, not a
/// failure), for a pre-parsed HEP packet (which carries no IP header to read),
/// and for a quote too short to name both endpoints.
///
/// # Examples
///
/// ```
/// use sipnab::capture::packet::Packet;
/// use sipnab::capture::parse::{IcmpErrorKind, parse_icmp_error};
///
/// // Raw-IP (DLT_RAW = 12) ICMPv4 port-unreachable quoting a UDP datagram
/// // sent 10.0.0.1:5060 -> 10.0.0.2:5060.
/// let quoted: Vec<u8> = vec![
///     0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, // IPv4, proto 17 (UDP)
///     10, 0, 0, 1, 10, 0, 0, 2, //
///     0x13, 0xc4, 0x13, 0xc4, 0, 8, 0, 0, // 5060 -> 5060
/// ];
/// let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0]; // type 3, code 3
/// icmp.extend_from_slice(&quoted);
/// let mut frame: Vec<u8> = vec![
///     0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, // IPv4, proto 1 (ICMP)
///     203, 0, 113, 1, 10, 0, 0, 1, // router -> sender
/// ];
/// frame.extend_from_slice(&icmp);
/// let total = frame.len() as u16;
/// frame[2..4].copy_from_slice(&total.to_be_bytes());
///
/// let len = frame.len();
/// let pkt = Packet::new(chrono::Utc::now(), frame, len, len, None, 12);
/// let q = parse_icmp_error(&pkt).expect("an ICMP error");
/// assert_eq!(q.kind, IcmpErrorKind::DestinationUnreachable);
/// assert_eq!(q.description(), "port unreachable");
/// // The endpoint that did not answer — not the router that said so.
/// assert_eq!(q.quoted_dst.to_string(), "10.0.0.2");
/// assert_eq!(q.quoted_dst_port, Some(5060));
/// assert_eq!(q.reporter.to_string(), "203.0.113.1");
/// ```
pub fn parse_icmp_error(packet: &Packet) -> Option<IcmpQuote> {
    // A pre-parsed (HEP) packet delivers a transport payload with addressing
    // asserted out of band; there is no IP header, so there is no quote.
    if packet.pre_parsed.is_some() {
        return None;
    }
    let sliced = slice_link_layer(packet.link_type, &packet.data, &mut Budget::new()).ok()?;
    icmp_from_sliced(packet.timestamp, &packet.data, &sliced, 0)
}

/// Walk `sliced` (stripping encapsulation) to an ICMP transport and decode it.
fn icmp_from_sliced(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    sliced: &SlicedPacket<'_>,
    depth: u8,
) -> Option<IcmpQuote> {
    let net = sliced.net.as_ref()?;
    let ip_payload = net.ip_payload_ref()?;

    if depth < MAX_ENCAP_DEPTH && !ip_payload.fragmented {
        let inner = match ip_payload.ip_number {
            IpNumber::IPV4 | IpNumber::IPV6 => Some(ip_payload.payload),
            IpNumber::GRE => match gre_inner_offset(ip_payload.payload) {
                Ok((ETHERTYPE_IPV4 | ETHERTYPE_IPV6, off)) => ip_payload.payload.get(off..),
                _ => None,
            },
            _ => None,
        };
        if let Some(inner) = inner {
            let s = SlicedPacket::from_ip(inner).ok()?;
            return icmp_from_sliced(timestamp, data, &s, depth + 1);
        }
    }

    let (reporter, reported_to) = net_addresses(net)?;
    let msg = match sliced.transport.as_ref()? {
        TransportSlice::Icmpv4(icmp) => IcmpMessage {
            icmp_type: icmp.type_u8(),
            icmp_code: icmp.code_u8(),
            payload: icmp.payload(),
            v6: false,
        },
        TransportSlice::Icmpv6(icmp) => IcmpMessage {
            icmp_type: icmp.type_u8(),
            icmp_code: icmp.code_u8(),
            payload: icmp.payload(),
            v6: true,
        },
        _ => return None,
    };
    icmp_quote(timestamp, data, reporter, reported_to, &msg)
}

// ── DLT constants ─────────────────────────────────────────────────────

/// Pcap link type for BSD loopback encapsulation (DLT_NULL).
const DLT_NULL: i32 = 0;
/// Pcap link type for Ethernet II (DLT_EN10MB).
const DLT_EN10MB: i32 = 1;
/// Pcap link type for OpenBSD loopback encapsulation (DLT_LOOP).
const DLT_LOOP: i32 = 108;
/// Pcap link type for raw IPv4/IPv6 (DLT_RAW).
const DLT_RAW: i32 = 12;
/// Pcap link type for Linux cooked capture v1 (DLT_LINUX_SLL).
const DLT_LINUX_SLL: i32 = 113;
/// Pcap link type for Linux cooked capture v2 (DLT_LINUX_SLL2).
const DLT_LINUX_SLL2: i32 = 276;
/// Pcap link type for PPP (DLT_PPP), with or without HDLC-like framing.
const DLT_PPP: i32 = 9;
/// Pcap link type for PPP in HDLC-like framing (DLT_PPP_SERIAL).
const DLT_PPP_SERIAL: i32 = 50;
/// Pcap link type for PPPoE session packets (DLT_PPP_ETHER).
const DLT_PPP_ETHER: i32 = 51;
/// Pcap link type for a bare IPv4 datagram (DLT_IPV4).
const DLT_IPV4: i32 = 228;
/// Pcap link type for a bare IPv6 datagram (DLT_IPV6).
const DLT_IPV6: i32 = 229;

/// Every link layer this parser decodes, as a CLOSED set.
///
/// # Why an enum and not the raw DLT number
///
/// Two walks read a frame's link headers: [`slice_link_layer`] for the full
/// parse, and [`peek_host_pair`] for the cheap `--cores N` shard key. Both
/// used to `match` on the `i32` — a match over integers always needs a
/// wildcard arm, so a link type added to one walk compiled perfectly in the
/// other and simply fell through it. That is not a hypothetical: it is the
/// shape of every divergence this type exists to prevent, and each one was
/// found by a person reading one arm rather than by anything mechanical.
///
/// Both walks now dispatch on this enum with an EXHAUSTIVE match and no
/// wildcard. Adding a variant is a COMPILE error in both until each has an
/// arm for it, which is the strongest available statement that the shard key
/// and the parse know the same set of link types. `tests/shard_peek_parity_test.rs`
/// keeps the wildcard from being reintroduced and enumerates one frame per
/// link type and encapsulation.
///
/// What it does NOT close over, stated rather than implied: an
/// *encapsulation* — a VLAN tag, PPPoE, MPLS, NSH, a PBB I-TAG, MACsec — is
/// not a variant here. Those are arms of [`eth_payload`] and [`sll_payload`],
/// which both walks already share, so the compiler has nothing to check;
/// the parity test reads those arms out of this file's source instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkType {
    /// Ethernet II — `DLT_EN10MB`.
    Ethernet,
    /// Linux cooked capture v1 — `DLT_LINUX_SLL`, what `-i any` writes.
    LinuxSll,
    /// Linux cooked capture v2 — `DLT_LINUX_SLL2`.
    LinuxSll2,
    /// Raw IP of either version — `DLT_RAW`.
    Raw,
    /// A bare IPv4 datagram — `DLT_IPV4`, which declares its own version.
    BareIpv4,
    /// A bare IPv6 datagram — `DLT_IPV6`.
    BareIpv6,
    /// BSD loopback — `DLT_NULL`, address family in the writing host's order.
    BsdNull,
    /// OpenBSD loopback — `DLT_LOOP`, address family in network order.
    BsdLoop,
    /// PPP — `DLT_PPP`, with or without RFC 1662 §3.1 HDLC-like framing.
    Ppp,
    /// PPP in HDLC-like framing — `DLT_PPP_SERIAL`.
    PppSerial,
    /// A bare PPPoE session packet — `DLT_PPP_ETHER`.
    PppEther,
}

impl LinkType {
    /// Recognize a captured frame's libpcap link-type number.
    ///
    /// `None` for a link type this parser does not decode; the full parse
    /// turns that into [`CaptureError::UnsupportedLinkType`] and the shard
    /// peek into "no key", which the dispatcher sends to worker 0.
    ///
    /// A `match` rather than a scan of a table: this runs once per packet on
    /// the `--cores` dispatcher's serial path, and it allocates nothing.
    fn from_dlt(dlt: i32) -> Option<Self> {
        Some(match dlt {
            DLT_EN10MB => Self::Ethernet,
            DLT_LINUX_SLL => Self::LinuxSll,
            DLT_LINUX_SLL2 => Self::LinuxSll2,
            DLT_RAW => Self::Raw,
            DLT_IPV4 => Self::BareIpv4,
            DLT_IPV6 => Self::BareIpv6,
            DLT_NULL => Self::BsdNull,
            DLT_LOOP => Self::BsdLoop,
            DLT_PPP => Self::Ppp,
            DLT_PPP_SERIAL => Self::PppSerial,
            DLT_PPP_ETHER => Self::PppEther,
            _ => return None,
        })
    }
}

// ── BSD loopback (DLT_NULL / DLT_LOOP) constants ──────────────────────

/// Length of the BSD loopback header: one 4-byte address family, then IP.
const LOOPBACK_HEADER_LEN: usize = 4;

/// `AF_INET` — 2 on every BSD, on macOS and on Linux alike.
const BSD_AF_INET: u32 = 2;

/// The `AF_INET6` values a loopback capture can legitimately carry.
///
/// A set rather than a single constant because `AF_INET6` is an OS ABI number,
/// not a protocol number: nobody ever registered it, and the BSDs picked
/// different values. 10 is Linux, 24 is NetBSD / OpenBSD / BSD-OS (and what
/// Npcap writes on Windows), 28 is FreeBSD, 30 is macOS. libpcap's own
/// consumers enumerate exactly these — tcpdump's `BSD_AFNUM_INET6_BSD` /
/// `_FREEBSD` / `_DARWIN` and Wireshark's `packet-null.c` — because the value
/// in the file is the *writing* host's, and a capture taken on a FreeBSD SBC
/// is read on a macOS laptop every day of the week. Hard-coding the local
/// host's number would drop the other three platforms' loopback traffic in
/// silence, which is the failure this whole arm exists to remove.
const BSD_AF_INET6: [u32; 4] = [10, 24, 28, 30];

/// Whether a BSD address-family number names an IP family.
///
/// Anything else — `AF_UNSPEC`, `AF_ISO`, `AF_APPLETALK`, `AF_IPX` — is a
/// frame whose payload is not an IP header, so slicing it as one would report
/// addresses and ports that the wire never carried.
fn is_bsd_ip_family(af: u32) -> bool {
    af == BSD_AF_INET || BSD_AF_INET6.contains(&af)
}

/// Offset of the IP header inside a BSD loopback frame, or `None` if the
/// frame is truncated or names a family that is not IP.
///
/// DLT_NULL (link type 0) and DLT_LOOP (108) are identical but for the byte
/// order of that 4-byte family word, so both arrive here and `link_type`
/// decides how it is read:
///
/// * **DLT_LOOP** carries the family in network byte order, always — that is
///   the entire reason OpenBSD defined a second link type, and libpcap's
///   link-type list says so. Only the big-endian reading is accepted; swapping
///   it "helpfully" would erase the one distinction the link type exists to
///   make.
/// * **DLT_NULL** carries it in the *writing host's* order. In principle the
///   pcap file's own magic settles that, but the byte order does not survive
///   into a [`Packet`] here (and a live DLT_NULL capture has no file order at
///   all), so this accepts either reading — the conventional approach, and a
///   safe one, because the two readings cannot alias. Every legal family value
///   is below 256 and non-zero, so a host-order word is `XX 00 00 00` and a
///   network-order word is `00 00 00 XX`; a given 4-byte word can satisfy at
///   most one of them. The single value where they would coincide is 0, and 0
///   is `AF_UNSPEC`, which is not an IP family and is rejected either way.
///
/// Capture data is attacker-controlled, so the length is checked before the
/// read and nothing is sliced without `.get()`.
fn loopback_ip_offset(d: &[u8], link_type: LinkType) -> Option<usize> {
    let raw: [u8; 4] = d.get(..LOOPBACK_HEADER_LEN)?.try_into().ok()?;
    if is_bsd_ip_family(u32::from_be_bytes(raw))
        || (link_type == LinkType::BsdNull && is_bsd_ip_family(u32::from_le_bytes(raw)))
    {
        return Some(LOOPBACK_HEADER_LEN);
    }
    None
}

// ── Ethernet EtherType / PPPoE constants ──────────────────────────────

/// 802.1Q VLAN tag protocol identifier; the tag it introduces is 4 bytes.
const ETHERTYPE_VLAN: u16 = 0x8100;
/// 802.1ad provider-bridging (QinQ) tag protocol identifier.
const ETHERTYPE_QINQ: u16 = 0x88A8;
/// Legacy double-tagging TPID, walked as a VLAN tag on purpose.
///
/// **0x9100 is unregistered, and that is not an oversight.** EtherTypes are
/// assigned by the IEEE Registration Authority, not by IANA — RFC 9542 §2 says
/// exactly that, and IANA's own `ieee-802-numbers` registry is informational.
/// 0x9100 does not appear anywhere in the IEEE RA's public EtherType listing:
/// no assignee, no protocol text. The registered tag TPIDs are 0x8100
/// (802.1Q C-TAG) and 0x88A8 (802.1ad S-TAG, assigned to the IEEE 802.1 Chair).
///
/// It is here because 0x9100 predates 802.1ad and is still configured as the
/// service-tag TPID on deployed carrier equipment — the same generation of
/// gear that still runs PPPoE, which is how a 0x9100 tag comes to sit in front
/// of a frame sipnab needs to decapsulate. Supporting it is a concession to
/// hardware that exists, NOT a claim of spec conformance, so do not delete it
/// after checking a registry and finding nothing. `etherparse` walks it too
/// (`EtherType::VLAN_DOUBLE_TAGGED_FRAME`), so omitting it here made sipnab's
/// own walk and the slicer disagree about where a frame's payload begins.
const ETHERTYPE_VLAN_LEGACY: u16 = 0x9100;

/// Maximum stacked VLAN tags walked before a frame is refused.
///
/// 802.1Q-2022 gives a frame one C-TAG; 802.1ad provider bridging adds an
/// S-TAG outside it, for two. Real carrier gear stacks a third
/// (S-TAG + S-TAG + C-TAG); nothing standardized goes past that.
/// `etherparse` — the slicer the full-parse path uses — keeps at most
/// `SlicedPacket::LINK_EXTS_CAP` (3) link extensions and stops walking after
/// them, so a fourth tag is already invisible to the full parse; matching that
/// bound is what keeps the cheap peek and the full parse from disagreeing
/// about the same frame.
///
/// The cap is also what makes the walk's cost independent of the frame.
/// Unbounded, it terminates only by running off the end of the buffer, so a
/// 64 KB frame of nothing but 0x8100 costs ~16k iterations over
/// attacker-controlled bytes, per packet, on the capture hot path.
const MAX_VLAN_TAGS: usize = 3;
/// EtherType for the PPPoE **Session** stage (RFC 2516 §6: "The ETHER_TYPE
/// field is set to 0x8864").
///
/// PPPoE Discovery is a *different* EtherType, 0x8863 (RFC 2516 §5), and is
/// deliberately not decapsulated anywhere in this file: a Discovery frame's
/// payload is TLV tags, so reading it as an IP header would report addresses
/// and ports that the wire never carried.
const ETHERTYPE_PPPOE_SESSION: u16 = 0x8864;

/// MPLS unicast (RFC 3032 §3: "the Ethertype value 8847 hex is used").
const ETHERTYPE_MPLS_UNICAST: u16 = 0x8847;
/// The second MPLS EtherType (RFC 3032 §3: 8848 hex), reassigned by RFC 5332
/// §3 to "MPLS with upstream-assigned label" — which is why it is walked with
/// exactly the same label-stack code and not treated as a different protocol.
const ETHERTYPE_MPLS_UPSTREAM: u16 = 0x8848;
/// Network Service Header (RFC 8300 §2.2 / IEEE RA assignment 0x894F).
const ETHERTYPE_NSH: u16 = 0x894F;
/// MACsec SecTAG (IEEE Std 802.1AE-2018 §9.3).
const ETHERTYPE_MACSEC: u16 = 0x88E5;
/// Provider Backbone Bridge I-TAG (IEEE Std 802.1Q-2014 §9.7).
const ETHERTYPE_PBB_ITAG: u16 = 0x88E7;

/// What an unreadable MACsec frame is called in the diagnosis.
///
/// Phrased as a noun so [`CaptureError::NotIp`]'s "{what} has no IP layer"
/// reads as a sentence an operator can act on. The frame was recognized and
/// its SecTAG validated; what is missing is the key, not the decoder.
const MACSEC_OPAQUE: &str = "MACsec-encrypted frame";

/// PPPoE VER/TYPE octet — RFC 2516 §4 fixes VER at 0x1 and TYPE at 0x1.
const PPPOE_VER_TYPE: u8 = 0x11;
/// PPPoE CODE for a session-stage packet (RFC 2516 §6: "The PPPoE CODE MUST be
/// set to 0x00").
const PPPOE_CODE_SESSION: u8 = 0x00;
/// PPP Protocol field for IPv4.
///
/// PPP Protocol numbers are their own IANA registry and are NOT EtherTypes —
/// 0x0021 here, not 0x0800. Reusing [`ETHERTYPE_IPV4`] would compile and
/// silently reject every PPPoE frame.
const PPP_PROTO_IPV4: u16 = 0x0021;
/// PPP Protocol field for IPv6 (see [`PPP_PROTO_IPV4`] on the registry).
const PPP_PROTO_IPV6: u16 = 0x0057;

/// Offset of the IP header inside a PPPoE Session frame.
///
/// `pppoe_off` is the offset of the PPPoE header itself, i.e. the first byte
/// after the 0x8864 EtherType. RFC 2516 §4 lays that header out as:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  VER  | TYPE  |      CODE     |          SESSION_ID           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            LENGTH             |           payload             ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// and §6 says the session payload "contains a PPP frame. The frame begins
/// with the PPP Protocol-ID", so the IP header sits 6 + 1-or-2 bytes in.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// frame, a header that is not session-stage, or a PPP protocol that carries
/// no IP. Capture data is attacker-controlled, so every read is checked.
///
/// RFC 2516 is Informational and current: no RFC obsoletes or updates it, and
/// none of its eleven errata touch the header layout or the EtherTypes.
fn pppoe_ip_offset(d: &[u8], pppoe_off: usize) -> Option<usize> {
    // VER/TYPE and CODE are what make this a session-stage frame at all. A
    // non-zero CODE means the payload is TAGs (PADI/PADO/PADS/PADT), not a PPP
    // frame; decoding those as IP would manufacture a flow out of bytes that
    // never described one.
    if *d.get(pppoe_off)? != PPPOE_VER_TYPE || *d.get(pppoe_off + 1)? != PPPOE_CODE_SESSION {
        return None;
    }
    // SESSION_ID (2 bytes) and LENGTH (2 bytes) are read only to prove they
    // are present. LENGTH deliberately bounds nothing: a capture taken with a
    // snaplen routinely holds "LENGTH says 1492, caplen is 96", so trusting it
    // would reject ordinary traffic, and it is attacker-controlled besides.
    // The buffer's own length is the only bound used here.
    d.get(pppoe_off + 2..pppoe_off + 6)?;

    ppp_ip_offset(d, pppoe_off + 6)
}

/// Offset of the IP header inside a PPP frame whose PPP header — the Protocol
/// field — begins at `ppp_off`.
///
/// Split out of [`pppoe_ip_offset`] because the PPP Protocol field is the same
/// field wherever PPP is carried: RFC 2516 §6 says a PPPoE session payload
/// "contains a PPP frame. The frame begins with the PPP Protocol-ID", and the
/// PPP link types (DLT_PPP, DLT_PPP_SERIAL) put that same field at the start
/// of the captured frame. One implementation, so the two cannot drift about
/// which protocol numbers mean IP or about how a compressed field is read.
///
/// Returns `None` — never a panic, never a read past `d` — for a truncated
/// frame or a PPP protocol that carries no IP. Capture data is
/// attacker-controlled, so every read is checked.
fn ppp_ip_offset(d: &[u8], ppp_off: usize) -> Option<usize> {
    let first = *d.get(ppp_off)?;
    if first & 1 == 1 {
        // Protocol-Field Compression: a 1-octet field. RFC 1661 §2 assigns PPP
        // Protocol values so that the least significant octet is odd and the
        // most significant octet even, so an odd first byte can only be a
        // compressed field — nothing else aliases it. RFC 2516 §7 makes PFC
        // "NOT RECOMMENDED" on PPPoE rather than forbidden (unlike ACFC, which
        // is a MUST NOT), so a conforming-but-unusual peer may still send it.
        // Handling it costs one mask on a path only PPP frames reach;
        // refusing it would reproduce the exact silence this code removes.
        return match u16::from(first) {
            PPP_PROTO_IPV4 | PPP_PROTO_IPV6 => ppp_off.checked_add(1),
            _ => None,
        };
    }
    match u16::from_be_bytes([first, *d.get(ppp_off + 1)?]) {
        PPP_PROTO_IPV4 | PPP_PROTO_IPV6 => ppp_off.checked_add(2),
        // LCP, IPCP, MPLS-over-PPP, a compression protocol … all real PPP
        // traffic, none of it an IP datagram.
        _ => None,
    }
}

/// HDLC-like framing's Address (0xFF, "All-Stations") and Control (0x03,
/// Unnumbered Information) octets — RFC 1662 §3.1.
const PPP_HDLC_ADDRESS_CONTROL: [u8; 2] = [0xFF, 0x03];

/// Offset of the IP header inside a frame whose *link layer* is PPP, or
/// `None` when the frame carries no IP.
///
/// Three link types share this arm because sipnab already owns every piece
/// they need — the PPPoE header check in [`pppoe_ip_offset`] and the PPP
/// Protocol field in [`ppp_ip_offset`] — and they differ only in what sits in
/// front of that field. libpcap's link-type list settles each one:
///
/// * **DLT_PPP (9)** — "If the first 2 octets are 0xff and 0x03, it's PPP in
///   HDLC-like framing, as specified by Section 3.1 of RFC1662, but without
///   flag octets, with the PPP header following the address and control
///   fields, otherwise it's PPP without framing, and the packet begins with
///   the PPP header." Both shapes are accepted, exactly as written. The two
///   cannot be confused: 0xFF03 is not a legal PPP Protocol number (RFC 1661
///   §2 requires an even most-significant octet), and read as a *compressed*
///   Protocol field 0xFF is not IP either.
/// * **DLT_PPP_SERIAL (50)** — the frames "include the address and control
///   fields as specified by Section 3.1 of RFC1662", so a frame without them
///   is refused rather than guessed at.
/// * **DLT_PPP_ETHER (51)** — "PPPoE session packets, containing the Ethernet
///   payload without an Ethernet header or CRC, as per section 4 of RFC 2516",
///   i.e. the PPPoE header sipnab already decodes, at offset 0.
///
/// Not handled, and named rather than left to look like an oversight: a
/// DLT_PPP_SERIAL frame in **Cisco HDLC** framing (first octet 0x0F or 0x8F,
/// RFC 1547 §4.3.1). That is a different header — address, control, then a
/// two-byte EtherType — and the current libpcap description of this link type
/// does not mention it, so decoding it here would be reading a layout the
/// spec sipnab cites does not describe. Such a frame is counted and named as
/// undecodable, which is the correct outcome for a framing this parser has
/// not been shown to understand.
///
/// No depth is charged from the encapsulation budget: this is the frame's own
/// link header, at depth zero, not a tunnel stacked inside one. Every offset
/// it can return is a small constant plus a bounded PPP Protocol field, so
/// there is nothing here for a hostile frame to iterate.
fn ppp_link_ip_offset(d: &[u8], link_type: LinkType) -> Option<usize> {
    let hdlc_framed = d.get(..2) == Some(&PPP_HDLC_ADDRESS_CONTROL[..]);
    let ppp_off = match link_type {
        LinkType::Ppp if hdlc_framed => 2,
        LinkType::Ppp => 0,
        LinkType::PppSerial if hdlc_framed => 2,
        LinkType::PppEther => return pppoe_ip_offset(d, 0),
        // DLT_PPP_SERIAL without `ff 03`, or a link type that never reaches
        // here.
        _ => return None,
    };
    ppp_ip_offset(d, ppp_off)
}

/// Offset of the IP header in a bare-IP framing that names its own version,
/// or `None` when the frame does not begin with the version it declares.
///
/// libpcap on LINKTYPE_IPV4 (228): "Packets are IPv4 datagrams beginning with
/// an IPv4 header … This should only be used for traffic that consists solely
/// of IPv4 packets, and in which IPv6 packets should be considered errors."
/// LINKTYPE_IPV6 (229) says the same with the versions exchanged, and both
/// point at LINKTYPE_RAW for mixed traffic. So the version nibble is checked
/// against the link type rather than sniffed: a frame that does not begin with
/// the declared version is a broken writer, and reporting a host pair out of
/// it would report something the file does not claim to hold.
///
/// DLT_RAW (12) deliberately does not come through here — it is the framing
/// that carries either version, and it keeps letting the slicer decide.
fn bare_ip_offset(d: &[u8], link_type: LinkType) -> Option<usize> {
    let declared = match link_type {
        LinkType::BareIpv4 => 4,
        LinkType::BareIpv6 => 6,
        _ => return None,
    };
    (d.first()? >> 4 == declared).then_some(0)
}

/// What an Ethernet II frame's EtherType chain resolved to.
///
/// Offsets are absolute within the frame slice, matching
/// [`crate::capture::tunnel::Inner`], so a caller never has to remember which
/// base a given decoder measured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EthPayload {
    /// An IP header (v4 or v6 — the caller reads the version nibble) begins
    /// here. Reached directly, or through PPPoE, MPLS, NSH, MACsec or a PBB
    /// customer frame.
    Ip(usize),
    /// The chain ended at an EtherType this parser neither decapsulates nor
    /// reads as IP — ARP, LLDP, EAPOL, an 802.3 length field.
    ///
    /// Carries nothing on purpose. There is no offset worth reporting, since
    /// no caller can do anything with the bytes; and the EtherType is not
    /// carried either, because the only consumer that wants it —
    /// [`crate::capture::FrameFacts`] — takes its numbers from the error path,
    /// and a field nobody reads is a field nobody keeps true.
    Other,
    /// The encapsulation was recognized and its header validated, and the
    /// payload still cannot be read.
    ///
    /// Deliberately not an error: "MACsec-encrypted frame" is a diagnosis an
    /// operator can act on, where a frame that merely vanished is not.
    Opaque(&'static str),
}

impl EthPayload {
    /// Where an IP header begins, or `None` when the frame carries none this
    /// walk can point at.
    fn ip_offset(self) -> Option<usize> {
        match self {
            Self::Ip(off) => Some(off),
            Self::Other | Self::Opaque(_) => None,
        }
    }
}

/// Walk an Ethernet II frame's EtherType chain and report where its payload
/// begins.
///
/// `frame_start` is the offset of the frame's destination MAC within `d` —
/// zero for the captured frame itself, and non-zero for a frame that arrived
/// inside a tunnel (VXLAN, Geneve, GRE-TEB, NSH, a PBB customer frame).
///
/// 802.1Q / 802.1ad / legacy-0x9100 tags are skipped four bytes at a time, up
/// to [`MAX_VLAN_TAGS`] of them; a deeper stack yields `None` rather than
/// being followed. Every other recognized EtherType hands off to the
/// decapsulator in [`crate::capture::tunnel`] that owns it, spending one unit
/// of `budget` first — so a frame cannot buy extra walk depth by varying which
/// encapsulation it stacks.
///
/// One copy of this arithmetic on purpose: two would be two places for an
/// encapsulated packet's start offset to drift, and the cheap `--cores` peek
/// and the full parse both read it.
fn eth_payload(d: &[u8], frame_start: usize, budget: &mut Budget) -> Option<EthPayload> {
    let mut off = frame_start.checked_add(12)?; // skip dst+src MAC
    let mut vlan_tags = 0usize;
    // Termination: the VLAN arm is capped by `vlan_tags`, the MACsec arm by
    // `budget` (and both strictly advance `off`), and every other arm returns.
    loop {
        let et = u16::from_be_bytes([*d.get(off)?, *d.get(off.checked_add(1)?)?]);
        let after = off.checked_add(2)?;
        match et {
            // a VLAN tag (TPID+TCI)
            ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_LEGACY => {
                vlan_tags += 1;
                if vlan_tags > MAX_VLAN_TAGS {
                    return None;
                }
                off = off.checked_add(4)?;
            }
            // Named here rather than folded into the catch-all, because a
            // frame that arrived inside a tunnel is walked by this function
            // alone — there is no `etherparse` slice behind it to notice that
            // 0x0800 means "an IPv4 header starts at `after`".
            ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => return Some(EthPayload::Ip(after)),
            ETHERTYPE_PPPOE_SESSION => {
                budget.spend()?;
                return Some(EthPayload::Ip(pppoe_ip_offset(d, after)?));
            }
            ETHERTYPE_MPLS_UNICAST | ETHERTYPE_MPLS_UPSTREAM => {
                budget.spend()?;
                return eth_inner(d, tunnel::mpls::decap(d, after)?, budget);
            }
            ETHERTYPE_NSH => {
                budget.spend()?;
                return eth_inner(d, tunnel::nsh::decap(d, after)?, budget);
            }
            ETHERTYPE_PBB_ITAG => {
                budget.spend()?;
                return eth_inner(d, tunnel::l2::itag_decap(d, after)?, budget);
            }
            // MACsec is a transparent insertion between the source MAC and
            // the EtherType that was already there (IEEE Std 802.1AE-2018
            // §6.2), so the walk resumes *mid-header* rather than restarting:
            // a VLAN tag inside the Secure Data is an ordinary tag and gets
            // the ordinary arm above.
            ETHERTYPE_MACSEC => {
                budget.spend()?;
                let tag = tunnel::l2::macsec_sectag(d, after)?;
                if tag.opaque {
                    return Some(EthPayload::Opaque(MACSEC_OPAQUE));
                }
                off = tag.payload_off;
            }
            _ => return Some(EthPayload::Other),
        }
    }
}

// ── Linux cooked capture (DLT_LINUX_SLL / SLL2) constants ─────────────
//
// The two layouts are NOT the same shape with a different length, and reading
// one arm's offsets on the other frame is the mistake this block exists to
// make impossible. libpcap's LINKTYPE_LINUX_SLL is
//
//   0 packet type (2) | 2 ARPHRD_ (2) | 4 address length (2) |
//   6 address (8)     | 14 protocol type (2) | 16 payload
//
// and LINKTYPE_LINUX_SLL2 is
//
//   0 protocol type (2) | 2 reserved MBZ (2) | 4 interface index (4) |
//   8 ARPHRD_ (2) | 10 packet type (1) | 11 address length (1) |
//   12 address (8) | 20 payload
//
// — the protocol field moved to the front and the header grew by four bytes.

/// Length of the Linux SLL v1 header (libpcap's `SLL_HDR_LEN`).
const SLL_HEADER_LEN: usize = 16;
/// Offset of the SLL v1 ARPHRD_ type.
const SLL_ARPHRD_OFF: usize = 2;
/// Offset of the SLL v1 protocol type — **14**, not 0.
const SLL_PROTO_OFF: usize = 14;

/// Length of the Linux SLL2 header.
const SLL2_HEADER_LEN: usize = 20;
/// Offset of the SLL2 ARPHRD_ type.
const SLL2_ARPHRD_OFF: usize = 8;
/// Offset of the SLL2 protocol type — **0**, not 14.
const SLL2_PROTO_OFF: usize = 0;

/// ARPHRD_ types whose cooked-capture protocol field is not an EtherType.
///
/// libpcap's LINKTYPE_LINUX_SLL / SLL2 pages make the protocol field's meaning
/// depend on the ARPHRD_ type: a Netlink protocol type for ARPHRD_NETLINK
/// (824), a GRE protocol type for ARPHRD_IPGRE (778) and ARPHRD_IP6GRE (823),
/// and ignored entirely for ARPHRD_IEEE80211_RADIOTAP (803) and ARPHRD_FRAD
/// (770). Only "otherwise" is it "the Ethernet protocol type for the payload".
///
/// Checked because the alternative fabricates: a Netlink message whose
/// protocol number happens to be 0x8864 is not a PPPoE frame, and
/// decapsulating six bytes of it as a PPPoE header would report a host pair
/// and a call out of bytes that never described one.
const SLL_ARPHRD_WITHOUT_ETHERTYPE: [u16; 5] = [770, 778, 803, 823, 824];

/// Offset of the IP header inside a Linux cooked-capture frame, or `None`
/// when the frame carries none this walk can point at.
///
/// One function for both versions, parameterised by the three numbers that
/// differ, and used by BOTH the full parse and the `--cores` shard peek — a
/// second copy of these offsets is a second place for them to drift, and a
/// peek that disagreed with the parse is the split brain `--cores` keeps
/// finding.
///
/// What it follows, and why each is here rather than being a fixed skip:
///
/// * **PPPoE Session (0x8864).** `tcpdump -i any` on a BNG/BRAS writes exactly
///   this: cooked header, then RFC 2516 §4's PPPoE header, then the PPP
///   Protocol field, then IP. Skipping a flat header length landed the slicer
///   on the PPPoE header, whose first nibble is 1, and the frame came back
///   "unsupported IP version 1" or "not IP" — a whole access network's traffic
///   counted as undecodable.
/// * **A re-inserted VLAN tag.** When the kernel strips a tag into packet aux
///   data, libpcap puts it back — for cooked captures at `SLL_HDR_LEN - 2`
///   (`set_vlan_offset` in `pcap-linux.c`), i.e. *over* the protocol field, so
///   the protocol field becomes the TPID and the payload begins with the TCI
///   and the protocol the tag encapsulates. `etherparse` has always followed
///   that on the full-parse path, so the peek has to as well. The same walk is
///   applied to SLL2 for symmetry; libpcap does not re-insert tags there
///   (`set_vlan_offset` leaves `vlan_offset` at -1 for every other link type),
///   so that arm is unreachable from libpcap's own writer and costs one
///   comparison.
///
/// Anything else — ARP, LLDP, the non-EtherType protocol values libpcap lists
/// (0x0001 Novell 802.3, 0x0004 802.2 LLC, 0x000C/0x000D/0x000E CAN, 0x00F8
/// DSA) — comes back [`EthPayload::Other`], and the two callers do NOT do the
/// same thing with it, which is deliberate and worth stating because it looks
/// like an inconsistency:
///
/// * The **full parse** falls back to a fixed header skip, but only on the
///   manual path (`etherparse` refused the frame outright), and it then hands
///   the bytes to `SlicedPacket::from_ip`, which validates them. That is what
///   reads frames from the ARPHRD_ types `etherparse` will not touch, and
///   narrowing it is a separate change with its own risk.
/// * The **shard peek** takes no offset at all. It has no cheap way to run
///   that validation, and a header skip it cannot validate manufactures a host
///   pair out of whatever sits there — an STP BPDU's DSAP is 0x42, whose high
///   nibble is 4. See [`peek_host_pair`] for the full reasoning.
///
/// `budget` is spent for the PPPoE decapsulation, matching what the Ethernet
/// walk charges for the same header, so a frame cannot buy extra depth by
/// arriving cooked instead of on the wire.
fn sll_payload(
    d: &[u8],
    arphrd_off: usize,
    proto_off: usize,
    header_len: usize,
    budget: &mut Budget,
) -> Option<EthPayload> {
    let arphrd = u16::from_be_bytes([*d.get(arphrd_off)?, *d.get(arphrd_off + 1)?]);
    if SLL_ARPHRD_WITHOUT_ETHERTYPE.contains(&arphrd) {
        return None;
    }
    let mut proto = u16::from_be_bytes([*d.get(proto_off)?, *d.get(proto_off + 1)?]);
    let mut off = header_len;
    let mut vlan_tags = 0usize;
    // Termination: every iteration adds a tag, and the count is capped.
    while matches!(
        proto,
        ETHERTYPE_VLAN | ETHERTYPE_QINQ | ETHERTYPE_VLAN_LEGACY
    ) {
        vlan_tags += 1;
        if vlan_tags > MAX_VLAN_TAGS {
            return None;
        }
        // The tag body is TCI then the encapsulated protocol — the TPID was
        // the protocol field this iteration just read.
        proto = u16::from_be_bytes([*d.get(off.checked_add(2)?)?, *d.get(off.checked_add(3)?)?]);
        off = off.checked_add(4)?;
    }
    match proto {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => Some(EthPayload::Ip(off)),
        ETHERTYPE_PPPOE_SESSION => {
            budget.spend()?;
            Some(EthPayload::Ip(pppoe_ip_offset(d, off)?))
        }
        _ => Some(EthPayload::Other),
    }
}

/// Turn a decapsulator's [`Inner`] into an [`EthPayload`], re-entering the
/// Ethernet walk when what came out is a frame rather than a packet.
///
/// The re-entry is not charged again: the layer that produced the inner frame
/// already spent its unit, and charging twice would make a VXLAN frame cost
/// more depth than an IP-in-IP one for no reason.
fn eth_inner(d: &[u8], inner: Inner, budget: &mut Budget) -> Option<EthPayload> {
    match inner {
        Inner::Ip(off) => Some(EthPayload::Ip(off)),
        Inner::Ethernet(off) => eth_payload(d, off, budget),
        Inner::Opaque(label) => Some(EthPayload::Opaque(label)),
    }
}

/// Cheap outer host-pair extraction for multi-core sharding (`--cores N`).
///
/// Reads ONLY the link + IP headers at fixed offsets to get the outer src/dst
/// IPs — no transport/payload parse, no allocation, no `etherparse` slicing — so
/// the dispatcher's per-packet serial cost stays tiny while the full parse +
/// reassembly happen in the worker. Handles EN10MB (incl. 802.1Q/QinQ VLAN and
/// PPPoE Session, RFC 2516), Linux SLL v1/v2 (with the same VLAN and PPPoE
/// walk the full parse uses), PPP (DLT_PPP / DLT_PPP_SERIAL / DLT_PPP_ETHER),
/// BSD loopback (DLT_NULL / DLT_LOOP) and raw IP (DLT_RAW / DLT_IPV4 /
/// DLT_IPV6), for IPv4 and IPv6, plus pre-parsed (HEP) packets.
/// Every link type the full parse decodes is decoded here too: a peek
/// that returns `None` where the full parse succeeds would leave `--cores N`
/// shipping every packet to worker 0, and a peek that reads a *different*
/// offset than the full parse would shard a flow's packets across workers.
/// Returns `None` for anything it can't cheaply read; the caller shards those to
/// worker 0 (still correct — that worker has its own reassembly — just less
/// balanced).
///
/// # Which tunnels the peek follows, and why the line is drawn there
///
/// **Link-layer encapsulation: followed.** VLAN, QinQ, PPPoE, MPLS, MACsec,
/// the PBB customer frame and NSH-over-Ethernet all go through the single
/// Ethernet walk the full parse uses, and a cooked-capture frame goes through
/// the single `sll_payload` walk the full parse uses, so the two cannot
/// disagree about where a frame's IP header begins. That matters most for the
/// encapsulations `etherparse` decodes natively — MACsec on Ethernet, a
/// re-inserted VLAN tag on SLL: a peek that stopped at `0x88E5`, or that
/// skipped a flat 16 bytes past a tag, returns `None` for every frame on such
/// a link and collapses `--cores N` onto one worker.
///
/// **Network- and transport-layer tunnels: NOT followed.** IP-in-IP, 6in4,
/// GRE, AH and every UDP tunnel (VXLAN, GTP-U, Geneve, Teredo, L2TP) report
/// the *tunnel's* host pair here, never the inner one. This is a decision, not
/// an oversight, and the reason is IP fragmentation: a link-layer header is
/// re-applied to every frame by the forwarding element, so every fragment of a
/// datagram carries it, but a GRE or VXLAN header sits in the datagram's
/// payload and therefore appears **only in the first fragment**. A peek that
/// followed those would key the first fragment on the inner pair and the rest
/// on the outer one, scattering one datagram's fragments across workers and
/// silently breaking reassembly — the exact failure sharding exists to avoid.
///
/// The consequence is stated rather than hidden: under `--cores N`, all
/// traffic through one tunnel lands on one worker, because every frame of it
/// shares the tunnel endpoints. That is a load-balance loss, not a correctness
/// one — the worker that receives them does the full decapsulation and owns
/// its own reassembly state — and it is the same behavior `--cores` has
/// always had for GRE.
///
/// # A payload the walk cannot name yields NO key, never a guessed offset
///
/// Where `sll_payload` comes back `EthPayload::Other` — a cooked frame
/// whose protocol field is 802.2 LLC, a CAN frame, DSA, Novell 802.3 — this
/// used to fall back to a fixed header skip and read whatever sat there. The
/// claim was that the full parse falls back the same way, and it does not:
/// the full parse only reaches its fixed skip when `etherparse` *rejects* the
/// frame outright, and even then it hands the bytes to `SlicedPacket::from_ip`,
/// which validates them. This peek validated nothing beyond a version nibble.
///
/// A Spanning Tree BPDU on `-i any` is the frame that shows what that cost.
/// LLC's DSAP for STP is 0x42, and `0x42 >> 4` is 4, so the fixed skip landed
/// on the BPDU and the nibble said "IPv4": the peek returned a host pair built
/// from the root bridge identifier and the root path cost, for a frame the
/// full parse refuses. Every Linux bridge produces those frames.
///
/// So the rule is uniform across every link type now: the offset comes from
/// `EthPayload::ip_offset` or from nothing. The exchange is a *narrow* loss
/// of balance — a cooked frame whose ARPHRD_ type `etherparse` refuses AND
/// whose protocol field is not an EtherType this walk follows AND whose
/// payload really is an IP header now shards to worker 0 instead of being
/// spread — for the removal of a whole class of invented shard keys. That is
/// the right direction to err: a `None` costs load balance, and every worker
/// owns its own reassembly, so a WRONG pair costs correctness.
pub fn peek_host_pair(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    if let Some(meta) = &packet.pre_parsed {
        return Some((meta.src_addr, meta.dst_addr));
    }
    let d: &[u8] = &packet.data;
    let link = LinkType::from_dlt(packet.link_type)?;
    let ip_off = match link {
        LinkType::Ethernet => eth_payload(d, 0, &mut Budget::new())?.ip_offset()?,
        // `ip_offset()`, never a fixed header skip — see "A payload the walk
        // cannot name yields NO key" above.
        LinkType::LinuxSll => sll_payload(
            d,
            SLL_ARPHRD_OFF,
            SLL_PROTO_OFF,
            SLL_HEADER_LEN,
            &mut Budget::new(),
        )?
        .ip_offset()?,
        LinkType::LinuxSll2 => sll_payload(
            d,
            SLL2_ARPHRD_OFF,
            SLL2_PROTO_OFF,
            SLL2_HEADER_LEN,
            &mut Budget::new(),
        )?
        .ip_offset()?,
        LinkType::Raw => 0,
        LinkType::BareIpv4 | LinkType::BareIpv6 => bare_ip_offset(d, link)?,
        LinkType::BsdNull | LinkType::BsdLoop => loopback_ip_offset(d, link)?,
        LinkType::Ppp | LinkType::PppSerial | LinkType::PppEther => ppp_link_ip_offset(d, link)?,
    };
    match d.get(ip_off)? >> 4 {
        4 => {
            let s: [u8; 4] = d.get(ip_off + 12..ip_off + 16)?.try_into().ok()?;
            let t: [u8; 4] = d.get(ip_off + 16..ip_off + 20)?.try_into().ok()?;
            Some((IpAddr::V4(s.into()), IpAddr::V4(t.into())))
        }
        6 => {
            let s: [u8; 16] = d.get(ip_off + 8..ip_off + 24)?.try_into().ok()?;
            let t: [u8; 16] = d.get(ip_off + 24..ip_off + 40)?.try_into().ok()?;
            Some((IpAddr::V6(s.into()), IpAddr::V6(t.into())))
        }
        _ => None,
    }
}

// ── GRE constants ─────────────────────────────────────────────────────

/// Minimum GRE header length (4 bytes: flags + protocol type).
const GRE_HEADER_MIN: usize = 4;
/// GRE flag bit for checksum present.
const GRE_FLAG_CHECKSUM: u16 = 0x8000;
/// GRE flag bit for key present.
const GRE_FLAG_KEY: u16 = 0x2000;
/// GRE flag bit for sequence number present.
const GRE_FLAG_SEQ: u16 = 0x1000;
/// EtherType for IPv4 inside GRE.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6 inside GRE.
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// GRE Protocol Type for Transparent Ethernet Bridging.
///
/// RFC 7637 §3.2: "The Protocol Type field in the GRE header is set to 0x6558
/// (Transparent Ethernet Bridging)". That is the current normative statement
/// of this value, and it references RFC 2784 for the GRE header itself.
/// **Not** RFC 1701, which is Informational, describes a different (pre-2784)
/// header layout with a Key/Sequence/Routing scheme this parser does not
/// implement, and would be the wrong citation for the header actually walked
/// by [`gre_inner_offset`].
///
/// The payload is a complete Ethernet II frame — MAC addresses first — not a
/// bare IP packet, so the Ethernet walk is re-entered rather than the IP one.
const GRE_PROTO_TEB: u16 = 0x6558;

/// Map an IANA IP-protocol number to a [`TransportProto`].
///
/// Used by the pre-parsed short-circuit path; HEP and similar sources
/// carry the IP protocol number, not the application-level transport
/// like TLS or WS — so this only recognizes UDP / TCP / SCTP. Any other
/// protocol number yields `None`: the caller rejects the packet rather
/// than guessing a transport, so e.g. ESP is never mislabeled as UDP.
fn ip_protocol_to_transport(p: u8) -> Option<TransportProto> {
    match p {
        6 => Some(TransportProto::Tcp),
        17 => Some(TransportProto::Udp),
        132 => Some(TransportProto::Sctp),
        _ => None,
    }
}

// ── SCTP ──────────────────────────────────────────────────────────────

/// A zero-copy reference to one SCTP DATA chunk's control fields and payload.
///
/// `payload` is the byte range of the chunk value (the user data — here, a SIP
/// message or a fragment of one) within the SCTP packet slice passed to
/// [`find_sctp_data_chunk`]; `src_port`/`dst_port` come from the SCTP common
/// header. `begin`/`end` are the B/E fragment flags and `tsn`/`sid`/`ssn`
/// identify the fragment's place in its stream for cross-packet reassembly.
struct SctpDataChunkRef {
    /// Source port from the SCTP common header.
    src_port: u16,
    /// Destination port from the SCTP common header.
    dst_port: u16,
    /// Transmission Sequence Number of this DATA chunk (contiguous across the
    /// fragments of one message).
    tsn: u32,
    /// Stream Identifier (shared by all fragments of one message).
    sid: u16,
    /// Stream Sequence Number (shared by all fragments of one message).
    ssn: u16,
    /// B (beginning) fragment flag.
    begin: bool,
    /// E (ending) fragment flag.
    end: bool,
    /// Byte range of the chunk's user data within the SCTP packet slice.
    payload: std::ops::Range<usize>,
}

/// Find the first DATA chunk in an SCTP packet matching the requested
/// completeness, returning its ports, fragment control fields, and payload
/// range.
///
/// `sctp` is the full SCTP packet: the 12-byte common header (src port, dst
/// port, verification tag, checksum) followed by one or more chunks. Each chunk
/// is `type(1) flags(1) length(2)` — where `length` includes the 4-byte chunk
/// header — then `length - 4` value bytes, then padding to the next 4-byte
/// boundary (the final chunk's padding may be absent).
///
/// A DATA chunk (type 0) carries a 12-byte data header (TSN, stream id, stream
/// seq, PPID); the application payload is the chunk value after that data
/// header. A chunk with both the B (beginning) and E (ending) flags set is a
/// complete, unfragmented message; any other combination is a fragment of a
/// message split across chunks/packets (RFC 4960 §3.3.1).
///
/// When `complete_only` is `true` this returns the first complete (B+E) chunk
/// (the single-packet fast path); when `false` it returns the first *fragment*
/// (a B-only, middle, or E-only chunk), the input to cross-packet reassembly.
/// Only chunks with a non-empty payload are returned.
///
/// Fails closed: any truncation, out-of-bounds, or malformed length yields
/// `None`.
fn find_sctp_data_chunk(sctp: &[u8], complete_only: bool) -> Option<SctpDataChunkRef> {
    const COMMON_HEADER_LEN: usize = 12; // src+dst ports, verification tag, checksum
    const CHUNK_HEADER_LEN: usize = 4; // type(1) + flags(1) + length(2)
    const DATA_HEADER_LEN: usize = 12; // TSN, stream id, stream seq, PPID
    const DATA_CHUNK_TYPE: u8 = 0; // chunk type carrying application data
    const FLAG_E: u8 = 0x01; // ending fragment
    const FLAG_B: u8 = 0x02; // beginning fragment

    if sctp.len() < COMMON_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([sctp[0], sctp[1]]);
    let dst_port = u16::from_be_bytes([sctp[2], sctp[3]]);

    let mut offset = COMMON_HEADER_LEN;
    while offset + CHUNK_HEADER_LEN <= sctp.len() {
        let chunk_type = sctp[offset];
        let flags = sctp[offset + 1];
        let length = u16::from_be_bytes([sctp[offset + 2], sctp[offset + 3]]) as usize;

        // The length always includes the 4-byte header; a smaller value is
        // malformed and could stall iteration, so fail closed.
        if length < CHUNK_HEADER_LEN {
            return None;
        }
        // The declared chunk must fit within the buffer.
        let chunk_end = offset.checked_add(length)?;
        if chunk_end > sctp.len() {
            return None;
        }

        if chunk_type == DATA_CHUNK_TYPE {
            let begin = flags & FLAG_B != 0;
            let end = flags & FLAG_E != 0;
            let complete = begin && end;
            let data_start = offset.checked_add(CHUNK_HEADER_LEN)?;
            let payload_start = data_start.checked_add(DATA_HEADER_LEN)?;
            // `payload_start < chunk_end` guarantees the full data header is
            // present and the payload is non-empty. `complete == complete_only`
            // selects complete chunks for the fast path and fragments for
            // reassembly.
            if complete == complete_only && payload_start < chunk_end {
                let tsn = u32::from_be_bytes([
                    sctp[data_start],
                    sctp[data_start + 1],
                    sctp[data_start + 2],
                    sctp[data_start + 3],
                ]);
                let sid = u16::from_be_bytes([sctp[data_start + 4], sctp[data_start + 5]]);
                let ssn = u16::from_be_bytes([sctp[data_start + 6], sctp[data_start + 7]]);
                return Some(SctpDataChunkRef {
                    src_port,
                    dst_port,
                    tsn,
                    sid,
                    ssn,
                    begin,
                    end,
                    payload: payload_start..chunk_end,
                });
            }
            // Otherwise it is the wrong kind of chunk or an empty DATA chunk —
            // keep scanning.
        }

        // Advance past this chunk, rounding its length up to the next 4-byte
        // boundary. The final chunk's padding may be absent, so an advance
        // beyond the buffer simply ends iteration.
        let padded = length.checked_add(3)? & !3usize;
        offset = offset.checked_add(padded)?;
    }
    None
}

/// One SCTP DATA fragment recovered from a captured packet, ready to feed to
/// [`SctpReassembler`]. `data` is a zero-copy view of the fragment's user data;
/// `begin`/`end` are the B/E flags and `tsn`/`sid`/`ssn` place it in its stream.
#[derive(Debug, Clone)]
pub(crate) struct SctpFragment {
    /// Source port from the SCTP common header.
    pub(crate) src_port: u16,
    /// Destination port from the SCTP common header.
    pub(crate) dst_port: u16,
    /// Transmission Sequence Number (contiguous across a message's fragments).
    pub(crate) tsn: u32,
    /// Stream Identifier (shared by a message's fragments).
    pub(crate) sid: u16,
    /// Stream Sequence Number (shared by a message's fragments).
    pub(crate) ssn: u16,
    /// B (beginning) fragment flag.
    pub(crate) begin: bool,
    /// E (ending) fragment flag.
    pub(crate) end: bool,
    /// The fragment's user data (zero-copy view of the packet buffer).
    pub(crate) data: bytes::Bytes,
}

/// Recover the first SCTP DATA *fragment* (a B-only, middle, or E-only chunk)
/// from a raw captured packet, for cross-packet reassembly.
///
/// Complements the stateless [`parse_packet`] path, which already emits the SIP
/// payload of a single-packet complete (B+E) chunk. Only non-encapsulated SCTP
/// over the recognized link types is handled; encapsulated SCTP and pre-parsed
/// (HEP) sources are not reassembled here (fail-closed — such fragments are
/// simply not reassembled). Returns `None` when the packet is not SCTP, carries
/// no DATA fragment, or is malformed.
pub(crate) fn parse_sctp_fragment(packet: &Packet) -> Option<SctpFragment> {
    if packet.pre_parsed.is_some() {
        return None;
    }
    let sliced = slice_link_layer(packet.link_type, &packet.data, &mut Budget::new()).ok()?;
    let net = sliced.net.as_ref()?;
    let ip_payload = net.ip_payload_ref()?;
    // 132 = SCTP. Encapsulated SCTP (inside IP-in-IP / GRE) is out of scope for
    // fragment reassembly and left unreassembled rather than mis-parsed.
    if ip_payload.ip_number.0 != 132 {
        return None;
    }
    let chunk = find_sctp_data_chunk(ip_payload.payload, false)?;
    let bytes = ip_payload.payload.get(chunk.payload.clone())?;
    Some(SctpFragment {
        src_port: chunk.src_port,
        dst_port: chunk.dst_port,
        tsn: chunk.tsn,
        sid: chunk.sid,
        ssn: chunk.ssn,
        begin: chunk.begin,
        end: chunk.end,
        data: slice_of(&packet.data, bytes),
    })
}

/// Default cap on concurrently tracked SCTP reassembly streams. Mirrors the
/// other reassemblers' session cap so a flood of incomplete fragment streams
/// cannot grow memory without bound.
const DEFAULT_MAX_SCTP_STREAMS: usize = 10_000;

/// Upper bound on a single reassembled SCTP message (bytes). A fragment stream
/// whose accumulated user data would exceed this is dropped, so a peer cannot
/// pin memory with an unbounded run of B/middle fragments.
const MAX_SCTP_REASSEMBLY: usize = 65_536;

/// Reassembly key: the SCTP association (5-tuple; proto is implicitly SCTP)
/// plus the Stream Identifier and Stream Sequence Number that all fragments of
/// one user message share (RFC 4960 §3.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SctpStreamKey {
    /// Source socket (association endpoint).
    src: SocketAddr,
    /// Destination socket (association endpoint).
    dst: SocketAddr,
    /// Stream Identifier.
    sid: u16,
    /// Stream Sequence Number.
    ssn: u16,
}

/// In-progress reassembly of one fragmented SCTP user message.
struct SctpPartial {
    /// TSN expected on the next fragment; fragments of a message are contiguous.
    next_tsn: u32,
    /// User data accumulated so far, in TSN order (B, then middles).
    buf: Vec<u8>,
}

/// Cross-packet SCTP DATA fragment reassembler (RFC 4960 §3.3.1).
///
/// A message split across DATA chunks — a B (beginning) fragment, zero or more
/// middle fragments, then an E (ending) fragment sharing one (association, SID,
/// SSN) with contiguous TSNs — is buffered here until the E fragment arrives,
/// then emitted as the concatenated user data (the SIP message).
///
/// Fails closed, mirroring the single-chunk SCTP path: a middle/E fragment with
/// no started stream, a TSN gap or reorder, or an over-cap message is dropped
/// rather than emitting a corrupt payload. The stream table is bounded by
/// `max_streams` with least-recently-updated eviction (map order is update
/// recency), so incomplete fragment streams cannot grow memory unbounded.
pub(crate) struct SctpReassembler {
    /// In-progress reassemblies keyed by (association, SID, SSN). Map order is
    /// update recency: index 0 is always the least-recently-updated stream.
    streams: IndexMap<SctpStreamKey, SctpPartial, RandomState>,
    /// Cap on tracked streams; at capacity the stalest entry is evicted.
    max_streams: usize,
}

impl SctpReassembler {
    /// Create a reassembler with the default stream cap.
    pub(crate) fn new() -> Self {
        Self::with_max_streams(DEFAULT_MAX_SCTP_STREAMS)
    }

    /// Create a reassembler tracking at most `max_streams` concurrent fragment
    /// streams (clamped to at least 1).
    pub(crate) fn with_max_streams(max_streams: usize) -> Self {
        Self {
            streams: IndexMap::default(),
            max_streams: max_streams.max(1),
        }
    }

    /// Feed one DATA fragment; returns the reassembled user message when this
    /// fragment is the E (ending) one that completes it, otherwise `None`.
    ///
    /// `src`/`dst` are the association endpoints (from the packet's IP addresses
    /// and the fragment's ports). A self-contained (B+E) fragment returns its
    /// data immediately. Fail-closed drops (missing B, TSN gap, overflow) return
    /// `None` and discard any partial for the stream.
    pub(crate) fn insert(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        frag: &SctpFragment,
    ) -> Option<bytes::Bytes> {
        // A complete (B+E) chunk carries a whole message — no state needed.
        if frag.begin && frag.end {
            return Some(frag.data.clone());
        }

        let key = SctpStreamKey {
            src,
            dst,
            sid: frag.sid,
            ssn: frag.ssn,
        };

        if frag.begin {
            // Beginning fragment: start (or restart) this stream's buffer.
            // An over-cap opening fragment is refused outright.
            if frag.data.len() > MAX_SCTP_REASSEMBLY {
                self.streams.shift_remove(&key);
                return None;
            }
            // Bound the stream count: evict the least-recently-updated entry
            // (index 0) before admitting a genuinely new stream.
            if !self.streams.contains_key(&key) && self.streams.len() >= self.max_streams {
                self.streams.shift_remove_index(0);
            }
            // Remove any stale partial for this key, then insert so this stream
            // becomes the most-recently-updated (map tail).
            self.streams.shift_remove(&key);
            self.streams.insert(
                key,
                SctpPartial {
                    next_tsn: frag.tsn.wrapping_add(1),
                    buf: frag.data.to_vec(),
                },
            );
            return None;
        }

        // Middle or ending fragment: requires a started, TSN-contiguous stream.
        // Taking it out first means every fail-closed exit already drops it.
        let mut partial = self.streams.shift_remove(&key)?;
        let over_cap = partial.buf.len().saturating_add(frag.data.len()) > MAX_SCTP_REASSEMBLY;
        if frag.tsn != partial.next_tsn || over_cap {
            // Gap / reorder / overflow — drop the partial, emit nothing.
            //
            // A gap is the protocol's business; an overflow is ours. RFC 4960
            // sets no reassembly ceiling, so a SIP-over-SCTP message (RFC 4168)
            // with a large body is dropped ENTIRELY here — not truncated, not
            // malformed, absent. The call simply does not appear. Warned once
            // so that absence has a stated cause.
            if over_cap {
                static SCTP_OVER_CAP_WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !SCTP_OVER_CAP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        "an SCTP message exceeded the {MAX_SCTP_REASSEMBLY}-byte reassembly \
                         cap and was dropped entirely, so the messages it carried will not \
                         appear at all. RFC 4960 sets no such limit; this is sipnab's."
                    );
                }
            }
            return None;
        }
        partial.buf.extend_from_slice(&frag.data);
        partial.next_tsn = frag.tsn.wrapping_add(1);
        if frag.end {
            return Some(bytes::Bytes::from(partial.buf));
        }
        // More fragments expected — re-insert as the most-recently-updated.
        self.streams.insert(key, partial);
        None
    }

    /// Number of in-progress reassembly streams (for tests / diagnostics).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.streams.len()
    }
}

// ── Public API ────────────────────────────────────────────────────────

/// Byte range `child` occupies within `parent`, if `child` is a subslice.
fn subslice_range(parent: &[u8], child: &[u8]) -> Option<std::ops::Range<usize>> {
    let p = parent.as_ptr() as usize;
    let c = child.as_ptr() as usize;
    let start = c.checked_sub(p)?;
    let end = start.checked_add(child.len())?;
    (end <= parent.len()).then_some(start..end)
}

/// Zero-copy view of `child` (a slice derived from `data`) as `Bytes` —
/// a refcount bump plus offset, no allocation. Falls back to a copy if
/// `child` does not alias `data` (defensive; should not happen).
fn slice_of(data: &bytes::Bytes, child: &[u8]) -> bytes::Bytes {
    match subslice_range(data, child) {
        Some(r) => data.slice(r),
        None => bytes::Bytes::copy_from_slice(child),
    }
}

/// Re-parse the transport header from a reassembled IP payload.
///
/// After IP-fragment reassembly the buffer is the full IP payload — i.e. the
/// transport header (UDP/TCP) followed by the application data. The original
/// fragment carried no usable transport header (non-first fragments have none,
/// and the first fragment's UDP length covers the whole datagram), so the ports
/// and the header length must be recovered here before the SIP/RTP parser sees
/// the payload. Returns `(src_port, dst_port, transport, header_len)` or `None`
/// for a truncated buffer or an unhandled protocol.
pub(crate) fn reparse_transport(
    ip_protocol: u8,
    payload: &[u8],
) -> Option<(u16, u16, TransportProto, usize)> {
    match ip_protocol {
        17 => {
            // UDP: src(2) dst(2) len(2) cksum(2) = 8-byte fixed header.
            if payload.len() < 8 {
                return None;
            }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            Some((sp, dp, TransportProto::Udp, 8))
        }
        6 => {
            // TCP: data offset (high nibble of byte 12) in 32-bit words.
            if payload.len() < 20 {
                return None;
            }
            let sp = u16::from_be_bytes([payload[0], payload[1]]);
            let dp = u16::from_be_bytes([payload[2], payload[3]]);
            let data_off = ((payload[12] >> 4) as usize) * 4;
            if data_off < 20 || payload.len() < data_off {
                return None;
            }
            Some((sp, dp, TransportProto::Tcp, data_off))
        }
        _ => None,
    }
}

/// Slice the IP header at `off` out of a frame whose link layer has already
/// been walked.
///
/// One helper rather than the same three lines in each arm, because the two
/// failure modes have to stay distinguishable: a frame shorter than the offset
/// the walk resolved is `TooShort` (the operator's snaplen), and bytes that
/// are not an IP header is `PacketDecode` (the frame is something else).
/// `what` names the framing in both, since "failed to decode IP" without
/// saying from what is the diagnosis this project keeps removing.
fn slice_ip_at<'a>(
    d: &'a [u8],
    off: usize,
    what: &'static str,
) -> Result<SlicedPacket<'a>, CaptureError> {
    let ip = d.get(off..).ok_or(CaptureError::TooShort {
        what,
        need: off,
        got: d.len(),
    })?;
    SlicedPacket::from_ip(ip).map_err(|e| CaptureError::PacketDecode {
        what,
        source: Box::new(e),
    })
}

/// Slice a raw link-layer frame into an [`SlicedPacket`] based on `link_type`.
///
/// Handles Ethernet II (with VLAN / QinQ via `etherparse`, and with PPPoE
/// Session decapsulated here because `etherparse` does not know it), Linux
/// cooked capture v1 (`DLT_LINUX_SLL`, with a manual header-skip fallback for
/// kernel SLL variants `etherparse` rejects) and v2 (`DLT_LINUX_SLL2`) — both
/// including PPPoE, which is what `-i any` on a BNG/BRAS produces — raw IP
/// (`DLT_RAW`, `DLT_IPV4`, `DLT_IPV6`), PPP as a link layer (`DLT_PPP`,
/// `DLT_PPP_SERIAL`, `DLT_PPP_ETHER`) and BSD loopback (`DLT_NULL` /
/// `DLT_LOOP`) — what a capture on `lo0` holds on every BSD and on macOS.
/// Shared by [`parse_packet`] and the SCTP fragment recovery path so both
/// reach the network layer the same way.
///
/// # Errors
///
/// Returns `UnsupportedLinkType` for an unrecognized `link_type`, `TooShort`
/// for a truncated SLL/SLL2/PPPoE/loopback header, `NotIp` for a loopback
/// frame whose address family is not an IP family, a cooked frame whose
/// ARPHRD_ type gives its protocol field a non-EtherType meaning, a PPP frame
/// carrying no IP or a bare-IP frame of the version its link type does not
/// declare, or `PacketDecode` when the frame cannot be sliced.
fn slice_link_layer<'a>(
    link_type: i32,
    data: &'a [u8],
    budget: &mut Budget,
) -> Result<SlicedPacket<'a>, CaptureError> {
    // Resolved to the closed set FIRST, so the dispatch below is exhaustive
    // and a link type added here is a compile error in [`peek_host_pair`]
    // until the shard peek learns it too — see [`LinkType`].
    let link = LinkType::from_dlt(link_type).ok_or(CaptureError::UnsupportedLinkType(link_type))?;
    match link {
        // `etherparse` has no PPPoE support, so a PPPoE Session frame slices as
        // perfectly valid Ethernet carrying a network layer it does not
        // recognize — `net` is None and the frame is discarded as "not IP" one
        // caller up. That `net.is_none()` case is ALREADY the discard path (an
        // unrecognized EtherType), so ordinary IPv4/IPv6/ARP traffic never
        // evaluates the PPPoE look: the cost falls only on frames that are
        // currently being thrown away.
        LinkType::Ethernet => match SlicedPacket::from_ethernet(data) {
            Ok(sliced) if sliced.net.is_none() => match eth_payload(data, 0, budget) {
                // PPPoE, MPLS, NSH, a PBB customer frame or integrity-only
                // MACsec: the walk already resolved an inner IP header.
                Some(EthPayload::Ip(off)) => {
                    let ip = data.get(off..).ok_or(CaptureError::TooShort {
                        what: "encapsulated IP payload",
                        need: off,
                        got: data.len(),
                    })?;
                    SlicedPacket::from_ip(ip).map_err(|e| CaptureError::PacketDecode {
                        what: "IP from encapsulated Ethernet frame",
                        source: Box::new(e),
                    })
                }
                // Recognized and unreadable. Named, so the report can say
                // *which* encapsulation the operator is looking at rather
                // than counting another anonymous non-IP frame.
                Some(EthPayload::Opaque(what)) => Err(CaptureError::NotIp { what }),
                // Not an encapsulation this parser walks: keep the original
                // slice so ARP and friends still report `NotIp` rather than a
                // decode failure.
                _ => Ok(sliced),
            },
            Ok(sliced) => Ok(sliced),
            Err(e) => Err(CaptureError::PacketDecode {
                what: "Ethernet packet",
                source: Box::new(e),
            }),
        },
        // Linux SLL (cooked capture v1): a 16-byte header whose protocol type
        // sits at offset 14. `etherparse` reads it, and follows a re-inserted
        // VLAN tag, but knows nothing about PPPoE — which is precisely what
        // `-i any` on a BNG produces — so the frames it hands back with no
        // network layer get the same second look the Ethernet arm gives them.
        LinkType::LinuxSll => match SlicedPacket::from_linux_sll(data) {
            Ok(sliced) if sliced.net.is_none() => {
                match sll_payload(data, SLL_ARPHRD_OFF, SLL_PROTO_OFF, SLL_HEADER_LEN, budget) {
                    Some(EthPayload::Ip(off)) => slice_ip_at(data, off, "IP from Linux SLL packet"),
                    // A protocol this walk does not follow: keep the original
                    // slice so ARP and friends still report `NotIp` rather
                    // than a decode failure.
                    _ => Ok(sliced),
                }
            }
            Ok(sliced) => Ok(sliced),
            // Some ARPHRD_ types `etherparse` refuses outright — ARPHRD_PPP
            // (512) among them, which is what `-i any` stamps on a frame from
            // `ppp0`. The header length is fixed, so the frame is still
            // readable; the walk says where its payload starts.
            Err(_) => {
                if data.len() < SLL_HEADER_LEN {
                    return Err(CaptureError::TooShort {
                        what: "Linux SLL packet",
                        need: SLL_HEADER_LEN,
                        got: data.len(),
                    });
                }
                let off = match sll_payload(
                    data,
                    SLL_ARPHRD_OFF,
                    SLL_PROTO_OFF,
                    SLL_HEADER_LEN,
                    budget,
                ) {
                    Some(EthPayload::Ip(off)) => off,
                    Some(_) => SLL_HEADER_LEN,
                    None => {
                        return Err(CaptureError::NotIp {
                            what: "Linux SLL packet",
                        });
                    }
                };
                slice_ip_at(data, off, "IP from Linux SLL packet (manual fallback)")
            }
        },
        LinkType::Raw => SlicedPacket::from_ip(data).map_err(|e| CaptureError::PacketDecode {
            what: "raw IP packet",
            source: Box::new(e),
        }),
        // DLT_IPV4 / DLT_IPV6: raw IP that names its own version, so the
        // version nibble is checked against the link type rather than sniffed
        // — see [`bare_ip_offset`].
        LinkType::BareIpv4 | LinkType::BareIpv6 => {
            if data.is_empty() {
                return Err(CaptureError::TooShort {
                    what: "bare IP packet",
                    need: 1,
                    got: 0,
                });
            }
            let off = bare_ip_offset(data, link).ok_or(CaptureError::NotIp {
                what: if link == LinkType::BareIpv4 {
                    "non-IPv4 frame in a DLT_IPV4 capture"
                } else {
                    "non-IPv6 frame in a DLT_IPV6 capture"
                },
            })?;
            slice_ip_at(data, off, "bare IP packet")
        }
        // PPP as the link layer: DLT_PPP (9), DLT_PPP_SERIAL (50) and
        // DLT_PPP_ETHER (51) all resolve through the PPP Protocol field and
        // PPPoE header this file already owns — see [`ppp_link_ip_offset`].
        LinkType::Ppp | LinkType::PppSerial | LinkType::PppEther => {
            let what = if link == LinkType::PppEther {
                "PPPoE session packet"
            } else {
                "PPP frame"
            };
            let off = ppp_link_ip_offset(data, link).ok_or(CaptureError::NotIp { what })?;
            slice_ip_at(data, off, "IP from PPP frame")
        }
        // BSD loopback: a 4-byte address family, then the IP header. The
        // family is what proves the payload is IP at all — see
        // [`loopback_ip_offset`] for the byte-order rule that separates the
        // two link types.
        LinkType::BsdNull | LinkType::BsdLoop => {
            if data.len() < LOOPBACK_HEADER_LEN {
                return Err(CaptureError::TooShort {
                    what: "BSD loopback packet",
                    need: LOOPBACK_HEADER_LEN,
                    got: data.len(),
                });
            }
            let off = loopback_ip_offset(data, link).ok_or(CaptureError::NotIp {
                what: "BSD loopback packet",
            })?;
            let ip = data.get(off..).ok_or(CaptureError::TooShort {
                what: "BSD loopback packet",
                need: off,
                got: data.len(),
            })?;
            SlicedPacket::from_ip(ip).map_err(|e| CaptureError::PacketDecode {
                what: "IP from BSD loopback packet",
                source: Box::new(e),
            })
        }
        // SLL2 has a 20-byte header and, unlike SLL v1, its protocol type sits
        // at offset 0. `etherparse` has no SLL2 parser at all, so this arm
        // does the whole walk itself.
        LinkType::LinuxSll2 => {
            if data.len() < SLL2_HEADER_LEN {
                return Err(CaptureError::TooShort {
                    what: "Linux SLL2 packet",
                    need: SLL2_HEADER_LEN,
                    got: data.len(),
                });
            }
            let off = match sll_payload(
                data,
                SLL2_ARPHRD_OFF,
                SLL2_PROTO_OFF,
                SLL2_HEADER_LEN,
                budget,
            ) {
                Some(EthPayload::Ip(off)) => off,
                Some(_) => SLL2_HEADER_LEN,
                None => {
                    return Err(CaptureError::NotIp {
                        what: "Linux SLL2 packet",
                    });
                }
            };
            slice_ip_at(data, off, "IP from Linux SLL2 packet")
        }
    }
}

/// Parse a raw captured [`Packet`] into a [`ParsedPacket`].
///
/// Walks through link-layer, network, and transport headers based on
/// the packet's `link_type`. Handles:
/// - Ethernet II (DLT_EN10MB), including VLAN / QinQ — 802.1Q (0x8100),
///   802.1ad (0x88A8) and the unregistered legacy 0x9100, up to
///   three stacked tags
/// - PPPoE Session (RFC 2516) inside Ethernet, including behind VLAN / QinQ
///   tags — the access encapsulation on DSL and much FTTH. Both the
///   uncompressed and the protocol-field-compressed PPP Protocol field are
///   accepted; PPPoE Discovery (0x8863) is not IP and is rejected.
/// - Linux cooked capture (DLT_LINUX_SLL / SLL2), including PPPoE Session and
///   a re-inserted VLAN tag inside either — the protocol type is read at
///   offset 14 on SLL and offset 0 on SLL2, and only where the frame's
///   ARPHRD_ type makes it an EtherType at all
/// - PPP as a link layer: DLT_PPP (9) with or without RFC 1662 §3.1 HDLC
///   address/control octets, DLT_PPP_SERIAL (50) with them, and
///   DLT_PPP_ETHER (51), which is a bare PPPoE session packet
/// - Raw IP: DLT_RAW (12) for either version, DLT_IPV4 (228) and DLT_IPV6
///   (229) for the one version each declares
/// - BSD loopback (DLT_NULL, DLT_LOOP): a 4-byte address family then the IP
///   header, host byte order on DLT_NULL and network byte order on DLT_LOOP
/// - MPLS (0x8847 / 0x8848), NSH (0x894F), MACsec (0x88E5) and the PBB I-TAG
///   (0x88E7) inside Ethernet, each behind VLAN tags or the others
/// - Encapsulation stripping: IP-in-IP (protocol 4), 6in4 (41), GRE (47)
///   including Transparent Ethernet Bridging, MPLS-in-IP (137) and the
///   Authentication Header (51); plus the UDP tunnels claimed by destination
///   port (VXLAN, GTP-U, Geneve, Teredo, L2TP). See the module docs for the
///   shared depth budget that bounds all of them together.
///
/// # Errors
///
/// Returns a matchable [`CaptureError`] when the packet cannot be parsed
/// (e.g., too short, unsupported link type, non-IP traffic like ARP).
///
/// # Examples
///
/// ```
/// use sipnab::capture::packet::Packet;
/// use sipnab::capture::parse::parse_packet;
/// use sipnab::CaptureError;
///
/// // A minimal raw-IP (DLT_RAW = 12) UDP packet: IPv4 header + UDP header.
/// let ip_udp: Vec<u8> = vec![
///     0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, // IPv4, proto 17 (UDP)
///     10, 0, 0, 1, 10, 0, 0, 2, // 10.0.0.1 -> 10.0.0.2
///     0x13, 0xc4, 0x13, 0xc4, 0, 8, 0, 0, // 5060 -> 5060, len 8
/// ];
/// let pkt = Packet::new(chrono::Utc::now(), ip_udp, 28, 28, None, 12);
/// let parsed = parse_packet(&pkt)?;
/// assert_eq!(parsed.src_port, 5060);
/// assert_eq!(parsed.dst_addr.to_string(), "10.0.0.2");
///
/// // Unsupported link types are a matchable error:
/// let odd = Packet::new(chrono::Utc::now(), vec![0; 64], 64, 64, None, 147);
/// assert!(matches!(
///     parse_packet(&odd),
///     Err(CaptureError::UnsupportedLinkType(147))
/// ));
/// # Ok::<(), sipnab::CaptureError>(())
/// ```
pub fn parse_packet(packet: &Packet) -> Result<ParsedPacket, CaptureError> {
    let mut parsed = parse_packet_unstamped(packet)?;
    // Stamp provenance once, at the boundary, rather than threading it through
    // the encapsulation recursion. Every return path in the header walk --
    // plain, IP-in-IP, GRE, SCTP, the pre-parsed HEP shortcut -- funnels back
    // through here, so one assignment covers all of them. A parameter carried
    // down through `parse_inner_ip` and `parse_gre` would be one more thing the
    // next decapsulation path could forget to pass, and a frame that silently
    // loses its pointer is indistinguishable from one that never had one.
    parsed.frame = packet.frame_locator();
    Ok(parsed)
}

/// [`parse_packet`] without the provenance stamp — the header walk itself.
///
/// Split out so the stamp has exactly one site. Callers want `parse_packet`.
fn parse_packet_unstamped(packet: &Packet) -> Result<ParsedPacket, CaptureError> {
    // Short-circuit: when the packet's source already knows the
    // addressing (e.g. HEP listener that reads it from HEP chunks),
    // skip link/IP/transport parsing and produce a ParsedPacket
    // directly. `data` is the transport-layer payload only.
    if let Some(meta) = &packet.pre_parsed {
        // A non-SIP transport (not UDP/TCP/SCTP) carries no message we can
        // label without guessing; reject it so downstream never sees a
        // mislabeled transport (e.g. ESP silently reported as UDP).
        let transport = ip_protocol_to_transport(meta.ip_protocol)
            .ok_or(CaptureError::UnsupportedIpProtocol(meta.ip_protocol))?;
        return Ok(ParsedPacket {
            // Carried, not dropped. A uprobe read's whole provenance is this
            // pointer -- it is the only thing that says which process the
            // bytes came out of -- and a HEP packet's pointer is equally
            // meaningful. `frame_locator` yields None when either half is
            // missing, which is the old behavior for sources that set neither.
            frame: packet.frame_locator(),
            timestamp: packet.timestamp,
            src_addr: meta.src_addr,
            dst_addr: meta.dst_addr,
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            transport,
            payload: packet.data.clone(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: meta.ip_protocol,
            // No IP header was observed. HEP delivers addressing in chunks a
            // remote sender asserted, and carries no DSCP chunk at all, so
            // there is nothing to read and nothing honest to guess. `Some(0)`
            // here would tell an operator their HEP-fed trunk is unmarked.
            dscp: None,
            // Pre-parsed no longer implies HEP: a uprobe read has no IP header
            // either. The kind comes from the source name through the SAME
            // function that recovers it for a frame pointer, so the two cannot
            // disagree about the same string -- and a disagreement here would
            // decide whether scanner-kill may transmit.
            input_origin: match packet
                .interface
                .as_deref()
                .map(crate::capture::packet::FrameSource::from_source_name)
            {
                Some(crate::capture::packet::FrameSource::Uprobe { .. }) => InputOrigin::Uprobe,
                _ => InputOrigin::Hep,
            },
        });
    }

    let data = &packet.data;
    let budget = &mut Budget::new();

    // First-pass parse based on link type
    let sliced = slice_link_layer(packet.link_type, data, budget)?;

    // Extract IP-layer information
    let net = sliced
        .net
        .as_ref()
        .ok_or(CaptureError::NotIp { what: "packet" })?;

    // Check for encapsulation and handle recursively
    let ip_payload = net
        .ip_payload_ref()
        .ok_or(CaptureError::NoIpPayload { what: "packet" })?;

    if let Some(parsed) = walk_ip_encapsulation(
        packet.timestamp,
        &packet.data,
        net,
        ip_payload.ip_number,
        ip_payload.payload,
        ip_payload.fragmented,
        budget,
    ) {
        return parsed;
    }

    // Normal (non-encapsulated) packet — extract fields
    extract_parsed_packet(
        packet.timestamp,
        &packet.data,
        net,
        &sliced.transport,
        budget,
    )
}

// ── Encapsulation helpers ─────────────────────────────────────────────

/// Maximum encapsulation layers walked in one frame.
///
/// Deliberately a budget for the *whole* frame rather than a per-kind depth:
/// see [`Budget`].
const MAX_ENCAP_DEPTH: u8 = 5;

/// The one encapsulation budget for one frame's walk.
///
/// Every decapsulation in this file — VLAN-adjacent link tunnels (PPPoE, MPLS,
/// NSH, MACsec, PBB), IP-in-IP, 6in4, GRE, GRE-TEB, AH, MPLS-in-IP and every
/// UDP tunnel — spends from this single counter, threaded by `&mut` through
/// the whole walk so a nested layer cannot get a fresh allowance.
///
/// A per-kind limit would be no limit at all. Capture data is
/// attacker-controlled, and each encapsulation this parser learns adds another
/// axis to alternate along: MACsec inside QinQ inside MPLS inside GTP-U inside
/// IP-in-IP would otherwise walk five times as far as five layers of any one
/// of them, for a frame that costs the sender nothing to build. Sharing the
/// counter makes the walk's depth — and so its cost, and its stack usage —
/// a property of the parser rather than of the frame.
///
/// Not `Copy`, on purpose: a copy is a second budget.
#[derive(Debug)]
struct Budget {
    /// Layers already spent by this frame.
    spent: u8,
}

impl Budget {
    /// A frame's full allowance.
    const fn new() -> Self {
        Self { spent: 0 }
    }

    /// Charge one encapsulation layer, or `None` once the frame has spent
    /// [`MAX_ENCAP_DEPTH`] of them.
    ///
    /// The `Option` shape is for the link-layer walk, which has no error
    /// channel; [`Budget::charge`] is the same gate for callers that do.
    fn spend(&mut self) -> Option<()> {
        if self.spent >= MAX_ENCAP_DEPTH {
            return None;
        }
        self.spent += 1;
        Some(())
    }

    /// [`Budget::spend`], reporting the refusal as `EncapTooDeep`.
    ///
    /// `kind` names the layer that could not be walked, so the error says
    /// which encapsulation the frame ran out of budget on.
    fn charge(&mut self, kind: &'static str) -> Result<(), CaptureError> {
        self.spend().ok_or(CaptureError::EncapTooDeep {
            kind,
            limit: MAX_ENCAP_DEPTH,
        })
    }
}

/// IANA IP protocol 137, MPLS-in-IP (RFC 4023 §3: "IANA has assigned the IP
/// protocol number 137 for MPLS-in-IP"). The label stack begins at the first
/// byte after the IP header.
const IP_PROTO_MPLS_IN_IP: IpNumber = IpNumber(137);

/// Dispatch one IP payload to whatever encapsulation its protocol number
/// names, or `None` when the payload is not an encapsulation this parser
/// walks.
///
/// Shared by the outer parse and by [`parse_inner_ip`] so a tunnel nested
/// inside another is decoded exactly like one at the top, and so a newly
/// supported protocol number cannot be wired into one of the two and forgotten
/// in the other.
///
/// `ip_data` is the IP payload — the bytes after the IP header — and must
/// alias `data`, because the offset-based decapsulators are handed absolute
/// offsets into the frame.
///
/// Every arm requires `!fragmented`: a non-first fragment's payload is not a
/// tunnel header but the middle of one, and a first fragment carries only the
/// head of whatever it wraps.
fn walk_ip_encapsulation(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    net: &NetSlice<'_>,
    ip_number: IpNumber,
    ip_data: &[u8],
    fragmented: bool,
    budget: &mut Budget,
) -> Option<Result<ParsedPacket, CaptureError>> {
    if fragmented {
        return None;
    }
    match ip_number {
        // IP-in-IP (protocol 4) and 6in4 (protocol 41). `parse_inner_ip` uses
        // `SlicedPacket::from_ip`, which detects the inner IP version, so it
        // handles both alike.
        IpNumber::IPV4 | IpNumber::IPV6 => Some(parse_inner_ip(timestamp, data, ip_data, budget)),
        IpNumber::GRE => Some(parse_gre(timestamp, data, ip_data, budget)),
        IP_PROTO_MPLS_IN_IP => Some(parse_mpls_in_ip(timestamp, data, ip_data, budget)),
        // AH authenticates without encrypting, so what it protects is in the
        // clear. `etherparse` walks a single AH itself; reaching this arm
        // means a second one, which it stops at.
        //
        // ESP (protocol 50) is deliberately absent: its payload is
        // ciphertext, and reporting ciphertext as a SIP message would be a
        // fabricated call rather than a missed one.
        IpNumber::AUTHENTICATION_HEADER => {
            Some(parse_after_ah(timestamp, data, net, ip_data, budget))
        }
        _ => None,
    }
}

/// Parse an inner IP packet (from IP-in-IP or after GRE stripping).
///
/// The `depth` parameter tracks recursion depth to prevent stack exhaustion
/// from maliciously crafted packets with deeply nested encapsulation.
///
/// # Arguments
///
/// * `timestamp` — capture time carried through from the outer packet.
/// * `data` — the original packet's refcounted buffer, used so the payload
///   can be sliced zero-copy.
/// * `ip_data` — the inner bytes starting at the inner IP header.
/// * `budget` — the frame's shared encapsulation budget; one unit is spent
///   here, before anything is decoded.
///
/// # Returns
///
/// The `ParsedPacket` for the innermost packet after stripping any further
/// encapsulation layers.
///
/// # Errors
///
/// Returns `EncapTooDeep` once the frame's [`Budget`] is spent, or the
/// decode/extraction errors of the nested parse.
fn parse_inner_ip(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    ip_data: &[u8],
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    budget.charge("IP-in-IP")?;

    let sliced = SlicedPacket::from_ip(ip_data).map_err(|e| CaptureError::PacketDecode {
        what: "inner IP packet",
        source: Box::new(e),
    })?;

    let net = sliced.net.as_ref().ok_or(CaptureError::NotIp {
        what: "inner packet",
    })?;

    // Check for nested encapsulation (unlikely but possible)
    let ip_payload = net.ip_payload_ref().ok_or(CaptureError::NoIpPayload {
        what: "inner packet",
    })?;

    if let Some(parsed) = walk_ip_encapsulation(
        timestamp,
        data,
        net,
        ip_payload.ip_number,
        ip_payload.payload,
        ip_payload.fragmented,
        budget,
    ) {
        return parsed;
    }

    extract_parsed_packet(timestamp, data, net, &sliced.transport, budget)
}

/// Parse an MPLS-in-IP packet (RFC 4023): a label stack sitting directly on
/// an IP header, no shim protocol in between.
///
/// `ip_data` is the IP payload and must alias `data`: `mpls::decap` measures
/// from the frame rather than from a subslice, so the payload's absolute
/// offset has to be recovered before the stack is handed over. Passing the
/// subslice's own base would point the label walk at the frame's Ethernet
/// header.
///
/// # Errors
///
/// `EncapTooDeep` once the frame's [`Budget`] is spent, `NotIp` for a label
/// stack that does not resolve to a packet this parser can read, or the
/// nested parse's errors.
fn parse_mpls_in_ip(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    ip_data: &[u8],
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    budget.charge("MPLS-in-IP")?;
    const UNREADABLE: CaptureError = CaptureError::NotIp {
        what: "MPLS-in-IP payload",
    };
    let base = subslice_range(data, ip_data).ok_or(UNREADABLE)?;
    let inner = tunnel::mpls::decap(data, base.start).ok_or(UNREADABLE)?;
    parse_tunnel_inner(timestamp, data, inner, budget)
}

/// Continue the walk into whatever a decapsulator reported.
///
/// The single place an [`Inner`] becomes a parse, so every tunnel — MPLS, NSH,
/// PBB, VXLAN, GTP-U, Geneve, Teredo, L2TP, GRE-TEB — reaches the inner packet
/// by the same route and gets the same treatment for an unreadable payload.
///
/// No budget is spent here: the caller that produced the `Inner` already paid
/// for the layer it stripped.
///
/// # Errors
///
/// `TooShort` when the reported offset is past the captured frame, `NotIp`
/// naming the encapsulation for an [`Inner::Opaque`] payload, or the nested
/// parse's own errors.
fn parse_tunnel_inner(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    inner: Inner,
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    match inner {
        Inner::Ip(off) => {
            let ip = data.get(off..).ok_or(CaptureError::TooShort {
                what: "encapsulated IP packet",
                need: off,
                got: data.len(),
            })?;
            parse_inner_ip(timestamp, data, ip, budget)
        }
        Inner::Ethernet(off) => parse_encapsulated_ethernet(timestamp, data, off, budget),
        // A diagnosis, not a decode failure: the frame was understood well
        // enough to say what is in it and why it cannot be read.
        Inner::Opaque(what) => Err(CaptureError::NotIp { what }),
    }
}

/// Parse a complete Ethernet II frame that arrived inside a tunnel.
///
/// `frame_start` is the offset of the encapsulated frame's destination MAC
/// within `data`. The frame gets the ordinary [`eth_payload`] walk — VLAN tags
/// and all — because an encapsulated frame is an ordinary frame; VXLAN and
/// GRE-TEB both carry tagged frames in the field.
///
/// # Errors
///
/// `NotIp` for an inner frame that carries no IP layer (or one this parser
/// cannot read), `TooShort` for a frame cut off before its payload, or the
/// nested parse's errors.
fn parse_encapsulated_ethernet(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    frame_start: usize,
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    match eth_payload(data, frame_start, budget) {
        Some(EthPayload::Ip(off)) => {
            let ip = data.get(off..).ok_or(CaptureError::TooShort {
                what: "encapsulated Ethernet frame",
                need: off,
                got: data.len(),
            })?;
            parse_inner_ip(timestamp, data, ip, budget)
        }
        Some(EthPayload::Opaque(what)) => Err(CaptureError::NotIp { what }),
        // An inner ARP / LLDP / unknown EtherType, or a walk that ran out of
        // budget or off the end of the capture. Either way there is no inner
        // IP packet to report.
        Some(EthPayload::Other) | None => Err(CaptureError::NotIp {
            what: "encapsulated Ethernet frame",
        }),
    }
}

// ── IP Authentication Header (RFC 4302) ───────────────────────────────

/// Octets of AH that are present regardless of the ICV: Next Header (1),
/// Payload Len (1), RESERVED (2), SPI (4) and Sequence Number (4)
/// (RFC 4302 §2).
const AH_FIXED_LEN: usize = 12;

/// Octets per unit of AH's Payload Len field.
///
/// RFC 4302 §2.2 defines Payload Len as "the length of this Authentication
/// Header in 4-octet units, minus 2" — the IPv6 extension-header convention
/// (RFC 8200 §4.2), which AH follows even over IPv4. So a 24-octet AH (the
/// 12 fixed octets plus a 96-bit ICV, "the default length" of §2.6) writes 4,
/// not 6 and not 24. Reading the field as octets, or forgetting the bias,
/// lands the walk in the middle of the ICV.
const AH_LEN_UNIT: usize = 4;

/// The bias subtracted from AH's true length before it is written to Payload
/// Len; see [`AH_LEN_UNIT`].
const AH_LEN_BIAS: usize = 2;

/// The UDP header (RFC 768): source and destination ports, Length, Checksum.
const UDP_HEADER_LEN: usize = 8;

/// The TCP header without options (RFC 9293 §3.1), i.e. a Data Offset of 5.
const TCP_HEADER_MIN: usize = 20;

/// The protected payload of one Authentication Header: its Next Header value
/// and the bytes that follow the header.
///
/// `ah` starts at the AH itself. Returns `None` — never a panic, never a read
/// past `ah` — for a header truncated before its fixed part, a Payload Len
/// that describes a header shorter than the fixed part, or one that runs past
/// the captured bytes.
fn ah_payload(ah: &[u8]) -> Option<(u8, &[u8])> {
    let next_header = *ah.first()?;
    let header_len = usize::from(*ah.get(1)?)
        .checked_add(AH_LEN_BIAS)?
        .checked_mul(AH_LEN_UNIT)?;
    // A header shorter than its own mandatory fields is not an AH, and
    // trusting it would move the walk backwards.
    if header_len < AH_FIXED_LEN {
        return None;
    }
    Some((next_header, ah.get(header_len..)?))
}

/// Walk one or more stacked Authentication Headers and parse what they
/// protect.
///
/// AH provides "connectionless integrity, data origin authentication, and an
/// optional anti-replay service" (RFC 4302 §1) and **no confidentiality**, so
/// unlike ESP the protected payload is sitting in the capture in plain text.
/// Throwing it away loses signaling that is legible.
///
/// Both IPsec modes are handled, because they put different things behind the
/// header. In tunnel mode the payload is a whole IP packet and the addresses
/// that matter are the inner ones. In transport mode AH protects the transport
/// header of *this* datagram, so the outer addresses are already the right
/// ones and only the ports and payload come from behind the header — which is
/// why `net` is threaded in here.
///
/// # Errors
///
/// `EncapTooDeep` once the frame's [`Budget`] is spent, `TooShort` for a
/// truncated header, `UnsupportedIpProtocol` for a protected protocol that is
/// not IPv4, IPv6, UDP or TCP, or the nested parse's errors.
fn parse_after_ah(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    net: &NetSlice<'_>,
    ah_data: &[u8],
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    let mut next = IpNumber::AUTHENTICATION_HEADER;
    let mut rest = ah_data;
    // Bounded by the budget, which every header spends from: a chain of AH
    // Next Header values pointing at each other cannot spin.
    while next == IpNumber::AUTHENTICATION_HEADER {
        budget.charge("AH")?;
        let (nh, protected) = ah_payload(rest).ok_or(CaptureError::TooShort {
            what: "IP Authentication Header",
            need: AH_FIXED_LEN,
            got: rest.len(),
        })?;
        next = IpNumber(nh);
        rest = protected;
    }

    // Tunnel mode: the protected payload is a complete IP packet.
    if next == IpNumber::IPV4 || next == IpNumber::IPV6 {
        return parse_inner_ip(timestamp, data, rest, budget);
    }

    // Transport mode: the addresses stay outer and only the transport header
    // moved, so the ordinary extraction runs against the outer `net` with a
    // transport slice taken from behind the header.
    let (sliced, need) = match next {
        // Lax on the UDP Length field for the same reason the rest of this
        // file is: a snaplen-truncated capture legitimately holds less than
        // the header declares, and refusing those would drop real traffic.
        IpNumber::UDP => (
            UdpSlice::from_slice_lax(rest).ok().map(TransportSlice::Udp),
            UDP_HEADER_LEN,
        ),
        IpNumber::TCP => (
            TcpSlice::from_slice(rest).ok().map(TransportSlice::Tcp),
            TCP_HEADER_MIN,
        ),
        _ => return Err(CaptureError::UnsupportedIpProtocol(next.0)),
    };
    let transport = sliced.ok_or(CaptureError::TooShort {
        what: "AH-protected transport header",
        need,
        got: rest.len(),
    })?;

    let mut parsed = extract_parsed_packet(timestamp, data, net, &Some(transport), budget)?;
    // The outer IP header says 51; what it protects is what the packet
    // actually carries, and it is what fragment reassembly and every consumer
    // downstream need to see.
    parsed.ip_protocol = next.0;
    Ok(parsed)
}

/// The inner protocol and the offset the inner packet starts at, from a GRE
/// header's flags and its optional checksum / key / sequence fields.
///
/// Factored out of [`parse_gre`] because the ICMP walker needs to reach the
/// same inner packet, and two copies of this arithmetic would be two places
/// for a tunneled packet's start offset to drift.
///
/// # Errors
///
/// `TooShort` for a header truncated before its base or its optional fields.
fn gre_inner_offset(gre_data: &[u8]) -> Result<(u16, usize), CaptureError> {
    if gre_data.len() < GRE_HEADER_MIN {
        return Err(CaptureError::TooShort {
            what: "GRE header",
            need: GRE_HEADER_MIN,
            got: gre_data.len(),
        });
    }

    let flags = u16::from_be_bytes([gre_data[0], gre_data[1]]);
    let protocol = u16::from_be_bytes([gre_data[2], gre_data[3]]);

    // Calculate variable header length based on optional fields
    let mut offset = GRE_HEADER_MIN;
    if flags & GRE_FLAG_CHECKSUM != 0 {
        offset += 4; // checksum (2) + reserved (2)
    }
    if flags & GRE_FLAG_KEY != 0 {
        offset += 4;
    }
    if flags & GRE_FLAG_SEQ != 0 {
        offset += 4;
    }

    if gre_data.len() < offset {
        return Err(CaptureError::TooShort {
            what: "GRE optional fields",
            need: offset,
            got: gre_data.len(),
        });
    }
    Ok((protocol, offset))
}

/// Parse a GRE-encapsulated packet.
///
/// Strips the GRE header (variable length based on flags) and re-parses
/// the inner IP packet.
///
/// # Arguments
///
/// * `timestamp` — capture time carried through from the outer packet.
/// * `data` — the original packet's refcounted buffer for zero-copy slicing.
/// * `gre_data` — bytes starting at the GRE header.
/// * `budget` — the frame's shared encapsulation budget.
///
/// # Returns
///
/// The `ParsedPacket` for the packet carried inside the GRE tunnel.
///
/// # Errors
///
/// Returns `EncapTooDeep` once the frame's [`Budget`] is spent, `TooShort` for
/// a truncated GRE header or optional fields, `UnsupportedGreProtocol` for a
/// payload type this parser does not decode, or the nested parse's errors.
fn parse_gre(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    gre_data: &[u8],
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    let (protocol, offset) = gre_inner_offset(gre_data)?;
    let inner = &gre_data[offset..];

    match protocol {
        // `parse_inner_ip` charges the budget for this layer.
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => parse_inner_ip(timestamp, data, inner, budget),
        // Transparent Ethernet Bridging: a whole frame, so the Ethernet walk
        // is re-entered at its destination MAC.
        GRE_PROTO_TEB => {
            budget.charge("GRE-TEB")?;
            let frame_start = subslice_range(data, inner)
                .ok_or(CaptureError::UnsupportedGreProtocol(protocol))?
                .start;
            parse_encapsulated_ethernet(timestamp, data, frame_start, budget)
        }
        _ => Err(CaptureError::UnsupportedGreProtocol(protocol)),
    }
}

// ── Field extraction ──────────────────────────────────────────────────

/// Extract a [`ParsedPacket`] from already-parsed network and transport slices.
///
/// Pulls addresses, fragmentation fields, and the IP protocol from `net`,
/// then extracts ports/payload from `transport` — with special handling for
/// IP fragments (no transport header; ports 0) and SCTP (parsed manually,
/// failing closed to an empty payload on malformed chunks). `data` is the
/// original packet's refcounted buffer so payloads are zero-copy slices.
///
/// # Errors
///
/// Returns `NotIp` for ARP, `NoTransport` when a non-fragment packet lacks
/// a transport slice, and `Icmp` for ICMPv4/v6 traffic.
///
/// # Side effects
///
/// An ICMP/ICMPv6 *error* is recorded as evidence via
/// [`crate::pipeline::record_icmp_error`] before the `Icmp` error is returned
/// — see the comment on that arm for why the recording lives here. Nothing
/// else in this function touches shared state.
fn extract_parsed_packet(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    net: &NetSlice<'_>,
    transport: &Option<TransportSlice<'_>>,
    budget: &mut Budget,
) -> Result<ParsedPacket, CaptureError> {
    // IP addresses
    let (src_addr, dst_addr, ip_id, fragment_offset, more_fragments, ip_protocol) = match net {
        NetSlice::Ipv4(v4) => {
            let hdr = v4.header();
            (
                IpAddr::V4(hdr.source_addr()),
                IpAddr::V4(hdr.destination_addr()),
                Some(u32::from(hdr.identification())),
                Some(hdr.fragments_offset().value()),
                hdr.more_fragments(),
                // The *payload's* protocol, not the header's, so an IPv4
                // packet carrying an Authentication Header reports what AH
                // protects rather than 51 — which is what `reparse_transport`
                // needs after fragment reassembly, and what IPv6 has always
                // reported here (`v6.payload().ip_number`).
                //
                // Only when the payload is whole: `etherparse` walks the AH
                // whenever the header names protocol 51, including on a
                // non-first fragment, where those bytes are the middle of the
                // datagram and not a header at all. A fragment must key on
                // the number the IP header actually states.
                if v4.payload().fragmented {
                    hdr.protocol().0
                } else {
                    v4.payload().ip_number.0
                },
            )
        }
        NetSlice::Ipv6(v6) => {
            let hdr = v6.header();
            // IPv6 fragmentation is carried in a Fragment extension header, not
            // the base header — pull its offset / MF / 32-bit id so fragments
            // are reassembled (otherwise each fragment is mis-parsed as a whole
            // datagram and the SIP message is silently dropped).
            //
            // The overwhelmingly common case is no extension headers at all, so
            // short-circuit on the empty chain: that path allocates nothing and
            // walks nothing. Only when extension headers are actually present do
            // we scan for the Fragment header. `etherparse`'s `IntoIterator` is
            // by value only (there is no by-reference iterator), so scanning
            // needs an owned `Ipv6ExtensionsSlice`; `.clone()` there is a
            // field-wise copy of a slice reference plus two small fields — no
            // heap allocation — and now happens off the hot path.
            let exts = v6.extensions();
            let (foff, more, id) = if exts.is_empty() {
                (None, false, None)
            } else {
                exts.clone()
                    .into_iter()
                    .find_map(|ext| match ext {
                        Ipv6ExtensionSlice::Fragment(f) => Some((
                            Some(f.fragment_offset().value()),
                            f.more_fragments(),
                            Some(f.identification()),
                        )),
                        _ => None,
                    })
                    .unwrap_or((None, false, None))
            };
            (
                IpAddr::V6(hdr.source_addr()),
                IpAddr::V6(hdr.destination_addr()),
                id,
                foff,
                more,
                // the ip_number from the payload (after ext headers)
                v6.payload().ip_number.0,
            )
        }
        // ARP (added as a NetSlice variant in etherparse 0.20) carries no IP
        // layer; sipnab only parses SIP/RTP over IP, so reject it here.
        NetSlice::Arp(_) => return Err(CaptureError::NotIp { what: "ARP packet" }),
    };

    // The DSCP the network was asked to honor for this packet.
    //
    // Read here rather than in the tuple above because it is the only field
    // whose IPv4 and IPv6 accessors carry different names for the same six
    // bits — etherparse spells the IPv4 one `dcp` — and burying that in a
    // six-element tuple hides the asymmetry a reader has to know about.
    //
    // `net` is the INNERMOST network slice: `parse_inner_ip` re-slices and
    // re-enters this function per encapsulation layer, so every tunnel
    // (IP-in-IP, GRE, MPLS-in-IP, AH tunnel mode, VXLAN, GTP-U, Geneve,
    // Teredo, L2TP) records the marking of the packet the operator sent, not
    // the carrier's outer wrapper. That is the answer an operator wants: the
    // outer marking is the transit provider's business and the inner one is
    // theirs.
    let dscp = Some(match net {
        NetSlice::Ipv4(v4) => v4.header().dcp().value(),
        NetSlice::Ipv6(v6) => v6.header().dscp().value(),
        // Unreachable: the IP-address match above already bails on ARP.
        NetSlice::Arp(_) => 0,
    });

    // Check if this is a fragment (non-first fragment has no transport header)
    let is_fragment = match net {
        NetSlice::Ipv4(v4) => v4.header().is_fragmenting_payload(),
        NetSlice::Ipv6(_) => {
            // etherparse sets fragmented in the payload slice
            net.ip_payload_ref().map(|p| p.fragmented).unwrap_or(false)
        }
        // Unreachable: the IP-address match above already bails on ARP.
        NetSlice::Arp(_) => false,
    };

    // For non-first fragments, there's no transport header
    if is_fragment {
        let payload = net
            .ip_payload_ref()
            .map(|p| slice_of(data, p.payload))
            .unwrap_or_default();

        return Ok(ParsedPacket {
            frame: None,
            timestamp,
            src_addr,
            dst_addr,
            src_port: 0,
            dst_port: 0,
            transport: TransportProto::Udp, // placeholder; reassembly will determine this
            payload,
            ip_id,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset,
            more_fragments,
            ip_protocol,
            dscp,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        });
    }

    // SCTP: etherparse does not parse SCTP, so it arrives with no transport
    // slice. Recover the ports and the SIP payload from the first complete DATA
    // chunk ourselves. On any malformed/truncated SCTP, fail closed to an empty
    // payload so downstream never misreads SCTP header bytes as a SIP message.
    if ip_protocol == 132 {
        let extracted = net.ip_payload_ref().and_then(|p| {
            let data_ref = find_sctp_data_chunk(p.payload, true)?;
            let sip = p.payload.get(data_ref.payload)?;
            Some((data_ref.src_port, data_ref.dst_port, slice_of(data, sip)))
        });
        let (src_port, dst_port, payload) = extracted.unwrap_or((0, 0, bytes::Bytes::new()));
        return Ok(ParsedPacket {
            frame: None,
            timestamp,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            transport: TransportProto::Sctp,
            payload,
            ip_id,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset,
            more_fragments,
            ip_protocol,
            dscp,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        });
    }

    // Transport header extraction
    let transport_slice = transport.as_ref().ok_or(CaptureError::NoTransport)?;

    // UDP tunnels (VXLAN, GTP-U, Geneve, Teredo, L2TP, UDP-encapsulated ESP)
    // are claimed by destination port, so the check runs here — after the
    // fragment return above, which is the fragment guard: `etherparse` slices
    // no transport at all for a fragmented payload, so a fragment never
    // reaches this line and a second guard here would be unreachable code
    // asserting the same thing.
    //
    // `udp.payload()` rather than the IP payload, deliberately: `etherparse`
    // bounds it by the UDP Length field, which is what makes Ethernet's
    // 60-octet minimum padding invisible to every length check the
    // decapsulators run. `base` comes from `subslice_range` against the SAME
    // `data` the returned offsets are used in. And only the destination port
    // is offered — a tunnel port appearing as the *source* port is an
    // ordinary ephemeral port on an RTP stream, and reading that stream's
    // samples as a tunnel header is how a decoder invents a call.
    if let TransportSlice::Udp(udp) = transport_slice
        && let Some(range) = subslice_range(data, udp.payload())
        && let Some(inner) = tunnel::udp::decap(udp.payload(), range.start, udp.destination_port())
    {
        // Charged only on a successful decap, so ordinary UDP — which is
        // almost all of it — pays nothing for tunnels being supported.
        budget.charge("UDP tunnel")?;
        return parse_tunnel_inner(timestamp, data, inner, budget);
    }

    match transport_slice {
        TransportSlice::Udp(udp) => Ok(ParsedPacket {
            frame: None,
            timestamp,
            src_addr,
            dst_addr,
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
            transport: TransportProto::Udp,
            payload: slice_of(data, udp.payload()),
            ip_id,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset,
            more_fragments,
            ip_protocol,
            dscp,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        }),
        TransportSlice::Tcp(tcp) => Ok(ParsedPacket {
            frame: None,
            timestamp,
            src_addr,
            dst_addr,
            src_port: tcp.source_port(),
            dst_port: tcp.destination_port(),
            transport: TransportProto::Tcp,
            payload: slice_of(data, tcp.payload()),
            ip_id,
            tcp_seq: Some(tcp.sequence_number()),
            tcp_flags: Some(TcpFlags {
                syn: tcp.syn(),
                ack: tcp.ack(),
                fin: tcp.fin(),
                rst: tcp.rst(),
                psh: tcp.psh(),
            }),
            fragment_offset,
            more_fragments,
            ip_protocol,
            dscp,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        }),
        // ICMP is still not a `ParsedPacket` — it carries no message, and
        // making one would put a header prefix into message counts and dialog
        // ladders. But the error it reports is the most diagnostic thing in
        // the capture, so the quoted datagram is recorded as EVIDENCE on the
        // way past.
        //
        // Recording here, rather than at the call sites, is deliberate. Every
        // path into the parser funnels through this arm — file, live, HEP,
        // `--cores`, and each encapsulation layer — so this is the one place
        // that cannot be forgotten. It is also the only place that is correct
        // under `--cores`: sharding routes packets by outer host pair, and an
        // ICMP error's outer pair is (router, sender), which is a different
        // pair from the dialog it is evidence about. Per-worker state would
        // scatter the evidence away from the dialog; the process-global store
        // in `pipeline` does not care which worker saw it.
        //
        // The cost is confined to ICMP: the arm is only reached for IP
        // protocol 1 and 58, so the UDP/TCP hot paths never touch the lock.
        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
            // Only the recording below consumes this, and wasm does not build
            // the store it records into — so on wasm the binding is genuinely
            // unused rather than accidentally so.
            #[cfg_attr(target_arch = "wasm32", allow(unused_variables))]
            let msg = match transport_slice {
                TransportSlice::Icmpv4(icmp) => IcmpMessage {
                    icmp_type: icmp.type_u8(),
                    icmp_code: icmp.code_u8(),
                    payload: icmp.payload(),
                    v6: false,
                },
                TransportSlice::Icmpv6(icmp) => IcmpMessage {
                    icmp_type: icmp.type_u8(),
                    icmp_code: icmp.code_u8(),
                    payload: icmp.payload(),
                    v6: true,
                },
                // Unreachable: the outer arm already matched only ICMP.
                _ => return Err(CaptureError::Icmp),
            };
            // The evidence store lives in `pipeline`, which wasm does not
            // build. Parsing the quote is not native-only: a wasm build still
            // decodes it correctly, it just has nowhere to file it.
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(q) = icmp_quote(timestamp, data, src_addr, dst_addr, &msg) {
                crate::pipeline::record_icmp_error(&q);
            }
            Err(CaptureError::Icmp)
        }
        // IGMP (etherparse 0.21) is multicast group management, not ICMP, so it
        // reports as "not UDP/TCP" rather than borrowing the ICMP error.
        TransportSlice::Igmp(_) => Err(CaptureError::NoTransport),
        // NOTE: this match is deliberately exhaustive — no `_` arm. When
        // etherparse adds a transport, the build must fail here so someone
        // decides whether it can carry SIP or RTP. A wildcard would silently
        // drop a future SIP-bearing transport instead of surfacing it.
        // (sipnab's SCTP handling runs earlier, at IP protocol 132.)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

/// Tests for header parsing across link types, encapsulation stripping,
/// SCTP DATA-chunk extraction, the pre-parsed (HEP) short-circuit, and the
/// cheap host-pair peek used for multi-core sharding.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // Multi-core sharding (--cores): the cheap host-pair peek must extract the
    // outer src/dst IPs from the link+IP headers — for plain Ethernet, VLAN-tagged
    // frames, and gracefully return None for non-IP / truncated input (those
    // shard to worker 0). The peek must agree with the full parse on the IPs.
    /// `peek_host_pair` matches the full parse for plain and VLAN-tagged
    /// Ethernet, and returns `None` for non-IP or truncated frames.
    #[test]
    fn peek_host_pair_extracts_endpoints() {
        use std::net::{IpAddr, Ipv4Addr};
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);

        // plain Ethernet/IPv4
        let pkt = make_packet(
            build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x"),
            DLT_EN10MB,
        );
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
        // and it agrees with the full parse
        let parsed = parse_packet(&pkt).expect("parses");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );

        // 802.1Q VLAN-tagged: insert TPID 0x8100 + TCI before the IPv4 ethertype.
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");
        let mut vlan = base[0..12].to_vec(); // dst+src MAC
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]); // VLAN tag, VID 100
        vlan.extend_from_slice(&base[12..]); // ethertype 0x0800 + IPv4 …
        assert_eq!(
            peek_host_pair(&make_packet(vlan, DLT_EN10MB)),
            Some((IpAddr::V4(a), IpAddr::V4(b)))
        );

        // non-IP / truncated → None (caller shards these to worker 0)
        assert_eq!(peek_host_pair(&make_packet(vec![0u8; 8], DLT_EN10MB)), None);
        assert_eq!(peek_host_pair(&make_packet(vec![], DLT_EN10MB)), None);
    }

    /// After reassembly, a UDP buffer yields its ports and the 8-byte
    /// header offset.
    #[test]
    fn reparse_transport_udp_recovers_ports_and_strips_header() {
        // After IP reassembly the buffer is the IP payload = UDP header + body.
        // reparse must recover the ports and the offset past the 8-byte header.
        let mut buf = Vec::new();
        buf.extend_from_slice(&5060u16.to_be_bytes()); // src port
        buf.extend_from_slice(&5062u16.to_be_bytes()); // dst port
        buf.extend_from_slice(&0u16.to_be_bytes()); // len (ignored)
        buf.extend_from_slice(&0u16.to_be_bytes()); // cksum
        buf.extend_from_slice(b"OPTIONS sip:x SIP/2.0\r\n");
        let (sp, dp, tp, hdr) = reparse_transport(17, &buf).expect("udp reparse");
        assert_eq!((sp, dp), (5060, 5062));
        assert_eq!(tp, TransportProto::Udp);
        assert_eq!(&buf[hdr..hdr + 7], b"OPTIONS");
    }

    /// A TCP buffer's header length comes from the data-offset nibble.
    #[test]
    fn reparse_transport_tcp_uses_data_offset() {
        let mut buf = vec![0u8; 20];
        buf[0..2].copy_from_slice(&5060u16.to_be_bytes());
        buf[2..4].copy_from_slice(&40000u16.to_be_bytes());
        buf[12] = 5 << 4; // data offset = 5 words = 20 bytes, no options
        buf.extend_from_slice(b"INVITE");
        let (sp, dp, tp, hdr) = reparse_transport(6, &buf).expect("tcp reparse");
        assert_eq!((sp, dp), (5060, 40000));
        assert_eq!(tp, TransportProto::Tcp);
        assert_eq!(hdr, 20);
    }

    /// Truncated UDP/TCP buffers and unhandled protocols (SCTP) yield
    /// `None`.
    #[test]
    fn reparse_transport_rejects_truncated_and_unknown() {
        assert!(reparse_transport(17, &[0, 0, 0]).is_none()); // < 8 bytes
        assert!(reparse_transport(6, &[0u8; 10]).is_none()); // < 20 bytes
        assert!(reparse_transport(132, &[0u8; 40]).is_none()); // SCTP: not handled
    }

    /// Build a minimal Ethernet + IPv4 + UDP packet.
    fn build_eth_ipv4_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len: u16 = 8 + payload.len() as u16;
        let ip_total_len: u16 = 20 + udp_len;
        let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

        // Ethernet header (14 bytes)
        pkt.extend_from_slice(&[0xAA; 6]); // dst MAC
        pkt.extend_from_slice(&[0xBB; 6]); // src MAC
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // identification = 1
        pkt.extend_from_slice(&[0x40, 0x00]); // flags=DF, fragment offset=0
        pkt.push(64); // TTL
        pkt.push(17); // protocol: UDP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // UDP header (8 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum

        // Payload
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build a minimal Ethernet + IPv4 + IGMP packet (IP protocol 2).
    ///
    /// etherparse 0.21 added `TransportSlice::Igmp`, so IGMP now reaches the
    /// transport match instead of failing earlier. It carries neither SIP nor
    /// RTP, so the parser must report it as "not UDP/TCP" rather than panicking
    /// or being mistaken for ICMP.
    fn build_eth_ipv4_igmp(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        // IGMPv2 membership query: type, max-resp-time, checksum, group addr.
        let igmp: [u8; 8] = [0x11, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let ip_total_len: u16 = 20 + igmp.len() as u16;
        let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]);
        pkt.extend_from_slice(&[0x40, 0x00]);
        pkt.push(1); // TTL 1, as IGMP uses
        pkt.push(2); // protocol: IGMP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        pkt.extend_from_slice(&igmp);
        pkt
    }

    /// Build a minimal Ethernet + IPv4 + TCP packet.
    fn build_eth_ipv4_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8, // bit layout: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len: u16 = 20;
        let ip_total_len: u16 = 20 + tcp_header_len + payload.len() as u16;
        let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

        // Ethernet header
        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]);

        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x02]); // identification = 2
        pkt.extend_from_slice(&[0x40, 0x00]); // DF
        pkt.push(64);
        pkt.push(6); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        // TCP header (20 bytes, no options)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes()); // sequence number
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack number
        pkt.push(0x50); // data offset = 5 (20 bytes), reserved = 0
        pkt.push(flags); // flags
        pkt.extend_from_slice(&1024u16.to_be_bytes()); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        // Payload
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Build an Ethernet + IPv6 + UDP packet.
    fn build_eth_ipv6_udp(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len: u16 = 8 + payload.len() as u16;
        let mut pkt = Vec::with_capacity(14 + 40 + udp_len as usize);

        // Ethernet header
        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6

        // IPv6 header (40 bytes)
        pkt.push(0x60); // version=6, traffic class (upper 4 bits)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class (lower) + flow label
        pkt.extend_from_slice(&udp_len.to_be_bytes()); // payload length
        pkt.push(17); // next header: UDP
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src_ip); // source
        pkt.extend_from_slice(&dst_ip); // destination

        // UDP header
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum

        pkt.extend_from_slice(payload);
        pkt
    }

    /// Re-wrap an Ethernet frame's payload in a PPPoE header (RFC 2516 §4).
    ///
    /// `base` is a frame from [`build_eth_ipv4_udp`] / [`build_eth_ipv6_udp`];
    /// its 14-byte Ethernet header is kept but the EtherType is replaced by
    /// `ethertype`, and the 6-byte PPPoE header plus `ppp_proto` are spliced in
    /// ahead of the network layer — exactly the shape a DSL/FTTH access node
    /// puts on the wire. `ver_type` and `code` are parameters so the negative
    /// tests can craft a frame that is well-formed everywhere except the one
    /// field under test.
    ///
    /// LENGTH is set honestly (PPP Protocol field + payload, per RFC 2516 §4:
    /// it counts the PPPoE payload and excludes the Ethernet and PPPoE
    /// headers); [`pppoe_lying_length`] exists for the case where it is not.
    fn wrap_in_pppoe(
        base: &[u8],
        ethertype: u16,
        ver_type: u8,
        code: u8,
        ppp_proto: &[u8],
    ) -> Vec<u8> {
        let payload = &base[14..]; // everything past the base frame's EtherType
        let mut pkt = base[0..12].to_vec(); // dst+src MAC
        pkt.extend_from_slice(&ethertype.to_be_bytes());
        pkt.push(ver_type); // VER (4 bits) / TYPE (4 bits)
        pkt.push(code); // CODE
        pkt.extend_from_slice(&[0x18, 0xE5]); // SESSION_ID
        let len = (ppp_proto.len() + payload.len()) as u16;
        pkt.extend_from_slice(&len.to_be_bytes()); // LENGTH
        pkt.extend_from_slice(ppp_proto); // PPP Protocol field
        pkt.extend_from_slice(payload);
        pkt
    }

    /// A conforming PPPoE **Session** frame (EtherType 0x8864, VER/TYPE 0x11,
    /// CODE 0x00) carrying `ppp_proto` — RFC 2516 §6.
    fn pppoe_session(base: &[u8], ppp_proto: &[u8]) -> Vec<u8> {
        wrap_in_pppoe(base, 0x8864, 0x11, 0x00, ppp_proto)
    }

    /// A PPPoE Session frame whose LENGTH field claims far more payload than
    /// the frame holds — the shape a snaplen-truncated capture and a hostile
    /// sender both produce.
    fn pppoe_lying_length(base: &[u8]) -> Vec<u8> {
        let mut pkt = pppoe_session(base, &[0x00, 0x21]);
        pkt[18..20].copy_from_slice(&0xFFFFu16.to_be_bytes()); // LENGTH
        pkt
    }

    /// Prefix an 802.1Q (0x8100), 802.1ad (0x88A8) or legacy (0x9100) tag onto
    /// a frame, keeping the MACs first:
    /// `dst+src MAC | TPID | TCI | <original EtherType> …`.
    ///
    /// `tci` is written verbatim, so a caller that only cares about the VID can
    /// pass it directly (PCP and DEI then come out 0) and a caller testing what
    /// the priority bits do to a byte-offset walk can set the whole field.
    fn prepend_vlan_tag(base: &[u8], tpid: u16, tci: u16) -> Vec<u8> {
        let mut pkt = base[0..12].to_vec();
        pkt.extend_from_slice(&tpid.to_be_bytes());
        pkt.extend_from_slice(&tci.to_be_bytes());
        pkt.extend_from_slice(&base[12..]);
        pkt
    }

    /// SCTP common header (12 bytes): src port, dst port, verification tag,
    /// checksum.
    fn sctp_common_header(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(12);
        h.extend_from_slice(&src_port.to_be_bytes());
        h.extend_from_slice(&dst_port.to_be_bytes());
        h.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // verification tag
        h.extend_from_slice(&0u32.to_be_bytes()); // checksum (0 = skip)
        h
    }

    /// Build one SCTP DATA chunk (type 0) with the given `flags`, TSN, stream
    /// id, and stream seq, wrapping `payload` after the 12-byte data header
    /// (TSN, stream id, stream seq, PPID). The chunk is padded to the next
    /// 4-byte boundary.
    fn sctp_data_chunk_full(flags: u8, tsn: u32, sid: u16, ssn: u16, payload: &[u8]) -> Vec<u8> {
        let length = 4 + 12 + payload.len(); // chunk header + data header + value
        let mut chunk = Vec::new();
        chunk.push(0); // type: DATA
        chunk.push(flags);
        chunk.extend_from_slice(&(length as u16).to_be_bytes());
        chunk.extend_from_slice(&tsn.to_be_bytes()); // TSN
        chunk.extend_from_slice(&sid.to_be_bytes()); // stream id
        chunk.extend_from_slice(&ssn.to_be_bytes()); // stream seq
        chunk.extend_from_slice(&0u32.to_be_bytes()); // PPID
        chunk.extend_from_slice(payload);
        while chunk.len() % 4 != 0 {
            chunk.push(0); // padding to 4-byte boundary
        }
        chunk
    }

    /// Build one SCTP DATA chunk with the given `flags` at TSN 1, stream 0,
    /// stream seq 0 — the single-chunk shape used by the pre-existing tests.
    fn sctp_data_chunk(flags: u8, payload: &[u8]) -> Vec<u8> {
        sctp_data_chunk_full(flags, 1, 0, 0, payload)
    }

    /// Build an Ethernet/IPv4/SCTP packet (10.0.0.1 → 10.0.0.2, ports
    /// 5060/5062) carrying a single DATA chunk with the given fragment `flags`,
    /// TSN, stream id, and stream seq — one fragment of a message per packet.
    fn sctp_frag_packet(flags: u8, tsn: u32, sid: u16, ssn: u16, payload: &[u8]) -> Packet {
        let mut sctp = sctp_common_header(5060, 5062);
        sctp.extend_from_slice(&sctp_data_chunk_full(flags, tsn, sid, ssn, payload));
        let data = build_eth_ipv4_sctp_raw([10, 0, 0, 1], [10, 0, 0, 2], &sctp);
        make_packet(data, DLT_EN10MB)
    }

    /// The association endpoints used by [`sctp_frag_packet`].
    fn sctp_endpoints() -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::new("10.0.0.1".parse().unwrap(), 5060),
            SocketAddr::new("10.0.0.2".parse().unwrap(), 5062),
        )
    }

    // SCTP DATA fragment flags (RFC 4960 §3.3.1): B = beginning, E = ending.
    const SCTP_FLAG_E: u8 = 0x01;
    const SCTP_FLAG_B: u8 = 0x02;

    /// Wrap raw SCTP bytes (common header + chunks) in Ethernet + IPv4 with
    /// IP protocol byte = 132.
    fn build_eth_ipv4_sctp_raw(src_ip: [u8; 4], dst_ip: [u8; 4], sctp: &[u8]) -> Vec<u8> {
        let ip_total_len: u16 = 20 + sctp.len() as u16;
        let mut pkt = Vec::with_capacity(14 + ip_total_len as usize);

        // Ethernet header
        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        // IPv4 header (20 bytes, no options)
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&ip_total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x03]); // identification = 3
        pkt.extend_from_slice(&[0x40, 0x00]); // DF
        pkt.push(64);
        pkt.push(132); // protocol: SCTP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);

        pkt.extend_from_slice(sctp);
        pkt
    }

    /// Build Ethernet + IPv4 + SCTP with a single complete (B&E) DATA chunk
    /// carrying `sip`.
    fn build_eth_ipv4_sctp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        sip: &[u8],
    ) -> Vec<u8> {
        let mut sctp = sctp_common_header(src_port, dst_port);
        sctp.extend_from_slice(&sctp_data_chunk(0x03, sip)); // B|E
        build_eth_ipv4_sctp_raw(src_ip, dst_ip, &sctp)
    }

    /// Helper to create a [`Packet`] from raw data.
    fn make_packet(data: Vec<u8>, link_type: i32) -> Packet {
        let len = data.len();
        Packet::new(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            data,
            len,
            len,
            None,
            link_type,
        )
    }

    /// A plain Ethernet/IPv4/UDP packet parses with addresses, ports, and
    /// payload intact and no TCP fields.
    #[test]
    fn parse_ethernet_ipv4_udp() {
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let data = build_eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.src_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);
        assert!(parsed.tcp_seq.is_none());
        assert!(parsed.tcp_flags.is_none());
        assert_eq!(parsed.ip_id, Some(1));
    }

    /// An Ethernet/IPv4/TCP packet surfaces its sequence number and the
    /// exact flag set (PSH+ACK here).
    #[test]
    fn parse_ethernet_ipv4_tcp() {
        let payload = b"SIP/2.0 200 OK\r\n\r\n";
        let data = build_eth_ipv4_tcp(
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            5060,
            5061,
            1000,
            0x18, // PSH + ACK
            payload,
        );
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.src_addr, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "192.168.1.20".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5061);
        assert_eq!(parsed.transport, TransportProto::Tcp);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(parsed.tcp_seq, Some(1000));

        let flags = parsed.tcp_flags.unwrap();
        assert!(flags.psh);
        assert!(flags.ack);
        assert!(!flags.syn);
        assert!(!flags.fin);
        assert!(!flags.rst);
    }

    /// An Ethernet/IPv6/UDP packet parses; IPv6 has no identification
    /// field so `ip_id` is `None`.
    #[test]
    fn parse_ipv6_udp() {
        let payload = b"RTP data here";
        // ::1 -> ::2
        let mut src = [0u8; 16];
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[15] = 2;

        let data = build_eth_ipv6_udp(src, dst, 10000, 20000, payload);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.src_addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 10000);
        assert_eq!(parsed.dst_port, 20000);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);
        assert!(parsed.ip_id.is_none()); // IPv6 has no identification
    }

    /// A complete (B|E) SCTP DATA chunk yields its ports and the SIP
    /// payload with SCTP headers stripped.
    #[test]
    fn parse_ethernet_ipv4_sctp_data_chunk_sip() {
        let sip = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/SCTP\r\n\r\n";
        let data = build_eth_ipv4_sctp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5062, sip);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.src_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5062);
        assert_eq!(parsed.payload[..], sip[..]);
    }

    /// The SCTP extractor is payload-agnostic: non-SIP bytes pass through
    /// unmodified (SIP detection is downstream).
    #[test]
    fn parse_sctp_data_chunk_is_payload_agnostic() {
        // The transport parser only extracts bytes; SIP detection is downstream.
        let raw = b"\x00\x01\x02\x03not-sip-at-all\xff\xfe";
        let data = build_eth_ipv4_sctp([10, 0, 0, 5], [10, 0, 0, 6], 9000, 9001, raw);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 9000);
        assert_eq!(parsed.dst_port, 9001);
        assert_eq!(parsed.payload[..], raw[..]);
    }

    /// An SCTP packet shorter than the 12-byte common header fails closed:
    /// ports 0 and an empty payload, no panic.
    #[test]
    fn parse_sctp_common_header_truncated_yields_empty_payload() {
        // Fewer than the 12-byte common header — must not panic, empty payload.
        let sctp = vec![0x13, 0xc4, 0x13, 0xc6, 0x00, 0x00]; // 6 bytes only
        let data = build_eth_ipv4_sctp_raw([10, 0, 0, 1], [10, 0, 0, 2], &sctp);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
        assert!(parsed.payload.is_empty());
    }

    /// An SCTP packet containing only a SACK chunk (no DATA) yields an
    /// empty payload.
    #[test]
    fn parse_sctp_non_data_chunk_yields_empty_payload() {
        // A single SACK chunk (type 3), no DATA chunk present.
        let mut sctp = sctp_common_header(5060, 5062);
        let mut sack = Vec::new();
        sack.push(3); // type: SACK
        sack.push(0); // flags
        sack.extend_from_slice(&16u16.to_be_bytes()); // length incl. header
        sack.extend_from_slice(&[0u8; 12]); // cum TSN ack + a_rwnd + counts
        sctp.extend_from_slice(&sack);
        let data = build_eth_ipv4_sctp_raw([10, 0, 0, 1], [10, 0, 0, 2], &sctp);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
        assert!(parsed.payload.is_empty());
    }

    /// A DATA chunk whose declared length overruns the buffer fails closed
    /// to an empty payload.
    #[test]
    fn parse_sctp_data_chunk_length_past_buffer_yields_empty_payload() {
        // DATA chunk header claims a length that runs past the buffer end.
        let mut sctp = sctp_common_header(5060, 5062);
        sctp.push(0); // type: DATA
        sctp.push(0x03); // B|E
        sctp.extend_from_slice(&0xFFFFu16.to_be_bytes()); // absurd length
        sctp.extend_from_slice(&[0u8; 8]); // only a few value bytes actually present
        let data = build_eth_ipv4_sctp_raw([10, 0, 0, 1], [10, 0, 0, 2], &sctp);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
        assert!(parsed.payload.is_empty());
    }

    /// A fragmented DATA chunk (B without E) is skipped — no SCTP fragment
    /// reassembly — leaving an empty payload.
    #[test]
    fn parse_sctp_fragmented_data_chunk_yields_empty_payload() {
        // B set, E clear → a fragment; must be skipped (no reassembly here).
        let mut sctp = sctp_common_header(5060, 5062);
        sctp.extend_from_slice(&sctp_data_chunk(0x02, b"fragment start only")); // B, no E
        let data = build_eth_ipv4_sctp_raw([10, 0, 0, 1], [10, 0, 0, 2], &sctp);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse");

        assert_eq!(parsed.transport, TransportProto::Sctp);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
        assert!(parsed.payload.is_empty());
    }

    // ── SCTP cross-packet DATA fragment reassembly (RFC 4960 §3.3.1) ──────
    // A SIP message can be split across DATA chunks: a B (beginning) fragment,
    // zero or more middles, then an E (ending) fragment sharing one (SID, SSN)
    // with contiguous TSNs. These drive `parse_sctp_fragment` + `SctpReassembler`
    // — the cross-packet path the single-chunk `parse_packet` cannot cover.

    /// (a) A SIP INVITE split across three DATA chunks (B / middle / E) in three
    /// packets reassembles to the complete original message; only the E fragment
    /// completes it.
    #[test]
    fn sctp_data_reassembles_across_three_packets() {
        let sip: &[u8] =
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/SCTP\r\nContent-Length: 4\r\n\r\nbody";
        let (p1, p2, p3) = (&sip[..24], &sip[24..56], &sip[56..]);
        let (src, dst) = sctp_endpoints();
        let mut r = SctpReassembler::new();

        let f1 = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 1, 0, 0, p1)).expect("B frag");
        assert!(f1.begin && !f1.end, "first fragment is B, not E");
        assert!(
            r.insert(src, dst, &f1).is_none(),
            "B fragment alone does not complete a message"
        );

        let f2 = parse_sctp_fragment(&sctp_frag_packet(0x00, 2, 0, 0, p2)).expect("middle frag");
        assert!(
            r.insert(src, dst, &f2).is_none(),
            "middle fragment does not complete a message"
        );

        let f3 = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_E, 3, 0, 0, p3)).expect("E frag");
        let done = r
            .insert(src, dst, &f3)
            .expect("E fragment completes the reassembled message");
        assert_eq!(&done[..], sip, "reassembled INVITE matches the original");
        assert_eq!(
            r.len(),
            0,
            "the completed stream is removed from the buffer"
        );
    }

    /// (b) Fragments of one (SID, SSN) reassemble correctly even when a fragment
    /// of an unrelated stream (different SID) is interleaved between them.
    #[test]
    fn sctp_reassembly_is_isolated_per_stream() {
        let msg: &[u8] = b"MESSAGE sip:a SIP/2.0\r\nCall-ID: split\r\n\r\nhello-world-body";
        let (m1, m2, m3) = (&msg[..20], &msg[20..40], &msg[40..]);
        let (src, dst) = sctp_endpoints();
        let mut r = SctpReassembler::new();

        // Stream (sid=0, ssn=0): B fragment.
        let b0 = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 1, 0, 0, m1)).expect("b0");
        assert!(r.insert(src, dst, &b0).is_none());

        // An unrelated stream (sid=7) opens in between — must not disturb sid=0.
        let other = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 100, 7, 0, b"unrelated"))
            .expect("o");
        assert!(r.insert(src, dst, &other).is_none());

        // Stream (sid=0) middle then end.
        let mid0 = parse_sctp_fragment(&sctp_frag_packet(0x00, 2, 0, 0, m2)).expect("mid0");
        assert!(r.insert(src, dst, &mid0).is_none());
        let e0 = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_E, 3, 0, 0, m3)).expect("e0");
        let done = r
            .insert(src, dst, &e0)
            .expect("sid=0 completes independently of sid=7");
        assert_eq!(
            &done[..],
            msg,
            "sid=0 reassembled from only its own fragments"
        );
        assert_eq!(r.len(), 1, "the unrelated sid=7 stream is still buffered");
    }

    /// (c) A missing middle TSN (a gap) fails closed: the ending fragment emits
    /// nothing and the partial stream is dropped rather than corruptly joined.
    #[test]
    fn sctp_reassembly_fails_closed_on_tsn_gap() {
        let (src, dst) = sctp_endpoints();
        let mut r = SctpReassembler::new();

        let b = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 1, 0, 0, b"AAAA")).expect("b");
        assert!(r.insert(src, dst, &b).is_none());
        assert_eq!(r.len(), 1, "the B fragment started a stream");

        // E arrives at TSN 3 — TSN 2 (a middle) was never seen: a gap.
        let e = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_E, 3, 0, 0, b"CCCC")).expect("e");
        assert!(
            r.insert(src, dst, &e).is_none(),
            "a TSN gap must not emit a corrupt reassembly"
        );
        assert_eq!(r.len(), 0, "the gapped partial stream is dropped");
    }

    /// (d) A flood of distinct incomplete fragment streams is bounded: the
    /// stream table never exceeds its cap (oldest-out eviction) and never panics.
    #[test]
    fn sctp_reassembly_buffer_is_bounded() {
        let (src, dst) = sctp_endpoints();
        let mut r = SctpReassembler::with_max_streams(4);

        // 32 distinct streams (distinct SSN), each only ever a B fragment, so
        // none ever completes — memory must stay bounded by the cap.
        for ssn in 0..32u16 {
            let b = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 1, 0, ssn, b"frag"))
                .expect("b frag");
            assert!(r.insert(src, dst, &b).is_none());
            assert!(r.len() <= 4, "stream table must stay within its cap");
        }
        assert_eq!(r.len(), 4, "exactly the cap remains after the flood");
    }

    /// (e, unit) A self-contained single-packet complete (B+E) fragment fed to
    /// the reassembler returns its data immediately with no buffering — the
    /// single-packet path never regresses. (The end-to-end `parse_packet`
    /// regression is `parse_ethernet_ipv4_sctp_data_chunk_sip`.)
    #[test]
    fn sctp_reassembler_passes_complete_chunk_through() {
        let sip: &[u8] = b"OPTIONS sip:h SIP/2.0\r\n\r\n";
        let (src, dst) = sctp_endpoints();
        let mut r = SctpReassembler::new();
        // A B+E chunk is complete; `parse_sctp_fragment` only surfaces *incomplete*
        // fragments, so build the fragment directly to exercise the reassembler.
        let frag = SctpFragment {
            src_port: 5060,
            dst_port: 5062,
            tsn: 1,
            sid: 0,
            ssn: 0,
            begin: true,
            end: true,
            data: bytes::Bytes::copy_from_slice(sip),
        };
        let done = r
            .insert(src, dst, &frag)
            .expect("complete chunk returns its data");
        assert_eq!(&done[..], sip);
        assert_eq!(r.len(), 0, "a complete chunk needs no buffering");
    }

    /// `parse_sctp_fragment` surfaces an *incomplete* DATA fragment (B-only
    /// here) with its ports, flags, TSN/SID/SSN, and user data — but returns
    /// `None` for a complete (B+E) chunk, which the stateless `parse_packet`
    /// path already handles.
    #[test]
    fn parse_sctp_fragment_extracts_fragment_but_skips_complete() {
        let frag = parse_sctp_fragment(&sctp_frag_packet(SCTP_FLAG_B, 9, 3, 4, b"partial"))
            .expect("B-only fragment surfaced");
        assert_eq!((frag.src_port, frag.dst_port), (5060, 5062));
        assert!(frag.begin && !frag.end);
        assert_eq!((frag.tsn, frag.sid, frag.ssn), (9, 3, 4));
        assert_eq!(&frag.data[..], b"partial");

        // A complete B+E chunk is not a fragment for reassembly purposes.
        let complete = sctp_frag_packet(SCTP_FLAG_B | SCTP_FLAG_E, 1, 0, 0, b"whole");
        assert!(
            parse_sctp_fragment(&complete).is_none(),
            "complete chunks are handled by parse_packet, not reassembly"
        );
    }

    /// A GRE-encapsulated IPv4/UDP packet is stripped to its inner
    /// addresses, ports, and payload (outer addresses discarded).
    #[test]
    fn parse_gre_encapsulated() {
        let payload = b"inner payload";
        // Build inner Ethernet-less IPv4/UDP packet (raw IP)
        let inner_udp_len: u16 = 8 + payload.len() as u16;
        let inner_ip_total: u16 = 20 + inner_udp_len;
        let mut inner = Vec::new();

        // Inner IPv4 header
        inner.push(0x45);
        inner.push(0x00);
        inner.extend_from_slice(&inner_ip_total.to_be_bytes());
        inner.extend_from_slice(&[0x00, 0x03]); // id=3
        inner.extend_from_slice(&[0x40, 0x00]); // DF
        inner.push(64);
        inner.push(17); // UDP
        inner.extend_from_slice(&[0x00, 0x00]);
        inner.extend_from_slice(&[172, 16, 0, 1]);
        inner.extend_from_slice(&[172, 16, 0, 2]);

        // Inner UDP
        inner.extend_from_slice(&8000u16.to_be_bytes());
        inner.extend_from_slice(&9000u16.to_be_bytes());
        inner.extend_from_slice(&inner_udp_len.to_be_bytes());
        inner.extend_from_slice(&[0x00, 0x00]);
        inner.extend_from_slice(payload);

        // Build GRE header: flags=0, protocol=0x0800 (IPv4)
        let mut gre = Vec::new();
        gre.extend_from_slice(&[0x00, 0x00]); // flags: none
        gre.extend_from_slice(&[0x08, 0x00]); // protocol: IPv4
        gre.extend_from_slice(&inner);

        // Outer IPv4 header wrapping GRE
        let outer_ip_total: u16 = 20 + gre.len() as u16;
        let mut outer_ip = Vec::new();
        outer_ip.push(0x45);
        outer_ip.push(0x00);
        outer_ip.extend_from_slice(&outer_ip_total.to_be_bytes());
        outer_ip.extend_from_slice(&[0x00, 0x04]); // id=4
        outer_ip.extend_from_slice(&[0x40, 0x00]);
        outer_ip.push(64);
        outer_ip.push(47); // protocol: GRE
        outer_ip.extend_from_slice(&[0x00, 0x00]);
        outer_ip.extend_from_slice(&[10, 0, 0, 1]); // outer src
        outer_ip.extend_from_slice(&[10, 0, 0, 2]); // outer dst
        outer_ip.extend_from_slice(&gre);

        // Wrap in Ethernet
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0xAA; 6]);
        eth.extend_from_slice(&[0xBB; 6]);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&outer_ip);

        let pkt = make_packet(eth, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse GRE");

        // Should see inner addresses, not outer
        assert_eq!(parsed.src_addr, "172.16.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "172.16.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 8000);
        assert_eq!(parsed.dst_port, 9000);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);
    }

    /// An IP-in-IP (protocol 4) packet is stripped to the inner IPv4/UDP
    /// flow.
    #[test]
    fn parse_ip_in_ip() {
        let payload = b"tunneled SIP";
        // Build inner IPv4/UDP
        let inner_udp_len: u16 = 8 + payload.len() as u16;
        let inner_ip_total: u16 = 20 + inner_udp_len;
        let mut inner = Vec::new();

        inner.push(0x45);
        inner.push(0x00);
        inner.extend_from_slice(&inner_ip_total.to_be_bytes());
        inner.extend_from_slice(&[0x00, 0x05]);
        inner.extend_from_slice(&[0x40, 0x00]);
        inner.push(64);
        inner.push(17); // UDP
        inner.extend_from_slice(&[0x00, 0x00]);
        inner.extend_from_slice(&[192, 168, 10, 1]);
        inner.extend_from_slice(&[192, 168, 10, 2]);

        inner.extend_from_slice(&5060u16.to_be_bytes());
        inner.extend_from_slice(&5060u16.to_be_bytes());
        inner.extend_from_slice(&inner_udp_len.to_be_bytes());
        inner.extend_from_slice(&[0x00, 0x00]);
        inner.extend_from_slice(payload);

        // Outer IPv4 with protocol=4 (IP-in-IP)
        let outer_ip_total: u16 = 20 + inner.len() as u16;
        let mut outer = Vec::new();
        outer.push(0x45);
        outer.push(0x00);
        outer.extend_from_slice(&outer_ip_total.to_be_bytes());
        outer.extend_from_slice(&[0x00, 0x06]);
        outer.extend_from_slice(&[0x40, 0x00]);
        outer.push(64);
        outer.push(4); // protocol: IPv4-in-IPv4
        outer.extend_from_slice(&[0x00, 0x00]);
        outer.extend_from_slice(&[10, 0, 0, 1]);
        outer.extend_from_slice(&[10, 0, 0, 2]);
        outer.extend_from_slice(&inner);

        // Wrap in Ethernet
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0xAA; 6]);
        eth.extend_from_slice(&[0xBB; 6]);
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&outer);

        let pkt = make_packet(eth, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse IP-in-IP");

        assert_eq!(parsed.src_addr, "192.168.10.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "192.168.10.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
    }

    /// An ARP frame returns an error rather than panicking.
    #[test]
    fn parse_non_ip_returns_error() {
        // ARP packet: EtherType 0x0806
        let mut data = Vec::new();
        data.extend_from_slice(&[0xAA; 6]); // dst MAC
        data.extend_from_slice(&[0xBB; 6]); // src MAC
        data.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
        data.extend_from_slice(&[0x00; 28]); // ARP payload (enough bytes)

        let pkt = make_packet(data, DLT_EN10MB);
        let result = parse_packet(&pkt);
        assert!(result.is_err(), "ARP should return error, not panic");
    }

    // ── PPPoE (RFC 2516) ──────────────────────────────────────────────
    //
    // PPPoE is the access encapsulation on DSL and much FTTH, so an operator
    // capturing on that segment sees EtherType 0x8864 on every frame. sipnab
    // used to slice such a frame as Ethernet, find no network layer, and drop
    // it at debug level — a capture full of INVITEs reported as "No SIP
    // traffic found", which is a confident wrong answer about customer
    // traffic rather than an honest silence.
    //
    // These tests pin BOTH dispatch sites (`parse_packet` for the full walk,
    // `peek_host_pair` for the `--cores N` shard peek) and, just as
    // importantly, pin the frames that must NOT be decapsulated: a Discovery
    // frame's payload is TLV tags and a non-IP PPP protocol's payload is
    // control data, so reading either as an IP header would manufacture
    // addresses out of bytes that never carried any.

    /// A PPPoE Session frame carrying IPv4/UDP parses to the INNER addresses,
    /// ports and payload, and the shard peek agrees with the full parse.
    #[test]
    fn parse_pppoe_session_ipv4_udp() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        // PPP Protocol 0x0021 = IPv4 (IANA PPP DLL Protocol Numbers).
        let pkt = make_packet(pppoe_session(&base, &[0x00, 0x21]), DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("PPPoE session frame should parse");

        assert_eq!(parsed.src_addr, IpAddr::V4(a));
        assert_eq!(parsed.dst_addr, IpAddr::V4(b));
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5062);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);

        // The cheap peek must find the same pair, not fall back to None —
        // asserting only "peek agrees with parse" would be satisfied by both
        // being None, which is precisely the regression this guards.
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// A PPPoE Session frame carrying PPP protocol 0x0057 parses as IPv6.
    #[test]
    fn parse_pppoe_session_ipv6_udp() {
        let a: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let payload = b"OPTIONS sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv6_udp(a.octets(), b.octets(), 5060, 5062, payload);

        // PPP Protocol 0x0057 = IPv6.
        let pkt = make_packet(pppoe_session(&base, &[0x00, 0x57]), DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("PPPoE IPv6 session frame should parse");

        assert_eq!(parsed.src_addr, IpAddr::V6(a));
        assert_eq!(parsed.dst_addr, IpAddr::V6(b));
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5062);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V6(a), IpAddr::V6(b))));
    }

    /// A 1-byte (protocol-field-compressed) PPP Protocol field is accepted.
    ///
    /// RFC 2516 §7 makes PFC "NOT RECOMMENDED" on PPPoE — discouraged, not
    /// forbidden, unlike ACFC which is a MUST NOT — so a conforming-but-unusual
    /// peer can still send it. RFC 1661 §2 makes the discrimination exact and
    /// free: a Protocol field's least significant octet is always odd and its
    /// most significant octet always even, so an odd first byte means a 1-byte
    /// field and nothing else can alias it.
    #[test]
    fn parse_pppoe_protocol_field_compression() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");

        // 0x0021 compressed to a single 0x21 octet.
        let pkt = make_packet(pppoe_session(&base, &[0x21]), DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("PFC PPPoE frame should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));

        // And the IPv6 twin, 0x0057 compressed to 0x57.
        let a6: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b6: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let base6 = build_eth_ipv6_udp(a6.octets(), b6.octets(), 5060, 5062, b"x");
        let pkt6 = make_packet(pppoe_session(&base6, &[0x57]), DLT_EN10MB);
        let parsed6 = parse_packet(&pkt6).expect("PFC IPv6 PPPoE frame should parse");
        assert_eq!(
            (parsed6.src_addr, parsed6.dst_addr),
            (IpAddr::V6(a6), IpAddr::V6(b6))
        );
        assert_eq!(
            peek_host_pair(&pkt6),
            Some((IpAddr::V6(a6), IpAddr::V6(b6)))
        );
    }

    /// PPP control protocols carry no IP, so their payload must never be
    /// sliced as an IP header.
    ///
    /// LCP (0xC021) and IPCP (0x8021) negotiate the link; their option bytes
    /// would parse as a plausible-looking IP header if the decapsulator skipped
    /// a fixed number of bytes without inspecting the PPP Protocol field.
    #[test]
    fn pppoe_rejects_non_ip_ppp_protocols() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"x",
        );
        for proto in [[0xC0u8, 0x21], [0x80, 0x21]] {
            let pkt = make_packet(pppoe_session(&base, &proto), DLT_EN10MB);
            assert!(
                parse_packet(&pkt).is_err(),
                "PPP protocol {proto:02X?} carries no IP and must not parse"
            );
            assert_eq!(peek_host_pair(&pkt), None, "PPP protocol {proto:02X?}");
        }
    }

    /// A PPPoE **Discovery** frame is never treated as session data.
    ///
    /// RFC 2516 §5 gives Discovery its own EtherType (0x8863) and its payload
    /// is TLV tags, not a PPP frame. This frame is byte-identical to a valid
    /// session frame apart from that EtherType, so nothing but the EtherType
    /// check can reject it — and if it were accepted, sipnab would report a
    /// host pair and a SIP message that the wire never carried.
    #[test]
    fn pppoe_discovery_is_never_session_data() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let discovery = wrap_in_pppoe(&base, 0x8863, 0x11, 0x00, &[0x00, 0x21]);
        let pkt = make_packet(discovery, DLT_EN10MB);
        assert!(
            parse_packet(&pkt).is_err(),
            "PPPoE Discovery (0x8863) must not be decapsulated as a session"
        );
        assert_eq!(peek_host_pair(&pkt), None);
    }

    /// A session-EtherType frame whose PPPoE header is malformed is rejected.
    ///
    /// RFC 2516 §4 fixes VER and TYPE at 0x1 each and §6 requires CODE 0x00 for
    /// the session stage. A non-zero CODE means the payload is TAGs (a PADT or
    /// a mis-tagged PADI), not a PPP frame; decoding those as IP would invent a
    /// flow. The LENGTH field is attacker-controlled and snaplen truncation
    /// makes an over-long LENGTH ordinary, so it must never bound a slice —
    /// a frame whose LENGTH lies still parses from the bytes actually present.
    #[test]
    fn pppoe_malformed_session_header_rejected() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");

        // CODE 0x09 (PADI) mis-tagged into the session EtherType.
        let pkt = make_packet(
            wrap_in_pppoe(&base, 0x8864, 0x11, 0x09, &[0x00, 0x21]),
            DLT_EN10MB,
        );
        assert!(parse_packet(&pkt).is_err(), "CODE != 0x00 is not a session");
        assert_eq!(peek_host_pair(&pkt), None, "CODE != 0x00 is not a session");

        // VER/TYPE 0x21 — VER 2, which RFC 2516 §4 forbids.
        let pkt = make_packet(
            wrap_in_pppoe(&base, 0x8864, 0x21, 0x00, &[0x00, 0x21]),
            DLT_EN10MB,
        );
        assert!(
            parse_packet(&pkt).is_err(),
            "VER/TYPE != 0x11 is not a session"
        );
        assert_eq!(peek_host_pair(&pkt), None, "VER/TYPE != 0x11");

        // LENGTH claiming 65535 bytes of payload: advisory only, still parses.
        let pkt = make_packet(pppoe_lying_length(&base), DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("an over-long LENGTH must not block the parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// Every truncation point in a PPPoE frame yields an error / `None`,
    /// never a panic and never a read past the captured bytes.
    ///
    /// Capture data is attacker-controlled and snaplen truncation is routine,
    /// so each of the four places the decapsulator reads — the PPPoE header,
    /// its tail, the PPP Protocol field, and the IP header behind it — has to
    /// be independently bounds-checked.
    #[test]
    fn pppoe_truncated_frames_yield_none_not_panic() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let full = pppoe_session(&base, &[0x00, 0x21]);

        // 14 = ethertype only; 15..=19 = a partial 6-byte PPPoE header;
        // 20 = header but no PPP Protocol field; 21 = half of one;
        // 22 = protocol field but no IP header; 23 = one IP byte.
        for cut in 14..=23usize {
            let pkt = make_packet(full[..cut].to_vec(), DLT_EN10MB);
            assert!(
                parse_packet(&pkt).is_err(),
                "PPPoE frame truncated to {cut} bytes must not parse"
            );
            assert_eq!(
                peek_host_pair(&pkt),
                None,
                "PPPoE frame truncated to {cut} bytes must peek None"
            );
        }
    }

    /// VLAN-then-PPPoE unwraps in that order — the real DSL access shape.
    ///
    /// The access node tags the subscriber VLAN outside the PPPoE session, so
    /// the tag stack must be walked FIRST and the PPPoE check must sit inside
    /// that walk. A PPPoE check placed ahead of the VLAN loop sees 0x8100 and
    /// gives up.
    #[test]
    fn vlan_then_pppoe_unwraps_in_order() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);
        let pppoe = pppoe_session(&base, &[0x00, 0x21]);

        // 802.1Q (VID 100) then PPPoE.
        let tagged = prepend_vlan_tag(&pppoe, 0x8100, 100);
        let pkt = make_packet(tagged, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("VLAN + PPPoE should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));

        // QinQ: 802.1ad outer (VID 200) + 802.1Q inner (VID 100), then PPPoE.
        let qinq = prepend_vlan_tag(&prepend_vlan_tag(&pppoe, 0x8100, 100), 0x88A8, 200);
        let pkt = make_packet(qinq, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("QinQ + PPPoE should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    // ── BSD loopback (DLT_NULL / DLT_LOOP) ────────────────────────────
    //
    // A loopback capture — `tcpdump -i lo0` on any BSD or macOS, and every
    // trace of a softphone talking to a proxy on the same host — carries a
    // 4-byte BSD address-family header where Ethernet would be. sipnab had no
    // arm for either link type, so every frame came back
    // `UnsupportedLinkType` and the run printed "No SIP traffic found" over a
    // capture full of INVITEs. `tests/pcap-samples/h263-over-rtp.pcap` is
    // exactly such a file, and `tests/link_layer_decap_test.rs` pins the
    // end-to-end counts it must now report; the tests here pin the header walk
    // and the `--cores` shard peek that feed it.

    /// Wrap an Ethernet frame's payload in a BSD loopback header.
    ///
    /// `base` is a frame from [`build_eth_ipv4_udp`] / [`build_eth_ipv6_udp`];
    /// its 14-byte Ethernet header is dropped and replaced by the 4-byte
    /// address family, written in the requested byte order — the one axis on
    /// which DLT_NULL and DLT_LOOP differ.
    fn bsd_loopback(base: &[u8], af: u32, big_endian: bool) -> Vec<u8> {
        let mut pkt = if big_endian {
            af.to_be_bytes().to_vec()
        } else {
            af.to_le_bytes().to_vec()
        };
        pkt.extend_from_slice(&base[14..]);
        pkt
    }

    /// A DLT_NULL frame parses to the addresses, ports and payload it carries,
    /// and the shard peek agrees with the full parse.
    #[test]
    fn parse_null_loopback_ipv4_udp() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(127, 0, 0, 1);
        let b = Ipv4Addr::new(127, 0, 0, 1);
        let payload = b"INVITE sip:auto@localhost SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 13764, 5060, payload);

        // AF_INET = 2 on every BSD, macOS and Linux alike.
        let pkt = make_packet(bsd_loopback(&base, 2, false), DLT_NULL);
        let parsed = parse_packet(&pkt).expect("DLT_NULL frame should parse");

        assert_eq!(parsed.src_addr, IpAddr::V4(a));
        assert_eq!(parsed.dst_addr, IpAddr::V4(b));
        assert_eq!(parsed.src_port, 13764);
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);

        // Asserting only "peek agrees with parse" would be satisfied by both
        // being None, which is the split-brain this guards against.
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// DLT_NULL reads the family in either byte order; DLT_LOOP only in
    /// network order. That is the entire difference between the two link
    /// types, so both halves are pinned here.
    ///
    /// A DLT_LOOP frame whose family word is `02 00 00 00` is AF 0x02000000 —
    /// not AF_INET — and must be refused rather than "helpfully" swapped, or
    /// DLT_LOOP stops being distinguishable from DLT_NULL at all.
    #[test]
    fn null_reads_either_byte_order_and_loop_reads_only_network_order() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");

        for big_endian in [false, true] {
            let pkt = make_packet(bsd_loopback(&base, 2, big_endian), DLT_NULL);
            let parsed = parse_packet(&pkt)
                .unwrap_or_else(|e| panic!("DLT_NULL, big_endian={big_endian}: {e}"));
            assert_eq!(
                (parsed.src_addr, parsed.dst_addr),
                (IpAddr::V4(a), IpAddr::V4(b))
            );
            assert_eq!(
                peek_host_pair(&pkt),
                want,
                "DLT_NULL, big_endian={big_endian}"
            );
        }

        let network_order = make_packet(bsd_loopback(&base, 2, true), DLT_LOOP);
        let parsed = parse_packet(&network_order).expect("DLT_LOOP is big-endian AF_INET");
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(peek_host_pair(&network_order), want);

        let host_order = make_packet(bsd_loopback(&base, 2, false), DLT_LOOP);
        assert!(
            parse_packet(&host_order).is_err(),
            "DLT_LOOP carries AF in network order only; 02 00 00 00 is not AF_INET"
        );
        assert_eq!(peek_host_pair(&host_order), None);
    }

    /// Every AF_INET6 value a real OS writes is accepted.
    ///
    /// The constant is not portable: 24 on NetBSD/OpenBSD/BSD-OS, 28 on
    /// FreeBSD, 30 on macOS, 10 on Linux. A capture written on one host is
    /// routinely read on another, so a decoder that hard-codes its own host's
    /// value drops the other three platforms' loopback traffic in silence.
    #[test]
    fn null_loopback_accepts_every_os_af_inet6_value() {
        let a: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let want = Some((IpAddr::V6(a), IpAddr::V6(b)));
        let payload = b"OPTIONS sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv6_udp(a.octets(), b.octets(), 5060, 5062, payload);

        for af in [10u32, 24, 28, 30] {
            let pkt = make_packet(bsd_loopback(&base, af, false), DLT_NULL);
            let parsed =
                parse_packet(&pkt).unwrap_or_else(|e| panic!("AF_INET6 = {af} rejected: {e}"));
            assert_eq!(
                (parsed.src_addr, parsed.dst_addr),
                (IpAddr::V6(a), IpAddr::V6(b))
            );
            assert_eq!(parsed.payload[..], payload[..]);
            assert_eq!(peek_host_pair(&pkt), want, "AF_INET6 = {af}");
        }
    }

    /// A family that is not an IP family is never sliced as IP.
    ///
    /// The payload behind these headers is byte-identical to a valid IPv4
    /// datagram, so nothing but the family check can reject them — and if it
    /// did not, sipnab would report a host pair and a SIP message out of bytes
    /// that were an AppleTalk or IPX frame.
    #[test]
    fn null_loopback_rejects_a_non_ip_address_family() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        // 0 = AF_UNSPEC, 7 = AF_ISO, 16 = AF_APPLETALK, 23 = AF_IPX, and a
        // value no BSD assigns at all.
        for af in [0u32, 7, 16, 23, 99] {
            for link_type in [DLT_NULL, DLT_LOOP] {
                let pkt = make_packet(bsd_loopback(&base, af, true), link_type);
                assert!(
                    parse_packet(&pkt).is_err(),
                    "AF {af} on link type {link_type} is not IP and must not parse"
                );
                assert_eq!(
                    peek_host_pair(&pkt),
                    None,
                    "AF {af} on link type {link_type}"
                );
            }
        }
    }

    /// Every truncation point in a loopback frame yields an error / `None`,
    /// never a panic and never a read past the captured bytes.
    #[test]
    fn null_loopback_truncated_frames_yield_none_not_panic() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let full = bsd_loopback(&base, 2, false);

        // 0..=3 is a partial family word; 4 is the word with no IP header
        // behind it; 5..=23 is a partial IPv4 header.
        for cut in 0..=23usize {
            for link_type in [DLT_NULL, DLT_LOOP] {
                let pkt = make_packet(full[..cut].to_vec(), link_type);
                assert!(
                    parse_packet(&pkt).is_err(),
                    "loopback frame truncated to {cut} bytes must not parse"
                );
                assert_eq!(
                    peek_host_pair(&pkt),
                    None,
                    "loopback frame truncated to {cut} bytes must peek None"
                );
            }
        }
    }

    // ── Legacy QinQ (0x9100) and the bounded tag walk ─────────────────

    /// Prefix `count` 802.1Q tags onto a frame, keeping the MACs first.
    fn prepend_vlan_tags(base: &[u8], count: usize) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(12 + count * 4 + base.len() - 12);
        pkt.extend_from_slice(&base[0..12]);
        for _ in 0..count {
            pkt.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
            pkt.extend_from_slice(&100u16.to_be_bytes()); // TCI: PCP/DEI 0, VID 100
        }
        pkt.extend_from_slice(&base[12..]);
        pkt
    }

    /// EtherType 0x9100 is walked like a VLAN tag, so PPPoE behind one is
    /// still decapsulated.
    ///
    /// `etherparse` treats 0x9100 as a tag, so a 0x9100 → IPv4 frame always
    /// worked; sipnab's own walk did not, so a 0x9100 → PPPoE frame stopped at
    /// the tag and never reached the PPPoE arm. Legacy carrier gear that still
    /// emits 0x9100 is exactly the gear that still runs PPPoE, so the two meet.
    #[test]
    fn legacy_qinq_tag_is_walked_before_pppoe() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);
        let pppoe = pppoe_session(&base, &[0x00, 0x21]);

        let tagged = prepend_vlan_tag(&pppoe, 0x9100, 100);
        let pkt = make_packet(tagged, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("0x9100 + PPPoE should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// A 0x9100 tag never makes the shard peek invent a host pair.
    ///
    /// The peek's only IP check is the version nibble at the offset the walk
    /// returned. With 0x9100 unwalked that offset landed on the TCI, and a TCI
    /// with PCP=2, DEI=0 starts `0x4…` — the IPv4 version nibble. The peek then
    /// read the "addresses" out of the middle of the real IPv4 header:
    /// 64.17.0.0 (TTL, protocol, checksum) talking to 192.0.2.10 (the real
    /// source). Both halves are asserted: the pair is right, and it is
    /// specifically not that fabrication.
    #[test]
    fn legacy_qinq_peek_does_not_invent_a_host_pair() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");

        // TCI 0x4064 = PCP 2, DEI 0, VID 100.
        let pkt = make_packet(prepend_vlan_tag(&base, 0x9100, 0x4064), DLT_EN10MB);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
        assert_ne!(
            peek_host_pair(&pkt),
            Some((
                IpAddr::V4(Ipv4Addr::new(64, 17, 0, 0)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            )),
            "the peek read its host pair out of the middle of the IPv4 header"
        );

        // The full parse and the peek must also still agree.
        let parsed = parse_packet(&pkt).expect("0x9100 + IPv4 should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
    }

    /// The tag walk stops at a fixed depth instead of following whatever the
    /// frame says.
    ///
    /// Three tags is the deepest stack `etherparse` itself keeps
    /// (`SlicedPacket::LINK_EXTS_CAP`), so a fourth is already invisible to the
    /// full parse; matching that bound keeps the two dispatch paths from
    /// disagreeing, and stops a 64 KB frame of 0x8100 from costing ~16k
    /// iterations per packet.
    #[test]
    fn the_vlan_tag_walk_is_bounded() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");
        let pppoe = pppoe_session(&base, &[0x00, 0x21]);

        for depth in 0..=3usize {
            let pkt = make_packet(prepend_vlan_tags(&base, depth), DLT_EN10MB);
            assert_eq!(peek_host_pair(&pkt), want, "{depth} tags must still peek");
            let pkt = make_packet(prepend_vlan_tags(&pppoe, depth), DLT_EN10MB);
            let parsed = parse_packet(&pkt)
                .unwrap_or_else(|e| panic!("{depth} tags + PPPoE must still parse: {e}"));
            assert_eq!(
                (parsed.src_addr, parsed.dst_addr),
                (IpAddr::V4(a), IpAddr::V4(b))
            );
        }

        // One past the bound, and a frame that is nothing but tags: rejected,
        // not walked.
        for depth in [4usize, 4096] {
            let pkt = make_packet(prepend_vlan_tags(&base, depth), DLT_EN10MB);
            assert_eq!(
                peek_host_pair(&pkt),
                None,
                "{depth} tags must not be walked"
            );
            let pkt = make_packet(prepend_vlan_tags(&pppoe, depth), DLT_EN10MB);
            assert!(
                parse_packet(&pkt).is_err(),
                "{depth} tags + PPPoE must not parse"
            );
        }
    }

    /// A DLT_RAW packet (IP header first, no Ethernet) parses correctly.
    #[test]
    fn parse_raw_ip_link_type() {
        let payload = b"raw ip payload";
        let udp_len: u16 = 8 + payload.len() as u16;
        let ip_total: u16 = 20 + udp_len;
        let mut data = Vec::new();

        // IPv4 header directly (no Ethernet)
        data.push(0x45);
        data.push(0x00);
        data.extend_from_slice(&ip_total.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x07]);
        data.extend_from_slice(&[0x40, 0x00]);
        data.push(64);
        data.push(17);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[10, 1, 1, 1]);
        data.extend_from_slice(&[10, 2, 2, 2]);

        data.extend_from_slice(&4000u16.to_be_bytes());
        data.extend_from_slice(&5000u16.to_be_bytes());
        data.extend_from_slice(&udp_len.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(payload);

        let pkt = make_packet(data, DLT_RAW);
        let parsed = parse_packet(&pkt).expect("should parse raw IP");
        assert_eq!(parsed.src_port, 4000);
        assert_eq!(parsed.dst_port, 5000);
        assert_eq!(parsed.payload[..], payload[..]);
    }

    /// When a packet carries pre-parsed metadata (e.g. from a HEP listener
    /// that already has the addressing from HEP chunks), `parse_packet`
    /// must short-circuit the IP-header parse path and produce a
    /// `ParsedPacket` from the metadata + payload directly. The payload
    /// bytes do NOT contain link/IP/transport headers.
    #[test]
    fn parse_packet_short_circuits_when_pre_parsed_present_udp() {
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec();
        let pkt = Packet::with_pre_parsed(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            payload.clone(),
            Some("hep:0.0.0.0:9060".to_string()),
            super::super::packet::PreParsed {
                src_addr: "192.0.2.10".parse().unwrap(),
                dst_addr: "192.0.2.20".parse().unwrap(),
                src_port: 5060,
                dst_port: 5060,
                ip_protocol: 17, // UDP
            },
        );
        let parsed = parse_packet(&pkt).expect("should parse via pre-parsed path");

        assert_eq!(parsed.src_addr, "192.0.2.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "192.0.2.20".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);
        assert!(parsed.tcp_seq.is_none());
        assert!(parsed.tcp_flags.is_none());
        assert_eq!(parsed.fragment_offset, None);
        assert!(!parsed.more_fragments);
        assert_eq!(parsed.ip_protocol, 17);
    }

    /// A pre-parsed packet from a uprobe must NOT be labeled HEP. Both are
    /// pre-parsed -- neither has an IP header -- so the branch cannot assume
    /// HEP any more. Getting this wrong would let `--hep-allow-kill` re-enable
    /// transmission for input that carries no address at all.
    #[test]
    fn parse_packet_flags_a_uprobe_source_as_uprobe_origin() {
        let pkt = Packet::with_pre_parsed(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec(),
            Some("uprobe:opensips/1234".to_string()),
            super::super::packet::PreParsed {
                src_addr: "0.0.0.0".parse().unwrap(),
                dst_addr: "0.0.0.0".parse().unwrap(),
                src_port: 0,
                dst_port: 0,
                ip_protocol: 6,
            },
        );
        assert_eq!(
            parse_packet(&pkt).unwrap().input_origin,
            InputOrigin::Uprobe,
            "a uprobe read must never be labeled HEP: it has no address at \
             all, so no opt-in may make it transmit-eligible"
        );
    }

    /// A pre-parsed (HEP-listener-origin) packet is flagged `Hep` so
    /// downstream active responses (scanner-kill) can refuse to trust its
    /// attacker-assertable addressing by default (SN-01).
    #[test]
    fn parse_packet_flags_pre_parsed_as_hep_origin() {
        let pkt = Packet::with_pre_parsed(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec(),
            Some("hep:0.0.0.0:9060".to_string()),
            super::super::packet::PreParsed {
                src_addr: "192.0.2.10".parse().unwrap(),
                dst_addr: "192.0.2.20".parse().unwrap(),
                src_port: 5060,
                dst_port: 5060,
                ip_protocol: 17,
            },
        );
        assert_eq!(
            parse_packet(&pkt).unwrap().input_origin,
            InputOrigin::Hep,
            "HEP-origin must be recorded, so scanner-kill can refuse it"
        );
    }

    /// A normally captured (link/IP/transport) packet is NOT flagged
    /// `Hep`, so scanner-kill remains eligible for live/pcap traffic.
    #[test]
    fn parse_packet_normal_capture_is_wire_origin() {
        let data = build_eth_ipv4_udp(
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            5060,
            5060,
            b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n",
        );
        let pkt = make_packet(data, DLT_EN10MB);
        assert!(
            parse_packet(&pkt).unwrap().input_origin == InputOrigin::Wire,
            "live capture is not HEP-origin"
        );
    }

    /// The pre-parsed short-circuit maps `ip_protocol = 6` to
    /// `TransportProto::Tcp` and passes the payload through untouched.
    #[test]
    fn parse_packet_short_circuits_when_pre_parsed_present_tcp() {
        let payload = b"REGISTER sip:carol@example.com SIP/2.0\r\n\r\n".to_vec();
        let pkt = Packet::with_pre_parsed(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            payload.clone(),
            None,
            super::super::packet::PreParsed {
                src_addr: "192.168.1.10".parse().unwrap(),
                dst_addr: "192.168.1.20".parse().unwrap(),
                src_port: 5060,
                dst_port: 5061,
                ip_protocol: 6, // TCP
            },
        );
        let parsed = parse_packet(&pkt).expect("should parse via pre-parsed path");

        assert_eq!(parsed.transport, TransportProto::Tcp);
        assert_eq!(parsed.payload[..], payload[..]);
    }

    /// A 6in4 tunnel — an outer IPv4 packet with protocol 41 carrying an
    /// inner IPv6 datagram — is stripped to the inner IPv6/UDP flow so
    /// tunneled SIP is delivered rather than dropped.
    #[test]
    fn parse_6in4_ipv6_in_ipv4() {
        let sip = b"OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n";

        // Inner raw IPv6 + UDP (no Ethernet): 2001::1 -> 2001::2, 5060 -> 5062.
        let mut src = [0u8; 16];
        src[0] = 0x20;
        src[1] = 0x01;
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[0] = 0x20;
        dst[1] = 0x01;
        dst[15] = 2;
        let udp_len: u16 = 8 + sip.len() as u16;
        let mut inner = Vec::new();
        inner.push(0x60); // version=6
        inner.extend_from_slice(&[0x00, 0x00, 0x00]); // traffic class + flow label
        inner.extend_from_slice(&udp_len.to_be_bytes()); // payload length
        inner.push(17); // next header: UDP
        inner.push(64); // hop limit
        inner.extend_from_slice(&src);
        inner.extend_from_slice(&dst);
        inner.extend_from_slice(&5060u16.to_be_bytes());
        inner.extend_from_slice(&5062u16.to_be_bytes());
        inner.extend_from_slice(&udp_len.to_be_bytes());
        inner.extend_from_slice(&[0x00, 0x00]); // checksum
        inner.extend_from_slice(sip);

        // Outer IPv4 header, protocol 41 (IPv6 encapsulation).
        let outer_total: u16 = 20 + inner.len() as u16;
        let mut outer = Vec::new();
        outer.push(0x45);
        outer.push(0x00);
        outer.extend_from_slice(&outer_total.to_be_bytes());
        outer.extend_from_slice(&[0x00, 0x09]); // identification
        outer.extend_from_slice(&[0x40, 0x00]); // DF
        outer.push(64);
        outer.push(41); // protocol: IPv6-in-IPv4 (6in4)
        outer.extend_from_slice(&[0x00, 0x00]); // checksum
        outer.extend_from_slice(&[10, 0, 0, 1]); // outer src
        outer.extend_from_slice(&[10, 0, 0, 2]); // outer dst
        outer.extend_from_slice(&inner);

        // Wrap in Ethernet.
        let mut eth = Vec::new();
        eth.extend_from_slice(&[0xAA; 6]);
        eth.extend_from_slice(&[0xBB; 6]);
        eth.extend_from_slice(&[0x08, 0x00]); // EtherType: IPv4
        eth.extend_from_slice(&outer);

        let pkt = make_packet(eth, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("should parse 6in4 tunnel");

        // Inner IPv6 endpoints, not the outer IPv4 ones.
        assert_eq!(parsed.src_addr, "2001::1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "2001::2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5062);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], sip[..]);
    }

    /// A pre-parsed (HEP) packet whose IP protocol is neither UDP, TCP, nor
    /// SCTP (here ESP = 50) is rejected rather than silently mislabeled as
    /// UDP.
    #[test]
    fn parse_packet_rejects_unknown_ip_protocol_pre_parsed() {
        let pkt = Packet::with_pre_parsed(
            Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            b"not-sip".to_vec(),
            Some("hep:0.0.0.0:9060".to_string()),
            super::super::packet::PreParsed {
                src_addr: "192.0.2.10".parse().unwrap(),
                dst_addr: "192.0.2.20".parse().unwrap(),
                src_port: 5060,
                dst_port: 5060,
                ip_protocol: 50, // ESP — not a SIP transport
            },
        );
        let result = parse_packet(&pkt);
        assert!(
            matches!(result, Err(CaptureError::UnsupportedIpProtocol(50))),
            "ESP must be rejected, not mislabeled as UDP; got {result:?}"
        );
    }

    /// IGMP reaches the transport match under etherparse 0.21 (which added
    /// `TransportSlice::Igmp`). It must be reported as "not UDP/TCP" — not
    /// mislabeled as ICMP, and not a panic or a compile-time surprise the next
    /// time etherparse grows a variant.
    #[test]
    fn igmp_is_rejected_as_not_udp_or_tcp() {
        let pkt = make_packet(
            build_eth_ipv4_igmp([192, 0, 2, 10], [224, 0, 0, 1]),
            DLT_EN10MB,
        );
        let result = parse_packet(&pkt);
        assert!(
            matches!(result, Err(CaptureError::NoTransport)),
            "IGMP must be rejected as not-UDP/TCP, and must not be reported as \
             ICMP; got {result:?}"
        );
    }

    /// An IPv6 packet carrying a Fragment extension header (first fragment)
    /// surfaces the fragment offset, the More-Fragments flag, and the 32-bit
    /// identification. Characterizes the extension-header walk so the
    /// hot-path clone removal cannot change fragmented-IPv6 behavior.
    #[test]
    fn parse_ipv6_fragment_header_extracts_frag_fields() {
        let body = b"first-fragment-body";
        let mut src = [0u8; 16];
        src[15] = 1;
        let mut dst = [0u8; 16];
        dst[15] = 2;

        let frag_payload_len = 8 + body.len(); // fragment header (8) + body
        let mut pkt = Vec::new();
        // Ethernet
        pkt.extend_from_slice(&[0xAA; 6]);
        pkt.extend_from_slice(&[0xBB; 6]);
        pkt.extend_from_slice(&[0x86, 0xDD]); // EtherType: IPv6
        // IPv6 header (40 bytes)
        pkt.push(0x60);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&(frag_payload_len as u16).to_be_bytes());
        pkt.push(44); // next header: Fragment
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        // Fragment header (8 bytes): next=UDP, res, offset 0 + MF=1, identification
        pkt.push(17); // next header: UDP
        pkt.push(0); // reserved
        pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // offset 0, MF=1
        pkt.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // identification
        pkt.extend_from_slice(body);

        let p = make_packet(pkt, DLT_EN10MB);
        let parsed = parse_packet(&p).expect("should parse IPv6 fragment");
        assert_eq!(parsed.ip_id, Some(0xDEAD_BEEF));
        assert_eq!(parsed.fragment_offset, Some(0));
        assert!(parsed.more_fragments);
        assert_eq!(parsed.ip_protocol, 17); // UDP, after the fragment header
    }

    // ── Tunnel decapsulation ──────────────────────────────────────────
    //
    // Every case here proves the SAME SIP INVITE comes back out of a
    // different wrapper, byte for byte, with the INNER addresses and ports.
    // The refusals matter just as much: a decoder that invents a flow out of
    // an RTP payload is worse than one that misses a tunnel, so each
    // encapsulation also has a case where one field is wrong and the frame
    // must NOT be decapsulated.

    /// The one message every tunnel test recovers.
    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";

    /// Replace `base`'s EtherType with `ethertype` and splice `header` in
    /// between it and the network layer, keeping the two MAC addresses.
    fn splice_after_macs(base: &[u8], ethertype: u16, header: &[u8]) -> Vec<u8> {
        let mut pkt = base[0..12].to_vec();
        pkt.extend_from_slice(&ethertype.to_be_bytes());
        pkt.extend_from_slice(header);
        pkt.extend_from_slice(&base[14..]);
        pkt
    }

    /// One MPLS label stack entry (RFC 3032 §2.1): 20-bit label, 3-bit TC,
    /// the S bit, then TTL.
    fn mpls_label(label: u32, bottom: bool) -> [u8; 4] {
        ((label << 12) | (u32::from(bottom) << 8) | 64).to_be_bytes()
    }

    /// An NSH MD Type 1 header (RFC 8300 §2.2): Base + Service Path + the
    /// mandatory 16 octets of fixed context, so Length is exactly 0x6.
    fn nsh_md1_header(version: u8, md_type: u8, next_proto: u8) -> Vec<u8> {
        let mut h = vec![version << 6, 0x06, md_type, next_proto];
        h.extend_from_slice(&[0x00, 0x00, 0x00, 0xFF]); // SPI 0, SI 255
        h.extend_from_slice(&[0u8; 16]); // fixed context headers
        h
    }

    /// Wrap a complete Ethernet frame in a Provider Backbone Bridge I-TAG
    /// (IEEE Std 802.1Q-2014 §9.7): backbone MACs, EtherType 0x88E7, then the
    /// flags octet and I-SID — the rest of the 16-octet I-TAG TCI *is* the
    /// customer frame's own C-DA and C-SA.
    ///
    /// The customer frame is passed through [`with_individual_source_mac`]
    /// because §9.7 h) / §20.33.1 make a group-addressed C-SA a discard
    /// condition.
    fn wrap_in_itag(customer: &[u8], isid: [u8; 3]) -> Vec<u8> {
        let inner = with_individual_source_mac(customer);
        let mut pkt = vec![0xCC; 6]; // B-DA
        pkt.extend_from_slice(&[0xDD; 6]); // B-SA
        pkt.extend_from_slice(&0x88E7u16.to_be_bytes());
        pkt.push(0x00); // I-PCP / I-DEI / UCA / Res1 / Res2 all clear
        pkt.extend_from_slice(&isid);
        pkt.extend_from_slice(&inner);
        pkt
    }

    /// Insert a MACsec SecTAG (IEEE Std 802.1AE-2018 §9.3) between the source
    /// MAC and the EtherType that was there before — the transparent
    /// insertion the standard describes, with no SCI.
    fn wrap_in_macsec(base: &[u8], tci_an: u8) -> Vec<u8> {
        let mut pkt = base[0..12].to_vec();
        pkt.extend_from_slice(&0x88E5u16.to_be_bytes());
        pkt.push(tci_an); // TCI / AN
        pkt.push(0x00); // SL
        pkt.extend_from_slice(&1u32.to_be_bytes()); // PN
        pkt.extend_from_slice(&base[12..]); // the displaced EtherType onward
        pkt
    }

    /// A VXLAN header (RFC 7348 §5): I flag set, everything reserved zero.
    fn vxlan_header(vni: u32) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[0] = 0x08;
        h[4..7].copy_from_slice(&vni.to_be_bytes()[1..4]);
        h
    }

    /// A GTP-U G-PDU header (3GPP TS 29.281 §5.1) with no optional block.
    fn gtpu_header(teid: u32, payload_len: usize) -> Vec<u8> {
        let mut h = vec![0x30, 255]; // version 1, PT 1; message type G-PDU
        h.extend_from_slice(&(payload_len as u16).to_be_bytes());
        h.extend_from_slice(&teid.to_be_bytes());
        h
    }

    /// An RFC 4302 §2 Authentication Header.
    ///
    /// Payload Len is "the length of this Authentication Header in 4-octet
    /// units, minus 2" — the IPv6 extension-header convention, which is why
    /// a 24-octet AH (12 fixed + a 96-bit ICV) writes 4 and not 6 or 24.
    fn ah_header(next_header: u8, icv_len: usize) -> Vec<u8> {
        let total = 12 + icv_len;
        assert_eq!(total % 4, 0, "AH is a whole number of 4-octet units");
        let mut h = vec![next_header, (total / 4 - 2) as u8, 0x00, 0x00];
        h.extend_from_slice(&0x1122_3344u32.to_be_bytes()); // SPI
        h.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
        h.resize(total, 0xEE); // Integrity Check Value
        h
    }

    /// Wrap `payload` in an IPv4 header carrying `protocol`.
    fn wrap_in_ipv4(payload: &[u8], protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[0x00, 0x07]); // identification
        ip.extend_from_slice(&[0x40, 0x00]); // DF, offset 0
        ip.push(64); // TTL
        ip.push(protocol);
        ip.extend_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(payload);
        ip
    }

    /// Wrap `payload` in an Ethernet II header with `ethertype`.
    fn wrap_in_eth(payload: &[u8], ethertype: u16) -> Vec<u8> {
        let mut eth = vec![0xAA; 6];
        eth.extend_from_slice(&[0xBB; 6]);
        eth.extend_from_slice(&ethertype.to_be_bytes());
        eth.extend_from_slice(payload);
        eth
    }

    /// A GRE header (RFC 2784 §2.1) with every optional field absent.
    fn gre_header(protocol_type: u16) -> Vec<u8> {
        let mut gre = vec![0x00, 0x00]; // C and reserved0 clear, version 0
        gre.extend_from_slice(&protocol_type.to_be_bytes());
        gre
    }

    /// The INVITE-bearing frame every tunnel test wraps: 10.0.0.1:5060 →
    /// 10.0.0.2:5060 over Ethernet/IPv4/UDP.
    fn invite_frame() -> Vec<u8> {
        build_eth_ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, INVITE)
    }

    /// The raw IPv4/UDP packet inside [`invite_frame`], without its Ethernet
    /// header.
    fn invite_packet() -> Vec<u8> {
        invite_frame()[14..].to_vec()
    }

    /// Clear the Group bit of a frame's source MAC.
    ///
    /// IEEE 802.3 clause 3.2.3 reserves that bit in the Source Address field
    /// and requires it transmitted as 0 — a frame is sent by a station, and a
    /// station never has a group address. Every inner-Ethernet decoder in
    /// `capture::tunnel` uses it as a plausibility gate, and the shared frame
    /// builders here use 0xBB (odd, i.e. group), so an *encapsulated* frame
    /// has to be corrected to be a legal one.
    fn with_individual_source_mac(frame: &[u8]) -> Vec<u8> {
        let mut f = frame.to_vec();
        f[6] &= !0x01;
        f
    }

    /// [`invite_frame`] made legal as an encapsulated frame.
    fn invite_inner_frame() -> Vec<u8> {
        with_individual_source_mac(&invite_frame())
    }

    /// Assert a parse recovered the INVITE with the inner five-tuple intact.
    #[track_caller]
    fn assert_invite_recovered(parsed: &ParsedPacket) {
        assert_eq!(parsed.src_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(&parsed.payload[..], INVITE);
    }

    /// EtherType 0x8847: an MPLS-labeled frame yields the labeled packet's
    /// own five-tuple, not silence.
    #[test]
    fn parse_mpls_unicast_recovers_invite() {
        let data = splice_after_macs(&invite_frame(), 0x8847, &mpls_label(16_000, true));
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("MPLS unicast");
        assert_invite_recovered(&parsed);
    }

    /// EtherType 0x8848 (RFC 5332's upstream-assigned label) walks the same
    /// stack as 0x8847.
    #[test]
    fn parse_mpls_multicast_ethertype_recovers_invite() {
        let data = splice_after_macs(&invite_frame(), 0x8848, &mpls_label(16_001, true));
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("MPLS multicast");
        assert_invite_recovered(&parsed);
    }

    /// A two-label stack (the carrier norm: transport label over service
    /// label) is walked to the bottom of stack.
    #[test]
    fn parse_mpls_two_label_stack_recovers_invite() {
        let mut stack = mpls_label(16_000, false).to_vec();
        stack.extend_from_slice(&mpls_label(16_001, true));
        let data = splice_after_macs(&invite_frame(), 0x8847, &stack);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("two-label MPLS");
        assert_invite_recovered(&parsed);
    }

    /// MPLS behind a VLAN tag — the ordinary shape on a carrier access port —
    /// still reaches the labeled packet.
    #[test]
    fn parse_vlan_then_mpls_recovers_invite() {
        let mpls = splice_after_macs(&invite_frame(), 0x8847, &mpls_label(16_000, true));
        let data = prepend_vlan_tag(&mpls, ETHERTYPE_VLAN, 0x0064);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("VLAN over MPLS");
        assert_invite_recovered(&parsed);
    }

    /// The Implicit NULL label (3) "should never actually appear in the
    /// encapsulation" (RFC 3032 §2.1), so a stack containing it is not a
    /// label stack and must not be walked.
    #[test]
    fn parse_mpls_implicit_null_label_is_refused() {
        let data = splice_after_macs(&invite_frame(), 0x8847, &mpls_label(3, true));
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NotIp { .. }),
            "implicit NULL must not be decapsulated, got {err:?}"
        );
    }

    /// EtherType 0x894F: an NSH-encapsulated IPv4 packet is recovered.
    #[test]
    fn parse_nsh_recovers_invite() {
        let data = splice_after_macs(&invite_frame(), 0x894F, &nsh_md1_header(0, 0x1, 0x1));
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("NSH MD type 1");
        assert_invite_recovered(&parsed);
    }

    /// RFC 8300 §2.2 reserves version 01b precisely because it would alias
    /// IPv4's first nibble; a non-zero version is refused.
    #[test]
    fn parse_nsh_nonzero_version_is_refused() {
        let data = splice_after_macs(&invite_frame(), 0x894F, &nsh_md1_header(1, 0x1, 0x1));
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NotIp { .. }),
            "NSH version 1 must not be decapsulated, got {err:?}"
        );
    }

    /// An NSH Length that contradicts its MD Type locates the payload
    /// nowhere, so the frame is refused rather than guessed at.
    #[test]
    fn parse_nsh_md_type_length_mismatch_is_refused() {
        let mut hdr = nsh_md1_header(0, 0x1, 0x1);
        hdr[1] = 0x05; // MD Type 0x1 requires Length 0x6
        let data = splice_after_macs(&invite_frame(), 0x894F, &hdr);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NotIp { .. }),
            "an MD-Type/Length mismatch must not be decapsulated, got {err:?}"
        );
    }

    /// EtherType 0x88E7: the customer frame inside a PBB I-TAG is walked as a
    /// complete Ethernet frame.
    #[test]
    fn parse_pbb_itag_recovers_invite() {
        let data = wrap_in_itag(&invite_frame(), [0x00, 0x00, 0x64]);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("PBB I-TAG");
        assert_invite_recovered(&parsed);
    }

    /// The wildcard I-SID (0xFFFFFF) "shall not be ... transmitted in an
    /// I-TAG header" (Table 9-3), so these octets are not an I-TAG.
    #[test]
    fn parse_pbb_itag_wildcard_isid_is_refused() {
        let data = wrap_in_itag(&invite_frame(), [0xFF, 0xFF, 0xFF]);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NotIp { .. }),
            "a wildcard I-SID must not be decapsulated, got {err:?}"
        );
    }

    /// EtherType 0x88E5 with E and C clear is integrity-only MACsec: the User
    /// Data is plaintext and the walk resumes at the displaced EtherType.
    #[test]
    fn parse_macsec_integrity_only_recovers_invite() {
        let data = wrap_in_macsec(&invite_frame(), 0x00);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("integrity-only MACsec");
        assert_invite_recovered(&parsed);
    }

    /// MACsec is a transparent insertion, so the walk that resumes after the
    /// SecTAG must be the SAME walk — VLAN tags inside the Secure Data are
    /// ordinary tags (IEEE Std 802.1AE-2018 §6.2), not a second dialect.
    #[test]
    fn parse_macsec_over_inner_vlan_recovers_invite() {
        let tagged = prepend_vlan_tag(&invite_frame(), ETHERTYPE_VLAN, 0x0064);
        let data = wrap_in_macsec(&tagged, 0x00);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("MACsec over VLAN");
        assert_invite_recovered(&parsed);
    }

    /// With the C bit set the Secure Data cannot be recovered from the frame
    /// alone. That is a diagnosis, not a decode failure, and it must never
    /// produce a flow.
    #[test]
    fn parse_macsec_encrypted_is_reported_not_invented() {
        let data = wrap_in_macsec(&invite_frame(), TCI_E_C_SET);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NotIp { what } if what == MACSEC_OPAQUE),
            "encrypted MACsec must be named, got {err:?}"
        );
    }

    /// TCI with both E (0x08) and C (0x04) set: confidentiality.
    const TCI_E_C_SET: u8 = 0x0C;

    /// IP protocol 137 is MPLS-in-IP (RFC 4023): the label stack begins at
    /// the byte after the IP header, and the offset handed to the decoder is
    /// absolute within the frame.
    #[test]
    fn parse_mpls_in_ip_recovers_invite() {
        let mut mpls = mpls_label(16_000, true).to_vec();
        mpls.extend_from_slice(&invite_packet());
        let ip = wrap_in_ipv4(&mpls, 137, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("MPLS-in-IP");
        assert_invite_recovered(&parsed);
    }

    /// AH (IP protocol 51) authenticates without encrypting. In tunnel mode
    /// the protected payload is a whole IP packet, and it is readable.
    #[test]
    fn parse_ah_tunnel_mode_recovers_invite() {
        let mut ah = ah_header(4, 12); // Next Header 4 = IPv4-in-IPv4
        ah.extend_from_slice(&invite_packet());
        let ip = wrap_in_ipv4(&ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("AH tunnel mode");
        assert_invite_recovered(&parsed);
    }

    /// In transport mode AH protects the transport header of the same
    /// datagram: the addresses stay outer, the ports and payload are inner,
    /// and `ip_protocol` names what AH actually protects rather than 51.
    #[test]
    fn parse_ah_transport_mode_recovers_invite() {
        let udp = &invite_packet()[20..]; // UDP header + INVITE
        let mut ah = ah_header(17, 12);
        ah.extend_from_slice(udp);
        let ip = wrap_in_ipv4(&ah, 51, [10, 0, 0, 1], [10, 0, 0, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("AH transport mode");
        assert_invite_recovered(&parsed);
        assert_eq!(parsed.ip_protocol, 17);
    }

    /// A longer ICV moves the protected payload: the Payload Length field is
    /// in 4-octet units minus 2, and reading it any other way lands on the
    /// wrong byte. A 32-octet AH (12 fixed + a 160-bit ICV) writes 6.
    #[test]
    fn parse_ah_longer_icv_still_finds_payload() {
        let mut ah = ah_header(4, 20);
        assert_eq!(ah[1], 6, "32-octet AH writes Payload Len 6");
        ah.extend_from_slice(&invite_packet());
        let ip = wrap_in_ipv4(&ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("AH with 160-bit ICV");
        assert_invite_recovered(&parsed);
    }

    /// Two stacked Authentication Headers. `etherparse` walks exactly one, so
    /// this is the case sipnab's own RFC 4302 traversal has to cover — and
    /// where reading Payload Len in anything but 4-octet-units-minus-2 lands
    /// in the middle of an ICV.
    #[test]
    fn parse_nested_ah_tunnel_mode_recovers_invite() {
        let mut inner_ah = ah_header(4, 12); // protects an IPv4 packet
        inner_ah.extend_from_slice(&invite_packet());
        let mut outer_ah = ah_header(51, 20); // protects another AH
        outer_ah.extend_from_slice(&inner_ah);
        let ip = wrap_in_ipv4(&outer_ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("stacked AH");
        assert_invite_recovered(&parsed);
    }

    /// Stacked AH in transport mode: the addresses stay outer, and the
    /// protocol reported is the one AH protects.
    #[test]
    fn parse_nested_ah_transport_mode_recovers_invite() {
        let mut inner_ah = ah_header(17, 12); // protects UDP
        inner_ah.extend_from_slice(&invite_packet()[20..]);
        let mut outer_ah = ah_header(51, 12);
        outer_ah.extend_from_slice(&inner_ah);
        let ip = wrap_in_ipv4(&outer_ah, 51, [10, 0, 0, 1], [10, 0, 0, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("stacked AH transport");
        assert_invite_recovered(&parsed);
        assert_eq!(parsed.ip_protocol, 17);
    }

    /// A Payload Len that runs past the captured bytes is refused, not
    /// followed: the field is attacker-controlled.
    #[test]
    fn parse_nested_ah_overlong_payload_len_is_refused() {
        let mut inner_ah = ah_header(4, 12);
        inner_ah[1] = 0xFF; // 1028 octets of AH in a frame that has far less
        inner_ah.extend_from_slice(&invite_packet());
        let mut outer_ah = ah_header(51, 12);
        outer_ah.extend_from_slice(&inner_ah);
        let ip = wrap_in_ipv4(&outer_ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(
                err,
                CaptureError::TooShort {
                    what: "IP Authentication Header",
                    ..
                }
            ),
            "an overlong AH must be refused, got {err:?}"
        );
    }

    /// A Payload Len describing a header shorter than AH's own mandatory
    /// fields would move the walk backwards. RFC 4302 §2 fixes those fields at
    /// 12 octets, so Payload Len 0 (an 8-octet AH) cannot be one.
    #[test]
    fn parse_nested_ah_undersized_header_is_refused() {
        let mut inner_ah = ah_header(4, 12);
        inner_ah[1] = 0x00; // claims an 8-octet AH
        inner_ah.extend_from_slice(&invite_packet());
        let mut outer_ah = ah_header(51, 12);
        outer_ah.extend_from_slice(&inner_ah);
        let ip = wrap_in_ipv4(&outer_ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(
                err,
                CaptureError::TooShort {
                    what: "IP Authentication Header",
                    ..
                }
            ),
            "an undersized AH must be refused, got {err:?}"
        );
    }

    /// A stack of Authentication Headers spends the same budget every other
    /// encapsulation does, so an attacker cannot chain them without limit.
    #[test]
    fn stacked_ah_headers_exhaust_the_budget() {
        let mut ah = ah_header(4, 12);
        ah.extend_from_slice(&invite_packet());
        for _ in 0..6 {
            let mut outer = ah_header(51, 12);
            outer.extend_from_slice(&ah);
            ah = outer;
        }
        let ip = wrap_in_ipv4(&ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(
                err,
                CaptureError::EncapTooDeep {
                    kind: "AH",
                    limit: 5
                }
            ),
            "stacked AH must share the frame's budget, got {err:?}"
        );
    }

    /// A fragment of an AH-protected datagram must key on protocol 51 — the
    /// number its IP header states — because that is what its sibling
    /// fragments key on and reassembly joins them by it.
    ///
    /// `etherparse` walks an Authentication Header whenever the IPv4 header
    /// names protocol 51, fragment or not, so on a non-first fragment it
    /// reads payload bytes as a header. Those bytes are the middle of a
    /// datagram, and the number it recovers from them is not the datagram's.
    #[test]
    fn ah_fragment_keys_on_the_header_protocol() {
        let mut body = ah_header(17, 12); // bytes that *look* like an AH
        body.extend_from_slice(&invite_packet()[20..]);
        let mut data = wrap_in_eth(
            &wrap_in_ipv4(&body, 51, [10, 0, 0, 1], [10, 0, 0, 2]),
            ETHERTYPE_IPV4,
        );
        data[20..22].copy_from_slice(&0x2000u16.to_be_bytes()); // MF set
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("AH fragment");
        assert!(parsed.more_fragments);
        assert_eq!(parsed.ip_protocol, 51, "a fragment keys on its own header");
    }

    /// A protected protocol that is neither an IP packet nor a transport
    /// header sipnab reads is named rather than guessed at.
    #[test]
    fn parse_nested_ah_unknown_protected_protocol_is_named() {
        let mut inner_ah = ah_header(50, 12); // AH over ESP
        inner_ah.extend_from_slice(&invite_packet());
        let mut outer_ah = ah_header(51, 12);
        outer_ah.extend_from_slice(&inner_ah);
        let ip = wrap_in_ipv4(&outer_ah, 51, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::UnsupportedIpProtocol(50)),
            "expected the protected protocol in the error, got {err:?}"
        );
    }

    /// ESP (protocol 50) is encrypted. It stays undecodable — traversing it
    /// would report ciphertext as a SIP message.
    #[test]
    fn parse_esp_is_not_traversed() {
        let mut esp = 0x1122_3344u32.to_be_bytes().to_vec(); // SPI
        esp.extend_from_slice(&1u32.to_be_bytes()); // Sequence Number
        esp.extend_from_slice(&invite_packet());
        let ip = wrap_in_ipv4(&esp, 50, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::NoTransport),
            "ESP must stay opaque, got {err:?}"
        );
    }

    /// GRE Protocol Type 0x6558 is Transparent Ethernet Bridging (RFC 7637
    /// §3.2): the payload is a whole Ethernet frame, so the Ethernet walk is
    /// re-entered rather than the IP walk.
    #[test]
    fn parse_gre_teb_recovers_invite() {
        let mut gre = gre_header(0x6558);
        gre.extend_from_slice(&invite_inner_frame());
        let ip = wrap_in_ipv4(&gre, 47, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("GRE-TEB");
        assert_invite_recovered(&parsed);
    }

    /// A GRE Protocol Type sipnab does not decode is still named in the
    /// error rather than guessed at.
    #[test]
    fn parse_gre_unknown_protocol_is_still_named() {
        let mut gre = gre_header(0x6559); // one past TEB
        gre.extend_from_slice(&invite_inner_frame());
        let ip = wrap_in_ipv4(&gre, 47, [192, 0, 2, 1], [192, 0, 2, 2]);
        let data = wrap_in_eth(&ip, ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::UnsupportedGreProtocol(0x6559)),
            "expected the protocol type in the error, got {err:?}"
        );
    }

    /// UDP 4789: the VXLAN payload is a full Ethernet frame.
    #[test]
    fn parse_vxlan_recovers_invite() {
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx.extend_from_slice(&invite_inner_frame());
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("VXLAN");
        assert_invite_recovered(&parsed);
    }

    /// UDP 2152: a GTP-U G-PDU carries a bare IP packet, which is how VoLTE
    /// signaling crosses S1-U / N3.
    #[test]
    fn parse_gtpu_recovers_invite() {
        let inner = invite_packet();
        let mut gtp = gtpu_header(0xDEAD_BEEF, inner.len());
        gtp.extend_from_slice(&inner);
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 2152, 2152, &gtp);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("GTP-U");
        assert_invite_recovered(&parsed);
    }

    /// A tunnel port appearing as the SOURCE port is an ordinary ephemeral
    /// port, not a tunnel. Only the destination port may claim a payload.
    #[test]
    fn parse_udp_tunnel_port_as_source_is_not_decapsulated() {
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx.extend_from_slice(&invite_inner_frame());
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 4789, 5060, &vx);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("plain UDP");
        assert_eq!(parsed.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_port, 5060);
        assert_eq!(&parsed.payload[..], &vx[..]);
    }

    /// A VXLAN header whose reserved bits are not zero is an RTP payload that
    /// happened to land on port 4789. It must stay an RTP payload.
    #[test]
    fn parse_vxlan_nonzero_reserved_stays_plain_udp() {
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx[3] = 0x01; // a reserved octet RFC 7348 §5 requires to be zero
        vx.extend_from_slice(&invite_inner_frame());
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("plain UDP");
        assert_eq!(parsed.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_port, 4789);
        assert_eq!(&parsed.payload[..], &vx[..]);
    }

    /// A non-first fragment's payload is not a tunnel header, and neither is
    /// a first fragment's tail. A fragmented datagram on a tunnel port stays
    /// a fragment, so reassembly — not decapsulation — gets it.
    #[test]
    fn parse_fragmented_tunnel_port_is_not_decapsulated() {
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx.extend_from_slice(&invite_inner_frame());
        let mut data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx);
        data[20..22].copy_from_slice(&0x2000u16.to_be_bytes()); // MF set, offset 0
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("first fragment");
        assert_eq!(parsed.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 0, "a fragment has no transport header");
        assert!(parsed.more_fragments);
    }

    /// Octets that sit inside the IP datagram but past the end of the UDP one
    /// — Ethernet's minimum-length padding, a trailer, an FCS a capture stack
    /// kept — are not part of the tunnel payload.
    ///
    /// Every length check the decapsulators run is a comparison against the
    /// payload they were handed: GTP-U's declared length, the inner header's
    /// Total Length. Hand them the tail of the frame and each of those reads
    /// the extra octets as payload the header failed to account for, and
    /// refuses a frame that is perfectly good. The UDP **Length** field is the
    /// only bound that is tight, which is why `udp.payload()` is what the
    /// dispatch is given.
    #[test]
    fn parse_gtpu_ignores_octets_past_the_udp_length() {
        let inner = invite_packet();
        let mut gtp = gtpu_header(7, inner.len());
        gtp.extend_from_slice(&inner);
        let mut data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 2152, 2152, &gtp);
        // Four octets after the UDP datagram, still inside the IP one.
        const TRAILER: usize = 4;
        let total = u16::from_be_bytes([data[16], data[17]]) + TRAILER as u16;
        data[16..18].copy_from_slice(&total.to_be_bytes());
        data.resize(data.len() + TRAILER, 0x00);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("GTP-U with a trailer");
        assert_invite_recovered(&parsed);
    }

    /// The Ethernet payload the UDP tunnels hand back re-enters the same
    /// walk, VLAN tags and all.
    #[test]
    fn parse_vxlan_over_inner_vlan_recovers_invite() {
        let tagged = prepend_vlan_tag(&invite_inner_frame(), ETHERTYPE_QINQ, 0x0064);
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx.extend_from_slice(&tagged);
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("VXLAN over VLAN");
        assert_invite_recovered(&parsed);
    }

    /// A first fragment carries only the *head* of whatever it wraps, and a
    /// non-first fragment carries the middle of it. Neither is a tunnel
    /// header, so a fragmented datagram is handed to reassembly whole rather
    /// than decapsulated from a partial header.
    ///
    /// Decapsulating one would report the inner addresses for the first
    /// fragment and the outer addresses for the rest, which both scatters the
    /// datagram across `--cores` workers and reassembles it under the wrong
    /// key.
    #[test]
    fn parse_fragmented_ip_in_ip_is_not_decapsulated() {
        let mut data = wrap_in_eth(
            &wrap_in_ipv4(&invite_packet(), 4, [192, 0, 2, 1], [192, 0, 2, 2]),
            ETHERTYPE_IPV4,
        );
        data[20..22].copy_from_slice(&0x2000u16.to_be_bytes()); // MF set, offset 0
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("first fragment");
        assert_eq!(parsed.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.dst_addr, "192.0.2.2".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.src_port, 0, "a fragment has no transport header");
        assert!(parsed.more_fragments);
        assert_eq!(parsed.ip_protocol, 4);
    }

    // ── One shared recursion budget ───────────────────────────────────

    /// Wrap `frame` in `n` layers of IPv4-in-IPv4, outermost last.
    fn nest_ip_in_ip(packet: &[u8], n: usize) -> Vec<u8> {
        let mut cur = packet.to_vec();
        for _ in 0..n {
            cur = wrap_in_ipv4(&cur, 4, [172, 16, 0, 1], [172, 16, 0, 2]);
        }
        cur
    }

    /// Five encapsulations of the same kind are within budget.
    #[test]
    fn five_ip_in_ip_layers_are_within_budget() {
        let data = wrap_in_eth(&nest_ip_in_ip(&invite_packet(), 5), ETHERTYPE_IPV4);
        let parsed = parse_packet(&make_packet(data, DLT_EN10MB)).expect("5 layers");
        assert_invite_recovered(&parsed);
    }

    /// Six are not — attacker-controlled nesting terminates.
    #[test]
    fn six_ip_in_ip_layers_exhaust_the_budget() {
        let data = wrap_in_eth(&nest_ip_in_ip(&invite_packet(), 6), ETHERTYPE_IPV4);
        let err = parse_packet(&make_packet(data, DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
            "expected the depth limit, got {err:?}"
        );
    }

    /// Build MACsec → MPLS → GTP-U → `ip_layers` × IP-in-IP → the INVITE.
    ///
    /// Four different encapsulation kinds plus a tunable IP-in-IP stack, so
    /// the same fixture proves both halves of the budget rule.
    fn mixed_encapsulation(ip_layers: usize) -> Vec<u8> {
        let inner = nest_ip_in_ip(&invite_packet(), ip_layers);
        let mut gtp = gtpu_header(1, inner.len());
        gtp.extend_from_slice(&inner);
        let udp = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 2152, 2152, &gtp);
        let mpls = splice_after_macs(&udp, 0x8847, &mpls_label(16_000, true));
        wrap_in_macsec(&mpls, 0x00)
    }

    /// MACsec + MPLS + GTP-U + two IP-in-IP layers is five encapsulations of
    /// five different kinds, and it parses — the budget is a depth limit, not
    /// a per-kind one.
    #[test]
    fn five_mixed_encapsulations_are_within_budget() {
        let parsed =
            parse_packet(&make_packet(mixed_encapsulation(1), DLT_EN10MB)).expect("5 mixed layers");
        assert_invite_recovered(&parsed);
    }

    /// A sixth layer of any kind exhausts the SAME budget: a frame cannot buy
    /// extra depth by varying the encapsulation it uses.
    #[test]
    fn six_mixed_encapsulations_exhaust_the_budget() {
        let err = parse_packet(&make_packet(mixed_encapsulation(2), DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
            "a mixed stack must share one budget, got {err:?}"
        );
    }

    /// An MPLS-in-IP packet under `ip_layers` of IP-in-IP.
    ///
    /// Costs `ip_layers + 2` units of budget: one per IP-in-IP hop, one for
    /// the label stack, one for the packet it exposes.
    fn mpls_in_ip_under(ip_layers: usize) -> Vec<u8> {
        let mut mpls = mpls_label(16_000, true).to_vec();
        mpls.extend_from_slice(&invite_packet());
        let inner = wrap_in_ipv4(&mpls, 137, [192, 0, 2, 1], [192, 0, 2, 2]);
        wrap_in_eth(&nest_ip_in_ip(&inner, ip_layers), ETHERTYPE_IPV4)
    }

    /// A GRE-TEB frame under `ip_layers` of IP-in-IP; same accounting as
    /// [`mpls_in_ip_under`].
    fn gre_teb_under(ip_layers: usize) -> Vec<u8> {
        let mut gre = gre_header(0x6558);
        gre.extend_from_slice(&invite_inner_frame());
        let inner = wrap_in_ipv4(&gre, 47, [192, 0, 2, 1], [192, 0, 2, 2]);
        wrap_in_eth(&nest_ip_in_ip(&inner, ip_layers), ETHERTYPE_IPV4)
    }

    /// The label stack itself costs a unit, so three IP-in-IP hops over
    /// MPLS-in-IP is exactly five layers and parses …
    #[test]
    fn mpls_in_ip_within_budget_parses() {
        let parsed = parse_packet(&make_packet(mpls_in_ip_under(3), DLT_EN10MB)).expect("5 layers");
        assert_invite_recovered(&parsed);
    }

    /// … and a fourth hop is a sixth layer, which is refused. Without the
    /// label stack's own charge this frame would be five and would parse.
    #[test]
    fn mpls_in_ip_spends_from_the_shared_budget() {
        let err = parse_packet(&make_packet(mpls_in_ip_under(4), DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
            "MPLS-in-IP must spend a unit of the frame's budget, got {err:?}"
        );
    }

    /// The same accounting for GRE-TEB: the bridged frame costs a unit.
    #[test]
    fn gre_teb_within_budget_parses() {
        let parsed = parse_packet(&make_packet(gre_teb_under(3), DLT_EN10MB)).expect("5 layers");
        assert_invite_recovered(&parsed);
    }

    /// One hop deeper is refused; without GRE-TEB's charge it would parse.
    #[test]
    fn gre_teb_spends_from_the_shared_budget() {
        let err = parse_packet(&make_packet(gre_teb_under(4), DLT_EN10MB)).unwrap_err();
        assert!(
            matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
            "GRE-TEB must spend a unit of the frame's budget, got {err:?}"
        );
    }

    // ── peek_host_pair: the `--cores` shard key ───────────────────────

    /// The peek follows link-layer encapsulation, so an MPLS frame shards on
    /// the same host pair the full parse reports.
    #[test]
    fn peek_follows_mpls_like_the_full_parse() {
        let data = splice_after_macs(&invite_frame(), 0x8847, &mpls_label(16_000, true));
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("MPLS");
        assert_eq!(
            peek_host_pair(&pkt),
            Some((parsed.src_addr, parsed.dst_addr))
        );
    }

    /// An EtherType the walk does not decode yields no shard key at all —
    /// not an offset for the caller to read addresses from.
    ///
    /// The distinction is not academic. A destination MAC beginning `0x4…` or
    /// `0x6…` is an ordinary unicast address, and a peek that handed back an
    /// offset into a frame it could not decode would read the version nibble
    /// out of that MAC, agree with itself that this is IPv4, and return a host
    /// pair assembled from link-layer bytes. Those addresses were never on the
    /// wire, and they would key a shard — and every report keyed off it.
    #[test]
    fn peek_refuses_an_undecodable_ethertype() {
        let mut data = vec![0x40; 6]; // dst MAC whose first nibble reads as IPv4
        data.extend_from_slice(&[0xBA; 6]); // src MAC
        data.extend_from_slice(&0x0806u16.to_be_bytes()); // ARP
        // A well-formed ARP request, so the refusal is "no IP layer" rather
        // than a decode failure that would mask what is under test.
        data.extend_from_slice(&[0x00, 0x01]); // htype: Ethernet
        data.extend_from_slice(&[0x08, 0x00]); // ptype: IPv4
        data.extend_from_slice(&[6, 4]); // hlen, plen
        data.extend_from_slice(&[0x00, 0x01]); // oper: request
        data.extend_from_slice(&[0xBA; 6]); // sender hardware address
        data.extend_from_slice(&[10, 0, 0, 1]); // sender protocol address
        data.extend_from_slice(&[0x00; 6]); // target hardware address
        data.extend_from_slice(&[10, 0, 0, 2]); // target protocol address
        let pkt = make_packet(data, DLT_EN10MB);
        assert_eq!(peek_host_pair(&pkt), None, "no key from undecoded bytes");
        // `etherparse` slices ARP into `NetSlice::Arp`, which has no IP
        // payload to walk into, so the full parse's refusal is `NoIpPayload`.
        // `classify_undecodable` files it beside `NotIp` for exactly that
        // reason: a well-formed ARP frame is the commonest non-IP frame on
        // any Ethernet capture, not a truncation.
        assert!(
            matches!(
                parse_packet(&pkt),
                Err(CaptureError::NoIpPayload { what: "packet" })
            ),
            "and the full parse agrees there is no IP layer"
        );
    }

    /// The peek follows MACsec too: the SecTAG is on every frame of a flow,
    /// including every fragment of one datagram.
    #[test]
    fn peek_follows_macsec_like_the_full_parse() {
        let data = wrap_in_macsec(&invite_frame(), 0x00);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("MACsec");
        assert_eq!(
            peek_host_pair(&pkt),
            Some((parsed.src_addr, parsed.dst_addr))
        );
    }

    /// The peek deliberately does NOT follow a UDP tunnel: it reports the
    /// TUNNEL endpoints while the full parse reports the inner ones. Every
    /// frame of the tunnel — including fragments that carry no VXLAN header
    /// at all — therefore shards to one worker.
    #[test]
    fn peek_stays_outer_for_udp_tunnels() {
        let mut vx = vxlan_header(0x00_1234).to_vec();
        vx.extend_from_slice(&invite_inner_frame());
        let data = build_eth_ipv4_udp([192, 0, 2, 1], [192, 0, 2, 2], 32_768, 4789, &vx);
        let pkt = make_packet(data, DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("VXLAN");
        assert_eq!(parsed.src_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            peek_host_pair(&pkt),
            Some((
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap()
            )),
            "the peek must key on the tunnel endpoints"
        );
    }

    /// The same for a network-layer tunnel: GRE's inner packet is invisible
    /// to the peek by design.
    #[test]
    fn peek_stays_outer_for_gre() {
        let mut gre = gre_header(0x0800);
        gre.extend_from_slice(&invite_packet());
        let ip = wrap_in_ipv4(&gre, 47, [192, 0, 2, 1], [192, 0, 2, 2]);
        let pkt = make_packet(wrap_in_eth(&ip, ETHERTYPE_IPV4), DLT_EN10MB);
        let parsed = parse_packet(&pkt).expect("GRE");
        assert_eq!(parsed.src_addr, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(
            peek_host_pair(&pkt),
            Some((
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "192.0.2.2".parse::<IpAddr>().unwrap()
            ))
        );
    }

    // ── Linux cooked capture (DLT_LINUX_SLL / SLL2) ───────────────────
    //
    // `tcpdump -i any` is what an operator reaches for on a box whose access
    // interface is not the one they can name, and on a BNG/BRAS that access
    // interface carries PPPoE. sipnab decoded PPPoE behind Ethernet and
    // skipped a fixed header length for SLL / SLL2, so the exact combination
    // the operator produces — PPPoE inside a cooked-capture frame — reached
    // the IP slicer at the PPPoE header and came back "not IP".

    /// The RFC 7042 §2.1.2 documentation MAC, in the 8-byte SLL address field.
    const SLL_ADDRESS: [u8; 8] = [0x00, 0x00, 0x5E, 0x00, 0x53, 0x01, 0x00, 0x00];

    /// ARPHRD_ETHER — the type an `-i any` capture of an Ethernet-backed
    /// interface carries, and the one that makes the protocol field an
    /// EtherType.
    const ARPHRD_ETHER: u16 = 1;

    /// Wrap `payload` in a Linux SLL (cooked capture v1) header.
    ///
    /// libpcap's `LINKTYPE_LINUX_SLL`: packet type (2), ARPHRD_ type (2),
    /// address length (2), address (8), **protocol type (2, at offset 14)**,
    /// then the payload at 16. The protocol field's offset is the whole point
    /// of these helpers — SLL2 puts its at 0 — so it is written last here and
    /// first in [`linux_sll2`], where the layouts put them.
    fn linux_sll(payload: &[u8], arphrd: u16, proto: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(16 + payload.len());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // LINUX_SLL_HOST
        pkt.extend_from_slice(&arphrd.to_be_bytes());
        pkt.extend_from_slice(&6u16.to_be_bytes()); // address length
        pkt.extend_from_slice(&SLL_ADDRESS);
        pkt.extend_from_slice(&proto.to_be_bytes()); // offset 14
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Wrap `payload` in a Linux SLL2 header.
    ///
    /// libpcap's `LINKTYPE_LINUX_SLL2`: **protocol type (2, at offset 0)**,
    /// reserved MBZ (2), interface index (4), ARPHRD_ type (2, at offset 8),
    /// packet type (1), address length (1), address (8), then the payload at
    /// 20.
    fn linux_sll2(payload: &[u8], arphrd: u16, proto: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(20 + payload.len());
        pkt.extend_from_slice(&proto.to_be_bytes()); // offset 0
        pkt.extend_from_slice(&0u16.to_be_bytes()); // reserved, MBZ
        pkt.extend_from_slice(&2u32.to_be_bytes()); // interface index
        pkt.extend_from_slice(&arphrd.to_be_bytes()); // offset 8
        pkt.push(0); // packet type
        pkt.push(6); // address length
        pkt.extend_from_slice(&SLL_ADDRESS);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// A PPPoE Session frame's bytes from the PPPoE header onward — what a
    /// cooked-capture frame carries after its protocol field says 0x8864.
    fn pppoe_body(base: &[u8], ppp_proto: &[u8]) -> Vec<u8> {
        pppoe_session(base, ppp_proto)[14..].to_vec()
    }

    /// PPPoE inside SLL — `tcpdump -i any` on a BNG — decapsulates, and the
    /// shard peek agrees with the full parse.
    #[test]
    fn pppoe_inside_linux_sll_decapsulates() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        let frame = linux_sll(&pppoe_body(&base, &[0x00, 0x21]), ARPHRD_ETHER, 0x8864);
        let pkt = make_packet(frame, DLT_LINUX_SLL);
        let parsed = parse_packet(&pkt).expect("PPPoE inside SLL should parse");
        assert_eq!(parsed.src_addr, IpAddr::V4(a));
        assert_eq!(parsed.dst_addr, IpAddr::V4(b));
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5062);
        assert_eq!(parsed.transport, TransportProto::Udp);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// The same for SLL2, and for IPv6 behind PPP protocol 0x0057.
    #[test]
    fn pppoe_inside_linux_sll2_decapsulates() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        let frame = linux_sll2(&pppoe_body(&base, &[0x00, 0x21]), ARPHRD_ETHER, 0x8864);
        let pkt = make_packet(frame, DLT_LINUX_SLL2);
        let parsed = parse_packet(&pkt).expect("PPPoE inside SLL2 should parse");
        assert_eq!(parsed.src_addr, IpAddr::V4(a));
        assert_eq!(parsed.dst_addr, IpAddr::V4(b));
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));

        let a6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let base6 = build_eth_ipv6_udp(a6.octets(), b6.octets(), 5060, 5062, payload);
        let frame6 = linux_sll2(&pppoe_body(&base6, &[0x00, 0x57]), ARPHRD_ETHER, 0x8864);
        let pkt6 = make_packet(frame6, DLT_LINUX_SLL2);
        let parsed6 = parse_packet(&pkt6).expect("PPPoE IPv6 inside SLL2 should parse");
        assert_eq!(parsed6.src_addr, IpAddr::V6(a6));
        assert_eq!(parsed6.dst_addr, IpAddr::V6(b6));
        assert_eq!(
            peek_host_pair(&pkt6),
            Some((IpAddr::V6(a6), IpAddr::V6(b6)))
        );
    }

    /// SLL reads its protocol field at offset 14 and SLL2 reads its at offset
    /// 0 — the two layouts are not the same, and copying one arm onto the
    /// other is the mistake this test exists to catch.
    ///
    /// Each frame carries a decoy 0x8864 at the *other* link type's protocol
    /// offset and a real 0x0800 at its own, so an arm that reads the wrong
    /// offset sees "PPPoE" where the frame says "IPv4" and decapsulates six
    /// bytes that are not a PPPoE header.
    #[test]
    fn sll_and_sll2_read_the_protocol_field_at_their_own_offset() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let payload = b"OPTIONS sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);
        let ip = &base[14..];

        // SLL: real protocol at 14; bytes 0..2 are the packet type, and an
        // arm that read the protocol there (the SLL2 offset) would see 0x8864.
        let mut sll = linux_sll(ip, ARPHRD_ETHER, 0x0800);
        sll[0..2].copy_from_slice(&0x8864u16.to_be_bytes());
        let pkt = make_packet(sll, DLT_LINUX_SLL);
        let parsed = parse_packet(&pkt).expect("SLL protocol type lives at offset 14");
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), want);

        // SLL2: real protocol at 0; bytes 14..16 are inside the link-layer
        // address, which is where the SLL offset would look.
        let mut sll2 = linux_sll2(ip, ARPHRD_ETHER, 0x0800);
        sll2[14..16].copy_from_slice(&0x8864u16.to_be_bytes());
        let pkt2 = make_packet(sll2, DLT_LINUX_SLL2);
        let parsed2 = parse_packet(&pkt2).expect("SLL2 protocol type lives at offset 0");
        assert_eq!(parsed2.src_port, 5060);
        assert_eq!(parsed2.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt2), want);
    }

    /// A VLAN tag re-inserted into an SLL frame moves the payload four bytes,
    /// and the shard peek must move with it.
    ///
    /// libpcap re-inserts a hardware-stripped tag at `SLL_HDR_LEN - 2`
    /// (`set_vlan_offset` in `pcap-linux.c`), so the SLL protocol field
    /// becomes the TPID and the payload begins with the TCI and the protocol
    /// the tag encapsulates. `etherparse` has always followed that; the peek
    /// skipped a flat 16 bytes and returned `None`, which is the `--cores`
    /// split brain in its quiet form: every frame on a tagged cooked capture
    /// shards to worker 0.
    #[test]
    fn sll_vlan_tag_moves_the_payload_for_peek_and_parse_alike() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        // One tag: TCI (VID 100) then the encapsulated EtherType.
        let mut tagged = vec![0x00, 0x64];
        tagged.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        tagged.extend_from_slice(&base[14..]);
        let pkt = make_packet(
            linux_sll(&tagged, ARPHRD_ETHER, ETHERTYPE_VLAN),
            DLT_LINUX_SLL,
        );
        let parsed = parse_packet(&pkt).expect("VLAN inside SLL should parse");
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), want);

        // The access shape that matters: the subscriber VLAN outside PPPoE.
        let mut tagged_pppoe = vec![0x00, 0x64];
        tagged_pppoe.extend_from_slice(&0x8864u16.to_be_bytes());
        tagged_pppoe.extend_from_slice(&pppoe_body(&base, &[0x00, 0x21]));
        let pkt = make_packet(
            linux_sll(&tagged_pppoe, ARPHRD_ETHER, ETHERTYPE_VLAN),
            DLT_LINUX_SLL,
        );
        let parsed = parse_packet(&pkt).expect("VLAN + PPPoE inside SLL should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), want);
    }

    /// The protocol field is only an EtherType for the ARPHRD_ types where
    /// libpcap says it is.
    ///
    /// For ARPHRD_NETLINK (824) it is a Netlink protocol type, for
    /// ARPHRD_IPGRE (778) / ARPHRD_IP6GRE (823) a GRE protocol type, and for
    /// ARPHRD_IEEE80211_RADIOTAP (803) and ARPHRD_FRAD (770) it is ignored
    /// entirely. Reading 0x8864 there and decapsulating six bytes as a PPPoE
    /// header would manufacture a flow out of a Netlink message.
    #[test]
    fn sll_protocol_field_is_not_an_ethertype_for_every_arphrd_type() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let body = pppoe_body(&base, &[0x00, 0x21]);

        for arphrd in [770u16, 778, 803, 823, 824] {
            let pkt = make_packet(linux_sll(&body, arphrd, 0x8864), DLT_LINUX_SLL);
            assert!(
                parse_packet(&pkt).is_err(),
                "ARPHRD {arphrd} does not carry an EtherType in its protocol field"
            );
            assert_eq!(peek_host_pair(&pkt), None, "ARPHRD {arphrd} (SLL)");

            let pkt2 = make_packet(linux_sll2(&body, arphrd, 0x8864), DLT_LINUX_SLL2);
            assert!(
                parse_packet(&pkt2).is_err(),
                "ARPHRD {arphrd} does not carry an EtherType in its protocol field"
            );
            assert_eq!(peek_host_pair(&pkt2), None, "ARPHRD {arphrd} (SLL2)");
        }
    }

    /// An SLL frame whose ARPHRD_ type `etherparse` refuses still parses.
    ///
    /// `etherparse` only knows five ARPHRD_ values; `ARPHRD_PPP` (512) — what
    /// `-i any` stamps on a frame from `ppp0` — is not one of them, so the
    /// whole header comes back as an error and the manual header skip is the
    /// only thing that reads the frame. It predates this work and must
    /// survive it.
    #[test]
    fn sll_frames_etherparse_rejects_still_parse_through_the_manual_skip() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"REGISTER sip:example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        // ARPHRD_PPP = 512.
        let pkt = make_packet(linux_sll(&base[14..], 512, ETHERTYPE_IPV4), DLT_LINUX_SLL);
        let parsed = parse_packet(&pkt).expect("ARPHRD_PPP frame should still parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));
    }

    /// Every truncation point in a PPPoE-in-SLL / SLL2 frame yields an error
    /// or `None`, never a panic and never a read past the captured bytes.
    #[test]
    fn sll_pppoe_truncated_frames_yield_none_not_panic() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let body = pppoe_body(&base, &[0x00, 0x21]);
        let v1 = linux_sll(&body, ARPHRD_ETHER, 0x8864);
        let v2 = linux_sll2(&body, ARPHRD_ETHER, 0x8864);

        // `ip_off` is where the walk must land: cooked header + 6-byte PPPoE
        // header + 2-byte PPP Protocol field. A frame cut before
        // `ip_off + 20` cannot hold the IPv4 destination address, so the peek
        // has nothing legitimate to report and any host pair it returns was
        // read out of bytes that are not addresses.
        for (frame, link_type, ip_off) in
            [(&v1, DLT_LINUX_SLL, 16 + 8), (&v2, DLT_LINUX_SLL2, 20 + 8)]
        {
            assert!(
                frame.len() > ip_off + 20,
                "the fixture must be longer than the truncation sweep"
            );
            for cut in 0..(ip_off + 20) {
                let pkt = make_packet(frame[..cut].to_vec(), link_type);
                assert!(
                    parse_packet(&pkt).is_err(),
                    "link type {link_type} truncated to {cut} bytes must not parse"
                );
                assert_eq!(
                    peek_host_pair(&pkt),
                    None,
                    "link type {link_type} truncated to {cut} bytes must peek None"
                );
            }
            // …and the untruncated frame does parse, so the sweep above is not
            // passing on a decoder that refuses everything.
            let whole = make_packet(frame.to_vec(), link_type);
            assert_eq!(
                parse_packet(&whole)
                    .expect("the whole frame parses")
                    .src_port,
                5060
            );
        }
    }

    /// An offset past the end of the frame is `TooShort`, not a panic.
    ///
    /// Capture data is attacker-controlled and every link-layer walk in this
    /// file hands [`slice_ip_at`] an offset computed from it, so the one place
    /// they all funnel through is the one that must not index. The two error
    /// shapes are asserted apart because they mean different things to an
    /// operator: a frame shorter than its own headers is a snaplen, and bytes
    /// that are not an IP header are a framing this parser got wrong.
    #[test]
    fn slice_ip_at_refuses_an_offset_past_the_frame() {
        let frame = [0x45u8, 0x00, 0x00, 0x14];
        assert!(
            matches!(
                slice_ip_at(&frame, 64, "test frame"),
                Err(CaptureError::TooShort {
                    need: 64,
                    got: 4,
                    ..
                })
            ),
            "an offset past the end must be TooShort, never an index"
        );
        assert!(matches!(
            slice_ip_at(&[0x00, 0x01], 0, "test frame"),
            Err(CaptureError::PacketDecode { .. })
        ));
    }

    /// Stack `count` VLAN tags into a cooked frame, returning the protocol
    /// field to declare and the payload to put behind it.
    ///
    /// In a cooked capture the outermost TPID *is* the protocol field, and
    /// each tag body is `TCI | next protocol` — which is why this returns a
    /// pair rather than prefixing bytes the way the Ethernet helper does.
    fn sll_vlan_stack(inner: &[u8], inner_proto: u16, count: usize) -> (u16, Vec<u8>) {
        if count == 0 {
            return (inner_proto, inner.to_vec());
        }
        let mut payload = Vec::new();
        for i in 0..count {
            payload.extend_from_slice(&100u16.to_be_bytes()); // TCI: VID 100
            let next = if i + 1 == count {
                inner_proto
            } else {
                ETHERTYPE_VLAN
            };
            payload.extend_from_slice(&next.to_be_bytes());
        }
        payload.extend_from_slice(inner);
        (ETHERTYPE_VLAN, payload)
    }

    /// The cooked-capture tag walk is bounded at the same three tags the
    /// Ethernet walk allows.
    ///
    /// Unbounded, the walk terminates only by running off the end of the
    /// buffer, so a 64 KB frame of nothing but tags costs ~16k iterations
    /// over attacker-controlled bytes, per packet, on the capture hot path.
    /// Three is also `etherparse`'s `SlicedPacket::LINK_EXTS_CAP`, so a
    /// deeper stack is already invisible to the full parse and matching the
    /// bound is what keeps the peek and the parse agreeing.
    #[test]
    fn the_cooked_capture_vlan_walk_is_bounded() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, b"x");
        let pppoe = pppoe_body(&base, &[0x00, 0x21]);

        for depth in 0..=3usize {
            let (proto, payload) = sll_vlan_stack(&base[14..], ETHERTYPE_IPV4, depth);
            let pkt = make_packet(linux_sll(&payload, ARPHRD_ETHER, proto), DLT_LINUX_SLL);
            assert_eq!(peek_host_pair(&pkt), want, "{depth} tags must still peek");

            let (proto, payload) = sll_vlan_stack(&pppoe, 0x8864, depth);
            let pkt = make_packet(linux_sll(&payload, ARPHRD_ETHER, proto), DLT_LINUX_SLL);
            let parsed = parse_packet(&pkt)
                .unwrap_or_else(|e| panic!("{depth} tags + PPPoE must still parse: {e}"));
            assert_eq!(
                (parsed.src_addr, parsed.dst_addr),
                (IpAddr::V4(a), IpAddr::V4(b))
            );
            assert_eq!(peek_host_pair(&pkt), want, "{depth} tags + PPPoE");
        }

        // One past the bound, and a frame that is nothing but tags.
        for depth in [4usize, 4096] {
            let (proto, payload) = sll_vlan_stack(&base[14..], ETHERTYPE_IPV4, depth);
            let pkt = make_packet(linux_sll(&payload, ARPHRD_ETHER, proto), DLT_LINUX_SLL);
            assert_eq!(
                peek_host_pair(&pkt),
                None,
                "{depth} tags must not be walked"
            );

            let (proto, payload) = sll_vlan_stack(&pppoe, 0x8864, depth);
            let pkt = make_packet(linux_sll(&payload, ARPHRD_ETHER, proto), DLT_LINUX_SLL);
            assert!(
                parse_packet(&pkt).is_err(),
                "{depth} tags + PPPoE must not parse"
            );
            assert_eq!(peek_host_pair(&pkt), None, "{depth} tags + PPPoE");
        }
    }

    /// PPPoE inside a cooked frame spends from the same per-frame
    /// encapsulation budget the Ethernet walk charges it from.
    ///
    /// Five nested IP-in-IP layers are exactly the budget
    /// (`MAX_ENCAP_DEPTH`), so the pair below differs only in whether the
    /// PPPoE header was charged: the plain cooked frame parses, and the
    /// identical stack behind a PPPoE header is one layer too deep. Without
    /// the charge a frame could buy an extra layer of nesting simply by
    /// arriving cooked instead of on the wire.
    #[test]
    fn pppoe_inside_a_cooked_frame_spends_from_the_frame_budget() {
        let deep = nest_ip_in_ip(&invite_packet(), 5);

        let plain = make_packet(
            linux_sll(&deep, ARPHRD_ETHER, ETHERTYPE_IPV4),
            DLT_LINUX_SLL,
        );
        parse_packet(&plain).expect("five IP-in-IP layers are within the budget");

        let body = pppoe_body(&wrap_in_eth(&deep, ETHERTYPE_IPV4), &[0x00, 0x21]);
        let via_pppoe = make_packet(linux_sll(&body, ARPHRD_ETHER, 0x8864), DLT_LINUX_SLL);
        let err = parse_packet(&via_pppoe).unwrap_err();
        assert!(
            matches!(err, CaptureError::EncapTooDeep { limit: 5, .. }),
            "PPPoE must cost a layer inside a cooked frame too, got {err:?}"
        );
    }

    // ── Bare-IP link types (DLT_IPV4 / DLT_IPV6) ──────────────────────

    /// DLT_IPV4 (228) and DLT_IPV6 (229) carry a bare IP datagram, and both
    /// the full parse and the shard peek read it.
    #[test]
    fn bare_ip_link_types_parse_and_peek() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);
        let pkt = make_packet(base[14..].to_vec(), DLT_IPV4);
        let parsed = parse_packet(&pkt).expect("DLT_IPV4 frame should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));

        let a6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let base6 = build_eth_ipv6_udp(a6.octets(), b6.octets(), 5060, 5062, payload);
        let pkt6 = make_packet(base6[14..].to_vec(), DLT_IPV6);
        let parsed6 = parse_packet(&pkt6).expect("DLT_IPV6 frame should parse");
        assert_eq!(
            (parsed6.src_addr, parsed6.dst_addr),
            (IpAddr::V6(a6), IpAddr::V6(b6))
        );
        assert_eq!(parsed6.payload[..], payload[..]);
        assert_eq!(
            peek_host_pair(&pkt6),
            Some((IpAddr::V6(a6), IpAddr::V6(b6)))
        );
    }

    /// Each bare-IP link type refuses the version it does not declare.
    ///
    /// libpcap: LINKTYPE_IPV4 "should only be used for traffic that consists
    /// solely of IPv4 packets, and in which IPv6 packets should be considered
    /// errors", and LINKTYPE_IPV6 says the same with the versions swapped.
    /// DLT_RAW (12) is the mixed framing and keeps taking both.
    #[test]
    fn bare_ip_link_types_refuse_the_version_they_do_not_declare() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let v4 = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            payload,
        )[14..]
            .to_vec();
        let a6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b6: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let v6 = build_eth_ipv6_udp(a6.octets(), b6.octets(), 5060, 5062, payload)[14..].to_vec();

        for (data, link_type) in [(&v6, DLT_IPV4), (&v4, DLT_IPV6)] {
            let pkt = make_packet(data.clone(), link_type);
            assert!(
                parse_packet(&pkt).is_err(),
                "link type {link_type} declares one IP version and must refuse the other"
            );
            assert_eq!(peek_host_pair(&pkt), None, "link type {link_type}");
        }

        // DLT_RAW takes either, unchanged.
        for data in [&v4, &v6] {
            let pkt = make_packet(data.clone(), DLT_RAW);
            assert_eq!(
                parse_packet(&pkt)
                    .expect("DLT_RAW takes both versions")
                    .src_port,
                5060
            );
        }

        // An empty frame is short, not mis-versioned.
        for link_type in [DLT_IPV4, DLT_IPV6] {
            let pkt = make_packet(Vec::new(), link_type);
            assert!(parse_packet(&pkt).is_err());
            assert_eq!(peek_host_pair(&pkt), None);
        }
    }

    // ── PPP link types (DLT_PPP / DLT_PPP_SERIAL / DLT_PPP_ETHER) ─────

    /// DLT_PPP_ETHER (51) frames begin at the PPPoE header itself.
    ///
    /// libpcap: "Packets are PPPoE session packets, containing the Ethernet
    /// payload without an Ethernet header or CRC, as per section 4 of
    /// RFC 2516" — so it is the PPPoE decapsulator sipnab already owns,
    /// pointed at offset 0.
    #[test]
    fn ppp_ether_frames_start_at_the_pppoe_header() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let base = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload);

        let pkt = make_packet(pppoe_body(&base, &[0x00, 0x21]), DLT_PPP_ETHER);
        let parsed = parse_packet(&pkt).expect("DLT_PPP_ETHER frame should parse");
        assert_eq!(
            (parsed.src_addr, parsed.dst_addr),
            (IpAddr::V4(a), IpAddr::V4(b))
        );
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.payload[..], payload[..]);
        assert_eq!(peek_host_pair(&pkt), Some((IpAddr::V4(a), IpAddr::V4(b))));

        // A Discovery-stage frame is not session data here either.
        let discovery = wrap_in_pppoe(&base, 0x8863, 0x11, 0x09, &[0x00, 0x21])[14..].to_vec();
        let pkt = make_packet(discovery, DLT_PPP_ETHER);
        assert!(parse_packet(&pkt).is_err());
        assert_eq!(peek_host_pair(&pkt), None);
    }

    /// DLT_PPP (9) takes the HDLC address/control octets or their absence;
    /// DLT_PPP_SERIAL (50) requires them.
    ///
    /// libpcap on LINKTYPE_PPP: "If the first 2 octets are 0xff and 0x03, it's
    /// PPP in HDLC-like framing … otherwise it's PPP without framing, and the
    /// packet begins with the PPP header." On LINKTYPE_PPP_HDLC: the frames
    /// "include the address and control fields as specified by Section 3.1 of
    /// RFC1662".
    #[test]
    fn ppp_link_types_handle_the_hdlc_address_and_control_octets() {
        use std::net::Ipv4Addr;
        let a = Ipv4Addr::new(192, 0, 2, 10);
        let b = Ipv4Addr::new(198, 51, 100, 20);
        let want = Some((IpAddr::V4(a), IpAddr::V4(b)));
        let payload = b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n";
        let ip = build_eth_ipv4_udp(a.octets(), b.octets(), 5060, 5062, payload)[14..].to_vec();

        // PPP Protocol 0x0021 = IPv4, with and without `ff 03` in front.
        let mut framed = vec![0xFF, 0x03, 0x00, 0x21];
        framed.extend_from_slice(&ip);
        let mut bare = vec![0x00, 0x21];
        bare.extend_from_slice(&ip);

        for (frame, link_type) in [
            (&framed, DLT_PPP),
            (&bare, DLT_PPP),
            (&framed, DLT_PPP_SERIAL),
        ] {
            let pkt = make_packet(frame.clone(), link_type);
            let parsed = parse_packet(&pkt)
                .unwrap_or_else(|e| panic!("link type {link_type} frame should parse: {e}"));
            assert_eq!(
                (parsed.src_addr, parsed.dst_addr),
                (IpAddr::V4(a), IpAddr::V4(b))
            );
            assert_eq!(parsed.src_port, 5060);
            assert_eq!(parsed.payload[..], payload[..]);
            assert_eq!(peek_host_pair(&pkt), want, "link type {link_type}");
        }

        // DLT_PPP_SERIAL without the address and control fields is not a
        // frame of that link type, and is refused rather than guessed at.
        let pkt = make_packet(bare.clone(), DLT_PPP_SERIAL);
        assert!(parse_packet(&pkt).is_err());
        assert_eq!(peek_host_pair(&pkt), None);
    }

    /// A PPP frame carrying something that is not IP is never read as IP.
    ///
    /// LCP (0xC021), IPCP (0x8021), CHAP (0xC223) and Compressed Datagram
    /// (0x00FD) are all real PPP traffic on a live link, and each would slice
    /// as a plausible IPv4 header if the protocol field were not checked.
    #[test]
    fn ppp_link_types_reject_non_ip_protocols() {
        use std::net::Ipv4Addr;
        let ip = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        )[14..]
            .to_vec();

        for proto in [[0xC0u8, 0x21], [0x80, 0x21], [0xC2, 0x23], [0x00, 0xFD]] {
            let mut frame = vec![0xFF, 0x03];
            frame.extend_from_slice(&proto);
            frame.extend_from_slice(&ip);
            for link_type in [DLT_PPP, DLT_PPP_SERIAL] {
                let pkt = make_packet(frame.clone(), link_type);
                assert!(
                    parse_packet(&pkt).is_err(),
                    "PPP protocol {proto:02X?} on link type {link_type} is not IP"
                );
                assert_eq!(peek_host_pair(&pkt), None, "PPP protocol {proto:02X?}");
            }
        }
    }

    /// Every truncation point in a PPP-framed frame yields an error or
    /// `None`, never a panic.
    #[test]
    fn ppp_link_type_truncated_frames_yield_none_not_panic() {
        use std::net::Ipv4Addr;
        let base = build_eth_ipv4_udp(
            Ipv4Addr::new(192, 0, 2, 10).octets(),
            Ipv4Addr::new(198, 51, 100, 20).octets(),
            5060,
            5062,
            b"INVITE sip:echo@example.com SIP/2.0\r\n\r\n",
        );
        let mut framed = vec![0xFF, 0x03, 0x00, 0x21];
        framed.extend_from_slice(&base[14..]);
        let pppoe = pppoe_body(&base, &[0x00, 0x21]);

        // `ip_off`: 2 HDLC octets + 2 PPP Protocol octets for the PPP link
        // types, and the 6-byte PPPoE header + 2-byte Protocol field for
        // DLT_PPP_ETHER. Below `ip_off + 20` the IPv4 destination address is
        // not in the frame, so a host pair from the peek is a fabrication.
        for (frame, link_type, ip_off) in [
            (&framed, DLT_PPP, 4),
            (&framed, DLT_PPP_SERIAL, 4),
            (&pppoe, DLT_PPP_ETHER, 8),
        ] {
            for cut in 0..(ip_off + 20) {
                let pkt = make_packet(frame[..cut].to_vec(), link_type);
                assert!(
                    parse_packet(&pkt).is_err(),
                    "link type {link_type} truncated to {cut} bytes must not parse"
                );
                assert_eq!(
                    peek_host_pair(&pkt),
                    None,
                    "link type {link_type} truncated to {cut} bytes must peek None"
                );
            }
            let whole = make_packet(frame.to_vec(), link_type);
            assert_eq!(
                parse_packet(&whole)
                    .expect("the whole frame parses")
                    .src_port,
                5060
            );
        }
    }
}

/// What one ICMP error says about one SIP request that went unanswered.
///
/// The two addresses are the point of the type. `unreachable_addr` is the
/// quoted datagram's destination — the endpoint that did not answer, and the
/// address a finding should name. `reported_by` is the ICMP message's own
/// source — the router or host that noticed, which is frequently a different
/// device and is not itself faulty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEvidence {
    /// Capture time of the ICMP error.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// The endpoint that did not answer: the quoted datagram's destination.
    pub unreachable_addr: std::net::IpAddr,
    /// The port that was not listening, when the quote reached the transport
    /// header. `None` for a quote truncated before it.
    pub unreachable_port: Option<u16>,
    /// Who reported the failure: the ICMP message's source. A router on the
    /// path, not necessarily `unreachable_addr`.
    pub reported_by: std::net::IpAddr,
    /// Raw ICMP type byte.
    pub icmp_type: u8,
    /// Raw ICMP code byte.
    pub icmp_code: u8,
    /// The network's own words for this type/code, e.g. `port unreachable`.
    pub description: &'static str,
    /// `Call-ID` recovered from the quoted prefix. `None` when the quote
    /// stopped before that header, which makes the evidence unattributable —
    /// counted, never silently dropped.
    pub call_id: Option<String>,
    /// Method of the quoted request, when its start line was quoted.
    pub method: Option<String>,
    /// `CSeq` header of the quoted request, verbatim, when quoted.
    pub cseq: Option<String>,
    /// Whether the quote is known to be shorter than the datagram it quotes.
    pub truncated: bool,
    /// Bytes of the original SIP message the quote actually carried.
    pub quoted_bytes: usize,
}

/// Every ICMP error recorded against one dialog.
///
/// `errors` is exact; `samples` is capped. Two fields rather than one `Vec`
/// because a corpus run showed the difference mattering: 720 of 3,232 real
/// errors fell past the per-dialog sample cap, and a finding that counted the
/// retained samples would have reported "8 times" for a peer that failed
/// thirty. The count is what a reader acts on; the samples are what shows
/// them one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DialogIcmpEvidence {
    /// How many ICMP errors quoted this dialog's requests. Exact, whatever the
    /// retention cap.
    pub errors: u64,
    /// Retained errors, oldest first, capped by `pipeline::MAX_ICMP_PER_CALL_ID`
    /// (not linkable from here: the cap lives with the store, this is the type
    /// the store hands back, and wasm builds this without building that).
    pub samples: Vec<IcmpEvidence>,
}
