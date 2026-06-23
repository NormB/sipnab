//! Network header parsing for raw captured packets.
//!
//! Parses raw packet bytes through the link, network, and transport layers
//! using [`etherparse`] for zero-copy header parsing. Handles encapsulation
//! stripping (IP-in-IP, GRE) and produces [`ParsedPacket`] structs ready for
//! reassembly or direct consumption by upper-layer parsers.

use std::net::IpAddr;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use etherparse::{IpNumber, NetSlice, SlicedPacket, TransportSlice};

use super::packet::Packet;

// ── Public types ──────────────────────────────────────────────────────

/// Transport-layer protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProto {
    /// User Datagram Protocol.
    Udp,
    /// Transmission Control Protocol.
    Tcp,
    /// Stream Control Transmission Protocol (stub for future use).
    Sctp,
    /// TLS-encrypted TCP.
    Tls,
    /// WebSocket (SIP over WS).
    Ws,
}

impl TransportProto {
    /// Return the canonical string representation without allocating.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Sctp => "SCTP",
            Self::Tls => "TLS",
            Self::Ws => "WS",
        }
    }
}

impl std::fmt::Display for TransportProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    /// IPv4 identification field for fragment tracking (`None` for IPv6).
    pub ip_id: Option<u16>,
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
}

// ── DLT constants ─────────────────────────────────────────────────────

/// Pcap link type for Ethernet II (DLT_EN10MB).
const DLT_EN10MB: i32 = 1;
/// Pcap link type for raw IPv4/IPv6 (DLT_RAW).
const DLT_RAW: i32 = 12;
/// Pcap link type for Linux cooked capture v1 (DLT_LINUX_SLL).
const DLT_LINUX_SLL: i32 = 113;
/// Pcap link type for Linux cooked capture v2 (DLT_LINUX_SLL2).
const DLT_LINUX_SLL2: i32 = 276;

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

/// Map an IANA IP-protocol number to a [`TransportProto`].
///
/// Used by the pre-parsed short-circuit path; HEP and similar sources
/// carry the IP protocol number, not the application-level transport
/// like TLS or WS — so this only handles UDP / TCP / SCTP. Anything
/// else falls back to UDP, matching the most common HEP payload type.
fn ip_protocol_to_transport(p: u8) -> TransportProto {
    match p {
        6 => TransportProto::Tcp,
        17 => TransportProto::Udp,
        132 => TransportProto::Sctp,
        _ => TransportProto::Udp,
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

/// Parse a raw captured [`Packet`] into a [`ParsedPacket`].
///
/// Walks through link-layer, network, and transport headers based on
/// the packet's `link_type`. Handles:
/// - Ethernet II (DLT_EN10MB), including VLAN / QinQ
/// - Linux cooked capture (DLT_LINUX_SLL / SLL2)
/// - Raw IP (DLT_RAW)
/// - Encapsulation stripping: IP-in-IP (protocol 4) and GRE (protocol 47)
///
/// # Errors
///
/// Returns an error if the packet cannot be parsed (e.g., too short,
/// unsupported link type, non-IP traffic like ARP).
pub fn parse_packet(packet: &Packet) -> Result<ParsedPacket> {
    // Short-circuit: when the packet's source already knows the
    // addressing (e.g. HEP listener that reads it from HEP chunks),
    // skip link/IP/transport parsing and produce a ParsedPacket
    // directly. `data` is the transport-layer payload only.
    if let Some(meta) = &packet.pre_parsed {
        return Ok(ParsedPacket {
            timestamp: packet.timestamp,
            src_addr: meta.src_addr,
            dst_addr: meta.dst_addr,
            src_port: meta.src_port,
            dst_port: meta.dst_port,
            transport: ip_protocol_to_transport(meta.ip_protocol),
            payload: packet.data.clone(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: meta.ip_protocol,
        });
    }

    let data = &packet.data;

    // First-pass parse based on link type
    let sliced = match packet.link_type {
        DLT_EN10MB => {
            SlicedPacket::from_ethernet(data).context("Failed to parse Ethernet packet")?
        }
        DLT_LINUX_SLL => {
            // Linux SLL (cooked capture v1) has a 16-byte header:
            //   2 bytes: packet type
            //   2 bytes: ARPHRD type
            //   2 bytes: link-layer address length
            //   8 bytes: link-layer address
            //   2 bytes: protocol type (e.g., 0x0800 = IPv4)
            // Try etherparse first; fall back to manual parsing if it fails
            // (some kernel versions produce SLL variants etherparse doesn't handle).
            match SlicedPacket::from_linux_sll(data) {
                Ok(sliced) => sliced,
                Err(_) => {
                    if data.len() < 16 {
                        anyhow::bail!("Linux SLL packet too short ({} bytes)", data.len());
                    }
                    // Manual fallback: skip 16-byte SLL header, parse as IP
                    SlicedPacket::from_ip(&data[16..])
                        .context("Failed to parse IP from Linux SLL packet (manual fallback)")?
                }
            }
        }
        DLT_RAW => SlicedPacket::from_ip(data).context("Failed to parse raw IP packet")?,
        DLT_LINUX_SLL2 => {
            // SLL2 has a 20-byte header; etherparse doesn't have a dedicated
            // parser, but the IP packet starts at offset 20. Detect IP version
            // from the first nibble of the IP header.
            if data.len() < 20 {
                anyhow::bail!("Linux SLL2 packet too short ({} bytes)", data.len());
            }
            SlicedPacket::from_ip(&data[20..])
                .context("Failed to parse IP from Linux SLL2 packet")?
        }
        other => anyhow::bail!("Unsupported link type: {other}"),
    };

    // Extract IP-layer information
    let net = sliced.net.as_ref().context("Non-IP packet (e.g., ARP)")?;

    // Check for encapsulation and handle recursively
    let ip_payload = net.ip_payload_ref().context("No IP payload available")?;

    let ip_number = ip_payload.ip_number;

    // IP-in-IP (protocol 4) or GRE (protocol 47) — strip and re-parse
    if ip_number == IpNumber::IPV4 && !ip_payload.fragmented {
        // IP-in-IP encapsulation: inner packet is IPv4
        return parse_inner_ip(packet.timestamp, &packet.data, ip_payload.payload, 0);
    }
    if ip_number == IpNumber::GRE && !ip_payload.fragmented {
        return parse_gre(packet.timestamp, &packet.data, ip_payload.payload, 0);
    }

    // Normal (non-encapsulated) packet — extract fields
    extract_parsed_packet(packet.timestamp, &packet.data, net, &sliced.transport)
}

// ── Encapsulation helpers ─────────────────────────────────────────────

/// Maximum encapsulation recursion depth to prevent stack exhaustion.
const MAX_ENCAP_DEPTH: u8 = 5;

/// Parse an inner IP packet (from IP-in-IP or after GRE stripping).
///
/// The `depth` parameter tracks recursion depth to prevent stack exhaustion
/// from maliciously crafted packets with deeply nested encapsulation.
fn parse_inner_ip(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    ip_data: &[u8],
    depth: u8,
) -> Result<ParsedPacket> {
    if depth > MAX_ENCAP_DEPTH {
        anyhow::bail!("IP-in-IP encapsulation depth exceeds limit ({MAX_ENCAP_DEPTH})");
    }

    let sliced = SlicedPacket::from_ip(ip_data).context("Failed to parse inner IP packet")?;

    let net = sliced
        .net
        .as_ref()
        .context("Inner packet has no IP layer")?;

    // Check for nested encapsulation (unlikely but possible)
    let ip_payload = net
        .ip_payload_ref()
        .context("No IP payload in inner packet")?;

    if ip_payload.ip_number == IpNumber::IPV4 && !ip_payload.fragmented {
        return parse_inner_ip(timestamp, data, ip_payload.payload, depth + 1);
    }
    if ip_payload.ip_number == IpNumber::GRE && !ip_payload.fragmented {
        return parse_gre(timestamp, data, ip_payload.payload, depth + 1);
    }

    extract_parsed_packet(timestamp, data, net, &sliced.transport)
}

/// Parse a GRE-encapsulated packet.
///
/// Strips the GRE header (variable length based on flags) and re-parses
/// the inner IP packet.
fn parse_gre(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    gre_data: &[u8],
    depth: u8,
) -> Result<ParsedPacket> {
    if depth > MAX_ENCAP_DEPTH {
        anyhow::bail!("GRE encapsulation depth exceeds limit ({MAX_ENCAP_DEPTH})");
    }
    if gre_data.len() < GRE_HEADER_MIN {
        anyhow::bail!(
            "GRE header too short ({} bytes, need at least {GRE_HEADER_MIN})",
            gre_data.len()
        );
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
        anyhow::bail!(
            "GRE packet too short for optional fields ({} bytes, need {offset})",
            gre_data.len()
        );
    }

    let inner = &gre_data[offset..];

    match protocol {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => parse_inner_ip(timestamp, data, inner, depth),
        _ => anyhow::bail!("Unsupported GRE inner protocol: 0x{protocol:04X}"),
    }
}

// ── Field extraction ──────────────────────────────────────────────────

/// Extract a [`ParsedPacket`] from already-parsed network and transport slices.
fn extract_parsed_packet(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    net: &NetSlice<'_>,
    transport: &Option<TransportSlice<'_>>,
) -> Result<ParsedPacket> {
    // IP addresses
    let (src_addr, dst_addr, ip_id, fragment_offset, more_fragments, ip_protocol) = match net {
        NetSlice::Ipv4(v4) => {
            let hdr = v4.header();
            (
                IpAddr::V4(hdr.source_addr()),
                IpAddr::V4(hdr.destination_addr()),
                Some(hdr.identification()),
                Some(hdr.fragments_offset().value()),
                hdr.more_fragments(),
                hdr.protocol().0,
            )
        }
        NetSlice::Ipv6(v6) => {
            let hdr = v6.header();
            (
                IpAddr::V6(hdr.source_addr()),
                IpAddr::V6(hdr.destination_addr()),
                None,
                None,
                false,
                // For IPv6, use the ip_number from the payload (after ext headers)
                v6.payload().ip_number.0,
            )
        }
        // ARP (added as a NetSlice variant in etherparse 0.20) carries no IP
        // layer; sipnab only parses SIP/RTP over IP, so reject it here.
        NetSlice::Arp(_) => anyhow::bail!("ARP packet has no IP layer to parse"),
    };

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
        });
    }

    // SCTP: etherparse does not parse SCTP, so it arrives with no transport slice.
    // Detect it via the IP protocol number and return a debug log rather than an error.
    if ip_protocol == 132 {
        tracing::debug!("SCTP packet detected — not yet parsed");
        let payload = net
            .ip_payload_ref()
            .map(|p| slice_of(data, p.payload))
            .unwrap_or_default();
        return Ok(ParsedPacket {
            timestamp,
            src_addr,
            dst_addr,
            src_port: 0,
            dst_port: 0,
            transport: TransportProto::Sctp,
            payload,
            ip_id,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset,
            more_fragments,
            ip_protocol,
        });
    }

    // Transport header extraction
    let transport_slice = transport
        .as_ref()
        .context("No transport header (not UDP/TCP)")?;

    match transport_slice {
        TransportSlice::Udp(udp) => Ok(ParsedPacket {
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
        }),
        TransportSlice::Tcp(tcp) => Ok(ParsedPacket {
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
        }),
        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => {
            anyhow::bail!("ICMP packets are not processed by sipnab")
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

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
}
