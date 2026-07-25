// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network header parsing for raw captured packets.
//!
//! Parses raw packet bytes through the link, network, and transport layers
//! using [`etherparse`] for zero-copy header parsing. Handles encapsulation
//! stripping (IP-in-IP, GRE) and produces [`ParsedPacket`] structs ready for
//! reassembly or direct consumption by upper-layer parsers. Encapsulation
//! stripping covers IP-in-IP, 6in4 (IPv6-in-IPv4), and GRE.

use std::net::{IpAddr, SocketAddr};

use crate::error::CaptureError;
use ahash::RandomState;
use chrono::{DateTime, Utc};
use etherparse::{IpNumber, Ipv6ExtensionSlice, NetSlice, SlicedPacket, TransportSlice};
use indexmap::IndexMap;

use super::packet::Packet;

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
    /// Whether this packet originated from the HEP listener (its addressing
    /// came from HEP chunks a remote sender asserted, not from an observed
    /// IP header). Active responses such as scanner-kill treat HEP-origin
    /// packets as ineligible by default, since their src/dst are
    /// attacker-controllable and unauthenticated absent `--hep-auth` (SN-01).
    pub from_hep: bool,
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

/// Cheap outer host-pair extraction for multi-core sharding (`--cores N`).
///
/// Reads ONLY the link + IP headers at fixed offsets to get the outer src/dst
/// IPs — no transport/payload parse, no allocation, no `etherparse` slicing — so
/// the dispatcher's per-packet serial cost stays tiny while the full parse +
/// reassembly happen in the worker. Handles EN10MB (incl. 802.1Q/QinQ VLAN),
/// Linux SLL v1/v2, and raw IP, for IPv4 and IPv6, plus pre-parsed (HEP) packets.
/// Returns `None` for anything it can't cheaply read; the caller shards those to
/// worker 0 (still correct — that worker has its own reassembly — just less
/// balanced). All fragments / a flow's packets share an outer host pair, so they
/// always route to the same worker, keeping reassembly correct.
pub fn peek_host_pair(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    if let Some(meta) = &packet.pre_parsed {
        return Some((meta.src_addr, meta.dst_addr));
    }
    let d: &[u8] = &packet.data;
    let ip_off = match packet.link_type {
        DLT_EN10MB => {
            let mut off = 12usize; // skip dst+src MAC
            let mut et = u16::from_be_bytes([*d.get(off)?, *d.get(off + 1)?]);
            while et == 0x8100 || et == 0x88a8 {
                off += 4; // skip a VLAN tag (TPID+TCI)
                et = u16::from_be_bytes([*d.get(off)?, *d.get(off + 1)?]);
            }
            off + 2 // past the ethertype
        }
        DLT_RAW => 0,
        DLT_LINUX_SLL => 16,
        DLT_LINUX_SLL2 => 20,
        _ => return None,
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
    let sliced = slice_link_layer(packet.link_type, &packet.data).ok()?;
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
        if frag.tsn != partial.next_tsn
            || partial.buf.len().saturating_add(frag.data.len()) > MAX_SCTP_REASSEMBLY
        {
            // Gap / reorder / overflow — drop the partial, emit nothing.
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

/// Slice a raw link-layer frame into an [`SlicedPacket`] based on `link_type`.
///
/// Handles Ethernet II (with VLAN / QinQ via `etherparse`), Linux cooked
/// capture v1 (`DLT_LINUX_SLL`, with a manual header-skip fallback for kernel
/// SLL variants `etherparse` rejects) and v2 (`DLT_LINUX_SLL2`), and raw IP
/// (`DLT_RAW`). Shared by [`parse_packet`] and the SCTP fragment recovery path
/// so both reach the network layer the same way.
///
/// # Errors
///
/// Returns `UnsupportedLinkType` for an unrecognized `link_type`, `TooShort`
/// for a truncated SLL/SLL2 header, or `PacketDecode` when the frame cannot be
/// sliced.
fn slice_link_layer(link_type: i32, data: &[u8]) -> Result<SlicedPacket<'_>, CaptureError> {
    match link_type {
        DLT_EN10MB => SlicedPacket::from_ethernet(data).map_err(|e| CaptureError::PacketDecode {
            what: "Ethernet packet",
            source: Box::new(e),
        }),
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
                Ok(sliced) => Ok(sliced),
                Err(_) => {
                    if data.len() < 16 {
                        return Err(CaptureError::TooShort {
                            what: "Linux SLL packet",
                            need: 16,
                            got: data.len(),
                        });
                    }
                    // Manual fallback: skip 16-byte SLL header, parse as IP
                    SlicedPacket::from_ip(&data[16..]).map_err(|e| CaptureError::PacketDecode {
                        what: "IP from Linux SLL packet (manual fallback)",
                        source: Box::new(e),
                    })
                }
            }
        }
        DLT_RAW => SlicedPacket::from_ip(data).map_err(|e| CaptureError::PacketDecode {
            what: "raw IP packet",
            source: Box::new(e),
        }),
        DLT_LINUX_SLL2 => {
            // SLL2 has a 20-byte header; etherparse doesn't have a dedicated
            // parser, but the IP packet starts at offset 20. Detect IP version
            // from the first nibble of the IP header.
            if data.len() < 20 {
                return Err(CaptureError::TooShort {
                    what: "Linux SLL2 packet",
                    need: 20,
                    got: data.len(),
                });
            }
            SlicedPacket::from_ip(&data[20..]).map_err(|e| CaptureError::PacketDecode {
                what: "IP from Linux SLL2 packet",
                source: Box::new(e),
            })
        }
        other => Err(CaptureError::UnsupportedLinkType(other)),
    }
}

/// Parse a raw captured [`Packet`] into a [`ParsedPacket`].
///
/// Walks through link-layer, network, and transport headers based on
/// the packet's `link_type`. Handles:
/// - Ethernet II (DLT_EN10MB), including VLAN / QinQ
/// - Linux cooked capture (DLT_LINUX_SLL / SLL2)
/// - Raw IP (DLT_RAW)
/// - Encapsulation stripping: IP-in-IP (protocol 4), 6in4 (protocol 41),
///   and GRE (protocol 47)
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
            from_hep: true,
        });
    }

    let data = &packet.data;

    // First-pass parse based on link type
    let sliced = slice_link_layer(packet.link_type, data)?;

    // Extract IP-layer information
    let net = sliced
        .net
        .as_ref()
        .ok_or(CaptureError::NotIp { what: "packet" })?;

    // Check for encapsulation and handle recursively
    let ip_payload = net
        .ip_payload_ref()
        .ok_or(CaptureError::NoIpPayload { what: "packet" })?;

    let ip_number = ip_payload.ip_number;

    // IP-in-IP (protocol 4), 6in4 (protocol 41), or GRE (protocol 47) —
    // strip and re-parse. `parse_inner_ip` uses `SlicedPacket::from_ip`,
    // which detects the inner IP version, so it handles an inner IPv4
    // (IP-in-IP) and an inner IPv6 (6in4) alike.
    if (ip_number == IpNumber::IPV4 || ip_number == IpNumber::IPV6) && !ip_payload.fragmented {
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
///
/// # Arguments
///
/// * `timestamp` — capture time carried through from the outer packet.
/// * `data` — the original packet's refcounted buffer, used so the payload
///   can be sliced zero-copy.
/// * `ip_data` — the inner bytes starting at the inner IP header.
/// * `depth` — current encapsulation depth (0 for the first inner layer).
///
/// # Returns
///
/// The `ParsedPacket` for the innermost packet after stripping any further
/// IP-in-IP / GRE layers.
///
/// # Errors
///
/// Returns `EncapTooDeep` past `MAX_ENCAP_DEPTH`, or the decode/extraction
/// errors of the nested parse.
fn parse_inner_ip(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    ip_data: &[u8],
    depth: u8,
) -> Result<ParsedPacket, CaptureError> {
    if depth > MAX_ENCAP_DEPTH {
        return Err(CaptureError::EncapTooDeep {
            kind: "IP-in-IP",
            limit: MAX_ENCAP_DEPTH,
        });
    }

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

    if (ip_payload.ip_number == IpNumber::IPV4 || ip_payload.ip_number == IpNumber::IPV6)
        && !ip_payload.fragmented
    {
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
///
/// # Arguments
///
/// * `timestamp` — capture time carried through from the outer packet.
/// * `data` — the original packet's refcounted buffer for zero-copy slicing.
/// * `gre_data` — bytes starting at the GRE header.
/// * `depth` — current encapsulation depth (passed through unchanged to the
///   inner IP parse).
///
/// # Returns
///
/// The `ParsedPacket` for the packet carried inside the GRE tunnel.
///
/// # Errors
///
/// Returns `EncapTooDeep` past `MAX_ENCAP_DEPTH`, `TooShort` for a
/// truncated GRE header or optional fields, `UnsupportedGreProtocol` for a
/// non-IPv4/IPv6 payload type, or the nested parse's errors.
fn parse_gre(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    gre_data: &[u8],
    depth: u8,
) -> Result<ParsedPacket, CaptureError> {
    if depth > MAX_ENCAP_DEPTH {
        return Err(CaptureError::EncapTooDeep {
            kind: "GRE",
            limit: MAX_ENCAP_DEPTH,
        });
    }
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

    let inner = &gre_data[offset..];

    match protocol {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => parse_inner_ip(timestamp, data, inner, depth),
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
fn extract_parsed_packet(
    timestamp: DateTime<Utc>,
    data: &bytes::Bytes,
    net: &NetSlice<'_>,
    transport: &Option<TransportSlice<'_>>,
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
                hdr.protocol().0,
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
            from_hep: false,
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
            from_hep: false,
        });
    }

    // Transport header extraction
    let transport_slice = transport.as_ref().ok_or(CaptureError::NoTransport)?;

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
            from_hep: false,
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
            from_hep: false,
        }),
        TransportSlice::Icmpv4(_) | TransportSlice::Icmpv6(_) => Err(CaptureError::Icmp),
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

    /// A pre-parsed (HEP-listener-origin) packet is flagged `from_hep` so
    /// downstream active responses (scanner-kill) can refuse to trust its
    /// attacker-assertable addressing by default (SN-01).
    #[test]
    fn parse_packet_flags_pre_parsed_as_from_hep() {
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
        assert!(
            parse_packet(&pkt).unwrap().from_hep,
            "HEP-origin must be flagged"
        );
    }

    /// A normally captured (link/IP/transport) packet is NOT flagged
    /// `from_hep`, so scanner-kill remains eligible for live/pcap traffic.
    #[test]
    fn parse_packet_normal_capture_is_not_from_hep() {
        let data = build_eth_ipv4_udp(
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            5060,
            5060,
            b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n",
        );
        let pkt = make_packet(data, DLT_EN10MB);
        assert!(
            !parse_packet(&pkt).unwrap().from_hep,
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
}
