//! Core packet type for sipnab.
//!
//! [`Packet`] represents a single captured network packet with metadata
//! including timestamp, raw bytes, capture/original lengths, source interface,
//! and link-layer type.

use chrono::{DateTime, Utc};
use std::net::IpAddr;

/// Pre-parsed addressing metadata for packets that arrive from a source
/// which already knows the inner addresses (e.g. a HEP listener that
/// reads `src_addr` / `dst_addr` from HEP chunks). When present, the
/// parser short-circuits the link/IP/transport header walk and produces
/// a parsed packet directly from this metadata plus the payload bytes.
#[derive(Debug, Clone)]
pub struct PreParsed {
    /// Source IP address.
    pub src_addr: IpAddr,
    /// Destination IP address.
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// IANA IP protocol number (17 = UDP, 6 = TCP, 132 = SCTP).
    pub ip_protocol: u8,
}

/// A captured network packet with metadata.
///
/// Carries the raw bytes from the link layer along with timing and source
/// information needed for downstream parsing and output. When `pre_parsed`
/// is `Some`, `data` is the inner transport-layer payload only and the
/// parser should not attempt to walk link/IP/transport headers.
#[derive(Debug, Clone)]
pub struct Packet {
    /// When the packet was captured (UTC).
    pub timestamp: DateTime<Utc>,
    /// Raw packet bytes (refcounted; payload slices view this buffer).
    /// Starts at the link layer when `pre_parsed` is `None`; is the
    /// transport-layer payload only when `pre_parsed` is `Some`.
    pub data: bytes::Bytes,
    /// Number of bytes actually captured (may be less than `origlen`).
    pub caplen: usize,
    /// Original length of the packet on the wire.
    pub origlen: usize,
    /// Name of the capture interface, if from a live source.
    pub interface: Option<String>,
    /// Pcap link-layer header type (e.g., `1` for `DLT_EN10MB`). Ignored
    /// when `pre_parsed` is `Some`.
    pub link_type: i32,
    /// Pre-parsed addressing metadata when the packet's source already
    /// knows the inner addresses (e.g. HEP listener). When `Some`, the
    /// parser uses this directly and `data` is the transport payload.
    pub pre_parsed: Option<PreParsed>,
}

impl Packet {
    /// Create a new packet from raw capture data starting at the link layer.
    pub fn new(
        timestamp: DateTime<Utc>,
        data: Vec<u8>,
        caplen: usize,
        origlen: usize,
        interface: Option<String>,
        link_type: i32,
    ) -> Self {
        Self {
            timestamp,
            data: data.into(),
            caplen,
            origlen,
            interface,
            link_type,
            pre_parsed: None,
        }
    }

    /// Create a new packet whose addressing is already known from its
    /// source (e.g. a HEP listener that reads addresses from HEP chunks).
    /// `data` is the transport-layer payload only — no link/IP/transport
    /// headers. The parser short-circuits to produce a parsed packet
    /// directly from `pre_parsed` + `data`.
    pub fn with_pre_parsed(
        timestamp: DateTime<Utc>,
        data: Vec<u8>,
        interface: Option<String>,
        pre_parsed: PreParsed,
    ) -> Self {
        let len = data.len();
        Self {
            timestamp,
            data: data.into(),
            caplen: len,
            origlen: len,
            interface,
            link_type: 0,
            pre_parsed: Some(pre_parsed),
        }
    }
}
