// SPDX-License-Identifier: MIT OR Apache-2.0

//! Core packet type for sipnab.
//!
//! [`Packet`] represents a single captured network packet with metadata
//! including timestamp, raw bytes, capture/original lengths, source interface,
//! and link-layer type.

use chrono::{DateTime, Utc};
use std::net::IpAddr;
use std::sync::Arc;

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
    /// Where this packet came from: the capture device for live capture, the
    /// capture FILE for replay, the listener address for HEP. `None` only for
    /// sources that genuinely have no identity (synthetic packets).
    ///
    /// This is what the pcapng writer turns into an Interface Description
    /// Block, so it is the export's claim about the packet's origin — see
    /// [`crate::capture::writer::PcapWriter::write`].
    ///
    /// `Arc<str>` rather than `String` because the value is CONSTANT for the
    /// whole of a source and is stamped on every packet: a 14M-packet replay
    /// interns the path once per file and pays a refcount increment per
    /// packet, where an owned `String` would be 14M allocations of the same
    /// bytes. Cloning is cheap enough that no hot path has an excuse to skip
    /// the stamp; construct with [`Packet::with_source`] to reuse the handle.
    pub interface: Option<Arc<str>>,
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
    ///
    /// Pure constructor: converts `data` into refcounted `bytes::Bytes` and
    /// leaves `pre_parsed` as `None`, so the parser walks the full
    /// link/IP/transport header chain.
    ///
    /// # Arguments
    ///
    /// * `timestamp` — capture time of the packet (UTC).
    /// * `data` — raw packet bytes beginning at the link layer.
    /// * `caplen` — number of bytes actually captured (may be < `origlen`
    ///   when the capture used a snap length).
    /// * `origlen` — original on-the-wire length of the packet in bytes.
    /// * `interface` — name of the source this packet came from, if known.
    /// * `link_type` — pcap link-layer header type (e.g. 1 = `DLT_EN10MB`).
    ///
    /// # Returns
    ///
    /// A `Packet` whose `data` starts at the link layer.
    pub fn new(
        timestamp: DateTime<Utc>,
        data: Vec<u8>,
        caplen: usize,
        origlen: usize,
        interface: Option<String>,
        link_type: i32,
    ) -> Self {
        Self::with_source(
            timestamp,
            data,
            caplen,
            origlen,
            interface.map(Arc::from),
            link_type,
        )
    }

    /// As [`new`](Self::new), but takes an already-interned source handle.
    ///
    /// The source name is the same string for every packet of a capture file
    /// or device, so a reader interns it once and clones the handle per
    /// packet — a refcount increment instead of an allocation. Use this on
    /// any path that stamps a source onto a whole stream;
    /// [`new`](Self::new) is the convenience wrapper for the one-off callers
    /// that already hold a `String`.
    ///
    /// # Arguments
    ///
    /// * `timestamp` — capture time of the packet (UTC).
    /// * `data` — raw packet bytes beginning at the link layer.
    /// * `caplen` — number of bytes actually captured (may be < `origlen`).
    /// * `origlen` — original on-the-wire length of the packet in bytes.
    /// * `source` — interned name of the device/file/listener it came from.
    /// * `link_type` — pcap link-layer header type (e.g. 1 = `DLT_EN10MB`).
    ///
    /// # Returns
    ///
    /// A `Packet` whose `data` starts at the link layer.
    pub fn with_source(
        timestamp: DateTime<Utc>,
        data: Vec<u8>,
        caplen: usize,
        origlen: usize,
        source: Option<Arc<str>>,
        link_type: i32,
    ) -> Self {
        // `data` holds exactly the captured bytes, so `caplen` must equal
        // `data.len()` (snap-length truncation shortens `data` too; only
        // `origlen` may exceed it). Catch a desynced caller in debug builds
        // without changing release behavior.
        debug_assert_eq!(
            caplen,
            data.len(),
            "Packet::with_source: caplen ({caplen}) must equal data.len() ({})",
            data.len(),
        );
        Self {
            timestamp,
            data: data.into(),
            caplen,
            origlen,
            interface: source,
            link_type,
            pre_parsed: None,
        }
    }

    /// Create a new packet whose addressing is already known from its
    /// source (e.g. a HEP listener that reads addresses from HEP chunks).
    /// `data` is the transport-layer payload only — no link/IP/transport
    /// headers. The parser short-circuits to produce a parsed packet
    /// directly from `pre_parsed` + `data`.
    ///
    /// # Arguments
    ///
    /// * `timestamp` — capture time of the packet (UTC).
    /// * `data` — transport-layer payload bytes only (e.g. the SIP message).
    /// * `interface` — logical source name (e.g. `"hep:0.0.0.0:9060"`).
    /// * `pre_parsed` — addressing metadata supplied by the source.
    ///
    /// # Returns
    ///
    /// A `Packet` with `caplen`/`origlen` both set to `data.len()`,
    /// `link_type` set to 0 (ignored on this path), and `pre_parsed`
    /// populated so the parser skips the header walk.
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
            interface: interface.map(Arc::from),
            link_type: 0,
            pre_parsed: Some(pre_parsed),
        }
    }
}
