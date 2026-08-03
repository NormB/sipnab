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

/// Where in its source a packet was read from.
///
/// Half of a provenance pointer. The other half is [`Packet::interface`],
/// which names the source — together they identify one frame, and
/// [`Packet::frame_ref`] pairs them.
///
/// # Why the ordinal is per source, not per run
///
/// A frame's identity is the file it lives in plus its position in that file.
/// Counting across the whole run instead would give the same bytes a different
/// name depending on how the run was invoked: frame 40 of `b.pcap` would be
/// "packet 4,212" when `a.pcap` was read first and "packet 40" when it was
/// read alone. A pointer that changes with the command line cannot be compared
/// between two runs, which is the one thing a provenance pointer is for.
///
/// `read_opened_inner` keeps this counter separately from the run-global one
/// it already threads through for `--count` and the summary line, because
/// those two answer different questions and only one of them resets per file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameOrigin {
    /// 0-based position of this frame within its source.
    pub ordinal: u64,
    /// Digest of the frame's bytes as they were read, when one was computed.
    ///
    /// This is what lets a resolver tell "here is your frame" apart from "the
    /// capture changed under you". Following a pointer to the WRONG frame is
    /// worse than not following it at all — it manufactures confidence, the
    /// same way the pcapng writer naming the wrong input file did — so a
    /// resolver holding a digest that does not match must refuse rather than
    /// return bytes.
    ///
    /// `None` when the run did not compute one. A resolver must then say the
    /// frame is UNVERIFIED rather than implying it checked.
    pub digest: Option<u64>,
}

/// FNV-1a over a frame's bytes.
///
/// Deliberately not `DefaultHasher`: its output is explicitly not guaranteed
/// stable across Rust releases, and a digest that changes when the toolchain
/// changes would make every stored pointer unverifiable after an upgrade —
/// silently, and in the direction that refuses valid frames. FNV-1a is fixed
/// by its specification, so a digest written today still means the same thing
/// to a build from next year.
///
/// Not cryptographic, and does not need to be. It answers "did these bytes
/// change", not "did someone change these bytes on purpose".
#[must_use]
pub fn frame_digest(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A resolvable pointer to the bytes a fact came from.
///
/// Produced by [`Packet::frame_ref`]. Rendered as `<source>#<ordinal>`, which
/// is the form that appears in output and the form a resolver accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRef {
    /// The source the frame was read from — a capture file path for replay,
    /// a device name for live capture, a listener address for HEP.
    pub source: Arc<str>,
    /// Where in that source it sat.
    pub origin: FrameOrigin,
}

impl std::fmt::Display for FrameRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.source, self.origin.ordinal)
    }
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
    /// Where in [`Packet::interface`] this frame sat.
    ///
    /// `None` for sources that cannot number their frames, and for synthetic
    /// packets that were never read from anything. A `None` here is not a
    /// gap to be filled in later by a downstream guess: a fact built from a
    /// packet with no origin has no provenance, and must say so rather than
    /// borrow the previous packet's.
    pub origin: Option<FrameOrigin>,
}

impl Packet {
    /// This packet's provenance pointer, when it has one.
    ///
    /// Requires BOTH halves. A source with no ordinal cannot name a frame, and
    /// an ordinal with no source does not say which file it counts within — so
    /// either alone is unresolvable, and returning it would be the fabrication
    /// this whole mechanism exists to prevent.
    pub fn frame_ref(&self) -> Option<FrameRef> {
        Some(FrameRef {
            source: Arc::clone(self.interface.as_ref()?),
            origin: (self.origin)?,
        })
    }

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
            origin: None,
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
            origin: None,
        }
    }
}
