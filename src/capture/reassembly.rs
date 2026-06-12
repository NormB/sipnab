//! IP fragment and TCP segment reassembly.
//!
//! Provides [`FragmentReassembler`] for reassembling IP-fragmented packets and
//! [`TcpReassembler`] for reordering and flushing TCP byte streams. Both
//! enforce size limits, entry caps, and TTL-based eviction.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::parse::ParsedPacket;

// ── Constants ─────────────────────────────────────────────────────────

/// Maximum reassembled datagram size (64 KB, per IP spec).
const MAX_REASSEMBLED_SIZE: usize = 65535;

/// Default maximum number of tracked entries (fragments or TCP streams).
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default time-to-live for incomplete entries before eviction.
const DEFAULT_TTL: Duration = Duration::from_secs(30);

/// Maximum TCP stream buffer size before forced flush (64 KB).
const MAX_TCP_BUFFER: usize = 65536;

// ═══════════════════════════════════════════════════════════════════════
// IP Fragment Reassembly
// ═══════════════════════════════════════════════════════════════════════

/// Key identifying a unique IP datagram for fragment reassembly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    src: IpAddr,
    dst: IpAddr,
    ip_id: u16,
    protocol: u8,
}

/// State for an in-progress fragment reassembly.
struct FragmentEntry {
    /// Collected fragments: (byte offset, data).
    fragments: Vec<(usize, Vec<u8>)>,
    /// Total datagram length, known once the final fragment arrives.
    total_len: Option<usize>,
    /// When this entry was created (for TTL eviction).
    created: Instant,
}

/// Reassembles IP-fragmented packets into complete datagrams.
///
/// Fragments are tracked by (src, dst, ip_id, protocol). The reassembler
/// enforces a maximum entry count, a per-entry TTL, a maximum reassembled
/// size of 64 KB, and detects overlapping fragments as an evasion indicator.
pub struct FragmentReassembler {
    entries: HashMap<FragmentKey, FragmentEntry>,
    max_entries: usize,
    ttl: Duration,
}

impl FragmentReassembler {
    /// Create a new fragment reassembler with default limits.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
            ttl: DEFAULT_TTL,
        }
    }

    /// Create a new fragment reassembler with custom limits.
    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            ttl,
        }
    }

    /// Insert a fragment from a parsed packet.
    ///
    /// Returns `Some(reassembled_payload)` when all fragments for the
    /// datagram have been received and reassembled. Returns `None` if
    /// more fragments are still expected.
    ///
    /// # Behavior
    ///
    /// - Overlapping fragments cause the entire entry to be dropped (evasion detection).
    /// - Reassembled size exceeding 64 KB causes the entry to be dropped.
    /// - When the entry cap is reached, the oldest entry is evicted.
    pub fn insert(&mut self, parsed: &ParsedPacket) -> Option<Vec<u8>> {
        let ip_id = parsed.ip_id?;
        let frag_offset = parsed.fragment_offset.unwrap_or(0);
        // Fragment offset field is in units of 8 bytes
        let byte_offset = frag_offset as usize * 8;

        let key = FragmentKey {
            src: parsed.src_addr,
            dst: parsed.dst_addr,
            ip_id,
            protocol: parsed.ip_protocol,
        };

        // Enforce max entries: evict oldest if full
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| FragmentEntry {
                fragments: Vec::new(),
                total_len: None,
                created: Instant::now(),
            });

        // Check for overlapping fragments
        for (existing_offset, existing_data) in &entry.fragments {
            let existing_end = *existing_offset + existing_data.len();
            let new_end = byte_offset + parsed.payload.len();

            // Overlap detection: ranges [existing_offset..existing_end) and [byte_offset..new_end)
            if byte_offset < existing_end && new_end > *existing_offset {
                tracing::warn!(
                    "Overlapping IP fragment detected (id={ip_id}, src={}, dst={}); \
                     dropping all fragments for this datagram (possible evasion)",
                    parsed.src_addr,
                    parsed.dst_addr,
                );
                self.entries.remove(&key);
                return None;
            }
        }

        // Store this fragment
        entry.fragments.push((byte_offset, parsed.payload.clone()));

        // If MF=0 (no more fragments), we can compute the total length
        if !parsed.more_fragments {
            entry.total_len = Some(byte_offset + parsed.payload.len());
        }

        // Check if reassembly is complete
        let total_len = entry.total_len?;

        // Safety check: refuse to reassemble datagrams > 64KB
        if total_len > MAX_REASSEMBLED_SIZE {
            tracing::warn!(
                "Oversized reassembled datagram ({total_len} bytes > {MAX_REASSEMBLED_SIZE}); \
                 dropping (id={ip_id}, src={}, dst={})",
                parsed.src_addr,
                parsed.dst_addr,
            );
            self.entries.remove(&key);
            return None;
        }

        // Sort fragments by offset and check contiguity
        let mut sorted: Vec<&(usize, Vec<u8>)> = entry.fragments.iter().collect();
        sorted.sort_by_key(|(off, _)| *off);

        let mut cursor = 0;
        for (off, data) in &sorted {
            if *off != cursor {
                // Gap: not all fragments received yet
                return None;
            }
            cursor += data.len();
        }

        if cursor != total_len {
            return None;
        }

        // All fragments present — reassemble
        let mut reassembled = vec![0u8; total_len];
        for (off, data) in &sorted {
            reassembled[*off..*off + data.len()].copy_from_slice(data);
        }

        tracing::debug!(
            "Reassembled IP datagram: id={ip_id}, {} -> {}, {total_len} bytes",
            parsed.src_addr,
            parsed.dst_addr,
        );

        self.entries.remove(&key);
        Some(reassembled)
    }

    /// Evict entries older than the configured TTL.
    ///
    /// Should be called periodically (e.g., every 5 seconds) from the main loop.
    pub fn sweep(&mut self) {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_key, entry| now.duration_since(entry.created) < self.ttl);
        let evicted = before - self.entries.len();
        if evicted > 0 {
            tracing::debug!("Fragment reassembler: swept {evicted} stale entries");
        }
    }

    /// Number of tracked fragment entries (for diagnostics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the reassembler has no tracked entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the oldest entries (a batch of cap/100) when the cap is
    /// reached. One-at-a-time eviction cost an O(n) min-scan plus a
    /// warn! line per incoming fragment at capacity — a CPU-DoS and log
    /// flood under a deliberate fragment flood. One sort per batch is
    /// amortized across the next cap/100 inserts, and one summary line
    /// replaces per-fragment spam.
    fn evict_oldest(&mut self) {
        let batch = (self.max_entries / 100).max(1).min(self.entries.len());
        let mut by_age: Vec<(Instant, FragmentKey)> = self
            .entries
            .iter()
            .map(|(k, e)| (e.created, k.clone()))
            .collect();
        by_age.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (_, key) in by_age.into_iter().take(batch) {
            self.entries.remove(&key);
        }
        tracing::warn!(
            "Fragment reassembler at capacity ({}); evicted {batch} oldest \
             entries (possible fragment flood)",
            self.max_entries,
        );
    }
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TCP Segment Reassembly
// ═══════════════════════════════════════════════════════════════════════

/// Key identifying a TCP stream direction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpStreamKey {
    src: SocketAddr,
    dst: SocketAddr,
}

/// State for a tracked TCP stream.
struct TcpStream {
    /// Next expected sequence number.
    expected_seq: u32,
    /// Out-of-order segment buffer, keyed by sequence number.
    buffer: BTreeMap<u32, Vec<u8>>,
    /// When this stream was first seen.
    #[allow(dead_code)]
    created: Instant,
    /// When the last segment was received.
    last_seen: Instant,
    /// Total buffered bytes (for overflow detection).
    buffered_bytes: usize,
    /// Whether the initial sequence number has been set.
    initialized: bool,
    /// Whether a SYN was seen (meaning expected_seq is authoritative).
    syn_seen: bool,
}

/// Reassembles TCP segments into ordered byte streams.
///
/// Tracks individual TCP stream directions (src -> dst) and buffers
/// out-of-order segments. Flushes reassembled data on PSH flag,
/// connection close (FIN/RST), or buffer overflow.
pub struct TcpReassembler {
    streams: HashMap<TcpStreamKey, TcpStream>,
    max_entries: usize,
    ttl: Duration,
}

impl TcpReassembler {
    /// Create a new TCP reassembler with default limits.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
            ttl: DEFAULT_TTL,
        }
    }

    /// Create a new TCP reassembler with custom limits.
    pub fn with_limits(max_entries: usize, ttl: Duration) -> Self {
        Self {
            streams: HashMap::new(),
            max_entries,
            ttl,
        }
    }

    /// Insert a TCP segment and return any flushed payloads.
    ///
    /// Returns a `Vec` of reassembled byte chunks. This may be:
    /// - Empty (segment buffered, waiting for more)
    /// - One entry (normal flush on PSH/FIN)
    /// - Multiple entries (if buffer overflow triggers partial flushes)
    ///
    /// # Behavior
    ///
    /// - **PSH flag:** flushes all buffered in-order data.
    /// - **FIN flag:** flushes remaining data and removes the stream.
    /// - **RST flag:** discards the stream entirely (returns empty).
    /// - **Buffer overflow (>64 KB):** forces a flush.
    /// - **SYN flag:** initializes or resets the stream's expected sequence.
    pub fn insert(&mut self, parsed: &ParsedPacket) -> Vec<Vec<u8>> {
        let flags = match &parsed.tcp_flags {
            Some(f) => f,
            None => return Vec::new(),
        };
        let seq = match parsed.tcp_seq {
            Some(s) => s,
            None => return Vec::new(),
        };

        let key = TcpStreamKey {
            src: SocketAddr::new(parsed.src_addr, parsed.src_port),
            dst: SocketAddr::new(parsed.dst_addr, parsed.dst_port),
        };

        // RST: discard the stream entirely
        if flags.rst {
            if self.streams.remove(&key).is_some() {
                tracing::debug!("TCP RST: discarded stream {} -> {}", key.src, key.dst,);
            }
            return Vec::new();
        }

        // Enforce max entries
        if !self.streams.contains_key(&key) && self.streams.len() >= self.max_entries {
            self.evict_oldest();
        }

        let stream = self
            .streams
            .entry(key.clone())
            .or_insert_with(|| TcpStream {
                expected_seq: seq,
                buffer: BTreeMap::new(),
                created: Instant::now(),
                last_seen: Instant::now(),
                buffered_bytes: 0,
                initialized: false,
                syn_seen: false,
            });

        stream.last_seen = Instant::now();

        // SYN: (re)initialize expected sequence
        if flags.syn {
            // SYN consumes one sequence number; data starts at seq+1
            stream.expected_seq = seq.wrapping_add(1);
            stream.initialized = true;
            stream.syn_seen = true;
            stream.buffer.clear();
            stream.buffered_bytes = 0;
            // SYN packets typically have no payload
            if parsed.payload.is_empty() {
                return Vec::new();
            }
        }

        // If stream not initialized (missed the SYN), use first segment's seq
        if !stream.initialized {
            stream.expected_seq = seq;
            stream.initialized = true;
        }

        // If we see a segment earlier than expected_seq and we never saw a SYN,
        // the stream's initial expected_seq was a guess from the first segment
        // we received (which may not have been the lowest). Adjust downward so
        // we can assemble from the true beginning.
        if !parsed.payload.is_empty() && seq < stream.expected_seq && !stream.syn_seen {
            stream.expected_seq = seq;
        }

        // Buffer the segment (skip empty payloads from pure ACKs)
        if !parsed.payload.is_empty() {
            stream.buffered_bytes += parsed.payload.len();
            stream.buffer.insert(seq, parsed.payload.clone());
        }

        let mut results = Vec::new();

        // FIN: flush everything and remove stream
        if flags.fin {
            let flushed = self.drain_in_order(&key);
            if !flushed.is_empty() {
                results.push(flushed);
            }
            self.streams.remove(&key);
            return results;
        }

        // Buffer overflow: force flush
        if stream.buffered_bytes > MAX_TCP_BUFFER {
            let flushed = self.drain_in_order(&key);
            if !flushed.is_empty() {
                tracing::debug!(
                    "TCP buffer overflow flush: {} -> {} ({} bytes)",
                    key.src,
                    key.dst,
                    flushed.len(),
                );
                results.push(flushed);
            }
            return results;
        }

        // PSH: flush in-order data
        if flags.psh {
            let flushed = self.drain_in_order(&key);
            if !flushed.is_empty() {
                results.push(flushed);
            }
        }

        results
    }

    /// Drain consecutive in-order segments from a stream's buffer.
    ///
    /// Returns the concatenated payload of all segments starting from
    /// `expected_seq`, advancing it past each drained segment.
    fn drain_in_order(&mut self, key: &TcpStreamKey) -> Vec<u8> {
        let stream = match self.streams.get_mut(key) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let mut result = Vec::new();

        while let Some((&next, _)) = stream.buffer.first_key_value() {
            if next == stream.expected_seq {
                // This is an in-order segment — consume it
                let data = match stream.buffer.remove(&next) {
                    Some(d) => d,
                    None => break,
                };
                stream.expected_seq = stream.expected_seq.wrapping_add(data.len() as u32);
                stream.buffered_bytes = stream.buffered_bytes.saturating_sub(data.len());
                result.extend_from_slice(&data);
            } else if next < stream.expected_seq {
                // Retransmit or duplicate — skip it
                let data = match stream.buffer.remove(&next) {
                    Some(d) => d,
                    None => break,
                };
                stream.buffered_bytes = stream.buffered_bytes.saturating_sub(data.len());
            } else {
                // Gap — waiting for missing segment
                break;
            }
        }

        result
    }

    /// Evict TCP stream entries older than the configured TTL.
    ///
    /// Should be called periodically (e.g., every 5 seconds) from the main loop.
    pub fn sweep(&mut self) {
        let now = Instant::now();
        let before = self.streams.len();
        self.streams
            .retain(|_key, stream| now.duration_since(stream.last_seen) < self.ttl);
        let evicted = before - self.streams.len();
        if evicted > 0 {
            tracing::debug!("TCP reassembler: swept {evicted} stale streams");
        }
    }

    /// Number of tracked TCP streams (for diagnostics).
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether the reassembler has no tracked streams.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Evict the oldest streams (a batch of cap/100) when the cap is
    /// reached — same amortization and log-flood rationale as
    /// [`FragmentReassembler::evict_oldest`].
    fn evict_oldest(&mut self) {
        let batch = (self.max_entries / 100).max(1).min(self.streams.len());
        let mut by_age: Vec<(Instant, TcpStreamKey)> = self
            .streams
            .iter()
            .map(|(k, s)| (s.last_seen, k.clone()))
            .collect();
        by_age.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        for (_, key) in by_age.into_iter().take(batch) {
            self.streams.remove(&key);
        }
        tracing::warn!(
            "TCP reassembler at capacity ({}); evicted {batch} oldest \
             streams (possible connection flood)",
            self.max_entries,
        );
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::{TcpFlags, TransportProto};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper to build a fragment ParsedPacket.
    fn make_fragment(
        src: IpAddr,
        dst: IpAddr,
        ip_id: u16,
        offset: u16, // in 8-byte units
        more_fragments: bool,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            timestamp: Utc::now(),
            src_addr: src,
            dst_addr: dst,
            src_port: 0,
            dst_port: 0,
            transport: TransportProto::Udp,
            payload: payload.to_vec(),
            ip_id: Some(ip_id),
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: Some(offset),
            more_fragments,
            ip_protocol: 17, // UDP
        }
    }

    /// Helper to build a TCP segment ParsedPacket.
    fn make_tcp_segment(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> ParsedPacket {
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        ParsedPacket {
            timestamp: Utc::now(),
            src_addr: src,
            dst_addr: dst,
            src_port,
            dst_port,
            transport: TransportProto::Tcp,
            payload: payload.to_vec(),
            ip_id: None,
            tcp_seq: Some(seq),
            tcp_flags: Some(flags),
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 6, // TCP
        }
    }

    fn default_tcp_flags() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        }
    }

    /// At large caps, eviction is batched (cap/100 at a time): the old
    /// one-at-a-time eviction did an O(n) min-scan PLUS a warn! line per
    /// incoming fragment once at capacity — a CPU-DoS and log flood
    /// under a deliberate fragment flood.
    #[test]
    fn fragment_eviction_batches_at_large_cap() {
        let mut r = FragmentReassembler::with_limits(1000, DEFAULT_TTL);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        for i in 0..1001u16 {
            // Unique ip_id per fragment → unique reassembly key.
            let f = make_fragment(src, dst, i, 0, true, &[0xAA; 8]);
            r.insert(&f);
            assert!(r.len() <= 1000, "cap is a hard upper bound");
        }
        assert_eq!(
            r.len(),
            991,
            "1001st insert evicts a batch of cap/100 = 10, then inserts"
        );
    }

    #[test]
    fn tcp_eviction_batches_at_large_cap() {
        let mut r = TcpReassembler::with_limits(1000, DEFAULT_TTL);
        for i in 0..1001u16 {
            // Unique src_port per segment → unique stream key.
            let seg = make_tcp_segment(10000 + i, 5060, 1, default_tcp_flags(), b"x");
            r.insert(&seg);
            assert!(r.len() <= 1000, "cap is a hard upper bound");
        }
        assert_eq!(
            r.len(),
            991,
            "1001st insert evicts a batch of cap/100 = 10, then inserts"
        );
    }

    // ── Fragment reassembly tests ─────────────────────────────────────

    #[test]
    fn fragment_two_pieces_reassembled() {
        let mut r = FragmentReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // First fragment: offset=0, MF=1, 16 bytes
        let frag1 = make_fragment(src, dst, 42, 0, true, &[0xAA; 16]);
        assert!(r.insert(&frag1).is_none());

        // Second fragment: offset=2 (2*8=16 bytes), MF=0, 8 bytes
        let frag2 = make_fragment(src, dst, 42, 2, false, &[0xBB; 8]);
        let result = r.insert(&frag2).expect("should reassemble");

        assert_eq!(result.len(), 24);
        assert_eq!(&result[..16], &[0xAA; 16]);
        assert_eq!(&result[16..], &[0xBB; 8]);
        assert!(r.is_empty());
    }

    #[test]
    fn fragment_out_of_order() {
        let mut r = FragmentReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Send last fragment first
        let frag2 = make_fragment(src, dst, 99, 2, false, &[0xBB; 8]);
        assert!(r.insert(&frag2).is_none());

        // Then the first fragment
        let frag1 = make_fragment(src, dst, 99, 0, true, &[0xAA; 16]);
        let result = r.insert(&frag1).expect("should reassemble out-of-order");

        assert_eq!(result.len(), 24);
        assert_eq!(&result[..16], &[0xAA; 16]);
        assert_eq!(&result[16..], &[0xBB; 8]);
    }

    #[test]
    fn fragment_overlapping_dropped() {
        let mut r = FragmentReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // First fragment: offset=0, 16 bytes (covers bytes 0-15)
        let frag1 = make_fragment(src, dst, 55, 0, true, &[0xAA; 16]);
        assert!(r.insert(&frag1).is_none());

        // Overlapping fragment: offset=1 (byte 8), overlaps bytes 8-15
        let frag2 = make_fragment(src, dst, 55, 1, false, &[0xBB; 16]);
        assert!(r.insert(&frag2).is_none());

        // Entry should be gone
        assert!(r.is_empty());
    }

    #[test]
    fn fragment_timeout_evicted() {
        let mut r = FragmentReassembler::with_limits(100, Duration::from_millis(50));
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let frag1 = make_fragment(src, dst, 77, 0, true, &[0xAA; 8]);
        assert!(r.insert(&frag1).is_none());
        assert_eq!(r.len(), 1);

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(60));
        r.sweep();

        assert!(r.is_empty(), "stale entry should have been swept");
    }

    #[test]
    fn fragment_oversized_dropped() {
        let mut r = FragmentReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // First fragment at offset 0
        let frag1 = make_fragment(src, dst, 88, 0, true, &[0xAA; 8]);
        assert!(r.insert(&frag1).is_none());

        // "Last" fragment claiming the datagram is > 64KB
        // offset = 8192 (8192*8 = 65536), 8 bytes payload => total = 65544
        let frag2 = make_fragment(src, dst, 88, 8192, false, &[0xBB; 8]);
        assert!(r.insert(&frag2).is_none());

        // Entry should be dropped
        assert!(r.is_empty());
    }

    #[test]
    fn fragment_max_entries_evicts_oldest() {
        let mut r = FragmentReassembler::with_limits(2, DEFAULT_TTL);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Fill to capacity
        let f1 = make_fragment(src, dst, 1, 0, true, &[0xAA; 8]);
        r.insert(&f1);
        let f2 = make_fragment(src, dst, 2, 0, true, &[0xBB; 8]);
        r.insert(&f2);
        assert_eq!(r.len(), 2);

        // Adding a third should evict the oldest
        let f3 = make_fragment(src, dst, 3, 0, true, &[0xCC; 8]);
        r.insert(&f3);
        assert_eq!(r.len(), 2, "should stay at capacity after eviction");
    }

    // ── TCP reassembly tests ─────────────────────────────────────────

    #[test]
    fn tcp_in_order_with_psh() {
        let mut r = TcpReassembler::new();

        // First segment: data
        let seg1 = make_tcp_segment(5060, 5061, 100, default_tcp_flags(), b"INVITE ");
        assert!(r.insert(&seg1).is_empty());

        // Second segment with PSH: triggers flush
        let mut flags = default_tcp_flags();
        flags.psh = true;
        let seg2 = make_tcp_segment(5060, 5061, 107, flags, b"sip:bob@ex");
        let result = r.insert(&seg2);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"INVITE sip:bob@ex");
    }

    #[test]
    fn tcp_out_of_order_reordered() {
        let mut r = TcpReassembler::new();

        // Send second segment first (out of order)
        let seg2 = make_tcp_segment(5060, 5061, 105, default_tcp_flags(), b"world");
        assert!(r.insert(&seg2).is_empty());

        // Send first segment with PSH to trigger flush
        let mut flags = default_tcp_flags();
        flags.psh = true;
        let seg1 = make_tcp_segment(5060, 5061, 100, flags, b"hello");
        let result = r.insert(&seg1);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"helloworld");
    }

    #[test]
    fn tcp_fin_flushes_remaining() {
        let mut r = TcpReassembler::new();

        let seg1 = make_tcp_segment(5060, 5061, 100, default_tcp_flags(), b"data");
        assert!(r.insert(&seg1).is_empty());

        // FIN triggers flush and removes stream
        let mut flags = default_tcp_flags();
        flags.fin = true;
        let seg2 = make_tcp_segment(5060, 5061, 104, flags, b"end");
        let result = r.insert(&seg2);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"dataend");
        assert!(r.is_empty(), "stream should be removed after FIN");
    }

    #[test]
    fn tcp_rst_discards_stream() {
        let mut r = TcpReassembler::new();

        let seg1 = make_tcp_segment(5060, 5061, 100, default_tcp_flags(), b"data");
        r.insert(&seg1);
        assert_eq!(r.len(), 1);

        // RST: discard everything, return nothing
        let mut flags = default_tcp_flags();
        flags.rst = true;
        let seg2 = make_tcp_segment(5060, 5061, 104, flags, b"");
        let result = r.insert(&seg2);

        assert!(result.is_empty());
        assert!(r.is_empty(), "stream should be discarded on RST");
    }

    #[test]
    fn tcp_timeout_evicted() {
        let mut r = TcpReassembler::with_limits(100, Duration::from_millis(50));

        let seg = make_tcp_segment(5060, 5061, 100, default_tcp_flags(), b"hello");
        r.insert(&seg);
        assert_eq!(r.len(), 1);

        std::thread::sleep(Duration::from_millis(60));
        r.sweep();
        assert!(r.is_empty(), "stale stream should be swept");
    }

    #[test]
    fn tcp_max_entries_evicts_oldest() {
        let mut r = TcpReassembler::with_limits(2, DEFAULT_TTL);

        // Stream 1
        let s1 = make_tcp_segment(1000, 2000, 100, default_tcp_flags(), b"a");
        r.insert(&s1);
        // Stream 2 (different ports)
        let s2 = make_tcp_segment(3000, 4000, 200, default_tcp_flags(), b"b");
        r.insert(&s2);
        assert_eq!(r.len(), 2);

        // Stream 3 should evict the oldest
        let s3 = make_tcp_segment(5000, 6000, 300, default_tcp_flags(), b"c");
        r.insert(&s3);
        assert_eq!(r.len(), 2);
    }
}
