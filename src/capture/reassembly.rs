// SPDX-License-Identifier: MIT OR Apache-2.0

//! IP fragment and TCP segment reassembly.
//!
//! Provides [`FragmentReassembler`] for reassembling IP-fragmented packets and
//! [`TcpReassembler`] for reordering and flushing TCP byte streams. Both
//! enforce size limits, entry caps, and TTL-based eviction.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::parse::ParsedPacket;

// ── Timeout counter ───────────────────────────────────────────────────

/// Reassembly entries dropped because they aged past their TTL, exported as
/// `sipnab_reassembly_timeouts_total`.
///
/// Process-global: both reassemblers feed it, every capture thread has its
/// own pair, and a scrape asks about the capture rather than about one
/// [`FragmentReassembler`]. Capacity evictions are deliberately NOT counted
/// here — those say the cap is too small, not that a peer stopped sending,
/// and they already warn.
static REASSEMBLY_TIMEOUTS: AtomicU64 = AtomicU64::new(0);

/// Reassembly entries timed out since start — the value behind
/// `sipnab_reassembly_timeouts_total`.
///
/// Counts IP fragments whose datagram never completed and TCP streams that
/// went idle, both dropped by a `sweep` once older than the TTL.
///
/// # Returns
///
/// Monotonic count of entries evicted by TTL across both reassemblers.
pub fn reassembly_timeouts() -> u64 {
    REASSEMBLY_TIMEOUTS.load(Ordering::Relaxed)
}

// ── Constants ─────────────────────────────────────────────────────────

/// Maximum reassembled datagram size (64 KB, per IP spec).
const MAX_REASSEMBLED_SIZE: usize = 65535;

/// Default maximum number of tracked entries (fragments or TCP streams).
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default time-to-live for incomplete entries before eviction.
///
/// `pub` because the only production constructor for a reassembler,
/// `PacketProcessor::with_max_sessions`, sits in `capture::mod` and used to
/// pass its own inline `Duration::from_secs(30)`. Two spellings of one policy
/// that happened to agree — changing this constant would have moved the
/// default everywhere EXCEPT the path every live capture actually takes.
///
/// Thirty seconds describes an IP datagram whose fragments are in flight, and
/// the TCP reassembler inherited it. Those are not the same wait. A persistent
/// SIP/TLS trunk to a carrier is idle for far longer than thirty seconds on any
/// quiet night, and sweeping its half-read stream means the next segment
/// re-initializes MID-MESSAGE: the message it lands in the middle of parses as
/// malformed, and the peer that sent a perfectly good one is the peer reported
/// broken. `--max-reassembly` bounds how MANY entries are held and says nothing
/// about how long; `--reassembly-ttl` or `[limits] reassembly_ttl_secs` is the
/// other half.
///
/// Raising it holds partial state for longer, which is memory the entry cap
/// already bounds — so the cost of a wider window is bounded and the cost of a
/// narrow one is data.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);

/// The TTL this process declared, in seconds.
///
/// Process-global and written once at startup, the same shape as
/// [`MAX_TCP_BUFFER`] below and for the same reason: a reassembler is created
/// by the batch runner, the TUI and every `--cores` shard, so a value threaded
/// to some of them is a setting honored on some surfaces and ignored on
/// others.
static REASSEMBLY_TTL_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_TTL.as_secs());

/// How long an incomplete entry is held before a sweep may evict it.
#[must_use]
pub fn reassembly_ttl() -> Duration {
    Duration::from_secs(REASSEMBLY_TTL_SECS.load(std::sync::atomic::Ordering::Relaxed))
}

/// Declare the reassembly TTL for this process. Call once, at startup.
///
/// # Arguments
///
/// * `secs` — seconds an incomplete entry survives. `0` is treated as the
///   shipped default; the operator-facing refusal happens earlier, in
///   `crate::config::LimitsConfig::validate` and in clap, so it can name the
///   key. A zero TTL would evict every partial on the first sweep after it
///   arrived, which is not "no waiting" but reassembly switched off while still
///   reporting the halves as malformed messages.
///
/// # Side effects
///
/// Stores `secs` into a process-wide atomic (relaxed ordering), affecting every
/// reassembler CONSTRUCTED after this call.
pub fn set_reassembly_ttl_secs(secs: u64) {
    REASSEMBLY_TTL_SECS.store(
        if secs == 0 {
            DEFAULT_TTL.as_secs()
        } else {
            secs
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Shipped maximum TCP stream buffer size before forced flush (64 KB).
///
/// This is policy wearing a protocol's clothes. TCP imposes no such ceiling and
/// neither does RFC 3261: a SIP/TCP message carrying a large multipart body —
/// ISUP encapsulation, a long `Record-Route` set, a fat SDP offer — legitimately
/// exceeds it. When it does, the buffer is flushed MID-MESSAGE and the fragment
/// parses as garbage, so the failure surfaces as a malformed message rather than
/// as a limit that was reached.
///
/// Raise it with `--max-tcp-buffer` or `[limits] max_tcp_buffer`; see
/// [`crate::cli::Cli::tcp_buffer_cap`].
pub const DEFAULT_MAX_TCP_BUFFER: usize = 65536;

/// Smallest ceiling that can hold one SIP header line, and therefore the
/// smallest one any message can survive.
///
/// Grounded on [`crate::sip::parser::DEFAULT_MAX_HEADER_LINE_LEN`] rather than
/// chosen: below one header line the reassembler flushes mid-message on every
/// SIP/TCP message in the capture, so a "smaller buffer" is not a tighter
/// setting but a switch that reports every peer as broken. Refused by
/// `crate::config::LimitsConfig::validate` and by clap, from the same number.
pub const MIN_TCP_BUFFER: usize = crate::sip::parser::DEFAULT_MAX_HEADER_LINE_LEN;

/// The ceiling this process declared, in bytes per TCP direction.
///
/// Process-global and written once at startup, the same shape as
/// [`crate::rtp::stream::set_lost_seq_log_cap`] and for the same reason: a
/// reassembler is created by the batch runner, the TUI and every `--cores`
/// shard, so a value threaded to some of them is a setting honored on some
/// surfaces and ignored on others.
static MAX_TCP_BUFFER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_MAX_TCP_BUFFER);

/// Bytes one TCP direction may buffer before the reassembler forces a flush.
#[must_use]
pub fn max_tcp_buffer() -> usize {
    MAX_TCP_BUFFER.load(std::sync::atomic::Ordering::Relaxed)
}

/// Declare the SIP/TCP reassembly ceiling for this process. Call once, at
/// startup.
///
/// # Arguments
///
/// * `bytes` — bytes one direction may buffer. A value below
///   [`MIN_TCP_BUFFER`] is treated as the shipped default; the operator-facing
///   refusal happens earlier, in `crate::config::LimitsConfig::validate` and in
///   clap, so it can name the key.
///
/// # Side effects
///
/// Stores `bytes` into a process-wide atomic (relaxed ordering), affecting
/// every flush decision made after this call.
pub fn set_max_tcp_buffer(bytes: usize) {
    MAX_TCP_BUFFER.store(
        if bytes < MIN_TCP_BUFFER {
            DEFAULT_MAX_TCP_BUFFER
        } else {
            bytes
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// IP Fragment Reassembly
// ═══════════════════════════════════════════════════════════════════════

/// Key identifying a unique IP datagram for fragment reassembly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    /// Source IP address.
    src: IpAddr,
    /// Destination IP address.
    dst: IpAddr,
    /// IP identification field shared by all fragments of the datagram.
    ip_id: u32,
    /// IP protocol number (e.g. 6 = TCP, 17 = UDP).
    protocol: u8,
}

/// State for an in-progress fragment reassembly.
struct FragmentEntry {
    /// Collected fragments: (byte offset, data).
    fragments: Vec<(usize, bytes::Bytes)>,
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
    /// In-progress reassemblies keyed by (src, dst, ip_id, protocol).
    entries: HashMap<FragmentKey, FragmentEntry>,
    /// Entry cap; reaching it triggers batched oldest-first eviction.
    max_entries: usize,
    /// Age at which an incomplete entry is swept.
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
    ///
    /// # Arguments
    ///
    /// * `parsed` - the fragment; its `fragment_offset` (8-byte units),
    ///   `more_fragments`, `ip_id`, addresses, and payload are consumed.
    ///   Packets without an `ip_id` return `None` immediately.
    ///
    /// # Side effects
    ///
    /// Mutates the entry map (insert/remove/evict) and logs overlaps,
    /// oversize drops, and completions via tracing.
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
        let mut sorted: Vec<&(usize, bytes::Bytes)> = entry.fragments.iter().collect();
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
    ///
    /// # Side effects
    ///
    /// Drops the timed-out entries and adds them to the process-wide
    /// reassembly-timeout counter read by [`reassembly_timeouts`].
    pub fn sweep(&mut self) {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries
            .retain(|_key, entry| now.duration_since(entry.created) < self.ttl);
        let evicted = before - self.entries.len();
        if evicted > 0 {
            REASSEMBLY_TIMEOUTS.fetch_add(evicted as u64, Ordering::Relaxed);
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
        by_age.sort_unstable_by_key(|a| a.0);
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
    /// Equivalent to `FragmentReassembler::new()` (default cap and TTL).
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
    /// Sender socket address of this direction.
    src: SocketAddr,
    /// Receiver socket address of this direction.
    dst: SocketAddr,
}

/// State for a tracked TCP stream.
struct TcpStream {
    /// Next expected sequence number.
    expected_seq: u32,
    /// Out-of-order segment buffer, keyed by sequence number.
    buffer: BTreeMap<u32, bytes::Bytes>,
    /// When the last segment was received.
    last_seen: Instant,
    /// Total buffered bytes (for overflow detection).
    buffered_bytes: usize,
    /// Whether the initial sequence number has been set.
    initialized: bool,
    /// Whether a SYN was seen (meaning expected_seq is authoritative).
    syn_seen: bool,
    /// A PSH was seen but its data could not yet be drained (a missing earlier
    /// segment left a gap). Stays set until the gap fills and the data flushes,
    /// so an out-of-order push completes instead of being buffered forever.
    pending_flush: bool,
}

/// Serial (modular) "less than" over the 2^32 TCP sequence space, per the
/// RFC 793 SEQ comparison convention (RFC 1982 serial arithmetic): `a`
/// precedes `b` iff the wrapping distance `a - b`, reinterpreted as a
/// signed 32-bit value, is negative. This yields a total order within any
/// window narrower than 2^31; two values exactly 2^31 apart are mutually
/// "less than" and cannot be ordered. Raw `<` on the u32 values breaks for
/// streams whose sequence numbers cross the 2^32 wrap.
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Reassembles TCP segments into ordered byte streams.
///
/// Tracks individual TCP stream directions (src -> dst) and buffers
/// out-of-order segments. Flushes reassembled data on PSH flag,
/// connection close (FIN/RST), or buffer overflow.
pub struct TcpReassembler {
    /// Tracked stream directions keyed by (src, dst).
    streams: HashMap<TcpStreamKey, TcpStream>,
    /// Stream cap; reaching it triggers batched oldest-first eviction.
    max_entries: usize,
    /// Idle age (since `last_seen`) at which a stream is swept.
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
    /// - **Buffer overflow (past [`max_tcp_buffer`]):** forces a flush.
    /// - **SYN flag:** initializes or resets the stream's expected sequence.
    ///
    /// # Arguments
    ///
    /// * `parsed` - the segment; its `tcp_flags`, `tcp_seq`, addresses,
    ///   ports, and payload are consumed. Packets without flags or a
    ///   sequence number return empty immediately.
    ///
    /// # Side effects
    ///
    /// Mutates the stream map (creating, updating, evicting, or removing
    /// streams), updates per-stream buffers/counters/`last_seen`, and logs
    /// RST discards and overflow flushes at debug level.
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
                last_seen: Instant::now(),
                buffered_bytes: 0,
                initialized: false,
                syn_seen: false,
                pending_flush: false,
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
        if !parsed.payload.is_empty() && seq_lt(seq, stream.expected_seq) && !stream.syn_seen {
            stream.expected_seq = seq;
        }

        // Buffer the segment (skip empty payloads from pure ACKs)
        if !parsed.payload.is_empty() {
            stream.buffered_bytes += parsed.payload.len();
            stream.buffer.insert(seq, parsed.payload.clone());
        }
        // A PSH requests delivery of the data up to here; record it while we hold
        // the borrow. It may not be drainable yet (a gap before it) — the flush
        // below retries it once a later out-of-order segment fills the gap.
        if flags.psh {
            stream.pending_flush = true;
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
        let ceiling = max_tcp_buffer();
        if stream.buffered_bytes > ceiling {
            let flushed = self.drain_in_order(&key);
            if !flushed.is_empty() {
                // Warned, not just debugged: this cuts a message in half, and
                // the halves parse as malformed SIP. An operator reading the
                // output sees a broken message from a peer that sent a
                // perfectly good one, and nothing connects that to a buffer
                // ceiling. Once per process — a peer that exceeds it once
                // usually exceeds it on every call.
                static OVERFLOW_WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !OVERFLOW_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        "a SIP/TCP message from {} to {} exceeded the {ceiling}-byte \
                         reassembly buffer and was flushed mid-message, so it will parse as \
                         malformed. TCP sets no such limit; this is sipnab's ceiling. Large \
                         multipart bodies (ISUP, long Record-Route sets) hit it legitimately. \
                         Raise it with --max-tcp-buffer or [limits] max_tcp_buffer.",
                        key.src,
                        key.dst,
                    );
                }
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

        // Flush if a push is pending — now, or one that earlier stalled on a
        // missing segment that this (out-of-order) segment has just filled.
        if self.streams.get(&key).is_some_and(|s| s.pending_flush) {
            let flushed = self.drain_in_order(&key);
            if !flushed.is_empty() {
                results.push(flushed);
            }
            // Once the contiguous data is delivered, the push is satisfied.
            if let Some(s) = self.streams.get_mut(&key)
                && s.buffer.is_empty()
            {
                s.pending_flush = false;
            }
        }

        results
    }

    /// Drain consecutive in-order segments from a stream's buffer.
    ///
    /// Returns the concatenated payload of all segments starting from
    /// `expected_seq`, advancing it past each drained segment. Duplicate /
    /// retransmitted segments (sequence serial-below `expected_seq`) are
    /// discarded; draining stops at the first gap. Empty when `key` is
    /// untracked or nothing is in order yet.
    ///
    /// # Side effects
    ///
    /// Removes consumed segments from the stream's buffer and updates its
    /// `expected_seq` and `buffered_bytes`.
    fn drain_in_order(&mut self, key: &TcpStreamKey) -> Vec<u8> {
        let stream = match self.streams.get_mut(key) {
            Some(s) => s,
            None => return Vec::new(),
        };

        let mut result = Vec::new();

        // The buffer's BTreeMap iteration order is numeric, which diverges
        // from serial order once a stream crosses the 2^32 sequence wrap
        // (post-wrap keys sort numerically first). Segments are therefore
        // selected by serial position relative to `expected_seq` — direct
        // lookup for the in-order segment, a serial-below scan for
        // retransmits — never by key iteration order.
        loop {
            // In-order segment — consume it and advance.
            if let Some(data) = stream.buffer.remove(&stream.expected_seq) {
                stream.expected_seq = stream.expected_seq.wrapping_add(data.len() as u32);
                stream.buffered_bytes = stream.buffered_bytes.saturating_sub(data.len());
                result.extend_from_slice(&data);
                continue;
            }
            // Retransmits / duplicates — anything serial-below expected_seq.
            let stale: Vec<u32> = stream
                .buffer
                .keys()
                .copied()
                .filter(|&s| seq_lt(s, stream.expected_seq))
                .collect();
            if stale.is_empty() {
                // Gap (or empty buffer) — waiting for the missing segment.
                break;
            }
            for s in stale {
                if let Some(data) = stream.buffer.remove(&s) {
                    stream.buffered_bytes = stream.buffered_bytes.saturating_sub(data.len());
                }
            }
        }

        result
    }

    /// Evict TCP stream entries older than the configured TTL.
    ///
    /// Should be called periodically (e.g., every 5 seconds) from the main loop.
    ///
    /// # Side effects
    ///
    /// Drops the idle streams and adds them to the process-wide
    /// reassembly-timeout counter read by [`reassembly_timeouts`].
    pub fn sweep(&mut self) {
        let now = Instant::now();
        let before = self.streams.len();
        self.streams
            .retain(|_key, stream| now.duration_since(stream.last_seen) < self.ttl);
        let evicted = before - self.streams.len();
        if evicted > 0 {
            REASSEMBLY_TIMEOUTS.fetch_add(evicted as u64, Ordering::Relaxed);
            tracing::debug!("TCP reassembler: swept {evicted} stale streams");
        }
    }

    /// Whether a stream for this (src, dst) direction is still tracked. A stream
    /// is dropped on FIN/RST/timeout, so a `false` after an `insert` means the
    /// connection ended on that packet — the SIP framer uses this to decide
    /// whether to hold a partial message or flush it as a truncated tail.
    pub fn contains(&self, src: SocketAddr, dst: SocketAddr) -> bool {
        self.streams.contains_key(&TcpStreamKey { src, dst })
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
        by_age.sort_unstable_by_key(|a| a.0);
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
    /// Equivalent to `TcpReassembler::new()` (default cap and TTL).
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

/// Tests for IP-fragment and TCP-segment reassembly: ordering, overlap and
/// oversize defenses, TTL sweeps, and capacity eviction.
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
        ip_id: u32,
        offset: u16, // in 8-byte units
        more_fragments: bool,
        payload: &[u8],
    ) -> ParsedPacket {
        ParsedPacket {
            frame: None,
            timestamp: Utc::now(),
            src_addr: src,
            dst_addr: dst,
            src_port: 0,
            dst_port: 0,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::copy_from_slice(payload),
            ip_id: Some(ip_id),
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: Some(offset),
            more_fragments,
            ip_protocol: 17, // UDP
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
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
            frame: None,
            timestamp: Utc::now(),
            src_addr: src,
            dst_addr: dst,
            src_port,
            dst_port,
            transport: TransportProto::Tcp,
            payload: bytes::Bytes::copy_from_slice(payload),
            ip_id: None,
            tcp_seq: Some(seq),
            tcp_flags: Some(flags),
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 6, // TCP
            dscp: None,
            input_origin: crate::capture::parse::InputOrigin::Wire,
        }
    }

    /// ACK-only flags (no SYN/FIN/RST/PSH) for plain data segments.
    fn default_tcp_flags() -> TcpFlags {
        TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        }
    }

    /// A PSH that stalls on a sequence gap must flush when a later
    /// out-of-order segment fills the gap, not stay buffered forever.
    #[test]
    fn tcp_psh_on_final_segment_arriving_first_flushes_when_gap_fills() {
        // Real-world out-of-order: the FINAL segment (carrying PSH) arrives
        // first; the earlier segment (no PSH) arrives last and fills the gap.
        // The push stalled on the gap, so when the gap fills the now-contiguous
        // data MUST be flushed — previously it was buffered forever (decoded 0).
        let mut r = TcpReassembler::new();
        // SYN establishes the sequence base (data starts at seq 100), so a later
        // seg at 105 has a real gap rather than redefining the stream start.
        let mut syn = default_tcp_flags();
        syn.syn = true;
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 99, syn, b""))
                .is_empty()
        );
        let mut psh = default_tcp_flags();
        psh.psh = true;
        // seg2 = bytes [105..110) with PSH, arrives first
        let seg2 = make_tcp_segment(5060, 5061, 105, psh, b"world");
        assert!(r.insert(&seg2).is_empty(), "gap before it → nothing yet");
        // seg1 = bytes [100..105), NO PSH, arrives last and fills the gap
        let seg1 = make_tcp_segment(5060, 5061, 100, default_tcp_flags(), b"hello");
        let result = r.insert(&seg1);
        assert_eq!(
            result,
            vec![b"helloworld".to_vec()],
            "filling the gap must complete the stalled push"
        );
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
        for i in 0..1001u32 {
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

    /// TCP stream eviction at capacity is batched (cap/100), mirroring the
    /// fragment reassembler's anti-flood behavior.
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

    /// Two in-order fragments reassemble into the concatenated datagram and
    /// the entry is removed.
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

    /// Fragments arriving last-first still reassemble in offset order.
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

    /// Overlapping fragments (an evasion indicator) drop the whole entry.
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

    /// An incomplete entry older than the TTL is removed by `sweep`.
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

    /// A datagram whose declared total exceeds 64 KB is dropped entirely.
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

    /// At the entry cap, inserting a new key evicts the oldest so the count
    /// never exceeds the cap.
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

    /// Two in-order segments flush as one concatenated chunk on PSH.
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

    /// A segment arriving before its predecessor is reordered before the
    /// PSH flush.
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

    /// FIN flushes all buffered data and removes the stream.
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

    /// RST discards the stream and returns nothing.
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

    /// An idle stream older than the TTL is removed by `sweep`.
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

    /// At the stream cap, a new stream evicts the oldest so the count never
    /// exceeds the cap.
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

    // ── TCP sequence-wrap (serial arithmetic) tests ──────────────────

    /// Serial comparison sanity at the boundaries: total order at the wrap
    /// and within a 2^31 window; exactly 2^31 apart is mutually "less".
    #[test]
    fn tcp_serial_seq_lt_boundaries() {
        assert!(
            seq_lt(0xFFFF_FFFF, 0),
            "0xFFFFFFFF precedes 0 across the wrap"
        );
        assert!(!seq_lt(0, 0xFFFF_FFFF));
        assert!(seq_lt(0, 1));
        assert!(!seq_lt(1, 0));
        assert!(!seq_lt(42, 42), "irreflexive");
        // Largest ordered distance: 2^31 - 1.
        assert!(seq_lt(0, 0x7FFF_FFFF));
        assert!(!seq_lt(0x7FFF_FFFF, 0));
        assert!(seq_lt(0x8000_0001, 0)); // distance 2^31 - 1 the other way
        // Exactly 2^31 apart is unordered (both directions "less").
        assert!(seq_lt(0, 0x8000_0000));
        assert!(seq_lt(0x8000_0000, 0));
    }

    /// An in-order stream whose sequence numbers cross the 2^32 wrap must
    /// reassemble contiguously: the post-wrap segment is in-order data,
    /// not a retransmit.
    #[test]
    fn tcp_in_order_stream_across_seq_wrap() {
        let mut r = TcpReassembler::new();
        let mut syn = default_tcp_flags();
        syn.syn = true;
        // SYN at 0xFFFF_FEFF: data starts at 0xFFFF_FF00.
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 0xFFFF_FEFF, syn, b""))
                .is_empty()
        );
        // Pre-wrap segment: 0x200 bytes from 0xFFFF_FF00, crossing to 0x100.
        let pre = vec![0xAB; 0x200];
        assert!(
            r.insert(&make_tcp_segment(
                5060,
                5061,
                0xFFFF_FF00,
                default_tcp_flags(),
                &pre
            ))
            .is_empty()
        );
        // Post-wrap segment at 0x100 with PSH flushes both, in order.
        let mut psh = default_tcp_flags();
        psh.psh = true;
        let result = r.insert(&make_tcp_segment(5060, 5061, 0x100, psh, b"tail"));
        let mut expected = pre.clone();
        expected.extend_from_slice(b"tail");
        assert_eq!(
            result,
            vec![expected],
            "post-wrap segment is in-order data, not a retransmit"
        );
    }

    /// Out-of-order delivery across the wrap: the post-wrap segment (the
    /// numerically SMALLEST buffer key) arrives first and must be held,
    /// then drained in serial order once the pre-wrap segment fills the gap.
    #[test]
    fn tcp_out_of_order_across_seq_wrap_drains_serially() {
        let mut r = TcpReassembler::new();
        let mut syn = default_tcp_flags();
        syn.syn = true;
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 0xFFFF_FEFF, syn, b""))
                .is_empty()
        );
        // Post-wrap segment arrives FIRST.
        let mut psh = default_tcp_flags();
        psh.psh = true;
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 0x100, psh, b"world"))
                .is_empty(),
            "gap before the wrap point - nothing drains yet"
        );
        // Pre-wrap segment fills the gap; drain runs serially across the wrap.
        let pre = vec![0xCD; 0x200];
        let result = r.insert(&make_tcp_segment(
            5060,
            5061,
            0xFFFF_FF00,
            default_tcp_flags(),
            &pre,
        ));
        let mut expected = pre.clone();
        expected.extend_from_slice(b"world");
        assert_eq!(
            result,
            vec![expected],
            "buffer must drain in serial order across the wrap"
        );
    }

    /// A genuine retransmit just after the wrap (serial-below the advanced
    /// `expected_seq`) is still classified as a retransmit and discarded.
    #[test]
    fn tcp_genuine_retransmit_after_wrap_discarded() {
        let mut r = TcpReassembler::new();
        let mut syn = default_tcp_flags();
        syn.syn = true;
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 0xFFFF_FEFF, syn, b""))
                .is_empty()
        );
        let mut psh = default_tcp_flags();
        psh.psh = true;
        // Pre-wrap segment flushes; expected advances across the wrap to 0x100.
        let pre = vec![0xEF; 0x200];
        assert_eq!(
            r.insert(&make_tcp_segment(5060, 5061, 0xFFFF_FF00, psh, &pre)),
            vec![pre.clone()]
        );
        assert_eq!(
            r.insert(&make_tcp_segment(5060, 5061, 0x100, psh, b"abcde")),
            vec![b"abcde".to_vec()]
        );
        // Retransmit of the post-wrap segment (serial-below expected 0x105).
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 0x100, psh, b"abcde"))
                .is_empty(),
            "retransmit just after the wrap must still be discarded"
        );
        // Stream continues normally.
        assert_eq!(
            r.insert(&make_tcp_segment(5060, 5061, 0x105, psh, b"xyz")),
            vec![b"xyz".to_vec()]
        );
    }

    /// Regression guard: a normal mid-range stream (no wrap) behaves exactly
    /// as before - in-order flush, retransmit discard, out-of-order reorder.
    #[test]
    fn tcp_mid_range_stream_unchanged() {
        let mut r = TcpReassembler::new();
        let mut syn = default_tcp_flags();
        syn.syn = true;
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 99, syn, b""))
                .is_empty()
        );
        let mut psh = default_tcp_flags();
        psh.psh = true;
        assert_eq!(
            r.insert(&make_tcp_segment(5060, 5061, 100, psh, b"hello")),
            vec![b"hello".to_vec()]
        );
        // Genuine retransmit is discarded.
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 100, psh, b"hello"))
                .is_empty()
        );
        // Out-of-order pair still reorders before the flush.
        assert!(
            r.insert(&make_tcp_segment(5060, 5061, 110, psh, b"world"))
                .is_empty()
        );
        let result = r.insert(&make_tcp_segment(
            5060,
            5061,
            105,
            default_tcp_flags(),
            b" big ",
        ));
        assert_eq!(result, vec![b" big world".to_vec()]);
    }
}
