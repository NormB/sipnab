//! Network packet capture, pcap/pcapng file reading, TCP reassembly, HEP protocol,
//! and TLS decryption.
//!
//! This module coordinates live device capture, pcap file reading, and output
//! writing. It provides [`start_capture`] as the main entry point, which spawns
//! a capture thread and returns a [`CaptureHandle`] for lifecycle management.

#[cfg(feature = "native")]
pub mod atomic;
#[cfg(feature = "native")]
pub mod channel;
#[cfg(feature = "tls")]
pub mod decrypt;
#[cfg(feature = "native")]
pub mod device;
#[cfg(feature = "tls")]
pub mod dtls;
#[cfg(feature = "native")]
pub mod file;
#[cfg(feature = "hep")]
pub mod hep;
#[cfg(feature = "native")]
pub mod live;
pub mod packet;
pub mod parse;
pub mod pcap_reader;
#[cfg(feature = "native")]
pub mod pcapng_meta;
pub mod reassembly;
#[cfg(feature = "tls")]
pub mod rsa_key;
#[cfg(feature = "tls")]
pub mod tls;
pub mod websocket;
#[cfg(feature = "native")]
pub mod writer;

// Live-capture sources and thread orchestration (CaptureSource / CaptureConfig
// / CaptureHandle / start_capture / start_multi_capture) live here, gated once.
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{CaptureConfig, CaptureHandle, CaptureSource, start_capture, start_multi_capture};

use std::time::Duration;

use anyhow::{Context, Result};
use smallvec::{SmallVec, smallvec};

pub use packet::Packet;
pub use parse::ParsedPacket;

/// Output of [`PacketProcessor::process`]: the parsed packets ready from one
/// input packet. Inline-sized for one element — the dominant case (UDP, a
/// single-frame TCP message, one reassembled fragment) allocates nothing;
/// only a multi-message TCP segment spills to the heap.
pub type ParsedPackets = SmallVec<[ParsedPacket; 1]>;
#[cfg(feature = "native")]
pub use writer::{PcapExportMode, PcapWriter};

use parse::parse_packet;
use reassembly::{FragmentReassembler, TcpReassembler};

/// Stateful packet processing pipeline.
///
/// Combines header parsing, IP fragment reassembly, and TCP segment
/// reassembly into a single processing step. Feed raw [`Packet`]s in and
/// get back zero or more [`ParsedPacket`]s ready for upper-layer parsing.
pub struct PacketProcessor {
    /// IPv4/IPv6 fragment reassembler (bounded, oldest-out eviction).
    fragment_reassembler: FragmentReassembler,
    /// TCP stream reassembler that reorders segments before SIP framing.
    tcp_reassembler: TcpReassembler,
    /// Per-direction leftover bytes of an incomplete trailing SIP message held
    /// across TCP flushes (SNB-0008). Keyed by (src, dst); bounded by
    /// `max_sessions`.
    tcp_sip_leftover:
        std::collections::HashMap<(std::net::SocketAddr, std::net::SocketAddr), Vec<u8>>,
    /// Cap on tracked `tcp_sip_leftover` sessions; when full, an arbitrary
    /// entry is evicted to keep memory bounded.
    max_sessions: usize,
    /// When `false` (`--no-reassembly`), IP fragments and TCP segments pass
    /// through as individual packets instead of being reassembled/reframed.
    reassembly: bool,
    /// When `Some(n)` (`-S`/`--limitlen`), each emitted packet's payload is
    /// truncated to `n` bytes before upper-layer parsing — the sipgrep `-S`
    /// "look at only the first N bytes" cap, independent of the capture snaplen.
    parse_limit: Option<usize>,
}

/// Default reassembly session cap (matches the reassemblers' default).
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Upper bound on a single held partial SIP message (bytes). A larger remainder
/// is flushed rather than buffered, so a peer can't pin memory with an
/// unterminated message.
const MAX_TCP_LEFTOVER: usize = 65_536;

impl PacketProcessor {
    /// Create a new packet processor with default reassembly limits.
    pub fn new() -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::new(),
            tcp_reassembler: TcpReassembler::new(),
            tcp_sip_leftover: std::collections::HashMap::new(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            reassembly: true,
            parse_limit: None,
        }
    }

    /// Builder: enable or disable IP-fragment / TCP-segment reassembly
    /// (`--no-reassembly` sets this `false`). Default `true`.
    #[must_use]
    pub fn with_reassembly(mut self, on: bool) -> Self {
        self.reassembly = on;
        self
    }

    /// Builder: cap the bytes of each emitted packet handed to the parser
    /// (`-S`/`--limitlen`). Default `None` (no cap).
    #[must_use]
    pub fn with_parse_limit(mut self, limit: Option<usize>) -> Self {
        self.parse_limit = limit;
        self
    }

    /// Create a new packet processor with a custom maximum reassembly session count.
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::with_limits(
                max_sessions,
                std::time::Duration::from_secs(30),
            ),
            tcp_reassembler: TcpReassembler::with_limits(
                max_sessions,
                std::time::Duration::from_secs(30),
            ),
            tcp_sip_leftover: std::collections::HashMap::new(),
            max_sessions,
            reassembly: true,
            parse_limit: None,
        }
    }

    /// Process a raw captured packet through the parsing and reassembly pipeline.
    ///
    /// Returns zero or more [`ParsedPacket`]s:
    /// - **Zero:** packet is non-IP, a buffered fragment, or a buffered TCP segment.
    /// - **One:** typical UDP packet or a completed fragment/TCP flush.
    /// - **Multiple:** TCP reassembly may flush several accumulated segments.
    ///
    /// Applies the `-S`/`--limitlen` parse cap to every emitted packet.
    ///
    /// # Arguments
    ///
    /// * `packet` - the raw captured packet (link-layer frame plus metadata).
    ///
    /// # Side effects
    ///
    /// Mutates the fragment/TCP reassembler state and the held-partial map
    /// via `process_inner`.
    pub fn process(&mut self, packet: &Packet) -> ParsedPackets {
        let mut out = self.process_inner(packet);
        if let Some(limit) = self.parse_limit {
            for p in out.iter_mut() {
                if p.payload.len() > limit {
                    p.payload = p.payload.slice(..limit);
                }
            }
        }
        out
    }

    /// Core dispatch behind `process`: parse the packet, then route it through
    /// IP-fragment reassembly, TCP reassembly plus SIP framing, or (for UDP and
    /// other transports) pass it through directly.
    ///
    /// # Arguments
    ///
    /// * `packet` - the raw captured packet to parse and reassemble.
    ///
    /// # Returns
    ///
    /// Zero or more parsed packets, before the `-S`/`--limitlen` cap is
    /// applied (that happens in `process`). Empty when the packet is
    /// unparseable, a buffered IP fragment, or a buffered TCP segment.
    ///
    /// # Side effects
    ///
    /// Mutates both reassemblers and the `tcp_sip_leftover` map (inserting,
    /// removing, and — at the `max_sessions` cap — evicting an arbitrary held
    /// partial); logs unparseable packets at debug level.
    fn process_inner(&mut self, packet: &Packet) -> ParsedPackets {
        let parsed = match parse_packet(packet) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Skipping unparseable packet: {e}");
                return SmallVec::new();
            }
        };

        // Reassembly disabled (`--no-reassembly`): every packet stands alone —
        // IP fragments and TCP segments are neither reassembled nor reframed.
        if !self.reassembly {
            return smallvec![parsed];
        }

        // Check if this is an IP fragment that needs reassembly
        let is_fragment =
            parsed.fragment_offset.is_some_and(|off| off > 0) || parsed.more_fragments;

        if is_fragment {
            return match self.fragment_reassembler.insert(&parsed) {
                Some(reassembled) => {
                    // The reassembled buffer is the full IP payload (transport
                    // header + data). Re-parse the transport header so the ports
                    // and offset are recovered — the fragments themselves carried
                    // no usable transport header, so without this the payload
                    // still begins with the UDP/TCP header and SIP parsing fails.
                    let mut completed = parsed;
                    if let Some((sp, dp, tp, hdr)) =
                        parse::reparse_transport(completed.ip_protocol, &reassembled)
                    {
                        completed.src_port = sp;
                        completed.dst_port = dp;
                        completed.transport = tp;
                        completed.payload = bytes::Bytes::copy_from_slice(&reassembled[hdr..]);
                    } else {
                        completed.payload = reassembled.into();
                    }
                    completed.fragment_offset = Some(0);
                    completed.more_fragments = false;
                    smallvec![completed]
                }
                None => SmallVec::new(),
            };
        }

        // TCP: feed into reassembler, then frame the reassembled byte stream
        // into individual SIP messages (SNB-0008 — one segment can carry many).
        if parsed.transport == parse::TransportProto::Tcp {
            let flushed = self.tcp_reassembler.insert(&parsed);
            let src = std::net::SocketAddr::new(parsed.src_addr, parsed.src_port);
            let dst = std::net::SocketAddr::new(parsed.dst_addr, parsed.dst_port);
            let key = (src, dst);
            // `false` here means the connection ended on this packet (FIN/RST):
            // a held partial will never complete, so flush it as a truncated tail.
            let stream_open = self.tcp_reassembler.contains(src, dst);

            if flushed.is_empty() {
                // Connection ended (FIN/RST) with a partial message still held:
                // surface it as a truncated tail so it is flagged malformed
                // downstream rather than silently dropped.
                if !stream_open
                    && let Some(rem) = self.tcp_sip_leftover.remove(&key)
                    && !rem.is_empty()
                {
                    let mut p = parsed.clone();
                    p.payload = bytes::Bytes::from(rem);
                    return smallvec![p];
                }
                return SmallVec::new();
            }

            // Prepend any partial message held from a previous flush.
            let mut buf = self.tcp_sip_leftover.remove(&key).unwrap_or_default();
            for chunk in &flushed {
                buf.extend_from_slice(chunk);
            }

            // Only SIP-over-TCP is Content-Length framed. TLS, WebSocket, and any
            // other binary TCP payload must pass through whole (downstream
            // try_tls_decrypt / websocket unwrap handle them) — framing them as
            // SIP would swallow them.
            if !crate::sip::is_sip_message(&buf) {
                let mut p = parsed.clone();
                p.payload = bytes::Bytes::from(buf);
                return smallvec![p];
            }

            let (ranges, consumed) = frame_tcp_sip(&buf);

            let mut out: ParsedPackets = ranges
                .into_iter()
                .map(|r| {
                    let mut p = parsed.clone();
                    p.payload = bytes::Bytes::copy_from_slice(&buf[r]);
                    p
                })
                .collect();

            let remainder = &buf[consumed..];
            if !remainder.is_empty() {
                if stream_open && remainder.len() <= MAX_TCP_LEFTOVER {
                    // More bytes may arrive — hold the partial for the next flush.
                    if !self.tcp_sip_leftover.contains_key(&key)
                        && self.tcp_sip_leftover.len() >= self.max_sessions
                        && let Some(victim) = self.tcp_sip_leftover.keys().next().copied()
                    {
                        self.tcp_sip_leftover.remove(&victim);
                    }
                    self.tcp_sip_leftover.insert(key, remainder.to_vec());
                } else {
                    // Connection ended (or the partial is oversized): surface the
                    // truncated tail so a downstream parser can flag it malformed
                    // rather than silently dropping it.
                    let mut p = parsed.clone();
                    p.payload = bytes::Bytes::copy_from_slice(remainder);
                    out.push(p);
                }
            }
            return out;
        }

        // UDP (and other non-TCP, non-fragment): ready immediately
        smallvec![parsed]
    }

    /// Sweep stale entries from both reassemblers.
    ///
    /// Should be called periodically (e.g., every 5 seconds) to evict
    /// incomplete fragments and idle TCP streams.
    ///
    /// # Side effects
    ///
    /// Removes timed-out entries from both reassemblers and drops any held
    /// SIP partial whose TCP stream is no longer tracked.
    pub fn sweep(&mut self) {
        self.fragment_reassembler.sweep();
        self.tcp_reassembler.sweep();
        // Drop held SIP partials whose TCP stream was swept (timed out without a
        // FIN), so an idle half-message can't leak.
        self.tcp_sip_leftover
            .retain(|(src, dst), _| self.tcp_reassembler.contains(*src, *dst));
    }
}

impl Default for PacketProcessor {
    /// Equivalent to `PacketProcessor::new()` (default limits, reassembly on).
    fn default() -> Self {
        Self::new()
    }
}

/// Frame a reassembled TCP byte stream into individual SIP messages.
///
/// Over TCP, SIP message boundaries are delimited by `Content-Length`, not by
/// packet boundaries — a single TCP segment can carry several complete messages
/// (and a flush can end mid-message). This walks `data` message by message:
/// for each, it finds the end of headers (`\r\n\r\n`, or `\n\n`), reads
/// `Content-Length` (absent ⇒ 0; compact form `l` honored), and the message
/// spans up to `header_end + content_length`. The body is taken verbatim by
/// length, so a blank line *inside* a body never splits a message.
///
/// Returns the byte ranges of the complete messages plus `consumed` — the index
/// where the first incomplete (held-back) message begins. `data[consumed..]`
/// should be retained and prepended to the next flush of the same stream.
fn frame_tcp_sip(data: &[u8]) -> (Vec<std::ops::Range<usize>>, usize) {
    let mut ranges = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let rest = &data[pos..];
        let Some(body_start) = find_header_end(rest) else {
            break; // headers not yet complete — hold the remainder
        };
        let content_length = parse_content_length(&rest[..body_start]);
        let msg_end = match body_start.checked_add(content_length) {
            Some(e) => e,
            None => break, // absurd Content-Length overflow — hold
        };
        if rest.len() < msg_end {
            break; // body not fully arrived — hold the remainder
        }
        ranges.push(pos..pos + msg_end);
        pos += msg_end;
    }
    (ranges, pos)
}

/// Find the end of the SIP header section, returning the index just past the
/// blank-line separator (i.e. where the body starts). Accepts CRLFCRLF and the
/// lenient LFLF form. `None` if no complete header terminator is present yet.
fn find_header_end(data: &[u8]) -> Option<usize> {
    // SIMD substring search (memchr) rather than scalar `windows()` scans —
    // this runs once per candidate message on the TCP framing path. Both
    // forms are searched and the earliest wins; `\r\n\r\n` cannot contain
    // `\n\n` (the `\r` separates the newlines), so the two never overlap.
    let crlf = memchr::memmem::find(data, b"\r\n\r\n").map(|i| i + 4);
    let lf = memchr::memmem::find(data, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Parse `Content-Length` (or its compact form `l`) from a SIP header block.
/// Returns 0 when absent or unparseable (the framer then treats the message as
/// bodyless; a downstream parser still flags any real mismatch).
fn parse_content_length(headers: &[u8]) -> usize {
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = std::str::from_utf8(&line[..colon]).unwrap_or("").trim();
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l") {
            let val = std::str::from_utf8(&line[colon + 1..]).unwrap_or("").trim();
            return val.parse::<usize>().unwrap_or(0);
        }
    }
    0
}

/// Parse a duration string like "30s", "5m", "1h" into a [`Duration`].
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours).
/// A bare number is treated as seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Empty duration string");
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        (s, 1u64) // Bare number = seconds
    };

    let value: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid duration value: '{num_str}'"))?;

    Ok(Duration::from_secs(value * multiplier))
}

/// Unit tests for duration parsing, TCP SIP framing, and the
/// `PacketProcessor` pipeline (fragment/TCP reassembly dispatch).
#[cfg(test)]
mod tests {
    use super::*;

    /// "30s" and a bare "30" both parse as 30 seconds.
    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    /// "5m" parses as 300 seconds.
    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    /// "2h" parses as 7200 seconds.
    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    /// Empty strings, non-numeric values, and unknown suffixes are errors.
    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
    }

    // ── TCP SIP framing (SNB-0008) ──────────────────────────────────
    // Over TCP one segment may carry several SIP messages; the framer must
    // split them all (not just the first), hold an incomplete tail, and never
    // split on a blank line inside a body.

    /// Build a complete bodyless OPTIONS message whose Via branch and Call-ID
    /// are `cid`, as raw bytes.
    fn opts(cid: &str) -> Vec<u8> {
        format!(
            "OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/TCP h;branch={cid}\r\n\
             Call-ID: {cid}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    /// Run `frame_tcp_sip` over `data` and return the framed messages as
    /// lossy strings plus the consumed byte count.
    fn frame_strs(data: &[u8]) -> (Vec<String>, usize) {
        let (ranges, consumed) = frame_tcp_sip(data);
        (
            ranges
                .iter()
                .map(|r| String::from_utf8_lossy(&data[r.clone()]).into_owned())
                .collect(),
            consumed,
        )
    }

    /// Three complete messages in one buffer are all framed, in order, with
    /// the whole buffer consumed.
    #[test]
    fn frame_three_complete_messages_in_one_buffer() {
        let mut buf = opts("a");
        buf.extend(opts("b"));
        buf.extend(opts("c"));
        let total = buf.len();
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 3, "all three messages must be framed");
        assert!(msgs[0].contains("Call-ID: a"));
        assert!(msgs[1].contains("Call-ID: b"));
        assert!(msgs[2].contains("Call-ID: c"));
        assert_eq!(consumed, total, "fully consumed, nothing held");
    }

    /// A trailing message whose headers lack the blank-line terminator is
    /// held (not framed); `consumed` stops at its start.
    #[test]
    fn frame_holds_incomplete_trailing_headers() {
        let mut buf = opts("a");
        buf.extend(opts("b"));
        let consumed_expected = buf.len();
        buf.extend_from_slice(b"OPTIONS sip:h SIP/2.0\r\nCall-ID: partial\r\n"); // no \r\n\r\n
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 2, "two complete; the partial third is held");
        assert_eq!(consumed, consumed_expected, "held bytes start after msg 2");
    }

    /// A message with complete headers but fewer body bytes than
    /// Content-Length declares is held until the body arrives.
    #[test]
    fn frame_holds_message_with_unfinished_body() {
        // Headers complete, Content-Length declares 10 but no body bytes yet.
        let mut buf = opts("a");
        let after_a = buf.len();
        buf.extend_from_slice(b"INVITE sip:h SIP/2.0\r\nCall-ID: b\r\nContent-Length: 10\r\n\r\n");
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(msgs.len(), 1, "only the bodyless OPTIONS is complete");
        assert_eq!(
            consumed, after_a,
            "the CL:10 message is held until its body"
        );
    }

    /// A body containing its own blank line is taken whole by Content-Length,
    /// never split at the embedded separator.
    #[test]
    fn frame_body_with_embedded_blank_line_not_split() {
        // A body that itself contains \r\n\r\n must be taken by Content-Length,
        // not split at the blank line.
        let body = "v=0\r\n\r\no=x"; // 10 bytes, contains a blank line
        let msg = format!(
            "INVITE sip:h SIP/2.0\r\nCall-ID: b\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes();
        let mut buf = msg.clone();
        buf.extend(opts("tail"));
        let (msgs, consumed) = frame_strs(&buf);
        assert_eq!(
            msgs.len(),
            2,
            "the INVITE (with blank-line body) + the OPTIONS"
        );
        assert!(
            msgs[0].ends_with("o=x"),
            "body taken whole by Content-Length"
        );
        assert_eq!(consumed, buf.len());
    }

    /// The compact `l:` form of Content-Length is honored when framing.
    #[test]
    fn frame_compact_content_length_header() {
        let body = "abcd";
        let msg = format!("MESSAGE sip:h SIP/2.0\r\nCall-ID: m\r\nl: 4\r\n\r\n{body}").into_bytes();
        let (msgs, consumed) = frame_strs(&msg);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].ends_with("abcd"), "compact 'l' header honored");
        assert_eq!(consumed, msg.len());
    }

    /// A message using bare-LF line endings (LFLF header terminator) frames.
    #[test]
    fn frame_lenient_lf_only_separator() {
        let msg = b"OPTIONS sip:h SIP/2.0\nCall-ID: x\nContent-Length: 0\n\n";
        let (msgs, consumed) = frame_strs(msg);
        assert_eq!(msgs.len(), 1, "LFLF terminator accepted");
        assert_eq!(consumed, msg.len());
    }

    /// The earliest of CRLFCRLF/LFLF wins and the index lands just past it.
    #[test]
    fn find_header_end_takes_earliest_terminator() {
        // Pins the CRLFCRLF-vs-LFLF precedence: the earliest blank-line
        // separator of either form wins, and the index is just past it.
        assert_eq!(find_header_end(b"A: b\r\n\r\nBODY"), Some(8));
        assert_eq!(find_header_end(b"A: b\n\nBODY"), Some(6));
        // A lenient LFLF before a later CRLFCRLF wins (earliest).
        assert_eq!(find_header_end(b"A\n\nx\r\n\r\ny"), Some(3));
        // A CRLFCRLF before a later LFLF wins.
        assert_eq!(find_header_end(b"A\r\n\r\nx\n\ny"), Some(5));
        // Incomplete: no terminator yet.
        assert_eq!(find_header_end(b"A: b\r\nCall-ID: x\r\n"), None);
    }

    /// Bodies with NULs, backslashes, and CRLFs are framed strictly by length.
    #[test]
    fn frame_adversarial_bodies() {
        // Body with backslashes, embedded NUL, and special chars — taken whole.
        let body = b"a\\b\x00c\r\nd";
        let mut msg = format!(
            "MESSAGE sip:h SIP/2.0\r\nCall-ID: z\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        msg.extend_from_slice(body);
        let after = msg.len();
        msg.extend(opts("next"));
        let (ranges, consumed) = frame_tcp_sip(&msg);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 0..after, "NUL/backslash body framed by length");
        assert_eq!(consumed, msg.len());
    }

    /// Empty input frames nothing; terminator-less garbage is held entirely.
    #[test]
    fn frame_empty_and_garbage() {
        // Empty input: nothing framed, nothing consumed.
        assert_eq!(frame_tcp_sip(b""), (vec![], 0));
        // Garbage without a header terminator: held entirely (consumed 0).
        let (ranges, consumed) = frame_tcp_sip(b"not a sip message at all");
        assert!(ranges.is_empty());
        assert_eq!(consumed, 0);
    }

    /// Build an EN10MB frame (Ethernet+IPv4+TCP) carrying `payload`, so a raw
    /// `Packet` can be pushed through `PacketProcessor::process` end to end.
    fn tcp_frame(payload: &[u8], seq: u32, psh: bool, fin: bool) -> Packet {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&[0x14, 0x6e]); // src port 5230
        tcp.extend_from_slice(&[0x13, 0xc4]); // dst port 5060
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        let flags = 0x10 | if psh { 0x08 } else { 0 } | if fin { 0x01 } else { 0 };
        tcp.extend_from_slice(&[0x50, flags]); // data offset 5 words + flags
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, csum(0), urg
        tcp.extend_from_slice(payload);

        let total_len = (20 + tcp.len()) as u16;
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]); // id, flags, ttl, proto=6, csum0
        ip.extend_from_slice(&[127, 0, 0, 1]); // src
        ip.extend_from_slice(&[127, 0, 0, 2]); // dst
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]); // IPv4
        eth.extend_from_slice(&ip);

        let len = eth.len();
        Packet::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            eth,
            len,
            len,
            None,
            1, // DLT_EN10MB
        )
    }

    /// SNB-0008 regression: three SIP messages packed into one TCP segment
    /// all emerge from `process`, not just the first.
    #[test]
    fn process_splits_multiple_sip_messages_in_one_tcp_segment() {
        // SNB-0008 regression: three SIP messages packed into one TCP segment
        // must all emerge from process(), not just the first.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        payload.extend(opts("c"));
        let pkt = tcp_frame(&payload, 1000, true, false);

        let mut proc = PacketProcessor::new();
        let out = proc.process(&pkt);
        assert_eq!(out.len(), 3, "every message in the segment is emitted");
        let ids: Vec<String> = out
            .iter()
            .map(|p| String::from_utf8_lossy(&p.payload).into_owned())
            .collect();
        assert!(ids[0].contains("Call-ID: a"));
        assert!(ids[1].contains("Call-ID: b"));
        assert!(ids[2].contains("Call-ID: c"));
        assert!(
            out.iter()
                .all(|p| p.transport == parse::TransportProto::Tcp)
        );
    }

    /// A partial message held while the stream is open is emitted truncated
    /// on FIN so a downstream parser can flag it, never silently dropped.
    #[test]
    fn process_surfaces_truncated_tail_on_fin() {
        // A message whose body never completes before the connection closes is
        // held while the stream is open, then emitted (truncated) on FIN so a
        // downstream parser can flag it malformed — never silently dropped.
        let mut proc = PacketProcessor::new();
        let head = b"INVITE sip:h SIP/2.0\r\nCall-ID: trunc\r\nContent-Length: 60\r\n\r\n";
        let out1 = proc.process(&tcp_frame(head, 1, true, false));
        assert_eq!(
            out1.len(),
            0,
            "incomplete body held while the stream is open"
        );
        // FIN with no new data: the held partial must be surfaced.
        let out2 = proc.process(&tcp_frame(b"", 1 + head.len() as u32, false, true));
        assert_eq!(out2.len(), 1, "truncated tail emitted on FIN, not dropped");
        assert!(String::from_utf8_lossy(&out2[0].payload).contains("Call-ID: trunc"));
    }

    /// With `--no-reassembly` a multi-message TCP segment passes through as
    /// one raw packet, byte-for-byte, instead of being reframed.
    #[test]
    fn no_reassembly_passes_tcp_segment_through_unframed() {
        // Two SIP messages packed in one TCP segment: with reassembly OFF
        // (sipgrep -a inverse) the raw segment emerges as a single packet,
        // not reframed into individual messages.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        let pkt = tcp_frame(&payload, 1000, true, false);

        let mut proc = PacketProcessor::new().with_reassembly(false);
        let out = proc.process(&pkt);
        assert_eq!(
            out.len(),
            1,
            "no reassembly emits the raw segment as one packet"
        );
        assert_eq!(
            &out[0].payload[..],
            &payload[..],
            "bytes pass through intact"
        );
    }

    /// The default processor (reassembly on) reframes the same two-message
    /// segment into two separate parsed packets.
    #[test]
    fn reassembly_on_by_default_reframes_tcp() {
        // Contrast: the default processor DOES reframe the same segment.
        let mut payload = opts("a");
        payload.extend(opts("b"));
        let mut proc = PacketProcessor::new();
        let out = proc.process(&tcp_frame(&payload, 1000, true, false));
        assert_eq!(
            out.len(),
            2,
            "default reassembly reframes into two messages"
        );
    }

    /// Binary TCP payloads (e.g. TLS records) are never SIP-framed, even when
    /// they contain a CRLFCRLF — they pass through whole for TLS decryption.
    #[test]
    fn process_passes_non_sip_tcp_through_unframed() {
        // TLS-over-TCP (and other binary payloads) must NOT be SIP-framed — they
        // pass through whole so downstream TLS decryption still sees them.
        let mut proc = PacketProcessor::new();
        // A TLS ClientHello-ish record: type 0x16, version 0x0301, then bytes
        // that happen to include a CRLFCRLF, to prove framing is not applied.
        let tls = b"\x16\x03\x01\x00\x20payload\r\n\r\nmore-tls-bytes-here";
        let out = proc.process(&tcp_frame(tls, 1, true, false));
        assert_eq!(
            out.len(),
            1,
            "non-SIP TCP payload emerges as a single packet"
        );
        assert_eq!(&out[0].payload[..], &tls[..], "bytes pass through intact");
    }

    /// A body split across two TCP segments is held silently, then emitted
    /// complete once the rest of the body arrives.
    #[test]
    fn process_holds_partial_across_segments_then_completes() {
        // A message body split across two TCP segments must be held, not
        // emitted as a (false) malformed message, then completed on arrival.
        let mut proc = PacketProcessor::new();
        let head = b"MESSAGE sip:h SIP/2.0\r\nCall-ID: split\r\nContent-Length: 5\r\n\r\nab";
        let out1 = proc.process(&tcp_frame(head, 1, true, false));
        assert_eq!(
            out1.len(),
            0,
            "incomplete body is held, nothing emitted yet"
        );
        let out2 = proc.process(&tcp_frame(b"cde", 1 + head.len() as u32, true, false));
        assert_eq!(
            out2.len(),
            1,
            "the completed message is emitted once the body arrives"
        );
        assert!(String::from_utf8_lossy(&out2[0].payload).ends_with("abcde"));
    }

    /// Leading zeros and surrounding whitespace in a Content-Length value
    /// still parse to the correct body length.
    #[test]
    fn frame_content_length_whitespace_and_zeros() {
        // Leading zeros and surrounding spaces in the CL value parse fine.
        let msg = b"OPTIONS sip:h SIP/2.0\r\nCall-ID: w\r\nContent-Length:  007\r\n\r\n\
                    1234567";
        let (ranges, consumed) = frame_tcp_sip(msg);
        assert_eq!(ranges.len(), 1);
        assert_eq!(consumed, msg.len(), "CL ' 007' == 7 body bytes consumed");
    }

    // ── PacketProcessor::process dispatch (device-free) ─────────────────
    /// Tests of `PacketProcessor::process` dispatch that need no capture
    /// device: UDP pass-through, parse limits, and non-IP/garbage inputs.
    #[cfg(feature = "native")]
    mod processor {
        use super::*;
        use crate::capture::packet::Packet;
        use chrono::Utc;

        /// Minimal Ethernet + IPv4 + UDP frame carrying `payload`.
        fn eth_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
            let udp_len = 8 + payload.len() as u16;
            let ip_total = 20 + udp_len;
            let mut p = Vec::new();
            p.extend_from_slice(&[0xAA; 6]); // dst MAC
            p.extend_from_slice(&[0xBB; 6]); // src MAC
            p.extend_from_slice(&[0x08, 0x00]); // IPv4
            p.push(0x45); // ver/ihl
            p.push(0x00);
            p.extend_from_slice(&ip_total.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x01]); // id
            p.extend_from_slice(&[0x40, 0x00]); // DF, offset 0
            p.push(64); // ttl
            p.push(17); // UDP
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(&[10, 0, 0, 1]); // src ip
            p.extend_from_slice(&[10, 0, 0, 2]); // dst ip
            p.extend_from_slice(&src_port.to_be_bytes());
            p.extend_from_slice(&dst_port.to_be_bytes());
            p.extend_from_slice(&udp_len.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x00]); // checksum
            p.extend_from_slice(payload);
            p
        }

        /// Wrap raw frame bytes `data` in a `Packet` stamped "now" with
        /// Ethernet link type.
        fn packet(data: Vec<u8>) -> Packet {
            let n = data.len();
            Packet::new(Utc::now(), data, n, n, None, 1) // linktype 1 = Ethernet
        }

        /// A plain UDP SIP packet yields exactly one parsed packet with the
        /// right transport and ports.
        #[test]
        fn udp_packet_yields_one_parsed() {
            let mut proc = PacketProcessor::new();
            let frame = eth_ipv4_udp(5060, 5060, b"REGISTER sip:x SIP/2.0\r\n\r\n");
            let out = proc.process(&packet(frame));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].transport, parse::TransportProto::Udp);
            assert_eq!(out[0].dst_port, 5060);
        }

        /// A parse limit (`-S`/`--limitlen`) caps the emitted payload at N
        /// bytes.
        #[test]
        fn parse_limit_truncates_payload() {
            // `-S`/`--limitlen`: only the first N bytes of each message are
            // handed downstream, independent of capture snaplen.
            let mut proc = PacketProcessor::new().with_parse_limit(Some(10));
            let sip = b"REGISTER sip:x SIP/2.0\r\nCall-ID: hidden-after-limit\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(out.len(), 1);
            assert_eq!(
                out[0].payload.len(),
                10,
                "payload capped to the parse limit"
            );
            assert_eq!(&out[0].payload[..], &sip[..10]);
        }

        /// Without a parse limit the full payload is preserved.
        #[test]
        fn parse_limit_none_keeps_full_payload() {
            let mut proc = PacketProcessor::new();
            let sip = b"REGISTER sip:x SIP/2.0\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(out[0].payload.len(), sip.len(), "no limit → full payload");
        }

        /// A parse limit larger than the payload leaves it untouched.
        #[test]
        fn parse_limit_larger_than_payload_is_noop() {
            let mut proc = PacketProcessor::new().with_parse_limit(Some(100_000));
            let sip = b"REGISTER sip:x SIP/2.0\r\n\r\n";
            let out = proc.process(&packet(eth_ipv4_udp(5060, 5060, sip)));
            assert_eq!(
                out[0].payload.len(),
                sip.len(),
                "limit beyond payload is a no-op"
            );
        }

        /// A non-IP frame (ARP EtherType) yields no parsed packets.
        #[test]
        fn non_ip_frame_yields_nothing() {
            let mut proc = PacketProcessor::with_max_sessions(16);
            // EtherType 0x0806 (ARP) — not IP, so parse yields no ParsedPacket.
            let mut frame = vec![0xAAu8; 6];
            frame.extend_from_slice(&[0xBB; 6]);
            frame.extend_from_slice(&[0x08, 0x06]); // ARP
            frame.extend_from_slice(&[0u8; 28]);
            assert!(proc.process(&packet(frame)).is_empty());
        }

        /// Bytes too short to be a valid frame hit the parse-error path and
        /// yield nothing.
        #[test]
        fn truncated_garbage_yields_nothing() {
            let mut proc = PacketProcessor::new();
            // Too short to be a valid Ethernet/IP frame -> parse error path.
            assert!(proc.process(&packet(vec![0x01, 0x02, 0x03])).is_empty());
        }

        /// `sweep` on a processor with no tracked state is a safe no-op.
        #[test]
        fn sweep_is_safe_on_empty_state() {
            let mut proc = PacketProcessor::default();
            proc.sweep(); // exercises both reassembler sweeps with no entries
        }
    }
}
