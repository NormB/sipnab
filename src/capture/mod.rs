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

use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(feature = "native")]
use channel::PacketTx;
#[cfg(feature = "native")]
use std::thread;

pub use packet::Packet;
pub use parse::ParsedPacket;
#[cfg(feature = "native")]
pub use writer::{PcapExportMode, PcapWriter};

use parse::parse_packet;
use reassembly::{FragmentReassembler, TcpReassembler};

/// Describes where packets come from.
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub enum CaptureSource {
    /// Live capture from a network interface.
    Live {
        /// Device name (e.g., "eth0", "en0").
        device: String,
    },
    /// Read packets from a pcap file.
    File {
        /// Path to the pcap file.
        path: std::path::PathBuf,
    },
    /// Receive packets via HEP (Homer Encapsulation Protocol).
    Hep {
        /// Address to bind the HEP listener on.
        bind_addr: String,
        /// CIDR allowlist for source IP filtering.
        #[cfg(feature = "hep")]
        allowlist: Vec<hep::CidrRange>,
        /// Maximum HEP packets per second (0 = unlimited).
        rate_limit: u64,
    },
}

/// Aggregated configuration for the capture subsystem.
///
/// Combines CLI flags and config file values into a single struct consumed
/// by the capture thread.
#[cfg(feature = "native")]
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Packet snapshot length in bytes.
    pub snaplen: u32,
    /// Kernel capture buffer size in MiB.
    pub buffer_mb: u32,
    /// Optional BPF filter expression.
    pub bpf_filter: Option<String>,
    /// Stop after capturing this many packets.
    pub count: Option<u64>,
    /// Stop after this duration.
    pub duration: Option<Duration>,
    /// Replay pcap file with original inter-packet timing.
    pub replay: bool,
    /// Memory budget (MiB) for the in-flight packet queue between capture and
    /// processing. Converted to a packet-count cap via [`Self::channel_capacity`].
    pub buffer_budget_mb: u32,
}

#[cfg(feature = "native")]
impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: 65535,
            buffer_mb: 2,
            bpf_filter: None,
            count: None,
            duration: None,
            replay: false,
            buffer_budget_mb: 64,
        }
    }
}

#[cfg(feature = "native")]
impl CaptureConfig {
    /// Assumed average bytes per buffered packet (mixed SIP signaling + small
    /// RTP) when converting the memory budget to a packet count.
    const EST_AVG_PACKET_BYTES: usize = 2048;
    /// Floor so the cap never regresses below the historical fixed default.
    const MIN_CHANNEL_CAPACITY: usize = 10_000;
    /// Ceiling so a huge budget can't request an absurd permit pool.
    const MAX_CHANNEL_CAPACITY: usize = 5_000_000;

    /// Packet-count cap for the capture→processing queue, derived from
    /// `buffer_budget_mb`. Worst-case memory is `capacity × snaplen`; typical
    /// memory is far lower (packets are usually 0.2–5 KiB). Clamped to
    /// `[MIN_CHANNEL_CAPACITY, MAX_CHANNEL_CAPACITY]`.
    pub fn channel_capacity(&self) -> usize {
        let budget = (self.buffer_budget_mb as usize).saturating_mul(1024 * 1024);
        (budget / Self::EST_AVG_PACKET_BYTES)
            .clamp(Self::MIN_CHANNEL_CAPACITY, Self::MAX_CHANNEL_CAPACITY)
    }
}

/// Handle to a running capture thread.
///
/// Provides the [`JoinHandle`](thread::JoinHandle) for waiting on the capture
/// thread and the capture source metadata.
#[cfg(feature = "native")]
pub struct CaptureHandle {
    /// The spawned capture thread.
    pub thread: std::thread::JoinHandle<Result<()>>,
    /// Which source this handle is capturing from.
    pub source: CaptureSource,
}

/// Start a capture from the given source, sending packets into `tx`.
///
/// Spawns a dedicated thread for the capture loop and returns a
/// [`CaptureHandle`] immediately. The capture runs until shutdown is
/// signaled, limits are reached, or (for files) EOF is hit.
///
/// If `ready_tx` is provided, the capture thread will send `Ok(())` on it
/// after successfully opening the capture device/file/socket, or `Err(msg)`
/// if opening fails. This allows the caller to wait until the capture
/// resource is acquired before dropping privileges.
///
/// # Errors
///
/// Returns an error if the source configuration is invalid (e.g., HEP
/// without the `hep` feature). Capture-thread errors are returned when
/// joining the handle.
#[cfg(feature = "native")]
pub fn start_capture(
    source: CaptureSource,
    config: CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<CaptureHandle> {
    let source_clone = source.clone();

    let thread = match &source {
        CaptureSource::Live { device } => {
            let device = device.clone();
            thread::Builder::new()
                .name(format!("capture-{device}"))
                .spawn(move || live::capture_live(&device, &config, tx, ready_tx))
                .context("Failed to spawn live capture thread")?
        }
        CaptureSource::File { path } => {
            let path = path.clone();
            thread::Builder::new()
                .name("capture-file".to_string())
                .spawn(move || file::capture_file(&path, &config, tx, ready_tx))
                .context("Failed to spawn file reader thread")?
        }
        #[cfg(feature = "hep")]
        CaptureSource::Hep {
            bind_addr,
            allowlist,
            rate_limit,
        } => {
            let addr = bind_addr.clone();
            let allow = allowlist.clone();
            let rate = *rate_limit;
            thread::Builder::new()
                .name("capture-hep".to_string())
                .spawn(move || hep::capture_hep(&addr, &config, tx, &allow, rate, ready_tx))
                .context("Failed to spawn HEP capture thread")?
        }
        #[cfg(not(feature = "hep"))]
        CaptureSource::Hep {
            bind_addr,
            rate_limit,
            ..
        } => {
            let _ = (bind_addr, rate_limit);
            anyhow::bail!("HEP support requires the 'hep' feature: cargo build --features hep");
        }
    };

    Ok(CaptureHandle {
        thread,
        source: source_clone,
    })
}

/// Start captures on multiple devices simultaneously.
///
/// Splits the comma-separated device string, spawns a capture thread for
/// each device, and all threads send to the same channel. Returns a
/// [`CaptureHandle`] whose thread joins all sub-threads.
///
/// If `ready_tx` is provided, it signals `Ok(())` once **all** per-device
/// capture threads have successfully opened their devices, or `Err(msg)` if
/// any device fails to open.
#[cfg(feature = "native")]
pub fn start_multi_capture(
    devices: &str,
    config: CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<CaptureHandle> {
    // Parse + validate the selected-interface list up front so a malformed
    // spec (empty, doubled/stray comma, embedded NUL) fails with a precise
    // message *before* we spawn any capture threads.
    let device_list = device::parse_device_list(devices)?;

    if device_list.len() == 1 {
        // Single device: fall back to normal capture
        return start_capture(
            CaptureSource::Live {
                device: match device_list.into_iter().next() {
                    Some(d) => d,
                    None => return Err(anyhow::anyhow!("no capture device available")),
                },
            },
            config,
            tx,
            ready_tx,
        );
    }

    tracing::info!(
        "Multi-device capture on {} interfaces: {}",
        device_list.len(),
        devices
    );

    let source = CaptureSource::Live {
        device: devices.to_string(),
    };

    let thread = thread::Builder::new()
        .name("capture-multi".to_string())
        .spawn(move || {
            let mut handles = Vec::new();
            let mut per_device_ready_rxs = Vec::new();

            for dev in &device_list {
                let dev_name = dev.clone();
                let config = config.clone();
                let tx = tx.clone();

                // Each sub-thread gets its own ready signal so we can
                // aggregate them before signaling the caller.
                let (dev_ready_tx, dev_ready_rx) =
                    crossbeam_channel::bounded::<Result<(), String>>(1);
                per_device_ready_rxs.push((dev.clone(), dev_ready_rx));

                let dev_ctx = dev.clone(); // for error context
                let h = thread::Builder::new()
                    .name(format!("capture-{dev_name}"))
                    .spawn(move || {
                        live::capture_live(&dev_name, &config, tx, Some(dev_ready_tx))
                    })
                    .with_context(|| format!("Failed to spawn capture thread for '{dev_ctx}'"))?;

                handles.push(h);
            }

            // Wait for all sub-threads to report ready (or failure).
            if let Some(ready) = ready_tx {
                let mut first_err: Option<String> = None;
                for (dev_name, dev_rx) in &per_device_ready_rxs {
                    match dev_rx.recv() {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            if first_err.is_none() {
                                first_err =
                                    Some(format!("Device '{dev_name}' failed to open: {e}"));
                            }
                        }
                        Err(_) => {
                            if first_err.is_none() {
                                first_err = Some(format!(
                                    "Device '{dev_name}' capture thread exited before signaling ready"
                                ));
                            }
                        }
                    }
                }
                let _ = ready.send(match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                });
            }

            // Drop our copy of tx so the channel closes when all capture
            // threads finish.
            drop(tx);

            let mut first_error = None;
            for h in handles {
                match h.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        tracing::warn!("Capture thread error: {e}");
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                    Err(_) => {
                        tracing::error!("Capture thread panicked");
                    }
                }
            }

            if let Some(e) = first_error {
                return Err(e);
            }
            Ok(())
        })
        .context("Failed to spawn multi-capture coordinator thread")?;

    Ok(CaptureHandle { thread, source })
}

/// Stateful packet processing pipeline.
///
/// Combines header parsing, IP fragment reassembly, and TCP segment
/// reassembly into a single processing step. Feed raw [`Packet`]s in and
/// get back zero or more [`ParsedPacket`]s ready for upper-layer parsing.
pub struct PacketProcessor {
    fragment_reassembler: FragmentReassembler,
    tcp_reassembler: TcpReassembler,
    /// Per-direction leftover bytes of an incomplete trailing SIP message held
    /// across TCP flushes (SNB-0008). Keyed by (src, dst); bounded by
    /// `max_sessions`.
    tcp_sip_leftover:
        std::collections::HashMap<(std::net::SocketAddr, std::net::SocketAddr), Vec<u8>>,
    max_sessions: usize,
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
        }
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
        }
    }

    /// Process a raw captured packet through the parsing and reassembly pipeline.
    ///
    /// Returns zero or more [`ParsedPacket`]s:
    /// - **Zero:** packet is non-IP, a buffered fragment, or a buffered TCP segment.
    /// - **One:** typical UDP packet or a completed fragment/TCP flush.
    /// - **Multiple:** TCP reassembly may flush several accumulated segments.
    pub fn process(&mut self, packet: &Packet) -> Vec<ParsedPacket> {
        let parsed = match parse_packet(packet) {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("Skipping unparseable packet: {e}");
                return Vec::new();
            }
        };

        // Check if this is an IP fragment that needs reassembly
        let is_fragment =
            parsed.fragment_offset.is_some_and(|off| off > 0) || parsed.more_fragments;

        if is_fragment {
            return match self.fragment_reassembler.insert(&parsed) {
                Some(reassembled) => {
                    // Re-parse the reassembled datagram to get transport headers.
                    // The reassembled data is the IP payload (transport header + data),
                    // so we need to create a synthetic packet for re-parsing.
                    // For now, emit the parsed packet with the reassembled payload.
                    let mut completed = parsed;
                    completed.payload = reassembled.into();
                    completed.fragment_offset = Some(0);
                    completed.more_fragments = false;
                    vec![completed]
                }
                None => Vec::new(),
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
                    return vec![p];
                }
                return Vec::new();
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
                return vec![p];
            }

            let (ranges, consumed) = frame_tcp_sip(&buf);

            let mut out: Vec<ParsedPacket> = ranges
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
        vec![parsed]
    }

    /// Sweep stale entries from both reassemblers.
    ///
    /// Should be called periodically (e.g., every 5 seconds) to evict
    /// incomplete fragments and idle TCP streams.
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
    let crlf = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4);
    let lf = data.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

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

    fn opts(cid: &str) -> Vec<u8> {
        format!(
            "OPTIONS sip:h SIP/2.0\r\nVia: SIP/2.0/TCP h;branch={cid}\r\n\
             Call-ID: {cid}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

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

    #[test]
    fn frame_compact_content_length_header() {
        let body = "abcd";
        let msg = format!("MESSAGE sip:h SIP/2.0\r\nCall-ID: m\r\nl: 4\r\n\r\n{body}").into_bytes();
        let (msgs, consumed) = frame_strs(&msg);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].ends_with("abcd"), "compact 'l' header honored");
        assert_eq!(consumed, msg.len());
    }

    #[test]
    fn frame_lenient_lf_only_separator() {
        let msg = b"OPTIONS sip:h SIP/2.0\nCall-ID: x\nContent-Length: 0\n\n";
        let (msgs, consumed) = frame_strs(msg);
        assert_eq!(msgs.len(), 1, "LFLF terminator accepted");
        assert_eq!(consumed, msg.len());
    }

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

    #[test]
    fn frame_content_length_whitespace_and_zeros() {
        // Leading zeros and surrounding spaces in the CL value parse fine.
        let msg = b"OPTIONS sip:h SIP/2.0\r\nCall-ID: w\r\nContent-Length:  007\r\n\r\n\
                    1234567";
        let (ranges, consumed) = frame_tcp_sip(msg);
        assert_eq!(ranges.len(), 1);
        assert_eq!(consumed, msg.len(), "CL ' 007' == 7 body bytes consumed");
    }

    #[cfg(feature = "native")]
    #[test]
    fn default_capture_config() {
        let config = CaptureConfig::default();
        assert_eq!(config.snaplen, 65535);
        assert_eq!(config.buffer_mb, 2);
        assert!(config.bpf_filter.is_none());
        assert!(config.count.is_none());
        assert!(config.duration.is_none());
        assert_eq!(config.buffer_budget_mb, 64);
    }

    #[cfg(feature = "native")]
    #[test]
    fn channel_capacity_derives_from_budget_and_clamps() {
        let cfg = |mb: u32| CaptureConfig {
            buffer_budget_mb: mb,
            ..CaptureConfig::default()
        };
        // 64 MiB / 2 KiB = 32768, inside the clamp range.
        assert_eq!(cfg(64).channel_capacity(), 64 * 1024 * 1024 / 2048);
        // A tiny budget clamps up to the 10k floor (no regression below today).
        assert_eq!(cfg(1).channel_capacity(), 10_000);
        assert_eq!(cfg(0).channel_capacity(), 10_000);
        // A huge budget clamps to the ceiling.
        assert_eq!(cfg(1_000_000).channel_capacity(), 5_000_000);
        // Monotonic in between.
        assert!(cfg(256).channel_capacity() > cfg(64).channel_capacity());
    }

    #[cfg(feature = "native")]
    #[test]
    fn capture_source_debug() {
        use std::path::PathBuf;
        // Ensure CaptureSource variants can be debug-printed
        let live = CaptureSource::Live {
            device: "eth0".to_string(),
        };
        let file = CaptureSource::File {
            path: PathBuf::from("/tmp/test.pcap"),
        };
        assert!(format!("{live:?}").contains("eth0"));
        assert!(format!("{file:?}").contains("test.pcap"));
    }

    #[cfg(feature = "native")]
    #[test]
    fn ready_signal_sent_on_file_capture() {
        use std::path::PathBuf;
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("udp_5060.pcap");
        if !fixture.exists() {
            eprintln!("Skipping: fixture not found at {}", fixture.display());
            return;
        }

        let (pkt_tx, pkt_rx) = channel::packet_channel(1 << 20);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);
        let config = CaptureConfig::default();

        let handle = start_capture(
            CaptureSource::File { path: fixture },
            config,
            pkt_tx,
            Some(ready_tx),
        )
        .expect("start_capture should succeed");

        // The ready signal must arrive before we'd drop privileges.
        let ready_result = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("ready signal should arrive");
        assert!(
            ready_result.is_ok(),
            "ready signal should be Ok, got: {ready_result:?}"
        );

        // Capture should also produce packets.
        handle.thread.join().expect("capture thread panicked").ok();
        let packets: Vec<_> = pkt_rx.try_iter().collect();
        assert!(!packets.is_empty(), "Expected packets from fixture file");
    }

    // ── start_multi_capture input validation ────────────────────────────
    #[cfg(feature = "native")]
    #[test]
    fn multi_capture_rejects_malformed_device_spec_before_spawning() {
        // A doubled comma is a validation error: start_multi_capture must
        // return Err immediately, without spawning any capture thread.
        let (tx, _rx) = channel::packet_channel(1 << 20);
        match start_multi_capture("eth0,,docker0", CaptureConfig::default(), tx, None) {
            Ok(_) => panic!("malformed device spec must be rejected"),
            Err(e) => assert!(e.to_string().contains("empty interface name"), "got: {e}"),
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn multi_capture_rejects_empty_device_spec() {
        let (tx, _rx) = channel::packet_channel(1 << 20);
        assert!(start_multi_capture("   ", CaptureConfig::default(), tx, None).is_err());
        // (Ok(_) is not Debug; .is_err() avoids unwrapping the handle.)
    }

    // ── PacketProcessor::process dispatch (device-free) ─────────────────
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

        fn packet(data: Vec<u8>) -> Packet {
            let n = data.len();
            Packet::new(Utc::now(), data, n, n, None, 1) // linktype 1 = Ethernet
        }

        #[test]
        fn udp_packet_yields_one_parsed() {
            let mut proc = PacketProcessor::new();
            let frame = eth_ipv4_udp(5060, 5060, b"REGISTER sip:x SIP/2.0\r\n\r\n");
            let out = proc.process(&packet(frame));
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].transport, parse::TransportProto::Udp);
            assert_eq!(out[0].dst_port, 5060);
        }

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

        #[test]
        fn truncated_garbage_yields_nothing() {
            let mut proc = PacketProcessor::new();
            // Too short to be a valid Ethernet/IP frame -> parse error path.
            assert!(proc.process(&packet(vec![0x01, 0x02, 0x03])).is_empty());
        }

        #[test]
        fn sweep_is_safe_on_empty_state() {
            let mut proc = PacketProcessor::default();
            proc.sweep(); // exercises both reassembler sweeps with no entries
        }
    }
}
