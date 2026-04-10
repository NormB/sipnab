//! HEP (Homer Encapsulation Protocol) v2/v3 receiver and sender.
//!
//! HEP is used by SIP servers (OpenSIPS, Kamailio, FreeSWITCH, etc.) to mirror
//! SIP traffic to a capture server. sipnab acts as a HEP receiver (like
//! Homer/heplify-server) when invoked with `-L`, and as a HEP sender when
//! invoked with `-H`.
//!
//! ## Wire formats
//!
//! **HEP v3** (RFC-style, chunk-based):
//! ```text
//! "HEP3" magic (4 bytes) | total length (2 bytes, big-endian)
//! followed by variable-length chunks, each:
//!   vendor_id (2) | type (2) | length (2, includes 6-byte header) | data (N)
//! ```
//!
//! **HEP v2** (legacy, fixed header):
//! ```text
//! version (1 byte, 0x02) | header_length (1 byte)
//! src_port (2) | dst_port (2) | src_ip (4) | dst_ip (4)
//! payload follows immediately after the header
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, TimeZone, Utc};
use crossbeam_channel::Sender;

use super::CaptureConfig;
use super::packet::Packet;
use crate::signals;

// ── HEP v3 chunk type constants (vendor 0x0000) ─────────────────────

/// Chunk type: IP protocol family (1 byte: 2=IPv4, 10=IPv6).
const CHUNK_IP_FAMILY: u16 = 0x0001;
/// Chunk type: IP protocol ID (1 byte: 6=TCP, 17=UDP).
const CHUNK_IP_PROTO: u16 = 0x0002;
/// Chunk type: Source IPv4 address (4 bytes).
const CHUNK_SRC_IPV4: u16 = 0x0003;
/// Chunk type: Destination IPv4 address (4 bytes).
const CHUNK_DST_IPV4: u16 = 0x0004;
/// Chunk type: Source IPv6 address (16 bytes).
const CHUNK_SRC_IPV6: u16 = 0x0005;
/// Chunk type: Destination IPv6 address (16 bytes).
const CHUNK_DST_IPV6: u16 = 0x0006;
/// Chunk type: Source port (2 bytes, big-endian).
const CHUNK_SRC_PORT: u16 = 0x0007;
/// Chunk type: Destination port (2 bytes, big-endian).
const CHUNK_DST_PORT: u16 = 0x0008;
/// Chunk type: Timestamp seconds since epoch (4 bytes, big-endian).
const CHUNK_TS_SEC: u16 = 0x0009;
/// Chunk type: Timestamp microseconds (4 bytes, big-endian).
const CHUNK_TS_USEC: u16 = 0x000a;
/// Chunk type: Protocol type (1 byte: 1=SIP, 5=RTCP, 32=RTP).
const CHUNK_PROTO_TYPE: u16 = 0x000b;
/// Chunk type: Capture agent ID (4 bytes, big-endian).
const CHUNK_CAPTURE_ID: u16 = 0x000c;
/// Chunk type: Payload — the actual SIP/RTP message (variable length).
const CHUNK_PAYLOAD: u16 = 0x000f;
/// Chunk type: Correlation ID — typically the Call-ID (variable length).
const CHUNK_CORRELATION_ID: u16 = 0x0011;

/// HEP v3 magic bytes.
const HEP3_MAGIC: &[u8; 4] = b"HEP3";
/// HEP v3 fixed header length (magic + total length).
const HEP3_HEADER_LEN: usize = 6;
/// Minimum chunk size: 6-byte header with no data.
const CHUNK_HEADER_LEN: usize = 6;

/// HEP v2 version byte.
const HEP2_VERSION: u8 = 0x02;
/// Minimum HEP v2 header length for IPv4 (version + hdr_len + ports + IPs).
const HEP2_MIN_HEADER: usize = 16;

// ── DLT constant for raw IP ──────────────────────────────────────────

/// Pcap link type for raw IPv4/IPv6 (DLT_RAW). HEP packets have no
/// link-layer framing, so we present them as raw IP to the parser.
const DLT_RAW: i32 = 12;

// ── Public types ─────────────────────────────────────────────────────

/// Protocol type carried inside a HEP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HepProtocol {
    /// SIP signaling (protocol type 1).
    Sip,
    /// RTCP control packets (protocol type 5).
    Rtcp,
    /// RTP media packets (protocol type 32).
    Rtp,
    /// Unrecognized protocol type.
    Unknown(u8),
}

impl HepProtocol {
    /// Decode a HEP protocol type byte into the enum.
    fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Sip,
            5 => Self::Rtcp,
            32 => Self::Rtp,
            other => Self::Unknown(other),
        }
    }

    /// Encode the enum back to a HEP protocol type byte.
    fn to_byte(self) -> u8 {
        match self {
            Self::Sip => 1,
            Self::Rtcp => 5,
            Self::Rtp => 32,
            Self::Unknown(b) => b,
        }
    }
}

/// A parsed HEP packet with extracted metadata and payload.
#[derive(Debug, Clone)]
pub struct HepPacket {
    /// HEP version (2 or 3).
    pub version: u8,
    /// Source IP address from the original SIP/RTP flow.
    pub src_addr: IpAddr,
    /// Destination IP address from the original SIP/RTP flow.
    pub dst_addr: IpAddr,
    /// Source transport port.
    pub src_port: u16,
    /// Destination transport port.
    pub dst_port: u16,
    /// Timestamp of the captured packet.
    pub timestamp: DateTime<Utc>,
    /// Protocol type (SIP, RTP, RTCP, etc.).
    pub protocol: HepProtocol,
    /// The encapsulated payload (SIP message, RTP packet, etc.).
    pub payload: Vec<u8>,
    /// Correlation ID (typically Call-ID), if present (v3 only).
    pub correlation_id: Option<String>,
    /// Capture agent ID, if present (v3 only).
    pub capture_id: Option<u32>,
}

// ── Parsing ──────────────────────────────────────────────────────────

/// Parse a HEP packet from raw bytes.
///
/// Detects the version automatically:
/// - First 4 bytes == `"HEP3"` → HEP v3 (chunk-based)
/// - First byte == `0x02` → HEP v2 (fixed header)
///
/// # Errors
///
/// Returns an error if the packet is malformed, truncated, or
/// uses an unrecognized version.
pub fn parse_hep(data: &[u8]) -> Result<HepPacket> {
    if data.len() >= 4 && &data[..4] == HEP3_MAGIC {
        parse_hep_v3(data)
    } else if !data.is_empty() && data[0] == HEP2_VERSION {
        parse_hep_v2(data)
    } else {
        bail!("Not a HEP packet: unrecognized magic/version byte");
    }
}

/// Parse a HEP v3 (chunk-based) packet.
fn parse_hep_v3(data: &[u8]) -> Result<HepPacket> {
    ensure!(
        data.len() >= HEP3_HEADER_LEN,
        "HEP v3 packet too short: {} bytes (minimum {})",
        data.len(),
        HEP3_HEADER_LEN,
    );

    let total_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    ensure!(
        total_len <= data.len(),
        "HEP v3 total_length ({total_len}) exceeds packet size ({})",
        data.len(),
    );

    // Walk chunks
    let mut src_addr: Option<IpAddr> = None;
    let mut dst_addr: Option<IpAddr> = None;
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut ts_sec: u32 = 0;
    let mut ts_usec: u32 = 0;
    let mut protocol = HepProtocol::Unknown(0);
    let mut payload: Vec<u8> = Vec::new();
    let mut correlation_id: Option<String> = None;
    let mut capture_id: Option<u32> = None;

    let mut offset = HEP3_HEADER_LEN;
    while offset + CHUNK_HEADER_LEN <= total_len {
        let _vendor = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let chunk_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let chunk_len = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;

        ensure!(
            chunk_len >= CHUNK_HEADER_LEN,
            "HEP v3 chunk length ({chunk_len}) is smaller than header ({})",
            CHUNK_HEADER_LEN,
        );
        ensure!(
            offset + chunk_len <= total_len,
            "HEP v3 chunk at offset {offset} overflows packet (chunk_len={chunk_len}, remaining={})",
            total_len - offset,
        );

        let chunk_data = &data[offset + CHUNK_HEADER_LEN..offset + chunk_len];

        match chunk_type {
            CHUNK_IP_FAMILY => {
                // 1 byte: 2=IPv4, 10=IPv6 — informational, addresses come
                // from dedicated chunks.
            }
            CHUNK_IP_PROTO => {
                // 1 byte: 6=TCP, 17=UDP — informational for now.
            }
            CHUNK_SRC_IPV4 => {
                ensure!(chunk_data.len() >= 4, "SRC_IPV4 chunk too short");
                src_addr = Some(IpAddr::V4(Ipv4Addr::new(
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                )));
            }
            CHUNK_DST_IPV4 => {
                ensure!(chunk_data.len() >= 4, "DST_IPV4 chunk too short");
                dst_addr = Some(IpAddr::V4(Ipv4Addr::new(
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                )));
            }
            CHUNK_SRC_IPV6 => {
                ensure!(chunk_data.len() >= 16, "SRC_IPV6 chunk too short");
                let octets: [u8; 16] =
                    chunk_data[..16].try_into().context("SRC_IPV6 conversion")?;
                src_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            CHUNK_DST_IPV6 => {
                ensure!(chunk_data.len() >= 16, "DST_IPV6 chunk too short");
                let octets: [u8; 16] =
                    chunk_data[..16].try_into().context("DST_IPV6 conversion")?;
                dst_addr = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            CHUNK_SRC_PORT => {
                ensure!(chunk_data.len() >= 2, "SRC_PORT chunk too short");
                src_port = u16::from_be_bytes([chunk_data[0], chunk_data[1]]);
            }
            CHUNK_DST_PORT => {
                ensure!(chunk_data.len() >= 2, "DST_PORT chunk too short");
                dst_port = u16::from_be_bytes([chunk_data[0], chunk_data[1]]);
            }
            CHUNK_TS_SEC => {
                ensure!(chunk_data.len() >= 4, "TS_SEC chunk too short");
                ts_sec = u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]);
            }
            CHUNK_TS_USEC => {
                ensure!(chunk_data.len() >= 4, "TS_USEC chunk too short");
                ts_usec = u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]);
            }
            CHUNK_PROTO_TYPE => {
                ensure!(!chunk_data.is_empty(), "PROTO_TYPE chunk too short");
                protocol = HepProtocol::from_byte(chunk_data[0]);
            }
            CHUNK_CAPTURE_ID => {
                ensure!(chunk_data.len() >= 4, "CAPTURE_ID chunk too short");
                capture_id = Some(u32::from_be_bytes([
                    chunk_data[0],
                    chunk_data[1],
                    chunk_data[2],
                    chunk_data[3],
                ]));
            }
            CHUNK_PAYLOAD => {
                payload = chunk_data.to_vec();
            }
            CHUNK_CORRELATION_ID => {
                correlation_id = Some(
                    String::from_utf8_lossy(chunk_data)
                        .trim_end_matches('\0')
                        .to_string(),
                );
            }
            _ => {
                // Unknown chunk — skip silently for forward compatibility.
                log::trace!(
                    "Skipping unknown HEP v3 chunk: vendor={_vendor:#06x}, type={chunk_type:#06x}"
                );
            }
        }

        offset += chunk_len;
    }

    let timestamp = Utc
        .timestamp_opt(ts_sec as i64, ts_usec * 1000)
        .single()
        .unwrap_or_else(Utc::now);

    Ok(HepPacket {
        version: 3,
        src_addr: src_addr.context("HEP v3 packet missing source address chunk")?,
        dst_addr: dst_addr.context("HEP v3 packet missing destination address chunk")?,
        src_port,
        dst_port,
        timestamp,
        protocol,
        payload,
        correlation_id,
        capture_id,
    })
}

/// Parse a HEP v2 (fixed-header) packet.
fn parse_hep_v2(data: &[u8]) -> Result<HepPacket> {
    ensure!(
        data.len() >= 2,
        "HEP v2 packet too short to read header length",
    );

    let header_len = data[1] as usize;
    ensure!(
        header_len >= HEP2_MIN_HEADER,
        "HEP v2 header length ({header_len}) is below minimum ({HEP2_MIN_HEADER})",
    );
    ensure!(
        data.len() >= header_len,
        "HEP v2 packet truncated: have {} bytes, header says {header_len}",
        data.len(),
    );

    // Fixed layout after version + header_len:
    //   [2..4]  source port
    //   [4..6]  dest port
    //   [6..10] source IPv4
    //   [10..14] dest IPv4
    let src_port = u16::from_be_bytes([data[2], data[3]]);
    let dst_port = u16::from_be_bytes([data[4], data[5]]);
    let src_addr = IpAddr::V4(Ipv4Addr::new(data[6], data[7], data[8], data[9]));
    let dst_addr = IpAddr::V4(Ipv4Addr::new(data[10], data[11], data[12], data[13]));

    let payload = data[header_len..].to_vec();

    Ok(HepPacket {
        version: 2,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        timestamp: Utc::now(),
        protocol: HepProtocol::Sip, // v2 was SIP-only
        payload,
        correlation_id: None,
        capture_id: None,
    })
}

// ── HEP v3 builder (for sender) ─────────────────────────────────────

/// Build a HEP v3 packet from components.
///
/// Constructs a valid HEP v3 byte sequence with all required chunks.
/// Used by [`HepSender`] and by round-trip tests.
#[allow(clippy::too_many_arguments)]
pub fn build_hep_v3(
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: u16,
    dst_port: u16,
    timestamp: DateTime<Utc>,
    protocol: HepProtocol,
    capture_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut chunks: Vec<u8> = Vec::with_capacity(256 + payload.len());

    // IP protocol family
    let family: u8 = match src_addr {
        IpAddr::V4(_) => 2,
        IpAddr::V6(_) => 10,
    };
    append_chunk(&mut chunks, 0x0000, CHUNK_IP_FAMILY, &[family]);

    // IP protocol (assume UDP for SIP/RTP)
    append_chunk(&mut chunks, 0x0000, CHUNK_IP_PROTO, &[17]);

    // Source/destination addresses
    match src_addr {
        IpAddr::V4(v4) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_SRC_IPV4, &v4.octets());
        }
        IpAddr::V6(v6) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_SRC_IPV6, &v6.octets());
        }
    }
    match dst_addr {
        IpAddr::V4(v4) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_DST_IPV4, &v4.octets());
        }
        IpAddr::V6(v6) => {
            append_chunk(&mut chunks, 0x0000, CHUNK_DST_IPV6, &v6.octets());
        }
    }

    // Ports
    append_chunk(&mut chunks, 0x0000, CHUNK_SRC_PORT, &src_port.to_be_bytes());
    append_chunk(&mut chunks, 0x0000, CHUNK_DST_PORT, &dst_port.to_be_bytes());

    // Timestamp
    let ts_sec = timestamp.timestamp() as u32;
    let ts_usec = timestamp.timestamp_subsec_micros();
    append_chunk(&mut chunks, 0x0000, CHUNK_TS_SEC, &ts_sec.to_be_bytes());
    append_chunk(&mut chunks, 0x0000, CHUNK_TS_USEC, &ts_usec.to_be_bytes());

    // Protocol type
    append_chunk(&mut chunks, 0x0000, CHUNK_PROTO_TYPE, &[protocol.to_byte()]);

    // Capture agent ID
    append_chunk(
        &mut chunks,
        0x0000,
        CHUNK_CAPTURE_ID,
        &capture_id.to_be_bytes(),
    );

    // Payload
    append_chunk(&mut chunks, 0x0000, CHUNK_PAYLOAD, payload);

    // Build final packet: magic + total_length + chunks
    let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(HEP3_MAGIC);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&chunks);
    pkt
}

/// Append a single HEP v3 chunk to the buffer.
fn append_chunk(buf: &mut Vec<u8>, vendor: u16, chunk_type: u16, data: &[u8]) {
    let len = (CHUNK_HEADER_LEN + data.len()) as u16;
    buf.extend_from_slice(&vendor.to_be_bytes());
    buf.extend_from_slice(&chunk_type.to_be_bytes());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

// ── CIDR allowlist ──────────────────────────────────────────────────

/// A parsed CIDR range for IP allowlisting.
#[derive(Debug, Clone)]
pub struct CidrRange {
    /// Network address (masked).
    network: u128,
    /// Number of prefix bits.
    prefix_len: u8,
    /// Whether this is an IPv4 or IPv6 range.
    is_v4: bool,
}

impl CidrRange {
    /// Parse a CIDR string like "10.0.0.0/8" or "2001:db8::/32".
    ///
    /// # Errors
    ///
    /// Returns an error string if the CIDR notation is invalid.
    pub fn parse(cidr: &str) -> Result<Self, String> {
        let (addr_str, prefix_str) = cidr
            .split_once('/')
            .ok_or_else(|| format!("invalid CIDR '{cidr}': missing /prefix"))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix length in '{cidr}': {e}"))?;

        let addr: IpAddr = addr_str
            .parse()
            .map_err(|e| format!("invalid IP in '{cidr}': {e}"))?;

        let (ip_bits, is_v4, max_prefix) = match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4) as u128;
                (bits << 96, true, 32u8)
            }
            IpAddr::V6(v6) => (u128::from(v6), false, 128u8),
        };

        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_prefix} for '{cidr}'"
            ));
        }

        let mask = if prefix_len == 0 {
            0u128
        } else if is_v4 {
            let shift = 32 - prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (128 - prefix_len)
        };

        Ok(Self {
            network: ip_bits & mask,
            prefix_len,
            is_v4,
        })
    }

    /// Check whether an IP address falls within this CIDR range.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let ip_bits = match addr {
            IpAddr::V4(v4) => {
                if !self.is_v4 {
                    return false;
                }
                (u32::from(v4) as u128) << 96
            }
            IpAddr::V6(v6) => {
                if self.is_v4 {
                    return false;
                }
                u128::from(v6)
            }
        };

        let max_prefix = if self.is_v4 { 32u8 } else { 128u8 };
        let mask = if self.prefix_len == 0 {
            0u128
        } else if self.is_v4 {
            let shift = 32 - self.prefix_len;
            ((u32::MAX << shift) as u128) << 96
        } else {
            u128::MAX << (max_prefix - self.prefix_len)
        };

        (ip_bits & mask) == self.network
    }
}

/// Simple token-bucket rate limiter for HEP input.
struct HepRateLimiter {
    max_per_second: u64,
    count_this_second: u64,
    window_start: Instant,
    dropped_total: u64,
}

impl HepRateLimiter {
    fn new(max_per_second: u64) -> Self {
        Self {
            max_per_second,
            count_this_second: 0,
            window_start: Instant::now(),
            dropped_total: 0,
        }
    }

    /// Returns `true` if the message should be processed, `false` if rate-limited.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= 1 {
            self.window_start = now;
            self.count_this_second = 0;
        }

        self.count_this_second += 1;
        if self.count_this_second > self.max_per_second {
            self.dropped_total += 1;
            log::debug!(
                "HEP rate limit exceeded ({}/s), dropping packet (total dropped: {})",
                self.max_per_second,
                self.dropped_total
            );
            return false;
        }
        true
    }
}

// ── HEP capture (receiver) ──────────────────────────────────────────

/// HEP listener: binds a UDP socket and receives HEP packets.
///
/// Each received HEP packet is parsed and converted into a [`Packet`] struct
/// (using `DLT_RAW` since HEP carries no link-layer framing) and sent through
/// the channel for downstream processing.
///
/// The listener checks [`signals::shutdown_requested`] each iteration and
/// respects the `count` and `duration` limits from `config`.
///
/// # Default bind address
///
/// Per design decision D18, the default bind address is `127.0.0.1:9060`.
///
/// # Errors
///
/// Returns an error if the UDP socket cannot be bound.
pub fn capture_hep(
    bind_addr: &str,
    config: &CaptureConfig,
    tx: Sender<Packet>,
    allowlist: &[CidrRange],
    rate_limit: u64,
) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .with_context(|| format!("Failed to bind HEP listener on '{bind_addr}'"))?;

    // 100ms timeout so we can check shutdown_requested() frequently
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("Failed to set socket read timeout")?;

    let start = Instant::now();
    let mut count: u64 = 0;
    let mut buf = vec![0u8; 65535];
    let mut rate_limiter = HepRateLimiter::new(rate_limit);

    if !allowlist.is_empty() {
        log::info!("HEP allowlist active: {} CIDR range(s)", allowlist.len());
    }

    log::info!("HEP listener started on {bind_addr}");

    loop {
        if signals::shutdown_requested() {
            log::debug!("Shutdown requested, stopping HEP listener");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            log::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            log::debug!("Reached duration limit ({duration:?})");
            break;
        }

        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok((n, peer)) => (n, peer),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => {
                log::error!("HEP socket recv error: {e}");
                return Err(e).context("Fatal HEP socket error");
            }
        };

        // Check allowlist
        if !allowlist.is_empty() {
            let peer_ip = peer.ip();
            if !allowlist.iter().any(|cidr| cidr.contains(peer_ip)) {
                log::debug!("Dropping HEP packet from non-allowed source {peer_ip}");
                continue;
            }
        }

        // Check rate limit
        if !rate_limiter.allow() {
            continue;
        }

        let hep = match parse_hep(&buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                log::debug!("Skipping malformed HEP packet ({n} bytes): {e}");
                continue;
            }
        };

        // Convert to a Packet that the rest of the pipeline can process.
        // HEP already provides parsed metadata, so we pass the *payload*
        // (the inner SIP/RTP message) as the packet data. We use DLT_RAW
        // because there's no Ethernet framing.
        let packet = Packet::new(
            hep.timestamp,
            hep.payload,
            n,
            n,
            Some(format!("hep:{bind_addr}")),
            DLT_RAW,
        );

        if tx.send(packet).is_err() {
            log::debug!("Receiver dropped, stopping HEP listener");
            break;
        }

        count += 1;
    }

    log::info!("HEP listener on {bind_addr} finished: {count} packets");
    Ok(())
}

// ── HEP sender ───────────────────────────────────────────────────────

/// HEP v3 sender: encapsulates SIP messages as HEP v3 and sends via UDP.
///
/// Create one `HepSender` per destination. Each [`send`](HepSender::send)
/// call builds a HEP v3 packet and transmits it over UDP.
pub struct HepSender {
    /// Underlying UDP socket (connected to the destination).
    socket: UdpSocket,
    /// Capture agent ID included in every HEP packet.
    capture_id: u32,
}

impl HepSender {
    /// Create a new HEP sender targeting `dest_addr` (e.g., `"10.0.0.50:9060"`).
    ///
    /// Binds an ephemeral local UDP socket and connects it to the destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be created or connected.
    pub fn new(dest_addr: &str, capture_id: u32) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind ephemeral UDP socket for HEP sender")?;
        socket
            .connect(dest_addr)
            .with_context(|| format!("Failed to connect HEP sender to '{dest_addr}'"))?;
        Ok(Self { socket, capture_id })
    }

    /// Encapsulate and send a SIP message as a HEP v3 packet.
    ///
    /// Builds the HEP v3 envelope from the SIP message's network metadata
    /// (addresses, ports, timestamp) and the raw SIP bytes, then sends it
    /// over the connected UDP socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP send fails.
    pub fn send(&self, msg: &crate::sip::message::SipMessage) -> Result<()> {
        let pkt = build_hep_v3(
            msg.src_addr,
            msg.dst_addr,
            msg.src_port,
            msg.dst_port,
            msg.timestamp,
            HepProtocol::Sip,
            self.capture_id,
            &msg.raw,
        );

        self.socket
            .send(&pkt)
            .with_context(|| "Failed to send HEP v3 packet")?;

        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Helper: build a minimal valid HEP v3 packet with the given fields.
    fn make_hep_v3(
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        ts_sec: u32,
        ts_usec: u32,
        proto: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut chunks = Vec::new();

        // IP family
        let family: u8 = match src {
            IpAddr::V4(_) => 2,
            IpAddr::V6(_) => 10,
        };
        append_chunk(&mut chunks, 0, CHUNK_IP_FAMILY, &[family]);

        // IP proto (UDP)
        append_chunk(&mut chunks, 0, CHUNK_IP_PROTO, &[17]);

        // Addresses
        match src {
            IpAddr::V4(v4) => append_chunk(&mut chunks, 0, CHUNK_SRC_IPV4, &v4.octets()),
            IpAddr::V6(v6) => append_chunk(&mut chunks, 0, CHUNK_SRC_IPV6, &v6.octets()),
        }
        match dst {
            IpAddr::V4(v4) => append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &v4.octets()),
            IpAddr::V6(v6) => append_chunk(&mut chunks, 0, CHUNK_DST_IPV6, &v6.octets()),
        }

        // Ports
        append_chunk(&mut chunks, 0, CHUNK_SRC_PORT, &src_port.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_DST_PORT, &dst_port.to_be_bytes());

        // Timestamp
        append_chunk(&mut chunks, 0, CHUNK_TS_SEC, &ts_sec.to_be_bytes());
        append_chunk(&mut chunks, 0, CHUNK_TS_USEC, &ts_usec.to_be_bytes());

        // Protocol type
        append_chunk(&mut chunks, 0, CHUNK_PROTO_TYPE, &[proto]);

        // Capture ID
        append_chunk(&mut chunks, 0, CHUNK_CAPTURE_ID, &42u32.to_be_bytes());

        // Payload
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, payload);

        // Assemble final packet
        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        let mut pkt = Vec::new();
        pkt.extend_from_slice(HEP3_MAGIC);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&chunks);
        pkt
    }

    /// Helper: build a minimal HEP v2 packet.
    fn make_hep_v2(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let header_len: u8 = 16; // version(1) + hdr_len(1) + ports(4) + ips(8) + 2 padding
        let mut pkt = Vec::new();
        pkt.push(HEP2_VERSION);
        pkt.push(header_len);
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        // Pad to header_len (already at 14 bytes; need 2 more)
        pkt.extend_from_slice(&[0u8; 2]);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_valid_hep_v3_ipv4() {
        let sip_payload = b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n";
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let data = make_hep_v3(src, dst, 5060, 5061, 1700000000, 123456, 1, sip_payload);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 3);
        assert_eq!(hep.src_addr, src);
        assert_eq!(hep.dst_addr, dst);
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5061);
        assert_eq!(hep.protocol, HepProtocol::Sip);
        assert_eq!(hep.payload, sip_payload);
        assert_eq!(hep.capture_id, Some(42));
        assert_eq!(hep.timestamp.timestamp(), 1700000000);
    }

    #[test]
    fn parse_valid_hep_v3_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let payload = b"SIP/2.0 200 OK\r\n\r\n";

        let data = make_hep_v3(src, dst, 5060, 5080, 1700000000, 0, 1, payload);

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 3);
        assert_eq!(hep.src_addr, src);
        assert_eq!(hep.dst_addr, dst);
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5080);
    }

    #[test]
    fn parse_valid_hep_v2() {
        let payload = b"REGISTER sip:example.com SIP/2.0\r\n\r\n";
        let data = make_hep_v2(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 20),
            5060,
            5060,
            payload,
        );

        let hep = parse_hep(&data).expect("parse should succeed");
        assert_eq!(hep.version, 2);
        assert_eq!(hep.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(hep.dst_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)));
        assert_eq!(hep.src_port, 5060);
        assert_eq!(hep.dst_port, 5060);
        assert_eq!(hep.protocol, HepProtocol::Sip);
        assert_eq!(hep.payload, payload);
    }

    #[test]
    fn parse_truncated_hep_v3_errors() {
        // Too short to even have the header
        let data = b"HEP3\x00";
        assert!(parse_hep(data).is_err());
    }

    #[test]
    fn parse_hep_v3_bad_total_length() {
        // total_length claims 1000 bytes but we only have 6
        let mut data = Vec::new();
        data.extend_from_slice(b"HEP3");
        data.extend_from_slice(&1000u16.to_be_bytes());
        assert!(parse_hep(&data).is_err());
    }

    #[test]
    fn parse_hep_v3_missing_src_addr() {
        // Build a v3 packet with no source address chunks
        let mut chunks = Vec::new();
        append_chunk(&mut chunks, 0, CHUNK_DST_IPV4, &[10, 0, 0, 1]);
        append_chunk(&mut chunks, 0, CHUNK_PAYLOAD, b"test");

        let total_len = (HEP3_HEADER_LEN + chunks.len()) as u16;
        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        data.extend_from_slice(&total_len.to_be_bytes());
        data.extend_from_slice(&chunks);

        let err = parse_hep(&data).unwrap_err();
        assert!(
            format!("{err}").contains("source address"),
            "Error should mention missing source address, got: {err}"
        );
    }

    #[test]
    fn parse_non_hep_data_errors() {
        assert!(parse_hep(b"").is_err());
        assert!(parse_hep(b"\x00\x00\x00\x00").is_err());
        assert!(parse_hep(b"HTTP/1.1 200 OK").is_err());
    }

    #[test]
    fn parse_hep_v2_truncated() {
        // Just the version byte
        assert!(parse_hep(&[0x02]).is_err());
        // Header says 16 bytes but only 10 available
        assert!(parse_hep(&[0x02, 16, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn build_and_parse_round_trip_ipv4() {
        let src = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2));
        let ts = Utc.timestamp_opt(1700000000, 500_000_000).single().unwrap();
        let payload = b"INVITE sip:alice@example.com SIP/2.0\r\n\r\n";

        let built = build_hep_v3(src, dst, 5060, 5061, ts, HepProtocol::Sip, 99, payload);
        let parsed = parse_hep(&built).expect("round-trip parse should succeed");

        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
        assert_eq!(parsed.src_port, 5060);
        assert_eq!(parsed.dst_port, 5061);
        assert_eq!(parsed.protocol, HepProtocol::Sip);
        assert_eq!(parsed.capture_id, Some(99));
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.timestamp.timestamp(), 1700000000);
        // Microsecond precision: 500_000_000 ns = 500_000 us
        assert_eq!(parsed.timestamp.timestamp_subsec_micros(), 500_000);
    }

    #[test]
    fn build_and_parse_round_trip_ipv6() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        let ts = Utc.timestamp_opt(1700000000, 0).single().unwrap();
        let payload = b"BYE sip:test@example.com SIP/2.0\r\n\r\n";

        let built = build_hep_v3(src, dst, 6000, 7000, ts, HepProtocol::Rtp, 1, payload);
        let parsed = parse_hep(&built).expect("round-trip parse should succeed");

        assert_eq!(parsed.src_addr, src);
        assert_eq!(parsed.dst_addr, dst);
        assert_eq!(parsed.src_port, 6000);
        assert_eq!(parsed.dst_port, 7000);
        assert_eq!(parsed.protocol, HepProtocol::Rtp);
    }

    #[test]
    fn hep_protocol_round_trip() {
        assert_eq!(HepProtocol::from_byte(1), HepProtocol::Sip);
        assert_eq!(HepProtocol::from_byte(5), HepProtocol::Rtcp);
        assert_eq!(HepProtocol::from_byte(32), HepProtocol::Rtp);
        assert_eq!(HepProtocol::from_byte(99), HepProtocol::Unknown(99));

        assert_eq!(HepProtocol::Sip.to_byte(), 1);
        assert_eq!(HepProtocol::Rtcp.to_byte(), 5);
        assert_eq!(HepProtocol::Rtp.to_byte(), 32);
        assert_eq!(HepProtocol::Unknown(42).to_byte(), 42);
    }

    #[test]
    fn hep_v3_chunk_overflow_rejected() {
        // Build a packet where a chunk claims to be longer than remaining data
        let mut data = Vec::new();
        data.extend_from_slice(HEP3_MAGIC);
        // total_len = 6 (header) + 6 (one chunk header that claims 100 bytes) = 12
        // but the chunk says it's 100 bytes, which overflows
        let total_len: u16 = 12;
        data.extend_from_slice(&total_len.to_be_bytes());
        // chunk: vendor=0, type=1, length=100
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&100u16.to_be_bytes());

        assert!(parse_hep(&data).is_err());
    }
}
