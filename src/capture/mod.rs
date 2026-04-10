//! Packet capture orchestration for sipnab.
//!
//! This module coordinates live device capture, pcap file reading, and output
//! writing. It provides [`start_capture`] as the main entry point, which spawns
//! a capture thread and returns a [`CaptureHandle`] for lifecycle management.

pub mod file;
pub mod live;
pub mod packet;
pub mod parse;
pub mod reassembly;
pub mod writer;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

pub use packet::Packet;
pub use parse::ParsedPacket;
pub use writer::PcapWriter;

use parse::parse_packet;
use reassembly::{FragmentReassembler, TcpReassembler};

/// Describes where packets come from.
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
        path: PathBuf,
    },
    /// Receive packets via HEP (Homer Encapsulation Protocol).
    Hep {
        /// Address to bind the HEP listener on.
        bind_addr: String,
    },
}

/// Aggregated configuration for the capture subsystem.
///
/// Combines CLI flags and config file values into a single struct consumed
/// by the capture thread.
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
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: 65535,
            buffer_mb: 2,
            bpf_filter: None,
            count: None,
            duration: None,
        }
    }
}

/// Handle to a running capture thread.
///
/// Provides the [`JoinHandle`](thread::JoinHandle) for waiting on the capture
/// thread and the capture source metadata.
pub struct CaptureHandle {
    /// The spawned capture thread.
    pub thread: thread::JoinHandle<Result<()>>,
    /// Which source this handle is capturing from.
    pub source: CaptureSource,
}

/// Start a capture from the given source, sending packets into `tx`.
///
/// Spawns a dedicated thread for the capture loop and returns a
/// [`CaptureHandle`] immediately. The capture runs until shutdown is
/// signaled, limits are reached, or (for files) EOF is hit.
///
/// # Errors
///
/// Returns an error if the source configuration is invalid (e.g., HEP
/// without the `hep` feature). Capture-thread errors are returned when
/// joining the handle.
pub fn start_capture(
    source: CaptureSource,
    config: CaptureConfig,
    tx: Sender<Packet>,
) -> Result<CaptureHandle> {
    let source_clone = source.clone();

    let thread = match &source {
        CaptureSource::Live { device } => {
            let device = device.clone();
            thread::Builder::new()
                .name(format!("capture-{device}"))
                .spawn(move || live::capture_live(&device, &config, tx))
                .context("Failed to spawn live capture thread")?
        }
        CaptureSource::File { path } => {
            let path = path.clone();
            thread::Builder::new()
                .name("capture-file".to_string())
                .spawn(move || file::capture_file(&path, &config, tx))
                .context("Failed to spawn file reader thread")?
        }
        CaptureSource::Hep { bind_addr } => {
            let _addr = bind_addr.clone();
            anyhow::bail!("HEP capture is not yet implemented");
        }
    };

    Ok(CaptureHandle {
        thread,
        source: source_clone,
    })
}

/// Stateful packet processing pipeline.
///
/// Combines header parsing, IP fragment reassembly, and TCP segment
/// reassembly into a single processing step. Feed raw [`Packet`]s in and
/// get back zero or more [`ParsedPacket`]s ready for upper-layer parsing.
pub struct PacketProcessor {
    fragment_reassembler: FragmentReassembler,
    tcp_reassembler: TcpReassembler,
}

impl PacketProcessor {
    /// Create a new packet processor with default reassembly limits.
    pub fn new() -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::new(),
            tcp_reassembler: TcpReassembler::new(),
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
                log::debug!("Skipping unparseable packet: {e}");
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
                    completed.payload = reassembled;
                    completed.fragment_offset = Some(0);
                    completed.more_fragments = false;
                    vec![completed]
                }
                None => Vec::new(),
            };
        }

        // TCP: feed into reassembler
        if parsed.transport == parse::TransportProto::Tcp {
            let flushed = self.tcp_reassembler.insert(&parsed);
            if flushed.is_empty() {
                return Vec::new();
            }
            return flushed
                .into_iter()
                .map(|payload| {
                    let mut p = parsed.clone();
                    p.payload = payload;
                    p
                })
                .collect();
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
    }
}

impl Default for PacketProcessor {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn default_capture_config() {
        let config = CaptureConfig::default();
        assert_eq!(config.snaplen, 65535);
        assert_eq!(config.buffer_mb, 2);
        assert!(config.bpf_filter.is_none());
        assert!(config.count.is_none());
        assert!(config.duration.is_none());
    }

    #[test]
    fn capture_source_debug() {
        // Ensure CaptureSource variants can be debug-printed
        let live = CaptureSource::Live {
            device: "eth0".to_string(),
        };
        let file = CaptureSource::File {
            path: PathBuf::from("/tmp/test.pcap"),
        };
        let hep = CaptureSource::Hep {
            bind_addr: "0.0.0.0:9060".to_string(),
        };

        assert!(format!("{live:?}").contains("eth0"));
        assert!(format!("{file:?}").contains("test.pcap"));
        assert!(format!("{hep:?}").contains("9060"));
    }
}
