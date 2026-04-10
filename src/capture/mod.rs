//! Packet capture orchestration for sipnab.
//!
//! This module coordinates live device capture, pcap file reading, and output
//! writing. It provides [`start_capture`] as the main entry point, which spawns
//! a capture thread and returns a [`CaptureHandle`] for lifecycle management.

#[cfg(feature = "tls")]
pub mod decrypt;
pub mod file;
#[cfg(feature = "hep")]
pub mod hep;
pub mod live;
pub mod packet;
pub mod parse;
pub mod reassembly;
#[cfg(feature = "tls")]
pub mod tls;
pub mod websocket;
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
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: 65535,
            buffer_mb: 2,
            bpf_filter: None,
            count: None,
            duration: None,
            replay: false,
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
pub fn start_capture(
    source: CaptureSource,
    config: CaptureConfig,
    tx: Sender<Packet>,
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
pub fn start_multi_capture(
    devices: &str,
    config: CaptureConfig,
    tx: Sender<Packet>,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<CaptureHandle> {
    let device_list: Vec<String> = devices.split(',').map(|s| s.trim().to_string()).collect();

    if device_list.is_empty() {
        anyhow::bail!("No devices specified for multi-device capture");
    }

    if device_list.len() == 1 {
        // Single device: fall back to normal capture
        return start_capture(
            CaptureSource::Live {
                device: device_list.into_iter().next().unwrap(),
            },
            config,
            tx,
            ready_tx,
        );
    }

    log::info!(
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
                        log::warn!("Capture thread error: {e}");
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                    Err(_) => {
                        log::error!("Capture thread panicked");
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
}

impl PacketProcessor {
    /// Create a new packet processor with default reassembly limits.
    pub fn new() -> Self {
        Self {
            fragment_reassembler: FragmentReassembler::new(),
            tcp_reassembler: TcpReassembler::new(),
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
        assert!(format!("{live:?}").contains("eth0"));
        assert!(format!("{file:?}").contains("test.pcap"));
    }

    #[test]
    fn ready_signal_sent_on_file_capture() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("udp_5060.pcap");
        if !fixture.exists() {
            eprintln!("Skipping: fixture not found at {}", fixture.display());
            return;
        }

        let (pkt_tx, pkt_rx) = crossbeam_channel::unbounded();
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
}
