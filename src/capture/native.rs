// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native-only capture surface: live device / pcap-file / HEP sources and
//! the capture-thread orchestration.
//!
//! Split out of `capture::mod` (WS2d) so the ~7 `#[cfg(feature = "native")]`
//! gates on these items collapse to a single gate on the `mod native` line
//! in the parent; `capture` re-exports everything here with `pub use`.

use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use super::channel::PacketTx;
#[cfg(feature = "hep")]
use super::hep;
use super::{device, file, live};

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
        path: std::path::PathBuf,
    },
    /// Receive packets via HEP (Homer Encapsulation Protocol).
    Hep {
        /// Address to bind the HEP listener on.
        bind_addr: String,
        /// CIDR allowlist for source IP filtering.
        #[cfg(feature = "hep")]
        allowlist: Vec<hep::CidrRange>,
        /// Maximum HEP packets per second across all peers (0 = unlimited).
        rate_limit: u64,
        /// Maximum HEP packets per second from any single source IP
        /// (0 = disabled; global ceiling still applies).
        per_peer_rate_limit: u64,
        /// Receiver-side shared secret. When set, incoming HEP packets must
        /// carry a matching 0x000e auth-key chunk or they are dropped.
        auth_key: Option<String>,
        /// How the 0x000e chunk is interpreted (verbatim secret vs HMAC token).
        #[cfg(feature = "hep")]
        auth_mode: crate::cli::HepAuthMode,
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
    /// Memory budget (MiB) for the in-flight packet queue between capture and
    /// processing. Converted to a packet-count cap via [`Self::channel_capacity`].
    pub buffer_budget_mb: u32,
    /// Put a named interface into promiscuous mode. The `"any"` pseudo-device is
    /// never promiscuous regardless of this flag. Disabled by `--no-promisc`.
    pub promisc: bool,
}

impl Default for CaptureConfig {
    /// Defaults matching the CLI: full 65535 snaplen, 2 MiB kernel buffer,
    /// no filter/limits, no replay, 64 MiB queue budget, promiscuous on.
    fn default() -> Self {
        Self {
            snaplen: 65535,
            buffer_mb: 2,
            bpf_filter: None,
            count: None,
            duration: None,
            replay: false,
            buffer_budget_mb: 64,
            promisc: true,
        }
    }
}

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
/// without the `hep` feature) or the thread cannot be spawned.
/// Capture-thread errors are returned when joining the handle.
///
/// # Arguments
///
/// * `source` - live device, pcap file, or HEP listener to capture from.
/// * `config` - capture parameters passed through to the capture loop.
/// * `tx` - channel the capture thread sends packets into.
/// * `ready_tx` - optional readiness signal (see above).
///
/// # Side effects
///
/// Spawns a named OS thread that owns the capture resource and runs until a
/// stop condition.
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
            per_peer_rate_limit,
            auth_key,
            auth_mode,
        } => {
            let addr = bind_addr.clone();
            let allow = allowlist.clone();
            let rate = *rate_limit;
            let per_peer = *per_peer_rate_limit;
            let auth = auth_key.clone();
            let mode = *auth_mode;
            thread::Builder::new()
                .name("capture-hep".to_string())
                .spawn(move || {
                    let opts = hep::HepListenerOpts {
                        allowlist: &allow,
                        rate_limit: rate,
                        per_peer_rate_limit: per_peer,
                        auth_key: auth.as_deref(),
                        auth_mode: mode,
                    };
                    hep::capture_hep(&addr, &config, tx, &opts, ready_tx)
                })
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
///
/// # Arguments
///
/// * `devices` - comma-separated interface list (validated before any
///   thread is spawned; a single device falls back to `start_capture`).
/// * `config` - capture parameters, cloned into each per-device thread.
/// * `tx` - shared channel all capture threads send into.
/// * `ready_tx` - optional aggregated readiness signal (see above).
///
/// # Errors
///
/// Fails on a malformed device spec or when a thread cannot be spawned. The
/// coordinator thread's result (joined via the handle) carries the first
/// per-device capture error, if any.
///
/// # Side effects
///
/// Spawns one coordinator thread plus one capture thread per device, and
/// logs the interface roster at info level.
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

/// Tests for capture configuration defaults, channel-capacity derivation,
/// and capture-thread startup/validation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::channel;

    /// `CaptureConfig::default()` matches the documented CLI defaults.
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

    /// `channel_capacity` scales with the budget and clamps to the
    /// 10k floor / 5M ceiling, monotonically in between.
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

    /// `CaptureSource` variants debug-print their device/path.
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

    /// A file capture signals readiness (before privileges would drop) and
    /// then delivers the fixture's packets.
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
    /// A doubled comma in the device spec is rejected before any capture
    /// thread spawns.
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

    /// A whitespace-only device spec is rejected.
    #[test]
    fn multi_capture_rejects_empty_device_spec() {
        let (tx, _rx) = channel::packet_channel(1 << 20);
        assert!(start_multi_capture("   ", CaptureConfig::default(), tx, None).is_err());
        // (Ok(_) is not Debug; .is_err() avoids unwrapping the handle.)
    }
}
