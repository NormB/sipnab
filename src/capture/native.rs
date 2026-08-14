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
use crate::signals;

/// Describes where packets come from.
#[derive(Debug, Clone)]
pub enum CaptureSource {
    /// Live capture from a network interface.
    Live {
        /// Device name (e.g., "eth0", "en0").
        device: String,
    },
    /// Read packets from one or more capture files.
    ///
    /// A list rather than a single path because `tcpdump -C -W` splits a
    /// capture across a ring buffer, and a call whose INVITE lands in one file
    /// and BYE in the next is only reconstructable by feeding both into the
    /// same dialog store. Ordered by first-packet timestamp — see
    /// [`crate::capture::input_set`] for why filename order is wrong.
    File {
        /// Capture files, in the order they are to be read.
        paths: Vec<std::path::PathBuf>,
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
        /// Distinct source IPs one counting window may hold at once
        /// (`[limits] max_tracked_peers`).
        max_tracked_peers: usize,
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
    /// Ask libpcap to hand each packet over the moment it arrives
    /// (`pcap_set_immediate_mode`) instead of letting the kernel accumulate
    /// them in the capture ring.
    ///
    /// This is not a latency dial with no other consequences: on Linux it also
    /// picks the ring format. libpcap's `prepare_tpacket_socket` guards
    /// TPACKET_V3 with `if (!handle->opt.immediate)` — a V3 block cannot be
    /// handed up early, so asking for immediate delivery forces TPACKET_V2.
    /// V2 sizes every ring slot from the snaplen, and sipnab's default snaplen
    /// is 65535, so on the default `any` device a 64 MiB ring is carved into
    /// only about a thousand slots. V3 sizes its frames from a fixed maximum
    /// instead and has no such capacity cliff.
    ///
    /// So the value follows who is reading the packets, decided in
    /// `app::bootstrap` from the run mode: the interactive TUI keeps immediate
    /// mode because a human is watching individual messages land, and a
    /// headless capture gives it up to get the deeper ring. Ignored by the file
    /// and HEP sources, which have no kernel ring.
    pub immediate_mode: bool,
}

/// Default kernel capture buffer, in MiB — the ring libpcap fills and sipnab
/// drains ([`CaptureConfig::buffer_mb`], `-B`/`--buffer`).
///
/// **This is the single most important anti-drop setting sipnab has**, which is
/// why it is a named constant read by both `CaptureConfig::default` and the CLI
/// resolution in `app::bootstrap` rather than a literal written twice.
///
/// It was 2 MiB, inherited from libpcap's own default, and 2 MiB is a default
/// for a debugging sniffer rather than a capture tool: roughly 1,400 full-MTU
/// frames, which at the rates sipnab is benchmarked at is **under a millisecond
/// of slack**. Any scheduling hiccup and the kernel starts discarding — and
/// before `KERNEL_DROPPED` existed nothing said so, which is how a lossy
/// capture came to look like a clean one.
///
/// 64 MiB buys roughly 45,000 full-MTU frames — tens of milliseconds of
/// tolerance, enough to ride out a scheduler delay or a slow consumer. The cost
/// is 64 MiB of kernel memory **per capture device**, so a `--multi-device` run
/// over eight interfaces reserves half a gigabyte; lower it with `-B` there.
/// Small or memory-constrained hosts do not need to: an allocation this size
/// can fail on them, and [`super::live`] retries with progressively smaller
/// rings rather than refusing to capture.
pub const DEFAULT_BUFFER_MB: u32 = 64;

impl Default for CaptureConfig {
    /// Defaults matching the CLI: full 65535 snaplen,
    /// [`DEFAULT_BUFFER_MB`] kernel buffer, no filter/limits, no replay,
    /// 64 MiB queue budget, promiscuous on, immediate mode on.
    ///
    /// `immediate_mode: true` is the interactive answer, which is both the CLI
    /// default (no `-N` means the TUI) and what every capture did
    /// unconditionally before the choice existed — so a caller that builds a
    /// config from `default()` and never touches the field captures exactly as
    /// it always has, rather than silently switching ring format.
    fn default() -> Self {
        Self {
            snaplen: 65535,
            buffer_mb: DEFAULT_BUFFER_MB,
            bpf_filter: None,
            count: None,
            duration: None,
            replay: false,
            buffer_budget_mb: 64,
            promisc: true,
            immediate_mode: true,
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

/// Stop the capture thread and wait for it, for startup paths that fail after
/// the thread is already running.
///
/// # Arguments
///
/// * `handle` — the capture thread's join handle.
/// * `rx` — the packet receiver, dropped so the thread observes a disconnected
///   channel.
///
/// # Side effects
///
/// Sets the global shutdown flag and blocks until the capture thread returns.
///
/// Every fatal exit between [`start_capture`] and the end of the receive loop
/// has to come through here. `std::process::exit` runs no destructors and joins
/// no threads, so exiting directly abandons a thread that still holds an open
/// capture source — ThreadSanitizer reports it as a thread leak, and
/// `sipnab -I /nonexistent.pcap` was enough to produce one.
///
/// Both stop signals are used deliberately: dropping `rx` ends a thread blocked
/// on a send, and the shutdown flag ends one blocked elsewhere in its loop — a
/// live capture waiting out its read timeout reaches the flag check first. The
/// join is unbounded, matching the one the batch receive loop already performs
/// at end of capture.
pub fn stop_and_join(handle: CaptureHandle, rx: super::channel::PacketRx) {
    crate::signals::request_shutdown();
    drop(rx);
    match handle.thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Capture thread error during shutdown: {e}"),
        Err(_) => tracing::error!("Capture thread panicked during shutdown"),
    }
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
        CaptureSource::File { paths } => {
            let paths = paths.clone();
            thread::Builder::new()
                .name("capture-file".to_string())
                .spawn(move || file::capture_files(&paths, &config, tx, ready_tx))
                .context("Failed to spawn file reader thread")?
        }
        #[cfg(feature = "hep")]
        CaptureSource::Hep {
            bind_addr,
            allowlist,
            rate_limit,
            per_peer_rate_limit,
            max_tracked_peers,
            auth_key,
            auth_mode,
        } => {
            let addr = bind_addr.clone();
            let allow = allowlist.clone();
            let rate = *rate_limit;
            let per_peer = *per_peer_rate_limit;
            let peer_capacity = *max_tracked_peers;
            let auth = auth_key.clone();
            let mode = *auth_mode;
            thread::Builder::new()
                .name("capture-hep".to_string())
                .spawn(move || {
                    let opts = hep::HepListenerOpts {
                        allowlist: &allow,
                        rate_limit: rate,
                        per_peer_rate_limit: per_peer,
                        max_tracked_peers: peer_capacity,
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
/// A multi-device capture is one logical session: if **any** device fails to
/// open, the siblings that did open are signaled to stop (via the global
/// shutdown flag their capture loops poll), and a single error naming the
/// failed device is surfaced — on `ready_tx` (when provided) and as the
/// coordinator thread's result — matching how a single-device open failure
/// surfaces. No partial capture is left running.
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
/// Fails on a malformed device spec or when the coordinator thread cannot be
/// spawned. The coordinator thread's result (joined via the handle) carries
/// the device-open error (after tearing the siblings down, see above) or,
/// once running, the first per-device capture error, if any.
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
            run_multi_capture(
                &device_list,
                &config,
                tx,
                ready_tx,
                spawn_live_device,
                signals::request_shutdown,
            )
        })
        .context("Failed to spawn multi-capture coordinator thread")?;

    Ok(CaptureHandle { thread, source })
}

/// One-shot readiness signal a per-device capture thread reports through.
type DeviceReadyTx = crossbeam_channel::Sender<Result<(), String>>;

/// Spawn the real per-device live-capture thread (production `spawn_device`
/// for [`run_multi_capture`]).
fn spawn_live_device(
    device: String,
    config: CaptureConfig,
    tx: PacketTx,
    ready: DeviceReadyTx,
) -> Result<thread::JoinHandle<Result<()>>> {
    let dev_ctx = device.clone(); // for error context
    thread::Builder::new()
        .name(format!("capture-{device}"))
        .spawn(move || live::capture_live(&device, &config, tx, Some(ready)))
        .with_context(|| format!("Failed to spawn capture thread for '{dev_ctx}'"))
}

/// Body of the multi-capture coordinator thread: spawn one capture thread per
/// device (via `spawn_device`), aggregate their readiness, then reap them.
///
/// Parameterized over the device spawner and the sibling-stop signal so the
/// startup/teardown logic is testable without capture privileges; production
/// passes [`spawn_live_device`] and [`signals::request_shutdown`].
fn run_multi_capture<S, K>(
    device_list: &[String],
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
    spawn_device: S,
    stop_siblings: K,
) -> Result<()>
where
    S: Fn(String, CaptureConfig, PacketTx, DeviceReadyTx) -> Result<thread::JoinHandle<Result<()>>>,
    K: Fn(),
{
    let mut handles = Vec::new();
    let mut per_device_ready_rxs = Vec::new();
    let mut first_err: Option<String> = None;

    for dev in device_list {
        // Each sub-thread gets its own ready signal so we can
        // aggregate them before signaling the caller.
        let (dev_ready_tx, dev_ready_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);
        per_device_ready_rxs.push((dev.clone(), dev_ready_rx));

        match spawn_device(dev.clone(), config.clone(), tx.clone(), dev_ready_tx) {
            Ok(h) => handles.push(h),
            Err(e) => {
                // A failed spawn dooms the session like a failed open: stop
                // spawning, tear the started siblings down below.
                first_err = Some(format!("{e:#}"));
                break;
            }
        }
    }

    // Drop our copy of tx so the channel closes when all capture
    // threads finish.
    drop(tx);

    // Aggregate readiness from every spawned device — even when the caller
    // did not ask for a ready signal, because a failed open must still tear
    // the sibling captures down rather than leave a partial capture running.
    // (`handles` may be shorter than the rx list after a spawn failure; a
    // dropped ready sender then surfaces as a disconnect, which the spawn
    // error already outranks via `first_err`.)
    for (dev_name, dev_rx) in per_device_ready_rxs.iter().take(handles.len()) {
        match dev_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if first_err.is_none() {
                    first_err = Some(format!("Device '{dev_name}' failed to open: {e}"));
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

    if let Some(err) = first_err {
        // One device failing dooms the whole multi-capture: a capture that
        // silently covers only some of the requested interfaces would be
        // worse than an error (matching single-capture, where the open
        // failure is THE error). Signal the siblings that did open to stop
        // (their capture loops poll the shutdown flag), unblock the caller
        // with the one aggregated error naming the failed device, then reap
        // the threads instead of blocking on them forever.
        stop_siblings();
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(err.clone()));
        }
        for h in handles {
            let _ = h.join();
        }
        return Err(anyhow::anyhow!(err));
    }
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

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
        assert_eq!(config.buffer_mb, DEFAULT_BUFFER_MB);
        assert!(config.bpf_filter.is_none());
        assert!(config.count.is_none());
        assert!(config.duration.is_none());
        assert_eq!(config.buffer_budget_mb, 64);
    }

    /// The default is the interactive answer — the same thing every capture
    /// asked for before the field existed. A caller that builds a config from
    /// `default()` must not have its ring format changed under it; only
    /// `app::bootstrap`, which knows the run mode, turns this off.
    #[test]
    fn default_capture_config_keeps_immediate_mode() {
        assert!(
            CaptureConfig::default().immediate_mode,
            "default must preserve the historical immediate-mode capture"
        );
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
            paths: vec![PathBuf::from("/tmp/test.pcap")],
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
            CaptureSource::File {
                paths: vec![fixture],
            },
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

    // ── multi-capture teardown on device-open failure ───────────────────
    /// Teardown tests drive `run_multi_capture` with fake devices (no capture
    /// privileges): a device named `bad*` fails its open; any other device
    /// "opens" and then loops until the injected stop signal fires — exactly
    /// how `capture_live` polls the global shutdown flag. Production wires
    /// `stop_siblings` to `signals::request_shutdown`, which is not testable
    /// here without real, openable devices.
    mod multi_teardown {
        use super::*;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        /// Build a fake `spawn_device`: `bad*` devices signal an open error
        /// and exit; others count into `opened`, signal ready, and loop until
        /// `stop` is set.
        fn fake_spawner(
            stop: Arc<AtomicBool>,
            opened: Arc<AtomicU64>,
        ) -> impl Fn(
            String,
            CaptureConfig,
            channel::PacketTx,
            DeviceReadyTx,
        ) -> Result<thread::JoinHandle<Result<()>>> {
            move |dev, _config, _tx, ready| {
                let stop = stop.clone();
                let opened = opened.clone();
                thread::Builder::new()
                    .name(format!("fake-{dev}"))
                    .spawn(move || {
                        if dev.starts_with("bad") {
                            let _ = ready.send(Err("no such device".to_string()));
                            return Err(anyhow::anyhow!("no such device"));
                        }
                        opened.fetch_add(1, Ordering::SeqCst);
                        let _ = ready.send(Ok(()));
                        while !stop.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Ok(())
                    })
                    .map_err(Into::into)
            }
        }

        /// Run `run_multi_capture` over `devs` on a helper thread and return
        /// (coordinator result rx, sibling-stop flag, opened counter,
        /// caller-side ready rx).
        #[allow(clippy::type_complexity)]
        fn run(
            devs: &[&str],
            with_ready: bool,
        ) -> (
            crossbeam_channel::Receiver<Result<()>>,
            Arc<AtomicBool>,
            Arc<AtomicU64>,
            Option<crossbeam_channel::Receiver<Result<(), String>>>,
        ) {
            let stop = Arc::new(AtomicBool::new(false));
            let opened = Arc::new(AtomicU64::new(0));
            let devs: Vec<String> = devs.iter().map(|d| d.to_string()).collect();
            // The fakes never send packets, so the receiver half can drop.
            let (tx, _rx) = channel::packet_channel(16);
            let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
            let ready_tx = with_ready.then_some(ready_tx);
            let (done_tx, done_rx) = crossbeam_channel::bounded(1);
            let spawner = fake_spawner(stop.clone(), opened.clone());
            let stop2 = stop.clone();
            thread::Builder::new()
                .name("test-coordinator".into())
                .spawn(move || {
                    let res = run_multi_capture(
                        &devs,
                        &CaptureConfig::default(),
                        tx,
                        ready_tx,
                        spawner,
                        move || stop2.store(true, Ordering::SeqCst),
                    );
                    let _ = done_tx.send(res);
                })
                .unwrap();
            (done_rx, stop, opened, with_ready.then_some(ready_rx))
        }

        /// One failed device open must (a) surface ONE error naming that
        /// device on the ready channel, (b) stop the sibling captures that
        /// did open, and (c) let the coordinator finish with the same named
        /// error instead of hanging on live siblings forever.
        #[test]
        fn open_failure_stops_siblings_and_surfaces_one_named_error() {
            let (done_rx, stop, opened, ready_rx) = run(&["good0", "bad1", "good2"], true);
            let msg = ready_rx
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .expect("aggregated ready signal must arrive")
                .expect_err("a failed device open must surface as Err");
            assert!(msg.contains("bad1"), "error must name the device: {msg}");
            let res = done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("coordinator must reap stopped siblings, not hang");
            let err = res.expect_err("coordinator must fail when a device fails");
            assert!(err.to_string().contains("bad1"), "got: {err}");
            assert!(stop.load(Ordering::SeqCst), "siblings must be told to stop");
            assert_eq!(opened.load(Ordering::SeqCst), 2, "both good devices ran");
        }

        /// The same teardown must happen when the caller passed no ready
        /// channel: the failure is still detected, siblings still stop, and
        /// the coordinator still returns the named error.
        #[test]
        fn open_failure_without_ready_channel_still_tears_down() {
            let (done_rx, stop, _opened, _none) = run(&["good0", "bad1"], false);
            let res = done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("coordinator must finish without a ready channel too");
            let err = res.expect_err("coordinator must fail when a device fails");
            assert!(err.to_string().contains("bad1"), "got: {err}");
            assert!(stop.load(Ordering::SeqCst), "siblings must be told to stop");
        }

        /// All devices opening cleanly must NOT trip the stop signal; the
        /// caller gets `Ok(())` on ready and the siblings keep running.
        #[test]
        fn all_devices_ok_does_not_stop_anyone() {
            let (done_rx, stop, opened, ready_rx) = run(&["good0", "good1"], true);
            ready_rx
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .expect("ready signal must arrive")
                .expect("all devices opened, ready must be Ok");
            assert_eq!(opened.load(Ordering::SeqCst), 2);
            assert!(!stop.load(Ordering::SeqCst), "no failure, no stop signal");
            // Siblings are still capturing; the coordinator must still be
            // waiting on them (nothing on done_rx yet).
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "coordinator must keep running while captures are healthy"
            );
            // Shut the fakes down so the test does not leak spinning threads.
            stop.store(true, Ordering::SeqCst);
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("coordinator finishes after siblings stop")
                .expect("clean shutdown is Ok");
        }
    }
}
