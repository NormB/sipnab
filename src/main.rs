//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! Entry point: parses CLI, sets up logging and signal handlers, loads config,
//! and dispatches to the appropriate capture mode. Phase 2 wires all modules
//! together: capture → SIP parsing → dialog tracking → RTP tracking →
//! filtering → output.

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use sipnab::capture::parse::TransportProto;
use sipnab::capture::websocket;
use sipnab::capture::{self, CaptureConfig, CaptureSource, ParsedPacket, PcapWriter};
use sipnab::cli::{self, Cli};
use sipnab::config::Config;
use sipnab::output::{self, ColorMode, EventExecEngine, OutputOptions, ReportFormat};
use sipnab::privilege;
use sipnab::process_isolation::{self, KillRequest, ScannerKillHandle};
use sipnab::rtp::{self, parser::parse_rtp_header, rtcp::parse_rtcp, stream_store::StreamStore};
use sipnab::security::{
    self as sec, AlertEngine, AlertRule, DigestLeakDetector, FraudDetector, RegFloodDetector,
    ScannerDetector,
};
use sipnab::signals;
use sipnab::sip::{self, dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

#[cfg(feature = "tls")]
use sipnab::capture::decrypt::TlsDecryptor;
#[cfg(feature = "tls")]
use sipnab::capture::tls;

fn main() {
    // 1. Parse CLI arguments
    let cli = Cli::parse_args();

    // 2. Setup logging (env var: SIPNAB_LOG, default: info; quiet overrides to warn)
    let default_level = if cli.quiet { "warn" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::new().filter_or("SIPNAB_LOG", default_level))
        .format_timestamp_millis()
        .init();

    // 3. Install signal handlers
    signals::install_handlers();

    // 4. Validate CLI argument combinations
    if let Err(msg) = cli.validate() {
        log::error!("{}", msg);
        std::process::exit(2);
    }

    // 4a. Warn about unimplemented flags that were set
    cli.warn_unimplemented_flags();

    // 5. Load configuration
    let loaded = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(loaded) => {
            if let Some(ref source) = loaded.source {
                log::info!("Loaded config from {}", source.display());
            }
            loaded
        }
        Err(e) => {
            log::error!("{}", e);
            std::process::exit(1);
        }
    };

    // 5a. Apply configurable security limits from [limits] section
    if let Some(v) = loaded.config.limits.max_header_line {
        sipnab::sip::parser::set_parser_limits(
            v as usize,
            loaded.config.limits.max_headers_per_message
                .map(|h| h as usize)
                .unwrap_or(sipnab::sip::parser::DEFAULT_MAX_HEADERS_PER_MESSAGE),
        );
    } else if let Some(v) = loaded.config.limits.max_headers_per_message {
        sipnab::sip::parser::set_parser_limits(
            sipnab::sip::parser::DEFAULT_MAX_HEADER_LINE_LEN,
            v as usize,
        );
    }
    if let Some(v) = loaded.config.limits.max_messages_per_dialog {
        sipnab::sip::dialog_store::set_max_messages_per_dialog(v as usize);
    }

    // 6. --dump-config: print version + effective config, then exit
    if cli.dump_config {
        println!("sipnab v{}", cli::build_version());
        println!();
        if let Some(ref source) = loaded.source {
            println!("# Loaded from: {}", source.display());
        } else {
            println!("# No config file loaded (defaults only)");
        }
        println!("{}", loaded.config.dump());
        return;
    }

    // 7. Determine capture source
    let source = if let Some(ref input) = cli.input {
        Some(CaptureSource::File {
            path: PathBuf::from(input),
        })
    } else if let Some(ref device) = cli.device {
        Some(CaptureSource::Live {
            device: device.clone(),
        })
    } else if let Some(ref device) = loaded.config.capture.device {
        Some(CaptureSource::Live {
            device: device.clone(),
        })
    } else {
        cli.hep_listen.as_ref().map(|hep_addr| {
            #[cfg(feature = "hep")]
            let allowlist: Vec<sipnab::capture::hep::CidrRange> = cli
                .hep_allow
                .iter()
                .map(|cidr| match sipnab::capture::hep::CidrRange::parse(cidr) {
                    Ok(r) => r,
                    Err(e) => {
                        log::error!("Invalid --hep-allow CIDR '{}': {}", cidr, e);
                        std::process::exit(2);
                    }
                })
                .collect();

            CaptureSource::Hep {
                bind_addr: hep_addr.clone(),
                #[cfg(feature = "hep")]
                allowlist,
                rate_limit: cli.hep_rate_limit,
            }
        })
    };

    let source = match source {
        Some(s) => s,
        None => {
            // Auto-detect default network interface (matches sngrep behavior)
            match capture::device::find_default_device() {
                Ok(device) => {
                    log::info!("Auto-detected capture device: {}", device);
                    CaptureSource::Live { device }
                }
                Err(e) => {
                    let devices = capture::device::list_devices();
                    if devices.is_empty() {
                        log::error!(
                            "No capture device found. Use -d <device> or -I <file>\n  \
                             Try: sudo sipnab"
                        );
                    } else {
                        log::error!(
                            "{}\n  Available devices: {}\n  Try: sipnab -d {}",
                            e,
                            devices.join(", "),
                            devices[0]
                        );
                    }
                    std::process::exit(1);
                }
            }
        }
    };

    // 8. Build CaptureConfig from CLI + config file
    let mut capture_config = build_capture_config(&cli, &loaded.config);

    // 8a. Parse --portrange (CLI > config file > default "5060-5061")
    let portrange_str = if cli.portrange != "5060-5061" {
        &cli.portrange
    } else if let Some(ref pr) = loaded.config.capture.portrange {
        pr.as_str()
    } else {
        "5060-5061"
    };
    let portrange = match parse_portrange(portrange_str) {
        Ok(range) => range,
        Err(e) => {
            log::error!("Invalid --portrange: {e}");
            std::process::exit(2);
        }
    };

    // 8a2. Auto-generate BPF filter from portrange for live captures when no
    //      explicit filter was set. This is critical for performance: without a
    //      BPF filter, capturing on 'any' device processes ALL traffic.
    if capture_config.bpf_filter.is_none() && matches!(source, CaptureSource::Live { .. }) {
        let (lo, hi) = portrange;
        capture_config.bpf_filter = Some(if lo == hi {
            format!("port {lo}")
        } else {
            format!("portrange {lo}-{hi}")
        });
        if let Some(ref filter) = capture_config.bpf_filter {
            log::info!("Auto-generated BPF filter: {filter}");
        }
    }

    // 8b. Parse --autostop condition
    let autostop_duration: Option<std::time::Duration>;
    let autostop_filesize_mb: Option<u64>;
    if let Some(ref cond) = cli.autostop {
        let (dur, size) = match parse_autostop(cond) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Invalid --autostop: {e}");
                std::process::exit(2);
            }
        };
        autostop_duration = dur;
        autostop_filesize_mb = size;
    } else {
        autostop_duration = None;
        autostop_filesize_mb = None;
    }

    // 9. Parse --split for output rotation
    let (split_bytes, split_duration) = if let Some(ref split) = cli.split {
        match capture::writer::parse_split(split) {
            Ok(params) => params,
            Err(e) => {
                log::error!("{e}");
                std::process::exit(2);
            }
        }
    } else {
        (None, None)
    };

    // 10. Build the SIP matcher from CLI filter flags
    let matcher = match SipMatcher::new(&cli, None) {
        Ok(m) => m,
        Err(e) => {
            log::error!("Invalid filter pattern: {e}");
            std::process::exit(2);
        }
    };

    // 11. Build the filter DSL expression if --filter (or diagnostic aliases)
    let filter_expr = build_filter_expr(&cli);

    // 12. Build output options
    let output_opts = OutputOptions {
        color: match cli.color.as_str() {
            "always" => ColorMode::Always,
            "never" => ColorMode::Never,
            _ => ColorMode::Auto,
        },
        delta_time: cli.delta_time || loaded.config.display.delta_time.unwrap_or(false),
        payload_limit: cli.payload_limit.or(loaded.config.display.payload_limit),
        show_empty: cli.show_empty,
    };

    // 13. Build the event exec engine
    let event_exec = EventExecEngine::new(
        cli.on_dialog_exec.clone(),
        cli.on_quality_exec.clone(),
        cli.exec_rate_limit,
        cli.quality_threshold,
    );

    // 14. Create the packet channel
    let (tx, rx) = crossbeam_channel::bounded(10_000);

    // 15. Start the capture thread (multi-device aware).
    //     Use a rendezvous channel so the capture thread can signal that the
    //     device/file/socket is open before we drop privileges.
    let (ready_tx, ready_rx) = crossbeam_channel::bounded::<Result<(), String>>(1);

    let handle = if cli.multi_device {
        let device_str = match &source {
            CaptureSource::Live { device } => device.clone(),
            _ => {
                log::error!("--multi-device requires a live capture device (-d)");
                std::process::exit(2);
            }
        };
        match capture::start_multi_capture(&device_str, capture_config.clone(), tx, Some(ready_tx))
        {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to start multi-device capture: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match capture::start_capture(source, capture_config.clone(), tx, Some(ready_tx)) {
            Ok(h) => h,
            Err(e) => {
                log::error!("Failed to start capture: {e}");
                std::process::exit(1);
            }
        }
    };

    // 15a. Wait for the capture thread to confirm the device/file/socket is open.
    //      This must happen BEFORE privilege drop so we don't lose CAP_NET_RAW.
    match ready_rx.recv() {
        Ok(Ok(())) => {
            log::debug!("Capture source opened successfully");
        }
        Ok(Err(e)) => {
            let is_permission = e.contains("ermission")
                || e.contains("EPERM")
                || e.contains("Operation not permitted")
                || e.contains("socket:");
            if is_permission {
                let dev_name = match &handle.source {
                    CaptureSource::Live { device } => device.as_str(),
                    _ => "capture source",
                };
                log::error!(
                    "Permission denied on '{}'. Run with sudo or set capabilities:\n  \
                     sudo sipnab\n  \
                     # or (Linux only):\n  \
                     sudo setcap cap_net_raw+ep $(which sipnab)",
                    dev_name
                );
            } else {
                log::error!("Capture source failed to open: {e}");
            }
            std::process::exit(1);
        }
        Err(_) => {
            log::error!("Capture thread exited before signaling ready");
            std::process::exit(1);
        }
    }

    // 16. Chroot BEFORE dropping privileges (chroot requires root).
    // Correct POSIX sequence: chroot → chdir("/") → setgroups → setgid → setuid
    if let Some(ref chroot_dir) = cli.chroot
        && let Err(e) = privilege::do_chroot(std::path::Path::new(chroot_dir))
    {
        log::error!("Failed to chroot: {e}");
        std::process::exit(1);
    }

    // 16a. Drop privileges now that capture devices are open and chroot is applied (D15)
    if let Err(e) = privilege::drop_privileges(cli.user.as_deref(), cli.no_priv_drop) {
        log::error!("Failed to drop privileges: {e}");
        std::process::exit(1);
    }

    // 16b. Initialize syslog if --syslog is set
    if cli.syslog {
        sipnab::security::alerting::init_syslog();
    }

    // 16c. Validate --hep-send requires hep feature
    #[cfg(not(feature = "hep"))]
    if cli.hep_send.is_some() {
        log::error!("HEP support requires --features hep");
        std::process::exit(2);
    }

    // 16d. Validate --hep-parse requires hep feature
    #[cfg(not(feature = "hep"))]
    if cli.hep_parse {
        log::error!("HEP support requires --features hep");
        std::process::exit(2);
    }

    // 16d2. Validate TLS flags require tls feature
    #[cfg(not(feature = "tls"))]
    {
        if cli.tls_key.is_some() {
            log::error!("--tls-key requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.keylog.is_some() {
            log::error!("--keylog requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.keylog_watch {
            log::error!("--keylog-watch requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.srtp_keys.is_some() {
            log::error!("--srtp-keys requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
    }

    // 16d3. Validate API flags require api feature
    #[cfg(not(feature = "api"))]
    {
        if cli.api.is_some() {
            log::error!("--api requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_key.is_some() {
            log::error!("--api-key requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_tls_cert.is_some() {
            log::error!("--api-tls-cert requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_tls_key.is_some() {
            log::error!("--api-tls-key requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
    }

    // 16e. Validate --pcap-export-mode
    match cli.pcap_export_mode.as_str() {
        "decrypted" | "encrypted+dsb" | "raw" => {}
        other => {
            log::error!(
                "Invalid --pcap-export-mode '{other}': must be 'decrypted', 'encrypted+dsb', or 'raw'"
            );
            std::process::exit(2);
        }
    }

    // 16f. Load DTLS keylog if --dtls-keylog is set
    #[cfg(feature = "tls")]
    if let Some(ref dtls_path) = cli.dtls_keylog {
        match sipnab::capture::decrypt::TlsDecryptor::load_dtls_keylog(std::path::Path::new(
            dtls_path,
        )) {
            Ok(count) => {
                log::info!("DTLS keylog: {count} entries loaded from {dtls_path}");
            }
            Err(e) => {
                log::error!("Failed to load DTLS keylog: {e}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(feature = "tls"))]
    if cli.dtls_keylog.is_some() {
        log::error!("--dtls-keylog requires the 'tls' feature (not compiled in)");
        std::process::exit(2);
    }

    // 16g. Validate --api-tls-cert/--api-tls-key consistency
    if cli.api_tls_cert.is_some() != cli.api_tls_key.is_some() {
        log::error!("--api-tls-cert and --api-tls-key must both be specified together");
        std::process::exit(2);
    }

    // 17. Disable core dumps if any decryption keys are loaded (D19)
    let has_decrypt_keys = cli.tls_key.is_some()
        || cli.keylog.is_some()
        || cli.srtp_keys.is_some()
        || cli.dtls_keylog.is_some();
    if has_decrypt_keys
        && !cli.allow_coredump
        && let Err(e) = privilege::disable_core_dumps()
    {
        log::error!("Failed to disable core dumps: {e}");
        std::process::exit(1);
    }

    // 17a. Start standalone metrics server if --metrics is set (without --api).
    // Note: The metrics server shares the same stores that are created inside
    // run_tui_mode/run_batch_mode. We parse/validate the address here but defer
    // actual server start to those functions where the stores are available.
    #[cfg(feature = "api")]
    let metrics_bind_addr: Option<std::net::SocketAddr> = cli.metrics.as_deref().map(|addr_str| {
        match sipnab::output::prometheus_server::parse_metrics_addr(addr_str) {
            Ok(a) => a,
            Err(e) => {
                log::error!("Invalid --metrics address: {e}");
                std::process::exit(2);
            }
        }
    });

    // 18. Branch: TUI mode vs non-interactive mode
    #[cfg(feature = "tui")]
    let use_tui = !cli.no_tui;
    #[cfg(not(feature = "tui"))]
    let use_tui = false;

    if use_tui {
        #[cfg(feature = "tui")]
        run_tui_mode(
            cli,
            loaded.config,
            capture_config,
            handle,
            rx,
            split_bytes,
            split_duration,
            portrange,
            #[cfg(feature = "api")]
            metrics_bind_addr,
        );
    } else {
        run_batch_mode(
            cli,
            &loaded.config,
            capture_config,
            handle,
            rx,
            matcher,
            filter_expr,
            output_opts,
            event_exec,
            split_bytes,
            split_duration,
            portrange,
            autostop_duration,
            autostop_filesize_mb,
        );
    }
}

// ── Portrange parsing ──────────────────────────────────────────────────

/// Parse a port range string like "5060-5061" or "5060-5080" into a `(u16, u16)` tuple.
fn parse_portrange(s: &str) -> Result<(u16, u16), String> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Expected format 'start-end' (e.g., '5060-5061'), got '{s}'"
        ));
    }
    let start: u16 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid port number: '{}'", parts[0]))?;
    let end: u16 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid port number: '{}'", parts[1]))?;
    if start > end {
        return Err(format!("Port range start ({start}) > end ({end})"));
    }
    Ok((start, end))
}

/// Check whether a source or destination port falls within the configured range.
fn port_in_range(src_port: u16, dst_port: u16, range: (u16, u16)) -> bool {
    let (lo, hi) = range;
    (src_port >= lo && src_port <= hi) || (dst_port >= lo && dst_port <= hi)
}

// ── Autostop parsing ───────────────────────────────────────────────────

/// Parse an `--autostop` condition string.
///
/// Supported formats:
/// - `duration:N` — stop after N seconds
/// - `filesize:N` — stop when output file reaches N megabytes
///
/// Returns `(Option<Duration>, Option<filesize_mb>)`.
fn parse_autostop(s: &str) -> Result<(Option<std::time::Duration>, Option<u64>), String> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Expected format 'duration:N' or 'filesize:N', got '{s}'"
        ));
    }
    let key = parts[0];
    let value: u64 = parts[1]
        .parse()
        .map_err(|_| format!("Invalid autostop value: '{}'", parts[1]))?;

    match key {
        "duration" => Ok((Some(std::time::Duration::from_secs(value)), None)),
        "filesize" => Ok((None, Some(value))),
        _ => Err(format!(
            "Unknown autostop condition: '{key}'. Expected 'duration' or 'filesize'"
        )),
    }
}

// ── TUI mode ────────────────────────────────────────────────────────

/// Run sipnab in interactive TUI mode.
///
/// Wraps stores in `Arc<RwLock>`, spawns a processing thread, and runs
/// the TUI event loop on the main thread.
#[cfg(feature = "tui")]
#[allow(clippy::too_many_arguments)]
fn run_tui_mode(
    cli: Cli,
    config: Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: crossbeam_channel::Receiver<capture::Packet>,
    split_bytes: Option<u64>,
    split_duration: Option<std::time::Duration>,
    portrange: (u16, u16),
    #[cfg(feature = "api")] metrics_bind_addr: Option<std::net::SocketAddr>,
) {
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);

    let dialog_store = Arc::new(RwLock::new(DialogStore::new(
        cli.limit as usize,
        cli.rotate,
    )));
    let stream_store = Arc::new(RwLock::new(StreamStore::new(cli.max_streams as usize)));

    // Start standalone metrics server with the REAL stores (not empty copies)
    #[cfg(feature = "api")]
    let _metrics_handle = if let Some(bind_addr) = metrics_bind_addr {
        match sipnab::output::prometheus_server::start_metrics_server(
            bind_addr,
            Arc::clone(&dialog_store),
            Arc::clone(&stream_store),
            cli.metrics_auth.clone(),
        ) {
            Ok(h) => Some(h),
            Err(e) => {
                log::error!("Failed to start metrics server: {e}");
                None
            }
        }
    } else {
        None
    };

    // Shared pause flag between TUI and processing thread
    let paused_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Clone references for the processing thread
    let ds = Arc::clone(&dialog_store);
    let ss = Arc::clone(&stream_store);
    let paused_for_thread = Arc::clone(&paused_flag);
    let cli_clone = cli.clone();

    // Spawn packet processing thread
    let processing_thread = std::thread::Builder::new()
        .name("tui-processor".to_string())
        .spawn(move || {
            let mut processor =
                capture::PacketProcessor::with_max_sessions(cli_clone.max_reassembly as usize);
            let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
            let mut writer: Option<PcapWriter> = None;
            let mut last_sweep = std::time::Instant::now();
            let sweep_interval = std::time::Duration::from_secs(5);
            let start = std::time::Instant::now();
            let mut total_count: u64 = 0;

            loop {
                if signals::shutdown_requested() {
                    break;
                }

                if last_sweep.elapsed() >= sweep_interval {
                    processor.sweep();
                    ss.write().mark_orphaned(std::time::Duration::from_secs(30));
                    last_sweep = std::time::Instant::now();
                }

                let packet = match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(pkt) => pkt,
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                };

                // Lazily initialize writer
                if writer.is_none()
                    && let Some(ref output_path) = cli_clone.output
                {
                    match PcapWriter::new(
                        &PathBuf::from(output_path),
                        packet.link_type,
                        split_bytes,
                        split_duration,
                    ) {
                        Ok(w) => writer = Some(w),
                        Err(e) => {
                            log::error!("Failed to open output file: {e}");
                            break;
                        }
                    }
                }

                if let Some(ref mut w) = writer
                    && let Err(e) = w.write(&packet)
                {
                    log::error!("Failed to write packet: {e}");
                    break;
                }

                total_count += 1;

                let parsed_packets = processor.process(&packet);
                for pp in &parsed_packets {
                    // Skip processing when paused (capture continues to prevent buffer overflow)
                    if paused_for_thread.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if !port_in_range(pp.src_port, pp.dst_port, portrange) {
                        continue;
                    }
                    tui_process_packet(pp, &ds, &ss, &mut rtp_heuristic, &cli_clone, no_rtp);
                }

                if let Some(max_count) = capture_config.count
                    && total_count >= max_count
                {
                    break;
                }

                if let Some(duration) = capture_config.duration
                    && start.elapsed() >= duration
                {
                    break;
                }
            }
        });
    let processing_thread = match processing_thread {
        Ok(handle) => handle,
        Err(e) => {
            log::error!("Failed to spawn processing thread: {e}");
            std::process::exit(1);
        }
    };

    // Start API server if --api is specified
    #[cfg(feature = "api")]
    let _api_thread = start_api_server(&cli, Arc::clone(&dialog_store), Arc::clone(&stream_store));

    // Build resolved theme and keymap from config
    let theme = sipnab::tui::Theme::from_config(&config.theme);
    let keymap = sipnab::tui::Keymap::from_config(&config.keybindings);

    // Run TUI on the main thread
    if let Err(e) = sipnab::tui::run_tui_with_pause(
        Arc::clone(&dialog_store),
        Arc::clone(&stream_store),
        Some(paused_flag),
        theme,
        keymap,
    ) {
        log::error!("TUI error: {e}");
    }

    // Signal shutdown and wait for threads
    // The TUI has exited; signal shutdown so processing thread stops
    signals::request_shutdown();

    if let Err(e) = processing_thread.join() {
        log::error!("Processing thread panicked: {:?}", e);
    }

    drop(handle);
}

/// Process a parsed packet in TUI mode (updates shared stores).
#[cfg(feature = "tui")]
fn tui_process_packet(
    pp: &ParsedPacket,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    rtp_heuristic: &mut rtp::heuristic::RtpHeuristic,
    cli: &Cli,
    no_rtp: bool,
) {
    // Try WebSocket unwrapping for TCP on common WS ports
    let ws_payload = try_websocket_unwrap(pp);
    let effective_payload = ws_payload.as_deref().unwrap_or(&pp.payload);
    let effective_transport = if ws_payload.is_some() {
        TransportProto::Ws
    } else {
        pp.transport
    };

    // Try SIP detection first — parse OUTSIDE the lock, then do a quick
    // write-lock-and-release to minimize contention with the TUI render thread.
    if sip::is_sip_message(effective_payload) {
        if let Ok(sip_msg) = sip::parse_sip(
            effective_payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            effective_transport,
        ) && !cli.no_dialog
        {
            // Extract SDP link info before acquiring any lock
            let sdp_links: Vec<(std::net::IpAddr, u16, String)> = if let Some(sdp) = sip_msg.sdp()
                && let Some(call_id) = sip_msg.call_id()
            {
                sdp.media
                    .iter()
                    .filter_map(|media| {
                        let addr_str = sip::sdp::effective_address(media, &sdp);
                        addr_str
                            .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                            .map(|ip| (ip, media.port, call_id.to_string()))
                    })
                    .collect()
            } else {
                Vec::new()
            };

            // Quick write to dialog store, then release
            {
                dialog_store.write().process_message(sip_msg);
            }

            // Link SDP media endpoints to RTP streams (separate lock)
            if !sdp_links.is_empty() {
                let mut ss = stream_store.write();
                for (ip, port, call_id) in &sdp_links {
                    ss.link_to_dialog(*ip, *port, call_id);
                }
            }
        }
        return;
    }

    // RTP/RTCP detection
    if no_rtp || pp.transport != TransportProto::Udp {
        return;
    }

    if is_rtcp_packet(&pp.payload, pp.dst_port) {
        let rtcp_packets = rtp::rtcp::parse_rtcp(&pp.payload);
        if !rtcp_packets.is_empty() {
            stream_store.write().process_rtcp(&rtcp_packets);
        }
        return;
    }

    if rtp::is_rtp_packet(&pp.payload)
        && let Ok(rtp_hdr) = rtp::parser::parse_rtp_header(&pp.payload)
    {
        stream_store.write().process_rtp(pp, &rtp_hdr, pp.timestamp);
        return;
    }

    if let Some(rtp_hdr) = rtp_heuristic.check(pp) {
        stream_store.write().process_rtp(pp, &rtp_hdr, pp.timestamp);
    }
}

// ── Batch (non-interactive) mode ────────────────────────────────────

/// Run sipnab in non-interactive batch mode (original behavior).
#[allow(clippy::too_many_arguments)]
fn run_batch_mode(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: crossbeam_channel::Receiver<capture::Packet>,
    matcher: SipMatcher,
    filter_expr: Option<FilterExpr>,
    output_opts: OutputOptions,
    mut event_exec: EventExecEngine,
    split_bytes: Option<u64>,
    split_duration: Option<std::time::Duration>,
    portrange: (u16, u16),
    autostop_duration: Option<std::time::Duration>,
    autostop_filesize_mb: Option<u64>,
) {
    // 16. Open output writer if -O is specified
    let mut writer: Option<PcapWriter> = None;
    let use_pcapng = cli.pcapng;

    // 16a. Initialize HEP sender if --hep-send is set
    #[cfg(feature = "hep")]
    let hep_sender: Option<sipnab::capture::hep::HepSender> = if let Some(ref addr) = cli.hep_send {
        match sipnab::capture::hep::HepSender::new(addr, 1) {
            Ok(sender) => {
                log::info!("HEP sender targeting {addr}");
                Some(sender)
            }
            Err(e) => {
                log::error!("Failed to create HEP sender: {e}");
                None
            }
        }
    } else {
        None
    };

    // 17. Initialize processing state
    let mut processor = capture::PacketProcessor::with_max_sessions(cli.max_reassembly as usize);
    let mut dialog_store = DialogStore::new(cli.limit as usize, cli.rotate);
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    let mut stream_store = StreamStore::new(cli.max_streams as usize);
    let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

    // 17a. Initialize security detectors
    let kill_scanner_active = cli.kill_scanner || config.security.kill_scanner.unwrap_or(false);
    let mut scanner_detector = if kill_scanner_active {
        let custom = cli
            .kill_ua
            .as_deref()
            .map(|s| vec![s.to_string()])
            .unwrap_or_default();
        Some(ScannerDetector::new(&custom))
    } else {
        None
    };

    // 17a-2. Spawn scanner-kill worker thread (D16: process isolation)
    let mut scanner_kill_handle: Option<ScannerKillHandle> = if kill_scanner_active {
        match process_isolation::spawn_scanner_kill_worker(None) {
            Ok(handle) => Some(handle),
            Err(e) => {
                log::error!("Failed to spawn scanner-kill worker: {e}");
                None
            }
        }
    } else {
        None
    };
    let kill_response_code = cli.kill_response;

    let mut fraud_detector = if cli.fraud_detect || config.security.fraud_detect.unwrap_or(false) {
        Some(FraudDetector::new(None))
    } else {
        None
    };

    let mut digest_detector = if cli.digest_leak {
        Some(DigestLeakDetector::new())
    } else {
        None
    };

    let mut reg_flood_detector = if cli.reg_flood {
        Some(RegFloodDetector::new(0))
    } else {
        None
    };

    // 17b. Initialize alert engine from --alert rules and --alert-exec
    let alert_rules: Vec<AlertRule> = cli
        .alert
        .iter()
        .filter_map(|s| match AlertRule::parse(s) {
            Ok(r) => Some(r),
            Err(e) => {
                log::warn!("Skipping invalid alert rule '{}': {}", s, e);
                None
            }
        })
        .collect();
    let mut alert_engine = AlertEngine::new(alert_rules, cli.alert_exec.clone());
    if cli.syslog {
        alert_engine.set_syslog(true);
    }

    // 17c. Initialize TLS decryptor if --keylog is provided
    #[cfg(feature = "tls")]
    let mut tls_decryptor: Option<TlsDecryptor> = if cli.keylog.is_some() {
        let keylog_path = cli.keylog.as_deref().map(std::path::Path::new);
        let crypto = sipnab::crypto::default_backend();
        match TlsDecryptor::new(keylog_path, crypto) {
            Ok(d) => {
                if d.keylog_entry_count() > 0 {
                    log::info!(
                        "sipnab: TLS decryption active (keylog loaded). \
                         Decrypted traffic visible in output."
                    );
                }
                Some(d)
            }
            Err(e) => {
                log::error!("Failed to initialize TLS decryptor: {e}");
                None
            }
        }
    } else {
        None
    };

    // Start API server if --api is specified (feature-gated)
    // In batch mode, we share stores via Arc<RwLock> when the API is active.
    #[cfg(feature = "api")]
    let (shared_ds, shared_ss, _api_thread) = {
        if cli.api.is_some() {
            let ds = Arc::new(RwLock::new(DialogStore::new(
                cli.limit as usize,
                cli.rotate,
            )));
            let ss = Arc::new(RwLock::new(StreamStore::new(cli.max_streams as usize)));
            let thread = start_api_server(&cli, Arc::clone(&ds), Arc::clone(&ss));
            (Some(ds), Some(ss), thread)
        } else {
            (None, None, None)
        }
    };

    let mut last_sweep = std::time::Instant::now();
    let sweep_interval = std::time::Duration::from_secs(5);

    // 18. Main receive loop
    let start = std::time::Instant::now();
    let mut total_count: u64 = 0;
    let mut sip_count: u64 = 0;
    let mut rtp_count: u64 = 0;
    let mut prev_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;

    // --after / -A trailing context counter
    let after_count = cli.after.unwrap_or(0);
    let mut trailing_remaining: usize = 0;

    // Autostop filesize in bytes (input is in MB)
    let autostop_filesize_bytes = autostop_filesize_mb.map(|mb| mb * 1_000_000);

    loop {
        if signals::shutdown_requested() {
            break;
        }

        // Periodic sweep of reassembly state and orphan detection (every 5 seconds)
        if last_sweep.elapsed() >= sweep_interval {
            processor.sweep();
            stream_store.mark_orphaned(std::time::Duration::from_secs(30));
            let security_max_age = std::time::Duration::from_secs(120);
            if let Some(det) = scanner_detector.as_mut() {
                det.sweep(security_max_age);
            }
            if let Some(det) = fraud_detector.as_mut() {
                det.sweep(security_max_age);
            }
            if let Some(det) = reg_flood_detector.as_mut() {
                det.sweep(security_max_age);
            }
            #[cfg(feature = "api")]
            if let Some(ref ss) = shared_ss {
                ss.write().mark_orphaned(std::time::Duration::from_secs(30));
            }

            // --keylog-watch: poll for new keys in the keylog file
            #[cfg(feature = "tls")]
            if cli.keylog_watch
                && let Some(ref mut decryptor) = tls_decryptor
                && let Err(e) = decryptor.poll_keylog_file()
            {
                log::debug!("Keylog poll error: {e}");
            }

            last_sweep = std::time::Instant::now();
        }

        // Use recv_timeout so we can check shutdown periodically
        let packet = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
            Ok(pkt) => pkt,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        // Lazily initialize the writer on first packet (we need link_type)
        if writer.is_none()
            && let Some(ref output_path) = cli.output
        {
            match PcapWriter::with_format(
                &PathBuf::from(output_path),
                packet.link_type,
                split_bytes,
                split_duration,
                use_pcapng,
            ) {
                Ok(w) => writer = Some(w),
                Err(e) => {
                    log::error!("Failed to open output file: {e}");
                    std::process::exit(1);
                }
            }
        }

        // Write to output pcap if configured
        if let Some(ref mut w) = writer
            && let Err(e) = w.write(&packet)
        {
            log::error!("Failed to write packet: {e}");
            break;
        }

        total_count += 1;

        // Parse and reassemble the packet
        let parsed_packets = processor.process(&packet);
        for pp in &parsed_packets {
            // --hep-parse: try to unwrap HEP-encapsulated packets
            #[cfg(feature = "hep")]
            let hep_unwrapped = if cli.hep_parse && pp.transport == TransportProto::Udp {
                sipnab::capture::hep::parse_hep(&pp.payload)
                    .ok()
                    .map(|hep| {
                        let mut unwrapped = pp.clone();
                        unwrapped.payload = hep.payload;
                        unwrapped.src_addr = hep.src_addr;
                        unwrapped.dst_addr = hep.dst_addr;
                        unwrapped.src_port = hep.src_port;
                        unwrapped.dst_port = hep.dst_port;
                        unwrapped
                    })
            } else {
                None
            };

            #[cfg(not(feature = "hep"))]
            let hep_unwrapped: Option<ParsedPacket> = None;

            let pp = hep_unwrapped.as_ref().unwrap_or(pp);

            // Port range filtering: skip packets outside the configured range
            if !port_in_range(pp.src_port, pp.dst_port, portrange) {
                continue;
            }

            // Attempt TLS decryption for TCP payloads when --keylog is active
            #[cfg(feature = "tls")]
            let tls_decrypted = try_tls_decrypt(pp, &mut tls_decryptor);

            #[cfg(not(feature = "tls"))]
            let tls_decrypted: Option<ParsedPacket> = None;

            // If TLS decryption yielded a SIP message, process the decrypted packet
            let is_tls = tls_decrypted.is_some();
            let effective_pp = tls_decrypted.as_ref().unwrap_or(pp);
            process_parsed_packet(
                effective_pp,
                &matcher,
                &filter_expr,
                &output_opts,
                &cli,
                &mut dialog_store,
                &mut stream_store,
                &mut rtp_heuristic,
                &mut event_exec,
                &mut scanner_detector,
                &mut fraud_detector,
                &mut digest_detector,
                &mut reg_flood_detector,
                &mut alert_engine,
                &scanner_kill_handle,
                kill_response_code,
                &mut sip_count,
                &mut rtp_count,
                &mut prev_timestamp,
                no_rtp,
                is_tls,
                after_count,
                &mut trailing_remaining,
            );

            // --hep-send: forward matched SIP messages via HEP
            #[cfg(feature = "hep")]
            if let Some(ref sender) = hep_sender
                && sip::is_sip_message(&effective_pp.payload)
                && let Ok(sip_msg) = sip::parse_sip(
                    &effective_pp.payload,
                    effective_pp.timestamp,
                    effective_pp.src_addr,
                    effective_pp.dst_addr,
                    effective_pp.src_port,
                    effective_pp.dst_port,
                    sipnab::capture::parse::TransportProto::Udp,
                )
                && let Err(e) = sender.send(&sip_msg)
            {
                log::debug!("HEP send failed: {e}");
            }

            // Mirror updates to shared stores for API access
            #[cfg(feature = "api")]
            if let (Some(ds), Some(ss)) = (&shared_ds, &shared_ss) {
                mirror_to_shared_stores(effective_pp, ds, ss, no_rtp);
            }
        }

        // Check --count limit
        if let Some(max_count) = capture_config.count
            && total_count >= max_count
        {
            break;
        }

        // Check --duration limit
        if let Some(duration) = capture_config.duration
            && start.elapsed() >= duration
        {
            break;
        }

        // Check --autostop duration
        if let Some(autostop_dur) = autostop_duration
            && start.elapsed() >= autostop_dur
        {
            log::info!("Autostop: duration limit reached ({autostop_dur:?})");
            break;
        }

        // Check --autostop filesize
        if let Some(max_bytes) = autostop_filesize_bytes
            && let Some(ref w) = writer
            && w.bytes_written() >= max_bytes
        {
            log::info!(
                "Autostop: filesize limit reached ({} MB)",
                autostop_filesize_mb.unwrap_or(0)
            );
            break;
        }
    }

    // 19. Shut down scanner-kill worker (D16)
    if let Some(ref mut kill_handle) = scanner_kill_handle {
        kill_handle.shutdown();
    }

    // 20. Wait for the capture thread to finish
    //     Drop rx first so the capture thread sees a disconnected channel
    drop(rx);
    match handle.thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("Capture thread error: {e}"),
        Err(_) => log::error!("Capture thread panicked"),
    }

    // 21. Post-capture output
    generate_reports(&cli, &dialog_store, &stream_store);

    // 21a. --wireshark: print Wireshark display filter for all tracked dialogs
    if cli.wireshark {
        let call_ids: Vec<&str> = dialog_store.iter().map(|d| d.call_id.as_str()).collect();
        if call_ids.is_empty() {
            eprintln!("No SIP dialogs to generate Wireshark filter for.");
        } else {
            let filter_parts: Vec<String> = call_ids
                .iter()
                .map(|id| format!("sip.Call-ID == \"{}\"", id))
                .collect();
            println!("{}", filter_parts.join(" || "));
        }
    }

    // 21b. --tshark-filter: print full tshark command for matched dialogs
    if cli.tshark_filter.is_some() || (cli.wireshark && cli.input.is_some()) {
        if let Some(ref _tshark_expr) = cli.tshark_filter {
            // User provided a custom tshark filter expression
            let input_file = cli.input.as_deref().unwrap_or("capture.pcap");
            println!("tshark -r {} -Y '{}' -V", input_file, _tshark_expr);
        } else if cli.input.is_some() {
            // Generate tshark command from tracked dialogs (only when --wireshark + -I)
            let call_ids: Vec<&str> = dialog_store.iter().map(|d| d.call_id.as_str()).collect();
            if !call_ids.is_empty() {
                let input_file = cli.input.as_deref().unwrap_or("capture.pcap");
                let filter_parts: Vec<String> = call_ids
                    .iter()
                    .map(|id| format!("sip.Call-ID == \"{}\"", id))
                    .collect();
                println!(
                    "tshark -r {} -Y '{}' -V",
                    input_file,
                    filter_parts.join(" || ")
                );
            }
        }
    }

    // 22. Summary
    if !cli.quiet {
        log::info!(
            "sipnab: {total_count} packets captured, {sip_count} SIP messages, {rtp_count} RTP streams",
        );

        // Helpful guidance when no SIP traffic was found
        if sip_count == 0 {
            eprintln!(
                "No SIP traffic found. Check that the capture contains SIP packets (typically UDP port 5060-5061)."
            );
            eprintln!("Tip: Use 'sipnab -N -I file.pcap --hexdump' to inspect raw packet content.");
        }
    }

    // If the API server is running, keep the process alive so clients can
    // query the captured data. The API thread serves until interrupted.
    #[cfg(feature = "api")]
    if let Some(thread) = _api_thread {
        log::info!("API server active — press Ctrl-C to stop");
        let _ = thread.join();
    }
}

// ── Packet processing ─────────────────────────────────────────────────

/// Process a single parsed packet through SIP/RTP detection, matching,
/// dialog tracking, and output dispatch.
///
/// `tls_decrypted` should be `true` when the payload was decrypted from a
/// TLS record, so the transport is reported as "TLS" rather than "TCP".
#[allow(clippy::too_many_arguments)]
fn process_parsed_packet(
    pp: &ParsedPacket,
    matcher: &SipMatcher,
    filter_expr: &Option<FilterExpr>,
    output_opts: &OutputOptions,
    cli: &Cli,
    dialog_store: &mut DialogStore,
    stream_store: &mut StreamStore,
    rtp_heuristic: &mut rtp::heuristic::RtpHeuristic,
    event_exec: &mut EventExecEngine,
    scanner_detector: &mut Option<ScannerDetector>,
    fraud_detector: &mut Option<FraudDetector>,
    digest_detector: &mut Option<DigestLeakDetector>,
    reg_flood_detector: &mut Option<RegFloodDetector>,
    alert_engine: &mut AlertEngine,
    scanner_kill_handle: &Option<ScannerKillHandle>,
    kill_response_code: u16,
    sip_count: &mut u64,
    rtp_count: &mut u64,
    prev_timestamp: &mut Option<chrono::DateTime<chrono::Utc>>,
    no_rtp: bool,
    tls_decrypted: bool,
    after_count: usize,
    trailing_remaining: &mut usize,
) {
    // Hexdump output (applies to all packets)
    if cli.hexdump && cli.no_tui {
        let dump = output::hexdump(&pp.payload);
        print!(
            "{} {}:{} -> {}:{} {}\n{}",
            pp.timestamp.format("%H:%M:%S%.3f"),
            pp.src_addr,
            pp.src_port,
            pp.dst_addr,
            pp.dst_port,
            pp.transport,
            dump,
        );
    }

    // Try WebSocket unwrapping for TCP on common WS ports
    let ws_payload = try_websocket_unwrap(pp);
    let effective_payload = ws_payload.as_deref().unwrap_or(&pp.payload);

    // Try SIP detection first
    if sip::is_sip_message(effective_payload) {
        let effective_transport = match pp.transport {
            TransportProto::Tcp if ws_payload.is_some() => TransportProto::Ws,
            TransportProto::Tcp if tls_decrypted => TransportProto::Tls,
            other => other,
        };

        match sip::parse_sip(
            effective_payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            effective_transport,
        ) {
            Ok(sip_msg) => {
                *sip_count += 1;

                // Apply matcher (header-level filters)
                let matcher_pass = matcher.matches(&sip_msg);

                // Track dialog regardless of filter (needed for filter DSL evaluation)
                if !cli.no_dialog {
                    // Fire event exec before updating state (captures state change)
                    let prev_state = sip_msg
                        .call_id()
                        .and_then(|id| dialog_store.get(id))
                        .map(|d| format!("{:?}", d.state));

                    dialog_store.process_message(sip_msg.clone());

                    // Apply --tag to the dialog
                    if let Some(ref tag_label) = cli.tag
                        && let Some(call_id) = sip_msg.call_id()
                        && let Some(dialog) = dialog_store.get_mut(call_id)
                        && !dialog.tags.contains(tag_label)
                    {
                        dialog.tags.push(tag_label.clone());
                    }

                    // Check if state changed, fire event
                    if let Some(call_id) = sip_msg.call_id()
                        && let Some(dialog) = dialog_store.get(call_id)
                    {
                        let new_state = format!("{:?}", dialog.state);
                        if prev_state.as_deref() != Some(&new_state) {
                            event_exec.fire_dialog_event(dialog);
                        }
                    }

                    // Link SDP media endpoints to RTP streams
                    if let Some(sdp) = sip_msg.sdp()
                        && let Some(call_id) = sip_msg.call_id()
                    {
                        for media in &sdp.media {
                            let addr_str = sip::sdp::effective_address(media, &sdp);
                            if let Some(addr) = addr_str
                                && let Ok(ip) = addr.parse::<std::net::IpAddr>()
                            {
                                stream_store.link_to_dialog(ip, media.port, call_id);
                            }
                        }
                    }
                }

                // Apply DSL filter (evaluated after dialog update)
                let filter_pass = if let Some(expr) = &filter_expr {
                    if let Some(call_id) = sip_msg.call_id() {
                        if let Some(dialog) = dialog_store.get(call_id) {
                            let streams: Vec<&sipnab::rtp::stream::RtpStream> =
                                stream_store.iter().collect();
                            let dialog_streams: Vec<&sipnab::rtp::stream::RtpStream> = streams
                                .into_iter()
                                .filter(|s| s.associated_dialog.as_deref() == Some(call_id))
                                .collect();
                            expr.matches_dialog(dialog, &dialog_streams)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };

                // Security detection: scanner
                if let Some(det) = scanner_detector
                    && let Some(alert) = det.check(&sip_msg)
                {
                    alert_engine.fire(
                        "scanner",
                        alert.src_ip,
                        &format!(
                            "method={} ua={} detection={}",
                            alert.method, alert.ua, alert.detection_method
                        ),
                    );
                    if cli.fail2ban {
                        let event = output::format_scanner_event(
                            &alert.src_ip.to_string(),
                            &alert.ua,
                            &alert.method,
                        );
                        println!("{event}");
                    }

                    // D16: Send kill response via isolated worker thread
                    if let Some(handle) = &scanner_kill_handle
                        && let Some(response_bytes) =
                            sec::scanner_kill::build_scanner_response(&sip_msg, kill_response_code)
                    {
                        let _ = handle.send_kill(KillRequest::SendResponse {
                            dst_addr: sip_msg.src_addr,
                            dst_port: sip_msg.src_port,
                            response_bytes,
                        });
                    }
                }

                // Security detection: fraud
                if let Some(det) = fraud_detector
                    && let Some(call_id) = sip_msg.call_id()
                    && let Some(dialog) = dialog_store.get(call_id)
                    && let Some(alert) = det.check(&sip_msg, dialog)
                {
                    alert_engine.fire(
                        "fraud",
                        alert.src_ip,
                        &format!("{:?}: {}", alert.alert_type, alert.detail),
                    );
                }

                // Security detection: digest leak
                if let Some(det) = digest_detector {
                    let alerts = det.check(&sip_msg);
                    for alert in &alerts {
                        alert_engine.fire(
                            "digest",
                            sip_msg.src_addr,
                            &format!("{:?}: {}", alert.vulnerability, alert.detail),
                        );
                    }
                }

                // Security detection: registration flood
                if let Some(det) = reg_flood_detector
                    && let Some(alert) = det.check(&sip_msg)
                {
                    alert_engine.fire(
                        "reg_flood",
                        alert.src_ip,
                        &format!(
                            "count={} threshold={}",
                            alert.register_count, alert.threshold
                        ),
                    );
                    if cli.fail2ban {
                        let event = output::format_reg_flood_event(
                            &alert.src_ip.to_string(),
                            alert.register_count,
                        );
                        println!("{event}");
                    }
                }

                // STIR/SHAKEN extraction (I1)
                #[cfg(feature = "tls")]
                if cli.stir_shaken
                    && let Some(result) = sip_msg.stir_shaken()
                {
                    match result {
                        Ok(info) => {
                            log::info!(
                                "STIR/SHAKEN: attest={:?} orig={} dest={} verified={:?}",
                                info.attestation,
                                info.orig_tn.as_deref().unwrap_or("-"),
                                info.dest_tn.as_deref().unwrap_or("-"),
                                info.verified,
                            );
                        }
                        Err(e) => {
                            log::debug!("STIR/SHAKEN parse error: {e}");
                        }
                    }
                }

                // I5: --calls-only: skip non-INVITE dialogs from output
                let calls_only_pass = if cli.calls_only {
                    if let Some(call_id) = sip_msg.call_id()
                        && let Some(dialog) = dialog_store.get(call_id)
                    {
                        dialog.method == "INVITE"
                    } else {
                        // No dialog tracked — only show if it's an INVITE request
                        sip_msg.method.as_deref() == Some("INVITE")
                    }
                } else {
                    true
                };

                // Output if matcher/filter pass, or if trailing context is active
                let direct_match = matcher_pass && filter_pass && calls_only_pass;
                let trailing_match = *trailing_remaining > 0;

                if (direct_match || trailing_match) && cli.no_tui {
                    dispatch_sip_output(&sip_msg, output_opts, cli, *prev_timestamp);

                    if direct_match {
                        // Reset trailing counter on new match
                        *trailing_remaining = after_count;
                    } else if trailing_match {
                        *trailing_remaining -= 1;
                    }
                }

                *prev_timestamp = Some(sip_msg.timestamp);
            }
            Err(e) => {
                log::debug!("SIP parse error: {e}");
            }
        }
        return;
    }

    // RTP/RTCP detection (only for UDP, unless disabled)
    if no_rtp || pp.transport != TransportProto::Udp {
        return;
    }

    // RTCP detection: odd port, version=2, PT in 200-204 range
    if is_rtcp_packet(&pp.payload, pp.dst_port) {
        let rtcp_packets = parse_rtcp(&pp.payload);
        if !rtcp_packets.is_empty() {
            stream_store.process_rtcp(&rtcp_packets);
        }
        return;
    }

    // RTP detection: explicit check first
    if rtp::is_rtp_packet(&pp.payload)
        && let Ok(rtp_hdr) = parse_rtp_header(&pp.payload)
    {
        stream_store.process_rtp(pp, &rtp_hdr, pp.timestamp);
        *rtp_count += 1;

        // DTMF extraction (I2): if --telephone-event is set and we
        // have the RTP payload after the header, attempt DTMF decode.
        // Uses a default telephone-event PT of 101 (common convention).
        if cli.telephone_event && rtp_hdr.payload_offset < pp.payload.len() {
            let rtp_payload = &pp.payload[rtp_hdr.payload_offset..];
            if let Some(dtmf) = rtp::dtmf::extract_dtmf(
                rtp_payload,
                rtp_hdr.payload_type,
                101, // Default telephone-event PT
                pp.timestamp,
            ) {
                log::info!(
                    "DTMF digit='{}' duration={}ms ssrc=0x{:08x}",
                    dtmf.digit,
                    dtmf.duration_ms,
                    rtp_hdr.ssrc
                );
            }
        }

        // Fire quality events on each RTP packet (rate-limited internally)
        let key = sipnab::rtp::stream::StreamKey {
            ssrc: rtp_hdr.ssrc,
            src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
            dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
        };
        if let Some(stream) = stream_store.get(&key) {
            event_exec.fire_quality_event(stream);
        }
        return;
    }

    // Heuristic RTP detection for non-obvious RTP
    if let Some(rtp_hdr) = rtp_heuristic.check(pp) {
        stream_store.process_rtp(pp, &rtp_hdr, pp.timestamp);
        *rtp_count += 1;
    }
}

/// Attempt TLS decryption on a TCP payload.
///
/// If the payload looks like TLS, parses the records and tries to decrypt
/// ApplicationData records. If decryption yields SIP content, returns a
/// synthetic [`ParsedPacket`] with the decrypted payload and transport set
/// to reflect the TLS origin.
#[cfg(feature = "tls")]
fn try_tls_decrypt(
    pp: &ParsedPacket,
    tls_decryptor: &mut Option<TlsDecryptor>,
) -> Option<ParsedPacket> {
    let decryptor = tls_decryptor.as_mut()?;

    if pp.transport != TransportProto::Tcp {
        return None;
    }

    if !tls::is_tls(&pp.payload) {
        return None;
    }

    let records = tls::parse_tls_records(&pp.payload);
    for record in &records {
        if let Some(plaintext) = decryptor.try_decrypt(record, pp.src_addr, pp.dst_addr)
            && sip::is_sip_message(&plaintext)
        {
            // Build a synthetic ParsedPacket with the decrypted SIP payload.
            // The transport string "TLS" is set during SIP message construction
            // in process_parsed_packet via the tls_decrypted flag.
            let mut decrypted_pp = pp.clone();
            decrypted_pp.payload = plaintext;
            return Some(decrypted_pp);
        }
    }

    None
}

/// Try to unwrap a WebSocket frame from a TCP packet on common WS ports.
///
/// Returns `Some(payload)` if the packet is TCP, the destination or source
/// port is a common WebSocket port (80, 443, 8080, 8443), and the data
/// contains a valid WebSocket data frame wrapping SIP content.
fn try_websocket_unwrap(pp: &ParsedPacket) -> Option<Vec<u8>> {
    if pp.transport != TransportProto::Tcp {
        return None;
    }

    // Only attempt on common WebSocket ports
    let is_ws_port =
        websocket::WS_PORTS.contains(&pp.dst_port) || websocket::WS_PORTS.contains(&pp.src_port);
    if !is_ws_port {
        return None;
    }

    if !websocket::is_websocket_frame(&pp.payload) {
        return None;
    }

    match websocket::unwrap_websocket_frame(&pp.payload) {
        Ok(Some(payload)) if sip::is_sip_message(&payload) => Some(payload),
        _ => None,
    }
}

/// Check if a UDP payload looks like RTCP.
///
/// RTCP convention: odd destination port (RTP port + 1), version=2,
/// and payload type in the 200-204 range.
fn is_rtcp_packet(data: &[u8], dst_port: u16) -> bool {
    if data.len() < 8 {
        return false;
    }
    // RTCP typically uses odd port (RTP+1)
    if dst_port.is_multiple_of(2) {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    let pt = data[1];
    (200..=204).contains(&pt)
}

// ── SIP output dispatch ──────────────────────────────────────────────

/// Dispatch a matched SIP message to the configured output backend.
fn dispatch_sip_output(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
) {
    if cli.json || cli.json_pretty {
        let json = output::json::message_to_json(msg);
        print!("{json}");
    } else if cli.fail2ban {
        // Fail2ban output for scanner-like messages
        if msg.is_request {
            let ua = msg.user_agent().unwrap_or("unknown");
            let method = msg.method.as_deref().unwrap_or("UNKNOWN");
            let event = output::format_scanner_event(&msg.src_addr.to_string(), ua, method);
            println!("{event}");
        }
    } else if cli.text_dump {
        // Raw SIP message text dump
        let raw = String::from_utf8_lossy(&msg.raw);
        println!("{raw}");
    } else {
        output::print_sip_message(msg, opts, prev_timestamp);
    }

    // Flush if --line-buffer is set
    if cli.line_buffer {
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }
}

// ── Report generation ────────────────────────────────────────────────

/// Generate post-capture reports based on CLI flags.
fn generate_reports(cli: &Cli, dialog_store: &DialogStore, stream_store: &StreamStore) {
    // --report: dialog summary table
    if cli.report && cli.no_tui {
        let dialogs: Vec<&sipnab::sip::dialog::SipDialog> = dialog_store.iter().collect();
        let streams: Vec<&sipnab::rtp::stream::RtpStream> = stream_store.iter().collect();
        let report = output::print_dialog_report(&dialogs, &streams);
        print!("{report}");
    }

    // --call-report <call-id>: detailed single-call report
    if let Some(ref call_id) = cli.call_report {
        if let Some(dialog) = dialog_store.get(call_id) {
            let all_streams: Vec<&sipnab::rtp::stream::RtpStream> = stream_store.iter().collect();
            let dialog_streams: Vec<&sipnab::rtp::stream::RtpStream> = all_streams
                .into_iter()
                .filter(|s| s.associated_dialog.as_deref() == Some(call_id.as_str()))
                .collect();
            let diagnosis = sipnab::rtp::diagnosis::diagnose_media(&dialog_streams, None);
            let format = if cli.json || cli.json_pretty {
                ReportFormat::Json
            } else if cli.markdown {
                ReportFormat::Markdown
            } else {
                ReportFormat::Text
            };
            let report = output::generate_call_report(dialog, &dialog_streams, &diagnosis, format);
            print!("{report}");
        } else {
            log::warn!("Call-ID '{}' not found in tracked dialogs", call_id);
        }
    }
}

// ── Filter expression building ──────────────────────────────────────

/// Build a `FilterExpr` from CLI `--filter` flag or diagnostic aliases.
fn build_filter_expr(cli: &Cli) -> Option<FilterExpr> {
    // Explicit --filter takes precedence
    if let Some(ref expr) = cli.filter {
        match FilterExpr::parse(expr) {
            Ok(f) => return Some(f),
            Err(e) => {
                log::error!("Invalid --filter expression: {e}");
                std::process::exit(2);
            }
        }
    }

    // Diagnostic alias expansion
    let mut parts: Vec<&str> = Vec::new();

    if cli.problems {
        parts.push("retransmits > 0 OR state == 'Failed'");
    }
    if cli.slow_setup {
        parts.push("setup_time > 3.0");
    }
    if cli.short_calls {
        parts.push("duration < 10.0");
    }
    if cli.one_way {
        parts.push("one_way == true");
    }
    if cli.nat_issues {
        parts.push("nat_mismatch == true");
    }

    if parts.is_empty() {
        return None;
    }

    let combined = parts.join(" OR ");
    match FilterExpr::parse(&combined) {
        Ok(f) => Some(f),
        Err(e) => {
            log::error!("Internal error building diagnostic filter: {e}");
            std::process::exit(2);
        }
    }
}

// ── Capture config builder ──────────────────────────────────────────

/// Build a [`CaptureConfig`] by merging CLI flags with config file values.
fn build_capture_config(cli: &Cli, config: &Config) -> CaptureConfig {
    let snaplen = cli.snaplen.or(config.capture.snaplen).unwrap_or(65535);

    let buffer_mb = cli.buffer.or(config.capture.buffer).unwrap_or(2);

    // BPF filter: --bpf-file takes precedence, then positional args
    let bpf_filter = if let Some(ref bpf_file) = cli.bpf_file {
        match std::fs::read_to_string(bpf_file) {
            Ok(content) => Some(content.trim().to_string()),
            Err(e) => {
                log::error!("Failed to read BPF filter file '{}': {e}", bpf_file);
                std::process::exit(2);
            }
        }
    } else if !cli.bpf_filter.is_empty() {
        Some(cli.bpf_filter.join(" "))
    } else {
        None
    };

    let count = cli.count;

    let duration = cli
        .duration
        .as_ref()
        .map(|d| match capture::parse_duration(d) {
            Ok(dur) => dur,
            Err(e) => {
                log::error!("Invalid --duration: {e}");
                std::process::exit(2);
            }
        });

    CaptureConfig {
        snaplen,
        buffer_mb,
        bpf_filter,
        count,
        duration,
        replay: cli.replay,
    }
}

// ── API server ─────────────────────────────────────────────────────

/// Start the REST API server in a background thread with its own tokio runtime.
///
/// Returns the thread handle, or `None` if `--api` was not specified.
#[cfg(feature = "api")]
fn start_api_server(
    cli: &Cli,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
) -> Option<std::thread::JoinHandle<()>> {
    use sipnab::output::api::{self, ApiServerConfig, ApiState, RateLimiter};

    let addr_str = cli.api.as_ref()?;
    let bind_addr = match api::parse_bind_addr(addr_str) {
        Ok(a) => a,
        Err(e) => {
            log::error!("Invalid --api address: {e}");
            std::process::exit(2);
        }
    };

    let state = ApiState {
        dialog_store,
        stream_store,
        api_key: cli.api_key.clone(),
        rate_limiter: Arc::new(parking_lot::Mutex::new(RateLimiter::new(100))),
    };

    let server_config = ApiServerConfig {
        max_conn: cli.api_max_conn,
        tls_cert: cli.api_tls_cert.clone(),
        tls_key: cli.api_tls_key.clone(),
    };

    let handle = std::thread::Builder::new()
        .name("api-server".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("Failed to create tokio runtime for API server: {e}");
                    return;
                }
            };

            if let Err(e) = rt.block_on(api::run_server(bind_addr, state, server_config)) {
                log::error!("API server error: {e}");
            }
        });
    match handle {
        Ok(h) => Some(h),
        Err(e) => {
            log::error!("Failed to spawn API server thread: {e}");
            None
        }
    }
}

/// Mirror a parsed packet into the shared stores used by the API server.
///
/// This is used in batch mode when the API is enabled: the main processing
/// loop uses local stores for performance, and we duplicate updates to the
/// shared stores so the API can read them.
#[cfg(feature = "api")]
fn mirror_to_shared_stores(
    pp: &ParsedPacket,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    no_rtp: bool,
) {
    // Try WebSocket unwrapping for TCP on common WS ports
    let ws_payload = try_websocket_unwrap(pp);
    let effective_payload = ws_payload.as_deref().unwrap_or(&pp.payload);

    let effective_transport = match pp.transport {
        TransportProto::Tcp if ws_payload.is_some() => TransportProto::Ws,
        other => other,
    };

    // Mirror SIP messages
    if sip::is_sip_message(effective_payload) {
        if let Ok(sip_msg) = sip::parse_sip(
            effective_payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            effective_transport,
        ) {
            let mut ds = dialog_store.write();
            ds.process_message(sip_msg.clone());

            // Link SDP media endpoints to RTP streams
            if let Some(sdp) = sip_msg.sdp()
                && let Some(call_id) = sip_msg.call_id()
            {
                let mut ss = stream_store.write();
                for media in &sdp.media {
                    let addr_str = sip::sdp::effective_address(media, &sdp);
                    if let Some(addr) = addr_str
                        && let Ok(ip) = addr.parse::<std::net::IpAddr>()
                    {
                        ss.link_to_dialog(ip, media.port, call_id);
                    }
                }
            }
        }
        return;
    }

    // Mirror RTP
    if no_rtp || pp.transport != TransportProto::Udp {
        return;
    }

    if rtp::is_rtp_packet(&pp.payload)
        && let Ok(rtp_hdr) = parse_rtp_header(&pp.payload)
    {
        stream_store.write().process_rtp(pp, &rtp_hdr, pp.timestamp);
    }
}
