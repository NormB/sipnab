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
use sipnab::capture::{
    self, CaptureConfig, CaptureSource, ParsedPacket, PcapExportMode, PcapWriter,
};
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

// ── Bundled parameter structs ──────────────────────────────────────

/// Security detection engines bundle.
struct DetectionEngines {
    scanner: Option<ScannerDetector>,
    fraud: Option<FraudDetector>,
    digest: Option<DigestLeakDetector>,
    reg_flood: Option<RegFloodDetector>,
    /// Shared with the MCP server (when --mcp is on) so the
    /// `security_findings` tool can read the FindingsHistory ring buffer.
    alerts: Arc<RwLock<AlertEngine>>,
    kill_handle: Option<ScannerKillHandle>,
    kill_response_code: u16,
}

/// Packet processing counters and state.
struct PacketCounters {
    sip_count: u64,
    rtp_count: u64,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    trailing_remaining: usize,
}

/// Owned batch-mode processing components.
struct BatchProcessing {
    matcher: SipMatcher,
    filter_expr: Option<FilterExpr>,
    output_opts: OutputOptions,
    event_exec: EventExecEngine,
}

/// Immutable batch-mode configuration for packet processing.
struct BatchContext<'a> {
    matcher: &'a SipMatcher,
    filter_expr: &'a Option<FilterExpr>,
    output_opts: &'a OutputOptions,
    cli: &'a Cli,
    no_rtp: bool,
    after_count: usize,
    portrange: (u16, u16),
}

/// Mutable processing state for the main receive loop.
struct ProcessingState<'a> {
    dialog_store: &'a mut DialogStore,
    stream_store: &'a mut StreamStore,
    rtp_heuristic: &'a mut rtp::heuristic::RtpHeuristic,
    event_exec: &'a mut EventExecEngine,
}

/// Capture split/stop policy.
struct CapturePolicy {
    split_bytes: Option<u64>,
    split_duration: Option<std::time::Duration>,
    autostop_duration: Option<std::time::Duration>,
    autostop_filesize_mb: Option<u64>,
    portrange: (u16, u16),
}

fn main() {
    // 1. Parse CLI arguments
    let cli = Cli::parse_args();

    // 2. Setup logging (env var: SIPNAB_LOG, default: info; quiet overrides to warn)
    // TUI mode: suppress log output to avoid corruption of the alternate screen.
    // Logs are only visible in CLI mode (-N) or when SIPNAB_LOG is explicitly set.
    let tui_active = !cli.no_tui;
    let default_level = if cli.quiet {
        "warn"
    } else if tui_active && std::env::var("SIPNAB_LOG").is_err() {
        "error"
    } else {
        "info"
    };
    // Phase 8.0b: tracing-subscriber writes to stderr by default — preserves
    // the future stdio MCP invariant that stdout is the JSON-RPC wire.
    // tracing-log routes any remaining `log::*` events from third-party deps
    // through the same subscriber.
    let env_filter = tracing_subscriber::EnvFilter::try_from_env("SIPNAB_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    let _ = tracing_log::LogTracer::init();

    // 3. Install signal handlers
    signals::install_handlers();

    // 4. Validate CLI argument combinations
    if let Err(msg) = cli.validate() {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }

    // 4a. Warn about unimplemented flags that were set
    cli.warn_unimplemented_flags();

    // 5. Load configuration
    let loaded = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(loaded) => {
            if let Some(ref source) = loaded.source {
                tracing::info!("Loaded config from {}", source.display());
            }
            loaded
        }
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };

    // 5a. Validate limits config
    if let Err(e) = loaded.config.limits.validate() {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    // 5b. Apply configurable security limits from [limits] section
    if let Some(v) = loaded.config.limits.max_header_line {
        sipnab::sip::parser::set_parser_limits(
            v as usize,
            loaded
                .config
                .limits
                .max_headers_per_message
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
        match loaded.config.dump() {
            Ok(toml_str) => println!("{toml_str}"),
            Err(e) => {
                tracing::error!("Failed to dump config: {e}");
                std::process::exit(1);
            }
        }
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
                        tracing::error!("Invalid --hep-allow CIDR '{}': {}", cidr, e);
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
                    tracing::info!("Auto-detected capture device: {}", device);
                    CaptureSource::Live { device }
                }
                Err(e) => {
                    let devices = capture::device::list_devices();
                    if devices.is_empty() {
                        tracing::error!(
                            "No capture device found. Use -d <device> or -I <file>\n  \
                             Try: sudo sipnab"
                        );
                    } else {
                        tracing::error!(
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
            tracing::error!("Invalid --portrange: {e}");
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
            tracing::info!("Auto-generated BPF filter: {filter}");
        }
    }

    // 8b. Parse --autostop condition
    let autostop_duration: Option<std::time::Duration>;
    let autostop_filesize_mb: Option<u64>;
    if let Some(ref cond) = cli.autostop {
        let (dur, size) = match parse_autostop(cond) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("Invalid --autostop: {e}");
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
                tracing::error!("{e}");
                std::process::exit(2);
            }
        }
    } else {
        (None, None)
    };

    // 10. Build the SIP matcher from CLI filter flags, with config fallbacks
    let effective_from = cli.from.as_deref().or(loaded.config.filter.from.as_deref());
    let effective_to = cli.to.as_deref().or(loaded.config.filter.to.as_deref());
    let matcher = match SipMatcher::new_with_overrides(&cli, None, effective_from, effective_to) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Invalid filter pattern: {e}");
            std::process::exit(2);
        }
    };

    // 11. Build the filter DSL expression if --filter (or diagnostic aliases),
    //     falling back to config.filter.expression
    let filter_expr = build_filter_expr(&cli, &loaded.config);

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
                tracing::error!("--multi-device requires a live capture device (-d)");
                std::process::exit(2);
            }
        };
        match capture::start_multi_capture(&device_str, capture_config.clone(), tx, Some(ready_tx))
        {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Failed to start multi-device capture: {e}");
                std::process::exit(1);
            }
        }
    } else {
        match capture::start_capture(source, capture_config.clone(), tx, Some(ready_tx)) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Failed to start capture: {e}");
                std::process::exit(1);
            }
        }
    };

    // 15a. Wait for the capture thread to confirm the device/file/socket is open.
    //      This must happen BEFORE privilege drop so we don't lose CAP_NET_RAW.
    match ready_rx.recv() {
        Ok(Ok(())) => {
            tracing::debug!("Capture source opened successfully");
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
                tracing::error!(
                    "Permission denied on '{}'. Run with sudo or set capabilities:\n  \
                     sudo sipnab\n  \
                     # or (Linux only):\n  \
                     sudo setcap cap_net_raw+ep $(which sipnab)",
                    dev_name
                );
            } else {
                tracing::error!("Capture source failed to open: {e}");
            }
            std::process::exit(1);
        }
        Err(_) => {
            tracing::error!("Capture thread exited before signaling ready");
            std::process::exit(1);
        }
    }

    // 16. Chroot BEFORE dropping privileges (chroot requires root).
    // Correct POSIX sequence: chroot → chdir("/") → setgroups → setgid → setuid
    let effective_chroot = cli
        .chroot
        .as_ref()
        .or(loaded.config.privilege.chroot.as_ref());
    if let Some(ref chroot_dir) = effective_chroot
        && let Err(e) = privilege::do_chroot(std::path::Path::new(chroot_dir))
    {
        tracing::error!("Failed to chroot: {e}");
        std::process::exit(1);
    }

    // 16a. Drop privileges now that capture devices are open and chroot is applied (D15)
    let effective_user = cli
        .user
        .as_deref()
        .or(loaded.config.privilege.user.as_deref());
    let effective_no_priv_drop =
        cli.no_priv_drop || loaded.config.privilege.no_priv_drop.unwrap_or(false);
    if let Err(e) = privilege::drop_privileges(effective_user, effective_no_priv_drop) {
        tracing::error!("Failed to drop privileges: {e}");
        std::process::exit(1);
    }

    // 16b. Initialize syslog if --syslog is set
    if cli.syslog {
        sipnab::security::alerting::init_syslog();
    }

    // 16c. Validate --hep-send requires hep feature
    #[cfg(not(feature = "hep"))]
    if cli.hep_send.is_some() {
        tracing::error!("HEP support requires --features hep");
        std::process::exit(2);
    }

    // 16d. Validate --hep-parse requires hep feature
    #[cfg(not(feature = "hep"))]
    if cli.hep_parse {
        tracing::error!("HEP support requires --features hep");
        std::process::exit(2);
    }

    // 16d2. Validate TLS flags require tls feature
    #[cfg(not(feature = "tls"))]
    {
        if cli.tls_key.is_some() {
            tracing::error!("--tls-key requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.keylog.is_some() {
            tracing::error!("--keylog requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.keylog_watch {
            tracing::error!("--keylog-watch requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.srtp_keys.is_some() {
            tracing::error!("--srtp-keys requires the 'tls' feature (not compiled in)");
            std::process::exit(2);
        }
    }

    // 16d3. Validate API flags require api feature
    #[cfg(not(feature = "api"))]
    {
        if cli.api.is_some() {
            tracing::error!("--api requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_key.is_some() {
            tracing::error!("--api-key requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_tls_cert.is_some() {
            tracing::error!("--api-tls-cert requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
        if cli.api_tls_key.is_some() {
            tracing::error!("--api-tls-key requires the 'api' feature (not compiled in)");
            std::process::exit(2);
        }
    }

    // 16e. Validate --pcap-export-mode
    match cli.pcap_export_mode.as_str() {
        "decrypted" | "encrypted+dsb" | "raw" => {}
        other => {
            tracing::error!(
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
                tracing::info!("DTLS keylog: {count} entries loaded from {dtls_path}");
            }
            Err(e) => {
                tracing::error!("Failed to load DTLS keylog: {e}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(feature = "tls"))]
    if cli.dtls_keylog.is_some() {
        tracing::error!("--dtls-keylog requires the 'tls' feature (not compiled in)");
        std::process::exit(2);
    }

    // 16g. Validate --api-tls-cert/--api-tls-key consistency
    if cli.api_tls_cert.is_some() != cli.api_tls_key.is_some() {
        tracing::error!("--api-tls-cert and --api-tls-key must both be specified together");
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
        tracing::error!("Failed to disable core dumps: {e}");
        std::process::exit(1);
    }

    // 17a. Start standalone metrics server if --metrics is set (without --api).
    // Note: The metrics server shares the same stores that are created inside
    // run_tui_mode/run_batch_mode. We parse/validate the address here but defer
    // actual server start to those functions where the stores are available.
    // Only consumed by run_tui_mode (TUI path); batch mode starts its metrics
    // server separately, so gate this to the combination that actually uses it.
    #[cfg(all(feature = "api", feature = "tui"))]
    let metrics_bind_addr: Option<std::net::SocketAddr> = cli.metrics.as_deref().map(|addr_str| {
        match sipnab::output::prometheus_server::parse_metrics_addr(addr_str) {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("Invalid --metrics address: {e}");
                std::process::exit(2);
            }
        }
    });

    // 18. Branch: TUI mode vs non-interactive mode.
    //
    // MCP mode (--mcp) is treated as a non-interactive variant of batch mode:
    // it forces no_tui, suppresses stdout text/JSON event output, and spawns
    // an MCP server thread alongside the capture loop. The decision lives
    // inside run_batch_mode so MCP mode reuses the existing single-parse,
    // shared-store infrastructure from Phase 8.0a.
    #[cfg(feature = "mcp")]
    let use_tui = !cli.no_tui && !cli.mcp;
    #[cfg(all(feature = "tui", not(feature = "mcp")))]
    let use_tui = !cli.no_tui;
    #[cfg(not(any(feature = "tui", feature = "mcp")))]
    let use_tui = false;

    if use_tui {
        #[cfg(feature = "tui")]
        run_tui_mode(
            cli,
            loaded.config,
            capture_config,
            handle,
            rx,
            CapturePolicy {
                split_bytes,
                split_duration,
                autostop_duration,
                autostop_filesize_mb,
                portrange,
            },
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
            BatchProcessing {
                matcher,
                filter_expr,
                output_opts,
                event_exec,
            },
            CapturePolicy {
                split_bytes,
                split_duration,
                autostop_duration,
                autostop_filesize_mb,
                portrange,
            },
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
fn run_tui_mode(
    cli: Cli,
    config: Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: crossbeam_channel::Receiver<capture::Packet>,
    policy: CapturePolicy,
    #[cfg(feature = "api")] metrics_bind_addr: Option<std::net::SocketAddr>,
) {
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);

    let dialog_store = Arc::new(RwLock::new(DialogStore::new(
        cli.limit as usize,
        cli.rotate,
    )));
    let stream_store = {
        let mut ss = StreamStore::new(cli.max_streams as usize);
        if let Some(max_frames) = config.limits.max_audio_frames {
            ss.set_max_audio_frames(max_frames as usize);
        }
        Arc::new(RwLock::new(ss))
    };

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
                tracing::error!("Failed to start metrics server: {e}");
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
            let tui_export_mode = PcapExportMode::parse_mode(&cli_clone.pcap_export_mode)
                .unwrap_or(PcapExportMode::Decrypted);
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
                    let compacted = ds.write().compact_idle(chrono::Utc::now());
                    if compacted.messages_evicted > 0 {
                        tracing::debug!(
                            "idle-dialog compaction: dropped {} messages from {} dialogs",
                            compacted.messages_evicted,
                            compacted.dialogs_compacted
                        );
                    }
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
                    match PcapWriter::with_format(
                        &PathBuf::from(output_path),
                        packet.link_type,
                        policy.split_bytes,
                        policy.split_duration,
                        cli_clone.pcapng,
                        tui_export_mode,
                    ) {
                        Ok(mut w) => {
                            // Write DSB with keylog content if mode requires it
                            if let Some(ref keylog_path) = cli_clone.keylog
                                && let Err(e) =
                                    w.maybe_write_keylog_dsb(std::path::Path::new(keylog_path))
                            {
                                tracing::warn!("Failed to write DSB: {e}");
                            }
                            writer = Some(w);
                        }
                        Err(e) => {
                            tracing::error!("Failed to open output file: {e}");
                            break;
                        }
                    }
                }

                if let Some(ref mut w) = writer
                    && let Err(e) = w.write(&packet)
                {
                    tracing::error!("Failed to write packet: {e}");
                    break;
                }

                total_count += 1;

                let parsed_packets = processor.process(&packet);
                for pp in &parsed_packets {
                    // Skip processing when paused (capture continues to prevent buffer overflow)
                    if paused_for_thread.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    sipnab::pipeline::process_packet(
                        pp,
                        &ds,
                        &ss,
                        &mut rtp_heuristic,
                        &sipnab::pipeline::PipelineOptions {
                            no_dialog: cli_clone.no_dialog,
                            no_rtp,
                        },
                    );
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

            // Flush the output writer explicitly: BufWriter's Drop
            // discards flush errors (silent truncation on ENOSPC).
            if let Some(ref mut w) = writer
                && let Err(e) = w.finish()
            {
                tracing::error!("Output file may be incomplete: {e}");
            }
        });
    let processing_thread = match processing_thread {
        Ok(handle) => handle,
        Err(e) => {
            tracing::error!("Failed to spawn processing thread: {e}");
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
        config.display.visible_columns.clone(),
    ) {
        tracing::error!("TUI error: {e}");
    }

    // Signal shutdown and wait for threads
    // The TUI has exited; signal shutdown so processing thread stops
    signals::request_shutdown();

    if let Err(e) = processing_thread.join() {
        tracing::error!("Processing thread panicked: {:?}", e);
    }

    drop(handle);
}

// ── Batch (non-interactive) mode ────────────────────────────────────

/// Run sipnab in non-interactive batch mode (original behavior).
fn run_batch_mode(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: crossbeam_channel::Receiver<capture::Packet>,
    batch: BatchProcessing,
    policy: CapturePolicy,
) {
    let matcher = batch.matcher;
    let filter_expr = batch.filter_expr;
    let output_opts = batch.output_opts;
    let mut event_exec = batch.event_exec;
    let split_bytes = policy.split_bytes;
    let split_duration = policy.split_duration;
    let portrange = policy.portrange;
    let autostop_duration = policy.autostop_duration;
    let autostop_filesize_mb = policy.autostop_filesize_mb;
    // 16. Open output writer if -O is specified
    let mut writer: Option<PcapWriter> = None;
    let use_pcapng = cli.pcapng;
    let export_mode =
        PcapExportMode::parse_mode(&cli.pcap_export_mode).unwrap_or(PcapExportMode::Decrypted);

    // 16a. Initialize HEP sender if --hep-send is set
    #[cfg(feature = "hep")]
    let hep_sender: Option<sipnab::capture::hep::HepSender> = if let Some(ref addr) = cli.hep_send {
        match sipnab::capture::hep::HepSender::new(addr, 1) {
            Ok(sender) => {
                tracing::info!("HEP sender targeting {addr}");
                Some(sender)
            }
            Err(e) => {
                tracing::error!("Failed to create HEP sender: {e}");
                None
            }
        }
    } else {
        None
    };

    // 17. Initialize processing state
    //
    // Stores live behind Arc<RwLock<...>> from the start so the API server
    // (when --api is set) reads from the SAME store the packet loop writes
    // to, eliminating the prior mirror-and-double-parse pattern. In the
    // common single-writer batch case the locks are uncontested.
    let mut processor = capture::PacketProcessor::with_max_sessions(cli.max_reassembly as usize);
    let dialog_store: Arc<RwLock<DialogStore>> = Arc::new(RwLock::new(DialogStore::new(
        cli.limit as usize,
        cli.rotate,
    )));
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    let stream_store: Arc<RwLock<StreamStore>> = {
        let mut ss = StreamStore::new(cli.max_streams as usize);
        if let Some(max_frames) = config.limits.max_audio_frames {
            ss.set_max_audio_frames(max_frames as usize);
        }
        // Batch mode has no audio export/playback path; don't pay a
        // per-packet payload clone for buffers nothing will read.
        ss.set_audio_capture(false);
        Arc::new(RwLock::new(ss))
    };
    let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

    // 17a. Initialize security detectors
    let kill_scanner_active = cli.kill_scanner || config.security.kill_scanner.unwrap_or(false);
    let scanner_detector = if kill_scanner_active {
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
    let scanner_kill_handle: Option<ScannerKillHandle> = if kill_scanner_active {
        match process_isolation::spawn_scanner_kill_worker(None) {
            Ok(handle) => Some(handle),
            Err(e) => {
                tracing::error!("Failed to spawn scanner-kill worker: {e}");
                None
            }
        }
    } else {
        None
    };
    let kill_response_code = cli.kill_response;

    let fraud_detector = if cli.fraud_detect || config.security.fraud_detect.unwrap_or(false) {
        Some(FraudDetector::new(None))
    } else {
        None
    };

    let digest_detector = if cli.digest_leak {
        Some(DigestLeakDetector::new())
    } else {
        None
    };

    let reg_flood_detector = if cli.reg_flood {
        Some(RegFloodDetector::new(0))
    } else {
        None
    };

    // 17b. Initialize alert engine from --alert rules and --alert-exec,
    //      falling back to config.security.alert and config.security.alert_exec
    let effective_alert_sources: &[String] = if cli.alert.is_empty() {
        config.security.alert.as_deref().unwrap_or(&[])
    } else {
        &cli.alert
    };
    let alert_rules: Vec<AlertRule> = effective_alert_sources
        .iter()
        .filter_map(|s| match AlertRule::parse(s) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("Skipping invalid alert rule '{}': {}", s, e);
                None
            }
        })
        .collect();
    let effective_alert_exec = cli
        .alert_exec
        .clone()
        .or(config.security.alert_exec.clone());
    let mut alert_engine = AlertEngine::new(alert_rules, effective_alert_exec);
    if cli.syslog {
        alert_engine.set_syslog(true);
    }
    let alert_engine = Arc::new(RwLock::new(alert_engine));

    let mut engines = DetectionEngines {
        scanner: scanner_detector,
        fraud: fraud_detector,
        digest: digest_detector,
        reg_flood: reg_flood_detector,
        alerts: alert_engine,
        kill_handle: scanner_kill_handle,
        kill_response_code,
    };

    // 17c. Initialize TLS decryptor if --keylog is provided
    #[cfg(feature = "tls")]
    let mut tls_decryptor: Option<TlsDecryptor> = if cli.keylog.is_some() {
        let keylog_path = cli.keylog.as_deref().map(std::path::Path::new);
        let crypto = sipnab::crypto::default_backend();
        match TlsDecryptor::new(keylog_path, crypto) {
            Ok(d) => {
                if d.keylog_entry_count() > 0 {
                    tracing::info!(
                        "sipnab: TLS decryption active (keylog loaded). \
                         Decrypted traffic visible in output."
                    );
                }
                Some(d)
            }
            Err(e) => {
                tracing::error!("Failed to initialize TLS decryptor: {e}");
                None
            }
        }
    } else {
        None
    };

    // Start API server if --api is specified (feature-gated)
    // The API reads from the SAME stores the packet loop writes to —
    // no mirror, no second parse.
    #[cfg(feature = "api")]
    let _api_thread = if cli.api.is_some() {
        start_api_server(&cli, Arc::clone(&dialog_store), Arc::clone(&stream_store))
    } else {
        None
    };

    // Start MCP server if --mcp is specified (feature-gated). The server
    // reads the same Arc<RwLock<...>> stores the packet loop writes to,
    // plus the shared AlertEngine for the security_findings tool.
    #[cfg(feature = "mcp")]
    let _mcp_thread = if cli.mcp {
        start_mcp_server(
            &cli,
            Arc::clone(&dialog_store),
            Arc::clone(&stream_store),
            Arc::clone(&engines.alerts),
        )
    } else {
        None
    };

    // --after / -A trailing context counter
    let after_count = cli.after.unwrap_or(0);

    let batch_ctx = BatchContext {
        matcher: &matcher,
        filter_expr: &filter_expr,
        output_opts: &output_opts,
        cli: &cli,
        no_rtp,
        after_count,
        portrange,
    };

    let mut last_sweep = std::time::Instant::now();
    let sweep_interval = std::time::Duration::from_secs(5);

    // 18. Main receive loop
    let start = std::time::Instant::now();
    let mut total_count: u64 = 0;
    let mut counters = PacketCounters {
        sip_count: 0,
        rtp_count: 0,
        prev_timestamp: None,
        trailing_remaining: 0,
    };

    // Autostop filesize in bytes (input is in MB)
    let autostop_filesize_bytes = autostop_filesize_mb.map(|mb| mb * 1_000_000);

    loop {
        if signals::shutdown_requested() {
            break;
        }

        // Periodic sweep of reassembly state and orphan detection (every 5 seconds)
        if last_sweep.elapsed() >= sweep_interval {
            processor.sweep();
            stream_store
                .write()
                .mark_orphaned(std::time::Duration::from_secs(30));
            let compacted = dialog_store.write().compact_idle(chrono::Utc::now());
            if compacted.messages_evicted > 0 {
                tracing::debug!(
                    "idle-dialog compaction: dropped {} messages from {} dialogs",
                    compacted.messages_evicted,
                    compacted.dialogs_compacted
                );
            }
            let security_max_age = std::time::Duration::from_secs(120);
            if let Some(det) = engines.scanner.as_mut() {
                det.sweep(security_max_age);
            }
            if let Some(det) = engines.fraud.as_mut() {
                det.sweep(security_max_age);
            }
            if let Some(det) = engines.reg_flood.as_mut() {
                det.sweep(security_max_age);
            }

            // --keylog-watch: poll for new keys in the keylog file
            #[cfg(feature = "tls")]
            if cli.keylog_watch
                && let Some(ref mut decryptor) = tls_decryptor
                && let Err(e) = decryptor.poll_keylog_file()
            {
                tracing::debug!("Keylog poll error: {e}");
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
                export_mode,
            ) {
                Ok(mut w) => {
                    // Write DSB with keylog content if mode requires it
                    if let Some(ref keylog_path) = cli.keylog
                        && let Err(e) = w.maybe_write_keylog_dsb(std::path::Path::new(keylog_path))
                    {
                        tracing::warn!("Failed to write DSB: {e}");
                    }
                    writer = Some(w);
                }
                Err(e) => {
                    tracing::error!("Failed to open output file: {e}");
                    std::process::exit(1);
                }
            }
        }

        // Write to output pcap if configured
        if let Some(ref mut w) = writer
            && let Err(e) = w.write(&packet)
        {
            tracing::error!("Failed to write packet: {e}");
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
                        unwrapped.payload = hep.payload.into();
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

            // Port range filtering only applies to SIP detection — RTP uses
            // dynamic ports negotiated via SDP and must not be filtered here.
            // The filter is applied inside process_parsed_packet for SIP only.

            // Attempt TLS decryption for TCP payloads when --keylog is active
            #[cfg(feature = "tls")]
            let tls_decrypted = try_tls_decrypt(pp, &mut tls_decryptor);

            #[cfg(not(feature = "tls"))]
            let tls_decrypted: Option<ParsedPacket> = None;

            // If TLS decryption yielded a SIP message, process the decrypted packet
            let is_tls = tls_decrypted.is_some();
            let effective_pp = tls_decrypted.as_ref().unwrap_or(pp);

            // Acquire write locks once per packet. The locks are uncontested
            // in the no-API case; with --api, the API thread briefly waits
            // for in-flight per-packet processing to finish.
            {
                let mut ds_guard = dialog_store.write();
                let mut ss_guard = stream_store.write();
                let mut proc_state = ProcessingState {
                    dialog_store: &mut ds_guard,
                    stream_store: &mut ss_guard,
                    rtp_heuristic: &mut rtp_heuristic,
                    event_exec: &mut event_exec,
                };
                process_parsed_packet(
                    effective_pp,
                    &batch_ctx,
                    &mut proc_state,
                    &mut engines,
                    &mut counters,
                    is_tls,
                );
            }

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
                tracing::debug!("HEP send failed: {e}");
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
            tracing::info!("Autostop: duration limit reached ({autostop_dur:?})");
            break;
        }

        // Check --autostop filesize
        if let Some(max_bytes) = autostop_filesize_bytes
            && let Some(ref w) = writer
            && w.bytes_written() >= max_bytes
        {
            tracing::info!(
                "Autostop: filesize limit reached ({} MB)",
                autostop_filesize_mb.unwrap_or(0)
            );
            break;
        }
    }

    // Flush the output writer explicitly: BufWriter's Drop discards
    // flush errors, so without this an ENOSPC at end of capture would
    // truncate the file silently with exit code 0.
    if let Some(ref mut w) = writer
        && let Err(e) = w.finish()
    {
        tracing::error!("Output file may be incomplete: {e}");
    }

    // 19. Shut down scanner-kill worker (D16)
    if let Some(ref mut kill_handle) = engines.kill_handle {
        kill_handle.shutdown();
    }

    // 20. Wait for the capture thread to finish
    //     Drop rx first so the capture thread sees a disconnected channel
    drop(rx);
    match handle.thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("Capture thread error: {e}"),
        Err(_) => tracing::error!("Capture thread panicked"),
    }

    // 21. Post-capture output
    {
        let ds_guard = dialog_store.read();
        let ss_guard = stream_store.read();
        generate_reports(&cli, &ds_guard, &ss_guard);
    }

    // 21a. --wireshark: print Wireshark display filter for all tracked dialogs
    if cli.wireshark {
        let ds_guard = dialog_store.read();
        let call_ids: Vec<String> = ds_guard.iter().map(|d| d.call_id.clone()).collect();
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
            let ds_guard = dialog_store.read();
            let call_ids: Vec<String> = ds_guard.iter().map(|d| d.call_id.clone()).collect();
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
        let stream_count = stream_store.read().len();
        tracing::info!(
            "sipnab: {total_count} packets captured, {} SIP messages, {} RTP packets across {stream_count} streams",
            counters.sip_count,
            counters.rtp_count,
        );

        // Helpful guidance when no SIP signalling was found. If RTP was
        // parsed, the capture was readable — just media-only — so soften
        // the message rather than implying a parse failure.
        if counters.sip_count == 0 {
            if counters.rtp_count > 0 {
                eprintln!(
                    "No SIP signalling found, but {} RTP packets across {stream_count} stream(s) were parsed. Use --report to see stream details.",
                    counters.rtp_count
                );
            } else {
                eprintln!(
                    "No SIP traffic found. Check that the capture contains SIP packets (typically UDP port 5060-5061)."
                );
                eprintln!(
                    "Tip: Use 'sipnab -N -I file.pcap --hexdump' to inspect raw packet content."
                );
            }
        }
    }

    // If the API or MCP server is running, keep the process alive so clients
    // can query the captured data. Poll the shutdown flag so SIGINT/SIGTERM
    // exits cleanly instead of blocking on a thread that never returns.
    #[cfg(feature = "api")]
    let api_active = _api_thread.is_some();
    #[cfg(not(feature = "api"))]
    let api_active = false;

    #[cfg(feature = "mcp")]
    let mcp_active = _mcp_thread.is_some();
    #[cfg(not(feature = "mcp"))]
    let mcp_active = false;

    if api_active || mcp_active {
        if api_active {
            tracing::info!("API server active — press Ctrl-C to stop");
        }
        if mcp_active {
            tracing::info!("MCP server active — press Ctrl-C to stop");
        }
        while !signals::shutdown_requested() {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        #[cfg(feature = "api")]
        drop(_api_thread);
        #[cfg(feature = "mcp")]
        drop(_mcp_thread);
    }
}

// ── Packet processing ─────────────────────────────────────────────────

/// Process a single parsed packet through SIP/RTP detection, matching,
/// dialog tracking, and output dispatch.
///
/// `tls_decrypted` should be `true` when the payload was decrypted from a
/// TLS record, so the transport is reported as "TLS" rather than "TCP".
fn process_parsed_packet(
    pp: &ParsedPacket,
    ctx: &BatchContext<'_>,
    state: &mut ProcessingState<'_>,
    engines: &mut DetectionEngines,
    counters: &mut PacketCounters,
    tls_decrypted: bool,
) {
    let matcher = ctx.matcher;
    let filter_expr = ctx.filter_expr;
    let output_opts = ctx.output_opts;
    let cli = ctx.cli;
    let no_rtp = ctx.no_rtp;
    let after_count = ctx.after_count;
    let portrange = ctx.portrange;
    let dialog_store = &mut *state.dialog_store;
    let stream_store = &mut *state.stream_store;
    let rtp_heuristic = &mut *state.rtp_heuristic;
    let event_exec = &mut *state.event_exec;
    let scanner_detector = &mut engines.scanner;
    let fraud_detector = &mut engines.fraud;
    let digest_detector = &mut engines.digest;
    let reg_flood_detector = &mut engines.reg_flood;
    let alert_engine = &mut engines.alerts;
    let scanner_kill_handle = &engines.kill_handle;
    let kill_response_code = engines.kill_response_code;
    let sip_count = &mut counters.sip_count;
    let rtp_count = &mut counters.rtp_count;
    let prev_timestamp = &mut counters.prev_timestamp;
    let trailing_remaining = &mut counters.trailing_remaining;
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
    let ws_payload = sipnab::pipeline::try_websocket_unwrap(pp);
    let was_ws = ws_payload.is_some();
    let effective_payload: bytes::Bytes = match ws_payload {
        Some(v) => v.into(),
        None => pp.payload.clone(),
    };
    let effective_payload = &effective_payload;

    // Try SIP detection first — only on packets matching the SIP port range.
    // RTP uses dynamic ports negotiated via SDP and is detected below without
    // port filtering.
    if sipnab::pipeline::port_in_range(pp.src_port, pp.dst_port, portrange)
        && sip::is_sip_message(effective_payload)
    {
        let effective_transport = match pp.transport {
            TransportProto::Tcp if was_ws => TransportProto::Ws,
            TransportProto::Tcp if tls_decrypted => TransportProto::Tls,
            other => other,
        };

        match sip::parser::parse_sip_bytes(
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
                        .map(|d| d.state().to_string());

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
                        let new_state = dialog.state().to_string();
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
                                stream_store
                                    .link_to_dialog_with_sdp(ip, media.port, call_id, media);
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
                    alert_engine.write().fire(
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
                    alert_engine.write().fire(
                        "fraud",
                        alert.src_ip,
                        &format!("{:?}: {}", alert.alert_type, alert.detail),
                    );
                }

                // Security detection: digest leak
                if let Some(det) = digest_detector {
                    let alerts = det.check(&sip_msg);
                    for alert in &alerts {
                        alert_engine.write().fire(
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
                    alert_engine.write().fire(
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
                            tracing::info!(
                                "STIR/SHAKEN: attest={:?} orig={} dest={} verified={:?}",
                                info.attestation,
                                info.orig_tn.as_deref().unwrap_or("-"),
                                info.dest_tn.as_deref().unwrap_or("-"),
                                info.verified,
                            );
                        }
                        Err(e) => {
                            tracing::debug!("STIR/SHAKEN parse error: {e}");
                        }
                    }
                }

                // I5: --calls-only: skip non-INVITE dialogs from output
                let calls_only_pass = if cli.calls_only {
                    if let Some(call_id) = sip_msg.call_id()
                        && let Some(dialog) = dialog_store.get(call_id)
                    {
                        dialog.method == crate::sip::SipMethod::Invite
                    } else {
                        // No dialog tracked — only show if it's an INVITE request
                        sip_msg.method.as_ref() == Some(&crate::sip::SipMethod::Invite)
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
                tracing::debug!("SIP parse error: {e}");
            }
        }
        return;
    }

    // RTP/RTCP detection (only for UDP, unless disabled)
    if no_rtp || pp.transport != TransportProto::Udp {
        return;
    }

    // RTCP detection: odd port, version=2, PT in 200-204 range
    if sipnab::pipeline::is_rtcp_packet(&pp.payload, pp.dst_port) {
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
                tracing::info!(
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
            decrypted_pp.payload = plaintext.into();
            return Some(decrypted_pp);
        }
    }

    None
}

// ── SIP output dispatch ──────────────────────────────────────────────

/// Dispatch a matched SIP message to the configured output backend.
fn dispatch_sip_output(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
) {
    // Phase 8.1 — MCP mode owns stdout; no per-packet text/JSON output.
    #[cfg(feature = "mcp")]
    if cli.mcp {
        return;
    }
    // --no-cli-print suppresses every per-message dump (text/JSON/fail2ban/raw)
    // so post-capture reports (--call-report, --report) aren't drowned out.
    if cli.no_cli_print {
        return;
    }
    if cli.json || cli.json_pretty {
        let json = output::json::message_to_json(msg);
        print!("{json}");
    } else if cli.fail2ban {
        // Fail2ban output for scanner-like messages
        if msg.is_request {
            let ua = msg.user_agent().unwrap_or("unknown");
            let method = msg.method.as_ref().map(|m| m.as_str()).unwrap_or("UNKNOWN");
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
            let mut diagnosis = sipnab::rtp::diagnosis::diagnose_media(&dialog_streams, None);
            sipnab::rtp::diagnosis::diagnose_asymmetry(
                &mut diagnosis,
                Some(dialog),
                &dialog_streams,
                &sipnab::rtp::diagnosis::AsymmetryThresholds::default(),
            );
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
            tracing::warn!("Call-ID '{}' not found in tracked dialogs", call_id);
        }
    }
}

// ── Filter expression building ──────────────────────────────────────

/// Build a `FilterExpr` from CLI `--filter` flag, diagnostic aliases, or config fallback.
fn build_filter_expr(cli: &Cli, config: &Config) -> Option<FilterExpr> {
    // Explicit --filter takes precedence. Try alias expansion first
    // (so `--filter codec-asym` works the same as MCP find_problems'
    // kinds shorthand); fall back to raw DSL parsing.
    if let Some(ref expr) = cli.filter {
        let resolved = sipnab::sip::dsl::expand_alias(expr).unwrap_or(expr.as_str());
        match FilterExpr::parse(resolved) {
            Ok(f) => return Some(f),
            Err(e) => {
                tracing::error!("Invalid --filter expression: {e}");
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

    if !parts.is_empty() {
        let combined = parts.join(" OR ");
        return match FilterExpr::parse(&combined) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::error!("Internal error building diagnostic filter: {e}");
                std::process::exit(2);
            }
        };
    }

    // Fall back to config file expression
    if let Some(ref expr) = config.filter.expression {
        match FilterExpr::parse(expr) {
            Ok(f) => return Some(f),
            Err(e) => {
                tracing::error!("Invalid config filter expression: {e}");
                std::process::exit(2);
            }
        }
    }

    None
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
                tracing::error!("Failed to read BPF filter file '{}': {e}", bpf_file);
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
                tracing::error!("Invalid --duration: {e}");
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
            tracing::error!("Invalid --api address: {e}");
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
                    tracing::error!("Failed to create tokio runtime for API server: {e}");
                    return;
                }
            };

            if let Err(e) = rt.block_on(api::run_server(bind_addr, state, server_config)) {
                tracing::error!("API server error: {e}");
            }
        });
    match handle {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::error!("Failed to spawn API server thread: {e}");
            None
        }
    }
}

// `mirror_to_shared_stores` was removed in Phase 8.0a — batch mode now writes
// to a single Arc<RwLock<...>> store that the API server reads from directly,
// eliminating the second parse pass per packet.

/// Spawn the MCP server on a dedicated thread with its own current-thread
/// tokio runtime. Mirrors the `start_api_server` pattern. The server holds
/// references to the same Arc<RwLock<...>> stores the capture loop writes to.
#[cfg(feature = "mcp")]
fn start_mcp_server(
    cli: &Cli,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    alerts: Arc<RwLock<AlertEngine>>,
) -> Option<std::thread::JoinHandle<()>> {
    let transport = cli.mcp_transport.as_str();
    match transport {
        "stdio" => {
            let server =
                sipnab::mcp::SipnabMcp::new(dialog_store, stream_store).with_alert_engine(alerts);
            let handle = std::thread::Builder::new()
                .name("mcp-stdio".into())
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(rt) => rt,
                        Err(e) => {
                            tracing::error!("Failed to build tokio runtime for MCP: {e}");
                            return;
                        }
                    };
                    runtime.block_on(async move {
                        if let Err(e) = sipnab::mcp::transport::serve_stdio(server).await {
                            tracing::error!("MCP stdio server error: {e}");
                        }
                    });
                });
            handle.ok()
        }
        #[cfg(feature = "mcp-http")]
        "http" => start_mcp_http_server(cli, dialog_store, stream_store, alerts),
        #[cfg(not(feature = "mcp-http"))]
        "http" => {
            tracing::error!(
                "--mcp-transport http requires the mcp-http feature; rebuild with \
                 --features mcp-http (or full)."
            );
            None
        }
        other => {
            tracing::error!("unknown --mcp-transport '{other}', expected stdio or http");
            None
        }
    }
}

/// Resolve the MCP bind address (default 127.0.0.1:8731) plus the bearer token
/// from --mcp-token / --mcp-token-file / SIPNAB_MCP_TOKEN env, then start a
/// dedicated thread with a current-thread tokio runtime running the HTTP
/// transport.
#[cfg(feature = "mcp-http")]
fn start_mcp_http_server(
    cli: &Cli,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    alerts: Arc<RwLock<AlertEngine>>,
) -> Option<std::thread::JoinHandle<()>> {
    let bind_str = cli.mcp_bind.as_deref().unwrap_or("127.0.0.1:8731");
    let bind = match output::api::parse_bind_addr(bind_str) {
        Ok(addr) => addr,
        Err(e) => {
            tracing::error!("--mcp-bind: {e}");
            return None;
        }
    };

    // Resolve token: --mcp-token > --mcp-token-file > SIPNAB_MCP_TOKEN.
    let token: Option<String> = if let Some(t) = cli.mcp_token.as_ref() {
        Some(t.trim().to_string())
    } else if let Some(path) = cli.mcp_token_file.as_ref() {
        match std::fs::read_to_string(path) {
            Ok(s) => Some(s.trim().to_string()),
            Err(e) => {
                tracing::error!("--mcp-token-file '{path}': {e}");
                return None;
            }
        }
    } else {
        None
    }
    .filter(|s| !s.is_empty());

    let extra_allowed_hosts = cli.mcp_allowed_host.clone();

    let server = sipnab::mcp::SipnabMcp::new(dialog_store, stream_store).with_alert_engine(alerts);
    let handle = std::thread::Builder::new()
        .name("mcp-http".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!("Failed to build tokio runtime for MCP HTTP: {e}");
                    return;
                }
            };
            runtime.block_on(async move {
                if let Err(e) =
                    sipnab::mcp::transport::serve_http(server, bind, token, extra_allowed_hosts)
                        .await
                {
                    tracing::error!("MCP HTTP server error: {e}");
                }
            });
        });
    handle.ok()
}

// ── Unit tests for the binary's pure helpers ────────────────────────────
//
// These cover the stand-alone logic in `main.rs` that needs no live capture
// device: argument parsers, filter/capture-config builders, post-capture
// report generation, per-message output dispatch, and a synthetic drive of
// `process_parsed_packet`. The live-capture / TUI arms stay integration-only.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Baseline non-interactive CLI; mutate the pub fields per test.
    fn base_cli() -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.no_tui = true;
        cli
    }

    /// Raw bytes of a minimal but well-formed SIP INVITE for `call_id`.
    /// (`sipnab::test_utils` is `#[cfg(test)]`-gated in the lib and so is not
    /// visible from the binary's own test build — inline the construction.)
    fn invite_bytes(call_id: &str) -> Vec<u8> {
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Max-Forwards: 70".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
            "Content-Length: 0".to_string(),
        ];
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        msg.into_bytes()
    }

    fn parsed_sip_packet(payload: Vec<u8>, src_port: u16, dst_port: u16) -> ParsedPacket {
        ParsedPacket {
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port,
            dst_port,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
        }
    }

    // ── parse_portrange ────────────────────────────────────────────────

    #[test]
    fn parse_portrange_valid_and_trimmed() {
        assert_eq!(parse_portrange("5060-5061").unwrap(), (5060, 5061));
        // surrounding whitespace is trimmed on each side
        assert_eq!(parse_portrange(" 100 - 200 ").unwrap(), (100, 200));
        // single-port range (start == end) is allowed
        assert_eq!(parse_portrange("5060-5060").unwrap(), (5060, 5060));
    }

    #[test]
    fn parse_portrange_errors() {
        // wrong number of '-' separated parts
        assert!(parse_portrange("5060").is_err());
        assert!(parse_portrange("5060-5061-5062").is_err());
        // non-numeric start / end
        assert!(parse_portrange("abc-5061").is_err());
        assert!(parse_portrange("5060-xyz").is_err());
        // out of u16 range
        assert!(parse_portrange("0-70000").is_err());
        // start > end
        let err = parse_portrange("6000-5000").unwrap_err();
        assert!(err.contains("start"), "got: {err}");
    }

    // ── parse_autostop ─────────────────────────────────────────────────

    #[test]
    fn parse_autostop_duration_and_filesize() {
        let (dur, size) = parse_autostop("duration:30").unwrap();
        assert_eq!(dur, Some(std::time::Duration::from_secs(30)));
        assert_eq!(size, None);

        let (dur, size) = parse_autostop("filesize:100").unwrap();
        assert_eq!(dur, None);
        assert_eq!(size, Some(100));
    }

    #[test]
    fn parse_autostop_errors() {
        assert!(parse_autostop("duration").is_err()); // missing ':'
        assert!(parse_autostop("duration:notanumber").is_err());
        assert!(parse_autostop("unknown:10").is_err()); // unknown key
    }

    // ── build_filter_expr ──────────────────────────────────────────────

    #[test]
    fn build_filter_expr_explicit_flag_wins() {
        let mut cli = base_cli();
        cli.filter = Some("retransmits > 0".to_string());
        let config = Config::default();
        assert!(build_filter_expr(&cli, &config).is_some());
    }

    #[test]
    fn build_filter_expr_diagnostic_aliases() {
        let config = Config::default();
        // Each diagnostic flag on its own produces a filter.
        let flags: [fn(&mut Cli); 5] = [
            |c| c.problems = true,
            |c| c.slow_setup = true,
            |c| c.short_calls = true,
            |c| c.one_way = true,
            |c| c.nat_issues = true,
        ];
        for set in flags {
            let mut cli = base_cli();
            set(&mut cli);
            assert!(build_filter_expr(&cli, &config).is_some());
        }
        // Multiple flags combine with OR.
        let mut cli = base_cli();
        cli.problems = true;
        cli.one_way = true;
        assert!(build_filter_expr(&cli, &config).is_some());
    }

    #[test]
    fn build_filter_expr_config_fallback_and_none() {
        // No flags, no config -> None.
        assert!(build_filter_expr(&base_cli(), &Config::default()).is_none());

        // Config fallback expression is used when no CLI flag is set.
        let mut config = Config::default();
        config.filter.expression = Some("retransmits > 0".to_string());
        assert!(build_filter_expr(&base_cli(), &config).is_some());
    }

    // ── build_capture_config ───────────────────────────────────────────

    #[test]
    fn build_capture_config_defaults() {
        let cc = build_capture_config(&base_cli(), &Config::default());
        assert_eq!(cc.snaplen, 65535);
        assert_eq!(cc.buffer_mb, 2);
        assert_eq!(cc.bpf_filter, None);
        assert_eq!(cc.count, None);
        assert_eq!(cc.duration, None);
        assert!(!cc.replay);
    }

    #[test]
    fn build_capture_config_cli_overrides() {
        let mut cli = base_cli();
        cli.snaplen = Some(1500);
        cli.buffer = Some(8);
        cli.count = Some(42);
        cli.replay = true;
        cli.bpf_filter = vec!["udp".to_string(), "port".to_string(), "5060".to_string()];
        let cc = build_capture_config(&cli, &Config::default());
        assert_eq!(cc.snaplen, 1500);
        assert_eq!(cc.buffer_mb, 8);
        assert_eq!(cc.count, Some(42));
        assert!(cc.replay);
        assert_eq!(cc.bpf_filter.as_deref(), Some("udp port 5060"));
    }

    #[test]
    fn build_capture_config_bpf_file_takes_precedence() {
        let dir = std::env::temp_dir();
        let path = dir.join("sipnab_test_bpf_filter.txt");
        std::fs::write(&path, "  udp and port 5060\n").unwrap();
        let mut cli = base_cli();
        cli.bpf_file = Some(path.to_string_lossy().into_owned());
        // positional filter present but --bpf-file wins
        cli.bpf_filter = vec!["tcp".to_string()];
        let cc = build_capture_config(&cli, &Config::default());
        assert_eq!(cc.bpf_filter.as_deref(), Some("udp and port 5060"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn build_capture_config_config_fallback() {
        let mut config = Config::default();
        config.capture.snaplen = Some(256);
        config.capture.buffer = Some(16);
        // CLI leaves snaplen/buffer unset -> config values used.
        let cc = build_capture_config(&base_cli(), &config);
        assert_eq!(cc.snaplen, 256);
        assert_eq!(cc.buffer_mb, 16);
    }

    // ── dispatch_sip_output ────────────────────────────────────────────

    #[test]
    fn dispatch_sip_output_all_modes() {
        let data = bytes::Bytes::from(invite_bytes("disp-1@example.com"));
        let msg = sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("invite should parse");
        let opts = OutputOptions::default();

        // Default pretty print.
        dispatch_sip_output(&msg, &opts, &base_cli(), None);

        // JSON.
        let mut cli = base_cli();
        cli.json = true;
        dispatch_sip_output(&msg, &opts, &cli, None);

        // fail2ban (request path).
        let mut cli = base_cli();
        cli.fail2ban = true;
        dispatch_sip_output(&msg, &opts, &cli, None);

        // raw text dump.
        let mut cli = base_cli();
        cli.text_dump = true;
        dispatch_sip_output(&msg, &opts, &cli, None);

        // suppressed entirely.
        let mut cli = base_cli();
        cli.no_cli_print = true;
        dispatch_sip_output(&msg, &opts, &cli, None);

        // line-buffer flush branch.
        let mut cli = base_cli();
        cli.line_buffer = true;
        dispatch_sip_output(&msg, &opts, &cli, Some(chrono::Utc::now()));
    }

    // ── generate_reports ───────────────────────────────────────────────

    #[test]
    fn generate_reports_summary_and_call_report() {
        let mut dialog_store = DialogStore::new(100, false);
        let stream_store = StreamStore::new(100);

        // Empty --report summary path.
        let mut cli = base_cli();
        cli.report = true;
        generate_reports(&cli, &dialog_store, &stream_store);

        // --call-report for an unknown Call-ID hits the "not found" warn arm.
        let mut cli = base_cli();
        cli.call_report = Some("does-not-exist".to_string());
        generate_reports(&cli, &dialog_store, &stream_store);

        // Insert a dialog, then --call-report finds it across all formats.
        let call_id = "report-1@example.com";
        let data = bytes::Bytes::from(invite_bytes(call_id));
        let msg = sip::parser::parse_sip_bytes(
            &data,
            chrono::Utc::now(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap();
        dialog_store.process_message(msg);
        assert!(dialog_store.get(call_id).is_some());

        let formats: [fn(&mut Cli); 3] = [
            |_c| {},
            |c| c.json = true,
            |c| c.markdown = true,
        ];
        for setup in formats {
            let mut cli = base_cli();
            cli.call_report = Some(call_id.to_string());
            setup(&mut cli);
            generate_reports(&cli, &dialog_store, &stream_store);
        }
    }

    // ── process_parsed_packet ──────────────────────────────────────────

    /// Build the engine/state/context scaffolding and drive a single packet,
    /// returning the resulting (sip_count, rtp_count).
    fn drive_packet(cli: &Cli, pp: &ParsedPacket, portrange: (u16, u16)) -> (u64, u64) {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();

        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(None, None, 0, 0.0);

        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None))),
            kill_handle: None,
            kill_response_code: 0,
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
        };

        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange,
        };
        let mut state = ProcessingState {
            dialog_store: &mut dialog_store,
            stream_store: &mut stream_store,
            rtp_heuristic: &mut rtp_heuristic,
            event_exec: &mut event_exec,
        };

        process_parsed_packet(pp, &ctx, &mut state, &mut engines, &mut counters, false);
        (counters.sip_count, counters.rtp_count)
    }

    #[test]
    fn process_parsed_packet_counts_sip() {
        let mut cli = base_cli();
        cli.no_cli_print = true; // keep test output quiet
        let pp = parsed_sip_packet(invite_bytes("ppp-1@example.com"), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 1, "one SIP message should be counted");
    }

    #[test]
    fn process_parsed_packet_ignores_non_sip_and_out_of_range() {
        let mut cli = base_cli();
        cli.no_cli_print = true;

        // Garbage payload on the SIP port: not a SIP message -> no count.
        let pp = parsed_sip_packet(b"\x00\x01\x02not-sip-at-all".to_vec(), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 0);

        // A valid SIP message but on a port outside the SIP range -> skipped.
        let pp = parsed_sip_packet(invite_bytes("oor-1@example.com"), 40000, 40001);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 0);
    }
}
