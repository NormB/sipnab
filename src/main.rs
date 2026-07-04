//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! Entry point: parses CLI, sets up logging and signal handlers, loads config,
//! and dispatches to the appropriate capture mode. Phase 2 wires all modules
//! together: capture → SIP parsing → dialog tracking → RTP tracking →
//! filtering → output.

// Same production-path panic policy as the library (tests exempt via
// clippy.toml).
#![warn(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

// Faster general-purpose allocator: sipnab's offline ingestion does one heap
// allocation per captured packet, so the allocator is on the hot path.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use sipnab::app::batch::{BatchProcessing, CapturePolicy};
use sipnab::capture::{self, CaptureConfig, CaptureSource, PcapExportMode, PcapWriter};
use sipnab::cli::{self, Cli};
use sipnab::config::Config;
use sipnab::output::{ColorMode, EventExecEngine, OutputOptions};
use sipnab::privilege;
use sipnab::rtp::{self, stream_store::StreamStore};
use sipnab::signals;
use sipnab::sip::{dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

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

    // --setup-caps: grant this binary the capabilities needed for live capture
    // and exit. Handled before any config/capture setup so it works right after
    // a fresh `cargo install` with no config present.
    if cli.setup_caps {
        match privilege::setup_capabilities() {
            Ok(()) => return,
            Err(e) => {
                tracing::error!("{e}");
                std::process::exit(1);
            }
        }
    }

    // 2b. --strip-secrets: write a DSB-free copy of the input pcapng and exit.
    // The input is never modified; the output is written atomically.
    if let Some(ref out) = cli.strip_secrets {
        let Some(ref input) = cli.input else {
            tracing::error!("--strip-secrets requires an input file (-I <file>)");
            std::process::exit(1);
        };
        match sipnab::capture::pcapng_meta::strip_secrets(
            std::path::Path::new(input),
            std::path::Path::new(out),
        ) {
            Ok(n) => {
                tracing::info!("Stripped {n} decryption secret(s): {input} -> {out}");
                return;
            }
            Err(e) => {
                tracing::error!("--strip-secrets failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // 3. Install signal handlers
    signals::install_handlers();

    // 4. Validate CLI argument combinations
    if let Err(msg) = cli.validate() {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }

    // 4a. Warn about unimplemented flags that were set
    cli.warn_unimplemented_flags();

    // 4b. --mint-token: mint a signed bearer token and exit. Does NOT start
    // capture or any server. Gated to builds with auth (api or mcp).
    #[cfg(any(feature = "api", feature = "mcp"))]
    if cli.mint_token {
        match mint_token_and_exit(&cli) {
            Ok(token) => {
                println!("{token}");
                std::process::exit(0);
            }
            Err(msg) => {
                tracing::error!("{msg}");
                std::process::exit(2);
            }
        }
    }
    #[cfg(not(any(feature = "api", feature = "mcp")))]
    if cli.mint_token {
        tracing::error!("--mint-token requires the 'api' or 'mcp' feature (not compiled in)");
        std::process::exit(2);
    }

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

    // 13b. Multi-core offline reconstruction (`--cores N`, offline file). Read the
    //      pcap directly and shard packets across N worker threads, fusing
    //      read+peek+shard into one stage — no capture reader thread, no semaphore
    //      channel (that hand-off capped --cores scaling at ~2 workers). Bypasses
    //      the single-threaded run_batch_mode path entirely for this case.
    if cli.cores > 1
        && cli.input.is_some()
        && !cli.multi_device
        && let Some(input) = cli.input.as_ref()
    {
        let no_rtp = cli.no_rtp || loaded.config.capture.no_rtp.unwrap_or(false);
        let pcfg = sipnab::parallel::ParallelConfig {
            cores: cli.cores,
            max_streams: cli.max_streams as usize,
            max_dialogs: cli.limit as usize,
            rotate: cli.rotate_enabled(),
            max_reassembly: cli.max_reassembly as usize,
            portrange,
            no_dialog: cli.no_dialog,
            no_rtp,
        };
        match sipnab::parallel::run_offline_parallel_file(
            std::path::Path::new(input),
            &capture_config,
            pcfg,
        ) {
            Ok(r) => {
                sipnab::app::batch::generate_reports(&cli, &r.dialog_store, &r.stream_store);
                if !cli.quiet {
                    tracing::info!(
                        "sipnab: {} packets, {} SIP messages, {} RTP packets across {} streams ({} cores)",
                        r.total_count,
                        r.sip_count,
                        r.rtp_count,
                        r.stream_store.len(),
                        cli.cores,
                    );
                }
            }
            Err(e) => {
                tracing::error!("multi-core reconstruction failed: {e:#}");
                std::process::exit(1);
            }
        }
        return;
    }

    // 14. Create the packet channel: a capped, auto-shrinking queue. Occupancy
    //     grows under load up to the cap and the (unbounded) storage frees its
    //     segments when idle. Capacity is derived from the memory budget.
    let (tx, rx) = capture::channel::packet_channel(capture_config.channel_capacity());

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
                    "Permission denied on '{}'. Grant capture capabilities once \
                     (Linux), then re-run without sudo:\n  \
                     sipnab --setup-caps\n  \
                     # or run this invocation under sudo:\n  \
                     sudo sipnab\n  \
                     # equivalent manual step:\n  \
                     sudo setcap cap_net_raw,cap_net_admin+ep $(which sipnab)",
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

    // 16f. --dtls-keylog: the DTLS-SRTP extractor is constructed later (alongside
    // the SRTP context); here we only enforce the feature gate.
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
        sipnab::app::batch::run(
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
/// Build the TUI name-resolution setup from CLI flags and config:
/// construct the resolver (with a reverse-DNS worker when requested), load the
/// system hosts file plus any operator mapping files, and pick the initial mode.
fn build_name_setup(cli: &Cli, config: &Config) -> sipnab::tui::NameSetup {
    let cfg = &config.names;
    let (resolver, mode) = sipnab::app::build_resolver(cli, config);

    // Default persistence file for the in-TUI `N` dialog; preload it.
    let save_path = default_names_path();
    if let Some(p) = &save_path {
        let _ = resolver.load_manual_file(p);
    }
    // Opt-in: also persist `N`-dialog edits into the user's sipnabrc.
    let config_path = if cfg.persist_to_config.unwrap_or(false) {
        sipnab::config::default_user_config_path()
    } else {
        None
    };

    sipnab::tui::NameSetup {
        resolver,
        mode,
        save_path,
        config_path,
    }
}

/// Default file where in-TUI manual name mappings persist:
/// `$XDG_CONFIG_HOME/sipnab/hosts`, falling back to `~/.config/sipnab/hosts`.
#[cfg(feature = "tui")]
fn default_names_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("sipnab").join("hosts"))
}

#[cfg(feature = "tui")]
fn run_tui_mode(
    cli: Cli,
    config: Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: capture::channel::PacketRx,
    policy: CapturePolicy,
    #[cfg(feature = "api")] metrics_bind_addr: Option<std::net::SocketAddr>,
) {
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);

    let dialog_store = Arc::new(RwLock::new(DialogStore::new(
        cli.limit as usize,
        cli.rotate_enabled(),
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
            Some(rx.meter()),
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

            // SRTP/DTLS-SRTP media-decryption state for the live pipeline.
            #[cfg(feature = "tls")]
            let mut srtp_context: Option<sipnab::rtp::srtp::SrtpContext> = {
                let backend = sipnab::crypto::default_backend();
                match cli_clone.srtp_keys.as_deref() {
                    Some(keyfile) => sipnab::rtp::srtp::SrtpContext::from_key_file(
                        std::path::Path::new(keyfile),
                        backend,
                    )
                    .map_err(|e| tracing::error!("Failed to load --srtp-keys {keyfile}: {e}"))
                    .ok(),
                    // No key file, but SDES keys may still arrive via SDP.
                    None => Some(sipnab::rtp::srtp::SrtpContext::new(Vec::new(), backend)),
                }
            };
            #[cfg(feature = "tls")]
            let mut dtls_extractor: Option<sipnab::capture::dtls::DtlsSrtpExtractor> =
                cli_clone.dtls_keylog.as_deref().and_then(|keylog| {
                    sipnab::capture::dtls::DtlsSrtpExtractor::from_keylog_file(
                        std::path::Path::new(keylog),
                        sipnab::crypto::default_backend(),
                    )
                    .map_err(|e| tracing::error!("Failed to load --dtls-keylog {keylog}: {e}"))
                    .ok()
                });
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
                    // Record the capture source as the pcapng interface name
                    // (SNB-0001): the capture device for live, input for replay.
                    let capture_source = cli_clone.device.as_deref().or(cli_clone.input.as_deref());
                    match PcapWriter::with_interface(
                        &PathBuf::from(output_path),
                        packet.link_type,
                        policy.split_bytes,
                        policy.split_duration,
                        cli_clone.pcapng,
                        tui_export_mode,
                        capture_source,
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
                    #[cfg(feature = "tls")]
                    let mut media_decrypt = sipnab::pipeline::MediaDecrypt {
                        srtp: srtp_context.as_mut(),
                        dtls: dtls_extractor.as_mut(),
                    };
                    #[cfg(not(feature = "tls"))]
                    let mut media_decrypt = sipnab::pipeline::MediaDecrypt::default();
                    sipnab::pipeline::process_packet(
                        pp,
                        &ds,
                        &ss,
                        &mut rtp_heuristic,
                        &sipnab::pipeline::PipelineOptions {
                            no_dialog: cli_clone.no_dialog,
                            no_rtp,
                            // Live capture: BPF (auto-generated from
                            // --portrange) already filtered; no SIP port gate.
                            sip_portrange: None,
                        },
                        &mut media_decrypt,
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

    // Start the REST API server if --api is specified. The TUI owns stdio,
    // so MCP stdio is never selected here.
    let _servers_thread = sipnab::app::servers::start_servers(
        &cli,
        &dialog_store,
        &stream_store,
        None,
        sipnab::app::servers::Selection {
            api: true,
            mcp: false,
        },
    )
    .unwrap_or_else(|e| {
        tracing::error!("{e}");
        std::process::exit(2);
    });

    // Build resolved theme and keymap from config
    let theme = sipnab::tui::Theme::from_config(&config.theme);
    let keymap = sipnab::tui::Keymap::from_config(&config.keybindings);
    let name_setup = build_name_setup(&cli, &config);

    // From/To column default: CLI flag wins, then the [display] from_to config
    // value (warned + ignored if invalid), else the built-in Default.
    let from_to_mode = cli
        .from_to_mode
        .map(|a| sipnab::tui::FromToMode::parse(a.as_str()).unwrap_or_default())
        .or_else(|| {
            config.display.from_to.as_deref().and_then(|s| {
                let m = sipnab::tui::FromToMode::parse(s);
                if m.is_none() {
                    tracing::warn!("ignoring invalid [display] from_to = {s:?}");
                }
                m
            })
        })
        .unwrap_or_default();

    // Run TUI on the main thread
    if let Err(e) = sipnab::tui::run_tui_with_pause(
        Arc::clone(&dialog_store),
        Arc::clone(&stream_store),
        Some(paused_flag),
        theme,
        keymap,
        config.display.visible_columns.clone(),
        name_setup,
        from_to_mode,
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

    // Memory budget for the in-flight packet queue (capture→processing).
    let buffer_budget_mb = cli
        .buffer_budget
        .or(config.capture.buffer_budget_mb)
        .unwrap_or(64);

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
        buffer_budget_mb,
    }
}

// ── Auth / token helpers ───────────────────────────────────────────

/// Read one signing key from a file (contents trimmed). Logs and exits on
/// failure (a misconfigured key file is fatal).
#[cfg(any(feature = "api", feature = "mcp"))]
/// Mint a signed token from the CLI configuration and return it. Picks the
/// surface (API vs MCP) based on which signing keys are configured. Returns an
/// error message string on misconfiguration.
#[cfg(any(feature = "api", feature = "mcp"))]
fn mint_token_and_exit(cli: &Cli) -> Result<String, String> {
    // Gather the first signing key + TTL, preferring API config, then MCP.
    #[allow(unused_mut)]
    let mut first_key: Option<Vec<u8>> = None;
    #[allow(unused_mut)]
    let mut ttl: i64 = 3600;

    #[cfg(feature = "api")]
    {
        if cli.api_signing_key_file.is_some() || !cli.api_signing_key.is_empty() {
            let cfg = sipnab::app::servers::resolve_api_verifier_config(cli);
            first_key = cfg.signing_keys.into_iter().next();
            ttl = cli.api_token_ttl;
        }
    }
    #[cfg(feature = "mcp")]
    if first_key.is_none()
        && (cli.mcp_signing_key_file.is_some() || !cli.mcp_signing_key.is_empty())
    {
        let cfg = sipnab::app::servers::resolve_mcp_verifier_config(cli);
        first_key = cfg.signing_keys.into_iter().next();
        ttl = cli.mcp_token_ttl;
    }

    let key = first_key.ok_or_else(|| {
        "--mint-token requires at least one --api-signing-key/--api-signing-key-file \
         or --mcp-signing-key/--mcp-signing-key-file"
            .to_string()
    })?;

    if ttl <= 0 {
        return Err(format!("token TTL must be positive, got {ttl}"));
    }

    let now = chrono::Utc::now().timestamp();
    let exp = now.saturating_add(ttl);
    let id = cli
        .token_id
        .clone()
        .unwrap_or_else(|| format!("tok-{}", chrono::Utc::now().timestamp_micros()));

    Ok(sipnab::auth::mint(&key, &id, exp))
}

// ── Unit tests for the binary's pure helpers ────────────────────────────
//
// These cover the stand-alone logic in `main.rs` that needs no live capture
// device: argument parsers, filter/capture-config builders, post-capture
// and the filter/capture-config builders. The batch runner's tests live in
// `sipnab::app::batch`; the live-capture / TUI arms stay integration-only.
#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline non-interactive CLI; mutate the pub fields per test.
    fn base_cli() -> Cli {
        let mut cli = Cli::parse_from_args(["sipnab"]);
        cli.no_tui = true;
        cli
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
}
