//! Bootstrap planning (WS2c): the testable seam between argument parsing
//! and running.
//!
//! [`plan`] is a pure `Cli` + `Config` → [`RunPlan`] mapping — every
//! decision main() used to make inline (capture source, portrange, BPF
//! auto-generation, filters, output options, run mode) becomes a value that
//! unit tests can assert on, with configuration errors returned as
//! [`PlanError`] instead of process exits buried in helpers. [`launch`]
//! then performs the side-effectful part: channel creation, capture start,
//! readiness hand-shake, chroot, and privilege drop.

use std::path::PathBuf;

use crate::capture::{self, CaptureConfig, CaptureSource};
use crate::cli::{self, Cli};
use crate::config::{Config, LoadedConfig};
use crate::output::{ColorMode, EventExecEngine, OutputOptions};
use crate::privilege;
use crate::sip::{dsl::FilterExpr, matcher::SipMatcher};

use super::batch::CapturePolicy;

/// A fatal configuration problem found while planning: the message main()
/// should log and the process exit code (2 for argument errors, 1 for
/// environment errors) — the same codes the inline checks used.
#[derive(Debug)]
pub struct PlanError {
    /// Process exit code.
    pub exit_code: i32,
    /// Human-readable error, logged by the caller.
    pub message: String,
}

impl PlanError {
    fn arg(message: String) -> Self {
        Self {
            exit_code: 2,
            message,
        }
    }

    /// Log the message and terminate with the planned exit code.
    pub fn exit(self) -> ! {
        tracing::error!("{}", self.message);
        std::process::exit(self.exit_code);
    }
}

/// Which top-level mode this invocation runs.
pub enum RunMode {
    /// Interactive TUI (the default when compiled in and stdio is free).
    Tui,
    /// Headless batch capture/replay ([`super::batch::run`]).
    Batch,
    /// Multi-core offline file reconstruction (`--cores N -I file`),
    /// bypassing the capture thread entirely.
    CoresFile,
}

/// Everything main() needs to run, decided up front from CLI + config.
pub struct RunPlan {
    /// The capture source; `None` defers to device auto-detection in
    /// [`launch`].
    pub source: Option<CaptureSource>,
    /// Capture configuration (BPF filter, counts, memory budget, ...).
    pub capture_config: CaptureConfig,
    /// SIP signaling port range.
    pub portrange: (u16, u16),
    /// Output split / autostop policy.
    pub policy: CapturePolicy,
    /// Header-level SIP matcher.
    pub matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    pub filter_expr: Option<FilterExpr>,
    /// Per-message output formatting options.
    pub output_opts: OutputOptions,
    /// `--on-*` event execution engine.
    pub event_exec: EventExecEngine,
    /// Top-level run mode (TUI vs batch vs multi-core file).
    pub mode: RunMode,
    /// Parsed `--metrics` bind address (TUI path only; batch handles its
    /// own). Always `None` in builds without the `api` + `tui` features.
    pub metrics_bind: Option<std::net::SocketAddr>,
}

/// Decide everything: capture source precedence, capture config, portrange
/// (CLI > config > default), BPF auto-generation for live captures,
/// autostop/split policy, matcher/filter/output/event-exec construction,
/// and the run mode. Pure — no capture, no exits, no privilege changes.
pub fn plan(cli: &Cli, config: &Config) -> Result<RunPlan, PlanError> {
    // Capture source precedence: -I file > -d device > config device >
    // --hep-listen > auto-detect (deferred to launch()).
    // manual_map: without the `hep` feature the --hep-listen arm cfg-shrinks
    // to a bare Some(..) that clippy wants as .map(), but the full arm uses
    // `?` (CIDR parsing), which a map closure cannot.
    #[allow(clippy::manual_map)]
    let source = if let Some(ref input) = cli.input {
        Some(CaptureSource::File {
            path: PathBuf::from(input),
        })
    } else if let Some(ref device) = cli.device {
        Some(CaptureSource::Live {
            device: device.clone(),
        })
    } else if let Some(ref device) = config.capture.device {
        Some(CaptureSource::Live {
            device: device.clone(),
        })
    } else if let Some(hep_addr) = cli.hep_listen.as_ref() {
        #[cfg(feature = "hep")]
        let allowlist = {
            let mut v: Vec<crate::capture::hep::CidrRange> = Vec::new();
            for cidr in &cli.hep_allow {
                v.push(crate::capture::hep::CidrRange::parse(cidr).map_err(|e| {
                    PlanError::arg(format!("Invalid --hep-allow CIDR '{cidr}': {e}"))
                })?);
            }
            v
        };
        Some(CaptureSource::Hep {
            bind_addr: hep_addr.clone(),
            #[cfg(feature = "hep")]
            allowlist,
            rate_limit: cli.hep_rate_limit,
        })
    } else {
        None
    };

    // Capture config from CLI + config file.
    let mut capture_config = build_capture_config(cli, config);

    // Portrange: CLI > config file > default "5060-5061".
    let portrange_str = if cli.portrange != "5060-5061" {
        &cli.portrange
    } else if let Some(ref pr) = config.capture.portrange {
        pr.as_str()
    } else {
        "5060-5061"
    };
    let portrange = parse_portrange(portrange_str)
        .map_err(|e| PlanError::arg(format!("Invalid --portrange: {e}")))?;

    // Auto-generate a BPF filter from the portrange for live captures when
    // no explicit filter was set. Critical for performance: without a BPF
    // filter, capturing on 'any' processes ALL traffic. `None` source means
    // auto-detect — which always yields a live device.
    let is_live = match source {
        Some(CaptureSource::Live { .. }) | None => true,
        Some(_) => false,
    };
    if capture_config.bpf_filter.is_none() && is_live {
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

    // --autostop condition.
    let (autostop_duration, autostop_filesize_mb) = match cli.autostop {
        Some(ref cond) => {
            parse_autostop(cond).map_err(|e| PlanError::arg(format!("Invalid --autostop: {e}")))?
        }
        None => (None, None),
    };

    // --split output rotation.
    let (split_bytes, split_duration) = match cli.split {
        Some(ref split) => {
            capture::writer::parse_split(split).map_err(|e| PlanError::arg(e.to_string()))?
        }
        None => (None, None),
    };

    // SIP matcher from CLI filter flags, with config fallbacks.
    let effective_from = cli.from.as_deref().or(config.filter.from.as_deref());
    let effective_to = cli.to.as_deref().or(config.filter.to.as_deref());
    let matcher = SipMatcher::new_with_overrides(cli, None, effective_from, effective_to)
        .map_err(|e| PlanError::arg(format!("Invalid filter pattern: {e}")))?;

    // Filter DSL expression (--filter or diagnostic aliases), falling back
    // to config.filter.expression.
    let filter_expr = build_filter_expr(cli, config);

    // Output options.
    let output_opts = OutputOptions {
        color: match cli.color.as_str() {
            "always" => ColorMode::Always,
            "never" => ColorMode::Never,
            _ => ColorMode::Auto,
        },
        delta_time: cli.delta_time || config.display.delta_time.unwrap_or(false),
        payload_limit: cli.payload_limit.or(config.display.payload_limit),
        show_empty: cli.show_empty,
    };

    // Event exec engine.
    let event_exec = EventExecEngine::new(
        cli.on_dialog_exec.clone(),
        cli.on_quality_exec.clone(),
        cli.exec_rate_limit,
        cli.quality_threshold,
    );

    // Parsed --metrics bind address (consumed by the TUI path only; batch
    // starts its own metrics server).
    #[cfg(all(feature = "api", feature = "tui"))]
    let metrics_bind = match cli.metrics.as_deref() {
        Some(addr_str) => Some(
            crate::output::prometheus_server::parse_metrics_addr(addr_str)
                .map_err(|e| PlanError::arg(format!("Invalid --metrics address: {e}")))?,
        ),
        None => None,
    };
    #[cfg(not(all(feature = "api", feature = "tui")))]
    let metrics_bind = None;

    // Run mode. The multi-core offline file path outranks the TUI/batch
    // choice; MCP forces batch (it owns stdio, the TUI must not start).
    let mode = if cli.cores > 1 && cli.input.is_some() && !cli.multi_device {
        RunMode::CoresFile
    } else {
        #[cfg(feature = "mcp")]
        let use_tui = !cli.no_tui && !cli.mcp;
        #[cfg(all(feature = "tui", not(feature = "mcp")))]
        let use_tui = !cli.no_tui;
        #[cfg(not(any(feature = "tui", feature = "mcp")))]
        let use_tui = false;
        if use_tui {
            RunMode::Tui
        } else {
            RunMode::Batch
        }
    };

    Ok(RunPlan {
        source,
        capture_config,
        portrange,
        policy: CapturePolicy {
            split_bytes,
            split_duration,
            autostop_duration,
            autostop_filesize_mb,
            portrange,
        },
        matcher,
        filter_expr,
        output_opts,
        event_exec,
        mode,
        metrics_bind,
    })
}

/// The running capture: its thread handle and the packet channel receiver.
pub struct Launched {
    /// Capture-thread handle (joined by the consuming mode at EOF).
    pub handle: capture::CaptureHandle,
    /// Receiving side of the packet channel.
    pub rx: capture::channel::PacketRx,
}

/// Perform the side-effectful launch sequence exactly as main() did:
/// resolve device auto-detection, create the packet channel, start the
/// capture thread, wait for the source-open handshake, then chroot, drop
/// privileges, and apply the remaining runtime hardening. Exits the
/// process on failure (these are unrecoverable environment errors).
pub fn launch(
    cli: &Cli,
    config: &Config,
    source: Option<CaptureSource>,
    capture_config: &CaptureConfig,
) -> Launched {
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
    let effective_chroot = cli.chroot.as_ref().or(config.privilege.chroot.as_ref());
    if let Some(ref chroot_dir) = effective_chroot
        && let Err(e) = privilege::do_chroot(std::path::Path::new(chroot_dir))
    {
        tracing::error!("Failed to chroot: {e}");
        std::process::exit(1);
    }

    // 16a. Drop privileges now that capture devices are open and chroot is applied (D15)
    let effective_user = cli.user.as_deref().or(config.privilege.user.as_deref());
    let effective_no_priv_drop = cli.no_priv_drop || config.privilege.no_priv_drop.unwrap_or(false);
    if let Err(e) = privilege::drop_privileges(effective_user, effective_no_priv_drop) {
        tracing::error!("Failed to drop privileges: {e}");
        std::process::exit(1);
    }

    // 16b. Initialize syslog if --syslog is set
    if cli.syslog {
        crate::security::alerting::init_syslog();
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

    Launched { handle, rx }
}

/// Initialize the tracing/log subscriber from `SIPNAB_LOG` and the CLI's
/// quiet/TUI flags, writing to stderr (stdout stays reserved for MCP's
/// JSON-RPC wire and per-message output).
pub fn init_logging(cli: &Cli) {
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
}

/// Handle the commands that run before config load and exit immediately
/// (`--setup-caps`, `--strip-secrets`). Returns the process exit code when
/// one of them ran.
pub fn run_startup_commands(cli: &Cli) -> Option<i32> {
    // --setup-caps: grant this binary the capabilities needed for live
    // capture. Handled before any config/capture setup so it works right
    // after a fresh `cargo install` with no config present.
    if cli.setup_caps {
        return Some(match privilege::setup_capabilities() {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("{e}");
                1
            }
        });
    }

    // --strip-secrets: write a DSB-free copy of the input pcapng. The input
    // is never modified; the output is written atomically.
    if let Some(ref out) = cli.strip_secrets {
        let Some(ref input) = cli.input else {
            tracing::error!("--strip-secrets requires an input file (-I <file>)");
            return Some(1);
        };
        return Some(
            match crate::capture::pcapng_meta::strip_secrets(
                std::path::Path::new(input),
                std::path::Path::new(out),
            ) {
                Ok(n) => {
                    tracing::info!("Stripped {n} decryption secret(s): {input} -> {out}");
                    0
                }
                Err(e) => {
                    tracing::error!("--strip-secrets failed: {e}");
                    1
                }
            },
        );
    }

    None
}

/// Handle `--mint-token`: mint a signed bearer token, print it, and return
/// the exit code — or `None` when the flag is absent. The body is
/// feature-swapped so the caller contains no `cfg`.
pub fn run_mint_token(cli: &Cli) -> Option<i32> {
    if !cli.mint_token {
        return None;
    }
    #[cfg(any(feature = "api", feature = "mcp"))]
    {
        match mint_token_and_exit(cli) {
            Ok(token) => {
                println!("{token}");
                Some(0)
            }
            Err(msg) => {
                tracing::error!("{msg}");
                Some(2)
            }
        }
    }
    #[cfg(not(any(feature = "api", feature = "mcp")))]
    {
        tracing::error!("--mint-token requires the 'api' or 'mcp' feature (not compiled in)");
        Some(2)
    }
}

/// Load the configuration file and apply the `[limits]` section's parser /
/// dialog caps.
pub fn load_config(cli: &Cli) -> Result<LoadedConfig, PlanError> {
    let loaded = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(loaded) => {
            if let Some(ref source) = loaded.source {
                tracing::info!("Loaded config from {}", source.display());
            }
            loaded
        }
        Err(e) => {
            return Err(PlanError {
                exit_code: 1,
                message: e.to_string(),
            });
        }
    };

    if let Err(e) = loaded.config.limits.validate() {
        return Err(PlanError {
            exit_code: 1,
            message: e.to_string(),
        });
    }

    // Apply configurable security limits from the [limits] section.
    if let Some(v) = loaded.config.limits.max_header_line {
        crate::sip::parser::set_parser_limits(
            v as usize,
            loaded
                .config
                .limits
                .max_headers_per_message
                .map(|h| h as usize)
                .unwrap_or(crate::sip::parser::DEFAULT_MAX_HEADERS_PER_MESSAGE),
        );
    } else if let Some(v) = loaded.config.limits.max_headers_per_message {
        crate::sip::parser::set_parser_limits(
            crate::sip::parser::DEFAULT_MAX_HEADER_LINE_LEN,
            v as usize,
        );
    }
    if let Some(v) = loaded.config.limits.max_messages_per_dialog {
        crate::sip::dialog_store::set_max_messages_per_dialog(v as usize);
    }

    Ok(loaded)
}

/// Handle `--dump-config`: print the version and effective config.
/// Returns the process exit code.
pub fn dump_config(loaded: &LoadedConfig) -> i32 {
    println!("sipnab v{}", cli::build_version());
    println!();
    if let Some(ref source) = loaded.source {
        println!("# Loaded from: {}", source.display());
    } else {
        println!("# No config file loaded (defaults only)");
    }
    match loaded.config.dump() {
        Ok(toml_str) => {
            println!("{toml_str}");
            0
        }
        Err(e) => {
            tracing::error!("Failed to dump config: {e}");
            1
        }
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

// ── Filter expression building ──────────────────────────────────────

/// Build a `FilterExpr` from CLI `--filter` flag, diagnostic aliases, or config fallback.
fn build_filter_expr(cli: &Cli, config: &Config) -> Option<FilterExpr> {
    // Explicit --filter takes precedence. Try alias expansion first
    // (so `--filter codec-asym` works the same as MCP find_problems'
    // kinds shorthand); fall back to raw DSL parsing.
    if let Some(ref expr) = cli.filter {
        let resolved = crate::sip::dsl::expand_alias(expr).unwrap_or(expr.as_str());
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
            let cfg = crate::app::servers::resolve_api_verifier_config(cli);
            first_key = cfg.signing_keys.into_iter().next();
            ttl = cli.api_token_ttl;
        }
    }
    #[cfg(feature = "mcp")]
    if first_key.is_none()
        && (cli.mcp_signing_key_file.is_some() || !cli.mcp_signing_key.is_empty())
    {
        let cfg = crate::app::servers::resolve_mcp_verifier_config(cli);
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

    Ok(crate::auth::mint(&key, &id, exp))
}

// ── Unit tests for the binary's pure helpers ────────────────────────────
//
// These cover the stand-alone logic in `main.rs` that needs no live capture
// device: argument parsers, filter/capture-config builders, post-capture
// and the filter/capture-config builders. The batch runner's tests live in
// `crate::app::batch`; the live-capture / TUI arms stay integration-only.
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
