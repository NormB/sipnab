// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bootstrap planning (WS2c): the testable seam between argument parsing
//! and running.
//!
//! `plan` is a `Cli` + `Config` → `RunPlan` mapping — every decision
//! main() used to make inline (capture source, portrange, BPF
//! auto-generation, filters, output options, run mode) becomes a value that
//! unit tests can assert on, with most configuration errors returned as
//! `PlanError` instead of process exits buried in helpers (the filter and
//! capture-config builders still exit directly on invalid input). `launch`
//! then performs the side-effectful part: channel creation, capture start,
//! readiness hand-shake, chroot, and privilege drop.

use crate::capture::{self, CaptureConfig, CaptureSource};
use crate::cli::{self, Cli};
use crate::config::{Config, LoadedConfig};
use crate::output::{ColorMode, EventExecEngine, OutputOptions};
use crate::privilege;
use crate::sip::{dsl::FilterExpr, matcher::SipMatcher};

use super::batch::{CapturePolicy, audio_retention_wanted};

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
    /// Shorthand for an argument-level error (exit code 2).
    fn arg(message: String) -> Self {
        Self {
            exit_code: 2,
            message,
        }
    }

    /// Log the message via `tracing::error!` and terminate the process
    /// with the planned exit code. Never returns.
    pub fn exit(self) -> ! {
        tracing::error!("{}", self.message);
        std::process::exit(self.exit_code);
    }

    /// Like [`exit`](Self::exit), but runs `cleanup` between reporting and
    /// exiting. Never returns.
    ///
    /// # Arguments
    ///
    /// * `cleanup` — teardown that must happen before the process dies, such as
    ///   stopping a capture thread that is already running.
    ///
    /// The error is reported first so the reason reaches the user ahead of any
    /// noise the teardown emits, and `std::process::exit` is called only after
    /// the cleanup returns — it runs no destructors, so anything not done here
    /// does not happen at all.
    pub fn exit_after(self, cleanup: impl FnOnce()) -> ! {
        tracing::error!("{}", self.message);
        cleanup();
        std::process::exit(self.exit_code);
    }
}

/// Which top-level mode this invocation runs.
pub enum RunMode {
    /// Interactive TUI (the default when compiled in and stdio is free).
    Tui,
    /// Headless batch capture/replay (`super::batch::run`).
    Batch,
    /// Multi-core offline file reconstruction (`--cores N -I file`),
    /// bypassing the capture thread entirely.
    CoresFile,
}

/// Everything main() needs to run, decided up front from CLI + config.
pub struct RunPlan {
    /// The capture source; `None` defers to device auto-detection in
    /// `launch`.
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
    /// Every capture file the run will read, resolved and in read order.
    ///
    /// `source` is MOVED into `launch`, so anything downstream that needs the
    /// whole set has to receive it separately — and several things do. Features
    /// that reached for `cli.primary_input()` got the first `-I` ARGUMENT,
    /// which after chronological reordering is often not even the first file
    /// read, and for `-I /pcaps` is a directory. Empty for live and HEP
    /// sources, which read no files (#48).
    pub input_files: Vec<std::path::PathBuf>,
    /// Top-level run mode (TUI vs batch vs multi-core file).
    pub mode: RunMode,
    /// Parsed `--metrics` bind address (TUI path only; batch handles its
    /// own). Always `None` in builds without the `metrics` + `tui` features.
    pub metrics_bind: Option<std::net::SocketAddr>,
}

/// Decide everything: capture source precedence, capture config, portrange
/// (CLI > config > default), BPF auto-generation for live captures,
/// autostop/split policy, matcher/filter/output/event-exec construction,
/// and the run mode. No capture is started and no privileges change here,
/// and no path exits the process: every fatal misconfiguration — including
/// an unreadable `--bpf-file`, invalid `--duration`, or invalid filter
/// expression surfaced by the `build_capture_config` / `build_filter_expr`
/// helpers — is returned as a `PlanError` for the caller to handle.
///
/// # Arguments
///
/// * `cli` — parsed command-line flags.
/// * `config` — loaded configuration supplying fallbacks for most flags.
///
/// # Returns
///
/// The complete `RunPlan` main() dispatches on.
///
/// # Errors
///
/// Returns a `PlanError` (exit code 2) for an invalid `--hep-allow` CIDR,
/// HEP auth misconfiguration, an unreadable `--bpf-file`, invalid
/// `--duration`, invalid `--portrange`, `--autostop`, `--split`, filter
/// pattern, `--filter`/diagnostic/config filter expression, or `--metrics`
/// address.
pub fn plan(cli: &Cli, config: &Config) -> Result<RunPlan, PlanError> {
    // FIRST, before anything can mint an identity. `set_node_name` writes a
    // process-global `OnceLock` and the first writer wins, so a later call
    // would be silently ignored and answers would carry the hostname while the
    // command line said otherwise.
    //
    // CLI first, config second, hostname last — and the ORDER of these two
    // calls is the precedence, because the first writer wins. Written as a
    // chain rather than an if/else so adding a third source cannot
    // accidentally invert it.
    for candidate in [
        cli.node_name.as_deref(),
        config.capture.node_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        crate::provenance::set_node_name(candidate);
    }

    // Capture source precedence: -I file > -d device > config device >
    // --hep-listen > auto-detect (deferred to launch()).
    // manual_map: without the `hep` feature the --hep-listen arm cfg-shrinks
    // to a bare Some(..) that clippy wants as .map(), but the full arm uses
    // `?` (CIDR parsing), which a map closure cannot.
    // `-I` beating `-d` is a silent wrong answer, so say so.
    //
    // Both flags parse happily together and `-I` simply wins: sipnab reads the
    // file, never touches the interface, and the output is byte-identical to a
    // correct run. Someone adapting a documented pcap command to watch live
    // traffic naturally adds `-d` and leaves `-I` in place — and then an agent
    // answers questions about a stale capture with total confidence. For a
    // diagnostic tool that is the worst failure mode there is: not a crash, but
    // a confident wrong answer nobody has reason to doubt.
    //
    // A warning rather than an error, because the precedence is long-standing
    // and someone may be relying on it deliberately.
    if cli.has_input() && cli.device.is_some() {
        tracing::warn!(
            "both --input/-I and --device/-d given: reading the FILE and ignoring the \
             interface. Drop -I to capture live traffic."
        );
    }

    #[allow(clippy::manual_map)]
    let source = if cli.has_input() {
        // Expand directories, globs and repeated -I into the exact files to
        // read, ordered by when their packets were captured. Resolution
        // happens here rather than in the reader so a bad path fails before
        // any thread starts and the operator sees the count they are about to
        // analyse.
        let resolved =
            match crate::capture::input_set::resolve(&cli.input, &cli.input_resolve_options()) {
                Ok(r) => r,
                Err(e) => {
                    return Err(PlanError {
                        exit_code: 1,
                        message: format!("{e:#}"),
                    });
                }
            };
        if resolved.len() > 1 {
            tracing::info!(
                "Reading {} capture files in timestamp order (first: '{}')",
                resolved.len(),
                resolved[0].path.display()
            );
        }
        let paths: Vec<std::path::PathBuf> = resolved.into_iter().map(|r| r.path).collect();

        // Precondition, not a post-hoc error: an output that names an input is
        // refused here, before any writer exists. `-O` opens with truncation,
        // so a check made after the open has already destroyed the capture —
        // and a capture is routinely the only copy of an incident. Checked
        // against the whole resolved SET and the directories `-I` named, since
        // `-I` takes a directory or a glob.
        let protected =
            crate::capture::output_guard::ProtectedInputs::new(&cli.input, &paths, cli.recursive);
        if let Some(ref out) = cli.output {
            let split_active = cli.split.is_some();
            protected
                .check(std::path::Path::new(out), "-O/--output", split_active)
                .map_err(PlanError::arg)?;
        }

        Some(CaptureSource::File { paths })
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
        let hep_auth = cli
            .resolve_hep_auth()
            .map_err(|e| PlanError::arg(format!("HEP auth: {e}")))?;
        Some(CaptureSource::Hep {
            bind_addr: hep_addr.clone(),
            #[cfg(feature = "hep")]
            allowlist,
            rate_limit: cli.hep_rate_limit_resolved(config),
            per_peer_rate_limit: cli
                .hep_rate_limit_per_peer
                .resolve(cli.hep_rate_limit_resolved(config), cli.hep_allow.len()),
            auth_key: hep_auth,
            #[cfg(feature = "hep")]
            auth_mode: cli.hep_auth_mode,
        })
    } else {
        None
    };

    // An operator who asked for a transmitting feature and is reading a file
    // gets told once, here, before any mode branches. The refusal itself is
    // structural (`security::transmit_guard::TransmitPermit` cannot be built
    // from a file source, so the kill worker cannot be spawned and its sends
    // cannot compile), but a structural refusal nobody is told about leaves
    // someone believing their scanner defence is armed. Said in `plan` rather
    // than at the spawn site because `plan` runs for every mode, including
    // `--cores` and the TUI, which never reach the spawn site at all.
    let kill_requested = cli.kill_scanner
        || !cli.kill_target.is_empty()
        || config.security.kill_scanner.unwrap_or(false);
    if kill_requested
        && let Some(ref s) = source
        && crate::security::transmit_guard::TransmitPermit::for_source(s).is_none()
    {
        let flags = if cli.kill_target.is_empty() {
            "--kill-scanner"
        } else if cli.kill_scanner {
            "--kill-scanner / -K"
        } else {
            "-K/--kill-target"
        };
        tracing::warn!(
            "{}",
            crate::security::transmit_guard::offline_refusal(flags)
        );
    }

    // `--hep-send` is the other way a packet leaves, and it is not the same
    // question. Its destination is one the operator typed, so it is not
    // refused on a file the way the kill path is — replaying an archive into a
    // collector is a supported workflow. What it owes them is a sentence:
    // pointed at `-I customer.pcap`, the flag forwards that capture's
    // signalling off the machine, and its name says nothing about files.
    // Emitted here, beside the refusal above, so the operator reads it before
    // the capture thread opens anything.
    #[cfg(feature = "hep")]
    if let Some(ref addr) = cli.hep_send
        && let Some(CaptureSource::File { ref paths }) = source
        && let Some(notice) = crate::capture::hep::file_export_notice(
            &crate::capture::hep::OperatorDestination::from_cli_flag(
                crate::capture::hep::HEP_SEND_FLAG,
                addr,
            ),
            paths,
        )
    {
        tracing::warn!("{notice}");
    }

    // Capture config from CLI + config file.
    let mut capture_config = build_capture_config(cli, config)?;

    // Portrange: CLI > config file > default "5060-5061".
    let portrange_str = cli
        .portrange
        .as_deref()
        .or(config.capture.portrange.as_deref())
        .unwrap_or("5060-5061");
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
    //
    // The filter is encapsulation-aware because the previous one was not, and
    // that is the worst shape a capture bug can take: `portrange 5060-5061`
    // matches 0 of the 32 PPPoE-encapsulated SIP frames in
    // `tests/pcap-samples/DTMFsipinfo.pcap`. The frames were discarded by the
    // KERNEL, so no userspace counter, metric or report could see them — the
    // operator got "No SIP traffic found" on a link carrying calls. See
    // `auto_bpf_filter` for why this cannot be written with libpcap's `vlan` /
    // `mpls` / `pppoes` qualifiers.
    let tunnel_ports = resolve_tunnel_ports(cli)?;
    if capture_config.bpf_filter.is_none() && is_live {
        let (lo, hi) = portrange;
        let filter = auto_bpf_filter(lo, hi, &tunnel_ports);
        tracing::info!("Auto-generated BPF filter: {filter}");
        if let Some(msg) = tunnel_omission_notice(&tunnel_ports) {
            tracing::warn!("{msg}");
        }
        capture_config.bpf_filter = Some(filter);
    } else if is_live && let Some(ref filter) = capture_config.bpf_filter {
        // Their expression, unmodified — but say what it cannot see.
        if let Some(msg) = explicit_filter_encap_notice(filter) {
            tracing::warn!("{msg}");
        }
        if !tunnel_ports.is_empty() {
            tracing::warn!(
                "--capture-tunnels is ignored: this run uses the BPF filter you \
                 supplied, and sipnab does not edit it. Add the tunnel ports to \
                 your own expression (e.g. `or udp port \
                 {TUNNEL_PORTS_DEFAULT_LIST}`, one `udp port N` term each)."
            );
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
    let matcher = SipMatcher::new_with_overrides(
        cli,
        cli.match_expr.as_deref(),
        effective_from,
        effective_to,
    )
    .map_err(|e| PlanError::arg(format!("Invalid filter pattern: {e}")))?;

    // Filter DSL expression (--filter or diagnostic aliases), falling back
    // to config.filter.expression.
    let filter_expr = build_filter_expr(cli, config)?;

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
        show_proto_number: cli.proto_number,
    };

    // Event exec engine.
    let event_exec = EventExecEngine::new(
        cli.on_dialog_exec.clone(),
        cli.on_quality_exec.clone(),
        cli.exec_rate_limit,
        cli.quality_threshold,
    );

    // Parsed --metrics bind address, validated here so a bad address fails at
    // plan time rather than after a capture is running.
    //
    // The comment this replaces claimed "batch starts its own metrics server".
    // It did not — `start_metrics_server` had one call site, in tui_mode.rs —
    // and the claim is why the gap survived: a reader checking whether headless
    // was covered found a note saying it was. `servers::start_servers` now
    // starts it for both modes, so the `feature = "tui"` coupling below is
    // gone too.
    #[cfg(feature = "metrics")]
    let metrics_bind = match cli.metrics.as_deref() {
        Some(addr_str) => Some(
            crate::output::prometheus_server::parse_metrics_addr(addr_str)
                .map_err(|e| PlanError::arg(format!("Invalid --metrics address: {e}")))?,
        ),
        None => None,
    };
    #[cfg(not(feature = "metrics"))]
    let metrics_bind = None;

    // Run mode. The multi-core offline file path outranks the TUI/batch
    // choice; MCP forces batch (it owns stdio, the TUI must not start).
    //
    // `--call-report` also lands in batch, but it does so because
    // `Cli::normalize` has already set `no_tui` — the implication is applied
    // once at the parse boundary rather than re-derived here. Deriving it
    // here instead would fix only this decision and leave the three output
    // gates in `app::batch` still reading `no_tui` as a proxy for "batch".
    // `--cores N` shards by host pair and rebuilds dialogs per shard. It has no
    // per-message stream to write, no writer for `-O`, and no replay clock — so
    // asking for any of those alongside it used to produce NOTHING, exit 0,
    // beside a summary that cheerfully reported the messages it had found.
    // Measured on one capture: `--json` 13,460 lines at `--cores 1` and 0 at
    // `--cores 4`; `--text-dump` 194,321 and 0; `-O` a 100 MB file and no file
    // at all. An empty output that exits 0 reads as "there was nothing to
    // report", which is the one conclusion the run had disproved.
    //
    // Refusing is not the whole answer — these could be implemented, and #82
    // records what that would take. It is the honest answer until then, because
    // the alternative is a silent wrong result.
    if cli.cores > 1 && cli.has_input() && !cli.multi_device {
        let mut unsupported: Vec<&str> = Vec::new();
        if cli.json || cli.json_pretty {
            unsupported.push("--json");
        }
        if cli.text_dump {
            unsupported.push("--text-dump");
        }
        if cli.fail2ban {
            unsupported.push("--fail2ban");
        }
        if cli.output.is_some() {
            unsupported.push("-O/--output");
        }
        if !unsupported.is_empty() {
            tracing::error!(
                "--cores {} cannot produce {}: the parallel reader rebuilds \
                 dialogs per shard and has no per-message stream or capture \
                 writer, so it would emit nothing and still exit 0. Drop \
                 --cores for these, or keep --cores and ask for a whole-capture \
                 view instead (--json-dialogs, --report, --call-report), which \
                 the parallel path does produce.",
                cli.cores,
                unsupported.join(", ")
            );
            std::process::exit(2);
        }
    }

    // The complement of the block above: `--cores N` on a source the parallel
    // reader cannot take. Not fatal — the run is correct, just single-threaded
    // — but never silent again. See `cores_ignored_warning`.
    if let Some(msg) = cores_ignored_warning(cli) {
        tracing::warn!("{msg}");
    }

    // The one path `--metrics` still does not reach, said out loud rather than
    // left to be discovered by an empty Grafana panel.
    #[cfg(feature = "metrics")]
    if let Some(msg) = metrics_ignored_on_cores_warning(cli) {
        tracing::warn!("{msg}");
    }

    // A truncating --snaplen feeding -O writes a short pcap that reads as whole:
    // the one place capture truncation leaves the tool and cannot be inferred
    // downstream. Warned, not refused — the analysis is complete.
    if let Some(msg) = snaplen_truncation_warning(cli, config) {
        tracing::warn!("{msg}");
    }

    // Unlike -O, a truncating --snaplen here reaches sipnab's own analysis:
    // --retain-audio buffers RTP payload for export_audio to decode, and a
    // snaplen tuned for signalling truncates that payload before retention
    // ever sees it.
    if let Some(msg) = snaplen_audio_retention_warning(cli, config) {
        tracing::warn!("{msg}");
    }

    let mode = if cli.cores > 1 && cli.has_input() && !cli.multi_device {
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

    // Immediate mode picks the kernel ring format, so it can only be answered
    // once the consumer is known — which is here, and not in
    // `build_capture_config`, which runs before the mode is decided.
    capture_config.immediate_mode = immediate_mode_for(&mode);

    // Derived from `source` before it moves, so the two cannot disagree about
    // which files the run reads. Re-resolving here would open every file a
    // second time and give the two answers a chance to differ.
    let input_files: Vec<std::path::PathBuf> = match source {
        Some(CaptureSource::File { ref paths }) => paths.clone(),
        _ => Vec::new(),
    };

    Ok(RunPlan {
        source,
        input_files,
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
    /// Raw socket for source-spoofed scanner-kill responses, opened in the
    /// privileged window when the kill feature is active and `--kill-spoof`
    /// permits it. `None` → the worker uses the ephemeral UDP send.
    pub raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
}

/// Perform the side-effectful launch sequence exactly as main() did:
/// resolve device auto-detection, create the packet channel, start the
/// capture thread, wait for the source-open handshake, then chroot, drop
/// privileges, and apply the remaining runtime hardening. Exits the
/// process on failure (these are unrecoverable environment errors).
///
/// # Arguments
///
/// * `cli` / `config` — parsed flags and loaded configuration.
/// * `source` — the planned capture source; `None` triggers device
///   auto-detection here.
/// * `capture_config` — capture parameters (BPF, snaplen, memory budget)
///   handed to the capture thread.
///
/// # Returns
///
/// A `Launched` bundle: the capture-thread handle, the packet receiver,
/// and the optional raw scanner-kill socket.
///
/// # Side effects
///
/// In order: fails fast on flags whose feature is not compiled in; creates
/// the bounded packet channel; spawns the capture thread (single- or
/// multi-device) and blocks on its readiness handshake; chroots when
/// configured (root only); opens a CAP_NET_RAW raw socket for spoofed
/// scanner-kill responses while still privileged; drops privileges
/// (setgroups/setgid/setuid); initializes syslog for `--syslog`; validates
/// the remaining feature-gated flags and `--pcap-export-mode`; and
/// disables core dumps when decryption keys are loaded. Every failure path
/// logs and exits the process (code 1 for environment errors, 2 for
/// argument/feature errors).
pub fn launch(
    cli: &Cli,
    config: &Config,
    source: Option<CaptureSource>,
    capture_config: &CaptureConfig,
) -> Launched {
    // 13a. Feature gates that must fail fast, BEFORE any capture device is
    // opened: without them the flag silently degrades (--mcp used to run a
    // plain batch capture with no server; --hep-listen used to error late at
    // capture spawn with a generic failure and exit 1).
    #[cfg(not(feature = "mcp"))]
    if cli.mcp {
        tracing::error!("--mcp requires the 'mcp' feature (not compiled in)");
        std::process::exit(2);
    }
    #[cfg(not(feature = "hep"))]
    if cli.hep_listen.is_some() {
        tracing::error!("--hep-listen requires the 'hep' feature (not compiled in)");
        std::process::exit(2);
    }

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

    // Whether this run may put a packet on the network at all — decided from
    // the source that was actually resolved (auto-detection included), before
    // it is moved into the capture thread. See `security::transmit_guard`.
    let may_transmit =
        crate::security::transmit_guard::TransmitPermit::for_source(&source).is_some();

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
            capture::stop_and_join(handle, rx);
            std::process::exit(1);
        }
        Err(_) => {
            tracing::error!("Capture thread exited before signaling ready");
            capture::stop_and_join(handle, rx);
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
        capture::stop_and_join(handle, rx);
        std::process::exit(1);
    }

    // 16-kill. Open the raw scanner-kill socket while still privileged (it
    //         needs CAP_NET_RAW, which the drop below sheds). Only when the
    //         kill feature is active and --kill-spoof permits it.
    //
    //         Reading a capture file grants no transmit permit, so no kill
    //         worker will be spawned and the socket would have nothing to send.
    //         Skipping the open here also keeps `--kill-spoof raw -I file.pcap`
    //         from failing the run over a raw socket it was never going to
    //         use — the operator has already been told (in `plan`) that the
    //         kill response is off for this run. Debug-level here: one warning
    //         per run, not one per decision point.
    let kill_active = cli.kill_scanner || !cli.kill_target.is_empty();
    if kill_active && !may_transmit {
        tracing::debug!("Scanner-kill: offline run, not opening a raw send socket");
    }
    let raw_kill_sock = if kill_active
        && may_transmit
        && cli.kill_spoof != crate::cli::KillSpoof::Ephemeral
    {
        match crate::process_isolation::RawKillSocket::open() {
            Ok(sock) => {
                tracing::info!("Scanner-kill: source-spoofing enabled (raw socket)");
                Some(sock)
            }
            Err(e) => {
                if cli.kill_spoof == crate::cli::KillSpoof::Raw {
                    tracing::error!(
                        "--kill-spoof raw requires a raw socket but it could not be opened: {e}. \
                         Grant CAP_NET_RAW (sipnab --setup-caps / run under sudo) or use \
                         --kill-spoof ephemeral."
                    );
                    capture::stop_and_join(handle, rx);
                    std::process::exit(1);
                }
                tracing::warn!(
                    "Scanner-kill: raw socket unavailable ({e}); falling back to ephemeral \
                     source port. Kill responses will come from sipnab's own port."
                );
                None
            }
        }
    } else {
        None
    };

    // 16a. Drop privileges now that capture devices are open and chroot is applied (D15)
    let effective_user = cli.user.as_deref().or(config.privilege.user.as_deref());
    let effective_no_priv_drop = cli.no_priv_drop || config.privilege.no_priv_drop.unwrap_or(false);
    if let Err(e) = privilege::drop_privileges(effective_user, effective_no_priv_drop) {
        tracing::error!("Failed to drop privileges: {e}");
        capture::stop_and_join(handle, rx);
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
        capture::stop_and_join(handle, rx);
        std::process::exit(2);
    }

    // 16d. Validate --hep-parse requires hep feature
    #[cfg(not(feature = "hep"))]
    if cli.hep_parse {
        tracing::error!("HEP support requires --features hep");
        capture::stop_and_join(handle, rx);
        std::process::exit(2);
    }

    // 16d2. Validate TLS flags require tls feature
    #[cfg(not(feature = "tls"))]
    {
        if cli.tls_key.is_some() {
            tracing::error!("--tls-key requires the 'tls' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.keylog.is_some() {
            tracing::error!("--keylog requires the 'tls' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.keylog_watch {
            tracing::error!("--keylog-watch requires the 'tls' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.srtp_keys.is_some() {
            tracing::error!("--srtp-keys requires the 'tls' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
    }

    // 16d3. Validate API flags require api feature
    #[cfg(not(feature = "api"))]
    {
        if cli.api.is_some() {
            tracing::error!("--api requires the 'api' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.api_key.is_some() {
            tracing::error!("--api-key requires the 'api' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.api_tls_cert.is_some() {
            tracing::error!("--api-tls-cert requires the 'api' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
        if cli.api_tls_key.is_some() {
            tracing::error!("--api-tls-key requires the 'api' feature (not compiled in)");
            capture::stop_and_join(handle, rx);
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
            capture::stop_and_join(handle, rx);
            std::process::exit(2);
        }
    }

    // 16f. --dtls-keylog: the DTLS-SRTP extractor is constructed later (alongside
    // the SRTP context); here we only enforce the feature gate.
    #[cfg(not(feature = "tls"))]
    if cli.dtls_keylog.is_some() {
        tracing::error!("--dtls-keylog requires the 'tls' feature (not compiled in)");
        capture::stop_and_join(handle, rx);
        std::process::exit(2);
    }

    // 16g. Validate --api-tls-cert/--api-tls-key consistency
    if cli.api_tls_cert.is_some() != cli.api_tls_key.is_some() {
        tracing::error!("--api-tls-cert and --api-tls-key must both be specified together");
        capture::stop_and_join(handle, rx);
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
        capture::stop_and_join(handle, rx);
        std::process::exit(1);
    }

    Launched {
        handle,
        rx,
        raw_kill_sock,
    }
}

/// Initialize the tracing/log subscriber from `SIPNAB_LOG` and the CLI's
/// quiet/TUI flags, writing to stderr (stdout stays reserved for MCP's
/// JSON-RPC wire and per-message output).
///
/// # Side effects
///
/// Installs the global tracing subscriber and the `log`-to-`tracing`
/// bridge for the rest of the process; both installs are best-effort
/// (errors from double initialization are ignored). Reads the
/// `SIPNAB_LOG` environment variable.
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
    // The tracing subscriber writes to stderr — preserves the stdio MCP
    // invariant that stdout is the JSON-RPC wire.
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
/// (`--completions`, `--setup-caps`, `--strip-secrets`).
///
/// # Returns
///
/// The process exit code when one of them ran; `None` when no startup
/// command was requested and normal startup should continue.
///
/// # Side effects
///
/// `--completions` prints a shell-completion script to stdout;
/// `--setup-caps` sets file capabilities on the sipnab binary;
/// `--strip-secrets` resolves `-I` (reading the directories and globs it
/// names) and writes a DSB-free copy of the one capture it resolves to
/// (atomically; the input is never modified). It refuses an input set of any
/// other size rather than sanitising part of it.
pub fn run_startup_commands(cli: &Cli) -> Option<i32> {
    // --completions <shell>: print a completion script and exit. Needs no
    // config, capture, or privileges.
    if let Some(shell) = cli.completions {
        use clap::CommandFactory;
        let mut cmd = crate::cli::Cli::command();
        clap_complete::generate(shell, &mut cmd, "sipnab", &mut std::io::stdout());
        return Some(0);
    }

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

    // --show-frame <pointer>: follow a pointer a previous run emitted and print
    // that frame. Needs no config, no capture and no privileges -- it reads one
    // frame out of one file.
    if let Some(ref pointer) = cli.show_frame {
        return Some(show_frame(pointer));
    }

    // --strip-secrets: write a DSB-free copy of the input pcapng. The input
    // is never modified; the output is written atomically.
    if let Some(ref out) = cli.strip_secrets {
        if !cli.has_input() {
            tracing::error!("--strip-secrets requires an input file (-I <file>)");
            return Some(1);
        }
        // Resolve `-I` the way a normal run does instead of reading
        // `cli.primary_input()`, the first `-I` *argument*. `-I` is repeatable
        // and expands directories and globs, so the argument is often not a
        // file at all — a directory reached the pcapng writer as a path and
        // failed with a bare "Is a directory".
        //
        // Resolution opens each candidate through libpcap, so a file sipnab
        // cannot read as a capture is now named in an error rather than handed
        // to the stripper. That is the same standard every other `-I` path
        // holds, and the operator learns which file rather than which errno.
        let resolved =
            match crate::capture::input_set::resolve(&cli.input, &cli.input_resolve_options()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("--strip-secrets: {e:#}");
                    return Some(1);
                }
            };

        // More than one resolved file is refused, not partly handled.
        //
        // `--strip-secrets <out>` names ONE output path, so a set of inputs has
        // nowhere to go: stripping every file would mean inventing output names
        // and writing files the operator never asked for. The alternative this
        // replaces was worse — it sanitised the first file, exited 0, and said
        // "Stripped N decryption secret(s)". This is a privacy control. Someone
        // running it before sending captures to a vendor reads that success and
        // ships the remaining files with live TLS keys inside them, and nothing
        // in the output gives them a reason to doubt it. A partial job reported
        // as a whole one is the failure being fixed here, so refusing is the
        // fix: an error naming every resolved file loses nobody any keys, and
        // re-running once per file is a loop the operator can write.
        if resolved.len() != 1 {
            let names = resolved
                .iter()
                .map(|r| format!("'{}'", r.path.display()))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!(
                "--strip-secrets writes one sanitised copy, but -I resolved to {} files: {names}. \
                 Run it once per file — stripping only one of them would ship the rest with \
                 their decryption secrets intact.",
                resolved.len()
            );
            return Some(1);
        }
        // Same precondition as `-O`: the sanitised copy must not be written
        // over the file it is sanitising. `--strip-secrets` promises the input
        // is never modified, and pointed at its own input it replaced it —
        // taking the only copy of the decryption secrets with it, which is
        // precisely the material this flag exists to preserve a copy without.
        let protected = crate::capture::output_guard::ProtectedInputs::new(
            &cli.input,
            &resolved.iter().map(|r| r.path.clone()).collect::<Vec<_>>(),
            cli.recursive,
        );
        if let Err(msg) = protected.check(std::path::Path::new(out), "--strip-secrets", false) {
            tracing::error!("{msg}");
            return Some(2);
        }

        let input = resolved[0].path.display().to_string();
        return Some(
            match crate::capture::pcapng_meta::strip_secrets(
                &resolved[0].path,
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
/// Follow one frame pointer and print the frame, or refuse and say why.
///
/// The refusals are the reason this exists. Returning the bytes at an ordinal
/// without checking them is the failure the whole provenance feature is built
/// to avoid: the caller gets a frame, believes it is the frame the finding was
/// about, and has no way to tell the capture was rotated underneath them. So a
/// digest mismatch is an error, not a warning printed above the bytes.
///
/// # Returns
///
/// `0` when the frame was found (verified, or unverified and labelled as
/// such), `1` when the pointer could not be honoured, `2` when it did not
/// parse.
fn show_frame(pointer: &str) -> i32 {
    use crate::capture::resolve::{Resolution, ResolveError, parse_pointer, resolve};

    let parsed = match parse_pointer(pointer) {
        Ok(p) => p,
        Err(_) => {
            tracing::error!(
                "not a frame pointer: {pointer}\n\
                 expected <source>#<ordinal>, optionally #<ordinal>@<digest> — \
                 the form the `frame` field of --json-dialogs, --report, REST \
                 and MCP emits"
            );
            return 2;
        }
    };

    match resolve(&parsed) {
        Ok(Resolution::Verified(bytes)) => {
            println!("VERIFIED  {pointer}");
            println!(
                "{} bytes, frame {} of {}",
                bytes.len(),
                parsed.origin.ordinal,
                parsed.source
            );
            println!();
            print!("{}", crate::output::hexdump::hexdump(&bytes));
            0
        }
        Ok(Resolution::Unverified(bytes)) => {
            // Printed, but never called "found": the pointer carried no digest,
            // so these are the bytes at that position and nothing establishes
            // they are the bytes the pointer was made against.
            println!("UNVERIFIED  {pointer}");
            println!(
                "{} bytes, frame {} of {}",
                bytes.len(),
                parsed.origin.ordinal,
                parsed.source
            );
            println!(
                "The pointer carried no digest, so these bytes were not checked \
                 against anything. If the capture changed since the pointer was \
                 made, this is the wrong frame and nothing here can tell."
            );
            println!();
            print!("{}", crate::output::hexdump::hexdump(&bytes));
            0
        }
        Err(ResolveError::Changed { source, ordinal }) => {
            tracing::error!(
                "refusing: {source} frame {ordinal} is not the frame this \
                 pointer was made against. The capture was rotated, truncated \
                 or rewritten since then. Showing you what is there now would \
                 look like an answer and be the wrong one."
            );
            1
        }
        Err(ResolveError::NoSuchFrame {
            source,
            ordinal,
            frames_present,
        }) => {
            tracing::error!(
                "refusing: {source} holds {frames_present} frame(s), so there is \
                 no frame {ordinal}"
            );
            1
        }
        Err(ResolveError::Unreadable { source, cause }) => {
            tracing::error!("refusing: cannot read {source}: {cause}");
            1
        }
        Err(ResolveError::Malformed(t)) => {
            tracing::error!("not a frame pointer: {t}");
            2
        }
    }
}

/// the exit code — or `None` when the flag is absent. The body is
/// feature-swapped so the caller contains no `cfg`.
///
/// # Returns
///
/// `Some(0)` after printing the token to stdout, `Some(2)` on
/// misconfiguration (or when neither the `api` nor `mcp` feature is
/// compiled in), `None` when `--mint-token` was not given.
pub fn run_mint_token(cli: &Cli) -> Option<i32> {
    if !cli.mint_token {
        return None;
    }
    #[cfg(any(feature = "api", feature = "mcp"))]
    {
        match mint_token(cli) {
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
///
/// # Errors
///
/// Returns a `PlanError` (exit code 1) when the config file cannot be
/// loaded/parsed or its `[limits]` section fails validation.
///
/// # Side effects
///
/// Reads the config file from disk (logging its path when found) and
/// mutates process-global parser and dialog-store limits via
/// `set_parser_limits` / `set_max_messages_per_dialog`.
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

/// Handle `--dump-config`: print the version and effective config as TOML
/// to stdout. Returns the process exit code (0 on success, 1 when the
/// config fails to serialize).
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

/// Parse a port range string like "5060-5061" or "5060-5080" into a
/// `(u16, u16)` tuple. Errors on a malformed shape, non-numeric or
/// out-of-range ports, or start > end.
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

/// Build a `FilterExpr` from CLI `--filter` flag, diagnostic aliases, or
/// config fallback.
///
/// # Returns
///
/// The compiled expression, or `None` when no filter source is configured.
///
/// # Errors
///
/// Returns a `PlanError` (exit code 2) when the `--filter` expression, an
/// expanded diagnostic alias, or the config-file expression fails to parse.
/// Returning (rather than exiting) keeps planning testable and composable.
fn build_filter_expr(cli: &Cli, config: &Config) -> Result<Option<FilterExpr>, PlanError> {
    // Explicit --filter takes precedence. Try alias expansion first
    // (so `--filter codec-asym` works the same as MCP find_problems'
    // kinds shorthand); fall back to raw DSL parsing.
    if let Some(ref expr) = cli.filter {
        let resolved = crate::sip::dsl::expand_alias(expr).unwrap_or(expr.as_str());
        return match FilterExpr::parse(resolved) {
            Ok(f) => Ok(Some(f)),
            Err(e) => Err(PlanError::arg(format!("Invalid --filter expression: {e}"))),
        };
    }

    // Diagnostic alias expansion, through the SAME table `--filter <name>`
    // and the MCP `find_problems` kinds use. These flags are documented as
    // that alias by another name, and the hand-written copies that used to
    // live here had drifted from it: `--short-calls` was `duration < 10.0`
    // with no state gate, selecting 2310 of 2311 dialogs on a real capture
    // where the documented `duration < 5.0 AND state == 'Completed'` selected
    // 1681, and `--slow-setup` measured `setup_time` where the alias measures
    // `pdd`. Two spellings of one flag cannot disagree if there is only one.
    let mut parts: Vec<&str> = Vec::new();
    for (enabled, alias) in [
        (cli.problems, "problems"),
        (cli.slow_setup, "slow-setup"),
        (cli.short_calls, "short-calls"),
        (cli.one_way, "one-way"),
        (cli.nat_issues, "nat-issues"),
    ] {
        if enabled && let Some(expansion) = crate::sip::dsl::expand_alias(alias) {
            parts.push(expansion);
        }
    }

    if !parts.is_empty() {
        // Parenthesized: an alias may expand to an `AND` (short-calls does),
        // and joining those bare would let `OR` capture only its last term.
        let combined = parts
            .iter()
            .map(|p| format!("({p})"))
            .collect::<Vec<_>>()
            .join(" OR ");
        return match FilterExpr::parse(&combined) {
            Ok(f) => Ok(Some(f)),
            Err(e) => Err(PlanError::arg(format!(
                "Internal error building diagnostic filter: {e}"
            ))),
        };
    }

    // Fall back to config file expression
    if let Some(ref expr) = config.filter.expression {
        return match FilterExpr::parse(expr) {
            Ok(f) => Ok(Some(f)),
            Err(e) => Err(PlanError::arg(format!(
                "Invalid config filter expression: {e}"
            ))),
        };
    }

    Ok(None)
}

// ── Capture config builder ──────────────────────────────────────────

/// Build a `CaptureConfig` by merging CLI flags with config file values
/// (CLI wins; hard-coded defaults last).
///
/// # Side effects
///
/// Reads `--bpf-file` from disk when given.
///
/// # Errors
///
/// Returns a `PlanError` (exit code 2) on an unreadable `--bpf-file` or an
/// invalid `--duration`. Returning (rather than exiting) keeps planning
/// testable and composable.
fn build_capture_config(cli: &Cli, config: &Config) -> Result<CaptureConfig, PlanError> {
    let snaplen = cli.snaplen.or(config.capture.snaplen).unwrap_or(65535);

    let buffer_mb = cli
        .buffer
        .or(config.capture.buffer)
        .unwrap_or(crate::capture::DEFAULT_BUFFER_MB);

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
                return Err(PlanError::arg(format!(
                    "Failed to read BPF filter file '{bpf_file}': {e}"
                )));
            }
        }
    } else if !cli.bpf_filter.is_empty() {
        Some(cli.bpf_filter.join(" "))
    } else {
        None
    };

    let count = cli.count;

    let duration = match cli.duration.as_ref() {
        Some(d) => Some(
            capture::parse_duration(d)
                .map_err(|e| PlanError::arg(format!("Invalid --duration: {e}")))?,
        ),
        None => None,
    };

    // Promiscuous mode: on by default; `--no-promisc` (or `[capture] promisc`)
    // turns it off. The CLI flag wins over the config value.
    let promisc = if cli.no_promisc {
        false
    } else {
        config.capture.promisc.unwrap_or(true)
    };

    Ok(CaptureConfig {
        snaplen,
        buffer_mb,
        bpf_filter,
        count,
        duration,
        replay: cli.replay,
        buffer_budget_mb,
        promisc,
        // Finalised by `plan` once the run mode is known — see
        // `immediate_mode_for`. The interactive value is the right thing to
        // start from: it is what every capture asked for before the choice
        // existed, so nothing here can quietly change a ring format on its own.
        immediate_mode: true,
    })
}

/// Whether the capture handle should ask libpcap for immediate mode, given the
/// run mode this invocation resolved to.
///
/// The flag reads like a latency preference and is really a ring-format choice
/// (see [`CaptureConfig::immediate_mode`]), so it is answered by asking who
/// consumes the packets rather than by a flag anyone types.
///
/// The TUI keeps it. A person is watching individual messages appear, the link
/// under a live troubleshooting session is human-scale, and a message that
/// shows up a block later than it arrived is exactly the thing that makes an
/// interactive tool feel wrong.
///
/// Everything else gives it up. A headless capture — batch, `--json`, `-O`,
/// MCP, the API — is throughput-bound with nobody watching, and TPACKET_V3's
/// ring is what keeps a burst from being dropped on the floor. Trading a few
/// milliseconds of delivery latency nobody perceives for a ring that does not
/// shrink with the snaplen is the correct trade there.
fn immediate_mode_for(mode: &RunMode) -> bool {
    matches!(mode, RunMode::Tui)
}

// ── Auto-generated BPF filter ──────────────────────────────────────────

/// The UDP tunnel ports `--capture-tunnels` covers when given no value:
/// 2152 (GTP-U), 4789 (VXLAN), 6081 (GENEVE).
pub const TUNNEL_PORTS_DEFAULT: &[u16] = &[2152, 4789, 6081];

/// [`TUNNEL_PORTS_DEFAULT`] as clap spells it — the flag's
/// `default_missing_value`, so the two cannot drift.
pub const TUNNEL_PORTS_DEFAULT_LIST: &str = "2152,4789,6081";

/// Link-layer protocol numbers that put something other than IP next: a
/// 4-byte VLAN tag (802.1Q, 802.1ad, and the pre-standard 0x9100 some carrier
/// gear still emits), a PPPoE Session header, or an MPLS label stack
/// (unicast, multicast).
///
/// Matched through libpcap's `ether proto`, which resolves to the right
/// offset for whatever link type the filter is compiled against — see
/// [`auto_bpf_filter`].
const ENCAP_ETHERTYPES: &[u16] = &[0x8100, 0x88a8, 0x9100, 0x8864, 0x8847, 0x8848];

/// Lengths, in bytes, of the link-layer headers that carry a protocol field:
/// Ethernet (14), `DLT_LINUX_SLL` (16) and `DLT_LINUX_SLL2` (20).
///
/// Raw-IP and the two loopback link types are absent on purpose: they have no
/// protocol field, so `ether proto` is a compile-time FALSE there and no
/// encapsulated arm can fire — which is correct, since none of them can carry
/// a VLAN tag, and it also drops the arm's whole instruction cost on those
/// link types.
const LINK_HEADER_LENS: &[usize] = &[14, 16, 20];

/// Distances, in bytes, from the end of the link-layer header to the inner IP
/// header, one per encapsulation shape the filter claims.
///
/// 4 — one VLAN tag, or one MPLS label.
/// 8 — QinQ, a PPPoE Session header, or two MPLS labels.
/// 12 — one VLAN tag over a PPPoE Session header.
const ENCAP_DEPTHS: &[usize] = &[4, 8, 12];

/// "One of the two 16-bit port fields at `off` (source) and `off + 2`
/// (destination) is inside `lo..=hi`", as an absolute-offset BPF term.
fn port_pair_at(off: usize, lo: u16, hi: u16) -> String {
    let one = |o: usize| {
        if lo == hi {
            format!("ether[{o}:2] = {lo}")
        } else {
            format!("(ether[{o}:2] >= {lo} and ether[{o}:2] <= {hi})")
        }
    };
    format!("({} or {})", one(off), one(off + 2))
}

/// "An IPv4 or IPv6 datagram starts at `ip_off` and carries UDP or TCP with a
/// signalling port", as absolute-offset BPF terms.
///
/// IPv4 is pinned to `0x45` — version 4, header length 5 words — because the
/// port offset has to be a constant and BPF cannot multiply the IHL nibble
/// into an index. IPv4 options are therefore missed on the ENCAPSULATED arms
/// only; the untagged arm is a real libpcap `portrange`, which handles them.
/// The fragment-offset mask keeps the arm off trailing fragments, which carry
/// no ports at all, matching what libpcap's own port matching does.
fn ip_and_ports_at(ip_off: usize, lo: u16, hi: u16) -> String {
    let v4 = format!(
        "(ether[{ip_off}] = 0x45 and (ether[{proto}] = 17 or ether[{proto}] = 6) \
         and ether[{frag}:2] & 0x1fff = 0 and {ports})",
        proto = ip_off + 9,
        frag = ip_off + 6,
        ports = port_pair_at(ip_off + 20, lo, hi),
    );
    let v6 = format!(
        "(ether[{ip_off}] & 0xf0 = 0x60 and (ether[{nh}] = 17 or ether[{nh}] = 6) \
         and {ports})",
        nh = ip_off + 6,
        ports = port_pair_at(ip_off + 40, lo, hi),
    );
    format!("({v4} or {v6})")
}

/// Build the BPF filter sipnab installs when it captures live and the operator
/// gave no filter of their own.
///
/// # Arguments
///
/// * `lo` / `hi` — the SIP signalling port range (`--portrange`).
/// * `tunnel_ports` — UDP ports to take wholesale (see
///   [`TUNNEL_PORTS_DEFAULT`]); empty for the default, narrow filter.
///
/// # Returns
///
/// A `pcap_compile`-ready expression: a plain `portrange` for untagged
/// traffic, one encapsulated arm that pairs a link-aware protocol test with
/// every inner IP-header offset, plus one `udp port N` per requested tunnel
/// port.
///
/// # Why not `vlan` / `mpls` / `pppoes`
///
/// libpcap's encapsulation qualifiers look like the obvious answer and are
/// wrong here twice over.
///
/// They are **stateful**: the first one re-bases the decoding offsets for
/// everything to its right, cumulatively and across `or`. So the union a
/// reader expects — `portrange P or (vlan and portrange P) or (pppoes and
/// portrange P)` — compiles, runs, and matches ZERO PPPoE frames, because the
/// `vlan` on its left already moved the offsets 4 bytes. Measured: that
/// expression matches 0 of the 32 PPPoE SIP frames in `DTMFsipinfo.pcap`,
/// where `portrange P or (pppoes and portrange P)` matches all 32. Worse,
/// `mpls` followed by `pppoes` is not a wrong answer but a hard
/// `pcap_compile` error ("unsupported protocol over mpls").
///
/// They are also **not portable across link types**. `vlan` and `mpls` are
/// `pcap_compile` errors on `DLT_LINUX_SLL`/`SLL2` — the Linux `any`
/// pseudo-device, which is what sipnab opens when `-d` is omitted — and on
/// `DLT_RAW` (tun) and `DLT_NULL` (loopback): "no VLAN support for Linux
/// cooked v1". A filter that will not compile does not miss traffic, it stops
/// the capture from starting.
///
/// # Why `ether proto` outside and `ether[N:M]` inside
///
/// `ether proto N` carries no state, so it brings back neither defect, and
/// libpcap resolves it PER LINK TYPE while compiling. Measured with
/// `tcpdump -d` on a capture of each type: `ldh [12]` on Ethernet, `ldh [14]`
/// on Linux cooked v1, `ldh [0]` on Linux cooked v2, and a constant false on
/// raw-IP, `DLT_NULL` and `DLT_LOOP`, which have no protocol field to test.
/// That is exactly the "is this frame encapsulated" question, asked in the
/// only way that survives a change of link type.
///
/// The first version of these arms asked it with `ether[12:2]` instead. That
/// is the EtherType on Ethernet and two bytes of the zero-padded link-layer
/// address on a cooked capture, so the arms compiled, ran, and matched
/// nothing there: 1 of 11 encapsulated SIP frames on cooked v1 and v2 against
/// 11 of 11 on Ethernet. Cooked is what `sipnab` opens when no `-d` names an
/// interface, so that was the DEFAULT invocation.
///
/// `ether[N:M]` stays for the inner IP header, because there `ether proto`
/// has nothing to offer: it only ever tests the outermost protocol field. The
/// offsets are absolute from the start of the link-layer header, so the arm
/// has to name one per (link-header length, encapsulation depth) pair —
/// `LINK_HEADER_LENS` times `ENCAP_DEPTHS`, nine pairs and seven distinct
/// offsets.
///
/// # Coverage, and what it costs
///
/// On any of the three link types, the depths in `ENCAP_DEPTHS` are
/// covered: one VLAN tag (802.1Q / 802.1ad / 0x9100) or one MPLS label; QinQ,
/// PPPoE Session or two MPLS labels; and one VLAN tag over PPPoE Session.
/// Each offset covers IPv4 (no options, first fragment) and IPv6, UDP and TCP.
///
/// The cost of one filter string serving three link types is that four of the
/// seven offsets belong to a different link header than the one in front of
/// any given packet, and get probed anyway. Those probes can only ever fire
/// on a frame that ALREADY carries one of `ENCAP_ETHERTYPES`, and only if
/// its bytes at a wrong offset spell a whole IPv4-or-IPv6 header — right
/// version, UDP or TCP, zero fragment offset — with a port in the signalling
/// range. Ordinary traffic cannot reach the probes at all, which
/// `the_outer_link_type_test_keeps_untagged_traffic_out_of_the_encapsulated_arms`
/// pins with a datagram built to be mistaken for one.
///
/// Rejected alternative: three separate arm sets, each guarded so it can only
/// fire on its own link type. There is no guard to write. libpcap exposes
/// nothing that distinguishes cooked from Ethernet at compile time —
/// `inbound`/`outbound` come closest and are a `pcap_compile` ERROR on
/// Ethernet — and the data-level candidates (the zero padding in `sll_addr`,
/// the must-be-zero halfword in `sll2_header`) are only conventionally zero.
/// Guarding on one of those would put the cooked arms right back where they
/// started, inert and silent, which is the failure being fixed.
///
/// Rejected alternative: compile the filter after opening the device, when
/// the link type is known. `--multi-device` opens several interfaces under
/// one filter and they need not agree on a link type, and the filter is
/// logged for the operator to paste into `tcpdump`, where a device-specific
/// expression would be a trap.
pub fn auto_bpf_filter(lo: u16, hi: u16, tunnel_ports: &[u16]) -> String {
    let mut arms: Vec<String> = Vec::with_capacity(2 + tunnel_ports.len());

    // The untagged case stays a real libpcap portrange: it is the only arm
    // that gets IPv4 options, fragmentation and every link type right.
    arms.push(if lo == hi {
        format!("port {lo}")
    } else {
        format!("portrange {lo}-{hi}")
    });

    // Outer: "this frame is encapsulated", asked per link type by libpcap.
    let encapsulated = ENCAP_ETHERTYPES
        .iter()
        .map(|t| format!("ether proto {t:#06x}"))
        .collect::<Vec<_>>()
        .join(" or ");

    // Inner: one IP-and-ports test per distinct offset, so the expensive test
    // is emitted seven times rather than once per (link type, encapsulation).
    let mut offsets: Vec<usize> = LINK_HEADER_LENS
        .iter()
        .flat_map(|len| ENCAP_DEPTHS.iter().map(move |depth| len + depth))
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    let inner = offsets
        .iter()
        .map(|off| ip_and_ports_at(*off, lo, hi))
        .collect::<Vec<_>>()
        .join(" or ");

    arms.push(format!("(({encapsulated}) and ({inner}))"));

    // Opt-in only: these are not narrowing terms, they are the whole port.
    for port in tunnel_ports {
        arms.push(format!("udp port {port}"));
    }

    arms.join(" or ")
}

/// Resolve `--capture-tunnels` into the UDP ports to take wholesale.
///
/// # Returns
///
/// The requested ports in the order given, de-duplicated; empty when the flag
/// was not passed.
///
/// # Errors
///
/// Returns a `PlanError` (exit code 2) for an empty list or any element that
/// is not a port number in 1..=65535. Refused rather than skipped: a typo that
/// silently produced no coverage would leave the operator believing tunnelled
/// SIP was captured, which is the failure this flag exists to prevent.
fn resolve_tunnel_ports(cli: &Cli) -> Result<Vec<u16>, PlanError> {
    let Some(ref list) = cli.capture_tunnels else {
        return Ok(Vec::new());
    };
    let mut ports: Vec<u16> = Vec::new();
    let mut any = false;
    for field in list.split(',') {
        any = true;
        let text = field.trim();
        let port: u16 = text.parse().unwrap_or(0);
        if port == 0 {
            return Err(PlanError::arg(format!(
                "Invalid --capture-tunnels port '{text}': expected a \
                 comma-separated list of UDP ports in 1-65535, e.g. \
                 --capture-tunnels={TUNNEL_PORTS_DEFAULT_LIST}"
            )));
        }
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    if !any || ports.is_empty() {
        return Err(PlanError::arg(format!(
            "--capture-tunnels was given an empty port list; drop the flag, or \
             pass ports, e.g. --capture-tunnels={TUNNEL_PORTS_DEFAULT_LIST}"
        )));
    }
    Ok(ports)
}

/// The sentence the default live path owes the operator about what the
/// auto-generated filter does NOT cover, or `None` once it covers it.
///
/// The encapsulation arms are free — they match the same SIP, wrapped — so
/// they are always on. UDP tunnels are not free: BPF cannot parse a
/// variable-length GTP-U extension-header chain to reach the inner port, so
/// the only way to cover them is to capture the whole port, which on a mobile
/// core is the entire user plane. Leaving that off is the right default and
/// leaving it UNSAID is not: the operator would see "No SIP traffic found" on
/// a link carrying calls and have nothing to act on. That is the same failure
/// this change fixes, one level up.
fn tunnel_omission_notice(tunnel_ports: &[u16]) -> Option<String> {
    if !tunnel_ports.is_empty() {
        return None;
    }
    Some(format!(
        "The auto-generated filter covers SIP inside VLAN, QinQ, PPPoE and \
         MPLS, but NOT SIP inside a UDP tunnel (GTP-U 2152, VXLAN 4789, \
         GENEVE 6081) — BPF cannot reach the inner port, so covering those \
         means capturing every packet on the port. If this link carries \
         tunnelled signalling, add --capture-tunnels \
         (defaults to {TUNNEL_PORTS_DEFAULT_LIST}) and size the buffer for it."
    ))
}

/// The sentence an operator-supplied filter earns when it looks
/// encapsulation-blind, or `None` when it does not.
///
/// Their expression is handed to `pcap_compile` exactly as typed — silently
/// rewriting what someone asked for is worse than the blindness. But a bare
/// `port 5060` on a tagged link matches nothing, and that reads as "no calls"
/// rather than "wrong filter", so it is worth a sentence.
///
/// Deliberately narrow: it fires only when the filter has a port term and no
/// sign of encapsulation handling. A filter with no port term at all is
/// selecting on something else and gets nothing.
fn explicit_filter_encap_notice(filter: &str) -> Option<String> {
    let lower = filter.to_ascii_lowercase();
    if !lower.contains("port") {
        return None;
    }
    let already_aware = ["vlan", "mpls", "pppoes", "ether[", "link[", "radio["]
        .iter()
        .any(|token| lower.contains(token));
    if already_aware {
        return None;
    }
    Some(
        "Your BPF filter is used as given and was not modified. Note that a \
         port-based filter is matched against the outer headers only: it will \
         not see SIP inside a VLAN tag, QinQ, PPPoE or MPLS, and the packets \
         are dropped in the kernel where no sipnab counter can report them. \
         Drop the filter to get sipnab's encapsulation-aware one, or add \
         --capture-tunnels for UDP-tunnelled signalling."
            .to_string(),
    )
}

/// The message to log when `--cores N` was asked for on a run that cannot use
/// it, or `None` when the request will be honoured.
///
/// `--cores` selects offline parallel reconstruction: it shards a saved capture
/// by host pair and rebuilds dialogs per shard, which needs the whole file up
/// front. There is no equivalent for a stream still arriving, so a live source
/// (and `--multi-device`, which is live by definition) falls through to the
/// single-threaded path.
///
/// It used to fall through in silence. `sipnab --cores 8 -d eth0` parses, runs,
/// exits 0, and produces a correct capture on one core — the operator asked for
/// eight and nothing in the run says they did not get them. On a host chosen
/// for its core count that is a sizing decision made on a false premise.
///
/// Warned rather than refused, and that is the difference from the neighbouring
/// `--cores` + `--json`/`-O` check that exits 2. There the combination emits
/// *nothing* and still exits 0, so the output is a wrong answer and the only
/// safe response is to refuse. Here the output is complete and correct; only
/// the parallelism is missing. Refusing would break invocations that work today
/// (a wrapper script that passes `--cores` uniformly and sometimes points at a
/// device) to fix a problem that one sentence fixes.
fn cores_ignored_warning(cli: &Cli) -> Option<String> {
    if cli.cores <= 1 {
        return None;
    }
    let reason = if cli.multi_device {
        "--multi-device opens one capture per interface"
    } else if !cli.has_input() {
        "this run captures live rather than reading a saved file"
    } else {
        // `--cores N -I file` without --multi-device: honoured, say nothing.
        return None;
    };
    Some(format!(
        "--cores {n} is ignored here: {reason}, and parallel reconstruction is \
         offline-only — it shards a capture FILE by host pair, which needs the \
         whole capture up front. This run continues on ONE core; its output is \
         complete, just slower. Point --cores at a saved capture \
         (-I/--input <file>, without --multi-device) to actually use {n} of them.",
        n = cli.cores,
    ))
}

/// `--metrics` alongside the parallel offline path, which never serves it.
///
/// The last place `--metrics` is still inert. `batch::run` returns from the
/// `--cores N` branch before `BatchRunner::new` is reached, and the runner is
/// what starts the metrics server — so `sipnab -N --cores 4 -I capture.pcap
/// --metrics 127.0.0.1:9090` parses the address, validates it, refuses a bad
/// bind, and listens on nothing. Exactly the shape this ticket removed from the
/// ordinary headless path.
///
/// Warned rather than refused, on the same reasoning as
/// [`cores_ignored_warning`]: the analysis is complete and correct, and only
/// the endpoint is missing. It is also the combination least worth
/// implementing — a parallel offline run finishes in seconds and exits, so
/// there is no steady state for a scraper to sample even if it did bind.
///
/// Returns the message rather than logging it, so it can be asserted on.
#[cfg(feature = "metrics")]
fn metrics_ignored_on_cores_warning(cli: &Cli) -> Option<String> {
    if cli.metrics.is_none() || !(cli.cores > 1 && cli.has_input() && !cli.multi_device) {
        return None;
    }
    Some(format!(
        "--metrics is ignored with --cores {n}: the parallel offline reader \
         shards, merges and exits without starting the metrics server, so \
         nothing would answer a scrape. Drop --cores to serve metrics from \
         this run; a parallel offline run is too short to scrape in any case.",
        n = cli.cores,
    ))
}

/// A truncating `--snaplen` on a live capture that also writes `-O`.
///
/// `--snaplen N` tells the kernel to copy only the first N bytes of each frame;
/// below the 65535-byte default, any larger packet is captured truncated
/// (`caplen < origlen`). sipnab's own analysis is unaffected — it parses what it
/// captured — but `-O` re-emits those truncated frames, and a truncated pcap is
/// structurally a valid one: a later reader cannot tell payload dropped at
/// capture from payload that was never on the wire. That is the same silent
/// data-loss class as an `-O` file truncated by `ENOSPC`, so it is said out
/// loud rather than left to be discovered downstream.
///
/// Live only: a saved-file reader (`-I`) copies whole records, so `--snaplen`
/// never shortens a file read. Returns the message rather than logging it, so
/// it can be asserted on, matching [`cores_ignored_warning`].
fn snaplen_truncation_warning(cli: &Cli, config: &Config) -> Option<String> {
    let snaplen = cli.snaplen.or(config.capture.snaplen).unwrap_or(65535);
    // `has_input()` is a saved-file read, where snaplen does not truncate; no
    // `-O`, nothing is re-emitted; the full default keeps whole frames.
    if snaplen >= 65535 || cli.output.is_none() || cli.has_input() {
        return None;
    }
    Some(format!(
        "--snaplen {snaplen} truncates each captured frame to {snaplen} bytes, \
         and -O writes those truncated frames: the pcap will drop every byte \
         past {snaplen} in any larger packet, with nothing in the file to mark \
         it as short. sipnab's own analysis is unaffected. Remove --snaplen (the \
         default 65535 keeps whole frames) if the -O capture must be complete."
    ))
}

/// A truncating `--snaplen` on a live capture with `--retain-audio` armed.
///
/// `--snaplen N` tells the kernel to copy only the first N bytes of each
/// frame. Unlike [`snaplen_truncation_warning`]'s `-O` case, sipnab's *own*
/// analysis is affected here: `--retain-audio` buffers RTP payload bytes for
/// the `export_audio` MCP tool to decode later, and a snaplen sized for
/// signalling (CT3's own guidance is 200-400 bytes for SIP headers) truncates
/// that payload before it ever reaches the retention buffer. The exported WAV
/// or Opus audio is then short or corrupted for exactly the packets that were
/// truncated, with nothing marking which frames those were — the same silent
/// class as the `-O` case, but landing in a decoded artifact instead of a
/// re-emitted pcap.
///
/// Live only: a saved-file reader (`-I`) copies whole records, so `--snaplen`
/// never shortens a file read. Returns the message rather than logging it,
/// matching [`snaplen_truncation_warning`].
fn snaplen_audio_retention_warning(cli: &Cli, config: &Config) -> Option<String> {
    let snaplen = cli.snaplen.or(config.capture.snaplen).unwrap_or(65535);
    if snaplen >= 65535 || !audio_retention_wanted(cli) || cli.has_input() {
        return None;
    }
    Some(format!(
        "--snaplen {snaplen} truncates each captured frame to {snaplen} bytes, \
         and --retain-audio buffers what the kernel handed it: any RTP packet \
         whose header and payload extend past {snaplen} bytes is retained \
         truncated, so audio exported later through export_audio will be short \
         or corrupted for those packets. Remove --snaplen (the default 65535 \
         keeps whole frames) if retained audio must be complete."
    ))
}

// ── Auth / token helpers ───────────────────────────────────────────

/// Mint a signed token from the CLI configuration and return it. Picks the
/// surface (API vs MCP) based on which signing keys are configured
/// (API keys preferred). The caller (`run_mint_token`) prints the token and
/// turns the result into an exit code.
///
/// # Errors
///
/// Returns an error message string when no signing key is configured on
/// either surface or the token TTL is non-positive.
///
/// # Side effects
///
/// Resolving the verifier configs may read signing-key files from disk
/// (and exit the process when one is unreadable — see
/// `crate::app::servers::read_signing_key_file`).
#[cfg(any(feature = "api", feature = "mcp"))]
fn mint_token(cli: &Cli) -> Result<String, String> {
    // Gather the first signing key + TTL, preferring API config, then MCP.
    #[allow(unused_mut)]
    let mut first_key: Option<Vec<u8>> = None;
    #[allow(unused_mut)]
    let mut ttl: i64 = 3600;
    // The minted token is bound to whichever surface supplied the signing key,
    // so a token minted from --api-signing-key is rejected by HTTP MCP (and
    // vice versa) even when both surfaces share one secret.
    #[allow(unused_mut)]
    let mut audience: &str = crate::auth::AUDIENCE_API;

    #[cfg(feature = "api")]
    {
        if cli.api_signing_key_file.is_some() || !cli.api_signing_key.is_empty() {
            let cfg = crate::app::servers::resolve_api_verifier_config(cli);
            first_key = cfg.signing_keys.into_iter().next();
            ttl = cli.api_token_ttl;
            audience = crate::auth::AUDIENCE_API;
        }
    }
    #[cfg(feature = "mcp")]
    if first_key.is_none()
        && (cli.mcp_signing_key_file.is_some() || !cli.mcp_signing_key.is_empty())
    {
        let cfg = crate::app::servers::resolve_mcp_verifier_config(cli);
        first_key = cfg.signing_keys.into_iter().next();
        ttl = cli.mcp_token_ttl;
        audience = crate::auth::AUDIENCE_MCP;
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

    // Each narrow scope names something that exists on exactly one surface,
    // so a cross-surface mint is rejected rather than minting a token that
    // could never authorize what its scope names.
    //
    // MCP has no metrics surface: a scrape-only MCP token would name a route
    // that does not exist there.
    if cli.token_scope == crate::auth::SCOPE_METRICS && audience == crate::auth::AUDIENCE_MCP {
        return Err(
            "--token-scope metrics applies to the REST API only; the MCP surface has no \
             /metrics endpoint"
                .to_string(),
        );
    }
    // And the REST API has no read-only scope: its routes are one trust
    // domain apart from /metrics, so a `read` API token would verify and then
    // be refused by every scope check — worse than failing at mint time,
    // because the operator would ship it before learning it opens nothing.
    if cli.token_scope == crate::auth::SCOPE_READ && audience == crate::auth::AUDIENCE_API {
        return Err(
            "--token-scope read applies to the MCP surface only; the REST API has no \
             read-only scope — use `full`, or `metrics` for a scrape-only token"
                .to_string(),
        );
    }

    Ok(crate::auth::mint(
        &key,
        &id,
        exp,
        audience,
        &cli.token_scope,
    ))
}

// ── Unit tests for the binary's pure helpers ────────────────────────────
//
// These cover the stand-alone bootstrap logic that needs no live capture
// device: the argument parsers and the filter/capture-config builders. The
// batch runner's tests live in `crate::app::batch`; the live-capture / TUI
// arms stay integration-only.
/// Unit tests for the pure planning helpers (parsers and builders).
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

    /// Well-formed ranges parse, whitespace is trimmed, start==end allowed.
    #[test]
    fn parse_portrange_valid_and_trimmed() {
        assert_eq!(parse_portrange("5060-5061").unwrap(), (5060, 5061));
        // surrounding whitespace is trimmed on each side
        assert_eq!(parse_portrange(" 100 - 200 ").unwrap(), (100, 200));
        // single-port range (start == end) is allowed
        assert_eq!(parse_portrange("5060-5060").unwrap(), (5060, 5060));
    }

    /// Malformed shapes, non-numeric or out-of-range ports, and start > end
    /// all produce errors.
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

    /// `duration:N` yields a Duration; `filesize:N` yields a megabyte count.
    #[test]
    fn parse_autostop_duration_and_filesize() {
        let (dur, size) = parse_autostop("duration:30").unwrap();
        assert_eq!(dur, Some(std::time::Duration::from_secs(30)));
        assert_eq!(size, None);

        let (dur, size) = parse_autostop("filesize:100").unwrap();
        assert_eq!(dur, None);
        assert_eq!(size, Some(100));
    }

    /// Missing colon, non-numeric value, and unknown key are rejected.
    #[test]
    fn parse_autostop_errors() {
        assert!(parse_autostop("duration").is_err()); // missing ':'
        assert!(parse_autostop("duration:notanumber").is_err());
        assert!(parse_autostop("unknown:10").is_err()); // unknown key
    }

    // ── build_filter_expr ──────────────────────────────────────────────

    /// An explicit `--filter` expression compiles into a filter.
    #[test]
    fn build_filter_expr_explicit_flag_wins() {
        let mut cli = base_cli();
        cli.filter = Some("retransmits > 0".to_string());
        let config = Config::default();
        assert!(build_filter_expr(&cli, &config).unwrap().is_some());
    }

    /// A malformed `--filter` expression yields an `Err` (exit code 2),
    /// NOT a process exit — so `plan()` stays testable and composable.
    #[test]
    fn build_filter_expr_invalid_filter_returns_err() {
        let mut cli = base_cli();
        // `from.user ==` is the documented invalid-DSL example.
        cli.filter = Some("from.user ==".to_string());
        let err = build_filter_expr(&cli, &Config::default())
            .expect_err("a malformed --filter must return Err, not exit");
        assert_eq!(err.exit_code, 2);
        assert!(
            err.message.contains("Invalid --filter expression"),
            "got: {}",
            err.message
        );
    }

    /// A malformed config-file filter expression yields an `Err`, not an exit.
    #[test]
    fn build_filter_expr_invalid_config_expr_returns_err() {
        let mut config = Config::default();
        config.filter.expression = Some("from.user ==".to_string());
        let err = build_filter_expr(&base_cli(), &config)
            .expect_err("a malformed config filter must return Err, not exit");
        assert_eq!(err.exit_code, 2);
        assert!(
            err.message.contains("Invalid config filter expression"),
            "got: {}",
            err.message
        );
    }

    /// Each diagnostic alias flag builds a filter; multiple flags OR together.
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
            assert!(build_filter_expr(&cli, &config).unwrap().is_some());
        }
        // Multiple flags combine with OR.
        let mut cli = base_cli();
        cli.problems = true;
        cli.one_way = true;
        assert!(build_filter_expr(&cli, &config).unwrap().is_some());
    }

    /// No sources → `None`; a config-file expression is the fallback source.
    #[test]
    fn build_filter_expr_config_fallback_and_none() {
        // No flags, no config -> None.
        assert!(
            build_filter_expr(&base_cli(), &Config::default())
                .unwrap()
                .is_none()
        );

        // Config fallback expression is used when no CLI flag is set.
        let mut config = Config::default();
        config.filter.expression = Some("retransmits > 0".to_string());
        assert!(build_filter_expr(&base_cli(), &config).unwrap().is_some());
    }

    // ── build_capture_config ───────────────────────────────────────────

    /// With no flags or config, the hard-coded capture defaults apply.
    #[test]
    fn build_capture_config_defaults() {
        let cc = build_capture_config(&base_cli(), &Config::default()).unwrap();
        assert_eq!(cc.snaplen, 65535);
        assert_eq!(cc.buffer_mb, crate::capture::DEFAULT_BUFFER_MB);
        assert_eq!(cc.bpf_filter, None);
        assert_eq!(cc.count, None);
        assert_eq!(cc.duration, None);
        assert!(!cc.replay);
    }

    /// Promiscuous mode defaults to on.
    #[test]
    fn build_capture_config_promisc_default_on() {
        let cc = build_capture_config(&base_cli(), &Config::default()).unwrap();
        assert!(cc.promisc, "promiscuous mode should default to on");
    }

    /// `--no-promisc` disables promiscuous mode.
    #[test]
    fn build_capture_config_no_promisc_flag_disables() {
        let mut cli = base_cli();
        cli.no_promisc = true;
        let cc = build_capture_config(&cli, &Config::default()).unwrap();
        assert!(!cc.promisc, "--no-promisc should disable promiscuous mode");
    }

    /// `[capture] promisc = false` is honored when the CLI flag is unset.
    #[test]
    fn build_capture_config_promisc_config_fallback() {
        let mut config = Config::default();
        config.capture.promisc = Some(false);
        // CLI leaves --no-promisc unset -> config value wins.
        let cc = build_capture_config(&base_cli(), &config).unwrap();
        assert!(
            !cc.promisc,
            "[capture] promisc=false should disable promisc"
        );
    }

    /// `--no-promisc` wins over `[capture] promisc = true`.
    #[test]
    fn build_capture_config_no_promisc_flag_overrides_config() {
        let mut config = Config::default();
        config.capture.promisc = Some(true);
        let mut cli = base_cli();
        cli.no_promisc = true;
        let cc = build_capture_config(&cli, &config).unwrap();
        assert!(
            !cc.promisc,
            "--no-promisc must override [capture] promisc=true"
        );
    }

    /// CLI snaplen/buffer/count/replay/positional-BPF override the defaults.
    #[test]
    fn build_capture_config_cli_overrides() {
        let mut cli = base_cli();
        cli.snaplen = Some(1500);
        cli.buffer = Some(8);
        cli.count = Some(42);
        cli.replay = true;
        cli.bpf_filter = vec!["udp".to_string(), "port".to_string(), "5060".to_string()];
        let cc = build_capture_config(&cli, &Config::default()).unwrap();
        assert_eq!(cc.snaplen, 1500);
        assert_eq!(cc.buffer_mb, 8);
        assert_eq!(cc.count, Some(42));
        assert!(cc.replay);
        assert_eq!(cc.bpf_filter.as_deref(), Some("udp port 5060"));
    }

    /// `--bpf-file` contents (trimmed) win over a positional BPF filter.
    #[test]
    fn build_capture_config_bpf_file_takes_precedence() {
        let dir = std::env::temp_dir();
        let path = dir.join("sipnab_test_bpf_filter.txt");
        std::fs::write(&path, "  udp and port 5060\n").unwrap();
        let mut cli = base_cli();
        cli.bpf_file = Some(path.to_string_lossy().into_owned());
        // positional filter present but --bpf-file wins
        cli.bpf_filter = vec!["tcp".to_string()];
        let cc = build_capture_config(&cli, &Config::default()).unwrap();
        assert_eq!(cc.bpf_filter.as_deref(), Some("udp and port 5060"));
        let _ = std::fs::remove_file(&path);
    }

    /// Config-file snaplen/buffer values apply when the CLI leaves them unset.
    #[test]
    fn build_capture_config_config_fallback() {
        let mut config = Config::default();
        config.capture.snaplen = Some(256);
        config.capture.buffer = Some(16);
        // CLI leaves snaplen/buffer unset -> config values used.
        let cc = build_capture_config(&base_cli(), &config).unwrap();
        assert_eq!(cc.snaplen, 256);
        assert_eq!(cc.buffer_mb, 16);
    }

    /// A malformed `--duration` yields an `Err` (exit code 2), not a process
    /// exit — the plan must stay composable and testable.
    #[test]
    fn build_capture_config_bad_duration_returns_err() {
        let mut cli = base_cli();
        cli.duration = Some("abc".to_string());
        let err = build_capture_config(&cli, &Config::default())
            .expect_err("a malformed --duration must return Err, not exit");
        assert_eq!(err.exit_code, 2);
        assert!(
            err.message.contains("Invalid --duration"),
            "got: {}",
            err.message
        );
    }

    // ── immediate mode / ring format (CT7) ─────────────────────────────
    //
    // No live interface is available in a test run, so what is asserted is the
    // decision — which run mode gets immediate delivery, and that `plan` puts
    // that answer on the config the capture thread receives. Whether TPACKET_V3
    // is then actually selected is libpcap's side of the contract and needs a
    // real NIC to observe.

    /// Only the interactive TUI keeps immediate mode; every headless mode
    /// trades it for TPACKET_V3's snaplen-independent ring.
    #[test]
    fn immediate_mode_is_the_tui_and_nothing_else() {
        assert!(immediate_mode_for(&RunMode::Tui));
        assert!(!immediate_mode_for(&RunMode::Batch));
        assert!(!immediate_mode_for(&RunMode::CoresFile));
    }

    /// A headless live capture (`-N -d ...`) must reach the capture thread with
    /// immediate mode OFF — the whole point of the change, since that is what
    /// lets libpcap choose TPACKET_V3.
    #[test]
    fn plan_turns_immediate_mode_off_for_headless_capture() {
        let mut cli = base_cli(); // -N
        cli.device = Some("eth0".to_string());
        let p = plan(&cli, &Config::default()).expect("plan must succeed");
        assert!(matches!(p.mode, RunMode::Batch));
        assert!(
            !p.capture_config.immediate_mode,
            "a headless capture must let libpcap pick TPACKET_V3"
        );
    }

    /// The TUI keeps immediate mode: a person is watching messages land, and a
    /// packet held back until its ring block retires is what makes an
    /// interactive tool feel broken.
    #[cfg(feature = "tui")]
    #[test]
    fn plan_keeps_immediate_mode_for_the_tui() {
        let mut cli = Cli::parse_from_args(["sipnab"]); // no -N: interactive
        cli.device = Some("eth0".to_string());
        let p = plan(&cli, &Config::default()).expect("plan must succeed");
        assert!(matches!(p.mode, RunMode::Tui));
        assert!(
            p.capture_config.immediate_mode,
            "the interactive path must keep per-packet delivery"
        );
    }

    /// Whatever the feature set, the flag on the plan always agrees with the
    /// mode on the plan — the two can never drift apart.
    #[test]
    fn plan_immediate_mode_always_matches_the_run_mode() {
        for headless in [true, false] {
            let mut cli = Cli::parse_from_args(["sipnab"]);
            cli.no_tui = headless;
            cli.device = Some("eth0".to_string());
            let p = plan(&cli, &Config::default()).expect("plan must succeed");
            assert_eq!(
                p.capture_config.immediate_mode,
                matches!(p.mode, RunMode::Tui),
                "immediate mode must follow the run mode exactly (headless={headless})"
            );
        }
    }

    // ── --cores on a source that cannot use it (G6) ────────────────────

    /// The honoured case says nothing: `--cores N -I file` is exactly what the
    /// parallel reader is for.
    #[test]
    fn cores_warning_silent_when_cores_are_actually_used() {
        let mut cli = base_cli();
        cli.cores = 8;
        cli.input = vec!["capture.pcap".to_string()];
        assert!(cores_ignored_warning(&cli).is_none());
    }

    /// `--cores 1` is the default and means nothing was asked for, on any
    /// source — warning about it would be noise on every live run.
    #[test]
    fn cores_warning_silent_at_the_default_core_count() {
        let mut cli = base_cli();
        cli.cores = 1;
        cli.device = Some("eth0".to_string());
        assert!(cores_ignored_warning(&cli).is_none());
        cli.multi_device = true;
        assert!(cores_ignored_warning(&cli).is_none());
    }

    /// The defect: `--cores 8 -d eth0` used to run single-threaded in silence.
    /// The warning must name the count that was discarded and the flag that
    /// would honour it.
    #[test]
    fn cores_warning_fires_on_a_live_device() {
        let mut cli = base_cli();
        cli.cores = 8;
        cli.device = Some("eth0".to_string());
        let msg = cores_ignored_warning(&cli).expect("--cores on a live device must be reported");
        assert!(msg.contains("--cores 8"), "names the request: {msg}");
        assert!(msg.contains("-I"), "names the flag that works: {msg}");
        assert!(
            msg.contains("ONE core"),
            "says what actually happens: {msg}"
        );
    }

    /// No source at all is still a live run — the device is auto-detected —
    /// so `--cores` is ignored there too and must say so.
    #[test]
    fn cores_warning_fires_on_auto_detected_capture() {
        let mut cli = base_cli();
        cli.cores = 4;
        assert!(cores_ignored_warning(&cli).is_some());
    }

    /// `--multi-device` bypasses the parallel reader even with `-I` present,
    /// because the run-mode test excludes it. A warning that keyed only on
    /// "no input" would miss this and leave the same silence behind.
    #[test]
    fn cores_warning_fires_on_multi_device_even_with_input() {
        let mut cli = base_cli();
        cli.cores = 4;
        cli.input = vec!["capture.pcap".to_string()];
        cli.multi_device = true;
        let msg = cores_ignored_warning(&cli).expect("--multi-device must be reported");
        assert!(msg.contains("--multi-device"), "got: {msg}");
    }

    /// The warning fires exactly when the run mode is NOT `CoresFile`, for
    /// every combination of the two inputs that decide it. Pinning the
    /// complement is what stops the two conditions drifting apart later.
    #[test]
    fn cores_warning_is_the_exact_complement_of_the_parallel_path() {
        for (has_input, multi_device) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut cli = base_cli();
            cli.cores = 4;
            cli.multi_device = multi_device;
            if has_input {
                cli.input = vec!["capture.pcap".to_string()];
            } else {
                cli.device = Some("eth0".to_string());
            }
            let takes_parallel_path = cli.cores > 1 && cli.has_input() && !cli.multi_device;
            assert_eq!(
                cores_ignored_warning(&cli).is_none(),
                takes_parallel_path,
                "input={has_input} multi_device={multi_device}: the warning must \
                 cover every case the parallel path does not"
            );
        }
    }

    /// `--metrics` with `--cores N -I file` must say it will not be served.
    ///
    /// The combination is the last one where the flag is inert, and an inert
    /// metrics flag is invisible: the address parses, a bad bind is still
    /// refused, and the only symptom is a dashboard that never fills in.
    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_warns_when_the_parallel_path_will_not_serve_it() {
        let mut cli = base_cli();
        cli.cores = 4;
        cli.input = vec!["capture.pcap".to_string()];
        cli.metrics = Some("127.0.0.1:9090".to_string());
        let msg = metrics_ignored_on_cores_warning(&cli)
            .expect("--metrics on the parallel path must be reported");
        assert!(
            msg.contains("--metrics") && msg.contains("--cores"),
            "the warning must name both flags so the operator knows what to \
             drop: {msg}"
        );
    }

    /// Silent whenever the endpoint WILL be served, or was never asked for.
    ///
    /// The complement matters as much as the warning: a metrics flag that
    /// warns on a run which then serves metrics teaches operators to ignore
    /// it, and an ignored warning is the same as no warning.
    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_warning_is_silent_wherever_metrics_are_actually_served() {
        // Asked for, and the single-threaded headless path serves it.
        let mut served = base_cli();
        served.input = vec!["capture.pcap".to_string()];
        served.metrics = Some("127.0.0.1:9090".to_string());
        assert!(
            metrics_ignored_on_cores_warning(&served).is_none(),
            "--cores 1 serves metrics; warning here would be false"
        );

        // Parallel path, but no metrics were requested.
        let mut unasked = base_cli();
        unasked.cores = 4;
        unasked.input = vec!["capture.pcap".to_string()];
        assert!(
            metrics_ignored_on_cores_warning(&unasked).is_none(),
            "nothing was asked for, so nothing is being ignored"
        );

        // `--cores` present but NOT taken (live device): that run is
        // single-threaded and does serve metrics.
        let mut live = base_cli();
        live.cores = 4;
        live.device = Some("eth0".to_string());
        live.metrics = Some("127.0.0.1:9090".to_string());
        assert!(
            metrics_ignored_on_cores_warning(&live).is_none(),
            "a live run falls back to one core and starts the metrics server"
        );
    }

    // ── truncating --snaplen feeding -O (CT3) ──────────────────────────

    /// The defect: a truncating `--snaplen` on a live capture writes a short
    /// pcap through `-O` with nothing in the file to mark it short. The warning
    /// must name the snaplen, the `-O` output it feeds, and that the analysis
    /// itself is intact — only the re-emitted file is truncated.
    #[test]
    fn snaplen_truncation_warning_fires_on_live_capture_writing_output() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.snaplen = Some(262);
        cli.output = Some("out.pcap".to_string());
        let msg = snaplen_truncation_warning(&cli, &Config::default())
            .expect("a truncating snaplen feeding -O must be reported");
        assert!(msg.contains("262"), "names the snaplen: {msg}");
        assert!(msg.contains("-O"), "names the output it feeds: {msg}");
        assert!(
            msg.contains("analysis is unaffected"),
            "says the analysis is intact, only the file is short: {msg}"
        );
    }

    /// A small snaplen with no `-O` truncates only the in-memory capture, which
    /// is the point of setting it — nothing is written, so there is nothing to
    /// warn about. A warning here would fire on every deliberate signalling
    /// capture and train operators to ignore it.
    #[test]
    fn snaplen_truncation_warning_silent_without_output() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.snaplen = Some(262);
        assert!(snaplen_truncation_warning(&cli, &Config::default()).is_none());
    }

    /// The full-frame default keeps whole packets, so `-O` writes a complete
    /// pcap: neither the unset default nor an explicit 65535 truncates.
    #[test]
    fn snaplen_truncation_warning_silent_at_the_full_frame_default() {
        let mut unset = base_cli();
        unset.device = Some("eth0".to_string());
        unset.output = Some("out.pcap".to_string());
        assert!(
            snaplen_truncation_warning(&unset, &Config::default()).is_none(),
            "the unset default is 65535 — whole frames"
        );
        unset.snaplen = Some(65535);
        assert!(
            snaplen_truncation_warning(&unset, &Config::default()).is_none(),
            "an explicit 65535 truncates nothing"
        );
    }

    /// A saved-file read (`-I`) copies whole records; `--snaplen` never shortens
    /// it, so re-emitting through `-O` loses nothing and the warning stays
    /// silent even with a small snaplen present.
    #[test]
    fn snaplen_truncation_warning_silent_on_file_input() {
        let mut cli = base_cli();
        cli.input = vec!["capture.pcap".to_string()];
        cli.snaplen = Some(262);
        cli.output = Some("out.pcap".to_string());
        assert!(snaplen_truncation_warning(&cli, &Config::default()).is_none());
    }

    /// The snaplen resolves from the config file too, so a small
    /// `[capture] snaplen` with `-O` on a live source is caught even when the
    /// CLI flag is absent — the truncation is the same whichever set it.
    #[test]
    fn snaplen_truncation_warning_catches_a_config_file_snaplen() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.output = Some("out.pcap".to_string());
        let mut config = Config::default();
        config.capture.snaplen = Some(320);
        let msg = snaplen_truncation_warning(&cli, &config)
            .expect("a config-file snaplen truncates just as a CLI one does");
        assert!(msg.contains("320"), "names the resolved snaplen: {msg}");
    }

    // ── truncating --snaplen feeding --retain-audio (CT3) ───────────────

    /// The defect: a truncating `--snaplen` on a live capture with
    /// `--retain-audio` armed retains truncated RTP payload with nothing
    /// marking it short. Unlike the `-O` warning, this one must say the
    /// analysis itself (the exported audio) is affected, not intact.
    #[test]
    fn snaplen_audio_retention_warning_fires_on_live_capture_with_retain_audio() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.snaplen = Some(262);
        cli.mcp = true;
        cli.retain_audio = true;
        let msg = snaplen_audio_retention_warning(&cli, &Config::default())
            .expect("a truncating snaplen feeding retained audio must be reported");
        assert!(msg.contains("262"), "names the snaplen: {msg}");
        assert!(
            msg.contains("export_audio"),
            "names the tool the truncation reaches: {msg}"
        );
        assert!(
            msg.contains("retain-audio"),
            "names the flag that arms retention: {msg}"
        );
    }

    /// A small snaplen with no `--retain-audio` never buffers RTP payload, so
    /// there is nothing retained to corrupt — silent, matching the `-O`
    /// warning's silence when nothing is written.
    #[test]
    fn snaplen_audio_retention_warning_silent_without_retain_audio() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.snaplen = Some(262);
        assert!(snaplen_audio_retention_warning(&cli, &Config::default()).is_none());
    }

    /// The full-frame default keeps whole packets, so retained RTP payload is
    /// always complete: neither the unset default nor an explicit 65535
    /// truncates.
    #[test]
    fn snaplen_audio_retention_warning_silent_at_the_full_frame_default() {
        let mut unset = base_cli();
        unset.device = Some("eth0".to_string());
        unset.mcp = true;
        unset.retain_audio = true;
        assert!(
            snaplen_audio_retention_warning(&unset, &Config::default()).is_none(),
            "the unset default is 65535 — whole frames"
        );
        unset.snaplen = Some(65535);
        assert!(
            snaplen_audio_retention_warning(&unset, &Config::default()).is_none(),
            "an explicit 65535 truncates nothing"
        );
    }

    /// A saved-file read (`-I`) copies whole records; `--snaplen` never
    /// shortens it, so retained RTP payload is complete even with a small
    /// snaplen present.
    #[test]
    fn snaplen_audio_retention_warning_silent_on_file_input() {
        let mut cli = base_cli();
        cli.input = vec!["capture.pcap".to_string()];
        cli.snaplen = Some(262);
        cli.mcp = true;
        cli.retain_audio = true;
        assert!(snaplen_audio_retention_warning(&cli, &Config::default()).is_none());
    }

    /// The snaplen resolves from the config file too, so a small
    /// `[capture] snaplen` with `--retain-audio` on a live source is caught
    /// even when the CLI flag is absent — the truncation is the same
    /// whichever set it.
    #[test]
    fn snaplen_audio_retention_warning_catches_a_config_file_snaplen() {
        let mut cli = base_cli();
        cli.device = Some("eth0".to_string());
        cli.mcp = true;
        cli.retain_audio = true;
        let mut config = Config::default();
        config.capture.snaplen = Some(320);
        let msg = snaplen_audio_retention_warning(&cli, &config)
            .expect("a config-file snaplen truncates just as a CLI one does");
        assert!(msg.contains("320"), "names the resolved snaplen: {msg}");
    }

    /// An unreadable `--bpf-file` yields an `Err` (exit code 2), not an exit.
    #[test]
    fn build_capture_config_unreadable_bpf_file_returns_err() {
        let mut cli = base_cli();
        cli.bpf_file = Some(
            std::env::temp_dir()
                .join("sipnab_no_such_bpf_file_xyzzy.txt")
                .to_string_lossy()
                .into_owned(),
        );
        let err = build_capture_config(&cli, &Config::default())
            .expect_err("an unreadable --bpf-file must return Err, not exit");
        assert_eq!(err.exit_code, 2);
        assert!(
            err.message.contains("Failed to read BPF filter file"),
            "got: {}",
            err.message
        );
    }

    // ── Encapsulation-aware auto BPF filter ────────────────────────────
    //
    // Every count below was first measured with tcpdump 4.99.4 / libpcap
    // 1.10.4 against the same bytes these tests build, and the assertions
    // pin those measurements. `> 0` would pass against a filter that
    // matched the whole link.

    /// `DLT_NULL` — BSD loopback.
    const DLT_NULL: u32 = 0;
    /// `DLT_EN10MB` — Ethernet.
    const DLT_EN10MB: u32 = 1;
    /// `DLT_RAW` — bare IP, as written into a pcap file (tun devices).
    const DLT_RAW: u32 = 101;
    /// `DLT_LOOP` — OpenBSD loopback; `DLT_NULL` with a big-endian AF word.
    const DLT_LOOP: u32 = 108;
    /// `DLT_LINUX_SLL` — the Linux cooked header the `any` device used to use.
    const DLT_LINUX_SLL: u32 = 113;
    /// `DLT_LINUX_SLL2` — the cooked header the `any` device uses today.
    const DLT_LINUX_SLL2: u32 = 276;

    /// A SIP body small enough to keep every fixture frame in one datagram.
    const SIP_BODY: &[u8] = b"OPTIONS sip:probe@example.com SIP/2.0\r\n\r\n";

    /// Write `frames` as a little-endian classic pcap file with `linktype`.
    ///
    /// Hand-rolled rather than pulled from a crate so the fixtures are exactly
    /// the bytes the assertions describe — the whole point here is that the
    /// kernel filter sees a known frame layout.
    fn write_pcap(path: &std::path::Path, linktype: u32, frames: &[Vec<u8>]) {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&linktype.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            out.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        std::fs::write(path, out).expect("write fixture pcap");
    }

    /// IPv4 (IHL 5, DF, no options) + UDP carrying `payload`.
    ///
    /// The flags/fragment word is `0x4000` on purpose: Don't-Fragment set with
    /// a zero offset, so it exercises the filter's `& 0x1fff = 0` mask instead
    /// of passing it trivially.
    fn ipv4_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut v: Vec<u8> = vec![0x45, 0x00];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x2a, 0x40, 0x00, 64, 17, 0x00, 0x00]);
        v.extend_from_slice(&[192, 0, 2, 1]);
        v.extend_from_slice(&[198, 51, 100, 1]);
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&(udp_len as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    /// IPv6 (no extension headers) + UDP carrying `payload`.
    fn ipv6_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut v: Vec<u8> = vec![0x60, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(udp_len as u16).to_be_bytes());
        v.extend_from_slice(&[17, 64]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&(udp_len as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(payload);
        v
    }

    /// A 14-byte Ethernet header (RFC 7042 documentation MACs) with `ethertype`.
    fn eth(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = vec![
            0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x02,
        ];
        v.extend_from_slice(&ethertype.to_be_bytes());
        v
    }

    /// A 16-byte `DLT_LINUX_SLL` header carrying `ethertype`.
    ///
    /// Field order is `struct sll_header` from libpcap's `pcap/sll.h`: packet
    /// type, hardware type, address length, an 8-byte address field, and the
    /// protocol LAST, at offset 14. The prose above that struct lists the
    /// fields in a different order and is wrong; the struct is what libpcap
    /// writes and what `pcap_compile` indexes.
    fn sll(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x06];
        v.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v
    }

    /// A 20-byte `DLT_LINUX_SLL2` header carrying `ethertype`.
    ///
    /// `struct sll2_header` puts the protocol FIRST, at offset 0, then a
    /// must-be-zero halfword, a 4-byte interface index, hardware type, packet
    /// type, address length and an 8-byte address.
    fn sll2(ethertype: u16) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(20);
        v.extend_from_slice(&ethertype.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x06]);
        v.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01, 0x00, 0x00]);
        v
    }

    /// Builds a link-layer header announcing the protocol it is given.
    type LinkHeader = fn(u16) -> Vec<u8>;

    /// The link-layer headers a live capture can put in front of SIP, each
    /// paired with the pcap link type that names it.
    ///
    /// Ethernet, Linux cooked v1 and Linux cooked v2 are the three that carry
    /// a protocol field, so they are the three the encapsulated arms have to
    /// cover. `sipnab` opens cooked when no `-d` names an interface on Linux,
    /// which makes the second and third entries the DEFAULT invocation.
    const LINK_HEADERS: &[(&str, u32, LinkHeader)] = &[
        ("Ethernet", DLT_EN10MB, eth as LinkHeader),
        ("Linux cooked v1", DLT_LINUX_SLL, sll as LinkHeader),
        ("Linux cooked v2", DLT_LINUX_SLL2, sll2 as LinkHeader),
    ];

    /// A 4-byte 802.1Q/802.1ad tag body: TCI followed by the next EtherType.
    fn tag(vid: u16, next: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(4);
        v.extend_from_slice(&vid.to_be_bytes());
        v.extend_from_slice(&next.to_be_bytes());
        v
    }

    /// A 4-byte MPLS label stack entry (`label`, TTL 64, bottom-of-stack `s`).
    fn mpls(label: u32, s: bool) -> Vec<u8> {
        let word = (label << 12) | (u32::from(s) << 8) | 64;
        word.to_be_bytes().to_vec()
    }

    /// An 8-byte PPPoE Session header + PPP protocol field for `inner`
    /// (`0x0021` IPv4, `0x0057` IPv6).
    fn pppoe(inner_len: usize, ppp_proto: u16) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x11, 0x00, 0x00, 0x01];
        v.extend_from_slice(&((inner_len + 2) as u16).to_be_bytes());
        v.extend_from_slice(&ppp_proto.to_be_bytes());
        v
    }

    /// Every encapsulation the default filter claims, each wrapping the same
    /// IPv4/UDP SIP datagram, behind the link-layer header `link` builds:
    /// `(label, frame)`.
    ///
    /// The link header is a parameter because the encapsulated arms are the
    /// part that used to be Ethernet-shaped: the identical set of frames has
    /// to match behind a cooked header too.
    fn encapsulated_sip_frames_on(link: LinkHeader) -> Vec<(&'static str, Vec<u8>)> {
        let ip = ipv4_udp(5060, 5060, SIP_BODY);
        let ip6 = ipv6_udp(5061, 5061, SIP_BODY);
        let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

        let mut f = link(0x0800);
        f.extend_from_slice(&ip);
        out.push(("untagged", f));

        let mut f = link(0x8100);
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&ip);
        out.push(("802.1Q", f));

        let mut f = link(0x88a8);
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&ip);
        out.push(("802.1ad single tag", f));

        let mut f = link(0x9100);
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&ip);
        out.push(("0x9100 single tag", f));

        let mut f = link(0x88a8);
        f.extend_from_slice(&tag(10, 0x8100));
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&ip);
        out.push(("QinQ", f));

        let mut f = link(0x8100);
        f.extend_from_slice(&tag(10, 0x8100));
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&ip);
        out.push(("QinQ, 0x8100 outer", f));

        let mut f = link(0x8864);
        f.extend_from_slice(&pppoe(ip.len(), 0x0021));
        f.extend_from_slice(&ip);
        out.push(("PPPoE Session", f));

        let mut f = link(0x8100);
        f.extend_from_slice(&tag(100, 0x8864));
        f.extend_from_slice(&pppoe(ip.len(), 0x0021));
        f.extend_from_slice(&ip);
        out.push(("802.1Q over PPPoE", f));

        let mut f = link(0x8847);
        f.extend_from_slice(&mpls(16, true));
        f.extend_from_slice(&ip);
        out.push(("MPLS, 1 label", f));

        let mut f = link(0x8848);
        f.extend_from_slice(&mpls(16, false));
        f.extend_from_slice(&mpls(17, true));
        f.extend_from_slice(&ip);
        out.push(("MPLS, 2 labels", f));

        let mut f = link(0x8100);
        f.extend_from_slice(&tag(100, 0x86dd));
        f.extend_from_slice(&ip6);
        out.push(("802.1Q over IPv6", f));

        out
    }

    /// [`encapsulated_sip_frames_on`] behind an Ethernet header.
    fn encapsulated_sip_frames() -> Vec<(&'static str, Vec<u8>)> {
        encapsulated_sip_frames_on(eth)
    }

    /// Non-SIP traffic in the same encapsulations: RTP on ports 10000/10002,
    /// behind the link-layer header `link` builds.
    /// None of it may reach the ring — this is the "not a firehose" gate.
    fn encapsulated_non_sip_frames_on(link: LinkHeader) -> Vec<(&'static str, Vec<u8>)> {
        let rtp = ipv4_udp(
            10000,
            10002,
            &[0x80, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();

        let mut f = link(0x0800);
        f.extend_from_slice(&rtp);
        out.push(("untagged RTP", f));

        let mut f = link(0x8100);
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&rtp);
        out.push(("802.1Q RTP", f));

        let mut f = link(0x88a8);
        f.extend_from_slice(&tag(10, 0x8100));
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(&rtp);
        out.push(("QinQ RTP", f));

        let mut f = link(0x8864);
        f.extend_from_slice(&pppoe(rtp.len(), 0x0021));
        f.extend_from_slice(&rtp);
        out.push(("PPPoE RTP", f));

        let mut f = link(0x8847);
        f.extend_from_slice(&mpls(16, true));
        f.extend_from_slice(&rtp);
        out.push(("MPLS RTP", f));

        out
    }

    /// [`encapsulated_non_sip_frames_on`] behind an Ethernet header.
    fn encapsulated_non_sip_frames() -> Vec<(&'static str, Vec<u8>)> {
        encapsulated_non_sip_frames_on(eth)
    }

    /// Frames of every UDP-tunnel flavour the opt-in flag covers, each an
    /// outer IPv4/UDP datagram on the tunnel port.
    fn udp_tunnel_frames() -> Vec<(&'static str, Vec<u8>)> {
        [("GTP-U", 2152u16), ("VXLAN", 4789), ("GENEVE", 6081)]
            .into_iter()
            .map(|(name, port)| {
                let mut f = eth(0x0800);
                f.extend_from_slice(&ipv4_udp(40000, port, SIP_BODY));
                (name, f)
            })
            .collect()
    }

    /// How many frames of `path` the compiled `filter` accepts.
    ///
    /// Goes through libpcap itself, not a re-implementation: this is the same
    /// `pcap_compile`/`pcap_setfilter` pair the capture thread hands the
    /// kernel, so a filter that passes here is one the kernel will run.
    fn count_matching(path: &std::path::Path, filter: &str) -> usize {
        let mut cap = pcap::Capture::from_file(path).expect("open fixture");
        cap.filter(filter, true).expect("filter must compile");
        let mut n = 0usize;
        loop {
            match cap.next_packet() {
                Ok(_) => n += 1,
                Err(pcap::Error::NoMorePackets) => return n,
                Err(e) => panic!("reading {}: {e}", path.display()),
            }
        }
    }

    /// Write `frames` to a one-off fixture under `dir` and count the matches.
    fn count_frames(
        dir: &std::path::Path,
        name: &str,
        linktype: u32,
        frames: &[Vec<u8>],
        filter: &str,
    ) -> usize {
        let path = dir.join(format!("{name}.pcap"));
        write_pcap(&path, linktype, frames);
        count_matching(&path, filter)
    }

    /// The checked-in PPPoE capture that proved the defect: 32 frames, every
    /// one of them PPPoE-encapsulated SIP.
    fn pppoe_fixture() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/DTMFsipinfo.pcap")
    }

    /// A plain-Ethernet SIP capture: 23 frames, all on 5060.
    fn plain_fixture() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap-samples/sip-problem-call.pcap")
    }

    /// The regression itself, stated as a number.
    ///
    /// `portrange 5060-5061` — what sipnab generated for every live capture —
    /// matches 0 of the 32 PPPoE-encapsulated SIP frames in `DTMFsipinfo.pcap`,
    /// and the filter this change generates matches all 32. The drop happened
    /// in the kernel, so no userspace counter could ever have shown it.
    #[test]
    fn auto_filter_sees_pppoe_encapsulated_sip_that_portrange_alone_drops() {
        let fixture = pppoe_fixture();
        assert_eq!(
            count_matching(&fixture, "portrange 5060-5061"),
            0,
            "the old auto-filter is supposed to be blind here; if this is \
             non-zero the fixture changed and the rest of this test proves \
             nothing"
        );
        assert_eq!(
            count_matching(&fixture, &auto_bpf_filter(5060, 5061, &[])),
            32,
            "the auto-filter must see every PPPoE-encapsulated SIP frame"
        );
    }

    /// Adding encapsulation coverage must not cost the untagged case.
    #[test]
    fn auto_filter_still_matches_plain_ethernet_exactly() {
        let fixture = plain_fixture();
        assert_eq!(count_matching(&fixture, "portrange 5060-5061"), 23);
        assert_eq!(
            count_matching(&fixture, &auto_bpf_filter(5060, 5061, &[])),
            23,
            "a union that loses the untagged case is the naive `vlan and ...` \
             bug in the other direction"
        );
    }

    /// Every encapsulation the filter claims, one frame each, all matched.
    #[test]
    fn auto_filter_matches_every_claimed_encapsulation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (label, frame) in encapsulated_sip_frames() {
            assert_eq!(
                count_frames(dir.path(), "one", DLT_EN10MB, &[frame], &filter),
                1,
                "{label}: SIP in this encapsulation is invisible to the kernel"
            );
        }
    }

    /// And the whole set at once, so a filter that matched only the last
    /// disjunct built cannot pass.
    #[test]
    fn auto_filter_matches_the_whole_encapsulation_set_in_one_capture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let frames: Vec<Vec<u8>> = encapsulated_sip_frames()
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(frames.len(), 11, "fixture set changed; update the count");
        assert_eq!(
            count_frames(
                dir.path(),
                "all",
                DLT_EN10MB,
                &frames,
                &auto_bpf_filter(5060, 5061, &[])
            ),
            11
        );
    }

    /// Not a firehose: encapsulated NON-SIP traffic stays out of the ring.
    ///
    /// The failure this guards is the tempting fix — `portrange ... or vlan or
    /// mpls or pppoes` — which on a trunk port delivers the entire link.
    #[test]
    fn auto_filter_matches_no_encapsulated_non_sip_traffic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (label, frame) in encapsulated_non_sip_frames() {
            assert_eq!(
                count_frames(dir.path(), "neg", DLT_EN10MB, &[frame], &filter),
                0,
                "{label}: the filter is delivering traffic that is not SIP"
            );
        }
    }

    /// The IPv6 arm is load-bearing, not decoration: SIP over IPv6 inside a
    /// VLAN is matched, and the IPv4-only offsets would miss it.
    #[test]
    fn auto_filter_matches_encapsulated_ipv6_sip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut frame = eth(0x8100);
        frame.extend_from_slice(&tag(100, 0x86dd));
        frame.extend_from_slice(&ipv6_udp(5060, 5060, SIP_BODY));
        assert_eq!(
            count_frames(
                dir.path(),
                "v6",
                DLT_EN10MB,
                &[frame],
                &auto_bpf_filter(5060, 5061, &[])
            ),
            1
        );
    }

    /// Both port fields are checked, not just one.
    ///
    /// A UA sending from an ephemeral port to a proxy on 5060 is the ordinary
    /// case, and the reply comes back the other way round. Checking only the
    /// source (or only the destination) loses half of every call, which on a
    /// dialog view looks like one-way signalling rather than a filter bug.
    #[test]
    fn encapsulated_arms_check_both_the_source_and_the_destination_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (sport, dport, expected, what) in [
            (40000u16, 5060u16, 1usize, "request to the proxy"),
            (5060, 40000, 1, "reply from the proxy"),
            (5061, 40000, 1, "top of the range, source side"),
            (40000, 5061, 1, "top of the range, destination side"),
            (40000, 40001, 0, "neither side is signalling"),
            (5059, 40000, 0, "just below the range"),
            (40000, 5062, 0, "just above the range"),
        ] {
            let mut frame = eth(0x8100);
            frame.extend_from_slice(&tag(100, 0x0800));
            frame.extend_from_slice(&ipv4_udp(sport, dport, SIP_BODY));
            assert_eq!(
                count_frames(dir.path(), "pair", DLT_EN10MB, &[frame], &filter),
                expected,
                "{sport} -> {dport} inside a VLAN ({what})"
            );
        }
    }

    /// An IPv4 header with `proto`, fragment word `frag`, and a payload whose
    /// first four bytes are the port pair 5060/5060.
    ///
    /// The point is that the port bytes are ALWAYS in signalling range, so the
    /// only thing that can decide the match is the field under test.
    fn ipv4_with(proto: u8, frag: u16) -> Vec<u8> {
        let payload: [u8; 12] = [
            0x13, 0xc4, 0x13, 0xc4, 0x00, 0x14, 0x00, 0x00, 0x41, 0x42, 0x43, 0x44,
        ];
        let total = 20 + payload.len();
        let mut v: Vec<u8> = vec![0x45, 0x00];
        v.extend_from_slice(&(total as u16).to_be_bytes());
        v.extend_from_slice(&[0x00, 0x2a]);
        v.extend_from_slice(&frag.to_be_bytes());
        v.extend_from_slice(&[64, proto, 0x00, 0x00]);
        v.extend_from_slice(&[192, 0, 2, 1]);
        v.extend_from_slice(&[198, 51, 100, 1]);
        v.extend_from_slice(&payload);
        v
    }

    /// The same IPv4 bytes wrapped in one VLAN tag.
    fn vlan_wrap(ip: &[u8]) -> Vec<u8> {
        let mut f = eth(0x8100);
        f.extend_from_slice(&tag(100, 0x0800));
        f.extend_from_slice(ip);
        f
    }

    /// The encapsulated arms check the IP protocol, and it matters: without
    /// it any protocol whose 21st and 23rd payload bytes happen to read as a
    /// signalling port would be delivered.
    ///
    /// The three frames differ in exactly one byte — the protocol field.
    #[test]
    fn encapsulated_arms_match_udp_and_tcp_and_nothing_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (proto, expected) in [(17u8, 1usize), (6, 1), (47, 0), (50, 0), (1, 0)] {
            assert_eq!(
                count_frames(
                    dir.path(),
                    "proto",
                    DLT_EN10MB,
                    &[vlan_wrap(&ipv4_with(proto, 0x4000))],
                    &filter
                ),
                expected,
                "IP protocol {proto} inside a VLAN"
            );
        }
    }

    /// A trailing fragment carries no ports, so the bytes at the port offsets
    /// are payload — matching them would be a false positive.
    ///
    /// These frames differ from the matching one only in the fragment word.
    #[test]
    fn encapsulated_arms_skip_trailing_fragments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (frag, expected, what) in [
            (0x0000u16, 1usize, "no flags, offset 0"),
            (0x4000, 1, "DF, offset 0"),
            (
                0x2000,
                1,
                "MF, offset 0 — the FIRST fragment does carry ports",
            ),
            (0x0001, 0, "offset 1"),
            (0x20b9, 0, "MF, offset 185"),
        ] {
            assert_eq!(
                count_frames(
                    dir.path(),
                    "frag",
                    DLT_EN10MB,
                    &[vlan_wrap(&ipv4_with(17, frag))],
                    &filter
                ),
                expected,
                "fragment word {frag:#06x} ({what})"
            );
        }
    }

    /// A KNOWN GAP, pinned so it cannot change silently: on the encapsulated
    /// arms, IPv4 headers carrying options are not matched.
    ///
    /// BPF byte-slice indices must be constants, so the arm cannot multiply
    /// the IHL nibble into the port offset the way libpcap's own `portrange`
    /// does. The untagged arm IS a real `portrange`, so the gap exists only
    /// for encapsulated traffic — which the second half of this test proves,
    /// so the limitation is never mistaken for a whole-filter one.
    #[test]
    fn encapsulated_arms_do_not_match_ipv4_options_but_the_untagged_arm_does() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);

        // IHL 6: 20 bytes of header + one 4-byte option (RFC 791 NOP padding).
        let mut ip: Vec<u8> = vec![0x46, 0x00, 0x00, 0x28];
        ip.extend_from_slice(&[0x00, 0x2a, 0x40, 0x00, 64, 17, 0x00, 0x00]);
        ip.extend_from_slice(&[192, 0, 2, 1]);
        ip.extend_from_slice(&[198, 51, 100, 1]);
        ip.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]);
        ip.extend_from_slice(&[0x13, 0xc4, 0x13, 0xc4, 0x00, 0x0c, 0x00, 0x00]);

        assert_eq!(
            count_frames(
                dir.path(),
                "opt-vlan",
                DLT_EN10MB,
                &[vlan_wrap(&ip)],
                &filter
            ),
            0,
            "known gap: IPv4 options inside an encapsulation are not reached"
        );

        let mut untagged = eth(0x0800);
        untagged.extend_from_slice(&ip);
        assert_eq!(
            count_frames(dir.path(), "opt-plain", DLT_EN10MB, &[untagged], &filter),
            1,
            "untagged IPv4-with-options must still match — the gap is the \
             encapsulated arms only, and if this ever returns 0 the base \
             `portrange` arm has been broken"
        );
    }

    /// The filter must COMPILE on every link type a live capture can open.
    ///
    /// This is the gate that rules out libpcap's `vlan` / `mpls` / `pppoes`
    /// qualifiers, which are what a first reading of pcap-filter(7) suggests.
    /// They are `pcap_compile` ERRORS on `DLT_LINUX_SLL` (the Linux `any`
    /// pseudo-device — sipnab's default when `-d` is omitted), on `DLT_RAW`
    /// (tun) and on `DLT_NULL` (BSD loopback): "no VLAN support for Linux
    /// cooked v1". A filter that fails to compile does not merely miss
    /// traffic, it stops the capture from starting at all.
    #[test]
    fn auto_filter_compiles_on_every_link_type_a_live_capture_can_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[2152]);
        let ip = ipv4_udp(5060, 5060, SIP_BODY);

        for (label, linktype, frame) in [
            ("Ethernet", DLT_EN10MB, {
                let mut f = eth(0x0800);
                f.extend_from_slice(&ip);
                f
            }),
            ("Linux cooked v1", DLT_LINUX_SLL, {
                let mut f = sll(0x0800);
                f.extend_from_slice(&ip);
                f
            }),
            ("Linux cooked v2", DLT_LINUX_SLL2, {
                let mut f = sll2(0x0800);
                f.extend_from_slice(&ip);
                f
            }),
            ("Raw IP", DLT_RAW, ip.clone()),
            ("BSD loopback", DLT_NULL, {
                let mut f: Vec<u8> = vec![0x02, 0x00, 0x00, 0x00];
                f.extend_from_slice(&ip);
                f
            }),
            ("OpenBSD loopback", DLT_LOOP, {
                let mut f: Vec<u8> = vec![0x00, 0x00, 0x00, 0x02];
                f.extend_from_slice(&ip);
                f
            }),
        ] {
            // Compiles (count_matching panics if it does not) AND still
            // delivers the plain SIP frame on that link type.
            assert_eq!(
                count_frames(dir.path(), "dlt", linktype, &[frame], &filter),
                1,
                "{label}: the auto-filter must compile and still pass untagged \
                 SIP on this link type"
            );
        }
    }

    // ── Cooked (Linux `any`) captures ──────────────────────────────────

    /// The whole encapsulation set behind a COOKED link header, which is what
    /// `sipnab` opens when no `-d` names an interface.
    ///
    /// This is the residual gap the absolute-offset arms left behind. They
    /// were written against the Ethernet header, so `ether[12:2]` read the
    /// EtherType on Ethernet and two bytes of the padded link-layer address on
    /// `DLT_LINUX_SLL` — a field that is never a tag EtherType. The arms
    /// compiled, ran, and matched nothing: measured 1 of these 11 frames on
    /// cooked v1 and 1 of 11 on cooked v2 (the untagged one, via the base
    /// `portrange`) against 11 of 11 on Ethernet.
    ///
    /// The link types are the real ones, not a stand-in: `DLT_LINUX_SLL` is
    /// the Linux `any` device before libpcap 1.10 and `DLT_LINUX_SLL2` after
    /// it, so between them they are the default invocation on every Linux
    /// host sipnab runs on.
    #[test]
    fn auto_filter_sees_encapsulated_sip_behind_a_cooked_link_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (label, linktype, link) in LINK_HEADERS {
            let frames = encapsulated_sip_frames_on(*link);
            assert_eq!(frames.len(), 11, "fixture set changed; update the count");
            for (what, frame) in &frames {
                assert_eq!(
                    count_frames(
                        dir.path(),
                        "cooked-one",
                        *linktype,
                        std::slice::from_ref(frame),
                        &filter
                    ),
                    1,
                    "{label}: SIP in {what} is invisible to the kernel"
                );
            }
            let all: Vec<Vec<u8>> = frames.into_iter().map(|(_, f)| f).collect();
            assert_eq!(
                count_frames(dir.path(), "cooked-all", *linktype, &all, &filter),
                11,
                "{label}: the whole encapsulation set in one capture"
            );
        }
    }

    /// And the cooked arms are not a firehose either: the same RTP set that
    /// must stay out on Ethernet must stay out behind a cooked header.
    ///
    /// Worth its own test because the cooked arms probe the inner IP header at
    /// offsets that belong to a DIFFERENT link header, so a widened arm would
    /// show up here first.
    #[test]
    fn auto_filter_matches_no_encapsulated_non_sip_traffic_on_any_link_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);
        for (label, linktype, link) in LINK_HEADERS {
            for (what, frame) in encapsulated_non_sip_frames_on(*link) {
                assert_eq!(
                    count_frames(dir.path(), "cooked-neg", *linktype, &[frame], &filter),
                    0,
                    "{label}: {what} is being delivered and it is not SIP"
                );
            }
        }
    }

    /// The outer test is the LINK-AWARE `ether proto`, not the Ethernet-only
    /// `ether[12:2]`, and that is the whole fix.
    ///
    /// `ether proto N` is not a byte comparison at a fixed offset: libpcap
    /// resolves it per link type at compile time — `ether[12:2]` on Ethernet,
    /// `ether[14:2]` on cooked v1, `ether[0:2]` on cooked v2, and a constant
    /// FALSE on raw-IP and loopback, which have no protocol field at all.
    /// Measured with `tcpdump -d` on each. It carries no state, so it does not
    /// bring back the `vlan` / `mpls` / `pppoes` defect the byte offsets were
    /// chosen to avoid.
    #[test]
    fn auto_filter_selects_encapsulation_with_the_link_aware_ether_proto() {
        let f = auto_bpf_filter(5060, 5061, &[]);
        for ethertype in ["0x8100", "0x88a8", "0x9100", "0x8864", "0x8847", "0x8848"] {
            assert_eq!(
                f.matches(&format!("ether proto {ethertype}")).count(),
                1,
                "{ethertype} must be selected once, through `ether proto`: {f}"
            );
        }
        assert_eq!(
            f.matches("ether[12:2]").count(),
            0,
            "`ether[12:2]` is the EtherType on Ethernet ONLY; on a cooked \
             capture it reads the link-layer address and the arm sits inert: {f}"
        );
    }

    /// The inner IP header is probed at every (link-header length, encapsulation
    /// depth) pair, because one filter string has to serve all three link types.
    ///
    /// Link-header lengths 14 (Ethernet), 16 (cooked v1) and 20 (cooked v2);
    /// depths 4 (one VLAN tag or one MPLS label), 8 (QinQ, PPPoE Session, two
    /// MPLS labels) and 12 (one VLAN tag over PPPoE). Nine pairs, seven
    /// distinct offsets — 24 and 28 each arise twice.
    #[test]
    fn auto_filter_probes_every_link_header_length_and_encapsulation_depth() {
        let f = auto_bpf_filter(5060, 5061, &[]);
        let mut want: Vec<usize> = LINK_HEADER_LENS
            .iter()
            .flat_map(|b| ENCAP_DEPTHS.iter().map(move |d| b + d))
            .collect();
        want.sort_unstable();
        want.dedup();
        assert_eq!(want, vec![18usize, 20, 22, 24, 26, 28, 32]);
        for ip_off in &want {
            assert_eq!(
                f.matches(&format!("ether[{ip_off}] = 0x45")).count(),
                1,
                "no IPv4 probe at offset {ip_off}: {f}"
            );
            assert_eq!(
                f.matches(&format!("ether[{ip_off}] & 0xf0 = 0x60")).count(),
                1,
                "no IPv6 probe at offset {ip_off}: {f}"
            );
        }
        assert_eq!(
            f.matches("] = 0x45").count(),
            7,
            "exactly seven IPv4 probes, one per distinct offset: {f}"
        );
    }

    /// The exact outer type test is what keeps the offset union honest.
    ///
    /// Seven offsets are probed on every link type, four of which belong to a
    /// different link header than the one in front of the packet. The only
    /// thing stopping that from reaching ordinary traffic is that the arm
    /// fires solely for the six encapsulating link-layer protocols.
    ///
    /// The frame below is the proof: an ordinary IPv4/UDP datagram on ports
    /// 40000/40001 whose own header bytes, read four octets in, spell a second
    /// IPv4/UDP header on port 5060 — identification `0x4500` supplies the
    /// `0x45`, the source address supplies protocol 17, the header checksum
    /// supplies a zero fragment word and the UDP checksum supplies the port.
    /// Untagged it must be dropped; with a tag EtherType in front of the very
    /// same bytes it must be delivered, which proves the bytes really are what
    /// the encapsulated arms accept.
    #[test]
    fn the_outer_link_type_test_keeps_untagged_traffic_out_of_the_encapsulated_arms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let filter = auto_bpf_filter(5060, 5061, &[]);

        let mut decoy: Vec<u8> = vec![0x45, 0x00, 0x00, 0x2a];
        decoy.extend_from_slice(&[0x45, 0x00]); // identification -> the 0x45
        decoy.extend_from_slice(&[0x40, 0x00]); // flags / fragment offset
        decoy.extend_from_slice(&[64, 17]); // TTL, UDP
        decoy.extend_from_slice(&[0x00, 0x00]); // checksum -> the zero frag word
        decoy.extend_from_slice(&[192, 17, 2, 1]); // source -> the 17
        decoy.extend_from_slice(&[198, 51, 100, 1]); // destination
        decoy.extend_from_slice(&40000u16.to_be_bytes());
        decoy.extend_from_slice(&40001u16.to_be_bytes());
        decoy.extend_from_slice(&22u16.to_be_bytes()); // UDP length
        decoy.extend_from_slice(&5060u16.to_be_bytes()); // UDP checksum -> the port
        decoy.extend_from_slice(b"not sip at all");

        let mut untagged = eth(0x0800);
        untagged.extend_from_slice(&decoy);
        assert_eq!(
            count_frames(dir.path(), "decoy-plain", DLT_EN10MB, &[untagged], &filter),
            0,
            "an untagged datagram must never be read at an encapsulated offset"
        );

        let mut tagged = eth(0x8100);
        tagged.extend_from_slice(&decoy);
        assert_eq!(
            count_frames(dir.path(), "decoy-tagged", DLT_EN10MB, &[tagged], &filter),
            1,
            "the same bytes behind a tag EtherType must match, or the frame \
             above proves nothing about the outer test"
        );
    }

    /// The stateful qualifiers must never appear in a generated filter.
    ///
    /// Stated as a source-level gate as well as the compile gate above,
    /// because the compile failure only shows up on a link type the test
    /// machine may not have — and because these three words are exactly what
    /// the next person will reach for.
    #[test]
    fn auto_filter_uses_no_stateful_libpcap_qualifier() {
        for (lo, hi) in [(5060u16, 5061u16), (5060, 5060)] {
            let f = auto_bpf_filter(lo, hi, &[2152, 4789, 6081]);
            for word in ["vlan", "mpls", "pppoes"] {
                assert!(
                    !f.contains(word),
                    "generated filter contains the stateful qualifier `{word}`: \
                     it re-bases offsets for everything to its right (so a union \
                     of them silently mis-decodes) and it is a pcap_compile error \
                     on Linux cooked, raw-IP and loopback link types. Filter: {f}"
                );
            }
        }
    }

    /// A single-port range spells the base term `port N`, not `portrange N-N`,
    /// and narrows every encapsulated arm to the same single port.
    #[test]
    fn auto_filter_single_port_range_uses_port() {
        let f = auto_bpf_filter(5060, 5060, &[]);
        assert!(f.starts_with("port 5060 or "), "got: {f}");
        assert!(!f.contains("portrange"), "got: {f}");
        assert!(!f.contains(">= 5060"), "got: {f}");
        assert!(f.contains("ether[38:2] = 5060"), "got: {f}");
    }

    /// The base term is the untagged `portrange`, first and unchanged.
    #[test]
    fn auto_filter_leads_with_the_plain_portrange() {
        assert!(
            auto_bpf_filter(5060, 5061, &[]).starts_with("portrange 5060-5061 or "),
            "the untagged case must stay a plain libpcap portrange — it is the \
             only arm that handles IPv4 options, fragments and every link type \
             correctly"
        );
        assert!(auto_bpf_filter(5080, 5090, &[]).starts_with("portrange 5080-5090 or "));
    }

    /// A non-default portrange reaches every encapsulated arm, not just the
    /// base term.
    #[test]
    fn auto_filter_carries_a_custom_portrange_into_every_arm() {
        let f = auto_bpf_filter(5080, 5090, &[]);
        assert_eq!(
            f.matches("5080").count(),
            29,
            "one base term + 4 lower bounds (source and destination, v4 and \
             v6) at each of the 7 inner offsets: {f}"
        );
        assert!(!f.contains("5060"), "the default range leaked in: {f}");

        // And it behaves: SIP on 5080 inside a VLAN is matched, 5060 is not.
        let dir = tempfile::tempdir().expect("tempdir");
        for (port, expected) in [(5080u16, 1usize), (5090, 1), (5060, 0), (5091, 0)] {
            let mut frame = eth(0x8100);
            frame.extend_from_slice(&tag(100, 0x0800));
            frame.extend_from_slice(&ipv4_udp(port, port, SIP_BODY));
            assert_eq!(
                count_frames(dir.path(), "range", DLT_EN10MB, &[frame], &f),
                expected,
                "port {port} inside a VLAN"
            );
        }
    }

    // ── Opt-in UDP tunnel ports ────────────────────────────────────────

    /// The default filter must NOT carry the UDP tunnel ports.
    ///
    /// BPF cannot walk a GTP-U extension-header chain to the inner port, so
    /// covering these means capturing EVERYTHING on the port. On a mobile core
    /// that is the whole user plane.
    #[test]
    fn auto_filter_omits_udp_tunnel_ports_by_default() {
        let f = auto_bpf_filter(5060, 5061, &[]);
        for port in TUNNEL_PORTS_DEFAULT {
            assert!(
                !f.contains(&port.to_string()),
                "port {port} is in the default filter: {f}"
            );
        }
        let dir = tempfile::tempdir().expect("tempdir");
        for (label, frame) in udp_tunnel_frames() {
            assert_eq!(
                count_frames(dir.path(), "tun", DLT_EN10MB, &[frame], &f),
                0,
                "{label} traffic must not reach the ring unless asked for"
            );
        }
    }

    /// Asking for them adds exactly one `udp port` term per port, and they
    /// then match.
    #[test]
    fn requested_udp_tunnel_ports_are_appended_and_match() {
        let f = auto_bpf_filter(5060, 5061, TUNNEL_PORTS_DEFAULT);
        assert!(
            f.ends_with(" or udp port 2152 or udp port 4789 or udp port 6081"),
            "got: {f}"
        );
        let dir = tempfile::tempdir().expect("tempdir");
        for (label, frame) in udp_tunnel_frames() {
            assert_eq!(
                count_frames(dir.path(), "tun", DLT_EN10MB, &[frame], &f),
                1,
                "{label} was requested and must be captured"
            );
        }
        // Still not a firehose in the other direction: ordinary RTP on a
        // non-tunnel port stays out.
        for (label, frame) in encapsulated_non_sip_frames() {
            assert_eq!(
                count_frames(dir.path(), "neg", DLT_EN10MB, &[frame], &f),
                0,
                "{label}"
            );
        }
    }

    /// The three defaults are the IANA-assigned tunnel ports.
    #[test]
    fn default_tunnel_ports_are_the_iana_assignments() {
        assert_eq!(TUNNEL_PORTS_DEFAULT, &[2152u16, 4789, 6081]);
    }

    /// `--capture-tunnels` with no value means the three defaults; with a
    /// value it means exactly the ports named, in order, de-duplicated.
    #[test]
    fn capture_tunnels_flag_resolves_to_ports() {
        let mut cli = base_cli();
        assert_eq!(
            resolve_tunnel_ports(&cli).expect("no flag"),
            Vec::<u16>::new()
        );

        cli.capture_tunnels = Some(TUNNEL_PORTS_DEFAULT_LIST.to_string());
        assert_eq!(
            resolve_tunnel_ports(&cli).expect("bare flag"),
            TUNNEL_PORTS_DEFAULT.to_vec()
        );

        cli.capture_tunnels = Some("8472, 4789 ,8472".to_string());
        assert_eq!(
            resolve_tunnel_ports(&cli).expect("explicit list"),
            vec![8472u16, 4789],
            "order is the operator's, duplicates collapse"
        );
    }

    /// A malformed port list is an argument error, not a silently empty set.
    #[test]
    fn capture_tunnels_rejects_a_malformed_port_list() {
        let mut cli = base_cli();
        for bad in ["", "http", "70000", "2152,", "0"] {
            cli.capture_tunnels = Some(bad.to_string());
            let err = resolve_tunnel_ports(&cli)
                .err()
                .unwrap_or_else(|| panic!("'{bad}' must be refused"));
            assert_eq!(err.exit_code, 2, "'{bad}'");
            assert!(
                err.message.contains("--capture-tunnels"),
                "'{bad}': the error must name the flag, got: {}",
                err.message
            );
        }
    }

    // ── The notices ────────────────────────────────────────────────────

    /// The default path SAYS it does not cover UDP-tunnelled SIP, and names
    /// the flag that does. A silent omission recreates the bug one level up.
    #[test]
    fn tunnel_omission_notice_fires_by_default_and_names_the_flag() {
        let msg = tunnel_omission_notice(&[]).expect("the default path must say so");
        assert!(msg.contains("--capture-tunnels"), "got: {msg}");
        for name in ["GTP-U", "VXLAN", "GENEVE"] {
            assert!(msg.contains(name), "the notice must name {name}: {msg}");
        }
        assert_eq!(
            tunnel_omission_notice(TUNNEL_PORTS_DEFAULT),
            None,
            "nothing to warn about once the ports are covered"
        );
    }

    /// An operator's own filter is never rewritten, but one that cannot see
    /// past an encapsulation gets a sentence about it.
    #[test]
    fn explicit_filter_encap_notice_fires_only_on_a_blind_port_filter() {
        let msg = explicit_filter_encap_notice("udp port 5060")
            .expect("a bare port filter is encapsulation-blind");
        assert!(msg.contains("not modified"), "got: {msg}");
        assert!(msg.contains("--capture-tunnels"), "got: {msg}");

        // Already encapsulation-aware, by qualifier or by raw offset.
        assert_eq!(explicit_filter_encap_notice("vlan and port 5060"), None);
        assert_eq!(explicit_filter_encap_notice("pppoes and port 5060"), None);
        assert_eq!(explicit_filter_encap_notice("mpls and port 5060"), None);
        assert_eq!(
            explicit_filter_encap_notice("port 5060 or ether[12:2] = 0x8100"),
            None
        );
        // No port term at all: the operator is filtering on something else
        // entirely and this notice would be noise.
        assert_eq!(explicit_filter_encap_notice("host 192.0.2.1"), None);
    }

    // ── plan() wiring ──────────────────────────────────────────────────

    /// A live capture with no explicit filter gets the encapsulation-aware
    /// filter — the exact string, not something like it.
    #[test]
    fn plan_generates_the_encapsulation_aware_filter_for_a_live_capture() {
        let mut cli = base_cli();
        cli.device = Some("eth0".into());
        let plan = plan(&cli, &Config::default()).expect("plan");
        assert_eq!(
            plan.capture_config.bpf_filter.as_deref(),
            Some(auto_bpf_filter(5060, 5061, &[]).as_str())
        );
    }

    /// `--capture-tunnels` reaches the generated filter.
    #[test]
    fn plan_adds_requested_tunnel_ports_to_the_generated_filter() {
        let mut cli = base_cli();
        cli.device = Some("eth0".into());
        cli.capture_tunnels = Some(TUNNEL_PORTS_DEFAULT_LIST.to_string());
        let plan = plan(&cli, &Config::default()).expect("plan");
        assert_eq!(
            plan.capture_config.bpf_filter.as_deref(),
            Some(auto_bpf_filter(5060, 5061, TUNNEL_PORTS_DEFAULT).as_str())
        );
    }

    /// `--portrange` reaches the generated filter.
    #[test]
    fn plan_generates_the_filter_for_a_custom_portrange() {
        let mut cli = base_cli();
        cli.device = Some("eth0".into());
        cli.portrange = Some("5080-5090".into());
        let plan = plan(&cli, &Config::default()).expect("plan");
        assert_eq!(
            plan.capture_config.bpf_filter.as_deref(),
            Some(auto_bpf_filter(5080, 5090, &[]).as_str())
        );
    }

    /// An explicit filter goes to the kernel verbatim. Never rewritten,
    /// never extended, whatever sipnab thinks of it.
    #[test]
    fn plan_never_rewrites_an_explicit_filter() {
        let mut cli = base_cli();
        cli.device = Some("eth0".into());
        cli.bpf_filter = vec!["udp".into(), "port".into(), "5060".into()];
        let plan = plan(&cli, &Config::default()).expect("plan");
        assert_eq!(
            plan.capture_config.bpf_filter.as_deref(),
            Some("udp port 5060"),
            "the operator's expression must reach the kernel unmodified"
        );
    }

    /// Reading a file still gets no auto-filter at all.
    #[test]
    fn plan_generates_no_filter_when_reading_a_file() {
        let mut cli = base_cli();
        cli.input = vec![FIXTURE_FILE.to_string()];
        let plan = plan(&cli, &Config::default()).expect("plan");
        assert_eq!(plan.capture_config.bpf_filter, None);
    }

    /// A real capture, for the `-I` paths that resolve their input.
    const FIXTURE_FILE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";
}
