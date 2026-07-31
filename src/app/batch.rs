// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch (non-interactive) mode: the state and receive loop behind every
//! headless run (`--no-tui`, `--mcp`, replay, `--cores`).
//!
//! `BatchRunner` owns what used to be ~25 loose locals in main.rs — the
//! writer, detector engines, decryption state, counters, and companion-server
//! handles — built once in `BatchRunner::new` and consumed by the receive
//! loop. `run` is the single entry point the binary dispatches to (WS2).

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::capture::{self, CaptureConfig, ParsedPacket, PcapExportMode, PcapWriter};
use crate::cli::Cli;
use crate::config::Config;
use crate::output::{self, EventExecEngine, OutputOptions, ReportFormat};
use crate::process_isolation::{self, KillRequest, ScannerKillHandle};
use crate::rtp::{self, stream_store::StreamStore};
use crate::security::{
    self as sec, AlertEngine, AlertRule, DigestLeakDetector, FraudDetector, RegFloodDetector,
    ScannerDetector,
};
use crate::signals;
use crate::sip::{self, dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

#[cfg(feature = "tls")]
use crate::capture::decrypt::TlsDecryptor;
#[cfg(any(feature = "hep", feature = "tls", test))]
use crate::capture::parse::TransportProto;
#[cfg(feature = "tls")]
use crate::capture::tls;

// ── Bundled parameter structs ──────────────────────────────────────

/// Security detection engines bundle.
struct DetectionEngines {
    /// UA/behavioral SIP-scanner detector (`--kill-scanner`).
    scanner: Option<ScannerDetector>,
    /// Toll-fraud pattern detector (`--fraud-detect`).
    fraud: Option<FraudDetector>,
    /// Digest-authentication credential-leak detector (`--digest-leak`).
    digest: Option<DigestLeakDetector>,
    /// REGISTER-flood detector (`--reg-flood`).
    reg_flood: Option<RegFloodDetector>,
    /// Shared with the MCP server (when --mcp is on) so the
    /// `security_findings` tool can read the FindingsHistory ring buffer.
    alerts: Arc<RwLock<AlertEngine>>,
    /// Channel to the isolated scanner-kill worker thread; `None` when no
    /// kill feature is active (or the worker failed to spawn).
    kill_handle: Option<ScannerKillHandle>,
    /// SIP status code sent in kill responses (`--kill-response`).
    kill_response_code: u16,
    /// Targeted-kill directives (`-K` / `--kill-target`): any SIP request whose
    /// source matches is killed regardless of UA/behavioral detection.
    kill_targets: Vec<sec::scanner_kill::KillTarget>,
}

/// Packet processing counters and state.
struct PacketCounters {
    /// Total SIP messages classified so far.
    sip_count: u64,
    /// Total RTP packets classified so far.
    rtp_count: u64,
    /// Timestamp of the previously emitted SIP message, for `--delta-time`.
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    /// Remaining trailing-context (`-A`) budget; re-armed by each direct match.
    trailing_remaining: usize,
    /// Call-IDs of dialogs "armed" by a `-e` payload match. Once a dialog is
    /// armed, every subsequent message of it is emitted (dialog-following).
    followed_dialogs: std::collections::HashSet<String>,
    /// Completed RFC 4733 telephone-event (DTMF) digits decoded so far
    /// (`--telephone-event`).
    dtmf_count: u64,
}

/// Owned batch-mode processing components, built by the binary's
/// bootstrap and handed to `run`.
pub struct BatchProcessing {
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    pub matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    pub filter_expr: Option<FilterExpr>,
    /// Per-message output formatting options.
    pub output_opts: OutputOptions,
    /// `--on-*` event execution engine.
    pub event_exec: EventExecEngine,
}

/// Immutable batch-mode configuration for packet processing.
struct BatchContext<'a> {
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    matcher: &'a SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    filter_expr: &'a Option<FilterExpr>,
    /// Per-message output formatting options.
    output_opts: &'a OutputOptions,
    /// Full parsed CLI, consulted for the many per-message flags.
    cli: &'a Cli,
    /// Skip all RTP processing (`--no-rtp` or config equivalent).
    no_rtp: bool,
    /// Trailing-context budget granted per direct match (`-A N`).
    after_count: usize,
    /// SIP signaling port range; RTP is never gated by it.
    portrange: (u16, u16),
}

/// Mutable processing state for the main receive loop.
struct ProcessingState<'a> {
    /// Dialog store (already write-locked by the caller).
    dialog_store: &'a mut DialogStore,
    /// RTP stream store (already write-locked by the caller).
    stream_store: &'a mut StreamStore,
    /// Heuristic RTP detector for streams with no SDP linkage.
    rtp_heuristic: &'a mut rtp::heuristic::RtpHeuristic,
    /// `--on-*` event execution engine (dialog + quality events).
    event_exec: &'a mut EventExecEngine,
    /// SRTP decryption context (keys from `--srtp-keys` + SDES `a=crypto`),
    /// used to authenticate and decrypt RTP payloads before media analysis.
    #[cfg(feature = "tls")]
    srtp: Option<&'a mut crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP extractor (`--dtls-keylog`): recovers SRTP keys from observed
    /// DTLS handshakes and feeds them into `srtp`.
    #[cfg(feature = "tls")]
    dtls: Option<&'a mut crate::capture::dtls::DtlsSrtpExtractor>,
    /// `--group-by` buffer. `Some` reroutes per-message output into it so the
    /// capture can be replayed grouped at the end; `None` keeps the ordinary
    /// streaming path, including the allocation-free `--json` fast path.
    group: Option<&'a mut output::group::GroupBuffer>,
}

/// Resolve the pcap file a `--tshark-filter` / `--wireshark` command should
/// reference. Precedence: the input file (`-I`, offline analysis), then the
/// file the live capture was written to (`-O`).
///
/// # Errors
///
/// Returns a message when neither is set: a live capture that saves no pcap
/// leaves nothing for `tshark -r` to read, so emitting a placeholder path
/// (the old `capture.pcap`) would only produce a command that fails.
fn tshark_input_file<'a>(
    input: Option<&'a str>,
    output: Option<&'a str>,
) -> Result<&'a str, String> {
    input.or(output).ok_or_else(|| {
        "no pcap to read: pass -I <file> to analyze a capture file, or -O <file> \
         to save the live capture so tshark has a file to read"
            .to_string()
    })
}

/// Capture split/stop policy resolved from the CLI.
pub struct CapturePolicy {
    /// Rotate the output file after this many bytes (`--split-size`).
    pub split_bytes: Option<u64>,
    /// Rotate the output file after this duration (`--split-time`).
    pub split_duration: Option<std::time::Duration>,
    /// Stop capturing after this duration (`--autostop duration:N`).
    pub autostop_duration: Option<std::time::Duration>,
    /// Stop after the output file reaches this size (`--autostop filesize:N`).
    pub autostop_filesize_mb: Option<u64>,
    /// SIP signaling port range (`--portrange`); media is never gated.
    pub portrange: (u16, u16),
}

/// Build the `ParallelConfig` shared by both offline multi-core paths
/// (`run_cores_file` and the `--cores N` arm of `run`) from the CLI, config,
/// resolved port range, and `no_rtp` decision — keeping the two call sites in
/// lockstep instead of duplicating the field-by-field construction.
fn parallel_config(
    cli: &Cli,
    config: &Config,
    portrange: (u16, u16),
    no_rtp: bool,
) -> crate::parallel::ParallelConfig {
    crate::parallel::ParallelConfig {
        cores: cli.cores,
        max_streams: cli.max_streams as usize,
        max_dialogs: cli.limit as usize,
        rotate: cli.rotate_enabled(),
        max_reassembly: cli.max_reassembly as usize,
        portrange,
        no_dialog: cli.no_dialog,
        dialog_tracking: cli.dialog_track.unwrap_or_default(),
        no_rtp,
        quiet_bad_parse: cli.quiet_bad_parse,
        xcid_headers: config.sip.xcid_headers.clone().unwrap_or_default(),
        reassembly: !cli.no_reassembly,
        parse_limit: cli.limitlen,
    }
}

/// Multi-core offline file reconstruction (`--cores N` with `-I file`,
/// single device): read the pcap directly and shard packets across N worker
/// threads, fusing read+peek+shard into one stage — no capture reader
/// thread, no semaphore channel. Reports and exits; advanced per-message
/// features use the single-threaded path.
///
/// # Arguments
///
/// * `cli` — parsed flags; `cli.input` names the pcap (a silent no-op when
///   absent) and `cli.cores` the worker count.
/// * `config` — loaded configuration for `no_rtp` / X-CID fallbacks.
/// * `capture_config` — capture parameters forwarded to the file reader.
/// * `portrange` — SIP signaling port range for classification.
///
/// # Side effects
///
/// Spawns N worker threads inside `run_offline_parallel_file`, prints the
/// post-capture reports and summary to stdout/stderr, and exits the
/// process with code 1 when reconstruction fails.
pub fn run_cores_file(
    cli: &Cli,
    config: &Config,
    capture_config: &CaptureConfig,
    portrange: (u16, u16),
) {
    let Some(input) = cli.primary_input() else {
        return;
    };
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    let pcfg = parallel_config(cli, config, portrange, no_rtp);
    match crate::parallel::run_offline_parallel_file(
        std::path::Path::new(input),
        capture_config,
        pcfg,
    ) {
        Ok(r) => {
            // The return value is the "report could not be produced" signal and
            // was dropped here, so an unknown --call-report id or an unwritable
            // stdout exited 0 on the --cores path while exiting 1 elsewhere.
            let reports_ok = generate_reports(cli, &r.dialog_store, &r.stream_store);
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
            if !reports_ok {
                std::process::exit(1);
            }
        }
        Err(e) => {
            tracing::error!("multi-core reconstruction failed: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Run batch mode to completion: the multi-core offline fast path when
/// `--cores N` applies, otherwise the single-threaded `BatchRunner`.
///
/// # Arguments
///
/// * `cli` / `config` — parsed flags and loaded configuration (owned; this
///   is the mode's terminal consumer).
/// * `capture_config` — capture limits (`--count`, `--duration`) enforced
///   by the receive loop.
/// * `handle` — the running capture thread's handle, joined at EOF.
/// * `rx` — receiving side of the packet channel.
/// * `batch` — pre-built matcher/filter/output/event-exec components.
/// * `policy` — split/autostop policy resolved from the CLI.
/// * `raw_kill_sock` — raw socket opened during the privileged window for
///   source-spoofed kill responses, when active.
///
/// # Side effects
///
/// The multi-core arm spawns worker threads, joins the capture thread, and
/// prints reports; the single-threaded arm builds a `BatchRunner` (which
/// spawns the kill worker and companion-server thread) and drives its
/// receive loop to completion. Either way this function blocks until the
/// batch run is over.
#[expect(clippy::too_many_arguments)]
pub fn run(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: capture::channel::PacketRx,
    batch: BatchProcessing,
    policy: CapturePolicy,
    raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
) {
    let portrange = policy.portrange;
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    // 17p. Offline multi-core reconstruction (`--cores N`, N>1). Shard parsed
    // packets by host pair across N workers with thread-local stores, merge, and
    // report — covers dialog + RTP-stream reconstruction and `--report`/`--json`.
    // Advanced features (live, per-message output ordering, security detectors,
    // SRTP) use the single-threaded path below; this branch only triggers for an
    // offline input file.
    if cli.cores > 1 && cli.has_input() {
        let pcfg = parallel_config(&cli, config, portrange, no_rtp);
        let result = crate::parallel::run_offline_parallel(rx, pcfg);
        let _ = handle.thread.join();
        let reports_ok = generate_reports(&cli, &result.dialog_store, &result.stream_store);
        if !cli.quiet {
            tracing::info!(
                "sipnab: {} packets, {} SIP messages, {} RTP packets across {} streams ({} cores)",
                result.total_count,
                result.sip_count,
                result.rtp_count,
                result.stream_store.len(),
                cli.cores,
            );
        }
        if !reports_ok {
            std::process::exit(1);
        }
        return;
    }

    let runner = match BatchRunner::new(cli, config, batch, policy, raw_kill_sock) {
        Ok(runner) => runner,
        Err(fatal) => {
            // `handle`'s thread has been running since bootstrap::launch, and
            // it owns the capture source. Exiting straight from here abandons
            // it mid-read — which is what ThreadSanitizer reported as a thread
            // leak on the --api-tls-cert fail-fast path. Stop it and reap it
            // first; this is the only scope that holds both the handle and the
            // receiver, which is why the error had to travel here to be
            // handled.
            fatal.exit_after(|| capture::stop_and_join(handle, rx));
        }
    };
    runner.run_loop(capture_config, handle, rx);
}

/// All owned batch-mode state: writer, detector engines, decryption state,
/// stores, and companion-server handles. Built once by `BatchRunner::new`
/// (bootstrap steps 16-17), consumed by `BatchRunner::run_loop` (step 18).
pub struct BatchRunner {
    /// Parsed command-line flags (owned for the life of the run).
    cli: Cli,
    /// Loaded configuration (cloned; consulted for NRB name resolution).
    config: Config,
    /// Header-level SIP matcher (`-m`, `--method`, ...).
    matcher: SipMatcher,
    /// Compiled `--filter` DSL expression, when given.
    filter_expr: Option<FilterExpr>,
    /// Per-message output formatting options.
    output_opts: OutputOptions,
    /// `--on-*` event execution engine.
    event_exec: EventExecEngine,
    /// `-O` output writer; `None` until the first packet supplies the
    /// link type (opened lazily in `run_loop`).
    writer: Option<PcapWriter>,
    /// Write pcapng (with DSB/NRB blocks) instead of classic pcap.
    use_pcapng: bool,
    /// What payload variant `-O` records (decrypted / encrypted+DSB / raw).
    export_mode: PcapExportMode,
    /// `--hep-send` forwarder for matched SIP messages, when configured.
    #[cfg(feature = "hep")]
    hep_sender: Option<crate::capture::hep::HepSender>,
    /// IP/TCP reassembly and parse front-end for raw captured packets.
    processor: capture::PacketProcessor,
    /// Dialog store; shared with the companion servers via the lock.
    dialog_store: Arc<RwLock<DialogStore>>,
    /// RTP stream store; shared with the companion servers via the lock.
    stream_store: Arc<RwLock<StreamStore>>,
    /// Heuristic RTP detector for streams with no SDP linkage.
    rtp_heuristic: rtp::heuristic::RtpHeuristic,
    /// Skip all RTP processing (`--no-rtp` or config equivalent).
    no_rtp: bool,
    /// Security detectors, alert engine, and kill-worker handle.
    engines: DetectionEngines,
    /// SIP-over-TLS decryptor (`--keylog` / `--tls-key`), when configured.
    #[cfg(feature = "tls")]
    tls_decryptor: Option<TlsDecryptor>,
    /// SRTP media decryption context (`--srtp-keys` + learned SDES keys).
    #[cfg(feature = "tls")]
    srtp_context: Option<crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP key extractor (`--dtls-keylog`), when configured.
    #[cfg(feature = "tls")]
    dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor>,
    /// Handles to the companion-server thread (REST API / MCP), when any
    /// server started.
    servers: Option<crate::app::servers::ServerHandles>,
    /// Split/autostop policy resolved from the CLI.
    policy: CapturePolicy,
}

impl BatchRunner {
    /// Build every piece of batch state (bootstrap steps 16-17): output
    /// writer policy, HEP sender, stores, security detectors + alert engine,
    /// TLS/SRTP/DTLS decryption state, and the companion servers.
    ///
    /// # Arguments
    ///
    /// * `cli` / `config` — parsed flags and loaded configuration.
    /// * `batch` — pre-built matcher/filter/output/event-exec components.
    /// * `policy` — split/autostop policy resolved from the CLI.
    /// * `raw_kill_sock` — raw socket for spoofed kill responses, handed to
    ///   the kill worker when spawned.
    ///
    /// # Side effects
    ///
    /// Spawns the isolated scanner-kill worker thread when any kill feature
    /// is active; reads TLS keylog / RSA key / SRTP key / DTLS keylog files
    /// and embedded pcapng secrets from disk; starts the companion REST
    /// API + MCP servers on their shared runtime thread; logs progress via
    /// `tracing`.
    ///
    /// # Errors
    ///
    /// An unloadable `--tls-key`, `--srtp-keys` or `--dtls-keylog` file (exit
    /// code 1), or a companion-server configuration error (exit code 2).
    ///
    /// These used to call `std::process::exit` here. They cannot: the capture
    /// thread is already running by this point — `bootstrap::launch` spawned it
    /// before batch mode was entered — and this function does not own its
    /// handle, so exiting from here abandons a thread that still holds an open
    /// capture source. ThreadSanitizer reported exactly that as a thread leak
    /// on the `--api-tls-cert` fail-fast path. Returning lets `run` stop the
    /// capture thread first, which is the only place that can.
    fn new(
        cli: Cli,
        config: &Config,
        batch: BatchProcessing,
        policy: CapturePolicy,
        raw_kill_sock: Option<crate::process_isolation::RawKillSocket>,
    ) -> Result<Self, crate::app::bootstrap::PlanError> {
        let matcher = batch.matcher;
        let filter_expr = batch.filter_expr;
        let output_opts = batch.output_opts;
        let event_exec = batch.event_exec;
        // 16. Output writer placeholder for -O — opened lazily on the first
        //     packet in run_loop, once the link type is known.
        let writer: Option<PcapWriter> = None;
        let use_pcapng = cli.pcapng;
        let export_mode =
            PcapExportMode::parse_mode(&cli.pcap_export_mode).unwrap_or(PcapExportMode::Decrypted);

        // 16a. Initialize HEP sender if --hep-send is set
        #[cfg(feature = "hep")]
        let hep_sender: Option<crate::capture::hep::HepSender> = if let Some(ref addr) =
            cli.hep_send
        {
            let capture_id = cli.hep_id.unwrap_or(1);
            let hep_auth = match cli.resolve_hep_auth() {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("HEP auth: {e}");
                    None
                }
            };
            let authenticated = hep_auth.is_some();
            match crate::capture::hep::HepSender::new(addr, capture_id, hep_auth, cli.hep_auth_mode)
            {
                Ok(sender) => {
                    tracing::info!(
                        "HEP sender targeting {addr} (capture id {capture_id}{})",
                        if authenticated { ", authenticated" } else { "" }
                    );
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
        let processor = capture::PacketProcessor::with_max_sessions(cli.max_reassembly as usize)
            .with_reassembly(!cli.no_reassembly)
            .with_parse_limit(cli.limitlen);
        let dialog_store: Arc<RwLock<DialogStore>> = Arc::new(RwLock::new(
            {
                let mut ds = DialogStore::new(cli.limit as usize, cli.rotate_enabled());
                // The wiring whose absence made the old --dialog-track a dead
                // flag: declared, parsed, and never handed to anything.
                ds.set_tracking(cli.dialog_track.unwrap_or_default());
                ds
            }
            .with_xcid_headers(config.sip.xcid_headers.clone().unwrap_or_default()),
        ));
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
        let rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

        // 17a. Initialize security detectors
        let kill_scanner_active = cli.kill_scanner || config.security.kill_scanner.unwrap_or(false);

        // Targeted-kill directives (-K). Already validated in Cli::validate();
        // reparse here and skip (loudly) any that somehow fail so a bad entry
        // can't take the whole run down mid-capture.
        let kill_targets: Vec<sec::scanner_kill::KillTarget> = cli
            .kill_target
            .iter()
            .filter_map(|spec| match sec::scanner_kill::KillTarget::parse(spec) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::error!("Ignoring invalid --kill-target '{spec}': {e}");
                    None
                }
            })
            .collect();
        // The kill worker is needed whenever we may emit a kill response —
        // detection-driven (--kill-scanner) OR targeted (-K).
        let kill_worker_active = kill_scanner_active || !kill_targets.is_empty();

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
        let scanner_kill_handle: Option<ScannerKillHandle> = if kill_worker_active {
            match process_isolation::spawn_scanner_kill_worker(None, raw_kill_sock) {
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
        // `--alert` is declared as a CHANNEL flag — "syslog", "json", "exec" —
        // and every documented example passes a channel name. It used to be fed
        // straight to `AlertRule::parse`, whose grammar is
        // `<name>:<threshold>/<window>`, so `--alert syslog` failed to parse,
        // warned, and enabled nothing. The docs taught it anyway, including a
        // line claiming it wrote to LOCAL0. For a security path that is the
        // worst shape of bug: the operator believes alerting is on.
        //
        // A bare word is now a channel, as advertised. A value containing ':'
        // is still parsed as a rule, so anyone who discovered the old grammar
        // from the source keeps working.
        let mut alert_channel_syslog = false;
        let mut alert_channel_json = false;
        let mut alert_rules: Vec<AlertRule> = Vec::new();
        for spec in effective_alert_sources.iter() {
            let value = spec.trim();
            if value.contains(':') {
                match AlertRule::parse(value) {
                    Ok(r) => alert_rules.push(r),
                    Err(e) => tracing::warn!("Skipping invalid alert rule '{}': {}", value, e),
                }
                continue;
            }
            match value.to_ascii_lowercase().as_str() {
                "syslog" => alert_channel_syslog = true,
                "json" => alert_channel_json = true,
                // The exec channel is the presence of --alert-exec; naming it
                // here is accepted so the documented triple all work, but it
                // cannot invent a command.
                "exec" => {
                    if cli.alert_exec.is_none() && config.security.alert_exec.is_none() {
                        tracing::warn!(
                            "--alert exec given without --alert-exec <CMD>; no command to run"
                        );
                    }
                }
                other => tracing::warn!(
                    "Unknown alert channel '{other}'. Valid channels: syslog, json, exec. \
                     (A value containing ':' is treated as an alert rule.)"
                ),
            }
        }
        let effective_alert_exec = cli
            .alert_exec
            .clone()
            .or(config.security.alert_exec.clone());
        let mut alert_engine = AlertEngine::new(alert_rules, effective_alert_exec);
        if cli.syslog || alert_channel_syslog {
            alert_engine.set_syslog(true);
        }
        if cli.alert_json || alert_channel_json {
            alert_engine.set_json_output(true);
        }
        let alert_engine = Arc::new(RwLock::new(alert_engine));

        let engines = DetectionEngines {
            scanner: scanner_detector,
            fraud: fraud_detector,
            digest: digest_detector,
            reg_flood: reg_flood_detector,
            alerts: alert_engine,
            kill_handle: scanner_kill_handle,
            kill_response_code,
            kill_targets,
        };

        // 17c. Initialize TLS decryptor if --keylog and/or --tls-key is provided
        #[cfg(feature = "tls")]
        let mut tls_decryptor: Option<TlsDecryptor> =
            if cli.keylog.is_some() || cli.tls_key.is_some() {
                let keylog_path = cli.keylog.as_deref().map(std::path::Path::new);
                let crypto = crate::crypto::default_backend();
                match TlsDecryptor::new(keylog_path, crypto) {
                    Ok(mut d) => {
                        if d.keylog_entry_count() > 0 {
                            tracing::info!(
                                "sipnab: TLS decryption active (keylog loaded). \
                         Decrypted traffic visible in output."
                            );
                        }
                        // Load the RSA private key for TLS 1.2 RSA-key-exchange decryption.
                        if let Some(ref keyfile) = cli.tls_key {
                            match crate::capture::rsa_key::RsaKey::from_pem_file(
                                std::path::Path::new(keyfile),
                            ) {
                                Ok(k) => {
                                    d.set_rsa_key(k);
                                    tracing::info!(
                                        "sipnab: TLS decryption active (--tls-key loaded; \
                                 decrypts TLS 1.2 RSA-key-exchange handshakes only)."
                                    );
                                }
                                Err(e) => {
                                    return Err(crate::app::bootstrap::PlanError {
                                        exit_code: 1,
                                        message: format!("Failed to load --tls-key {keyfile}: {e}"),
                                    });
                                }
                            }
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

        // 17d. Feed TLS secrets embedded in a pcapng (Decryption Secrets Block) into
        // the decryptor, so a self-contained capture decrypts without an external
        // --keylog. Creates a decryptor on demand when the file carries secrets.
        #[cfg(feature = "tls")]
        if let Some(input) = cli.primary_input() {
            let path = std::path::Path::new(input);
            if let Some(ref mut dec) = tls_decryptor {
                let added = crate::capture::decrypt::feed_embedded_secrets(path, dec);
                if added > 0 {
                    tracing::info!("TLS decryption: +{added} embedded DSB secret(s) from {input}");
                }
            } else if let Ok(meta) = crate::capture::pcapng_meta::read_pcapng_metadata(path)
                && !meta.tls_secrets.is_empty()
                && let Ok(mut d) = TlsDecryptor::new(None, crate::crypto::default_backend())
            {
                let added: usize = meta.tls_secrets.iter().map(|s| d.add_keylog_text(s)).sum();
                if added > 0 {
                    tracing::info!(
                        "TLS decryption active: {added} secret(s) from embedded DSB in {input}"
                    );
                    tls_decryptor = Some(d);
                }
            }
        }

        // 17e. Initialize the SRTP decryption context from --srtp-keys (and, later,
        // SDES `a=crypto` lines fed in as SDP is parsed). Authenticated RTP payloads
        // are decrypted in place before stream/audio analysis.
        #[cfg(feature = "tls")]
        let srtp_context: Option<crate::rtp::srtp::SrtpContext> =
            if let Some(ref keyfile) = cli.srtp_keys {
                match crate::rtp::srtp::SrtpContext::from_key_file(
                    std::path::Path::new(keyfile),
                    crate::crypto::default_backend(),
                ) {
                    Ok(ctx) => {
                        tracing::info!(
                            "SRTP decryption active: {} key(s) from {keyfile}",
                            ctx.key_count()
                        );
                        Some(ctx)
                    }
                    Err(e) => {
                        return Err(crate::app::bootstrap::PlanError {
                            exit_code: 1,
                            message: format!("Failed to load --srtp-keys {keyfile}: {e}"),
                        });
                    }
                }
            } else {
                // No key file, but SDES keys may still arrive via SDP — start empty
                // and let `add_sdes` populate it as `a=crypto` lines are seen.
                Some(crate::rtp::srtp::SrtpContext::new(
                    Vec::new(),
                    crate::crypto::default_backend(),
                ))
            };

        // 17f. Initialize the DTLS-SRTP extractor from --dtls-keylog. It recovers
        // SRTP master keys from the DTLS handshake (RFC 5764 exporter) and feeds
        // them into the SRTP context as handshakes are observed.
        #[cfg(feature = "tls")]
        let dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor> =
            if let Some(ref keylog) = cli.dtls_keylog {
                match crate::capture::dtls::DtlsSrtpExtractor::from_keylog_file(
                    std::path::Path::new(keylog),
                    crate::crypto::default_backend(),
                ) {
                    Ok(ex) => {
                        tracing::info!(
                            "DTLS-SRTP active: {} keylog entr(ies) from {keylog}",
                            ex.keylog_len()
                        );
                        Some(ex)
                    }
                    Err(e) => {
                        return Err(crate::app::bootstrap::PlanError {
                            exit_code: 1,
                            message: format!("Failed to load --dtls-keylog {keylog}: {e}"),
                        });
                    }
                }
            } else {
                None
            };

        // Start the companion servers (REST API + MCP) on one shared runtime
        // thread. They read the SAME stores the packet loop writes to — no
        // mirror, no second parse; MCP additionally reads the AlertEngine for
        // the security_findings tool.
        let servers = crate::app::servers::start_servers(
            &cli,
            &dialog_store,
            &stream_store,
            Some(&engines.alerts),
            crate::app::servers::Selection {
                api: true,
                mcp: true,
            },
        )
        .map_err(|e| crate::app::bootstrap::PlanError {
            exit_code: 2,
            message: e.to_string(),
        })?;

        Ok(Self {
            cli,
            config: config.clone(),
            matcher,
            filter_expr,
            output_opts,
            event_exec,
            writer,
            use_pcapng,
            export_mode,
            #[cfg(feature = "hep")]
            hep_sender,
            processor,
            dialog_store,
            stream_store,
            rtp_heuristic,
            no_rtp,
            engines,
            #[cfg(feature = "tls")]
            tls_decryptor,
            #[cfg(feature = "tls")]
            srtp_context,
            #[cfg(feature = "tls")]
            dtls_extractor,
            servers,
            policy,
        })
    }

    /// The main receive loop (step 18) plus end-of-capture reporting and the
    /// server keep-alive tail. Consumes the runner.
    ///
    /// # Arguments
    ///
    /// * `capture_config` — supplies the `--count` / `--duration` stop
    ///   limits.
    /// * `handle` — capture-thread handle, joined once the channel drains.
    /// * `rx` — receiving side of the packet channel.
    ///
    /// # Side effects
    ///
    /// Blocks until capture ends: drains the packet channel, mutates the
    /// shared stores, lazily opens and writes the `-O` output file
    /// (embedding DSB/NRB blocks for pcapng), emits per-message output
    /// through the buffered stdout sink, fires alert/exec events, sweeps
    /// reassembly and detector state every 5 s, and honors the
    /// count/duration/autostop stop conditions. On exit it flushes the
    /// sink and writer, shuts down the kill worker, joins the capture
    /// thread, flips the MCP `source_exhausted` flag, prints reports and
    /// the summary, and — when a companion server is running — parks until
    /// shutdown is requested or the MCP stdio client disconnects. Exits
    /// the process on a failed output-file open (code 1), a failed
    /// `--call-report` lookup (code 1), or a failed output-file *write* or
    /// final flush (code 1) — the last of which previously logged and exited
    /// 0, so a capture truncated by ENOSPC reported success.
    fn run_loop(
        self,
        capture_config: CaptureConfig,
        handle: capture::CaptureHandle,
        rx: capture::channel::PacketRx,
    ) {
        let BatchRunner {
            cli,
            config,
            matcher,
            filter_expr,
            output_opts,
            mut event_exec,
            mut writer,
            use_pcapng,
            export_mode,
            #[cfg(feature = "hep")]
            hep_sender,
            mut processor,
            dialog_store,
            stream_store,
            mut rtp_heuristic,
            no_rtp,
            mut engines,
            #[cfg(feature = "tls")]
            mut tls_decryptor,
            #[cfg(feature = "tls")]
            mut srtp_context,
            #[cfg(feature = "tls")]
            mut dtls_extractor,
            servers,
            policy,
        } = self;

        // Set when writing the -O output fails. The open path a few hundred
        // lines below exits 1; the write and final-flush paths only logged,
        // so a capture truncated by ENOSPC reported success and any
        // `sipnab -O out.pcap && next-step` pipeline ran on partial data.
        let mut output_failed = false;
        let split_bytes = policy.split_bytes;
        let split_duration = policy.split_duration;
        let portrange = policy.portrange;
        let autostop_duration = policy.autostop_duration;
        let autostop_filesize_mb = policy.autostop_filesize_mb;

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

        // --group-by buffers per-message output and replays it grouped once the
        // capture ends (see output::group for why it cannot stream, and for the
        // caps that keep an attacker-keyed map bounded). None = stream as usual.
        let mut group_buf = cli
            .group_by
            .as_deref()
            .and_then(|f| output::group::GroupField::parse(f).ok())
            .map(output::group::GroupBuffer::new);

        let mut last_sweep = std::time::Instant::now();
        let sweep_interval = std::time::Duration::from_secs(5);

        // Shared buffered stdout sink for every per-message emitter (JSON,
        // sipgrep-style text, fail2ban, hexdump). Flushed whenever the packet
        // channel goes idle — live output stays real-time — and at end of
        // capture; `--line-buffer` flushes after every message.
        let mut sink = output::BatchSink::stdout(cli.line_buffer);

        // 18. Main receive loop
        let start = std::time::Instant::now();
        let mut total_count: u64 = 0;
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
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

            // Use recv_timeout so we can check shutdown periodically. Flush
            // pending output first whenever the channel has gone idle, so a
            // quiet live capture never sits on buffered messages.
            if rx.is_empty() {
                sink.flush();
            }
            let packet = match rx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(pkt) => pkt,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            };

            // Lazily initialize the writer on first packet (we need link_type)
            if writer.is_none()
                && let Some(ref output_path) = cli.output
            {
                // Record the capture source as the pcapng interface name (SNB-0001):
                // the capture device for live, the input file for replay.
                let capture_source = cli.device.as_deref().or(cli.primary_input());
                match PcapWriter::with_interface(
                    &PathBuf::from(output_path),
                    packet.link_type,
                    split_bytes,
                    split_duration,
                    use_pcapng,
                    export_mode,
                    capture_source,
                ) {
                    Ok(mut w) => {
                        // Write DSB with keylog content if mode requires it
                        if let Some(ref keylog_path) = cli.keylog
                            && let Err(e) =
                                w.maybe_write_keylog_dsb(std::path::Path::new(keylog_path))
                        {
                            tracing::warn!("Failed to write DSB: {e}");
                        }
                        // Embed a Name Resolution Block when name resolution is active
                        // (SNB-0001): headless `--names`/`--resolve` should travel with
                        // the capture, mirroring the TUI save path. Before packets.
                        if use_pcapng {
                            let (resolver, mode) = crate::app::build_resolver(&cli, &config);
                            if mode != crate::names::NameMode::Off {
                                let include_dns = mode == crate::names::NameMode::Dns;
                                let entries = resolver.nrb_entries(include_dns);
                                if let Err(e) = w.write_name_resolution_block(&entries) {
                                    tracing::warn!("Failed to write name resolution block: {e}");
                                }
                            }
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
                // Failing to OPEN the output exits 1 a few lines above; failing
                // to WRITE it used to exit 0, so `sipnab -O out.pcap && process
                // out.pcap` proceeded on a truncated capture.
                output_failed = true;
                break;
            }

            total_count += 1;

            // Parse and reassemble the packet
            let parsed_packets = processor.process(&packet);
            for pp in &parsed_packets {
                // --hep-parse: try to unwrap HEP-encapsulated packets
                #[cfg(feature = "hep")]
                let hep_unwrapped = if cli.hep_parse && pp.transport == TransportProto::Udp {
                    crate::capture::hep::parse_hep(&pp.payload).ok().map(|hep| {
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

                // If TLS decryption yielded a SIP message, process the decrypted
                // packet (its transport is already stamped Tls).
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
                        #[cfg(feature = "tls")]
                        srtp: srtp_context.as_mut(),
                        #[cfg(feature = "tls")]
                        dtls: dtls_extractor.as_mut(),
                        group: group_buf.as_mut(),
                    };
                    process_parsed_packet(
                        effective_pp,
                        &batch_ctx,
                        &mut proc_state,
                        &mut engines,
                        &mut counters,
                        &mut sink,
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
                        crate::capture::parse::TransportProto::Udp,
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

        // Replay any --group-by buffer before draining, so grouped output lands
        // ahead of reports exactly where the streamed output would have.
        if let Some(ref mut buf) = group_buf {
            if buf.truncated() {
                tracing::warn!("{}", buf.truncation_note());
            }
            let machine_readable = cli.json || cli.json_pretty || cli.fail2ban;
            for (header, chunks) in buf.drain() {
                // Headers are for humans; machine formats stay parseable, where
                // the grouping is the contiguity of the records themselves.
                if let Some(h) = header
                    && !machine_readable
                {
                    sink.write_str(&format!("\n── {h} ──\n"));
                }
                for chunk in chunks {
                    sink.write_str(&chunk);
                }
            }
        }

        // Drain the per-message output sink before anything else writes to
        // stdout (reports, wireshark/tshark lines), preserving output order.
        sink.flush();

        // A write that failed for any reason other than a closed pipe means the
        // emitted output is incomplete — same class as a truncated -O file, and
        // it must not exit 0 either.
        if let Some(e) = sink.hard_error() {
            tracing::error!("Failed to write output: {e}");
            output_failed = true;
        }

        // Flush the output writer explicitly: BufWriter's Drop discards
        // flush errors, so without this an ENOSPC at end of capture would
        // truncate the file silently with exit code 0.
        if let Some(ref mut w) = writer
            && let Err(e) = w.finish()
        {
            tracing::error!("Output file may be incomplete: {e}");
            output_failed = true;
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

        // 20a. The source is fully drained: flip the flag MCP's tail_dialogs
        //      reports as source_exhausted, so a polling client knows no more
        //      dialog updates will arrive.
        if let Some(ref servers) = servers
            && let Some(ref flag) = servers.source_exhausted
        {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // 21. Post-capture output
        {
            let ds_guard = dialog_store.read();
            let ss_guard = stream_store.read();
            if !generate_reports(&cli, &ds_guard, &ss_guard) {
                std::process::exit(1);
            }
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

        // 21b. --tshark-filter: print full tshark command for matched dialogs.
        // The emitted `tshark -r <file>` must name a pcap that actually
        // exists: the input file (`-I`), or the file the live capture was
        // saved to (`-O`). A live capture with neither has no pcap for tshark
        // to read, so emit a clear error instead of a bogus `capture.pcap`.
        if cli.tshark_filter.is_some() || (cli.wireshark && cli.has_input()) {
            let input_file = tshark_input_file(cli.primary_input(), cli.output.as_deref());
            if let Some(ref tshark_expr) = cli.tshark_filter {
                // User provided a custom tshark filter expression.
                match &input_file {
                    Ok(file) => println!("tshark -r {file} -Y '{tshark_expr}' -V"),
                    Err(e) => tracing::error!("Cannot emit --tshark-filter command: {e}"),
                }
            } else if let Ok(file) = &input_file {
                // Generate tshark command from tracked dialogs (only when
                // --wireshark + -I; the outer guard ensures the input exists).
                let ds_guard = dialog_store.read();
                let call_ids: Vec<String> = ds_guard.iter().map(|d| d.call_id.clone()).collect();
                if !call_ids.is_empty() {
                    let filter_parts: Vec<String> = call_ids
                        .iter()
                        .map(|id| format!("sip.Call-ID == \"{}\"", id))
                        .collect();
                    println!("tshark -r {} -Y '{}' -V", file, filter_parts.join(" || "));
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

        // If any companion server is running, keep the process alive so clients
        // can query the captured data. Poll the shutdown flag so SIGINT/SIGTERM
        // exits cleanly instead of blocking on a thread that never returns.
        if let Some(servers) = servers {
            #[cfg(feature = "api")]
            if cli.api.is_some() {
                tracing::info!("API server active — press Ctrl-C to stop");
            }
            #[cfg(feature = "mcp")]
            if cli.mcp {
                tracing::info!("MCP server active — press Ctrl-C to stop");
            }
            while !signals::shutdown_requested() {
                // A stdio MCP client owns the lifetime: when it closes stdin the
                // serve task finishes, and there is no client left to serve — so
                // exit instead of spinning forever (otherwise the process leaks
                // until SIGINT). HTTP/API tasks only finish on a signal, so the
                // flag stays unset there.
                if mcp_stdio_client_gone(servers.mcp_stdio_done.as_ref()) {
                    tracing::info!("MCP client disconnected — shutting down");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        // Report a truncated output as a failure. This runs after the sink
        // flush, the writer's finish(), the kill-worker shutdown and the
        // capture-thread join, so nothing is skipped to get here — the exit
        // code is the only thing that changes.
        //
        // Reports still print above: a partial capture is worth looking at,
        // it just must not be mistaken for a whole one by a script reading $?.
        if output_failed {
            std::process::exit(1);
        }
    }
}

/// Whether the wait loop that keeps a batch run alive for its companion
/// servers should stop because the stdio MCP client has closed its end.
///
/// A stdio MCP client owns the process lifetime: once its `mcp_stdio_done`
/// flag flips (it closed stdin, so the serve task finished), there is no
/// client left to serve and the process must exit rather than spin forever.
/// The flag is `None` for HTTP/API-only runs — those finish on a signal
/// instead — so this stays `false` there, and `false` while a stdio client is
/// still connected (flag present but unset).
fn mcp_stdio_client_gone(
    mcp_stdio_done: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> bool {
    mcp_stdio_done.is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
}

// ── Packet processing ─────────────────────────────────────────────────

/// Decide whether a SIP message should be emitted, updating dialog-follow and
/// trailing-context state.
///
/// This implements two overlapping selection rules:
///
/// * **Dialog-following** (sngrep/sipgrep `-e`): when `follow_dialogs` is set, a
///   `direct_match` arms the message's dialog, and every later message of an
///   armed dialog is emitted regardless of its own content. Followed messages
///   are not "trailing context" and never spend the `-A` budget.
/// * **Trailing context** (`-A N`): a `direct_match` (re)arms an `after_count`
///   budget; the next non-matching messages are emitted until it drains.
///
/// With `follow_dialogs == false` the follow set stays empty and behavior is
/// identical to trailing-context-only selection.
///
/// # Arguments
///
/// * `direct_match` — the message itself passed matcher + DSL + calls-only.
/// * `call_id` — the message's Call-ID, when present.
/// * `follow_dialogs` — dialog-following (`-e`) is active.
/// * `followed` — set of armed Call-IDs; mutated when a match arms one.
/// * `trailing_remaining` — live `-A` budget; mutated as described above.
/// * `after_count` — the `-A N` budget granted per direct match.
///
/// # Returns
///
/// `true` when the message should be emitted.
fn decide_emit(
    direct_match: bool,
    call_id: Option<&str>,
    follow_dialogs: bool,
    followed: &mut std::collections::HashSet<String>,
    trailing_remaining: &mut usize,
    after_count: usize,
) -> bool {
    let followed_match = follow_dialogs && call_id.is_some_and(|id| followed.contains(id));

    // A direct match arms the dialog so its remaining messages follow.
    if direct_match
        && follow_dialogs
        && let Some(id) = call_id
    {
        followed.insert(id.to_string());
    }

    let trailing_match = *trailing_remaining > 0;
    let emit = direct_match || followed_match || trailing_match;

    if emit {
        if direct_match {
            // A fresh match re-arms the trailing (`-A`) budget.
            *trailing_remaining = after_count;
        } else if trailing_match && !followed_match {
            // Only pure trailing-context messages spend the budget; a
            // followed-dialog message emits without consuming it.
            *trailing_remaining -= 1;
        }
    }

    emit
}

/// Process a single parsed packet: classify via the shared pipeline core,
/// then apply the batch extras — counters, matcher/DSL filter, output
/// dispatch, security detectors, dialog events, DTMF, quality events.
///
/// # Arguments
///
/// * `pp` — the parsed (and possibly TLS-decrypted) packet to classify.
/// * `ctx` — immutable per-run configuration (matcher, filter, CLI, ports).
/// * `state` — mutable stores, heuristic, event engine, and media-decrypt
///   state (the store guards are held by the caller).
/// * `engines` — security detectors, alert engine, and kill-worker handle.
/// * `counters` — SIP/RTP counts and emit-selection state, updated here.
/// * `sink` — buffered per-message output sink.
///
/// # Side effects
///
/// Mutates the dialog and stream stores; fires alert-engine findings and
/// `--on-*` exec events; hands kill requests to the isolated worker for
/// detected or targeted scanners; writes hexdump/fail2ban/per-message
/// output into `sink`; decrypts SRTP payloads in place via the pipeline;
/// and logs DTMF/STIR-SHAKEN details.
fn process_parsed_packet<W: std::io::Write>(
    pp: &ParsedPacket,
    ctx: &BatchContext<'_>,
    state: &mut ProcessingState<'_>,
    engines: &mut DetectionEngines,
    counters: &mut PacketCounters,
    sink: &mut output::BatchSink<W>,
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
    let event_exec = &mut *state.event_exec;
    let group = &mut state.group;
    let scanner_detector = &mut engines.scanner;
    let fraud_detector = &mut engines.fraud;
    let digest_detector = &mut engines.digest;
    let reg_flood_detector = &mut engines.reg_flood;
    let alert_engine = &mut engines.alerts;
    let scanner_kill_handle = &engines.kill_handle;
    let kill_response_code = engines.kill_response_code;
    let kill_targets = &engines.kill_targets;
    let sip_count = &mut counters.sip_count;
    let rtp_count = &mut counters.rtp_count;
    let dtmf_count = &mut counters.dtmf_count;
    let prev_timestamp = &mut counters.prev_timestamp;
    let trailing_remaining = &mut counters.trailing_remaining;
    let followed_dialogs = &mut counters.followed_dialogs;
    // Hexdump output (applies to all packets)
    if cli.hexdump && cli.no_tui {
        let dump = output::hexdump(&pp.payload);
        write!(
            sink,
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

    // Classify via the shared pipeline core (WS unwrap, SIP parse + SDP link
    // extraction, SDES/DTLS key learning, RTCP/RTP/heuristic detection), then
    // apply the action with the batch extras: counters, matcher/DSL filter,
    // output dispatch, security detectors, events, DTMF.
    let opts = crate::pipeline::PipelineOptions {
        no_dialog: cli.no_dialog,
        no_rtp,
        sip_portrange: Some(portrange),
        quiet_bad_parse: cli.quiet_bad_parse,
    };
    #[cfg(feature = "tls")]
    let mut decrypt = crate::pipeline::MediaDecrypt {
        srtp: state.srtp.as_deref_mut(),
        dtls: state.dtls.as_deref_mut(),
    };
    #[cfg(not(feature = "tls"))]
    let mut decrypt = crate::pipeline::MediaDecrypt::default();

    match crate::pipeline::classify_packet(pp, state.rtp_heuristic, &opts, &mut decrypt) {
        crate::pipeline::PacketAction::None => {}
        crate::pipeline::PacketAction::Sip { msg, sdp_links } => {
            let sip_msg = msg;
            *sip_count += 1;

            // Apply matcher (header-level filters)
            let matcher_pass = matcher.matches(&sip_msg);

            // Track dialog regardless of filter (needed for filter DSL evaluation)
            if !cli.no_dialog {
                // Fire event exec before updating state (captures state change)
                let prev_state = sip_msg
                    .call_id()
                    .and_then(|id| dialog_store.get(id))
                    .map(|d| d.state().clone());

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
                    && prev_state.as_ref() != Some(dialog.state())
                {
                    event_exec.fire_dialog_event(dialog);
                }

                // Link SDP media endpoints to RTP streams
                for (ip, port, call_id, media) in &sdp_links {
                    stream_store.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }

            // Apply DSL filter (evaluated after dialog update)
            let filter_pass = if let Some(expr) = &filter_expr {
                if let Some(call_id) = sip_msg.call_id() {
                    if let Some(dialog) = dialog_store.get(call_id) {
                        let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                            stream_store.streams_for(call_id).collect();
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
                        output::render_absent(alert.method.as_deref()),
                        output::render_absent(alert.ua.as_deref()),
                        alert.detection_method
                    ),
                );
                if cli.fail2ban {
                    let event = output::format_scanner_event(
                        &alert.src_ip.to_string(),
                        alert.ua.as_deref(),
                        alert.method.as_deref(),
                    );
                    sink.write_str(&event);
                    sink.write_str("\n");
                }

                // D16: Send kill response via isolated worker thread.
                // SN-01: HEP-origin packets are ineligible unless the operator
                // opted in (--hep-allow-kill), since their src/dst are
                // sender-asserted and unauthenticated absent --hep-auth.
                if let Some(handle) = &scanner_kill_handle
                    && sec::scanner_kill::kill_response_eligible(pp.from_hep, cli.hep_allow_kill)
                    && let Some(response_bytes) =
                        sec::scanner_kill::build_scanner_response(&sip_msg, kill_response_code)
                {
                    let _ = handle.send_kill(KillRequest::SendResponse {
                        dst_addr: sip_msg.src_addr,
                        dst_port: sip_msg.src_port,
                        src_addr: sip_msg.dst_addr,
                        src_port: sip_msg.dst_port,
                        response_bytes,
                    });
                }
            }

            // Targeted scanner kill (sipgrep -K): kill any request whose source
            // matches a --kill-target, independent of UA/behavioral detection.
            if !kill_targets.is_empty()
                && sip_msg.is_request
                && kill_targets
                    .iter()
                    .any(|t| t.matches(sip_msg.src_addr, sip_msg.src_port))
            {
                let method = sip_msg.method.as_ref().map(|m| m.as_str());
                let ua = sip_msg.user_agent();
                alert_engine.write().fire(
                    "scanner",
                    sip_msg.src_addr,
                    &format!(
                        "method={} ua={} detection=kill-target",
                        output::render_absent(method),
                        output::render_absent(ua)
                    ),
                );
                if cli.fail2ban {
                    let event =
                        output::format_scanner_event(&sip_msg.src_addr.to_string(), ua, method);
                    sink.write_str(&event);
                    sink.write_str("\n");
                }
                // SN-01: same HEP-origin ineligibility as behavioral kill above.
                if let Some(handle) = &scanner_kill_handle
                    && sec::scanner_kill::kill_response_eligible(pp.from_hep, cli.hep_allow_kill)
                    && let Some(response_bytes) =
                        sec::scanner_kill::build_scanner_response(&sip_msg, kill_response_code)
                {
                    let _ = handle.send_kill(KillRequest::SendResponse {
                        dst_addr: sip_msg.src_addr,
                        dst_port: sip_msg.src_port,
                        src_addr: sip_msg.dst_addr,
                        src_port: sip_msg.dst_port,
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
                    sink.write_str(&event);
                    sink.write_str("\n");
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
                            info.dest_display(),
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

            // Emit if the message directly matches, if it belongs to a dialog
            // armed by a `-e` payload match (dialog-following), or if trailing
            // context (`-A`) is still active.
            let direct_match = matcher_pass && filter_pass && calls_only_pass;
            let follow_dialogs = cli.match_expr.is_some();
            let emit = decide_emit(
                direct_match,
                sip_msg.call_id(),
                follow_dialogs,
                followed_dialogs,
                trailing_remaining,
                after_count,
            );

            if emit && cli.no_tui {
                dispatch_sip_output(
                    &sip_msg,
                    output_opts,
                    cli,
                    *prev_timestamp,
                    sink,
                    group.as_deref_mut(),
                );
            }

            *prev_timestamp = Some(sip_msg.timestamp);
        }
        crate::pipeline::PacketAction::Rtcp(rtcp_packets) => {
            stream_store.process_rtcp(&rtcp_packets);
        }
        crate::pipeline::PacketAction::Rtp {
            hdr: rtp_hdr,
            decrypted_payload,
            via_heuristic,
        } => {
            // Heuristically-discovered streams keep the pre-existing batch
            // contract: stream tracking only — no DTMF, no quality events.
            if via_heuristic {
                stream_store.process_rtp(pp, &rtp_hdr, pp.timestamp);
                *rtp_count += 1;
                return;
            }

            // SRTP: classification substituted a plaintext payload when a key
            // authenticated the packet. The auth tag is the gate — a wrong
            // key never produces plaintext.
            let srtp_decrypted: Option<ParsedPacket> = decrypted_payload.map(|plain| {
                let mut d = pp.clone();
                d.payload = plain;
                d
            });
            let rtp_pp: &ParsedPacket = srtp_decrypted.as_ref().unwrap_or(pp);

            stream_store.process_rtp(rtp_pp, &rtp_hdr, rtp_pp.timestamp);
            *rtp_count += 1;

            // DTMF extraction (I2): if --telephone-event is set and we have
            // the RTP payload after the header, attempt DTMF decode. The
            // telephone-event payload type and clock rate are negotiated in
            // SDP (`a=rtpmap:<pt> telephone-event/<clock>`), not fixed at the
            // PT 101 / 8000 Hz conventions. `process_rtp` above resolved this
            // stream's codec, payload_type, and clock_rate from that rtpmap,
            // so when the codec is telephone-event we use the stream's
            // negotiated PT and clock; otherwise fall back to the conventions
            // (e.g. a DTMF-only stream with no observed SDP).
            if cli.telephone_event && rtp_hdr.payload_offset < rtp_pp.payload.len() {
                let rtp_payload = &rtp_pp.payload[rtp_hdr.payload_offset..];
                let key = crate::rtp::stream::StreamKey {
                    ssrc: rtp_hdr.ssrc,
                    src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
                    dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
                };
                let (expected_pt, clock_rate) = stream_store
                    .get(&key)
                    .filter(|s| {
                        s.codec
                            .as_deref()
                            .is_some_and(|c| c.eq_ignore_ascii_case("telephone-event"))
                    })
                    .map(|s| (s.payload_type, s.clock_rate))
                    .unwrap_or((101, 8000));
                if let Some(dtmf) = rtp::dtmf::extract_dtmf_with_clock(
                    rtp_payload,
                    rtp_hdr.payload_type,
                    expected_pt,
                    clock_rate,
                    pp.timestamp,
                ) {
                    *dtmf_count += 1;
                    tracing::info!(
                        "DTMF digit='{}' duration={}ms ssrc=0x{:08x}",
                        dtmf.digit,
                        dtmf.duration_ms,
                        rtp_hdr.ssrc
                    );
                }
            }

            // Fire quality events on each RTP packet (rate-limited internally). Guard
            // on a configured command so the common no-`--on-quality` path skips the
            // StreamKey rebuild + second store lookup entirely (per-RTP-packet
            // constant-factor cut; fire_quality_event no-ops otherwise).
            if event_exec.quality_events_enabled() {
                let key = crate::rtp::stream::StreamKey {
                    ssrc: rtp_hdr.ssrc,
                    src: std::net::SocketAddr::new(pp.src_addr, pp.src_port),
                    dst: std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
                };
                if let Some(stream) = stream_store.get(&key) {
                    event_exec.fire_quality_event(stream);
                }
            }
        }
    }
}

/// Attempt TLS decryption on a TCP payload.
///
/// If the payload looks like TLS, parses the records and tries to decrypt
/// ApplicationData records. If decryption yields SIP content, returns a
/// synthetic `ParsedPacket` with the decrypted payload and transport set
/// to reflect the TLS origin; returns `None` for non-TCP/non-TLS payloads,
/// when no decryptor is configured, or when nothing decrypts to SIP. As a
/// side effect, Handshake records are fed into the decryptor to capture
/// key material.
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
        // Feed Handshake records (ClientHello/ServerHello/ClientKeyExchange) so
        // the decryptor can capture randoms + the RSA-encrypted pre-master for
        // the --tls-key path and the TLS 1.2 CLIENT_RANDOM keylog path.
        if record.content_type == tls::TlsContentType::Handshake {
            decryptor.process_record(
                record,
                std::net::SocketAddr::new(pp.src_addr, pp.src_port),
                std::net::SocketAddr::new(pp.dst_addr, pp.dst_port),
            );
            continue;
        }
        if let Some(plaintext) = decryptor.try_decrypt(record, pp.src_addr, pp.dst_addr)
            && sip::is_sip_message(&plaintext)
        {
            // Build a synthetic ParsedPacket with the decrypted SIP payload,
            // stamped Tls so the pipeline parses (and reports) the true
            // transport origin.
            let mut decrypted_pp = pp.clone();
            decrypted_pp.payload = plaintext.into();
            decrypted_pp.transport = TransportProto::Tls;
            return Some(decrypted_pp);
        }
    }

    None
}

// ── SIP output dispatch ──────────────────────────────────────────────

/// Dispatch a matched SIP message to the configured output backend
/// (pretty JSON, NDJSON, fail2ban event, raw text dump, or the default
/// sipgrep-style print).
///
/// # Arguments
///
/// * `msg` — the SIP message to emit.
/// * `opts` — formatting options for the default text print.
/// * `cli` — flags selecting the backend and suppression modes.
/// * `prev_timestamp` — previous message's timestamp for `--delta-time`.
/// * `sink` — buffered output sink written to.
///
/// # Side effects
///
/// Writes into `sink` (flushing per message when `--line-buffer` is set).
/// Emits nothing in MCP mode (stdout is the JSON-RPC wire) or under
/// `--no-cli-print`.
fn dispatch_sip_output<W: std::io::Write>(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    sink: &mut output::BatchSink<W>,
    group: Option<&mut output::group::GroupBuffer>,
) {
    // MCP mode owns stdout (JSON-RPC wire); no per-packet text/JSON output.
    #[cfg(feature = "mcp")]
    if cli.mcp {
        return;
    }
    // --no-cli-print suppresses every per-message dump (text/JSON/fail2ban/raw)
    // so post-capture reports (--call-report, --report) aren't drowned out.
    if cli.no_cli_print {
        return;
    }
    // --group-by cannot stream: the last packet may belong to the first group,
    // so nothing can be written until the capture ends. Render to a String and
    // buffer it. This is the one path that pays for a per-message allocation,
    // which is why the streaming branches below are left untouched.
    if let Some(buf) = group {
        if let Some(rendered) = render_sip_output(msg, opts, cli, prev_timestamp) {
            buf.push(msg, rendered);
        }
        sink.end_message();
        return;
    }
    if cli.json_pretty {
        let json = output::json::message_to_json_pretty(msg);
        sink.write_str(&json);
    } else if cli.json {
        // Hot path: serialize straight into the sink's buffer — no
        // per-message String, no per-message write(2).
        // to_writer bypasses the sink's error tracking, so hand the result
        // back: a full disk here is data loss, not a closed pipe.
        //
        // Pass the io::Error through UNWRAPPED. Boxing it (Error::other)
        // resets the kind to Other, which makes a BrokenPipe from `| head`
        // indistinguishable from ENOSPC — and then the pipeline that is
        // supposed to exit 0 exits 1.
        let r = output::json::write_message_json(msg, sink.writer());
        sink.record(r);
    } else if cli.fail2ban {
        // Fail2ban output for scanner-like messages
        if msg.is_request {
            let ua = msg.user_agent();
            let method = msg.method.as_ref().map(|m| m.as_str());
            let event = output::format_scanner_event(&msg.src_addr.to_string(), ua, method);
            sink.write_str(&event);
            sink.write_str("\n");
        }
    } else if cli.text_dump {
        // Raw SIP message text dump
        let raw = String::from_utf8_lossy(&msg.raw);
        sink.write_str(&raw);
        sink.write_str("\n");
    } else {
        let text = output::cli_print::format_sip_message(msg, opts, prev_timestamp);
        sink.write_str(&text);
    }

    // Flush if --line-buffer is set
    sink.end_message();
}

/// Render one message exactly as `dispatch_sip_output` would have written it,
/// returning the bytes instead of emitting them. Used only by `--group-by`,
/// which must hold output back until the capture ends.
///
/// # Returns
/// `None` for a mode that emits nothing for this message (`--fail2ban` skips
/// responses).
fn render_sip_output(
    msg: &sip::SipMessage,
    opts: &OutputOptions,
    cli: &Cli,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<String> {
    if cli.json_pretty {
        Some(output::json::message_to_json_pretty(msg))
    } else if cli.json {
        let mut bytes: Vec<u8> = Vec::new();
        output::json::write_message_json(msg, &mut bytes).ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else if cli.fail2ban {
        if !msg.is_request {
            return None;
        }
        let ua = msg.user_agent();
        let method = msg.method.as_ref().map(|m| m.as_str());
        Some(format!(
            "{}\n",
            output::format_scanner_event(&msg.src_addr.to_string(), ua, method)
        ))
    } else if cli.text_dump {
        Some(format!("{}\n", String::from_utf8_lossy(&msg.raw)))
    } else {
        Some(output::cli_print::format_sip_message(
            msg,
            opts,
            prev_timestamp,
        ))
    }
}

// ── Report generation ────────────────────────────────────────────────

/// Write `text` to stdout, returning `false` if it could not be delivered.
///
/// A `BrokenPipe` is the reader's choice (`| head`) and counts as success;
/// every other error means the output is incomplete. `print!` would panic on
/// both, which is how `--report` to a full disk exited 101 with a backtrace
/// while `-O` and `--json` reported the same condition as a clean failure.
fn write_stdout(text: &str) -> bool {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => true,
        Err(e) => {
            tracing::error!("Failed to write report: {e}");
            false
        }
    }
}

/// Generate post-capture reports (`--report`, `--call-report`) from the
/// final store contents. Returns `false` when a requested report could not
/// be produced (unknown `--call-report` Call-ID) so the caller can exit
/// non-zero — scripts must be able to trust the exit code.
///
/// # Side effects
///
/// Prints the requested reports to stdout, the not-found error (and the
/// opt-in `SIPNAB_PERF_STATS=1` perf line) to stderr; reads the
/// `SIPNAB_PERF_STATS` environment variable.
pub fn generate_reports(cli: &Cli, dialog_store: &DialogStore, stream_store: &StreamStore) -> bool {
    // SNB-0015 probe: set SIPNAB_PERF_STATS=1 to surface the per-run work that
    // scales with call count. `endpoint_link_scan_visits` is the cost that was
    // O(calls²) before the endpoint index; it now grows ~linearly with streams.
    // A value near streams² means the quadratic regression is back.
    if std::env::var_os("SIPNAB_PERF_STATS").is_some() {
        eprintln!(
            "[perf-stats] dialogs={} streams={} endpoint_link_scan_visits={} evict_shift_work={}",
            dialog_store.len(),
            stream_store.len(),
            stream_store.link_scan_iters(),
            stream_store.evict_shift_work(),
        );
    }

    // --report: dialog summary table
    if cli.report && cli.no_tui {
        let dialogs: Vec<&crate::sip::dialog::SipDialog> = dialog_store.iter().collect();
        let streams: Vec<&crate::rtp::stream::RtpStream> = stream_store.iter().collect();
        let report = output::print_dialog_report(&dialogs, &streams);
        // `print!` PANICS if stdout cannot be written, so `--report > /full/disk`
        // died with exit 101 and a Rust backtrace instead of an error. A closed
        // pipe stays fine — `sipnab --report | head` must not fail — but a real
        // write error makes the report incomplete, which is a failed report.
        if !write_stdout(&report) {
            return false;
        }
    }

    // --plugin: load once, before the emit loop. A plugin that cannot load is
    // reported and skipped rather than failing the run — the capture already
    // happened, and throwing it away because an optional extension was
    // misconfigured would lose real data over a configuration error.
    #[cfg(feature = "plugins")]
    let plugins: Vec<crate::plugin::Plugin> = cli
        .plugin
        .iter()
        .filter_map(|path| match crate::plugin::Plugin::load(path) {
            Ok(p) => {
                tracing::info!("loaded plugin {}", p.name());
                Some(p)
            }
            Err(e) => {
                tracing::error!("plugin {}: {e}", path.display());
                None
            }
        })
        .collect();

    // --json-dialogs: one NDJSON object per dialog
    if cli.json_dialogs && cli.no_tui {
        let mut out = String::new();
        for dialog in dialog_store.iter() {
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                stream_store.streams_for(&dialog.call_id).collect();
            let mut diagnosis = crate::rtp::diagnosis::diagnose_media(&dialog_streams, None);
            crate::rtp::diagnosis::diagnose_asymmetry(
                &mut diagnosis,
                Some(dialog),
                &dialog_streams,
                &crate::rtp::diagnosis::AsymmetryThresholds::default(),
            );
            let line = output::dialog_to_ndjson(dialog, &dialog_streams, &diagnosis);

            #[cfg(feature = "plugins")]
            let line = apply_plugins(&plugins, dialog, &line);

            out.push_str(&line);
        }
        // Same write discipline as --report: a real write error means the
        // output is incomplete, which is a failed run, while a closed pipe
        // (`| head`) stays fine.
        if !write_stdout(&out) {
            return false;
        }
    }

    // --call-report <call-id>: detailed single-call report
    if let Some(ref call_id) = cli.call_report {
        if let Some(dialog) = dialog_store.get(call_id) {
            let dialog_streams: Vec<&crate::rtp::stream::RtpStream> =
                stream_store.streams_for(call_id).collect();
            let mut diagnosis = crate::rtp::diagnosis::diagnose_media(&dialog_streams, None);
            crate::rtp::diagnosis::diagnose_asymmetry(
                &mut diagnosis,
                Some(dialog),
                &dialog_streams,
                &crate::rtp::diagnosis::AsymmetryThresholds::default(),
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
            // eprintln (not tracing) so the failure is visible even with
            // logging off — it decides the process exit code.
            eprintln!("Call-ID '{call_id}' not found in tracked dialogs");
            return false;
        }
    }
    true
}

// ── Unit tests for the batch runner's pure helpers ──────────────────────
/// Unit tests for the batch runner's pure helpers: output dispatch, report
/// generation, packet processing, targeted kills, and emit selection.
/// Run every loaded plugin over one dialog and fold their findings into the
/// emitted JSON line.
///
/// Findings land under a top-level `plugin_findings` array rather than inside
/// `signaling_diagnosis`. Keeping them separate means a reader can always tell
/// which findings sipnab stands behind and which came from third-party code —
/// and it keeps `signaling_diagnosis` matching its schema, which is
/// `additionalProperties: false`.
///
/// A plugin error is logged against that dialog and the line is emitted
/// unchanged. Losing one plugin's opinion must not cost the dialog.
#[cfg(feature = "plugins")]
fn apply_plugins(
    plugins: &[crate::plugin::Plugin],
    dialog: &crate::sip::dialog::SipDialog,
    line: &str,
) -> String {
    if plugins.is_empty() {
        return line.to_string();
    }
    let trimmed = line.trim_end();
    let input = crate::plugin::plugin_input_json(dialog, trimmed);

    let mut findings = Vec::new();
    for p in plugins {
        match p.analyze(&input) {
            Ok(fs) => findings.extend(fs),
            Err(e) => tracing::error!("plugin {} on {}: {e}", p.name(), dialog.call_id),
        }
    }
    if findings.is_empty() {
        return line.to_string();
    }

    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return line.to_string();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "plugin_findings".to_string(),
            serde_json::to_value(&findings).unwrap_or(serde_json::Value::Null),
        );
    }
    let mut out = value.to_string();
    out.push('\n');
    out
}

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

    /// The companion-server wait loop exits only once a stdio MCP client has
    /// actually closed its end — never for an HTTP/API-only run, and not while
    /// a stdio client is still connected. Guards the exit path that stops a
    /// finished-stdio run from spinning until SIGINT.
    #[test]
    fn mcp_stdio_client_gone_signals_exit_only_when_flag_set() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // No stdio MCP client (HTTP/API-only run): the loop keeps running and
        // exits on a signal instead, so this must stay false.
        assert!(!mcp_stdio_client_gone(None));

        // A stdio client is connected but has not closed stdin yet: keep serving.
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!mcp_stdio_client_gone(Some(&flag)));

        // The client closed stdin -> the serve task flipped the flag -> exit.
        flag.store(true, Ordering::Relaxed);
        assert!(mcp_stdio_client_gone(Some(&flag)));
    }

    /// Raw bytes of a minimal but well-formed SIP INVITE for `call_id`.
    /// (`crate::test_utils` is `#[cfg(test)]`-gated in the lib and so is not
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

    /// A UDP `ParsedPacket` from 10.0.0.1 to 10.0.0.2 carrying `payload`.
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
            from_hep: false,
        }
    }

    /// Raw bytes of an INVITE whose SDP negotiates a telephone-event codec at
    /// payload type `pt` and `clock` Hz, with media at 10.0.0.2:`media_port`.
    fn invite_with_te_sdp(call_id: &str, media_port: u16, pt: u8, clock: u32) -> Vec<u8> {
        let sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 10.0.0.2\r\n\
             s=-\r\n\
             c=IN IP4 10.0.0.2\r\n\
             t=0 0\r\n\
             m=audio {media_port} RTP/AVP {pt}\r\n\
             a=rtpmap:{pt} telephone-event/{clock}\r\n"
        );
        let headers = [
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-te".to_string(),
            "From: Alice <sip:alice@example.com>;tag=a1b2".to_string(),
            "To: Bob <sip:bob@example.com>".to_string(),
            format!("Call-ID: {call_id}"),
            "CSeq: 1 INVITE".to_string(),
            "Max-Forwards: 70".to_string(),
            "Contact: <sip:alice@10.0.0.1:5060>".to_string(),
            "Content-Type: application/sdp".to_string(),
            format!("Content-Length: {}", sdp.len()),
        ];
        let mut msg = String::from("INVITE sip:bob@example.com SIP/2.0\r\n");
        for h in headers {
            msg.push_str(&h);
            msg.push_str("\r\n");
        }
        msg.push_str("\r\n");
        msg.push_str(&sdp);
        msg.into_bytes()
    }

    /// A UDP RTP packet to 10.0.0.2:`dst_port` carrying a completed RFC 4733
    /// telephone-event (E bit set) for `event` with `duration_ts` timestamp
    /// units, using RTP payload type `pt` and the given `ssrc`.
    fn rtp_dtmf_packet(
        dst_port: u16,
        pt: u8,
        ssrc: u32,
        event: u8,
        duration_ts: u16,
    ) -> ParsedPacket {
        let mut payload: Vec<u8> = vec![
            0x80,      // V=2, no padding/extension, 0 CSRC
            pt & 0x7F, // marker=0 + payload type
            0x00,
            0x01, // sequence
            0x00,
            0x00,
            0x00,
            0x00, // RTP timestamp
        ];
        payload.extend_from_slice(&ssrc.to_be_bytes());
        // telephone-event descriptor: event, E-bit(0x80)+volume, duration.
        payload.push(event);
        payload.push(0x80);
        payload.extend_from_slice(&duration_ts.to_be_bytes());
        ParsedPacket {
            timestamp: chrono::Utc::now(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 40001,
            dst_port,
            transport: TransportProto::Udp,
            payload: bytes::Bytes::from(payload),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        }
    }

    /// Drive an ordered sequence of packets through one shared set of stores
    /// (so an SDP offer seen in packet N informs stream resolution for a later
    /// RTP packet) and return the number of DTMF digits decoded.
    fn drive_packets_dtmf(cli: &Cli, packets: &[ParsedPacket], portrange: (u16, u16)) -> u64 {
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
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
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
        let mut sink = output::BatchSink::new(Vec::new(), false);
        for pp in packets {
            let mut state = ProcessingState {
                dialog_store: &mut dialog_store,
                stream_store: &mut stream_store,
                rtp_heuristic: &mut rtp_heuristic,
                event_exec: &mut event_exec,
                #[cfg(feature = "tls")]
                srtp: None,
                #[cfg(feature = "tls")]
                dtls: None,
                group: None,
            };
            process_parsed_packet(pp, &ctx, &mut state, &mut engines, &mut counters, &mut sink);
        }
        counters.dtmf_count
    }

    /// A telephone-event stream negotiated at a non-101 payload type must be
    /// decoded using the SDP-negotiated PT — not the hard-coded 101. Feeding
    /// the SDP offer (PT 96) then an RTP DTMF packet with PT 96 yields one
    /// decoded digit; the pre-fix code (expecting PT 101) decoded zero.
    #[test]
    fn dtmf_honors_negotiated_non_101_payload_type() {
        let mut cli = base_cli();
        cli.telephone_event = true;
        let packets = [
            parsed_sip_packet(invite_with_te_sdp("dtmf-96@x", 40000, 96, 8000), 5060, 5060),
            rtp_dtmf_packet(40000, 96, 0x1111_2222, 5, 800),
        ];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "negotiated PT 96 telephone-event must decode");
    }

    /// The negotiated telephone-event clock rate is plumbed through alongside
    /// the PT: a wideband (16000 Hz) rtpmap still decodes the completed event.
    /// (Both PT and clock come from the same resolved-stream lookup, so a
    /// non-default clock also exercises the clock-rate wiring.)
    #[test]
    fn dtmf_honors_negotiated_wideband_clock() {
        let mut cli = base_cli();
        cli.telephone_event = true;
        let packets = [
            parsed_sip_packet(
                invite_with_te_sdp("dtmf-wb@x", 40000, 100, 16000),
                5060,
                5060,
            ),
            rtp_dtmf_packet(40000, 100, 0x3333_4444, 7, 320),
        ];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "negotiated 16 kHz telephone-event must decode");
    }

    /// With no SDP telephone-event negotiation seen, the PT 101 convention is
    /// the fallback: a PT-101 DTMF packet still decodes.
    #[test]
    fn dtmf_falls_back_to_pt_101_without_sdp() {
        let mut cli = base_cli();
        cli.telephone_event = true;
        let packets = [rtp_dtmf_packet(40000, 101, 0x5555_6666, 9, 800)];
        let dtmf = drive_packets_dtmf(&cli, &packets, (5060, 5061));
        assert_eq!(dtmf, 1, "PT 101 fallback must decode when no SDP is seen");
    }

    // ── tshark_input_file ──────────────────────────────────────────────

    /// The input file (`-I`) is preferred, and wins over any output file.
    #[test]
    fn tshark_input_file_prefers_input() {
        assert_eq!(
            tshark_input_file(Some("in.pcap"), Some("out.pcap")).unwrap(),
            "in.pcap"
        );
        assert_eq!(tshark_input_file(Some("in.pcap"), None).unwrap(), "in.pcap");
    }

    /// A custom `--tshark-filter` on a live capture WITHOUT `-I` references
    /// the real saved pcap (`-O`) instead of the old `capture.pcap` placeholder.
    #[test]
    fn tshark_input_file_custom_filter_without_input_uses_output() {
        let f = tshark_input_file(None, Some("saved.pcap"))
            .expect("a saved output file is a valid tshark source");
        assert_eq!(f, "saved.pcap");
    }

    /// A live capture with neither `-I` nor `-O` has no pcap for tshark to
    /// read: error clearly rather than emitting a bogus `capture.pcap`.
    #[test]
    fn tshark_input_file_no_input_no_output_errors() {
        let err = tshark_input_file(None, None)
            .expect_err("no pcap source must be an error, not a placeholder");
        assert!(!err.contains("capture.pcap"), "must not name a placeholder");
        assert!(err.contains("-I") && err.contains("-O"), "got: {err}");
    }

    // ── dispatch_sip_output ────────────────────────────────────────────

    /// Every output backend (default text, JSON, pretty JSON, fail2ban, raw
    /// dump, suppressed, line-buffered) produces its expected bytes.
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
        // Force color OFF so the expected text output is deterministic even
        // when the test runner is attached to a TTY.
        let opts = OutputOptions {
            color: output::ColorMode::Never,
            ..Default::default()
        };
        let sink_bytes = |cli: &Cli, prev: Option<chrono::DateTime<chrono::Utc>>| {
            let mut sink = output::BatchSink::new(Vec::new(), cli.line_buffer);
            dispatch_sip_output(&msg, &opts, cli, prev, &mut sink, None);
            sink.into_inner()
        };

        // Default sipgrep-style print: byte-identical to format_sip_message.
        let out = sink_bytes(&base_cli(), None);
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            crate::output::cli_print::format_sip_message(&msg, &opts, None),
        );

        // JSON: byte-identical to message_to_json (NDJSON line + newline).
        let mut cli = base_cli();
        cli.json = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).expect("utf8"),
            output::json::message_to_json(&msg),
        );

        // Pretty JSON: byte-identical to message_to_json_pretty.
        let mut cli = base_cli();
        cli.json_pretty = true;
        assert_eq!(
            String::from_utf8(sink_bytes(&cli, None)).expect("utf8"),
            output::json::message_to_json_pretty(&msg),
        );

        // fail2ban (request path): one event line.
        let mut cli = base_cli();
        cli.fail2ban = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).expect("utf8");
        assert!(
            out.contains("10.0.0.1") && out.ends_with('\n'),
            "fail2ban event line expected, got {out:?}"
        );

        // raw text dump: raw message + newline.
        let mut cli = base_cli();
        cli.text_dump = true;
        let out = String::from_utf8(sink_bytes(&cli, None)).expect("utf8");
        assert!(out.starts_with("INVITE sip:bob@example.com SIP/2.0"));
        assert!(out.ends_with('\n'));

        // suppressed entirely.
        let mut cli = base_cli();
        cli.no_cli_print = true;
        assert!(sink_bytes(&cli, None).is_empty());

        // line-buffer flush branch still writes the message.
        let mut cli = base_cli();
        cli.line_buffer = true;
        assert!(!sink_bytes(&cli, Some(chrono::Utc::now())).is_empty());
    }

    // ── generate_reports ───────────────────────────────────────────────

    /// `--report` and `--call-report` run without panicking on empty stores,
    /// unknown Call-IDs, and a tracked dialog across all report formats.
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

        let formats: [fn(&mut Cli); 3] = [|_c| {}, |c| c.json = true, |c| c.markdown = true];
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
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
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
            #[cfg(feature = "tls")]
            srtp: None,
            #[cfg(feature = "tls")]
            dtls: None,
            group: None,
        };

        process_parsed_packet(
            pp,
            &ctx,
            &mut state,
            &mut engines,
            &mut counters,
            &mut output::BatchSink::new(Vec::new(), false),
        );
        (counters.sip_count, counters.rtp_count)
    }

    /// Drive one packet with `--kill-target` directives active and return the
    /// detail lines of any "scanner" findings the alert engine recorded. Uses
    /// `kill_handle: None`, so no socket send is attempted — the targeted-kill
    /// alert still fires before the (absent) worker handoff.
    fn drive_kill_targets(cli: &Cli, pp: &ParsedPacket, targets: &[&str]) -> Vec<String> {
        let matcher = SipMatcher::new(cli, None).expect("matcher");
        let filter_expr: Option<FilterExpr> = None;
        let output_opts = OutputOptions::default();
        let mut dialog_store = DialogStore::new(100, false);
        let mut stream_store = StreamStore::new(100);
        let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();
        let mut event_exec = EventExecEngine::new(None, None, 0, 0.0);

        let kill_targets = targets
            .iter()
            .map(|s| sec::scanner_kill::KillTarget::parse(s).expect("valid target"))
            .collect();
        let alerts = Arc::new(RwLock::new(AlertEngine::new(Vec::new(), None)));
        let mut engines = DetectionEngines {
            scanner: None,
            fraud: None,
            digest: None,
            reg_flood: None,
            alerts: Arc::clone(&alerts),
            kill_handle: None,
            kill_response_code: 200,
            kill_targets,
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
        };
        let ctx = BatchContext {
            matcher: &matcher,
            filter_expr: &filter_expr,
            output_opts: &output_opts,
            cli,
            no_rtp: false,
            after_count: 0,
            portrange: (5060, 5061),
        };
        let mut state = ProcessingState {
            dialog_store: &mut dialog_store,
            stream_store: &mut stream_store,
            rtp_heuristic: &mut rtp_heuristic,
            event_exec: &mut event_exec,
            #[cfg(feature = "tls")]
            srtp: None,
            #[cfg(feature = "tls")]
            dtls: None,
            group: None,
        };
        process_parsed_packet(
            pp,
            &ctx,
            &mut state,
            &mut engines,
            &mut counters,
            &mut output::BatchSink::new(Vec::new(), false),
        );

        alerts
            .read()
            .iter_findings(&["scanner"], None, 16)
            .into_iter()
            .map(|f| f.detail.clone())
            .collect()
    }

    /// A request whose source IP:port falls inside a `--kill-target` range
    /// fires a kill-target scanner alert.
    #[test]
    fn kill_target_matching_request_fires_kill_alert() {
        // parsed_sip_packet sources from 10.0.0.1; src_port 5075 is inside the
        // target's 5060-5090 range → the targeted kill must fire.
        let mut cli = base_cli();
        cli.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-hit@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"]);
        assert!(
            details.iter().any(|d| d.contains("detection=kill-target")),
            "expected a kill-target alert, got {details:?}"
        );
    }

    /// A source port outside the target's range must not trigger a kill.
    #[test]
    fn kill_target_out_of_range_port_does_not_fire() {
        // src_port 6000 is outside 5060-5090 → no targeted kill.
        let mut cli = base_cli();
        cli.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-miss@example.com"), 6000, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.1:5060-5090"]);
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a source outside the port range, got {details:?}"
        );
    }

    /// A source IP different from the target's must not trigger a kill.
    #[test]
    fn kill_target_wrong_ip_does_not_fire() {
        // Target a different IP than the packet's source (10.0.0.1) → no kill.
        let mut cli = base_cli();
        cli.no_cli_print = true;
        let pp = parsed_sip_packet(invite_bytes("kt-ip@example.com"), 5075, 5060);
        let details = drive_kill_targets(&cli, &pp, &["10.0.0.99:5060-5090"]);
        assert!(
            !details.iter().any(|d| d.contains("kill-target")),
            "should not kill a non-targeted source IP, got {details:?}"
        );
    }

    /// Drive a packet through `process_parsed_packet` with an active SRTP
    /// context, returning the rtp_count so wiring can be asserted.
    #[cfg(feature = "tls")]
    fn drive_packet_with_srtp(
        cli: &Cli,
        pp: &ParsedPacket,
        portrange: (u16, u16),
        srtp: &mut crate::rtp::srtp::SrtpContext,
    ) -> u64 {
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
            kill_targets: Vec::new(),
        };
        let mut counters = PacketCounters {
            sip_count: 0,
            rtp_count: 0,
            prev_timestamp: None,
            trailing_remaining: 0,
            followed_dialogs: std::collections::HashSet::new(),
            dtmf_count: 0,
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
            srtp: Some(srtp),
            dtls: None,
            group: None,
        };
        process_parsed_packet(
            pp,
            &ctx,
            &mut state,
            &mut engines,
            &mut counters,
            &mut output::BatchSink::new(Vec::new(), false),
        );
        counters.rtp_count
    }

    /// A plaintext (non-SRTP) RTP packet must pass through an active SRTP
    /// context untouched: the auth tag never verifies on ordinary RTP, so the
    /// pipeline must NOT mangle it as a false "decryption". This guards the
    /// wiring's safety property at the binary layer.
    #[cfg(feature = "tls")]
    #[test]
    fn srtp_context_never_false_decrypts_plain_rtp() {
        use crate::rtp::srtp::{SrtpContext, SrtpKeyMaterial, SrtpSuite};

        // A loaded context with one master key.
        let key = SrtpKeyMaterial {
            tag: 1,
            suite: SrtpSuite::AesCm128HmacSha1_80,
            master_key: vec![0x01u8; 16],
            master_salt: vec![0x02u8; 14],
            ssrc: None,
            media_addr: None,
            media_port: None,
        };
        let mut srtp = SrtpContext::new(vec![key], crate::crypto::default_backend());

        // Ordinary RTP: 12-byte header (V=2, PT=0/PCMU) + 20 bytes payload.
        let mut payload = vec![0x80u8, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x10, 0x00];
        payload.extend_from_slice(&[0x00, 0x00, 0xAB, 0xCD]); // SSRC
        payload.extend_from_slice(&[0x7Fu8; 20]); // PCMU silence-ish payload
        let pp = ParsedPacket {
            payload: payload.into(),
            ..parsed_sip_packet(invite_bytes("x@y"), 40000, 40000)
        };

        let mut cli = base_cli();
        cli.no_cli_print = true;
        let rtp = drive_packet_with_srtp(&cli, &pp, (5060, 5061), &mut srtp);
        assert_eq!(rtp, 1, "the RTP packet must still be counted/processed");
        assert_eq!(
            srtp.decrypted_count, 0,
            "ordinary RTP must never be falsely decrypted (auth-tag gate)"
        );
    }

    /// A valid INVITE on the SIP port increments the SIP counter.
    #[test]
    fn process_parsed_packet_counts_sip() {
        let mut cli = base_cli();
        cli.no_cli_print = true; // keep test output quiet
        let pp = parsed_sip_packet(invite_bytes("ppp-1@example.com"), 5060, 5060);
        let (sip, _rtp) = drive_packet(&cli, &pp, (5060, 5061));
        assert_eq!(sip, 1, "one SIP message should be counted");
    }

    /// Garbage payloads and SIP messages outside the port range are not
    /// counted as SIP.
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

    // ── decide_emit: dialog-following (`-e`) + trailing context (`-A`) ────

    use std::collections::HashSet;

    /// Convenience: run decide_emit with fresh trailing/no -A, follow on.
    fn emit_follow(direct: bool, call_id: Option<&str>, followed: &mut HashSet<String>) -> bool {
        let mut trailing = 0usize;
        decide_emit(direct, call_id, true, followed, &mut trailing, 0)
    }

    /// A direct match arms its dialog; later non-matching messages of that
    /// dialog still emit while unrelated dialogs stay silent.
    #[test]
    fn follow_arms_dialog_then_emits_rest() {
        let mut followed = HashSet::new();
        // A direct match on dialog X arms it and emits.
        assert!(emit_follow(true, Some("X"), &mut followed));
        // A later non-matching message of X is still emitted (followed).
        assert!(emit_follow(false, Some("X"), &mut followed));
        assert!(emit_follow(false, Some("X"), &mut followed));
        // An unrelated dialog Y that never matched is not emitted.
        assert!(!emit_follow(false, Some("Y"), &mut followed));
    }

    /// With follow off, matching is strictly per-message and no dialog is
    /// ever armed.
    #[test]
    fn no_follow_when_expression_absent() {
        // follow_dialogs = false → per-message semantics, no arming.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        assert!(decide_emit(
            true,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            0
        ));
        // Next non-matching message of X must NOT be emitted (no dialog-follow).
        assert!(!decide_emit(
            false,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            0
        ));
        assert!(
            followed.is_empty(),
            "follow set must stay empty when inactive"
        );
    }

    /// `-A 2` without follow: a match shows the next two messages, then the
    /// budget is exhausted.
    #[test]
    fn trailing_context_preserved_without_follow() {
        // -A 2, no match-expression: a match shows the next 2 messages, then stops.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        assert!(decide_emit(
            true,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 2);
        assert!(decide_emit(
            false,
            Some("X"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 1);
        assert!(decide_emit(
            false,
            Some("Y"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
        assert_eq!(trailing, 0);
        // Budget exhausted → no more trailing emits.
        assert!(!decide_emit(
            false,
            Some("Z"),
            false,
            &mut followed,
            &mut trailing,
            2
        ));
    }

    /// A followed-dialog message emits without spending the `-A` budget;
    /// only pure trailing-context messages consume it.
    #[test]
    fn followed_messages_do_not_consume_trailing_budget() {
        // With both -A 1 and a match-expression: a followed-dialog message is
        // emitted but must not spend the trailing budget meant for context.
        let mut followed = HashSet::new();
        let mut trailing = 0usize;
        // Direct match on X arms X and sets trailing budget to 1.
        assert!(decide_emit(
            true,
            Some("X"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 1);
        // A followed message of X emits but leaves the budget untouched.
        assert!(decide_emit(
            false,
            Some("X"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 1, "followed message must not decrement -A budget");
        // An unrelated dialog Y consumes the trailing budget as pure context.
        assert!(decide_emit(
            false,
            Some("Y"),
            true,
            &mut followed,
            &mut trailing,
            1
        ));
        assert_eq!(trailing, 0);
    }

    /// A match without a Call-ID emits but cannot arm any dialog.
    #[test]
    fn follow_with_missing_call_id_does_not_arm_or_panic() {
        // A direct match with no Call-ID cannot arm any dialog.
        let mut followed = HashSet::new();
        assert!(emit_follow(true, None, &mut followed));
        assert!(followed.is_empty(), "no Call-ID must not arm a dialog");
        // A subsequent Call-ID-less non-match is not emitted.
        assert!(!emit_follow(false, None, &mut followed));
    }

    /// Call-IDs with NUL/backslash/tab bytes round-trip through the follow
    /// set without corruption.
    #[test]
    fn follow_handles_adversarial_call_id_bytes() {
        // Call-IDs with backslashes / embedded NUL must round-trip through the
        // follow set unharmed.
        let weird = "call\u{0}id\\weird\t";
        let mut followed = HashSet::new();
        assert!(emit_follow(true, Some(weird), &mut followed));
        assert!(emit_follow(false, Some(weird), &mut followed));
        assert!(!emit_follow(false, Some("other"), &mut followed));
    }
}
