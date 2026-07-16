//! Batch (non-interactive) mode: the state and receive loop behind every
//! headless run (`--no-tui`, `--mcp`, replay, `--cores`).
//!
//! [`BatchRunner`] owns what used to be ~25 loose locals in main.rs — the
//! writer, detector engines, decryption state, counters, and companion-server
//! handles — built once in `BatchRunner::new` and consumed by the receive
//! loop. [`run`] is the single entry point the binary dispatches to (WS2).

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
    scanner: Option<ScannerDetector>,
    fraud: Option<FraudDetector>,
    digest: Option<DigestLeakDetector>,
    reg_flood: Option<RegFloodDetector>,
    /// Shared with the MCP server (when --mcp is on) so the
    /// `security_findings` tool can read the FindingsHistory ring buffer.
    alerts: Arc<RwLock<AlertEngine>>,
    kill_handle: Option<ScannerKillHandle>,
    kill_response_code: u16,
    /// Targeted-kill directives (`-K` / `--kill-target`): any SIP request whose
    /// source matches is killed regardless of UA/behavioral detection.
    kill_targets: Vec<sec::scanner_kill::KillTarget>,
}

/// Packet processing counters and state.
struct PacketCounters {
    sip_count: u64,
    rtp_count: u64,
    prev_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    trailing_remaining: usize,
    /// Call-IDs of dialogs "armed" by a `-e` payload match. Once a dialog is
    /// armed, every subsequent message of it is emitted (dialog-following).
    followed_dialogs: std::collections::HashSet<String>,
}

/// Owned batch-mode processing components, built by the binary's
/// bootstrap and handed to [`run`].
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
    /// SRTP decryption context (keys from `--srtp-keys` + SDES `a=crypto`),
    /// used to authenticate and decrypt RTP payloads before media analysis.
    #[cfg(feature = "tls")]
    srtp: Option<&'a mut crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP extractor (`--dtls-keylog`): recovers SRTP keys from observed
    /// DTLS handshakes and feeds them into `srtp`.
    #[cfg(feature = "tls")]
    dtls: Option<&'a mut crate::capture::dtls::DtlsSrtpExtractor>,
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

/// Multi-core offline file reconstruction (`--cores N` with `-I file`,
/// single device): read the pcap directly and shard packets across N worker
/// threads, fusing read+peek+shard into one stage — no capture reader
/// thread, no semaphore channel. Reports and exits; advanced per-message
/// features use the single-threaded path.
pub fn run_cores_file(
    cli: &Cli,
    config: &Config,
    capture_config: &CaptureConfig,
    portrange: (u16, u16),
) {
    let Some(input) = cli.input.as_ref() else {
        return;
    };
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    let pcfg = crate::parallel::ParallelConfig {
        cores: cli.cores,
        max_streams: cli.max_streams as usize,
        max_dialogs: cli.limit as usize,
        rotate: cli.rotate_enabled(),
        max_reassembly: cli.max_reassembly as usize,
        portrange,
        no_dialog: cli.no_dialog,
        no_rtp,
        xcid_headers: config.sip.xcid_headers.clone().unwrap_or_default(),
        reassembly: !cli.no_reassembly,
        parse_limit: cli.limitlen,
    };
    match crate::parallel::run_offline_parallel_file(
        std::path::Path::new(input),
        capture_config,
        pcfg,
    ) {
        Ok(r) => {
            generate_reports(cli, &r.dialog_store, &r.stream_store);
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
}

/// Run batch mode to completion: the multi-core offline fast path when
/// `--cores N` applies, otherwise the single-threaded [`BatchRunner`].
pub fn run(
    cli: Cli,
    config: &Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: capture::channel::PacketRx,
    batch: BatchProcessing,
    policy: CapturePolicy,
) {
    let portrange = policy.portrange;
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);
    // 17p. Offline multi-core reconstruction (`--jobs N`, N>1). Shard parsed
    // packets by host pair across N workers with thread-local stores, merge, and
    // report — covers dialog + RTP-stream reconstruction and `--report`/`--json`.
    // Advanced features (live, per-message output ordering, security detectors,
    // SRTP) use the single-threaded path below; this branch only triggers for an
    // offline input file.
    if cli.cores > 1 && cli.input.is_some() {
        let pcfg = crate::parallel::ParallelConfig {
            cores: cli.cores,
            max_streams: cli.max_streams as usize,
            max_dialogs: cli.limit as usize,
            rotate: cli.rotate_enabled(),
            max_reassembly: cli.max_reassembly as usize,
            portrange,
            no_dialog: cli.no_dialog,
            no_rtp,
            xcid_headers: config.sip.xcid_headers.clone().unwrap_or_default(),
            reassembly: !cli.no_reassembly,
            parse_limit: cli.limitlen,
        };
        let result = crate::parallel::run_offline_parallel(rx, pcfg);
        let _ = handle.thread.join();
        generate_reports(&cli, &result.dialog_store, &result.stream_store);
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
        return;
    }

    BatchRunner::new(cli, config, batch, policy).run_loop(capture_config, handle, rx);
}

/// All owned batch-mode state: writer, detector engines, decryption state,
/// stores, and companion-server handles. Built once by `BatchRunner::new`
/// (bootstrap steps 16-17), consumed by `BatchRunner::run_loop` (step 18).
pub struct BatchRunner {
    cli: Cli,
    config: Config,
    matcher: SipMatcher,
    filter_expr: Option<FilterExpr>,
    output_opts: OutputOptions,
    event_exec: EventExecEngine,
    writer: Option<PcapWriter>,
    use_pcapng: bool,
    export_mode: PcapExportMode,
    #[cfg(feature = "hep")]
    hep_sender: Option<crate::capture::hep::HepSender>,
    processor: capture::PacketProcessor,
    dialog_store: Arc<RwLock<DialogStore>>,
    stream_store: Arc<RwLock<StreamStore>>,
    rtp_heuristic: rtp::heuristic::RtpHeuristic,
    no_rtp: bool,
    engines: DetectionEngines,
    #[cfg(feature = "tls")]
    tls_decryptor: Option<TlsDecryptor>,
    #[cfg(feature = "tls")]
    srtp_context: Option<crate::rtp::srtp::SrtpContext>,
    #[cfg(feature = "tls")]
    dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor>,
    servers: Option<crate::app::servers::ServerHandles>,
    policy: CapturePolicy,
}

impl BatchRunner {
    /// Build every piece of batch state (bootstrap steps 16-17): output
    /// writer policy, HEP sender, stores, security detectors + alert engine,
    /// TLS/SRTP/DTLS decryption state, and the companion servers.
    fn new(cli: Cli, config: &Config, batch: BatchProcessing, policy: CapturePolicy) -> Self {
        let matcher = batch.matcher;
        let filter_expr = batch.filter_expr;
        let output_opts = batch.output_opts;
        let event_exec = batch.event_exec;
        // 16. Open output writer if -O is specified
        let writer: Option<PcapWriter> = None;
        let use_pcapng = cli.pcapng;
        let export_mode =
            PcapExportMode::parse_mode(&cli.pcap_export_mode).unwrap_or(PcapExportMode::Decrypted);

        // 16a. Initialize HEP sender if --hep-send is set
        #[cfg(feature = "hep")]
        let hep_sender: Option<crate::capture::hep::HepSender> =
            if let Some(ref addr) = cli.hep_send {
                let capture_id = cli.hep_id.unwrap_or(1);
                match crate::capture::hep::HepSender::new(addr, capture_id, cli.hep_auth.clone()) {
                    Ok(sender) => {
                        tracing::info!(
                            "HEP sender targeting {addr} (capture id {capture_id}{})",
                            if cli.hep_auth.is_some() {
                                ", authenticated"
                            } else {
                                ""
                            }
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
            DialogStore::new(cli.limit as usize, cli.rotate_enabled())
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
        if cli.alert_json {
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
                                    tracing::error!("Failed to load --tls-key {keyfile}: {e}");
                                    std::process::exit(1);
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
        if let Some(ref input) = cli.input {
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
                        tracing::error!("Failed to load --srtp-keys {keyfile}: {e}");
                        std::process::exit(1);
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
                        tracing::error!("Failed to load --dtls-keylog {keylog}: {e}");
                        std::process::exit(1);
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
        .unwrap_or_else(|e| {
            tracing::error!("{e}");
            std::process::exit(2);
        });

        Self {
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
        }
    }

    /// The main receive loop (step 18) plus end-of-capture reporting and the
    /// server keep-alive tail. Consumes the runner.
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
            followed_dialogs: std::collections::HashSet::new(),
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
                // Record the capture source as the pcapng interface name (SNB-0001):
                // the capture device for live, the input file for replay.
                let capture_source = cli.device.as_deref().or(cli.input.as_deref());
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
                    };
                    process_parsed_packet(
                        effective_pp,
                        &batch_ctx,
                        &mut proc_state,
                        &mut engines,
                        &mut counters,
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
                if servers
                    .mcp_stdio_done
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
                {
                    tracing::info!("MCP client disconnected — shutting down");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}
// ── Packet processing ─────────────────────────────────────────────────

/// Process a single parsed packet: classify via the shared pipeline core,
/// then apply the batch extras — counters, matcher/DSL filter, output
/// dispatch, security detectors, dialog events, DTMF, quality events.
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

fn process_parsed_packet(
    pp: &ParsedPacket,
    ctx: &BatchContext<'_>,
    state: &mut ProcessingState<'_>,
    engines: &mut DetectionEngines,
    counters: &mut PacketCounters,
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
    let prev_timestamp = &mut counters.prev_timestamp;
    let trailing_remaining = &mut counters.trailing_remaining;
    let followed_dialogs = &mut counters.followed_dialogs;
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

    // Classify via the shared pipeline core (WS unwrap, SIP parse + SDP link
    // extraction, SDES/DTLS key learning, RTCP/RTP/heuristic detection), then
    // apply the action with the batch extras: counters, matcher/DSL filter,
    // output dispatch, security detectors, events, DTMF.
    let opts = crate::pipeline::PipelineOptions {
        no_dialog: cli.no_dialog,
        no_rtp,
        sip_portrange: Some(portrange),
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

            // Targeted scanner kill (sipgrep -K): kill any request whose source
            // matches a --kill-target, independent of UA/behavioral detection.
            if !kill_targets.is_empty()
                && sip_msg.is_request
                && kill_targets
                    .iter()
                    .any(|t| t.matches(sip_msg.src_addr, sip_msg.src_port))
            {
                let method = sip_msg.method.as_ref().map_or("-", |m| m.as_str());
                let ua = sip_msg.user_agent().unwrap_or("-");
                alert_engine.write().fire(
                    "scanner",
                    sip_msg.src_addr,
                    &format!("method={method} ua={ua} detection=kill-target"),
                );
                if cli.fail2ban {
                    let event =
                        output::format_scanner_event(&sip_msg.src_addr.to_string(), ua, method);
                    println!("{event}");
                }
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
                dispatch_sip_output(&sip_msg, output_opts, cli, *prev_timestamp);
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

            // DTMF extraction (I2): if --telephone-event is set and we
            // have the RTP payload after the header, attempt DTMF decode.
            // Uses a default telephone-event PT of 101 (common convention).
            if cli.telephone_event && rtp_hdr.payload_offset < rtp_pp.payload.len() {
                let rtp_payload = &rtp_pp.payload[rtp_hdr.payload_offset..];
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
        // Feed Handshake records (ClientHello/ServerHello/ClientKeyExchange) so
        // the decryptor can capture randoms + the RSA-encrypted pre-master for
        // the --tls-key path and the TLS 1.2 CLIENT_RANDOM keylog path.
        if record.content_type == tls::TlsContentType::Handshake {
            decryptor.process_record(record);
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
    if cli.json_pretty {
        let json = output::json::message_to_json_pretty(msg);
        print!("{json}");
    } else if cli.json {
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

/// Generate post-capture reports (`--report`, `--call-report`) from the
/// final store contents. Returns `false` when a requested report could not
/// be produced (unknown `--call-report` Call-ID) so the caller can exit
/// non-zero — scripts must be able to trust the exit code.
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
        print!("{report}");
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
        };

        process_parsed_packet(pp, &ctx, &mut state, &mut engines, &mut counters);
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
        };
        process_parsed_packet(pp, &ctx, &mut state, &mut engines, &mut counters);

        alerts
            .read()
            .iter_findings(&["scanner"], None, 16)
            .into_iter()
            .map(|f| f.detail.clone())
            .collect()
    }

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
        };
        process_parsed_packet(pp, &ctx, &mut state, &mut engines, &mut counters);
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

    // ── decide_emit: dialog-following (`-e`) + trailing context (`-A`) ────

    use std::collections::HashSet;

    /// Convenience: run decide_emit with fresh trailing/no -A, follow on.
    fn emit_follow(direct: bool, call_id: Option<&str>, followed: &mut HashSet<String>) -> bool {
        let mut trailing = 0usize;
        decide_emit(direct, call_id, true, followed, &mut trailing, 0)
    }

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

    #[test]
    fn follow_with_missing_call_id_does_not_arm_or_panic() {
        // A direct match with no Call-ID cannot arm any dialog.
        let mut followed = HashSet::new();
        assert!(emit_follow(true, None, &mut followed));
        assert!(followed.is_empty(), "no Call-ID must not arm a dialog");
        // A subsequent Call-ID-less non-match is not emitted.
        assert!(!emit_follow(false, None, &mut followed));
    }

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
