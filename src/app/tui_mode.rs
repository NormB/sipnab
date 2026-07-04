//! Interactive TUI mode (WS2c): store setup, the processing thread that
//! drives the shared pipeline, and the terminal main loop. Extracted
//! verbatim from main.rs; deeper decomposition is WS5.

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::capture::{self, CaptureConfig, PcapExportMode, PcapWriter};
use crate::cli::Cli;
use crate::config::Config;
use crate::rtp;
use crate::rtp::stream_store::StreamStore;
use crate::signals;
use crate::sip::dialog_store::DialogStore;

use super::batch::CapturePolicy;

/// Build the TUI name-resolution setup from CLI flags and config:
/// construct the resolver (with a reverse-DNS worker when requested), load the
/// system hosts file plus any operator mapping files, and pick the initial mode.
fn build_name_setup(cli: &Cli, config: &Config) -> crate::tui::NameSetup {
    let cfg = &config.names;
    let (resolver, mode) = crate::app::build_resolver(cli, config);

    // Default persistence file for the in-TUI `N` dialog; preload it.
    let save_path = default_names_path();
    if let Some(p) = &save_path {
        let _ = resolver.load_manual_file(p);
    }
    // Opt-in: also persist `N`-dialog edits into the user's sipnabrc.
    let config_path = if cfg.persist_to_config.unwrap_or(false) {
        crate::config::default_user_config_path()
    } else {
        None
    };

    crate::tui::NameSetup {
        resolver,
        mode,
        save_path,
        config_path,
    }
}

/// Default file where in-TUI manual name mappings persist:
/// `$XDG_CONFIG_HOME/sipnab/hosts`, falling back to `~/.config/sipnab/hosts`.
fn default_names_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config"))
        })?;
    Some(base.join("sipnab").join("hosts"))
}

/// Run interactive TUI mode: wraps stores in `Arc<RwLock>`, spawns the
/// packet-processing thread that drives the shared pipeline, starts the
/// API/metrics companions when configured, and runs the terminal main loop
/// until quit.
pub fn run_tui_mode(
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
        match crate::output::prometheus_server::start_metrics_server(
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
            let mut srtp_context: Option<crate::rtp::srtp::SrtpContext> = {
                let backend = crate::crypto::default_backend();
                match cli_clone.srtp_keys.as_deref() {
                    Some(keyfile) => crate::rtp::srtp::SrtpContext::from_key_file(
                        std::path::Path::new(keyfile),
                        backend,
                    )
                    .map_err(|e| tracing::error!("Failed to load --srtp-keys {keyfile}: {e}"))
                    .ok(),
                    // No key file, but SDES keys may still arrive via SDP.
                    None => Some(crate::rtp::srtp::SrtpContext::new(Vec::new(), backend)),
                }
            };
            #[cfg(feature = "tls")]
            let mut dtls_extractor: Option<crate::capture::dtls::DtlsSrtpExtractor> =
                cli_clone.dtls_keylog.as_deref().and_then(|keylog| {
                    crate::capture::dtls::DtlsSrtpExtractor::from_keylog_file(
                        std::path::Path::new(keylog),
                        crate::crypto::default_backend(),
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
                    let mut media_decrypt = crate::pipeline::MediaDecrypt {
                        srtp: srtp_context.as_mut(),
                        dtls: dtls_extractor.as_mut(),
                    };
                    #[cfg(not(feature = "tls"))]
                    let mut media_decrypt = crate::pipeline::MediaDecrypt::default();
                    crate::pipeline::process_packet(
                        pp,
                        &ds,
                        &ss,
                        &mut rtp_heuristic,
                        &crate::pipeline::PipelineOptions {
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
    let _servers_thread = crate::app::servers::start_servers(
        &cli,
        &dialog_store,
        &stream_store,
        None,
        crate::app::servers::Selection {
            api: true,
            mcp: false,
        },
    )
    .unwrap_or_else(|e| {
        tracing::error!("{e}");
        std::process::exit(2);
    });

    // Build resolved theme and keymap from config
    let theme = crate::tui::Theme::from_config(&config.theme);
    let keymap = crate::tui::Keymap::from_config(&config.keybindings);
    let name_setup = build_name_setup(&cli, &config);

    // From/To column default: CLI flag wins, then the [display] from_to config
    // value (warned + ignored if invalid), else the built-in Default.
    let from_to_mode = cli
        .from_to_mode
        .map(|a| crate::tui::FromToMode::parse(a.as_str()).unwrap_or_default())
        .or_else(|| {
            config.display.from_to.as_deref().and_then(|s| {
                let m = crate::tui::FromToMode::parse(s);
                if m.is_none() {
                    tracing::warn!("ignoring invalid [display] from_to = {s:?}");
                }
                m
            })
        })
        .unwrap_or_default();

    // Run TUI on the main thread
    if let Err(e) = crate::tui::run_tui_with_pause(
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
