// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Account for one received packet against the `--count` limit, honoring the
/// pause state.
///
/// A paused capture still writes packets to the output pcap (so the on-disk
/// capture stays complete) and still advances reassembly, but its packets are
/// NOT analyzed. They must therefore NOT count toward `--count`: if they did,
/// `--count N` could stop the capture mid-pause with packets that were
/// received but never processed. Paused packets leave `total_count` untouched
/// and never trip the limit.
///
/// Returns `true` when, after counting a non-paused packet, `total_count` has
/// reached `max_count` (the caller then stops the capture).
fn count_and_check_limit(paused: bool, total_count: &mut u64, max_count: Option<u64>) -> bool {
    if paused {
        return false;
    }
    *total_count += 1;
    matches!(max_count, Some(max) if *total_count >= max)
}

/// The BPF expression the TUI's status bar reports for this session.
///
/// Reads the RESOLVED capture config — the one `bootstrap::plan` finished —
/// so a live capture that was given no filter reports the encapsulation-aware
/// expression `plan` generated from `--portrange`, which is the one the kernel
/// is enforcing. Taking the operator's typed words instead would report
/// nothing for the default live invocation while packets were being dropped
/// before sipnab saw them, and the status slot is there to explain exactly
/// that class of "where did my calls go".
///
/// # Arguments
///
/// * `capture_config` — the resolved config handed to the capture thread.
///
/// # Returns
///
/// The effective expression, or an empty string when no filter was compiled
/// at all (the normal case for `-I` without one).
fn bpf_status_text(capture_config: &CaptureConfig) -> String {
    capture_config.bpf_filter.clone().unwrap_or_default()
}

/// Build the TUI name-resolution setup from CLI flags and config:
/// construct the resolver (with a reverse-DNS worker when requested), load the
/// system hosts file plus any operator mapping files, and pick the initial mode.
///
/// # Returns
///
/// A `NameSetup` bundling the resolver, the initial name mode, the default
/// persistence path for in-TUI `N`-dialog edits, and (when
/// `[names] persist_to_config` is set) the user's sipnabrc path.
///
/// # Side effects
///
/// Delegates to `crate::app::build_resolver` (reads `/etc/hosts` and mapping
/// files) and additionally preloads the default persistence file when it
/// exists; load failures are ignored.
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
/// Returns `None` when neither `XDG_CONFIG_HOME` nor `HOME` is set.
fn default_names_path() -> Option<std::path::PathBuf> {
    names_path_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

/// The XDG resolution [`default_names_path`] performs, with the environment
/// passed in rather than read.
///
/// Split from the reader because the decision it makes is asymmetric and easy
/// to get wrong in a way nothing would notice: `XDG_CONFIG_HOME` already *is*
/// the config directory and is used verbatim, while `HOME` is not and must
/// have `.config` appended. Get that backwards and every in-TUI `N`-dialog
/// edit is written to, and reloaded from, a path no other sipnab process
/// looks at — a silent loss with no error anywhere. Reading the environment
/// inside the function would make that untestable without mutating
/// process-global state that every other test in this binary shares.
///
/// # Arguments
///
/// * `xdg` — the value of `XDG_CONFIG_HOME`, if set.
/// * `home` — the value of `HOME`, if set.
///
/// # Returns
///
/// `<config dir>/sipnab/hosts`, or `None` when neither variable is set.
fn names_path_from(
    xdg: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let base = xdg
        .map(std::path::PathBuf::from)
        .or_else(|| home.map(|h| std::path::PathBuf::from(h).join(".config")))?;
    Some(base.join("sipnab").join("hosts"))
}

/// Build the two shared stores the TUI and its processing thread both write
/// through, with every CLI flag and config key that shapes them applied.
///
/// Split out of [`run_tui_mode`] because this is the one piece of the mode's
/// wiring that can be exercised without a terminal, and because the wiring is
/// where this mode has actually been wrong: `--dialog-track` was declared,
/// parsed and never handed to the store, so for as long as the flag existed
/// it did nothing at all. The same class of defect took out every `[limits]`
/// key once — parsed, validated, documented, never read. A store built here
/// with a knob dropped looks exactly like one built with it applied, which is
/// why the tests below assert the store's *behaviour* rather than its
/// construction.
///
/// # Returns
///
/// `(dialog_store, stream_store)`, each already wrapped in the `Arc<RwLock<_>>`
/// the TUI thread and the processing thread share.
fn build_stores(
    cli: &Cli,
    config: &Config,
) -> (Arc<RwLock<DialogStore>>, Arc<RwLock<StreamStore>>) {
    let dialog_store = Arc::new(RwLock::new(
        {
            let mut ds = DialogStore::new(cli.dialog_limit(config), cli.rotate_enabled());
            // The wiring whose absence made the old --dialog-track a dead
            // flag: declared, parsed, and never handed to anything.
            ds.set_tracking(cli.dialog_track.unwrap_or_default());
            ds
        }
        .with_xcid_headers(config.sip.xcid_headers.clone().unwrap_or_default()),
    ));
    let stream_store = {
        let mut ss = StreamStore::new(cli.max_streams_limit(config));
        if let Some(max_frames) = config.limits.max_audio_frames {
            ss.set_max_audio_frames(max_frames as usize);
        }
        Arc::new(RwLock::new(ss))
    };
    (dialog_store, stream_store)
}

/// Run interactive TUI mode: wraps stores in `Arc<RwLock>`, spawns the
/// packet-processing thread that drives the shared pipeline, starts the
/// API/metrics companions when configured, and runs the terminal main loop
/// until quit.
///
/// # Arguments
///
/// * `cli` / `config` — parsed flags and loaded configuration (owned; this
///   function is the mode's terminal consumer).
/// * `capture_config` — capture limits (`--count`, `--duration`) the
///   processing thread enforces.
/// * `handle` — the running capture thread's handle; dropped (not joined)
///   on exit.
/// * `rx` — receiving side of the packet channel the processing thread
///   drains.
/// * `policy` — output split policy applied to the optional `-O` writer.
/// * `metrics_bind_addr` — parsed `--metrics` bind address (`metrics`
///   feature builds only).
///
/// # Side effects
///
/// Heavy wiring, in order: optionally starts the standalone Prometheus
/// metrics server; spawns the "tui-processor" thread that drains the packet
/// channel, drives the shared pipeline into the stores, lazily opens and
/// writes the `-O` pcap/pcapng file, decrypts SRTP/DTLS-SRTP media when
/// configured, and sweeps reassembly/idle state every 5 s; starts the REST
/// API companion via `start_servers` (never MCP stdio — the TUI owns
/// stdio); takes over the terminal for the TUI main loop; and on TUI exit
/// requests process-wide shutdown, joins the processing thread, and drops
/// the capture handle. Exits the process on thread-spawn or server-start
/// failure.
pub fn run_tui_mode(
    cli: Cli,
    config: Config,
    capture_config: CaptureConfig,
    handle: capture::CaptureHandle,
    rx: capture::channel::PacketRx,
    policy: CapturePolicy,
    #[cfg(feature = "metrics")] _metrics_bind_addr: Option<std::net::SocketAddr>,
) {
    let no_rtp = cli.no_rtp || config.capture.no_rtp.unwrap_or(false);

    // Read before the capture config moves into the processing thread below.
    let bpf_filter = bpf_status_text(&capture_config);

    let (dialog_store, stream_store) = build_stores(&cli, &config);

    // Shared pause flag between TUI and processing thread
    let paused_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Clone references for the processing thread
    let ds = Arc::clone(&dialog_store);
    let ss = Arc::clone(&stream_store);
    let paused_for_thread = Arc::clone(&paused_flag);
    let cli_clone = cli.clone();
    // Resolved before the move: the thread owns a Cli clone but not the
    // Config, and the cap needs both.
    let reassembly_cap = cli.max_reassembly_limit(&config);

    // Taken BEFORE `rx` moves into the thread below. The meter is a cheap
    // shared handle; `PacketRx` is not `Clone`, so reading it afterwards would
    // be a borrow of a moved value.
    #[cfg(feature = "metrics")]
    let capture_meter = Some(rx.meter());

    // Spawn packet processing thread
    let processing_thread = std::thread::Builder::new()
        .name("tui-processor".to_string())
        .spawn(move || {
            let mut processor = capture::PacketProcessor::with_max_sessions(reassembly_cap)
                .with_reassembly(!cli_clone.no_reassembly)
                .with_parse_limit(cli_clone.limitlen);
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
            // Wall time for a live device, the capture's own timeline for
            // `-I`: the TUI reads files too, and there the packet clock and
            // `Utc::now()` are unrelated. See `batch::SweepClock`.
            let mut sweep_clock = crate::app::batch::SweepClock::new(cli_clone.has_input());
            let sweep_interval = std::time::Duration::from_secs(5);
            let start = std::time::Instant::now();
            let mut total_count: u64 = 0;

            loop {
                if signals::shutdown_requested() {
                    break;
                }

                if let Some(now) = sweep_clock.take_due(sweep_interval) {
                    processor.sweep();
                    ss.write()
                        .mark_orphaned(now.get(), std::time::Duration::from_secs(30));
                    let compacted = ds.write().compact_idle(now.get());
                    if compacted.messages_evicted > 0 {
                        tracing::debug!(
                            "idle-dialog compaction: dropped {} messages from {} dialogs",
                            compacted.messages_evicted,
                            compacted.dialogs_compacted
                        );
                    }
                }

                let packet = match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                    Ok(pkt) => pkt,
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                };

                // Offline, this packet's timestamp is what "now" means to the
                // next sweep. Recorded before parsing so undecoded traffic
                // still advances the clock.
                sweep_clock.observe(packet.timestamp);

                // Lazily initialize writer
                if writer.is_none()
                    && let Some(ref output_path) = cli_clone.output
                {
                    // Record the capture source as the pcapng interface name
                    // (SNB-0001): the capture device for live, input for replay.
                    let capture_source = cli_clone.device.as_deref().or(cli_clone.primary_input());
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

                // Load the pause state once per packet. A paused capture keeps
                // writing to the pcap and advancing reassembly (to prevent
                // buffer overflow and keep TCP reassembly consistent), but its
                // packets are neither analyzed nor counted toward --count.
                let is_paused = paused_for_thread.load(std::sync::atomic::Ordering::Relaxed);

                let parsed_packets = processor.process(&packet);
                if !is_paused {
                    for pp in &parsed_packets {
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
                                quiet_bad_parse: cli_clone.quiet_bad_parse,
                            },
                            &mut media_decrypt,
                        );
                    }
                }

                if count_and_check_limit(is_paused, &mut total_count, capture_config.count) {
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
            metrics: true,
        },
        #[cfg(feature = "metrics")]
        capture_meter,
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
        crate::tui::TuiOptions {
            theme,
            keymap,
            visible_columns: config.display.visible_columns.clone(),
            name_setup,
            from_to_mode,
            // The save dialog writes wherever the analyst types, and the
            // capture on screen is the obvious name to reach for.
            protected_inputs: crate::capture::output_guard::ProtectedInputs::new(
                &cli.input,
                &[],
                cli.recursive,
            ),
            bpf_filter,
        },
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

/// Unit tests for the parts of TUI mode that are reachable without a
/// terminal: the pause/`--count` accounting seam, the store wiring, and the
/// name-persistence path resolution.
#[cfg(test)]
mod tests {
    use super::{bpf_status_text, build_stores, count_and_check_limit, names_path_from};
    use crate::capture::CaptureConfig;
    use crate::cli::Cli;
    use crate::config::Config;
    use crate::sip::dialog_store::DialogTracking;
    use clap::Parser as _;
    use std::path::{Path, PathBuf};

    /// The status bar reports the filter the capture is running with, taken
    /// from the resolved config, so the generated live filter reaches the
    /// screen exactly as the kernel got it — not a summary of it, which an
    /// operator would paste into `tcpdump` and get different traffic.
    #[test]
    fn the_status_text_is_the_resolved_filter_verbatim() {
        let generated = crate::app::bootstrap::auto_bpf_filter(5060, 5061, &[]);
        let config = CaptureConfig {
            bpf_filter: Some(generated.clone()),
            ..Default::default()
        };
        assert_eq!(bpf_status_text(&config), generated);
    }

    /// No compiled filter reports an empty string, which is what leaves the
    /// slot blank. Blank has to mean "nothing was filtered" and nothing else,
    /// or the one case the slot exists to explain becomes unreadable.
    #[test]
    fn no_compiled_filter_reports_an_empty_status_text() {
        let config = CaptureConfig {
            bpf_filter: None,
            ..Default::default()
        };
        assert!(
            bpf_status_text(&config).is_empty(),
            "a capture with no BPF must not put text in the slot"
        );
    }

    /// An unpaused packet advances the count and trips the limit on the Nth.
    #[test]
    fn unpaused_packets_count_and_trip_limit() {
        let mut total = 0u64;
        // First two are below the limit of 3.
        assert!(!count_and_check_limit(false, &mut total, Some(3)));
        assert_eq!(total, 1);
        assert!(!count_and_check_limit(false, &mut total, Some(3)));
        assert_eq!(total, 2);
        // The third reaches the limit.
        assert!(count_and_check_limit(false, &mut total, Some(3)));
        assert_eq!(total, 3);
    }

    /// Paused packets must NOT advance the count nor trip the limit, even when
    /// the count already sits one short of the limit — otherwise a `--count N`
    /// capture could stop mid-pause with packets never processed.
    #[test]
    fn paused_packets_do_not_count_or_trip_limit() {
        let mut total = 2u64; // one short of the limit of 3
        // A flurry of paused packets changes nothing and never trips.
        for _ in 0..100 {
            assert!(!count_and_check_limit(true, &mut total, Some(3)));
        }
        assert_eq!(total, 2, "paused packets must not advance the count");
        // Resuming, the next processed packet trips the limit as expected.
        assert!(count_and_check_limit(false, &mut total, Some(3)));
        assert_eq!(total, 3);
    }

    /// With no `--count` set, the limit is never reached regardless of pause.
    #[test]
    fn no_count_limit_never_trips() {
        let mut total = 0u64;
        assert!(!count_and_check_limit(false, &mut total, None));
        assert!(!count_and_check_limit(true, &mut total, None));
        assert_eq!(total, 1, "only the unpaused packet advanced the count");
    }

    // ── Name-persistence path resolution ──────────────────────────────────

    /// `XDG_CONFIG_HOME` already names the config directory, so it is used as
    /// given — no `.config` appended.
    #[test]
    fn xdg_config_home_is_used_verbatim_as_the_config_directory() {
        let got = names_path_from(Some("/xdg".into()), Some("/home/u".into()));
        assert_eq!(
            got,
            Some(PathBuf::from("/xdg/sipnab/hosts")),
            "XDG_CONFIG_HOME IS the config dir; appending .config to it would \
             write the N-dialog's edits somewhere nothing else reads"
        );
    }

    /// `HOME` is not the config directory, so the fallback has to append
    /// `.config` — the asymmetry with `XDG_CONFIG_HOME` above is the whole
    /// point of this pair.
    #[test]
    fn the_home_fallback_appends_dot_config_before_the_sipnab_directory() {
        let got = names_path_from(None, Some("/home/u".into()));
        assert_eq!(got, Some(PathBuf::from("/home/u/.config/sipnab/hosts")));
    }

    /// `XDG_CONFIG_HOME` wins when both are set: the fallback must not be
    /// consulted at all.
    #[test]
    fn xdg_config_home_takes_precedence_over_home() {
        let got = names_path_from(Some("/xdg".into()), Some("/home/u".into()));
        let home_only = names_path_from(None, Some("/home/u".into()));
        assert_ne!(
            got, home_only,
            "with XDG_CONFIG_HOME set the HOME-derived path must not be chosen"
        );
    }

    /// With neither variable set there is nowhere to persist to, and the
    /// answer is `None` rather than a relative path under the process's
    /// working directory.
    #[test]
    fn a_bare_environment_yields_no_names_path_rather_than_a_relative_one() {
        let got = names_path_from(None, None);
        assert_eq!(got, None, "got {got:?}");
        assert!(
            !got.is_some_and(|p| p.is_relative()),
            "a relative fallback would scatter hosts files across working dirs"
        );
    }

    // ── Store wiring ──────────────────────────────────────────────────────

    /// Parse a CLI from arguments, `sipnab` included as argv[0].
    fn cli_from(args: &[&str]) -> Cli {
        let mut argv = vec!["sipnab"];
        argv.extend_from_slice(args);
        Cli::parse_from(argv)
    }

    /// One INVITE for `call_id`, carrying `branch` in its top Via.
    ///
    /// Two of these with the same Call-ID and different branches are the
    /// minimal input that tells the two dialog-tracking modes apart: Call-ID
    /// mode files them as one unit, branch mode as two.
    fn invite(call_id: &str, branch: &str) -> crate::sip::SipMessage {
        use std::net::{IpAddr, Ipv4Addr};
        let raw = crate::test_utils::build_sip_message(
            "INVITE sip:b@example.net SIP/2.0",
            &[
                &format!("Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}"),
                "From: <sip:a@example.com>;tag=1",
                "To: <sip:b@example.net>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
            ],
            b"",
        );
        crate::sip::parser::parse_sip(
            &raw,
            chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .expect("the fixture INVITE parses")
    }

    /// A UDP packet carrying a 12-byte RTP header plus 160 bytes of payload,
    /// which at payload type 0 (PCMU) is exactly what the store buffers for
    /// audio export.
    fn pcmu_packet() -> crate::capture::ParsedPacket {
        use std::net::{IpAddr, Ipv4Addr};
        crate::capture::ParsedPacket {
            frame: None,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid epoch"),
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            src_port: 20000,
            dst_port: 30000,
            transport: crate::net::TransportProto::Udp,
            payload: vec![0u8; 12 + 160].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        }
    }

    /// A PCMU RTP header for sequence `seq` of one stream.
    fn pcmu_header(seq: u16) -> crate::rtp::parser::RtpHeader {
        crate::rtp::parser::RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: u32::from(seq) * 160,
            ssrc: 0x5150_0001,
            payload_offset: 12,
        }
    }

    /// `--dialog-track branch` must reach the store the TUI writes through.
    ///
    /// This is the regression gate for the defect the flag shipped with: it
    /// was declared, parsed into `Cli::dialog_track`, and never handed to any
    /// store, so setting it changed nothing an operator could see. Asserting
    /// that `build_stores` *called* a setter would not have caught that —
    /// what is asserted here is the observable consequence, that one Call-ID
    /// seen on two Via branches becomes two tracked units.
    #[test]
    fn dialog_track_branch_reaches_the_store_and_splits_a_reused_call_id() {
        let cli = cli_from(&["--dialog-track", "branch"]);
        assert_eq!(
            cli.dialog_track,
            Some(DialogTracking::Branch),
            "precondition: the flag parsed"
        );
        let (dialogs, _streams) = build_stores(&cli, &Config::default());
        {
            let mut ds = dialogs.write();
            ds.process_message(invite("shared-call-id@example.com", "z9hG4bK-one"));
            ds.process_message(invite("shared-call-id@example.com", "z9hG4bK-two"));
        }
        assert_eq!(
            dialogs.read().len(),
            2,
            "--dialog-track branch must group by Call-ID + top-Via branch; one \
             unit here means the flag never reached the store"
        );
    }

    /// The companion to the test above: without the flag, the same two
    /// messages stay one unit.
    ///
    /// Without this, a store that unconditionally tracked by branch would
    /// pass the branch test while silently changing the default view of every
    /// capture.
    #[test]
    fn the_default_tracking_mode_keeps_one_call_id_in_a_single_unit() {
        let cli = cli_from(&[]);
        assert_eq!(cli.dialog_track, None, "precondition: the flag is unset");
        let (dialogs, _streams) = build_stores(&cli, &Config::default());
        {
            let mut ds = dialogs.write();
            ds.process_message(invite("shared-call-id@example.com", "z9hG4bK-one"));
            ds.process_message(invite("shared-call-id@example.com", "z9hG4bK-two"));
        }
        assert_eq!(
            dialogs.read().len(),
            1,
            "the default is Call-ID grouping: one call, one unit"
        );
    }

    /// `[limits] max_audio_frames` must reach the stream store.
    ///
    /// Same class as the dialog-track defect and it has bitten this project
    /// before: every `[limits]` key was parsed, validated and documented while
    /// nothing read any of them. The effect asserted is the retention itself —
    /// the ring buffer stops at the configured depth — because a store built
    /// with the key dropped is indistinguishable from one built with it
    /// applied until RTP actually arrives.
    #[test]
    fn the_configured_audio_frame_cap_reaches_the_stream_store() {
        let mut config = Config::default();
        config.limits.max_audio_frames = Some(2);
        let (_dialogs, streams) = build_stores(&cli_from(&[]), &config);
        {
            let mut ss = streams.write();
            let packet = pcmu_packet();
            for seq in 1..=5u16 {
                ss.process_rtp(&packet, &pcmu_header(seq), packet.timestamp);
            }
        }
        let store = streams.read();
        let stream = store.iter().next().expect("one stream was created");
        assert_eq!(
            stream.payload_buffer.len(),
            2,
            "five frames arrived under a cap of 2; an unwired cap leaves all 5 \
             buffered at the 1500-frame default"
        );
    }

    /// With no `[limits] max_audio_frames`, the store's own default applies
    /// and nothing is dropped at this volume — so the cap test above is
    /// measuring the config value, not the arrival count.
    #[test]
    fn without_a_configured_cap_every_arriving_frame_is_retained() {
        let (_dialogs, streams) = build_stores(&cli_from(&[]), &Config::default());
        {
            let mut ss = streams.write();
            let packet = pcmu_packet();
            for seq in 1..=5u16 {
                ss.process_rtp(&packet, &pcmu_header(seq), packet.timestamp);
            }
        }
        let store = streams.read();
        let stream = store.iter().next().expect("one stream was created");
        assert_eq!(stream.payload_buffer.len(), 5);
    }

    /// `--limit` must bound the dialog store the TUI writes through.
    #[test]
    fn the_dialog_limit_bounds_the_store_the_tui_writes_through() {
        let cli = cli_from(&["--limit", "2"]);
        let (dialogs, _streams) = build_stores(&cli, &Config::default());
        {
            let mut ds = dialogs.write();
            for n in 0..5 {
                ds.process_message(invite(&format!("call-{n}@example.com"), "z9hG4bK-x"));
            }
        }
        assert_eq!(
            dialogs.read().len(),
            2,
            "five distinct Call-IDs under --limit 2 must leave 2 tracked units"
        );
    }

    // ── Name setup ────────────────────────────────────────────────────────

    /// `[names] persist_to_config` decides whether in-TUI `N`-dialog edits are
    /// also written back to the user's sipnabrc.
    ///
    /// Both directions are asserted against the same source of truth
    /// `build_name_setup` uses, so the test cannot pass by accident in an
    /// environment where no user config path can be derived at all.
    #[test]
    fn persist_to_config_decides_whether_name_edits_reach_the_users_sipnabrc() {
        let cli = cli_from(&[]);

        let off = super::build_name_setup(&cli, &Config::default());
        assert_eq!(
            off.config_path, None,
            "the default must not write the user's config file"
        );

        let mut config = Config::default();
        config.names.persist_to_config = Some(true);
        let on = super::build_name_setup(&cli, &config);
        assert_eq!(
            on.config_path,
            crate::config::default_user_config_path(),
            "opting in must target the user's sipnabrc"
        );
    }

    /// The name setup always names the default persistence file, and it is the
    /// XDG one — the `N` dialog has nowhere to save otherwise.
    #[test]
    fn the_name_setup_carries_the_default_persistence_path() {
        let setup = super::build_name_setup(&cli_from(&[]), &Config::default());
        assert_eq!(setup.save_path, super::default_names_path());
        if let Some(p) = setup.save_path {
            assert!(
                p.ends_with(Path::new("sipnab/hosts")),
                "unexpected persistence path {}",
                p.display()
            );
        }
    }
}
