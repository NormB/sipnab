//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! Entry point: parses CLI, sets up logging and signal handlers, loads config,
//! and dispatches to the appropriate capture mode. Phase 2 wires all modules
//! together: capture → SIP parsing → dialog tracking → RTP tracking →
//! filtering → output.

use std::path::PathBuf;

use sipnab::capture::parse::TransportProto;
use sipnab::capture::{self, CaptureConfig, CaptureSource, ParsedPacket, PcapWriter};
use sipnab::cli::Cli;
use sipnab::config::Config;
use sipnab::output::{self, ColorMode, EventExecEngine, OutputOptions, ReportFormat};
use sipnab::rtp::{self, parser::parse_rtp_header, rtcp::parse_rtcp, stream_store::StreamStore};
use sipnab::signals;
use sipnab::sip::{self, dialog_store::DialogStore, dsl::FilterExpr, matcher::SipMatcher};

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

    // 6. --dump-config: print version + effective config, then exit
    if cli.dump_config {
        println!("sipnab v{}", env!("CARGO_PKG_VERSION"));
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
        cli.hep_listen.as_ref().map(|hep_addr| CaptureSource::Hep {
            bind_addr: hep_addr.clone(),
        })
    };

    let Some(source) = source else {
        log::info!(
            "sipnab v{} — no capture source specified (use -d, -I, or -L)",
            env!("CARGO_PKG_VERSION")
        );
        return;
    };

    // 8. Build CaptureConfig from CLI + config file
    let capture_config = build_capture_config(&cli, &loaded.config);

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
    let mut event_exec = EventExecEngine::new(
        cli.on_dialog_exec.clone(),
        cli.on_quality_exec.clone(),
        cli.exec_rate_limit,
        cli.quality_threshold,
    );

    // 14. Create the packet channel
    let (tx, rx) = crossbeam_channel::bounded(10_000);

    // 15. Start the capture thread
    let handle = match capture::start_capture(source, capture_config.clone(), tx) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to start capture: {e}");
            std::process::exit(1);
        }
    };

    // 16. Open output writer if -O is specified
    let mut writer: Option<PcapWriter> = None;

    // 17. Initialize processing state
    let mut processor = capture::PacketProcessor::new();
    let mut dialog_store = DialogStore::new(cli.limit as usize, cli.rotate);
    let no_rtp = cli.no_rtp || loaded.config.capture.no_rtp.unwrap_or(false);
    let mut stream_store = StreamStore::new(cli.max_streams as usize);
    let mut rtp_heuristic = rtp::heuristic::RtpHeuristic::new();

    let mut last_sweep = std::time::Instant::now();
    let sweep_interval = std::time::Duration::from_secs(5);

    // 18. Main receive loop
    let start = std::time::Instant::now();
    let mut total_count: u64 = 0;
    let mut sip_count: u64 = 0;
    let mut rtp_count: u64 = 0;
    let mut prev_timestamp: Option<chrono::DateTime<chrono::Utc>> = None;

    loop {
        if signals::shutdown_requested() {
            break;
        }

        // Periodic sweep of reassembly state and orphan detection (every 5 seconds)
        if last_sweep.elapsed() >= sweep_interval {
            processor.sweep();
            stream_store.mark_orphaned(std::time::Duration::from_secs(30));
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
            match PcapWriter::new(
                &PathBuf::from(output_path),
                packet.link_type,
                split_bytes,
                split_duration,
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
            process_parsed_packet(
                pp,
                &matcher,
                &filter_expr,
                &output_opts,
                &cli,
                &mut dialog_store,
                &mut stream_store,
                &mut rtp_heuristic,
                &mut event_exec,
                &mut sip_count,
                &mut rtp_count,
                &mut prev_timestamp,
                no_rtp,
            );
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
    }

    // 19. Wait for the capture thread to finish
    //     Drop rx first so the capture thread sees a disconnected channel
    drop(rx);
    match handle.thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("Capture thread error: {e}"),
        Err(_) => log::error!("Capture thread panicked"),
    }

    // 20. Post-capture output
    generate_reports(&cli, &dialog_store, &stream_store);

    // 21. Summary
    if !cli.quiet {
        log::info!(
            "sipnab: {total_count} packets captured, {sip_count} SIP messages, {rtp_count} RTP streams",
        );
    }
}

// ── Packet processing ─────────────────────────────────────────────────

/// Process a single parsed packet through SIP/RTP detection, matching,
/// dialog tracking, and output dispatch.
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
    sip_count: &mut u64,
    rtp_count: &mut u64,
    prev_timestamp: &mut Option<chrono::DateTime<chrono::Utc>>,
    no_rtp: bool,
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

    // Try SIP detection first
    if sip::is_sip_message(&pp.payload) {
        let transport_str = match pp.transport {
            TransportProto::Udp => "UDP",
            TransportProto::Tcp => "TCP",
            TransportProto::Sctp => "SCTP",
        };

        match sip::parse_sip(
            &pp.payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            transport_str,
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

                // Output if both matcher and filter pass
                if matcher_pass && filter_pass && cli.no_tui {
                    dispatch_sip_output(&sip_msg, output_opts, cli, *prev_timestamp);
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
    }
}
