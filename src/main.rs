//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! Entry point: parses CLI, sets up logging and signal handlers, loads config,
//! and dispatches to the appropriate capture mode.

use std::path::PathBuf;

use sipnab::capture::{self, CaptureConfig, CaptureSource, PcapWriter};
use sipnab::cli::Cli;
use sipnab::config::Config;
use sipnab::signals;

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

    // 10. Create the packet channel
    let (tx, rx) = crossbeam_channel::bounded(10_000);

    // 11. Start the capture thread
    let handle = match capture::start_capture(source, capture_config.clone(), tx) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to start capture: {e}");
            std::process::exit(1);
        }
    };

    // 12. Open output writer if -O is specified
    let mut writer: Option<PcapWriter> = None;

    // 12b. Initialize the packet processor (parsing + reassembly pipeline)
    let mut processor = capture::PacketProcessor::new();
    let mut last_sweep = std::time::Instant::now();
    let sweep_interval = std::time::Duration::from_secs(5);

    // 13. Main receive loop
    let start = std::time::Instant::now();
    let mut total_count: u64 = 0;
    let mut parsed_count: u64 = 0;

    loop {
        if signals::shutdown_requested() {
            break;
        }

        // Periodic sweep of reassembly state (every 5 seconds)
        if last_sweep.elapsed() >= sweep_interval {
            processor.sweep();
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
            parsed_count += 1;
            log::debug!(
                "Parsed {} {}:{} -> {}:{} ({} bytes)",
                pp.transport,
                pp.src_addr,
                pp.src_port,
                pp.dst_addr,
                pp.dst_port,
                pp.payload.len(),
            );
        }

        // Check --count limit (main thread enforces this as well for output)
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

    // 14. Wait for the capture thread to finish
    //     Drop rx first so the capture thread sees a disconnected channel
    drop(rx);
    match handle.thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("Capture thread error: {e}"),
        Err(_) => log::error!("Capture thread panicked"),
    }

    // 15. Report results
    if !cli.quiet {
        log::info!("sipnab: {total_count} packets captured, {parsed_count} parsed",);
    }
}

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
