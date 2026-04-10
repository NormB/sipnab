//! Pcap file reader.
//!
//! Reads packets from a pcap (or pcap-ng) file and sends them through a
//! crossbeam channel. Supports BPF filtering, packet count limits, and
//! duration limits. EOF is treated as a clean exit.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use crossbeam_channel::Sender;

use super::CaptureConfig;
use super::packet::Packet;
use crate::signals;

/// Read packets from a pcap file and send them through the channel.
///
/// Opens the file with `pcap::Capture::from_file`, applies any BPF filter,
/// and reads packets until EOF, shutdown, count limit, or duration limit.
///
/// This function blocks and is intended to be called from a dedicated thread.
pub fn capture_file(path: &Path, config: &CaptureConfig, tx: Sender<Packet>) -> Result<()> {
    let mut cap = pcap::Capture::from_file(path)
        .with_context(|| format!("Failed to open pcap file '{}'", path.display()))?;

    if let Some(ref bpf) = config.bpf_filter {
        cap.filter(bpf, true)
            .with_context(|| format!("Failed to compile BPF filter: {bpf}"))?;
    }

    let link_type = cap.get_datalink().0;
    let start = std::time::Instant::now();
    let mut count: u64 = 0;
    let replay = config.replay;
    let mut prev_ts: Option<DateTime<Utc>> = None;

    if replay {
        log::info!("Replaying from '{}' with original timing", path.display());
    } else {
        log::info!("Reading from '{}'", path.display());
    }

    loop {
        if signals::shutdown_requested() {
            log::debug!("Shutdown requested, stopping file reader");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            log::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            log::debug!("Reached duration limit ({duration:?})");
            break;
        }

        match cap.next_packet() {
            Ok(pkt) => {
                let ts = pcap_ts_to_chrono(pkt.header.ts);

                // Replay mode: sleep for the inter-packet delta
                if replay {
                    if let Some(prev) = prev_ts {
                        let delta = ts.signed_duration_since(prev);
                        if let Ok(dur) = delta.to_std()
                            && !dur.is_zero()
                        {
                            std::thread::sleep(dur);
                        }
                        // Negative deltas (out-of-order timestamps) are skipped
                    }
                    prev_ts = Some(ts);
                }

                let packet = Packet::new(
                    ts,
                    pkt.data.to_vec(),
                    pkt.header.caplen as usize,
                    pkt.header.len as usize,
                    None, // File captures have no interface name
                    link_type,
                );

                if tx.send(packet).is_err() {
                    log::debug!("Receiver dropped, stopping file reader");
                    break;
                }

                count += 1;
            }
            Err(pcap::Error::NoMorePackets) => {
                log::debug!("End of file reached");
                break;
            }
            Err(e) => {
                log::error!("Error reading pcap file '{}': {e}", path.display());
                return Err(e).context("Error reading pcap file");
            }
        }
    }

    log::info!(
        "File reader finished: {count} packets from '{}'",
        path.display()
    );
    Ok(())
}

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    Utc.timestamp_opt(ts.tv_sec, (ts.tv_usec as u32) * 1000)
        .single()
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    /// Helper: path to the test fixture pcap.
    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("udp_5060.pcap")
    }

    #[test]
    fn read_fixture_pcap() {
        let path = fixture_path();
        if !path.exists() {
            // Skip if fixture not yet generated
            eprintln!("Skipping: fixture not found at {}", path.display());
            return;
        }

        let (tx, rx) = unbounded();
        let config = CaptureConfig::default();
        capture_file(&path, &config, tx).unwrap();

        let packets: Vec<Packet> = rx.try_iter().collect();
        assert!(
            !packets.is_empty(),
            "Expected at least one packet from fixture"
        );

        for pkt in &packets {
            assert!(!pkt.data.is_empty());
            assert!(pkt.caplen > 0);
            assert!(pkt.interface.is_none()); // File captures have no interface
        }
    }
}
