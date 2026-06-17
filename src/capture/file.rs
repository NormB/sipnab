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

/// Open an offline capture, transparently decompressing gzip-compressed files.
///
/// libpcap's `pcap_open_offline` cannot read gzip-compressed captures (it
/// reports "unknown file format"), but Wireshark decompresses them on the fly —
/// and tools routinely hand out `.pcap` files that are actually gzip. We match
/// Wireshark: if the file starts with the gzip magic (`1f 8b`), decompress it
/// to a temporary file and open that instead.
///
/// Returns the open capture together with an optional temp-file guard. The
/// guard owns the decompressed file and deletes it on drop, so the caller MUST
/// keep it alive for as long as it reads from the capture.
pub fn open_offline(
    path: &Path,
) -> Result<(pcap::Capture<pcap::Offline>, Option<tempfile::TempPath>)> {
    use std::io::Read;

    // Peek the first two bytes for the gzip magic. A file too short to hold a
    // magic number isn't gzip; let libpcap report on it as before.
    let is_gzip = {
        let mut magic = [0u8; 2];
        let read_two = std::fs::File::open(path)
            .and_then(|mut f| f.read(&mut magic))
            .map(|n| n == 2)
            .unwrap_or(false);
        read_two && magic == [0x1f, 0x8b]
    };

    if !is_gzip {
        let cap = pcap::Capture::from_file(path)
            .with_context(|| format!("Failed to open pcap file '{}'", path.display()))?;
        return Ok((cap, None));
    }

    // Decompress to a temp file libpcap can open. MultiGzDecoder handles
    // concatenated gzip members, which some capture tools emit.
    let input = std::fs::File::open(path)
        .with_context(|| format!("Failed to open '{}'", path.display()))?;
    let mut decoder = flate2::read::MultiGzDecoder::new(std::io::BufReader::new(input));
    let mut temp = tempfile::Builder::new()
        .prefix("sipnab-gz-")
        .suffix(".pcap")
        .tempfile()
        .context("Failed to create temp file for gzip decompression")?;
    std::io::copy(&mut decoder, temp.as_file_mut())
        .with_context(|| format!("Failed to decompress gzip capture '{}'", path.display()))?;
    let temp_path = temp.into_temp_path();

    let cap = pcap::Capture::from_file(&temp_path).with_context(|| {
        format!(
            "Failed to open decompressed capture from '{}'",
            path.display()
        )
    })?;
    Ok((cap, Some(temp_path)))
}

/// Read packets from a pcap file and send them through the channel.
///
/// Opens the file with [`open_offline`] (transparently handling gzip), applies
/// any BPF filter, and reads packets until EOF, shutdown, count limit, or
/// duration limit.
///
/// This function blocks and is intended to be called from a dedicated thread.
pub fn capture_file(
    path: &Path,
    config: &CaptureConfig,
    tx: Sender<Packet>,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<()> {
    // `_gz_guard` owns any decompressed temp file; it must outlive all reads
    // below, so keep it bound for the whole function.
    let (mut cap, _gz_guard) = match open_offline(path) {
        Ok(opened) => opened,
        Err(e) => {
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{e:#}")));
            }
            return Err(e);
        }
    };

    if let Some(ref bpf) = config.bpf_filter
        && let Err(e) = cap.filter(bpf, true)
    {
        let err = anyhow::Error::new(e).context(format!("Failed to compile BPF filter: {bpf}"));
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(format!("{err:#}")));
        }
        return Err(err);
    }

    // Signal that the capture file is open and ready.
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    let link_type = cap.get_datalink().0;
    let start = std::time::Instant::now();
    let mut count: u64 = 0;
    let replay = config.replay;
    let mut prev_ts: Option<DateTime<Utc>> = None;

    if replay {
        tracing::info!("Replaying from '{}' with original timing", path.display());
    } else {
        tracing::info!("Reading from '{}'", path.display());
    }

    loop {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping file reader");
            break;
        }

        if let Some(max_count) = config.count
            && count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            break;
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
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
                    tracing::debug!("Receiver dropped, stopping file reader");
                    break;
                }

                count += 1;
            }
            Err(pcap::Error::NoMorePackets) => {
                tracing::debug!("End of file reached");
                break;
            }
            Err(e) => {
                tracing::error!("Error reading pcap file '{}': {e}", path.display());
                return Err(e).context("Error reading pcap file");
            }
        }
    }

    tracing::info!(
        "File reader finished: {count} packets from '{}'",
        path.display()
    );
    Ok(())
}

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    // tv_usec is attacker-controllable in a crafted capture; clamp to a valid
    // microsecond before the µs→ns multiply so it can overflow neither u64 (the
    // clamp bounds the operand) nor the resulting u32.
    let nanos = ts.tv_usec.clamp(0, 999_999) as u32 * 1000;
    Utc.timestamp_opt(ts.tv_sec, nanos)
        .single()
        .unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::unbounded;

    #[test]
    fn pcap_ts_to_chrono_out_of_range_usec_does_not_panic() {
        // A corrupt/hostile pcap can carry tv_usec outside [0, 1_000_000).
        // The microsecond→nanosecond conversion must clamp rather than overflow
        // u32 (which panics in debug / wraps in release).
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: 4_294_968, // * 1000 overflows u32
        });
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: i64::MAX,
        });
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: -1,
        });
    }

    /// Helper: path to the test fixture pcap.
    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("udp_5060.pcap")
    }

    /// Helper: a real multi-packet SIP/RTP sample (classic pcap).
    fn sample_pcap() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pcap-samples")
            .join("sip-rtp-g711.pcap")
    }

    /// Read a capture file via `capture_file` and return the packet count.
    fn count_packets(path: &Path) -> usize {
        let (tx, rx) = unbounded();
        capture_file(path, &CaptureConfig::default(), tx, None).unwrap();
        rx.try_iter().count()
    }

    /// gzip-compressed captures must read transparently: libpcap cannot open
    /// them (it reports "unknown file format"), but Wireshark decompresses on
    /// the fly, so sipnab matches that behavior. Regression for the
    /// `.pcap.gz`-mislabeled-as-`.pcap` case.
    #[test]
    fn reads_gzip_compressed_pcap() {
        use std::io::Write;

        let sample = sample_pcap();
        if !sample.exists() {
            eprintln!("Skipping: sample not found at {}", sample.display());
            return;
        }
        let baseline = count_packets(&sample);
        assert!(baseline > 0, "sample should contain packets");

        // Produce a gzip-compressed copy with a deliberately plain `.pcap` name.
        let raw = std::fs::read(&sample).unwrap();
        let gz_file = tempfile::Builder::new()
            .prefix("sipnab-test-")
            .suffix(".pcap")
            .tempfile()
            .unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let compressed = encoder.finish().unwrap();
        std::fs::write(gz_file.path(), &compressed).unwrap();

        let via_gz = count_packets(gz_file.path());
        assert_eq!(
            via_gz, baseline,
            "gzip-compressed capture should yield the same packets as the original"
        );
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
        capture_file(&path, &config, tx, None).unwrap();

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
