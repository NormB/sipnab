// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pcap file reader.
//!
//! Reads packets from a pcap (or pcap-ng) file and sends them through a
//! crossbeam channel. Supports BPF filtering, packet count limits, and
//! duration limits. EOF is treated as a clean exit.

use std::path::Path;

use super::channel::PacketTx;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

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
///
/// # Arguments
///
/// * `path` - path to the pcap/pcapng file (optionally gzip-compressed).
///
/// # Errors
///
/// Fails when the file cannot be opened by libpcap, when the temp file for
/// decompression cannot be created, or when the gzip stream is corrupt.
///
/// # Side effects
///
/// Reads `path` (twice for gzip input: magic peek, then decompression) and,
/// for gzip input, writes a decompressed copy to a temporary file that is
/// deleted when the returned guard drops.
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
///
/// # Arguments
///
/// * `path` - the capture file to read.
/// * `config` - BPF filter, count/duration limits, and the `replay` flag
///   (replay sleeps for each inter-packet delta to reproduce original timing).
/// * `tx` - channel the decoded `Packet`s are sent into.
/// * `ready_tx` - optional one-shot channel: receives `Ok(())` once the file
///   is open and filtered, or `Err(msg)` if opening/filtering fails.
///
/// # Returns
///
/// `Ok(())` on EOF, shutdown, count limit, or duration limit.
///
/// # Errors
///
/// Fails when the file cannot be opened, the BPF filter does not compile, or
/// libpcap reports a read error mid-file.
///
/// # Side effects
///
/// Reads the file, sends packets on `tx`, signals `ready_tx`, sleeps between
/// packets in replay mode, checks the global shutdown flag, and logs progress
/// via tracing.
pub fn capture_file(
    path: &Path,
    config: &CaptureConfig,
    tx: PacketTx,
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

    let mut count: u64 = 0;
    let mut prev_ts: Option<DateTime<Utc>> = None;
    read_opened(
        &mut cap,
        path,
        config,
        &tx,
        std::time::Instant::now(),
        &mut count,
        &mut prev_ts,
    )
}

/// Read a set of capture files, in order, into one packet stream.
///
/// The files feed a single channel and therefore a single dialog store, which
/// is the whole point: `tcpdump -C -W` splits a busy capture across a ring
/// buffer, and a call whose INVITE lands in `tg.pcap3` and whose BYE lands in
/// `tg.pcap4` is only reconstructable if both are read without resetting state
/// in between. Analysed separately, one file shows a call that never ends and
/// the other a stray BYE, and neither reports the truth.
///
/// `paths` must already be in read order — [`crate::capture::input_set`]
/// orders them by first-packet timestamp, which is not filename order.
///
/// The packet count, the duration clock and the replay timeline are shared
/// across the whole set. A `--count 100` over four files means a hundred
/// packets in total, not four hundred, and replay reproduces the gap *between*
/// files as well as within them.
///
/// # Arguments
///
/// * `paths` - capture files, in read order.
/// * `config` - BPF filter, count/duration limits, and the `replay` flag.
/// * `tx` - channel the decoded `Packet`s are sent into.
/// * `ready_tx` - optional one-shot, signalled once the FIRST file is open and
///   filtered. Later files cannot report readiness — the consumer is already
///   running by then — so a failure to open one of them is logged and skipped.
///
/// # Errors
///
/// Fails when the first file cannot be opened or its BPF filter does not
/// compile, or when libpcap reports a read error mid-file.
///
/// # Side effects
///
/// Reads each file, sends packets on `tx`, signals `ready_tx`, sleeps between
/// packets in replay mode, checks the global shutdown flag, and logs progress.
pub fn capture_files(
    paths: &[std::path::PathBuf],
    config: &CaptureConfig,
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<()> {
    let Some((first, rest)) = paths.split_first() else {
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err("no capture files to read".to_string()));
        }
        anyhow::bail!("no capture files to read");
    };

    // The first file owns readiness: opening it is what proves the whole set
    // is usable, and the consumer starts as soon as it is signalled.
    let (mut cap, _gz_guard) = match open_offline(first) {
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
    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    let start = std::time::Instant::now();
    let mut count: u64 = 0;
    let mut prev_ts: Option<DateTime<Utc>> = None;

    if !read_opened_inner(
        &mut cap,
        first,
        config,
        &tx,
        start,
        &mut count,
        &mut prev_ts,
    )? {
        return Ok(());
    }
    drop(cap);
    drop(_gz_guard);

    for path in rest {
        // A file that fails here is logged and skipped rather than aborting.
        // The set was already probed during resolution, so reaching this means
        // something changed underneath us mid-read — a rotating capture
        // directory being cleaned up while it is analysed. Losing one file of
        // a set is bad; losing the analysis of the other nine is worse.
        let (mut cap, _gz_guard) = match open_offline(path) {
            Ok(opened) => opened,
            Err(e) => {
                tracing::error!("Skipping '{}': {e:#}", path.display());
                continue;
            }
        };
        if let Some(ref bpf) = config.bpf_filter
            && let Err(e) = cap.filter(bpf, true)
        {
            tracing::error!("Skipping '{}': bad BPF filter: {e}", path.display());
            continue;
        }
        if !read_opened_inner(&mut cap, path, config, &tx, start, &mut count, &mut prev_ts)? {
            break;
        }
    }

    tracing::info!("Read {count} packets from {} file(s)", paths.len());
    Ok(())
}

/// Read every packet from an already-opened capture into `tx`.
///
/// Split out of [`capture_file`] so a multi-file set shares one packet count,
/// one duration clock, and one replay timeline across its members —
/// see [`capture_files`]. Returns `Ok(false)` when the whole read should stop
/// (shutdown, a limit reached, or the receiver gone) rather than merely this
/// file ending.
fn read_opened(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    start: std::time::Instant,
    count: &mut u64,
    prev_ts: &mut Option<DateTime<Utc>>,
) -> Result<()> {
    let _ = read_opened_inner(cap, path, config, tx, start, count, prev_ts)?;
    Ok(())
}

/// The read loop itself, returning whether the caller should continue to the
/// next file.
///
/// Separate from [`read_opened`] only so the "stop the whole set" signal has a
/// return value: a count limit reached inside file three must not be mistaken
/// for file three simply ending.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn read_opened_inner(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    start: std::time::Instant,
    count: &mut u64,
    prev_ts: &mut Option<DateTime<Utc>>,
) -> Result<bool> {
    let link_type = cap.get_datalink().0;
    let replay = config.replay;

    if replay {
        tracing::info!("Replaying from '{}' with original timing", path.display());
    } else {
        tracing::info!("Reading from '{}'", path.display());
    }

    loop {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping file reader");
            return Ok(false);
        }

        if let Some(max_count) = config.count
            && *count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            return Ok(false);
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            return Ok(false);
        }

        match cap.next_packet() {
            Ok(pkt) => {
                let ts = pcap_ts_to_chrono(pkt.header.ts);

                // Replay mode: reproduce the inter-packet gap, but sleep in
                // bounded slices that poll the shutdown flag between them, so a
                // large delta cannot delay shutdown by more than one slice.
                if replay {
                    if let Some(prev) = *prev_ts {
                        let delta = ts.signed_duration_since(prev);
                        if let Ok(dur) = delta.to_std()
                            && !dur.is_zero()
                            && sleep_interruptible(dur, signals::shutdown_requested)
                        {
                            tracing::debug!(
                                "Shutdown requested during replay delay, stopping file reader"
                            );
                            return Ok(false);
                        }
                        // Negative deltas (out-of-order timestamps) are skipped
                    }
                    *prev_ts = Some(ts);
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
                    return Ok(false);
                }

                *count += 1;
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
        "File reader finished: {count} packets total, through '{}'",
        path.display()
    );
    Ok(true)
}

/// Sleep for `total`, waking at least every 200 ms to poll `should_stop`.
///
/// Replaying a capture reproduces the original inter-packet timing, so a gap of
/// minutes or hours between packets would otherwise be one blocking
/// `thread::sleep` that ignores shutdown for its whole duration. Slicing the
/// wait bounds the shutdown latency to a single slice regardless of the gap.
///
/// `should_stop` is the same signal the surrounding capture loop observes
/// (`signals::shutdown_requested`); it is injectable so the slicing logic can
/// be tested without touching the process-global flag.
///
/// Returns `true` if `should_stop` fired before `total` elapsed (the caller
/// should then stop), `false` if the full duration was slept.
fn sleep_interruptible(total: std::time::Duration, should_stop: impl Fn() -> bool) -> bool {
    const SLICE: std::time::Duration = std::time::Duration::from_millis(200);
    let mut remaining = total;
    while !remaining.is_zero() {
        if should_stop() {
            return true;
        }
        let nap = remaining.min(SLICE);
        std::thread::sleep(nap);
        remaining -= nap;
    }
    should_stop()
}

/// Convert a pcap `libc::timeval` to a chrono UTC datetime.
///
/// Routes through the single hardened converter in
/// [`super::live::pcap_ts_to_chrono`] so the file/replay path and live capture
/// treat a corrupt timeval identically: an out-of-range `tv_usec` or an
/// unrepresentable `tv_sec` falls back to the current wall clock, and — unlike
/// the old silent fallback here — the event is counted in
/// [`super::live::INVALID_PCAP_TIMESTAMPS`] and warned about (rate-limited),
/// because a silently substituted timestamp corrupts every downstream timing
/// computation.
pub(crate) fn pcap_ts_to_chrono(ts: libc::timeval) -> DateTime<Utc> {
    super::live::pcap_ts_to_chrono(ts)
}

/// Tests for file reading: timestamp hardening, fixture reads, and
/// transparent gzip decompression.
#[cfg(test)]
mod tests {
    use super::super::channel::packet_channel;
    use super::*;

    /// A capacity large enough that `capture_file` (which sends every packet
    /// before the test drains) never blocks on the cap.
    const TEST_CAP: usize = 1 << 20;

    /// Out-of-range/negative `tv_usec` values from a hostile capture must
    /// clamp rather than overflow the u32 nanosecond conversion.
    #[test]
    fn pcap_ts_to_chrono_out_of_range_usec_does_not_panic() {
        // A corrupt/hostile pcap can carry tv_usec outside [0, 1_000_000).
        // The microsecond→nanosecond conversion must clamp rather than overflow
        // u32 (which panics in debug / wraps in release). Values are chosen to
        // fit `suseconds_t` on every target (i32 on macOS, i64 on Linux) while
        // still overflowing the old `as u32 * 1000`.
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: 4_294_968, // * 1000 overflows u32
        });
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: 2_000_000_000, // fits i32; * 1000 overflows u32
        });
        let _ = pcap_ts_to_chrono(libc::timeval {
            tv_sec: 0,
            tv_usec: -1, // as u32 → huge → overflow in old code
        });
    }

    /// A huge replay inter-packet delta must not delay shutdown: the sleep is
    /// sliced and polls the stop signal between slices, so it returns promptly
    /// once the signal fires instead of blocking for the full duration.
    /// Regression for the "large delta delays shutdown arbitrarily" gap.
    #[test]
    fn sleep_interruptible_returns_promptly_on_stop() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let stop_setter = Arc::clone(&stop);
        // Fire the stop signal shortly after the (would-be hour-long) sleep starts.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            stop_setter.store(true, Ordering::SeqCst);
        });

        let started = std::time::Instant::now();
        let interrupted = sleep_interruptible(std::time::Duration::from_secs(3600), || {
            stop.load(Ordering::SeqCst)
        });
        let elapsed = started.elapsed();

        assert!(
            interrupted,
            "must report that the stop signal interrupted the sleep"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "sliced sleep must react to the stop signal promptly, took {elapsed:?}"
        );
    }

    /// Without a stop signal the sliced sleep runs to completion and reports
    /// that it was not interrupted.
    #[test]
    fn sleep_interruptible_runs_to_completion_without_stop() {
        let started = std::time::Instant::now();
        let interrupted = sleep_interruptible(std::time::Duration::from_millis(120), || false);
        assert!(!interrupted, "no stop signal → not interrupted");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(100),
            "must actually sleep the requested duration"
        );
    }

    /// A tv_sec/tv_usec that cannot be represented must fall back to the wall
    /// clock *loudly*: like live capture, the file/replay path must count the
    /// event in the shared `INVALID_PCAP_TIMESTAMPS` counter rather than
    /// silently substituting "now". Regression for the consistency gap where
    /// `file.rs` fell back without counting while `live.rs` counted+warned.
    #[test]
    fn fallback_to_now_is_counted_like_live() {
        use std::sync::atomic::Ordering;
        let counter = &crate::capture::live::INVALID_PCAP_TIMESTAMPS;
        let before = counter.load(Ordering::Relaxed);
        // i64::MAX seconds is unrepresentable → fallback to now().
        let dt = pcap_ts_to_chrono(libc::timeval {
            tv_sec: i64::MAX,
            tv_usec: 0,
        });
        let after = counter.load(Ordering::Relaxed);
        assert!(
            after > before,
            "invalid pcap timestamp must be counted, not silently stamped with now()"
        );
        // The fallback stamps the current wall clock.
        assert!((Utc::now() - dt).num_seconds().abs() < 60);
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
        let (tx, rx) = packet_channel(TEST_CAP);
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

    /// Reading the UDP fixture yields non-empty packets with no interface
    /// name (file captures carry none).
    #[test]
    fn read_fixture_pcap() {
        let path = fixture_path();
        if !path.exists() {
            // Skip if fixture not yet generated
            eprintln!("Skipping: fixture not found at {}", path.display());
            return;
        }

        let (tx, rx) = packet_channel(TEST_CAP);
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
