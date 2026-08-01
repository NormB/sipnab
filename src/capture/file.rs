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
/// Fails when the first file cannot be opened, when the BPF filter does not
/// compile against ANY file of the set, or when libpcap reports a read error
/// mid-file.
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
    let mut tally = ReadTally {
        given: paths.len(),
        ..ReadTally::default()
    };
    let mut count: u64 = 0;
    let result = read_set(paths, config, &tx, ready_tx, &mut tally, &mut count);

    // Reported before the result is propagated, and on every path out: a
    // filter that fails against file twelve still read eleven, and what
    // reached the store is exactly what the operator has to be told.
    if paths.is_empty() {
        return result;
    }
    let line = tally.summary(count);
    if tally.lossy() {
        tracing::warn!("{line}");
    } else {
        tracing::info!("{line}");
    }
    result
}

/// What became of each file of one `-I` set.
///
/// The old summary was `"Read {count} packets from {} file(s)", paths.len()` —
/// the size of the set decided BEFORE any file was opened. Both `continue`
/// arms and the read-error arm fell through to it, so a run that opened 3 of 27
/// files still claimed 27, and an earlier truncation bug that abandoned twelve
/// files was nearly invisible because the line it printed did not change.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReadTally {
    /// Files in the resolved set — what used to be reported on its own.
    given: usize,
    /// Files read through to their last packet.
    complete: usize,
    /// Files whose read stopped before their end: a mid-file read error, or a
    /// `--count`/`--duration` limit or shutdown landing inside them.
    stopped_early: usize,
    /// Files that never yielded a packet: they could not be opened, or the BPF
    /// filter would not compile against their link type.
    skipped: usize,
    /// Whether anything was lost rather than merely left unread on request.
    ///
    /// Separate from the counts because `--count 100` over a 27-file set stops
    /// early and leaves 26 files unread by design; a read error or a file that
    /// would not open is data missing from the analysis, and only that turns
    /// the summary into a warning.
    lost: bool,
}

impl ReadTally {
    /// Files the run never got to, because it stopped inside an earlier one.
    fn not_reached(&self) -> usize {
        self.given
            .saturating_sub(self.complete + self.stopped_early + self.skipped)
    }

    /// Whether the summary describes missing data rather than a requested stop.
    fn lossy(&self) -> bool {
        self.lost
    }

    /// The closing line: packets read, and what happened to every file.
    fn summary(&self, packets: u64) -> String {
        let mut line = format!(
            "Read {packets} packets: {} of {} file(s) read in full",
            self.complete, self.given
        );
        for (n, what) in [
            (self.stopped_early, "stopped early"),
            (self.skipped, "skipped"),
            (self.not_reached(), "not reached"),
        ] {
            if n > 0 {
                line.push_str(", ");
                line.push_str(&n.to_string());
                line.push(' ');
                line.push_str(what);
            }
        }
        line
    }
}

/// State carried from one file of a set to the next.
///
/// Bundled rather than passed as six more parameters, because every member of
/// it exists precisely so the set reads as ONE capture: one packet count, one
/// replay timeline, one tally, and one running end-of-the-previous-file.
struct SetState<'a> {
    /// Packets sent so far, shared so `--count` spans the whole set.
    count: &'a mut u64,
    /// Previous packet's timestamp, shared so replay reproduces the gap
    /// BETWEEN files as well as within them.
    prev_ts: Option<DateTime<Utc>>,
    /// Per-file outcomes for the closing summary.
    tally: &'a mut ReadTally,
    /// The last file that held packets, and the time of its last packet.
    prev_end: Option<(std::path::PathBuf, DateTime<Utc>)>,
}

/// Read every file of the set, tallying what happened to each.
///
/// Split out of [`capture_files`] so the summary is reported on every path out
/// — including the error paths — and so the tally can be asserted directly in
/// tests rather than through a log line.
fn read_set(
    paths: &[std::path::PathBuf],
    config: &CaptureConfig,
    tx: &PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
    tally: &mut ReadTally,
    count: &mut u64,
) -> Result<()> {
    let Some((first, rest)) = paths.split_first() else {
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err("no capture files to read".to_string()));
        }
        anyhow::bail!("no capture files to read");
    };

    let start = std::time::Instant::now();
    let mut state = SetState {
        count,
        prev_ts: None,
        tally,
        prev_end: None,
    };

    // The first file owns readiness: opening it is what proves the whole set
    // is usable, and the consumer starts as soon as it is signalled.
    if !read_member(first, config, tx, start, &mut state, ready_tx)? {
        return Ok(());
    }

    for path in rest {
        if !read_member(path, config, tx, start, &mut state, None)? {
            break;
        }
    }
    Ok(())
}

/// Read one file of a set. Returns whether the set should continue.
///
/// `ready_tx` is `Some` only for the FIRST file, and that is the one asymmetry
/// left between the members: a first file that will not open has proved the
/// whole set unusable before the consumer started, so it fails the run, while
/// a later one is logged and skipped. The set was already probed during
/// resolution, so a later open failure means something changed underneath us
/// mid-read — a rotating capture directory being cleaned up while it is
/// analysed — and losing one file of a set is bad where losing the analysis of
/// the other nine is worse.
///
/// A BPF filter that will not compile is treated the same wherever it happens.
/// See [`filter_failure`].
fn read_member(
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    start: std::time::Instant,
    state: &mut SetState,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<bool> {
    // `_gz_guard` owns any decompressed temp file and must outlive the read.
    let (mut cap, _gz_guard) = match open_offline(path) {
        Ok(opened) => opened,
        Err(e) => {
            if let Some(ready) = ready_tx {
                let _ = ready.send(Err(format!("{e:#}")));
                return Err(e);
            }
            state.tally.skipped += 1;
            state.tally.lost = true;
            tracing::error!("Skipping '{}': {e:#}", path.display());
            return Ok(true);
        }
    };

    if let Some(ref bpf) = config.bpf_filter
        && let Err(e) = cap.filter(bpf, true)
    {
        let err = filter_failure(bpf, path, e);
        state.tally.skipped += 1;
        state.tally.lost = true;
        if let Some(ready) = ready_tx {
            let _ = ready.send(Err(format!("{err:#}")));
        }
        return Err(err);
    }

    if let Some(ready) = ready_tx {
        let _ = ready.send(Ok(()));
    }

    // A read error stops THIS file, not the set. Truncation is the normal
    // state of a ring buffer -- the newest member is still being written when
    // the capture stops, and libpcap reports `truncated dump file` on the
    // trailing partial record. Propagating that with `?` abandoned every
    // remaining file: observed on a 15-file directory where 15 started and 14
    // finished, and it escaped notice only because the truncated member
    // happened to sort last. Whatever was read before the break is already in
    // the store and stays there.
    let read = match read_opened_inner(
        &mut cap,
        path,
        config,
        tx,
        start,
        state.count,
        &mut state.prev_ts,
    ) {
        Ok(read) => read,
        Err(e) => {
            state.tally.stopped_early += 1;
            state.tally.lost = true;
            tracing::error!(
                "Stopped reading '{}' early: {e:#}. Continuing with the rest of the set.",
                path.display()
            );
            return Ok(true);
        }
    };

    if read.reached_eof {
        state.tally.complete += 1;
    } else {
        // A limit or a shutdown landed inside this file. Requested, so not a
        // loss — but the file was still not read to its end.
        state.tally.stopped_early += 1;
    }

    if let Some((first_ts, last_ts)) = read.span {
        if let Some((prev_path, prev_end)) = state.prev_end.as_ref()
            && let Some(msg) = overlap_message(prev_path, *prev_end, path, first_ts)
        {
            tracing::warn!("{msg}");
        }
        state.prev_end = Some((path.to_path_buf(), last_ts));
    }

    Ok(read.reached_eof)
}

/// The error for a BPF filter that will not compile against a file.
///
/// The same error whichever file of the set it happens on. The two arms used to
/// disagree — the first file returned it, every later one logged
/// `Skipping ...` and read on — and the skip is the wrong half of that
/// disagreement: the filter text does not change between files, so a failure is
/// a static misconfiguration against that file's link type, not a mid-read race
/// like a file disappearing from a rotating directory. Skipping quietly dropped
/// the whole traffic of every file with that link type (a Linux-cooked or
/// DLT_NULL member among Ethernet ones) while the run still exited 0 with a
/// confident report. An operator who wants only part of a mixed-link-type set
/// filtered can select it with `--input-name` and run it separately.
fn filter_failure(bpf: &str, path: &Path, e: pcap::Error) -> anyhow::Error {
    anyhow::Error::new(e).context(format!(
        "Failed to compile BPF filter '{bpf}' against '{}'",
        path.display()
    ))
}

/// The warning for a handover where the next file starts before the previous
/// one ended, or `None` when the two are a clean sequence.
///
/// A clean ring buffer hands over cleanly: each file starts after the previous
/// one ends. Overlap means the set is not one sequence — most often two capture
/// runs, or the same traffic collected on two interfaces, mixed into one
/// directory. sipnab will still read it, and the result double-counts every
/// packet that appears twice, so this says so rather than letting the totals
/// quietly disagree with reality.
///
/// This is the check [`super::input_set`] cannot make: a file's END time is not
/// known until its last packet has been read, and reading every file twice to
/// learn it would double the I/O of a 900 MB set. Here the packets stream past
/// anyway, so the end costs nothing.
fn overlap_message(
    prev: &Path,
    prev_end: DateTime<Utc>,
    next: &Path,
    next_start: DateTime<Utc>,
) -> Option<String> {
    if next_start >= prev_end {
        return None;
    }
    let by = prev_end
        .signed_duration_since(next_start)
        .num_milliseconds();
    Some(format!(
        "'{}' starts at {next_start} but '{}' runs to {prev_end} — they overlap by {by} ms, \
         so packets present in both are counted twice",
        next.display(),
        prev.display()
    ))
}

/// Read every packet from an already-opened capture into `tx`.
///
/// Split out of [`capture_file`] so a multi-file set shares one packet count,
/// one duration clock, and one replay timeline across its members —
/// see [`capture_files`].
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

/// What one file's read produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileRead {
    /// Whether the read ran out of packets rather than stopping on a limit, a
    /// shutdown, or a dropped receiver.
    ///
    /// The distinction is the "stop the whole set" signal: a count limit
    /// reached inside file three must not be mistaken for file three simply
    /// ending.
    reached_eof: bool,
    /// Timestamps of the first and last packet actually read, or `None` for a
    /// file that held no packets.
    ///
    /// The end is what the overlap check in [`overlap_message`] needs, and
    /// carrying it out of the read is what makes that check free: the resolver
    /// would have to read every file a second time to learn it.
    span: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

/// The read loop itself.
///
/// Separate from [`read_opened`] only so its [`FileRead`] is available to
/// [`capture_files`], which needs both halves of it.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn read_opened_inner(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    start: std::time::Instant,
    count: &mut u64,
    prev_ts: &mut Option<DateTime<Utc>>,
) -> Result<FileRead> {
    let link_type = cap.get_datalink().0;
    let replay = config.replay;
    // First and last packet of THIS file, tracked unconditionally: `prev_ts`
    // above is the replay pacing state and is only written in replay mode.
    let mut span: Option<(DateTime<Utc>, DateTime<Utc>)> = None;

    if replay {
        tracing::info!("Replaying from '{}' with original timing", path.display());
    } else {
        tracing::info!("Reading from '{}'", path.display());
    }

    // The read stopped short of this file's end. The span it did cover is
    // still reported: it is real, and it is what the overlap check must use.
    macro_rules! stopped {
        () => {
            return Ok(FileRead {
                reached_eof: false,
                span,
            })
        };
    }

    loop {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping file reader");
            stopped!();
        }

        if let Some(max_count) = config.count
            && *count >= max_count
        {
            tracing::debug!("Reached packet count limit ({max_count})");
            stopped!();
        }

        if let Some(duration) = config.duration
            && start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            stopped!();
        }

        match cap.next_packet() {
            Ok(pkt) => {
                let ts = pcap_ts_to_chrono(pkt.header.ts);
                span = Some(match span {
                    Some((first, _)) => (first, ts),
                    None => (ts, ts),
                });

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
                            stopped!();
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
                    stopped!();
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
    Ok(FileRead {
        reached_eof: true,
        span,
    })
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

    /// The closing summary counts files that were READ, not the size of the
    /// set decided before any of them was opened.
    ///
    /// `paths.len()` was the old count, so a run that opened 3 of 27 files
    /// still claimed 27 — which is what made an earlier truncation bug nearly
    /// invisible.
    #[test]
    fn the_summary_reports_files_read_not_files_offered() {
        let tally = ReadTally {
            given: 27,
            complete: 3,
            stopped_early: 1,
            skipped: 2,
            lost: true,
        };
        let line = tally.summary(1234);
        assert!(line.contains("1234 packets"), "{line}");
        assert!(line.contains("3 of 27 file(s) read in full"), "{line}");
        assert!(line.contains("1 stopped early"), "{line}");
        assert!(line.contains("2 skipped"), "{line}");
        assert!(
            line.contains("21 not reached"),
            "the files never opened are the other half of the count: {line}"
        );
        assert!(tally.lossy(), "a read error and two skips are losses");
    }

    /// The overwhelmingly common case stays one clause, and is not a warning.
    #[test]
    fn the_summary_of_a_clean_single_file_run_stays_one_clause() {
        let tally = ReadTally {
            given: 1,
            complete: 1,
            ..ReadTally::default()
        };
        assert_eq!(
            tally.summary(852),
            "Read 852 packets: 1 of 1 file(s) read in full"
        );
        assert!(!tally.lossy());
    }

    /// A requested stop is not a loss: `--count` leaving files unread is what
    /// the operator asked for, so the summary reports it without crying wolf.
    #[test]
    fn a_count_limit_is_reported_but_not_called_a_loss() {
        let tally = ReadTally {
            given: 3,
            stopped_early: 1,
            ..ReadTally::default()
        };
        let line = tally.summary(1);
        assert!(line.contains("0 of 3 file(s) read in full"), "{line}");
        assert!(line.contains("2 not reached"), "{line}");
        assert!(!tally.lossy(), "a limit is not data loss");
    }

    /// A file of the set that cannot be opened is counted, not absorbed.
    #[test]
    fn a_file_of_the_set_that_cannot_be_opened_is_counted_as_skipped() {
        let good = sample_pcap();
        let also_good = fixture_path();
        for p in [&good, &also_good] {
            assert!(p.exists(), "fixture missing: {}", p.display());
        }
        let missing = std::path::PathBuf::from("/nonexistent/definitely-not-a-capture.pcap");

        let (tx, _rx) = packet_channel(TEST_CAP);
        let mut tally = ReadTally {
            given: 3,
            ..ReadTally::default()
        };
        let mut count = 0u64;
        read_set(
            &[good, missing, also_good],
            &CaptureConfig::default(),
            &tx,
            None,
            &mut tally,
            &mut count,
        )
        .expect("one unopenable file must not fail the set");

        assert_eq!(tally.complete, 2, "{tally:?}");
        assert_eq!(tally.skipped, 1, "{tally:?}");
        assert_eq!(tally.not_reached(), 0, "{tally:?}");
        assert!(tally.lossy(), "a file that never opened is a loss");
        assert!(count > 0, "the readable files still contributed packets");
    }

    /// A read reports the span it covered, which is where the end time for the
    /// overlap check comes from — no extra pass over the file.
    #[test]
    fn a_file_read_reports_the_span_it_covered() {
        let path = sample_pcap();
        let (mut cap, _guard) = open_offline(&path).expect("open");
        let (tx, _rx) = packet_channel(TEST_CAP);
        let mut count = 0u64;
        let mut prev_ts = None;
        let read = read_opened_inner(
            &mut cap,
            &path,
            &CaptureConfig::default(),
            &tx,
            std::time::Instant::now(),
            &mut count,
            &mut prev_ts,
        )
        .expect("read");

        assert!(read.reached_eof, "the fixture reads to the end");
        let (first, last) = read.span.expect("the fixture holds packets");
        assert_eq!(
            first.timestamp(),
            1_480_171_979,
            "the fixture's first packet is a fixed fact about it"
        );
        assert!(
            last > first,
            "the last packet cannot precede the first: {first} .. {last}"
        );
    }

    /// Overlap is the previous file's END against the next file's START.
    ///
    /// Comparing consecutive STARTS — what the resolver could see without
    /// reading anything — never described the case the warning exists for: two
    /// capture runs, or the same traffic collected on two interfaces, whose
    /// packets are then counted twice.
    #[test]
    fn overlap_is_the_previous_end_against_the_next_start() {
        let t = |s: i64| DateTime::from_timestamp(s, 0).expect("timestamp");
        let a = Path::new("first.pcap");
        let b = Path::new("second.pcap");

        // second.pcap starts 30 s before first.pcap ends: the two hold the same
        // 30 s of traffic and every count spanning it is inflated.
        let msg = overlap_message(a, t(1_767_225_660), b, t(1_767_225_630))
            .expect("an overlapping handover must be reported");
        assert!(
            msg.contains("first.pcap") && msg.contains("second.pcap"),
            "{msg}"
        );
        assert!(
            msg.contains("twice"),
            "the consequence must be stated: {msg}"
        );
    }

    /// A clean ring-buffer handover is silent: file N+1 starts after file N
    /// ends, which is the normal state of every `tcpdump -C -W` set.
    #[test]
    fn a_clean_handover_is_not_reported_as_overlap() {
        let t = |s: i64| DateTime::from_timestamp(s, 0).expect("timestamp");
        assert!(
            overlap_message(
                Path::new("a.pcap"),
                t(1_767_225_630),
                Path::new("b.pcap"),
                t(1_767_225_660),
            )
            .is_none()
        );
    }

    /// Helper: a sample whose link type is NOT Ethernet, so an `ether` filter
    /// cannot compile against it. `h263-over-rtp.pcap` is DLT_NULL (BSD
    /// loopback); libpcap rejects `ether host ...` on it.
    fn non_ethernet_pcap() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pcap-samples")
            .join("h263-over-rtp.pcap")
    }

    /// A BPF filter that does not compile fails the run wherever in the set it
    /// fails — not only when the file it fails on happens to sort first.
    ///
    /// The two arms used to disagree: the first file returned the error, every
    /// later one logged `Skipping ...` and read on. A filter that will not
    /// compile against a link type is a static misconfiguration, not a
    /// mid-read race, so the whole traffic of that file — and of every other
    /// file sharing its link type — left the analysis behind one log line while
    /// the run still exited 0.
    #[test]
    fn a_bpf_filter_that_does_not_compile_fails_on_a_later_file_too() {
        let ethernet = sample_pcap();
        let other_link = non_ethernet_pcap();
        for p in [&ethernet, &other_link] {
            assert!(p.exists(), "fixture missing: {}", p.display());
        }
        let config = CaptureConfig {
            // Compiles against Ethernet, cannot compile against DLT_NULL.
            bpf_filter: Some("ether host 00:00:00:00:00:01".to_string()),
            ..CaptureConfig::default()
        };

        // Failing on the FIRST file has always been an error.
        let (tx, _rx) = packet_channel(TEST_CAP);
        let first = capture_files(&[other_link.clone(), ethernet.clone()], &config, tx, None);
        assert!(first.is_err(), "first-file filter failure must error");

        // Failing on a LATER file must be the same error, not a skip.
        let (tx, _rx) = packet_channel(TEST_CAP);
        let later = capture_files(&[ethernet, other_link], &config, tx, None);
        let err = later.expect_err(
            "a filter that does not compile against file 2's link type must fail \
             the run, not silently drop that file's traffic",
        );
        assert!(
            format!("{err:#}").contains("BPF filter"),
            "the error must name the filter: {err:#}"
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
