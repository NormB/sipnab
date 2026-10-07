// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pcap file reader.
//!
//! Reads packets from a pcap (or pcap-ng) file and sends them through a
//! crossbeam channel. Supports BPF filtering, packet count limits, and
//! duration limits. EOF is treated as a clean exit.

use std::path::Path;

use super::channel::{self, PacketTx};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use super::CaptureConfig;
use super::live::ReadStep;
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
/// The decompression is [`crate::capture::archive`]'s, so it runs under the
/// same `--max-gunzip-bytes` ceiling as every archive layer; it used to inflate
/// to disk with no bound at all. An ARCHIVE of several captures is refused by
/// name: this opens one capture, and an archive is a set, which `-I`, the TUI
/// file browser and MCP `open_capture` each read as one.
///
/// Returns the open capture together with an optional guard. The guard owns
/// the decompressed file and deletes it on drop, so the caller MUST keep it
/// alive for as long as it reads from the capture.
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
pub fn open_offline(path: &Path) -> Result<(pcap::Capture<pcap::Offline>, Option<OfflineGuard>)> {
    open_offline_with(path, &crate::capture::archive::Limits::for_run())
}

/// Owns whatever [`open_offline`] decompressed, and deletes it on drop.
#[derive(Debug)]
pub struct OfflineGuard {
    /// The unwrapped capture and its directory.
    _expansion: crate::capture::archive::Expansion,
}

/// [`open_offline`] with explicit inflation limits.
///
/// # Errors
///
/// As [`open_offline`].
pub fn open_offline_with(
    path: &Path,
    limits: &crate::capture::archive::Limits,
) -> Result<(pcap::Capture<pcap::Offline>, Option<OfflineGuard>)> {
    use crate::capture::archive;

    match archive::container_format(path) {
        Ok(Some(f)) if archive::unwraps(f) => {}
        Ok(Some(other)) => anyhow::bail!(
            "Failed to open '{}': {}",
            crate::capture::archive::source_name(path),
            archive::SkipReason::Unsupported(other)
        ),
        // A capture, or something libpcap will judge and name.
        Ok(None) | Err(_) => {
            let cap = pcap::Capture::from_file(path).with_context(|| {
                format!(
                    "Failed to open pcap file '{}'",
                    crate::capture::archive::source_name(path)
                )
            })?;
            return Ok((cap, None));
        }
    }

    let exp = archive::expand(path, limits).with_context(|| {
        format!(
            "Failed to unpack '{}'",
            crate::capture::archive::source_name(path)
        )
    })?;
    if let Some(stop) = exp.stops.first() {
        anyhow::bail!(
            "Failed to open '{}': {stop}",
            crate::capture::archive::source_name(path)
        );
    }
    // A compressed capture unwraps to exactly one member that keeps the
    // file's own name. Anything else is an archive: a set, not a capture.
    let own_name = crate::capture::archive::source_name(path).to_string();
    match exp.members.as_slice() {
        [only] if only.label == own_name => {
            let cap = pcap::Capture::from_file(&only.path).with_context(|| {
                format!(
                    "Failed to open decompressed capture from '{}'",
                    crate::capture::archive::source_name(path)
                )
            })?;
            Ok((cap, Some(OfflineGuard { _expansion: exp })))
        }
        [] => match exp.skipped.first() {
            Some(s) => anyhow::bail!("Failed to open '{}': {}", s.label, s.reason),
            None => anyhow::bail!(
                "Failed to open '{}': it holds no capture",
                crate::capture::archive::source_name(path)
            ),
        },
        members => anyhow::bail!(
            "'{}' is an archive holding {} capture(s), and this opens one capture. \
             Read it as a set: -I takes an archive the way it takes a directory",
            crate::capture::archive::source_name(path),
            members.len()
        ),
    }
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
    // A pcapng whose interfaces disagree on snaplen or link type. libpcap
    // accepts the file and then fails on the first packet naming a second
    // interface, so this is decided up front rather than by catching an error
    // that arrives mid-loop. Per-packet encapsulation is the point of a merged
    // capture, so no rewrite makes libpcap read one.
    if crate::capture::merged::is_merged(path) {
        match crate::capture::merged::MergedPcapNg::open(path) {
            Ok(merged) => {
                if let Some(ready) = ready_tx {
                    let _ = ready.send(Ok(()));
                }
                let mut count: u64 = 0;
                read_merged(merged, path, config, &tx, &mut count)?;
                return Ok(());
            }
            Err(e) => {
                if let Some(ready) = ready_tx {
                    let _ = ready.send(Err(format!("{e:#}")));
                }
                return Err(e);
            }
        }
    }

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
        let err = anyhow::Error::new(e).context(format!(
            "Failed to compile BPF filter: {bpf}{}",
            crate::capture::bpf_filter::positional_filter_hint(config.bpf_filter_positional)
                .map_or_else(String::new, |h| format!(". {h}"))
        ));
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
        ReadTimeline {
            start: std::time::Instant::now(),
            count: &mut count,
            prev_ts: &mut prev_ts,
        },
    )
}

/// Read a merged pcapng, taking each frame's link type from its own interface.
///
/// Deliberately simpler than [`read_opened_inner`]: no send batching, no replay
/// pacing, no multi-file ordinal continuity. Those exist for the hot path, and
/// this is the path for a capture libpcap will not open at all — an assembled
/// artifact, not a live ring buffer. Reaching for them here would duplicate two
/// hundred lines of the loop that matters to serve the case that does not.
fn read_merged(
    mut merged: crate::capture::merged::MergedPcapNg,
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    count: &mut u64,
) -> Result<u64> {
    let source: std::sync::Arc<str> = crate::capture::archive::source_arc(path);
    let types: Vec<String> = merged.link_types().iter().map(i32::to_string).collect();
    tracing::info!(
        "Reading '{}' with the merged-pcapng decoder: libpcap refuses a file \
         whose interfaces disagree. Link types present: {}",
        crate::capture::archive::source_name(path),
        types.join(", ")
    );

    // Run-global, like every other reader: `--count` spans a whole set, and a
    // summary built from a per-file counter would disagree with the limit.
    let started_at = *count;
    send_merged_frames(&mut merged, config, tx, &source, count);

    // Said out loud, because a frame dropped in silence is indistinguishable
    // from a capture that never held it.
    let skipped = merged.skipped();
    if skipped > 0 {
        tracing::warn!(
            "{skipped} block(s) in '{}' named an interface the file never \
             described and were not read",
            crate::capture::archive::source_name(path)
        );
    }
    let read = *count - started_at;
    tracing::info!(
        "Read {read} packets from '{}'",
        crate::capture::archive::source_name(path)
    );
    Ok(read)
}

/// Send every frame of a merged pcapng, until the frames run out, shutdown
/// is requested, `--count` is reached, or the receiver is gone.
fn send_merged_frames(
    merged: &mut crate::capture::merged::MergedPcapNg,
    config: &CaptureConfig,
    tx: &PacketTx,
    source: &std::sync::Arc<str>,
    count: &mut u64,
) {
    let mut ordinal: u64 = 0;
    while let Some(frame) = merged.next_frame() {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping merged reader");
            break;
        }
        if super::live::count_limit_reached(config.count, *count) {
            break;
        }

        let packet = merged_packet(frame, ordinal, source);
        ordinal += 1;
        *count += 1;
        if tx.send(packet).is_err() {
            tracing::debug!("Receiver dropped, stopping merged reader");
            break;
        }
    }
}

/// The packet for one merged-pcapng frame at position `ordinal` of `source`.
#[inline]
fn merged_packet(
    frame: crate::capture::merged::MergedFrame,
    ordinal: u64,
    source: &std::sync::Arc<str>,
) -> Packet {
    let mut packet = Packet::with_source(
        frame.ts,
        frame.data,
        frame.caplen as usize,
        frame.origlen as usize,
        Some(std::sync::Arc::clone(source)),
        // The whole reason this path exists.
        frame.link_type,
    );
    packet.origin = Some(crate::capture::packet::FrameOrigin {
        ordinal,
        // Not hashed here. The digest verifies a pointer something KEPT,
        // and ~93% of frames are never pointed at, so hashing on the reader
        // spends the one serial stage on work nobody can use.
        // `ParsedPacket::retained_frame_ref` computes it where the pointer
        // is stored, over the same bytes, to the same FNV-1a value.
        digest: None,
        // A capture file can be reopened, so the question a digest answers
        // is one this source can actually be asked.
        verifiable: true,
    });
    packet
}

/// Read a set of capture files, in order, into one packet stream.
///
/// The files feed a single channel and therefore a single dialog store, which
/// is the whole point: `tcpdump -C -W` splits a busy capture across a ring
/// buffer, and a call whose INVITE lands in `tg.pcap3` and whose BYE lands in
/// `tg.pcap4` is only reconstructable if both are read without resetting state
/// in between. Analyzed separately, one file shows a call that never ends and
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
/// * `ready_tx` - optional one-shot, signaled once the FIRST file is open and
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
    tally.report(count);
    result
}

/// What became of each file of one `-I` set.
///
/// The old summary was `"Read {count} packets from {} file(s)", paths.len()` —
/// the size of the set decided BEFORE any file was opened. Both `continue`
/// arms and the read-error arm fell through to it, so a run that opened 3 of 27
/// files still claimed 27, and an earlier truncation bug that abandoned twelve
/// files was nearly invisible because the line it printed did not change.
///
/// `pub(crate)` because the parallel reader in [`crate::parallel`] tallies into
/// the same type rather than growing a second one. `--cores N` reads the same
/// `-I` set as `--cores 1` and owes the operator the same account of it; two
/// implementations of that account would be two sentences to keep in step, and
/// the one that is printed less often is the one that would drift. The parallel
/// path went further than drifting and printed nothing at all, so a `--cores`
/// run over a 27-file directory said which files it OPENED and never said how
/// many it finished.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadTally {
    /// Files in the resolved set — what used to be reported on its own.
    pub(crate) given: usize,
    /// Files read through to their last packet.
    pub(crate) complete: usize,
    /// Files whose read stopped before their end: a mid-file read error, or a
    /// `--count`/`--duration` limit or shutdown landing inside them.
    pub(crate) stopped_early: usize,
    /// Files that never yielded a packet: they could not be opened, or the BPF
    /// filter would not compile against their link type.
    pub(crate) skipped: usize,
    /// Whether anything was lost rather than merely left unread on request.
    ///
    /// Separate from the counts because `--count 100` over a 27-file set stops
    /// early and leaves 26 files unread by design; a read error or a file that
    /// would not open is data missing from the analysis, and only that turns
    /// the summary into a warning.
    pub(crate) lost: bool,
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

    /// Emit the closing line, at the severity the outcome earns.
    ///
    /// Both readers end here instead of formatting their own line, so the ONE
    /// sentence an operator uses to decide whether a run saw the whole capture
    /// cannot say something different depending on whether `--cores` was
    /// passed. The severity is half of that sentence and is bound to it for the
    /// same reason: a set with a file missing from it must reach a `warn`-level
    /// log — which is the level a batch run's stderr is usually filtered to —
    /// while a `--count` limit leaving files unread is what was asked for and
    /// stays `info`, or the warning that matters is buried under the ones that
    /// do not.
    ///
    /// The same tally also lands in `output::run_integrity`, from here and
    /// only from here. A person reads the stderr sentence and a script reads
    /// the record, but they are ONE statement about the run, and emitting them
    /// from two places is how they come to disagree — the same argument that
    /// put both readers' closing lines in this one function. It also means the
    /// identical `lost` predicate decides the log severity and moves `$?`, so
    /// `warn` on stderr and a non-zero exit cannot come apart.
    ///
    /// # Arguments
    ///
    /// * `packets` — packets the run read across the whole set.
    ///
    /// # Side effects
    ///
    /// Emits exactly one `warn!` (data missing) or `info!` (clean, or a
    /// requested stop) line via tracing, and adds this set's outcome to the
    /// process-global run-integrity record.
    pub(crate) fn report(&self, packets: u64) {
        let line = self.summary(packets);
        if self.lossy() {
            tracing::warn!("{line}");
        } else {
            tracing::info!("{line}");
        }
        crate::output::run_integrity::record_files_read(
            crate::output::run_integrity::FileReadOutcome {
                given: self.given as u64,
                read_in_full: self.complete as u64,
                stopped_early: self.stopped_early as u64,
                skipped: self.skipped as u64,
                not_reached: self.not_reached() as u64,
                lost: self.lost,
            },
        );
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

/// Where a read stands on the run's timeline: when it started, how many
/// packets went out, and the previous packet's time.
///
/// One value because the three together are what make several files read as
/// one capture (one `--count`, one `--duration` clock, one replay timeline),
/// and a reader handed only some of them would keep its own.
struct ReadTimeline<'a> {
    /// When the run started reading, for `--duration`.
    start: std::time::Instant,
    /// Packets sent so far, across every file read on this timeline.
    count: &'a mut u64,
    /// Previous packet's timestamp, so replay reproduces the gaps.
    prev_ts: &'a mut Option<DateTime<Utc>>,
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

    // The first file READ owns readiness: opening it is what proves the whole
    // set is usable, and the consumer starts as soon as it is signaled. That
    // is the first file unless it is skipped outright — an undecodable link
    // type the filter cannot apply to — in which case the next one inherits
    // it, or the consumer would wait on a signal nothing will ever send.
    let mut ready = ready_tx;
    for path in std::iter::once(first).chain(rest) {
        if !read_member(path, config, tx, start, &mut state, &mut ready)? {
            break;
        }
    }
    if let Some(ready) = ready {
        let _ = ready.send(Err(
            "no file of the set could be read: every one was skipped".to_string(),
        ));
        anyhow::bail!("no file of the set could be read: every one was skipped");
    }
    Ok(())
}

/// Read one file of a set. Returns whether the set should continue.
///
/// `ready_tx` is `Some` only until a file takes it — the first file read —
/// and that is the one asymmetry left between the members: a first file that
/// will not open has proved the whole set unusable before the consumer
/// started, so it fails the run, while a later one is logged and skipped. The set was already probed during
/// resolution, so a later open failure means something changed underneath us
/// mid-read — a rotating capture directory being cleaned up while it is
/// analyzed — and losing one file of a set is bad where losing the analysis of
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
    ready_tx: &mut Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<bool> {
    // A set may hold a merged pcapng; same up-front check as the single-file
    // path, for the same reason. Skipping it would drop a whole member while
    // the run reported success on the rest.
    if crate::capture::merged::is_merged(path)
        && let Ok(merged) = crate::capture::merged::MergedPcapNg::open(path)
    {
        if let Some(ready) = ready_tx.take() {
            let _ = ready.send(Ok(()));
        }
        // Counted into the set tally like any other member, or the closing
        // summary reports "0 packets, 1 file not reached" for a file it just
        // read in full -- a contradiction the operator has to resolve alone.
        read_merged(merged, path, config, tx, state.count)?;
        state.tally.complete += 1;
        return Ok(true);
    }

    // `_gz_guard` owns any decompressed temp file and must outlive the read.
    let (mut cap, _gz_guard) = match open_offline(path) {
        Ok(opened) => opened,
        Err(e) => return skip_unopened_member(path, e, state, ready_tx),
    };

    let link_type = cap.get_datalink().0;
    if filter_member(&mut cap, path, link_type, config, state, ready_tx)? == MemberFilter::Skipped {
        return Ok(true);
    }
    if !crate::capture::parse::link_type_is_decoded(link_type) {
        // Read anyway: every frame is then counted, by reason, in the
        // undecodable tally the run summary reports. This line says WHICH
        // file those frames came from, which the tally cannot.
        tracing::warn!(
            "'{}' has link type {link_type}, which sipnab does not decode; its frames \
             are counted as not decoded",
            crate::capture::archive::source_name(path)
        );
    }

    if let Some(ready) = ready_tx.take() {
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
        ReadTimeline {
            start,
            count: state.count,
            prev_ts: &mut state.prev_ts,
        },
    ) {
        Ok(read) => read,
        Err(e) => {
            state.tally.stopped_early += 1;
            state.tally.lost = true;
            tracing::error!(
                "Stopped reading '{}' early: {e:#}. Continuing with the rest of the set.",
                crate::capture::archive::source_name(path)
            );
            return Ok(true);
        }
    };

    state.record_read(path, read);
    Ok(read.reached_eof)
}

/// A member that would not open: the first file read fails the run with `e`,
/// a later one is skipped, counted as lost, and the set continues.
fn skip_unopened_member(
    path: &Path,
    e: anyhow::Error,
    state: &mut SetState,
    ready_tx: &mut Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<bool> {
    if let Some(ready) = ready_tx.take() {
        let _ = ready.send(Err(format!("{e:#}")));
        return Err(e);
    }
    state.tally.skipped += 1;
    state.tally.lost = true;
    tracing::error!(
        "Skipping '{}': {e:#}",
        crate::capture::archive::source_name(path)
    );
    Ok(true)
}

/// Whether a member's BPF filter let it be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberFilter {
    /// No filter, or the filter compiled and is installed: read the member.
    Installed,
    /// The filter does not compile against a link type sipnab does not
    /// decode: the member is skipped and the set continues.
    Skipped,
}

/// Install the BPF filter on one member of a set.
///
/// # Errors
///
/// The filter does not compile against a link type sipnab decodes. That ends
/// the set; see [`filter_failure`].
fn filter_member(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &Path,
    link_type: i32,
    config: &CaptureConfig,
    state: &mut SetState,
    ready_tx: &mut Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> Result<MemberFilter> {
    let Some(ref bpf) = config.bpf_filter else {
        return Ok(MemberFilter::Installed);
    };
    let Err(e) = cap.filter(bpf, true) else {
        return Ok(MemberFilter::Installed);
    };
    // A member sipnab could not decode a frame of anyway loses nothing by
    // being skipped, so a filter that will not compile against ITS link
    // type is no reason to end the set. The rule below still holds for
    // every link type sipnab decodes: skipping one of those would drop
    // real traffic while the run reported success.
    if let Some(line) = undecodable_filter_skip(path, link_type, bpf, &e) {
        state.tally.skipped += 1;
        tracing::warn!("{line}");
        return Ok(MemberFilter::Skipped);
    }
    let err = filter_failure(bpf, path, e, config.bpf_filter_positional);
    state.tally.skipped += 1;
    state.tally.lost = true;
    if let Some(ready) = ready_tx.take() {
        let _ = ready.send(Err(format!("{err:#}")));
    }
    Err(err)
}

impl SetState<'_> {
    /// Tally a member read without error, and warn when it starts before the
    /// previous member that held packets ended.
    fn record_read(&mut self, path: &Path, read: FileRead) {
        if read.reached_eof {
            self.tally.complete += 1;
        } else {
            // A limit or a shutdown landed inside this file. Requested, so not a
            // loss — but the file was still not read to its end.
            self.tally.stopped_early += 1;
        }

        if let Some((first_ts, last_ts)) = read.span {
            if let Some((prev_path, prev_end)) = self.prev_end.as_ref()
                && let Some(msg) = overlap_message(prev_path, *prev_end, path, first_ts)
            {
                tracing::warn!("{msg}");
            }
            self.prev_end = Some((path.to_path_buf(), last_ts));
        }
    }
}

/// The warning to log when a BPF filter that will not compile against `path`
/// should SKIP it rather than end the set — or `None` when it must end the set.
///
/// Skipped only when sipnab does not decode `link_type` at all: every frame of
/// such a file would be counted as not decoded whatever the filter said, so
/// skipping it loses nothing a filter could have selected. For a link type
/// sipnab DOES decode, [`filter_failure`]'s refusal stands. One rule for both
/// readers, so `--cores` cannot come to skip what `--cores 1` refuses.
pub(crate) fn undecodable_filter_skip(
    path: &Path,
    link_type: i32,
    bpf: &str,
    e: &pcap::Error,
) -> Option<String> {
    if crate::capture::parse::link_type_is_decoded(link_type) {
        return None;
    }
    Some(format!(
        "Skipping '{}': link type {link_type}, which sipnab does not decode, and the \
         BPF filter '{bpf}' does not compile against it ({e})",
        crate::capture::archive::source_name(path)
    ))
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
///
/// `pub(crate)` for the same reason [`ReadTally`] is: the parallel reader in
/// [`crate::parallel`] refuses on exactly this condition and must refuse with
/// exactly this sentence. It used to build its own — `Failed to compile BPF
/// filter '{bpf}': {e}` — which named the filter and NOT the file, so the one
/// question an operator has when a forty-file set stops ("which of them?") had
/// no answer in the error itself. Two constructors are two wordings to keep in
/// step; one is one.
pub(crate) fn filter_failure(
    bpf: &str,
    path: &Path,
    e: pcap::Error,
    positional: bool,
) -> anyhow::Error {
    anyhow::Error::new(e).context(format!(
        "Failed to compile BPF filter '{bpf}' against '{}'{}",
        crate::capture::archive::source_name(path),
        crate::capture::bpf_filter::positional_filter_hint(positional)
            .map_or_else(String::new, |h| format!(". {h}"))
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
        crate::capture::archive::source_name(next),
        crate::capture::archive::source_name(prev)
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
    timeline: ReadTimeline<'_>,
) -> Result<()> {
    let _ = read_opened_inner(cap, path, config, tx, timeline)?;
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

/// Accumulates a regular file's packets into channel batches.
///
/// One [`PacketTx::send_many`] per [`FILE_BATCH`](channel::FILE_BATCH) packets
/// instead of one `send` per packet: the per-packet slot claim, storage send
/// and receiver wake-up were ~35% of a single-core reconstruction's wall time,
/// against ~9% for the analysis itself. A batch costs one of each.
///
/// Only the non-replay regular-file read uses this. Replay reproduces
/// inter-packet timing, so each packet must be visible the moment its moment
/// arrives; and a FIFO or other non-regular path can trickle, which would
/// leave up to a batch of packets parked here while the producer stalls.
/// Both keep the per-packet send.
struct SendBatcher<'a> {
    /// The channel these batches are sent on.
    tx: &'a PacketTx,
    /// Packets accumulated toward the next batch; flushed at
    /// [`FILE_BATCH`](channel::FILE_BATCH) and at every exit from the read loop.
    buf: Vec<Packet>,
}

impl<'a> SendBatcher<'a> {
    /// A batcher sending on `tx`, its buffer sized to one batch.
    fn new(tx: &'a PacketTx) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(channel::FILE_BATCH),
        }
    }

    /// Buffer one packet, flushing when the batch is full.
    ///
    /// # Errors
    ///
    /// `Err(n)` when the receiver is gone: `n` packets (this one included)
    /// were dropped with the dead channel, so the caller can keep its
    /// delivered-count honest before it stops.
    fn push(&mut self, packet: Packet) -> Result<(), u64> {
        self.buf.push(packet);
        if self.buf.len() >= channel::FILE_BATCH {
            self.flush()
        } else {
            Ok(())
        }
    }

    /// Send whatever is buffered. Called at every exit from the read loop —
    /// EOF, shutdown, `--count`/`--duration` limits, and read errors — so a
    /// packet that was read is never quietly left behind in this buffer.
    ///
    /// # Errors
    ///
    /// `Err(n)`: the receiver is gone and `n` buffered packets went with it.
    fn flush(&mut self) -> Result<(), u64> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let n = self.buf.len() as u64;
        let batch = std::mem::replace(&mut self.buf, Vec::with_capacity(channel::FILE_BATCH));
        self.tx.send_many(batch).map_err(|_| n)
    }
}

/// The read loop itself.
///
/// Separate from [`read_opened`] only so its [`FileRead`] is available to
/// [`capture_files`], which needs both halves of it.
fn read_opened_inner(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &Path,
    config: &CaptureConfig,
    tx: &PacketTx,
    timeline: ReadTimeline<'_>,
) -> Result<FileRead> {
    let ReadTimeline {
        start,
        count,
        prev_ts,
    } = timeline;
    let replay = config.replay;

    announce_read(path, replay);

    let reader = FileReader {
        tx,
        config,
        start,
        count,
        prev_ts,
        link_type: cap.get_datalink().0,
        // The source stamped on every packet this file yields. Interned ONCE per
        // file: the value is the same string for all of them, so each packet
        // clones an `Arc` (a refcount increment) instead of allocating the path
        // again — a 14M-packet corpus would otherwise pay 14M allocations for one
        // constant. Cheap enough that no packet is left unstamped, which matters:
        // an unstamped packet is one the pcapng writer cannot tell apart from the
        // previous file's, and it then names the wrong file as its origin.
        source: crate::capture::archive::source_arc(path),
        // Position within THIS file, which is not the same question as `count`.
        // `count` is run-global: it drives `--count` and the "N packets total"
        // summary, and it keeps rising across a set. This one restarts at zero for
        // every file, because a frame is identified by the file it lives in plus
        // where it sits in that file. Counting across the run would give the same
        // bytes a different name depending on how the run was invoked, and a
        // pointer that moves with the command line cannot be compared between two
        // runs.
        ordinal: 0,
        // First and last packet of THIS file, tracked unconditionally: `prev_ts`
        // above is the replay pacing state and is only written in replay mode.
        span: None,
        batcher: batches_sends(path, replay).then(|| SendBatcher::new(tx)),
    };

    reader.run(cap, path)
}

/// Whether the read of `path` batches its sends: only the plain read of a
/// regular file does. See [`SendBatcher`] for why replay and non-regular paths
/// keep the per-packet send.
fn batches_sends(path: &Path, replay: bool) -> bool {
    !replay && path.metadata().is_ok_and(|m| m.is_file())
}

/// Log which file is being read, and whether with its original timing.
fn announce_read(path: &Path, replay: bool) {
    if replay {
        tracing::info!(
            "Replaying from '{}' with original timing",
            crate::capture::archive::source_name(path)
        );
    } else {
        tracing::info!(
            "Reading from '{}'",
            crate::capture::archive::source_name(path)
        );
    }
}

/// One file's read in progress: where its packets go, what stamps them, and
/// the run's timeline it advances.
struct FileReader<'a> {
    /// The channel each packet is sent on when it is not batched.
    tx: &'a PacketTx,
    /// Count and duration limits, and the replay flag.
    config: &'a CaptureConfig,
    /// When the run started reading, for `--duration`.
    start: std::time::Instant,
    /// Packets sent so far, across every file read on this timeline.
    count: &'a mut u64,
    /// Previous packet's timestamp, so replay reproduces the gaps.
    prev_ts: &'a mut Option<DateTime<Utc>>,
    /// The file's link type, stamped on every packet.
    link_type: i32,
    /// The source name stamped on every packet.
    source: std::sync::Arc<str>,
    /// Position of the next packet within this file.
    ordinal: u64,
    /// First and last packet of this file.
    span: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// The send batcher, for the plain read of a regular file.
    batcher: Option<SendBatcher<'a>>,
}

impl FileReader<'_> {
    /// Read packets until the file ends, a limit or shutdown stops the read,
    /// the receiver is gone, or libpcap reports an error.
    fn run(mut self, cap: &mut pcap::Capture<pcap::Offline>, path: &Path) -> Result<FileRead> {
        loop {
            if self.limit_reached() {
                return Ok(self.stopped());
            }

            match cap.next_packet() {
                Ok(pkt) => {
                    if self.take(&pkt) == ReadStep::Stop {
                        return Ok(self.stopped());
                    }
                }
                Err(pcap::Error::NoMorePackets) => {
                    tracing::debug!("End of file reached");
                    break;
                }
                Err(e) => {
                    // The packets read before the error are real and already
                    // counted; they go out before the error does.
                    self.flush();
                    tracing::error!(
                        "Error reading pcap file '{}': {e}",
                        crate::capture::archive::source_name(path)
                    );
                    return Err(e).context("Error reading pcap file");
                }
            }
        }

        // EOF: the last partial batch goes out before this file is declared done.
        self.flush();

        tracing::info!(
            "File reader finished: {} packets total, through '{}'",
            self.count,
            crate::capture::archive::source_name(path)
        );
        Ok(FileRead {
            reached_eof: true,
            span: self.span,
        })
    }

    /// Whether shutdown, `--count` or `--duration` ends the read before the
    /// next packet.
    #[inline]
    fn limit_reached(&self) -> bool {
        if signals::shutdown_requested() {
            tracing::debug!("Shutdown requested, stopping file reader");
            return true;
        }

        if super::live::count_limit_reached(self.config.count, *self.count) {
            return true;
        }

        if let Some(duration) = self.config.duration
            && self.start.elapsed() >= duration
        {
            tracing::debug!("Reached duration limit ({duration:?})");
            return true;
        }
        false
    }

    /// The read stopped short of this file's end. The span it did cover is
    /// still reported: it is real, and it is what the overlap check must use.
    /// Buffered packets go out first — they were read, so they are owed to the
    /// consumer — and a flush the dead channel refuses is subtracted from the
    /// delivered count it was optimistically added to.
    fn stopped(&mut self) -> FileRead {
        self.flush();
        FileRead {
            reached_eof: false,
            span: self.span,
        }
    }

    /// Send whatever the batcher holds, taking back from the delivered count
    /// what a dead channel refused.
    fn flush(&mut self) {
        if let Some(b) = self.batcher.as_mut()
            && let Err(lost) = b.flush()
        {
            *self.count = self.count.saturating_sub(lost);
        }
    }

    /// Stamp one packet read from the file, pace it in replay, and send it.
    #[inline]
    fn take(&mut self, pkt: &pcap::Packet<'_>) -> ReadStep {
        let ts = pcap_ts_to_chrono(pkt.header.ts);
        self.span = Some(match self.span {
            Some((first, _)) => (first, ts),
            None => (ts, ts),
        });

        if self.config.replay && self.replay_delay_interrupted(ts) {
            tracing::debug!("Shutdown requested during replay delay, stopping file reader");
            return ReadStep::Stop;
        }

        let mut packet = Packet::with_source(
            ts,
            pkt.data.to_vec(),
            pkt.header.caplen as usize,
            pkt.header.len as usize,
            // The file IS this packet's source. Without it a
            // multi-file set is indistinguishable downstream and the
            // pcapng export attributes every frame to the first
            // input — including the ones read out of the others.
            Some(std::sync::Arc::clone(&self.source)),
            self.link_type,
        );
        // Stamped here, beside the source, because these two together
        // are what makes the frame nameable. Set before the send: once
        // the packet is on the channel this thread cannot amend it, and
        // a consumer that inferred the ordinal from arrival order would
        // be wrong the moment anything reorders or drops.
        packet.origin = Some(crate::capture::packet::FrameOrigin {
            ordinal: self.ordinal,
            // See the note in `merged_packet`: hashed at retention, not
            // here. The ordinal still must be stamped before the send,
            // for the reason above; the digest has no such constraint,
            // because the bytes travel with the packet.
            digest: None,
            verifiable: true,
        });
        self.ordinal += 1;
        self.send(packet)
    }

    /// Replay mode: reproduce the inter-packet gap before the packet at `ts`,
    /// but sleep in bounded slices that poll the shutdown flag between them,
    /// so a large delta cannot delay shutdown by more than one slice.
    ///
    /// Returns whether shutdown interrupted the wait.
    fn replay_delay_interrupted(&mut self, ts: DateTime<Utc>) -> bool {
        if let Some(prev) = *self.prev_ts {
            let delta = ts.signed_duration_since(prev);
            if let Ok(dur) = delta.to_std()
                && !dur.is_zero()
                && sleep_interruptible(dur, signals::shutdown_requested)
            {
                return true;
            }
            // Negative deltas (out-of-order timestamps) are skipped
        }
        *self.prev_ts = Some(ts);
        false
    }

    /// Send one packet, batched or on its own. `Stop` when the receiver is
    /// gone.
    #[inline]
    fn send(&mut self, packet: Packet) -> ReadStep {
        match self.batcher.as_mut() {
            Some(b) => {
                // Counted at read time, so the `--count` check at the
                // loop top sees packets still sitting in the batch and
                // the limit stays exact. A flush the dead channel
                // refuses subtracts what it dropped.
                *self.count += 1;
                if let Err(lost) = b.push(packet) {
                    *self.count = self.count.saturating_sub(lost);
                    tracing::debug!("Receiver dropped, stopping file reader");
                    return ReadStep::Stop;
                }
            }
            None => {
                if self.tx.send(packet).is_err() {
                    tracing::debug!("Receiver dropped, stopping file reader");
                    return ReadStep::Stop;
                }
                *self.count += 1;
            }
        }
        ReadStep::Continue
    }
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

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A capacity large enough that `capture_file` (which sends every packet
    /// before the test drains) never blocks on the cap.
    const TEST_CAP: usize = 1 << 20;

    /// Out-of-range/negative `tv_usec` values from a hostile capture must
    /// clamp rather than overflow the u32 nanosecond conversion.
    #[test]
    #[serial_test::serial(invalid_timestamps)]
    fn pcap_ts_to_chrono_out_of_range_usec_does_not_panic() -> Result<(), TestError> {
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
        Ok(())
    }

    /// A huge replay inter-packet delta must not delay shutdown: the sleep is
    /// sliced and polls the stop signal between slices, so it returns promptly
    /// once the signal fires instead of blocking for the full duration.
    /// Regression for the "large delta delays shutdown arbitrarily" gap.
    #[test]
    fn sleep_interruptible_returns_promptly_on_stop() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Without a stop signal the sliced sleep runs to completion and reports
    /// that it was not interrupted.
    #[test]
    fn sleep_interruptible_runs_to_completion_without_stop() -> Result<(), TestError> {
        let started = std::time::Instant::now();
        let interrupted = sleep_interruptible(std::time::Duration::from_millis(120), || false);
        assert!(!interrupted, "no stop signal → not interrupted");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(100),
            "must actually sleep the requested duration"
        );
        Ok(())
    }

    /// A tv_sec/tv_usec that cannot be represented must fall back to the wall
    /// clock *loudly*: like live capture, the file/replay path must count the
    /// event in the shared `INVALID_PCAP_TIMESTAMPS` counter rather than
    /// silently substituting "now". Regression for the consistency gap where
    /// `file.rs` fell back without counting while `live.rs` counted+warned.
    #[test]
    #[serial_test::serial(invalid_timestamps)]
    fn fallback_to_now_is_counted_like_live() -> Result<(), TestError> {
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
        Ok(())
    }

    /// Helper: path to the test fixture pcap.
    fn fixture_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("udp_5060.pcap")
    }

    /// Helper: path to a checked-in sample capture.
    fn sample(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("pcap-samples")
            .join(name)
    }

    /// Helper: a real multi-packet SIP/RTP sample (classic pcap).
    fn sample_pcap() -> std::path::PathBuf {
        sample("sip-rtp-g711.pcap")
    }

    /// Read a capture file via `capture_file` and return the packet count.
    fn count_packets(path: &Path) -> Result<usize, TestError> {
        let (tx, rx) = packet_channel(TEST_CAP);
        capture_file(path, &CaptureConfig::default(), tx, None)?;
        Ok(rx.try_iter().count())
    }

    /// gzip-compressed captures must read transparently: libpcap cannot open
    /// them (it reports "unknown file format"), but Wireshark decompresses on
    /// the fly, so sipnab matches that behavior. Regression for the
    /// `.pcap.gz`-mislabeled-as-`.pcap` case.
    #[test]
    fn reads_gzip_compressed_pcap() -> Result<(), TestError> {
        use std::io::Write;

        let sample = sample_pcap();
        if !sample.exists() {
            stderr_line!("Skipping: sample not found at {}", sample.display());
            return Ok(());
        }
        let baseline = count_packets(&sample)?;
        assert!(baseline > 0, "sample should contain packets");

        // Produce a gzip-compressed copy with a deliberately plain `.pcap` name.
        let raw = std::fs::read(&sample)?;
        let gz_file = tempfile::Builder::new()
            .prefix("sipnab-test-")
            .suffix(".pcap")
            .tempfile()?;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw)?;
        let compressed = encoder.finish()?;
        std::fs::write(gz_file.path(), &compressed)?;

        let via_gz = count_packets(gz_file.path())?;
        assert_eq!(
            via_gz, baseline,
            "gzip-compressed capture should yield the same packets as the original"
        );
        Ok(())
    }

    /// The closing summary counts files that were READ, not the size of the
    /// set decided before any of them was opened.
    ///
    /// `paths.len()` was the old count, so a run that opened 3 of 27 files
    /// still claimed 27 — which is what made an earlier truncation bug nearly
    /// invisible.
    #[test]
    fn the_summary_reports_files_read_not_files_offered() -> Result<(), TestError> {
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
        Ok(())
    }

    /// The overwhelmingly common case stays one clause, and is not a warning.
    #[test]
    fn the_summary_of_a_clean_single_file_run_stays_one_clause() -> Result<(), TestError> {
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
        Ok(())
    }

    /// A requested stop is not a loss: `--count` leaving files unread is what
    /// the operator asked for, so the summary reports it without crying wolf.
    #[test]
    fn a_count_limit_is_reported_but_not_called_a_loss() -> Result<(), TestError> {
        let tally = ReadTally {
            given: 3,
            stopped_early: 1,
            ..ReadTally::default()
        };
        let line = tally.summary(1);
        assert!(line.contains("0 of 3 file(s) read in full"), "{line}");
        assert!(line.contains("2 not reached"), "{line}");
        assert!(!tally.lossy(), "a limit is not data loss");
        Ok(())
    }

    /// A file of the set that cannot be opened is counted, not absorbed.
    #[test]
    fn a_file_of_the_set_that_cannot_be_opened_is_counted_as_skipped() -> Result<(), TestError> {
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
        .map_err(|e| format!("one unopenable file must not fail the set: {e:?}"))?;

        assert_eq!(tally.complete, 2, "{tally:?}");
        assert_eq!(tally.skipped, 1, "{tally:?}");
        assert_eq!(tally.not_reached(), 0, "{tally:?}");
        assert!(tally.lossy(), "a file that never opened is a loss");
        assert!(count > 0, "the readable files still contributed packets");
        Ok(())
    }

    /// A read reports the span it covered, which is where the end time for the
    /// overlap check comes from — no extra pass over the file.
    #[test]
    fn a_file_read_reports_the_span_it_covered() -> Result<(), TestError> {
        let path = sample_pcap();
        let (mut cap, _guard) = open_offline(&path).map_err(|e| format!("open: {e:?}"))?;
        let (tx, _rx) = packet_channel(TEST_CAP);
        let mut count = 0u64;
        let mut prev_ts = None;
        let read = read_opened_inner(
            &mut cap,
            &path,
            &CaptureConfig::default(),
            &tx,
            ReadTimeline {
                start: std::time::Instant::now(),
                count: &mut count,
                prev_ts: &mut prev_ts,
            },
        )
        .map_err(|e| format!("read: {e:?}"))?;

        assert!(read.reached_eof, "the fixture reads to the end");
        let (first, last) = read.span.ok_or("the fixture holds packets")?;
        assert_eq!(
            first.timestamp(),
            1_480_171_979,
            "the fixture's first packet is a fixed fact about it"
        );
        assert!(
            last > first,
            "the last packet cannot precede the first: {first} .. {last}"
        );
        Ok(())
    }

    /// Overlap is the previous file's END against the next file's START.
    ///
    /// Comparing consecutive STARTS — what the resolver could see without
    /// reading anything — never described the case the warning exists for: two
    /// capture runs, or the same traffic collected on two interfaces, whose
    /// packets are then counted twice.
    #[test]
    fn overlap_is_the_previous_end_against_the_next_start() -> Result<(), TestError> {
        let t = |s: i64| DateTime::from_timestamp(s, 0).ok_or("timestamp");
        let a = Path::new("first.pcap");
        let b = Path::new("second.pcap");

        // second.pcap starts 30 s before first.pcap ends: the two hold the same
        // 30 s of traffic and every count spanning it is inflated.
        let msg = overlap_message(a, t(1_767_225_660)?, b, t(1_767_225_630)?)
            .ok_or("an overlapping handover must be reported")?;
        assert!(
            msg.contains("first.pcap") && msg.contains("second.pcap"),
            "{msg}"
        );
        assert!(
            msg.contains("twice"),
            "the consequence must be stated: {msg}"
        );
        Ok(())
    }

    /// A clean ring-buffer handover is silent: file N+1 starts after file N
    /// ends, which is the normal state of every `tcpdump -C -W` set.
    #[test]
    fn a_clean_handover_is_not_reported_as_overlap() -> Result<(), TestError> {
        let t = |s: i64| DateTime::from_timestamp(s, 0).ok_or("timestamp");
        assert!(
            overlap_message(
                Path::new("a.pcap"),
                t(1_767_225_630)?,
                Path::new("b.pcap"),
                t(1_767_225_660)?,
            )
            .is_none()
        );
        Ok(())
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
    fn a_bpf_filter_that_does_not_compile_fails_on_a_later_file_too() -> Result<(), TestError> {
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
        let err = later.err().ok_or(
            "a filter that does not compile against file 2's link type must fail \
             the run, not silently drop that file's traffic",
        )?;
        assert!(
            format!("{err:#}").contains("BPF filter"),
            "the error must name the filter: {err:#}"
        );
        Ok(())
    }

    /// Reading the UDP fixture yields non-empty packets, each stamped with
    /// the file it was read from.
    #[test]
    fn read_fixture_pcap() -> Result<(), TestError> {
        let path = fixture_path();
        if !path.exists() {
            // Skip if fixture not yet generated
            stderr_line!("Skipping: fixture not found at {}", path.display());
            return Ok(());
        }

        let (tx, rx) = packet_channel(TEST_CAP);
        let config = CaptureConfig::default();
        capture_file(&path, &config, tx, None)?;

        let packets: Vec<Packet> = rx.try_iter().collect();
        assert!(
            !packets.is_empty(),
            "Expected at least one packet from fixture"
        );

        for pkt in &packets {
            assert!(!pkt.data.is_empty());
            assert!(pkt.caplen > 0);
            assert_eq!(
                pkt.interface.as_deref(),
                Some(path.display().to_string().as_str()),
                "a replayed packet names the file it came from"
            );
        }
        Ok(())
    }

    /// A classic pcap of `link_type` holding one record stamped `secs`.
    fn one_record(link_type: u32, secs: u32, frame: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        f.extend_from_slice(&2u16.to_le_bytes());
        f.extend_from_slice(&4u16.to_le_bytes());
        for v in [0u32, 0, 65_535, link_type, secs, 0] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        f.extend_from_slice(frame);
        f
    }

    fn gzip(data: &[u8]) -> Result<Vec<u8>, TestError> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(data).map_err(|e| format!("gzip: {e:?}"))?;
        Ok(enc.finish().map_err(|e| format!("gzip: {e:?}"))?)
    }

    fn tgz(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, TestError> {
        use crate::capture::archive::tar::testutil::{Spec, build};
        let specs: Vec<Spec<'_>> = entries.iter().map(|(n, d)| Spec::file(n, d)).collect();
        Ok(gzip(&build(&specs))?)
    }

    /// A packet read out of an archive member is stamped with the member's
    /// label — the name its frame pointers resolve through — never with the
    /// temporary file it happened to be read from.
    #[test]
    fn each_archive_member_stamps_its_label_as_the_source() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = root.path().join("two.tgz");
        let frame = [0xabu8; 60];
        std::fs::write(
            &path,
            tgz(&[
                ("a.pcap", &one_record(1, 1_000, &frame)),
                ("b.pcap", &one_record(1, 2_000, &frame)),
            ])?,
        )
        .map_err(|e| format!("write: {e:?}"))?;
        let set = crate::capture::input_set::resolve_set(
            &[path.display().to_string()],
            &crate::capture::input_set::ResolveOptions::default(),
        )
        .map_err(|e| format!("resolve: {e:?}"))?;

        let (tx, rx) = packet_channel(TEST_CAP);
        capture_files(&set.paths(), &CaptureConfig::default(), tx, None)
            .map_err(|e| format!("read: {e:?}"))?;
        let sources: Vec<String> = rx
            .try_iter()
            .map(|p| p.interface.as_deref().unwrap_or_default().to_string())
            .collect();
        let root_name = path.display().to_string();
        assert_eq!(
            sources,
            vec![format!("{root_name}/a.pcap"), format!("{root_name}/b.pcap")]
        );
        Ok(())
    }

    /// `open_offline` opens ONE capture. Handed an archive of several it says
    /// what the file is and how to read it, instead of libpcap's "unknown file
    /// format".
    #[test]
    fn open_offline_names_an_archive_instead_of_failing_obscurely() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = root.path().join("set.tgz");
        let rec = one_record(1, 1_000, &[0u8; 60]);
        std::fs::write(&path, tgz(&[("a.pcap", &rec), ("b.pcap", &rec)])?)
            .map_err(|e| format!("write: {e:?}"))?;
        let err = open_offline(&path)
            .map(|_| ())
            .err()
            .ok_or("an archive is a set")?;
        let msg = format!("{err:#}");
        assert!(
            msg.contains("archive") && msg.contains("2 capture"),
            "{msg}"
        );
        Ok(())
    }

    /// A `.pcap.gz` is inflated under the same ceiling as an archive. It used
    /// to be inflated to disk with no bound at all, so a few kilobytes could
    /// claim the whole temp filesystem.
    #[test]
    fn open_offline_bounds_a_compressed_capture() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let mut big = one_record(1, 1_000, &[0u8; 60]);
        big.resize(4 * 1024 * 1024, 0);
        let path = root.path().join("bomb.pcap.gz");
        std::fs::write(&path, gzip(&big)?).map_err(|e| format!("write: {e:?}"))?;
        let limits = crate::capture::archive::Limits {
            max_inflated_bytes: 1024 * 1024,
            ..crate::capture::archive::Limits::for_run()
        };
        let err = open_offline_with(&path, &limits)
            .map(|_| ())
            .err()
            .ok_or("over the ceiling")?;
        assert!(format!("{err:#}").contains("ceiling"), "{err:#}");

        let small = root.path().join("ok.pcap.gz");
        std::fs::write(&small, gzip(&one_record(1, 1_000, &[0u8; 60]))?)
            .map_err(|e| format!("write: {e:?}"))?;
        let (mut cap, _guard) =
            open_offline_with(&small, &limits).map_err(|e| format!("within the ceiling: {e:?}"))?;
        assert!(cap.next_packet().is_ok());
        Ok(())
    }

    /// Replaying a set reproduces the gap BETWEEN its files, not only within
    /// them: the timeline (`ReadTimeline::prev_ts`) is shared, so the second
    /// file's first packet waits for the time that separated it from the
    /// first file's last.
    #[test]
    fn replaying_a_set_reproduces_the_gap_between_its_files() -> Result<(), TestError> {
        // One Ethernet record per file, 300 ms apart.
        fn record_at(secs: u32, usecs: u32) -> Vec<u8> {
            let frame = [0u8; 60];
            let mut f = Vec::new();
            f.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
            f.extend_from_slice(&2u16.to_le_bytes());
            f.extend_from_slice(&4u16.to_le_bytes());
            for v in [0u32, 0, 65_535, 1, secs, usecs] {
                f.extend_from_slice(&v.to_le_bytes());
            }
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            f.extend_from_slice(&frame);
            f
        }
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let first = root.path().join("a.pcap");
        let second = root.path().join("b.pcap");
        std::fs::write(&first, record_at(1_000, 0)).map_err(|e| format!("write: {e:?}"))?;
        std::fs::write(&second, record_at(1_000, 300_000)).map_err(|e| format!("write: {e:?}"))?;
        let config = CaptureConfig {
            replay: true,
            ..CaptureConfig::default()
        };
        let mut tally = ReadTally {
            given: 2,
            ..ReadTally::default()
        };
        let mut count = 0u64;
        let (tx, _rx) = packet_channel(TEST_CAP);
        let started = std::time::Instant::now();
        read_set(&[first, second], &config, &tx, None, &mut tally, &mut count)
            .map_err(|e| format!("both files read: {e:?}"))?;
        let took = started.elapsed();
        assert_eq!(count, 2);
        assert!(
            took >= std::time::Duration::from_millis(250),
            "the 300 ms gap between the files was not replayed: took {took:?}"
        );
        Ok(())
    }

    /// A member whose link type sipnab cannot decode is skipped when the BPF
    /// filter will not compile against it — nothing decodable is lost by
    /// that — instead of ending the whole set, as a filter failure on a
    /// decodable member still does.
    #[test]
    fn an_undecodable_link_type_is_skipped_not_fatal_under_a_filter() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        // DLT 149 (USER2): what an LTE/NR MAC capture from a test handset uses,
        // which libpcap cannot compile a filter against.
        let mac = root.path().join("mac.pcap");
        std::fs::write(&mac, one_record(149, 1_000, &[0x42u8; 40]))
            .map_err(|e| format!("write: {e:?}"))?;
        let eth = sample_pcap();
        let config = CaptureConfig {
            bpf_filter: Some("udp".to_string()),
            ..CaptureConfig::default()
        };
        let mut tally = ReadTally {
            given: 2,
            ..ReadTally::default()
        };
        let mut count = 0u64;
        let (tx, _rx) = packet_channel(TEST_CAP);
        read_set(&[eth, mac], &config, &tx, None, &mut tally, &mut count)
            .map_err(|e| format!("an undecodable member must not end the set: {e:?}"))?;
        assert_eq!(tally.complete, 1, "{tally:?}");
        assert_eq!(tally.skipped, 1, "{tally:?}");
        assert!(!tally.lost, "nothing sipnab could decode was skipped");
        assert!(count > 0);
        Ok(())
    }

    /// When the file that sorts FIRST is the one skipped, readiness passes to
    /// the next file. It used to be owned by the first file alone, so skipping
    /// it left the consumer waiting for a signal that never came and the run
    /// died with "exited before signaling ready".
    #[test]
    fn readiness_passes_on_when_the_first_file_is_skipped() -> Result<(), TestError> {
        let root = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let mac = root.path().join("mac.pcap");
        std::fs::write(&mac, one_record(149, 1_000, &[0x42u8; 40]))
            .map_err(|e| format!("write: {e:?}"))?;
        let config = CaptureConfig {
            bpf_filter: Some("udp".to_string()),
            ..CaptureConfig::default()
        };
        let (tx, rx) = packet_channel(TEST_CAP);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        capture_files(&[mac, sample_pcap()], &config, tx, Some(ready_tx))
            .map_err(|e| format!("read: {e:?}"))?;
        assert_eq!(
            ready_rx.try_recv(),
            Ok(Ok(())),
            "the second file signals readiness"
        );
        assert!(rx.try_iter().count() > 0);
        Ok(())
    }

    /// Every packet of a two-file set names the file it was actually read
    /// from — not the first file of the set.
    ///
    /// This is the identity the pcapng export binds its Interface Description
    /// Blocks to. While replayed packets carried `interface: None`, the
    /// writer had nothing to tell two same-link-type inputs apart and put
    /// every frame on the first input's interface, so the export stated the
    /// wrong origin for the whole of the second file.
    #[test]
    fn each_file_of_a_set_stamps_its_own_source() -> Result<(), TestError> {
        let a = sample("register-invite-reinvite-bye.pcap");
        let b = sample("sip-rtp-g711.pcap");
        if !a.exists() || !b.exists() {
            stderr_line!("Skipping: samples not found");
            return Ok(());
        }

        let (tx, rx) = packet_channel(4096);
        capture_files(&[a.clone(), b.clone()], &CaptureConfig::default(), tx, None)
            .map_err(|e| format!("read the set: {e:?}"))?;

        let packets: Vec<Packet> = rx.try_iter().collect();
        let from_a = packets
            .iter()
            .filter(|p| p.interface.as_deref() == Some(a.display().to_string().as_str()))
            .count();
        let from_b = packets
            .iter()
            .filter(|p| p.interface.as_deref() == Some(b.display().to_string().as_str()))
            .count();

        assert!(from_a > 0 && from_b > 0, "both files contribute packets");
        assert_eq!(
            from_a + from_b,
            packets.len(),
            "every packet names one of the two files it could have come from"
        );
        Ok(())
    }

    /// A classic Ethernet pcap of `n` one-byte records, all stamped `secs`.
    fn pcap_of(n: usize, secs: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        for v in [0u32, 0, 65535, 1] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for _ in 0..n {
            for v in [secs, 0, 1, 1] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out.push(0xAB);
        }
        out
    }

    /// Read `path` alone with `config`, returning what the read reported and
    /// the packet count it left.
    fn read_alone(
        path: &Path,
        config: &CaptureConfig,
        tx: &PacketTx,
    ) -> Result<(FileRead, u64), TestError> {
        let (mut cap, _guard) = open_offline(path).map_err(|e| format!("open: {e:?}"))?;
        let mut count = 0u64;
        let mut prev_ts = None;
        let read = read_opened_inner(
            &mut cap,
            path,
            config,
            tx,
            ReadTimeline {
                start: std::time::Instant::now(),
                count: &mut count,
                prev_ts: &mut prev_ts,
            },
        )
        .map_err(|e| format!("read: {e:?}"))?;
        Ok((read, count))
    }

    /// A merged pcapng numbers its frames from zero in file order, and
    /// `--count` stops it at the limit.
    #[test]
    fn a_merged_capture_numbers_its_frames_and_stops_at_the_count() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("merged.pcapng");
        crate::capture::merged::testutil::merged_fixture(&path);

        let (tx, rx) = packet_channel(TEST_CAP);
        capture_file(&path, &CaptureConfig::default(), tx, None)
            .map_err(|e| format!("read: {e:?}"))?;
        let ordinals: Vec<Option<u64>> =
            rx.try_iter().map(|p| p.origin.map(|o| o.ordinal)).collect();
        assert_eq!(ordinals, vec![Some(0), Some(1)]);

        let (tx, rx) = packet_channel(TEST_CAP);
        let config = CaptureConfig {
            count: Some(1),
            ..CaptureConfig::default()
        };
        capture_file(&path, &config, tx, None).map_err(|e| format!("read: {e:?}"))?;
        assert_eq!(rx.try_iter().count(), 1, "--count 1 sends one frame");
        Ok(())
    }

    /// The frames of one file are numbered from zero in file order.
    #[test]
    fn a_file_numbers_its_frames_from_zero() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let path = dir.path().join("three.pcap");
        std::fs::write(&path, pcap_of(3, 1_700_000_000)).map_err(|e| format!("write: {e:?}"))?;
        let (tx, rx) = packet_channel(TEST_CAP);
        let (read, count) = read_alone(&path, &CaptureConfig::default(), &tx)?;
        assert!(read.reached_eof);
        assert_eq!(count, 3);
        let ordinals: Vec<Option<u64>> =
            rx.try_iter().map(|p| p.origin.map(|o| o.ordinal)).collect();
        assert_eq!(ordinals, vec![Some(0), Some(1), Some(2)]);
        Ok(())
    }

    /// A first file that will not open fails the set, and readiness carries
    /// its reason: the consumer has not started, so nothing was read.
    #[test]
    fn a_first_file_that_will_not_open_fails_the_set() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let missing = dir.path().join("gone.pcap");
        let (tx, _rx) = packet_channel(TEST_CAP);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let result = capture_files(
            &[missing, sample_pcap()],
            &CaptureConfig::default(),
            tx,
            Some(ready_tx),
        );
        assert!(result.is_err(), "the first file failing fails the set");
        let answer = ready_rx
            .try_recv()
            .map_err(|e| format!("readiness was answered: {e:?}"))?;
        let msg = answer.err().ok_or("readiness says the open failed")?;
        assert!(msg.contains("gone.pcap"), "{msg}");
        Ok(())
    }

    /// A BPF filter that does not compile against the first file answers
    /// readiness with the filter error, so the consumer is told why.
    #[test]
    fn a_filter_failure_on_the_first_file_answers_readiness() -> Result<(), TestError> {
        let config = CaptureConfig {
            bpf_filter: Some("ether host 00:00:00:00:00:01".to_string()),
            ..CaptureConfig::default()
        };
        let (tx, _rx) = packet_channel(TEST_CAP);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);
        let result = capture_files(
            &[non_ethernet_pcap(), sample_pcap()],
            &config,
            tx,
            Some(ready_tx),
        );
        assert!(result.is_err());
        let msg = ready_rx
            .try_recv()
            .map_err(|e| format!("readiness was answered: {e:?}"))?
            .err()
            .ok_or("readiness carries the failure")?;
        assert!(msg.contains("BPF filter"), "{msg}");
        Ok(())
    }

    /// A filter that fails on a later file marks the set as having lost
    /// data: the files after it are never read.
    #[test]
    fn a_filter_failure_on_a_later_file_is_a_loss() -> Result<(), TestError> {
        let config = CaptureConfig {
            bpf_filter: Some("ether host 00:00:00:00:00:01".to_string()),
            ..CaptureConfig::default()
        };
        let (tx, _rx) = packet_channel(TEST_CAP);
        let paths = [sample_pcap(), non_ethernet_pcap()];
        let mut tally = ReadTally {
            given: paths.len(),
            ..ReadTally::default()
        };
        let mut count = 0u64;
        let result = read_set(&paths, &config, &tx, None, &mut tally, &mut count);
        assert!(result.is_err());
        assert!(tally.lossy(), "{tally:?}");
        assert_eq!(tally.skipped, 1, "{tally:?}");
        Ok(())
    }

    /// `--duration` that has already run out stops the read before the first
    /// packet, as a stop and not as the end of the file.
    #[test]
    fn an_exhausted_duration_stops_the_read_before_the_first_packet() -> Result<(), TestError> {
        let config = CaptureConfig {
            duration: Some(std::time::Duration::ZERO),
            ..CaptureConfig::default()
        };
        let (tx, rx) = packet_channel(TEST_CAP);
        let (read, count) = read_alone(&sample_pcap(), &config, &tx)?;
        assert!(!read.reached_eof);
        assert_eq!(count, 0);
        assert_eq!(rx.try_iter().count(), 0);
        Ok(())
    }

    /// Packets a dead receiver refused are not counted as delivered, whether
    /// the batch was refused when full, at the end of the file, or one
    /// packet at a time in replay. A refused full batch stops the read.
    #[test]
    fn packets_a_dead_receiver_refused_are_not_counted() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let few = dir.path().join("few.pcap");
        std::fs::write(&few, pcap_of(3, 1_700_000_000)).map_err(|e| format!("write: {e:?}"))?;
        let many = dir.path().join("many.pcap");
        let batch = super::super::channel::FILE_BATCH;
        std::fs::write(&many, pcap_of(batch + 1, 1_700_000_000))
            .map_err(|e| format!("write: {e:?}"))?;

        let dead = || {
            let (tx, rx) = packet_channel(TEST_CAP);
            drop(rx);
            tx
        };
        let plain = CaptureConfig::default();
        let replay = CaptureConfig {
            replay: true,
            ..CaptureConfig::default()
        };

        let (read, count) = read_alone(&few, &plain, &dead())?;
        assert_eq!(count, 0, "the final partial batch was refused");
        assert!(read.reached_eof, "the refusal came at the end of the file");

        let (read, count) = read_alone(&many, &plain, &dead())?;
        assert_eq!(count, 0, "the first full batch was refused");
        assert!(!read.reached_eof, "a refused batch stops the read");

        let (read, count) = read_alone(&few, &replay, &dead())?;
        assert_eq!(count, 0, "the first replayed packet was refused");
        assert!(!read.reached_eof, "a refused packet stops the read");
        Ok(())
    }

    /// Only the plain read of a regular file batches its sends: replay must
    /// deliver each packet when its time comes, and a path that is not a
    /// regular file may trickle.
    #[test]
    fn only_the_plain_read_of_a_regular_file_batches() -> Result<(), TestError> {
        let regular = sample_pcap();
        assert!(batches_sends(&regular, false));
        assert!(!batches_sends(&regular, true), "replay");
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        assert!(!batches_sends(dir.path(), false), "not a regular file");
        assert!(
            !batches_sends(&dir.path().join("missing"), false),
            "nothing there"
        );
        Ok(())
    }
}
