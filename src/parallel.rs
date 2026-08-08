// SPDX-License-Identifier: MIT OR Apache-2.0

//! Multi-core offline processing (`--cores N`).
//!
//! sipnab's hot path is per-packet and was effectively single-threaded, so on a
//! many-core host it left most cores idle. RTP is ~93% of carrier traffic and is
//! independent per stream, so the work parallelizes well — *if* a flow's packets
//! always land on the same worker. This module provides the sharding function
//! and (with `crate::rtp::stream_store` / `crate::sip::dialog_store` merge)
//! the building blocks of a sharded worker pool: one reader → N workers, each
//! owning thread-local stores, merged at the end.
//!
//! Sharding is by the **direction-independent host pair**, so both directions of
//! a flow — and a call's RTP both ways — route to one worker. That is what
//! RTP/RTCP need, because they carry no Call-ID, only a 5-tuple: a stream that
//! split across workers could not be reassembled at all.
//!
//! **A call's SIP does NOT stay on one worker, and nothing here assumes it
//! does.** Signalling that traverses a proxy or SBC is captured on two host
//! pairs — access side and trunk side — and shards to two workers, which
//! reconstruct two fragments of one Call-ID. That is the common case on carrier
//! traffic, not an exotic one: in one 100 MB file of the reference corpus 1173
//! of 2311 dialogs were proxied. `crate::sip::dialog_store::DialogStore::merge`
//! is what makes them whole again — it concatenates the fragments' message
//! lists in capture-timestamp order and re-runs the state machine over the
//! result, so the merged dialog is the one the single-threaded path would have
//! built. (An earlier version of this doc claimed a call's SIP "stays together",
//! and `merge` was written to that premise: it kept whichever fragment held more
//! messages and dropped the other. Roughly half of every proxied call's
//! signalling vanished, invisibly, because the dialog COUNT was unaffected.)
//!
//! Dialog↔stream association crosses workers for the same reason — plus the
//! carrier case where SDP advertises a separate media IP, so the SDP lands on a
//! different worker than the RTP — and is likewise resolved globally at merge
//! (`crate::rtp::stream_store::StreamStore::reassociate_all`).
//!
//! # The sweep runs once, after the merge
//!
//! The single-threaded receive loop sweeps every five seconds of capture time:
//! it flags RTP streams that no dialog claims as orphaned, and compacts dialogs
//! that have gone idle. This module used to do neither, so the same bytes gave
//! two answers. On one reference-corpus set `--cores 4` reported no orphaned
//! streams at all where the single-threaded path reported 80, and the report's
//! "Orphaned Streams:" header was absent entirely — those streams appeared in
//! the ordinary RTP section instead, reading as though they belonged to a call.
//!
//! `final_sweep` closes that, and runs exactly ONCE, after the merge, at the
//! capture's final timestamp. Not per worker: a call's SIP does not stay on one
//! worker (see above), and a worker only sees the packets of its own host
//! pairs, so its local last timestamp can be minutes behind the capture's. A
//! per-worker sweep would measure each fragment against its own clock and
//! produce a THIRD answer, matching neither path — worse than the divergence it
//! replaced, because it would look right.
//!
//! The "now" comes from `crate::app::batch::SweepClock`, the same capture clock
//! the single-threaded loop uses, so the result is a function of the bytes
//! rather than of how fast the machine read them.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// Worker index in `0..jobs` for a packet identified by its two endpoint IPs.
///
/// Direction-independent: `shard_for(a, b, n) == shard_for(b, a, n)`, so a
/// bidirectional flow never splits across workers. `jobs <= 1` always returns 0
/// (the single-threaded path).
pub fn shard_for(src: IpAddr, dst: IpAddr, jobs: usize) -> usize {
    if jobs <= 1 {
        return 0;
    }
    let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
    let mut h = DefaultHasher::new();
    a.hash(&mut h);
    b.hash(&mut h);
    (h.finish() % jobs as u64) as usize
}

use std::thread;

use crate::app::batch::{ORPHAN_AFTER, SweepClock};
use crate::capture::PacketProcessor;
use crate::capture::channel::PacketRx;
use crate::capture::parse::ParsedPacket;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// Sweep the MERGED stores once, at the capture's final timestamp.
///
/// The two calls answer different questions and both are needed. `mark_orphaned`
/// is analysis: it classifies streams no dialog ever claimed, which is what puts
/// them under the report's "Orphaned Streams:" heading instead of among the
/// media of real calls. `compact_idle` is the memory bound: it evicts messages
/// from dialogs that have gone quiet, keeping the ones that say what the dialog
/// did. Running only the first leaves the parallel path retaining every message
/// the capture held; running only the second leaves every orphan unflagged.
///
/// Call this AFTER
/// [`reassociate_all`](crate::rtp::stream_store::StreamStore::reassociate_all).
/// Orphan status is sticky, and cross-worker association is not resolved until
/// that pass runs — sweeping first would permanently flag streams whose SDP
/// merely landed on another worker.
///
/// # Arguments
///
/// * `clock` — the run's capture clock, fed every packet the reader saw.
/// * `ds` / `ss` — the merged stores, swept in place.
///
/// # Side effects
///
/// Flags streams on `ss`, drops messages from idle dialogs on `ds` (counted
/// into its lifetime retention totals, which the batch summary reports), and
/// logs a `debug!` line naming what compaction shed. Does nothing at all when
/// the run read no packets, because then there is no capture time to measure
/// against and nothing in the stores to sweep.
fn final_sweep(clock: &SweepClock, ds: &mut DialogStore, ss: &mut StreamStore) {
    let Some(now) = clock.final_now() else {
        return;
    };
    ss.mark_orphaned(now.get(), ORPHAN_AFTER);
    let compacted = ds.compact_idle(now.get());
    if compacted.messages_evicted > 0 {
        tracing::debug!(
            "idle-dialog compaction: dropped {} messages from {} dialogs",
            compacted.messages_evicted,
            compacted.dialogs_compacted
        );
    }
}

/// Configuration for the offline parallel reconstruction engine.
#[derive(Clone)]
pub struct ParallelConfig {
    /// Number of worker cores/threads (the reader + dispatcher are additional).
    pub cores: usize,
    /// Per-worker stream-store capacity (`--max-streams`).
    pub max_streams: usize,
    /// Per-worker dialog-store capacity (`--limit`).
    pub max_dialogs: usize,
    /// Evict the oldest dialog/stream at capacity (`--rotate`).
    pub rotate: bool,
    /// Max concurrent TCP/TLS reassembly sessions in the dispatcher.
    pub max_reassembly: usize,
    /// SIP port range (matches the single-threaded path's `--portrange`).
    pub portrange: (u16, u16),
    /// Skip dialog reconstruction (`--no-dialog`).
    pub no_dialog: bool,
    /// How messages are grouped (`--dialog-track`). Carried through the config
    /// because each worker builds its own store; without it the parallel path
    /// would silently ignore the flag the single-core path honours.
    pub dialog_tracking: crate::sip::dialog_store::DialogTracking,
    /// Skip RTP/RTCP processing (`--no-rtp`).
    pub no_rtp: bool,
    /// Suppress the bad-parse diagnostic (`--quiet-bad-parse`, sipgrep `-x`).
    pub quiet_bad_parse: bool,
    /// Correlation header names for B2BUA leg matching (sngrep `sip.xcid`).
    /// Empty falls back to the `DialogStore` default (`["X-Call-ID"]`).
    pub xcid_headers: Vec<String>,
    /// Reassemble IP fragments / TCP segments (`--no-reassembly` sets false).
    pub reassembly: bool,
    /// Cap on parsed bytes per packet (`-S`/`--limitlen`).
    pub parse_limit: Option<usize>,
}

/// Merged reconstruction output of all workers.
pub struct ReconResult {
    /// Merged dialogs from every worker.
    pub dialog_store: DialogStore,
    /// Merged + globally reassociated RTP streams.
    pub stream_store: StreamStore,
    /// Total SIP messages reconstructed.
    pub sip_count: u64,
    /// Total RTP packets processed.
    pub rtp_count: u64,
    /// Total parsed packets dispatched.
    pub total_count: u64,
    /// Raw packets lost because a worker thread died mid-run (its receiver was
    /// gone, so the shard send failed). Zero on a healthy run; nonzero means
    /// the reconstruction is incomplete and was logged at `warn`.
    pub dropped_count: u64,
    /// Worker threads this run actually used — `cores.max(2)`, which is not
    /// necessarily the `--cores` the operator typed.
    ///
    /// Carried because it is the denominator of every load-balance question,
    /// including the one [`Self::unshardable_count`] answers: "all on worker 0"
    /// is a catastrophe across sixteen workers and a tautology across one.
    pub workers: usize,
    /// RAW packets the reader made a shard decision about.
    ///
    /// Deliberately NOT [`Self::total_count`], which counts what the workers
    /// PARSED: reassembly turns several raw frames into one parsed packet, and
    /// a frame no decoder understands is counted here and nowhere else. A
    /// capture of nothing but ARP has thousands of `packets_read` and a
    /// `total_count` of zero, so using the latter as the fallback denominator
    /// would report "4000 of 0".
    pub packets_read: u64,
    /// Of those, the ones [`crate::capture::parse::peek_host_pair`] could read
    /// no host pair from, which therefore fell back to worker 0 instead of
    /// being sharded across the pool.
    ///
    /// The fallback is *correct* — worker 0 owns its own reassembly, so nothing
    /// is lost — but it is not free, and it used to be invisible. A capture
    /// whose encapsulation the peek cannot follow (a legacy QinQ tag, a MACsec
    /// link, a VLAN inside a Linux cooked capture — i.e. `-i any`, the default
    /// invocation on Linux) sends EVERY packet to worker 0 and reports exactly
    /// the throughput story of a capture that sharded perfectly. The operator
    /// sees a slow run and no reason for it. See [`shard_fallback_summary`].
    pub unshardable_count: u64,
}

/// Share of a run's packets that must land on the fallback worker before the
/// notice stops being informational and starts saying the run was not parallel.
///
/// Half, the same threshold and the same reasoning as `BLIND_RUN_SHARE` in
/// [`crate::app::batch`]. Below it, a fallback is ordinary background — ARP,
/// LLDP, a stray non-IP frame — and the other workers still carry the traffic
/// that matters. At or above it, the majority of the capture ran on one
/// worker, and the run's throughput is a statement about worker 0 rather than
/// about `--cores`.
const FALLBACK_PILEUP_SHARE: f64 = 50.0;

/// What the shard fallback cost this run, as the line a summary prints — or
/// `None` when there is nothing to say.
///
/// The sibling of `app::batch`'s `undecodable_summary` and
/// `pipeline::portrange_skip_report`, and the answer to the same shape of
/// question in the load-balancing dimension: `--cores 16` on a capture the peek
/// cannot read produces one busy worker, fifteen idle ones, and a summary
/// identical to a perfectly sharded run.
///
/// A pure function rather than an inline `if`, for the reason
/// `undecodable_summary` is one: the whole value is in WHICH sentence it
/// chooses and which numbers it names, and a test asserting that "something was
/// logged" would pass on a notice naming the wrong count or the wrong tier.
///
/// # Arguments
///
/// * `unshardable` — packets the peek could read no host pair from.
/// * `packets_read` — raw packets the reader sharded, the denominator for the
///   share. A zero here suppresses the share rather than dividing by it.
/// * `workers` — worker threads that actually ran.
///
/// # Returns
///
/// The notice, or `None` when every packet sharded — a clean run stays quiet,
/// the same rule `retention_summary` follows — **or** when `workers <= 1`.
/// That second gate is the contract for callers on the single-threaded path:
/// [`shard_for`] sends everything to worker 0 when `jobs <= 1`, so there the
/// count is a tautology and printing it is noise.
pub fn shard_fallback_summary(
    unshardable: u64,
    packets_read: u64,
    workers: usize,
) -> Option<String> {
    if workers <= 1 || unshardable == 0 {
        return None;
    }

    let mut msg = format!("NOT SHARDED: {unshardable} of {packets_read} packet(s)");
    // Guarding the divide rather than assuming: the two counters are
    // incremented at different places, and a share of infinity printed beside a
    // real count would discredit both.
    let share = if packets_read > 0 {
        let pct = unshardable as f64 * 100.0 / packets_read as f64;
        msg.push_str(&format!(" ({pct:.1}%)"));
        pct
    } else {
        0.0
    };
    msg.push_str(&format!(
        " carried no host pair the shard peek could read, so they were dispatched to \
         worker 0 instead of being spread across the {workers} workers."
    ));

    // Two tiers, because "most of it" and "all of it" are different findings and
    // the second is the one this notice exists for: at 100% the pool did no
    // balancing whatsoever and every core past the first was bought and idled.
    if packets_read > 0 && unshardable >= packets_read {
        msg.push_str(&format!(
            " --cores BOUGHT NOTHING ON THIS CAPTURE — every packet ran on worker 0 while \
             the other {} worker(s) idled, so this run was single-threaded whatever \
             --cores said. The peek cannot follow this capture's encapsulation; report \
             its link type.",
            workers - 1
        ));
    } else if share >= FALLBACK_PILEUP_SHARE {
        msg.push_str(&format!(
            " MOST OF THIS RUN WAS SINGLE-THREADED — the majority of the capture ran on \
             worker 0, so --cores bought far less than the {workers} workers suggest. The \
             peek cannot follow part of this capture's encapsulation; report its link type."
        ));
    }
    Some(msg)
}

impl ReconResult {
    /// This run's shard-fallback notice, or `None` when there is nothing to
    /// say.
    ///
    /// The one place that binds the run's counters to
    /// [`shard_fallback_summary`], so the sentence an operator reads and the
    /// numbers a caller can assert on cannot drift apart. `run_offline_parallel`
    /// and `run_offline_parallel_file` both log exactly this.
    pub fn shard_fallback_notice(&self) -> Option<String> {
        shard_fallback_summary(self.unshardable_count, self.packets_read, self.workers)
    }
}

/// Send one shard item to worker `s`'s channel, returning the number of raw
/// packets LOST if the worker's receiver is gone (its thread died) — `0` on a
/// live worker, else `weight` (1 for a single packet, the batch length for a
/// batch). The bounded channel only errors on disconnect (it blocks, never
/// errors, when merely full), so a nonzero return is unambiguously a dead
/// worker. Callers fold the result into a run-total that is logged and
/// surfaced on [`ReconResult::dropped_count`], instead of the old `let _ =`
/// that swallowed the loss silently.
fn shard_send<T>(tx: &crossbeam_channel::Sender<T>, item: T, weight: u64) -> u64 {
    match tx.send(item) {
        Ok(()) => 0,
        Err(_) => weight,
    }
}

/// Reconstruct ONE already-parsed packet into thread-local stores, using the
/// same `crate::pipeline::classify_packet` core as every other router — so
/// `--cores N` classifies identically to `--cores 1` (WebSocket-SIP unwrap and
/// heuristic RTP discovery included). Only the flag-gated batch extras (SRTP
/// decrypt, DTMF, quality events, security detectors, per-message output) stay
/// on the single-threaded path; none of them change dialog/stream
/// reconstruction. Heuristic state lives per worker, which is sound because
/// sharding pins each flow's packets to one worker.
fn reconstruct(
    pp: &ParsedPacket,
    ds: &mut DialogStore,
    ss: &mut StreamStore,
    heuristic: &mut crate::rtp::heuristic::RtpHeuristic,
    cfg: &ParallelConfig,
    sip: &mut u64,
    rtp: &mut u64,
) {
    use crate::pipeline::{MediaDecrypt, PacketAction, PipelineOptions, classify_packet};
    let opts = PipelineOptions {
        no_dialog: cfg.no_dialog,
        no_rtp: cfg.no_rtp,
        sip_portrange: Some(cfg.portrange),
        quiet_bad_parse: cfg.quiet_bad_parse,
    };
    let mut decrypt = MediaDecrypt::default();
    match classify_packet(pp, heuristic, &opts, &mut decrypt) {
        PacketAction::None => {}
        PacketAction::Sip { msg, sdp_links } => {
            *sip += 1;
            if !cfg.no_dialog {
                // The store takes the message by move — cloning a SipMessage
                // deep-copies every header String.
                ds.process_message(msg);
                for (ip, port, call_id, media) in &sdp_links {
                    ss.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
        }
        PacketAction::Rtcp(pkts) => {
            ss.process_rtcp(&pkts);
        }
        PacketAction::Rtp { hdr, .. } => {
            // No SRTP context in the sharded path, so there is never a
            // decrypted payload to substitute.
            ss.process_rtp(pp, &hdr, pp.timestamp);
            *rtp += 1;
        }
    }
}

/// Offline multi-core reconstruction. A single dispatcher reads `rx` and, using a
/// cheap host-pair peek (`crate::capture::parse::peek_host_pair` — link+IP
/// headers only, no full parse), shards each RAW packet to one of `cfg.cores`
/// worker threads. Each worker owns its own `PacketProcessor` (so reassembly
/// stays per-flow correct — a flow's packets share a host pair and route to one
/// worker) plus thread-local stores, and does the heavy work: the L2/L3/L4 parse,
/// the SIP parse, RTP/RTCP classify, and all store updates — all in parallel. The
/// dispatcher's per-packet cost is just the peek + a channel send, so the serial
/// fraction is tiny and throughput scales with cores. At EOF the stores merge and
/// stream↔dialog association is resolved globally.
///
/// Returns the merged stores for report generation. Reconstruction only — see
/// Fill in the frame digest the reader deliberately left empty.
///
/// The reader stamps the ordinal — a serial fact only it can know — and leaves
/// `digest: None`, because hashing is a pure function of bytes and the reader
/// is the stage every worker waits on. This runs in the workers, where the
/// cores are idle, and produces the identical FNV-1a value the single-threaded
/// reader produces, so a pointer from a `--cores` run resolves the same way.
///
/// Idempotent, and it never invents provenance: a packet that arrived with no
/// origin at all (live capture, HEP) is left alone rather than given one, and a
/// digest already present is not recomputed.
fn stamp_digest(packet: &mut crate::capture::packet::Packet) {
    if let Some(origin) = packet.origin.as_mut()
        && origin.digest.is_none()
    {
        origin.digest = Some(crate::capture::packet::frame_digest(&packet.data));
    }
}

/// `reconstruct`; advanced features stay on the single-threaded path.
pub fn run_offline_parallel(rx: PacketRx, cfg: ParallelConfig) -> ReconResult {
    use crate::capture::packet::Packet;
    use crossbeam_channel::bounded;
    let n = cfg.cores.max(2);

    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| bounded::<Packet>(8192)).unzip();
    let workers: Vec<_> = rxs
        .into_iter()
        .map(|wrx| {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let mut processor = PacketProcessor::with_max_sessions(cfg.max_reassembly)
                    .with_reassembly(cfg.reassembly)
                    .with_parse_limit(cfg.parse_limit);
                let mut ds = {
                    let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
                    ds.set_tracking(cfg.dialog_tracking);
                    ds
                }
                .with_xcid_headers(cfg.xcid_headers.clone());
                let mut ss = StreamStore::new(cfg.max_streams);
                ss.set_audio_capture(false); // batch mode never reads audio buffers
                let mut heuristic = crate::rtp::heuristic::RtpHeuristic::new();
                let (mut sip, mut rtp, mut total) = (0u64, 0u64, 0u64);
                for mut packet in wrx.iter() {
                    // Off the reader's serial path, onto this idle core.
                    stamp_digest(&mut packet);
                    for pp in processor.process(&packet) {
                        total += 1;
                        reconstruct(
                            &pp,
                            &mut ds,
                            &mut ss,
                            &mut heuristic,
                            &cfg,
                            &mut sip,
                            &mut rtp,
                        );
                    }
                }
                (ds, ss, sip, rtp, total)
            })
        })
        .collect();

    // Dispatcher: cheap host-pair peek, shard the RAW packet to a worker. A packet
    // the peek can't read routes to worker 0 (still correct via its own reassembly).
    // The dispatcher is also the only place that sees EVERY packet's timestamp, so
    // it is where the capture clock for the post-merge sweep is kept.
    let mut dropped: u64 = 0;
    let mut packets_read: u64 = 0;
    let mut unshardable: u64 = 0;
    let mut clock = SweepClock::new(true);
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(packet) => {
                clock.observe(packet.timestamp);
                packets_read += 1;
                let s = match crate::capture::parse::peek_host_pair(&packet) {
                    Some((a, b)) => shard_for(a, b, n),
                    // Counted, not merely tolerated. Two plain `u64` increments
                    // on the dispatcher's serial path: no atomic, no lock, no
                    // allocation, and the branch was already here.
                    None => {
                        unshardable += 1;
                        0
                    }
                };
                dropped += shard_send(&txs[s], packet, 1);
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
        }
    }
    drop(txs); // signal workers to finish
    if dropped > 0 {
        tracing::warn!(
            "parallel reconstruction lost {dropped} packet(s): a worker thread \
             died mid-run (its shard channel closed); results are incomplete"
        );
    }

    // Merge thread-local stores into one, then resolve cross-worker associations.
    let mut ds = {
        let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
        ds.set_tracking(cfg.dialog_tracking);
        ds
    }
    .with_xcid_headers(cfg.xcid_headers.clone());
    let mut ss = StreamStore::new(cfg.max_streams);
    let (mut sip_count, mut rtp_count, mut total) = (0u64, 0u64, 0u64);
    for w in workers {
        if let Ok((wds, wss, wsip, wrtp, wtot)) = w.join() {
            ds.merge(wds);
            ss.merge(wss);
            sip_count += wsip;
            rtp_count += wrtp;
            total += wtot;
        }
    }
    ss.reassociate_all();
    final_sweep(&clock, &mut ds, &mut ss);

    let result = ReconResult {
        dialog_store: ds,
        stream_store: ss,
        sip_count,
        rtp_count,
        total_count: total,
        dropped_count: dropped,
        workers: n,
        packets_read,
        unshardable_count: unshardable,
    };
    report_shard_fallback(&result);
    result
}

/// Log this run's shard-fallback notice, when there is one.
///
/// Called from both entry points rather than written inline, for the reason
/// `app::batch`'s `report_undecodable` is: a notice that exists on one path and
/// not the other makes `--cores` over a file and `--cores` over a device
/// disagree about the same capture. `warn` rather than `debug`, and beside the
/// dropped-packet warning it sits next to, because the default batch log level
/// is `info` — a `debug!` line here would be the same silence in a new shape.
///
/// # Side effects
///
/// Emits one `warn!` line when packets fell back to worker 0 on a run with more
/// than one worker. Silent otherwise.
fn report_shard_fallback(result: &ReconResult) {
    if let Some(msg) = result.shard_fallback_notice() {
        tracing::warn!("{msg}");
    }
}

/// The reader hands packets to workers in BATCHES rather than one at a time.
/// Focused --cores research (SNB-0015 follow-up) showed the regression past
/// cores 2 is NOT the reconstruction work — even with idle workers throughput
/// halved from cores 2→4. The cost is the per-packet channel hop: every send
/// bounces a cache line across cores, and that coherency traffic scales with
/// worker count. Sending ~`BATCH` packets per channel op amortizes that hop by
/// ~BATCH×, so the single reader can feed more workers before saturating.
/// Channel depth is in batches; BATCH × depth keeps the in-flight packet cap
/// (~8192) identical to the old per-packet bound.
const BATCH: usize = 128;

/// Reader state that spans the WHOLE `-I` set rather than one member of it.
///
/// Bundled because all three are shared for the same reason: `--count 100`
/// over four files means a hundred packets in total, a worker that dies is
/// counted once for the run, and the sweep's "now" is the last timestamp of
/// the set — not of whichever file happened to be read last.
struct ReadProgress {
    /// Packets read so far, measured against the `--count` budget.
    count: u64,
    /// Raw packets lost because a worker's shard channel had closed.
    dropped: u64,
    /// Packets whose host pair the cheap peek could not read, which therefore
    /// fell back to worker 0. Shared across the set for the same reason
    /// [`Self::dropped`] is: the operator ran one analysis, not four, and a
    /// per-file share would understate a set whose encapsulation is uniform.
    unshardable: u64,
    /// Capture clock, fed every packet, read once by [`final_sweep`].
    clock: SweepClock,
}

/// Read every packet of an already-opened capture into the per-worker batches,
/// flushing a batch to its worker whenever it fills.
///
/// Split out of [`run_offline_parallel_file`] so a multi-file set shares ONE set
/// of partial batches, one packet budget and one loss counter across its
/// members — the direct analogue of `read_opened_inner` in
/// [`crate::capture::file`] on the single-threaded path. Partial batches
/// deliberately survive the file boundary: flushing them per file would be pure
/// channel overhead, and the workers' stores live for the whole run either way.
///
/// Returns `Ok(false)` when the whole SET should stop (the `--count` budget is
/// spent) rather than merely this file ending.
fn shard_opened(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &std::path::Path,
    capture_config: &crate::capture::CaptureConfig,
    txs: &[crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
    batches: &mut [Vec<crate::capture::packet::Packet>],
    progress: &mut ReadProgress,
) -> anyhow::Result<bool> {
    use crate::capture::file::pcap_ts_to_chrono;
    use crate::capture::packet::Packet;

    let n = txs.len();
    let link_type = cap.get_datalink().0;
    tracing::info!("Reading from '{}'", path.display());
    // Stamp provenance exactly as the single-threaded reader does (see
    // `crate::capture::file`): the file is the source, the ordinal is this
    // frame's 0-based position IN this file, and the digest is over the bytes
    // as read. This function is the one stage that sees every packet of every
    // file in order, so the ordinal it assigns is the same one a resolver
    // counts to — a pointer from a `--cores` run resolves identically to one
    // from a single-threaded run. Without this, every fact a parallel run
    // produced carried no `frame_ref` at all, so `--cores` silently dropped
    // packet provenance from every surface.
    let source: std::sync::Arc<str> = std::sync::Arc::from(path.display().to_string());
    let mut ordinal: u64 = 0;
    loop {
        if let Some(max) = capture_config.count
            && progress.count >= max
        {
            tracing::debug!("Reached packet count limit ({max})");
            return Ok(false);
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let mut packet = Packet::with_source(
                    pcap_ts_to_chrono(pkt.header.ts),
                    pkt.data.to_vec(),
                    pkt.header.caplen as usize,
                    pkt.header.len as usize,
                    Some(std::sync::Arc::clone(&source)),
                    link_type,
                );
                // The ORDINAL is stamped here, before the send, for the reasons
                // in `crate::capture::file`: once the packet is on a worker's
                // channel this thread cannot amend it, and an ordinal inferred
                // from arrival order would be wrong the moment a shard reorders.
                //
                // The DIGEST is deliberately NOT computed here. It is a pure
                // function of bytes this thread has already finished with, so
                // it does not need the serial stage — and this is the one stage
                // the whole `--cores` design is bottlenecked on: one thread
                // reads, copies and host-pair-peeks every packet while N
                // workers wait. Hashing here charged that thread ~240 bytes of
                // dependent multiplies per packet and cost 39% of two-core
                // throughput (2.27M -> 1.39M pkts/s on the 535k benchmark
                // corpus, bisected to this stamp in 0.5.84). `stamp_digest`
                // runs it in the workers instead, where the cores are idle.
                // Same input, same FNV-1a, same value: a pointer emitted by a
                // `--cores` run still resolves identically to one from a
                // single-threaded run.
                packet.origin = Some(crate::capture::packet::FrameOrigin {
                    ordinal,
                    digest: None,
                });
                ordinal += 1;
                // Observed here rather than in the workers: this is the only
                // stage that sees every packet of every file, and the sweep's
                // "now" has to be the SET's last timestamp.
                progress.clock.observe(packet.timestamp);
                let s = match crate::capture::parse::peek_host_pair(&packet) {
                    Some((a, b)) => shard_for(a, b, n),
                    // Counted, not merely tolerated — see the same branch in
                    // `run_offline_parallel`. One `u64` increment on the
                    // reader's serial path: no atomic, no lock, no allocation.
                    None => {
                        progress.unshardable += 1;
                        0
                    }
                };
                batches[s].push(packet);
                if batches[s].len() >= BATCH {
                    let full = std::mem::replace(&mut batches[s], Vec::with_capacity(BATCH));
                    let weight = full.len() as u64;
                    progress.dropped += shard_send(&txs[s], full, weight);
                }
                progress.count += 1;
            }
            Err(pcap::Error::NoMorePackets) => return Ok(true),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Error reading pcap '{}': {e}",
                    path.display()
                ));
            }
        }
    }
}

/// Read every file of the set into the worker batches, tallying what became of
/// each one.
///
/// Split out of [`run_offline_parallel_file`] for the reason
/// `read_set` is split out of [`crate::capture::file::capture_files`] on the
/// single-threaded path: the closing summary is then reported on EVERY path out
/// of the read, including the ones that return an error. A BPF filter that will
/// not compile against the twelfth file still leaves an account of the eleven
/// to give, and an account only printed on the happy path is one the operator
/// learns not to rely on.
///
/// The tally is [`crate::capture::file::ReadTally`] — the single-threaded
/// reader's type, not a parallel copy of it — so both readers state what they
/// read in one sentence with one wording and one severity rule.
///
/// Returns `Ok(())` once the set is exhausted, the `--count` budget is spent, or
/// a file's read stopped and the rest of the set was read on regardless.
///
/// # Errors
///
/// When the FIRST file cannot be opened — that proves the whole set unusable
/// before any packet has been sharded — or when the BPF filter will not compile
/// against ANY file of the set, wherever in it that file sits. The two are
/// different kinds of failure and only the first is position-dependent: an open
/// that fails on a later file means something changed underneath the run, while
/// a filter that will not compile was always going to fail on that file.
///
/// # Side effects
///
/// Opens and reads each file (writing a decompressed temp copy for gzip input),
/// pushes packets into `batches` and flushes full ones to `txs`, advances
/// `progress` and `tally`, and logs per-file progress and per-file failures.
fn shard_set(
    paths: &[std::path::PathBuf],
    capture_config: &crate::capture::CaptureConfig,
    txs: &[crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
    batches: &mut [Vec<crate::capture::packet::Packet>],
    progress: &mut ReadProgress,
    tally: &mut crate::capture::file::ReadTally,
) -> anyhow::Result<()> {
    use crate::capture::file::open_offline;

    for (i, path) in paths.iter().enumerate() {
        let is_first = i == 0;
        let (mut cap, _gz_guard) = match open_offline(path) {
            Ok(opened) => opened,
            // The first file owns the "is this set usable at all" verdict. A
            // later one that vanished mid-run — a rotating capture directory
            // being cleaned up while it is analysed — is logged and skipped:
            // losing one file of a set is bad, losing the other nine is worse.
            Err(e) if is_first => return Err(e),
            Err(e) => {
                tally.skipped += 1;
                tally.lost = true;
                tracing::error!("Skipping '{}': {e:#}", path.display());
                continue;
            }
        };
        if let Some(ref bpf) = capture_config.bpf_filter
            && let Err(e) = cap.filter(bpf, true)
        {
            // Counted as a skip BEFORE the refusal is propagated: a file whose
            // traffic never reached the workers is data missing from the
            // analysis, and the caller reports the tally on every path out — so
            // a run that refuses on file twelve still says it read eleven.
            tally.skipped += 1;
            tally.lost = true;
            // Refused wherever in the set it happens, not only on the first
            // file. The filter text does not change between files, so a failure
            // is a static misconfiguration against that file's link type, not a
            // mid-read race like a member vanishing from a rotating directory:
            // the filter was always going to fail on that file. Reading on
            // dropped the whole traffic of every member sharing that link type
            // — a Linux-cooked or DLT_NULL file among Ethernet ones — behind
            // one log line, and then exited 0 with a report that looked
            // complete, which is the defect class the summary above exists to
            // remove. `crate::capture::file::filter_failure` builds the error
            // so both readers refuse with the same sentence, and so the sentence
            // NAMES the file: the operator's first question about a forty-file
            // set is which of the forty.
            return Err(crate::capture::file::filter_failure(bpf, path, e));
        }
        // A read error stops THIS file, not the set. Truncation is the normal
        // state of a ring buffer — the newest member is still being written when
        // the capture stops, and libpcap reports `truncated dump file` on the
        // trailing partial record. Whatever was read before the break is already
        // in the workers' stores and stays there.
        match shard_opened(&mut cap, path, capture_config, txs, batches, progress) {
            Ok(true) => tally.complete += 1,
            // The `--count` budget ran out inside this file. Requested, so not
            // a loss — but the file was still not read to its end, and the
            // files behind it are "not reached" rather than absent.
            Ok(false) => {
                tally.stopped_early += 1;
                return Ok(());
            }
            Err(e) => {
                tally.stopped_early += 1;
                tally.lost = true;
                tracing::error!(
                    "Stopped reading '{}' early: {e:#}. Continuing with the rest of the set.",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Like `run_offline_parallel`, but reads the capture FILES directly in this
/// thread instead of consuming a `PacketRx` fed by a separate capture reader
/// thread. This fuses pcap-read + host-pair peek + shard into a SINGLE serial
/// stage — eliminating the dispatcher thread and the semaphore-capped capture
/// channel that capped `--cores` scaling at ~2 workers (the read→dispatcher
/// hand-off was two serial stages). Sharding/reassembly/merge are identical to
/// `run_offline_parallel`, so `--cores N` parity with `--cores 1` is preserved.
///
/// # Cross-file dialog stitching
///
/// `paths` is the whole `-I` set — a directory, a glob or repeated `-I` all
/// resolve to one ordered list (see [`crate::capture::input_set`]) — and every
/// file feeds the SAME worker pool, whose thread-local stores live for the
/// entire run. A call whose INVITE lands in `tg.pcap3` and whose BYE lands in
/// `tg.pcap4` therefore reconstructs as one dialog exactly as it does on the
/// single-threaded path ([`crate::capture::file::capture_files`]): sharding is
/// by direction-independent host pair, so both files' halves of a leg route to
/// the same worker, and legs that shard apart (a proxied call) are stitched by
/// `DialogStore::merge` at the end. Reading each file into a fresh pool would
/// report two fragments instead — a call that never ends, and a stray BYE.
///
/// `paths` must already be in read order; the packet budget (`--count`) and the
/// loss counter are shared across the set, so `--count 100` over four files
/// means a hundred packets in total.
///
/// # Errors
///
/// When `paths` is empty, when the FIRST file cannot be opened — opening it is
/// what proves the set usable at all — or when the BPF filter does not compile
/// against any member of the set, first or fortieth. A later file that cannot
/// be opened, or that stops reading mid-way (the normal state of a ring
/// buffer's newest member), is logged and skipped so one bad member cannot hide
/// the rest of the set. This mirrors [`crate::capture::file::capture_files`]
/// exactly; without it `--cores` would abandon a set the single-threaded path
/// reads through, and — until the filter arm was made to refuse — would answer
/// a mixed-link-type set with a confident partial report where `--cores 1`
/// refused.
///
/// The tally is reported before the error is propagated, so a refused run still
/// states how much of the set it managed to read.
pub fn run_offline_parallel_file(
    paths: &[std::path::PathBuf],
    capture_config: &crate::capture::CaptureConfig,
    cfg: ParallelConfig,
) -> anyhow::Result<ReconResult> {
    use crate::capture::packet::Packet;
    use crossbeam_channel::bounded;
    let n = cfg.cores.max(2);

    if paths.is_empty() {
        anyhow::bail!("no capture files to read");
    }

    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| bounded::<Vec<Packet>>(64)).unzip();
    let workers: Vec<_> = rxs
        .into_iter()
        .map(|wrx| {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let mut processor = PacketProcessor::with_max_sessions(cfg.max_reassembly)
                    .with_reassembly(cfg.reassembly)
                    .with_parse_limit(cfg.parse_limit);
                let mut ds = {
                    let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
                    ds.set_tracking(cfg.dialog_tracking);
                    ds
                }
                .with_xcid_headers(cfg.xcid_headers.clone());
                let mut ss = StreamStore::new(cfg.max_streams);
                ss.set_audio_capture(false);
                let mut heuristic = crate::rtp::heuristic::RtpHeuristic::new();
                let (mut sip, mut rtp, mut total) = (0u64, 0u64, 0u64);
                for mut batch in wrx.iter() {
                    for packet in batch.iter_mut() {
                        // Off the reader's serial path, onto this idle core.
                        stamp_digest(packet);
                        for pp in processor.process(packet) {
                            total += 1;
                            reconstruct(
                                &pp,
                                &mut ds,
                                &mut ss,
                                &mut heuristic,
                                &cfg,
                                &mut sip,
                                &mut rtp,
                            );
                        }
                    }
                }
                (ds, ss, sip, rtp, total)
            })
        })
        .collect();

    // Single reader+sharder: open each pcap in turn (gzip-transparent), apply any
    // BPF, and for each packet do the cheap host-pair peek + append to that
    // worker's batch. A batch is flushed (one channel hop for ~BATCH packets)
    // when it fills, and any partial batches are flushed once the whole SET is
    // read. One thread, one copy, one hop per batch.
    let mut progress = ReadProgress {
        count: 0,
        dropped: 0,
        unshardable: 0,
        clock: SweepClock::new(true),
    };
    let mut batches: Vec<Vec<Packet>> = (0..n).map(|_| Vec::with_capacity(BATCH)).collect();
    let mut tally = crate::capture::file::ReadTally {
        given: paths.len(),
        ..crate::capture::file::ReadTally::default()
    };
    let read = shard_set(
        paths,
        capture_config,
        &txs,
        &mut batches,
        &mut progress,
        &mut tally,
    );
    // Reported before the error is propagated, and on every path out, exactly
    // as `capture_files` does it: a filter that fails against file twelve still
    // read eleven, and what reached the workers is what the operator has to be
    // told. This line was absent entirely from the `--cores` path, so the only
    // reader that can be pointed at a 27-file ring buffer and finish in a
    // reasonable time was also the only one that never said how much of it it
    // had actually read.
    tally.report(progress.count);
    read?;
    // Flush every partial batch so no tail packets are lost.
    for (s, b) in batches.into_iter().enumerate() {
        if !b.is_empty() {
            let weight = b.len() as u64;
            progress.dropped += shard_send(&txs[s], b, weight);
        }
    }
    drop(txs);
    let dropped = progress.dropped;
    if dropped > 0 {
        tracing::warn!(
            "parallel reconstruction lost {dropped} packet(s): a worker thread \
             died mid-run (its shard channel closed); results are incomplete"
        );
    }

    let mut ds = {
        let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
        ds.set_tracking(cfg.dialog_tracking);
        ds
    }
    .with_xcid_headers(cfg.xcid_headers.clone());
    let mut ss = StreamStore::new(cfg.max_streams);
    let (mut sip_count, mut rtp_count, mut total) = (0u64, 0u64, 0u64);
    for w in workers {
        if let Ok((wds, wss, wsip, wrtp, wtot)) = w.join() {
            ds.merge(wds);
            ss.merge(wss);
            sip_count += wsip;
            rtp_count += wrtp;
            total += wtot;
        }
    }
    ss.reassociate_all();
    final_sweep(&progress.clock, &mut ds, &mut ss);
    let result = ReconResult {
        dialog_store: ds,
        stream_store: ss,
        sip_count,
        rtp_count,
        total_count: total,
        dropped_count: dropped,
        workers: n,
        packets_read: progress.count,
        unshardable_count: progress.unshardable,
    };
    report_shard_fallback(&result);
    Ok(result)
}

#[cfg(test)]
mod tests {
    //! Sharding-invariant tests and end-to-end offline-reconstruction fixtures
    //! (heuristic RTP, core-count invariance, codec negotiation, dynamic codec).
    use super::*;
    use std::net::Ipv4Addr;

    /// Build an IPv4 `IpAddr` from four octets (test brevity helper).
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// A shard send to a DEAD worker (its receiver dropped) must be COUNTED
    /// as a packet loss, not silently swallowed. A live worker counts zero;
    /// after the receiver is gone every send returns its weight (1 for a
    /// packet, the batch length for a batch).
    #[test]
    fn dead_worker_shard_send_is_counted() {
        use crossbeam_channel::bounded;
        let (tx, rx) = bounded::<u32>(4);
        // Live worker: send succeeds, nothing lost.
        assert_eq!(shard_send(&tx, 1u32, 1), 0, "live worker loses nothing");
        // Simulate the worker thread dying: its receiver is dropped.
        drop(rx);
        // Now the loss must be reported, not hidden behind `let _ =`.
        assert_eq!(shard_send(&tx, 2u32, 1), 1, "one lost packet is counted");
        assert_eq!(
            shard_send(&tx, 3u32, 128),
            128,
            "a lost batch counts every packet in it"
        );
    }

    // ── Shard-fallback observability ──────────────────────────────────
    //
    // `peek_host_pair` returning `None` sends a packet to worker 0. That is
    // correct — worker 0 owns its own reassembly — but on a capture whose
    // encapsulation the peek cannot follow it is EVERY packet, and the run
    // reports the same summary as one that sharded perfectly. These tests pin
    // the count and the sentence that says so.

    /// A run where every packet sharded says nothing at all — a clean run stays
    /// quiet, the same rule the retention and undecodable notices follow.
    #[test]
    fn shard_fallback_summary_is_silent_when_every_packet_sharded() {
        assert_eq!(shard_fallback_summary(0, 4_000_000, 8), None);
        assert_eq!(shard_fallback_summary(0, 0, 2), None);
    }

    /// With one worker (or none) the number is a tautology: `shard_for` sends
    /// everything to worker 0 when `jobs <= 1`, so "all on worker 0" says
    /// nothing about the capture. Printing it on the single-threaded path is
    /// noise, and this is the gate that keeps it off.
    #[test]
    fn shard_fallback_summary_is_silent_on_the_single_threaded_path() {
        assert_eq!(shard_fallback_summary(4_000_000, 4_000_000, 1), None);
        assert_eq!(shard_fallback_summary(4_000_000, 4_000_000, 0), None);
        // …and the very same numbers DO produce a notice once a second worker
        // exists, so the gate above is about the worker count and nothing else.
        assert_ne!(
            shard_fallback_summary(4_000_000, 4_000_000, 2),
            None,
            "two workers must report what one worker suppresses"
        );
    }

    /// A handful of unreadable frames among millions is background — ARP, LLDP,
    /// a stray non-IP frame. The notice names the exact count and share and
    /// stops there: no emphasis, because nothing emphatic happened.
    #[test]
    fn shard_fallback_summary_names_the_exact_count_and_share() {
        assert_eq!(
            shard_fallback_summary(12, 4_000_000, 4).as_deref(),
            Some(
                "NOT SHARDED: 12 of 4000000 packet(s) (0.0%) carried no host pair the \
                 shard peek could read, so they were dispatched to worker 0 instead of \
                 being spread across the 4 workers."
            )
        );
    }

    /// The case this whole notice exists for: nothing sharded, so `--cores 4`
    /// ran one busy worker and three idle ones and reported the throughput
    /// story of a perfectly balanced run.
    #[test]
    fn shard_fallback_summary_is_emphatic_when_nothing_sharded() {
        assert_eq!(
            shard_fallback_summary(4_000_000, 4_000_000, 4).as_deref(),
            Some(
                "NOT SHARDED: 4000000 of 4000000 packet(s) (100.0%) carried no host pair \
                 the shard peek could read, so they were dispatched to worker 0 instead \
                 of being spread across the 4 workers. --cores BOUGHT NOTHING ON THIS \
                 CAPTURE — every packet ran on worker 0 while the other 3 worker(s) \
                 idled, so this run was single-threaded whatever --cores said. The peek \
                 cannot follow this capture's encapsulation; report its link type."
            )
        );
    }

    /// A majority on the fallback worker is its own finding: the run was mostly
    /// single-threaded, which is not the same claim as "entirely".
    #[test]
    fn shard_fallback_summary_flags_a_mostly_single_threaded_run() {
        assert_eq!(
            shard_fallback_summary(3, 4, 2).as_deref(),
            Some(
                "NOT SHARDED: 3 of 4 packet(s) (75.0%) carried no host pair the shard \
                 peek could read, so they were dispatched to worker 0 instead of being \
                 spread across the 2 workers. MOST OF THIS RUN WAS SINGLE-THREADED — the \
                 majority of the capture ran on worker 0, so --cores bought far less than \
                 the 2 workers suggest. The peek cannot follow part of this capture's \
                 encapsulation; report its link type."
            )
        );
    }

    /// The emphasis threshold is exactly half, and the two tiers do not bleed
    /// into each other: 49% is quiet, 50% is "mostly", 100% is "bought
    /// nothing" and never "mostly".
    #[test]
    fn shard_fallback_emphasis_thresholds_are_exact() {
        let mostly = "MOST OF THIS RUN WAS SINGLE-THREADED";
        let nothing = "--cores BOUGHT NOTHING ON THIS CAPTURE";

        let just_under = shard_fallback_summary(49, 100, 8).expect("49 fell back");
        assert!(!just_under.contains(mostly), "49% is not a majority");
        assert!(!just_under.contains(nothing), "49% is not all of it");

        let at_half = shard_fallback_summary(50, 100, 8).expect("50 fell back");
        assert!(at_half.contains(mostly), "50% is exactly the threshold");
        assert!(!at_half.contains(nothing), "50% is not all of it");

        let all = shard_fallback_summary(100, 100, 8).expect("100 fell back");
        assert!(all.contains(nothing), "100% is all of it");
        assert!(
            !all.contains(mostly),
            "the total case must not also claim the majority case"
        );
    }

    /// A zero denominator suppresses the share instead of dividing by it: a
    /// percentage of infinity printed beside a real count would discredit both.
    #[test]
    fn shard_fallback_summary_guards_the_zero_denominator() {
        assert_eq!(
            shard_fallback_summary(5, 0, 4).as_deref(),
            Some(
                "NOT SHARDED: 5 of 0 packet(s) carried no host pair the shard peek could \
                 read, so they were dispatched to worker 0 instead of being spread across \
                 the 4 workers."
            )
        );
    }

    /// `jobs <= 1` always routes to worker 0 (the single-threaded path).
    #[test]
    fn jobs_one_is_always_shard_zero() {
        assert_eq!(shard_for(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1), 0);
        assert_eq!(shard_for(ip(1, 2, 3, 4), ip(5, 6, 7, 8), 0), 0);
    }

    /// Both directions of a host pair hash to the same worker, so a flow never
    /// splits across workers.
    #[test]
    fn direction_independent() {
        // Both directions of a flow must hash to the same worker.
        for n in [2usize, 4, 8, 12, 16] {
            let a = ip(10, 20, 30, 40);
            let b = ip(10, 31, 5, 9);
            assert_eq!(
                shard_for(a, b, n),
                shard_for(b, a, n),
                "src/dst order must not change the shard (n={n})"
            );
        }
    }

    /// Every shard index stays within `0..jobs` across many inputs.
    #[test]
    fn shard_in_range() {
        for n in [2usize, 4, 7, 12] {
            for i in 0..500u32 {
                let s = shard_for(ip(10, 20, (i >> 8) as u8, i as u8), ip(10, 30, 0, 1), n);
                assert!(s < n, "shard {s} out of range for n={n}");
            }
        }
    }

    /// Distinct host pairs spread across all workers (no empty bucket).
    #[test]
    fn distributes_across_workers() {
        // Distinct host pairs should spread over the workers (not all in one).
        let n = 8;
        let mut buckets = [0usize; 8];
        for i in 0..2000u32 {
            let s = shard_for(ip(10, 20, (i >> 8) as u8, i as u8), ip(10, 30, 0, 1), n);
            buckets[s] += 1;
        }
        // Every worker gets a meaningful share (no empty bucket; rough balance).
        for (w, &c) in buckets.iter().enumerate() {
            assert!(c > 0, "worker {w} got nothing — sharding not distributing");
        }
    }

    /// Minimal Ethernet + IPv4 + UDP frame carrying `payload` (10.0.0.1 →
    /// 10.0.0.2), for driving the worker pool without a pcap fixture.
    #[cfg(feature = "native")]
    fn eth_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len() as u16;
        let ip_total = 20 + udp_len;
        let mut p = Vec::new();
        p.extend_from_slice(&[0xAA; 6]); // dst MAC
        p.extend_from_slice(&[0xBB; 6]); // src MAC
        p.extend_from_slice(&[0x08, 0x00]); // IPv4
        p.push(0x45); // ver/ihl
        p.push(0x00);
        p.extend_from_slice(&ip_total.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01]); // id
        p.extend_from_slice(&[0x40, 0x00]); // DF, offset 0
        p.push(64); // ttl
        p.push(17); // UDP
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p.extend_from_slice(&[10, 0, 0, 1]); // src ip
        p.extend_from_slice(&[10, 0, 0, 2]); // dst ip
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&udp_len.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p.extend_from_slice(payload);
        p
    }

    /// Minimal Ethernet ARP request — a frame `peek_host_pair` reads no host
    /// pair from, which is what makes it the fallback fixture.
    ///
    /// ARP is not exotic; it is on every LAN segment. The peek declines it for
    /// the same structural reason it declines an encapsulation it cannot
    /// follow, so it drives the counter without depending on any particular
    /// tunnel's decode state.
    #[cfg(feature = "native")]
    fn eth_arp(sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0xFF; 6]); // broadcast dst MAC
        p.extend_from_slice(&[0xBB; 6]); // src MAC
        p.extend_from_slice(&[0x08, 0x06]); // EtherType: ARP
        p.extend_from_slice(&[0x00, 0x01]); // htype: Ethernet
        p.extend_from_slice(&[0x08, 0x00]); // ptype: IPv4
        p.push(6); // hlen
        p.push(4); // plen
        p.extend_from_slice(&[0x00, 0x01]); // opcode: request
        p.extend_from_slice(&[0xBB; 6]); // sender MAC
        p.extend_from_slice(&sender);
        p.extend_from_slice(&[0x00; 6]); // target MAC
        p.extend_from_slice(&target);
        p
    }

    /// Write `frames` to a classic little-endian pcap file with link type
    /// `DLT_EN10MB`, returning its path.
    ///
    /// Hand-built rather than taken from `tests/pcap-samples` because the
    /// fallback tests assert an EXACT unshardable count, which needs an exact
    /// known mix of readable and unreadable frames.
    #[cfg(feature = "native")]
    fn write_eth_pcap(dir: &std::path::Path, name: &str, frames: &[Vec<u8>]) -> std::path::PathBuf {
        use std::io::Write;
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create the temp pcap");
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (µs, LE)
        hdr.extend_from_slice(&2u16.to_le_bytes()); // version major
        hdr.extend_from_slice(&4u16.to_le_bytes()); // version minor
        hdr.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        hdr.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
        f.write_all(&hdr).expect("write the pcap file header");
        for (i, frame) in frames.iter().enumerate() {
            let len = u32::try_from(frame.len()).expect("test frame fits a u32");
            let mut rec = Vec::new();
            rec.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes()); // ts_sec
            rec.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
            rec.extend_from_slice(&len.to_le_bytes()); // incl_len
            rec.extend_from_slice(&len.to_le_bytes()); // orig_len
            f.write_all(&rec).expect("write the record header");
            f.write_all(frame).expect("write the frame");
        }
        path
    }

    /// The channel-fed `--cores` path must COUNT every packet that fell back to
    /// worker 0, and say so in the run's own notice.
    ///
    /// Seven ARP frames and six IP frames: the peek reads a host pair from the
    /// six and nothing from the seven, so the fallback is the majority and the
    /// run is mostly single-threaded. Before this counter both numbers were
    /// invisible — a capture that sharded nothing reported the same summary as
    /// one that sharded perfectly.
    ///
    /// Serialized on `undecodable_tally` because the ARP frames also reach the
    /// workers' parser, whose reason tally is process-global and asserted on
    /// exactly elsewhere.
    #[cfg(feature = "native")]
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn channel_fed_cores_path_counts_every_unshardable_packet() {
        use crate::capture::packet::Packet;
        let (tx, rx) = crate::capture::channel::packet_channel(1024);
        for i in 0..7u8 {
            let frame = eth_arp([10, 0, 0, i], [10, 0, 0, 200]);
            let n = frame.len();
            tx.send(Packet::new(chrono::Utc::now(), frame, n, n, None, 1))
                .expect("worker pool must accept packets");
        }
        for seq in 1u16..=6 {
            let mut payload = vec![0x80, 0x00];
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&[0, 0, 0, 1]);
            payload.extend_from_slice(&0xFEEDu32.to_be_bytes());
            payload.extend_from_slice(&[0xaa; 60]);
            let frame = eth_ipv4_udp(41000, 42000, &payload);
            let n = frame.len();
            tx.send(Packet::new(chrono::Utc::now(), frame, n, n, None, 1))
                .expect("worker pool must accept packets");
        }
        drop(tx);

        let r = run_offline_parallel(rx, pcfg(2));
        assert_eq!(r.packets_read, 13, "thirteen raw packets were sharded");
        assert_eq!(
            r.unshardable_count, 7,
            "the seven ARP frames carry no host pair the peek can read"
        );
        assert_eq!(r.workers, 2, "pcfg(2) runs two workers");
        assert_eq!(
            r.shard_fallback_notice().as_deref(),
            Some(
                "NOT SHARDED: 7 of 13 packet(s) (53.8%) carried no host pair the shard \
                 peek could read, so they were dispatched to worker 0 instead of being \
                 spread across the 2 workers. MOST OF THIS RUN WAS SINGLE-THREADED — the \
                 majority of the capture ran on worker 0, so --cores bought far less than \
                 the 2 workers suggest. The peek cannot follow part of this capture's \
                 encapsulation; report its link type."
            )
        );
    }

    /// The file-fed `--cores` path — the one `-I` reaches, and the one an
    /// operator actually runs — counts the same fallback across the whole set.
    ///
    /// Three ARP frames and two IP frames in one file. The count is shared
    /// across the `-I` set for the same reason the loss counter is: the
    /// operator ran one analysis, not one per file.
    #[cfg(feature = "native")]
    #[test]
    #[serial_test::serial(undecodable_tally)]
    fn file_fed_cores_path_counts_every_unshardable_packet() {
        use crate::capture::CaptureConfig;
        let dir = tempfile::tempdir().expect("temp dir");
        let mut frames = vec![
            eth_arp([10, 0, 0, 1], [10, 0, 0, 200]),
            eth_arp([10, 0, 0, 2], [10, 0, 0, 200]),
            eth_arp([10, 0, 0, 3], [10, 0, 0, 200]),
        ];
        for seq in 1u16..=2 {
            let mut payload = vec![0x80, 0x00];
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&[0, 0, 0, 1]);
            payload.extend_from_slice(&0xFEEDu32.to_be_bytes());
            payload.extend_from_slice(&[0xaa; 60]);
            frames.push(eth_ipv4_udp(41000, 42000, &payload));
        }
        let path = write_eth_pcap(dir.path(), "arp-and-ip.pcap", &frames);

        let r = run_offline_parallel_file(&[path], &CaptureConfig::default(), pcfg(4))
            .expect("the fixture reads");
        assert_eq!(r.packets_read, 5, "five raw packets were sharded");
        assert_eq!(r.unshardable_count, 3, "the three ARP frames fell back");
        assert_eq!(r.workers, 4, "pcfg(4) runs four workers");
        assert_eq!(
            r.shard_fallback_notice().as_deref(),
            Some(
                "NOT SHARDED: 3 of 5 packet(s) (60.0%) carried no host pair the shard \
                 peek could read, so they were dispatched to worker 0 instead of being \
                 spread across the 4 workers. MOST OF THIS RUN WAS SINGLE-THREADED — the \
                 majority of the capture ran on worker 0, so --cores bought far less than \
                 the 4 workers suggest. The peek cannot follow part of this capture's \
                 encapsulation; report its link type."
            )
        );
    }

    /// A capture whose every frame the peek CAN read reports nothing at all.
    ///
    /// The other half of the contract, and the one that keeps the notice worth
    /// reading: an ordinary Ethernet corpus must stay silent, so a line that
    /// does appear means something. Run at `--cores 4` against the same corpus
    /// the core-count-invariance test uses.
    #[cfg(feature = "native")]
    #[test]
    fn a_fully_shardable_capture_reports_no_fallback() {
        use crate::capture::CaptureConfig;
        let paths = [std::path::PathBuf::from(
            "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap",
        )];
        let r = run_offline_parallel_file(&paths, &CaptureConfig::default(), pcfg(4))
            .expect("the corpus fixture reads");
        assert_eq!(
            r.packets_read, 1042,
            "the fixture holds 1042 frames, every one of them sharded"
        );
        assert_eq!(
            r.unshardable_count, 0,
            "plain Ethernet/IPv4 is exactly what the peek reads"
        );
        assert_eq!(
            r.shard_fallback_notice(),
            None,
            "a fully sharded run must stay quiet, or the notice means nothing"
        );
    }

    /// The `--cores` path must discover heuristic-only RTP exactly like the
    /// single-threaded batch path: a PT-72 flow fails the strict
    /// `is_rtp_packet` pre-filter but is promoted by the consecutive-packet
    /// heuristic, so it must land in the merged stream store.
    #[cfg(feature = "native")]
    #[test]
    fn cores_path_discovers_heuristic_rtp() {
        use crate::capture::packet::Packet;
        let (tx, rx) = crate::capture::channel::packet_channel(1024);
        for seq in 1u16..=6 {
            let mut payload = vec![0x80, 72];
            payload.extend_from_slice(&seq.to_be_bytes());
            payload.extend_from_slice(&[0, 0, 0, 1]);
            payload.extend_from_slice(&0xFEEDu32.to_be_bytes());
            payload.extend_from_slice(&[0xaa; 60]);
            let frame = eth_ipv4_udp(41000, 42000, &payload);
            let n = frame.len();
            tx.send(Packet::new(chrono::Utc::now(), frame, n, n, None, 1))
                .expect("worker pool must accept packets");
        }
        drop(tx);
        let r = run_offline_parallel(rx, pcfg(2));
        assert_eq!(
            r.stream_store.len(),
            1,
            "--cores must heuristically discover the PT-72 RTP flow"
        );
        assert!(
            r.rtp_count >= 1,
            "promoted heuristic packets must count as RTP"
        );
    }

    /// The channel-fed entry point sweeps its merged stores too.
    ///
    /// `run_offline_parallel_file` is what `-I` reaches; this one is reached by
    /// `--multi-device`, and it merged and returned without sweeping just the
    /// same. The stream here is announced by no SDP and lives for two minutes
    /// of capture time against a thirty-second timeout, so the only correct
    /// answer is "orphaned" — and the capture epoch is years in the past, so a
    /// sweep reading the wall clock would flag it for the wrong reason and a
    /// sweep reading nothing would not flag it at all.
    #[cfg(feature = "native")]
    #[test]
    fn channel_fed_cores_path_sweeps_after_the_merge() {
        use crate::capture::packet::Packet;
        let base = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid timestamp");
        let (tx, rx) = crate::capture::channel::packet_channel(1024);
        for n in 0..20u16 {
            let mut payload = vec![0x80, 0x00];
            payload.extend_from_slice(&(n + 1).to_be_bytes());
            payload.extend_from_slice(&(160 * (u32::from(n) + 1)).to_be_bytes());
            payload.extend_from_slice(&0x1122_3344u32.to_be_bytes());
            payload.extend_from_slice(&[0xaa; 160]);
            let frame = eth_ipv4_udp(40000, 40002, &payload);
            let len = frame.len();
            // Six seconds apart, so the capture spans just under two minutes.
            let ts = base + chrono::TimeDelta::seconds(i64::from(n) * 6);
            tx.send(Packet::new(ts, frame, len, len, None, 1))
                .expect("worker pool must accept packets");
        }
        drop(tx);
        let r = run_offline_parallel(rx, pcfg(2));
        assert_eq!(r.stream_store.len(), 1, "the fixture holds one RTP stream");
        assert_eq!(
            r.stream_store.orphaned_count(),
            1,
            "a stream no dialog claimed, two minutes old in capture time, must \
             be flagged orphaned by the post-merge sweep"
        );
    }

    /// A permissive `ParallelConfig` for tests: large capacities, reassembly
    /// on, full port range, all protocols enabled.
    #[cfg(feature = "native")]
    fn pcfg(cores: usize) -> ParallelConfig {
        ParallelConfig {
            cores,
            max_streams: 100_000,
            max_dialogs: 100_000,
            rotate: false,
            max_reassembly: 1024,
            portrange: (1, 65535),
            no_dialog: false,
            dialog_tracking: crate::sip::dialog_store::DialogTracking::default(),
            no_rtp: false,
            quiet_bad_parse: false,
            xcid_headers: Vec::new(),
            reassembly: true,
            parse_limit: None,
        }
    }

    /// Batching the reader→worker hand-off must not change what gets
    /// reconstructed. The corpus has 1042 packets across several host pairs —
    /// well past any per-shard batch flush threshold — so running it at
    /// cores 2/4/8 must yield byte-identical dialog/stream/SIP/RTP totals.
    /// This is the regression guard for the batched dispatch: a botched flush
    /// (dropped tail batch, off-by-one) would desync the counts here.
    #[cfg(feature = "native")]
    #[test]
    fn batched_dispatch_is_core_count_invariant() {
        use crate::capture::CaptureConfig;
        let paths = [std::path::PathBuf::from(
            "tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap",
        )];
        let cc = CaptureConfig::default();

        let runs: Vec<(usize, ReconResult)> = [2usize, 4, 8]
            .into_iter()
            .map(|c| (c, run_offline_parallel_file(&paths, &cc, pcfg(c)).unwrap()))
            .collect();

        let (base_c, base) = &runs[0];
        // Sanity: the corpus actually exercised the pipeline (not an empty read).
        assert!(base.total_count > 0, "fixture produced no packets");
        for (c, r) in &runs[1..] {
            assert_eq!(
                r.dialog_store.len(),
                base.dialog_store.len(),
                "dialog count differs: cores {c} vs {base_c}"
            );
            assert_eq!(
                r.stream_store.len(),
                base.stream_store.len(),
                "stream count differs: cores {c} vs {base_c}"
            );
            assert_eq!(
                (r.sip_count, r.rtp_count, r.total_count),
                (base.sip_count, base.rtp_count, base.total_count),
                "SIP/RTP/total counts differ: cores {c} vs {base_c}"
            );
        }
    }

    /// End-to-end codec-negotiation fixture: the INVITE offered PCMU/PCMA/G722,
    /// the call used PCMU, then a re-INVITE switched it to G722 — PCMA was
    /// offered but never used. Reconstructing the capture must surface the two
    /// *used* codecs (PCMU + G722) as the stream codecs, and never PCMA. This is
    /// the real-RTP source the call-flow RTP-in-flow bar reads to label the used
    /// codec rather than the SDP offer list.
    #[cfg(feature = "native")]
    #[test]
    fn codec_negotiation_fixture_reconstructs_used_codecs() {
        use crate::capture::CaptureConfig;
        let paths = [std::path::PathBuf::from(
            "tests/pcap-samples/codec-negotiation.pcap",
        )];
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(&paths, &cc, pcfg(2)).unwrap();
        let codecs: std::collections::HashSet<String> = r
            .stream_store
            .iter()
            .filter_map(|s| s.codec.clone())
            .collect();
        assert!(
            codecs.contains("PCMU"),
            "first segment used PCMU; got {codecs:?}"
        );
        assert!(
            codecs.contains("G722"),
            "re-INVITE switched to G722; got {codecs:?}"
        );
        assert!(
            !codecs.contains("PCMA"),
            "PCMA was offered but never used — must not appear: {codecs:?}"
        );
    }

    /// Opus is a dynamic RTP payload type (here PT 96) with no entry in the
    /// static PT→codec table; the codec is resolved from the dialog SDP's
    /// `a=rtpmap:96 opus/48000`. Reconstructing the plain-Opus fixture must
    /// surface the stream as `opus` at 48000 Hz — proving the SDP-driven dynamic
    /// codec resolution works end to end through the offline engine.
    #[cfg(feature = "native")]
    #[test]
    fn opus_fixture_reconstructs_dynamic_codec_from_sdp() {
        use crate::capture::CaptureConfig;
        let paths = [std::path::PathBuf::from(
            "tests/pcap-samples/invite-opus-bye.pcap",
        )];
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(&paths, &cc, pcfg(2)).unwrap();
        let opus = r
            .stream_store
            .iter()
            .find(|s| s.codec.as_deref() == Some("opus"));
        let opus = opus.expect("expected an opus stream resolved from the SDP rtpmap");
        assert_eq!(opus.payload_type, 96, "opus carried on dynamic PT 96");
    }

    /// The parallel reader stamps packet provenance exactly as the
    /// single-threaded one does. It used to build packets with no source and no
    /// ordinal, so `--cores` produced dialogs whose `first_frame` was `None`,
    /// and every provenance surface (the `--json` `frame`, a finding's
    /// `frame_ref`, `--show-frame`) silently went blank on a parallel run. Read
    /// a real SIP fixture and require every reconstructed dialog to carry a
    /// verifiable pointer into that file — the effect, not the assignment.
    #[cfg(feature = "native")]
    #[test]
    fn parallel_read_stamps_a_verifiable_frame_pointer_on_every_dialog() {
        use crate::capture::CaptureConfig;
        let path = "tests/pcap-samples/invite-opus-bye.pcap";
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(&[std::path::PathBuf::from(path)], &cc, pcfg(2)).unwrap();

        let dialogs: Vec<_> = r.dialog_store.iter().collect();
        assert!(
            !dialogs.is_empty(),
            "the fixture must reconstruct at least one dialog to prove anything"
        );
        for d in &dialogs {
            let frame = d.first_frame.as_ref().expect(
                "a --cores dialog with no frame pointer is the exact silent gap \
                 this stamps: first_frame must be Some, not None",
            );
            assert_eq!(
                frame.source.as_ref(),
                path,
                "the pointer must name the file the frame was read from"
            );
            assert!(
                frame.origin.digest.is_some(),
                "the parallel reader must compute the verifying digest the \
                 single-threaded path does, or the pointer resolves UNVERIFIED"
            );
        }
    }

    /// The digest a `--cores` run stamps must be the value the bytes hash to,
    /// not merely *a* value.
    ///
    /// `parallel_read_stamps_a_verifiable_frame_pointer_on_every_dialog` above
    /// proves a digest is PRESENT, which a constant would satisfy too. This
    /// pins what it equals, and it is the gate that makes moving the hash off
    /// the serial reader safe: the work now runs in the workers, so if that
    /// relocation ever stamped the wrong packet's bytes — an off-by-one across
    /// a shard boundary, a batch reused between packets — every pointer from a
    /// parallel run would resolve as "the capture changed under you" while
    /// pointing at bytes that never moved. Cheap to assert, and the failure it
    /// catches is one that looks like a corrupted capture rather than a bug.
    #[test]
    fn a_parallel_digest_is_the_digest_of_that_frames_bytes() {
        use crate::capture::CaptureConfig;
        use crate::capture::packet::frame_digest;

        let path = "tests/pcap-samples/invite-opus-bye.pcap";
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(&[std::path::PathBuf::from(path)], &cc, pcfg(2)).unwrap();

        // Read the same file straight through, so ordinal -> bytes is known
        // independently of anything the parallel path did.
        let mut cap = pcap::Capture::from_file(path).expect("fixture opens");
        let mut by_ordinal: std::collections::HashMap<u64, Vec<u8>> =
            std::collections::HashMap::new();
        let mut n = 0u64;
        while let Ok(pkt) = cap.next_packet() {
            by_ordinal.insert(n, pkt.data.to_vec());
            n += 1;
        }
        assert!(n > 0, "the fixture must contain frames to compare against");

        let mut checked = 0usize;
        for d in r.dialog_store.iter() {
            let Some(frame) = d.first_frame.as_ref() else {
                continue;
            };
            let Some(got) = frame.origin.digest else {
                continue;
            };
            let bytes = by_ordinal
                .get(&frame.origin.ordinal)
                .unwrap_or_else(|| panic!("ordinal {} is past the file", frame.origin.ordinal));
            assert_eq!(
                got,
                frame_digest(bytes),
                "frame {} carries a digest that is not its own bytes' digest",
                frame.origin.ordinal
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no dialog carried a digest, so this asserted nothing — the \
             comparison, not the capture, is what failed"
        );
    }

    /// A two-file set whose SECOND member has a link type the filter cannot
    /// compile against.
    ///
    /// Chosen from the stock fixtures rather than synthesised, because the
    /// resolver orders a set by first-packet time and the failing member has to
    /// land SECOND for this to be the later-file case at all:
    /// `sip-register.pcap` is Ethernet at 1312180642, `loopback-dlt-loop.pcap`
    /// is `DLT_LOOP` at 1400000000. `ether host ...` compiles against the
    /// first and libpcap rejects it on the second.
    #[cfg(feature = "native")]
    fn set_whose_second_file_rejects_an_ether_filter() -> [std::path::PathBuf; 2] {
        [
            std::path::PathBuf::from("tests/pcap-samples/sip-register.pcap"),
            std::path::PathBuf::from("tests/pcap-samples/loopback-dlt-loop.pcap"),
        ]
    }

    /// Both readers REFUSE a BPF filter that will not compile against a later
    /// file of the set, and both refuse with the same sentence naming that file.
    ///
    /// The two used to disagree about the same input, and the disagreement was
    /// the defect: `capture::file::read_member` returned the error, while
    /// `shard_set` logged `Skipping ...` and read on, so `--cores N` dropped the
    /// whole traffic of every member sharing that link type and still produced a
    /// report that looked like the answer. A filter that will not compile is a
    /// static misconfiguration against that file's link type — the filter text
    /// does not change between files, so it was always going to fail on that one
    /// — and a partial answer that looks complete is worse than no answer.
    ///
    /// The assertion is equality of the two errors, not a shape check on each:
    /// two readers each producing a plausible refusal is how the wordings drift,
    /// and only comparing them catches a parallel path that refuses in its own
    /// words. One `filter_failure` produces both, which is also what makes the
    /// file's name structurally present in each — an operator pointed at forty
    /// files needs to know which one refused.
    #[cfg(feature = "native")]
    #[test]
    fn both_readers_refuse_a_filter_that_will_not_compile_against_a_later_file() {
        use crate::capture::CaptureConfig;
        let paths = set_whose_second_file_rejects_an_ether_filter();
        for p in &paths {
            assert!(p.exists(), "fixture missing: {}", p.display());
        }
        let cc = CaptureConfig {
            bpf_filter: Some("ether host 00:00:00:00:00:01".to_string()),
            ..CaptureConfig::default()
        };

        // The single-threaded reader is the reference: it has refused here
        // since the two arms were reconciled.
        let (tx, _rx) = crate::capture::channel::packet_channel(1024);
        let single = crate::capture::file::capture_files(&paths, &cc, tx, None).expect_err(
            "the single-threaded reader must refuse a filter that cannot compile \
             against file 2",
        );
        // Matched rather than `expect_err`: `ReconResult` is not `Debug`, and a
        // successful run is exactly the failure this test exists to catch, so
        // it gets the sentence rather than a derive.
        let parallel = match run_offline_parallel_file(&paths, &cc, pcfg(4)) {
            Err(e) => e,
            Ok(_) => panic!(
                "--cores must refuse the same input the same way; reading on \
                 drops file 2's entire traffic and still answers as though it \
                 had read it"
            ),
        };

        let (single, parallel) = (format!("{single:#}"), format!("{parallel:#}"));
        assert_eq!(
            parallel, single,
            "both readers must refuse with ONE sentence.\n  single:   {single}\n  \
             parallel: {parallel}"
        );
        assert!(
            parallel.contains("loopback-dlt-loop.pcap"),
            "the refusal must name the file it refused on, or a forty-file set \
             leaves the operator nothing to act on: {parallel}"
        );
    }
}
