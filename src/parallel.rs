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
//! does.** Signaling that traverses a proxy or SBC is captured on two host
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
//! signaling vanished, invisibly, because the dialog COUNT was unaffected.)
//!
//! Dialog↔stream association crosses workers for the same reason — plus the
//! carrier case where SDP advertises a separate media IP, so the SDP lands on a
//! different worker than the RTP — and is likewise resolved globally at merge
//! (`crate::rtp::stream_store::StreamStore::reassociate_all`).
//!
//! # The sweep runs once, after the merge
//!
//! The single-threaded receive loop compacts idle dialogs every five seconds of
//! capture time. This module used to do neither that nor the orphan flagging
//! that used to accompany it, so the same bytes gave two answers: on one
//! reference-corpus set `--cores 4` reported no orphaned streams at all where
//! the single-threaded path reported 80, and the report's "Orphaned Streams:"
//! header was absent entirely — those streams appeared in the ordinary RTP
//! section instead, reading as though they belonged to a call.
//!
//! Half of that divergence is now unrepresentable rather than fixed: orphan
//! status is derived from `associated_dialog` at every read
//! ([`crate::rtp::stream::RtpStream::orphaned`]), so no path can flag it
//! differently from another. What remains is compaction, and `final_sweep`
//! runs it exactly ONCE, after the merge, at the capture's final timestamp. Not
//! per worker: a call's SIP does not stay on one worker (see above), and a
//! worker only sees the packets of its own host pairs, so its local last
//! timestamp can be minutes behind the capture's. A per-worker sweep would
//! measure each fragment against its own clock and produce a THIRD answer,
//! matching neither path — worse than the divergence it replaced, because it
//! would look right.
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

use crate::app::batch::SweepClock;
use crate::capture::PacketProcessor;
use crate::capture::channel::PacketRx;
use crate::capture::parse::ParsedPacket;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// Compact the MERGED dialog store once, at the capture's final timestamp.
///
/// `compact_idle` is the memory bound: it evicts messages from dialogs that
/// have gone quiet, keeping the ones that say what the dialog did. Without it
/// the parallel path retains every message the capture held.
///
/// It no longer sweeps orphans. Orphan status is derived from
/// `associated_dialog` at every read — see
/// [`RtpStream::orphaned`](crate::rtp::stream::RtpStream::orphaned) — so there
/// is no flag for a sweep to set, and the ordering hazard the sweep carried
/// goes with it: this used to have to run AFTER
/// [`reassociate_all`](crate::rtp::stream_store::StreamStore::reassociate_all),
/// because a sticky flag set before cross-worker association resolved would
/// permanently mark streams whose SDP merely landed on another worker.
///
/// # Arguments
///
/// * `clock` — the run's capture clock, fed every packet the reader saw.
/// * `ds` — the merged dialog store, compacted in place.
///
/// # Side effects
///
/// Drops messages from idle dialogs on `ds` (counted into its lifetime
/// retention totals, which the batch summary reports), and logs a `debug!` line
/// naming what compaction shed. Does nothing at all when the run read no
/// packets, because then there is no capture time to measure against and
/// nothing in the store to compact.
fn final_sweep(clock: &SweepClock, ds: &mut DialogStore) {
    let Some(now) = clock.final_now() else {
        return;
    };
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
    /// would silently ignore the flag the single-core path honors.
    pub dialog_tracking: crate::sip::dialog_store::DialogTracking,
    /// Skip RTP/RTCP processing (`--no-rtp`).
    pub no_rtp: bool,
    /// Suppress the bad-parse diagnostic (`--quiet-bad-parse`, sipgrep `-x`).
    pub quiet_bad_parse: bool,
    /// Correlation header names for B2BUA leg matching (sngrep `sip.xcid`).
    /// Empty falls back to the `DialogStore` default (`["X-Call-ID"]`).
    pub xcid_headers: Vec<String>,
    /// How far apart, in milliseconds, two legs of one call may be created and
    /// still correlate on timing alone (`--leg-correlation-window`). Carried
    /// through for the same reason `xcid_headers` is: each worker builds its
    /// own store, and without it the parallel path would silently apply the
    /// shipped window the single-core path was told to replace.
    pub leg_correlation_window_ms: u64,
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
                // Same provenance the single-threaded router records, so a
                // `--cores` run and a `--cores 1` run reach the same answer
                // about which source advertised an endpoint and when.
                let provenance = crate::rtp::stream_store::SdpProvenance::observed(
                    pp.input_origin,
                    pp.timestamp,
                );
                for (ip, port, call_id, media) in &sdp_links {
                    ss.link_to_dialog_with_sdp_from(*ip, *port, call_id, media, provenance);
                }
            }
        }
        PacketAction::Rtcp(pkts) => {
            ss.process_rtcp(&pkts, pp.timestamp);
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
                .with_xcid_headers(cfg.xcid_headers.clone())
                .with_leg_correlation_window_ms(cfg.leg_correlation_window_ms);
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
    .with_xcid_headers(cfg.xcid_headers.clone())
    .with_leg_correlation_window_ms(cfg.leg_correlation_window_ms);
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
    final_sweep(&clock, &mut ds);

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

impl ReadProgress {
    /// Fold one file's read into the run's totals, returning the error that
    /// stopped that file short of its end, if one did.
    ///
    /// The ONE place a [`FileRead`] becomes part of the run, so the serial
    /// reader and the parallel one cannot count differently. It is called in
    /// FILE ORDER by both — the parallel dispatcher folds a file's read only
    /// when it reaches that file — which is what keeps `--count` arithmetic,
    /// the capture clock and the fallback share independent of how many
    /// threads happened to do the reading.
    ///
    /// The error is returned rather than logged here because only the caller
    /// knows the sentence: "stopped reading X early" is about a file, and this
    /// type is about a run.
    fn absorb(&mut self, read: FileRead) -> Option<anyhow::Error> {
        self.count += read.count;
        self.unshardable += read.unshardable;
        if let Some(latest) = read.latest {
            self.clock.observe(latest);
        }
        read.stopped
    }
}

/// Read every packet of an already-opened capture, batching by shard and
/// handing each finished batch to `sink`.
///
/// Written ONCE for both readers. A single-file `-I` is read in the calling
/// thread and hands its batches straight to the workers; a member of a
/// multi-file set is read in its own thread and hands them to the dispatcher
/// that releases them in file order ([`shard_set_parallel`]). Where the batch
/// goes is the whole of the difference, and it is the whole of [`ShardSink`]:
/// the ordinal, the source, the capture clock and the host-pair peek are
/// stamped here for both, so the two cannot drift in what a packet carries.
///
/// The per-shard partial batches are this FILE's, not the set's. They used to
/// survive the file boundary, on the argument that flushing them per file was
/// pure channel overhead; a file read in its own thread has no way to share
/// them with another file's reader, and the price is one partial batch per
/// shard per file — 64 extra sends on the 8-file, 8-shard set that already
/// costs 33k of them.
///
/// Everything read is reported in the returned [`FileRead`], including on the
/// path where the read stopped mid-file: `FileRead::stopped` carries the error
/// instead of the function returning it, because a truncated file is the
/// NORMAL state of a ring buffer's newest member and the packets before the
/// break are real ones that a caller must still count.
fn shard_opened<S: ShardSink>(
    cap: &mut pcap::Capture<pcap::Offline>,
    path: &std::path::Path,
    capture_config: &crate::capture::CaptureConfig,
    n: usize,
    budget: Option<u64>,
    sink: &mut S,
) -> FileRead {
    use crate::capture::packet::Packet;
    // Map the file when it can be mapped, and read it through libpcap when it
    // cannot. A BPF filter is libpcap's to apply, so a filtered read never
    // maps: bypassing the filter would silently widen the capture, which is a
    // wrong answer rather than a slow one.
    let mut frames = Frames::open(cap, path, capture_config.bpf_filter.is_none());
    let link_type = frames.link_type();
    // Stamp provenance exactly as the single-threaded reader does (see
    // `crate::capture::file`): the file is the source, the ordinal is this
    // frame's 0-based position IN this file, and the digest is over the bytes
    // as read. The ordinal counts within THIS file and nothing else, which is
    // what lets a file be read in its own thread without changing a single
    // pointer: a resolver counts frames from the start of the file it is given,
    // so a pointer from a `--cores` run resolves identically to one from a
    // single-threaded run however many threads did the reading. Without the
    // stamp, every fact a parallel run produced carried no `frame_ref` at all,
    // so `--cores` silently dropped packet provenance from every surface.
    let source: std::sync::Arc<str> = std::sync::Arc::from(path.display().to_string());
    let mut ordinal: u64 = 0;

    // One partial batch per shard, this FILE's own; see the doc comment.
    let mut batches: Vec<Vec<Packet>> = (0..n).map(|_| Vec::with_capacity(BATCH)).collect();
    let mut read = FileRead::default();

    // Frames are cut from a shared block rather than allocated one at a time.
    //
    // `pkt.data.to_vec()` was one allocation per packet on the reader, freed
    // later by whichever WORKER finished with it. mimalloc's cross-thread free
    // path is atomic, so a 535k-packet capture paid it 535k times -- the
    // largest single driver in the profile. Slicing from a block makes the
    // allocation and its free amortise across every frame that shares it: at
    // 64 KiB and ~240-byte frames that is ~270 packets per allocation, so the
    // cross-thread traffic falls by the same factor.
    //
    // 64 KiB deliberately, not larger. A block stays alive until the LAST
    // slice cut from it drops, so an oversized block keeps a whole span of
    // memory resident because one packet in it is still being processed.
    // Bigger blocks buy fewer allocations and cost bounded-ness.
    loop {
        if let Some(max) = budget
            && read.count >= max
        {
            tracing::debug!("Reached packet count limit ({max})");
            read.budget_spent = true;
            break;
        }
        match frames.next() {
            Ok(Some(frame)) => {
                let mut packet = Packet::from_bytes(
                    frame.timestamp,
                    frame.data,
                    frame.caplen,
                    frame.origlen,
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
                // The newest timestamp of THIS file, folded into the run's
                // one capture clock by whoever collects the read
                // ([`ReadProgress::absorb`]). `SweepClock` keeps only the
                // maximum, so one value per file is the same clock as one per
                // packet — and it is the only form a reader thread can report,
                // because the clock belongs to the run and the sweep's "now"
                // has to be the SET's last timestamp, not this file's.
                if read.latest.is_none_or(|latest| packet.timestamp > latest) {
                    read.latest = Some(packet.timestamp);
                }
                let s = match crate::capture::parse::peek_host_pair(&packet) {
                    Some((a, b)) => shard_for(a, b, n),
                    // Counted, not merely tolerated — see the same branch in
                    // `run_offline_parallel`. One `u64` increment on the
                    // reader's serial path: no atomic, no lock, no allocation.
                    None => {
                        read.unshardable += 1;
                        0
                    }
                };
                batches[s].push(packet);
                read.count += 1;
                if batches[s].len() >= BATCH {
                    let full = std::mem::replace(&mut batches[s], Vec::with_capacity(BATCH));
                    // A refused batch ends the read and is not recorded.
                    // The only sink that refuses is the queue one, and it
                    // refuses only once the run has already been refused —
                    // this file's verdict is on its way to a dispatcher that
                    // has stopped reading verdicts.
                    if !sink.emit(s, full) {
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                read.stopped = Some(anyhow::anyhow!(
                    "Error reading pcap '{}': {e}",
                    path.display()
                ));
                break;
            }
        }
    }
    // Flushed on EVERY path out, including the error one. The partial batches
    // used to belong to the set and were flushed once at the end of the run;
    // now that they belong to the file, the file has to flush them — and a
    // read that stopped on a truncated record has already read real packets
    // that must still reach a worker.
    for (s, b) in batches.into_iter().enumerate() {
        if b.is_empty() {
            continue;
        }
        if !sink.emit(s, b) {
            break;
        }
    }
    read
}

/// What one file's read produced, reported as ONE value rather than written
/// into the run's totals as it goes.
///
/// The run's counters cannot be incremented in place any more: a file read in
/// its own thread has no exclusive access to them, and one that did would make
/// the totals depend on which reader got there first. Every field here is
/// folded into [`ReadProgress`] by the thread that owns it, in file order, by
/// [`ReadProgress::absorb`] — so the serial reader and the parallel one build
/// the same totals from the same arithmetic.
#[derive(Debug, Default)]
struct FileRead {
    /// Packets read from this file.
    count: u64,
    /// Packets of this file whose host pair the cheap peek could not read,
    /// which therefore fell back to worker 0.
    unshardable: u64,
    /// Newest capture timestamp in this file, or `None` for an empty one.
    latest: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the read stopped because the `--count` budget ran out inside
    /// this file rather than at its end.
    budget_spent: bool,
    /// The error that stopped this file short of its end, if one did.
    stopped: Option<anyhow::Error>,
}

/// Where a finished batch goes once the reader has filled it.
///
/// The two answers are "straight to the worker that owns the shard" (a
/// single-file set, read in the calling thread) and "into this reader's queue,
/// for the dispatcher to release in file order" (one file of many, read in its
/// own thread). [`shard_opened`] is written against this so there is one copy
/// of the read loop rather than one per reader.
///
/// `emit` returns `false` when the run is over and the reader must stop —
/// the set has already been refused, and the queue it is filling will never be
/// drained again. A reader that ignored it would block forever on a bounded
/// channel and hang the process instead of letting the error be reported.
trait ShardSink {
    /// Hand `batch` to the worker that owns `shard`. `false` means stop
    /// reading.
    fn emit(&mut self, shard: usize, batch: Vec<crate::capture::packet::Packet>) -> bool;
}

/// The single-file sink: one hop, straight to the worker.
struct DirectSink<'a> {
    /// One sender per worker, indexed by shard.
    txs: &'a [crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
    /// Raw packets lost because a worker's shard channel had closed.
    dropped: u64,
}

impl ShardSink for DirectSink<'_> {
    fn emit(&mut self, shard: usize, batch: Vec<crate::capture::packet::Packet>) -> bool {
        let weight = batch.len() as u64;
        self.dropped += shard_send(&self.txs[shard], batch, weight);
        // A dead worker does NOT stop the read: the loss is counted and
        // reported once at the end, exactly as it was before this sink
        // existed. Stopping here would turn one dead shard into a truncated
        // analysis of every other one.
        true
    }
}

/// Where the reader's frames come from, and the reason there are two answers.
///
/// A mapped file hands out slices of one mapping that stay valid for as long as
/// any frame does. libpcap hands out a buffer it reuses on the very next call,
/// so a frame read that way must be copied before it can cross a channel. The
/// copy is the whole difference: it costs nothing on one core and 10.5% of
/// throughput on eight, because the price is the per-frame allocate-here /
/// free-there pair crossing the reader-to-worker boundary rather than the
/// `memcpy` itself. `docs/internals/zero-copy-payloads.md` records the same
/// effect one stage downstream.
///
/// Both arms yield the same [`crate::capture::mapped::MappedFrame`], so the
/// reader loop below cannot tell them apart and there is only one copy of the
/// sharding, ordinal-stamping and batching logic to keep correct.
enum Frames<'a> {
    /// The always-works arm. Owns the block that frames are copied into.
    Libpcap {
        /// The open capture. Borrowed rather than owned because the caller
        /// opened it and applied any BPF filter before this point.
        cap: &'a mut pcap::Capture<pcap::Offline>,
        /// Frames are cut from a shared block rather than allocated one at a
        /// time.
        ///
        /// `pkt.data.to_vec()` was one allocation per packet on the reader,
        /// freed later by whichever WORKER finished with it. mimalloc's
        /// cross-thread free path is atomic, so a 535k-packet capture paid it
        /// 535k times -- the largest single driver in the profile. Slicing from
        /// a block makes the allocation and its free amortise across every
        /// frame that shares it: at 64 KiB and ~240-byte frames that is ~270
        /// packets per allocation, so the cross-thread traffic falls by the
        /// same factor.
        ///
        /// 64 KiB deliberately, not larger. A block stays alive until the LAST
        /// slice cut from it drops, so an oversized block keeps a whole span of
        /// memory resident because one packet in it is still being processed.
        /// Bigger blocks buy fewer allocations and cost bounded-ness.
        block: bytes::BytesMut,
        /// libpcap's datalink number, read once at open so the reader loop does
        /// not ask per frame.
        link_type: i32,
    },
    /// The fast arm. Maps the file and reads records in place; see
    /// [`crate::capture::mapped`] for what it costs and what it declines.
    Mapped(Box<crate::capture::mapped::MappedPcap>),
}

impl<'a> Frames<'a> {
    /// Block size frames are copied into on the libpcap arm, matching the
    /// mapped reader's own so both arms amortise allocation the same way.
    const BLOCK: usize = 64 * 1024;

    /// Prefer the mapping, fall back to libpcap. `may_map` is false when a BPF
    /// filter is set, because applying it is libpcap's job.
    fn open(
        cap: &'a mut pcap::Capture<pcap::Offline>,
        path: &std::path::Path,
        may_map: bool,
    ) -> Self {
        if !may_map {
            // Said out loud: otherwise the only sign that the fast path was
            // skipped is the absence of the line below, and an absent log line
            // is indistinguishable from a log that was never wired up.
            tracing::debug!(
                "A BPF filter is set, so '{}' reads via libpcap, which applies it",
                path.display()
            );
        }
        if may_map {
            // A file that will not map is the ordinary case for pcapng and
            // gzip, so this is debug-level rather than a warning.
            match crate::capture::mapped::MappedPcap::open(path) {
                Ok(Some(m)) => {
                    tracing::debug!("Mapped '{}' for a copy-free read", path.display());
                    return Frames::Mapped(Box::new(m));
                }
                Ok(None) => {
                    tracing::debug!("'{}' cannot be mapped; reading via libpcap", path.display());
                }
                Err(e) => {
                    tracing::debug!(
                        "Mapping '{}' failed ({e}); reading via libpcap",
                        path.display()
                    );
                }
            }
        }
        let link_type = cap.get_datalink().0;
        Frames::Libpcap {
            cap,
            block: bytes::BytesMut::with_capacity(Self::BLOCK),
            link_type,
        }
    }

    /// This file's datalink number, whichever arm is reading it. Both must
    /// report the same value, or a frame would be decoded against one link type
    /// on the fast path and another on the fallback.
    fn link_type(&self) -> i32 {
        match self {
            Frames::Libpcap { link_type, .. } => *link_type,
            Frames::Mapped(m) => m.link_type(),
        }
    }

    /// The next frame, `Ok(None)` at end of file.
    fn next(&mut self) -> Result<Option<crate::capture::mapped::MappedFrame>, anyhow::Error> {
        match self {
            Frames::Mapped(m) => match m.next_frame() {
                Some(f) => Ok(Some(f)),
                // A file that ended mid-record stops the read AND says so, in
                // libpcap's own words, because the fallback path reports it and
                // an operator must not learn that a capture is complete from
                // whichever reader happened to open it.
                None => match m.truncation() {
                    Some((wanted, got)) => Err(anyhow::anyhow!(
                        "truncated dump file; tried to read {wanted} captured bytes, only got {got}"
                    )),
                    None => Ok(None),
                },
            },
            Frames::Libpcap { cap, block, .. } => match cap.next_packet() {
                Ok(pkt) => {
                    // NOT `n`: that name is already the SHARD COUNT in the
                    // caller, and shadowing it fed the frame length to
                    // `shard_for` -- a 236-byte frame indexed shard 236 of 2.
                    let frame_len = pkt.data.len();
                    // A frame larger than the block gets its own exact-sized
                    // one: `split_to` below must not outrun the capacity, and a
                    // jumbo frame should not force every later frame into a
                    // bigger block.
                    if block.capacity() < frame_len {
                        *block = bytes::BytesMut::with_capacity(Self::BLOCK.max(frame_len));
                    }
                    block.extend_from_slice(pkt.data);
                    // `split_to` hands back the bytes just written and leaves
                    // the remaining capacity in `block`, both views of ONE
                    // allocation.
                    let data = block.split_to(frame_len).freeze();
                    Ok(Some(crate::capture::mapped::MappedFrame {
                        timestamp: crate::capture::file::pcap_ts_to_chrono(pkt.header.ts),
                        data,
                        caplen: pkt.header.caplen as usize,
                        origlen: pkt.header.len as usize,
                    }))
                }
                Err(pcap::Error::NoMorePackets) => Ok(None),
                Err(e) => Err(anyhow::Error::new(e)),
            },
        }
    }
}

/// Read every file of the set in THIS thread, tallying what became of each
/// one.
///
/// The serial reader, and now one of two: [`shard_set_parallel`] reads a
/// multi-file set with one thread per file. This one is what a single-file
/// `-I` uses — there is one file, so there is one reader, and a thread to hand
/// it to would be pure overhead — and what a `--count` run uses, because a
/// budget shared across a set only means anything read in order.
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
/// pushes batches to `txs`, advances `progress` and `tally`, and logs per-file
/// progress and per-file failures.
fn shard_set(
    paths: &[std::path::PathBuf],
    capture_config: &crate::capture::CaptureConfig,
    txs: &[crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
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
            // being cleaned up while it is analyzed — is logged and skipped:
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
        tracing::info!("Reading from '{}'", path.display());
        // A read error stops THIS file, not the set. Truncation is the normal
        // state of a ring buffer — the newest member is still being written when
        // the capture stops, and libpcap reports `truncated dump file` on the
        // trailing partial record. Whatever was read before the break is already
        // in the workers' stores and stays there.
        let mut sink = DirectSink { txs, dropped: 0 };
        // The budget is what is LEFT of `--count` across the set, so a hundred
        // packets over four files is still a hundred packets.
        let budget = capture_config
            .count
            .map(|max| max.saturating_sub(progress.count));
        let read = shard_opened(&mut cap, path, capture_config, txs.len(), budget, &mut sink);
        progress.dropped += sink.dropped;
        let budget_spent = read.budget_spent;
        match progress.absorb(read) {
            None if budget_spent => {
                // The `--count` budget ran out inside this file. Requested, so
                // not a loss — but the file was still not read to its end, and
                // the files behind it are "not reached" rather than absent.
                tally.stopped_early += 1;
                return Ok(());
            }
            None => tally.complete += 1,
            Some(e) => {
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

/// How far the readers of LATER files may run ahead of the file the dispatcher
/// is releasing, in bytes, across the whole set.
///
/// This number is the entire speed/memory trade of the parallel read, because
/// a later file's reader cannot deliver a single packet until the earlier
/// file's reader has delivered its last one — the workers must see a shard's
/// packets in capture order — so everything it reads early it has to hold.
/// Speedup is therefore bounded by `1 + runway / file size` and capped at the
/// reader count: a runway of one whole file lets the next file be dispatched
/// the instant its predecessor ends, which halves the read stage; a runway of
/// a tenth of a file buys a tenth.
///
/// Measured on the 8-file rotated set below at `--cores 8`, sweeping this
/// value with everything else fixed — read stage, then peak RSS:
///
/// ```text
///   runway     read     RSS        runway     read     RSS
///   0        0.875s   212 MiB      1024     0.579s   299 MiB
///   256      0.814s   222 MiB      2048     0.583s   383 MiB
///   512      0.733s   250 MiB      4096     0.580s   412 MiB
/// ```
///
/// (in batches, as the sweep was run; the budget is in bytes for the reason
/// below.) The curve has a knee and then a cliff into pure cost: past ~1024
/// batches the read stage does not move again, because 0.58s is where the
/// EIGHT WORKERS become the bottleneck instead — a bigger runway then buys
/// nothing and still holds the memory. A runway of zero is the control, and it
/// is worth its own line: the reader threads and the dispatcher, with no
/// read-ahead at all, are 3-4% SLOWER than reading the set in one thread.
/// Every gain here is bought with this budget, and none of it comes free from
/// the threading.
///
/// Bytes rather than batches because a batch is 128 packets of ANY size, and
/// sipnab's default snaplen is 65535: on a jumbo capture a 1024-batch runway
/// is 8 GiB. The charge is the frame plus the `Packet` that carries it, which
/// is what the batch actually costs; 48 MiB of that is ~131k packets of the
/// ~240-byte frames in the set below, the knee above. Real resident cost runs
/// well above the charge, because the allocator's 64 KiB blocks stay alive
/// until the last frame cut from them drops: the shipped value measures 293
/// MiB peak RSS at `--cores 8` against 205 MiB for the serial reader over the
/// same set.
///
/// (The sweep above predates [`DISPATCH_RESERVE_BYTES`], so its RSS column
/// carries a second, unbounded buffer that no longer exists. The read-stage
/// column is unaffected — at eight cores the dispatcher barely blocks, so that
/// buffer stayed near empty — and the 1024-batch row's 299 MiB is within
/// measurement of the 293 MiB the shipped build now takes.)
const READ_AHEAD_BYTES: usize = 48 * 1024 * 1024;

/// How far the reader of the file being dispatched may run ahead, in bytes.
///
/// A separate, much smaller pool because it answers a different question. The
/// runway above buys parallelism; this only smooths the moment the dispatcher
/// spends blocked on a full worker channel, and 8 MiB is ~21k packets of the
/// set below — more than enough that the reader is never idle waiting for it.
///
/// It exists because that reader is exempt from the runway, and "exempt" was
/// briefly "unbounded": its queue was capped in BATCHES, so when the workers
/// were the bottleneck it filled the queue instead of waiting. Measured at
/// `--cores 2` on the 8-file set, peak RSS went 168 MiB -> 366 MiB, where the
/// runway alone accounts for ~82 MiB of that; the rest was one reader running
/// hundreds of MiB ahead of a dispatcher blocked on the workers. With a
/// 65535-byte snaplen the same queue is tens of gigabytes. With this pool the
/// same run peaks at 286 MiB and loses no throughput for it.
const DISPATCH_RESERVE_BYTES: usize = 8 * 1024 * 1024;

/// What one buffered packet is charged against [`READ_AHEAD_BYTES`]: its
/// frame, plus the `Packet` that carries the frame. The second half is what
/// gives the charge a floor — a capture of 64-byte frames would otherwise buy
/// a runway of millions of packets for nothing.
fn read_ahead_charge(batch: &[crate::capture::packet::Packet]) -> usize {
    let frames: usize = batch.iter().map(|p| p.data.len()).sum();
    frames + std::mem::size_of_val(batch)
}

/// A batch on its way from one file's reader to the dispatcher.
enum ReaderMsg {
    /// One shard's worth of packets, in capture order.
    Batch {
        /// Which worker owns them.
        shard: usize,
        /// What this batch was charged against the run-ahead ledger, carried
        /// so the dispatcher can give it back without re-walking 128 packets
        /// it otherwise never touches.
        charge: usize,
        /// The packets, already stamped with source and ordinal.
        packets: Vec<crate::capture::packet::Packet>,
    },
    /// This file is finished — read, refused, or never opened. Always the LAST
    /// message a file sends, which is how the dispatcher knows it may move on
    /// to the next one.
    Done(FileOutcome),
}

/// What became of one file, reported to the dispatcher by its reader.
///
/// The three arms are the three verdicts [`shard_set`] reaches inline, kept
/// apart here because a reader thread cannot reach them: only the dispatcher
/// knows whether this is the FIRST file (whose open failing proves the set
/// unusable) and only it may write the tally.
enum FileOutcome {
    /// The file could not be opened.
    OpenFailed(anyhow::Error),
    /// The BPF filter would not compile against this file's link type.
    FilterFailed(anyhow::Error),
    /// The file was opened and read; [`FileRead::stopped`] says whether the
    /// read reached the end.
    Read(FileRead),
}

/// How far each file's reader may run ahead of the dispatcher, and the state
/// that keeps that bounded.
///
/// The ledger is in BYTES: a reader charges what a batch costs before handing
/// it over. There are two pools, because the readers ahead and the reader
/// being dispatched are bounded for different reasons.
///
/// [`READ_AHEAD_BYTES`] is the runway proper — what a LATER file's reader may
/// hold, and the whole speed/memory trade. A file's charge comes back in one
/// move rather than batch by batch: when the dispatcher reaches file `f`,
/// everything reader `f` was holding is released at once.
///
/// [`DISPATCH_RESERVE_BYTES`] is what the reader of the CURRENT file may hold,
/// and it is released batch by batch as the dispatcher forwards them. That
/// reader must never wait on the RUNWAY — without that exemption the whole set
/// deadlocks the moment the readers ahead hold the entire budget, because the
/// dispatcher would be waiting on a reader that is waiting on the dispatcher —
/// but "exempt from the runway" is not "unbounded", which is what it was until
/// this pool existed.
///
/// Neither pool can deadlock on a batch bigger than itself: a caller holding
/// nothing is admitted whatever it asks for, and takes only what was there.
///
/// # One claimant at a time
///
/// The whole runway goes to the file the dispatcher will reach NEXT, and no
/// other, until that file is either fully read or out of permits. Sharing it
/// out is the obvious policy and it is the wrong one, because what the runway
/// buys is the head start ONE file has when its turn comes. Measured on the
/// 8-file rotated set at `--cores 8` with the same 2048-batch budget: shared
/// out between the seven waiting readers the read stage was 0.677s, spent on
/// the next file in line it is 0.583s. Each file gets the same head start in
/// turn, and a runway larger than a file passes straight on to the file after
/// it — so a set of many small files still reads every one of them at once.
struct Runway {
    /// Guards the whole ledger. Taken once per BATCH — 128 packets — so its
    /// cost is 1/128th of a lock per packet.
    state: std::sync::Mutex<RunwayState>,
    /// Signaled when permits are freed or the run is canceled.
    ready: std::sync::Condvar,
}

/// The permit ledger. See [`Runway`].
struct RunwayState {
    /// Bytes of the runway nobody holds.
    free: usize,
    /// Bytes of the dispatch reserve nobody holds.
    reserve: usize,
    /// The file the dispatcher is releasing. Its reader is charged nothing.
    current: usize,
    /// Bytes held per file index.
    held: Vec<usize>,
    /// Which files have been read to their end, so the claim can pass on. A
    /// file that could not be opened counts as finished: it will never ask for
    /// a permit, and a claim it holds is one no other file can use.
    finished: Vec<bool>,
    /// Set when the run is over and every waiting reader must give up.
    canceled: bool,
}

impl RunwayState {
    /// The one file entitled to spend the runway: the nearest one after the
    /// dispatch point that has not finished reading.
    fn claimant(&self) -> usize {
        let mut file = self.current + 1;
        while file < self.finished.len() && self.finished[file] {
            file += 1;
        }
        file
    }
}

impl Runway {
    /// A ledger for `files` files, `budget` bytes of read-ahead and
    /// [`DISPATCH_RESERVE_BYTES`] for the file being dispatched.
    fn new(files: usize, budget: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(RunwayState {
                free: budget,
                reserve: DISPATCH_RESERVE_BYTES,
                current: 0,
                held: vec![0; files],
                finished: vec![false; files],
                canceled: false,
            }),
            ready: std::sync::Condvar::new(),
        }
    }

    /// Claim the right to hand one more batch, costing `charge` bytes, to the
    /// dispatcher — blocking until the run-ahead allows it. `false` means the
    /// run was canceled and the reader must stop.
    ///
    /// A batch larger than the pool it draws on is still admitted, once that
    /// pool is otherwise untouched. Refusing it would be a deadlock, not a
    /// saving: the packets are already read and no smaller batch is coming.
    /// What it takes is what was THERE, not what it asked for — a pool that
    /// gave back more than it lent would grow by the overdraft every time an
    /// oversized batch went through, and a bound that rises each time it is
    /// exceeded is not a bound.
    ///
    /// # Side effects
    ///
    /// Charges one of the two pools; blocks the calling thread until there is
    /// room in it.
    fn acquire(&self, file: usize, charge: usize) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if state.canceled {
                return false;
            }
            if file <= state.current {
                // The file being dispatched draws on the reserve, which comes
                // back batch by batch as the dispatcher forwards them. It is
                // full whenever the dispatcher has caught up, so a reader the
                // dispatcher is keeping up with never waits here at all.
                if state.reserve >= charge || state.reserve == DISPATCH_RESERVE_BYTES {
                    state.reserve -= charge.min(state.reserve);
                    return true;
                }
            } else if state.claimant() == file && (state.free >= charge || state.held[file] == 0) {
                let taken = charge.min(state.free);
                state.free -= taken;
                state.held[file] += taken;
                return true;
            }
            state = self.ready.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Give back what a forwarded batch was holding.
    ///
    /// Always to the RESERVE, whichever pool the batch was charged to. A batch
    /// charged to the runway had that charge returned wholesale when the
    /// dispatcher reached its file, so returning it again would double-count —
    /// which the ceiling at [`DISPATCH_RESERVE_BYTES`] absorbs, and is why the
    /// dispatcher does not have to remember which pool paid.
    ///
    /// # Side effects
    ///
    /// Wakes the reader of the file being dispatched, if it is waiting.
    fn release(&self, charge: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reserve = state
            .reserve
            .saturating_add(charge)
            .min(DISPATCH_RESERVE_BYTES);
        drop(state);
        self.ready.notify_all();
    }

    /// Bytes of the dispatch reserve nobody holds.
    ///
    /// Only an assertion reads this, and that is the point: at the end of a
    /// clean run it must be the whole reserve again, because every batch the
    /// reserve lent for has been forwarded. A dispatcher that forwarded a
    /// batch without giving its bytes back would leave this short, and would
    /// eventually stall a reader against a reserve that only ever shrinks.
    fn reserve_free(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).reserve
    }

    /// Whether the run is over. Read by a reader between files, so a set whose
    /// third member was refused does not go on to open the other
    /// twenty-four.
    fn canceled(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .canceled
    }

    /// Move the dispatch point to `file`, releasing everything that file's
    /// reader was holding.
    ///
    /// # Side effects
    ///
    /// Wakes every reader waiting for a permit.
    fn advance(&self, file: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.current = file;
        state.free += std::mem::take(&mut state.held[file]);
        drop(state);
        self.ready.notify_all();
    }

    /// Record that a file has been read to its end, passing the claim on the
    /// runway to the next unfinished file.
    ///
    /// # Side effects
    ///
    /// Wakes every reader waiting for a permit.
    fn retire(&self, file: usize) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.finished[file] = true;
        drop(state);
        self.ready.notify_all();
    }

    /// End the run: every reader waiting for a permit gives up.
    ///
    /// # Side effects
    ///
    /// Wakes every reader waiting for a permit.
    fn cancel(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.canceled = true;
        drop(state);
        self.ready.notify_all();
    }
}

/// The multi-file sink: into this reader's own queue, for the dispatcher to
/// release when it reaches this file.
struct QueueSink<'a> {
    /// This file's index in the set, which is what the run-ahead is measured
    /// against.
    file: usize,
    /// This reader THREAD's queue. A thread reads files `first`, `first+R`,
    /// `first+2R`… in order and the dispatcher reaches them in that order too,
    /// so one queue per thread already delivers every message in the order its
    /// consumer wants it.
    tx: &'a crossbeam_channel::Sender<ReaderMsg>,
    /// The shared read-ahead ledger.
    runway: &'a Runway,
}

impl ShardSink for QueueSink<'_> {
    fn emit(&mut self, shard: usize, batch: Vec<crate::capture::packet::Packet>) -> bool {
        // Walked once, here, on the thread that just built the batch and has
        // every `Packet` in its cache — not on the dispatcher, which otherwise
        // touches nothing but the pointer.
        let charge = read_ahead_charge(&batch);
        if !self.runway.acquire(self.file, charge) {
            return false;
        }
        self.tx
            .send(ReaderMsg::Batch {
                shard,
                charge,
                packets: batch,
            })
            .is_ok()
    }
}

/// Read one file, all the way, in a reader thread.
///
/// The open and the filter check are the same two steps [`shard_set`] takes
/// inline; what differs is that a thread cannot decide what they MEAN — the
/// first file's open failing is a verdict on the whole set, and only the
/// dispatcher knows which file is first.
///
/// # Side effects
///
/// Sends this file's batches into `sink`'s queue, blocking on the run-ahead.
fn read_one_file(
    file: usize,
    path: &std::path::Path,
    capture_config: &crate::capture::CaptureConfig,
    shards: usize,
    tx: &crossbeam_channel::Sender<ReaderMsg>,
    runway: &Runway,
) -> FileOutcome {
    let (mut cap, _gz_guard) = match crate::capture::file::open_offline(path) {
        Ok(opened) => opened,
        Err(e) => return FileOutcome::OpenFailed(e),
    };
    if let Some(ref bpf) = capture_config.bpf_filter
        && let Err(e) = cap.filter(bpf, true)
    {
        return FileOutcome::FilterFailed(crate::capture::file::filter_failure(bpf, path, e));
    }
    let mut sink = QueueSink { file, tx, runway };
    // No `--count` budget: a set read in parallel never has one. See
    // `shard_set_parallel` for why.
    FileOutcome::Read(shard_opened(
        &mut cap,
        path,
        capture_config,
        shards,
        None,
        &mut sink,
    ))
}

/// Read every file of a multi-file set, one reader thread per file, and
/// release what they read into the worker pool IN FILE ORDER.
///
/// # Why this exists
///
/// One thread used to read the whole `-I` set: open a file, read + copy +
/// host-pair-peek every packet of it, then the next file, while N workers
/// waited. That single stage is what `--cores` plateaus on — measured on an
/// 8×535k-packet rotated set (`bench/carrier.py --calls 40000`, cut into eight
/// members with `editcap -F pcap -c 535000`), the read stage takes 0.85s at
/// `--cores 4` and 0.83s at `--cores 8`, so past four cores the extra workers
/// buy nothing at all. Since `-I` routinely names a directory or glob of
/// rotated captures, there are N files to read and no reason one thread should
/// read them all.
///
/// Interleaved against the serial reader on that set, median of nine on an
/// idle host, whole-process wall clock:
///
/// ```text
///   cores   serial    per-file   change
///   1       2.815s     2.822s     -0.3%   (control: neither uses this)
///   2       1.794s     1.821s     -1.5%
///   4       1.168s     1.215s     -4.0%
///   8       1.146s     0.909s    +20.7%
///   12      1.228s     0.957s    +22.1%
/// ```
///
/// The peak moves with it: 3.66M pkts/s at four cores becomes 4.71M at eight.
/// The two- and four-core rows are a real regression and are the trade, not an
/// oversight — there the WORKERS are the bottleneck, so the read-ahead buys
/// nothing and still costs a second reader competing for memory bandwidth, a
/// channel hop, and 48 MiB moving through the caches the workers are using.
///
/// A SINGLE-file `-I` has one file and therefore one reader: this function is
/// not used for it at all ([`run_offline_parallel_file`] calls [`shard_set`]
/// instead), and nothing here makes a one-file run faster. That is not a
/// limitation to work around later — a pcap record's length is only known from
/// the record before it, so a file cannot be cut into pieces without first
/// walking it.
///
/// # Why the dispatcher exists
///
/// The readers do not send to the workers. They cannot: a worker must see its
/// shard's packets in capture order, and the workers are stateful in ways that
/// order decides — the RTP sequence tracking that derives loss and jitter, the
/// SIP dialog state machine, and TCP reassembly all read the packets one after
/// another. A reader for file 4 that sent a BYE before file 3's reader sent
/// the INVITE would not merely reorder the output, it would produce different
/// numbers. So each reader fills its own queue and this thread releases them
/// file by file, which reproduces the serial reader's per-worker sequence
/// EXACTLY: for every shard, file 0's packets in order, then file 1's, and so
/// on. Nothing downstream can tell the two readers apart.
///
/// The cost of that guarantee is memory, and [`READ_AHEAD_BYTES`] is where it
/// is paid and bounded.
///
/// # `--count`
///
/// Never used with one: a budget shared across a set means "the first N
/// packets in read order", and a reader that does not know how many packets
/// the files before it held cannot honor it. [`run_offline_parallel_file`]
/// sends a `--count` run down the serial reader instead, where the semantics
/// are exact. A `--count` run is a peek at a capture, not a throughput
/// problem.
///
/// # Errors
///
/// The two the serial reader raises, from the same files, in the same order:
/// the FIRST file failing to open, or the BPF filter refusing to compile
/// against any member. The verdicts are reached in file
/// order because the dispatcher folds each file's outcome only when it reaches
/// that file — a reader that finished file 7 early cannot make file 7's
/// failure the one that is reported when file 3 also failed.
///
/// # Side effects
///
/// Spawns one thread per reader, reads and maps files, pushes batches into
/// `txs`, advances `progress` and `tally`, and logs per-file progress and
/// per-file failures.
fn shard_set_parallel(
    paths: &[std::path::PathBuf],
    capture_config: &crate::capture::CaptureConfig,
    txs: &[crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
    progress: &mut ReadProgress,
    tally: &mut crate::capture::file::ReadTally,
    readers: usize,
) -> anyhow::Result<()> {
    debug_assert!(paths.len() > 1 && readers > 1 && capture_config.count.is_none());
    let shards = txs.len();
    let runway = Runway::new(paths.len(), READ_AHEAD_BYTES);
    // Deep enough that the BYTE ledger is what stops a reader, never the
    // queue: the smallest a batch can be charged is 128 `Packet`s, so that
    // divides the two pools into the most batches they can ever cover.
    let depth = (READ_AHEAD_BYTES + DISPATCH_RESERVE_BYTES)
        / (BATCH * std::mem::size_of::<crate::capture::packet::Packet>())
        + 8;

    std::thread::scope(|scope| {
        // One queue per reader THREAD, sized past both byte pools so that the
        // ledger is what blocks a reader and the queue never is.
        let mut queues = Vec::with_capacity(readers);
        for first in 0..readers {
            let (tx, rx) = crossbeam_channel::bounded::<ReaderMsg>(depth);
            queues.push(rx);
            let runway = &runway;
            scope.spawn(move || {
                for file in (first..paths.len()).step_by(readers) {
                    if runway.canceled() {
                        return;
                    }
                    let outcome =
                        read_one_file(file, &paths[file], capture_config, shards, &tx, runway);
                    // Retired BEFORE the verdict is queued: the `Done` message
                    // sits behind every batch this file produced and the
                    // dispatcher will not see it for a while, but the runway
                    // this file is no longer using has to pass to the next one
                    // immediately or it goes unspent.
                    runway.retire(file);
                    if tx.send(ReaderMsg::Done(outcome)).is_err() {
                        return;
                    }
                }
            });
        }

        let outcome = dispatch_in_file_order(paths, txs, &queues, &runway, progress, tally);

        // No reader may be left blocked, on ANY path out. This scope joins
        // every thread before it returns, so a reader still waiting for a
        // permit or for room in a queue nobody drains would hang the process
        // instead of letting the error above be reported. Canceling releases
        // the waiters; draining releases the senders.
        runway.cancel();
        for rx in &queues {
            while rx.recv().is_ok() {}
        }
        // Every batch the dispatcher forwarded gave its bytes back, so a run
        // that read the whole set ends with the reserve whole. Checked rather
        // than assumed because the symptom of the alternative is a hang on a
        // big capture and nothing at all on a small one — the reserve is
        // 8 MiB, so a fixture never reaches it and only a real run does.
        // Skipped on the error paths, where readers were canceled holding
        // bytes for batches nobody will forward.
        debug_assert!(
            outcome.is_err() || runway.reserve_free() == DISPATCH_RESERVE_BYTES,
            "the dispatch reserve leaked: {} of {DISPATCH_RESERVE_BYTES} bytes \
             came back",
            runway.reserve_free()
        );
        outcome
    })
}

/// Release what the readers produced into the worker pool, file by file.
///
/// See [`shard_set_parallel`] for why this stage exists at all. It does one
/// thing per batch — hand it to the worker that owns the shard — and nothing
/// per packet, which is the whole point: the per-packet work is in the reader
/// threads.
///
/// # Errors
///
/// A file's reader vanishing without reporting (it panicked), the FIRST file
/// failing to open, or the BPF filter refusing a file.
///
/// # Side effects
///
/// Sends batches to the workers, advances `progress` and `tally`, moves the
/// run-ahead's dispatch point, and logs one line per file read and one per
/// file lost.
fn dispatch_in_file_order(
    paths: &[std::path::PathBuf],
    txs: &[crossbeam_channel::Sender<Vec<crate::capture::packet::Packet>>],
    queues: &[crossbeam_channel::Receiver<ReaderMsg>],
    runway: &Runway,
    progress: &mut ReadProgress,
    tally: &mut crate::capture::file::ReadTally,
) -> anyhow::Result<()> {
    for (file, path) in paths.iter().enumerate() {
        runway.advance(file);
        let rx = &queues[file % queues.len()];
        // Said at the moment the file's traffic starts reaching the workers,
        // not at the moment its reader opened it, so the narration stays in
        // file order however the reads interleaved. An operator watching a
        // 27-file run reads this line as "the run is on file 12 now", and
        // eight readers announcing themselves at once would destroy that.
        let mut announced = false;
        let announce = |announced: &mut bool| {
            if !*announced {
                tracing::info!("Reading from '{}'", path.display());
                *announced = true;
            }
        };
        loop {
            match rx.recv() {
                Ok(ReaderMsg::Batch {
                    shard,
                    charge,
                    packets,
                }) => {
                    announce(&mut announced);
                    let weight = packets.len() as u64;
                    progress.dropped += shard_send(&txs[shard], packets, weight);
                    // After the send, not before: the reserve exists to bound
                    // what is IN FLIGHT, and this batch is only out of flight
                    // once a worker owns it.
                    runway.release(charge);
                }
                Ok(ReaderMsg::Done(FileOutcome::Read(read))) => {
                    // Announced even for an empty file: it WAS read, and the
                    // serial reader says so too.
                    announce(&mut announced);
                    match progress.absorb(read) {
                        None => tally.complete += 1,
                        // A read error stops THIS file, not the set.
                        // Truncation is the normal state of a ring buffer —
                        // the newest member is still being written when the
                        // capture stops. Whatever was read before the break
                        // has already been released above.
                        Some(e) => {
                            tally.stopped_early += 1;
                            tally.lost = true;
                            tracing::error!(
                                "Stopped reading '{}' early: {e:#}. Continuing with the rest of the set.",
                                path.display()
                            );
                        }
                    }
                    break;
                }
                Ok(ReaderMsg::Done(FileOutcome::OpenFailed(e))) => {
                    // The first file owns the "is this set usable at all"
                    // verdict. A later one that vanished mid-run — a rotating
                    // capture directory being cleaned up while it is analyzed
                    // — is logged and skipped: losing one file of a set is
                    // bad, losing the other nine is worse.
                    if file == 0 {
                        return Err(e);
                    }
                    tally.skipped += 1;
                    tally.lost = true;
                    tracing::error!("Skipping '{}': {e:#}", path.display());
                    break;
                }
                Ok(ReaderMsg::Done(FileOutcome::FilterFailed(e))) => {
                    // Counted as a skip BEFORE the refusal is propagated: a
                    // file whose traffic never reached the workers is data
                    // missing from the analysis, and the caller reports the
                    // tally on every path out.
                    tally.skipped += 1;
                    tally.lost = true;
                    return Err(e);
                }
                Err(_) => {
                    // The reader dropped its queue without a verdict, which
                    // only happens if it panicked. Said out loud rather than
                    // treated as end-of-file: a silently short set is the
                    // failure this whole module's tally exists to prevent.
                    return Err(anyhow::anyhow!(
                        "the reader thread for '{}' stopped without reporting",
                        path.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Like `run_offline_parallel`, but reads the capture FILES itself instead of
/// consuming a `PacketRx` fed by a separate capture reader thread. That
/// eliminated the semaphore-capped capture channel which capped `--cores`
/// scaling at ~2 workers, by fusing pcap-read + host-pair peek + shard into
/// one stage instead of two. Sharding/reassembly/merge are identical to
/// `run_offline_parallel`, so `--cores N` parity with `--cores 1` is preserved.
///
/// That fused stage is SERIAL for one file and is what `--cores` then
/// plateaued on. A set of several files no longer runs it in one thread: see
/// `shard_set_parallel`, which reads the files concurrently and releases
/// what they read in file order, so the workers see exactly the sequence the
/// serial reader gave them. One file still means one reader — a pcap record's
/// length is only known from the record before it, so a single file cannot be
/// cut into pieces without first walking it.
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
                .with_xcid_headers(cfg.xcid_headers.clone())
                .with_leg_correlation_window_ms(cfg.leg_correlation_window_ms);
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

    // Read the set: open each pcap (gzip-transparent), apply any BPF, and for
    // each packet do the cheap host-pair peek + append to that worker's batch,
    // flushed to the worker when it fills — one channel hop per ~BATCH
    // packets.
    let mut progress = ReadProgress {
        count: 0,
        dropped: 0,
        unshardable: 0,
        clock: SweepClock::new(true),
    };
    let mut tally = crate::capture::file::ReadTally {
        given: paths.len(),
        ..crate::capture::file::ReadTally::default()
    };
    // One reader thread per file, capped at the worker count — but only where
    // that means anything. A single-file `-I` has ONE file and therefore one
    // reader whatever this says, so it stays in this thread rather than paying
    // for a queue and a dispatcher it cannot use; and a `--count` run keeps
    // the serial reader because "the first N packets of the set" is defined in
    // read order (see [`shard_set_parallel`]).
    let readers = paths.len().min(n);
    let read = if readers > 1 && capture_config.count.is_none() {
        shard_set_parallel(
            paths,
            capture_config,
            &txs,
            &mut progress,
            &mut tally,
            readers,
        )
    } else {
        shard_set(paths, capture_config, &txs, &mut progress, &mut tally)
    };
    // Reported before the error is propagated, and on every path out, exactly
    // as `capture_files` does it: a filter that fails against file twelve still
    // read eleven, and what reached the workers is what the operator has to be
    // told. This line was absent entirely from the `--cores` path, so the only
    // reader that can be pointed at a 27-file ring buffer and finish in a
    // reasonable time was also the only one that never said how much of it it
    // had actually read.
    tally.report(progress.count);
    read?;
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
    .with_xcid_headers(cfg.xcid_headers.clone())
    .with_leg_correlation_window_ms(cfg.leg_correlation_window_ms);
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
    final_sweep(&progress.clock, &mut ds);
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
        write_eth_pcap_at(dir, name, frames, 1_700_000_000)
    }

    /// The same, with the first record's timestamp chosen by the caller.
    ///
    /// A rotated capture set is ONE timeline cut into pieces, so a fixture that
    /// restarts the clock in every file is not one: the members would overlap
    /// in time, and a test about reading them in order would be asserting
    /// against an input no capture rotation produces.
    #[cfg(feature = "native")]
    fn write_eth_pcap_at(
        dir: &std::path::Path,
        name: &str,
        frames: &[Vec<u8>],
        first_ts: u32,
    ) -> std::path::PathBuf {
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
            rec.extend_from_slice(&(first_ts + i as u32).to_le_bytes()); // ts_sec
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

    /// The channel-fed entry point reports orphans from its merged stores too.
    ///
    /// `run_offline_parallel_file` is what `-I` reaches; this one is reached by
    /// `--multi-device`, and it merged and returned without sweeping just the
    /// same, so its orphan count disagreed with the single-threaded path's.
    /// The stream here is announced by no SDP, so the only correct answer is
    /// "orphaned" — and it is now correct without any sweep having run, which
    /// is the point: the count is derived from `associated_dialog` at read
    /// time, and merging cannot lose a flag that does not exist.
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
            "a stream no dialog claimed must be reported as an orphan by the \
             merged store"
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
            leg_correlation_window_ms: crate::sip::dialog_store::DEFAULT_LEG_CORRELATION_WINDOW_MS,
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

    // ── One reader thread per file ─────────────────────────────────

    /// One RTP frame: 12-byte header, `ssrc`, `seq`, and a fixed payload.
    #[cfg(feature = "native")]
    fn rtp_frame(ssrc: u32, seq: u16) -> Vec<u8> {
        let mut payload = vec![0x80, 0x00];
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&(160u32 * u32::from(seq)).to_be_bytes());
        payload.extend_from_slice(&ssrc.to_be_bytes());
        payload.extend_from_slice(&[0xaa; 160]);
        eth_ipv4_udp(40000, 40002, &payload)
    }

    /// EVERY file of a multi-file `-I` set is read, and every file's packets
    /// are counted against the run.
    ///
    /// Five files of five different lengths, each carrying its own SSRC, so
    /// the assertions name what came from where: a reader that dropped a file,
    /// read one twice, or read only the first would move the total AND lose a
    /// stream, and the per-stream provenance says which file went missing
    /// rather than only that the arithmetic no longer adds up.
    ///
    /// This is the test the parallel reader had to pass before it was worth
    /// measuring: `-I` routinely names a directory of rotated captures, and a
    /// reader that quietly reads some of them is a wrong answer that looks
    /// like a fast one.
    #[cfg(feature = "native")]
    #[test]
    fn every_file_of_a_multi_file_set_is_read_and_counted() {
        use crate::capture::CaptureConfig;
        let dir = tempfile::tempdir().expect("temp dir");
        let lengths = [7usize, 11, 13, 17, 19];
        let mut paths = Vec::new();
        for (i, len) in lengths.iter().enumerate() {
            let ssrc = 0x1000_0000 + i as u32;
            let frames: Vec<Vec<u8>> = (0..*len).map(|s| rtp_frame(ssrc, s as u16 + 1)).collect();
            paths.push(write_eth_pcap_at(
                dir.path(),
                &format!("rot.pcap{i}"),
                &frames,
                1_700_000_000 + (i as u32 * 1000),
            ));
        }

        let r = run_offline_parallel_file(&paths, &CaptureConfig::default(), pcfg(4))
            .expect("a set of five readable files must read");

        let total: usize = lengths.iter().sum();
        assert_eq!(
            r.packets_read, total as u64,
            "every file's packets must reach the run: {} of {total} read",
            r.packets_read
        );
        assert_eq!(
            r.stream_store.len(),
            lengths.len(),
            "one stream per file; a missing stream is a file that was never read"
        );
        let mut seen: Vec<(String, u64)> = r
            .stream_store
            .iter()
            .map(|s| {
                let source = s
                    .first_frame
                    .as_ref()
                    .expect("every stream must carry the file it was read from")
                    .source
                    .to_string();
                (source, s.packet_count)
            })
            .collect();
        seen.sort();
        let mut want: Vec<(String, u64)> = paths
            .iter()
            .zip(lengths.iter())
            .map(|(p, len)| (p.display().to_string(), *len as u64))
            .collect();
        want.sort();
        assert_eq!(
            seen, want,
            "each file must contribute exactly its own packets, attributed to \
             itself"
        );
    }

    /// A stream split across the files of a rotated set is delivered to its
    /// worker in CAPTURE order, so the order-derived metrics are the ones the
    /// serial reader produces.
    ///
    /// This is the guarantee the dispatcher exists for. Four files carry one
    /// stream's sequence numbers 1..200 in order; a reader that let file 3
    /// reach the worker before file 1 would not merely reorder the output, it
    /// would report loss that is not there — `RtpStream::update` counts a
    /// forward sequence gap as loss, so the jump from 50 to 101 is 50 packets
    /// "lost" and the backwards step afterwards is written off as reordering.
    ///
    /// Asserted twice over: against the serial reader's own answer for the
    /// same bytes, which is the property that matters, and against the
    /// absolute values, so the test still bites if the two paths ever stop
    /// being selected the way this test selects them.
    #[cfg(feature = "native")]
    #[test]
    fn a_stream_split_across_files_is_delivered_in_capture_order() {
        use crate::capture::CaptureConfig;
        let dir = tempfile::tempdir().expect("temp dir");
        let per_file = 50u16;
        let files = 4u16;
        let mut paths = Vec::new();
        for f in 0..files {
            let frames: Vec<Vec<u8>> = (0..per_file)
                .map(|i| rtp_frame(0x2233_4455, f * per_file + i + 1))
                .collect();
            paths.push(write_eth_pcap_at(
                dir.path(),
                &format!("rot.pcap{f}"),
                &frames,
                1_700_000_000 + u32::from(f) * u32::from(per_file),
            ));
        }
        let total = u64::from(per_file) * u64::from(files);

        let parallel = run_offline_parallel_file(&paths, &CaptureConfig::default(), pcfg(4))
            .expect("the set must read");
        // `--count` keeps the serial reader, because a budget shared across a
        // set only means anything read in order. A budget nothing can spend
        // therefore reads the same bytes the same way, one file after another,
        // which is exactly the reference this needs.
        let serial_cc = CaptureConfig {
            count: Some(u64::MAX),
            ..CaptureConfig::default()
        };
        let serial =
            run_offline_parallel_file(&paths, &serial_cc, pcfg(4)).expect("the set must read");

        for (label, r) in [("parallel", &parallel), ("serial", &serial)] {
            let s = r
                .stream_store
                .iter()
                .next()
                .unwrap_or_else(|| panic!("{label}: the fixture holds one RTP stream"));
            assert_eq!(
                s.packet_count, total,
                "{label}: every packet of the split stream must arrive"
            );
            assert_eq!(
                s.lost_packets, 0,
                "{label}: the sequence runs 1..{total} unbroken, so any loss \
                 reported is a file that reached the worker out of turn"
            );
            assert_eq!(
                s.last_seq,
                per_file * files,
                "{label}: the last packet the worker saw must be the last one \
                 in the capture"
            );
        }
        let (p, s) = (
            parallel.stream_store.iter().next().expect("one stream"),
            serial.stream_store.iter().next().expect("one stream"),
        );
        assert_eq!(
            (
                p.packet_count,
                p.lost_packets,
                p.last_seq,
                p.jitter.to_bits()
            ),
            (
                s.packet_count,
                s.lost_packets,
                s.last_seq,
                s.jitter.to_bits()
            ),
            "reading the set in parallel must produce the serial reader's \
             answer, bit for bit, for every metric the packet ORDER decides"
        );
    }

    /// A member of the set that cannot be opened is skipped and the rest of
    /// the set is still read — the parallel reader's copy of the rule the
    /// serial one has always had.
    ///
    /// Losing one file of a rotating capture directory being cleaned up
    /// underneath the run is bad; losing the other two because of it is worse.
    #[cfg(feature = "native")]
    #[test]
    fn a_missing_file_mid_set_does_not_take_the_rest_of_the_set_with_it() {
        use crate::capture::CaptureConfig;
        let dir = tempfile::tempdir().expect("temp dir");
        let first: Vec<Vec<u8>> = (0..9).map(|s| rtp_frame(0x3000_0001, s + 1)).collect();
        let last: Vec<Vec<u8>> = (0..5).map(|s| rtp_frame(0x3000_0002, s + 1)).collect();
        let paths = vec![
            write_eth_pcap_at(dir.path(), "rot.pcap0", &first, 1_700_000_000),
            dir.path().join("rot.pcap1-vanished"),
            write_eth_pcap_at(dir.path(), "rot.pcap2", &last, 1_700_001_000),
        ];

        let r = run_offline_parallel_file(&paths, &CaptureConfig::default(), pcfg(4))
            .expect("one unreadable member must not fail the whole set");
        assert_eq!(
            r.packets_read, 14,
            "the two readable files must be read in full"
        );
        assert_eq!(
            r.stream_store.len(),
            2,
            "both readable files' traffic must reach the workers"
        );
    }

    // ── The read-ahead ledger ──────────────────────────────────────

    /// Run `f` on a thread and report whether it finished promptly, so a test
    /// about blocking does not hang the suite when the answer is wrong.
    #[cfg(feature = "native")]
    fn finishes_promptly(f: impl FnOnce() + Send + 'static) -> bool {
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2)).is_ok()
    }

    /// The reader of the file being dispatched never waits on the RUNWAY, even
    /// with the runway entirely spent.
    ///
    /// Not an optimization: it is what makes the whole arrangement live. The
    /// dispatcher waits on the current file's reader, so a current reader that
    /// waited for a budget only the dispatcher can release would deadlock the
    /// run.
    #[cfg(feature = "native")]
    #[test]
    fn the_dispatched_files_reader_is_never_charged_the_runway() {
        let runway = std::sync::Arc::new(Runway::new(3, 0));
        let r = std::sync::Arc::clone(&runway);
        assert!(
            finishes_promptly(move || assert!(r.acquire(0, 1 << 20))),
            "the file being dispatched must be admitted with an empty runway, \
             or the run deadlocks the moment the readers ahead spend it"
        );
    }

    /// It is bounded all the same: it draws on the dispatch reserve, and waits
    /// when that is spent until the dispatcher forwards something.
    ///
    /// "Exempt from the runway" was briefly "unbounded", and the queue depth
    /// was the only thing holding it — a cap counted in BATCHES of any size.
    /// At `--cores 2`, where the workers rather than the reader are the
    /// bottleneck, that reader ran far enough ahead of a blocked dispatcher to
    /// take peak RSS from 170 MiB to 366 MiB on the 8-file set; with a
    /// 65535-byte snaplen the same queue is tens of gigabytes.
    #[cfg(feature = "native")]
    #[test]
    fn the_dispatched_files_reader_waits_when_its_reserve_is_spent() {
        let runway = std::sync::Arc::new(Runway::new(2, 0));
        assert!(
            runway.acquire(0, DISPATCH_RESERVE_BYTES),
            "an untouched reserve admits a batch the size of the whole reserve"
        );

        let waiting = std::sync::Arc::clone(&runway);
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            let admitted = waiting.acquire(0, 4096);
            let _ = tx.send(admitted);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "with the reserve spent, even the file being dispatched must wait: \
             the alternative is a reader that keeps reading into a queue \
             nobody is draining"
        );

        runway.release(4096);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(true),
            "forwarding a batch must hand its bytes back and wake the reader"
        );
    }

    /// The whole runway goes to the file the dispatcher will reach NEXT, and
    /// passes on only when that file is finished.
    ///
    /// Sharing it out is the policy this replaced: it left every file with a
    /// seventh of a head start instead of one file with all of it, and the
    /// read stage 0.677s instead of 0.583s.
    #[cfg(feature = "native")]
    #[test]
    fn only_the_next_file_in_line_may_spend_the_runway() {
        let runway = std::sync::Arc::new(Runway::new(4, 1000));
        assert!(runway.acquire(1, 400), "file 1 is next in line");

        let waiting = std::sync::Arc::clone(&runway);
        assert!(
            !finishes_promptly(move || {
                waiting.acquire(2, 100);
            }),
            "file 2 must not spend a budget file 1 has not finished with, \
             however much of it is free"
        );

        runway.retire(1);
        let claiming = std::sync::Arc::clone(&runway);
        assert!(
            finishes_promptly(move || assert!(claiming.acquire(2, 100))),
            "the claim must pass on the moment file 1 is finished"
        );
    }

    /// A batch bigger than the whole budget is admitted rather than refused
    /// forever.
    ///
    /// The packets are already read and no smaller batch is coming, so
    /// refusing is a deadlock, not a saving. A jumbo capture with a 64 KiB
    /// snaplen is the ordinary way to reach this.
    #[cfg(feature = "native")]
    #[test]
    fn a_batch_larger_than_the_whole_runway_is_still_admitted() {
        let runway = std::sync::Arc::new(Runway::new(2, 100));
        let r = std::sync::Arc::clone(&runway);
        assert!(
            finishes_promptly(move || assert!(r.acquire(1, 5_000_000))),
            "one oversized batch must go through, or a jumbo capture stops \
             dead"
        );
    }

    /// Every byte the reserve lends comes back when the batch is forwarded.
    ///
    /// The arithmetic half of the assertion at the end of
    /// [`shard_set_parallel`]. A reserve that gave back less than it lent
    /// shrinks by that much per batch and eventually stalls the reader of
    /// every file; one that gave back more would stop being a bound.
    #[cfg(feature = "native")]
    #[test]
    fn every_byte_the_dispatch_reserve_lends_comes_back() {
        let runway = Runway::new(2, 0);
        assert!(runway.acquire(0, 4096));
        assert!(runway.acquire(0, 8192));
        assert_eq!(
            runway.reserve_free(),
            DISPATCH_RESERVE_BYTES - 12288,
            "both batches must be charged while they are in flight"
        );
        runway.release(4096);
        runway.release(8192);
        assert_eq!(
            runway.reserve_free(),
            DISPATCH_RESERVE_BYTES,
            "forwarding both must restore the reserve exactly — no more, no less"
        );
    }

    /// Canceling releases a reader that is waiting for the runway.
    ///
    /// The run ends on the error paths too — a refused BPF filter, a reader
    /// that will never be reached — and every one of them joins the reader
    /// threads. A waiter nobody wakes turns a reported error into a hang.
    #[cfg(feature = "native")]
    #[test]
    fn cancelling_the_runway_releases_a_waiting_reader() {
        let runway = std::sync::Arc::new(Runway::new(4, 0));
        let waiting = std::sync::Arc::clone(&runway);
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            let admitted = waiting.acquire(2, 10);
            let _ = tx.send(admitted);
        });
        // The waiter must be parked before the cancel, or the test proves
        // nothing about waking one.
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "file 2 must be waiting: the budget is empty and it is not next in \
             line"
        );
        runway.cancel();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(2)),
            Ok(false),
            "a canceled runway must release its waiters, and tell them the \
             run is over rather than admitting them"
        );
    }
}
