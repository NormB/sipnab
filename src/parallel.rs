//! Multi-core offline processing (`--jobs N`).
//!
//! sipnab's hot path is per-packet and was effectively single-threaded, so on a
//! many-core host it left most cores idle. RTP is ~93% of carrier traffic and is
//! independent per stream, so the work parallelizes well — *if* a flow's packets
//! always land on the same worker. This module provides the sharding function
//! and (with [`crate::rtp::stream_store`] / [`crate::sip::dialog_store`] merge)
//! the building blocks of a sharded worker pool: one reader → N workers, each
//! owning thread-local stores, merged at the end.
//!
//! Sharding is by the **direction-independent host pair**, so both directions of
//! a flow — and a call's RTP both ways — route to one worker (RTP/RTCP carry no
//! Call-ID, only a 5-tuple). A call's SIP between the same two hosts likewise
//! stays together for correct dialog reconstruction. When SIP signaling and its
//! media ride *different* host pairs (e.g. a proxy/SBC in the signaling path, or
//! the carrier corpus where SDP advertises a separate media IP), the SDP lands
//! on a different worker than the RTP — so dialog↔stream association is resolved
//! globally at merge ([`crate::rtp::stream_store::StreamStore::reassociate_all`]),
//! reproducing the single-threaded result.

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

use crate::capture::PacketProcessor;
use crate::capture::channel::PacketRx;
use crate::capture::parse::ParsedPacket;
use crate::rtp::parser::parse_rtp_header;
use crate::rtp::rtcp::parse_rtcp;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// Configuration for the offline parallel reconstruction engine.
#[derive(Clone)]
pub struct ParallelConfig {
    /// Number of worker threads (the dispatcher is additional).
    pub jobs: usize,
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
    /// Skip RTP/RTCP processing (`--no-rtp`).
    pub no_rtp: bool,
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
}

/// Reconstruct ONE already-parsed packet into thread-local stores. This mirrors
/// the reconstruction dispatch of the single-threaded path (RTCP → RTP → SIP),
/// minus the flag-gated extras (SRTP decrypt, DTMF, quality events, security
/// detectors, per-message output) that do not change dialog/stream
/// reconstruction. Keeping the exact same classify/parse/store calls is what
/// makes the merged result match `--jobs 1`.
fn reconstruct(
    pp: &ParsedPacket,
    ds: &mut DialogStore,
    ss: &mut StreamStore,
    cfg: &ParallelConfig,
    sip: &mut u64,
    rtp: &mut u64,
) {
    // RTCP first (odd port, version 2, PT 200-204).
    if crate::pipeline::is_rtcp_packet(&pp.payload, pp.dst_port) {
        if !cfg.no_rtp {
            let pkts = parse_rtcp(&pp.payload);
            if !pkts.is_empty() {
                ss.process_rtcp(&pkts);
            }
        }
        return;
    }
    // RTP.
    if !cfg.no_rtp
        && crate::rtp::is_rtp_packet(&pp.payload)
        && let Ok(hdr) = parse_rtp_header(&pp.payload)
    {
        ss.process_rtp(pp, &hdr, pp.timestamp);
        *rtp += 1;
        return;
    }
    // SIP (port-filtered, like the single path).
    if crate::pipeline::port_in_range(pp.src_port, pp.dst_port, cfg.portrange)
        && crate::sip::is_sip_message(&pp.payload)
        && let Ok(msg) = crate::sip::parser::parse_sip_bytes(
            &pp.payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            pp.transport,
        )
    {
        *sip += 1;
        if !cfg.no_dialog {
            ds.process_message(msg.clone());
            if let Some(sdp) = msg.sdp()
                && let Some(call_id) = msg.call_id()
            {
                for media in &sdp.media {
                    if let Some(addr) = crate::sip::sdp::effective_address(media, &sdp)
                        && let Ok(ip) = addr.parse::<std::net::IpAddr>()
                    {
                        ss.link_to_dialog_with_sdp(ip, media.port, call_id, media);
                    }
                }
            }
        }
    }
}

/// Offline multi-core reconstruction. A single dispatcher reads `rx`, runs the
/// (stateful, serial) L2/L3/L4 parse + reassembly via one `PacketProcessor`, and
/// shards each resulting `ParsedPacket` by host pair to one of `cfg.jobs` worker
/// threads. Each worker owns thread-local stores and does the parallel-friendly
/// work (SIP parse, RTP/RTCP classify, all store updates). At EOF the workers'
/// stores are merged and stream↔dialog association is resolved globally.
///
/// Returns the merged stores for report generation. Reconstruction only — see
/// [`reconstruct`]; advanced features stay on the single-threaded path.
pub fn run_offline_parallel(rx: PacketRx, cfg: ParallelConfig) -> ReconResult {
    use crossbeam_channel::bounded;
    let n = cfg.jobs.max(2);

    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| bounded::<ParsedPacket>(8192)).unzip();
    let workers: Vec<_> = rxs
        .into_iter()
        .map(|wrx| {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
                let mut ss = StreamStore::new(cfg.max_streams);
                ss.set_audio_capture(false); // batch mode never reads audio buffers
                let (mut sip, mut rtp) = (0u64, 0u64);
                for pp in wrx.iter() {
                    reconstruct(&pp, &mut ds, &mut ss, &cfg, &mut sip, &mut rtp);
                }
                (ds, ss, sip, rtp)
            })
        })
        .collect();

    // Dispatcher: serial parse + reassembly, shard parsed packets by host pair.
    let mut processor = PacketProcessor::with_max_sessions(cfg.max_reassembly);
    let mut total = 0u64;
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(packet) => {
                for pp in processor.process(&packet) {
                    total += 1;
                    let s = shard_for(pp.src_addr, pp.dst_addr, n);
                    let _ = txs[s].send(pp);
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
        }
    }
    drop(txs); // signal workers to finish

    // Merge thread-local stores into one, then resolve cross-worker associations.
    let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate);
    let mut ss = StreamStore::new(cfg.max_streams);
    let (mut sip_count, mut rtp_count) = (0u64, 0u64);
    for w in workers {
        if let Ok((wds, wss, wsip, wrtp)) = w.join() {
            ds.merge(wds);
            ss.merge(wss);
            sip_count += wsip;
            rtp_count += wrtp;
        }
    }
    ss.reassociate_all();

    ReconResult {
        dialog_store: ds,
        stream_store: ss,
        sip_count,
        rtp_count,
        total_count: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn jobs_one_is_always_shard_zero() {
        assert_eq!(shard_for(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1), 0);
        assert_eq!(shard_for(ip(1, 2, 3, 4), ip(5, 6, 7, 8), 0), 0);
    }

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

    #[test]
    fn shard_in_range() {
        for n in [2usize, 4, 7, 12] {
            for i in 0..500u32 {
                let s = shard_for(ip(10, 20, (i >> 8) as u8, i as u8), ip(10, 30, 0, 1), n);
                assert!(s < n, "shard {s} out of range for n={n}");
            }
        }
    }

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
}
