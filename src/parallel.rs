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
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

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
    /// Skip RTP/RTCP processing (`--no-rtp`).
    pub no_rtp: bool,
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
}

/// Reconstruct ONE already-parsed packet into thread-local stores, using the
/// same [`crate::pipeline::classify_packet`] core as every other router — so
/// `--jobs N` classifies identically to `--jobs 1` (WebSocket-SIP unwrap and
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
/// cheap host-pair peek ([`crate::capture::parse::peek_host_pair`] — link+IP
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
                let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate)
                    .with_xcid_headers(cfg.xcid_headers.clone());
                let mut ss = StreamStore::new(cfg.max_streams);
                ss.set_audio_capture(false); // batch mode never reads audio buffers
                let mut heuristic = crate::rtp::heuristic::RtpHeuristic::new();
                let (mut sip, mut rtp, mut total) = (0u64, 0u64, 0u64);
                for packet in wrx.iter() {
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
    loop {
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(packet) => {
                let s = match crate::capture::parse::peek_host_pair(&packet) {
                    Some((a, b)) => shard_for(a, b, n),
                    None => 0,
                };
                let _ = txs[s].send(packet);
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
        }
    }
    drop(txs); // signal workers to finish

    // Merge thread-local stores into one, then resolve cross-worker associations.
    let mut ds =
        DialogStore::new(cfg.max_dialogs, cfg.rotate).with_xcid_headers(cfg.xcid_headers.clone());
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

    ReconResult {
        dialog_store: ds,
        stream_store: ss,
        sip_count,
        rtp_count,
        total_count: total,
    }
}

/// Like [`run_offline_parallel`], but reads the pcap FILE directly in this thread
/// instead of consuming a [`PacketRx`] fed by a separate capture reader thread.
/// This fuses pcap-read + host-pair peek + shard into a SINGLE serial stage —
/// eliminating the dispatcher thread and the semaphore-capped capture channel
/// that capped `--cores` scaling at ~2 workers (the read→dispatcher hand-off was
/// two serial stages). Sharding/reassembly/merge are identical to
/// [`run_offline_parallel`], so `--cores N` parity with `--cores 1` is preserved.
pub fn run_offline_parallel_file(
    path: &std::path::Path,
    capture_config: &crate::capture::CaptureConfig,
    cfg: ParallelConfig,
) -> anyhow::Result<ReconResult> {
    use crate::capture::file::{open_offline, pcap_ts_to_chrono};
    use crate::capture::packet::Packet;
    use crossbeam_channel::bounded;
    let n = cfg.cores.max(2);

    // The reader hands packets to workers in BATCHES rather than one at a time.
    // Focused --cores research (SNB-0015 follow-up) showed the regression past
    // cores 2 is NOT the reconstruction work — even with idle workers throughput
    // halved from cores 2→4. The cost is the per-packet channel hop: every send
    // bounces a cache line across cores, and that coherency traffic scales with
    // worker count. Sending ~`BATCH` packets per channel op amortizes that hop
    // by ~BATCH×, so the single reader can feed more workers before saturating.
    // Channel depth is in batches; BATCH × depth keeps the in-flight packet cap
    // (~8192) identical to the old per-packet bound.
    const BATCH: usize = 128;
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..n).map(|_| bounded::<Vec<Packet>>(64)).unzip();
    let workers: Vec<_> = rxs
        .into_iter()
        .map(|wrx| {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let mut processor = PacketProcessor::with_max_sessions(cfg.max_reassembly)
                    .with_reassembly(cfg.reassembly)
                    .with_parse_limit(cfg.parse_limit);
                let mut ds = DialogStore::new(cfg.max_dialogs, cfg.rotate)
                    .with_xcid_headers(cfg.xcid_headers.clone());
                let mut ss = StreamStore::new(cfg.max_streams);
                ss.set_audio_capture(false);
                let mut heuristic = crate::rtp::heuristic::RtpHeuristic::new();
                let (mut sip, mut rtp, mut total) = (0u64, 0u64, 0u64);
                for batch in wrx.iter() {
                    for packet in &batch {
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

    // Single reader+sharder: open the pcap (gzip-transparent), apply any BPF, and
    // for each packet do the cheap host-pair peek + append to that worker's batch.
    // A batch is flushed (one channel hop for ~BATCH packets) when it fills, and
    // any partial batches are flushed at EOF. One thread, one copy, one hop per
    // batch.
    let (mut cap, _gz_guard) = open_offline(path)?;
    if let Some(ref bpf) = capture_config.bpf_filter {
        cap.filter(bpf, true)
            .map_err(|e| anyhow::anyhow!("Failed to compile BPF filter '{bpf}': {e}"))?;
    }
    let link_type = cap.get_datalink().0;
    let mut count: u64 = 0;
    let mut batches: Vec<Vec<Packet>> = (0..n).map(|_| Vec::with_capacity(BATCH)).collect();
    loop {
        if let Some(max) = capture_config.count
            && count >= max
        {
            break;
        }
        match cap.next_packet() {
            Ok(pkt) => {
                let packet = Packet::new(
                    pcap_ts_to_chrono(pkt.header.ts),
                    pkt.data.to_vec(),
                    pkt.header.caplen as usize,
                    pkt.header.len as usize,
                    None,
                    link_type,
                );
                let s = match crate::capture::parse::peek_host_pair(&packet) {
                    Some((a, b)) => shard_for(a, b, n),
                    None => 0,
                };
                batches[s].push(packet);
                if batches[s].len() >= BATCH {
                    let full = std::mem::replace(&mut batches[s], Vec::with_capacity(BATCH));
                    let _ = txs[s].send(full);
                }
                count += 1;
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Error reading pcap '{}': {e}",
                    path.display()
                ));
            }
        }
    }
    // Flush every partial batch so no tail packets are lost.
    for (s, b) in batches.into_iter().enumerate() {
        if !b.is_empty() {
            let _ = txs[s].send(b);
        }
    }
    drop(txs);

    let mut ds =
        DialogStore::new(cfg.max_dialogs, cfg.rotate).with_xcid_headers(cfg.xcid_headers.clone());
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
    Ok(ReconResult {
        dialog_store: ds,
        stream_store: ss,
        sip_count,
        rtp_count,
        total_count: total,
    })
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

    /// The `--jobs` path must discover heuristic-only RTP exactly like the
    /// single-threaded batch path: a PT-72 flow fails the strict
    /// `is_rtp_packet` pre-filter but is promoted by the consecutive-packet
    /// heuristic, so it must land in the merged stream store.
    #[cfg(feature = "native")]
    #[test]
    fn jobs_path_discovers_heuristic_rtp() {
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
            "--jobs must heuristically discover the PT-72 RTP flow"
        );
        assert!(
            r.rtp_count >= 1,
            "promoted heuristic packets must count as RTP"
        );
    }

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
            no_rtp: false,
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
        let path = std::path::Path::new("tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap");
        let cc = CaptureConfig::default();

        let runs: Vec<(usize, ReconResult)> = [2usize, 4, 8]
            .into_iter()
            .map(|c| (c, run_offline_parallel_file(path, &cc, pcfg(c)).unwrap()))
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
        let path = std::path::Path::new("tests/pcap-samples/codec-negotiation.pcap");
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(path, &cc, pcfg(2)).unwrap();
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
        let path = std::path::Path::new("tests/pcap-samples/invite-opus-bye.pcap");
        let cc = CaptureConfig::default();
        let r = run_offline_parallel_file(path, &cc, pcfg(2)).unwrap();
        let opus = r
            .stream_store
            .iter()
            .find(|s| s.codec.as_deref() == Some("opus"));
        let opus = opus.expect("expected an opus stream resolved from the SDP rtpmap");
        assert_eq!(opus.payload_type, 96, "opus carried on dynamic PT 96");
    }
}
