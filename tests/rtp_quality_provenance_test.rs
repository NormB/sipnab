// SPDX-License-Identifier: MIT OR Apache-2.0

//! Provenance guards for the RTP quality figures.
//!
//! Every number sipnab prints beside an RTP stream is either something it
//! measured from the media it saw, or something a datagram asserted. These
//! tests exist because those two were once the same field, and the resulting
//! figures were wrong on real traffic in ways no synthetic test noticed: clean
//! streams reported at up to 50% loss with a MOS at the 1.0 floor, and a
//! 90 kHz video stream whose own measurement was 0.98 ms of jitter published
//! at 272,087 ms.
//!
//! The corpus-backed tests read `SIPNAB_CORPUS` and skip when it is unset, in
//! the same shape as
//! `capture::input_set::corpus_directory_resolves_in_timestamp_order`. They
//! assert properties, never values from any particular capture — nothing here
//! records an address, a port, a Call-ID or an SSRC from real traffic.
#![cfg(feature = "native")]

use std::path::PathBuf;

use parking_lot::RwLock;
use std::sync::Arc;

use sipnab::capture::parse::parse_packet;
use sipnab::pipeline::{self, PacketAction, PipelineOptions};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::rtcp::{RtcpPacket, XrBlock, is_rtcp_packet_type, looks_like_rtcp, parse_rtcp};
use sipnab::rtp::stream::StreamKey;
use sipnab::rtp::stream_store::{ClockGrounding, StreamStore};
use sipnab::sip::dialog_store::DialogStore;

#[path = "support/corpus.rs"]
mod corpus_support;
#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// Resolve the corpus in capture order, or `None` when `SIPNAB_CORPUS` is
/// unset. A ring buffer wraps, so filename order is not capture order.
fn corpus() -> Option<Vec<PathBuf>> {
    // `corpus_support::root` announces the skip on stderr, once per test
    // binary. The call sites below used to `eprintln!` it, which libtest
    // captures and discards on success — so these gates reported `ok` while
    // never touching a capture.
    let dir = corpus_support::root()?.to_string_lossy().into_owned();
    let files = sipnab::capture::input_set::resolve(
        std::slice::from_ref(&dir),
        &sipnab::capture::input_set::ResolveOptions::default(),
    )
    .unwrap_or_else(|e| panic!("resolve SIPNAB_CORPUS '{dir}': {e:#}"));
    Some(files.iter().map(|f| f.path.clone()).collect())
}

/// What one replay of the corpus observed about a stream. Deliberately holds
/// only quality figures — no identifiers from the capture.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Observed {
    lost_packets: u64,
    jitter: f64,
    packet_count: u64,
}

/// Replay `paths` through the real classification pipeline. When `apply_rtcp`
/// is false, RTCP packets are parsed and then dropped instead of being handed
/// to the store, which is the A/B that isolates their effect.
fn replay(paths: &[PathBuf], apply_rtcp: bool) -> Vec<(StreamKey, Observed, ClockGrounding)> {
    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = paths.to_vec();
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });

    let dialogs = Arc::new(RwLock::new(DialogStore::new(200_000, false)));
    let mut streams = StreamStore::new(200_000);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();

    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(120)) {
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        match pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt) {
            PacketAction::Sip { msg, sdp_links } => {
                dialogs.write().process_message(msg);
                for (ip, port, call_id, media) in &sdp_links {
                    streams.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
            PacketAction::Rtcp(pkts) => {
                if apply_rtcp {
                    streams.process_rtcp(&pkts, pp.timestamp);
                }
            }
            PacketAction::Rtp { hdr, .. } => streams.process_rtp(&pp, &hdr, pp.timestamp),
            PacketAction::None => {}
        }
    }
    let _ = reader.join();

    streams
        .iter()
        .map(|s| {
            (
                s.key.clone(),
                Observed {
                    lost_packets: s.lost_packets,
                    jitter: s.jitter,
                    packet_count: s.packet_count,
                },
                streams.clock_grounding(&s.key).expect("stream is tracked"),
            )
        })
        .collect()
}

/// On real traffic, RTCP must not change a single stream's measured loss or
/// jitter.
///
/// This is the property, not a threshold: whatever the corpus contains, the
/// two replays must agree stream for stream. Before the fix they did not — the
/// far end's `cumulative_lost` was written into `lost_packets` and then divided
/// by a locally observed packet count, which is not a loss rate under any
/// reading of RFC 3550 §6.4.1, and the report's jitter replaced the estimator's.
#[test]
fn corpus_rtcp_never_moves_the_measurement() {
    let Some(paths) = corpus() else {
        return;
    };
    let with_rtcp = replay(&paths, true);
    let without_rtcp: std::collections::HashMap<_, _> = replay(&paths, false)
        .into_iter()
        .map(|(k, o, _)| (k, o))
        .collect();

    assert!(
        with_rtcp.len() > 100,
        "corpus should yield a substantial number of streams, got {}",
        with_rtcp.len()
    );

    let mut divergent = 0usize;
    let mut worst = String::new();
    for (key, observed, _) in &with_rtcp {
        let Some(base) = without_rtcp.get(key) else {
            continue;
        };
        if base != observed {
            divergent += 1;
            if worst.is_empty() {
                // Shapes only; nothing that identifies the traffic.
                worst = format!(
                    "measured (lost={}, jitter={:.6}) became (lost={}, jitter={:.6}) \
                     over {} packets",
                    base.lost_packets,
                    base.jitter,
                    observed.lost_packets,
                    observed.jitter,
                    observed.packet_count
                );
            }
        }
    }
    assert_eq!(
        divergent,
        0,
        "RTCP changed the measured figures on {divergent} of {} streams — {worst}. \
         A remote report is evidence about the reporter's path segment over the \
         reporter's session; it belongs beside the measurement, not in it.",
        with_rtcp.len()
    );
}

/// On real traffic, a stream whose clock rate had to be guessed reports no
/// jitter measurement.
///
/// Jitter is an RTP timestamp difference divided by the clock rate. Guess the
/// divisor and the result is a different quantity — captured video with no
/// `a=rtpmap` produced jitter figures in the millions of milliseconds, which
/// is not an imprecise measurement of anything.
#[test]
fn corpus_ungrounded_clock_yields_no_jitter_measurement() {
    let Some(paths) = corpus() else {
        return;
    };
    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = paths.clone();
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });
    let dialogs = Arc::new(RwLock::new(DialogStore::new(200_000, false)));
    let mut streams = StreamStore::new(200_000);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();
    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(120)) {
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        match pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt) {
            PacketAction::Sip { msg, sdp_links } => {
                dialogs.write().process_message(msg);
                for (ip, port, call_id, media) in &sdp_links {
                    streams.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
            PacketAction::Rtp { hdr, .. } => streams.process_rtp(&pp, &hdr, pp.timestamp),
            _ => {}
        }
    }
    let _ = reader.join();

    let keys: Vec<StreamKey> = streams.iter().map(|s| s.key.clone()).collect();
    let mut assumed = 0usize;
    for key in &keys {
        match streams.clock_grounding(key).expect("tracked") {
            ClockGrounding::Assumed => {
                assumed += 1;
                assert_eq!(
                    streams.measured_jitter_ms(key),
                    None,
                    "a stream with no basis for its clock rate must report no \
                     jitter measurement, not the figure the placeholder produced"
                );
            }
            // A grounded clock rate may still be withheld while a restarted
            // estimator re-converges; what it must never do is claim a
            // measurement it does not have.
            _ => {
                if let Some(j) = streams.measured_jitter_ms(key) {
                    assert!(
                        j.is_finite() && j >= 0.0,
                        "jitter must be a finite ms value"
                    );
                }
            }
        }
    }
    eprintln!(
        "corpus: {} streams, {assumed} with an assumed clock rate",
        keys.len()
    );
}

/// Every RTCP datagram in the corpus is recognized as RTCP from its content,
/// whatever port it arrived on and whether or not sipnab decodes its type.
///
/// The counterexample this guards is real: RTCP XR (packet type 207) arriving
/// on the conventional odd RTCP port was rejected by a classifier that
/// enumerated only types 200-204, then accepted by the RTP path — `207 & 0x7F`
/// is payload type 79 — and registered as a media stream that did not exist.
/// The XR's block header at bytes 8-11 became its SSRC.
#[test]
fn corpus_rtcp_is_recognized_by_content_not_by_port() {
    let Some(paths) = corpus() else {
        return;
    };
    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = paths.clone();
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });

    let mut rtcp_seen = 0u64;
    let mut undecodable = 0u64;
    let mut types = std::collections::BTreeSet::new();
    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(120)) {
        let Ok(pp) = parse_packet(&pkt) else { continue };
        if !looks_like_rtcp(&pp.payload) {
            continue;
        }
        rtcp_seen += 1;
        types.insert(pp.payload[1]);
        assert!(
            is_rtcp_packet_type(pp.payload[1]),
            "looks_like_rtcp accepted a non-RTCP packet type"
        );
        if parse_rtcp(&pp.payload).is_empty() {
            undecodable += 1;
        }
    }
    let _ = reader.join();

    assert!(
        rtcp_seen > 0,
        "the corpus is expected to carry RTCP; none was recognized"
    );
    assert!(
        types.iter().any(|&pt| !(200..=204).contains(&pt)),
        "this guard is only meaningful if the corpus carries an RTCP type \
         outside 200-204 (XR is 207); saw types {types:?}"
    );
    eprintln!("corpus: {rtcp_seen} RTCP datagrams, types {types:?}, {undecodable} with no decoder");
}

/// On real traffic, no XR VoIP Metrics block about a tracked stream is
/// discarded.
///
/// RTCP XR was decoded in full — the far end's own R factor, MOS-LQ, MOS-CQ,
/// burst and gap densities, round-trip and end-system delay — and then dropped
/// on the floor by a `_ => continue` in `process_rtcp` that matched only SR and
/// RR. The docs meanwhile described the metrics as reaching the detail panel
/// and the report output. This is the property that closes that: replay the
/// corpus, count the VoIP Metrics blocks naming an SSRC the store tracks, and
/// require every one of those streams to be able to show it.
///
/// Asserts a property, not a threshold. Counts are printed, never values.
#[test]
fn corpus_xr_voip_metrics_are_retained_not_discarded() {
    let Some(paths) = corpus() else {
        return;
    };

    let (tx, rx) = sipnab::capture::channel::packet_channel(1 << 16);
    let owned = paths.clone();
    let reader = std::thread::spawn(move || {
        let cfg = sipnab::capture::CaptureConfig::default();
        let _ = sipnab::capture::file::capture_files(&owned, &cfg, tx, None);
    });

    let dialogs = Arc::new(RwLock::new(DialogStore::new(200_000, false)));
    let mut streams = StreamStore::new(200_000);
    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions::default();

    let mut xr_packets = 0u64;
    let mut voip_blocks = 0u64;
    let mut other_blocks = 0u64;
    // SSRCs named by a VoIP Metrics block, so the retention check runs against
    // exactly the streams a block was about.
    let mut reported_ssrcs = std::collections::BTreeSet::new();

    while let Ok(pkt) = rx.recv_timeout(std::time::Duration::from_secs(120)) {
        let Ok(pp) = parse_packet(&pkt) else { continue };
        let mut decrypt = pipeline::MediaDecrypt::default();
        match pipeline::classify_packet(&pp, &mut heuristic, &opts, &mut decrypt) {
            PacketAction::Sip { msg, sdp_links } => {
                dialogs.write().process_message(msg);
                for (ip, port, call_id, media) in &sdp_links {
                    streams.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
            PacketAction::Rtcp(pkts) => {
                for p in &pkts {
                    if let RtcpPacket::ExtendedReport(xr) = p {
                        xr_packets += 1;
                        for b in &xr.blocks {
                            match b {
                                XrBlock::VoipMetrics(m) => {
                                    voip_blocks += 1;
                                    reported_ssrcs.insert(m.ssrc);
                                }
                                _ => other_blocks += 1,
                            }
                        }
                    }
                }
                streams.process_rtcp(&pkts, pp.timestamp);
            }
            PacketAction::Rtp { hdr, .. } => streams.process_rtp(&pp, &hdr, pp.timestamp),
            PacketAction::None => {}
        }
    }
    let _ = reader.join();

    let keys: Vec<StreamKey> = streams.iter().map(|s| s.key.clone()).collect();
    let mut tracked_and_reported = 0u64;
    let mut retained = 0u64;
    for key in &keys {
        if !reported_ssrcs.contains(&key.ssrc) {
            continue;
        }
        tracked_and_reported += 1;
        if streams.remote_voip_metrics(key).is_some() {
            retained += 1;
        }
    }

    eprintln!(
        "corpus: {xr_packets} XR packets, {voip_blocks} VoIP Metrics blocks, \
         {other_blocks} other XR blocks, {} distinct reported SSRCs, \
         {tracked_and_reported} tracked streams a block was about, {retained} retained",
        reported_ssrcs.len()
    );

    assert!(
        voip_blocks > 0,
        "this guard is only meaningful if the corpus carries XR VoIP Metrics; \
         saw {xr_packets} XR packets carrying none"
    );
    assert_eq!(
        retained,
        tracked_and_reported,
        "every VoIP Metrics block naming a tracked stream must be retrievable; \
         {} were parsed and then discarded",
        tracked_and_reported - retained
    );
    assert!(
        tracked_and_reported > 0,
        "the corpus carries VoIP Metrics blocks but none named a tracked \
         stream — the SSRC index or the RTP path regressed"
    );
}

/// On real traffic, an endpoint's XR figures never become sipnab's.
///
/// The sibling of `corpus_rtcp_never_moves_the_measurement`, aimed squarely at
/// XR: for every stream the far end reported on, the number sipnab measured and
/// the number the endpoint claimed stay separately addressable, and the MOS
/// sipnab scores comes only from its own.
#[test]
fn corpus_xr_never_becomes_the_local_measurement() {
    let Some(paths) = corpus() else {
        return;
    };

    let with_rtcp = replay(&paths, true);
    let without = replay(&paths, false);
    let by_key: std::collections::HashMap<_, _> = without
        .iter()
        .map(|(k, o, g)| (k.clone(), (*o, *g)))
        .collect();

    let mut compared = 0u64;
    for (key, observed, grounding) in &with_rtcp {
        let Some((baseline, base_grounding)) = by_key.get(key) else {
            continue;
        };
        compared += 1;
        assert_eq!(
            observed, baseline,
            "RTCP — XR included — moved a measured figure"
        );
        assert_eq!(grounding, base_grounding, "RTCP moved a clock grounding");
    }

    eprintln!("corpus: {compared} streams compared with and without RTCP applied");
    assert!(
        compared > 0,
        "no stream was comparable across the two replays"
    );
}

/// A synthesised XR on an odd port, for the case where no corpus is available.
///
/// Pins the two halves of the classification hazard side by side: the payload
/// is unambiguously RTCP by content, and the RTP pre-filter — which looks only
/// at the version bits and `byte1 & 0x7F` — cannot tell. Classification must
/// therefore ask the RTCP module first; a port-parity test that also narrows
/// the accepted packet types answers "not RTCP" for every type it does not
/// list.
#[test]
fn an_xr_datagram_is_rtcp_and_the_rtp_prefilter_cannot_tell() {
    // V=2, PT=207, length 0xF8 words → (0xF8 + 1) * 4 = 996 bytes, then the
    // originator SSRC and a Receiver Reference Time block (BT=4, 2 words).
    let mut xr = vec![0x80u8, 207, 0x00, 0xF8];
    xr.extend_from_slice(&0x4142_4344u32.to_be_bytes());
    xr.extend_from_slice(&[4, 0, 0, 2]);
    xr.resize(1000, 0);

    assert!(looks_like_rtcp(&xr), "content says RTCP");
    assert!(
        !parse_rtcp(&xr).is_empty(),
        "and it decodes, so nothing is lost by routing it to the RTCP path"
    );
    assert!(
        sipnab::rtp::is_rtp_packet(&xr),
        "the RTP pre-filter admits it — this is why the RTCP question must be \
         asked first, and asked about the whole RFC 5761 packet-type range"
    );
    let hdr = sipnab::rtp::parser::parse_rtp_header(&xr).expect("parses as a 12-byte header");
    assert_eq!(hdr.payload_type, 79, "207 & 0x7F");
    assert_eq!(
        hdr.ssrc, 0x0400_0002,
        "the XR's first block header read as an SSRC — the phantom stream's identity"
    );
}

// ── Burst and gap DURATIONS are measured, not assumed ────────────────

/// Burst and gap durations sipnab reports for the first stream of the first
/// dialog, off `--json-dialogs`.
fn reported_burst_and_gap(pcap: &std::path::Path) -> (f64, f64) {
    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8 path"),
            "--json-dialogs",
            "--no-config",
        ],
        Some("error"),
    );
    assert_eq!(code, Some(0), "sipnab must exit cleanly; stderr:\n{stderr}");
    let line = stdout
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("the fixture must produce one dialog; stdout:\n{stdout}"));
    let v: serde_json::Value = serde_json::from_str(line).expect("valid dialog JSON");
    let bg = &v["streams"][0]["burst_gap"];
    (
        bg["burst_duration_ms"]
            .as_f64()
            .expect("the linked stream must carry a burst/gap analysis"),
        bg["gap_duration_ms"].as_f64().expect("and a gap duration"),
    )
}

/// Burst and gap durations follow the stream's OWN packetization interval.
///
/// `burst_gap_analysis` charged every frame a flat 20 ms while the ptime
/// inference one module away — already validated against 5..=200 ms for the
/// ptime-asymmetry detector — sat unused. On G.729 at 30 ms that understates
/// every reported burst and gap by a third, and on a satellite trunk at 40 ms
/// by half: a three-second outage published as two.
///
/// Three identical captures differing only in cadence, so the assertion is a
/// RATIO and cannot be satisfied by any fixed number that happens to match.
#[test]
fn burst_and_gap_durations_follow_the_streams_own_packetization() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut measured = Vec::new();
    for ptime in [20u64, 30, 40] {
        let pcap = dir.path().join(format!("lossy-{ptime}ms.pcap"));
        pcap_build::write_pcap_at(
            &pcap,
            &pcap_build::sdp_call_with_lossy_rtp_at(&format!("ptime-{ptime}"), 400, 3, ptime),
            1,
        );
        measured.push((ptime, reported_burst_and_gap(&pcap)));
    }

    let (_, (base_burst, base_gap)) = measured[0];
    assert!(
        base_burst > 0.0 && base_gap > 0.0,
        "the 20 ms fixture must report a burst AND a gap, or the ratios below \
         prove nothing"
    );
    for &(ptime, (burst, gap)) in &measured[1..] {
        let want = ptime as f64 / 20.0;
        for (label, got, base) in [("burst", burst, base_burst), ("gap", gap, base_gap)] {
            let ratio = got / base;
            assert!(
                (ratio - want).abs() < 0.05,
                "a {ptime} ms stream must report {want:.2}x the {label} duration \
                 of the same losses at 20 ms, got {ratio:.2}x ({got} vs {base}) — \
                 a flat 20 ms assumption reports 1.00x and understates the outage \
                 by {:.0}%",
                (1.0 - 20.0 / ptime as f64) * 100.0
            );
        }
    }
}

/// The SDP `a=ptime` reaches the stream, in both orderings of SDP and RTP.
///
/// The declaration is worth nothing if it stops at a struct field nothing
/// fills. Both orderings are asserted because the store learns an endpoint by
/// two different routes — `link_endpoint` enriches streams that already exist,
/// and `resolve_from_sdp` fills one created afterwards — and a value wired
/// into only one is a setting honoured on offline replay and dropped on live
/// capture, or the reverse.
#[test]
fn the_sdp_ptime_reaches_the_stream_in_both_orderings() {
    use sipnab::capture::parse::{ParsedPacket, TransportProto};
    use sipnab::rtp::parser::RtpHeader;
    use sipnab::sip::sdp::{SdpDirection, SdpMedia};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let media_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let far_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let pp = ParsedPacket {
        frame: None,
        timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
        src_addr: media_ip,
        dst_addr: far_ip,
        src_port: 20000,
        dst_port: 30000,
        transport: TransportProto::Udp,
        payload: vec![0u8; 172].into(),
        ip_id: None,
        tcp_seq: None,
        tcp_flags: None,
        fragment_offset: None,
        more_fragments: false,
        ip_protocol: 17,
        from_hep: false,
    };
    let hdr = RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 8,
        sequence: 1,
        timestamp: 0,
        ssrc: 0x5151_5151,
        payload_offset: 12,
    };
    let media = SdpMedia {
        media_type: "audio".into(),
        port: 20000,
        proto: "RTP/AVP".into(),
        formats: vec!["8".into()],
        connection: None,
        direction: SdpDirection::SendRecv,
        rtpmap: Vec::new(),
        fmtp: Vec::new(),
        ptime: Some(30),
        crypto: Vec::new(),
        ice_candidates: Vec::new(),
        rtcp_mux: false,
        rtcp_port: None,
    };
    let key = StreamKey {
        ssrc: hdr.ssrc,
        src: SocketAddr::new(media_ip, 20000),
        dst: SocketAddr::new(far_ip, 30000),
    };

    // RTP first, SDP after — the offline-replay ordering.
    let mut store = StreamStore::new(16);
    store.process_rtp(&pp, &hdr, pp.timestamp);
    assert_eq!(
        store.get(&key).and_then(|s| s.sdp_ptime_ms),
        None,
        "no SDP has been seen yet, or this case proves nothing"
    );
    store.link_to_dialog_with_sdp(media_ip, 20000, "ptime-order-a", &media);
    assert_eq!(
        store.get(&key).and_then(|s| s.sdp_ptime_ms),
        Some(30),
        "a=ptime:30 must reach a stream that already existed when the SDP arrived"
    );

    // SDP first, RTP after — the live-capture ordering.
    let mut store = StreamStore::new(16);
    store.link_to_dialog_with_sdp(media_ip, 20000, "ptime-order-b", &media);
    store.process_rtp(&pp, &hdr, pp.timestamp);
    assert_eq!(
        store.get(&key).and_then(|s| s.sdp_ptime_ms),
        Some(30),
        "a=ptime:30 must reach a stream created after its SDP"
    );
}

/// A stream too short to measure its own cadence falls back to the SDP
/// `a=ptime`, and only then to the shipped 20 ms.
///
/// The order is the claim: a measurement beats a declaration because a
/// declaration can be stale, and a declaration beats a guess because the
/// endpoints agreed on it. Asserted on the stream rather than through the
/// binary because "too short to measure" means a one-packet stream, which
/// carries no losses for a burst/gap analysis to report.
#[test]
fn a_stream_too_short_to_measure_uses_the_declared_ptime() {
    use sipnab::rtp::parser::RtpHeader;
    use sipnab::rtp::stream::RtpStream;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let key = StreamKey {
        ssrc: 0x4242_4242,
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 20000),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000),
    };
    let hdr = RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: false,
        payload_type: 18,
        sequence: 1,
        timestamp: 0,
        ssrc: key.ssrc,
        payload_offset: 12,
    };
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid");
    let mut s = RtpStream::new(key, &hdr, at);

    assert_eq!(
        s.inferred_ptime_ms(),
        None,
        "one packet cannot be measured, or this test proves nothing"
    );
    assert_eq!(
        s.ptime_ms(),
        20.0,
        "with nothing measured and nothing declared, the shipped guess stands"
    );

    s.sdp_ptime_ms = Some(30);
    assert_eq!(
        s.ptime_ms(),
        30.0,
        "the SDP a=ptime the endpoints agreed on beats the shipped guess"
    );

    // Now give it a measurable 40 ms cadence: the measurement must win over
    // the declaration, which is the half a stale `a=ptime` would otherwise
    // silently decide.
    for seq in 2..=11u16 {
        let next = RtpHeader {
            sequence: seq,
            timestamp: u32::from(seq - 1) * 320,
            ..hdr.clone()
        };
        s.update(
            &next,
            at + chrono::Duration::milliseconds(40 * i64::from(seq - 1)),
            160,
        );
    }
    assert_eq!(s.inferred_ptime_ms(), Some(40));
    assert_eq!(
        s.ptime_ms(),
        40.0,
        "a measurement off the wire must beat a declaration that can be stale"
    );
}
