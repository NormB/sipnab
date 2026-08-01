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
use sipnab::rtp::rtcp::{is_rtcp_packet_type, looks_like_rtcp, parse_rtcp};
use sipnab::rtp::stream::StreamKey;
use sipnab::rtp::stream_store::{ClockGrounding, StreamStore};
use sipnab::sip::dialog_store::DialogStore;

/// Resolve the corpus in capture order, or `None` when `SIPNAB_CORPUS` is
/// unset. A ring buffer wraps, so filename order is not capture order.
fn corpus() -> Option<Vec<PathBuf>> {
    let dir = std::env::var("SIPNAB_CORPUS").ok()?;
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
                    streams.process_rtcp(&pkts);
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
        eprintln!("SIPNAB_CORPUS not set — skipping");
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
        eprintln!("SIPNAB_CORPUS not set — skipping");
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
        eprintln!("SIPNAB_CORPUS not set — skipping");
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
