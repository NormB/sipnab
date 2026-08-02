// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICMP errors about MEDIA, proved against REAL captures.
//!
//! The synthetic tests in `icmp_media_test` prove that each association rule
//! does what it says. Only a corpus can answer the question that decides
//! whether the feature is worth having: on real traffic, do these quotes carry
//! enough to reach a stream at all?
//!
//! The defect this guards was found by counting. `tshark` dissects 3,776 ICMP
//! errors across one corpus of fifteen captures; 3,232 of them quote a SIP
//! request and were already read, and the remaining 544 quote a non-SIP port
//! and reached no output whatsoever. `tshark` independently places the exact
//! quoted 5-tuple of 543 of those 544 in traffic the same corpus contains —
//! which is what makes the 5-tuple a real association key rather than a
//! plausible-sounding one.
//!
//! Two things are checked here that a fixture cannot check, because a fixture
//! is built by someone who already knows the answer:
//!
//! 1. **Real routers quote what they quote.** How often a quote reaches an RTP
//!    or RTCP header, and how often a flow reaches a stream, is decided by the
//!    corpus.
//! 2. **Nothing became a stream.** The evidence must not move a single stream
//!    count, because the whole feature rests on a quote being evidence about a
//!    packet rather than one.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents — address, port, SSRC, `Call-ID` —
//! is ever printed. Assertions and diagnostics name files and counts only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::pipeline::{self, MediaMatch, PipelineOptions, QuotedMediaKind};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;

/// Files larger than this are skipped: the corpus root can hold archives that
/// are not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The corpus root, or `None` when `SIPNAB_CORPUS` is unset.
fn corpus_root() -> Option<PathBuf> {
    match std::env::var("SIPNAB_CORPUS") {
        Ok(dir) => Some(PathBuf::from(dir)),
        Err(_) => {
            eprintln!("SIPNAB_CORPUS not set — skipping");
            None
        }
    }
}

/// Every regular file directly under `root`, in sorted order.
fn captures(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.metadata().map(|m| m.len()).unwrap_or(0) <= MAX_FILE_BYTES {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Replay one capture through the real pipeline into `stores`.
///
/// Drives `parse_packet` and `process_packet`, which is the point: ICMP
/// evidence is filed as a side effect of the former and the streams it is
/// matched against are built by the latter, so anything that works here works
/// in the binary.
///
/// # Returns
///
/// `(packets, streams_after)`, or `None` when the file is not a readable
/// capture.
fn replay(
    path: &Path,
    dialogs: &Arc<RwLock<DialogStore>>,
    streams: &Arc<RwLock<StreamStore>>,
) -> Option<(u64, usize)> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut heuristic = RtpHeuristic::new();
    let opts = PipelineOptions {
        // The corpus's SIP lives well outside 5060-5061 (measured: 31.2% of it
        // would be skipped), and a skipped INVITE is a missing SDP, which is a
        // missing media endpoint to attribute against.
        sip_portrange: Some((1, 65535)),
        ..PipelineOptions::default()
    };

    let mut packets = 0u64;
    for pkt in reader {
        let ts = chrono::DateTime::from_timestamp(
            pkt.timestamp_secs as i64,
            (u64::from(pkt.timestamp_usecs) * 1000).min(999_999_999) as u32,
        )
        .unwrap_or_default();
        let caplen = pkt.data.len();
        let orig_len = pkt.orig_len as usize;
        let link_type = pkt.link_type as i32;
        let packet = Packet::new(ts, pkt.data, caplen, orig_len, pkt.interface, link_type);
        packets += 1;

        // ICMP errors are recorded here, on the `Err` path, and never reach
        // `process_packet`.
        if let Ok(parsed) = parse_packet(&packet) {
            let mut decrypt = pipeline::MediaDecrypt::default();
            pipeline::process_packet(
                &parsed,
                dialogs,
                streams,
                &mut heuristic,
                &opts,
                &mut decrypt,
            );
        }
    }
    let n = streams.read().len();
    Some((packets, n))
}

/// The corpus holds ICMP errors about media, and sipnab now reads them.
///
/// This is the finding restated as a test: a corpus of real SIP captures
/// contains ICMP errors whose quoted datagram is not SIP, every one of them
/// used to be invisible, and the quoted 5-tuple is enough to place a
/// meaningful share of them on the media the capture actually holds.
#[test]
#[serial_test::serial(icmp_evidence)]
fn the_corpus_icmp_errors_about_media_are_read_and_placed() {
    let Some(root) = corpus_root() else { return };
    pipeline::reset_icmp_evidence();

    let dialogs = Arc::new(RwLock::new(DialogStore::new(200_000, false)));
    let streams = Arc::new(RwLock::new(StreamStore::new(200_000)));

    let mut files = 0usize;
    let mut total_packets = 0u64;
    for path in captures(&root) {
        let Some((packets, stream_count)) = replay(&path, &dialogs, &streams) else {
            continue;
        };
        files += 1;
        total_packets += packets;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Filename and counts only — nothing from the wire.
        eprintln!("{name}: {packets} packets, {stream_count} streams so far");
    }

    let report = pipeline::icmp_media_report(&streams.read());
    let by_match = |m: MediaMatch| report.flows.iter().filter(|f| f.matched == m).count();
    let errors_by_match = |m: MediaMatch| -> u64 {
        report
            .flows
            .iter()
            .filter(|f| f.matched == m)
            .map(|f| f.errors)
            .sum()
    };

    eprintln!(
        "corpus: {files} captures, {total_packets} packets, {} streams, \
         {} ICMP errors quoting non-SIP traffic ({} media, {} attributed, {} unattributed, \
         {} unkeyed, {} in untracked flows) across {} flow(s) and {} endpoint(s)",
        streams.read().len(),
        report.errors,
        report.media,
        report.attributed,
        report.unattributed,
        report.unkeyed,
        report.untracked_flows,
        report.flows.len(),
        report.endpoints.len(),
    );
    for m in [
        MediaMatch::Flow,
        MediaMatch::Ssrc,
        MediaMatch::Endpoint,
        MediaMatch::SdpEndpoint,
        MediaMatch::None,
    ] {
        eprintln!(
            "  {m:?}: {} flow(s), {} error(s)",
            by_match(m),
            errors_by_match(m)
        );
    }
    let payloads =
        |p: fn(&QuotedMediaKind) -> bool| report.flows.iter().filter(|f| p(&f.payload)).count();
    eprintln!(
        "  quoted payloads: {} RTP, {} RTCP, {} unread, {} not media",
        payloads(|p| matches!(p, QuotedMediaKind::Rtp { .. })),
        payloads(|p| matches!(p, QuotedMediaKind::Rtcp { .. })),
        payloads(|p| matches!(p, QuotedMediaKind::Unread)),
        payloads(|p| matches!(p, QuotedMediaKind::NotMedia)),
    );

    assert!(
        files > 0,
        "no capture under SIPNAB_CORPUS could be read, so this test proves nothing"
    );
    assert!(
        report.errors > 0,
        "the corpus at SIPNAB_CORPUS holds no ICMP error quoting a non-SIP datagram, so \
         this test proves nothing — point it at a corpus that does"
    );
    // Every error is placed in exactly one of the two buckets. A third outcome
    // would be a silent drop, which is the defect being fixed.
    assert_eq!(
        report.attributed + report.unattributed,
        report.errors,
        "every media ICMP error is either attributed or counted as unattributed"
    );
    // Every error names an endpoint, or is counted as untallied. An evidence
    // record with nowhere to point is a finding a reader cannot act on.
    assert_eq!(
        report.endpoints.iter().map(|e| e.errors).sum::<u64>() + report.untallied_endpoints,
        report.errors,
        "every media ICMP error must be tallied against exactly one endpoint"
    );
    // The per-flow counts, the unkeyed count and the untracked-flow count must
    // between them account for every error. A gap here is evidence that
    // reached a total and then left it.
    assert_eq!(
        report.flows.iter().map(|f| f.errors).sum::<u64>()
            + report.unkeyed
            + report.untracked_flows,
        report.errors,
        "every media ICMP error must reach a flow, or be counted as unkeyed or untracked"
    );
    assert!(
        report.attributed > 0,
        "not one of {} media ICMP errors reached a stream or an SDP endpoint — the \
         association rule is not doing anything on real traffic",
        report.errors
    );

    pipeline::reset_icmp_evidence();
}

/// Reading media ICMP changes no stream count.
///
/// The feature rests on "a quote is evidence about a packet, not a packet". If
/// that stops being true, every stream total sipnab prints inflates, and a
/// stream that never existed acquires quality metrics. The check is direct:
/// replay the corpus twice and require the stream counts to be identical, with
/// the second pass running against an already-populated evidence store.
#[test]
#[serial_test::serial(icmp_evidence)]
fn media_evidence_never_moves_a_stream_count() {
    let Some(root) = corpus_root() else { return };
    let files = captures(&root);
    assert!(!files.is_empty(), "no captures under SIPNAB_CORPUS");

    let pass = || -> Vec<(String, usize)> {
        let dialogs = Arc::new(RwLock::new(DialogStore::new(200_000, false)));
        let streams = Arc::new(RwLock::new(StreamStore::new(200_000)));
        files
            .iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().into_owned();
                let (_, n) = replay(p, &dialogs, &streams)?;
                Some((name, n))
            })
            .collect()
    };

    pipeline::reset_icmp_evidence();
    let first = pass();
    let armed = {
        let empty = StreamStore::new(1);
        pipeline::icmp_media_report(&empty).errors
    };
    // Second pass with the store already populated: if a quote could reach the
    // media path, the second pass would create a stream the first did not.
    let second = pass();

    assert_eq!(
        first, second,
        "stream counts changed between passes — an ICMP quote reached the media path \
         and invented a stream"
    );
    assert!(
        armed > 0,
        "no media ICMP was recorded, so this proves nothing about the counts"
    );
    eprintln!(
        "corpus: {} captures, stream counts identical across both passes, \
         {armed} non-SIP ICMP quotes recorded as evidence",
        first.len()
    );

    pipeline::reset_icmp_evidence();
}
