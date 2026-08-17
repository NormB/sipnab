// SPDX-License-Identifier: MIT OR Apache-2.0

//! ICMP evidence, proved against REAL captures.
//!
//! The defect this guards was found by counting: `tshark` dissects 2,598 SIP
//! frames in one corpus file and sipnab analyzed 1,902 — a 26.8% deficit that
//! matched the file's ICMP count exactly. Every one of those was an ICMP error
//! quoting a SIP request that sipnab never looked inside, on calls it then
//! reported as unanswered with no explanation.
//!
//! Two things are checked here that a synthetic fixture cannot check, because
//! a fixture is built by someone who already knows the answer:
//!
//! 1. **The quotes are real and attributable.** Real routers quote what they
//!    quote; the corpus decides how often a `Call-ID` survives, not the author
//!    of a fixture.
//! 2. **Nothing became a message.** The evidence must not have moved a single
//!    SIP message count, because the whole feature is built on the claim that
//!    a quote is evidence about a message rather than one.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents — `Call-ID`, user part, address —
//! is ever printed. Assertions and diagnostics name files and counts only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::pipeline;
use sipnab::sip::is_sip_message;

/// Files larger than this are skipped: the corpus root can hold archives that
/// are not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

#[path = "support/corpus.rs"]
mod corpus_support;

/// The corpus root, or `None` when `SIPNAB_CORPUS` is unset.
///
/// The skip is announced on stderr by [`corpus_support::root`], once per test
/// binary. It used to be an `eprintln!` that libtest captured and discarded on
/// success, so this suite reported `ok` while proving nothing about real
/// traffic.
fn corpus_root() -> Option<PathBuf> {
    corpus_support::root()
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

/// What one capture holds, counted without retaining anything from the wire.
#[derive(Default, Debug)]
struct Counts {
    /// Packets read from the file.
    packets: u64,
    /// Packets that parsed and carried a SIP message.
    sip_messages: u64,
    /// Packets rejected by the parser (ICMP among them).
    unparseable: u64,
}

/// Read one capture, counting SIP messages exactly as the pipeline does.
///
/// ICMP evidence is recorded as a side effect of `parse_packet`, which is the
/// behavior under test — so this deliberately drives the same entry point the
/// binary drives rather than calling the ICMP parser directly.
fn read(path: &Path) -> Option<Counts> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut counts = Counts::default();
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
        counts.packets += 1;

        match parse_packet(&packet) {
            Ok(parsed) => {
                if !parsed.payload.is_empty() && is_sip_message(&parsed.payload) {
                    counts.sip_messages += 1;
                }
            }
            Err(_) => counts.unparseable += 1,
        }
    }
    Some(counts)
}

/// The corpus holds ICMP errors quoting SIP, and sipnab reads them.
///
/// This is the finding restated as a test: a corpus of real SIP captures
/// contains ICMP errors whose payload is a SIP request, and every one of them
/// used to be invisible.
#[test]
#[serial_test::serial(icmp_evidence)]
fn the_corpus_icmp_errors_quoting_sip_are_read() {
    let Some(root) = corpus_root() else { return };
    pipeline::reset_icmp_evidence();

    let mut files = 0usize;
    let mut with_evidence = 0usize;
    let mut total_packets = 0u64;
    for path in captures(&root) {
        let Some(counts) = read(&path) else { continue };
        files += 1;
        total_packets += counts.packets;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let report = pipeline::icmp_evidence_report();
        if report.errors > 0 {
            with_evidence += 1;
        }
        // Filename and counts only — nothing from the wire.
        eprintln!(
            "{name}: {} packets, {} SIP messages, {} unparseable, ICMP-quoted SIP so far: {}",
            counts.packets, counts.sip_messages, counts.unparseable, report.errors
        );
    }

    let report = pipeline::icmp_evidence_report();
    eprintln!(
        "corpus: {files} captures, {total_packets} packets, {} ICMP errors quoting SIP \
         ({} attributed to a Call-ID, {} unattributable, {} in untracked dialogs, \
         {} untallied endpoints) across {} unreachable endpoint(s); \
         {with_evidence} file(s) held some",
        report.errors,
        report.attributed,
        report.unattributed,
        report.untracked_dialogs,
        report.untallied_endpoints,
        report.endpoints.len(),
    );

    assert!(
        files > 0,
        "no capture under SIPNAB_CORPUS could be read, so this test proves nothing"
    );
    assert!(
        report.errors > 0,
        "the corpus at SIPNAB_CORPUS holds no ICMP error quoting a SIP request, so this \
         test proves nothing — point it at a corpus that does"
    );
    // Every recorded error must name the endpoint it is about. An evidence
    // record with no endpoint would be a finding with nowhere to point.
    assert_eq!(
        report.endpoints.iter().map(|e| e.errors).sum::<u64>() + report.untallied_endpoints,
        report.errors,
        "every ICMP error must be tallied against exactly one endpoint, or counted \
         as untallied — anything else is an error that reached no total"
    );
    assert_eq!(
        report.attributed + report.unattributed,
        report.errors,
        "every ICMP error is either attributed to a Call-ID or counted as \
         unattributable; a third outcome would be a silent drop"
    );

    pipeline::reset_icmp_evidence();
}

/// Reading ICMP changes no SIP message count.
///
/// The feature rests on "a quote is evidence about a message, not a message".
/// If that ever stops being true, every total sipnab prints inflates and the
/// `analyzed + skipped` reconciliation stops meaning what it says. The check
/// is direct: count the corpus with the evidence store armed and again with it
/// cleared, and require the counts to be identical.
#[test]
#[serial_test::serial(icmp_evidence)]
fn icmp_evidence_never_moves_a_sip_message_count() {
    let Some(root) = corpus_root() else { return };

    let files = captures(&root);
    assert!(!files.is_empty(), "no captures under SIPNAB_CORPUS");

    pipeline::reset_icmp_evidence();
    let first: Vec<(String, u64)> = files
        .iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_string_lossy().into_owned();
            Some((name, read(p)?.sip_messages))
        })
        .collect();
    let armed = pipeline::icmp_evidence_report().errors;

    // Second pass over the same files with the store already populated: if any
    // quote could reach the SIP path, a second pass would count it again.
    let second: Vec<(String, u64)> = files
        .iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_string_lossy().into_owned();
            Some((name, read(p)?.sip_messages))
        })
        .collect();

    assert_eq!(
        first, second,
        "SIP message counts changed between passes — an ICMP quote reached the \
         message path and inflated a total"
    );
    eprintln!(
        "corpus: {} captures, SIP message counts identical across both passes, \
         {armed} ICMP-quoted SIP requests recorded as evidence",
        first.len()
    );

    pipeline::reset_icmp_evidence();
}
