// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two silent-loss fixes, held against REAL captures.
//!
//! The synthetic tests in `silent_sip_loss_test.rs` prove the behavior on
//! hand-built packets. These prove it on the traffic the defects were found
//! in, because both defects are of the kind a fixture only reproduces once you
//! already know the answer — nobody writes a `KDMQ` fixture before discovering
//! that `KDMQ` was being deleted.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents — Call-ID, user part, address,
//! SSRC, or a method token that would name a deployment's software — is ever
//! printed. Assertions carry counts and filenames only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::pipeline::{
    self, MediaDecrypt, PacketAction, PipelineOptions, classify_packet, portrange_skip_report,
};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::sip::method::SipMethod;

/// Files larger than this are skipped: the corpus root holds archives that are
/// not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The default `--portrange`, the one an operator gets by passing no flags.
const DEFAULT_RANGE: (u16, u16) = (5060, 5061);

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

/// Every regular file under `root`, recursively, in sorted order.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// What one capture yields when classified under `portrange`.
#[derive(Default)]
struct Tally {
    /// SIP messages classified (`PacketAction::Sip`).
    sip: u64,
    /// Of those, requests whose method is an extension token.
    extension_methods: u64,
    /// Distinct extension method tokens seen. Counted, never named — a
    /// vendor's private method names its software.
    distinct_extension_methods: usize,
}

/// Classify every packet of `path` under `portrange`, or `None` when the file
/// is not a capture this build can read.
///
/// # Arguments
///
/// * `path` — capture file to read.
/// * `portrange` — the SIP port gate; `None` classifies SIP on any port.
fn classify_file(path: &Path, portrange: Option<(u16, u16)>) -> Option<Tally> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let opts = PipelineOptions {
        // Media tracking off: these tests are about signaling, and the RTP
        // path is the slowest part of a 100 MB capture.
        no_rtp: true,
        sip_portrange: portrange,
        quiet_bad_parse: true,
        ..Default::default()
    };
    let mut heuristic = RtpHeuristic::new();
    let mut decrypt = MediaDecrypt::default();
    let mut tally = Tally::default();
    let mut seen_extensions = std::collections::BTreeSet::new();

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
        let Ok(parsed) = parse_packet(&packet) else {
            continue;
        };
        if let PacketAction::Sip { msg, .. } =
            classify_packet(&parsed, &mut heuristic, &opts, &mut decrypt)
        {
            tally.sip += 1;
            if let Some(SipMethod::Custom(token)) = msg.method.as_ref() {
                tally.extension_methods += 1;
                seen_extensions.insert(token.to_string());
            }
        }
    }
    tally.distinct_extension_methods = seen_extensions.len();
    Some(tally)
}

/// Requests using an RFC 3261 extension method are analyzed, not deleted.
///
/// Before the fix the first-line sniffer knew fourteen method names and every
/// other request failed it, so the message never reached the parser and
/// appeared in no output. It is not a corner case: the validation corpus holds
/// 11,623 of them.
///
/// The count is a ratchet against this corpus. More is fine — bump it. FEWER
/// means the method sniff narrowed again and real requests are being dropped
/// before anything can report them.
#[test]
#[serial_test::serial(portrange_skips)]
fn extension_method_requests_are_analysed_across_the_corpus() {
    let Some(root) = corpus_root() else { return };

    let mut files = 0usize;
    let mut total_sip = 0u64;
    let mut total_extension = 0u64;
    let mut distinct = 0usize;
    for path in walk(&root) {
        let Some(tally) = classify_file(&path, None) else {
            continue;
        };
        files += 1;
        total_sip += tally.sip;
        total_extension += tally.extension_methods;
        distinct = distinct.max(tally.distinct_extension_methods);
    }

    // Counts only — printed so a maintainer whose corpus differs can see what
    // to ratchet to without reading a packet.
    eprintln!(
        "corpus: {files} file(s), {total_sip} SIP messages, \
         {total_extension} extension-method request(s), \
         {distinct} distinct extension token(s)"
    );
    assert!(files > 0, "no readable capture under SIPNAB_CORPUS");
    assert!(
        total_extension > 0,
        "the corpus at SIPNAB_CORPUS holds no extension-method request, so \
         this test proves nothing about the defect it exists for — point it at \
         a capture that has one ({files} file(s), {total_sip} SIP messages read)"
    );
    assert!(
        total_extension >= 11_623,
        "extension-method requests analyzed dropped to {total_extension} across \
         {files} file(s) ({distinct} distinct method token(s), {total_sip} SIP \
         messages). More is fine — bump this. FEWER means the first-line sniff \
         narrowed again and real requests are being discarded before any output \
         format can name them."
    );
}

/// Nothing the `--portrange` gate discards goes unaccounted for.
///
/// The identity that has to hold on every capture:
///
/// > analyzed under the default range + reported as skipped
/// >   == analyzed with no port gate at all
///
/// That is the whole reporting fix stated as an equation. If the left side is
/// short, SIP is being dropped that the report does not mention — which is the
/// original defect, just quieter. If it is long, the report is inflating the
/// loss, which would send an operator chasing traffic that is not there.
///
/// It also measures the loss: the corpus is 32% skipped under the default
/// range, so this is not a theoretical accounting concern.
#[test]
#[serial_test::serial(portrange_skips)]
fn every_message_the_port_gate_discards_is_reported() {
    let Some(root) = corpus_root() else { return };

    let mut files = 0usize;
    let mut sum_gated = 0u64;
    let mut sum_skipped = 0u64;
    let mut sum_ungated = 0u64;
    for path in walk(&root) {
        pipeline::reset_portrange_skips();
        let Some(gated) = classify_file(&path, Some(DEFAULT_RANGE)) else {
            continue;
        };
        let skipped = portrange_skip_report();
        let Some(ungated) = classify_file(&path, None) else {
            continue;
        };
        files += 1;

        let name = path.file_name().unwrap_or_default().to_string_lossy();
        assert_eq!(
            gated.sip + skipped.messages,
            ungated.sip,
            "{name}: {} analyzed under --portrange {}-{} plus {} reported \
             skipped does not equal the {} analysable with no port gate — the \
             gate is losing SIP the report does not account for",
            gated.sip,
            DEFAULT_RANGE.0,
            DEFAULT_RANGE.1,
            skipped.messages,
            ungated.sip
        );
        assert_eq!(
            skipped.messages,
            skipped.ports.iter().map(|p| p.messages).sum::<u64>(),
            "{name}: the per-port breakdown does not add up to the total"
        );

        sum_gated += gated.sip;
        sum_skipped += skipped.messages;
        sum_ungated += ungated.sip;
    }

    let pct = 100.0 * sum_skipped as f64 / sum_ungated.max(1) as f64;
    eprintln!(
        "corpus: {files} file(s), {sum_gated} analyzed under --portrange \
         {}-{}, {sum_skipped} skipped and reported, {sum_ungated} analysable \
         ({pct:.1}% skipped)",
        DEFAULT_RANGE.0, DEFAULT_RANGE.1
    );
    assert!(files > 0, "no readable capture under SIPNAB_CORPUS");
    assert!(
        sum_skipped > 0,
        "the corpus at SIPNAB_CORPUS has no SIP outside --portrange {}-{}, so \
         this test proves nothing about the defect it exists for ({files} \
         file(s), {sum_ungated} SIP messages)",
        DEFAULT_RANGE.0,
        DEFAULT_RANGE.1
    );
    // 46,421 is what this corpus loses to the default range — 31% of its SIP.
    // More is fine — bump this. FEWER means the gate started skipping SIP
    // without counting it, and the default run is back to under-reporting
    // silently.
    assert!(
        sum_skipped >= 46_421,
        "the default --portrange skipped {sum_skipped} SIP message(s) across \
         {files} file(s) ({sum_gated} analyzed, {sum_ungated} analysable). More \
         is fine — bump this. FEWER means skipped SIP stopped being counted."
    );
}
