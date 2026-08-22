// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance-rule hit rates, measured against REAL captures.
//!
//! A rule that fires on nearly every dialog is a bug in the rule, not a
//! discovery about the traffic. sipnab has been here before: the scanner
//! signature raised 25,738 alerts on this corpus and 21 after it was fixed, and
//! the only reason anyone noticed was a hit-rate count against real captures.
//!
//! These tests hold every rule to a plausibility ceiling and print the whole
//! table, so adding a rule that fires on everything fails here rather than in
//! somebody's CI a month later.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to hold PII, so nothing
//! derived from a packet's contents — no address, no Call-ID, no user part, no
//! digest — is ever printed. Assertions and output name files, rule
//! identifiers and counts only.
#![cfg(feature = "native")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::pipeline::{MediaDecrypt, PacketAction, PipelineOptions, classify_packet};
use sipnab::rtp::heuristic::RtpHeuristic;
use sipnab::rtp::stream_store::StreamStore;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::lint::{Finding, LintConfig, Linter, ObservedMedia, ObservedRtcp, RULES};

/// Files larger than this are skipped: the corpus root holds archives that are
/// not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The share of dialogs a rule may trip before the rule itself is suspect.
///
/// Not a statement about how conformant SIP is. A rule above this either
/// encodes a mistaken reading of the RFC or fires on a condition the capture
/// cannot settle, and both look identical from the output alone. The number is
/// deliberately generous: real corpora do carry defects that most dialogs share
/// — every phone on one PBX runs one firmware — so the ceiling catches "fires
/// on everything", not "fires often".
const IMPLAUSIBLE_HIT_RATE: f64 = 0.95;

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

/// One capture, ingested the way the live pipeline ingests it.
struct Ingested {
    /// Dialogs built from the SIP messages.
    dialogs: DialogStore,
    /// RTP streams built from the media.
    streams: StreamStore,
    /// RTCP arrivals, counted per endpoint pair. The stream store folds
    /// reception reports into the stream they describe and keeps no record of
    /// where they landed, which is exactly what RFC 5761 §5.1.1 asks about.
    rtcp: BTreeMap<(SocketAddr, SocketAddr), u64>,
}

/// Read one capture through `classify_packet`, or `None` when the file is not
/// a capture this build can read.
///
/// Deliberately the pipeline's own classifier rather than a private reader: a
/// hit rate measured against a different ingestion path than the product uses
/// measures the harness.
fn ingest(path: &Path) -> Option<Ingested> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut out = Ingested {
        dialogs: DialogStore::new(100_000, false),
        streams: StreamStore::new(100_000),
        rtcp: BTreeMap::new(),
    };
    let mut heuristic = RtpHeuristic::default();
    let opts = PipelineOptions::default();

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
        let mut decrypt = MediaDecrypt::default();
        match classify_packet(&parsed, &mut heuristic, &opts, &mut decrypt) {
            PacketAction::None => {}
            PacketAction::Sip { msg, sdp_links } => {
                out.dialogs.process_message(msg);
                for (ip, port, call_id, media) in &sdp_links {
                    out.streams
                        .link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }
            PacketAction::RelayControl { sdp_links } => {
                sipnab::pipeline::apply_relay_control_links(
                    &mut out.streams,
                    &sdp_links,
                    parsed.input_origin,
                    parsed.timestamp,
                );
            }
            PacketAction::Rtcp(packets) => {
                out.streams.process_rtcp(&packets, parsed.timestamp);
                let key = (
                    SocketAddr::new(parsed.src_addr, parsed.src_port),
                    SocketAddr::new(parsed.dst_addr, parsed.dst_port),
                );
                *out.rtcp.entry(key).or_default() += 1;
            }
            PacketAction::Rtp { hdr, .. } => {
                out.streams.process_rtp(&parsed, &hdr, parsed.timestamp);
            }
        }
    }
    Some(out)
}

/// Findings for every dialog in one capture, as `(call index, findings)`.
///
/// The call index is a position, not an identifier: a Call-ID is user data.
fn lint_capture(ingested: &Ingested, config: &LintConfig) -> Vec<(usize, Vec<Finding>)> {
    let linter = Linter::new(config.clone());
    ingested
        .dialogs
        .iter()
        .enumerate()
        .map(|(i, dialog)| {
            let mut media =
                ObservedMedia::from_streams(ingested.streams.streams_for(&dialog.call_id));
            for ((src, dst), packets) in &ingested.rtcp {
                media = media.with_rtcp(ObservedRtcp {
                    src: *src,
                    dst: *dst,
                    packets: *packets,
                });
            }
            (i, linter.lint_dialog_with_media(dialog, &media))
        })
        .collect()
}

/// What one pass over the corpus measured.
struct CorpusScan {
    /// Dialogs tripping each rule, by rule identifier.
    hits: BTreeMap<&'static str, usize>,
    /// Dialogs linted.
    dialogs: usize,
    /// Captures that yielded at least one dialog.
    files: usize,
    /// Dialogs the media rules had at least one RTP stream to read.
    ///
    /// Reported because a zero hit rate on an observation rule means one of two
    /// very different things — the traffic is clean, or the rule saw no media —
    /// and the rule table alone cannot tell them apart.
    dialogs_with_media: usize,
    /// Dialogs whose signaling declared at least one media description.
    dialogs_with_sdp: usize,
    /// `Contact`, `From` and `To` header values carrying a bare URI with at
    /// least one parameter. The population the bracket rules draw from.
    bare_uris_with_params: usize,
}

/// Lint the whole corpus once and measure everything the tests below assert on.
fn scan_corpus() -> Option<CorpusScan> {
    let root = corpus_root()?;
    let config = LintConfig::new();
    let mut scan = CorpusScan {
        hits: BTreeMap::new(),
        dialogs: 0,
        files: 0,
        dialogs_with_media: 0,
        dialogs_with_sdp: 0,
        bare_uris_with_params: 0,
    };

    for path in walk(&root) {
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Some(ingested) = ingest(&path) else {
            continue;
        };
        if ingested.dialogs.is_empty() {
            continue;
        }
        scan.files += 1;
        for dialog in ingested.dialogs.iter() {
            if ingested
                .streams
                .streams_for(&dialog.call_id)
                .next()
                .is_some()
            {
                scan.dialogs_with_media += 1;
            }
            if dialog.messages.iter().any(|m| m.sdp().is_some()) {
                scan.dialogs_with_sdp += 1;
            }
            for msg in &dialog.messages {
                for name in ["Contact", "From", "To"] {
                    for value in msg.headers_by_name(name) {
                        if !value.contains('<') && value.contains(';') {
                            scan.bare_uris_with_params += 1;
                        }
                    }
                }
            }
        }
        for (_, findings) in lint_capture(&ingested, &config) {
            scan.dialogs += 1;
            let mut tripped: Vec<&'static str> = findings.iter().map(|f| f.rule_id).collect();
            tripped.sort_unstable();
            tripped.dedup();
            for id in tripped {
                *scan.hits.entry(id).or_default() += 1;
            }
        }
    }
    Some(scan)
}

/// Print the hit table and fail on any rule that fires on nearly everything.
///
/// The table is the deliverable. A rule at 100% has either misread its RFC or
/// asked a question the capture cannot answer, and both are indistinguishable
/// from a genuine epidemic until somebody reads the section.
#[test]
fn rule_hit_rates_are_plausible() {
    let Some(scan) = scan_corpus() else {
        return;
    };
    assert!(scan.dialogs > 0, "corpus produced no dialogs");

    eprintln!(
        "\ncorpus: {} readable captures, {} dialogs, {} with SDP, {} with observed media, \
         {} bare URIs carrying parameters\n",
        scan.files,
        scan.dialogs,
        scan.dialogs_with_sdp,
        scan.dialogs_with_media,
        scan.bare_uris_with_params
    );
    eprintln!("{:<48} {:>8} {:>8}", "rule", "dialogs", "rate");
    let mut implausible = Vec::new();
    for rule in RULES {
        let n = scan.hits.get(rule.id).copied().unwrap_or(0);
        let rate = n as f64 / scan.dialogs as f64;
        eprintln!("{:<48} {n:>8} {:>7.1}%", rule.id, rate * 100.0);
        if rate > IMPLAUSIBLE_HIT_RATE {
            implausible.push((rule.id, n, rate));
        }
    }
    eprintln!();

    assert!(
        implausible.is_empty(),
        "rules firing on more than {:.0}% of dialogs — investigate the rule, not the traffic: {implausible:?}",
        IMPLAUSIBLE_HIT_RATE * 100.0
    );
}

/// The observation rules had real media to read.
///
/// A zero hit rate on an observation rule is only evidence about the traffic if
/// the rule saw any traffic. Without this, a refactor that broke SDP-to-stream
/// linking would turn every media rule silent and the hit table would call it a
/// clean corpus.
#[test]
fn observation_rules_have_media_to_read() {
    let Some(scan) = scan_corpus() else {
        return;
    };
    assert!(
        scan.dialogs_with_media > 0,
        "no dialog in the corpus had linked RTP — the media rules measured nothing"
    );
    eprintln!(
        "{} of {} dialogs carried linked media ({} declared SDP)",
        scan.dialogs_with_media, scan.dialogs, scan.dialogs_with_sdp
    );
}

/// Linting the whole corpus never panics, and every finding carries a citation
/// that resolves to a rule in the catalog.
///
/// A finding whose `rule_id` is not in `RULES` cannot be suppressed, documented
/// or looked up, which makes it worse than no finding at all.
#[test]
fn every_finding_is_wellformed() {
    let Some(root) = corpus_root() else {
        return;
    };
    let config = LintConfig::new();
    let mut checked = 0usize;

    for path in walk(&root) {
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Some(ingested) = ingest(&path) else {
            continue;
        };
        for (index, findings) in lint_capture(&ingested, &config) {
            for f in &findings {
                let rule = sipnab::sip::lint::rule_by_id(f.rule_id).unwrap_or_else(|| {
                    panic!(
                        "{}: dialog {index} raised unknown rule {}",
                        path.display(),
                        f.rule_id
                    )
                });
                assert_eq!(f.rfc, rule.rfc, "{}: citation drift", f.rule_id);
                assert_eq!(f.section, rule.section, "{}: citation drift", f.rule_id);
                assert!(!f.observed.is_empty(), "{}: empty observation", f.rule_id);
                assert!(!f.expected.is_empty(), "{}: empty expectation", f.rule_id);
                assert!(
                    !f.explanation.is_empty(),
                    "{}: empty explanation",
                    f.rule_id
                );
                checked += 1;
            }
        }
    }
    eprintln!("{checked} findings checked across the corpus");
}

/// Suppression works against real traffic, not only against fixtures.
///
/// The corpus is where a suppression pattern that silences nothing, or
/// everything, would show up.
#[test]
fn suppression_reduces_corpus_findings() {
    let Some(root) = corpus_root() else {
        return;
    };
    let all = LintConfig::new();
    let quiet = LintConfig::new().suppress("OBS-*").suppress("SIP-*");

    let mut total_all = 0usize;
    let mut total_quiet = 0usize;
    for path in walk(&root) {
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
            continue;
        }
        let Some(ingested) = ingest(&path) else {
            continue;
        };
        total_all += lint_capture(&ingested, &all)
            .iter()
            .map(|(_, f)| f.len())
            .sum::<usize>();
        total_quiet += lint_capture(&ingested, &quiet)
            .iter()
            .map(|(_, f)| f.len())
            .sum::<usize>();
    }

    assert!(total_all > 0, "corpus raised no findings at all");
    assert!(
        total_quiet < total_all,
        "suppressing SIP-* and OBS-* changed nothing: {total_all} before, {total_quiet} after"
    );
}
