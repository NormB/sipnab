// SPDX-License-Identifier: MIT OR Apache-2.0

//! A behavioural scanner alert must be supported by an OUTCOME the capture
//! contains, proved against REAL captures.
//!
//! The rate and spread signals used to stand on their own, and neither
//! separates reconnaissance from operation. A SIP trunk sends OPTIONS
//! continuously because that is how each end learns the other is alive, and an
//! SBC fronting a hunt group reaches dozens of distinct extensions a second.
//! Measured on volume alone an ordinary eleven-second carrier trunk produced
//! 2719 detections across 14 peers — the carrier's own PBX and thirteen
//! customer desk phones — and every one of them was a fail2ban ban.
//!
//! Synthetic fixtures reproduce that only once you already know the answer,
//! because a hand-built message sequence carries whatever outcomes it was
//! given. Real traffic does not need to be told: these tests replay a corpus
//! and check every behavioural alert against an INDEPENDENT count of rejected
//! and unanswered probe transactions taken from the packets themselves. An
//! alert no outcome in the capture supports is a false positive, and with
//! `--kill-scanner` or a fail2ban jail behind it, a false positive is a banned
//! carrier.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents — address, Call-ID, user part,
//! `Via` branch — is ever printed. Assertions name files and counts only.
//!
//! The oracle is quadratic in the window, so budget minutes and use an
//! optimized profile:
//!
//! ```text
//! SIPNAB_CORPUS=/path/to/pcaps cargo test --all-features --profile profiling \
//!     --test scanner_signature_corpus_test -- --nocapture
//! ```
#![cfg(feature = "native")]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, Utc};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::security::ScannerDetector;
use sipnab::sip::{SipMessage, is_sip_message, parser::parse_sip};

/// Files larger than this are skipped: the corpus root holds archives that are
/// not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The detector's behavioural window, in seconds. Mirrors
/// `BEHAVIORAL_WINDOW_SECS`, which is private to the detector.
const WINDOW_SECS: i64 = 5;

/// Rejected probe transactions in one window at which a source reads as
/// probing. Mirrors `REJECTED_PROBE_MIN`.
const REJECTED_PROBE_MIN: usize = 5;

/// Unanswered probe transactions in one window at which a source reads as
/// sweeping, provided they are also the majority. Mirrors
/// `UNANSWERED_PROBE_MIN`.
const UNANSWERED_PROBE_MIN: usize = 5;

/// Evidence multiplier for a source that completed a registration or a call.
/// Mirrors `ESTABLISHED_EVIDENCE_FACTOR`.
const ESTABLISHED_EVIDENCE_FACTOR: usize = 4;

/// How long a probe must go unanswered before it counts. Mirrors
/// `PROBE_ANSWER_GRACE_MS`.
const PROBE_ANSWER_GRACE_MS: i64 = 500;

/// Response codes that answer a request without saying anything about whether
/// its sender belongs here. Mirrors `BENIGN_RESPONSE_CODES`.
const BENIGN_RESPONSE_CODES: &[u16] = &[401, 407, 408, 480, 486, 487, 488, 491, 600, 603];

/// Whether a final response tells its recipient no.
///
/// Restated here rather than exported: this is the test's own oracle, and an
/// oracle that calls the code under test proves nothing.
fn is_rejection(status: u16) -> bool {
    (400..700).contains(&status)
        && !(500..600).contains(&status)
        && !BENIGN_RESPONSE_CODES.contains(&status)
}

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

/// Every SIP message in one capture, in the order the file holds them, or
/// `None` when the file is not a capture this build can read.
fn sip_messages(path: &Path) -> Option<Vec<SipMessage>> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut out = Vec::new();
    for pkt in reader {
        let ts = DateTime::from_timestamp(
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
        if parsed.payload.is_empty() || !is_sip_message(&parsed.payload) {
            continue;
        }
        if let Ok(msg) = parse_sip(
            &parsed.payload,
            parsed.timestamp,
            parsed.src_addr,
            parsed.dst_addr,
            parsed.src_port,
            parsed.dst_port,
            parsed.transport,
        ) {
            out.push(msg);
        }
    }
    Some(out)
}

/// Every readable capture under the corpus root, as `(display name, messages)`.
///
/// The display name is the path relative to the corpus root — a filename, not
/// packet content, so it carries nothing from the wire. Captures holding no SIP
/// are dropped: they cannot support or refute anything here.
fn corpus_captures(root: &Path) -> Vec<(String, Vec<SipMessage>)> {
    let mut out = Vec::new();
    for path in walk(root) {
        if path.metadata().map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            continue;
        }
        let Some(msgs) = sip_messages(&path) else {
            continue;
        };
        if msgs.is_empty() {
            continue;
        }
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        out.push((name, msgs));
    }
    out
}

/// One probe transaction a source opened, and what became of it.
struct Probe {
    /// Capture time of the request that opened it.
    at: DateTime<Utc>,
    /// Capture time the first response of any kind came back, if one did.
    ///
    /// Any kind, including a provisional: the unanswered test asks whether
    /// anything is there, and a `100 Trying` settles that. Waiting for the
    /// FINAL response would count every ringing call as an unanswered probe.
    answered_at: Option<DateTime<Utc>>,
    /// A final response told the sender no.
    rejected: bool,
}

impl Probe {
    /// Whether this probe went unanswered for longer than the grace.
    ///
    /// An answer that arrives late is not an answer the detector can have had
    /// in hand, so the bound has to allow for one.
    fn unanswered(&self) -> bool {
        match self.answered_at {
            None => true,
            Some(t) => {
                t.signed_duration_since(self.at) > TimeDelta::milliseconds(PROBE_ANSWER_GRACE_MS)
            }
        }
    }
}

/// What one source did, taken straight off the packets.
#[derive(Default)]
struct SourceFacts {
    /// Probe transactions, in capture order.
    probes: Vec<Probe>,
    /// When the source first completed a registration or a call, if it did.
    ///
    /// The TIME matters, not just the fact. The detector learns this from the
    /// `2xx` as it passes, so an alert raised before that packet was judged
    /// against the ordinary bar and an oracle that applied
    /// [`ESTABLISHED_EVIDENCE_FACTOR`] to the whole capture would call a
    /// legitimate early alert unsupported.
    established_at: Option<DateTime<Utc>>,
}

/// Whether a request is one of the methods the detector treats as a probe.
fn is_probe_method(msg: &SipMessage) -> bool {
    msg.is_request
        && matches!(
            msg.method.as_ref().map(|m| m.as_str()),
            Some("REGISTER" | "OPTIONS" | "INVITE")
        )
}

/// Reduce a capture to per-source probe transactions and their outcomes.
///
/// A response travels back the way its request came, so the source it settles
/// is the response's DESTINATION, and the top `Via` branch it echoes names the
/// transaction.
fn source_facts(msgs: &[SipMessage]) -> HashMap<IpAddr, SourceFacts> {
    let mut facts: HashMap<IpAddr, SourceFacts> = HashMap::new();
    let mut index: HashMap<(IpAddr, String), usize> = HashMap::new();
    let window = TimeDelta::seconds(WINDOW_SECS);
    for msg in msgs {
        if msg.is_request {
            if !is_probe_method(msg) {
                continue;
            }
            let Some(branch) = msg.top_via_branch() else {
                continue;
            };
            let key = (msg.src_addr, branch.to_string());
            // A repeat of a branch is a retransmission — the same transaction —
            // but only while the detector's window still holds the original.
            // Devices do reuse a branch across keepalives, and the detector
            // clears its map every WINDOW_SECS, so a reuse further apart than
            // that is a second transaction to it as well.
            if let Some(&i) = index.get(&key)
                && facts
                    .get(&msg.src_addr)
                    .and_then(|f| f.probes.get(i))
                    .is_some_and(|p| msg.timestamp.signed_duration_since(p.at) < window)
            {
                continue;
            }
            let entry = facts.entry(msg.src_addr).or_default();
            index.insert(key, entry.probes.len());
            entry.probes.push(Probe {
                at: msg.timestamp,
                answered_at: None,
                rejected: false,
            });
            continue;
        }
        let Some(status) = msg.status_code else {
            continue;
        };
        if (200..300).contains(&status)
            && msg
                .cseq()
                .is_some_and(|(_, m)| matches!(m, "REGISTER" | "INVITE"))
        {
            facts
                .entry(msg.dst_addr)
                .or_default()
                .established_at
                .get_or_insert(msg.timestamp);
        }
        let Some(branch) = msg.top_via_branch() else {
            continue;
        };
        if let Some(&i) = index.get(&(msg.dst_addr, branch.to_string()))
            && let Some(p) = facts
                .get_mut(&msg.dst_addr)
                .and_then(|f| f.probes.get_mut(i))
        {
            p.answered_at.get_or_insert(msg.timestamp);
            p.rejected |= is_rejection(status);
        }
    }
    for f in facts.values_mut() {
        f.probes.sort_by_key(|p| p.at);
    }
    facts
}

/// Whether any window of `WINDOW_SECS` holds enough of an outcome to call this
/// source a prober.
///
/// This is an UPPER bound on the evidence the detector can have had, which is
/// what a soundness check needs: it ignores the answers to a source's other
/// transactions (which only ever reduce the unanswered count) and measures
/// over a sliding window (which only ever holds more than the detector's
/// tumbling one). Evidence below this bound is evidence the detector could not
/// legitimately have had.
fn has_probing_evidence(facts: &SourceFacts, alert_at: DateTime<Utc>) -> bool {
    let factor = match facts.established_at {
        Some(t) if t <= alert_at => ESTABLISHED_EVIDENCE_FACTOR,
        _ => 1,
    };
    let width = TimeDelta::seconds(WINDOW_SECS);
    let probes = &facts.probes;
    let mut lo = 0usize;
    for hi in 0..probes.len() {
        // Evidence the detector could not yet have seen proves nothing about
        // an alert it has already raised.
        if probes[hi].at > alert_at {
            break;
        }
        while probes[hi].at.signed_duration_since(probes[lo].at) >= width {
            lo += 1;
        }
        let window = &probes[lo..=hi];
        let rejected = window.iter().filter(|p| p.rejected).count();
        if rejected >= REJECTED_PROBE_MIN * factor {
            return true;
        }
        let unanswered = window.iter().filter(|p| p.unanswered()).count();
        if unanswered >= UNANSWERED_PROBE_MIN * factor && unanswered * 2 > window.len() {
            return true;
        }
    }
    false
}

/// Every behavioural scanner alert over the corpus names a source the capture
/// shows being refused, or sending into a hole.
///
/// A source is reported only if, somewhere in the capture, it really did
/// collect `REJECTED_PROBE_MIN` rejections or `UNANSWERED_PROBE_MIN`
/// unanswered probes — a majority of what it sent — inside one window, times
/// `ESTABLISHED_EVIDENCE_FACTOR` if it had already completed a registration or
/// a call with us. A `ua_pattern` alert is exempt: a signature match is a
/// property of one message and needs no window.
///
/// Gated on rate and spread alone this failed on the corpus: an eleven-second
/// trunk reported fourteen peers, every one of them answered, most of them
/// registered, and 94% of the traffic that convicted them was OPTIONS
/// keepalives.
#[test]
fn every_behavioural_alert_is_supported_by_an_outcome_in_the_capture() {
    let Some(root) = corpus_root() else {
        return;
    };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture with SIP in it — this test would \
         pass without proving anything"
    );

    let (mut files_with_alerts, mut alerts_total, mut sources_total) = (0usize, 0usize, 0usize);
    for (name, msgs) in &captures {
        let facts = source_facts(msgs);
        let mut det = ScannerDetector::new(&[]);
        let mut unsupported = 0usize;
        let mut alerts = 0usize;
        let mut reported: HashSet<IpAddr> = HashSet::new();
        for msg in msgs {
            let Some(alert) = det.check(msg) else {
                continue;
            };
            if alert.detection_method == "ua_pattern" {
                continue;
            }
            alerts += 1;
            reported.insert(alert.src_ip);
            let empty = SourceFacts::default();
            let f = facts.get(&alert.src_ip).unwrap_or(&empty);
            if !has_probing_evidence(f, msg.timestamp) {
                unsupported += 1;
            }
        }
        assert_eq!(
            unsupported, 0,
            "{name}: {unsupported} of {alerts} behavioural alerts name a source no \
             outcome in the capture refuses or ignores — the signature is back to \
             reporting peers for being busy"
        );
        alerts_total += alerts;
        sources_total += reported.len();
        if alerts > 0 {
            files_with_alerts += 1;
        }
    }
    eprintln!(
        "scanner signature: {} captures replayed, {files_with_alerts} raised behavioural \
         alerts, {alerts_total} alerts over {sources_total} sources, all supported by an \
         outcome in the capture",
        captures.len()
    );
}

/// A source every one of whose probes we answered is never reported.
///
/// The narrowest statement of the defect, and the one that names the traffic it
/// fired on. A trunk running OPTIONS keepalives gets a `200` to every one, and
/// under the old rate-and-spread signature that was exactly what convicted it:
/// the keepalives were the volume. This holds whatever the thresholds are and
/// whatever the windows do, so it cannot fail on a genuine detection the way a
/// majority test can — a compromised registered phone can be reported while
/// most of its traffic is still answered, but not while ALL of it is.
#[test]
fn a_source_we_answered_every_time_is_never_reported() {
    let Some(root) = corpus_root() else {
        return;
    };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture"
    );

    let mut checked = 0usize;
    for (name, msgs) in &captures {
        let facts = source_facts(msgs);
        let mut det = ScannerDetector::new(&[]);
        let mut offenders = 0usize;
        for msg in msgs {
            let Some(alert) = det.check(msg) else {
                continue;
            };
            if alert.detection_method == "ua_pattern" {
                continue;
            }
            let Some(f) = facts.get(&alert.src_ip) else {
                continue;
            };
            if !f.probes.is_empty() && f.probes.iter().all(|p| !p.unanswered() && !p.rejected) {
                offenders += 1;
            }
        }
        assert_eq!(
            offenders, 0,
            "{name}: {offenders} alerts name a peer whose every probe we answered, and \
             answered without refusing — a working trunk, and with --kill-scanner behind \
             a jail, a banned one"
        );
        checked += 1;
    }
    eprintln!(
        "scanner signature: {checked} captures hold no alert against a peer we answered every time"
    );
}
