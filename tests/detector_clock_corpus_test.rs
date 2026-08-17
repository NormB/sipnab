// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security detections must be supported by the CAPTURE's timeline, proved
//! against REAL captures.
//!
//! The scanner and fraud detectors both make claims of the form "N of these in
//! the last W seconds", and both used to measure W with `std::time::Instant` —
//! the clock of the machine doing the reading. Live that is right; a packet is
//! timestamped as it arrives. Offline it is not: a file is replayed as fast as
//! the disk allows, so the window never expires, the counters accumulate over
//! the whole capture, and every peer that was merely busy gets reported.
//!
//! Synthetic fixtures reproduce that only once you already know the answer,
//! because a hand-built message sequence is fed at whatever rate the test loop
//! runs. Real traffic does not need to be told: these tests replay a corpus and
//! check every alert against an INDEPENDENT sliding-window count taken from the
//! packet timestamps. An alert the capture cannot account for is a false
//! positive, and with `--kill-scanner` or a fail2ban jail behind it, a false
//! positive is a banned carrier.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents — address, Call-ID, user part — is
//! ever printed. Assertions name files and counts only.
//!
//! These replay every capture three times and the oracles are quadratic in the
//! window, so budget minutes, and use `--release`:
//!
//! ```text
//! SIPNAB_CORPUS=/path/to/pcaps cargo test --all-features --release \
//!     --test detector_clock_corpus_test -- --test-threads=1 --nocapture
//! ```
#![cfg(feature = "native")]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeDelta, Utc};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::security::{FraudDetector, ScannerDetector};
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::{SipMessage, is_sip_message, parser::parse_sip};

/// Files larger than this are skipped: the corpus root holds archives that are
/// not captures, and the pure-Rust reader works from a whole-file slice.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// The scanner detector's behavioral/enumeration window, in seconds.
/// Mirrors `BEHAVIORAL_WINDOW_SECS`, which is private to the detector.
const SCANNER_WINDOW_SECS: i64 = 5;

/// The scanner rate threshold; an alert needs strictly more than this.
/// Mirrors `BEHAVIORAL_THRESHOLD`.
const SCANNER_RATE_THRESHOLD: usize = 10;

/// The scanner enumeration threshold; an alert needs strictly more distinct
/// targets than this. Mirrors `ENUMERATION_THRESHOLD`.
const SCANNER_ENUM_THRESHOLD: usize = 5;

/// The fraud volume window, in seconds. Mirrors `VOLUME_WINDOW_SECS`.
const VOLUME_WINDOW_SECS: i64 = 60;

/// The fraud volume floor; a spike needs at least this many calls in the
/// window. Mirrors `VOLUME_SPIKE_MIN_CALLS`.
const VOLUME_MIN_CALLS: usize = 6;

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

/// The largest number of entries of `events` that fall inside any window of
/// `width`, measured as a half-open span: an event exactly `width` old is
/// outside, which is what "in the last W seconds" means.
///
/// `events` must be sorted by timestamp.
fn max_in_window(events: &[DateTime<Utc>], width: TimeDelta) -> usize {
    let (mut lo, mut best) = (0usize, 0usize);
    for hi in 0..events.len() {
        while events[hi].signed_duration_since(events[lo]) >= width {
            lo += 1;
        }
        best = best.max(hi - lo + 1);
    }
    best
}

/// The largest number of DISTINCT values of `events` inside any window of
/// `width`. `events` must be sorted by timestamp.
fn max_distinct_in_window(events: &[(DateTime<Utc>, String)], width: TimeDelta) -> usize {
    let mut best = 0usize;
    for hi in 0..events.len() {
        let mut seen = std::collections::HashSet::new();
        let mut lo = hi;
        loop {
            if events[hi].0.signed_duration_since(events[lo].0) >= width {
                break;
            }
            if !events[lo].1.is_empty() {
                seen.insert(events[lo].1.as_str());
            }
            if lo == 0 {
                break;
            }
            lo -= 1;
        }
        best = best.max(seen.len());
    }
    best
}

/// The user part of a SIP URI, mirroring the crate-private `extract_uri_user`
/// the detector uses on a Request-URI.
///
/// Restated here rather than exported: this is the test's own oracle, and an
/// oracle that calls the code under test proves nothing. A Request-URI is an
/// addr-spec, so only the bare form needs handling.
fn uri_user(uri: &str) -> Option<String> {
    let addr = uri.trim().split(';').next().unwrap_or("").trim();
    let after_scheme = addr
        .strip_prefix("sip:")
        .or_else(|| addr.strip_prefix("sips:"))?;
    let user = &after_scheme[..after_scheme.find('@')?];
    (!user.is_empty()).then(|| user.to_string())
}

/// The target extension a request probes: `To` user, falling back to the
/// Request-URI user. Never printed — only counted.
fn probe_target(msg: &SipMessage) -> String {
    msg.to_user()
        .or_else(|| msg.request_uri.as_deref().and_then(uri_user))
        .unwrap_or_default()
}

/// Every scanner alert the detector raises over a corpus capture is one the
/// capture's own timeline can account for.
///
/// A source is reported only if, somewhere in the capture, it really did send
/// more than `BEHAVIORAL_THRESHOLD` probes or reach more than
/// `ENUMERATION_THRESHOLD` distinct extensions inside one
/// `BEHAVIORAL_WINDOW_SECS` window — or send a User-Agent on the known-scanner
/// list, which needs no window at all.
///
/// Paced by the wall clock this failed on the corpus: sources whose busiest
/// five seconds held five distinct extensions were reported for enumeration,
/// because the window never expired and the distinct targets accumulated over
/// the entire capture.
#[test]
fn every_scanner_alert_is_supported_by_the_capture_timeline() {
    let Some(root) = corpus_root() else {
        return;
    };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture with SIP in it — this test would \
         pass without proving anything"
    );

    let (mut files_with_alerts, mut alerts_total) = (0usize, 0usize);
    for (name, msgs) in &captures {
        // Ground truth, straight off the packet timestamps.
        let mut probes: HashMap<IpAddr, Vec<(DateTime<Utc>, String)>> = HashMap::new();
        for msg in msgs {
            let is_probe = msg.is_request
                && matches!(
                    msg.method.as_ref().map(|m| m.as_str()),
                    Some("REGISTER" | "OPTIONS" | "INVITE")
                );
            if is_probe {
                probes
                    .entry(msg.src_addr)
                    .or_default()
                    .push((msg.timestamp, probe_target(msg)));
            }
        }
        for v in probes.values_mut() {
            v.sort_by_key(|(t, _)| *t);
        }

        let window = TimeDelta::seconds(SCANNER_WINDOW_SECS);
        let mut det = ScannerDetector::new(&[]);
        let mut unsupported = 0usize;
        let mut alerts = 0usize;
        for msg in msgs {
            let Some(alert) = det.check(msg) else {
                continue;
            };
            alerts += 1;
            let empty = Vec::new();
            let ev = probes.get(&alert.src_ip).unwrap_or(&empty);
            let supported = match alert.detection_method.as_str() {
                // A signature match is a property of one message; no window.
                "ua_pattern" => true,
                "behavioral" => {
                    let times: Vec<DateTime<Utc>> = ev.iter().map(|(t, _)| *t).collect();
                    max_in_window(&times, window) > SCANNER_RATE_THRESHOLD
                }
                "enumeration" => max_distinct_in_window(ev, window) > SCANNER_ENUM_THRESHOLD,
                _ => false,
            };
            if !supported {
                unsupported += 1;
            }
        }
        assert_eq!(
            unsupported, 0,
            "{name}: {unsupported} of {alerts} scanner alerts describe a rate or a spread \
             the capture's own timestamps do not contain — the detection window is being \
             paced by how fast the file was read"
        );
        alerts_total += alerts;
        if alerts > 0 {
            files_with_alerts += 1;
        }
    }
    eprintln!(
        "scanner: {} captures replayed, {files_with_alerts} raised alerts, \
         {alerts_total} alerts, all supported by packet time",
        captures.len()
    );
}

/// Every VolumeSpike the fraud detector raises over a corpus capture names a
/// count the capture's own timeline can account for.
///
/// A spike claims "N calls in `VOLUME_WINDOW_SECS`s". N must be reachable: the
/// source must really have placed at least `VOLUME_SPIKE_MIN_CALLS` INVITEs
/// inside one such window, and N must not exceed the busiest window it had.
///
/// Paced by the wall clock this failed on the corpus: nothing was ever pruned,
/// so the "in 60s" count was the source's lifetime total. One source whose
/// busiest minute held four calls was reported as six in sixty seconds.
#[test]
fn every_volume_spike_names_a_count_the_capture_contains() {
    let Some(root) = corpus_root() else {
        return;
    };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture with SIP in it"
    );

    let window = TimeDelta::seconds(VOLUME_WINDOW_SECS);
    let (mut spikes_total, mut files_with_spikes) = (0usize, 0usize);
    for (name, msgs) in &captures {
        let mut invites: HashMap<IpAddr, Vec<DateTime<Utc>>> = HashMap::new();
        for msg in msgs {
            if msg.is_request && msg.method.as_ref() == Some(&sipnab::sip::SipMethod::Invite) {
                invites.entry(msg.src_addr).or_default().push(msg.timestamp);
            }
        }
        for v in invites.values_mut() {
            v.sort();
        }

        let mut store = DialogStore::new(100_000, false);
        let mut det = FraudDetector::new(None);
        let mut unsupported = 0usize;
        let mut spikes = 0usize;
        for msg in msgs {
            store.process_message(msg.clone());
            let Some(call_id) = msg.call_id().map(str::to_string) else {
                continue;
            };
            let Some(dialog) = store.get(&call_id) else {
                continue;
            };
            let Some(alert) = det.check(msg, dialog) else {
                continue;
            };
            if alert.alert_type != sipnab::security::fraud_detect::FraudType::VolumeSpike {
                continue;
            }
            spikes += 1;
            let claimed: usize = alert
                .detail
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let empty = Vec::new();
            let times = invites.get(&alert.src_ip).unwrap_or(&empty);
            let real = max_in_window(times, window);
            if claimed < VOLUME_MIN_CALLS || claimed > real {
                unsupported += 1;
            }
        }
        assert_eq!(
            unsupported, 0,
            "{name}: {unsupported} of {spikes} VolumeSpike alerts claim more calls in \
             {VOLUME_WINDOW_SECS}s than the source ever placed in {VOLUME_WINDOW_SECS}s of \
             capture time — the window is not being measured against the packets"
        );
        spikes_total += spikes;
        if spikes > 0 {
            files_with_spikes += 1;
        }
    }
    eprintln!(
        "fraud: {} captures replayed, {files_with_spikes} raised VolumeSpike, \
         {spikes_total} spikes, all supported by packet time",
        captures.len()
    );
}

/// Every wangiri alert over the corpus is backed by calls that really ended
/// quickly.
///
/// The alert says "N short calls to prefix P in 60s". A call is short only if
/// it ENDED soon after it started, which is knowable only once it has ended —
/// so for every alert, the source must have at least N INVITE dialogs that
/// reached a terminal state within `SHORT_CALL_SECS` of their first message.
///
/// This failed on the corpus before: the duration was read at the moment the
/// INVITE arrived, when the dialog has exactly one message and measures zero
/// seconds, so every call counted as short. One source's three INVITEs — which
/// never received so much as a provisional response, let alone ended — were
/// reported as "3 short calls to prefix … in 60s".
#[test]
fn every_wangiri_alert_is_backed_by_calls_that_really_ended_short() {
    let Some(root) = corpus_root() else {
        return;
    };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "SIPNAB_CORPUS holds no readable capture with SIP in it"
    );

    // Matches the detector's own `SHORT_CALL_SECS`, which is private to it.
    let short = TimeDelta::seconds(3);
    let (mut alerts_total, mut files_with_alerts) = (0usize, 0usize);
    for (name, msgs) in &captures {
        let mut store = DialogStore::new(100_000, false);
        let mut det = FraudDetector::new(None);
        let mut unsupported = 0usize;
        let mut alerts = 0usize;
        // Per source: how many of its INVITE dialogs ever ended short.
        let mut ended_short: HashMap<IpAddr, usize> = HashMap::new();
        let mut counted: std::collections::HashSet<String> = std::collections::HashSet::new();

        for msg in msgs {
            store.process_message(msg.clone());
            let Some(call_id) = msg.call_id().map(str::to_string) else {
                continue;
            };
            let Some(dialog) = store.get(&call_id) else {
                continue;
            };
            let terminal = matches!(
                dialog.state(),
                sipnab::sip::dialog::DialogState::Completed
                    | sipnab::sip::dialog::DialogState::Canceled
                    | sipnab::sip::dialog::DialogState::Failed
                    | sipnab::sip::dialog::DialogState::Redirected
            );
            if dialog.method == sipnab::sip::SipMethod::Invite
                && terminal
                && dialog.updated_at.signed_duration_since(dialog.created_at) < short
                && counted.insert(call_id.clone())
            {
                *ended_short.entry(dialog.src_addr).or_default() += 1;
            }

            let Some(dialog) = store.get(&call_id) else {
                continue;
            };
            let Some(alert) = det.check(msg, dialog) else {
                continue;
            };
            if alert.alert_type != sipnab::security::fraud_detect::FraudType::Wangiri {
                continue;
            }
            alerts += 1;
            let claimed: usize = alert
                .detail
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            if claimed > ended_short.get(&alert.src_ip).copied().unwrap_or(0) {
                unsupported += 1;
            }
        }
        assert_eq!(
            unsupported, 0,
            "{name}: {unsupported} of {alerts} wangiri alerts count more short calls than \
             the source ever finished quickly — the duration is being read before the call \
             has a duration"
        );
        alerts_total += alerts;
        if alerts > 0 {
            files_with_alerts += 1;
        }
    }
    eprintln!(
        "wangiri: {} captures replayed, {files_with_alerts} raised alerts, \
         {alerts_total} alerts, all backed by calls that ended short",
        captures.len()
    );
}
