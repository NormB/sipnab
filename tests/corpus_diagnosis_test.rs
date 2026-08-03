// SPDX-License-Identifier: MIT OR Apache-2.0

//! Diagnosis claims and message retention, proved against REAL captures.
//!
//! Two defects were found by reading sipnab's own output against a corpus of
//! captures whose filenames state what they contain, and both are the kind
//! that a synthetic fixture can reproduce only after you already know the
//! answer. So the fixtures live beside the code they guard, and these tests
//! hold the same properties against whatever the corpus actually holds:
//!
//! 1. A `REGISTER` rejection used to be reported as "the endpoint is offline"
//!    for every status code. The corpus contains registrations rejected `403`
//!    immediately after the endpoint answered a `401` challenge — proof the
//!    endpoint was online, in the same dialog as the claim that it was not.
//!
//! 2. Idle compaction kept the LAST N messages of a dialog, so the `200 OK`
//!    of an answered call — which arrives early — was among the first
//!    evicted, and the call's outcome disappeared.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is not committed and is assumed to contain PII, so
//! nothing derived from a packet's contents (Call-ID, user part, address)
//! is ever printed — assertions name files, indices, status codes and
//! counts only.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};

use sipnab::capture::pcap_reader::{PcapReader, decompress_capture};
use sipnab::capture::{Packet, parse::parse_packet};
use sipnab::sip::diagnosis::diagnose_signaling;
use sipnab::sip::dialog_store::{DialogStore, KEEP_MESSAGES_PER_IDLE_DIALOG};
use sipnab::sip::{is_sip_message, parser::parse_sip};

/// Files larger than this are skipped: the corpus root holds a multi-gigabyte
/// archive that is not a capture at all, and the pure-Rust reader works from a
/// whole-file slice. Reported, never silent — a test that quietly covers a
/// tenth of what it claims to is the failure mode this whole exercise is
/// about.
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

/// Read one capture into a fresh `DialogStore`, or `None` when the file is
/// not a capture this build can read.
fn load(path: &Path) -> Option<DialogStore> {
    let data = std::fs::read(path).ok()?;
    let inflated = decompress_capture(&data).ok()?;
    let reader = PcapReader::new(&inflated).ok()?;

    let mut store = DialogStore::new(100_000, false);
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
            store.process_message(msg);
        }
    }
    Some(store)
}

/// Every readable capture under the corpus root, as `(display name, store)`.
///
/// The display name is the path relative to the corpus root — a filename, not
/// packet content, so it carries nothing from the wire.
fn corpus_stores(root: &Path) -> Vec<(String, DialogStore)> {
    let mut out = Vec::new();
    let (mut too_big, mut unreadable) = (0usize, 0usize);
    for path in walk(root) {
        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        if size > MAX_FILE_BYTES {
            too_big += 1;
            continue;
        }
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        match load(&path) {
            Some(store) => out.push((name, store)),
            None => unreadable += 1,
        }
    }
    eprintln!(
        "corpus: {} captures read, {too_big} over {} MiB skipped, {unreadable} not readable as \
         captures",
        out.len(),
        MAX_FILE_BYTES / (1024 * 1024),
    );
    out
}

// ── Defect 1: what a rejected REGISTER actually means ────────────────

/// No `REGISTER` rejection in the corpus claims the endpoint is offline
/// unless the code is `408` — the only one where a reachability problem is a
/// live possibility.
///
/// Every other rejection in the corpus is a response the registrar sent to a
/// request it received: the endpoint reached it. `403` after a challenge,
/// `404` for an unknown address-of-record, `480 No DNS results` from a proxy
/// that could not resolve — all three appear here, and all three used to be
/// reported as an offline endpoint.
#[test]
fn no_corpus_registration_rejection_claims_the_endpoint_is_offline() {
    let Some(root) = corpus_root() else { return };

    let mut rejections = 0usize;
    let mut codes: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();

    for (name, store) in corpus_stores(&root) {
        for dialog in store.iter() {
            let diag = diagnose_signaling(&dialog.messages);
            let Some(reg) = &diag.registration_failure else {
                continue;
            };
            if !(200..300).contains(&reg.code) {
                rejections += 1;
                codes.insert(reg.code);
            }
            for hint in diag.hints.iter().filter(|h| h.starts_with("Registration")) {
                let lower = hint.to_lowercase();
                if reg.code == 408 {
                    continue;
                }
                for claim in ["offline", "unreachable", "not reachable"] {
                    assert!(
                        !lower.contains(claim),
                        "{name}: a {} registration response is reported as '{claim}': {hint}",
                        reg.code
                    );
                }
            }
        }
    }

    eprintln!("corpus registration rejections: {rejections}, codes {codes:?}");
    assert!(
        rejections > 0,
        "the corpus at SIPNAB_CORPUS holds no rejected REGISTER, so this test proves \
         nothing — point it at a corpus containing registration failures"
    );
}

/// The direct evidence: a `REGISTER` challenged `401`, answered with
/// credentials, and refused `403`. The endpoint transmitted twice and the
/// registrar answered twice, so "the endpoint is offline" was contradicted by
/// the same four messages it was drawn from.
#[test]
fn corpus_forbidden_after_challenge_reads_as_a_credential_rejection() {
    let Some(root) = corpus_root() else { return };

    let mut found = 0usize;
    for (name, store) in corpus_stores(&root) {
        for dialog in store.iter() {
            let diag = diagnose_signaling(&dialog.messages);
            let Some(reg) = &diag.registration_failure else {
                continue;
            };
            if reg.code != 403 {
                continue;
            }
            // The shape that makes this case decidable: a challenge, then a
            // REGISTER carrying the Authorization the challenge asked for.
            let challenged = dialog
                .messages
                .iter()
                .any(|m| matches!(m.status_code, Some(401 | 407)));
            let answered = dialog
                .messages
                .iter()
                .any(|m| m.is_request && m.header("Authorization").is_some());
            if !(challenged && answered) {
                continue;
            }
            found += 1;

            let hint = diag
                .hints
                .iter()
                .find(|h| h.starts_with("Registration"))
                .unwrap_or_else(|| panic!("{name}: 403 rejection with no registration hint"));
            let lower = hint.to_lowercase();
            assert!(
                lower.contains("credential"),
                "{name}: 403 after an answered challenge is a credential rejection, not a \
                 connectivity problem: {hint}"
            );
            assert!(
                !lower.contains("offline"),
                "{name}: the endpoint answered the challenge in this very dialog: {hint}"
            );
        }
    }

    assert!(
        found > 0,
        "the corpus at SIPNAB_CORPUS holds no REGISTER challenged and then refused 403 — \
         the shape this test exists to pin down"
    );
}

// ── Defect 2: compaction must not eat the outcome ────────────────────

/// Idle compaction of a real captured dialog must not change what the call
/// did. Position-based eviction changed `final_status_code()` from the code
/// the registrar or callee actually sent to `None`, which the report renders
/// as `-` and every failure-selecting filter reads as "no outcome".
#[test]
fn corpus_compaction_preserves_the_final_status_code() {
    let Some(root) = corpus_root() else { return };

    let mut checked = 0usize;
    let mut total_evicted = 0u64;

    for (name, mut store) in corpus_stores(&root) {
        // What every dialog reported BEFORE any compaction, by Call-ID. The
        // Call-ID is a map key inside this test and is never printed.
        let before: Vec<(String, Option<u16>, usize)> = store
            .iter()
            .map(|d| (d.call_id.clone(), d.final_status_code(), d.messages.len()))
            .collect();

        // Nothing to prove on a capture with no dialog long enough to compact.
        let Some(latest) = store.iter().map(|d| d.updated_at).max() else {
            continue;
        };
        if !before
            .iter()
            .any(|(_, code, len)| code.is_some() && *len > KEEP_MESSAGES_PER_IDLE_DIALOG)
        {
            continue;
        }

        // Every dialog is idle an hour after the capture's last packet.
        store.compact_idle(latest + chrono::TimeDelta::hours(1));
        total_evicted += store.total_idle_messages_evicted();

        for (call_id, code, len) in &before {
            let Some(dialog) = store.get(call_id) else {
                continue;
            };
            if len <= &KEEP_MESSAGES_PER_IDLE_DIALOG {
                continue;
            }
            checked += 1;
            assert_eq!(
                dialog.final_status_code(),
                *code,
                "{name}: compaction changed the outcome of a {len}-message dialog"
            );
        }
    }

    eprintln!(
        "corpus compaction: {checked} over-limit dialogs checked, {total_evicted} messages evicted"
    );
    assert!(
        checked > 0,
        "the corpus at SIPNAB_CORPUS holds no dialog longer than {KEEP_MESSAGES_PER_IDLE_DIALOG} \
         messages with a final response, so compaction was never exercised"
    );
}

/// The lifetime eviction counter must be readable from outside the crate.
///
/// It had no caller anywhere but its own unit test, so a run could discard
/// hundreds of messages while every surface reported the full count. This is
/// the consumer that keeps the accessor honest; wiring it into the CLI
/// summary is a separate job with its own golden tests.
#[test]
fn corpus_eviction_counter_is_reachable_and_counts() {
    let Some(root) = corpus_root() else { return };

    let mut counted = 0u64;
    for (_, mut store) in corpus_stores(&root) {
        assert_eq!(
            store.total_idle_messages_evicted(),
            0,
            "a store that has never been compacted has evicted nothing"
        );
        let Some(latest) = store.iter().map(|d| d.updated_at).max() else {
            continue;
        };
        let stats = store.compact_idle(latest + chrono::TimeDelta::hours(1));
        assert_eq!(
            store.total_idle_messages_evicted(),
            stats.messages_evicted as u64,
            "the lifetime counter must agree with the sweep that fed it"
        );
        counted += store.total_idle_messages_evicted();
    }

    eprintln!("corpus messages evicted by idle compaction: {counted}");
}
