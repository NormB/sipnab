// SPDX-License-Identifier: MIT OR Apache-2.0

//! `nat_mismatch` and `no_media` fire on REAL captures, and only where they
//! should.
//!
//! Both flags were structurally unreachable: `diagnose_media` computed them
//! only when handed the dialog's SDP, and every production caller handed it
//! `None`. Zero matches on every capture anyone pointed at sipnab, which reads
//! exactly like a clean trunk. A fixture test proves the wiring; only a corpus
//! proves the flags fire on traffic nobody wrote to make them fire, and — the
//! harder half — that they stay quiet on the far larger set of healthy calls
//! beside them.
//!
//! Each test carries its own independent check rather than a pinned number, so
//! it survives a corpus change:
//!
//! * **Agreement.** `nat_mismatch` is recomputed here from the *unfiltered*
//!   per-dialog JSON — the `sdp_timeline` and `streams` blocks rendered by
//!   `output::json`, a different code path from the diagnosis under test — and
//!   must agree dialog for dialog.
//! * **Bound.** The flag must not swallow the capture. A diagnosis that fires
//!   on every call with media is not a diagnosis.
//! * **Silence where the question is unanswerable.** A capture holding no RTP
//!   cannot show that one call had none, and must report no `no_media`.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is assumed to contain PII, so nothing derived from a
//! packet is printed or asserted on by value — Call-IDs are set members and
//! counted, addresses are compared and discarded, and the only names printed
//! are filenames.
#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "support/run.rs"]
mod run_support;

/// Skip captures larger than this: the corpus root can hold archives that are
/// not captures at all, and each file is parsed in full.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// How many captures of each kind to exercise. Both halves are needed and
/// neither substitutes for the other: the media-carrying captures are the only
/// place `nat_mismatch` can fire, and the RTP-free ones are the only place the
/// capture-level `no_media` guard is under any pressure. Taking the first N
/// files in path order filled the whole budget with signalling-only captures
/// and left the flag under test never exercised — passing, and proving
/// nothing.
const WANT_PER_KIND: usize = 4;

/// Files to open before giving up on filling either bucket. Bounds runtime on
/// a corpus whose media-carrying captures sort late.
const MAX_SCANNED: usize = 60;

/// A diagnosis that fires on more than this share of the calls that carry
/// media is describing the capture, not the calls in it.
const MAX_FLAGGED_SHARE: f64 = 0.75;

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

/// Run `sipnab -N -I <capture> --no-cli-print --json-dialogs` over the WHOLE
/// port range and return `(dialogs, exit_code)`.
///
/// `--portrange` is spelled out because the 5060-5061 default hides about a
/// third of the SIP in a carrier capture, and a diagnosis measured against a
/// third of the traffic is not measured. The exit code comes back rather than
/// being swallowed: a run that died reads as "zero dialogs matched" to anyone
/// counting lines.
fn dialogs(capture: &Path) -> (Vec<serde_json::Value>, Option<i32>) {
    let capture = capture.to_string_lossy().into_owned();
    let argv = [
        "-N",
        "-I",
        &capture,
        "--no-cli-print",
        "--json-dialogs",
        "--portrange",
        "1-65535",
    ];
    let (stdout, _stderr, code) = run_support::run(&argv, Some("error"));
    let parsed = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("dialog line must be JSON"))
        .collect();
    (parsed, code)
}

/// Readable captures under the size cap, as `(filename, dialogs)`, balanced
/// between those that carry RTP and those that do not.
fn corpus_captures(root: &Path) -> Vec<(String, Vec<serde_json::Value>)> {
    let (mut with_media, mut without_media) = (Vec::new(), Vec::new());
    let (mut too_big, mut unreadable, mut scanned) = (0usize, 0usize, 0usize);
    for path in walk(root) {
        if with_media.len() == WANT_PER_KIND && without_media.len() == WANT_PER_KIND {
            break;
        }
        if scanned == MAX_SCANNED {
            break;
        }
        if path.metadata().map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            too_big += 1;
            continue;
        }
        scanned += 1;
        let (all, code) = dialogs(&path);
        if code != Some(0) || all.is_empty() {
            unreadable += 1;
            continue;
        }
        let bucket = if all.iter().any(has_streams) {
            &mut with_media
        } else {
            &mut without_media
        };
        if bucket.len() == WANT_PER_KIND {
            continue;
        }
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        bucket.push((name, all));
    }
    eprintln!(
        "corpus: {} captures with RTP, {} without, {scanned} opened, {too_big} over {} MiB, \
         {unreadable} not usable",
        with_media.len(),
        without_media.len(),
        MAX_FILE_BYTES / (1024 * 1024),
    );
    with_media.extend(without_media);
    with_media
}

/// The address part of an `ip:port` string, or the whole string when it holds
/// no colon-separated port.
fn addr_of(endpoint: &str) -> &str {
    endpoint.rsplit_once(':').map_or(endpoint, |(a, _)| a)
}

/// Whether this dialog's JSON shows a stream sourced from an address that no
/// `sdp_timeline` entry advertised.
///
/// Recomputed from the rendered dialog rather than read off the diagnosis, so
/// agreement between the two is a cross-check rather than a tautology.
fn has_unadvertised_stream_source(dialog: &serde_json::Value) -> bool {
    let advertised: BTreeSet<&str> = dialog["sdp_timeline"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e["media_addr"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if advertised.is_empty() {
        return false;
    }
    dialog["streams"]
        .as_array()
        .map(|streams| {
            streams
                .iter()
                .filter_map(|s| s["src"].as_str())
                .any(|src| !advertised.contains(addr_of(src)))
        })
        .unwrap_or(false)
}

/// Whether the dialog carries any linked RTP stream.
fn has_streams(dialog: &serde_json::Value) -> bool {
    dialog["streams"].as_array().is_some_and(|s| !s.is_empty())
}

/// Read a boolean out of the rendered `diagnosis` block.
fn flag(dialog: &serde_json::Value, name: &str) -> bool {
    dialog["diagnosis"][name].as_bool().unwrap_or(false)
}

// ── nat_mismatch ────────────────────────────────────────────────────────

/// `nat_mismatch` fires somewhere in the corpus, and agrees dialog for dialog
/// with the same question asked of the rendered JSON.
///
/// The agreement half is what makes this more than a smoke test: it fails both
/// ways round. A flag that stopped firing fails the count, and a flag that
/// started firing on calls whose media came from an address the SDP did name
/// fails the comparison.
#[test]
fn corpus_nat_mismatch_fires_and_agrees_with_the_rendered_sdp() {
    let Some(root) = corpus_root() else { return };

    let (mut flagged, mut with_media, mut disagreements) = (0usize, 0usize, 0usize);
    for (name, all) in corpus_captures(&root) {
        let mut per_file = 0usize;
        for dialog in &all {
            if has_streams(dialog) {
                with_media += 1;
            }
            let claimed = flag(dialog, "nat_mismatch");
            let independent = has_unadvertised_stream_source(dialog);
            if claimed {
                flagged += 1;
                per_file += 1;
            }
            if claimed != independent {
                disagreements += 1;
                eprintln!(
                    "{name}: diagnosis says nat_mismatch={claimed} but the rendered \
                     sdp_timeline/streams say {independent}"
                );
            }
        }
        if per_file > 0 {
            eprintln!("{name}: {per_file} nat_mismatch");
        }
    }

    eprintln!("corpus nat_mismatch: {flagged} of {with_media} dialogs carrying media");
    assert_eq!(
        disagreements, 0,
        "the diagnosis and the rendered dialog must answer the same question the same way"
    );
    assert!(
        flagged > 0,
        "no capture under SIPNAB_CORPUS shows RTP arriving from an unadvertised address, \
         so this test proves nothing — the flag was structurally unreachable once and a \
         corpus with no NAT in it cannot tell that apart from a fix"
    );
    assert!(
        with_media > 0,
        "the corpus holds no dialog with linked RTP, so nat_mismatch could not fire either way"
    );
    let share = flagged as f64 / with_media as f64;
    assert!(
        share <= MAX_FLAGGED_SHARE,
        "nat_mismatch fired on {flagged} of {with_media} dialogs with media ({:.0}%) — \
         a diagnosis that selects nearly every call is a false-positive problem, not a fix",
        share * 100.0
    );
}

// ── no_media ────────────────────────────────────────────────────────────

/// A capture that recorded no RTP at all reports no `no_media`.
///
/// Every answered call in a signalling-only capture has zero RTP, so without
/// the capture-level guard the flag selects all of them and describes where
/// the tap sits rather than what happened on any call.
#[test]
fn corpus_signalling_only_captures_report_no_no_media() {
    let Some(root) = corpus_root() else { return };

    let (mut checked, mut answered_in_them) = (0usize, 0usize);
    for (name, all) in corpus_captures(&root) {
        if all.iter().any(has_streams) {
            continue; // this capture carries media; a different test's job
        }
        checked += 1;
        let answered = all
            .iter()
            .filter(|d| d["final_status_code"].as_u64() == Some(200))
            .count();
        answered_in_them += answered;
        let claimed = all.iter().filter(|d| flag(d, "no_media")).count();
        assert_eq!(
            claimed, 0,
            "{name}: holds no RTP at all yet claims {claimed} calls had no media \
             (of {answered} answered) — that describes the capture, not the calls"
        );
    }

    eprintln!(
        "corpus signalling-only captures: {checked} checked, {answered_in_them} answered calls \
         in them, 0 no_media claims"
    );
    assert!(
        checked > 0,
        "no capture under SIPNAB_CORPUS is free of RTP, so the guard was never exercised"
    );
}

/// `no_media` never fires on a dialog that carries linked RTP.
///
/// The two are contradictory by definition, and the check is cheap enough to
/// hold over the whole corpus rather than trusting the branch to stay ordered.
#[test]
fn corpus_no_media_never_claimed_for_a_dialog_that_has_streams() {
    let Some(root) = corpus_root() else { return };

    let mut with_media = 0usize;
    for (name, all) in corpus_captures(&root) {
        for dialog in &all {
            if !has_streams(dialog) {
                continue;
            }
            with_media += 1;
            assert!(
                !flag(dialog, "no_media"),
                "{name}: a dialog with linked RTP streams is reported as having no media"
            );
        }
    }

    eprintln!("corpus: {with_media} dialogs with media, none claimed no_media");
    assert!(
        with_media > 0,
        "the corpus holds no dialog with linked RTP, so this proves nothing"
    );
}
