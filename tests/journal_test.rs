// SPDX-License-Identifier: MIT OR Apache-2.0

//! The operations journal: durable, ordered, chained, bounded (JOURNAL).
//!
//! Written before the behavior exists, from the approved spec
//! (https://claude.ai/artifact/BmVZTqH833Vh2tPZvMD5A9). sipnab journals the
//! operations it performs on other systems so a restarted sipnab knows what it
//! did, what was in flight, and which limits it had spent. These tests cover
//! the file itself; what goes in it is covered where actions are taken.

#![cfg(all(unix, feature = "full"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;
use sipnab::journal::{Journal, JournalError, JournalLimits};

fn dir() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().expect("tempdir");
    let d = t.path().join("journal");
    (t, d)
}

fn segments(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)
        .expect("read dir")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    v.sort();
    v
}

fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .expect("read")
        .lines()
        .map(str::to_string)
        .collect()
}

// ── the files ────────────────────────────────────────────────────────────

#[test]
fn opening_creates_a_private_directory_and_segment() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-1").expect("open");
    j.append("run_start", json!({})).expect("append");
    let dmode = std::fs::metadata(&d).expect("stat").permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    let segs = segments(&d);
    assert_eq!(segs.len(), 1);
    assert!(segs[0].ends_with("journal-000001.jsonl"), "{segs:?}");
    let fmode = std::fs::metadata(&segs[0])
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(fmode, 0o600);
}

#[test]
fn a_second_writer_on_the_same_journal_is_refused() {
    let (_t, d) = dir();
    let (_j, _) = Journal::open(&d, "run-1").expect("first");
    match Journal::open(&d, "run-2") {
        Err(JournalError::Locked(path)) => assert_eq!(path, d),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn the_lock_is_released_when_the_journal_is_dropped() {
    let (_t, d) = dir();
    drop(Journal::open(&d, "run-1").expect("first"));
    Journal::open(&d, "run-2").expect("the first writer is gone");
}

// ── records ──────────────────────────────────────────────────────────────

#[test]
fn a_record_carries_version_sequence_time_run_kind_and_body() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-7f3c").expect("open");
    let seq = j
        .append(
            "action_intent",
            json!({"id": "a-1", "address": "198.51.100.20"}),
        )
        .expect("append");
    assert_eq!(seq, 1);
    let line = &lines(&segments(&d)[0])[0];
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
    assert_eq!(v["v"], 1);
    assert_eq!(v["seq"], 1);
    assert_eq!(v["run"], "run-7f3c");
    assert_eq!(v["kind"], "action_intent");
    assert_eq!(v["id"], "a-1");
    assert_eq!(v["address"], "198.51.100.20");
    let ts = v["ts"].as_str().expect("ts is a string");
    assert!(ts.ends_with('Z'), "UTC: {ts}");
    chrono::DateTime::parse_from_rfc3339(ts).expect("RFC 3339");
}

#[test]
fn a_record_is_on_disk_when_append_returns() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-1").expect("open");
    j.append("action_intent", json!({"id": "a-1"}))
        .expect("append");
    // Read through a separate handle, before anything else happens.
    assert_eq!(lines(&segments(&d)[0]).len(), 1);
}

#[test]
fn a_body_cannot_overwrite_the_envelope() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-1").expect("open");
    let err = j
        .append("action_intent", json!({"seq": 99, "prev": "forged"}))
        .expect_err("a body naming an envelope field is refused");
    assert!(matches!(err, JournalError::ReservedField(_)), "{err:?}");
}

#[test]
fn each_record_links_to_the_one_before_it() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-1").expect("open");
    j.append("a", json!({})).expect("1");
    j.append("b", json!({})).expect("2");
    let l = lines(&segments(&d)[0]);
    let second: serde_json::Value = serde_json::from_str(&l[1]).expect("json");
    use sha2::Digest;
    let hex: String = sha2::Sha256::digest(l[0].as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let expected = format!("sha256:{hex}");
    assert_eq!(second["prev"], expected.as_str());
}

#[test]
fn sequence_numbers_continue_across_restarts() {
    let (_t, d) = dir();
    {
        let (mut j, _) = Journal::open(&d, "run-1").expect("open");
        j.append("a", json!({})).expect("1");
        j.append("b", json!({})).expect("2");
    }
    let (mut j, recovered) = Journal::open(&d, "run-2").expect("reopen");
    assert_eq!(recovered.records.len(), 2, "the earlier run is read back");
    assert_eq!(j.append("c", json!({})).expect("3"), 3);
}

#[test]
fn reopening_reads_every_record_back_in_order() {
    let (_t, d) = dir();
    {
        let (mut j, _) = Journal::open(&d, "run-1").expect("open");
        for k in ["run_start", "action_intent", "action_outcome"] {
            j.append(k, json!({"k": k})).expect("append");
        }
    }
    let (_j, recovered) = Journal::open(&d, "run-2").expect("reopen");
    let kinds: Vec<&str> = recovered.records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["run_start", "action_intent", "action_outcome"]);
    assert_eq!(recovered.records[1].body["k"], "action_intent");
}

// ── tampering and damage ─────────────────────────────────────────────────

fn write_three(d: &Path) -> PathBuf {
    let (mut j, _) = Journal::open(d, "run-1").expect("open");
    for k in ["a", "b", "c"] {
        j.append(k, json!({"k": k})).expect("append");
    }
    segments(d)[0].clone()
}

#[test]
fn an_edited_record_is_detected_and_named() {
    let (_t, d) = dir();
    let seg = write_three(&d);
    let text =
        std::fs::read_to_string(&seg)
            .expect("read")
            .replacen("\"k\":\"b\"", "\"k\":\"B\"", 1);
    std::fs::write(&seg, text).expect("write");
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 3, "the record after the edit"),
        other => panic!("expected Broken, got {other:?}"),
    }
}

#[test]
fn a_deleted_record_is_detected() {
    let (_t, d) = dir();
    let seg = write_three(&d);
    let l = lines(&seg);
    std::fs::write(&seg, format!("{}\n{}\n", l[0], l[2])).expect("write");
    assert!(matches!(
        Journal::open(&d, "run-2"),
        Err(JournalError::Broken { .. })
    ));
}

#[test]
fn reordered_records_are_detected() {
    let (_t, d) = dir();
    let seg = write_three(&d);
    let l = lines(&seg);
    std::fs::write(&seg, format!("{}\n{}\n{}\n", l[0], l[2], l[1])).expect("write");
    assert!(matches!(
        Journal::open(&d, "run-2"),
        Err(JournalError::Broken { .. })
    ));
}

#[test]
fn a_torn_last_line_is_discarded_recorded_and_the_chain_continues() {
    // A crash during the write of the last record leaves part of a line. That
    // record's fsync never returned, so nothing it described was done: it is
    // safe to discard, and the discard itself is recorded.
    let (_t, d) = dir();
    let seg = write_three(&d);
    let mut text = std::fs::read_to_string(&seg).expect("read");
    text.push_str("{\"v\":1,\"seq\":4,\"kind\":\"action_int");
    std::fs::write(&seg, text).expect("write");
    let (mut j, recovered) = Journal::open(&d, "run-2").expect("a torn tail is not tampering");
    assert_eq!(recovered.records.len(), 3);
    assert!(recovered.torn_bytes > 0);
    j.append("d", json!({})).expect("append after repair");
    drop(j);
    let (_j, again) = Journal::open(&d, "run-3").expect("chain intact after repair");
    let kinds: Vec<&str> = again.records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["a", "b", "c", "torn_tail_discarded", "d"]);
}

// ── size and retention ───────────────────────────────────────────────────

#[test]
fn a_full_segment_rolls_over_and_the_new_one_opens_with_a_checkpoint() {
    let (_t, d) = dir();
    let limits = JournalLimits {
        segment_bytes: 400,
        ..JournalLimits::default()
    };
    let (mut j, _) = Journal::open_with(&d, "run-1", limits).expect("open");
    for i in 0..10 {
        j.append("action_intent", json!({"i": i, "pad": "x".repeat(40)}))
            .expect("append");
        if j.segment_full() {
            j.roll_over(json!({"owned": []})).expect("roll over");
        }
    }
    let segs = segments(&d);
    assert!(segs.len() >= 2, "{segs:?}");
    for seg in &segs[1..] {
        let first: serde_json::Value = serde_json::from_str(&lines(seg)[0]).expect("json");
        assert_eq!(first["kind"], "checkpoint", "{}", seg.display());
    }
    drop(j);
    Journal::open(&d, "run-2").expect("the chain runs across segments");
}

#[test]
fn pruning_removes_old_closed_segments_and_the_chain_still_verifies() {
    let (_t, d) = dir();
    let limits = JournalLimits {
        segment_bytes: 300,
        ..JournalLimits::default()
    };
    {
        let (mut j, _) = Journal::open_with(&d, "run-1", limits).expect("open");
        for i in 0..12 {
            j.append("action_intent", json!({"i": i, "pad": "x".repeat(40)}))
                .expect("append");
            if j.segment_full() {
                j.roll_over(json!({"owned": []})).expect("roll over");
            }
        }
    }
    let before = segments(&d);
    assert!(before.len() >= 3, "{before:?}");
    // Everything is older than a zero-second window, but the current segment
    // must survive, and so must enough of the chain to verify.
    let removed = Journal::prune(&d, std::time::Duration::ZERO).expect("prune");
    let after = segments(&d);
    assert_eq!(removed, before.len() - 1);
    assert_eq!(after, vec![before.last().cloned().expect("last")]);
    let (_j, recovered) = Journal::open(&d, "run-2").expect("verifies from the checkpoint");
    assert_eq!(recovered.records[0].kind, "checkpoint");
}

#[test]
fn pruning_keeps_segments_inside_the_window() {
    let (_t, d) = dir();
    let limits = JournalLimits {
        segment_bytes: 300,
        ..JournalLimits::default()
    };
    {
        let (mut j, _) = Journal::open_with(&d, "run-1", limits).expect("open");
        for i in 0..12 {
            j.append("x", json!({"i": i, "pad": "x".repeat(40)}))
                .expect("append");
            if j.segment_full() {
                j.roll_over(json!({})).expect("roll over");
            }
        }
    }
    let before = segments(&d);
    let removed = Journal::prune(&d, std::time::Duration::from_secs(90 * 86_400)).expect("prune");
    assert_eq!(removed, 0);
    assert_eq!(segments(&d), before);
}

#[test]
fn the_shipped_limits_match_the_spec() {
    let l = JournalLimits::default();
    assert_eq!(l.segment_bytes, 16 * 1024 * 1024);
    assert_eq!(l.retention, std::time::Duration::from_secs(90 * 86_400));
}

#[test]
fn a_journal_missing_its_beginning_is_detected() {
    // Cutting records off the front leaves a first record that is neither
    // record 1 nor a checkpoint, which only pruning may produce.
    let (_t, d) = dir();
    let seg = write_three(&d);
    let l = lines(&seg);
    std::fs::write(&seg, format!("{}\n{}\n", l[1], l[2])).expect("write");
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 2),
        other => panic!("expected Broken, got {other:?}"),
    }
}

/// `append` syncs the line before it returns.
///
/// Durability cannot be observed from a test: a line reaches the page cache,
/// and every read sees it, whether or not it was synced. Only a power loss
/// tells the difference. So this pins the call in the one function every
/// record goes through, and the spec's reason for it: an intent must be on
/// disk before the action it describes starts.
#[test]
fn append_syncs_each_record_before_returning() {
    let src = include_str!("../src/journal.rs");
    let start = src.find("pub fn append(").expect("append exists");
    let body = &src[start..];
    let end = body.find("\n    }\n").expect("append ends");
    let body = &body[..end];
    let write = body.find(".write_all(").expect("append writes");
    let sync = body.find(".sync_data()").expect("append syncs");
    let ok = body.find("Ok(seq)").expect("append returns the sequence");
    assert!(write < sync && sync < ok, "write, then sync, then return");
}

#[test]
fn an_edited_sequence_number_on_the_last_record_is_detected() {
    // The chain protects every record by the hash in the one after it, which
    // the last record does not have. Its sequence number is checked on its own.
    let (_t, d) = dir();
    let seg = write_three(&d);
    let text = std::fs::read_to_string(&seg)
        .expect("read")
        .replacen("\"seq\":3", "\"seq\":7", 1);
    std::fs::write(&seg, text).expect("write");
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 7),
        other => panic!("expected Broken, got {other:?}"),
    }
}

// ── reading while sipnab runs ─────────────────────────────────────────────

/// `--journal-show` reads the journal a running sipnab holds: no lock, and no
/// repair of a last line the writer may be in the middle of.
#[test]
fn reading_takes_no_lock_and_repairs_nothing() {
    let (_t, d) = dir();
    let (mut j, _) = Journal::open(&d, "run-a").expect("open");
    j.append("action_intent", json!({"id": "a-1"}))
        .expect("append");
    j.append("action_outcome", json!({"id": "a-1"}))
        .expect("append");
    let seg = segments(&d).pop().expect("a segment");
    let before = std::fs::read(&seg).expect("read");
    // The writer is mid-line.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&seg)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"{\"v\":1,\"seq\""))
        .expect("tear");
    let read = Journal::read(&d).expect("read while held");
    assert_eq!(read.records.len(), 2);
    assert!(read.torn_bytes > 0);
    let after = std::fs::read(&seg).expect("read");
    assert_eq!(&after[..before.len()], &before[..]);
    assert!(
        after.len() > before.len(),
        "the partial line is left for its writer"
    );
    // And the writer still holds it.
    assert!(matches!(
        Journal::open(&d, "run-b"),
        Err(JournalError::Locked(_))
    ));
}

#[test]
fn reading_a_damaged_journal_names_the_record() {
    let (_t, d) = dir();
    let seg = write_three(&d);
    let mut text = std::fs::read_to_string(&seg).expect("read");
    assert!(text.contains("\"kind\":\"b\""), "{text}");
    text = text.replacen("\"kind\":\"b\"", "\"kind\":\"x\"", 1);
    std::fs::write(&seg, text).expect("edit");
    let err = Journal::read(&d).expect_err("broken");
    assert!(matches!(err, JournalError::Broken { .. }), "{err:?}");
}

#[test]
fn reading_where_no_journal_is_says_so() {
    let (_t, d) = dir();
    let err = Journal::read(&d.join("never-written")).expect_err("absent");
    assert!(matches!(err, JournalError::Absent(_)), "{err:?}");
}
