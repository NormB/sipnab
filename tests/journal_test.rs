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

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn dir() -> Result<(tempfile::TempDir, PathBuf), TestError> {
    let t = tempfile::tempdir()?;
    let d = t.path().join("journal");
    Ok((t, d))
}

fn segments(d: &Path) -> Result<Vec<PathBuf>, TestError> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(d)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    v.sort();
    Ok(v)
}

fn lines(p: &Path) -> Result<Vec<String>, TestError> {
    Ok(std::fs::read_to_string(p)?
        .lines()
        .map(str::to_string)
        .collect())
}

// ── the files ────────────────────────────────────────────────────────────

#[test]
fn opening_creates_a_private_directory_and_segment() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-1")?;
    j.append("run_start", json!({}))?;
    let dmode = std::fs::metadata(&d)?.permissions().mode() & 0o777;
    assert_eq!(dmode, 0o700);
    let segs = segments(&d)?;
    assert_eq!(segs.len(), 1);
    assert!(segs[0].ends_with("journal-000001.jsonl"), "{segs:?}");
    let fmode = std::fs::metadata(&segs[0])?.permissions().mode() & 0o777;
    assert_eq!(fmode, 0o600);
    Ok(())
}

#[test]
fn a_second_writer_on_the_same_journal_is_refused() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (_j, _) = Journal::open(&d, "run-1")?;
    match Journal::open(&d, "run-2") {
        Err(JournalError::Locked(path)) => assert_eq!(path, d),
        other => return Err(format!("expected Locked, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn the_lock_is_released_when_the_journal_is_dropped() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    drop(Journal::open(&d, "run-1")?);
    Journal::open(&d, "run-2")?;
    Ok(())
}

// ── records ──────────────────────────────────────────────────────────────

#[test]
fn a_record_carries_version_sequence_time_run_kind_and_body() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-7f3c")?;
    let seq = j.append(
        "action_intent",
        json!({"id": "a-1", "address": "198.51.100.20"}),
    )?;
    assert_eq!(seq, 1);
    let line = &lines(&segments(&d)?[0])?[0];
    let v: serde_json::Value = serde_json::from_str(line)?;
    assert_eq!(v["v"], 1);
    assert_eq!(v["seq"], 1);
    assert_eq!(v["run"], "run-7f3c");
    assert_eq!(v["kind"], "action_intent");
    assert_eq!(v["id"], "a-1");
    assert_eq!(v["address"], "198.51.100.20");
    let ts = v["ts"].as_str().ok_or("ts is a string")?;
    assert!(ts.ends_with('Z'), "UTC: {ts}");
    chrono::DateTime::parse_from_rfc3339(ts)?;
    Ok(())
}

#[test]
fn a_record_is_on_disk_when_append_returns() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-1")?;
    j.append("action_intent", json!({"id": "a-1"}))?;
    // Read through a separate handle, before anything else happens.
    assert_eq!(lines(&segments(&d)?[0])?.len(), 1);
    Ok(())
}

#[test]
fn a_body_cannot_overwrite_the_envelope() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-1")?;
    let err = j
        .append("action_intent", json!({"seq": 99, "prev": "forged"}))
        .err()
        .ok_or("a body naming an envelope field is refused")?;
    assert!(matches!(err, JournalError::ReservedField(_)), "{err:?}");
    Ok(())
}

#[test]
fn each_record_links_to_the_one_before_it() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-1")?;
    j.append("a", json!({}))?;
    j.append("b", json!({}))?;
    let l = lines(&segments(&d)?[0])?;
    let second: serde_json::Value = serde_json::from_str(&l[1])?;
    use sha2::Digest;
    let hex: String = sha2::Sha256::digest(l[0].as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let expected = format!("sha256:{hex}");
    assert_eq!(second["prev"], expected.as_str());
    Ok(())
}

#[test]
fn sequence_numbers_continue_across_restarts() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    {
        let (mut j, _) = Journal::open(&d, "run-1")?;
        j.append("a", json!({}))?;
        j.append("b", json!({}))?;
    }
    let (mut j, recovered) = Journal::open(&d, "run-2")?;
    assert_eq!(recovered.records.len(), 2, "the earlier run is read back");
    assert_eq!(j.append("c", json!({}))?, 3);
    Ok(())
}

#[test]
fn reopening_reads_every_record_back_in_order() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    {
        let (mut j, _) = Journal::open(&d, "run-1")?;
        for k in ["run_start", "action_intent", "action_outcome"] {
            j.append(k, json!({"k": k}))?;
        }
    }
    let (_j, recovered) = Journal::open(&d, "run-2")?;
    let kinds: Vec<&str> = recovered.records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["run_start", "action_intent", "action_outcome"]);
    assert_eq!(recovered.records[1].body["k"], "action_intent");
    Ok(())
}

// ── tampering and damage ─────────────────────────────────────────────────

fn write_three(d: &Path) -> Result<PathBuf, TestError> {
    let (mut j, _) = Journal::open(d, "run-1")?;
    for k in ["a", "b", "c"] {
        j.append(k, json!({"k": k}))?;
    }
    Ok(segments(d)?[0].clone())
}

#[test]
fn an_edited_record_is_detected_and_named() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let text = std::fs::read_to_string(&seg)?.replacen("\"k\":\"b\"", "\"k\":\"B\"", 1);
    std::fs::write(&seg, text)?;
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 3, "the record after the edit"),
        other => return Err(format!("expected Broken, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn a_deleted_record_is_detected() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let l = lines(&seg)?;
    std::fs::write(&seg, format!("{}\n{}\n", l[0], l[2]))?;
    assert!(matches!(
        Journal::open(&d, "run-2"),
        Err(JournalError::Broken { .. })
    ));
    Ok(())
}

#[test]
fn reordered_records_are_detected() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let l = lines(&seg)?;
    std::fs::write(&seg, format!("{}\n{}\n{}\n", l[0], l[2], l[1]))?;
    assert!(matches!(
        Journal::open(&d, "run-2"),
        Err(JournalError::Broken { .. })
    ));
    Ok(())
}

#[test]
fn a_torn_last_line_is_discarded_recorded_and_the_chain_continues() -> Result<(), TestError> {
    // A crash during the write of the last record leaves part of a line. That
    // record's fsync never returned, so nothing it described was done: it is
    // safe to discard, and the discard itself is recorded.
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let mut text = std::fs::read_to_string(&seg)?;
    text.push_str("{\"v\":1,\"seq\":4,\"kind\":\"action_int");
    std::fs::write(&seg, text)?;
    let (mut j, recovered) = Journal::open(&d, "run-2")?;
    assert_eq!(recovered.records.len(), 3);
    assert!(recovered.torn_bytes > 0);
    j.append("d", json!({}))?;
    drop(j);
    let (_j, again) = Journal::open(&d, "run-3")?;
    let kinds: Vec<&str> = again.records.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(kinds, ["a", "b", "c", "torn_tail_discarded", "d"]);
    Ok(())
}

// ── size and retention ───────────────────────────────────────────────────

#[test]
fn a_full_segment_rolls_over_and_the_new_one_opens_with_a_checkpoint() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let limits = JournalLimits {
        segment_bytes: 400,
        ..JournalLimits::default()
    };
    let (mut j, _) = Journal::open_with(&d, "run-1", limits)?;
    for i in 0..10 {
        j.append("action_intent", json!({"i": i, "pad": "x".repeat(40)}))?;
        if j.segment_full() {
            j.roll_over(json!({"owned": []}))?;
        }
    }
    let segs = segments(&d)?;
    assert!(segs.len() >= 2, "{segs:?}");
    for seg in &segs[1..] {
        let first: serde_json::Value = serde_json::from_str(&lines(seg)?[0])?;
        assert_eq!(first["kind"], "checkpoint", "{}", seg.display());
    }
    drop(j);
    Journal::open(&d, "run-2")?;
    Ok(())
}

#[test]
fn pruning_removes_old_closed_segments_and_the_chain_still_verifies() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let limits = JournalLimits {
        segment_bytes: 300,
        ..JournalLimits::default()
    };
    {
        let (mut j, _) = Journal::open_with(&d, "run-1", limits)?;
        for i in 0..12 {
            j.append("action_intent", json!({"i": i, "pad": "x".repeat(40)}))?;
            if j.segment_full() {
                j.roll_over(json!({"owned": []}))?;
            }
        }
    }
    let before = segments(&d)?;
    assert!(before.len() >= 3, "{before:?}");
    // Everything is older than a zero-second window, but the current segment
    // must survive, and so must enough of the chain to verify.
    let removed = Journal::prune(&d, std::time::Duration::ZERO)?;
    let after = segments(&d)?;
    assert_eq!(removed, before.len() - 1);
    assert_eq!(after, vec![before.last().cloned().ok_or("last")?]);
    let (_j, recovered) = Journal::open(&d, "run-2")?;
    assert_eq!(recovered.records[0].kind, "checkpoint");
    Ok(())
}

#[test]
fn pruning_keeps_segments_inside_the_window() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let limits = JournalLimits {
        segment_bytes: 300,
        ..JournalLimits::default()
    };
    {
        let (mut j, _) = Journal::open_with(&d, "run-1", limits)?;
        for i in 0..12 {
            j.append("x", json!({"i": i, "pad": "x".repeat(40)}))?;
            if j.segment_full() {
                j.roll_over(json!({}))?;
            }
        }
    }
    let before = segments(&d)?;
    let removed = Journal::prune(&d, std::time::Duration::from_secs(90 * 86_400))?;
    assert_eq!(removed, 0);
    assert_eq!(segments(&d)?, before);
    Ok(())
}

#[test]
fn the_shipped_limits_match_the_spec() -> Result<(), TestError> {
    let l = JournalLimits::default();
    assert_eq!(l.segment_bytes, 16 * 1024 * 1024);
    assert_eq!(l.retention, std::time::Duration::from_secs(90 * 86_400));
    Ok(())
}

#[test]
fn a_journal_missing_its_beginning_is_detected() -> Result<(), TestError> {
    // Cutting records off the front leaves a first record that is neither
    // record 1 nor a checkpoint, which only pruning may produce.
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let l = lines(&seg)?;
    std::fs::write(&seg, format!("{}\n{}\n", l[1], l[2]))?;
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 2),
        other => return Err(format!("expected Broken, got {other:?}").into()),
    }
    Ok(())
}

/// `append` syncs the line before it returns.
///
/// Durability cannot be observed from a test: a line reaches the page cache,
/// and every read sees it, whether or not it was synced. Only a power loss
/// tells the difference. So this pins the call in the one function every
/// record goes through, and the spec's reason for it: an intent must be on
/// disk before the action it describes starts.
#[test]
fn append_syncs_each_record_before_returning() -> Result<(), TestError> {
    let src = include_str!("../src/journal.rs");
    let start = src.find("pub fn append(").ok_or("append exists")?;
    let body = &src[start..];
    let end = body.find("\n    }\n").ok_or("append ends")?;
    let body = &body[..end];
    let write = body.find(".write_all(").ok_or("append writes")?;
    let sync = body.find(".sync_data()").ok_or("append syncs")?;
    let ok = body.find("Ok(seq)").ok_or("append returns the sequence")?;
    assert!(write < sync && sync < ok, "write, then sync, then return");
    Ok(())
}

#[test]
fn an_edited_sequence_number_on_the_last_record_is_detected() -> Result<(), TestError> {
    // The chain protects every record by the hash in the one after it, which
    // the last record does not have. Its sequence number is checked on its own.
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let text = std::fs::read_to_string(&seg)?.replacen("\"seq\":3", "\"seq\":7", 1);
    std::fs::write(&seg, text)?;
    match Journal::open(&d, "run-2") {
        Err(JournalError::Broken { seq, .. }) => assert_eq!(seq, 7),
        other => return Err(format!("expected Broken, got {other:?}").into()),
    }
    Ok(())
}

// ── reading while sipnab runs ─────────────────────────────────────────────

/// `--journal-show` reads the journal a running sipnab holds: no lock, and no
/// repair of a last line the writer may be in the middle of.
#[test]
fn reading_takes_no_lock_and_repairs_nothing() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let (mut j, _) = Journal::open(&d, "run-a")?;
    j.append("action_intent", json!({"id": "a-1"}))?;
    j.append("action_outcome", json!({"id": "a-1"}))?;
    let seg = segments(&d)?.pop().ok_or("a segment")?;
    let before = std::fs::read(&seg)?;
    // The writer is mid-line.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&seg)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"{\"v\":1,\"seq\""))?;
    let read = Journal::read(&d)?;
    assert_eq!(read.records.len(), 2);
    assert!(read.torn_bytes > 0);
    let after = std::fs::read(&seg)?;
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
    Ok(())
}

#[test]
fn reading_a_damaged_journal_names_the_record() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let seg = write_three(&d)?;
    let mut text = std::fs::read_to_string(&seg)?;
    assert!(text.contains("\"kind\":\"b\""), "{text}");
    text = text.replacen("\"kind\":\"b\"", "\"kind\":\"x\"", 1);
    std::fs::write(&seg, text)?;
    let err = Journal::read(&d).err().ok_or("broken")?;
    assert!(matches!(err, JournalError::Broken { .. }), "{err:?}");
    Ok(())
}

#[test]
fn reading_where_no_journal_is_says_so() -> Result<(), TestError> {
    let (_t, d) = dir()?;
    let err = Journal::read(&d.join("never-written"))
        .err()
        .ok_or("absent")?;
    assert!(matches!(err, JournalError::Absent(_)), "{err:?}");
    Ok(())
}
