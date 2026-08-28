// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(all(unix, feature = "tui"))]
//! AUDIT2 — the TUI operator action trail, driven through the real key path.
//!
//! Every test here presses keys at an `App` built the way the event loop
//! builds one and then reads the file that came out. Nothing calls a recorder
//! directly, because the defect this is written against is not "the recorder
//! is wrong" — it is "the recorder is never reached", which is what a test
//! calling it cannot see.
//!
//! Two of these are PRIVACY assertions rather than behavior ones:
//! [`navigation_keys_leave_no_record`] and
//! [`a_search_term_never_reaches_the_trail`]. They are here so that the day
//! somebody widens the trail to "everything the operator pressed", the suite
//! goes red instead of the search field — which holds phone numbers — quietly
//! ending up in an audit file.

// The low-level SIP fixture builders, shared with `tui_state_test.rs` and
// `tui_snapshot_test.rs` so the three suites cannot drift. Declared at file
// scope so the `#[path]` resolves against `tests/`.
#[path = "support/tui_fixtures.rs"]
mod fixtures;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crossterm::event::KeyCode;
use sipnab::tui::App;
use sipnab::tui::action_trail::ActionTrail;

/// Absolute path to a file under `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// An `App` holding one complete call, with a trail attached at `path`.
fn app_with_trail(path: &Path) -> (App, Arc<ActionTrail>) {
    let trail = Arc::new(ActionTrail::open(path).expect("open trail"));
    let mut app = app_with_a_call();
    app.set_action_trail(Some(Arc::clone(&trail)));
    (app, trail)
}

/// An `App` whose dialog store holds one answered call, so the exporters
/// have something to write.
fn app_with_a_call() -> App {
    let t0 = fixtures::base_ts();
    App::with_processed_messages(vec![
        fixtures::make_invite("trail-1@test", "1001", "1002", t0),
        fixtures::make_response(
            "trail-1@test",
            200,
            "OK",
            "INVITE",
            t0 + chrono::TimeDelta::seconds(1),
        ),
    ])
}

/// Every JSON record in `path`.
fn records(path: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("a trail line is not one JSON object: {e}\n{l}"))
        })
        .collect()
}

/// The records whose `action` is `name`.
fn actions<'a>(recs: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    recs.iter().filter(|r| r["action"] == name).collect()
}

/// Drive the F2 save dialog to completion against `dest`.
fn export_to(app: &mut App, dest: &Path) {
    app.handle_key(KeyCode::F(2));
    app.set_save_path(&dest.to_string_lossy());
    app.handle_key(KeyCode::Enter);
    app.settle_background_work();
}

// ── What the trail must record ─────────────────────────────────────────

/// An export names its destination. This is the question the whole entry was
/// written for: "who exported which calls, when".
#[test]
fn an_export_is_recorded_and_names_its_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let dest = dir.path().join("subset.pcap");
    let (mut app, _trail) = app_with_trail(&trail_path);

    export_to(&mut app, &dest);

    let recs = records(&trail_path);
    let exports = actions(&recs, "export");
    assert_eq!(
        exports.len(),
        1,
        "exactly one export happened and the trail says {}: {recs:#?}",
        exports.len()
    );
    let e = exports[0];
    assert_eq!(
        e["target"],
        serde_json::Value::from(dest.to_string_lossy().to_string()),
        "the trail must name WHERE the calls went: {e}"
    );
    assert_eq!(e["outcome"], "ok", "the export succeeded: {e}");
    assert_eq!(e["format"], "pcap");
    assert_eq!(e["record"], "tui");
    assert!(
        e["caller"]
            .as_str()
            .is_some_and(|c| c.starts_with("tui ") && c.contains("uid=")),
        "the trail must say who was at the terminal, and a terminal has no \
         MCP peer to name: {e}"
    );
    assert!(dest.exists(), "the export itself must have happened");
}

/// An applied filter is recorded, and so is clearing it.
///
/// Both directions, because a trail that recorded only narrowings would leave
/// a reader believing the last filter was still in force over everything that
/// came after it.
#[test]
fn an_applied_filter_and_a_cleared_one_are_both_recorded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, _trail) = app_with_trail(&trail_path);

    // INVITE only: the first checkbox, everything else off.
    let mut methods = [false; 10];
    methods[0] = true;
    app.apply_method_filter_for_test(methods);
    // F9 on the call list drops every narrowing input.
    app.handle_key(KeyCode::F(9));

    let recs = records(&trail_path);
    let applied = actions(&recs, "filter_applied");
    assert_eq!(applied.len(), 1, "the filter was not recorded: {recs:#?}");
    assert!(
        applied[0]["target"].as_str().is_some_and(|t| !t.is_empty()),
        "the record must say WHAT was filtered, or it cannot explain what a \
         later export contained: {}",
        applied[0]
    );
    assert_eq!(
        actions(&recs, "filter_cleared").len(),
        1,
        "clearing the filter was not recorded: {recs:#?}"
    );
}

/// Swapping the capture in-session is recorded with the file that replaced it.
///
/// The swap empties both stores and drops the filter, so every record after it
/// is about a different capture. A trail that did not mark the boundary would
/// attribute the new capture's exports to the old one.
#[test]
fn swapping_the_capture_is_recorded_with_the_new_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let swapped = dir.path().join("swapped.pcap");
    std::fs::copy(fixture("sip_call.pcap"), &swapped).expect("copy fixture");

    let (mut app, _trail) = app_with_trail(&trail_path);
    app.set_open_dir_for_test(dir.path().to_path_buf());
    app.handle_key(KeyCode::Char('O'));
    // The browser lists `..` first; one Down lands on the only capture in the
    // directory.
    app.handle_key(KeyCode::Down);
    app.handle_key(KeyCode::Enter);
    app.settle_background_work();

    let recs = records(&trail_path);
    let swaps = actions(&recs, "capture_swapped");
    assert_eq!(swaps.len(), 1, "the swap was not recorded: {recs:#?}");
    assert!(
        swaps[0]["target"]
            .as_str()
            .is_some_and(|t| t.ends_with("swapped.pcap")),
        "the record must name the capture that replaced the old one: {}",
        swaps[0]
    );
}

/// A refused export is recorded, not skipped.
///
/// "The operator tried to write over the capture they were reading" is exactly
/// what a review is looking for, and a trail holding only what succeeded
/// answers the opposite question.
#[test]
fn a_refused_export_is_recorded_with_its_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let capture = dir.path().join("live.pcap");
    std::fs::copy(fixture("sip_call.pcap"), &capture).expect("copy fixture");

    let (mut app, _trail) = app_with_trail(&trail_path);
    app.set_protected_inputs(sipnab::capture::output_guard::ProtectedInputs::new(
        &[capture.to_string_lossy().to_string()],
        &[],
        false,
    ));
    export_to(&mut app, &capture);

    let recs = records(&trail_path);
    let exports = actions(&recs, "export");
    assert_eq!(exports.len(), 1, "the refusal was not recorded: {recs:#?}");
    assert_eq!(
        exports[0]["outcome"], "refused",
        "a refused export must not read as a completed one: {}",
        exports[0]
    );
    assert!(
        exports[0]["error"].as_str().is_some_and(|e| !e.is_empty()),
        "a refusal with no reason does not answer why: {}",
        exports[0]
    );
}

/// Sequence numbers are contiguous from 1, so a gap means a lost record and
/// nothing else.
///
/// This is the property the whole fail-open decision rests on: a reader
/// detects a missing action by the numbering alone, with no cooperation from
/// the disk that refused to write it.
#[test]
fn the_sequence_numbers_are_contiguous_so_a_gap_means_a_lost_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, _trail) = app_with_trail(&trail_path);

    let mut methods = [false; 10];
    methods[0] = true;
    app.apply_method_filter_for_test(methods);
    export_to(&mut app, &dir.path().join("one.pcap"));
    app.handle_key(KeyCode::F(9));
    export_to(&mut app, &dir.path().join("two.pcap"));

    let seqs: Vec<u64> = records(&trail_path)
        .iter()
        .map(|r| r["seq"].as_u64().expect("seq"))
        .collect();
    assert!(
        seqs.len() >= 4,
        "too few records to prove anything: {seqs:?}"
    );
    let want: Vec<u64> = (1..=seqs.len() as u64).collect();
    assert_eq!(
        seqs, want,
        "the numbering must be contiguous, or a reader cannot tell a gap from \
         the way records are numbered"
    );
}

/// The closing record names what the session was offered and what it lost.
///
/// The one thing the sequence gap cannot cover: records lost at the TAIL leave
/// no upper bound, so a file that simply stops looks like a session that
/// simply ended.
#[test]
fn the_closing_record_names_what_the_session_offered_and_lost() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, trail) = app_with_trail(&trail_path);
    export_to(&mut app, &dir.path().join("one.pcap"));
    assert_eq!(trail.close_session(), None, "the close must succeed");

    let recs = records(&trail_path);
    let last = recs.last().expect("a closing record");
    assert_eq!(
        last["action"], "session_end",
        "no closing record: {recs:#?}"
    );
    assert_eq!(last["actions_lost"], 0);
    assert_eq!(
        last["actions_offered"], 1,
        "the count must match what the session actually recorded: {last}"
    );
    assert_eq!(last["outcome"], "ok");
}

/// The trail file is owner-only: a filter expression and an export path are
/// both operator text and both routinely hold a number.
#[test]
fn the_trail_file_is_not_readable_by_other_accounts() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, _trail) = app_with_trail(&trail_path);
    export_to(&mut app, &dir.path().join("one.pcap"));
    let mode = std::fs::metadata(&trail_path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the trail carries operator text");
}

// ── What the trail must NOT record ─────────────────────────────────────

/// Navigation writes nothing.
///
/// A privacy and a legibility assertion at once. The TUI binds 38 keys and
/// almost all of them move a cursor; a trail that recorded them would be
/// unreadable at review time, which is how an audit file stops being read.
#[test]
fn navigation_keys_leave_no_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, _trail) = app_with_trail(&trail_path);

    for key in [
        KeyCode::Down,
        KeyCode::Up,
        KeyCode::Tab,
        KeyCode::PageDown,
        KeyCode::PageUp,
        KeyCode::Home,
        KeyCode::End,
        KeyCode::Enter,
        KeyCode::Esc,
        KeyCode::F(1),
        KeyCode::Esc,
    ] {
        app.handle_key(key);
    }

    let recs = records(&trail_path);
    assert!(
        recs.is_empty(),
        "moving around a capture is not a state change and must not be \
         recorded: {recs:#?}"
    );
}

/// A search term never reaches the trail — not the text, not the fact that a
/// search happened.
///
/// The sharpest privacy assertion in this file. The TUI's search field is
/// where an operator types a phone number, and `--tui-audit-file` is a file
/// somebody keeps. This test fails the moment a keystroke logger, a "search
/// applied" record, or a status-line copy puts that text on disk.
#[test]
fn a_search_term_never_reaches_the_trail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, _trail) = app_with_trail(&trail_path);

    // A number nothing else in this test could produce.
    const NUMBER: &str = "15558675309";
    app.handle_key(KeyCode::Char('/'));
    for c in NUMBER.chars() {
        app.handle_key(KeyCode::Char(c));
    }
    app.handle_key(KeyCode::Enter);
    assert_eq!(
        app.search_query(),
        NUMBER,
        "the search itself must still work, or this test proves nothing"
    );

    // Export afterwards, so the file is not empty for an uninteresting
    // reason: the assertion below has to be about the search and not about
    // the trail never being written to at all.
    export_to(&mut app, &dir.path().join("one.pcap"));

    let text = std::fs::read_to_string(&trail_path).expect("read trail");
    assert!(
        !text.contains(NUMBER),
        "the search term reached the audit file: {text}"
    );
    assert!(
        !text.contains("search"),
        "even the FACT of a search must stay out, or the trail says which \
         records to correlate with a wiretap request: {text}"
    );
    assert!(
        text.contains("\"action\":\"export\""),
        "the export must still be there, or this test passes vacuously: {text}"
    );
}

/// Off by default: no trail attached, nothing written, and every action still
/// works.
#[test]
fn no_record_is_written_when_no_trail_is_attached() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("one.pcap");
    let mut app = app_with_a_call();
    assert!(app.action_trail().is_none(), "the default is off");

    export_to(&mut app, &dest);

    assert!(dest.exists(), "the export must still happen");
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read tempdir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        left,
        vec!["one.pcap".to_string()],
        "a session that was not asked to record anything wrote {left:?}"
    );
}

// ── The refused-write decision: FAIL OPEN, loudly ──────────────────────

/// THE DECISION, asserted. A write that fails does NOT stop the session: the
/// export still happens, the trail marks itself incomplete, the status line
/// says so, and the exit notice names the path and the count.
///
/// `/dev/full` opens cleanly and fails every write with `ENOSPC`, which is the
/// full-disk condition itself rather than a mock of it. The alternative rule —
/// stop the TUI — would mean an operator holding a live capture that exists
/// nowhere else loses it because a log partition filled, which is destroying
/// the evidence in order to protect the record of it.
#[test]
fn a_refused_write_does_not_stop_the_session_and_says_so_loudly() {
    if !Path::new("/dev/full").exists() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("one.pcap");
    let (mut app, trail) = app_with_trail(Path::new("/dev/full"));

    export_to(&mut app, &dest);

    assert!(
        dest.exists(),
        "the export must still have happened -- the whole point of failing \
         open is that the operator's work survives the audit file's disk"
    );
    assert!(
        trail.is_incomplete(),
        "a trail that lost a record must know it has"
    );
    assert_eq!(trail.lost(), 1, "one action was offered and lost");
    assert_eq!(trail.offered(), 1);
    let status = app.status_error().unwrap_or_default();
    assert!(
        status.contains("AUDIT TRAIL INCOMPLETE"),
        "the operator must find out while they can still do something about \
         it: {status:?}"
    );
    let notice = trail.exit_notice().expect("an exit notice");
    assert!(
        notice.contains("/dev/full") && notice.contains("INCOMPLETE"),
        "the notice must name the path and say what is wrong: {notice}"
    );
    assert!(
        notice.contains("1 of 1"),
        "the notice must say how much is missing: {notice}"
    );
}

/// A refused write consumes the sequence number, so the gap a reader sees is
/// real.
///
/// This is the mechanism the decision above rests on, asserted on the sink
/// itself: if the number were allocated only on success, records would stay
/// contiguous across a lost write and the loss would be invisible in the file
/// — which is silently dropping records, the one option the entry ruled out.
#[test]
fn a_refused_write_still_consumes_its_sequence_number() {
    if !Path::new("/dev/full").exists() {
        return;
    }
    // The mechanism, asserted on the sink itself: a write that failed must
    // still have SPENT its number. `records_written` is the next sequence
    // minus one, so it is exactly "how many numbers this sink has handed out"
    // -- which is what a reader counts against the lines actually present.
    let sink = sipnab::app::audit::AuditSink::open(Path::new("/dev/full"))
        .expect("open /dev/full for append");
    assert!(
        sink.append_with(|seq, ts| format!("{{\"seq\":{seq},\"ts\":\"{ts}\"}}"))
            .is_err(),
        "/dev/full must refuse the write, or this test proves nothing"
    );
    assert_eq!(
        sink.records_written(),
        1,
        "the sequence number must be spent by a write that FAILED. Allocated \
         only on success, the numbering would stay contiguous across a lost \
         record and the loss would be invisible in the file -- which is \
         silently dropping records, the one option AUDIT2 ruled out"
    );

    // And the trail on top of it counts the loss, so the exit notice can
    // report how much is missing.
    let trail = ActionTrail::open(Path::new("/dev/full")).expect("open /dev/full");
    for _ in 0..3 {
        trail.record(&sipnab::tui::action_trail::ActionRecord {
            action: "export",
            target: "/tmp/x.pcap",
            format: "pcap",
            outcome: "ok",
            error: "",
        });
    }
    assert_eq!(
        trail.lost(),
        3,
        "every refused record must be counted, or the exit notice \
         under-reports the damage"
    );
    assert!(trail.is_incomplete());
}

/// FAIL CLOSED on the OPEN, which is the opposite call to the one above and
/// deliberately so: refusing here costs nothing, because the terminal has not
/// been taken and no packet has been read.
///
/// Runs the real binary, because "stops the run" is a process exit code and
/// nothing an `App` can be asked about.
#[test]
fn a_trail_path_that_cannot_be_opened_stops_the_run_before_the_terminal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("no-such-dir").join("trail.jsonl");
    let pcap = fixture("sip_call.pcap");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-I",
            &pcap.to_string_lossy(),
            "--tui-audit-file",
            &path.to_string_lossy(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn sipnab");
    assert!(!out.status.success(), "the run must not succeed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&path.to_string_lossy().to_string()) && stderr.contains("--tui-audit-file"),
        "the message must name the flag and the path that failed: {stderr}"
    );
}

/// `-N` plus `--tui-audit-file` is REFUSED, not quietly accepted.
///
/// There is no operator and no terminal in headless mode, so accepting it
/// would create the exact state the flag exists to prevent: a run that reads
/// as audited and has no trail. The message has to name the flag that does
/// cover a headless run, because "wrong mode" and "wrong flag" are otherwise
/// indistinguishable to whoever wrote the command.
#[test]
fn the_flag_is_refused_in_headless_mode_rather_than_silently_doing_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("trail.jsonl");
    let pcap = fixture("sip_call.pcap");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            &pcap.to_string_lossy(),
            "--tui-audit-file",
            &path.to_string_lossy(),
        ])
        .output()
        .expect("spawn sipnab");
    assert!(!out.status.success(), "the run must not succeed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--run-provenance-file"),
        "the refusal must point at the flag that DOES record a headless run: \
         {stderr}"
    );
    assert!(
        !path.exists(),
        "a refused run must not leave a trail file behind"
    );
}

/// A trail that never failed reports nothing at exit and closes cleanly.
///
/// The other half of the decision: failing open must not mean warning about
/// nothing. A notice on every session is a notice nobody reads.
#[test]
fn a_whole_trail_reports_nothing_at_exit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let trail_path = dir.path().join("trail.jsonl");
    let (mut app, trail) = app_with_trail(&trail_path);
    export_to(&mut app, &dir.path().join("one.pcap"));
    assert!(!trail.is_incomplete());
    assert_eq!(trail.exit_notice(), None);
    assert_eq!(trail.close_session(), None);
}
