// SPDX-License-Identifier: MIT OR Apache-2.0

//! A run that could not do what was asked must not exit 0 (VAL2).
//!
//! sipnab detected every condition tested here long before this file existed,
//! and described each one accurately on stderr. Nothing downstream could see
//! it: a truncated pcap and a `--plugin` that would not load both exited 0
//! with a report that looked whole, so `sipnab -I x.pcap --json-dialogs &&
//! next-step` fed the next step a partial answer and `$?` said everything was
//! fine.
//!
//! `docs/fault-model.md` already states the rule for the LIVE capture path:
//! *"The exit status is the only place that distinction survives: downgrade
//! that join to a warning and exit 0, and an incomplete run reads exactly like
//! a whole one to anything checking `$?`."* These tests are that paragraph
//! applied to the FILE path, plus the machine-readable half of it — because a
//! consumer reading `--json-dialogs` on stdout never sees `$?` at all.
//!
//! # Why these run the real binary
//!
//! Every assertion here is about an EFFECT a script can observe: the process's
//! exit code, the bytes on its stdout, the bytes on its stderr. A unit test on
//! the predicate would pass with the predicate wired to nothing, which is the
//! precise shape of the defect being fixed.
//!
//! # Why every test asserts output as well as a code
//!
//! A test that only asserts "non-zero" passes when the binary failed to build,
//! when the fixture was missing, and when the arguments were rejected — none of
//! which is the behavior under test. So each one asserts the SPECIFIC code and
//! that the run produced the output it should have produced, which makes
//! "broken harness" and "correct rejection" different outcomes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Exit code the run is expected to return once it has failed to do what was
/// asked. Not hard-coded from taste: `documented_exit_code_matches_the_binary`
/// reads it back out of `docs/cli-reference.md` and compares.
const EXPECTED_FAILURE_CODE: i32 = 1;

/// The committed fixture every case reads. Small, and already used by other
/// suites, so a truncation of it is cheap and reproducible.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stun_sdp_mismatch.pcap")
}

/// Run the binary and return the whole outcome.
fn sipnab(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .output()
        .expect("the sipnab binary runs")
}

/// The exit code, or a message naming the signal that replaced it.
///
/// `Option::None` from `ExitStatus::code()` means the process was killed by a
/// signal; treating that as "non-zero, good enough" would let a segfault pass
/// a test about exit codes.
fn code_of(out: &Output) -> i32 {
    match out.status.code() {
        Some(c) => c,
        None => panic!(
            "sipnab was killed by a signal, not exited: {:?}",
            out.status
        ),
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Copy the leading 60% of the fixture into `dir`, producing a pcap whose last
/// record is cut in half — exactly what a `tcpdump` killed mid-write leaves
/// behind, and what libpcap reports as `truncated dump file`.
fn truncated_capture(dir: &Path) -> PathBuf {
    let whole = std::fs::read(fixture()).expect("fixture is readable");
    let cut = whole.len() * 60 / 100;
    let path = dir.join("half.pcap");
    std::fs::write(&path, &whole[..cut]).expect("truncated fixture is writable");
    path
}

/// Every NDJSON line of a `--json-dialogs` run, parsed.
fn ndjson(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("every --json-dialogs line is JSON: {e}: {l}"))
        })
        .collect()
}

/// The run-integrity trailer, if the run emitted one.
fn marker(lines: &[serde_json::Value]) -> Option<serde_json::Value> {
    lines
        .iter()
        .find(|v| v.get("sipnab_run").is_some())
        .map(|v| v["sipnab_run"].clone())
}

/// Lines that are dialogs rather than the trailer.
fn dialog_lines(lines: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    lines
        .iter()
        .filter(|v| v.get("sipnab_run").is_none())
        .collect()
}

// ── The input was not read in full ────────────────────────────────────────

#[test]
fn a_truncated_capture_exits_non_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let half = truncated_capture(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &half.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);

    // The specific code, not merely "non-zero": a binary that failed to build
    // or rejected the arguments also exits non-zero, and neither is this.
    assert_eq!(
        code_of(&out),
        EXPECTED_FAILURE_CODE,
        "stdout={} stderr={}",
        stdout_of(&out),
        stderr_of(&out)
    );
    // And the run really did the work — a partial read is still worth looking
    // at, and this is what tells a rejected invocation from a completed one.
    let lines = ndjson(&stdout_of(&out));
    assert!(
        !dialog_lines(&lines).is_empty(),
        "a truncated capture must still report the dialogs it did read: {}",
        stdout_of(&out)
    );
}

#[test]
fn an_intact_capture_still_exits_zero() {
    // The regression that matters most. Every other test here can be satisfied
    // by a binary that always fails; this is the one that cannot.
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        0,
        "an intact capture must still exit 0; stderr={}",
        stderr_of(&out)
    );
    let lines = ndjson(&stdout_of(&out));
    assert!(!dialog_lines(&lines).is_empty(), "and must report dialogs");
}

#[test]
fn a_truncated_capture_marks_its_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let half = truncated_capture(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &half.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let lines = ndjson(&stdout_of(&out));
    let m = marker(&lines).unwrap_or_else(|| {
        panic!(
            "a truncated capture's JSON must carry the run-integrity trailer: {}",
            stdout_of(&out)
        )
    });

    assert_eq!(
        m["input_complete"],
        serde_json::json!(false),
        "the trailer must say the input was not complete: {m}"
    );
    assert_eq!(m["files"]["given"], serde_json::json!(1), "{m}");
    assert_eq!(m["files"]["read_in_full"], serde_json::json!(0), "{m}");
    assert_eq!(m["files"]["stopped_early"], serde_json::json!(1), "{m}");
    // The stdout half must agree with the `$?` half, or a consumer of one
    // reaches a different verdict than a consumer of the other.
    assert_eq!(code_of(&out), EXPECTED_FAILURE_CODE);
    // And it must name a reason, not merely raise a flag: a bare `false` says
    // something is wrong without saying what, which is the half-answer the
    // exit code alone already gives.
    let reasons = m["reasons"].as_array().cloned().unwrap_or_default();
    assert!(
        reasons.iter().any(|r| r
            .as_str()
            .unwrap_or_default()
            .contains("not read to the end")),
        "{m}"
    );
}

#[test]
fn an_intact_capture_does_not_mark_its_json() {
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let lines = ndjson(&stdout_of(&out));
    assert!(
        marker(&lines).is_none(),
        "a clean run must declare nothing: {}",
        stdout_of(&out)
    );
    assert!(
        !dialog_lines(&lines).is_empty(),
        "and the absence must be because the run was clean, not because it \
         produced nothing: {}",
        stdout_of(&out)
    );
}

#[test]
fn a_truncated_capture_marks_its_report() {
    let dir = tempfile::tempdir().expect("tempdir");
    let half = truncated_capture(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &half.display().to_string(),
        "--report",
        "--no-cli-print",
    ]);
    let text = stdout_of(&out);
    assert!(
        text.contains("INCOMPLETE RUN"),
        "--report must carry the marker too — a reader looking at the table \
         has no $? in front of them: {text}"
    );
    assert!(
        text.contains("not read to the end"),
        "and it must say what happened: {text}"
    );
    assert_eq!(code_of(&out), EXPECTED_FAILURE_CODE);
}

#[test]
fn an_intact_capture_does_not_mark_its_report() {
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--report",
        "--no-cli-print",
    ]);
    let text = stdout_of(&out);
    assert_eq!(code_of(&out), 0, "stderr={}", stderr_of(&out));
    assert!(
        !text.contains("INCOMPLETE"),
        "a clean report must be unchanged: {text}"
    );
    assert!(
        !text.trim().is_empty(),
        "and it must actually be a report: {text}"
    );
}

#[test]
fn the_human_signal_survives_the_machine_one() {
    // The stderr lines were never the problem — they were the only thing that
    // worked. Trading them for the exit code would be a different defect with
    // the same shape.
    let dir = tempfile::tempdir().expect("tempdir");
    let half = truncated_capture(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &half.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    let err = stderr_of(&out);
    assert!(
        err.contains("truncated dump file"),
        "libpcap's reason must still print: {err}"
    );
    assert!(
        err.contains("Stopped reading"),
        "the per-file line must still print: {err}"
    );
    assert!(
        err.contains("0 of 1 file(s) read in full"),
        "the closing tally must still print: {err}"
    );
    assert!(
        err.contains("1 stopped early"),
        "and must still say how many stopped early: {err}"
    );
}

// ── A requested --plugin did not load ─────────────────────────────────────

/// A conforming plugin, assembled from WAT so the test needs no wasm32
/// toolchain. Mirrors the host's own fixtures in `src/plugin/mod.rs`.
#[cfg(feature = "plugins")]
fn loadable_plugin(dir: &Path) -> PathBuf {
    let abi = sipnab::plugin::ABI_VERSION;
    let wat = format!(
        r#"(module
             (memory (export "memory") 2)
             (func (export "sipnab_plugin_abi_version") (result i32) (i32.const {abi}))
             (func (export "sipnab_alloc") (param i32) (result i32) (i32.const 2048))
             (func (export "sipnab_dealloc") (param i32 i32))
             (func (export "sipnab_analyze") (param i32 i32) (result i64) (i64.const 0)))"#
    );
    let bytes = wat::parse_str(&wat).expect("fixture WAT assembles");
    let path = dir.join("ok.wasm");
    std::fs::write(&path, bytes).expect("plugin is writable");
    path
}

#[cfg(feature = "plugins")]
#[test]
fn an_absent_plugin_exits_non_zero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("not-here.wasm");
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--plugin",
        &missing.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        EXPECTED_FAILURE_CODE,
        "stderr={}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("cannot read plugin"),
        "the human signal must survive: {}",
        stderr_of(&out)
    );
    // The capture itself was whole, so the dialogs are still there and the
    // trailer must blame the plugin rather than the input.
    let lines = ndjson(&stdout_of(&out));
    assert!(!dialog_lines(&lines).is_empty(), "{}", stdout_of(&out));
    let m = marker(&lines).unwrap_or_else(|| panic!("no trailer: {}", stdout_of(&out)));
    assert_eq!(m["plugins"]["requested"], serde_json::json!(1), "{m}");
    assert_eq!(m["plugins"]["failed"], serde_json::json!(1), "{m}");
    assert_eq!(m["plugins"]["loaded"], serde_json::json!(0), "{m}");
    assert_eq!(
        m["files"]["read_in_full"],
        serde_json::json!(1),
        "the capture was whole; only the plugin failed: {m}"
    );
}

#[cfg(feature = "plugins")]
#[test]
fn an_oversized_plugin_exits_non_zero() {
    // A second, distinct failure mode: the file exists and is readable, and is
    // refused by the size cap before a single byte reaches the interpreter.
    //
    // The cap is a private constant, so the size is written here — and the
    // stderr assertion below is the tripwire that keeps that from going stale
    // silently. Raise the cap without touching this file and the run fails for
    // a different reason (not valid WASM), which this test then reports.
    let dir = tempfile::tempdir().expect("tempdir");
    let fat = dir.path().join("fat.wasm");
    std::fs::write(&fat, vec![0u8; 16 * 1024 * 1024 + 1]).expect("oversized plugin is writable");
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--plugin",
        &fat.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        EXPECTED_FAILURE_CODE,
        "stderr={}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("plugin limit"),
        "the size cap must be the reason, not some later one: {}",
        stderr_of(&out)
    );
    let m = marker(&ndjson(&stdout_of(&out)))
        .unwrap_or_else(|| panic!("no trailer: {}", stdout_of(&out)));
    assert_eq!(m["plugins"]["failed"], serde_json::json!(1), "{m}");
}

#[cfg(feature = "plugins")]
#[test]
fn a_plugin_that_is_not_wasm_exits_non_zero() {
    // A third failure mode, and the one the reproducer in the backlog uses:
    // the path resolves and reads, and holds no module.
    let dir = tempfile::tempdir().expect("tempdir");
    let junk = dir.path().join("junk.wasm");
    std::fs::write(&junk, b"this is not a wasm module").expect("junk plugin is writable");
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--plugin",
        &junk.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        EXPECTED_FAILURE_CODE,
        "stderr={}",
        stderr_of(&out)
    );
    assert!(
        stderr_of(&out).contains("not a valid WASM module"),
        "{}",
        stderr_of(&out)
    );
}

#[cfg(feature = "plugins")]
#[test]
fn a_plugin_that_loads_still_exits_zero() {
    // The other regression guard. A fix that failed every run with `--plugin`
    // would pass all three tests above.
    let dir = tempfile::tempdir().expect("tempdir");
    let good = loadable_plugin(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--plugin",
        &good.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        0,
        "a plugin that loads must not fail the run; stderr={}",
        stderr_of(&out)
    );
    let lines = ndjson(&stdout_of(&out));
    assert!(
        marker(&lines).is_none(),
        "and must declare nothing: {}",
        stdout_of(&out)
    );
    assert!(!dialog_lines(&lines).is_empty(), "{}", stdout_of(&out));
}

#[cfg(feature = "plugins")]
#[test]
fn one_failed_plugin_among_several_is_counted_as_one() {
    // The `--on-dialog-exec` standard: distinguish "none ran" from "one of
    // three did not". A flag cannot; the counts can.
    let dir = tempfile::tempdir().expect("tempdir");
    let good = loadable_plugin(dir.path());
    let missing = dir.path().join("not-here.wasm");
    let out = sipnab(&[
        "-N",
        "-I",
        &fixture().display().to_string(),
        "--plugin",
        &good.display().to_string(),
        "--plugin",
        &missing.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(code_of(&out), EXPECTED_FAILURE_CODE);
    let m = marker(&ndjson(&stdout_of(&out)))
        .unwrap_or_else(|| panic!("no trailer: {}", stdout_of(&out)));
    assert_eq!(m["plugins"]["requested"], serde_json::json!(2), "{m}");
    assert_eq!(m["plugins"]["loaded"], serde_json::json!(1), "{m}");
    assert_eq!(m["plugins"]["failed"], serde_json::json!(1), "{m}");
}

// ── The published contract ────────────────────────────────────────────────

#[test]
fn documented_exit_code_matches_the_binary() {
    // `docs/cli-reference.md` says "Scripts can rely on these" above its
    // exit-code table. A gate that only checked the binary against a constant
    // in this file would let the code and the published contract drift apart
    // while both stayed internally consistent — so this reads the number out
    // of the table and runs the binary against it.
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/cli-reference.md"),
    )
    .expect("docs/cli-reference.md is readable");

    let table = doc
        .split("## Exit codes")
        .nth(1)
        .unwrap_or_else(|| panic!("docs/cli-reference.md has an '## Exit codes' section"));

    // The row that claims this class of failure. Matched on the words the
    // table itself uses, so renaming the row is a deliberate act that shows up
    // here rather than a silent drift.
    let row = table
        .lines()
        .take_while(|l| !l.starts_with("## ") || l.starts_with("## Exit codes"))
        .find(|l| l.starts_with('|') && l.contains("capture error"))
        .unwrap_or_else(|| panic!("the exit-code table has no row for a capture error:\n{table}"));

    let documented: i32 = row
        .split('|')
        .nth(1)
        .unwrap_or_default()
        .trim()
        .trim_matches('`')
        .parse()
        .unwrap_or_else(|e| panic!("the code cell of {row:?} is a number: {e}"));

    assert_eq!(
        documented, EXPECTED_FAILURE_CODE,
        "this suite and the published table must agree"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let half = truncated_capture(dir.path());
    let out = sipnab(&[
        "-N",
        "-I",
        &half.display().to_string(),
        "--json-dialogs",
        "--no-cli-print",
    ]);
    assert_eq!(
        code_of(&out),
        documented,
        "the binary must return the code docs/cli-reference.md publishes for a \
         capture error; stderr={}",
        stderr_of(&out)
    );
}

#[test]
fn the_exit_code_table_documents_the_partial_read() {
    // The other half of the doc gate: the table must actually describe the new
    // behavior, not merely happen to carry a compatible number. Without this
    // the fix ships with a contract that never mentions it.
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/cli-reference.md"),
    )
    .expect("docs/cli-reference.md is readable");
    let table = doc
        .split("## Exit codes")
        .nth(1)
        .unwrap_or_else(|| panic!("docs/cli-reference.md has an '## Exit codes' section"));
    let row = table
        .lines()
        .find(|l| l.starts_with('|') && l.contains("capture error"))
        .unwrap_or_default();
    assert!(
        row.contains("read in full") || row.contains("not read to the end"),
        "the `1` row must say that a capture file not read to the end lands \
         here: {row}"
    );
    assert!(
        row.contains("--plugin"),
        "and that a --plugin that would not load lands here: {row}"
    );
}

/// Every line of a clean `--json-dialogs` run must be a dialog.
///
/// The invariant a consumer actually relies on, and the one the run trailer
/// broke. `tests/filter_corpus_test.rs` reads each line as a dialog — as any
/// downstream reader would — so a run-scoped object in the stream counted as
/// an extra dialog, and it appeared in both a filter's results and its
/// negation's, which is logically impossible for a real row.
///
/// Caught only by the corpus gate: the trailer fired for 15 messages dropped
/// by idle compaction on a healthy 3 MB capture, and retention fires on most
/// long captures. No fixture here is large enough to compact, which is exactly
/// why this test pins the INVARIANT rather than the retention case — it fails
/// for any future line that is not a dialog, whatever puts it there.
///
/// Be clear about what that does NOT cover, because the mutation says so:
/// reverting `ndjson_line` to its old `is_degraded()` gate — the actual
/// defect — leaves THIS test green and is caught only by
/// `run_integrity::tests::retention_is_reported_without_failing_the_run`.
/// Forcing compaction end to end would need `[limits] idle_compact_after_secs`
/// from a config file, and there is no `--config` flag: it is discovered from
/// a path, so planting one is the shared-state poisoning this suite has been
/// bitten by before. The unit test guards the retention case; this one guards
/// the invariant. Emitting the trailer unconditionally fails four tests here,
/// so the pair does hold the ground between them.
#[test]
fn every_line_of_a_clean_json_dialogs_run_is_a_dialog() {
    let out = sipnab(&[
        "-N",
        "-I",
        "tests/pcap-samples/sip-rtp-g711.pcap",
        "--json-dialogs",
        "--no-cli-print",
        "--quiet",
    ]);
    assert_eq!(out.status.code(), Some(0), "the control run must be clean");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert!(
        !lines.is_empty(),
        "no JSON emitted at all — this test would pass vacuously"
    );
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("unparseable line: {e}\n{line}"));
        assert!(
            v.get("call_id").is_some(),
            "a clean run put a line in the dialog stream that is not a dialog. \
             A consumer iterating lines counts it as one:\n{line}"
        );
        assert!(
            v.get("sipnab_run").is_none(),
            "the run trailer must not appear on a complete read:\n{line}"
        );
    }
}

/// A partial read adds exactly one line, and it is unmistakably not a dialog.
///
/// The other half: withholding the trailer from clean runs must not withhold
/// it when the answer really is partial. It carries a key no dialog has, so a
/// consumer that checks can tell them apart rather than guessing.
#[test]
fn a_partial_read_adds_exactly_one_line_and_it_is_not_a_dialog() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = Path::new("tests/pcap-samples/sip-rtp-g711.pcap");
    let whole = std::fs::read(src).expect("read fixture");
    let cut = dir.path().join("truncated.pcap");
    std::fs::write(&cut, &whole[..whole.len() * 60 / 100]).expect("write truncated");

    let clean = sipnab(&[
        "-N",
        "-I",
        &src.to_string_lossy(),
        "--json-dialogs",
        "--no-cli-print",
        "--quiet",
    ]);
    let partial = sipnab(&[
        "-N",
        "-I",
        &cut.to_string_lossy(),
        "--json-dialogs",
        "--no-cli-print",
        "--quiet",
    ]);
    assert_eq!(partial.status.code(), Some(1), "a partial read exits 1");

    let count = |o: &Output| -> (usize, usize) {
        let s = String::from_utf8_lossy(&o.stdout);
        let mut dialogs = 0;
        let mut trailers = 0;
        for line in s.lines().filter(|l| l.starts_with('{')) {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("sipnab_run").is_some() {
                trailers += 1;
            } else if v.get("call_id").is_some() {
                dialogs += 1;
            }
        }
        (dialogs, trailers)
    };
    let (_, clean_trailers) = count(&clean);
    let (_, partial_trailers) = count(&partial);
    assert_eq!(clean_trailers, 0, "a complete read declares nothing");
    assert_eq!(
        partial_trailers, 1,
        "a partial read must declare itself exactly once"
    );
}
