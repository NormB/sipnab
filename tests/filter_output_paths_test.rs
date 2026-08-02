// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--filter` must narrow the post-capture output paths, not just the
//! per-message stream.
//!
//! The compiled DSL expression was applied only while packets streamed past
//! (`--json` / the per-message printer). `--report` and `--json-dialogs` are
//! generated from the final store contents *after* the capture ends, and that
//! code iterated the whole dialog store: every valid expression returned the
//! entire capture, silently, exit 0. An operator narrowing a large capture to
//! its failed calls got all of it back and had no signal that the filter had
//! done nothing.
//!
//! These tests pin the selection to ROWS, not to parseability — a filter that
//! parses and then selects everything is exactly the defect. Every expected
//! count below is cross-checked two ways: against the tool's own unfiltered
//! per-dialog JSON (rendered by `output::json`, a different code path from the
//! `sip::dsl` evaluator under test) and against arithmetic over the whole
//! capture (the parts must sum to the whole and none may be the whole).
#![cfg(feature = "native")]

#[path = "support/run.rs"]
mod run_support;

/// 1334 dialogs: a SIPp run of REGISTERs plus rejected calls. Chosen because
/// it splits cleanly into two states, so "the filter selected everything" and
/// "the filter selected the right rows" cannot be confused.
const BRANCH: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";

/// Two dialogs, one RTP stream linked to each — enough to prove the report's
/// stream tables follow the dialog selection.
const G711: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Run the binary and require a clean exit.
///
/// A bare field name (`--filter no_media`) is a parse error and exits 2; a
/// caller that only counts stdout lines reads that as "zero rows matched".
/// Asserting the code here makes a dead process impossible to mistake for a
/// selective filter.
///
/// # Arguments
/// * `args` — CLI arguments passed to the binary.
///
/// # Returns
/// Captured stdout.
///
/// # Panics
/// When the process exits non-zero, with its stderr attached.
fn run_ok(args: &[&str]) -> String {
    let (stdout, stderr, code) = run_support::run(args, Some("error"));
    assert_eq!(code, Some(0), "sipnab {args:?} exited {code:?}\n{stderr}");
    stdout
}

/// Every `call_id` in an NDJSON dialog stream, in emission order.
fn call_ids(ndjson: &str) -> Vec<String> {
    ndjson
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("dialog line must be JSON");
            v["call_id"].as_str().unwrap_or_default().to_string()
        })
        .collect()
}

/// Assert two dialog selections hold the same rows, reporting the sizes and
/// the disagreement rather than dumping every Call-ID: a 1334-row diff buries
/// the one number that identifies the failure.
fn assert_same_rows(got: &[String], expected: &[String], what: &str) {
    let got_set: std::collections::BTreeSet<&String> = got.iter().collect();
    let want_set: std::collections::BTreeSet<&String> = expected.iter().collect();
    let missing = want_set.difference(&got_set).count();
    let extra = got_set.difference(&want_set).count();
    assert_eq!(
        (missing, extra),
        (0, 0),
        "{what}: selected {} rows, expected {} ({missing} missing, {extra} unexpected)",
        got.len(),
        expected.len(),
    );
}

/// `call_id`s of the dialogs whose unfiltered JSON has the given `state`.
///
/// The independent expectation: `output::json` renders `state` from
/// `SipDialog::state()` while the DSL compares against `sip::dsl::state_to_str`
/// — two renderings of the same field, so agreement is a real cross-check
/// rather than the evaluator agreeing with itself.
fn call_ids_in_state(ndjson: &str, state: &str) -> Vec<String> {
    ndjson
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("dialog line must be JSON");
            (v["state"].as_str() == Some(state))
                .then(|| v["call_id"].as_str().unwrap_or_default().to_string())
        })
        .collect()
}

/// The dialog-table rows of a `--report`, as `(call_id, state)` pairs.
///
/// The table is `Call-ID From To State ...` in fixed-width columns; the fields
/// themselves are SIP tokens and never contain spaces, so splitting on
/// whitespace survives a value that overflows its column.
fn report_rows(report: &str) -> Vec<(String, String)> {
    report
        .lines()
        .skip_while(|l| !l.starts_with("---"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let call_id = it.next().unwrap_or_default().to_string();
            let state = it.nth(2).unwrap_or_default().to_string();
            (call_id, state)
        })
        .collect()
}

/// SSRC column of each row under the report's "RTP Streams:" heading.
fn report_stream_ssrcs(report: &str) -> Vec<String> {
    report
        .lines()
        .skip_while(|l| !l.starts_with("RTP Streams:"))
        .skip(3)
        .take_while(|l| l.starts_with("0x"))
        .map(|l| l.split_whitespace().next().unwrap_or_default().to_string())
        .collect()
}

// ── --json-dialogs ──────────────────────────────────────────────────

/// `--filter "state == 'Failed'"` must emit the failed dialogs and nothing
/// else. It used to emit all 1334.
#[test]
fn json_dialogs_filter_selects_only_matching_dialogs() {
    let all = run_ok(&["-N", "-I", BRANCH, "--no-cli-print", "--json-dialogs"]);
    let expected = call_ids_in_state(&all, "Failed");

    // Ground truth, checkable by hand: the fixture holds 1334 dialogs, 127 of
    // them Failed. `sipnab -N -I <fixture> --json-dialogs | grep -c Failed`.
    assert_eq!(call_ids(&all).len(), 1334, "fixture dialog count changed");
    assert_eq!(expected.len(), 127, "fixture Failed count changed");

    let filtered = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "state == 'Failed'",
    ]);

    assert_same_rows(
        &call_ids(&filtered),
        &expected,
        "--filter \"state == 'Failed'\" must select the 127 Failed dialogs, not all 1334",
    );
}

/// The two states partition the capture: neither selection may be the whole
/// file, and together they must account for all of it. This is the check that
/// an inert filter cannot pass — it catches "returns everything" without
/// depending on any particular expected count.
#[test]
fn json_dialogs_filters_partition_the_capture() {
    let all = run_ok(&["-N", "-I", BRANCH, "--no-cli-print", "--json-dialogs"]);
    let total = call_ids(&all).len();

    let failed = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "state == 'Failed'",
    ]);
    let registered = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "state == 'Registered'",
    ]);

    let (n_failed, n_registered) = (call_ids(&failed).len(), call_ids(&registered).len());
    assert!(n_failed > 0 && n_failed < total, "Failed rows: {n_failed}");
    assert!(
        n_registered > 0 && n_registered < total,
        "Registered rows: {n_registered}"
    );
    assert_eq!(
        n_failed + n_registered,
        total,
        "the two states must partition the {total} dialogs"
    );
}

/// A filter that matches nothing must emit nothing and still exit 0 — an
/// empty result is an answer, not an error.
#[test]
fn json_dialogs_filter_matching_nothing_emits_no_rows() {
    let out = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "from.user == '__no_such_user__'",
    ]);
    assert_eq!(call_ids(&out).len(), 0, "unmatched filter emitted rows");
}

/// A numeric field selects on its value, not on parseability: `msg_count`
/// splits the capture, and the two halves must sum to the whole.
#[test]
fn json_dialogs_numeric_filter_splits_on_the_value() {
    let all = run_ok(&["-N", "-I", BRANCH, "--no-cli-print", "--json-dialogs"]);
    let total = call_ids(&all).len();
    // Independent expectation from the unfiltered JSON's own msg_count.
    let expected_small = all
        .lines()
        .filter(|l| l.starts_with('{'))
        .filter(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("JSON");
            v["msg_count"].as_u64().unwrap_or(0) < 4
        })
        .count();

    let small = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "msg_count < 4",
    ]);
    let big = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--json-dialogs",
        "--filter",
        "msg_count >= 4",
    ]);

    assert_eq!(call_ids(&small).len(), expected_small, "msg_count < 4");
    assert_eq!(
        call_ids(&small).len() + call_ids(&big).len(),
        total,
        "msg_count halves must sum to the capture"
    );
}

// ── --report ────────────────────────────────────────────────────────

/// `--report` is generated from the same final store and was equally inert.
#[test]
fn report_dialog_table_honours_the_filter() {
    let all = run_ok(&["-N", "-I", BRANCH, "--no-cli-print", "--json-dialogs"]);
    let expected = call_ids_in_state(&all, "Failed");

    let report = run_ok(&[
        "-N",
        "-I",
        BRANCH,
        "--no-cli-print",
        "--report",
        "--filter",
        "state == 'Failed'",
    ]);
    let rows = report_rows(&report);

    assert_eq!(
        rows.len(),
        expected.len(),
        "--report must print the {} Failed dialogs",
        expected.len()
    );
    for (call_id, state) in &rows {
        assert_eq!(state, "Failed", "row {call_id} is not Failed");
    }
}

/// The report's RTP tables must follow the dialog selection: showing every
/// stream in the capture beside three filtered dialogs misreports which media
/// belongs to the calls on screen.
#[test]
fn report_stream_table_follows_the_dialog_filter() {
    let unfiltered = run_ok(&["-N", "-I", G711, "--no-cli-print", "--report"]);
    // Two dialogs (Completed, InCall), one linked stream each.
    assert_eq!(report_rows(&unfiltered).len(), 2, "fixture dialog count");
    assert_eq!(report_stream_ssrcs(&unfiltered).len(), 2, "fixture streams");

    let filtered = run_ok(&[
        "-N",
        "-I",
        G711,
        "--no-cli-print",
        "--report",
        "--filter",
        "state == 'Completed'",
    ]);
    assert_eq!(report_rows(&filtered).len(), 1, "one Completed dialog");
    assert_eq!(
        report_stream_ssrcs(&filtered).len(),
        1,
        "only the Completed dialog's stream may be listed"
    );
}

/// With no filter the report is unchanged — the fix must not quietly start
/// dropping streams from an unfiltered run.
#[test]
fn report_without_a_filter_is_unchanged() {
    let report = run_ok(&["-N", "-I", G711, "--no-cli-print", "--report"]);
    assert_eq!(report_rows(&report).len(), 2);
    assert_eq!(report_stream_ssrcs(&report).len(), 2);
}

// ── aliases ─────────────────────────────────────────────────────────

/// docs/filter-dsl.md: "The alias and the expression it expands to select the
/// same dialogs." Proved on rows, not on both being accepted.
#[test]
fn filter_alias_and_its_expansion_select_the_same_rows() {
    for (alias, expansion) in [
        ("short-calls", "duration < 5.0 AND state == 'Completed'"),
        ("one-way", "one_way == true"),
        ("nat-issues", "nat_mismatch == true"),
        ("slow-setup", "pdd > 3.0"),
    ] {
        let by_alias = run_ok(&[
            "-N",
            "-I",
            BRANCH,
            "--no-cli-print",
            "--json-dialogs",
            "--filter",
            alias,
        ]);
        let by_expansion = run_ok(&[
            "-N",
            "-I",
            BRANCH,
            "--no-cli-print",
            "--json-dialogs",
            "--filter",
            expansion,
        ]);
        assert_same_rows(
            &call_ids(&by_alias),
            &call_ids(&by_expansion),
            &format!("--filter {alias} vs --filter \"{expansion}\""),
        );
    }
}

/// The dedicated alias flags (`--short-calls`, ...) are documented as the same
/// aliases behind `--filter <name>`, so they must select the same rows.
#[test]
fn alias_flags_match_their_documented_expansions() {
    for (flag, alias) in [
        ("--short-calls", "short-calls"),
        ("--slow-setup", "slow-setup"),
        ("--one-way", "one-way"),
        ("--nat-issues", "nat-issues"),
        ("--problems", "problems"),
    ] {
        let by_flag = run_ok(&["-N", "-I", BRANCH, "--no-cli-print", "--json-dialogs", flag]);
        let by_alias = run_ok(&[
            "-N",
            "-I",
            BRANCH,
            "--no-cli-print",
            "--json-dialogs",
            "--filter",
            alias,
        ]);
        assert_same_rows(
            &call_ids(&by_flag),
            &call_ids(&by_alias),
            &format!("{flag} vs --filter {alias}"),
        );
    }
}

// ── --call-report ───────────────────────────────────────────────────

/// `--call-report` names one Call-ID exactly; a filter narrows a listing, and
/// must not turn a named lookup into a "not found" exit.
#[test]
fn call_report_names_a_dialog_regardless_of_the_filter() {
    let all = run_ok(&["-N", "-I", G711, "--no-cli-print", "--json-dialogs"]);
    let in_call = call_ids_in_state(&all, "InCall");
    let target = in_call.first().expect("fixture has an InCall dialog");

    // The filter excludes this dialog; the explicit lookup still resolves.
    let out = run_ok(&[
        "-N",
        "-I",
        G711,
        "--no-cli-print",
        "--call-report",
        target,
        "--filter",
        "state == 'Completed'",
    ]);
    assert!(
        out.contains(target),
        "--call-report must still report the Call-ID it was given"
    );
}
