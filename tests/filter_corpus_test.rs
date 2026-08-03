// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every documented filter field and alias, proved to select the RIGHT ROWS
//! on REAL captures.
//!
//! The fixture tests in `filter_output_paths_test` prove the wiring: a filter
//! reaches `--report` and `--json-dialogs` at all. This file proves the
//! selection against traffic nobody wrote to make it pass — a filter that
//! parses and then admits every dialog passes a parse test, which is exactly
//! how `--filter` shipped inert.
//!
//! Two independent checks per expression:
//!
//! 1. **Exact rows.** The expected set is computed from the tool's own
//!    *unfiltered* per-dialog JSON, rendered by `output::json` — a different
//!    code path from the `sip::dsl` evaluator under test. Agreement between
//!    them is a cross-check; agreement of the evaluator with itself would not
//!    be.
//! 2. **Partition.** `E` and `NOT E` must together return every dialog and
//!    never the same one twice. No expected count is needed, and a filter that
//!    returns everything cannot satisfy it unless `E` really is universal.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to a directory of captures; unset, every test here
//! skips. The corpus is assumed to contain PII, so nothing derived from a
//! packet is ever printed or asserted on by value — Call-IDs are compared as
//! opaque sets and reported only as counts, and the only names printed are
//! filenames.
#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "support/run.rs"]
mod run_support;

/// Skip captures larger than this: the corpus root can hold archives that are
/// not captures, and a 3-second parse per filter expression adds up.
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// A capture must yield at least this many dialogs to be worth asserting on —
/// a two-dialog file cannot distinguish "selected the right rows" from
/// "selected everything".
const MIN_DIALOGS: usize = 20;

/// How many captures to exercise. Each expression costs one full parse of the
/// file, so the bound is runtime, not coverage.
const MAX_CAPTURES: usize = 2;

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

/// Run `sipnab -N -I <capture> --no-cli-print --json-dialogs [args]` and
/// return the parsed dialog objects.
///
/// # Panics
///
/// When the process exits non-zero. A bare field name (`--filter no_media`)
/// exits 2 with a parse error, and counting stdout lines without checking the
/// code reads that dead process as "zero dialogs matched" — the measurement
/// trap this whole file exists to avoid.
fn dialogs(capture: &Path, args: &[&str]) -> Vec<serde_json::Value> {
    let (out, stderr, code) = try_dialogs(capture, args);
    assert_eq!(
        code,
        Some(0),
        "sipnab exited {code:?} for {args:?}; stderr tail: {}",
        stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ")
    );
    out
}

/// The same run without the exit-code assertion, for the discovery pass: a
/// corpus root holds files that are not captures at all, and refusing to open
/// one is correct behaviour, not a test failure.
///
/// # Returns
/// `(dialogs, stderr, exit_code)`.
fn try_dialogs(capture: &Path, args: &[&str]) -> (Vec<serde_json::Value>, String, Option<i32>) {
    let capture = capture.to_string_lossy().into_owned();
    let mut argv: Vec<&str> = vec![
        "-N",
        "-I",
        &capture,
        "--no-cli-print",
        "--json-dialogs",
        "--portrange",
        "1-65535",
    ];
    argv.extend_from_slice(args);
    let (stdout, stderr, code) = run_support::run(&argv, Some("error"));
    let dialogs = stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("dialog line must be JSON"))
        .collect();
    (dialogs, stderr, code)
}

/// The Call-IDs of a dialog list, as an opaque set. Never printed.
fn ids(dialogs: &[serde_json::Value]) -> BTreeSet<String> {
    dialogs
        .iter()
        .map(|d| d["call_id"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Captures worth asserting on: readable, under the size cap, and holding
/// enough dialogs to tell selection from pass-through.
fn corpus_captures(root: &Path) -> Vec<(String, PathBuf, Vec<serde_json::Value>)> {
    let mut out = Vec::new();
    let (mut too_big, mut too_few, mut unreadable) = (0usize, 0usize, 0usize);
    for path in walk(root) {
        if out.len() == MAX_CAPTURES {
            break;
        }
        if path.metadata().map(|m| m.len()).unwrap_or(0) > MAX_FILE_BYTES {
            too_big += 1;
            continue;
        }
        let (all, _, code) = try_dialogs(&path, &[]);
        if code != Some(0) {
            unreadable += 1;
            continue;
        }
        if all.len() < MIN_DIALOGS {
            too_few += 1;
            continue;
        }
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        eprintln!("corpus: {name} — {} dialogs", all.len());
        out.push((name, path, all));
    }
    eprintln!(
        "corpus: {} captures used, {too_big} over {} MiB, {unreadable} not captures, \
         {too_few} under {MIN_DIALOGS} dialogs",
        out.len(),
        MAX_FILE_BYTES / (1024 * 1024),
    );
    out
}

/// One documented expression and the predicate that decides, from the
/// unfiltered JSON alone, which dialogs it must select.
struct Case {
    /// The `--filter` expression under test.
    expr: &'static str,
    /// Independent expectation over one unfiltered dialog object.
    want: fn(&serde_json::Value) -> bool,
}

/// Milliseconds from a `timing` sub-object, as seconds; absent reads 0.0,
/// matching the DSL's `unwrap_or(0.0)` for an unmeasured interval.
fn timing_secs(d: &serde_json::Value, key: &str) -> f64 {
    d["timing"][key].as_f64().unwrap_or(0.0) / 1000.0
}

/// The documented fields, each with an expectation that does not go through
/// the DSL. Fields the per-dialog JSON does not carry (`src.ip`, `dst.port`,
/// `ua`, `payload`) are covered by the partition test below instead.
const CASES: &[Case] = &[
    Case {
        expr: "state == 'Failed'",
        want: |d| d["state"] == "Failed",
    },
    Case {
        expr: "state == 'Completed'",
        want: |d| d["state"] == "Completed",
    },
    Case {
        expr: "state =~ '^Reg'",
        want: |d| {
            d["state"]
                .as_str()
                .is_some_and(|s| s.starts_with("Reg") && s != "Redirected")
        },
    },
    Case {
        expr: "method == 'INVITE'",
        want: |d| d["method"] == "INVITE",
    },
    Case {
        expr: "msg_count > 3",
        want: |d| d["msg_count"].as_u64().unwrap_or(0) > 3,
    },
    Case {
        expr: "duration < 5.0",
        want: |d| d["duration_sec"].as_f64().unwrap_or(0.0) < 5.0,
    },
    Case {
        expr: "retransmits > 0",
        want: |d| d["timing"]["retransmits"].as_u64().unwrap_or(0) > 0,
    },
    Case {
        expr: "pdd > 3.0",
        want: |d| timing_secs(d, "pdd_ms") > 3.0,
    },
    Case {
        expr: "setup_time > 3.0",
        want: |d| timing_secs(d, "setup_ms") > 3.0,
    },
    Case {
        expr: "one_way == true",
        want: |d| d["diagnosis"]["one_way_audio"] == true,
    },
    Case {
        expr: "no_media == true",
        want: |d| d["diagnosis"]["no_media"] == true,
    },
    Case {
        expr: "nat_mismatch == true",
        want: |d| d["diagnosis"]["nat_mismatch"] == true,
    },
    Case {
        expr: "rtp.packets > 0",
        want: |d| {
            d["streams"]
                .as_array()
                .is_some_and(|s| s.iter().any(|s| s["packets"].as_u64().unwrap_or(0) > 0))
        },
    },
    // `rtp.orphaned` is deliberately absent. It was withdrawn as a filter field
    // — see the note in `docs/filter-dsl.md` and
    // `rtp_orphaned_is_refused_with_a_reason` in `src/sip/dsl.rs`, which pins
    // that asking for it is an error rather than a silent no-match. A row here
    // asserted the opposite and made this whole test exit 2 on every real
    // capture, which nothing noticed because the corpus suite needs
    // `SIPNAB_CORPUS` and CI never sets it.
    Case {
        expr: "rtp.codec == 'PCMU'",
        want: |d| {
            d["streams"]
                .as_array()
                .is_some_and(|s| s.iter().any(|s| s["codec"] == "PCMU"))
        },
    },
    // `rtp.mos` is the worst MOS across the dialog's streams, and
    // `approximate_mos` floors a real stream at 1.0 — so anything BELOW 1.0 is
    // not a measurement, it is the `unwrap_or(0.0)` default for a dialog with
    // no RTP at all. Documented as a 1.0-5.0 field; this pins the gap.
    Case {
        expr: "rtp.mos < 1.0",
        want: |d| d["streams"].as_array().is_some_and(|s| s.is_empty()),
    },
];

/// Every documented field selects the dialogs the unfiltered JSON says it
/// should — no more (the defect: all of them) and no fewer.
#[test]
fn documented_fields_select_the_right_rows_on_real_captures() {
    let Some(root) = corpus_root() else { return };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "no capture under SIPNAB_CORPUS holds {MIN_DIALOGS}+ dialogs, so this test proves nothing"
    );

    let mut discriminating = 0usize;
    for (name, path, all) in &captures {
        let total = all.len();
        for case in CASES {
            let expected: BTreeSet<String> = ids(&all
                .iter()
                .filter(|d| (case.want)(d))
                .cloned()
                .collect::<Vec<_>>());
            let got = ids(&dialogs(path, &["--filter", case.expr]));

            // Counts only: a Call-ID from a real capture never reaches the log.
            let missing = expected.difference(&got).count();
            let extra = got.difference(&expected).count();
            assert_eq!(
                (missing, extra),
                (0, 0),
                "{name}: [{}] selected {} of {total} dialogs; expected {} \
                 ({missing} missing, {extra} unexpected)",
                case.expr,
                got.len(),
                expected.len(),
            );
            if !got.is_empty() && got.len() < total {
                discriminating += 1;
            }
        }
        eprintln!("corpus: {name} — {} expressions checked", CASES.len());
    }

    // The gate that the old behaviour could never pass: on real traffic at
    // least some of these expressions must select a PROPER subset. All-or-
    // nothing results everywhere would mean the corpus cannot tell an applied
    // filter from an ignored one.
    assert!(
        discriminating >= 3,
        "only {discriminating} expressions selected a proper subset across the \
         corpus — this run cannot distinguish an applied filter from an ignored one"
    );
}

/// `E` and `NOT E` partition the capture. Needs no expected count, so it
/// covers the fields the per-dialog JSON does not expose.
#[test]
fn every_expression_partitions_the_capture() {
    let Some(root) = corpus_root() else { return };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "no usable capture under SIPNAB_CORPUS"
    );

    const EXPRS: &[&str] = &[
        "state == 'Failed'",
        "src.port >= 5060",
        "dst.ip =~ '^10\\.'",
        "ua =~ '.'",
        "payload =~ 'INVITE'",
        "msg_count > 3",
    ];

    for (name, path, all) in &captures {
        let total = ids(all);
        for expr in EXPRS {
            let yes = ids(&dialogs(path, &["--filter", expr]));
            let no = ids(&dialogs(path, &["--filter", &format!("NOT {expr}")]));

            let overlap = yes.intersection(&no).count();
            let union = yes.union(&no).count();
            assert_eq!(overlap, 0, "{name}: [{expr}] and its negation share rows");
            assert_eq!(
                union,
                total.len(),
                "{name}: [{expr}] ({}) plus its negation ({}) cover {union} of \
                 {} dialogs",
                yes.len(),
                no.len(),
                total.len()
            );
        }
        eprintln!(
            "corpus: {name} — {} expressions partitioned {} dialogs",
            EXPRS.len(),
            total.len()
        );
    }
}

/// Each alias flag and the `--filter <alias>` spelling select the same rows on
/// real traffic — the flags used to carry their own hand-written expansions.
#[test]
fn alias_flags_agree_with_the_documented_aliases_on_real_captures() {
    let Some(root) = corpus_root() else { return };
    let captures = corpus_captures(&root);
    assert!(
        !captures.is_empty(),
        "no usable capture under SIPNAB_CORPUS"
    );

    for (name, path, all) in &captures {
        for (flag, alias) in [
            ("--short-calls", "short-calls"),
            ("--slow-setup", "slow-setup"),
            ("--one-way", "one-way"),
            ("--nat-issues", "nat-issues"),
            ("--problems", "problems"),
        ] {
            let by_flag = ids(&dialogs(path, &[flag]));
            let by_alias = ids(&dialogs(path, &["--filter", alias]));
            assert_eq!(
                by_flag.symmetric_difference(&by_alias).count(),
                0,
                "{name}: {flag} selected {} dialogs, --filter {alias} selected {} \
                 (of {})",
                by_flag.len(),
                by_alias.len(),
                all.len()
            );
        }
        eprintln!("corpus: {name} — 5 alias flags agree with their aliases");
    }
}
