// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every `#[ignore]`d test says why, and something runs it.
//!
//! An ignored test is skipped by every plain `cargo test`, the pre-commit hook
//! and CI's main suite included. That is fine while the test runs somewhere
//! else. It is a silent hole when nothing runs it: the test keeps compiling,
//! looks like coverage, and has not executed since the day it was written.
//!
//! Two rules, over every `#[ignore]` in `src/` and `tests/`:
//!
//! 1. **A reason.** `#[ignore = "needs tmux"]`, not a bare `#[ignore]`. libtest
//!    prints the reason beside the skip, so a reader of the output learns why
//!    without opening the file.
//! 2. **A runner.** One of:
//!    - a workflow under `.github/workflows/` passes `--ignored` (or
//!      `--include-ignored`) to a `--test` target that is the test's file;
//!    - the test is a CHILD ROLE: its own file spawns it with `"--ignored"` and
//!      names it in a string literal, so the parent test runs it every time the
//!      suite runs;
//!    - it is listed in [`MANUAL_ONLY`] with the reason no CI runner can run it.
//!
//! The scan is a pure function over source text, driven by fixtures below
//! before it is pointed at the tree.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

/// Ignored tests that no CI runner can execute, with the reason.
///
/// Each entry is `(file, test name, why no CI step runs it)`. An entry that
/// names no ignored test is itself a failure, so this list cannot outlive the
/// tests it excuses.
const MANUAL_ONLY: &[(&str, &str, &str)] = &[(
    "src/capture/fanout.rs",
    "fanout_applies_to_an_open_pcap_handle",
    "opens a live AF_PACKET socket, which needs CAP_NET_RAW. The GitHub-hosted \
     runners run cargo as an unprivileged user, and the self-hosted thor-02 \
     runner in self-hosted-smoke.yml runs without sudo. Run by hand with \
     `sudo <test-binary> --ignored fanout_applies_to_an_open_pcap_handle`.",
)];

/// One `#[ignore]` attribute found in a source file.
#[derive(Debug, PartialEq)]
struct Ignore {
    /// 1-based line of the attribute.
    line: usize,
    /// The test function the attribute applies to, when one follows it.
    test: Option<String>,
    /// The non-empty reason string, or `None` for a bare `#[ignore]`.
    reason: Option<String>,
}

/// Every `#[ignore]` attribute in `src`, with its reason and its test.
///
/// Only a line that STARTS with `#[ignore` counts, so a string literal or a
/// comment that mentions the attribute is not mistaken for one.
fn ignores_in(src: &str) -> Vec<Ignore> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim_start();
        if !line.starts_with("#[ignore") {
            continue;
        }
        let reason = line
            .strip_prefix("#[ignore")
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix('"'))
            .and_then(|rest| rest.split('"').next())
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(str::to_string);
        let test = lines[i + 1..].iter().map(|l| l.trim_start()).find_map(|l| {
            let l = l.strip_prefix("pub ").unwrap_or(l);
            let l = l.strip_prefix("async ").unwrap_or(l);
            let name = l.strip_prefix("fn ")?;
            let end = name
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(name.len());
            Some(name[..end].to_string())
        });
        out.push(Ignore {
            line: i + 1,
            test,
            reason,
        });
    }
    out
}

/// The `--test` targets a workflow runs with `--ignored` or
/// `--include-ignored`, as file stems.
fn ci_ignored_targets(workflow: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in workflow.lines() {
        if !(line.contains("--ignored") || line.contains("--include-ignored")) {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        for pair in words.windows(2) {
            if pair[0] == "--test" {
                out.push(pair[1].to_string());
            }
        }
    }
    out
}

/// Whether `file_src` spawns `test` itself as an `#[ignore]`d child role.
fn is_self_spawned_child(file_src: &str, test: &str) -> bool {
    file_src.contains("\"--ignored\"") && file_src.contains(&format!("\"{test}\""))
}

/// Why one ignore in `rel` breaks a rule, or `None` when it is clean.
fn violation(
    rel: &str,
    file_src: &str,
    ig: &Ignore,
    ci_targets: &[String],
    manual: &[(&str, &str, &str)],
) -> Option<String> {
    let at = format!("{rel}:{}", ig.line);
    let Some(test) = &ig.test else {
        return Some(format!("{at}: `#[ignore]` with no test function after it"));
    };
    if ig.reason.is_none() {
        return Some(format!(
            "{at}: `{test}` has a bare `#[ignore]`. Write `#[ignore = \"why\"]`"
        ));
    }
    let stem = Path::new(rel)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let run_by_ci = rel.starts_with("tests/") && ci_targets.iter().any(|t| t == stem);
    let manual_only = manual.iter().any(|(f, t, _)| *f == rel && t == test);
    if run_by_ci || manual_only || is_self_spawned_child(file_src, test) {
        None
    } else {
        Some(format!(
            "{at}: `{test}` is ignored and nothing runs it: no workflow passes \
             `--ignored` to `--test {stem}`, its file does not spawn it, and it \
             is not in MANUAL_ONLY"
        ))
    }
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `dir`, recursively, as repo-relative paths.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "fixtures") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every workflow's `--ignored` targets, read off the real files.
fn tree_ci_targets() -> Vec<String> {
    let mut targets = Vec::new();
    let dir = repo().join(".github/workflows");
    for entry in std::fs::read_dir(&dir)
        .expect("read .github/workflows")
        .flatten()
    {
        let text = std::fs::read_to_string(entry.path()).expect("read workflow");
        targets.extend(ci_ignored_targets(&text));
    }
    targets
}

#[test]
fn the_scanner_reads_reasons_and_test_names() {
    let src = "#[test]\n#[ignore = \"needs tmux\"]\nfn one() {}\n\n#[test]\n#[ignore] // slow\npub fn two() {}\n";
    assert_eq!(
        ignores_in(src),
        vec![
            Ignore {
                line: 2,
                test: Some("one".into()),
                reason: Some("needs tmux".into()),
            },
            Ignore {
                line: 6,
                test: Some("two".into()),
                reason: None,
            },
        ]
    );
}

#[test]
fn an_empty_reason_is_no_reason() {
    let src = "#[ignore = \"  \"]\nfn blank() {}\n";
    assert_eq!(ignores_in(src)[0].reason, None);
}

#[test]
fn a_mention_in_a_string_or_comment_is_not_an_attribute() {
    let src = "let s = \"#[ignore]\";\n// #[ignore] is how\n/// `#[ignore]`d child\nfn f() {}\n";
    assert!(ignores_in(src).is_empty());
}

#[test]
fn ci_targets_come_only_from_ignored_invocations() {
    let wf = "      run: |\n          cargo test --features tui --test tui_e2e_test -- --ignored\n          cargo test --test plain_test\n          cargo test --test inc_test -- --include-ignored\n";
    assert_eq!(ci_ignored_targets(wf), vec!["tui_e2e_test", "inc_test"]);
}

#[test]
fn a_bare_ignore_is_refused_even_when_ci_runs_it() {
    let src = "#[ignore]\nfn e2e() {}\n";
    let ig = &ignores_in(src)[0];
    let v = violation("tests/e2e_test.rs", src, ig, &["e2e_test".into()], &[]);
    assert!(v.is_some_and(|m| m.contains("bare")));
}

#[test]
fn an_ignore_nothing_runs_is_refused() {
    let src = "#[ignore = \"needs root\"]\nfn orphan() {}\n";
    let ig = &ignores_in(src)[0];
    assert!(violation("tests/x_test.rs", src, ig, &["other_test".into()], &[]).is_some());
    // A `src/` unit test is not covered by a `--test` target of the same stem.
    assert!(violation("src/x_test.rs", src, ig, &["x_test".into()], &[]).is_some());
}

#[test]
fn each_runner_clears_a_reasoned_ignore() {
    let src = "#[ignore = \"child\"]\nfn role() {}\n";
    let ig = &ignores_in(src)[0];
    assert_eq!(
        violation("tests/a_test.rs", src, ig, &["a_test".into()], &[]),
        None
    );
    assert_eq!(
        violation(
            "tests/a_test.rs",
            src,
            ig,
            &[],
            &[("tests/a_test.rs", "role", "manual")]
        ),
        None
    );
    let spawner = format!("{src}run(\"role\");\ncmd.args([\"--exact\", \"--ignored\"]);\n");
    assert_eq!(violation("tests/a_test.rs", &spawner, ig, &[], &[]), None);
}

#[test]
fn every_ignore_in_the_tree_has_a_reason_and_a_runner() {
    let root = repo();
    let ci = tree_ci_targets();
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("tests"), &mut files);
    files.sort();

    let mut seen = 0usize;
    let mut problems = Vec::new();
    let mut ignored_tests = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("read source");
        let rel = path
            .strip_prefix(&root)
            .expect("under the repo")
            .to_string_lossy()
            .replace('\\', "/");
        for ig in ignores_in(&src) {
            seen += 1;
            if let Some(t) = &ig.test {
                ignored_tests.push((rel.clone(), t.clone()));
            }
            problems.extend(violation(&rel, &src, &ig, &ci, MANUAL_ONLY));
        }
    }
    // The scanner found the tree's ignores rather than nothing: there are
    // dozens of child roles alone.
    assert!(
        seen >= 20,
        "found only {seen} #[ignore] attributes; the scan is broken"
    );

    for (file, test, why) in MANUAL_ONLY {
        assert!(
            !why.trim().is_empty(),
            "MANUAL_ONLY {file}::{test} has no reason"
        );
        if !ignored_tests.iter().any(|(f, t)| f == file && t == test) {
            problems.push(format!(
                "MANUAL_ONLY names {file}::{test}, which is not an ignored test"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{} ignore problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
