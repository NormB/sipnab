// SPDX-License-Identifier: MIT OR Apache-2.0

//! Open code-scanning alerts block CI and block a tag -- through ONE script.
//!
//! # The defect this exists for
//!
//! CodeQL ran on every push and its findings went to a tab nobody had to
//! read: the only required check was "CI success", CodeQL is a separate
//! workflow, and the tag hook checked CI but never alerts. Nine alerts sat
//! open on `main` while 0.5.145, 0.5.146 and 0.5.147 were tagged past them.
//! `scripts/code-scanning-clean.py` is the one rule: it waits for CodeQL's
//! analysis of the commit in question, then fails on any open alert. CI's
//! aggregate job requires it and the pre-push tag check calls it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}
fn script() -> PathBuf {
    repo().join("scripts/code-scanning-clean.py")
}
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Runs the script in fixture mode: alerts and analyses come from JSON files,
/// never the network, so every branch can be driven.
fn run(alerts: &str, analyses: &str, sha: &str) -> (i32, String) {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sipnab-cs-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let a = dir.join("alerts.json");
    let b = dir.join("analyses.json");
    std::fs::write(&a, alerts).expect("w");
    std::fs::write(&b, analyses).expect("w");
    let out = Command::new("python3")
        .arg(script())
        .args(["--sha", sha, "--alerts-json"])
        .arg(&a)
        .arg("--analyses-json")
        .arg(&b)
        .output()
        .expect("python3");
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

const SHA: &str = "35c31afe0000000000000000000000000000abcd";
fn analysis_for(sha: &str) -> String {
    format!(r#"[{{"commit_sha": "{sha}", "tool": {{"name": "CodeQL"}}, "results_count": 0}}]"#)
}
fn alert(rule: &str, path: &str, state: &str) -> String {
    format!(
        r#"{{"number": 344, "state": "{state}", "rule": {{"id": "{rule}", "severity": "warning"}}, "most_recent_instance": {{"location": {{"path": "{path}", "start_line": 475}}, "message": {{"text": "This hard-coded value is used as a nonce."}}}}}}"#
    )
}

#[test]
fn no_open_alerts_and_an_analysis_of_this_commit_is_clean() {
    let (rc, out) = run("[]", &analysis_for(SHA), SHA);
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("clean"), "{out}");
}

#[test]
fn one_open_alert_fails_and_names_rule_and_path() {
    let alerts = format!(
        "[{}]",
        alert(
            "rust/hard-coded-cryptographic-value",
            "src/security/digest_leak.rs",
            "open"
        )
    );
    let (rc, out) = run(&alerts, &analysis_for(SHA), SHA);
    assert_eq!(rc, 1, "{out}");
    assert!(
        out.contains("rust/hard-coded-cryptographic-value") && out.contains("digest_leak.rs:475"),
        "{out}"
    );
}

#[test]
fn dismissed_and_fixed_alerts_do_not_count() {
    let alerts = format!(
        "[{}, {}]",
        alert("x/y", "a.rs", "dismissed"),
        alert("x/z", "b.rs", "fixed")
    );
    let (rc, out) = run(&alerts, &analysis_for(SHA), SHA);
    assert_eq!(rc, 0, "{out}");
}

/// No analysis of THIS commit yet is not "clean": the scanner has not spoken.
#[test]
fn no_analysis_of_this_commit_is_not_a_pass() {
    let (rc, out) = run(
        "[]",
        &analysis_for("0000000000000000000000000000000000000000"),
        SHA,
    );
    assert_eq!(rc, 2, "{out}");
    assert!(out.to_lowercase().contains("no codeql analysis"), "{out}");
}

/// An unreadable API answer is exit 2, never a silent 0 -- a gate that cannot
/// see must say so rather than pass.
#[test]
fn an_unreadable_answer_is_reported_not_passed() {
    let (rc, out) = run("<html>502 Bad Gateway</html>", &analysis_for(SHA), SHA);
    assert_eq!(rc, 2, "{out}");
}

/// CI requires the gate: a job runs the script and the aggregate needs it.
#[test]
fn ci_success_requires_the_code_scanning_gate() {
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("scripts/code-scanning-clean.py"),
        "ci.yml never runs the script"
    );
    assert!(
        ci.contains("security-events: read"),
        "the job cannot read alerts without security-events: read"
    );
    let i = ci.find("name: CI success").expect("aggregate job");
    let needs = &ci[i..ci[i..].find("runs-on:").map(|j| i + j).unwrap_or(ci.len())];
    assert!(
        needs.contains("code-scanning-clean"),
        "the aggregate does not need the gate:\n{needs}"
    );
}

/// The tag hook calls the SAME script -- one rule, one place.
#[test]
fn the_tag_hook_refuses_a_commit_with_open_alerts_via_the_same_script() {
    let hook = read(".githooks/pre-push");
    let i = hook.find("checking CI").expect("tag loop");
    let tail = &hook[i..];
    assert!(
        tail.contains("scripts/code-scanning-clean.py"),
        "the tag check never consults code scanning"
    );
}

/// The exit-code contract is written where a caller reads it.
#[test]
fn the_scripts_exit_codes_are_documented_in_its_header() {
    let s = read("scripts/code-scanning-clean.py");
    for needle in ["exit 0", "exit 1", "exit 2"] {
        assert!(s.contains(needle), "header does not state `{needle}`");
    }
}

/// Fixing alerts by silencing the rule is the one fix this must never accept.
#[test]
fn the_codeql_config_does_not_exclude_the_crypto_material_rule() {
    let cfg = read(".github/codeql/codeql-config.yml");
    let excluded = cfg
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains("id: rust/hard-coded-cryptographic-value"));
    assert!(
        !excluded,
        "the rule is excluded in codeql-config.yml -- fix the code, not the scanner"
    );
}

/// `tags contain: test` filters a QUERY's metadata tags, which no security
/// query carries; it cannot scope a rule to test code, and two filters in
/// that form suppressed nothing for months while claiming to.
#[test]
fn no_query_filter_pretends_to_scope_by_test_code() {
    let cfg = read(".github/codeql/codeql-config.yml");
    let live: Vec<&str> = cfg
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let bad: Vec<&&str> = live
        .iter()
        .filter(|l| l.contains("tags contain") && l.contains("test"))
        .collect();
    assert!(bad.is_empty(), "ineffective test-scoped filter(s): {bad:?}");
}
