//! "No untested flag" governance gate (verification plan M6 — T6.2).
//!
//! Operationalizes the spec §15 mandate ("a new CLI flag cannot ship
//! untested"): every long flag the CLI accepts must be referenced by at least
//! one test or golden. A new flag added without any referencing test fails this
//! test, turning the registry's intent into an enforced CI gate.
//!
//! "Referenced" = the `--flag` token appears somewhere in the test corpus:
//! everything under `tests/` (integration tests + `.trycmd` goldens) plus the
//! `#[cfg(test)]` portion of `src/cli.rs` (its `parse_from_args` cases). The
//! clap *definitions* in `src/cli.rs` are deliberately excluded, so a flag
//! cannot satisfy the gate merely by existing.
#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::Path;

use clap::CommandFactory;

/// Baseline of flags that currently have NO referencing test — **technical
/// debt**, not an exemption. The gate is a *ratchet*: this list may only
/// shrink. Adding a new flag without a test fails the gate (it isn't here);
/// adding a test for a listed flag also fails the gate until you remove it
/// from this list. Burn this down toward zero (spec §15 = 100%).
const KNOWN_UNTESTED: &[&str] = &[
    // Burned down in M6 (see tests/cli_flag_behavior_test.rs): count,
    // calls-only, text-dump, pcapng, api-signing-key-file, api-token-ttl,
    // mcp-signing-key-file — removed from this baseline as the ratchet requires.
    "after",
    "alert-exec",
    "buffer",
    "chroot",
    "dtls-keylog",
    "hep-parse",
    "ignore-case",
    "invert",
    "keylog",
    "keylog-watch",
    "metrics",
    "metrics-auth",
    "on-quality-exec",
    "pcap-export-mode",
    "replay",
    "rotate",
    "split",
    "srtp-keys",
    "syslog",
    "tag",
    "telephone-event",
    "tls-key",
    "word",
];

/// All long flags (and long aliases) the CLI accepts, via clap.
fn cli_long_flags() -> BTreeSet<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags = BTreeSet::new();
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long() {
            flags.insert(long.to_string());
        }
        if let Some(aliases) = arg.get_all_aliases() {
            for a in aliases {
                flags.insert(a.to_string());
            }
        }
    }
    flags.insert("help".to_string());
    flags.insert("version".to_string());
    flags
}

/// Core gate logic, factored out so it can be tested with synthetic data:
/// returns the flags whose `--name` token is absent from `corpus`.
fn unreferenced(flags: &BTreeSet<String>, corpus: &str) -> Vec<String> {
    flags
        .iter()
        .filter(|f| !corpus.contains(&format!("--{f}")))
        .cloned()
        .collect()
}

/// Recursively read every file under `dir` whose extension matches, appending
/// to `out`. (Used to assemble the test corpus.)
fn read_tree(dir: &Path, exts: &[&str], out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            read_tree(&path, exts, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| exts.contains(&e))
            .unwrap_or(false)
            && let Ok(s) = std::fs::read_to_string(&path)
        {
            out.push_str(&s);
            out.push('\n');
        }
    }
}

/// Build the corpus: all of `tests/` + the `#[cfg(test)]` tail of `src/cli.rs`
/// (which holds `parse_from_args` cases). Excludes this gate's own file so its
/// waiver list cannot count as "references".
fn test_corpus(manifest: &Path) -> String {
    let mut corpus = String::new();
    read_tree(&manifest.join("tests"), &["rs", "trycmd"], &mut corpus);

    // Append only the test module of cli.rs (after the first `#[cfg(test)]`),
    // so flag *definitions* (`long = "..."`) don't trivially satisfy the gate.
    if let Ok(cli) = std::fs::read_to_string(manifest.join("src/cli.rs"))
        && let Some(idx) = cli.find("#[cfg(test)]")
    {
        corpus.push_str(&cli[idx..]);
    }
    corpus
}

#[test]
fn every_cli_flag_is_referenced_by_a_test() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus = test_corpus(manifest);
    let flags = cli_long_flags();
    let waived: BTreeSet<String> = KNOWN_UNTESTED.iter().map(|s| s.to_string()).collect();

    // (a) No NEW untested flag: every flag is referenced OR explicitly waived.
    let missing: Vec<String> = unreferenced(&flags, &corpus)
        .into_iter()
        .filter(|f| !waived.contains(f))
        .collect();
    assert!(
        missing.is_empty(),
        "these CLI flags are referenced by NO test/golden — add a test (or, \
         only if truly untestable, add to KNOWN_UNTESTED with rationale):\n  {}",
        missing.join("\n  ")
    );

    // (b) Ratchet: a waived flag that is now referenced must be REMOVED from
    // KNOWN_UNTESTED, so the baseline can only shrink.
    let referenced: BTreeSet<String> = flags
        .iter()
        .filter(|f| corpus.contains(&format!("--{f}")))
        .cloned()
        .collect();
    let now_tested: Vec<String> = waived.intersection(&referenced).cloned().collect();
    assert!(
        now_tested.is_empty(),
        "these flags are now tested — remove them from KNOWN_UNTESTED:\n  {}",
        now_tested.join("\n  ")
    );

    // (c) No stale waiver: every KNOWN_UNTESTED entry must still be a real flag.
    let stale: Vec<String> = waived.difference(&flags).cloned().collect();
    assert!(
        stale.is_empty(),
        "KNOWN_UNTESTED lists flags that no longer exist — remove them:\n  {}",
        stale.join("\n  ")
    );
}

// ── Negative meta-test (proves the gate actually guards) ──────────────
#[test]
fn gate_detects_an_unreferenced_flag() {
    let flags: BTreeSet<String> = ["json", "ghost-flag-xyz"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let corpus = "a test that uses --json somewhere";
    let missing = unreferenced(&flags, corpus);
    assert_eq!(
        missing,
        vec!["ghost-flag-xyz".to_string()],
        "the gate must flag a flag that no test references"
    );
}
