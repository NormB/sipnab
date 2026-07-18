//! Ratchet guard: every user-facing CLI flag must appear in at least two
//! runnable example commands in the documentation.
//!
//! Companion to `docs_drift_test` (which proves documented flags EXIST) and
//! `flag_coverage_test` (which proves flags are TESTED). This one proves flags
//! are DEMONSTRATED — the maintainer's "every parameter gets multiple
//! examples" requirement (tasks/docs-website-improvements-2026-07-18.md).
//!
//! Regression history: an audit on 2026-07-18 found 80 flags with zero
//! examples and 17 with one; grouped `**Examples**` blocks in
//! `docs/cli-reference.md` (+ website mirror) closed the gap to 135/135. This
//! test keeps it closed — a new flag added without two examples fails CI.
#![cfg(feature = "native")]

use clap::CommandFactory;
use std::collections::BTreeMap;

/// Minimum example occurrences required per user-facing flag.
const MIN_EXAMPLES: usize = 2;

/// Flags that legitimately cannot carry a runnable example (none today).
/// Each entry MUST carry a written justification, mirroring the
/// `KNOWN_UNTESTED` ratchet convention in `flag_coverage_test.rs`.
const WAIVED: &[(&str, &str)] = &[
    // Hidden internal flag (clap `hide = true`, absent from --help): it
    // deliberately triggers a panic to exercise the crash-report hook. Not a
    // user-facing feature; documenting a "crash on purpose" flag with runnable
    // examples would be actively misleading.
    (
        "panic-selftest",
        "hidden internal panic-hook self-test, not user-facing",
    ),
    // Built-in API TLS is not wired up (axum-server not integrated): setting
    // these makes sipnab exit at startup. Documented as reverse-proxy-only, so
    // a runnable example would be a command that always errors.
    (
        "api-tls-cert",
        "API TLS not implemented; documented as reverse-proxy-only",
    ),
    (
        "api-tls-key",
        "API TLS not implemented; documented as reverse-proxy-only",
    ),
];

/// Every markdown doc that carries user-facing command examples. Read at
/// runtime from CARGO_MANIFEST_DIR so new docs are covered automatically.
fn doc_corpus() -> Vec<(String, String)> {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut docs = Vec::new();
    for dir in ["docs", "website/content/docs"] {
        let path = std::path::Path::new(root).join(dir);
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) == Some("md")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                docs.push((
                    format!("{dir}/{}", p.file_name().unwrap().to_string_lossy()),
                    text,
                ));
            }
        }
    }
    let readme = std::path::Path::new(root).join("README.md");
    if let Ok(text) = std::fs::read_to_string(&readme) {
        docs.push(("README.md".into(), text));
    }
    assert!(
        docs.len() > 15,
        "doc corpus suspiciously small ({}) — path resolution broken?",
        docs.len()
    );
    docs
}

/// Concatenated text of every ```bash fenced block in the corpus.
fn all_bash_blocks(corpus: &[(String, String)]) -> String {
    let re = regex::Regex::new(r"(?s)```bash\n(.*?)```").unwrap();
    let mut out = String::new();
    for (_, text) in corpus {
        for cap in re.captures_iter(text) {
            out.push_str(&cap[1]);
            out.push('\n');
        }
    }
    out
}

/// Primary long name of every user-facing flag (aliases and auto
/// help/version excluded — we count the canonical spelling only).
fn user_facing_long_flags() -> Vec<String> {
    let cmd = sipnab::cli::Cli::command();
    let mut flags = Vec::new();
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long()
            && long != "help"
            && long != "version"
        {
            flags.push(long.to_string());
        }
    }
    flags
}

#[test]
fn every_flag_has_at_least_two_examples() {
    let corpus = doc_corpus();
    let blocks = all_bash_blocks(&corpus);
    let waived: BTreeMap<&str, &str> = WAIVED.iter().copied().collect();

    let mut under = Vec::new();
    for flag in user_facing_long_flags() {
        if waived.contains_key(flag.as_str()) {
            continue;
        }
        // Count occurrences of `--flag` not followed by a flag char, so
        // `--api` doesn't match inside `--api-token-ttl`. The `regex` crate
        // has no look-ahead, so check the trailing byte by hand.
        let needle = format!("--{flag}");
        let n = blocks
            .match_indices(&needle)
            .filter(|(i, _)| {
                let after = i + needle.len();
                blocks[after..]
                    .chars()
                    .next()
                    .map(|c| !(c.is_ascii_alphanumeric() || c == '-'))
                    .unwrap_or(true)
            })
            .count();
        if n < MIN_EXAMPLES {
            under.push(format!("--{flag}: {n} example(s)"));
        }
    }
    under.sort();
    assert!(
        under.is_empty(),
        "{} flag(s) below the {MIN_EXAMPLES}-example minimum — add runnable \
         `**Examples**` blocks in docs/cli-reference.md (and mirror to the \
         website), or waive with justification:\n{}",
        under.len(),
        under.join("\n")
    );
}

#[test]
fn waived_flags_still_exist() {
    // A waiver for a removed flag is dead weight — fail so it gets cleaned up.
    let real: std::collections::BTreeSet<String> = user_facing_long_flags().into_iter().collect();
    let stale: Vec<&str> = WAIVED
        .iter()
        .map(|(f, _)| *f)
        .filter(|f| !real.contains(*f))
        .collect();
    assert!(stale.is_empty(), "waivers for nonexistent flags: {stale:?}");
}
