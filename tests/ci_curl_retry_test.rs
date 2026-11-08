// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every `curl` download in CI retries a transient failure and is bounded.
//!
//! On 2026-10-12 the "Docs (prose, spelling, links)" job on pull request
//! #471 failed in its Pagefind step: `curl -fsSL` fetching the Pagefind
//! release tarball from github.com got HTTP 504 once and exited 22. The
//! commit was fine; the job failed because the download had no retry. The
//! bpf-linker download in release.yml already carried
//! `--retry 5 --retry-delay 5 --retry-all-errors --max-time 300` for the same
//! reason.
//!
//! curl's `--retry` covers timeouts and the HTTP 408, 429, 500, 502, 503 and
//! 504 responses; `--retry-all-errors` extends it to every error, which
//! includes a connection reset mid-transfer. `--max-time` bounds each attempt
//! so a stalled transfer fails and is retried instead of holding the job.
//!
//! That was not enough. On 2026-11-08 github.com answered release downloads
//! with HTTP 504 from at least 08:57Z to at least 09:48Z, and five retries 5 s
//! apart are about 25 s. Every CI download now goes through
//! `scripts/fetch-pinned.sh` (CI-TOOL-DOWNLOAD-RESILIENCE), whose own loop
//! retries with exponential backoff for up to five minutes and whose
//! behavior `scripts/tests/test_fetch_pinned.py` drives against a local
//! server. So the rule here is now: no CI file runs `curl` itself, and the
//! script's one `curl` bounds each attempt and leaves retrying to the loop.
//!
//! The scanner finds every `curl` command in `.github/workflows/*.yml` and
//! `.github/actions/*/action.yml`, joining `\`-continued lines.

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

/// The fewest retries a download may carry.
const MIN_RETRIES: u32 = 5;

/// Every workflow and composite-action file.
fn ci_files() -> Result<Vec<PathBuf>, TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root.join("workflows"))? {
        let p = entry?.path();
        if p.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(p);
        }
    }
    let actions = root.join("actions");
    if actions.is_dir() {
        for entry in std::fs::read_dir(actions)? {
            let p = entry?.path().join("action.yml");
            if p.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Each `curl` command in `text` as one line, with its 1-based line number.
///
/// A command continues onto the next line while its line ends in `\`. Lines
/// that are comments are skipped.
fn curl_commands(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let t = lines[i].trim_start();
        let is_curl = !t.starts_with('#')
            && t.split_whitespace()
                .any(|w| w == "curl" || w.ends_with("/curl"));
        if is_curl {
            let start = i;
            let mut cmd = String::new();
            loop {
                let l = lines[i].trim();
                let (body, more) = match l.strip_suffix('\\') {
                    Some(b) => (b, true),
                    None => (l, false),
                };
                cmd.push_str(body);
                cmd.push(' ');
                if !more || i + 1 >= lines.len() {
                    break;
                }
                i += 1;
            }
            out.push((start + 1, cmd));
        }
        i += 1;
    }
    out
}

/// What is missing from one `curl` command, or nothing.
fn missing_options(cmd: &str) -> Vec<String> {
    let words: Vec<&str> = cmd.split_whitespace().collect();
    let mut missing = Vec::new();
    let retries = words
        .windows(2)
        .find(|w| w[0] == "--retry")
        .and_then(|w| w[1].parse::<u32>().ok());
    match retries {
        Some(n) if n >= MIN_RETRIES => {}
        Some(n) => missing.push(format!("--retry {n} is below {MIN_RETRIES}")),
        None => missing.push(format!("--retry {MIN_RETRIES}")),
    }
    for opt in ["--retry-all-errors", "--max-time"] {
        if !words.contains(&opt) {
            missing.push(opt.to_string());
        }
    }
    missing
}

/// The scanner sees a continued command whole, and judges its options.
#[test]
fn the_scanner_reads_a_continued_command_and_judges_it() {
    let yml = "      run: |\n        # curl in a comment is not a command\n        \
               curl -fsSL -o a.tgz \\\n          \"https://example.invalid/a.tgz\"\n        \
               curl -fsSL --retry 5 --retry-delay 5 --retry-all-errors --max-time 300 \\\n          \
               -o b.tgz \"https://example.invalid/b.tgz\"\n";
    let cmds = curl_commands(yml);
    assert_eq!(cmds.len(), 2, "{cmds:?}");
    assert_eq!(cmds[0].0, 3);
    assert!(cmds[0].1.contains("a.tgz"), "{cmds:?}");
    assert_eq!(
        missing_options(&cmds[0].1),
        vec!["--retry 5", "--retry-all-errors", "--max-time"]
    );
    assert!(cmds[1].1.contains("b.tgz"), "{cmds:?}");
    assert!(missing_options(&cmds[1].1).is_empty(), "{cmds:?}");
    assert_eq!(
        missing_options("curl --retry 2 --retry-all-errors --max-time 60 x"),
        vec!["--retry 2 is below 5"]
    );
}

/// No CI file runs `curl` itself: downloads go through the one rule.
#[test]
fn no_ci_file_runs_curl_itself() -> Result<(), TestError> {
    let mut found = Vec::new();
    let files = ci_files()?;
    assert!(
        files.len() > 5,
        "found only {} CI files; the scan stopped matching",
        files.len()
    );
    for file in files {
        let text = std::fs::read_to_string(&file)?;
        let rel = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&file)
            .display()
            .to_string();
        for (line, cmd) in curl_commands(&text) {
            found.push(format!("{rel}:{line}: {cmd}"));
        }
    }
    assert!(
        found.is_empty(),
        "{} CI step(s) run curl themselves. Fetch a pinned file through \
         .github/actions/pinned-download, or scripts/fetch-pinned.sh where no \
         cache can help: it verifies the sha256 and retries an outage for up \
         to five minutes, where a bare curl gave up after about 25 s:\n  {}",
        found.len(),
        found.join("\n  ")
    );
    Ok(())
}

/// The script's one `curl` bounds each attempt, fails on an HTTP error, and
/// leaves retrying to the script's budgeted loop.
#[test]
fn fetch_pinned_bounds_each_attempt_and_owns_the_retries() -> Result<(), TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/fetch-pinned.sh");
    let text = std::fs::read_to_string(&path)?;
    let cmds = curl_commands(&text);
    assert_eq!(
        cmds.len(),
        1,
        "scripts/fetch-pinned.sh should run curl in one place: {cmds:?}"
    );
    let words: Vec<&str> = cmds[0].1.split_whitespace().collect();
    for opt in ["--max-time", "--connect-timeout", "--fail"] {
        assert!(
            words.contains(&opt),
            "the script's curl lacks {opt}: {}",
            cmds[0].1
        );
    }
    // curl's own --retry inside the loop would multiply the attempts, and
    // the time, past the budget the loop enforces.
    assert!(
        !words.iter().any(|w| w.starts_with("--retry")),
        "the script's curl retries by itself as well as in the loop: {}",
        cmds[0].1
    );
    Ok(())
}
