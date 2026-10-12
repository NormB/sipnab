// SPDX-License-Identifier: MIT OR Apache-2.0

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
//! This test finds every `curl` command in `.github/workflows/*.yml` and
//! `.github/actions/*/action.yml`, joining `\`-continued lines, and requires
//! all three options at each one.

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

/// Every download in CI retries and is bounded.
#[test]
fn every_ci_curl_download_retries_and_is_bounded() -> Result<(), TestError> {
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in ci_files()? {
        let text = std::fs::read_to_string(&file)?;
        let rel = file
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(&file)
            .display()
            .to_string();
        for (line, cmd) in curl_commands(&text) {
            seen += 1;
            let missing = missing_options(&cmd);
            if !missing.is_empty() {
                bad.push(format!("{rel}:{line} lacks {}", missing.join(", ")));
            }
        }
    }
    // Pinned so a scanner that stops finding commands cannot pass vacuously:
    // the bpf-linker download in release.yml, two in pages.yml (Zola,
    // Pagefind) and six in quality.yml (Vale, its Google style, Pagefind and
    // three Zola).
    assert!(seen >= 9, "found only {seen} curl commands in CI");
    assert!(
        bad.is_empty(),
        "{} CI download(s) fail a job on one transient error:\n  {}",
        bad.len(),
        bad.join("\n  ")
    );
    Ok(())
}
