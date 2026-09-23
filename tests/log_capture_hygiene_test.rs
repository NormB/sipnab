// SPDX-License-Identifier: MIT OR Apache-2.0

//! A unit test that captures logs goes through ONE helper.
//!
//! `tracing` caches, per call site and for the whole process, whether any
//! subscriber wants that call site's events. `with_default` installs a
//! subscriber for one thread only. When another test thread, running with no
//! subscriber, reaches a call site first, the cached answer can be "nobody",
//! and the capturing test then misses an event it asserted on. That is how
//! `a_relay_that_is_down_is_reported_once_not_once_per_stream` failed in CI's
//! `native,hep,api,mcp,mcp-http` leg on 2026-09-22: the first line of the run
//! arrived, the closing line did not, and the test passed every time it ran
//! alone.
//!
//! `test_utils::capture_logs` rebuilds the cache after installing its
//! subscriber, the fix two integration tests already carried. The race itself
//! needs a second thread to reach a call site at the wrong instant, so it
//! cannot be driven on demand. What CAN be held is the rule: no unit test calls
//! `with_default` itself, so there is one place the fix lives.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

/// The one file allowed to call `with_default`: the helper.
const HELPER: &str = "src/test_utils.rs";

/// Every `path:line` in `files` that calls `tracing::subscriber::with_default`
/// outside the helper. Pure, so both directions are driven from fixtures.
fn raw_calls(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, text) in files {
        if path == HELPER {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("subscriber::with_default(") {
                out.push(format!("{path}:{}", n + 1));
            }
        }
    }
    out
}

fn rust_files(root: &Path, dir: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.join(dir)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, std::fs::read_to_string(&p).unwrap_or_default()));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn the_scan_finds_a_raw_call_and_spares_the_helper_and_comments() {
    let files = vec![
        (
            "src/a.rs".to_owned(),
            "fn t() {\n    tracing::subscriber::with_default(sub, f);\n}\n".to_owned(),
        ),
        (
            HELPER.to_owned(),
            "tracing::subscriber::with_default(sub, f);\n".to_owned(),
        ),
        (
            "src/b.rs".to_owned(),
            "// never call tracing::subscriber::with_default( directly\n".to_owned(),
        ),
    ];
    assert_eq!(raw_calls(&files), vec!["src/a.rs:2".to_owned()]);
}

#[test]
fn unit_tests_capture_logs_through_the_one_helper() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = rust_files(&root, "src");
    assert!(
        files.iter().any(|(p, _)| p == HELPER),
        "{HELPER} is missing; the scan is reading the wrong tree"
    );
    let raw = raw_calls(&files);
    assert!(
        raw.is_empty(),
        "these call `with_default` themselves, and can miss events another \
         test thread's cached call-site interest hides. Use \
         `crate::test_utils::capture_logs` instead:\n  {}",
        raw.join("\n  ")
    );
}
