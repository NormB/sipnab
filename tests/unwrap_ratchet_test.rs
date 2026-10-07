// SPDX-License-Identifier: MIT OR Apache-2.0

//! The number of `.unwrap()`, `.expect(` and `panic!(` calls only falls.
//!
//! Every test returns a `Result` and uses `?`; a panic comes only from an
//! assertion macro. The conversion lands in batches, and until the last one
//! the clippy lints (`unwrap_used`, `expect_used`, `panic`) cannot be denied
//! in test code without failing on the sites not yet converted. This test
//! holds the ground each batch gains: it counts the calls in every tracked
//! `.rs` file and requires the count per area to equal the figure below.
//! A batch lowers the figure in the same commit as the code; a new call
//! raises the count and fails here.
//!
//! The count is a text scan, not clippy's analysis: it matches the call
//! syntax on lines that are not comments. Clippy is the final check, once the
//! lints are denied and this file is deleted.

use std::collections::BTreeMap;

/// Remaining calls per area: (area, unwrap, expect, panic).
const EXPECTED: &[(&str, usize, usize, usize)] = &[
    ("benches", 12, 8, 0),
    ("bpf", 0, 0, 0),
    ("build.rs", 0, 2, 2),
    ("build_script", 0, 0, 0),
    ("clients", 0, 0, 0),
    ("crates", 9, 3, 0),
    ("examples", 0, 3, 0),
    ("fuzz", 0, 0, 0),
    ("src", 1848, 4441, 238),
    ("tests", 0, 0, 2),
];

/// Every tracked `.rs` file, relative to the crate root.
fn tracked_rust_files() -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "*.rs"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .map_err(|e| format!("git ls-files: {e}"));
    let out = match out {
        Ok(o) if o.status.success() => o,
        other => {
            // The assertion below reports this; an empty list would pass
            // the ratchet vacuously.
            assert!(other.is_ok(), "git ls-files failed: {other:?}");
            return Vec::new();
        }
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// The area a path counts toward: its first component.
fn area(path: &str) -> &str {
    path.split('/').next().unwrap_or(path)
}

/// (unwrap, expect, panic) calls in `text`, skipping comment lines.
fn calls_in(text: &str) -> (usize, usize, usize) {
    let mut counts = (0, 0, 0);
    for line in text.lines() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        counts.0 += code.matches(".unwrap()").count();
        counts.1 += code.matches(".expect(").count();
        counts.2 += code.matches("panic!(").count();
    }
    counts
}

#[test]
fn unwrap_expect_and_panic_calls_only_fall() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = tracked_rust_files();
    assert!(files.len() > 300, "only {} tracked .rs files", files.len());
    let mut measured: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for file in &files {
        // This file names the three calls in its own scan.
        if file == "tests/unwrap_ratchet_test.rs" {
            continue;
        }
        let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
        let (u, e, p) = calls_in(&text);
        let entry = measured.entry(area(file).to_string()).or_default();
        entry.0 += u;
        entry.1 += e;
        entry.2 += p;
    }
    let expected: BTreeMap<String, (usize, usize, usize)> = EXPECTED
        .iter()
        .map(|(a, u, e, p)| ((*a).to_string(), (*u, *e, *p)))
        .collect();
    let report: Vec<String> = measured
        .iter()
        .map(|(a, (u, e, p))| format!("    (\"{a}\", {u}, {e}, {p}),"))
        .collect();
    assert_eq!(
        measured,
        expected,
        "the (unwrap, expect, panic) counts changed. If a batch removed calls, \
         set EXPECTED to the measured figures; if one was added, convert it to \
         `?` instead. Measured:\n{}",
        report.join("\n")
    );
}
