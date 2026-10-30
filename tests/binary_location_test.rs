// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! No test finds the `sipnab` binary by walking up from its own executable.
//!
//! Four test files located the binary as `current_exe()`, minus the file
//! name, minus a trailing `deps`, plus `sipnab`. That is true of one cargo
//! layout, `target/<profile>/deps/`, and of no other. The weekly Quality job
//! "Branch coverage (nightly)" runs its test binaries from
//! `target/llvm-cov-target/debug/build/sipnab/<hash>/out/`, where the derived
//! path names nothing. `tests/filter_alias_parity_test.rs` failed there with
//! `NotFound` on every scheduled run from 2026-10-07 (runs 37612341740,
//! 38543579026, 39577037128, 40674099450). The other three never ran,
//! because cargo stops at the first test binary that fails.
//!
//! Cargo gives each integration test the binary's real path at compile time
//! in `CARGO_BIN_EXE_<name>`, whatever the layout, so that is the one way a
//! test names the binary. Re-running the test executable itself through
//! `current_exe()` stays allowed: that path is always right.

/// Lines that call `current_exe()` and then, within the next few lines,
/// build a path to a sibling binary or step out of a `deps` directory.
///
/// # Arguments
/// * `src` — the whole text of one Rust source file.
///
/// # Returns
/// The 1-based line number of each such `current_exe()` call.
fn derives_the_binary_from_this_executable(src: &str) -> Vec<usize> {
    const WINDOW: usize = 8;
    const LAYOUT_MARKERS: [&str; 2] = [".join(\"sipnab\")", "ends_with(\"deps\")"];
    let lines: Vec<&str> = src.lines().collect();
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("current_exe()") {
            continue;
        }
        let end = (i + WINDOW + 1).min(lines.len());
        if lines[i..end]
            .iter()
            .any(|l| LAYOUT_MARKERS.iter().any(|m| l.contains(m)))
        {
            found.push(i + 1);
        }
    }
    found
}

#[test]
fn the_scan_finds_the_deps_walk_that_broke_branch_coverage() {
    let src = "fn bin() -> Result<PathBuf, TestError> {\n    \
               let mut p = std::env::current_exe()?;\n    \
               p.pop();\n    \
               if p.ends_with(\"deps\") {\n        \
               p.pop();\n    \
               }\n    \
               Ok(p.join(\"sipnab\"))\n\
               }\n";
    assert_eq!(derives_the_binary_from_this_executable(src), vec![2]);
    let parent = "let exe = std::env::current_exe()?;\nlet bin = exe.parent().ok_or(\"dir\")?.join(\"sipnab\");\n";
    assert_eq!(derives_the_binary_from_this_executable(parent), vec![1]);
}

#[test]
fn the_scan_allows_rerunning_this_test_and_the_cargo_path() {
    let rerun = "let exe = std::env::current_exe()?;\nlet out = Command::new(exe)\n    .args([\"--exact\", role, \"--ignored\"])\n    .output()?;\n";
    assert!(derives_the_binary_from_this_executable(rerun).is_empty());
    let cargo = "let out = Command::new(env!(\"CARGO_BIN_EXE_sipnab\")).output()?;\n";
    assert!(derives_the_binary_from_this_executable(cargo).is_empty());
}

#[test]
fn no_test_derives_the_sipnab_binary_from_its_own_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders = Vec::new();
    let mut files = 0;
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            // This file spells the shape it refuses, in its fixtures.
            if path.extension().is_none_or(|e| e != "rs")
                || path.ends_with("binary_location_test.rs")
            {
                continue;
            }
            files += 1;
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            for line in derives_the_binary_from_this_executable(&src) {
                let rel = path.strip_prefix(&root).unwrap_or(&path);
                offenders.push(format!("tests/{}:{line}", rel.display()));
            }
        }
    }
    assert!(files > 300, "scanned only {files} test files");
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "these find sipnab from the test executable's own path, which holds \
         only for the target/<profile>/deps/ layout. Use \
         env!(\"CARGO_BIN_EXE_sipnab\"):\n  {}",
        offenders.join("\n  ")
    );
}
