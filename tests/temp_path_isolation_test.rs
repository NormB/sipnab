// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A temp path built by a test must be unique per PROCESS, not merely per test.
//!
//! `std::env::temp_dir()` is shared by everything on the machine. A test that
//! joins a FIXED name onto it -- or a `format!` discriminated only by the test's
//! own name -- collides with any other process running the same test, because
//! the two agree on the path exactly.
//!
//! This is not hypothetical. `build_capture_config_bpf_file_takes_precedence`
//! wrote `$TMPDIR/sipnab_test_bpf_filter.txt` and removed it on the way out.
//! Running the harness twice at once produced 3170 passed, 1 failed: the loser
//! read the file after the winner deleted it and reported
//! "Failed to read BPF filter file ... No such file or directory" -- which reads
//! like a defect in `--bpf-file`, not like a test colliding with itself. That is
//! the expensive part: the symptom names the wrong component.
//!
//! It reaches past one developer's machine. CI runs on a self-hosted runner, so
//! a CI job and a local build share one `/tmp`.
//!
//! The fix is `tempfile::tempdir()` (or `tempfile::Builder` with a prefix):
//! a name no other process can pick, removed when its guard drops, which
//! happens on a panic as well as on a pass.
//!
//! A per-process discriminator (`std::process::id()`) used to be accepted as
//! the alternative. It is unique per process, but the directory is removed
//! only by the test's own last line, so every failing or killed run leaves it
//! behind. On 2026-10-27 the temp directory of the machine that runs these
//! tests held 23,710 `sipnab*` test directories, about 600 per test name and
//! 16 GB in all. So a pid-named path is refused like a fixed one.

use std::path::PathBuf;

#[path = "../src/test_scratch.rs"]
mod test_scratch;

type TestError = Box<dyn std::error::Error>;

/// Sites that share a fixed path ON PURPOSE, each with the reason it is correct.
/// Keyed by the literal itself rather than by file, so a new fixed path in an
/// already-listed file is still caught.
const DELIBERATELY_SHARED: &[(&str, &str)] = &[
    (
        "sipnab",
        "src/config.rs: the production default report directory. A stable, \
         predictable path is the entire point -- an operator has to find it.",
    ),
    (
        "sipnab_no_such_bpf_file_xyzzy.txt",
        "src/app/bootstrap.rs: names a file that must NOT exist. The assertion \
         is about absence, so two processes agreeing on the path is harmless -- \
         neither creates it.",
    ),
    (
        "sipnab-selftest-unwritten.pcap",
        "tests/support_selftest.rs: a path formatted into a string for the \
         normalizer and never created, so no two processes can collide on it.",
    ),
    (
        "crate-package",
        "tests/crate_package_test.rs: the CARGO_TARGET_DIR `cargo package` \
         builds into, under CARGO_TARGET_TMPDIR. Cargo locks a target directory, \
         so concurrent runs wait for each other, and reusing it is the build \
         cache that keeps the test fast.",
    ),
    (
        "crate-package.lock",
        "tests/crate_package_test.rs: the lock every test process of that file \
         takes before `cargo package` and holds until it exits, so no process \
         rewrites a `.crate` another is reading. It must be one path for all of \
         them to be one lock; it holds no data.",
    ),
    (
        "discarded-coverage",
        "tests/support/mod.rs: where child processes that are killed write their \
         coverage profiles, named by their own pid (%p). It has to outlive every \
         child it is handed to, so no guard can own it; it lives under \
         CARGO_TARGET_TMPDIR, only an instrumented build writes into it, \
         `cargo clean` removes it, and cargo llvm-cov merges only the profiles \
         at the top of its target directory, never this subdirectory.",
    ),
];

/// The fewest `.rs` files the walk of `src/` and `tests/` may read: 884 on
/// 2026-11-04, so a walk that skips a directory tree falls below it.
const MIN_RS_FILES: usize = 800;

/// What one statement that names a shared root does with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Site {
    /// Joins a literal listed in [`DELIBERATELY_SHARED`].
    Shared,
    /// Named by the process id: unique per process, but removed only by the
    /// test's own last line, so a failing run leaves it behind.
    PerProcess,
    /// Any other name: the same in every process, so concurrent runs collide.
    Fixed,
}

/// Classify one statement that names a shared root.
fn classify(stmt: &str) -> Site {
    if stmt.contains("process::id()") {
        return Site::PerProcess;
    }
    let literal = stmt
        .find(".join(\"")
        .map(|j| &stmt[j + 7..])
        .and_then(|rest| rest.find('"').map(|e| &rest[..e]));
    match literal {
        Some(lit) if DELIBERATELY_SHARED.iter().any(|(k, _)| *k == lit) => Site::Shared,
        _ => Site::Fixed,
    }
}

/// Whether the gate refuses a site of this kind: everything but a listed,
/// reasoned sharer.
fn refused(site: Site) -> bool {
    site != Site::Shared
}

/// The calls that name a directory other processes share.
const SHARED_ROOTS: [&str; 2] = ["temp_dir()", "env!(\"CARGO_TARGET_TMPDIR\")"];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rs_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join("src"), repo().join("tests")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn every_temp_path_is_unique_per_process() -> Result<(), TestError> {
    let mut sites = 0usize;
    let mut per_process = 0usize;
    let mut allowed = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    let files = rs_files();
    for path in &files {
        let text = std::fs::read_to_string(path)?;
        let rel = path
            .strip_prefix(repo())
            .unwrap_or(path)
            .display()
            .to_string();

        // Skip this file. It necessarily contains the pattern it hunts for --
        // in the matcher and in the failure message -- so a scanner that reads
        // itself reports itself, which is the same self-match that makes
        // `pgrep -f foo` find the shell running the grep. Keyed off `file!()`
        // rather than a hardcoded name so renaming this file cannot silently
        // turn the exclusion off.
        if rel == file!() {
            continue;
        }

        // Both shared roots: the system temp directory, and the per-target
        // one Cargo hands integration tests, which every run of this target
        // directory shares and only `cargo clean` empties.
        let mut uses: Vec<usize> = SHARED_ROOTS
            .iter()
            .flat_map(|root| text.match_indices(root).map(|(i, _)| i))
            .collect();
        uses.sort_unstable();
        for idx in uses {
            // A mention in a COMMENT is prose about the rule, not a use of it.
            //
            // The scan reads raw text, so `/// ... temp_dir() ...` counted as a
            // site, and the statement window below then ran from inside the
            // comment to the next `;` -- which is the first line of real code
            // AFTER the comment. The offender line it printed was therefore a
            // paragraph of documentation glued to an unrelated statement, and
            // the only way to satisfy it was to stop writing the words down.
            // Found 2026-08-19 by documenting `tmp_re()` in tests/support/mod.rs:
            // one doc comment produced five offenders, none of which built a
            // path at all.
            //
            // Line-level and deliberately so: a real site (`let p =
            // temp_dir().join(...)`) does not start its line with `//`, and a
            // trailing `// note` after real code leaves the line starting with
            // the code. Block comments are not handled because this tree has no
            // `/* */` mention of it; if one appears, the sites floor below drops
            // and says so rather than this going quiet.
            let line_start = text[..idx].rfind('\n').map(|n| n + 1).unwrap_or(0);
            if text[line_start..idx].trim_start().starts_with("//") {
                continue;
            }

            // A match that is the TAIL OF AN IDENTIFIER is not a call.
            // `fn scrubs_paths_under_the_platform_temp_dir()` ends in the
            // needle and was reported as a site; the real call is
            // `std::env::temp_dir()`, whose preceding character is `:`. Anything
            // preceded by a word character is part of a longer name.
            let prev = text[..idx].chars().next_back();
            if prev.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue;
            }

            // Read to the end of the STATEMENT, not the end of the line. A
            // `format!` spanning several lines carries its `process::id()` on a
            // later line, and a line-only window reports it as an offender --
            // which is exactly the false positive that inflated my first count
            // of this defect from 19 to "about 14 more".
            let tail = &text[idx..];
            let stmt = &tail[..tail.find(';').map(|e| e + 1).unwrap_or(tail.len())];

            // A use that BINDS NOTHING and JOINS NOTHING names no path.
            //
            // The contract in this file's header is about joining a fixed name
            // onto the shared directory. `assert!(.., temp_dir().display())`
            // and `push(escape(&format!("{}/", temp_dir().to_string_lossy())))`
            // do neither: they read the directory, produce a string, and create
            // no file for anyone to collide over. Both were reported as
            // offenders with a remedy -- "append std::process::id()" -- that
            // would have been meaningless in each.
            //
            // `let` is the other half of the condition and it is what keeps
            // this from being a hole: `let d = temp_dir();` followed by
            // `d.join("fixed")` on a later line has no `.join(` in ITS
            // statement either, and must stay an offender. So a binding is
            // always a site; only a non-binding, non-joining expression is
            // waved through.
            if !stmt.contains(".join(") && !stmt.contains("let ") {
                continue;
            }

            sites += 1;
            let site = classify(stmt);
            if site == Site::PerProcess {
                per_process += 1;
            }
            if refused(site) {
                let line_no = text[..idx].lines().count();
                offenders.push(format!(
                    "{rel}:{line_no}: {}",
                    stmt.split_whitespace().collect::<Vec<_>>().join(" ")
                ));
            } else {
                allowed += 1;
            }
        }
    }

    // Anti-vacuity. A gate that scans nothing passes for the wrong reason, and
    // this one walks the tree itself rather than taking a file list, so a bad
    // walk would silently check zero sites. The floors are measured, and being
    // ABOVE them is fine -- below means the walk or the extractor broke.
    // The tree no longer holds a refused site, so the count of sites is the
    // deliberately shared ones; the walk is checked by how many files it read.
    assert!(
        files.len() >= MIN_RS_FILES,
        "read only {} .rs files; expected >= {MIN_RS_FILES}. The walk broke -- \
         this gate is not checking what it claims to.",
        files.len()
    );
    assert!(
        sites >= DELIBERATELY_SHARED.len(),
        "found only {sites} temp_dir() sites, fewer than the {} deliberately \
         shared ones. The match broke.",
        DELIBERATELY_SHARED.len()
    );
    assert!(
        offenders.is_empty(),
        "these temp paths are either identical in every process, so two \
         concurrent runs collide, or named by the process id, so a failing run \
         leaves them behind ({per_process} of them):\n  {}\n\nUse \
         tempfile::tempdir() or tempfile::Builder, whose guard removes the \
         directory when it drops, on a panic too. If a site must be shared, add \
         its literal to DELIBERATELY_SHARED with the reason.",
        offenders.join("\n  ")
    );

    assert_eq!(
        allowed,
        DELIBERATELY_SHARED.len(),
        "expected exactly {} deliberately-shared sites, found {allowed}. If one \
         was removed, drop it from DELIBERATELY_SHARED so the list cannot rot \
         into permission nobody needs.",
        DELIBERATELY_SHARED.len()
    );
    Ok(())
}

/// A panicking test body leaves no directory behind when it holds its
/// directory through [`test_scratch::ScratchDir`], the guard every test in
/// this tree uses.
///
/// The test body runs on its own thread so its panic can be observed: the
/// guard drops while the panic unwinds, before `join` returns.
#[test]
fn a_panicking_body_removes_its_tempdir() -> Result<(), TestError> {
    let made = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = std::sync::Arc::clone(&made);
    let body = std::thread::spawn(move || -> std::io::Result<()> {
        let dir = test_scratch::ScratchDir::new("sipnab-panic-probe-")?;
        std::fs::write(dir.path().join("evidence"), b"x")?;
        if let Ok(mut slot) = seen.lock() {
            *slot = Some(dir.path().to_path_buf());
        }
        panic!("the test body fails");
    });
    let joined = body.join();
    assert!(
        joined.is_err(),
        "the probe body was meant to panic; it returned {:?}",
        joined.ok()
    );
    let path = made
        .lock()
        .map_err(|e| format!("probe mutex: {e}"))?
        .clone()
        .ok_or("the probe body never created its directory")?;
    assert!(
        !path.exists(),
        "{} outlived the panic that ended its test",
        path.display()
    );
    Ok(())
}

/// Negative control: the pattern the gate now refuses, a pid-named directory
/// removed on the test's last line, survives the same panic. Without this the
/// test above could pass because the probe never wrote anything.
#[test]
fn a_panicking_body_leaks_a_pid_named_directory() -> Result<(), TestError> {
    let probe = tempfile::tempdir()?;
    let path = probe
        .path()
        .join(format!("sipnab-pid-probe-{}", std::process::id()));
    let inner = path.clone();
    let body = std::thread::spawn(move || -> std::io::Result<()> {
        std::fs::create_dir_all(&inner)?;
        // The cleanup line such a test ends with is never reached.
        panic!("the test body fails");
    });
    let joined = body.join();
    assert!(
        joined.is_err(),
        "the probe body was meant to panic; it returned {:?}",
        joined.ok()
    );
    assert!(
        path.exists(),
        "the pid-named probe was removed, so the control does not reproduce the leak"
    );
    Ok(())
}

/// Edge: a guard handed out by a helper, the shape most fixtures in this tree
/// use. The directory survives the helper's return (a guard dropped inside the
/// helper would delete it before the test used it), and is still removed when
/// the test body that holds it panics.
#[test]
fn a_helper_returned_guard_outlives_the_helper_and_not_the_panic() -> Result<(), TestError> {
    fn fixture() -> std::io::Result<test_scratch::ScratchDir> {
        let dir = test_scratch::ScratchDir::new("sipnab-helper-probe-")?;
        std::fs::write(dir.join("staged"), b"x")?;
        Ok(dir)
    }
    let made = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = std::sync::Arc::clone(&made);
    let body = std::thread::spawn(move || -> std::io::Result<()> {
        let dir = fixture()?;
        let staged = dir.join("staged");
        if let Ok(mut slot) = seen.lock() {
            *slot = Some((dir.path().to_path_buf(), staged.exists()));
        }
        panic!("the test body fails");
    });
    let joined = body.join();
    assert!(
        joined.is_err(),
        "the probe body was meant to panic; it returned {:?}",
        joined.ok()
    );
    let (path, existed) = made
        .lock()
        .map_err(|e| format!("probe mutex: {e}"))?
        .clone()
        .ok_or("the probe body never built its fixture")?;
    assert!(
        existed,
        "the fixture's file was gone when the test used it, so the guard dropped inside the helper"
    );
    assert!(
        !path.exists(),
        "{} outlived the panic that ended its test",
        path.display()
    );
    Ok(())
}

/// The rule itself, on statements of each kind: a pid-named path and a fixed
/// one are refused, a listed sharer is not. The tree no longer holds a refused
/// site, so without this a gate that stopped refusing would still pass.
#[test]
fn the_rule_refuses_a_pid_named_or_fixed_path_and_spares_a_listed_one() {
    let pid = "let d = std::env::temp_dir().join(format!(\"sipnab-x-{}\", std::process::id()));";
    assert_eq!(classify(pid), Site::PerProcess, "a pid-named path");
    assert!(refused(classify(pid)), "a pid-named path is refused");
    let fixed = "let d = std::env::temp_dir().join(\"sipnab-fixed\");";
    assert_eq!(classify(fixed), Site::Fixed, "a fixed name");
    assert!(refused(classify(fixed)), "a fixed name is refused");
    let listed = format!(
        "let d = std::env::temp_dir().join(\"{}\");",
        DELIBERATELY_SHARED[0].0
    );
    assert_eq!(classify(&listed), Site::Shared, "a listed sharer");
    assert!(!refused(classify(&listed)), "a listed sharer is spared");
}
