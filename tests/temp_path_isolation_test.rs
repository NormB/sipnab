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
//! The fix is a per-process discriminator (`std::process::id()`) or
//! `tempfile::tempdir()`, both already used elsewhere in this tree.

use std::path::PathBuf;

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
];

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
fn every_temp_path_is_unique_per_process() {
    let mut sites = 0usize;
    let mut per_process = 0usize;
    let mut allowed = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for path in rs_files() {
        let text = std::fs::read_to_string(&path).unwrap();
        let rel = path
            .strip_prefix(repo())
            .unwrap_or(&path)
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

        for (idx, _) in text.match_indices("temp_dir()") {
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

            if stmt.contains("process::id()") {
                per_process += 1;
                continue;
            }

            let line_no = text[..idx].lines().count();
            let literal = stmt
                .find(".join(\"")
                .map(|j| &stmt[j + 7..])
                .and_then(|rest| rest.find('"').map(|e| &rest[..e]));

            match literal {
                Some(lit) if DELIBERATELY_SHARED.iter().any(|(k, _)| *k == lit) => {
                    allowed += 1;
                }
                _ => offenders.push(format!(
                    "{rel}:{line_no}: {}",
                    stmt.split_whitespace().collect::<Vec<_>>().join(" ")
                )),
            }
        }
    }

    // Anti-vacuity. A gate that scans nothing passes for the wrong reason, and
    // this one walks the tree itself rather than taking a file list, so a bad
    // walk would silently check zero sites. The floors are measured, and being
    // ABOVE them is fine -- below means the walk or the extractor broke.
    assert!(
        sites >= 20,
        "found only {sites} temp_dir() sites; expected >= 20. The walk or the \
         match broke -- this gate is not checking what it claims to."
    );
    assert!(
        per_process >= 15,
        "only {per_process} sites carry a per-process discriminator; expected \
         >= 15. Either the codebase regressed or the detector stopped matching."
    );
    assert_eq!(
        allowed,
        DELIBERATELY_SHARED.len(),
        "expected exactly {} deliberately-shared sites, found {allowed}. If one \
         was removed, drop it from DELIBERATELY_SHARED so the list cannot rot \
         into permission nobody needs.",
        DELIBERATELY_SHARED.len()
    );

    assert!(
        offenders.is_empty(),
        "these temp paths are identical in every process, so two concurrent \
         runs collide:\n  {}\n\nUse tempfile::tempdir(), or append \
         std::process::id() to the name. If a site must be shared, add its \
         literal to DELIBERATELY_SHARED with the reason.",
        offenders.join("\n  ")
    );
}
