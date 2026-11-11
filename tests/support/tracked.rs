// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one reader of `git ls-files` for the test suite.
//!
//! `git ls-files` prints an unmerged path once per index stage: a path in
//! conflict appears up to three times (base, ours, theirs). A gate that counts
//! the listing then counts that path three times, and a gate that reads each
//! listed file reads it three times and reports each finding three times.
//! Seen on 2026-11-08: a tracked-markdown count of 350 against a real 346
//! with two unmerged pages.
//!
//! Every test that needs the tracked paths calls [`ls_files`], which returns
//! each path once. The rule that removes the repeats is [`unique_paths`], a
//! pure function of the listing bytes, so `tests/support_selftest.rs` drives
//! it with a listing that repeats a path, with no merge needed.
//! `support_selftest` also refuses a `git ls-files` call anywhere else in
//! `tests/` or `scripts/`. The scripts have the same rule in
//! `scripts/lib_tracked.py`.
//!
//! This file lives in a `tests/` subdirectory, so cargo does not compile it as
//! its own test binary; consumers include it with
//! `#[path = "support/tracked.rs"] mod tracked;`.
#![allow(dead_code)]

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// The error [`ls_files`] returns: any error, boxed, so `?` works in a test
/// that returns `Box<dyn std::error::Error>`.
pub type ListError = Box<dyn std::error::Error>;

/// Each path of a NUL-separated `git ls-files -z` listing, once, in the order
/// of its first appearance.
///
/// Empty fields (the one after the final NUL) are dropped. Bytes that are not
/// UTF-8 are replaced, as `String::from_utf8_lossy` does.
pub fn unique_paths(listing: &[u8]) -> Vec<String> {
    let mut seen = HashSet::new();
    listing
        .split(|b| *b == 0)
        .filter(|field| !field.is_empty())
        .filter(|field| seen.insert(*field))
        .map(|field| String::from_utf8_lossy(field).into_owned())
        .collect()
}

/// The paths `git ls-files -z <args>` lists in the repository at `root`, each
/// once.
///
/// The git environment is inherited: under a hook, `GIT_INDEX_FILE` names the
/// index being committed, and that is the one a gate must read.
///
/// # Errors
///
/// When git cannot be started, or exits with a failure status.
pub fn ls_files(root: impl AsRef<Path>, args: &[&str]) -> Result<Vec<String>, ListError> {
    let mut git = Command::new("git");
    git.current_dir(root.as_ref());
    ls_files_from(git, args)
}

/// [`ls_files`] over a `git` command the caller prepared (its directory and
/// its environment), for a test that builds a repository of its own.
///
/// # Errors
///
/// When git cannot be started, or exits with a failure status.
pub fn ls_files_from(mut git: Command, args: &[&str]) -> Result<Vec<String>, ListError> {
    let out = git
        .args(["ls-files", "-z"])
        .args(args)
        .output()
        .map_err(|e| format!("git ls-files could not start: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files {args:?} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(unique_paths(&out.stdout))
}

/// The 1-based lines of `src` that run `git ls-files` themselves and so can
/// list an unmerged path more than once.
///
/// A line is exempt when it asks a question a repeat cannot change:
/// `--error-unmatch` (is this one path tracked), `--others` / `-o` (untracked
/// files have no stages), or `-s` (the caller asked for the stages). The flag
/// is looked for on the call's line, and on the line after it when the call's
/// line ends with the command name.
pub fn raw_listing_lines(src: &str) -> Vec<usize> {
    const CALL: &str = concat!("\"ls-", "files\"");
    const EXEMPT: [&str; 4] = ["\"--error-unmatch\"", "\"--others\"", "\"-o\"", "\"-s\""];
    let lines: Vec<&str> = src.lines().collect();
    let exempt = |line: &str| EXEMPT.iter().any(|flag| line.contains(flag));
    // The formatter put each argument on a line of its own: the call's line
    // ends with the command name, and the flag is on the next line.
    let continues = |line: &str| {
        line.trim_end()
            .strip_suffix(',')
            .is_some_and(|l| l.ends_with(CALL))
    };
    (0..lines.len())
        .filter(|&index| lines[index].contains(CALL))
        .filter(|&index| {
            let on_next =
                continues(lines[index]) && lines.get(index + 1).is_some_and(|l| exempt(l));
            !exempt(lines[index]) && !on_next
        })
        .map(|index| index + 1)
        .collect()
}
