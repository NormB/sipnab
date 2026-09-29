// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which git files the build script watches, as a function of the checkout.
//!
//! Shared by `build.rs` and `tests/build_git_triggers_test.rs` through
//! `#[path]`, so the rule the build uses is the rule the test drives.

use std::path::{Path, PathBuf};

/// The files whose change means a new commit, for `cargo:rerun-if-changed`.
///
/// `HEAD` catches branch switches; the resolved ref file catches commits
/// on the current branch when refs are loose; `packed-refs` catches them when
/// refs have been packed (e.g. after `git gc`). Empty when there is no git
/// metadata (building from a published tarball).
///
/// Only files that exist are returned: cargo counts a missing path as changed
/// on every build, which re-ran this script and rebuilt the crate each time.
/// Nothing is lost by dropping one: a ref that is packed later deletes its
/// loose file, which is watched, and `packed-refs` appears only then.
///
/// In a linked worktree `.git` is a file (`gitdir: <path>`) naming the
/// worktree's own git directory, which holds `HEAD`; that directory's
/// `commondir` names the shared one, which holds the refs.
pub fn rerun_paths(checkout: &Path) -> Vec<PathBuf> {
    let Some(git_dir) = git_dir(checkout) else {
        return Vec::new();
    };
    let common_dir = match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(rel) => git_dir.join(rel.trim()),
        Err(_) => git_dir.clone(),
    };
    let mut paths = vec![git_dir.join("HEAD"), common_dir.join("packed-refs")];
    if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD"))
        && let Some(ref_path) = head.strip_prefix("ref:").map(str::trim)
    {
        paths.push(common_dir.join(ref_path));
    }
    paths.retain(|p| p.is_file());
    paths
}

/// The checkout's git directory: `.git` itself, or where a worktree's `.git`
/// file points (relative paths are relative to the checkout).
fn git_dir(checkout: &Path) -> Option<PathBuf> {
    let dot_git = checkout.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    let text = std::fs::read_to_string(&dot_git).ok()?;
    let target = text.trim().strip_prefix("gitdir:")?.trim();
    Some(checkout.join(target))
}
