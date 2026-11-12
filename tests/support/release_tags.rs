// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one way a release test lists release tags: the `v*` tags reachable
//! from the commit under test (RELEASE-TESTS-READ-UNREACHABLE-TAGS).
//!
//! The release tests compare the working tree (the crate version, the
//! CHANGELOG, the site configuration) with the tags. `git tag --list` answers
//! with every tag in the repository, and a repository's tags are shared by
//! all of its worktrees. A `git fetch` in one worktree brought `v0.5.246`
//! into the shared git directory, and the commit hook of another worktree,
//! on a branch from before that release, then failed five release tests with
//! no change of that branch involved (2026-11-11): its tree described
//! 0.5.245 and the tag list said 0.5.246.
//!
//! The rule: a tag counts when it is reachable from `HEAD`, or when it is
//! not newer than the newest tag that is ([`counted_tags`]). During a merge
//! the tags reachable from `MERGE_HEAD` count as reachable: the commit hook
//! runs before the merge commit exists, on a working tree that already holds
//! the merged release.

// Shared test support: each test binary uses a different part of this file.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// The `git` arguments that list the release tags which count. `merging`
/// says whether a merge is in progress.
pub fn tag_list_args(merging: bool) -> Vec<&'static str> {
    let mut args = vec!["tag", "--list", "v*", "--merged", "HEAD"];
    if merging {
        args.extend(["--merged", "MERGE_HEAD"]);
    }
    args
}

/// A `git` command in `repo` that the environment of a running git hook
/// cannot point at another repository.
fn git_in(repo: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    cmd
}

/// Whether a merge is in progress in `repo`: `MERGE_HEAD` names a commit.
pub fn merge_in_progress(repo: &Path) -> bool {
    git_in(repo)
        .args(["rev-parse", "--quiet", "--verify", "MERGE_HEAD^{commit}"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// The names of the release tags which count in `repo`, in git's order.
///
/// # Returns
/// `None` when git could not answer: `repo` is not a repository, or it has
/// no commit yet. `Some` of an empty list when no release tag is reachable.
/// The two differ on purpose: a gate that folds them together passes by
/// examining nothing.
pub fn reachable_release_tags(repo: &Path) -> Option<Vec<String>> {
    let reachable = tag_names(repo, &tag_list_args(merge_in_progress(repo)))?;
    let all = tag_names(repo, &["tag", "--list", "v*"])?;
    Some(counted_tags(&all, &reachable))
}

/// The lines of a `git tag` answer in `repo`, or `None` when git failed.
fn tag_names(repo: &Path, args: &[&str]) -> Option<Vec<String>> {
    let out = git_in(repo).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// The `(x, y, z)` of a `vX.Y.Z` tag name; `None` for any other name.
pub fn tag_version(tag: &str) -> Option<(u32, u32, u32)> {
    let mut parts = tag.strip_prefix('v')?.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}

/// Which of `all` the repository's release tags count, given the ones
/// `reachable` from the commit under test.
///
/// - Every reachable tag counts.
/// - A tag that is not reachable counts when its version is not above the
///   newest reachable version. It is a release from before the point this
///   checkout has reached, on a commit the history no longer holds:
///   `v0.5.144` is such a tag in this repository, and the CHANGELOG entry
///   dated for it is still a released version.
/// - A tag that is not reachable and is newer than every reachable version
///   does not count: the checkout has not reached that release. This is the
///   tag another worktree's `git fetch` brings in.
/// - With no reachable `vX.Y.Z` tag, nothing counts.
///
/// The answer keeps the order of `all`, and holds no name twice.
pub fn counted_tags(all: &[String], reachable: &[String]) -> Vec<String> {
    let newest = reachable.iter().filter_map(|t| tag_version(t)).max();
    let mut counted: Vec<String> = Vec::new();
    for tag in all.iter().chain(reachable) {
        let counts = reachable.contains(tag)
            || matches!((tag_version(tag), newest), (Some(v), Some(n)) if v <= n);
        if counts && !counted.contains(tag) {
            counted.push(tag.clone());
        }
    }
    counted
}
