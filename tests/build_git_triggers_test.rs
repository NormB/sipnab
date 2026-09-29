// SPDX-License-Identifier: MIT OR Apache-2.0

//! The build script watches only git files that exist.
//!
//! Cargo treats a `rerun-if-changed` path that does not exist as changed on
//! every build. The build script watched `.git/HEAD`, `.git/packed-refs` and
//! `.git/<ref>`, which in a linked worktree (where `.git` is a file naming the
//! real git directory) never exist, so every cargo command there re-ran the
//! build script and rebuilt sipnab and all of its test binaries: 95 s for a
//! second `cargo test --no-run` with nothing changed, measured on 2026-09-29,
//! and every step of both git hooks paid it again. A clone that has never
//! packed its refs has no `packed-refs` and paid the same.
//!
//! These drive `build_script/git_triggers.rs`, the function `build.rs`
//! itself calls, against each layout git produces.

#[path = "../build_script/git_triggers.rs"]
mod git_triggers;

use std::path::{Path, PathBuf};

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
    std::fs::write(path, text).expect("write");
}

/// Every watched path must exist, or cargo rebuilds on every invocation.
fn assert_all_exist(paths: &[PathBuf]) {
    let missing: Vec<&PathBuf> = paths.iter().filter(|p| !p.is_file()).collect();
    assert!(
        missing.is_empty(),
        "the build script would watch paths that do not exist, so cargo \
         rebuilds sipnab on every command: {missing:?} (all: {paths:?})"
    );
}

/// A main repository plus a linked worktree on branch `feature`, the way
/// `git worktree add` lays them out. `gitdir` is what the worktree's `.git`
/// file says: absolute by default, relative under `worktree.useRelativePaths`.
fn worktree_fixture(root: &Path, relative: bool) -> PathBuf {
    let common = root.join("main/.git");
    write(&common.join("HEAD"), "ref: refs/heads/main\n");
    write(
        &common.join("refs/heads/main"),
        "1111111111111111111111111111111111111111\n",
    );
    write(
        &common.join("refs/heads/feature"),
        "2222222222222222222222222222222222222222\n",
    );
    let admin = common.join("worktrees/wt");
    write(&admin.join("HEAD"), "ref: refs/heads/feature\n");
    write(&admin.join("commondir"), "../..\n");
    let checkout = root.join("wt");
    let gitdir = if relative {
        "../main/.git/worktrees/wt".to_string()
    } else {
        admin.display().to_string()
    };
    write(&checkout.join(".git"), &format!("gitdir: {gitdir}\n"));
    checkout
}

fn assert_worktree_triggers(root: &Path, checkout: &Path) {
    let paths = git_triggers::rerun_paths(checkout);
    assert_all_exist(&paths);
    let canon: Vec<PathBuf> = paths
        .iter()
        .map(|p| p.canonicalize().expect("canonicalize"))
        .collect();
    for wanted in [
        root.join("main/.git/worktrees/wt/HEAD"),
        root.join("main/.git/refs/heads/feature"),
    ] {
        let wanted = wanted.canonicalize().expect("fixture file");
        assert!(
            canon.contains(&wanted),
            "a worktree build must watch {} (a commit or branch switch there \
             must re-stamp the version); it watches {paths:?}",
            wanted.display()
        );
    }
}

#[test]
fn a_worktree_with_an_absolute_gitdir_watches_its_own_head_and_branch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let checkout = worktree_fixture(tmp.path(), false);
    assert_worktree_triggers(tmp.path(), &checkout);
}

#[test]
fn a_worktree_with_a_relative_gitdir_watches_its_own_head_and_branch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let checkout = worktree_fixture(tmp.path(), true);
    assert_worktree_triggers(tmp.path(), &checkout);
}

#[test]
fn a_repository_that_never_packed_its_refs_watches_no_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let git = tmp.path().join(".git");
    write(&git.join("HEAD"), "ref: refs/heads/main\n");
    write(
        &git.join("refs/heads/main"),
        "1111111111111111111111111111111111111111\n",
    );
    let paths = git_triggers::rerun_paths(tmp.path());
    assert_all_exist(&paths);
    for wanted in [git.join("HEAD"), git.join("refs/heads/main")] {
        assert!(
            paths.contains(&wanted),
            "must watch {}; watches {paths:?}",
            wanted.display()
        );
    }
}

#[test]
fn a_tarball_build_watches_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    assert!(git_triggers::rerun_paths(tmp.path()).is_empty());
}

/// The checkout this test runs in, whatever its layout: a worktree locally, a
/// plain clone in CI. The hook's `GIT_*` variables are removed so git
/// describes this checkout rather than the hook's idea of one.
#[test]
fn this_checkout_watches_its_head_and_nothing_missing() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut git = std::process::Command::new("git");
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
    ] {
        git.env_remove(var);
    }
    let out = git
        .args(["rev-parse", "--path-format=absolute", "--git-path", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("run git");
    if !out.status.success() {
        eprintln!("SKIPPED: not a git checkout");
        return;
    }
    let head = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
        .canonicalize()
        .expect("HEAD exists");
    let paths = git_triggers::rerun_paths(repo);
    assert_all_exist(&paths);
    assert!(
        paths
            .iter()
            .any(|p| p.canonicalize().ok().as_deref() == Some(head.as_path())),
        "must watch this checkout's HEAD {}; watches {paths:?}",
        head.display()
    );
}
