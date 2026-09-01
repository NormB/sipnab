// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mess is deleted by a rule, not by remembering.
//!
//! CLAUDE.md has said "delete every temp file in the SAME turn" for months,
//! and on 2026-09-01 this repository held 21 stray `.git/*.log` files I had
//! written across sessions, three abandoned worktrees totalling 136 GB, and a
//! `target/` of 1.6 TB — 44% of the disk — on a box whose root filesystem
//! genuinely fills up. The instruction was right and it was not enforced by
//! anything, so it was followed exactly as well as an instruction with no gate
//! ever is.
//!
//! Two halves, and they run at different times:
//!
//!  * the GATE below, which runs with the suite and fails while the mess is
//!    small enough to be one `rm`;
//!  * `scripts/clean-stale.py`, which reclaims what has already accumulated
//!    and is safe to run unattended.
//!
//! The script is driven against fixture trees here rather than only against
//! this repository, because a cleaner is the last thing that should have
//! branches nobody has watched execute. It deletes files; being wrong is
//! expensive in the one direction that cannot be undone.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Logs the pre-commit and pre-push hooks write on purpose.
///
/// These are the durable ones CLAUDE.md points at — read them rather than
/// making a second copy — so they are not mess and the gate must not report
/// them.
const HOOK_LOG_PREFIX: &str = "sipnab-pre-";

// ── the gate: no mess in the tree right now ─────────────────────────────

/// `.git/` holds no stray log but the hooks' own.
///
/// Every `.git/*.log` that is not a hook's is a redirect target somebody left
/// behind. They are invisible to `git status`, which is exactly why they
/// accumulate: nothing that anyone looks at ever mentions them.
#[test]
fn the_git_directory_holds_no_stray_logs() {
    let gitdir = repo().join(".git");
    let Ok(entries) = std::fs::read_dir(&gitdir) else {
        return; // a worktree or a bare checkout: nothing to police
    };
    let stray: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".log"))
        .filter(|n| !n.starts_with(HOOK_LOG_PREFIX))
        .collect();
    assert!(
        stray.is_empty(),
        ".git/ holds {} stray log(s) that no hook wrote: {stray:?}\n\
         These are redirect targets left behind by a session. They are \
         invisible to `git status`, so nothing ever reminds anyone. Delete \
         them, or write to .git/{HOOK_LOG_PREFIX}* if a gate genuinely needs \
         a durable log.",
        stray.len()
    );
}

/// The working tree holds no editor or test detritus.
///
/// `.orig` and `.rej` are a merge somebody walked away from; `.snap.new` is an
/// insta snapshot awaiting review. Each is legitimate for an hour and mess
/// after that, and a stale one silently misleads the next person to look.
#[test]
fn the_working_tree_holds_no_conflict_or_snapshot_detritus() {
    let out = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(repo())
        .output()
        .expect("git status");
    let listing = String::from_utf8_lossy(&out.stdout);

    let detritus: Vec<&str> = listing
        .lines()
        .filter_map(|l| l.get(3..))
        .filter(|f| {
            f.ends_with(".orig")
                || f.ends_with(".rej")
                || f.ends_with(".snap.new")
                || f.ends_with(".bak")
                || f.ends_with('~')
        })
        .collect();
    assert!(
        detritus.is_empty(),
        "the working tree holds conflict or snapshot detritus: {detritus:?}\n\
         An abandoned .snap.new is how a rejected snapshot gets mistaken for \
         an accepted one."
    );
}

/// No abandoned worktree with nothing in it worth keeping.
///
/// A sipnab worktree costs 18-87 GB once its `target/` is warm. Three of them
/// sat here holding no uncommitted work at all — pure cost. This reports only
/// the ones that are safe to remove, because a worktree with work in it is not
/// mess, it is somebody's session.
#[test]
fn no_worktree_is_abandoned_with_nothing_worth_keeping() {
    let out = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(repo())
        .output()
        .expect("git worktree list");
    let listing = String::from_utf8_lossy(&out.stdout);

    let mut abandoned = Vec::new();
    for line in listing.lines() {
        let Some(path) = line.strip_prefix("worktree ") else {
            continue;
        };
        if Path::new(path) == repo() {
            continue; // the checkout we are running in
        }
        let dirty = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(path)
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(true); // unreadable: assume it matters, never delete
        if !dirty {
            abandoned.push(path.to_string());
        }
    }
    assert!(
        abandoned.is_empty(),
        "these worktrees hold no uncommitted work and are pure disk cost \
         ({} of them): {abandoned:?}\n\
         Remove with `git worktree remove --force <path>`, or \
         `scripts/clean-stale.py --apply`.",
        abandoned.len()
    );
}

// ── the script: driven against fixtures, because it deletes ─────────────

/// A throwaway tree for the cleaner to act on.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git")).expect("fixture .git");
        Self { root }
    }

    fn write(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("fixture parent");
        }
        std::fs::write(&p, body).expect("fixture file");
        p
    }

    /// Backdate a file so age-gated rules can see it as old.
    fn age(&self, rel: &str, days: u64) {
        let p = self.root.join(rel);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        let ft = filetime(when);
        let _ = Command::new("touch")
            .args(["-d", &ft, p.to_string_lossy().as_ref()])
            .status();
    }

    fn run(&self, extra: &[&str]) -> (bool, String) {
        let mut cmd = Command::new("python3");
        cmd.arg(repo().join("scripts/clean-stale.py"))
            .arg("--root")
            .arg(&self.root)
            .args(extra)
            .current_dir(repo());
        let out = cmd.output().expect("run scripts/clean-stale.py");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), said)
    }

    fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }

    fn discard(self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn filetime(when: std::time::SystemTime) -> String {
    let secs = when
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("@{secs}")
}

/// Dry run is the default, and it removes nothing.
///
/// The property that makes a cleaner safe to run by accident. A tool that
/// deletes unless told not to will one day be run without the flag.
#[test]
fn the_cleaner_removes_nothing_without_apply() {
    let f = Fixture::new("clean_dryrun");
    f.write(".git/scratch.log", "x");
    f.age(".git/scratch.log", 30);
    let (ok, said) = f.run(&[]);
    let survived = f.exists(".git/scratch.log");
    f.discard();

    assert!(ok, "the cleaner failed on a dry run:\n{said}");
    assert!(
        survived,
        "a dry run deleted a file. The default must never delete: this tool \
         will eventually be run without its flag."
    );
    assert!(
        said.contains("scratch.log"),
        "a dry run must NAME what it would remove, or there is no way to \
         check it before granting it --apply:\n{said}"
    );
}

/// With `--apply`, a stray log goes and a hook's log stays.
///
/// The distinction the gate above draws, enforced in the tool that acts on it.
/// Deleting `sipnab-pre-commit-tests.log` would remove the durable record
/// CLAUDE.md tells me to read instead of making a second copy.
#[test]
fn apply_removes_a_stray_log_and_keeps_the_hooks_own() {
    let f = Fixture::new("clean_apply");
    f.write(".git/scratch.log", "x");
    f.write(".git/sipnab-pre-commit-tests.log", "x");
    f.age(".git/scratch.log", 30);
    f.age(".git/sipnab-pre-commit-tests.log", 30);

    let (ok, said) = f.run(&["--apply"]);
    let stray_gone = !f.exists(".git/scratch.log");
    let hook_kept = f.exists(".git/sipnab-pre-commit-tests.log");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(stray_gone, "a stray log survived --apply:\n{said}");
    assert!(
        hook_kept,
        "the cleaner deleted a hook's own durable log, which is the record \
         the gates are supposed to be read from:\n{said}"
    );
}

/// A file young enough to still be in use is left alone.
///
/// The cleaner may run at any time, including while a build is writing. An age
/// floor is what separates a cleaner from a race.
#[test]
fn a_recent_file_is_never_removed() {
    let f = Fixture::new("clean_recent");
    f.write(".git/scratch.log", "x"); // written just now
    let (ok, said) = f.run(&["--apply"]);
    let survived = f.exists(".git/scratch.log");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        survived,
        "a file written seconds ago was deleted. The cleaner can run while a \
         build is writing, and an age floor is what keeps it from racing one."
    );
}

/// Detritus goes; source does not.
///
/// The blast radius. A cleaner that took `.rs` files with it would be a
/// catastrophe found long after the fact, so the negative case is asserted
/// beside the positive one every time.
#[test]
fn apply_removes_detritus_and_never_source() {
    let f = Fixture::new("clean_detritus");
    for (path, _) in [
        ("src/thing.rs.orig", ()),
        ("src/thing.rs.rej", ()),
        ("tests/snapshots/x.snap.new", ()),
        ("notes.bak", ()),
    ] {
        f.write(path, "x");
        f.age(path, 30);
    }
    f.write("src/thing.rs", "fn main() {}");
    f.write("tests/snapshots/x.snap", "snapshot");
    f.age("src/thing.rs", 30);
    f.age("tests/snapshots/x.snap", 30);

    let (ok, said) = f.run(&["--apply"]);
    let removed = [
        "src/thing.rs.orig",
        "src/thing.rs.rej",
        "tests/snapshots/x.snap.new",
        "notes.bak",
    ]
    .iter()
    .filter(|p| !f.exists(p))
    .count();
    let source_kept = f.exists("src/thing.rs") && f.exists("tests/snapshots/x.snap");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert_eq!(removed, 4, "not all detritus was removed:\n{said}");
    assert!(
        source_kept,
        "the cleaner deleted SOURCE. This is the failure that cannot be \
         undone, and the reason every positive case here has this assertion \
         beside it:\n{said}"
    );
}

/// It reports what it reclaimed.
///
/// A cleanup that runs unattended and says nothing is indistinguishable from
/// one that is not running at all — which is how the 1.6 TB accumulated.
#[test]
fn the_cleaner_reports_what_it_reclaimed() {
    let f = Fixture::new("clean_report");
    f.write(".git/scratch.log", &"x".repeat(4096));
    f.age(".git/scratch.log", 30);
    let (ok, said) = f.run(&["--apply"]);
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        said.to_lowercase().contains("reclaim") || said.to_lowercase().contains("removed"),
        "the cleaner must say what it did; a silent unattended job cannot be \
         told from one that never ran:\n{said}"
    );
}

/// It refuses a root that is not a checkout.
///
/// Pointed at the wrong directory, a recursive remover is a disaster. It must
/// decline rather than do its best.
#[test]
fn the_cleaner_refuses_a_root_that_is_not_a_checkout() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("clean_notarepo");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("mkdir");
    std::fs::write(root.join("important.rs"), "fn main() {}").expect("write");

    let out = Command::new("python3")
        .arg(repo().join("scripts/clean-stale.py"))
        .arg("--root")
        .arg(&root)
        .arg("--apply")
        .current_dir(repo())
        .output()
        .expect("run cleaner");
    let kept = root.join("important.rs").exists();
    let code = out.status.code().unwrap_or(-1);
    let _ = std::fs::remove_dir_all(&root);

    assert_ne!(
        code, 0,
        "the cleaner accepted a directory that is not a checkout; pointed at \
         the wrong path, a recursive remover must decline rather than do its \
         best"
    );
    assert!(
        kept,
        "the cleaner deleted from a directory it should have refused"
    );
}

/// The gate and the cleaner agree on what a hook log looks like.
///
/// One rule in one place. If the gate reports `sipnab-pre-*` as mess while the
/// cleaner preserves it, one of them is wrong and the disagreement shows up as
/// a gate nobody can satisfy.
#[test]
fn the_gate_and_the_cleaner_share_one_definition_of_a_hook_log() {
    let script = std::fs::read_to_string(repo().join("scripts/clean-stale.py"))
        .expect("read scripts/clean-stale.py");
    assert!(
        script.contains(HOOK_LOG_PREFIX),
        "the cleaner does not know the {HOOK_LOG_PREFIX:?} prefix this gate \
         exempts, so the two disagree about what is mess"
    );
}

/// Build caches survive when there is room.
///
/// A cache dropped every night never pays for itself. The threshold is what
/// makes this safe to wire to a timer instead of something run by hand after
/// the disk already hurts.
#[test]
fn build_caches_are_kept_when_there_is_room() {
    let f = Fixture::new("clean_cache_room");
    f.write("target/debug/incremental/x.bin", "payload");
    let (ok, said) = f.run(&["--apply", "--reclaim-build-cache", "--disk-floor-gb", "1"]);
    let kept = f.exists("target/debug/incremental/x.bin");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        kept,
        "a build cache was dropped while the disk had room. Rebuilding it \
         costs a slow build for nothing:\n{said}"
    );
    assert!(
        said.contains("above the"),
        "the cleaner must say WHY it kept the caches, or a timer that never \
         reclaims looks the same as one that is not running:\n{said}"
    );
}

/// Under pressure they go — and only with `--apply`.
///
/// The dry run must still name them: this is the branch that reclaims
/// hundreds of gigabytes, so it is the one whose plan most needs reading
/// before it is granted the flag.
#[test]
fn build_caches_go_only_under_pressure_and_only_with_apply() {
    let f = Fixture::new("clean_cache_pressure");
    f.write("target/debug/incremental/x.bin", "payload");

    let (ok, plan) = f.run(&["--reclaim-build-cache", "--disk-floor-gb", "99999999"]);
    let survived_dry = f.exists("target/debug/incremental/x.bin");

    let (ok2, done) = f.run(&[
        "--apply",
        "--reclaim-build-cache",
        "--disk-floor-gb",
        "99999999",
    ]);
    let gone = !f.exists("target/debug/incremental/x.bin");
    let source_kept = f.exists("target/debug");
    f.discard();

    assert!(ok && ok2, "the cleaner failed:\n{plan}\n{done}");
    assert!(survived_dry, "the dry run deleted a build cache:\n{plan}");
    assert!(
        plan.contains("incremental"),
        "the dry run must name the caches it would drop:\n{plan}"
    );
    assert!(gone, "the cache survived --apply under pressure:\n{done}");
    assert!(
        source_kept,
        "the cleaner removed more than the cache directory:\n{done}"
    );
}

/// `deps/` is never touched.
///
/// It is 961 GB of the same accumulation and is deliberately out of scope: a
/// partial removal leaves cargo rebuilding in confusing ways, so reclaiming it
/// is a `cargo clean` — a decision a person makes, not a cron job.
#[test]
fn the_cleaner_never_touches_the_dependency_cache() {
    let f = Fixture::new("clean_deps_safe");
    f.write("target/debug/deps/libthing.rlib", "artifact");
    f.write("target/debug/incremental/x.bin", "payload");
    let (ok, said) = f.run(&[
        "--apply",
        "--reclaim-build-cache",
        "--disk-floor-gb",
        "99999999",
    ]);
    let deps_kept = f.exists("target/debug/deps/libthing.rlib");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        deps_kept,
        "the cleaner removed from target/debug/deps. Partial removal there \
         leaves cargo rebuilding in ways that look like corruption:\n{said}"
    );
}
