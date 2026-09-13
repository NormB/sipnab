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
    if !gitdir.is_dir() {
        return; // a worktree or a bare checkout: nothing to police
    }
    let stray = stray_git_files(&gitdir);
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
/// A `git` invocation inside a worktree that reports on THAT worktree.
///
/// # The defect this exists for
///
/// Under `git commit`, the pre-commit hook runs with `GIT_DIR`,
/// `GIT_INDEX_FILE` and `GIT_WORK_TREE` set for the repository being committed
/// to. A child `git status` spawned with `current_dir(worktree)` inherits them
/// and silently reports on the PARENT repository instead: measured, a worktree
/// with 22 changed files answered "4" (the parent's staged files) with the
/// variables leaked in, and "0" with the hook's temporary index. So the gate
/// called a live agent's worktree abandoned, and blocked every commit for as
/// long as the worktree existed — while passing when run by hand, because by
/// hand there is nothing to leak.
fn worktree_git(path: &str) -> Command {
    let mut c = Command::new("git");
    c.current_dir(path);
    for var in [
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "GIT_PREFIX",
        "GIT_COMMON_DIR",
    ] {
        c.env_remove(var);
    }
    c
}

/// Whether a worktree holds anything a person would miss.
///
/// Uncommitted changes obviously. Commits not yet merged anywhere too: a
/// worktree whose work is all committed on its own branch is not empty, it is
/// finished and waiting — the previous check read that as abandoned.
fn worth_keeping(dirty_lines: usize, commits_ahead: usize) -> bool {
    dirty_lines > 0 || commits_ahead > 0
}

/// The probe must scrub the hook's variables, or it reports the wrong repo.
#[test]
fn the_worktree_probe_scrubs_the_hooks_git_environment() {
    let c = worktree_git(".");
    let removed: Vec<&std::ffi::OsStr> = c
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k)
        .collect();
    for var in ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"] {
        assert!(
            removed.iter().any(|k| *k == var),
            "{var} is not scrubbed; under `git commit` the probe would report the \
             parent repository and call a live worktree abandoned"
        );
    }
}

/// Committed-but-unmerged work counts. Only nothing-at-all is abandoned.
#[test]
fn a_worktree_is_kept_for_uncommitted_or_unmerged_work_and_dropped_for_neither() {
    assert!(
        worth_keeping(22, 0),
        "uncommitted changes are worth keeping"
    );
    assert!(
        worth_keeping(0, 1),
        "a commit nobody has merged is worth keeping"
    );
    assert!(worth_keeping(3, 2));
    assert!(
        !worth_keeping(0, 0),
        "nothing uncommitted and nothing unmerged is disk cost"
    );
}

/// The worktrees this gate may report, out of `git worktree list --porcelain`.
///
/// Two are excluded, and only one of them was before:
///
/// * **The checkout the test is running in.** Its own uncommitted work is the
///   change under review.
/// * **The MAIN checkout**, which `git worktree list --porcelain` always
///   prints first. `git worktree remove` REFUSES it — "is a main working
///   tree" — so reporting it hands the reader an instruction that cannot be
///   followed, and this gate found itself doing exactly that the first time it
///   ran from inside a linked worktree with a clean main checkout. A gate
///   demanding output its own fixer will never produce is unfixable by design.
///
/// Identified by POSITION rather than by comparing against a path, because
/// every path-shaped answer is wrong somewhere: `CARGO_MANIFEST_DIR` names the
/// running checkout, not the main one, and `--git-common-dir` is relative
/// under some invocations and absolute under others.
fn reportable_worktrees(listing: &str, running_in: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen_main = false;
    for line in listing.lines() {
        let Some(path) = line.strip_prefix("worktree ") else {
            continue;
        };
        if !seen_main {
            seen_main = true;
            continue; // the main checkout, which git refuses to remove
        }
        if Path::new(path) == running_in {
            continue; // the checkout we are running in
        }
        out.push(path.to_string());
    }
    out
}

/// The main checkout is never reported, and a clean linked one still is.
///
/// **First of two tests owed** for the run in which this gate reported the
/// main checkout. Driven on a synthetic listing in both directions, because
/// the exclusion and the rule fail differently: an exclusion that is too wide
/// makes the gate report nothing ever, and one that is too narrow sends a
/// reader to a command that refuses.
#[test]
fn the_main_checkout_is_never_reported_and_a_linked_one_still_is() {
    let listing = "\
worktree /srv/checkouts/sipnab
HEAD 1111111111111111111111111111111111111111
branch refs/heads/main

worktree /srv/checkouts/sipnab-feature
HEAD 2222222222222222222222222222222222222222
branch refs/heads/feature

worktree /srv/checkouts/sipnab-running
HEAD 3333333333333333333333333333333333333333
branch refs/heads/running
";
    let running = Path::new("/srv/checkouts/sipnab-running");
    let got = reportable_worktrees(listing, running);
    assert_eq!(
        got,
        vec!["/srv/checkouts/sipnab-feature".to_string()],
        "only the linked worktree that is neither main nor the running one is \
         reportable"
    );

    // The main checkout stays excluded even when the test runs inside it,
    // which is the ordinary case and must not start reporting a second
    // worktree by accident.
    let got = reportable_worktrees(listing, Path::new("/srv/checkouts/sipnab"));
    assert_eq!(
        got,
        vec![
            "/srv/checkouts/sipnab-feature".to_string(),
            "/srv/checkouts/sipnab-running".to_string(),
        ]
    );
}

/// **Second of two.** The exclusion cannot swallow the rule.
///
/// A listing with only the main checkout in it yields nothing to report, and a
/// listing with none at all yields nothing either — but the gate above asserts
/// `abandoned.is_empty()`, so "nothing to report" and "the parse broke" look
/// identical from the outside. This pins that the parser really is reading the
/// listing rather than returning an empty vector whatever it is given.
#[test]
fn the_worktree_parser_reads_the_listing_it_is_given() {
    assert!(
        reportable_worktrees("", Path::new("/nowhere")).is_empty(),
        "an empty listing has nothing to report"
    );
    assert!(
        reportable_worktrees(
            "worktree /only/main
",
            Path::new("/nowhere")
        )
        .is_empty(),
        "a lone main checkout has nothing to report"
    );
    let many = (0..5)
        .map(|i| {
            format!(
                "worktree /w{i}
HEAD 0

"
            )
        })
        .collect::<String>();
    assert_eq!(
        reportable_worktrees(&many, Path::new("/nowhere")).len(),
        4,
        "five worktrees, one of them main, leaves four reportable"
    );
}

#[test]
fn no_worktree_is_abandoned_with_nothing_worth_keeping() {
    let out = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(repo())
        .output()
        .expect("git worktree list");
    let listing = String::from_utf8_lossy(&out.stdout);

    let mut abandoned = Vec::new();
    for path in reportable_worktrees(&listing, &repo()) {
        let path = path.as_str();
        let dirty_lines = worktree_git(path)
            .args(["status", "--porcelain"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count())
            .unwrap_or(1); // unreadable: assume it matters, never delete
        let commits_ahead = worktree_git(path)
            .args(["rev-list", "--count", "@{upstream}..HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .unwrap_or_else(|| {
                // No upstream: count against the main checkout's HEAD instead.
                worktree_git(path)
                    .args([
                        "rev-list",
                        "--count",
                        "HEAD",
                        "--not",
                        "--remotes",
                        "--branches=main",
                    ])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
                    .unwrap_or(1)
            });
        if !worth_keeping(dirty_lines, commits_ahead) {
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

/// Whether a file body still carries merge-conflict markers.
///
/// Only the two markers that never occur legitimately: `<<<<<<< ` and
/// `>>>>>>> ` at line start. A bare `=======` is a setext underline in
/// Markdown, so it is not evidence on its own.
fn has_conflict_markers(body: &str) -> bool {
    body.lines()
        .any(|l| l.starts_with("<<<<<<< ") || l.starts_with(">>>>>>> "))
}

/// No tracked file may carry a merge-conflict marker.
///
/// # The defect this exists for
///
/// A squash merge left `<<<<<<< HEAD` / `=======` / `>>>>>>>` in CHANGELOG.md
/// and index.html, the files were staged, and the full pre-commit hook ran
/// fmt, Vale, codespell, clippy and the whole test suite over them without
/// noticing. Only the homepage count ratchet flinched, and only because the
/// two sides of one block named different numbers. A gate that lets a
/// conflict marker through to a commit is missing the one thing every reader
/// would spot first.
#[test]
fn no_tracked_file_carries_a_conflict_marker() {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    let mut bad = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
        if rel.is_empty() {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(repo().join(rel)) else {
            continue; // binary or unreadable: not a text file to scan
        };
        if has_conflict_markers(&body) {
            bad.push(rel.to_string());
        }
    }
    assert!(
        bad.is_empty(),
        "tracked file(s) still carry merge-conflict markers: {bad:?}"
    );
}

/// POSITIVE CONTROL: the predicate must see a marker when one is there, and
/// must not mistake a Markdown underline for one.
#[test]
fn the_conflict_marker_predicate_sees_markers_and_not_underlines() {
    assert!(has_conflict_markers(
        "a\n<<<<<<< HEAD\nb\n=======\nc\n>>>>>>> other\n"
    ));
    assert!(has_conflict_markers(">>>>>>> theirs\n"));
    assert!(
        !has_conflict_markers("Title\n=======\n\nbody\n"),
        "a setext underline is not a marker"
    );
    assert!(!has_conflict_markers("no markers here\n"));
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
    ///
    /// Done in Rust rather than by shelling out. `touch -d @<epoch>` is a GNU
    /// extension: on macOS it fails, the file keeps today's mtime, the age
    /// floor correctly declines to remove it, and three tests fail with
    /// assertions about the CLEANER when the fixture was what broke. CI found
    /// that on 2026-09-01 and the local run could not have.
    ///
    /// The write is verified, because a setup step that silently does nothing
    /// looks exactly like one that worked.
    fn age(&self, rel: &str, days: u64) {
        let p = self.root.join(rel);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        let f = std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap_or_else(|e| panic!("open {} to backdate: {e}", p.display()));
        f.set_modified(when)
            .unwrap_or_else(|e| panic!("backdate {}: {e}", p.display()));

        let got = std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .unwrap_or_else(|e| panic!("read back mtime of {}: {e}", p.display()));
        let age = std::time::SystemTime::now()
            .duration_since(got)
            .unwrap_or_default();
        assert!(
            age.as_secs() >= days * 86_400 / 2,
            "backdating {} did not take: it reads as {}s old, not {}d. Every \
             age-gated assertion below would then be testing the fixture \
             rather than the cleaner.",
            p.display(),
            age.as_secs(),
            days
        );
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
    // And the same list of redirect-target extensions. The gate widening to
    // `.out` while the cleaner still globbed `*.log` would demand a deletion
    // the fixer never performs.
    let line = script
        .lines()
        .find(|l| l.starts_with("STRAY_REDIRECT_SUFFIXES = ("))
        .expect("the cleaner declares STRAY_REDIRECT_SUFFIXES on one line");
    let theirs: Vec<&str> = regex::Regex::new(r#""(\.[a-z]+)""#)
        .expect("regex")
        .captures_iter(line)
        .map(|c| c.get(1).map_or("", |m| m.as_str()))
        .collect();
    assert_eq!(
        theirs, STRAY_REDIRECT_SUFFIXES,
        "the gate and the cleaner disagree about which extensions a stray \
         redirect target has"
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

// ── portability: a fixture that no-ops is worse than one that fails ─────
//
// On 2026-09-01 three of the tests above failed on macOS and nowhere else.
// `Fixture::age` backdated files with `touch -d @<epoch>`, a GNU extension.
// On macOS the command simply failed, the file kept today's mtime, the
// cleaner's age floor correctly declined to remove it, and three assertions
// about the CLEANER failed when the FIXTURE was what broke. The local run
// could not have caught it and the failure message pointed at the wrong code.
//
// The class is broader than one flag: test infrastructure that depends on GNU
// behavior and does nothing, quietly, somewhere else.

/// Backdating actually moves the file's timestamp.
///
/// The primitive every age-gated test rests on, checked directly. If this is
/// wrong then every assertion above is testing the fixture rather than the
/// cleaner -- and it will say so in the language of the cleaner.
#[test]
fn backdating_a_fixture_file_actually_moves_its_mtime() {
    let f = Fixture::new("age_primitive");
    f.write(".git/probe.log", "x");

    let before = std::fs::metadata(f.root.join(".git/probe.log"))
        .and_then(|m| m.modified())
        .expect("mtime before");
    f.age(".git/probe.log", 30);
    let after = std::fs::metadata(f.root.join(".git/probe.log"))
        .and_then(|m| m.modified())
        .expect("mtime after");
    f.discard();

    let moved = before
        .duration_since(after)
        .expect("backdating must move the mtime BACKWARDS");
    assert!(
        moved.as_secs() >= 29 * 86_400,
        "backdating moved the mtime by only {}s; the age floor cannot be \
         exercised and every age-gated test is measuring the wrong thing",
        moved.as_secs()
    );
}

/// The floor separates a recent file from a backdated one, in one run.
///
/// Both directions together on purpose. A fixture that made everything look
/// OLD would pass the removal tests; one that made everything look NEW would
/// pass the retention test. Only asserting both at once catches a backdating
/// mechanism that has quietly stopped working.
#[test]
fn the_age_floor_separates_recent_from_backdated_in_one_run() {
    let f = Fixture::new("age_both_ways");
    f.write(".git/old.log", "x");
    f.write(".git/new.log", "x");
    f.age(".git/old.log", 30);

    let (ok, said) = f.run(&["--apply"]);
    let old_gone = !f.exists(".git/old.log");
    let new_kept = f.exists(".git/new.log");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        old_gone && new_kept,
        "the age floor did not separate the two: old removed={old_gone}, \
         recent kept={new_kept}. If BOTH went the floor is not applied; if \
         NEITHER went the backdating is not taking.\n{said}"
    );
}

/// No test shells out to read or write file metadata.
///
/// `touch`, `stat`, `date` and `readlink` differ between GNU and BSD in
/// exactly the flags a test reaches for. Rust's own filesystem API is
/// portable, so there is no reason to leave the process.
#[test]
fn no_test_shells_out_for_file_metadata() {
    let mut offenders = Vec::new();
    let mut scanned = 0;
    let out = Command::new("git")
        .args(["ls-files", "tests/"])
        .current_dir(repo())
        .output()
        .expect("git ls-files tests/");
    for file in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        if !file.ends_with(".rs") {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(repo().join(file)) else {
            continue;
        };
        scanned += 1;
        for (n, line) in src.lines().enumerate() {
            let l = line.trim();
            if l.starts_with("//") {
                continue;
            }
            for tool in ["\"touch\"", "\"stat\"", "\"date\"", "\"readlink\""] {
                if l.contains(&format!("Command::new({tool}")) {
                    offenders.push(format!("  {file}:{}: {l}", n + 1));
                }
            }
        }
    }
    assert!(
        scanned >= 40,
        "only {scanned} test file(s) scanned; the walk is wrong"
    );
    assert!(
        offenders.is_empty(),
        "these tests shell out for file metadata, where GNU and BSD disagree \
         on the flags. Use std::fs, which is portable:\n{}",
        offenders.join("\n")
    );
}

/// No executable line uses a GNU-only spelling.
///
/// The general form, across the scripts and hooks too. Each pattern here has
/// a BSD counterpart that differs, so the command does not fail loudly on
/// macOS -- it fails in whatever way that platform's tool chooses, which was
/// "silently do nothing" for the one that started this.
#[test]
fn no_executable_line_uses_a_gnu_only_spelling() {
    // Measured 2026-09-01: one real hit, `stat -c %s` in bench/live-capture.sh,
    // now `wc -c` which is POSIX. Everything else that matches is prose
    // explaining the hazard, which is why comment lines are skipped.
    const GNU_ONLY: &[(&str, &str)] = &[
        ("touch -d", "BSD touch has no -d; use std::fs or -t"),
        ("stat -c", "BSD spells it `stat -f`; `wc -c` is portable"),
        ("readlink -f", "BSD readlink has no -f"),
        ("date -d ", "BSD date spells it -v or -j -f"),
        ("cp --preserve", "BSD cp uses -p"),
    ];
    let out = Command::new("git")
        .args(["ls-files", "scripts/", ".githooks/", "bench/"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");

    let mut offenders = Vec::new();
    let mut scanned = 0;
    for file in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        let Ok(src) = std::fs::read_to_string(repo().join(file)) else {
            continue; // binary fixture
        };
        scanned += 1;
        for (n, line) in src.lines().enumerate() {
            let l = line.trim();
            if l.starts_with('#') || l.starts_with("//") {
                continue;
            }
            for (pattern, fix) in GNU_ONLY {
                if l.contains(pattern) {
                    offenders.push(format!("  {file}:{}: {pattern} -- {fix}", n + 1));
                }
            }
        }
    }
    assert!(
        scanned >= 20,
        "only {scanned} script(s) scanned; the walk is wrong and this proves \
         nothing"
    );
    assert!(
        offenders.is_empty(),
        "these lines use a GNU-only spelling and behave differently on \
         macOS:\n{}",
        offenders.join("\n")
    );
}

/// The cleaner leaves the process entirely alone.
///
/// It is pure stdlib Python, which is what makes it portable by construction
/// rather than by inspection. A `subprocess` call here would reintroduce the
/// same platform question the fixture just tripped over -- in the tool that
/// DELETES things.
#[test]
fn the_cleaner_shells_out_to_nothing() {
    let script = std::fs::read_to_string(repo().join("scripts/clean-stale.py"))
        .expect("read scripts/clean-stale.py");
    for forbidden in ["subprocess", "os.system", "Popen", "shell=True"] {
        assert!(
            !script.contains(forbidden),
            "the cleaner uses {forbidden}. It deletes files; it must not also \
             depend on which platform's `rm`, `find` or `stat` is installed."
        );
    }
    assert!(
        script.contains("import pathlib"),
        "the cleaner no longer uses pathlib; this check is reading the wrong \
         file"
    );
}

/// Every fixture lives under the cargo temp dir and nowhere else.
///
/// These tests hand a recursive remover a root. If a fixture could be
/// constructed outside `CARGO_TARGET_TMPDIR` -- an absolute path, a `..`
/// escape -- a bug in the cleaner would delete real files rather than a
/// throwaway tree.
#[test]
fn every_fixture_is_confined_to_the_cargo_temp_dir() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    for name in ["confine_a", "confine_b"] {
        let f = Fixture::new(name);
        let root = f.root.clone();
        f.discard();
        assert!(
            root.starts_with(&tmp),
            "a fixture root {root:?} is outside {tmp:?}; these tests point a \
             recursive remover at that path"
        );
        assert!(
            !root.to_string_lossy().contains(".."),
            "a fixture root escapes upward: {root:?}"
        );
    }
}

/// Every capture fixture says where it came from.
///
/// The harness has always produced captures and always thrown them away:
/// `harness/.gitignore` discards `captures/*.pcap` and only `.gitkeep` is
/// tracked, so each run reproduced traffic no test would ever see again while
/// the project went short of fixtures. That is `LIVE2` in
/// `docs/design/backlog.md`.
///
/// The reason it could not simply keep them is `LIVE4`: a capture with no
/// recorded provenance cannot be safely promoted afterwards, because nobody
/// can later establish which scenario produced it, which media anchor was in
/// force, or whether it carries anything that must not be committed. Five
/// undocumented captures sat in `harness/captures/` for two weeks and had to
/// be deleted rather than promoted, for exactly that reason.
///
/// So promotion now goes through `harness/scripts/promote.sh`, which writes an
/// entry here, and this gate is what makes the entry non-optional.
///
/// **The pre-manifest list is a ratchet that only shrinks.** The 36 fixtures
/// below predate this rule and most are third-party captures whose provenance
/// nobody in this repository can now establish -- inventing one would be worse
/// than admitting the gap. A fixture moves off that list by gaining a real
/// manifest entry, and the two sets are disjoint so a name cannot be in both.
#[test]
fn every_committed_capture_fixture_says_where_it_came_from() {
    // Fixtures that predate PROVENANCE.md. Do not add to this list: a new
    // fixture arrives through promote.sh, which writes the manifest entry.
    const PRE_MANIFEST: &[&str] = &[
        "Asterisk_ZFONE_XLITE.pcap",
        "b2bua-asterisk.pcapng",
        "c07-sip-r2.cap",
        "codec-negotiation.pcap",
        "DTMFsipinfo.pcap",
        "h263-over-rtp.pcap",
        "http-example.cap",
        "invite-opus-bye.pcap",
        "linux-sll2-pppoe.pcap",
        "linux-sll-pppoe.pcap",
        "loopback-dlt-loop.pcap",
        "metasploit-sip-invite-spoof.pcap",
        "options-keepalive-reused-cseq.pcap",
        "register-invite-reinvite-bye.pcap",
        "rtp-protocol.pcap",
        "rtsp-interleaved-tcp.cap",
        "rtsp-packets.cap",
        "sip-488-codec-reject.pcapng",
        "sip-auth-failure.pcapng",
        "SIP_CALL_RTP_G711",
        "SIP_DTMF2.cap",
        "sip-lint-findings.pcap",
        "sip-over-tcp.pcap",
        "sipp-branch-scenario.pcapng",
        "sip-problem-call.pcap",
        "sip-proxy.pcap",
        "siprec-opensips-invite.pcap",
        "sip-register.pcap",
        "sip-routing-error.pcapng",
        "sip-rtp-g711.pcap",
        "sip-rtp-g722.pcap",
        "sip-rtp-g729a.pcap",
        "sip-rtp-opus-hybrid.pcap",
        "sip-sdp-example.pcap",
        "speech_8k_ulaw.pcap",
        "voicecmd_combined.pcap",
    ];
    // Every label promote.sh writes. A manifest entry missing one of these is
    // the shape the whole rule exists to prevent: a fixture that LOOKS
    // documented and cannot answer which anchor was in force.
    const REQUIRED_LABELS: &[&str] = &[
        "**Taken:**",
        "**Media anchor:**",
        "**Filter:**",
        "**Packets:**",
        "**SHA-256:**",
        "**Pins:**",
    ];

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("tests/pcap-samples");
    let manifest_path = root.join("tests/pcap-samples/PROVENANCE.md");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read tests/pcap-samples/PROVENANCE.md: {e}"));

    // Sections, in order, as `### <file name>` followed by its body.
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in manifest.lines() {
        if let Some(name) = line.strip_prefix("### ") {
            if let Some(done) = current.take() {
                sections.push(done);
            }
            current = Some((name.trim().to_string(), String::new()));
        } else if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(done) = current.take() {
        sections.push(done);
    }

    let documented: std::collections::BTreeSet<&str> =
        sections.iter().map(|(n, _)| n.as_str()).collect();

    // 1. Every entry names a file that is really there.
    for (name, _) in &sections {
        assert!(
            dir.join(name).is_file(),
            "PROVENANCE.md documents {name}, which is not in tests/pcap-samples/. \
             An entry for a fixture nobody can open is worse than no entry."
        );
    }

    // 2. Every entry carries every label.
    for (name, body) in &sections {
        for label in REQUIRED_LABELS {
            assert!(
                body.contains(label),
                "PROVENANCE.md's entry for {name} has no {label} line. \
                 promote.sh writes all {} of them; an entry missing one was \
                 written by hand and cannot answer what it claims to.",
                REQUIRED_LABELS.len()
            );
        }
    }

    // 3. The two sets are disjoint, so a fixture is described in exactly one
    //    place. A name in both would let the pre-manifest list keep a fixture
    //    exempt while its entry rotted.
    for name in PRE_MANIFEST {
        assert!(
            !documented.contains(name),
            "{name} is on the pre-manifest list AND has a PROVENANCE.md entry. \
             Take it off the list -- the entry is the better answer, and two \
             records of one fixture is how they come apart."
        );
    }

    // 4. Nothing is undocumented.
    let mut orphans: Vec<String> = Vec::new();
    let mut present = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read tests/pcap-samples") {
        let entry = entry.expect("dir entry");
        if !entry.file_type().expect("file type").is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "PROVENANCE.md" {
            continue;
        }
        present += 1;
        if !documented.contains(name.as_str()) && !PRE_MANIFEST.contains(&name.as_str()) {
            orphans.push(name);
        }
    }
    orphans.sort();
    assert!(
        orphans.is_empty(),
        "these capture fixtures say nothing about where they came from:\n  {}\n\
         Promote captures with harness/scripts/promote.sh, which writes the \
         entry. A fixture nobody can attribute cannot be trusted by the next \
         person to change a parser, because they cannot tell whether its \
         assertion is load-bearing.",
        orphans.join("\n  ")
    );

    // The count is a floor, not a fact about the directory: it exists so that
    // a read_dir that stopped matching reports as a failure rather than as an
    // empty, passing sweep.
    assert!(
        present >= PRE_MANIFEST.len(),
        "found only {present} fixtures against {} on the pre-manifest list. \
         Fixtures do not get deleted casually, so this is far more likely to \
         be the directory walk breaking than the tree shrinking.",
        PRE_MANIFEST.len()
    );
}

// ── What counts as a stray file in `.git/` ─────────────────────────────

/// The extensions a shell redirect target ends up with.
///
/// Mirrored in `scripts/clean-stale.py` as `STRAY_REDIRECT_SUFFIXES`, and
/// `the_gate_and_the_cleaner_share_one_definition_of_a_hook_log` fails
/// if the two lists differ. It was `.log` alone until 2026-09-12, when a
/// background commit wrote `.git/sipnab-bg-commit.log` and the gate caught it
/// -- and would have missed the identical mistake spelled `bg-commit.out`.
///
/// `.txt` is deliberately absent: the pre-commit hook writes
/// `.git/sipnab-test-wedge-stacks.txt` on purpose, without the hook prefix.
const STRAY_REDIRECT_SUFFIXES: &[&str] = &[".log", ".out", ".err"];

/// Whether one `.git/` entry is a redirect target nobody owns.
fn is_stray_git_file(name: &str) -> bool {
    STRAY_REDIRECT_SUFFIXES.iter().any(|s| name.ends_with(s)) && !name.starts_with(HOOK_LOG_PREFIX)
}

/// Every stray redirect target directly inside `gitdir`, sorted.
fn stray_git_files(gitdir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(gitdir) else {
        return Vec::new();
    };
    let mut stray: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_stray_git_file(n))
        .collect();
    stray.sort();
    stray
}

/// A redirect target is stray whatever extension it was given.
#[test]
fn a_redirect_target_is_stray_whatever_its_extension() {
    for name in [
        "sipnab-bg-commit.log", // the file that tripped this gate on 2026-09-12
        "bg-commit.out",        // the same mistake the old `.log` rule would miss
        "cargo-test.err",
    ] {
        assert!(
            is_stray_git_file(name),
            "{name} is a redirect target nobody owns"
        );
    }
}

/// The hooks' own files, and git's, are never called stray.
#[test]
fn the_hooks_and_gits_own_files_are_never_called_stray() {
    for name in [
        "sipnab-pre-commit-tests.log",
        "sipnab-pre-commit-tests.live",
        "sipnab-pre-push-corpus.log",
        "sipnab-test-wedge-stacks.txt",
        "COMMIT_EDITMSG",
        "ORIG_HEAD",
        "index",
    ] {
        assert!(!is_stray_git_file(name), "{name} is owned, not stray");
    }
}

/// The scanner, driven against a real directory, reports exactly the strays.
///
/// The predicate being right is not the same as the scan applying it. A scan
/// that filtered on the wrong field, or stopped at the first match, would pass
/// every predicate test and miss a real file.
#[test]
fn the_stray_scan_reports_exactly_the_strays_in_a_real_directory() {
    let f = Fixture::new("stray_git_scan");
    for owned in [
        "sipnab-pre-commit-tests.log",
        "sipnab-test-wedge-stacks.txt",
        "COMMIT_EDITMSG",
    ] {
        f.write(&format!(".git/{owned}"), "x");
    }
    for stray in ["bg-commit.out", "scratch.log", "cargo.err"] {
        f.write(&format!(".git/{stray}"), "x");
    }
    // A directory named like a log is not a file, and is not this rule's.
    std::fs::create_dir_all(f.root.join(".git/weird.log")).expect("fixture dir");
    let found = stray_git_files(&f.root.join(".git"));
    f.discard();
    assert_eq!(
        found,
        vec![
            "bg-commit.out".to_owned(),
            "cargo.err".to_owned(),
            "scratch.log".to_owned()
        ],
        "the scan must report every stray file and nothing owned"
    );
}

/// With `--apply`, a stray `.out` goes too -- the cleaner acts on the widened rule.
#[test]
fn apply_removes_a_stray_out_file_as_well_as_a_log() {
    let f = Fixture::new("clean_apply_out");
    f.write(".git/bg-commit.out", "x");
    f.age(".git/bg-commit.out", 30);
    let (ok, said) = f.run(&["--apply"]);
    let gone = !f.exists(".git/bg-commit.out");
    f.discard();
    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        gone,
        "the gate reports a stray `.out` and the cleaner kept it, so the gate \
         demands a deletion its own fixer will not do:\n{said}"
    );
}
