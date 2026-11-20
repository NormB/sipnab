// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Mess is deleted by a rule, not by remembering.
//!
//! CLAUDE.md has said "delete every temp file in the SAME turn" for months,
//! and on 2026-09-01 this repository held 21 stray `.git/*.log` files I had
//! written across sessions, three abandoned worktrees totaling 136 GB, and a
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

#[path = "../src/test_scratch.rs"]
mod test_scratch;

#[path = "../src/test_prereq.rs"]
mod test_prereq;
#[path = "support/tracked.rs"]
mod tracked;

use std::path::{Path, PathBuf};
use std::process::Command;

/// The error a fallible test returns: any error, boxed, so `?` works on
/// I/O, parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

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
fn the_git_directory_holds_no_stray_logs() -> Result<(), TestError> {
    let gitdir = repo().join(".git");
    let probe = if gitdir.is_dir() {
        Ok(())
    } else {
        Err(format!("{} is not a directory", gitdir.display()))
    };
    if !test_prereq::present(
        "git-dir",
        test_prereq::Need::Optional(
            "a linked worktree or a source tarball has no .git directory of its own; \
             CI's checkout has one.",
        ),
        probe,
    ) {
        return Ok(());
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
    Ok(())
}

/// The working tree holds no editor or test detritus.
///
/// `.orig` and `.rej` are a merge somebody walked away from; `.snap.new` is an
/// insta snapshot awaiting review. Each is legitimate for an hour and mess
/// after that, and a stale one silently misleads the next person to look.
#[test]
fn the_working_tree_holds_no_conflict_or_snapshot_detritus() -> Result<(), TestError> {
    let out = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(repo())
        .output()
        .map_err(|e| format!("git status: {e}"))?;
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
    Ok(())
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

/// How long a clean worktree must sit untouched before it counts as abandoned.
const ABANDONED_AFTER: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Abandoned means nothing worth keeping AND nobody has touched it for a day.
fn is_abandoned(
    dirty_lines: usize,
    commits_ahead: usize,
    idle: std::time::Duration,
    in_use: bool,
) -> bool {
    !in_use && !worth_keeping(dirty_lines, commits_ahead) && idle >= ABANDONED_AFTER
}

/// Whether a process has its working directory in `worktree`, from `cwds`.
/// `Path::starts_with` compares whole components, so `/w/wt-2` is not in `/w/wt`.
fn in_use(worktree: &Path, cwds: &[PathBuf]) -> bool {
    cwds.iter().any(|cwd| cwd.starts_with(worktree))
}

/// The working directories of this host's processes, from `/proc/*/cwd`
/// (Linux). Empty where there is no `/proc`: the idle rule alone then decides.
/// A process this user cannot read is skipped.
fn process_cwds() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .bytes()
                .all(|b| b.is_ascii_digit())
        })
        .filter_map(|e| std::fs::read_link(e.path().join("cwd")).ok())
        .collect()
}

/// Time since anyone last moved this worktree's HEAD or index, from the mtimes
/// of those files in its own git directory. Unreadable reads as "just touched",
/// so a probe that fails never reports a worktree for removal.
fn idle_for(path: &str) -> std::time::Duration {
    let git_dir = worktree_git(path)
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let newest = git_dir.and_then(|dir| {
        ["HEAD", "index"]
            .iter()
            .filter_map(|f| {
                std::fs::metadata(Path::new(&dir).join(f))
                    .ok()?
                    .modified()
                    .ok()
            })
            .max()
    });
    newest
        .and_then(|t| t.elapsed().ok())
        .unwrap_or(std::time::Duration::ZERO)
}

/// A clean worktree created minutes ago is someone's work starting, not waste.
///
/// `git worktree add` leaves a checkout with nothing uncommitted and nothing
/// unmerged, so until its first edit the gate called it abandoned and failed
/// every other checkout's hook: seen 2026-10-01 for a worktree another session
/// had created seconds before. Only a clean worktree idle for a day is reported.
#[test]
fn a_clean_worktree_is_abandoned_only_once_it_has_sat_idle() -> Result<(), TestError> {
    let hour = std::time::Duration::from_secs(3600);
    assert!(
        !is_abandoned(0, 0, hour, false),
        "a clean worktree touched an hour ago is in use"
    );
    assert!(
        is_abandoned(0, 0, 25 * hour, false),
        "a clean worktree idle for over a day is abandoned"
    );
    assert!(
        !is_abandoned(3, 0, 1000 * hour, false) && !is_abandoned(0, 1, 1000 * hour, false),
        "work worth keeping is never abandoned, however old"
    );
    Ok(())
}

/// A worktree a process is working in is in use, however old its index.
///
/// On 2026-11-23 the gate named a clean worktree whose index dated from two
/// days before while a resumed agent ran `cargo test` in it, and so failed
/// another agent's pre-check on a third checkout's state.
#[test]
fn a_clean_idle_worktree_a_process_works_in_is_not_abandoned() -> Result<(), TestError> {
    let week = std::time::Duration::from_secs(7 * 24 * 3600);
    assert!(
        !is_abandoned(0, 0, week, true),
        "a clean worktree idle for a week with a process in it is in use"
    );
    assert!(
        is_abandoned(0, 0, week, false),
        "the same worktree with no process in it is abandoned"
    );
    Ok(())
}

#[test]
fn a_process_in_the_worktree_root_uses_it() -> Result<(), TestError> {
    let cwds = [PathBuf::from("/w/sipnab-docs")];
    assert!(
        in_use(Path::new("/w/sipnab-docs"), &cwds),
        "a process whose cwd is the worktree uses it"
    );
    Ok(())
}

#[test]
fn a_process_in_a_subdirectory_uses_the_worktree() -> Result<(), TestError> {
    let cwds = [
        PathBuf::from("/srv/x"),
        PathBuf::from("/w/wt/website/content"),
    ];
    assert!(
        in_use(Path::new("/w/wt"), &cwds),
        "a process in a subdirectory of the worktree uses it"
    );
    Ok(())
}

#[test]
fn a_sibling_whose_name_extends_the_worktree_name_does_not_use_it() -> Result<(), TestError> {
    let cwds = [PathBuf::from("/w/wt-2"), PathBuf::from("/w/wtx/src")];
    assert!(
        !in_use(Path::new("/w/wt"), &cwds),
        "/w/wt-2 and /w/wtx are other directories, not part of /w/wt"
    );
    Ok(())
}

#[test]
fn a_parent_directory_cwd_does_not_use_the_worktree() -> Result<(), TestError> {
    let cwds = [PathBuf::from("/w"), PathBuf::from("/")];
    assert!(
        !in_use(Path::new("/w/wt"), &cwds),
        "a shell in the parent directory is not working in the worktree"
    );
    Ok(())
}

#[test]
fn no_process_means_no_use() -> Result<(), TestError> {
    assert!(
        !in_use(Path::new("/w/wt"), &[]),
        "an empty process list uses nothing"
    );
    Ok(())
}

/// The reader is proved on this process: its own working directory is listed.
#[cfg(target_os = "linux")]
#[test]
fn the_process_reader_lists_this_tests_own_working_directory() -> Result<(), TestError> {
    let here = std::env::current_dir()?;
    let cwds = process_cwds();
    assert!(
        cwds.contains(&here),
        "{here:?} is this process's cwd and /proc lists it; read {} cwds",
        cwds.len()
    );
    Ok(())
}

/// The probe must scrub the hook's variables, or it reports the wrong repo.
#[test]
fn the_worktree_probe_scrubs_the_hooks_git_environment() -> Result<(), TestError> {
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
    Ok(())
}

/// Committed-but-unmerged work counts. Only nothing-at-all is abandoned.
#[test]
fn a_worktree_is_kept_for_uncommitted_or_unmerged_work_and_dropped_for_neither()
-> Result<(), TestError> {
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
    Ok(())
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
    // Each entry is a block that starts with its `worktree` line. A `locked`
    // line anywhere in the block means the worktree is in use (see
    // `a_locked_worktree_is_in_use_and_never_reported`).
    let mut entry: Option<(&str, bool)> = None;
    let mut finish = |entry: Option<(&str, bool)>, out: &mut Vec<String>| {
        let Some((path, locked)) = entry else { return };
        if !seen_main {
            seen_main = true;
            return; // the main checkout, which git refuses to remove
        }
        if locked || Path::new(path) == running_in {
            return; // in use, or the checkout we are running in
        }
        out.push(path.to_string());
    };
    for line in listing.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            finish(entry.take(), &mut out);
            entry = Some((path, false));
        } else if (line == "locked" || line.starts_with("locked "))
            && let Some((_, locked)) = entry.as_mut()
        {
            *locked = true;
        }
    }
    finish(entry, &mut out);
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
fn the_main_checkout_is_never_reported_and_a_linked_one_still_is() -> Result<(), TestError> {
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
    Ok(())
}

/// A LOCKED worktree is in use, and git itself refuses to remove it.
///
/// Agent tools lock a worktree for as long as their process runs (`git worktree
/// lock`, recorded as a `locked` line in the porcelain listing). Until the agent
/// commits, it holds nothing uncommitted and nothing unmerged, so the gate
/// called a live worktree abandoned and failed every other checkout's hook. The
/// fix it named, `git worktree remove --force`, is refused for a locked
/// worktree: the same "demands output its fixer will never produce" defect the
/// main-checkout exclusion below answers. An unlocked clean one is still
/// reported.
#[test]
fn a_locked_worktree_is_in_use_and_never_reported() -> Result<(), TestError> {
    let listing = "\
worktree /srv/checkouts/sipnab
HEAD 1111111111111111111111111111111111111111
branch refs/heads/main

worktree /srv/checkouts/sipnab-agent
HEAD 2222222222222222222222222222222222222222
branch refs/heads/agent
locked claude agent agent-1 (pid 42 start 7)

worktree /srv/checkouts/sipnab-bare-lock
HEAD 3333333333333333333333333333333333333333
branch refs/heads/bare
locked

worktree /srv/checkouts/sipnab-idle
HEAD 4444444444444444444444444444444444444444
branch refs/heads/idle
";
    assert_eq!(
        reportable_worktrees(listing, Path::new("/nowhere")),
        vec!["/srv/checkouts/sipnab-idle".to_string()],
        "both locked worktrees (with and without a reason) are in use; the \
         unlocked idle one is still reportable"
    );
    Ok(())
}

/// **Second of two.** The exclusion cannot swallow the rule.
///
/// A listing with only the main checkout in it yields nothing to report, and a
/// listing with none at all yields nothing either — but the gate above asserts
/// `abandoned.is_empty()`, so "nothing to report" and "the parse broke" look
/// identical from the outside. This pins that the parser really is reading the
/// listing rather than returning an empty vector whatever it is given.
#[test]
fn the_worktree_parser_reads_the_listing_it_is_given() -> Result<(), TestError> {
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
    Ok(())
}

#[test]
fn no_worktree_is_abandoned_with_nothing_worth_keeping() -> Result<(), TestError> {
    let out = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(repo())
        .output()
        .map_err(|e| format!("git worktree list: {e}"))?;
    let listing = String::from_utf8_lossy(&out.stdout);

    let mut abandoned = Vec::new();
    let cwds = process_cwds();
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
        if is_abandoned(
            dirty_lines,
            commits_ahead,
            idle_for(path),
            in_use(Path::new(path), &cwds),
        ) {
            abandoned.push(path.to_string());
        }
    }
    assert!(
        abandoned.is_empty(),
        "these worktrees hold no uncommitted work, have sat untouched for a \
         day, and are pure disk cost \
         ({} of them): {abandoned:?}\n\
         Remove with `git worktree remove --force <path>`, or \
         `scripts/clean-stale.py --apply`.",
        abandoned.len()
    );
    Ok(())
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
fn no_tracked_file_carries_a_conflict_marker() -> Result<(), TestError> {
    let listed = tracked::ls_files(repo(), &[])?;
    let mut bad = Vec::new();
    for rel in listed.iter().map(String::as_str) {
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
    Ok(())
}

/// POSITIVE CONTROL: the predicate must see a marker when one is there, and
/// must not mistake a Markdown underline for one.
#[test]
fn the_conflict_marker_predicate_sees_markers_and_not_underlines() -> Result<(), TestError> {
    assert!(has_conflict_markers(
        "a\n<<<<<<< HEAD\nb\n=======\nc\n>>>>>>> other\n"
    ));
    assert!(has_conflict_markers(">>>>>>> theirs\n"));
    assert!(
        !has_conflict_markers("Title\n=======\n\nbody\n"),
        "a setext underline is not a marker"
    );
    assert!(!has_conflict_markers("no markers here\n"));
    Ok(())
}

// ── the script: driven against fixtures, because it deletes ─────────────

/// A throwaway tree for the cleaner to act on.
struct Fixture {
    root: test_scratch::ScratchDir,
}

impl Fixture {
    fn new(name: &str) -> Result<Self, TestError> {
        let root = test_scratch::ScratchDir::new_in(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
            &format!("{name}-"),
        )
        .map_err(|e| format!("scratch dir: {e}"))?;
        std::fs::create_dir_all(root.join(".git")).map_err(|e| format!("fixture .git: {e}"))?;
        Ok(Self { root })
    }

    fn write(&self, rel: &str, body: &str) -> Result<PathBuf, TestError> {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("fixture parent: {e}"))?;
        }
        std::fs::write(&p, body).map_err(|e| format!("fixture file: {e}"))?;
        Ok(p)
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
    fn age(&self, rel: &str, days: u64) -> Result<(), TestError> {
        let p = self.root.join(rel);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
        let f = std::fs::File::options()
            .write(true)
            .open(&p)
            .map_err(|e| format!("open {} to backdate: {e}", p.display()))?;
        f.set_modified(when)
            .map_err(|e| format!("backdate {}: {e}", p.display()))?;

        let got = std::fs::metadata(&p)
            .and_then(|m| m.modified())
            .map_err(|e| format!("read back mtime of {}: {e}", p.display()))?;
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
        Ok(())
    }

    fn run(&self, extra: &[&str]) -> Result<(bool, String), TestError> {
        let mut cmd = Command::new("python3");
        cmd.arg(repo().join("scripts/clean-stale.py"))
            .arg("--root")
            .arg(&self.root)
            .args(extra)
            .current_dir(repo());
        let out = cmd
            .output()
            .map_err(|e| format!("run scripts/clean-stale.py: {e}"))?;
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok((out.status.success(), said))
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
fn the_cleaner_removes_nothing_without_apply() -> Result<(), TestError> {
    let f = Fixture::new("clean_dryrun")?;
    f.write(".git/scratch.log", "x")?;
    f.age(".git/scratch.log", 30)?;
    let (ok, said) = f.run(&[])?;
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
    Ok(())
}

/// With `--apply`, a stray log goes and a hook's log stays.
///
/// The distinction the gate above draws, enforced in the tool that acts on it.
/// Deleting `sipnab-pre-commit-tests.log` would remove the durable record
/// CLAUDE.md tells me to read instead of making a second copy.
#[test]
fn apply_removes_a_stray_log_and_keeps_the_hooks_own() -> Result<(), TestError> {
    let f = Fixture::new("clean_apply")?;
    f.write(".git/scratch.log", "x")?;
    f.write(".git/sipnab-pre-commit-tests.log", "x")?;
    f.age(".git/scratch.log", 30)?;
    f.age(".git/sipnab-pre-commit-tests.log", 30)?;

    let (ok, said) = f.run(&["--apply"])?;
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
    Ok(())
}

/// A file young enough to still be in use is left alone.
///
/// The cleaner may run at any time, including while a build is writing. An age
/// floor is what separates a cleaner from a race.
#[test]
fn a_recent_file_is_never_removed() -> Result<(), TestError> {
    let f = Fixture::new("clean_recent")?;
    f.write(".git/scratch.log", "x")?; // written just now
    let (ok, said) = f.run(&["--apply"])?;
    let survived = f.exists(".git/scratch.log");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        survived,
        "a file written seconds ago was deleted. The cleaner can run while a \
         build is writing, and an age floor is what keeps it from racing one."
    );
    Ok(())
}

/// Detritus goes; source does not.
///
/// The blast radius. A cleaner that took `.rs` files with it would be a
/// catastrophe found long after the fact, so the negative case is asserted
/// beside the positive one every time.
#[test]
fn apply_removes_detritus_and_never_source() -> Result<(), TestError> {
    let f = Fixture::new("clean_detritus")?;
    for (path, _) in [
        ("src/thing.rs.orig", ()),
        ("src/thing.rs.rej", ()),
        ("tests/snapshots/x.snap.new", ()),
        ("notes.bak", ()),
    ] {
        f.write(path, "x")?;
        f.age(path, 30)?;
    }
    f.write("src/thing.rs", "fn main() {}")?;
    f.write("tests/snapshots/x.snap", "snapshot")?;
    f.age("src/thing.rs", 30)?;
    f.age("tests/snapshots/x.snap", 30)?;

    let (ok, said) = f.run(&["--apply"])?;
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
    Ok(())
}

/// It reports what it reclaimed.
///
/// A cleanup that runs unattended and says nothing is indistinguishable from
/// one that is not running at all — which is how the 1.6 TB accumulated.
#[test]
fn the_cleaner_reports_what_it_reclaimed() -> Result<(), TestError> {
    let f = Fixture::new("clean_report")?;
    f.write(".git/scratch.log", &"x".repeat(4096))?;
    f.age(".git/scratch.log", 30)?;
    let (ok, said) = f.run(&["--apply"])?;
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        said.to_lowercase().contains("reclaim") || said.to_lowercase().contains("removed"),
        "the cleaner must say what it did; a silent unattended job cannot be \
         told from one that never ran:\n{said}"
    );
    Ok(())
}

/// It refuses a root that is not a checkout.
///
/// Pointed at the wrong directory, a recursive remover is a disaster. It must
/// decline rather than do its best.
#[test]
fn the_cleaner_refuses_a_root_that_is_not_a_checkout() -> Result<(), TestError> {
    let root = test_scratch::ScratchDir::new_in(
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        "clean_notarepo-",
    )
    .map_err(|e| format!("scratch dir: {e}"))?;
    std::fs::create_dir_all(&root).map_err(|e| format!("mkdir: {e}"))?;
    std::fs::write(root.join("important.rs"), "fn main() {}").map_err(|e| format!("write: {e}"))?;

    let out = Command::new("python3")
        .arg(repo().join("scripts/clean-stale.py"))
        .arg("--root")
        .arg(&root)
        .arg("--apply")
        .current_dir(repo())
        .output()
        .map_err(|e| format!("run cleaner: {e}"))?;
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
    Ok(())
}

/// The gate and the cleaner agree on what a hook log looks like.
///
/// One rule in one place. If the gate reports `sipnab-pre-*` as mess while the
/// cleaner preserves it, one of them is wrong and the disagreement shows up as
/// a gate nobody can satisfy.
#[test]
fn the_gate_and_the_cleaner_share_one_definition_of_a_hook_log() -> Result<(), TestError> {
    let script = std::fs::read_to_string(repo().join("scripts/clean-stale.py"))
        .map_err(|e| format!("read scripts/clean-stale.py: {e}"))?;
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
        .ok_or("the cleaner declares STRAY_REDIRECT_SUFFIXES on one line")?;
    let theirs: Vec<&str> = regex::Regex::new(r#""(\.[a-z]+)""#)
        .map_err(|e| format!("regex: {e}"))?
        .captures_iter(line)
        .map(|c| c.get(1).map_or("", |m| m.as_str()))
        .collect();
    assert_eq!(
        theirs, STRAY_REDIRECT_SUFFIXES,
        "the gate and the cleaner disagree about which extensions a stray \
         redirect target has"
    );
    Ok(())
}

/// Build caches survive when there is room.
///
/// A cache dropped every night never pays for itself. The threshold is what
/// makes this safe to wire to a timer instead of something run by hand after
/// the disk already hurts.
#[test]
fn build_caches_are_kept_when_there_is_room() -> Result<(), TestError> {
    let f = Fixture::new("clean_cache_room")?;
    f.write("target/debug/incremental/x.bin", "payload")?;
    let (ok, said) = f.run(&["--apply", "--reclaim-build-cache", "--disk-floor-gb", "1"])?;
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
    Ok(())
}

/// Under pressure they go — and only with `--apply`.
///
/// The dry run must still name them: this is the branch that reclaims
/// hundreds of gigabytes, so it is the one whose plan most needs reading
/// before it is granted the flag.
#[test]
fn build_caches_go_only_under_pressure_and_only_with_apply() -> Result<(), TestError> {
    let f = Fixture::new("clean_cache_pressure")?;
    f.write("target/debug/incremental/x.bin", "payload")?;

    let (ok, plan) = f.run(&["--reclaim-build-cache", "--disk-floor-gb", "99999999"])?;
    let survived_dry = f.exists("target/debug/incremental/x.bin");

    let (ok2, done) = f.run(&[
        "--apply",
        "--reclaim-build-cache",
        "--disk-floor-gb",
        "99999999",
    ])?;
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
    Ok(())
}

/// `deps/` is never touched.
///
/// It is 961 GB of the same accumulation and is deliberately out of scope: a
/// partial removal leaves cargo rebuilding in confusing ways, so reclaiming it
/// is a `cargo clean` — a decision a person makes, not a cron job.
#[test]
fn the_cleaner_never_touches_the_dependency_cache() -> Result<(), TestError> {
    let f = Fixture::new("clean_deps_safe")?;
    f.write("target/debug/deps/libthing.rlib", "artifact")?;
    f.write("target/debug/incremental/x.bin", "payload")?;
    let (ok, said) = f.run(&[
        "--apply",
        "--reclaim-build-cache",
        "--disk-floor-gb",
        "99999999",
    ])?;
    let deps_kept = f.exists("target/debug/deps/libthing.rlib");
    f.discard();

    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        deps_kept,
        "the cleaner removed from target/debug/deps. Partial removal there \
         leaves cargo rebuilding in ways that look like corruption:\n{said}"
    );
    Ok(())
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
fn backdating_a_fixture_file_actually_moves_its_mtime() -> Result<(), TestError> {
    let f = Fixture::new("age_primitive")?;
    f.write(".git/probe.log", "x")?;

    let before = std::fs::metadata(f.root.join(".git/probe.log"))
        .and_then(|m| m.modified())
        .map_err(|e| format!("mtime before: {e}"))?;
    f.age(".git/probe.log", 30)?;
    let after = std::fs::metadata(f.root.join(".git/probe.log"))
        .and_then(|m| m.modified())
        .map_err(|e| format!("mtime after: {e}"))?;
    f.discard();

    let moved = before
        .duration_since(after)
        .map_err(|e| format!("backdating must move the mtime BACKWARDS: {e}"))?;
    assert!(
        moved.as_secs() >= 29 * 86_400,
        "backdating moved the mtime by only {}s; the age floor cannot be \
         exercised and every age-gated test is measuring the wrong thing",
        moved.as_secs()
    );
    Ok(())
}

/// The floor separates a recent file from a backdated one, in one run.
///
/// Both directions together on purpose. A fixture that made everything look
/// OLD would pass the removal tests; one that made everything look NEW would
/// pass the retention test. Only asserting both at once catches a backdating
/// mechanism that has quietly stopped working.
#[test]
fn the_age_floor_separates_recent_from_backdated_in_one_run() -> Result<(), TestError> {
    let f = Fixture::new("age_both_ways")?;
    f.write(".git/old.log", "x")?;
    f.write(".git/new.log", "x")?;
    f.age(".git/old.log", 30)?;

    let (ok, said) = f.run(&["--apply"])?;
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
    Ok(())
}

/// No test shells out to read or write file metadata.
///
/// `touch`, `stat`, `date` and `readlink` differ between GNU and BSD in
/// exactly the flags a test reaches for. Rust's own filesystem API is
/// portable, so there is no reason to leave the process.
#[test]
fn no_test_shells_out_for_file_metadata() -> Result<(), TestError> {
    let mut offenders = Vec::new();
    let mut scanned = 0;
    let listed = tracked::ls_files(repo(), &["--", "tests/"])?;
    for file in listed.iter().map(String::as_str) {
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
    Ok(())
}

/// No executable line uses a GNU-only spelling.
///
/// The general form, across the scripts, hooks, workflows and packaging.
/// Each flag in `shell_flags::RULES` has a BSD counterpart that differs, so
/// the command does not fail loudly on macOS -- it fails in whatever way that
/// platform's tool chooses, which was "silently do nothing" for the one that
/// started this.
///
/// Until 2026-11-20 this matched fixed substrings (`stat -c`), so `stat -L -c
/// %s` passed it and failed CI's macOS shard (PR #848, run 44258178176). It
/// now parses each command and its flags (`shell_flags`), in any position and
/// in clustered short flags.
#[test]
fn no_executable_line_uses_a_gnu_only_spelling() -> Result<(), TestError> {
    let listed = tracked::ls_files(repo(), &[])?;

    let mut offenders = Vec::new();
    let mut scanned = 0;
    for file in listed.iter().map(String::as_str) {
        let Ok(src) = std::fs::read_to_string(repo().join(file)) else {
            continue; // binary fixture
        };
        if !shell_flags::is_scanned_file(file, src.lines().next().unwrap_or("")) {
            continue;
        }
        scanned += 1;
        for (line, finding) in shell_flags::scan_file(file, &src) {
            let fix = shell_flags::fix_for(&finding);
            offenders.push(format!("  {file}:{line}: {finding} -- {fix}"));
        }
    }
    // Measured 2026-11-20 on origin/main 0f6d2e9af: see SCANNED_FLOOR.
    assert!(
        scanned >= shell_flags::SCANNED_FLOOR,
        "only {scanned} file(s) scanned, fewer than {}; the walk is wrong and \
         this proves nothing",
        shell_flags::SCANNED_FLOOR
    );
    assert!(
        offenders.is_empty(),
        "these lines use a GNU-only spelling and behave differently on \
         macOS. Use the portable form, put the BSD form on the same line \
         after `||`, or (for a file or line that runs only on Linux) add it \
         to shell_flags::LINUX_ONLY with the reason:\n{}",
        offenders.join("\n")
    );
    Ok(())
}

/// Every LINUX_ONLY allowance still allows something, and says why.
///
/// An allowance that no longer matches a GNU form is a hole waiting for the
/// next one: it would let a new GNU-only line into a file nobody re-checked.
#[test]
fn every_linux_only_allowance_is_live_and_has_a_reason() -> Result<(), TestError> {
    for entry in shell_flags::LINUX_ONLY {
        assert!(
            shell_flags::reason_is_stated(entry.reason),
            "{}: the allowance needs a stated reason, got {:?}",
            entry.path,
            entry.reason
        );
        let src = std::fs::read_to_string(repo().join(entry.path)).map_err(|e| {
            format!(
                "{}: allowance names a file that cannot be read: {e}",
                entry.path
            )
        })?;
        let raw = shell_flags::raw_findings(entry.path, &src);
        let matched: Vec<_> = raw
            .iter()
            .filter(|(_, text, _)| entry.line.is_none_or(|l| text.contains(l)))
            .collect();
        assert!(
            !matched.is_empty(),
            "{} (line {:?}): the allowance matches no GNU-only form any more; \
             remove it",
            entry.path,
            entry.line
        );
        if let Some(guard) = entry.guard {
            let lines: Vec<usize> = matched.iter().map(|(n, _, _)| *n).collect();
            let unguarded = shell_flags::unguarded_lines(&src, guard, &lines)
                .map_err(|e| format!("{}: {e}", entry.path))?;
            assert!(
                unguarded.is_empty(),
                "{}: lines {unguarded:?} hold a GNU form before the Linux guard \
                 {guard:?}, so the guard does not protect them",
                entry.path
            );
        }
    }
    Ok(())
}

/// The cleaner leaves the process entirely alone.
///
/// It is pure stdlib Python, which is what makes it portable by construction
/// rather than by inspection. A `subprocess` call here would reintroduce the
/// same platform question the fixture just tripped over -- in the tool that
/// DELETES things.
#[test]
fn the_cleaner_shells_out_to_nothing() -> Result<(), TestError> {
    let script = std::fs::read_to_string(repo().join("scripts/clean-stale.py"))
        .map_err(|e| format!("read scripts/clean-stale.py: {e}"))?;
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
    Ok(())
}

/// Every fixture lives under the cargo temp dir and nowhere else.
///
/// These tests hand a recursive remover a root. If a fixture could be
/// constructed outside `CARGO_TARGET_TMPDIR` -- an absolute path, a `..`
/// escape -- a bug in the cleaner would delete real files rather than a
/// throwaway tree.
#[test]
fn every_fixture_is_confined_to_the_cargo_temp_dir() -> Result<(), TestError> {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    for name in ["confine_a", "confine_b"] {
        let f = Fixture::new(name)?;
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
    Ok(())
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
fn every_committed_capture_fixture_says_where_it_came_from() -> Result<(), TestError> {
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
        .map_err(|e| format!("read tests/pcap-samples/PROVENANCE.md: {e}"))?;

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
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read tests/pcap-samples: {e}"))? {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        if !entry
            .file_type()
            .map_err(|e| format!("file type: {e}"))?
            .is_file()
        {
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
    Ok(())
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
fn a_redirect_target_is_stray_whatever_its_extension() -> Result<(), TestError> {
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
    Ok(())
}

/// The hooks' own files, and git's, are never called stray.
#[test]
fn the_hooks_and_gits_own_files_are_never_called_stray() -> Result<(), TestError> {
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
    Ok(())
}

/// The scanner, driven against a real directory, reports exactly the strays.
///
/// The predicate being right is not the same as the scan applying it. A scan
/// that filtered on the wrong field, or stopped at the first match, would pass
/// every predicate test and miss a real file.
#[test]
fn the_stray_scan_reports_exactly_the_strays_in_a_real_directory() -> Result<(), TestError> {
    let f = Fixture::new("stray_git_scan")?;
    for owned in [
        "sipnab-pre-commit-tests.log",
        "sipnab-test-wedge-stacks.txt",
        "COMMIT_EDITMSG",
    ] {
        f.write(&format!(".git/{owned}"), "x")?;
    }
    for stray in ["bg-commit.out", "scratch.log", "cargo.err"] {
        f.write(&format!(".git/{stray}"), "x")?;
    }
    // A directory named like a log is not a file, and is not this rule's.
    std::fs::create_dir_all(f.root.join(".git/weird.log"))
        .map_err(|e| format!("fixture dir: {e}"))?;
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
    Ok(())
}

/// With `--apply`, a stray `.out` goes too -- the cleaner acts on the widened rule.
#[test]
fn apply_removes_a_stray_out_file_as_well_as_a_log() -> Result<(), TestError> {
    let f = Fixture::new("clean_apply_out")?;
    f.write(".git/bg-commit.out", "x")?;
    f.age(".git/bg-commit.out", 30)?;
    let (ok, said) = f.run(&["--apply"])?;
    let gone = !f.exists(".git/bg-commit.out");
    f.discard();
    assert!(ok, "the cleaner failed:\n{said}");
    assert!(
        gone,
        "the gate reports a stray `.out` and the cleaner kept it, so the gate \
         demands a deletion its own fixer will not do:\n{said}"
    );
    Ok(())
}

// ── shell_flags: the command/flag parser behind the GNU-only gate ───────

/// Finds GNU-only flags in shell command lines.
///
/// A small shell lexer, not a shell: it splits a line into simple commands
/// at `|`, `||`, `&&`, `;`, `&`, `(`, `)`, `$(...)` and backticks, honoring
/// single and double quotes, then reads the flags of every word that names
/// one of the tools in `RULES`, wherever it stands in the command (`sudo
/// stat`, `find -exec sed`). Short flags are read cluster by cluster
/// (`-Lc`), skipping the argument of an option that takes one, so `stat -f
/// -c` is a format, not `-c`. Words after `--` are operands.
///
/// The BSD facts behind `RULES` were read from the FreeBSD manual pages
/// (man.freebsd.org, 2026-11-20): stat, touch, readlink, date and sed
/// document no long options; readlink has only -f and -n; date has no
/// date-string option; touch -d takes only YYYY-MM-DDThh:mm:SS; sed -i
/// takes its extension as an argument, so a bare `-i` reads the next word
/// differently from GNU sed; cp has no -t, -T, -u, -b or -d, and its few
/// long options are not in its synopsis and do not include --parents or
/// --preserve. macOS's tools were not read, so every long option of these
/// six tools counts as GNU-only: one rule, and the short forms are the ones
/// both manuals share.
///
/// Not scanned: Python, Rust and Markdown (no shell lexer applies; Rust tests
/// that shell out are held by `no_test_shells_out_for_file_metadata`), and
/// Dockerfiles, whose RUN lines run in a Linux image by construction.
pub(crate) mod shell_flags {
    /// A Linux-only file or line, and why the GNU form there cannot reach a
    /// BSD host.
    pub struct LinuxOnly {
        pub path: &'static str,
        /// `None`: the whole file. `Some(text)`: lines that contain `text`.
        pub line: Option<&'static str>,
        /// Text of a line that must come BEFORE every allowed GNU form (the
        /// file's own "not Linux, stop here" check), or `None`.
        pub guard: Option<&'static str>,
        pub reason: &'static str,
    }

    /// Files and lines that run only on Linux, each with its reason.
    /// `every_linux_only_allowance_is_live_and_has_a_reason` refuses an entry
    /// that no longer matches a GNU form.
    pub const LINUX_ONLY: &[LinuxOnly] = &[
        LinuxOnly {
            path: "packaging/rpm/build-rpm.sh",
            line: None,
            guard: None,
            reason: "builds the .rpm: release.yml runs it only when matrix.target is \
                     x86_64- or aarch64-unknown-linux-gnu, and ci.yml's RPM job runs on a \
                     self-hosted Linux runner",
        },
        LinuxOnly {
            path: "scripts/check-non-linux.sh",
            line: None,
            guard: Some("[ \"$(uname -s)\" = \"Linux\" ] || skip"),
            reason: "the script calls skip() at its `uname -s` check on every host that \
                     is not Linux, before its first GNU form (the guard is checked)",
        },
        LinuxOnly {
            path: "scripts/check-cert-expiry.sh",
            line: Some("date -u -d \"$not_after\""),
            guard: None,
            reason: "cert-expiry.yml runs it on ubuntu-24.04; where `date -d` fails the \
                     empty result is classified WARN on the next line, never a pass",
        },
    ];

    /// Files the gate must scan at least, measured 2026-11-20 on origin/main
    /// 0f6d2e9af (290 scanned) and set a little under it, so a broken walk
    /// fails while ordinary deletions do not.
    pub const SCANNED_FLOOR: usize = 280;

    /// One GNU-only rule set per tool.
    struct Rule {
        tool: &'static str,
        /// Short options that take an argument (attached or the next word).
        takes_arg: &'static str,
        /// Short options whose argument, if any, must be attached.
        attached_arg: &'static str,
        /// Short options that are GNU-only, with the portable fix.
        gnu_short: &'static [(char, &'static str)],
        /// A short option that is GNU-only when it has nothing attached.
        bare_gnu: Option<(char, &'static str)>,
    }

    const RULES: &[Rule] = &[
        Rule {
            tool: "stat",
            takes_arg: "cft",
            attached_arg: "",
            gnu_short: &[(
                'c',
                "BSD stat spells it -f FORMAT; `wc -c < file` is portable",
            )],
            bare_gnu: None,
        },
        Rule {
            tool: "touch",
            takes_arg: "Adrt",
            attached_arg: "",
            gnu_short: &[(
                'd',
                "BSD touch -d takes only YYYY-MM-DDThh:mm:SS; use -t or std::fs",
            )],
            bare_gnu: None,
        },
        Rule {
            tool: "readlink",
            takes_arg: "",
            attached_arg: "",
            gnu_short: &[
                (
                    'f',
                    "not in every BSD readlink; `cd -P` with `pwd -P` is POSIX",
                ),
                ('e', "BSD readlink has only -f and -n"),
                ('m', "BSD readlink has only -f and -n"),
                ('q', "BSD readlink has only -f and -n"),
                ('s', "BSD readlink has only -f and -n"),
                ('v', "BSD readlink has only -f and -n"),
                ('z', "BSD readlink has only -f and -n"),
            ],
            bare_gnu: None,
        },
        Rule {
            tool: "date",
            takes_arg: "frvz",
            attached_arg: "I",
            gnu_short: &[(
                'd',
                "BSD date has no date-string option; it parses with -j -f FORMAT",
            )],
            bare_gnu: None,
        },
        Rule {
            tool: "cp",
            takes_arg: "St",
            attached_arg: "",
            gnu_short: &[
                ('t', "BSD cp has no -t; name the target last"),
                ('T', "BSD cp has no -T"),
                ('u', "BSD cp has no -u"),
                ('b', "BSD cp has no -b"),
                ('d', "BSD cp has no -d; use -P"),
                ('S', "BSD cp has no -S"),
            ],
            bare_gnu: None,
        },
        Rule {
            tool: "sed",
            takes_arg: "ef",
            attached_arg: "i",
            gnu_short: &[('s', "BSD sed has no -s"), ('z', "BSD sed has no -z")],
            bare_gnu: Some((
                'i',
                "GNU and BSD read the word after a bare -i differently; use -i.bak and remove the .bak",
            )),
        },
    ];

    /// The `lines` (1-based) that do not come after the first line holding
    /// `guard`; an error when no line holds it.
    pub fn unguarded_lines(src: &str, guard: &str, lines: &[usize]) -> Result<Vec<usize>, String> {
        let guard_at = src
            .lines()
            .position(|l| l.contains(guard))
            .map(|i| i + 1)
            .ok_or_else(|| format!("guard {guard:?} is gone"))?;
        Ok(lines.iter().copied().filter(|&n| n <= guard_at).collect())
    }

    /// A stated reason: at least five words.
    pub fn reason_is_stated(reason: &str) -> bool {
        reason.split_whitespace().count() >= 5
    }

    /// The portable fix for a finding (`stat -c`, `cp --parents`).
    pub fn fix_for(finding: &str) -> String {
        let (tool, flag) = finding.split_once(' ').unwrap_or((finding, ""));
        let Some(rule) = RULES.iter().find(|r| r.tool == tool) else {
            return String::from("unknown tool");
        };
        if flag.starts_with("--") {
            return format!("long options are not portable to BSD {tool}; use the short form");
        }
        let ch = flag.chars().nth(1).unwrap_or(' ');
        rule.gnu_short
            .iter()
            .chain(rule.bare_gnu.iter())
            .find(|(g, _)| *g == ch)
            .map_or_else(|| String::from("GNU-only"), |(_, fix)| (*fix).to_string())
    }

    /// One simple command (its words, quotes removed), and whether `||`
    /// joined it to the one before. A quoted command name still runs the
    /// command (`"stat" -c`), so quoting does not exempt a word.
    struct Segment {
        words: Vec<String>,
        after_or: bool,
    }

    #[derive(PartialEq)]
    enum Kind {
        Top,
        Subst,
        Backtick,
    }

    /// One command context: the line itself, a `$(...)` or a backtick pair.
    struct Ctx {
        kind: Kind,
        parens: u32,
        words: Vec<String>,
        cur: String,
        started: bool,
        in_dq: bool,
        after_or: bool,
    }

    impl Ctx {
        fn new(kind: Kind) -> Self {
            Ctx {
                kind,
                parens: 0,
                words: Vec::new(),
                cur: String::new(),
                started: false,
                in_dq: false,
                after_or: false,
            }
        }

        fn end_word(&mut self) {
            if self.started {
                self.words.push(std::mem::take(&mut self.cur));
            }
            self.started = false;
        }

        fn end_segment(&mut self, out: &mut Vec<Segment>, next_after_or: bool) {
            self.end_word();
            if self.words.is_empty() {
                self.after_or |= next_after_or;
            } else {
                out.push(Segment {
                    words: std::mem::take(&mut self.words),
                    after_or: self.after_or,
                });
                self.after_or = next_after_or;
            }
        }

        fn push_char(&mut self, c: char) {
            self.cur.push(c);
            self.started = true;
        }
    }

    /// Splits one logical line into simple commands.
    fn segments(line: &str) -> Vec<Segment> {
        let chars: Vec<char> = line.chars().collect();
        let mut out = Vec::new();
        let mut stack = vec![Ctx::new(Kind::Top)];
        let mut i = 0;
        'scan: while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            let Some(ctx) = stack.last_mut() else { break };
            if ctx.in_dq {
                match (c, next) {
                    ('"', _) => ctx.in_dq = false,
                    ('\\', Some(n)) => {
                        ctx.push_char(n);
                        i += 1;
                    }
                    ('$', Some('(')) => {
                        ctx.started = true;
                        stack.push(Ctx::new(Kind::Subst));
                        i += 1;
                    }
                    ('`', _) => {
                        ctx.started = true;
                        stack.push(Ctx::new(Kind::Backtick));
                    }
                    _ => ctx.push_char(c),
                }
                i += 1;
                continue;
            }
            match (c, next) {
                (' ' | '\t', _) => ctx.end_word(),
                ('\'', _) => {
                    ctx.started = true;
                    i += 1;
                    while i < chars.len() && chars[i] != '\'' {
                        ctx.cur.push(chars[i]);
                        i += 1;
                    }
                }
                ('"', _) => {
                    ctx.started = true;
                    ctx.in_dq = true;
                }
                ('\\', Some(n)) => {
                    ctx.push_char(n);
                    i += 1;
                }
                ('#', _) if !ctx.started => break 'scan,
                ('$', Some('(')) => {
                    ctx.started = true;
                    stack.push(Ctx::new(Kind::Subst));
                    i += 1;
                }
                ('$', Some('{')) => {
                    while i < chars.len() && chars[i] != '}' {
                        ctx.push_char(chars[i]);
                        i += 1;
                    }
                    ctx.push_char('}');
                }
                ('`', _) => {
                    if ctx.kind == Kind::Backtick {
                        close(&mut stack, &mut out);
                    } else {
                        ctx.started = true;
                        stack.push(Ctx::new(Kind::Backtick));
                    }
                }
                ('(', _) => {
                    if ctx.kind == Kind::Subst {
                        ctx.parens += 1;
                    }
                    ctx.end_segment(&mut out, false);
                }
                (')', _) => {
                    if ctx.kind == Kind::Subst && ctx.parens == 0 {
                        close(&mut stack, &mut out);
                    } else {
                        ctx.parens = ctx.parens.saturating_sub(1);
                        ctx.end_segment(&mut out, false);
                    }
                }
                ('|', Some('|')) | ('&', Some('&')) => {
                    ctx.end_segment(&mut out, c == '|');
                    i += 1;
                }
                ('&', _) if ctx.cur.ends_with(['>', '<']) => ctx.push_char(c),
                ('|' | '&' | ';', _) => ctx.end_segment(&mut out, false),
                _ => ctx.push_char(c),
            }
            i += 1;
        }
        while !stack.is_empty() {
            close(&mut stack, &mut out);
        }
        out
    }

    /// Ends the innermost context and returns to its parent.
    fn close(stack: &mut Vec<Ctx>, out: &mut Vec<Segment>) {
        if let Some(mut ctx) = stack.pop() {
            ctx.end_segment(out, false);
        }
    }

    /// The rule for a command word, by its basename (`/usr/bin/stat`).
    fn rule_for(word: &str) -> Option<&'static Rule> {
        let base = word.rsplit('/').next().unwrap_or("");
        RULES.iter().find(|r| r.tool == base)
    }

    /// The GNU-only flags among one tool's arguments.
    fn flags_of(rule: &Rule, args: &[String]) -> Vec<String> {
        let mut found = Vec::new();
        let mut k = 0;
        while k < args.len() {
            let w = args[k].as_str();
            if w == "--" {
                break;
            }
            if let Some(long) = w.strip_prefix("--") {
                let name = long.split('=').next().unwrap_or("");
                found.push(format!("{} --{name}", rule.tool));
            } else if let Some(cluster) = w.strip_prefix('-') {
                let letters: Vec<char> = cluster.chars().collect();
                for (p, &ch) in letters.iter().enumerate() {
                    let last = p + 1 == letters.len();
                    if rule.gnu_short.iter().any(|(g, _)| *g == ch) {
                        found.push(format!("{} -{ch}", rule.tool));
                    }
                    if let Some((b, _)) = rule.bare_gnu
                        && b == ch
                    {
                        if last {
                            found.push(format!("{} -{ch}", rule.tool));
                        }
                        break;
                    }
                    if rule.attached_arg.contains(ch) {
                        break;
                    }
                    if rule.takes_arg.contains(ch) {
                        if last {
                            k += 1;
                        }
                        break;
                    }
                }
            }
            k += 1;
        }
        found
    }

    /// One tool invocation: the segment it is in, its tool and its findings.
    struct Invocation {
        segment: usize,
        tool: &'static str,
        findings: Vec<String>,
    }

    fn invocations(segs: &[Segment]) -> Vec<Invocation> {
        let mut out = Vec::new();
        for (s, seg) in segs.iter().enumerate() {
            let starts = seg
                .words
                .iter()
                .enumerate()
                .filter_map(|(k, w)| rule_for(w).map(|r| (k, r)));
            for (k, rule) in starts {
                // find's `-exec` terminator (`\;` lexes to the word `;`, or
                // `+`) ends this tool's arguments. Another tool's name does
                // not: it may be an operand (`cp -p date -t dir`).
                let end = (k + 1..seg.words.len())
                    .find(|&e| seg.words[e] == ";" || seg.words[e] == "+")
                    .unwrap_or(seg.words.len());
                out.push(Invocation {
                    segment: s,
                    tool: rule.tool,
                    findings: flags_of(rule, &seg.words[k + 1..end]),
                });
            }
        }
        out
    }

    /// The GNU-only findings of one logical line, minus those that carry a
    /// BSD fallback: the same tool, without a GNU-only flag, in another
    /// command of the line, the later of the two joined by `||`.
    pub fn gnu_flags_in(line: &str) -> Vec<String> {
        let segs = segments(line);
        let calls = invocations(&segs);
        let mut out = Vec::new();
        for (i, call) in calls.iter().enumerate() {
            if call.findings.is_empty() {
                continue;
            }
            let has_fallback = calls.iter().enumerate().any(|(j, other)| {
                j != i
                    && other.tool == call.tool
                    && other.findings.is_empty()
                    && other.segment != call.segment
                    && segs[other.segment.max(call.segment)].after_or
            });
            if !has_fallback {
                out.extend(call.findings.iter().cloned());
            }
        }
        out
    }

    /// The source's lines with backslash continuations joined, each with the
    /// number (1-based) of the line it starts on.
    pub fn logical_lines(src: &str) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        let mut pending: Option<(usize, String)> = None;
        for (n, line) in src.lines().enumerate() {
            let (start, mut text) = pending.take().unwrap_or((n + 1, String::new()));
            if let Some(cont) = line.strip_suffix('\\') {
                text.push_str(cont);
                pending = Some((start, text));
            } else {
                text.push_str(line);
                out.push((start, text));
            }
        }
        if let Some(rest) = pending {
            out.push(rest);
        }
        out
    }

    /// Whether `line_no` (1-based) of a workflow sits in a job whose
    /// `runs-on` names only Linux runners: an `ubuntu` image or a
    /// self-hosted label list (every self-hosted runner registered for this
    /// repository reports os Linux: `gh api repos/NormB/sipnab/actions/runners`,
    /// 2026-11-20). An expression counts by every label it names: Linux only
    /// when it names an ubuntu image or self-hosted and never macos or
    /// windows; one that names no label (`${{ matrix.os }}`), or a job with
    /// no runs-on, is not known to be Linux.
    pub fn workflow_job_is_linux(src: &str, line_no: usize) -> bool {
        let lines: Vec<&str> = src.lines().collect();
        let idx = line_no.saturating_sub(1);
        if idx >= lines.len() {
            return false;
        }
        let is_header = |l: &str| {
            l.strip_prefix("  ").is_some_and(|rest| {
                rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
        };
        // A job header is a two-space key (`  build:`); the `on:` triggers
        // have the same shape but hold no runs-on, so they never count.
        let Some(start) = (0..=idx).rev().find(|&k| is_header(lines[k])) else {
            return false;
        };
        let end = (start + 1..lines.len())
            .find(|&k| {
                is_header(lines[k]) || (!lines[k].starts_with(' ') && !lines[k].trim().is_empty())
            })
            .unwrap_or(lines.len());
        if idx >= end {
            return false;
        }
        let runs_on = lines[start..end]
            .iter()
            .find_map(|l| l.strip_prefix("    runs-on:"))
            .map(str::trim);
        runs_on.is_some_and(|v| {
            !v.contains("macos")
                && !v.contains("windows")
                && (v.contains("ubuntu") || v.contains("self-hosted"))
        })
    }

    /// Every GNU-only finding of a file before any allowance: (line, the
    /// logical line's text, the finding).
    pub fn raw_findings(_path: &str, src: &str) -> Vec<(usize, String, String)> {
        let mut out = Vec::new();
        for (n, text) in logical_lines(src) {
            for finding in gnu_flags_in(&text) {
                out.push((n, text.clone(), finding));
            }
        }
        out
    }

    /// The findings the gate reports: raw findings minus the Linux-only
    /// workflow jobs and the `LINUX_ONLY` allowances.
    pub fn scan_file(path: &str, src: &str) -> Vec<(usize, String)> {
        let workflow = path.starts_with(".github/workflows/");
        raw_findings(path, src)
            .into_iter()
            .filter(|(n, text, _)| {
                let allowed = LINUX_ONLY
                    .iter()
                    .any(|a| a.path == path && a.line.is_none_or(|l| text.contains(l)));
                !allowed && !(workflow && workflow_job_is_linux(src, *n))
            })
            .map(|(n, _, finding)| (n, finding))
            .collect()
    }

    /// Whether the gate reads this tracked file: shell by extension or
    /// shebang, the git hooks, workflows and composite actions, Makefiles,
    /// and everything under scripts/ and bench/ (the gate's paths before
    /// 2026-11-20, kept whole).
    pub fn is_scanned_file(path: &str, first_line: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        let shebang_shell = first_line.strip_prefix("#!").is_some_and(|cmd| {
            cmd.split([' ', '/'])
                .any(|w| matches!(w, "sh" | "bash" | "dash" | "ksh" | "zsh"))
        });
        path.ends_with(".sh")
            || path.ends_with(".bash")
            || shebang_shell
            || path.starts_with(".githooks/")
            || path.starts_with("scripts/")
            || path.starts_with("bench/")
            || (path.starts_with(".github/workflows/")
                && (path.ends_with(".yml") || path.ends_with(".yaml")))
            || (path.starts_with(".github/actions/") && name == "action.yml")
            || name == "Makefile"
    }
}

/// The GNU-only findings of one command line, for the tests below.
fn gnu(line: &str) -> Vec<String> {
    shell_flags::gnu_flags_in(line)
}

/// Asserts `line` holds exactly `want` GNU-only findings, in order.
fn assert_gnu(line: &str, want: &[&str]) {
    let got = gnu(line);
    assert_eq!(
        got, want,
        "GNU-only findings of {line:?}: got {got:?}, expected {want:?}"
    );
}

// Failure: the parser finds the GNU-only flag.

#[test]
fn gnu_flag_after_another_flag_is_found_the_pr_848_case() {
    assert_gnu("bytes=$(stat -L -c %s -- \"$bin\")", &["stat -c"]);
}

#[test]
fn gnu_flag_inside_a_short_flag_cluster_is_found() {
    assert_gnu("stat -Lc %s f", &["stat -c"]);
}

#[test]
fn gnu_flag_with_its_argument_attached_is_found() {
    assert_gnu("stat -c%s f", &["stat -c"]);
}

#[test]
fn gnu_long_option_of_stat_is_found() {
    assert_gnu("stat --format=%s f", &["stat --format"]);
}

#[test]
fn gnu_flag_after_an_operand_is_found() {
    assert_gnu("stat f -c %s", &["stat -c"]);
}

#[test]
fn touch_date_flag_is_found() {
    assert_gnu("touch -d @0 f", &["touch -d"]);
}

#[test]
fn readlink_canonicalize_flags_are_found() {
    assert_gnu("readlink -f x", &["readlink -f"]);
    assert_gnu("readlink -e x", &["readlink -e"]);
    assert_gnu("readlink -m x", &["readlink -m"]);
}

#[test]
fn date_string_flag_is_found_after_another_flag() {
    assert_gnu("end=$(date -u -d \"$x\" +%s)", &["date -d"]);
}

#[test]
fn date_string_flag_is_found_in_a_cluster() {
    assert_gnu("date -ud x +%s", &["date -d"]);
}

#[test]
fn date_long_option_is_found() {
    assert_gnu("date --date=x", &["date --date"]);
}

#[test]
fn cp_parents_and_preserve_are_found() {
    assert_gnu("cp --parents a b", &["cp --parents"]);
    assert_gnu("cp --preserve=mode a b", &["cp --preserve"]);
}

#[test]
fn every_long_option_of_cp_is_found() {
    assert_gnu("cp --recursive a b", &["cp --recursive"]);
}

#[test]
fn cp_target_directory_flag_is_found_beside_parents() {
    assert_gnu(
        "(cd \"$ROOT\" && in_tree ! -type d -exec cp -a --parents -t \"$TREE\" {} +)",
        &["cp --parents", "cp -t"],
    );
}

#[test]
fn bare_sed_in_place_is_found() {
    assert_gnu("sed -i 's/a/b/' f", &["sed -i"]);
    assert_gnu("sed -i '' 's/a/b/' f", &["sed -i"]);
}

#[test]
fn bare_sed_in_place_at_the_end_of_a_cluster_is_found() {
    assert_gnu("sed -Ei 's/a/b/' f", &["sed -i"]);
}

#[test]
fn sed_long_option_is_found() {
    assert_gnu("sed --in-place 's/a/b/' f", &["sed --in-place"]);
}

#[test]
fn a_tool_in_the_middle_of_a_command_is_found() {
    assert_gnu(
        "find \"$T\" -name '*.rs' -exec sed -i -e x {} +",
        &["sed -i"],
    );
    assert_gnu("find . -exec stat -c %s {} \\;", &["stat -c"]);
}

#[test]
fn gnu_flag_in_a_quoted_command_substitution_is_found() {
    assert_gnu(
        "stage_elf \"$(readlink -f \"${BIN_SRC}\")\" \"$STAGED_BIN\"",
        &["readlink -f"],
    );
}

#[test]
fn gnu_flag_in_backticks_is_found() {
    assert_gnu("n=`stat -c %s f`", &["stat -c"]);
}

#[test]
fn gnu_flag_after_a_wrapper_or_a_path_is_found() {
    assert_gnu("sudo stat -c %s f", &["stat -c"]);
    assert_gnu("/usr/bin/stat -c %s f", &["stat -c"]);
    assert_gnu("LC_ALL=C timeout 5 date -d x", &["date -d"]);
}

#[test]
fn or_to_another_tool_is_not_a_bsd_fallback() {
    assert_gnu("stat -c %s f || echo 0", &["stat -c"]);
}

#[test]
fn or_to_another_listed_tool_is_not_a_bsd_fallback() {
    assert_gnu("n=$(stat -c %s f || date -u +%s)", &["stat -c"]);
}

#[test]
fn and_to_the_bsd_form_is_not_a_fallback() {
    assert_gnu("stat -c %s f && stat -f %z f", &["stat -c"]);
}

#[test]
fn gnu_flag_after_a_stderr_redirect_is_found() {
    assert_gnu("stat 2>&1 -c %s f", &["stat -c"]);
}

#[test]
fn gnu_only_short_flags_of_cp_are_found() {
    assert_gnu("cp -u a b", &["cp -u"]);
    assert_gnu("cp -d a b", &["cp -d"]);
}

// Success: a portable line is not flagged.

#[test]
fn bsd_stat_format_is_not_flagged() {
    assert_gnu("stat -f %z f", &[]);
    assert_gnu("stat -L -f %z f", &[]);
}

#[test]
fn posix_size_count_is_not_flagged() {
    assert_gnu("bytes=$(wc -c < \"$f\")", &[]);
}

#[test]
fn sed_in_place_with_an_attached_suffix_is_not_flagged() {
    assert_gnu("sed -i.bak 's/a/b/' f && rm -f f.bak", &[]);
}

#[test]
fn ordinary_sed_is_not_flagged() {
    assert_gnu("sed -n 's/x/y/p' f | sed -n 1p", &[]);
    assert_gnu("sed -E -e 's/-i//' f", &[]);
}

#[test]
fn portable_date_forms_are_not_flagged() {
    assert_gnu("date -u +%s", &[]);
    assert_gnu("date -r 0 +%Y", &[]);
    assert_gnu("date -u -v-1d +%F", &[]);
    assert_gnu("date -Iseconds", &[]);
}

#[test]
fn touch_with_a_posix_time_is_not_flagged() {
    assert_gnu("touch -t 202601010000 f", &[]);
    assert_gnu("touch -r ref f", &[]);
}

#[test]
fn portable_cp_is_not_flagged() {
    assert_gnu("cp -p a b; cp -R a b; cp -a a b", &[]);
}

#[test]
fn readlink_without_gnu_flags_is_not_flagged() {
    assert_gnu("readlink x", &[]);
    assert_gnu("readlink -n x", &[]);
}

#[test]
fn bsd_fallback_after_or_is_allowed() {
    assert_gnu(
        "bytes=$(stat -L -c %s -- \"$bin\" 2>/dev/null || stat -L -f %z -- \"$bin\")",
        &[],
    );
}

#[test]
fn bsd_form_first_and_gnu_after_or_is_allowed() {
    assert_gnu("stat -f %z f 2>/dev/null || stat -c %s f", &[]);
}

#[test]
fn a_bsd_form_in_a_subshell_before_or_is_a_fallback() {
    assert_gnu("(stat -f %z f) || stat -c %s f", &[]);
}

#[test]
fn the_release_yml_size_line_is_allowed() {
    assert_gnu(
        "size=$(stat -c%s \"$bin\" 2>/dev/null || stat -f%z \"$bin\")",
        &[],
    );
}

#[test]
fn the_install_sh_mode_line_is_allowed() {
    assert_gnu(
        "t \"mode\" \"644\" \"$(stat -c %a \"$f\" 2>/dev/null || stat -f %Lp \"$f\" 2>/dev/null)\"",
        &[],
    );
}

#[test]
fn an_explicit_gnu_coreutils_name_is_not_matched() {
    assert_gnu("gstat -c %s f; gdate -d x", &[]);
}

#[test]
fn quoted_prose_is_not_a_command() {
    assert_gnu("echo \"stat -c is GNU-only\"", &[]);
    assert_gnu("x='readlink -f y'", &[]);
}

#[test]
fn a_quoted_command_name_still_runs_the_command() {
    assert_gnu("\"stat\" -c %s f", &["stat -c"]);
    assert_gnu("'date' -d x", &["date -d"]);
}

#[test]
fn comments_are_not_commands() {
    assert_gnu("# stat -c %s f", &[]);
    assert_gnu("wc -c f # not stat -c", &[]);
}

#[test]
fn flags_after_end_of_options_are_operands() {
    assert_gnu("stat -f %z -- -c", &[]);
    assert_gnu("cp -- --parents b", &[]);
}

#[test]
fn a_tool_named_as_an_argument_takes_no_flags() {
    assert_gnu("command -v stat >/dev/null", &[]);
}

// Edge: the boundaries of the parser.

#[test]
fn an_empty_or_blank_line_has_no_findings() {
    assert_gnu("", &[]);
    assert_gnu("   \t ", &[]);
}

#[test]
fn an_unterminated_quote_still_reports_the_flag_before_it() {
    assert_gnu("stat -c \"%s f", &["stat -c"]);
}

#[test]
fn an_unterminated_substitution_still_reports_its_flag() {
    assert_gnu("x=$(stat -c %s f", &["stat -c"]);
}

#[test]
fn an_option_argument_that_looks_like_a_gnu_flag_is_not_one() {
    assert_gnu("date -r -d", &[]);
    assert_gnu("stat -f -c f", &[]);
}

#[test]
fn sed_in_place_with_a_one_letter_suffix_is_not_bare() {
    assert_gnu("sed -ie 's/a/b/' f", &[]);
}

#[test]
fn two_gnu_forms_joined_by_or_are_not_a_fallback() {
    assert_gnu("stat -c a f || stat -c b f", &["stat -c", "stat -c"]);
}

#[test]
fn a_gnu_flag_in_a_nested_substitution_is_found() {
    assert_gnu(
        "a=\"$(dirname \"$(readlink -f \"$0\")\")\"",
        &["readlink -f"],
    );
}

#[test]
fn a_command_after_a_closed_quoted_substitution_is_read_as_a_command() {
    assert_gnu("a=\"$(dirname x)\"; stat -c %s f", &["stat -c"]);
    assert_gnu("a=\"`dirname x`\"; stat -c %s f", &["stat -c"]);
}

#[test]
fn find_exec_terminator_keeps_a_later_tools_flags_from_the_earlier_tool() {
    // `-u` is GNU-only for cp but portable for date.
    assert_gnu("find . -exec cp -p {} d \\; -exec date -u \\;", &[]);
}

#[test]
fn a_tool_name_as_an_operand_does_not_end_the_commands_flags() {
    // A file named `date` is copied; cp's GNU-only -t still counts.
    assert_gnu("cp -p date -t dir", &["cp -t"]);
}

#[test]
fn find_exec_terminators_end_the_tools_arguments() {
    // Without the terminator, find's next `-exec` reads as `stat -e -x -e -c`.
    assert_gnu("find . -exec stat -f %z {} \\; -exec true \\;", &[]);
    assert_gnu("find . -exec stat -f %z {} + -exec true \\;", &[]);
    assert_gnu(
        "find . -exec cp -p {} d \\; -exec stat -c %s {} \\;",
        &["stat -c"],
    );
}

#[test]
fn two_invocations_in_one_command_are_not_a_fallback() {
    assert_gnu(
        "true || find . -exec stat -c %s {} \\; -exec stat -f %z {} \\;",
        &["stat -c"],
    );
}

#[test]
fn a_subshell_inside_a_substitution_does_not_close_it() {
    assert_gnu("x=\"$( (cd d) ; stat -c %s f )\"", &["stat -c"]);
    assert_gnu("x=\"$( (cd d) )\"; stat -c %s f", &["stat -c"]);
}

#[test]
fn a_parameter_expansion_is_one_word_even_with_a_separator_inside() {
    assert_gnu("stat ${a%;*} -c %s f", &["stat -c"]);
}

#[test]
fn multiple_tools_on_one_line_each_report() {
    assert_gnu(
        "touch -d x f; date -d y; cp --parents a b",
        &["touch -d", "date -d", "cp --parents"],
    );
}

#[test]
fn logical_lines_join_continuations_and_keep_the_first_line_number() {
    let got = shell_flags::logical_lines("a\nsed -i \\\n\t-e x \\\n\tf\nb\n");
    let want = vec![
        (1, "a".to_string()),
        (2, "sed -i \t-e x \tf".to_string()),
        (5, "b".to_string()),
    ];
    assert_eq!(
        got, want,
        "continuation lines must join into one logical line"
    );
}

#[test]
fn a_flag_on_a_continuation_line_is_found_at_the_first_line() {
    let got = shell_flags::scan_file("contrib/x.sh", "#!/bin/sh\nstat -L \\\n  -c %s f\n");
    assert_eq!(
        got,
        vec![(2, "stat -c".to_string())],
        "a flag on a continuation line belongs to the command that started above"
    );
}

/// A workflow with one job per runner kind; the line numbers in the tests
/// below are its lines (1-based).
const WORKFLOW: &str = concat!(
    "name: x\n",
    "env:\n",
    "  A: $(date -d x)\n",
    "jobs:\n",
    "  lin:\n",
    "    runs-on: ubuntu-24.04\n",
    "    steps:\n",
    "      - run: sed -i s/a/b/ f\n",
    "  mac:\n",
    "    runs-on: macos-26\n",
    "    steps:\n",
    "      - run: sed -i s/a/b/ f\n",
    "  mat:\n",
    "    runs-on: ${{ matrix.os }}\n",
    "    steps:\n",
    "      - run: sed -i s/a/b/ f\n",
    "  own:\n",
    "    runs-on: [self-hosted, jetson]\n",
    "    steps:\n",
    "      - run: sed -i s/a/b/ f\n",
    "  none:\n",
    "    steps:\n",
    "      - run: sed -i s/a/b/ f\n",
);

#[test]
fn a_workflow_job_on_ubuntu_is_linux() {
    assert!(
        shell_flags::workflow_job_is_linux(WORKFLOW, 8),
        "line 8 is in job `lin`, which runs on ubuntu-24.04"
    );
}

#[test]
fn a_workflow_job_on_a_self_hosted_runner_is_linux() {
    assert!(
        shell_flags::workflow_job_is_linux(WORKFLOW, 20),
        "line 20 is in job `own`, on [self-hosted, jetson]; every registered \
         self-hosted runner reports Linux"
    );
}

#[test]
fn a_workflow_job_on_macos_is_not_linux() {
    assert!(
        !shell_flags::workflow_job_is_linux(WORKFLOW, 12),
        "line 12 is in job `mac`, on macos-26"
    );
}

#[test]
fn a_workflow_job_on_an_expression_is_not_known_to_be_linux() {
    assert!(
        !shell_flags::workflow_job_is_linux(WORKFLOW, 16),
        "line 16 is in job `mat`, whose runs-on is an expression that names \
         no runner label"
    );
}

/// Whether a one-job workflow with this `runs-on` value counts as Linux.
fn runs_on_is_linux(value: &str) -> bool {
    let src = format!("jobs:\n  j:\n    runs-on: {value}\n    steps:\n      - run: x\n");
    shell_flags::workflow_job_is_linux(&src, 5)
}

#[test]
fn a_self_hosted_label_list_naming_macos_or_windows_is_not_linux() {
    assert!(
        !runs_on_is_linux("[self-hosted, macos]"),
        "a self-hosted macOS runner"
    );
    assert!(
        !runs_on_is_linux("[self-hosted, windows]"),
        "a self-hosted Windows runner"
    );
}

#[test]
fn an_expression_choosing_only_linux_runners_is_linux() {
    assert!(
        runs_on_is_linux("${{ matrix.big && 'ubuntu-24.04-arm' || 'ubuntu-24.04' }}"),
        "both choices are ubuntu images"
    );
    assert!(
        runs_on_is_linux(
            "${{ github.ref == 'refs/heads/main' && fromJSON('[\"self-hosted\",\"jetson\"]') || fromJSON('[\"self-hosted\",\"overflow\"]') }}"
        ),
        "both choices are self-hosted label lists"
    );
}

#[test]
fn an_expression_that_can_choose_macos_is_not_linux() {
    assert!(
        !runs_on_is_linux("${{ matrix.os == 'ubuntu-24.04' && 'ubuntu-24.04-arm' || 'macos-26' }}"),
        "one choice is a macOS image"
    );
}

#[test]
fn a_top_level_key_after_the_jobs_is_in_no_job() {
    let src = concat!(
        "jobs:\n",
        "  j:\n",
        "    runs-on: ubuntu-24.04\n",
        "x-note: $(sed -i s/a/b/ f)\n",
    );
    assert!(
        !shell_flags::workflow_job_is_linux(src, 4),
        "line 4 is a top-level key, outside job `j`"
    );
}

#[test]
fn a_comment_at_job_indent_does_not_end_the_job() {
    let src = concat!(
        "jobs:\n",
        "  j:\n",
        "    runs-on: ubuntu-24.04\n",
        "  # macos jobs: none here\n",
        "    steps:\n",
        "      - run: sed -i s/a/b/ f\n",
    );
    assert!(
        shell_flags::workflow_job_is_linux(src, 6),
        "a comment is not a job header"
    );
}

#[test]
fn a_step_input_named_runs_on_is_not_the_jobs_runner() {
    let src = concat!(
        "jobs:\n",
        "  j:\n",
        "    steps:\n",
        "      - uses: ./x\n",
        "        with:\n",
        "          runs-on: ubuntu-24.04\n",
        "      - run: sed -i s/a/b/ f\n",
    );
    assert!(
        !shell_flags::workflow_job_is_linux(src, 7),
        "only the job's own runs-on (indent 4) names its runner"
    );
}

#[test]
fn a_workflow_job_without_runs_on_is_not_linux() {
    assert!(
        !shell_flags::workflow_job_is_linux(WORKFLOW, 23),
        "line 23 is in job `none`, which states no runner"
    );
}

#[test]
fn a_workflow_line_outside_any_job_is_not_linux() {
    assert!(
        !shell_flags::workflow_job_is_linux(WORKFLOW, 3),
        "line 3 is the workflow's top-level env, in no job"
    );
}

#[test]
fn a_workflow_scan_reports_only_the_jobs_not_known_to_be_linux() {
    let got: Vec<usize> = shell_flags::scan_file(".github/workflows/x.yml", WORKFLOW)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        got,
        vec![3, 12, 16, 23],
        "the ubuntu and self-hosted jobs are Linux; the rest are not"
    );
}

#[test]
fn a_composite_action_gets_no_job_allowance() {
    let src = "runs:\n  using: composite\n  steps:\n    - run: sed -i s/a/b/ f\n";
    let got = shell_flags::scan_file(".github/actions/x/action.yml", src);
    assert_eq!(
        got,
        vec![(4, "sed -i".to_string())],
        "an action runs on whichever runner calls it, macOS included"
    );
}

#[test]
fn only_a_workflow_file_gets_the_job_allowance() {
    // A script that writes a workflow: its text has a job shape, but it runs
    // wherever the script runs.
    let src = concat!(
        "cat >ci.yml <<'YAML'\n",
        "  j:\n",
        "    runs-on: ubuntu-24.04\n",
        "    sed -i s/a/b/ f\n",
        "YAML\n",
    );
    assert_eq!(
        shell_flags::scan_file("contrib/gen-ci.sh", src),
        vec![(4, "sed -i".to_string())],
        "the job allowance is for .github/workflows/ only"
    );
}

#[test]
fn a_linux_only_file_is_not_reported_and_others_are() {
    let src = "x=\"$(readlink -f y)\"\n";
    assert!(
        shell_flags::scan_file("packaging/rpm/build-rpm.sh", src).is_empty(),
        "build-rpm.sh is listed as Linux-only"
    );
    assert_eq!(
        shell_flags::scan_file("packaging/deb/build-deb.sh", src),
        vec![(1, "readlink -f".to_string())],
        "the allowance names one file, not its directory"
    );
}

#[test]
fn a_linux_only_line_allowance_covers_only_its_line() {
    let src = "end=$(date -u -d \"$not_after\" +%s 2>/dev/null || printf '')\nn=$(date -d x)\n";
    assert_eq!(
        shell_flags::scan_file("scripts/check-cert-expiry.sh", src),
        vec![(2, "date -d".to_string())],
        "the cert-expiry allowance is for its one parse line"
    );
}

#[test]
fn every_finding_kind_names_its_portable_fix() {
    for (finding, want) in [
        (
            "stat -c",
            "BSD stat spells it -f FORMAT; `wc -c < file` is portable",
        ),
        (
            "sed -i",
            "GNU and BSD read the word after a bare -i differently; use -i.bak and remove the .bak",
        ),
        (
            "sed --in-place",
            "long options are not portable to BSD sed; use the short form",
        ),
        (
            "cp --parents",
            "long options are not portable to BSD cp; use the short form",
        ),
        ("cp -t", "BSD cp has no -t; name the target last"),
        ("awk -x", "unknown tool"),
    ] {
        let got = shell_flags::fix_for(finding);
        assert_eq!(got, want, "fix_for({finding:?})");
    }
}

#[test]
fn a_gnu_form_before_the_linux_guard_is_unguarded() {
    let src = "a\nsed -i x f\n[ \"$(uname -s)\" = Linux ] || exit 0\nsed -i y f\n";
    let got = shell_flags::unguarded_lines(src, "uname -s", &[2, 4]);
    assert_eq!(got, Ok(vec![2]), "line 2 runs before the guard on line 3");
}

#[test]
fn a_missing_guard_is_an_error() {
    let got = shell_flags::unguarded_lines("sed -i x f\n", "uname -s", &[1]);
    assert!(got.is_err(), "a guard that is gone must fail, got {got:?}");
}

#[test]
fn a_gnu_form_on_the_guard_line_is_unguarded() {
    let got = shell_flags::unguarded_lines("uname -s; sed -i x f\n", "uname -s", &[1]);
    assert_eq!(
        got,
        Ok(vec![1]),
        "the guard line itself is not protected by the guard"
    );
}

#[test]
fn an_allowance_reason_must_be_a_sentence() {
    assert!(!shell_flags::reason_is_stated(""), "an empty reason");
    assert!(
        !shell_flags::reason_is_stated("linux"),
        "one word is not a reason"
    );
    assert!(
        shell_flags::reason_is_stated("runs only in the ubuntu-24.04 job of cert-expiry.yml"),
        "a sentence naming where it runs"
    );
}

#[test]
fn shell_files_are_selected_by_extension_shebang_and_place() {
    for (path, first, want) in [
        ("contrib/a.sh", "", true),
        ("harness/x/run", "#!/usr/bin/env bash", true),
        ("harness/x/run2", "#!/bin/sh -eu", true),
        (".githooks/pre-push", "", true),
        (".github/workflows/ci.yml", "", true),
        (".github/actions/x/action.yml", "", true),
        ("demos/Makefile", "", true),
        // Not a Python or shell name: a path under scripts/ with one of
        // those extensions reads as a citation to
        // mcp_tool_descriptions_test's every_cited_script_exists.
        ("scripts/notes.txt", "", true),
        ("bench/plot.py", "#!/usr/bin/env python3", true),
        ("contrib/x.bash", "", true),
        (".github/workflows/x.yaml", "", true),
        (".github/actions/x/README.yml", "", false),
        (".github/workflows/README.md", "", false),
        ("tools/run.py", "#!/usr/bin/env python3", false),
        (".github/ISSUE_TEMPLATE/bug.yml", "", false),
        ("docs/install.md", "", false),
        ("Dockerfile", "", false),
        ("src/main.rs", "", false),
    ] {
        assert_eq!(
            shell_flags::is_scanned_file(path, first),
            want,
            "is_scanned_file({path:?}, {first:?})"
        );
    }
}
