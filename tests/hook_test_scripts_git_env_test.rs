// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The hook test scripts leave the repository that runs them alone.
//!
//! `scripts/test-pre-commit.sh` and `scripts/test-pre-push.sh` build throwaway
//! repositories with `cd <tmp> && git init -q . && git config user.name ...`.
//! Git hands a hook the repository it is running for: in a linked worktree it
//! exports an absolute `GIT_DIR` (`<repo>/.git/worktrees/<name>`) and
//! `GIT_INDEX_FILE`, and `git --git-dir=... commit` exports them anywhere.
//! Inherited, those variables send every one of the scripts' `git` calls to
//! THAT repository: `git init .` re-initializes it instead of creating
//! `<tmp>/.git`, `git config` writes its shared `.git/config`, and
//! `git commit` commits the fixture into it. vcon-server's copy of this
//! pattern did exactly that to its own `.git/config` on 2026-10-28.
//!
//! No sipnab hook runs these scripts (CI does), so this is the case of a
//! developer or an agent running one from a shell that carries `GIT_DIR`, or
//! from a hook of their own. The test reproduces it the way it happens: each
//! script runs from inside a real pre-commit hook, in a linked worktree of a
//! scratch repository, and that scratch repository's config and history must
//! come out untouched. Nothing here touches this checkout's own `.git`.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

#[path = "support/executable.rs"]
mod executable;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A `git` for the scratch repository itself, with every `GIT_*` variable
/// this process inherited removed: this test may itself be running under a
/// hook (the pre-commit hook runs the suite), and its own setup must not
/// reach the checkout that hook is for.
fn scrubbed_git(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(key);
        }
    }
    cmd
}

fn git(dir: &Path, args: &[&str]) -> Result<String, TestError> {
    let out = scrubbed_git(dir).args(args).output()?;
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// How long one script may run inside the hook. test-pre-commit.sh takes
/// about a minute; a hang becomes a failure instead of an entry that holds
/// the host's build lock.
const HOOK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// `git commit` in `worktree`, in a process group of its own, ended (the whole
/// group: the hook and every script under it) and reported as a failure if it
/// outlives [`HOOK_DEADLINE`].
fn commit_with_deadline(worktree: &Path, log: &Path) -> Result<(), TestError> {
    use std::os::unix::process::CommandExt;

    let mut child = scrubbed_git(worktree)
        .args(["commit", "-q", "-m", "worktree-commit"])
        .process_group(0)
        .spawn()?;
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(
                status.success(),
                "the worktree commit failed ({status}); the script log ends:\n{}",
                tail(&std::fs::read_to_string(log).unwrap_or_default())
            );
            return Ok(());
        }
        if started.elapsed() > HOOK_DEADLINE {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-TERM", "--", &group]).status();
            let _ = child.wait();
            return Err(format!(
                "the hook did not finish within {HOOK_DEADLINE:?}; its process group was \
                 ended. The script log ends:\n{}",
                tail(&std::fs::read_to_string(log).unwrap_or_default())
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// What one run of a script from inside a hook did to the scratch repository.
struct HookRun {
    config_before: Vec<u8>,
    config_after: Vec<u8>,
    subjects: Vec<String>,
    log: String,
    _tmp: tempfile::TempDir,
}

/// Run `script` from inside a real pre-commit hook of a linked worktree of a
/// scratch repository.
///
/// `cargo` and `rustfmt` are stubbed to succeed at once: the question is
/// what the scripts' own `git` calls touch, not whether their scenarios pass.
/// The `cargo` stub keeps test-pre-push.sh from building its fixture crates
/// for real, and the `rustfmt` stub lets it start on a machine without the
/// format gate's pinned nightly.
fn run_from_inside_a_hook(script: &Path) -> Result<HookRun, TestError> {
    let tmp = tempfile::tempdir()?;
    let parent = tmp.path().join("parent");
    let worktree = tmp.path().join("wt");
    let hooks = tmp.path().join("hooks");
    let stubs = tmp.path().join("stubs");
    let log = tmp.path().join("script.log");
    std::fs::create_dir_all(&parent)?;
    std::fs::create_dir_all(&hooks)?;
    std::fs::create_dir_all(&stubs)?;

    git(&parent, &["init", "-q", "-b", "main"])?;
    git(&parent, &["config", "user.email", "t@example.invalid"])?;
    git(&parent, &["config", "user.name", "scratch"])?;
    git(&parent, &["config", "commit.gpgsign", "false"])?;
    git(
        &parent,
        &["commit", "-q", "--allow-empty", "-m", "parent-base"],
    )?;
    git(
        &parent,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "side",
            &worktree.to_string_lossy(),
        ],
    )?;
    git(
        &parent,
        &["config", "core.hooksPath", &hooks.to_string_lossy()],
    )?;

    executable::write_executable(&stubs.join("cargo"), "#!/bin/sh\nexit 0\n")?;
    // `rustfmt` too: test-pre-push.sh refuses to start without the dated
    // nightly rustfmt the format gate pins, and the CI jobs that run this
    // suite (Coverage, macOS) do not install it. Its scenarios' verdicts are
    // not the question here, only what the script's git calls touch.
    executable::write_executable(&stubs.join("rustfmt"), "#!/bin/sh\nexit 0\n")?;
    // The hook refuses to run inside itself. A script whose fixture commits
    // land in THIS repository fires this hook again, and that recursion is the
    // defect under test: on 2026-10-28 it nested test-pre-push.sh 285 deep
    // and held the host's build lock for half an hour. With the guard a
    // regression shows up as the config and history checks below failing.
    executable::write_executable(
        &hooks.join("pre-commit"),
        &format!(
            "#!/bin/sh\n[ -n \"$SIPNAB_SCRATCH_HOOK_ACTIVE\" ] && exit 0\n\
             export SIPNAB_SCRATCH_HOOK_ACTIVE=1\n\
             PATH='{}':\"$PATH\" sh '{}' > '{}' 2>&1\nexit 0\n",
            stubs.display(),
            script.display(),
            log.display()
        ),
    )?;

    let config = parent.join(".git").join("config");
    let config_before = std::fs::read(&config)?;

    std::fs::write(worktree.join("change"), "x\n")?;
    git(&worktree, &["add", "change"])?;
    commit_with_deadline(&worktree, &log)?;

    let config_after = std::fs::read(&config)?;
    let subjects = git(&parent, &["log", "--all", "--format=%s"])?
        .lines()
        .map(str::to_owned)
        .collect();
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    Ok(HookRun {
        config_before,
        config_after,
        subjects,
        log,
        _tmp: tmp,
    })
}

/// The last lines of a script's log, for a failure message.
fn tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// Assert the scratch repository came out of `run` exactly as it went in,
/// apart from the hook's own commit.
fn assert_untouched(script: &str, summary: &str, run: &HookRun) {
    // Anti-vacuity: the script ran to its summary line, so its git calls
    // were all made. A hook that never started it would leave the config
    // unchanged too.
    assert!(
        run.log.contains(summary),
        "{script} did not run to its summary line ({summary:?}) inside the hook, \
         so this proves nothing. Its log ended:\n{}",
        tail(&run.log)
    );
    assert!(
        run.config_before == run.config_after,
        "{script}, run from inside a hook, rewrote the .git/config of the repository \
         the hook ran for.\nbefore:\n{}\nafter:\n{}",
        String::from_utf8_lossy(&run.config_before),
        String::from_utf8_lossy(&run.config_after)
    );
    let mut subjects = run.subjects.clone();
    subjects.sort();
    assert_eq!(
        subjects,
        ["parent-base", "worktree-commit"],
        "{script}, run from inside a hook, committed into the repository the hook ran for"
    );
}

/// `scripts/test-pre-commit.sh` run from inside a hook leaves that hook's
/// repository untouched.
#[test]
fn test_pre_commit_sh_leaves_the_hooks_repository_alone() -> Result<(), TestError> {
    let script = "scripts/test-pre-commit.sh";
    let run = run_from_inside_a_hook(&repo().join(script))?;
    assert_untouched(script, " passed, ", &run);
    Ok(())
}

/// `scripts/test-pre-push.sh` run from inside a hook leaves that hook's
/// repository untouched.
///
/// Linux only: the script runs nowhere else. CI's "Git hook scenarios" job
/// runs it on ubuntu-24.04-arm, and on macOS it stops without its summary line
/// after the reduced-combo scenarios (seen on the PR #659 macOS job; tracked
/// as TEST-PRE-PUSH-SH-STOPS-ON-DARWIN). The git sandbox it shares with
/// test-pre-commit.sh is still exercised on macOS by the test above.
#[cfg(target_os = "linux")]
#[test]
fn test_pre_push_sh_leaves_the_hooks_repository_alone() -> Result<(), TestError> {
    let script = "scripts/test-pre-push.sh";
    let run = run_from_inside_a_hook(&repo().join(script))?;
    assert_untouched(script, "--- test-pre-push summary:", &run);
    Ok(())
}

/// Negative control: the harness sees the defect. A script doing what the two
/// scripts did, `cd <tmp> && git init -q . && git config user.name ...`, run
/// the same way, rewrites the scratch repository's config. Without this the
/// two tests above could pass because the hook never exported `GIT_DIR`.
#[test]
fn the_harness_sees_a_script_that_writes_the_hooks_config() -> Result<(), TestError> {
    let scripts = tempfile::tempdir()?;
    let bad = scripts.path().join("bad.sh");
    std::fs::write(
        &bad,
        "#!/bin/sh\nd=$(mktemp -d)\n( cd \"$d\" && git init -q . && git config user.name leaked )\n\
         rm -rf \"$d\"\necho ' passed, '\n",
    )?;
    let run = run_from_inside_a_hook(&bad)?;
    assert!(
        run.log.contains(" passed, "),
        "the probe script did not run inside the hook:\n{}",
        tail(&run.log)
    );
    assert!(
        run.config_before != run.config_after
            && String::from_utf8_lossy(&run.config_after).contains("leaked"),
        "a script that runs `git config` in a temp dir under the hook's GIT_DIR left \
         the scratch config unchanged, so the harness cannot see the defect:\n{}",
        String::from_utf8_lossy(&run.config_after)
    );
    Ok(())
}

/// Run `body` in `sh` after sourcing `scripts/lib-git-sandbox.sh`, with `envs`
/// set, and return (exit code, combined output).
fn with_lib(
    dir: &Path,
    envs: &[(&str, &Path)],
    body: &str,
) -> Result<(Option<i32>, String), TestError> {
    let lib = repo().join("scripts/lib-git-sandbox.sh");
    let mut sh = Command::new("sh");
    sh.current_dir(dir);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            sh.env_remove(key);
        }
    }
    let out = sh
        .envs(envs.iter().copied())
        .arg("-c")
        .arg(format!(". '{}'\n{body}", lib.display()))
        .output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code(), text))
}

/// Edge: a sandbox whose git directory resolves outside it is refused before
/// anything is written. The sandbox here is a plain subdirectory of another
/// repository, so `git rev-parse` finds that repository, exactly what an
/// inherited `GIT_DIR` would make it find.
#[test]
fn a_sandbox_that_resolves_another_repository_is_refused() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let outer = tmp.path().join("outer");
    let sandbox = outer.join("sandbox");
    std::fs::create_dir_all(&sandbox)?;
    git(&outer, &["init", "-q"])?;
    let (code, text) = with_lib(
        tmp.path(),
        &[],
        &format!("require_own_git_dir '{}'", sandbox.display()),
    )?;
    assert_eq!(
        code,
        Some(1),
        "a sandbox inside another repository's work tree was accepted:\n{text}"
    );
    assert!(
        text.contains("REFUSED"),
        "the refusal must say what it refused:\n{text}"
    );

    // And the same directory with a repository of its own is accepted.
    git(&sandbox, &["init", "-q"])?;
    let (code, text) = with_lib(
        tmp.path(),
        &[],
        &format!("require_own_git_dir '{}'", sandbox.display()),
    )?;
    assert_eq!(
        code,
        Some(0),
        "a sandbox with its own .git was refused:\n{text}"
    );
    Ok(())
}

/// `clear_git_env` leaves no `GIT_*` variable exported.
#[test]
fn clear_git_env_unsets_every_git_variable() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let p = tmp.path();
    let (code, text) = with_lib(
        p,
        &[
            ("GIT_DIR", p),
            ("GIT_INDEX_FILE", p),
            ("GIT_WORK_TREE", p),
            ("GIT_COMMON_DIR", p),
        ],
        "clear_git_env\nenv | grep '^GIT_' || echo NONE",
    )?;
    assert_eq!(code, Some(0), "the probe failed:\n{text}");
    assert_eq!(
        text.trim(),
        "NONE",
        "clear_git_env left GIT_* variables exported"
    );
    Ok(())
}
