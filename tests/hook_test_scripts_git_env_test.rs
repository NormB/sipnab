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

/// What ends a hook run that is not going to finish.
///
/// There is no limit on the run as a whole. Each harness is about 45 seconds
/// of processor time in short processes, one after another
/// (scripts/test-pre-commit.sh 46.0 s, scripts/test-pre-push.sh 44.4 s,
/// measured alone with `cargo` stubbed on 2026-11-13), so the time a run takes
/// is that work divided by the share of one core the host gives it: 75 s and
/// 55 s alone at a load average near 30 on 14 cores, and more than 300 s in
/// the suite at a load average of 38, where a limit of 300 s on the whole run
/// ended both (2026-11-12). What a run that will not finish looks like does
/// not depend on the load: its log stops growing, or never stops.
struct HookLimits {
    /// The longest the script's log may stay the same size. The harnesses
    /// print a line per check; the longest step between two lines was 5.1 s
    /// in the measurement above.
    silence: std::time::Duration,
    /// The most the script may write. The harnesses write 75 and 623 lines.
    log_bytes: u64,
}

/// The limits for a whole harness.
const HOOK_LIMITS: HookLimits = HookLimits {
    silence: std::time::Duration::from_secs(120),
    log_bytes: 4 * 1024 * 1024,
};

/// Why a hook run must be ended, when it must: its log has not grown for
/// longer than the limit, or has grown past its limit.
fn overdue(limits: &HookLimits, silent_for: std::time::Duration, log_bytes: u64) -> Option<String> {
    if log_bytes > limits.log_bytes {
        return Some(format!(
            "the hook wrote {log_bytes} bytes to its log, more than the {} allowed",
            limits.log_bytes
        ));
    }
    if silent_for > limits.silence {
        return Some(format!(
            "the hook wrote no output for {silent_for:?}, longer than the {:?} allowed",
            limits.silence
        ));
    }
    None
}

/// `git commit` in `worktree`, in a process group of its own, ended (the whole
/// group: the hook and every script under it) and reported as a failure when
/// [`overdue`] says so.
fn commit_with_deadline(worktree: &Path, log: &Path, limits: &HookLimits) -> Result<(), TestError> {
    use std::os::unix::process::CommandExt;

    let mut child = scrubbed_git(worktree)
        .args(["commit", "-q", "-m", "worktree-commit"])
        .process_group(0)
        .spawn()?;
    let started = std::time::Instant::now();
    // The size of the log when it last changed, and when that was.
    let mut seen = 0;
    let mut changed = started;
    loop {
        if let Some(status) = child.try_wait()? {
            assert!(
                status.success(),
                "the worktree commit failed ({status}); the script log ends:\n{}",
                tail(&std::fs::read_to_string(log).unwrap_or_default())
            );
            return Ok(());
        }
        let size = std::fs::metadata(log).map_or(0, |meta| meta.len());
        if size != seen {
            seen = size;
            changed = std::time::Instant::now();
        }
        if let Some(why) = overdue(limits, changed.elapsed(), size) {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-TERM", "--", &group]).status();
            let _ = child.wait();
            return Err(format!(
                "{why}; its process group was ended after {:?}. The script log ends:\n{}",
                started.elapsed(),
                tail(&std::fs::read_to_string(log).unwrap_or_default())
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// A scratch repository with a linked worktree whose pre-commit hook is the
/// text `hook` returns for the scratch directory and the hook's log file.
struct Scratch {
    tmp: tempfile::TempDir,
    parent: PathBuf,
    worktree: PathBuf,
    log: PathBuf,
}

fn scratch_with_hook(
    hook: impl FnOnce(&Path, &Path) -> Result<String, TestError>,
) -> Result<Scratch, TestError> {
    let tmp = tempfile::tempdir()?;
    let parent = tmp.path().join("parent");
    let worktree = tmp.path().join("wt");
    let hooks = tmp.path().join("hooks");
    let log = tmp.path().join("script.log");
    std::fs::create_dir_all(&parent)?;
    std::fs::create_dir_all(&hooks)?;

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
    let text = hook(tmp.path(), &log)?;
    executable::write_executable(&hooks.join("pre-commit"), &text)?;
    std::fs::write(worktree.join("change"), "x\n")?;
    git(&worktree, &["add", "change"])?;
    Ok(Scratch {
        tmp,
        parent,
        worktree,
        log,
    })
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
    let scratch = scratch_with_hook(|tmp, log| {
        let stubs = tmp.join("stubs");
        std::fs::create_dir_all(&stubs)?;
        executable::write_executable(&stubs.join("cargo"), "#!/bin/sh\nexit 0\n")?;
        // `rustfmt` too: test-pre-push.sh refuses to start without the dated
        // nightly rustfmt the format gate pins, and the CI jobs that run this
        // suite (Coverage, macOS) do not install it. Its scenarios' verdicts
        // are not the question here, only what the script's git calls touch.
        executable::write_executable(&stubs.join("rustfmt"), "#!/bin/sh\nexit 0\n")?;
        // The hook refuses to run inside itself. A script whose fixture
        // commits land in THIS repository fires this hook again, and that
        // recursion is the defect under test: on 2026-10-28 it nested
        // test-pre-push.sh 285 deep and held the host's build lock for half an
        // hour. With the guard a regression shows up as the config and history
        // checks below failing.
        Ok(format!(
            "#!/bin/sh\n[ -n \"$SIPNAB_SCRATCH_HOOK_ACTIVE\" ] && exit 0\n\
             export SIPNAB_SCRATCH_HOOK_ACTIVE=1\n\
             PATH='{}':\"$PATH\" sh '{}' > '{}' 2>&1\nexit 0\n",
            stubs.display(),
            script.display(),
            log.display()
        ))
    })?;

    let config = scratch.parent.join(".git").join("config");
    let config_before = std::fs::read(&config)?;

    commit_with_deadline(&scratch.worktree, &scratch.log, &HOOK_LIMITS)?;

    let config_after = std::fs::read(&config)?;
    let subjects = git(&scratch.parent, &["log", "--all", "--format=%s"])?
        .lines()
        .map(str::to_owned)
        .collect();
    let log = std::fs::read_to_string(&scratch.log).unwrap_or_default();
    Ok(HookRun {
        config_before,
        config_after,
        subjects,
        log,
        _tmp: scratch.tmp,
    })
}

/// A hook, for the tests of the limits, whose body is `body` with its output
/// in the hook's log.
fn hook_running(body: &str) -> Result<Scratch, TestError> {
    scratch_with_hook(|tmp, log| {
        Ok(format!(
            "#!/bin/sh\necho $$ > '{}'\n{{\n{body}\n}} > '{}' 2>&1\nexit 0\n",
            tmp.join("hook.pid").display(),
            log.display()
        ))
    })
}

/// Whether the process the hook ran as is gone, waited for with a bound.
fn hook_process_is_gone(scratch: &Scratch) -> Result<bool, TestError> {
    let pid = std::fs::read_to_string(scratch.tmp.path().join("hook.pid"))?;
    let started = std::time::Instant::now();
    while started.elapsed() < std::time::Duration::from_secs(30) {
        if !Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()?
            .success()
        {
            return Ok(true);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(false)
}

/// The limit is on silence, not on the run: a hook that keeps writing runs for
/// longer than the silence limit and is left to finish. Under a limit on the
/// whole run this is the failure of 2026-11-12, when a loaded host made both
/// harnesses slower than 300 s while they were still printing a line every few
/// seconds.
#[test]
fn a_hook_that_keeps_writing_is_not_ended_however_long_it_runs() -> Result<(), TestError> {
    let limits = HookLimits {
        silence: std::time::Duration::from_secs(4),
        log_bytes: 1024 * 1024,
    };
    // 40 lines, each after a fifth of a second: at least 8 s in all. The
    // `sleep` here is the hook's work, not a wait of this test.
    let scratch =
        hook_running("i=0\nwhile [ $i -lt 40 ]; do echo \"step $i\"; sleep 0.2; i=$((i+1)); done")?;
    let started = std::time::Instant::now();
    let outcome = commit_with_deadline(&scratch.worktree, &scratch.log, &limits);
    let took = started.elapsed();
    assert!(
        outcome.is_ok(),
        "a hook that printed a line every 0.2 s was ended: {outcome:?}"
    );
    assert!(
        took > limits.silence,
        "the hook ran {took:?}, not longer than the silence limit {:?}, so this proves nothing",
        limits.silence
    );
    let log = std::fs::read_to_string(&scratch.log)?;
    assert!(
        log.contains("step 39"),
        "the hook did not run to its last line; its log ends:\n{}",
        tail(&log)
    );
    Ok(())
}

/// A hook that stops writing and does not end is ended, with every process
/// under it, and the failure says how long it was silent and shows its log.
#[test]
fn a_hook_that_goes_silent_is_ended() -> Result<(), TestError> {
    let limits = HookLimits {
        silence: std::time::Duration::from_secs(2),
        log_bytes: 1024 * 1024,
    };
    // Bounded on purpose: a watch that no longer ends a silent hook fails
    // this test after a minute and a half.
    let scratch = hook_running("echo last-words\nsleep 90\necho woke-up")?;
    let outcome = commit_with_deadline(&scratch.worktree, &scratch.log, &limits);
    let message = match outcome {
        Ok(()) => return Err("a hook that slept 90 s was not ended".into()),
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("wrote no output for") && message.contains("last-words"),
        "the failure does not say the hook was silent, or does not show its log: {message}"
    );
    assert!(
        !std::fs::read_to_string(&scratch.log)?.contains("woke-up"),
        "the hook ran to its end; it was not ended"
    );
    assert!(
        hook_process_is_gone(&scratch)?,
        "the hook's process outlived the end of its process group"
    );
    Ok(())
}

/// A hook that writes more than the size limit is ended by the size of its
/// log, whatever the silence limit is.
///
/// The hook here is bounded on purpose (4 MB of output, then half a minute
/// more), so a watch that has stopped reading the size fails this test in
/// half a minute and does not fill the disk.
#[test]
fn a_hook_that_writes_past_the_size_limit_is_ended() -> Result<(), TestError> {
    let limits = HookLimits {
        silence: std::time::Duration::from_secs(3600),
        log_bytes: 64 * 1024,
    };
    let scratch = hook_running(
        "i=0\nwhile [ $i -lt 100000 ]; do echo 0123456789012345678901234567890123456789; \
         i=$((i+1)); done\nsleep 30\necho wrote-it-all",
    )?;
    let outcome = commit_with_deadline(&scratch.worktree, &scratch.log, &limits);
    let message = match outcome {
        Ok(()) => {
            return Err("a hook that wrote 4 MB against a limit of 64 kB was not ended".into());
        }
        Err(e) => e.to_string(),
    };
    assert!(
        message.contains("bytes to its log, more than the 65536 allowed"),
        "the failure does not name the size limit: {message}"
    );
    assert!(
        !std::fs::read_to_string(&scratch.log)?.contains("wrote-it-all"),
        "the hook ran to its end; it was not ended"
    );
    assert!(
        hook_process_is_gone(&scratch)?,
        "the hook's process outlived the end of its process group"
    );
    Ok(())
}

/// [`overdue`] over a table: runs within both limits, runs past one, and the
/// values at and beside each limit, for the limits of a whole harness and for
/// small ones.
#[test]
fn overdue_decides_each_case_of_the_table() {
    const MIB4: u64 = 4 * 1024 * 1024;
    let small = HookLimits {
        silence: std::time::Duration::from_millis(1500),
        log_bytes: 10,
    };
    // (limits, silence in ms, log bytes, the word the reason must hold or None)
    let cases: &[(&HookLimits, u64, u64, Option<&str>)] = &[
        // Within both limits.
        (&HOOK_LIMITS, 0, 0, None),
        (&HOOK_LIMITS, 200, 0, None),
        (&HOOK_LIMITS, 5_100, 6_000, None),
        (&HOOK_LIMITS, 30_000, 60_000, None),
        (&HOOK_LIMITS, 60_000, 1, None),
        (&HOOK_LIMITS, 100_000, 1024 * 1024, None),
        (&HOOK_LIMITS, 1, MIB4 / 2, None),
        (&HOOK_LIMITS, 119_000, MIB4 - 4096, None),
        (&small, 0, 0, None),
        (&small, 1, 1, None),
        (&small, 700, 5, None),
        (&small, 1_400, 9, None),
        // Past a limit.
        (&HOOK_LIMITS, 121_000, 0, Some("no output")),
        (&HOOK_LIMITS, 300_000, 6_000, Some("no output")),
        (&HOOK_LIMITS, 3_600_000, 1, Some("no output")),
        (&HOOK_LIMITS, 0, MIB4 + 4096, Some("bytes")),
        (&HOOK_LIMITS, 200, 2 * MIB4, Some("bytes")),
        (&HOOK_LIMITS, 0, u64::MAX, Some("bytes")),
        (&HOOK_LIMITS, 600_000, 2 * MIB4, Some("bytes")),
        (&small, 2_000, 0, Some("no output")),
        (&small, 60_000, 10, Some("no output")),
        (&small, 0, 11, Some("bytes")),
        (&small, 1_000, 4_000_000, Some("bytes")),
        (&small, 9_000, 9_000, Some("bytes")),
        // At and beside each limit.
        (&HOOK_LIMITS, 120_000, 0, None),
        (&HOOK_LIMITS, 119_999, 0, None),
        (&HOOK_LIMITS, 120_001, 0, Some("no output")),
        (&HOOK_LIMITS, 0, MIB4, None),
        (&HOOK_LIMITS, 0, MIB4 - 1, None),
        (&HOOK_LIMITS, 0, MIB4 + 1, Some("bytes")),
        (&HOOK_LIMITS, 120_000, MIB4, None),
        (&HOOK_LIMITS, 120_001, MIB4 + 1, Some("bytes")),
        (&small, 1_500, 10, None),
        (&small, 1_501, 10, Some("no output")),
        (&small, 1_500, 11, Some("bytes")),
        (&small, 1_499, 9, None),
    ];
    for (limits, silent_ms, bytes, want) in cases {
        let got = overdue(limits, std::time::Duration::from_millis(*silent_ms), *bytes);
        match want {
            None => assert_eq!(
                got, None,
                "{silent_ms} ms of silence and {bytes} bytes are within {:?} and {} bytes",
                limits.silence, limits.log_bytes
            ),
            Some(word) => assert!(
                got.as_deref().is_some_and(|why| why.contains(word)),
                "{silent_ms} ms of silence and {bytes} bytes against {:?} and {} bytes must \
                 give a reason holding {word:?}, got {got:?}",
                limits.silence,
                limits.log_bytes
            ),
        }
    }
}

/// [`overdue`], the one rule both limits come from.
#[test]
fn overdue_names_the_limit_that_was_passed() {
    let secs = std::time::Duration::from_secs;
    let limits = HookLimits {
        silence: secs(120),
        log_bytes: 1000,
    };
    for (silent, bytes) in [(0, 0), (119, 999), (120, 1000), (0, 1000), (120, 0)] {
        assert_eq!(
            overdue(&limits, secs(silent), bytes),
            None,
            "{silent} s of silence and {bytes} bytes are within the limits"
        );
    }
    let silent = overdue(&limits, secs(121), 0);
    assert!(
        silent.as_deref().is_some_and(
            |why| why.contains("wrote no output for 121s") && why.contains("120s allowed")
        ),
        "121 s of silence must be past a limit of 120 s: {silent:?}"
    );
    let large = overdue(&limits, secs(0), 1001);
    assert!(
        large
            .as_deref()
            .is_some_and(|why| why.contains("wrote 1001 bytes")
                && why.contains("more than the 1000 allowed")),
        "1001 bytes must be past a limit of 1000: {large:?}"
    );
    let both = overdue(&limits, secs(500), 5000);
    assert!(
        both.as_deref()
            .is_some_and(|why| why.contains("wrote 5000 bytes")),
        "past both limits the size is named, the one that cannot be load: {both:?}"
    );
    assert_eq!(
        overdue(&HOOK_LIMITS, secs(60), 100_000),
        None,
        "a minute of silence and 100 kB are within the limits of a whole harness"
    );
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
