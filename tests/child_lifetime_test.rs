// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A sipnab a test starts ends with that test, also when the test process is
//! killed and no `Drop` runs (TEST-CHILD-ORPHAN).
//!
//! The helpers that start a serving sipnab (`ApiServer`, the HTTP MCP
//! server, the fleet `Center`) stopped it in `Drop` only. A test process
//! killed with SIGKILL, by the kernel's OOM killer or by a harness that
//! signals the test's pid and not its process group runs no `Drop`, and its
//! servers kept running with init as their parent.
//!
//! Every process the tests start from the sipnab binary is now spawned
//! through `tied_to_test` (`tests/support/child_lifetime.rs`), which on
//! Linux sets `PR_SET_PDEATHSIG` to SIGKILL: the kernel kills the child when
//! the thread that started it ends, however it ends. Other systems have no
//! such setting, and there the helpers' `Drop` is still the only stop.
//!
//! The orphan tests run a *child role*: this binary again, filtered to one
//! `#[ignore]`d test, which starts a server, writes the server's pid to a
//! file, and waits. The parent test SIGKILLs that process (its pid only) and
//! requires the server to be gone within a bounded wait.
#![cfg(all(target_os = "linux", feature = "api"))]

#[path = "support/server.rs"]
mod server;

#[cfg(feature = "mcp-http")]
#[path = "support/mcp.rs"]
mod mcp;

#[path = "support/fleet_center.rs"]
mod fleet_center;

include!("support/child_lifetime.rs");

#[path = "support/root_run.rs"]
mod root_run;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

type TestError = Box<dyn std::error::Error>;

/// Names the server a child role starts: `api`, `mcp` or `center`.
const ROLE_KIND: &str = "SIPNAB_CHILD_LIFETIME_KIND";

/// Where a child role writes the server's pid.
const ROLE_PIDFILE: &str = "SIPNAB_CHILD_LIFETIME_PIDFILE";

/// How long a server may take to end after its test process is killed. The
/// kernel sends the signal as the process exits, so it is gone in
/// milliseconds; the bound is for a loaded host.
const GONE_WITHIN: Duration = Duration::from_secs(10);

/// Whether process `pid` has ended: no `/proc` entry, or a zombie waiting to
/// be reaped by its new parent.
fn ended(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_none_or(|state| state == "Z" || state == "X"),
    }
}

/// Wait up to `within` for `pid` to end.
fn ends_within(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while !ended(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

/// Stop a sipnab this test caused to be started and that outlived its
/// test process, so a failing run leaves nothing behind. Only a process
/// whose command line is the sipnab binary is signaled.
fn stop_leftover(pid: u32) {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let ours = cmdline
        .split(|b| *b == 0)
        .next()
        .is_some_and(|argv0| argv0 == env!("CARGO_BIN_EXE_sipnab").as_bytes());
    if ours && let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill(2) on a pid whose command line was just read as this
        // build's sipnab binary.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// Run the child role `role` for `kind`, wait for it to report the pid of
/// the process it started, SIGKILL the role process, and return that pid.
fn kill_a_test_holding(role: &str, kind: &str) -> Result<u32, TestError> {
    let dir = tempfile::tempdir()?;
    kill_a_test_holding_in(role, kind, dir.path())
}

/// [`kill_a_test_holding`], with the pid file `server.pid` in `dir`, for a
/// caller that reads what else the held process writes there.
fn kill_a_test_holding_in(role: &str, kind: &str, dir: &Path) -> Result<u32, TestError> {
    let pidfile = dir.join("server.pid");
    let role_name = role;
    let mut role = Command::new(std::env::current_exe()?);
    role.args([
        role_name,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(ROLE_KIND, kind)
    .env(ROLE_PIDFILE, &pidfile)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    let mut role = role.tied_to_test().spawn()?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let pid = loop {
        if let Some(pid) = std::fs::read_to_string(&pidfile)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
        {
            break pid;
        }
        if let Some(status) = role.try_wait()? {
            let mut err = String::new();
            if let Some(mut e) = role.stderr.take() {
                use std::io::Read as _;
                let _ = e.read_to_string(&mut err);
            }
            return Err(format!("the {kind} child role ended first: {status}\n{err}").into());
        }
        if Instant::now() >= deadline {
            let _ = role.kill();
            let _ = role.wait();
            return Err(format!("the {kind} child role started no server within 60 s").into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // SIGKILL to the role's pid alone: no Drop runs in it.
    role.kill()?;
    role.wait()?;
    Ok(pid)
}

/// The orphan check for `kind`: the server is gone within [`GONE_WITHIN`]
/// of its test process being killed.
fn assert_server_ends_with_its_test(kind: &str) -> Result<(), TestError> {
    let pid = kill_a_test_holding("child_role_holds_a_server", kind)?;
    let gone = ends_within(pid, GONE_WITHIN);
    if !gone {
        stop_leftover(pid);
    }
    assert!(
        gone,
        "the {kind} server (pid {pid}) was still running {GONE_WITHIN:?} after \
         its test process was killed"
    );
    Ok(())
}

/// A test process that holds a `sipnab --api` started by `ApiServer` and is
/// killed with SIGKILL leaves no server behind.
#[test]
fn an_api_server_ends_when_its_test_process_is_killed() -> Result<(), TestError> {
    assert_server_ends_with_its_test("api")
}

/// The same for the HTTP MCP server `support/mcp.rs` starts.
#[cfg(feature = "mcp-http")]
#[test]
fn an_http_mcp_server_ends_when_its_test_process_is_killed() -> Result<(), TestError> {
    assert_server_ends_with_its_test("mcp")
}

/// The same for `sipnab fleet serve`, started by `support/fleet_center.rs`.
#[test]
fn a_fleet_center_ends_when_its_test_process_is_killed() -> Result<(), TestError> {
    assert_server_ends_with_its_test("center")
}

/// The child role: start the server `ROLE_KIND` names, write its pid to
/// `ROLE_PIDFILE`, and wait to be killed. Run directly, with no parent, it
/// does nothing.
#[test]
#[ignore = "a child role, run by the orphan tests in this file"]
fn child_role_holds_a_server() -> Result<(), TestError> {
    let (Some(kind), Some(pidfile)) = (std::env::var_os(ROLE_KIND), std::env::var_os(ROLE_PIDFILE))
    else {
        return Ok(());
    };
    let pidfile = PathBuf::from(pidfile);
    let dir = tempfile::tempdir()?;
    // Each arm keeps its server alive until the parent kills this process.
    let _held: Box<dyn std::any::Any> = match kind.to_str() {
        Some("api") => {
            let srv = server::ApiServer::spawn_unsettled(&[])?;
            write_pid(&pidfile, srv.pid())?;
            Box::new(srv)
        }
        #[cfg(feature = "mcp-http")]
        Some("mcp") => {
            let (child, _addr) =
                mcp::spawn_http_loopback(&[])?.ok_or("the HTTP MCP server did not start")?;
            write_pid(&pidfile, child.id())?;
            Box::new(child)
        }
        Some("center") => {
            let center = start_center(dir.path())?;
            write_pid(&pidfile, center.pid())?;
            Box::new(center)
        }
        other => return Err(format!("unknown child role kind {other:?}").into()),
    };
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}

/// Write `pid` to `path` in one rename, so the parent never reads half of it.
fn write_pid(path: &Path, pid: u32) -> Result<(), TestError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, pid.to_string())?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// A fleet center on loopback with a store and signing key in `dir`.
fn start_center(dir: &Path) -> Result<fleet_center::Center, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let key = dir.join("center.signing");
    std::fs::write(&key, "child-lifetime-signing-key-0123456789abcdef")?;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let store = dir.join("center.store");
    let store_key = fleet_center::store_key_file(dir)?;
    fleet_center::Center::start(&[
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ])
}

/// A tied server still serves: `ApiServer` answers `/health` with 200.
#[test]
fn a_tied_api_server_still_serves() -> Result<(), TestError> {
    let srv = server::ApiServer::spawn(&[])?;
    let resp = srv.get("/health")?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    Ok(())
}

/// Dropping a tied `ApiServer` still stops it, as before.
#[test]
fn dropping_a_tied_api_server_still_stops_it() -> Result<(), TestError> {
    let srv = server::ApiServer::spawn_unsettled(&[])?;
    let pid = srv.pid();
    drop(srv);
    assert!(
        ends_within(pid, GONE_WITHIN),
        "the server (pid {pid}) outlived its Drop"
    );
    Ok(())
}

/// A tied child keeps its own exit status: tying it changes nothing while
/// its test runs.
#[test]
fn a_tied_child_keeps_its_exit_status() -> Result<(), TestError> {
    let status = Command::new("sh")
        .args(["-c", "exit 3"])
        .tied_to_test()
        .status()?;
    assert_eq!(status.code(), Some(3), "a tied child keeps its exit status");
    Ok(())
}

/// The death signal follows the THREAD that spawned the child, not the
/// process: a child started on a thread that then ends is killed although
/// the test process lives on. A helper must start its server on the thread
/// that holds it.
#[test]
fn a_child_ends_when_the_thread_that_started_it_ends() -> Result<(), TestError> {
    let child = std::thread::spawn(|| -> Result<std::process::Child, String> {
        Command::new("sleep")
            .arg("60")
            .tied_to_test()
            .spawn()
            .map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "the spawning thread panicked")??;
    let mut child = scopeguard_child(child);
    let gone = matches!(
        wait_for_status(&mut child.0, GONE_WITHIN)?,
        Some(status) if status.signal() == Some(libc::SIGKILL)
    );
    assert!(
        gone,
        "a child outlived the thread that started it by {GONE_WITHIN:?}"
    );
    Ok(())
}

/// The race the tie closes: a test process that dies between the fork and
/// the `prctl` sends no death signal. The child then sees a parent that is
/// not the one that forked it and does not start. Here the expected parent
/// is a pid that is not this process, which is what the child of a parent
/// that already died sees.
#[test]
fn a_child_whose_parent_is_already_gone_does_not_start() -> Result<(), TestError> {
    let mut cmd = Command::new("sleep");
    cmd.arg("60");
    // pid 1 is never this test's process.
    tie_to_parent(&mut cmd, 1);
    match cmd.spawn() {
        Ok(child) => {
            let mut child = scopeguard_child(child);
            let _ = child.0.kill();
            Err("a child whose parent was not the expected one started".into())
        }
        Err(e) => {
            assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "{e}");
            Ok(())
        }
    }
}

use std::os::unix::process::ExitStatusExt as _;

/// A child killed and reaped when the test ends, whatever it asserted.
struct ReapedChild(std::process::Child);

impl Drop for ReapedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Wrap `child` so it is killed and reaped on every path.
fn scopeguard_child(child: std::process::Child) -> ReapedChild {
    ReapedChild(child)
}

/// The child's status if it ends within `within`.
fn wait_for_status(
    child: &mut std::process::Child,
    within: Duration,
) -> Result<Option<std::process::ExitStatus>, TestError> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Every `.spawn()` in a test file that starts the sipnab binary, and every
/// `.spawn()` in `tests/support/`, goes through `tied_to_test`: on the same
/// line, or as the call just before it in the chain. The exceptions are a
/// command from `root_run::sudo()` or `root_run::tied()`
/// (`tests/support/root_run.rs`), as `privilege_drop_test.rs` runs: the
/// kernel clears the death signal when a set-user-ID program such as `sudo`
/// executes, so those commands are tied by a pipe instead; and the race test
/// in this file, which ties its child by hand.
///
/// The scan is by text, so it also counts spawns of other programs in those
/// files (a `sleep`, a `tmux` server, this binary's own child roles). They
/// are tied too: one rule for every child a sipnab test starts.
#[test]
fn every_child_a_sipnab_test_spawns_is_tied_to_it() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files: Vec<PathBuf> = Vec::new();
    for dir in [root.clone(), root.join("support")] {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut untied = Vec::new();
    let mut checked = 0usize;
    for path in &files {
        let text = std::fs::read_to_string(path)?;
        let in_support = path.parent().is_some_and(|p| p.ends_with("support"));
        if !in_support && !text.contains(concat!("CARGO_BIN_EXE_", "sipnab")) {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !spawns_a_process(line) {
                continue;
            }
            checked += 1;
            let before = lines[..i]
                .iter()
                .rev()
                .find(|l| !l.trim().is_empty())
                .copied()
                .unwrap_or_default();
            let tied = line.contains("tied_to_test()") || before.trim() == ".tied_to_test()";
            // The program is the one the nearest `Command::new` above names,
            // or a command `tests/support/root_run.rs` prepared.
            let program = lines[i.saturating_sub(40)..=i]
                .iter()
                .rev()
                .find(|l| l.contains("Command::new(") || l.contains("root_run::"))
                .copied()
                .unwrap_or_default();
            let sudo = program.contains("root_run::sudo()") || program.contains("root_run::tied()");
            // `a_child_whose_parent_is_already_gone_does_not_start` ties its
            // child to a chosen parent, with the same function.
            let tied_by_hand = lines[i.saturating_sub(4)..i]
                .iter()
                .any(|l| l.contains("tie_to_parent(&mut cmd"));
            if !tied && !sudo && !tied_by_hand {
                let name = path.strip_prefix(&root).unwrap_or(path).display();
                untied.push(format!("tests/{name}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        checked >= 80,
        "only {checked} spawn(s) found: the scan stopped matching"
    );
    assert!(
        untied.is_empty(),
        "these spawns are not tied to their test (add `.tied_to_test()` before \
         `.spawn()`, from tests/support/child_lifetime.rs):\n{}",
        untied.join("\n")
    );
    Ok(())
}

/// Whether `line` spawns a process with `Command::spawn`, as opposed to a
/// thread or a task.
fn spawns_a_process(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or_default();
    code.contains(".spawn()") && !code.contains("thread::spawn") && !code.contains("tokio::spawn")
}

// ── Commands tied by a pipe (tests/support/root_run.rs) ───────────────────
//
// A command under `sudo` cannot be tied with the death signal, so
// `root_run::sudo()` ties it with a pipe the test process holds
// (PRIVILEGE-TEST-LEAVES-SUDO-CHILD-WHEN-CUT-SHORT). `root_run::tied()` is
// the same `sh` program without `sudo`, so its rules are tested on every
// runner, and one test runs it under `sudo` where that is available.

/// The seconds a held command sleeps for. No test waits that long: the
/// number marks the process as one this file started, so a failing run stops
/// that process and no other.
const HELD_SECS: &str = "86311";

/// The `sh -c` text of a held command, run with the pid file as its `$0`:
/// it runs `before`, writes its own pid to the file in one rename, and
/// becomes `sleep` with the same pid.
fn held(before: &str) -> String {
    format!(r#"{before}echo $$ > "$0.tmp" && mv "$0.tmp" "$0" && exec sleep {HELD_SECS}"#)
}

/// The pid a held command wrote to `path`, if it does so within `within`.
fn pid_written(path: &Path, within: Duration) -> Option<u32> {
    let deadline = Instant::now() + within;
    loop {
        if let Some(pid) = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok())
        {
            return Some(pid);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Stop a held command that outlived what should have ended it, so a failing
/// run leaves nothing behind. Only a process whose command line holds
/// [`HELD_SECS`] is signaled; `as_root` for one that `sudo` started.
fn stop_leftover_run(pid: u32, as_root: bool) {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let ours = cmdline
        .windows(HELD_SECS.len())
        .any(|w| w == HELD_SECS.as_bytes());
    if !ours {
        return;
    }
    if as_root {
        if let Ok(mut kill) = root_run::sudo() {
            let _ = kill.args(["kill", "-KILL", &pid.to_string()]).status();
        }
    } else if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: kill(2) on a pid whose command line was just read as a
        // held command of this file.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// The child role of the pipe-tied tests: start a held command the way
/// `ROLE_KIND` names (`tied`, `deaf` for one that ignores SIGTERM, `sudo`),
/// and wait to be killed. Run directly, with no parent, it does nothing.
#[test]
#[ignore = "a child role, run by the pipe-tied tests in this file"]
fn child_role_holds_a_tied_run() -> Result<(), TestError> {
    let (Some(kind), Some(pidfile)) = (std::env::var_os(ROLE_KIND), std::env::var_os(ROLE_PIDFILE))
    else {
        return Ok(());
    };
    let (mut cmd, before) = match kind.to_str() {
        Some("tied") => (root_run::tied()?, ""),
        Some("deaf") => (root_run::tied()?, "trap '' TERM; "),
        // Stays an `sh` (it never reaches the `exec sleep`), records a
        // SIGTERM beside the pid file, and ends.
        Some("noting") => (
            root_run::tied()?,
            "trap 'echo got > \"$0.term\"; exit 0' TERM; \
             echo $$ > \"$0.tmp\" && mv \"$0.tmp\" \"$0\"; \
             while :; do sleep 1; done; ",
        ),
        Some("sudo") => (root_run::sudo()?, ""),
        other => return Err(format!("unknown child role kind {other:?}").into()),
    };
    // Held, never stopped here: only the pipe ends it.
    let _run = cmd
        .args(["sh", "-c", &held(before)])
        .arg(&pidfile)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::sleep(Duration::from_secs(60));
    Ok(())
}

/// The orphan check for a pipe-tied command: it is gone within `within` of
/// its test process being killed.
fn assert_run_ends_with_its_test(kind: &str, within: Duration) -> Result<(), TestError> {
    let pid = kill_a_test_holding("child_role_holds_a_tied_run", kind)?;
    let gone = ends_within(pid, within);
    if !gone {
        stop_leftover_run(pid, kind == "sudo");
    }
    assert!(
        gone,
        "the {kind} command (pid {pid}) was still running {within:?} after its \
         test process was killed"
    );
    Ok(())
}

/// A test process that holds a pipe-tied command and is killed takes the
/// command with it. The command is not a child of the test's `Drop`: SIGKILL
/// runs none.
#[test]
fn a_pipe_tied_command_ends_when_its_test_process_is_killed() -> Result<(), TestError> {
    assert_run_ends_with_its_test("tied", GONE_WITHIN)
}

/// A command that ignores SIGTERM is ended with SIGKILL after the grace.
#[test]
fn a_pipe_tied_command_that_ignores_sigterm_is_killed_after_the_grace() -> Result<(), TestError> {
    let within = GONE_WITHIN + Duration::from_secs(u64::from(root_run::GRACE_SECS));
    assert_run_ends_with_its_test("deaf", within)
}

/// The command is asked to stop before it is killed: it receives SIGTERM
/// first, and has the grace to act on it.
#[test]
fn a_pipe_tied_command_receives_sigterm_before_it_is_killed() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pid = kill_a_test_holding_in("child_role_holds_a_tied_run", "noting", dir.path())?;
    let within = GONE_WITHIN + Duration::from_secs(u64::from(root_run::GRACE_SECS));
    let gone = ends_within(pid, within);
    if !gone {
        stop_leftover_run(pid, false);
    }
    assert!(
        gone,
        "the command (pid {pid}) was still running {within:?} after its test \
         process was killed"
    );
    assert!(
        dir.path().join("server.pid.term").exists(),
        "the command recorded no SIGTERM before it ended"
    );
    Ok(())
}

/// The defect itself: a command `sudo` started ends when its test process is
/// killed. It kept running with init as its parent, because the kernel
/// clears the death signal when `sudo` executes.
#[test]
fn a_sudo_command_ends_when_its_test_process_is_killed() -> Result<(), TestError> {
    let sudo_works = root_run::sudo()?
        .arg("true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !sudo_works {
        use std::io::Write as _;
        // The real stderr: libtest drops a passing test's captured output.
        let _ = writeln!(
            std::io::stderr(),
            "NOTICE: `a_sudo_command_ends_when_its_test_process_is_killed` did NOT run: \
             passwordless sudo is not available."
        );
        return Ok(());
    }
    assert_run_ends_with_its_test("sudo", GONE_WITHIN)
}

/// Run `args` (program, then arguments) pipe-tied, and collect it. A run
/// that has not ended within [`GONE_WITHIN`] is an error: none of the
/// commands these tests pass waits for anything.
fn tied_output(args: &[&str]) -> Result<std::process::Output, TestError> {
    let mut cmd = root_run::tied()?;
    let mut child = cmd
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if wait_for_status(&mut child, GONE_WITHIN)?.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("{args:?} had not ended after {GONE_WITHIN:?}").into());
    }
    Ok(child.wait_with_output()?)
}

/// A pipe-tied command that succeeds is reported as exit 0, while the test
/// that started it still runs: the run does not wait for the pipe.
#[test]
fn a_pipe_tied_command_that_succeeds_exits_0() -> Result<(), TestError> {
    let out = tied_output(&["true"])?;
    assert_eq!(out.status.code(), Some(0), "a command that exits 0");
    Ok(())
}

/// A pipe-tied command keeps its own exit code.
#[test]
fn a_pipe_tied_command_keeps_its_exit_code() -> Result<(), TestError> {
    for code in [1, 2, 7, 126] {
        let out = tied_output(&["sh", "-c", &format!("exit {code}")])?;
        assert_eq!(out.status.code(), Some(code), "a command that exits {code}");
    }
    Ok(())
}

/// A pipe-tied command's standard output and standard error arrive as it
/// wrote them, each on its own stream.
#[test]
fn a_pipe_tied_command_keeps_its_output() -> Result<(), TestError> {
    let out = tied_output(&["sh", "-c", "echo to-out; echo to-err >&2"])?;
    assert_eq!(out.stdout, b"to-out\n", "standard output");
    assert_eq!(out.stderr, b"to-err\n", "standard error");
    Ok(())
}

/// Every argument reaches the command as one argument, unchanged: a space,
/// an empty string, a glob, quotes, a dollar sign, a leading dash.
#[test]
fn a_pipe_tied_command_gets_its_arguments_unchanged() -> Result<(), TestError> {
    let args = ["a b", "", "*", "it's", "$HOME", "\"q\"", "-n", "a;b"];
    let mut argv = vec!["printf", "[%s]\\n"];
    argv.extend(args);
    let out = tied_output(&argv)?;
    let want: String = args.iter().map(|a| format!("[{a}]\n")).collect();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        want,
        "the arguments the command saw"
    );
    Ok(())
}

/// A program that does not exist is reported as exit 127, as `sh` reports
/// it, and named on standard error.
#[test]
fn a_pipe_tied_program_that_does_not_exist_exits_127() -> Result<(), TestError> {
    let out = tied_output(&["sipnab-test-no-such-program"])?;
    assert_eq!(out.status.code(), Some(127), "a program that is not there");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("sipnab-test-no-such-program"),
        "standard error names the program: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// A command that a signal ended is reported as exit 128 plus the signal
/// number.
#[test]
fn a_pipe_tied_command_a_signal_ended_exits_128_plus_the_signal() -> Result<(), TestError> {
    let out = tied_output(&["sh", "-c", "kill -KILL $$"])?;
    assert_eq!(
        out.status.code(),
        Some(128 + libc::SIGKILL),
        "a command SIGKILL ended"
    );
    Ok(())
}

/// The command's standard input is `/dev/null`, not the pipe that ties it:
/// a command that reads its input to the end returns at once.
#[test]
fn a_pipe_tied_command_reads_dev_null_not_the_pipe() -> Result<(), TestError> {
    let out = tied_output(&["sh", "-c", "cat && readlink /proc/$$/fd/0"])?;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "/dev/null\n",
        "the command's standard input"
    );
    Ok(())
}

/// Prints the target of every descriptor the shell that runs it holds.
const LIST_DESCRIPTORS: &str = "for fd in /proc/$$/fd/*; do readlink \"$fd\"; done";

/// How many lines of `links` name a pipe.
fn pipes_in(links: &str) -> usize {
    links.lines().filter(|l| l.starts_with("pipe:")).count()
}

/// The command does not inherit the descriptor the `sh` program keeps the
/// pipe on: it holds as many pipes as the same command started without the
/// tie.
///
/// The count is compared with an untied run, not with the number two. A test
/// process can itself have been started with pipes that pass to every child
/// (under `cargo llvm-cov` it holds two), and those are not the tie.
#[test]
fn a_pipe_tied_command_does_not_inherit_the_pipe() -> Result<(), TestError> {
    let untied = Command::new("env")
        .args(["--", "sh", "-c", LIST_DESCRIPTORS])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    // The listing's exit status is that of its last `readlink`, which fails
    // when the last name is a descriptor the shell closed after listing the
    // directory; the lines it printed are what is read here.
    let untied_links = String::from_utf8_lossy(&untied.stdout);
    let expected = pipes_in(&untied_links);
    assert!(
        expected >= 2,
        "an untied command holds at least its two output pipes: {untied_links:?}"
    );

    let out = tied_output(&["sh", "-c", LIST_DESCRIPTORS])?;
    let links = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        pipes_in(&links),
        expected,
        "the tied command holds the pipes an untied one holds and no other: \
         tied {links:?}, untied {untied_links:?}"
    );
    Ok(())
}

/// The pids of the processes whose command line holds `token`.
fn processes_naming(token: &str) -> Result<Vec<u32>, TestError> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let name = entry?.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if cmdline.windows(token.len()).any(|w| w == token.as_bytes()) {
            found.push(pid);
        }
    }
    Ok(found)
}

/// A run that has ended leaves no process behind: the part of the `sh`
/// program that waits on the pipe is stopped with the command, and does not
/// stay until the test process ends.
#[test]
fn a_finished_pipe_tied_run_leaves_no_process_behind() -> Result<(), TestError> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let token = format!("sipnab-tied-token-{}-{nanos}", std::process::id());
    // Many short runs: the waiting part of one was once left behind when its
    // stop signal reached it before it had reset the traps it inherited.
    for run in 0..40 {
        let out = tied_output(&["true", &token])?;
        assert_eq!(out.status.code(), Some(0), "run {run} itself");
    }
    let deadline = Instant::now() + GONE_WITHIN;
    let mut left = processes_naming(&token)?;
    while !left.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        left = processes_naming(&token)?;
    }
    assert!(
        left.is_empty(),
        "processes of a finished run were still there after {GONE_WITHIN:?}: {left:?}"
    );
    Ok(())
}

/// Send `signal` to the `sh` program of a held command, and require the
/// command to end and the run to report exit 128 plus SIGTERM: the signal
/// reaches the command as SIGTERM. This is how `privilege_drop_test.rs`
/// stops a server: it signals the `sudo` above the program, which relays.
fn assert_a_signal_to_the_program_ends_the_command(signal: libc::c_int) -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pidfile = dir.path().join("run.pid");
    let mut cmd = root_run::tied()?;
    let mut run = scopeguard_child(
        cmd.args(["sh", "-c", &held("")])
            .arg(&pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let pid = pid_written(&pidfile, Duration::from_secs(60))
        .ok_or("the held command did not start within 60 s")?;
    let program = libc::pid_t::try_from(run.0.id())?;
    // SAFETY: kill(2) on a child of this test that it has not reaped.
    let sent = unsafe { libc::kill(program, signal) };
    let status = wait_for_status(&mut run.0, GONE_WITHIN)?;
    let gone = ends_within(pid, GONE_WITHIN);
    if !gone {
        stop_leftover_run(pid, false);
    }
    assert_eq!(sent, 0, "signal {signal} to the sh program");
    assert!(
        gone,
        "the command (pid {pid}) was still running {GONE_WITHIN:?} after signal {signal}"
    );
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(128 + libc::SIGTERM),
        "the run reports the command as ended by SIGTERM after signal {signal}"
    );
    Ok(())
}

/// SIGTERM to the `sh` program ends the command.
#[test]
fn sigterm_to_a_pipe_tied_run_ends_its_command() -> Result<(), TestError> {
    assert_a_signal_to_the_program_ends_the_command(libc::SIGTERM)
}

/// SIGINT to the `sh` program ends the command.
#[test]
fn sigint_to_a_pipe_tied_run_ends_its_command() -> Result<(), TestError> {
    assert_a_signal_to_the_program_ends_the_command(libc::SIGINT)
}

/// SIGHUP to the `sh` program ends the command.
#[test]
fn sighup_to_a_pipe_tied_run_ends_its_command() -> Result<(), TestError> {
    assert_a_signal_to_the_program_ends_the_command(libc::SIGHUP)
}

/// `sudo` is named in one place under `tests/`: the helper that ties what it
/// starts. A test that names it directly starts a command nothing ends when
/// the test process is cut short.
#[test]
fn only_the_tying_helper_names_sudo() -> Result<(), TestError> {
    let needle = concat!("Command::new(\"su", "do\")");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut found = Vec::new();
    for dir in [root.clone(), root.join("support")] {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            for (i, line) in text.lines().enumerate() {
                if line.contains(needle) {
                    let name = path.strip_prefix(&root).unwrap_or(&path).display();
                    found.push(format!("tests/{name}:{}", i + 1));
                }
            }
        }
    }
    assert_eq!(found.len(), 1, "sites that name sudo: {found:?}");
    assert!(
        found[0].starts_with("tests/support/root_run.rs:"),
        "the one site is the helper (use `root_run::sudo()`): {found:?}"
    );
    Ok(())
}
