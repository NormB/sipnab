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

/// Run the child role for `kind`, wait for it to report its server's pid,
/// SIGKILL the role process, and return the server's pid.
fn kill_a_test_holding(kind: &str) -> Result<u32, TestError> {
    let dir = tempfile::tempdir()?;
    let pidfile = dir.path().join("server.pid");
    let mut role = Command::new(std::env::current_exe()?);
    role.args([
        "child_role_holds_a_server",
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
    let pid = kill_a_test_holding(kind)?;
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
/// `Command::new("sudo")`, as `privilege_drop_test.rs` runs: the kernel
/// clears the death signal when a set-user-ID program such as `sudo`
/// executes, so tying it would claim a stop that does not happen; and the
/// race test in this file, which ties its child by hand.
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
            // The program is the one the nearest `Command::new` above names.
            let program = lines[i.saturating_sub(40)..=i]
                .iter()
                .rev()
                .find(|l| l.contains("Command::new("))
                .copied()
                .unwrap_or_default();
            let sudo = program.contains(r#"Command::new("sudo")"#);
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
