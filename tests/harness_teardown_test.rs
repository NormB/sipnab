// SPDX-License-Identifier: MIT OR Apache-2.0

//! How the spawn harnesses stop the processes they start.
//!
//! Every harness that spawns the binary -- `ApiServer`, `McpSession`,
//! `HepListener` and the per-file ones -- tears its child down through one
//! function, `terminate` in `support/teardown.rs`. They used to call
//! `Child::kill()`, which is SIGKILL, and the LLVM profile runtime writes a
//! process's `.profraw` only when that process exits: every line a harnessed
//! server ran was missing from the coverage report, so the figure CI publishes
//! understated what the suite exercises.
//!
//! The rule tested here is SIGTERM, a bounded wait, and SIGKILL only for a
//! child still alive at the end of it. The first two tests use a shell child,
//! because the rule has to hold for a process that ignores SIGTERM and sipnab
//! does not; the rest drive the real binary through the shared harnesses and
//! read its exit status, which is the observable half of "the profile was
//! written".
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

include!("support/timeout.rs");
include!("support/teardown.rs");

#[cfg(feature = "api")]
#[path = "support/server.rs"]
mod server;

#[cfg(feature = "mcp")]
#[path = "support/mcp.rs"]
mod mcp;

/// Spawn `sh -c script` and return once it prints `ready`.
///
/// Each script prints `ready` after installing its trap, so a test that
/// signals the child cannot race the shell's startup and hit the default
/// disposition instead of the one under test.
fn shell_ready(script: &str) -> Child {
    let mut child = Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sh");
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().expect("piped stdout"))
        .read_line(&mut line)
        .expect("read the ready line");
    assert_eq!(line.trim(), "ready", "the helper script did not start");
    child
}

/// A child that handles SIGTERM is given the chance to: teardown signals it,
/// waits, and returns the status the child chose.
///
/// The loop sleeps in short steps with its output discarded, so the shell runs
/// its trap promptly and leaves no process holding the pipe behind it.
#[test]
fn a_child_that_handles_sigterm_exits_with_the_status_it_chose() {
    let mut child =
        shell_ready("trap 'exit 7' TERM; echo ready; while :; do sleep 0.05 >/dev/null; done");

    let status = terminate_within(&mut child, test_timeout(10)).expect("reap the child");

    assert_eq!(
        status.code(),
        Some(7),
        "teardown must send SIGTERM and wait for the child's own exit, got {status}"
    );
}

/// A child that ignores SIGTERM is still stopped: once the grace period has
/// passed it is SIGKILLed, so a wedged server can never hang the suite -- and
/// not before, because the grace period is what a clean exit is owed.
///
/// `exec` hands the ignored disposition to `sleep` itself, so the SIGKILL lands
/// on the process that ignores SIGTERM and nothing is orphaned.
#[test]
fn a_child_that_ignores_sigterm_is_killed_once_the_grace_period_ends() {
    let grace = Duration::from_millis(500);
    let mut child = shell_ready("trap '' TERM; echo ready; exec sleep 60");

    let started = Instant::now();
    let status = terminate_within(&mut child, grace).expect("reap the child");
    let took = started.elapsed();

    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "a child that ignores SIGTERM must end up SIGKILLed, got {status}"
    );
    assert!(
        took >= grace,
        "the child was killed after {took:?}, before its {grace:?} grace period ran out"
    );
    assert!(
        took < grace + test_timeout(10),
        "teardown took {took:?}; the {grace:?} bound did not hold"
    );
}

/// Teardown reaps what it stops: once it returns, the pid is gone rather than
/// left as a zombie.
#[test]
fn teardown_reaps_the_child_it_stops() {
    let mut child =
        shell_ready("trap 'exit 0' TERM; echo ready; while :; do sleep 0.05 >/dev/null; done");
    let pid = libc::pid_t::try_from(child.id()).expect("pid fits pid_t");

    terminate_within(&mut child, test_timeout(10)).expect("reap the child");

    // SAFETY: signal 0 only asks whether the pid exists; nothing is delivered.
    let exists = unsafe { libc::kill(pid, 0) } == 0;
    assert!(!exists, "pid {pid} still exists after teardown returned");
}

/// The REST harness stops `sipnab --api` with SIGTERM, and it exits 0.
#[cfg(feature = "api")]
#[test]
fn the_api_harness_stops_sipnab_with_a_clean_exit() {
    let srv = server::ApiServer::spawn(&[]);
    assert_eq!(
        srv.get("/health").status,
        200,
        "control: the server must be answering before it is stopped"
    );

    let status = srv.stop();

    assert_eq!(
        status.code(),
        Some(0),
        "sipnab --api must exit on SIGTERM, not be killed: {status}"
    );
}

/// A test that panics still reaps its server: `Drop` runs the same teardown.
#[cfg(feature = "api")]
#[test]
fn a_panicking_test_still_reaps_its_api_server() {
    let pid = std::sync::Mutex::new(None);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let srv = server::ApiServer::spawn(&[]);
        *pid.lock().expect("pid lock") = Some(srv.pid());
        panic!("a failing assertion while the server is up");
    }));
    assert!(outcome.is_err(), "the closure must have panicked");
    let pid = pid
        .into_inner()
        .expect("pid lock")
        .expect("the server was spawned before the panic");
    let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");

    // SAFETY: signal 0 only asks whether the pid exists; nothing is delivered.
    let exists = unsafe { libc::kill(pid, 0) } == 0;
    assert!(
        !exists,
        "sipnab --api (pid {pid}) outlived the panicking test that owned it"
    );
}

/// The stdio MCP harness stops `sipnab --mcp` with SIGTERM, and it exits 0.
///
/// `start` has already waited for the capture to load, so the server is in
/// its serving loop when it is stopped.
#[cfg(feature = "mcp")]
#[test]
fn the_mcp_session_harness_stops_sipnab_with_a_clean_exit() {
    let pcap = mcp::fixture("sip_call.pcap");
    let session = mcp::McpSession::start(pcap.to_str().expect("utf-8 path"), &[]);

    let status = session.stop();

    assert_eq!(
        status.code(),
        Some(0),
        "sipnab --mcp must exit on SIGTERM, not be killed: {status}"
    );
}
