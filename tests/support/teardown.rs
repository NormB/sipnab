// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Included textually with `include!`, for the reason `timeout.rs` gives:
// `support/server.rs` and `support/mcp.rs` are themselves pulled in with
// `#[path]` by many test binaries, and every harness that spawns the binary
// needs this one teardown rule without a module path that resolves
// differently per includer. Needs `test_timeout` from `timeout.rs` in scope.

/// How long a spawned child gets to exit on SIGTERM before it is SIGKILLed,
/// in seconds, before `SIPNAB_TEST_TIMEOUT_SCALE`.
///
/// Not a measure of how long sipnab takes. Every server mode the harnesses
/// start (`--api`, `--mcp` over stdio and HTTP, `--hep-listen`) exited 0
/// within 70 ms of SIGTERM when measured on 2026-09-21, and teardown returns
/// as soon as the child does. The bound exists for a wedged child, and it is
/// generous for one reason: a child SIGKILLed while it is writing its profile
/// at exit leaves a truncated `.profraw`, and one truncated file fails the
/// whole `llvm-profdata merge` (see `discard_coverage_profile`). Ten seconds
/// is far past any profile write and still short enough that a wedged server
/// costs one test, not the suite.
#[allow(dead_code)]
const TERMINATE_GRACE_SECS: u64 = 10;

/// Stop a spawned child the way an operator does, and reap it.
///
/// SIGTERM first, so the child leaves through its ordinary exit path. That is
/// the path on which the LLVM profile runtime writes the child's coverage;
/// `Child::kill()` is SIGKILL, which ends the process before any of it runs,
/// and every line a harnessed server executed used to go unrecorded because of
/// it. SIGKILL is still sent, but only to a child alive at the end of
/// [`TERMINATE_GRACE_SECS`], so nothing that ignores SIGTERM can hang a run.
///
/// Safe to call on a child that has already exited or been reaped: it returns
/// the recorded status without signaling anything, which is what lets a
/// harness's `stop` and its `Drop` both call it.
///
/// # Returns
/// How the child exited -- `code()` for a clean exit, `signal()` when the
/// SIGKILL fallback had to be used.
#[allow(dead_code)]
fn terminate(child: &mut std::process::Child) -> std::io::Result<std::process::ExitStatus> {
    terminate_within(child, test_timeout(TERMINATE_GRACE_SECS))
}

/// [`terminate`] with an explicit grace period, so the fallback can be tested
/// without waiting out the real one.
#[allow(dead_code)]
fn terminate_within(
    child: &mut std::process::Child,
    grace: std::time::Duration,
) -> std::io::Result<std::process::ExitStatus> {
    // A reaped pid may already belong to another process; never signal it.
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let pid = libc::pid_t::try_from(child.id()).expect("a child pid fits pid_t");
    // SAFETY: kill(2) on a child this process spawned and has not reaped, so
    // the pid cannot have been reused; touches no memory.
    unsafe { libc::kill(pid, libc::SIGTERM) };

    let deadline = std::time::Instant::now() + grace;
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        // Short, because the wait is the cost of every teardown in the suite
        // and a clean exit takes milliseconds.
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    // Still running after the grace period: the child is wedged, and ending
    // the run matters more than its profile. The reap below runs whatever the
    // kill reports, so no path out of here leaves a zombie.
    let _ = child.kill();
    child.wait()
}
