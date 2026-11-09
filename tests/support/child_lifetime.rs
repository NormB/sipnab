// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//
// Included textually with `include!`, as `timeout.rs` is: the support files
// that start sipnab are themselves pulled in with `#[path]` by many test
// binaries, and `include!` resolves relative to the including file.

/// The one rule for a process a test starts: it ends with the test
/// (TEST-CHILD-ORPHAN).
///
/// The helpers stop their child in `Drop`, and `Drop` does not run when the
/// test process is killed: SIGKILL, the kernel's OOM killer, or a harness
/// that signals the test's pid and not its process group. A serving sipnab
/// left that way keeps running with init as its parent.
///
/// On Linux, [`TiedToTest::tied_to_test`] sets `PR_SET_PDEATHSIG` to SIGKILL
/// in the child before it executes, so the kernel kills the child when the
/// thread that spawned it ends, however the thread ends. Three consequences:
///
/// - The signal follows the spawning THREAD, not the process. A helper must
///   spawn its child on the thread that holds it for the test; a child
///   spawned on a thread that then ends is killed at once.
/// - The kernel clears the setting when the child executes a set-user-ID or
///   set-group-ID program (such as `sudo`), or changes its effective or
///   filesystem user or group id. A sipnab run under `sudo`, or one that drops
///   privileges with `--user`, is not tied.
/// - The child's own children are not tied: the setting is cleared on fork.
///
/// Other systems have no such setting. There this changes nothing, and the
/// helpers' `Drop` remains the only stop.
#[allow(dead_code)]
trait TiedToTest {
    /// Make the child this command spawns end when the spawning thread ends.
    fn tied_to_test(&mut self) -> &mut Self;
}

impl TiedToTest for std::process::Command {
    fn tied_to_test(&mut self) -> &mut Self {
        #[cfg(target_os = "linux")]
        tie_to_parent(self, std::process::id());
        self
    }
}

/// Set the death signal in the child, then check that its parent is still
/// `parent`.
///
/// The check closes a race: a parent that dies after the fork and before
/// the `prctl` sends no signal, because the child has already been given to
/// a new parent. The child then sees a different parent, and its spawn
/// fails with `ESRCH` instead of running untied.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn tie_to_parent(cmd: &mut std::process::Command, parent: u32) {
    use std::os::unix::process::CommandExt as _;
    // A pid that does not fit is never the parent, so the spawn fails.
    let parent = libc::pid_t::try_from(parent).unwrap_or(-1);
    // SAFETY: the closure runs in the forked child before exec, and calls
    // only prctl(2) and getppid(2), which are async-signal-safe. It builds
    // its errors from an errno value, which does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
}
