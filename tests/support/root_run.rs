// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one way a test starts a command under `sudo`: tied to the test process
//! by a pipe, so the command ends when the test process ends
//! (PRIVILEGE-TEST-LEAVES-SUDO-CHILD-WHEN-CUT-SHORT).
//!
//! `tests/support/child_lifetime.rs` ties a child to its test with
//! `PR_SET_PDEATHSIG`. The kernel clears that setting when a set-user-ID
//! program such as `sudo` is executed, and other systems do not have it. A
//! `sudo sipnab ... --api` server whose test binary was ended before the test
//! stopped it kept running with init as its parent (2026-11-11).
//!
//! The rule here needs no kernel setting. The test process holds the write
//! end of one pipe for as long as it lives, and never writes to it. Every
//! command started through [`sudo`] or [`tied`] runs under a small `sh`
//! program that holds the read end. When the test process ends, by any cause
//! including SIGKILL, the kernel closes the write end, the `sh` program reads
//! end-of-file, and it ends the command: SIGTERM first, SIGKILL after
//! [`GRACE_SECS`] seconds. Under `sudo` that `sh` runs as root, so it can
//! signal a command that has since dropped to another user.
//!
//! What a caller sees through the `sh` program:
//!
//! - The command's arguments, output and exit code are unchanged.
//! - A command that a signal ended is reported as exit code 128 plus the
//!   signal number, as `sh` reports it.
//! - SIGTERM, SIGINT and SIGHUP sent to the `sh` program (or to the `sudo`
//!   above it, which relays them) reach the command as SIGTERM.
//! - The command's standard input is `/dev/null`.
//! - The command starts with SIGINT and SIGQUIT ignored, as every background
//!   command of a non-interactive `sh` does; a command that installs its own
//!   handlers is not affected.

use std::io::{PipeReader, PipeWriter};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Seconds between the SIGTERM and the SIGKILL that end a tied command after
/// the test process has gone.
pub const GRACE_SECS: u32 = 2;

/// The name the `sh` program runs under (its `$0`), so `ps` shows what the
/// process is.
pub const TIED_NAME: &str = "sipnab-test-tied-run";

/// The `sh` program a tied command runs under. Standard input is the read
/// end of the test's pipe; `"$@"` is the command; `$GRACE` is replaced with
/// [`GRACE_SECS`] before the program runs.
///
/// Line by line: keep the pipe on descriptor 3 and read `/dev/null`; note a
/// signal that arrives before the command's pid is known (`t`), and pass a
/// later one on as SIGTERM; on SIGUSR1 send the command SIGKILL; start the
/// command without descriptor 3; start the part that waits on the pipe, with
/// no output descriptor of the caller's, so a caller that collects output
/// does not wait for it; wait for the command, again after each signal that
/// interrupted the wait (a wait that answers 127 has no child left to
/// report); forget the command's pid, stop the waiting part and answer with
/// the command's status.
///
/// Two rules keep a signal from reaching a process this program did not
/// start:
///
/// - The waiting part signals only the program itself (`$$`), never the
///   command: the program is its parent, and passes the signal on while the
///   command is still its unreaped child.
/// - The program stops the waiting part with SIGKILL before it exits. A
///   SIGTERM can be lost: `dash` drops a signal that reaches a subshell
///   before the subshell has reset the traps it inherited. A waiting part
///   left that way was seen once (2026-11-11), with init as its parent,
///   after the run it belonged to had ended.
const TIED_SH: &str = r#"exec 3<&0 </dev/null
t=
c=
trap 't=1; [ -z "$c" ] || kill -TERM "$c" 2>/dev/null' TERM INT HUP
trap '[ -z "$c" ] || kill -KILL "$c" 2>/dev/null' USR1
"$@" 3<&- &
c=$!
[ -z "$t" ] || kill -TERM "$c" 2>/dev/null
(
	IFS= read -r line <&3
	kill -TERM "$$" 2>/dev/null
	sleep "$GRACE"
	kill -USR1 "$$" 2>/dev/null
) >/dev/null 2>&1 &
w=$!
exec 3<&-
wait "$c"
rc=$?
while [ "$rc" -gt 128 ] && kill -0 "$c" 2>/dev/null; do
	wait "$c"
	again=$?
	[ "$again" -eq 127 ] && break
	rc=$again
done
c=
kill -KILL "$w" 2>/dev/null
exit "$rc"
"#;

/// The pipe whose write end this process holds until it ends.
///
/// Both ends are close-on-exec (`std::io::pipe`), so no child inherits the
/// write end; a child that did would keep the pipe open after the test.
fn lifeline() -> std::io::Result<&'static (PipeReader, PipeWriter)> {
    static LIFELINE: OnceLock<(PipeReader, PipeWriter)> = OnceLock::new();
    if let Some(pipe) = LIFELINE.get() {
        return Ok(pipe);
    }
    let pipe = std::io::pipe()?;
    Ok(LIFELINE.get_or_init(|| pipe))
}

/// Append the tied `sh` program to `cmd` and give it the pipe's read end.
fn tie(mut cmd: Command) -> std::io::Result<Command> {
    let (reader, _writer) = lifeline()?;
    let program = TIED_SH.replace("$GRACE", &GRACE_SECS.to_string());
    cmd.args(["sh", "-c", &program, TIED_NAME])
        .stdin(Stdio::from(reader.try_clone()?));
    Ok(cmd)
}

/// A command that runs what the caller appends (program, then arguments) as
/// root through `sudo -n`, tied to this test process.
///
/// # Errors
/// The pipe could not be created or its read end duplicated.
///
/// # Side effects
/// Creates the process-wide pipe on first use.
pub fn sudo() -> std::io::Result<Command> {
    let mut cmd = Command::new("sudo");
    cmd.arg("-n");
    tie(cmd)
}

/// A command that runs what the caller appends (program, then arguments) as
/// the current user, tied to this test process. It is the same `sh` program
/// [`sudo`] uses, so its rules can be tested where there is no `sudo`.
///
/// # Errors
/// The pipe could not be created or its read end duplicated.
///
/// # Side effects
/// Creates the process-wide pipe on first use.
#[allow(
    dead_code,
    reason = "used by the tests of the rule, not by every binary"
)]
pub fn tied() -> std::io::Result<Command> {
    let mut cmd = Command::new("env");
    cmd.arg("--");
    tie(cmd)
}
