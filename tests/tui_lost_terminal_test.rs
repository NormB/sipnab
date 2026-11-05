// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The TUI stops when its terminal goes away, and when a stop signal asks it
//! to (TUI-LOST-TERMINAL-SPIN).
//!
//! 0.5.234 made SIGHUP a graceful stop (OPS-5) instead of the signal's
//! default action, which had ended the process at once. The TUI's event loop
//! never read the stop flag the signal handlers set, and it waited for input
//! through crossterm, whose reader loops forever once the terminal has hung
//! up: a read of a hung-up terminal returns end-of-file, and crossterm reads
//! again. So a TUI whose terminal went away (its tmux server killed, its
//! window closed) kept running in a busy loop, and SIGTERM did not stop it either,
//! with or without a terminal. Only SIGKILL did. Hook runs of the e2e suite in
//! `tests/tui_e2e_test.rs` left such processes behind.
//!
//! Each test runs the real binary on a pseudo-terminal this test owns. The
//! test answers the cursor-position query crossterm sends at startup (a bare
//! pty has no terminal emulator to answer it), waits until the call list is
//! drawn, and then takes the terminal away or sends the signal. The child is
//! this test's own, so its exit status is read with `wait`, and a child still
//! running at the deadline is killed by the pid recorded at spawn: a failing
//! test leaves no process behind.
//!
//! Linux only: the pty set-up uses Linux's `openpty`/`TIOCSCTTY` semantics.
//! The code under test does not differ by platform.
#![cfg(all(feature = "tui", target_os = "linux"))]

include!("support/timeout.rs");

use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type TestError = Box<dyn std::error::Error>;

/// The cursor-position query crossterm writes at startup.
const CURSOR_QUERY: &[u8] = b"\x1b[6n";

/// The answer a terminal at row 1, column 1 gives it.
const CURSOR_ANSWER: &[u8] = b"\x1b[1;1R";

/// What the TUI writes when it leaves the alternate screen: the terminal
/// guard ran, so the run ended through the UI's own exit path.
const LEAVE_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049l";

/// One sipnab TUI run on a pty this test owns.
struct PtyRun {
    /// The sipnab process, spawned by this test and not yet reaped.
    child: Child,
    /// Everything the TUI wrote to its terminal.
    output: Arc<Mutex<Vec<u8>>>,
    /// Set to make the reader thread close the pty's master side, which
    /// hangs the terminal up.
    hang_up: Arc<AtomicBool>,
    /// Bytes for the reader thread to type into the terminal.
    typed: Arc<Mutex<Vec<u8>>>,
    /// The reader thread, which owns the master side.
    reader: Option<thread::JoinHandle<()>>,
}

impl PtyRun {
    /// Start `sipnab -I sip_call.pcap <extra>` in `tests/fixtures` on a new
    /// 200x50 pty, in a new session. With `controlling` the pty becomes the
    /// session's controlling terminal, so a hang-up also sends SIGHUP, as it
    /// does to a process a terminal window or tmux pane starts; without it no
    /// SIGHUP arrives and only the terminal itself reports the hang-up.
    fn spawn(extra: &[&str], controlling: bool) -> Result<Self, TestError> {
        let spawning = SPAWNING
            .lock()
            .map_err(|_| "a test panicked while spawning")?;
        let (master, slave) = open_pty(50, 200)?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
            .args(["-I", "sip_call.pcap"])
            .args(extra)
            .env("SIPNAB_LOG", "off")
            .env("TERM", "xterm-256color")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        // SAFETY: the closure runs in the forked child before exec and calls
        // only setsid(2) and ioctl(2), both async-signal-safe. The pty's slave
        // side is the child's stdin (fd 0) by then.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if controlling && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        // The parent's copies of the slave side close here, with `cmd`.
        drop(cmd);
        drop(spawning);
        let output = Arc::new(Mutex::new(Vec::new()));
        let hang_up = Arc::new(AtomicBool::new(false));
        let typed = Arc::new(Mutex::new(Vec::new()));
        let reader = {
            let output = Arc::clone(&output);
            let hang_up = Arc::clone(&hang_up);
            let typed = Arc::clone(&typed);
            thread::spawn(move || serve_terminal(master, &output, &hang_up, &typed))
        };
        Ok(PtyRun {
            child,
            output,
            hang_up,
            typed,
            reader: Some(reader),
        })
    }

    /// Type `bytes` into the terminal, in one write.
    fn type_bytes(&self, bytes: &[u8]) -> Result<(), TestError> {
        self.typed
            .lock()
            .map_err(|_| "the pty reader thread panicked")?
            .extend_from_slice(bytes);
        Ok(())
    }

    /// The CPU time sipnab has used, in clock ticks (`utime` + `stime`).
    fn cpu_ticks(&self) -> Result<u64, TestError> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.child.id()))?;
        let rest = stat.rsplit_once(')').ok_or("no command name in stat")?.1;
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // utime and stime are fields 14 and 15; `rest` starts at field 3.
        let utime: u64 = fields.get(11).ok_or("no utime")?.parse()?;
        let stime: u64 = fields.get(12).ok_or("no stime")?.parse()?;
        Ok(utime + stime)
    }

    /// Whether the TUI has written `needle` to its terminal.
    fn wrote(&self, needle: &[u8]) -> bool {
        let out = self.output.lock().map(|o| o.clone()).unwrap_or_default();
        out.windows(needle.len()).any(|w| w == needle)
    }

    /// Wait until the TUI has drawn the call list.
    fn wait_until_drawn(&mut self) -> Result<(), TestError> {
        let deadline = Instant::now() + test_timeout(60);
        while !self.wrote(b"INVITE") {
            if let Some(status) = self.child.try_wait()? {
                return Err(format!("sipnab ended before it drew the call list: {status}").into());
            }
            if Instant::now() >= deadline {
                return Err("sipnab did not draw the call list within 60 s".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Close the master side of the pty: the terminal hangs up.
    fn hang_up(&mut self) -> Result<(), TestError> {
        self.hang_up.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            reader
                .join()
                .map_err(|_| "the pty reader thread panicked")?;
        }
        Ok(())
    }

    /// Send `signal` to the sipnab process.
    fn signal(&self, signal: libc::c_int) -> Result<(), TestError> {
        let pid = libc::pid_t::try_from(self.child.id())?;
        // SAFETY: kill(2) on the child this test spawned and has not reaped,
        // so the pid cannot have been reused.
        if unsafe { libc::kill(pid, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// The exit status, if sipnab ends within `within`. A run still going at
    /// the deadline is an error, and Drop kills it.
    fn wait_for_exit(&mut self, within: Duration, after: &str) -> Result<ExitStatus, TestError> {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "sipnab was still running {} s after {after}",
                    within.as_secs()
                )
                .into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for PtyRun {
    /// Kill the child by the handle this test spawned it with, if it is
    /// still running, and reap it; then stop the reader thread.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.hang_up.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// A new pty pair of `rows` x `cols`: (master, slave).
fn open_pty(rows: u16, cols: u16) -> Result<(OwnedFd, OwnedFd), TestError> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty(3) writes two descriptors into the two out-parameters;
    // the name and termios pointers may be null, and `size` is valid.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openpty succeeded, so both are open descriptors this function
    // now owns.
    let pair = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // openpty(3) cannot open them close-on-exec. A sipnab that inherited the
    // master side would hold its own terminal open, and closing the test's
    // copy would hang nothing up.
    for fd in [pair.0.as_raw_fd(), pair.1.as_raw_fd()] {
        // SAFETY: fcntl(2) on a descriptor this function owns.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(pair)
}

/// Held from `openpty` until the child is spawned. The descriptors are not
/// close-on-exec until `fcntl` marks them, and a test spawning in another
/// thread in between would hand them to its own child.
static SPAWNING: Mutex<()> = Mutex::new(());

/// Act as the terminal: collect what sipnab writes and answer its
/// cursor-position queries, until `hang_up` is set; then drop the master
/// side, which hangs the terminal up.
fn serve_terminal(
    master: OwnedFd,
    output: &Mutex<Vec<u8>>,
    hang_up: &AtomicBool,
    typed: &Mutex<Vec<u8>>,
) {
    let mut file = std::fs::File::from(master);
    let mut buf = [0u8; 4096];
    let mut answered = 0;
    while !hang_up.load(Ordering::SeqCst) {
        let pending = typed
            .lock()
            .map(|mut t| std::mem::take(&mut *t))
            .unwrap_or_default();
        if !pending.is_empty() {
            let _ = file.write_all(&pending);
        }
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for an open descriptor.
        let ready = unsafe { libc::poll(&mut pfd, 1, 50) };
        if ready <= 0 || pfd.revents & libc::POLLIN == 0 {
            if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                // The slave side is closed everywhere: sipnab has exited.
                thread::sleep(Duration::from_millis(50));
            }
            continue;
        }
        let Ok(n) = file.read(&mut buf) else {
            thread::sleep(Duration::from_millis(50));
            continue;
        };
        let Ok(mut out) = output.lock() else { return };
        out.extend_from_slice(&buf[..n]);
        let queries = out
            .windows(CURSOR_QUERY.len())
            .filter(|w| *w == CURSOR_QUERY)
            .count();
        drop(out);
        while answered < queries {
            let _ = file.write_all(CURSOR_ANSWER);
            answered += 1;
        }
    }
}

/// Assert that `status` is an exit with `code`, not an end by a signal.
fn assert_exit(status: ExitStatus, code: i32, why: &str) {
    assert_eq!(
        status.signal(),
        None,
        "{why}: sipnab ended by a signal: {status}"
    );
    assert_eq!(status.code(), Some(code), "{why}: {status}");
}

/// A terminal that hangs up ends the TUI, which exits 129 as a SIGHUP stop
/// does. This is the tmux-pane case: the pty is the session's controlling
/// terminal, so the kernel also sends SIGHUP.
#[test]
fn a_tui_whose_terminal_hangs_up_exits_129() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.hang_up()?;
    let status = run.wait_for_exit(test_timeout(15), "its terminal hung up")?;
    assert_exit(status, 129, "a lost terminal stops the run as SIGHUP does");
    Ok(())
}

/// The same with no SIGHUP: the pty is not the run's controlling terminal,
/// so only the terminal itself says it has gone. The TUI must notice that on
/// its own rather than rely on the signal.
#[test]
fn a_tui_notices_a_lost_terminal_without_sighup() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], false)?;
    run.wait_until_drawn()?;
    run.hang_up()?;
    let status = run.wait_for_exit(test_timeout(15), "its terminal hung up")?;
    assert_exit(status, 129, "a lost terminal stops the run as SIGHUP does");
    Ok(())
}

/// `-c` opens the same TUI filtered to calls; a lost terminal ends it too.
#[test]
fn a_calls_only_tui_whose_terminal_hangs_up_exits_129() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&["-c"], true)?;
    run.wait_until_drawn()?;
    run.hang_up()?;
    let status = run.wait_for_exit(test_timeout(15), "its terminal hung up")?;
    assert_exit(
        status,
        129,
        "a lost terminal stops the -c run as SIGHUP does",
    );
    Ok(())
}

/// SIGTERM stops a TUI whose terminal is still there, through the UI's own
/// exit path (the terminal is restored), and the run exits 0 as a SIGTERM
/// stop of a batch run does.
#[test]
fn sigterm_stops_a_tui_and_restores_the_terminal() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.signal(libc::SIGTERM)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
    assert_exit(status, 0, "SIGTERM is a graceful stop");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the TUI must restore the terminal on its way out"
    );
    Ok(())
}

/// SIGHUP with the terminal still there stops the TUI the same way, and the
/// run exits 129 (OPS-5).
#[test]
fn sighup_stops_a_tui_and_exits_129() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.signal(libc::SIGHUP)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGHUP")?;
    assert_exit(status, 129, "a SIGHUP stop exits 128 + 1");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the TUI must restore the terminal on its way out"
    );
    Ok(())
}

/// Input that crossterm leaves unread in the terminal does not make the TUI
/// spin. crossterm reads at most 1,024 bytes at a time and returns at the
/// first complete event, and its own wait is edge-triggered, so the rest
/// stays in the terminal until more input arrives. The TUI's wait is
/// level-triggered: it would report that input on every call and the loop
/// would run flat out, unless the TUI stops waiting on input crossterm did
/// not read (`terminal_input::next_interest`).
///
/// 3,000 bytes is 1,000 focus-in reports (`ESC [ I`), which the TUI ignores,
/// and fits the terminal's 4,096-byte input buffer, so the write cannot
/// block. A spinning TUI uses most of a core; an idle one draws a frame every
/// 500 ms and uses a few ticks a second.
#[test]
fn input_crossterm_leaves_unread_does_not_make_the_tui_spin() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.type_bytes(&b"\x1b[I".repeat(1_000))?;
    thread::sleep(Duration::from_secs(1));
    let before = run.cpu_ticks()?;
    thread::sleep(Duration::from_secs(3));
    let used = run.cpu_ticks()? - before;
    // SAFETY: sysconf(3) only reads a system value.
    let per_second = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })?;
    assert!(
        used < per_second,
        "the TUI used {used} ticks of CPU in 3 s with input it had not read (limit {per_second})"
    );
    run.signal(libc::SIGTERM)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
    assert_exit(status, 0, "SIGTERM is a graceful stop");
    Ok(())
}
