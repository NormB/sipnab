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
//! The last section runs the TUI with the REST API on the same harness, for
//! the web console (`--api-console`): this file holds the one pty harness the
//! ordinary suite runs.
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
    /// A stall of the reader thread, which a test asks for with
    /// [`Self::stall_reader`].
    stall: Arc<Mutex<Stall>>,
    /// The reader thread, which owns the master side.
    reader: Option<thread::JoinHandle<()>>,
    /// The master side of a separate input terminal ([`Self::spawn_split`]),
    /// held so that terminal stays open when the output terminal hangs up.
    _input: Option<OwnedFd>,
}

/// Which terminals a run gets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Terminals {
    /// One pty for standard input, output and error. With `controlling` it
    /// is the session's controlling terminal.
    One { controlling: bool },
    /// Standard input on one pty, which stays open, and standard output and
    /// error on another, which [`PtyRun::hang_up`] hangs up: the terminal
    /// the TUI draws on goes away while the one it reads stays.
    Split,
}

impl PtyRun {
    /// Start `sipnab -I sip_call.pcap <extra>` in `tests/fixtures` on a new
    /// 200x50 pty, in a new session. With `controlling` the pty becomes the
    /// session's controlling terminal, so a hang-up also sends SIGHUP, as it
    /// does to a process a terminal window or tmux pane starts; without it no
    /// SIGHUP arrives and only the terminal itself reports the hang-up.
    fn spawn(extra: &[&str], controlling: bool) -> Result<Self, TestError> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
            .args(["-I", "sip_call.pcap"])
            .args(extra)
            .env("SIPNAB_LOG", "off")
            .env("TERM", "xterm-256color");
        Self::spawn_command(cmd, controlling)
    }

    /// Start `sipnab -I sip_call.pcap` as [`Self::spawn`] does, with standard
    /// input on one pty and standard output and error on another
    /// ([`Terminals::Split`]). `home` is the run's home directory, where a
    /// crash report would be written.
    fn spawn_split(home: &std::path::Path) -> Result<Self, TestError> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
        cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
            .args(["--no-config", "-I", "sip_call.pcap"])
            .env("SIPNAB_LOG", "off")
            .env("HOME", home)
            .env_remove("XDG_STATE_HOME")
            .env("TERM", "xterm-256color");
        Self::spawn_on(cmd, Terminals::Split)
    }

    /// Start `cmd` on a new 200x50 pty, in a new session, as [`Self::spawn`]
    /// starts sipnab. The pty is its standard input, output and error.
    fn spawn_command(cmd: Command, controlling: bool) -> Result<Self, TestError> {
        Self::spawn_on(cmd, Terminals::One { controlling })
    }

    /// Start `cmd` in a new session on new 200x50 terminals, as `terminals`
    /// says.
    fn spawn_on(mut cmd: Command, terminals: Terminals) -> Result<Self, TestError> {
        let spawning = SPAWNING
            .lock()
            .map_err(|_| "a test panicked while spawning")?;
        let (master, slave) = open_pty(50, 200)?;
        // The input terminal of a split run is the session's controlling
        // terminal, so hanging the output terminal up sends no SIGHUP.
        let controlling = terminals != Terminals::One { controlling: false };
        let input = if terminals == Terminals::Split {
            let (input_master, input_slave) = open_pty(50, 200)?;
            cmd.stdin(Stdio::from(input_slave));
            Some(input_master)
        } else {
            cmd.stdin(Stdio::from(slave.try_clone()?));
            None
        };
        // Where the cursor-position answers are typed: the terminal sipnab
        // reads.
        let answers = match &input {
            Some(input) => Some(std::fs::File::from(input.try_clone()?)),
            None => None,
        };
        cmd.stdout(Stdio::from(slave.try_clone()?))
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
        let child = cmd.tied_to_test().spawn()?;
        // The parent's copies of the slave side close here, with `cmd`.
        drop(cmd);
        drop(spawning);
        let output = Arc::new(Mutex::new(Vec::new()));
        let hang_up = Arc::new(AtomicBool::new(false));
        let typed = Arc::new(Mutex::new(Vec::new()));
        let stall = Arc::new(Mutex::new(Stall::default()));
        let reader = {
            let output = Arc::clone(&output);
            let hang_up = Arc::clone(&hang_up);
            let typed = Arc::clone(&typed);
            let stall = Arc::clone(&stall);
            thread::spawn(move || {
                serve_terminal(master, answers, &output, &hang_up, &typed, &stall);
            })
        };
        Ok(PtyRun {
            child,
            output,
            hang_up,
            typed,
            stall,
            reader: Some(reader),
            _input: input,
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

    /// Make the reader thread read nothing for `period` from now, and return
    /// once it has stopped reading: a read it had already begun is over, so
    /// nothing written from here on is read before the stall ends.
    fn stall_reader(&self, period: Duration) -> Result<(), TestError> {
        let poisoned = |_| "the pty reader thread panicked";
        *self.stall.lock().map_err(poisoned)? = Stall {
            until: Some(Instant::now() + period),
            entered: false,
        };
        let deadline = Instant::now() + test_timeout(10);
        while !self.stall.lock().map_err(poisoned)?.entered {
            if Instant::now() >= deadline {
                return Err("the pty reader thread did not stall within 10 s".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
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

    /// The exit status, if sipnab ends within `within`, once everything it
    /// wrote to its terminal is in the output. A run still going at the
    /// deadline is an error, and Drop kills it.
    ///
    /// The exit alone does not say that: the reader thread reads on its own
    /// schedule, and the last bytes the child wrote (the terminal restore)
    /// can still be in the terminal when the exit is seen. The reader ends
    /// when the terminal reports that no process holds its slave side any
    /// more and nothing is left to read, so this waits for the reader.
    fn wait_for_exit(&mut self, within: Duration, after: &str) -> Result<ExitStatus, TestError> {
        let deadline = Instant::now() + within;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "sipnab was still running {} s after {after}",
                    within.as_secs()
                )
                .into());
            }
            thread::sleep(Duration::from_millis(50));
        };
        self.read_to_the_end(deadline)?;
        Ok(status)
    }

    /// Wait until the reader thread has read everything written to the
    /// terminal and ended, then join it. Nothing to do when [`Self::hang_up`]
    /// already joined it.
    fn read_to_the_end(&mut self, deadline: Instant) -> Result<(), TestError> {
        let Some(reader) = self.reader.take() else {
            return Ok(());
        };
        while !reader.is_finished() {
            if Instant::now() >= deadline {
                // Drop stops it.
                self.reader = Some(reader);
                return Err("the terminal was still open after sipnab exited".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        reader
            .join()
            .map_err(|_| "the pty reader thread panicked".into())
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

/// A stall of the reader thread: it reads nothing until `until`.
#[derive(Default)]
struct Stall {
    /// When the reader may read again; `None` for no stall.
    until: Option<Instant>,
    /// Set by the reader once it has stopped reading for this stall.
    entered: bool,
}

/// Held from `openpty` until the child is spawned. The descriptors are not
/// close-on-exec until `fcntl` marks them, and a test spawning in another
/// thread in between would hand them to its own child.
static SPAWNING: Mutex<()> = Mutex::new(());

/// Act as the terminal: collect what sipnab writes and answer its
/// cursor-position queries, until `hang_up` is set or everything written
/// to the terminal has been read; then drop the master side, which hangs
/// the terminal up.
///
/// Everything has been read when a read of the master side fails or
/// returns nothing: Linux's master side reads `EIO` once no process holds
/// the slave side open and no byte written to it is left, so that read
/// comes only after the child has exited and its output is in `output`.
///
/// The answers are typed into `answers`, the master side of a separate input
/// terminal, when there is one.
fn serve_terminal(
    master: OwnedFd,
    mut answers: Option<std::fs::File>,
    output: &Mutex<Vec<u8>>,
    hang_up: &AtomicBool,
    typed: &Mutex<Vec<u8>>,
    stall: &Mutex<Stall>,
) {
    let mut file = std::fs::File::from(master);
    let mut buf = [0u8; 4096];
    let mut answered = 0;
    while !hang_up.load(Ordering::SeqCst) {
        let rest = stall.lock().ok().and_then(|mut s| {
            let rest = s.until?.checked_duration_since(Instant::now())?;
            s.entered = true;
            Some(rest)
        });
        if let Some(rest) = rest {
            thread::sleep(rest.min(Duration::from_millis(50)));
            continue;
        }
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
        if ready <= 0 || pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            continue;
        }
        // Readable, or the slave side is closed everywhere: either way a
        // read does not block, and it returns what is left before it fails.
        let n = match file.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Ok(mut out) = output.lock() else { return };
        out.extend_from_slice(&buf[..n]);
        let queries = out
            .windows(CURSOR_QUERY.len())
            .filter(|w| *w == CURSOR_QUERY)
            .count();
        drop(out);
        while answered < queries {
            let _ = match answers.as_mut() {
                Some(input) => input.write_all(CURSOR_ANSWER),
                None => file.write_all(CURSOR_ANSWER),
            };
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

/// The crash reports under `home`, where a run started by
/// [`PtyRun::spawn_split`] writes them.
fn crash_reports(home: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(home.join(".local/state/sipnab"))
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default()
}

/// The terminal the TUI draws on hangs up while the one it reads stays
/// (TUI-LOST-OUTPUT-TERMINAL): the run ends as a hang-up, exit 129, and does
/// not panic. Before the fix the failed frame was an error of the run, the
/// ratatui Terminal was dropped, its failure to show the cursor was printed
/// with `eprintln!` to the terminal that had gone, and that panicked: exit
/// 101 and a crash report.
#[test]
fn a_tui_whose_output_terminal_hangs_up_exits_129() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let mut run = PtyRun::spawn_split(home.path())?;
    run.wait_until_drawn()?;
    run.hang_up()?;
    let status = run.wait_for_exit(test_timeout(15), "its output terminal hung up")?;
    assert_exit(status, 129, "a lost output terminal is a hang-up");
    assert_eq!(
        crash_reports(home.path()),
        Vec::<std::path::PathBuf>::new(),
        "a lost output terminal is not a crash"
    );
    Ok(())
}

/// The same with a stop signal right after the hang-up. The signal and the
/// next frame race, so the run ends as the signal's stop or as the hang-up;
/// it never panics, whichever is seen first.
#[test]
fn a_stop_signal_after_the_output_terminal_hangs_up_does_not_panic() -> Result<(), TestError> {
    for (signal, name, codes) in [
        (libc::SIGTERM, "SIGTERM", [0, 129]),
        (libc::SIGINT, "SIGINT", [0, 129]),
        (libc::SIGHUP, "SIGHUP", [129, 129]),
    ] {
        let home = tempfile::tempdir()?;
        let mut run = PtyRun::spawn_split(home.path())?;
        run.wait_until_drawn()?;
        run.hang_up()?;
        // The run may have ended on the lost terminal already.
        let _ = run.signal(signal);
        let status = run.wait_for_exit(test_timeout(15), name)?;
        assert_eq!(status.signal(), None, "{name}: ended by a signal: {status}");
        assert!(
            status.code().is_some_and(|code| codes.contains(&code)),
            "{name} after the output terminal hung up: {status}, wanted one of {codes:?}"
        );
        assert_eq!(
            crash_reports(home.path()),
            Vec::<std::path::PathBuf>::new(),
            "{name} after the output terminal hung up is not a crash"
        );
    }
    Ok(())
}

/// A split run whose terminals both stay is an ordinary run: SIGTERM stops
/// it with exit 0 and the terminal restored. This holds the harness: the
/// answers typed on the input terminal reach the TUI, and what it draws is
/// read from the output terminal.
#[test]
fn sigterm_stops_a_tui_on_split_terminals_and_restores_the_output() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let mut run = PtyRun::spawn_split(home.path())?;
    run.wait_until_drawn()?;
    run.signal(libc::SIGTERM)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
    assert_exit(status, 0, "SIGTERM is a graceful stop");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the TUI must restore the output terminal on its way out"
    );
    assert_eq!(
        crash_reports(home.path()),
        Vec::<std::path::PathBuf>::new(),
        "a SIGTERM stop is not a crash"
    );
    Ok(())
}

/// A page of the repository with each run of white space as one space, so a
/// sentence is found wherever the page wraps it.
fn page_text(page: &str) -> Result<String, TestError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(page);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The service page states what the tests above hold: a run on two terminals
/// that loses either one exits 129.
#[test]
fn the_service_page_states_the_exit_for_either_lost_terminal() -> Result<(), TestError> {
    let page = page_text("docs/run-as-a-service.md")?;
    for sentence in [
        "sipnab stops as it does for `SIGHUP` and exits 129, whether or not the signal arrives.",
        "A run that reads one terminal and draws on another (standard output redirected to a \
         second terminal) stops the same way and exits 129 when either of the two goes away.",
    ] {
        assert!(
            page.contains(sentence),
            "docs/run-as-a-service.md must state: {sentence}"
        );
    }
    Ok(())
}

/// The two exit-code tables give 129 to a lost terminal, and do not name
/// which terminal: the row covers the one the run reads and the one it draws
/// on.
#[test]
fn the_exit_code_tables_give_129_to_a_lost_terminal() -> Result<(), TestError> {
    for (page, row) in [
        (
            "docs/cli-reference.md",
            "| `129` | Stopped by `SIGHUP`, or the terminal of a terminal interface run went away.",
        ),
        (
            "docs/errors.md",
            "| `129` | `SIGHUP` stopped the run, or the terminal of a terminal interface run went away.",
        ),
    ] {
        assert!(
            page_text(page)?.contains(row),
            "{page} must hold the exit-code row that begins: {row}"
        );
    }
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

// ── What the TUI wrote before it exited is read before it is checked ──
//
// `wait_for_exit` returns once the child has ended. The reader thread reads
// the terminal on its own schedule, and on a loaded host it can run after
// the test has seen the exit and asked whether the restore was written: the
// bytes are in the terminal, not yet in `output`. These tests stall the
// reader across the exit, which is that order made certain.

/// How long the stalled reader reads nothing: longer than a TUI takes to
/// exit after a stop signal (at most 0.31 s from the signal to the exit
/// seen, measured over 740 runs at a load average up to 64 on 14 cores).
const READER_STALL: Duration = Duration::from_secs(3);

/// SIGTERM's restore is seen when the reader runs only after the exit.
#[test]
fn sigterm_restore_is_seen_when_the_reader_lags_the_exit() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.stall_reader(READER_STALL)?;
    run.signal(libc::SIGTERM)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
    assert_exit(status, 0, "SIGTERM is a graceful stop");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the restore the TUI wrote before it exited must be read before the check"
    );
    Ok(())
}

/// The same for SIGHUP, which exits 129.
#[test]
fn sighup_restore_is_seen_when_the_reader_lags_the_exit() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.stall_reader(READER_STALL)?;
    run.signal(libc::SIGHUP)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGHUP")?;
    assert_exit(status, 129, "a SIGHUP stop exits 128 + 1");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the restore the TUI wrote before it exited must be read before the check"
    );
    Ok(())
}

/// SIGINT stops the TUI as SIGTERM does, exiting 0 with the terminal
/// restored, with the reader stalled across the exit.
#[test]
fn sigint_stops_a_tui_and_restores_the_terminal() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&[], true)?;
    run.wait_until_drawn()?;
    run.stall_reader(READER_STALL)?;
    run.signal(libc::SIGINT)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGINT")?;
    assert_exit(status, 0, "SIGINT is a graceful stop");
    assert!(
        run.wrote(LEAVE_ALTERNATE_SCREEN),
        "the TUI must restore the terminal on its way out"
    );
    Ok(())
}

/// The harness itself, with a child that is not sipnab: a few bytes written
/// just before the child exits are in the output once `wait_for_exit`
/// returns, though the reader read nothing until after the exit.
#[test]
fn the_last_bytes_before_an_exit_are_read() -> Result<(), TestError> {
    let mut cmd = Command::new("printf");
    cmd.arg("last-bytes-before-exit");
    let mut run = PtyRun::spawn_command(cmd, true)?;
    run.stall_reader(READER_STALL)?;
    let status = run.wait_for_exit(test_timeout(15), "printf")?;
    assert_exit(status, 0, "printf succeeds");
    assert!(
        run.wrote(b"last-bytes-before-exit"),
        "what the child wrote before it exited must be read"
    );
    Ok(())
}

/// More output than the terminal holds arrives whole: 300,000 bytes, then
/// a marker. The child blocks until the reader reads, so most of it is read
/// while the child runs, and the rest after it exits.
#[test]
fn output_larger_than_the_terminal_buffer_is_read_whole() -> Result<(), TestError> {
    const BYTES: usize = 300_000;
    let mut cmd = Command::new("sh");
    cmd.args([
        "-c",
        "head -c 300000 /dev/zero | tr '\\000' x; printf end-of-output",
    ]);
    let mut run = PtyRun::spawn_command(cmd, true)?;
    run.stall_reader(Duration::from_secs(1))?;
    let status = run.wait_for_exit(test_timeout(30), "sh")?;
    assert_exit(status, 0, "the shell succeeds");
    let out = run.output.lock().map(|o| o.clone()).unwrap_or_default();
    let xs = out.iter().filter(|b| **b == b'x').count();
    assert_eq!(xs, BYTES, "every byte the child wrote is read");
    assert!(
        out.ends_with(b"end-of-output"),
        "the marker written last is read last"
    );
    Ok(())
}

/// A child that writes nothing ends the reader too: `wait_for_exit` returns
/// with the status and an empty output, and does not wait for bytes that
/// never come.
#[test]
fn a_child_that_writes_nothing_is_waited_for_without_output() -> Result<(), TestError> {
    let mut run = PtyRun::spawn_command(Command::new("true"), true)?;
    let status = run.wait_for_exit(test_timeout(15), "true")?;
    assert_exit(status, 0, "true succeeds");
    let out = run.output.lock().map(|o| o.clone()).unwrap_or_default();
    assert!(out.is_empty(), "nothing was written: {out:?}");
    Ok(())
}

// ── The web console on a TUI run ─────────────────────────────────────────
//
// The harness above is the one way this suite runs the real TUI, so the
// console's TUI wiring is checked here: the REST API a TUI run starts serves
// the console when asked to, and a TUI run without the API refuses it.

/// What the TUI writes when it enters the alternate screen.
#[cfg(feature = "api")]
const ENTER_ALTERNATE_SCREEN: &[u8] = b"\x1b[?1049h";

/// A TUI run with the REST API on a port the system picks, logging at `info`
/// so the bound address is written to the terminal.
#[cfg(feature = "api")]
fn spawn_with_api(extra: &[&str]) -> Result<PtyRun, TestError> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
        .args(["--no-config", "-I", "sip_call.pcap", "--api", "127.0.0.1:0"])
        .args(extra)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .env("TERM", "xterm-256color");
    PtyRun::spawn_command(cmd, true)
}

/// The port of the REST API `run` started, read from its log line.
#[cfg(feature = "api")]
fn api_port(run: &mut PtyRun) -> Result<u16, TestError> {
    const LINE: &[u8] = b"REST API listening on 127.0.0.1:";
    let deadline = Instant::now() + test_timeout(60);
    loop {
        let out = run.output.lock().map(|o| o.clone()).unwrap_or_default();
        if let Some(at) = out.windows(LINE.len()).position(|w| w == LINE) {
            let digits: Vec<u8> = out[at + LINE.len()..]
                .iter()
                .copied()
                .take_while(u8::is_ascii_digit)
                .collect();
            // The line is whole once something follows the digits.
            if out.len() > at + LINE.len() + digits.len() && !digits.is_empty() {
                return Ok(std::str::from_utf8(&digits)?.parse()?);
            }
        }
        if let Some(status) = run.child.try_wait()? {
            return Err(format!("sipnab ended before the API listened: {status}").into());
        }
        if Instant::now() >= deadline {
            return Err("the REST API did not report its address within 60 s".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// The status code of `GET path` on the loopback `port`.
#[cfg(feature = "api")]
fn get_status(port: u16, path: &str) -> Result<u16, TestError> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(test_timeout(30)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let code = answer.split_whitespace().nth(1).ok_or("no status line")?;
    Ok(code.parse()?)
}

/// A TUI run with `--api --api-console` serves the console page.
#[cfg(feature = "api")]
#[test]
fn a_tui_with_the_api_serves_the_console_when_asked() -> Result<(), TestError> {
    let mut run = spawn_with_api(&["--api-console"])?;
    let port = api_port(&mut run)?;
    assert_eq!(
        get_status(port, "/console/")?,
        200,
        "the TUI's REST API serves the console page"
    );
    assert_eq!(
        get_status(port, "/health")?,
        200,
        "the API answers beside the console"
    );
    run.signal(libc::SIGTERM)?;
    let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
    assert_exit(status, 0, "SIGTERM is a graceful stop");
    Ok(())
}

/// A TUI run with `--api` and no console has no console path, and
/// `--api-console=false` is the same.
#[cfg(feature = "api")]
#[test]
fn a_tui_with_the_api_has_no_console_unless_asked() -> Result<(), TestError> {
    for extra in [&[][..], &["--api-console=false"]] {
        let mut run = spawn_with_api(extra)?;
        let port = api_port(&mut run)?;
        assert_eq!(get_status(port, "/console/")?, 404, "{extra:?}");
        assert_eq!(get_status(port, "/health")?, 200, "{extra:?}");
        run.signal(libc::SIGTERM)?;
        let status = run.wait_for_exit(test_timeout(15), "SIGTERM")?;
        assert_exit(status, 0, "SIGTERM is a graceful stop");
    }
    Ok(())
}

/// A TUI run that turns the console on with no `--api` is refused with exit
/// 2 before the screen is taken: the message is on the terminal as plain
/// text, and the alternate screen was never entered.
#[cfg(feature = "api")]
#[test]
fn a_tui_without_the_api_refuses_the_console_before_it_draws() -> Result<(), TestError> {
    let mut run = PtyRun::spawn(&["--no-config", "--api-console"], true)?;
    let status = run.wait_for_exit(test_timeout(60), "the refusal")?;
    assert_exit(status, 2, "the console without the API is invalid usage");
    assert!(
        run.wrote(b"--api-console needs the REST API"),
        "the refusal is on the terminal"
    );
    assert!(run.wrote(b"Add --api ADDR"), "it says what to add");
    assert!(
        !run.wrote(ENTER_ALTERNATE_SCREEN),
        "the screen was taken before the refusal"
    );
    Ok(())
}

include!("support/child_lifetime.rs");
