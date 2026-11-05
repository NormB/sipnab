// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Waiting for terminal input without crossterm's wait, so that a terminal
//! that goes away ends the TUI (TUI-LOST-TERMINAL-SPIN).
//!
//! crossterm 0.29's Unix event source reads the terminal in a loop that ends
//! only on `WouldBlock`. A hung-up terminal never says `WouldBlock`: a read
//! returns end-of-file (or `EIO`) every time, so the loop never returns and
//! the process spins in a busy loop, deaf to the stop flag the signal handlers
//! set. Until 0.5.234 SIGHUP's default action ended the process before that
//! loop was reached; since OPS-5 made SIGHUP a graceful stop, nothing did.
//!
//! So the TUI waits on the terminal itself, with `poll(2)`, which reports a
//! hang-up as `POLLHUP` (or `POLLERR`/`POLLNVAL`), and calls crossterm only to
//! read input this wait has just seen, never to wait. It checks for a hang-up
//! again before every crossterm read. A hang-up that lands between that check
//! and crossterm's read of the same event, a window of a few microseconds
//! while input is pending, still reaches crossterm's loop; only a change to
//! crossterm's event source can close it.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, RawFd};
use std::time::Duration;

/// What one wait on the terminal found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    /// The terminal has input to read.
    Input,
    /// Nothing happened before the timeout, or a signal interrupted the wait.
    Idle,
    /// The terminal has gone: hung up, failed, or closed.
    Gone,
}

/// What the next wait waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Interest {
    /// Input or a hang-up, whichever comes first.
    Input,
    /// A hang-up only, for the full timeout. Only one `poll(2)` reports
    /// (`POLLHUP` on Linux); macOS's shows at the next [`TerminalInput::gone`].
    HangupOnly,
}

/// The [`Wait`] that `poll(2)`'s `revents` for the terminal mean, with
/// `queued`, the bytes `FIONREAD` reports waiting (`None` when it fails).
/// Pure.
///
/// A hang-up wins over input: a hung-up terminal reports `POLLIN` as well
/// (its reads return end-of-file at once), and reading it is what spins.
/// Linux reports the hang-up as `POLLHUP`. macOS does not: its hung-up
/// terminal is only readable, with nothing to read. A raw-mode terminal is
/// readable only once a byte is queued, so readable with none queued, or
/// with a queue that cannot be read, is end-of-file: the terminal has gone.
pub(crate) fn classify(revents: libc::c_short, queued: Option<libc::c_int>) -> Wait {
    if revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        Wait::Gone
    } else if revents & libc::POLLIN != 0 {
        match queued {
            Some(n) if n > 0 => Wait::Input,
            _ => Wait::Gone,
        }
    } else {
        Wait::Idle
    }
}

/// What the wait after this one waits for, given what this wait found and
/// whether crossterm then produced an event. Pure.
///
/// `poll(2)` is level-triggered and crossterm's own wait is edge-triggered,
/// and crossterm can leave bytes in the terminal that it reads only after
/// more arrive (it stops reading at the first complete event). Input this
/// wait saw that crossterm did not turn into an event would make every
/// following wait return at once, and the loop would spin. So after such a
/// wait the next one watches for a hang-up only, for its full timeout, and
/// crossterm is asked again when it ends.
pub(crate) fn next_interest(found: Wait, crossterm_had_events: bool) -> Interest {
    if found == Wait::Input && !crossterm_had_events {
        Interest::HangupOnly
    } else {
        Interest::Input
    }
}

/// How a TUI run ended, from what its event loop returned and whether the
/// terminal has gone: the result to return, and whether the run was hung up.
/// Pure but for calling `gone`, which is called only for an error.
///
/// `Ok(true)` is the loop's own report of a lost terminal. An error with the
/// terminal gone is the same thing seen through a failed read or write (a
/// frame drawn to a hung-up terminal fails with `EIO`), so it is a hang-up
/// too, not a failure of the run. Any other error stays an error.
pub(crate) fn settle<E>(
    outcome: Result<bool, E>,
    gone: impl FnOnce() -> bool,
) -> (Result<(), E>, bool) {
    match outcome {
        Ok(lost) => (Ok(()), lost),
        Err(_) if gone() => (Ok(()), true),
        Err(e) => (Err(e), false),
    }
}

/// The terminal crossterm reads input from, for waiting on.
pub(crate) struct TerminalInput {
    /// The descriptor polled: standard input, or the opened `/dev/tty`.
    fd: RawFd,
    /// The `/dev/tty` this opened, held open while it is polled.
    _tty: Option<File>,
}

impl TerminalInput {
    /// The terminal crossterm reads: standard input when it is a terminal,
    /// else `/dev/tty`. The same rule as crossterm's `tty_fd`, so the
    /// descriptor waited on is the terminal crossterm reads.
    ///
    /// # Errors
    ///
    /// Opening `/dev/tty` failed.
    pub(crate) fn open() -> io::Result<Self> {
        // SAFETY: isatty(3) only inspects the descriptor.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
            return Ok(TerminalInput {
                fd: libc::STDIN_FILENO,
                _tty: None,
            });
        }
        let tty = File::options().read(true).write(true).open("/dev/tty")?;
        Ok(TerminalInput {
            fd: tty.as_raw_fd(),
            _tty: Some(tty),
        })
    }

    /// Wait up to `timeout` for what `interest` names.
    ///
    /// # Errors
    ///
    /// `poll(2)` failed for a reason other than a signal.
    pub(crate) fn wait(&self, timeout: Duration, interest: Interest) -> io::Result<Wait> {
        let events = match interest {
            Interest::Input => libc::POLLIN,
            // POLLHUP, POLLERR and POLLNVAL are reported whatever `events` asks.
            Interest::HangupOnly => 0,
        };
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events,
            revents: 0,
        };
        let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `pfd` is one valid pollfd for a descriptor this value keeps
        // open.
        let ready = unsafe { libc::poll(&mut pfd, 1, millis) };
        if ready < 0 {
            let e = io::Error::last_os_error();
            // A signal: the caller checks the stop flag before waiting again.
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(Wait::Idle);
            }
            return Err(e);
        }
        let queued = (pfd.revents & libc::POLLIN != 0)
            .then(|| self.queued())
            .flatten();
        Ok(classify(pfd.revents, queued))
    }

    /// The bytes waiting to be read (`FIONREAD`), or `None` when the terminal
    /// will not say.
    fn queued(&self) -> Option<libc::c_int> {
        let mut n: libc::c_int = 0;
        // SAFETY: FIONREAD writes one c_int through the pointer, which points
        // at `n`; the descriptor is open while `self` is.
        let rc = unsafe { libc::ioctl(self.fd, libc::FIONREAD, &mut n) };
        (rc == 0).then_some(n)
    }

    /// Whether the terminal has gone, without waiting.
    ///
    /// # Errors
    ///
    /// `poll(2)` failed for a reason other than a signal.
    pub(crate) fn gone(&self) -> io::Result<bool> {
        // Interest in input too: macOS reports a hang-up only as readable
        // with nothing queued.
        Ok(self.wait(Duration::ZERO, Interest::Input)? == Wait::Gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hang-up, an error and a closed descriptor each mean the terminal has
    /// gone, also when input is reported with them.
    #[test]
    fn a_hang_up_wins_over_input() {
        for gone in [libc::POLLHUP, libc::POLLERR, libc::POLLNVAL] {
            assert_eq!(classify(gone, None), Wait::Gone, "{gone:#x}");
            assert_eq!(
                classify(gone | libc::POLLIN, Some(3)),
                Wait::Gone,
                "{gone:#x}|POLLIN with input queued"
            );
        }
    }

    /// Readable with nothing queued is end-of-file: the terminal has gone.
    /// macOS reports a hung-up terminal this way, with no POLLHUP. A queue
    /// that cannot be read (Linux answers EIO on a hung-up terminal) is the
    /// same.
    #[test]
    fn readable_with_nothing_queued_is_a_hang_up() {
        assert_eq!(classify(libc::POLLIN, Some(0)), Wait::Gone, "end-of-file");
        assert_eq!(classify(libc::POLLIN, None), Wait::Gone, "no queue to read");
    }

    /// Input with bytes queued is input, and nothing is idle.
    #[test]
    fn input_and_nothing() {
        assert_eq!(
            classify(libc::POLLIN, Some(1)),
            Wait::Input,
            "bytes queued are input"
        );
        assert_eq!(classify(0, None), Wait::Idle, "no event is idle");
        assert_eq!(
            classify(libc::POLLOUT, None),
            Wait::Idle,
            "writable is not input"
        );
    }

    /// Input crossterm turned into no event makes the next wait watch for a
    /// hang-up only; every other outcome waits for input again.
    #[test]
    fn input_crossterm_did_not_read_is_not_waited_on_again() {
        let cases = [
            (Wait::Input, false, Interest::HangupOnly),
            (Wait::Input, true, Interest::Input),
            (Wait::Idle, false, Interest::Input),
            (Wait::Idle, true, Interest::Input),
        ];
        for (found, had_events, want) in cases {
            assert_eq!(
                next_interest(found, had_events),
                want,
                "after {found:?} with crossterm events {had_events}"
            );
        }
    }

    /// A lost terminal, reported or seen through a failed write, is a
    /// hang-up; an error with the terminal there stays an error. Whether the
    /// terminal has gone is asked only for an error.
    #[test]
    fn a_failure_on_a_gone_terminal_is_a_hang_up() {
        /// One case: what the loop returned and whether the terminal has
        /// gone, then what `settle` must give and whether it asks.
        struct Case {
            outcome: Result<bool, &'static str>,
            gone: bool,
            want: Result<(), &'static str>,
            want_hung_up: bool,
            want_asked: bool,
        }
        let cases = [
            Case {
                outcome: Ok(true),
                gone: false,
                want: Ok(()),
                want_hung_up: true,
                want_asked: false,
            },
            Case {
                outcome: Ok(false),
                gone: true,
                want: Ok(()),
                want_hung_up: false,
                want_asked: false,
            },
            Case {
                outcome: Err("EIO"),
                gone: true,
                want: Ok(()),
                want_hung_up: true,
                want_asked: true,
            },
            Case {
                outcome: Err("EINVAL"),
                gone: false,
                want: Err("EINVAL"),
                want_hung_up: false,
                want_asked: true,
            },
        ];
        for case in cases {
            let asked = std::cell::Cell::new(false);
            let got = settle(case.outcome, || {
                asked.set(true);
                case.gone
            });
            assert_eq!(
                got,
                (case.want, case.want_hung_up),
                "outcome {:?} with the terminal gone: {}",
                case.outcome,
                case.gone
            );
            assert_eq!(
                asked.get(),
                case.want_asked,
                "whether the terminal was asked about, for {:?}",
                case.outcome
            );
        }
    }

    /// The real descriptor: a pty whose master side closes reads as gone,
    /// and one that is open and quiet reads as idle; written input reads as
    /// input.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pty_reports_input_and_its_hang_up() -> io::Result<()> {
        use std::io::Write as _;
        use std::os::fd::{FromRawFd as _, OwnedFd};
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        // SAFETY: openpty(3) writes two descriptors into the out-parameters;
        // the other pointers may be null.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openpty succeeded; this test owns both descriptors.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let input = TerminalInput {
            fd: slave.as_raw_fd(),
            _tty: None,
        };
        assert_eq!(
            input.wait(Duration::ZERO, Interest::Input)?,
            Wait::Idle,
            "an open, quiet pty is idle"
        );
        let mut master = File::from(master);
        master.write_all(b"x\n")?;
        assert_eq!(
            input.wait(Duration::from_secs(5), Interest::Input)?,
            Wait::Input,
            "written bytes are input"
        );
        assert_eq!(
            input.wait(Duration::ZERO, Interest::HangupOnly)?,
            Wait::Idle,
            "pending input does not end a hang-up-only wait"
        );
        assert!(!input.gone()?, "an open pty has not gone");
        drop(master);
        assert!(input.gone()?, "a closed master is a hang-up");
        assert_eq!(
            input.wait(Duration::from_secs(5), Interest::Input)?,
            Wait::Gone,
            "a hang-up wins over the pending input"
        );
        Ok(())
    }
}
