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
//!
//! The end of a run is here too (TUI-LOST-OUTPUT-TERMINAL): [`output_gone`]
//! asks the terminal the TUI draws on, which can be another one than it
//! reads, and [`release`] gives up the ratatui `Terminal` without letting its
//! Drop print to a terminal that has gone.

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

/// Whether the terminal or pipe behind `fd`, a descriptor the TUI writes to,
/// has gone: hung up, failed, or closed. Does not wait.
///
/// The TUI can read one terminal and draw on another (standard input a
/// terminal, standard output redirected to a second one), and
/// [`TerminalInput::gone`] asks only the one it reads. A platform that
/// reports neither a hung-up terminal nor a pipe with no reader answers
/// `false`, and [`release`] still keeps the run from panicking.
///
/// The question asked is "can this be written": macOS reports a hang-up only
/// for an event that was asked for, and reported none for a pipe with no
/// reader when no event was asked (CI's macOS run of 2026-11-12). Linux
/// reports a hang-up whatever is asked.
///
/// # Errors
///
/// `poll(2)` failed for a reason other than a signal.
pub(crate) fn output_gone(fd: RawFd) -> io::Result<bool> {
    let revents = crate::input_wait::poll_one(fd, libc::POLLOUT, Duration::ZERO)?;
    Ok(output_has_gone(revents))
}

/// Whether what `poll(2)` reported for a descriptor asked "can this be
/// written" says it has gone. Pure. Writable is not gone, and nor is a full
/// pipe, which reports nothing.
pub(crate) fn output_has_gone(revents: libc::c_short) -> bool {
    revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Give up a ratatui `Terminal` at the end of a run: `true` when its cursor
/// could be shown again, `false` when it could not.
///
/// ratatui's `Terminal` shows the cursor when it drops and reports a failure
/// with `eprintln!`, which panics when standard error cannot be written: the
/// terminal that has gone is usually standard error too. So the cursor is
/// shown here, where a failure is a value, and a `Terminal` whose cursor
/// cannot be shown is not dropped: nothing can be shown on that terminal.
pub(crate) fn release<B: ratatui::backend::Backend>(mut terminal: ratatui::Terminal<B>) -> bool {
    // A shown cursor is recorded in the Terminal, so its Drop writes nothing.
    let shown = terminal.show_cursor().is_ok();
    if !shown {
        std::mem::forget(terminal);
    }
    shown
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
            // Linux reports POLLHUP, POLLERR and POLLNVAL whatever `events`
            // asks. macOS may not (see `output_gone`): there this wait can
            // run to its timeout, and the `Input` wait after it sees the
            // hang-up.
            Interest::HangupOnly => 0,
        };
        // A signal reads as nothing happened (0, so `Idle`): the caller
        // checks the stop flag before waiting again.
        let revents = crate::input_wait::poll_one(self.fd, events, timeout)?;
        let queued = (revents & libc::POLLIN != 0)
            .then(|| self.queued())
            .flatten();
        Ok(classify(revents, queued))
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

    /// What a [`Probe`] backend saw, shared with the test that made it.
    #[derive(Default)]
    struct Seen {
        /// Calls of `show_cursor`.
        shows: std::cell::Cell<u32>,
        /// Whether the backend was dropped.
        dropped: std::cell::Cell<bool>,
    }

    /// A backend whose `show_cursor` fails when `broken`, as a write to a
    /// terminal that has gone does; everything else succeeds and does nothing.
    struct Probe {
        broken: bool,
        seen: std::rc::Rc<Seen>,
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            self.seen.dropped.set(true);
        }
    }

    impl ratatui::backend::Backend for Probe {
        type Error = io::Error;

        fn draw<'a, I>(&mut self, _content: I) -> io::Result<()>
        where
            I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
        {
            Ok(())
        }

        fn hide_cursor(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn show_cursor(&mut self) -> io::Result<()> {
            self.seen.shows.set(self.seen.shows.get() + 1);
            if self.broken {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        }

        fn get_cursor_position(&mut self) -> io::Result<ratatui::layout::Position> {
            Ok(ratatui::layout::Position::ORIGIN)
        }

        fn set_cursor_position<P: Into<ratatui::layout::Position>>(
            &mut self,
            _position: P,
        ) -> io::Result<()> {
            Ok(())
        }

        fn clear(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn clear_region(&mut self, _clear_type: ratatui::backend::ClearType) -> io::Result<()> {
            Ok(())
        }

        fn size(&self) -> io::Result<ratatui::layout::Size> {
            Ok(ratatui::layout::Size::new(80, 24))
        }

        fn window_size(&mut self) -> io::Result<ratatui::backend::WindowSize> {
            Ok(ratatui::backend::WindowSize {
                columns_rows: ratatui::layout::Size::new(80, 24),
                pixels: ratatui::layout::Size::new(0, 0),
            })
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A ratatui Terminal on a [`Probe`], with the cursor hidden when
    /// `hidden`, as a run that has drawn a frame leaves it.
    fn probe_terminal(
        broken: bool,
        hidden: bool,
    ) -> io::Result<(ratatui::Terminal<Probe>, std::rc::Rc<Seen>)> {
        let seen = std::rc::Rc::new(Seen::default());
        let mut terminal = ratatui::Terminal::new(Probe {
            broken,
            seen: std::rc::Rc::clone(&seen),
        })?;
        if hidden {
            terminal.hide_cursor()?;
        }
        Ok((terminal, seen))
    }

    /// A Terminal whose cursor cannot be shown is not dropped: ratatui's
    /// Drop would try again and print the failure with `eprintln!`, which
    /// panics when standard error is the terminal that has gone
    /// (TUI-LOST-OUTPUT-TERMINAL). The cursor is asked for once.
    #[test]
    fn a_terminal_whose_cursor_cannot_be_shown_is_not_dropped() -> io::Result<()> {
        let (terminal, seen) = probe_terminal(true, true)?;
        assert!(!release(terminal), "the cursor could not be shown");
        assert_eq!(
            seen.shows.get(),
            1,
            "the cursor is asked for once, not again by ratatui's Drop"
        );
        assert!(
            !seen.dropped.get(),
            "a Terminal on a gone terminal must not be dropped"
        );
        Ok(())
    }

    /// The same when no frame hid the cursor: the release still asks once,
    /// finds the terminal gone, and does not drop it.
    #[test]
    fn a_gone_terminal_that_never_hid_its_cursor_is_not_dropped() -> io::Result<()> {
        let (terminal, seen) = probe_terminal(true, false)?;
        assert!(!release(terminal), "the cursor could not be shown");
        assert_eq!(seen.shows.get(), 1, "asked once");
        assert!(!seen.dropped.get(), "not dropped");
        Ok(())
    }

    /// A Terminal that is still there has its cursor shown once and is
    /// dropped: ratatui's Drop finds the cursor shown and writes nothing.
    #[test]
    fn a_terminal_that_is_there_is_shown_its_cursor_and_dropped() -> io::Result<()> {
        for hidden in [true, false] {
            let (terminal, seen) = probe_terminal(false, hidden)?;
            assert!(release(terminal), "the cursor was shown (hidden: {hidden})");
            assert_eq!(
                seen.shows.get(),
                1,
                "the cursor is shown once (hidden: {hidden})"
            );
            assert!(
                seen.dropped.get(),
                "a Terminal that is there is dropped (hidden: {hidden})"
            );
        }
        Ok(())
    }

    /// A pipe nobody reads has gone for a writer, and one with a reader has
    /// not; nor has a device that takes every write.
    #[test]
    fn an_output_with_no_reader_has_gone() -> io::Result<()> {
        let (reader, writer) = io::pipe()?;
        assert!(
            !output_gone(writer.as_raw_fd())?,
            "a pipe with a reader has not gone"
        );
        drop(reader);
        assert!(
            output_gone(writer.as_raw_fd())?,
            "a pipe with no reader has gone"
        );
        let file = File::options().write(true).open("/dev/null")?;
        assert!(!output_gone(file.as_raw_fd())?, "/dev/null has not gone");
        Ok(())
    }

    /// What `poll(2)` reported for an output: a hang-up, an error or a
    /// closed descriptor is gone, alone or with "writable"; writable,
    /// nothing (a full pipe) and readable are not.
    #[test]
    fn what_poll_reported_for_an_output_is_read() {
        for (revents, gone, what) in [
            (libc::POLLHUP, true, "hung up"),
            (libc::POLLERR, true, "failed"),
            (libc::POLLNVAL, true, "not open"),
            (libc::POLLOUT | libc::POLLHUP, true, "writable and hung up"),
            (libc::POLLOUT | libc::POLLERR, true, "writable and failed"),
            (libc::POLLOUT, false, "writable"),
            (0, false, "nothing reported"),
            (libc::POLLIN, false, "readable"),
        ] {
            assert_eq!(output_has_gone(revents), gone, "{what}");
        }
    }

    /// A pipe that is full and has a reader has not gone: it cannot be
    /// written now, which is not a hang-up. It has gone once its reader has.
    #[test]
    fn a_full_pipe_with_a_reader_has_not_gone() -> io::Result<()> {
        use std::io::Write as _;
        let (reader, mut writer) = io::pipe()?;
        // Fill it without a write that waits: while the pipe reports
        // "writable", a write of no more than PIPE_BUF (at least 512 bytes
        // by POSIX) is taken whole at once.
        let block = [0u8; 512];
        let mut written = 0usize;
        while crate::input_wait::poll_one(writer.as_raw_fd(), libc::POLLOUT, Duration::ZERO)?
            & libc::POLLOUT
            != 0
        {
            writer.write_all(&block)?;
            written += block.len();
            assert!(written <= 64 << 20, "the pipe took 64 MiB and is not full");
        }
        assert!(written > 0, "an empty pipe must report writable");
        assert!(
            !output_gone(writer.as_raw_fd())?,
            "a full pipe with a reader has not gone"
        );
        drop(reader);
        assert!(
            output_gone(writer.as_raw_fd())?,
            "a full pipe with no reader has gone"
        );
        Ok(())
    }

    /// Wait for what `interest` names for up to 5 s, waiting again after an
    /// `Idle`. `wait` reports a signal that interrupts `poll(2)` as `Idle`,
    /// so one wait can end early with nothing seen; a pre-commit run of the
    /// whole library test binary on 2026-11-05 saw one such `Idle` here.
    #[cfg(target_os = "linux")]
    fn wait_past_idle(input: &TerminalInput, interest: Interest) -> io::Result<Wait> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let found = input.wait(left, interest)?;
            if found != Wait::Idle || left.is_zero() {
                return Ok(found);
            }
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
            wait_past_idle(&input, Interest::Input)?,
            Wait::Input,
            "written bytes are input"
        );
        assert_eq!(
            input.wait(Duration::ZERO, Interest::HangupOnly)?,
            Wait::Idle,
            "pending input does not end a hang-up-only wait"
        );
        assert!(!input.gone()?, "an open pty has not gone");
        assert!(
            !output_gone(slave.as_raw_fd())?,
            "an open pty has not gone for its writer"
        );
        drop(master);
        assert!(input.gone()?, "a closed master is a hang-up");
        assert!(
            output_gone(slave.as_raw_fd())?,
            "a closed master is a hang-up for the writer too"
        );
        assert_eq!(
            wait_past_idle(&input, Interest::Input)?,
            Wait::Gone,
            "a hang-up wins over the pending input"
        );
        Ok(())
    }
}
