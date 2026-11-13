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
    /// A hang-up only: input that is queued does not end the wait.
    HangupOnly,
}

/// The events a wait for `interest` asks `poll(2)` for. Pure.
///
/// The hang-up-only wait asks for POLLHUP, not for nothing. Linux reports
/// POLLHUP, POLLERR and POLLNVAL whatever is asked. macOS reports a hang-up
/// only to a wait that asked for an event: for a pty whose other side had
/// closed it answered nothing when no event was asked and POLLHUP when
/// POLLHUP was (CI's macOS run of 2026-11-13), so a wait that asked nothing
/// ran to its timeout on a terminal that had gone. On both, a wait that asks
/// POLLHUP is not ended by input that is queued.
pub(crate) fn requested(interest: Interest) -> libc::c_short {
    match interest {
        Interest::Input => libc::POLLIN,
        Interest::HangupOnly => libc::POLLHUP,
    }
}

/// The [`Wait`] that `poll(2)`'s `revents` for the terminal mean, with
/// `queued`, the bytes `FIONREAD` reports waiting (`None` when it fails).
/// Pure.
///
/// A hang-up wins over input: a hung-up terminal reports `POLLIN` as well
/// (its reads return end-of-file at once), and reading it is what spins.
/// Linux reports the hang-up as `POLLHUP` and `POLLERR`, and macOS as
/// `POLLHUP` with `POLLIN` when input was asked for (CI's macOS run of
/// 2026-11-13, a pty whose other side had closed). A terminal that is only
/// readable with nothing to read has gone too: a raw-mode terminal is
/// readable only once a byte is queued, so readable with none queued, or
/// with a queue that cannot be read, is end-of-file.
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
/// has gone: hung up or failed. Does not wait.
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
///
/// POLLNVAL is not gone either: it says that `poll` cannot judge the
/// descriptor (it is closed, or it is a device `poll` does not serve on that
/// platform), not that a terminal hung up. On macOS the question asked of
/// `/dev/null` was answered "gone" while POLLNVAL counted (CI's macOS run of
/// 2026-11-12). The caller asks only after a read or a write failed, and a
/// failure with no hang-up reported stays an error of the run.
pub(crate) fn output_has_gone(revents: libc::c_short) -> bool {
    revents & (libc::POLLHUP | libc::POLLERR) != 0
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
        // A signal reads as nothing happened (0, so `Idle`): the caller
        // checks the stop flag before waiting again.
        let revents = crate::input_wait::poll_one(self.fd, requested(interest), timeout)?;
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
        // Interest in input too: a terminal that is readable with nothing
        // queued has gone, and only a wait that asks for input sees that.
        Ok(self.wait(Duration::ZERO, Interest::Input)? == Wait::Gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each wait asks `poll(2)` for an event. macOS reports a hang-up only
    /// to a wait that asked for one: its pty with a closed master answered
    /// nothing when no event was asked and POLLHUP when POLLHUP was (CI's
    /// macOS run of 2026-11-13). A wait that asks POLLHUP does not end on
    /// queued input on either platform, which the pty tests below measure.
    #[test]
    fn every_wait_asks_poll_for_an_event() {
        assert_eq!(
            requested(Interest::HangupOnly),
            libc::POLLHUP,
            "the hang-up-only wait asks for the hang-up"
        );
        assert_eq!(
            requested(Interest::Input),
            libc::POLLIN,
            "the wait for input asks for input"
        );
        assert_eq!(
            requested(Interest::HangupOnly) & libc::POLLIN,
            0,
            "the hang-up-only wait does not ask for input, which would end it at once"
        );
    }

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
    /// A queue that cannot be read (Linux answers EIO on a hung-up terminal)
    /// is the same.
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
    ///
    /// Each message carries what `poll(2)` reported, as `output_gone` asks
    /// it, so a platform that answers another way names its answer in the
    /// failure.
    #[test]
    fn an_output_with_no_reader_has_gone() -> io::Result<()> {
        let asked = |fd: RawFd| crate::input_wait::poll_one(fd, libc::POLLOUT, Duration::ZERO);
        let (reader, writer) = io::pipe()?;
        assert!(
            !output_gone(writer.as_raw_fd())?,
            "a pipe with a reader has not gone: poll reported {:#x}",
            asked(writer.as_raw_fd())?
        );
        drop(reader);
        assert!(
            output_gone(writer.as_raw_fd())?,
            "a pipe with no reader has gone: poll reported {:#x}",
            asked(writer.as_raw_fd())?
        );
        let file = File::options().write(true).open("/dev/null")?;
        assert!(
            !output_gone(file.as_raw_fd())?,
            "/dev/null has not gone: poll reported {:#x}",
            asked(file.as_raw_fd())?
        );
        Ok(())
    }

    /// What `poll(2)` reported for an output: a hang-up or an error is gone,
    /// alone or with "writable"; writable, nothing (a full pipe) and
    /// readable are not, and nor is POLLNVAL, which says only that `poll`
    /// cannot judge the descriptor.
    #[test]
    fn what_poll_reported_for_an_output_is_read() {
        for (revents, gone, what) in [
            (libc::POLLHUP, true, "hung up"),
            (libc::POLLERR, true, "failed"),
            (libc::POLLNVAL, false, "poll cannot judge it"),
            (libc::POLLOUT | libc::POLLNVAL, false, "writable, unjudged"),
            (libc::POLLHUP | libc::POLLNVAL, true, "hung up, not judged"),
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

    /// A new pty: its master side and its slave side. The one `openpty` call
    /// of these tests. The null pointers are `null_mut` because macOS
    /// declares the last two parameters `*mut` and Linux `*const`.
    fn open_pty() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
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
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openpty succeeded; the caller owns both descriptors.
        Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
    }

    /// The slave side of a pty as the terminal the TUI reads.
    fn input_on(slave: &std::os::fd::OwnedFd) -> TerminalInput {
        TerminalInput {
            fd: slave.as_raw_fd(),
            _tty: None,
        }
    }

    /// A pty whose slave side has `b"x\n"` waiting to be read.
    fn pty_with_input() -> io::Result<(File, std::os::fd::OwnedFd)> {
        use std::io::Write as _;
        let (master, slave) = open_pty()?;
        let mut master = File::from(master);
        master.write_all(b"x\n")?;
        let found = wait_past_idle(&input_on(&slave), Interest::Input)?;
        if found != Wait::Input {
            return Err(io::Error::other(format!(
                "bytes written to the master read as {found:?} on the slave"
            )));
        }
        Ok((master, slave))
    }

    /// What `poll(2)` reports at once for the slave side asked each of no
    /// event, POLLHUP, POLLIN and POLLOUT, then the bytes `FIONREAD` reports
    /// queued: one line for a failure message.
    fn poll_answers(slave: &std::os::fd::OwnedFd) -> io::Result<String> {
        let mut line = String::new();
        for (name, events) in [
            ("0", 0),
            ("POLLHUP", libc::POLLHUP),
            ("POLLIN", libc::POLLIN),
            ("POLLOUT", libc::POLLOUT),
        ] {
            let revents = crate::input_wait::poll_one(slave.as_raw_fd(), events, Duration::ZERO)?;
            line.push_str(&format!("asked {name}: {revents:#06x}; "));
        }
        line.push_str(&format!("queued: {:?}", input_on(slave).queued()));
        Ok(line)
    }

    /// Whether a wait of `LONG` on `slave` for `events` (a raw `poll(2)`
    /// request, or the product's hang-up-only wait when `None`) ended early
    /// with nothing reported, in each of three tries: a request that input
    /// already queued ends at once would make the event loop spin. One early
    /// end can be a signal, so one full wait answers `false`.
    fn ends_early(slave: &std::os::fd::OwnedFd, events: Option<libc::c_short>) -> io::Result<bool> {
        const LONG: Duration = Duration::from_millis(300);
        for _ in 0..3 {
            let started = std::time::Instant::now();
            let nothing = match events {
                Some(events) => crate::input_wait::poll_one(slave.as_raw_fd(), events, LONG)? == 0,
                None => input_on(slave).wait(LONG, Interest::HangupOnly)? == Wait::Idle,
            };
            if !nothing || started.elapsed() >= LONG / 2 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// What `poll(2)` and the product's waits report for the slave side of a
    /// pty in four states, measured before anything is asserted, so that a
    /// failure on a platform this was not written on (CI's macOS job) prints
    /// every fact a fix needs in one run (MACOS-HANGUP-ONLY-WAIT).
    struct PtyFacts {
        /// Master open, nothing written.
        quiet_poll: String,
        quiet_hangup_only: Wait,
        quiet_gone: bool,
        /// Master open, `b"x\n"` queued on the slave.
        input_poll: String,
        input_hangup_only: Wait,
        input_hangup_only_ends_early: bool,
        input_asked_pollhup_ends_early: bool,
        /// Master closed, nothing queued.
        hung_up_poll: String,
        hung_up_hangup_only: Wait,
        hung_up_input: Wait,
        hung_up_output_gone: bool,
        /// Master closed with `b"x\n"` queued and unread.
        hung_up_unread_poll: String,
        hung_up_unread_hangup_only: Wait,
        hung_up_unread_input: Wait,
    }

    impl std::fmt::Display for PtyFacts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let PtyFacts {
                quiet_poll,
                quiet_hangup_only,
                quiet_gone,
                input_poll,
                input_hangup_only,
                input_hangup_only_ends_early,
                input_asked_pollhup_ends_early,
                hung_up_poll,
                hung_up_hangup_only,
                hung_up_input,
                hung_up_output_gone,
                hung_up_unread_poll,
                hung_up_unread_hangup_only,
                hung_up_unread_input,
            } = self;
            write!(
                f,
                "measured on {os}\n\
                 master open, quiet: {quiet_poll}; hang-up-only wait {quiet_hangup_only:?}; \
                 gone {quiet_gone}\n\
                 master open, input queued: {input_poll}; hang-up-only wait \
                 {input_hangup_only:?}, ends early {input_hangup_only_ends_early}; a wait \
                 asked POLLHUP ends early {input_asked_pollhup_ends_early}\n\
                 master closed: {hung_up_poll}; hang-up-only wait {hung_up_hangup_only:?}; \
                 wait for input {hung_up_input:?}; output gone {hung_up_output_gone}\n\
                 master closed, input unread: {hung_up_unread_poll}; hang-up-only wait \
                 {hung_up_unread_hangup_only:?}; wait for input {hung_up_unread_input:?}",
                os = std::env::consts::OS,
            )
        }
    }

    fn pty_facts() -> io::Result<PtyFacts> {
        const SHORT: Duration = Duration::from_millis(300);
        let (master, slave) = open_pty()?;
        let quiet_poll = poll_answers(&slave)?;
        let quiet_hangup_only = input_on(&slave).wait(Duration::ZERO, Interest::HangupOnly)?;
        let quiet_gone = input_on(&slave).gone()?;
        drop(master);
        let hung_up_poll = poll_answers(&slave)?;
        let hung_up_hangup_only = input_on(&slave).wait(SHORT, Interest::HangupOnly)?;
        let hung_up_input = input_on(&slave).wait(SHORT, Interest::Input)?;
        let hung_up_output_gone = output_gone(slave.as_raw_fd())?;

        let (master, with_input) = pty_with_input()?;
        let input_poll = poll_answers(&with_input)?;
        let input_hangup_only = input_on(&with_input).wait(Duration::ZERO, Interest::HangupOnly)?;
        let input_hangup_only_ends_early = ends_early(&with_input, None)?;
        let input_asked_pollhup_ends_early = ends_early(&with_input, Some(libc::POLLHUP))?;
        drop(master);
        let hung_up_unread_poll = poll_answers(&with_input)?;
        let hung_up_unread_hangup_only = input_on(&with_input).wait(SHORT, Interest::HangupOnly)?;
        let hung_up_unread_input = input_on(&with_input).wait(SHORT, Interest::Input)?;
        Ok(PtyFacts {
            quiet_poll,
            quiet_hangup_only,
            quiet_gone,
            input_poll,
            input_hangup_only,
            input_hangup_only_ends_early,
            input_asked_pollhup_ends_early,
            hung_up_poll,
            hung_up_hangup_only,
            hung_up_input,
            hung_up_output_gone,
            hung_up_unread_poll,
            hung_up_unread_hangup_only,
            hung_up_unread_input,
        })
    }

    /// An open pty is not gone to a hang-up-only wait, with or without input
    /// queued, and the wait does not end early on that input. Runs on every
    /// platform; a failure prints every measured fact.
    #[test]
    fn a_hangup_only_wait_on_an_open_pty_reports_nothing() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.quiet_hangup_only,
            Wait::Idle,
            "an open, quiet pty is idle to a hang-up-only wait: {facts}"
        );
        assert!(
            !facts.quiet_gone,
            "an open, quiet pty has not gone: {facts}"
        );
        assert_eq!(
            facts.input_hangup_only,
            Wait::Idle,
            "queued input is nothing to a hang-up-only wait: {facts}"
        );
        assert!(
            !facts.input_hangup_only_ends_early,
            "queued input does not end a hang-up-only wait early: {facts}"
        );
        Ok(())
    }

    /// A pty whose master side has closed is gone to a hang-up-only wait
    /// within that wait, not at the wait after it (MACOS-HANGUP-ONLY-WAIT).
    /// Runs on every platform; a failure prints every measured fact.
    #[test]
    fn a_hangup_only_wait_reports_a_closed_master() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.hung_up_hangup_only,
            Wait::Gone,
            "a closed master ends a hang-up-only wait as gone: {facts}"
        );
        assert_eq!(
            facts.hung_up_input,
            Wait::Gone,
            "a closed master ends a wait for input as gone: {facts}"
        );
        Ok(())
    }

    /// A pty whose master side has closed is gone for the side that writes
    /// to it as well. Runs on every platform; a failure prints every
    /// measured fact.
    #[test]
    fn a_closed_master_is_gone_for_the_writer() -> io::Result<()> {
        let facts = pty_facts()?;
        assert!(
            facts.hung_up_output_gone,
            "a closed master is a hang-up for the writer: {facts}"
        );
        Ok(())
    }

    /// A pty whose master side closed with input still unread is gone, to
    /// both waits: read as input, crossterm's read loop would never return.
    /// Runs on every platform; a failure prints every measured fact.
    #[test]
    fn a_closed_master_with_unread_input_is_gone_not_input() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.hung_up_unread_input,
            Wait::Gone,
            "a closed master with unread input is gone to a wait for input: {facts}"
        );
        assert_eq!(
            facts.hung_up_unread_hangup_only,
            Wait::Gone,
            "a closed master with unread input is gone to a hang-up-only wait: {facts}"
        );
        Ok(())
    }

    /// The real descriptor: a pty whose master side closes reads as gone,
    /// and one that is open and quiet reads as idle; written input reads as
    /// input.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pty_reports_input_and_its_hang_up() -> io::Result<()> {
        use std::io::Write as _;
        let (master, slave) = open_pty()?;
        let input = input_on(&slave);
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
