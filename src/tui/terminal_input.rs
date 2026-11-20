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
//! hang-up as `POLLHUP` (or `POLLERR`/`POLLNVAL`), and reads the terminal
//! itself ([`take_input`]): a read of 0 or an `EIO` is the terminal gone, and
//! the bytes read go to crossterm's own parser, copied in `input_parse`.
//! crossterm's reader is never used, so crossterm never reads the terminal.
//! Checking for a hang-up before handing the terminal to crossterm left a
//! window: a hang-up between that check and crossterm's read entered the
//! loop, and 1 of 60 launches on macOS CI spun at full CPU after its tmux
//! session was killed (TUI-SPINS-IN-CROSSTERM-READ-AFTER-TERMINAL-LOSS).
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

/// What one read of the terminal found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Read {
    /// This many bytes, at least one.
    Bytes(usize),
    /// Nothing now: the read would have blocked, or a signal interrupted it.
    Nothing,
    /// The terminal has gone.
    Gone,
}

/// The [`Read`] that the result of a `read(2)` of the terminal means. Pure.
///
/// A read of 0 is end-of-file: a terminal that hung up reads 0 on macOS and
/// after a hang-up on Linux. `EIO` is a pty whose other side closed on Linux,
/// and `ENXIO` a terminal device that is no longer there. Those are the
/// reads crossterm's loop never left. Any other failure is an error of the
/// run.
///
/// # Errors
///
/// The read failed for a reason that says nothing about the terminal going.
pub(crate) fn read_outcome(result: io::Result<usize>) -> io::Result<Read> {
    match result {
        Ok(0) => Ok(Read::Gone),
        Ok(n) => Ok(Read::Bytes(n)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(Read::Nothing)
        }
        Err(e) if matches!(e.raw_os_error(), Some(libc::EIO | libc::ENXIO)) => Ok(Read::Gone),
        Err(e) => Err(e),
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

/// The terminal the TUI reads input from.
pub(crate) struct TerminalInput {
    /// Standard input (a duplicate of its descriptor), or the opened
    /// `/dev/tty`.
    file: File,
}

impl TerminalInput {
    /// The terminal the TUI reads: standard input when it is a terminal,
    /// else `/dev/tty`. The same rule as crossterm's `tty_fd`, which picks
    /// the terminal crossterm puts in raw mode.
    ///
    /// # Errors
    ///
    /// Duplicating standard input or opening `/dev/tty` failed.
    pub(crate) fn open() -> io::Result<Self> {
        use std::os::fd::AsFd as _;
        // SAFETY: isatty(3) only inspects the descriptor.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
            let stdin = io::stdin().as_fd().try_clone_to_owned()?;
            return Ok(TerminalInput {
                file: File::from(stdin),
            });
        }
        let file = File::options().read(true).write(true).open("/dev/tty")?;
        Ok(TerminalInput { file })
    }

    /// The descriptor waited on and read.
    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Wait up to `timeout` for input or a hang-up.
    ///
    /// The wait asks for POLLIN, not for nothing: macOS reports a hang-up
    /// only to a wait that asked for an event (CI's macOS run of
    /// 2026-11-13), and Linux reports POLLHUP, POLLERR and POLLNVAL
    /// whatever is asked.
    ///
    /// # Errors
    ///
    /// `poll(2)` failed for a reason other than a signal.
    pub(crate) fn wait(&self, timeout: Duration) -> io::Result<Wait> {
        // A signal reads as nothing happened (0, so `Idle`): the caller
        // checks the stop flag before waiting again.
        let revents = crate::input_wait::poll_one(self.fd(), libc::POLLIN, timeout)?;
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
        let rc = unsafe { libc::ioctl(self.fd(), libc::FIONREAD, &mut n) };
        (rc == 0).then_some(n)
    }

    /// Whether the terminal has gone, without waiting.
    ///
    /// # Errors
    ///
    /// `poll(2)` failed for a reason other than a signal.
    pub(crate) fn gone(&self) -> io::Result<bool> {
        Ok(self.wait(Duration::ZERO)? == Wait::Gone)
    }
}

/// The terminal an input step reads: [`TerminalInput`], or a test's own.
pub(crate) trait Source {
    /// The bytes waiting to be read, or `None` when the terminal will not
    /// say.
    fn queued(&self) -> Option<libc::c_int>;

    /// One `read(2)` into `buf`.
    ///
    /// # Errors
    ///
    /// The read failed.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl Source for TerminalInput {
    fn queued(&self) -> Option<libc::c_int> {
        TerminalInput::queued(self)
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read as _;
        (&self.file).read(buf)
    }
}

/// What one input step took from the terminal.
#[derive(Debug, PartialEq)]
pub(crate) enum Taken {
    /// The events read, in order; none when the bytes made no event.
    Events(Vec<crossterm::event::Event>),
    /// The terminal has gone.
    Gone,
}

/// The size of one read, crossterm's: a read that fills it tells the parser
/// that more bytes may follow at once.
pub(crate) const READ_SIZE: usize = 1024;

/// Take the input the terminal holds after a wait that found `found`, and
/// parse it with `parser`.
///
/// Only a wait that found input is followed by a read. The first read is
/// made whatever the terminal reports queued now: the bytes the wait saw are
/// still there, as nothing else reads this terminal, unless a hang-up has
/// taken them, and then the read returns at once with 0 or `EIO`. Each read
/// after it is made only while bytes are reported queued, so no read waits.
/// A queue that cannot be read after a read is a terminal that has gone. The
/// terminal is never handed to crossterm, whose read loop never returns on
/// a terminal that has gone.
///
/// # Errors
///
/// A read failed for a reason [`read_outcome`] does not count as the
/// terminal going.
pub(crate) fn take_input(
    source: &impl Source,
    found: Wait,
    parser: &mut crate::tui::input_parse::Parser,
) -> io::Result<Taken> {
    // A lone ESC held from an earlier read whose ESC_DELAY has passed is the
    // Esc key, before any newer byte.
    parser.flush_escape_if_due();
    match found {
        Wait::Gone => return Ok(Taken::Gone),
        Wait::Idle => return Ok(Taken::Events(parser.take())),
        Wait::Input => {}
    }
    let mut buf = [0_u8; READ_SIZE];
    let mut first = true;
    loop {
        if !first {
            match source.queued() {
                None => return Ok(Taken::Gone),
                Some(n) if n <= 0 => break,
                Some(_) => {}
            }
        }
        first = false;
        match read_outcome(source.read(&mut buf))? {
            Read::Gone => return Ok(Taken::Gone),
            Read::Nothing => break,
            Read::Bytes(n) => {
                let bytes = buf.get(..n).unwrap_or(&buf);
                parser.advance(bytes, n == READ_SIZE);
            }
        }
    }
    Ok(Taken::Events(parser.take()))
}

/// A SIGWINCH handler for as long as this value lives, so a resize
/// interrupts the TUI's terminal wait and the next frame is drawn at the new
/// size at once.
///
/// With SIGWINCH's default action (ignore) a resize would be drawn only when
/// the wait times out. crossterm's reader installed such a handler when the
/// TUI first asked it for events; the TUI no longer uses that reader.
pub(crate) struct ResizeWake {
    /// The handler's registration, removed on drop.
    id: signal_hook::SigId,
    /// Set by each SIGWINCH; read by tests only, as the wake is the effect.
    #[cfg(test)]
    resized: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ResizeWake {
    /// Install the handler.
    ///
    /// # Errors
    ///
    /// `sigaction(2)` refused the handler.
    pub(crate) fn install() -> io::Result<Self> {
        let resized = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let id = signal_hook::flag::register(
            signal_hook::consts::SIGWINCH,
            std::sync::Arc::clone(&resized),
        )?;
        Ok(ResizeWake {
            id,
            #[cfg(test)]
            resized,
        })
    }
}

impl Drop for ResizeWake {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.id);
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
            soon(|| output_gone(writer.as_raw_fd()))?,
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
            soon(|| output_gone(writer.as_raw_fd()))?,
            "a full pipe with no reader has gone"
        );
        Ok(())
    }

    /// Wait for input or a hang-up for up to 5 s, waiting again after an
    /// `Idle`. `wait` reports a signal that interrupts `poll(2)` as `Idle`,
    /// so one wait can end early with nothing seen; a pre-commit run of the
    /// whole library test binary on 2026-11-05 saw one such `Idle` here.
    fn wait_past_idle(input: &TerminalInput) -> io::Result<Wait> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let found = input.wait(left)?;
            if found != Wait::Idle || left.is_zero() {
                return Ok(found);
            }
        }
    }

    /// Whether `check` holds within 5 s, asked every 5 ms.
    ///
    /// A test that closes its end of a pipe or a pty and asks the other end
    /// at once can find it still held: a process that another test is
    /// starting holds a copy of every descriptor of this process from its
    /// fork until its exec, close-on-exec ones too. 3 of 20 runs of this
    /// module, whose child-process tests start such processes, saw a closed
    /// master or reader still open when asked at once (2026-11-16, Linux).
    fn soon(mut check: impl FnMut() -> io::Result<bool>) -> io::Result<bool> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if check()? {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(5));
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
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        // openpty's descriptors are inherited by a child process, and a
        // master a child holds keeps the terminal there after this process
        // closes its own. `try_clone` duplicates with close-on-exec set.
        Ok((master.try_clone()?, slave.try_clone()?))
    }

    /// The slave side of a pty as the terminal the TUI reads.
    fn input_on(slave: &std::os::fd::OwnedFd) -> io::Result<TerminalInput> {
        Ok(TerminalInput {
            file: File::from(slave.try_clone()?),
        })
    }

    /// A pty whose slave side has `b"x\n"` waiting to be read.
    fn pty_with_input() -> io::Result<(File, std::os::fd::OwnedFd)> {
        use std::io::Write as _;
        let (master, slave) = open_pty()?;
        let mut master = File::from(master);
        master.write_all(b"x\n")?;
        let found = wait_past_idle(&input_on(&slave)?)?;
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
        line.push_str(&format!("queued: {:?}", input_on(slave)?.queued()));
        Ok(line)
    }

    /// What `poll(2)` and the product's wait report for the slave side of a
    /// pty in four states, measured before anything is asserted, so that a
    /// failure on a platform this was not written on (CI's macOS job) prints
    /// every fact a fix needs in one run (MACOS-HANGUP-ONLY-WAIT).
    struct PtyFacts {
        /// Master open, nothing written.
        quiet_poll: String,
        quiet_wait: Wait,
        quiet_gone: bool,
        /// Master open, `b"x\n"` queued on the slave.
        input_poll: String,
        input_wait: Wait,
        /// Master closed, nothing queued.
        hung_up_poll: String,
        hung_up_input: Wait,
        hung_up_output_gone: bool,
        /// Master closed with `b"x\n"` queued and unread.
        hung_up_unread_poll: String,
        hung_up_unread_input: Wait,
    }

    impl std::fmt::Display for PtyFacts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let PtyFacts {
                quiet_poll,
                quiet_wait,
                quiet_gone,
                input_poll,
                input_wait,
                hung_up_poll,
                hung_up_input,
                hung_up_output_gone,
                hung_up_unread_poll,
                hung_up_unread_input,
            } = self;
            write!(
                f,
                "measured on {os}\n\
                 master open, quiet: {quiet_poll}; wait {quiet_wait:?}; gone {quiet_gone}\n\
                 master open, input queued: {input_poll}; wait {input_wait:?}\n\
                 master closed: {hung_up_poll}; wait {hung_up_input:?}; output gone \
                 {hung_up_output_gone}\n\
                 master closed, input unread: {hung_up_unread_poll}; wait \
                 {hung_up_unread_input:?}",
                os = std::env::consts::OS,
            )
        }
    }

    fn pty_facts() -> io::Result<PtyFacts> {
        const SHORT: Duration = Duration::from_millis(300);
        let (master, slave) = open_pty()?;
        let quiet_poll = poll_answers(&slave)?;
        let quiet_wait = input_on(&slave)?.wait(Duration::ZERO)?;
        let quiet_gone = input_on(&slave)?.gone()?;
        drop(master);
        // The facts after the close, once a process starting elsewhere has
        // let go of its copy of the master (see `soon`).
        soon(|| input_on(&slave)?.gone())?;
        let hung_up_poll = poll_answers(&slave)?;
        let hung_up_input = input_on(&slave)?.wait(SHORT)?;
        let hung_up_output_gone = output_gone(slave.as_raw_fd())?;

        let (master, with_input) = pty_with_input()?;
        let input_poll = poll_answers(&with_input)?;
        let input_wait = input_on(&with_input)?.wait(Duration::ZERO)?;
        drop(master);
        soon(|| input_on(&with_input)?.gone())?;
        let hung_up_unread_poll = poll_answers(&with_input)?;
        let hung_up_unread_input = input_on(&with_input)?.wait(SHORT)?;
        Ok(PtyFacts {
            quiet_poll,
            quiet_wait,
            quiet_gone,
            input_poll,
            input_wait,
            hung_up_poll,
            hung_up_input,
            hung_up_output_gone,
            hung_up_unread_poll,
            hung_up_unread_input,
        })
    }

    /// An open pty is idle when quiet, has input when input is queued, and
    /// has not gone. Runs on every platform; a failure prints every measured
    /// fact.
    #[test]
    fn an_open_pty_is_idle_or_has_input_and_has_not_gone() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.quiet_wait,
            Wait::Idle,
            "an open, quiet pty is idle: {facts}"
        );
        assert!(
            !facts.quiet_gone,
            "an open, quiet pty has not gone: {facts}"
        );
        assert_eq!(
            facts.input_wait,
            Wait::Input,
            "queued input is input: {facts}"
        );
        Ok(())
    }

    /// A pty whose master side has closed ends a wait as gone (Linux and
    /// macOS answer POLLIN with POLLHUP). Runs on every platform; a failure
    /// prints every measured fact.
    #[test]
    fn a_closed_master_ends_a_wait_as_gone() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.hung_up_input,
            Wait::Gone,
            "a closed master ends a wait as gone: {facts}"
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

    /// A pty whose master side closed with input still unread is gone, not
    /// input. Runs on every platform; a failure prints every measured fact.
    #[test]
    fn a_closed_master_with_unread_input_is_gone_not_input() -> io::Result<()> {
        let facts = pty_facts()?;
        assert_eq!(
            facts.hung_up_unread_input,
            Wait::Gone,
            "a closed master with unread input is gone to a wait: {facts}"
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
        let input = input_on(&slave)?;
        assert_eq!(
            input.wait(Duration::ZERO)?,
            Wait::Idle,
            "an open, quiet pty is idle"
        );
        let mut master = File::from(master);
        master.write_all(b"x\n")?;
        assert_eq!(
            wait_past_idle(&input)?,
            Wait::Input,
            "written bytes are input"
        );
        assert!(!input.gone()?, "an open pty has not gone");
        assert!(
            !output_gone(slave.as_raw_fd())?,
            "an open pty has not gone for its writer"
        );
        drop(master);
        assert!(soon(|| input.gone())?, "a closed master is a hang-up");
        assert!(
            output_gone(slave.as_raw_fd())?,
            "a closed master is a hang-up for the writer too"
        );
        assert_eq!(
            wait_past_idle(&input)?,
            Wait::Gone,
            "a hang-up wins over the pending input"
        );
        Ok(())
    }

    /// Print one line to standard output and flush it, for a parent process
    /// that reads the lines as they come. Not `println!`, which panics when
    /// the reader has closed the pipe.
    fn say(line: std::fmt::Arguments<'_>) -> io::Result<()> {
        use std::io::Write as _;
        let mut out = io::stdout().lock();
        writeln!(out, "{line}")?;
        out.flush()
    }

    /// The environment variable that makes [`take_input_in_a_child`] run its
    /// body; its value names the case.
    const TAKE_CHILD: &str = "SIPNAB_TEST_TAKE_INPUT_CHILD";

    /// How long a child is given to take its input. The defect is a step
    /// that never returns; a step that works returns within milliseconds of
    /// the child's start.
    const CHILD_DEADLINE: Duration = Duration::from_secs(20);

    /// One answer of a [`Scripted`] terminal's read.
    enum Answer {
        /// These bytes.
        Bytes(&'static [u8]),
        /// A read of 0.
        Eof,
        /// A failure with this `errno`.
        Errno(i32),
        /// A failure of this kind.
        Kind(io::ErrorKind),
    }

    /// A terminal that answers reads and queue questions from a script, and
    /// counts the reads made. A read past the script fails the test: that
    /// read would have waited on a real terminal.
    struct Scripted {
        /// The answers of `read`, in order.
        reads: std::cell::RefCell<std::collections::VecDeque<Answer>>,
        /// The answers of `queued`, in order; `Some(0)` once they run out.
        queued: std::cell::RefCell<std::collections::VecDeque<Option<libc::c_int>>>,
        /// The reads made.
        reads_made: std::cell::Cell<usize>,
    }

    impl Scripted {
        fn new(reads: Vec<Answer>, queued: Vec<Option<libc::c_int>>) -> Self {
            Scripted {
                reads: std::cell::RefCell::new(reads.into()),
                queued: std::cell::RefCell::new(queued.into()),
                reads_made: std::cell::Cell::new(0),
            }
        }
    }

    impl Source for Scripted {
        fn queued(&self) -> Option<libc::c_int> {
            self.queued.borrow_mut().pop_front().unwrap_or(Some(0))
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads_made.set(self.reads_made.get() + 1);
            match self.reads.borrow_mut().pop_front() {
                Some(Answer::Bytes(bytes)) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                Some(Answer::Eof) => Ok(0),
                Some(Answer::Errno(errno)) => Err(io::Error::from_raw_os_error(errno)),
                Some(Answer::Kind(kind)) => Err(io::Error::from(kind)),
                None => Err(io::Error::other(
                    "a read past the script: it would have waited",
                )),
            }
        }
    }

    /// A raw-mode parser, the TUI's.
    fn parser() -> crate::tui::input_parse::Parser {
        crate::tui::input_parse::Parser::new(true)
    }

    /// The key event a character key makes.
    fn char_key(c: char) -> crossterm::event::Event {
        crossterm::event::Event::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char(c),
            crossterm::event::KeyModifiers::NONE,
        ))
    }

    /// Take input from a script after a wait that found input.
    fn take(script: &Scripted) -> io::Result<Taken> {
        take_input(script, Wait::Input, &mut parser())
    }

    /// What a child that took its input printed, and whether it ended
    /// before [`CHILD_DEADLINE`].
    struct ChildRun {
        ended: bool,
        said: String,
    }

    /// The line a child prints once its terminal is open and the TUI's
    /// reader has been asked once, before the parent changes the terminal.
    const CHILD_READY: &str = "READY";

    /// The case value that makes the child wait for its terminal to go
    /// before it takes input; any other case takes input at once.
    const CASE_LOST: &str = "lost";

    /// Run [`take_input_in_a_child`] in a new process with `slave` (a pty's
    /// slave side) as its standard input and `case` as its case. `change`
    /// runs once the child has said [`CHILD_READY`]: it closes the master,
    /// or writes to it.
    fn run_take_child(
        slave: std::os::fd::OwnedFd,
        case: &str,
        change: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<ChildRun> {
        let mut change = Some(change);
        run_child(
            "take_input_in_a_child",
            slave,
            case,
            CHILD_DEADLINE,
            |line| {
                // The harness prints the test's name on the same line.
                if line.ends_with(CHILD_READY)
                    && let Some(change) = change.take()
                {
                    return change();
                }
                Ok(())
            },
        )
    }

    /// Run the test `test` of this module in a new process, in a process
    /// group of its own, with `slave` as its standard input and `case` in
    /// [`TAKE_CHILD`]; `on_line` is called with each line the child prints.
    /// A child still running at `deadline` is killed; it starts no process
    /// of its own.
    fn run_child(
        test: &str,
        slave: std::os::fd::OwnedFd,
        case: &str,
        deadline: Duration,
        mut on_line: impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<ChildRun> {
        use std::io::{BufRead as _, Read as _};
        use std::os::unix::process::CommandExt as _;
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, module)| module);
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", &format!("{module}::{test}")])
            .args(["--ignored", "--nocapture", "--test-threads=1"])
            .env(TAKE_CHILD, case)
            .stdin(std::process::Stdio::from(slave))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()?;
        let deadline = std::time::Instant::now() + deadline;
        // The child's standard output, line by line, from a thread of its
        // own, so waiting for a line has a deadline.
        let (lines_tx, lines) = std::sync::mpsc::channel::<String>();
        let reader = child.stdout.take().map(|out| {
            std::thread::spawn(move || {
                for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                    if lines_tx.send(line).is_err() {
                        break;
                    }
                }
            })
        });
        let mut said = String::new();
        // Until the child closes its output (it has ended) or the deadline.
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) => {
                    said.push_str(&line);
                    said.push('\n');
                    on_line(&line)?;
                }
                Err(_) => break,
            }
        }
        let ended = loop {
            if child.try_wait()?.is_some() {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                // What the child was doing: a busy loop shows in its CPU
                // time and its state (R).
                let ps = std::process::Command::new("ps")
                    .args(["-o", "stat=,time=", "-p", &child.id().to_string()])
                    .output()?;
                said.push_str(&format!(
                    "(at the deadline: ps stat and CPU time {})\n",
                    String::from_utf8_lossy(&ps.stdout).trim()
                ));
                child.kill()?;
                child.wait()?;
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if let Some(reader) = reader {
            let _ = reader.join();
        }
        said.extend(lines.try_iter().map(|line| line + "\n"));
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut said)?;
        }
        Ok(ChildRun { ended, said })
    }

    /// The child's half of the terminal-loss steps. Its standard input is a
    /// pty's slave side. It opens that terminal and asks crossterm's reader
    /// once, as a TUI before this fix had, says READY, and for [`CASE_LOST`]
    /// waits until the terminal has gone, which no check before the read can
    /// see in time in a real run; then it takes input as after a wait that
    /// found input, and prints what was taken and, when that was events,
    /// what the next wait finds.
    #[test]
    #[ignore = "a child process of the terminal-loss tests below; they run it"]
    fn take_input_in_a_child() -> io::Result<()> {
        use std::io::Write as _;
        let Some(case) = std::env::var_os(TAKE_CHILD) else {
            return Ok(());
        };
        // Raw mode, as the TUI's: a key is input at once, not at a newline.
        crossterm::terminal::enable_raw_mode()?;
        let input = TerminalInput::open()?;
        let _ = crossterm::event::poll(Duration::ZERO)?;
        say(format_args!("{CHILD_READY}"))?;
        std::io::stdout().flush()?;
        let found = if case == CASE_LOST {
            let deadline = std::time::Instant::now() + CHILD_DEADLINE;
            while !input.gone()? {
                if std::time::Instant::now() >= deadline {
                    say(format_args!("the terminal never went"))?;
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            say(format_args!("GONE SEEN"))?;
            std::io::stdout().flush()?;
            // The race: the wait found input, then the terminal went.
            Wait::Input
        } else {
            let found = wait_past_idle(&input)?;
            say(format_args!("WAIT: {found:?}"))?;
            found
        };
        let taken = take_input(&input, found, &mut parser())?;
        say(format_args!("TAKEN: {taken:?}"))?;
        if taken != Taken::Gone {
            say(format_args!("AFTER: {:?}", input.wait(Duration::ZERO)?))?;
        }
        Ok(())
    }

    /// Whether a child's run ended with its terminal gone: the step said so,
    /// or it returned the bytes that were there and the next wait did.
    fn ended_gone(run: &ChildRun) -> bool {
        run.said.contains("TAKEN: Gone") || run.said.contains("AFTER: Gone")
    }

    /// A terminal that hangs up after the check and before the read ends
    /// the input step as gone: the read itself finds the hang-up, and the
    /// terminal is not handed to crossterm. Red before the fix on Linux:
    /// the child spun in crossterm's read until killed (CPU time 19 s of 20).
    #[test]
    fn a_terminal_lost_between_the_check_and_the_read_ends_the_step() -> io::Result<()> {
        let (master, slave) = open_pty()?;
        let run = run_take_child(slave, CASE_LOST, || {
            drop(master);
            Ok(())
        })?;
        assert!(
            run.ended,
            "the input step was still running {CHILD_DEADLINE:?} after its terminal had \
             gone (killed): {}",
            run.said
        );
        assert!(
            ended_gone(&run),
            "the step must report the terminal gone: {}",
            run.said
        );
        Ok(())
    }

    /// A terminal that hangs up with input still unread ends the step too,
    /// whether the hang-up took the input or the read returns it first.
    #[test]
    fn a_terminal_lost_with_input_unread_ends_the_step() -> io::Result<()> {
        use std::io::Write as _;
        let (master, slave) = open_pty()?;
        let run = run_take_child(slave, CASE_LOST, || {
            let mut master = File::from(master);
            master.write_all(b"q")?;
            drop(master);
            Ok(())
        })?;
        assert!(
            run.ended,
            "the input step was still running {CHILD_DEADLINE:?} after its terminal had \
             gone with input unread (killed): {}",
            run.said
        );
        assert!(
            ended_gone(&run),
            "the step, or the wait after it, must report the terminal gone: {}",
            run.said
        );
        Ok(())
    }

    /// On a terminal that is there, the step returns the key typed, and the
    /// next wait finds the terminal idle, not gone.
    #[test]
    fn a_terminal_that_is_there_gives_its_input() -> io::Result<()> {
        use std::io::Write as _;
        let (master, slave) = open_pty()?;
        let mut master = File::from(master);
        let run = run_take_child(slave, "there", || master.write_all(b"x"))?;
        assert!(run.ended, "the child must end: {}", run.said);
        assert!(
            run.said.contains("WAIT: Input"),
            "the wait must find the key: {}",
            run.said
        );
        assert!(
            run.said
                .contains(&format!("TAKEN: {:?}", Taken::Events(vec![char_key('x')]))),
            "the step must return the key typed: {}",
            run.said
        );
        assert!(
            run.said.contains("AFTER: Idle"),
            "a terminal that is there is idle after its input is read: {}",
            run.said
        );
        drop(master);
        Ok(())
    }

    /// A read of some bytes is those bytes.
    #[test]
    fn success_a_read_of_bytes_is_those_bytes() -> io::Result<()> {
        assert_eq!(read_outcome(Ok(5))?, Read::Bytes(5), "five bytes read");
        assert_eq!(read_outcome(Ok(1))?, Read::Bytes(1), "one byte read");
        assert_eq!(
            read_outcome(Ok(READ_SIZE))?,
            Read::Bytes(READ_SIZE),
            "a full read"
        );
        Ok(())
    }

    /// A read of 0 is end-of-file: the terminal has gone.
    #[test]
    fn failure_a_read_of_0_is_the_terminal_gone() -> io::Result<()> {
        assert_eq!(read_outcome(Ok(0))?, Read::Gone, "end-of-file");
        Ok(())
    }

    /// `EIO`, a pty whose other side closed on Linux, is the terminal gone.
    #[test]
    fn failure_eio_is_the_terminal_gone() -> io::Result<()> {
        assert_eq!(
            read_outcome(Err(io::Error::from_raw_os_error(libc::EIO)))?,
            Read::Gone,
            "EIO"
        );
        Ok(())
    }

    /// `ENXIO`, a terminal device that is no longer there, is the terminal
    /// gone.
    #[test]
    fn failure_enxio_is_the_terminal_gone() -> io::Result<()> {
        assert_eq!(
            read_outcome(Err(io::Error::from_raw_os_error(libc::ENXIO)))?,
            Read::Gone,
            "ENXIO"
        );
        Ok(())
    }

    /// A failure that says nothing about the terminal going is an error of
    /// the run, with its own errno.
    #[test]
    fn failure_another_read_failure_is_an_error() {
        for errno in [libc::EBADF, libc::EINVAL, libc::EFAULT] {
            let outcome = read_outcome(Err(io::Error::from_raw_os_error(errno)));
            assert_eq!(
                outcome.as_ref().map_err(io::Error::raw_os_error).err(),
                Some(Some(errno)),
                "errno {errno} must stay an error: {outcome:?}"
            );
        }
    }

    /// A read that would block, or that a signal interrupted, read nothing
    /// and is not a lost terminal.
    #[test]
    fn edge_would_block_and_interrupted_are_nothing() -> io::Result<()> {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::Interrupted] {
            assert_eq!(
                read_outcome(Err(io::Error::from(kind)))?,
                Read::Nothing,
                "{kind:?}"
            );
        }
        for errno in [libc::EAGAIN, libc::EINTR] {
            assert_eq!(
                read_outcome(Err(io::Error::from_raw_os_error(errno)))?,
                Read::Nothing,
                "errno {errno}"
            );
        }
        Ok(())
    }

    /// One read's bytes become their events, and no read is made once
    /// nothing is queued.
    #[test]
    fn success_one_read_gives_its_events() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Bytes(b"ab")], vec![Some(0)]);
        assert_eq!(
            take(&script)?,
            Taken::Events(vec![char_key('a'), char_key('b')]),
            "two keys"
        );
        assert_eq!(script.reads_made.get(), 1, "one read");
        Ok(())
    }

    /// Reads go on while bytes are queued, so a burst is taken in one step.
    #[test]
    fn success_reads_go_on_while_bytes_are_queued() -> io::Result<()> {
        let script = Scripted::new(
            vec![
                Answer::Bytes(b"a"),
                Answer::Bytes(b"b"),
                Answer::Bytes(b"c"),
            ],
            vec![Some(1), Some(1), Some(0)],
        );
        assert_eq!(
            take(&script)?,
            Taken::Events(vec![char_key('a'), char_key('b'), char_key('c')]),
            "three reads, three keys"
        );
        assert_eq!(script.reads_made.get(), 3, "three reads");
        Ok(())
    }

    /// A sequence split over two reads is one event.
    #[test]
    fn success_a_sequence_split_over_two_reads_is_one_event() -> io::Result<()> {
        let script = Scripted::new(
            vec![Answer::Bytes(b"\x1b[1;5"), Answer::Bytes(b"A")],
            vec![Some(1), Some(0)],
        );
        let ctrl_up = crossterm::event::Event::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Up,
            crossterm::event::KeyModifiers::CONTROL,
        ));
        assert_eq!(take(&script)?, Taken::Events(vec![ctrl_up]), "Ctrl+Up");
        Ok(())
    }

    /// A paste split over reads is one paste.
    #[test]
    fn success_a_paste_split_over_reads_is_one_paste() -> io::Result<()> {
        let script = Scripted::new(
            vec![
                Answer::Bytes(b"\x1b[200~pass"),
                Answer::Bytes(b"word\x1b[201~"),
            ],
            vec![Some(1), Some(0)],
        );
        assert_eq!(
            take(&script)?,
            Taken::Events(vec![crossterm::event::Event::Paste("password".into())]),
            "one paste"
        );
        Ok(())
    }

    /// A read that fills the buffer tells the parser that more may follow:
    /// an ESC at its end is the start of a sequence the next read ends, not
    /// the Esc key.
    #[test]
    fn success_a_full_read_holds_a_trailing_escape_for_the_next() -> io::Result<()> {
        static FULL: [u8; READ_SIZE] = {
            let mut full = [b'x'; READ_SIZE];
            full[READ_SIZE - 1] = 0x1b;
            full
        };
        let script = Scripted::new(
            vec![Answer::Bytes(&FULL), Answer::Bytes(b"[A")],
            vec![Some(2), Some(0)],
        );
        let Taken::Events(events) = take(&script)? else {
            return Err(io::Error::other("an open terminal has not gone"));
        };
        assert_eq!(
            events.len(),
            READ_SIZE,
            "1023 keys and one Up: {}",
            events.len()
        );
        assert_eq!(
            events.last(),
            Some(&crossterm::event::Event::Key(
                crossterm::event::KeyCode::Up.into()
            )),
            "the ESC began the Up sequence"
        );
        Ok(())
    }

    /// A wait that found nothing makes no read.
    #[test]
    fn success_an_idle_wait_reads_nothing() -> io::Result<()> {
        let script = Scripted::new(vec![], vec![]);
        assert_eq!(
            take_input(&script, Wait::Idle, &mut parser())?,
            Taken::Events(vec![]),
            "nothing taken"
        );
        assert_eq!(script.reads_made.get(), 0, "no read");
        Ok(())
    }

    /// A first read of 0 is a lost terminal, and no read follows it.
    #[test]
    fn failure_a_first_read_of_0_is_gone() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Eof], vec![Some(1)]);
        assert_eq!(take(&script)?, Taken::Gone, "end-of-file");
        assert_eq!(script.reads_made.get(), 1, "no read after the end");
        Ok(())
    }

    /// A first read that fails with `EIO` is a lost terminal.
    #[test]
    fn failure_a_first_read_of_eio_is_gone() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Errno(libc::EIO)], vec![Some(1)]);
        assert_eq!(take(&script)?, Taken::Gone, "EIO");
        assert_eq!(script.reads_made.get(), 1, "no read after EIO");
        Ok(())
    }

    /// A read of 0 after bytes is a lost terminal: the bytes before it are
    /// of a terminal that has gone.
    #[test]
    fn failure_a_read_of_0_after_bytes_is_gone() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Bytes(b"a"), Answer::Eof], vec![Some(1)]);
        assert_eq!(take(&script)?, Taken::Gone, "end-of-file after a key");
        Ok(())
    }

    /// `EIO` after bytes is a lost terminal.
    #[test]
    fn failure_eio_after_bytes_is_gone() -> io::Result<()> {
        let script = Scripted::new(
            vec![Answer::Bytes(b"a"), Answer::Errno(libc::EIO)],
            vec![Some(1)],
        );
        assert_eq!(take(&script)?, Taken::Gone, "EIO after a key");
        Ok(())
    }

    /// A queue that cannot be read after a read is a lost terminal, and no
    /// second read is made: on a terminal that is there it could wait.
    #[test]
    fn failure_an_unreadable_queue_after_a_read_is_gone() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Bytes(b"a")], vec![None]);
        assert_eq!(take(&script)?, Taken::Gone, "no queue to read");
        assert_eq!(script.reads_made.get(), 1, "one read only");
        Ok(())
    }

    /// A wait that found the terminal gone makes no read.
    #[test]
    fn failure_a_gone_wait_reads_nothing() -> io::Result<()> {
        let script = Scripted::new(vec![], vec![]);
        assert_eq!(
            take_input(&script, Wait::Gone, &mut parser())?,
            Taken::Gone,
            "gone"
        );
        assert_eq!(script.reads_made.get(), 0, "no read");
        Ok(())
    }

    /// A read failure that is not a lost terminal is an error of the step.
    #[test]
    fn failure_a_read_error_is_returned() {
        let script = Scripted::new(vec![Answer::Errno(libc::EBADF)], vec![]);
        let taken = take(&script);
        assert_eq!(
            taken.as_ref().map_err(io::Error::raw_os_error).err(),
            Some(Some(libc::EBADF)),
            "EBADF is an error: {taken:?}"
        );
    }

    /// The first read is made whatever the queue says: the bytes the wait
    /// saw are still there, and the queue is not asked before it.
    #[test]
    fn edge_the_first_read_does_not_ask_the_queue() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Bytes(b"a")], vec![Some(0), Some(0)]);
        assert_eq!(take(&script)?, Taken::Events(vec![char_key('a')]), "a");
        assert_eq!(
            script.queued.borrow().len(),
            1,
            "the queue is asked once, after the first read"
        );
        Ok(())
    }

    /// A first read that would block takes nothing and is not a loss.
    #[test]
    fn edge_a_first_read_that_would_block_takes_nothing() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Kind(io::ErrorKind::WouldBlock)], vec![]);
        assert_eq!(take(&script)?, Taken::Events(vec![]), "nothing");
        Ok(())
    }

    /// A later read that a signal interrupted keeps the events read before
    /// it; the bytes left are read after the next wait.
    #[test]
    fn edge_an_interrupted_read_keeps_the_events_before_it() -> io::Result<()> {
        let script = Scripted::new(
            vec![
                Answer::Bytes(b"a"),
                Answer::Kind(io::ErrorKind::Interrupted),
            ],
            vec![Some(1)],
        );
        assert_eq!(take(&script)?, Taken::Events(vec![char_key('a')]), "a");
        assert_eq!(script.reads_made.get(), 2, "two reads");
        Ok(())
    }

    /// A queue size below zero is no bytes queued.
    #[test]
    fn edge_a_negative_queue_is_nothing_queued() -> io::Result<()> {
        let script = Scripted::new(vec![Answer::Bytes(b"a")], vec![Some(-1)]);
        assert_eq!(take(&script)?, Taken::Events(vec![char_key('a')]), "a");
        assert_eq!(script.reads_made.get(), 1, "no read after it");
        Ok(())
    }

    /// Bytes that make no event yet stay in the parser between steps.
    #[test]
    fn edge_an_unfinished_sequence_waits_in_the_parser() -> io::Result<()> {
        let mut parser = parser();
        let first = Scripted::new(vec![Answer::Bytes(b"\x1b[")], vec![]);
        assert_eq!(
            take_input(&first, Wait::Input, &mut parser)?,
            Taken::Events(vec![]),
            "no event yet"
        );
        let second = Scripted::new(vec![Answer::Bytes(b"B")], vec![]);
        assert_eq!(
            take_input(&second, Wait::Input, &mut parser)?,
            Taken::Events(vec![crossterm::event::Event::Key(
                crossterm::event::KeyCode::Down.into()
            )]),
            "Down, from two steps"
        );
        Ok(())
    }

    /// The child's half of [`record_crossterm_events`]: crossterm's own
    /// reader, in raw mode, reads each read of the corpus from standard
    /// input, a pty, and prints the events it gave.
    #[test]
    #[ignore = "a child process of record_crossterm_events; it runs it"]
    fn record_crossterm_in_a_child() -> io::Result<()> {
        use std::io::Write as _;
        if std::env::var_os(TAKE_CHILD).is_none() {
            return Ok(());
        }
        crossterm::terminal::enable_raw_mode()?;
        for index in 0..crate::tui::input_parse::CORPUS.len() {
            say(format_args!("NEXT {index}"))?;
            std::io::stdout().flush()?;
            let mut events = Vec::new();
            let mut wait = Duration::from_millis(500);
            while crossterm::event::poll(wait)? {
                events.push(crossterm::event::read()?);
                wait = Duration::from_millis(100);
            }
            say(format_args!("CHUNK {index}: {events:?}"))?;
        }
        crossterm::terminal::disable_raw_mode()?;
        Ok(())
    }

    /// Record what crossterm 0.29.0's own reader gives for each read of
    /// `input_parse::CORPUS`, and print it as the `CROSSTERM_0_29` table.
    /// Run by hand when crossterm or the corpus changes:
    /// `cargo test --features tui --lib record_crossterm_events -- --ignored --nocapture`.
    /// Each read is written only after the child has finished the one
    /// before, so each is one read of crossterm's.
    #[test]
    #[ignore = "a recorder run by hand; its table is input_parse::CROSSTERM_0_29"]
    fn record_crossterm_events() -> io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let corpus = crate::tui::input_parse::CORPUS;
        let (master, slave) = open_pty()?;
        // crossterm's reader reads until a read would block, so on a
        // blocking terminal a read whose bytes make no event leaves it in a
        // second read that waits for the next key, past its poll timeout
        // (measured here 2026-11-16: `poll(500 ms)` after `ESC [ X` had not
        // returned 150 s later). The child is given the slave side opened
        // again non-blocking, so each read is recorded on its own. The path
        // comes from /proc, so the recorder runs on Linux.
        let path = std::fs::read_link(format!("/proc/self/fd/{}", slave.as_raw_fd()))?;
        let slave = std::os::fd::OwnedFd::from(
            File::options()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
                .open(path)?,
        );
        let mut master = File::from(master);
        let run = run_child(
            "record_crossterm_in_a_child",
            slave,
            "record",
            Duration::from_secs(300),
            |line| {
                let Some((_, index)) = line.rsplit_once("NEXT ") else {
                    return Ok(());
                };
                let index: usize = index.trim().parse().map_err(io::Error::other)?;
                master.write_all(corpus[index])
            },
        )?;
        assert!(run.ended, "the recorder child must end: {}", run.said);
        let mut table = Vec::new();
        for line in run.said.lines() {
            if let Some((_, rest)) = line.split_once("CHUNK ")
                && let Some((index, events)) = rest.split_once(": ")
            {
                table.push((
                    index.parse::<usize>().map_err(io::Error::other)?,
                    events.to_owned(),
                ));
            }
        }
        assert_eq!(
            table.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..corpus.len()).collect::<Vec<_>>(),
            "one recorded line per read, in order: {}",
            run.said
        );
        say(format_args!(
            "pub(crate) const CROSSTERM_0_29: &[&str] = &["
        ))?;
        for (_, events) in table {
            say(format_args!("    {events:?},"))?;
        }
        say(format_args!("];"))?;
        Ok(())
    }

    /// The resize wake catches SIGWINCH, so a resize interrupts the wait.
    #[test]
    fn success_the_resize_wake_catches_sigwinch() -> io::Result<()> {
        let wake = ResizeWake::install()?;
        signal_hook::low_level::raise(signal_hook::consts::SIGWINCH)?;
        assert!(
            wake.resized.load(std::sync::atomic::Ordering::SeqCst),
            "SIGWINCH must reach the wake's handler"
        );
        Ok(())
    }

    /// A wake that has been dropped is no longer told of a resize.
    #[test]
    fn edge_a_dropped_resize_wake_is_not_told() -> io::Result<()> {
        let wake = ResizeWake::install()?;
        let resized = std::sync::Arc::clone(&wake.resized);
        drop(wake);
        signal_hook::low_level::raise(signal_hook::consts::SIGWINCH)?;
        assert!(
            !resized.load(std::sync::atomic::Ordering::SeqCst),
            "a dropped wake's handler is removed"
        );
        Ok(())
    }
}
