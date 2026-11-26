// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Writing a run's answer to standard output when the reader may have gone.
//!
//! `println!` panics when its write fails. A reader that closes the pipe early
//! (`sipnab ... | head -1`) makes every later write fail with `EPIPE`, so a
//! run that had done everything it was asked exited 101 through the panic
//! hook and left a crash report. `out!` and `outln!` write through
//! [`emit`] instead: a closed pipe ends the output quietly, and any other
//! write error (a full disk under `> file`) is an error the run reports and
//! exits 1 on, because the answer did not reach its destination.
//!
//! The per-message stream has its own buffered writer with the same rule
//! (`crate::output::sink::BatchSink`); this is for everything else a run
//! prints to stdout.

use std::io::Write;

/// Write `args` to `w`, treating a reader that closed the pipe as success.
///
/// # Errors
///
/// Any write error other than [`std::io::ErrorKind::BrokenPipe`].
pub fn write_to<W: Write>(w: &mut W, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
    match w.write_fmt(args).and_then(|()| w.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Write `args` to standard output.
///
/// A closed pipe is ignored. Any other write error is printed on stderr and
/// the run exits 1, or [`UNWRITABLE_EXIT_CODE`] when standard output cannot
/// be written at all.
pub fn emit(args: std::fmt::Arguments<'_>) {
    if let Err(e) = write_to(&mut lock(), args) {
        say_failed(&e);
        crate::capture::archive::release_run_and_exit(1);
    }
}

/// Print the line [`emit`] prints for a failed write: `e` names the reason.
pub fn say_failed(e: &std::io::Error) {
    stderr_line!("writing to standard output failed: {e}");
}

// ── A standard output that cannot be written ────────────────────────────
//
// Rust's standard library hides two cases. A write to a standard output
// opened read-only fails with `EBADF`, and `std::io::Stdout` reports it as a
// write of the whole buffer (`handle_ebadf` in library/std/src/io/stdio.rs).
// A standard output that was closed when the process started is opened on
// `/dev/null` before `main` (`sanitize_standard_fds` in
// library/std/src/sys/pal/unix/mod.rs), so every write succeeds. A run in
// either case printed nothing and exited 0. Every write sipnab makes to
// standard output goes through [`Checked`], which refuses both.

/// The exit code of a run whose standard output could not be written at
/// all: closed, or not open for writing. A run that would have exited 0 or 1
/// exits with this code instead; any other code is kept.
///
/// Not 5: the internal scanner-kill worker process exits 5 on a serving error
/// (`crate::process_isolation::worker_process`).
pub const UNWRITABLE_EXIT_CODE: i32 = 6;

/// Why standard output cannot take a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unwritable {
    /// Descriptor 1 was closed when the process started.
    Closed,
    /// Descriptor 1 is open, but not for writing (read-only, or `O_PATH`).
    NotForWriting,
}

impl std::fmt::Display for Unwritable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Closed => "standard output is closed",
            Self::NotForWriting => "standard output is not open for writing",
        })
    }
}

impl std::error::Error for Unwritable {}

/// Decide whether standard output can be written.
///
/// `closed_at_exec` says descriptor 1 was closed before the runtime opened
/// `/dev/null` on it. `status_flags` is `fcntl(1, F_GETFL)`, `None` when that
/// call failed (the descriptor is not open now).
pub fn classify(closed_at_exec: bool, status_flags: Option<libc::c_int>) -> Option<Unwritable> {
    match status_flags {
        _ if closed_at_exec => Some(Unwritable::Closed),
        None => Some(Unwritable::Closed),
        Some(flags) if flags & libc::O_ACCMODE == libc::O_RDONLY => Some(Unwritable::NotForWriting),
        Some(_) => None,
    }
}

/// Descriptor 1 was closed when the process started: set before `main`, by
/// [`probe_at_exec`].
static CLOSED_AT_EXEC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set once a write to standard output was refused; read by [`exit_code`].
static REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record whether descriptor 1 is closed, before the runtime opens
/// `/dev/null` on it. Runs from the platform's initializer list, ahead of
/// `main` and of the standard library's start-up.
///
/// Why before `main`: Rust's runtime start-up, `sanitize_standard_fds` in
/// library/std/src/sys/pal/unix/mod.rs, runs before `main` and opens
/// `/dev/null` read-write on every closed standard descriptor. From `main` on,
/// a descriptor 1 closed by the shell (`>&-`) is the same as one the user
/// opened with `1<> /dev/null`, or that daemon(3) and start-stop-daemon set
/// up, which are writable outputs a run must not refuse. Only a check made
/// before that start-up can tell them apart. The probe does one `fcntl` and
/// one atomic store, and allocates nothing.
extern "C" fn probe_at_exec() {
    // SAFETY: fcntl(2) with F_GETFD on the fixed descriptor 1 only reads its
    // descriptor flags; it touches no memory of this process. It runs before
    // std's `sanitize_standard_fds`, so a closed descriptor still fails here
    // with EBADF instead of naming the `/dev/null` std opens on it later.
    let closed = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFD) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    CLOSED_AT_EXEC.store(closed, std::sync::atomic::Ordering::Relaxed);
}

/// [`probe_at_exec`] in the ELF initializer list.
// before-main: std's sanitize_standard_fds hides a closed stdout from main.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[used]
#[unsafe(link_section = ".init_array")]
static PROBE_AT_EXEC: extern "C" fn() = probe_at_exec;

/// [`probe_at_exec`] in the Mach-O initializer list.
// before-main: std's sanitize_standard_fds hides a closed stdout from main.
#[cfg(target_vendor = "apple")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static PROBE_AT_EXEC: extern "C" fn() = probe_at_exec;

/// Why this process's standard output cannot be written, or `None` when it
/// can. Decided once: the descriptor does not change during a run.
pub fn unwritable() -> Option<Unwritable> {
    static STATE: std::sync::OnceLock<Option<Unwritable>> = std::sync::OnceLock::new();
    *STATE.get_or_init(|| {
        // SAFETY: as in `probe_at_exec`; F_GETFL only reads the flags.
        let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
        classify(
            CLOSED_AT_EXEC.load(std::sync::atomic::Ordering::Relaxed),
            (flags != -1).then_some(flags),
        )
    })
}

/// Record that standard output refused a write, and return the error.
pub fn refusal(why: Unwritable) -> std::io::Error {
    REFUSED.store(true, std::sync::atomic::Ordering::Relaxed);
    std::io::Error::other(why)
}

/// Whether `e` is a refusal of an unwritable standard output.
pub fn is_unwritable(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Unwritable>())
}

/// The code a run exits with when its output failed with `e`: 1, or
/// [`UNWRITABLE_EXIT_CODE`] when standard output cannot be written.
pub fn exit_code_for(e: &std::io::Error) -> i32 {
    if is_unwritable(e) {
        UNWRITABLE_EXIT_CODE
    } else {
        1
    }
}

/// The exit code of a run that would exit `code`: see [`adjust_exit_code`].
pub fn exit_code(code: i32) -> i32 {
    adjust_exit_code(code, REFUSED.load(std::sync::atomic::Ordering::Relaxed))
}

/// `code`, or [`UNWRITABLE_EXIT_CODE`] in place of 0 or 1 when `refused`.
pub fn adjust_exit_code(code: i32, refused: bool) -> i32 {
    if refused && (code == 0 || code == 1) {
        UNWRITABLE_EXIT_CODE
    } else {
        code
    }
}

/// The exit code for a command line clap did not run: it printed help or
/// the version, or refused the command line. Help and version go to
/// standard output, so an unwritable one is refused.
pub fn clap_exit_code(e: &clap::Error) -> i32 {
    if !e.use_stderr()
        && let Some(why) = unwritable()
    {
        say_failed(&refusal(why));
        return UNWRITABLE_EXIT_CODE;
    }
    let _ = e.print();
    if e.use_stderr() { 2 } else { 0 }
}

/// A writer in front of standard output that refuses every non-empty write
/// when standard output cannot be written. A flush is passed on: it writes
/// nothing a refused write could have left.
#[derive(Debug)]
pub struct Checked<W> {
    /// The standard output handle or lock.
    inner: W,
    /// Why a write is refused, or `None` when writes go through.
    refuse: Option<Unwritable>,
}

impl<W> Checked<W> {
    /// `inner` with the given refusal; for tests in this crate.
    #[cfg(test)]
    pub(crate) fn with_refusal(inner: W, refuse: Option<Unwritable>) -> Self {
        Self { inner, refuse }
    }

    /// The error for a write of `len` bytes, if it is refused.
    fn check(&self, len: usize) -> std::io::Result<()> {
        match self.refuse {
            Some(why) if len > 0 => Err(refusal(why)),
            _ => Ok(()),
        }
    }
}

impl<W: Write> Write for Checked<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check(buf.len())?;
        self.inner.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.check(buf.len())?;
        self.inner.write_all(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Standard output, checked.
pub fn handle() -> Checked<std::io::Stdout> {
    Checked {
        inner: std::io::stdout(),
        refuse: unwritable(),
    }
}

/// Standard output, locked and checked.
pub fn lock() -> Checked<std::io::StdoutLock<'static>> {
    Checked {
        inner: std::io::stdout().lock(),
        refuse: unwritable(),
    }
}

/// `print!` for a run's answer: see the module documentation.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::stdout::emit(::std::format_args!($($arg)*))
    };
}

/// `println!` for a run's answer: see the module documentation.
macro_rules! outln {
    () => {
        $crate::output::stdout::emit(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::output::stdout::emit(::std::format_args!(
            "{}\n",
            ::std::format_args!($($arg)*)
        ))
    };
}

pub(crate) use {out, outln};

#[cfg(test)]
mod tests {
    use super::*;

    /// The error a test returns.
    type TestError = Box<dyn std::error::Error>;

    /// A writer whose every write fails with `kind`.
    struct Failing(std::io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(self.0.into())
        }
    }

    /// A reader that went away is not an error of the run.
    #[test]
    fn a_closed_pipe_is_not_an_error() {
        let r = write_to(
            &mut Failing(std::io::ErrorKind::BrokenPipe),
            format_args!("x"),
        );
        assert!(r.is_ok(), "{r:?}");
    }

    /// Output that could not be written anywhere else is an error: the
    /// answer did not reach its destination.
    #[test]
    fn any_other_write_error_is_returned() {
        let r = write_to(
            &mut Failing(std::io::ErrorKind::StorageFull),
            format_args!("x"),
        );
        assert_eq!(
            r.map_err(|e| e.kind()),
            Err(std::io::ErrorKind::StorageFull)
        );
    }

    /// What is written arrives as formatted.
    #[test]
    fn the_text_arrives_as_formatted() -> Result<(), TestError> {
        let mut buf = Vec::new();
        write_to(&mut buf, format_args!("{} {}\n", "a", 1))?;
        assert_eq!(String::from_utf8(buf)?, "a 1\n");
        Ok(())
    }

    // ── classify: success (writable) ─────────────────────────────────

    /// Write-only, as `> file` opens it, is writable.
    #[test]
    fn classify_write_only_is_writable() {
        assert_eq!(classify(false, Some(libc::O_WRONLY)), None, "O_WRONLY");
    }

    /// Read-write, as `1<> file` opens it, is writable.
    #[test]
    fn classify_read_write_is_writable() {
        assert_eq!(classify(false, Some(libc::O_RDWR)), None, "O_RDWR");
    }

    /// Append mode is writable.
    #[test]
    fn classify_append_is_writable() {
        assert_eq!(
            classify(false, Some(libc::O_WRONLY | libc::O_APPEND)),
            None,
            "O_WRONLY|O_APPEND"
        );
    }

    /// A non-blocking pipe's write end is writable.
    #[test]
    fn classify_non_blocking_write_end_is_writable() {
        assert_eq!(
            classify(false, Some(libc::O_WRONLY | libc::O_NONBLOCK)),
            None,
            "O_WRONLY|O_NONBLOCK"
        );
    }

    // ── classify: failure (refused) ──────────────────────────────────

    /// Read-only is not open for writing.
    #[test]
    fn classify_read_only_is_refused() {
        assert_eq!(
            classify(false, Some(libc::O_RDONLY)),
            Some(Unwritable::NotForWriting),
            "O_RDONLY"
        );
    }

    /// Read-only with other status flags is still read-only.
    #[test]
    fn classify_read_only_with_flags_is_refused() {
        assert_eq!(
            classify(
                false,
                Some(libc::O_RDONLY | libc::O_NONBLOCK | libc::O_APPEND)
            ),
            Some(Unwritable::NotForWriting),
            "O_RDONLY with status flags"
        );
    }

    /// An `O_PATH` descriptor cannot be written.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn classify_path_only_is_refused() {
        assert_eq!(
            classify(false, Some(libc::O_PATH)),
            Some(Unwritable::NotForWriting),
            "O_PATH"
        );
    }

    /// A descriptor `fcntl` cannot read is closed.
    #[test]
    fn classify_no_flags_is_closed() {
        assert_eq!(
            classify(false, None),
            Some(Unwritable::Closed),
            "F_GETFL failed"
        );
    }

    /// Closed at start wins over the `/dev/null` the runtime put there.
    #[test]
    fn classify_closed_at_exec_is_closed() {
        assert_eq!(
            classify(true, Some(libc::O_RDWR)),
            Some(Unwritable::Closed),
            "closed at exec, /dev/null now"
        );
    }

    /// Closed at start and unreadable now: still closed.
    #[test]
    fn classify_closed_at_exec_and_now_is_closed() {
        assert_eq!(
            classify(true, None),
            Some(Unwritable::Closed),
            "closed twice"
        );
    }

    /// Closed at start is named closed even when the descriptor is read-only.
    #[test]
    fn classify_closed_at_exec_beats_read_only() {
        assert_eq!(
            classify(true, Some(libc::O_RDONLY)),
            Some(Unwritable::Closed),
            "closed at exec, read-only now"
        );
    }

    // ── Checked ──────────────────────────────────────────────────────

    /// A writable output lets every write through.
    #[test]
    fn checked_passes_writes_through() -> Result<(), TestError> {
        let mut w = Checked::with_refusal(Vec::new(), None);
        w.write_all(b"one ")?;
        write!(w, "{}", 2)?;
        w.flush()?;
        assert_eq!(w.inner, b"one 2", "the bytes arrive");
        Ok(())
    }

    /// A refused write writes nothing and names the reason.
    #[test]
    fn checked_refuses_a_write_of_a_closed_output() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::Closed));
        let e = w.write(b"x").err();
        assert_eq!(
            e.as_ref().map(ToString::to_string).as_deref(),
            Some("standard output is closed"),
            "the reason"
        );
        assert!(w.inner.is_empty(), "nothing written");
    }

    /// `write_all` is refused like `write`.
    #[test]
    fn checked_refuses_write_all() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::NotForWriting));
        let r = w.write_all(b"x");
        assert!(r.as_ref().is_err_and(is_unwritable), "refused: {r:?}");
        assert!(w.inner.is_empty(), "nothing written");
    }

    /// `write!` is refused like `write`.
    #[test]
    fn checked_refuses_formatted_writes() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::NotForWriting));
        let r = write!(w, "{}", 1);
        assert!(r.is_err(), "refused");
        assert!(w.inner.is_empty(), "nothing written");
    }

    /// A refusal is not a closed pipe: callers that ignore `| head` must
    /// still see it.
    #[test]
    fn a_refusal_is_not_a_broken_pipe() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::Closed));
        let r = write_to(&mut w, format_args!("x"));
        assert!(
            r.as_ref()
                .is_err_and(|e| e.kind() != std::io::ErrorKind::BrokenPipe),
            "write_to keeps it: {r:?}"
        );
    }

    /// An empty write is not refused: nothing would be lost.
    #[test]
    fn checked_lets_an_empty_write_through() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::Closed));
        assert_eq!(w.write(b"").ok(), Some(0), "empty write");
        assert!(w.write_all(b"").is_ok(), "empty write_all");
    }

    /// A flush is not refused: it writes nothing a refused write left.
    #[test]
    fn checked_lets_a_flush_through() {
        let mut w = Checked::with_refusal(Vec::new(), Some(Unwritable::Closed));
        assert!(w.flush().is_ok(), "flush");
    }

    /// Behind a buffer, the refusal surfaces at the flush that writes.
    #[test]
    fn checked_behind_a_buffer_refuses_at_flush() {
        let inner = Checked::with_refusal(Vec::new(), Some(Unwritable::NotForWriting));
        let mut w = std::io::BufWriter::new(inner);
        assert!(w.write_all(b"x").is_ok(), "buffered, not yet written");
        let r = w.flush();
        assert!(r.as_ref().is_err_and(is_unwritable), "refused: {r:?}");
    }

    /// Behind an empty buffer, a flush writes nothing and is not refused.
    #[test]
    fn checked_behind_an_empty_buffer_flushes() {
        let inner = Checked::with_refusal(Vec::new(), Some(Unwritable::Closed));
        let mut w = std::io::BufWriter::new(inner);
        assert!(w.flush().is_ok(), "nothing to write");
    }

    // ── the reasons and the codes ────────────────────────────────────

    /// The two reasons read as their stderr lines name them.
    #[test]
    fn the_reasons_have_names() {
        assert_eq!(
            Unwritable::Closed.to_string(),
            "standard output is closed",
            "the closed name"
        );
        assert_eq!(
            Unwritable::NotForWriting.to_string(),
            "standard output is not open for writing",
            "the not-for-writing name"
        );
    }

    /// A refusal is recognized; any other error is not.
    #[test]
    fn is_unwritable_tells_a_refusal_from_other_errors() {
        assert!(is_unwritable(&refusal(Unwritable::Closed)), "refusal");
        assert!(
            !is_unwritable(&std::io::Error::from(std::io::ErrorKind::StorageFull)),
            "ENOSPC"
        );
        assert!(
            !is_unwritable(&std::io::Error::from_raw_os_error(libc::EBADF)),
            "a raw EBADF is not this refusal"
        );
        assert!(!is_unwritable(&std::io::Error::other("text")), "other text");
    }

    /// A refusal exits 6, any other output error 1.
    #[test]
    fn exit_code_for_names_the_code() {
        assert_eq!(
            exit_code_for(&refusal(Unwritable::NotForWriting)),
            6,
            "refusal"
        );
        assert_eq!(
            exit_code_for(&std::io::Error::from(std::io::ErrorKind::StorageFull)),
            1,
            "ENOSPC"
        );
    }

    /// The documented code.
    #[test]
    fn the_code_is_6() {
        assert_eq!(UNWRITABLE_EXIT_CODE, 6, "the documented code");
    }

    /// A refused run that would have succeeded exits 6.
    #[test]
    fn adjust_turns_success_into_6() {
        assert_eq!(adjust_exit_code(0, true), 6, "0 refused");
    }

    /// A refused run whose output failed exits 6, not 1.
    #[test]
    fn adjust_turns_output_failure_into_6() {
        assert_eq!(adjust_exit_code(1, true), 6, "1 refused");
    }

    /// Any other code is kept: usage (2), a failed check (3), low disk (4),
    /// the worker's 5.
    #[test]
    fn adjust_keeps_other_codes() {
        for code in [2, 3, 4, 5, 101, 129, 130] {
            assert_eq!(adjust_exit_code(code, true), code, "code {code} kept");
        }
    }

    /// No refusal: every code is kept.
    #[test]
    fn adjust_without_a_refusal_keeps_the_code() {
        for code in [0, 1, 2, 3, 4, 5, 6, 101, 129] {
            assert_eq!(adjust_exit_code(code, false), code, "code {code} kept");
        }
    }
}
