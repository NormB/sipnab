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
/// A closed pipe is ignored. Any other write error is logged and the run
/// exits 1.
pub fn emit(args: std::fmt::Arguments<'_>) {
    if let Err(e) = write_to(&mut std::io::stdout().lock(), args) {
        tracing::error!("writing to standard output failed: {e}");
        crate::capture::archive::release_run_and_exit(1);
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
}
