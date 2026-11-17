// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Waiting for input in a way that a stop signal ends
//! (STDIN-READ-IGNORES-STOP).
//!
//! sipnab's handlers for SIGTERM, SIGINT and SIGHUP only set a flag
//! ([`crate::signals`]), and they are installed with `SA_RESTART`. So a
//! blocking `read(2)` that one of these signals interrupts starts again, and
//! nothing reads the flag until input arrives or the input ends. A run that
//! waited that way for standard input (`--vcon-fetch -`) could be ended only
//! with SIGKILL.
//!
//! Every wait for input therefore goes through [`poll_one`]: `poll(2)` for at
//! most a set time, which a signal ends with `EINTR` whatever `SA_RESTART`
//! says, so the caller checks its stop flag before it waits again. The
//! terminal interface ([`crate::tui`]'s terminal input), the archive
//! password prompt and [`read_to_string_unless_stopped`] use it.

use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd as _, RawFd};
use std::time::Duration;

/// How long one wait lasts before the caller checks its stop flag again:
/// the longest a stop waits to be noticed.
pub const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// The bytes each read asks for. Above the 8 KiB buffer of
/// [`std::io::Stdin`], so its reads go to the descriptor and leave nothing
/// in that buffer for a `poll(2)` of the descriptor to miss.
const CHUNK: usize = 64 * 1024;

/// Wait up to `timeout` for `events` on `fd`: the `revents` `poll(2)`
/// reported, or 0 when the wait timed out or a signal interrupted it. On 0
/// the caller checks its stop flag before it waits again.
///
/// Linux reports `POLLHUP`, `POLLERR` and `POLLNVAL` whatever `events` asks.
/// macOS reported no hang-up for a pipe with no reader when `events` was 0,
/// so a caller that must see a hang-up there asks for an event.
///
/// # Errors
///
/// `poll(2)` failed for a reason other than a signal.
pub fn poll_one(fd: RawFd, events: libc::c_short, timeout: Duration) -> io::Result<libc::c_short> {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `pfd` is one valid pollfd, and the count passed is 1. A
    // descriptor that is not open is reported as POLLNVAL, not undefined.
    let ready = unsafe { libc::poll(&mut pfd, 1, millis) };
    if ready < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(if ready == 0 { 0 } else { pfd.revents })
}

/// Read `src` to its end as UTF-8 text, as [`Read::read_to_string`] does,
/// unless `stopped` returns `true` first: then `Ok(None)`, with whatever
/// was read dropped. `stopped` is called before every wait, so a stop is
/// seen within [`POLL_INTERVAL`] of its signal.
///
/// For [`std::io::Stdin`], a closed descriptor 0 reads as empty, as
/// `read_to_string` reads it.
///
/// # Errors
///
/// A read or `poll(2)` failed, or the text is not UTF-8
/// ([`io::ErrorKind::InvalidData`]).
pub fn read_to_string_unless_stopped<R: Read + AsFd>(
    src: &mut R,
    stopped: &dyn Fn() -> bool,
) -> io::Result<Option<String>> {
    let fd = src.as_fd().as_raw_fd();
    let mut bytes = Vec::new();
    let mut chunk = vec![0u8; CHUNK];
    loop {
        if stopped() {
            return Ok(None);
        }
        if poll_one(fd, libc::POLLIN, POLL_INTERVAL)? == 0 {
            continue;
        }
        // Readable, at its end, or failed: this read does not wait.
        match src.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Text and then the end of input: the whole text.
    #[test]
    fn reads_to_the_end() -> TestResult {
        let (mut reader, mut writer) = std::io::pipe()?;
        writer.write_all(b"aaaa-1\n# note\nbbbb-2\n")?;
        drop(writer);
        let text = read_to_string_unless_stopped(&mut reader, &|| false)?;
        assert_eq!(
            text.as_deref(),
            Some("aaaa-1\n# note\nbbbb-2\n"),
            "the whole text, up to the end of input"
        );
        Ok(())
    }

    /// More than one read's worth arrives whole.
    #[test]
    fn reads_past_one_chunk() -> TestResult {
        let (mut reader, mut writer) = std::io::pipe()?;
        let big = "x".repeat(CHUNK * 3 + 7);
        let sent = big.clone();
        let feeder = std::thread::spawn(move || writer.write_all(sent.as_bytes()));
        let text = read_to_string_unless_stopped(&mut reader, &|| false)?;
        feeder.join().map_err(|_| "feeder panicked")??;
        assert_eq!(
            text.map(|t| t.len()),
            Some(big.len()),
            "every byte of a text longer than one read"
        );
        Ok(())
    }

    /// Read `reader` on its own thread with a stop that answers `true` from
    /// its `stop_at`-th question on (never when `stop_at` is 0), while this
    /// thread holds `writer` open.
    ///
    /// # Returns
    ///
    /// What the read returned and how many times it asked whether to stop.
    /// A read that does not ask between waits never ends while the writer
    /// is open; after `CEILING`, far past any wait, the writer is closed so
    /// the read ends at the end of input and the test fails on the text it
    /// returns instead of hanging.
    fn counted_read(
        mut reader: std::io::PipeReader,
        writer: std::io::PipeWriter,
        stop_at: u32,
    ) -> Result<(Option<String>, u32), Box<dyn std::error::Error>> {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        const CEILING: Duration = Duration::from_secs(60);
        let asked = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&asked);
        let (tx, rx) = std::sync::mpsc::channel();
        let reading = std::thread::spawn(move || {
            let stopped = || {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                stop_at != 0 && n >= stop_at
            };
            let text = read_to_string_unless_stopped(&mut reader, &stopped);
            let _ = tx.send(());
            text
        });
        let _ = rx.recv_timeout(CEILING);
        drop(writer);
        let text = reading.join().map_err(|_| "the reader panicked")??;
        Ok((text, asked.load(Ordering::SeqCst)))
    }

    /// A stop while the input is open and idle ends the read with `None`: the
    /// writer is still open, so the input never ends.
    ///
    /// Proved by the count of questions, not by a stopwatch (this test once
    /// asserted "under ten waits", 2 s, which a loaded host can pass): the
    /// first wait reads the queued bytes, the second times out, and the
    /// third question says stop.
    #[test]
    fn a_stop_ends_a_read_of_idle_input() -> TestResult {
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(b"partial")?;
        let (text, asked) = counted_read(reader, writer, 3)?;
        assert_eq!(
            text, None,
            "a stopped read returned text: the stop was not asked between waits"
        );
        assert_eq!(
            asked, 3,
            "the read ends at the first yes, the third question"
        );
        Ok(())
    }

    /// The stop is asked before every wait, idle or not: a stop that says yes
    /// on its fifth question ends the read after exactly five.
    #[test]
    fn the_stop_is_asked_before_every_wait() -> TestResult {
        let (reader, writer) = std::io::pipe()?;
        let (text, asked) = counted_read(reader, writer, 5)?;
        assert_eq!(text, None, "a stopped read returned text");
        assert_eq!(
            asked, 5,
            "one question per wait, and the read ends at the yes"
        );
        Ok(())
    }

    /// Input that ends before any stop is read whole, asking once per wait:
    /// one wait for the bytes and one for the end of input.
    #[test]
    fn input_that_ends_first_is_read_whole_asking_once_per_wait() -> TestResult {
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(b"aaaa-1\n")?;
        let (_keep, unused) = std::io::pipe()?;
        drop(writer);
        let (text, asked) = counted_read(reader, unused, 0)?;
        assert_eq!(text.as_deref(), Some("aaaa-1\n"), "the whole text");
        assert_eq!(asked, 2, "one question before each of the two waits");
        Ok(())
    }

    /// A stop already requested reads nothing at all, and is asked once.
    #[test]
    fn a_stop_before_the_read_reads_nothing() -> TestResult {
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(b"aaaa-1\n")?;
        let (text, asked) = counted_read(reader, writer, 1)?;
        assert_eq!(
            text, None,
            "a stop requested before the read returns no text"
        );
        assert_eq!(asked, 1, "the first question says stop; no wait follows");
        Ok(())
    }

    /// Bytes that are not UTF-8 are refused, as `read_to_string` refuses
    /// them.
    #[test]
    fn text_that_is_not_utf8_is_refused() -> TestResult {
        let (mut reader, mut writer) = std::io::pipe()?;
        writer.write_all(&[0xff, 0xfe, b'\n'])?;
        drop(writer);
        let e = read_to_string_unless_stopped(&mut reader, &|| false)
            .err()
            .ok_or("bytes that are not UTF-8 were accepted")?;
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        Ok(())
    }

    /// An idle descriptor times out with 0; a readable one reports POLLIN;
    /// one whose writer has gone reports POLLHUP.
    #[test]
    fn poll_one_reports_what_poll_saw() -> TestResult {
        let (reader, mut writer) = std::io::pipe()?;
        let fd = reader.as_fd().as_raw_fd();
        assert_eq!(poll_one(fd, libc::POLLIN, Duration::ZERO)?, 0, "idle");
        writer.write_all(b"x")?;
        assert_ne!(
            poll_one(fd, libc::POLLIN, Duration::ZERO)? & libc::POLLIN,
            0,
            "readable"
        );
        drop(writer);
        assert_ne!(
            poll_one(fd, libc::POLLIN, Duration::ZERO)? & libc::POLLHUP,
            0,
            "hung up"
        );
        Ok(())
    }
}
