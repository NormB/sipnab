//! Buffered stdout sink for batch-mode per-message output.
//!
//! The batch receive loop used to emit every SIP message through `print!` /
//! `println!`: Rust's stdout is line-buffered, so a 70k-message offline run
//! paid 70k `write(2)` syscalls plus a stdout lock/unlock per message —
//! measured at ~40% of the wall time of `sipnab -N --json -I file.pcap`.
//!
//! `BatchSink` wraps one writer (a 64 KiB `BufWriter<Stdout>` in
//! production) that every per-message emitter in the batch loop shares, so
//! output ordering is preserved while syscalls collapse to one per buffer
//! fill. The receive loop flushes it whenever the packet channel goes idle
//! (live capture stays real-time) and at end of capture; `--line-buffer`
//! keeps its contract by flushing after every message.
//!
//! Writes are best-effort, matching the existing text path
//! (`print_sip_message`): a broken pipe (e.g. `sipnab ... | head`) must not
//! panic the capture process.

use std::io::Write;

/// Shared buffered writer for every per-message emitter in the batch loop.
///
/// All writes are best-effort: errors (broken pipe) are swallowed so a
/// downstream `| head` never panics the capture process. `line_buffer`
/// preserves the `--line-buffer` contract of one flush per message.
pub struct BatchSink<W: Write> {
    /// The wrapped writer all emitters share.
    w: W,
    /// When `true`, `end_message` flushes after every message
    /// (`--line-buffer`).
    line_buffer: bool,
}

impl BatchSink<std::io::BufWriter<std::io::Stdout>> {
    /// Production sink: a 64 KiB buffer in front of stdout. Stdout's own
    /// line buffering only sees whole buffer fills, so per-message
    /// `write(2)` syscalls collapse to a couple per 64 KiB.
    pub fn stdout(line_buffer: bool) -> Self {
        Self::new(
            std::io::BufWriter::with_capacity(64 * 1024, std::io::stdout()),
            line_buffer,
        )
    }
}

impl<W: Write> BatchSink<W> {
    /// Wrap `w`; `line_buffer` mirrors the CLI's `--line-buffer` flag.
    pub fn new(w: W, line_buffer: bool) -> Self {
        Self { w, line_buffer }
    }

    /// Write a string, best-effort.
    pub fn write_str(&mut self, s: &str) {
        let _ = self.w.write_all(s.as_bytes());
    }

    /// Write formatted output, best-effort (enables `write!(sink, ...)`).
    pub fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) {
        let _ = self.w.write_fmt(args);
    }

    /// Direct access to the underlying writer, for zero-copy serializers
    /// (`serde_json::to_writer`). Callers must treat errors as best-effort.
    pub fn writer(&mut self) -> &mut W {
        &mut self.w
    }

    /// Mark the end of one message: flushes only under `--line-buffer`.
    pub fn end_message(&mut self) {
        if self.line_buffer {
            self.flush();
        }
    }

    /// Flush the buffer, best-effort. The batch loop calls this when the
    /// packet channel goes idle and at end of capture.
    pub fn flush(&mut self) {
        let _ = self.w.flush();
    }

    /// Consume the sink and return the underlying writer (test helper).
    pub fn into_inner(self) -> W {
        self.w
    }

    /// Borrow the underlying writer (test helper).
    pub fn get_ref(&self) -> &W {
        &self.w
    }
}

// ── Tests ────────────────────────────────────────────────────────────

/// Tests for pass-through writes, flush semantics, and best-effort error
/// swallowing via an instrumented probe writer.
#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that records flush calls and can be told to fail writes.
    struct Probe {
        /// Bytes successfully written.
        buf: Vec<u8>,
        /// Number of `flush` calls observed.
        flushes: usize,
        /// When `true`, every write fails with `BrokenPipe`.
        fail_writes: bool,
    }

    impl Probe {
        /// A fresh probe: empty buffer, zero flushes, writes succeed.
        fn new() -> Self {
            Self {
                buf: Vec::new(),
                flushes: 0,
                fail_writes: false,
            }
        }
    }

    impl Write for Probe {
        /// Record `data` into the buffer, or fail with `BrokenPipe` when
        /// `fail_writes` is set.
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.fail_writes {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.buf.extend_from_slice(data);
            Ok(data.len())
        }
        /// Count the flush call; always succeeds.
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// Consecutive `write_str` calls append bytes unmodified.
    #[test]
    fn write_str_passes_bytes_through() {
        let mut sink = BatchSink::new(Probe::new(), false);
        sink.write_str("hello ");
        sink.write_str("world\n");
        assert_eq!(sink.get_ref().buf, b"hello world\n");
    }

    /// `write!` formatting lands in the underlying writer.
    #[test]
    fn write_fmt_formats_into_sink() {
        let mut sink = BatchSink::new(Probe::new(), false);
        let (a, b) = ("a", "b");
        write!(sink, "{a} {b}:{}", 42);
        assert_eq!(sink.get_ref().buf, b"a b:42");
    }

    /// `end_message` flushes only when `line_buffer` is set.
    #[test]
    fn end_message_flushes_only_in_line_buffer_mode() {
        let mut sink = BatchSink::new(Probe::new(), false);
        sink.write_str("x");
        sink.end_message();
        assert_eq!(
            sink.get_ref().flushes,
            0,
            "no per-message flush without --line-buffer"
        );

        let mut sink = BatchSink::new(Probe::new(), true);
        sink.write_str("x");
        sink.end_message();
        assert_eq!(
            sink.get_ref().flushes,
            1,
            "--line-buffer must flush after every message"
        );
    }

    /// An explicit `flush` reaches the underlying writer.
    #[test]
    fn flush_is_forwarded() {
        let mut sink = BatchSink::new(Probe::new(), false);
        sink.write_str("x");
        sink.flush();
        assert_eq!(sink.get_ref().flushes, 1);
    }

    /// Failing writes (broken pipe) are swallowed without panicking.
    #[test]
    fn broken_pipe_does_not_panic() {
        // Adversarial: downstream `| head` closes the pipe mid-stream. The
        // sink must swallow the error (matching print_sip_message's
        // best-effort contract), not panic the capture process.
        let mut probe = Probe::new();
        probe.fail_writes = true;
        let mut sink = BatchSink::new(probe, true);
        sink.write_str("dropped");
        let also_dropped = "dropped too";
        write!(sink, "{also_dropped}");
        sink.end_message();
        sink.flush();
        assert!(sink.get_ref().buf.is_empty());
    }

    /// Empty writes and NUL/backslash/multi-byte UTF-8 pass through intact.
    #[test]
    fn empty_and_special_bytes_round_trip() {
        // Boundary/adversarial: empty writes, embedded NUL, backslashes and
        // multi-byte UTF-8 must pass through unmodified.
        let mut sink = BatchSink::new(Probe::new(), false);
        sink.write_str("");
        sink.write_str("a\\b\"c\u{0}d\u{00e9}");
        assert_eq!(sink.get_ref().buf, "a\\b\"c\u{0}d\u{00e9}".as_bytes());
    }
}
