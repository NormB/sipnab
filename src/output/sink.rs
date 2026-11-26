// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
/// A downstream `| head` closing the pipe must never fail the capture, so
/// `BrokenPipe` is swallowed. Every OTHER error is remembered.
///
/// That distinction is the whole point. This type used to swallow all errors
/// alike, which matched its stated intent for `| head` but also meant
/// `sipnab --json > out.ndjson` on a full disk wrote a truncated file and
/// exited 0. The two cases look identical to `write_all` and are opposite in
/// meaning: one is a reader that stopped caring, the other is data loss.
///
/// `line_buffer` preserves the `--line-buffer` contract of one flush per
/// message.
pub struct BatchSink<W: Write> {
    /// The wrapped writer all emitters share.
    w: W,
    /// When `true`, `end_message` flushes after every message
    /// (`--line-buffer`).
    line_buffer: bool,
    /// First non-`BrokenPipe` write/flush error, if any. Kept rather than
    /// returned so the hot per-message path stays infallible.
    hard_error: Option<std::io::Error>,
    /// Called once, with the first non-`BrokenPipe` error, when it happens
    /// (FILE-2 d): the batch loop prints a line at once instead of only at
    /// the end of the run, which for a live capture can be days later.
    on_first_failure: Option<FirstFailure>,
}

/// What [`BatchSink`] calls with its first hard error.
pub type FirstFailure = Box<dyn FnMut(&std::io::Error) + Send>;

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
        Self {
            w,
            line_buffer,
            hard_error: None,
            on_first_failure: None,
        }
    }

    /// Call `f` once, with the first non-`BrokenPipe` error, at the moment
    /// [`BatchSink::record`] keeps it.
    #[must_use]
    pub fn on_first_failure(mut self, f: FirstFailure) -> Self {
        self.on_first_failure = Some(f);
        self
    }

    /// Record `r` unless it succeeded or failed with `BrokenPipe`.
    ///
    /// Only the first is kept: later writes to a broken sink fail too, and the
    /// first failure is the one that explains what happened.
    pub fn record(&mut self, r: std::io::Result<()>) {
        if let Err(e) = r
            && e.kind() != std::io::ErrorKind::BrokenPipe
            && self.hard_error.is_none()
        {
            if let Some(f) = self.on_first_failure.as_mut() {
                f(&e);
            }
            self.hard_error = Some(e);
        }
    }

    /// The first non-`BrokenPipe` error seen, if any.
    ///
    /// Callers use this to decide the process exit code: output that could not
    /// be written must not be reported as success.
    pub fn hard_error(&self) -> Option<&std::io::Error> {
        self.hard_error.as_ref()
    }

    /// Write a string, best-effort.
    pub fn write_str(&mut self, s: &str) {
        let r = self.w.write_all(s.as_bytes());
        self.record(r);
    }

    /// Write formatted output, best-effort (enables `write!(sink, ...)`).
    pub fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) {
        let r = self.w.write_fmt(args);
        self.record(r);
    }

    /// Direct access to the underlying writer, for zero-copy serializers
    /// (`serde_json::to_writer`). Errors here bypass this type's tracking, so
    /// callers must feed the result back through [`BatchSink::record`].
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
        let r = self.w.flush();
        self.record(r);
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

    // ── FILE-2 (d): the first hard failure is reported when it happens ──
    //
    // `u_s_` success, `u_f_` no call expected, `u_e_` edge. The binary's line
    // is tested in tests/stdout_first_failure_test.rs.

    use std::collections::VecDeque;
    use std::io::ErrorKind;
    use std::sync::mpsc;

    /// A writer whose writes and flushes fail as scripted.
    #[derive(Default)]
    struct Failing {
        /// Bytes written.
        buf: Vec<u8>,
        /// The outcome of each next write: `Some(kind)` fails with `kind`,
        /// `None` succeeds. When empty, `then` applies.
        script: VecDeque<Option<ErrorKind>>,
        /// The outcome of every write after the script.
        then: Option<ErrorKind>,
        /// When set, every flush fails with it.
        flush_err: Option<ErrorKind>,
    }

    impl Failing {
        /// Every write and flush fails with `kind`.
        fn always(kind: ErrorKind) -> Self {
            Self {
                then: Some(kind),
                flush_err: Some(kind),
                ..Self::default()
            }
        }

        /// Writes succeed and every flush fails with `kind`.
        fn flush_fails(kind: ErrorKind) -> Self {
            Self {
                flush_err: Some(kind),
                ..Self::default()
            }
        }

        /// The writes fail in the order of `script`, then succeed.
        fn scripted(script: &[Option<ErrorKind>]) -> Self {
            Self {
                script: script.iter().copied().collect(),
                ..Self::default()
            }
        }
    }

    impl Write for Failing {
        /// Fail as scripted, or append `data`.
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            match self.script.pop_front().unwrap_or(self.then) {
                Some(kind) => Err(std::io::Error::new(kind, format!("scripted {kind:?}"))),
                None => {
                    self.buf.extend_from_slice(data);
                    Ok(data.len())
                }
            }
        }
        /// Fail with `flush_err` when set.
        fn flush(&mut self) -> std::io::Result<()> {
            match self.flush_err {
                Some(kind) => Err(std::io::Error::new(kind, format!("scripted {kind:?}"))),
                None => Ok(()),
            }
        }
    }

    /// A callback that sends each call's error kind and text, and the
    /// receiver that collects them.
    fn recorder() -> (FirstFailure, mpsc::Receiver<(ErrorKind, String)>) {
        let (tx, rx) = mpsc::channel();
        let f: FirstFailure = Box::new(move |e: &std::io::Error| {
            let _ = tx.send((e.kind(), e.to_string()));
        });
        (f, rx)
    }

    /// The calls received so far.
    fn calls(rx: &mpsc::Receiver<(ErrorKind, String)>) -> Vec<(ErrorKind, String)> {
        rx.try_iter().collect()
    }

    /// A sink over `w` with a recorder.
    fn sink_with(
        w: Failing,
        line_buffer: bool,
    ) -> (BatchSink<Failing>, mpsc::Receiver<(ErrorKind, String)>) {
        let (f, rx) = recorder();
        (BatchSink::new(w, line_buffer).on_first_failure(f), rx)
    }

    /// The first hard error calls the callback once, with that error.
    #[test]
    fn u_s_the_first_hard_error_is_reported_once() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("x");
        let got = calls(&rx);
        assert_eq!(got.len(), 1, "one call: {got:?}");
        assert_eq!(got[0].0, ErrorKind::StorageFull, "with the error: {got:?}");
    }

    /// A failing flush is reported.
    #[test]
    fn u_s_a_failing_flush_is_reported() {
        let w = Failing::flush_fails(ErrorKind::StorageFull);
        let (mut sink, rx) = sink_with(w, false);
        sink.write_str("x");
        assert!(calls(&rx).is_empty(), "the write itself succeeded");
        sink.flush();
        assert_eq!(calls(&rx).len(), 1, "the flush failure is reported");
    }

    /// A failing `write!` is reported.
    #[test]
    fn u_s_a_failing_write_fmt_is_reported() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        write!(sink, "{}", 42);
        assert_eq!(calls(&rx).len(), 1, "write! failure reported");
    }

    /// A failing `write_str` is reported.
    #[test]
    fn u_s_a_failing_write_str_is_reported() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::PermissionDenied), false);
        sink.write_str("line\n");
        let got = calls(&rx);
        assert_eq!(got.len(), 1, "one call: {got:?}");
        assert_eq!(got[0].0, ErrorKind::PermissionDenied, "its kind: {got:?}");
    }

    /// Under `--line-buffer`, the flush at the end of a message reports.
    #[test]
    fn u_s_a_line_buffered_message_end_is_reported() {
        let w = Failing::flush_fails(ErrorKind::StorageFull);
        let (mut sink, rx) = sink_with(w, true);
        sink.write_str("x");
        sink.end_message();
        assert_eq!(calls(&rx).len(), 1, "the per-message flush reports");
    }

    /// An error fed back through `record` (the zero-copy writer path) is
    /// reported.
    #[test]
    fn u_s_an_error_fed_back_through_record_is_reported() {
        let (mut sink, rx) = sink_with(Failing::default(), false);
        let r = sink
            .writer()
            .write_all(b"x")
            .and(Err(std::io::Error::from(ErrorKind::StorageFull)));
        sink.record(r);
        assert_eq!(calls(&rx).len(), 1, "record reports");
    }

    /// The callback gets the error's own text.
    #[test]
    fn u_s_the_error_text_reaches_the_callback() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("x");
        let got = calls(&rx);
        assert_eq!(
            got.first().map(|c| c.1.as_str()),
            Some("scripted StorageFull"),
            "the text: {got:?}"
        );
    }

    /// The error is still kept for the end of the run.
    #[test]
    fn u_s_the_error_is_still_kept() {
        let (mut sink, _rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("x");
        assert_eq!(
            sink.hard_error().map(std::io::Error::kind),
            Some(ErrorKind::StorageFull),
            "hard_error keeps it"
        );
    }

    /// The call happens at the failing write, before any flush.
    #[test]
    fn u_s_the_call_happens_at_the_failure() {
        let (mut sink, rx) = sink_with(
            Failing::scripted(&[None, Some(ErrorKind::StorageFull)]),
            false,
        );
        sink.write_str("a");
        assert!(calls(&rx).is_empty(), "no call after the good write");
        sink.write_str("b");
        assert_eq!(calls(&rx).len(), 1, "the call at the failing write");
    }

    /// The sink stays usable after a failure.
    #[test]
    fn u_s_the_sink_goes_on_after_the_failure() {
        let (mut sink, rx) = sink_with(Failing::scripted(&[Some(ErrorKind::StorageFull)]), false);
        sink.write_str("lost");
        sink.write_str("kept");
        assert_eq!(sink.get_ref().buf, b"kept", "later writes still go through");
        assert_eq!(calls(&rx).len(), 1, "one call");
    }

    /// The production constructor takes the callback.
    #[test]
    fn u_s_the_stdout_sink_takes_a_callback() {
        let (f, rx) = recorder();
        let sink = BatchSink::stdout(false).on_first_failure(f);
        assert!(sink.hard_error().is_none(), "nothing failed");
        assert!(calls(&rx).is_empty(), "no call without a failure");
    }

    /// Writes that succeed never call.
    #[test]
    fn u_f_good_writes_never_call() {
        let (mut sink, rx) = sink_with(Failing::default(), true);
        for _ in 0..100 {
            sink.write_str("x");
            sink.end_message();
        }
        sink.flush();
        assert!(calls(&rx).is_empty(), "no failure, no call");
    }

    /// A closed pipe on write never calls.
    #[test]
    fn u_f_a_closed_pipe_on_write_never_calls() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::BrokenPipe), false);
        sink.write_str("x");
        assert!(calls(&rx).is_empty(), "EPIPE is not reported");
    }

    /// A closed pipe on flush never calls.
    #[test]
    fn u_f_a_closed_pipe_on_flush_never_calls() {
        let w = Failing::flush_fails(ErrorKind::BrokenPipe);
        let (mut sink, rx) = sink_with(w, true);
        sink.write_str("x");
        sink.end_message();
        sink.flush();
        assert!(calls(&rx).is_empty(), "EPIPE on flush is not reported");
    }

    /// Many closed-pipe errors never call.
    #[test]
    fn u_f_many_closed_pipe_errors_never_call() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::BrokenPipe), true);
        for _ in 0..1000 {
            sink.write_str("x");
            sink.end_message();
        }
        assert!(calls(&rx).is_empty(), "no call for EPIPE");
    }

    /// `record(Ok)` never calls.
    #[test]
    fn u_f_record_ok_never_calls() {
        let (mut sink, rx) = sink_with(Failing::default(), false);
        sink.record(Ok(()));
        assert!(calls(&rx).is_empty(), "Ok is not a failure");
    }

    /// After a closed pipe there is nothing kept and nothing called.
    #[test]
    fn u_f_a_closed_pipe_keeps_nothing() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::BrokenPipe), false);
        sink.write_str("x");
        assert!(sink.hard_error().is_none(), "EPIPE is not kept");
        assert!(calls(&rx).is_empty(), "and not reported");
    }

    /// A second hard error does not call again.
    #[test]
    fn u_f_a_second_hard_error_does_not_call_again() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("a");
        sink.write_str("b");
        assert_eq!(calls(&rx).len(), 1, "one call for two failures");
    }

    /// Without a callback the first error is still kept.
    #[test]
    fn u_f_without_a_callback_the_error_is_kept() {
        let mut sink = BatchSink::new(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("x");
        assert!(sink.hard_error().is_some(), "kept with no callback");
    }

    /// A closed pipe through `write!` never calls.
    #[test]
    fn u_f_a_closed_pipe_through_write_fmt_never_calls() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::BrokenPipe), false);
        write!(sink, "{}", 1);
        assert!(
            calls(&rx).is_empty(),
            "EPIPE through write! is not reported"
        );
    }

    /// A closed pipe and then a hard error: one call, with the hard error.
    #[test]
    fn u_e_a_closed_pipe_then_a_hard_error_reports_the_hard_one() {
        let (mut sink, rx) = sink_with(
            Failing::scripted(&[Some(ErrorKind::BrokenPipe), Some(ErrorKind::StorageFull)]),
            false,
        );
        sink.write_str("a");
        sink.write_str("b");
        let got = calls(&rx);
        assert_eq!(got.len(), 1, "one call: {got:?}");
        assert_eq!(got[0].0, ErrorKind::StorageFull, "the hard one: {got:?}");
    }

    /// Ten thousand failing writes: one call.
    #[test]
    fn u_e_ten_thousand_failures_make_one_call() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), true);
        for _ in 0..10_000 {
            sink.write_str("x");
            sink.end_message();
        }
        assert_eq!(calls(&rx).len(), 1, "one call");
    }

    /// Two kinds of hard error: the call carries the first.
    #[test]
    fn u_e_the_first_of_two_kinds_is_reported() {
        let (mut sink, rx) = sink_with(
            Failing::scripted(&[
                Some(ErrorKind::PermissionDenied),
                Some(ErrorKind::StorageFull),
            ]),
            false,
        );
        sink.write_str("a");
        sink.write_str("b");
        let got = calls(&rx);
        assert_eq!(got.len(), 1, "one call: {got:?}");
        assert_eq!(got[0].0, ErrorKind::PermissionDenied, "the first: {got:?}");
    }

    /// `WriteZero` (a writer that takes nothing) is a hard error.
    #[test]
    fn u_e_write_zero_is_reported() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::WriteZero), false);
        sink.write_str("x");
        assert_eq!(calls(&rx).len(), 1, "WriteZero reported");
    }

    /// An error of kind `Other` carries its own message to the callback.
    #[test]
    fn u_e_an_other_error_keeps_its_message() {
        let (mut sink, rx) = sink_with(Failing::default(), false);
        sink.record(Err(std::io::Error::other("disk went away")));
        let got = calls(&rx);
        assert_eq!(
            got.first().map(|c| c.1.as_str()),
            Some("disk went away"),
            "the message: {got:?}"
        );
    }

    /// A failure after good output: one call, the earlier bytes intact.
    #[test]
    fn u_e_a_failure_after_good_output_keeps_the_earlier_bytes() {
        let (mut sink, rx) = sink_with(
            Failing::scripted(&[None, None, Some(ErrorKind::StorageFull)]),
            false,
        );
        sink.write_str("a");
        sink.write_str("b");
        sink.write_str("c");
        assert_eq!(sink.get_ref().buf, b"ab", "the bytes before the failure");
        assert_eq!(calls(&rx).len(), 1, "one call");
    }

    /// An empty write to a failing writer writes nothing and calls nothing.
    #[test]
    fn u_e_an_empty_write_calls_nothing() {
        let w = Failing {
            then: Some(ErrorKind::StorageFull),
            ..Failing::default()
        };
        let (mut sink, rx) = sink_with(w, false);
        sink.write_str("");
        assert!(calls(&rx).is_empty(), "write_all of nothing does not write");
    }

    /// A second callback replaces the first: only it is called.
    #[test]
    fn u_e_a_second_callback_replaces_the_first() {
        let (first, rx1) = recorder();
        let (second, rx2) = recorder();
        let mut sink = BatchSink::new(Failing::always(ErrorKind::StorageFull), false)
            .on_first_failure(first)
            .on_first_failure(second);
        sink.write_str("x");
        assert!(calls(&rx1).is_empty(), "the replaced one is not called");
        assert_eq!(calls(&rx2).len(), 1, "the last one is");
    }

    /// Without `--line-buffer`, the end of a message does not flush, so a
    /// failing flush is not reached and not reported.
    #[test]
    fn u_e_no_flush_no_report_without_line_buffer() {
        let w = Failing::flush_fails(ErrorKind::StorageFull);
        let (mut sink, rx) = sink_with(w, false);
        sink.write_str("x");
        sink.end_message();
        assert!(calls(&rx).is_empty(), "the flush was not reached");
    }

    /// A failure on the very first write of the run is reported.
    #[test]
    fn u_e_a_failure_on_the_first_write_is_reported() {
        let (mut sink, rx) = sink_with(Failing::scripted(&[Some(ErrorKind::StorageFull)]), false);
        sink.write_str("first");
        assert_eq!(calls(&rx).len(), 1, "reported at once");
    }

    /// A failing write then a failing flush: still one call.
    #[test]
    fn u_e_a_failing_write_then_flush_make_one_call() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.write_str("x");
        sink.flush();
        assert_eq!(calls(&rx).len(), 1, "one call");
    }

    /// An error recorded directly, then failing writes: one call.
    #[test]
    fn u_e_a_recorded_error_then_failing_writes_make_one_call() {
        let (mut sink, rx) = sink_with(Failing::always(ErrorKind::StorageFull), false);
        sink.record(Err(std::io::Error::from(ErrorKind::TimedOut)));
        sink.write_str("x");
        let got = calls(&rx);
        assert_eq!(got.len(), 1, "one call: {got:?}");
        assert_eq!(got[0].0, ErrorKind::TimedOut, "the recorded one: {got:?}");
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
