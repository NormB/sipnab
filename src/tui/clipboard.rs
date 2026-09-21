// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared clipboard support for the TUI.
//!
//! Primary mechanism: OSC 52 — the escape sequence terminals map to
//! "set the system clipboard". It travels in-band over the pty, so it
//! works across SSH with no X11/Wayland display, which the helper
//! binaries (pbcopy/xclip) cannot do. The sequence is written to
//! `/dev/tty` (ratatui owns stdout; a shell redirect must not swallow
//! it), falling back to stdout only when the controlling terminal
//! cannot be opened.
//!
//! Belt and suspenders: after emitting OSC 52 (fire-and-forget — there
//! is no acknowledgment), the platform helper is also tried silently,
//! for local terminals without OSC 52 support. A missing helper is not
//! reported as a failure, because the OSC 52 write likely worked.

use std::io::Write;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Maximum raw bytes encoded into one OSC 52 sequence: 72 KiB.
///
/// Many terminals cap the whole OSC 52 sequence around 100 KB
/// (xterm's default `allowWindowOps` string limit is 100,000 bytes).
/// 73,728 raw bytes base64-encode to 98,304 bytes; with the 8-byte
/// framing the sequence stays comfortably under every known cap.
pub(in crate::tui) const OSC52_MAX_RAW_BYTES: usize = 73_728;

/// Build the OSC 52 clipboard sequence for `text`, bounding the payload
/// at [`OSC52_MAX_RAW_BYTES`] (truncated on a char boundary).
///
/// # Returns
/// `(sequence, copied_bytes, truncated)`: the full escape sequence
/// (`ESC ] 52 ; c ; <base64> BEL`), how many raw bytes of `text` were
/// encoded, and whether the input was truncated to fit the bound. Pure.
pub(in crate::tui) fn osc52_sequence(text: &str) -> (String, usize, bool) {
    let mut end = OSC52_MAX_RAW_BYTES.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = end < text.len();
    let payload = STANDARD.encode(&text.as_bytes()[..end]);
    (format!("\x1b]52;c;{payload}\x07"), end, truncated)
}

/// Write an OSC 52 sequence to the controlling terminal.
///
/// `/dev/tty` first — ratatui owns stdout, and a shell redirect of
/// stdout must not swallow (or corrupt) the sequence. Falls back to
/// stdout when the controlling terminal cannot be opened (e.g. no tty
/// in tests / under some service managers).
fn emit_osc52(sequence: &str) -> std::io::Result<()> {
    match std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        Ok(mut tty) => write_sequence(&mut tty, sequence),
        Err(_) => write_sequence(&mut std::io::stdout().lock(), sequence),
    }
}

/// Write `sequence` to `out` whole and flush it, so the terminal sees the
/// complete escape at once. Split from [`emit_osc52`] so the bytes that reach
/// the terminal can be checked against an in-memory writer.
fn write_sequence(out: &mut impl Write, sequence: &str) -> std::io::Result<()> {
    out.write_all(sequence.as_bytes())?;
    out.flush()
}

/// Run the platform clipboard helper (pbcopy/xclip) with a bounded wait
/// so a wedged helper is killed instead of leaking. Worker-thread only.
///
/// Best-effort: a missing binary or non-zero exit returns `None`
/// silently — OSC 52 is the primary mechanism and has likely already
/// worked, so a missing helper must not be reported as a failure.
///
/// # Returns
/// The helper's name on success, `None` otherwise.
fn helper_copy_bounded(text: &str) -> Option<&'static str> {
    let cmd = if cfg!(target_os = "macos") {
        "pbcopy"
    } else {
        "xclip"
    };
    let args: Vec<&str> = if cfg!(target_os = "macos") {
        vec![]
    } else {
        vec!["-selection", "clipboard"]
    };
    run_helper_bounded(cmd, &args, text, HELPER_TIMEOUT).then_some(cmd)
}

/// How long a clipboard helper may run before it is killed as wedged.
const HELPER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Run `cmd args`, feed it `text` on stdin, and wait at most `timeout` for it
/// to exit, killing it past the deadline. Worker-thread only.
///
/// Split from [`helper_copy_bounded`] so the bounded wait is exercised with
/// harmless commands; the real helpers would write the system clipboard.
///
/// # Returns
/// `true` only when the command started, took all of `text`, and exited
/// successfully within `timeout`.
fn run_helper_bounded(cmd: &str, args: &[&str], text: &str, timeout: std::time::Duration) -> bool {
    let Some(mut child) = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
    else {
        return false;
    };
    // Write, then drop stdin so the helper sees EOF and exits.
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(text.as_bytes()).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Copy `text` to the system clipboard, blocking the calling thread
/// (worker-thread only — use [`spawn_clipboard_copy`] from the UI).
///
/// OSC 52 first, then the platform helper silently; see the module
/// docs for the rationale.
///
/// # Returns
/// A human-readable outcome for the status line, e.g.
/// `"Copied 813 bytes (OSC 52 + xclip)"`, with a truncation note when
/// the OSC 52 bound cut the text.
pub(in crate::tui) fn copy_to_clipboard(text: &str) -> String {
    let (sequence, copied, truncated) = osc52_sequence(text);
    let osc_ok = emit_osc52(&sequence).is_ok();
    // The helper gets the SAME (possibly truncated) slice: both mechanisms
    // target the same system clipboard, and which write wins depends on the
    // terminal — the content must not differ between them.
    let helper = helper_copy_bounded(&text[..copied]);
    copy_outcome(osc_ok, helper, copied, text.len(), truncated)
}

/// The status-line outcome of a copy: which mechanisms reported success, how
/// many bytes went, and whether the OSC 52 bound cut the text. Pure, so every
/// combination is tested without touching a clipboard.
///
/// # Arguments
/// * `osc_ok` - whether the OSC 52 write succeeded.
/// * `helper` - the platform helper that succeeded, if any.
/// * `copied` / `total` - bytes copied, and the length of the whole text.
/// * `truncated` - whether `copied` is short of `total` because of the bound.
fn copy_outcome(
    osc_ok: bool,
    helper: Option<&str>,
    copied: usize,
    total: usize,
    truncated: bool,
) -> String {
    let mechanisms = match (osc_ok, helper) {
        (true, Some(h)) => format!("OSC 52 + {h}"),
        (true, None) => "OSC 52".to_string(),
        (false, Some(h)) => h.to_string(),
        (false, None) => {
            return "Clipboard error: OSC 52 write failed and no pbcopy/xclip helper".to_string();
        }
    };
    if truncated {
        format!("Copied first {copied} of {total} bytes ({mechanisms})")
    } else {
        format!("Copied {copied} bytes ({mechanisms})")
    }
}

/// Copy `text` to the system clipboard on a detached worker thread,
/// pushing the outcome message into `messages` (drained into the status
/// line by the event-loop tick). Never blocks the caller.
///
/// # Arguments
/// * `text` - the content to place on the clipboard.
/// * `messages` - shared queue the worker (or a failed spawn) reports into.
pub(in crate::tui) fn spawn_clipboard_copy(
    text: String,
    messages: Arc<parking_lot::Mutex<Vec<String>>>,
) {
    spawn_copy_worker(text, messages, copy_to_clipboard);
}

/// [`spawn_clipboard_copy`] with the copy itself passed in: runs `copy` on the
/// detached `clipboard` worker and pushes its outcome into `messages`.
///
/// The seam exists for tests, which pass a copy that never reaches the system
/// clipboard; production passes [`copy_to_clipboard`].
pub(in crate::tui) fn spawn_copy_worker(
    text: String,
    messages: Arc<parking_lot::Mutex<Vec<String>>>,
    copy: fn(&str) -> String,
) {
    let worker_messages = Arc::clone(&messages);
    let spawned = std::thread::Builder::new()
        .name("clipboard".to_string())
        .spawn(move || {
            let msg = copy(&text);
            worker_messages.lock().push(msg);
        });
    if let Err(e) = spawned {
        messages.lock().push(format!("Clipboard: {e}"));
    }
}

// ── Tests ───────────────────────────────────────────────────────────

/// Unit tests for the OSC 52 sequence builder: exact framing, base64
/// payload, and truncation at the size bound.
#[cfg(test)]
mod tests {
    use super::*;

    /// Known input produces the exact escape framing and base64 payload.
    #[test]
    fn osc52_sequence_frames_known_input() {
        let (seq, copied, truncated) = osc52_sequence("hello");
        assert_eq!(seq, "\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(copied, 5);
        assert!(!truncated);
    }

    /// Empty input still produces a well-formed (empty-payload) sequence.
    #[test]
    fn osc52_sequence_empty_input() {
        let (seq, copied, truncated) = osc52_sequence("");
        assert_eq!(seq, "\x1b]52;c;\x07");
        assert_eq!(copied, 0);
        assert!(!truncated);
    }

    /// Input over the bound is truncated to exactly the bound and the
    /// payload decodes back to the leading bytes.
    #[test]
    fn osc52_sequence_truncates_at_bound() {
        let text = "a".repeat(OSC52_MAX_RAW_BYTES + 10);
        let (seq, copied, truncated) = osc52_sequence(&text);
        assert_eq!(copied, OSC52_MAX_RAW_BYTES);
        assert!(truncated);
        let payload = seq
            .strip_prefix("\x1b]52;c;")
            .and_then(|s| s.strip_suffix('\x07'))
            .expect("well-formed OSC 52 framing");
        let decoded = STANDARD.decode(payload).expect("valid base64");
        assert_eq!(decoded.len(), OSC52_MAX_RAW_BYTES);
        assert_eq!(decoded, text.as_bytes()[..OSC52_MAX_RAW_BYTES]);
    }

    /// Truncation never splits a multibyte char: the cut lands on a char
    /// boundary at or below the bound.
    #[test]
    fn osc52_sequence_truncates_on_char_boundary() {
        // 'α' is 2 bytes; an odd bound position must back off by one.
        let text = "α".repeat(OSC52_MAX_RAW_BYTES); // 2× the bound in bytes
        let (seq, copied, truncated) = osc52_sequence(&text);
        assert!(truncated);
        assert!(copied <= OSC52_MAX_RAW_BYTES);
        assert!(text.is_char_boundary(copied), "cut split a char");
        let payload = seq
            .strip_prefix("\x1b]52;c;")
            .and_then(|s| s.strip_suffix('\x07'))
            .expect("well-formed OSC 52 framing");
        let decoded = STANDARD.decode(payload).expect("valid base64");
        assert!(std::str::from_utf8(&decoded).is_ok(), "payload not UTF-8");
    }
}

/// Tests for everything around the OSC 52 builder: the status-line wording,
/// the bytes handed to the terminal writer, the bounded helper run, and the
/// detached worker.
///
/// The wire itself is out of reach on purpose. `emit_osc52` writes to
/// `/dev/tty` (or stdout), which in a developer's terminal SETS THEIR
/// CLIPBOARD, and `helper_copy_bounded` runs xclip/pbcopy, which does the same
/// to the desktop clipboard. So these tests drive the pieces those two are
/// built from — `write_sequence` against an in-memory writer,
/// `run_helper_bounded` with harmless commands (`cat`, `false`, `sleep`,
/// `true`), `spawn_copy_worker` with a copy that returns a string — and never
/// the production copy.
#[cfg(test)]
mod seam_tests {
    use super::*;

    /// Each mechanism that worked is named; when neither did, the outcome is
    /// an error rather than a claim that something was copied.
    #[test]
    fn the_outcome_names_every_mechanism_that_worked() {
        assert_eq!(
            copy_outcome(true, Some("xclip"), 5, 5, false),
            "Copied 5 bytes (OSC 52 + xclip)"
        );
        assert_eq!(
            copy_outcome(true, None, 5, 5, false),
            "Copied 5 bytes (OSC 52)"
        );
        assert_eq!(
            copy_outcome(false, Some("pbcopy"), 5, 5, false),
            "Copied 5 bytes (pbcopy)"
        );
        assert_eq!(
            copy_outcome(false, None, 5, 5, false),
            "Clipboard error: OSC 52 write failed and no pbcopy/xclip helper"
        );
    }

    /// A copy cut by the OSC 52 bound says how much of how much went; a copy
    /// where nothing worked reports the error even when it was also cut.
    #[test]
    fn a_truncated_copy_says_how_much_of_the_text_went() {
        assert_eq!(
            copy_outcome(true, None, OSC52_MAX_RAW_BYTES, 80_000, true),
            format!("Copied first {OSC52_MAX_RAW_BYTES} of 80000 bytes (OSC 52)")
        );
        assert!(copy_outcome(false, None, 10, 20, true).starts_with("Clipboard error"));
    }

    /// With the bound landing INSIDE a two-byte character, the cut backs off
    /// to the boundary just below it. (`osc52_sequence_truncates_on_char_boundary`
    /// above repeats `α` from offset 0, so every even offset — the bound
    /// included — is already a boundary and the back-off never runs; a
    /// one-byte prefix moves the boundaries to odd offsets.)
    #[test]
    fn the_cut_backs_off_to_the_char_boundary_below_the_bound() {
        let text = format!("a{}", "α".repeat(OSC52_MAX_RAW_BYTES));
        assert!(
            !text.is_char_boundary(OSC52_MAX_RAW_BYTES),
            "the bound is mid-char"
        );
        let (seq, copied, truncated) = osc52_sequence(&text);
        assert!(truncated);
        assert_eq!(copied, OSC52_MAX_RAW_BYTES - 1, "backed off by one byte");
        let payload = seq
            .strip_prefix("\x1b]52;c;")
            .and_then(|s| s.strip_suffix('\x07'))
            .expect("well-formed OSC 52 framing");
        let decoded = STANDARD.decode(payload).expect("valid base64");
        assert_eq!(decoded, text.as_bytes()[..copied]);
        assert!(std::str::from_utf8(&decoded).is_ok(), "no split character");
    }

    /// Records every byte written and how many had arrived when flushed.
    #[derive(Default)]
    struct Recorder {
        bytes: Vec<u8>,
        flushed_at: Option<usize>,
    }

    impl Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed_at = Some(self.bytes.len());
            Ok(())
        }
    }

    /// A writer whose every write fails, and which records a flush.
    #[derive(Default)]
    struct Broken {
        flushed: bool,
    }

    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }

    /// The terminal receives the exact sequence, whole, and it is flushed only
    /// after the last byte; a failed write is reported and not flushed.
    #[test]
    fn the_sequence_reaches_the_writer_whole_and_flushed() {
        let (seq, _, _) = osc52_sequence("hi");
        let mut rec = Recorder::default();
        write_sequence(&mut rec, &seq).expect("an in-memory write succeeds");
        assert_eq!(rec.bytes, b"\x1b]52;c;aGk=\x07");
        assert_eq!(rec.flushed_at, Some(rec.bytes.len()), "flushed after all");

        let mut broken = Broken::default();
        let err = write_sequence(&mut broken, &seq).expect_err("the write fails");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(!broken.flushed, "nothing to flush after a failed write");
    }

    /// The bounded run is a success only for a command that starts, takes the
    /// text, and exits zero: `cat` is; `false` (non-zero exit) and a missing
    /// binary are not.
    #[cfg(unix)]
    #[test]
    fn a_helper_run_succeeds_only_on_a_clean_exit() {
        let wait = std::time::Duration::from_secs(10);
        assert!(run_helper_bounded("cat", &[], "hello", wait));
        assert!(!run_helper_bounded("false", &[], "hello", wait));
        assert!(!run_helper_bounded(
            "/nonexistent/sipnab-no-such-helper",
            &[],
            "hello",
            wait
        ));
    }

    /// A helper that never exits is killed at the deadline and reported as a
    /// failure, instead of holding the worker for as long as it runs.
    #[cfg(unix)]
    #[test]
    fn a_wedged_helper_is_killed_at_the_deadline() {
        let started = std::time::Instant::now();
        assert!(!run_helper_bounded(
            "sleep",
            &["30"],
            "x",
            std::time::Duration::from_millis(200)
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "killed at the deadline, not waited out: {:?}",
            started.elapsed()
        );
    }

    /// A helper that exits zero WITHOUT taking the text did not copy it: the
    /// failed write is a failure even though the exit status is clean.
    #[cfg(unix)]
    #[test]
    fn a_helper_that_does_not_take_the_text_is_not_a_success() {
        // Far larger than a pipe buffer, so the write cannot complete before
        // `true` exits without reading it.
        let text = "x".repeat(4 * 1024 * 1024);
        assert!(!run_helper_bounded(
            "true",
            &[],
            &text,
            std::time::Duration::from_secs(10)
        ));
    }

    /// The copy runs on the detached `clipboard` worker, never the caller's
    /// thread, and its outcome lands in the shared queue.
    #[test]
    fn the_copy_runs_on_the_clipboard_worker_and_reports_into_the_queue() {
        let messages = Arc::new(parking_lot::Mutex::new(Vec::new()));
        spawn_copy_worker(
            "graph TD;".to_string(),
            Arc::clone(&messages),
            |text: &str| {
                let thread = std::thread::current();
                format!("{text} @ {}", thread.name().unwrap_or("unnamed"))
            },
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while messages.lock().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never reported"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(*messages.lock(), vec!["graph TD; @ clipboard".to_string()]);
    }
}
