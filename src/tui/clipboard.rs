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
//! is no acknowledgement), the platform helper is also tried silently,
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
        Ok(mut tty) => {
            tty.write_all(sequence.as_bytes())?;
            tty.flush()
        }
        Err(_) => {
            let mut out = std::io::stdout().lock();
            out.write_all(sequence.as_bytes())?;
            out.flush()
        }
    }
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
    let mut child = std::process::Command::new(cmd)
        .args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    // Write, then drop stdin so the helper sees EOF and exits.
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(text.as_bytes()).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Some(cmd),
            Ok(Some(_)) => return None,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => return None,
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
    let mechanisms = match (osc_ok, helper) {
        (true, Some(h)) => format!("OSC 52 + {h}"),
        (true, None) => "OSC 52".to_string(),
        (false, Some(h)) => h.to_string(),
        (false, None) => {
            return "Clipboard error: OSC 52 write failed and no pbcopy/xclip helper".to_string();
        }
    };
    if truncated {
        format!(
            "Copied first {copied} of {} bytes ({mechanisms})",
            text.len()
        )
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
    let worker_messages = Arc::clone(&messages);
    let spawned = std::thread::Builder::new()
        .name("clipboard".to_string())
        .spawn(move || {
            let msg = copy_to_clipboard(&text);
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
