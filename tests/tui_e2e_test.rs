//! End-to-end PTY tests for sipnab's TUI.
//!
//! These tests spawn the actual sipnab binary in a pseudo-terminal via
//! `expectrl`, send keystrokes, and verify terminal output. They are
//! slower (~2s each) but provide the highest confidence that the TUI
//! works correctly from the user's perspective.
//!
//! Feature-gated to `tui` + Unix (PTY is not available on Windows).
//! Marked `#[ignore]` by default since PTY tests can be flaky in CI
//! environments without a real terminal. Run with:
//!
//! ```sh
//! cargo test --all-features -- tui_e2e --ignored
//! ```

#[cfg(all(feature = "tui", unix))]
mod tui_e2e {
    use expectrl::{Eof, Expect};
    use std::time::Duration;

    type OsSession = expectrl::session::OsSession;

    /// Spawn sipnab in a PTY with the given arguments.
    ///
    /// Sets a generous 5-second expect timeout to accommodate TUI
    /// initialization and rendering time.
    fn spawn_sipnab(args: &[&str]) -> OsSession {
        let bin = env!("CARGO_BIN_EXE_sipnab");
        let mut cmd_args = vec![bin];
        cmd_args.extend_from_slice(args);
        let mut session =
            expectrl::spawn(cmd_args.join(" ")).expect("failed to spawn sipnab in PTY");
        session.set_expect_timeout(Some(Duration::from_secs(5)));
        session
    }

    /// Small delay between keystrokes to let the TUI process input and
    /// re-render. Without this, fast sends can race ahead of the
    /// rendering loop.
    fn keystroke_delay() {
        std::thread::sleep(Duration::from_millis(300));
    }

    #[test]
    #[ignore] // PTY tests are flaky in CI — run explicitly
    fn tui_launches_with_pcap_and_shows_call_list() {
        let mut s = spawn_sipnab(&["-I", "tests/fixtures/sip_call.pcap"]);
        // The call list and INVITE data are rendered in a single frame.
        // Matching "INVITE" proves both that the TUI launched and that
        // the pcap was loaded (INVITE appears in the table body, after
        // the "Call List" title).
        s.expect("INVITE").unwrap();
        // Quit cleanly
        s.send("q").unwrap();
        s.expect(Eof).unwrap();
    }

    #[test]
    #[ignore]
    fn tui_tab_switches_to_stream_list() {
        let mut s = spawn_sipnab(&["-I", "tests/fixtures/sip_call.pcap"]);
        // "Dialogs:" appears in the call-list status line.
        s.expect("Dialogs:").unwrap();
        // Send Tab to switch views
        s.send("\t").unwrap();
        keystroke_delay();
        // Stream list table has an "SSRC" column header.
        s.expect("SSRC").unwrap();
        // Quit
        s.send("q").unwrap();
        s.expect(Eof).unwrap();
    }

    #[test]
    #[ignore]
    fn tui_f1_shows_help() {
        let mut s = spawn_sipnab(&["-I", "tests/fixtures/sip_call.pcap"]);
        s.expect("Dialogs:").unwrap();
        // Send F1 (xterm escape sequence: ESC O P)
        s.send("\x1bOP").unwrap();
        keystroke_delay();
        // Help overlay should appear
        s.expect("Help").unwrap();
        // Esc to close help
        s.send("\x1b").unwrap();
        keystroke_delay();
        // Quit
        s.send("q").unwrap();
        s.expect(Eof).unwrap();
    }

    #[test]
    #[ignore]
    fn tui_enter_opens_call_flow() {
        let mut s = spawn_sipnab(&["-I", "tests/fixtures/sip_call.pcap"]);
        s.expect("Dialogs:").unwrap();
        // Enter on first dialog to open call flow
        s.send("\r").unwrap();
        keystroke_delay();
        // Call flow should show INVITE in the ladder diagram
        s.expect("INVITE").unwrap();
        // Esc back to call list
        s.send("\x1b").unwrap();
        keystroke_delay();
        // Quit
        s.send("q").unwrap();
        s.expect(Eof).unwrap();
    }

    #[test]
    #[ignore]
    fn tui_quit_exits_cleanly() {
        let mut s = spawn_sipnab(&["-I", "tests/fixtures/sip_call.pcap"]);
        s.expect("Dialogs:").unwrap();
        s.send("q").unwrap();
        // Should reach EOF (process exited)
        s.expect(Eof).unwrap();
    }
}
