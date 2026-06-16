//! End-to-end TUI tests that drive the real `sipnab` binary inside a `tmux`
//! session.
//!
//! Why tmux rather than a bare PTY (e.g. expectrl): sipnab's TUI queries the
//! terminal at startup (crossterm emits `ESC[6n` to read the cursor position).
//! A bare pseudo-terminal has no terminal emulator behind it, so the query is
//! never answered and the TUI aborts with "cursor position could not be read".
//! tmux *is* a terminal emulator — it answers the query, provides a real
//! window size, and lets us send keys and snapshot the screen with
//! `capture-pane`. This is the only PTY-style harness that actually runs the
//! TUI in this environment.
//!
//! These tests are `#[ignore]` by default (they need `tmux` on PATH and are
//! slower than unit tests). Run them explicitly:
//!
//! ```sh
//! cargo test --features tui --test tui_e2e_test -- --ignored
//! ```

#[cfg(all(feature = "tui", unix))]
mod tui_e2e {
    use std::process::Command;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    static SESSION_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A tmux session running sipnab; killed automatically on drop.
    struct TuiSession {
        name: String,
    }

    impl TuiSession {
        /// Launch sipnab in a detached tmux session of the given size, with the
        /// working directory set to `cwd` (so the file-open browser lists files
        /// there) and the given extra CLI args.
        fn launch(cols: u16, rows: u16, cwd: &str, args: &[&str]) -> Self {
            let bin = env!("CARGO_BIN_EXE_sipnab");
            let seq = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
            let name = format!("sipnab_e2e_{}_{}", std::process::id(), seq);

            // tmux runs the command via the shell; cd first so the file browser
            // and any relative paths resolve under the fixture directory.
            let cmd = format!(
                "cd {} && exec {} {}",
                shell_quote(cwd),
                shell_quote(bin),
                args.iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            );

            let status = Command::new("tmux")
                .args([
                    "new-session",
                    "-d",
                    "-s",
                    &name,
                    "-x",
                    &cols.to_string(),
                    "-y",
                    &rows.to_string(),
                    &cmd,
                ])
                .status()
                .expect("failed to run tmux (is it installed?)");
            assert!(status.success(), "tmux new-session failed");

            TuiSession { name }
        }

        /// Default-size launch loading the bundled SIP call fixture.
        fn launch_sip_call() -> Self {
            Self::launch(150, 40, fixtures_dir(), &["-I", "sip_call.pcap"])
        }

        /// Capture the visible pane contents as text.
        fn screen(&self) -> String {
            let out = Command::new("tmux")
                .args(["capture-pane", "-t", &self.name, "-p"])
                .output()
                .expect("tmux capture-pane failed");
            String::from_utf8_lossy(&out.stdout).into_owned()
        }

        /// Poll the screen until `needle` appears, returning the screen. Panics
        /// with the last captured screen on timeout.
        fn wait_for(&self, needle: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let last = self.screen();
                if last.contains(needle) {
                    return last;
                }
                if Instant::now() >= deadline {
                    panic!(
                        "timed out waiting for {needle:?} in session {}.\nlast screen:\n{last}",
                        self.name
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        /// Send a named key (e.g. "Enter", "Tab", "Escape", "F1").
        fn key(&self, name: &str) {
            self.send(&[name]);
        }

        /// Send literal characters (case-preserving), e.g. "v" or "O".
        fn literal(&self, chars: &str) {
            self.send(&["-l", chars]);
        }

        fn send(&self, tail: &[&str]) {
            let mut args = vec!["send-keys", "-t", &self.name];
            args.extend_from_slice(tail);
            let status = Command::new("tmux")
                .args(&args)
                .status()
                .expect("tmux send-keys failed");
            assert!(status.success(), "tmux send-keys failed");
            // Give the render loop a moment to process the key.
            std::thread::sleep(Duration::from_millis(120));
        }

        /// True once the session has ended (the process exited).
        fn ended(&self) -> bool {
            !Command::new("tmux")
                .args(["has-session", "-t", &self.name])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        }

        fn wait_until_ended(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.ended() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!("session {} did not exit", self.name);
        }
    }

    impl Drop for TuiSession {
        fn drop(&mut self) {
            let _ = Command::new("tmux")
                .args(["kill-session", "-t", &self.name])
                .status();
        }
    }

    fn fixtures_dir() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")
    }

    /// Minimal single-quote shell quoting for paths/args.
    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[test]
    #[ignore] // needs tmux; slower than unit tests
    fn tui_launches_with_pcap_and_shows_call_list() {
        let s = TuiSession::launch_sip_call();
        // INVITE in the call-list body proves the TUI launched and loaded the pcap.
        s.wait_for("INVITE");
    }

    #[test]
    #[ignore]
    fn tui_tab_switches_to_stream_list() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.key("Tab");
        s.wait_for("SSRC"); // stream-list column header
    }

    #[test]
    #[ignore]
    fn tui_f1_shows_help() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.key("F1");
        s.wait_for("Help");
    }

    #[test]
    #[ignore]
    fn tui_enter_opens_call_flow() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.key("Enter");
        s.wait_for("INVITE"); // ladder
    }

    #[test]
    #[ignore]
    fn tui_quit_exits_cleanly() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.literal("q");
        s.wait_until_ended();
    }

    // ── New-feature coverage ─────────────────────────────────────────────

    #[test]
    #[ignore]
    fn tui_tab_switches_call_flow_pane_focus() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.key("Enter");
        // Split view is on by default; ladder focused first.
        s.wait_for("Focus: Ladder");
        s.key("Tab");
        s.wait_for("Focus: Detail");
        s.key("Tab");
        s.wait_for("Focus: Ladder");
    }

    #[test]
    #[ignore]
    fn tui_v_shows_version_with_commit() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.literal("v");
        // Version line includes the crate version and the git commit in parens.
        let screen = s.wait_for("sipnab 0.");
        assert!(
            screen.contains('(') && screen.contains(')'),
            "version should include git commit:\n{screen}"
        );
    }

    #[test]
    #[ignore]
    fn tui_call_flow_detail_scrollbar_appears_when_overflowing() {
        // A short terminal forces the detail pane to overflow → scrollbar.
        let s = TuiSession::launch(120, 14, fixtures_dir(), &["-I", "sip_call.pcap"]);
        s.wait_for("Dialogs:");
        s.key("Enter");
        s.wait_for("Focus: Ladder");
        // The scrollbar thumb glyph is unique to the scrollbar widget.
        let screen = s.wait_for("\u{2588}");
        assert!(
            screen.contains('\u{2588}'),
            "scrollbar thumb missing:\n{screen}"
        );
    }

    #[test]
    #[ignore]
    fn tui_file_open_lists_pcaps_in_cwd() {
        // cwd is the fixtures dir, which contains sip_call.pcap + udp_5060.pcap.
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        s.literal("O"); // open file browser
        s.wait_for("sip_call.pcap");
    }

    #[test]
    #[ignore]
    fn tui_name_address_resolves_in_columns() {
        let s = TuiSession::launch_sip_call();
        s.wait_for("Dialogs:");
        // N opens the Name Address popup for the selected dialog's source.
        s.literal("N");
        s.wait_for("Name Address");
        s.literal("edge-proxy");
        s.key("Enter");
        // Resolution auto-enables; the name now shows in the Source column.
        let named = s.wait_for("edge-proxy");
        assert!(named.contains("edge-proxy"), "name not shown:\n{named}");
        // Toggling name mode back to Off restores the raw IP (no name).
        s.literal("n"); // Static -> DNS
        s.literal("n"); // DNS -> Off
        let off = s.screen();
        assert!(
            !off.contains("edge-proxy"),
            "name should be hidden when Off:\n{off}"
        );
    }
}
