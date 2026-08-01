// SPDX-License-Identifier: MIT OR Apache-2.0

//! TUI snapshot tests using ratatui's TestBackend and insta.
//!
//! Each test renders a specific view into an in-memory terminal buffer, then
//! snapshots the textual content via `insta::assert_snapshot!`.
//!
//! Determinism: fixtures use a fixed base timestamp, fixed addresses, and a
//! pinned test version string, so a buffer renders identically on every run;
//! save/file dialogs override their time-derived default paths. Snapshots
//! live in `tests/snapshots/` — review intended visual changes with
//! `cargo insta review`. The whole module is gated on the `tui` feature, and
//! one view (`stream_detail_view`) snapshots under per-feature names because
//! the `audio` build renders an extra footer hint.

// Low-level SIP fixture builders shared with `tui_state_test.rs` so the two
// suites can't drift. Declared at file scope (not nested) so the `#[path]`
// resolves against `tests/`.
#[cfg(feature = "tui")]
#[path = "support/tui_fixtures.rs"]
mod fixtures;

#[cfg(feature = "tui")]
mod tui_snapshots {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use chrono::{DateTime, TimeDelta, Utc};
    use parking_lot::RwLock;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crossterm::event::KeyCode;
    use sipnab::capture::parse::TransportProto;
    use sipnab::rtp::parser::RtpHeader;
    use sipnab::rtp::stream_store::StreamStore;
    use sipnab::sip::SipMessage;
    use sipnab::sip::dialog_store::DialogStore;
    use sipnab::sip::parser::parse_sip;
    use sipnab::tui::App;

    // ── Helper: extract buffer as a plain string ───────────────────────

    /// Flatten the terminal buffer into one string, one line per row, with
    /// trailing spaces trimmed so snapshots stay stable across widths.
    ///
    /// # Arguments
    /// * `terminal` - The in-memory terminal whose buffer is read.
    ///
    /// # Returns
    /// The newline-joined visible text of the buffer.
    fn buffer_to_string(terminal: &Terminal<TestBackend>) -> String {
        let buf = terminal.backend().buffer();
        let area = buf.area;
        let mut output = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = buf.cell((x, y)).unwrap();
                output.push_str(cell.symbol());
            }
            // Trim trailing spaces for stable snapshots
            let trimmed = output.trim_end_matches(' ');
            output.truncate(trimmed.len());
            output.push('\n');
        }
        output
    }

    // ── Helper: SIP message constructors ───────────────────────────────
    //
    // The low-level fixture builders (endpoint addresses, base timestamp,
    // raw-wire assembly, minimal INVITE/response) are shared with
    // `tui_state_test.rs` via the file-scoped `fixtures` module above so the
    // two suites can't drift. Snapshot-specific builders (BYE, SDP variants,
    // dialog assemblers) stay below.
    use super::fixtures::{base_ts, build_sip, endpoint_a, endpoint_b, make_invite, make_response};

    /// Parse a BYE (A-side to B-side, CSeq 2) that completes a dialog.
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
    fn make_bye(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:1002@example.com SIP/2.0",
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            endpoint_a(),
            endpoint_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse BYE")
    }

    // ── Helper: create App with 3 test dialogs ─────────────────────────

    /// Build an `App` preloaded with three fixture dialogs:
    ///
    /// Dialog 1: Completed INVITE 1001 -> 1002
    /// Dialog 2: Failed INVITE 1003 -> 1004
    /// Dialog 3: Active (InCall) INVITE 1005 -> 1006
    ///
    /// # Returns
    /// The `App` with all eight messages (including 180 and BYE for dialog 1)
    /// already processed into its dialog store.
    fn test_app_with_dialogs() -> App {
        let t0 = base_ts();
        let messages = vec![
            // Dialog 1: Completed
            make_invite("call-1@test", "1001", "1002", t0),
            make_response(
                "call-1@test",
                180,
                "Ringing",
                "INVITE",
                t0 + TimeDelta::seconds(1),
            ),
            make_response(
                "call-1@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(2),
            ),
            make_bye("call-1@test", t0 + TimeDelta::seconds(62)),
            // Dialog 2: Failed
            make_invite("call-2@test", "1003", "1004", t0 + TimeDelta::seconds(5)),
            make_response(
                "call-2@test",
                503,
                "Service Unavailable",
                "INVITE",
                t0 + TimeDelta::seconds(6),
            ),
            // Dialog 3: Active (InCall)
            make_invite("call-3@test", "1005", "1006", t0 + TimeDelta::seconds(10)),
            make_response(
                "call-3@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(12),
            ),
        ];
        App::with_processed_messages(messages)
    }

    /// Create an App with streams for stream list tests.
    ///
    /// Stream 1 (SSRC `0xAAAABBBB`, PCMU) is linked to dialog `call-1@test`;
    /// stream 2 (SSRC `0xCCCCDDDD`, PCMA) is marked orphaned.
    ///
    /// # Returns
    /// An `App` built over the populated dialog and stream stores.
    fn test_app_with_streams() -> App {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));

        // Add two RTP streams via the store
        {
            let mut store = ss.write();
            let ts = DateTime::from_timestamp(1_700_000_000, 0).unwrap();

            // Stream 1: healthy, linked to dialog
            let parsed1 = sipnab::capture::ParsedPacket {
                timestamp: ts,
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 20000,
                dst_port: 30000,
                transport: sipnab::capture::parse::TransportProto::Udp,
                payload: vec![0u8; 172].into(),
                ip_id: None,
                tcp_seq: None,
                tcp_flags: None,
                fragment_offset: None,
                more_fragments: false,
                ip_protocol: 17,
                from_hep: false,
            };
            let rtp1 = RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 0,
                sequence: 1,
                timestamp: 0,
                ssrc: 0xAAAA_BBBB,
                payload_offset: 12,
            };
            store.process_rtp(&parsed1, &rtp1, ts);
            store.link_to_dialog(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30000, "call-1@test");

            // Stream 2: orphaned
            let parsed2 = sipnab::capture::ParsedPacket {
                timestamp: ts,
                src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                src_port: 20002,
                dst_port: 30002,
                transport: sipnab::capture::parse::TransportProto::Udp,
                payload: vec![0u8; 172].into(),
                ip_id: None,
                tcp_seq: None,
                tcp_flags: None,
                fragment_offset: None,
                more_fragments: false,
                ip_protocol: 17,
                from_hep: false,
            };
            let rtp2 = RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 8,
                sequence: 100,
                timestamp: 0,
                ssrc: 0xCCCC_DDDD,
                payload_offset: 12,
            };
            store.process_rtp(&parsed2, &rtp2, ts);
            // Zero timeout on the capture clock: orphaned as of this packet.
            store.mark_orphaned(ts, std::time::Duration::from_secs(0));
        }

        App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        )
    }

    /// Feed one RTP packet (`ssrc`, `seq`) A→B into `store` at `ts`.
    ///
    /// Sequence gaps between successive calls register as packet loss, which
    /// the packet-loss-map fixtures rely on to place clustered vs no loss.
    fn push_rtp(store: &mut StreamStore, ssrc: u32, seq: u16, ts: DateTime<Utc>) {
        let parsed = sipnab::capture::ParsedPacket {
            timestamp: ts,
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 20000,
            dst_port: 30000,
            transport: TransportProto::Udp,
            payload: vec![0u8; 172].into(),
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
            from_hep: false,
        };
        let rtp = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: seq,
            timestamp: u32::from(seq) * 160,
            ssrc,
            payload_offset: 12,
        };
        store.process_rtp(&parsed, &rtp, ts);
    }

    /// An App with a single PCMU stream whose loss is one contiguous burst
    /// (a 100-packet sequence gap) surrounded by clean traffic — the
    /// clustered signature the loss map draws as a dark run.
    fn test_app_with_clustered_loss() -> App {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let ssrc = 0xAAAA_BBBB;
        {
            let mut store = ss.write();
            let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
            let mut tick = 0i64;
            let mut at = || {
                tick += 1;
                t0 + TimeDelta::milliseconds(tick * 20)
            };
            // Clean lead-in.
            for seq in 1000..1020u16 {
                push_rtp(&mut store, ssrc, seq, at());
            }
            // One big gap: sequences 1020..1119 are lost (a burst).
            push_rtp(&mut store, ssrc, 1120, at());
            // Clean tail.
            for seq in 1121..1141u16 {
                push_rtp(&mut store, ssrc, seq, at());
            }
        }
        App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        )
    }

    /// An App with a single loss-free PCMU stream — the loss map's
    /// degraded, empty-window path.
    fn test_app_with_clean_stream() -> App {
        let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
        let ss = Arc::new(RwLock::new(StreamStore::new(100)));
        let ssrc = 0xAAAA_BBBB;
        {
            let mut store = ss.write();
            let t0 = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
            for (i, seq) in (1..40u16).enumerate() {
                push_rtp(
                    &mut store,
                    ssrc,
                    seq,
                    t0 + TimeDelta::milliseconds(i as i64 * 20),
                );
            }
        }
        App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        )
    }

    /// Navigate an app holding one stream to that stream's packet loss map:
    /// Call List → RTP Streams (Tab) → Stream Detail (Enter) → Loss Map (L).
    fn open_loss_map(app: &mut App) {
        app.handle_key(KeyCode::Tab); // CallList -> StreamList
        app.handle_key(KeyCode::Enter); // -> StreamDetail of the one stream
        app.handle_key(KeyCode::Char('L')); // -> StreamLossMap
    }

    // ── Snapshot tests ────────────────────────────────────────────────

    /// Snapshot: the packet loss map of a stream whose loss is one contiguous
    /// burst — the strip must show a dark run of density glyphs.
    #[test]
    fn loss_map_clustered() {
        let backend = TestBackend::new(100, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_clustered_loss();
        open_loss_map(&mut app);
        assert!(
            matches!(app.current_view(), sipnab::tui::View::StreamLossMap(_)),
            "expected the loss-map view, got {:?}",
            app.current_view()
        );

        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        assert!(
            output.contains('\u{2588}') || output.contains('\u{2593}'),
            "clustered loss must draw a heavy density glyph:\n{output}"
        );
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the packet loss map of a loss-free stream — the centered
    /// empty-window message replaces the density strip.
    #[test]
    fn loss_map_no_loss() {
        let backend = TestBackend::new(100, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_clean_stream();
        open_loss_map(&mut app);

        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        assert!(
            output.contains("No packet loss recorded in the retained window"),
            "empty-window message missing:\n{output}"
        );
        insta::assert_snapshot!(output);
    }

    /// Snapshot: empty call list at 80x24.
    #[test]
    fn call_list_empty() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list with the three fixture dialogs at 80x24.
    #[test]
    fn call_list_with_dialogs() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the same call list at 130x40, where the wide layout fits more columns.
    #[test]
    fn call_list_with_dialogs_wide() {
        let backend = TestBackend::new(130, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: empty stream list.
    #[test]
    fn stream_list_empty() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(crossterm::event::KeyCode::Tab); // switch to stream list

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: quality dashboard (`D`) with dialogs but no RTP streams.
    #[test]
    fn quality_dashboard_no_streams() {
        let backend = TestBackend::new(130, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(crossterm::event::KeyCode::Char('D')); // open dashboard

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: quality dashboard with the two fixture RTP streams.
    #[test]
    fn quality_dashboard_with_streams() {
        let backend = TestBackend::new(130, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_streams();
        app.handle_key(crossterm::event::KeyCode::Char('D')); // open dashboard

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Rendering the dashboard on a 10x3 terminal must not panic or underflow (no snapshot taken).
    #[test]
    fn quality_dashboard_survives_tiny_terminal() {
        // render-robustness: a 10x3 terminal must not panic or underflow
        let backend = TestBackend::new(10, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_streams();
        app.handle_key(crossterm::event::KeyCode::Char('D'));
        terminal.draw(|frame| app.render(frame)).unwrap();
    }

    /// Snapshot: stream list showing a dialog-linked stream and an orphaned one.
    #[test]
    fn stream_list_with_streams() {
        let backend = TestBackend::new(130, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_streams();
        app.handle_key(crossterm::event::KeyCode::Tab); // switch to stream list

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // M4/T4.2: the StreamDetail view was the one view with no snapshot.
    /// Snapshot: `StreamDetail` view, under per-feature names because the audio build adds a "P Play" footer entry.
    #[test]
    fn stream_detail_view() {
        let backend = TestBackend::new(130, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_streams();
        app.handle_key(crossterm::event::KeyCode::Tab); // CallList -> StreamList
        app.handle_key(crossterm::event::KeyCode::Enter); // open StreamDetail of selected stream

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        // The F-key footer hint differs by feature: the `audio` build adds a
        // "P Play" entry. Snapshot under a feature-specific name so both the
        // headless (no-audio) build and the full (audio) build stay green.
        #[cfg(feature = "audio")]
        insta::assert_snapshot!("stream_detail_view_audio", output);
        #[cfg(not(feature = "audio"))]
        insta::assert_snapshot!("stream_detail_view_noaudio", output);
    }

    /// Snapshot: call flow ladder of the first fixture dialog.
    #[test]
    fn call_flow_basic() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        // Select first dialog and open call flow
        app.handle_key(crossterm::event::KeyCode::Enter);

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// The `h` key cycles header-name display (as captured → expanded →
    /// compact) as a purely visual transform: the same message renders
    /// with `f:`/`i:` in compact mode and `From:`/`Call-ID:` again after
    /// cycling back, regardless of the wire form in the capture.
    #[test]
    fn raw_message_header_form_toggle_is_display_only() {
        let mut app = test_app_with_dialogs();
        app.handle_key(crossterm::event::KeyCode::Char('r')); // open raw view
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| app.render(frame)).unwrap();
        let as_captured = buffer_to_string(&terminal);
        assert!(as_captured.contains("From:"), "got:\n{as_captured}");

        // h, h → compact display.
        app.handle_key(crossterm::event::KeyCode::Char('h'));
        app.handle_key(crossterm::event::KeyCode::Char('h'));
        terminal.draw(|frame| app.render(frame)).unwrap();
        let compact = buffer_to_string(&terminal);
        assert!(
            compact.contains("f: \"1001\"") && compact.contains("i: call-1@test"),
            "compact forms shown, got:\n{compact}"
        );
        assert!(!compact.contains("From:"), "got:\n{compact}");

        // h → back to as-captured: the full names return (display only,
        // nothing was mutated).
        app.handle_key(crossterm::event::KeyCode::Char('h'));
        terminal.draw(|frame| app.render(frame)).unwrap();
        let restored = buffer_to_string(&terminal);
        assert!(restored.contains("From:"), "got:\n{restored}");
    }

    /// Field report: OpenSIPS' default provisional reason ("100 trying --
    /// your call is important to us", 42 chars) rendered as a blank arrow
    /// in the ladder because labels wider than the pipe gap were dropped.
    /// The truncated label must be visible on the arrow row.
    #[test]
    fn call_flow_long_reason_phrase_stays_visible() {
        let t0 = base_ts();
        let messages = vec![
            make_invite("long-reason@test", "1001", "1002", t0),
            make_response(
                "long-reason@test",
                100,
                "trying -- your call is important to us",
                "INVITE",
                t0 + chrono::TimeDelta::milliseconds(20),
            ),
        ];
        let mut app = App::with_processed_messages(messages);
        app.handle_key(crossterm::event::KeyCode::Enter);

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        assert!(
            output.contains("100 trying"),
            "the 100's reason must be visible (truncated) on the arrow, got:\n{output}"
        );
    }

    /// Snapshot: Tab moves focus to the detail pane; asserts the "Focus: Detail" indicator first.
    #[test]
    fn call_flow_split_focus_detail() {
        // Open the call flow split, then Tab to focus the detail pane. The
        // status line should read "Focus: Detail" and the detail border should
        // be highlighted — locked in by the snapshot.
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Tab); // focus detail pane

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        assert!(
            output.contains("Focus: Detail"),
            "focus indicator missing:\n{output}"
        );
        insta::assert_snapshot!(output);
    }

    /// Snapshot: on a 100x10 terminal the detail pane overflows, so the scrollbar thumb must appear.
    #[test]
    fn call_flow_detail_scrollbar_on_overflow() {
        // A short terminal forces the detail pane to overflow, so the vertical
        // scrollbar (thumb glyph) must appear on the right border.
        let backend = TestBackend::new(100, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow (split on by default)

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        assert!(
            output.contains('\u{2588}'),
            "scrollbar thumb missing:\n{output}"
        );
        insta::assert_snapshot!(output);
    }

    /// Snapshot: raw message view reached via call list, call flow, Enter.
    #[test]
    fn raw_message_view() {
        let backend = TestBackend::new(90, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        // Navigate: call list -> call flow -> raw message
        app.handle_key(crossterm::event::KeyCode::Enter); // open call flow
        app.handle_key(crossterm::event::KeyCode::Enter); // open raw message at scroll 0

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: Help view (version pinned to "0.0.0-test" keeps it deterministic).
    #[test]
    fn help_view() {
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(crossterm::event::KeyCode::F(1)); // open help

        terminal.draw(|frame| app.render(frame)).unwrap();

        // `App::new_test()` pins the version to a fixed "0.0.0-test", so the
        // help view no longer embeds the build's git commit / feature list and
        // the snapshot is deterministic without any post-render redaction.
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// A long version string (release tag + dirty marker + the full feature
    /// list, e.g. a dirty build sitting on a release tag) must not wrap inside
    /// the help box and shove the last keybinding off the bottom. Regression
    /// test for the non-deterministic `help_view` snapshot: the version line is
    /// truncated to a single row so it can never wrap and shove the rest of the
    /// help down. (The help itself is scrollable, so not every binding is on
    /// screen at once — this asserts the *version line* behavior specifically.)
    #[test]
    fn help_view_long_version_does_not_wrap() {
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.set_version_for_test(
            "0.4.3 (v0.4.3 a84ac0ca-dirty) features: native,tui,audio,tls,hep,api,mcp,mcp-http",
        );
        app.handle_key(crossterm::event::KeyCode::F(1)); // open help

        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);

        // The version line is present (truncated to one row).
        assert!(
            output.contains("v0.4.3 (v0.4.3 a84ac0ca-dirty) features:"),
            "version line missing from help box:\n{output}"
        );
        // It must NOT wrap: the feature-list tail must not leak onto its own row.
        assert!(
            !output.contains("\u{2502}native,tui"),
            "version line wrapped instead of being truncated:\n{output}"
        );
        // Because the version stayed on one row, the first section header is
        // still visible immediately below it (not pushed off by a wrap).
        assert!(
            output.contains("CALL LIST:"),
            "a wrapped version line pushed the help body down:\n{output}"
        );
    }

    /// The F1 help exceeds an 80x40 screen, so it must be scrollable: bindings
    /// in later sections become visible after scrolling down.
    #[test]
    fn help_view_scrolls_to_later_sections() {
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(crossterm::event::KeyCode::F(1)); // open help

        // At the top, a CALL FLOW-only binding is below the fold.
        terminal.draw(|frame| app.render(frame)).unwrap();
        assert!(!buffer_to_string(&terminal).contains("Export Mermaid sequence diagram"));

        // Scroll down a page; the later section comes into view.
        for _ in 0..40 {
            app.handle_key(crossterm::event::KeyCode::PageDown);
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let scrolled = buffer_to_string(&terminal);
        assert!(
            scrolled.contains("COPY & PASTE:")
                && scrolled.contains("Shift+drag bypasses capture in many terminals."),
            "scrolling did not reveal the end of the help:\n{scrolled}"
        );
    }

    /// Snapshot: call list narrowed by an applied From filter of "1003".
    #[test]
    fn call_list_with_filter_active() {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();

        // Open filter dialog, type From filter "1003", and apply it
        app.handle_key(crossterm::event::KeyCode::F(7)); // open filter
        // Type "1003" into the SIP From field (focused by default)
        for c in "1003".chars() {
            app.handle_key(crossterm::event::KeyCode::Char(c));
        }
        app.handle_key(crossterm::event::KeyCode::Enter); // apply filter

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: a list containing only a failed (503) dialog, locking in the failure styling.
    #[test]
    fn call_list_failed_dialog_styling() {
        // Render with only failed dialogs to verify the styling appears
        let t0 = base_ts();
        let messages = vec![
            make_invite("fail-only@test", "1003", "1004", t0),
            make_response(
                "fail-only@test",
                503,
                "Service Unavailable",
                "INVITE",
                t0 + TimeDelta::seconds(1),
            ),
        ];
        let mut app = App::with_processed_messages(messages);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: statistics view over the three fixture dialogs at 60x20.
    #[test]
    fn statistics_view() {
        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(crossterm::event::KeyCode::Char('s')); // open stats

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the F7 filter popup over an empty call list.
    #[test]
    fn filter_dialog_popup() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(crossterm::event::KeyCode::F(7)); // open filter popup

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the F2 save popup, with the path overridden for determinism.
    #[test]
    fn save_dialog_popup() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(crossterm::event::KeyCode::F(2)); // open save popup
        // Override the timestamp-based path for deterministic snapshots
        app.set_save_path("/tmp/sipnab_20240615_120000.pcap");

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Helper: SDP-containing message constructors ───────────────────

    /// Build an INVITE with SDP body.
    ///
    /// # Returns
    /// The parsed INVITE offering PCMU/PCMA audio on port 20000; panics on
    /// parse failure.
    fn make_invite_with_sdp(call_id: &str, from: &str, to: &str, ts: DateTime<Utc>) -> SipMessage {
        let sdp = "v=0\r\n\
                   o=- 123456 654321 IN IP4 10.0.0.1\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 20000 RTP/AVP 0 8\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n";
        let headers = format!(
            "INVITE sip:{}@10.0.0.2 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-{}\r\n\
             From: <sip:{}@10.0.0.1>;tag=t1\r\n\
             To: <sip:{}@10.0.0.2>\r\n\
             Call-ID: {}\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Type: application/sdp\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            to,
            call_id,
            from,
            to,
            call_id,
            sdp.len(),
            sdp
        );
        let raw = headers.into_bytes();
        sipnab::sip::parser::parse_sip(
            &raw,
            ts,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            5060,
            5060,
            sipnab::capture::parse::TransportProto::Udp,
        )
        .unwrap()
    }

    /// Create an app with SDP-containing dialogs.
    ///
    /// # Returns
    /// An `App` with one dialog: an SDP-bearing INVITE plus its 200 OK.
    fn test_app_with_sdp_dialogs() -> App {
        let t0 = base_ts();
        let messages = vec![
            make_invite_with_sdp("sdp-call@test", "2001", "2002", t0),
            make_response(
                "sdp-call@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(2),
            ),
        ];
        App::with_processed_messages(messages)
    }

    // ── Call List Rendering ───────────────────────────────────────────

    /// Snapshot: call list after hiding the first (#) column via the column selector.
    #[test]
    fn call_list_column_hidden() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        // Hide the first column (#) via column selector
        app.handle_key(KeyCode::F(10)); // open column selector
        app.handle_key(KeyCode::Char(' ')); // toggle column 0 (Index)
        app.handle_key(KeyCode::Enter); // close selector
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list after one `t` press. Delta-prev is the default,
    /// so one press lands on Delta-first — the test and its snapshot are
    /// named for what they actually render.
    #[test]
    fn call_list_timestamp_delta_first() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('t')); // DeltaPrev (default) -> DeltaFirst
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list after two `t` presses. Delta-prev is the default,
    /// so two presses land on Scaled — the test and its snapshot are named
    /// for what they actually render.
    #[test]
    fn call_list_timestamp_scaled() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('t')); // DeltaPrev (default) -> DeltaFirst
        app.handle_key(KeyCode::Char('t')); // DeltaFirst -> Scaled
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list sorted by the Method column via `>`.
    #[test]
    fn call_list_sort_by_method() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('>')); // sort by next column (Method)
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: two rows check-selected with Space.
    #[test]
    fn call_list_multi_selected() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char(' ')); // select row 0
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Char(' ')); // select row 1
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // sngrep parity: every call-list row shows a [ ]/[*] selection checkbox
    // so users can see and pick which dialogs to act on (e.g. save).
    /// Every row renders a selection checkbox: the checked row shows [*], others [ ] (sngrep parity).
    #[test]
    fn call_list_selection_checkbox_visible() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char(' ')); // check row 0
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        // The checked row shows [*]; unchecked rows show [ ].
        assert!(
            output.contains("[*]"),
            "expected a checked [*] row:\n{output}"
        );
        assert!(
            output.contains("[ ]"),
            "expected unchecked [ ] rows:\n{output}"
        );
    }

    /// Snapshot: call list with autoscroll toggled off via `A`.
    #[test]
    fn call_list_autoscroll_off() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('A')); // toggle autoscroll off
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list while capture is paused via `p`.
    #[test]
    fn call_list_paused() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('p')); // pause
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the status line reports the new timestamp mode after `t`.
    #[test]
    fn call_list_status_error() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('t')); // cycle timestamp → status message
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: search prompt active with "test" typed.
    #[test]
    fn call_list_search_active() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('/')); // activate search
        for c in "test".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the F10 column selector popup.
    #[test]
    fn call_list_column_selector_popup() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(10)); // open column selector
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Call Flow Rendering ───────────────────────────────────────────

    /// Snapshot: call flow after one `t` press. Delta-prev is the default,
    /// so one press lands on Delta-first — the test and its snapshot are
    /// named for what they actually render.
    #[test]
    fn call_flow_timestamp_delta_first() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('t')); // DeltaPrev (default) -> DeltaFirst timestamps
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call flow in CallId color mode via `c`.
    #[test]
    fn call_flow_color_callid() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('c')); // CallId color mode
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call flow with the raw-preview split toggled off via `R`.
    #[test]
    fn call_flow_raw_preview_off() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('R')); // toggle raw preview off
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call flow in extended mode via `x`.
    #[test]
    fn call_flow_extended_flow() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('x')); // extended flow toggle
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: SDP-bearing call flow in SDP Summary mode (`d`).
    #[test]
    fn call_flow_sdp_summary() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_sdp_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('d')); // SDP Summary mode
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: SDP-bearing call flow in SDP Full mode (`d` twice).
    #[test]
    fn call_flow_sdp_full() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_sdp_dialogs();
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('d')); // Summary
        app.handle_key(KeyCode::Char('d')); // Full
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Other Views ───────────────────────────────────────────────────

    /// Snapshot: statistics view with no dialogs.
    #[test]
    fn statistics_view_empty() {
        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: diff of messages 0 and 1 of the first dialog.
    #[test]
    fn message_diff_view() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char(' ')); // select msg 0
        app.handle_key(KeyCode::Down); // move to msg 1
        app.handle_key(KeyCode::Char(' ')); // open diff
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: call list at 60x15, exercising the narrow layout.
    #[test]
    fn narrow_terminal_layout() {
        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: save popup after cycling to the PCAP-NG format.
    #[test]
    fn save_dialog_pcapng_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.pcap");
        app.handle_key(KeyCode::Tab); // cycle to PcapNg
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: save popup after cycling to the TXT format.
    #[test]
    fn save_dialog_txt_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.pcap");
        app.handle_key(KeyCode::Tab); // PcapNg
        app.handle_key(KeyCode::Tab); // Txt
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: the F8 settings popup at 120x40.
    #[test]
    fn settings_popup() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(8));
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: file-open dialog in manual-path mode with a typed path (browser mode would list the cwd).
    #[test]
    fn file_open_popup() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        // Open the file dialog, switch to manual-path mode for deterministic
        // rendering (the browser mode lists the current working directory),
        // then type a sample path.
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Tab);
        app.open_path_clear_for_test();
        for c in "/tmp/test.pcap".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Save dialog new format snapshots ─────────────────────────────

    /// Snapshot: save popup on the JSON format.
    #[test]
    fn save_dialog_json_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.json");
        // Cycle to Json: Pcap -> PcapNg -> Txt -> Json = 3 tabs
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Tab);
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: save popup on the CSV format.
    #[test]
    fn save_dialog_csv_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.csv");
        // Cycle to Csv: 5 tabs
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: save popup on the HTML format.
    #[test]
    fn save_dialog_html_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.html");
        // Cycle to Html: 6 tabs
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    /// Snapshot: save popup on the SIPp XML format.
    #[test]
    fn save_dialog_sipp_xml_format() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_20240615_120000.xml");
        // Cycle to SippXml: 9 tabs
        for _ in 0..9 {
            app.handle_key(KeyCode::Tab);
        }
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Call flow timestamp Scaled mode snapshot ─────────────────────

    /// Snapshot: call flow in Scaled timestamp mode (two `t` presses from the Delta-prev default).
    #[test]
    fn call_flow_timestamp_scaled() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('t')); // DeltaFirst
        app.handle_key(KeyCode::Char('t')); // Scaled
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Call flow with mark set ──────────────────────────────────────

    /// Snapshot: call flow with a mark set at message 0 and the selection moved to message 1.
    #[test]
    fn call_flow_with_mark() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('m')); // set mark at msg 0
        app.handle_key(KeyCode::Down); // move to msg 1
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    // ── Call flow with fold expanded ─────────────────────────────────

    /// Snapshot: call flow with the fold at index 0 expanded via `e`.
    #[test]
    fn call_flow_fold_expanded() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('e')); // expand fold at index 0
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }
}
