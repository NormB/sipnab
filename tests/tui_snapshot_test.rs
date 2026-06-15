//! TUI snapshot tests using ratatui's TestBackend and insta.
//!
//! Each test renders a specific view into an in-memory terminal buffer, then
//! snapshots the textual content via `insta::assert_snapshot!`.

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

    fn localhost_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn localhost_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
    }

    fn base_ts() -> DateTime<Utc> {
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0).unwrap()
    }

    fn build_sip(first_line: &str, headers: &[&str]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg
    }

    fn make_invite(call_id: &str, from: &str, to: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
                &format!("To: \"{to}\" <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            localhost_a(),
            localhost_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse INVITE")
    }

    fn make_response(
        call_id: &str,
        status: u16,
        reason: &str,
        cseq_method: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("SIP/2.0 {status} {reason}"),
            &[
                "From: \"Alice\" <sip:1001@example.com>;tag=t1",
                "To: \"Bob\" <sip:1002@example.com>;tag=t2",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: 1 {cseq_method}"),
                "Content-Length: 0",
            ],
        );
        parse_sip(
            &raw,
            ts,
            localhost_b(),
            localhost_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse response")
    }

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
            localhost_a(),
            localhost_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse BYE")
    }

    // ── Helper: create App with 3 test dialogs ─────────────────────────

    /// Dialog 1: Completed INVITE 1001 -> 1002
    /// Dialog 2: Failed INVITE 1003 -> 1004
    /// Dialog 3: Active (InCall) INVITE 1005 -> 1006
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
            store.mark_orphaned(std::time::Duration::from_secs(0));
        }

        App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        )
    }

    // ── Snapshot tests ────────────────────────────────────────────────

    #[test]
    fn call_list_empty() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn call_list_with_dialogs() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn call_list_with_dialogs_wide() {
        let backend = TestBackend::new(130, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

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

    #[test]
    fn help_view() {
        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(crossterm::event::KeyCode::F(1)); // open help

        terminal.draw(|frame| app.render(frame)).unwrap();

        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

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

    #[test]
    fn call_list_timestamp_delta_prev() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('t')); // cycle to DeltaPrev
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn call_list_timestamp_delta_first() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Char('t')); // DeltaPrev
        app.handle_key(KeyCode::Char('t')); // DeltaFirst
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

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

    #[test]
    fn call_flow_timestamp_delta_prev() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow
        app.handle_key(KeyCode::Char('t')); // DeltaPrev timestamps
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

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

    #[test]
    fn narrow_terminal_layout() {
        let backend = TestBackend::new(60, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = test_app_with_dialogs();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let output = buffer_to_string(&terminal);
        insta::assert_snapshot!(output);
    }

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
