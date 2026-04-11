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
        parse_sip(&raw, ts, localhost_a(), localhost_b(), 5060, 5060, "UDP").expect("parse INVITE")
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
        parse_sip(&raw, ts, localhost_b(), localhost_a(), 5060, 5060, "UDP")
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
        parse_sip(&raw, ts, localhost_a(), localhost_b(), 5060, 5060, "UDP").expect("parse BYE")
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
                payload: vec![0u8; 172],
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
                payload: vec![0u8; 172],
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

        App::new(ds, ss)
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
}
