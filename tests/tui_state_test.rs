//! TUI state machine tests.
//!
//! Tests App state transitions (view switching, key handling, filtering)
//! without rendering. These exercise the core TUI logic independent of
//! the visual output.

#[cfg(feature = "tui")]
mod tui_state {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{DateTime, TimeDelta, Utc};
    use crossterm::event::KeyCode;

    use sipnab::sip::SipMessage;
    use sipnab::sip::parser::parse_sip;
    use sipnab::tui::{App, View};

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

    fn app_with_three_dialogs() -> App {
        let t0 = base_ts();
        let messages = vec![
            // Dialog 1: Completed
            make_invite("call-1@test", "1001", "1002", t0),
            make_response(
                "call-1@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(2),
            ),
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

    // ── State machine tests ───────────────────────────────────────────

    #[test]
    fn initial_view_is_call_list() {
        let app = App::new_test();
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn tab_switches_to_stream_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
    }

    #[test]
    fn tab_toggles_back_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn q_sets_should_quit() {
        let mut app = App::new_test();
        assert!(!app.should_quit());
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    #[test]
    fn esc_from_help_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1)); // open help
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key(KeyCode::Esc); // close help
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn enter_on_dialog_opens_call_flow() {
        let mut app = app_with_three_dialogs();
        assert_eq!(*app.current_view(), View::CallList);
        app.handle_key(KeyCode::Enter);
        assert!(
            matches!(app.current_view(), View::CallFlow(_)),
            "expected CallFlow, got {:?}",
            app.current_view()
        );
    }

    #[test]
    fn esc_from_call_flow_returns_to_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // call flow
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn enter_on_empty_list_stays_in_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Enter);
        // No dialogs, so Enter does nothing
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn f7_opens_filter_dialog() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        assert_eq!(*app.current_view(), View::FilterDialog);
    }

    #[test]
    fn filter_esc_cancels_without_applying() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7)); // open filter
        assert_eq!(*app.current_view(), View::FilterDialog);
        app.handle_key(KeyCode::Esc); // cancel
        assert_eq!(*app.current_view(), View::CallList);
        assert_eq!(app.visible_dialog_count(), 3); // no filter applied
    }

    #[test]
    fn filter_applied_narrows_visible_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        // Open filter, type "state == 'Failed'", apply
        app.handle_key(KeyCode::F(7));
        for c in "state == 'Failed'".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        assert_eq!(*app.current_view(), View::CallList);
        assert_eq!(app.visible_dialog_count(), 1); // only the Failed dialog
    }

    #[test]
    fn f7_again_clears_filter() {
        let mut app = app_with_three_dialogs();

        // Apply filter
        app.handle_key(KeyCode::F(7));
        for c in "state == 'Failed'".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // F7 again clears
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.visible_dialog_count(), 3);
    }

    #[test]
    fn s_opens_statistics_view() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
    }

    #[test]
    fn esc_from_statistics_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn esc_from_stream_list_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // switch to stream list
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn call_flow_enter_opens_raw_message() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // call flow for dialog 1
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app.handle_key(KeyCode::Enter); // raw message at scroll 0
        assert!(
            matches!(app.current_view(), View::RawMessage { .. }),
            "expected RawMessage, got {:?}",
            app.current_view()
        );
    }

    #[test]
    fn esc_from_raw_message_returns_to_call_flow() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // call flow
        app.handle_key(KeyCode::Enter); // raw message
        assert!(matches!(app.current_view(), View::RawMessage { .. }));
        app.handle_key(KeyCode::Esc); // back to call flow
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    #[test]
    fn q_quits_from_any_view() {
        // From stream list
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());

        // From call flow
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn invalid_filter_shows_error_returns_to_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7)); // open filter
        // Type an invalid expression
        for c in "invalid garbage!!".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        // Should return to call list
        assert_eq!(*app.current_view(), View::CallList);
        // No filter applied (expression was invalid)
        assert_eq!(app.visible_dialog_count(), 3);
    }

    #[test]
    fn empty_filter_clears_active_filter() {
        let mut app = app_with_three_dialogs();

        // Apply a valid filter
        app.handle_key(KeyCode::F(7));
        for c in "state == 'Failed'".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // F7 clears active filter (since one is set)
        app.handle_key(KeyCode::F(7));
        assert_eq!(*app.current_view(), View::CallList); // stays in call list
        assert_eq!(app.visible_dialog_count(), 3); // filter cleared

        // Now F7 opens filter dialog since no filter is active
        app.handle_key(KeyCode::F(7));
        assert_eq!(*app.current_view(), View::FilterDialog);
        // Submit empty string to clear (no-op since already cleared)
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 3);
    }
}
