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
    use sipnab::tui::{App, Popup, View};

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
    fn f7_opens_filter_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
        // Underlying view is still CallList
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn filter_esc_cancels_without_applying() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7)); // open filter popup
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
        app.handle_key(KeyCode::Esc); // cancel
        assert_eq!(app.active_popup(), None);
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

        // Now F7 opens filter popup since no filter is active
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
        // Submit empty string to clear (no-op since already cleared)
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 3);
    }

    // ── F5 / Ctrl-L — Clear calls ─────────────────────────────────────

    #[test]
    fn f5_clears_all_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::F(5));
        assert_eq!(app.visible_dialog_count(), 0);
    }

    #[test]
    fn ctrl_l_clears_all_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key_with_modifiers(
            KeyCode::Char('l'),
            crossterm::event::KeyModifiers::CONTROL,
        );
        assert_eq!(app.visible_dialog_count(), 0);
    }

    #[test]
    fn f5_clears_only_selected_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        // Select first dialog (row 0)
        app.handle_key(KeyCode::Char(' ')); // toggle select row 0
        // Clear selected only
        app.handle_key(KeyCode::F(5));
        assert_eq!(app.visible_dialog_count(), 2);
    }

    // ── F6 / r — Raw message view ─────────────────────────────────────

    #[test]
    fn f6_opens_raw_message_view() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(6));
        assert!(
            matches!(app.current_view(), View::RawMessage { .. }),
            "expected RawMessage, got {:?}",
            app.current_view()
        );
    }

    #[test]
    fn r_opens_raw_message_view() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('r'));
        assert!(
            matches!(app.current_view(), View::RawMessage { .. }),
            "expected RawMessage, got {:?}",
            app.current_view()
        );
    }

    // ── F10 / t — Column selector ─────────────────────────────────────

    #[test]
    fn f10_opens_column_selector() {
        let mut app = App::new_test();
        assert!(!app.call_list_state().column_selector_open);
        app.handle_key(KeyCode::F(10));
        assert!(app.call_list_state().column_selector_open);
    }

    #[test]
    fn t_opens_column_selector() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('t'));
        assert!(app.call_list_state().column_selector_open);
    }

    #[test]
    fn column_selector_enter_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10)); // open
        assert!(app.call_list_state().column_selector_open);
        app.handle_key(KeyCode::Enter); // close
        assert!(!app.call_list_state().column_selector_open);
    }

    #[test]
    fn column_selector_esc_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Esc);
        assert!(!app.call_list_state().column_selector_open);
    }

    #[test]
    fn column_selector_space_toggles_visibility() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10)); // open column selector
        // All columns visible by default
        assert!(app.call_list_state().visible_columns[0]);
        app.handle_key(KeyCode::Char(' ')); // toggle first column
        assert!(!app.call_list_state().visible_columns[0]);
        app.handle_key(KeyCode::Char(' ')); // toggle back
        assert!(app.call_list_state().visible_columns[0]);
    }

    // ── Sort column cycling ───────────────────────────────────────────

    #[test]
    fn angle_brackets_cycle_sort_column() {
        use sipnab::tui::call_list::SortColumn;
        let mut app = App::new_test();
        assert_eq!(app.call_list_state().sort_column(), SortColumn::Index);

        app.handle_key(KeyCode::Char('>')); // next -> Method
        assert_eq!(app.call_list_state().sort_column(), SortColumn::Method);

        app.handle_key(KeyCode::Char('>')); // next -> From
        assert_eq!(app.call_list_state().sort_column(), SortColumn::From);

        app.handle_key(KeyCode::Char('<')); // prev -> Method
        assert_eq!(app.call_list_state().sort_column(), SortColumn::Method);

        app.handle_key(KeyCode::Char('<')); // prev -> Index
        assert_eq!(app.call_list_state().sort_column(), SortColumn::Index);
    }

    // ── Z — Reverse sort ──────────────────────────────────────────────

    #[test]
    fn z_reverses_sort_direction() {
        let mut app = App::new_test();
        assert!(app.call_list_state().sort_ascending());
        app.handle_key(KeyCode::Char('Z'));
        assert!(!app.call_list_state().sort_ascending());
        app.handle_key(KeyCode::Char('Z'));
        assert!(app.call_list_state().sort_ascending());
    }

    // ── A — Toggle autoscroll ─────────────────────────────────────────

    #[test]
    fn a_toggles_autoscroll() {
        let mut app = App::new_test();
        assert!(app.call_list_state().autoscroll);
        app.handle_key(KeyCode::Char('A'));
        assert!(!app.call_list_state().autoscroll);
        app.handle_key(KeyCode::Char('A'));
        assert!(app.call_list_state().autoscroll);
    }

    // ── p — Pause/resume ──────────────────────────────────────────────

    #[test]
    fn p_toggles_paused() {
        let mut app = App::new_test();
        assert!(!app.paused());
        app.handle_key(KeyCode::Char('p'));
        assert!(app.paused());
        app.handle_key(KeyCode::Char('p'));
        assert!(!app.paused());
    }

    // ── i/I — Clear with filter ───────────────────────────────────────

    #[test]
    fn i_clears_non_matching_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        // Apply filter: keep only Failed
        app.handle_key(KeyCode::F(7));
        for c in "state == 'Failed'".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // i: clear non-matching (keep only Failed)
        app.handle_key(KeyCode::Char('i'));

        // Now clear filter to see all remaining
        app.handle_key(KeyCode::F(7)); // clears active filter
        // Only the Failed dialog should remain
        assert_eq!(app.visible_dialog_count(), 1);
    }

    #[test]
    fn i_uppercase_clears_matching_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        // Apply filter: match Failed
        app.handle_key(KeyCode::F(7));
        for c in "state == 'Failed'".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // I: clear matching (remove Failed, keep the rest)
        app.handle_key(KeyCode::Char('I'));

        // Clear filter to see all remaining
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.visible_dialog_count(), 2);
    }

    #[test]
    fn i_without_filter_does_nothing() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::Char('i'));
        assert_eq!(app.visible_dialog_count(), 3); // no change
    }

    #[test]
    fn i_uppercase_without_filter_does_nothing() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::Char('I'));
        assert_eq!(app.visible_dialog_count(), 3); // no change
    }
}
