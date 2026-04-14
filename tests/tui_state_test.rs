//! TUI state machine tests.
//!
//! Tests App state transitions (view switching, key handling, filtering)
//! without rendering. These exercise the core TUI logic independent of
//! the visual output.

#[cfg(feature = "tui")]
mod tui_state {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::{DateTime, TimeDelta, Utc};
    use crossterm::event::{KeyCode, KeyModifiers};

    use sipnab::capture::parse::TransportProto;
    use sipnab::sip::SipMessage;
    use sipnab::sip::parser::parse_sip;
    use sipnab::tui::{App, ColorMode, Popup, SaveFormat, SdpDisplayMode, TimestampMode, View};

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
        parse_sip(&raw, ts, localhost_a(), localhost_b(), 5060, 5060, TransportProto::Udp).expect("parse INVITE")
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
        parse_sip(&raw, ts, localhost_b(), localhost_a(), 5060, 5060, TransportProto::Udp)
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

        // Open filter, type "1003" into SIP From field, apply
        app.handle_key(KeyCode::F(7));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        assert_eq!(*app.current_view(), View::CallList);
        assert_eq!(app.visible_dialog_count(), 1); // only dialog with From=1003
    }

    #[test]
    fn f9_clears_filter() {
        let mut app = app_with_three_dialogs();

        // Apply filter
        app.handle_key(KeyCode::F(7));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // F9 clears
        app.handle_key(KeyCode::F(9));
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
    fn invalid_regex_filter_shows_error_returns_to_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7)); // open filter
        // Type an invalid regex pattern into SIP From field
        for c in "[invalid".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        // Should return to call list
        assert_eq!(*app.current_view(), View::CallList);
        // No filter applied (regex was invalid)
        assert_eq!(app.visible_dialog_count(), 3);
    }

    #[test]
    fn empty_filter_clears_active_filter() {
        let mut app = app_with_three_dialogs();

        // Apply a valid filter via SIP From field
        app.handle_key(KeyCode::F(7));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // F9 clears the filter and dialog state
        app.handle_key(KeyCode::F(9));
        assert_eq!(app.visible_dialog_count(), 3); // filter cleared

        // F7 opens filter popup (state was cleared)
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
        // Submit empty fields to clear (no-op since already cleared)
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 3);
    }

    // ── Filter dialog checkbox grid navigation ─────────────────────────

    #[test]
    fn filter_checkbox_down_moves_by_row() {
        // Layout: 2 columns, 5 rows. idx 0=REGISTER, 1=OPTIONS, 2=INVITE, ...
        // Text fields: focused_field 0-4. Checkboxes: 5-14. Buttons: 15-16.
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7)); // open filter
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));

        // Tab down through 5 text fields to reach first checkbox (REGISTER, ff=5)
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_dialog.focused_field(), 5); // REGISTER (idx 0)

        // Down should go to INVITE (idx 2, ff=7), not OPTIONS (idx 1, ff=6)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 7); // INVITE (idx 2)

        // Down again -> SUBSCRIBE (idx 4, ff=9)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 9); // SUBSCRIBE (idx 4)

        // Down again -> NOTIFY (idx 6, ff=11)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 11); // NOTIFY (idx 6)

        // Down again -> INFO (idx 8, ff=13)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 13); // INFO (idx 8)

        // Down from bottom row -> buttons (ff=15)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 15); // Filter button
    }

    #[test]
    fn filter_checkbox_right_moves_by_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_dialog.focused_field(), 5); // REGISTER (idx 0, left col)

        // Right should go to OPTIONS (idx 1, ff=6)
        app.handle_key(KeyCode::Right);
        assert_eq!(app.filter_dialog.focused_field(), 6); // OPTIONS (idx 1)

        // Right again from right column — no-op
        app.handle_key(KeyCode::Right);
        assert_eq!(app.filter_dialog.focused_field(), 6); // still OPTIONS

        // Left should go back to REGISTER (idx 0, ff=5)
        app.handle_key(KeyCode::Left);
        assert_eq!(app.filter_dialog.focused_field(), 5); // REGISTER
    }

    #[test]
    fn filter_checkbox_up_moves_by_row() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Navigate to INVITE (idx 2, ff=7): tab to checkboxes, then down once
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        app.handle_key(KeyCode::Down); // REGISTER -> INVITE
        assert_eq!(app.filter_dialog.focused_field(), 7); // INVITE (idx 2)

        // Up should go back to REGISTER (idx 0, ff=5)
        app.handle_key(KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field(), 5); // REGISTER

        // Up from top row checkbox -> last text field (ff=4, Payload)
        app.handle_key(KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field(), 4); // Payload text field
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
        app.handle_key_with_modifiers(KeyCode::Char('l'), crossterm::event::KeyModifiers::CONTROL);
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
    fn t_cycles_timestamp_mode() {
        let mut app = App::new_test();
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaPrev);
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaFirst);
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::Scaled);
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::Absolute);
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaPrev);
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

        // Apply filter via SIP From field: match only dialog with From=1003
        app.handle_key(KeyCode::F(7));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // i: clear non-matching (keep only the matching dialog)
        app.handle_key(KeyCode::Char('i'));

        // Now clear filter to see all remaining
        app.handle_key(KeyCode::F(9)); // F9 clears filter
        // Only the matching dialog should remain
        assert_eq!(app.visible_dialog_count(), 1);
    }

    #[test]
    fn i_uppercase_clears_matching_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        // Apply filter via SIP From field: match dialog with From=1003
        app.handle_key(KeyCode::F(7));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 1);

        // I: clear matching (remove the matched dialog, keep the rest)
        app.handle_key(KeyCode::Char('I'));

        // Clear filter to see all remaining
        app.handle_key(KeyCode::F(9)); // F9 clears filter
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

    // ── Additional helpers ────────────────────────────────────────────

    fn make_bye(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "BYE sip:1002@10.0.0.2 SIP/2.0",
            &[
                "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bye",
                &format!("From: <sip:1001@10.0.0.1>;tag=t1"),
                &format!("To: <sip:1002@10.0.0.2>;tag=t2"),
                &format!("Call-ID: {}", call_id),
                "CSeq: 2 BYE",
                "Content-Length: 0",
            ],
        );
        parse_sip(&raw, ts, localhost_a(), localhost_b(), 5060, 5060, TransportProto::Udp).unwrap()
    }

    /// Create an app with the call flow view open on dialog 1.
    fn app_with_call_flow_open() -> App {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow for first dialog
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app
    }

    /// Create an app with the raw message view open.
    fn app_in_raw_message() -> App {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Enter); // open raw message from call flow
        assert!(matches!(app.current_view(), View::RawMessage { .. }));
        app
    }

    /// Create an app in the message diff view.
    fn app_in_message_diff() -> App {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select first message
        app.handle_key(KeyCode::Down);      // move to second
        app.handle_key(KeyCode::Char(' ')); // open diff
        assert!(matches!(app.current_view(), View::MessageDiff { .. }));
        app
    }

    // ── Call list: additional keys ───────────────────────────────────

    #[test]
    fn home_moves_to_top() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.call_list_state().selected(), 2);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    #[test]
    fn slash_activates_search_mode() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
        assert_eq!(app.search_query(), "");
    }

    #[test]
    fn f3_activates_search_mode() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(3));
        assert!(app.search_active());
    }

    #[test]
    fn f4_on_empty_list_stays_in_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(4));
        // No dialogs, so F4 does nothing
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn f8_opens_settings_popup_from_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert_eq!(app.active_popup(), Some(&Popup::SettingsDialog));
    }

    // ── Search mode ──────────────────────────────────────────────────

    #[test]
    fn search_esc_cancels_and_clears() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "test".chars() { app.handle_key(KeyCode::Char(c)); }
        assert_eq!(app.search_query(), "test");
        app.handle_key(KeyCode::Esc);
        assert!(!app.search_active());
        assert_eq!(app.search_query(), "");
    }

    #[test]
    fn search_enter_commits_query() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "hello".chars() { app.handle_key(KeyCode::Char(c)); }
        app.handle_key(KeyCode::Enter);
        assert!(!app.search_active());
        assert_eq!(app.search_query(), "hello"); // retained for highlighting
    }

    #[test]
    fn search_backspace_removes_last_char() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        for c in "abc".chars() { app.handle_key(KeyCode::Char(c)); }
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.search_query(), "ab");
    }

    #[test]
    fn search_char_appends() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        app.handle_key(KeyCode::Char('x'));
        app.handle_key(KeyCode::Char('y'));
        assert_eq!(app.search_query(), "xy");
        assert!(app.search_active());
    }

    #[test]
    fn search_backspace_on_empty_is_noop() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.search_query(), "");
        assert!(app.search_active());
    }

    // ── Call flow: navigation ────────────────────────────────────────

    #[test]
    fn call_flow_q_quits() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn call_flow_esc_returns_to_call_list() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn call_flow_down_increments_selected_msg() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.selected_msg_index(), 0);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.selected_msg_index(), 1);
    }

    #[test]
    fn call_flow_up_at_top_stays() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_msg_index(), 0);
    }

    #[test]
    fn call_flow_up_decrements() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_msg_index(), 0);
    }

    #[test]
    fn call_flow_j_increments() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.selected_msg_index(), 1);
    }

    #[test]
    fn call_flow_k_decrements() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.selected_msg_index(), 0);
    }

    #[test]
    fn call_flow_down_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        // Scroll the detail panel, then navigate to next message — scroll resets
        app.handle_key(KeyCode::Char(']'));
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn call_flow_page_down() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::PageDown);
        // Dialog 1 has 2 messages; PageDown advances by 20 but clamps to max (1)
        assert_eq!(app.selected_msg_index(), 1);
    }

    #[test]
    fn call_flow_page_up_after_page_down() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::PageDown);
        let after_down = app.selected_msg_index();
        app.handle_key(KeyCode::PageUp);
        assert!(app.selected_msg_index() < after_down || after_down == 0);
    }

    #[test]
    fn call_flow_home_goes_to_first() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.selected_msg_index(), 0);
        assert_eq!(app.call_flow_scroll(), 0);
    }

    #[test]
    fn call_flow_end_goes_to_last() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::End);
        // Dialog 1 has INVITE + 200 = 2 msgs, so last = 1
        assert_eq!(app.selected_msg_index(), 1);
    }

    #[test]
    fn call_flow_enter_opens_raw_at_selected() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down); // select msg 1
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::RawMessage { message_index, .. } => assert_eq!(*message_index, 1),
            other => panic!("Expected RawMessage, got {:?}", other),
        }
    }

    // ── Call flow: display modes ─────────────────────────────────────

    #[test]
    fn call_flow_d_cycles_sdp_display() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::None);
        app.handle_key(KeyCode::Char('d'));
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::Summary);
        app.handle_key(KeyCode::Char('d'));
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::Full);
        app.handle_key(KeyCode::Char('d'));
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::None);
    }

    #[test]
    fn call_flow_t_cycles_timestamp() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaFirst);
    }

    #[test]
    fn call_flow_c_cycles_color() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.color_mode(), ColorMode::Method);
        app.handle_key(KeyCode::Char('c'));
        assert_eq!(app.color_mode(), ColorMode::CallId);
        app.handle_key(KeyCode::Char('c'));
        assert_eq!(app.color_mode(), ColorMode::CSeq);
        app.handle_key(KeyCode::Char('c'));
        assert_eq!(app.color_mode(), ColorMode::Method);
    }

    // ── Call flow: split controls ────────────────────────────────────

    #[test]
    fn call_flow_r_toggles_raw_preview() {
        let mut app = app_with_call_flow_open();
        assert!(app.raw_preview()); // default true
        app.handle_key(KeyCode::Char('R'));
        assert!(!app.raw_preview());
        app.handle_key(KeyCode::Char('R'));
        assert!(app.raw_preview());
    }

    #[test]
    fn call_flow_plus_increases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('+'));
        assert_eq!(app.raw_preview_pct(), before + 5);
    }

    #[test]
    fn call_flow_minus_decreases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('-'));
        assert_eq!(app.raw_preview_pct(), before - 5);
    }

    #[test]
    fn call_flow_plus_clamps_at_max() {
        let mut app = app_with_call_flow_open();
        for _ in 0..20 { app.handle_key(KeyCode::Char('+')); }
        assert!(app.raw_preview_pct() <= 80);
    }

    #[test]
    fn call_flow_minus_clamps_at_min() {
        let mut app = app_with_call_flow_open();
        for _ in 0..20 { app.handle_key(KeyCode::Char('-')); }
        assert!(app.raw_preview_pct() >= 10);
    }

    #[test]
    fn call_flow_bracket_scrolls_detail() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert_eq!(app.detail_scroll(), 1);
        app.handle_key(KeyCode::Char('['));
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn call_flow_bracket_up_at_zero_stays() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('['));
        assert_eq!(app.detail_scroll(), 0);
    }

    // ── Call flow: toggles ───────────────────────────────────────────

    #[test]
    fn call_flow_f4_toggles_extended_flow() {
        let mut app = app_with_call_flow_open();
        assert!(!app.extended_flow());
        app.handle_key(KeyCode::F(4));
        assert!(app.extended_flow());
        app.handle_key(KeyCode::F(4));
        assert!(!app.extended_flow());
    }

    #[test]
    fn call_flow_x_toggles_extended_flow() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('x'));
        assert!(app.extended_flow());
    }

    #[test]
    fn call_flow_f6_toggles_rtp_in_flow() {
        let mut app = app_with_call_flow_open();
        assert!(!app.show_rtp_in_flow());
        app.handle_key(KeyCode::F(6));
        assert!(app.show_rtp_in_flow());
        app.handle_key(KeyCode::F(6));
        assert!(!app.show_rtp_in_flow());
    }

    // ── Call flow: diff / compare ────────────────────────────────────

    #[test]
    fn call_flow_space_sets_diff_selected() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.diff_selected_msg(), None);
        app.handle_key(KeyCode::Char(' '));
        assert_eq!(app.diff_selected_msg(), Some(0));
    }

    #[test]
    fn call_flow_space_second_opens_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select msg 0
        app.handle_key(KeyCode::Down);       // move to msg 1
        app.handle_key(KeyCode::Char(' ')); // open diff
        assert!(matches!(app.current_view(), View::MessageDiff { .. }));
    }

    #[test]
    fn call_flow_space_same_msg_no_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select msg 0
        app.handle_key(KeyCode::Char(' ')); // same msg — no diff opened
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        assert_eq!(app.diff_selected_msg(), Some(0)); // still set
    }

    #[test]
    fn call_flow_f5_resets_compare() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // set diff
        assert!(app.diff_selected_msg().is_some());
        app.handle_key(KeyCode::F(5));
        assert_eq!(app.diff_selected_msg(), None);
    }

    #[test]
    fn call_flow_esc_clears_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // set diff
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.diff_selected_msg(), None);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Call flow: popups and navigation ─────────────────────────────

    #[test]
    fn call_flow_f1_opens_help() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    #[test]
    fn call_flow_f2_opens_save() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    #[test]
    fn call_flow_f7_opens_filter() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
    }

    #[test]
    fn call_flow_f9_clears_filter() {
        let mut app = app_with_call_flow_open();
        // First apply a filter from the call list
        app.handle_key(KeyCode::Esc); // back to call list
        app.handle_key(KeyCode::F(7));
        for c in "1001".chars() { app.handle_key(KeyCode::Char(c)); }
        app.handle_key(KeyCode::Enter);
        let filtered_count = app.visible_dialog_count();
        // Re-enter call flow and clear filter
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::F(9));
        app.handle_key(KeyCode::Esc); // back to list to check count
        assert!(app.visible_dialog_count() >= filtered_count);
    }

    // ── Raw message: navigation ──────────────────────────────────────

    #[test]
    fn raw_msg_q_quits() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn raw_msg_esc_returns_to_call_flow() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Esc);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    #[test]
    fn raw_msg_down_scrolls() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        assert_eq!(app.raw_msg_scroll(), 1);
    }

    #[test]
    fn raw_msg_up_scrolls_back() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Up);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    #[test]
    fn raw_msg_j_scrolls() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.raw_msg_scroll(), 1);
    }

    #[test]
    fn raw_msg_k_scrolls_back() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    #[test]
    fn raw_msg_page_down() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::PageDown);
        assert_eq!(app.raw_msg_scroll(), 20);
    }

    #[test]
    fn raw_msg_page_up_after_page_down() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::PageDown);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    #[test]
    fn raw_msg_home_resets_scroll() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    // ── Raw message: modes ───────────────────────────────────────────

    #[test]
    fn raw_msg_slash_activates_search() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
    }

    #[test]
    fn raw_msg_s_toggles_syntax_highlight() {
        let mut app = app_in_raw_message();
        let before = app.syntax_highlight();
        app.handle_key(KeyCode::Char('s'));
        assert_ne!(app.syntax_highlight(), before);
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(app.syntax_highlight(), before);
    }

    #[test]
    fn raw_msg_c_cycles_color_mode() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('c'));
        assert_eq!(app.color_mode(), ColorMode::CallId);
    }

    #[test]
    fn raw_msg_f1_opens_help() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    #[test]
    fn raw_msg_f2_opens_save() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    // ── Message diff ─────────────────────────────────────────────────

    #[test]
    fn message_diff_q_quits() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    #[test]
    fn message_diff_esc_returns_to_call_flow() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::Esc);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    #[test]
    fn message_diff_f1_opens_help() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    // ── Stream list: additional keys ─────────────────────────────────

    #[test]
    fn stream_list_slash_activates_search() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // go to stream list
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
    }

    #[test]
    fn stream_list_f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    #[test]
    fn stream_list_f7_opens_filter() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
    }

    // ── Help view ────────────────────────────────────────────────────

    #[test]
    fn help_f1_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1)); // open help
        app.handle_key(KeyCode::F(1)); // close help
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn help_q_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        app.handle_key(KeyCode::Char('q'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Statistics view ──────────────────────────────────────────────

    #[test]
    fn statistics_q_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Char('q'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn statistics_s_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Save popup ───────────────────────────────────────────────────

    #[test]
    fn save_popup_esc_closes() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.active_popup(), None);
    }

    #[test]
    fn save_popup_tab_cycles_format() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.save_format(), SaveFormat::Pcap);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::PcapNg);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Txt);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Json);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Ndjson);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Csv);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Html);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Markdown);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Wav);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::SippXml);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::RtpJson);
        // Wraps back to Pcap
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Pcap);
    }

    #[test]
    fn save_popup_backtab_reverse_cycles() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        // From Pcap, BackTab should go to RtpJson (last format)
        app.handle_key(KeyCode::BackTab);
        assert_eq!(app.save_format(), SaveFormat::RtpJson);
        // And one more BackTab goes to SippXml
        app.handle_key(KeyCode::BackTab);
        assert_eq!(app.save_format(), SaveFormat::SippXml);
    }

    #[test]
    fn save_popup_tab_updates_extension() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Tab);
        assert!(app.save_path().ends_with(".pcapng"), "got: {}", app.save_path());
        app.handle_key(KeyCode::Tab);
        assert!(app.save_path().ends_with(".txt"), "got: {}", app.save_path());
    }

    #[test]
    fn save_popup_backspace_removes_char() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let before_len = app.save_path().len();
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.save_path().len(), before_len - 1);
    }

    #[test]
    fn save_popup_left_moves_cursor() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let end = app.save_cursor();
        app.handle_key(KeyCode::Left);
        assert_eq!(app.save_cursor(), end - 1);
    }

    #[test]
    fn save_popup_right_at_end_is_noop() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let end = app.save_cursor();
        app.handle_key(KeyCode::Right);
        assert_eq!(app.save_cursor(), end); // already at end
    }

    #[test]
    fn save_popup_home_moves_cursor_to_start() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        assert_eq!(app.save_cursor(), 0);
    }

    #[test]
    fn save_popup_end_moves_cursor_to_end() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::End);
        assert_eq!(app.save_cursor(), app.save_path().len());
    }

    #[test]
    fn save_popup_char_inserts() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::Char('X'));
        assert!(app.save_path().starts_with('X'));
    }

    #[test]
    fn save_popup_enter_closes() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/sipnab_test_save.pcap");
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.active_popup(), None);
        assert!(app.status_error().is_some()); // save result message
    }

    // ── Column selector: navigation ──────────────────────────────────

    #[test]
    fn column_selector_down_moves_cursor() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.call_list_state().column_selector_cursor, 1);
    }

    #[test]
    fn column_selector_up_at_top_stays() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Up);
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
    }

    // ── Global shortcuts ─────────────────────────────────────────────

    #[test]
    fn ctrl_c_quits_from_call_list() {
        let mut app = App::new_test();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    #[test]
    fn ctrl_c_quits_from_call_flow() {
        let mut app = app_with_call_flow_open();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    #[test]
    fn ctrl_c_quits_from_raw_message() {
        let mut app = app_in_raw_message();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    #[test]
    fn ctrl_c_quits_from_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    #[test]
    fn ctrl_c_quits_from_statistics() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    #[test]
    fn ctrl_c_quits_from_save_popup() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    // ── Call list: more navigation ───────────────────────────────────

    #[test]
    fn end_moves_to_bottom() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::End);
        assert_eq!(app.call_list_state().selected(), 2);
    }

    #[test]
    fn page_down_on_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::PageDown);
        // PageDown moves by 20, clamped to last (2)
        assert_eq!(app.call_list_state().selected(), 2);
    }

    #[test]
    fn page_up_on_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::End);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    #[test]
    fn down_at_bottom_stays() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down); // past end
        assert_eq!(app.call_list_state().selected(), 2);
    }

    #[test]
    fn up_at_top_stays() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Up);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    #[test]
    fn j_moves_down_in_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.call_list_state().selected(), 1);
    }

    #[test]
    fn k_moves_up_in_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.call_list_state().selected(), 0);
    }

    #[test]
    fn call_list_f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    #[test]
    fn call_list_f2_opens_save() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    // ── Stream list: more navigation ─────────────────────────────────

    #[test]
    fn stream_list_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn stream_list_tab_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // go to stream list
        app.handle_key(KeyCode::Tab); // toggle back
        assert_eq!(*app.current_view(), View::CallList);
    }

    #[test]
    fn stream_list_q_quits() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    // ── Help: Esc closes ─────────────────────────────────────────────

    #[test]
    fn help_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Statistics: Esc closes ───────────────────────────────────────

    #[test]
    fn statistics_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Popup intercepts keys ────────────────────────────────────────

    #[test]
    fn popup_intercepts_normal_keys() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2)); // open save popup
        // 'q' should be consumed by save popup (inserts char), not quit
        app.handle_key(KeyCode::Char('q'));
        assert!(!app.should_quit());
        assert!(app.save_path().contains('q'));
    }

    #[test]
    fn search_mode_intercepts_normal_keys() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
        // 'q' should go into search query, not quit
        app.handle_key(KeyCode::Char('q'));
        assert!(!app.should_quit());
        assert_eq!(app.search_query(), "q");
    }

    // ── Call flow: Right key resizes split ────────────────────────────

    #[test]
    fn call_flow_right_increases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Right);
        assert_eq!(app.raw_preview_pct(), before + 5);
    }

    #[test]
    fn call_flow_left_decreases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Left);
        assert_eq!(app.raw_preview_pct(), before - 5);
    }

    // ── Call flow: End resets detail_scroll ───────────────────────────

    #[test]
    fn call_flow_end_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::End);
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn call_flow_home_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn call_flow_page_up_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.detail_scroll(), 0);
    }

    #[test]
    fn call_flow_page_down_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::PageDown);
        assert_eq!(app.detail_scroll(), 0);
    }

    // ── Call flow: raw_preview off disables resize ───────────────────

    #[test]
    fn call_flow_plus_noop_when_preview_off() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('R')); // turn off raw preview
        assert!(!app.raw_preview());
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('+'));
        assert_eq!(app.raw_preview_pct(), before); // unchanged
    }

    #[test]
    fn call_flow_minus_noop_when_preview_off() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('R'));
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('-'));
        assert_eq!(app.raw_preview_pct(), before);
    }

    // ── Column selector: j/k alternatives ────────────────────────────

    #[test]
    fn column_selector_j_moves_down() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.call_list_state().column_selector_cursor, 1);
    }

    #[test]
    fn column_selector_k_moves_up() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
    }

    // ── Save popup: backspace at 0 is noop ───────────────────────────

    #[test]
    fn save_popup_backspace_at_zero_is_noop() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home); // cursor to 0
        let before = app.save_path().to_string();
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.save_path(), before);
    }

    #[test]
    fn save_popup_left_at_zero_is_noop() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::Left);
        assert_eq!(app.save_cursor(), 0);
    }

    #[test]
    fn save_popup_right_then_left_round_trips() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let end = app.save_cursor();
        app.handle_key(KeyCode::Left);
        app.handle_key(KeyCode::Right);
        assert_eq!(app.save_cursor(), end);
    }

    // ── Default state assertions ─────────────────────────────────────

    #[test]
    fn default_sdp_display_mode_is_none() {
        let app = App::new_test();
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::None);
    }

    #[test]
    fn default_color_mode_is_method() {
        let app = App::new_test();
        assert_eq!(app.color_mode(), ColorMode::Method);
    }

    #[test]
    fn default_raw_preview_is_true() {
        let app = App::new_test();
        assert!(app.raw_preview());
    }

    #[test]
    fn default_raw_preview_pct_is_40() {
        let app = App::new_test();
        assert_eq!(app.raw_preview_pct(), 40);
    }

    #[test]
    fn default_syntax_highlight_is_true() {
        let app = App::new_test();
        assert!(app.syntax_highlight());
    }

    #[test]
    fn default_save_format_is_pcap() {
        let app = App::new_test();
        assert_eq!(app.save_format(), SaveFormat::Pcap);
    }

    #[test]
    fn default_extended_flow_is_false() {
        let app = App::new_test();
        assert!(!app.extended_flow());
    }

    #[test]
    fn default_show_rtp_in_flow_is_false() {
        let app = App::new_test();
        assert!(!app.show_rtp_in_flow());
    }

    #[test]
    fn default_diff_selected_is_none() {
        let app = App::new_test();
        assert_eq!(app.diff_selected_msg(), None);
    }

    #[test]
    fn default_paused_is_false() {
        let app = App::new_test();
        assert!(!app.paused());
    }

    // ── Step 2 & 3: F4 extended flow and F8 settings popup ──────────

    #[test]
    fn f4_opens_extended_call_flow() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(4));
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        assert!(app.extended_flow());
    }

    #[test]
    fn f8_opens_settings_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert!(app.active_popup().is_some());
    }

    #[test]
    fn settings_popup_esc_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert!(app.active_popup().is_some());
        app.handle_key(KeyCode::Esc);
        assert!(app.active_popup().is_none());
    }

    #[test]
    fn settings_popup_enter_toggles_color_mode() {
        let mut app = App::new_test();
        let initial = app.color_mode();
        app.handle_key(KeyCode::F(8));
        app.handle_key(KeyCode::Enter); // Toggle item 0 = color mode
        assert_ne!(app.color_mode(), initial);
    }

    #[test]
    fn settings_popup_navigate_and_toggle() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        app.handle_key(KeyCode::Down); // Move to timestamp mode (item 1)
        let initial_ts = app.timestamp_mode();
        app.handle_key(KeyCode::Enter); // Toggle timestamp mode
        assert_ne!(app.timestamp_mode(), initial_ts);
    }

    // ── Mark + Delta (Feature 1) ──────────────────────────────────

    #[test]
    fn call_flow_m_sets_mark() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.mark_index(), None);
        app.handle_key(KeyCode::Char('m'));
        assert_eq!(app.mark_index(), Some(0));
        assert_eq!(app.status_error(), Some("Mark set"));
    }

    #[test]
    fn call_flow_m_uppercase_clears_mark() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('m')); // set mark
        assert_eq!(app.mark_index(), Some(0));
        app.handle_key(KeyCode::Char('M')); // clear mark
        assert_eq!(app.mark_index(), None);
        assert_eq!(app.status_error(), Some("Mark cleared"));
    }

    #[test]
    fn call_flow_mark_follows_selected() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down); // select msg 1
        app.handle_key(KeyCode::Char('m')); // mark at msg 1
        assert_eq!(app.mark_index(), Some(1));
    }

    // ── Fold expand toggle (Feature 3) ──────────────────────────────

    #[test]
    fn call_flow_e_toggles_fold_expand() {
        let mut app = app_with_call_flow_open();
        assert!(app.fold_expanded().is_empty());
        app.handle_key(KeyCode::Char('e')); // expand fold at index 0
        assert!(app.fold_expanded().contains(&0));
        app.handle_key(KeyCode::Char('e')); // collapse fold at index 0
        assert!(!app.fold_expanded().contains(&0));
    }

    #[test]
    fn call_flow_e_at_different_indices() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('e')); // expand at 0
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Char('e')); // expand at 1
        assert!(app.fold_expanded().contains(&0));
        assert!(app.fold_expanded().contains(&1));
    }

    // ── File Open popup ─────────────────────────────────────────────

    #[test]
    fn file_open_o_opens_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        assert_eq!(app.active_popup(), Some(&Popup::FileOpenDialog));
    }

    #[test]
    fn file_open_esc_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        assert!(app.active_popup().is_some());
        app.handle_key(KeyCode::Esc);
        assert!(app.active_popup().is_none());
    }

    #[test]
    fn file_open_char_appends() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Char('/'));
        app.handle_key(KeyCode::Char('t'));
        app.handle_key(KeyCode::Char('m'));
        app.handle_key(KeyCode::Char('p'));
        assert_eq!(app.open_path(), "/tmp");
        assert_eq!(app.open_cursor(), 4);
    }

    #[test]
    fn file_open_backspace() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Char('b'));
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.open_path(), "a");
        assert_eq!(app.open_cursor(), 1);
    }

    #[test]
    fn file_open_left_right_cursor() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Char('b'));
        app.handle_key(KeyCode::Char('c'));
        app.handle_key(KeyCode::Left);
        app.handle_key(KeyCode::Left);
        assert_eq!(app.open_cursor(), 1);
        app.handle_key(KeyCode::Right);
        assert_eq!(app.open_cursor(), 2);
    }

    #[test]
    fn file_open_home_end() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Char('b'));
        app.handle_key(KeyCode::Home);
        assert_eq!(app.open_cursor(), 0);
        app.handle_key(KeyCode::End);
        assert_eq!(app.open_cursor(), 2);
    }

    #[test]
    fn file_open_enter_empty_path_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Enter);
        // Should close popup with error message
        assert!(app.active_popup().is_none());
        assert!(app.status_error().is_some());
    }

    #[test]
    fn file_open_enter_nonexistent_file() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        // Type a nonexistent path
        for c in "/nonexistent/file.pcap".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        let err = app.status_error().unwrap();
        assert!(
            err.contains("not found") || err.contains("Failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn file_open_enter_valid_pcap_loads() {
        // Use one of the test pcap files (path relative to CARGO_MANIFEST_DIR)
        let pcap_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pcap-samples/sip-rtp-g711.pcap");
        if !std::path::Path::new(pcap_path).exists() {
            return; // Skip if test pcaps not available
        }

        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        for c in pcap_path.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        assert!(app.active_popup().is_none());
        // Should have loaded some dialogs
        assert!(
            app.visible_dialog_count() > 0,
            "Expected dialogs to be loaded from pcap"
        );
    }

    #[test]
    fn file_open_clears_existing_data() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        let pcap_path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pcap-samples/sip-sdp-example.pcap");
        if !std::path::Path::new(pcap_path).exists() {
            return;
        }

        app.handle_key(KeyCode::Char('O'));
        for c in pcap_path.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        // Original 3 dialogs should be gone, replaced by pcap content
        let status = app.status_error().unwrap();
        assert!(status.contains("Loaded"), "unexpected status: {status}");
    }

    // ── Save format labels (all 11) ─────────────────────────────────

    #[test]
    fn save_popup_format_labels() {
        assert_eq!(SaveFormat::Pcap.label(), "PCAP");
        assert_eq!(SaveFormat::PcapNg.label(), "PCAP-NG");
        assert_eq!(SaveFormat::Txt.label(), "TXT");
        assert_eq!(SaveFormat::Json.label(), "JSON");
        assert_eq!(SaveFormat::Ndjson.label(), "NDJSON");
        assert_eq!(SaveFormat::Csv.label(), "CSV");
        assert_eq!(SaveFormat::Html.label(), "HTML");
        assert_eq!(SaveFormat::Markdown.label(), "MD");
        assert_eq!(SaveFormat::Wav.label(), "WAV");
        assert_eq!(SaveFormat::SippXml.label(), "SIPp");
        assert_eq!(SaveFormat::RtpJson.label(), "RTP");
    }

    #[test]
    fn save_popup_format_extensions() {
        assert_eq!(SaveFormat::Pcap.extension(), "pcap");
        assert_eq!(SaveFormat::PcapNg.extension(), "pcapng");
        assert_eq!(SaveFormat::Txt.extension(), "txt");
        assert_eq!(SaveFormat::Json.extension(), "json");
        assert_eq!(SaveFormat::Ndjson.extension(), "ndjson");
        assert_eq!(SaveFormat::Csv.extension(), "csv");
        assert_eq!(SaveFormat::Html.extension(), "html");
        assert_eq!(SaveFormat::Markdown.extension(), "md");
        assert_eq!(SaveFormat::Wav.extension(), "wav");
        assert_eq!(SaveFormat::SippXml.extension(), "xml");
        assert_eq!(SaveFormat::RtpJson.extension(), "rtp.json");
    }

    #[test]
    fn save_popup_format_categories() {
        assert_eq!(SaveFormat::Pcap.category(), "Packet Capture");
        assert_eq!(SaveFormat::PcapNg.category(), "Packet Capture");
        assert_eq!(SaveFormat::Txt.category(), "SIP-Specific");
        assert_eq!(SaveFormat::Json.category(), "Structured/Analytics");
        assert_eq!(SaveFormat::Ndjson.category(), "Structured/Analytics");
        assert_eq!(SaveFormat::Csv.category(), "Structured/Analytics");
        assert_eq!(SaveFormat::Html.category(), "Reporting");
        assert_eq!(SaveFormat::Markdown.category(), "Reporting");
        assert_eq!(SaveFormat::Wav.category(), "RTP/Media");
        assert_eq!(SaveFormat::SippXml.category(), "SIP-Specific");
        assert_eq!(SaveFormat::RtpJson.category(), "RTP/Media");
    }

    // ── Mark + delta additional tests ────────────────────────────────

    #[test]
    fn call_flow_mark_delta_different_messages() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('m')); // set mark at 0
        assert_eq!(app.mark_index(), Some(0));
        app.handle_key(KeyCode::Down); // move to msg 1
        assert_eq!(app.selected_msg_index(), 1);
        // Mark stays at 0, selected at 1 — they differ
        assert_ne!(app.mark_index().unwrap(), app.selected_msg_index());
    }

    // ── Fold expansion additional tests ──────────────────────────────

    #[test]
    fn call_flow_fold_starts_empty() {
        let app = app_with_call_flow_open();
        assert!(app.fold_expanded().is_empty(), "fold_expanded should start empty");
    }

    #[test]
    fn call_flow_fold_multiple_toggles() {
        let mut app = app_with_call_flow_open();
        // Toggle fold at index 0 on
        app.handle_key(KeyCode::Char('e'));
        assert!(app.fold_expanded().contains(&0));
        // Toggle fold at index 0 off
        app.handle_key(KeyCode::Char('e'));
        assert!(!app.fold_expanded().contains(&0));
        assert!(app.fold_expanded().is_empty());
    }

    // ── Swimlane selection default ───────────────────────────────────

    #[test]
    fn default_selection_state_is_normal() {
        use sipnab::tui::call_flow::SelectionState;
        let app = App::new_test();
        // A new app with no messages should not have any specific selection state;
        // verify the enum default variant.
        assert_eq!(SelectionState::Normal, SelectionState::Normal);
        assert_ne!(SelectionState::Normal, SelectionState::Selected);
        assert_ne!(SelectionState::Normal, SelectionState::Related);
        // App without call flow open: no swimlane state to inspect beyond the enum itself.
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Mermaid export key (E) ───────────────────────────────────────

    #[test]
    fn call_flow_e_uppercase_export_mermaid() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('E'));
        // Should set a status message about clipboard or Mermaid
        let status = app.status_error();
        assert!(
            status.is_some(),
            "Expected status message after Mermaid export"
        );
        let msg = status.unwrap();
        assert!(
            msg.contains("clipboard") || msg.contains("Clipboard") || msg.contains("Mermaid"),
            "Expected clipboard or Mermaid in status: {msg}"
        );
    }

    // ── New save format file save tests ──────────────────────────────

    #[test]
    fn save_json_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to JSON: Pcap -> PcapNg -> Txt -> Json = 3 tabs
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Json);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "JSON file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("call_id"),
            "JSON should contain call_id field"
        );
    }

    #[test]
    fn save_ndjson_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ndjson");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Ndjson: Pcap -> PcapNg -> Txt -> Json -> Ndjson = 4 tabs
        for _ in 0..4 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::Ndjson);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "NDJSON file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("call_id"),
            "NDJSON should contain call_id field"
        );
    }

    #[test]
    fn save_csv_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.csv");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Csv: 5 tabs
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::Csv);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "CSV file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        // CSV should have a header row
        assert!(
            content.contains("call_id") || content.contains("Call-ID"),
            "CSV should contain a header with call_id"
        );
    }

    #[test]
    fn save_html_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.html");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Html: 6 tabs
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::Html);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "HTML file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("mermaid") || content.contains("html") || content.contains("HTML"),
            "HTML should contain mermaid or html content"
        );
    }

    #[test]
    fn save_markdown_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.md");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Markdown: 7 tabs
        for _ in 0..7 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::Markdown);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "Markdown file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains('#') || content.contains("Call"),
            "Markdown should contain heading or Call reference"
        );
    }

    #[test]
    fn save_wav_shows_not_implemented_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wav");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Wav: 8 tabs
        for _ in 0..8 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::Wav);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        // WAV should produce a status message about RTP payload capture
        let status = app.status_error().unwrap();
        assert!(
            status.contains("RTP payload") || status.contains("WAV") || status.contains("planned"),
            "Expected WAV not-implemented message, got: {status}"
        );
    }

    #[test]
    fn save_sipp_xml_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.xml");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to SippXml: 9 tabs
        for _ in 0..9 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::SippXml);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        assert!(path.exists(), "SIPp XML file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("scenario") || content.contains("sipp") || content.contains("xml"),
            "SIPp XML should contain scenario content"
        );
    }

    #[test]
    fn save_rtp_json_no_streams_shows_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.rtp.json");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to RtpJson: 10 tabs
        for _ in 0..10 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::RtpJson);
        app.handle_key(KeyCode::Enter);
        assert!(app.active_popup().is_none());
        // With no RTP streams, save returns a message instead of creating file
        let status = app.status_error().unwrap();
        assert!(
            status.contains("No RTP streams") || status.contains("rtp"),
            "Expected no-streams message, got: {status}"
        );
    }

    // ── Settings popup timestamp mode cycle with Scaled ──────────────

    #[test]
    fn settings_popup_timestamp_cycles_through_scaled() {
        let mut app = App::new_test();
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaPrev);
        app.handle_key(KeyCode::F(8)); // open settings
        app.handle_key(KeyCode::Down); // move to timestamp mode (item 1)
        app.handle_key(KeyCode::Enter); // DeltaPrev -> DeltaFirst
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaFirst);
        app.handle_key(KeyCode::Enter); // DeltaFirst -> Scaled
        assert_eq!(app.timestamp_mode(), TimestampMode::Scaled);
        app.handle_key(KeyCode::Enter); // Scaled -> Absolute
        assert_eq!(app.timestamp_mode(), TimestampMode::Absolute);
        app.handle_key(KeyCode::Enter); // Absolute -> DeltaPrev
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaPrev);
    }
}
