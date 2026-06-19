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

    // ── SIP method checkbox set/unset scenarios ──────────────────────────
    // All three fixture dialogs are INVITEs. INVITE is checkbox index 2.
    const INVITE_IDX: usize = 2;

    #[test]
    fn filter_default_open_apply_shows_all_messages() {
        // SIP messages are checked by default → applying with nothing changed
        // shows every dialog (the reported bug was the opposite).
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7));
        app.handle_key(KeyCode::Enter); // apply with all methods still checked
        assert_eq!(app.active_popup(), None);
        assert_eq!(app.visible_dialog_count(), 3);
    }

    #[test]
    fn filter_uncheck_all_methods_shows_nothing() {
        let mut app = app_with_three_dialogs();
        app.apply_method_filter_for_test([false; 10]);
        assert_eq!(
            app.visible_dialog_count(),
            0,
            "no methods selected → show nothing"
        );
    }

    #[test]
    fn filter_only_invite_checked_shows_invite_dialogs() {
        let mut app = app_with_three_dialogs();
        let mut methods = [false; 10];
        methods[INVITE_IDX] = true; // only INVITE
        app.apply_method_filter_for_test(methods);
        assert_eq!(app.visible_dialog_count(), 3, "all fixtures are INVITE");
    }

    #[test]
    fn filter_uncheck_invite_hides_invite_dialogs() {
        let mut app = app_with_three_dialogs();
        let mut methods = [true; 10];
        methods[INVITE_IDX] = false; // everything except INVITE
        app.apply_method_filter_for_test(methods);
        assert_eq!(
            app.visible_dialog_count(),
            0,
            "INVITE excluded → none of the fixtures match"
        );
    }

    #[test]
    fn filter_recheck_all_after_unchecking_shows_all_again() {
        let mut app = app_with_three_dialogs();
        app.apply_method_filter_for_test([false; 10]);
        assert_eq!(app.visible_dialog_count(), 0);
        app.apply_method_filter_for_test([true; 10]);
        assert_eq!(
            app.visible_dialog_count(),
            3,
            "re-checking all methods shows everything"
        );
    }

    #[test]
    fn filter_space_toggles_method_via_keys() {
        // Drive the real key path: F7, move focus to the INVITE checkbox, Space
        // to uncheck it, Enter to apply. With INVITE unchecked the INVITE
        // fixtures must disappear.
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7));
        // Focus starts on text field 0. Tab advances one element at a time:
        // 5 text fields then the checkboxes, so 7 Tabs lands on checkbox index 2
        // (INVITE).
        for _ in 0..7 {
            app.handle_key(KeyCode::Tab);
        }
        app.handle_key(KeyCode::Char(' ')); // uncheck INVITE
        app.handle_key(KeyCode::Enter);
        assert_eq!(
            app.visible_dialog_count(),
            0,
            "unchecking INVITE hid the INVITE dialogs"
        );
    }

    #[test]
    fn filter_right_column_reachable_by_tab_and_toggle() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // 5 text fields (focus 0..4) then checkbox 0 (focus 5), checkbox 1 (focus 6).
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        let (focus, _) = app.filter_focus_and_methods_for_test();
        assert_eq!(
            focus, 6,
            "6 Tabs should land on right-column checkbox 1 (OPTIONS)"
        );
        app.handle_key(KeyCode::Char(' '));
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert!(
            !methods[1],
            "Space should toggle OPTIONS (index 1) off; methods={methods:?}"
        );
    }

    #[test]
    fn filter_right_column_focus_renders_bold() {
        use ratatui::style::Modifier;
        let backend = ratatui::backend::TestBackend::new(80, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab); // focus checkbox 1 (OPTIONS, right column)
        }
        terminal.draw(|f| app.render(f)).unwrap();
        // Collect the text of all BOLD cells (the focus highlight is bold+selected).
        let buf = terminal.backend().buffer();
        let mut bold = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let cell = &buf[(x, y)];
                if cell.modifier.contains(Modifier::BOLD) {
                    bold.push_str(cell.symbol());
                }
            }
        }
        assert!(
            bold.contains("OPTIONS"),
            "focused right-column checkbox OPTIONS should render bold; bold cells were: {bold:?}"
        );
    }

    #[test]
    fn filter_down_arrow_reaches_second_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Into the checkbox grid: 5 Tabs -> checkbox 0 (REGISTER, focus 5).
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        // Down 4 times walks the left column to INFO (idx 8, focus 13).
        for _ in 0..4 {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            5 + 8,
            "Down reaches INFO (left col bottom)"
        );
        // One more Down must enter the SECOND column (OPTIONS, idx 1) rather than
        // skipping straight to the buttons — otherwise the right column is
        // unreachable by vertical navigation.
        app.handle_key(KeyCode::Down);
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            5 + 1,
            "Down from the bottom of column 1 must reach column 2 (OPTIONS)"
        );
    }

    #[test]
    fn filter_right_arrow_reaches_second_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Tab into the checkbox grid: 5 tabs -> checkbox 0 (REGISTER, focus 5).
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_focus_and_methods_for_test().0, 5);
        // Right arrow should move into the second column (checkbox 1, focus 6).
        app.handle_key(KeyCode::Right);
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            6,
            "Right arrow should move from REGISTER into OPTIONS (second column)"
        );
        app.handle_key(KeyCode::Char(' '));
        assert!(!app.filter_focus_and_methods_for_test().1[1]);
    }

    #[test]
    fn filter_f9_clears_method_filter_to_show_all() {
        let mut app = app_with_three_dialogs();
        app.apply_method_filter_for_test([false; 10]);
        assert_eq!(app.visible_dialog_count(), 0);
        app.handle_key(KeyCode::F(9)); // clear filter
        assert_eq!(app.visible_dialog_count(), 3, "F9 clear restores show-all");
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

        // Down from the bottom of the LEFT column continues into the RIGHT
        // column (OPTIONS, idx 1, ff=6) so it's reachable by vertical nav.
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 6); // OPTIONS (idx 1)
        // ...down the right column: PUBLISH(3,8) MESSAGE(5,10) REFER(7,12) UPDATE(9,14)
        for expected in [8, 10, 12, 14] {
            app.handle_key(KeyCode::Down);
            assert_eq!(app.filter_dialog.focused_field(), expected);
        }
        // Down from the bottom of the RIGHT column -> buttons (ff=15).
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
        app.handle_key(KeyCode::Down); // move to second
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
        for c in "test".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        assert_eq!(app.search_query(), "test");
        app.handle_key(KeyCode::Esc);
        assert!(!app.search_active());
        assert_eq!(app.search_query(), "");
    }

    #[test]
    fn search_enter_commits_query() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "hello".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert!(!app.search_active());
        assert_eq!(app.search_query(), "hello"); // retained for highlighting
    }

    #[test]
    fn search_backspace_removes_last_char() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        for c in "abc".chars() {
            app.handle_key(KeyCode::Char(c));
        }
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
        for _ in 0..20 {
            app.handle_key(KeyCode::Char('+'));
        }
        assert!(app.raw_preview_pct() <= 80);
    }

    #[test]
    fn call_flow_minus_clamps_at_min() {
        let mut app = app_with_call_flow_open();
        for _ in 0..20 {
            app.handle_key(KeyCode::Char('-'));
        }
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
        app.handle_key(KeyCode::Down); // move to msg 1
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
        for c in "1001".chars() {
            app.handle_key(KeyCode::Char(c));
        }
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
        assert!(
            app.save_path().ends_with(".pcapng"),
            "got: {}",
            app.save_path()
        );
        app.handle_key(KeyCode::Tab);
        assert!(
            app.save_path().ends_with(".txt"),
            "got: {}",
            app.save_path()
        );
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
    fn call_flow_right_decreases_pct() {
        // Right = push split right = ladder wider = detail pct decreases
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Right);
        assert_eq!(app.raw_preview_pct(), before - 5);
    }

    #[test]
    fn call_flow_left_increases_pct() {
        // Left = push split left = detail wider = detail pct increases
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Left);
        assert_eq!(app.raw_preview_pct(), before + 5);
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

    /// Helper: open the file dialog and switch to manual-path mode with an
    /// empty path. The browser is the default mode (see `open_file_dialog`),
    /// so tests that exercise path-editing use Tab to enter the text-input
    /// variant and then clear the seeded directory path.
    fn open_manual_file_dialog(app: &mut App) {
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Tab);
        app.open_path_clear_for_test();
    }

    #[test]
    fn file_open_char_appends() {
        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
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
        open_manual_file_dialog(&mut app);
        app.handle_key(KeyCode::Char('a'));
        app.handle_key(KeyCode::Char('b'));
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.open_path(), "a");
        assert_eq!(app.open_cursor(), 1);
    }

    #[test]
    fn file_open_left_right_cursor() {
        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
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
        open_manual_file_dialog(&mut app);
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
        open_manual_file_dialog(&mut app);
        app.handle_key(KeyCode::Enter);
        // Should close popup with error message
        assert!(app.active_popup().is_none());
        assert!(app.status_error().is_some());
    }

    #[test]
    fn file_open_enter_nonexistent_file() {
        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
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
        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/sip-rtp-g711.pcap"
        );
        if !std::path::Path::new(pcap_path).exists() {
            return; // Skip if test pcaps not available
        }

        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
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
    fn file_open_rtp_only_pcap_populates_streams_and_switches_view() {
        // RTP-only pcap (no SIP) — exercises the RTP ingestion path in
        // `load_pcap_file` and the auto-switch to the stream list.
        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/speech_8k_ulaw.pcap"
        );
        if !std::path::Path::new(pcap_path).exists() {
            return;
        }

        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
        for c in pcap_path.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        assert!(app.active_popup().is_none());
        assert_eq!(app.visible_dialog_count(), 0, "no SIP in this pcap");
        assert!(
            app.stream_count_for_test() > 0,
            "expected RTP streams to be parsed"
        );
        assert!(
            matches!(app.current_view(), View::StreamList),
            "should auto-switch to stream list when SIP=0 and RTP>0, got {:?}",
            app.current_view()
        );
    }

    #[test]
    fn file_open_clears_existing_data() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/sip-sdp-example.pcap"
        );
        if !std::path::Path::new(pcap_path).exists() {
            return;
        }

        open_manual_file_dialog(&mut app);
        for c in pcap_path.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        // Original 3 dialogs should be gone, replaced by pcap content
        let status = app.status_error().unwrap();
        assert!(status.contains("Loaded"), "unexpected status: {status}");
    }

    /// Browser mode should list symlinked directories as directories, not
    /// filter them out as non-pcap files. `DirEntry::file_type()` reports
    /// symlinks with `is_dir() == false` on Linux, so the picker must
    /// follow symlinks before classifying the entry.
    #[test]
    fn file_open_browser_shows_symlinked_directories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("realdir");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("linkdir")).unwrap();

        let mut app = App::new_test();
        app.set_open_dir_for_test(tmp.path().to_path_buf());
        app.handle_key(KeyCode::Char('O'));

        let names = app.open_entry_names_for_test();
        assert!(
            names.iter().any(|n| n == "realdir"),
            "expected realdir in listing: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "linkdir"),
            "symlinked directory should be listed: {names:?}"
        );
    }

    /// Browser mode end-to-end: from the crate root, filter+Enter into
    /// `tests/`, then into `tests/pcap-samples/`, and verify the sample
    /// pcap files appear in the listing.
    #[test]
    fn file_open_browser_navigates_to_pcap_samples() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let samples = manifest_dir.join("tests/pcap-samples");
        if !samples.is_dir() {
            return;
        }

        let mut app = App::new_test();
        app.set_open_dir_for_test(manifest_dir.clone());
        app.handle_key(KeyCode::Char('O'));
        assert_eq!(app.active_popup(), Some(&Popup::FileOpenDialog));

        let names = app.open_entry_names_for_test();
        assert!(
            names.iter().any(|n| n == "tests"),
            "expected 'tests' directory in listing: {names:?}"
        );

        for c in "tests".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        // First entry is always ".." — skip it before entering.
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.open_dir_for_test(), manifest_dir.join("tests"));

        for c in "pcap-samples".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.open_dir_for_test(), samples);

        let names = app.open_entry_names_for_test();
        assert!(
            names.iter().any(|n| n == "sip-rtp-g711.pcap"),
            "expected sip-rtp-g711.pcap in listing: {names:?}"
        );
        assert_eq!(app.active_popup(), Some(&Popup::FileOpenDialog));
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
        assert!(
            app.fold_expanded().is_empty(),
            "fold_expanded should start empty"
        );
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
    fn save_wav_without_rtp_streams_shows_error() {
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
        // WAV export with no RTP streams should produce an informative error
        let status = app.status_error().unwrap();
        assert!(
            status.contains("No RTP streams"),
            "Expected no-RTP-streams message, got: {status}"
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

    // ── Save format correctness tests ──────────────────────────────────

    #[test]
    fn save_txt_format_correct() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to Txt: Pcap -> PcapNg -> Txt = 2 tabs
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Tab);
        assert_eq!(app.save_format(), SaveFormat::Txt);
        app.handle_key(KeyCode::Enter);
        assert!(path.exists(), "Txt file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# Message"),
            "Txt should have message headers"
        );
        assert!(content.contains("---"), "Txt should have separators");
        assert!(content.contains("SIP/2.0"), "Txt should contain raw SIP");
    }

    #[test]
    fn save_csv_has_correct_header() {
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
        assert!(path.exists(), "CSV file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert!(
            first_line.contains("call_id"),
            "CSV header should contain call_id"
        );
        assert!(
            first_line.contains("method"),
            "CSV header should contain method"
        );
        // Verify there are data rows (at least header + 1 row = 2 lines)
        assert!(
            content.lines().count() >= 2,
            "CSV should have header + data rows"
        );
    }

    #[test]
    fn save_markdown_has_headings() {
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
        assert!(path.exists(), "Markdown file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# Call Summary") || content.contains("## Dialog"),
            "MD should have headings"
        );
        assert!(content.contains("|"), "MD should have table pipes");
    }

    #[test]
    fn save_sipp_xml_has_scenario_tags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.xml");
        let mut app = app_with_three_dialogs();
        // Open call flow first since SIPp exports current dialog
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().unwrap());
        // Cycle to SippXml: 9 tabs
        for _ in 0..9 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.save_format(), SaveFormat::SippXml);
        app.handle_key(KeyCode::Enter);
        assert!(path.exists(), "SIPp XML file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("<scenario"),
            "SIPp should have <scenario> tag"
        );
        assert!(
            content.contains("</scenario>"),
            "SIPp should close </scenario>"
        );
        assert!(
            content.contains("<send>") || content.contains("<recv"),
            "SIPp should have send/recv"
        );
    }

    // ── 3-participant prepare_messages test ──────────────────────────

    #[test]
    fn prepare_messages_three_participants() {
        use sipnab::tui::call_flow::prepare::prepare_messages;
        use sipnab::tui::{ColorMode, SdpDisplayMode, Theme, TimestampMode};
        use std::collections::HashSet;

        let t0 = base_ts();
        let la = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let lb = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let lc = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Build messages with 3 distinct endpoints: A -> B, B -> C, C -> B, B -> A
        let msg1 = {
            let raw = build_sip(
                "INVITE sip:proxy@10.0.0.2 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.3>",
                    "Call-ID: three-party@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
            );
            parse_sip(&raw, t0, la, lb, 5060, 5060, TransportProto::Udp).unwrap()
        };
        let msg2 = {
            let raw = build_sip(
                "INVITE sip:bob@10.0.0.3 SIP/2.0",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.3>",
                    "Call-ID: three-party@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
            );
            parse_sip(
                &raw,
                t0 + TimeDelta::milliseconds(100),
                lb,
                lc,
                5060,
                5060,
                TransportProto::Udp,
            )
            .unwrap()
        };
        let msg3 = {
            let raw = build_sip(
                "SIP/2.0 200 OK",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.3>;tag=t2",
                    "Call-ID: three-party@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
            );
            parse_sip(
                &raw,
                t0 + TimeDelta::milliseconds(200),
                lc,
                lb,
                5060,
                5060,
                TransportProto::Udp,
            )
            .unwrap()
        };
        let msg4 = {
            let raw = build_sip(
                "SIP/2.0 200 OK",
                &[
                    "From: <sip:alice@10.0.0.1>;tag=t1",
                    "To: <sip:bob@10.0.0.3>;tag=t2",
                    "Call-ID: three-party@test",
                    "CSeq: 1 INVITE",
                    "Content-Length: 0",
                ],
            );
            parse_sip(
                &raw,
                t0 + TimeDelta::milliseconds(300),
                lb,
                la,
                5060,
                5060,
                TransportProto::Udp,
            )
            .unwrap()
        };

        let messages = vec![msg1, msg2, msg3, msg4];
        let theme = Theme::default();
        let fold_expanded = HashSet::new();

        let flow_opts = sipnab::tui::call_flow::FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::DeltaPrev,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg: None,
            theme: &theme,
            resolver: Box::leak(Box::new(sipnab::names::NameResolver::new())),
            name_mode: sipnab::names::NameMode::Off,
        };
        let (participants, formatted) =
            prepare_messages(&messages, t0, None, &flow_opts, &fold_expanded);

        assert_eq!(
            participants.len(),
            3,
            "should have 3 participants, got {}",
            participants.len()
        );
        assert!(
            formatted.len() >= 4,
            "should have at least 4 messages, got {}",
            formatted.len()
        );
        // Verify src_col and dst_col use different columns for different endpoints
        let cols_used: HashSet<usize> = formatted
            .iter()
            .flat_map(|m| [m.src_col, m.dst_col])
            .collect();
        assert_eq!(
            cols_used.len(),
            3,
            "all 3 participant columns should be used"
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

    // ═══════════════════════════════════════════════════════════════════
    // RTP drill-down from call flow + stream detail navigation tests
    // ═══════════════════════════════════════════════════════════════════

    // ── Helper: SIP message with SDP body ────────────────────────────

    fn build_sip_with_body(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(first_line.as_bytes());
        msg.extend_from_slice(b"\r\n");
        for h in headers {
            msg.extend_from_slice(h.as_bytes());
            msg.extend_from_slice(b"\r\n");
        }
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(body);
        msg
    }

    fn make_invite_sdp(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let sdp = "v=0\r\n\
                   o=- 123 456 IN IP4 10.0.0.1\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.1\r\n\
                   t=0 0\r\n\
                   m=audio 20000 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";
        let raw = build_sip_with_body(
            "INVITE sip:1002@10.0.0.2 SIP/2.0",
            &[
                "From: <sip:1001@10.0.0.1>;tag=t1",
                "To: <sip:1002@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp.len()),
            ],
            sdp.as_bytes(),
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
        .unwrap()
    }

    fn make_100_trying(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 100 Trying",
            &[
                "From: <sip:1001@10.0.0.1>;tag=t1",
                "To: <sip:1002@10.0.0.2>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
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
        .unwrap()
    }

    fn make_180_ringing(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "SIP/2.0 180 Ringing",
            &[
                "From: <sip:1001@10.0.0.1>;tag=t1",
                "To: <sip:1002@10.0.0.2>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
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
        .unwrap()
    }

    fn make_200_ok_with_sdp(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let sdp = "v=0\r\n\
                   o=- 789 101 IN IP4 10.0.0.2\r\n\
                   s=-\r\n\
                   c=IN IP4 10.0.0.2\r\n\
                   t=0 0\r\n\
                   m=audio 30000 RTP/AVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";
        let raw = build_sip_with_body(
            "SIP/2.0 200 OK",
            &[
                "From: <sip:1001@10.0.0.1>;tag=t1",
                "To: <sip:1002@10.0.0.2>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
                &format!("Content-Length: {}", sdp.len()),
            ],
            sdp.as_bytes(),
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
        .unwrap()
    }

    fn make_ack(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "ACK sip:1002@10.0.0.2 SIP/2.0",
            &[
                "From: <sip:1001@10.0.0.1>;tag=t1",
                "To: <sip:1002@10.0.0.2>;tag=t2",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 ACK",
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
        .unwrap()
    }

    /// Build a full INVITE dialog: INVITE(SDP) -> 100 -> 180 -> 200 OK(SDP) -> ACK
    fn make_full_dialog_messages(call_id: &str) -> Vec<SipMessage> {
        let t0 = base_ts();
        vec![
            make_invite_sdp(call_id, t0),
            make_100_trying(call_id, t0 + TimeDelta::milliseconds(50)),
            make_180_ringing(call_id, t0 + TimeDelta::milliseconds(500)),
            make_200_ok_with_sdp(call_id, t0 + TimeDelta::seconds(2)),
            make_ack(
                call_id,
                t0 + TimeDelta::seconds(2) + TimeDelta::milliseconds(10),
            ),
        ]
    }

    // ── Test 1: stream_detail_enter_from_stream_list ─────────────────

    #[test]
    fn stream_detail_enter_from_stream_list() {
        use sipnab::capture::parse::ParsedPacket;
        use sipnab::rtp::parser::parse_rtp_header;
        use sipnab::rtp::stream_store::StreamStore;
        use std::net::Ipv4Addr;

        // Create an App with a stream in its store
        let ds = std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::sip::dialog_store::DialogStore::new(100, false),
        ));
        let ss = std::sync::Arc::new(parking_lot::RwLock::new(StreamStore::new(100)));

        // Feed some RTP packets so the stream store has a stream
        {
            let mut store = ss.write();
            let ssrc = 0xDEADBEEF_u32;
            for i in 0u16..5 {
                let mut payload = Vec::with_capacity(172);
                payload.push(0x80);
                payload.push(0x00); // PT=0 (PCMU)
                payload.extend_from_slice(&(100 + i).to_be_bytes());
                payload.extend_from_slice(&((i as u32) * 160).to_be_bytes());
                payload.extend_from_slice(&ssrc.to_be_bytes());
                payload.extend_from_slice(&[0x7F; 160]);

                let parsed = ParsedPacket {
                    timestamp: chrono::DateTime::from_timestamp(1_700_000_000 + i as i64, 0)
                        .unwrap(),
                    src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20000,
                    dst_port: 30000,
                    transport: TransportProto::Udp,
                    payload: payload.into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                };
                let rtp = parse_rtp_header(&parsed.payload).unwrap();
                store.process_rtp(&parsed, &rtp, parsed.timestamp);
            }
        }

        let mut app = sipnab::tui::App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        );

        // Navigate to StreamList
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);

        // Enter should open StreamDetail
        app.handle_key(KeyCode::Enter);
        assert!(
            matches!(app.current_view(), View::StreamDetail(_)),
            "expected StreamDetail, got {:?}",
            app.current_view()
        );
    }

    // ── Test 2: stream_detail_escape_returns_to_stream_list ──────────

    #[test]
    fn stream_detail_escape_returns_to_stream_list() {
        use sipnab::capture::parse::ParsedPacket;
        use sipnab::rtp::parser::parse_rtp_header;
        use sipnab::rtp::stream_store::StreamStore;
        use std::net::Ipv4Addr;

        let ds = std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::sip::dialog_store::DialogStore::new(100, false),
        ));
        let ss = std::sync::Arc::new(parking_lot::RwLock::new(StreamStore::new(100)));

        // Feed RTP packets
        {
            let mut store = ss.write();
            let ssrc = 0xCAFEBABE_u32;
            for i in 0u16..5 {
                let mut payload = Vec::with_capacity(172);
                payload.push(0x80);
                payload.push(0x00);
                payload.extend_from_slice(&(100 + i).to_be_bytes());
                payload.extend_from_slice(&((i as u32) * 160).to_be_bytes());
                payload.extend_from_slice(&ssrc.to_be_bytes());
                payload.extend_from_slice(&[0x7F; 160]);

                let parsed = ParsedPacket {
                    timestamp: chrono::DateTime::from_timestamp(1_700_000_000 + i as i64, 0)
                        .unwrap(),
                    src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20000,
                    dst_port: 30000,
                    transport: TransportProto::Udp,
                    payload: payload.into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                };
                let rtp = parse_rtp_header(&parsed.payload).unwrap();
                store.process_rtp(&parsed, &rtp, parsed.timestamp);
            }
        }

        let mut app = sipnab::tui::App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        );

        // Navigate to StreamList, then Enter to open StreamDetail
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::StreamDetail(_)));

        // Escape should return to StreamList
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::StreamList);
    }

    // ── Test 3: stream_detail_scroll_j_k ─────────────────────────────

    #[test]
    fn stream_detail_scroll_j_k() {
        use sipnab::capture::parse::ParsedPacket;
        use sipnab::rtp::parser::parse_rtp_header;
        use sipnab::rtp::stream_store::StreamStore;
        use std::net::Ipv4Addr;

        let ds = std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::sip::dialog_store::DialogStore::new(100, false),
        ));
        let ss = std::sync::Arc::new(parking_lot::RwLock::new(StreamStore::new(100)));

        {
            let mut store = ss.write();
            let ssrc = 0x11223344_u32;
            for i in 0u16..5 {
                let mut payload = Vec::with_capacity(172);
                payload.push(0x80);
                payload.push(0x00);
                payload.extend_from_slice(&(100 + i).to_be_bytes());
                payload.extend_from_slice(&((i as u32) * 160).to_be_bytes());
                payload.extend_from_slice(&ssrc.to_be_bytes());
                payload.extend_from_slice(&[0x7F; 160]);

                let parsed = ParsedPacket {
                    timestamp: chrono::DateTime::from_timestamp(1_700_000_000 + i as i64, 0)
                        .unwrap(),
                    src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    src_port: 20000,
                    dst_port: 30000,
                    transport: TransportProto::Udp,
                    payload: payload.into(),
                    ip_id: None,
                    tcp_seq: None,
                    tcp_flags: None,
                    fragment_offset: None,
                    more_fragments: false,
                    ip_protocol: 17,
                };
                let rtp = parse_rtp_header(&parsed.payload).unwrap();
                store.process_rtp(&parsed, &rtp, parsed.timestamp);
            }
        }

        let mut app = sipnab::tui::App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        );

        // Navigate to StreamDetail
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::StreamDetail(_)));
        assert_eq!(app.stream_detail_scroll(), 0);

        // j scrolls down
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.stream_detail_scroll(), 1);
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.stream_detail_scroll(), 2);

        // k scrolls up
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.stream_detail_scroll(), 1);

        // k at 0 stays at 0
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.stream_detail_scroll(), 0);
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.stream_detail_scroll(), 0);
    }

    // ── Test 4: rtp_bar_is_after_ack_not_200ok ───────────────────────

    #[test]
    fn rtp_bar_is_after_ack_not_200ok() {
        use sipnab::tui::call_flow::prepare::prepare_messages;
        use sipnab::tui::{ColorMode, SdpDisplayMode, Theme, TimestampMode};
        use std::collections::HashSet;

        let messages = make_full_dialog_messages("rtp-bar-test@call");
        let t0 = messages[0].timestamp;
        let theme = Theme::default();
        let fold_expanded = HashSet::new();

        let flow_opts = sipnab::tui::call_flow::FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::Summary,
            ts_mode: TimestampMode::DeltaPrev,
            color_mode: ColorMode::Method,
            show_rtp: true,
            selected_msg: None,
            theme: &theme,
            resolver: Box::leak(Box::new(sipnab::names::NameResolver::new())),
            name_mode: sipnab::names::NameMode::Off,
        };
        let (_participants, formatted) =
            prepare_messages(&messages, t0, None, &flow_opts, &fold_expanded);

        // Find the RTP bar message
        let rtp_bar_idx = formatted
            .iter()
            .position(|m| m.is_rtp_bar)
            .expect("should have an RTP bar in the formatted output");

        // Find the ACK message (the one with label "ACK")
        let ack_idx = formatted
            .iter()
            .position(|m| m.label == "ACK")
            .expect("should have an ACK message");

        // Find the 200 OK message
        let ok_200_idx = formatted
            .iter()
            .position(|m| m.label.starts_with("200"))
            .expect("should have a 200 OK message");

        // The RTP bar should be a separate entry AFTER the ACK, not on the 200 OK
        assert!(
            rtp_bar_idx > ack_idx,
            "RTP bar (idx {rtp_bar_idx}) should come after ACK (idx {ack_idx})"
        );
        assert!(
            rtp_bar_idx > ok_200_idx,
            "RTP bar (idx {rtp_bar_idx}) should come after 200 OK (idx {ok_200_idx})"
        );

        // Sanity: ACK comes after 200 OK
        assert!(
            ack_idx > ok_200_idx,
            "ACK (idx {ack_idx}) should come after 200 OK (idx {ok_200_idx})"
        );
    }

    // ── Test 5: rtp_bar_has_timestamp_and_codec ──────────────────────

    #[test]
    fn rtp_bar_has_timestamp_and_codec() {
        use sipnab::tui::call_flow::prepare::prepare_messages;
        use sipnab::tui::{ColorMode, SdpDisplayMode, Theme, TimestampMode};
        use std::collections::HashSet;

        let messages = make_full_dialog_messages("rtp-codec-test@call");
        let t0 = messages[0].timestamp;
        let theme = Theme::default();
        let fold_expanded = HashSet::new();

        let flow_opts = sipnab::tui::call_flow::FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::Summary,
            ts_mode: TimestampMode::DeltaPrev,
            color_mode: ColorMode::Method,
            show_rtp: true,
            selected_msg: None,
            theme: &theme,
            resolver: Box::leak(Box::new(sipnab::names::NameResolver::new())),
            name_mode: sipnab::names::NameMode::Off,
        };
        let (_participants, formatted) =
            prepare_messages(&messages, t0, None, &flow_opts, &fold_expanded);

        // Find the RTP bar message
        let rtp_bar = formatted
            .iter()
            .find(|m| m.is_rtp_bar)
            .expect("should have an RTP bar");

        // The RTP bar label should contain RTP info
        let bar_text = &rtp_bar.label;

        assert!(
            bar_text.contains("RTP"),
            "RTP bar label should contain 'RTP', got: {bar_text}"
        );

        // Should contain the codec info from the 200 OK SDP (PCMU)
        assert!(
            bar_text.contains("PCMU"),
            "RTP bar label should contain 'PCMU' codec from 200 OK SDP, got: {bar_text}"
        );

        // Should contain "active" status
        assert!(
            bar_text.contains("active"),
            "RTP bar label should contain 'active' status, got: {bar_text}"
        );

        // The timestamp field should be populated (not empty)
        assert!(
            !rtp_bar.timestamp.trim().is_empty(),
            "RTP bar should have a timestamp"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Body search tests — search matches against raw SIP message content
    // ═══════════════════════════════════════════════════════════════════

    /// Build an INVITE with a User-Agent header that only appears in the
    /// raw bytes, not in any structured dialog field.
    fn make_invite_with_user_agent(
        call_id: &str,
        from: &str,
        to: &str,
        user_agent: &str,
        ts: DateTime<Utc>,
    ) -> SipMessage {
        let raw = build_sip(
            &format!("INVITE sip:{to}@example.com SIP/2.0"),
            &[
                &format!("From: \"{from}\" <sip:{from}@example.com>;tag=t1"),
                &format!("To: \"{to}\" <sip:{to}@example.com>"),
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("User-Agent: {user_agent}"),
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
        .expect("parse INVITE with User-Agent")
    }

    fn app_with_user_agent_dialog() -> App {
        let t0 = base_ts();
        let messages = vec![
            make_invite_with_user_agent(
                "call-ua@test",
                "alice",
                "bob",
                "FreeSWITCH-mod-sofia/1.10",
                t0,
            ),
            make_response(
                "call-ua@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(1),
            ),
        ];
        App::with_processed_messages(messages)
    }

    #[test]
    fn body_search_finds_sip_header_in_body() {
        // "FreeSWITCH" appears only in the User-Agent header of the raw
        // message bytes — it is not a structured field (method, from, to,
        // state, call_id, src/dst).  Body search should still match.
        let app = app_with_user_agent_dialog();
        let store = app.dialog_store_ref().read();
        let q = "freeswitch".to_ascii_lowercase();
        let matches: Vec<_> = store
            .iter()
            .filter(|d| {
                d.call_id.to_ascii_lowercase().contains(&q)
                    || d.method.as_str().to_ascii_lowercase().contains(&q)
                    || d.from_user
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.to_user
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.src_addr.to_string().contains(&q)
                    || d.dst_addr.to_string().contains(&q)
                    || sipnab::tui::call_list::state_display_str(d.state())
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.messages.iter().any(|msg| {
                        String::from_utf8_lossy(&msg.raw)
                            .to_ascii_lowercase()
                            .contains(&q)
                    })
            })
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "Body search for 'freeswitch' should match exactly one dialog"
        );
    }

    #[test]
    fn body_search_no_match_excludes_dialog() {
        let app = app_with_user_agent_dialog();
        let store = app.dialog_store_ref().read();
        let q = "nonexistent-xyz-string".to_ascii_lowercase();
        let matches: Vec<_> = store
            .iter()
            .filter(|d| {
                d.call_id.to_ascii_lowercase().contains(&q)
                    || d.method.as_str().to_ascii_lowercase().contains(&q)
                    || d.from_user
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.to_user
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.src_addr.to_string().contains(&q)
                    || d.dst_addr.to_string().contains(&q)
                    || sipnab::tui::call_list::state_display_str(d.state())
                        .to_ascii_lowercase()
                        .contains(&q)
                    || d.messages.iter().any(|msg| {
                        String::from_utf8_lossy(&msg.raw)
                            .to_ascii_lowercase()
                            .contains(&q)
                    })
            })
            .collect();
        assert_eq!(
            matches.len(),
            0,
            "Body search for 'nonexistent-xyz-string' should match no dialogs"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Column preference tests — apply_visible_columns
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn column_config_apply_visible_columns() {
        use sipnab::tui::call_list::CallListState;

        let mut state = CallListState::new();
        // All visible by default
        assert!(state.visible_columns.iter().all(|&v| v));

        state.apply_visible_columns(&["#".to_string(), "Method".to_string(), "State".to_string()]);

        // Index (#) = 0, Method = 1, State = 6
        assert!(state.visible_columns[0], "# should be visible");
        assert!(state.visible_columns[1], "Method should be visible");
        assert!(state.visible_columns[6], "State should be visible");

        // Everything else should be hidden
        assert!(!state.visible_columns[2], "From should be hidden");
        assert!(!state.visible_columns[3], "To should be hidden");
        assert!(!state.visible_columns[4], "Source should be hidden");
        assert!(!state.visible_columns[5], "Destination should be hidden");
        assert!(!state.visible_columns[7], "Msgs should be hidden");
        assert!(!state.visible_columns[8], "Date should be hidden");
        assert!(!state.visible_columns[9], "PDD should be hidden");
    }

    #[test]
    fn column_config_case_insensitive() {
        use sipnab::tui::call_list::CallListState;

        let mut state = CallListState::new();
        state.apply_visible_columns(&[
            "method".to_string(), // lowercase
            "FROM".to_string(),   // uppercase
            "pdd".to_string(),    // lowercase
        ]);

        // Method = 1, From = 2, PDD = 9
        assert!(
            state.visible_columns[1],
            "method (lowercase) should match Method"
        );
        assert!(
            state.visible_columns[2],
            "FROM (uppercase) should match From"
        );
        assert!(state.visible_columns[9], "pdd (lowercase) should match PDD");

        // Others hidden
        assert!(!state.visible_columns[0], "# should be hidden");
        assert!(!state.visible_columns[3], "To should be hidden");
        assert!(!state.visible_columns[6], "State should be hidden");
    }

    #[test]
    fn column_config_empty_list_preserves_defaults() {
        use sipnab::tui::call_list::CallListState;

        let mut state = CallListState::new();
        // All visible by default
        assert!(state.visible_columns.iter().all(|&v| v));

        // Apply empty list — should leave all columns visible
        state.apply_visible_columns(&[]);

        assert!(
            state.visible_columns.iter().all(|&v| v),
            "All columns should remain visible when applying an empty list"
        );
    }
}
