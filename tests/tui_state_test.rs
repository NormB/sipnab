// SPDX-License-Identifier: MIT OR Apache-2.0

//! TUI state machine tests.
//!
//! Tests App state transitions (view switching, key handling, filtering)
//! without rendering. These exercise the core TUI logic independent of
//! the visual output.
//!
//! Approach: each test builds an `App` directly (no real terminal, no capture
//! thread), feeds it synthetic SIP messages produced by the fixture builders
//! below, and drives it through `handle_key`/`handle_mouse_kind`, asserting
//! on the view/state accessors. A minority of tests do render — into an
//! in-memory ratatui `TestBackend` — where the behavior under test depends on
//! layout (scroll clamping, checkbox focus styling, autoscroll, fold-row
//! mapping); they assert on state or buffer cells, never on snapshots
//! (`tui_snapshot_test.rs` owns those). Everything is gated on the `tui`
//! feature.

// Low-level SIP fixture builders shared with `tui_snapshot_test.rs` so the
// two suites can't drift. Declared at file scope (not nested) so the
// `#[path]` resolves against `tests/`.
#[cfg(feature = "tui")]
#[path = "support/tui_fixtures.rs"]
mod fixtures;

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
    //
    // The low-level fixture builders (endpoint addresses, base timestamp,
    // raw-wire assembly, minimal INVITE/response) are shared with
    // `tui_snapshot_test.rs` via the file-scoped `fixtures` module above so
    // the two suites can't drift. File-specific higher-level builders stay
    // below.
    use super::fixtures::{base_ts, build_sip, endpoint_a, endpoint_b, make_invite, make_response};

    /// Build an `App` preloaded with three INVITE dialogs: `call-1@test`
    /// completed (200 OK), `call-2@test` failed (503), `call-3@test` active
    /// in-call (200 OK, no BYE).
    ///
    /// # Returns
    /// The `App` with all six messages already processed into its dialog store.
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

    /// A fresh app starts in the `CallList` view.
    #[test]
    fn initial_view_is_call_list() {
        let app = App::new_test();
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Tab from the call list switches to the `StreamList` view.
    #[test]
    fn tab_switches_to_stream_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
    }

    /// A second Tab from the stream list returns to the call list.
    #[test]
    fn tab_toggles_back_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Pressing `q` sets the quit flag.
    #[test]
    fn q_sets_should_quit() {
        let mut app = App::new_test();
        assert!(!app.should_quit());
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    /// F1 opens the Help view.
    #[test]
    fn f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    /// Esc closes Help and returns to the call list.
    #[test]
    fn esc_from_help_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1)); // open help
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key(KeyCode::Esc); // close help
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Enter on a populated call list opens `CallFlow` for the selected dialog.
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

    /// Esc from the call flow returns to the call list.
    #[test]
    fn esc_from_call_flow_returns_to_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // call flow
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Enter with no dialogs is a no-op: the view stays on the call list.
    #[test]
    fn enter_on_empty_list_stays_in_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Enter);
        // No dialogs, so Enter does nothing
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// F7 opens the filter popup while the underlying view stays `CallList`.
    #[test]
    fn f7_opens_filter_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
        // Underlying view is still CallList
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Esc in the filter popup cancels without applying: all 3 dialogs stay visible.
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

    /// Typing "1003" into the From field and applying narrows the list to 1 dialog.
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

    /// F9 clears an applied filter, restoring all 3 dialogs.
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

    /// `s` opens the Statistics view.
    #[test]
    fn s_opens_statistics_view() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
    }

    /// Esc closes Statistics back to the call list.
    #[test]
    fn esc_from_statistics_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Esc leaves the stream list for the call list.
    #[test]
    fn esc_from_stream_list_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // switch to stream list
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Enter inside the call flow opens `RawMessage` for the selected message.
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

    /// Esc from a raw message opened via the call flow returns to the call flow.
    #[test]
    fn esc_from_raw_message_returns_to_call_flow() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // call flow
        app.handle_key(KeyCode::Enter); // raw message
        assert!(matches!(app.current_view(), View::RawMessage { .. }));
        app.handle_key(KeyCode::Esc); // back to call flow
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    /// `q` quits from the stream list and from the call flow alike.
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

    /// Filter text like "[invalid" is a literal substring: no error, zero matches.
    #[test]
    fn regex_metachars_in_filter_are_literal_text() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7)); // open filter
        // Filter fields are literal substrings, never regexes: "[invalid"
        // must not error — it simply matches no From user here.
        for c in "[invalid".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(*app.current_view(), View::CallList);
        assert_eq!(app.status_error(), None, "literal text must not error");
        assert_eq!(app.visible_dialog_count(), 0);
    }

    /// F9 clears filter and dialog state; re-applying empty filter fields
    /// afterwards is a no-op that keeps all 3 dialogs visible.
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
    /// Method-checkbox grid index of INVITE in the filter popup (the grid
    /// itself starts at focus index 6, after the 5 text fields and "All").
    const INVITE_IDX: usize = 2;

    /// Applying the popup untouched (all methods checked) shows every dialog (regression: it used to show none).
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

    /// With every method checkbox unchecked, no dialogs are shown.
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

    /// With only INVITE checked, all three INVITE fixtures remain visible.
    #[test]
    fn filter_only_invite_checked_shows_invite_dialogs() {
        let mut app = app_with_three_dialogs();
        let mut methods = [false; 10];
        methods[INVITE_IDX] = true; // only INVITE
        app.apply_method_filter_for_test(methods);
        assert_eq!(app.visible_dialog_count(), 3, "all fixtures are INVITE");
    }

    /// With every method except INVITE checked, all INVITE fixtures disappear.
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

    /// Re-checking all methods after an uncheck-all restores every dialog.
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

    // ── "All" master checkbox (enable/disable every method at once) ─────

    /// The "All" master checkbox toggles every method off then back on; applying then shows all dialogs.
    #[test]
    fn filter_all_checkbox_disables_then_enables_every_method() {
        // Focus order: 5 text fields (0-4), the "All" master checkbox (5),
        // then the 10 method checkboxes (6-15).
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7));
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        app.handle_key(KeyCode::Char(' ')); // all checked -> disable all
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert_eq!(methods, [false; 10], "All toggles every method off");

        app.handle_key(KeyCode::Char(' ')); // none checked -> enable all
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert_eq!(methods, [true; 10], "All toggles every method back on");

        // Applying with everything re-checked shows every dialog.
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 3);
    }

    /// From a mixed checkbox state, toggling "All" enables every method first.
    #[test]
    fn filter_all_checkbox_from_mixed_state_enables_all_first() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Uncheck INVITE (focus 8) for a mixed state.
        for _ in 0..8 {
            app.handle_key(KeyCode::Tab);
        }
        app.handle_key(KeyCode::Char(' '));
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert!(
            !methods[INVITE_IDX] && methods[0],
            "mixed state established"
        );
        // Back up to the All checkbox (focus 5, above the grid) and toggle.
        for _ in 0..3 {
            app.handle_key(KeyCode::BackTab);
        }
        app.handle_key(KeyCode::Char(' '));
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert_eq!(
            methods, [true; 10],
            "from a mixed state, All enables everything first"
        );
    }

    /// The rendered filter popup contains the "All" master checkbox label.
    #[test]
    fn filter_all_checkbox_is_rendered_in_popup() {
        let backend = ratatui::backend::TestBackend::new(80, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        terminal.draw(|f| app.render(f)).unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains("All"),
            "the popup must render the All master checkbox; popup text:\n{text}"
        );
    }

    /// Via the real key path (F7, 8 Tabs, Space, Enter), unchecking INVITE hides the INVITE dialogs.
    #[test]
    fn filter_space_toggles_method_via_keys() {
        // Drive the real key path: F7, move focus to the INVITE checkbox, Space
        // to uncheck it, Enter to apply. With INVITE unchecked the INVITE
        // fixtures must disappear.
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(7));
        // Focus starts on text field 0. Tab advances one element at a time:
        // 5 text fields, the All checkbox, then the method checkboxes — so 8
        // Tabs lands on method index 2 (INVITE).
        for _ in 0..8 {
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

    /// Seven Tabs land on right-column checkbox OPTIONS (focus 7) and Space toggles it off.
    #[test]
    fn filter_right_column_reachable_by_tab_and_toggle() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // 5 text fields (0-4), All (5), checkbox 0 (6), checkbox 1 (7).
        for _ in 0..7 {
            app.handle_key(KeyCode::Tab);
        }
        let (focus, _) = app.filter_focus_and_methods_for_test();
        assert_eq!(
            focus, 7,
            "7 Tabs should land on right-column checkbox 1 (OPTIONS)"
        );
        app.handle_key(KeyCode::Char(' '));
        let (_, methods) = app.filter_focus_and_methods_for_test();
        assert!(
            !methods[1],
            "Space should toggle OPTIONS (index 1) off; methods={methods:?}"
        );
    }

    /// A focused right-column checkbox (OPTIONS) renders bold in the popup.
    #[test]
    fn filter_right_column_focus_renders_bold() {
        use ratatui::style::Modifier;
        let backend = ratatui::backend::TestBackend::new(80, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        for _ in 0..7 {
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

    /// Down from the bottom of the left checkbox column enters the right column instead of skipping to the buttons.
    #[test]
    fn filter_down_arrow_reaches_second_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Into the checkbox grid: 6 Tabs -> checkbox 0 (REGISTER, focus 6;
        // the All master checkbox sits at focus 5).
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        // Down 4 times walks the left column to INFO (idx 8, focus 14).
        for _ in 0..4 {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            6 + 8,
            "Down reaches INFO (left col bottom)"
        );
        // One more Down must enter the SECOND column (OPTIONS, idx 1) rather than
        // skipping straight to the buttons — otherwise the right column is
        // unreachable by vertical navigation.
        app.handle_key(KeyCode::Down);
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            6 + 1,
            "Down from the bottom of column 1 must reach column 2 (OPTIONS)"
        );
    }

    /// Right arrow moves focus from REGISTER (left column) into OPTIONS (right column).
    #[test]
    fn filter_right_arrow_reaches_second_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Tab into the checkbox grid: 6 tabs -> checkbox 0 (REGISTER, focus 6).
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_focus_and_methods_for_test().0, 6);
        // Right arrow should move into the second column (checkbox 1, focus 7).
        app.handle_key(KeyCode::Right);
        assert_eq!(
            app.filter_focus_and_methods_for_test().0,
            7,
            "Right arrow should move from REGISTER into OPTIONS (second column)"
        );
        app.handle_key(KeyCode::Char(' '));
        assert!(!app.filter_focus_and_methods_for_test().1[1]);
    }

    /// F9 clears a no-methods filter and restores all dialogs.
    #[test]
    fn filter_f9_clears_method_filter_to_show_all() {
        let mut app = app_with_three_dialogs();
        app.apply_method_filter_for_test([false; 10]);
        assert_eq!(app.visible_dialog_count(), 0);
        app.handle_key(KeyCode::F(9)); // clear filter
        assert_eq!(app.visible_dialog_count(), 3, "F9 clear restores show-all");
    }

    // ── Filter dialog checkbox grid navigation ─────────────────────────

    /// Down walks the checkbox grid row by row: left column, then right column, then the buttons.
    #[test]
    fn filter_checkbox_down_moves_by_row() {
        // Layout: 2 columns, 5 rows. idx 0=REGISTER, 1=OPTIONS, 2=INVITE, ...
        // Text fields: ff 0-4. All: ff 5. Method checkboxes: 6-15. Buttons: 16-17.
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7)); // open filter
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));

        // Tab through 5 text fields + the All row to the first method (REGISTER, ff=6)
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_dialog.focused_field(), 6); // REGISTER (idx 0)

        // Down should go to INVITE (idx 2, ff=8), not OPTIONS (idx 1, ff=7)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 8); // INVITE (idx 2)

        // Down again -> SUBSCRIBE (idx 4, ff=10)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 10); // SUBSCRIBE (idx 4)

        // Down again -> NOTIFY (idx 6, ff=12)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 12); // NOTIFY (idx 6)

        // Down again -> INFO (idx 8, ff=14)
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 14); // INFO (idx 8)

        // Down from the bottom of the LEFT column continues into the RIGHT
        // column (OPTIONS, idx 1, ff=7) so it's reachable by vertical nav.
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 7); // OPTIONS (idx 1)
        // ...down the right column: PUBLISH(3,9) MESSAGE(5,11) REFER(7,13) UPDATE(9,15)
        for expected in [9, 11, 13, 15] {
            app.handle_key(KeyCode::Down);
            assert_eq!(app.filter_dialog.focused_field(), expected);
        }
        // Down from the bottom of the RIGHT column -> buttons (ff=16).
        app.handle_key(KeyCode::Down);
        assert_eq!(app.filter_dialog.focused_field(), 16); // Filter button
    }

    /// Right/Left move between the two checkbox columns; Right at the right edge is a no-op.
    #[test]
    fn filter_checkbox_right_moves_by_column() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        assert_eq!(app.filter_dialog.focused_field(), 6); // REGISTER (idx 0, left col)

        // Right should go to OPTIONS (idx 1, ff=7)
        app.handle_key(KeyCode::Right);
        assert_eq!(app.filter_dialog.focused_field(), 7); // OPTIONS (idx 1)

        // Right again from right column — no-op
        app.handle_key(KeyCode::Right);
        assert_eq!(app.filter_dialog.focused_field(), 7); // still OPTIONS

        // Left should go back to REGISTER (idx 0, ff=6)
        app.handle_key(KeyCode::Left);
        assert_eq!(app.filter_dialog.focused_field(), 6); // REGISTER
    }

    /// Up walks a method row up, then to the All checkbox, then to the last text field.
    #[test]
    fn filter_checkbox_up_moves_by_row() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(7));
        // Navigate to INVITE (idx 2, ff=8): tab to the grid, then down once
        for _ in 0..6 {
            app.handle_key(KeyCode::Tab);
        }
        app.handle_key(KeyCode::Down); // REGISTER -> INVITE
        assert_eq!(app.filter_dialog.focused_field(), 8); // INVITE (idx 2)

        // Up should go back to REGISTER (idx 0, ff=6)
        app.handle_key(KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field(), 6); // REGISTER

        // Up from the top method row -> the All checkbox (ff=5)
        app.handle_key(KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field(), 5); // All

        // Up from All -> last text field (ff=4, Payload)
        app.handle_key(KeyCode::Up);
        assert_eq!(app.filter_dialog.focused_field(), 4); // Payload text field
    }

    // ── F5 / Ctrl-L — Clear calls ─────────────────────────────────────

    /// F5 with nothing check-selected clears every dialog.
    #[test]
    fn f5_clears_all_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::F(5));
        assert_eq!(app.visible_dialog_count(), 0);
    }

    /// Ctrl-L clears every dialog, same as F5.
    #[test]
    fn ctrl_l_clears_all_dialogs() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key_with_modifiers(KeyCode::Char('l'), crossterm::event::KeyModifiers::CONTROL);
        assert_eq!(app.visible_dialog_count(), 0);
    }

    /// With one row check-selected, F5 clears only that dialog, leaving 2.
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

    /// F6 from the call list jumps straight to the `RawMessage` view.
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

    /// `r` from the call list opens the `RawMessage` view.
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

    /// F10 opens the call-list column selector.
    #[test]
    fn f10_opens_column_selector() {
        let mut app = App::new_test();
        assert!(!app.call_list_state().column_selector_open);
        app.handle_key(KeyCode::F(10));
        assert!(app.call_list_state().column_selector_open);
    }

    /// `t` cycles the timestamp mode DeltaPrev, DeltaFirst, Scaled, Absolute, back to DeltaPrev.
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

    /// Enter closes the column selector.
    #[test]
    fn column_selector_enter_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10)); // open
        assert!(app.call_list_state().column_selector_open);
        app.handle_key(KeyCode::Enter); // close
        assert!(!app.call_list_state().column_selector_open);
    }

    /// Esc closes the column selector.
    #[test]
    fn column_selector_esc_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Esc);
        assert!(!app.call_list_state().column_selector_open);
    }

    /// Space in the column selector toggles the focused column's visibility both ways.
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

    /// `>` and `<` cycle the sort column forward and backward (Index, Method, From).
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

    /// `Z` toggles the sort direction between ascending and descending.
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

    /// `A` toggles the call-list autoscroll flag off and back on.
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

    /// `p` toggles capture pause on and off.
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

    /// With a filter active, `i` deletes the non-matching dialogs, keeping only the 1 match.
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

    /// With a filter active, `I` deletes the matching dialog, keeping the other 2.
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

    /// `i` without an active filter changes nothing.
    #[test]
    fn i_without_filter_does_nothing() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::Char('i'));
        assert_eq!(app.visible_dialog_count(), 3); // no change
    }

    /// `I` without an active filter changes nothing.
    #[test]
    fn i_uppercase_without_filter_does_nothing() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);
        app.handle_key(KeyCode::Char('I'));
        assert_eq!(app.visible_dialog_count(), 3); // no change
    }

    /// Create an app with the call flow view open on dialog 1.
    ///
    /// # Returns
    /// The three-dialog fixture app with the call flow view active.
    fn app_with_call_flow_open() -> App {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Enter); // open call flow for first dialog
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        app
    }

    /// Create an app with the raw message view open.
    ///
    /// # Returns
    /// The fixture app viewing the raw bytes of dialog 1's first message.
    fn app_in_raw_message() -> App {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Enter); // open raw message from call flow
        assert!(matches!(app.current_view(), View::RawMessage { .. }));
        app
    }

    /// Create an app in the message diff view.
    ///
    /// # Returns
    /// The fixture app with the diff of dialog 1's messages 0 and 1 open.
    fn app_in_message_diff() -> App {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select first message
        app.handle_key(KeyCode::Down); // move to second
        app.handle_key(KeyCode::Char(' ')); // open diff
        assert!(matches!(app.current_view(), View::MessageDiff { .. }));
        app
    }

    // ── Call list: selection must resolve against the DISPLAYED list ──
    // (filter + search + sort), not a filter-only unsorted list.

    // With a search narrowing the list to one row, Enter must open that row.
    /// With search narrowed to one row, a single Enter commits the query and opens that row (`call-2@test`).
    #[test]
    fn enter_after_search_opens_the_call_the_user_sees() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        // ONE Enter accepts the search (query persists) and opens the
        // only visible row in the same press.
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::CallFlow(cid) => assert_eq!(
                cid, "call-2@test",
                "the single searched row is call-2 (from user 1003)"
            ),
            v => panic!("expected CallFlow, got {v:?}"),
        }
    }

    // With a search active, Down must not walk the selection past the
    // visible rows.
    /// With one searched row visible, repeated Down keeps the selection clamped at 0.
    #[test]
    fn navigation_clamps_to_searched_rows() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        for _ in 0..5 {
            app.handle_key(KeyCode::Down);
        }
        assert_eq!(
            app.call_list_state().selected(),
            0,
            "one visible row -> selection stays at 0"
        );
    }

    // After reversing the sort, the top row is the LAST dialog; Enter must
    // open that one.
    /// After `Z` reverses the sort, Enter opens the new top row (`call-3@test`), not the old index.
    #[test]
    fn enter_after_sort_reversal_opens_the_top_displayed_row() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('Z')); // reverse sort direction
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::CallFlow(cid) => assert_eq!(
                cid, "call-3@test",
                "reversed sort puts call-3 on top; Enter must open it"
            ),
            v => panic!("expected CallFlow, got {v:?}"),
        }
    }

    // Multi-select checkmarks must stick to the CALL, not the row position:
    // selecting call-1, then reordering the list, then clearing selected must
    // remove call-1 — not whatever now sits at the old row index.
    /// A selection checkmark follows the call across a sort reversal: F5 clears checked call-1, not the new row-0 occupant.
    #[test]
    fn multi_select_survives_reordering() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char(' ')); // check row 0 = call-1
        app.handle_key(KeyCode::Char('Z')); // reverse sort: call-3 now on top
        app.handle_key(KeyCode::F(5)); // clear the checked calls
        assert_eq!(app.visible_dialog_count(), 2);
        let store = app.dialog_store_ref().read();
        assert!(
            store.get("call-1@test").is_none(),
            "the checked call-1 must be the one cleared"
        );
        assert!(
            store.get("call-3@test").is_some(),
            "call-3 was never checked; reordering must not transfer the mark"
        );
    }

    // Esc from a raw message opened DIRECTLY from the call list (F6) must
    // return to the call list, not dump the user into a call-flow view they
    // never opened.
    /// Esc from a raw message opened via F6 returns to the call list, not to an unvisited call flow.
    #[test]
    fn esc_from_raw_message_opened_from_call_list_returns_to_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(6));
        assert!(matches!(app.current_view(), View::RawMessage { .. }));
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Filter dialog: user text is matched literally ──────────────────

    /// Parse an INVITE whose From user is exactly `from_user` (no display
    /// name) and that carries a fixed User-Agent, for literal filter matching.
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
    fn make_invite_from_user(call_id: &str, from_user: &str, ts: DateTime<Utc>) -> SipMessage {
        let raw = build_sip(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                &format!("From: <sip:{from_user}@example.com>;tag=t1"),
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "User-Agent: sipsak-test-agent",
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
        .expect("parse INVITE")
    }

    /// Open the filter popup, type `text` into the From field, apply.
    ///
    /// # Arguments
    /// * `app` - App driven via key events.
    /// * `text` - Literal (non-regex) text typed into the focused From field.
    fn apply_from_filter(app: &mut App, text: &str) {
        app.handle_key(KeyCode::F(7));
        assert!(matches!(app.active_popup(), Some(Popup::FilterDialog)));
        for c in text.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
    }

    // Regex metacharacters typed into a filter field must match literally —
    // "a+b" is a user name, not a regex.
    /// Filter text "a+b" matches only the literal `a+b` user (a regex would also match "aab"), with no error.
    #[test]
    fn filter_text_with_regex_metachars_matches_literally() {
        let t0 = base_ts();
        let mut app = App::with_processed_messages(vec![
            make_invite_from_user("plus@test", "a+b", t0),
            make_invite_from_user("plain@test", "aab", t0 + TimeDelta::seconds(1)),
        ]);
        apply_from_filter(&mut app, "a+b");
        assert_eq!(
            app.status_error(),
            None,
            "literal filter text must not produce a filter error"
        );
        assert_eq!(
            app.visible_dialog_count(),
            1,
            "'a+b' must match only the literal a+b user (a regex would also match 'aab')"
        );
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::CallFlow(cid) => assert_eq!(
                cid, "plus@test",
                "the literal a+b dialog must be the surviving row"
            ),
            v => panic!("expected CallFlow, got {v:?}"),
        }
    }

    // Adversarial input: unbalanced parens, quotes, backslashes must never
    // produce a parse error — they are literal text that simply matches
    // nothing here.
    /// Unbalanced parens/brackets/quotes/backslashes in a filter never error; they just match nothing.
    #[test]
    fn filter_adversarial_text_never_errors() {
        let t0 = base_ts();
        for adversarial in ["(", "[[", "a\\", "it's", "\"", "*?"] {
            let mut app =
                App::with_processed_messages(vec![make_invite_from_user("adv@test", "1001", t0)]);
            apply_from_filter(&mut app, adversarial);
            assert_eq!(
                app.status_error(),
                None,
                "adversarial input {adversarial:?} must not error"
            );
            assert_eq!(app.visible_dialog_count(), 0, "input {adversarial:?}");
        }
    }

    // The Payload field must actually filter: it matches against the raw
    // message content of the dialog.
    /// The Payload filter field matches raw message content (a User-Agent string), narrowing to 1 dialog.
    #[test]
    fn payload_filter_matches_message_content() {
        let t0 = base_ts();
        let mut app = App::with_processed_messages(vec![
            make_invite_from_user("ua@test", "1001", t0),
            make_invite("plain@test", "1002", "1003", t0 + TimeDelta::seconds(1)),
        ]);
        // Focus the Payload field (index 4) and type a string only present
        // in the first dialog's User-Agent header.
        app.handle_key(KeyCode::F(7));
        for _ in 0..4 {
            app.handle_key(KeyCode::Tab);
        }
        for c in "sipsak-test-agent".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.status_error(), None);
        assert_eq!(
            app.visible_dialog_count(),
            1,
            "payload filter must narrow to the dialog containing the text"
        );
    }

    // Reopening search must allow refining the existing query, not wipe it.
    /// Reopening search with `/` keeps the committed query for refinement instead of wiping it.
    #[test]
    fn search_query_preserved_on_reopen() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        for c in "1003".chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.search_query(), "1003");
        app.handle_key(KeyCode::Char('/')); // reopen to refine
        assert_eq!(
            app.search_query(),
            "1003",
            "reopening search must keep the query for editing"
        );
    }

    // ── Scroll clamping: no view may strand past its content ──────────

    /// Render one frame of `app` into the given test terminal.
    ///
    /// # Arguments
    /// * `app` - App whose `render` is invoked.
    /// * `term` - In-memory terminal receiving the frame.
    fn draw(app: &mut App, term: &mut ratatui::Terminal<ratatui::backend::TestBackend>) {
        term.draw(|f| app.render(f)).unwrap();
    }

    /// Build an 80x10 in-memory terminal, small enough to force overflow
    /// and exercise scroll clamping.
    ///
    /// # Returns
    /// A ratatui `Terminal` over a `TestBackend`.
    fn small_terminal() -> ratatui::Terminal<ratatui::backend::TestBackend> {
        ratatui::Terminal::new(ratatui::backend::TestBackend::new(80, 10)).unwrap()
    }

    // Raw message view: scrolling far past the end must clamp to the content
    // (so a single Up immediately moves the view back).
    /// Raw view: 50 Downs and End both clamp near the ~8-line message, and one Up immediately moves back.
    #[test]
    fn raw_message_overscroll_clamps_and_recovers() {
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        app.handle_key(KeyCode::F(6)); // raw view from call list
        draw(&mut app, &mut term);
        for _ in 0..50 {
            app.handle_key(KeyCode::Down);
            draw(&mut app, &mut term);
        }
        let stranded = app.raw_msg_scroll();
        assert!(
            stranded < 30,
            "scroll must clamp near the ~8-line message, got {stranded}"
        );
        // End must also land clamped, and Up must move immediately.
        app.handle_key(KeyCode::End);
        draw(&mut app, &mut term);
        let at_end = app.raw_msg_scroll();
        assert!(at_end < 30, "End must clamp, got {at_end}");
        app.handle_key(KeyCode::Up);
        assert_eq!(app.raw_msg_scroll(), at_end.saturating_sub(1));
    }

    // Combined (transaction/dialog) detail: End claimed to clamp but never
    // did — u16::MAX scroll rendered a blank screen.
    /// Combined detail: End clamps to content height instead of stranding at `u16::MAX` on a blank screen (regression).
    #[test]
    fn combined_detail_end_is_clamped_not_blank() {
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        app.handle_key(KeyCode::Enter); // call flow
        draw(&mut app, &mut term);
        app.handle_key(KeyCode::Char('A')); // whole-dialog combined detail
        assert!(matches!(app.current_view(), View::CombinedDetail { .. }));
        draw(&mut app, &mut term);
        app.handle_key(KeyCode::End);
        draw(&mut app, &mut term);
        assert!(
            app.raw_msg_scroll() < 60,
            "End must clamp to content height, got {}",
            app.raw_msg_scroll()
        );
    }

    // Call flow ladder: PageDown must not push the scroll past the ladder.
    /// Repeated PageDown clamps the ladder scroll on a 2-message call flow.
    #[test]
    fn call_flow_pagedown_clamps_to_ladder() {
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        app.handle_key(KeyCode::Enter);
        draw(&mut app, &mut term);
        for _ in 0..5 {
            app.handle_key(KeyCode::PageDown);
            draw(&mut app, &mut term);
        }
        assert!(
            app.call_flow_scroll() < 10,
            "2-message ladder: scroll must clamp, got {}",
            app.call_flow_scroll()
        );
    }

    // Statistics view must scroll: content taller than the pane was simply
    // cut off with no way to see the bottom.
    /// Statistics scrolls with Down, clamps at End, and Home returns to 0.
    #[test]
    fn statistics_view_scrolls_and_clamps() {
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        draw(&mut app, &mut term);
        app.handle_key(KeyCode::Down);
        draw(&mut app, &mut term);
        assert_eq!(app.stats_scroll(), 1, "Down must scroll the statistics");
        app.handle_key(KeyCode::End);
        draw(&mut app, &mut term);
        assert!(
            app.stats_scroll() < 200,
            "End must clamp to content, got {}",
            app.stats_scroll()
        );
        app.handle_key(KeyCode::Home);
        assert_eq!(app.stats_scroll(), 0);
    }

    // Message diff must scroll: long messages were truncated with no
    // navigation at all.
    /// Message diff scrolls with Down, clamps at End, and Home returns to 0.
    #[test]
    fn message_diff_scrolls_and_clamps() {
        let mut app = app_in_message_diff();
        let mut term = small_terminal();
        draw(&mut app, &mut term);
        app.handle_key(KeyCode::Down);
        draw(&mut app, &mut term);
        assert_eq!(app.diff_scroll(), 1, "Down must scroll the diff");
        app.handle_key(KeyCode::End);
        draw(&mut app, &mut term);
        assert!(
            app.diff_scroll() < 100,
            "End must clamp to content, got {}",
            app.diff_scroll()
        );
        app.handle_key(KeyCode::PageUp);
        draw(&mut app, &mut term);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.diff_scroll(), 0);
    }

    // ── Keymap rebinds must apply in EVERY view ────────────────────────

    /// Rebinding quit to `x` applies in the diff view; the unbound `q` no longer quits.
    #[test]
    fn diff_view_respects_quit_rebind() {
        let mut app = app_in_message_diff();
        app.keymap.quit = KeyCode::Char('x');
        app.handle_key(KeyCode::Char('q'));
        assert!(!app.should_quit(), "unbound 'q' must no longer quit");
        app.handle_key(KeyCode::Char('x'));
        assert!(
            app.should_quit(),
            "rebound quit key must work in the diff view"
        );
    }

    /// Rebinding help to F12 applies in the combined detail view.
    #[test]
    fn combined_detail_respects_help_rebind() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('A'));
        assert!(matches!(app.current_view(), View::CombinedDetail { .. }));
        app.keymap.help = KeyCode::F(12);
        app.handle_key(KeyCode::F(12));
        assert_eq!(*app.current_view(), View::Help);
    }

    // A key the user rebinds to an action must win over the built-in global
    // fallbacks ('v' version, 'n' name-mode cycle).
    /// A user rebind (`n` mapped to quit) wins over the built-in global fallback (name-mode cycle).
    #[test]
    fn keymap_rebind_beats_global_fallback_keys() {
        let mut app = app_with_three_dialogs();
        app.keymap.quit = KeyCode::Char('n');
        app.handle_key(KeyCode::Char('n'));
        assert!(
            app.should_quit(),
            "'n' rebound to quit must quit, not cycle name mode"
        );
    }

    // ── Mouse wheel ────────────────────────────────────────────────────

    /// Mouse wheel moves the call-list selection down twice and back up once.
    #[test]
    fn mouse_wheel_scrolls_call_list() {
        use crossterm::event::MouseEventKind;
        let mut app = app_with_three_dialogs();
        app.handle_mouse_kind(MouseEventKind::ScrollDown);
        app.handle_mouse_kind(MouseEventKind::ScrollDown);
        assert_eq!(app.call_list_state().selected(), 2);
        app.handle_mouse_kind(MouseEventKind::ScrollUp);
        assert_eq!(app.call_list_state().selected(), 1);
    }

    /// Mouse wheel scrolls the Help view.
    #[test]
    fn mouse_wheel_scrolls_help_view() {
        use crossterm::event::MouseEventKind;
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
        app.handle_mouse_kind(MouseEventKind::ScrollDown);
        assert!(app.help_scroll() > 0, "wheel must scroll the help view");
    }

    /// The call timeline is a single-screen, single-call view with no
    /// scrollable or selectable content: the mouse wheel is intentionally
    /// a no-op there. This pins the static contract — wheeling neither
    /// panics nor leaves the timeline view.
    #[test]
    fn mouse_wheel_is_noop_on_timeline() {
        use crossterm::event::MouseEventKind;
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('T'));
        assert!(
            matches!(app.current_view(), View::CallTimeline(_)),
            "Shift+T must open the timeline"
        );
        let before = app.current_view().clone();
        app.handle_mouse_kind(MouseEventKind::ScrollDown);
        app.handle_mouse_kind(MouseEventKind::ScrollUp);
        assert_eq!(
            *app.current_view(),
            before,
            "wheel must not change the static timeline view"
        );
    }

    /// Navigation keys on the timeline are intentionally inert: the view is
    /// static, so arrows/paging/Enter do nothing and only Esc closes back to
    /// the call list.
    #[test]
    fn navigation_keys_are_inert_on_timeline() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('T'));
        let before = app.current_view().clone();
        for code in [
            KeyCode::Down,
            KeyCode::Up,
            KeyCode::PageDown,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Enter,
        ] {
            app.handle_key(code);
            assert_eq!(
                *app.current_view(),
                before,
                "{code:?} must leave the static timeline unchanged"
            );
        }
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // Left/Right in call flow silently did nothing with the split pane off.
    /// Left with the split pane off shows a status hint mentioning `R` instead of silently doing nothing.
    #[test]
    fn call_flow_left_right_hint_when_split_off() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('R')); // split off
        assert!(!app.raw_preview());
        app.handle_key(KeyCode::Left);
        let hint = app.status_error().unwrap_or_default().to_string();
        assert!(
            hint.contains('R'),
            "Left with split off must hint how to enable the split, got {hint:?}"
        );
    }

    // ── Settings must actually do something ────────────────────────────

    // Autoscroll: with the toggle ON and the selection sitting on the last
    // row, newly arriving dialogs pull the selection to the new bottom.
    // With the selection elsewhere, or the toggle OFF, nothing moves.
    /// With autoscroll on and the selection on the last row, a newly arriving dialog pulls the selection to the new bottom.
    #[test]
    fn autoscroll_follows_new_dialogs_when_at_bottom() {
        let t0 = base_ts();
        let mut app =
            App::with_processed_messages(vec![make_invite("as-1@test", "1001", "1002", t0)]);
        let mut term = small_terminal();
        draw(&mut app, &mut term);
        assert_eq!(app.call_list_state().selected(), 0);
        app.dialog_store_ref().write().process_message(make_invite(
            "as-2@test",
            "1003",
            "1004",
            t0 + TimeDelta::seconds(1),
        ));
        // Sticky-bottom follows at the churn-floor cadence (≤300 ms), not
        // per tick; elapse the floor as real time would between refreshes.
        app.elapse_churn_floors_for_test();
        draw(&mut app, &mut term);
        assert_eq!(
            app.call_list_state().selected(),
            1,
            "autoscroll must follow the newest dialog"
        );
    }

    /// A new dialog does not move a selection that is not sitting on the bottom row.
    #[test]
    fn autoscroll_does_not_yank_selection_away() {
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        draw(&mut app, &mut term);
        // User is inspecting row 0, not the bottom.
        assert_eq!(app.call_list_state().selected(), 0);
        app.dialog_store_ref().write().process_message(make_invite(
            "as-4@test",
            "1007",
            "1008",
            base_ts() + TimeDelta::seconds(20),
        ));
        draw(&mut app, &mut term);
        assert_eq!(
            app.call_list_state().selected(),
            0,
            "selection away from the bottom must not be yanked"
        );
    }

    // Syntax highlight toggle: OFF must render the raw message plain.
    /// Toggling syntax highlight off with `s` renders the raw message with zero bold cells.
    #[test]
    fn syntax_highlight_toggle_takes_effect() {
        use ratatui::style::Modifier;
        let mut app = app_with_three_dialogs();
        let mut term = small_terminal();
        app.handle_key(KeyCode::F(6)); // raw view
        draw(&mut app, &mut term);
        // Count only inside the message block (skip the app status bar and
        // the block border, which carry their own styling).
        let bold_cells = |t: &ratatui::Terminal<ratatui::backend::TestBackend>| {
            let buf = t.backend().buffer();
            let mut n = 0;
            for y in 4..buf.area.height.saturating_sub(1) {
                for x in 1..buf.area.width.saturating_sub(1) {
                    if buf
                        .cell((x, y))
                        .unwrap()
                        .style()
                        .add_modifier
                        .contains(Modifier::BOLD)
                    {
                        n += 1;
                    }
                }
            }
            n
        };
        assert!(bold_cells(&term) > 0, "highlighting ON renders styled text");
        app.handle_key(KeyCode::Char('s')); // toggle OFF
        draw(&mut app, &mut term);
        assert_eq!(
            bold_cells(&term),
            0,
            "highlighting OFF must render the message plain"
        );
    }

    // ── Call flow with folded retransmissions: index mapping ──────────

    /// Parse an OPTIONS keepalive without a Via header, so retransmission
    /// detection falls back to CSeq identity (a repeated `cseq` folds as a retx).
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
    fn make_options(call_id: &str, cseq: u32, ts: DateTime<Utc>) -> SipMessage {
        // No Via header → retransmission detection falls back to CSeq
        // identity, so a repeated CSeq is flagged as a retransmission.
        let raw = build_sip(
            "OPTIONS sip:ping@example.com SIP/2.0",
            &[
                "From: <sip:mon@example.com>;tag=m1",
                "To: <sip:ping@example.com>",
                &format!("Call-ID: {call_id}"),
                &format!("CSeq: {cseq} OPTIONS"),
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
        .expect("parse OPTIONS")
    }

    /// Call flow open on a dialog whose ladder folds two retransmissions:
    /// raw messages [OPT#1, retx#1, OPT#2, retx#2] render as two visible
    /// rows, each a fold header (+1 retx). Renders once so the App caches
    /// (visible row count, row→message mapping) are populated like in the
    /// real event loop.
    ///
    /// # Returns
    /// The app (call flow open) and the 120x40 terminal it was rendered into.
    fn app_with_folded_flow() -> (App, ratatui::Terminal<ratatui::backend::TestBackend>) {
        let t0 = base_ts();
        let messages = vec![
            make_options("fold@test", 1, t0),
            make_options("fold@test", 1, t0 + TimeDelta::milliseconds(500)),
            make_options("fold@test", 2, t0 + TimeDelta::seconds(30)),
            make_options("fold@test", 2, t0 + TimeDelta::seconds(31)),
        ];
        let mut app = App::with_processed_messages(messages);
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        let backend = ratatui::backend::TestBackend::new(120, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|f| app.render(f)).unwrap();
        (app, terminal)
    }

    // Enter must open the raw view of the message the user SEES selected.
    // Visible row 1 is the second OPTIONS (raw message index 2) because the
    // two retransmissions are folded away.
    /// In a folded ladder, Enter on visible row 1 opens raw message index 2 (OPT#2), not the folded retransmission.
    #[test]
    fn flow_enter_opens_the_message_the_user_sees() {
        let (mut app, mut terminal) = app_with_folded_flow();
        app.handle_key(KeyCode::Down); // visible row 1 = OPT#2
        terminal.draw(|f| app.render(f)).unwrap();
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::RawMessage { message_index, .. } => {
                assert_eq!(
                    *message_index, 2,
                    "visible row 1 is raw message 2 (OPT#2), not the folded retx"
                );
            }
            v => panic!("expected RawMessage, got {v:?}"),
        }
    }

    // 'e' on a fold header must expand THAT header's retransmissions, even
    // when earlier folds make the visible index differ from the raw index.
    /// `e` on the second fold header expands that header's own retransmission (raw index 3) despite earlier folds shifting indices.
    #[test]
    fn flow_expand_on_second_fold_header_reveals_its_retransmissions() {
        let (mut app, mut terminal) = app_with_folded_flow();
        app.handle_key(KeyCode::Down); // visible row 1 = OPT#2 fold header (raw 2)
        terminal.draw(|f| app.render(f)).unwrap();
        app.handle_key(KeyCode::Char('e'));
        terminal.draw(|f| app.render(f)).unwrap();
        // Expanded: OPT#1(+1 retx), OPT#2, retx#2 → 3 visible rows, so the
        // row after the header is the revealed retransmission (raw 3).
        app.handle_key(KeyCode::Down);
        terminal.draw(|f| app.render(f)).unwrap();
        app.handle_key(KeyCode::Enter);
        match app.current_view() {
            View::RawMessage { message_index, .. } => {
                assert_eq!(
                    *message_index, 3,
                    "row below the expanded header must be its retransmission (raw 3)"
                );
            }
            v => panic!("expected RawMessage, got {v:?}"),
        }
    }

    // Down at the end of the folded ladder must stop at the last VISIBLE row
    // (folded rows are not navigable positions).
    /// Down past the end of a folded ladder clamps to the last visible row (1), not the raw message count (3).
    #[test]
    fn flow_selection_clamps_to_visible_rows_not_raw_count() {
        let (mut app, mut terminal) = app_with_folded_flow();
        for _ in 0..10 {
            app.handle_key(KeyCode::Down);
            terminal.draw(|f| app.render(f)).unwrap();
        }
        assert_eq!(
            app.selected_msg_index(),
            1,
            "only 2 visible rows exist; selection must clamp to index 1"
        );
    }

    // ── Call list: additional keys ───────────────────────────────────

    /// Home returns the call-list selection to row 0.
    #[test]
    fn home_moves_to_top() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.call_list_state().selected(), 2);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    /// `/` enters search mode with an empty query.
    #[test]
    fn slash_activates_search_mode() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
        assert_eq!(app.search_query(), "");
    }

    /// F3 also enters search mode.
    #[test]
    fn f3_activates_search_mode() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(3));
        assert!(app.search_active());
    }

    /// F4 (extended flow) on an empty list does nothing.
    #[test]
    fn f4_on_empty_list_stays_in_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(4));
        // No dialogs, so F4 does nothing
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// F8 opens the settings popup from the call list.
    #[test]
    fn f8_opens_settings_popup_from_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert_eq!(app.active_popup(), Some(&Popup::SettingsDialog));
    }

    // ── Search mode ──────────────────────────────────────────────────

    /// Esc in search mode cancels and clears the typed query.
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

    /// Enter commits the search query; it is retained for highlighting after search mode exits.
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

    /// Backspace removes the last character from the search query.
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

    /// Typed characters append to the search query while search stays active.
    #[test]
    fn search_char_appends() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        app.handle_key(KeyCode::Char('x'));
        app.handle_key(KeyCode::Char('y'));
        assert_eq!(app.search_query(), "xy");
        assert!(app.search_active());
    }

    /// Backspace with an empty query is a no-op and search stays active.
    #[test]
    fn search_backspace_on_empty_is_noop() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('/'));
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.search_query(), "");
        assert!(app.search_active());
    }

    // ── Call flow: navigation ────────────────────────────────────────

    /// `q` quits from the call flow.
    #[test]
    fn call_flow_q_quits() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    /// Esc from the call flow returns to the call list.
    #[test]
    fn call_flow_esc_returns_to_call_list() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Down advances the selected message index from 0 to 1.
    #[test]
    fn call_flow_down_increments_selected_msg() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.selected_msg_index(), 0);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.selected_msg_index(), 1);
    }

    /// Up at the first message keeps the selection at 0.
    #[test]
    fn call_flow_up_at_top_stays() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_msg_index(), 0);
    }

    /// Up after Down returns the selection to 0.
    #[test]
    fn call_flow_up_decrements() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Up);
        assert_eq!(app.selected_msg_index(), 0);
    }

    /// `j` moves the message selection down.
    #[test]
    fn call_flow_j_increments() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.selected_msg_index(), 1);
    }

    /// `k` moves the message selection back up.
    #[test]
    fn call_flow_k_decrements() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.selected_msg_index(), 0);
    }

    /// Moving to another message resets the detail-pane scroll to 0.
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

    /// PageDown clamps to the last message (index 1) of a 2-message dialog.
    #[test]
    fn call_flow_page_down() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::PageDown);
        // Dialog 1 has 2 messages; PageDown advances by 20 but clamps to max (1)
        assert_eq!(app.selected_msg_index(), 1);
    }

    /// PageUp after PageDown moves the selection back toward the top.
    ///
    /// Dialog 1 has two messages (INVITE + 200 OK), so PageDown lands on the
    /// last visible row (index 1) and PageUp returns to the first (index 0).
    /// Asserting the concrete positions makes this fail if either paging key
    /// is a no-op — the old `< after_down || after_down == 0` form passed
    /// vacuously whenever PageDown happened not to move.
    #[test]
    fn call_flow_page_up_after_page_down() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::PageDown);
        let after_down = app.selected_msg_index();
        assert_eq!(
            after_down, 1,
            "PageDown must advance to the last of the two messages"
        );
        app.handle_key(KeyCode::PageUp);
        assert_eq!(
            app.selected_msg_index(),
            0,
            "PageUp must return to the first message"
        );
    }

    /// Home selects the first message and resets the ladder scroll.
    #[test]
    fn call_flow_home_goes_to_first() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.selected_msg_index(), 0);
        assert_eq!(app.call_flow_scroll(), 0);
    }

    /// End selects the last message (index 1 of 2).
    #[test]
    fn call_flow_end_goes_to_last() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::End);
        // Dialog 1 has INVITE + 200 = 2 msgs, so last = 1
        assert_eq!(app.selected_msg_index(), 1);
    }

    /// Enter opens the `RawMessage` view at the currently selected message index.
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

    /// `d` cycles the SDP display None, Summary, Full, back to None.
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

    /// `t` in the call flow advances the timestamp mode (DeltaPrev to DeltaFirst).
    #[test]
    fn call_flow_t_cycles_timestamp() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('t'));
        assert_eq!(app.timestamp_mode(), TimestampMode::DeltaFirst);
    }

    /// `c` cycles the color mode Method, CallId, CSeq, back to Method.
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

    /// `R` toggles the raw-preview split pane off and back on (default on).
    #[test]
    fn call_flow_r_toggles_raw_preview() {
        let mut app = app_with_call_flow_open();
        assert!(app.raw_preview()); // default true
        app.handle_key(KeyCode::Char('R'));
        assert!(!app.raw_preview());
        app.handle_key(KeyCode::Char('R'));
        assert!(app.raw_preview());
    }

    /// `+` grows the detail split width by 5 percentage points.
    #[test]
    fn call_flow_plus_increases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('+'));
        assert_eq!(app.raw_preview_pct(), before + 5);
    }

    /// `-` shrinks the detail split width by 5 percentage points.
    #[test]
    fn call_flow_minus_decreases_pct() {
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('-'));
        assert_eq!(app.raw_preview_pct(), before - 5);
    }

    /// Repeated `+` clamps the split at 80 percent.
    #[test]
    fn call_flow_plus_clamps_at_max() {
        let mut app = app_with_call_flow_open();
        for _ in 0..20 {
            app.handle_key(KeyCode::Char('+'));
        }
        assert!(app.raw_preview_pct() <= 80);
    }

    /// Repeated `-` clamps the split at 10 percent.
    #[test]
    fn call_flow_minus_clamps_at_min() {
        let mut app = app_with_call_flow_open();
        for _ in 0..20 {
            app.handle_key(KeyCode::Char('-'));
        }
        assert!(app.raw_preview_pct() >= 10);
    }

    /// `]` and `[` scroll the detail pane down and back up.
    #[test]
    fn call_flow_bracket_scrolls_detail() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert_eq!(app.detail_scroll(), 1);
        app.handle_key(KeyCode::Char('['));
        assert_eq!(app.detail_scroll(), 0);
    }

    /// `[` at detail scroll 0 is a no-op.
    #[test]
    fn call_flow_bracket_up_at_zero_stays() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('['));
        assert_eq!(app.detail_scroll(), 0);
    }

    // ── Call flow: toggles ───────────────────────────────────────────

    /// F4 toggles extended flow on and off.
    #[test]
    fn call_flow_f4_toggles_extended_flow() {
        let mut app = app_with_call_flow_open();
        assert!(!app.extended_flow());
        app.handle_key(KeyCode::F(4));
        assert!(app.extended_flow());
        app.handle_key(KeyCode::F(4));
        assert!(!app.extended_flow());
    }

    /// `x` enables extended flow.
    #[test]
    fn call_flow_x_toggles_extended_flow() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('x'));
        assert!(app.extended_flow());
    }

    /// F6 toggles RTP display in the ladder on and off.
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

    /// Space marks the current message as the diff anchor.
    #[test]
    fn call_flow_space_sets_diff_selected() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.diff_selected_msg(), None);
        app.handle_key(KeyCode::Char(' '));
        assert_eq!(app.diff_selected_msg(), Some(0));
    }

    /// Space on a second, different message opens the `MessageDiff` view.
    #[test]
    fn call_flow_space_second_opens_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select msg 0
        app.handle_key(KeyCode::Down); // move to msg 1
        app.handle_key(KeyCode::Char(' ')); // open diff
        assert!(matches!(app.current_view(), View::MessageDiff { .. }));
    }

    /// Space twice on the same message opens no diff; the anchor stays set.
    #[test]
    fn call_flow_space_same_msg_no_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // select msg 0
        app.handle_key(KeyCode::Char(' ')); // same msg — no diff opened
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        assert_eq!(app.diff_selected_msg(), Some(0)); // still set
    }

    /// F5 clears the diff anchor.
    #[test]
    fn call_flow_f5_resets_compare() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // set diff
        assert!(app.diff_selected_msg().is_some());
        app.handle_key(KeyCode::F(5));
        assert_eq!(app.diff_selected_msg(), None);
    }

    /// Esc clears the diff anchor and leaves the call flow for the call list.
    #[test]
    fn call_flow_esc_clears_diff() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(' ')); // set diff
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.diff_selected_msg(), None);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Call flow: popups and navigation ─────────────────────────────

    /// F1 opens Help from the call flow.
    #[test]
    fn call_flow_f1_opens_help() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    /// F2 opens the save popup from the call flow.
    #[test]
    fn call_flow_f2_opens_save() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    /// F7 opens the filter popup from the call flow.
    #[test]
    fn call_flow_f7_opens_filter() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
    }

    /// F9 inside the call flow clears the active filter (visible count grows back).
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
        // The "1001" filter matches only dialog 1 (From=1001).
        assert_eq!(
            filtered_count, 1,
            "filter should narrow to the one 1001 dialog"
        );
        // Re-enter call flow and clear filter
        app.handle_key(KeyCode::Enter);
        app.handle_key(KeyCode::F(9));
        app.handle_key(KeyCode::Esc); // back to list to check count
        // F9 must restore all three dialogs; the old `>= filtered_count`
        // form passed even if F9 did nothing (1 >= 1). Assert the concrete
        // cleared state so a no-op F9 fails.
        assert_eq!(
            app.visible_dialog_count(),
            3,
            "F9 must clear the filter and restore all dialogs"
        );
    }

    // ── Raw message: navigation ──────────────────────────────────────

    /// `q` quits from the raw message view.
    #[test]
    fn raw_msg_q_quits() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    /// Esc from the raw view returns to the call flow it was opened from.
    #[test]
    fn raw_msg_esc_returns_to_call_flow() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Esc);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    /// Down scrolls the raw view by one line.
    #[test]
    fn raw_msg_down_scrolls() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        assert_eq!(app.raw_msg_scroll(), 1);
    }

    /// Up scrolls the raw view back to 0.
    #[test]
    fn raw_msg_up_scrolls_back() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Up);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    /// `j` scrolls the raw view down.
    #[test]
    fn raw_msg_j_scrolls() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.raw_msg_scroll(), 1);
    }

    /// `k` scrolls the raw view back up.
    #[test]
    fn raw_msg_k_scrolls_back() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    /// PageDown scrolls the raw view by 20 lines.
    #[test]
    fn raw_msg_page_down() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::PageDown);
        assert_eq!(app.raw_msg_scroll(), 20);
    }

    /// PageUp undoes a PageDown, back to 0.
    #[test]
    fn raw_msg_page_up_after_page_down() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::PageDown);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    /// Home resets the raw-view scroll to 0.
    #[test]
    fn raw_msg_home_resets_scroll() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.raw_msg_scroll(), 0);
    }

    // ── Raw message: modes ───────────────────────────────────────────

    /// `/` activates search from the raw view.
    #[test]
    fn raw_msg_slash_activates_search() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
    }

    /// `s` toggles syntax highlighting off and back on.
    #[test]
    fn raw_msg_s_toggles_syntax_highlight() {
        let mut app = app_in_raw_message();
        let before = app.syntax_highlight();
        app.handle_key(KeyCode::Char('s'));
        assert_ne!(app.syntax_highlight(), before);
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(app.syntax_highlight(), before);
    }

    /// `c` advances the color mode (Method to CallId) from the raw view.
    #[test]
    fn raw_msg_c_cycles_color_mode() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::Char('c'));
        assert_eq!(app.color_mode(), ColorMode::CallId);
    }

    /// F1 opens Help from the raw view.
    #[test]
    fn raw_msg_f1_opens_help() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    /// F2 opens the save popup from the raw view.
    #[test]
    fn raw_msg_f2_opens_save() {
        let mut app = app_in_raw_message();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    // ── Message diff ─────────────────────────────────────────────────

    /// `q` quits from the diff view.
    #[test]
    fn message_diff_q_quits() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    /// Esc from the diff returns to the call flow.
    #[test]
    fn message_diff_esc_returns_to_call_flow() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::Esc);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
    }

    /// F1 opens Help from the diff view.
    #[test]
    fn message_diff_f1_opens_help() {
        let mut app = app_in_message_diff();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    // ── Stream list: additional keys ─────────────────────────────────

    /// `/` activates search in the stream list.
    #[test]
    fn stream_list_slash_activates_search() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // go to stream list
        app.handle_key(KeyCode::Char('/'));
        assert!(app.search_active());
    }

    /// F1 opens Help from the stream list.
    #[test]
    fn stream_list_f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    /// F7 opens the filter popup from the stream list.
    #[test]
    fn stream_list_f7_opens_filter() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::F(7));
        assert_eq!(app.active_popup(), Some(&Popup::FilterDialog));
    }

    // ── Help view ────────────────────────────────────────────────────

    /// F1 while Help is open closes it back to the call list.
    #[test]
    fn help_f1_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1)); // open help
        app.handle_key(KeyCode::F(1)); // close help
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// `q` closes Help back to the call list (it does not quit the app).
    #[test]
    fn help_q_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        app.handle_key(KeyCode::Char('q'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Statistics view ──────────────────────────────────────────────

    /// `q` closes Statistics back to the call list (it does not quit).
    #[test]
    fn statistics_q_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Char('q'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// A second `s` closes Statistics.
    #[test]
    fn statistics_s_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Save popup ───────────────────────────────────────────────────

    /// Esc closes the save popup.
    #[test]
    fn save_popup_esc_closes() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
        app.handle_key(KeyCode::Esc);
        assert_eq!(app.active_popup(), None);
    }

    /// Tab cycles through all 11 save formats in order and wraps back to Pcap.
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

    /// BackTab cycles formats in reverse (Pcap, RtpJson, SippXml).
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

    /// Cycling the format rewrites the path extension (.pcapng, then .txt).
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

    /// Backspace deletes one character from the save path.
    #[test]
    fn save_popup_backspace_removes_char() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let before_len = app.save_path().len();
        app.handle_key(KeyCode::Backspace);
        assert_eq!(app.save_path().len(), before_len - 1);
    }

    /// Left moves the save-path cursor one position back.
    #[test]
    fn save_popup_left_moves_cursor() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let end = app.save_cursor();
        app.handle_key(KeyCode::Left);
        assert_eq!(app.save_cursor(), end - 1);
    }

    /// Right with the cursor already at the end of the path is a no-op.
    #[test]
    fn save_popup_right_at_end_is_noop() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        let end = app.save_cursor();
        app.handle_key(KeyCode::Right);
        assert_eq!(app.save_cursor(), end); // already at end
    }

    /// Home moves the save-path cursor to position 0.
    #[test]
    fn save_popup_home_moves_cursor_to_start() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        assert_eq!(app.save_cursor(), 0);
    }

    /// End moves the cursor to the end of the path.
    #[test]
    fn save_popup_end_moves_cursor_to_end() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::End);
        assert_eq!(app.save_cursor(), app.save_path().len());
    }

    /// A typed character inserts at the cursor position.
    #[test]
    fn save_popup_char_inserts() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::Char('X'));
        assert!(app.save_path().starts_with('X'));
    }

    /// Enter performs the save, closes the popup, and reports a status
    /// message. Writes into a tempdir that is removed when the test ends, so
    /// nothing leaks into `/tmp`.
    #[test]
    fn save_popup_enter_closes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sipnab_test_save.pcap");
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path(path.to_str().expect("utf-8 tempdir path"));
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.active_popup(), None);
        assert!(app.status_error().is_some()); // save result message
    }

    // ── Column selector: navigation ──────────────────────────────────

    /// Down moves the column-selector cursor from 0 to 1.
    #[test]
    fn column_selector_down_moves_cursor() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
        app.handle_key(KeyCode::Down);
        assert_eq!(app.call_list_state().column_selector_cursor, 1);
    }

    /// Up at the top of the column selector stays at 0.
    #[test]
    fn column_selector_up_at_top_stays() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Up);
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
    }

    // ── Global shortcuts ─────────────────────────────────────────────

    /// Ctrl-C quits from the call list.
    #[test]
    fn ctrl_c_quits_from_call_list() {
        let mut app = App::new_test();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    /// Ctrl-C quits from the call flow.
    #[test]
    fn ctrl_c_quits_from_call_flow() {
        let mut app = app_with_call_flow_open();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    /// Ctrl-C quits from the raw message view.
    #[test]
    fn ctrl_c_quits_from_raw_message() {
        let mut app = app_in_raw_message();
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    /// Ctrl-C quits even while Help is open.
    #[test]
    fn ctrl_c_quits_from_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    /// Ctrl-C quits from the Statistics view.
    #[test]
    fn ctrl_c_quits_from_statistics() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    /// Ctrl-C quits even with the save popup open.
    #[test]
    fn ctrl_c_quits_from_save_popup() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
        app.handle_key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(app.should_quit());
    }

    // ── Call list: more navigation ───────────────────────────────────

    /// End selects the last call-list row.
    #[test]
    fn end_moves_to_bottom() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::End);
        assert_eq!(app.call_list_state().selected(), 2);
    }

    /// PageDown clamps to the last row of a 3-row list.
    #[test]
    fn page_down_on_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::PageDown);
        // PageDown moves by 20, clamped to last (2)
        assert_eq!(app.call_list_state().selected(), 2);
    }

    /// PageUp from the bottom returns to row 0.
    #[test]
    fn page_up_on_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::End);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    /// Down past the last row clamps at the bottom.
    #[test]
    fn down_at_bottom_stays() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Down); // past end
        assert_eq!(app.call_list_state().selected(), 2);
    }

    /// Up at row 0 stays at 0.
    #[test]
    fn up_at_top_stays() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Up);
        assert_eq!(app.call_list_state().selected(), 0);
    }

    /// `j` moves the call-list selection down.
    #[test]
    fn j_moves_down_in_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.call_list_state().selected(), 1);
    }

    /// `k` moves the call-list selection back up.
    #[test]
    fn k_moves_up_in_call_list() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.call_list_state().selected(), 0);
    }

    /// F1 opens Help from the call list.
    #[test]
    fn call_list_f1_opens_help() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
    }

    /// F2 opens the save popup from the call list.
    #[test]
    fn call_list_f2_opens_save() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        assert_eq!(app.active_popup(), Some(&Popup::SaveDialog));
    }

    // ── Stream list: more navigation ─────────────────────────────────

    /// Esc leaves the stream list for the call list.
    #[test]
    fn stream_list_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        assert_eq!(*app.current_view(), View::StreamList);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// Tab toggles from the stream list back to the call list.
    #[test]
    fn stream_list_tab_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab); // go to stream list
        app.handle_key(KeyCode::Tab); // toggle back
        assert_eq!(*app.current_view(), View::CallList);
    }

    /// `q` quits from the stream list.
    #[test]
    fn stream_list_q_quits() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Char('q'));
        assert!(app.should_quit());
    }

    // ── Help: Esc closes ─────────────────────────────────────────────

    /// Esc closes Help back to the call list.
    #[test]
    fn help_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(1));
        assert_eq!(*app.current_view(), View::Help);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Statistics: Esc closes ───────────────────────────────────────

    /// Esc closes Statistics back to the call list.
    #[test]
    fn statistics_esc_returns_to_call_list() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('s'));
        assert_eq!(*app.current_view(), View::Statistics);
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::CallList);
    }

    // ── Popup intercepts keys ────────────────────────────────────────

    /// With the save popup open, `q` is typed into the path instead of quitting.
    #[test]
    fn popup_intercepts_normal_keys() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2)); // open save popup
        // 'q' should be consumed by save popup (inserts char), not quit
        app.handle_key(KeyCode::Char('q'));
        assert!(!app.should_quit());
        assert!(app.save_path().contains('q'));
    }

    /// In search mode, `q` goes into the query instead of quitting.
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

    /// Right pushes the split right: the detail percentage shrinks by 5.
    #[test]
    fn call_flow_right_decreases_pct() {
        // Right = push split right = ladder wider = detail pct decreases
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Right);
        assert_eq!(app.raw_preview_pct(), before - 5);
    }

    /// Left pushes the split left: the detail percentage grows by 5.
    #[test]
    fn call_flow_left_increases_pct() {
        // Left = push split left = detail wider = detail pct increases
        let mut app = app_with_call_flow_open();
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Left);
        assert_eq!(app.raw_preview_pct(), before + 5);
    }

    // ── Call flow: End resets detail_scroll ───────────────────────────

    /// End resets the detail-pane scroll to 0.
    #[test]
    fn call_flow_end_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::End);
        assert_eq!(app.detail_scroll(), 0);
    }

    /// Home resets the detail-pane scroll to 0.
    #[test]
    fn call_flow_home_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::Home);
        assert_eq!(app.detail_scroll(), 0);
    }

    /// PageUp resets the detail-pane scroll to 0.
    #[test]
    fn call_flow_page_up_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::PageUp);
        assert_eq!(app.detail_scroll(), 0);
    }

    /// PageDown resets the detail-pane scroll to 0.
    #[test]
    fn call_flow_page_down_resets_detail_scroll() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char(']'));
        assert!(app.detail_scroll() > 0);
        app.handle_key(KeyCode::PageDown);
        assert_eq!(app.detail_scroll(), 0);
    }

    // ── Call flow: raw_preview off disables resize ───────────────────

    /// `+` does not resize the split while the raw preview is off.
    #[test]
    fn call_flow_plus_noop_when_preview_off() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('R')); // turn off raw preview
        assert!(!app.raw_preview());
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('+'));
        assert_eq!(app.raw_preview_pct(), before); // unchanged
    }

    /// `-` does not resize the split while the raw preview is off.
    #[test]
    fn call_flow_minus_noop_when_preview_off() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('R'));
        let before = app.raw_preview_pct();
        app.handle_key(KeyCode::Char('-'));
        assert_eq!(app.raw_preview_pct(), before);
    }

    // ── Column selector: j/k alternatives ────────────────────────────

    /// `j` moves the column-selector cursor down.
    #[test]
    fn column_selector_j_moves_down() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Char('j'));
        assert_eq!(app.call_list_state().column_selector_cursor, 1);
    }

    /// `k` moves the column-selector cursor back up.
    #[test]
    fn column_selector_k_moves_up() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(10));
        app.handle_key(KeyCode::Char('j'));
        app.handle_key(KeyCode::Char('k'));
        assert_eq!(app.call_list_state().column_selector_cursor, 0);
    }

    // ── Save popup: backspace at 0 is noop ───────────────────────────

    /// Backspace with the cursor at 0 leaves the path unchanged.
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

    /// Left at cursor 0 is a no-op.
    #[test]
    fn save_popup_left_at_zero_is_noop() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(2));
        app.set_save_path("/tmp/test.pcap");
        app.handle_key(KeyCode::Home);
        app.handle_key(KeyCode::Left);
        assert_eq!(app.save_cursor(), 0);
    }

    /// Left then Right returns the cursor to its original position.
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

    /// The SDP display mode defaults to None.
    #[test]
    fn default_sdp_display_mode_is_none() {
        let app = App::new_test();
        assert_eq!(app.sdp_display_mode(), SdpDisplayMode::None);
    }

    /// The color mode defaults to Method.
    #[test]
    fn default_color_mode_is_method() {
        let app = App::new_test();
        assert_eq!(app.color_mode(), ColorMode::Method);
    }

    /// The raw-preview split defaults to on.
    #[test]
    fn default_raw_preview_is_true() {
        let app = App::new_test();
        assert!(app.raw_preview());
    }

    /// The detail split defaults to 40 percent.
    #[test]
    fn default_raw_preview_pct_is_40() {
        let app = App::new_test();
        assert_eq!(app.raw_preview_pct(), 40);
    }

    /// Syntax highlighting defaults to on.
    #[test]
    fn default_syntax_highlight_is_true() {
        let app = App::new_test();
        assert!(app.syntax_highlight());
    }

    /// The save format defaults to Pcap.
    #[test]
    fn default_save_format_is_pcap() {
        let app = App::new_test();
        assert_eq!(app.save_format(), SaveFormat::Pcap);
    }

    /// Extended flow defaults to off.
    #[test]
    fn default_extended_flow_is_false() {
        let app = App::new_test();
        assert!(!app.extended_flow());
    }

    /// RTP-in-flow display defaults to off.
    #[test]
    fn default_show_rtp_in_flow_is_false() {
        let app = App::new_test();
        assert!(!app.show_rtp_in_flow());
    }

    /// No diff anchor is set by default.
    #[test]
    fn default_diff_selected_is_none() {
        let app = App::new_test();
        assert_eq!(app.diff_selected_msg(), None);
    }

    /// Capture starts unpaused.
    #[test]
    fn default_paused_is_false() {
        let app = App::new_test();
        assert!(!app.paused());
    }

    // ── Step 2 & 3: F4 extended flow and F8 settings popup ──────────

    /// F4 from the call list opens the call flow with extended mode already on.
    #[test]
    fn f4_opens_extended_call_flow() {
        let mut app = app_with_three_dialogs();
        app.handle_key(KeyCode::F(4));
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        assert!(app.extended_flow());
    }

    /// F8 opens the settings popup.
    #[test]
    fn f8_opens_settings_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert!(app.active_popup().is_some());
    }

    /// Esc closes the settings popup.
    #[test]
    fn settings_popup_esc_closes() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::F(8));
        assert!(app.active_popup().is_some());
        app.handle_key(KeyCode::Esc);
        assert!(app.active_popup().is_none());
    }

    /// Enter on settings item 0 cycles the color mode.
    #[test]
    fn settings_popup_enter_toggles_color_mode() {
        let mut app = App::new_test();
        let initial = app.color_mode();
        app.handle_key(KeyCode::F(8));
        app.handle_key(KeyCode::Enter); // Toggle item 0 = color mode
        assert_ne!(app.color_mode(), initial);
    }

    /// Down then Enter toggles the second settings item (timestamp mode).
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

    /// `m` sets the mark at the selected message and reports "Mark set".
    #[test]
    fn call_flow_m_sets_mark() {
        let mut app = app_with_call_flow_open();
        assert_eq!(app.mark_index(), None);
        app.handle_key(KeyCode::Char('m'));
        assert_eq!(app.mark_index(), Some(0));
        assert_eq!(app.status_error(), Some("Mark set"));
    }

    /// `M` clears the mark and reports "Mark cleared".
    #[test]
    fn call_flow_m_uppercase_clears_mark() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Char('m')); // set mark
        assert_eq!(app.mark_index(), Some(0));
        app.handle_key(KeyCode::Char('M')); // clear mark
        assert_eq!(app.mark_index(), None);
        assert_eq!(app.status_error(), Some("Mark cleared"));
    }

    /// The mark is placed at the message selected when `m` is pressed (index 1 after Down).
    #[test]
    fn call_flow_mark_follows_selected() {
        let mut app = app_with_call_flow_open();
        app.handle_key(KeyCode::Down); // select msg 1
        app.handle_key(KeyCode::Char('m')); // mark at msg 1
        assert_eq!(app.mark_index(), Some(1));
    }

    // ── Fold expand toggle (Feature 3) ──────────────────────────────

    /// `e` expands and re-collapses the fold at the selected index.
    #[test]
    fn call_flow_e_toggles_fold_expand() {
        let mut app = app_with_call_flow_open();
        assert!(app.fold_expanded().is_empty());
        app.handle_key(KeyCode::Char('e')); // expand fold at index 0
        assert!(app.fold_expanded().contains(&0));
        app.handle_key(KeyCode::Char('e')); // collapse fold at index 0
        assert!(!app.fold_expanded().contains(&0));
    }

    /// Folds expanded at two different indices are tracked independently.
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

    /// `O` opens the file-open dialog.
    #[test]
    fn file_open_o_opens_popup() {
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        assert_eq!(app.active_popup(), Some(&Popup::FileOpenDialog));
    }

    /// Esc closes the file-open dialog.
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

    /// Typed characters append to the manual path and advance the cursor.
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

    /// Backspace removes the last typed path character.
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

    /// Left/Right move the path cursor without editing the text.
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

    /// Home and End jump the path cursor to the start and end.
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

    /// Enter on an empty path closes the dialog with an error status.
    #[test]
    fn file_open_enter_empty_path_closes() {
        let mut app = App::new_test();
        open_manual_file_dialog(&mut app);
        app.handle_key(KeyCode::Enter);
        // Should close popup with error message
        assert!(app.active_popup().is_none());
        assert!(app.status_error().is_some());
    }

    /// Enter on a nonexistent path closes the dialog and reports not-found/failure.
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

    /// Entering a real pcap path loads dialogs from it (silently skipped when the sample is absent).
    #[test]
    fn file_open_enter_valid_pcap_loads() {
        // Use one of the test pcap files (path relative to CARGO_MANIFEST_DIR)
        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/sip-rtp-g711.pcap"
        );
        // The fixture is committed; a missing one is a broken checkout, not a
        // reason to pass silently. Fail loudly instead of skipping.
        assert!(
            std::path::Path::new(pcap_path).exists(),
            "missing committed test fixture: {pcap_path}"
        );

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

    /// An RTP-only pcap yields 0 dialogs, populates streams, and auto-switches to the stream list.
    #[test]
    fn file_open_rtp_only_pcap_populates_streams_and_switches_view() {
        // RTP-only pcap (no SIP) — exercises the RTP ingestion path in
        // `load_pcap_file` and the auto-switch to the stream list.
        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/speech_8k_ulaw.pcap"
        );
        assert!(
            std::path::Path::new(pcap_path).exists(),
            "missing committed test fixture: {pcap_path}"
        );

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

    /// Opening a pcap replaces the existing dialogs and reports a "Loaded" status.
    #[test]
    fn file_open_clears_existing_data() {
        let mut app = app_with_three_dialogs();
        assert_eq!(app.visible_dialog_count(), 3);

        let pcap_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pcap-samples/sip-sdp-example.pcap"
        );
        assert!(
            std::path::Path::new(pcap_path).exists(),
            "missing committed test fixture: {pcap_path}"
        );

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
        // Assert, do not skip. `if !is_dir { return }` made this test report
        // green on a checkout without the fixtures while asserting nothing --
        // the same silent-skip the three sibling tests in this file were
        // already fixed for. A missing fixture is a broken checkout, and it
        // should say so rather than manufacture a pass.
        assert!(
            samples.is_dir(),
            "fixture directory missing: {} -- this test cannot run without it, \
             and passing without running it is worse than failing",
            samples.display()
        );

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

    /// Each of the 11 save formats reports its expected UI label.
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

    /// Each save format maps to its expected file extension.
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

    /// Each save format reports its expected category grouping.
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

    /// After marking message 0 and moving to 1, mark and selection point at different messages.
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

    /// No folds are expanded when the call flow opens.
    #[test]
    fn call_flow_fold_starts_empty() {
        let app = app_with_call_flow_open();
        assert!(
            app.fold_expanded().is_empty(),
            "fold_expanded should start empty"
        );
    }

    /// Toggling the same fold twice returns the expanded set to empty.
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

    /// With no selection, `prepare_messages` marks every row `Normal`; with a
    /// selection it marks the chosen row `Selected` and same-leg peers
    /// `Related`.
    ///
    /// This drives the real production selection-assignment predicate
    /// (`prepare_messages` → `style`) rather than asserting `Normal == Normal`,
    /// which was a tautology that could never fail. It falls back to `Normal`
    /// as the default state, so a broken default (or broken Selected/Related
    /// assignment) now fails here.
    #[test]
    fn default_selection_state_is_normal() {
        use sipnab::tui::call_flow::prepare::prepare_messages;
        use sipnab::tui::call_flow::{FlowDisplayOptions, SelectionState};
        use sipnab::tui::{ColorMode, SdpDisplayMode, Theme, TimestampMode};
        use std::collections::HashSet;

        let t0 = base_ts();
        // A two-message dialog on one leg: INVITE A->B, then 200 OK B->A.
        let messages = vec![
            make_invite("sel-state@test", "1001", "1002", t0),
            make_response(
                "sel-state@test",
                200,
                "OK",
                "INVITE",
                t0 + TimeDelta::seconds(1),
            ),
        ];
        let theme = Theme::default();
        let resolver = sipnab::names::NameResolver::new();
        let fold_expanded = HashSet::new();
        let opts = |selected_msg| FlowDisplayOptions {
            sdp_mode: SdpDisplayMode::None,
            ts_mode: TimestampMode::DeltaPrev,
            color_mode: ColorMode::Method,
            show_rtp: false,
            selected_msg,
            theme: &theme,
            resolver: &resolver,
            name_mode: sipnab::names::NameMode::Off,
            rtp_segments: &[],
        };

        // No selection ⇒ default state is Normal for every rendered row.
        let (_p, unselected) = prepare_messages(&messages, t0, None, &opts(None), &fold_expanded);
        assert!(
            unselected
                .iter()
                .filter(|m| !m.is_spacer)
                .all(|m| m.selection_state == SelectionState::Normal),
            "with no selection every row must default to Normal"
        );

        // Select the first row ⇒ it becomes Selected, its same-leg peer Related.
        let (_p, selected) = prepare_messages(&messages, t0, None, &opts(Some(0)), &fold_expanded);
        let states: Vec<SelectionState> = selected
            .iter()
            .filter(|m| !m.is_spacer)
            .map(|m| m.selection_state)
            .collect();
        assert_eq!(
            states[0],
            SelectionState::Selected,
            "the selected row must be marked Selected"
        );
        assert_eq!(
            states[1],
            SelectionState::Related,
            "the same-leg peer must be marked Related, not Normal"
        );
    }

    // ── Mermaid export key (E) ───────────────────────────────────────

    /// `E` exports a Mermaid sequence diagram and reports a clipboard/Mermaid status message.
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
        // The status may be the synchronous "Copying … to clipboard…" or,
        // if the detached clipboard worker has already reported back through
        // the async drain, its outcome ("Copied N bytes (OSC 52)" /
        // "Clipboard error: …"). Both are valid export statuses; accept any
        // so the assertion isn't racing the worker (llvm-cov timing exposed
        // this).
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("clipboard")
                || lower.contains("mermaid")
                || lower.contains("osc 52")
                || lower.contains("copied"),
            "Expected a clipboard/Mermaid export status: {msg}"
        );
    }

    // ── New save format file save tests ──────────────────────────────

    /// Saving as JSON writes a file containing `call_id` fields (in a tempdir).
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

    /// Saving as NDJSON writes a file containing `call_id` fields (in a tempdir).
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

    /// Saving as CSV writes a file whose content includes a `call_id` header (in a tempdir).
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

    /// Saving as HTML writes a file with html/mermaid content (in a tempdir).
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

    /// Saving as Markdown writes a file with a heading or Call reference (in a tempdir).
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

    /// WAV export with no RTP streams reports a "No RTP streams" error instead of writing a file.
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

    /// Saving as SIPp XML writes a scenario file (in a tempdir).
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

    /// RTP-JSON export with no streams reports a no-streams message instead of writing a file.
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

    /// TXT export contains per-message headers, separators, and raw SIP text.
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

    /// CSV export's first line carries `call_id` and `method` columns, followed by data rows.
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

    /// Markdown export has summary/dialog headings and table pipes.
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

    /// SIPp export from the call flow contains scenario open/close tags and send/recv elements.
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

    /// `prepare_messages` with 3 distinct endpoints yields 3 participants and messages spanning all 3 columns.
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
            rtp_segments: &[],
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

    /// The settings popup cycles the timestamp mode through all four values, including Scaled.
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

    /// Assemble raw SIP bytes like `build_sip`, then append `body` after the
    /// blank separator line.
    ///
    /// # Returns
    /// The complete wire-format message bytes.
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

    /// Parse an INVITE carrying a PCMU SDP offer (audio port 20000).
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_a(),
            endpoint_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap()
    }

    /// Parse a `100 Trying` provisional response for the given Call-ID.
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_b(),
            endpoint_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap()
    }

    /// Parse a `180 Ringing` provisional response (with a To tag).
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_b(),
            endpoint_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap()
    }

    /// Parse a `200 OK` carrying a PCMU SDP answer (audio port 30000).
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_b(),
            endpoint_a(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap()
    }

    /// Parse the ACK that completes the INVITE transaction.
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_a(),
            endpoint_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .unwrap()
    }

    /// Build a full INVITE dialog: INVITE(SDP) -> 100 -> 180 -> 200 OK(SDP) -> ACK
    ///
    /// # Returns
    /// The five parsed messages in capture order, timestamped from `base_ts`.
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

    /// Build an `App` whose stream store holds one PCMU stream, fed from five
    /// synthetic RTP packets (10.0.0.1:20000 -> 10.0.0.2:30000, given `ssrc`).
    ///
    /// Shared by the stream-detail navigation tests below, which previously
    /// copy-pasted this 40-line feed block and only differed in the SSRC.
    fn app_with_one_rtp_stream(ssrc: u32) -> App {
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
            for i in 0u16..5 {
                let mut payload = Vec::with_capacity(172);
                payload.push(0x80);
                payload.push(0x00); // PT=0 (PCMU)
                payload.extend_from_slice(&(100 + i).to_be_bytes());
                payload.extend_from_slice(&((i as u32) * 160).to_be_bytes());
                payload.extend_from_slice(&ssrc.to_be_bytes());
                payload.extend_from_slice(&[0x7F; 160]);

                let parsed = ParsedPacket {
                    frame: None,
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
                    from_hep: false,
                };
                let rtp = parse_rtp_header(&parsed.payload).unwrap();
                store.process_rtp(&parsed, &rtp, parsed.timestamp);
            }
        }

        sipnab::tui::App::new(
            ds,
            ss,
            sipnab::tui::Theme::default(),
            sipnab::tui::Keymap::default(),
        )
    }

    // ── Test 1: stream_detail_enter_from_stream_list ─────────────────

    /// Enter on a populated stream list opens the `StreamDetail` view.
    #[test]
    fn stream_detail_enter_from_stream_list() {
        let mut app = app_with_one_rtp_stream(0xDEADBEEF);

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

    /// Esc from stream detail returns to the stream list.
    #[test]
    fn stream_detail_escape_returns_to_stream_list() {
        let mut app = app_with_one_rtp_stream(0xCAFEBABE);

        // Navigate to StreamList, then Enter to open StreamDetail
        app.handle_key(KeyCode::Tab);
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::StreamDetail(_)));

        // Escape should return to StreamList
        app.handle_key(KeyCode::Esc);
        assert_eq!(*app.current_view(), View::StreamList);
    }

    // ── Test 3: stream_detail_scroll_j_k ─────────────────────────────

    /// `j`/`k` scroll the stream detail down and up, clamping at 0.
    #[test]
    fn stream_detail_scroll_j_k() {
        let mut app = app_with_one_rtp_stream(0x11223344);

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

    /// The RTP bar is a separate ladder entry placed after the ACK (and 200 OK), not attached to the 200 OK.
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
            rtp_segments: &[],
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

    /// The RTP bar label carries "RTP" plus the PCMU codec, no redundant "active", and a populated timestamp.
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
            rtp_segments: &[],
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

        // The codec alone marks the channel as in-flow — no redundant "active".
        assert!(
            !bar_text.contains("active"),
            "RTP bar label should no longer carry the redundant 'active', got: {bar_text}"
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
    ///
    /// # Returns
    /// The parsed `SipMessage`; panics if parsing fails.
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
            endpoint_a(),
            endpoint_b(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .expect("parse INVITE with User-Agent")
    }

    /// Build an `App` with one completed dialog whose INVITE carries a
    /// FreeSWITCH User-Agent header, for body-search tests.
    ///
    /// # Returns
    /// The `App` with both messages processed.
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

    /// The full-text search predicate matches "freeswitch", which exists only in the raw message bytes.
    #[test]
    fn body_search_finds_sip_header_in_body() {
        // "FreeSWITCH" appears only in the User-Agent header of the raw
        // message bytes — it is not a structured field (method, from, to,
        // state, call_id, src/dst).  Body search should still match.
        let app = app_with_user_agent_dialog();
        let store = app.dialog_store_ref().read();
        // Drive the production search predicate directly so the test can't
        // drift from what the call list actually filters on.
        let q = "freeswitch".to_ascii_lowercase();
        let matches: Vec<_> = store
            .iter()
            .filter(|d| sipnab::tui::call_list::dialog_matches_search(d, &q))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "Body search for 'freeswitch' should match exactly one dialog"
        );
    }

    /// The same predicate matches nothing for a string absent from every field and body.
    #[test]
    fn body_search_no_match_excludes_dialog() {
        let app = app_with_user_agent_dialog();
        let store = app.dialog_store_ref().read();
        let q = "nonexistent-xyz-string".to_ascii_lowercase();
        let matches: Vec<_> = store
            .iter()
            .filter(|d| sipnab::tui::call_list::dialog_matches_search(d, &q))
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

    /// `apply_visible_columns` shows exactly the named columns and hides all others.
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

    /// Column names in the config list match case-insensitively.
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

    /// Applying an empty column list leaves all columns visible.
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

    // ── Call flow ←/→: a press is never both inert and mute ───────────
    //
    // ←/→ carry two meanings in the call flow (resize the split; h-scroll
    // the focused unwrapped detail pane), and each has a state in which it
    // legitimately cannot move anything. #184 fixed the resize side. The
    // h-scroll side survived it because the clamp that erases the movement
    // runs in the RENDER pass: the controller set an offset, the render
    // pinned it back, and nothing said so — so with no line wider than the
    // pane, both arrows were dead and silent indefinitely (#188).
    //
    // #184's post-mortem is the reason these assert on the drawn frame and
    // the status line rather than on `detail_hscroll`: every test that
    // existed before it asserted the state field the controller wrote, all
    // of them passed, and the operator still saw nothing happen.

    /// A call flow whose selected message has one header far wider than any
    /// pane these tests render into, so h-scrolling has somewhere to go.
    ///
    /// # Arguments
    /// * `call_id` - Call-ID for the dialog.
    /// * `ts` - Capture timestamp.
    ///
    /// # Returns
    /// The parsed INVITE; panics if parsing fails.
    fn make_wide_invite(call_id: &str, ts: DateTime<Utc>) -> SipMessage {
        // A single long token: no whitespace, so nothing can shorten the
        // widest line except horizontal scrolling.
        let long_value = "x".repeat(400);
        let raw = build_sip(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                "From: \"1001\" <sip:1001@example.com>;tag=t1",
                "To: \"1002\" <sip:1002@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                &format!("User-Agent: {long_value}"),
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
        .expect("parse wide INVITE")
    }

    /// The drawn main pane: everything between the three status lines at the
    /// top and the F-key bar at the bottom. This is the region an operator
    /// watches for movement, and excluding the status line is deliberate —
    /// a new status message must not be able to masquerade as movement.
    ///
    /// # Arguments
    /// * `term` - Terminal holding the frame to read.
    ///
    /// # Returns
    /// One string per main-area row, joined with newlines.
    fn main_pane_text(term: &ratatui::Terminal<ratatui::backend::TestBackend>) -> String {
        let buf = term.backend().buffer();
        let area = *buf.area();
        (3..area.height.saturating_sub(1))
            .map(|y| {
                (0..area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Open the call flow of `messages` in a wide terminal and put the view
    /// into the requested arrow-key mode, drawing a frame afterwards so the
    /// render pass has measured the detail pane exactly as the event loop
    /// would before the operator's next key.
    ///
    /// # Arguments
    /// * `messages` - Messages to preload.
    /// * `focus_detail` - Press Tab, moving focus to the detail pane.
    /// * `unwrap_detail` - Press `w`, turning detail wrapping off.
    ///
    /// # Returns
    /// The app on the call-flow view and the 200x24 terminal it drew into.
    fn call_flow_in_arrow_mode(
        messages: Vec<SipMessage>,
        focus_detail: bool,
        unwrap_detail: bool,
    ) -> (App, ratatui::Terminal<ratatui::backend::TestBackend>) {
        let mut app = App::with_processed_messages(messages);
        let mut term = ratatui::Terminal::new(ratatui::backend::TestBackend::new(200, 24)).unwrap();
        app.handle_key(KeyCode::Enter);
        assert!(matches!(app.current_view(), View::CallFlow(_)));
        draw(&mut app, &mut term);
        if focus_detail {
            app.handle_key(KeyCode::Tab);
        }
        if unwrap_detail {
            app.handle_key(KeyCode::Char('w'));
        }
        draw(&mut app, &mut term);
        (app, term)
    }

    /// With the detail pane focused, wrapping off and no line wider than the
    /// pane, → moves nothing on screen and the status line names both the
    /// reason and the way out (instead of the indefinite silence of #188).
    #[test]
    fn a_clamped_horizontal_scroll_names_the_reason_instead_of_doing_nothing_silently() {
        let t0 = base_ts();
        // The fixture INVITE's widest header is ~40 columns; the detail pane
        // of a 200-column terminal is far wider, so nothing overflows.
        let (mut app, mut term) = call_flow_in_arrow_mode(
            vec![
                make_invite("fits@test", "1001", "1002", t0),
                make_response("fits@test", 200, "OK", "INVITE", t0 + TimeDelta::seconds(1)),
            ],
            true,
            true,
        );

        let before = main_pane_text(&term);
        app.handle_key(KeyCode::Right);
        draw(&mut app, &mut term);

        assert_eq!(
            main_pane_text(&term),
            before,
            "a message narrower than the pane cannot scroll: the drawn frame must be identical"
        );
        let status = app.status_error().unwrap_or_default();
        assert!(
            status.contains("fits the pane") && status.contains("nothing to scroll"),
            "→ moved nothing, so the status line must name the reason; got {status:?}"
        );
        assert!(
            status.contains("w to") && status.contains("Tab"),
            "the reason must come with the way out (w re-wraps, Tab returns to the ladder); got {status:?}"
        );

        // ← is the same press in the other direction and must not be silent
        // either — the original report could not name its conditions
        // precisely because BOTH arrows were dead.
        let before = main_pane_text(&term);
        app.handle_key(KeyCode::Left);
        draw(&mut app, &mut term);
        assert_eq!(main_pane_text(&term), before, "← cannot move it either");
        let status = app.status_error().unwrap_or_default();
        assert!(
            status.contains("fits the pane"),
            "← must name the same reason; got {status:?}"
        );
    }

    /// Every ←/→ press in the call flow either moves the drawn frame or
    /// leaves a fresh status message: the property applies to both arrows in
    /// all four combinations of pane focus and wrap mode, not just to the
    /// branch #188 was reported against.
    #[test]
    fn every_call_flow_arrow_press_either_moves_the_frame_or_says_why_it_could_not() {
        let t0 = base_ts();
        for focus_detail in [false, true] {
            for unwrap_detail in [false, true] {
                for arrow in [KeyCode::Left, KeyCode::Right] {
                    let (mut app, mut term) = call_flow_in_arrow_mode(
                        vec![
                            make_invite("fits@test", "1001", "1002", t0),
                            make_response(
                                "fits@test",
                                200,
                                "OK",
                                "INVITE",
                                t0 + TimeDelta::seconds(1),
                            ),
                        ],
                        focus_detail,
                        unwrap_detail,
                    );
                    // Park an unrelated message on the status line first.
                    // Without it a leftover "Detail wrap: OFF …" from the `w`
                    // press would stand in for a press that said nothing —
                    // the false green this gate exists to avoid.
                    app.handle_key(KeyCode::Char('m'));
                    assert_eq!(app.status_error(), Some("Mark set"));
                    draw(&mut app, &mut term);

                    let before = main_pane_text(&term);
                    app.handle_key(arrow);
                    draw(&mut app, &mut term);

                    let moved = main_pane_text(&term) != before;
                    let spoke = app.status_error().is_some_and(|s| s != "Mark set");
                    assert!(
                        moved || spoke,
                        "{arrow:?} with focus_detail={focus_detail} unwrap_detail={unwrap_detail} \
                         moved nothing and said nothing; status was {:?}",
                        app.status_error()
                    );
                }
            }
        }
    }

    /// The reason-naming must not be bought by disabling the feature: with a
    /// header wider than the pane, → still visibly scrolls the detail pane
    /// and reports the column it landed on.
    #[test]
    fn a_line_wider_than_the_pane_still_scrolls_and_reports_its_column() {
        let t0 = base_ts();
        let (mut app, mut term) = call_flow_in_arrow_mode(
            vec![
                make_wide_invite("wide@test", t0),
                make_response("wide@test", 200, "OK", "INVITE", t0 + TimeDelta::seconds(1)),
            ],
            true,
            true,
        );

        let before = main_pane_text(&term);
        app.handle_key(KeyCode::Right);
        draw(&mut app, &mut term);

        assert_ne!(
            main_pane_text(&term),
            before,
            "a 400-column header overflows the pane: → must visibly scroll it"
        );
        let status = app.status_error().unwrap_or_default();
        assert!(
            status.starts_with("Detail column "),
            "a press that moved must report where it landed; got {status:?}"
        );
        assert!(
            !status.contains("fits the pane"),
            "an overflowing message must never be reported as fitting; got {status:?}"
        );
    }

    /// The headroom the arrows consult is measured even while wrapping is
    /// on, so the very first → after `w` is answered from the pane the
    /// operator is actually looking at — a burst of `w` then → arrives in
    /// one event drain, with no frame in between.
    #[test]
    fn the_first_arrow_after_the_wrap_toggle_is_answered_from_the_wrapped_frame() {
        let t0 = base_ts();
        // Focused, wrapping still ON: the frame drawn here is the only one
        // the controller can consult for the presses below.
        let (mut app, mut term) = call_flow_in_arrow_mode(
            vec![
                make_wide_invite("wide@test", t0),
                make_response("wide@test", 200, "OK", "INVITE", t0 + TimeDelta::seconds(1)),
            ],
            true,
            false,
        );

        // `w` and → in one drain, exactly as a fast operator produces them.
        app.handle_key(KeyCode::Char('w'));
        app.handle_key(KeyCode::Right);
        let status = app.status_error().unwrap_or_default();
        assert!(
            !status.contains("fits the pane"),
            "the wrapped frame measured a 400-column header: → must not claim it fits; got {status:?}"
        );

        let before = main_pane_text(&term);
        draw(&mut app, &mut term);
        assert_ne!(
            main_pane_text(&term),
            before,
            "that first press must land as a real scroll, not be clamped away"
        );
    }
}
