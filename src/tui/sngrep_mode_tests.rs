// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! sngrep mode as the whole session sees it: the App built the way
//! `run_tui_mode` builds it, keys pressed through the real dispatcher and
//! frames drawn into a test terminal. The unit tests of the key map, the
//! colors and the layout arithmetic are in `sngrep_mode.rs`.
//!
//! Each test's doc comment starts with its class for the feature's test
//! count: Success (the mode does what it should), Failure (an input the mode
//! refuses or ignores) or Edge (a boundary or a combination).

use super::controllers::test_support::{base_ts, make_invite, make_ok};
use super::{
    App, DisplayPrefs, Keymap, SdpDisplayMode, Theme, TuiOptions, View, enable_sngrep_mode,
    sngrep_mode,
};
use crate::config::{DisplayConfig, ThemeConfig};
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use chrono::TimeDelta;
use crossterm::event::KeyCode;
use parking_lot::RwLock;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style};
use std::sync::Arc;

type TestError = Box<dyn std::error::Error>;

/// Two answered calls, as `run_tui_mode` builds the session: the theme from
/// the config (NO_COLOR when `no_color`), then sngrep mode when `sngrep`.
fn app(no_color: bool, sngrep: bool) -> Result<App, TestError> {
    let t0 = base_ts();
    let ds = Arc::new(RwLock::new(DialogStore::new(100, false)));
    let ss = Arc::new(RwLock::new(StreamStore::new(100)));
    {
        let mut store = ds.write();
        store.process_message(make_invite("sg-1@test", "1001", "1002", t0)?);
        store.process_message(make_ok("sg-1@test", t0 + TimeDelta::seconds(1))?);
        store.process_message(make_invite(
            "sg-2@test",
            "1003",
            "1004",
            t0 + TimeDelta::seconds(5),
        )?);
    }
    let mut theme = Theme::from_config_with_no_color(&ThemeConfig::default(), no_color);
    if sngrep {
        enable_sngrep_mode(&mut theme);
    }
    let mut app = App::new(ds, ss, theme, Keymap::default());
    app.version = "0.0.0-test".to_string();
    Ok(app)
}

/// Draw one frame of `app` at `w` x `h` and return the buffer.
fn draw(app: &mut App, w: u16, h: u16) -> Result<Buffer, TestError> {
    let mut terminal = Terminal::new(TestBackend::new(w, h))?;
    terminal.draw(|f| app.render(f))?;
    Ok(terminal.backend().buffer().clone())
}

/// The buffer's text, one line per row.
fn text(buf: &Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// One row of the buffer as text.
fn row(buf: &Buffer, y: u16) -> String {
    (0..buf.area.width).map(|x| buf[(x, y)].symbol()).collect()
}

/// Every cell that carries a foreground or background color, as
/// `(x, y, fg, bg)`.
fn colored_cells(buf: &Buffer) -> Vec<(u16, u16, Color, Color)> {
    let mut out = Vec::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let c = &buf[(x, y)];
            if c.fg != Color::Reset || c.bg != Color::Reset {
                out.push((x, y, c.fg, c.bg));
            }
        }
    }
    out
}

/// The cells of row `y` that are in reverse video.
fn reversed_in_row(buf: &Buffer, y: u16) -> usize {
    (0..buf.area.width)
        .filter(|&x| buf[(x, y)].modifier.contains(Modifier::REVERSED))
        .count()
}

/// The row of the buffer whose text contains `needle`.
fn row_of(buf: &Buffer, needle: &str) -> Option<u16> {
    (0..buf.area.height).find(|&y| row(buf, y).contains(needle))
}

/// Open the first call's flow from the call list.
fn open_flow(app: &mut App) -> Result<(), TestError> {
    app.handle_key(KeyCode::Enter);
    if !matches!(app.current_view, View::CallFlow(_)) {
        return Err(format!("Enter opened {:?}, not a call flow", app.current_view).into());
    }
    Ok(())
}

// ── C1: NO_COLOR keeps the mode, drops only the colors ───────────────

/// Success: under NO_COLOR, sngrep mode is still on for the views: the
/// theme the views read says so.
#[test]
fn no_color_keeps_sngrep_mode_on_for_the_views() -> Result<(), TestError> {
    let app = app(true, true)?;
    assert!(
        app.theme.sngrep,
        "NO_COLOR must not turn sngrep mode off for the views"
    );
    assert!(app.theme.no_color, "the theme is still the NO_COLOR one");
    Ok(())
}

/// Success: under NO_COLOR the help view lists sngrep's key map, as it does
/// with colors.
#[test]
fn no_color_help_lists_the_sngrep_key_map() -> Result<(), TestError> {
    let first = sngrep_mode::HELP_TEXT
        .lines()
        .next()
        .ok_or("the sngrep help has a first line")?;
    for no_color in [false, true] {
        let mut app = app(no_color, true)?;
        app.handle_key(KeyCode::F(1));
        let shown = text(&draw(&mut app, 120, 40)?);
        assert!(
            shown.contains(first),
            "no_color={no_color}: the help must open on sngrep's key map:\n{shown}"
        );
    }
    Ok(())
}

/// Success: under NO_COLOR the call list's bottom bar is sngrep's.
#[test]
fn no_color_call_list_bar_is_sngreps() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    let buf = draw(&mut app, 160, 30)?;
    let bar = row(&buf, buf.area.height - 1);
    assert!(
        bar.contains("Space Check"),
        "the bottom bar must be sngrep's under NO_COLOR: {bar:?}"
    );
    Ok(())
}

/// Success: under NO_COLOR, `9` widens the raw pane of the call flow and
/// `0` narrows it, as with colors.
#[test]
fn no_color_nine_and_zero_move_the_raw_pane() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    let (before, cols) = app.flow.sngrep_raw_drawn;
    assert_eq!(cols, 160, "the sngrep layout drew the raw pane");
    app.handle_key(KeyCode::Char('9'));
    assert_eq!(
        app.flow.sngrep_raw_fixed,
        Some(before + 2),
        "9 widens the pane by two columns"
    );
    draw(&mut app, 160, 30)?;
    app.handle_key(KeyCode::Char('0'));
    assert_eq!(
        app.flow.sngrep_raw_fixed,
        Some(before),
        "0 narrows it back by two columns"
    );
    Ok(())
}

/// Failure: NO_COLOR refuses every sngrep color: the call list paints no
/// cell with a color.
#[test]
fn no_color_call_list_paints_no_color() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    let buf = draw(&mut app, 160, 30)?;
    let painted = colored_cells(&buf);
    assert!(
        painted.is_empty(),
        "NO_COLOR call list painted colors: {:?}",
        &painted[..painted.len().min(8)]
    );
    Ok(())
}

/// Failure: NO_COLOR refuses every sngrep color: the call flow with its raw
/// pane paints no cell with a color.
#[test]
fn no_color_call_flow_paints_no_color() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    let buf = draw(&mut app, 160, 30)?;
    let painted = colored_cells(&buf);
    assert!(
        painted.is_empty(),
        "NO_COLOR call flow painted colors: {:?}",
        &painted[..painted.len().min(8)]
    );
    Ok(())
}

/// Failure: NO_COLOR refuses sngrep's cyan for the time of a message chosen
/// to compare, the time from it to the cursor, and the delta time form.
#[test]
fn no_color_compare_mark_and_delta_time_paint_no_color() -> Result<(), TestError> {
    for no_color in [false, true] {
        let mut app = app(no_color, true)?;
        open_flow(&mut app)?;
        draw(&mut app, 160, 30)?;
        app.handle_key(KeyCode::Char(' '));
        app.handle_key(KeyCode::Down);
        let marked = draw(&mut app, 160, 30)?;
        app.handle_key(KeyCode::Char('w'));
        let delta = draw(&mut app, 160, 30)?;
        let cyan = |buf: &Buffer| {
            colored_cells(buf)
                .iter()
                .filter(|&&(x, _, fg, _)| fg == Color::Cyan && x < 60)
                .count()
        };
        if no_color {
            assert_eq!(
                cyan(&marked),
                0,
                "NO_COLOR compare mark:\n{}",
                text(&marked)
            );
            assert_eq!(cyan(&delta), 0, "NO_COLOR delta time:\n{}", text(&delta));
        } else {
            assert!(
                cyan(&marked) > 0,
                "the compare mark is cyan:\n{}",
                text(&marked)
            );
            assert!(
                cyan(&delta) > 0,
                "the delta time is cyan:\n{}",
                text(&delta)
            );
        }
    }
    Ok(())
}

/// Failure: NO_COLOR refuses sngrep's syntax colors on the raw message
/// screen.
#[test]
fn no_color_raw_message_paints_no_color() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    app.handle_key(KeyCode::Enter);
    if !matches!(app.current_view, View::RawMessage { .. }) {
        return Err(format!("Enter opened {:?}, not a raw message", app.current_view).into());
    }
    let buf = draw(&mut app, 120, 30)?;
    let painted = colored_cells(&buf);
    assert!(
        painted.is_empty(),
        "NO_COLOR raw message painted colors: {:?}",
        &painted[..painted.len().min(8)]
    );
    Ok(())
}

/// Failure: NO_COLOR refuses the help view's colors in sngrep mode.
#[test]
fn no_color_help_paints_no_color() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    app.handle_key(KeyCode::F(1));
    let buf = draw(&mut app, 120, 40)?;
    let painted = colored_cells(&buf);
    assert!(
        painted.is_empty(),
        "NO_COLOR help painted colors: {:?}",
        &painted[..painted.len().min(8)]
    );
    Ok(())
}

/// Edge: under NO_COLOR the current call-list row stays visible, in reverse
/// video, since sngrep's white-on-blue band is a color.
#[test]
fn no_color_current_call_row_is_reversed() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    let buf = draw(&mut app, 160, 30)?;
    let y = row_of(&buf, "1001").ok_or("the first call is on screen")?;
    assert!(
        reversed_in_row(&buf, y) > 10,
        "the current row must be in reverse video: {:?}",
        row(&buf, y)
    );
    Ok(())
}

/// Edge: under NO_COLOR the selected ladder message stays visible, in
/// reverse video.
#[test]
fn no_color_selected_flow_message_is_reversed() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    let buf = draw(&mut app, 160, 30)?;
    // The ladder is left of the raw pane; the first message is selected.
    let ladder_w = 160 - app.flow.sngrep_raw_drawn.0 - 2;
    let hits = (0..buf.area.height)
        .filter(|&y| row(&buf, y).contains("INVITE"))
        .flat_map(|y| (0..ladder_w).map(move |x| (x, y)))
        .filter(|&(x, y)| buf[(x, y)].modifier.contains(Modifier::REVERSED))
        .count();
    assert!(
        hits > 0,
        "the selected message must be in reverse video:\n{}",
        text(&buf)
    );
    Ok(())
}

/// Edge: with colors, sngrep mode still paints sngrep's colors (the
/// NO_COLOR fix must not drop them everywhere).
#[test]
fn with_colors_sngrep_mode_paints_its_colors() -> Result<(), TestError> {
    let mut app = app(false, true)?;
    let buf = draw(&mut app, 160, 30)?;
    let y = row_of(&buf, "1001").ok_or("the first call is on screen")?;
    let blue = (0..buf.area.width)
        .filter(|&x| buf[(x, y)].bg == Color::Blue)
        .count();
    assert!(blue > 10, "the current row is on sngrep's blue band");
    assert!(
        colored_cells(&buf)
            .iter()
            .any(|&(_, _, fg, _)| fg == Color::Red),
        "INVITE is drawn in sngrep's red"
    );
    Ok(())
}

/// Edge: NO_COLOR without sngrep mode is unchanged: sipnab's bar, no color.
#[test]
fn no_color_without_sngrep_mode_is_sipnabs() -> Result<(), TestError> {
    let mut app = app(true, false)?;
    assert!(!app.theme.sngrep, "the mode is off");
    let buf = draw(&mut app, 160, 30)?;
    let bar = row(&buf, buf.area.height - 1);
    assert!(!bar.contains("Space Check"), "sipnab's own bar: {bar:?}");
    assert!(colored_cells(&buf).is_empty(), "NO_COLOR paints no color");
    Ok(())
}

// ── C2: the ignored `sdp_display = "sngrep"` is said on screen ───────

/// A `[display]` table with `sdp_display` set to `value`.
fn display_with_sdp(value: &str) -> DisplayConfig {
    DisplayConfig {
        sdp_display: Some(value.to_string()),
        ..DisplayConfig::default()
    }
}

/// Failure: `sdp_display = "sngrep"` with the mode off is ignored, and a
/// notice says why and how to turn the mode on.
#[test]
fn sngrep_sdp_form_without_the_mode_has_a_notice() -> Result<(), TestError> {
    let notice = DisplayPrefs::ignored_notice(&display_with_sdp("sngrep"), false)
        .ok_or("the ignored key must have a notice")?;
    assert!(
        notice.contains("sdp_display") && notice.contains("--sngrep-mode"),
        "the notice names the key and the flag: {notice}"
    );
    Ok(())
}

/// Edge: in sngrep mode the same key is used, so there is no notice.
#[test]
fn sngrep_sdp_form_in_the_mode_has_no_notice() -> Result<(), TestError> {
    assert_eq!(
        DisplayPrefs::ignored_notice(&display_with_sdp("sngrep"), true),
        None,
        "the key is honored in sngrep mode"
    );
    Ok(())
}

/// Edge: the three sipnab forms, and no key at all, have no notice in
/// either mode.
#[test]
fn sipnab_sdp_forms_have_no_notice() -> Result<(), TestError> {
    for value in ["none", "summary", "full"] {
        for sngrep in [false, true] {
            assert_eq!(
                DisplayPrefs::ignored_notice(&display_with_sdp(value), sngrep),
                None,
                "sdp_display = {value:?}, sngrep={sngrep}"
            );
        }
    }
    assert_eq!(
        DisplayPrefs::ignored_notice(&DisplayConfig::default(), false),
        None,
        "no key, no notice"
    );
    Ok(())
}

/// Success: the notice reaches the status line when the session opens.
#[test]
fn the_ignored_key_notice_is_on_the_status_line() -> Result<(), TestError> {
    let notice = DisplayPrefs::ignored_notice(&display_with_sdp("sngrep"), false)
        .ok_or("the ignored key must have a notice")?;
    let app = TuiOptions {
        startup_notice: Some(notice.clone()),
        ..TuiOptions::default()
    }
    .into_app(
        Arc::new(RwLock::new(DialogStore::new(10, false))),
        Arc::new(RwLock::new(StreamStore::new(10))),
    );
    assert_eq!(
        app.status_error.as_deref(),
        Some(notice.as_str()),
        "the start-up notice is on the status line"
    );
    Ok(())
}

/// Success: in sngrep mode `sdp_display = "sngrep"` is honored.
#[test]
fn sngrep_sdp_form_in_the_mode_is_used() -> Result<(), TestError> {
    assert_eq!(
        DisplayPrefs::resolve(&display_with_sdp("sngrep"), true).sdp_display,
        SdpDisplayMode::Sngrep,
        "the mode uses its own SDP form"
    );
    Ok(())
}

/// Failure: with the mode off, `sdp_display = "sngrep"` falls back to the
/// default form, hidden.
#[test]
fn sngrep_sdp_form_without_the_mode_falls_back() -> Result<(), TestError> {
    assert_eq!(
        DisplayPrefs::resolve(&display_with_sdp("sngrep"), false).sdp_display,
        SdpDisplayMode::None,
        "the ignored key leaves the default"
    );
    Ok(())
}

/// Failure: the config loader refuses an SDP form no mode has, naming the
/// fourth form and when it applies.
#[test]
fn an_unknown_sdp_form_is_refused_at_load() -> Result<(), TestError> {
    for value in ["sngrp", "SNGREP", "Full", ""] {
        let err = display_with_sdp(value)
            .validate()
            .err()
            .ok_or_else(|| format!("{value:?} must be refused"))?;
        assert!(
            err.to_string()
                .contains("must be one of none, summary, full (or sngrep, in sngrep mode)"),
            "{value:?}: {err}"
        );
    }
    assert!(
        display_with_sdp("sngrep").validate().is_ok(),
        "sngrep is accepted at load in every mode"
    );
    Ok(())
}

/// Failure: `[display] sngrep_mode` takes only a boolean.
#[test]
fn a_non_boolean_sngrep_mode_is_refused() -> Result<(), TestError> {
    for text in [
        "[display]\nsngrep_mode = \"yes\"\n",
        "[display]\nsngrep_mode = 1\n",
    ] {
        assert!(
            toml::from_str::<crate::config::Config>(text).is_err(),
            "{text:?} must be refused"
        );
    }
    Ok(())
}

// ── The flag and the config key ──────────────────────────────────────

/// Parse a command line for the mode tests.
fn parse_from<const N: usize>(argv: [&str; N]) -> Result<crate::cli::Cli, TestError> {
    use clap::Parser;
    Ok(crate::cli::Cli::try_parse_from(argv)?)
}

/// A config with `[display] sngrep_mode` set to `on`.
fn config_with_mode(on: bool) -> crate::config::Config {
    let mut c = crate::config::Config::default();
    c.display.sngrep_mode = Some(on);
    c
}

/// Success: `--sngrep-mode` turns the mode on; the default is off.
#[test]
fn the_flag_turns_the_mode_on() -> Result<(), TestError> {
    let plain = crate::config::Config::default();
    assert!(
        parse_from(["sipnab", "--sngrep-mode"])?.sngrep_mode(&plain),
        "the flag"
    );
    assert!(
        !parse_from(["sipnab"])?.sngrep_mode(&plain),
        "off by default"
    );
    Ok(())
}

/// Success: `[display] sngrep_mode = true` turns the mode on without the
/// flag.
#[test]
fn the_config_key_turns_the_mode_on() -> Result<(), TestError> {
    assert!(
        parse_from(["sipnab"])?.sngrep_mode(&config_with_mode(true)),
        "the key"
    );
    assert!(
        !parse_from(["sipnab"])?.sngrep_mode(&config_with_mode(false)),
        "false"
    );
    Ok(())
}

/// Edge: `--no-sngrep-mode` wins over the config key, and of the two flags
/// the last one typed wins.
#[test]
fn the_last_flag_typed_wins() -> Result<(), TestError> {
    let on = config_with_mode(true);
    assert!(
        !parse_from(["sipnab", "--no-sngrep-mode"])?.sngrep_mode(&on),
        "--no-sngrep-mode over the key"
    );
    assert!(
        !parse_from(["sipnab", "--sngrep-mode", "--no-sngrep-mode"])?.sngrep_mode(&on),
        "the later --no-sngrep-mode wins"
    );
    assert!(
        parse_from(["sipnab", "--no-sngrep-mode", "--sngrep-mode"])?
            .sngrep_mode(&crate::config::Config::default()),
        "the later --sngrep-mode wins"
    );
    Ok(())
}

// ── The mode's screens ───────────────────────────────────────────────

/// Success: the walkthrough's check: the call list's bar starts with these
/// four commands, with colors and without.
#[test]
fn the_call_list_bar_reads_as_the_walkthrough_says() -> Result<(), TestError> {
    for no_color in [false, true] {
        let mut app = app(no_color, true)?;
        let buf = draw(&mut app, 160, 30)?;
        let bar = row(&buf, buf.area.height - 1);
        assert!(
            bar.starts_with("Esc Quit  F1 Help  Enter Open call  Space Check"),
            "no_color={no_color}: {bar:?}"
        );
    }
    Ok(())
}

/// Success: under NO_COLOR the call flow's bar is sngrep's.
#[test]
fn no_color_call_flow_bar_is_sngreps() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    let buf = draw(&mut app, 160, 30)?;
    let bar = row(&buf, buf.area.height - 1);
    assert!(
        bar.contains("Raw call") && bar.contains("9 Raw wider"),
        "the flow bar must be sngrep's under NO_COLOR: {bar:?}"
    );
    Ok(())
}

/// Success: under NO_COLOR the raw message screen's bar is sngrep's.
#[test]
fn no_color_raw_message_bar_is_sngreps() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    app.handle_key(KeyCode::Enter);
    let buf = draw(&mut app, 120, 30)?;
    let bar = row(&buf, buf.area.height - 1);
    assert!(
        bar.contains("C Syntax"),
        "the raw bar must be sngrep's under NO_COLOR: {bar:?}"
    );
    Ok(())
}

/// Success: under NO_COLOR the mode opens with its own defaults:
/// autoscroll off and sngrep's SDP form.
#[test]
fn no_color_mode_opens_with_its_defaults() -> Result<(), TestError> {
    let app = app(true, true)?;
    assert!(!app.call_list.autoscroll, "autoscroll starts off");
    assert_eq!(
        app.sdp_display_mode,
        SdpDisplayMode::Sngrep,
        "the SDP form starts as sngrep's"
    );
    Ok(())
}

/// Success: under NO_COLOR a sngrep key reaches its command: `i` on the
/// call list opens the statistics.
#[test]
fn no_color_sngrep_key_reaches_its_command() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    app.handle_key(KeyCode::Char('i'));
    assert_eq!(
        app.current_view,
        View::Statistics,
        "i is sngrep's statistics"
    );
    Ok(())
}

/// Success: `K` under NO_COLOR shows the letters on the bottom bar.
#[test]
fn no_color_k_shows_the_letters() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    app.handle_key(KeyCode::Char('K'));
    let buf = draw(&mut app, 160, 30)?;
    let bar = row(&buf, buf.area.height - 1);
    assert!(bar.starts_with("q Quit  h Help"), "letters: {bar:?}");
    Ok(())
}

/// Success: with colors the raw pane is drawn after sngrep's blue line, so
/// `tone` passes colors through when NO_COLOR is not set.
#[test]
fn with_colors_the_raw_pane_has_its_blue_line() -> Result<(), TestError> {
    let mut app = app(false, true)?;
    open_flow(&mut app)?;
    let buf = draw(&mut app, 160, 30)?;
    assert!(
        colored_cells(&buf)
            .iter()
            .any(|&(_, _, fg, _)| fg == Color::Blue),
        "the raw pane's line is blue"
    );
    Ok(())
}

/// Success: `T` puts the raw pane back to the width the ladder leaves.
#[test]
fn t_resets_the_raw_pane() -> Result<(), TestError> {
    let mut app = app(false, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    app.handle_key(KeyCode::Char('9'));
    assert!(app.flow.sngrep_raw_fixed.is_some(), "9 set a width");
    app.handle_key(KeyCode::Char('T'));
    assert_eq!(app.flow.sngrep_raw_fixed, None, "T clears it");
    assert_eq!(
        app.status_error.as_deref(),
        Some("Raw pane: default width"),
        "the status line says so"
    );
    Ok(())
}

/// Failure: `-` on the call list is refused with how to move a column.
#[test]
fn minus_on_the_call_list_points_to_the_column_selector() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    app.handle_key(KeyCode::Char('-'));
    let msg = app.status_error.clone().unwrap_or_default();
    assert!(msg.contains("F10"), "the refusal names F10: {msg:?}");
    assert_eq!(app.current_view, View::CallList, "nothing else happens");
    Ok(())
}

/// Failure: Left in the call flow is refused with the keys that size the
/// raw pane.
#[test]
fn left_in_the_flow_points_to_nine_and_zero() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    let before = app.flow.sngrep_raw_drawn;
    app.handle_key(KeyCode::Left);
    let msg = app.status_error.clone().unwrap_or_default();
    assert!(msg.contains("9 / 0"), "the refusal names 9 / 0: {msg:?}");
    assert_eq!(app.flow.sngrep_raw_drawn, before, "the pane did not move");
    Ok(())
}

/// Failure: `9` with the raw pane hidden (`t`) changes nothing.
#[test]
fn nine_with_the_raw_pane_hidden_does_nothing() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    app.handle_key(KeyCode::Char('t'));
    assert!(!app.flow.raw_preview, "t hides the raw pane");
    app.handle_key(KeyCode::Char('9'));
    assert_eq!(app.flow.sngrep_raw_fixed, None, "no width was set");
    Ok(())
}

/// Failure: out of sngrep mode `9` is not sngrep's: no raw pane width is set.
#[test]
fn nine_out_of_the_mode_is_not_sngreps() -> Result<(), TestError> {
    let mut app = app(false, false)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    app.handle_key(KeyCode::Char('9'));
    assert_eq!(app.flow.sngrep_raw_fixed, None, "sipnab's own 9");
    assert_eq!(app.flow.sngrep_raw_drawn, (0, 0), "no sngrep layout");
    Ok(())
}

/// Failure: an SDP body with no RTP media gives no sngrep title: a T.38
/// `udptl` media is not RTP.
#[test]
fn sdp_without_rtp_media_has_no_sngrep_title() -> Result<(), TestError> {
    let t38 = b"v=0\r\nc=IN IP4 192.0.2.5\r\nt=0 0\r\nm=image 4000 udptl t38\r\n";
    assert_eq!(sngrep_mode::sdp_info("INVITE", t38), None, "T.38 only");
    assert_eq!(
        sngrep_mode::sdp_info("INVITE", b"hello"),
        None,
        "not SDP at all"
    );
    assert_eq!(sngrep_mode::sdp_info("INVITE", b""), None, "an empty body");
    Ok(())
}

/// Edge: an offer with an RTP and a T.38 media lists only the RTP one.
#[test]
fn sdp_with_rtp_and_t38_lists_the_rtp_media() -> Result<(), TestError> {
    let body = b"v=0\r\nc=IN IP4 192.0.2.5\r\nt=0 0\r\n\
                 m=audio 4002 RTP/AVP 0\r\nm=image 4000 udptl t38\r\n";
    let (title, lines) =
        sngrep_mode::sdp_info("INVITE", body).ok_or("the RTP media gives a title")?;
    assert_eq!(title, "INV (192.0.2.5)", "the first RTP media's address");
    assert_eq!(lines, vec!["audio 4002 (PCMU)".to_string()], "one line");
    Ok(())
}

/// Edge: `9` stops at the widest pane the screen allows, and more presses
/// change nothing.
#[test]
fn nine_stops_at_the_widest_pane() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    for _ in 0..200 {
        app.handle_key(KeyCode::Char('9'));
    }
    let widest = app.flow.sngrep_raw_fixed.ok_or("9 set a width")?;
    assert!(widest <= 145, "the ladder keeps 15 columns: {widest}");
    app.handle_key(KeyCode::Char('9'));
    assert_eq!(app.flow.sngrep_raw_fixed, Some(widest), "no wider");
    Ok(())
}

/// Edge: `0` stops at ten columns, and more presses change nothing.
#[test]
fn zero_stops_at_ten_columns() -> Result<(), TestError> {
    let mut app = app(true, true)?;
    open_flow(&mut app)?;
    draw(&mut app, 160, 30)?;
    for _ in 0..200 {
        app.handle_key(KeyCode::Char('0'));
    }
    let narrowest = app.flow.sngrep_raw_fixed.ok_or("0 set a width")?;
    assert!(
        (10..=11).contains(&narrowest),
        "the pane keeps ten columns: {narrowest}"
    );
    app.handle_key(KeyCode::Char('0'));
    assert_eq!(app.flow.sngrep_raw_fixed, Some(narrowest), "no narrower");
    Ok(())
}

/// Edge: a very small terminal draws every sngrep screen, with and without
/// colors, without a panic.
#[test]
fn a_tiny_terminal_draws_every_sngrep_screen() -> Result<(), TestError> {
    for no_color in [false, true] {
        for (w, h) in [(10, 3), (20, 5), (1, 1)] {
            let mut app = app(no_color, true)?;
            draw(&mut app, w, h)?;
            app.handle_key(KeyCode::Enter);
            draw(&mut app, w, h)?;
            app.handle_key(KeyCode::Enter);
            draw(&mut app, w, h)?;
        }
    }
    Ok(())
}

// ── tone: the one rule for sngrep's colors ───────────────────────────

/// Edge: under NO_COLOR a background band becomes reverse video and loses
/// both colors.
#[test]
fn tone_turns_a_band_into_reverse_video() -> Result<(), TestError> {
    let mono = Theme::monochrome();
    let s = sngrep_mode::tone(&mono, Style::default().fg(Color::White).bg(Color::Blue));
    assert_eq!((s.fg, s.bg), (None, None), "no color is left");
    assert!(
        s.add_modifier.contains(Modifier::REVERSED),
        "the band is reverse video"
    );
    Ok(())
}

/// Edge: under NO_COLOR a foreground color goes and bold stays; no reverse
/// video is added where there was no band.
#[test]
fn tone_keeps_the_text_attributes() -> Result<(), TestError> {
    let mono = Theme::monochrome();
    let s = sngrep_mode::tone(
        &mono,
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    );
    assert_eq!(s.fg, None, "the color goes");
    assert!(s.add_modifier.contains(Modifier::BOLD), "bold stays");
    assert!(
        !s.add_modifier.contains(Modifier::REVERSED),
        "no band, no reverse video"
    );
    let reset_bg = sngrep_mode::tone(&mono, Style::default().bg(Color::Reset));
    assert!(
        !reset_bg.add_modifier.contains(Modifier::REVERSED),
        "a reset background is not a band"
    );
    Ok(())
}

/// Edge: with colors, `tone` and `tone_lines` change nothing.
#[test]
fn tone_with_colors_changes_nothing() -> Result<(), TestError> {
    let theme = Theme::default();
    let s = Style::default().fg(Color::White).bg(Color::Blue);
    assert_eq!(sngrep_mode::tone(&theme, s), s, "one style");
    let lines = sngrep_mode::syntax_lines("INVITE sip:a@example.com SIP/2.0\nVia: x;branch=z9\n");
    assert_eq!(
        sngrep_mode::tone_lines(&theme, lines.clone()),
        lines,
        "the syntax lines"
    );
    Ok(())
}

/// Edge: under NO_COLOR `tone_lines` leaves no color on any span and keeps
/// the text.
#[test]
fn tone_lines_strips_every_span() -> Result<(), TestError> {
    let mono = Theme::monochrome();
    let raw =
        "INVITE sip:a@example.com SIP/2.0\nVia: x;branch=z9\nFrom: <sip:b@example.com>;tag=1\n";
    let lines = sngrep_mode::tone_lines(&mono, sngrep_mode::syntax_lines(raw));
    let text: String = lines
        .iter()
        .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
        .collect();
    assert!(text.contains("branch=z9"), "the text is kept: {text}");
    for line in &lines {
        assert_eq!((line.style.fg, line.style.bg), (None, None), "line style");
        for span in &line.spans {
            assert_eq!(
                (span.style.fg, span.style.bg),
                (None, None),
                "span {:?}",
                span.content
            );
        }
    }
    Ok(())
}
