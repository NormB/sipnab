// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TUI's HEP senders view: opened with `s` from the capture-health panel,
//! it shows the roster the listener hung on the capture meter — the same table
//! `--hep-senders` prints — and `Esc` returns to capture health.
//!
//! Driven through the public `App` the way `tui_state_test` drives every other
//! view: keys in, a rendered buffer out, with the roster built on a frozen
//! clock so "silent for 40s" is a fixed fact rather than a race.
#![cfg(all(feature = "tui", feature = "hep"))]

use std::net::IpAddr;
use std::sync::Arc;

use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use sipnab::capture::hep_roster::{
    HepRefusal, HepRoster, RosterState, SenderTrust, hep_source_label,
};
use sipnab::tui::{App, View};

/// A meter carrying a roster: sender 7 live, sender 9 silent for 40 seconds,
/// and one address refused for a wrong key.
fn meter_with_roster() -> sipnab::capture::channel::CaptureMeter {
    let t = std::time::Instant::now();
    let mut state = RosterState::new(
        SenderTrust::SharedSecretPlain,
        4096,
        std::time::Duration::from_secs(30),
        t,
        chrono::Utc::now(),
    );
    let at = |s: u64| t + std::time::Duration::from_secs(s);
    for (id, peer, when) in [(9u32, "192.0.2.9", at(0)), (7, "192.0.2.7", at(38))] {
        let peer: IpAddr = peer.parse().expect("literal");
        state.admitted(Some(id), peer, &hep_source_label(Some(id), peer), when);
    }
    let bad: IpAddr = "203.0.113.66".parse().expect("literal");
    state.refused(HepRefusal::AuthMismatch, bad, at(1));
    let frozen = at(40);
    let (_tx, rx) = sipnab::capture::channel::packet_channel(8);
    let meter = rx.meter();
    assert!(meter.attach_hep_roster(HepRoster::with_clock(state, Arc::new(move || frozen))));
    meter
}

/// The visible text of the buffer, one line per row.
fn screen(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(130, 40)).expect("terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf.cell((x, y)).map_or(" ", |c| c.symbol()));
        }
        out.push('\n');
    }
    out
}

/// `h` then `s` opens the roster; it names each sender, marks the silent one,
/// lists the refused address with its reason; `Esc` goes back.
#[test]
fn the_roster_opens_from_capture_health_and_shows_every_sender() {
    let mut app = App::new_test();
    app.set_capture_meter_for_test(meter_with_roster());
    app.handle_key(KeyCode::Char('h'));
    assert!(matches!(app.current_view(), View::CaptureHealth));
    app.handle_key(KeyCode::Char('s'));
    assert!(
        matches!(app.current_view(), View::HepSenders),
        "`s` in capture health opens the HEP senders view"
    );

    let text = screen(&mut app);
    for needle in [
        "hep:7@192.0.2.7",
        "hep:9@192.0.2.9",
        "SILENT",
        "203.0.113.66",
        "auth_mismatch=1",
    ] {
        assert!(text.contains(needle), "`{needle}` missing from:\n{text}");
    }
    let silent_row = text
        .lines()
        .find(|l| l.contains("hep:9@192.0.2.9"))
        .unwrap_or_default();
    assert!(silent_row.contains("SILENT"), "{silent_row}");

    app.handle_key(KeyCode::Esc);
    assert!(
        matches!(app.current_view(), View::CaptureHealth),
        "Esc returns to the panel the roster was opened from"
    );
}

/// With no listener the view says so rather than drawing an empty roster.
#[test]
fn without_a_listener_the_view_says_so() {
    let mut app = App::new_test();
    app.handle_key(KeyCode::Char('h'));
    app.handle_key(KeyCode::Char('s'));
    assert!(matches!(app.current_view(), View::HepSenders));
    let text = screen(&mut app);
    assert!(text.contains("no HEP listener"), "{text}");
}

/// The capture-health panel itself carries the one-line summary and the key
/// that opens the rest.
#[test]
fn capture_health_names_the_listener_and_the_key_to_its_roster() {
    let mut app = App::new_test();
    app.set_capture_meter_for_test(meter_with_roster());
    app.handle_key(KeyCode::Char('h'));
    let text = screen(&mut app);
    let line = text
        .lines()
        .find(|l| l.contains("HEP senders"))
        .unwrap_or_else(|| panic!("no HEP line in capture health:\n{text}"));
    assert!(
        line.contains("2 tracked") && line.contains("1 silent") && line.contains("1 refused"),
        "{line}"
    );
    assert!(text.contains("press s"), "{text}");
}
