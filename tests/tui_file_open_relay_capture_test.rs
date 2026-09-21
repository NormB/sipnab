// SPDX-License-Identifier: MIT OR Apache-2.0

//! Opening a relay's own capture from the TUI's file browser names its streams
//! from the relay's control plane.
//!
//! `rtpengine-opensips-ng.pcap` is what a separate relay host sees: media and
//! the relay's control plane, no SIP. The only Call-ID in it is the one the
//! proxy handed the relay. `rtpengine-opensips-media-only.pcap` is the same
//! media with the control plane stripped, so the pair makes the claim
//! falsifiable: with the control plane the stream list names the call; without
//! it, nothing does.
//!
//! This lives here rather than beside the loader in
//! `src/tui/controllers/file_open.rs` because the relay-seam gate
//! (`tests/relay_seam_test.rs`) keeps vendor names out of code under
//! `src/tui/`, and these fixtures are named for the relay that produced them.

#![cfg(feature = "tui")]

use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sipnab::tui::{App, View};

/// The Call-ID OpenSIPS gave the relay, cut to the eleven characters the
/// stream list's Call-ID column shows.
const CALL_ID_CELL: &str = "1-4062@172.";

/// Open `fixture` through the file browser the way a user would — `O`, step
/// past `..`, Enter — and return the app once the background load has settled.
fn open_through_the_browser(fixture: &str) -> App {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
        dir.path().join(fixture),
    )
    .expect("copy the fixture");
    let mut app = App::new_test();
    app.set_open_dir_for_test(dir.path().to_path_buf());
    app.handle_key(KeyCode::Char('O'));
    assert_eq!(
        app.open_entry_names_for_test(),
        vec!["..".to_string(), fixture.to_string()]
    );
    app.handle_key(KeyCode::Down);
    // `handle_key` settles the background load before it returns.
    app.handle_key(KeyCode::Enter);
    app
}

/// Render one tick of the current view into a wide in-memory terminal and
/// return its text, one line per row.
fn screen(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(200, 30)).expect("terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf.cell((x, y)).expect("cell in bounds").symbol());
        }
        out.push('\n');
    }
    out
}

/// With the control plane in the capture, the load opens on the stream list
/// (there is no SIP to list calls from) and both legs carry the proxy's
/// Call-ID.
#[test]
fn a_relay_capture_opens_on_streams_named_from_its_control_plane() {
    let mut app = open_through_the_browser("rtpengine-opensips-ng.pcap");
    assert_eq!(app.current_view(), &View::StreamList);
    assert_eq!(app.stream_count_for_test(), 2);
    let text = screen(&mut app);
    assert_eq!(
        text.matches(CALL_ID_CELL).count(),
        2,
        "both legs are named from the control plane:\n{text}"
    );
}

/// The same media with its control plane stripped loads the same two streams,
/// and nothing names them.
#[test]
fn the_same_media_without_its_control_plane_names_nothing() {
    let mut app = open_through_the_browser("rtpengine-opensips-media-only.pcap");
    assert_eq!(app.current_view(), &View::StreamList);
    assert_eq!(app.stream_count_for_test(), 2);
    let text = screen(&mut app);
    assert!(
        !text.contains(CALL_ID_CELL),
        "without the control plane nothing names the streams:\n{text}"
    );
}
