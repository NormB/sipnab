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

/// The Call-ID OpenSIPS gave the relay, `1-4062@198.51.100.21`, cut to the
/// eleven characters the stream list's Call-ID column shows. Its host part
/// was a container address until September 2026, when the fixture pair was
/// rebuilt from a generator on documentation addresses.
const CALL_ID_CELL: &str = "1-4062@198.";

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

// ── rtpproxy, whose control plane is named on the command line ──────────────

#[path = "support/pcap_build.rs"]
mod pcap_build;

const RTPPROXY_CALL: &str = "rp-tui@192.0.2.10";
/// What the Dialog column shows of it: the column truncates.
const RTPPROXY_CELL: &str = "rp-tui@192.";

/// rtpproxy's `U` command and reply, then media on the port the reply names,
/// written to `dir`. The shapes are the lab relay's (rtpproxy 3.2.0).
fn write_rtpproxy_capture(dir: &std::path::Path) -> &'static str {
    use pcap_build::{udp_frame, write_pcap_or_panic};
    let (proxy, relay, party) = ([192, 0, 2, 10], [192, 0, 2, 40], [192, 0, 2, 60]);
    let command = format!("c1 U {RTPPROXY_CALL} 192.0.2.60 40000 ftag1\n");
    let mut frames = vec![
        udp_frame(proxy, relay, 43000, 7722, command.as_bytes()),
        udp_frame(relay, proxy, 7722, 43000, b"c1 49514 192.0.2.40\n"),
    ];
    for seq in 0u16..20 {
        let mut rtp = vec![0x80, 0x00];
        rtp.extend_from_slice(&seq.to_be_bytes());
        rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
        rtp.extend_from_slice(&0x1111_2222u32.to_be_bytes());
        rtp.extend_from_slice(&[0xff; 160]);
        frames.push(udp_frame(party, relay, 40000, 49514, &rtp));
    }
    let name = "rtpproxy-relay.pcap";
    write_pcap_or_panic(&dir.join(name), &frames);
    name
}

fn open_rtpproxy_capture(control: Option<std::net::SocketAddr>) -> App {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = write_rtpproxy_capture(dir.path());
    // Through the session's startup options, the path `src/app` takes, rather
    // than a setter a test could call and production never does.
    let options = sipnab::tui::TuiOptions {
        capture_options: sipnab::pipeline::PipelineOptions {
            rtpproxy_control: control,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut app = options.into_app(
        std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::sip::dialog_store::DialogStore::new(100, false),
        )),
        std::sync::Arc::new(parking_lot::RwLock::new(
            sipnab::rtp::stream_store::StreamStore::new(100),
        )),
    );
    app.set_open_dir_for_test(dir.path().to_path_buf());
    app.handle_key(KeyCode::Char('O'));
    assert_eq!(
        app.open_entry_names_for_test(),
        vec!["..".to_string(), name.to_string()]
    );
    app.handle_key(KeyCode::Down);
    app.handle_key(KeyCode::Enter);
    app
}

/// `--rtpproxy-control` reaches a capture opened from inside the TUI, not
/// only the one named on the command line.
#[test]
fn an_rtpproxy_capture_opened_in_the_tui_is_named_from_its_control_socket() {
    let mut app = open_rtpproxy_capture(Some("192.0.2.40:7722".parse().unwrap()));
    assert_eq!(app.stream_count_for_test(), 1);
    let text = screen(&mut app);
    assert!(
        text.contains(RTPPROXY_CELL),
        "the stream is named from rtpproxy's reply:\n{text}"
    );
}

#[test]
fn without_the_control_socket_the_tui_names_nothing() {
    let mut app = open_rtpproxy_capture(None);
    assert_eq!(app.stream_count_for_test(), 1);
    let text = screen(&mut app);
    assert!(
        !text.contains(RTPPROXY_CELL),
        "nothing names the stream:\n{text}"
    );
}
