// SPDX-License-Identifier: MIT OR Apache-2.0

//! The call flow's RTP display (F6) on real captures: one row per stream,
//! drawn as an arrow from the column of the stream's source address to the
//! column of its destination address (#495).
//!
//! Each expectation below was read off sngrep 1.8.0's call flow (`F3 RTP`) on
//! the same capture at 200x50, then turned into an assertion about sipnab's
//! ladder:
//!
//! - **Two-way call** (`sip_captures/voip-extension2downata.pcap`). sngrep
//!   draws two rows, `RTP (g711u) 194` one way and `RTP (g711u) 187` back,
//!   between the two signaling hosts.
//! - **One-way call** (`sip_captures/sip-phone-to-phone.pcapng`). sngrep draws
//!   one row, `RTP (g711u) 17`, from the called party to the caller, and
//!   nothing back.
//! - **Media relay on the capture host** (`issue495/rtpengine-relay.pcap`).
//!   The capture was taken on the relay host. The proxy signals on 127.0.0.1;
//!   the relay sends and receives media on 10.0.0.40, an address no SIP
//!   message uses. sngrep adds a `10.0.0.40` column and draws four
//!   `RTP (...) 250` rows: caller to relay, relay to callee, callee to relay,
//!   relay to caller.
//! - **B2BUA, two Call-IDs** (`sip_captures/test_voip.pcap.pcapng`). The B2BUA
//!   relays media for both legs. sngrep's extended flow did not join the
//!   legs, so it showed the two streams of one leg only; sipnab's extended
//!   view joins them and must draw the streams of both.
//!
//! The corpus is not committed. With `SIPNAB_CORPUS` unset every test here
//! skips, and the skip is announced once on stderr. Assertions name columns
//! by position and compare addresses only with each other, so no address
//! from a capture appears in this file, apart from the relay capture, which
//! was made on a lab host for this issue.

#![cfg(all(feature = "tui", feature = "native"))]

use std::path::PathBuf;

use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sipnab::tui::{App, View};

#[path = "support/corpus.rs"]
mod corpus_support;

type TestError = Box<dyn std::error::Error>;

/// One RTP row of the ladder, as the test API reports it.
#[derive(Debug, Clone)]
struct Row {
    /// Column the arrow starts at.
    src: usize,
    /// Column the arrowhead lands on.
    dst: usize,
    /// The row's label, for example `RTP (PCMU) 194`.
    label: String,
}

/// The corpus capture at `rel`, or `None` when the corpus is not configured.
fn capture(rel: &str) -> Option<PathBuf> {
    corpus_support::root().map(|r| r.join(rel))
}

/// Open `path` through the file browser, the way a user would, and return the
/// app with the load settled.
fn open(path: &std::path::Path) -> Result<App, TestError> {
    let dir = tempfile::tempdir()?;
    let name = path.file_name().ok_or("capture has a file name")?;
    std::fs::copy(path, dir.path().join(name))?;
    let mut app = App::new_test();
    app.set_open_dir_for_test(dir.path().to_path_buf());
    app.handle_key(KeyCode::Char('O'));
    app.handle_key(KeyCode::Down);
    app.handle_key(KeyCode::Enter);
    Ok(app)
}

/// From the call list, open the call flow of the first dialog that holds an
/// INVITE, whose Call-ID is returned.
fn open_invite_flow(app: &mut App) -> Result<String, TestError> {
    for _ in 0..20 {
        app.handle_key(KeyCode::Enter);
        if let View::CallFlow(cid) = app.current_view().clone() {
            let has_invite = app.dialog_store_ref().read().get(&cid).is_some_and(|d| {
                d.messages
                    .iter()
                    .any(|m| m.is_request && m.method == Some(sipnab::sip::SipMethod::Invite))
            });
            if has_invite {
                return Ok(cid);
            }
            app.handle_key(KeyCode::Esc);
        }
        app.handle_key(KeyCode::Down);
    }
    Err("no dialog with an INVITE in the call list".into())
}

/// Render one tick at the size the sngrep screens were taken at and return
/// the text, one line per row.
fn screen(app: &mut App) -> Result<String, TestError> {
    let mut terminal = Terminal::new(TestBackend::new(200, 50))?;
    terminal.draw(|frame| app.render(frame))?;
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf.cell((x, y)).ok_or("cell in bounds")?.symbol());
        }
        out.push('\n');
    }
    Ok(out)
}

/// The RTP rows of the ladder now on screen.
fn rtp_rows(app: &mut App) -> Result<Vec<Row>, TestError> {
    screen(app)?;
    Ok(app
        .ladder_rtp_rows_for_test()
        .into_iter()
        .map(|(src, dst, label)| Row { src, dst, label })
        .collect())
}

/// The packet count a row's label carries: the number after the codec.
fn count_of(row: &Row) -> Option<u64> {
    row.label
        .split_whitespace()
        .find_map(|w| w.parse::<u64>().ok())
}

/// Whether the reverse of `row` (same columns, swapped) is among `rows`.
fn has_reverse(row: &Row, rows: &[Row]) -> bool {
    rows.iter().any(|r| r.src == row.dst && r.dst == row.src)
}

/// sngrep: two rows between the two signaling hosts, opposite directions,
/// `g711u` with 194 and 187 packets. Neither is one-way.
#[test]
fn a_two_way_call_draws_one_arrow_per_direction() -> Result<(), TestError> {
    let Some(path) = capture("sip_captures/voip-extension2downata.pcap") else {
        return Ok(());
    };
    let mut app = open(&path)?;
    open_invite_flow(&mut app)?;
    app.handle_key(KeyCode::F(6));
    let rows = rtp_rows(&mut app)?;
    assert_eq!(rows.len(), 2, "one row per stream: {rows:?}");
    assert!(
        rows.iter().all(|r| r.src != r.dst),
        "each stream crosses columns: {rows:?}"
    );
    assert!(
        has_reverse(&rows[0], &rows),
        "opposite directions: {rows:?}"
    );
    let mut counts: Vec<u64> = rows.iter().filter_map(count_of).collect();
    counts.sort_unstable();
    assert_eq!(counts, vec![187, 194], "packet counts: {rows:?}");
    for r in &rows {
        assert!(r.label.starts_with("RTP (PCMU)"), "codec: {r:?}");
        assert!(!r.label.contains("one-way"), "paired stream: {r:?}");
    }
    let text = screen(&mut app)?;
    assert!(text.contains("RTP (PCMU) 194"), "{text}");
    assert!(text.contains("RTP (PCMU) 187"), "{text}");
    Ok(())
}

/// sngrep: a single row, `g711u` 17 packets, from the called party (the
/// INVITE's destination) to the caller. sipnab marks it one-way.
#[test]
fn a_one_way_call_draws_one_arrow_marked_one_way() -> Result<(), TestError> {
    let Some(path) = capture("sip_captures/sip-phone-to-phone.pcapng") else {
        return Ok(());
    };
    let mut app = open(&path)?;
    open_invite_flow(&mut app)?;
    app.handle_key(KeyCode::F(6));
    let rows = rtp_rows(&mut app)?;
    assert_eq!(rows.len(), 1, "{rows:?}");
    // The INVITE goes from column 0 to column 1, so the media from the
    // called party to the caller points from 1 to 0.
    assert_eq!((rows[0].src, rows[0].dst), (1, 0), "{rows:?}");
    assert_eq!(count_of(&rows[0]), Some(17), "{rows:?}");
    assert!(rows[0].label.starts_with("RTP (PCMU)"), "{rows:?}");
    assert!(rows[0].label.contains("one-way"), "{rows:?}");
    let text = screen(&mut app)?;
    assert!(text.contains("one-way"), "{text}");
    Ok(())
}

/// sngrep: the relay's media address gets a column of its own, and four rows
/// of 250 packets connect it to the caller and to the callee in both
/// directions.
#[test]
fn a_relay_on_the_capture_host_gets_a_column_and_four_arrows() -> Result<(), TestError> {
    let Some(path) = capture("issue495/rtpengine-relay.pcap") else {
        return Ok(());
    };
    let mut app = open(&path)?;
    open_invite_flow(&mut app)?;
    let before = app.ladder_participant_labels_for_test();
    assert!(
        !before.iter().any(|l| l == "10.0.0.40"),
        "no media column without F6: {before:?}"
    );
    app.handle_key(KeyCode::F(6));
    let rows = rtp_rows(&mut app)?;
    let labels = app.ladder_participant_labels_for_test();
    let relay = labels
        .iter()
        .position(|l| l == "10.0.0.40")
        .ok_or_else(|| format!("relay media column missing: {labels:?}"))?;
    let caller = labels
        .iter()
        .position(|l| l == "127.0.0.2:5080")
        .ok_or("caller column")?;
    let callee = labels
        .iter()
        .position(|l| l == "127.0.0.3:5091")
        .ok_or("callee column")?;
    assert_eq!(rows.len(), 4, "{rows:?}");
    let mut pairs: Vec<(usize, usize)> = rows.iter().map(|r| (r.src, r.dst)).collect();
    pairs.sort_unstable();
    let mut want = vec![
        (caller, relay),
        (relay, callee),
        (callee, relay),
        (relay, caller),
    ];
    want.sort_unstable();
    assert_eq!(pairs, want, "{rows:?} over {labels:?}");
    for r in &rows {
        assert_eq!(count_of(r), Some(250), "{r:?}");
        assert!(!r.label.contains("one-way"), "{r:?}");
    }
    // The extended view of a single-Call-ID relay call draws the same rows.
    app.handle_key(KeyCode::Char('x'));
    assert!(app.extended_flow(), "x turns the extended view on");
    let extended = rtp_rows(&mut app)?;
    assert_eq!(extended.len(), 4, "{extended:?}");
    Ok(())
}

/// The B2BUA relays the media of two dialogs with different Call-IDs. The
/// plain view of one leg draws that leg's two streams; the extended view
/// draws all four, through the B2BUA's column.
#[test]
fn the_extended_view_draws_every_legs_streams() -> Result<(), TestError> {
    let Some(path) = capture("sip_captures/test_voip.pcap.pcapng") else {
        return Ok(());
    };
    let mut app = open(&path)?;
    open_invite_flow(&mut app)?;
    app.handle_key(KeyCode::F(6));
    let plain = rtp_rows(&mut app)?;
    assert_eq!(plain.len(), 2, "one leg's streams: {plain:?}");
    app.handle_key(KeyCode::Char('x'));
    assert!(app.extended_flow(), "x turns the extended view on");
    let rows = rtp_rows(&mut app)?;
    assert_eq!(rows.len(), 4, "both legs' streams: {rows:?}");
    // Every stream touches the B2BUA: one column common to all four rows.
    let n = app.ladder_participant_labels_for_test().len();
    let hub = (0..n).find(|c| rows.iter().all(|r| r.src == *c || r.dst == *c));
    assert!(
        hub.is_some(),
        "the relaying column joins all four: {rows:?}"
    );
    for r in &rows {
        assert!(has_reverse(r, &rows), "every stream is paired: {rows:?}");
        assert!(!r.label.contains("one-way"), "{r:?}");
    }
    Ok(())
}
