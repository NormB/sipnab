// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "tui")]
//! Operator notes in the TUI, driven through the real key path.
//!
//! `C` on a message opens a one-line editor; Enter keeps the note. The note is
//! shown in a pane labeled as not being sipnab's analysis, the ladder marks
//! the row, the PCAP-NG save writes it as the comment on that message's
//! rebuilt frame with a pointer back to the original, and the Notes format of
//! the save dialog writes the file `--notes` resumes from. Quitting or opening
//! another capture with notes not saved to a notes file asks first.
//!
//! Every test presses keys at an `App` and reads what came out (a file, a
//! rendered frame, the popup state), because the defects worth catching here
//! are "the key does nothing" and "the note never reached the file".

#[path = "support/tui_fixtures.rs"]
mod fixtures;

use std::path::Path;

use crossterm::event::KeyCode;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use sipnab::capture::resolve::parse_pointer;
use sipnab::sip::SipMessage;
use sipnab::tui::{App, Popup, SaveFormat};

/// The pointer each fixture message claims it was read from.
const INVITE_FRAME: &str = "call.pcap#0@00000000000000a1";
/// The 200 OK's frame.
const OK_FRAME: &str = "call.pcap#1@00000000000000b2";
/// A note no fixture contains.
const SENTINEL: &str = "SENTINEL-TUI the SBC answered twice";

/// `msg` as though read from `pointer`.
fn framed(mut msg: SipMessage, pointer: &str) -> SipMessage {
    msg.frame = Some(parse_pointer(pointer).expect("a test pointer"));
    msg
}

/// One answered call whose two messages carry frame pointers.
fn app_with_a_framed_call() -> App {
    let t0 = fixtures::base_ts();
    App::with_processed_messages(vec![
        framed(
            fixtures::make_invite("notes-1@test", "1001", "1002", t0),
            INVITE_FRAME,
        ),
        framed(
            fixtures::make_response(
                "notes-1@test",
                200,
                "OK",
                "INVITE",
                t0 + chrono::TimeDelta::seconds(1),
            ),
            OK_FRAME,
        ),
    ])
}

/// Type `text` into whatever has the keyboard.
fn type_text(app: &mut App, text: &str) {
    for c in text.chars() {
        app.handle_key(KeyCode::Char(c));
    }
}

/// Open the call flow on the first call, press `C` on the first message, and
/// type and keep `text`.
fn note_first_message(app: &mut App, text: &str) {
    app.handle_key(KeyCode::Enter);
    app.handle_key(KeyCode::Char('C'));
    assert_eq!(
        app.active_popup(),
        Some(&Popup::NoteEditor),
        "C on a message opens the note editor"
    );
    type_text(app, text);
    app.handle_key(KeyCode::Enter);
}

/// Save through F2 in `format` to `dest`.
fn save_as(app: &mut App, format: SaveFormat, dest: &Path) {
    app.handle_key(KeyCode::F(2));
    while app.save_format() != format {
        app.handle_key(KeyCode::Tab);
    }
    app.set_save_path(dest.to_str().expect("utf-8 path"));
    app.handle_key(KeyCode::Enter);
    app.settle_background_work();
}

/// Every EPB's comments, in frame order, and the section comments.
fn pcapng_comments(path: &Path) -> (Vec<Vec<String>>, Vec<String>) {
    use pcap_file::pcapng::PcapNgReader;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
    use pcap_file::pcapng::blocks::section_header::SectionHeaderOption;
    let bytes = std::fs::read(path).expect("read the save");
    let mut reader = PcapNgReader::new(&bytes[..]).expect("a pcapng");
    let section = reader
        .section()
        .options
        .iter()
        .filter_map(|o| match o {
            SectionHeaderOption::Comment(c) => Some(c.to_string()),
            _ => None,
        })
        .collect();
    let mut frames = Vec::new();
    while let Some(block) = reader.next_block() {
        if let Some(epb) = block.expect("every block parses").into_enhanced_packet() {
            frames.push(
                epb.options
                    .iter()
                    .filter_map(|o| match o {
                        EnhancedPacketOption::Comment(c) => Some(c.to_string()),
                        _ => None,
                    })
                    .collect(),
            );
        }
    }
    (frames, section)
}

/// The screen as text.
fn screen(app: &mut App, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal.draw(|f| app.render(f)).expect("draw");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// A note typed on a message is the comment on that message's rebuilt frame,
/// with the pointer to the frame it was typed on.
#[test]
fn a_note_typed_on_a_message_is_the_comment_on_its_rebuilt_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("annotated.pcapng");
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    assert_eq!(app.active_popup(), None, "Enter keeps the note and closes");
    assert_eq!(app.notes_for_test().len(), 1);

    save_as(&mut app, SaveFormat::PcapNg, &dest);
    assert!(dest.exists(), "the save happened: {:?}", app.status_error());
    let (frames, section) = pcapng_comments(&dest);
    assert_eq!(frames.len(), 2, "both messages are written");
    assert_eq!(
        frames[0],
        vec![format!(
            "[operator note] {SENTINEL}\noriginal frame: {INVITE_FRAME}"
        )],
        "the INVITE's frame carries the note and the way back to the original"
    );
    assert!(frames[1].is_empty(), "the 200 OK carries nothing");
    let section = section.join("\n");
    assert!(section.contains("REBUILT, NOT COPIED"), "{section}");
    assert!(
        section.contains("1 packet comment(s) in this file are notes typed by a person"),
        "{section}"
    );
}

/// The note is shown in a pane that says it is not analysis, and the ladder
/// marks the row it is on.
#[test]
fn the_note_pane_is_labeled_and_the_row_is_marked() {
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    let out = screen(&mut app, 120, 30);
    assert!(
        out.contains("operator note — not sipnab analysis"),
        "the pane must say what it is:\n{out}"
    );
    assert!(out.contains(SENTINEL), "the pane shows the note:\n{out}");
    assert!(out.contains('✎'), "the ladder marks the noted row:\n{out}");

    // On the row without a note there is no pane.
    app.handle_key(KeyCode::Down);
    let out = screen(&mut app, 120, 30);
    assert!(
        !out.contains("operator note — not sipnab analysis"),
        "a message with no note shows no pane:\n{out}"
    );
    assert!(out.contains('✎'), "the mark stays on the noted row:\n{out}");
}

/// A refused note leaves the editor open, says why without quoting the key,
/// and keeps nothing.
#[test]
fn a_refused_note_keeps_the_editor_open_and_stores_nothing() {
    let mut app = app_with_a_framed_call();
    let refused_text = "inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1c";
    note_first_message(&mut app, refused_text);
    assert_eq!(
        app.active_popup(),
        Some(&Popup::NoteEditor),
        "a refused note must not close the editor"
    );
    let status = app.status_error().unwrap_or_default().to_string();
    assert!(status.contains("SDES"), "the refusal says why: {status}");
    assert!(!status.contains("d0Rmdm"), "and never quotes the key");
    assert_eq!(app.notes_for_test().len(), 0, "nothing was kept");
    app.handle_key(KeyCode::Esc);
    assert_eq!(app.active_popup(), None, "Esc abandons the edit");
}

/// Clearing a note's text removes the note.
#[test]
fn an_emptied_note_is_removed() {
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, "short");
    assert_eq!(app.notes_for_test().len(), 1);
    app.handle_key(KeyCode::Char('C'));
    for _ in 0.."short".len() {
        app.handle_key(KeyCode::Backspace);
    }
    app.handle_key(KeyCode::Enter);
    assert_eq!(app.notes_for_test().len(), 0, "an empty note removes it");
}

/// A message read from no frame cannot carry a note: there is nowhere to
/// save it and nothing to point the comment back at.
#[test]
fn a_message_with_no_frame_takes_no_note() {
    let t0 = fixtures::base_ts();
    let mut app = App::with_processed_messages(vec![fixtures::make_invite(
        "unframed@test",
        "1001",
        "1002",
        t0,
    )]);
    app.handle_key(KeyCode::Enter);
    app.handle_key(KeyCode::Char('C'));
    assert_eq!(app.active_popup(), None, "no editor opens");
    let status = app.status_error().unwrap_or_default();
    assert!(
        status.contains("frame"),
        "and the status says why: {status}"
    );
}

/// A note bound for classic pcap is refused, never silently dropped.
#[test]
fn a_note_bound_for_classic_pcap_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dest = dir.path().join("classic.pcap");
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    save_as(&mut app, SaveFormat::Pcap, &dest);
    let status = app.status_error().unwrap_or_default();
    assert!(
        !dest.exists(),
        "no classic file is written without the note"
    );
    assert!(
        status.contains("PCAP-NG"),
        "the refusal names the format that can carry it: {status}"
    );
}

/// The Notes format writes the file `--notes` resumes from, and a session
/// built from it has the note back.
#[test]
fn saved_notes_resume_in_a_new_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let notes_file = dir.path().join("session.notes.jsonl");
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    save_as(&mut app, SaveFormat::Notes, &notes_file);
    assert!(
        app.status_error()
            .unwrap_or_default()
            .contains("Saved 1 note"),
        "{:?}",
        app.status_error()
    );

    let loaded = sipnab::annotate::Notes::load(&notes_file).expect("the saved file loads");
    assert_eq!(loaded.len(), 1);
    let mut resumed = app_with_a_framed_call();
    resumed.set_notes(loaded, Some(notes_file.clone()));
    resumed.handle_key(KeyCode::Enter);
    let out = screen(&mut resumed, 120, 30);
    assert!(out.contains(SENTINEL), "the resumed note is shown:\n{out}");
}

/// Quitting with notes not saved to a notes file says they will be lost; once
/// saved, it does not.
#[test]
fn the_quit_prompt_names_unsaved_notes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    app.handle_key(KeyCode::Char('q'));
    assert_eq!(app.active_popup(), Some(&Popup::QuitConfirm));
    let out = screen(&mut app, 120, 30);
    assert!(
        out.contains("1 operator note") && out.contains("not saved to a notes file"),
        "the prompt must say a note would be lost:\n{out}"
    );
    app.handle_key(KeyCode::Char('n'));

    save_as(&mut app, SaveFormat::Notes, &dir.path().join("n.jsonl"));
    app.handle_key(KeyCode::Char('q'));
    let out = screen(&mut app, 120, 30);
    assert_eq!(app.active_popup(), Some(&Popup::QuitConfirm));
    assert!(
        !out.contains("not saved to a notes file"),
        "saved notes are not lost and the prompt must not say so:\n{out}"
    );
}

/// Opening another capture with unsaved notes asks first. No keeps the
/// session as it was; yes opens the capture and drops the notes, which were
/// about frames of the capture that is gone.
#[test]
fn unsaved_notes_ask_before_a_capture_swap() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sip_call.pcap"),
        dir.path().join("next.pcap"),
    )
    .expect("copy fixture");
    let mut app = app_with_a_framed_call();
    note_first_message(&mut app, SENTINEL);
    app.handle_key(KeyCode::Esc); // back to the call list

    let open_next = |app: &mut App| {
        app.set_open_dir_for_test(dir.path().to_path_buf());
        app.handle_key(KeyCode::Char('O'));
        let names = app.open_entry_names_for_test();
        let at = names.iter().position(|n| n == "next.pcap").expect("listed");
        for _ in 0..at {
            app.handle_key(KeyCode::Down);
        }
        app.handle_key(KeyCode::Enter);
    };

    open_next(&mut app);
    assert_eq!(
        app.active_popup(),
        Some(&Popup::UnsavedNotes),
        "an unsaved note must stop the swap and ask"
    );
    app.handle_key(KeyCode::Char('n'));
    assert_eq!(app.active_popup(), None);
    assert!(
        app.dialog_store_ref().read().get("notes-1@test").is_some(),
        "no keeps the capture on screen"
    );
    assert_eq!(app.notes_for_test().len(), 1, "and its note");

    open_next(&mut app);
    assert_eq!(app.active_popup(), Some(&Popup::UnsavedNotes));
    app.handle_key(KeyCode::Char('y'));
    app.settle_background_work();
    assert!(
        app.dialog_store_ref().read().get("notes-1@test").is_none(),
        "yes opens the other capture"
    );
    assert_eq!(app.notes_for_test().len(), 0, "and drops the old notes");
}
