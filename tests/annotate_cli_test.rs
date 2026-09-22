// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--notes FILE --write-annotated OUT -I CAPTURE`, end to end.
//!
//! Two properties matter, and each is tested against the binary rather than
//! the library, because the defect either would be is "the copy an operator
//! sends is wrong", which only the command's own output can show:
//!
//! 1. **sipnab never reads a packet comment** (L4 of the design, Invariant 13
//!    in `docs/internals/invariants.md`). An annotated copy and its original
//!    produce byte-identical `--json` once the path is normalized, and a
//!    sentinel note appears in no `--json` line and in no MCP `get_message` or
//!    `search_messages` answer over the copy. Each check first proves the
//!    sentinel IS in the copy, so none of them passes by annotating nothing.
//! 2. **A note lands on the frame it names, or nothing is written.** A changed
//!    frame, a pointer with no digest, a pointer into another capture and a
//!    classic-pcap output are each refused with a non-zero exit and no file.

#![cfg(all(unix, feature = "mcp"))] // `mcp` implies `native`; MCP is half of L4.

use std::path::{Path, PathBuf};

#[path = "support/run.rs"]
mod run_support;

#[path = "support/pcap_build.rs"]
mod pcap_build;

#[path = "support/mcp.rs"]
mod mcp;

/// A note no capture could contain, so finding it anywhere is the note.
const SENTINEL: &str = "SENTINEL-4f2b9 operator note, never analysis";

/// Absolute path under the repository.
fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Run sipnab with no config file and logging off; `(stdout, stderr, code)`.
fn sipnab(args: &[&str]) -> (String, String, i32) {
    let mut argv = vec!["-F"];
    argv.extend_from_slice(args);
    let (out, err, code) = run_support::run(&argv, Some("warn"));
    (out, err, code.unwrap_or(-1))
}

/// `--json` over `capture`, asserting it succeeded.
fn json_of(capture: &Path) -> String {
    let (out, err, code) = sipnab(&["-N", "-I", capture.to_str().expect("utf-8"), "--json"]);
    assert_eq!(code, 0, "--json over {} failed:\n{err}", capture.display());
    out
}

/// Every distinct `frame` pointer in `--json` output, in first-seen order.
fn frames_in(json: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in json.lines().filter(|l| l.starts_with('{')) {
        let v: serde_json::Value = serde_json::from_str(line).expect("a JSON line");
        if let Some(f) = v["frame"].as_str()
            && !out.iter().any(|x| x == f)
        {
            out.push(f.to_string());
        }
    }
    out
}

/// Write a notes file putting `note` on each of `frames`.
fn write_notes(path: &Path, frames: &[String], note: &str) {
    let mut text = String::new();
    for f in frames {
        text.push_str(&serde_json::json!({"frame": f, "note": note}).to_string());
        text.push('\n');
    }
    std::fs::write(path, text).expect("write notes");
}

/// `--write-annotated` from `notes` over `input` into `out`.
fn annotate(input: &Path, notes: &Path, out: &Path) -> (String, i32) {
    let (_o, err, code) = sipnab(&[
        "-N",
        "--notes",
        notes.to_str().expect("utf-8"),
        "--write-annotated",
        out.to_str().expect("utf-8"),
        "-I",
        input.to_str().expect("utf-8"),
    ]);
    (err, code)
}

/// The packet comments of every frame of a pcapng, in frame order, with each
/// frame's bytes.
fn comments_and_frames(path: &Path) -> Vec<(Vec<String>, Vec<u8>)> {
    use pcap_file::pcapng::PcapNgReader;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
    let bytes = std::fs::read(path).expect("read the copy");
    let mut reader = PcapNgReader::new(&bytes[..]).expect("a pcapng");
    let mut out = Vec::new();
    while let Some(block) = reader.next_block() {
        if let Some(epb) = block.expect("every block parses").into_enhanced_packet() {
            let comments = epb
                .options
                .iter()
                .filter_map(|o| match o {
                    EnhancedPacketOption::Comment(c) => Some(c.to_string()),
                    _ => None,
                })
                .collect();
            out.push((comments, epb.data.to_vec()));
        }
    }
    out
}

/// The captures the invisibility check runs over: every checked-in pcapng
/// sample, and the classic-pcap fixture most of the suite reads.
fn invisibility_captures() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(repo("tests/pcap-samples"))
        .expect("tests/pcap-samples")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pcapng"))
        .collect();
    out.sort();
    assert!(
        out.len() >= 5,
        "only {} pcapng samples found; the directory scan stopped working",
        out.len()
    );
    out.push(repo("tests/fixtures/sip_call.pcap"));
    out
}

// ── L4: sipnab never reads a packet comment ─────────────────────────────

/// An annotated copy reads exactly as its original, and the note is nowhere
/// in what sipnab says about it.
///
/// Over every pcapng sample: annotate every frame `--json` names with the
/// sentinel, prove the copy carries one comment per note, then compare
/// `--json` over the two with the capture path normalized. Any difference is
/// either the copy altering a frame or sipnab reading a comment, and both are
/// the failure this exists for.
#[test]
fn an_annotated_copy_reads_exactly_as_its_original() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (i, original) in invisibility_captures().iter().enumerate() {
        let before = json_of(original);
        let frames = frames_in(&before);
        assert!(
            !frames.is_empty(),
            "{} yields no framed message, so annotating it proves nothing",
            original.display()
        );
        let notes = dir.path().join(format!("notes-{i}.jsonl"));
        let copy = dir.path().join(format!("copy-{i}.pcapng"));
        write_notes(&notes, &frames, SENTINEL);

        let (err, code) = annotate(original, &notes, &copy);
        assert_eq!(code, 0, "annotating {} failed:\n{err}", original.display());

        // Non-vacuity: the sentinel IS in the file, once per note.
        let in_file: usize = comments_and_frames(&copy)
            .iter()
            .flat_map(|(c, _)| c)
            .filter(|c| c.contains(SENTINEL))
            .count();
        assert_eq!(
            in_file,
            frames.len(),
            "the copy of {} must carry one comment per note",
            original.display()
        );

        let after = json_of(&copy);
        assert!(
            !after.contains(SENTINEL),
            "sipnab read a packet comment back into --json over the copy of {}",
            original.display()
        );
        let orig_path = original.to_str().expect("utf-8");
        let copy_path = copy.to_str().expect("utf-8");
        assert_eq!(
            after.replace(copy_path, "<CAPTURE>"),
            before.replace(orig_path, "<CAPTURE>"),
            "--json over the annotated copy of {} differs from the original",
            original.display()
        );
    }
}

/// No MCP answer over an annotated copy carries the note.
///
/// `get_message` for every message of every dialog, and `search_messages`
/// for the sentinel's own words and for a method every call has. An agent
/// reading the copy sees exactly what it would see reading the original.
#[test]
fn no_mcp_answer_over_an_annotated_copy_carries_the_note() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let frames = frames_in(&json_of(&original));
    let notes = dir.path().join("notes.jsonl");
    let copy = dir.path().join("copy.pcapng");
    write_notes(&notes, &frames, SENTINEL);
    let (err, code) = annotate(&original, &notes, &copy);
    assert_eq!(code, 0, "annotate failed:\n{err}");
    assert!(
        comments_and_frames(&copy)
            .iter()
            .any(|(c, _)| c.iter().any(|x| x.contains(SENTINEL))),
        "the copy must carry the note, or this test proves nothing"
    );

    let mut session = mcp::McpSession::start(copy.to_str().expect("utf-8"), &["-F"]);
    let dialogs = session.ok("list_dialogs", serde_json::json!({}));
    let rows = dialogs["dialogs"].as_array().expect("dialogs").clone();
    assert!(!rows.is_empty(), "the copy must load dialogs: {dialogs}");
    let mut answers = Vec::new();
    let mut messages = 0usize;
    for row in &rows {
        let call_id = row["call_id"].as_str().expect("call_id").to_string();
        let count = row["msg_count"].as_u64().expect("msg_count");
        for index in 0..count {
            let reply = session.call(
                "get_message",
                serde_json::json!({"call_id": call_id, "index": index}),
            );
            assert!(reply["result"].is_object(), "get_message failed: {reply}");
            answers.push(reply.to_string());
            messages += 1;
        }
    }
    assert!(messages >= 5, "only {messages} messages were read back");
    for query in ["SENTINEL", "operator note", "INVITE"] {
        let reply = session.call("search_messages", serde_json::json!({"query": query}));
        assert!(
            reply["result"].is_object(),
            "search_messages failed: {reply}"
        );
        answers.push(reply.to_string());
    }
    for answer in &answers {
        assert!(
            !answer.contains("SENTINEL") && !answer.contains("operator note"),
            "an MCP answer over the annotated copy carried the note: {answer}"
        );
    }
}

// ── A note lands on its frame, or nothing is written ────────────────────

/// Every note lands on the frame whose digest it names, and on no other.
#[test]
fn every_note_lands_on_the_frame_whose_digest_it_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let frames = frames_in(&json_of(&original));
    assert!(frames.len() >= 3, "the fixture must have several frames");
    let chosen = [frames[0].clone(), frames[2].clone()];
    let notes = dir.path().join("notes.jsonl");
    let mut text = String::new();
    for (n, f) in chosen.iter().enumerate() {
        text.push_str(&serde_json::json!({"frame": f, "note": format!("note {n}")}).to_string());
        text.push('\n');
    }
    std::fs::write(&notes, text).expect("notes");
    let copy = dir.path().join("copy.pcapng");
    let (err, code) = annotate(&original, &notes, &copy);
    assert_eq!(code, 0, "annotate failed:\n{err}");

    let written = comments_and_frames(&copy);
    for (n, pointer) in chosen.iter().enumerate() {
        let parsed = sipnab::capture::resolve::parse_pointer(pointer).expect("pointer");
        let ordinal = usize::try_from(parsed.origin.ordinal).expect("small");
        let (comments, data) = &written[ordinal];
        assert_eq!(
            comments,
            &vec![format!("[operator note] note {n}")],
            "frame {ordinal} must carry exactly its own note"
        );
        assert_eq!(
            Some(sipnab::capture::packet::frame_digest(data)),
            parsed.origin.digest,
            "the frame carrying the note is the frame the note's digest names"
        );
    }
    let annotated: usize = written.iter().filter(|(c, _)| !c.is_empty()).count();
    assert_eq!(annotated, 2, "no other frame carries a comment");
}

/// A frame whose bytes no longer match the note's digest refuses the whole
/// copy: non-zero exit, a reason, and no file.
#[test]
fn a_changed_frame_refuses_the_copy_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let frames = frames_in(&json_of(&original));
    let (head, _) = frames[0].rsplit_once('@').expect("a digest");
    let wrong = format!("{head}@0000000000000001");
    let notes = dir.path().join("notes.jsonl");
    write_notes(
        &notes,
        std::slice::from_ref(&wrong),
        "about a frame that changed",
    );
    let copy = dir.path().join("copy.pcapng");

    let (err, code) = annotate(&original, &notes, &copy);
    assert_ne!(code, 0, "a changed frame must be refused");
    assert!(
        err.contains(&wrong),
        "the refusal names the pointer:\n{err}"
    );
    assert!(err.contains("digest"), "and says why:\n{err}");
    assert!(!copy.exists(), "a refused copy must leave no file behind");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("list")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".sipnab-tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temporary file either: {leftovers:?}"
    );
}

/// A pointer with no digest cannot be bound to bytes, so it is refused.
#[test]
fn a_pointer_without_a_digest_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let notes = dir.path().join("notes.jsonl");
    let bare = format!("{}#0", original.display());
    write_notes(&notes, &[bare], "typed by hand");
    let copy = dir.path().join("copy.pcapng");
    let (err, code) = annotate(&original, &notes, &copy);
    assert_ne!(code, 0, "a note with no digest must be refused");
    assert!(err.contains("no digest"), "{err}");
    assert!(!copy.exists());
}

/// A note naming another capture is refused, and the refusal names it.
#[test]
fn a_note_naming_another_capture_is_refused_and_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let other = frames_in(&json_of(&repo("tests/fixtures/udp_5060.pcap")));
    let notes = dir.path().join("notes.jsonl");
    write_notes(&notes, &other[..1], "about udp_5060");
    let copy = dir.path().join("copy.pcapng");
    let (err, code) = annotate(&original, &notes, &copy);
    assert_ne!(code, 0, "a note on another capture must be refused");
    assert!(
        err.contains("udp_5060.pcap"),
        "the refusal names it:\n{err}"
    );
    assert!(err.contains("another capture"), "{err}");
    assert!(!copy.exists());
}

/// A classic-pcap output name is refused: it has nowhere to put a comment.
#[test]
fn a_classic_pcap_output_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let frames = frames_in(&json_of(&original));
    let notes = dir.path().join("notes.jsonl");
    write_notes(&notes, &frames[..1], "n");
    let copy = dir.path().join("copy.pcap");
    let (err, code) = annotate(&original, &notes, &copy);
    assert_ne!(code, 0, "{err}");
    assert!(
        err.contains(".pcapng"),
        "the refusal names the remedy:\n{err}"
    );
    assert!(!copy.exists());
}

/// A decryption secret in the input never reaches the copy.
///
/// The copy is what gets sent; the input may be a pcapng a decrypting run
/// wrote with its key log embedded. Re-encoding through libpcap drops every
/// DSB, and the section comment says it did.
#[test]
fn a_decryption_secret_in_the_input_is_not_in_the_copy() {
    const DSB: u32 = 0x0000_000a;
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("with-secrets.pcapng");
    let frame = pcap_build::udp_frame(
        [10, 1, 0, 1],
        [10, 2, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:a@b SIP/2.0\r\nCall-ID: dsb-copy\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    );
    // A key-log line built from repeated bytes, not pasted material.
    let dsb_text = format!("CLIENT_RANDOM {} {}\n", "0a".repeat(32), "0b".repeat(48));
    pcap_build::write_pcapng_with_dsb(&input, &dsb_text, &frame);
    assert_eq!(
        pcap_build::count_pcapng_blocks(&input, DSB),
        1,
        "fixture has a DSB"
    );

    let frames = frames_in(&json_of(&input));
    let notes = dir.path().join("notes.jsonl");
    write_notes(&notes, &frames[..1], "the OPTIONS");
    let copy = dir.path().join("copy.pcapng");
    let (err, code) = annotate(&input, &notes, &copy);
    assert_eq!(code, 0, "annotate failed:\n{err}");

    assert_eq!(
        pcap_build::count_pcapng_blocks(&copy, DSB),
        0,
        "the annotated copy must carry no Decryption Secrets Block"
    );
    let bytes = std::fs::read(&copy).expect("read copy");
    let marker = "0b".repeat(48);
    assert!(
        !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
        "the key-log material must not appear anywhere in the copy"
    );
    assert_eq!(
        comments_and_frames(&copy).len(),
        1,
        "the frame itself is copied"
    );
}

/// `--write-annotated` without `--notes` is a usage error, and `--notes`
/// alone in a headless run has nothing to act on.
#[test]
fn the_two_flags_need_each_other_in_a_headless_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = repo("tests/fixtures/sip_call.pcap");
    let copy = dir.path().join("copy.pcapng");
    let (_o, err, code) = sipnab(&[
        "-N",
        "--write-annotated",
        copy.to_str().expect("utf-8"),
        "-I",
        original.to_str().expect("utf-8"),
    ]);
    assert_ne!(code, 0, "--write-annotated needs --notes");
    assert!(err.contains("--notes"), "{err}");
    assert!(!copy.exists());

    let notes = dir.path().join("notes.jsonl");
    write_notes(&notes, &frames_in(&json_of(&original))[..1], "n");
    let (_o, err, code) = sipnab(&[
        "-N",
        "--notes",
        notes.to_str().expect("utf-8"),
        "-I",
        original.to_str().expect("utf-8"),
    ]);
    assert_ne!(
        code, 0,
        "--notes alone does nothing headless and must say so"
    );
    assert!(err.contains("--write-annotated"), "{err}");
}
