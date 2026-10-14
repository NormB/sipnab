// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDP in an OPTIONS 200 OK links no RTP stream, proved on a real capture.
//!
//! In `sip_captures/test_voip.pcap.pcapng` a phone answers an OPTIONS with a
//! 200 OK whose SDP names its own media socket. A few seconds later the same
//! phone takes a call on that socket and sends ten RTP packets before the
//! call's 200 OK. sipnab bound those ten packets to the OPTIONS dialog, then
//! split the stream in two when the 200 OK named the socket again.
//!
//! [RFC 6337 section 2.4](https://www.rfc-editor.org/rfc/rfc6337.html#section-2.4) names a 200 OK for OPTIONS as a session
//! description that is neither an offer nor an answer. It sets up no media,
//! so it links no stream.
//!
//! `tshark -o rtp.heuristic_rtp:TRUE -z rtp,streams` counts four streams in
//! this capture: 334, 345, 355 and 362 packets. sipnab must report the same
//! four, each bound to the INVITE dialog that carries it.
//!
//! # Running
//!
//! Set `SIPNAB_CORPUS` to the corpus root; unset, the test skips. The corpus
//! is not committed and is assumed to contain PII, so no address, SSRC or
//! `Call-ID` is written here or printed. Streams are told apart by their
//! packet counts and their relation to each other.
#![cfg(feature = "native")]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::process::Command;

#[path = "support/corpus.rs"]
mod corpus_support;

type TestError = Box<dyn std::error::Error>;

/// The capture, relative to the corpus root.
const CAPTURE: &str = "sip_captures/test_voip.pcap.pcapng";

/// One stream as `--json-dialogs` reports it, with the method of the dialog
/// it was printed under.
#[derive(Debug)]
struct Stream {
    packets: u64,
    src: String,
    dst: String,
    associated_dialog: Option<String>,
    dialog_method: String,
    dialog_call_id: String,
}

/// Every stream of every dialog `sipnab -N -I <capture> --json-dialogs
/// <extra>` prints.
fn streams(capture: &std::path::Path, extra: &[&str]) -> Result<Vec<Stream>, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-N")
        .arg("-I")
        .arg(capture)
        .arg("--json-dialogs")
        .args(extra)
        .output()?;
    if !out.status.success() {
        return Err(format!("sipnab {extra:?} exited {:?}", out.status.code()).into());
    }
    let mut found = Vec::new();
    for line in String::from_utf8(out.stdout)?.lines() {
        if !line.starts_with('{') {
            continue;
        }
        let dialog: serde_json::Value = serde_json::from_str(line)?;
        let method = dialog["method"].as_str().ok_or("a dialog has a method")?;
        let call_id = dialog["call_id"].as_str().ok_or("a dialog has a call_id")?;
        for stream in dialog["streams"].as_array().into_iter().flatten() {
            found.push(Stream {
                packets: stream["packets"].as_u64().ok_or("a stream has packets")?,
                src: stream["src"].as_str().ok_or("a stream has src")?.to_owned(),
                dst: stream["dst"].as_str().ok_or("a stream has dst")?.to_owned(),
                associated_dialog: stream["associated_dialog"].as_str().map(str::to_owned),
                dialog_method: method.to_owned(),
                dialog_call_id: call_id.to_owned(),
            });
        }
    }
    Ok(found)
}

/// The checks, for one run's streams.
fn check(found: &[Stream], run: &str) -> Result<(), TestError> {
    let mut counts: Vec<u64> = found.iter().map(|s| s.packets).collect();
    counts.sort_unstable();
    assert_eq!(
        counts,
        vec![334, 345, 355, 362],
        "{run}: the stream packet counts differ from tshark's"
    );
    for stream in found {
        assert_eq!(
            stream.dialog_method, "INVITE",
            "{run}: a {}-packet stream is reported under a {} dialog",
            stream.packets, stream.dialog_method
        );
        assert_eq!(
            stream.associated_dialog.as_deref(),
            Some(stream.dialog_call_id.as_str()),
            "{run}: the {}-packet stream is printed under one dialog and bound to another",
            stream.packets
        );
    }
    let by_count: BTreeMap<u64, &Stream> = found.iter().map(|s| (s.packets, s)).collect();
    let pair = |a: u64, b: u64| -> Result<(), TestError> {
        let (x, y) = (
            by_count.get(&a).ok_or("first stream of a pair")?,
            by_count.get(&b).ok_or("second stream of a pair")?,
        );
        assert!(
            x.src == y.dst && x.dst == y.src,
            "{run}: the {a}- and {b}-packet streams are not the two directions of one call"
        );
        assert_eq!(
            x.associated_dialog, y.associated_dialog,
            "{run}: the {a}- and {b}-packet streams are bound to different dialogs"
        );
        Ok(())
    };
    // The call that the OPTIONS 200 OK collided with, and the other call.
    pair(362, 334)?;
    pair(345, 355)?;
    assert_ne!(
        by_count.get(&362).map(|s| &s.associated_dialog),
        by_count.get(&345).map(|s| &s.associated_dialog),
        "{run}: the two calls are bound to one dialog"
    );
    Ok(())
}

/// One stream per SSRC, each counted as tshark counts it and bound to its
/// call, never to the OPTIONS dialog. Run on the batch path and on the
/// `--cores` path, which apply SDP links separately.
#[test]
fn options_200_sdp_links_no_stream_on_a_real_capture() -> Result<(), TestError> {
    let Some(root) = corpus_support::root() else {
        return Ok(());
    };
    let capture = root.join(CAPTURE);
    if !capture.is_file() {
        // Another machine's corpus. Written past libtest's capture, as the
        // shared gate does, so the skip is not mistaken for a pass.
        let _ = writeln!(
            std::io::stderr(),
            "corpus_options_sdp_media_link_test: {CAPTURE} is not under SIPNAB_CORPUS, skipping"
        );
        return Ok(());
    }
    check(&streams(&capture, &[])?, "batch")?;
    check(&streams(&capture, &["--cores", "4"])?, "--cores 4")?;
    Ok(())
}
