// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `forked_answers` from the real binary: a forked INVITE that two legs answer
//! `2xx` names the second leg's tag in `--json-dialogs`, a call one leg
//! answered carries no such key, and `--cores 2` gives the serial answer.
//!
//! The committed captures hold no forked call, so the capture is built here
//! (tests/doc_jq_fields_test.rs lists the key as one no fixture shows, and
//! names this file).

#![cfg(all(unix, feature = "full"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/surface_parity.rs"]
mod surface_parity;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use pcap_build::{sip_call_frames, udp_frame, write_pcap};
use surface_parity::run_cli;
use test_scratch::ScratchDir;

type TestError = Box<dyn std::error::Error>;

/// The caller (RFC 5737).
const UAC: [u8; 4] = [192, 0, 2, 1];
/// The forking proxy (RFC 5737).
const PROXY: [u8; 4] = [198, 51, 100, 1];

/// A forked call `call_id` as UDP frames between the caller and the proxy:
/// legs `fork-a` and `fork-b` ring, `fork-b` answers, `fork-a` answers after
/// it, and the caller acknowledges both and ends `fork-a`'s dialog.
fn forked_call(call_id: &str) -> Vec<Vec<u8>> {
    let via = "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-fork-1\r\n";
    let from = "From: <sip:alice@example.com>;tag=caller\r\n";
    let cid = format!("Call-ID: {call_id}\r\n");
    let to = |tag: &str| format!("To: <sip:bob@example.com>;tag={tag}\r\n");
    let response = |status: &str, tag: &str, cseq: &str| {
        format!(
            "SIP/2.0 {status}\r\n{via}{from}{}{cid}CSeq: {cseq}\r\nContent-Length: 0\r\n\r\n",
            to(tag)
        )
    };
    // An ACK to a 2xx and a BYE are transactions of their own, each on a
    // new branch (RFC 3261 section 13.2.2.4).
    let request = |method: &str, tag: &str, cseq: &str| {
        format!(
            "{method} sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{method}-{tag}\r\n\
             Max-Forwards: 70\r\n{from}{}{cid}CSeq: {cseq}\r\nContent-Length: 0\r\n\r\n",
            to(tag)
        )
    };
    let invite = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n{via}Max-Forwards: 70\r\n{from}\
         To: <sip:bob@example.com>\r\n{cid}CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@192.0.2.1:5060>\r\nContent-Length: 0\r\n\r\n"
    );
    let up = |m: &str| udp_frame(UAC, PROXY, 5060, 5060, m.as_bytes());
    let down = |m: &str| udp_frame(PROXY, UAC, 5060, 5060, m.as_bytes());
    vec![
        up(&invite),
        down(&response("180 Ringing", "fork-a", "1 INVITE")),
        down(&response("180 Ringing", "fork-b", "1 INVITE")),
        down(&response("200 OK", "fork-b", "1 INVITE")),
        up(&request("ACK", "fork-b", "1 ACK")),
        down(&response("200 OK", "fork-a", "1 INVITE")),
        up(&request("ACK", "fork-a", "1 ACK")),
        up(&request("BYE", "fork-a", "2 BYE")),
        down(&response("200 OK", "fork-a", "2 BYE")),
    ]
}

/// `--json-dialogs` over `frames`, with `extra` arguments, as one object per
/// dialog.
fn dialogs(frames: &[Vec<u8>], extra: &[&str]) -> Result<Vec<serde_json::Value>, TestError> {
    let dir = ScratchDir::new("sipnab-forked-answers-")?;
    let path = dir.join("calls.pcap");
    write_pcap(&path, frames)?;
    let path = path.to_str().ok_or("a UTF-8 path")?;
    let mut args = vec!["--json-dialogs", "--no-cli-print", "--quiet"];
    args.extend_from_slice(extra);
    let run = run_cli(path, &args)?;
    assert_eq!(run.code, Some(0), "sipnab exits 0; stderr:\n{}", run.stderr);
    run.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("a JSON line: {e}: {l}").into()))
        .collect()
}

/// The one dialog `call_id` among `all`.
fn the<'a>(
    all: &'a [serde_json::Value],
    call_id: &str,
) -> Result<&'a serde_json::Value, TestError> {
    let found: Vec<_> = all.iter().filter(|d| d["call_id"] == call_id).collect();
    match found.as_slice() {
        [one] => Ok(one),
        _ => Err(format!("{} dialogs named {call_id} in {all:?}", found.len()).into()),
    }
}

#[test]
fn a_forked_call_names_the_second_answering_leg() -> Result<(), TestError> {
    let all = dialogs(&forked_call("forked-1@example.com"), &[])?;
    let d = the(&all, "forked-1@example.com")?;
    assert_eq!(
        d["forked_answers"],
        serde_json::json!(["fork-a"]),
        "the leg that answered second, by its To tag; got {d}"
    );
    Ok(())
}

#[test]
fn a_call_one_leg_answered_has_no_forked_answers_key() -> Result<(), TestError> {
    let all = dialogs(
        &sip_call_frames("single-1@example.com", "s1", "alice", "bob"),
        &[],
    )?;
    let d = the(&all, "single-1@example.com")?;
    assert!(
        d.get("forked_answers").is_none(),
        "absent, never empty; got {d}"
    );
    Ok(())
}

#[test]
fn cores_two_reports_the_forked_answer_the_serial_run_does() -> Result<(), TestError> {
    let mut frames = forked_call("forked-2@example.com");
    frames.extend(sip_call_frames(
        "single-2@example.com",
        "s2",
        "carol",
        "dave",
    ));
    let serial = dialogs(&frames, &[])?;
    let parallel = dialogs(&frames, &["--cores", "2"])?;
    for call_id in ["forked-2@example.com", "single-2@example.com"] {
        assert_eq!(
            the(&parallel, call_id)?.get("forked_answers"),
            the(&serial, call_id)?.get("forked_answers"),
            "{call_id}: --cores 2 agrees with one core"
        );
    }
    assert_eq!(
        the(&parallel, "forked-2@example.com")?["forked_answers"],
        serde_json::json!(["fork-a"]),
        "and the answer is the forked leg"
    );
    Ok(())
}
