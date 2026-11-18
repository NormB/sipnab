// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! DEDUP-1: a message seen on the wire AND reported by a HEP tracer is one
//! message, not two.
//!
//! A run that reads the wire and a HEP feed of the same proxy (`-d any -L`,
//! or `-I` of a capture holding both with `--hep-parse`) gets every message
//! twice. Both copies joined the dialog, and the second was taken for a
//! retransmission: a 7-message call showed 14 messages and 7 retransmissions.
//! A copy is now merged into the message it copies, which records each
//! source that saw it; the counts each source delivered stay visible in
//! `seen_by`.
//!
//! These captures hold both sources: each message as a UDP frame between the
//! SIP endpoints, and the same bytes wrapped in HEP v3 on 127.0.0.1:9063.
#![cfg(all(feature = "native", feature = "hep"))]

use std::path::{Path, PathBuf};

use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};

type TestError = Box<dyn std::error::Error>;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

/// The first second of every capture here, as `write_pcap_at` counts it.
const BASE_SECS: i64 = 1_700_000_000;

/// Which source a frame stands for.
#[derive(Clone, Copy)]
enum Src {
    /// A plain UDP frame between the endpoints.
    Wire,
    /// The same bytes in HEP v3 on 127.0.0.1:9063.
    Hep,
}

/// One frame: its source, the SIP text, and its time in microseconds after
/// [`BASE_SECS`].
type Ev = (Src, String, u64);

/// The call of these tests: seven messages, `INVITE` to the `BYE`'s `200`.
fn call(call_id: &str) -> Vec<String> {
    pcap_build::sip_call(call_id, "copies", "1001", "1002")
}

/// Whether message `i` of [`call`] goes caller to callee.
fn from_caller(i: usize) -> bool {
    matches!(i, 0 | 4 | 5)
}

/// The frame for one event.
fn frame(ev: &Ev, caller_side: bool) -> Result<Vec<u8>, TestError> {
    let a = [10, 1, 0, 1];
    let b = [10, 2, 0, 1];
    let (src, dst) = if caller_side { (a, b) } else { (b, a) };
    Ok(match ev.0 {
        Src::Wire => pcap_build::udp_frame(src, dst, 5060, 5060, ev.1.as_bytes()),
        Src::Hep => {
            let ep = HepEndpoint {
                src_addr: src.into(),
                dst_addr: dst.into(),
                src_port: 5060,
                dst_port: 5060,
                transport: sipnab::net::TransportProto::Udp,
            };
            let secs = BASE_SECS + (ev.2 / 1_000_000) as i64;
            let nanos = ((ev.2 % 1_000_000) * 1000) as u32;
            let ts = chrono::DateTime::from_timestamp(secs, nanos).ok_or("timestamp")?;
            let hep = build_hep_v3(&ep, ts, HepProtocol::Sip, 1, None, ev.1.as_bytes());
            pcap_build::udp_frame([127, 0, 0, 1], [127, 0, 0, 1], 40000, 9063, &hep)
        }
    })
}

/// Write `events` (each with its direction) to `dir/<name>`, in time order.
fn write(dir: &Path, name: &str, events: &[(Ev, bool)]) -> Result<PathBuf, TestError> {
    let mut sorted: Vec<&(Ev, bool)> = events.iter().collect();
    sorted.sort_by_key(|(ev, _)| ev.2);
    let frames = sorted
        .iter()
        .map(|(ev, dir)| Ok((frame(ev, *dir)?, ev.2)))
        .collect::<Result<Vec<_>, TestError>>()?;
    let path = dir.join(name);
    pcap_build::write_pcap_at(&path, &frames, 1)?;
    Ok(path)
}

/// The call `call_id` with message `i` at `i * 100 ms`, once per source in
/// `sources`, the source `k` of them `k` ms later than the first.
fn both(call_id: &str, sources: &[Src]) -> Vec<(Ev, bool)> {
    let mut out = Vec::new();
    for (i, msg) in call(call_id).into_iter().enumerate() {
        for (k, src) in sources.iter().enumerate() {
            let t = i as u64 * 100_000 + k as u64 * 1_000;
            out.push(((*src, msg.clone(), t), from_caller(i)));
        }
    }
    out
}

/// Run `sipnab -N -I <pcap> --hep-parse [extra] --json-dialogs` and return
/// the dialogs.
fn dialogs(pcap: &Path, extra: &[&str]) -> Result<Vec<serde_json::Value>, TestError> {
    let mut argv = vec!["-N", "-I", pcap.to_str().ok_or("utf-8")?, "--hep-parse"];
    argv.extend_from_slice(extra);
    argv.push("--json-dialogs");
    let (stdout, stderr, code) = run_support::run(&argv, Some("error"))?;
    assert_eq!(code, Some(0), "sipnab {argv:?}:\n{stderr}");
    Ok(stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

/// The one dialog of a run.
fn only(all: &[serde_json::Value]) -> Result<&serde_json::Value, TestError> {
    match all {
        [d] => Ok(d),
        _ => Err(format!("expected one dialog, got {all:?}").into()),
    }
}

/// `msg_count` and `timing.retransmits` of a dialog.
fn counts(d: &serde_json::Value) -> Result<(u64, u64), TestError> {
    Ok((
        d["msg_count"].as_u64().ok_or("msg_count")?,
        d["timing"]["retransmits"].as_u64().ok_or("retransmits")?,
    ))
}

/// A run of `events` in a fresh directory: its one dialog.
fn one_dialog(events: &[(Ev, bool)], extra: &[&str]) -> Result<serde_json::Value, TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write(dir.path(), "c.pcap", events)?;
    Ok(only(&dialogs(&pcap, extra)?)?.clone())
}

// ── SUCCESS ──────────────────────────────────────────────────────────────

/// The reported case: seven messages, each seen twice, count seven.
#[test]
fn a_call_seen_on_the_wire_and_by_hep_counts_each_message_once() -> Result<(), TestError> {
    let d = one_dialog(&both("c1@example.com", &[Src::Wire, Src::Hep]), &[])?;
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    Ok(())
}

/// A copy is not a retransmission.
#[test]
fn a_copy_is_not_counted_as_a_retransmission() -> Result<(), TestError> {
    let d = one_dialog(&both("c2@example.com", &[Src::Wire, Src::Hep]), &[])?;
    assert_eq!(d["timing"]["retransmits"], 0, "{d}");
    Ok(())
}

/// What each source delivered stays visible.
#[test]
fn seen_by_counts_what_each_source_delivered() -> Result<(), TestError> {
    let d = one_dialog(&both("c3@example.com", &[Src::Wire, Src::Hep]), &[])?;
    assert_eq!(
        d["seen_by"],
        serde_json::json!({"wire": 7, "hep": 7}),
        "{d}"
    );
    Ok(())
}

/// HEP first: the same answer.
#[test]
fn hep_first_counts_each_message_once() -> Result<(), TestError> {
    let d = one_dialog(&both("c4@example.com", &[Src::Hep, Src::Wire]), &[])?;
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    assert_eq!(
        d["seen_by"],
        serde_json::json!({"wire": 7, "hep": 7}),
        "{d}"
    );
    Ok(())
}

/// The merged dialog says what the wire alone says.
#[test]
fn the_merged_dialog_matches_the_wire_alone() -> Result<(), TestError> {
    let merged = one_dialog(&both("c5@example.com", &[Src::Wire, Src::Hep]), &[])?;
    let wire = one_dialog(&both("c5@example.com", &[Src::Wire]), &[])?;
    for key in ["msg_count", "state", "final_status_code", "method"] {
        assert_eq!(merged[key], wire[key], "{key}");
    }
    assert_eq!(
        merged["timing"]["retransmits"], wire["timing"]["retransmits"],
        "retransmits"
    );
    Ok(())
}

/// And what HEP alone says.
#[test]
fn the_merged_dialog_matches_hep_alone() -> Result<(), TestError> {
    let merged = one_dialog(&both("c6@example.com", &[Src::Wire, Src::Hep]), &[])?;
    let hep = one_dialog(&both("c6@example.com", &[Src::Hep]), &[])?;
    assert_eq!(counts(&merged)?, counts(&hep)?, "counts");
    assert_eq!(merged["state"], hep["state"], "state");
    Ok(())
}

/// The parallel path (`--cores 2`) merges the same way.
#[test]
fn two_cores_count_each_message_once() -> Result<(), TestError> {
    let d = one_dialog(
        &both("c7@example.com", &[Src::Wire, Src::Hep]),
        &["--cores", "2"],
    )?;
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    Ok(())
}

/// The dialog's origin is the source of its first message, as before.
#[test]
fn the_dialog_origin_is_its_first_source() -> Result<(), TestError> {
    let d = one_dialog(&both("c8@example.com", &[Src::Wire, Src::Hep]), &[])?;
    assert_eq!(d["input_origin"], "wire", "{d}");
    let h = one_dialog(&both("c8@example.com", &[Src::Hep, Src::Wire]), &[])?;
    assert_eq!(h["input_origin"], "hep", "{h}");
    Ok(())
}

/// A real retransmission is still one, and each of its copies merges.
#[test]
fn a_retransmission_seen_by_both_is_one_retransmission() -> Result<(), TestError> {
    let mut ev = both("c9@example.com", &[Src::Wire, Src::Hep]);
    let invite = call("c9@example.com")[0].clone();
    // The INVITE again, 50 ms after the first, between it and the 100.
    ev.push(((Src::Wire, invite.clone(), 50_000), true));
    ev.push(((Src::Hep, invite, 51_000), true));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (8, 1), "{d}");
    assert_eq!(
        d["seen_by"],
        serde_json::json!({"wire": 8, "hep": 8}),
        "{d}"
    );
    Ok(())
}

/// Two calls in one capture: each counts its own messages once.
#[test]
fn two_calls_each_count_their_messages_once() -> Result<(), TestError> {
    let mut ev = both("d1@example.com", &[Src::Wire, Src::Hep]);
    ev.extend(both("d2@example.com", &[Src::Wire, Src::Hep]));
    let dir = tempfile::tempdir()?;
    let pcap = write(dir.path(), "two.pcap", &ev)?;
    let all = dialogs(&pcap, &[])?;
    assert_eq!(all.len(), 2, "{all:?}");
    for d in &all {
        assert_eq!(counts(d)?, (7, 0), "{d}");
    }
    Ok(())
}

/// The message stream (`--json`) still prints every arrival with its own
/// source: it reports what arrived, not the dialog.
#[test]
fn the_message_stream_still_prints_each_arrival() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write(
        dir.path(),
        "s.pcap",
        &both("c10@example.com", &[Src::Wire, Src::Hep]),
    )?;
    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().ok_or("utf-8")?,
            "--hep-parse",
            "--json",
        ],
        Some("error"),
    )?;
    assert_eq!(code, Some(0), "{stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| l.starts_with('{')).collect();
    assert_eq!(lines.len(), 14, "{stdout}");
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.contains("\"input_origin\":\"hep\""))
            .count(),
        7,
        "seven of the arrivals came over HEP:\n{stdout}"
    );
    Ok(())
}

// ── FAILURE: what is NOT a copy ──────────────────────────────────────────

/// The same message twice from the same source is a retransmission.
#[test]
fn twice_from_the_wire_is_a_retransmission() -> Result<(), TestError> {
    let mut ev = both("f1@example.com", &[Src::Wire]);
    ev.push(((Src::Wire, call("f1@example.com")[0].clone(), 50_000), true));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (8, 1), "{d}");
    Ok(())
}

/// Twice from HEP alone: a retransmission too.
#[test]
fn twice_from_hep_is_a_retransmission() -> Result<(), TestError> {
    let mut ev = both("f2@example.com", &[Src::Hep]);
    ev.push(((Src::Hep, call("f2@example.com")[0].clone(), 50_000), true));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (8, 1), "{d}");
    Ok(())
}

/// A HEP report whose bytes differ from the wire's is not merged: the two
/// sources disagree, and both are kept.
#[test]
fn a_report_with_different_bytes_is_kept_apart() -> Result<(), TestError> {
    let mut ev = both("f3@example.com", &[Src::Wire]);
    let changed = call("f3@example.com")[5].replace("Max-Forwards: 70", "Max-Forwards: 69");
    ev.push(((Src::Hep, changed, 5 * 100_000 + 1_000), true));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(d["msg_count"], 8, "{d}");
    Ok(())
}

/// A HEP report 10 s after the wire copy is not a copy of it.
#[test]
fn a_report_far_outside_the_window_is_not_merged() -> Result<(), TestError> {
    let mut ev = both("f4@example.com", &[Src::Wire]);
    ev.push((
        (Src::Hep, call("f4@example.com")[5].clone(), 10_500_000),
        true,
    ));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(d["msg_count"], 8, "{d}");
    Ok(())
}

/// A message only HEP reported shows in the counts.
#[test]
fn a_message_only_hep_reported_shows_in_seen_by() -> Result<(), TestError> {
    let ev: Vec<(Ev, bool)> = both("f5@example.com", &[Src::Wire, Src::Hep])
        .into_iter()
        .filter(|((src, text, _), _)| {
            !(matches!(src, Src::Wire) && text.starts_with("SIP/2.0 180"))
        })
        .collect();
    let d = one_dialog(&ev, &[])?;
    assert_eq!(d["msg_count"], 7, "{d}");
    assert_eq!(
        d["seen_by"],
        serde_json::json!({"wire": 6, "hep": 7}),
        "{d}"
    );
    Ok(())
}

/// A message only the wire carried shows too.
#[test]
fn a_message_only_the_wire_carried_shows_in_seen_by() -> Result<(), TestError> {
    let ev: Vec<(Ev, bool)> = both("f6@example.com", &[Src::Wire, Src::Hep])
        .into_iter()
        .filter(|((src, text, _), _)| !(matches!(src, Src::Hep) && text.starts_with("BYE")))
        .collect();
    let d = one_dialog(&ev, &[])?;
    assert_eq!(d["msg_count"], 7, "{d}");
    assert_eq!(
        d["seen_by"],
        serde_json::json!({"wire": 7, "hep": 6}),
        "{d}"
    );
    Ok(())
}

/// A run of one source prints no `seen_by`.
#[test]
fn a_wire_only_run_has_no_seen_by() -> Result<(), TestError> {
    let d = one_dialog(&both("f7@example.com", &[Src::Wire]), &[])?;
    assert!(d.get("seen_by").is_none(), "{d}");
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    Ok(())
}

/// Nor does a HEP-only run.
#[test]
fn a_hep_only_run_has_no_seen_by() -> Result<(), TestError> {
    let d = one_dialog(&both("f8@example.com", &[Src::Hep]), &[])?;
    assert!(d.get("seen_by").is_none(), "{d}");
    Ok(())
}

// ── EDGE ─────────────────────────────────────────────────────────────────

/// Copies 1.9 s apart (a HEP sender's clock ahead of the capture) merge.
#[test]
fn copies_just_inside_the_window_merge() -> Result<(), TestError> {
    let mut ev = both("e1@example.com", &[Src::Wire]);
    for (i, msg) in call("e1@example.com").into_iter().enumerate() {
        ev.push((
            (Src::Hep, msg, i as u64 * 100_000 + 1_900_000),
            from_caller(i),
        ));
    }
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    Ok(())
}

/// Copies 2.1 s apart do not.
#[test]
fn copies_just_outside_the_window_stay_apart() -> Result<(), TestError> {
    let mut ev = both("e2@example.com", &[Src::Wire]);
    ev.push((
        (
            Src::Hep,
            call("e2@example.com")[5].clone(),
            5 * 100_000 + 2_100_000,
        ),
        true,
    ));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(d["msg_count"], 8, "{d}");
    Ok(())
}

/// Each HEP copy of a retransmitted INVITE pairs with its own wire copy:
/// one retransmission, not two and not none.
#[test]
fn each_copy_of_a_retransmission_pairs_once() -> Result<(), TestError> {
    let mut ev = both("e3@example.com", &[Src::Wire]);
    let invite = call("e3@example.com")[0].clone();
    ev.push(((Src::Wire, invite.clone(), 50_000), true));
    ev.push(((Src::Hep, invite.clone(), 1_000), true));
    ev.push(((Src::Hep, invite, 51_000), true));
    for (i, msg) in call("e3@example.com").into_iter().enumerate().skip(1) {
        ev.push(((Src::Hep, msg, i as u64 * 100_000 + 1_000), from_caller(i)));
    }
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (8, 1), "{d}");
    Ok(())
}

/// A third HEP copy of a message both sources already gave is a
/// retransmission of HEP's, not another copy.
#[test]
fn a_second_hep_copy_is_a_hep_retransmission() -> Result<(), TestError> {
    let mut ev = both("e4@example.com", &[Src::Wire, Src::Hep]);
    ev.push((
        (
            Src::Hep,
            call("e4@example.com")[5].clone(),
            5 * 100_000 + 2_000,
        ),
        true,
    ));
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (8, 1), "{d}");
    Ok(())
}

/// Copies with the same timestamp merge.
#[test]
fn copies_at_the_same_instant_merge() -> Result<(), TestError> {
    let mut ev = Vec::new();
    for (i, msg) in call("e5@example.com").into_iter().enumerate() {
        let t = i as u64 * 100_000;
        ev.push(((Src::Wire, msg.clone(), t), from_caller(i)));
        ev.push(((Src::Hep, msg, t), from_caller(i)));
    }
    let d = one_dialog(&ev, &[])?;
    assert_eq!(counts(&d)?, (7, 0), "{d}");
    Ok(())
}

/// The analysis of the merged call ranks no retransmission pattern.
#[test]
fn the_analysis_of_a_merged_call_has_no_retransmissions() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = write(
        dir.path(),
        "a.pcap",
        &both("e6@example.com", &[Src::Wire, Src::Hep]),
    )?;
    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            pcap.to_str().ok_or("utf-8")?,
            "--hep-parse",
            "--analyze",
        ],
        Some("error"),
    )?;
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stdout.to_lowercase().contains("retransmi"), "{stdout}");
    Ok(())
}
