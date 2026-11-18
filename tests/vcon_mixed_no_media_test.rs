// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A run that reads a vCon and a pcap with RTP must not call the vCon's
//! answered call `no_media`.
//!
//! `no_media` means "this call negotiated media, was answered, and none of
//! its RTP was seen, in a capture that did see RTP". The last clause was read
//! off the whole run, so the pcap's RTP made it true for the vCon's call as
//! well, and `-I call.vcon.json -I other.pcap` reported the vCon's call
//! `no_media` where `-I call.vcon.json` alone did not. A vCon carries a
//! call's signaling and none of its packets: this run's RTP is no evidence
//! about that call. Wire and HEP calls keep the run's fact, because a
//! composite run takes the signaling from HEP and the RTP from the wire.
#![cfg(all(feature = "native", feature = "vcon"))]

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

#[path = "support/run.rs"]
mod run_support;

/// The vCon fixture: one answered G.711 call, `1-1966@10.0.2.20`.
const VCON: &str = "tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json";
/// The vCon's call id.
const VCON_CALL: &str = "1-1966@10.0.2.20";
/// A pcap with one answered G.722 call and its RTP, `1-2161@10.0.2.20`.
const RTP_PCAP: &str = "tests/pcap-samples/sip-rtp-g722.pcap";
/// That pcap's call id.
const RTP_CALL: &str = "1-2161@10.0.2.20";
/// The capture the vCon fixture was made from.
const G711_PCAP: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Run `sipnab -N <args> --json-dialogs` and return every dialog object.
fn dialogs(args: &[&str]) -> Result<Vec<serde_json::Value>, TestError> {
    let mut argv = vec!["-N"];
    argv.extend_from_slice(args);
    argv.push("--json-dialogs");
    let (stdout, stderr, code) = run_support::run(&argv, Some("error"))?;
    assert_eq!(code, Some(0), "sipnab {argv:?} failed:\n{stderr}");
    Ok(stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

/// The dialog with `call_id`.
fn dialog<'a>(
    all: &'a [serde_json::Value],
    call_id: &str,
) -> Result<&'a serde_json::Value, TestError> {
    all.iter()
        .find(|d| d["call_id"] == call_id)
        .ok_or_else(|| format!("no dialog {call_id} in {all:?}").into())
}

/// The `no_media` verdict of `call_id`.
fn no_media(all: &[serde_json::Value], call_id: &str) -> Result<bool, TestError> {
    dialog(all, call_id)?["diagnosis"]["no_media"]
        .as_bool()
        .ok_or_else(|| format!("{call_id} has no diagnosis.no_media").into())
}

/// The call ids a run prints, sorted.
fn call_ids(all: &[serde_json::Value]) -> Vec<String> {
    let mut ids: Vec<String> = all
        .iter()
        .filter_map(|d| d["call_id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids
}

/// The G.711 capture's signaling alone, written to `dir`: the vCon's call as
/// a wire call whose RTP this run never sees.
fn signaling_only(dir: &Path) -> Result<PathBuf, TestError> {
    let out = dir.join("sig.pcap");
    let o = out.to_str().ok_or("utf-8")?;
    let (_, stderr, code) = run_support::run(
        &["-N", "-I", G711_PCAP, "-O", o, "udp", "port", "5060"],
        Some("error"),
    )?;
    assert_eq!(code, Some(0), "building the signaling-only copy:\n{stderr}");
    Ok(out)
}

// ── SUCCESS ──────────────────────────────────────────────────────────────

/// The reported case: the vCon's call is not `no_media` beside a pcap's RTP.
#[test]
fn a_vcon_call_beside_a_pcap_with_rtp_is_not_no_media() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// The input order does not change it.
#[test]
fn the_pcap_first_gives_the_same_verdict() -> Result<(), TestError> {
    let all = dialogs(&["-I", RTP_PCAP, "-I", VCON])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// The mixed run and the vCon alone agree.
#[test]
fn the_mixed_run_agrees_with_the_vcon_alone() -> Result<(), TestError> {
    let alone = dialogs(&["-I", VCON])?;
    let mixed = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert_eq!(
        no_media(&mixed, VCON_CALL)?,
        no_media(&alone, VCON_CALL)?,
        "the pcap beside it must not change the vCon's verdict"
    );
    Ok(())
}

/// The pcap's own call is unchanged: it has its stream and no finding.
#[test]
fn the_pcap_call_keeps_its_verdict() -> Result<(), TestError> {
    let alone = dialogs(&["-I", RTP_PCAP])?;
    let mixed = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert_eq!(
        no_media(&mixed, RTP_CALL)?,
        no_media(&alone, RTP_CALL)?,
        "pcap call"
    );
    assert!(!no_media(&mixed, RTP_CALL)?, "it carries RTP");
    Ok(())
}

/// The vCon's call is still reported as coming from the vCon.
#[test]
fn the_vcon_call_still_names_its_origin() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert_eq!(dialog(&all, VCON_CALL)?["input_origin"], "vcon", "origin");
    assert_eq!(dialog(&all, RTP_CALL)?["input_origin"], "wire", "origin");
    Ok(())
}

/// Both calls are printed.
#[test]
fn the_mixed_run_prints_both_calls() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert_eq!(
        call_ids(&all),
        vec![VCON_CALL.to_string(), RTP_CALL.to_string()],
        "the vCon's call and the pcap's call"
    );
    Ok(())
}

/// The vCon's call has no stream of its own in this run.
#[test]
fn the_vcon_call_has_no_stream() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    let streams = dialog(&all, VCON_CALL)?["streams"]
        .as_array()
        .map(Vec::len)
        .ok_or("streams")?;
    assert_eq!(streams, 0, "a vCon brings no packets");
    Ok(())
}

/// `--filter "no_media == true"` no longer selects the vCon's call.
#[test]
fn a_no_media_filter_does_not_select_the_vcon_call() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP, "--filter", "no_media == true"])?;
    assert!(
        !call_ids(&all).contains(&VCON_CALL.to_string()),
        "selected: {:?}",
        call_ids(&all)
    );
    Ok(())
}

/// `--filter "no_media == false"` selects both calls.
#[test]
fn the_inverse_filter_selects_both_calls() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP, "--filter", "no_media == false"])?;
    assert_eq!(
        call_ids(&all),
        vec![VCON_CALL.to_string(), RTP_CALL.to_string()],
        "neither call is no_media, so both are selected"
    );
    Ok(())
}

/// The vCon's call carries no "no RTP was observed" hint.
#[test]
fn the_vcon_call_has_no_no_rtp_hint() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    let text = dialog(&all, VCON_CALL)?.to_string();
    assert!(!text.contains("no RTP was observed"), "{text}");
    Ok(())
}

// ── FAILURE: the verdict still fires where the run's RTP is evidence ─────

/// The same call as a wire capture without its RTP, beside a pcap with RTP,
/// is still `no_media`: those packets were this run's to see.
#[test]
fn the_same_call_from_the_wire_without_rtp_is_still_no_media() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&["-I", sig.to_str().ok_or("utf-8")?, "-I", RTP_PCAP])?;
    assert!(no_media(&all, VCON_CALL)?, "{:?}", dialog(&all, VCON_CALL)?);
    Ok(())
}

/// That wire call carries the hint naming what was not observed.
#[test]
fn the_wire_call_without_rtp_carries_the_hint() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&["-I", sig.to_str().ok_or("utf-8")?, "-I", RTP_PCAP])?;
    let text = dialog(&all, VCON_CALL)?.to_string();
    assert!(text.contains("no RTP was observed"), "{text}");
    Ok(())
}

/// And the no_media filter selects it.
#[test]
fn the_no_media_filter_selects_the_wire_call() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&[
        "-I",
        sig.to_str().ok_or("utf-8")?,
        "-I",
        RTP_PCAP,
        "--filter",
        "no_media == true",
    ])?;
    assert!(
        call_ids(&all).contains(&VCON_CALL.to_string()),
        "selected: {:?}",
        call_ids(&all)
    );
    Ok(())
}

/// The vCon alone: no RTP anywhere, no verdict.
#[test]
fn the_vcon_alone_is_not_no_media() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON])?;
    assert!(!no_media(&all, VCON_CALL)?, "no RTP in the run");
    Ok(())
}

/// The wire call alone, without RTP anywhere, is not `no_media` either.
#[test]
fn the_wire_call_alone_without_rtp_is_not_no_media() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&["-I", sig.to_str().ok_or("utf-8")?])?;
    assert!(!no_media(&all, VCON_CALL)?, "no RTP in the run");
    Ok(())
}

// ── --analyze: the "No media on an answered call" pattern ───────────────

/// The pattern title `--analyze` prints for `no_media`.
const PATTERN: &str = "No media on an answered call";

/// `sipnab -N <args> --analyze`'s stdout.
fn analyze(args: &[&str]) -> Result<String, TestError> {
    let mut argv = vec!["-N"];
    argv.extend_from_slice(args);
    argv.push("--analyze");
    let (stdout, stderr, code) = run_support::run(&argv, Some("error"))?;
    assert_eq!(code, Some(0), "sipnab {argv:?} failed:\n{stderr}");
    Ok(stdout)
}

/// The mixed run's analysis ranks no no-media pattern.
#[test]
fn the_mixed_analysis_has_no_no_media_pattern() -> Result<(), TestError> {
    let text = analyze(&["-I", VCON, "-I", RTP_PCAP])?;
    assert!(!text.contains(PATTERN), "{text}");
    Ok(())
}

/// Nor with the pcap read first.
#[test]
fn the_pcap_first_analysis_has_no_no_media_pattern() -> Result<(), TestError> {
    let text = analyze(&["-I", RTP_PCAP, "-I", VCON])?;
    assert!(!text.contains(PATTERN), "{text}");
    Ok(())
}

/// The analysis still says the vCon holds no RTP.
#[test]
fn the_mixed_analysis_still_says_a_vcon_holds_no_rtp() -> Result<(), TestError> {
    let text = analyze(&["-I", VCON, "-I", RTP_PCAP])?;
    assert!(text.contains("A vCon holds no RTP"), "{text}");
    Ok(())
}

/// The wire call without its RTP beside RTP is ranked as no-media.
#[test]
fn the_wire_analysis_without_rtp_ranks_the_pattern() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let text = analyze(&["-I", sig.to_str().ok_or("utf-8")?, "-I", RTP_PCAP])?;
    assert!(text.contains(PATTERN), "{text}");
    Ok(())
}

/// The vCon beside its own capture: no pattern.
#[test]
fn a_vcon_beside_its_own_capture_ranks_no_pattern() -> Result<(), TestError> {
    let text = analyze(&["-I", VCON, "-I", G711_PCAP])?;
    assert!(!text.contains(PATTERN), "{text}");
    Ok(())
}

// ── EDGE ─────────────────────────────────────────────────────────────────

/// The vCon and the call's signaling-only wire copy share a Call-ID and
/// become one dialog. Part of it was captured by this run, so beside RTP it
/// is judged as the wire call is.
#[test]
fn a_call_from_a_vcon_and_from_the_wire_is_judged_as_the_wire_call() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&[
        "-I",
        VCON,
        "-I",
        sig.to_str().ok_or("utf-8")?,
        "-I",
        RTP_PCAP,
    ])?;
    assert!(no_media(&all, VCON_CALL)?, "{:?}", dialog(&all, VCON_CALL)?);
    Ok(())
}

/// The same pair without RTP anywhere: no verdict.
#[test]
fn a_call_from_a_vcon_and_from_the_wire_without_rtp_is_not_no_media() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let sig = signaling_only(dir.path())?;
    let all = dialogs(&["-I", VCON, "-I", sig.to_str().ok_or("utf-8")?])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// The vCon and its own source capture together: the call is read twice and
/// the wire copy's RTP is the call's own, so it is not `no_media`.
#[test]
fn a_vcon_beside_its_own_capture_is_not_no_media() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", G711_PCAP])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// The vCon read twice beside RTP: still not `no_media`.
#[test]
fn a_vcon_given_twice_beside_rtp_is_not_no_media() -> Result<(), TestError> {
    let all = dialogs(&["-I", VCON, "-I", VCON, "-I", RTP_PCAP])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// Two pcaps with RTP beside the vCon: still not `no_media`.
#[test]
fn a_vcon_beside_two_rtp_pcaps_is_not_no_media() -> Result<(), TestError> {
    let all = dialogs(&[
        "-I",
        VCON,
        "-I",
        RTP_PCAP,
        "-I",
        "tests/pcap-samples/sip-rtp-g729a.pcap",
    ])?;
    assert!(
        !no_media(&all, VCON_CALL)?,
        "{:?}",
        dialog(&all, VCON_CALL)?
    );
    Ok(())
}

/// The vCon's other diagnosis fields are what the vCon alone gives.
#[test]
fn the_rest_of_the_vcon_diagnosis_is_unchanged() -> Result<(), TestError> {
    let alone = dialogs(&["-I", VCON])?;
    let mixed = dialogs(&["-I", VCON, "-I", RTP_PCAP])?;
    assert_eq!(
        dialog(&mixed, VCON_CALL)?["diagnosis"],
        dialog(&alone, VCON_CALL)?["diagnosis"],
        "the whole diagnosis object"
    );
    Ok(())
}
