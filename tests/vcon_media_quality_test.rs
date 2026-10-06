// SPDX-License-Identifier: MIT OR Apache-2.0

//! A vCon export carries the call's MOS, as every other surface does (CMP6).
//!
//! The call report and the vCon were the two surfaces that carried no
//! quality figure at all. The container's analysis body now lists each RTP
//! stream's MOS, R-factor and what the MOS rests on, from the projection
//! `GET /v1/streams` serializes.

#![cfg(feature = "vcon")]

use std::process::Command;

const PCAP: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/pcap-samples/sip-rtp-g711.pcap"
);

#[test]
fn an_exported_vcon_carries_the_calls_mos() {
    let dialogs = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            PCAP,
            "--no-config",
            "--json-dialogs",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "off")
        .output()
        .expect("run sipnab");
    let first: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&dialogs.stdout)
            .lines()
            .next()
            .expect("one dialog"),
    )
    .expect("dialog JSON");
    let call_id = first["call_id"].as_str().expect("call_id").to_string();

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("call.vcon.json");
    let run = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            PCAP,
            "--no-config",
            "--export-vcon",
            &call_id,
            "--vcon-out",
        ])
        .arg(&out)
        .env("SIPNAB_LOG", "off")
        .output()
        .expect("run sipnab");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let vcon: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("container")).expect("JSON");
    let body: serde_json::Value =
        serde_json::from_str(vcon["analysis"][0]["body"].as_str().expect("body string"))
            .expect("body JSON");
    let rows = body["media_quality"]
        .as_array()
        .unwrap_or_else(|| panic!("no media_quality: {body}"));
    assert!(!rows.is_empty(), "{body}");
    for row in rows {
        assert!(row["mos"].is_number(), "{row}");
        assert!(row["r_factor"].is_number(), "{row}");
        assert_eq!(row["mos_grounded"], true, "G.711 is published: {row}");
    }
}

/// The end-of-run export states how many frames the run read: the count the
/// run hands to the reports with its stores (`batch::CaptureRead`).
/// `sip_call.pcap` holds 7 frames.
#[test]
fn an_exported_vcon_states_how_many_frames_the_run_read() {
    const SIP_CALL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let dialogs = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            SIP_CALL,
            "--no-config",
            "--json-dialogs",
            "--no-cli-print",
        ])
        .env("SIPNAB_LOG", "off")
        .output()
        .expect("run sipnab");
    let first: serde_json::Value = serde_json::from_str(
        String::from_utf8_lossy(&dialogs.stdout)
            .lines()
            .next()
            .expect("one dialog"),
    )
    .expect("dialog JSON");
    let call_id = first["call_id"].as_str().expect("call_id").to_string();
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("call.vcon.json");
    let run = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            SIP_CALL,
            "--no-config",
            "--export-vcon",
            &call_id,
            "--vcon-out",
        ])
        .arg(&out)
        .env("SIPNAB_LOG", "off")
        .output()
        .expect("run sipnab");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let vcon: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).expect("container")).expect("JSON");
    let body: serde_json::Value =
        serde_json::from_str(vcon["analysis"][0]["body"].as_str().expect("body string"))
            .expect("body JSON");
    assert_eq!(body["capture_completeness"]["frames_read"], 7, "{body}");
}
