// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A call that crosses a B2BUA or a PBX is two dialogs, and so two containers.
//! Each container names the other leg's container and how strongly the two
//! are tied, so a reader can join them and can tell an identifier match from
//! a timing guess.
#![cfg(all(feature = "native", feature = "vcon"))]

#[path = "support/pcap_build.rs"]
mod pcap_build;
mod support;

use std::path::Path;
use std::process::Command;

use pcap_build::{leg_invite as invite, write_pcap_at};

type TestError = Box<dyn std::error::Error>;

const RELATED: &str = "sipnab-related-legs";

/// The containers in `dir`, keyed by the Call-ID of their signaling object.
fn containers(dir: &Path) -> Result<Vec<(String, serde_json::Value)>, TestError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".vcon.json") {
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            let call_id = v["dialog"][0]["sip_call_id"]
                .as_str()
                .ok_or("a signaling object")?
                .to_owned();
            out.push((call_id, v));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The related-legs attachment's body, parsed, or `None` when there is none.
fn related(container: &serde_json::Value) -> Result<Option<serde_json::Value>, TestError> {
    let found = container["attachments"]
        .as_array()
        .ok_or("attachments")?
        .iter()
        .find(|a| a["purpose"] == RELATED);
    match found {
        None => Ok(None),
        Some(a) if a["body"].is_object() => Ok(Some(a["body"].clone())),
        Some(a) => Err(format!("the related-legs body is the object itself: {a}").into()),
    }
}

/// Run sipnab over `frames` with `config`, exporting into `dir`.
fn export(
    home: &Path,
    frames: &[(Vec<u8>, u64)],
    config: &str,
    dir: &Path,
) -> Result<String, TestError> {
    export_with(home, frames, config, dir, &[])
}

/// [`export`], with `extra` arguments.
fn export_with(
    home: &Path,
    frames: &[(Vec<u8>, u64)],
    config: &str,
    dir: &Path,
    extra: &[&str],
) -> Result<String, TestError> {
    let pcap = home.join("legs.pcap");
    write_pcap_at(&pcap, frames, 1)?;
    let cfg = home.join("sipnab.toml");
    std::fs::write(&cfg, config)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--no-cli-print", "-I"])
        .arg(&pcap)
        .arg("--config")
        .arg(&cfg)
        .args(["--export-vcon-when", "call_id =~ '.'", "--export-vcon-dir"])
        .arg(dir)
        .args(extra)
        .env("HOME", home)
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "{stderr}");
    Ok(stderr)
}

/// Two legs tied by `X-Call-ID`: each container names the other's uuid, and
/// says the tie is an identifier match.
#[test]
fn each_leg_names_the_other_legs_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let frames = [
        (invite("a-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        (
            invite("b-leg", [10, 2, 0, 1], [10, 3, 0, 1], Some("a-leg")),
            30_000_000,
        ),
    ];
    let stderr = export(
        home.path(),
        &frames,
        "[sip]\nxcid_headers = [\"X-Call-ID\"]\n",
        &dir,
    )?;
    let written = containers(&dir)?;
    assert_eq!(written.len(), 2, "{stderr}");
    let (a, b) = (&written[0].1, &written[1].1);
    let validator = support::schema::load_validator("vcon.schema.json")?;
    for container in [a, b] {
        support::schema::assert_valid(&validator, container, "a linked leg's container");
    }
    for (this, other) in [(a, b), (b, a)] {
        let body = related(this)?.ok_or("a related-legs attachment")?;
        let legs = body["legs"].as_array().ok_or("legs")?;
        assert_eq!(legs.len(), 1, "{body}");
        assert_eq!(legs[0]["uuid"], other["uuid"], "{body}");
        assert_eq!(legs[0]["strategy"], "x_call_id", "{body}");
        assert_eq!(legs[0]["identifier_match"], true, "{body}");
        let score = legs[0]["score"].as_u64().ok_or("a score")?;
        assert!((1..=100).contains(&score), "{body}");
    }
    Ok(())
}

/// Two legs tied only by timing: the link is written and says it is a guess.
#[test]
fn a_timing_tie_is_stated_as_a_guess() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let frames = [
        (invite("in-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        (
            invite("out-leg", [10, 2, 0, 1], [10, 3, 0, 1], None),
            20_000,
        ),
    ];
    let stderr = export(home.path(), &frames, "", &dir)?;
    let written = containers(&dir)?;
    assert_eq!(written.len(), 2, "{stderr}");
    for (_, container) in &written {
        let body = related(container)?.ok_or("a related-legs attachment")?;
        assert_eq!(body["legs"][0]["strategy"], "timing_heuristic", "{body}");
        assert_eq!(body["legs"][0]["identifier_match"], false, "{body}");
    }
    Ok(())
}

/// A call with no other leg carries no related-legs attachment.
#[test]
fn a_lone_call_names_no_other_leg() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let frames = [(invite("alone", [10, 1, 0, 1], [10, 2, 0, 1], None), 0)];
    let stderr = export(home.path(), &frames, "", &dir)?;
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    assert_eq!(related(&written[0].1)?, None);
    Ok(())
}

/// Redaction keeps the link: a redacted container still names the other leg's
/// container by the uuid that container carries.
#[test]
fn a_redacted_container_still_names_the_other_leg() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let frames = [
        (invite("in-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        (
            invite("out-leg", [10, 2, 0, 1], [10, 3, 0, 1], None),
            20_000,
        ),
    ];
    let stderr = export_with(home.path(), &frames, "", &dir, &["--redact"])?;
    let mut uuids = Vec::new();
    let mut linked = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.to_string_lossy().ends_with(".vcon.json") {
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            uuids.push(v["uuid"].as_str().ok_or("uuid")?.to_owned());
            let body = related(&v)?.ok_or("a related-legs attachment")?;
            linked.push(
                body["legs"][0]["uuid"]
                    .as_str()
                    .ok_or("leg uuid")?
                    .to_owned(),
            );
        }
    }
    assert_eq!(uuids.len(), 2, "{stderr}");
    linked.reverse();
    assert_eq!(uuids, linked, "each names the other's uuid");
    Ok(())
}

/// `--export-vcon CALL-ID --vcon-out FILE`, the one-container export, names
/// the other leg as the directory export does.
#[test]
fn the_single_container_export_names_the_other_leg() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let pcap = home.path().join("legs.pcap");
    pcap_build::write_two_linked_legs(&pcap)?;
    let cfg = home.path().join("sipnab.toml");
    std::fs::write(&cfg, "[sip]\nxcid_headers = [\"X-Call-ID\"]\n")?;
    let mut uuids = Vec::new();
    let mut linked = Vec::new();
    for call_id in ["a-leg", "b-leg"] {
        let file = home.path().join(format!("{call_id}.vcon.json"));
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "--no-cli-print", "-I"])
            .arg(&pcap)
            .arg("--config")
            .arg(&cfg)
            .args(["--export-vcon", call_id, "--vcon-out"])
            .arg(&file)
            .env("HOME", home.path())
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&file)?)?;
        uuids.push(v["uuid"].clone());
        let body = related(&v)?.ok_or("a related-legs attachment")?;
        linked.push(body["legs"][0]["uuid"].clone());
    }
    linked.reverse();
    assert_eq!(uuids, linked, "each names the other's uuid");
    Ok(())
}

/// A leg tied to two others lists the identifier tie before the timing guess.
#[test]
fn the_stronger_tie_is_listed_first() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("out");
    let frames = [
        (invite("a-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        // Inside the timing window of a-leg, sharing its address.
        (invite("c-leg", [10, 2, 0, 1], [10, 4, 0, 1], None), 20_000),
        // Far outside the window, tied by X-Call-ID alone.
        (
            invite("b-leg", [10, 5, 0, 1], [10, 6, 0, 1], Some("a-leg")),
            30_000_000,
        ),
    ];
    let stderr = export(
        home.path(),
        &frames,
        "[sip]\nxcid_headers = [\"X-Call-ID\"]\n",
        &dir,
    )?;
    let written = containers(&dir)?;
    let (_, a) = written
        .iter()
        .find(|(id, _)| id == "a-leg")
        .ok_or("a-leg's container")?;
    let body = related(a)?.ok_or("a related-legs attachment")?;
    let strategies: Vec<&str> = body["legs"]
        .as_array()
        .ok_or("legs")?
        .iter()
        .filter_map(|l| l["strategy"].as_str())
        .collect();
    assert_eq!(strategies, ["x_call_id", "timing_heuristic"], "{stderr}");
    Ok(())
}

const CALL_LEGS: &str = "sipnab-call-legs";

/// A rule writing into `dir` with `grouping`, and `X-Call-ID` followed.
fn grouped(dir: &Path, grouping: &str) -> String {
    format!(
        "[sip]\nxcid_headers = [\"X-Call-ID\"]\n\n[[vcon.rule]]\nname = \"calls\"\n\
         when = \"call_id =~ '.'\"\ndir = \"{}\"\ngrouping = \"{grouping}\"\n",
        dir.display()
    )
}

/// Run sipnab over `frames` with `config` and no export flags.
fn run_config(
    home: &Path,
    frames: &[(Vec<u8>, u64)],
    config: &str,
) -> Result<std::process::Output, TestError> {
    let pcap = home.join("legs.pcap");
    write_pcap_at(&pcap, frames, 1)?;
    let cfg = home.join("sipnab.toml");
    std::fs::write(&cfg, config)?;
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--no-cli-print", "-I"])
        .arg(&pcap)
        .arg("--config")
        .arg(&cfg)
        .env("HOME", home)
        .output()?)
}

fn linked_legs() -> [(Vec<u8>, u64); 2] {
    [
        (invite("a-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        (
            invite("b-leg", [10, 2, 0, 1], [10, 3, 0, 1], Some("a-leg")),
            30_000_000,
        ),
    ]
}

/// The body of the attachment with `purpose`, parsed.
fn attachment(container: &serde_json::Value, purpose: &str) -> Option<serde_json::Value> {
    container["attachments"]
        .as_array()?
        .iter()
        .find(|a| a["purpose"] == purpose)
        .map(|a| a["body"].clone())
        .filter(serde_json::Value::is_object)
}

/// Every party and dialog index the container holds points inside it.
fn assert_indices_resolve(v: &serde_json::Value) -> Result<(), TestError> {
    let parties = v["parties"].as_array().ok_or("parties")?.len() as u64;
    let dialogs = v["dialog"].as_array().ok_or("dialog")?.len() as u64;
    for d in v["dialog"].as_array().ok_or("dialog")? {
        for p in d["parties"].as_array().into_iter().flatten() {
            assert!(p.as_u64().ok_or("index")? < parties, "{d}");
        }
        for key in ["transferor", "transferee", "transfer_target"] {
            if let Some(p) = d[key].as_u64() {
                assert!(p < parties, "{key} {d}");
            }
        }
        for key in ["original", "consultation", "recording_set"] {
            if let Some(i) = d[key].as_u64() {
                assert!(i < dialogs, "{key} {d}");
            }
        }
    }
    for a in v["attachments"].as_array().ok_or("attachments")? {
        assert!(a["party"].as_u64().ok_or("party")? < parties, "{a}");
        assert!(a["dialog"].as_u64().ok_or("dialog")? < dialogs, "{a}");
    }
    for a in v["analysis"].as_array().ok_or("analysis")? {
        assert!(a["dialog"].as_u64().ok_or("dialog")? < dialogs, "{a}");
    }
    Ok(())
}

/// `grouping = "call"`: both legs in one container, each leg's signaling and
/// parties present, the tie stated, every index resolving, the container
/// valid core-04.
#[test]
fn a_call_rule_writes_both_legs_in_one_container() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let out = run_config(home.path(), &linked_legs(), &grouped(&dir, "call"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "one container for the call: {stderr}");
    let v = &written[0].1;
    let signaling: Vec<&str> = v["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .filter(|d| d["sip_call_id"].is_string() && d["type"] != "transfer")
        .filter_map(|d| d["sip_call_id"].as_str())
        .collect();
    assert_eq!(signaling, ["a-leg", "b-leg"], "{v}");
    // Two observed parties per leg, and one observer, last.
    let parties = v["parties"].as_array().ok_or("parties")?;
    assert_eq!(parties.len(), 5, "{v}");
    assert_eq!(parties[4]["role"], "observer", "{v}");
    assert_indices_resolve(v)?;
    // Each leg's trace, report and parties point at that leg, not at the
    // first leg's objects at the same offsets.
    let dialog = v["dialog"].as_array().ok_or("dialog")?;
    let call_of = |i: &serde_json::Value| -> Option<String> {
        dialog.get(usize::try_from(i.as_u64()?).ok()?)?["sip_call_id"]
            .as_str()
            .map(str::to_owned)
    };
    let traced: Vec<Option<String>> = v["attachments"]
        .as_array()
        .ok_or("attachments")?
        .iter()
        .filter(|a| a["purpose"] == "sip-message-trace")
        .map(|a| call_of(&a["dialog"]))
        .collect();
    assert_eq!(traced, [Some("a-leg".into()), Some("b-leg".into())], "{v}");
    let reported: Vec<Option<String>> = v["analysis"]
        .as_array()
        .ok_or("analysis")?
        .iter()
        .map(|a| call_of(&a["dialog"]))
        .collect();
    assert_eq!(
        reported,
        [Some("a-leg".into()), Some("b-leg".into())],
        "{v}"
    );
    let legs = attachment(v, CALL_LEGS).ok_or("a call-legs attachment")?;
    assert_eq!(
        legs["legs"],
        serde_json::json!([{ "dialog": 0 }, { "dialog": 1 }]),
        "{legs}"
    );
    assert_eq!(
        legs["ties"][0]["dialogs"],
        serde_json::json!([0, 1]),
        "{legs}"
    );
    assert_eq!(legs["truncated"], false, "{legs}");
    assert_eq!(legs["ties"][0]["strategy"], "x_call_id", "{legs}");
    assert_eq!(legs["ties"][0]["identifier_match"], true, "{legs}");
    assert_eq!(
        attachment(v, RELATED),
        None,
        "no link to leg containers that were not written"
    );
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, v, "a call container");
    Ok(())
}

/// The call container's uuid is its own: not either leg's, and the same on
/// a second run.
#[test]
fn a_call_container_has_its_own_stable_uuid() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let (calls, legs) = (home.path().join("calls"), home.path().join("legs"));
    let config = format!(
        "{}\n[[vcon.rule]]\nname = \"legs\"\nwhen = \"call_id =~ '.'\"\ndir = \"{}\"\n",
        grouped(&calls, "call"),
        legs.display()
    );
    let first = run_config(home.path(), &linked_legs(), &config)?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let call_uuid = containers(&calls)?[0].1["uuid"].clone();
    for (_, leg) in containers(&legs)? {
        assert_ne!(leg["uuid"], call_uuid);
    }
    std::fs::remove_dir_all(&calls)?;
    let second = run_config(home.path(), &linked_legs(), &config)?;
    assert!(second.status.success());
    assert_eq!(containers(&calls)?[0].1["uuid"], call_uuid);
    Ok(())
}

/// Two legs tied only by timing are grouped, and the container says the tie
/// is a guess.
#[test]
fn a_call_container_states_a_timing_tie() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let frames = [
        (invite("in-leg", [10, 1, 0, 1], [10, 2, 0, 1], None), 0),
        (
            invite("out-leg", [10, 2, 0, 1], [10, 3, 0, 1], None),
            20_000,
        ),
    ];
    let out = run_config(home.path(), &frames, &grouped(&dir, "call"))?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1);
    let legs = attachment(&written[0].1, CALL_LEGS).ok_or("a call-legs attachment")?;
    assert_eq!(legs["ties"][0]["strategy"], "timing_heuristic", "{legs}");
    assert_eq!(legs["ties"][0]["identifier_match"], false, "{legs}");
    Ok(())
}

/// `grouping = "leg"`, and no `grouping` at all, write one container per leg.
#[test]
fn leg_is_the_default_grouping() -> Result<(), TestError> {
    for config in ["leg", ""] {
        let home = tempfile::tempdir()?;
        let dir = home.path().join("calls");
        let text = if config.is_empty() {
            grouped(&dir, "leg").replace("grouping = \"leg\"\n", "")
        } else {
            grouped(&dir, config)
        };
        let out = run_config(home.path(), &linked_legs(), &text)?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(containers(&dir)?.len(), 2, "grouping '{config}'");
    }
    Ok(())
}

/// An unknown grouping is refused, naming the rule and the values it takes.
#[test]
fn an_unknown_grouping_is_refused() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let out = run_config(home.path(), &linked_legs(), &grouped(&dir, "dialog"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("'calls'"), "{stderr}");
    assert!(stderr.contains("grouping = 'dialog'"), "{stderr}");
    assert!(
        stderr.contains("'leg'") && stderr.contains("'call'"),
        "{stderr}"
    );
    Ok(())
}

/// A leg the rule does not select is not in the call container.
#[test]
fn a_call_container_holds_only_the_legs_the_rule_selects() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let config = grouped(&dir, "call").replace("call_id =~ '.'", "call_id != 'b-leg'");
    let out = run_config(home.path(), &linked_legs(), &config)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1);
    let ids: Vec<&str> = written[0].1["dialog"]
        .as_array()
        .ok_or("dialog")?
        .iter()
        .filter_map(|d| d["sip_call_id"].as_str())
        .collect();
    assert_eq!(ids, ["a-leg"]);
    Ok(())
}

/// A call with more legs than one container holds is cut at the cap, and the
/// container says so; the rest of the legs are written in further containers
/// rather than dropped.
#[test]
fn a_call_over_the_leg_cap_says_it_was_cut() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let mut frames = vec![(invite("leg-00", [10, 1, 0, 1], [10, 2, 0, 1], None), 0)];
    for n in 1..=16u8 {
        frames.push((
            invite(
                &format!("leg-{n:02}"),
                [10, 3, 0, n],
                [10, 4, 0, n],
                Some("leg-00"),
            ),
            u64::from(n) * 30_000_000,
        ));
    }
    let out = run_config(home.path(), &frames, &grouped(&dir, "call"))?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let written = containers(&dir)?;
    let objects: usize = written
        .iter()
        .map(|(_, v)| v["dialog"].as_array().map_or(0, Vec::len))
        .sum();
    assert_eq!(objects, 17, "every leg is written once");
    let (_, first) = written
        .iter()
        .find(|(id, _)| id == "leg-00")
        .ok_or("leg-00's container")?;
    assert_eq!(first["dialog"].as_array().map(Vec::len), Some(16));
    let legs = attachment(first, CALL_LEGS).ok_or("a call-legs attachment")?;
    assert_eq!(legs["truncated"], true, "{legs}");
    Ok(())
}

/// A tone that differs per stream, so each channel is identifiable.
fn tone(stream: usize, frame: usize, i: usize) -> u8 {
    ((stream * 37 + frame * 3 + i) % 200) as u8
}

/// `grouping = "call"` with audio: each leg's recording is in the container,
/// and every channel maps to a party of its own leg, so every party of the
/// call has a channel and the mapping is stated.
#[test]
fn a_call_container_maps_every_channel_to_its_own_legs_party() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let dir = home.path().join("calls");
    let mut frames = pcap_build::g711_leg(
        &pcap_build::G711Leg {
            call_id: "a-leg",
            caller: ([10, 1, 0, 1], 20000, 0xa1a1_a1a1),
            callee: ([10, 9, 0, 1], 30000, 0xa2a2_a2a2),
            header: None,
            start_us: 0,
            ends: true,
        },
        1,
        tone,
    );
    frames.extend(pcap_build::g711_leg(
        &pcap_build::G711Leg {
            call_id: "b-leg",
            caller: ([10, 9, 0, 1], 31000, 0xb1b1_b1b1),
            callee: ([10, 2, 0, 1], 40000, 0xb2b2_b2b2),
            header: Some("X-Call-ID: a-leg"),
            start_us: 50_000,
            ends: true,
        },
        1,
        tone,
    ));
    frames.sort_by_key(|(_, at)| *at);
    let config = grouped(&dir, "call") + "audio = \"inline\"\n";
    let out = run_config(home.path(), &frames, &config)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let written = containers(&dir)?;
    assert_eq!(written.len(), 1, "{stderr}");
    let v = &written[0].1;
    assert_indices_resolve(v)?;
    let dialog = v["dialog"].as_array().ok_or("dialog")?;
    let recordings: Vec<(&str, Vec<u64>)> = dialog
        .iter()
        .filter(|d| d["type"] == "recording" && d["body"].is_string())
        .map(|d| {
            (
                d["sip_call_id"].as_str().unwrap_or_default(),
                d["parties"]
                    .as_array()
                    .map(|p| p.iter().filter_map(serde_json::Value::as_u64).collect())
                    .unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(recordings.len(), 2, "one recording per leg: {v}");
    let mut channels: Vec<u64> = Vec::new();
    for (call_id, parties) in &recordings {
        assert_eq!(parties.len(), 2, "two channels on {call_id}: {v}");
        let own = if *call_id == "a-leg" { 0..2 } else { 2..4 };
        for p in parties {
            assert!(own.contains(p), "{call_id} channel maps to party {p}: {v}");
        }
        channels.extend(parties);
    }
    channels.sort_unstable();
    assert_eq!(channels, [0, 1, 2, 3], "every party has a channel: {v}");
    let validator = support::schema::load_validator("vcon.schema.json")?;
    support::schema::assert_valid(&validator, v, "a call container with audio");
    Ok(())
}
