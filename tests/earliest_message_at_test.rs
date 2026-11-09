// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A dialog's `earliest_message_at` is the oldest timestamp among its
//! messages, and the dialog's duration runs from it to `latest_message_at`.
//!
//! `created_at` stays the timestamp of the message READ first, which never
//! changes, so the pagers, the time windows and the vCon uuid keep their key.
//! On an `-I` set whose files overlap in time, a call's first message in the
//! file read first is not always its oldest, so a duration measured from
//! `created_at` started late. The set built here reads `early.pcap` first (its
//! first packet, another call's INVITE, is at 0 s); it holds the call's 200 OK
//! at 2 s and its BYE at 3.5 s. `older.pcap`, read second, holds the call's
//! INVITE at 1 s.

#[path = "support/codecs.rs"]
mod codecs;

#[path = "support/cores_parity_captures.rs"]
mod captures;

#[path = "support/schema.rs"]
#[allow(dead_code)]
mod schema;

use captures::{Frame, Leg};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The call read from its middle.
const CALL: &str = "middle@example.com";

/// The caller's side of the call.
const LEG: Leg = Leg {
    caller: [192, 0, 2, 40],
    callee: [198, 51, 100, 40],
};

/// Another call, whose INVITE opens the file read first.
const OTHER: Leg = Leg {
    caller: [192, 0, 2, 41],
    callee: [198, 51, 100, 41],
};

/// Write `frames` as `name` in `dir`.
fn write(
    dir: &std::path::Path,
    name: &str,
    frames: &[Frame],
) -> Result<std::path::PathBuf, TestError> {
    let path = dir.join(name);
    std::fs::write(&path, captures::pcap(frames))?;
    Ok(path)
}

/// The two-file set, the file read first first.
fn write_set(dir: &std::path::Path) -> Result<[std::path::PathBuf; 2], TestError> {
    let answered = Leg {
        caller: LEG.callee,
        callee: LEG.caller,
    };
    let early = vec![
        (
            0,
            captures::request(OTHER, "INVITE", "other@example.com", 1, ""),
        ),
        (
            2_000_000,
            captures::response(answered, 200, "INVITE", CALL, 1, ""),
        ),
        (3_500_000, captures::request(LEG, "BYE", CALL, 2, "")),
    ];
    let older = vec![(1_000_000, captures::request(LEG, "INVITE", CALL, 1, ""))];
    Ok([
        write(dir, "early.pcap", &early)?,
        write(dir, "older.pcap", &older)?,
    ])
}

/// The `--cores` path over the set at `cores` workers.
#[cfg(feature = "native")]
fn sharded(
    set: &[std::path::PathBuf; 2],
    cores: usize,
) -> Result<sipnab::parallel::ReconResult, TestError> {
    let cfg = sipnab::parallel::ParallelConfig {
        cores,
        max_streams: 100_000,
        max_dialogs: 100_000,
        rotate: false,
        max_reassembly: 1024,
        reassembly: true,
        parse_limit: None,
        shard_assignment: 0,
        portrange: (5060, 5060),
        no_dialog: false,
        dialog_tracking: Default::default(),
        no_rtp: false,
        quiet_bad_parse: false,
        hep_parse: false,
        rtpproxy_control: None,
        ng_control_port: None,
        xcid_headers: Vec::new(),
        leg_correlation_window_ms: sipnab::sip::dialog_store::DEFAULT_LEG_CORRELATION_WINDOW_MS,
        retain_audio: false,
        audio_limits: sipnab::rtp::stream_store::AudioLimits::default(),
    };
    let cc = sipnab::capture::CaptureConfig::default();
    Ok(sipnab::parallel::run_offline_parallel_file(
        &[set[0].clone(), set[1].clone()],
        &cc,
        cfg,
    )?)
}

/// The call's `DialogSummary` (the REST, MCP and TUI-save row) at `cores`
/// workers, as JSON.
#[cfg(feature = "native")]
fn summary_at(cores: usize) -> Result<serde_json::Value, TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let r = sharded(&set, cores)?;
    let d = r.dialog_store.get(CALL).ok_or("the call is in the store")?;
    Ok(serde_json::to_value(
        sipnab::output::model::DialogSummary::from(d),
    )?)
}

/// An RFC 3339 field of a summary.
fn at(v: &serde_json::Value) -> Result<chrono::DateTime<chrono::FixedOffset>, TestError> {
    Ok(chrono::DateTime::parse_from_rfc3339(
        v.as_str().ok_or("an RFC 3339 string")?,
    )?)
}

/// The summary names the INVITE read second as the oldest message, and
/// keeps `created_at` on the 200 OK read first.
#[cfg(feature = "native")]
#[test]
fn the_summary_names_the_message_read_second_as_the_oldest() -> Result<(), TestError> {
    let s = summary_at(1)?;
    let earliest = at(&s["earliest_message_at"])?;
    let created = at(&s["created_at"])?;
    assert_eq!(
        created - earliest,
        chrono::TimeDelta::seconds(1),
        "the INVITE at 1 s is 1 s before the 200 OK read first, at 2 s: {s}"
    );
    assert_eq!(s["duration_sec"], 2.5, "1 s to 3.5 s: {s}");
    Ok(())
}

/// Every worker count builds the same oldest message.
#[cfg(feature = "native")]
#[test]
fn the_oldest_message_is_the_same_at_every_worker_count() -> Result<(), TestError> {
    let one = summary_at(1)?;
    for cores in [2, 4] {
        let many = summary_at(cores)?;
        assert_eq!(
            many["earliest_message_at"], one["earliest_message_at"],
            "--cores {cores} against --cores 1"
        );
        assert_eq!(
            many["duration_sec"], one["duration_sec"],
            "--cores {cores} against --cores 1"
        );
    }
    Ok(())
}

/// `dialog.schema.json` requires `earliest_message_at`, as a date-time
/// string.
#[test]
fn the_dialog_schema_requires_earliest_message_at_as_a_date_time() -> Result<(), TestError> {
    let text = std::fs::read_to_string(schema::schema_path("dialog.schema.json"))?;
    let doc: serde_json::Value = serde_json::from_str(&text)?;
    let required = doc["required"].as_array().ok_or("a required list")?;
    assert!(
        required.iter().any(|r| r == "earliest_message_at"),
        "the schema requires earliest_message_at: {required:?}"
    );
    assert_eq!(
        doc["properties"]["earliest_message_at"],
        serde_json::json!({ "type": "string", "format": "date-time" }),
        "earliest_message_at is a date-time string, as the other three times are"
    );
    Ok(())
}

/// A real summary, with its `earliest_message_at`, validates against the
/// published schema.
#[cfg(feature = "native")]
#[test]
fn a_real_summary_validates_against_the_dialog_schema() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    let s = summary_at(1)?;
    assert!(
        s["earliest_message_at"].is_string(),
        "the field is there: {s}"
    );
    schema::assert_valid(&validator, &s, "the call's summary");
    Ok(())
}

/// The schema refuses a summary that leaves `earliest_message_at` out.
#[cfg(feature = "native")]
#[test]
fn the_dialog_schema_refuses_a_summary_without_earliest_message_at() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    let mut s = summary_at(1)?;
    s.as_object_mut()
        .ok_or("an object")?
        .remove("earliest_message_at");
    assert!(
        !validator.is_valid(&s),
        "a summary without it is refused: {s}"
    );
    Ok(())
}

/// The schema refuses an `earliest_message_at` that is not a string.
#[cfg(feature = "native")]
#[test]
fn the_dialog_schema_refuses_a_numeric_earliest_message_at() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    let mut s = summary_at(1)?;
    s["earliest_message_at"] = serde_json::json!(1_700_000_001);
    assert!(!validator.is_valid(&s), "a number is refused: {s}");
    Ok(())
}

/// The oldest message is never later than the first read or the last read.
#[cfg(feature = "native")]
#[test]
fn earliest_message_at_is_never_after_created_at_or_updated_at() -> Result<(), TestError> {
    let s = summary_at(1)?;
    let earliest = at(&s["earliest_message_at"])?;
    assert!(
        earliest < at(&s["created_at"])?,
        "the fixture reads an older message after the first: {s}"
    );
    assert!(
        earliest <= at(&s["updated_at"])?,
        "the oldest is never after the last read: {s}"
    );
    assert!(
        earliest < at(&s["latest_message_at"])?,
        "the oldest is before the newest: {s}"
    );
    Ok(())
}
