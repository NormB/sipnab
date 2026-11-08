// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A dialog's `latest_message_at` is the newest timestamp among its messages,
//! and the dialog's duration runs from `created_at` to it.
//!
//! `updated_at` stays the timestamp of the message READ last, which is what
//! the live vCon export watches for change. On an `-I` set whose files
//! overlap in time the last message read is not the newest one, so a duration
//! measured to `updated_at` stopped short of the call's end. The fixture is
//! `synthetic_captures::callid_across_files`: in each of its sixteen calls the
//! edge capture is read first and holds the call's newest messages (to
//! 2.505 s after it opened), and the core capture, read second, ends at
//! 0.905 s.

#[path = "support/synthetic_captures.rs"]
mod synthetic_captures;

#[path = "support/codecs.rs"]
mod codecs;

#[path = "support/cores_parity_captures.rs"]
mod captures;

#[path = "support/schema.rs"]
#[allow(dead_code)]
mod schema;

use captures::{Frame, Leg, SECOND};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Seconds from each spanning call's first message to its newest one: the
/// edge capture's second use ends with a 200 OK to BYE 2,505 ms after the
/// first use's INVITE.
const SPAN_SECONDS: f64 = 2.505;

/// The two captures of the spanning fixture, written to `dir`, edge first.
fn write_set(dir: &std::path::Path) -> Result<[std::path::PathBuf; 2], TestError> {
    let [edge, core] = synthetic_captures::callid_across_files();
    let paths = [dir.join("edge.pcap"), dir.join("core.pcap")];
    std::fs::write(&paths[0], edge)?;
    std::fs::write(&paths[1], core)?;
    Ok(paths)
}

/// Standard output of `sipnab -N` over `inputs` at `cores`, with `args`.
fn run(inputs: &[&std::path::Path], cores: &str, args: &[&str]) -> Result<String, TestError> {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.arg("-N");
    for input in inputs {
        cmd.arg("-I").arg(input);
    }
    let out = cmd.args(["--cores", cores]).args(args).output()?;
    assert!(
        out.status.success(),
        "--cores {cores} {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)?)
}

/// `--json-dialogs` over `inputs` at `cores`, one parsed object per dialog.
fn json_dialogs(
    inputs: &[&std::path::Path],
    cores: &str,
) -> Result<Vec<serde_json::Value>, TestError> {
    run(inputs, cores, &["--json-dialogs", "--no-cli-print"])?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

/// The dialog whose Call-ID is `call_id` among `dialogs`.
fn dialog<'a>(
    dialogs: &'a [serde_json::Value],
    call_id: &str,
) -> Result<&'a serde_json::Value, TestError> {
    dialogs
        .iter()
        .find(|d| d["call_id"] == call_id)
        .ok_or_else(|| format!("no dialog {call_id} in {dialogs:?}").into())
}

/// The first spanning call's duration runs to its newest message, 2.505 s,
/// not to the last one read, 0.905 s.
#[test]
fn span_0s_duration_covers_its_newest_message() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let [edge, core] = write_set(dir.path())?;
    let dialogs = json_dialogs(&[&core, &edge], "1")?;
    let span = dialog(&dialogs, "span-0@example.com")?;
    assert_eq!(span["duration_sec"].as_f64(), Some(SPAN_SECONDS), "{span}");
    Ok(())
}

/// Every spanning call's duration runs to its newest message.
#[test]
fn every_spanning_calls_duration_covers_its_newest_message() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let [edge, core] = write_set(dir.path())?;
    let dialogs = json_dialogs(&[&core, &edge], "1")?;
    assert_eq!(
        dialogs.len(),
        usize::from(synthetic_captures::SPANNING_CALLS),
        "every Call-ID of the fixture is one dialog"
    );
    for d in &dialogs {
        assert_eq!(d["duration_sec"].as_f64(), Some(SPAN_SECONDS), "{d}");
    }
    Ok(())
}

/// The set is read in the order of each file's first packet, so naming the
/// files the other way round changes no duration.
#[test]
fn the_order_the_files_are_named_in_changes_no_duration() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let [edge, core] = write_set(dir.path())?;
    assert_eq!(
        json_dialogs(&[&edge, &core], "1")?,
        json_dialogs(&[&core, &edge], "1")?,
        "the set is read in first-packet order whatever order it is named in"
    );
    Ok(())
}

/// Each spanning call's newest message is the edge capture's last 200 OK,
/// 2,505 ms after its INVITE at `20 i` ms, whichever of 1, 2, 4 or 8
/// workers reconstructed it.
#[cfg(feature = "native")]
#[test]
fn the_newest_message_is_the_same_at_every_worker_count() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let t0 = chrono::DateTime::from_timestamp(i64::try_from(captures::EPOCH)?, 0)
        .ok_or("the fixture's epoch")?;
    for cores in [1, 2, 4, 8] {
        let r = sharded(&set, cores)?;
        for i in 0..synthetic_captures::SPANNING_CALLS {
            let id = format!("span-{i}@example.com");
            let d = r.dialog_store.get(&id).ok_or_else(|| format!("no {id}"))?;
            let summary = sipnab::output::model::DialogSummary::from(d);
            let newest = t0 + chrono::TimeDelta::milliseconds(2505 + 20 * i64::from(i));
            assert_eq!(
                summary.latest_message_at,
                newest.to_rfc3339(),
                "{id} at {cores} workers"
            );
        }
    }
    Ok(())
}

/// The `--cores` path over the spanning set at `cores` workers.
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

// ── small sets built here ────────────────────────────────────────────

/// The one leg every call below runs on.
const LEG: Leg = Leg {
    caller: [192, 0, 2, 20],
    callee: [198, 51, 100, 20],
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

/// The `duration_sec` of `call_id` over the set `files` at `--cores 1`.
fn duration_of(files: &[std::path::PathBuf], call_id: &str) -> Result<Option<f64>, TestError> {
    let inputs: Vec<&std::path::Path> = files.iter().map(std::path::PathBuf::as_path).collect();
    let dialogs = json_dialogs(&inputs, "1")?;
    Ok(dialog(&dialogs, call_id)?["duration_sec"].as_f64())
}

/// A dialog of one message has lasted no time.
#[test]
fn a_one_message_dialog_has_no_duration() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let file = write(
        dir.path(),
        "one.pcap",
        &[(
            0,
            captures::request(LEG, "INVITE", "one@example.com", 1, ""),
        )],
    )?;
    assert_eq!(
        duration_of(&[file], "one@example.com")?,
        Some(0.0),
        "one message lasts no time"
    );
    Ok(())
}

/// A file read second whose message shares the newest timestamp of the first
/// leaves the duration at that timestamp.
#[test]
fn a_message_at_the_newest_instant_in_a_later_file_keeps_the_duration() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let call = "tie@example.com";
    let first = write(
        dir.path(),
        "first.pcap",
        &[
            (0, captures::request(LEG, "INVITE", call, 1, "")),
            (SECOND, captures::response(LEG, 200, "INVITE", call, 1, "")),
        ],
    )?;
    let second = write(
        dir.path(),
        "second.pcap",
        &[(SECOND, captures::request(LEG, "ACK", call, 1, ""))],
    )?;
    assert_eq!(
        duration_of(&[second, first], call)?,
        Some(1.0),
        "the later file's ACK at 1 s ties the newest message"
    );
    Ok(())
}

/// A retransmission of the INVITE in a file read second, stamped long before
/// the call's BYE, does not cut the call's duration back to itself.
#[test]
fn a_late_retransmission_with_an_older_timestamp_keeps_the_duration() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let call = "retx@example.com";
    let mut frames = captures::answered_call(LEG, call, 0);
    frames.push((5 * SECOND, captures::request(LEG, "BYE", call, 2, "")));
    frames.push((
        5 * SECOND + 1_000,
        captures::response(LEG, 200, "BYE", call, 2, ""),
    ));
    let first = write(dir.path(), "call.pcap", &frames)?;
    let second = write(
        dir.path(),
        "retx.pcap",
        &[(SECOND / 2, captures::request(LEG, "INVITE", call, 1, ""))],
    )?;
    let inputs = [first.as_path(), second.as_path()];
    let dialogs = json_dialogs(&inputs, "1")?;
    let d = dialog(&dialogs, call)?;
    assert_eq!(d["duration_sec"].as_f64(), Some(5.001), "{d}");
    assert_eq!(d["timing"]["retransmits"].as_u64(), Some(1), "{d}");
    Ok(())
}

/// A call whose first message read is newer than one read after it reports
/// no time, never a negative duration.
#[test]
fn a_call_read_newest_first_reports_no_negative_duration() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let call = "backwards@example.com";
    let other = Leg {
        caller: [192, 0, 2, 21],
        callee: [198, 51, 100, 21],
    };
    let first = write(
        dir.path(),
        "first.pcap",
        &[
            (
                0,
                captures::request(other, "OPTIONS", "opener@example.com", 1, ""),
            ),
            (2 * SECOND, captures::request(LEG, "INVITE", call, 1, "")),
        ],
    )?;
    let second = write(
        dir.path(),
        "second.pcap",
        &[(SECOND, captures::response(LEG, 486, "INVITE", call, 1, ""))],
    )?;
    assert_eq!(
        duration_of(&[first, second], call)?,
        Some(0.0),
        "the call read newest first lasts no time, not -1 s"
    );
    Ok(())
}

// ── the published dialog summary ────────────────────────────────────

/// Every spanning call's `DialogSummary` (the REST, MCP and TUI-save row),
/// reconstructed at one worker, as JSON.
#[cfg(feature = "native")]
fn summaries() -> Result<Vec<serde_json::Value>, TestError> {
    let dir = tempfile::tempdir()?;
    let set = write_set(dir.path())?;
    let r = sharded(&set, 1)?;
    r.dialog_store
        .iter()
        .map(|d| {
            Ok(serde_json::to_value(
                sipnab::output::model::DialogSummary::from(d),
            )?)
        })
        .collect()
}

/// `dialog.schema.json` requires `latest_message_at`, as a date-time string.
#[test]
fn the_dialog_schema_requires_latest_message_at_as_a_date_time() -> Result<(), TestError> {
    let text = std::fs::read_to_string(schema::schema_path("dialog.schema.json"))?;
    let doc: serde_json::Value = serde_json::from_str(&text)?;
    let required = doc["required"].as_array().ok_or("a required list")?;
    assert!(
        required.iter().any(|r| r == "latest_message_at"),
        "{required:?}"
    );
    assert_eq!(
        doc["properties"]["latest_message_at"],
        serde_json::json!({ "type": "string", "format": "date-time" }),
        "latest_message_at is a date-time string, as created_at and updated_at are"
    );
    Ok(())
}

/// A real summary, with its `latest_message_at`, validates against the
/// published schema.
#[cfg(feature = "native")]
#[test]
fn a_real_summary_validates_against_the_dialog_schema() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    for s in summaries()? {
        assert!(s["latest_message_at"].is_string(), "{s}");
        schema::assert_valid(&validator, &s, "a spanning call's summary");
    }
    Ok(())
}

/// The schema refuses a summary that leaves `latest_message_at` out.
#[cfg(feature = "native")]
#[test]
fn the_dialog_schema_refuses_a_summary_without_latest_message_at() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    let mut s = summaries()?.swap_remove(0);
    s.as_object_mut()
        .ok_or("an object")?
        .remove("latest_message_at");
    assert!(!validator.is_valid(&s), "{s}");
    Ok(())
}

/// The schema refuses a `latest_message_at` that is not a string.
#[cfg(feature = "native")]
#[test]
fn the_dialog_schema_refuses_a_numeric_latest_message_at() -> Result<(), TestError> {
    let validator = schema::load_validator("dialog.schema.json")?;
    let mut s = summaries()?.swap_remove(0);
    s["latest_message_at"] = serde_json::json!(1_700_000_002.505);
    assert!(!validator.is_valid(&s), "{s}");
    Ok(())
}

/// The newest message is never older than the first or than the one read
/// last, in any spanning call's summary.
#[cfg(feature = "native")]
#[test]
fn latest_message_at_is_never_before_created_at_or_updated_at() -> Result<(), TestError> {
    let at = |v: &serde_json::Value| -> Result<chrono::DateTime<chrono::FixedOffset>, TestError> {
        Ok(chrono::DateTime::parse_from_rfc3339(
            v.as_str().ok_or("an RFC 3339 string")?,
        )?)
    };
    for s in summaries()? {
        let latest = at(&s["latest_message_at"])?;
        assert!(latest >= at(&s["created_at"])?, "{s}");
        assert!(
            latest > at(&s["updated_at"])?,
            "the fixture reads an older message last: {s}"
        );
    }
    Ok(())
}
