// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The fleet center's history store, end to end on the real binary.
//!
//! A `sipnab fleet serve` takes call records over HTTP, files them into
//! sealed Parquet files and answers `GET /v1/fleet/calls`. What only the
//! real process shows: the answer equals what was pushed, before and after
//! the filing and across a kill; the store directory holds no call in
//! clear; retention removes the days past it at start; a changed file is
//! reported and the center keeps serving.
//!
//! The same file holds the tests of a build without the `fleet-store`
//! feature: it says at start that it has no history store, and the route
//! answers `501` with the same text.

#![cfg(all(feature = "api", unix))]

use std::path::{Path, PathBuf};
#[cfg(feature = "fleet-store")]
use std::time::{Duration, Instant};

#[path = "support/fleet_center.rs"]
mod fleet_center;

use fleet_center::{Center, TestError, http, store_key_file};

/// The center's signing key.
const CENTER_KEY: &str = "fleet-history-e2e-center-key-0123456789abcdef";

/// How long a test waits for the center to file or to answer.
#[cfg(feature = "fleet-store")]
const WAIT: Duration = Duration::from_secs(40);

/// A token of the center's key.
fn token(id: &str, scope: &str) -> String {
    sipnab::auth::mint(
        CENTER_KEY.as_bytes(),
        id,
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        scope,
    )
}

/// A file in `dir` only its owner can read.
fn private_file(dir: &Path, name: &str, text: &str) -> Result<PathBuf, TestError> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(text.as_bytes())?;
    Ok(path)
}

/// A center on a port of its own whose store is in `dir`, with `more`
/// arguments.
fn center(dir: &Path, more: &[&str]) -> Result<Center, TestError> {
    let key = match std::fs::metadata(dir.join("center.signing")) {
        Ok(_) => dir.join("center.signing"),
        Err(_) => private_file(dir, "center.signing", CENTER_KEY)?,
    };
    let store = dir.join("center.store");
    let store_key = store_key_file(dir)?;
    let mut args = vec![
        "--listen",
        "127.0.0.1:0",
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ];
    args.extend_from_slice(more);
    Center::start(&args)
}

/// The call record at `seq` of stream `s` as a member writes it.
fn call_line(seq: u64) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "kind": "call",
        "stream": "s",
        "seq": seq,
        "sent_at": chrono::Utc::now().to_rfc3339(),
        "selected_by": "failed",
        "call": {
            "call_id": format!("call-{seq}@example.com"),
            "from": "sip:+12025550101@example.com",
            "to": "sip:+12025550102@example.com",
            "state": "failed",
        },
    })
}

/// Push call records `from` to `to` as `member` and return them as sent.
fn push(addr: &str, member: &str, from: u64, to: u64) -> Result<Vec<serde_json::Value>, TestError> {
    let lines: Vec<serde_json::Value> = (from..=to).map(call_line).collect();
    let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let (status, answer) = http(
        addr,
        "POST",
        "/v1/fleet/ingest",
        &token(member, sipnab::auth::SCOPE_FLEET_REPORT),
        body.as_bytes(),
    )?;
    if status != 200 {
        return Err(format!("ingest answered {status}: {answer}").into());
    }
    Ok(lines)
}

/// `GET /v1/fleet/calls` with `query` and a `full` token: status and body.
fn calls(addr: &str, query: &str) -> Result<(u16, serde_json::Value), TestError> {
    let (status, body) = http(
        addr,
        "GET",
        &format!("/v1/fleet/calls{query}"),
        &token("ops", sipnab::auth::SCOPE_FULL),
        b"",
    )?;
    Ok((status, serde_json::from_str(&body).unwrap_or_default()))
}

/// The `history` object of the center's members report.
fn history_report(addr: &str) -> Result<serde_json::Value, TestError> {
    let (status, body) = http(
        addr,
        "GET",
        "/v1/fleet/members",
        &token("reader", sipnab::auth::SCOPE_INVENTORY),
        b"",
    )?;
    if status != 200 {
        return Err(format!("members answered {status}: {body}").into());
    }
    let report: serde_json::Value = serde_json::from_str(&body)?;
    Ok(report["history"].clone())
}

/// Poll `f` until it is true or `within` has passed.
#[cfg(feature = "fleet-store")]
fn wait_until(
    within: Duration,
    mut f: impl FnMut() -> Result<bool, TestError>,
) -> Result<bool, TestError> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if f()? {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(false)
}

/// `sipnab` with `args`: exit code, stdout and stderr.
fn sipnab(args: &[&str]) -> Result<(Option<i32>, String, String), TestError> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()?;
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

#[test]
fn the_version_says_whether_the_build_has_the_history_store() -> Result<(), TestError> {
    let (code, out, err) = sipnab(&["--version"])?;
    assert_eq!(code, Some(0), "--version exits 0: {err}");
    assert_eq!(
        out.contains("fleet-store"),
        cfg!(feature = "fleet-store"),
        "the feature list of --version shows fleet-store exactly in a build that has it: {out}"
    );
    Ok(())
}

/// The two pages that list what each token scope reaches name every route
/// a fleet center serves, and say that call records need `full`.
#[test]
fn the_scope_tables_name_every_route_of_a_fleet_center() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/app/fleet_center.rs"))?;
    let routes: Vec<&str> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix(".route(\""))
        .filter_map(|rest| rest.split('"').next())
        .collect();
    assert!(
        routes.len() >= 3 && routes.contains(&"/v1/fleet/calls"),
        "the center's router lists its routes, the calls route among them: {routes:?}"
    );
    for page in ["docs/auth.md", "docs/rest-api.md"] {
        let text = std::fs::read_to_string(root.join(page))?;
        let rows: Vec<&str> = text.lines().filter(|l| l.starts_with("| `")).collect();
        for route in &routes {
            assert!(
                rows.iter().any(|row| row.contains(route)),
                "{page}: no row of a scope table names {route}"
            );
        }
        let full = rows
            .iter()
            .find(|row| row.starts_with("| `full`"))
            .ok_or("a `full` row")?;
        assert!(
            full.contains("GET /v1/fleet/calls"),
            "{page}: the `full` row says it reads a fleet center's call records: {full}"
        );
        let inventory = rows
            .iter()
            .find(|row| row.starts_with("| `inventory`"))
            .ok_or("an `inventory` row")?;
        assert!(
            inventory.contains("not") && inventory.contains("/v1/fleet/calls"),
            "{page}: the `inventory` row says it does not read call records: {inventory}"
        );
    }
    Ok(())
}

#[test]
fn retention_and_flush_values_outside_their_range_are_refused() -> Result<(), TestError> {
    for (flag, value) in [
        ("--calls-retention-days", "0"),
        ("--calls-retention-days", "549"),
        ("--calls-flush-secs", "0"),
        ("--calls-flush-secs", "3601"),
        ("--calls-retention-days", "ninety"),
    ] {
        let (code, _, err) = sipnab(&[
            "fleet",
            "serve",
            "--listen",
            "127.0.0.1:0",
            "--store",
            "/nonexistent/center.store",
            "--signing-key-file",
            "/nonexistent/key",
            flag,
            value,
        ])?;
        assert_eq!(code, Some(2), "failure {flag} {value} is refused: {err}");
        assert!(
            err.contains(flag),
            "failure the refusal names {flag}: {err}"
        );
    }
    Ok(())
}

/// The heartbeat at `seq` of stream `s`, sent every `secs` seconds, as a
/// member writes it.
fn beat_line(seq: u64, secs: u64) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "kind": "heartbeat",
        "stream": "s",
        "seq": seq,
        "sent_at": chrono::Utc::now().to_rfc3339(),
        "heartbeat_secs": secs,
        "inventory": {
            "host": "edge.example.com",
            "marker": format!("inventory-marker-{seq}"),
        },
    })
}

/// Send `lines` as `member` in one request and return the center's answer.
fn send(
    addr: &str,
    member: &str,
    lines: &[serde_json::Value],
) -> Result<serde_json::Value, TestError> {
    let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let (status, answer) = http(
        addr,
        "POST",
        "/v1/fleet/ingest",
        &token(member, sipnab::auth::SCOPE_FLEET_REPORT),
        body.as_bytes(),
    )?;
    if status != 200 {
        return Err(format!("ingest answered {status}: {answer}").into());
    }
    Ok(serde_json::from_str(&answer)?)
}

/// `GET /v1/fleet/members/<member>/history` with `query` and a token of
/// `scope`: status and body.
fn heartbeats_as(
    addr: &str,
    member: &str,
    query: &str,
    scope: &str,
) -> Result<(u16, serde_json::Value), TestError> {
    let (status, body) = http(
        addr,
        "GET",
        &format!("/v1/fleet/members/{member}/history{query}"),
        &token("reader", scope),
        b"",
    )?;
    Ok((status, serde_json::from_str(&body).unwrap_or_default()))
}

/// [`heartbeats_as`] with an `inventory` token.
fn heartbeats(
    addr: &str,
    member: &str,
    query: &str,
) -> Result<(u16, serde_json::Value), TestError> {
    heartbeats_as(addr, member, query, sipnab::auth::SCOPE_INVENTORY)
}

/// The scope tables say an `inventory` token reads a member's heartbeat
/// history.
#[test]
fn the_scope_tables_give_heartbeat_history_to_inventory() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for page in ["docs/auth.md", "docs/rest-api.md"] {
        let text = std::fs::read_to_string(root.join(page))?;
        let inventory = text
            .lines()
            .find(|row| row.starts_with("| `inventory`"))
            .ok_or("an `inventory` row")?;
        assert!(
            inventory.contains("GET /v1/fleet/members/{id}/history"),
            "{page}: the `inventory` row says it reads a member's heartbeat history: {inventory}"
        );
    }
    Ok(())
}

#[cfg(not(feature = "fleet-store"))]
mod without_the_store {
    use super::*;

    #[test]
    fn a_build_without_the_store_answers_501_for_heartbeat_history() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &[])?;
        send(&c.addr, "edge-a", &[beat_line(1, 30)])?;
        let (status, answer) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(
            status, 501,
            "failure the route answers 501, not an empty list: {answer}"
        );
        assert_eq!(
            answer["detail"],
            sipnab::app::fleet_center::NO_HISTORY_STORE,
            "failure with the text the start logs"
        );
        assert!(
            sipnab::app::fleet_center::NO_HISTORY_STORE.contains("/history"),
            "failure and that text names the heartbeat history route"
        );
        let (status, _) = heartbeats_as(&c.addr, "edge-a", "", sipnab::auth::SCOPE_METRICS)?;
        assert_eq!(
            status, 401,
            "failure a token that does not read members is refused before the 501"
        );
        Ok(())
    }

    #[test]
    fn a_build_without_the_store_says_so_at_start_and_on_the_route() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-retention-days", "30"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains(sipnab::app::fleet_center::NO_HISTORY_STORE)),
            "failure the start says the build has no history store: {:?}",
            c.early
        );
        push(&c.addr, "edge-a", 1, 2)?;
        let (status, answer) = calls(&c.addr, "")?;
        assert_eq!(
            status, 501,
            "failure the route answers 501, not an empty list"
        );
        assert_eq!(
            answer["detail"],
            sipnab::app::fleet_center::NO_HISTORY_STORE,
            "failure with the same text"
        );
        let report = history_report(&c.addr)?;
        assert_eq!(
            report["available"], false,
            "failure the members report says there is no history store"
        );
        assert!(
            !dir.path().join("center.store.parquet").exists(),
            "failure no history directory is made"
        );
        Ok(())
    }
}

#[cfg(feature = "fleet-store")]
mod with_the_store {
    use super::*;
    use sipnab::app::fleet_history::History;
    use sipnab::app::fleet_intake::IntakeRecord;
    use sipnab::app::fleet_seal::{Keys, MasterKey};

    /// The store key `store_key_file` writes: every byte is 1.
    const STORE_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// The history store of the center in `dir`, for reading and for
    /// writing files the way the center does.
    fn history(dir: &Path) -> Result<History, TestError> {
        let keys = Keys::new(MasterKey::parse(STORE_KEY)?, Vec::new());
        Ok(History::open(
            &dir.join("center.store"),
            std::sync::Arc::new(keys),
        )?)
    }

    /// Every file under `dir` with its bytes.
    fn files_under(dir: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, TestError> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(&at)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                } else {
                    out.push((entry.path(), std::fs::read(entry.path())?));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// What the route answered for each call, as the member sent it.
    fn as_sent(answer: &serde_json::Value) -> Vec<serde_json::Value> {
        let mut rows: Vec<serde_json::Value> = answer["calls"]
            .as_array()
            .map(|calls| {
                calls
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "schema_version": 1,
                            "kind": "call",
                            "stream": c["stream"],
                            "seq": c["seq"],
                            "sent_at": c["sent_at"],
                            "selected_by": c["selected_by"],
                            "call": c["call"],
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        rows.sort_by_key(|r| r["seq"].as_u64());
        rows
    }

    /// `sent` with each send time as the center spells it: UTC with `Z`.
    fn normalized(sent: &[serde_json::Value]) -> Result<Vec<serde_json::Value>, TestError> {
        sent.iter()
            .map(|line| {
                let mut line = line.clone();
                let at = chrono::DateTime::parse_from_rfc3339(
                    line["sent_at"].as_str().ok_or("a send time")?,
                )?
                .with_timezone(&chrono::Utc);
                line["sent_at"] = serde_json::to_value(at)?;
                Ok(line)
            })
            .collect()
    }

    #[test]
    fn pushed_records_are_answered_before_and_after_the_filing_and_never_in_clear()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("history store") && l.contains("90 day(s)")),
            "success the start names the history store and its retention: {:?}",
            c.early
        );
        let sent = normalized(&push(&c.addr, "edge-a", 1, 5)?)?;
        let (status, first) = calls(&c.addr, "")?;
        assert_eq!(status, 200, "success the route answers: {first}");
        assert_eq!(
            as_sent(&first),
            sent,
            "success a record is answered as it was pushed from the moment it is acknowledged"
        );
        let filed = wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 5))?;
        assert!(
            filed,
            "success the center files the records within its flush interval: {}",
            history_report(&c.addr)?
        );
        let (_, second) = calls(&c.addr, "?member=edge-a")?;
        assert_eq!(
            as_sent(&second),
            sent,
            "success a row read back from a sealed Parquet file equals the pushed record"
        );
        assert_eq!(second["files_read"], 1, "success read from one file");
        assert_eq!(second["complete"], true, "success and whole");
        let (_, one) = calls(&c.addr, "?call_id=call-3%40example.com")?;
        assert_eq!(
            one["calls"][0]["seq"], 3,
            "success a call is found by its Call-ID: {one}"
        );
        assert_eq!(one["count"], 1, "success and only that call");
        let files = files_under(dir.path())?;
        assert!(
            files.iter().any(|(p, _)| p
                .to_string_lossy()
                .contains("center.store.parquet/calls/date=")
                && p.to_string_lossy().contains("/member=edge-a/")),
            "success the file is under class, day and member: {:?}",
            files.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );
        for (path, bytes) in &files {
            for needle in ["+12025550101", "call-3@example.com", "PAR1"] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "success {} holds {needle} in clear",
                    path.display()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn records_acknowledged_before_a_kill_are_filed_once_by_the_next_start() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        let sent = normalized(&push(&c.addr, "edge-a", 1, 4)?)?;
        assert_eq!(
            history_report(&c.addr)?["rows_filed"],
            0,
            "edge nothing is filed before the flush interval"
        );
        // The files are written as a filing writes them, and the center
        // is killed before it empties its intake.
        let keys = Keys::new(MasterKey::parse(STORE_KEY)?, Vec::new());
        let intake = std::fs::read(dir.path().join("center.store.intake"))?;
        let waiting: Vec<IntakeRecord> = sipnab::app::fleet_seal::open_log(
            &intake,
            &keys,
            sipnab::app::fleet_seal::Kind::Intake,
        )
        .map_err(|e| e.to_string())?
        .records
        .iter()
        .map(|line| serde_json::from_slice(line))
        .collect::<Result<_, _>>()?;
        assert_eq!(waiting.len(), 4, "edge the intake holds the four records");
        history(dir.path())?.file(&waiting[..2])?;
        drop(c);
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("filed 2 call record(s)") && l.contains("2 were in it already")),
            "edge the start files the two rows no file holds and says two were filed already: \
             {:?}",
            c.early
        );
        let (_, answer) = calls(&c.addr, "")?;
        assert_eq!(
            as_sent(&answer),
            sent,
            "edge every acknowledged record is answered once after the kill"
        );
        assert_eq!(answer["count"], 4, "edge four rows, none twice");
        let again = push(&c.addr, "edge-a", 1, 4);
        assert!(again.is_ok(), "edge the member's replay is accepted");
        let (_, after) = calls(&c.addr, "")?;
        assert_eq!(
            after["count"], 4,
            "edge and a replay after the restart stores nothing twice: {after}"
        );
        Ok(())
    }

    #[test]
    fn a_start_removes_the_days_past_the_retention_and_no_other() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let now = chrono::Utc::now();
        let row = |days_ago: i64, seq: u64| IntakeRecord {
            member: "edge-a".to_string(),
            received_at: now - chrono::TimeDelta::days(days_ago),
            stream: "s".to_string(),
            seq,
            sent_at: now - chrono::TimeDelta::days(days_ago),
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": format!("call-{seq}@example.com")}),
        };
        let store = history(dir.path())?;
        store.file(&[row(40, 1), row(10, 2), row(3, 3), row(2, 4), row(0, 5)])?;
        let c = center(dir.path(), &["--calls-retention-days", "2"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("3 day(s) and 3 file(s)")
                    && l.contains("--calls-retention-days 2")),
            "success the start says what retention removed: {:?}",
            c.early
        );
        let (_, answer) = calls(&c.addr, "")?;
        let seqs: Vec<u64> = answer["calls"]
            .as_array()
            .map(|a| a.iter().filter_map(|c| c["seq"].as_u64()).collect())
            .unwrap_or_default();
        assert_eq!(
            seqs,
            vec![5, 4],
            "success the rows of today and of two days ago stay; the older days are gone"
        );
        assert_eq!(
            files_under(&dir.path().join("center.store.parquet"))?.len(),
            2,
            "success two files are left on disk"
        );
        Ok(())
    }

    #[test]
    fn a_changed_file_is_reported_and_the_center_keeps_serving() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        push(&c.addr, "edge-a", 1, 3)?;
        push(&c.addr, "edge-b", 1, 2)?;
        let filed = wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 5))?;
        assert!(filed, "failure the records were filed first");
        let files = files_under(&dir.path().join("center.store.parquet"))?;
        let (path, mut bytes) = files
            .into_iter()
            .find(|(p, _)| p.to_string_lossy().contains("member=edge-a"))
            .ok_or("edge-a's file")?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let (status, answer) = calls(&c.addr, "")?;
        assert_eq!(status, 200, "failure the route still answers");
        assert_eq!(
            answer["complete"], false,
            "failure and says it is not whole"
        );
        let refused = answer["refused"][0]["file"].as_str().unwrap_or_default();
        assert!(
            path.to_string_lossy().ends_with(refused) && refused.starts_with("calls/date="),
            "failure the changed file is named by its path in the store: {answer}"
        );
        assert!(
            answer["refused"][0]["reason"]
                .as_str()
                .is_some_and(|r| r.contains("sealed layer")),
            "failure with the layer that refused it: {answer}"
        );
        assert!(
            answer["refused"][0]["reason"]
                .as_str()
                .is_some_and(|r| !r.contains(refused) && r.starts_with("sealed layer")),
            "failure the reason does not repeat the path the file field holds: {answer}"
        );
        assert_eq!(
            answer["count"], 2,
            "failure the other member's rows are answered"
        );
        let (status, narrow) = calls(&c.addr, "?member=edge-b")?;
        assert_eq!(
            (status, &narrow["complete"]),
            (200, &serde_json::json!(true)),
            "failure a question that does not need the changed file is whole"
        );
        push(&c.addr, "edge-a", 4, 4)?;
        let (_, later) = calls(&c.addr, "?call_id=call-4%40example.com&member=edge-a")?;
        assert_eq!(
            later["count"], 1,
            "failure and the center still takes and answers new records: {later}"
        );
        Ok(())
    }

    /// What the scope tables say of the calls route: `full` reads it, and
    /// so do `actions` and `admin`, which read whatever `full` reads.
    #[test]
    fn the_scopes_the_tables_name_read_call_records() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &[])?;
        push(&c.addr, "edge-a", 1, 1)?;
        for scope in [
            sipnab::auth::SCOPE_FULL,
            sipnab::auth::SCOPE_ACTIONS,
            sipnab::auth::SCOPE_ADMIN,
        ] {
            let (status, body) = http(&c.addr, "GET", "/v1/fleet/calls", &token("x", scope), b"")?;
            assert_eq!(
                status, 200,
                "success a {scope} token reads call records: {body}"
            );
        }
        for scope in [sipnab::auth::SCOPE_METRICS, sipnab::auth::SCOPE_AUDIO] {
            let (status, body) = http(&c.addr, "GET", "/v1/fleet/calls", &token("x", scope), b"")?;
            assert_eq!(
                status, 401,
                "failure a {scope} token does not read call records: {body}"
            );
        }
        Ok(())
    }

    #[test]
    fn the_calls_route_refuses_tokens_that_do_not_read_calls_and_bad_questions()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &[])?;
        push(&c.addr, "edge-a", 1, 1)?;
        for scope in [
            sipnab::auth::SCOPE_INVENTORY,
            sipnab::auth::SCOPE_FLEET_REPORT,
        ] {
            let (status, body) = http(&c.addr, "GET", "/v1/fleet/calls", &token("x", scope), b"")?;
            assert_eq!(
                status, 401,
                "failure a {scope} token does not read call records: {body}"
            );
        }
        let (status, answer) = calls(&c.addr, "?limit=5000")?;
        assert_eq!(
            status, 400,
            "failure a limit past the bound is a bad request"
        );
        assert!(
            answer["detail"]
                .as_str()
                .is_some_and(|d| d.contains("limit") && d.contains("1000")),
            "failure naming the parameter and its bound: {answer}"
        );
        let (status, _) = calls(&c.addr, "?limit=1")?;
        assert_eq!(status, 200, "failure and a good question is answered after");
        Ok(())
    }

    #[test]
    fn files_under_an_earlier_key_need_that_key_listed() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        push(&c.addr, "edge-a", 1, 2)?;
        let filed = wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 2))?;
        assert!(filed, "edge the records were filed under the first key");
        drop(c);
        // A new key: the first becomes an old key.
        let old = private_file(dir.path(), "old.storekey", &format!("{STORE_KEY}\n"))?;
        let new = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n";
        std::fs::remove_file(dir.path().join("center.storekey"))?;
        // `center` writes the fixed first key again, so this start names
        // its files itself.
        let new_key = private_file(dir.path(), "new.storekey", new)?;
        let signing = dir.path().join("center.signing");
        let store = dir.path().join("center.store");
        let start = |old_key: Option<&Path>| -> Result<Center, TestError> {
            let mut args = vec![
                "--listen".to_string(),
                "127.0.0.1:0".to_string(),
                "--store".to_string(),
                store.display().to_string(),
                "--store-key-file".to_string(),
                new_key.display().to_string(),
                "--signing-key-file".to_string(),
                signing.display().to_string(),
            ];
            if let Some(old_key) = old_key {
                args.push("--store-old-key-file".to_string());
                args.push(old_key.display().to_string());
            }
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            Center::start(&args)
        };
        let c = start(Some(&old))?;
        let (_, answer) = calls(&c.addr, "")?;
        assert_eq!(
            (answer["count"].as_u64(), &answer["complete"]),
            (Some(2), &serde_json::json!(true)),
            "edge with the earlier key listed, its files are read: {answer}"
        );
        Ok(())
    }
}

/// The heartbeat history: class `members` of the history store, and the
/// registry a center rebuilds from it.
#[cfg(feature = "fleet-store")]
mod heartbeat_history {
    use super::*;

    /// The members report of the center.
    fn members(addr: &str) -> Result<serde_json::Value, TestError> {
        let (status, body) = http(
            addr,
            "GET",
            "/v1/fleet/members",
            &token("reader", sipnab::auth::SCOPE_INVENTORY),
            b"",
        )?;
        if status != 200 {
            return Err(format!("members answered {status}: {body}").into());
        }
        Ok(serde_json::from_str(&body)?)
    }

    /// The positions of the heartbeats in `answer`, as answered.
    fn seqs(answer: &serde_json::Value) -> Vec<u64> {
        answer["heartbeats"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r["self_reported"]["seq"].as_u64())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every file under `dir`.
    fn paths_under(dir: &Path) -> Result<Vec<PathBuf>, TestError> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(at) = todo.pop() {
            for entry in std::fs::read_dir(&at)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    todo.push(entry.path());
                } else {
                    out.push(entry.path());
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Wait until the center says it filed `rows` heartbeats.
    fn filed(addr: &str, rows: u64) -> Result<bool, TestError> {
        wait_until(WAIT, || {
            Ok(history_report(addr)?["heartbeats_filed"] == rows)
        })
    }

    #[test]
    fn heartbeats_are_answered_before_and_after_the_filing_and_never_in_clear()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        for seq in 1..=3 {
            send(&c.addr, "edge-a", &[beat_line(seq, 30)])?;
        }
        send(&c.addr, "edge-b", &[beat_line(1, 30)])?;
        let (status, first) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(status, 200, "success the route answers: {first}");
        assert_eq!(
            seqs(&first),
            [3, 2, 1],
            "success every acknowledged heartbeat of the member is answered, newest first: {first}"
        );
        assert_eq!(
            first["member"], "edge-a",
            "success the answer names the member"
        );
        assert!(
            filed(&c.addr, 4)?,
            "success the center files the heartbeats"
        );
        let (_, second) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(
            seqs(&second),
            [3, 2, 1],
            "success the rows read back from the sealed files are the same: {second}"
        );
        assert_eq!(second["complete"], true, "success and the answer is whole");
        assert!(
            second["files_read"].as_u64().is_some_and(|n| n >= 1),
            "success read from the files: {second}"
        );
        let row = &second["heartbeats"][0];
        assert_eq!(
            (
                &row["verified"]["heartbeats"],
                &row["self_reported"]["heartbeat_secs"],
                &row["self_reported"]["inventory"]["marker"],
            ),
            (
                &serde_json::json!(3),
                &serde_json::json!(30),
                &serde_json::json!("inventory-marker-3"),
            ),
            "success a row holds the count, the interval and the inventory of its heartbeat"
        );
        let (_, limited) = heartbeats(&c.addr, "edge-a", "?limit=1")?;
        assert_eq!(
            (seqs(&limited), &limited["more"]),
            (vec![3], &serde_json::json!(true)),
            "success a limit cuts the answer and says there is more"
        );
        let paths = paths_under(&dir.path().join("center.store.parquet"))?;
        assert!(
            paths.iter().any(|p| {
                let p = p.to_string_lossy();
                p.contains("center.store.parquet/members/date=") && p.contains("/member=edge-a/")
            }),
            "success the file is under class members, day and member: {paths:?}"
        );
        for path in paths_under(dir.path())? {
            let bytes = std::fs::read(&path)?;
            for needle in ["inventory-marker", "edge.example.com", "PAR1"] {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "success {} holds no '{needle}' in clear",
                    path.display()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn a_member_silent_before_a_stop_is_listed_silent_after_the_store_file_is_lost()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        send(&c.addr, "edge-a", &[beat_line(1, 1), beat_line(2, 1)])?;
        assert!(filed(&c.addr, 2)?, "success the heartbeats were filed");
        drop(c);
        std::fs::remove_file(dir.path().join("center.store"))?;
        let c = center(dir.path(), &["--silent-after-missed", "1"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("1 member(s)") && l.contains("taken from the history store")),
            "success the start says it took the member from the history store: {:?}",
            c.early
        );
        let listed = wait_until(WAIT, || {
            Ok(members(&c.addr)?["members"][0]["silent"] == true)
        })?;
        let report = members(&c.addr)?;
        assert!(
            listed,
            "success the member is listed, and as silent: {report}"
        );
        let row = &report["members"][0];
        assert_eq!(
            (
                &row["member"],
                &row["verified"]["heartbeats"],
                &row["self_reported"]["seq"],
                &row["self_reported"]["inventory"]["marker"],
            ),
            (
                &serde_json::json!("edge-a"),
                &serde_json::json!(2),
                &serde_json::json!(2),
                &serde_json::json!("inventory-marker-2"),
            ),
            "success with what its newest heartbeat said: {report}"
        );
        assert_eq!(
            report["history"]["members_restored"], 1,
            "success and the report counts the member as restored"
        );
        Ok(())
    }

    #[test]
    fn a_replay_is_a_duplicate_after_the_store_file_is_lost() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        send(&c.addr, "edge-a", &[beat_line(1, 30)])?;
        push(&c.addr, "edge-a", 2, 3)?;
        let both = wait_until(WAIT, || {
            let report = history_report(&c.addr)?;
            Ok(report["heartbeats_filed"] == 1 && report["rows_filed"] == 2)
        })?;
        assert!(
            both,
            "edge the heartbeat and the two call records were filed"
        );
        drop(c);
        std::fs::remove_file(dir.path().join("center.store"))?;
        let c = center(dir.path(), &[])?;
        let again = send(
            &c.addr,
            "edge-a",
            &[beat_line(1, 30), call_line(2), call_line(3)],
        )?;
        assert_eq!(
            (&again["accepted"], &again["duplicate"]),
            (&serde_json::json!(0), &serde_json::json!(3)),
            "edge the heartbeat and the call records filed after it are replays: {again}"
        );
        let (_, answer) = calls(&c.addr, "")?;
        assert_eq!(answer["count"], 2, "edge no call record is stored twice");
        let next = send(&c.addr, "edge-a", &[beat_line(4, 30)])?;
        assert_eq!(next["accepted"], 1, "edge and the next record is new");
        let report = members(&c.addr)?;
        assert_eq!(
            report["members"][0]["verified"]["heartbeats"], 2,
            "edge the count of heartbeats goes on from the restored one: {report}"
        );
        Ok(())
    }

    #[test]
    fn heartbeats_acknowledged_before_a_kill_are_filed_once() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        send(&c.addr, "edge-a", &[beat_line(1, 30), beat_line(2, 30)])?;
        send(&c.addr, "edge-a", &[beat_line(3, 30)])?;
        let report = history_report(&c.addr)?;
        assert_eq!(
            (&report["heartbeats_filed"], &report["heartbeats_waiting"]),
            (&serde_json::json!(0), &serde_json::json!(3)),
            "edge nothing is filed before the flush interval and three rows wait: {report}"
        );
        drop(c);
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        let (_, answer) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(
            seqs(&answer),
            [3, 2, 1],
            "edge every acknowledged heartbeat is answered once after the kill: {answer}"
        );
        assert_eq!(
            history_report(&c.addr)?["heartbeats_filed"],
            3,
            "edge the start filed the three rows the store file held"
        );
        drop(c);
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        let (_, answer) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(
            seqs(&answer),
            [3, 2, 1],
            "edge a second start files no row twice: {answer}"
        );
        assert_eq!(
            history_report(&c.addr)?["heartbeats_filed"],
            0,
            "edge and writes no file for rows the store holds"
        );
        Ok(())
    }

    #[test]
    fn the_history_route_refuses_tokens_and_questions_it_does_not_take() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &[])?;
        send(&c.addr, "edge-a", &[beat_line(1, 30)])?;
        for scope in [
            sipnab::auth::SCOPE_FLEET_REPORT,
            sipnab::auth::SCOPE_METRICS,
        ] {
            let (status, body) = heartbeats_as(&c.addr, "edge-a", "", scope)?;
            assert_eq!(
                status, 401,
                "failure a {scope} token does not read heartbeat history: {body}"
            );
        }
        for (query, names) in [
            ("?limit=0", "limit"),
            ("?limit=1001", "limit"),
            ("?call_id=a%40example.com", "call_id"),
            ("?member=edge-b", "member"),
            ("?from=yesterday", "from"),
            ("?from=2026-11-12T00:00:00Z&to=2026-11-11T00:00:00Z", "to"),
        ] {
            let (status, answer) = heartbeats(&c.addr, "edge-a", query)?;
            assert_eq!(status, 400, "failure {query} is a bad request: {answer}");
            assert!(
                answer["detail"].as_str().is_some_and(|d| d.contains(names)),
                "failure the refusal of {query} names {names}: {answer}"
            );
        }
        let long = "m".repeat(65);
        let (status, answer) = heartbeats(&c.addr, &long, "")?;
        assert_eq!(
            status, 400,
            "failure an id no member can have is refused: {answer}"
        );
        let (status, answer) = heartbeats(&c.addr, "edge-z", "")?;
        assert_eq!(
            (status, &answer["count"]),
            (200, &serde_json::json!(0)),
            "failure a member the center has no heartbeat of has an empty history: {answer}"
        );
        let (status, answer) = heartbeats_as(&c.addr, "edge-a", "", sipnab::auth::SCOPE_FULL)?;
        assert_eq!(
            (status, &answer["count"]),
            (200, &serde_json::json!(1)),
            "failure and a good question is answered after, for a full token too: {answer}"
        );
        Ok(())
    }

    #[test]
    fn a_changed_heartbeat_file_is_reported_and_the_center_keeps_serving() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        send(&c.addr, "edge-a", &[beat_line(1, 30)])?;
        assert!(filed(&c.addr, 1)?, "failure the heartbeat was filed first");
        let path = paths_under(&dir.path().join("center.store.parquet/members"))?
            .into_iter()
            .next()
            .ok_or("the heartbeat file")?;
        let mut bytes = std::fs::read(&path)?;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        std::fs::write(&path, bytes)?;
        let (status, answer) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(status, 200, "failure the route still answers: {answer}");
        assert_eq!(
            answer["complete"], false,
            "failure and says it is not whole"
        );
        let refused = answer["refused"][0]["file"].as_str().unwrap_or_default();
        assert!(
            path.to_string_lossy().ends_with(refused) && refused.starts_with("members/date="),
            "failure the changed file is named by its path in the store: {answer}"
        );
        assert!(
            answer["refused"][0]["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("sealed layer") && !r.contains(refused)),
            "failure with the layer that refused it and no second copy of the path: {answer}"
        );
        send(&c.addr, "edge-a", &[beat_line(2, 30)])?;
        let (_, later) = heartbeats(&c.addr, "edge-a", "")?;
        assert_eq!(
            seqs(&later),
            [2],
            "failure the center still takes and answers new heartbeats: {later}"
        );
        drop(c);
        let c = center(dir.path(), &[])?;
        let report = members(&c.addr)?;
        assert_eq!(
            report["members"][0]["verified"]["heartbeats"], 2,
            "failure a start with the changed file still lists the member from its store file"
        );
        Ok(())
    }
}
