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

    #[test]
    fn failure_a_build_without_the_store_cannot_verify() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let store = dir.path().join("center.store");
        let key = store_key_file(dir.path())?;
        // A history directory is there: the refusal is the build's, not a
        // missing directory's.
        std::fs::create_dir(dir.path().join("center.store.parquet"))?;
        let (code, out, err) = fleet_center::sipnab_within(
            &[
                "fleet",
                "verify",
                "--store",
                store.to_str().ok_or("utf-8")?,
                "--store-key-file",
                key.to_str().ok_or("utf-8")?,
            ],
            std::time::Duration::from_secs(40),
        )?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (
                Some(2),
                "",
                "sipnab fleet verify: this build has no history store (Cargo feature \
                 `fleet-store`): run the command from the build the center runs\n"
            ),
            "failure a build without the history store cannot run a pass and says which build can"
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
                .contains("center.store.parquet/calls/date=")),
            "success the file is under class and day: {:?}",
            files.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );
        assert!(
            !files.iter().any(|(p, _)| {
                let p = p.to_string_lossy();
                p.contains("member=") || p.contains("edge-a")
            }),
            "success no path under the center's directory names a member: {:?}",
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

    /// The call record at `seq` of `member`, received at `at`.
    fn row_at(member: &str, at: chrono::DateTime<chrono::Utc>, seq: u64) -> IntakeRecord {
        IntakeRecord {
            member: member.to_string(),
            received_at: at,
            stream: "s".to_string(),
            seq,
            sent_at: at,
            selected_by: "failed".to_string(),
            call: serde_json::json!({"call_id": format!("call-{seq}@example.com")}),
        }
    }

    /// Write `rows`, all of one member and one day, as release 0.5.249
    /// filed them: one sealed Parquet file without a codec under
    /// `member=<id>`, named by its times and its first row. No build writes
    /// that layout any more, so the test builds the file from the pieces
    /// that release used.
    fn file_as_0_5_249(dir: &Path, rows: &[IntakeRecord]) -> Result<PathBuf, TestError> {
        use sipnab::app::fleet_history::{FileName, Partition};
        let first = rows.first().ok_or("a file holds at least one row")?;
        let rel = format!(
            "{}/{}",
            Partition::of(first).rel_dir("calls"),
            FileName::of(rows)?.text()
        );
        write_uncompressed(dir, &rel, rows)
    }

    /// Write `rows`, all of one day, as releases 0.5.251 to 0.5.253 filed
    /// them: one sealed Parquet file without a codec under the day, named
    /// by its times and its rows.
    fn file_as_0_5_251(dir: &Path, rows: &[IntakeRecord]) -> Result<PathBuf, TestError> {
        use sipnab::app::fleet_history::IntervalName;
        let first = rows.first().ok_or("a file holds at least one row")?;
        let rel = format!(
            "calls/date={}/{}",
            first.received_at.format("%Y-%m-%d"),
            IntervalName::of(rows)?.text()
        );
        write_uncompressed(dir, &rel, rows)
    }

    /// Seal the Parquet of `rows`, without a codec, at `rel` under the
    /// history directory of the center in `dir`.
    fn write_uncompressed(
        dir: &Path,
        rel: &str,
        rows: &[IntakeRecord],
    ) -> Result<PathBuf, TestError> {
        use sipnab::app::fleet_history::{
            CHUNK_BYTES, dir_for, encode_uncompressed, sealed_lines, sorted,
        };
        use sipnab::app::fleet_seal::{Kind, LogSealer, system_draw};
        let (mut sealer, header) =
            LogSealer::new(&MasterKey::parse(STORE_KEY)?, Kind::Calls, &system_draw)?;
        let mut bytes = header.to_vec();
        let parquet = encode_uncompressed(&sorted(rows.to_vec()))?;
        for line in sealed_lines(rel, &parquet, CHUNK_BYTES) {
            bytes.extend(sealer.record(&line)?);
        }
        bytes.extend(sealer.base_end()?);
        let path = dir_for(&dir.join("center.store")).join(rel);
        std::fs::create_dir_all(path.parent().ok_or("a file has a directory")?)?;
        std::fs::write(&path, bytes)?;
        Ok(path)
    }

    /// The codec of every column chunk of the sealed history file at
    /// `path`, a file of call records of the center in `dir`.
    fn codecs_of(dir: &Path, path: &Path) -> Result<Vec<parquet::basic::Compression>, TestError> {
        use parquet::file::reader::FileReader as _;
        use parquet::file::serialized_reader::SerializedFileReader;
        use sipnab::app::fleet_history::{dir_for, unseal};
        use sipnab::app::fleet_seal::Kind;
        let rel = path
            .strip_prefix(dir_for(&dir.join("center.store")))?
            .to_string_lossy()
            .into_owned();
        let keys = Keys::new(MasterKey::parse(STORE_KEY)?, Vec::new());
        let parquet = unseal(&rel, &std::fs::read(path)?, &keys, Kind::Calls)?;
        let reader = SerializedFileReader::new(bytes::Bytes::from(parquet))?;
        Ok(reader
            .metadata()
            .row_groups()
            .iter()
            .flat_map(|group| group.columns().iter().map(|column| column.compression()))
            .collect())
    }

    #[test]
    fn the_center_files_zstd_beside_an_earlier_releases_file_and_answers_from_both()
    -> Result<(), TestError> {
        use parquet::basic::Compression;
        let dir = tempfile::tempdir()?;
        let hour_ago = chrono::Utc::now() - chrono::TimeDelta::hours(1);
        let old = file_as_0_5_251(
            dir.path(),
            &[
                row_at("edge-a", hour_ago, 101),
                row_at("edge-b", hour_ago, 102),
            ],
        )?;
        let old_bytes = std::fs::read(&old)?;
        assert_eq!(
            codecs_of(dir.path(), &old)?,
            vec![Compression::UNCOMPRESSED; 8],
            "success the file of the earlier release has no codec"
        );
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        push(&c.addr, "edge-a", 1, 3)?;
        drop(c);
        // The start files what the intake held.
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("filed 3 call record(s) in 1 file(s)")),
            "success the start files the three pushed records: {:?}",
            c.early
        );
        let files = files_under(&dir.path().join("center.store.parquet"))?;
        let new: Vec<&PathBuf> = files
            .iter()
            .map(|(p, _)| p)
            .filter(|p| **p != old)
            .collect();
        let [new] = new.as_slice() else {
            return Err(format!("one new file beside the old one, got {new:?}").into());
        };
        let codecs = codecs_of(dir.path(), new)?;
        assert!(
            codecs.len() == 8 && codecs.iter().all(|c| matches!(c, Compression::ZSTD(_))),
            "success every column of the file the center wrote is zstd: {codecs:?}"
        );
        assert_eq!(
            std::fs::read(&old)?,
            old_bytes,
            "success the center does not rewrite the file of the earlier release"
        );
        let (status, all) = calls(&c.addr, "")?;
        assert_eq!(
            (status, &all["count"], &all["files_read"], &all["complete"]),
            (
                200,
                &serde_json::json!(5),
                &serde_json::json!(2),
                &serde_json::json!(true)
            ),
            "success one answer holds the rows of the uncompressed file and of the zstd file: \
             {all}"
        );
        assert_eq!(
            all["refused"].as_array().map(Vec::len),
            Some(0),
            "success no file is refused: {all}"
        );
        Ok(())
    }

    #[test]
    fn the_members_of_one_filing_share_one_file_whose_path_names_no_member() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        push(&c.addr, "edge-a", 1, 3)?;
        push(&c.addr, "edge-b", 1, 2)?;
        push(&c.addr, "edge-c", 1, 1)?;
        drop(c);
        // The start files what the intake held: one filing for six
        // records of three members.
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("filed 6 call record(s) in 1 file(s)")),
            "success three members' records of one filing are one file: {:?}",
            c.early
        );
        let files = files_under(&dir.path().join("center.store.parquet"))?;
        assert_eq!(
            files.len(),
            1,
            "success one file on disk: {:?}",
            files.iter().map(|(p, _)| p).collect::<Vec<_>>()
        );
        let path = files[0].0.to_string_lossy().into_owned();
        assert!(
            path.contains("center.store.parquet/calls/date=")
                && !path.contains("member=")
                && !path.contains("edge-"),
            "success its path is the class, the day and a name, with no member: {path}"
        );
        let (_, one) = calls(&c.addr, "?member=edge-b")?;
        assert_eq!(
            (&one["count"], &one["files_read"], &one["complete"]),
            (
                &serde_json::json!(2),
                &serde_json::json!(1),
                &serde_json::json!(true)
            ),
            "success one member's records are read from the shared file: {one}"
        );
        assert!(
            one["calls"]
                .as_array()
                .is_some_and(|rows| rows.iter().all(|row| row["member"] == "edge-b")),
            "success and no other member's record is answered: {one}"
        );
        Ok(())
    }

    #[test]
    fn files_release_0_5_249_wrote_are_answered_and_stay_where_they_are() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let hour_ago = chrono::Utc::now() - chrono::TimeDelta::hours(1);
        // An hour ago can be yesterday: each file's rows are of one day.
        let old_a = file_as_0_5_249(
            dir.path(),
            &[row_at("edge-a", hour_ago, 1), row_at("edge-a", hour_ago, 2)],
        )?;
        let old_b = file_as_0_5_249(dir.path(), &[row_at("edge-b", hour_ago, 7)])?;
        assert!(
            old_a.to_string_lossy().contains("/member=edge-a/"),
            "success the file is at a path of release 0.5.249: {}",
            old_a.display()
        );
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        let (status, all) = calls(&c.addr, "")?;
        assert_eq!(
            (status, &all["count"], &all["complete"]),
            (200, &serde_json::json!(3), &serde_json::json!(true)),
            "success the rows of both old files are answered: {all}"
        );
        let (_, one) = calls(&c.addr, "?member=edge-a")?;
        assert_eq!(
            (&one["count"], &one["files_read"]),
            (&serde_json::json!(2), &serde_json::json!(1)),
            "success one member's old file is opened and the other's is not: {one}"
        );
        let (_, none) = calls(&c.addr, "?member=edge-z")?;
        assert_eq!(
            (&none["count"], &none["files_read"]),
            (&serde_json::json!(0), &serde_json::json!(0)),
            "success a member with no directory opens no old file: {none}"
        );
        assert!(
            old_a.exists() && old_b.exists(),
            "success a start leaves the old files at their paths"
        );
        Ok(())
    }

    #[test]
    fn a_start_removes_past_days_of_both_layouts_and_counts_their_files() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let now = chrono::Utc::now();
        let long_ago = now - chrono::TimeDelta::days(40);
        let old = file_as_0_5_249(dir.path(), &[row_at("edge-a", long_ago, 1)])?;
        let store = history(dir.path())?;
        store.file(&[row_at("edge-a", long_ago, 2), row_at("edge-b", long_ago, 1)])?;
        store.file(&[row_at("edge-a", now, 3)])?;
        let c = center(dir.path(), &["--calls-retention-days", "2"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("1 day(s) and 2 file(s)")
                    && l.contains("--calls-retention-days 2")),
            "success the start removes the old day and counts the file of each layout: {:?}",
            c.early
        );
        assert!(
            !old.exists(),
            "success the file release 0.5.249 wrote is gone"
        );
        let left = files_under(&dir.path().join("center.store.parquet"))?;
        assert_eq!(left.len(), 1, "success today's file is the one left");
        let (_, answer) = calls(&c.addr, "")?;
        assert_eq!(
            answer["count"], 1,
            "success and its row is answered: {answer}"
        );
        Ok(())
    }

    #[test]
    fn records_release_0_5_249_filed_before_a_kill_are_not_filed_again() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        push(&c.addr, "edge-a", 1, 4)?;
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
        // Release 0.5.249 filed two of them and was stopped before it
        // emptied its intake; this build starts on what it left.
        let same_day = waiting[0].received_at.date_naive() == waiting[1].received_at.date_naive();
        assert!(same_day, "edge the two records are of one day");
        file_as_0_5_249(dir.path(), &waiting[..2])?;
        drop(c);
        let c = center(dir.path(), &["--calls-flush-secs", "3600"])?;
        assert!(
            c.early
                .iter()
                .any(|l| l.contains("filed 2 call record(s) in 1 file(s)")
                    && l.contains("2 were in it already")),
            "edge the start files the two rows no file holds and leaves the two an old file \
             holds: {:?}",
            c.early
        );
        let (_, answer) = calls(&c.addr, "")?;
        assert_eq!(
            (&answer["count"], &answer["files_read"]),
            (&serde_json::json!(4), &serde_json::json!(2)),
            "edge four rows, none twice, from one file of each layout: {answer}"
        );
        Ok(())
    }

    #[test]
    fn a_changed_file_is_reported_and_the_center_keeps_serving() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let c = center(dir.path(), &["--calls-flush-secs", "1"])?;
        // Two filings, so two files: the first holds edge-a's rows, and
        // every row of the second was received after `between`.
        push(&c.addr, "edge-a", 1, 3)?;
        let filed = wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 3))?;
        assert!(filed, "failure edge-a's records were filed first");
        let files = files_under(&dir.path().join("center.store.parquet"))?;
        assert_eq!(files.len(), 1, "failure one filing is one file");
        let between = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        push(&c.addr, "edge-b", 1, 2)?;
        let filed = wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 5))?;
        assert!(filed, "failure edge-b's records were filed next");
        let (path, mut bytes) = files.into_iter().next().ok_or("the first file")?;
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
            "failure the rows of the other file are answered"
        );
        let (status, narrow) = calls(&c.addr, &format!("?from={between}"))?;
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
        drop(c);
        // The next start leaves the earlier key out: the store file is
        // under the new key by now, the history file is not.
        let c = start(None)?;
        let (status, answer) = calls(&c.addr, "")?;
        assert_eq!(
            (status, answer["count"].as_u64(), &answer["complete"]),
            (200, Some(0), &serde_json::json!(false)),
            "edge without the earlier key the center starts and answers without its files: \
             {answer}"
        );
        assert!(
            answer["refused"][0]["reason"]
                .as_str()
                .is_some_and(|why| why
                    .starts_with("sealed layer: the file was written under key id ")
                    && why.ends_with(", which is not loaded")),
            "edge the refused file names the key it is under: {answer}"
        );
        Ok(())
    }

    // ---- `sipnab fleet verify`, the real binary beside a center ----------
    //
    // Every pass runs through `sipnab_within`: one that is still there at
    // the deadline is killed and fails its test.

    /// The summary line of class `members` in a store that holds no
    /// heartbeat.
    const NO_MEMBERS: &str = "members: 0 files, 0 clean, 0 refused, 0 gone, 0 rows\n";

    /// What a reader of the store says of a FIFO under a history file's
    /// name.
    const NOT_A_FILE: &str = "is a pipe or FIFO, not a file of the history store";

    /// The summary of a store whose one file of call records holds two
    /// rows and is clean.
    fn two_rows_clean() -> String {
        format!("calls: 1 files, 1 clean, 0 refused, 0 gone, 2 rows\n{NO_MEMBERS}")
    }

    /// A running center in `dir` that filed two call records into one
    /// file, and that file's path.
    fn filed_center(dir: &Path) -> Result<(Center, PathBuf), TestError> {
        let c = center(dir, &["--calls-flush-secs", "1"])?;
        push(&c.addr, "edge-a", 1, 2)?;
        if !wait_until(WAIT, || Ok(history_report(&c.addr)?["rows_filed"] == 2))? {
            return Err(format!("the center did not file: {}", history_report(&c.addr)?).into());
        }
        let files = files_under(&dir.join("center.store.parquet"))?;
        match files.as_slice() {
            [(path, _)] => Ok((c, path.clone())),
            _ => Err(format!("one filing is one file, not {}", files.len()).into()),
        }
    }

    /// `sipnab fleet verify` on the store file `store` under the key file
    /// `key`, with `more` arguments, ended at the deadline.
    fn verify_at(
        store: &Path,
        key: &Path,
        more: &[&str],
    ) -> Result<(Option<i32>, String, String), TestError> {
        let mut args = vec![
            "fleet",
            "verify",
            "--store",
            store.to_str().ok_or("utf-8")?,
            "--store-key-file",
            key.to_str().ok_or("utf-8")?,
        ];
        args.extend_from_slice(more);
        fleet_center::sipnab_within(&args, WAIT)
    }

    /// `sipnab fleet verify` on the store of the center in `dir`.
    fn verify(dir: &Path, more: &[&str]) -> Result<(Option<i32>, String, String), TestError> {
        verify_at(
            &dir.join("center.store"),
            &dir.join("center.storekey"),
            more,
        )
    }

    /// Copy the directory `from`, with everything under it, to `to`.
    fn copy_tree(from: &Path, to: &Path) -> Result<(), TestError> {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target)?;
            }
        }
        Ok(())
    }

    #[test]
    fn success_a_pass_beside_a_running_center_is_clean_and_exits_0() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, _file) = filed_center(dir.path())?;
        let history = dir.path().join("center.store.parquet");
        let before = files_under(&history)?;
        let (code, out, err) = verify(dir.path(), &[])?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (Some(0), two_rows_clean().as_str(), ""),
            "success a pass beside a running center reads its file and both rows"
        );
        assert_eq!(
            files_under(&history)?,
            before,
            "success the pass created and changed nothing in the history directory"
        );
        let (status, answer) = calls(&c.addr, "")?;
        assert_eq!(
            (status, answer["count"].as_u64(), &answer["complete"]),
            (200, Some(2), &serde_json::json!(true)),
            "success the center answers as before the pass: {answer}"
        );
        Ok(())
    }

    #[test]
    fn success_the_json_of_a_pass_names_the_version_and_the_start() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (_c, file) = filed_center(dir.path())?;
        let earliest = chrono::Utc::now().timestamp();
        let (code, out, err) = verify(dir.path(), &["--json"])?;
        let latest = chrono::Utc::now().timestamp();
        assert_eq!(
            (code, err.as_str(), out.lines().count()),
            (Some(0), "", 1),
            "success --json prints one document on one line and exits 0: {out}"
        );
        let report: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            report["version"],
            env!("CARGO_PKG_VERSION"),
            "success the document names the version of the program that ran the pass"
        );
        let started = chrono::DateTime::parse_from_rfc3339(
            report["started_at"].as_str().ok_or("started_at is text")?,
        )?
        .timestamp();
        assert!(
            (earliest..=latest).contains(&started),
            "success started_at is the RFC 3339 time the pass started: {} is not in \
             {earliest}..={latest}",
            report["started_at"]
        );
        assert_eq!(
            (&report["result"], &report["classes"][0], &report["refused"]),
            (
                &serde_json::json!("clean"),
                &serde_json::json!({
                    "class": "calls", "files": 1, "clean": 1, "refused": 0, "gone": 0, "rows": 2
                }),
                &serde_json::json!([])
            ),
            "success the document carries the verdict and the counts of {}",
            file.display()
        );
        Ok(())
    }

    #[test]
    fn success_a_copy_of_the_history_directory_verifies_clean() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, _file) = filed_center(dir.path())?;
        // The copy is made while the center runs, as a backup is.
        let backup = dir.path().join("backup");
        copy_tree(
            &dir.path().join("center.store.parquet"),
            &backup.join("center.store.parquet"),
        )?;
        assert!(
            !backup.join("center.store").exists(),
            "success the copy holds the history directory and no store file"
        );
        let (code, out, err) = verify_at(
            &backup.join("center.store"),
            &dir.path().join("center.storekey"),
            &[],
        )?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (Some(0), two_rows_clean().as_str(), ""),
            "success a backup copy of the history directory is verified where it lies"
        );
        drop(c);
        Ok(())
    }

    #[test]
    fn failure_a_truncated_file_is_refused_with_exit_1() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, file) = filed_center(dir.path())?;
        let bytes = std::fs::read(&file)?;
        std::fs::write(&file, bytes.get(..bytes.len() / 2).ok_or("half the file")?)?;
        let rel = file
            .strip_prefix(dir.path().join("center.store.parquet"))?
            .to_str()
            .ok_or("utf-8")?
            .to_string();
        let (code, out, err) = verify(dir.path(), &[])?;
        assert_eq!(
            (code, err.as_str()),
            (Some(1), ""),
            "failure a refused file is exit status 1, and no error of the pass: {out}"
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(
            matches!(lines.as_slice(), [refused, calls, members]
                if refused.starts_with(&format!("refused: {rel}: "))
                    && *calls == "calls: 1 files, 0 clean, 1 refused, 0 gone, 0 rows"
                    && NO_MEMBERS.trim_end() == *members),
            "failure one line names the file and its reason, then one line for each class: {out}"
        );
        let (code, out, _) = verify(dir.path(), &["--json"])?;
        let report: serde_json::Value = serde_json::from_str(&out)?;
        assert_eq!(
            (code, &report["result"], &report["refused"][0]["file"]),
            (
                Some(1),
                &serde_json::json!("refused"),
                &serde_json::json!(rel)
            ),
            "failure the JSON of the same pass names the file and exits 1: {out}"
        );
        drop(c);
        Ok(())
    }

    #[test]
    fn failure_a_store_with_no_history_directory_exits_2() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, _file) = filed_center(dir.path())?;
        let other = dir.path().join("other.store");
        let (code, out, err) = verify_at(&other, &dir.path().join("center.storekey"), &[])?;
        assert_eq!(
            (code, out.as_str(), err),
            (
                Some(2),
                "",
                format!(
                    "sipnab fleet verify: no history directory '{}.parquet': nothing to verify\n",
                    other.display()
                )
            ),
            "failure a --store with no history directory beside it is not a clean pass"
        );
        assert!(
            !dir.path().join("other.store.parquet").exists(),
            "failure the pass did not create the directory it did not find"
        );
        drop(c);
        Ok(())
    }

    #[test]
    fn failure_a_pass_under_another_key_refuses_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, _file) = filed_center(dir.path())?;
        let other = private_file(
            dir.path(),
            "other.storekey",
            "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n",
        )?;
        let (code, out, err) = verify_at(&dir.path().join("center.store"), &other, &[])?;
        assert_eq!(
            (code, err.as_str()),
            (Some(1), ""),
            "failure a file under a key the pass was not given is a refused file: {out}"
        );
        assert!(
            out.contains("sealed layer: the file was written under key id ")
                && out.contains("calls: 1 files, 0 clean, 1 refused, 0 gone, 0 rows\n"),
            "failure the line names the key the file is under: {out}"
        );
        drop(c);
        Ok(())
    }

    #[test]
    fn failure_a_fifo_in_a_running_centers_store_is_refused_and_not_waited_on()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, file) = filed_center(dir.path())?;
        // A FIFO beside the file, under a name the store writes: the times
        // of the file's name, and another mark.
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("a file name")?;
        let (times, _mark) = name.rsplit_once("-h").ok_or("a name with a mark")?;
        let fifo = file.with_file_name(format!("{times}-h0000000000000001.sealed"));
        let made = std::process::Command::new("mkfifo").arg(&fifo).status()?;
        assert!(made.success(), "failure mkfifo made the FIFO: {made}");
        let rel = fifo
            .strip_prefix(dir.path().join("center.store.parquet"))?
            .to_str()
            .ok_or("utf-8")?
            .to_string();
        // `http` gives the answer ten seconds: a center that waits on the
        // FIFO for a writer fails here.
        let (status, answer) = calls(&c.addr, "")?;
        assert_eq!(
            (status, answer["count"].as_u64(), &answer["complete"]),
            (200, Some(2), &serde_json::json!(false)),
            "failure the center answers with the rows of the file and says it is not whole: \
             {answer}"
        );
        assert_eq!(
            (
                &answer["refused"][0]["file"],
                &answer["refused"][0]["reason"]
            ),
            (&serde_json::json!(rel), &serde_json::json!(NOT_A_FILE)),
            "failure the FIFO is the refused file, with the reason: {answer}"
        );
        let (code, out, err) = verify(dir.path(), &[])?;
        assert_eq!(
            (code, err.as_str()),
            (Some(1), ""),
            "failure a pass beside that center ends, with exit status 1: {out}"
        );
        assert!(
            out.contains(&format!("refused: {rel}: {NOT_A_FILE}\n"))
                && out.contains("calls: 2 files, 1 clean, 1 refused, 0 gone, 2 rows\n"),
            "failure the pass names the FIFO and reads the file beside it: {out}"
        );
        let (status, later) = calls(&c.addr, "?call_id=call-1%40example.com")?;
        assert_eq!(
            (status, later["count"].as_u64()),
            (200, Some(1)),
            "failure the center goes on answering: {later}"
        );
        Ok(())
    }

    #[test]
    fn edge_one_class_or_a_window_with_no_file_exits_0() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (c, _file) = filed_center(dir.path())?;
        let (code, out, err) = verify(dir.path(), &["--class", "members"])?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (Some(0), NO_MEMBERS, ""),
            "edge --class members reads no call record and prints one line"
        );
        let (code, out, err) = verify(dir.path(), &["--class", "calls", "--to", "2000-01-01"])?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (
                Some(0),
                "calls: 0 files, 0 clean, 0 refused, 0 gone, 0 rows\n",
                ""
            ),
            "edge a window that ends before the first day reads no file and is clean"
        );
        let (code, out, err) = verify(dir.path(), &["--from", "2000-01-02", "--to", "2000-01-01"])?;
        assert_eq!(
            (code, out.as_str(), err.as_str()),
            (
                Some(2),
                "",
                "sipnab fleet verify: --from 2000-01-02 is after --to 2000-01-01\n"
            ),
            "edge a window that ends before it starts cannot run"
        );
        drop(c);
        Ok(())
    }

    /// `len` characters that differ from row to row, so that the codec does
    /// not remove them: hex digits from a generator seeded with `seed`.
    fn varied(seed: u64, len: usize) -> String {
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut out = String::with_capacity(len + 16);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push_str(&format!("{state:016x}"));
        }
        out.truncate(len);
        out
    }

    /// The bytes of the sealed files under `dir`.
    fn sealed_bytes(dir: &Path) -> Result<u64, TestError> {
        Ok(files_under(dir)?
            .iter()
            .filter(|(path, _)| path.extension().is_some_and(|e| e == "sealed"))
            .map(|(_, bytes)| bytes.len() as u64)
            .sum())
    }

    /// One pass of the real binary, timed: what it took and what it printed
    /// go to the real stderr under `label`, for the how-to.
    fn measured(
        label: &str,
        dir: &Path,
        more: &[&str],
        code: Option<i32>,
    ) -> Result<String, TestError> {
        use std::io::Write as _;
        let started = Instant::now();
        let store = dir.join("center.store");
        let key = dir.join("center.storekey");
        let mut args = vec![
            "fleet",
            "verify",
            "--store",
            store.to_str().ok_or("utf-8")?,
            "--store-key-file",
            key.to_str().ok_or("utf-8")?,
        ];
        args.extend_from_slice(more);
        let (got, out, err) = fleet_center::sipnab_within(&args, Duration::from_secs(1800))?;
        let took = started.elapsed();
        writeln!(
            std::io::stderr(),
            "verify-measure {label} args={more:?} took={took:?} exit={got:?}\n\
             verify-measure-stdout-begin\n{out}verify-measure-stdout-end\n\
             verify-measure-stderr-begin\n{err}verify-measure-stderr-end"
        )?;
        assert_eq!(got, code, "edge the pass {label} ended as expected: {err}");
        Ok(out)
    }

    /// A pass of the real binary over a store of the size of a fleet,
    /// timed: 20 filings of 54,000 call records of about 1.2 kB, and one day
    /// of heartbeats of 2,000 members, one filing a minute. Then one file
    /// is cut in half, and the pass that refuses it is printed as lines and
    /// as JSON: the how-to's sample outputs are these.
    ///
    /// It is a measurement and not a check, so it runs only when asked for
    /// by name, in a release build (`cargo test --release --features full
    /// --test fleet_history_test a_pass_of_the_binary_is_measured --
    /// --ignored --nocapture`), and prints its figures.
    #[test]
    #[ignore = "a measurement: run it by name with --ignored in a release build"]
    fn edge_a_pass_of_the_binary_is_measured_for_a_fleet() -> Result<(), TestError> {
        use sipnab::app::fleet_calls::CallCounts;
        use sipnab::app::fleet_center::{Cursor, MemberRecord};
        use std::io::Write as _;
        let dir = tempfile::tempdir()?;
        let store = history(dir.path())?;
        store_key_file(dir.path())?;
        let day = chrono::DateTime::parse_from_rfc3339("2026-11-11T00:00:00Z")?
            .with_timezone(&chrono::Utc);
        let at = |ms: u64| -> Result<chrono::DateTime<chrono::Utc>, TestError> {
            Ok(day + chrono::TimeDelta::milliseconds(i64::try_from(ms)?))
        };
        for filing in 0..20_u64 {
            let rows = (0..54_000_u64)
                .map(|n| {
                    let seq = filing * 54_000 + n + 1;
                    let mut row = row_at(
                        &format!("edge-{:04}", n % 2000),
                        at(filing * 60_000 + n)?,
                        seq,
                    );
                    row.call["from"] = serde_json::json!("sip:+12025550101@example.com");
                    row.call["detail"] = serde_json::Value::String(varied(seq, 1000));
                    Ok(row)
                })
                .collect::<Result<Vec<IntakeRecord>, TestError>>()?;
            store.file(&rows)?;
        }
        for minute in 0..1440_u64 {
            let rows = (0..2000_u64)
                .map(|m| {
                    let member = format!("edge-{m:04}");
                    let received_at = at(minute * 60_000 + m)?;
                    Ok(MemberRecord {
                        received_at,
                        peer: "192.0.2.10".to_string(),
                        heartbeats: minute + 1,
                        cursor: Cursor {
                            stream: "s".to_string(),
                            seq: minute + 1,
                            sent_at: received_at,
                        },
                        heartbeat_secs: 60,
                        inventory: serde_json::json!({
                            "schema_version": 1,
                            "node_name": member,
                            "digest": varied(minute * 2000 + m, 240),
                        }),
                        call_records: minute + 1,
                        calls: Some(CallCounts {
                            selected: minute + 1,
                            dropped_by_cap: 0,
                            left_out: 0,
                            spooled: 0,
                        }),
                        member,
                    })
                })
                .collect::<Result<Vec<MemberRecord>, TestError>>()?;
            store.file(&rows)?;
        }
        let history_dir = dir.path().join("center.store.parquet");
        writeln!(
            std::io::stderr(),
            "verify-measure store calls_sealed_bytes={} members_sealed_bytes={}",
            sealed_bytes(&history_dir.join("calls"))?,
            sealed_bytes(&history_dir.join("members"))?
        )?;
        for round in ["round-0", "round-1", "round-2"] {
            measured(round, dir.path(), &["--class", "calls"], Some(0))?;
            measured(round, dir.path(), &["--class", "members"], Some(0))?;
            measured(round, dir.path(), &[], Some(0))?;
        }
        let (file, bytes) = files_under(&history_dir.join("calls"))?
            .into_iter()
            .next()
            .ok_or("a file of call records")?;
        std::fs::write(&file, bytes.get(..bytes.len() / 2).ok_or("half the file")?)?;
        let lines = measured("refused", dir.path(), &[], Some(1))?;
        assert!(
            lines.starts_with("refused: calls/date=2026-11-11/"),
            "edge the cut file is the refused one: {lines}"
        );
        measured("refused-json", dir.path(), &["--json"], Some(1))?;
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
                p.contains("center.store.parquet/members/date=") && !p.contains("member=")
            }),
            "success the file is under class members and its day, with no member in the path: \
             {paths:?}"
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
