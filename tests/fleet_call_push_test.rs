// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Fleet call records, end to end on real binaries: `sipnab` members that
//! read a capture and push their ended calls, and a `sipnab fleet serve`
//! center that stores them.
//!
//! What only real processes show: the record the center stored equals the
//! member's own REST answer for the dialog; a record the center
//! acknowledged is still there after the center is killed; nothing in the
//! member's spool or the center's intake holds a call in clear; the
//! exception cap holds and both ends count what it dropped.

#![cfg(all(feature = "api", unix))]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[path = "support/server.rs"]
mod server;

#[path = "support/fleet_center.rs"]
mod fleet_center;

#[path = "support/pcap_build.rs"]
mod pcap_build;

#[path = "support/ports.rs"]
mod ports;

use fleet_center::{Center, TestError, http, store_key_file};
use server::ApiServer;

/// The center's signing key.
const CENTER_KEY: &str = "fleet-call-push-e2e-center-key-0123456789abcdef";

/// The members' own API signing key.
const MEMBER_KEY: &str = "fleet-call-push-e2e-member-key-0123456789abcdef";

/// A spool key file's text: a key whose every byte is 2.
const SPOOL_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n";

/// The store key `store_key_file` writes: every byte is 1.
const STORE_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

/// How long a test waits for a member's push: the member looks at its
/// dialogs at its start and every 5 seconds after.
const PUSH_WAIT: Duration = Duration::from_secs(40);

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

/// `text` in a new file of `dir` that only this user can read.
fn private_file(dir: &Path, name: &str, text: &str) -> Result<PathBuf, TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(text.as_bytes())?;
    Ok(path)
}

/// A center on `listen` whose store is in `dir`.
fn center(dir: &Path, listen: &str) -> Result<Center, TestError> {
    let key = match std::fs::metadata(dir.join("center.signing")) {
        Ok(_) => dir.join("center.signing"),
        Err(_) => private_file(dir, "center.signing", CENTER_KEY)?,
    };
    let store = dir.join("center.store");
    let store_key = store_key_file(dir)?;
    Center::start(&[
        "--listen",
        listen,
        "--store",
        store.to_str().ok_or("utf-8")?,
        "--store-key-file",
        store_key.to_str().ok_or("utf-8")?,
        "--signing-key-file",
        key.to_str().ok_or("utf-8")?,
    ])
}

/// A member and where its spool is.
struct Member {
    srv: ApiServer,
    spool: PathBuf,
}

/// A member named `name` that reads `pcap`, reports to `center` every
/// second and pushes calls under `[fleet]` keys `calls` (TOML lines).
fn member(
    dir: &Path,
    name: &str,
    center: &str,
    pcap: &str,
    calls: &str,
) -> Result<Member, TestError> {
    let tok = private_file(
        dir,
        &format!("{name}.token"),
        &token(name, sipnab::auth::SCOPE_FLEET_REPORT),
    )?;
    let key = private_file(dir, &format!("{name}.spoolkey"), SPOOL_KEY)?;
    let spool = dir.join(format!("{name}.spool"));
    let cfg = dir.join(format!("{name}.toml"));
    std::fs::write(
        &cfg,
        format!(
            "[fleet]\nreport_url = \"http://{center}\"\nreport_token_file = {:?}\n\
             spool_dir = {:?}\nheartbeat_secs = 1\nspool_key_file = {:?}\n{calls}\n",
            tok.to_str().ok_or("utf-8")?,
            spool.to_str().ok_or("utf-8")?,
            key.to_str().ok_or("utf-8")?,
        ),
    )?;
    let srv = ApiServer::spawn_with_pcap(
        pcap,
        &[
            "--api-signing-key",
            MEMBER_KEY,
            "--node-name",
            name,
            "--config",
            cfg.to_str().ok_or("utf-8")?,
        ],
    )?;
    Ok(Member { srv, spool })
}

/// The center's members answer.
fn members(addr: &str) -> Result<serde_json::Value, TestError> {
    let reader = token("reader", sipnab::auth::SCOPE_INVENTORY);
    let (status, body) = http(addr, "GET", "/v1/fleet/members", &reader, b"")?;
    if status != 200 {
        return Err(format!("members answered {status}: {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

/// `member`'s row at the center, or null.
fn row(addr: &str, member: &str) -> Result<serde_json::Value, TestError> {
    let all = members(addr)?;
    Ok(all["members"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["member"] == member))
        .cloned()
        .unwrap_or_default())
}

/// Poll `f` until it is true or `within` has passed.
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

/// The call records the center whose store is in `dir` holds, oldest
/// first, read from its files with the store key: those in the intake
/// and, in a build with the history store, those the center filed, each
/// once.
fn intake(dir: &Path) -> Result<Vec<serde_json::Value>, TestError> {
    use sipnab::app::fleet_seal::{Keys, Kind, MasterKey, open_log};
    let keys = Keys::new(MasterKey::parse(STORE_KEY)?, Vec::new());
    let bytes = std::fs::read(dir.join("center.store.intake"))?;
    let log = open_log(&bytes, &keys, Kind::Intake).map_err(|e| e.to_string())?;
    #[cfg(not(feature = "fleet-store"))]
    {
        log.records
            .iter()
            .map(|line| Ok(serde_json::from_slice(line)?))
            .collect()
    }
    #[cfg(feature = "fleet-store")]
    {
        use sipnab::app::fleet_history::{History, Query};
        let waiting = log
            .records
            .iter()
            .map(|line| Ok(serde_json::from_slice(line)?))
            .collect::<Result<Vec<sipnab::app::fleet_intake::IntakeRecord>, TestError>>()?;
        let history = History::reader(&dir.join("center.store"), std::sync::Arc::new(keys));
        let all = Query::all();
        let files = history.list(sipnab::app::fleet_history::CLASS_CALLS, &all)?;
        let answer = history.answer(&all, &files, waiting);
        if let Some((file, why)) = answer.refused.first() {
            return Err(format!("{file}: {why}").into());
        }
        answer
            .rows
            .iter()
            .rev()
            .map(|row| Ok(serde_json::to_value(row)?))
            .collect()
    }
}

/// The member's own REST answer for the dialog `call_id`, without the
/// capture identity the API stamps on every answer: that describes the
/// capture at the moment of asking, not the dialog.
fn rest_answer(member: &Member, call_id: &str) -> Result<serde_json::Value, TestError> {
    let reader = sipnab::auth::mint(
        MEMBER_KEY.as_bytes(),
        "reader",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_FULL,
    );
    let path = format!("/v1/dialogs/{}", call_id.replace('@', "%40"));
    let resp = member.srv.get_bearer(&path, &reader)?;
    if resp.status != 200 {
        return Err(format!("{path} answered {}: {}", resp.status, resp.body).into());
    }
    let mut answer = resp.json()?;
    if let Some(object) = answer.as_object_mut() {
        object.remove("capture_identity");
    }
    Ok(answer)
}

/// Every file under `dir`, with its bytes.
fn files_under(dir: &Path) -> Result<Vec<(PathBuf, Vec<u8>)>, TestError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                // A file delivered and removed since the listing is not read.
                out.push((path, bytes));
            }
        }
    }
    Ok(out)
}

/// Whether `bytes` holds `needle`.
fn holds(bytes: &[u8], needle: &str) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// One SIP message between the two test hosts, as an Ethernet frame.
fn frame(first_line: &str, call_id: &str, cseq: &str, from_caller: bool) -> Vec<u8> {
    let text = format!(
        "{first_line}\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK{call_id}\r\n\
         Max-Forwards: 70\r\nFrom: <sip:+12025550101@192.0.2.10>;tag=a\r\n\
         To: <sip:+12025550102@192.0.2.20>;tag=b\r\nCall-ID: {call_id}\r\nCSeq: {cseq}\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let (a, b) = ([192, 0, 2, 10], [192, 0, 2, 20]);
    if from_caller {
        pcap_build::udp_frame(a, b, 5060, 5060, text.as_bytes())
    } else {
        pcap_build::udp_frame(b, a, 5060, 5060, text.as_bytes())
    }
}

/// A capture in `dir` of `busy` calls answered `486 Busy Here` and
/// `answered` calls that were answered and ended with `BYE`.
fn capture(dir: &Path, busy: usize, answered: usize) -> Result<String, TestError> {
    let invite = "INVITE sip:+12025550102@192.0.2.20 SIP/2.0";
    let mut frames = Vec::new();
    for i in 0..busy {
        let id = format!("busy-{i}@192.0.2.10");
        frames.push(frame(invite, &id, "1 INVITE", true));
        frames.push(frame("SIP/2.0 486 Busy Here", &id, "1 INVITE", false));
        frames.push(frame(
            "ACK sip:+12025550102@192.0.2.20 SIP/2.0",
            &id,
            "1 ACK",
            true,
        ));
    }
    for i in 0..answered {
        let id = format!("answered-{i}@192.0.2.10");
        frames.push(frame(invite, &id, "1 INVITE", true));
        frames.push(frame("SIP/2.0 200 OK", &id, "1 INVITE", false));
        frames.push(frame(
            "ACK sip:+12025550102@192.0.2.20 SIP/2.0",
            &id,
            "1 ACK",
            true,
        ));
        frames.push(frame(
            "BYE sip:+12025550102@192.0.2.20 SIP/2.0",
            &id,
            "2 BYE",
            true,
        ));
        frames.push(frame("SIP/2.0 200 OK", &id, "2 BYE", false));
    }
    let path = dir.join(format!("calls-{busy}-{answered}.pcap"));
    pcap_build::write_pcap(&path, &frames)?;
    Ok(path.to_str().ok_or("utf-8")?.to_string())
}

/// Two members, one center. The member under `exceptions` pushes its failed
/// call and not its answered one; the member under `all` pushes both. Each
/// record the center stored equals that member's own REST answer for the
/// dialog, field for field. The center is then killed with SIGKILL and
/// started again: the records it acknowledged are still in its intake, and
/// the same records sent again are counted as duplicates and not stored.
#[test]
fn a_pushed_record_equals_the_members_rest_answer_and_survives_a_killed_center()
-> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), 1, 1)?;
    let listen = "127.0.0.1:0";
    let c = center(dir.path(), listen)?;
    let addr = c.addr.clone();
    let exceptions = member(dir.path(), "edge-exc", &addr, &pcap, "")?;
    let all = member(dir.path(), "edge-all", &addr, &pcap, "call_push = \"all\"")?;
    let pushed = wait_until(PUSH_WAIT, || {
        Ok(row(&addr, "edge-exc")?["verified"]["call_records"] == 1
            && row(&addr, "edge-all")?["verified"]["call_records"] == 2)
    })?;
    assert!(pushed, "the center's members: {}", members(&addr)?);

    let stored = intake(dir.path())?;
    let of = |member: &str| -> Vec<&serde_json::Value> {
        stored.iter().filter(|r| r["member"] == member).collect()
    };
    let (exc, both) = (of("edge-exc"), of("edge-all"));
    assert_eq!(exc.len(), 1, "{stored:?}");
    assert_eq!(
        exc[0]["call"]["call_id"], "busy-0@192.0.2.10",
        "a pushed record equals the members rest answer and survives a killed center"
    );
    assert_eq!(
        exc[0]["selected_by"], "failed",
        "a pushed record equals the members rest answer and survives a killed center"
    );
    assert_eq!(both.len(), 2, "{stored:?}");
    for (who, records) in [(&exceptions, &exc), (&all, &both)] {
        for record in records {
            let call_id = record["call"]["call_id"].as_str().ok_or("a call id")?;
            let rest = rest_answer(who, call_id)?;
            assert!(
                rest.as_object().is_some_and(|o| o.len() > 10),
                "a full answer: {rest}"
            );
            assert_eq!(
                record["call"], rest,
                "the stored record is the REST answer for {call_id}"
            );
        }
    }
    // The member that pushed under `exceptions` says what it did.
    let said = wait_until(PUSH_WAIT, || {
        Ok(row(&addr, "edge-exc")?["self_reported"]["calls"]["spooled"] == 1)
    })?;
    assert!(said, "{}", row(&addr, "edge-exc")?);

    // Nothing waits in a spool, and nothing either end wrote holds a call in clear.
    for m in [&exceptions, &all] {
        let waiting = wait_until(PUSH_WAIT, || {
            Ok(!files_under(&m.spool)?
                .iter()
                .any(|(p, _)| p.extension().is_some_and(|e| e == "sealed")))
        })?;
        assert!(
            waiting,
            "a delivery is deleted when the center acknowledges it"
        );
    }
    for (path, bytes) in files_under(dir.path())? {
        let ours = path
            .extension()
            .is_some_and(|e| e == "intake" || e == "store" || e == "sealed");
        if ours {
            for clear in ["2025550101", "busy-0@", "answered-0@"] {
                assert!(!holds(&bytes, clear), "{clear} is in {}", path.display());
            }
        }
    }

    // SIGKILL, then a new center on the same store.
    drop(c);
    let c = center(dir.path(), &addr)?;
    assert_eq!(
        c.addr, addr,
        "a pushed record equals the members rest answer and survives a killed center"
    );
    let after = intake(dir.path())?;
    assert_eq!(after, stored, "every acknowledged record is still there");
    let line = serde_json::json!({
        "schema_version": 1, "kind": "call", "stream": exc[0]["stream"], "seq": exc[0]["seq"],
        "sent_at": exc[0]["sent_at"], "selected_by": "failed", "call": exc[0]["call"],
    })
    .to_string();
    let member_token = token("edge-exc", sipnab::auth::SCOPE_FLEET_REPORT);
    let (status, body) = http(
        &addr,
        "POST",
        "/v1/fleet/ingest",
        &member_token,
        line.as_bytes(),
    )?;
    let answer: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        (status, &answer["calls"]),
        (200, &serde_json::json!(0)),
        "{body}"
    );
    assert_eq!(answer["duplicate"], 1, "{body}");
    assert_eq!(intake(dir.path())?.len(), 3, "a replay is not stored twice");
    Ok(())
}

/// With the center away, a member's call records wait in its spool in
/// sealed files only, and no file there holds a number or a Call-ID in
/// clear. When the center comes, the spool drains and the center has them.
#[test]
fn records_wait_sealed_while_the_center_is_away_and_drain_when_it_comes() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), 2, 0)?;
    // The center's port is held, bound and not listening, for as long as
    // the center is away, so no other test is handed the number. It is let
    // go only where the center takes it.
    let away = ports::refused_tcp_port()?;
    let addr = away.addr().to_string();
    let m = member(dir.path(), "edge-a", &addr, &pcap, "")?;
    let sealed = |spool: &Path| -> Result<usize, TestError> {
        Ok(files_under(spool)?
            .iter()
            .filter(|(p, _)| p.extension().is_some_and(|e| e == "sealed"))
            .count())
    };
    let waits = wait_until(PUSH_WAIT, || Ok(sealed(&m.spool)? == 1))?;
    assert!(
        waits,
        "one sealed delivery waits: {:?}",
        std::fs::read_dir(&m.spool)?.count()
    );
    for (path, bytes) in files_under(&m.spool)? {
        for clear in ["2025550101", "2025550102", "busy-0@", "busy-1@", "call_id"] {
            assert!(!holds(&bytes, clear), "{clear} is in {}", path.display());
        }
    }
    drop(away);
    let c = center(dir.path(), &addr)?;
    let drained = wait_until(PUSH_WAIT, || {
        Ok(row(&c.addr, "edge-a")?["verified"]["call_records"] == 2 && sealed(&m.spool)? == 0)
    })?;
    assert!(drained, "{}", members(&c.addr)?);
    assert_eq!(
        intake(dir.path())?.len(),
        2,
        "records wait sealed while the center is away and drain when it comes"
    );
    Ok(())
}

/// Thirty failed calls and a cap of one exception a second: the member
/// pushes what the cap lets through, counts the rest, and the center
/// stores exactly what the member says it pushed.
#[test]
fn the_exception_cap_holds_and_both_ends_count_it() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let pcap = capture(dir.path(), 30, 0)?;
    let c = center(dir.path(), "127.0.0.1:0")?;
    let m = member(
        dir.path(),
        "edge-a",
        &c.addr,
        &pcap,
        "exception_max_per_sec = 1",
    )?;
    let counted = wait_until(PUSH_WAIT, || {
        let calls = row(&c.addr, "edge-a")?["self_reported"]["calls"].clone();
        Ok(
            calls["selected"].as_u64().unwrap_or(0) + calls["dropped_by_cap"].as_u64().unwrap_or(0)
                == 30
                && calls["spooled"] == calls["selected"],
        )
    })?;
    let seen = row(&c.addr, "edge-a")?;
    assert!(counted, "{seen}");
    let selected = seen["self_reported"]["calls"]["selected"]
        .as_u64()
        .ok_or("selected")?;
    // One record a second since the member started; the calls are pushed
    // once they have stood unchanged for the settle time.
    assert!((1..=25).contains(&selected), "the cap let through: {seen}");
    let stored = wait_until(PUSH_WAIT, || {
        Ok(row(&c.addr, "edge-a")?["verified"]["call_records"] == selected)
    })?;
    assert!(stored, "{}", row(&c.addr, "edge-a")?);
    assert_eq!(
        intake(dir.path())?.len() as u64,
        selected,
        "the exception cap holds and both ends count it"
    );
    drop(m);
    Ok(())
}

/// `call_push` that asks for records with no key to seal them under stops
/// the run at its start, with the fix, before anything is captured.
#[test]
fn call_push_without_a_spool_key_stops_the_run() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let cfg = dir.path().join("member.toml");
    std::fs::write(&cfg, "[fleet]\ncall_push = \"all\"\n")?;
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", pcap, "--config"])
        .arg(&cfg)
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a setting from the file: {stderr}"
    );
    assert!(
        stderr.contains("[fleet] call_push \"all\" needs [fleet] spool_key_file"),
        "{stderr}"
    );
    assert!(
        stderr.contains("sipnab fleet keygen --out FILE"),
        "{stderr}"
    );
    Ok(())
}

/// The real size of a call record's summary, measured over the checked-in
/// captures: each is read by a real member under `call_push = "all"`, and
/// the sizes are those of the `call` the center stored, as compact JSON.
/// Run with `--nocapture` to print them.
#[test]
fn the_summary_size_of_real_captures_is_measured() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let c = center(dir.path(), "127.0.0.1:0")?;
    let captures = [
        ("sip-call", "tests/fixtures/sip_call.pcap"),
        ("rtcp-xr", "tests/fixtures/rtcp-xr-call.pcap"),
        (
            "opensips-proxy",
            "tests/fixtures/opensips-proxy-signaling.pcap",
        ),
        ("rtpengine-ng", "tests/fixtures/rtpengine-opensips-ng.pcap"),
    ];
    let mut running = Vec::new();
    for (name, pcap) in captures {
        running.push(member(
            dir.path(),
            name,
            &c.addr,
            pcap,
            "call_push = \"all\"",
        )?);
    }
    // Three looks of every member, so each capture's ended calls are in.
    let looked = Instant::now() + Duration::from_secs(16);
    wait_until(PUSH_WAIT, || Ok(Instant::now() >= looked))?;
    let stored = intake(dir.path())?;
    let mut sizes: Vec<usize> = Vec::new();
    for (name, _) in captures {
        let mine: Vec<usize> = stored
            .iter()
            .filter(|r| r["member"] == name)
            .map(|r| r["call"].to_string().len())
            .collect();
        println!("summary bytes, {name}: {} call(s) {mine:?}", mine.len());
        sizes.extend(mine);
    }
    sizes.sort_unstable();
    assert!(
        !sizes.is_empty(),
        "no capture had an ended call: {}",
        members(&c.addr)?
    );
    let total: usize = sizes.iter().sum();
    println!(
        "summary bytes over {} call(s): min {} median {} mean {} max {}",
        sizes.len(),
        sizes[0],
        sizes[sizes.len() / 2],
        total / sizes.len(),
        sizes[sizes.len() - 1]
    );
    let largest = sizes[sizes.len() - 1];
    assert!(
        largest < 2 * 1024 * 1024,
        "a summary fits in one delivery: {largest}"
    );
    Ok(())
}
