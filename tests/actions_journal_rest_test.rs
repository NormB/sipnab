// SPDX-License-Identifier: MIT OR Apache-2.0

//! REST actions go through the journal, the rules and the rate limits
//! (JOURNAL, ACTIONS-HARDEN; approved 2026-09-28).
//!
//! Written before the behavior exists. Until it did, an enabled
//! `POST /v1/tfps/ban` ran `tfps_ctl` straight away: no record of it outlived
//! the process, nothing limited how often, and an unban could lift any ban.
//! Norm, 2026-09-28: "there must be security focused tests, rate limiting
//! tests and rate limiting must be enabled, there must be recovery tests that
//! can back out a bad or stale update".
//!
//! Every refusal is checked for its effect: the fake `tfps_ctl` records each
//! call, and a refused request must leave none.

#![cfg(all(unix, feature = "full"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[path = "support/server.rs"]
mod server;

use server::{ApiServer, TestError};

const SIGNING_KEY: &str = "actions-journal-rest-test-signing-key";

#[path = "support/fake_tfps_ctl.rs"]
mod fake_tfps_ctl;

use fake_tfps_ctl::Fake;

fn token_for(caller: &str) -> String {
    sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        caller,
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_ACTIONS,
    )
}

/// A server with TFPS actions enabled for REST, journaling into `journal`.
fn server(fake: &Fake, journal: &Path, extra: &[&str]) -> Result<ApiServer, TestError> {
    let ctl = fake.path();
    let dir = journal.display().to_string();
    let mut args = vec![
        "--api-signing-key",
        SIGNING_KEY,
        "--tfps-ctl",
        ctl.as_str(),
        "--allow-action",
        "tfps:rest",
        "--journal-dir",
        dir.as_str(),
    ];
    args.extend_from_slice(extra);
    ApiServer::spawn(&args)
}

fn ban_body(ip: &str) -> String {
    format!(r#"{{"ip":"{ip}"}}"#)
}

/// Every record in the journal, in order.
fn records(journal: &Path) -> Result<Vec<serde_json::Value>, TestError> {
    let mut segments: Vec<PathBuf> = std::fs::read_dir(journal)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    segments.sort();
    let mut out = Vec::new();
    for p in &segments {
        for l in std::fs::read_to_string(p)?.lines() {
            out.push(serde_json::from_str(l)?);
        }
    }
    Ok(out)
}

/// Wait up to 20 s for a sipnab that should refuse to start; one still
/// running then is killed, and reads as having started.
fn bounded(mut child: std::process::Child) -> Result<std::process::Output, TestError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    Ok(child.wait_with_output()?)
}

fn of_kind<'a>(records: &'a [serde_json::Value], kind: &str) -> Vec<&'a serde_json::Value> {
    records.iter().filter(|r| r["kind"] == kind).collect()
}

#[test]
fn a_ban_is_journaled_before_and_after_and_names_the_caller_by_token_id() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    let resp = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.20"), &token)?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let answer = resp.json()?;
    assert_eq!(answer["applied"], true, "{answer}");
    let id = answer["id"].as_str().ok_or("an action id")?.to_string();
    drop(srv);

    let all = records(journal.path())?;
    let intent = of_kind(&all, "action_intent");
    assert_eq!(intent.len(), 1, "{all:?}");
    assert_eq!(intent[0]["id"], id.as_str());
    assert_eq!(intent[0]["caller"], "token:ops-console");
    assert_eq!(intent[0]["surface"], "rest");
    assert_eq!(
        intent[0]["ttl_secs"], 3600,
        "a ban always carries a lifetime"
    );
    let outcome = of_kind(&all, "action_outcome");
    assert_eq!(outcome.len(), 1, "{all:?}");
    assert_eq!(outcome[0]["id"], id.as_str());
    assert_eq!(outcome[0]["result"], "applied");
    assert!(
        intent[0]["seq"].as_u64() < outcome[0]["seq"].as_u64(),
        "the intent precedes the outcome"
    );
    assert!(
        fake.calls().contains("--ttl\n3600"),
        "TFPS was sent the lifetime: {}",
        fake.calls()
    );
    Ok(())
}

#[test]
fn the_journal_holds_no_token_and_is_private_to_its_owner() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let dir = journal.path().join("j");
    let srv = server(&fake, &dir, &[])?;
    let token = token_for("ops-console");
    let _ = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.20"), &token)?;
    let _ = srv.post_json_bearer("/v1/tfps/ban", &ban_body("127.0.0.1"), &token)?;
    drop(srv);
    let mode = |p: &Path| -> Result<u32, TestError> {
        Ok(std::fs::metadata(p)?.permissions().mode() & 0o777)
    };
    assert_eq!(mode(&dir)?, 0o700);
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|x| x == "jsonl") {
            assert_eq!(mode(&path)?, 0o600, "{}", path.display());
            let text = std::fs::read_to_string(&path)?;
            assert!(!text.contains(&token), "a token reached the journal");
            assert!(
                !text.contains(SIGNING_KEY),
                "the signing key reached the journal"
            );
        }
    }
    Ok(())
}

#[test]
fn enabled_without_a_usable_journal_sipnab_refuses_to_start_and_names_it() -> Result<(), TestError>
{
    let fake = Fake::new()?;
    let blocker = tempfile::NamedTempFile::new()?;
    // A path under a regular file can never be a directory.
    let bad = blocker.path().join("journal");
    let bad_str = bad.display().to_string();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--api",
            "127.0.0.1:0",
            "--api-signing-key",
            SIGNING_KEY,
            "--tfps-ctl",
            &fake.path(),
            "--allow-action",
            "tfps:rest",
            "--journal-dir",
            &bad_str,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let out = bounded(out)?;
    assert!(!out.status.success(), "must refuse to start");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(&bad_str), "names the directory: {stderr}");
    assert_eq!(fake.calls(), "");
    Ok(())
}

#[test]
fn a_second_sipnab_on_the_same_journal_refuses_to_start() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let first = server(&fake, journal.path(), &[])?;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--api",
            "127.0.0.1:0",
            "--api-signing-key",
            SIGNING_KEY,
            "--tfps-ctl",
            &fake.path(),
            "--allow-action",
            "tfps:rest",
            "--journal-dir",
            &journal.path().display().to_string(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let out = bounded(out)?;
    assert!(!out.status.success(), "a second writer must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("in use by another sipnab"), "{stderr}");
    drop(first);
    Ok(())
}

#[test]
fn the_address_and_lifetime_rules_refuse_before_tfps_runs() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    for body in [
        r#"{"ip":"127.0.0.1"}"#.to_string(),
        r#"{"ip":"255.255.255.255"}"#.to_string(),
        r#"{"ip":"224.0.0.1"}"#.to_string(),
        r#"{"ip":"0.0.0.0"}"#.to_string(),
        r#"{"ip":"198.51.100.20","ttl_secs":0}"#.to_string(),
        r#"{"ip":"198.51.100.20","ttl_secs":604801}"#.to_string(),
    ] {
        let resp = srv.post_json_bearer("/v1/tfps/ban", &body, &token)?;
        assert_eq!(resp.status, 422, "{body}: {}", resp.body);
    }
    assert_eq!(fake.count("ban"), 0, "{}", fake.calls());
    drop(srv);
    let all = records(journal.path())?;
    assert_eq!(of_kind(&all, "action_intent").len(), 0);
    assert!(
        !of_kind(&all, "action_refused").is_empty(),
        "refusals are journaled: {all:?}"
    );
    Ok(())
}

#[test]
fn sipnab_will_not_lift_a_ban_it_did_not_place() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    // 198.51.100.10 is banned in TFPS's own list, by TFPS.
    let resp = srv.post_json_bearer(
        "/v1/tfps/unban",
        &ban_body("198.51.100.10"),
        &token_for("ops-console"),
    )?;
    assert_eq!(resp.status, 409, "{}", resp.body);
    assert_eq!(fake.count("unban"), 0, "{}", fake.calls());
    Ok(())
}

#[test]
fn the_sixth_action_a_minute_from_one_caller_is_refused_with_retry_after() -> Result<(), TestError>
{
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    for n in 1..=5 {
        let resp = srv.post_json_bearer(
            "/v1/tfps/ban",
            &ban_body(&format!("198.51.100.{n}")),
            &token,
        )?;
        assert_eq!(resp.status, 200, "ban {n}: {}", resp.body);
    }
    let resp = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.6"), &token)?;
    assert_eq!(resp.status, 429, "{}", resp.body);
    let secs: u64 = resp.retry_after.as_deref().ok_or("Retry-After")?.parse()?;
    assert!((1..=60).contains(&secs), "{secs}");
    assert_eq!(fake.count("ban"), 5, "{}", fake.calls());
    Ok(())
}

#[test]
fn another_caller_has_its_own_allowance_until_the_server_limit() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let mut n = 0;
    for caller in ["a", "b"] {
        let token = token_for(caller);
        for _ in 0..5 {
            n += 1;
            let resp = srv.post_json_bearer(
                "/v1/tfps/ban",
                &ban_body(&format!("198.51.100.{n}")),
                &token,
            )?;
            assert_eq!(resp.status, 200, "{caller} ban {n}: {}", resp.body);
        }
    }
    // Ten this minute: the server's limit, whoever asks next.
    let resp = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.99"), &token_for("c"))?;
    assert_eq!(resp.status, 429, "{}", resp.body);
    assert_eq!(fake.count("ban"), 10, "{}", fake.calls());
    Ok(())
}

#[test]
fn a_restart_does_not_refill_the_allowance() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let token = token_for("ops-console");
    let srv = server(&fake, journal.path(), &[])?;
    for n in 1..=5 {
        let resp = srv.post_json_bearer(
            "/v1/tfps/ban",
            &ban_body(&format!("198.51.100.{n}")),
            &token,
        )?;
        assert_eq!(resp.status, 200, "ban {n}: {}", resp.body);
    }
    drop(srv);
    let srv = server(&fake, journal.path(), &[])?;
    let resp = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.6"), &token)?;
    assert_eq!(
        resp.status, 429,
        "a restart bought a fresh allowance: {}",
        resp.body
    );
    assert_eq!(fake.count("ban"), 5, "{}", fake.calls());
    Ok(())
}

#[test]
fn a_ban_survives_a_restart_as_one_sipnab_may_lift() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let config_dir = tempfile::tempdir()?;
    let config = config_dir.path().join("sipnab.toml");
    std::fs::write(&config, "[action_limits]\naddress_cooldown_secs = 1\n")?;
    let config = config.display().to_string();
    let token = token_for("ops-console");

    let srv = server(&fake, journal.path(), &["--config", &config])?;
    let ban = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.20"), &token)?;
    assert_eq!(ban.status, 200, "{}", ban.body);
    drop(srv);

    let srv = server(&fake, journal.path(), &["--config", &config])?;
    std::thread::sleep(Duration::from_millis(1100));
    let unban = srv.post_json_bearer("/v1/tfps/unban", &ban_body("198.51.100.20"), &token)?;
    assert_eq!(unban.status, 200, "{}", unban.body);
    assert_eq!(unban.json()?["applied"], true, "{}", unban.body);
    assert_eq!(fake.count("unban"), 1, "{}", fake.calls());
    Ok(())
}

#[test]
fn an_unban_straight_after_a_ban_waits_out_the_address_cooldown() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    let ban = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.20"), &token)?;
    assert_eq!(ban.status, 200, "{}", ban.body);
    let unban = srv.post_json_bearer("/v1/tfps/unban", &ban_body("198.51.100.20"), &token)?;
    assert_eq!(unban.status, 429, "{}", unban.body);
    assert!(unban.retry_after.is_some(), "{}", unban.body);
    assert_eq!(fake.count("unban"), 0, "{}", fake.calls());
    Ok(())
}

#[test]
fn tfps_failing_is_a_bad_gateway_and_the_outcome_is_journaled_as_failed() -> Result<(), TestError> {
    let fake = Fake::new()?;
    fake.fail_bans()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let resp = srv.post_json_bearer(
        "/v1/tfps/ban",
        &ban_body("198.51.100.20"),
        &token_for("ops-console"),
    )?;
    assert_eq!(resp.status, 502, "{}", resp.body);
    assert!(resp.body.contains("map write failed"), "{}", resp.body);
    drop(srv);
    let all = records(journal.path())?;
    let outcome = of_kind(&all, "action_outcome");
    assert_eq!(outcome.len(), 1, "{all:?}");
    assert_eq!(outcome[0]["result"], "failed");
    Ok(())
}

/// The per-address request limit runs before the credential is looked at on
/// the action routes too, so guessing tokens at them is throttled.
#[test]
fn guessing_tokens_at_the_action_routes_is_throttled_before_auth() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &["--api-rate-limit-per-peer", "2"])?;
    let statuses: Vec<u16> = (0..6)
        .map(|n| {
            srv.post_json_bearer(
                "/v1/tfps/ban",
                &ban_body("198.51.100.20"),
                &format!("guess-{n}"),
            )
            .map(|r| r.status)
        })
        .collect::<Result<_, _>>()?;
    assert!(statuses.contains(&503), "{statuses:?}");
    assert!(
        statuses.iter().all(|s| *s == 401 || *s == 503),
        "{statuses:?}"
    );
    assert_eq!(fake.calls(), "");
    Ok(())
}

// ── revert over REST ─────────────────────────────────────────────────────

/// A config whose address cooldown is a second, so a test can revert what it
/// just banned without waiting out the shipped minute.
fn quick_cooldown() -> Result<(tempfile::TempDir, String), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    std::fs::write(&path, "[action_limits]\naddress_cooldown_secs = 1\n")?;
    let path = path.display().to_string();
    Ok((dir, path))
}

#[test]
fn a_ban_can_be_reverted_over_rest_by_its_id() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let (_cfg, config) = quick_cooldown()?;
    let srv = server(&fake, journal.path(), &["--config", &config])?;
    let token = token_for("ops-console");
    let ban = srv.post_json_bearer("/v1/tfps/ban", &ban_body("198.51.100.20"), &token)?;
    let id = ban.json()?["id"].as_str().ok_or("id")?.to_string();
    std::thread::sleep(Duration::from_millis(1100));
    let resp =
        srv.post_json_bearer("/v1/actions/revert", &format!(r#"{{"id":"{id}"}}"#), &token)?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(
        resp.json()?["reverted"],
        serde_json::json!([id]),
        "{}",
        resp.body
    );
    assert_eq!(fake.count("unban"), 1, "{}", fake.calls());
    drop(srv);
    let all = records(journal.path())?;
    let revert = of_kind(&all, "revert_intent");
    assert_eq!(revert.len(), 1, "{all:?}");
    assert_eq!(revert[0]["reverts"], id.as_str());
    assert_eq!(revert[0]["caller"], "token:ops-console");
    Ok(())
}

#[test]
fn revert_over_rest_needs_the_actions_scope_and_rest_enabled() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let full = sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "reader",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_FULL,
    );
    let resp = srv.post_json_bearer("/v1/actions/revert", r#"{"all":true}"#, &full)?;
    assert_eq!(resp.status, 401, "{}", resp.body);
    drop(srv);

    let ctl = fake.path();
    let dir = journal.path().display().to_string();
    let srv = ApiServer::spawn(&[
        "--api-signing-key",
        SIGNING_KEY,
        "--tfps-ctl",
        &ctl,
        "--allow-action",
        "tfps:mcp",
        "--journal-dir",
        &dir,
    ])?;
    let resp = srv.post_json_bearer(
        "/v1/actions/revert",
        r#"{"all":true}"#,
        &token_for("ops-console"),
    )?;
    assert_eq!(resp.status, 403, "{}", resp.body);
    assert_eq!(fake.count("unban"), 0);
    Ok(())
}

#[test]
fn a_revert_body_names_one_id_or_all_and_nothing_else() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    for body in [
        "{}",
        r#"{"all":false}"#,
        r#"{"id":"a-1","all":true}"#,
        r#"{"id":""}"#,
        r#"{"all":true,"force":true}"#,
        "[]",
    ] {
        let resp = srv.post_json_bearer("/v1/actions/revert", body, &token)?;
        assert_eq!(resp.status, 400, "{body}: {}", resp.body);
    }
    assert_eq!(fake.count("unban"), 0);
    Ok(())
}

#[test]
fn revert_all_over_rest_counts_against_the_callers_limit() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let token = token_for("ops-console");
    for n in 1..=5 {
        let resp = srv.post_json_bearer(
            "/v1/tfps/ban",
            &ban_body(&format!("198.51.100.{n}")),
            &token,
        )?;
        assert_eq!(resp.status, 200, "{}", resp.body);
    }
    // The caller's five for the minute are spent: a stolen token cannot turn
    // revert-all into a sixth, seventh, ... action.
    let resp = srv.post_json_bearer("/v1/actions/revert", r#"{"all":true}"#, &token)?;
    assert_eq!(resp.status, 429, "{}", resp.body);
    assert!(resp.retry_after.is_some());
    assert_eq!(fake.count("unban"), 0, "{}", fake.calls());
    Ok(())
}

#[test]
fn a_server_stopped_cleanly_journals_the_stop() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path(), &[])?;
    let resp = srv.post_json_bearer(
        "/v1/tfps/ban",
        &ban_body("198.51.100.20"),
        &token_for("ops-console"),
    )?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let status = srv.stop()?;
    assert!(status.success(), "{status:?}");
    let all = records(journal.path())?;
    assert_eq!(
        all.last().map(|r| r["kind"].clone()),
        Some(serde_json::json!("run_stop")),
        "{all:?}"
    );
    Ok(())
}

// ── credentials that must not act ────────────────────────────────────────

/// Every credential here fails for a different reason; each must be refused
/// before TFPS is asked, on every action route.
#[test]
fn forged_expired_tampered_revoked_and_foreign_tokens_cannot_act() -> Result<(), TestError> {
    use base64::Engine;
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let revoked = tempfile::NamedTempFile::new()?;
    std::fs::write(revoked.path(), "stolen-console\n")?;
    let revoked_path = revoked.path().display().to_string();
    let srv = server(
        &fake,
        journal.path(),
        &["--api-revoked-file", &revoked_path],
    )?;
    let later = chrono::Utc::now().timestamp() + 3600;
    let forged = sipnab::auth::mint(
        b"not-the-servers-key",
        "ops-console",
        later,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_ACTIONS,
    );
    let expired = sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "ops-console",
        chrono::Utc::now().timestamp() - 60,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_ACTIONS,
    );
    let for_mcp = sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "ops-console",
        later,
        sipnab::auth::AUDIENCE_MCP,
        sipnab::auth::SCOPE_ACTIONS,
    );
    let revoked_token = sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "stolen-console",
        later,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_ACTIONS,
    );
    // A genuine `full` token with `actions` written into its payload: the
    // signature no longer covers what it claims.
    let full = sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "reader",
        later,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_FULL,
    );
    let parts: Vec<&str> = full.split('.').collect();
    assert_eq!(parts.len(), 3, "{full}");
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut payload: serde_json::Value = serde_json::from_slice(&engine.decode(parts[1])?)?;
    payload["scope"] = serde_json::json!("actions");
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        engine.encode(serde_json::to_vec(&payload)?),
        parts[2]
    );
    for (why, credential) in [
        ("forged", forged),
        ("expired", expired),
        ("minted for MCP", for_mcp),
        ("revoked", revoked_token),
        ("tampered", tampered),
    ] {
        for (route, body) in [
            ("/v1/tfps/ban", ban_body("198.51.100.20")),
            ("/v1/tfps/unban", ban_body("198.51.100.20")),
            ("/v1/actions/revert", r#"{"all":true}"#.to_string()),
        ] {
            let resp = srv.post_json_bearer(route, &body, &credential)?;
            assert_eq!(resp.status, 401, "{why} on {route}: {}", resp.body);
        }
    }
    assert_eq!(fake.calls(), "", "a refused credential reached tfps_ctl");
    drop(srv);
    let all = records(journal.path())?;
    assert!(
        of_kind(&all, "action_intent").is_empty(),
        "nothing was admitted: {all:?}"
    );
    Ok(())
}
