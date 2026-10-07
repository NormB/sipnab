// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seeing and backing out what sipnab did, from the local command line
//! (JOURNAL; approved spec 2026-09-28).
//!
//! Written before the behavior exists. From the approved journal spec:
//! `sipnab --journal-show` prints what sipnab owns now, what is in doubt, and
//! the last refusals, read-only; `sipnab --revert-actions all` or
//! `--revert-actions <id>` runs, reports and exits, and works with actions
//! switched off, because after abuse the first thing an operator does is
//! switch them off.

#![cfg(all(unix, feature = "full"))]

use std::path::Path;
use std::process::{Command, Output};

#[path = "support/server.rs"]
mod server;

#[path = "support/fake_tfps_ctl.rs"]
mod fake_tfps_ctl;

use fake_tfps_ctl::Fake;
use server::{ApiServer, TestError};

const SIGNING_KEY: &str = "actions-cli-test-signing-key";

fn token() -> String {
    sipnab::auth::mint(
        SIGNING_KEY.as_bytes(),
        "ops-console",
        chrono::Utc::now().timestamp() + 3600,
        sipnab::auth::AUDIENCE_API,
        sipnab::auth::SCOPE_ACTIONS,
    )
}

/// A server that may ban over REST, journaling into `journal`.
fn server(fake: &Fake, journal: &Path) -> Result<ApiServer, TestError> {
    ApiServer::spawn(&[
        "--api-signing-key",
        SIGNING_KEY,
        "--tfps-ctl",
        &fake.path(),
        "--allow-action",
        "tfps:rest",
        "--journal-dir",
        &journal.display().to_string(),
    ])
}

/// Ban `ips` through a server, and return their action ids, oldest first.
fn ban_through_a_server(
    fake: &Fake,
    journal: &Path,
    ips: &[&str],
) -> Result<Vec<String>, TestError> {
    let srv = server(fake, journal)?;
    let mut ids = Vec::new();
    for ip in ips {
        let resp =
            srv.post_json_bearer("/v1/tfps/ban", &format!(r#"{{"ip":"{ip}"}}"#), &token())?;
        assert_eq!(resp.status, 200, "{}", resp.body);
        ids.push(resp.json()?["id"].as_str().ok_or("id")?.to_string());
    }
    drop(srv);
    Ok(ids)
}

/// Run sipnab with `args` and nothing else: no capture, no server.
fn sipnab(args: &[&str]) -> Result<Output, TestError> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()?)
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn journal_show_lists_the_bans_sipnab_holds_newest_first() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let ids = ban_through_a_server(&fake, journal.path(), &["198.51.100.20", "198.51.100.21"])?;
    let out = sipnab(&[
        "--journal-show",
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let at20 = stdout.find("198.51.100.20").ok_or("first ban listed")?;
    let at21 = stdout.find("198.51.100.21").ok_or("second ban listed")?;
    assert!(at21 < at20, "newest first: {stdout}");
    for id in &ids {
        assert!(stdout.contains(id.as_str()), "{id} in {stdout}");
    }
    assert!(stdout.contains("token:ops-console"), "{stdout}");
    assert!(stdout.contains("Last run: stopped cleanly"), "{stdout}");
    assert!(fake.count("unban") == 0, "showing changes nothing");
    Ok(())
}

#[test]
fn journal_show_works_while_a_sipnab_holds_the_journal() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path())?;
    let resp = srv.post_json_bearer("/v1/tfps/ban", r#"{"ip":"198.51.100.20"}"#, &token())?;
    assert_eq!(resp.status, 200, "{}", resp.body);
    let out = sipnab(&[
        "--journal-show",
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("198.51.100.20"));
    drop(srv);
    Ok(())
}

#[test]
fn journal_show_where_nothing_was_recorded_says_so() -> Result<(), TestError> {
    let empty = tempfile::tempdir()?;
    let dir = empty.path().join("journal");
    let out = sipnab(&[
        "--journal-show",
        "--journal-dir",
        &dir.display().to_string(),
    ])?;
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("no journal"), "{}", text(&out));
    Ok(())
}

#[test]
fn revert_all_backs_out_every_ban_with_actions_switched_off() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let ids = ban_through_a_server(&fake, journal.path(), &["198.51.100.20", "198.51.100.21"])?;
    // No --allow-action: actions are off, and recovery still works.
    let out = sipnab(&[
        "--revert-actions",
        "all",
        "--tfps-ctl",
        &fake.path(),
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert!(out.status.success(), "{}", text(&out));
    for id in &ids {
        assert!(text(&out).contains(id.as_str()), "{id}: {}", text(&out));
    }
    assert_eq!(fake.count("unban"), 2, "{}", fake.calls());
    let show = sipnab(&[
        "--journal-show",
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert!(
        String::from_utf8_lossy(&show.stdout).contains("Last run: stopped cleanly"),
        "the revert's own run ends with a stop record: {}",
        text(&show)
    );
    let show = sipnab(&[
        "--journal-show",
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(
        shown.contains("Held: none"),
        "nothing is held after a revert: {shown}"
    );
    Ok(())
}

#[test]
fn revert_one_backs_out_only_that_ban() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let ids = ban_through_a_server(&fake, journal.path(), &["198.51.100.20", "198.51.100.21"])?;
    let out = sipnab(&[
        "--revert-actions",
        &ids[0],
        "--tfps-ctl",
        &fake.path(),
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(fake.count("unban"), 1, "{}", fake.calls());
    assert!(
        fake.calls().contains("unban\n--json\n198.51.100.20"),
        "{}",
        fake.calls()
    );
    Ok(())
}

#[test]
fn reverting_an_id_sipnab_does_not_hold_fails_and_says_why() -> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let _ = ban_through_a_server(&fake, journal.path(), &["198.51.100.20"])?;
    let out = sipnab(&[
        "--revert-actions",
        "a-no-such-action",
        "--tfps-ctl",
        &fake.path(),
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("holds no ban"), "{}", text(&out));
    assert_eq!(fake.count("unban"), 0);
    Ok(())
}

#[test]
fn reverting_while_a_sipnab_holds_the_journal_is_refused_and_says_what_to_do()
-> Result<(), TestError> {
    let fake = Fake::new()?;
    let journal = tempfile::tempdir()?;
    let srv = server(&fake, journal.path())?;
    let out = sipnab(&[
        "--revert-actions",
        "all",
        "--tfps-ctl",
        &fake.path(),
        "--journal-dir",
        &journal.path().display().to_string(),
    ])?;
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let said = text(&out);
    assert!(said.contains("in use by another sipnab"), "{said}");
    assert!(
        said.contains("/v1/actions/revert"),
        "names the running server's way: {said}"
    );
    drop(srv);
    Ok(())
}

#[test]
fn an_unknown_revert_target_shape_is_refused_at_parse() -> Result<(), TestError> {
    let out = sipnab(&["--revert-actions", ""])?;
    assert!(!out.status.success(), "{}", text(&out));
    Ok(())
}
