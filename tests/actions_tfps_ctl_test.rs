// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The action service's TFPS, through `tfps_ctl` (JOURNAL).
//!
//! Written before the behavior exists. The service asks TFPS three things
//! through the [`TfpsActions`] trait; this is the implementation that runs
//! `tfps_ctl`, driven here by a fake that replays TFPS's own recorded replies
//! (the golden fixtures the contract tests use).

#![cfg(all(unix, feature = "full"))]

use std::net::Ipv4Addr;

use sipnab::security::actions::{TfpsActions, TfpsCtl, TfpsReply};
use sipnab::security::tfps::TfpsLocator;

type TestError = Box<dyn std::error::Error>;

#[path = "support/executable.rs"]
mod executable;

const BAN: &str = include_str!("fixtures/tfps-ban-golden.jsonl");
const UNBAN: &str = include_str!("fixtures/tfps-unban-golden.jsonl");
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");

fn line(fixture: &str, n: usize) -> Result<&str, TestError> {
    Ok(fixture.lines().nth(n - 1).ok_or("fixture line")?)
}

/// A `tfps_ctl` that prints `ban_line` to ban, `unban_line` to unban, and
/// the golden list to banned, and records its argv.
fn fake(ban_line: &str, unban_line: &str) -> Result<(tempfile::TempDir, TfpsCtl), TestError> {
    let dir = tempfile::tempdir()?;
    let here = dir.path().display();
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"{here}/argv\"\n\
         case \"$1\" in\n\
         ban) echo '{ban_line}';;\n\
         unban) echo '{unban_line}';;\n\
         banned) cat <<'SIPNAB_FIXTURE'\n{BANNED}\nSIPNAB_FIXTURE\n;;\n\
         esac\n"
    );
    let path = dir.path().join("tfps_ctl");
    executable::write_executable(&path, &script)?;
    let ctl = TfpsCtl::new(TfpsLocator::new(Some(path), None));
    Ok((dir, ctl))
}

#[test]
fn an_applied_ban_is_applied_and_carries_the_lifetime() -> Result<(), TestError> {
    let (dir, ctl) = fake(line(BAN, 1)?, line(UNBAN, 1)?)?;
    let reply = ctl.ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0)?;
    assert_eq!(reply, TfpsReply::Applied);
    let argv = std::fs::read_to_string(dir.path().join("argv"))?;
    assert!(
        argv.contains("198.51.100.20") && argv.contains("--ttl\n600"),
        "{argv}"
    );
    Ok(())
}

#[test]
fn a_ban_tfps_refuses_is_a_refusal_in_its_words() -> Result<(), TestError> {
    let (_dir, ctl) = fake(line(BAN, 3)?, line(UNBAN, 1)?)?;
    let reply = ctl.ban(Ipv4Addr::new(192, 0, 2, 1), 600, 0)?;
    assert_eq!(reply, TfpsReply::Refused("local".to_string()));
    Ok(())
}

#[test]
fn unban_applied_and_not_blocked() -> Result<(), TestError> {
    let (_dir, ctl) = fake(line(BAN, 1)?, line(UNBAN, 1)?)?;
    assert_eq!(
        ctl.unban(Ipv4Addr::new(198, 51, 100, 20))?,
        TfpsReply::Applied
    );
    let (_dir2, ctl2) = fake(line(BAN, 1)?, line(UNBAN, 2)?)?;
    assert_eq!(
        ctl2.unban(Ipv4Addr::new(198, 51, 100, 21))?,
        TfpsReply::Refused("not-blocked".to_string())
    );
    Ok(())
}

#[test]
fn banned_lists_every_address_with_its_expiry() -> Result<(), TestError> {
    let (_dir, ctl) = fake(line(BAN, 1)?, line(UNBAN, 1)?)?;
    let list = ctl.banned()?;
    assert_eq!(list.len(), BANNED.lines().count());
    assert!(
        list.contains(&(Ipv4Addr::new(198, 51, 100, 10), Some(1_756_921_200))),
        "{list:?}"
    );
    assert!(
        list.contains(&(Ipv4Addr::new(198, 51, 100, 11), None)),
        "{list:?}"
    );
    Ok(())
}

#[test]
fn a_machine_without_tfps_is_an_error_that_says_so() -> Result<(), TestError> {
    let empty = tempfile::tempdir()?;
    let ctl = TfpsCtl::new(TfpsLocator::new(None, None).with_search_path(empty.path().as_os_str()));
    let err = match ctl.ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0) {
        Ok(reply) => return Err(format!("no TFPS: expected an error, got {reply:?}").into()),
        Err(e) => e,
    };
    assert!(err.contains("tfps_ctl"), "{err}");
    assert!(ctl.banned().is_err(), "an absent peer is not an empty list");
    Ok(())
}

#[test]
fn an_unban_asks_tfps_to_unban_and_nothing_else() -> Result<(), TestError> {
    let (dir, ctl) = fake(line(BAN, 1)?, line(UNBAN, 1)?)?;
    ctl.unban(Ipv4Addr::new(198, 51, 100, 20))?;
    let argv = std::fs::read_to_string(dir.path().join("argv"))?;
    let verbs: Vec<&str> = argv
        .lines()
        .filter(|l| ["ban", "unban", "banned"].contains(l))
        .collect();
    assert_eq!(verbs, ["unban"], "{argv}");
    Ok(())
}

// ── A ban TFPS may have applied, with an answer sipnab cannot read ────────

/// A `tfps_ctl` that bans (it notes the address in `held`, as TFPS writes
/// its block map) and then answers with `answer`: shell lines run after the
/// ban took effect.
fn acts_then(answer: &str) -> Result<(tempfile::TempDir, TfpsCtl), TestError> {
    let dir = tempfile::tempdir()?;
    let here = dir.path().display();
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n\
         ban) echo \"$3\" >> \"{here}/held\"; {answer};;\n\
         esac\n"
    );
    let path = dir.path().join("tfps_ctl");
    executable::write_executable(&path, &script)?;
    let ctl = TfpsCtl::new(TfpsLocator::new(Some(path), None));
    Ok((dir, ctl))
}

/// Ban 198.51.100.20 through `ctl`, expecting TFPS to have acted and
/// sipnab to report the answer as unreadable rather than as an error.
fn unanswered(dir: &tempfile::TempDir, ctl: &TfpsCtl) -> Result<String, TestError> {
    let reply = ctl.ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0);
    let held = std::fs::read_to_string(dir.path().join("held")).unwrap_or_default();
    assert_eq!(held.trim(), "198.51.100.20", "the fake applied the ban");
    match reply {
        Ok(TfpsReply::Unanswered(why)) => Ok(why),
        other => Err(format!(
            "tfps_ctl ran and may have banned, so the answer is Unanswered, not {other:?}"
        )
        .into()),
    }
}

/// An answer that is not JSON at all.
#[test]
fn a_ban_answered_with_garbage_is_unanswered_not_failed() -> Result<(), TestError> {
    let (dir, ctl) = acts_then("echo 'segmentation fault (core dumped)'")?;
    let why = unanswered(&dir, &ctl)?;
    assert!(why.contains("tfps_ctl"), "names what ran: {why}");
    Ok(())
}

/// The answer a `tfps_ctl` built before TFPS's JSON contract gives: the
/// same object, with `expires` an RFC 3339 string instead of epoch seconds.
/// sipnab does not read that shape, and says why it may have met it.
#[test]
fn a_ban_answered_by_a_pre_contract_tfps_ctl_is_unanswered_and_says_why() -> Result<(), TestError> {
    let (dir, ctl) = acts_then(
        "echo '{\"ip\":\"198.51.100.20\",\"action\":\"ban\",\"applied\":true,\
         \"refused\":null,\"expires\":\"2026-11-03T17:00:00Z\",\"source\":\"operator\"}'",
    )?;
    let why = unanswered(&dir, &ctl)?;
    assert!(
        why.contains("e7ee57a"),
        "names the TFPS commit whose contract this answer does not meet: {why}"
    );
    Ok(())
}

/// A non-zero exit with no result, after the ban took effect.
#[test]
fn a_ban_that_exits_non_zero_with_no_result_is_unanswered() -> Result<(), TestError> {
    let (dir, ctl) = acts_then("echo 'tfps: lost the map' >&2; exit 3")?;
    let why = unanswered(&dir, &ctl)?;
    assert!(why.contains("lost the map"), "carries its stderr: {why}");
    Ok(())
}

/// A `tfps_ctl` that never answers, after the ban took effect.
#[test]
fn a_ban_that_times_out_is_unanswered() -> Result<(), TestError> {
    let (dir, ctl) = acts_then("sleep 30")?;
    let why = unanswered(&dir, &ctl)?;
    assert!(why.contains("did not finish"), "says it timed out: {why}");
    Ok(())
}

/// A `tfps_ctl` that cannot be started never ran, so nothing was banned:
/// that is still an error, not an unreadable answer.
#[test]
fn a_tfps_ctl_that_cannot_start_is_an_error_not_unanswered() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("tfps_ctl");
    std::fs::write(&path, "not executable")?;
    let ctl = TfpsCtl::new(TfpsLocator::new(Some(path), None));
    match ctl.ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0) {
        Err(e) => {
            assert!(e.contains("tfps_ctl"), "{e}");
            Ok(())
        }
        Ok(reply) => Err(format!("a peer that never ran answered {reply:?}").into()),
    }
}
