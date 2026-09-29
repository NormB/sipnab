// SPDX-License-Identifier: MIT OR Apache-2.0

//! The action service's TFPS, through `tfps_ctl` (JOURNAL).
//!
//! Written before the behavior exists. The service asks TFPS three things
//! through the [`TfpsActions`] trait; this is the implementation that runs
//! `tfps_ctl`, driven here by a fake that replays TFPS's own recorded replies
//! (the golden fixtures the contract tests use).

#![cfg(all(unix, feature = "full"))]

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;

use sipnab::security::actions::{TfpsActions, TfpsCtl, TfpsReply};
use sipnab::security::tfps::TfpsLocator;

const BAN: &str = include_str!("fixtures/tfps-ban-golden.jsonl");
const UNBAN: &str = include_str!("fixtures/tfps-unban-golden.jsonl");
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");

fn line(fixture: &str, n: usize) -> &str {
    fixture.lines().nth(n - 1).expect("fixture line")
}

/// A `tfps_ctl` that prints `ban_line` to ban, `unban_line` to unban, and
/// the golden list to banned, and records its argv.
fn fake(ban_line: &str, unban_line: &str) -> (tempfile::TempDir, TfpsCtl) {
    let dir = tempfile::tempdir().expect("tempdir");
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
    std::fs::write(&path, script).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let ctl = TfpsCtl::new(TfpsLocator::new(Some(path), None));
    (dir, ctl)
}

#[test]
fn an_applied_ban_is_applied_and_carries_the_lifetime() {
    let (dir, ctl) = fake(line(BAN, 1), line(UNBAN, 1));
    let reply = ctl
        .ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0)
        .expect("asked");
    assert_eq!(reply, TfpsReply::Applied);
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("argv");
    assert!(
        argv.contains("198.51.100.20") && argv.contains("--ttl\n600"),
        "{argv}"
    );
}

#[test]
fn a_ban_tfps_refuses_is_a_refusal_in_its_words() {
    let (_dir, ctl) = fake(line(BAN, 3), line(UNBAN, 1));
    let reply = ctl.ban(Ipv4Addr::new(192, 0, 2, 1), 600, 0).expect("asked");
    assert_eq!(reply, TfpsReply::Refused("local".to_string()));
}

#[test]
fn unban_applied_and_not_blocked() {
    let (_dir, ctl) = fake(line(BAN, 1), line(UNBAN, 1));
    assert_eq!(
        ctl.unban(Ipv4Addr::new(198, 51, 100, 20)).expect("asked"),
        TfpsReply::Applied
    );
    let (_dir2, ctl2) = fake(line(BAN, 1), line(UNBAN, 2));
    assert_eq!(
        ctl2.unban(Ipv4Addr::new(198, 51, 100, 21)).expect("asked"),
        TfpsReply::Refused("not-blocked".to_string())
    );
}

#[test]
fn banned_lists_every_address_with_its_expiry() {
    let (_dir, ctl) = fake(line(BAN, 1), line(UNBAN, 1));
    let list = ctl.banned().expect("asked");
    assert_eq!(list.len(), BANNED.lines().count());
    assert!(
        list.contains(&(Ipv4Addr::new(198, 51, 100, 10), Some(1_756_921_200))),
        "{list:?}"
    );
    assert!(
        list.contains(&(Ipv4Addr::new(198, 51, 100, 11), None)),
        "{list:?}"
    );
}

#[test]
fn a_machine_without_tfps_is_an_error_that_says_so() {
    let empty = tempfile::tempdir().expect("tempdir");
    let ctl = TfpsCtl::new(TfpsLocator::new(None, None).with_search_path(empty.path().as_os_str()));
    let err = ctl
        .ban(Ipv4Addr::new(198, 51, 100, 20), 600, 0)
        .expect_err("no TFPS");
    assert!(err.contains("tfps_ctl"), "{err}");
    assert!(ctl.banned().is_err(), "an absent peer is not an empty list");
}

#[test]
fn an_unban_asks_tfps_to_unban_and_nothing_else() {
    let (dir, ctl) = fake(line(BAN, 1), line(UNBAN, 1));
    ctl.unban(Ipv4Addr::new(198, 51, 100, 20)).expect("asked");
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("argv");
    let verbs: Vec<&str> = argv
        .lines()
        .filter(|l| ["ban", "unban", "banned"].contains(l))
        .collect();
    assert_eq!(verbs, ["unban"], "{argv}");
}
