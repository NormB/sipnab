// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where the journal lives and how tight the action limits are, as the
//! operator configures them (JOURNAL, ACTIONS-HARDEN; approved 2026-09-28).
//!
//! Written before the behavior exists. The approved journal spec: the journal
//! lives in `/var/lib/sipnab/journal/` unless `[journal] dir` or
//! `--journal-dir` says otherwise; the limits and ban lifetimes are
//! configurable and none of them can be turned off.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use sipnab::cli::Cli;
use sipnab::config::Config;

fn config(body: &str) -> Config {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sipnab.toml");
    std::fs::write(&path, body).expect("write");
    Config::load_file_with_env(&path, &|_| None).expect("config loads")
}

fn cli(args: &[&str]) -> Cli {
    let mut argv = vec!["sipnab", "-N"];
    argv.extend_from_slice(args);
    Cli::try_parse_from(argv).expect("parse")
}

#[test]
fn with_nothing_configured_the_journal_is_under_var_lib() {
    assert_eq!(
        cli(&[]).journal_dir(&config("")),
        PathBuf::from("/var/lib/sipnab/journal")
    );
}

#[test]
fn the_config_file_moves_the_journal_and_the_flag_overrides_it() {
    let c = config("[journal]\ndir = \"/srv/sipnab/journal\"\n");
    assert_eq!(cli(&[]).journal_dir(&c), Path::new("/srv/sipnab/journal"));
    assert_eq!(
        cli(&["--journal-dir", "/run/j"]).journal_dir(&c),
        Path::new("/run/j")
    );
}

#[test]
fn with_nothing_configured_the_limits_are_the_shipped_ones() {
    let l = cli(&[]).action_limits(&config("")).expect("limits");
    assert_eq!(l.per_minute(), 10);
    assert_eq!(l.per_caller_per_minute(), 5);
    assert_eq!(l.address_cooldown(), Duration::from_secs(60));
    assert_eq!(l.default_ban_secs(), 3_600);
    assert_eq!(l.max_ban_secs(), 7 * 86_400);
}

#[test]
fn every_limit_can_be_configured() {
    let c = config(
        "[action_limits]\nper_minute = 20\nper_caller_per_minute = 4\n\
         address_cooldown_secs = 2\ndefault_ban_secs = 600\nmax_ban_secs = 86400\n",
    );
    let l = cli(&[]).action_limits(&c).expect("limits");
    assert_eq!(l.per_minute(), 20);
    assert_eq!(l.per_caller_per_minute(), 4);
    assert_eq!(l.address_cooldown(), Duration::from_secs(2));
    assert_eq!(l.default_ban_secs(), 600);
    assert_eq!(l.max_ban_secs(), 86_400);
}

#[test]
fn no_limit_can_be_turned_off_with_zero() {
    for key in [
        "per_minute",
        "per_caller_per_minute",
        "address_cooldown_secs",
        "default_ban_secs",
        "max_ban_secs",
    ] {
        let c = config(&format!("[action_limits]\n{key} = 0\n"));
        let err = cli(&[]).action_limits(&c).expect_err(key);
        assert!(err.contains("cannot be turned off"), "{key}: {err}");
    }
}

#[test]
fn a_default_lifetime_over_the_maximum_is_refused() {
    let c = config("[action_limits]\ndefault_ban_secs = 7200\nmax_ban_secs = 3600\n");
    let err = cli(&[]).action_limits(&c).expect_err("default above max");
    assert!(err.contains("7200") && err.contains("3600"), "{err}");
}

#[test]
fn a_misspelled_limit_is_reported_as_unknown() {
    let unknown = Config::unknown_keys("[action_limits]\nper_minuet = 3\n").expect("parses");
    assert_eq!(unknown, ["action_limits.per_minuet"]);
    let unknown = Config::unknown_keys("[journal]\ndri = \"/x\"\n").expect("parses");
    assert_eq!(unknown, ["journal.dri"]);
    let known = Config::unknown_keys(
        "[action_limits]\nper_minute = 3\nper_caller_per_minute = 2\n\
         address_cooldown_secs = 5\ndefault_ban_secs = 60\nmax_ban_secs = 60\n\
         [journal]\ndir = \"/x\"\n",
    )
    .expect("parses");
    assert!(known.is_empty(), "{known:?}");
}
