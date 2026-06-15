//! Self-tests for the shared test-support `normalize()` helper (M1/T1.1).
//!
//! TDD: these are written against a stubbed `normalize` (red), then the real
//! implementation makes them pass (green). Per the repo TDD rule, edge cases
//! cover empty input, backslashes, NUL bytes, and multiple tokens per line.

#[path = "support/mod.rs"]
mod support;

use support::normalize;

#[test]
fn scrubs_rfc3339_timestamp() {
    assert_eq!(normalize("at 2024-06-15T12:00:00Z done"), "at <TS> done");
}

#[test]
fn scrubs_timestamp_with_fraction_and_offset() {
    assert_eq!(normalize("2024-06-15T12:00:00.123456+02:00"), "<TS>");
}

#[test]
fn scrubs_space_separated_timestamp() {
    // fail2ban-style "%Y-%m-%d %H:%M:%S".
    assert_eq!(normalize("ban 2024-06-15 12:00:00 ip"), "ban <TS> ip");
}

#[test]
fn scrubs_durations_with_units() {
    assert_eq!(
        normalize("setup 1.234s and 12.3 ms"),
        "setup <DUR> and <DUR>"
    );
}

#[test]
fn scrubs_temp_paths() {
    assert_eq!(normalize("wrote /tmp/abc123/out.pcap ok"), "wrote <TMP> ok");
}

#[test]
fn scrubs_pids_any_case() {
    assert_eq!(normalize("pid=12345"), "pid=<PID>");
    assert_eq!(normalize("PID: 678"), "pid=<PID>");
}

#[test]
fn scrubs_loopback_ports_keeping_host() {
    assert_eq!(normalize("bound 127.0.0.1:54321"), "bound 127.0.0.1:<PORT>");
    assert_eq!(normalize("mcp [::1]:8731"), "mcp [::1]:<PORT>");
}

#[test]
fn preserves_non_volatile_text() {
    // SIP, version numbers, and codec clock-rates must NOT be scrubbed.
    let s = "INVITE sip:alice@example.com SIP/2.0 v0.4.2 PCMU/8000";
    assert_eq!(normalize(s), s);
}

#[test]
fn empty_input_is_empty() {
    assert_eq!(normalize(""), "");
}

#[test]
fn backslashes_are_preserved() {
    let s = r"a\b\c windows\path";
    assert_eq!(normalize(s), s);
}

#[test]
fn nul_byte_is_preserved_without_panic() {
    let out = normalize("a\u{0}b");
    assert!(out.contains('\u{0}'));
    assert_eq!(out, "a\u{0}b");
}

#[test]
fn deterministic_env_sets_contract_vars() {
    use std::ffi::OsStr;
    let mut c = std::process::Command::new("true");
    support::deterministic_env(&mut c);
    let envs: std::collections::HashMap<_, _> = c
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
        .collect();
    assert_eq!(envs.get(OsStr::new("TZ")).unwrap(), "UTC");
    assert_eq!(envs.get(OsStr::new("NO_COLOR")).unwrap(), "1");
    assert_eq!(envs.get(OsStr::new("COLUMNS")).unwrap(), "120");
    assert_eq!(envs.get(OsStr::new("LINES")).unwrap(), "40");
}

#[test]
fn multiple_tokens_on_one_line() {
    let input = "2024-06-15T12:00:00Z call took 0.05s via 127.0.0.1:5060 pid=42 -> /tmp/x";
    assert_eq!(
        normalize(input),
        "<TS> call took <DUR> via 127.0.0.1:<PORT> pid=<PID> -> <TMP>",
    );
}
