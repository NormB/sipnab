// SPDX-License-Identifier: MIT OR Apache-2.0

//! Self-tests for the shared test-support `normalize()` helper (M1/T1.1).
//!
//! TDD: these are written against a stubbed `normalize` (red), then the real
//! implementation makes them pass (green). Per the repo TDD rule, edge cases
//! cover empty input, backslashes, NUL bytes, and multiple tokens per line.

#[path = "support/mod.rs"]
mod support;

use support::normalize;

/// An RFC3339 Z-suffixed timestamp is replaced with `<TS>`.
#[test]
fn scrubs_rfc3339_timestamp() {
    assert_eq!(normalize("at 2024-06-15T12:00:00Z done"), "at <TS> done");
}

/// A timestamp with fractional seconds and a numeric offset is fully replaced with `<TS>`.
#[test]
fn scrubs_timestamp_with_fraction_and_offset() {
    assert_eq!(normalize("2024-06-15T12:00:00.123456+02:00"), "<TS>");
}

/// A fail2ban-style space-separated timestamp is replaced with `<TS>`.
#[test]
fn scrubs_space_separated_timestamp() {
    // fail2ban-style "%Y-%m-%d %H:%M:%S".
    assert_eq!(normalize("ban 2024-06-15 12:00:00 ip"), "ban <TS> ip");
}

/// Second and millisecond durations (with or without a space) become `<DUR>`.
#[test]
fn scrubs_durations_with_units() {
    assert_eq!(
        normalize("setup 1.234s and 12.3 ms"),
        "setup <DUR> and <DUR>"
    );
}

/// A `/tmp/...` path is replaced with `<TMP>`.
#[test]
fn scrubs_temp_paths() {
    assert_eq!(normalize("wrote /tmp/abc123/out.pcap ok"), "wrote <TMP> ok");
}

/// `pid=N` and `PID: N` both normalize to `pid=<PID>`.
#[test]
fn scrubs_pids_any_case() {
    assert_eq!(normalize("pid=12345"), "pid=<PID>");
    assert_eq!(normalize("PID: 678"), "pid=<PID>");
}

/// Loopback IPv4/IPv6 ports become `<PORT>` while the host part is kept.
#[test]
fn scrubs_loopback_ports_keeping_host() {
    assert_eq!(normalize("bound 127.0.0.1:54321"), "bound 127.0.0.1:<PORT>");
    assert_eq!(normalize("mcp [::1]:8731"), "mcp [::1]:<PORT>");
}

/// SIP URIs, version numbers, and codec clock-rates pass through unscrubbed.
#[test]
fn preserves_non_volatile_text() {
    // SIP, version numbers, and codec clock-rates must NOT be scrubbed.
    let s = "INVITE sip:alice@example.com SIP/2.0 v0.4.2 PCMU/8000";
    assert_eq!(normalize(s), s);
}

/// Normalizing an empty string yields an empty string.
#[test]
fn empty_input_is_empty() {
    assert_eq!(normalize(""), "");
}

/// Backslashes (Windows paths) survive normalization unchanged.
#[test]
fn backslashes_are_preserved() {
    let s = r"a\b\c windows\path";
    assert_eq!(normalize(s), s);
}

/// An embedded NUL byte is preserved and does not panic the normalizer.
#[test]
fn nul_byte_is_preserved_without_panic() {
    let out = normalize("a\u{0}b");
    assert!(out.contains('\u{0}'));
    assert_eq!(out, "a\u{0}b");
}

/// `deterministic_env` stamps TZ=UTC, NO_COLOR=1, COLUMNS=120, LINES=40 onto a Command.
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

/// All volatile token classes on one line are scrubbed together in a single pass.
#[test]
fn multiple_tokens_on_one_line() {
    let input = "2024-06-15T12:00:00Z call took 0.05s via 127.0.0.1:5060 pid=42 -> /tmp/x";
    assert_eq!(
        normalize(input),
        "<TS> call took <DUR> via 127.0.0.1:<PORT> pid=<PID> -> <TMP>",
    );
}

include!("support/timeout.rs");

/// `test_timeout` scales deadlines, and refuses a scale that would zero them.
///
/// One test rather than three, deliberately: `cargo test` runs a binary's
/// tests in parallel, so three tests mutating the same environment variable
/// would race each other and pass or fail on scheduling. That is the same
/// class of bug the sanitizer job exists to find, and writing it into the
/// sanitizer job's own self-test would be a poor advertisement.
#[test]
fn timeout_scaling_contract() {
    // SAFETY: the only test in this binary that touches this variable, so no
    // other thread can be reading it concurrently.
    let set = |v: Option<&str>| unsafe {
        match v {
            Some(v) => std::env::set_var("SIPNAB_TEST_TIMEOUT_SCALE", v),
            None => std::env::remove_var("SIPNAB_TEST_TIMEOUT_SCALE"),
        }
    };
    let secs = |d: std::time::Duration| d.as_secs();

    // Unset: used as written.
    set(None);
    assert_eq!(secs(test_timeout(15)), 15);

    // Set: multiplied. This is what keeps the sanitizer job's red meaning
    // "there is a race" rather than "the runner was slow".
    set(Some("12"));
    assert_eq!(secs(test_timeout(15)), 180);

    // Garbage, empty and zero all fall back to 1. A scale that silently read
    // as zero would collapse every deadline to an instant timeout -- the same
    // defect in the opposite direction, and one that would look like a flood
    // of real failures.
    for bad in ["0", "", "  ", "nope", "-3", "1.5"] {
        set(Some(bad));
        assert_eq!(
            secs(test_timeout(5)),
            5,
            "scale {bad:?} must fall back to 1, not zero the deadline"
        );
    }
    set(None);
}
