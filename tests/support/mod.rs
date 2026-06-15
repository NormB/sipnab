//! Shared test-support helpers (verification plan M1 — T1.1 `normalize`, T1.5 env).
//!
//! `normalize()` replaces volatile substrings (timestamps, durations, temp
//! paths, PIDs, ephemeral loopback ports) with stable placeholders so golden /
//! snapshot comparisons stay reproducible across runs, machines, and locales.
//! See `tasks/verification-spec.md` §4d (determinism contract) and §13.4.
//!
//! This file lives in a `tests/` subdirectory, so cargo does not compile it as
//! its own test binary; consumers include it with
//! `#[path = "support/mod.rs"] mod support;`.
#![allow(dead_code)]

use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

/// Determinism contract (spec §4d): fixed virtual-terminal dimensions.
pub const FIXED_COLS: u16 = 120;
pub const FIXED_ROWS: u16 = 40;

/// Apply the deterministic environment contract to a command so CLI goldens
/// are stable across machines/locales (spec §4d / §13.4): UTC time, no color,
/// fixed terminal size.
pub fn deterministic_env(cmd: &mut Command) -> &mut Command {
    cmd.env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("COLUMNS", FIXED_COLS.to_string())
        .env("LINES", FIXED_ROWS.to_string())
        .env_remove("CLICOLOR_FORCE")
}

/// Replace volatile substrings with stable placeholders. See module docs.
///
/// Order matters: timestamps are scrubbed before durations so the seconds field
/// of a timestamp can't be mistaken for a duration.
pub fn normalize(input: &str) -> String {
    let subs: [(&Regex, &str); 5] = [
        (ts_re(), "<TS>"),
        (dur_re(), "<DUR>"),
        (tmp_re(), "<TMP>"),
        (pid_re(), "pid=<PID>"),
        (port_re(), "$host:<PORT>"),
    ];
    let mut out = input.to_string();
    for (re, rep) in subs {
        out = re.replace_all(&out, rep).into_owned();
    }
    out
}

/// RFC3339 / `%Y-%m-%d %H:%M:%S` timestamps, with optional fraction and offset.
fn ts_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
            .unwrap()
    })
}

/// Durations like `1.234s`, `12.3 ms`, `500us`, `7ns`.
fn dur_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d+(?:\.\d+)?\s?(?:ns|µs|us|ms|s)\b").unwrap())
}

/// Temp-file paths under `/tmp/`.
fn tmp_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"/tmp/[^\s"']+"#).unwrap())
}

/// `pid=NNN` / `PID: NNN` in any case.
fn pid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bpid\s*[=:]\s*\d+").unwrap())
}

/// Ephemeral ports on loopback hosts, keeping the host intact.
fn port_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?P<host>127\.0\.0\.1|\[::1\]|localhost):\d{2,5}").unwrap())
}
