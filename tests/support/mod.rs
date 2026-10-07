// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared test-support helpers.
//!
//! `normalize()` replaces volatile substrings (timestamps, durations, temp
//! paths, PIDs, ephemeral loopback ports) with stable placeholders so golden /
//! snapshot comparisons stay reproducible across runs, machines, and locales.
//! This is the determinism contract every golden/snapshot test relies on: two
//! runs that differ only in those volatile substrings must normalize equal.
//!
//! This file lives in a `tests/` subdirectory, so cargo does not compile it as
//! its own test binary; consumers include it with
//! `#[path = "support/mod.rs"] mod support;`.
#![allow(dead_code)]

use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

/// The error a fallible helper here returns: any error, boxed, so `?` works
/// on every error type alike.
pub type TestError = Box<dyn std::error::Error>;

/// JSON-Schema validation helpers (T1.3).
pub mod schema;

/// Whether the binary under test can open a live capture device here.
///
/// ONE implementation. Two files each carried their own, both read the test
/// runner's capabilities rather than the binary's, and both answered
/// "unprivileged" against a sipnab that captures happily.
pub mod capture_probe;

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

/// Send a spawned child's coverage profile somewhere it will not be merged.
///
/// Tests that kill the binary they spawned — `crash_test` (SIGABRT via the
/// `core = true` policy) and `parse_path_test` (`Child::kill()`, i.e. SIGKILL,
/// on a timeout) — can leave behind a truncated `.profraw`, because a process
/// killed by a signal never finishes its profile. Under `cargo llvm-cov` those
/// land in `target/llvm-cov-target/` beside the good ones and
/// `llvm-profdata merge` fails the entire Coverage job with
/// "invalid instrumentation profile data (file header is corrupt)".
///
/// That produced an intermittent red with no relation to the change under
/// test, which is precisely how a gate earns a reputation for flakiness and
/// then gets muted. Redirecting the doomed child's profile out of the merge
/// directory fixes the cause instead of retrying past it.
///
/// Nothing is lost: the coverage of a process that is about to be killed is not
/// meaningful, and the parent test binary still records its own.
///
/// Apply this to every spawn whose child may be signaled, not only the ones
/// that always are — `parse_path_test` only SIGKILLs on a timeout, so its
/// corrupt profile appears just on the slow runs that are hardest to reproduce.
///
/// A child that is merely being torn down does not belong here. The spawn
/// harnesses stop theirs with `terminate` (`support/teardown.rs`): SIGTERM,
/// which sipnab turns into an ordinary exit that writes a whole profile, and
/// SIGKILL only for a child still running once a grace period ends.
/// `hep_test` used to discard its listener's profile because the listener was
/// SIGKILLed; it is no longer, and that coverage now counts.
pub fn discard_coverage_profile(cmd: &mut Command) -> &mut Command {
    let dir = std::env::temp_dir().join(format!("sipnab-discarded-cov-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    // %p so concurrent children cannot collide with each other either.
    cmd.env("LLVM_PROFILE_FILE", dir.join("discarded-%p.profraw"))
}

/// Replace volatile substrings with stable placeholders. See module docs.
///
/// Order matters: timestamps are scrubbed before durations so the seconds field
/// of a timestamp can't be mistaken for a duration.
pub fn normalize(input: &str) -> Result<String, TestError> {
    let subs: [(&Regex, &str); 5] = [
        (ts_re()?, "<TS>"),
        (dur_re()?, "<DUR>"),
        (tmp_re()?, "<TMP>"),
        (pid_re()?, "pid=<PID>"),
        (port_re()?, "$host:<PORT>"),
    ];
    let mut out = input.to_string();
    for (re, rep) in subs {
        out = re.replace_all(&out, rep).into_owned();
    }
    Ok(out)
}

/// The regex `cell` holds, compiling `pattern()` on first use; a pattern that
/// fails to compile reports the same error on every call.
fn cached(
    cell: &'static OnceLock<Result<Regex, regex::Error>>,
    pattern: impl FnOnce() -> String,
) -> Result<&'static Regex, regex::Error> {
    cell.get_or_init(|| Regex::new(&pattern()))
        .as_ref()
        .map_err(Clone::clone)
}

/// RFC3339 / `%Y-%m-%d %H:%M:%S` timestamps, with optional fraction and offset.
fn ts_re() -> Result<&'static Regex, regex::Error> {
    static RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
    cached(&RE, || {
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?".to_string()
    })
}

/// Durations like `1.234s`, `12.3 ms`, `500us`, `7ns`.
fn dur_re() -> Result<&'static Regex, regex::Error> {
    static RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
    cached(&RE, || r"\d+(?:\.\d+)?\s?(?:ns|µs|us|ms|s)\b".to_string())
}

/// Temp-file paths, under `/tmp/` **and** under this platform's real temp
/// directory.
///
/// The pattern was `/tmp/` alone, which is the Linux answer and only the Linux
/// answer. `std::env::temp_dir()` reads `$TMPDIR` first, and on macOS launchd
/// sets that to a per-user, per-boot directory: measured 2026-08-19 on
/// macOS 26.5.2/aarch64 it is `/var/folders/4x/<hash>/T/`. Nothing a test wrote
/// there matched `/tmp/`, so `normalize()` substituted nothing, and "the
/// determinism contract every golden/snapshot test relies on" (see the module
/// doc) quietly held for one platform.
///
/// It reads as a passing normalizer either way, which is why it survived: the
/// self-test in `tests/support_selftest.rs` feeds it a literal
/// `/tmp/abc123/out.pcap`, so it exercises the branch that works on both hosts
/// and never the one that does not.
///
/// `/private/tmp` is here for the same reason and is macOS-specific too: `/tmp`
/// there is a symlink into `/private`, so a path that has been through
/// `canonicalize()` comes back with the longer prefix and no longer matches
/// `/tmp/`.
///
/// Built once from `temp_dir()` at first use rather than hardcoded, because the
/// `<hash>` differs per user and per boot. `regex::escape` is not optional: the
/// path is interpolated into a pattern.
fn tmp_re() -> Result<&'static Regex, regex::Error> {
    static RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
    cached(&RE, || {
        let mut alts = vec![regex::escape("/tmp/"), regex::escape("/private/tmp/")];
        let sys = std::env::temp_dir();
        let sys = sys.to_string_lossy();
        let sys = format!("{}/", sys.trim_end_matches('/'));
        if !alts.iter().any(|a| a == &regex::escape(&sys)) {
            alts.push(regex::escape(&sys));
        }
        // Longest-first: the alternation is ordered, and `/tmp/` would
        // otherwise win against a temp dir that happens to start with it.
        alts.sort_by_key(|a| std::cmp::Reverse(a.len()));
        format!(r#"(?:{})[^\s"']+"#, alts.join("|"))
    })
}

/// `pid=NNN` / `PID: NNN` in any case.
fn pid_re() -> Result<&'static Regex, regex::Error> {
    static RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
    cached(&RE, || r"(?i)\bpid\s*[=:]\s*\d+".to_string())
}

/// Ephemeral ports on loopback hosts, keeping the host intact.
fn port_re() -> Result<&'static Regex, regex::Error> {
    static RE: OnceLock<Result<Regex, regex::Error>> = OnceLock::new();
    cached(&RE, || {
        r"(?P<host>127\.0\.0\.1|\[::1\]|localhost):\d{2,5}".to_string()
    })
}

// Panicking forms of the functions above, for callers not yet converted to
// return a `Result`. Each is removed when its last caller is converted;
// `unwrap_ratchet_test` counts the `expect` in each.

/// [`normalize`], panicking on error.
pub fn normalize_or_panic(input: &str) -> String {
    normalize(input).expect("normalize")
}
