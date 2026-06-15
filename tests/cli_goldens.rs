//! CLI golden tests (verification plan M1 — T1.4; M2 — T2.1–T2.11).
//!
//! Declarative process snapshots via `trycmd`, in two case groups:
//! `tests/cli/cmd/*.trycmd` for global flags (`--help`/`--version`/`--dump-config`)
//! and `tests/cli/out/*.trycmd` for output formats run against
//! `tests/fixtures/sip_call.pcap`.
//! Each case pins a command's combined stdout/stderr and exit code. Cases run
//! under the determinism contract (spec §4d): `TZ=UTC`, `NO_COLOR=1`, fixed
//! terminal size — so output is stable across machines, locales, and TTY state.
//!
//! Output-format goldens are deterministic because they read fixed pcap packet
//! timestamps, not wall-clock. The one exception is `--fail2ban`, whose syslog
//! prefix carries the current date + PID; those are matched with `[..]`.
//!
//! Volatile substrings (the build's version/commit/feature banner) are matched
//! with trycmd's `[..]` wildcard rather than pinned, so a version bump or a
//! different feature set does not break the goldens. The exhaustive per-flag
//! `--help` surface is intentionally NOT pinned here (it is feature-dependent);
//! that coverage is enforced separately by the "no untested flag" gate (T6.2),
//! which reads `cli.rs` directly. These first cases prove the harness itself.
//!
//! Regenerate expected output after an intentional change with:
//!   `TRYCMD=overwrite cargo test --test cli_goldens`

#[path = "support/mod.rs"]
mod support;

#[test]
fn cli_goldens() {
    // Register the built binary explicitly: with more than one `[[bin]]` in the
    // package, trycmd's auto-detection won't map the `sipnab` token, and the
    // cases would be silently *ignored* (a false green) rather than run.
    trycmd::TestCases::new()
        .register_bin(
            "sipnab",
            std::path::PathBuf::from(env!("CARGO_BIN_EXE_sipnab")),
        )
        .default_bin_name("sipnab")
        .env("TZ", "UTC")
        .env("NO_COLOR", "1")
        .env("COLUMNS", support::FIXED_COLS.to_string())
        .env("LINES", support::FIXED_ROWS.to_string())
        // trycmd merges stderr; sipnab's tracing logs carry wall-clock
        // timestamps. Silence them so goldens pin only deterministic stdout.
        .env("SIPNAB_LOG", "off")
        .case("tests/cli/cmd/*.trycmd")
        .case("tests/cli/out/*.trycmd");
}
