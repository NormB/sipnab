// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// Runs every `tests/cli/cmd/*.trycmd` and `tests/cli/out/*.trycmd` case,
/// pinning each command's stdout/stderr and exit code under the determinism env.
#[test]
fn cli_goldens() {
    // ---- Config discovery is part of the determinism contract --------------
    //
    // `tests/cli/cmd/dump-config.trycmd` runs `sipnab --dump-config` with no
    // `-f` and no `--no-config`, and its golden opens with
    //
    //     # No config file loaded (defaults only)
    //
    // That is not a property of the binary. It is a property of the MACHINE.
    // `Config::load` searches `$SIPNAB_CONFIG`, then `$HOME/.config/sipnab/
    // sipnab.toml`, then `$HOME/.sipnabrc` (src/config.rs:1664-1687), and the
    // env pinned below covered time, color, terminal size and logging but not
    // `$HOME` -- so the golden held only on a runner with a pristine home
    // directory, which describes CI and describes no developer who has ever
    // used the tool they are working on.
    //
    // Demonstrated 2026-08-19 on macOS/aarch64 against the built binary: with
    // an empty `$HOME` the header reads `# No config file loaded (defaults
    // only)`; drop a two-line `.sipnabrc` into that same `$HOME` and it reads
    // `# Loaded from: <path>` with the file's values inlined below it. The
    // golden then fails, and it fails looking like a `--dump-config` bug
    // rather than an environment one. `touch ~/.sipnabrc` is the whole repro.
    //
    // So `$HOME` is pinned to a directory this test owns and keeps empty, and
    // `$SIPNAB_CONFIG` is pointed inside it at a file that is never created --
    // an exported `SIPNAB_CONFIG` outranks `$HOME` in the search, so pinning
    // one without the other would leave the same hole one entry higher up.
    // A miss there logs at `debug!`, which `SIPNAB_LOG=off` already silences.
    //
    // CARGO_TARGET_TMPDIR rather than the process-wide system temp directory:
    // it is per-target, inside `target/`, and removed by `cargo clean` along
    // with everything else this test builds.
    //
    // The pid suffix is what `tests/temp_path_isolation_test.rs` demands, and
    // it is right to: two `cargo test` runs against the same target directory
    // would otherwise share this HOME, and the second one's cleanup below
    // would delete a config the first was about to read. Exactly the collision
    // that file's header records against `sipnab_test_bpf_filter.txt`, where
    // the symptom named `--bpf-file` rather than the harness.
    let home = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cli-goldens-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create the pinned HOME for CLI goldens");
    for stray in [".sipnabrc", ".config/sipnab/sipnab.toml"] {
        let _ = std::fs::remove_file(home.join(stray));
    }

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
        .env("HOME", home.to_string_lossy().into_owned())
        .env(
            "SIPNAB_CONFIG",
            home.join("no-such-config.toml")
                .to_string_lossy()
                .into_owned(),
        )
        .case("tests/cli/cmd/*.trycmd")
        .case("tests/cli/out/*.trycmd");
}
