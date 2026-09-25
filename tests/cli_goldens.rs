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

    pinned_cases(&home)
        .case("tests/cli/cmd/*.trycmd")
        .case("tests/cli/out/*.trycmd")
        .run();

    // The cookbook group runs AFTER the one above, in the same test, and that
    // ordering is load-bearing: it changes the process working directory, and
    // a second `#[test]` in this binary would run on another thread against
    // relative globs that no longer resolve.
    cookbook::run(&home);

    let _ = std::fs::remove_dir_all(&home);
}

/// A `trycmd` run pinned to the determinism env every CLI golden shares.
fn pinned_cases(home: &std::path::Path) -> trycmd::TestCases {
    // Register the built binary explicitly: with more than one `[[bin]]` in the
    // package, trycmd's auto-detection won't map the `sipnab` token, and the
    // cases would be silently *ignored* (a false green) rather than run.
    let cases = trycmd::TestCases::new();
    cases
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
        );
    cases
}

/// EX8: the output of every cookbook command `scripts/check-cookbook.py`
/// executes, pinned under `tests/cli/cookbook/`.
///
/// The checker owns the list. Each case's command is the one it runs, spelled
/// by its `golden_case` -- the repo-relative fixture `tests/pcap-samples/...`
/// and a per-case output directory named after the case -- and the checker
/// fails any executed command with no case here and no reason in its
/// `OUTPUT_UNPINNED` table, and any case here no executed command produces
/// (`every_cookbook_command_still_works`). This function only runs them.
///
/// They run in a scratch directory, not the repository, because recipes
/// WRITE: vCon directories, a redaction map, a provenance log, a pcap. In the
/// repo root those would litter the tree, and a second run would meet the
/// first run's files -- sipnab refuses to write over an existing
/// `--redact-map`, so the golden would pin a refusal. The scratch directory
/// holds a `tests` symlink back to the repository, so the fixture path in
/// every case reads exactly as the checker spells it and nothing is copied.
///
/// Gated like `tests/cookbook_recipes_test.rs`, and for the same reason: the
/// recipes use flags (`--keylog`, `--hep-*`, `--plugin`) that exist only in a
/// build carrying those features, and the checker that decides which commands
/// get a golden is itself only run there.
mod cookbook {
    #[cfg(all(
        unix,
        feature = "native",
        feature = "tls",
        feature = "hep",
        feature = "mcp",
        feature = "api",
        feature = "metrics",
        feature = "plugins",
    ))]
    pub fn run(home: &std::path::Path) {
        use std::path::{Path, PathBuf};

        let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
        let scratch = home.join("cookbook");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("create the cookbook scratch dir");
        std::os::unix::fs::symlink(repo.join("tests"), scratch.join("tests"))
            .expect("link the scratch dir's tests/ to the repository's");

        // Each case writes into the directory its file is named after -- the
        // key the checker's `golden_case` puts in every output path -- and
        // sipnab does not create a missing parent for `--run-provenance-file`
        // or `-O`, so the directory has to exist before the case runs.
        for entry in std::fs::read_dir(repo.join("tests/cli/cookbook"))
            .expect("list tests/cli/cookbook")
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "trycmd") {
                let key = path.file_stem().expect("a case file has a stem");
                std::fs::create_dir(scratch.join(key)).expect("create a case's output dir");
            }
        }

        let cases: PathBuf = repo.join("tests/cli/cookbook/*.trycmd");
        let before = std::env::current_dir().expect("read the working directory");
        std::env::set_current_dir(&scratch).expect("enter the cookbook scratch dir");
        // Run inside a closure so the working directory is restored before
        // any assertion below can panic.
        let outcome = std::panic::catch_unwind(|| {
            super::pinned_cases(home)
                .case(cases.to_string_lossy().into_owned())
                .run();
        });
        std::env::set_current_dir(before).expect("restore the working directory");

        // Everything a case wrote must be inside its own directory. A write
        // anywhere else means a recipe gained an output flag the checker's
        // OUTPUT_FLAGS does not redirect, and two cases could then share it.
        let strays: Vec<String> = std::fs::read_dir(&scratch)
            .expect("list the cookbook scratch dir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name != "tests"
                    && !(name.len() == 10 && name.bytes().all(|b| b.is_ascii_hexdigit()))
            })
            .collect();
        let _ = std::fs::remove_dir_all(&scratch);
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
        assert!(
            strays.is_empty(),
            "a cookbook case wrote outside its own directory: {strays:?}. Add \
             the flag that names it to OUTPUT_FLAGS in scripts/check-cookbook.py"
        );
    }

    #[cfg(not(all(
        unix,
        feature = "native",
        feature = "tls",
        feature = "hep",
        feature = "mcp",
        feature = "api",
        feature = "metrics",
        feature = "plugins",
    )))]
    pub fn run(_home: &std::path::Path) {}
}
