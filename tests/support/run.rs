// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical binary-spawn helper for the CLI / output / config integration
//! tests.
//!
//! Before this module, a `run()` copy lived in each of
//! `cli_help_test`, `output_behavior_test`, `cli_flag_behavior_test`,
//! `cli_options_test`, and `config_wiring_test`, and every copy pinned a
//! *slightly different* environment:
//! * `current_dir` was set to the crate root in three files (required so their
//!   relative `tests/fixtures/...` paths resolve) and omitted in the other two.
//! * `SIPNAB_LOG` ranged over unset / `off` / `error` / `warn`, so a run with
//!   no explicit level silently inherited the developer's shell.
//! * `NO_COLOR=1` was set in three files and omitted in two.
//!
//! That drift was the bug: identical-looking helpers behaved differently, and
//! the "unset `SIPNAB_LOG`" cases were only reproducible by luck of the ambient
//! environment. [`run`] collapses them onto ONE controlled baseline:
//!
//! * **cwd = `CARGO_MANIFEST_DIR`, always.** Cargo already launches integration
//!   test binaries from the crate root, so this is a no-op for the absolute-path
//!   callers and makes the relative-fixture callers robust rather than
//!   luck-dependent.
//! * **`NO_COLOR=1` and `CLICOLOR_FORCE` removed.** The non-interactive
//!   `cli_print` batch path decides color purely from `--color` / isatty and
//!   never consults `NO_COLOR`, so `--color always` still emits ANSI and
//!   `--color never` still suppresses it; this only hardens the (never-a-TTY)
//!   pipe against any stray force-color state.
//! * **`SIPNAB_LOG` is caller-chosen, or *removed* when `None`.** Passing the
//!   level explicitly (or explicitly clearing it) means ambient shell state can
//!   never leak into a run — the latent inconsistency the copies suffered.
//!
//! Callers that need a typed return shape (`i32` exit code, bare stdout, a
//! success assertion) wrap [`run`] with a thin local adapter in their own file.
#![allow(dead_code)]

use std::process::Command;

/// Spawn the compiled `sipnab` binary under the controlled test baseline and
/// return its captured `(stdout, stderr, exit_code)`.
///
/// # Arguments
/// * `args` — CLI arguments passed to the binary.
/// * `log` — value for `SIPNAB_LOG`; `Some(level)` sets it, `None` removes it so
///   no ambient log level can leak in.
///
/// # Returns
/// `(stdout, stderr, exit_code)`; the exit code is `None` when the process was
/// terminated by a signal.
///
/// # Side effects
/// Spawns `env!("CARGO_BIN_EXE_sipnab")` as a subprocess from the crate root.
pub fn run(args: &[&str], log: Option<&str>) -> (String, String, Option<i32>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE");
    match log {
        Some(level) => {
            cmd.env("SIPNAB_LOG", level);
        }
        None => {
            cmd.env_remove("SIPNAB_LOG");
        }
    }
    let out = cmd.output().expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}
