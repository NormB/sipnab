// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
//! * **No user config.** `HOME`, `XDG_CONFIG_HOME` and `SIPNAB_CONFIG` point
//!   into an empty directory made for the run ([`config_isolation`]). Without
//!   them a caller that passed no `-f` read whatever `~/.sipnabrc` the machine
//!   running it held, so a result depended on whose machine ran it.
//!
//! Callers that need a typed return shape (`i32` exit code, bare stdout, a
//! success assertion) wrap [`run`] with a thin local adapter in their own file.
#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// The environment that keeps a spawned `sipnab` from loading the config of
/// whoever runs the tests, with `home` (an empty directory the caller owns)
/// as its home.
///
/// `Config::load` searches, from the environment, `$SIPNAB_CONFIG`, then
/// `$XDG_CONFIG_HOME/sipnab/sipnab.toml` (or `$HOME/.config/...` when it is
/// unset), then `$HOME/.sipnabrc`. Each one is pinned inside `home`, and
/// `SIPNAB_CONFIG` names a file there that is never created, so all three
/// miss. Pinning by value rather than removing keeps the list usable by
/// `trycmd`, which can set a variable but not remove one.
///
/// The last place it looks, `/etc/sipnab/sipnab.toml`, takes no variable and
/// cannot be pinned from here; a host that has one fails these tests the
/// same way on every run.
pub fn config_isolation(home: &Path) -> [(&'static str, std::ffi::OsString); 3] {
    [
        ("HOME", home.as_os_str().to_owned()),
        ("XDG_CONFIG_HOME", home.join(".config").into_os_string()),
        (
            "SIPNAB_CONFIG",
            home.join("no-such-config.toml").into_os_string(),
        ),
    ]
}

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
pub fn run(args: &[&str], log: Option<&str>) -> std::io::Result<(String, String, Option<i32>)> {
    run_with_ambient(&[], args, log)
}

/// As [`run`], with `ambient` set on the child first, standing in for the
/// environment it would otherwise inherit from whoever runs the tests.
///
/// It exists so the baseline can be tested against a developer's environment
/// without changing this process's own: setting `HOME` here would race every
/// other test thread in the binary.
pub fn run_with_ambient(
    ambient: &[(&str, std::ffi::OsString)],
    args: &[&str],
    log: Option<&str>,
) -> std::io::Result<(String, String, Option<i32>)> {
    // The pinned HOME lives as long as the child: `output()` waits for it,
    // and dropping the TempDir afterwards removes it on every path.
    let home = tempfile::tempdir()?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.envs(ambient.iter().map(|(k, v)| (k, v)));
    cmd.envs(config_isolation(home.path()));
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
    let out = cmd.output()?;
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    ))
}
