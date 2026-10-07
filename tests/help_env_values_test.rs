// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--help` never prints the value of an environment variable a flag reads.
//!
//! clap shows `[env: NAME=value]` beside a flag unless the argument sets
//! `hide_env_values`. Every environment variable sipnab reads carries a secret
//! (`SIPNAB_API_KEY`, `SIPNAB_HEP_AUTH`, the signing keys), so until 2026-10-07
//! `SIPNAB_HEP_AUTH=<key> sipnab --help` printed the key. The list is read from
//! clap, so a flag added later with an `env` is covered without editing this
//! file.

#![cfg(feature = "native")]

use std::process::Command;

use clap::CommandFactory as _;
use sipnab::cli::Cli;

type TestError = Box<dyn std::error::Error>;

/// Every environment variable a flag reads, by its flag's long name.
fn env_args() -> Vec<(String, String)> {
    Cli::command()
        .get_arguments()
        .filter_map(|a| {
            let env = a.get_env()?.to_str()?.to_string();
            Some((a.get_long().unwrap_or_default().to_string(), env))
        })
        .collect()
}

#[test]
fn every_environment_backed_flag_hides_its_value() -> Result<(), TestError> {
    let args = env_args();
    assert!(
        args.len() >= 4,
        "expected the secret env flags, found {args:?}"
    );
    let shown: Vec<_> = Cli::command()
        .get_arguments()
        .filter(|a| a.get_env().is_some() && !a.is_hide_env_values_set())
        .filter_map(|a| a.get_long().map(str::to_string))
        .collect();
    assert!(
        shown.is_empty(),
        "these flags print their env value in --help: {shown:?}"
    );
    Ok(())
}

#[test]
fn help_never_prints_an_environment_value() -> Result<(), TestError> {
    for (flag, env) in env_args() {
        let marker = format!("zz-help-probe-{}", env.to_lowercase());
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .arg("--help")
            .env(&env, &marker)
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !text.contains(&marker),
            "--help printed the value of {env} (read by --{flag})"
        );
    }
    Ok(())
}
