// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cli::SECRET_FLAGS` lists every flag that takes a secret inline, and the
//! run provenance record redacts exactly those. A secret flag missing from
//! the list would be written to disk by `--run-provenance-file`, so the list
//! is checked against what the parser declares: every flag read from an
//! environment variable, and every flag whose value is named as a key, token,
//! password or `user:pass` credential.

#![cfg(feature = "native")]

use clap::CommandFactory as _;
use sipnab::cli::{Cli, SECRET_FLAGS};

type TestError = Box<dyn std::error::Error>;

const SECRET_VALUE_NAMES: [&str; 5] = ["KEY", "TOKEN", "PASSWORD", "USER:PASS", "HEADER"];

#[test]
fn every_flag_that_takes_a_secret_inline_is_listed() -> Result<(), TestError> {
    let cmd = Cli::command();
    let mut missing = Vec::new();
    for a in cmd.get_arguments() {
        let Some(long) = a.get_long() else { continue };
        let named_secret = a
            .get_value_names()
            .is_some_and(|v| v.iter().any(|n| SECRET_VALUE_NAMES.contains(&n.as_str())));
        if (a.get_env().is_some() || named_secret) && !SECRET_FLAGS.contains(&long) {
            missing.push(long.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "secret flags missing from SECRET_FLAGS: {missing:?}"
    );
    Ok(())
}

#[test]
fn every_listed_secret_flag_exists_takes_a_value_and_has_no_short_form() -> Result<(), TestError> {
    // get_num_args is filled in when the command is built.
    let mut cmd = Cli::command();
    cmd.build();
    for flag in SECRET_FLAGS {
        let a = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some(flag))
            .ok_or_else(|| {
                format!("SECRET_FLAGS names --{flag}, which the parser does not have")
            })?;
        assert!(
            a.get_num_args().is_some_and(|n| n.takes_values()),
            "--{flag} takes no value"
        );
        assert!(
            a.get_short().is_none(),
            "--{flag} has a short form the redaction does not cover"
        );
    }
    Ok(())
}
