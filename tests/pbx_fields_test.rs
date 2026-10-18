// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The PBX filter fields that read the run's configuration, on the shipped
//! binary: `side` against `[pbx] addresses`, and `endpoint` against the names
//! the run gives addresses.
//!
//! The fixture's one call goes from 192.0.2.1 to 192.0.2.2.

use std::process::Command;

type TestError = Box<dyn std::error::Error>;

const CAPTURE: &str = "tests/fixtures/sip_call.pcap";

/// Run sipnab over the fixture with `config` and `filter`, returning the exit
/// code, how many dialogs it selected, and stderr.
fn run(config: &str, filter: &str) -> Result<(Option<i32>, usize, String), TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("pbx.toml");
    std::fs::write(&path, config)?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", CAPTURE, "--no-cli-print", "--json-dialogs"])
        .arg("--config")
        .arg(&path)
        .args(["--filter", filter])
        .env("HOME", dir.path())
        .output()?;
    let selected = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.starts_with('{'))
        .count();
    Ok((
        out.status.code(),
        selected,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// A call sent to an address in `[pbx] addresses` is `inbound`, and a CIDR
/// entry counts as the PBX's.
#[test]
fn side_reads_the_pbx_addresses_the_config_declares() -> Result<(), TestError> {
    for (config, side, want) in [
        ("[pbx]\naddresses = [\"192.0.2.2\"]\n", "inbound", 1),
        ("[pbx]\naddresses = [\"192.0.2.2\"]\n", "outbound", 0),
        ("[pbx]\naddresses = [\"192.0.2.0/24\"]\n", "internal", 1),
        ("[pbx]\naddresses = [\"192.0.2.1\"]\n", "outbound", 1),
        ("", "", 1),
    ] {
        let (code, selected, err) = run(config, &format!("side == '{side}'"))?;
        assert_eq!(code, Some(0), "{config:?}: {err}");
        assert_eq!(selected, want, "{config:?} side == '{side}': {err}");
    }
    Ok(())
}

/// An unusable `[pbx] addresses` entry refuses the run, naming it.
#[test]
fn an_unusable_pbx_address_refuses_the_run() -> Result<(), TestError> {
    let (code, _, err) = run(
        "[pbx]\naddresses = [\"pbx.example\"]\n",
        "method == 'INVITE'",
    )?;
    assert_eq!(code, Some(1), "a config-file value exits 1: {err}");
    assert!(err.contains("[pbx] addresses"), "{err}");
    assert!(err.contains("pbx.example"), "{err}");
    Ok(())
}

/// `endpoint` matches the name the run's `[names]` gives either end, whether
/// or not names are shown.
#[test]
fn endpoint_reads_the_runs_names() -> Result<(), TestError> {
    let config = "[names]\nmanual = { \"192.0.2.2\" = \"pbx-1\", \"192.0.2.1\" = \"phone-7\" }\n";
    for (name, want) in [("pbx-1", 1), ("phone-7", 1), ("elsewhere", 0)] {
        let (code, selected, err) = run(config, &format!("endpoint == '{name}'"))?;
        assert_eq!(code, Some(0), "{err}");
        assert_eq!(selected, want, "endpoint == '{name}': {err}");
    }
    Ok(())
}
