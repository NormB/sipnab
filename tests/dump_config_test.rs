// SPDX-License-Identifier: MIT OR Apache-2.0

//! `sipnab -D` answers "did sipnab read the file I meant, and did it accept my
//! keys?", so the warnings about keys it did not accept reach the terminal.
//!
//! `-D` draws no TUI, but without `-N` the log level was the TUI's (errors
//! only), so a misspelled key printed nothing and the dump looked clean.

use std::process::Command;

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

#[test]
fn dump_config_warns_about_a_key_it_does_not_know() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("sipnab.toml");
    std::fs::write(&config, "[capture]\ndevise = \"eth0\"\n")?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-f")
        .arg(&config)
        .arg("-D")
        .env_remove("SIPNAB_LOG")
        .env("XDG_STATE_HOME", dir.path())
        .env("HOME", dir.path())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("Unknown config key: capture.devise"),
        "-D must say which key it did not accept:\n{stderr}"
    );
    Ok(())
}

/// `-D` refuses every config file a run refuses, with the run's exit status
/// and the run's message, rather than printing it as though it were accepted.
///
/// These keys are checked when the run is planned, which is after `-D` used
/// to exit, so `-D` exited 0 on each of them while a run exited 1.
#[test]
fn dump_config_refuses_what_a_run_refuses() -> Result<(), TestError> {
    let cases: &[(&str, &str, &str)] = &[
        (
            "pbx",
            "[pbx]\naddresses = [\"not-an-ip\"]\n",
            "[pbx] addresses",
        ),
        (
            "portrange",
            "[capture]\nportrange = \"9-1\"\n",
            "[capture] portrange",
        ),
        ("mcp-tools", "[mcp]\ntools = [\"nope\"]\n", "[mcp] tools"),
        ("filters", "[filters]\nbad = \"method ==\"\n", "bad"),
        (
            "vcon-rule",
            "[[vcon.rule]]\nname = \"r\"\nwhen = \"method ==\"\ndir = \"vcons\"\n",
            "r",
        ),
    ];
    for (label, toml, names) in cases {
        let dir = tempfile::tempdir()?;
        let config = dir.path().join("sipnab.toml");
        std::fs::write(&config, toml)?;
        let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .arg("-f")
            .arg(&config)
            .arg("-D")
            .current_dir(dir.path())
            .env_remove("SIPNAB_LOG")
            .env("XDG_STATE_HOME", dir.path())
            .env("HOME", dir.path())
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "{label}: -D accepted it:\n{stderr}"
        );
        assert!(
            stderr.contains(names),
            "{label}: the refusal must name {names:?}:\n{stderr}"
        );
    }
    Ok(())
}
