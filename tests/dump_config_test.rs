// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
/// to exit, so `-D` exited 0 on each of them while a run exited 1. Measured
/// on 0.5.224, `-D` still exited 0 on `[security] alert`, `[actions] tfps`,
/// `[filter] expression` and `[action_limits]` values a run refuses. Each
/// case runs both `-D` and a run over a capture, and asserts the same exit
/// status and the same message from both.
#[test]
fn dump_config_refuses_what_a_run_refuses() -> Result<(), TestError> {
    let mut cases: Vec<(&str, &str, &str)> = vec![
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
            "alert-channel",
            "[security]\nalert = [\"bogus\"]\n",
            "[security] alert",
        ),
        (
            "alert-kind",
            "[security]\nalert = [\"nosuchkind:5/60\"]\n",
            "nosuchkind",
        ),
        (
            "actions",
            "[actions]\ntfps = [\"nope\"]\n",
            "[actions] tfps",
        ),
        (
            "filter-expression",
            "[filter]\nexpression = \"method ==\"\n",
            "[filter] expression",
        ),
    ];
    // A build without `vcon` reads no `[[vcon.rule]]`, so a run does not refuse
    // a malformed one and `-D` must not either.
    if cfg!(feature = "vcon") {
        cases.push((
            "vcon-rule",
            "[[vcon.rule]]\nname = \"r\"\nwhen = \"method ==\"\ndir = \"vcons\"\n",
            "r",
        ));
    }
    // `rest` is an actions surface only in a build with the REST API.
    if cfg!(feature = "api") {
        cases.push((
            "action-limits",
            "[actions]\ntfps = [\"rest\"]\n[action_limits]\nper_minute = 0\n",
            "[action_limits] per_minute",
        ));
    }
    let capture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sip_call.pcap");
    for (label, toml, names) in cases {
        let dir = tempfile::tempdir()?;
        let config = dir.path().join("sipnab.toml");
        std::fs::write(&config, toml)?;
        let run = |args: &[&std::ffi::OsStr]| {
            Command::new(env!("CARGO_BIN_EXE_sipnab"))
                .arg("-f")
                .arg(&config)
                .args(args)
                .current_dir(dir.path())
                .env_remove("SIPNAB_LOG")
                .env("NO_COLOR", "1")
                .env("XDG_STATE_HOME", dir.path())
                .env("HOME", dir.path())
                .output()
        };
        let out = run(&["-D".as_ref()])?;
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
        let refused =
            refusal(&stderr).ok_or_else(|| format!("{label}: no ERROR line:\n{stderr}"))?;

        let ran = run(&[
            "-N".as_ref(),
            "-I".as_ref(),
            capture.as_os_str(),
            "--no-cli-print".as_ref(),
        ])?;
        let ran_stderr = String::from_utf8_lossy(&ran.stderr);
        assert_eq!(
            ran.status.code(),
            out.status.code(),
            "{label}: a run and -D exit alike:\n{ran_stderr}"
        );
        assert_eq!(
            refusal(&ran_stderr).as_deref(),
            Some(refused.as_str()),
            "{label}: a run and -D give the same message:\n{ran_stderr}"
        );
    }
    Ok(())
}

/// The message of the first `ERROR` line in `stderr`, without the timestamp,
/// the level and the module path the log adds.
fn refusal(stderr: &str) -> Option<String> {
    let line = stderr.lines().find(|l| l.contains(" ERROR "))?;
    let (_, after) = line.split_once(" ERROR ")?;
    let message = after
        .trim_start()
        .split_once(": ")
        .map_or(after, |(_, m)| m);
    Some(message.to_string())
}

/// `-D` shows `[security] kill_scanner_detect_only` as the file set it, so an
/// operator can confirm a detect-only configuration before a live run.
#[test]
fn dump_config_shows_kill_scanner_detect_only() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let config = dir.path().join("sipnab.toml");
    std::fs::write(&config, "[security]\nkill_scanner_detect_only = true\n")?;
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("-f")
        .arg(&config)
        .arg("-D")
        .env_remove("SIPNAB_LOG")
        .env("XDG_STATE_HOME", dir.path())
        .env("HOME", dir.path())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stdout.contains("kill_scanner_detect_only = true"),
        "-D must show the key:\n{stdout}"
    );
    assert!(
        !stderr.contains("Unknown config key"),
        "the key must be one sipnab accepts:\n{stderr}"
    );
    Ok(())
}
