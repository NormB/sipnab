// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where sipnab looks for its config file, driven through the real binary.
//!
//! Each test runs `sipnab` as a subprocess with its own `HOME` and
//! `XDG_CONFIG_HOME`, so the search order is the binary's own and no test
//! changes this process's environment. `--dump-config` reports the file it
//! read and, now, the ones it found and did not read.

use std::path::Path;
use std::process::{Command, Output};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn sipnab(home: &Path, xdg: Option<&Path>, args: &[&str]) -> Result<Output, TestError> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.args(args)
        .env("HOME", home)
        .env_remove("SIPNAB_CONFIG")
        .env("SIPNAB_LOG", "warn");
    match xdg {
        Some(x) => cmd.env("XDG_CONFIG_HOME", x),
        None => cmd.env_remove("XDG_CONFIG_HOME"),
    };
    Ok(cmd.output()?)
}

fn write(path: &Path, body: &str) -> Result<(), TestError> {
    std::fs::create_dir_all(path.parent().ok_or("path has no parent")?)?;
    std::fs::write(path, body)?;
    Ok(())
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn xdg_config_home_is_where_the_user_file_is_read_from() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let xdg = home.path().join("xdg");
    let file = xdg.join("sipnab/sipnab.toml");
    write(&file, "[capture]\nportrange = \"5060-5091\"\n")?;
    let o = sipnab(home.path(), Some(&xdg), &["--dump-config"])?;
    let out = stdout(&o);
    assert!(
        out.contains(&format!("# Loaded from: {}", file.display())),
        "{out}"
    );
    assert!(out.contains(r#"portrange = "5060-5091""#), "{out}");
    Ok(())
}

#[test]
fn with_xdg_config_home_set_dot_config_is_not_read() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    write(
        &home.path().join(".config/sipnab/sipnab.toml"),
        "[capture]\nportrange = \"5060-5092\"\n",
    )?;
    let o = sipnab(
        home.path(),
        Some(&home.path().join("empty-xdg")),
        &["--dump-config"],
    )?;
    let out = stdout(&o);
    assert!(
        out.contains("# No config file loaded"),
        "only $XDG_CONFIG_HOME/sipnab is the user location:\n{out}"
    );
    Ok(())
}

#[test]
fn two_present_files_are_both_named_and_the_ignored_one_said_so() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let user = home.path().join(".config/sipnab/sipnab.toml");
    let rc = home.path().join(".sipnabrc");
    write(&user, "[capture]\nportrange = \"5060-5093\"\n")?;
    write(&rc, "[capture]\nportrange = \"5060-5094\"\n")?;
    let o = sipnab(home.path(), None, &["--dump-config"])?;
    let out = stdout(&o);
    assert!(
        out.contains(&format!("# Loaded from: {}", user.display())),
        "{out}"
    );
    assert!(
        out.contains(&format!("# Also present and NOT read: {}", rc.display())),
        "{out}"
    );
    let o = sipnab(home.path(), None, &["-N", "-I", "/nonexistent.pcap"])?;
    assert!(
        stderr(&o).contains(&format!("Also present and NOT read: {}", rc.display())),
        "a run says it too:\n{}",
        stderr(&o)
    );
    Ok(())
}

#[test]
fn one_present_file_reports_nothing_ignored() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    write(
        &home.path().join(".sipnabrc"),
        "[capture]\nportrange = \"5060-5095\"\n",
    )?;
    let o = sipnab(home.path(), None, &["--dump-config"])?;
    assert!(!stdout(&o).contains("NOT read"), "{}", stdout(&o));
    Ok(())
}

#[test]
fn an_explicit_config_is_a_choice_and_shadows_nothing() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    write(
        &home.path().join(".sipnabrc"),
        "[capture]\nportrange = \"5060-5096\"\n",
    )?;
    let chosen = home.path().join("lab.toml");
    write(&chosen, "[capture]\nportrange = \"5060-5097\"\n")?;
    let o = sipnab(
        home.path(),
        None,
        &[
            "--config",
            chosen.to_str().ok_or("path is not UTF-8")?,
            "--dump-config",
        ],
    )?;
    assert!(!stdout(&o).contains("NOT read"), "{}", stdout(&o));
    Ok(())
}

#[test]
fn a_misspelled_listening_context_stops_the_run_by_name() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let cfg = home.path().join("bad.toml");
    write(&cfg, "[media]\nlistening_context = \"diotc\"\n")?;
    let o = sipnab(
        home.path(),
        None,
        &[
            "--config",
            cfg.to_str().ok_or("path is not UTF-8")?,
            "-N",
            "-I",
            "/nonexistent.pcap",
        ],
    )?;
    assert!(
        !o.status.success(),
        "a typo must not run with the default silently in force"
    );
    assert!(
        stderr(&o).contains("[media] listening_context"),
        "{}",
        stderr(&o)
    );
    Ok(())
}
