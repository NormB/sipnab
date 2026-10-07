// SPDX-License-Identifier: MIT OR Apache-2.0

//! A save from the terminal UI writes the config file the run LOADED.
//!
//! It used to write `~/.config/sipnab/sipnab.toml` always. That file sits
//! ahead of `~/.sipnabrc` in the search order, so one saved column layout made
//! every later run load the new file and ignore the rest of `~/.sipnabrc`.
//! These tests drive the real search order: the binary runs as a subprocess
//! with its own `HOME`, and `--dump-config` says which file it loaded and what
//! it holds. No test changes this process's environment.

use std::path::Path;
use std::process::Command;

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

/// `sipnab --dump-config` with `HOME` set to `home` and no `$SIPNAB_CONFIG`.
fn dump_config(home: &Path, extra: &[&str]) -> Result<String, TestError> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(extra)
        .arg("--dump-config")
        .env("HOME", home)
        .env_remove("SIPNAB_CONFIG")
        .env_remove("XDG_CONFIG_HOME")
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn layout() -> Vec<String> {
    vec!["Method".to_string(), "From".to_string(), "To".to_string()]
}

/// The reported case: settings in `~/.sipnabrc`, one F10 save, and the next
/// run still has both the settings and the layout.
#[test]
fn saving_into_sipnabrc_keeps_its_settings_in_force() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let rc = home.path().join(".sipnabrc");
    std::fs::write(&rc, "[capture]\nportrange = \"5060-5099\"\n")?;

    let target = sipnab::config::save_target(
        Some(&rc),
        Some(&home.path().join(".config/sipnab/sipnab.toml")),
    )?;
    sipnab::config::write_display_columns_file(&target, &layout())?;

    assert!(
        !home.path().join(".config/sipnab/sipnab.toml").exists(),
        "a save must not create the file that shadows ~/.sipnabrc"
    );
    let dump = dump_config(home.path(), &[])?;
    assert!(
        dump.contains(&format!("# Loaded from: {}", rc.display())),
        "{dump}"
    );
    assert!(
        dump.contains(r#"portrange = "5060-5099""#),
        "the saved-from settings survive:\n{dump}"
    );
    assert!(
        dump.contains("visible_columns"),
        "the saved layout is in force:\n{dump}"
    );
    Ok(())
}

/// Why the old target was wrong, from the search order itself: a file at
/// `~/.config/sipnab/sipnab.toml` is loaded INSTEAD of `~/.sipnabrc`, so a
/// layout saved there hides every other setting the user had.
#[test]
fn a_user_file_beside_sipnabrc_hides_it() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    std::fs::write(
        home.path().join(".sipnabrc"),
        "[capture]\nportrange = \"5060-5099\"\n",
    )?;
    let shadow = home.path().join(".config/sipnab/sipnab.toml");
    sipnab::config::write_display_columns_file(&shadow, &layout())?;

    let dump = dump_config(home.path(), &[])?;
    assert!(
        dump.contains(&format!("# Loaded from: {}", shadow.display())),
        "{dump}"
    );
    assert!(
        !dump.contains("5060-5099"),
        "~/.sipnabrc is no longer read:\n{dump}"
    );
    Ok(())
}

/// Under `--config`, the save lands in that file, and toml_edit keeps the
/// operator's comments and other tables.
#[test]
fn saving_into_an_explicit_config_keeps_its_comments_and_settings() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let cfg = home.path().join("lab.toml");
    std::fs::write(
        &cfg,
        "# lab box: do not edit by hand\n[capture]\nportrange = \"5070-5079\"\n",
    )?;

    let target = sipnab::config::save_target(
        Some(&cfg),
        Some(&home.path().join(".config/sipnab/sipnab.toml")),
    )?;
    assert_eq!(target, cfg);
    sipnab::config::write_display_columns_file(&target, &layout())?;

    let text = std::fs::read_to_string(&cfg)?;
    assert!(text.contains("# lab box: do not edit by hand"), "{text}");
    let dump = dump_config(
        home.path(),
        &["--config", cfg.to_str().ok_or("path is not UTF-8")?],
    )?;
    assert!(
        dump.contains(r#"portrange = "5070-5079""#) && dump.contains("visible_columns"),
        "{dump}"
    );
    assert!(!home.path().join(".config/sipnab/sipnab.toml").exists());
    Ok(())
}

/// With no file loaded, the save creates the user file, and the next run
/// loads it.
#[test]
fn saving_with_no_file_creates_the_user_file() -> Result<(), TestError> {
    let home = tempfile::tempdir()?;
    let target =
        sipnab::config::save_target(None, Some(&home.path().join(".config/sipnab/sipnab.toml")))?;
    sipnab::config::write_display_columns_file(&target, &layout())?;
    let dump = dump_config(home.path(), &[])?;
    assert!(
        dump.contains(&format!(
            "# Loaded from: {}",
            home.path().join(".config/sipnab/sipnab.toml").display()
        )),
        "{dump}"
    );
    Ok(())
}
