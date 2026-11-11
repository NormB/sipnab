// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A gnu tarball installed by hand, or by `install.sh`, must leave the audio
//! plugin where sipnab looks for it.
//!
//! Up to this fix the gnu tarball steps in `docs/install.md` installed the
//! binary alone, and so did `website/static/install.sh`, although the tarball
//! holds `libsipnab_audio.so` beside the binary. sipnab looks for the plugin
//! next to its own executable and then in `/usr/lib/sipnab/`, so a reader who
//! followed the steps had no TUI audio playback.
//!
//! These tests run the documented commands, and the installer's own install
//! function, against a fake tarball laid out the way `release.yml` packs it,
//! inside a temporary root. They then ask sipnab's own search rule,
//! [`trusted_plugin_candidates_for`], where it would look for the installed
//! binary, so the rule is read from one place: `src/rtp/playback.rs`.
//!
//! The download steps (`curl`) are the one part not run: they reach GitHub.
//! The tarball they would fetch is built here instead.
#![cfg(all(feature = "audio", target_os = "linux"))]

use sipnab::rtp::playback::trusted_plugin_candidates_for;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The error a test returns: any error, boxed, so `?` works throughout.
type TestError = Box<dyn std::error::Error>;

/// The release the fake tarball claims to be.
const VERSION: &str = "9.9.9";

fn repo_file(rel: &str) -> Result<String, TestError> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

/// The `bash` code blocks of the gnu tarball steps in `docs/install.md`: from
/// the paragraph that opens them to the next `## ` heading.
fn documented_gnu_steps() -> Result<Vec<String>, TestError> {
    let doc = repo_file("docs/install.md")?;
    let start = doc
        .find("A manual download of the gnu build")
        .ok_or("docs/install.md: no gnu tarball steps")?;
    let rest = &doc[start..];
    let end = rest
        .find("\n## ")
        .ok_or("docs/install.md: gnu steps never end")?;
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in rest[..end].lines() {
        let trimmed = line.trim();
        match (&mut current, trimmed) {
            (None, "```bash") => current = Some(Vec::new()),
            (Some(_), "```") => {
                if let Some(lines) = current.take() {
                    blocks.push(lines.join("\n"));
                }
            }
            (Some(lines), _) => lines.push(trimmed),
            (None, _) => {}
        }
    }
    Ok(blocks)
}

/// The value the steps give `TARGET`.
fn documented_target(blocks: &[String]) -> Result<String, TestError> {
    blocks
        .iter()
        .flat_map(|b| b.lines())
        .find_map(|l| l.strip_prefix("TARGET="))
        .map(str::to_owned)
        .ok_or_else(|| "the gnu steps set no TARGET".into())
}

/// Runs `sh -c <script>` and fails with its output when it exits non-zero.
fn run_sh(script: &str, cwd: &Path, envs: &[(&str, &str)]) -> Result<(), TestError> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(script)
        .current_dir(cwd)
        .envs(envs.iter().copied())
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "script failed ({}):\n{script}\n--- stdout\n{}\n--- stderr\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

/// Builds `sipnab-<VERSION>-<target>.tar.gz` and its `.sha256` in `dir`, laid
/// out as the "Package (tar.gz + checksum)" step of `release.yml` packs a gnu
/// build: one directory holding the binary and the plugin beside it.
fn fake_tarball(dir: &Path, target: &str) -> Result<(), TestError> {
    let stage = format!("sipnab-{VERSION}-{target}");
    let script = format!(
        "set -eu
mkdir -p pack/{stage}
printf '#!/bin/sh\\n' > pack/{stage}/sipnab
chmod 755 pack/{stage}/sipnab
printf 'plugin\\n' > pack/{stage}/libsipnab_audio.so
printf 'readme\\n' > pack/{stage}/README.md
(cd pack && tar -czf ../{stage}.tar.gz {stage})
rm -rf pack
sha256sum {stage}.tar.gz > {stage}.tar.gz.sha256"
    );
    run_sh(&script, dir, &[])
}

/// `path` inside `root`: a candidate under `root` already is; an absolute one
/// elsewhere (`/usr/lib/sipnab/...`) is re-rooted.
fn rooted(root: &Path, path: &Path) -> PathBuf {
    if path.starts_with(root) {
        return path.to_path_buf();
    }
    match path.strip_prefix("/") {
        Ok(rel) => root.join(rel),
        Err(_) => path.to_path_buf(),
    }
}

/// Where sipnab, installed at `exe` inside `root`, finds a plugin file, if
/// anywhere. The bare-soname candidate is resolved by the dynamic loader's
/// search path, which these installs do not touch, so it is skipped.
fn plugin_sipnab_finds(root: &Path, exe: &Path) -> Option<PathBuf> {
    trusted_plugin_candidates_for(Some(exe))
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| rooted(root, &p))
        .find(|p| p.is_file())
}

/// The documented gnu steps as one script run inside `root`: the downloads
/// dropped, `sudo` dropped, and every absolute `/usr/` path moved under
/// `$ROOT`. Returns the script and how many commands it kept.
fn documented_script() -> Result<(String, usize), TestError> {
    let blocks = documented_gnu_steps()?;
    let mut kept = Vec::new();
    for block in &blocks {
        if block.starts_with("curl ") {
            continue;
        }
        kept.push(
            block
                .replace("sudo ", "")
                .replace(" /usr/", " \"$ROOT\"/usr/"),
        );
    }
    let count = kept.len();
    Ok((format!("set -eu\n{}\n", kept.join("\n")), count))
}

/// The gnu tarball steps in docs/install.md, run as written against a fake
/// tarball, leave a plugin where sipnab looks for it.
#[test]
fn the_documented_gnu_tarball_steps_install_the_plugin_where_sipnab_looks() -> Result<(), TestError>
{
    let blocks = documented_gnu_steps()?;
    let target = documented_target(&blocks)?;
    let tmp = tempfile::tempdir()?;
    let work = tmp.path().join("work");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&work)?;
    // What any Linux host has; the documented steps install into it.
    std::fs::create_dir_all(root.join("usr/local/bin"))?;
    fake_tarball(&work, &target)?;

    let (script, _) = documented_script()?;
    let root_str = root.to_str().ok_or("temporary root is not UTF-8")?;
    run_sh(&script, &work, &[("VERSION", VERSION), ("ROOT", root_str)])?;

    let exe = root.join("usr/local/bin/sipnab");
    assert!(
        exe.is_file(),
        "the documented steps did not install {} (script:\n{script})",
        exe.display()
    );
    let found = plugin_sipnab_finds(&root, &exe);
    assert!(
        found.is_some(),
        "after the documented gnu tarball steps sipnab finds no audio plugin; it \
         looks in {:?} (script:\n{script})",
        trusted_plugin_candidates_for(Some(&exe))
    );
    Ok(())
}

/// The test above runs what it extracted, so an extraction that found nothing
/// would let it fail for the wrong reason or, with a different doc, pass
/// having run nothing. The steps are: set TARGET, check the checksum, unpack,
/// install the binary, install the plugin, plus the two downloads.
#[test]
fn the_documented_gnu_steps_are_extracted_whole() -> Result<(), TestError> {
    let blocks = documented_gnu_steps()?;
    let downloads = blocks.iter().filter(|b| b.starts_with("curl ")).count();
    assert_eq!(
        downloads, 2,
        "expected the tarball and checksum downloads: {blocks:#?}"
    );
    let (script, kept) = documented_script()?;
    assert!(
        kept >= 5,
        "kept {kept} commands, expected at least 5:\n{script}"
    );
    for needle in [
        "TARGET=",
        "sha256sum -c",
        "tar -xzf",
        "/usr/local/bin/sipnab",
    ] {
        assert!(
            script.contains(needle),
            "the extracted steps lack {needle:?}:\n{script}"
        );
    }
    Ok(())
}

/// `install.sh` installs a gnu tarball's plugin where sipnab looks for it.
/// Runs the installer's own `install_payload` on the unpacked fake tarball.
#[test]
fn the_installer_installs_the_plugin_where_sipnab_looks() -> Result<(), TestError> {
    let tmp = tempfile::tempdir()?;
    let work = tmp.path().join("work");
    let root = tmp.path().join("root");
    let dest = root.join("usr/local/bin");
    std::fs::create_dir_all(&work)?;
    std::fs::create_dir_all(&dest)?;
    let target = "x86_64-unknown-linux-gnu";
    fake_tarball(&work, target)?;

    let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("website/static/install.sh");
    let installer = installer.to_str().ok_or("repository path is not UTF-8")?;
    let dest_str = dest.to_str().ok_or("temporary root is not UTF-8")?;
    let script = format!(
        "set -eu
mkdir x
tar -xzf sipnab-{VERSION}-{target}.tar.gz -C x
. \"$INSTALLER\"
install_payload x \"$DEST\""
    );
    run_sh(
        &script,
        &work,
        &[
            ("SIPNAB_INSTALL_TEST", "1"),
            ("INSTALLER", installer),
            ("DEST", dest_str),
        ],
    )?;

    let exe = dest.join("sipnab");
    assert!(
        exe.is_file(),
        "install_payload did not install {}",
        exe.display()
    );
    let found = plugin_sipnab_finds(&root, &exe);
    assert!(
        found.is_some(),
        "after install.sh's install_payload sipnab finds no audio plugin; it looks in {:?}",
        trusted_plugin_candidates_for(Some(&exe))
    );
    Ok(())
}
