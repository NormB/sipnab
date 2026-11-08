// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! A release tag is pushed only when it is signed by a trusted key.
//!
//! A `v*` tag publishes a release, so the tag is the one artifact this machine
//! makes that a user can check against the maintainer's identity. Tags
//! v0.5.176 to v0.5.197 went out annotated but unsigned: `tag.gpgSign` was never
//! set, and nothing noticed. `scripts/tag-signature-check.sh` is the rule, and
//! `.githooks/pre-push` runs it on every `v*` tag before the CI check. The keys
//! it trusts are in `.github/allowed_signers`, in the repository, so the check
//! gives the same answer on any machine and adding a signer is a reviewed
//! change.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/executable.rs"]
mod executable;

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    repo().join("scripts/tag-signature-check.sh")
}

fn git(dir: &Path, args: &[&str]) -> Result<(), TestError> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .map_err(|e| format!("git runs: {e}"))?;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

fn keygen(dir: &Path, name: &str) -> Result<PathBuf, TestError> {
    let key = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&key)
        .output()
        .map_err(|e| format!("ssh-keygen runs: {e}"))?;
    assert!(out.status.success(), "ssh-keygen failed");
    Ok(key)
}

/// A throwaway repository with one commit, a trusted key and an untrusted one,
/// and an allowed-signers file naming only the trusted key.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    allowed: PathBuf,
}

fn fixture() -> Result<Fixture, TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let root = dir.path().join("r");
    std::fs::create_dir(&root).map_err(|e| format!("mkdir: {e}"))?;
    git(&root, &["init", "-q"])?;
    git(&root, &["config", "user.name", "Release Bot"])?;
    git(&root, &["config", "user.email", "release@example.invalid"])?;
    git(&root, &["config", "commit.gpgsign", "false"])?;
    git(&root, &["config", "tag.gpgSign", "false"])?;
    git(&root, &["config", "gpg.format", "ssh"])?;
    git(&root, &["commit", "-q", "--allow-empty", "-m", "base"])?;
    let trusted = keygen(dir.path(), "trusted")?;
    let untrusted = keygen(dir.path(), "untrusted")?;
    let public = std::fs::read_to_string(trusted.with_extension("pub"))
        .map_err(|e| format!("pub key: {e}"))?;
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(&allowed, format!("release@example.invalid {public}"))
        .map_err(|e| format!("write: {e}"))?;
    Ok(Fixture {
        _dir: dir,
        root,
        trusted,
        untrusted,
        allowed,
    })
}

fn check(f: &Fixture, tag: &str) -> Result<(bool, String), TestError> {
    check_with(f, tag, &script(), None)
}

/// Run `script` on `tag`, with `path_prefix` (when given) first on `PATH`.
fn check_with(
    f: &Fixture,
    tag: &str,
    script: &Path,
    path_prefix: Option<&Path>,
) -> Result<(bool, String), TestError> {
    let sha = String::from_utf8(
        Command::new("git")
            .current_dir(&f.root)
            .args(["rev-parse", tag])
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .map_err(|e| format!("rev-parse: {e}"))?
            .stdout,
    )
    .map_err(|e| format!("utf8: {e}"))?;
    let mut cmd = Command::new("bash");
    if let Some(prefix) = path_prefix {
        let path = std::env::var("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{path}", prefix.display()));
    }
    let out = cmd
        .arg(script)
        .arg(sha.trim())
        .current_dir(&f.root)
        // A commit hook exports GIT_DIR and GIT_INDEX_FILE for the repository
        // being committed; inherited, they point every git call here at that
        // repository instead of the fixture.
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("SIPNAB_ALLOWED_SIGNERS", &f.allowed)
        .output()
        .map_err(|e| format!("script runs: {e}"))?;
    Ok((
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

fn signed_tag(f: &Fixture, name: &str, key: &Path) -> Result<(), TestError> {
    let pubkey = key.with_extension("pub");
    git(
        &f.root,
        &[
            "-c",
            &format!("user.signingkey={}", pubkey.display()),
            "tag",
            "-s",
            "-m",
            "release",
            name,
        ],
    )
}

#[test]
fn a_tag_signed_by_a_trusted_key_passes() -> Result<(), TestError> {
    let f = fixture()?;
    signed_tag(&f, "v9.9.1", &f.trusted.clone())?;
    let (ok, out) = check(&f, "v9.9.1")?;
    assert!(ok, "a tag signed by the trusted key must pass: {out}");
    Ok(())
}

#[test]
fn an_unsigned_annotated_tag_is_refused() -> Result<(), TestError> {
    let f = fixture()?;
    git(&f.root, &["tag", "-a", "-m", "release", "v9.9.2"])?;
    let (ok, out) = check(&f, "v9.9.2")?;
    assert!(!ok, "an unsigned annotated tag must be refused");
    assert!(out.contains("not signed"), "say why: {out}");
    Ok(())
}

#[test]
fn a_lightweight_tag_is_refused() -> Result<(), TestError> {
    let f = fixture()?;
    git(&f.root, &["tag", "v9.9.3"])?;
    let (ok, out) = check(&f, "v9.9.3")?;
    assert!(
        !ok,
        "a lightweight tag carries no signature and must be refused"
    );
    assert!(out.contains("lightweight"), "say why: {out}");
    Ok(())
}

#[test]
fn a_tag_signed_by_an_untrusted_key_is_refused() -> Result<(), TestError> {
    let f = fixture()?;
    signed_tag(&f, "v9.9.4", &f.untrusted.clone())?;
    let (ok, out) = check(&f, "v9.9.4")?;
    assert!(
        !ok,
        "a signature from a key not in allowed_signers must be refused"
    );
    assert!(out.contains("not a trusted"), "say why: {out}");
    Ok(())
}

/// The hook runs the check on every pushed `v*` tag, BEFORE the CI check, and
/// the trusted keys are committed rather than read from one machine.
#[test]
fn the_pre_push_gate_runs_the_check_on_every_v_tag_before_ci() -> Result<(), TestError> {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push"))
        .map_err(|e| format!("hook: {e}"))?;
    let check = hook
        .find("tag-signature-check.sh")
        .ok_or("pre-push runs scripts/tag-signature-check.sh")?;
    let ci = hook
        .find("checking CI ...")
        .ok_or("pre-push still checks CI for a tag")?;
    assert!(check < ci, "the signature is checked before the CI status");
    let signers = std::fs::read_to_string(repo().join(".github/allowed_signers"))
        .map_err(|e| format!(".github/allowed_signers lists the trusted release keys: {e}"))?;
    assert!(
        signers.lines().any(|l| l.contains("ssh-ed25519 ")),
        "allowed_signers names at least one key"
    );
    Ok(())
}

/// A `git` first on `PATH` that runs the real one, then prints 1 MiB, sixteen
/// times a pipe's capacity, after the two outputs the check searches: the tag
/// object and `verify-tag`'s verdict. Returns the directory holding it.
fn chatty_git(dir: &Path) -> Result<PathBuf, TestError> {
    let real = Command::new("sh")
        .args(["-c", "command -v git"])
        .output()
        .map_err(|e| format!("command -v git: {e}"))?;
    let real = String::from_utf8(real.stdout).map_err(|e| format!("utf8: {e}"))?;
    let bin = dir.join("chatty-bin");
    std::fs::create_dir(&bin).map_err(|e| format!("mkdir: {e}"))?;
    let wrapper = bin.join("git");
    executable::write_executable(
        &wrapper,
        &format!(
            "#!/bin/sh\n\
             '{}' \"$@\"\n\
             rc=$?\n\
             case \" $* \" in\n\
             *' cat-file -p '* | *' verify-tag '*)\n\
             \tdd if=/dev/zero bs=1048576 count=1 2>/dev/null | tr '\\0' x\n\
             \techo ;;\n\
             esac\n\
             exit $rc\n",
            real.trim()
        ),
    )
    .map_err(|e| format!("write wrapper: {e}"))?;
    Ok(bin)
}

/// The check reads git's output whole. Before 2026-11-08 it piped the tag
/// object and the `verify-tag` verdict into `grep -q` under `set -o pipefail`:
/// grep exited at the match, git (or printf) died of SIGPIPE while it still
/// had output, and a correctly signed tag was refused as "not signed".
#[test]
fn a_signed_tag_passes_when_git_prints_more_than_a_pipe_holds() -> Result<(), TestError> {
    let f = fixture()?;
    signed_tag(&f, "v9.9.5", &f.trusted.clone())?;
    let bin = chatty_git(f._dir.path())?;
    let (ok, out) = check_with(&f, "v9.9.5", &script(), Some(&bin))?;
    assert!(
        ok,
        "a signed tag must pass however much git prints: {}",
        &out[..out.len().min(600)]
    );
    Ok(())
}

/// The same tag through the check as it was at 47f2630b5 fails: the wrapper
/// above does induce the race the current check survives.
#[test]
fn the_pre_fix_check_refuses_that_tag() -> Result<(), TestError> {
    let f = fixture()?;
    signed_tag(&f, "v9.9.6", &f.trusted.clone())?;
    let bin = chatty_git(f._dir.path())?;
    let mut text = std::fs::read_to_string(script()).map_err(|e| format!("read: {e}"))?;
    for (new, old) in [
        (
            "if ! tag_object=$(git cat-file -p \"$sha\") \\\n\t|| ! grep -q -- '-----BEGIN SSH SIGNATURE-----' <<<\"$tag_object\"; then",
            "if ! git cat-file -p \"$sha\" | grep -q -- '-----BEGIN SSH SIGNATURE-----'; then",
        ),
        (
            "|| ! grep -q '^Good \"git\" signature for ' <<<\"$out\"; then",
            "|| ! printf '%s\\n' \"$out\" | grep -q '^Good \"git\" signature for '; then",
        ),
    ] {
        assert_eq!(
            text.matches(new).count(),
            1,
            "the check no longer has: {new}"
        );
        text = text.replace(new, old);
    }
    let old_script = f._dir.path().join("tag-signature-check-47f2630b5.sh");
    std::fs::write(&old_script, text).map_err(|e| format!("write: {e}"))?;
    let (ok, out) = check_with(&f, "v9.9.6", &old_script, Some(&bin))?;
    assert!(
        !ok,
        "the pre-fix check passed although git printed past a pipe's capacity"
    );
    assert!(
        out.contains("not signed"),
        "the old form refuses it as unsigned: {}",
        &out[..out.len().min(600)]
    );
    Ok(())
}
