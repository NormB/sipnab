// SPDX-License-Identifier: MIT OR Apache-2.0
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

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    repo().join("scripts/tag-signature-check.sh")
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn keygen(dir: &Path, name: &str) -> PathBuf {
    let key = dir.join(name);
    let out = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
        .arg(&key)
        .output()
        .expect("ssh-keygen runs");
    assert!(out.status.success(), "ssh-keygen failed");
    key
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

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("r");
    std::fs::create_dir(&root).expect("mkdir");
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.name", "Release Bot"]);
    git(&root, &["config", "user.email", "release@example.invalid"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    git(&root, &["config", "tag.gpgSign", "false"]);
    git(&root, &["config", "gpg.format", "ssh"]);
    git(&root, &["commit", "-q", "--allow-empty", "-m", "base"]);
    let trusted = keygen(dir.path(), "trusted");
    let untrusted = keygen(dir.path(), "untrusted");
    let public = std::fs::read_to_string(trusted.with_extension("pub")).expect("pub key");
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(&allowed, format!("release@example.invalid {public}")).expect("write");
    Fixture {
        _dir: dir,
        root,
        trusted,
        untrusted,
        allowed,
    }
}

fn check(f: &Fixture, tag: &str) -> (bool, String) {
    let sha = String::from_utf8(
        Command::new("git")
            .current_dir(&f.root)
            .args(["rev-parse", tag])
            .output()
            .expect("rev-parse")
            .stdout,
    )
    .expect("utf8");
    let out = Command::new("bash")
        .arg(script())
        .arg(sha.trim())
        .current_dir(&f.root)
        .env("SIPNAB_ALLOWED_SIGNERS", &f.allowed)
        .output()
        .expect("script runs");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn signed_tag(f: &Fixture, name: &str, key: &Path) {
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
    );
}

#[test]
fn a_tag_signed_by_a_trusted_key_passes() {
    let f = fixture();
    signed_tag(&f, "v9.9.1", &f.trusted.clone());
    let (ok, out) = check(&f, "v9.9.1");
    assert!(ok, "a tag signed by the trusted key must pass: {out}");
}

#[test]
fn an_unsigned_annotated_tag_is_refused() {
    let f = fixture();
    git(&f.root, &["tag", "-a", "-m", "release", "v9.9.2"]);
    let (ok, out) = check(&f, "v9.9.2");
    assert!(!ok, "an unsigned annotated tag must be refused");
    assert!(out.contains("not signed"), "say why: {out}");
}

#[test]
fn a_lightweight_tag_is_refused() {
    let f = fixture();
    git(&f.root, &["tag", "v9.9.3"]);
    let (ok, out) = check(&f, "v9.9.3");
    assert!(
        !ok,
        "a lightweight tag carries no signature and must be refused"
    );
    assert!(out.contains("lightweight"), "say why: {out}");
}

#[test]
fn a_tag_signed_by_an_untrusted_key_is_refused() {
    let f = fixture();
    signed_tag(&f, "v9.9.4", &f.untrusted.clone());
    let (ok, out) = check(&f, "v9.9.4");
    assert!(
        !ok,
        "a signature from a key not in allowed_signers must be refused"
    );
    assert!(out.contains("not a trusted"), "say why: {out}");
}

/// The hook runs the check on every pushed `v*` tag, BEFORE the CI check, and
/// the trusted keys are committed rather than read from one machine.
#[test]
fn the_pre_push_gate_runs_the_check_on_every_v_tag_before_ci() {
    let hook = std::fs::read_to_string(repo().join(".githooks/pre-push")).expect("hook");
    let check = hook
        .find("tag-signature-check.sh")
        .expect("pre-push runs scripts/tag-signature-check.sh");
    let ci = hook
        .find("checking CI ...")
        .expect("pre-push still checks CI for a tag");
    assert!(check < ci, "the signature is checked before the CI status");
    let signers = std::fs::read_to_string(repo().join(".github/allowed_signers"))
        .expect(".github/allowed_signers lists the trusted release keys");
    assert!(
        signers.lines().any(|l| l.contains("ssh-ed25519 ")),
        "allowed_signers names at least one key"
    );
}
