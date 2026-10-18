// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! A push carries no unsigned commit.
//!
//! Branch protection on `main` requires signed commits, and GitHub enforces it
//! only at merge time: a pull request holding one unsigned commit sits BLOCKED
//! with every check green and no reason on the page. That happened to PR #333,
//! which carried four unsigned commits. `scripts/commit-signature-check.sh` is
//! the rule, and `.githooks/pre-push` runs it on git's pre-push lines before
//! any other gate, so the refusal arrives in seconds and names each commit.
//!
//! Every test builds a throwaway repository and signs with throwaway SSH keys
//! made by `ssh-keygen` in a temporary directory. Signing settings are written
//! to the throwaway repository's own config, never to the global one.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

/// What git sends for the missing side of a ref update.
const ZERO: &str = "0000000000000000000000000000000000000000";

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    repo().join("scripts/commit-signature-check.sh")
}

/// A `git` command in `dir`, with the variables a commit hook exports removed:
/// inherited, they point every git call here at the repository being committed
/// instead of the fixture.
fn git_cmd(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
    cmd
}

fn git(dir: &Path, args: &[&str]) -> Result<String, TestError> {
    let out = git_cmd(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git runs: {e}"))?;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(String::from_utf8(out.stdout)
        .map_err(|e| format!("utf8: {e}"))?
        .trim()
        .to_string())
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

/// A throwaway repository with one UNSIGNED base commit, a trusted key and an
/// untrusted one, and an allowed-signers file naming only the trusted key.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    trusted: PathBuf,
    untrusted: PathBuf,
    allowed: PathBuf,
    base: String,
}

fn fixture() -> Result<Fixture, TestError> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let root = dir.path().join("r");
    std::fs::create_dir(&root).map_err(|e| format!("mkdir: {e}"))?;
    git(&root, &["init", "-q", "-b", "main"])?;
    git(&root, &["config", "user.name", "Contributor"])?;
    git(&root, &["config", "user.email", "dev@example.invalid"])?;
    // Local overrides: an inherited `commit.gpgsign true` would sign the
    // commits these tests need unsigned, with the user's own key.
    git(&root, &["config", "commit.gpgsign", "false"])?;
    git(&root, &["config", "gpg.format", "ssh"])?;
    git(&root, &["commit", "-q", "--allow-empty", "-m", "base"])?;
    let base = git(&root, &["rev-parse", "HEAD"])?;
    let trusted = keygen(dir.path(), "trusted")?;
    let untrusted = keygen(dir.path(), "untrusted")?;
    let public = std::fs::read_to_string(trusted.with_extension("pub"))
        .map_err(|e| format!("pub key: {e}"))?;
    let allowed = dir.path().join("allowed_signers");
    std::fs::write(&allowed, format!("dev@example.invalid {public}"))
        .map_err(|e| format!("write: {e}"))?;
    git(
        &root,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            &allowed.display().to_string(),
        ],
    )?;
    Ok(Fixture {
        _dir: dir,
        root,
        trusted,
        untrusted,
        allowed,
        base,
    })
}

impl Fixture {
    /// Commit with a signature from `key`, returning the commit's sha.
    fn signed(&self, subject: &str, key: &Path) -> Result<String, TestError> {
        let pubkey = key.with_extension("pub");
        git(
            &self.root,
            &[
                "-c",
                &format!("user.signingkey={}", pubkey.display()),
                "commit",
                "-q",
                "-S",
                "--allow-empty",
                "-m",
                subject,
            ],
        )?;
        git(&self.root, &["rev-parse", "HEAD"])
    }

    fn unsigned(&self, subject: &str) -> Result<String, TestError> {
        git(
            &self.root,
            &[
                "commit",
                "-q",
                "--no-gpg-sign",
                "--allow-empty",
                "-m",
                subject,
            ],
        )?;
        git(&self.root, &["rev-parse", "HEAD"])
    }

    /// Pretend `sha` is what the remote's `main` already holds.
    fn on_remote(&self, sha: &str) -> Result<(), TestError> {
        git(&self.root, &["update-ref", "refs/remotes/origin/main", sha])?;
        Ok(())
    }
}

/// Run `cmd` with `stdin` as its standard input; (exit success, stdout+stderr).
fn run(mut cmd: Command, stdin: &str) -> Result<(bool, String), TestError> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    // A program that exits without reading its input closes the pipe early.
    // That is its verdict to report, not an error of this harness.
    match child
        .stdin
        .take()
        .ok_or("stdin is piped")?
        .write_all(stdin.as_bytes())
    {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            return Err(format!("write stdin: {e}").into());
        }
        _ => {}
    }
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    Ok((
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

/// Feed `lines` (git's pre-push stdin) to the check inside the fixture.
fn check(f: &Fixture, lines: &str) -> Result<(bool, String), TestError> {
    let mut cmd = Command::new("bash");
    cmd.arg(script())
        .current_dir(&f.root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env("SIPNAB_ALLOWED_SIGNERS", &f.allowed);
    run(cmd, lines)
}

/// One pre-push line for `refs/heads/<branch>`.
fn line(branch: &str, local: &str, remote: &str) -> String {
    format!("refs/heads/{branch} {local} refs/heads/{branch} {remote}\n")
}

fn short(sha: &str) -> &str {
    &sha[..7]
}

#[test]
fn an_update_whose_commits_are_all_signed_by_a_trusted_key_passes() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    f.signed("one", &f.trusted)?;
    let tip = f.signed("two", &f.trusted)?;
    let (ok, out) = check(&f, &line("main", &tip, &f.base))?;
    assert!(
        ok,
        "two trusted signatures above the remote must pass: {out}"
    );
    Ok(())
}

#[test]
fn every_unsigned_commit_is_refused_by_name_with_the_fix() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let first = f.unsigned("first unsigned")?;
    f.signed("signed between", &f.trusted)?;
    let second = f.unsigned("second unsigned")?;
    let (ok, out) = check(&f, &line("main", &second, &f.base))?;
    assert!(
        !ok,
        "a range holding unsigned commits must be refused: {out}"
    );
    for (sha, subject) in [(&first, "first unsigned"), (&second, "second unsigned")] {
        let named = out
            .lines()
            .any(|l| l.contains(short(sha)) && l.contains(subject) && l.contains("not signed"));
        assert!(
            named,
            "name {} ({subject}) as not signed: {out}",
            short(sha)
        );
    }
    assert!(
        out.contains("git commit --amend -S"),
        "say how to re-sign the last commit: {out}"
    );
    assert!(
        out.contains("git rebase --exec 'git commit --amend --no-edit -S'"),
        "say how to re-sign a range: {out}"
    );
    Ok(())
}

#[test]
fn an_update_checks_only_the_commits_it_adds() -> Result<(), TestError> {
    let f = fixture()?;
    // The base is unsigned and already on the remote: not this push's doing.
    let tip = f.signed("on top", &f.trusted)?;
    let (ok, out) = check(&f, &line("main", &tip, &f.base))?;
    assert!(
        ok,
        "the remote's own unsigned base is outside the range: {out}"
    );
    assert!(
        !out.contains(short(&f.base)),
        "the base is not named: {out}"
    );
    Ok(())
}

#[test]
fn a_new_branch_checks_only_commits_no_remote_branch_has() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let tip = f.signed("feature", &f.trusted)?;
    let (ok, out) = check(&f, &line("feature", &tip, ZERO))?;
    assert!(
        ok,
        "a new branch whose only new commit is signed must pass, although the \
         remote's base is unsigned: {out}"
    );

    let bad = f.unsigned("feature, unsigned")?;
    let (ok, out) = check(&f, &line("feature", &bad, ZERO))?;
    assert!(
        !ok,
        "a new branch carrying an unsigned commit is refused: {out}"
    );
    assert!(out.contains(short(&bad)), "name the new commit: {out}");
    assert!(
        !out.contains(short(&f.base)),
        "a commit a remote branch already has is not this push's: {out}"
    );
    Ok(())
}

/// A branch rebased onto a main that gained commits, then force-pushed. The
/// update line carries the branch's OLD remote sha, so `<remote>..<local>`
/// spans everything main gained since the old base. Those commits are already
/// on the remote (a squash merge GitHub signs with a key this machine cannot
/// check reads as `E`), so only the branch's own commits are this push's.
#[test]
fn a_rebased_branch_checks_only_its_own_commits() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    git(&f.root, &["checkout", "-q", "-b", "topic"])?;
    let old_tip = f.signed("topic, first version", &f.trusted)?;
    git(
        &f.root,
        &["update-ref", "refs/remotes/origin/topic", &old_tip],
    )?;

    // main gains commits this machine cannot call good: one unsigned, one
    // whose signature no longer verifies.
    git(&f.root, &["checkout", "-q", "main"])?;
    let gained = f.unsigned("merged on main, unsigned")?;
    let signed = f.signed("merged on main, altered", &f.trusted)?;
    let raw = git(&f.root, &["cat-file", "commit", &signed])?;
    let altered = format!("{}\n", raw.replace("merged on main, altered", "altered"));
    let mut cmd = git_cmd(&f.root);
    cmd.args(["hash-object", "-t", "commit", "-w", "--stdin"]);
    let (ok, bad_sig) = run(cmd, &altered)?;
    assert!(ok, "hash-object: {bad_sig}");
    let bad_sig = bad_sig.trim().to_string();
    git(
        &f.root,
        &["update-ref", "refs/remotes/origin/main", &bad_sig],
    )?;

    // The branch is rebased onto the new main and re-signed.
    git(&f.root, &["checkout", "-q", "-B", "topic", &bad_sig])?;
    let new_tip = f.signed("topic, rebased", &f.trusted)?;

    let (ok, out) = check(&f, &line("topic", &new_tip, &old_tip))?;
    assert!(
        ok,
        "main's commits are already on the remote, so they are not this \
         push's to sign: {out}"
    );
    for sha in [&gained, &bad_sig] {
        assert!(!out.contains(short(sha)), "{} is main's: {out}", short(sha));
    }

    // The branch's own commits are still checked.
    let own = f.unsigned("topic, unsigned follow-up")?;
    let (ok, out) = check(&f, &line("topic", &own, &old_tip))?;
    assert!(!ok, "the branch's own unsigned commit is refused: {out}");
    assert!(out.contains(short(&own)), "name it: {out}");
    assert!(
        !out.contains(short(&gained)) && !out.contains(short(&bad_sig)),
        "and only it: {out}"
    );
    Ok(())
}

#[test]
fn a_deleted_ref_checks_nothing() -> Result<(), TestError> {
    let f = fixture()?;
    let (ok, out) = check(&f, &line("gone", ZERO, &f.base))?;
    assert!(ok, "deleting a ref pushes no commit: {out}");
    Ok(())
}

#[test]
fn one_bad_ref_among_several_refuses_the_push() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let good = f.signed("good", &f.trusted)?;
    git(&f.root, &["checkout", "-q", "-b", "other", &f.base])?;
    let bad = f.unsigned("bad")?;
    let lines = format!(
        "{}{}",
        line("main", &good, &f.base),
        line("other", &bad, ZERO)
    );
    let (ok, out) = check(&f, &lines)?;
    assert!(
        !ok,
        "the second ref's unsigned commit refuses the push: {out}"
    );
    assert!(out.contains(short(&bad)), "name it: {out}");
    Ok(())
}

/// `%G?` is `U` for a signature that verifies against a key the
/// allowed-signers file does not list. GitHub, not that file, decides whether
/// the key belongs to the committer, so the check lets it through and says so.
#[test]
fn a_good_signature_from_an_unlisted_key_passes_and_says_so() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let tip = f.signed("outside key", &f.untrusted)?;
    let (ok, out) = check(&f, &line("main", &tip, &f.base))?;
    assert!(ok, "a valid signature from an unlisted key passes: {out}");
    assert!(
        out.lines()
            .any(|l| l.contains(short(&tip)) && l.contains("not in")),
        "say the key is not in the allowed-signers file: {out}"
    );
    Ok(())
}

/// `%G?` is `B` when the signed content was altered after signing.
#[test]
fn a_signature_that_does_not_verify_is_refused() -> Result<(), TestError> {
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let signed = f.signed("original", &f.trusted)?;
    let raw = git(&f.root, &["cat-file", "commit", &signed])?;
    let altered = format!("{}\n", raw.replace("original", "altered"));
    let mut cmd = git_cmd(&f.root);
    cmd.args(["hash-object", "-t", "commit", "-w", "--stdin"]);
    let (ok, sha) = run(cmd, &altered)?;
    assert!(ok, "hash-object: {sha}");
    let sha = sha.trim().to_string();
    let (ok, out) = check(&f, &line("main", &sha, &f.base))?;
    assert!(!ok, "a bad signature must be refused: {out}");
    assert!(
        out.lines()
            .any(|l| l.contains(short(&sha)) && l.contains("bad signature")),
        "say the signature is bad: {out}"
    );
    Ok(())
}

/// The shipped hook, run for real inside the fixture. `cargo` is left off
/// `PATH` on purpose: the signature gate comes before every cargo gate, so a
/// signed push reaches "cargo not found" and an unsigned one never does.
fn hook(f: &Fixture, lines: &str) -> Result<(bool, String), TestError> {
    let mut cmd = Command::new("/bin/sh");
    cmd.arg(repo().join(".githooks/pre-push"))
        .arg("origin")
        .arg("https://example.invalid/r.git")
        .current_dir(&f.root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("SKIP_FMT_HOOK")
        .env("PATH", "/usr/bin:/bin")
        .env("SIPNAB_HOOK_ANY_TREE", "1")
        .env("SIPNAB_ALLOWED_SIGNERS", &f.allowed);
    run(cmd, lines)
}

#[test]
fn the_pre_push_hook_refuses_an_unsigned_commit_before_any_cargo_gate() -> Result<(), TestError> {
    assert!(
        !Path::new("/usr/bin/cargo").exists() && !Path::new("/bin/cargo").exists(),
        "this test needs a PATH without cargo; /usr/bin or /bin has one"
    );
    let f = fixture()?;
    f.on_remote(&f.base)?;
    let bad = f.unsigned("unsigned via hook")?;
    let (ok, out) = hook(&f, &line("main", &bad, &f.base))?;
    assert!(!ok, "the hook must refuse: {out}");
    assert!(
        out.contains(short(&bad)) && out.contains("not signed"),
        "the hook names the unsigned commit: {out}"
    );
    assert!(
        !out.contains("cargo not found"),
        "the signature gate runs before cargo is even looked for: {out}"
    );

    git(&f.root, &["reset", "-q", "--hard", &f.base])?;
    let good = f.signed("signed via hook", &f.trusted)?;
    let (ok, out) = hook(&f, &line("main", &good, &f.base))?;
    assert!(!ok, "with no cargo the hook still stops, later: {out}");
    assert!(
        out.contains("cargo not found"),
        "a signed push passes the signature gate and reaches the cargo check: {out}"
    );
    Ok(())
}
