// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! `sipnab g729 install` started as root downloads and unpacks the package
//! as another user (G729-INSTALL-DOWNLOADS-AS-ROOT).
//!
//! No test here reaches a network. Every run names `SSL_CERT_FILE`: a file
//! of the test's user with mode 0000 in a directory every user can search.
//! The download reads its trust roots before it resolves or connects, so
//! every run ends there. Root reads the file and finds no certificate in
//! it; any other user is refused reading it. The two messages differ, so
//! they say which user the download ran as.
//!
//! The as-root runs go through `sudo -n`, tied to this test process
//! (tests/support/root_run.rs), each bounded by [`RUN_LIMIT`]. Without
//! passwordless sudo they say so on stderr and pass.
#![cfg(all(unix, feature = "g729"))]

#[path = "support/root_run.rs"]
mod root_run;

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

type TestError = Box<dyn std::error::Error>;

/// The longest one run may take before it is stopped. A run here makes no
/// connection, so it ends in well under a second on an idle host.
const RUN_LIMIT: Duration = Duration::from_secs(120);

/// The sipnab binary under test.
const SIPNAB: &str = env!("CARGO_BIN_EXE_sipnab");

/// What the download prints when its trust roots cannot be read: the
/// refusal of a user that is not root.
const DENIED: &str = "Permission denied";

/// What the download prints when its trust roots hold no certificate: the
/// file was read, so by root.
const NO_CERTIFICATE: &str = "no certificate in this file";

/// The files one run reads and writes, removed when it drops.
struct Scene {
    /// Holds the CA file: mode 0755, so every user can search it.
    _ca_dir: tempfile::TempDir,
    /// The CA file: the test user's, mode 0000, holding no certificate.
    ca_file: PathBuf,
    /// TMPDIR: the test user's, mode 0700.
    tmp: tempfile::TempDir,
    /// Where the table file would go.
    tables: tempfile::TempDir,
}

impl Scene {
    fn new() -> Result<Self, TestError> {
        let ca_dir = tempfile::Builder::new()
            .prefix("sipnab-g729-drop-ca-")
            .tempdir()?;
        std::fs::set_permissions(ca_dir.path(), std::fs::Permissions::from_mode(0o755))?;
        let ca_file = ca_dir.path().join("no-certificate.pem");
        std::fs::write(&ca_file, b"not a certificate\n")?;
        std::fs::set_permissions(&ca_file, std::fs::Permissions::from_mode(0o000))?;
        let tmp = tempfile::Builder::new()
            .prefix("sipnab-g729-drop-tmp-")
            .tempdir()?;
        let tables = tempfile::Builder::new()
            .prefix("sipnab-g729-drop-tables-")
            .tempdir()?;
        Ok(Self {
            _ca_dir: ca_dir,
            ca_file,
            tmp,
            tables,
        })
    }

    fn table_file(&self) -> PathBuf {
        self.tables.path().join("g729-tables.bin")
    }

    /// The environment every run gets, through `env`, since `sudo` resets
    /// the caller's.
    fn env_args(&self) -> Vec<String> {
        vec![
            "env".into(),
            format!("TMPDIR={}", self.tmp.path().display()),
            format!("SSL_CERT_FILE={}", self.ca_file.display()),
        ]
    }

    /// `sipnab g729 install --yes --no-config` with `extra`, the table file
    /// in this scene.
    fn install_args(&self, extra: &[&str]) -> Vec<String> {
        let mut args = self.env_args();
        args.push(SIPNAB.into());
        args.extend(
            ["g729", "install", "--yes", "--no-config", "--g729-tables"]
                .iter()
                .map(|s| (*s).to_string()),
        );
        args.push(self.table_file().display().to_string());
        args.extend(extra.iter().map(|s| (*s).to_string()));
        args
    }

    fn tmp_entries(&self) -> Result<usize, TestError> {
        Ok(std::fs::read_dir(self.tmp.path())?.count())
    }
}

/// This process's user name.
fn me() -> Result<String, TestError> {
    // SAFETY: getpwuid returns a pointer into static storage or null; the
    // name is copied out before any other call that could reuse it.
    let name = unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() {
            return Err("this user has no password entry".into());
        }
        std::ffi::CStr::from_ptr((*entry).pw_name)
            .to_string_lossy()
            .into_owned()
    };
    Ok(name)
}

/// Whether passwordless sudo works here.
fn sudo_available() -> bool {
    root_run::sudo()
        .and_then(|mut sudo| sudo.arg("true").stdout(Stdio::null()).status())
        .is_ok_and(|s| s.success())
}

/// Say on stderr that `test` did not run, and why.
fn skipped(test: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "NOTICE: `{test}` did NOT run: no passwordless sudo here."
    );
}

/// Run `cmd`, in a process group of its own, for at most [`RUN_LIMIT`].
///
/// Standard input is the caller's choice: a command from
/// [`root_run::sudo`] reads the tie's pipe there, and replacing it with
/// `/dev/null` ends the run at once with SIGTERM.
///
/// # Errors
///
/// The run could not start, or it was still running at the limit; it is
/// then sent SIGTERM (which `sudo` relays) and the error says so.
fn bounded(mut cmd: Command) -> Result<Output, TestError> {
    use std::os::unix::process::CommandExt as _;
    let mut child = cmd
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .tied_to_test()
        .spawn()?;
    let deadline = Instant::now() + RUN_LIMIT;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            let pid = libc::pid_t::try_from(child.id())?;
            // SAFETY: kill(2) on the process this test spawned and has not
            // reaped, so the pid cannot have been reused.
            let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
            let _ = child.wait_with_output();
            return Err(format!("the run was still going after {RUN_LIMIT:?}; stopped").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(child.wait_with_output()?)
}

/// Run `args` as root.
fn as_root(args: &[String]) -> Result<Output, TestError> {
    let mut sudo = root_run::sudo()?;
    sudo.args(args);
    bounded(sudo)
}

/// Run `args` as this user.
fn as_me(args: &[String]) -> Result<Output, TestError> {
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]).stdin(Stdio::null());
    bounded(cmd)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Success: started as root with `--user`, the download runs as that user:
/// it cannot read the CA file root could read, and nothing is installed.
#[test]
fn a_root_install_downloads_as_the_named_user() -> Result<(), TestError> {
    if !sudo_available() {
        skipped("a_root_install_downloads_as_the_named_user");
        return Ok(());
    }
    let scene = Scene::new()?;
    let user = me()?;
    let out = as_root(&scene.install_args(&["--user", &user]))?;
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(1),
        "fails at the trust roots: {stdout}{stderr}"
    );
    assert!(
        stdout.contains(&format!("as user '{user}'")),
        "the progress line names the user: {stdout}"
    );
    assert!(
        stderr.contains(DENIED),
        "the download is not root: {stderr}"
    );
    assert!(
        !stderr.contains(NO_CERTIFICATE),
        "root did not read the CA file: {stderr}"
    );
    assert!(
        stderr.contains(&format!("the download as user '{user}' failed (exit 1)")),
        "the parent reports the child: {stderr}"
    );
    assert!(!scene.table_file().exists(), "nothing installed");
    assert_eq!(scene.tmp_entries()?, 0, "the work directory is gone");
    Ok(())
}

/// Failure: started as root, a TMPDIR the drop user cannot write in is
/// refused before the child starts, in the words of every dropping
/// command, offering the sudo user who can.
#[test]
fn a_root_install_refuses_a_tmpdir_nobody_cannot_write() -> Result<(), TestError> {
    if !sudo_available() {
        skipped("a_root_install_refuses_a_tmpdir_nobody_cannot_write");
        return Ok(());
    }
    let scene = Scene::new()?;
    let user = me()?;
    let out = as_root(&scene.install_args(&["--user", "nobody"]))?;
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "refused: {stderr}");
    assert!(
        stderr.contains("runs as user 'nobody', and 'nobody' cannot write in"),
        "the drop refusal: {stderr}"
    );
    assert!(stderr.contains("(TMPDIR)"), "names the setting: {stderr}");
    assert!(
        stderr.contains(&format!("run it with --user {user}, who can")),
        "offers the sudo user: {stderr}"
    );
    assert!(!stderr.contains(DENIED), "no child started: {stderr}");
    assert!(!scene.table_file().exists(), "nothing installed");
    assert_eq!(scene.tmp_entries()?, 0, "nothing made in TMPDIR");
    Ok(())
}

/// Success: `--no-priv-drop` downloads as root, as before, and says so.
#[test]
fn no_priv_drop_downloads_as_root_with_a_warning() -> Result<(), TestError> {
    if !sudo_available() {
        skipped("no_priv_drop_downloads_as_root_with_a_warning");
        return Ok(());
    }
    let scene = Scene::new()?;
    let out = as_root(&scene.install_args(&["--no-priv-drop"]))?;
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(
        out.status.code(),
        Some(1),
        "fails at the trust roots: {stdout}{stderr}"
    );
    assert!(
        stderr.contains("running as root because --no-priv-drop was given"),
        "the warning: {stderr}"
    );
    assert!(
        stderr.contains(NO_CERTIFICATE),
        "root read the CA file: {stderr}"
    );
    assert!(!stdout.contains("as user '"), "no child: {stdout}");
    assert_eq!(scene.tmp_entries()?, 0, "the work directory is gone");
    Ok(())
}

/// Failure: the hidden child command refuses to start as root.
#[test]
fn the_child_command_refuses_root() -> Result<(), TestError> {
    if !sudo_available() {
        skipped("the_child_command_refuses_root");
        return Ok(());
    }
    let scene = Scene::new()?;
    let mut args = scene.env_args();
    args.extend(
        [SIPNAB, "g729", "internal-fetch", "--as-user=nobody"]
            .iter()
            .map(|s| (*s).to_string()),
    );
    let out = as_root(&args)?;
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "refused: {stderr}");
    assert!(
        stderr.contains("refused: started as root"),
        "says why: {stderr}"
    );
    assert!(out.stdout.is_empty(), "nothing sent");
    assert_eq!(scene.tmp_entries()?, 0, "nothing made in TMPDIR");
    Ok(())
}

/// Failure: run by hand as a user, the child command stops at the trust
/// roots it cannot read, sends nothing, and leaves no work directory.
#[test]
fn the_child_command_sends_nothing_when_it_fails() -> Result<(), TestError> {
    let scene = Scene::new()?;
    let user = me()?;
    let mut args = scene.env_args();
    args.extend([
        SIPNAB.to_string(),
        "g729".into(),
        "internal-fetch".into(),
        format!("--as-user={user}"),
    ]);
    let out = as_me(&args)?;
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "failed: {stderr}");
    assert!(stderr.contains(DENIED), "the CA file: {stderr}");
    assert!(out.stdout.is_empty(), "nothing sent");
    assert_eq!(scene.tmp_entries()?, 0, "the work directory is gone");
    Ok(())
}

/// Edge: the child command in a TMPDIR it cannot write in refuses in the
/// words of every dropping command, before the download.
#[test]
fn the_child_command_refuses_an_unwritable_tmpdir() -> Result<(), TestError> {
    if root_run_is_root() {
        return Ok(());
    }
    let scene = Scene::new()?;
    std::fs::set_permissions(scene.tmp.path(), std::fs::Permissions::from_mode(0o500))?;
    let mut args = scene.env_args();
    args.extend(
        [SIPNAB, "g729", "internal-fetch", "--as-user=svc"]
            .iter()
            .map(|s| (*s).to_string()),
    );
    let out = as_me(&args);
    std::fs::set_permissions(scene.tmp.path(), std::fs::Permissions::from_mode(0o700))?;
    let out = out?;
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "refused: {stderr}");
    assert!(
        stderr.contains("runs as user 'svc'"),
        "the refusal: {stderr}"
    );
    assert!(!stderr.contains(DENIED), "no download: {stderr}");
    Ok(())
}

/// Edge: `install --help` lists the two new flags and not the child command.
#[test]
fn the_help_lists_the_flags_and_hides_the_child() -> Result<(), TestError> {
    let out = as_me(&[
        SIPNAB.to_string(),
        "g729".into(),
        "install".into(),
        "--help".into(),
    ])?;
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "help: {stdout}");
    assert!(stdout.contains("--user <USER>"), "--user: {stdout}");
    assert!(
        stdout.contains("--no-priv-drop"),
        "--no-priv-drop: {stdout}"
    );
    let out = as_me(&[SIPNAB.to_string(), "g729".into(), "--help".into()])?;
    let stdout = text(&out.stdout);
    assert!(!stdout.contains("internal-fetch"), "hidden: {stdout}");
    Ok(())
}

/// Whether this test process is root.
fn root_run_is_root() -> bool {
    // SAFETY: geteuid cannot fail and touches no memory.
    unsafe { libc::geteuid() == 0 }
}

include!("support/child_lifetime.rs");
