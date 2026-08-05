// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the privilege drop actually *does*, observed from the process it was
//! performed on.
//!
//! `src/privilege.rs` runs once, in the gap between "the capture handle is
//! open" and "the first attacker-controlled byte is parsed". Everything after
//! that call inherits whatever authority the call left behind, so the failure
//! that matters here is not a crash — it is a drop that returns `Ok` having
//! done less than it claimed. Nothing downstream would notice: the packets
//! still decode, the TUI still draws, and the only difference is that a bug in
//! the SIP parser now runs as root.
//!
//! That shape of defect is invisible to a test that checks a return value, so
//! the gates below read the process's own credentials back out of the kernel
//! after the call — `getuid`/`getgid`/`geteuid`/`getegid`, `getgroups`,
//! `PR_GET_NO_NEW_PRIVS`, `PR_GET_DUMPABLE` — and, for `chroot`, ask whether
//! the real root filesystem is still reachable.
//!
//! **Why so much of this runs in a child process.** A process cannot
//! demonstrate shedding a privilege it never had, so the interesting gates
//! need root; and a test runner that has dropped to `nobody`, chrooted into a
//! temp directory or turned off its own dumpability would poison every test
//! after it. Each root-requiring assertion therefore lives in an `#[ignore]`d
//! *child role* which a parent test spawns — under `sudo -n` when the runner
//! is unprivileged, directly when it is already root. Where neither is
//! possible the parent announces the skip on the real stderr and returns; it
//! never passes quietly.
//!
//! A user namespace is deliberately not used to fake root. Inside one only the
//! single mapped uid exists, so `setuid()` to `nobody` returns EINVAL and the
//! "the drop really happened" gate could never pass there. Reporting that as a
//! failure would be a lie about this code, so namespace root is detected and
//! reported as a skip.

#![cfg(all(unix, feature = "native"))]

use std::io::Write as _;
use std::process::{Command, Output};

/// Set by a parent on every child role it spawns. A child that finds it unset
/// was started by hand (`--include-ignored`) and must not change the
/// credentials of whatever process is hosting it.
const CHILD_ENV: &str = "SIPNAB_PRIVILEGE_DROP_CHILD";

/// Carries the parent-created directory that a chroot child confines itself to.
const CHROOT_DIR_ENV: &str = "SIPNAB_PRIVILEGE_CHROOT_DIR";

/// File the parent places inside that directory; its visibility at `/` is what
/// proves the new root took effect.
const CHROOT_MARKER: &str = "sipnab-chroot-marker";

/// Printed by a child role only after every one of its assertions has passed.
///
/// The parent requires it, and that requirement is load-bearing: without it a
/// child that took an early return would still exit 0, and the parent would
/// read that silence as proof — a gate that cannot fail.
const CHILD_COMPLETE: &str = "sipnab-privilege-child-complete";

/// Announce a skipped gate on this process's real stderr.
///
/// NOT `eprintln!`. libtest swaps the print machinery's sink per test and
/// throws the buffer away when the test passes, so a skip announced that way
/// is emitted and read by nobody — see `tests/support/corpus.rs`, where
/// exactly that left nine binaries reporting `ok` while proving nothing.
fn announce_skip(test: &str, reason: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "NOTICE: privilege gate `{test}` did NOT run — {reason}."
    );
}

/// True when passwordless sudo (`sudo -n true`) works in this environment.
///
/// # Side effects
/// Spawns `sudo -n true` as a probe.
fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Copy the fixture somewhere a dropped-privilege process can read it
/// (the repo may live under a 0700 home directory).
///
/// `tag` makes the destination unique per test: the two tests here run
/// in parallel (cargo's default), so a shared fixed path would let one
/// test's `fs::copy` truncate the file mid-read of the other, surfacing
/// as a spurious "truncated dump file" abort.
///
/// # Returns
/// Path to the copied fixture in the system temp directory.
///
/// # Side effects
/// Writes `sipnab-priv-guard-<tag>.pcap` into the system temp directory.
fn world_readable_fixture(tag: &str) -> std::path::PathBuf {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let dst = std::env::temp_dir().join(format!("sipnab-priv-guard-{tag}.pcap"));
    std::fs::copy(src, &dst).expect("copy fixture to temp");
    dst
}

/// This process's `(uid, gid, euid, egid)`.
fn credentials() -> (u32, u32, u32, u32) {
    // SAFETY: all four are read-only syscalls that cannot fail.
    unsafe {
        (
            libc::getuid(),
            libc::getgid(),
            libc::geteuid(),
            libc::getegid(),
        )
    }
}

/// Whether uid 0 here is the real thing rather than a user-namespace root.
///
/// The two are indistinguishable to `geteuid()` and behave completely
/// differently: in a namespace only the mapped uid exists, so `setuid()` to
/// any other account returns EINVAL and the drop can never complete.
///
/// # Returns
/// `Ok(())` for the initial user namespace, `Err(reason)` otherwise.
#[cfg(target_os = "linux")]
fn in_initial_user_namespace() -> Result<(), String> {
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(map) if map.split_whitespace().eq(["0", "0", "4294967295"]) => Ok(()),
        Ok(map) => Err(format!(
            "uid 0 here is a user-namespace root (uid_map: {:?}), where setuid() \
             to an unmapped account returns EINVAL",
            map.trim()
        )),
        Err(e) => Err(format!(
            "cannot read /proc/self/uid_map to tell real root from namespace root: {e}"
        )),
    }
}

/// Elsewhere there is no `/proc/self/uid_map` to consult, and no user
/// namespaces to be fooled by; uid 0 is uid 0.
#[cfg(not(target_os = "linux"))]
fn in_initial_user_namespace() -> Result<(), String> {
    Ok(())
}

/// Build the command that runs one `#[ignore]`d child role as root.
///
/// Already root: run the binary directly. Otherwise elevate with `sudo -n`,
/// via `env` because sudo's `env_reset` discards inherited variables and
/// refuses bare `VAR=value` assignments on most sudoers configurations —
/// `env` is a program sudo is happy to run, and it sets the variables itself.
///
/// # Returns
/// The prepared `Command`, or `Err(reason)` when this runner cannot reach root
/// at all.
fn root_child_command(role: &str, env: &[(&str, &std::ffi::OsStr)]) -> Result<Command, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate this binary: {e}"))?;
    let args = [
        role,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ];

    if credentials().2 == 0 {
        in_initial_user_namespace()?;
        let mut cmd = Command::new(exe);
        cmd.args(args).env(CHILD_ENV, "1");
        for (k, v) in env {
            cmd.env(k, v);
        }
        return Ok(cmd);
    }

    if !sudo_available() {
        return Err(
            "this runner is unprivileged and passwordless sudo is not available, so \
             no process here can shed a privilege it never had"
                .to_string(),
        );
    }
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "env"]);
    cmd.arg(format!("{CHILD_ENV}=1"));
    for (k, v) in env {
        let mut assignment = std::ffi::OsString::from(format!("{k}="));
        assignment.push(v);
        cmd.arg(assignment);
    }
    cmd.arg(exe).args(args);
    Ok(cmd)
}

/// Run a root child role and require that it ran to completion.
///
/// # Returns
/// `false` when the role could not be run at all (already announced as a
/// skip); `true` when it ran and every assertion in it passed.
fn root_child_passes(parent: &str, role: &str, env: &[(&str, &std::ffi::OsStr)]) -> bool {
    let mut cmd = match root_child_command(role, env) {
        Ok(c) => c,
        Err(reason) => {
            announce_skip(parent, &reason);
            return false;
        }
    };
    let out: Output = cmd.output().expect("spawn the child role");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "child role `{role}` exited {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code()
    );
    assert!(
        stdout.contains(CHILD_COMPLETE),
        "child role `{role}` exited 0 without reaching its completion marker, so \
         its assertions did not all run\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
    true
}

/// Refuse to run a child role that no parent spawned.
///
/// # Returns
/// `true` when the caller may proceed.
fn spawned_by_parent(role: &str) -> bool {
    if std::env::var_os(CHILD_ENV).is_some() {
        return true;
    }
    announce_skip(
        role,
        "it is a child role and no parent spawned it; running it here would change \
         the credentials of this whole test binary",
    );
    false
}

/// Look up an account's uid and primary gid, failing loudly when it is absent.
fn account_ids(name: &str) -> (u32, u32) {
    let c = std::ffi::CString::new(name).expect("account name has no null byte");
    // SAFETY: getpwnam returns a pointer into a static buffer valid until the
    // next passwd-database call; the two scalar fields are copied out
    // immediately, before anything else can touch it.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        assert!(!pw.is_null(), "account '{name}' must exist on this system");
        ((*pw).pw_uid, (*pw).pw_gid)
    }
}

// ── End-to-end: the binary's behaviour around the drop ────────────────────

/// Running as root with `--user` naming a nonexistent account exits non-zero
/// with "Failed to drop privileges" — never continues capturing as root.
#[test]
fn failed_privilege_drop_aborts_instead_of_running_as_root() {
    if !sudo_available() {
        announce_skip(
            "failed_privilege_drop_aborts_instead_of_running_as_root",
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return;
    }
    let fixture = world_readable_fixture("drop-fail");
    let out = Command::new("sudo")
        .args([
            "-n",
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().unwrap(),
            "--user",
            "no-such-user-sipnab-guard",
        ])
        .output()
        .expect("spawn sipnab under sudo");
    assert!(
        !out.status.success(),
        "a failed privilege drop must abort the process, not continue as root"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to drop privileges"),
        "abort must say why, got:\n{stderr}"
    );
}

/// Root dropping to `nobody` still reads and processes the fixture, exiting 0.
#[test]
fn successful_privilege_drop_still_processes_capture() {
    if !sudo_available() {
        announce_skip(
            "successful_privilege_drop_still_processes_capture",
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return;
    }
    let fixture = world_readable_fixture("drop-success");
    let out = Command::new("sudo")
        .args([
            "-n",
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().unwrap(),
            "--user",
            "nobody",
        ])
        .output()
        .expect("spawn sipnab under sudo");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "root -> drop to nobody -> read fixture must succeed, got:\n{stderr}"
    );
}

// ── What the drop does to the process that performed it ───────────────────

/// The drop moves all four credentials to the target account, clears the
/// supplementary groups, and leaves no way back.
///
/// The real/effective split is why this is several assertions and not one. The
/// kernel decides what is permitted from the EFFECTIVE ids, and those are what
/// code execution inside a parser would inherit; a drop that moved only the
/// real ids satisfies `getuid()` and leaves the process root in every way that
/// matters. The same goes for the supplementary groups: a process that is
/// `nobody` by uid and still in the invoking user's groups has not been
/// confined, it has been relabelled.
#[test]
fn privileges_are_actually_dropped_and_cannot_be_regained() {
    root_child_passes(
        "privileges_are_actually_dropped_and_cannot_be_regained",
        "child_drops_to_nobody_and_cannot_climb_back",
        &[],
    );
}

/// A drop that cannot be performed returns an error and leaves the process
/// exactly as privileged as it was — no half-drop, no downgrade to a warning.
///
/// `failed_privilege_drop_aborts_instead_of_running_as_root` above proves the
/// call site treats that error as fatal. This proves the other half: that
/// there is an error to treat, and that the credentials did not move on the
/// way to it.
#[test]
fn a_drop_that_cannot_be_performed_is_fatal_not_a_warning() {
    root_child_passes(
        "a_drop_that_cannot_be_performed_is_fatal_not_a_warning",
        "child_reports_an_impossible_drop_and_stays_put",
        &[],
    );
}

/// `--no-priv-drop` really does skip the drop.
///
/// Only observable from a process that had privileges to keep: unprivileged,
/// this flag is indistinguishable from the "not root, nothing to do" branch
/// immediately below it in `drop_privileges`, so no unprivileged test can tell
/// a working flag from a deleted one.
#[test]
fn the_no_priv_drop_flag_skips_the_drop_even_as_root() {
    root_child_passes(
        "the_no_priv_drop_flag_skips_the_drop_even_as_root",
        "child_keeps_its_credentials_when_the_drop_is_disabled",
        &[],
    );
}

/// `do_chroot` confines the process as documented: the new root's contents
/// appear at `/`, the old root's do not, and the working directory follows.
#[test]
fn chroot_confines_the_process_to_the_new_root() {
    let jail = tempfile::tempdir().expect("a directory to confine the child to");
    std::fs::write(jail.path().join(CHROOT_MARKER), b"visible only inside\n")
        .expect("place the marker inside the new root");
    // The directory is created by this (possibly unprivileged) runner and
    // entered by a root child, which can traverse it whatever its mode; the
    // marker is written from here so the child proves visibility, not its own
    // ability to write.
    root_child_passes(
        "chroot_confines_the_process_to_the_new_root",
        "child_chroots_and_loses_sight_of_the_real_root",
        &[(CHROOT_DIR_ENV, jail.path().as_os_str())],
    );
}

/// `disable_core_dumps` clears the dumpable flag rather than logging that it
/// tried.
///
/// This one is about key material: with dumpability left on, a crash while
/// TLS/SRTP keys are resident writes them to a file on disk nobody asked for.
/// The flag is read back out of the kernel because the function deliberately
/// swallows its own failures — it warns and returns `Ok(())` — so its return
/// value proves nothing whatsoever.
///
/// Needs no privileges, but still runs in a child: `PR_SET_DUMPABLE(0)` is
/// process-wide, irreversible for the runner, and reparents `/proc/self` to
/// root while it is set.
#[test]
#[cfg(target_os = "linux")]
fn disable_core_dumps_actually_clears_the_dumpable_flag() {
    let exe = std::env::current_exe().expect("path of this test binary");
    let out = Command::new(exe)
        .args([
            "child_core_dumps_are_off_after_the_call",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn the child role");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(CHILD_COMPLETE),
        "child role `child_core_dumps_are_off_after_the_call` did not complete: \
         {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Called by a non-root process, the drop touches nothing.
///
/// `drop_privileges` returning `Ok` here is not the interesting part — it is
/// that the four credentials come back byte-for-byte what they were. Move the
/// `is_root()` guard below the `setgroups`/`setgid`/`setuid` sequence, or
/// delete it, and an unprivileged run turns into a hard failure at the first
/// syscall instead of the documented no-op that every non-root deployment
/// depends on.
#[test]
fn drop_privileges_touches_no_credential_when_the_process_is_not_root() {
    if credentials().2 == 0 {
        announce_skip(
            "drop_privileges_touches_no_credential_when_the_process_is_not_root",
            "this runner IS root, so the call would really drop; this gate asserts \
             the unprivileged no-op path",
        );
        return;
    }
    let before = credentials();
    sipnab::privilege::drop_privileges(Some("nobody"), false)
        .expect("with no privileges to shed, the drop is a documented no-op");
    assert_eq!(
        credentials(),
        before,
        "a non-root drop must leave (uid, gid, euid, egid) untouched"
    );
}

// ── Child roles ───────────────────────────────────────────────────────────

/// Drop to `nobody` for real, then try every way back.
#[test]
#[ignore = "child role: spawned by privileges_are_actually_dropped_and_cannot_be_regained"]
fn child_drops_to_nobody_and_cannot_climb_back() {
    if !spawned_by_parent("child_drops_to_nobody_and_cannot_climb_back") {
        return;
    }
    let (want_uid, want_gid) = account_ids("nobody");
    assert_eq!(credentials().2, 0, "the parent only spawns this as root");

    sipnab::privilege::drop_privileges(Some("nobody"), false)
        .expect("root dropping to an existing account must succeed");

    let (uid, gid, euid, egid) = credentials();
    assert_eq!(
        (uid, euid),
        (want_uid, want_uid),
        "both the real and the effective uid must land on nobody; a real-only \
         change leaves the process root as far as the kernel is concerned"
    );
    assert_eq!((gid, egid), (want_gid, want_gid), "and both group ids");

    // SAFETY: getgroups(0, NULL) asks only for the count and writes nothing.
    let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert_eq!(
        ngroups, 0,
        "supplementary groups survived the drop — the process is still in every \
         group the invoking user was, whatever its uid now says"
    );

    // SAFETY: setuid/setgid are expected to be refused here; the return value
    // is the entire point of the call and no memory is involved.
    let regained_uid = unsafe { libc::setuid(0) };
    let uid_errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: as above.
    let regained_gid = unsafe { libc::setgid(0) };
    let gid_errno = std::io::Error::last_os_error().raw_os_error();
    assert_eq!(
        (regained_uid, uid_errno),
        (-1, Some(libc::EPERM)),
        "setuid(0) was permitted after the drop — the saved-set uid still holds \
         root, so any bug or exec can reclaim it"
    );
    assert_eq!(
        (regained_gid, gid_errno),
        (-1, Some(libc::EPERM)),
        "setgid(0) was permitted after the drop"
    );
    assert_eq!(
        credentials(),
        (want_uid, want_gid, want_uid, want_gid),
        "the failed climb-back must not have moved anything either"
    );

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_NO_NEW_PRIVS reads a flag; trailing args are unused.
        let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        assert_eq!(
            nnp, 1,
            "PR_SET_NO_NEW_PRIVS is not set, so exec'ing any setuid binary steps \
             straight back out of the drop"
        );
    }
    println!("{CHILD_COMPLETE}");
}

/// Ask for a drop that cannot succeed, and check that nothing moved.
#[test]
#[ignore = "child role: spawned by a_drop_that_cannot_be_performed_is_fatal_not_a_warning"]
fn child_reports_an_impossible_drop_and_stays_put() {
    if !spawned_by_parent("child_reports_an_impossible_drop_and_stays_put") {
        return;
    }
    let before = credentials();
    assert_eq!(before.2, 0, "the parent only spawns this as root");

    let err = sipnab::privilege::drop_privileges(Some("no-such-user-sipnab-guard"), false)
        .expect_err(
            "a drop to an account that does not exist cannot be reported as done — \
             the caller would carry on as root believing otherwise",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("not found"),
        "the failure must say the account could not be resolved, got: {msg}"
    );

    assert_eq!(
        credentials(),
        before,
        "the failed drop moved some credentials — a half-dropped process is the \
         worst of both outcomes, because nothing downstream can tell"
    );
    println!("{CHILD_COMPLETE}");
}

/// `--no-priv-drop` from a root process keeps every credential.
#[test]
#[ignore = "child role: spawned by the_no_priv_drop_flag_skips_the_drop_even_as_root"]
fn child_keeps_its_credentials_when_the_drop_is_disabled() {
    if !spawned_by_parent("child_keeps_its_credentials_when_the_drop_is_disabled") {
        return;
    }
    let before = credentials();
    assert_eq!(before.2, 0, "the parent only spawns this as root");

    sipnab::privilege::drop_privileges(Some("nobody"), true)
        .expect("--no-priv-drop returns Ok without touching anything");

    assert_eq!(
        credentials(),
        before,
        "--no-priv-drop dropped anyway; the flag exists precisely so a debugging \
         session or an already-unprivileged deployment keeps what it started with"
    );
    println!("{CHILD_COMPLETE}");
}

/// Chroot into a parent-prepared directory and check the old root is gone.
#[test]
#[ignore = "child role: spawned by chroot_confines_the_process_to_the_new_root"]
fn child_chroots_and_loses_sight_of_the_real_root() {
    if !spawned_by_parent("child_chroots_and_loses_sight_of_the_real_root") {
        return;
    }
    let jail = std::env::var_os(CHROOT_DIR_ENV).expect("the parent passes the new root");
    let jail = std::path::PathBuf::from(jail);
    assert!(
        jail.join(CHROOT_MARKER).exists(),
        "precondition: the parent placed the marker inside {}",
        jail.display()
    );
    assert!(
        std::path::Path::new("/etc/passwd").exists(),
        "precondition: the real root is reachable before the chroot"
    );

    sipnab::privilege::do_chroot(&jail).expect("root may chroot");

    assert_eq!(
        std::env::current_dir().expect("a working directory inside the new root"),
        std::path::Path::new("/"),
        "the documented sequence is chroot() then chdir(\"/\"); without the chdir \
         the working directory is still an open handle onto the old tree"
    );
    assert!(
        std::path::Path::new(&format!("/{CHROOT_MARKER}")).exists(),
        "the new root's own contents must be what `/` now resolves to"
    );
    assert!(
        !std::path::Path::new("/etc/passwd").exists(),
        "the real root filesystem is still reachable — nothing was confined"
    );
    println!("{CHILD_COMPLETE}");
}

/// Read the dumpable flag back after asking for core dumps to be disabled.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "child role: spawned by disable_core_dumps_actually_clears_the_dumpable_flag"]
fn child_core_dumps_are_off_after_the_call() {
    if !spawned_by_parent("child_core_dumps_are_off_after_the_call") {
        return;
    }
    // SAFETY: PR_GET_DUMPABLE reads a flag; the trailing args are unused.
    let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(
        before, 1,
        "precondition: a freshly spawned process is dumpable, so the assertion \
         below measures the call rather than the default"
    );

    sipnab::privilege::disable_core_dumps().expect("the call reports Ok by design");

    // SAFETY: as above.
    let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(
        after, 0,
        "the process is still dumpable, so a crash with TLS/SRTP keys resident \
         writes them to disk — and the function cannot report this, because it \
         downgrades its own failures to a warning and returns Ok"
    );
    println!("{CHILD_COMPLETE}");
}
