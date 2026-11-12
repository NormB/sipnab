// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/root_run.rs"]
mod root_run;
#[path = "support/tar_build.rs"]
mod tar_build;
#[path = "../src/test_scratch.rs"]
mod test_scratch;

use std::io::Write as _;
use std::process::{Command, Output};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

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
    root_run::sudo()
        .and_then(|mut sudo| sudo.arg("true").status())
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
/// The guard of the directory holding the copy, and the copy's path. The
/// directory is removed when the guard drops.
///
/// # Side effects
/// Writes `fixture.pcap` into a fresh `sipnab-priv-guard-<tag>-*` directory
/// under the system temp directory.
fn world_readable_fixture(
    tag: &str,
) -> Result<(test_scratch::ScratchDir, std::path::PathBuf), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    // A guarded directory, so a failing test leaves nothing behind, opened to
    // 0755: tempfile makes it 0700, and the process this test drops to must
    // still reach the capture inside it.
    let dir = test_scratch::ScratchDir::new(&format!("sipnab-priv-guard-{tag}-"))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    let dst = dir.join("fixture.pcap");
    std::fs::copy(src, &dst)?;
    Ok((dir, dst))
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
    let mut cmd =
        root_run::sudo().map_err(|e| format!("cannot tie a sudo run to this test: {e}"))?;
    cmd.arg("env");
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
fn root_child_passes(
    parent: &str,
    role: &str,
    env: &[(&str, &std::ffi::OsStr)],
) -> Result<bool, TestError> {
    let mut cmd = match root_child_command(role, env) {
        Ok(c) => c,
        Err(reason) => {
            announce_skip(parent, &reason);
            return Ok(false);
        }
    };
    let out: Output = cmd.output()?;
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
    Ok(true)
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
fn account_ids(name: &str) -> Result<(u32, u32), TestError> {
    let c = std::ffi::CString::new(name)?;
    // SAFETY: getpwnam returns a pointer into a static buffer valid until the
    // next passwd-database call; the two scalar fields are copied out
    // immediately, before anything else can touch it.
    Ok(unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        assert!(!pw.is_null(), "account '{name}' must exist on this system");
        ((*pw).pw_uid, (*pw).pw_gid)
    })
}

// ── End-to-end: the binary's behavior around the drop ────────────────────

/// Running as root with `--user` naming a nonexistent account exits non-zero
/// with "Failed to drop privileges" — never continues capturing as root.
#[test]
fn failed_privilege_drop_aborts_instead_of_running_as_root() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "failed_privilege_drop_aborts_instead_of_running_as_root",
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let (_fixture_dir, fixture) = world_readable_fixture("drop-fail")?;
    let out = root_run::sudo()?
        .args([
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().ok_or("path is not UTF-8")?,
            "--user",
            "no-such-user-sipnab-guard",
        ])
        .output()?;
    assert!(
        !out.status.success(),
        "a failed privilege drop must abort the process, not continue as root"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Failed to drop privileges"),
        "abort must say why, got:\n{stderr}"
    );
    Ok(())
}

/// Root dropping to `nobody` still reads and processes the fixture, exiting 0.
#[test]
fn successful_privilege_drop_still_processes_capture() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "successful_privilege_drop_still_processes_capture",
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let (_fixture_dir, fixture) = world_readable_fixture("drop-success")?;
    let out = root_run::sudo()?
        .args([
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().ok_or("path is not UTF-8")?,
            "--user",
            "nobody",
        ])
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "root -> drop to nobody -> read fixture must succeed, got:\n{stderr}"
    );
    Ok(())
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
/// confined, it has been relabeled.
#[test]
fn privileges_are_actually_dropped_and_cannot_be_regained() -> Result<(), TestError> {
    root_child_passes(
        "privileges_are_actually_dropped_and_cannot_be_regained",
        "child_drops_to_nobody_and_cannot_climb_back",
        &[],
    )?;
    Ok(())
}

/// A drop that cannot be performed returns an error and leaves the process
/// exactly as privileged as it was — no half-drop, no downgrade to a warning.
///
/// `failed_privilege_drop_aborts_instead_of_running_as_root` above proves the
/// call site treats that error as fatal. This proves the other half: that
/// there is an error to treat, and that the credentials did not move on the
/// way to it.
#[test]
fn a_drop_that_cannot_be_performed_is_fatal_not_a_warning() -> Result<(), TestError> {
    root_child_passes(
        "a_drop_that_cannot_be_performed_is_fatal_not_a_warning",
        "child_reports_an_impossible_drop_and_stays_put",
        &[],
    )?;
    Ok(())
}

/// `--no-priv-drop` really does skip the drop.
///
/// Only observable from a process that had privileges to keep: unprivileged,
/// this flag is indistinguishable from the "not root, nothing to do" branch
/// immediately below it in `drop_privileges`, so no unprivileged test can tell
/// a working flag from a deleted one.
#[test]
fn the_no_priv_drop_flag_skips_the_drop_even_as_root() -> Result<(), TestError> {
    root_child_passes(
        "the_no_priv_drop_flag_skips_the_drop_even_as_root",
        "child_keeps_its_credentials_when_the_drop_is_disabled",
        &[],
    )?;
    Ok(())
}

/// `do_chroot` confines the process as documented: the new root's contents
/// appear at `/`, the old root's do not, and the working directory follows.
#[test]
fn chroot_confines_the_process_to_the_new_root() -> Result<(), TestError> {
    let jail = tempfile::tempdir()?;
    std::fs::write(jail.path().join(CHROOT_MARKER), b"visible only inside\n")?;
    // The directory is created by this (possibly unprivileged) runner and
    // entered by a root child, which can traverse it whatever its mode; the
    // marker is written from here so the child proves visibility, not its own
    // ability to write.
    root_child_passes(
        "chroot_confines_the_process_to_the_new_root",
        "child_chroots_and_loses_sight_of_the_real_root",
        &[(CHROOT_DIR_ENV, jail.path().as_os_str())],
    )?;
    Ok(())
}

/// `disable_core_dumps` clears the dumpable flag rather than logging that it
/// tried.
///
/// This one is about key material: with dumpability left on, a crash while
/// TLS/SRTP keys are resident writes them to a file on disk nobody asked for.
/// The flag is read back out of the kernel rather than inferred from the return
/// value. `Ok(())` is now a real claim — the function used to warn and return
/// it whatever the syscall did — but a return value is still a statement about
/// what a function believes, and this is a security property, so the child asks
/// the kernel.
///
/// Needs no privileges, but still runs in a child: `PR_SET_DUMPABLE(0)` is
/// process-wide, irreversible for the runner, and reparents `/proc/self` to
/// root while it is set.
#[test]
#[cfg(target_os = "linux")]
fn disable_core_dumps_actually_clears_the_dumpable_flag() -> Result<(), TestError> {
    let exe = std::env::current_exe()?;
    let out = Command::new(exe)
        .args([
            "child_core_dumps_are_off_after_the_call",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(CHILD_COMPLETE),
        "child role `child_core_dumps_are_off_after_the_call` did not complete: \
         {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
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
fn drop_privileges_touches_no_credential_when_the_process_is_not_root() -> Result<(), TestError> {
    if credentials().2 == 0 {
        announce_skip(
            "drop_privileges_touches_no_credential_when_the_process_is_not_root",
            "this runner IS root, so the call would really drop; this gate asserts \
             the unprivileged no-op path",
        );
        return Ok(());
    }
    let before = credentials();
    sipnab::privilege::drop_privileges(Some("nobody"), false)?;
    assert_eq!(
        credentials(),
        before,
        "a non-root drop must leave (uid, gid, euid, egid) untouched"
    );
    Ok(())
}

/// `PR_SET_NO_NEW_PRIVS` is set on the path an unprivileged sipnab takes.
///
/// This is the gate for the install the documentation recommends. `sipnab
/// --setup-caps` writes `cap_net_raw,cap_net_admin+ep` onto the binary so
/// capture runs WITHOUT root, and on that path there is no uid to shed — but
/// no-new-privs has no uid precondition either, and skipping it with the drop
/// left the recommended deployment able to exec its way back to privilege.
///
/// Run in a child because the flag is one-way: a process that sets it cannot
/// clear it, so setting it here would silently alter every test that follows
/// in this binary.
#[test]
#[cfg(target_os = "linux")]
fn no_new_privs_is_set_even_when_there_is_nothing_to_drop() -> Result<(), TestError> {
    if credentials().2 == 0 {
        announce_skip(
            "no_new_privs_is_set_even_when_there_is_nothing_to_drop",
            "this runner IS root, and the child would inherit that; the case this \
             gate is about is the unprivileged process that has nothing to drop. \
             The end-to-end gate on the shipped binary still covers both",
        );
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    let out = Command::new(exe)
        .args([
            "child_no_new_privs_is_set_without_root",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains(CHILD_COMPLETE),
        "child role `child_no_new_privs_is_set_without_root` did not complete: \
         {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// The shipped binary hardens itself, observed from a process it spawned.
///
/// The unit gate above proves the function sets the flag; this one proves the
/// binary calls it, which is the half a deleted call site would leave green.
/// `PR_SET_NO_NEW_PRIVS` is inherited across `fork`/`exec`, so an
/// `--on-dialog-exec` hook reading its own `/proc/self/status` reports what
/// sipnab's own process is carrying — the real kernel flag on a real run, not
/// a log line saying so.
#[test]
#[cfg(target_os = "linux")]
fn the_shipped_binary_blocks_privilege_escalation_on_a_capture_run() -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir()?;
    // A root runner drops to `nobody` before the hook fires, and `nobody` has
    // to be able to write the report; without this the test would report "the
    // hook never ran" for a permission error.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))?;
    let report = dir.path().join("no-new-privs");
    let (_fixture_dir, fixture) = world_readable_fixture("no-new-privs")?;

    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            fixture.to_str().ok_or("fixture path is UTF-8")?,
            "--on-dialog-exec",
            &format!(
                "grep '^NoNewPrivs' /proc/self/status > {}",
                report.display()
            ),
        ])
        .output()?;
    assert!(
        out.status.success(),
        "sipnab must process the fixture, got {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // The hook engine deliberately never waits on a child (a hung hook must
    // not hold up the process), so the report can land just after sipnab
    // exits. Poll for it, and fail if it never arrives — an absent file is a
    // failure here, never a pass.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let line = loop {
        match std::fs::read_to_string(&report) {
            Ok(s) if !s.trim().is_empty() => break s,
            _ if std::time::Instant::now() >= deadline => {
                return Err(format!(
                    "the --on-dialog-exec hook never wrote {}, so nothing was measured",
                    report.display()
                )
                .into());
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };

    assert_eq!(
        line.trim(),
        "NoNewPrivs:\t1",
        "sipnab ran the hook from a process that can still gain privileges \
         through execve. On the `--setup-caps` install there is no uid to drop, \
         so this flag is the only thing standing between a bug in the parser and \
         a setuid binary"
    );
    Ok(())
}

// ── Child roles ───────────────────────────────────────────────────────────

/// Drop to `nobody` for real, then try every way back.
#[test]
#[ignore = "child role: spawned by privileges_are_actually_dropped_and_cannot_be_regained"]
fn child_drops_to_nobody_and_cannot_climb_back() -> Result<(), TestError> {
    if !spawned_by_parent("child_drops_to_nobody_and_cannot_climb_back") {
        return Ok(());
    }
    let (want_uid, want_gid) = account_ids("nobody")?;
    assert_eq!(credentials().2, 0, "the parent only spawns this as root");

    sipnab::privilege::drop_privileges(Some("nobody"), false)?;

    let (uid, gid, euid, egid) = credentials();
    assert_eq!(
        (uid, euid),
        (want_uid, want_uid),
        "both the real and the effective uid must land on nobody; a real-only \
         change leaves the process root as far as the kernel is concerned"
    );
    assert_eq!((gid, egid), (want_gid, want_gid), "and both group ids");

    // The property is "no group of the INVOKING user survived", not "the list is
    // empty" — and those are not the same statement across platforms.
    //
    // POSIX leaves it IMPLEMENTATION-DEFINED whether getgroups() reports the
    // effective GID alongside the supplementary list. Linux omits it, so a
    // cleared list reads 0. The BSDs, macOS among them, include it, so a cleared
    // list reads 1 and that single entry IS the new egid. Asserting the count
    // therefore measured the platform rather than the drop: it failed on macOS
    // for a process that had in fact given up every supplementary group, while
    // saying "supplementary groups survived" — a confident wrong answer of
    // exactly the kind this suite exists to prevent.
    //
    // Requiring every entry to equal the target gid states the security property
    // directly and holds on both. It is not vacuous on either: on Linux the list
    // is empty and any survivor shows up as a foreign entry; on macOS the list
    // holds exactly the egid and any survivor shows up beside it. A retained
    // `admin` or `wheel` membership — the case actually worth catching, because
    // it is a route back to root that a uid of `nobody` conceals — fails here on
    // both platforms.
    //
    // The old assertion reported only a count, which is why its CI failure could
    // not distinguish "the egid, as the BSDs report it" from "a surviving admin
    // membership". This one names the offending gids.
    //
    // SAFETY: getgroups(0, NULL) asks only for the count and writes nothing.
    let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(
        ngroups >= 0,
        "getgroups(0, NULL) failed: {}",
        std::io::Error::last_os_error()
    );
    let mut groups = vec![0 as libc::gid_t; ngroups as usize];
    if ngroups > 0 {
        // SAFETY: the buffer and its length are passed together, and the length
        // is the count the call above just reported, so getgroups cannot write
        // past the end.
        let got = unsafe { libc::getgroups(ngroups, groups.as_mut_ptr()) };
        assert!(
            got >= 0,
            "getgroups failed: {}",
            std::io::Error::last_os_error()
        );
        groups.truncate(got as usize);
    }
    let survivors: Vec<libc::gid_t> = groups
        .iter()
        .copied()
        .filter(|g| *g != want_gid as libc::gid_t)
        .collect();
    assert!(
        survivors.is_empty(),
        "supplementary groups survived the drop: {survivors:?}. The process is \
         still in {} group(s) other than its new primary {want_gid}, so a uid \
         reading `nobody` still carries everything those groups can reach.",
        survivors.len()
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

    // PR_SET_NO_NEW_PRIVS is deliberately NOT asserted here any more. It is no
    // longer part of the drop: it has no uid precondition, and setting it from
    // inside a function with two early returns is what left the `--setup-caps`
    // install unhardened. `no_new_privs_is_set_even_when_there_is_nothing_to_drop`
    // and `the_shipped_binary_blocks_privilege_escalation_on_a_capture_run` own
    // that property now, and the second of them covers this root path too.
    println!("{CHILD_COMPLETE}");
    Ok(())
}

/// Ask for a drop that cannot succeed, and check that nothing moved.
#[test]
#[ignore = "child role: spawned by a_drop_that_cannot_be_performed_is_fatal_not_a_warning"]
fn child_reports_an_impossible_drop_and_stays_put() -> Result<(), TestError> {
    if !spawned_by_parent("child_reports_an_impossible_drop_and_stays_put") {
        return Ok(());
    }
    let before = credentials();
    assert_eq!(before.2, 0, "the parent only spawns this as root");

    let err = sipnab::privilege::drop_privileges(Some("no-such-user-sipnab-guard"), false)
        .err()
        .ok_or(
            "a drop to an account that does not exist cannot be reported as done — \
             the caller would carry on as root believing otherwise",
        )?;
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
    Ok(())
}

/// `--no-priv-drop` from a root process keeps every credential.
#[test]
#[ignore = "child role: spawned by the_no_priv_drop_flag_skips_the_drop_even_as_root"]
fn child_keeps_its_credentials_when_the_drop_is_disabled() -> Result<(), TestError> {
    if !spawned_by_parent("child_keeps_its_credentials_when_the_drop_is_disabled") {
        return Ok(());
    }
    let before = credentials();
    assert_eq!(before.2, 0, "the parent only spawns this as root");

    sipnab::privilege::drop_privileges(Some("nobody"), true)?;

    assert_eq!(
        credentials(),
        before,
        "--no-priv-drop dropped anyway; the flag exists precisely so a debugging \
         session or an already-unprivileged deployment keeps what it started with"
    );
    println!("{CHILD_COMPLETE}");
    Ok(())
}

/// Chroot into a parent-prepared directory and check the old root is gone.
#[test]
#[ignore = "child role: spawned by chroot_confines_the_process_to_the_new_root"]
fn child_chroots_and_loses_sight_of_the_real_root() -> Result<(), TestError> {
    if !spawned_by_parent("child_chroots_and_loses_sight_of_the_real_root") {
        return Ok(());
    }
    let jail = std::env::var_os(CHROOT_DIR_ENV).ok_or("the parent passes the new root")?;
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

    sipnab::privilege::do_chroot(&jail)?;

    assert_eq!(
        std::env::current_dir()?,
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
    Ok(())
}

/// Set no-new-privs from an unprivileged process and read the flag back.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "child role: spawned by no_new_privs_is_set_even_when_there_is_nothing_to_drop"]
fn child_no_new_privs_is_set_without_root() -> Result<(), TestError> {
    if !spawned_by_parent("child_no_new_privs_is_set_without_root") {
        return Ok(());
    }
    // SAFETY: PR_GET_NO_NEW_PRIVS reads a flag; the trailing args are unused.
    let before = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    assert_eq!(
        before, 0,
        "precondition: a freshly spawned process has no-new-privs clear, so the \
         assertion below measures the call rather than an inherited flag"
    );

    assert_ne!(
        credentials().2,
        0,
        "precondition: this runner is unprivileged, which is the case the flag \
         used to be skipped in"
    );

    sipnab::privilege::block_privilege_escalation()?;

    // SAFETY: as above.
    let after = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    assert_eq!(
        after, 1,
        "no-new-privs is clear, so exec'ing any setuid binary steps straight past \
         everything else this module does"
    );
    println!("{CHILD_COMPLETE}");
    Ok(())
}

/// Read the dumpable flag back after asking for core dumps to be disabled.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "child role: spawned by disable_core_dumps_actually_clears_the_dumpable_flag"]
fn child_core_dumps_are_off_after_the_call() -> Result<(), TestError> {
    if !spawned_by_parent("child_core_dumps_are_off_after_the_call") {
        return Ok(());
    }
    // SAFETY: PR_GET_DUMPABLE reads a flag; the trailing args are unused.
    let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(
        before, 1,
        "precondition: a freshly spawned process is dumpable, so the assertion \
         below measures the call rather than the default"
    );

    sipnab::privilege::disable_core_dumps()?;

    // SAFETY: as above.
    let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(
        after, 0,
        "the process is still dumpable, so a crash with TLS/SRTP keys resident \
         writes them to disk — and the function cannot report this, because it \
         downgrades its own failures to a warning and returns Ok"
    );
    println!("{CHILD_COMPLETE}");
    Ok(())
}

// ── The keylog is read before the drop ────────────────────────────────────

/// One TLS 1.3 session's secrets, as a TLS stack writes them.
#[cfg(feature = "tls")]
const KEYLOG: &str = "CLIENT_TRAFFIC_SECRET_0 \
    5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a \
    3131313131313131313131313131313131313131313131313131313131313131\n";

/// **A keylog only root can read still loads when sipnab drops to `nobody`.**
///
/// The keylog a proxy writes is usually private to it, and sipnab runs as root
/// to capture, then drops privileges before it parses a byte. It read an
/// ordinary `--keylog` file only AFTER the drop, so a run that could capture
/// the wire could not read its own keys, and said only "Failed to initialize
/// TLS decryptor: Loading keylog from ..." with no cause (found reproducing
/// issue #301 with OpenSIPS). The file here sits in a 0700 directory owned by
/// the test's user: root can read it, `nobody` cannot.
#[cfg(feature = "tls")]
#[test]
fn a_keylog_only_root_can_read_is_loaded_before_the_drop() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_keylog_only_root_can_read_is_loaded_before_the_drop",
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let (_fixture_dir, fixture) = world_readable_fixture("keylog-before-drop")?;
    use std::os::unix::fs::PermissionsExt as _;
    let private = tempfile::tempdir()?;
    // Set explicitly: `tempdir` honors the umask, which left it 0775 here and
    // let `nobody` read the file, so the test passed without the fix.
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700))?;
    let keylog = private.path().join("proxy.keys");
    std::fs::write(&keylog, KEYLOG)?;
    std::fs::set_permissions(&keylog, std::fs::Permissions::from_mode(0o600))?;
    let out = root_run::sudo()?
        .args([
            env!("CARGO_BIN_EXE_sipnab"),
            "-N",
            "-I",
            fixture.to_str().ok_or("path is not UTF-8")?,
            "--keylog",
            keylog.to_str().ok_or("path is not UTF-8")?,
            "--user",
            "nobody",
        ])
        .env("SIPNAB_LOG", "info")
        .output()?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        !stderr.contains("Failed to initialize TLS decryptor"),
        "the keylog must be read while still root:\n{stderr}"
    );
    assert!(
        stderr.contains("TLS decryption active"),
        "and its keys loaded:\n{stderr}"
    );
    Ok(())
}

/// A keylog that cannot be read says WHY, and stops the run with exit 1 as
/// `--tls-key` does. The message used to stop at "Loading keylog from
/// <path>", which reads the same for a typo, a permission problem and a file
/// the producer has not created yet.
#[cfg(feature = "tls")]
#[test]
fn a_keylog_that_cannot_be_read_names_the_cause() -> Result<(), TestError> {
    let (_fixture_dir, fixture) = world_readable_fixture("keylog-cause")?;
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("not-written-yet.keys");
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            fixture.to_str().ok_or("path is not UTF-8")?,
            "--keylog",
            missing.to_str().ok_or("path is not UTF-8")?,
        ])
        .output()?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "the run must stop:\n{stderr}");
    let line = stderr
        .lines()
        .find(|l| l.contains("Failed to load --keylog"))
        .ok_or_else(|| format!("the failure must be reported:\n{stderr}"))?;
    assert!(
        line.contains("No such file or directory"),
        "the report must carry the operating system's reason: {line}"
    );
    Ok(())
}

// ── OPS-11: secret files are read before the drop ─────────────────────────

/// Root-owned 0600 copies of `files`, as an operator protects a secret.
///
/// Each `(name, bytes)` is written into `dir` by this runner and then handed
/// to root with `sudo -n install -m 0600 -o 0 -g 0`, so only root can
/// read it. The owner and group are numeric because macOS has no group named
/// `root` (gid 0 is `wheel` there), and `install -g root` fails on it. `dir` itself stays this runner's, so the tempdir can still delete
/// the files.
fn root_only_files(
    dir: &std::path::Path,
    files: &[(&str, &[u8])],
) -> Result<Vec<std::path::PathBuf>, TestError> {
    let mut out = Vec::new();
    for (name, bytes) in files {
        let staged = dir.join(format!("{name}.staged"));
        let path = dir.join(name);
        std::fs::write(&staged, bytes)?;
        let status = root_run::sudo()?
            .args(["install", "-m", "0600", "-o", "0", "-g", "0"])
            .arg(&staged)
            .arg(&path)
            .status()?;
        assert!(
            status.success(),
            "sudo install of {} failed",
            path.display()
        );
        std::fs::remove_file(&staged)?;
        out.push(path);
    }
    Ok(out)
}

/// A working directory that `nobody` can write, for a root run that drops to
/// it.
///
/// `sudo` resets the environment, so a coverage-instrumented sipnab gets no
/// `LLVM_PROFILE_FILE` and writes its `.profraw` into its working directory
/// when it exits, as `nobody`. The test's own working directory is the
/// checkout, which `nobody` cannot write, so the profiler prints `LLVM Profile
/// Error: Failed to write file ...: Permission denied` on stderr. That line is
/// the profiler's, not sipnab's, and it would fail every assertion that no
/// secret read was refused. sipnab changes its working directory only when it
/// chroots: it then works in the new root, so a `--chroot` run whose stderr is
/// checked for `Permission denied` chroots into one of these directories too.
fn dir_nobody_can_write() -> Result<tempfile::TempDir, TestError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777))?;
    Ok(dir)
}

/// A self-signed certificate for `localhost` and its private key, as PEM.
#[cfg(all(feature = "api", feature = "mcp-http", feature = "metrics"))]
fn localhost_cert() -> Result<(String, String), TestError> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// The path as a `&str`, for an argv.
#[cfg(any(feature = "hep", feature = "api"))]
fn arg(p: &std::path::Path) -> Result<&str, TestError> {
    Ok(p.to_str().ok_or("path is not UTF-8")?)
}

/// A root run that names root-only (0600) secret files, and sends HEP,
/// reads them before it drops to `nobody` and finishes.
///
/// It used to read `--hep-auth-file` in the HEP sender's constructor, after
/// the drop, and stop with exit 2: `HEP auth: --hep-auth-file '...':
/// Permission denied (os error 13)`. `--tls-key` and `--srtp-keys` were read
/// after the drop the same way.
#[cfg(all(feature = "hep", feature = "tls"))]
#[test]
fn a_root_run_reads_its_root_only_hep_and_key_files_before_the_drop() -> Result<(), TestError> {
    let test = "a_root_run_reads_its_root_only_hep_and_key_files_before_the_drop";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let rsa = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/tls_rsa/key.pem"
    ))?;
    let srtp = b"ssrc=1234 key=YUJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0\n";
    let files = root_only_files(
        dir.path(),
        &[
            ("hep.auth", b"hep-shared-secret\n"),
            ("rsa.pem", &rsa),
            ("srtp.keys", srtp),
        ],
    )?;
    let (_fixture_dir, fixture) = world_readable_fixture("secret-before-drop")?;
    let run_dir = dir_nobody_can_write()?;
    let out = root_run::sudo()?
        .current_dir(run_dir.path())
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", arg(&fixture)?, "--user", "nobody"])
        .args([
            "--hep-send",
            "127.0.0.1:9",
            "--hep-auth-file",
            arg(&files[0])?,
        ])
        .args(["--tls-key", arg(&files[1])?, "--srtp-keys", arg(&files[2])?])
        .output()?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a root run with root-only secret files must read them before the drop \
         and finish; it exited {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}

/// Wait up to `limit` for `child` (a `sudo` this test spawned) to exit; when
/// it is still running then, send it SIGTERM, which sudo relays, and collect
/// it.
///
/// # Returns
/// The exit status when the run ended by itself within `limit`, `None` when it
/// had to be stopped, and the collected output either way.
#[cfg(feature = "api")]
fn wait_or_stop(
    mut child: std::process::Child,
    limit: std::time::Duration,
) -> Result<(Option<std::process::ExitStatus>, Output), TestError> {
    let deadline = std::time::Instant::now() + limit;
    let mut early = None;
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            early = Some(status);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if early.is_none() {
        let pid = libc::pid_t::try_from(child.id())?;
        // SAFETY: kill(2) on the pid of the sudo process this test spawned and
        // has not yet reaped, so the pid cannot have been reused.
        assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0, "kill sudo");
    }
    Ok((early, child.wait_with_output()?))
}

/// A root run that serves REST, MCP over HTTP and metrics over TLS, with every
/// credential in a root-only (0600) file, starts all three as `nobody`.
///
/// It used to read each of these after the drop and stop with exit 2 on the
/// first: `--metrics-auth-file`, `--api-signing-key-file`, `--mcp-token-file`,
/// `--mcp-signing-key-file`, and the certificate and key of all three
/// listeners. The run serves until it is stopped, so the test lets it run,
/// sends SIGTERM to the `sudo` it started (which relays it), and requires that
/// it was still running and then stopped cleanly.
#[cfg(all(feature = "api", feature = "mcp-http", feature = "metrics"))]
#[test]
fn a_root_run_reads_its_root_only_server_credentials_before_the_drop() -> Result<(), TestError> {
    let test = "a_root_run_reads_its_root_only_server_credentials_before_the_drop";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let (cert, key) = localhost_cert()?;
    let files = root_only_files(
        dir.path(),
        &[
            ("metrics.auth", b"scrape:scrape-password\n"),
            ("api.signing", b"api-signing-key-0123456789abcdef0123\n"),
            ("mcp.token", b"mcp-static-token-0123456789abcdef\n"),
            ("mcp.signing", b"mcp-signing-key-0123456789abcdef0123\n"),
            ("cert.pem", cert.as_bytes()),
            ("key.pem", key.as_bytes()),
        ],
    )?;
    let [metrics_auth, api_signing, mcp_token, mcp_signing, cert, key] = files.as_slice() else {
        return Err("expected six files".into());
    };
    let (_fixture_dir, fixture) = world_readable_fixture("server-secrets-before-drop")?;
    let run_dir = dir_nobody_can_write()?;
    let child = root_run::sudo()?
        .current_dir(run_dir.path())
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", arg(&fixture)?, "--user", "nobody"])
        .args([
            "--metrics",
            "127.0.0.1:0",
            "--metrics-auth-file",
            arg(metrics_auth)?,
        ])
        .args([
            "--metrics-tls-cert",
            arg(cert)?,
            "--metrics-tls-key",
            arg(key)?,
        ])
        .args([
            "--api",
            "127.0.0.1:0",
            "--api-signing-key-file",
            arg(api_signing)?,
        ])
        .args(["--api-tls-cert", arg(cert)?, "--api-tls-key", arg(key)?])
        .args([
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-bind",
            "127.0.0.1:0",
        ])
        .args([
            "--mcp-token-file",
            arg(mcp_token)?,
            "--mcp-signing-key-file",
            arg(mcp_signing)?,
        ])
        .args(["--mcp-tls-cert", arg(cert)?, "--mcp-tls-key", arg(key)?])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    // A refusal arrives within a second of startup; five is the margin.
    let (early, out) = wait_or_stop(child, std::time::Duration::from_secs(5))?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        early.is_none(),
        "the run stopped by itself before it was signaled, exit {:?}: a server \
         credential was read after the drop:\n{stderr}",
        early.and_then(|s| s.code())
    );
    assert!(
        out.status.success(),
        "SIGTERM must stop the run cleanly, got {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}

/// The `[vcon_fetch]` store a root run's server doors read, written to
/// `dir/sipnab.toml`, with `auth`, `key`, `ca` and `signer` as its files.
#[cfg(all(feature = "api", feature = "vcon"))]
fn vcon_fetch_config(
    dir: &std::path::Path,
    auth: &std::path::Path,
    key: &std::path::Path,
    ca: &std::path::Path,
    signer: &std::path::Path,
) -> Result<std::path::PathBuf, TestError> {
    let config = dir.join("sipnab.toml");
    std::fs::write(
        &config,
        format!(
            "[vcon_fetch]\nurl = \"https://127.0.0.1:9/v/{{uuid}}\"\n\
             auth_file = \"{}\"\ndecrypt_key = \"{}\"\nca = \"{}\"\nsigner_ca = \"{}\"\n",
            auth.display(),
            key.display(),
            ca.display(),
            signer.display()
        ),
    )?;
    Ok(config)
}

/// Run `sudo sipnab` as a REST server with `--api-allow-vcon-fetch` and the
/// config file `config`, for up to five seconds, then stop it.
#[cfg(all(feature = "api", feature = "vcon"))]
fn serve_vcon_fetch_door(
    config: &std::path::Path,
    test: &str,
    extra: &[&str],
) -> Result<(Option<std::process::ExitStatus>, Output), TestError> {
    let (_fixture_dir, fixture) = world_readable_fixture(test)?;
    let run_dir = dir_nobody_can_write()?;
    let child = root_run::sudo()?
        .current_dir(run_dir.path())
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", arg(&fixture)?, "--user", "nobody"])
        .args(["-f", arg(config)?])
        .args(["--api", "127.0.0.1:0", "--api-allow-vcon-fetch"])
        .args(extra)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    // A refusal arrives within a second of startup; five is the margin.
    let stopped = wait_or_stop(child, std::time::Duration::from_secs(5));
    let _ = std::fs::remove_file(&fixture);
    stopped
}

/// OPS-11, `[vcon_fetch]`: a root run whose REST door may fetch from a vCon
/// store reads the store's root-only (0600) credential, decryption key, CA
/// and signer CA before the drop, and serves as `nobody`.
///
/// It used to build the fetcher when the servers started, after the drop,
/// and stop with exit 2: `--api-allow-vcon-fetch: [vcon_fetch] auth_file
/// '...': Permission denied (os error 13)`.
#[cfg(all(feature = "api", feature = "vcon"))]
#[test]
fn a_root_run_reads_its_root_only_vcon_fetch_files_before_the_drop() -> Result<(), TestError> {
    let test = "a_root_run_reads_its_root_only_vcon_fetch_files_before_the_drop";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let jose = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
    let key = std::fs::read(format!("{jose}/fake_grp.key"))?;
    let ca = std::fs::read(format!("{jose}/fake_ca_root.crt"))?;
    let dir = tempfile::tempdir()?;
    let files = root_only_files(
        dir.path(),
        &[
            ("fetch.auth", b"Authorization: Bearer fetch-token-0123\n"),
            ("decrypt.pem", &key),
            ("store-ca.pem", &ca),
            ("signer-ca.pem", &ca),
        ],
    )?;
    let [auth, key, ca, signer] = files.as_slice() else {
        return Err("expected four files".into());
    };
    let config = vcon_fetch_config(dir.path(), auth, key, ca, signer)?;
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-before-drop", &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        early.is_none(),
        "the run stopped by itself before it was signaled, exit {:?}: a \
         [vcon_fetch] file was read after the drop:\n{stderr}",
        early.and_then(|s| s.code())
    );
    assert!(
        out.status.success(),
        "SIGTERM must stop the run cleanly, got {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}

/// The advance read keeps the credential's permission rule as the dropped
/// user applied it: a credential that user owns, with a group bit set, is
/// still refused with exit 2, naming the mode.
#[cfg(all(feature = "api", feature = "vcon"))]
#[test]
fn a_root_run_still_refuses_a_vcon_fetch_credential_its_drop_user_lets_others_read()
-> Result<(), TestError> {
    let test = "a_root_run_still_refuses_a_vcon_fetch_credential_its_drop_user_lets_others_read";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let jose = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
    let key = std::fs::read(format!("{jose}/fake_grp.key"))?;
    let ca = std::fs::read(format!("{jose}/fake_ca_root.crt"))?;
    // Traversable, so `nobody` reaches its own file and the refusal is the
    // permission rule's, before the fix and after it.
    let dir = tempfile::tempdir()?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711))?;
    }
    let files = root_only_files(
        dir.path(),
        &[
            ("decrypt.pem", &key),
            ("store-ca.pem", &ca),
            ("signer-ca.pem", &ca),
        ],
    )?;
    let [key, ca, signer] = files.as_slice() else {
        return Err("expected three files".into());
    };
    let staged = dir.path().join("nobody.auth.staged");
    let auth = dir.path().join("nobody.auth");
    std::fs::write(&staged, b"Authorization: Bearer fetch-token-0123\n")?;
    let installed = root_run::sudo()?
        .args(["install", "-m", "0640", "-o", "nobody"])
        .arg(&staged)
        .arg(&auth)
        .status()?;
    assert!(installed.success(), "sudo install of the nobody-owned file");
    let config = vcon_fetch_config(dir.path(), &auth, key, ca, signer)?;
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-refusal-kept", &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        early.and_then(|s| s.code()),
        Some(2),
        "a credential the dropped user owns with mode 0640 must still be \
         refused with exit 2:\n{stderr}"
    );
    assert!(
        stderr.contains("can be read or written by other users (mode 0640)"),
        "{stderr}"
    );
    Ok(())
}

/// The four root-only `[vcon_fetch]` files, the store's CA doubling as the
/// signer CA, in `dir`: (auth, key, ca, signer).
#[cfg(all(feature = "api", feature = "vcon"))]
fn root_only_fetch_files(dir: &std::path::Path) -> Result<[std::path::PathBuf; 4], TestError> {
    let jose = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
    let key = std::fs::read(format!("{jose}/fake_grp.key"))?;
    let ca = std::fs::read(format!("{jose}/fake_ca_root.crt"))?;
    let files = root_only_files(
        dir,
        &[
            ("fetch.auth", b"Authorization: Bearer fetch-token-0123\n"),
            ("decrypt.pem", &key),
            ("store-ca.pem", &ca),
            ("signer-ca.pem", &ca),
        ],
    )?;
    let [a, k, c, g] = files.as_slice() else {
        return Err("expected four files".into());
    };
    Ok([a.clone(), k.clone(), c.clone(), g.clone()])
}

/// The run stopped by itself with exit 2 within the wait, and its stderr.
#[cfg(all(feature = "api", feature = "vcon"))]
fn refused_with_2(early: Option<std::process::ExitStatus>, out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        early.and_then(|s| s.code()),
        Some(2),
        "the run must stop with exit 2:\n{stderr}"
    );
    stderr
}

/// A `[vcon_fetch] auth_file` that does not exist stops a root run with exit
/// 2, naming the door's flag, the setting and the path.
#[cfg(all(feature = "api", feature = "vcon"))]
#[test]
fn a_root_run_names_a_missing_vcon_fetch_credential() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_root_run_names_a_missing_vcon_fetch_credential",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let [_, key, ca, signer] = root_only_fetch_files(dir.path())?;
    let missing = dir.path().join("no-such.auth");
    let config = vcon_fetch_config(dir.path(), &missing, &key, &ca, &signer)?;
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-missing-auth", &[])?;
    let stderr = refused_with_2(early, &out);
    assert!(
        stderr.contains(&format!(
            "--api-allow-vcon-fetch: [vcon_fetch] auth_file '{}': No such file or directory",
            missing.display()
        )),
        "{stderr}"
    );
    Ok(())
}

/// A root-owned decryption key other users can read is refused with exit 2:
/// read before the drop, it is still judged by its mode.
#[cfg(all(feature = "api", feature = "vcon"))]
#[test]
fn a_root_run_refuses_a_world_readable_decryption_key() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_root_run_refuses_a_world_readable_decryption_key",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let [auth, _, ca, signer] = root_only_fetch_files(dir.path())?;
    let staged = dir.path().join("open.pem.staged");
    let key = dir.path().join("open.pem");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/vcon-jose/fake_grp.key"
        ),
        &staged,
    )?;
    let ok = root_run::sudo()?
        .args(["install", "-m", "0644", "-o", "0", "-g", "0"])
        .arg(&staged)
        .arg(&key)
        .status()?;
    assert!(ok.success(), "sudo install of the world-readable key");
    let config = vcon_fetch_config(dir.path(), &auth, &key, &ca, &signer)?;
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-open-key", &[])?;
    let stderr = refused_with_2(early, &out);
    assert!(
        stderr.contains("can be read by other users (mode 644): chmod 600 it"),
        "{stderr}"
    );
    Ok(())
}

/// A credential named through a symbolic link to a root-only file is read
/// through the link before the drop, and the run serves.
#[cfg(all(feature = "api", feature = "vcon"))]
#[test]
fn a_root_run_reads_a_root_only_credential_through_a_symlink() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_root_run_reads_a_root_only_credential_through_a_symlink",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let [auth, key, ca, signer] = root_only_fetch_files(dir.path())?;
    let link = dir.path().join("link.auth");
    std::os::unix::fs::symlink(&auth, &link)?;
    let config = vcon_fetch_config(dir.path(), &link, &key, &ca, &signer)?;
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-symlink", &[])?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(early.is_none(), "the run stopped by itself:\n{stderr}");
    assert!(out.status.success(), "SIGTERM stops it cleanly:\n{stderr}");
    Ok(())
}

/// Both doors that may fetch, REST and MCP over HTTP, serve from one
/// root-only `[vcon_fetch]` store read before the drop.
#[cfg(all(feature = "api", feature = "vcon", feature = "mcp-http"))]
#[test]
fn a_root_run_serves_both_fetch_doors_from_root_only_files() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_root_run_serves_both_fetch_doors_from_root_only_files",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let [auth, key, ca, signer] = root_only_fetch_files(dir.path())?;
    let config = vcon_fetch_config(dir.path(), &auth, &key, &ca, &signer)?;
    let mcp = [
        "--mcp",
        "--mcp-transport",
        "http",
        "--mcp-bind",
        "127.0.0.1:0",
        "--mcp-allow-vcon-fetch",
    ];
    let (early, out) = serve_vcon_fetch_door(&config, "vcon-fetch-both-doors", &mcp)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(early.is_none(), "the run stopped by itself:\n{stderr}");
    assert!(out.status.success(), "SIGTERM stops it cleanly:\n{stderr}");
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}

/// A drop user that does not exist stops a root run with exit 1 before any
/// secret is used, naming the user; with `--chroot` as well, because the
/// user is looked up before the chroot.
#[test]
fn a_root_run_with_a_missing_drop_user_stops_naming_it() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_root_run_with_a_missing_drop_user_stops_naming_it",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let (_fixture_dir, fixture) = world_readable_fixture("missing-drop-user")?;
    let out = root_run::sudo()?
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I"])
        .arg(&fixture)
        .args(["--user", "sipnab-no-such-user-ops2"])
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Failed to drop privileges: User 'sipnab-no-such-user-ops2' not found"),
        "{stderr}"
    );
    Ok(())
}

/// The same refusal under `--chroot`: the lookup runs before the new root,
/// so the message names the missing user, not a missing password database.
#[test]
fn a_chroot_run_with_a_missing_drop_user_stops_naming_it() -> Result<(), TestError> {
    if !sudo_available() {
        announce_skip(
            "a_chroot_run_with_a_missing_drop_user_stops_naming_it",
            "no passwordless sudo",
        );
        return Ok(());
    }
    let jail = tempfile::tempdir()?;
    let (_fixture_dir, fixture) = world_readable_fixture("missing-drop-user-chroot")?;
    let out = root_run::sudo()?
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I"])
        .arg(&fixture)
        .args(["--user", "sipnab-no-such-user-ops2", "--chroot"])
        .arg(jail.path())
        .output()?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("User 'sipnab-no-such-user-ops2' not found"),
        "{stderr}"
    );
    Ok(())
}

/// A revocation list only root can read stops a root run once it has dropped
/// privileges, with exit 2 and the reason.
///
/// The list is re-read whenever it changes, so it cannot be read once before
/// the drop like the other credential files. The verifier treats a list it
/// cannot read as empty, so a run that went on would accept a revoked token.
#[cfg(feature = "api")]
#[test]
fn a_root_only_revocation_list_stops_a_root_run_after_the_drop() -> Result<(), TestError> {
    let test = "a_root_only_revocation_list_stops_a_root_run_after_the_drop";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let files = root_only_files(dir.path(), &[("revoked", b"tok-1\n")])?;
    let (_fixture_dir, fixture) = world_readable_fixture("revoked-after-drop")?;
    let run_dir = dir_nobody_can_write()?;
    let child = root_run::sudo()?
        .current_dir(run_dir.path())
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-q", "-I", arg(&fixture)?, "--user", "nobody"])
        .args([
            "--api",
            "127.0.0.1:0",
            "--api-revoked-file",
            arg(&files[0])?,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    // Without the refusal the run serves until it is stopped; five seconds
    // is far past the moment the refusal is made.
    let (early, out) = wait_or_stop(child, std::time::Duration::from_secs(5))?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        early.is_some(),
        "the run went on serving with a revocation list it cannot read:\n{stderr}"
    );
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--api-revoked-file"), "{stderr}");
    assert!(stderr.contains("revokes nothing"), "{stderr}");
    Ok(())
}

// ── OPS-8: the drop user is resolved before the chroot ────────────────────

/// A root run with `--chroot` into a directory that holds no password
/// database still drops to `--user` and finishes.
///
/// The user used to be looked up after the chroot, inside the new root, where
/// `getpwnam_r` finds no `/etc/passwd`, so every `--chroot` run stopped with
/// `Failed to drop privileges: User 'nobody' not found` and exit 1.
#[test]
fn a_root_run_with_chroot_resolves_the_drop_user_first() -> Result<(), TestError> {
    let test = "a_root_run_with_chroot_resolves_the_drop_user_first";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let jail = tempfile::tempdir()?;
    let (_fixture_dir, fixture) = world_readable_fixture("chroot-drop")?;
    let out = root_run::sudo()?
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-q",
            "-I",
            fixture.to_str().ok_or("path is not UTF-8")?,
        ])
        .args(["--user", "nobody", "--chroot"])
        .arg(jail.path())
        .output()?;
    let _ = std::fs::remove_file(&fixture);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a --chroot run must resolve --user before it enters the new root; \
         it exited {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(!stderr.contains("not found"), "{stderr}");
    Ok(())
}

/// The host bundles sipnab looks for, as `tls_files::SYSTEM_CA_BUNDLES` lists
/// them on Linux; a test that needs one skips when the host has none.
#[cfg(feature = "hep")]
const HOST_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Run `sudo sipnab` with `--chroot` into an empty directory and a TLS HEP
/// sender to a port nothing listens on, with `extra` appended, or `None`
/// when the host has no CA bundle to find.
#[cfg(feature = "hep")]
fn chroot_tls_sender(test: &str, extra: &[&str]) -> Result<Option<Output>, TestError> {
    if !HOST_BUNDLES
        .iter()
        .any(|b| std::path::Path::new(b).is_file())
    {
        announce_skip(test, "this host has no system CA bundle to find");
        return Ok(None);
    }
    let jail = tempfile::tempdir()?;
    let (_fixture_dir, fixture) = world_readable_fixture(test)?;
    let out = root_run::sudo()?
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .env_remove("SSL_CERT_FILE")
        .args([
            "-N",
            "-q",
            "-I",
            arg(&fixture)?,
            "--user",
            "nobody",
            "--chroot",
        ])
        .arg(jail.path())
        .args(["--hep-send", "127.0.0.1:9", "--hep-send-transport", "tls"])
        .args(extra)
        .output()?;
    let _ = std::fs::remove_file(&fixture);
    Ok(Some(out))
}

/// A `--chroot` run whose TLS HEP sender names no `--hep-tls-ca` trusts the
/// host bundle it could see before the chroot.
///
/// The bundle used to be looked up after the chroot, inside the new root,
/// which holds none: `Failed to create HEP sender: no system CA bundle found;
/// name the collector's issuer with --hep-tls-ca`, exit 2. With the bundle
/// found, the sender gets as far as the connection, which nothing on port 9
/// accepts.
#[cfg(feature = "hep")]
#[test]
fn a_chroot_run_trusts_the_host_bundle_it_found_before_the_chroot() -> Result<(), TestError> {
    let test = "a_chroot_run_trusts_the_host_bundle_it_found_before_the_chroot";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let Some(out) = chroot_tls_sender(test, &[])? else {
        return Ok(());
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("no system CA bundle found"),
        "the bundle found before the chroot must be used inside it:\n{stderr}"
    );
    assert!(
        stderr.contains("Failed to establish a TLS session with '127.0.0.1:9'"),
        "the sender must reach the connection:\n{stderr}"
    );
    Ok(())
}

/// `--hep-tls-extra-ca` joins the host bundle, so a `--chroot` run that adds
/// one needs the bundle found before the chroot just the same.
#[cfg(feature = "hep")]
#[test]
fn a_chroot_run_with_an_extra_ca_still_joins_the_host_bundle() -> Result<(), TestError> {
    let test = "a_chroot_run_with_an_extra_ca_still_joins_the_host_bundle";
    if !sudo_available() {
        announce_skip(
            test,
            "passwordless sudo is not available, so sipnab cannot be run as root here",
        );
        return Ok(());
    }
    let extra = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/vcon-jose/fake_ca_root.crt"
    );
    let Some(out) = chroot_tls_sender(test, &["--hep-tls-extra-ca", extra])? else {
        return Ok(());
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("no system CA bundle found"), "{stderr}");
    assert!(
        stderr.contains("Failed to establish a TLS session with '127.0.0.1:9'"),
        "{stderr}"
    );
    Ok(())
}

/// The drop target resolved before a chroot drops the process inside it, and
/// the same lookup made inside the chroot fails, which is why it must come
/// first.
#[test]
fn a_drop_target_resolved_before_the_chroot_still_drops_inside_it() -> Result<(), TestError> {
    let jail = tempfile::tempdir()?;
    root_child_passes(
        "a_drop_target_resolved_before_the_chroot_still_drops_inside_it",
        "child_resolves_then_chroots_then_drops",
        &[(CHROOT_DIR_ENV, jail.path().as_os_str())],
    )?;
    Ok(())
}

/// Resolve `nobody`, chroot into an empty directory, show that a lookup there
/// fails, then drop to the target resolved first.
#[test]
#[ignore = "child role: spawned by a_drop_target_resolved_before_the_chroot_still_drops_inside_it"]
fn child_resolves_then_chroots_then_drops() -> Result<(), TestError> {
    if !spawned_by_parent("child_resolves_then_chroots_then_drops") {
        return Ok(());
    }
    let jail = std::env::var_os(CHROOT_DIR_ENV).ok_or("the parent passes the new root")?;
    let (uid, gid) = account_ids("nobody")?;
    let target = sipnab::privilege::resolve_drop_target(Some("nobody"), false)?
        .ok_or("a root process with a user to drop to resolves a target")?;
    assert_eq!(
        (target.uid(), target.gid()),
        (uid, gid),
        "the target is the account the password database names"
    );

    sipnab::privilege::do_chroot(std::path::Path::new(&jail))?;
    let inside = sipnab::privilege::resolve_drop_target(Some("nobody"), false);
    // On Linux the account database is files under `/`, so inside the new
    // root the lookup finds nothing: the failure OPS-8 hit. macOS answers
    // `getpwnam` from opendirectoryd over IPC, and CI measured the lookup
    // succeeding inside the chroot there, so only the drop below is asserted.
    #[cfg(target_os = "linux")]
    assert!(
        inside.is_err(),
        "inside a root with no /etc/passwd the lookup must fail; that failure \
         is why the target is resolved first. Got {inside:?}"
    );
    #[cfg(not(target_os = "linux"))]
    let _ = inside;

    sipnab::privilege::drop_to(&target)?;
    let (ruid, rgid, euid, egid) = credentials();
    assert_eq!(
        (ruid, rgid, euid, egid),
        (uid, gid, uid, gid),
        "the drop inside the chroot reached the account resolved outside it"
    );
    println!("{CHILD_COMPLETE}");
    Ok(())
}

// ── OPS2: every file of a set is read after the drop ──────────────────────

/// Frames of a capture that holds no SIP: UDP from 192.0.2.1 to
/// 198.51.100.1, `count` of them, the first `start_us` after the writer's
/// base second and each `step_us` after the one before.
fn udp_frames(count: u64, start_us: u64, step_us: u64) -> Vec<(Vec<u8>, u64)> {
    let frame = pcap_build::udp_frame([192, 0, 2, 1], [198, 51, 100, 1], 40000, 40002, b"ops2");
    (0..count)
        .map(|i| (frame.clone(), start_us + i * step_us))
        .collect()
}

/// The bytes of a classic pcap holding `frames`, written through `scratch`.
fn pcap_bytes(scratch: &std::path::Path, frames: &[(Vec<u8>, u64)]) -> Result<Vec<u8>, TestError> {
    pcap_build::write_pcap_at(scratch, frames, 1)?;
    let bytes = std::fs::read(scratch)?;
    std::fs::remove_file(scratch)?;
    Ok(bytes)
}

/// The first file of a set a `--replay` run spends 1.5 seconds in: two
/// frames 1.5 seconds apart. Every file after it is reached well after the
/// privilege drop, whatever the scheduler does.
fn slow_first(scratch: &std::path::Path) -> Result<Vec<u8>, TestError> {
    pcap_bytes(scratch, &udp_frames(2, 0, 1_500_000))
}

/// A later file of the set: three frames starting 1.6 seconds after the
/// first file's first frame, plus 20 milliseconds per `index` so several of
/// them keep one order.
fn later(scratch: &std::path::Path, index: u64) -> Result<Vec<u8>, TestError> {
    pcap_bytes(scratch, &udp_frames(3, 1_600_000 + index * 20_000, 10))
}

/// Removes a directory as root when it drops, for a directory a root run
/// may leave root-owned files in: this runner could not remove them.
struct RootRemoves(std::path::PathBuf);

impl Drop for RootRemoves {
    fn drop(&mut self) {
        if let Ok(mut rm) = root_run::sudo() {
            let _ = rm.args(["rm", "-rf", "--"]).arg(&self.0).status();
        }
    }
}

/// A directory every user may create entries in, as `/tmp` is (mode 1777),
/// given to a root run as its `TMPDIR`, so what the run leaves there can be
/// listed.
fn scratch_tmpdir() -> Result<(tempfile::TempDir, RootRemoves), TestError> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777))?;
    let cleanup = RootRemoves(dir.path().to_path_buf());
    Ok((dir, cleanup))
}

/// Run sipnab as root, through `sudo -n env`, with `SIPNAB_LOG=info` and
/// `TMPDIR=tmpdir`, from a working directory `nobody` can write.
fn root_sipnab(tmpdir: &std::path::Path, args: &[&std::ffi::OsStr]) -> Result<Output, TestError> {
    let run_dir = dir_nobody_can_write()?;
    let mut tmp = std::ffi::OsString::from("TMPDIR=");
    tmp.push(tmpdir);
    Ok(root_run::sudo()?
        .current_dir(run_dir.path())
        .args(["env", "SIPNAB_LOG=info"])
        .arg(tmp)
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .output()?)
}

/// Assert that a run read all `files` of its set to their end, skipped none,
/// and exited 0.
fn assert_read_in_full(out: &Output, files: usize) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the run must read its whole set and exit 0; it exited {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains(&format!("{files} of {files} file(s) read in full")),
        "every file of the set must be read in full:\n{stderr}"
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    assert!(!stderr.contains("Skipping"), "{stderr}");
}

/// The entries left in `dir`.
fn entries(dir: &std::path::Path) -> Result<Vec<String>, TestError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(names)
}

/// Skip a root gate when this runner cannot reach root, announcing it.
fn root_unavailable(test: &str) -> bool {
    if sudo_available() {
        return false;
    }
    announce_skip(
        test,
        "passwordless sudo is not available, so sipnab cannot be run as root here",
    );
    true
}

/// **A root run reads a root-only member it reaches after the drop.**
///
/// Only the first file read used to be opened before the drop; every later
/// one was opened by path as `nobody` and skipped with `Permission denied`.
/// `--replay` holds the reader in the first file for 1.5 seconds, so the
/// second is reached after the drop on every run.
#[test]
fn a_root_run_reads_a_root_only_member_it_reaches_after_the_drop() -> Result<(), TestError> {
    if root_unavailable("a_root_run_reads_a_root_only_member_it_reaches_after_the_drop") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let files = root_only_files(
        dir.path(),
        &[
            ("a.pcap", &slow_first(&scratch)?),
            ("b.pcap", &later(&scratch, 0)?),
        ],
    )?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    Ok(())
}

/// The shape the defect was reported in: no `--replay`, and a first file
/// large enough (300,000 frames) that the reader is still in it when the run
/// drops to `nobody`.
#[test]
fn a_root_run_reads_every_root_only_member_after_a_large_first_file() -> Result<(), TestError> {
    if root_unavailable("a_root_run_reads_every_root_only_member_after_a_large_first_file") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let big = pcap_bytes(&scratch, &udp_frames(300_000, 0, 1))?;
    let small = pcap_bytes(&scratch, &udp_frames(3, 86_400_000_000, 10))?;
    let files = root_only_files(dir.path(), &[("big.pcap", &big), ("small.pcap", &small)])?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Read 300003 packets"), "{stderr}");
    Ok(())
}

/// A `--chroot` run reads every member too: after the chroot the members'
/// paths do not resolve at all, whoever the process is.
#[test]
fn a_chrooted_root_run_reads_every_root_only_member() -> Result<(), TestError> {
    if root_unavailable("a_chrooted_root_run_reads_every_root_only_member") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let files = root_only_files(
        dir.path(),
        &[
            ("a.pcap", &slow_first(&scratch)?),
            ("b.pcap", &later(&scratch, 0)?),
        ],
    )?;
    let jail = dir_nobody_can_write()?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
            "--chroot".as_ref(),
            jail.path().as_os_str(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    Ok(())
}

/// `--cores` reads the same set from reader threads, and opens it before
/// its own drop: every root-only member is read there as well.
#[test]
fn a_cores_root_run_reads_every_root_only_member() -> Result<(), TestError> {
    if root_unavailable("a_cores_root_run_reads_every_root_only_member") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let files = root_only_files(
        dir.path(),
        &[
            ("a.pcap", &slow_first(&scratch)?),
            ("b.pcap", &later(&scratch, 0)?),
        ],
    )?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--cores".as_ref(),
            "2".as_ref(),
            "--json-dialogs".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    Ok(())
}

/// `count` root-only files, the first one [`slow_first`], in `dir`.
fn root_only_set(dir: &std::path::Path, count: u64) -> Result<Vec<std::path::PathBuf>, TestError> {
    let scratch = dir.join("scratch.pcap");
    let mut named: Vec<(String, Vec<u8>)> = vec![("f000.pcap".to_string(), slow_first(&scratch)?)];
    for i in 1..count {
        named.push((format!("f{i:03}.pcap"), later(&scratch, i)?));
    }
    let refs: Vec<(&str, &[u8])> = named
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    root_only_files(dir, &refs)
}

/// Run sipnab as root under `sh -c 'ulimit <limits>; exec ...'`, reading
/// `-I dir` with `--replay`, dropping to `nobody`.
fn root_sipnab_under_limit(
    limits: &str,
    dir: &std::path::Path,
    tmpdir: &std::path::Path,
) -> Result<Output, TestError> {
    let run_dir = dir_nobody_can_write()?;
    let mut tmp = std::ffi::OsString::from("TMPDIR=");
    tmp.push(tmpdir);
    Ok(root_run::sudo()?
        .current_dir(run_dir.path())
        .args(["env", "SIPNAB_LOG=info"])
        .arg(tmp)
        .args(["sh", "-c"])
        .arg(format!("ulimit {limits} && exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--replay", "-I"])
        .arg(dir)
        .args(["--user", "nobody"])
        .output()?)
}

/// A set that does not fit under the soft open-file limit, and does under
/// the hard one, raises the soft limit and is read in full: 30 files and 64
/// descriptors of headroom against a soft limit of 40.
#[test]
fn a_root_run_raises_its_soft_open_file_limit_to_hold_its_set() -> Result<(), TestError> {
    if root_unavailable("a_root_run_raises_its_soft_open_file_limit_to_hold_its_set") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    root_only_set(dir.path(), 30)?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab_under_limit("-S -n 40", dir.path(), tmpdir.path())?;
    assert_read_in_full(&out, 30);
    Ok(())
}

/// A set that does not fit under the hard open-file limit is refused before
/// anything is read, with exit 2 and the limit named, instead of losing the
/// files that would not open.
#[test]
fn a_root_run_refuses_a_set_over_its_hard_open_file_limit() -> Result<(), TestError> {
    if root_unavailable("a_root_run_refuses_a_set_over_its_hard_open_file_limit") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    root_only_set(dir.path(), 30)?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab_under_limit("-n 40", dir.path(), tmpdir.path())?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("30 input file(s)") && stderr.contains("40 open files"),
        "the refusal names the set and the limit:\n{stderr}"
    );
    assert!(!stderr.contains("Read "), "nothing was read:\n{stderr}");
    Ok(())
}

// ── OPS2: archive members a root run extracts ─────────────────────────────

/// A root-only `.tar.gz` in `dir` holding [`slow_first`] and [`later`].
fn root_only_archive(dir: &std::path::Path) -> Result<std::path::PathBuf, TestError> {
    let scratch = dir.join("scratch.pcap");
    let a = slow_first(&scratch)?;
    let b = later(&scratch, 0)?;
    let archive = tar_build::gzip(&tar_build::tar(&[
        tar_build::Entry::file("a.pcap", &a),
        tar_build::Entry::file("b.pcap", &b),
    ]))?;
    Ok(root_only_files(dir, &[("set.tar.gz", &archive)])?.remove(0))
}

/// **A root run reads every member of a root-only archive.** The members
/// are extracted before the drop, as root, into a 0700 directory as 0600
/// files; a member reached after the drop could not be opened by `nobody`.
#[test]
fn a_root_run_reads_every_member_of_a_root_only_archive() -> Result<(), TestError> {
    if root_unavailable("a_root_run_reads_every_member_of_a_root_only_archive") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let archive = root_only_archive(dir.path())?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    Ok(())
}

/// A root-only compressed capture (`.pcap.gz`) is unwrapped the same way,
/// into one extracted member, and is read when reached after the drop.
#[test]
fn a_root_run_reads_a_root_only_compressed_member_after_the_drop() -> Result<(), TestError> {
    if root_unavailable("a_root_run_reads_a_root_only_compressed_member_after_the_drop") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let compressed = tar_build::gzip(&later(&scratch, 0)?)?;
    let files = root_only_files(
        dir.path(),
        &[
            ("a.pcap", &slow_first(&scratch)?),
            ("b.pcap.gz", &compressed),
        ],
    )?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    Ok(())
}

/// A root run whose `TMPDIR` sits inside a directory the drop user cannot
/// enter removes its extraction before the drop: `nobody` could not reach
/// the directory to remove it at exit. macOS gives root such a `TMPDIR`
/// (its per-user directory under `/var/folders`, mode 0700), and the macOS runner's
/// tests found the extraction left there.
#[test]
fn a_root_run_whose_tmpdir_the_drop_user_cannot_reach_leaves_nothing() -> Result<(), TestError> {
    if root_unavailable("a_root_run_whose_tmpdir_the_drop_user_cannot_reach_leaves_nothing") {
        return Ok(());
    }
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir()?;
    let archive = root_only_archive(dir.path())?;
    // A private directory (0700, this runner's), holding a scratch TMPDIR
    // anyone may write: the scratch is writable, but `nobody` cannot reach it.
    let private = tempfile::tempdir()?;
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700))?;
    let tmp = private.path().join("T");
    std::fs::create_dir(&tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o1777))?;
    let _cleanup = RootRemoves(tmp.clone());
    let out = root_sipnab(
        &tmp,
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_read_in_full(&out, 2);
    assert_eq!(
        entries(&tmp)?,
        Vec::<String>::new(),
        "an extraction the drop user cannot reach must be gone when the run ends:\n{stderr}"
    );
    Ok(())
}

/// A root run removes what it extracted: the extraction directory was made
/// by root, and the run that must remove it at exit runs as `nobody`.
#[test]
fn a_root_run_leaves_no_extracted_member_behind() -> Result<(), TestError> {
    if root_unavailable("a_root_run_leaves_no_extracted_member_behind") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let archive = root_only_archive(dir.path())?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        entries(tmpdir.path())?,
        Vec::<String>::new(),
        "the extraction directory must be gone when the run ends:\n{stderr}"
    );
    Ok(())
}

/// A root run whose root-only archive breaks off inside a member is
/// refused, naming it, and leaves no extraction directory behind.
#[test]
fn a_root_run_refuses_a_truncated_root_only_archive_and_leaves_nothing() -> Result<(), TestError> {
    if root_unavailable("a_root_run_refuses_a_truncated_root_only_archive_and_leaves_nothing") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    // A tar.gz cut off inside its second member: extraction starts, writes
    // the first member, then fails.
    let scratch = dir.path().join("scratch.pcap");
    let a = later(&scratch, 0)?;
    let b = slow_first(&scratch)?;
    let mut bad = tar_build::gzip(&tar_build::tar(&[
        tar_build::Entry::file("a.pcap", &a),
        tar_build::Entry::file("b.pcap", &b),
    ]))?;
    bad.truncate(bad.len() * 3 / 4);
    let archive = root_only_files(dir.path(), &[("set.tar.gz", &bad)])?.remove(0);
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a corrupt archive must not read:\n{stderr}"
    );
    assert!(
        stderr.contains("set.tar.gz"),
        "the refusal names the archive:\n{stderr}"
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    assert_eq!(
        entries(tmpdir.path())?,
        Vec::<String>::new(),
        "a refused archive leaves no extraction directory:\n{stderr}"
    );
    Ok(())
}

/// A root run whose later root-only member is not a capture is refused at
/// startup, naming that member and its format, not a permission the drop
/// took away: the set is checked as root, before the drop.
#[test]
fn a_root_run_refuses_a_later_root_only_member_that_is_not_a_capture() -> Result<(), TestError> {
    if root_unavailable("a_root_run_refuses_a_later_root_only_member_that_is_not_a_capture") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let files = root_only_files(
        dir.path(),
        &[
            ("a.pcap", &slow_first(&scratch)?),
            ("b.pcap", b"this is not a capture file at all\n"),
        ],
    )?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a set with a non-capture must not run:\n{stderr}"
    );
    assert!(
        stderr.contains("b.pcap") && stderr.contains("unknown file format"),
        "the refusal names the member and its format:\n{stderr}"
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    assert!(
        !stderr.contains("Dropped privileges"),
        "refused before the drop:\n{stderr}"
    );
    Ok(())
}

/// A `--chroot` run reads every member of an archive and removes the
/// extraction too: after the chroot its path does not resolve.
#[test]
fn a_chrooted_root_run_reads_an_archive_and_removes_its_extraction() -> Result<(), TestError> {
    if root_unavailable("a_chrooted_root_run_reads_an_archive_and_removes_its_extraction") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let archive = root_only_archive(dir.path())?;
    let jail = dir_nobody_can_write()?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--replay".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
            "--chroot".as_ref(),
            jail.path().as_os_str(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    assert_eq!(
        entries(tmpdir.path())?,
        Vec::<String>::new(),
        "the extraction must be gone"
    );
    Ok(())
}

/// A `--cores` run, which drops on its own path, removes its extraction too.
#[test]
fn a_cores_root_run_leaves_no_extracted_member_behind() -> Result<(), TestError> {
    if root_unavailable("a_cores_root_run_leaves_no_extracted_member_behind") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let archive = root_only_archive(dir.path())?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--cores".as_ref(),
            "2".as_ref(),
            "--json-dialogs".as_ref(),
            "-I".as_ref(),
            archive.as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    assert_read_in_full(&out, 2);
    assert_eq!(
        entries(tmpdir.path())?,
        Vec::<String>::new(),
        "the extraction must be gone"
    );
    Ok(())
}

// ── EMBEDDED-SECRETS-AFTER-DROP: TLS secrets embedded in the input ─────────

/// The bytes of a pcapng holding one UDP frame and a Decryption Secrets
/// Block with one TLS key-log line, built from repeated bytes.
#[cfg(feature = "tls")]
fn pcapng_with_dsb(scratch: &std::path::Path) -> Result<Vec<u8>, TestError> {
    let frame = pcap_build::udp_frame([192, 0, 2, 1], [198, 51, 100, 1], 40000, 40002, b"ops2");
    let dsb = format!("CLIENT_RANDOM {} {}\n", "0a".repeat(32), "0b".repeat(48));
    pcap_build::write_pcapng_with_dsb(scratch, &dsb, &frame)?;
    let bytes = std::fs::read(scratch)?;
    std::fs::remove_file(scratch)?;
    Ok(bytes)
}

/// The line a run logs when the secret embedded in `file` loaded.
#[cfg(feature = "tls")]
fn embedded_secret_loaded(out: &Output) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the run must finish; it exited {:?}:\n{stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains("TLS decryption active: 1 secret(s) from embedded DSB"),
        "the secret embedded in the root-only input must load:\n{stderr}"
    );
}

/// **A root run loads the TLS secrets embedded in a root-only input.** They
/// were read after the drop, as `nobody`, and silently lost: the run read
/// the capture in full and never logged a TLS line.
#[cfg(feature = "tls")]
#[test]
fn a_root_run_loads_tls_secrets_embedded_in_a_root_only_member() -> Result<(), TestError> {
    if root_unavailable("a_root_run_loads_tls_secrets_embedded_in_a_root_only_member") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let bytes = pcapng_with_dsb(&dir.path().join("scratch.pcapng"))?;
    let files = root_only_files(dir.path(), &[("dsb.pcapng", &bytes)])?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    embedded_secret_loaded(&out);
    Ok(())
}

/// The secrets of a later member of a set load too, not only the first's.
#[cfg(feature = "tls")]
#[test]
fn a_root_run_loads_tls_secrets_embedded_in_a_later_root_only_member() -> Result<(), TestError> {
    if root_unavailable("a_root_run_loads_tls_secrets_embedded_in_a_later_root_only_member") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let scratch = dir.path().join("scratch.pcap");
    let first = pcap_bytes(&scratch, &udp_frames(3, 0, 10))?;
    let bytes = pcapng_with_dsb(&dir.path().join("scratch.pcapng"))?;
    let files = root_only_files(dir.path(), &[("a.pcap", &first), ("b.pcapng", &bytes)])?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "-I".as_ref(),
            files[1].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    embedded_secret_loaded(&out);
    Ok(())
}

/// A `--chroot` run loads them as well: after the chroot the input's path
/// does not resolve at all.
#[cfg(feature = "tls")]
#[test]
fn a_chrooted_root_run_loads_tls_secrets_embedded_in_its_input() -> Result<(), TestError> {
    if root_unavailable("a_chrooted_root_run_loads_tls_secrets_embedded_in_its_input") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let bytes = pcapng_with_dsb(&dir.path().join("scratch.pcapng"))?;
    let files = root_only_files(dir.path(), &[("dsb.pcapng", &bytes)])?;
    let jail = dir_nobody_can_write()?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
            "--chroot".as_ref(),
            jail.path().as_os_str(),
        ],
    )?;
    embedded_secret_loaded(&out);
    Ok(())
}

/// A pcapng with secrets inside a root-only archive: its member is
/// extracted as root, and removed before a chroot, so its secrets must be
/// read before either.
#[cfg(feature = "tls")]
#[test]
fn a_chrooted_root_run_loads_tls_secrets_embedded_in_an_archive_member() -> Result<(), TestError> {
    if root_unavailable("a_chrooted_root_run_loads_tls_secrets_embedded_in_an_archive_member") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let bytes = pcapng_with_dsb(&dir.path().join("scratch.pcapng"))?;
    let archive = tar_build::gzip(&tar_build::tar(&[tar_build::Entry::file(
        "dsb.pcapng",
        &bytes,
    )]))?;
    let files = root_only_files(dir.path(), &[("set.tar.gz", &archive)])?;
    let jail = dir_nobody_can_write()?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
            "--chroot".as_ref(),
            jail.path().as_os_str(),
        ],
    )?;
    embedded_secret_loaded(&out);
    Ok(())
}

/// `--wireshark` names a root-only input in the `tshark -r` command it
/// prints and opens nothing: the command is for the operator to run, so the
/// input is read by whoever runs it, not by the user this run dropped to.
#[test]
fn a_root_run_prints_the_tshark_command_for_a_root_only_input() -> Result<(), TestError> {
    if root_unavailable("a_root_run_prints_the_tshark_command_for_a_root_only_input") {
        return Ok(());
    }
    let dir = tempfile::tempdir()?;
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sip_call.pcap"
    ))?;
    let files = root_only_files(dir.path(), &[("call.pcap", &fixture)])?;
    let (tmpdir, _cleanup) = scratch_tmpdir()?;
    let out = root_sipnab(
        tmpdir.path(),
        &[
            "-N".as_ref(),
            "--wireshark".as_ref(),
            "-I".as_ref(),
            files[0].as_os_str(),
            "--user".as_ref(),
            "nobody".as_ref(),
        ],
    )?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stdout.contains(&format!("tshark -r '{}'", files[0].display())),
        "the command names the input:\n{stdout}\n{stderr}"
    );
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    Ok(())
}
