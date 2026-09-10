// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the path sandbox actually DOES, observed from the process it was
//! installed on.
//!
//! A sandbox that failed to install and a sandbox that installed and permits
//! everything are indistinguishable from outside. Every gate here exists
//! because of that sentence: each one asserts an effect on the filesystem —
//! this open succeeded, that one came back `EACCES` — rather than a return
//! value the code under test chose.
//!
//! **Why so much of this runs in a child process.** A Landlock domain cannot
//! be removed, widened, or exited. A test runner that installed one would
//! confine every test after it, permanently, and the failures would land
//! somewhere else entirely. `tests/privilege_drop_test.rs` solved the same
//! problem for the privilege drop and its machinery is reused rather than
//! reinvented: `#[ignore]`d child roles a parent spawns, `CHILD_COMPLETE` on
//! stdout so an early return cannot read as success, and skips announced on
//! the real stderr because libtest throws away `eprintln!` from a passing
//! test.
//!
//! **Nothing here can kill a process.** Landlock denies an open; it does not
//! signal. That is the whole reason it ships before seccomp, whose failure
//! mode on a mis-derived allowlist is `SIGSYS` on a capture box.

#![cfg(all(unix, feature = "native"))]

use sipnab::sandbox::{self, LandlockStatus, SandboxPaths};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::Command;

/// Set by a parent on every child role it spawns. A child that finds it unset
/// was started by hand and must not confine whatever process is hosting it.
const CHILD_ENV: &str = "SIPNAB_SANDBOX_CHILD";

/// The directory a child's ruleset grants.
const INSIDE_ENV: &str = "SIPNAB_SANDBOX_INSIDE";

/// A file outside it, which the ruleset must put out of reach.
const OUTSIDE_ENV: &str = "SIPNAB_SANDBOX_OUTSIDE";

/// Printed by a child role only after every one of its assertions has passed.
///
/// Load-bearing: without it a child that took an early return would still exit
/// 0 and the parent would read that silence as proof.
const CHILD_COMPLETE: &str = "sipnab-sandbox-child-complete";

/// Announce a skipped gate on this process's real stderr.
///
/// NOT `eprintln!`. libtest swaps the print machinery's sink per test and
/// discards the buffer when the test passes, so a skip announced that way is
/// read by nobody.
fn announce_skip(test: &str, reason: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "NOTICE: sandbox gate `{test}` did NOT run — {reason}."
    );
}

/// Whether this kernel can enforce a Landlock ruleset at all.
fn landlock_available() -> bool {
    sandbox::kernel_abi().is_ok()
}

/// Two directories: one the ruleset will grant, one it will not, each holding
/// a readable marker file.
fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let inside = tmp.path().join("inside");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&inside).expect("create inside");
    std::fs::create_dir_all(&outside).expect("create outside");
    let inside_file = inside.join("readable");
    let outside_file = outside.join("secret");
    std::fs::write(&inside_file, b"granted").expect("write inside");
    std::fs::write(&outside_file, b"ungranted").expect("write outside");
    (tmp, inside_file, outside_file)
}

/// Run one `#[ignore]`d child role in a fresh process.
fn run_child(role: &str, inside: &std::path::Path, outside: &std::path::Path) -> (bool, String) {
    let exe = std::env::current_exe().expect("this test binary");
    let out = Command::new(exe)
        .args(["--exact", role, "--ignored", "--nocapture"])
        .env(CHILD_ENV, role)
        .env(INSIDE_ENV, inside)
        .env(OUTSIDE_ENV, outside)
        .output()
        .expect("spawn the child role");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success() && text.contains(CHILD_COMPLETE), text)
}

/// The parent-supplied paths, or a refusal to run outside a parent.
fn child_paths() -> Option<(PathBuf, PathBuf)> {
    let inside = std::env::var_os(INSIDE_ENV)?;
    let outside = std::env::var_os(OUTSIDE_ENV)?;
    std::env::var_os(CHILD_ENV)?;
    Some((PathBuf::from(inside), PathBuf::from(outside)))
}

/// Set `PR_SET_NO_NEW_PRIVS`, which Landlock requires without `CAP_SYS_ADMIN`.
fn set_no_new_privs() -> bool {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes no pointers and cannot be unset.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
}

/// Whether reading `path` failed specifically because permission was denied.
///
/// The errno is checked, not merely the failure: a path that vanished would
/// also fail to open, and reporting that as confinement would be a gate
/// passing for the wrong reason.
fn denied(path: &std::path::Path) -> Result<bool, String> {
    match std::fs::read(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(true),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

// ── Child roles. Each confines itself; none may run in the runner. ──────────

/// Install over `inside`, then prove both halves.
///
/// Both, because a child that could open nothing would pass the denial half
/// for the wrong reason — a broken fixture and a working sandbox look the same
/// from one assertion.
#[test]
#[ignore = "child role: installs a Landlock domain that cannot be removed"]
fn child_enforced_grants_inside_and_denies_outside() {
    let Some((inside, outside)) = child_paths() else {
        return;
    };
    assert!(set_no_new_privs(), "PR_SET_NO_NEW_PRIVS failed");

    let granted_dir = inside.parent().expect("inside has a parent").to_path_buf();
    let status = sandbox::install(&SandboxPaths {
        inputs: vec![granted_dir],
        ..SandboxPaths::default()
    });
    assert!(
        status.is_enforced(),
        "the ruleset did not install: {status:?}"
    );

    assert!(
        std::fs::read(&inside).is_ok(),
        "a granted path must stay readable, or the denial below proves nothing"
    );
    assert_eq!(
        denied(&outside),
        Ok(true),
        "a path outside the ruleset must come back EACCES"
    );
    println!("{CHILD_COMPLETE}");
}

/// Without the sandbox, the same outside path opens.
///
/// The mutation control. A denial test that passes with the sandbox removed is
/// testing something other than the sandbox.
#[test]
#[ignore = "child role: the unsandboxed control for the gate above"]
fn child_unsandboxed_reaches_both_paths() {
    let Some((inside, outside)) = child_paths() else {
        return;
    };
    assert!(
        std::fs::read(&inside).is_ok(),
        "the fixture's granted file must be readable"
    );
    assert!(
        std::fs::read(&outside).is_ok(),
        "with no ruleset installed the outside path must open; if it does not, \
         the denial gate would pass without a sandbox"
    );
    println!("{CHILD_COMPLETE}");
}

/// Without `PR_SET_NO_NEW_PRIVS` the install refuses, and says which control
/// is missing.
///
/// Landlock requires the flag without `CAP_SYS_ADMIN`. The install reads it
/// back rather than trusting an earlier step to have set it, because that step
/// runs in another function and a control asserted at a distance is a control
/// assumed.
#[test]
#[ignore = "child role: deliberately omits no-new-privs"]
fn child_without_no_new_privs_is_refused_by_name() {
    let Some((inside, _outside)) = child_paths() else {
        return;
    };
    let granted_dir = inside.parent().expect("inside has a parent").to_path_buf();
    let status = sandbox::install(&SandboxPaths {
        inputs: vec![granted_dir],
        ..SandboxPaths::default()
    });
    match status {
        LandlockStatus::Failed { reason } => {
            assert!(
                reason.contains("NO_NEW_PRIVS"),
                "the refusal must name the missing control: {reason}"
            );
        }
        other => panic!("expected a refusal naming no-new-privs, got {other:?}"),
    }
    // And nothing was confined: the outside path is still reachable.
    assert!(
        std::fs::read(inside).is_ok(),
        "a refused install must leave the process unconfined"
    );
    println!("{CHILD_COMPLETE}");
}

/// A plan naming nothing that exists is refused rather than installed.
///
/// A ruleset that governs the filesystem and grants nothing denies every file
/// the run needs. Refusing turns a broken capture into a reported
/// non-installation, which is the difference between an outage and a log line.
#[test]
#[ignore = "child role: installs nothing and must say so"]
fn child_with_an_empty_plan_is_refused_rather_than_confined() {
    let Some((inside, _outside)) = child_paths() else {
        return;
    };
    assert!(set_no_new_privs(), "PR_SET_NO_NEW_PRIVS failed");
    let absent = inside.parent().expect("parent").join("does-not-exist");
    let status = sandbox::install(&SandboxPaths {
        inputs: vec![absent],
        ..SandboxPaths::default()
    });
    match status {
        LandlockStatus::Failed { reason } => {
            assert!(reason.contains("deny every file"), "{reason}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        std::fs::read(inside).is_ok(),
        "a refused install must leave the process unconfined"
    );
    println!("{CHILD_COMPLETE}");
}

/// A write outside the ruleset is denied too, not only a read.
///
/// Reads and writes are separate rights, and a ruleset that granted write
/// everywhere while bounding reads would still let a defect drop a payload on
/// disk.
#[test]
#[ignore = "child role: installs a Landlock domain that cannot be removed"]
fn child_enforced_denies_a_write_outside_the_ruleset() {
    let Some((inside, outside)) = child_paths() else {
        return;
    };
    assert!(set_no_new_privs(), "PR_SET_NO_NEW_PRIVS failed");
    let granted_dir = inside.parent().expect("parent").to_path_buf();
    let status = sandbox::install(&SandboxPaths {
        output_dirs: vec![granted_dir.clone()],
        ..SandboxPaths::default()
    });
    assert!(status.is_enforced(), "did not install: {status:?}");

    assert!(
        std::fs::write(granted_dir.join("new-file"), b"ok").is_ok(),
        "a granted directory must stay writable"
    );
    let outside_dir = outside.parent().expect("parent");
    match std::fs::write(outside_dir.join("payload"), b"x") {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        other => panic!("a write outside the ruleset must be denied, got {other:?}"),
    }
    println!("{CHILD_COMPLETE}");
}

// ── Parents. These run in the runner and spawn the roles above. ─────────────

/// The gate: a granted path opens and an ungranted one does not.
#[test]
fn a_path_outside_the_ruleset_is_denied_and_one_inside_is_not() {
    if !landlock_available() {
        announce_skip(
            "a_path_outside_the_ruleset_is_denied_and_one_inside_is_not",
            "this kernel has no Landlock",
        );
        return;
    }
    let (_tmp, inside, outside) = fixture();
    let (ok, log) = run_child(
        "child_enforced_grants_inside_and_denies_outside",
        &inside,
        &outside,
    );
    assert!(ok, "the enforced child did not complete:\n{log}");
}

/// The same assertion with the sandbox removed must fail the other way.
///
/// Run unconditionally, including on kernels without Landlock: it proves the
/// fixture is reachable to begin with, so a denial elsewhere is the sandbox
/// and not a broken temp directory.
#[test]
fn without_the_sandbox_the_same_paths_are_reachable() {
    let (_tmp, inside, outside) = fixture();
    let (ok, log) = run_child("child_unsandboxed_reaches_both_paths", &inside, &outside);
    assert!(ok, "the unsandboxed control did not complete:\n{log}");
}

/// An install without no-new-privs is refused by name.
#[test]
fn an_install_without_no_new_privs_is_refused_by_name() {
    if !landlock_available() {
        announce_skip(
            "an_install_without_no_new_privs_is_refused_by_name",
            "this kernel has no Landlock",
        );
        return;
    }
    let (_tmp, inside, outside) = fixture();
    let (ok, log) = run_child(
        "child_without_no_new_privs_is_refused_by_name",
        &inside,
        &outside,
    );
    assert!(ok, "the no-new-privs child did not complete:\n{log}");
}

/// An empty plan is refused rather than installed.
#[test]
fn an_empty_plan_is_refused_rather_than_confining_the_process() {
    if !landlock_available() {
        announce_skip(
            "an_empty_plan_is_refused_rather_than_confining_the_process",
            "this kernel has no Landlock",
        );
        return;
    }
    let (_tmp, inside, outside) = fixture();
    let (ok, log) = run_child(
        "child_with_an_empty_plan_is_refused_rather_than_confined",
        &inside,
        &outside,
    );
    assert!(ok, "the empty-plan child did not complete:\n{log}");
}

/// Writes are bounded as well as reads.
#[test]
fn a_write_outside_the_ruleset_is_denied() {
    if !landlock_available() {
        announce_skip(
            "a_write_outside_the_ruleset_is_denied",
            "this kernel has no Landlock",
        );
        return;
    }
    let (_tmp, inside, outside) = fixture();
    let (ok, log) = run_child(
        "child_enforced_denies_a_write_outside_the_ruleset",
        &inside,
        &outside,
    );
    assert!(ok, "the write-denial child did not complete:\n{log}");
}

/// The ABI query answers, and its refusal is worded for an operator.
///
/// Runs on every host and asserts the shape of both answers, because the
/// degradation path is the one most machines take and an empty reason there
/// would be the silence this module exists to prevent.
#[test]
fn the_kernel_query_answers_with_an_abi_or_a_reason() {
    match sandbox::kernel_abi() {
        Ok(abi) => {
            assert!(abi >= 1, "a supported kernel reports at least ABI 1");
            assert!(
                abi <= sandbox::MAX_KNOWN_ABI,
                "an ABI newer than this code knows must be clamped, got {abi}"
            );
        }
        Err(LandlockStatus::Unsupported { reason }) => {
            assert!(!reason.trim().is_empty(), "a refusal must say why");
            assert!(
                reason.len() > 20,
                "the reason must be a sentence an operator can act on: {reason}"
            );
        }
        Err(other) => panic!("the query must answer or report unsupported, got {other:?}"),
    }
}

/// This host's own posture, reported rather than assumed.
///
/// Not an assertion about Landlock — an assertion that the module's answer
/// matches the kernel's own LSM list, so a query returning a stale or invented
/// answer is caught on whichever host the suite runs.
#[test]
fn the_query_agrees_with_the_kernels_own_lsm_list() {
    let Ok(lsm) = std::fs::read_to_string("/sys/kernel/security/lsm") else {
        announce_skip(
            "the_query_agrees_with_the_kernels_own_lsm_list",
            "this kernel exposes no LSM list to compare against",
        );
        return;
    };
    let listed = lsm.split(',').any(|s| s.trim() == "landlock");
    assert_eq!(
        listed,
        landlock_available(),
        "the kernel lists `{}` and the query says available={}",
        lsm.trim(),
        landlock_available()
    );
}

// ── The flag, driven through the real binary ────────────────────────────────

/// The compiled `sipnab` beside this test binary.
fn sipnab_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test binary path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sipnab")
}

/// A fixture capture every one of these can read.
fn fixture_capture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples/codec-negotiation.pcap")
}

/// Run the binary over the fixture with the given sandbox argument.
fn run_sipnab(args: &[&str]) -> (bool, String) {
    let bin = sipnab_bin();
    if !bin.is_file() {
        return (true, String::from("BINARY-ABSENT"));
    }
    let capture = fixture_capture();
    let mut cmd = Command::new(bin);
    cmd.args(["-N", "-I"]).arg(&capture).args(args);
    let out = cmd.output().expect("run sipnab");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// Without the flag, nothing is installed and nothing is said about it.
///
/// The default must not change any existing run. A line on every capture
/// would train an operator to skip the one that matters.
#[test]
fn the_default_run_installs_nothing_and_reports_nothing() {
    let (ok, log) = run_sipnab(&[]);
    if log == "BINARY-ABSENT" {
        announce_skip(
            "the_default_run_installs_nothing_and_reports_nothing",
            "the sipnab binary is not built beside this test",
        );
        return;
    }
    assert!(ok, "the default run must succeed:\n{log}");
    assert!(
        !log.contains("path sandbox"),
        "a run that asked for nothing must say nothing about a sandbox:\n{log}"
    );
}

/// `--sandbox best-effort` captures whatever the kernel offers, and says which.
///
/// One assertion holds on every host and that is the point: on a kernel with
/// Landlock the line reads ENFORCED, on one without it reads NOT active, and
/// in both cases the capture completes. Never refusing to capture because a
/// hardening feature was unavailable is the standing rule this follows.
#[test]
fn best_effort_captures_and_reports_either_way() {
    let (ok, log) = run_sipnab(&["--sandbox", "best-effort"]);
    if log == "BINARY-ABSENT" {
        announce_skip(
            "best_effort_captures_and_reports_either_way",
            "the sipnab binary is not built beside this test",
        );
        return;
    }
    assert!(ok, "best-effort must never stop a capture:\n{log}");
    assert!(
        log.contains("packets captured"),
        "the capture must have run:\n{log}"
    );
    assert!(
        log.contains("path sandbox"),
        "a run that asked for a sandbox must be told what it got:\n{log}"
    );
    if landlock_available() {
        assert!(
            log.contains("ENFORCED"),
            "on this kernel it should be on:\n{log}"
        );
    } else {
        assert!(
            log.contains("NOT active"),
            "on this kernel it cannot be:\n{log}"
        );
    }
}

/// `--sandbox required` refuses on a kernel that cannot, and captures on one
/// that can.
///
/// Both arms, on whichever host runs the suite. A test asserting only the
/// refusal would pass on every machine without Landlock while saying nothing
/// about the machines the flag exists for.
#[test]
fn required_refuses_only_when_no_sandbox_is_in_force() {
    let (ok, log) = run_sipnab(&["--sandbox", "required"]);
    if log == "BINARY-ABSENT" {
        announce_skip(
            "required_refuses_only_when_no_sandbox_is_in_force",
            "the sipnab binary is not built beside this test",
        );
        return;
    }
    if landlock_available() {
        assert!(ok, "a kernel that can sandbox must still capture:\n{log}");
        assert!(log.contains("packets captured"), "{log}");
    } else {
        assert!(!ok, "a kernel that cannot sandbox must refuse:\n{log}");
        assert!(
            log.contains("Refusing to capture"),
            "the refusal must say so plainly:\n{log}"
        );
        assert!(
            !log.contains("packets captured"),
            "a refused run must not have captured anything:\n{log}"
        );
    }
}
