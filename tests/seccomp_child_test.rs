// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the syscall filter actually DOES, observed from the process carrying
//! it.
//!
//! # The two things that have to be proved together
//!
//! A logging filter allows every call, so from outside it is indistinguishable
//! from **no filter at all**. Asserting "the process survived" proves nothing
//! on its own — a filter that failed to load survives just as well.
//!
//! So every gate here comes in a pair:
//!
//! 1. **The shipped shape does not interfere.** A child installs the logging
//!    filter and then does ordinary work: opens a file, reads it, writes to
//!    stdout, and exits 0. Nothing is denied and nothing is killed.
//! 2. **The same program, with the fallback swapped for `SECCOMP_RET_ERRNO`,
//!    denies.** Same builder, same install path, same architecture token —
//!    only the action differs. If that child's syscall comes back `EPERM`, the
//!    program compiled, loaded and ran. Which means the logging child's
//!    program did too, and its silence is the kernel allowing rather than the
//!    kernel never being asked.
//!
//! Nothing here ever builds a killing filter. `SECCOMP_RET_KILL_PROCESS` is
//! what the design document reserves for a derived allowlist, and a test that
//! reached for it to prove liveness would be shipping the exact hazard the
//! sequencing exists to defer.
//!
//! # Why child processes
//!
//! A seccomp filter cannot be removed, loosened or exited, and it is inherited
//! by every thread and child that follows. A runner that installed one would
//! carry it through every remaining test in the binary. The machinery is
//! `tests/sandbox_test.rs`'s, reused rather than reinvented: `#[ignore]`d
//! child roles a parent spawns, a completion marker on stdout so an early
//! return cannot read as success, and skips announced on the real stderr
//! because libtest discards `eprintln!` from a passing test.

#![cfg(all(unix, feature = "native"))]

use std::io::Write as _;
use std::process::Command;

use sipnab::seccomp::{self, SeccompMode, SeccompStatus};

/// Set by a parent on every child role. A child that finds it unset was
/// started by hand and must not install a filter on whatever is hosting it.
const CHILD_ENV: &str = "SIPNAB_SECCOMP_CHILD";

/// Printed by a child role only after every one of its assertions has passed.
const CHILD_COMPLETE: &str = "sipnab-seccomp-child-complete";

/// Exit code from the denying child when its excluded syscall came back
/// `EPERM`, which is the filter working.
const EXIT_REFUSED_AS_EXPECTED: i32 = 42;

/// Exit code when the excluded syscall SUCCEEDED, so no filter was in force.
const EXIT_NOT_REFUSED: i32 = 43;

/// Exit code when the call failed for some reason other than the filter's own
/// action, which proves nothing either way.
const EXIT_WRONG_ERRNO: i32 = 44;

/// Announce a skipped gate on this process's real stderr.
///
/// NOT `eprintln!`: libtest swaps the print sink per test and throws the
/// buffer away when the test passes, so a skip announced that way reaches
/// nobody.
fn announce_skip(test: &str, reason: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "NOTICE: seccomp gate `{test}` did NOT run — {reason}."
    );
}

/// Whether this build knows an `AUDIT_ARCH` token and runs on Linux.
///
/// Without the token a filter would match nothing, and a logging filter that
/// matches nothing is silent — which reads exactly like a clean run.
fn seccomp_possible() -> bool {
    cfg!(target_os = "linux") && seccomp::audit_arch().is_some()
}

/// Run one `#[ignore]`d child role in a fresh process.
fn run_child(role: &str) -> (bool, String) {
    let exe = std::env::current_exe().expect("this test binary");
    let out = Command::new(exe)
        .args(["--exact", role, "--ignored", "--nocapture"])
        .env(CHILD_ENV, role)
        .output()
        .expect("spawn the child role");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success() && text.contains(CHILD_COMPLETE), text)
}

/// Whether this process was started as a child role by a parent above.
///
/// Gated with the roles it serves rather than left always-compiled. Off Linux
/// there are no child roles, so an ungated definition is dead code and
/// `scripts/check-non-linux.sh` fails the push — which it did, and which is
/// the same platform-split-written-twice shape that broke main once already.
/// One split, in one place: this function exists exactly where its callers do.
#[cfg(target_os = "linux")]
fn in_child_role() -> bool {
    std::env::var_os(CHILD_ENV).is_some()
}

// ── Child roles. Each filters itself; none may run in the runner. ───────────

/// Install the shipped logging filter, then do ordinary work.
///
/// The work matters. A child that installed a filter and immediately exited
/// would exercise one syscall and prove nothing about the calls a capture
/// makes — so this opens, reads, writes and allocates, all of which the
/// filter's fallback action must allow.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "child role: installs a seccomp filter that cannot be removed"]
fn child_logging_filter_denies_nothing() {
    if !in_child_role() {
        return;
    }
    assert!(
        !seccomp::in_filter_mode(),
        "this process was already filtered before the gate installed anything, so          whatever it observes afterwards is somebody else's filter"
    );
    let status = seccomp::install(SeccompMode::Log);
    assert_eq!(
        status,
        SeccompStatus::Logging,
        "the logging filter did not install: {status:?}"
    );
    assert!(
        seccomp::in_filter_mode(),
        "install reported success and the kernel reports no filter mode; an          allowing filter and no filter are indistinguishable by their effects,          so this readback is the only thing between the two"
    );

    // Ordinary work, after the filter is in force.
    let dir = tempfile::tempdir().expect("tempdir after the filter");
    let path = dir.path().join("marker");
    std::fs::write(&path, b"seccomp logging allows this").expect("write after the filter");
    let read = std::fs::read(&path).expect("read after the filter");
    assert_eq!(read, b"seccomp logging allows this");
    let mut sink = Vec::with_capacity(1024);
    sink.extend_from_slice(&read);
    assert_eq!(sink.len(), read.len());
    // A socket, because libpcap's calls are what this exists to record.
    let listener = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind after the filter");
    assert!(listener.local_addr().is_ok());

    // A thread created AFTER the filter inherits it, which is the easy half.
    let after = std::thread::spawn(seccomp::in_filter_mode)
        .join()
        .expect("the thread finishes");
    assert!(after, "a thread created under the filter is not filtered");

    println!("{CHILD_COMPLETE}");
}

/// The SHIPPED install covers a thread that already existed.
///
/// The pair below proves the thread-sync flag is what does that; this proves
/// `install` actually passes it. Both are needed: the flag could be correct and
/// unused, which is the shape of every control that quietly does nothing.
///
/// A logging filter denies nothing, so its coverage cannot be observed from an
/// effect. It can be READ: `prctl(PR_GET_SECCOMP)` is per-thread, so a sibling
/// asking about itself answers the question directly.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "child role: installs a seccomp filter that cannot be removed"]
fn child_shipped_install_reaches_a_thread_that_already_existed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    if !in_child_role() {
        return;
    }
    let installed = Arc::new(AtomicBool::new(false));
    let verdict = Arc::new(AtomicU8::new(0xff));
    let go = Arc::clone(&installed);
    let seen = Arc::clone(&verdict);
    let sibling = std::thread::spawn(move || {
        while !go.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        seen.store(u8::from(seccomp::in_filter_mode()), Ordering::Release);
    });
    assert!(
        !seccomp::in_filter_mode(),
        "this process was filtered before the gate installed anything"
    );

    let status = seccomp::install(SeccompMode::Log);
    assert_eq!(status, SeccompStatus::Logging, "install said {status:?}");
    installed.store(true, Ordering::Release);
    sibling.join().expect("the sibling thread finishes");

    assert_eq!(
        verdict.load(Ordering::Acquire),
        1,
        "the shipped install left a thread that already existed unfiltered.          sipnab installs after the capture thread is spawned, so that thread's          syscalls — the libpcap ones an allowlist most needs — would go          unrecorded"
    );
    println!("{CHILD_COMPLETE}");
}

/// The same builder and the same install path, with a denying fallback.
///
/// The positive control, and the only thing in this file that proves a filter
/// was ever loaded.
///
/// **It reports through the exit status, and that is not a stylistic choice.**
/// The first version allow-listed the syscalls the Rust runtime needs so the
/// child could `println!` its verdict. That list was hand-derived on aarch64,
/// was incomplete for x86_64 glibc, and turned main red in CI — which is
/// precisely the hazard `docs/design/syscall-sandbox.md` §3 puts the enforcing
/// filter last to avoid, arrived at in a test rather than on a capture box.
///
/// So nothing between the install and the exit touches libc: the allowlist is
/// `exit_group` alone, the verdict is the exit code, and the child cannot need
/// a syscall the author forgot on an architecture the author does not have.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "child role: installs a seccomp filter that cannot be removed"]
fn child_denying_filter_refuses_the_call_it_left_out() {
    if !in_child_role() {
        return;
    }
    let arch = seccomp::audit_arch().expect("an architecture token");
    let deny = seccomp::SECCOMP_RET_ERRNO | u32::from(u16::try_from(libc::EPERM).expect("EPERM"));
    let prog =
        seccomp::build_program(arch, &[libc::SYS_exit_group], deny).expect("the program builds");
    // Deliberately WITHOUT thread sync. This filter denies almost everything,
    // and libtest's other threads are not the subject — synchronizing it onto
    // them would race their next syscall against this one's exit and could end
    // the process with somebody else's failure.
    seccomp::load(&prog, 0).expect("the kernel accepts the program");

    // SAFETY: `getpriority` takes two integers and touches no memory.
    let rc = unsafe { libc::syscall(libc::SYS_getpriority, 0, 0) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let verdict = if rc != -1 {
        EXIT_NOT_REFUSED
    } else if errno == libc::EPERM {
        EXIT_REFUSED_AS_EXPECTED
    } else {
        EXIT_WRONG_ERRNO
    };
    // SAFETY: `exit_group` never returns and touches no memory. Called raw
    // because every other way out of this process needs a syscall the filter
    // refuses.
    unsafe { libc::syscall(libc::SYS_exit_group, i64::from(verdict)) };
    unreachable!("exit_group returned");
}

/// A sibling thread that already exists when the filter installs.
///
/// The claim under test is about `clone` semantics, and it decides whether the
/// instrument records anything useful. sipnab installs at the END of bootstrap,
/// after the capture thread — the thread running libpcap, whose syscalls an
/// allowlist most needs — has already been spawned. If a filter installed on
/// the main thread does not reach a sibling that already exists, the derivation
/// misses exactly the calls it was built for.
///
/// **Driven with an ALLOWING filter and read back, not with a denial.** A
/// denying filter needs an allowlist covering everything the runtime does next,
/// and a hand-derived allowlist is the hazard this whole feature is sequenced
/// around — the first version of this helper carried one, was incomplete for
/// x86_64 glibc, and turned main red. `prctl(PR_GET_SECCOMP)` is per-thread, so
/// the sibling can answer the question about itself while every syscall it
/// needs still works.
#[cfg(target_os = "linux")]
fn sibling_thread_is_filtered(flags: libc::c_uint) -> Option<bool> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    let installed = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(AtomicU8::new(0xff));
    let go = Arc::clone(&installed);
    let seen = Arc::clone(&observed);
    let sibling = std::thread::spawn(move || {
        while !go.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        seen.store(u8::from(seccomp::in_filter_mode()), Ordering::Release);
    });

    let arch = seccomp::audit_arch()?;
    // No allowlist and a logging action: nothing is denied, so nothing the
    // sibling needs can go missing.
    let prog =
        seccomp::build_program(arch, &[], seccomp::SECCOMP_RET_LOG).expect("the program builds");
    seccomp::load(&prog, flags).expect("the kernel accepts the program");
    installed.store(true, Ordering::Release);
    sibling.join().expect("the sibling thread finishes");
    Some(observed.load(Ordering::Acquire) == 1)
}

/// With thread sync, a thread that already existed is covered.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "child role: installs a seccomp filter that cannot be removed"]
fn child_sibling_thread_is_covered_with_thread_sync() {
    if !in_child_role() {
        return;
    }
    let filtered = sibling_thread_is_filtered(seccomp::SECCOMP_FILTER_FLAG_TSYNC)
        .expect("an architecture token");
    assert!(
        filtered,
        "the sibling thread reports no filter, so the install did not reach a \
         thread that already existed. sipnab installs after the capture thread \
         is spawned, so an uncovered sibling means the instrument records \
         nothing from the thread running libpcap"
    );
    println!("{CHILD_COMPLETE}");
}

/// Without it, that thread escapes — which is why the flag is not optional.
///
/// The control, and the reason the flag is in the shipped path rather than left
/// to a default. Without this half the gate above would pass on a kernel that
/// covered siblings anyway, and the flag could be dropped unnoticed.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "child role: installs a seccomp filter that cannot be removed"]
fn child_sibling_thread_escapes_without_thread_sync() {
    if !in_child_role() {
        return;
    }
    let filtered = sibling_thread_is_filtered(0).expect("an architecture token");
    assert!(
        !filtered,
        "the sibling was covered without the thread-sync flag, so this kernel \
         covers existing threads on its own and the pair of gates no longer \
         says what it claims"
    );
    println!("{CHILD_COMPLETE}");
}

// ── Parents ─────────────────────────────────────────────────────────────────

/// The shipped filter allows the work a capture does.
#[test]
fn the_logging_filter_interferes_with_nothing() {
    if !seccomp_possible() {
        announce_skip(
            "the_logging_filter_interferes_with_nothing",
            "this target has no seccomp",
        );
        return;
    }
    let (ok, out) = run_child("child_logging_filter_denies_nothing");
    assert!(ok, "the logging child did not complete:\n{out}");
}

/// The shipped install reaches threads that already existed.
#[cfg(target_os = "linux")]
#[test]
fn the_shipped_install_covers_the_capture_thread_shape() {
    if !seccomp_possible() {
        announce_skip(
            "the_shipped_install_covers_the_capture_thread_shape",
            "this target has no seccomp",
        );
        return;
    }
    let (ok, out) = run_child("child_shipped_install_reaches_a_thread_that_already_existed");
    assert!(ok, "the sibling-coverage child did not complete:\n{out}");
}

/// A filter built the same way, with a denying action, denies.
///
/// Without this the file's other gate is unfalsifiable.
#[test]
fn a_filter_built_this_way_is_genuinely_loaded() {
    if !seccomp_possible() {
        announce_skip(
            "a_filter_built_this_way_is_genuinely_loaded",
            "this target has no seccomp",
        );
        return;
    }
    let exe = std::env::current_exe().expect("this test binary");
    let out = Command::new(exe)
        .args([
            "--exact",
            "child_denying_filter_refuses_the_call_it_left_out",
            "--ignored",
            "--nocapture",
        ])
        .env(
            CHILD_ENV,
            "child_denying_filter_refuses_the_call_it_left_out",
        )
        .output()
        .expect("spawn the denying child");
    let code = out.status.code();
    assert_ne!(
        code,
        Some(EXIT_NOT_REFUSED),
        "the syscall left off the allowlist succeeded, so no filter was in \
         force and every other gate in this file proves nothing"
    );
    assert_ne!(
        code,
        Some(EXIT_WRONG_ERRNO),
        "the call failed for a reason other than the filter's own action"
    );
    assert_eq!(
        code,
        Some(EXIT_REFUSED_AS_EXPECTED),
        "the denying child exited {code:?}; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The two children differ only in the action, and the outcomes differ.
///
/// The pair read as one statement: same builder, same loader, same
/// architecture, one allows and one refuses. That is what makes the allowing
/// child's silence evidence rather than an absence of evidence.
#[test]
fn the_two_children_share_everything_but_the_action() {
    if !seccomp_possible() {
        announce_skip(
            "the_two_children_share_everything_but_the_action",
            "this target has no seccomp",
        );
        return;
    }
    let logging = seccomp::build_program(
        seccomp::audit_arch().expect("token"),
        &[],
        seccomp::SECCOMP_RET_LOG,
    )
    .expect("builds");
    let denying = seccomp::build_program(
        seccomp::audit_arch().expect("token"),
        &[],
        seccomp::SECCOMP_RET_ERRNO | u32::from(u16::try_from(libc::EPERM).expect("EPERM")),
    )
    .expect("builds");
    assert_eq!(
        logging.len(),
        denying.len(),
        "the two programs must differ only in an action"
    );
    let differing: Vec<usize> = logging
        .iter()
        .zip(&denying)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        differing,
        vec![logging.len() - 2],
        "the programs differ at {differing:?}, not only at the fallback action"
    );
}

/// The filter reaches threads that already existed, and only with the flag.
///
/// One test for the pair, because the pair is one statement: the same program,
/// the same install path, the same sibling, and the verdict turns on the flag
/// alone.
#[cfg(target_os = "linux")]
#[test]
fn thread_sync_is_what_reaches_a_thread_that_already_existed() {
    if !seccomp_possible() {
        announce_skip(
            "thread_sync_is_what_reaches_a_thread_that_already_existed",
            "this target has no seccomp",
        );
        return;
    }
    let (covered, out) = run_child("child_sibling_thread_is_covered_with_thread_sync");
    assert!(covered, "the thread-sync child did not complete:\n{out}");
    let (escapes, out) = run_child("child_sibling_thread_escapes_without_thread_sync");
    assert!(escapes, "the no-thread-sync child did not complete:\n{out}");
}

/// Off never installs anything, on any platform.
#[test]
fn off_is_off_everywhere() {
    assert_eq!(seccomp::install(SeccompMode::Off), SeccompStatus::Disabled);
}

// ── The flag, through the binary an operator runs ───────────────────────────

/// `--seccomp log` installs the filter and the capture still completes.
///
/// The library gates above prove the filter works; this proves the FLAG is
/// wired to it. They are different claims, and the second is the one an
/// operator makes. A run that installed nothing and a run that installed a
/// filter produce identical output, so the startup line is the only
/// observable — which is exactly why the line is required to exist and
/// required to say what it does not protect.
#[cfg(target_os = "linux")]
#[test]
fn the_flag_installs_the_filter_and_the_capture_still_finishes() {
    if !seccomp_possible() {
        announce_skip(
            "the_flag_installs_the_filter_and_the_capture_still_finishes",
            "this target has no seccomp",
        );
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--seccomp",
            "log",
        ])
        .output()
        .expect("run sipnab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the run did not finish under a logging filter: {stderr}"
    );
    assert!(
        stderr.contains("Syscall logging on"),
        "the flag produced no startup line, which is the only way an operator          can tell the filter installed: {stderr}"
    );
    for phrase in ["protects nothing", "ausearch", "dmesg", "auditctl -s"] {
        assert!(
            stderr.contains(phrase),
            "the startup line omits {phrase:?}: {stderr}"
        );
    }
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("INVITE"),
        "the capture produced no output under the filter, so something was denied"
    );
}

/// Without the flag, nothing is installed and nothing is said.
///
/// The control. Without it the gate above would pass on a build that printed
/// the line unconditionally and never installed anything.
#[test]
fn no_flag_installs_nothing_and_says_nothing() {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", "tests/fixtures/sip_call.pcap"])
        .output()
        .expect("run sipnab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the plain run failed: {stderr}");
    assert!(
        !stderr.contains("Syscall logging"),
        "a run that asked for nothing announced a syscall filter: {stderr}"
    );
}

// ── The three owed for the hand-derived allowlist that broke CI ─────────────

/// This file's own source, for the structural gates below.
fn this_file() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/seccomp_child_test.rs"),
    )
    .expect("this test file is in the tree")
}

/// No child role hand-lists the syscalls a runtime needs.
///
/// The defect this replaces: two roles installed a DENYING filter and
/// allow-listed, by hand, everything the Rust runtime needed in order to print
/// a verdict. The list was derived on aarch64, was short on x86_64 glibc, and
/// the child died before it could say anything — which is `docs/design/
/// syscall-sandbox.md` §3.2's stated failure mode, met in CI.
///
/// The rule is a bound rather than a ban, because one entry is the design: the
/// denying role allows `exit_group` and nothing else, so the child cannot need
/// a call the author forgot on an architecture the author does not have.
#[test]
fn no_child_role_hand_lists_what_a_runtime_needs() {
    let src = this_file();
    let mut oversized = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let Some(rest) = line.split_once("build_program(").map(|(_, r)| r) else {
            continue;
        };
        // The allowlist argument is the slice literal on this line, if any.
        let Some(list) = rest.split_once('[').and_then(|(_, r)| r.split_once(']')) else {
            continue;
        };
        let entries = list.0.split(',').filter(|e| !e.trim().is_empty()).count();
        if entries > 1 {
            oversized.push(format!("line {}: {entries} entries", i + 1));
        }
    }
    assert!(
        oversized.is_empty(),
        "a child role allow-lists more than one syscall: {oversized:?}. A list \
         written by hand is right on the architecture it was written on and \
         wrong on the other, which is the failure this file exists to avoid \
         rather than reproduce"
    );
}

/// The denying role reaches its exit without touching libc again.
///
/// Linux-gated, and not because the reasoning is platform-specific: the role it
/// inspects is, and the search strings below name libc symbols that
/// `platform_split_test`'s line-oriented scanner cannot tell from real uses. A
/// scanner that cannot see quoting is the same shape as the marker extractor in
/// `fixture_isolation_test`, and the answer is the same — do not write the
/// pattern where a line-oriented reader will trip over it.
///
/// The property that makes it portable: between the `load` that puts the filter
/// in force and the raw `exit_group` that reports the verdict, the only libc
/// call is the one under test. Anything else would be a call the filter refuses
/// and the author has to have predicted.
#[cfg(target_os = "linux")]
#[test]
fn the_denying_role_touches_only_the_call_under_test_after_installing() {
    let src = this_file();
    let start = src
        .find("fn child_denying_filter_refuses_the_call_it_left_out")
        .expect("the denying role is in this file");
    let body = &src[start..];
    let after_load = body
        .find("seccomp::load(")
        .and_then(|i| body[i..].find('\n').map(|j| i + j))
        .expect("the role loads a filter");
    // The raw exit CALL, not the allowlist entry naming the same syscall —
    // that entry sits before the load and slicing to it inverts the range.
    let exit = after_load
        + body[after_load..]
            .find("libc::syscall(libc::SYS_exit_group")
            .expect("the role exits through a raw exit_group");
    let between = &body[after_load..exit];
    // CALLS, not references. `libc::EPERM` is a constant and makes no syscall;
    // counting it would make this gate fail on correct code, which is its own
    // way of teaching people to delete a gate. libc spells functions in
    // lowercase and constants in upper, so the case of the first character
    // after `libc::` is the discriminator.
    let calls: Vec<&str> = between
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| {
            l.match_indices("libc::").any(|(i, _)| {
                l[i + "libc::".len()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_lowercase)
            })
        })
        .collect();
    assert_eq!(
        calls.len(),
        1,
        "the denying role makes {} libc calls between installing the filter and \
         exiting; every one beyond the syscall under test is a call the filter \
         refuses and the author had to predict: {calls:?}",
        calls.len()
    );
    assert!(
        calls[0].contains("SYS_getpriority"),
        "the one call between install and exit is not the one under test: {calls:?}"
    );
}

/// The verdict travels in the exit status, never through the runtime.
///
/// A `println!` needs `write`, which needs the author to have allow-listed
/// `write` on both architectures — the exact mistake. The parent reads an exit
/// code instead, and this pins both halves so a future edit cannot quietly put
/// the verdict back through stdout.
#[test]
fn the_denying_roles_verdict_travels_in_the_exit_status() {
    let src = this_file();
    let start = src
        .find("fn child_denying_filter_refuses_the_call_it_left_out")
        .expect("the denying role is in this file");
    let end = start
        + src[start..]
            .find("\n#[cfg")
            .or_else(|| src[start..].find("\n/// "))
            .unwrap_or(src.len() - start);
    let body = &src[start..end];
    assert!(
        !body.contains("println!") && !body.contains(CHILD_COMPLETE),
        "the denying role reports through stdout, which needs a syscall it must \
         then allow-list on every architecture"
    );
    for code in [
        "EXIT_REFUSED_AS_EXPECTED",
        "EXIT_NOT_REFUSED",
        "EXIT_WRONG_ERRNO",
    ] {
        assert!(
            body.contains(code),
            "the role never produces {code}, so one outcome is indistinguishable \
             from another"
        );
    }
    assert_ne!(EXIT_REFUSED_AS_EXPECTED, EXIT_NOT_REFUSED);
    assert_ne!(EXIT_REFUSED_AS_EXPECTED, EXIT_WRONG_ERRNO);
    assert_ne!(EXIT_NOT_REFUSED, EXIT_WRONG_ERRNO);
}
