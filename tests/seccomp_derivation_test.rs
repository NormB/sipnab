// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The judge that decides whether a syscall derivation can be trusted.
//!
//! # Why this exists at all
//!
//! `docs/design/syscall-sandbox.md` §8 puts the enforcing filter last because a
//! mis-derived allowlist kills the process on a capture box during the incident
//! the capture was started for. Every other step of that design has shipped.
//! The last one is blocked on a question nobody had measured: **is the derived
//! set complete?**
//!
//! It was not, twice over, and neither failure announced itself.
//!
//! 1. **The log drops records under load.** Without an audit daemon they fall
//!    back to the kernel ring buffer, which rate limits and reports the loss as
//!    `callbacks suppressed`. A twenty-second capture emitted about 1,700
//!    records; 50 survived.
//! 2. **The log also drops records by age, silently.** The buffer wraps.
//!    Reading it after a run keeps only the last few hundred: that host holds
//!    about 454 audit lines, and three unrelated run shapes each returned 453
//!    to 455 — a number that describes the buffer, not any run. Reading
//!    afterwards gave 12 distinct syscalls where streaming gave 21.
//! 3. **And the set keeps growing.** Nine shapes into sipnab's own derivation,
//!    a `--report` run made an `ioctl` the previous eight never had. A filter
//!    built on the union of those eight would have killed every `--report`.
//!
//! So the script's answer is not a list. It is a verdict about whether a list
//! can be believed, and these are the tests of that verdict. The collector half
//! needs root, a network interface and a kernel log; the judge is a filter over
//! text, which is what makes it drivable here with logs this host could never
//! produce.

#![cfg(feature = "full")]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The script under test.
fn script() -> PathBuf {
    repo().join("scripts/derive-seccomp-allowlist.sh")
}

/// Run the judge over `log`, returning `(exit code, stdout)`.
fn classify(log: &str) -> Result<(i32, String), TestError> {
    let mut child = Command::new("sh")
        .arg(script())
        .arg("--classify")
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn the derivation judge: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("stdin")?
        .write_all(log.as_bytes())
        .map_err(|e| format!("write the log: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| format!("the judge finishes: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code().unwrap_or(-1), text))
}

/// One audit record, in the shape the kernel actually prints.
fn record(nr: u32) -> String {
    format!(
        "audit: type=1326 audit(1789088915.552:12): auid=1000 uid=0 pid=7 \
         comm=\"sipnab\" exe=\"/usr/bin/sipnab\" sig=0 arch=c000003e syscall={nr} \
         compat=0 ip=0x7f0 code=0x7ffc0000\n"
    )
}

/// A log of `shapes`, each a name and the syscalls it made.
fn log(shapes: &[(&str, &[u32])]) -> String {
    let mut out = String::new();
    for (name, nrs) in shapes {
        out.push_str(&format!("== SHAPE {name}\n"));
        for nr in *nrs {
            out.push_str(&record(*nr));
        }
    }
    out
}

/// A derivation whose last shapes added nothing is settled.
///
/// The positive control. Without it every refusal below could pass on a judge
/// that refuses everything, which is the shape of gate that gets deleted.
#[test]
fn a_set_that_stopped_growing_is_reported_as_settled() -> Result<(), TestError> {
    let (code, out) = classify(&log(&[
        ("offline", &[0, 1, 3, 257]),
        ("live", &[0, 1, 3]),
        ("report", &[1, 257]),
    ]))?;
    assert_eq!(code, 0, "a settled derivation was refused:\n{out}");
    assert!(out.contains("SETTLED"), "{out}");
    assert!(
        out.contains("0 1 3 257"),
        "the union is not reported in order:\n{out}"
    );
    Ok(())
}

/// Settled is not reported as complete.
///
/// The distinction this whole file turns on. Two quiet shapes mean these shapes
/// stopped finding calls, not that no shape would — and an operator who reads
/// "settled" as "done" enforces a list with a hole in it. The word has to carry
/// its own limit or it will be read as the stronger claim.
#[test]
fn settled_says_plainly_that_it_does_not_mean_complete() -> Result<(), TestError> {
    let (code, out) = classify(&log(&[("a", &[1]), ("b", &[1]), ("c", &[1])]))?;
    assert_eq!(code, 0);
    assert!(
        out.contains("not complete"),
        "the settled verdict does not disclaim completeness:\n{out}"
    );
    assert!(
        out.contains("kill"),
        "it does not say what an unexercised feature costs:\n{out}"
    );
    Ok(())
}

/// A set still growing at the last shape is refused.
///
/// The finding that blocked the enforcing filter: nine shapes in, a `--report`
/// run added a syscall the previous eight never made. A union that is still
/// climbing is not an allowlist, and the judge has to say so rather than hand
/// one over.
#[test]
fn a_set_still_growing_at_the_last_shape_is_refused() -> Result<(), TestError> {
    let (code, out) = classify(&log(&[("a", &[0, 1]), ("b", &[0, 1]), ("c", &[16])]))?;
    assert_eq!(code, 1, "a growing set was accepted:\n{out}");
    assert!(out.contains("NOT CONVERGED"), "{out}");
    assert!(
        out.contains("c") && out.contains("added: 16"),
        "the judge does not name the shape that added, so nobody can tell which \
         feature was missing:\n{out}"
    );
    Ok(())
}

/// One quiet shape is not enough, and the boundary is asserted.
///
/// An off-by-one here is the difference between a list that settled and one
/// that happened to repeat itself once. The pair pins both sides.
#[test]
fn one_quiet_shape_is_not_convergence_and_two_are() -> Result<(), TestError> {
    let (one, out_one) = classify(&log(&[("a", &[1]), ("b", &[2]), ("c", &[2])]))?;
    assert_eq!(
        one, 1,
        "a single quiet shape was accepted as convergence:\n{out_one}"
    );
    let (two, out_two) = classify(&log(&[("a", &[1]), ("b", &[2]), ("c", &[2]), ("d", &[2])]))?;
    assert_eq!(two, 0, "two quiet shapes were refused:\n{out_two}");
    Ok(())
}

/// A log the kernel suppressed records in is refused before anything else.
///
/// Order matters: a lossy log can easily LOOK settled, because the records that
/// would have added a syscall are the ones that went missing. So loss is judged
/// first and the union is never printed for one.
#[test]
fn a_log_that_lost_records_is_refused_and_no_list_is_offered() -> Result<(), TestError> {
    let mut lossy = log(&[("a", &[1]), ("b", &[1]), ("c", &[1])]);
    lossy.push_str("kauditd_printk_skb: 575 callbacks suppressed\n");
    let (code, out) = classify(&lossy)?;
    assert_eq!(code, 1, "a lossy log was accepted:\n{out}");
    assert!(out.contains("LOST"), "{out}");
    assert!(
        !out.contains("SETTLED"),
        "a lossy log was also called settled, which is the exact combination \
         that produces a short list somebody then enforces:\n{out}"
    );
    assert!(
        out.contains("printk_ratelimit"),
        "the refusal names no way to fix it:\n{out}"
    );
    Ok(())
}

/// A log with no records at all is a different refusal.
///
/// Distinct exit code on purpose. No records means the filter never installed,
/// or the log was read after the run rather than streamed during it — a
/// different mistake from losing some of it, and one with a different fix.
#[test]
fn a_log_with_no_records_is_told_apart_from_one_that_lost_some() -> Result<(), TestError> {
    let (code, out) = classify("[  0.000000] Linux version 6.12\nnothing to see\n")?;
    assert_eq!(
        code, 2,
        "an empty log was not distinguished from a lossy one:\n{out}"
    );
    assert!(out.contains("NO RECORDS"), "{out}");
    assert!(
        out.contains("streamed"),
        "the refusal does not mention the most likely cause, which is reading \
         the buffer after the run:\n{out}"
    );
    Ok(())
}

/// The judge reads the real record shape, not a simplified one.
///
/// The fixture guard. Every log above is built from [`record`], so if that
/// stopped matching what the kernel prints, every test here would go on passing
/// while the script matched nothing in the field. This pins the extraction
/// against a line copied from an actual `dmesg` on the lab VM.
#[test]
fn the_extraction_matches_a_line_the_kernel_really_printed() -> Result<(), TestError> {
    let real = "== SHAPE only\n\
        [1206801.923372] audit: type=1326 audit(1789088915.552:127): auid=1000 \
        uid=0 gid=0 ses=494 subj=unconfined pid=3347139 comm=\"sipnab\" \
        exe=\"/tmp/sipnab\" sig=0 arch=c000003e syscall=332 compat=0 \
        ip=0x7f41037e97b9 code=0x7ffc0000\n\
        == SHAPE b\n\
        [1206801.923400] audit: type=1326 audit(1789088915.552:128): syscall=332 \
        code=0x7ffc0000\n\
        == SHAPE c\n\
        [1206801.923500] audit: type=1326 audit(1789088915.552:129): syscall=332 \
        code=0x7ffc0000\n";
    let (code, out) = classify(real)?;
    assert_eq!(code, 0, "a real kernel line was not understood:\n{out}");
    assert!(
        out.contains("union is 1 syscall(s)"),
        "the syscall number was not extracted from a real record:\n{out}"
    );
    assert!(out.contains(" 332"), "{out}");
    Ok(())
}

/// The collector restores the rate limit it changed, on every exit path.
///
/// Structural, because the behavioral half needs root and a kernel log. Leaving
/// a host with `printk_ratelimit=0` is a slow way to fill somebody's disk, and
/// the failure is invisible until it is not — so the restore is on a trap that
/// covers signals, not on the last line of the happy path.
#[test]
fn the_collector_restores_the_rate_limit_it_changed() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let trap = src
        .lines()
        .find(|l| l.trim_start().starts_with("trap "))
        .unwrap_or_default();
    assert!(
        trap.contains("printk_ratelimit"),
        "nothing restores the rate limit on exit: {trap}"
    );
    for signal in ["EXIT", "INT", "TERM"] {
        assert!(
            trap.contains(signal),
            "the restore does not cover {signal}, so an interrupted derivation \
             leaves the host rate-limit-free: {trap}"
        );
    }
    // Code, not commentary. The header explains the setting at length, and
    // searching the whole file finds that prose first — the same
    // reading-the-wrong-text mistake that made an earlier gate compare against
    // an empty string.
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let set = code
        .find("sysctl -q kernel.printk_ratelimit=0")
        .ok_or("it lowers the limit")?;
    let trap_at = code.find("trap ").ok_or("it installs a trap")?;
    assert!(
        trap_at < set,
        "the limit is lowered before the restore is armed, so a signal in \
         between leaves it lowered"
    );
    Ok(())
}

/// The script is executable and names its two halves.
#[test]
fn the_script_is_runnable_and_documents_both_halves() -> Result<(), TestError> {
    let path = script();
    assert!(
        path.is_file(),
        "scripts/derive-seccomp-allowlist.sh is missing"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path)
            .map_err(|e| format!("stat: {e}"))?
            .permissions()
            .mode();
        assert!(mode & 0o111 != 0, "the script is not executable: {mode:o}");
    }
    let src = std::fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
    assert!(src.contains("--classify"), "the testable half is unnamed");
    assert!(
        src.contains("dmesg --follow"),
        "the collector does not stream, so it inherits both losses this file \
         exists to prevent"
    );
    Ok(())
}

/// The design document points at the script, and the script at the design.
///
/// A procedure written down in two places drifts; a procedure written down in
/// one and referenced from the other does not. The design owns the reasoning,
/// the script owns the steps, and each names the other so a reader landing on
/// either finds the half they need.
#[test]
fn the_design_document_and_the_script_name_each_other() -> Result<(), TestError> {
    let design = std::fs::read_to_string(repo().join("docs/design/syscall-sandbox.md"))
        .map_err(|e| format!("the design document is in the tree: {e}"))?;
    assert!(
        design.contains("derive-seccomp-allowlist.sh"),
        "the design document describes a derivation procedure and never names \
         the script that performs it"
    );
    let src = std::fs::read_to_string(script()).map_err(|e| format!("read: {e}"))?;
    assert!(
        src.contains("syscall-sandbox.md"),
        "the script performs a procedure and never names the document that \
         explains why it works that way"
    );
    Ok(())
}

// ── Three owed for shape markers clobbered by a shared stream ───────────────

/// The collector gives each shape its own stream.
///
/// Owed for a defect that made a still-growing set look settled — the one
/// verdict this script exists to refuse. The first version appended
/// `== SHAPE name` markers to the same file `dmesg --follow` was writing.
/// `dmesg` holds that file at its own offset and overwrote them, so every
/// shape's calls landed in the first shape, every later shape "added nothing",
/// and two quiet shapes appeared out of nowhere.
///
/// Structural because the behavior needs root and a kernel log: one writer per
/// file is the property, and two writers on one file is the defect.
#[test]
fn the_collector_gives_each_shape_its_own_stream() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    assert!(
        src.contains("dmesg --follow > \"$WORK/$name.log\""),
        "the collector does not stream each shape to its own file"
    );
    assert!(
        !src.contains(">> \"$STREAM\""),
        "something still appends to a file `dmesg --follow` is writing; that \
         text is overwritten and the shapes merge"
    );
    let combine = src
        .find("== SHAPE %s")
        .ok_or("the markers are written somewhere")?;
    let after = &src[combine..];
    assert!(
        after.contains("$COMBINED") || after.contains("COMBINED"),
        "the markers are not written into a combined log assembled after the \
         streams are closed"
    );
    Ok(())
}

/// The judge attributes calls to the shape that made them.
///
/// The second owed, and the property the clobbering destroyed. Three shapes
/// each making a different call must be reported as three shapes, each adding
/// its own — not as one shape that added everything and two that added nothing.
#[test]
fn the_judge_attributes_each_call_to_the_shape_that_made_it() -> Result<(), TestError> {
    let (code, out) = classify(&log(&[("first", &[1]), ("second", &[2]), ("third", &[3])]))?;
    assert_eq!(code, 1, "a set growing at every shape was accepted:\n{out}");
    for (shape, nr) in [("first", 1), ("second", 2), ("third", 3)] {
        assert!(
            out.contains(&format!("{shape} ")) && out.contains(&format!("added: {nr}")),
            "shape {shape} is not reported as the one that added {nr}:\n{out}"
        );
    }
    Ok(())
}

/// A merged log is refused rather than read as a settled one.
///
/// The third owed, and the exact shape the defect produced: everything in the
/// first shape, nothing in the rest. That LOOKS like convergence and is the
/// most dangerous thing this judge can be handed, so the reported attribution
/// has to make it visible — one shape carrying every call is the signature.
#[test]
fn a_log_where_every_call_landed_in_one_shape_is_visible_as_such() -> Result<(), TestError> {
    let (code, out) = classify(&log(&[
        ("first", &[1, 2, 3, 4]),
        ("second", &[]),
        ("third", &[]),
    ]))?;
    assert_eq!(
        code, 0,
        "the fixture must be the settled-looking shape:\n{out}"
    );
    assert!(
        out.contains("first") && out.contains("added: 1 2 3 4"),
        "the judge does not show that one shape carried every call, which is \
         what a merged log looks like:\n{out}"
    );
    assert!(
        out.contains("second") && out.contains("third"),
        "the shapes that added nothing are not listed, so a reader cannot see \
         that they contributed no records at all:\n{out}"
    );
    Ok(())
}

// ── Three owed for a restructure that moved a change above its trap ─────────

/// The collector cleans its workspace on every exit path.
///
/// Owed alongside the rate limit. The workspace is a `mktemp -d` full of
/// streamed kernel logs, and a derivation that is interrupted must leave
/// nothing behind — this repository's standing rule, and the reason the trap
/// covers signals rather than sitting on the happy path's last line.
#[test]
fn the_collector_cleans_its_workspace_on_every_exit_path() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let trap = src
        .lines()
        .find(|l| l.trim_start().starts_with("trap "))
        .unwrap_or_default();
    assert!(
        trap.contains("rm -rf") && trap.contains("WORK"),
        "the workspace is not removed on exit: {trap}"
    );
    for signal in ["EXIT", "INT", "TERM"] {
        assert!(
            trap.contains(signal),
            "the cleanup does not cover {signal}: {trap}"
        );
    }
    Ok(())
}

/// Everything the collector changes outside itself is undone by that trap.
///
/// The second owed, stated as a rule rather than a list: enumerate what the
/// script alters on the host, and require the trap to name each one. A
/// restructure added the workspace and moved the `sysctl` above the trap in the
/// same edit, so a rule that only knew about the rate limit would have caught
/// half of it.
#[test]
fn everything_the_collector_changes_is_named_in_its_trap() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let trap = code
        .lines()
        .find(|l| l.trim_start().starts_with("trap "))
        .unwrap_or_default();
    let mut changes = Vec::new();
    if code.contains("sysctl -q kernel.printk_ratelimit=0") {
        changes.push("printk_ratelimit");
    }
    if code.contains("mktemp -d") {
        changes.push("WORK");
    }
    assert!(
        changes.len() >= 2,
        "only {} host change(s) found; the scan has stopped matching and the \
         trap could be missing anything: {changes:?}",
        changes.len()
    );
    for change in changes {
        assert!(
            trap.contains(change),
            "the collector changes {change} and the trap does not undo it: {trap}"
        );
    }
    Ok(())
}

/// Nothing the collector changes happens before the trap is armed.
///
/// The third owed, and the one the restructure broke: a signal arriving between
/// a change and its trap leaves the change in place. Every alteration has to
/// come after the trap, and the rule is checked over all of them rather than
/// over the one that failed.
#[test]
fn no_change_happens_before_the_trap_is_armed() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let trap_at = code.find("trap ").ok_or("the collector installs a trap")?;
    for change in ["sysctl -q kernel.printk_ratelimit=0", "mktemp -d"] {
        let at = code
            .find(change)
            .ok_or_else(|| format!("the collector no longer does {change}"))?;
        // `mktemp -d` may precede the trap: the trap needs its name. Creating a
        // temporary directory is not a change to the HOST, and the shell has to
        // know the path before it can promise to remove it.
        if change == "mktemp -d" {
            continue;
        }
        assert!(
            trap_at < at,
            "{change} happens at {at}, before the trap at {trap_at}; a signal in \
             between leaves it applied"
        );
    }
    Ok(())
}

// ── Owed for a collector that read only the kernel log ──────────────────────
//
// On a host with an audit daemon the kernel hands seccomp records to that
// daemon and they land in its log (`/var/log/audit/audit.log`, searchable with
// `ausearch -m SECCOMP`), not in the kernel ring buffer. The collector streamed
// only `dmesg --follow`, so on such a host every run ended in NO RECORDS and no
// allowlist could be derived there. The source is now chosen by a function
// over `auditctl -s` output, and the one record parser reads both formats.

/// Run one of the script's text-only modes over `input`.
fn mode(flag: &str, input: &str) -> Result<(i32, String), TestError> {
    let mut child = Command::new("sh")
        .arg(script())
        .arg(flag)
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn the script in {flag}: {e}"))?;
    // A mode that exits without reading its input closes the pipe; that is
    // the script's answer, and the exit code and text below report it.
    match child
        .stdin
        .as_mut()
        .ok_or("stdin")?
        .write_all(input.as_bytes())
    {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            return Err(format!("write the input: {e}").into());
        }
        _ => {}
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("the script finishes: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.code().unwrap_or(-1), text))
}

/// `auditctl -s` from a host where a daemon is connected, as auditctl prints it.
const AUDITCTL_WITH_DAEMON: &str = "enabled 1\nfailure 1\npid 1043\nrate_limit 0\n\
    backlog_limit 8192\nlost 0\nbacklog 0\nbacklog_wait_time 60000\n\
    backlog_wait_time_actual 0\nloginuid_immutable 0 unlocked\n";

/// One audit-log SECCOMP record, in the enriched format auditd writes by
/// default: the raw fields, a group separator (0x1d), then the interpreted
/// fields, where `SYSCALL=` carries the name rather than the number.
fn audit_record(nr: u32, name: &str) -> String {
    format!(
        "type=SECCOMP msg=audit(1794138579.292:4786689): auid=4294967295 uid=0 \
         gid=0 ses=4294967295 subj=unconfined pid=7 comm=\"sipnab\" \
         exe=\"/usr/bin/sipnab\" sig=0 arch=c00000b7 syscall={nr} compat=0 \
         ip=0xffffa94416ec code=0x7ffc0000\u{1d}AUID=\"unset\" UID=\"root\" \
         GID=\"root\" ARCH=aarch64 SYSCALL={name}\n"
    )
}

/// A host with a connected audit daemon reads the audit log.
#[test]
fn a_host_with_an_audit_daemon_reads_the_audit_log() -> Result<(), TestError> {
    let (code, out) = mode("--source", AUDITCTL_WITH_DAEMON)?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.trim(), "audit", "the daemon's records were not chosen");
    Ok(())
}

/// A pid of 0 means no daemon, so the records are in the kernel log.
#[test]
fn a_pid_of_zero_reads_the_kernel_log() -> Result<(), TestError> {
    let (code, out) = mode(
        "--source",
        &AUDITCTL_WITH_DAEMON.replace("pid 1043", "pid 0"),
    )?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        out.trim(),
        "kernel",
        "a host without a daemon chose the audit log"
    );
    Ok(())
}

/// No `auditctl -s` output at all (not installed, or it refused) reads the
/// kernel log, and a field whose name only ends in `pid` is not the pid.
#[test]
fn no_auditctl_output_or_a_lookalike_field_reads_the_kernel_log() -> Result<(), TestError> {
    let (code, out) = mode("--source", "")?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.trim(), "kernel", "empty status chose the audit log");
    let (code, out) = mode("--source", "enabled 1\nppid 77\nlost 0\n")?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.trim(), "kernel", "`ppid 77` was read as a daemon pid");
    Ok(())
}

/// The record parser reads audit-log SECCOMP records.
#[test]
fn audit_log_records_are_parsed_by_the_same_judge() -> Result<(), TestError> {
    let mut text = String::new();
    for (shape, calls) in [
        ("a", &[(63_u32, "read"), (291, "statx")][..]),
        ("b", &[(63, "read")][..]),
        ("c", &[(291, "statx")][..]),
    ] {
        text.push_str(&format!("== SHAPE {shape}\n"));
        for (nr, name) in calls {
            text.push_str(&audit_record(*nr, name));
        }
    }
    let (code, out) = classify(&text)?;
    assert_eq!(code, 0, "audit-log records were not understood:\n{out}");
    assert!(out.contains("records 4 across 3 shape(s)"), "{out}");
    assert!(
        out.contains("union is 2 syscall(s)") && out.contains("63 291"),
        "the numbers were not extracted from audit-log records:\n{out}"
    );
    Ok(())
}

/// `ausearch -m SECCOMP` output, separators and time lines included, parses.
#[test]
fn ausearch_output_with_its_separators_parses() -> Result<(), TestError> {
    let mut text = String::new();
    for shape in ["a", "b", "c"] {
        text.push_str(&format!(
            "== SHAPE {shape}\n----\ntime->Sun Nov  8 07:21:01 2026\n"
        ));
        text.push_str(&audit_record(17, "getcwd"));
    }
    let (code, out) = classify(&text)?;
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("union is 1 syscall(s)") && out.contains(" 17"),
        "{out}"
    );
    Ok(())
}

/// The interpreted `SYSCALL=name` field is not taken for the number.
///
/// The enriched trailer repeats the field name in capitals with a name as its
/// value. A parser that matched it would record nothing, or the wrong field.
#[test]
fn the_enriched_syscall_name_is_not_taken_for_the_number() -> Result<(), TestError> {
    let mut text = String::new();
    for shape in ["a", "b", "c"] {
        text.push_str(&format!("== SHAPE {shape}\n"));
        text.push_str(&audit_record(291, "statx"));
    }
    let (code, out) = classify(&text)?;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("union is 1 syscall(s)"), "{out}");
    assert!(out.contains(" 291"), "{out}");
    assert!(
        !out.contains("statx"),
        "the name leaked into the union:\n{out}"
    );
    Ok(())
}

/// Records the audit subsystem lost during a shape refuse the run.
///
/// The audit path has no `callbacks suppressed` line; its loss shows as a
/// rising `lost` counter in `auditctl -s`. The collector writes the rise for
/// each shape as `== LOST <n>`, and the judge refuses any non-zero one.
#[test]
fn records_the_audit_subsystem_lost_refuse_the_run() -> Result<(), TestError> {
    let mut text = log(&[("a", &[1]), ("b", &[1])]);
    text.push_str("== LOST 0\n== SHAPE c\n");
    text.push_str(&record(1));
    text.push_str("== LOST 12\n");
    let (code, out) = classify(&text)?;
    assert_eq!(
        code, 1,
        "a run that lost audit records was accepted:\n{out}"
    );
    assert!(out.contains("LOST"), "{out}");
    assert!(!out.contains("SETTLED"), "{out}");
    assert!(
        out.contains("auditctl -b"),
        "the refusal names no fix for the audit path:\n{out}"
    );
    Ok(())
}

/// A lost count of zero is not a loss.
#[test]
fn a_lost_count_of_zero_is_not_a_loss() -> Result<(), TestError> {
    let mut text = String::new();
    for shape in ["a", "b", "c"] {
        text.push_str(&format!("== SHAPE {shape}\n"));
        text.push_str(&record(1));
        text.push_str("== LOST 0\n");
    }
    let (code, out) = classify(&text)?;
    assert_eq!(code, 0, "a zero lost count was treated as a loss:\n{out}");
    assert!(out.contains("SETTLED"), "{out}");
    Ok(())
}

/// The audit log's path comes from `log_file` in auditd.conf.
#[test]
fn the_audit_log_path_comes_from_auditd_conf() -> Result<(), TestError> {
    let conf = "# log_file = /nowhere\nlocal_events = yes\nlog_file = /srv/audit/a.log\n";
    let (code, out) = mode("--audit-log-file", conf)?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(out.trim(), "/srv/audit/a.log", "{out}");
    Ok(())
}

/// Without a `log_file` line (or without a readable config) it is auditd's
/// default.
#[test]
fn a_config_without_log_file_means_the_default_path() -> Result<(), TestError> {
    for conf in ["", "# log_file = /nowhere\nflush = INCREMENTAL_ASYNC\n"] {
        let (code, out) = mode("--audit-log-file", conf)?;
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            out.trim(),
            "/var/log/audit/audit.log",
            "for {conf:?}: {out}"
        );
    }
    Ok(())
}

/// The collector chooses its source with the tested function and streams the
/// audit log when that is the source.
///
/// Structural because the collector needs root: the property is that the code
/// path calls `choose_source` (the function `--source` drives) rather than a
/// second copy of the rule, and follows the audit log by name across rotation.
#[test]
fn the_collector_uses_the_tested_source_choice() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let collector = code
        .split("The collector")
        .nth(1)
        .unwrap_or(&code[code.find("BIN=").ok_or("the collector starts")?..]);
    assert!(
        collector.contains("auditctl -s 2>/dev/null | choose_source"),
        "the collector does not choose its source with choose_source"
    );
    assert!(
        collector.contains("tail -F -n 0 \"$AUDIT_LOG\""),
        "the collector does not follow the audit log"
    );
    assert_eq!(
        code.matches("pid [0-9]").count() + code.matches("$1 == \"pid\"").count(),
        1,
        "the source rule appears more or less than once"
    );
    Ok(())
}

/// The judge writes no file under a fixed /tmp name.
///
/// The collector runs as root; a predictable path in a world-writable
/// directory is one another user can plant a link at.
#[test]
fn the_script_writes_no_fixed_tmp_path() -> Result<(), TestError> {
    let src =
        std::fs::read_to_string(script()).map_err(|e| format!("the script is in the tree: {e}"))?;
    let code: Vec<&str> = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter(|l| l.contains("/tmp/"))
        .collect();
    assert!(code.is_empty(), "fixed /tmp paths in code: {code:?}");
    Ok(())
}
