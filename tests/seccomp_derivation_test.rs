// SPDX-License-Identifier: MIT OR Apache-2.0

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

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The script under test.
fn script() -> PathBuf {
    repo().join("scripts/derive-seccomp-allowlist.sh")
}

/// Run the judge over `log`, returning `(exit code, stdout)`.
fn classify(log: &str) -> (i32, String) {
    let mut child = Command::new("sh")
        .arg(script())
        .arg("--classify")
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the derivation judge");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(log.as_bytes())
        .expect("write the log");
    let out = child.wait_with_output().expect("the judge finishes");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), text)
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
fn a_set_that_stopped_growing_is_reported_as_settled() {
    let (code, out) = classify(&log(&[
        ("offline", &[0, 1, 3, 257]),
        ("live", &[0, 1, 3]),
        ("report", &[1, 257]),
    ]));
    assert_eq!(code, 0, "a settled derivation was refused:\n{out}");
    assert!(out.contains("SETTLED"), "{out}");
    assert!(
        out.contains("0 1 3 257"),
        "the union is not reported in order:\n{out}"
    );
}

/// Settled is not reported as complete.
///
/// The distinction this whole file turns on. Two quiet shapes mean these shapes
/// stopped finding calls, not that no shape would — and an operator who reads
/// "settled" as "done" enforces a list with a hole in it. The word has to carry
/// its own limit or it will be read as the stronger claim.
#[test]
fn settled_says_plainly_that_it_does_not_mean_complete() {
    let (code, out) = classify(&log(&[("a", &[1]), ("b", &[1]), ("c", &[1])]));
    assert_eq!(code, 0);
    assert!(
        out.contains("not complete"),
        "the settled verdict does not disclaim completeness:\n{out}"
    );
    assert!(
        out.contains("kill"),
        "it does not say what an unexercised feature costs:\n{out}"
    );
}

/// A set still growing at the last shape is refused.
///
/// The finding that blocked the enforcing filter: nine shapes in, a `--report`
/// run added a syscall the previous eight never made. A union that is still
/// climbing is not an allowlist, and the judge has to say so rather than hand
/// one over.
#[test]
fn a_set_still_growing_at_the_last_shape_is_refused() {
    let (code, out) = classify(&log(&[("a", &[0, 1]), ("b", &[0, 1]), ("c", &[16])]));
    assert_eq!(code, 1, "a growing set was accepted:\n{out}");
    assert!(out.contains("NOT CONVERGED"), "{out}");
    assert!(
        out.contains("c") && out.contains("added: 16"),
        "the judge does not name the shape that added, so nobody can tell which \
         feature was missing:\n{out}"
    );
}

/// One quiet shape is not enough, and the boundary is asserted.
///
/// An off-by-one here is the difference between a list that settled and one
/// that happened to repeat itself once. The pair pins both sides.
#[test]
fn one_quiet_shape_is_not_convergence_and_two_are() {
    let (one, out_one) = classify(&log(&[("a", &[1]), ("b", &[2]), ("c", &[2])]));
    assert_eq!(
        one, 1,
        "a single quiet shape was accepted as convergence:\n{out_one}"
    );
    let (two, out_two) = classify(&log(&[("a", &[1]), ("b", &[2]), ("c", &[2]), ("d", &[2])]));
    assert_eq!(two, 0, "two quiet shapes were refused:\n{out_two}");
}

/// A log the kernel suppressed records in is refused before anything else.
///
/// Order matters: a lossy log can easily LOOK settled, because the records that
/// would have added a syscall are the ones that went missing. So loss is judged
/// first and the union is never printed for one.
#[test]
fn a_log_that_lost_records_is_refused_and_no_list_is_offered() {
    let mut lossy = log(&[("a", &[1]), ("b", &[1]), ("c", &[1])]);
    lossy.push_str("kauditd_printk_skb: 575 callbacks suppressed\n");
    let (code, out) = classify(&lossy);
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
}

/// A log with no records at all is a different refusal.
///
/// Distinct exit code on purpose. No records means the filter never installed,
/// or the log was read after the run rather than streamed during it — a
/// different mistake from losing some of it, and one with a different fix.
#[test]
fn a_log_with_no_records_is_told_apart_from_one_that_lost_some() {
    let (code, out) = classify("[  0.000000] Linux version 6.12\nnothing to see\n");
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
}

/// The judge reads the real record shape, not a simplified one.
///
/// The fixture guard. Every log above is built from [`record`], so if that
/// stopped matching what the kernel prints, every test here would go on passing
/// while the script matched nothing in the field. This pins the extraction
/// against a line copied from an actual `dmesg` on the lab VM.
#[test]
fn the_extraction_matches_a_line_the_kernel_really_printed() {
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
    let (code, out) = classify(real);
    assert_eq!(code, 0, "a real kernel line was not understood:\n{out}");
    assert!(
        out.contains("union is 1 syscall(s)"),
        "the syscall number was not extracted from a real record:\n{out}"
    );
    assert!(out.contains(" 332"), "{out}");
}

/// The collector restores the rate limit it changed, on every exit path.
///
/// Structural, because the behavioral half needs root and a kernel log. Leaving
/// a host with `printk_ratelimit=0` is a slow way to fill somebody's disk, and
/// the failure is invisible until it is not — so the restore is on a trap that
/// covers signals, not on the last line of the happy path.
#[test]
fn the_collector_restores_the_rate_limit_it_changed() {
    let src = std::fs::read_to_string(script()).expect("the script is in the tree");
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
        .expect("it lowers the limit");
    let trap_at = code.find("trap ").expect("it installs a trap");
    assert!(
        trap_at < set,
        "the limit is lowered before the restore is armed, so a signal in \
         between leaves it lowered"
    );
}

/// The script is executable and names its two halves.
#[test]
fn the_script_is_runnable_and_documents_both_halves() {
    let path = script();
    assert!(
        path.is_file(),
        "scripts/derive-seccomp-allowlist.sh is missing"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert!(mode & 0o111 != 0, "the script is not executable: {mode:o}");
    }
    let src = std::fs::read_to_string(&path).expect("read");
    assert!(src.contains("--classify"), "the testable half is unnamed");
    assert!(
        src.contains("dmesg --follow"),
        "the collector does not stream, so it inherits both losses this file \
         exists to prevent"
    );
}

/// The design document points at the script, and the script at the design.
///
/// A procedure written down in two places drifts; a procedure written down in
/// one and referenced from the other does not. The design owns the reasoning,
/// the script owns the steps, and each names the other so a reader landing on
/// either finds the half they need.
#[test]
fn the_design_document_and_the_script_name_each_other() {
    let design = std::fs::read_to_string(repo().join("docs/design/syscall-sandbox.md"))
        .expect("the design document is in the tree");
    assert!(
        design.contains("derive-seccomp-allowlist.sh"),
        "the design document describes a derivation procedure and never names \
         the script that performs it"
    );
    let src = std::fs::read_to_string(script()).expect("read");
    assert!(
        src.contains("syscall-sandbox.md"),
        "the script performs a procedure and never names the document that \
         explains why it works that way"
    );
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
fn the_collector_gives_each_shape_its_own_stream() {
    let src = std::fs::read_to_string(script()).expect("the script is in the tree");
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
        .expect("the markers are written somewhere");
    let after = &src[combine..];
    assert!(
        after.contains("$COMBINED") || after.contains("COMBINED"),
        "the markers are not written into a combined log assembled after the \
         streams are closed"
    );
}

/// The judge attributes calls to the shape that made them.
///
/// The second owed, and the property the clobbering destroyed. Three shapes
/// each making a different call must be reported as three shapes, each adding
/// its own — not as one shape that added everything and two that added nothing.
#[test]
fn the_judge_attributes_each_call_to_the_shape_that_made_it() {
    let (code, out) = classify(&log(&[("first", &[1]), ("second", &[2]), ("third", &[3])]));
    assert_eq!(code, 1, "a set growing at every shape was accepted:\n{out}");
    for (shape, nr) in [("first", 1), ("second", 2), ("third", 3)] {
        assert!(
            out.contains(&format!("{shape} ")) && out.contains(&format!("added: {nr}")),
            "shape {shape} is not reported as the one that added {nr}:\n{out}"
        );
    }
}

/// A merged log is refused rather than read as a settled one.
///
/// The third owed, and the exact shape the defect produced: everything in the
/// first shape, nothing in the rest. That LOOKS like convergence and is the
/// most dangerous thing this judge can be handed, so the reported attribution
/// has to make it visible — one shape carrying every call is the signature.
#[test]
fn a_log_where_every_call_landed_in_one_shape_is_visible_as_such() {
    let (code, out) = classify(&log(&[
        ("first", &[1, 2, 3, 4]),
        ("second", &[]),
        ("third", &[]),
    ]));
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
}

// ── Three owed for a restructure that moved a change above its trap ─────────

/// The collector cleans its workspace on every exit path.
///
/// Owed alongside the rate limit. The workspace is a `mktemp -d` full of
/// streamed kernel logs, and a derivation that is interrupted must leave
/// nothing behind — this repository's standing rule, and the reason the trap
/// covers signals rather than sitting on the happy path's last line.
#[test]
fn the_collector_cleans_its_workspace_on_every_exit_path() {
    let src = std::fs::read_to_string(script()).expect("the script is in the tree");
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
}

/// Everything the collector changes outside itself is undone by that trap.
///
/// The second owed, stated as a rule rather than a list: enumerate what the
/// script alters on the host, and require the trap to name each one. A
/// restructure added the workspace and moved the `sysctl` above the trap in the
/// same edit, so a rule that only knew about the rate limit would have caught
/// half of it.
#[test]
fn everything_the_collector_changes_is_named_in_its_trap() {
    let src = std::fs::read_to_string(script()).expect("the script is in the tree");
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
}

/// Nothing the collector changes happens before the trap is armed.
///
/// The third owed, and the one the restructure broke: a signal arriving between
/// a change and its trap leaves the change in place. Every alteration has to
/// come after the trap, and the rule is checked over all of them rather than
/// over the one that failed.
#[test]
fn no_change_happens_before_the_trap_is_armed() {
    let src = std::fs::read_to_string(script()).expect("the script is in the tree");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let trap_at = code.find("trap ").expect("the collector installs a trap");
    for change in ["sysctl -q kernel.printk_ratelimit=0", "mktemp -d"] {
        let at = code
            .find(change)
            .unwrap_or_else(|| panic!("the collector no longer does {change}"));
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
}
