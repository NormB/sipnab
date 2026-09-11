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
