// SPDX-License-Identifier: MIT OR Apache-2.0

//! The half of the eBPF backend the suite cannot reach, and what covers it.
//!
//! # Why this file exists
//!
//! `src/capture/uprobe/bpf.rs` loads an eBPF program. Loading needs privileges
//! this suite does not have and must not acquire, so building the object is
//! covered and loading, attaching and reading are not — and those are where
//! the failures live. On 2026-09-09 that was not hypothetical: the released
//! object was rejected by the verifier on every kernel that had it, through
//! four releases, with a green suite the whole time.
//!
//! The rule this repository already applies to a surface that cannot be
//! driven is to test the CONVERSION it performs and record why the wire is
//! unreachable. Here the conversion is the VERDICT: given what sipnab printed
//! on a privileged host, did the program load and attach, or not? That is a
//! pure text judgement, it is the only part a machine reads, and it is what
//! turns a manual run into evidence rather than a memory.
//!
//! So `scripts/verify-bpf-load.sh` splits in two. `--classify` reads a run's
//! output and answers that question; these tests drive it with the real
//! strings from a real attach and a real rejection. The other half downloads a
//! published artifact and runs it, which needs root and a kernel with BTF and
//! belongs on the lab VM.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[path = "support/release_logic.rs"]
mod release_logic;

use release_logic::LOAD_VERIFICATION_RECORD;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Run the classifier over `text`, returning (exit code, stdout).
fn classify(text: &str) -> (i32, String) {
    let mut child = Command::new("bash")
        .arg(repo().join("scripts/verify-bpf-load.sh"))
        .arg("--classify")
        .current_dir(repo())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn verify-bpf-load.sh");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(text.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The line a successful load-and-attach actually prints.
///
/// Verbatim from the run on 2026-09-10 against the published 0.5.162
/// `x86_64-unknown-linux-gnu` artifact. Not paraphrased: the classifier exists
/// to recognize THIS, and a paraphrase would let the real message change while
/// the test went on passing.
const ATTACHED: &str = "\u{1b}[2m2026-09-10T02:27:03.285431Z\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m \u{1b}[2msipnab::capture::uprobe::bpf\u{1b}[0m\u{1b}[2m:\u{1b}[0m BPF capture attached to 2 libraries [/proc/1184/root/usr/lib/libssl.so.3:SSL_write, /proc/370/root/usr/lib/x86_64-linux-gnu/libssl.so.3:SSL_write] plus tcp_sendmsg. Dialogs carry real addresses when a write and its send paired on one thread, and none at all when they did not.";

/// The refusal the released 0.5.161 artifact produced, from the entry that
/// recorded it.
const REJECTED: &str =
    "Error: verifier rejected the uprobe: BPF_PROG_LOAD returned Permission denied";

#[test]
fn an_attach_is_recognized_from_the_message_sipnab_actually_prints() {
    let (code, verdict) = classify(ATTACHED);
    assert_eq!(
        code, 0,
        "the classifier did not accept a real attach; it said {verdict:?}"
    );
    assert!(
        verdict.contains("ATTACHED"),
        "expected an ATTACHED verdict, got {verdict:?}"
    );
}

#[test]
fn a_verifier_rejection_is_not_reported_as_a_pass() {
    let (code, verdict) = classify(REJECTED);
    assert_ne!(
        code, 0,
        "the classifier passed a verifier rejection: {verdict:?}"
    );
    assert!(
        verdict.contains("REFUSED"),
        "expected a REFUSED verdict, got {verdict:?}"
    );
}

/// Silence is the failure this whole entry is about.
///
/// A run that printed nothing recognizable is not a run that succeeded. The
/// released object failed in a way that looked, from a distance, like a
/// feature nobody had exercised — which is exactly what an empty verdict
/// treated as a pass would recreate.
#[test]
fn output_with_no_verdict_is_not_a_pass() {
    for text in ["", "sipnab: 0 packets captured, 0 SIP messages", "hello"] {
        let (code, verdict) = classify(text);
        assert_ne!(
            code, 0,
            "the classifier passed output that says nothing about loading: \
             {text:?} -> {verdict:?}"
        );
        assert!(
            verdict.contains("NO VERDICT"),
            "expected NO VERDICT for {text:?}, got {verdict:?}"
        );
    }
}

/// A rejection buried in an otherwise chatty run still fails.
///
/// The real output carries startup logging, a privilege drop and a capture
/// summary around the line that matters. A classifier that only reads the
/// first or last line would call this a pass.
#[test]
fn a_rejection_is_found_among_the_ordinary_logging() {
    let noisy =
        format!("INFO sipnab: starting\n{REJECTED}\nsipnab: 0 packets captured, 0 SIP messages\n");
    let (code, verdict) = classify(&noisy);
    assert_ne!(code, 0, "a buried rejection was passed: {verdict:?}");
    assert!(verdict.contains("REFUSED"), "got {verdict:?}");
}

/// The record names the release the site currently offers.
///
/// Same shape as the binary-ceiling record, and for the same reason: a
/// hand-kept table is only worth keeping if something makes it refresh. A
/// release cannot be advertised without moving `published_version`, and moving
/// it without recording a load verification fails here.
///
/// This is deliberately a POST-release gate. The artifact has to exist before
/// anybody can download and run it, so it cannot be satisfied while cutting.
#[test]
fn the_load_verification_record_names_the_published_release() {
    let published = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .expect("pattern")
        .captures(&read("website/config.toml"))
        .expect("website/config.toml has no published_version")[1]
        .to_string();
    let doc = read(LOAD_VERIFICATION_RECORD);
    let rows: Vec<&str> = doc
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("| ") && l.contains("attached"))
        .collect();
    assert!(
        !rows.is_empty(),
        "{LOAD_VERIFICATION_RECORD} records no load verification at all; this \
         gate would pass whatever shipped"
    );
    assert!(
        rows.iter().any(|r| r.contains(&published)),
        "no recorded eBPF load verification for {published}, the release the \
         site offers. Run `scripts/verify-bpf-load.sh` on a privileged host \
         with BTF and add the row. Recorded: {rows:?}"
    );
}

/// Every recorded row says where it was run.
///
/// "It worked" is not evidence. Which artifact, which kernel and which day are
/// what let a later reader tell whether a new failure is a regression or a
/// host that was never covered — the question that took a full elimination
/// matrix to answer the first time.
#[test]
fn every_recorded_verification_names_its_artifact_and_kernel() {
    let doc = read(LOAD_VERIFICATION_RECORD);
    let mut rows = 0usize;
    let mut thin = Vec::new();
    for line in doc.lines().map(str::trim) {
        if !line.starts_with("| ") || !line.contains("attached") {
            continue;
        }
        rows += 1;
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 6 || cells.iter().any(|c| c.is_empty()) {
            thin.push(line.to_string());
        }
    }
    assert!(
        thin.is_empty(),
        "these verification rows do not carry version, artifact, host, kernel, \
         date and result: {thin:?}"
    );
    assert!(
        rows > 0,
        "no verification rows were found, so this gate passed by checking \
         nothing -- the same silence the record exists to break"
    );
}
