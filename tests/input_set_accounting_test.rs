// SPDX-License-Identifier: MIT OR Apache-2.0

//! What `-I` left out, said where the operator reads it.
//!
//! The unit tests in `capture::input_set` assert the accounting itself. These
//! drive the real binary, because the accounting is only worth having if it
//! reaches stderr on a normal run — the invariant in
//! `docs/internals/invariants.md` is that a caveat belongs where its consumer
//! looks, and the consumer of a `-I` shortfall is whoever is watching the run
//! scroll past.
//!
//! The case that motivated the file is a directory tree. `-I /pcaps` over a
//! directory holding 15 captures beside three subdirectories holding 122 more
//! printed "Reading 15 capture files in timestamp order" and stopped there.
//! That line is byte-identical to the one a directory of exactly 15 captures
//! produces, so nothing in the run distinguishes "this is the whole capture"
//! from "this is 11% of it". Recursion staying opt-in is the right default —
//! silently reading an `archive/` subdirectory would be worse — but the
//! shortfall the default produces has to be visible.

use std::path::PathBuf;

#[path = "support/corpus.rs"]
mod corpus_support;
#[path = "support/run.rs"]
mod run_support;

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples")
}

/// Lay out `root/top.pcap` plus `n` subdirectories each holding one capture.
fn tree_with_subdirs(root: &std::path::Path, n: usize) {
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), root.join("top.pcap")).expect("copy");
    for i in 0..n {
        let sub = root.join(format!("host-{i}"));
        std::fs::create_dir(&sub).expect("mkdir");
        std::fs::copy(samples().join("sip-register.pcap"), sub.join("cap.pcap")).expect("copy");
    }
}

/// A directory run says how many subdirectories it did not enter.
///
/// Without this the run reports the files it read and nothing else, and the
/// operator has no way to tell a complete answer from a partial one.
#[test]
fn a_directory_run_says_how_many_subdirectories_it_did_not_enter() {
    let root = tempfile::tempdir().expect("tempdir");
    tree_with_subdirs(root.path(), 2);

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &root.path().to_string_lossy(), "--quiet"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "the run still succeeds:\n{err}");
    assert!(
        err.contains("2 subdirectory(ies) not descended"),
        "the count of what was left out must reach stderr:\n{err}"
    );
    assert!(
        err.contains("--recursive"),
        "a count with no remedy beside it is a puzzle, not a disclosure:\n{err}"
    );
    assert!(
        err.contains("1 capture file(s)"),
        "the two numbers have to appear together or they do not \
         reconcile:\n{err}"
    );
}

/// …and stops saying it once `--recursive` reads them.
///
/// A line that appears on every run is a line nobody reads. This is the half
/// that keeps the warning meaningful.
#[test]
fn the_shortfall_is_not_reported_when_recursive_read_them() {
    let root = tempfile::tempdir().expect("tempdir");
    tree_with_subdirs(root.path(), 2);

    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            &root.path().to_string_lossy(),
            "--recursive",
            "--quiet",
        ],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "{err}");
    assert!(
        !err.contains("not descended"),
        "every subdirectory was read; there is nothing to disclose:\n{err}"
    );
}

/// A run that dropped nothing says nothing about drops.
#[test]
fn a_single_named_file_reports_no_shortfall() {
    let f = samples().join("sip-rtp-g711.pcap");
    let (_out, err, code) =
        run_support::run(&["-N", "-I", &f.to_string_lossy(), "--quiet"], Some("info"));
    assert_eq!(code, Some(0), "{err}");
    assert!(
        !err.contains("-I resolved to"),
        "one file named directly drops nothing:\n{err}"
    );
}

/// An entry that cannot hold a capture is named rather than dropped in silence.
///
/// `path.is_file()` is false for a fifo, and that branch reported only broken
/// symlinks — so a `tcpdump | ...` pipeline's fifo sitting in the capture
/// directory left the set with nothing said.
#[cfg(unix)]
#[test]
fn a_fifo_in_a_capture_directory_is_named() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        samples().join("sip-rtp-g711.pcap"),
        root.path().join("real.pcap"),
    )
    .expect("copy");
    let fifo = root.path().join("live.pcap");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed");

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &root.path().to_string_lossy(), "--quiet"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "the real capture still analyzes:\n{err}");
    assert!(
        err.contains("live.pcap") && err.contains("not a file"),
        "the fifo must be named:\n{err}"
    );
    assert!(
        err.contains("1 entry(ies) that are not files"),
        "and counted beside the total it reduced:\n{err}"
    );
}

/// A directory whose captures are one level down says where they are.
///
/// "no files in '/pcaps'" reads as "that directory is empty". A per-host or
/// per-day capture tree has exactly this shape, and the operator's next move
/// is `--recursive`, not a hunt for the missing files.
#[test]
fn a_directory_whose_captures_are_deeper_says_so() {
    let root = tempfile::tempdir().expect("tempdir");
    let sub = root.path().join("host-a");
    std::fs::create_dir(&sub).expect("mkdir");
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), sub.join("cap.pcap")).expect("copy");

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &root.path().to_string_lossy(), "--quiet"],
        Some("error"),
    );
    assert_eq!(
        code,
        Some(1),
        "an empty-looking directory fails the run:\n{err}"
    );
    assert!(
        err.contains("not descended") && err.contains("--recursive"),
        "the error has to point one level down:\n{err}"
    );
}

/// The same accounting against a real capture directory named by
/// `SIPNAB_CORPUS`.
///
/// Skipped unless the variable is set. Prints counts and nothing else — the
/// corpus is real customer traffic and no filename, address or identifier from
/// it belongs in test output.
///
/// This is the case no fixture reproduces at scale: the corpus that motivated
/// the change resolves to 15 files at its top level and holds 122 more in three
/// subdirectories, and the run reported the 15 as though they were everything.
#[test]
fn corpus_directory_reports_what_it_did_not_enter() {
    // The skip is announced on stderr by `corpus_support::root`, once per test
    // binary. It used to be an `eprintln!` that libtest captured and discarded
    // on success, so this gate reported `ok` while never running.
    let Some(root) = corpus_support::root() else {
        return;
    };
    let dir = root.to_string_lossy().into_owned();
    let subdirs = std::fs::read_dir(&dir)
        .expect("read corpus dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .count();
    if subdirs == 0 {
        eprintln!("corpus has no subdirectories — nothing to disclose, skipping");
        return;
    }

    let (_out, err, code) =
        run_support::run(&["-N", "-I", &dir, "--count", "1", "--quiet"], Some("warn"));
    assert_eq!(code, Some(0), "the run still succeeds");
    assert!(
        err.contains(&format!("{subdirs} subdirectory(ies) not descended")),
        "a corpus with {subdirs} subdirectories must say so; got {} line(s) of \
         stderr",
        err.lines().count()
    );
    eprintln!("corpus: {subdirs} subdirectory(ies) reported as not descended");
}
