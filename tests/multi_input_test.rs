// SPDX-License-Identifier: MIT OR Apache-2.0

//! `-I` accepting a file, a directory, a glob, or several of each.
//!
//! The unit tests in `capture::input_set` cover resolution — which files are
//! selected and in what order. These drive the real binary end to end, because
//! resolution is only half the feature: the files also have to reach ONE
//! dialog store, and that is what makes a call split across a ring buffer
//! reconstructable.
//!
//! The split-call test is the one that matters. `tcpdump -C -W` cuts a busy
//! capture mid-call, so a dialog whose INVITE lands in one file and whose BYE
//! lands in the next is invisible to both when they are analysed separately:
//! one shows a call that never ends, the other a stray BYE. Measured on a real
//! 10-file ring buffer, 2271 of 20512 calls — 11% — crossed a boundary.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/run.rs"]
mod run_support;

fn samples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples")
}

/// Dialog Call-IDs sipnab reports for the given arguments.
fn dialog_ids(args: &[&str]) -> Vec<String> {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-N", "--json-dialogs", "--no-cli-print", "--quiet"])
        .args(args)
        .output()
        .expect("spawn sipnab");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["call_id"].as_str().map(str::to_string))
        .collect()
}

/// Split a capture into two files at `first_count` packets, preserving order.
///
/// `editcap -r` selects a packet range, so two calls carve the file in two
/// without rewriting timestamps — the halves stay a genuine sequence rather
/// than a synthetic one.
fn split_capture(src: &Path, first_count: usize, total: usize, dir: &Path) -> (PathBuf, PathBuf) {
    let head = dir.join("part-a.pcap");
    let tail = dir.join("part-b.pcap");
    for (out, range) in [
        (&head, format!("1-{first_count}")),
        (&tail, format!("{}-{total}", first_count + 1)),
    ] {
        let status = Command::new("editcap")
            .args(["-r", &src.to_string_lossy(), &out.to_string_lossy(), &range])
            .status()
            .expect("run editcap");
        assert!(status.success(), "editcap failed for range {range}");
    }
    (head, tail)
}

/// A call cut in half by a file boundary is reported ONCE, whole.
///
/// The assertion is deliberately a comparison against reading the whole file:
/// the set must produce exactly the dialogs the unsplit capture does. Asserting
/// only "at least one dialog" would pass on a build that reset state between
/// files and reported two fragments.
#[test]
fn a_call_split_across_two_files_is_stitched_back_together() {
    if Command::new("editcap").arg("--version").output().is_err() {
        eprintln!("editcap not installed — skipping");
        return;
    }
    let src = samples().join("sip-rtp-g711.pcap");
    let whole = dialog_ids(&["-I", &src.to_string_lossy()]);
    assert!(!whole.is_empty(), "fixture must hold dialogs");

    let dir = tempfile::tempdir().expect("tempdir");
    // 852 packets in this fixture; cut near the middle so the INVITE and the
    // BYE of at least one call land on opposite sides.
    let (head, tail) = split_capture(&src, 400, 852, dir.path());

    let together = dialog_ids(&["-I", &head.to_string_lossy(), "-I", &tail.to_string_lossy()]);
    let mut a = whole.clone();
    let mut b = together.clone();
    a.sort();
    b.sort();
    assert_eq!(
        b, a,
        "reading the two halves as a set must reproduce the dialogs of the \
         unsplit capture exactly.\n  whole: {a:?}\n  split: {b:?}"
    );

    // And the failure it prevents: each half alone tells a different story.
    let head_only = dialog_ids(&["-I", &head.to_string_lossy()]);
    let tail_only = dialog_ids(&["-I", &tail.to_string_lossy()]);
    assert!(
        head_only.len() + tail_only.len() >= together.len(),
        "per-file analysis should count at least as many dialog fragments as \
         the stitched set: {} + {} vs {}",
        head_only.len(),
        tail_only.len(),
        together.len()
    );
}

/// A truncated file in the MIDDLE of a set must not hide the files after it.
///
/// Truncation is the normal state of a ring buffer, not an exotic corruption:
/// the newest file is being written when the capture stops, and `tcpdump`
/// leaves it short. libpcap reports `truncated dump file` on the final partial
/// record.
///
/// This was a real regression. `capture_files` propagated the read error with
/// `?`, which abandoned every remaining file — observed on a 15-file directory
/// where 15 started and 14 finished. It only escaped notice because the
/// truncated member happened to sort last by timestamp; one position earlier
/// and the rest of the capture would have vanished behind a single WARN, with
/// the run still exiting 0 and printing a confident summary.
///
/// Open failures were already handled this way. Read failures were not, and
/// the reasoning is identical: losing one file of a set is bad, losing the
/// analysis of the others is worse.
#[test]
fn a_truncated_file_does_not_hide_the_files_after_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Chosen by their real first-packet timestamps so the truncated file lands
    // in the MIDDLE once resolve() orders the set: sip-register (1312180642)
    // < sip-proxy (1312180650) < sip-rtp-g711 (1480171979). `-I` order does
    // not decide this — resolution sorts by packet time regardless — so the
    // fixtures have to be picked for it.
    let first = dir.path().join("read-first.pcap");
    let broken = dir.path().join("truncated-in-the-middle.pcap");
    let after = dir.path().join("read-after-the-break.pcap");

    std::fs::copy(samples().join("sip-register.pcap"), &first).expect("copy");
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), &after).expect("copy");

    // Cut INSIDE a packet's data, not at a record boundary. libpcap tolerates a
    // file that simply ends between records — it only reports `truncated dump
    // file` when a packet header promises more bytes than the file holds, which
    // is what an interrupted writer actually leaves behind. Cutting at an
    // arbitrary offset produced a file libpcap read happily, and the test
    // passed against the unfixed code.
    //
    // pcap layout: 24-byte global header, then per record a 16-byte header
    // (ts_sec, ts_usec, incl_len, orig_len) followed by incl_len bytes.
    let whole = std::fs::read(samples().join("sip-proxy.pcap")).expect("read");
    let truncated = {
        let mut off = 24usize;
        let mut cut = None;
        // Walk to the third record, then keep its header and half its data.
        for _ in 0..3 {
            if off + 16 > whole.len() {
                break;
            }
            let incl = u32::from_le_bytes(whole[off + 8..off + 12].try_into().unwrap()) as usize;
            if off + 16 + incl > whole.len() {
                break;
            }
            cut = Some(off + 16 + incl / 2);
            off += 16 + incl;
        }
        cut.expect("fixture must hold at least one full record")
    };
    std::fs::write(&broken, &whole[..truncated]).expect("write truncated");

    let after_alone = dialog_ids(&["-I", &after.to_string_lossy()]);
    assert!(
        !after_alone.is_empty(),
        "the trailing fixture must hold dialogs"
    );

    let together = dialog_ids(&[
        "-I",
        &first.to_string_lossy(),
        "-I",
        &broken.to_string_lossy(),
        "-I",
        &after.to_string_lossy(),
    ]);

    // Assert on the file read AFTER the break. Checking the leading file would
    // pass whether or not the abort happens, since it is already read by then
    // — which is exactly how the first version of this test passed against the
    // unfixed code.
    for id in after_alone.iter() {
        assert!(
            together.contains(id),
            "dialog {id} comes from the file read AFTER the truncated one and \
             must still be reported; a read error must not abandon the rest of \
             the set.\n  got: {together:?}"
        );
    }
}

/// A directory reads every capture inside it.
#[test]
fn a_directory_reads_every_capture_in_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["sip-rtp-g711.pcap", "sip-register.pcap"] {
        std::fs::copy(samples().join(name), dir.path().join(name)).expect("copy");
    }
    let combined = dialog_ids(&["-I", &dir.path().to_string_lossy()]);
    let a = dialog_ids(&["-I", &samples().join("sip-rtp-g711.pcap").to_string_lossy()]);
    let b = dialog_ids(&["-I", &samples().join("sip-register.pcap").to_string_lossy()]);
    assert_eq!(
        combined.len(),
        a.len() + b.len(),
        "the directory must yield both files' dialogs"
    );
}

/// `--recursive` is required to reach a subdirectory, and reaches it.
#[test]
fn recursive_is_needed_to_reach_a_subdirectory() {
    let root = tempfile::tempdir().expect("tempdir");
    let sub = root.path().join("archive");
    std::fs::create_dir(&sub).expect("mkdir");
    std::fs::copy(
        samples().join("sip-rtp-g711.pcap"),
        root.path().join("top.pcap"),
    )
    .expect("copy");
    std::fs::copy(samples().join("sip-register.pcap"), sub.join("buried.pcap")).expect("copy");

    let shallow = dialog_ids(&["-I", &root.path().to_string_lossy()]);
    let deep = dialog_ids(&["-I", &root.path().to_string_lossy(), "--recursive"]);
    assert!(
        deep.len() > shallow.len(),
        "--recursive must reach the subdirectory: {} vs {}",
        deep.len(),
        shallow.len()
    );
}

/// `--input-name` narrows a directory to the matching files.
#[test]
fn input_name_filters_a_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        samples().join("sip-rtp-g711.pcap"),
        dir.path().join("keep-me.pcap"),
    )
    .expect("copy");
    std::fs::copy(
        samples().join("sip-register.pcap"),
        dir.path().join("skip-me.pcap"),
    )
    .expect("copy");

    let all = dialog_ids(&["-I", &dir.path().to_string_lossy()]);
    let filtered = dialog_ids(&[
        "-I",
        &dir.path().to_string_lossy(),
        "--input-name",
        "keep-*.pcap",
    ]);
    let only_kept = dialog_ids(&["-I", &dir.path().join("keep-me.pcap").to_string_lossy()]);

    assert!(filtered.len() < all.len(), "the filter must exclude a file");
    assert_eq!(
        filtered.len(),
        only_kept.len(),
        "the filtered read must match reading the kept file alone"
    );
}

/// A glob is expanded by sipnab, not the shell.
///
/// The pattern reaches the binary as a literal because it is passed as one
/// argument here, exactly as it would arrive from an MCP config or an
/// `ssh host 'sipnab -I ...'` command line where no shell expands it.
#[test]
fn a_glob_is_expanded_without_a_shell() {
    let pattern = format!("{}/sip-rtp-g7*.pcap", samples().display());
    let ids = dialog_ids(&["-I", &pattern]);
    assert!(
        !ids.is_empty(),
        "the glob must expand internally; an unexpanded literal would have \
         failed to open"
    );
}

/// A directory that holds no readable capture fails loudly.
#[test]
fn a_directory_with_nothing_readable_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("notes.txt"), "no packets here").expect("write");
    let (_out, err, code) =
        run_support::run(&["-N", "-I", &dir.path().to_string_lossy()], Some("error"));
    assert_eq!(code, Some(1), "must exit 1:\n{err}");
    assert!(
        err.contains("no readable capture") || err.contains("no files"),
        "the error must say the directory yielded nothing usable:\n{err}"
    );
}

/// Single-file input is untouched by any of this.
#[test]
fn a_single_file_still_behaves_exactly_as_before() {
    let src = samples().join("sip-rtp-g711.pcap");
    let ids = dialog_ids(&["-I", &src.to_string_lossy()]);
    assert_eq!(
        ids.len(),
        2,
        "this fixture has always reported 2 dialogs; multi-file support must \
         not change the overwhelmingly common case"
    );
}
