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

/// The `--json-dialogs` records sipnab reports for the given arguments.
fn dialog_records(args: &[&str]) -> Vec<serde_json::Value> {
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
        .collect()
}

/// Dialog Call-IDs sipnab reports for the given arguments.
fn dialog_ids(args: &[&str]) -> Vec<String> {
    dialog_records(args)
        .iter()
        .filter_map(|v| v["call_id"].as_str().map(str::to_string))
        .collect()
}

/// Dialog fingerprints — `call_id state msg_count`, sorted.
///
/// Sharper than [`dialog_ids`] for anything about stitching, because the split
/// call appears in BOTH halves of a cut capture: a Call-ID set alone cannot
/// tell a stitched dialog from two fragments, and `DialogStore::merge` is
/// Call-ID-keyed, so cross-worker fragments union back into one entry either
/// way. The *reconstruction* is what differs, and it differs visibly — in
/// `sip-rtp-g711.pcap` cut at packet 400 the call reads `InCall 4` in the head
/// and `Completed 2` in the tail, but `Completed 6` when the halves are read as
/// one set.
fn dialog_fingerprints(args: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = dialog_records(args)
        .iter()
        .map(|v| format!("{} {} {}", v["call_id"], v["state"], v["msg_count"]))
        .collect();
    out.sort();
    out
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

/// Write `src` to `dest` cut INSIDE a packet's data, the way an interrupted
/// writer leaves a file.
///
/// Not at a record boundary: libpcap tolerates a file that simply ends between
/// records, and only reports `truncated dump file` when a packet header
/// promises more bytes than the file holds. Cutting at an arbitrary offset
/// produces a file libpcap reads happily, which made an earlier version of the
/// single-threaded test pass against unfixed code.
///
/// pcap layout: 24-byte global header, then per record a 16-byte header
/// (ts_sec, ts_usec, incl_len, orig_len) followed by incl_len bytes.
fn truncate_mid_record(src: &Path, dest: &Path) {
    let whole = std::fs::read(src).expect("read");
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
    let cut = cut.expect("fixture must hold at least one full record");
    std::fs::write(dest, &whole[..cut]).expect("write truncated");
}

/// Lay out a three-file set whose MIDDLE member is truncated, returning the
/// directory and the path of the file read AFTER the break.
///
/// The fixtures are chosen by their real first-packet timestamps so the broken
/// one lands in the middle once `resolve()` orders the set: sip-register
/// (1312180642) < sip-proxy (1312180650) < sip-rtp-g711 (1480171979). `-I`
/// order does not decide this — resolution sorts by packet time regardless —
/// so the fixtures have to be picked for it.
fn set_with_a_truncated_middle(dir: &Path) -> PathBuf {
    let after = dir.join("read-after-the-break.pcap");
    std::fs::copy(
        samples().join("sip-register.pcap"),
        dir.join("read-first.pcap"),
    )
    .expect("copy");
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), &after).expect("copy");
    truncate_mid_record(
        &samples().join("sip-proxy.pcap"),
        &dir.join("truncated-in-the-middle.pcap"),
    );
    after
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

/// A call that traverses a PROXY must reconstruct identically under `--cores`.
///
/// This is a SINGLE file, so nothing about multi-file input is involved. The
/// sharding in `src/parallel.rs` is by host pair, and its module doc used to
/// assert that "a call's SIP between the same two hosts likewise stays
/// together". A proxied call has no single host pair: `sip-proxy.pcap` carries
/// ONE Call-ID across three of them (10.33.6.100↔.101, .100↔.102, .101↔.102),
/// so its eleven messages shard to different workers. `DialogStore::merge` then
/// kept whichever fragment held *more* messages and discarded the other's
/// message list outright — measured 7 of 11 messages at cores 2, 3, 4 and 8.
///
/// The Call-ID set is identical either way, which is exactly why this asserts
/// fingerprints: `merge` is Call-ID-keyed, so an ID-only assertion passes on a
/// reconstruction missing a third of its signalling. On the 100 MB carrier
/// corpus the same defect halved the message count of 1173 of 2311 dialogs.
///
/// The baseline is anchored to the literal message count so the test cannot be
/// satisfied by both paths regressing to the same wrong answer.
#[test]
fn the_cores_path_reconstructs_every_leg_of_a_proxied_call() {
    let src = samples().join("sip-proxy.pcap");
    let file = src.to_string_lossy().into_owned();

    let records = dialog_records(&["-I", &file]);
    assert_eq!(records.len(), 1, "the fixture is one proxied call");
    assert_eq!(
        records[0]["msg_count"].as_u64(),
        Some(11),
        "the proxied call has eleven messages spread over three host pairs; \
         the single-threaded path sees all of them"
    );

    let single = dialog_fingerprints(&["-I", &file]);
    for cores in ["2", "3", "4", "8"] {
        let cores_out = dialog_fingerprints(&["-I", &file, "--cores", cores]);
        assert_eq!(
            cores_out, single,
            "--cores {cores} must reconstruct the proxied call from EVERY leg, \
             not just the busiest host pair.\n  single: {single:?}\n  cores:  \
             {cores_out:?}"
        );
    }
}

/// `--cores N` must read the whole `-I` set, and stitch a call across a file
/// boundary exactly as the single-threaded path does.
///
/// `-I` gained directory, glob and repeated support in 0.5.70; the `--cores`
/// path never learned about it. `run_cores_file` re-derived its input from
/// `cli.primary_input()` — the first `-I` *argument*, which for `-I /pcaps` is a
/// directory — and handed that raw string to the pcap opener, which opened a
/// directory as a capture and yielded nothing. Measured on a 15-file corpus:
/// 18948 dialogs without `--cores`, 0 with `--cores 4`, exit code 0, no error
/// printed. A silent zero is the worst possible shape for that bug, because the
/// only thing distinguishing it from a quiet capture is a number nobody checks.
///
/// The assertion is against reading the UNSPLIT file, not merely against the
/// other path: comparing the two paths alone would pass on a build where both
/// read one file of the set. And it compares dialog *reconstructions*, not
/// Call-IDs — the split call appears in both halves, so an ID set cannot tell a
/// stitched dialog from two fragments (see [`dialog_fingerprints`]).
#[test]
fn the_cores_path_reads_a_whole_set_and_stitches_across_a_file_boundary() {
    if Command::new("editcap").arg("--version").output().is_err() {
        eprintln!("editcap not installed — skipping");
        return;
    }
    let src = samples().join("sip-rtp-g711.pcap");
    let whole = dialog_fingerprints(&["-I", &src.to_string_lossy()]);
    assert!(!whole.is_empty(), "fixture must hold dialogs");

    // 852 packets; cut near the middle so a call's INVITE and BYE land on
    // opposite sides. The halves go in a directory, so `-I` is given exactly
    // the shape `--cores` could not read at all.
    let dir = tempfile::tempdir().expect("tempdir");
    let (head, tail) = split_capture(&src, 400, 852, dir.path());
    let dir_spec = dir.path().to_string_lossy().into_owned();

    // The split has to actually cut a call, or this test proves nothing about
    // stitching. Read separately the halves must disagree with the whole —
    // a call that never ends in one, a stray half-call in the other.
    let head_only = dialog_fingerprints(&["-I", &head.to_string_lossy()]);
    let tail_only = dialog_fingerprints(&["-I", &tail.to_string_lossy()]);
    assert!(
        head_only
            .iter()
            .chain(tail_only.iter())
            .any(|d| !whole.contains(d)),
        "the split must straddle a call for this test to mean anything, so a \
         half must reconstruct differently from the whole.\n  whole: {whole:?}\
         \n  head:  {head_only:?}\n  tail:  {tail_only:?}"
    );

    let single = dialog_fingerprints(&["-I", &dir_spec]);
    let cores = dialog_fingerprints(&["-I", &dir_spec, "--cores", "4"]);

    assert_eq!(
        cores, whole,
        "--cores must read every file of the set and stitch the call cut in \
         half by the boundary, reproducing the unsplit capture exactly.\n  \
         whole: {whole:?}\n  cores: {cores:?}"
    );
    assert_eq!(
        cores, single,
        "--cores must report the same dialogs as the single-threaded path.\n  \
         single: {single:?}\n  cores:  {cores:?}"
    );
}

/// The other two `-I` shapes — a glob and repeated `-I` — under `--cores`.
///
/// All three broke the same way (the first `-I` argument is not a file), but a
/// glob and a repeated `-I` fail differently from a directory: the raw first
/// argument is a pattern that opens as nothing, or a real file that happens to
/// be only one member of the set. The second case is the quieter failure —
/// plausible output, silently missing every file after the first — so it is
/// asserted against the single-threaded result rather than against non-empty.
#[test]
fn the_cores_path_handles_globs_and_repeated_input_flags() {
    let glob = format!("{}/sip-rtp-g7*.pcap", samples().display());
    let a = samples().join("sip-rtp-g711.pcap");
    let b = samples().join("sip-register.pcap");
    let repeated: Vec<String> = vec![
        "-I".into(),
        a.to_string_lossy().into_owned(),
        "-I".into(),
        b.to_string_lossy().into_owned(),
    ];

    for spec in [vec!["-I".to_string(), glob], repeated] {
        let args: Vec<&str> = spec.iter().map(String::as_str).collect();
        let single = dialog_fingerprints(&args);
        assert!(!single.is_empty(), "{args:?} must resolve to dialogs");

        let mut with_cores = args.clone();
        with_cores.extend_from_slice(&["--cores", "4"]);
        let cores = dialog_fingerprints(&with_cores);

        assert_eq!(
            cores, single,
            "--cores must read the same set as the single-threaded path for \
             {args:?}.\n  single: {single:?}\n  cores:  {cores:?}"
        );
    }
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
    let after = set_with_a_truncated_middle(dir.path());

    let after_alone = dialog_ids(&["-I", &after.to_string_lossy()]);
    assert!(
        !after_alone.is_empty(),
        "the trailing fixture must hold dialogs"
    );

    let together = dialog_ids(&["-I", &dir.path().to_string_lossy()]);

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

/// `--cores` must survive a truncated file exactly as the single-threaded path
/// does — a second bug found while fixing the `-I` set plumbing.
///
/// The parallel reader propagated a mid-file read error out of
/// `run_offline_parallel_file`, which `run_cores_file` turned into exit 1 with
/// no report at all. Measured on one truncated file: single-threaded exited 0
/// and reported its 1 recovered dialog, `--cores 4` exited 1 and reported
/// nothing. A truncated final member is the NORMAL state of a `tcpdump -C -W`
/// ring buffer, so `--cores` threw away the entire analysis of every live ring
/// buffer it was ever pointed at — and, once the set plumbing was fixed, would
/// have thrown away the other fourteen files along with it.
///
/// The parallel reader now mirrors `capture::file::capture_files`: a read error
/// stops that file, not the set, and is logged naming the file.
#[test]
fn the_cores_path_survives_a_truncated_file_like_the_single_threaded_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let after = set_with_a_truncated_middle(dir.path());
    let dir_spec = dir.path().to_string_lossy().into_owned();

    let after_alone = dialog_fingerprints(&["-I", &after.to_string_lossy()]);
    assert!(
        !after_alone.is_empty(),
        "the trailing fixture must hold dialogs"
    );

    let single = dialog_fingerprints(&["-I", &dir_spec]);
    let cores = dialog_fingerprints(&["-I", &dir_spec, "--cores", "4"]);

    for d in &after_alone {
        assert!(
            cores.contains(d),
            "dialog {d} comes from the file read AFTER the truncated one; a read \
             error must not abandon the rest of the set on the --cores path \
             either.\n  got: {cores:?}"
        );
    }
    assert_eq!(
        cores, single,
        "--cores must recover from the truncated member exactly as the \
         single-threaded path does.\n  single: {single:?}\n  cores:  {cores:?}"
    );
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

/// Write two OVERLAPPING slices of `src` into `dir`, returning them in read
/// order.
///
/// The second slice starts inside the first, which is what two capture runs —
/// or the same traffic collected on two interfaces — look like once they are
/// mixed into one directory: every packet in the shared span is read twice.
fn overlapping_slices(src: &Path, dir: &Path) -> (PathBuf, PathBuf) {
    let early = dir.join("early.pcap");
    let late = dir.join("late.pcap");
    for (out, range) in [(&early, "1-600"), (&late, "400-852")] {
        let status = Command::new("editcap")
            .args(["-r", &src.to_string_lossy(), &out.to_string_lossy(), range])
            .status()
            .expect("run editcap");
        assert!(status.success(), "editcap failed for range {range}");
    }
    (early, late)
}

/// A capture reached through a symlink is read, not silently dropped.
///
/// Capture directories commonly symlink to storage. The directory walk keeps
/// `follow_links(false)` for loop protection, which makes walkdir report the
/// LINK's own type — so classifying by that type made every symlinked capture
/// disappear from the set with nothing logged.
#[cfg(unix)]
#[test]
fn a_symlinked_capture_in_a_directory_is_read() {
    let store = tempfile::tempdir().expect("tempdir");
    let view = tempfile::tempdir().expect("tempdir");
    let real = store.path().join("real.pcap");
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), &real).expect("copy");
    std::os::unix::fs::symlink(&real, view.path().join("link.pcap")).expect("symlink");

    let through_link = dialog_ids(&["-I", &view.path().to_string_lossy()]);
    let direct = dialog_ids(&["-I", &real.to_string_lossy()]);
    assert_eq!(
        through_link, direct,
        "a symlinked capture must yield exactly what the file itself does"
    );
}

/// A subdirectory that cannot be read is NAMED, not quietly dropped.
///
/// The walk used `filter_map(Result::ok)`, so a permission-denied directory
/// produced a shorter set and no reason for it — the same shape as traffic that
/// was never captured.
#[cfg(unix)]
#[test]
fn an_unreadable_subdirectory_is_named_not_silently_skipped() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        samples().join("sip-rtp-g711.pcap"),
        root.path().join("top.pcap"),
    )
    .expect("copy");
    let locked = root.path().join("locked");
    std::fs::create_dir(&locked).expect("mkdir");
    std::fs::copy(
        samples().join("sip-register.pcap"),
        locked.join("buried.pcap"),
    )
    .expect("copy");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &root.path().to_string_lossy(), "--recursive"],
        Some("warn"),
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    assert_eq!(code, Some(0), "the readable file still analyses:\n{err}");
    assert!(
        err.contains("locked") && err.contains("Skipping"),
        "the unreadable directory must be named:\n{err}"
    );
}

/// A symlink whose target is gone is named too.
///
/// A capture directory that symlinks into storage grows dangling links as the
/// storage rotates, and a dangling link is not a file: it left the set with
/// nothing said, looking exactly like traffic that was never captured.
#[cfg(unix)]
#[test]
fn a_symlink_with_no_target_is_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::copy(
        samples().join("sip-rtp-g711.pcap"),
        dir.path().join("real.pcap"),
    )
    .expect("copy");
    std::os::unix::fs::symlink(
        dir.path().join("rotated-away.pcap"),
        dir.path().join("dangling.pcap"),
    )
    .expect("symlink");

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &dir.path().to_string_lossy(), "--no-cli-print"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "the real capture still analyses:\n{err}");
    assert!(
        err.contains("dangling.pcap") && err.contains("Skipping"),
        "a symlink with no target must be named:\n{err}"
    );
}

/// The same, for a glob match that cannot be read.
#[cfg(unix)]
#[test]
fn a_glob_match_that_cannot_be_read_is_named() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("tempdir");
    let open_dir = root.path().join("open");
    let locked = root.path().join("locked");
    std::fs::create_dir(&open_dir).expect("mkdir");
    std::fs::create_dir(&locked).expect("mkdir");
    std::fs::copy(samples().join("sip-rtp-g711.pcap"), open_dir.join("a.pcap")).expect("copy");
    std::fs::copy(samples().join("sip-register.pcap"), locked.join("b.pcap")).expect("copy");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let pattern = format!("{}/*/*.pcap", root.path().display());
    let (_out, err, code) = run_support::run(&["-N", "-I", &pattern], Some("warn"));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    assert_eq!(code, Some(0), "the readable match still analyses:\n{err}");
    assert!(
        err.contains("locked") && err.contains("Skipping"),
        "a glob match that cannot be read must be named:\n{err}"
    );
}

/// `--input-name` narrows a GLOB, not only a directory.
///
/// It used to be read in exactly one place — the directory walk — so pairing it
/// with a glob was accepted and did nothing at all: the operator believes they
/// filtered and did not.
#[test]
fn input_name_filters_a_glob_too() {
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

    let pattern = format!("{}/*.pcap", dir.path().display());
    let filtered = dialog_ids(&["-I", &pattern, "--input-name", "keep-*"]);
    let only_kept = dialog_ids(&["-I", &dir.path().join("keep-me.pcap").to_string_lossy()]);
    let all = dialog_ids(&["-I", &pattern]);

    assert!(filtered.len() < all.len(), "the filter must exclude a file");
    assert_eq!(
        filtered, only_kept,
        "the filtered glob must read exactly the kept file"
    );
}

/// `--input-name` against a directly named file is refused instead of ignored.
///
/// There is no silent option: dropping the file loses a capture the operator
/// named, and ignoring the pattern leaves them believing they filtered.
#[test]
fn input_name_against_a_named_file_is_refused() {
    let f = samples().join("sip-rtp-g711.pcap");
    let (_out, err, code) = run_support::run(
        &["-N", "-I", &f.to_string_lossy(), "--input-name", "tg.pcap*"],
        Some("error"),
    );
    assert_eq!(code, Some(1), "the combination must fail:\n{err}");
    assert!(
        err.contains("--input-name"),
        "the error must point at the flag:\n{err}"
    );
}

/// A glob matching DIRECTORIES reads the captures inside them.
///
/// `-I '/caps/*'` over a tree of per-host subdirectories kept only
/// `path.is_file()`, so it resolved to nothing and said nothing.
#[test]
fn a_glob_over_per_host_directories_reads_their_captures() {
    let root = tempfile::tempdir().expect("tempdir");
    for (sub, sample) in [
        ("host-a", "sip-rtp-g711.pcap"),
        ("host-b", "sip-register.pcap"),
    ] {
        let dir = root.path().join(sub);
        std::fs::create_dir(&dir).expect("mkdir");
        std::fs::copy(samples().join(sample), dir.join("cap.pcap")).expect("copy");
    }

    let pattern = format!("{}/*", root.path().display());
    let via_glob = dialog_ids(&["-I", &pattern]);
    let a = dialog_ids(&["-I", &samples().join("sip-rtp-g711.pcap").to_string_lossy()]);
    let b = dialog_ids(&["-I", &samples().join("sip-register.pcap").to_string_lossy()]);
    assert_eq!(
        via_glob.len(),
        a.len() + b.len(),
        "both per-host directories must contribute: {via_glob:?}"
    );
}

/// The run summary counts the files that were READ, not the files that were
/// offered.
///
/// `paths.len()` was the size of the set decided before any file was opened, so
/// a run that opened 3 of 27 still claimed 27 — which is what made an earlier
/// truncation bug nearly invisible.
#[test]
fn the_run_summary_counts_files_read_not_files_offered() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _after = set_with_a_truncated_middle(dir.path());

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &dir.path().to_string_lossy(), "--no-cli-print"],
        Some("warn"),
    );
    assert_eq!(
        code,
        Some(0),
        "a truncated member does not fail the run:\n{err}"
    );
    assert!(
        err.contains("2 of 3 file(s) read in full"),
        "the summary must count what was read:\n{err}"
    );
    assert!(
        err.contains("1 stopped early"),
        "the truncated member must be reported as such:\n{err}"
    );
}

/// A limit that leaves files unread says so, without calling it a loss.
#[test]
fn the_run_summary_reports_files_a_limit_never_reached() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["sip-rtp-g711.pcap", "sip-register.pcap", "sip-proxy.pcap"] {
        std::fs::copy(samples().join(name), dir.path().join(name)).expect("copy");
    }

    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            &dir.path().to_string_lossy(),
            "-n",
            "1",
            "--no-cli-print",
        ],
        Some("info"),
    );
    assert_eq!(code, Some(0), "{err}");
    assert!(
        err.contains("2 not reached"),
        "files a limit never opened must be counted, not folded into the set \
         size:\n{err}"
    );
}

/// Two captures of the same traffic in one directory are reported.
///
/// This is the case the overlap warning exists for, and it had never fired:
/// the test compared consecutive files' START times with an ABSOLUTE
/// `f64::EPSILON` against epoch seconds, which degenerates to exact bit
/// equality. Real overlap is the previous file's END against the next file's
/// START, and here the two slices share 200 packets — every count spanning
/// them is inflated.
#[test]
fn overlapping_captures_in_one_directory_are_reported() {
    if Command::new("editcap").arg("--version").output().is_err() {
        eprintln!("editcap not installed — skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let (_early, _late) = overlapping_slices(&samples().join("sip-rtp-g711.pcap"), dir.path());

    let (_out, err, code) = run_support::run(
        &["-N", "-I", &dir.path().to_string_lossy(), "--no-cli-print"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "{err}");
    assert!(
        err.contains("overlap") && err.contains("counted twice"),
        "an overlapping pair must be reported, with the consequence stated:\n{err}"
    );
}

/// A clean ring-buffer set is NOT reported as overlapping.
///
/// The other half of the tolerance: a warning that fires on every ordinary
/// multi-file read is as useless as one that never fires.
#[test]
fn a_clean_multi_file_set_reports_no_overlap() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["sip-rtp-g711.pcap", "sip-register.pcap", "sip-proxy.pcap"] {
        std::fs::copy(samples().join(name), dir.path().join(name)).expect("copy");
    }
    let (_out, err, code) = run_support::run(
        &["-N", "-I", &dir.path().to_string_lossy(), "--no-cli-print"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "{err}");
    assert!(
        !err.contains("overlap") && !err.contains("same instant"),
        "three unrelated captures do not overlap:\n{err}"
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
