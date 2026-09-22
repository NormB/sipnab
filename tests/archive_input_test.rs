// SPDX-License-Identifier: MIT OR Apache-2.0

//! An archive of captures reads exactly like the directory it would unpack to.
//!
//! `-I session.tgz` used to fail with libpcap's `unknown file format`: sipnab
//! gunzipped one layer and handed libpcap a tar. These tests run the real
//! binary over the same synthetic captures presented five ways — a directory, a
//! `.tar`, a `.tgz`, a `.tar.gz`, and a tar holding a `.tgz` and a gzipped
//! member — and require the SAME dialogs, message counts and streams from every
//! one. They also pin what the reader owes the operator along the way: every
//! member accounted for with a reason, frame pointers that round-trip through
//! `--show-frame`, bounded inflation, and nothing left in the temp directory.
//!
//! Every fixture is built here, in the test. No capture bytes are committed.
#![cfg(feature = "native")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/tar_build.rs"]
mod tar_build;

use tar_build::{Entry, gzip, tar};

/// Captures, by member name: three calls at distinct times, one of them with
/// an RTP stream, plus an LTE-MAC-style capture sipnab cannot decode.
fn captures() -> Vec<(&'static str, Vec<u8>)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut out = Vec::new();
    let mut at = |name: &'static str, frames: Vec<Vec<u8>>, start_usec: u64, link: u32| {
        let p = dir.path().join(name);
        let timed: Vec<(Vec<u8>, u64)> = frames
            .into_iter()
            .enumerate()
            .map(|(i, f)| (f, start_usec + i as u64 * 1_000))
            .collect();
        pcap_build::write_pcap_at(&p, &timed, link);
        out.push((name, std::fs::read(&p).expect("read back")));
    };
    at(
        "a.pcap",
        pcap_build::sip_call_frames("arch-a@test", "a1", "alice", "bob"),
        10_000_000,
        1,
    );
    at(
        "b.pcap",
        pcap_build::sdp_call_with_lossy_rtp("arch-b@test", 50, 1),
        20_000_000,
        1,
    );
    at(
        "c.pcap",
        pcap_build::sip_call_frames("arch-c@test", "c1", "carol", "dave"),
        30_000_000,
        1,
    );
    // DLT 149 (USER2), what a test handset's MAC-NR log uses. Not decodable, and
    // it must cost the run nothing but a counted, named line.
    at(
        "mac.pcap",
        vec![vec![0x42; 40], vec![0x43; 40]],
        5_000_000,
        149,
    );
    out
}

/// The members every archive form carries besides the captures: things an
/// archive of captures really holds, each of which must be named and skipped.
fn clutter() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty.pcap", Vec::new()),
        ("README.txt", b"captured on the lab bench".to_vec()),
    ]
}

/// Lay the fixture out every way the suite compares, under `root`.
///
/// Returns `(label, path)` pairs: the directory first, then each archive form.
fn forms(root: &Path) -> Vec<(&'static str, PathBuf)> {
    let caps = captures();
    let clutter = clutter();

    let dir = root.join("unpacked");
    std::fs::create_dir(&dir).expect("mkdir");
    for (name, bytes) in caps.iter().chain(clutter.iter()) {
        std::fs::write(dir.join(name), bytes).expect("write member");
    }

    let flat: Vec<Entry<'_>> = caps
        .iter()
        .chain(clutter.iter())
        .map(|(n, b)| Entry::file(n, b))
        .collect();
    let plain_tar = tar(&flat);
    let tar_path = root.join("set.tar");
    std::fs::write(&tar_path, &plain_tar).expect("tar");
    let tgz_path = root.join("set.tgz");
    std::fs::write(&tgz_path, gzip(&plain_tar)).expect("tgz");
    let targz_path = root.join("set.tar.gz");
    std::fs::write(&targz_path, gzip(&plain_tar)).expect("tar.gz");

    // Two layers inside a third: a `.tgz` holding a and b, and c gzipped but
    // still NAMED c.pcap — the layer is found by its bytes, not its name.
    let inner: Vec<Entry<'_>> = caps
        .iter()
        .filter(|(n, _)| matches!(*n, "a.pcap" | "b.pcap"))
        .map(|(n, b)| Entry::file(n, b))
        .collect();
    let inner_tgz = gzip(&tar(&inner));
    let c_gz = gzip(&caps.iter().find(|(n, _)| *n == "c.pcap").expect("c").1);
    let mac = &caps.iter().find(|(n, _)| *n == "mac.pcap").expect("mac").1;
    let mut outer = vec![
        Entry::dir("nested/"),
        Entry::file("nested/inner.tgz", &inner_tgz),
        Entry::file("nested/c.pcap", &c_gz),
        Entry::file("nested/mac.pcap", mac),
    ];
    for (n, b) in &clutter {
        outer.push(Entry::file(n, b));
    }
    let nested_path = root.join("nested.tar");
    std::fs::write(&nested_path, tar(&outer)).expect("nested");

    vec![
        ("directory", dir),
        ("tar", tar_path),
        ("tgz", tgz_path),
        ("tar.gz", targz_path),
        ("nested", nested_path),
    ]
}

/// Run the binary. `tmpdir` becomes its `TMPDIR`, so what it extracts can be
/// looked for afterwards.
fn sipnab(args: &[&str], tmpdir: &Path) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("TMPDIR", tmpdir)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// The dialogs a run printed, with every capture-location prefix removed from
/// frame pointers so a member of an archive and the same file in a directory
/// compare equal. Sorted, because two captures may interleave.
fn dialogs(stdout: &str, prefixes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = stdout
        .lines()
        .filter(|l| l.contains("\"call_id\""))
        .map(|l| {
            let mut s = l.to_string();
            for p in prefixes {
                s = s.replace(p.as_str(), "");
            }
            s
        })
        .collect();
    out.sort();
    out
}

/// The closing count line: packets, SIP messages, RTP packets, streams.
fn summary(stderr: &str) -> String {
    stderr
        .lines()
        .find_map(|l| l.split_once("sipnab: ").map(|(_, rest)| rest.to_string()))
        .filter(|l| l.contains("SIP messages"))
        .unwrap_or_else(|| panic!("no summary line in:\n{stderr}"))
}

fn extraction_dirs(tmpdir: &Path) -> Vec<String> {
    std::fs::read_dir(tmpdir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("sipnab-archive-"))
                .collect()
        })
        .unwrap_or_default()
}

/// The headline property: five presentations of one capture set, one answer.
#[test]
fn every_archive_form_reads_exactly_like_the_directory() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());

    let mut reference: Option<(Vec<String>, String)> = None;
    for (label, path) in &forms {
        let spec = path.display().to_string();
        let (stdout, stderr, code) = sipnab(
            &[
                "-N",
                "-I",
                &spec,
                "--json-dialogs",
                "--no-cli-print",
                "--portrange",
                "1-65535",
            ],
            tmp.path(),
        );
        assert_eq!(code, Some(0), "{label}: exit status\n{stderr}");
        let prefixes = vec![
            format!("{spec}/nested/inner.tgz/"),
            format!("{spec}/nested/"),
            format!("{spec}/"),
        ];
        let got = (dialogs(&stdout, &prefixes), summary(&stderr));
        assert_eq!(got.0.len(), 3, "{label}: three calls\n{stdout}");
        match &reference {
            None => reference = Some(got),
            Some(want) => {
                assert_eq!(&got.1, &want.1, "{label}: counts differ from the directory");
                assert_eq!(
                    &got.0, &want.0,
                    "{label}: dialogs differ from the directory"
                );
            }
        }
        assert!(
            extraction_dirs(tmp.path()).is_empty(),
            "{label}: extracted members left behind: {:?}",
            extraction_dirs(tmp.path())
        );
    }
}

/// Every member that is not read is named with its reason, and the
/// reconciling line counts them. An LTE MAC member is read, reported by link
/// type, and costs the run nothing else.
#[test]
fn every_member_is_accounted_for() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());
    let tgz = &forms.iter().find(|(l, _)| *l == "tgz").expect("tgz").1;
    let spec = tgz.display().to_string();
    let (_, stderr, code) = sipnab(
        &["-N", "-I", &spec, "--report", "--no-cli-print"],
        tmp.path(),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("Skipping '{spec}/empty.pcap': empty (0 bytes)")),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("Skipping '{spec}/README.txt': not a capture")),
        "{stderr}"
    );
    assert!(
        stderr.contains("2 archive member(s) not read"),
        "the reconciling line counts them: {stderr}"
    );
    assert!(
        stderr.contains(&format!("'{spec}/mac.pcap' has link type 149")),
        "{stderr}"
    );
    assert!(stderr.contains("4 of 4 file(s) read in full"), "{stderr}");
}

/// A BPF filter that cannot compile against the undecodable member skips it
/// instead of ending the run, which it still does for a decodable one.
#[test]
fn a_filter_skips_an_undecodable_member_rather_than_ending_the_run() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());
    let tgz = &forms.iter().find(|(l, _)| *l == "tgz").expect("tgz").1;
    let spec = tgz.display().to_string();
    let (_, stderr, code) = sipnab(
        &["-N", "-I", &spec, "--report", "--no-cli-print", "udp"],
        tmp.path(),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("Skipping '{spec}/mac.pcap': link type 149")),
        "{stderr}"
    );
}

/// A frame pointer minted from a member resolves through `--show-frame` to
/// the same bytes as the pointer minted from the same file in a directory.
#[test]
fn a_frame_pointer_into_a_member_round_trips() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());
    let pointer_for = |path: &Path| {
        let spec = path.display().to_string();
        let (stdout, stderr, _) = sipnab(
            &["-N", "-I", &spec, "--json", "--portrange", "1-65535"],
            tmp.path(),
        );
        stdout
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["frame"].as_str().map(str::to_string))
            .find(|f| f.contains("c.pcap#"))
            .unwrap_or_else(|| panic!("no pointer into c.pcap:\n{stdout}\n{stderr}"))
    };
    let dir_ptr = pointer_for(&forms[0].1);
    let (dir_frame, _, dir_code) = sipnab(&["--show-frame", &dir_ptr], tmp.path());
    assert_eq!(dir_code, Some(0));

    for (label, path) in &forms[1..] {
        let ptr = pointer_for(path);
        assert!(
            ptr.starts_with(&path.display().to_string()),
            "{label}: the pointer names the archive: {ptr}"
        );
        let (frame, stderr, code) = sipnab(&["--show-frame", &ptr], tmp.path());
        assert_eq!(code, Some(0), "{label}: {ptr}\n{stderr}");
        assert!(frame.starts_with("VERIFIED"), "{label}: {frame}");
        let bytes = |s: &str| s.lines().skip(3).collect::<Vec<_>>().join("\n");
        assert_eq!(bytes(&frame), bytes(&dir_frame), "{label}: different bytes");
        assert!(
            extraction_dirs(tmp.path()).is_empty(),
            "{label}: left behind"
        );
    }
}

/// `--cores` reads an archive's members the way the single-threaded reader
/// does.
#[test]
fn cores_reads_an_archive_the_same_way() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());
    let tgz = forms[2].1.display().to_string();
    let run = |cores: &str| {
        let (_, stderr, code) = sipnab(
            &[
                "-N",
                "-I",
                &tgz,
                "--report",
                "--no-cli-print",
                "--portrange",
                "1-65535",
                "--cores",
                cores,
            ],
            tmp.path(),
        );
        assert_eq!(code, Some(0), "--cores {cores}: {stderr}");
        summary(&stderr)
    };
    // The two paths word their closing line differently; the counts in it
    // are what must agree.
    let numbers = |line: String| -> Vec<String> {
        line.split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .take(4)
            .map(str::to_string)
            .collect()
    };
    assert_eq!(numbers(run("1")), numbers(run("2")));
    assert!(extraction_dirs(tmp.path()).is_empty());
}

/// A decompression bomb is refused at the ceiling, the refusal names the
/// ceiling and the flag that moves it, and nothing is left on disk.
#[test]
fn a_bomb_is_refused_at_the_ceiling_and_cleaned_up() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let mut big = captures().remove(0).1;
    big.resize(4 * 1024 * 1024, 0);
    let bomb = root.path().join("bomb.tgz");
    std::fs::write(&bomb, gzip(&tar(&[Entry::file("big.pcap", &big)]))).expect("bomb");
    let spec = bomb.display().to_string();
    let (_, stderr, code) = sipnab(
        &[
            "-N",
            "-I",
            &spec,
            "--report",
            "--no-cli-print",
            "--max-gunzip-bytes",
            "65536",
        ],
        tmp.path(),
    );
    assert_ne!(code, Some(0), "{stderr}");
    assert!(stderr.contains("65536-byte ceiling"), "{stderr}");
    assert!(stderr.contains("--max-gunzip-bytes"), "{stderr}");
    assert!(extraction_dirs(tmp.path()).is_empty(), "left behind");
}

/// A run that ends in a non-zero exit — here because the archive was cut off
/// inside its last member, so the run cannot vouch for the whole capture —
/// still removes what it extracted. `std::process::exit` runs no destructors,
/// so this is the path a missed cleanup would leave files on.
#[test]
fn a_run_that_exits_nonzero_still_removes_what_it_extracted() {
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let caps = captures();
    let whole = tar(&[
        Entry::file("a.pcap", &caps[0].1),
        Entry::file("b.pcap", &caps[1].1),
    ]);
    // Cut inside b.pcap's data: the tar reads, a is whole, b is a prefix.
    let cut_at = 512 + caps[0].1.len().div_ceil(512) * 512 + 512 + 100;
    let cut = root.path().join("cut.tgz");
    std::fs::write(&cut, gzip(&whole[..cut_at])).expect("write");
    let spec = cut.display().to_string();
    let (_, stderr, code) = sipnab(
        &[
            "-N",
            "-I",
            &spec,
            "--report",
            "--no-cli-print",
            "--portrange",
            "1-65535",
        ],
        tmp.path(),
    );
    assert_eq!(code, Some(1), "an incomplete run exits 1\n{stderr}");
    assert!(
        stderr.contains("ends before its archive says it should"),
        "{stderr}"
    );
    assert!(
        extraction_dirs(tmp.path()).is_empty(),
        "left behind: {:?}",
        extraction_dirs(tmp.path())
    );
}

/// An archive the system `tar` wrote — GNU or BSD, whichever is installed —
/// reads like the directory it was made from. The one check this suite's own
/// writer cannot give.
#[test]
fn an_archive_the_system_tar_wrote_reads_like_its_directory() {
    let have_tar = Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_tar {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED an_archive_the_system_tar_wrote_reads_like_its_directory: no `tar` on PATH"
        );
        return;
    }
    let root = tempfile::tempdir().expect("root");
    let tmp = tempfile::tempdir().expect("tmpdir");
    let forms = forms(root.path());
    let dir = &forms[0].1;
    let made = root.path().join("system.tgz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&made)
        .arg("-C")
        .arg(dir)
        .arg(".")
        .status()
        .expect("run tar");
    assert!(status.success());

    let count = |path: &Path| {
        let spec = path.display().to_string();
        let (_, stderr, code) = sipnab(
            &[
                "-N",
                "-I",
                &spec,
                "--report",
                "--no-cli-print",
                "--portrange",
                "1-65535",
            ],
            tmp.path(),
        );
        assert_eq!(code, Some(0), "{stderr}");
        summary(&stderr)
    };
    assert_eq!(count(&made), count(dir));
}
