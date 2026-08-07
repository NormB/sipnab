// SPDX-License-Identifier: MIT OR Apache-2.0

//! An output path must never be an input path.
//!
//! `sipnab -I capture.pcap -O capture.pcap` opened the capture, truncated the
//! same file as the output, wrote whatever it had managed to read back over the
//! top, and exited 0. The original capture is gone. One tab-completion reaches
//! it, and an incident capture is very often the only copy in existence.
//!
//! Every assertion here compares the input's bytes before and after, because
//! "the run errored" is not the property that matters — "the file is still
//! there, unchanged" is. A guard that refuses *after* opening the writer would
//! satisfy an exit-code assertion and still have truncated the file.
//!
//! The comparison is by CANONICAL path, so `a.pcap`, `./a.pcap`, `dir/../a.pcap`
//! and a symlink pointing at it are all the same file, which is exactly how the
//! shell produces this mistake in the first place.

use std::path::{Path, PathBuf};

/// A fresh temp directory for one test.
fn tmp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sipnab-clobber-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

/// Copy a checked-in sample capture into `dir` under `name` and return its path.
fn sample_into(dir: &Path, name: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pcap-samples/register-invite-reinvite-bye.pcap");
    let dst = dir.join(name);
    std::fs::copy(&src, &dst).expect("copy sample capture");
    dst
}

/// Run sipnab with the given args, returning `(stderr, exit_code)`.
fn run(args: &[&str]) -> (String, Option<i32>) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Assert the capture at `path` is byte-identical to `before`.
fn assert_intact(path: &Path, before: &[u8], what: &str) {
    let after = std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{what}: the input capture is GONE ({e}) — {}",
            path.display()
        )
    });
    assert_eq!(
        after.len(),
        before.len(),
        "{what}: the input capture changed size ({} -> {} bytes) — it was \
         written over",
        before.len(),
        after.len()
    );
    assert!(
        after == before,
        "{what}: the input capture's contents changed — it was written over"
    );
}

/// Assert the run refused with an argument error that names the collision.
fn assert_refused(stderr: &str, code: Option<i32>, what: &str) {
    assert_eq!(
        code,
        Some(2),
        "{what}: expected an argument-error exit (2); stderr: {stderr}"
    );
    assert!(
        stderr.contains("would overwrite"),
        "{what}: the refusal must say the output would overwrite an input; \
         stderr: {stderr}"
    );
}

/// The literal case: the same string for `-I` and `-O`.
#[test]
fn output_at_the_input_path_is_refused_and_the_input_survives() {
    let dir = tmp_dir("same-path");
    let cap = sample_into(&dir, "capture.pcap");
    let before = std::fs::read(&cap).expect("read input");
    let p = cap.to_str().expect("utf8 path");

    let (stderr, code) = run(&["-N", "--quiet", "-I", p, "-O", p]);

    assert_refused(&stderr, code, "-I X -O X");
    assert_intact(&cap, &before, "-I X -O X");
}

/// Different spellings of the same file must still collide: canonicalization,
/// not string equality.
#[test]
fn different_spellings_of_the_same_file_still_collide() {
    let dir = tmp_dir("spellings");
    let cap = sample_into(&dir, "capture.pcap");
    let before = std::fs::read(&cap).expect("read input");
    let plain = cap.to_str().expect("utf8 path").to_string();
    // `dir/./capture.pcap` and `dir/sub/../capture.pcap` name the same inode.
    std::fs::create_dir_all(dir.join("sub")).expect("mkdir sub");
    let dotted = dir.join(".").join("capture.pcap");
    let dotdot = dir.join("sub").join("..").join("capture.pcap");

    for spelling in [&dotted, &dotdot] {
        let out = spelling.to_str().expect("utf8 path");
        let (stderr, code) = run(&["-N", "--quiet", "-I", &plain, "-O", out]);
        assert_refused(&stderr, code, &format!("-O {out}"));
        assert_intact(&cap, &before, &format!("-O {out}"));
    }
}

/// A symlink whose target is the input is the input.
#[test]
fn a_symlink_to_the_input_is_refused() {
    let dir = tmp_dir("symlink");
    let cap = sample_into(&dir, "capture.pcap");
    let before = std::fs::read(&cap).expect("read input");
    let link = dir.join("link.pcap");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&cap, &link).expect("create symlink");

    let (stderr, code) = run(&[
        "-N",
        "--quiet",
        "-I",
        cap.to_str().expect("utf8"),
        "-O",
        link.to_str().expect("utf8"),
    ]);

    assert_refused(&stderr, code, "-O symlink-to-input");
    assert_intact(&cap, &before, "-O symlink-to-input");
}

/// `-I` takes a directory, so the whole resolved SET is protected — writing
/// into a directory being read is the same failure with more files.
#[test]
fn writing_into_a_directory_being_read_is_refused() {
    let dir = tmp_dir("dir-input");
    let a = sample_into(&dir, "a.pcap");
    let b = sample_into(&dir, "b.pcap");
    let before_a = std::fs::read(&a).expect("read a");
    let before_b = std::fs::read(&b).expect("read b");

    // The output names an existing member of the set.
    let (stderr, code) = run(&[
        "-N",
        "--quiet",
        "-I",
        dir.to_str().expect("utf8"),
        "-O",
        a.to_str().expect("utf8"),
    ]);
    assert_refused(&stderr, code, "-I dir -O dir/a.pcap");
    assert_intact(&a, &before_a, "-I dir -O dir/a.pcap");
    assert_intact(&b, &before_b, "-I dir -O dir/a.pcap");

    // And a NEW name inside the same directory: harmless on this run, an
    // input on the next one, which is the same loss one run later.
    let fresh = dir.join("out.pcap");
    let (stderr, code) = run(&[
        "-N",
        "--quiet",
        "-I",
        dir.to_str().expect("utf8"),
        "-O",
        fresh.to_str().expect("utf8"),
    ]);
    assert_refused(&stderr, code, "-I dir -O dir/new.pcap");
    assert_intact(&a, &before_a, "-I dir -O dir/new.pcap");
}

/// `--split` rotates `-O out.pcap` into `out_00001.pcap`, so a rotated name
/// that is already an input is the same overwrite by a different route.
#[test]
fn split_rotation_onto_an_input_is_refused() {
    let dir = tmp_dir("split");
    let rotated = sample_into(&dir, "cap_00001.pcap");
    let before = std::fs::read(&rotated).expect("read input");
    let base = dir.join("cap.pcap");

    let (stderr, code) = run(&[
        "-N",
        "--quiet",
        "-I",
        rotated.to_str().expect("utf8"),
        "-O",
        base.to_str().expect("utf8"),
        "--split",
        "filesize:1",
    ]);

    assert_refused(&stderr, code, "--split rotating onto an input");
    assert_intact(&rotated, &before, "--split rotating onto an input");
}

/// `--strip-secrets` writes a sanitised COPY; the docs promise the input is
/// never modified. Pointed at its own input it replaced it, taking the only
/// copy of the decryption secrets with it.
#[test]
fn strip_secrets_onto_its_own_input_is_refused() {
    #[path = "support/pcap_build.rs"]
    mod pcap_build;

    let dir = tmp_dir("strip");
    let cap = dir.join("secrets.pcapng");
    let frame = pcap_build::udp_frame(
        [10, 1, 0, 1],
        [10, 2, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bK1\r\n\
          From: <sip:a@10.1.0.1>;tag=1\r\nTo: <sip:b@10.2.0.1>\r\nCall-ID: strip-guard\r\n\
          CSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    );
    pcap_build::write_pcapng_with_dsb(&cap, "CLIENT_RANDOM 00 11\n", &frame);
    let before = std::fs::read(&cap).expect("read input");
    assert_eq!(
        pcap_build::count_pcapng_blocks(&cap, 0x0000_000a),
        1,
        "the fixture must start with a Decryption Secrets Block"
    );

    let p = cap.to_str().expect("utf8");
    let (stderr, code) = run(&["-N", "--quiet", "-I", p, "--strip-secrets", p]);

    assert_eq!(
        code,
        Some(2),
        "--strip-secrets onto its own input must be refused; stderr: {stderr}"
    );
    assert!(
        stderr.contains("would overwrite"),
        "the refusal must say the output would overwrite an input; stderr: {stderr}"
    );
    assert_intact(&cap, &before, "--strip-secrets X -I X");
    assert_eq!(
        pcap_build::count_pcapng_blocks(&cap, 0x0000_000a),
        1,
        "the only copy of the decryption secrets must survive"
    );
}

/// The guard must not fire on a legitimate run: a distinct output in a
/// different directory still writes.
#[test]
fn a_distinct_output_path_still_works() {
    let dir = tmp_dir("ok");
    let cap = sample_into(&dir, "capture.pcap");
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");
    let out = out_dir.join("copy.pcap");

    let (stderr, code) = run(&[
        "-N",
        "--quiet",
        "--no-cli-print",
        "-I",
        cap.to_str().expect("utf8"),
        "-O",
        out.to_str().expect("utf8"),
    ]);

    assert_eq!(code, Some(0), "a legitimate -O must still run; {stderr}");
    assert!(
        out.is_file() && std::fs::metadata(&out).expect("stat").len() > 24,
        "the legitimate output was not written"
    );
}
