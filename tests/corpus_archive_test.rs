// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every real archive in the corpus reads exactly like its members unpacked.
//!
//! The synthetic suite (`archive_input_test`) proves the reader against
//! archives this repository built. This one proves it against archives people
//! actually made: for each tar or gzip-compressed tar under `SIPNAB_CORPUS`,
//! the system `tar` unpacks it into a scratch directory, and sipnab reads the
//! archive and the directory. The closing counts — packets, SIP messages, RTP
//! packets, streams — and the number of dialogs must agree exactly.
//!
//! The corpus is real traffic and never leaves the machine it was captured on,
//! so this suite skips, audibly, when `SIPNAB_CORPUS` is unset, and nothing
//! from it is written anywhere but a scratch directory deleted on the way out.
#![cfg(feature = "native")]

use std::io::Read;
use std::path::Path;
use std::process::Command;

#[path = "support/corpus.rs"]
mod corpus_support;

/// Whether `path` is a tar, possibly gzip-compressed: the archives sipnab
/// reads as a set. Judged by the bytes, as sipnab judges them.
fn holds_members(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 512];
    let Ok(n) = f.read(&mut head) else {
        return false;
    };
    let block: Vec<u8> = if head[..n].starts_with(&[0x1f, 0x8b]) {
        let Ok(f) = std::fs::File::open(path) else {
            return false;
        };
        let mut inner = vec![0u8; 512];
        let mut dec = flate2::read::MultiGzDecoder::new(f);
        if dec.read_exact(&mut inner).is_err() {
            return false;
        }
        inner
    } else {
        head[..n].to_vec()
    };
    block.len() >= 512 && &block[257..262] == b"ustar"
}

/// `(closing counts, dialogs)` for one `-I` input.
fn read(input: &Path, recursive: bool) -> (String, usize) {
    let spec = input.display().to_string();
    let mut args = vec![
        "-N",
        "-I",
        spec.as_str(),
        "--json-dialogs",
        "--no-cli-print",
        "--portrange",
        "1-65535",
    ];
    if recursive {
        args.push("--recursive");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let counts = stderr
        .lines()
        .find_map(|l| l.split_once("sipnab: ").map(|(_, r)| r.to_string()))
        .filter(|l| l.contains("SIP messages"))
        .unwrap_or_else(|| panic!("no summary for {spec}:\n{stderr}"));
    let dialogs = stdout.lines().filter(|l| l.contains("\"call_id\"")).count();
    (counts, dialogs)
}

#[test]
fn every_corpus_archive_reads_like_its_unpacked_members() {
    let Some(root) = corpus_support::root() else {
        return;
    };
    let have_tar = Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have_tar {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "SKIPPED every_corpus_archive_reads_like_its_unpacked_members: no `tar` on PATH"
        );
        return;
    }
    let archives: Vec<_> = corpus_support::walk(&root)
        .into_iter()
        .filter(|p| holds_members(p))
        .collect();
    {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "corpus_archive_test: {} archive(s) under {}",
            archives.len(),
            root.display()
        );
    }
    for archive in &archives {
        let scratch = tempfile::tempdir().expect("scratch");
        let status = Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(scratch.path())
            .status()
            .expect("run tar");
        assert!(
            status.success(),
            "tar could not unpack {}",
            archive.display()
        );
        let from_archive = read(archive, false);
        let from_directory = read(scratch.path(), true);
        assert_eq!(
            from_archive,
            from_directory,
            "{} reads differently from its unpacked members",
            archive.display()
        );
    }
}
