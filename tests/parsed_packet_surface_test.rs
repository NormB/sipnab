//! Every `ParsedPacket` literal in the repository names `frame_bytes`.
//!
//! Adding that field meant editing every construction site. The sweep was
//! driven off `cargo test --no-run`, which does not build `benches/`, so
//! `benches/store_bench.rs` was missed and the push was blocked by
//! `clippy --workspace --all-features --all-targets` -- a wider target set than
//! the one the sweep had used.
//!
//! The gate did its job. What was missing was any way to notice BEFORE paying a
//! compile of every target: this scans source text, so it sees a directory the
//! narrower command never builds, and it runs in milliseconds.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file in the directories that carry compilable targets.
fn scanned_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    for d in ["src", "tests", "benches", "fuzz", "examples"] {
        let dir = repo().join(d);
        if dir.is_dir() {
            walk(&dir, &mut out);
        }
    }
    out.sort();
    out
}

/// Byte offsets of each `ParsedPacket {` literal, ignoring the definition and
/// any occurrence inside a comment.
fn literal_sites(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || t.starts_with('*') {
            continue;
        }
        if t.contains("struct ParsedPacket") {
            continue;
        }
        // A RETURN TYPE is not a construction site. `fn f() -> ParsedPacket {`
        // opens a function body, and flagging it reported two healthy helpers
        // in pipeline.rs that build their value by calling another function.
        if t.contains("-> ParsedPacket {") {
            continue;
        }
        // Nor is the pattern written inside a string. Without this the scanner
        // matches its OWN source and reports itself -- the same self-match that
        // makes `pgrep -f` find its own command line.
        let Some(at) = line.find("ParsedPacket {") else {
            continue;
        };
        if line[..at].matches('"').count() % 2 == 1 {
            continue;
        }
        out.push(i);
    }
    out
}

/// 1. Every construction site names the field.
#[test]
fn every_parsed_packet_literal_names_frame_bytes() {
    let mut offenders = Vec::new();
    let mut sites = 0usize;
    for f in scanned_files() {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        for start in literal_sites(&text) {
            sites += 1;
            // A struct literal's fields sit between the brace and the matching
            // close. Scanning a bounded window is enough: these literals list
            // ~18 fields and none is anywhere near 60 lines long.
            let end = (start + 60).min(lines.len());
            let body = lines[start..end].join("\n");
            let body = body.split("\n    }").next().unwrap_or(&body);
            if !body.contains("frame_bytes") && !body.contains("..") {
                let rel = f.strip_prefix(repo()).unwrap_or(&f).display();
                offenders.push(format!("{rel}:{}", start + 1));
            }
        }
    }
    assert!(
        sites > 30,
        "only {sites} construction sites found; the walk is not reaching the \
         tree and this gate would pass on an empty repository"
    );
    assert!(
        offenders.is_empty(),
        "these `ParsedPacket` literals do not name `frame_bytes`. Without it \
         the frame's bytes never reach the retention site, so every pointer \
         built from one resolves UNVERIFIED:\n{}",
        offenders.join("\n")
    );
}

/// 2. The scan actually reaches `benches/` — the directory that broke.
///
/// `cargo test --no-run` does not build benches, which is exactly why the miss
/// happened. If this scanner shares that blind spot it reproduces the bug it
/// exists to prevent, and gate 1 would pass while a bench site was missing.
#[test]
fn the_scan_reaches_the_target_dirs_a_test_build_skips() {
    let files = scanned_files();
    let rels: Vec<String> = files
        .iter()
        .map(|f| f.strip_prefix(repo()).unwrap_or(f).display().to_string())
        .collect();
    for dir in ["src/", "tests/", "benches/"] {
        assert!(
            rels.iter().any(|r| r.starts_with(dir)),
            "the scan found no .rs files under {dir}. `cargo test --no-run` \
             skips benches/, which is how store_bench.rs was missed; a scanner \
             blind to the same directory is no improvement on it.\nfound: {:?}",
            &rels[..rels.len().min(5)]
        );
    }
    assert!(
        rels.iter().any(|r| r.starts_with("benches/")
            && std::fs::read_to_string(repo().join(r)).is_ok_and(|t| t.contains("ParsedPacket {"))),
        "no bench constructs a ParsedPacket any more. If that is deliberate \
         this gate has lost the case it was written for and should be re-aimed \
         rather than left passing vacuously"
    );
}
