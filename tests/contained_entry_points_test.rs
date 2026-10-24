// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every offline reader of untrusted bytes runs its unit inside a
//! containment scope (PANIC-ABORT-HOSTILE-INPUT).
//!
//! A panic in a parser, sipnab's or a dependency's, used to end the process,
//! so one hostile frame, record, archive member or vCon container ended the
//! whole run. Each reader now passes its unit through
//! `crate::capture::contained`, which turns the panic into an error for that
//! unit. The unit tests beside each reader prove the error; this file holds
//! the wiring, so a refactor that calls the uncontained half directly fails
//! here rather than in production on the next hostile input.
//!
//! What it holds:
//!
//! 1. Each entry point the readers call reaches its contained seam, and each
//!    seam opens its scope under its own label, exactly once.
//! 2. Under `src/capture`, `crate::crash::contain` is called in one place,
//!    `contained`, so every reader converts a panic the same way.

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

/// The body of the first `fn <name>(` or `fn <name><` in `src`: from that line
/// to the closing brace at the same indentation.
fn body_of<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = [format!("fn {name}("), format!("fn {name}<")]
        .iter()
        .filter_map(|needle| src.find(needle.as_str()))
        .min()?;
    let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
    let indent: String = src[line_start..]
        .chars()
        .take_while(|c| *c == ' ')
        .collect();
    let close = format!("\n{indent}}}\n");
    let end = src[start..].find(&close)?;
    Some(&src[start..start + end + close.len()])
}

/// An entry point the readers call, the seam its body must reach, and the
/// scope label the seam opens.
struct Entry {
    file: &'static str,
    entry: &'static str,
    calls: &'static str,
    seam: &'static str,
    opens: &'static str,
}

const ENTRIES: &[Entry] = &[
    Entry {
        file: "src/capture/mod.rs",
        entry: "decode_captured_frame",
        calls: "decode_frame_with(",
        seam: "decode_frame_with",
        opens: "contained_parse(\"captured frame\"",
    },
    Entry {
        file: "src/capture/frames.rs",
        entry: "next",
        calls: "contained_record(",
        seam: "contained_record",
        opens: "crate::capture::contained(\"capture record\"",
    },
    Entry {
        file: "src/capture/archive/mod.rs",
        entry: "walk",
        calls: "crate::capture::contained(\"archive member\"",
        seam: "walk",
        opens: "crate::capture::contained(\"archive member\"",
    },
    Entry {
        file: "src/capture/vcon_input.rs",
        entry: "read_file_reporting",
        calls: "rebuild_bytes_with(",
        seam: "rebuild_bytes_with",
        opens: "crate::capture::contained(\"vCon container\"",
    },
];

#[test]
fn every_offline_reader_reaches_its_containment_scope() -> Result<(), TestError> {
    for e in ENTRIES {
        let src = read(e.file)?;
        let entry =
            body_of(&src, e.entry).ok_or_else(|| format!("{}: no `fn {}(`", e.file, e.entry))?;
        assert!(
            entry.contains(e.calls),
            "{}: `{}` no longer calls `{}`, so a panic in it ends the process",
            e.file,
            e.entry,
            e.calls
        );
        let seam =
            body_of(&src, e.seam).ok_or_else(|| format!("{}: no `fn {}(`", e.file, e.seam))?;
        assert!(
            seam.contains(e.opens),
            "{}: `{}` no longer opens `{}`",
            e.file,
            e.seam,
            e.opens
        );
        assert_eq!(
            src.matches(e.opens).count(),
            1,
            "{}: `{}` should appear exactly once",
            e.file,
            e.opens
        );
    }
    Ok(())
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), TestError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn the_capture_readers_reach_crash_contain_through_one_function() -> Result<(), TestError> {
    let mut files = Vec::new();
    rust_files(&repo().join("src/capture"), &mut files)?;
    let mut sites = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f)?;
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("crate::crash::contain(") {
                let rel = f.strip_prefix(repo()).unwrap_or(f).display().to_string();
                sites.push(format!("{rel}:{}", n + 1));
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "`crate::crash::contain` should be called once under src/capture, in \
         `contained`; found {sites:?}"
    );
    let capture = read("src/capture/mod.rs")?;
    let contained =
        body_of(&capture, "contained").ok_or("src/capture/mod.rs: no `fn contained(`")?;
    assert!(
        contained.contains("crate::crash::contain("),
        "the one call is not in `contained`"
    );
    Ok(())
}

#[test]
fn body_of_stops_at_the_functions_own_closing_brace() -> Result<(), TestError> {
    let src = "impl X {\n    fn a() {\n        if x {\n        }\n    }\n\n    fn b() {}\n}\n";
    let a = body_of(src, "a").ok_or("finds a")?;
    assert!(a.ends_with("    }\n"), "{a:?}");
    assert!(!a.contains("fn b"), "{a:?}");
    let generic = "fn c<T>(x: T) -> T {\n    x\n}\n";
    assert!(
        body_of(generic, "c").is_some(),
        "a generic function is found"
    );
    Ok(())
}
