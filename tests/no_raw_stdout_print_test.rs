// SPDX-License-Identifier: MIT OR Apache-2.0

//! No program code writes to stdout with `print!` or `println!`.
//!
//! Both panic when the write fails, and a reader closing the pipe
//! (`sipnab ... | head -1`) makes every later write fail. A run's answer goes
//! through `out!` / `outln!` (`src/output/stdout.rs`) or the per-message
//! `BatchSink`, which treat a closed pipe as the reader's choice. `src/bin/`
//! holds developer tools that never run behind a pipe and is not scanned.

use std::path::{Path, PathBuf};

/// The error a test returns.
type TestError = Box<dyn std::error::Error>;

/// The 1-based lines of `src` that call `print!` or `println!`, ignoring
/// comment lines (doc examples included) and `eprint!` / `eprintln!`.
fn raw_print_lines(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| {
            line.match_indices("print").any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let after = &line[at + "print".len()..];
                !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                    && (after.starts_with("!(") || after.starts_with("ln!("))
            })
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// Every `.rs` file under `dir`, recursively, skipping `skip`.
fn rust_files(dir: &Path, skip: &Path, out: &mut Vec<PathBuf>) -> Result<(), TestError> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path == skip {
            continue;
        }
        if path.is_dir() {
            rust_files(&path, skip, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn a_print_call_is_found_and_comments_and_stderr_are_not() {
    let src = "fn f() {\n    println!(\"a\");\n    print!(\"b\");\n    eprintln!(\"c\");\n    \
               // println!(\"d\");\n    /// print!(\"e\");\n    outln!(\"f\");\n    \
               let s = format!(\"x\"); sprint!(s);\n}\n";
    assert_eq!(raw_print_lines(src), [2, 3]);
}

#[test]
fn no_program_code_prints_to_stdout_with_print_macros() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &root.join("bin"), &mut files)?;
    assert!(
        files.len() > 100,
        "the scan read only {} files",
        files.len()
    );
    let mut found = Vec::new();
    for file in &files {
        for line in raw_print_lines(&std::fs::read_to_string(file)?) {
            found.push(format!("{}:{line}", file.display()));
        }
    }
    assert!(
        found.is_empty(),
        "these lines print to stdout with a macro that panics when the reader \
         closes the pipe; use out!/outln! from src/output/stdout.rs:\n{}",
        found.join("\n")
    );
    Ok(())
}
