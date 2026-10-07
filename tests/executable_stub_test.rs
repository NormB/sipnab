// SPDX-License-Identifier: MIT OR Apache-2.0

//! No test writes a file itself and then runs it.
//!
//! Linux refuses to execute a file that any process has open for writing
//! (`ETXTBSY`). A child forked by another test thread inherits every
//! descriptor this process holds at that instant and keeps it until its own
//! `exec`, so a stub written with `std::fs::write` and run straight after can
//! fail with "Text file busy" when the suite runs loaded.
//! `the_ci_proof_step_macos_branch_checks_the_zip_and_the_uuid` failed that
//! way on main (CI run 37566862854). `support/executable.rs` writes the file
//! from a child process, so this process never holds a writable descriptor
//! to it. This gate finds a file that a test writes in-process and then
//! marks executable.

/// `set_permissions` calls that grant execute, on a path the same test wrote
/// with `std::fs::write` or `File::create` in the lines just before it.
fn written_then_made_executable(src: &str) -> Vec<usize> {
    const LOOKBACK: usize = 25;
    let lines: Vec<&str> = src.lines().collect();
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(at) = line.find("set_permissions(") else {
            continue;
        };
        if !grants_execute(line) {
            continue;
        }
        let Some(target) = first_argument(&line[at + "set_permissions(".len()..]) else {
            continue;
        };
        let start = i.saturating_sub(LOOKBACK);
        let wrote = lines[start..i].iter().enumerate().any(|(k, before)| {
            let joined = joined_from(&lines, start + k);
            ["fs::write(", "File::create("].iter().any(|call| {
                before.contains(call)
                    && joined
                        .find(call)
                        .and_then(|p| first_argument(&joined[p + call.len()..]))
                        .is_some_and(|written| same_path(&written, &target))
            })
        });
        if wrote {
            found.push(i + 1);
        }
    }
    found
}

/// Line `at` with the next few appended, so a call split across lines by
/// rustfmt reads as one.
fn joined_from(lines: &[&str], at: usize) -> String {
    lines[at..lines.len().min(at + 4)].join(" ")
}

/// Whether a `from_mode(0oNNN)` on this line sets an execute bit.
fn grants_execute(line: &str) -> bool {
    line.match_indices("from_mode(0o").any(|(at, m)| {
        line[at + m.len()..]
            .chars()
            .take(3)
            .filter_map(|c| c.to_digit(8))
            .any(|d| d & 1 == 1)
    })
}

/// The text of a call's first argument, up to the first top-level comma.
fn first_argument(after_paren: &str) -> Option<String> {
    let mut depth = 0i32;
    for (at, c) in after_paren.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => return Some(after_paren[..at].trim().to_string()),
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return Some(after_paren[..at].trim().to_string()),
            _ => {}
        }
    }
    None
}

/// Two argument texts that name the same path, ignoring a leading `&`.
fn same_path(a: &str, b: &str) -> bool {
    a.trim_start_matches('&').trim() == b.trim_start_matches('&').trim()
}

#[test]
fn the_scan_finds_a_written_stub_made_executable() {
    let src = "let dd = bin.join(\"x\");\nstd::fs::write(&dd, stub)?;\nstd::fs::set_permissions(&dd, std::fs::Permissions::from_mode(0o755))?;\n";
    assert_eq!(written_then_made_executable(src), vec![3]);
    let split = "std::fs::write(\n    &stub,\n    body,\n)\n?;\nstd::fs::set_permissions(&stub, Permissions::from_mode(0o700))?;\n";
    assert_eq!(written_then_made_executable(split), vec![6]);
}

#[test]
fn the_scan_ignores_directories_and_non_executable_modes() {
    let dir = "std::fs::create_dir(&ro)?;\nstd::fs::set_permissions(&ro, Permissions::from_mode(0o555))?;\n";
    assert!(written_then_made_executable(dir).is_empty());
    let data = "std::fs::write(&key, pem)?;\nstd::fs::set_permissions(&key, Permissions::from_mode(0o600))?;\n";
    assert!(written_then_made_executable(data).is_empty());
}

#[test]
fn no_test_runs_a_file_it_wrote_itself() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut offenders = Vec::new();
    let mut files = 0;
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs")
                || path.ends_with("executable_stub_test.rs")
            {
                continue;
            }
            files += 1;
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            for line in written_then_made_executable(&src) {
                let rel = path.strip_prefix(&root).unwrap_or(&path);
                offenders.push(format!("tests/{}:{line}", rel.display()));
            }
        }
    }
    assert!(files > 300, "scanned only {files} test files");
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "these write a file in this process and then make it executable; a \
         sibling test's child can hold it open and the exec fails with \
         ETXTBSY. Write it with support/executable.rs::write_executable:\n  {}",
        offenders.join("\n  ")
    );
}
