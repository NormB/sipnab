// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gate: the repository ships no ITU table values.
//!
//! The user-supplied tables (the trained codebooks and every other value the
//! Recommendation neither states nor defines by formula) must never appear in
//! a file that could be committed. This test imports them through the real
//! path, writes the table file, and runs `scripts/no-itu-values.py` over
//! every git-tracked file and every untracked file git does not ignore.
//!
//! The scan itself lives in that script, the one rule this test and the
//! release workflow's scan of the built binaries and packages share: a run of
//! 6 or more integer literals separated only by whitespace, commas,
//! semicolons, brackets, braces or parentheses that equals a contiguous run
//! of any user-supplied table, or the same 6 values as 16- or 32-bit
//! integers in a file's bytes. A match fails the test, naming the file, the
//! line and the table, never the values. `scripts/tests/test_no_itu_values.py`
//! tests the rule itself.

pub mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> std::io::Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
}

#[test]
fn the_repository_ships_no_itu_table_values() -> common::TestResult {
    let root = repo_root()?;
    let dir = std::env::temp_dir().join(format!("g729-no-itu-values-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let tables = dir.join("g729-tables.bin");
    std::fs::write(&tables, common::table_file()?)?;
    let names: Vec<&str> = g729::tables::ENTRIES.iter().map(|e| e.name).collect();
    let out = Command::new("python3")
        .arg(root.join("scripts/no-itu-values.py"))
        .arg("--tables")
        .arg(&tables)
        .arg("--names")
        .arg(names.join(","))
        .arg("--git-repo")
        .arg(&root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_WORK_TREE")
        .output();
    std::fs::remove_dir_all(&dir)?;
    let out = out?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let scanned: usize = stdout
        .split(' ')
        .nth(1)
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("no file count in: {stdout}"))?;
    assert!(scanned > 100, "git lists the repository's files: {stdout}");
    Ok(())
}
