// SPDX-License-Identifier: MIT OR Apache-2.0

//! No lint is silenced where the lint names a design problem.
//!
//! An `allow` for one of these lints hides what the lint found: a function
//! that takes too many loose values, a function that does too much, a type
//! nobody named. Each is fixed by a better design, not an attribute, and this
//! gate keeps the attribute from coming back. It reads every tracked `.rs`
//! file, `cfg_attr(..., allow(...))` and crate-level `#![allow(...)]` included.
//!
//! The list grows as each lint's existing suppressions are reworked away.

use std::process::Command;

/// Lints whose suppression is refused, with the design fix each one asks for.
const REFUSED: &[(&str, &str)] = &[(
    "too_many_arguments",
    "group the values that travel together into a named type",
)];

/// Every `allow` attribute naming a refused lint, as `path:line: lint`.
fn suppressions() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    let mut found = Vec::new();
    let mut files = 0;
    for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
        if rel.is_empty() {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(root.join(rel)).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if !code.contains("allow(") {
                continue;
            }
            for (lint, _) in REFUSED {
                if code.contains(&format!("clippy::{lint}")) {
                    found.push(format!("{rel}:{}: {lint}", n + 1));
                }
            }
        }
    }
    assert!(files >= 600, "read only {files} source files");
    found
}

#[test]
fn no_refused_lint_is_suppressed() {
    let found = suppressions();
    let fixes: Vec<String> = REFUSED
        .iter()
        .map(|(lint, fix)| format!("{lint}: {fix}"))
        .collect();
    assert!(
        found.is_empty(),
        "{} suppression(s) of a lint that names a design problem:\n  {}\n\nFix the design instead:\n  {}",
        found.len(),
        found.join("\n  "),
        fixes.join("\n  ")
    );
}
