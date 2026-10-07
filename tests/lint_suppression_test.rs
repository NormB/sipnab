// SPDX-License-Identifier: MIT OR Apache-2.0

//! No lint is silenced where the lint names a design problem.
//!
//! An `allow` for one of these lints hides what the lint found: a function
//! that takes too many loose values, a function that does too much, a type
//! nobody named. Each is fixed by a better design, not an attribute, and this
//! gate keeps the attribute from coming back. It reads every tracked `.rs`
//! file, `expect` as well as `allow`, `cfg_attr(..., allow(...))` and crate-level
//! `#![allow(...)]` included, and attributes that span several lines.
//!
//! The list grows as each lint's existing suppressions are reworked away.

use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// Lints whose suppression is refused, as written in an `allow`, with the
/// design fix each one asks for. Clippy's carry their `clippy::` prefix;
/// rustc's own (`unused_mut`) have none.
const REFUSED: &[(&str, &str)] = &[
    (
        "clippy::too_many_arguments",
        "group the values that travel together into a named type",
    ),
    (
        "clippy::large_enum_variant",
        "box the large variant's data so every value of the enum stays small",
    ),
    (
        "clippy::type_complexity",
        "name the type: a struct with named fields instead of a nested tuple",
    ),
    (
        "clippy::wildcard_imports",
        "name every import, so each name says where it comes from",
    ),
    (
        "clippy::many_single_char_names",
        "name the bindings for what they hold",
    ),
    (
        "clippy::cognitive_complexity",
        "split the function along its decisions, each one testable alone",
    ),
    (
        "unused_mut",
        "compute the value in one expression per feature set instead of \
         mutating it inside cfg blocks",
    ),
    (
        "unused_variables",
        "bind the value inside the cfg block that uses it",
    ),
];

/// Every `allow` attribute naming a refused lint, as `path:line: lint`.
fn suppressions() -> Result<Vec<String>, TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("git")
        .args(["ls-files", "-z", "--", "*.rs"])
        .current_dir(root)
        .output()?;
    assert!(out.status.success(), "git ls-files failed");
    let mut found = Vec::new();
    let mut files = 0;
    for rel in String::from_utf8_lossy(&out.stdout).split('\0') {
        if rel.is_empty() {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(root.join(rel))?;
        for (line, lint) in refused_in(&text) {
            found.push(format!("{rel}:{line}: {lint}"));
        }
    }
    assert!(files >= 600, "read only {files} source files");
    Ok(found)
}

#[test]
fn no_refused_lint_is_suppressed() -> Result<(), TestError> {
    let found = suppressions()?;
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
    Ok(())
}

/// Every refused lint that an attribute in `src` silences, with the 1-based
/// line the attribute starts on.
///
/// An attribute starts where a line begins with `#[` or `#![` and runs to the
/// `]` that balances it, across lines: a multi-line `#[expect(` names its lint
/// on a later line. `allow(` and `expect(` both silence a lint, so both count,
/// inside `cfg_attr` too. Code that calls a method named `expect`, and a lint
/// named in a comment or a string, is not an attribute.
fn refused_in(src: &str) -> Vec<(usize, &'static str)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let start = lines[i].trim_start();
        if !(start.starts_with("#[") || start.starts_with("#![")) {
            i += 1;
            continue;
        }
        // Collect the attribute through its balancing bracket.
        let mut attr = String::new();
        let mut depth = 0i32;
        let mut j = i;
        while j < lines.len() {
            let code = without_comment(lines[j]);
            depth += code.matches('[').count() as i32 - code.matches(']').count() as i32;
            attr.push_str(code);
            attr.push(' ');
            j += 1;
            if depth <= 0 {
                break;
            }
        }
        if silences(&attr) {
            for (lint, _) in REFUSED {
                if names_lint(&attr, lint) {
                    found.push((i + 1, *lint));
                }
            }
        }
        i = j;
    }
    found
}

/// `line` up to a `//` comment, leaving a `//` inside a string literal alone.
fn without_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    let bytes = line.as_bytes();
    for (at, &b) in bytes.iter().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b'/' && bytes.get(at + 1) == Some(&b'/') {
            return &line[..at];
        }
    }
    line
}

/// Whether an attribute's text applies `allow` or `expect`.
fn silences(attr: &str) -> bool {
    ["allow(", "expect("].iter().any(|word| {
        attr.match_indices(word).any(|(at, _)| {
            !attr[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.')
        })
    })
}

/// Whether `text` names `lint` as a whole name: `unused_mut` must not match
/// inside a longer one, and the `clippy::` prefix is part of the name.
fn names_lint(text: &str, lint: &str) -> bool {
    text.match_indices(lint).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + lint.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// A multi-line `#[expect(...)]` names its lint on a later line than the
/// attribute starts on; it is still a suppression.
#[test]
fn a_multi_line_expect_is_a_suppression() {
    let src = "fn a() {}\n#[expect(\n    clippy::too_many_arguments,\n    reason = \"x\"\n)]\nfn f() {}\n";
    assert_eq!(refused_in(src), vec![(2, "clippy::too_many_arguments")]);
}

/// `expect` inside `cfg_attr` and a crate-level `#![allow]` both count.
#[test]
fn cfg_attr_expect_and_crate_level_allow_are_suppressions() {
    let src =
        "#![allow(unused_mut)]\n#[cfg_attr(test, expect(clippy::type_complexity))]\nfn f() {}\n";
    assert_eq!(
        refused_in(src),
        vec![(1, "unused_mut"), (2, "clippy::type_complexity")]
    );
}

/// A method call named `expect` and a lint named in a string or a comment
/// are not suppressions.
#[test]
fn code_and_comments_that_name_a_lint_are_not_suppressions() {
    // Assembled so this file holds no call-shaped text for the unwrap
    // ratchet's line scan to count.
    let src = concat!(
        "// #[expect(clippy::too_many_arguments)]\nfn f() { x.expe",
        "ct(\"clippy::too_many_arguments\"); }\n#[deny(clippy::type_complexity)]\nfn g() {}\n"
    );
    assert!(refused_in(src).is_empty(), "{:?}", refused_in(src));
}

/// `//` inside a string is not a comment: an attribute holding a URL ends at
/// its own bracket and does not swallow the lines after it.
#[test]
fn a_url_in_an_attribute_does_not_extend_it() {
    let src = "#[schema(example = \"https://example.com/x\")]\npub kind: String,\n#[allow(dead_code)]\nlet mut unused_mut = 1;\n";
    assert!(refused_in(src).is_empty(), "{:?}", refused_in(src));
}
