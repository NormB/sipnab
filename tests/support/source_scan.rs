// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! One implementation of "the production part of a source file".
//!
//! Several gates scan `src/` text and must skip the file's own unit tests: a
//! test may name the very thing the gate bans (`VerificationStatus::Valid`), or
//! press keys no user has (`'z'`, `'Q'`), or assert `loss_pct > 30.0` about the
//! bands it is checking. Each gate grew its own way of cutting the file, and
//! each way was wrong in a different direction:
//!
//! * `src.split("#[cfg(test)]").next()` cuts at the first TEXT match, so a
//!   *comment* that spells the attribute ends the scan. That is how
//!   `surface_parity_test` read 17 lines of `src/tui/dashboard.rs` and passed
//!   on the rest of a view it had never opened.
//! * Cutting at the first `#[cfg(test)]` ATTRIBUTE fixes the comment but not
//!   the shape: the attribute also guards test-only `use` imports, a
//!   `thread_local!` call counter, and single statements inside an otherwise
//!   production function. `src/tui/controllers/mod.rs` puts one on line 23 —
//!   a `use` — so an attribute-based cut still reads 22 of its 1662 lines,
//!   discarding every `KeyCode::Char('…')` the dispatcher handles.
//!
//! What the gates actually mean is "stop at the test MODULE", so that is what
//! this cuts at: the first `#[cfg(test)]` whose item is a `mod` declaration.
//! Comments are stripped before the attribute is recognized, and a
//! `#[cfg(test)]` on anything else is stepped over rather than obeyed.
//!
//! A gate silenced this way cannot be told apart from a gate that found
//! nothing, which is why the rule lives in one place with its own self-tests
//! (`tests/support_selftest.rs`) instead of once per gate by hand. Five gates
//! call it: `cli_help_test`, `keybinding_drift_test`, `surface_parity_test`,
//! `metrics_docs_drift_test`, and `flag_coverage_test`.
//!
//! The last of those wants the OTHER side of the cut — the test module — and
//! takes it as `&src[production_source(src).len()..]`, which is why the result
//! is documented as a prefix. Its blindness ran the opposite way: a text match
//! moving the split UP swept `src/cli.rs`'s clap definitions into what is
//! supposed to be a corpus of tests, and a flag's own `///` help text then
//! counted as that flag's test coverage. Reading too much and reading too
//! little are the same defect, and one cut rule answers both.
#![allow(dead_code)]

/// The text of `src` up to (not including) its first `#[cfg(test)]` module.
///
/// The result is a PREFIX of `src`, so line numbers within it are the file's
/// own line numbers and `production_source(src).lines().count()` is the index
/// of the cut — callers that scan by line can slice their own `Vec<&str>` with
/// it without re-deriving the rule.
///
/// # Arguments
/// * `src` — the whole contents of a Rust source file.
///
/// # Returns
/// Everything before the test module, or all of `src` when it has none.
pub fn production_source(src: &str) -> &str {
    const ATTR: &str = "#[cfg(test)]";

    let mut offset = 0usize;
    // Byte offset of a `#[cfg(test)]` line whose item is on a later line.
    let mut pending: Option<usize> = None;

    for line in src.split_inclusive('\n') {
        let start = offset;
        offset += line.len();

        let code = strip_comment(line);
        let trimmed = code.trim_start();
        if trimmed.is_empty() {
            // Blank, or a line that was only a comment. Doc comments sit
            // BETWEEN the attribute and its item, so this must not clear
            // `pending`.
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix(ATTR) {
            let rest = rest.trim_start();
            if rest.is_empty() {
                pending = Some(start);
            } else if is_mod_decl(rest) {
                // `#[cfg(test)] mod tests;` — attribute and item on one line.
                return &src[..start];
            } else {
                pending = None;
            }
            continue;
        }

        // Other attributes (`#[allow(…)]`, inner `#![…]`) may sit between the
        // `#[cfg(test)]` and the item it guards.
        if trimmed.starts_with("#[") || trimmed.starts_with("#!") {
            continue;
        }

        if let Some(attr_start) = pending.take()
            && is_mod_decl(trimmed)
        {
            return &src[..attr_start];
        }
    }

    src
}

/// A line with its `//` comment tail removed.
///
/// Only ever shortens a line, so it cannot invent an attribute — it can only
/// stop one that was written in prose from being read as code.
fn strip_comment(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}

/// Whether `code` (already trimmed, comment-free) declares a module.
///
/// Accepts the visibility forms the crate actually uses — `mod`, `pub mod`,
/// `pub(crate) mod`, `pub(in crate::tui) mod` — and rejects every other item a
/// `#[cfg(test)]` may guard, which is the whole point of the check.
fn is_mod_decl(code: &str) -> bool {
    let mut rest = code.trim_start();
    if let Some(after_pub) = rest.strip_prefix("pub") {
        let after_pub = after_pub.trim_start();
        rest = match after_pub.strip_prefix('(') {
            // `pub(in crate::tui)` — skip to after the closing paren.
            Some(inner) => inner.split_once(')').map_or(inner, |(_, tail)| tail),
            None => after_pub,
        };
    }
    rest.trim_start()
        .strip_prefix("mod")
        .is_some_and(|tail| tail.starts_with(char::is_whitespace))
}

/// The byte ranges of `src` that are code: comments, string literals and
/// character literals are blanked to spaces, newlines kept, so offsets and
/// line numbers are the file's own.
///
/// Moved here from `tests/startup_refusal_stderr_test.rs` so that gate and
/// `tests/prereq_skip_gate_test.rs` read code by one rule.
#[must_use]
pub fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let blank = |c: u8| if c == b'\n' { b'\n' } else { b' ' };
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend(b"  ");
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == b'r'
            && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            // A raw string: r"..." or r#"..."#.
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            out.extend(std::iter::repeat_n(b' ', j + 1 - i));
            i = j + 1;
            while i < b.len() {
                let closes = b[i] == b'"'
                    && b.len() > i + hashes
                    && b[i + 1..=i + hashes].iter().all(|&h| h == b'#');
                if closes {
                    out.extend(std::iter::repeat_n(b' ', hashes + 1));
                    i += hashes + 1;
                    break;
                }
                out.push(blank(b[i]));
                i += 1;
            }
        } else if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    out.push(b' ');
                    if let Some(&n) = b.get(i + 1) {
                        out.push(blank(n));
                    }
                    i += 2;
                } else if b[i] == b'"' {
                    out.push(b' ');
                    i += 1;
                    break;
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == b'\'' {
            // A character literal ('x', '\n', '\''), or a lifetime ('a).
            let len = if b.get(i + 1) == Some(&b'\\') {
                b[i + 2..].iter().position(|&x| x == b'\'').map(|p| p + 3)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(3)
            } else {
                None
            };
            match len {
                Some(n) => {
                    out.extend(std::iter::repeat_n(b' ', n));
                    i += n;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
