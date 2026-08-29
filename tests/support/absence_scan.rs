// SPDX-License-Identifier: MIT OR Apache-2.0

//! The scanners behind `claims_of_absence_test`, as pure functions over text.
//!
//! Extracted for one reason. That scanner's first run produced four failures
//! and every one of them was a bug in the scanner: a crate import read as a
//! cross-reference, a placeholder in its own doc comment read as a real name,
//! string mentions counted as definitions, and five legitimate cross-surface
//! name pairs read as duplicates.
//!
//! Each was fixed by NARROWING the scanner until it went green. That move is
//! the hazard. Narrowing until green is indistinguishable, from the outside,
//! from narrowing until blind — the run looks the same either way, and the
//! exclusion that silenced a false positive is exactly the shape of the
//! exclusion that swallows a true one.
//!
//! So every narrowing below takes its inputs as arguments, including the
//! filesystem question, and `scanner_calibration_test` drives each one from
//! both sides: the case it was written to exclude, and a case it must still
//! catch.

// Shared test support: each test binary compiles this module independently and
// uses a different slice of it.
#![allow(dead_code)]

/// Phrases that assert nothing checks something.
pub const ABSENCE_PHRASES: &[&str] = &[
    "nothing gates",
    "nothing catches",
    "nothing enforces",
    "nothing asserts",
    "no gate covers",
    "nothing checks",
];

/// Below this, two files pinning the same ratchet value is coincidence.
///
/// Two fixture suites can each hold one dialog and both pin
/// `EXPECTED_DIALOG_COUNT = 1` without either being a copy of the other. Two
/// files independently arriving at `= 756` cannot.
pub const COINCIDENCE_CEILING: u64 = 20;

/// Whether a `left::right` token is a cross-reference into this test tree.
///
/// `file_exists` answers "is there a `tests/<left>.rs`", injected rather than
/// read so a caller can ask about trees that do not exist on disk.
///
/// # The narrowing
///
/// Without the existence question this matched `serial_test::serial` — a crate
/// import, naming nothing in this repository — and `some_test::some_fn`, which
/// was placeholder prose in the scanner's own documentation. Both were reported
/// as dangling references to tests that had been renamed away. Neither was a
/// reference at all.
///
/// The exclusion is deliberately about the FILE and not about the token's
/// spelling: `some_test::some_fn` is not excluded for looking like a
/// placeholder, it is excluded because `tests/some_test.rs` does not exist. Ask
/// the same question of a tree where it does, and it is a reference again.
#[must_use]
pub fn cross_reference(
    token: &str,
    file_exists: &dyn Fn(&str) -> bool,
) -> Option<(String, String)> {
    let (left, right) = token.split_once("::")?;
    if !left.ends_with("_test") || right.is_empty() || right.contains("::") {
        return None;
    }
    if !file_exists(left) {
        return None;
    }
    if !right
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    Some((left.to_string(), right.to_string()))
}

/// Every `left::right` token in a source text, before any narrowing.
///
/// Split out so a test can show what the raw scan produces and what the
/// narrowing then removes. A narrowing whose input was already empty removes
/// nothing and proves nothing.
#[must_use]
pub fn candidate_tokens(src: &str) -> Vec<String> {
    src.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
        .filter(|t| t.contains("::"))
        .map(str::to_string)
        .collect()
}

/// Every `#[test] fn name` DEFINED in one file.
///
/// # The narrowing
///
/// The duplicate check originally counted string occurrences of a test's name.
/// `claims_of_absence_test` names the advertisement gate four times in prose,
/// so the tree reported that gate as defined four times and the "exactly once"
/// rule failed. A name in a sentence is not a definition, and the difference is
/// the whole point of the rule: prose about a gate is what you write when there
/// is one, not evidence of a second.
#[must_use]
pub fn test_fns(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut armed = false;
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with("#[test]") {
            armed = true;
            continue;
        }
        if armed
            && let Some(rest) = t.strip_prefix("fn ")
            && let Some(name) = rest.split('(').next()
        {
            out.push(name.trim().to_string());
            armed = false;
        } else if armed && !t.starts_with('#') && !t.is_empty() {
            // An attribute run can carry `#[cfg(...)]` between the marker and
            // the fn; anything else means the marker was not for a function.
            armed = t.starts_with("fn ") || t.starts_with('#');
        }
    }
    out
}

/// How many times `name` is DEFINED as a test in this text.
#[must_use]
pub fn defines(src: &str, name: &str) -> usize {
    test_fns(src).iter().filter(|f| *f == name).count()
}

/// Every `(name, whitespace-collapsed body)` pair for the tests in a file.
///
/// # The narrowing
///
/// Keying duplicates on the NAME alone reported five pairs, and all five were
/// legitimate: `expired_signed_token_is_rejected` exists in both
/// `api_token_test` and `mcp_token_test` because the REST and MCP surfaces each
/// have to refuse an expired token. Renaming either to satisfy the rule would
/// have destroyed the symmetry that makes the pair readable.
///
/// The body is what separates "two surfaces asserting the same property" from
/// "one property asserted twice".
#[must_use]
pub fn test_bodies(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = src.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() != "#[test]" {
            continue;
        }
        let Some(decl) = lines[i + 1..]
            .iter()
            .position(|l| l.trim_start().starts_with("fn "))
        else {
            continue;
        };
        let start = i + 1 + decl;
        let Some(name) = lines[start]
            .trim()
            .strip_prefix("fn ")
            .and_then(|r| r.split('(').next())
        else {
            continue;
        };
        let mut body = String::new();
        for l in &lines[start + 1..] {
            if l.trim() == "#[test]" {
                break;
            }
            body.push_str(l.trim());
            body.push(' ');
        }
        out.push((
            name.trim().to_string(),
            body.split_whitespace().collect::<Vec<_>>().join(" "),
        ));
    }
    out
}

/// Every `const EXPECTED_NAME: T = value;` pin in a file, as `(name, value)`.
#[must_use]
pub fn ratchet_pins(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("const EXPECTED_") else {
            continue;
        };
        let Some(name) = rest.split(':').next() else {
            continue;
        };
        let value = t
            .rsplit('=')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches(';');
        out.push((format!("EXPECTED_{}", name.trim()), value.to_string()));
    }
    out
}

/// Whether a ratchet value shared by two files is implausible as coincidence.
///
/// # The narrowing
///
/// The first version flagged every shared value. `EXPECTED_DIALOG_COUNT = 1`
/// is pinned by two fixture suites that each happen to hold one dialog; that is
/// two ratchets sharing a word, not one ratchet written twice. A non-numeric
/// value is never coincidence — nothing arrives at the same expression twice by
/// accident.
#[must_use]
pub fn implausible_coincidence(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|v| v > COINCIDENCE_CEILING) || value.parse::<u64>().is_err()
}

/// Rust raw strings removed from a source, and their contents returned.
///
/// Returns `(source with raw strings blanked, contents of each)`. Newlines are
/// preserved in the blanked copy so line-oriented scanners keep their numbering.
///
/// # Why this exists
///
/// Every scanner above is line-oriented, which is deliberate — the tree is
/// read the way a person greps it. The cost is that quoting is invisible: a
/// `#[test] fn phantom()` written inside a raw string is counted as a
/// definition, and a `const EXPECTED_X = 756;` inside one is counted as a
/// ratchet pin.
///
/// The marker/definition equality does NOT catch that, and I claimed it did. A
/// phantom inside a raw string sits on its own physical line, so it brings a
/// marker along with it and the two counts move together. Separating them
/// needs an actual understanding of where the strings are, which is this.
///
/// The `r` must not follow an identifier character or a backslash, or `"a\r"`
/// and `for"` would each open a raw string that never closes.
#[must_use]
pub fn split_raw_strings(src: &str) -> (String, Vec<String>) {
    let b = src.as_bytes();
    let mut kept = String::with_capacity(src.len());
    let mut inner = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let boundary = i == 0 || {
            let p = b[i - 1];
            !(p.is_ascii_alphanumeric() || p == b'_' || p == b'\\')
        };
        if b[i] == b'r' && boundary {
            let mut j = i + 1;
            while j < b.len() && b[j] == b'#' {
                j += 1;
            }
            let hashes = j - i - 1;
            if j < b.len() && b[j] == b'"' {
                let mut close = String::from('"');
                for _ in 0..hashes {
                    close.push('#');
                }
                if let Some(rel) = src[j + 1..].find(&close) {
                    let end = j + 1 + rel;
                    inner.push(src[j + 1..end].to_string());
                    for c in src[i..end + close.len()].chars() {
                        kept.push(if c == '\n' { '\n' } else { ' ' });
                    }
                    i = end + close.len();
                    continue;
                }
            }
        }
        let ch = src[i..].chars().next().unwrap_or(' ');
        kept.push(ch);
        i += ch.len_utf8();
    }
    (kept, inner)
}
