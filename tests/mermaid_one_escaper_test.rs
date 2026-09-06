// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every Mermaid label goes through one escaper.
//!
//! # The defect
//!
//! sipnab had two independent Mermaid generators. `src/tui/call_flow/export.rs`
//! escapes its labels; `src/wasm.rs` did not, and interpolated `msg.reason` —
//! the reason phrase written by whoever sent the packet — straight into the
//! diagram source. The website's analyze page downloads that as a `.mmd`, so a
//! crafted reason phrase becomes diagram syntax in whatever the reader pastes
//! it into.
//!
//! It is the same rule written twice, and only one copy was ever fixed. The
//! structural cause is that the two could not share code: `src/output/` is
//! gated on `feature = "native"` and `src/wasm.rs` compiles only for
//! `target_arch = "wasm32"`, where `native` is off. So the shared escaper has
//! to live in an ungated module, and this gate is what keeps a third copy from
//! appearing the next time someone needs one.
//!
//! # Why a source gate rather than a behavioral test
//!
//! `wasm::Analyzer::export_mermaid` builds on `wasm_bindgen` types and only
//! compiles for wasm32, so the native test suite cannot call it. The
//! behavioral assertions live on the shared escaper, which both call. This
//! test proves they actually call it.
#![cfg(feature = "native")]

use std::path::Path;

/// Files that generate Mermaid source from capture-derived text.
const GENERATORS: &[&str] = &["src/wasm.rs", "src/tui/call_flow/export.rs"];

/// Read a source file relative to the crate root.
fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel} is readable: {e}"))
}

/// No generator interpolates a capture-derived field into Mermaid source
/// without escaping it.
///
/// `reason` is the sharpest case — it is a free-text field the sender writes,
/// with no grammar constraining it — so it stands for the class.
#[test]
fn no_mermaid_generator_interpolates_an_unescaped_reason_phrase() {
    let mut offenders: Vec<String> = Vec::new();
    for rel in GENERATORS {
        let src = read(rel);
        // Scoped to the Mermaid-generating function, and scanned by STATEMENT
        // rather than by line. Two earlier versions of this scan were wrong in
        // opposite directions: reading whole files flagged `"reason": m.reason`
        // in the JSON projection, which serde escapes correctly; reading single
        // lines then missed a correctly-escaped call whose `.reason` argument
        // had been wrapped onto its own line by the formatter. A statement is
        // the unit the question is actually about -- "does this expression pass
        // through the escaper" -- so it is the unit to scan.
        let Some(body_start) = src.find("fn export_mermaid") else {
            continue;
        };
        let body = &src[body_start..];
        let mut depth: i64 = 0;
        let mut end = body.len();
        for (i, ch) in body.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        // Every `escape_mermaid_label(` call's ARGUMENT SPAN, by paren
        // matching. Statement-level scanning was not enough and a mutation
        // proved it: reverting the raw interpolation left this gate GREEN,
        // because `let label = if .. { escaped } else { raw };` is ONE
        // statement and the escaped arm satisfied the check for both arms. A
        // span is the smallest unit that answers "is this expression escaped".
        let region = &body[..end];
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let needle = "escape_mermaid_label(";
        let mut from = 0;
        while let Some(rel_at) = region[from..].find(needle) {
            let open = from + rel_at + needle.len() - 1;
            let mut depth = 0i64;
            let mut close = region.len();
            for (i, ch) in region[open..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            spans.push((open, close));
            from = open + 1;
        }

        for (at, _) in region.match_indices(".reason") {
            let line_start = region[..at].rfind('\n').map_or(0, |i| i + 1);
            if region[line_start..at].trim_start().starts_with("//") {
                continue;
            }
            if !spans.iter().any(|(o, c)| at > *o && at < *c) {
                let line_end = region[at..].find('\n').map_or(region.len(), |i| at + i);
                offenders.push(format!("{rel}: {}", region[line_start..line_end].trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a Mermaid generator uses a sender-written reason phrase without \
         routing it through the shared escaper:\n  {}",
        offenders.join("\n  ")
    );
}

/// Exactly one escaper exists.
///
/// A second definition is how the first divergence happened. The shared one
/// lives in an ungated module so both `native` and `wasm32` builds can reach
/// it; a `fn escape_mermaid_label` defined anywhere else is a fork.
#[test]
fn the_mermaid_escaper_has_exactly_one_definition() {
    let mut definitions: Vec<String> = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ is readable") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable");
            for line in text.lines() {
                let t = line.trim_start();
                // Exact, not a prefix. The first version of this check used
                // `starts_with("fn escape_label")`, which matched
                // `escape_label_value` in the Prometheus exporter -- an
                // unrelated function -- so the assertion passed while the
                // Mermaid escaper it was written for did not yet exist.
                if t.starts_with("fn escape_mermaid_label(")
                    || t.starts_with("pub fn escape_mermaid_label(")
                    || t.starts_with("pub(crate) fn escape_mermaid_label(")
                {
                    definitions.push(path.display().to_string());
                }
            }
        }
    }
    assert_eq!(
        definitions.len(),
        1,
        "the Mermaid escaper must have exactly one definition, found: {definitions:?}"
    );
}
