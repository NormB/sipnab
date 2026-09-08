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
        // A generator that DELEGATES to `crate::mermaid::sequence_diagram`
        // satisfies this rule at one remove: that function escapes every
        // message label and every participant label itself, which
        // `the_shared_builder_escapes_every_label_it_writes` asserts
        // behaviorally. Delegation is the stronger arrangement — it is the
        // arrangement this gate wanted all along — so it is not an exemption
        // but the rule being met.
        if src.contains("sequence_diagram") {
            continue;
        }
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

/// No generator builds Mermaid source itself; every one delegates.
///
/// RTF3. `src/mermaid.rs` owns the cap, the positional ids and the truncation
/// note, and two generators reimplemented the source around it — so the cap
/// existed on the MCP surface, which returns fenced text nothing renders, and
/// not on the two whose output reaches the vendored renderer. That renderer
/// carries `maxEdges: 500` and refuses a larger diagram outright, so a long
/// SUBSCRIBE/NOTIFY dialog exported as a blank panel with no error.
///
/// A source gate for the same reason the escaper one is: `wasm.rs` compiles
/// only for wasm32, so the native suite cannot call it. Emitting the header
/// literal is the signature of a hand-rolled generator, and the shared entry
/// point is the only place it belongs.
#[test]
fn no_generator_emits_the_diagram_header_itself() {
    let mut offenders: Vec<String> = Vec::new();
    for rel in GENERATORS {
        let whole = read(rel);
        // Production only. A test that asserts the header appears in the
        // OUTPUT is the test doing its job, and a scanner that counts its own
        // fixtures is measuring itself.
        let src = whole.split("\nmod tests {").next().unwrap_or(&whole);
        for (n, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            // Doc comments and prose explain the rule; they do not break it.
            if trimmed.starts_with("//") {
                continue;
            }
            if line.contains("\"sequenceDiagram") {
                offenders.push(format!("{rel}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these generators build Mermaid source instead of calling \
         `crate::mermaid::sequence_diagram`, so the message cap and the \
         positional ids do not reach them:\n{}",
        offenders.join("\n")
    );
}

/// Every generator names the shared entry point.
///
/// The other half: a file that emitted no header AND called nothing would pass
/// the gate above while producing no diagram at all, and a file that stopped
/// exporting entirely would look identical to one that was fixed.
#[test]
fn every_generator_calls_the_shared_diagram_builder() {
    for rel in GENERATORS {
        let src = read(rel);
        assert!(
            src.contains("sequence_diagram"),
            "{rel} generates Mermaid but never calls the shared builder, so \
             nothing gives it a cap"
        );
    }
}

/// The shipped cap stays under the renderer's own ceiling.
///
/// Asserted here as well as at compile time because this file is where a
/// reader looks for the renderer's limits, and because the number that matters
/// is the one in the vendored bundle rather than a remembered one.
#[test]
fn the_message_cap_is_below_the_vendored_renderers_ceiling() {
    let bundle = read("website/static/js/mermaid.min.js");
    let declared = bundle
        .find("maxEdges:")
        .map(|i| {
            bundle[i + "maxEdges:".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|d| d.parse::<usize>().ok())
        .expect("the vendored bundle declares maxEdges");

    assert_eq!(
        declared,
        sipnab::mermaid::RENDERER_MAX_EDGES,
        "the vendored renderer's maxEdges moved; the constant that claims to \
         mirror it did not"
    );
    assert!(
        sipnab::mermaid::MAX_MESSAGES < declared,
        "the shipped cap ({}) must stay under the renderer's ceiling ({declared})",
        sipnab::mermaid::MAX_MESSAGES
    );
}
