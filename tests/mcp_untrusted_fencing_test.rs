// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every capture-derived field crossing the MCP boundary is classified (#139).
//!
//! sipnab's input is SIP written by whoever sent the packet, and the MCP caller
//! is a language model. A field that reaches it unmarked is indistinguishable
//! from something sipnab computed, so each one has to be a decision: fence it
//! (the sender wrote it) or return it verbatim (an identifier the agent passes
//! back to another tool).
//!
//! This gate lives in `tests/` rather than beside the code, alongside the
//! project's other source-scanning gates (`dev_docs_drift_test`,
//! `shard_peek_parity_test`). It also has to: the scan needs a `"\n}"` needle to
//! find the end of a struct, and `scripts/check-unwrap.py` counts braces
//! literally, so that one character inside a string collapses its depth and ends
//! the enclosing `#[cfg(test)]` exemption early. Keeping the scan out of `src/`
//! sidesteps a brace-counting bug rather than encoding a workaround into it.

#![cfg(feature = "mcp")]

use sipnab::mcp::shape::{MESSAGE_FENCED_FIELDS, MESSAGE_VERBATIM_FIELDS};

/// The body of a named struct in a source file, without its closing brace.
fn struct_body(src: &str, name: &str) -> String {
    let decl = format!("struct {name}");
    let start = src
        .find(&decl)
        .unwrap_or_else(|| panic!("{decl} is not defined in the scanned file"));
    let body = &src[start..];
    // The needle is built rather than written as a literal, for the reason in
    // the module docs: a bare `}` in a string breaks the unwrap checker's
    // brace tracking, and this file should not depend on where it happens to
    // live to stay correct.
    let close = format!("\n{}", '}');
    let end = body
        .find(&close)
        .unwrap_or_else(|| panic!("{decl} has no closing brace"));
    body[..end].to_string()
}

/// Every field of the per-message JSON is classified exactly once.
///
/// Fail-closed on purpose. A field added to `MessageJson` later belongs to
/// neither list, so this fails until somebody decides whether it carries text
/// the sender wrote. The alternative — defaulting to verbatim — is precisely how
/// the original defect happened: nobody decided, so nothing was marked.
#[test]
fn every_message_json_field_is_classified_as_fenced_or_verbatim() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/output/json.rs"))
        .expect("read src/output/json.rs");

    let body = struct_body(&src, "MessageJson");

    let field_re = regex::Regex::new(r"(?m)^\s{4}([a-z_]+):").expect("field regex");
    let fields: Vec<String> = field_re
        .captures_iter(&body)
        .map(|c| c[1].to_string())
        .collect();

    // A scan that matches nothing reports every field classified, which is
    // indistinguishable from a clean result. Pin the floor so a broken
    // extractor fails loudly instead of passing vacuously.
    assert!(
        fields.len() >= 15,
        "only found {} field(s) on MessageJson — the extractor stopped matching, \
         so this gate is not checking what it claims: {fields:?}",
        fields.len()
    );

    let mut unclassified = Vec::new();
    let mut both = Vec::new();
    for f in &fields {
        let fenced = MESSAGE_FENCED_FIELDS.contains(&f.as_str());
        let verbatim = MESSAGE_VERBATIM_FIELDS.contains(&f.as_str());
        match (fenced, verbatim) {
            (false, false) => unclassified.push(f.clone()),
            (true, true) => both.push(f.clone()),
            _ => {}
        }
    }

    assert!(
        unclassified.is_empty(),
        "MessageJson field(s) {unclassified:?} appear in neither \
         MESSAGE_FENCED_FIELDS nor MESSAGE_VERBATIM_FIELDS. Decide whether each \
         carries text the packet's sender wrote (fence it) or is an identifier an \
         agent passes back to another tool (verbatim). Leaving one unclassified \
         ships it to a language model unmarked, which is the defect #139 fixed."
    );
    assert!(
        both.is_empty(),
        "field(s) {both:?} are classified as both fenced and verbatim"
    );
}
