// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the code exposes, and whether any document names it.
//!
//! # Why these are ratchets rather than pass/fail
//!
//! Four surfaces here are documented in part and not in whole: numeric policy
//! ceilings, REST schema strictness, MCP output schemas, and configuration
//! keys outside `[limits]`. Demanding all of them at once would either block
//! every commit or get the gate deleted, and a gate that gets deleted protects
//! nothing.
//!
//! So each one pins the CURRENT gap and refuses to let it grow. The number may
//! only move down. That is the same shape `flag_coverage_test` uses, and the
//! reason it works is that the expensive part is never the first item — it is
//! the hundredth one landing unnoticed because nobody was counting.
//!
//! Two of the five are not ratchets at all, because the gap turned out to be
//! one item each and closing it outright was cheaper than pinning it:
//! environment variables an operator can set, and clap aliases.
//!
//! # The rule for moving a number
//!
//! Down, in the same commit that documents the thing. Never up. A count moving
//! the wrong way is the alarm, and the correct response is to attribute the
//! change per item rather than to update the constant.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under `src/`, concatenated.
fn source() -> String {
    let mut out = String::new();
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    out
}

/// Every `.md` file under `docs/`, plus the root policy documents.
fn documentation() -> String {
    let mut out = String::new();
    let mut stack = vec![repo().join("docs")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "md") {
                out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                out.push('\n');
            }
        }
    }
    for f in ["README.md", "SECURITY.md", "CHANGELOG.md"] {
        out.push_str(&std::fs::read_to_string(repo().join(f)).unwrap_or_default());
    }
    out
}

/// Environment variables read only by tests, and why each is exempt.
///
/// An explicit table rather than a `#[cfg(test)]` stripper. The first version
/// of this file hand-rolled one by counting braces, and it swallowed most of
/// the tree -- 2 environment reads found instead of 10, which read as "the
/// pattern broke" and would have read as "everything is documented" had the
/// guard below not been there. `scripts/check-unwrap.py` records the same
/// lesson in its own comments: brace COUNTING is not brace matching, and it
/// lexes properly rather than approximating. A four-entry table needs neither.
const TEST_ONLY_ENV: &[(&str, &str)] = &[(
    "SIPNAB_FANOUT_DEV",
    "picks the interface for one #[ignore]d test that needs CAP_NET_RAW. \
     Documenting it in the CLI reference would tell an operator about a knob \
     that does nothing outside `cargo test`.",
)];

/// The scanners see a real tree.
#[test]
fn the_coverage_scanners_read_a_real_tree() {
    let src = source();
    let docs = documentation();
    assert!(
        src.len() > 500_000,
        "read only {} bytes of source; every count below would be low for the \
         wrong reason",
        src.len()
    );
    assert!(
        docs.len() > 200_000,
        "read only {} bytes of documentation; every item would look \
         undocumented",
        docs.len()
    );
    assert!(
        !TEST_ONLY_ENV.is_empty(),
        "the test-only exemption table is empty; if that is now true the env \
         gate below needs no exemptions and the table should go, not sit here \
         unused"
    );
}

// ── DOC10: environment variables ────────────────────────────────────

/// Every environment variable an operator can set is documented.
///
/// Not a ratchet: the gap was one variable, and it was a test-only one. This
/// is the shape the others are aiming at.
#[test]
fn every_operator_environment_variable_is_documented() {
    let re = regex::Regex::new(r#"env::var(?:_os)?\(\s*"([A-Z][A-Z0-9_]+)""#).expect("pattern");
    let src = source();
    let docs = documentation();
    let read: BTreeSet<String> = re.captures_iter(&src).map(|c| c[1].to_string()).collect();
    assert!(
        read.len() >= 8,
        "found only {} environment read(s); the pattern has stopped matching \
         and this gate would report a clean tree",
        read.len()
    );
    let exempt: BTreeSet<&str> = TEST_ONLY_ENV.iter().map(|(v, _)| *v).collect();
    // An exemption that no longer applies is a hole nobody is watching.
    for (v, _) in TEST_ONLY_ENV {
        assert!(
            read.contains(*v),
            "{v} is exempted as test-only and is no longer read anywhere; \
             remove the entry rather than leaving a stale exemption"
        );
    }
    let undocumented: Vec<&String> = read
        .iter()
        .filter(|v| !exempt.contains(v.as_str()))
        .filter(|v| !docs.contains(v.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these environment variables are read at runtime and named in no \
         document: {undocumented:?}\n\nAn operator cannot set what nobody told \
         them about, and a credential-bearing one they do not know about is \
         worse than that."
    );
}

// ── DOC13: clap aliases ─────────────────────────────────────────────

/// Every accepted flag alias is documented.
///
/// Also not a ratchet, and also one item: `--uprobe-flavour` was accepted and
/// named nowhere. An alias exists because a released flag is a contract, which
/// is exactly the argument for writing it down -- a reader with an old script
/// needs to find out that the spelling still works.
#[test]
fn every_flag_alias_is_documented() {
    let re = regex::Regex::new(r#"(?:visible_)?alias(?:es)?\s*=\s*"([a-z0-9][a-z0-9-]+)""#)
        .expect("pattern");
    let src = source();
    let docs = documentation();
    let aliases: BTreeSet<String> = re.captures_iter(&src).map(|c| c[1].to_string()).collect();
    assert!(
        !aliases.is_empty(),
        "no clap aliases found at all; the pattern has stopped matching and \
         this gate is checking nothing"
    );
    // Only the ones that are actually flag spellings. A value alias like
    // `full` or `flavours` is an enum variant, documented with its values.
    let undocumented: Vec<&String> = aliases
        .iter()
        .filter(|a| a.contains('-'))
        .filter(|a| !docs.contains(&format!("--{a}")))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these flag aliases are accepted and documented nowhere: \
         {undocumented:?}\n\nA script written against the old spelling keeps \
         working, and its author has no way to learn that from the docs."
    );
}

// ── DOC11: numeric policy ceilings ──────────────────────────────────

/// Numeric policy ceilings named in no document.
///
/// Measured 2026-08-30. Every one of these is a bound a caller can hit, and
/// each shipped with a test proving the bound and nothing telling an operator
/// it exists. `MAX_EXPRESSION_NODES` was in this set until DOC7 moved it into
/// the filter reference, which is the worked example of how the number comes
/// down.
const UNDOCUMENTED_CEILINGS: usize = 106;

#[test]
fn undocumented_numeric_ceilings_do_not_increase() {
    let re = regex::Regex::new(
        r"(?m)^\s*(?:pub\s+)?const ((?:MAX|MIN|DEFAULT)_[A-Z0-9_]+)\s*:\s*(?:usize|u\d+)\s*=",
    )
    .expect("pattern");
    let src = source();
    let docs = documentation();
    let all: BTreeSet<String> = re.captures_iter(&src).map(|c| c[1].to_string()).collect();
    assert!(
        all.len() >= 50,
        "found only {} ceiling constant(s); the pattern has stopped matching",
        all.len()
    );
    let undocumented: Vec<&String> = all.iter().filter(|c| !docs.contains(c.as_str())).collect();
    assert!(
        undocumented.len() <= UNDOCUMENTED_CEILINGS,
        "undocumented numeric ceilings rose from {UNDOCUMENTED_CEILINGS} to \
         {}. A new bound shipped with no document naming it; a caller meets it \
         as an unexplained refusal.\n\nThe ones not documented: {undocumented:?}",
        undocumented.len()
    );
    assert!(
        undocumented.len() >= UNDOCUMENTED_CEILINGS.saturating_sub(15),
        "undocumented ceilings fell from {UNDOCUMENTED_CEILINGS} to {} -- good, \
         but lower the constant in the same commit so the gain is held.",
        undocumented.len()
    );
}

// ── DOC14: REST schema strictness ───────────────────────────────────

/// OpenAPI components that accept unknown fields.
///
/// The contract test passes bodies carrying `input_origin`, `evidence_omitted`
/// and `snapped_frames` because the schema never said they were not allowed.
/// The check is one-directional: a response missing a documented field fails, a
/// response carrying an undocumented one does not.
const PERMISSIVE_SCHEMA_COMPONENTS: usize = 19;

#[test]
fn permissive_rest_schema_components_do_not_increase() {
    let re = regex::Regex::new(r"#\[derive\([^)]*ToSchema[^)]*\)\]").expect("pattern");
    let src = source();
    let total = re.find_iter(&src).count();
    assert!(
        total >= 10,
        "found only {total} OpenAPI component(s); the derive pattern has \
         stopped matching"
    );
    let strict = src.matches("deny_unknown_fields").count();
    let permissive = total.saturating_sub(strict);
    assert!(
        permissive <= PERMISSIVE_SCHEMA_COMPONENTS,
        "REST components accepting unknown fields rose from \
         {PERMISSIVE_SCHEMA_COMPONENTS} to {permissive}. Each one is a body \
         the contract test will pass while carrying a field the schema never \
         described."
    );
}

// ── DOC15: MCP output schemas ───────────────────────────────────────

/// MCP tools that declare no `outputSchema`.
///
/// A client cannot validate what it gets back, so an undocumented response key
/// is indistinguishable from a typo. 17 live response keys are documented
/// nowhere for the same reason.
const TOOLS_WITHOUT_OUTPUT_SCHEMA: usize = 45;

#[test]
fn mcp_tools_without_an_output_schema_do_not_increase() {
    let re = regex::Regex::new(r#"(?m)^\s+name = "([a-z0-9_]+)","#).expect("pattern");
    let mut src = String::new();
    let mut stack = vec![repo().join("src/mcp")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                src.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                src.push('\n');
            }
        }
    }
    let tools: BTreeSet<String> = re.captures_iter(&src).map(|c| c[1].to_string()).collect();
    assert!(
        tools.len() >= 40,
        "found only {} MCP tool(s); the walk or the pattern is wrong",
        tools.len()
    );
    let declared = src.matches("output_schema").count();
    let without = tools.len().saturating_sub(declared);
    assert!(
        without <= TOOLS_WITHOUT_OUTPUT_SCHEMA,
        "MCP tools with no declared output schema rose from \
         {TOOLS_WITHOUT_OUTPUT_SCHEMA} to {without}. A client written against \
         one of these cannot tell a renamed key from a missing one."
    );
}
