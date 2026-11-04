// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! A prose list of correlation names in `src/` names all of them.
//!
//! # Why this exists
//!
//! 0.5.232 added a ninth correlation strategy, `th_callid_mapping`, a fifth
//! method, `mapping`, and two topology-hiding statuses, `mapped` and
//! `conflict`. The code that emits them was tested. The doc comments that
//! describe them were not: six of them still listed the old sets, and those
//! comments are the field descriptions in the published OpenAPI document and
//! the MCP tool schemas. A client reading the schema was told a closed set
//! that the server's answers left.
//!
//! Nothing compared the prose with the enums, because the lists are prose.
//! This test does. The vocabularies come from the library's own `ALL`
//! constants, and the test first checks that each constant names every
//! variant its enum declares, so a new variant cannot be left out of both.
//!
//! # The rule
//!
//! In a doc comment (`///` or `//!`) under `src/`, an enumeration is three or
//! more backquoted names joined by commas and a final "or" or "and", with any
//! parenthesized gloss removed first. An enumeration that names two or more
//! members of one vocabulary must name every member of it. Two names in
//! passing ("`session_id` and `x_call_id` both score 100") are not a list and
//! are not checked.

use std::collections::BTreeSet;
use std::path::Path;

use sipnab::sip::dialog_store::{CorrelationMethod, CorrelationReason, ThCallidStatus};

/// The error a fallible test returns: any error, boxed.
type TestError = Box<dyn std::error::Error>;

/// One vocabulary: its name for messages and its wire names.
struct Vocabulary {
    name: &'static str,
    words: BTreeSet<&'static str>,
}

/// The three vocabularies, from the library.
fn vocabularies() -> Vec<Vocabulary> {
    vec![
        Vocabulary {
            name: "correlation strategy (CorrelationReason::ALL)",
            words: CorrelationReason::ALL
                .iter()
                .map(|r| r.strategy().0)
                .collect(),
        },
        Vocabulary {
            name: "correlation method (CorrelationMethod::ALL)",
            words: CorrelationMethod::ALL.iter().map(|m| m.as_str()).collect(),
        },
        Vocabulary {
            name: "topology-hiding status (ThCallidStatus::ALL)",
            words: ThCallidStatus::ALL.iter().map(|s| s.as_str()).collect(),
        },
    ]
}

/// The unit variants `pub enum <name>` declares in `src`, in order.
///
/// A variant is a line of exactly four spaces, an identifier and a comma,
/// inside the enum's braces. Comments (`//` and `///`) and attributes
/// (`#[...]`) are skipped. The three enums here are unit-only, so a variant
/// with fields would be a change this test should stop on.
fn declared_variants(src: &str, name: &str) -> Result<Vec<String>, TestError> {
    let head = format!("pub enum {name} {{");
    let start = src
        .find(&head)
        .ok_or_else(|| format!("no `{head}` in src/sip/dialog_store.rs"))?;
    let body = &src[start + head.len()..];
    let end = body
        .find("\n}")
        .ok_or_else(|| format!("no closing brace for {name}"))?;
    let variant = regex::Regex::new(r"^    ([A-Z][A-Za-z0-9]*),$")?;
    let mut out = Vec::new();
    for line in body[..end].lines() {
        if let Some(c) = variant.captures(line) {
            out.push(c[1].to_string());
        } else if line.starts_with("    ")
            && !line.starts_with("    //")
            && !line.starts_with("    #[")
            && !line.starts_with("     ")
            && !line.trim().is_empty()
        {
            return Err(format!(
                "{name}: a line this test does not read as a unit variant: {line:?}"
            )
            .into());
        }
    }
    Ok(out)
}

/// A plain `//` comment and an attribute inside the enum are neither a
/// variant nor a reason to stop: `ThCallidStatus` carries both on
/// `NotConfigured` (a note on its name and `#[serde(rename = "no_secret")]`).
/// A variant with fields still stops the parser.
#[test]
fn declared_variants_skips_comments_and_attributes() -> Result<(), TestError> {
    let src = "pub enum Sample {\n    /// Doc.\n    First,\n    // A plain comment\n    \
               // that wraps.\n    #[serde(rename = \"second_wire\")]\n    Second,\n    \
               Third,\n}\n";
    assert_eq!(
        declared_variants(src, "Sample")?,
        ["First", "Second", "Third"],
        "the comment and the attribute are skipped and every variant is read"
    );
    let tuple = "pub enum Sample {\n    First,\n    Second(u8),\n}\n";
    assert!(
        declared_variants(tuple, "Sample").is_err(),
        "a variant with fields is a change the parser must stop on"
    );
    Ok(())
}

#[test]
fn each_all_constant_names_every_declared_variant() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/sip/dialog_store.rs"))?;
    let listed: [(&str, Vec<String>); 3] = [
        (
            "CorrelationReason",
            CorrelationReason::ALL
                .iter()
                .map(|v| format!("{v:?}"))
                .collect(),
        ),
        (
            "CorrelationMethod",
            CorrelationMethod::ALL
                .iter()
                .map(|v| format!("{v:?}"))
                .collect(),
        ),
        (
            "ThCallidStatus",
            ThCallidStatus::ALL
                .iter()
                .map(|v| format!("{v:?}"))
                .collect(),
        ),
    ];
    for (name, all) in listed {
        let declared = declared_variants(&src, name)?;
        assert!(
            declared.len() >= 5,
            "read only {} variants of {name}; the parser is broken",
            declared.len()
        );
        assert_eq!(
            all, declared,
            "{name}::ALL must list every variant the enum declares, in order"
        );
    }
    Ok(())
}

/// The three patterns the reader uses, compiled once: the tests read every
/// doc block under `src/` and `docs/`, and compiling per block made one run
/// take minutes.
struct Patterns {
    paren: regex::Regex,
    list: regex::Regex,
    name: regex::Regex,
}

fn patterns() -> Result<&'static Patterns, TestError> {
    static PATTERNS: std::sync::OnceLock<Patterns> = std::sync::OnceLock::new();
    if let Some(p) = PATTERNS.get() {
        return Ok(p);
    }
    let built = Patterns {
        paren: regex::Regex::new(r"\([^()]*\)")?,
        list: regex::Regex::new(r"`[^`]+`(?:\s*,\s*`[^`]+`)+\s*,?\s*(?:or|and)\s+`[^`]+`")?,
        name: regex::Regex::new(r"`([^`]+)`")?,
    };
    Ok(PATTERNS.get_or_init(|| built))
}

/// Remove every parenthesized group, innermost first.
fn strip_parentheticals(text: &str) -> Result<String, TestError> {
    let inner = &patterns()?.paren;
    let mut s = text.to_string();
    loop {
        let next = inner.replace_all(&s, "").into_owned();
        if next == s {
            return Ok(s);
        }
        s = next;
    }
}

/// The enumerations in one block of doc text: each is the list of its
/// backquoted names.
fn enumerations(text: &str) -> Result<Vec<Vec<String>>, TestError> {
    let p = patterns()?;
    let (list, name) = (&p.list, &p.name);
    if !text.contains('`') {
        return Ok(Vec::new());
    }
    let text = strip_parentheticals(text)?;
    Ok(list
        .find_iter(&text)
        .map(|m| {
            name.captures_iter(m.as_str())
                .map(|c| c[1].to_string())
                .collect()
        })
        .collect())
}

/// Every doc-comment block in `src`, as (first line number, joined text).
fn doc_blocks(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        let doc = t.strip_prefix("///").or_else(|| t.strip_prefix("//!"));
        match (doc, current.as_mut()) {
            (Some(d), Some((_, text))) => {
                text.push(' ');
                text.push_str(d.trim());
            }
            (Some(d), None) => current = Some((i + 1, d.trim().to_string())),
            (None, _) => {
                if let Some(block) = current.take() {
                    out.push(block);
                }
            }
        }
    }
    if let Some(block) = current {
        out.push(block);
    }
    out
}

/// What is wrong with one block, one line per incomplete list.
fn incomplete_lists(text: &str, vocabularies: &[Vocabulary]) -> Result<Vec<String>, TestError> {
    let mut out = Vec::new();
    for items in enumerations(text)? {
        let items: BTreeSet<&str> = items.iter().map(String::as_str).collect();
        for v in vocabularies {
            let named: Vec<&str> = v
                .words
                .iter()
                .copied()
                .filter(|w| items.contains(w))
                .collect();
            if named.len() < 2 {
                continue;
            }
            let missing: Vec<&str> = v
                .words
                .iter()
                .copied()
                .filter(|w| !items.contains(w))
                .collect();
            if !missing.is_empty() {
                out.push(format!(
                    "lists {} names of the {} vocabulary ({}) and omits {}",
                    named.len(),
                    v.name,
                    named.join(", "),
                    missing.join(", ")
                ));
            }
        }
    }
    Ok(out)
}

#[test]
fn every_prose_list_of_correlation_names_is_complete() -> Result<(), TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vocabularies = vocabularies();
    let mut failures = Vec::new();
    let mut lists_checked = 0usize;
    for entry in walkdir::WalkDir::new(root.join("src")) {
        let entry = entry?;
        if entry.path().extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(entry.path())?;
        let rel = entry.path().strip_prefix(root)?.display().to_string();
        for (line, text) in doc_blocks(&src) {
            for items in enumerations(&text)? {
                let items: BTreeSet<&str> = items.iter().map(String::as_str).collect();
                if vocabularies
                    .iter()
                    .any(|v| v.words.iter().filter(|w| items.contains(*w)).count() >= 2)
                {
                    lists_checked += 1;
                }
            }
            for problem in incomplete_lists(&text, &vocabularies)? {
                failures.push(format!("{rel}:{line}: {problem}"));
            }
        }
    }
    // Vacuity guard: the strategy list in src/output/query/correlated.rs and
    // the method lists beside it are lists this test must find. Fewer than
    // five means the block reader or the list pattern has stopped matching.
    assert!(
        lists_checked >= 5,
        "found only {lists_checked} lists of correlation names under src/; \
         the reader no longer recognizes them"
    );
    assert!(
        failures.is_empty(),
        "these doc comments list some correlation names but not all of them. \
         They are the descriptions clients read in the OpenAPI document and the \
         MCP schemas; name every member, or stop listing:\n{}",
        failures.join("\n")
    );
    Ok(())
}

/// Every paragraph or table of a Markdown page, outside code fences, as
/// (first line number, joined text).
fn markdown_blocks(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut current: Option<(usize, String)> = None;
    let mut in_fence = false;
    for (i, line) in text.lines().enumerate() {
        let fence = line.trim_start().starts_with("```");
        if fence {
            in_fence = !in_fence;
        }
        if fence || in_fence || line.trim().is_empty() {
            if let Some(block) = current.take() {
                out.push(block);
            }
            continue;
        }
        match current.as_mut() {
            Some((_, t)) => {
                t.push(' ');
                t.push_str(line.trim());
            }
            None => current = Some((i + 1, line.trim().to_string())),
        }
    }
    if let Some(block) = current {
        out.push(block);
    }
    out
}

/// Doc lists that name a subset on purpose, each with the words that find its
/// block and the reason it may be partial.
///
/// An entry that matches no block fails the test, so the list cannot outlive
/// the text it excuses.
const PARTIAL_LISTS: &[(&str, &str, &str)] = &[(
    "docs/opensips-sipnab.md",
    "sipnab reports which method joined a leg in `method`",
    "the three ways OpenSIPS topology hiding can join a leg, under a table of \
     exactly those three; `sdp` and `timing` are not topology-hiding methods",
)];

#[test]
fn every_prose_list_of_correlation_names_in_the_docs_is_complete() -> Result<(), TestError> {
    // The operator pages repeat the same lists, and drifted with the code:
    // docs/mcp-estate.md listed four methods after `mapping` became the fifth.
    // The design and research notes are working documents dated by their own
    // text, and the website mirrors are generated from docs/, so neither is
    // read here.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vocabularies = vocabularies();
    let mut failures = Vec::new();
    let mut pages = 0usize;
    let mut excused = vec![false; PARTIAL_LISTS.len()];
    for entry in walkdir::WalkDir::new(root.join("docs")) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(root)?.display().to_string();
        if entry.path().extension().and_then(|e| e.to_str()) != Some("md")
            || rel.starts_with("docs/design/")
            || rel.starts_with("docs/research/")
        {
            continue;
        }
        pages += 1;
        let text = std::fs::read_to_string(entry.path())?;
        for (line, block) in markdown_blocks(&text) {
            if let Some(i) = PARTIAL_LISTS
                .iter()
                .position(|(page, words, _)| *page == rel && block.contains(words))
            {
                excused[i] = true;
                continue;
            }
            for problem in incomplete_lists(&block, &vocabularies)? {
                failures.push(format!("{rel}:{line}: {problem}"));
            }
        }
    }
    for (i, (page, words, _)) in PARTIAL_LISTS.iter().enumerate() {
        assert!(
            excused[i],
            "PARTIAL_LISTS names {page}: {words:?}, which matches no block there; \
             remove the entry"
        );
    }
    assert!(
        pages >= 50,
        "read only {pages} pages under docs/; the walk is broken"
    );
    assert!(
        failures.is_empty(),
        "these docs list some correlation names but not all of them; name \
         every member, or stop listing:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn the_list_reader_finds_lists_and_ignores_names_in_passing() -> Result<(), TestError> {
    let v = vocabularies();
    // A complete list passes, with glosses that themselves hold backquotes.
    let complete = "How: `decoded` (a `th` Call-ID), `mapping`, `header` (a header \
                    `Session-ID` or `Via`), `sdp` or `timing` (the guess).";
    assert_eq!(
        incomplete_lists(complete, &v)?,
        Vec::<String>::new(),
        "a list naming all five methods, glosses included, must pass"
    );
    // The shape 0.5.232 left behind: four of five methods.
    let stale = "How: `decoded`, `header`, `sdp` or `timing`, as on the route.";
    let found = incomplete_lists(stale, &v)?;
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("omits mapping"), "{found:?}");
    // Two names in passing are not a list.
    let passing = "`session_id` and `x_call_id` both score 100.";
    assert_eq!(
        incomplete_lists(passing, &v)?,
        Vec::<String>::new(),
        "two names joined by `and` are a mention, not a list, and must pass"
    );
    // A list of statuses that shares `decoded` with the methods is checked
    // against the statuses only.
    let statuses = "Status: `decoded`, `no_secret`, `undecodable` or `unmatched`.";
    let found = incomplete_lists(statuses, &v)?;
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("mapped, conflict") || found[0].contains("conflict, mapped"),
        "{found:?}"
    );
    Ok(())
}
