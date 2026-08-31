// SPDX-License-Identifier: MIT OR Apache-2.0

//! The instruments that CHECK the work get the same scrutiny as the work.
//!
//! # The defects this file exists for
//!
//! Three incidents, all mine, and not one of them is in the product. Every
//! one is in a command or a script I reached for to verify something, and
//! every one produced confident output that was not about what I thought it
//! was about.
//!
//! **1. A filter that matched nothing.** Meaning to run two named tests I
//! typed `cargo test --features full --lib "a\|b"`. The argument cargo takes
//! there is a plain SUBSTRING, not a regex, so `a\|b` is a literal
//! four-character needle that no test name contains. The output was `test
//! result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4448 filtered out`.
//! It says `ok`, and I nearly filed it as proof the two tests passed. They had
//! not run. Writing the test below turned up a second layer I had not seen at
//! the time: `\|` is an alternation only in a BASIC regular expression, the
//! dialect `grep` and `sed` read. Every modern engine treats it as an escaped
//! literal pipe, so even a `cargo test` that DID take a regex would have
//! selected nothing. The argument was wrong in two dialects at once.
//!
//! **2. A field name my own probe invented.** Reading a `list_dialogs`
//! response I asked for `d.get('total')`. That key is not in the response —
//! the keys are `dialogs`, an array, and on other tools `total_matched` — so
//! every row printed `?` and I briefly reported the rows as unlabeled. The
//! reason it printed at all is that the probe ended in `unwrap_or`, which
//! turns "this key is absent" and "this key is empty" into the same character
//! on the screen. A missing key is a bug in the reader; an empty value is a
//! fact about the data. Collapsing them hides the first behind the second.
//!
//! **3. Citations broken by my own edits.** Twice, editing `src/mcp/server.rs`
//! moved a line that `docs/design/backlog.md` cites: `scope_of` was quoted at
//! :7714, then :7731, then :7782. `scripts/check-line-drift.py --apply`
//! re-points a citation when the symbol has ONE unambiguous definition, and
//! `scope_of` has two — a `#[cfg(feature = "mcp-http")]` arm and a
//! `#[cfg(not(feature = "mcp-http"))]` arm — so the fixer defers to a person.
//! It can only defer usefully if the prose says which arm it means, and that
//! sentence does: "the `mcp-http` arm".
//!
//! # The lesson, and what is pinned here
//!
//! A filter that selects nothing, a field name that does not exist, and a
//! citation that drifts all fail the same way: they keep printing, and what
//! they print reads like a result. So the three shapes are pinned as rules
//! rather than as habits — the substring/regex distinction, the difference
//! between a zero-passed summary and a run, and the requirement that an
//! ambiguous citation carry its own disambiguation — plus a fourth test whose
//! only job is to prove the other three examined a real corpus.
//!
//! Incident 2 has no test of its own, because the shape it teaches is inside
//! the second one: `Summary` gives "the filter selected nothing" and "this
//! binary holds nothing" two different values instead of folding both into one
//! `unwrap_or` default. Two facts that call for different fixes must not
//! arrive at the reader as the same symbol.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use regex::Regex;

// ── the fixtures and the corpus ─────────────────────────────────────

/// Real test names from this repository, as a `cargo test` filter sees them.
///
/// Real ones on purpose: a filter argument is matched against the name libtest
/// prints, so a fixture of invented names would be a rule about a naming style
/// nobody uses. Two of these — the first and the third — stand in for the two
/// tests incident 1 meant to run.
const TEST_NAMES: &[&str] = &[
    "a_zero_passed_summary_is_not_a_verified_run",
    "a_clean_walk_and_an_empty_walk_must_not_share_a_verdict",
    "every_marker_line_in_the_tree_is_bare",
    "filtering_by_test_name_selects_a_different_set_than_selecting_binaries",
    "line_citations_point_at_the_code_they_name",
    "code_tree_list_matches_the_repository",
    "the_cross_reference_scanner_reads_real_references",
    "every_test_named_in_a_cross_reference_exists",
    "no_claim_of_absence_names_a_test_that_exists",
    "the_gate_the_pre_push_prompt_names_exists",
];

/// The design page whose citations are checked here.
const BACKLOG: &str = "docs/design/backlog.md";

/// Floor under the backlog's size, in bytes. Measured: 489742.
///
/// A floor rather than the measurement, because the page grows every release.
/// What it has to catch is the page being truncated, moved, or replaced by a
/// stub — any of which would leave the citation scan below reporting a clean
/// document it never read.
const MIN_BACKLOG_BYTES: usize = 100_000;

/// Floor under the number of `src/…:NNN` citations in the backlog.
/// Measured: 283.
const MIN_SRC_CITATIONS: usize = 50;

/// Floor under the citations that resolve to a symbol defined in the cited
/// file. Measured: 37.
///
/// This is the corpus the ambiguity rule actually runs over, and it is much
/// smaller than the citation count because most citations name no symbol the
/// resolver can find. If it collapses, the rule is examining nothing.
const MIN_RESOLVABLE_CITATIONS: usize = 20;

/// How far before a citation the prose naming its subject may sit.
///
/// 90 characters, the same window `scripts/check-line-drift.py` uses. The two
/// have to agree about which symbol a citation is about, or this test would be
/// demanding disambiguation for a symbol the fixer was never looking at.
const CONTEXT_CHARS: usize = 90;

/// How much prose around a citation may carry the disambiguation.
///
/// Wider than [`CONTEXT_CHARS`], because the sentence that says which arm is
/// meant is not required to sit as close as the symbol name itself. Wider is
/// the conservative direction here: it can only make this test accept more.
const PROSE_CHARS: usize = 400;

/// How far above a definition a `#[cfg(…)]` attribute may sit and still be
/// read as gating it. Doc comments and other attributes intervene.
const CFG_LOOKBACK: usize = 40;

/// Identifiers that name a concept rather than a definition.
///
/// Copied in spirit from `scripts/check-line-drift.py`: finding `Some` or
/// `impl` next to a citation says nothing about what the citation is for.
const NOT_SYMBOLS: &[&str] = &[
    "true", "false", "None", "Some", "Ok", "Err", "self", "mut", "pub", "use", "if", "let", "fn",
    "match", "return", "async", "await", "impl", "dyn", "tests", "test", "main", "new", "default",
];

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The backlog page, or a panic naming the path.
fn backlog_text() -> String {
    let p = repo().join(BACKLOG);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// A byte range of `text`, widened to the nearest character boundaries.
///
/// The backlog is full of em dashes and typographic quotes, so a window
/// computed in bytes lands inside a multi-byte character often enough to
/// matter. A slice that panics there would take the whole gate down and look
/// like a defect in the document.
fn window(text: &str, start: usize, end: usize) -> &str {
    let mut s = start.min(text.len());
    while s > 0 && !text.is_char_boundary(s) {
        s -= 1;
    }
    let mut e = end.min(text.len());
    while e < text.len() && !text.is_char_boundary(e) {
        e += 1;
    }
    if s >= e { "" } else { &text[s..e] }
}

// ── 1. a cargo test filter is a substring ───────────────────────────

/// Apply a `cargo test` name filter the way libtest applies it.
///
/// One line, and that is the point: libtest's filter is `str::contains`. There
/// is no anchoring, no alternation, no character class. Everything incident 1
/// assumed about the argument lives in the gap between this function and
/// [`Regex`].
fn cargo_filter_matches<'a>(names: &[&'a str], filter: &str) -> Vec<&'a str> {
    names
        .iter()
        .copied()
        .filter(|n| n.contains(filter))
        .collect()
}

/// A `cargo test` filter is a substring; a regex written there selects nothing.
///
/// Incident 1, as a rule. Every pattern below is checked twice: once under the
/// substring rule libtest actually applies, where it must match ZERO names,
/// and once as a compiled regex, where it must match at least one. The second
/// half is what makes the first half evidence — a pattern that matched nothing
/// either way would only prove I had typed nonsense, while a pattern that is a
/// perfectly good regex and still selects nothing is the trap itself.
///
/// The argument I really typed gets its own block, because writing this test
/// found a layer I had not noticed. `a\|b` is a BASIC regular expression
/// alternation — the dialect `grep` and `sed` take — and in every modern
/// engine, this crate included, `\|` is an escaped literal pipe. So that
/// pattern selects nothing three ways: not as a substring, and not as a regex
/// either, because it is not one. Only the BRE reading gives it the meaning I
/// had in mind. The instrument was wrong in one more way than the incident
/// showed.
///
/// The consequence is the reason this is worth a test. A filter that selects
/// no test does not error. libtest runs the empty set, finds no failure in it,
/// and prints `test result: ok.` — the same word it prints for a real pass, on
/// the same line, with the same exit status. There is nothing at the call site
/// to react to, which is why the only defense is not writing one.
#[test]
fn a_cargo_test_filter_is_a_substring_and_a_regex_written_there_selects_nothing() {
    let regex_patterns: Vec<String> = vec![
        ".*".to_string(),
        "^a_zero_passed".to_string(),
        "_bare$".to_string(),
        "summary|marker".to_string(),
        "(marker|verdict)$".to_string(),
    ];
    assert!(
        regex_patterns.len() >= 5,
        "the pattern table lost its rows; a rule proven over {} pattern(s) \
         does not cover the metacharacters that get typed",
        regex_patterns.len()
    );

    for pattern in &regex_patterns {
        let selected = cargo_filter_matches(TEST_NAMES, pattern);
        assert!(
            selected.is_empty(),
            "`cargo test {pattern}` selected {selected:?} under the substring \
             rule. If a regex now selects tests, this rule has changed and the \
             advice built on it — never write a regex there — is wrong."
        );

        let re = Regex::new(pattern)
            .unwrap_or_else(|e| panic!("the fixture pattern {pattern} must be a valid regex: {e}"));
        let as_regex: Vec<&str> = TEST_NAMES
            .iter()
            .copied()
            .filter(|n| re.is_match(n))
            .collect();
        assert!(
            !as_regex.is_empty(),
            "the pattern {pattern} matches no name even as a regex, so the \
             zero above proves nothing about the substring rule — it only \
             proves the fixture is meaningless"
        );
    }

    // The literal argument from incident 1: two test names joined the way an
    // alternation is written for `grep`, which is the only dialect that reads
    // it that way.
    let bre = format!("{}\\|{}", TEST_NAMES[0], TEST_NAMES[2]);
    assert!(
        cargo_filter_matches(TEST_NAMES, &bre).is_empty(),
        "the argument from incident 1 selected tests under the substring rule; \
         the incident is then not reproducible and this whole file rests on a \
         misremembered command"
    );
    let as_modern = Regex::new(&bre).expect("an escaped pipe is a valid pattern");
    assert!(
        !TEST_NAMES.iter().any(|n| as_modern.is_match(n)),
        "`{bre}` matched a name as a modern regex. In this dialect `\\|` is an \
         escaped literal pipe, so it must not — if it now alternates, the note \
         above about BRE is wrong and the advice built on it misleads."
    );
    let as_bre = Regex::new(&bre.replace("\\|", "|")).expect("the BRE reading is a valid pattern");
    let intended: Vec<&str> = TEST_NAMES
        .iter()
        .copied()
        .filter(|n| as_bre.is_match(n))
        .collect();
    assert_eq!(
        intended,
        vec![TEST_NAMES[0], TEST_NAMES[2]],
        "the BRE reading of the incident's pattern must select exactly the two \
         tests it was meant to run; without that the pattern was meaningless \
         in every dialect and there was no near miss to learn from"
    );

    // The other direction: the rule selects, and selects exactly.
    let plain = cargo_filter_matches(TEST_NAMES, "cross_reference");
    assert_eq!(
        plain,
        vec![
            "the_cross_reference_scanner_reads_real_references",
            "every_test_named_in_a_cross_reference_exists",
        ],
        "a plain substring no longer selects the names that contain it; the \
         comparison above is then between two kinds of zero and says nothing"
    );
    assert_eq!(
        cargo_filter_matches(TEST_NAMES, TEST_NAMES[0]),
        vec![TEST_NAMES[0]],
        "a whole test name must select exactly that test — the invocation \
         incident 1 should have used, twice, instead of one alternation"
    );
}

// ── 2. a zero-passed summary is not a run ───────────────────────────

/// What one `test result:` line proves, with the filter separated out.
#[derive(Debug, PartialEq, Eq)]
enum Summary {
    /// Not a result line at all.
    NotAResultLine,
    /// This many tests executed and passed.
    Verified(usize),
    /// Tests executed and at least one failed.
    Failed,
    /// Nothing executed, and this many tests were excluded by the name filter.
    /// The binary was full of tests and the filter chose none of them.
    FilterMatchedNothing {
        /// Tests the filter excluded.
        filtered_out: usize,
    },
    /// Nothing executed and nothing was filtered: this binary holds no test
    /// the current feature set compiles.
    BinaryHeldNothing,
}

impl Summary {
    /// Whether this line is evidence that the named tests ran and passed.
    fn is_evidence(&self) -> bool {
        matches!(self, Summary::Verified(n) if *n > 0)
    }
}

/// Classify one line of cargo's output.
///
/// The two zero-passed shapes are deliberately different values.
/// `vacuous_success_test` folds them into one `NothingRan` because its subject
/// is the word `ok`; the subject here is the FILTER, and for that the split is
/// the whole answer. A large `filtered out` beside `0 passed` says the binary
/// was full and the argument selected none of it, which points at the filter's
/// syntax. A zero beside a zero says the binary was empty, which points
/// somewhere else entirely — a feature gate, a wrong `--test` name.
fn classify(line: &str) -> Summary {
    let summary = Regex::new(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
        .expect("the cargo summary pattern must compile");
    let filtered =
        Regex::new(r"(\d+) filtered out").expect("the filtered-out pattern must compile");
    let Some(caps) = summary.captures(line) else {
        return Summary::NotAResultLine;
    };
    let passed: usize = caps[2].parse().unwrap_or(0);
    let failed: usize = caps[3].parse().unwrap_or(0);
    if &caps[1] == "FAILED" || failed > 0 {
        return Summary::Failed;
    }
    if passed == 0 {
        let filtered_out: usize = filtered
            .captures(line)
            .and_then(|c| c[1].parse().ok())
            .unwrap_or(0);
        return if filtered_out > 0 {
            Summary::FilterMatchedNothing { filtered_out }
        } else {
            Summary::BinaryHeldNothing
        };
    }
    Summary::Verified(passed)
}

/// A summary with `0 passed` beside a large `filtered out` accuses the filter.
///
/// Incident 1's output, read as a line rather than as a word.
/// `vacuous_success_test::a_zero_passed_summary_is_not_a_verified_run` already
/// pins that `ok` with no passes is not a pass; this covers the half it does
/// not, which is the FILTER angle. Two claims are added on top of that one:
///
/// * the two zero-passed shapes are distinguishable from each other — an
///   empty binary and a filter that selected nothing are different problems
///   with different fixes, and a classifier that returns one value for both
///   sends the reader to the wrong one;
/// * `4448 filtered out` beside `0 passed` is itself the accusation. The
///   binary held 4448 tests. An argument that selects none of 4448 is not a
///   narrow filter, it is a filter that cannot match anything, which is what
///   `a\|b` is.
///
/// The exact line from the incident is the first row, verbatim.
#[test]
fn a_filter_that_selected_nothing_is_visible_in_the_summary_it_prints() {
    let incident = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; \
                    4448 filtered out; finished in 0.00s";
    let cases: Vec<(&str, Summary)> = vec![
        (
            incident,
            Summary::FilterMatchedNothing { filtered_out: 4448 },
        ),
        (
            "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.31s",
            Summary::Verified(12),
        ),
        (
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.00s",
            Summary::BinaryHeldNothing,
        ),
        (
            "test result: ok. 4 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; \
             finished in 0.02s",
            Summary::Verified(4),
        ),
        (
            "test result: FAILED. 11 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.44s",
            Summary::Failed,
        ),
        ("running 4448 tests", Summary::NotAResultLine),
    ];
    assert!(
        cases.len() >= 6,
        "the case table lost its rows; a classifier proven over {} line(s) \
         does not cover the shapes cargo prints",
        cases.len()
    );

    for (line, expected) in &cases {
        assert_eq!(
            &classify(line),
            expected,
            "misclassified a real cargo summary line: {line}"
        );
    }

    assert!(
        !classify(incident).is_evidence(),
        "the line from incident 1 was classified as evidence. It reports that \
         4448 tests were excluded and none ran; accepting it is how a run that \
         executed nothing gets filed as two tests passing."
    );
    assert!(
        classify(cases[1].0).is_evidence(),
        "a genuine `12 passed` was not classified as evidence; a classifier \
         that refuses everything is not a classifier and would be trusted \
         about nothing"
    );
    assert_ne!(
        classify(incident),
        classify(cases[2].0),
        "a filter that selected nothing and a binary that holds nothing \
         collapsed to one verdict. They have different fixes — retype the \
         filter, or check the feature set — and one verdict sends every reader \
         to the wrong one."
    );
    assert!(
        matches!(
            classify(incident),
            Summary::FilterMatchedNothing { filtered_out } if filtered_out >= 100
        ),
        "the filtered-out count was lost. That number is the accusation: a \
         binary with hundreds of tests, and an argument that matched none of \
         them, is a filter that cannot match rather than one that is narrow."
    );
}

// ── 3. an ambiguous citation must say which definition ──────────────

/// One `[`path.rs:NNN`](url)` citation in a document.
struct Citation {
    /// The path as the label spells it, which may be relative to `src/`.
    label: String,
    /// The URL, which is what says unambiguously which file is meant.
    href: String,
    /// Byte offset of the citation's start in the page.
    start: usize,
    /// Byte offset of the citation's end in the page.
    end: usize,
}

/// Every line citation on a page.
fn citations(text: &str) -> Vec<Citation> {
    let re = Regex::new(r"\[`([A-Za-z0-9_./-]+\.rs):(\d+)`\]\(([^)\s]*)\)")
        .expect("the citation pattern must compile");
    re.captures_iter(text)
        .map(|c| {
            let whole = c.get(0).expect("group 0 always exists");
            Citation {
                label: c[1].to_string(),
                href: c[3].to_string(),
                start: whole.start(),
                end: whole.end(),
            }
        })
        .collect()
}

/// The source file a citation is about, or `None` when it cannot be told.
///
/// The label is often relative to `src/` or a bare basename, so it resolves
/// from the repository root only sometimes. The link always says which file is
/// meant, and is the fallback — the same order `scripts/check-line-drift.py`
/// uses.
fn source_for(label: &str, href: &str) -> Option<PathBuf> {
    let direct = repo().join(label);
    if direct.is_file() {
        return Some(direct);
    }
    let blob = Regex::new(r"^https?://[^/]*github\.com/[^/]+/[^/]+/blob/[^/]+/(.+)$")
        .expect("the blob pattern must compile");
    let path = href.split('#').next()?;
    let caps = blob.captures(path)?;
    let cand = repo().join(&caps[1]);
    cand.is_file().then_some(cand)
}

/// Whether an identifier found in prose can be a citation's subject.
fn usable(name: &str) -> bool {
    name.len() > 2 && !NOT_SYMBOLS.contains(&name)
}

/// The identifier the prose names immediately before a citation.
///
/// Before only. The subject precedes its citation in every form these pages
/// use, and an identifier after one belongs to the NEXT citation — the same
/// finding `scripts/check-line-drift.py` records after its ranking-by-distance
/// version re-pointed correct citations at their neighbor's subject.
fn symbol_near(text: &str, start: usize) -> Option<String> {
    let before = window(text, start.saturating_sub(CONTEXT_CHARS), start);
    let ident = Regex::new(r"`([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)")
        .expect("the identifier pattern must compile");
    ident
        .captures_iter(before)
        .filter_map(|c| {
            let m = c.get(1)?;
            usable(m.as_str()).then(|| m.as_str().to_string())
        })
        .last()
}

/// 1-based lines where `sym` is DEFINED, not merely mentioned.
///
/// `impl` blocks are dropped when any other definition matches. A type has one
/// definition and any number of impl blocks, so counting the blocks would
/// report every documented type as ambiguous and drown the real cases.
fn definition_lines(lines: &[&str], sym: &str) -> Vec<usize> {
    let pat = Regex::new(&format!(
        r"\b(?:fn|struct|enum|const|static|impl|type|trait|mod|macro_rules!)\s+{}\b",
        regex::escape(sym)
    ))
    .expect("the definition pattern must compile");
    let is_impl = Regex::new(r"^\s*(?:pub\s+)?impl\b").expect("the impl pattern must compile");
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| pat.is_match(l))
        .map(|(i, _)| i + 1)
        .collect();
    let real: Vec<usize> = hits
        .iter()
        .copied()
        .filter(|n| !is_impl.is_match(lines[n - 1]))
        .collect();
    if real.is_empty() { hits } else { real }
}

/// Which segment of `Type::member` the prose is citing, or `None`.
///
/// The member first: a sentence naming `McpAuth::BearerVerified` is about the
/// variant, and resolving it to the type would point at a different line with
/// a different meaning.
fn resolve_symbol(lines: &[&str], qualified: &str) -> Option<String> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let segments: Vec<&str> = qualified.split("::").collect();
    for cand in segments.into_iter().rev() {
        if !seen.insert(cand) || !usable(cand) {
            continue;
        }
        if !definition_lines(lines, cand).is_empty() {
            return Some(cand.to_string());
        }
    }
    None
}

/// Words that would tell a reader which of several definitions is meant.
///
/// Derived from the code, not typed: every feature name in a `#[cfg(…)]`
/// attribute above one of the definitions. For `scope_of` that yields
/// `mcp-http`, which is exactly the word the backlog sentence uses. The
/// generic vocabulary — `cfg`, `arm`, `branch`, `variant` — is added by the
/// caller, since prose can disambiguate without naming a feature.
fn cfg_features(lines: &[&str], defs: &[usize]) -> BTreeSet<String> {
    let feature = Regex::new(r#"feature\s*=\s*"([A-Za-z0-9_.-]+)""#)
        .expect("the feature pattern must compile");
    let mut out = BTreeSet::new();
    for &def in defs {
        let first = def.saturating_sub(CFG_LOOKBACK).max(1);
        for line in &lines[first - 1..def.min(lines.len())] {
            if !line.contains("#[cfg") {
                continue;
            }
            for c in feature.captures_iter(line) {
                out.insert(c[1].to_ascii_lowercase());
            }
        }
    }
    out
}

/// A citation whose symbol has two definitions must say which one it means.
///
/// Incident 3, and deliberately the half
/// `dev_docs_drift_test::line_citations_point_at_the_code_they_name` does not
/// cover. That gate runs `scripts/check-line-drift.py`, which asks whether a
/// citation still lands on its symbol and re-points it when exactly ONE
/// definition exists. When there are two — this codebase's `#[cfg(feature =
/// "x")]` / `#[cfg(not(feature = "x"))]` pairs — the fixer refuses and prints
/// that it needs a person. Nothing asked whether that person can answer.
///
/// So: for every citation whose subject has more than one definition in the
/// cited file, the surrounding prose must name which one. Accepted evidence is
/// either a feature name read out of a `#[cfg(…)]` attribute above one of the
/// definitions, or the generic vocabulary this repository uses for a
/// conditional pair. `scope_of` passes on both counts — the sentence says "the
/// `mcp-http` arm".
///
/// # Limits
///
/// Conservative in every direction, because a false accusation against a
/// document is worse than a gap:
///
/// * A citation whose prose names no resolvable symbol is skipped, not
///   guessed at. Most are: 37 of the page's 82 citations resolve.
/// * The subject is the nearest backticked identifier BEFORE the citation,
///   within [`CONTEXT_CHARS`]. A sentence that names its subject further away
///   is not checked.
/// * `impl` blocks are not counted as definitions unless nothing else matches,
///   so a documented type with several impls is not reported as ambiguous.
/// * The disambiguation only has to be PRESENT within [`PROSE_CHARS`]. Whether
///   it names the correct arm is not decidable from here, and claiming
///   otherwise would be a second confident wrong answer.
#[test]
fn a_citation_whose_symbol_has_two_definitions_names_which_one() {
    let text = backlog_text();
    let cites = citations(&text);
    assert!(
        !cites.is_empty(),
        "no line citation was found in {BACKLOG}; the pattern has stopped \
         matching how this page writes them and the walk below examines nothing"
    );

    let generic = Regex::new(r"\b(cfg|arm|arms|branch|branches|variant|variants)\b")
        .expect("the generic-vocabulary pattern must compile");
    let mut resolvable = 0usize;
    let mut ambiguous = 0usize;
    let mut silent: Vec<String> = Vec::new();

    for c in &cites {
        let Some(path) = source_for(&c.label, &c.href) else {
            continue;
        };
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = src.lines().collect();
        let Some(qualified) = symbol_near(&text, c.start) else {
            continue;
        };
        let Some(sym) = resolve_symbol(&lines, &qualified) else {
            continue;
        };
        resolvable += 1;

        let defs = definition_lines(&lines, &sym);
        if defs.len() < 2 {
            continue;
        }
        ambiguous += 1;

        let prose = window(
            &text,
            c.start.saturating_sub(PROSE_CHARS),
            c.end + PROSE_CHARS,
        )
        .to_ascii_lowercase();
        let features = cfg_features(&lines, &defs);
        if features.iter().any(|f| prose.contains(f)) || generic.is_match(&prose) {
            continue;
        }
        silent.push(format!(
            "  {}: `{sym}` is defined at {defs:?}; the prose around the \
             citation names none of {features:?} and no cfg/arm wording",
            c.label
        ));
    }

    assert!(
        resolvable >= MIN_RESOLVABLE_CITATIONS,
        "only {resolvable} of {} citations in {BACKLOG} resolved to a symbol \
         defined in the cited file. The resolver has narrowed and the rule \
         below is running over almost nothing — fix the resolver rather than \
         lowering {MIN_RESOLVABLE_CITATIONS}.",
        cites.len()
    );
    assert!(
        ambiguous >= 1,
        "not one of the {resolvable} resolvable citations names a symbol with \
         two definitions, so this rule has no subject and passes without \
         deciding anything. Either the cfg-gated pair it was written for \
         (`scope_of` in src/mcp/server.rs) is gone, or the definition scan has \
         stopped seeing the second arm."
    );
    assert!(
        silent.is_empty(),
        "these citations name a symbol with more than one definition and do \
         not say which one is meant:\n{}\n\n\
         `scripts/check-line-drift.py --apply` refuses to re-point an \
         ambiguous citation and defers to a person. That person reads this \
         sentence; if it does not name the arm, the citation cannot be \
         repaired from the document and every future edit to the file moves it \
         again.",
        silent.join("\n")
    );
}

// ── 4. none of the above ran over nothing ───────────────────────────

/// The corpus every rule above rests on is real.
///
/// A scan over an empty document reports a clean document, and a filter rule
/// proven over an empty name list proves nothing about filters. Each floor
/// here is well under the measured value, so ordinary churn does not move it
/// while a corpus that has collapsed falls through loudly.
#[test]
fn the_corpus_behind_these_rules_is_not_empty() {
    let text = backlog_text();
    assert!(
        text.len() >= MIN_BACKLOG_BYTES,
        "{BACKLOG} is {} bytes, under the {MIN_BACKLOG_BYTES} floor. A \
         truncated or relocated page leaves the citation rule certifying a \
         document it never read.",
        text.len()
    );
    assert!(
        text.lines().count() >= 1000,
        "{BACKLOG} holds only {} lines; it is no longer the page these rules \
         were measured against",
        text.lines().count()
    );

    let src_cites = Regex::new(r"src/[A-Za-z0-9_./-]+\.rs:\d+")
        .expect("the src-citation pattern must compile")
        .find_iter(&text)
        .count();
    assert!(
        src_cites >= MIN_SRC_CITATIONS,
        "{BACKLOG} carries only {src_cites} `src/…:NNN` citations, under the \
         {MIN_SRC_CITATIONS} floor. Below that the ambiguity rule is a walk \
         over a handful of lines and a clean result means nothing."
    );

    let linked = citations(&text).len();
    assert!(
        linked >= MIN_SRC_CITATIONS,
        "only {linked} citations parse as `[`path.rs:NNN`](url)`; the citation \
         pattern no longer matches this page's own convention"
    );

    assert!(
        TEST_NAMES.len() >= 8,
        "the test-name fixture holds {} name(s); the substring/regex \
         comparison needs enough names for a regex to have something to match \
         that a substring does not",
        TEST_NAMES.len()
    );
    let distinct: BTreeSet<&&str> = TEST_NAMES.iter().collect();
    assert_eq!(
        distinct.len(),
        TEST_NAMES.len(),
        "the fixture repeats a name, so the exact-selection assertions above \
         are counting one entry twice"
    );
}
