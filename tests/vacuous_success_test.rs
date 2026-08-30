// SPDX-License-Identifier: MIT OR Apache-2.0

//! A check that examined nothing must not be able to report success.
//!
//! # The defect this file exists for
//!
//! Two incidents, the same shape, both mine.
//!
//! **The corpus that was never opened.** Meaning to validate sipnab against
//! the real capture corpus, I ran `cargo test --features full corpus`. That
//! trailing word filters test *names*; the gate it was standing in for derives
//! test *binaries* from the tree — every `tests/*.rs` that reads
//! `SIPNAB_CORPUS`. Five binaries printed `test result: ok. 0 passed; 0
//! failed` and I read five "ok"s as a pass. The invocation I meant ran 64
//! tests across 15 binaries. Nothing in that output separates "the corpus is
//! clean" from "the corpus was never opened": both spell it `ok`.
//!
//! **The links that were never fetched.** Pulling download links out of a
//! rendered page with a grep for `href="https://…"` returned an empty list,
//! because Zola HTML-escapes `/` as `&#x2F;` and newlines as `&#10;`. The
//! shell loop after it walked that empty list, set no failure flag, exited 0,
//! and I reported that every download link answered 200. Zero links, all of
//! them healthy.
//!
//! # The property
//!
//! **Empty input must produce a refusal, never a pass.** A verdict of "clean"
//! is a claim about things that were examined, so a walk that examined nothing
//! has to return a third answer — not the same `true` it returns for a
//! collection it checked and liked. Every idiom below fails the property in
//! the same way: `for x in $EMPTY`, `Iterator::all` over an empty slice, a
//! summary line reading `0 passed`, a regex that matched nothing. Each is
//! indistinguishable, at the call site, from real work.
//!
//! What is pinned here is the distinguishability, in five shapes plus one:
//! the walk, the selection, the summary line, the escaped document, the
//! derivation's own floor — and then this file turned on itself, because a
//! gate against vacuous success that is itself vacuous would be the purest
//! form of the bug it is named for.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

use regex::Regex;

// The extractor for `#[test]` function names is shared with the other gates
// that read this tree, rather than written a second time here: two extractors
// disagreeing about what a test is would give the tree an argument with itself.
#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::test_fns;

/// This file, excluded from its own scans.
///
/// The derivation below looks for files that name [`CORPUS_MARKER`], and this
/// file has to spell that marker in order to search for it. Counting itself
/// would inflate every number here by one and make the result describe the
/// scanner instead of the tree.
const SELF_FILE: &str = "vacuous_success_test.rs";

/// The environment variable every corpus-backed test binary reads.
const CORPUS_MARKER: &str = "SIPNAB_CORPUS";

/// The floor under the corpus-binary derivation.
///
/// Measured at 15 on 2026-08-30. Set to 10 so ordinary churn in the test tree
/// does not move it, while a derivation that has stopped matching — a renamed
/// marker, a walk that no longer reaches `tests/` — falls through it loudly
/// instead of reporting a clean run over nothing.
const MIN_CORPUS_BINARIES: usize = 10;

/// A `for` loop header in Rust source.
const FOR_LOOP: &str = r"\bfor\s+[^{;]{1,60}\sin\s";

/// Text that bounds a collection: an assertion about its size, or an explicit
/// empty-case return before it is walked.
///
/// Matched against a whole window of source rather than one line at a time,
/// because `rustfmt` splits every assertion in this file across lines: the
/// per-line form of this rule reported two loops as unguarded that are in fact
/// guarded, and a rule that cannot see what is there is the same failure in
/// reverse. `[^;]` holds the match inside one statement, so an unrelated
/// `.len()` further down the window cannot stand in for a guard.
const EMPTINESS_GUARD: &str =
    r"assert!\([^;]{0,240}(is_empty\(\)|\.len\(\)|\.count\(\))|if\s[^\n]*is_empty\(\)";

/// How many lines either side of a loop the guard may sit on.
const GUARD_WINDOW: usize = 10;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `tests/*.rs` except this one, as `(file name, text)`.
fn test_sources() -> Vec<(String, String)> {
    let dir = repo().join("tests");
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "tests/ must be readable to derive anything about the test tree: {}: {e}",
            dir.display()
        )
    });
    let mut out: Vec<(String, String)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter_map(|p| {
            let name = p.file_name()?.to_string_lossy().into_owned();
            if name == SELF_FILE {
                return None;
            }
            Some((name, std::fs::read_to_string(&p).ok()?))
        })
        .collect();
    out.sort();
    out
}

/// The corpus test binaries: every `tests/*.rs` whose text names the marker.
///
/// This is the *binary* selection — what `cargo test --test <name>` would be
/// pointed at — and it is a property of what a file READS, which is why no
/// filter over test names can reproduce it.
fn corpus_binaries() -> Vec<String> {
    test_sources()
        .into_iter()
        .filter(|(_, text)| text.contains(CORPUS_MARKER))
        .map(|(name, _)| name)
        .collect()
}

/// What a walk over a collection concluded.
#[derive(Debug, PartialEq, Eq)]
enum Walk {
    /// This many members were examined, and all of them passed.
    AllPassed(usize),
    /// This many members failed.
    SomeFailed(usize),
    /// The collection was empty. Nothing was examined, so nothing is known.
    NothingExamined,
}

/// The shell idiom, in Rust: walk the list, remember only the failures.
///
/// `Iterator::all` over an empty slice answers `true` for exactly the reason
/// the shell loop leaves its failure flag unset — neither ever ran the check.
/// The bug is modeled here on purpose so the test can show the two inputs this
/// signature cannot tell apart.
fn walk_reporting_only_failures(items: &[&str], ok: impl Fn(&str) -> bool) -> bool {
    items.iter().copied().all(ok)
}

/// The same walk with the empty case answered separately.
fn walk_refusing_empty(items: &[&str], ok: impl Fn(&str) -> bool) -> Walk {
    if items.is_empty() {
        return Walk::NothingExamined;
    }
    let failed = items.iter().copied().filter(|item| !ok(item)).count();
    if failed == 0 {
        Walk::AllPassed(items.len())
    } else {
        Walk::SomeFailed(failed)
    }
}

/// What one `test result:` line actually proves.
#[derive(Debug, PartialEq, Eq)]
enum RunOutcome {
    /// This many tests executed and passed.
    Verified(usize),
    /// Tests executed and at least one failed.
    Failed,
    /// No test executed at all; `filtered_out` were excluded by a name filter.
    NothingRan {
        /// Tests the filter excluded — the number that made the run empty.
        filtered_out: usize,
    },
}

/// Classify one line of cargo's test output.
///
/// The whole point is the `passed == 0` arm: cargo prints `ok` for a run that
/// executed nothing, so `ok` is not evidence and only a non-zero pass count is.
fn classify_cargo_summary(line: &str) -> Option<RunOutcome> {
    let summary = Regex::new(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
        .expect("the cargo summary pattern must compile");
    let filtered =
        Regex::new(r"(\d+) filtered out").expect("the filtered-out pattern must compile");
    let caps = summary.captures(line)?;
    let passed: usize = caps[2].parse().ok()?;
    let failed: usize = caps[3].parse().ok()?;
    if &caps[1] == "FAILED" || failed > 0 {
        return Some(RunOutcome::Failed);
    }
    if passed == 0 {
        let filtered_out = filtered
            .captures(line)
            .and_then(|c| c[1].parse::<usize>().ok())
            .unwrap_or(0);
        return Some(RunOutcome::NothingRan { filtered_out });
    }
    Some(RunOutcome::Verified(passed))
}

/// A page as the static site generator writes it.
const RENDERED_PAGE: &str = "<h2>Downloads</h2>
<a href=\"https://github.com/NormB/sipnab/releases/download/v0.5.134/sipnab-x86_64.tar.gz\">x86_64</a>
<a href=\"https://github.com/NormB/sipnab/releases/download/v0.5.134/sipnab-aarch64.tar.gz\">aarch64</a>
<a href=\"https://sipnab.com/install.sh?src=web&v=1\">install.sh</a>
";

/// Escape a document the way the site generator does.
///
/// `&` first, so the entities this introduces are not escaped again.
fn escape_like_zola(doc: &str) -> String {
    doc.replace('&', "&amp;")
        .replace('/', "&#x2F;")
        .replace('\n', "&#10;")
}

/// Decode a named, decimal, or hexadecimal HTML entity body.
fn decode_entity_body(body: &str) -> Option<char> {
    match body {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let digits = body.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse::<u32>().ok()?,
            };
            char::from_u32(code)
        }
    }
}

/// Decode HTML entities in one left-to-right pass.
///
/// One pass, not a sequence of `replace` calls: replacing `&amp;` before the
/// numeric entities would turn `&amp;#x2F;` — an escaped literal — into a
/// slash that was never in the document.
fn decode_entities(doc: &str) -> String {
    /// Longest entity body this recognizes, `&` and `;` included.
    const MAX_ENTITY: usize = 12;

    let chars: Vec<char> = doc.chars().collect();
    let mut out = String::with_capacity(doc.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '&' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let end = chars[i + 1..]
            .iter()
            .position(|&c| c == ';')
            .map(|p| i + 1 + p)
            .filter(|e| e - i <= MAX_ENTITY);
        let decoded = end.and_then(|e| {
            let body: String = chars[i + 1..e].iter().collect();
            decode_entity_body(&body).map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                i = e + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

/// Every `https://` URL in a document.
fn extract_urls(doc: &str) -> BTreeSet<String> {
    let re = Regex::new(r#"https://[^\s"'<>]+"#).expect("the URL pattern must compile");
    re.find_iter(doc).map(|m| m.as_str().to_string()).collect()
}

// ── 1. the walk ─────────────────────────────────────────────────────

/// A walk over nothing and a walk over a clean collection must not agree.
///
/// This is the defect in its smallest form. `walk_reporting_only_failures` is
/// the shell loop that reported 200 for zero links: it answers `true` for both
/// inputs, so its answer carries no information about whether anything was
/// checked. Pinning that both verdicts of the refusing walk are DIFFERENT is
/// what makes an empty input impossible to mistake for a clean one.
#[test]
fn a_clean_walk_and_an_empty_walk_must_not_share_a_verdict() {
    let checked = ["https://sipnab.com/", "https://sipnab.com/docs/"];
    let broken = ["https://sipnab.com/", "ftp://sipnab.com/"];
    let empty: [&str; 0] = [];
    let reachable = |u: &str| u.starts_with("https://");

    assert_eq!(
        walk_reporting_only_failures(&empty, reachable),
        walk_reporting_only_failures(&checked, reachable),
        "the modeled bug must still reproduce: a failures-only walk has to \
         answer the same thing for an empty list and a checked-and-clean one, \
         which is why 'all links returned 200' was reported over zero links"
    );

    assert_eq!(
        walk_refusing_empty(&empty, reachable),
        Walk::NothingExamined,
        "a walk over an empty collection must refuse, not pass: reporting \
         success here is how an unchecked set gets signed off as clean"
    );
    assert_eq!(
        walk_refusing_empty(&checked, reachable),
        Walk::AllPassed(2),
        "a walk that examined two members and found no fault must say so, and \
         say how many it examined; a bare 'ok' is what hides the empty case"
    );
    assert_eq!(
        walk_refusing_empty(&broken, reachable),
        Walk::SomeFailed(1),
        "the walk must still detect a real failure; a verdict function that \
         only ever distinguishes empty from non-empty has stopped checking"
    );
    assert_ne!(
        walk_refusing_empty(&empty, reachable),
        walk_refusing_empty(&checked, reachable),
        "empty and clean must be distinguishable verdicts; if they collapse to \
         one value, every caller downstream inherits the bug"
    );
}

// ── 2. the selection ────────────────────────────────────────────────

/// Filtering by test name is not the same thing as selecting test binaries.
///
/// The corpus incident, pinned against the real tree. Corpus coverage is a
/// property of what a file READS (it names the marker), while a name filter can
/// only see what a function is CALLED. The two sets diverge in both directions
/// at once, and this asserts both: corpus binaries in which a `corpus` name
/// filter runs nothing at all — the "0 passed" prints — and binaries the name
/// filter does run that never touch a capture.
#[test]
fn filtering_by_test_name_selects_a_different_set_than_selecting_binaries() {
    let sources = test_sources();
    let corpus: BTreeSet<String> = corpus_binaries().into_iter().collect();
    assert!(
        corpus.len() >= MIN_CORPUS_BINARIES,
        "derived only {} corpus binaries from {} test file(s); the comparison \
         below would be measuring the derivation's failure, not the filter's",
        corpus.len(),
        sources.len()
    );

    let mut selected: BTreeSet<String> = BTreeSet::new();
    let mut by_name: BTreeSet<String> = BTreeSet::new();
    let mut silent: Vec<String> = Vec::new();
    let mut strangers: BTreeSet<String> = BTreeSet::new();
    assert!(
        !sources.is_empty(),
        "no test sources were read, so the walk below would examine nothing"
    );
    for (file, text) in &sources {
        let fns = test_fns(text);
        let named: Vec<String> = fns
            .iter()
            .filter(|f| f.contains("corpus"))
            .cloned()
            .collect();
        if corpus.contains(file) {
            selected.extend(fns.iter().map(|f| format!("{file}::{f}")));
            if named.is_empty() {
                silent.push(file.clone());
            }
        } else if !named.is_empty() {
            strangers.insert(file.clone());
        }
        by_name.extend(named.into_iter().map(|f| format!("{file}::{f}")));
    }

    assert!(
        selected.len() >= 40,
        "the binary selection yielded only {} test(s) across {} binaries; the \
         extractor has stopped matching and every comparison below is vacuous",
        selected.len(),
        corpus.len()
    );
    assert!(
        !by_name.is_empty(),
        "the name filter matched no test anywhere in the tree, so it cannot be \
         shown to differ from anything"
    );
    assert_ne!(
        selected, by_name,
        "if a name filter and a binary selection agreed, the shorthand \
         `cargo test corpus` would be a safe substitute for the real gate"
    );

    let missed = selected.difference(&by_name).count();
    assert!(
        missed >= 20,
        "the name filter misses only {missed} of the {} tests the binary \
         selection runs; that margin is the reason a name-filtered run is not \
         evidence about the corpus",
        selected.len()
    );
    assert!(
        !silent.is_empty(),
        "expected at least one corpus binary holding no test whose NAME says \
         corpus — those are the binaries that print `0 passed` under a name \
         filter and look identical to a clean run"
    );
    assert!(
        !strangers.is_empty(),
        "expected at least one binary a `corpus` name filter runs that never \
         reads the corpus; without one, the filter would merely be narrow \
         rather than wrong, and the run would still be about the right files"
    );
}

// ── 3. the summary line ─────────────────────────────────────────────

/// `test result: ok. 0 passed` is not a pass.
///
/// The exact sentence I misread. cargo prints `ok` when its filter excluded
/// every test in the binary, so the word `ok` says only that nothing broke —
/// which is trivially true of a run that did nothing. Only a non-zero pass
/// count is evidence, and this pins that the classifier never returns
/// `Verified` without one.
#[test]
fn a_zero_passed_summary_is_not_a_verified_run() {
    let empty_run = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; \
                     2 filtered out; finished in 0.00s";
    let cases: Vec<(&str, RunOutcome)> = vec![
        (empty_run, RunOutcome::NothingRan { filtered_out: 2 }),
        (
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 0.00s",
            RunOutcome::NothingRan { filtered_out: 0 },
        ),
        (
            "test result: ok. 64 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 41.90s",
            RunOutcome::Verified(64),
        ),
        (
            "test result: ok. 1 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; \
             finished in 0.01s",
            RunOutcome::Verified(1),
        ),
        (
            "test result: FAILED. 61 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; \
             finished in 39.02s",
            RunOutcome::Failed,
        ),
    ];

    assert!(
        cases.len() >= 5,
        "the table lost its rows; a classifier examined over {} case(s) proves \
         nothing about the shapes cargo actually prints",
        cases.len()
    );
    for (line, expected) in &cases {
        let got = classify_cargo_summary(line).unwrap_or_else(|| {
            panic!("the classifier failed to recognize a real cargo summary line: {line}")
        });
        assert_eq!(
            &got, expected,
            "misclassified a real cargo summary line: {line}"
        );
    }

    assert!(
        !matches!(
            classify_cargo_summary(empty_run),
            Some(RunOutcome::Verified(_))
        ),
        "a run that executed nothing was classified as verified; that is the \
         exact reading that nearly shipped 'corpus validated' after five \
         binaries printed `ok` over zero tests"
    );
    assert_eq!(
        classify_cargo_summary("running 0 tests"),
        None,
        "a line that is not a result summary must not be classified at all; \
         inventing a verdict for it would put a pass where there was no report"
    );
}

// ── 4. the escaped document ─────────────────────────────────────────

/// Markup must be decoded before links are extracted from it.
///
/// The second incident, reproduced: the same page yields three URLs in its
/// unescaped form and none once the generator has written `/` as `&#x2F;`, and
/// the grep that found none reported no failures. Asserting the decoded
/// extraction matches the plain one — as a SET, not a count — pins that
/// decoding is what recovers the links rather than something that merely
/// changes how many are found.
#[test]
fn escaped_markup_must_be_decoded_before_links_are_extracted() {
    let plain = extract_urls(RENDERED_PAGE);
    assert!(
        plain.len() >= 3,
        "the fixture page yielded only {} URL(s); with too few, an extraction \
         that silently found nothing would still look like a match",
        plain.len()
    );

    let escaped = escape_like_zola(RENDERED_PAGE);
    assert!(
        escaped.contains("&#x2F;") && escaped.contains("&#10;"),
        "the escaper did not produce the entities the real generator emits, so \
         this test is not reproducing the page that broke the extraction"
    );

    let straight_from_the_page = extract_urls(&escaped);
    assert!(
        straight_from_the_page.is_empty(),
        "extraction over the escaped page found {} URL(s); the incident being \
         pinned is that it finds NONE, and a loop over that empty set then \
         reported every link healthy",
        straight_from_the_page.len()
    );

    assert_eq!(
        decode_entities(&escaped),
        RENDERED_PAGE,
        "decoding must restore the document exactly; a decoder that drops or \
         mangles text would change which links are found for a second reason"
    );
    let decoded = extract_urls(&decode_entities(&escaped));
    assert_eq!(
        decoded, plain,
        "the decoded page must yield the same URL set as the unescaped one; \
         anything less means the check runs over a subset nobody chose"
    );
}

// ── 5. the derivation's floor ───────────────────────────────────────

/// The corpus-binary derivation finds the binaries that exist.
///
/// Every count in this file rests on this walk. A derivation that broke — a
/// renamed marker, a path that no longer resolves, a filter that excludes
/// everything — would return an empty list, and each comparison built on it
/// would then compare nothing to nothing and pass. The floor makes that
/// failure loud. The upper bound matters just as much: a derivation matching
/// every file would clear the floor while selecting nothing in particular.
#[test]
fn the_corpus_binary_derivation_finds_the_binaries_that_exist() {
    let binaries = corpus_binaries();
    let total = test_sources().len();
    assert!(
        binaries.len() >= MIN_CORPUS_BINARIES,
        "derived {} corpus binaries from {total} test file(s), below the floor \
         of {MIN_CORPUS_BINARIES} (measured 15 on 2026-08-30); the walk or the \
         marker `{CORPUS_MARKER}` has changed and every count here is now \
         about the scanner, not the tree",
        binaries.len()
    );
    assert!(
        binaries.len() * 2 < total,
        "the derivation selected {} of {total} test files, which is not a \
         selection; a predicate matching nearly everything passes the floor \
         while telling nobody which binaries read a capture",
        binaries.len()
    );
    let missing: Vec<&String> = binaries
        .iter()
        .filter(|b| !repo().join("tests").join(b).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "the derivation named files that are not on disk: {missing:?}; a list \
         of binaries that cannot be run is not a selection anyone can act on"
    );
}

// ── 6. this file, turned on itself ──────────────────────────────────

/// Every loop in this file sits next to a check that it walked something.
///
/// Self-application, and not decoration: a gate against vacuous success that
/// is itself vacuous is the purest form of the bug. Each `for` loop here must
/// have, within [`GUARD_WINDOW`] lines, either an assertion about the size of
/// what it walks or an explicit empty-case return — so no loop in this file can
/// quietly iterate zero times and let the assertions after it pass by never
/// running. The scanner refuses to run over a file in which it finds no loops,
/// for the same reason.
#[test]
fn every_loop_in_this_file_is_bounded_by_a_non_emptiness_check() {
    let src = include_str!("vacuous_success_test.rs");
    let lines: Vec<&str> = src.lines().collect();
    let loop_re = Regex::new(FOR_LOOP).expect("the loop pattern must compile");
    let guard_re = Regex::new(EMPTINESS_GUARD).expect("the guard pattern must compile");

    let loops: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| loop_re.is_match(l))
        .map(|(i, _)| i)
        .collect();
    assert!(
        loops.len() >= 3,
        "the loop scanner found {} loop(s) in this file; below that it is not \
         reading its own source, and this test would pass by examining nothing \
         — which is the defect it exists to catch",
        loops.len()
    );

    let mut unguarded: Vec<usize> = Vec::new();
    for index in &loops {
        let low = index.saturating_sub(GUARD_WINDOW);
        let high = (index + GUARD_WINDOW).min(lines.len().saturating_sub(1));
        let window = lines[low..=high].join("\n");
        if !guard_re.is_match(&window) {
            unguarded.push(index + 1);
        }
    }
    assert!(
        unguarded.is_empty(),
        "loops on line(s) {unguarded:?} of this file walk a collection with no \
         nearby check that it holds anything; each one can iterate zero times \
         and report success over nothing"
    );
}
