// SPDX-License-Identifier: MIT OR Apache-2.0

//! US spellings, enforced by a RULE rather than by a list of known words.
//!
//! `the_tree_spells_in_us_english` has guarded this since 0.5.105, and it
//! guards a list: about seventy words somebody thought of. On 2026-09-01 it
//! caught `recognize` in a comment written minutes earlier — which is the
//! system working, and also the whole problem. It can only ever catch a word
//! already on the list, so every new British spelling is free until someone
//! notices it and adds it. Nobody notices; that is why the list grows one
//! embarrassment at a time.
//!
//! Measured the day this file was written: the tree held **67 distinct
//! British forms across 95 files** that the list had never named —
//! `containerized`, `synthesized`, `unrecognized`, `sanitized`,
//! `materializing`, `pseudonymizing`, `uninitialized`. Every one of them
//! passed every gate this repository has, for as long as it had been there.
//!
//! So this file enforces the morphology instead. English `-ise/-isation/
//! -isable` and `-yse` are British where US English writes `-ize/-ization/
//! -izable` and `-yze`, with a bounded set of exceptions — `precise`,
//! `otherwise`, `exercise` and their kin, where the `ise` is not a suffix at
//! all. Naming the exceptions is tractable. Naming every British word is not.
//!
//! The British fixtures below are BUILT rather than written, so this file
//! contains no British spelling and needs no exemption from its own gate. An
//! exemption is a permanent hole, and the last thing a spelling gate should
//! carry is a file where misspellings are allowed.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

/// Words where `ise`/`yse` is not the British suffix.
///
/// Each is a word this tree actually uses, checked by
/// [`every_exception_is_a_word_the_tree_actually_uses`]. An exception nobody
/// needs is a hole cut for nothing, and it is how an allowlist quietly becomes
/// the place British spellings go to be permitted.
const NOT_A_SUFFIX: &[&str] = &[
    "advertise",
    "advertised",
    "advertises",
    "advertising",
    "unadvertised",
    "asadvertised",
    "advise",
    "advised",
    "advises",
    "advising",
    "advisable",
    "compromise",
    "compromised",
    "compromises",
    "concise",
    "imprecise",
    "precise",
    "devise",
    "ndevise",
    "disguise",
    "disguises",
    "enterprise",
    "exercise",
    "exercised",
    "exercises",
    "exercising",
    "exercisable",
    "unexercised",
    "expertise",
    "likewise",
    "otherwise",
    "pairwise",
    "premise",
    "promise",
    "promised",
    "promises",
    "promising",
    "idxpromise",
    "surprise",
    "surprised",
    "surprises",
    "surprising",
    "supervise",
    "unsupervised",
    "improvises",
    "improvising",
    "revised",
    "madvise",
    "assertraises",
    "noise",
    // Inflections, not just base forms. `raise` was exempt and `raising` was
    // not, so the rule reported `raising -> raizing`: a gate that invents a
    // word teaches the reader to distrust it, and one distrusted gate is how
    // every later hit gets waved through.
    "raise",
    "raised",
    "raises",
    "raising",
    "rise",
    "rises",
    "rising",
    "arise",
    "arises",
    "arising",
    // Nothing to do with `-ise`: d-i-s-a-b-l-e simply ends in those letters,
    // and it appears on almost every command line this project documents.
    "disable",
    "wise",
];

/// Paths the scan does not read, each with the reason it cannot.
const NOT_SCANNED: &[(&str, &str)] = &[
    (
        "target/",
        "build output, not authored text; it also holds vendored crates whose \
         spellings are their authors' business",
    ),
    (
        "LICENSES/",
        "license texts are quoted verbatim and may not be edited, whatever \
         they spell",
    ),
    (
        "website/static/",
        "rendered and vendored assets, including binary demo captures",
    ),
    (
        "THIRD-PARTY-NOTICES.md",
        "generated from other projects' license text, which is theirs",
    ),
    (
        "CHANGELOG.md",
        "a record of what was released, including entries written before this \
         rule existed; rewriting history to match a present-day gate would \
         make the record disagree with the releases it describes",
    ),
    (
        "e2e/package-lock.json",
        "a generated lockfile of integrity hashes, not authored text; the \
         same reason `.lock` files are skipped, and base64 produces \
         convincing-looking fragments by the thousand",
    ),
    (
        "tests/docs_drift_test.rs",
        "it LISTS the words it forbids, so it necessarily contains all of \
         them; a gate cannot be its own violation. This file avoids needing \
         the same exemption by building its British fixtures at runtime",
    ),
    (
        "tests/schemas/vcon-store-openapi.json",
        "vendored from vcon.store, kept byte-for-byte so the divergence tests \
         measure a real second consumer rather than an edited copy of one",
    ),
];

/// Published names that happen to carry a British spelling.
///
/// The `unanalyzed_*` family — spelled the British way — are keys in
/// `GET /v1/stats` and in MCP's `capture_status`. The spelling is wrong and it
/// is also a WIRE CONTRACT: every consumer reads those keys by name, so
/// correcting them is a breaking change with a deprecation window, not a
/// sweep. Exempted as whole TOKENS rather than as the word itself, which stays
/// banned in prose — the hole is the size of the contract and no larger.
///
/// Built rather than written, for the same reason the fixtures are: a literal
/// here would make this file need an exemption from its own gate.
fn wire_identifiers() -> Vec<String> {
    let stem = british_form("unanal", "ysed");
    [
        "_sip_messages",
        "_busiest_ports",
        "_websocket_messages",
        "_websocket_ports",
        // The docs write the family with a `*` wildcard; the tokenizer sees
        // the stem with its trailing underscore.
        "_",
    ]
    .iter()
    .map(|tail| format!("{stem}{tail}"))
    .collect()
}

/// The suffix pairs: what British writes, and what US writes instead.
const SUFFIXES: &[(&str, &str)] = &[
    ("isation", "ization"),
    ("isable", "izable"),
    ("ising", "izing"),
    ("ised", "ized"),
    ("ises", "izes"),
    ("ise", "ize"),
    ("ysing", "yzing"),
    ("ysed", "yzed"),
    ("yses", "yzes"),
    ("yse", "yze"),
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every British-suffixed word in `text`, lowercased.
///
/// THE rule. Both the tree scan and the fixture tests call this, so there is
/// one definition to keep true rather than two that agree until they do not.
fn british_words(text: &str) -> BTreeSet<String> {
    let exceptions: BTreeSet<&str> = NOT_A_SUFFIX.iter().copied().collect();
    let wire = wire_identifiers();
    let mut out = BTreeSet::new();
    // Tokens first, then words. A British spelling hides inside a snake_case
    // identifier -- a published key, a test name -- where a word-boundary match never fires, because `_` is a
    // word character. Splitting on the underscore is what found ten of these
    // after a regex sweep reported the tree clean.
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if wire.iter().any(|w| w == token) {
            continue;
        }
        for run in token.split(|c: char| !c.is_ascii_alphabetic()) {
            for raw in split_camel(run) {
                if raw.len() < 4 {
                    continue;
                }
                let word = raw.to_ascii_lowercase();
                if exceptions.contains(word.as_str()) {
                    continue;
                }
                // The stem has to be able to be a word. `pyse` is four characters of
                // a base64 hash in a lockfile, not a British spelling, and a gate
                // that reports one teaches a reader to skim its output.
                if SUFFIXES
                    .iter()
                    .any(|(brit, _)| word.ends_with(brit) && word.len() >= brit.len() + 3)
                {
                    out.insert(word);
                }
            }
        }
    }
    out
}

/// A camelCase run split into its words.
///
/// `serializesWithFields` is three words with no punctuation between them, so
/// a tokenizer that splits only on punctuation reads it as one word ending in
/// `elds` and passes it. Split before an upper-case letter that follows a
/// lower-case one; `HTTPServer` has no such position and stays whole, which is
/// what keeps acronyms from becoming a stream of one-letter words.
fn split_camel(run: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = run.as_bytes();
    let mut start = 0;
    for i in 1..bytes.len() {
        if bytes[i].is_ascii_uppercase() && bytes[i - 1].is_ascii_lowercase() {
            out.push(&run[start..i]);
            start = i;
        }
    }
    if start < run.len() {
        out.push(&run[start..]);
    }
    out
}

/// The US spelling of a word this rule flagged.
fn us_form(word: &str) -> String {
    for (brit, us) in SUFFIXES {
        if let Some(stem) = word.strip_suffix(brit) {
            return format!("{stem}{us}");
        }
    }
    word.to_string()
}

/// A British word assembled at runtime, so no British spelling is written
/// literally in this file and it needs no exemption from its own gate.
fn british_form(stem: &str, suffix: &str) -> String {
    format!("{stem}{suffix}")
}

/// Every git-tracked file the scan reads.
fn scanned_files() -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter(|f| {
            !NOT_SCANNED.iter().any(|(p, _)| {
                if p.ends_with('/') {
                    f.starts_with(p)
                } else {
                    *f == *p
                }
            }) && !f.ends_with(".lock")
        })
        .map(str::to_string)
        .collect()
}

// ── 1. the rule, against the tree ───────────────────────────────────────

/// No tracked file spells a word the British way.
///
/// The gate itself. It names the US spelling for each hit, so acting on a
/// failure needs no dictionary.
#[test]
fn the_tree_uses_us_spellings() {
    let mut hits: Vec<String> = Vec::new();
    let mut read = 0usize;
    for f in scanned_files() {
        let Ok(text) = std::fs::read_to_string(repo().join(&f)) else {
            continue; // binary, or not UTF-8: nothing to spell
        };
        read += 1;
        for w in british_words(&text) {
            hits.push(format!("  {f}: \"{w}\" -> \"{}\"", us_form(&w)));
        }
    }
    assert!(
        read >= 200,
        "only {read} file(s) read; the walk is not reaching the tree and a \
         pass would mean nothing"
    );
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "{} British spelling(s). This tree is US English:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

// ── 2. the rule catches what no list names ──────────────────────────────

/// A British word nobody listed is still caught.
///
/// The reason this file exists. Every stem here is absent from the fixed list
/// in `docs_drift_test.rs`, and several were sitting in the tree unnoticed
/// until the day this was written.
#[test]
fn a_british_word_no_list_names_is_still_caught() {
    for (stem, suffix) in [
        ("container", "ised"),
        ("synthes", "ised"),
        ("sanit", "ised"),
        ("material", "ising"),
        ("pseudonym", "isation"),
        ("random", "ise"),
        ("real", "isable"),
        ("catal", "ysed"),
        ("paral", "yses"),
    ] {
        let word = british_form(stem, suffix);
        let found = british_words(&format!("a sentence with {word} in it"));
        assert!(
            found.contains(&word),
            "{word} is a British spelling and the rule did not catch it; a \
             gate that only knows words somebody listed is the gate this file \
             replaces"
        );
    }
}

/// The US spelling of each of those passes.
///
/// The paired half. Without it, "catch everything ending in a vowel" would
/// satisfy the test above.
#[test]
fn the_us_spelling_of_each_is_accepted() {
    for word in [
        "containerized",
        "synthesized",
        "sanitized",
        "materializing",
        "pseudonymization",
        "randomize",
        "realizable",
        "catalyzed",
        "paralyzes",
    ] {
        let found = british_words(&format!("a sentence with {word} in it"));
        assert!(
            found.is_empty(),
            "{word} is correct US English and the rule flagged it: {found:?}"
        );
    }
}

/// Words where `ise` is not a suffix are left alone.
///
/// The false-positive half. A gate that cries wolf gets switched off, and
/// these are the words that would make it cry.
#[test]
fn words_that_merely_end_in_ise_are_not_flagged() {
    let text = "otherwise the precise exercise of an enterprise promise may \
                surprise; we advise you devise a concise premise rather than \
                compromise, and disable whatever noise arises as usage rises";
    let found = british_words(text);
    assert!(
        found.is_empty(),
        "these are US English and the rule flagged them: {found:?}"
    );

    // Hash fragments are not words. The stem floor exists for these, and it
    // must not be wide enough to swallow a real one.
    for noise in ["pyse", "abise", "xyse"] {
        assert!(
            british_words(noise).is_empty(),
            "{noise} is a fragment, not a spelling; reporting it teaches a \
             reader to skim this gate's output"
        );
    }
    for (stem, suffix) in [("token", "ise"), ("catal", "yse"), ("normal", "ise")] {
        let real = british_form(stem, suffix);
        assert!(
            !british_words(&real).is_empty(),
            "{real} is a real British spelling and the stem floor swallowed \
             it; the floor must reject fragments, not words"
        );
    }
}

/// The correction it offers is the right word.
///
/// A gate that reports a hit but names the wrong replacement teaches the
/// wrong spelling, and it is the message, not the rule, that a reader acts on.
#[test]
fn the_reported_us_spelling_is_the_right_one() {
    for (stem, suffix, want) in [
        ("normal", "isation", "normalization"),
        ("optim", "ised", "optimized"),
        ("token", "ise", "tokenize"),
        ("general", "isable", "generalizable"),
        ("anal", "ysed", "analyzed"),
        ("anal", "yse", "analyze"),
    ] {
        let word = british_form(stem, suffix);
        assert_eq!(
            us_form(&word),
            want,
            "the rule would tell a reader to write the wrong word"
        );
    }
}

// ── 3. the rule subsumes the list it supplements ────────────────────────

/// Every suffixed word on the old fixed list is caught by this rule.
///
/// The two gates must not disagree. `docs_drift_test.rs` keeps a list that
/// also covers words this rule cannot reach — the `-our`, `-ogue` and
/// doubled-`-lled` classes are not suffix cases — so both stay; but for the
/// suffix class the rule has to be a superset, or a word could be dropped from
/// the list in good faith and become legal again.
#[test]
fn the_rule_subsumes_every_suffixed_word_on_the_fixed_list() {
    let gate = std::fs::read_to_string(repo().join("tests/docs_drift_test.rs"))
        .expect("read tests/docs_drift_test.rs");
    let start = gate.find("const BRITISH:").expect(
        "docs_drift_test.rs no longer declares BRITISH; this check is \
                 reading the wrong file",
    );
    let list = &gate[start..start + gate[start..].find("];").expect("unterminated BRITISH list")];

    let mut checked = 0;
    for raw in list.split('"') {
        let word = raw.trim().to_ascii_lowercase();
        if word.len() < 4 || !word.chars().all(|c| c.is_ascii_lowercase()) {
            continue;
        }
        if !SUFFIXES.iter().any(|(brit, _)| word.ends_with(brit)) {
            continue; // the -our and -ogue classes: not a suffix case
        }
        checked += 1;
        assert!(
            !british_words(&word).is_empty(),
            "{word} is on the fixed list and this rule does not catch it, so \
             deleting it from that list would make it legal again"
        );
    }
    assert!(
        checked >= 10,
        "only {checked} suffixed word(s) found on the fixed list; this check \
         is not reading it and proves nothing"
    );
}

// ── 4. the exceptions and exclusions are honest ─────────────────────────

/// Every exception is a word the tree actually uses.
///
/// An exception matching nothing is either a typo or a hole cut in advance.
/// Both are how an allowlist stops describing the tree and starts permitting
/// whatever anyone adds to it.
#[test]
fn every_exception_is_a_word_the_tree_actually_uses() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for f in scanned_files() {
        let Ok(text) = std::fs::read_to_string(repo().join(&f)) else {
            continue;
        };
        for raw in text.split(|c: char| !c.is_ascii_alphabetic()) {
            if raw.len() >= 4 {
                seen.insert(raw.to_ascii_lowercase());
            }
        }
    }
    let unused: Vec<&&str> = NOT_A_SUFFIX
        .iter()
        .filter(|w| w.len() >= 4 && !seen.contains(**w))
        .collect();
    assert!(
        unused.is_empty(),
        "these exceptions match nothing in the tree, so they exempt words \
         nobody writes -- remove them rather than leave the hole: {unused:?}"
    );
}

/// Every excluded path exists, and says why it cannot be read.
///
/// The other direction. An exclusion that outlives its path silently widens,
/// and "it was already there" is not a reason.
#[test]
fn every_exclusion_names_a_path_that_exists_and_says_why() {
    for (path, reason) in NOT_SCANNED {
        let p = repo().join(path.trim_end_matches('/'));
        assert!(
            p.exists(),
            "{path} is excluded from the spelling scan and does not exist; \
             remove the entry"
        );
        assert!(
            reason.len() > 40,
            "{path}'s exclusion must say why the file cannot be read or \
             edited, not that it was inconvenient"
        );
    }
}

/// Every wire exemption is a name this project actually publishes.
///
/// The exemption exists because renaming a published key breaks consumers. An
/// entry that is NOT published has no such excuse -- it would just be a
/// British spelling somebody wanted to keep, and this is exactly where such a
/// thing would be parked.
#[test]
fn every_wire_exemption_is_a_published_name() {
    let published = [
        "src/output/api.rs",
        "src/mcp/server.rs",
        "docs/api.md",
        "docs/mcp-tools.md",
    ]
    .iter()
    .filter_map(|f| std::fs::read_to_string(repo().join(f)).ok())
    .collect::<Vec<_>>()
    .join("\n");

    assert!(
        !published.is_empty(),
        "none of the published surfaces could be read; this check proves nothing"
    );
    for name in &wire_identifiers() {
        assert!(
            published.contains(name.as_str()),
            "{name} is exempted as a wire identifier and appears on no \
             published surface. If nothing publishes it, it is not a contract \
             and it must simply be spelled correctly."
        );
    }
}

// ── 5. the scan is looking at what it claims to ─────────────────────────

/// The scan reaches every kind of text this project ships.
///
/// The spelling that reaches a user is the one on the website and in the
/// docs, not the one in a comment. A scan that quietly covered only `.rs`
/// would leave every user-visible surface unguarded while passing.
#[test]
fn the_scan_reaches_every_kind_of_text_the_project_ships() {
    let files = scanned_files();
    for ext in ["rs", "md", "py", "toml", "html", "js", "yml", "sh"] {
        let n = files
            .iter()
            .filter(|f| f.ends_with(&format!(".{ext}")))
            .count();
        assert!(
            n > 0,
            "the scan reads no .{ext} file, so British spellings there are \
             invisible to it"
        );
    }
    assert!(
        files.len() >= 200,
        "only {} file(s) in the scan; the listing is wrong",
        files.len()
    );
}

// ── 6. the blind spot that let fourteen through ─────────────────────────
//
// A regex sweep with `\b` word boundaries reported this tree clean while
// fourteen British spellings sat inside snake_case identifiers -- `_` is a
// word character, so `\b` never fires before the `_` that follows. Every
// test below is that class: a spelling hidden by the SHAPE of the token it
// sits in rather than by the letters in it.

/// snake_case hides a British spelling from a word-boundary match.
///
/// The exact miss. `etag_serializes_with_named_fields` is a real test name
/// this tree carried, invisible to the sweep that declared it clean.
#[test]
fn a_british_spelling_inside_a_snake_case_identifier_is_caught() {
    for (stem, suffix, tail) in [
        ("etag_serial", "ises", "_with_named_fields"),
        ("scrape_initial", "ises", "_closed_label_sets"),
        ("a_newline_is_neutral", "ised", "_here"),
        ("unanal", "ysed", "_sip_count"),
    ] {
        let ident = format!("{}{tail}", british_form(stem, suffix));
        let found = british_words(&format!("fn {ident}() {{}}"));
        assert!(
            !found.is_empty(),
            "{ident} carries a British spelling and the rule missed it; a \
             word-boundary match misses exactly this, and it is how fourteen \
             of them survived a sweep that reported the tree clean"
        );
    }
}

/// camelCase hides one too.
///
/// The same defect one shape over. Nothing separates the words, so a
/// tokenizer that only splits on punctuation reads `serializesWithFields` as
/// one word ending in `elds` and passes it.
#[test]
fn a_british_spelling_inside_a_camel_case_identifier_is_caught() {
    for (stem, suffix, tail) in [
        ("serial", "ises", "WithFields"),
        ("normal", "ised", "Timing"),
        ("anal", "ysed", "Messages"),
    ] {
        let ident = format!("{}{tail}", british_form(stem, suffix));
        let found = british_words(&format!("let {ident} = 1;"));
        assert!(
            !found.is_empty(),
            "{ident} carries a British spelling and the rule missed it: \
             camelCase separates words with case, not punctuation"
        );
    }
}

/// SCREAMING_SNAKE is the same token shape, upper case.
#[test]
fn a_british_spelling_in_a_screaming_snake_constant_is_caught() {
    let ident = format!("{}_LIMIT", british_form("NORMAL", "ISED"));
    let found = british_words(&format!("const {ident}: usize = 4;"));
    assert!(
        !found.is_empty(),
        "{ident} carries a British spelling and the rule missed it"
    );
}

/// Hyphens and path separators are word boundaries too.
///
/// A doc filename or a URL fragment reaches a reader exactly as prose does.
#[test]
fn a_british_spelling_in_a_hyphenated_or_path_segment_is_caught() {
    for text in [
        format!(
            "see docs/design/{}-timing.md",
            british_form("normal", "ised")
        ),
        format!("the well-{} form", british_form("recogn", "ised")),
        format!(
            "https://example.test/{}/index.html",
            british_form("catal", "ysed")
        ),
    ] {
        let found = british_words(&text);
        assert!(
            !found.is_empty(),
            "a British spelling in {text:?} was missed; a hyphen and a slash \
             separate words as surely as a space does"
        );
    }
}

/// A wire exemption covers the WHOLE token and nothing longer.
///
/// A published key is a contract. That key with `_v2` appended is a new
/// name somebody just invented, and it must be spelled correctly. A
/// substring match would exempt every future field that happens to start
/// with an old one.
#[test]
fn a_wire_exemption_matches_only_the_whole_token() {
    let invented = format!("{}_v2", wire_identifiers()[0]);
    let found = british_words(&format!("\"{invented}\": 3"));
    assert!(
        !found.is_empty(),
        "{invented} is not the exempted contract, it is a new name that \
         inherited its spelling; the exemption must not stretch to cover it"
    );
}

/// A wire exemption does not permit the bare word in prose.
///
/// The hole is the size of the contract. A published key may keep its
/// spelling because consumers read that key by name; the sentence
/// explaining it has no such excuse.
#[test]
fn a_wire_exemption_does_not_permit_the_bare_word_in_prose() {
    let word = british_form("unanal", "ysed");
    let found = british_words(&format!("how many messages went {word} before analysis"));
    assert!(
        found.contains(&word),
        "the word {word} is exempt only as part of a published key, never as \
         prose; a whole-token exemption that leaked into the vocabulary would \
         legalize the very spelling it was cut around"
    );
}

/// The tracked PATHS are spelled correctly, not only their contents.
///
/// A file called `normalized-timing.md` ships its spelling in every link that
/// points at it, and a scan that reads only file CONTENTS never sees the name.
#[test]
fn no_tracked_path_is_spelled_the_british_way() {
    let mut hits = Vec::new();
    let files = scanned_files();
    for f in &files {
        for w in british_words(f) {
            hits.push(format!("  {f}: \"{w}\" -> \"{}\"", us_form(&w)));
        }
    }
    assert!(
        files.len() >= 200,
        "only {} path(s) examined; the listing is wrong",
        files.len()
    );
    assert!(
        hits.is_empty(),
        "these tracked paths are spelled the British way, and every link to \
         them carries it:\n{}",
        hits.join("\n")
    );
}

/// The two lists do not overlap.
///
/// A token in both is a contradiction: one list says the word is fine
/// anywhere, the other says it is tolerated only as a published key. Whichever
/// is read first wins, and which that is has nothing to do with intent.
#[test]
fn the_exception_and_wire_lists_do_not_overlap() {
    let exceptions: BTreeSet<&str> = NOT_A_SUFFIX.iter().copied().collect();
    let wire = wire_identifiers();
    let both: Vec<&String> = wire
        .iter()
        .filter(|w| exceptions.contains(w.as_str()))
        .collect();
    assert!(
        both.is_empty(),
        "{both:?} appear on both lists; a word cannot be both always-fine and \
         tolerated-only-as-a-key"
    );
}

/// No fixture above is passing because the word was exempt.
///
/// Anti-vacuity for this whole section. Every test here asserts that a made-up
/// identifier IS caught; if its stem had drifted onto an exemption list, the
/// assertion would fail loudly rather than silently -- but the fixture WORDS
/// must also not be exempt, or a future exemption would quietly hollow them.
#[test]
fn no_fixture_word_in_these_tests_is_exempt() {
    let exceptions: BTreeSet<&str> = NOT_A_SUFFIX.iter().copied().collect();
    let wire = wire_identifiers();
    for (stem, suffix) in [
        ("serial", "ises"),
        ("initial", "ises"),
        ("neutral", "ised"),
        ("unanal", "ysed"),
        ("normal", "ised"),
        ("recogn", "ised"),
        ("catal", "ysed"),
    ] {
        let word = british_form(stem, suffix);
        assert!(
            !exceptions.contains(word.as_str()),
            "{word} is on the exception list, so every test asserting it is \
             caught proves nothing"
        );
        assert!(
            !wire.contains(&word),
            "{word} is exempted as a wire identifier, which would hollow the \
             fixtures above"
        );
    }
}

/// Case does not hide a spelling either.
///
/// A sentence-initial `Normalized` and a shouted `NORMALIZED` are the same
/// mistake as the lower-case one, and a rule that compared literally would
/// catch one in three.
#[test]
fn capitalization_does_not_hide_a_british_spelling() {
    let lower = british_form("normal", "ised");
    let title = format!("{}{}", lower[..1].to_uppercase(), &lower[1..]);
    let upper = lower.to_uppercase();
    for variant in [lower.clone(), title, upper] {
        let found = british_words(&format!("{variant} timing is required"));
        assert!(
            found.contains(&lower),
            "{variant} was not caught; the rule must compare case-insensitively"
        );
    }
}

// ── 7. debts from the misses this file's own work produced ──────────────
//
// Three separate things went wrong while building the rule above, and each is
// worth a test rather than a memory:
//
//  * the scan reported 20/20 green while this file was UNTRACKED, so
//    `git ls-files` never handed it over and the gate never read itself;
//  * the first version reported `disable`, `raised` and `rising`, because the
//    exceptions listed base forms and not inflections;
//  * it reported `pyse`, four characters of a base64 hash in a lockfile.
//
// A gate that cries wolf gets switched off, and a gate that cannot see its own
// subject looks exactly like a clean tree.

/// The scan reads THIS file.
///
/// It reported twenty passing tests while this file was untracked and
/// therefore invisible to `git ls-files`. Staging it produced thirteen hits in
/// prose I had just written, including a helper whose own name was British.
/// A gate that exempts the file defining it proves the least where it matters
/// most.
#[test]
fn the_spelling_scan_reads_this_very_file() {
    let me = "tests/us_spelling_test.rs";
    assert!(
        scanned_files().iter().any(|f| f == me),
        "{me} is not in the scan. Either it is untracked -- in which case the \
         gate is passing on a file nobody checked -- or it has been excluded, \
         which a spelling gate may not do to its own definition."
    );
}

/// No test file is invisible to the scan.
///
/// The general form. A test file is where a British spelling is most likely to
/// be written and least likely to be read again, and a new one is invisible
/// until it is staged.
#[test]
fn every_tracked_test_file_is_reachable_by_the_scan() {
    let scanned = scanned_files();
    let out = Command::new("git")
        .args(["ls-files", "tests/"])
        .current_dir(repo())
        .output()
        .expect("git ls-files tests/");
    let listed: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .filter(|f| f.ends_with(".rs"))
        .map(str::to_string)
        .collect();

    assert!(
        listed.len() >= 40,
        "only {} test file(s) tracked; the listing is wrong",
        listed.len()
    );
    // Scanned, or excluded with a stated reason. Neither is the failure: a
    // file that is simply invisible, which is what an unstaged one is.
    let excluded: BTreeSet<&str> = NOT_SCANNED.iter().map(|(p, _)| *p).collect();
    let missed: Vec<&String> = listed
        .iter()
        .filter(|f| !scanned.iter().any(|s| s == *f))
        .filter(|f| !excluded.contains(f.as_str()))
        .collect();
    assert!(
        missed.is_empty(),
        "these tracked test files are neither scanned nor on the exclusion \
         list, so nothing checks their spelling and nothing says why: \
         {missed:?}"
    );
}

/// The scan reads what git tracks, and says so.
///
/// The limitation behind the hollow green, written down where it will be read.
/// An unstaged file is invisible; that is a property of the input, not a bug,
/// and the fix is to stage before believing a pass.
#[test]
fn the_scan_reads_what_git_tracks_and_nothing_else() {
    let scanned = scanned_files();
    assert!(
        !scanned.iter().any(|f| f.starts_with("target/")),
        "the scan is reading build output, so it is not reading git's listing"
    );
    assert!(
        scanned.iter().all(|f| repo().join(f).exists()),
        "the scan lists a path that is not on disk"
    );
    assert!(
        !scanned.iter().any(|f| f == "no/such/file.rs"),
        "the scan invented a path"
    );
}

/// A fenced code block is prose too.
///
/// Documentation examples are copied by readers verbatim. A British spelling
/// inside a fence reaches them as surely as one in a sentence, and reaches
/// their shell as a command that may not exist.
#[test]
fn a_british_spelling_in_a_code_fence_is_caught() {
    let word = british_form("normal", "ise");
    let fence = format!("```sh\nsipnab --{word}-timing\n```");
    assert!(
        !british_words(&fence).is_empty(),
        "a British spelling inside a code fence was missed; a reader copies \
         that line"
    );
}

/// A string literal is shipped text.
///
/// What a program PRINTS is the most user-visible prose it has, and it sits in
/// quotes where a prose-only reading would skip it.
#[test]
fn a_british_spelling_in_a_string_literal_is_caught() {
    let word = british_form("recogn", "ised");
    let src = format!("    return Err(format!(\"the header was not {word}\"));");
    assert!(
        !british_words(&src).is_empty(),
        "a British spelling inside a string literal was missed, and a string \
         literal is what the user actually reads"
    );
}

/// Digits do not hide a spelling.
///
/// A British verb with a digit stuck to either end is one token to a tokenizer
/// that splits only on punctuation, and neither form ends in a suffix as a
/// whole.
#[test]
fn a_british_spelling_adjacent_to_digits_is_caught() {
    let word = british_form("normal", "ise");
    for ident in [
        format!("{word}2"),
        format!("sip2{word}"),
        format!("v1_{word}"),
    ] {
        assert!(
            !british_words(&ident).is_empty(),
            "{ident} carries a British spelling and the rule missed it"
        );
    }
}

/// An acronym run is not shredded into fragments.
///
/// The camelCase split fires on a lower-to-upper transition only. Splitting on
/// every capital would turn `HTTPServer` into single letters and `SIPMessage`
/// into noise, and a rule that manufactures fragments manufactures hits.
#[test]
fn an_acronym_run_is_not_split_into_fragments() {
    for ident in [
        "HTTPServer",
        "SIPMessageParser",
        "RTPStreamID",
        "TLSKeylogSource",
    ] {
        let found = british_words(ident);
        assert!(
            found.is_empty(),
            "{ident} is an ordinary identifier and the rule reported {found:?}"
        );
    }
}

/// Hash and hex fragments are never reported.
///
/// `pyse` came from a base64 integrity hash in a lockfile. Base64 produces
/// convincing-looking fragments by the thousand, and one bogus hit teaches a
/// reader to skim every real one after it.
#[test]
fn a_hash_or_hex_fragment_is_never_reported() {
    // Built, not written: a literal here would be a British-suffixed token in
    // a file that may not contain one.
    let long_stem = format!("deadbeef{}", british_form("", "yse"));
    for fragment in [
        "sha512-Pyse".to_string(),
        "a3f9dise".to_string(),
        long_stem,
        "c2lnbmFsbGluZyse".to_string(),
    ] {
        let found = british_words(&fragment);
        for w in &found {
            assert!(
                w.len() >= 7,
                "{fragment} produced the fragment {w:?}, which is hash noise \
                 rather than a word"
            );
        }
    }
    assert!(
        british_words("sha512-Pyse").is_empty(),
        "a four-character hash fragment was reported as a spelling"
    );
}

/// Every suffix pair changes the spelling.
///
/// A pair mapping a suffix to itself would report a hit and offer the same
/// word back, which reads as a gate that is broken rather than a word that is
/// wrong.
#[test]
fn every_suffix_pair_maps_to_a_different_spelling() {
    for (brit, us) in SUFFIXES {
        assert_ne!(
            brit, us,
            "the suffix pair {brit:?} maps to itself; the correction it offers \
             would be the word it rejected"
        );
        assert_eq!(
            brit.len(),
            us.len(),
            "{brit} and {us} differ in length; every pair in this table is one \
             letter substituted, and a length change means a typo in the table"
        );
    }
}

/// Every suffix pair actually fires.
///
/// A pair nothing can trigger is a line of table that looks like coverage. The
/// longest suffixes are the ones at risk: `isation` is only reachable if the
/// table is tried longest-first, and a reordering would silently shadow it.
#[test]
fn every_suffix_pair_actually_fires() {
    for (brit, us) in SUFFIXES {
        let word = format!("normal{brit}");
        let found = british_words(&word);
        assert!(
            found.contains(&word),
            "the suffix {brit:?} never fires; it is a line of table that looks \
             like coverage"
        );
        assert_eq!(
            us_form(&word),
            format!("normal{us}"),
            "the suffix {brit:?} is shadowed by an earlier entry, so the \
             correction it offers comes from the wrong pair"
        );
    }
}
