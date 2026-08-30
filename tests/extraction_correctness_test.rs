// SPDX-License-Identifier: MIT OR Apache-2.0

//! An ad-hoc extractor's output is a claim about the extractor, not the tree.
//!
//! # The five incidents
//!
//! Every one of these was mine, and every one produced a confident number
//! that I reported as a finding before checking the thing that produced it.
//!
//! 1. **Brace counting.** A `#[cfg(test)]` module stripper counted `{` and
//!    `}` per line. A brace inside a string literal pushed its depth up and
//!    it never came back down, so the stripper stayed "inside the module" for
//!    the rest of the file and swallowed most of the source tree. The
//!    environment-variable scan running behind it reported 2 reads where the
//!    tree has 10. `scripts/check-unwrap.py` had already written the lesson
//!    down in its own comments — "brace COUNTING is not brace matching" — and
//!    lexes strings, comments and char literals instead.
//!
//! 2. **Raw-string state machine.** `if 'r#"' in line: inraw = True`, cleared
//!    on a line containing `"#`. A single-line raw string sets the flag and
//!    never clears it, because the clear is an `elif` the opener already
//!    consumed. Everything after the first single-line raw string in the file
//!    looked quoted — about 180 false positives.
//!
//! 3. **Regex over-match.** Rust raw strings matched as `r(#*)"(.*?)"\1`.
//!    That pattern also fires on a bare `r"` occurring inside ordinary text:
//!    the string `"a\r"` ends in the two characters that open a raw string,
//!    and so does any word ending in `r` immediately before a quote.
//!
//! 4. **Split on the wrong delimiter.** Comparing a scan against
//!    `cargo test -- --list`, I took `line.split(":")[0]`. A module-qualified
//!    entry is `module::test_name: test`, so the split truncated at the first
//!    colon of the `::` and returned the MODULE. It reported 5 phantom tests
//!    and 3 missing ones, and they were the same tests twice.
//!
//! 5. **Field name guess.** I read a JSON row's `from` field. The field is
//!    `from_user`. Missing keys read back as blank, blank is what an
//!    unlabeled row looks like, and I reported the rows as unlabeled.
//!
//! # The property
//!
//! An extractor is validated against known-good AND known-bad input before
//! its output is believed, and it is driven by the real tree so it cannot rot
//! into matching nothing. Both halves are needed: a validated extractor that
//! no longer matches anything reports a clean tree, and an extractor
//! exercised by the tree without a known-bad case reports whatever its bug
//! produces.
//!
//! Each test below therefore pins TWO answers — the correct one and the
//! specific wrong one the broken extractor gave — so the broken form cannot
//! be reintroduced as a simplification.

#![cfg(feature = "full")]

use std::path::PathBuf;

use regex::Regex;

#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::split_raw_strings;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file directly under `tests/`, sorted.
fn test_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(repo().join("tests"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    out.sort();
    out
}

/// A source fixture holding every raw-string shape that broke an ad-hoc
/// splitter, assembled line by line.
///
/// Written as a joined slice rather than as a raw string so the shapes below
/// are ordinary escaped text in this file. A fixture spelled as a real raw
/// string would be stripped out of this file by the very scanner it feeds.
fn raw_string_shapes() -> String {
    [
        "fn shapes() {",
        "    let single = r#\"one\"#;",
        "    let nested = r##\"has a \"# inside\"##;",
        "    let escaped = \"a\\r\";",
        "    let words = [\"color\", \"for\"];",
        "    let multi = r#\"",
        "first",
        "second",
        "\"#;",
        "}",
    ]
    .join("\n")
}

/// A fixture with a single-line raw string followed by more content, then a
/// genuine multi-line one.
///
/// The first raw string is the trap: it opens and closes on one line, which
/// is exactly the case the toggle cannot represent.
fn toggle_fixture() -> String {
    [
        "fn one() {",                // 0
        "    let a = r#\"alpha\"#;", // 1
        "}",                         // 2
        "",                          // 3
        "fn two() {",                // 4
        "    let b = 2;",            // 5
        "}",                         // 6
        "fn three() {",              // 7
        "    let c = r#\"",          // 8
        "body line",                 // 9
        "\"#;",                      // 10
        "}",                         // 11
    ]
    .join("\n")
}

/// Which lines the naive per-line toggle believes are inside a raw string.
///
/// Incident 2 verbatim: set on a line containing an opener, clear on a line
/// containing a closer, and the clear is unreachable when one line holds
/// both.
fn naive_in_raw_flags(src: &str) -> Vec<bool> {
    let mut out = Vec::new();
    let mut in_raw = false;
    for line in src.lines() {
        if line.contains("r#\"") {
            in_raw = true;
        } else if line.contains("\"#") {
            in_raw = false;
        }
        out.push(in_raw);
    }
    out
}

/// Which lines lie wholly inside a raw string, from the correct splitter.
///
/// A line is inside the body when the splitter blanked all of its content. A
/// line that merely CONTAINS a raw string keeps its code and is not inside
/// one — the distinction the toggle cannot make.
fn correct_in_raw_flags(src: &str) -> Vec<bool> {
    let (stripped, _) = split_raw_strings(src);
    src.lines()
        .zip(stripped.lines())
        .map(|(orig, kept)| !orig.trim().is_empty() && kept.trim().is_empty())
        .collect()
}

/// Test names taken from `cargo test -- --list` output, correctly.
///
/// Strip the `: test` suffix, then take the LAST `::` segment, which is the
/// function name whatever module it lives in.
fn listed_names(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|l| l.trim().strip_suffix(": test"))
        .map(|n| n.rsplit("::").next().unwrap_or(n).to_string())
        .collect()
}

/// Test names taken from the same output by splitting on `:` — incident 4.
fn names_split_on_colon(listing: &str) -> Vec<String> {
    listing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| l.split(':').next().unwrap_or(l).to_string())
        .collect()
}

/// Net brace depth change on one line, counting every `{` and `}` character.
fn net_braces_counted(line: &str) -> i32 {
    line.chars()
        .map(|c| match c {
            '{' => 1,
            '}' => -1,
            _ => 0,
        })
        .sum()
}

/// Net brace depth change on one line, ignoring braces inside literals.
///
/// The minimum lexing that makes a depth honest: string and char literals are
/// tracked, and a backslash consumes the character after it. Lifetimes would
/// need more than this — the fixture has none, and the point here is only
/// that counting and matching are different operations.
fn net_braces_lexed(line: &str) -> i32 {
    let mut depth = 0i32;
    let mut chars = line.chars().peekable();
    let mut in_str = false;
    let mut in_chr = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_str || in_chr => {
                chars.next();
            }
            '"' if !in_chr => in_str = !in_str,
            '\'' if !in_str => in_chr = !in_chr,
            '{' if !in_str && !in_chr => depth += 1,
            '}' if !in_str && !in_chr => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// A source with a `#[cfg(test)]` module removed, using the supplied depth
/// rule.
///
/// Identical control flow either way, so the only variable is whether the
/// depth is counted or matched.
fn strip_cfg_test_module(src: &str, net: fn(&str) -> i32) -> String {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut inside = false;
    for line in src.lines() {
        if !inside && line.trim() == "#[cfg(test)]" {
            inside = true;
            depth = 0;
            continue;
        }
        if inside {
            depth += net(line);
            if depth <= 0 && line.contains('}') {
                inside = false;
            }
            continue;
        }
        out.push(line);
    }
    out.join("\n")
}

/// How many environment reads a source performs — the scan that rode on top
/// of the broken stripper.
fn env_reads(src: &str) -> usize {
    src.matches("std::env::var(").count()
}

/// A source whose `#[cfg(test)]` module contains an unbalanced brace inside a
/// string literal.
fn unbalanced_brace_source() -> String {
    [
        "fn keep_one() {",
        "    let a = std::env::var(\"SIPNAB_A\");",
        "}",
        "",
        "#[cfg(test)]",
        "mod tests {",
        "    fn helper() {",
        "        let brace = \"{\";",
        "    }",
        "}",
        "",
        "fn keep_two() {",
        "    let b = std::env::var(\"SIPNAB_B\");",
        "}",
    ]
    .join("\n")
}

// ── 1. the splitter, against every shape that broke an ad-hoc one ───

/// The raw-string splitter is correct on all five shapes at once.
///
/// Pins the known-good and the known-bad halves of incident 3 in one fixture:
/// three real raw strings must be found with their exact contents, and the
/// two ordinary constructs that merely LOOK like openers must be left alone.
/// It also pins the regex form as over-matching, so it cannot come back as a
/// tidier way to do the same job.
///
/// Consequence if this fails: every scanner built on the splitter is reading
/// either poisoned text (fixtures counted as code) or truncated text (code
/// blanked as fixture), and the counts it reports are unrelated to the tree.
#[test]
fn the_raw_string_splitter_handles_every_shape_that_broke_an_ad_hoc_one() {
    let src = raw_string_shapes();
    let (stripped, inner) = split_raw_strings(&src);

    assert_eq!(
        inner,
        vec![
            "one".to_string(),
            "has a \"# inside".to_string(),
            "\nfirst\nsecond\n".to_string(),
        ],
        "the splitter did not return exactly the three raw strings in the \
         fixture; a missing entry means an opener was not recognized, an \
         extra entry means ordinary code was read as a string, and a short \
         entry means the closing delimiter was matched with the wrong hash \
         count"
    );

    // The nested case, stated as its own failure mode: closing on `"#`
    // regardless of hash count truncates at the `"#` the content contains.
    let nested_body = &inner[1];
    assert!(
        nested_body.contains("\"#"),
        "the `r##\"...\"##` body no longer contains the `\"#` that makes it a \
         nesting test, so this fixture has stopped exercising hash counting"
    );
    let truncated = nested_body.split("\"#").next().unwrap_or("");
    assert_ne!(
        truncated, nested_body,
        "closing on the first `\"#` and closing on `\"##` gave the same \
         answer here, so the nesting case is not being exercised"
    );

    // Ordinary code the over-eager forms swallow.
    assert!(
        stripped.contains("let escaped = \"a\\r\";"),
        "the string `\"a\\r\"` was consumed as a raw-string opener; from here \
         the splitter blanks the rest of the file and every scanner reading \
         it sees an almost empty tree"
    );
    assert!(
        stripped.contains("[\"color\", \"for\"]"),
        "a word ending in `r` immediately before a quote was read as a \
         raw-string opener; `color\"` and `for\"` are the shapes that do it, \
         and `for_each` is the same hazard one character away"
    );
    assert_eq!(
        stripped.lines().count(),
        src.lines().count(),
        "the blanked copy lost lines, so every line number a line-oriented \
         scanner reports from it is wrong"
    );
    for gone in ["one", "first", "second"] {
        assert!(
            !stripped.contains(gone),
            "raw-string content `{gone}` survived the strip, so fixture text \
             is still visible to scanners as code"
        );
    }

    // Incident 3 itself: the regex form fires on text that is not a raw
    // string. Backreferences are not available in the `regex` crate, so the
    // pattern below is the opener half of `r(#*)\"(.*?)\"\\1` — which is
    // where the over-match happens.
    let opener = Regex::new("r#*\"").expect("the over-matching opener pattern must compile");
    let regex_hits = opener.find_iter(&src).count();
    assert_eq!(
        regex_hits, 6,
        "the regex opener matched {regex_hits} times instead of 6; this pins \
         the over-match, not a target to satisfy — three real openers plus \
         `a\\r\"`, `color\"` and `for\"`"
    );
    assert_eq!(
        inner.len(),
        3,
        "the splitter must find exactly the three real raw strings while the \
         regex finds {regex_hits}; if these two ever agree, one of them has \
         changed behavior and the comparison below is no longer a control"
    );
    assert!(
        regex_hits > inner.len(),
        "the regex no longer over-matches relative to the splitter, so the \
         reason the splitter exists is no longer demonstrated here"
    );
}

// ── 2. the toggle, pinned as wrong ──────────────────────────────────

/// A per-line `inraw` toggle gives a different, wrong answer.
///
/// Pins incident 2 as a divergence rather than as prose. The single-line raw
/// string on line 1 sets the toggle, nothing clears it, and every following
/// line is reported as quoted until a line happens to hold a bare closer.
///
/// Consequence if this fails: the toggle has been reintroduced somewhere as
/// a simpler splitter, and any scanner using it silently ignores most of each
/// file after its first single-line raw string — the shape that produced
/// roughly 180 false positives.
#[test]
fn the_naive_in_raw_line_toggle_disagrees_with_the_splitter() {
    let src = toggle_fixture();
    let naive = naive_in_raw_flags(&src);
    let correct = correct_in_raw_flags(&src);

    assert_eq!(
        correct,
        vec![
            false, false, false, false, false, false, false, false, false, true, false, false
        ],
        "the splitter's view of which lines lie inside a raw string changed; \
         only the body line of the multi-line string is inside one, and the \
         single-line string on line 1 puts no line inside anything"
    );
    assert_eq!(
        naive,
        vec![
            false, true, true, true, true, true, true, true, true, true, false, false
        ],
        "the naive toggle's failure changed shape; it is pinned here because \
         a rewrite that makes it look right on this fixture would hide the \
         defect rather than remove it"
    );
    assert_ne!(
        naive, correct,
        "the toggle and the splitter now agree, which means one of them has \
         been changed into the other; the toggle cannot be made correct by \
         line-oriented means"
    );

    let wrong: Vec<usize> = (0..correct.len())
        .filter(|&i| naive[i] && !correct[i])
        .collect();
    assert_eq!(
        wrong,
        vec![1, 2, 3, 4, 5, 6, 7, 8],
        "the set of lines the toggle wrongly calls quoted changed; lines 1 \
         through 8 are the run from the single-line raw string to the real \
         opener, and every scanner using the toggle skips all of them"
    );
    assert!(
        naive[5],
        "line 5 is `let b = 2;`, ordinary code four lines past a closed raw \
         string, and the toggle must still be calling it quoted for this \
         fixture to reproduce the incident"
    );
}

// ── 3. the delimiter ────────────────────────────────────────────────

/// A module-qualified test name is its last `::` segment.
///
/// Pins incident 4 from both sides: the correct extraction on `--list`
/// output, and the exact phantom/missing pair that splitting on `:` invents.
///
/// Consequence if this fails: a comparison against the compiler's own list of
/// tests reports names that do not exist as missing and module names as
/// phantoms, and the two lists are the same tests seen twice.
#[test]
fn a_module_qualified_test_name_is_its_last_path_segment() {
    let listing = [
        "mod_a::test_one: test",
        "test_two: test",
        "nested::deep::test_three: test",
    ]
    .join("\n");

    assert_eq!(
        listed_names(&listing),
        vec!["test_one", "test_two", "test_three"],
        "the correct extraction no longer returns the function name from a \
         module-qualified entry; the last `::` segment is the name whatever \
         module holds it"
    );
    assert_eq!(
        names_split_on_colon(&listing),
        vec!["mod_a", "test_two", "nested"],
        "the wrong extraction is pinned here as wrong; splitting on `:` cuts \
         at the first colon of `::` and yields the MODULE for any qualified \
         entry"
    );

    let correct = listed_names(&listing);
    let wrong = names_split_on_colon(&listing);
    let phantoms: Vec<&String> = wrong.iter().filter(|n| !correct.contains(n)).collect();
    let missing: Vec<&String> = correct.iter().filter(|n| !wrong.contains(n)).collect();
    assert_eq!(
        phantoms,
        vec!["mod_a", "nested"],
        "the phantom names the wrong split invents changed; these are \
         reported as tests that exist in the list and not in the tree"
    );
    assert_eq!(
        missing,
        vec!["test_one", "test_three"],
        "the names the wrong split loses changed; these are reported as \
         missing from the list while sitting in it, so one defect is counted \
         twice and read as two"
    );
    assert_eq!(
        phantoms.len(),
        missing.len(),
        "the phantom and missing counts came apart; their being equal is the \
         signature that says one truncation is being reported from both ends"
    );
}

// ── 4. the field name ───────────────────────────────────────────────

/// A missing JSON key is distinguishable from a present empty value.
///
/// Pins incident 5. Reading `from` off a row whose field is `from_user` must
/// be visibly absent, not blank, and the collapse that makes the two look
/// alike is pinned as a collapse.
///
/// Consequence if this fails: a guessed field name prints an empty column,
/// an empty column reads as unlabeled data, and rows that are fully
/// labeled get reported as missing their labels.
#[test]
fn a_missing_json_key_is_not_an_empty_value() {
    let row: serde_json::Value = serde_json::from_str("{\"from_user\":\"alice\",\"to_user\":\"\"}")
        .expect("the fixture row must parse as JSON");

    assert!(
        row.get("from").is_none(),
        "`from` is not a key of this row; a lookup that finds one means the \
         fixture no longer reproduces the guessed-name case"
    );
    assert_eq!(
        row.get("from_user").and_then(serde_json::Value::as_str),
        Some("alice"),
        "`from_user` is the real field and must carry the value; if this is \
         None the extractor is reading the wrong row shape entirely"
    );
    assert_eq!(
        row.get("to_user").and_then(serde_json::Value::as_str),
        Some(""),
        "`to_user` is present and empty; that state must stay reachable, \
         because it is the one a missing key gets confused with"
    );

    // The collapse, stated as the defect. Both read back blank.
    let lenient = |key: &str| {
        row.get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    };
    assert_eq!(
        lenient("from"),
        lenient("to_user"),
        "a missing key and an empty value no longer print the same through \
         `unwrap_or(\"\")`; this equality is pinned as the reason a blank \
         column proves nothing about the data"
    );
    assert_ne!(
        row.get("from").is_some(),
        row.get("to_user").is_some(),
        "presence no longer separates the two, so nothing distinguishes `I \
         asked for the wrong field` from `this row has no sender`"
    );

    // Indexing is the same trap with no `Option` to notice.
    assert!(
        row["from"].is_null(),
        "indexing a missing key stopped yielding Null; it does not panic, \
         which is exactly why a typo'd field name is silent"
    );
    assert!(
        !row["to_user"].is_null(),
        "the present empty value indexed as Null, which would make the two \
         cases identical even to a caller that checks"
    );
}

// ── 5. exercised by the real tree ───────────────────────────────────

/// The floor below which the splitter is matching nothing.
///
/// Not a ratchet: a number chosen well under the tree's real count, so it
/// answers "is this still finding raw strings at all" and not "how many are
/// there today".
const MINIMUM_RAW_STRINGS: usize = 25;

/// The splitter is driven by the real `tests/*.rs` corpus.
///
/// Two claims a fixture cannot make. First, the splitter still matches real
/// source — an extractor that has rotted into matching nothing passes every
/// fixture it was written with and reports a clean tree forever. Second,
/// stripping raw strings never removes a `#[test]` the compiler sees: the
/// marker count is identical before and after, because a marker inside a raw
/// string is text the compiler ignores and a marker outside one is never
/// touched by the strip.
///
/// Consequence if the counts differ: either a real test definition is being
/// blanked — so the definition scanners under-count silently — or a fixture
/// marker is being counted as a definition, which is the phantom-test case.
#[test]
fn the_raw_string_splitter_is_exercised_by_the_real_test_tree() {
    let mut total_raw = 0usize;
    let mut files_with_raw = 0usize;
    let mut markers_before = 0usize;
    let mut markers_after = 0usize;
    let mut mismatched = Vec::new();

    // The corpus guard, first: every assertion below is satisfied by an empty
    // walk, so a walk that reaches nothing reports a clean tree.
    let files = test_files();
    assert!(
        files.len() >= 40,
        "the walk reached only {} file(s) under tests/; this test is vacuous \
         on a corpus that size, and its whole purpose is to be driven by a \
         real one",
        files.len()
    );

    for path in &files {
        let Ok(src) = std::fs::read_to_string(path) else {
            continue;
        };
        let (stripped, inner) = split_raw_strings(&src);
        total_raw += inner.len();
        if !inner.is_empty() {
            files_with_raw += 1;
        }
        let before = src.lines().filter(|l| l.trim() == "#[test]").count();
        let after = stripped.lines().filter(|l| l.trim() == "#[test]").count();
        markers_before += before;
        markers_after += after;
        if before != after {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            mismatched.push(format!("  {name}: {before} before, {after} after"));
        }
    }

    assert!(
        total_raw >= MINIMUM_RAW_STRINGS,
        "the splitter found only {total_raw} raw string(s) across the test \
         tree, under the floor of {MINIMUM_RAW_STRINGS}; an extractor that \
         has stopped matching real source passes every fixture it was born \
         with and reports whatever it scans as clean"
    );
    assert!(
        files_with_raw >= 5,
        "only {files_with_raw} file(s) in the tree contain a raw string the \
         splitter can see; the corpus driving this scanner has collapsed to \
         a handful of files and no longer resembles the tree"
    );
    assert!(
        markers_before > 0,
        "no bare `#[test]` marker was found anywhere in the tree, so the \
         before/after comparison below is comparing zero with zero"
    );
    assert!(
        mismatched.is_empty(),
        "stripping raw strings changed the test-marker count in these \
         files:\n{}\n\nEither a real definition is inside the blanked span — \
         the strip is eating code — or a raw string contains a marker, which \
         is a test the compiler never compiles and every scanner counts.",
        mismatched.join("\n")
    );
    assert_eq!(
        markers_before, markers_after,
        "the tree-wide marker count moved across the strip; the per-file list \
         above should have named where, and an empty list with unequal totals \
         means this test's own accounting is broken"
    );
}

// ── 6. counting versus matching ─────────────────────────────────────

/// Brace counting is fooled by a string literal; brace matching is not.
///
/// Pins incident 1. The fixture's `#[cfg(test)]` module holds `let brace =
/// "{";`, a brace the compiler never sees as one. The counting stripper's
/// depth never returns to zero, so it stays inside the module to the end of
/// the file and swallows the code after it — and the environment scan riding
/// on its output reports 1 read where the source has 2, the same shape as the
/// 2-instead-of-10 the real incident produced.
///
/// Consequence if this fails: a scan built on the counting stripper reports a
/// small number confidently, and the number is a measure of where the
/// stripper got stuck rather than of the tree.
#[test]
fn brace_counting_is_fooled_by_a_string_literal_and_matching_is_not() {
    let src = unbalanced_brace_source();
    assert_eq!(
        env_reads(&src),
        2,
        "the fixture must contain exactly two environment reads, one either \
         side of the module, or there is nothing for the stripper to lose"
    );

    let matched = strip_cfg_test_module(&src, net_braces_lexed);
    let counted = strip_cfg_test_module(&src, net_braces_counted);

    assert_eq!(
        env_reads(&matched),
        2,
        "the lexing stripper lost an environment read; it must remove the \
         test module and nothing else, so the scan behind it sees the whole \
         file"
    );
    assert!(
        matched.contains("SIPNAB_B"),
        "the code AFTER the test module is gone from the lexed strip, which \
         is the swallowing behavior this test exists to distinguish"
    );

    assert_eq!(
        env_reads(&counted),
        1,
        "the counting stripper no longer loses the read after the module. \
         That is not an improvement to accept quietly: this assertion pins \
         the defect, and counting braces cannot have become correct without \
         someone teaching it about string literals — in which case it is \
         matching, and belongs in the other function"
    );
    assert!(
        !counted.contains("SIPNAB_B"),
        "the counting stripper kept the code after the module, so the \
         unbalanced brace in the string is no longer trapping it and this \
         fixture has stopped reproducing the incident"
    );

    assert_ne!(
        matched, counted,
        "the two strippers produced identical output, so the fixture no \
         longer separates counting from matching"
    );
    for stripper in [&matched, &counted] {
        assert!(
            !stripper.contains("let brace"),
            "the module body leaked into the output; both strippers must \
             remove the module, so the only difference measured here is how \
             much MORE the counting one removes"
        );
    }
    assert!(
        matched.len() > counted.len(),
        "the counting strip is no longer shorter than the lexed one; the \
         defect is that it removes too much, and if it now removes less the \
         comparison has inverted and the fixture needs rereading"
    );
}
