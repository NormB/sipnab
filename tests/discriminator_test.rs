// SPDX-License-Identifier: MIT OR Apache-2.0

//! A rule must name what separates its two cases, and that thing must separate.
//!
//! # The defect this file exists for
//!
//! Writing `fixture_isolation_test` I produced two rules whose stated power
//! they did not have, and both failed on their first run:
//!
//! 1. **The marker/definition equality.** I wrote that it makes the silent
//!    direction loud — that a phantom smuggled in through a raw string adds a
//!    name without adding a marker, so the counts separate. They do not. The
//!    phantom sits on its own physical line, so it contributes a marker AND a
//!    definition and the two numbers move together. The rule is real; the
//!    property I claimed for it was not.
//! 2. **An indentation rule for ratchets.** I treated an indented
//!    `const EXPECTED_X` as fixture text. It reported eight pins and all eight
//!    were genuine ratchets declared inside their own test function, which is
//!    ordinary Rust. Indentation had never separated anything.
//!
//! Both are the same mistake in different clothes: **I picked a discriminator
//! by looking only at the case I wanted to catch, and never asked what else
//! shares it.** A discriminator validated against one side is not a
//! discriminator, it is a description of one example.
//!
//! Six instances of the surrounding class had already been found, all in test
//! code rather than in the product: a crate import read as a repository
//! reference, a placeholder in a doc comment read the same way, prose mentions
//! counted as definitions, eight legitimate cross-surface pairs read as
//! copies, a fabricated reference written into a fixture, and a string
//! continuation that armed the extractor.
//!
//! # What is actually new here
//!
//! Those six are gated where they were found. Nothing had asked whether the
//! same two-direction hole exists in the OTHER counters this repository
//! trusts, so this file goes and looks:
//!
//! * The **MCP tool counter** certifies the number on the homepage by regex
//!   over `src/mcp/**`. It is not string-aware, and a registration-shaped line
//!   inside a raw string is counted — demonstrated below, then gated.
//! * The **unwrap ban** is the counter-example, and the reason the pattern is
//!   worth naming: `scripts/check-unwrap.py` lexes Rust and strips comments,
//!   char literals and every string form BEFORE searching, precisely so a
//!   mention is not a violation. It gets both directions right, and pinning
//!   that means the good pattern cannot regress silently either.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/absence_scan.rs"]
mod absence_scan;

use absence_scan::{defines, ratchet_pins, split_raw_strings, test_fns};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a file, or the empty string.
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Every `.rs` file directly under `tests/`.
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

/// Lines whose trimmed text begins with the test marker.
fn marker_lines(src: &str) -> usize {
    src.lines()
        .map(str::trim)
        .filter(|t| t.starts_with("#[test]"))
        .count()
}

/// A file with a phantom test hidden inside a raw string.
///
/// Assembled rather than written out: spelled literally it would put a marker
/// at the start of a physical line in THIS file, which is the instance-six
/// shape that `every_marker_line_in_the_tree_is_bare` refuses.
fn phantom_in_a_raw_string() -> String {
    let marker = format!("#{}", "[test]");
    format!(
        "{marker}\nfn real_one() {{\n    assert!(true);\n}}\n\nfn helper() {{\n    let f = r#\"\n{marker}\nfn phantom_gate() {{}}\n\"#;\n    let _ = f;\n}}\n"
    )
}

// ── A. a discriminator must be validated from both sides ────────────

/// The equality and the raw-string rule cover different holes.
///
/// Directly encodes the first correction. Neither rule subsumes the other, and
/// the claim that the equality covers raw strings was wrong. Written as a
/// comparison rather than a comment so the next person to reach for one of
/// them can see which case it actually answers.
#[test]
fn the_equality_and_the_raw_string_rule_cover_different_holes() {
    // Case 1: a phantom inside a raw string. It brings its own marker.
    let raw = phantom_in_a_raw_string();
    assert_eq!(
        marker_lines(&raw),
        test_fns(&raw).len(),
        "the equality was claimed to catch this and does not -- if it now \
         does, the correction recorded here is stale and should be rewritten \
         rather than deleted"
    );
    let (stripped, _) = split_raw_strings(&raw);
    assert_eq!(
        test_fns(&stripped).len(),
        1,
        "the raw-string rule must catch what the equality cannot"
    );

    // Case 2: a marker with no definition. The raw-string rule is blind to it.
    let orphan = format!("#{}\n// not a function\nlet x = 1;\n", "[test]");
    let (orphan_stripped, inner) = split_raw_strings(&orphan);
    assert!(inner.is_empty(), "no raw strings in this case");
    assert_ne!(
        marker_lines(&orphan_stripped),
        test_fns(&orphan_stripped).len(),
        "the equality must catch a marker with no definition -- the case the \
         raw-string rule cannot see, since there is no string involved"
    );
}

/// Indentation does not separate a fixture from a declaration.
///
/// The disproof of the second wrong rule, kept as a test because the rule was
/// plausible enough that I shipped it. A genuine ratchet declared inside its
/// own test function is indented; so is a fixture pin inside a string. One bit
/// that is set for both cases carries no information.
#[test]
fn indentation_does_not_separate_a_fixture_from_a_declaration() {
    let genuine = "fn some_gate() {\n    const EXPECTED_TABLES: usize = 756;\n    assert_eq!(count(), EXPECTED_TABLES);\n}\n";
    let fixture =
        "fn helper() {\n    let f = r#\"\n    const EXPECTED_TABLES: usize = 756;\n\"#;\n}\n";

    let indent_of = |s: &str| {
        s.lines()
            .find(|l| l.trim_start().starts_with("const EXPECTED_"))
            .map(|l| l.len() - l.trim_start().len())
            .unwrap_or(0)
    };
    assert!(indent_of(genuine) > 0, "the genuine pin is indented");
    assert!(indent_of(fixture) > 0, "the fixture pin is indented too");
    assert_eq!(
        indent_of(genuine),
        indent_of(fixture),
        "these two differ in kind and not in indentation. A rule keyed on \
         indentation reports the genuine one, which is what it did: eight \
         hits, eight of them real."
    );
}

/// Being inside a string does separate them.
///
/// The control for the rule above, and the discriminator that replaced it. The
/// two cases must land on opposite sides — that is the whole definition of the
/// word.
#[test]
fn being_inside_a_string_does_separate_them() {
    let genuine = "fn some_gate() {\n    const EXPECTED_TABLES: usize = 756;\n}\n";
    let fixture =
        "fn helper() {\n    let f = r#\"\n    const EXPECTED_TABLES: usize = 756;\n\"#;\n}\n";

    let (g_stripped, g_inner) = split_raw_strings(genuine);
    let (f_stripped, f_inner) = split_raw_strings(fixture);

    assert_eq!(
        ratchet_pins(&g_stripped).len(),
        1,
        "the genuine pin survives"
    );
    assert!(g_inner.is_empty(), "the genuine case has no strings");
    assert_eq!(
        ratchet_pins(&f_stripped).len(),
        0,
        "the fixture pin must not survive the strip"
    );
    assert!(
        f_inner.iter().any(|c| c.contains("EXPECTED_TABLES")),
        "the fixture pin must be found INSIDE a string, which is what makes it \
         a fixture"
    );
}

/// A candidate discriminator is only one if the two cases land apart.
///
/// The general form, applied to both the failed and the working candidate, so
/// the method is written down rather than the two conclusions. A predicate
/// that returns the same verdict for both cases has no discriminating power
/// regardless of how well it describes the case that motivated it.
#[test]
fn a_candidate_discriminator_must_put_the_two_cases_apart() {
    let genuine = "fn some_gate() {\n    const EXPECTED_TABLES: usize = 756;\n}\n";
    let fixture =
        "fn helper() {\n    let f = r#\"\n    const EXPECTED_TABLES: usize = 756;\n\"#;\n}\n";

    let separates = |verdict: &dyn Fn(&str) -> bool| verdict(genuine) != verdict(fixture);

    let by_indentation = |s: &str| {
        s.lines()
            .any(|l| l.trim_start().starts_with("const EXPECTED_") && l.starts_with(' '))
    };
    let by_string_membership = |s: &str| {
        let (_, inner) = split_raw_strings(s);
        inner.iter().any(|c| c.contains("EXPECTED_"))
    };

    assert!(
        !separates(&by_indentation),
        "indentation now separates these two cases; the rule that was removed \
         for failing to would work after all, and this account is wrong"
    );
    assert!(
        separates(&by_string_membership),
        "string membership no longer separates the two cases, so the rule that \
         replaced the indentation one is resting on the same nothing"
    );
}

// ── B. a rule must examine something ────────────────────────────────

/// Every tree-walking rule guards against an empty corpus.
///
/// A rule that iterates a corpus and asserts nothing about its size reports
/// perfect health when the walk breaks. That is the failure mode with no
/// symptom: `assert!(bad.is_empty())` over zero files is true.
#[test]
fn every_tree_walking_rule_guards_against_an_empty_corpus() {
    // Walked, not listed. A hardcoded roster covers the files that existed
    // when it was typed, and the next scanner added here inherits no guard and
    // no complaint. It also let THIS file satisfy the rule for the wrong
    // reason: it names `test_files()` in a string literal, so a `contains`
    // test saw a caller that is not one.
    let files = test_files();
    assert!(
        files.len() >= 40,
        "the walk reached only {} file(s) under tests/; this rule is vacuous \
         on a corpus that size, which is the exact failure it exists to find",
        files.len()
    );

    let mut unguarded = Vec::new();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let src = read(path);
        // A CALL, not a mention: the definition line is not a call, and
        // neither is the name inside a string literal.
        let calls_the_walk = src.lines().any(|l| {
            l.contains("test_files()") && !l.contains("fn test_files()") && !l.contains('"')
        });
        if !calls_the_walk {
            continue;
        }
        // The THRESHOLD, not the shape. Checking for the text
        // `files.len() >= ` accepted `files.len() >= 0`, which asserts nothing
        // -- the guard was gone and the rule reading it stayed green. A
        // mutation survived on exactly that.
        let meaningful_threshold = src.match_indices("files.len() >= ").any(|(i, _)| {
            src[i + "files.len() >= ".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .is_ok_and(|n| n > 0)
        });
        if !(meaningful_threshold || src.contains("!files.is_empty()")) {
            unguarded.push(name);
        }
    }
    assert!(
        unguarded.is_empty(),
        "these files walk the test tree with no assertion that the walk found \
         anything: {unguarded:?}. An empty corpus satisfies every rule in them."
    );
}

/// The predicates return nothing on empty input, rather than something.
///
/// The other half: the guards above are only worth having if an empty corpus
/// really does produce an empty result rather than a default that looks like
/// a finding, or like a pass.
#[test]
fn the_predicates_return_nothing_on_empty_input() {
    assert!(test_fns("").is_empty(), "no definitions in nothing");
    assert!(ratchet_pins("").is_empty(), "no pins in nothing");
    assert_eq!(defines("", "anything"), 0);
    let (stripped, inner) = split_raw_strings("");
    assert!(stripped.is_empty() && inner.is_empty());
    assert_eq!(marker_lines(""), 0);
}

/// An empty corpus satisfies the marker equality, which is why it is guarded.
///
/// Stated as a demonstration rather than left implicit. `0 == 0` is the shape
/// of every vacuous pass in this repository, and the rule reads as healthy.
#[test]
fn an_empty_corpus_satisfies_the_marker_equality() {
    assert_eq!(
        marker_lines(""),
        test_fns("").len(),
        "an empty file balances trivially"
    );
    let real = format!("#{}\nfn real_one() {{}}\n", "[test]");
    assert_eq!(marker_lines(&real), 1, "a real file must not be empty-like");
}

/// A rule reading a missing file does not pass silently.
///
/// `read()` returns the empty string for a path that is not there, which is
/// convenient and dangerous: every `contains` check on it is false, so a rule
/// about a file that moved reads as a rule about a file that is clean.
#[test]
fn a_rule_reading_a_missing_file_does_not_pass_silently() {
    let missing = read(&repo().join("tests/this_file_does_not_exist.rs"));
    assert!(missing.is_empty(), "a missing file reads as empty");
    assert!(
        !missing.contains("anything at all"),
        "every content check on a missing file is vacuously false, which is \
         why each rule below asserts the file was readable first"
    );
    // The files this suite depends on must exist, checked rather than assumed.
    for required in [
        "tests/support/absence_scan.rs",
        "tests/site_journey_test.rs",
        "scripts/check-unwrap.py",
    ] {
        assert!(
            !read(&repo().join(required)).is_empty(),
            "{required} is missing or empty; rules that read it would pass by \
             examining nothing"
        );
    }
}

// ── C. the MCP tool counter, both directions ────────────────────────

/// The registration regex, read out of the gate that uses it.
///
/// Read rather than copied. A second spelling of this pattern would drift from
/// the one that certifies the homepage number, and then this file would be
/// testing something the gate does not do.
fn registration_regex() -> regex::Regex {
    let src = read(&repo().join("tests/site_journey_test.rs"));
    let anchor = src
        .find("fn registered_mcp_tool_count")
        .expect("site_journey_test still defines the MCP tool counter");
    let tail = &src[anchor..];
    let start = tail
        .find("Regex::new(r#\"")
        .expect("the counter still builds its regex inline")
        + "Regex::new(r#\"".len();
    let end = tail[start..]
        .find("\"#)")
        .expect("the regex literal is closed")
        + start;
    regex::Regex::new(&tail[start..end]).expect("the gate's own pattern compiles")
}

/// The counter agrees with the registrations actually in the tree.
///
/// The control. Everything below is about what else the pattern matches, and
/// none of it means anything if the pattern has stopped matching the real
/// thing.
#[test]
fn the_mcp_counter_matches_the_registrations_in_the_tree() {
    let re = registration_regex();
    let mut total = 0usize;
    let mut files = 0usize;
    let mut stack = vec![repo().join("src/mcp")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files += 1;
                total += re.find_iter(&read(&p)).count();
            }
        }
    }
    assert!(files >= 2, "the walk reached {files} file(s) under src/mcp");
    assert!(
        total >= 40,
        "only {total} MCP tool registration(s) found; the pattern has stopped \
         matching how they are written and every rule below is scanning \
         nothing"
    );
}

/// A registration-shaped line inside a raw string is counted.
///
/// The hole, demonstrated. The counter is a regex over raw source with no
/// notion of quoting, so a documentation example written as a raw string would
/// inflate the number this repository puts on its homepage — silently, because
/// nothing else measures it.
#[test]
fn a_registration_shaped_line_inside_a_raw_string_is_counted() {
    let re = registration_regex();
    let fixture = "const DOC: &str = r#\"\n    name = \"phantom_tool\",\n\"#;\n";
    assert_eq!(
        re.find_iter(fixture).count(),
        1,
        "a registration-shaped line inside a raw string is no longer counted. \
         If the counter learned about quoting, the gate below is guarding a \
         hole that has closed -- check before removing it."
    );
}

/// No raw string under `src/mcp` contains a registration-shaped line.
///
/// The gate for it. Cheaper and more honest than teaching the counter to lex
/// Rust: the counter is a regex on purpose, so the rule is that nothing in its
/// corpus may look like a registration without being one.
#[test]
fn no_raw_string_under_src_mcp_contains_a_registration_shaped_line() {
    let re = registration_regex();
    let mut bad = Vec::new();
    let mut files = 0usize;
    let mut stack = vec![repo().join("src/mcp")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if !p.extension().is_some_and(|x| x == "rs") {
                continue;
            }
            files += 1;
            let (_, inner) = split_raw_strings(&read(&p));
            for chunk in inner {
                if re.is_match(&chunk) {
                    bad.push(format!("  {}", p.display()));
                }
            }
        }
    }
    assert!(files >= 2, "the walk reached {files} file(s) under src/mcp");
    assert!(
        bad.is_empty(),
        "these files hide a registration-shaped line inside a string:\n{}\n\n\
         The tool counter is a regex over raw source and would count it, \
         inflating the number on the homepage.",
        bad.join("\n")
    );
}

/// The counter ignores a commented-out registration.
///
/// The direction that was already safe, pinned so it stays that way. The
/// pattern anchors on `name` after whitespace, so a `//` prefix takes the line
/// out of scope. That is worth an assertion because it is the difference
/// between the two comment forms, and nothing else records it.
#[test]
fn the_mcp_counter_ignores_a_commented_registration() {
    let re = registration_regex();
    let commented = "    // name = \"phantom_tool\",\n    /// name = \"other_tool\",\n";
    assert_eq!(
        re.find_iter(commented).count(),
        0,
        "a commented-out registration is being counted; the homepage number \
         would include tools that are not registered"
    );
}

// ── D. the unwrap ban, which gets both directions right ─────────────

/// The unwrap ban passes on the tree as it stands.
///
/// The control for the three below: they claim things about how the scanner
/// treats mentions, and none of that means anything if it is failing.
#[test]
fn the_unwrap_ban_passes_on_the_tree_as_it_stands() {
    let out = Command::new("python3")
        .arg(repo().join("scripts/check-unwrap.py"))
        .current_dir(repo())
        .output()
        .expect("python3 must be available to run the unwrap ban");
    assert!(
        out.status.success(),
        "scripts/check-unwrap.py failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Production code mentions `.unwrap()` in comments, and the ban allows it.
///
/// Demonstrated on real data rather than a fixture, which is the stronger
/// form: the exemption is exercised by the tree every time the gate runs, so
/// it cannot rot into a branch nothing reaches.
#[test]
fn the_unwrap_ban_allows_a_mention_in_a_comment() {
    let mut mentions = 0usize;
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if !p.extension().is_some_and(|x| x == "rs") {
                continue;
            }
            for line in read(&p).lines() {
                let t = line.trim_start();
                if (t.starts_with("//") || t.starts_with('*'))
                    && (t.contains(".unwrap()") || t.contains(".expect("))
                {
                    mentions += 1;
                }
            }
        }
    }
    assert!(
        mentions > 0,
        "no comment under src/ mentions .unwrap() or .expect(), so the \
         scanner's comment exemption is not exercised by the tree and this \
         test proves nothing about it"
    );
    // And the gate passes anyway -- checked by the control above.
}

/// The unwrap ban strips before it searches.
///
/// The property that makes the two directions work, asserted against the
/// script's own source. It is the one scanner in this repository that lexes
/// its input instead of grepping it, and that decision is what this file is
/// recommending everywhere else -- so it should not be able to disappear
/// quietly.
#[test]
fn the_unwrap_ban_strips_before_it_searches() {
    let src = read(&repo().join("scripts/check-unwrap.py"));
    assert!(!src.is_empty(), "scripts/check-unwrap.py must be readable");
    // Word-boundary, not substring: renaming the state to `_RAWX` leaves
    // `_RAW` present as a prefix, and a `contains` check passed while the
    // lexer had lost the state entirely. A mutation survived on exactly that.
    let names_symbol = |sym: &str| {
        src.match_indices(sym).any(|(i, _)| {
            src[i + sym.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
        })
    };
    for required in ["_RAW", "_BLOCK", "_STR"] {
        assert!(
            names_symbol(required),
            "check-unwrap.py no longer tracks {required}; it has stopped \
             lexing and a mention in a comment or a panic message is a \
             violation again"
        );
    }
}

/// The unwrap ban refuses to run against a corpus it cannot see.
///
/// Its own vacuity guards, pinned. This is the scanner that got the hard part
/// right, and it also got this right: it exits non-zero when it derives fewer
/// source roots than the workspace has, and when the walk reads no files at
/// all. A gate that reports OK after scanning nothing is the failure this
/// whole file is about.
#[test]
fn the_unwrap_ban_refuses_to_run_against_a_corpus_it_cannot_see() {
    let src = read(&repo().join("scripts/check-unwrap.py"));
    assert!(
        src.contains("derived only") && src.contains("scanned no files"),
        "check-unwrap.py has lost one of its vacuity guards. Without them a \
         broken walk reports OK, which is indistinguishable from a clean tree."
    );
    let exits = src.matches("raise SystemExit(2)").count();
    assert!(
        exits >= 2,
        "only {exits} hard exit(s) left in check-unwrap.py; the guards are \
         printing a warning and continuing, which is the same as not having \
         them"
    );
}

/// The unwrap ban also bans the macro spellings of "abort here".
///
/// `panic!`, `unreachable!`, `todo!` and `unimplemented!` end the process the
/// way an unwrap does, and the scanner never looked at them: a clippy
/// restriction-lint measurement found zero unwraps under `src/` beside nine
/// such sites. Pinned by name so the widening cannot quietly narrow again.
#[test]
fn the_unwrap_ban_names_the_four_abort_macros_and_the_gate_marker() {
    let src = read(&repo().join("scripts/check-unwrap.py"));
    assert!(!src.is_empty(), "scripts/check-unwrap.py must be readable");
    let pattern = src
        .lines()
        .find(|l| l.starts_with("_ABORT = "))
        .expect("check-unwrap.py no longer defines _ABORT, the abort-macro pattern");
    for macro_name in ["panic", "unreachable", "todo", "unimplemented"] {
        assert!(
            pattern.contains(macro_name),
            "check-unwrap.py's abort pattern no longer names {macro_name}!: {pattern}"
        );
    }
    assert!(
        src.contains("gate:") && src.contains("because"),
        "check-unwrap.py has lost the `// gate: <macro> because <reason>` marker; \
         every documented exception in src/ is now a violation, or the whole \
         check is gone"
    );
}

/// The abort-macro marker does not exempt a site that gives no reason.
///
/// The exception mechanism's one hard rule, held from the suite the hook runs
/// on every commit rather than only from `scripts/tests/`, which it runs when
/// `scripts/` changed. A marker that exempted a site with no reason would be
/// a magic word, and a gate with a magic word is a gate with a hole in it.
/// The control runs first: with a reason, the same site is accepted, so a
/// scanner that rejects everything cannot pass this.
#[test]
fn the_unwrap_ban_does_not_exempt_an_abort_site_with_no_reason() {
    let dir = tempfile::tempdir().expect("a scratch workspace");
    let root = dir.path();
    std::fs::create_dir_all(root.join("src")).expect("src");
    std::fs::create_dir_all(root.join("crates/sipnab-audio/src")).expect("member src");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\".\", \"crates/sipnab-audio\"]\n",
    )
    .expect("manifest");
    std::fs::write(
        root.join("crates/sipnab-audio/src/lib.rs"),
        "pub fn audio() -> u8 { 1 }\n",
    )
    .expect("member lib.rs");
    let scan = |marker: &str| {
        let body = format!(
            "pub fn prod(x: u8) -> u8 {{\n    match x {{\n        0 => 1,\n        \
             {marker}\n        _ => unreachable!(),\n    }}\n}}\n"
        );
        std::fs::write(root.join("src/lib.rs"), body).expect("lib.rs");
        let out = Command::new("python3")
            .arg(repo().join("scripts/check-unwrap.py"))
            .current_dir(root)
            .output()
            .expect("python3 must be available to run the unwrap ban");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (rc, err) = scan("// gate: unreachable because the caller masks every other value");
    assert_eq!(
        rc,
        Some(0),
        "a marker with a reason must exempt the site:\n{err}"
    );
    let (rc, err) = scan("// gate: unreachable because");
    assert_eq!(
        rc,
        Some(1),
        "a marker with no reason must not exempt the site:\n{err}"
    );
    assert!(
        err.contains("src/lib.rs:5:") && err.contains("no reason"),
        "the report must name the site and say the marker gave no reason:\n{err}"
    );
}
