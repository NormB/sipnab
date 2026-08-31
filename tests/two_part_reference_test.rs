// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gates for facts a document writes down TWICE, where only one copy was read.
//!
//! Two defects, one shape. In both, a gate existed, ran on every commit, and
//! reported green while the thing it was named for was broken -- because it
//! read one half of the evidence and the defect lived in the other half.
//!
//! # Defect 1: the label was checked, the anchor was not
//!
//! Every line citation in this tree carries its line number twice:
//!
//! ```text
//! [`src/mcp/server.rs:5278`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5250)
//!  ^^^^^^^^^^^^^^^^^^^^^^^ the label a reader sees      the anchor a click follows ^^^^^
//! ```
//!
//! When source shifted by 28 lines the LABELS were updated and the `#L`
//! ANCHORS were left behind. `scripts/check-line-drift.py` -- driven by
//! `dev_docs_drift_test::line_citations_point_at_the_code_they_name` -- reads
//! the label, resolves the symbol, and passed: by its rule every citation named
//! the right line. Every link still sent the reader 28 lines away. Nothing in
//! the repository compared the two numbers, and the defect was found by eye.
//!
//! `_repoint` in that script already rewrites both halves together, and
//! `scripts/tests/test_check_line_drift.py` already proves it does -- for ONE
//! citation handed to it directly. What was missing was a scan of the tree
//! asking the same question of the citations that are already there.
//!
//! The rule therefore lives in that same script (`check_anchors`), not in a
//! second Rust implementation: the script is both the gate and the fixer
//! (`--apply`), and this repository has already paid for two statements of one
//! rule -- `repo_paths_in_docs_are_clickable` against
//! `scripts/link-repo-paths.py`, where the fixer would have produced 33 links
//! the gate never asked for. The tests below DRIVE that script and pin what it
//! must report; they do not restate its rule.
//!
//! # Defect 2: one home root was banned, three exist
//!
//! `tests/suite_result_parsing_test.rs` was committed with an absolute checkout
//! path pasted out of real `cargo` output, and
//! `private_identity_test::e1_no_file_carries_an_account_path` caught it at
//! commit time. That gate works. What it did not do is cover the SHAPE space:
//! `rule::account_path` matched `/home/<account>` and nothing else, so the
//! macOS form and the tilde form walked past it. Measured on this tree before
//! this file existed: three occurrences, in `scripts/fix-line-anchors.py`,
//! `scripts/fix-tables.py` and `docs/design/backlog.md`.
//!
//! The breadth rule below is deliberately NOT a fourth path shape. It is the
//! account NAME, at a word boundary, anywhere in the tracked tree -- a rule no
//! new home root can slip past, because it never mentions a home root. It
//! subsumes `rule::account_path` rather than restating it, and it reads the
//! account list out of that gate so the two cannot disagree about who is
//! private.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

// -- Harness ---------------------------------------------------------

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: impl AsRef<Path>) -> String {
    let p = repo().join(rel.as_ref());
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Run `scripts/check-line-drift.py` over `pages`, or the whole tree when
/// none are named, and return `(exit ok, stdout)`.
///
/// Naming pages is what makes the FIXER testable, and it is the same door
/// `dev_docs_drift_test` uses: `--apply` EDITS what it is given, so a test that
/// handed it `docs/` would repair the tree as a side effect of running and
/// leave the gate green because the test fixed it.
fn drift(pages: &[&Path], apply: bool) -> (bool, String) {
    let mut cmd = Command::new("python3");
    cmd.arg("scripts/check-line-drift.py").current_dir(repo());
    if apply {
        cmd.arg("--apply");
    }
    for p in pages {
        cmd.arg(p);
    }
    let out = cmd.output().expect("run scripts/check-line-drift.py");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// The `key=value` fields of the checker's `two-part references:` summary.
///
/// Parsed rather than trusted: a scanner that stopped matching would report
/// zero disagreements exactly like a clean tree, so every test below reads the
/// counts out of the same line it reads the verdict from.
fn summary(report: &str) -> BTreeMap<String, usize> {
    let line = report
        .lines()
        .find(|l| l.starts_with("two-part references:"))
        .unwrap_or_else(|| {
            panic!(
                "the checker printed no `two-part references:` summary, so \
                 nothing proves the label/anchor scan ran at all:\n{report}"
            )
        });
    line.split_whitespace()
        .filter_map(|tok| {
            let (k, v) = tok.split_once('=')?;
            Some((k.to_string(), v.parse().ok()?))
        })
        .collect()
}

fn field(report: &str, key: &str) -> usize {
    *summary(report)
        .get(key)
        .unwrap_or_else(|| panic!("the summary has no `{key}` field:\n{report}"))
}

/// Write a one-page fixture where `--apply` may rewrite it.
fn fixture(dir: &Path, name: &str, body: &str) -> PathBuf {
    let page = dir.join(name);
    std::fs::write(&page, body).expect("write the fixture page");
    page
}

// -- Defect 1: the label and the anchor must agree --------------------

/// The whole documentation tree: no citation's two halves disagree.
///
/// This is the gate the desynchronized `#L` anchors walked past. It says
/// nothing about whether a cited line is CORRECT -- that is
/// `line_citations_point_at_the_code_they_name`, over the same script -- only
/// that the number a reader is shown and the number a click lands on are the
/// same number. A citation that fails both is sending readers to a wrong line
/// it does not even admit to.
#[test]
fn label_and_anchor_agree_across_the_documentation_tree() {
    let (ok, report) = drift(&[], false);

    // Anti-vacuity, and the specific way this scanner can go blind: its regex
    // is the only thing that decides a citation exists. A regex that stopped
    // matching would print `examined=0 disagreeing=0` and exit 0 forever.
    //
    // Floors rather than exact pins, because unlike the drift checker's
    // `checked` count -- which moves only when a citation gains a resolvable
    // symbol -- this one moves whenever anybody adds or removes a line
    // citation, which is most documentation commits. Measured 2026-08-31:
    // 781 examined, 781 carrying both halves, across 159 pages. The floors sit
    // ~10% under that: far enough not to churn, close enough that a scanner
    // reading half the tree cannot clear them.
    let examined = field(&report, "examined");
    let both = field(&report, "both_halves");
    assert!(
        examined >= 700,
        "the label/anchor scan examined only {examined} line citation(s); this \
         tree holds ~781, so the extraction narrowed and the gate below is \
         checking almost nothing:\n{report}"
    );
    assert!(
        both >= 700,
        "only {both} of {examined} line citation(s) carry BOTH a label line and \
         an `#L` fragment. The agreement rule can only see citations that have \
         two halves, so stripping fragments is the way to make it vacuous:\n{report}"
    );

    assert!(
        ok,
        "a citation's visible label and its `#L` anchor name different lines. \
         The label is what a reviewer reads and the anchor is where the click \
         lands, so this is a link that is confidently, silently wrong.\n{report}\n\
         Run `python3 scripts/check-line-drift.py --apply` to move each anchor \
         onto its own label."
    );
}

/// The scan reaches the published pages, not just `docs/`.
///
/// `dev_docs_drift_test::linked_code_targets_exist` walks `docs/internals/`
/// only, and `doc_link_hygiene_test::cited_line_numbers_link_to_the_line`
/// walks `docs/` and then EXEMPTS `docs/internals/`. Measured on this tree:
/// two line citations live under `website/content/`, on a page no Rust gate
/// opens for this rule at all. Two is small; the point is that the number is
/// not structurally zero, and a citation that is only ever published to the
/// site would otherwise be checked by nobody.
///
/// Asserted as agreement between the script's page count and an independent
/// walk here, so a page set that silently shrinks back to `docs/` fails.
#[test]
fn the_scan_reaches_every_page_the_documentation_is_published_from() {
    fn md_under(rel: &str) -> Vec<PathBuf> {
        let root = repo().join(rel);
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().and_then(|x| x.to_str()) == Some("md")
                    && !p.to_string_lossy().contains("superpowers")
                {
                    out.push(p);
                }
            }
        }
        out
    }

    let docs_only = md_under("docs").len();
    let expected = docs_only + md_under("website/content").len() + 1; // + README.md

    let (_, report) = drift(&[], false);
    let pages = field(&report, "pages");

    assert!(
        docs_only > 40,
        "the independent walk found only {docs_only} page(s) under docs/, so \
         the comparison below proves nothing"
    );
    assert!(
        expected > docs_only,
        "the walk found nothing outside docs/, so this test could not tell a \
         wider page set from a narrower one"
    );
    assert_eq!(
        pages, expected,
        "the checker scanned {pages} page(s); docs/ + website/content/ + \
         README.md is {expected}. A page set that shrank back to docs/ leaves \
         every citation published only to the website unchecked:\n{report}"
    );
}

/// A stale anchor beside a fresh label is reported, and named.
///
/// The reintroduced defect, in one page: the label was moved 28 lines and the
/// fragment was not. Both numbers must appear in the message, because the
/// failure is which of the two is right and the reader has to be able to see
/// them side by side.
#[test]
fn a_stale_anchor_beside_a_fresh_label_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = fixture(
        dir.path(),
        "desynchronized.md",
        "See [`src/mcp/server.rs:5278`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5250).\n",
    );

    let (ok, report) = drift(&[&page], false);
    assert!(
        !ok,
        "a label that says :5278 beside an anchor that lands on #L5250 must \
         fail; that is the defect this file exists for:\n{report}"
    );
    assert_eq!(
        field(&report, "disagreeing"),
        1,
        "one citation disagrees and the summary must say so:\n{report}"
    );
    assert!(
        report.contains("5278") && report.contains("5250"),
        "the message must name BOTH numbers -- which half is stale is the whole \
         question:\n{report}"
    );
}

/// Agreement is checked at both ends of a range.
///
/// Ranges are not a hypothetical form here: 228 of this tree's 781 citations
/// are `#L396-L401`, and every one of them is invisible to
/// `scripts/check-line-drift.py`'s drift rule, whose `CITE` regex requires a
/// backtick immediately after the digits. A rule that only compared the START
/// would certify `:35-40` -> `#L35-L99` as correct.
#[test]
fn a_range_citation_must_agree_at_both_ends() {
    let dir = tempfile::tempdir().expect("tempdir");

    let good = fixture(
        dir.path(),
        "range-ok.md",
        "See [`src/capture/device.rs:38-40`](https://github.com/NormB/sipnab/blob/main/src/capture/device.rs#L38-L40).\n",
    );
    let (ok, report) = drift(&[&good], false);
    assert!(ok, "a range that agrees must pass:\n{report}");
    assert_eq!(
        field(&report, "examined"),
        1,
        "the range form must be EXAMINED, not skipped -- a form the scanner \
         ignores is a form the defect can hide in:\n{report}"
    );

    let bad = fixture(
        dir.path(),
        "range-end.md",
        "See [`src/capture/device.rs:38-40`](https://github.com/NormB/sipnab/blob/main/src/capture/device.rs#L38-L99).\n",
    );
    let (ok, report) = drift(&[&bad], false);
    assert!(
        !ok,
        "the start agrees and the END does not; a rule that only compares the \
         first number certifies this:\n{report}"
    );
    assert!(
        report.contains("38-40") && report.contains("L38-L99"),
        "the message must show the label's range and the anchor's:\n{report}"
    );
}

/// A range label whose anchor covers one line is reported as a mismatch.
///
/// Measured on this tree: 228 range labels, 228 range anchors, zero of either
/// paired with the other shape. The shapes travel together because
/// `scripts/fix-line-anchors.py` writes them together, so a label promising
/// `:35-40` over an anchor that lands on a single line is a half-applied edit,
/// not a style choice.
#[test]
fn a_range_label_with_a_single_line_anchor_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = fixture(
        dir.path(),
        "collapsed.md",
        "See [`src/capture/device.rs:35-40`](https://github.com/NormB/sipnab/blob/main/src/capture/device.rs#L35).\n",
    );
    let (ok, report) = drift(&[&page], false);
    assert!(
        !ok,
        "the label promises six lines and the anchor lands on one:\n{report}"
    );
    assert!(
        report.contains("#L35-L40"),
        "the message must name the fragment the label asks for, so the fix is \
         a copy rather than a puzzle:\n{report}"
    );
}

/// What the anchor fixer writes, the anchor gate accepts.
///
/// The gate half runs on every commit; the fixer half would otherwise run for
/// nobody. That is the arrangement this repository has already been bitten by,
/// and "one implementation" argues that a gate and its fixer cannot DIVERGE --
/// it is not evidence that the fixer works. So: break it, repair it, re-check
/// it, and confirm the LABEL survived. The label is the half a human wrote and
/// the half the drift rule validates against the source; the anchor follows it.
#[test]
fn what_the_anchor_fixer_writes_the_gate_accepts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = fixture(
        dir.path(),
        "repairable.md",
        "See [`src/mcp/server.rs:5278`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5250) \
         and [`src/capture/device.rs:38-40`](https://github.com/NormB/sipnab/blob/main/src/capture/device.rs#L38-L99).\n",
    );

    let (ok, _) = drift(&[&page], false);
    assert!(
        !ok,
        "the fixture must start broken or the repair proves nothing"
    );

    let (_, applied) = drift(&[&page], true);
    assert!(
        applied.contains("re-anchored 2 citation(s)"),
        "the fixer must report what it moved:\n{applied}"
    );

    let repaired = std::fs::read_to_string(&page).expect("read the repaired page");
    let (ok, report) = drift(&[&page], false);
    assert!(
        ok,
        "the gate rejected what its own fixer wrote:\n{report}\n{repaired}"
    );
    assert!(
        repaired.contains("server.rs:5278") && repaired.contains("device.rs:38-40"),
        "the LABEL is the author's citation and the anchor follows it; \
         rewriting the label instead would silently change what the page \
         claims:\n{repaired}"
    );
    assert!(
        repaired.contains("#L5278") && repaired.contains("#L38-L40"),
        "both fragments must have moved onto their labels:\n{repaired}"
    );
}

/// The agreement rule sees the three forms the drift rule cannot match.
///
/// `CITE` in `scripts/check-line-drift.py` requires a `.rs` label and a single
/// line number, because it has to resolve a Rust symbol in the cited file.
/// That leaves 349 of this tree's 781 citations outside it: the 228 ranges, the
/// `docs/…​.md:149-150` cross-references, and the 79 bare `[`:1928`](…)` labels
/// used inside tables. None of those needs a symbol to be checkable for
/// AGREEMENT, and all three are in the corpus that desynchronized.
#[test]
fn the_agreement_rule_examines_forms_the_drift_rule_cannot_match() {
    let dir = tempfile::tempdir().expect("tempdir");
    let page = fixture(
        dir.path(),
        "other-forms.md",
        "A range [`src/capture/device.rs:38-40`](https://github.com/NormB/sipnab/blob/main/src/capture/device.rs#L38-L40), \
         a page [`docs/architecture.md:149-150`](https://github.com/NormB/sipnab/blob/main/docs/architecture.md#L149-L150), \
         and a bare [`:1928`](https://github.com/NormB/sipnab/blob/main/src/config.rs#L1928).\n",
    );

    let (ok, report) = drift(&[&page], false);
    assert!(ok, "all three agree, so all three must pass:\n{report}");
    assert_eq!(
        field(&report, "examined"),
        3,
        "all three forms must be examined:\n{report}"
    );
    assert!(
        report.contains("checked 0 citation(s)"),
        "and the drift rule must have matched NONE of them -- that is what \
         makes this coverage rather than duplication:\n{report}"
    );
}

/// A fenced example is skipped; the same citation in prose is not.
///
/// The paired half of the exclusion. Documentation about citations has to be
/// able to SHOW a broken one, and a gate that fails on its own worked example
/// gets an exemption comment instead of a fix. Measured: zero citations in
/// this tree currently sit inside a fence, so the exclusion costs no coverage
/// today -- which is exactly when it is safe to add and exactly when it needs
/// the second half of this test to stay honest.
#[test]
fn a_fenced_example_is_skipped_and_the_same_citation_in_prose_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cite = "[`src/mcp/server.rs:5278`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5250)";

    let fenced = fixture(
        dir.path(),
        "fenced.md",
        &format!("Never write this:\n\n```markdown\n{cite}\n```\n"),
    );
    let (ok, report) = drift(&[&fenced], false);
    assert!(ok, "a fenced example must not fail the gate:\n{report}");
    assert_eq!(
        field(&report, "fenced"),
        1,
        "the skip must be COUNTED, or a mask that swallowed the whole tree \
         would look like a clean tree:\n{report}"
    );
    assert_eq!(
        field(&report, "examined"),
        0,
        "nothing outside the fence to examine:\n{report}"
    );

    let prose = fixture(
        dir.path(),
        "prose.md",
        &format!("Written for real: {cite}\n"),
    );
    let (ok, report) = drift(&[&prose], false);
    assert!(
        !ok,
        "the identical citation in prose must still be caught, or the fence \
         mask is a way through the gate:\n{report}"
    );
}

// -- Defect 2: how broadly the account rule reaches -------------------

/// Extensions whose bytes are not prose, so a substring match in one is noise.
const BINARY_EXT: &[&str] = &[
    "pcap", "pcapng", "png", "jpg", "jpeg", "gif", "ico", "gz", "xz", "zst", "bin", "wav", "woff",
    "woff2", "ttf", "otf", "pdf", "wasm", "o", "a",
];

/// This file, which must talk about the rule without becoming a violation.
const SELF: &str = "tests/two_part_reference_test.rs";

/// The gate that owns the account list, and the only file allowed to spell it.
const ACCOUNT_GATE: &str = "tests/private_identity_test.rs";

/// The private account names, read from the ONE place that lists them.
///
/// Parsed out of `private_identity_test::rule::PRIVATE_ACCOUNTS` rather than
/// repeated here, for two reasons that both matter. A second copy would be a
/// second rule about who is private, and this file would then have to CONTAIN
/// the account name -- which is the disclosure it is written to prevent.
fn private_accounts() -> Vec<String> {
    let src = read(ACCOUNT_GATE);
    let list = Regex::new(r"PRIVATE_ACCOUNTS:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]")
        .expect("account list regex")
        .captures(&src)
        .unwrap_or_else(|| {
            panic!(
                "{ACCOUNT_GATE} no longer declares `PRIVATE_ACCOUNTS: &[&str]`. \
                 That constant is where this file learns who is private; with \
                 it gone every scan below runs over an empty list and passes."
            )
        })
        .get(1)
        .expect("group 1")
        .as_str()
        .to_string();

    let names: Vec<String> = Regex::new(r#""([^"]+)""#)
        .expect("string literal regex")
        .captures_iter(&list)
        .map(|c| c[1].to_string())
        .collect();

    assert!(
        !names.is_empty(),
        "PRIVATE_ACCOUNTS parsed to an empty list from `{list}` -- an empty \
         list makes every scan below vacuous"
    );
    assert!(
        names.iter().all(|n| n.len() >= 3),
        "an account name shorter than three characters would match inside \
         ordinary words: {names:?}"
    );
    names
}

/// A match on `needle` that does not fire inside a longer word.
///
/// The boundary is what separates the account from `aggregator`, `navigator`
/// and `investigator`, all of which are in this tree.
fn word_at(line: &str, needle: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let boundary =
        |c: Option<&u8>| !matches!(c, Some(b) if b.is_ascii_alphanumeric() || *b == b'_');
    line.match_indices(needle)
        .find(|(i, _)| {
            boundary(bytes.get(i.wrapping_sub(1)).filter(|_| *i > 0))
                && boundary(bytes.get(i + needle.len()))
        })
        .map(|(i, _)| i)
}

/// Every tracked text file, as (repo-relative path, contents).
fn tracked_text() -> Vec<(String, String)> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files -- the scan is over what is tracked, not what is present");
    assert!(out.status.success(), "git ls-files failed");

    let mut files = Vec::new();
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        let ext = PathBuf::from(rel)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if BINARY_EXT.contains(&ext.as_str())
            || rel.ends_with(".min.js")
            || rel.ends_with(".min.css")
        {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(repo().join(rel)) {
            files.push((rel.to_string(), text));
        }
    }
    files
}

/// Files that may name a private account, and why. Nothing else may.
///
/// An exemption without a reason beside it reads, six months later, exactly
/// like an oversight -- and the next person widens it rather than questioning
/// it. Each entry says what the file is doing with the name and what would
/// make the exemption wrong.
const ACCOUNT_NAME_EXEMPT: &[(&str, &str)] = &[(
    ACCOUNT_GATE,
    "The gate that BANS the account name has to spell it. `PRIVATE_ACCOUNTS` \
     is the list itself, and the E- and F-class controls prove the rule flags \
     the exact strings that leaked -- a rule with no positive control is a rule \
     nobody can tell from a rule that matches nothing. `scan` in that file \
     skips it by path for the same reason. The exemption is bounded by \
     `the_account_gate_carries_the_name_only_inside_a_control` below: every \
     occurrence must sit inside a string literal a test asserts on, never in \
     prose a reader could copy.",
)];

/// No tracked file names a private account, except the gate that bans it.
///
/// Broader than `rule::account_path` on purpose, and the breadth IS the fix.
/// That rule matched `/home/<account>` and nothing else, so three occurrences
/// under two other home roots -- `/Users/<account>` in `scripts/fix-line-anchors.py`
/// and `scripts/fix-tables.py`, `~<account>` in `docs/design/backlog.md` -- sat
/// in a public repository while the gate reported the tree clean. Adding a
/// fourth path shape would have left a fifth. The account NAME cannot be
/// slipped past by inventing a new prefix.
#[test]
fn no_tracked_file_names_a_private_account_outside_the_gate_that_bans_it() {
    let accounts = private_accounts();
    let files = tracked_text();

    assert!(
        files.len() > 500,
        "the scan reached only {} tracked text file(s); this tree holds \
         thousands, so the walk broke and a clean verdict means nothing",
        files.len()
    );

    let mut found = Vec::new();
    let mut exempted = 0usize;
    for (rel, text) in &files {
        if rel == SELF {
            continue; // names the exemption table, not an account
        }
        let exempt = ACCOUNT_NAME_EXEMPT.iter().any(|(f, _)| f == rel);
        for (i, line) in text.lines().enumerate() {
            for acct in &accounts {
                if word_at(line, acct).is_none() {
                    continue;
                }
                if exempt {
                    exempted += 1;
                } else {
                    let excerpt: String = line.trim().chars().take(110).collect();
                    found.push(format!("{rel}:{}: {excerpt}", i + 1));
                }
                break;
            }
        }
    }

    // The exempt file is the only positive control this scan has. If it stops
    // matching, the scan below has proved nothing about the rest of the tree
    // either -- the same way a smoke detector with no battery reports no fire.
    assert!(
        exempted > 0,
        "the scan found the account name nowhere at all, including in \
         {ACCOUNT_GATE}, which spells it in its own rule. The name-matching \
         rule is broken, not the tree."
    );

    assert!(
        found.is_empty(),
        "a tracked file names a private account. The name is not a path shape, \
         so writing it under a different home root does not make it less of a \
         disclosure -- and this repository is public, so it is disclosed the \
         moment it is pushed:\n{}\n\n\
         Write `$HOME`, `/srv/...`, or a path relative to the repository. If a \
         file genuinely must carry the name, add it to ACCOUNT_NAME_EXEMPT in \
         {SELF} WITH the reason.",
        found
            .iter()
            .take(25)
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every exemption is real, still needed, and carries its reason.
///
/// An exemption list rots in two directions. An entry for a file that no longer
/// carries the name is a license nobody is using, and the next person spends it
/// on something else. An entry with no reason is indistinguishable from an
/// oversight. Both are checked here.
#[test]
fn every_account_name_exemption_is_still_used_and_still_explained() {
    let accounts = private_accounts();
    let files = tracked_text();

    assert!(
        !ACCOUNT_NAME_EXEMPT.is_empty(),
        "an empty exemption table makes this test vacuous"
    );

    for (rel, reason) in ACCOUNT_NAME_EXEMPT {
        let text = files
            .iter()
            .find(|(r, _)| r == rel)
            .map(|(_, t)| t)
            .unwrap_or_else(|| panic!("{rel} is exempt but is not a tracked text file"));
        let hits = text
            .lines()
            .filter(|l| accounts.iter().any(|a| word_at(l, a).is_some()))
            .count();
        assert!(
            hits > 0,
            "{rel} is exempt from the account-name rule but no longer carries \
             the name. Delete the exemption rather than leaving a license \
             nobody is using."
        );
        assert!(
            reason.len() > 120,
            "the exemption for {rel} has no reason worth the name ({} chars). \
             A future reader has to be able to tell it from an oversight.",
            reason.len()
        );
    }
}

/// The exempt gate carries the name only inside a control, never in prose.
///
/// This is what bounds the exemption. `private_identity_test.rs` is skipped
/// wholesale by its own `scan`, for every rule it defines -- so without this,
/// that one file is a place where any amount of real PII can accumulate and
/// every gate in the suite stays green. Measured 2026-08-31: seven
/// occurrences, all inside a Rust string literal that a control asserts on.
///
/// A doc comment is the shape this is aimed at: `/// the corpus at
/// /home/<account>/pcaps` reads as an explanation and is a disclosure.
#[test]
fn the_account_gate_carries_the_name_only_inside_a_control() {
    let accounts = private_accounts();
    let text = read(ACCOUNT_GATE);

    let mut occurrences = 0usize;
    let mut loose = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for acct in &accounts {
            let Some(at) = word_at(line, acct) else {
                continue;
            };
            occurrences += 1;
            // Inside a string literal: an odd number of unescaped `"` before
            // it on this line. Cheap, and exact for the one-line literals a
            // control fixture is written as.
            let quotes = line[..at]
                .char_indices()
                .filter(|(j, c)| *c == '"' && !line[..*j].ends_with('\\'))
                .count();
            if quotes % 2 == 0 || line.trim_start().starts_with("//") {
                loose.push(format!("{ACCOUNT_GATE}:{}: {}", i + 1, line.trim()));
            }
            break;
        }
    }

    assert!(
        occurrences >= 5,
        "only {occurrences} occurrence(s) of a private account name found in \
         {ACCOUNT_GATE}; it declares the list and carries the positive controls \
         for it, so a number this low means the match broke and the check below \
         is empty"
    );
    assert!(
        loose.is_empty(),
        "{ACCOUNT_GATE} is exempt from the account-name scan so that its \
         controls can name what they ban. That exemption covers CONTROLS -- a \
         string literal a test asserts on -- and nothing else. These are prose \
         or bare code:\n{}\n\n\
         Move the value into a control, or take the name out.",
        loose.join("\n")
    );
}

/// The word boundary catches every home root and spares the words that
/// contain the name.
///
/// The paired halves of the exclusion, in one place. The negative controls are
/// not decoration: `aggregator`, `navigator` and `investigator` all occur in
/// this tree, and a rule that flagged them would be suppressed within a week
/// and then catch nothing at all.
#[test]
fn the_account_name_rule_flags_every_home_root_and_spares_the_words_around_it() {
    let acct = private_accounts()[0].clone();

    for root in ["/home", "/Users", "/var/home", "/export/home"] {
        let line = format!("{root}/{acct}/Development/sipnab");
        assert!(
            word_at(&line, &acct).is_some(),
            "a home root the path rule never listed must still be caught: {line}"
        );
    }
    for shape in [
        format!("user-local under `~{acct}`"),
        format!("ssh {acct}@the-build-host"),
        format!("  Full output: /home/{acct}/x/.git/worktrees/a/x.log"),
        format!("chown {acct}:{acct} /srv/pcaps"),
    ] {
        assert!(
            word_at(&shape, &acct).is_some(),
            "the name is the rule, not the path shape: {shape}"
        );
    }

    for benign in [
        "and every aggregator downstream of journald",
        "navigator.clipboard.writeText",
        "an investigator reading the trail",
        "/home/user/capture.pcap",
        "/home/<you>/pcaps",
        "$HOME/pcaps",
    ] {
        assert!(
            word_at(benign, &acct).is_none(),
            "a rule that cries about ordinary English gets suppressed, and then \
             catches nothing: {benign}"
        );
    }

    // The TRAILING boundary, which nothing above reaches. Every ordinary word
    // that contains the account name -- `aggregator`, `navigator`,
    // `investigator`, all three of them in this tree -- has a LETTER in front
    // of it, so the leading boundary alone rejects the lot. Only a longer
    // account name that starts the same way gets as far as the trailing test.
    //
    // Found by mutation: deleting the trailing boundary left every assertion
    // above passing and the whole-tree scan green, because nothing in the tree
    // happens to be shaped like this. A boundary no test reaches is a boundary
    // that can be deleted, and accusing a DIFFERENT account of a disclosure is
    // the false positive that gets a privacy gate suppressed.
    for longer in [
        format!("/home/{acct}ade/pcaps"),
        format!("/Users/{acct}son/Development"),
        format!("user-local under `~{acct}ade`"),
    ] {
        assert!(
            word_at(&longer, &acct).is_none(),
            "this names a different account that merely starts the same way: {longer}"
        );
    }
}
