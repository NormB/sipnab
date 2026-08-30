// SPDX-License-Identifier: MIT OR Apache-2.0

//! A gate is coupled to a shape, and the shape is allowed to move.
//!
//! # The defect class
//!
//! Every gate in this repository names something: a symbol, a table, a
//! heading, a set of states. Naming is what makes it a gate. It is also what
//! makes it fragile in one specific direction — the named thing moves for a
//! perfectly good reason, and the gate either breaks in a way that reads as a
//! product failure, or, far worse, keeps passing while checking less.
//!
//! Four instances, all real, all mine:
//!
//! 1. **A rename broke a gate.** `fn expiry_of` moved from
//!    `src/sip/diagnosis.rs` to `src/sip/mod.rs` and became
//!    `registration_expiry` when it gained a second caller.
//!    `docs_drift_test::sip_parameter_claims_match_the_parser` justifies a
//!    documented claim by the existence of a named function in a named file,
//!    so it failed with "claims sipnab parses `expires`, but `fn expiry_of` is
//!    gone". The claim was still true; the coupling was stale.
//!
//! 2. **A restructure broke an extractor.** `docs/mcp-tools.md` grew from one
//!    tool table into eight, one per category.
//!    `docs_drift_test::mcp_tool_table_lists_every_registered_tool` sliced
//!    from the first table header to the first blank line, read ten rows, and
//!    reported the other forty-one tools as undocumented. Nothing about the
//!    tools had changed.
//!
//! 3. **Duplicate anchors.** `#### Group name` index entries repeated the
//!    `## Group name` section headings. GitHub slugifies both identically and
//!    suffixes the second in DOCUMENT ORDER, so every link to the pair became
//!    position-dependent — it still resolved, at whichever heading happened to
//!    be second. `link_integrity_test::no_page_mints_a_positional_anchor`
//!    caught it.
//!
//! 4. **A known gap hidden inside a passing gate.** The sweep in
//!    `src/sip/dialog_state_machine.rs` asserted a HARDCODED list of nine
//!    reachable states, and its comment recorded the remainder as accepted:
//!    "`Expired` has no transition into it yet (nothing parses a REGISTER
//!    expiry)". A phone that unregistered was reported as `Registered` for as
//!    long as that exemption stood. The test was green the whole time.
//!
//! # The property
//!
//! A gate must fail LOUDLY when the thing it names moves; it must DERIVE its
//! expectations rather than hardcode them; and it must never record a known
//! defect as an accepted exemption unless that exemption is itself checked.
//!
//! The tests below hold the tree to that. Each one is a scan, and a scan that
//! matches nothing agrees with any tree — so
//! `every_scan_in_this_file_found_a_plausible_number_of_items` re-runs all of
//! them against documented floors, and each floor names what it was measured
//! at. A broken scan fails there rather than reporting a clean tree.

#![cfg(feature = "full")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[path = "support/source_scan.rs"]
mod source_scan;

// ---------------------------------------------------------------------------
// Tree access
// ---------------------------------------------------------------------------

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a file, naming it on failure.
fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `.rs` file directly under `tests/`, sorted.
///
/// Deliberately not recursive: `tests/support/` and `tests/cli/` are shared
/// modules compiled into many binaries, not gates in their own right.
fn test_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = repo().join("tests");
    for e in std::fs::read_dir(&dir).expect("read tests/").flatten() {
        let p = e.path();
        if p.is_file() && p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out.sort();
    out
}

/// Every file under `rel` with extension `ext`, recursively, sorted.
fn files_under(rel: &str, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join(rel)];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == ext) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// A repo-relative display path, for failure messages.
fn rel(p: &Path) -> String {
    p.strip_prefix(repo())
        .unwrap_or(p)
        .display()
        .to_string()
        .replace('\\', "/")
}

/// The 0-based line a byte offset falls on.
fn line_of(src: &str, offset: usize) -> usize {
    src[..offset].matches('\n').count()
}

// ---------------------------------------------------------------------------
// Scan 1: "symbol X exists in file Y" claims
// ---------------------------------------------------------------------------

/// One `"fn NAME"` literal a gate uses as evidence, beside a read of `src/`.
#[derive(Debug)]
struct SymbolClaim {
    /// Test file holding the literal.
    file: String,
    /// 1-based line of the literal.
    line: usize,
    /// The function name the literal names.
    symbol: String,
}

/// Every symbol claim in `tests/*.rs`, and how many `src/…` reads were seen.
///
/// # What this matches, and what it deliberately does not
///
/// A claim is a string literal of the form `"fn some_name"` (optionally
/// `"pub fn …"` / `"async fn …"`) within 30 lines of a call that reads a
/// `src/…` path — `read_to_string`, `include_str!`, or this tree's `read`
/// helper — where the path literal sits inside that same call expression.
///
/// The limits, each chosen so a miss is a gap in coverage rather than a false
/// failure:
///
/// * **Only `tests/*.rs`.** Support modules under `tests/support/` are
///   scanners, not gates.
/// * **Only a `src/…` path in the SAME call expression.** Pairing a `"fn X"`
///   literal with any `src/` mention in the window reported
///   `discriminator_test`'s `"fn registered_mcp_tool_count"` — which names a
///   helper in `tests/site_journey_test.rs` and would never be found under
///   `src/` — because an unrelated `"src/mcp"` string sat 20 lines away. The
///   pairing has to be with the read, not with the neighbourhood.
/// * **A 30-line window**, which is a proxy for "the same test body". A claim
///   further than that from its read is not scanned.
/// * **Snake-case names only**, so `"fn "` used as a bare token separator (as
///   `docs_drift_test` does when it slices a body) is not a claim.
///
/// A claim built by `format!`, or spelled with its parameter list, is missed.
/// That is the conservative direction: this gate certifies the claims it can
/// see and makes no assertion about the ones it cannot.
fn symbol_claims() -> (Vec<SymbolClaim>, usize) {
    // The path literal must be an argument of the reading call: `[^;{}]`
    // cannot leave the expression, so an unrelated `"src/…"` string later in
    // the function is not pulled in.
    let read_re = regex::Regex::new(
        r#"(?:read_to_string|include_str!|\bread)\s*\([^;{}]{0,200}?"(?:\./)?src/[A-Za-z0-9_/.\-]*""#,
    )
    .expect("read regex");
    let sym_re =
        regex::Regex::new(r#""(?:pub )?(?:async )?fn ([a-z_][a-z0-9_]*)""#).expect("symbol regex");

    let files = test_files();
    // A walk that reached nothing would report a tree with no stale claims.
    assert!(
        files.len() >= 40,
        "the walk reached only {} file(s) under tests/; every rule in this \
         file is vacuous on a corpus that size",
        files.len()
    );

    let mut claims = Vec::new();
    let mut reads = 0usize;
    for path in &files {
        let src = read(path);
        let read_lines: Vec<usize> = read_re
            .find_iter(&src)
            .map(|m| line_of(&src, m.start()))
            .collect();
        reads += read_lines.len();
        for m in sym_re.find_iter(&src) {
            let line = line_of(&src, m.start());
            if !read_lines.iter().any(|r| line.abs_diff(*r) <= 30) {
                continue;
            }
            let symbol = sym_re
                .captures(m.as_str())
                .expect("captures on a match")
                .get(1)
                .expect("group 1")
                .as_str()
                .to_string();
            claims.push(SymbolClaim {
                file: rel(path),
                line: line + 1,
                symbol,
            });
        }
    }
    (claims, reads)
}

/// Files under `src/` in which `name` is DEFINED as a function.
///
/// A definition boundary, not a substring: `contains("fn run_offline_paral")`
/// is satisfied by `fn run_offline_parallel`, so a gate could name a function
/// that has never existed and resolve against a real one whose name merely
/// starts the same way.
fn defining_files(name: &str) -> Vec<String> {
    let def = regex::Regex::new(&format!(r"\bfn\s+{}\s*[(<]", regex::escape(name)))
        .expect("definition regex");
    files_under("src", "rs")
        .into_iter()
        .filter(|p| def.is_match(&read(p)))
        .map(|p| rel(&p))
        .collect()
}

// ---------------------------------------------------------------------------
// Scan 2: heading slugs
// ---------------------------------------------------------------------------

/// Markdown with frontmatter and fenced code blocks removed.
///
/// Fences are tracked by their opening character AND length, and a closer must
/// use the same character and be at least as long. The naive version — one
/// `bool` toggled by any line starting with a fence — is wrong in a way that
/// silently disarms whatever is built on it: a `~~~` block *containing* a
/// ` ``` ` line switches fence mode on with nothing to switch it back, and the
/// rest of the file is blanked while still counting as scanned.
///
/// This matters here because a shell comment inside a ```` ```bash ```` block
/// is a `#` line, and reading one as a heading would manufacture collisions
/// out of ordinary examples.
fn markdown_prose(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0usize;
    if lines
        .first()
        .is_some_and(|l| l.trim() == "---" || l.trim() == "+++")
    {
        let delim = lines[0].trim().to_string();
        i = 1;
        while i < lines.len() && lines[i].trim() != delim {
            i += 1;
        }
        i += 1;
    }
    let mut out = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    while i < lines.len() {
        let t = lines[i].trim();
        let marker = t
            .chars()
            .next()
            .filter(|c| *c == '`' || *c == '~')
            .map(|c| (c, t.chars().take_while(|x| *x == c).count()))
            .filter(|(_, n)| *n >= 3);
        match (fence, marker) {
            (None, Some(open)) => fence = Some(open),
            (None, None) => out.push(lines[i]),
            (Some((fc, fn_len)), Some((c, n)))
                if c == fc && n >= fn_len && t[n..].trim().is_empty() =>
            {
                fence = None;
            }
            _ => {}
        }
        i += 1;
    }
    out.join("\n")
}

/// The text of every ATX heading in a markdown source.
fn headings(src: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^#{1,6}[ \t]+(.+?)[ \t#]*$").expect("heading regex");
    re.captures_iter(&markdown_prose(src))
        .map(|c| c[1].to_string())
        .collect()
}

/// The GitHub anchor slug for a heading.
///
/// Lowercase; keep ASCII alphanumerics, spaces and hyphens (plus `_` when
/// `keep_underscore`, which is what GitHub itself does); spaces become
/// hyphens. Everything else — punctuation, backticks, and any non-ASCII
/// letter — is dropped without leaving a separator behind, so an em-dash
/// surrounded by spaces yields a DOUBLE hyphen: `A — B` slugifies to `a--b`.
///
/// The `keep_underscore == false` form is STRICTER than GitHub and matches the
/// task-spec rule this repository also models. A stricter slug can only merge
/// more headings together, so it flags a superset of GitHub's collisions —
/// the safe direction for an anchor gate.
fn slug(heading: &str, keep_underscore: bool) -> String {
    heading
        .to_lowercase()
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || *c == ' ' || *c == '-' || (keep_underscore && *c == '_')
        })
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Headings that slugify identically within one page, plus the corpus size.
///
/// Returns `(clashes, pages with headings, headings seen)`.
fn slug_clashes(keep_underscore: bool) -> (Vec<String>, usize, usize) {
    let mut clashes = Vec::new();
    let mut pages = 0usize;
    let mut total = 0usize;
    for path in files_under("docs", "md") {
        let hs = headings(&read(&path));
        if hs.is_empty() {
            continue;
        }
        pages += 1;
        total += hs.len();
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for h in &hs {
            let s = slug(h, keep_underscore);
            if s.is_empty() {
                continue;
            }
            if let Some(first) = seen.get(&s) {
                clashes.push(format!(
                    "{}: \"{h}\" and \"{first}\" both mint #{s}",
                    rel(&path)
                ));
            } else {
                seen.insert(s, h.clone());
            }
        }
    }
    (clashes, pages, total)
}

// ---------------------------------------------------------------------------
// Scan 3: an exemption written beside a hardcoded list
// ---------------------------------------------------------------------------

/// The comment phrases that recorded a state as unreachable-and-accepted.
const EXEMPTION_PHRASES: &[&str] = &[
    "has no transition into it yet",
    "is only ever an initial state",
    "are only ever initial states",
];

/// Below this, a hardcoded list of states is an EXCEPTION list rather than a
/// stand-in for the derived set.
///
/// `INITIAL_ONLY = &[DialogState::Trying]` is one named exception whose own
/// assertion checks it. The list that hid the bug held nine, which is not an
/// exception list — it is the answer the sweep was supposed to compute.
const EXEMPTION_LIST_CEILING: usize = 3;

/// Exemption comments in `src` that sit beside a hardcoded state list.
///
/// Pure over text so it can be driven from both sides: the shape it must
/// catch, and the shape it must not.
///
/// Comment blocks are joined and whitespace-collapsed before the phrases are
/// searched, because the sentence that hid the bug wrapped across lines — a
/// line-oriented search would have matched none of it.
fn exemptions_beside_a_hardcoded_list(src: &str) -> Vec<String> {
    let list_re = regex::Regex::new(
        r"\[\s*DialogState::[A-Za-z0-9_]+\s*(?:,\s*DialogState::[A-Za-z0-9_]+\s*)*,?\s*\]",
    )
    .expect("list regex");
    let variant_re = regex::Regex::new(r"DialogState::[A-Za-z0-9_]+").expect("variant regex");
    let lines: Vec<&str> = src.lines().collect();

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        if !lines[i].trim_start().starts_with("//") {
            i += 1;
            continue;
        }
        let start = i;
        let mut text = String::new();
        while i < lines.len() && lines[i].trim_start().starts_with("//") {
            let t = lines[i].trim_start().trim_start_matches('/');
            text.push_str(t.trim());
            text.push(' ');
            i += 1;
        }
        let end = i - 1;
        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let Some(phrase) = EXEMPTION_PHRASES.iter().find(|p| collapsed.contains(**p)) else {
            continue;
        };
        // The window stands in for "the item this comment documents".
        let lo = start.saturating_sub(40);
        let hi = (end + 41).min(lines.len());
        let window = lines[lo..hi].join("\n");
        for m in list_re.find_iter(&window) {
            let n = variant_re.find_iter(m.as_str()).count();
            if n >= EXEMPTION_LIST_CEILING {
                out.push(format!(
                    "lines {}-{}: \"{phrase}\" is recorded beside a hardcoded \
                     list of {n} states",
                    start + 1,
                    end + 1
                ));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scan 4: DialogState variants and what produces them
// ---------------------------------------------------------------------------

/// Every variant of `DialogState`, read out of the enum in `src/sip/dialog.rs`.
fn dialog_state_variants() -> Vec<String> {
    let src = read(&repo().join("src/sip/dialog.rs"));
    let at = src
        .find("pub enum DialogState {")
        .expect("src/sip/dialog.rs no longer declares `pub enum DialogState`");
    let body = &src[at..];
    let end = body
        .find("\n}")
        .expect("the DialogState enum has no closing brace");
    body[..end]
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_suffix(','))
        .filter(|n| {
            n.starts_with(|c: char| c.is_ascii_uppercase()) && n.chars().all(char::is_alphanumeric)
        })
        .map(str::to_string)
        .collect()
}

/// For each variant, the production sites that produce it.
///
/// Production only: unit tests assign states freely, and a state produced
/// nowhere but a test is exactly the hole incident 4 was. `Trying`'s only
/// match under the three assignment forms is `d.state = DialogState::Trying`
/// inside `src/sip/dialog.rs`'s own test module, so the match-arm form —
/// `_ => DialogState::Trying` in the initial-state dispatch — is scanned too.
fn dialog_state_producers(variants: &[String]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> =
        variants.iter().map(|v| (v.clone(), Vec::new())).collect();
    for path in files_under("src", "rs") {
        let full = read(&path);
        let prod = source_scan::production_source(&full);
        for v in variants {
            let forms = [
                format!("Cell::To(DialogState::{v})"),
                format!("state = DialogState::{v}"),
                format!("state: DialogState::{v}"),
                format!("=> DialogState::{v}"),
            ];
            for form in forms {
                if prod.contains(&form) {
                    out.get_mut(v)
                        .expect("variant key")
                        .push(format!("{} ({form})", rel(&path)));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scan 5: the MCP tool index
// ---------------------------------------------------------------------------

/// Every tool name registered under `src/mcp/`, and the files walked.
fn registered_mcp_tools() -> (BTreeSet<String>, usize) {
    let re = regex::Regex::new(r#"(?m)^\s+name = "([a-z0-9_]+)","#).expect("registration regex");
    let files = files_under("src/mcp", "rs");
    let mut names = BTreeSet::new();
    for path in &files {
        for c in re.captures_iter(&read(path)) {
            names.insert(c[1].to_string());
        }
    }
    (names, files.len())
}

/// Every tool named in the index of `docs/mcp-tools.md`.
///
/// The index is EIGHT tables, one per category. It runs from the first
/// `| Tool | Parameters | Returns |` header to the first `## ` section
/// heading, and ALL of it is read — slicing to the first blank line stopped at
/// the end of table one and reported forty-one tools as undocumented.
///
/// A row's name may be plain or a link into the tool's own section, so both
/// spellings are matched: pinning the plain form alone made a formatting
/// change read as every tool disappearing.
fn documented_mcp_tools() -> BTreeSet<String> {
    let doc = read(&repo().join("docs/mcp-tools.md"));
    let start = doc
        .find("| Tool | Parameters | Returns |")
        .expect("docs/mcp-tools.md has no tool table");
    let end = doc[start..].find("\n## ").map_or(doc.len(), |i| start + i);
    regex::RegexBuilder::new(r"^\| \[?`([a-z0-9_]+)`")
        .multi_line(true)
        .build()
        .expect("row regex")
        .captures_iter(&doc[start..end])
        .map(|c| c[1].to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Documented floors. Each is the measured value, rounded down hard.
// ---------------------------------------------------------------------------

/// Symbol claims found across `tests/*.rs`. Measured: 3.
const MIN_SYMBOL_CLAIMS: usize = 3;
/// `src/…` reads those claims are paired against. Measured: 9.
const MIN_SRC_READS: usize = 5;
/// Pages under `docs/` carrying at least one heading. Measured: 96.
const MIN_DOC_PAGES: usize = 40;
/// Headings under `docs/`. Measured: 1790.
const MIN_DOC_HEADINGS: usize = 500;
/// Variants of `DialogState`. Measured: 13.
const MIN_DIALOG_STATES: usize = 10;
/// Files walked under `src/mcp/`. Measured: 27.
const MIN_MCP_FILES: usize = 10;
/// Tools registered under `src/mcp/`. Measured: 51.
const MIN_MCP_TOOLS: usize = 40;

// ---------------------------------------------------------------------------
// The gates
// ---------------------------------------------------------------------------

/// Every gate that says "symbol X exists in file Y" can still find X.
///
/// Incident 1. `docs_drift_test::sip_parameter_claims_match_the_parser`
/// justifies a documented parsing claim by the presence of a named function in
/// a named source file. That coupling is legitimate — the alternative is a
/// documentation claim nothing grounds — but it breaks on a rename, and it
/// breaks by accusing the DOCS of overstating support when what actually
/// happened is that a function moved and gained a better name.
///
/// So this asks the question one level up: for every such claim in the test
/// tree, does the named function exist anywhere under `src/` today? A claim
/// whose symbol is gone everywhere is a gate about to fire for the wrong
/// reason, and the failure below says which one and where.
///
/// The scan's limits are documented on `symbol_claims`. It is conservative by
/// construction: a claim it cannot see is uncovered, never falsely accused.
#[test]
fn every_symbol_a_gate_names_in_a_source_file_still_exists() {
    let (claims, _) = symbol_claims();
    assert!(
        claims.len() >= MIN_SYMBOL_CLAIMS,
        "the symbol-claim scan found only {} claim(s); its pattern no longer \
         matches how a gate names a symbol, so the check below is empty",
        claims.len()
    );

    let mut missing = Vec::new();
    for c in &claims {
        if defining_files(&c.symbol).is_empty() {
            missing.push(format!(
                "  {}:{} names `fn {}`, which is defined nowhere under src/",
                c.file, c.line, c.symbol
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "these gates justify a claim by a symbol that no longer exists:\n{}\n\n\
         The symbol moved or was renamed; the claim it grounds is probably \
         still true. Repoint the gate at the new name in the same commit as \
         the rename — do not delete the claim, and do not weaken the gate to \
         a substring.",
        missing.join("\n")
    );
}

/// No page under `docs/` mints the same GitHub anchor twice.
///
/// Incident 3. A duplicate does not fail to render: GitHub appends `-1`, `-2`
/// in DOCUMENT ORDER, so the link resolves at whichever heading is second
/// today and quietly moves when one is inserted above.
///
/// This DELIBERATELY duplicates
/// `link_integrity_test::no_page_mints_a_positional_anchor`, and the
/// duplication is the point rather than an oversight. That gate is the one to
/// keep; this one exists to answer whether an independently written
/// slugifier, an independently written fence stripper and an independent walk
/// reach the same verdict on the same tree. Two implementations agreeing is
/// evidence; one implementation agreeing with itself is not. If they ever
/// disagree, the bug is in a slug rule and both messages will point at the
/// same page.
///
/// Checked under both the strict rule (no underscores, this repository's
/// task-spec form) and GitHub's own (underscores kept), because a collision
/// under either is a broken bookmark for the readers using that renderer.
#[test]
fn no_docs_page_mints_two_headings_with_the_same_github_slug() {
    // The slugifier first, on the cases that make it non-obvious. A slug
    // function that returned the empty string for everything would report a
    // tree with no collisions, since empty slugs are skipped.
    assert_eq!(
        slug("Survey — what is in this capture", false),
        "survey--what-is-in-this-capture",
        "a spaced em-dash must leave BOTH its surrounding spaces as hyphens; \
         collapsing them would make this gate disagree with GitHub about every \
         heading written with one"
    );
    assert_eq!(
        slug("GET /v1/dialogs", false),
        "get-v1dialogs",
        "punctuation is dropped without leaving a separator"
    );
    assert_eq!(
        slug("`get_message`", true),
        "get_message",
        "backticks are dropped and underscores survive under GitHub's rule"
    );
    assert_eq!(
        slug("`get_message`", false),
        "getmessage",
        "the strict rule drops underscores too, which is why it flags a \
         superset of GitHub's collisions"
    );

    // The gate this reproduces must still be there. Deleting it should be a
    // visible act, not a quiet narrowing that leaves this copy alone.
    let peer = read(&repo().join("tests/link_integrity_test.rs"));
    assert!(
        peer.contains("fn no_page_mints_a_positional_anchor"),
        "tests/link_integrity_test.rs no longer defines the anchor gate this \
         test cross-checks; one of the two must be the primary"
    );

    for keep_underscore in [false, true] {
        let (clashes, pages, total) = slug_clashes(keep_underscore);
        assert!(
            pages >= MIN_DOC_PAGES && total >= MIN_DOC_HEADINGS,
            "the walk found {pages} page(s) and {total} heading(s) under \
             docs/; the fence stripper or the heading regex broke, so this \
             gate examined almost nothing"
        );
        assert!(
            clashes.is_empty(),
            "headings that slugify to one anchor (underscores kept: \
             {keep_underscore}):\n  {}\n\n\
             Both get the same `#anchor`, and the second silently becomes \
             `-1` in document order — every saved link to the pair moves the \
             next time a heading is inserted above. Rename one.",
            clashes.join("\n  ")
        );
    }
}

/// The dialog state machine records no exemption beside a hardcoded list.
///
/// Incident 4, pinned at the exact shape that hid it. The sweep asserted a
/// hardcoded list of nine reachable states and its comment carried the rest as
/// accepted — "`Expired` has no transition into it yet", "`Trying` and
/// `Pending` are only ever initial states". Two of those three were real
/// defects, and they were invisible precisely because they were written down.
/// A gate that names its own gap stops being a gate for that gap.
///
/// The general form of "derive, do not hardcode" is
/// `every_dialog_state_variant_is_produced_by_production_code`. This is the
/// specific form: an exemption phrase within forty lines of a hardcoded list
/// of three or more `DialogState` variants. One named exception whose own
/// assertion checks it — today's `INITIAL_ONLY = &[DialogState::Trying]` — is
/// the shape that is FINE, and the second half of this test requires that
/// exception to still be checked rather than merely declared.
///
/// The scanner is driven from both sides below, because a scanner that matches
/// nothing agrees with any file.
#[test]
fn the_state_machine_records_no_exemption_beside_a_hardcoded_destination_list() {
    // Built by concatenation: a fixture line must never start with the test
    // marker, and the same discipline keeps this fixture out of any
    // line-oriented scan of the real tree.
    let bad = String::new()
        + "// `Expired` has no transition into it yet (nothing parses a\n"
        + "// REGISTER expiry), and `Trying` and `Pending`\n"
        + "// are only ever initial states set by `SipDialog::new`.\n"
        + "const REACHABLE: &[DialogState] = &[\n"
        + "    DialogState::Ringing,\n"
        + "    DialogState::InCall,\n"
        + "    DialogState::Completed,\n"
        + "    DialogState::Canceled,\n"
        + "];\n";
    assert!(
        !exemptions_beside_a_hardcoded_list(&bad).is_empty(),
        "the scanner did not flag the exact shape it exists for; it would \
         agree with any file, including the one that shipped the bug"
    );

    let ok = String::new()
        + "// Only `Trying` is genuinely initial-only, and the assertion below\n"
        + "// checks that claim rather than resting on it: it is only ever an\n"
        + "// initial state, so nothing may produce it.\n"
        + "const INITIAL_ONLY: &[DialogState] = &[DialogState::Trying];\n";
    assert!(
        exemptions_beside_a_hardcoded_list(&ok).is_empty(),
        "one named exception, checked by its own assertion, is the shape that \
         is correct — a scanner that flags it will be narrowed until it flags \
         nothing"
    );

    let path = repo().join("src/sip/dialog_state_machine.rs");
    let src = read(&path);
    assert!(
        src.contains("DialogState::"),
        "src/sip/dialog_state_machine.rs no longer names DialogState; this \
         gate is reading the wrong file"
    );
    let found = exemptions_beside_a_hardcoded_list(&src);
    assert!(
        found.is_empty(),
        "src/sip/dialog_state_machine.rs records a known gap as an accepted \
         exemption beside a hardcoded list:\n  {}\n\n\
         That is how a phone reporting `Registered` after it unregistered sat \
         inside a passing test. Derive the set of reachable destinations from \
         the table instead, and keep only exceptions small enough that each \
         one carries its own assertion.",
        found.join("\n  ")
    );

    // And the exception that survived must still be checked, not just named.
    if src.contains("INITIAL_ONLY") {
        assert!(
            regex::Regex::new(r"!\s*reached\.contains\(")
                .expect("assertion regex")
                .is_match(&src),
            "INITIAL_ONLY is declared but nothing asserts its members are \
             UNREACHABLE. An exemption that is not itself checked is the \
             defect this test exists for, wearing a shorter list."
        );
    }
}

/// Every `DialogState` variant is produced by production code.
///
/// The general form of incident 4. The variant list is derived from the enum
/// in `src/sip/dialog.rs`, so adding a state adds an obligation here rather
/// than needing a constant to be bumped — which is exactly what the hardcoded
/// list of nine failed to do when `Expired` and `Pending` were added.
///
/// A state nothing produces is indistinguishable from a typo, and it reads as
/// covered in every list that names it: the filter DSL accepts it, the TUI has
/// a color for it, the docs describe it, and no capture can ever show it.
///
/// Production only. `#[cfg(test)]` modules assign states directly, so counting
/// them would have certified `Expired` as produced during the whole period
/// nothing produced it.
#[test]
fn every_dialog_state_variant_is_produced_by_production_code() {
    let variants = dialog_state_variants();
    assert!(
        variants.len() >= MIN_DIALOG_STATES,
        "read only {} DialogState variant(s) from src/sip/dialog.rs — the enum \
         parse broke, so this gate is asking about almost nothing: {variants:?}",
        variants.len()
    );
    assert!(
        variants.iter().any(|v| v == "Expired"),
        "the variant whose absence this gate was built for is not in the \
         parsed list, so the parse is wrong: {variants:?}"
    );

    let producers = dialog_state_producers(&variants);
    let orphans: Vec<&String> = variants
        .iter()
        .filter(|v| producers.get(*v).is_some_and(Vec::is_empty))
        .collect();
    assert!(
        orphans.is_empty(),
        "no production code produces these dialog states: {orphans:?}\n\n\
         Searched for `Cell::To(DialogState::X)`, `state = DialogState::X`, \
         `state: DialogState::X` and `=> DialogState::X` across src/, with \
         each file's `#[cfg(test)]` module removed. Either wire the state up \
         or delete it — a declared state nothing reaches is reported as \
         supported everywhere and observed nowhere, which is how a phone that \
         unregistered kept reporting `Registered`."
    );
}

/// The MCP tool index lists every registered tool, across all its tables.
///
/// Incident 2. Ground truth is the registration under `src/mcp/`, never a
/// second list. Two couplings are what broke before and both are pinned here:
/// the walk reads the WHOLE of `src/mcp/` recursively, because eleven of the
/// twelve tools in one batch landed outside `server.rs` and a scanner reading
/// one file certified 38 while 51 answered calls; and the index slice runs to
/// the first `## ` heading rather than the first blank line, because the index
/// became eight tables and a blank-line slice read only the first.
#[test]
fn the_mcp_tool_index_lists_every_registered_tool_across_all_its_tables() {
    let (registered, files) = registered_mcp_tools();
    assert!(
        files >= MIN_MCP_FILES && registered.len() >= MIN_MCP_TOOLS,
        "the walk found {} registration(s) across {files} file(s) under \
         src/mcp/ — it is not reaching the router submodules, so every count \
         it produces is a floor rather than a total",
        registered.len()
    );

    let documented = documented_mcp_tools();
    assert!(
        documented.len() >= MIN_MCP_TOOLS,
        "the index extractor found only {} row(s) — its pattern no longer \
         matches the table's markup, so the comparison below is meaningless: \
         {documented:?}",
        documented.len()
    );

    let missing: Vec<&String> = registered.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "these tools answer calls and appear in no index table: {missing:?}\n\n\
         Add a row to the table for the tool's category in docs/mcp-tools.md. \
         The index is read from the first `| Tool | Parameters | Returns |` \
         header to the first `## ` heading, so a new CATEGORY table needs no \
         change here — a new tool does."
    );

    let stale: Vec<&String> = documented.difference(&registered).collect();
    assert!(
        stale.is_empty(),
        "the index advertises tools nothing registers: {stale:?}\n\n\
         A caller reading the page gets `method not found`. Remove the row, or \
         restore the registration it describes."
    );
}

/// Every scan in this file found a plausible number of items.
///
/// The scans above are the instruments, and an instrument that cannot run
/// looks exactly like one that found nothing wrong. Each floor below is the
/// measured value rounded hard down, so ordinary growth never touches it and a
/// broken walk, a stale regex or a moved file fails HERE — naming the scan —
/// rather than reporting a clean tree from every gate at once.
///
/// A floor moving down is the alarm this exists for: attribute the drop per
/// file before touching the number.
#[test]
fn every_scan_in_this_file_found_a_plausible_number_of_items() {
    let mut report = Vec::new();

    let (claims, reads) = symbol_claims();
    report.push(format!("symbol claims: {}", claims.len()));
    report.push(format!("src reads paired against: {reads}"));
    assert!(
        claims.len() >= MIN_SYMBOL_CLAIMS,
        "symbol-claim scan found {} claim(s), floor {MIN_SYMBOL_CLAIMS} \
         (measured 3). A gate naming `fn X` in a src file went unread.",
        claims.len()
    );
    assert!(
        reads >= MIN_SRC_READS,
        "symbol-claim scan paired against {reads} src read(s), floor \
         {MIN_SRC_READS} (measured 9). The read-site pattern stopped matching, \
         so no claim can be found near one."
    );

    let (_, pages, total) = slug_clashes(false);
    report.push(format!("doc pages: {pages}, headings: {total}"));
    assert!(
        pages >= MIN_DOC_PAGES,
        "heading scan reached {pages} page(s), floor {MIN_DOC_PAGES} \
         (measured 96). The docs walk broke."
    );
    assert!(
        total >= MIN_DOC_HEADINGS,
        "heading scan read {total} heading(s), floor {MIN_DOC_HEADINGS} \
         (measured 1790). The fence stripper is eating the pages, or the \
         heading regex stopped matching."
    );

    let variants = dialog_state_variants();
    report.push(format!("DialogState variants: {}", variants.len()));
    assert!(
        variants.len() >= MIN_DIALOG_STATES,
        "enum parse read {} variant(s), floor {MIN_DIALOG_STATES} \
         (measured 13). The enum moved or changed shape.",
        variants.len()
    );
    let producers = dialog_state_producers(&variants);
    let sites: usize = producers.values().map(Vec::len).sum();
    report.push(format!("state producer sites: {sites}"));
    assert!(
        sites >= variants.len(),
        "found {sites} production site(s) for {} state(s), which cannot be \
         right if every state is produced — the producer patterns stopped \
         matching and the orphan check would accuse the product.",
        variants.len()
    );

    let (registered, files) = registered_mcp_tools();
    let documented = documented_mcp_tools();
    report.push(format!(
        "MCP: {} registered across {files} file(s), {} documented",
        registered.len(),
        documented.len()
    ));
    assert!(
        files >= MIN_MCP_FILES,
        "MCP walk reached {files} file(s), floor {MIN_MCP_FILES} (measured \
         27). It is not descending into src/mcp/tools/."
    );
    assert!(
        registered.len() >= MIN_MCP_TOOLS && documented.len() >= MIN_MCP_TOOLS,
        "MCP scan found {} registration(s) and {} documented row(s), floor \
         {MIN_MCP_TOOLS} each (measured 51 and 51). One of the two patterns \
         stopped matching, and the comparison between them means nothing.\n{}",
        registered.len(),
        documented.len(),
        report.join("\n")
    );

    // The state-machine scanner has no corpus to size, so its liveness is
    // proved by the fixture in
    // `the_state_machine_records_no_exemption_beside_a_hardcoded_destination_list`;
    // what is checkable here is that the file it reads is still the one.
    let sm = read(&repo().join("src/sip/dialog_state_machine.rs"));
    assert!(
        sm.lines().count() > 200 && sm.contains("DialogState::"),
        "src/sip/dialog_state_machine.rs is {} line(s) and may no longer hold \
         the table; the exemption scan would be reading the wrong file.\n{}",
        sm.lines().count(),
        report.join("\n")
    );
}
