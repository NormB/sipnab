// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every number and key the homepage states is DERIVED from the thing it
//! describes.
//!
//! # Why a second homepage gate file exists
//!
//! `site_journey_test.rs` already gates the homepage's tiles. On 2026-09-12 an
//! audit of the live page found six claims wrong at once, and the shape of the
//! miss is the lesson: the MCP tool tile said 66 because a gate derived it, and
//! a sentence four sections down said 32 because nobody did. One page, two
//! numbers for one fact, both served to visitors.
//!
//! So these gates read the PROSE, not the tiles, and each one derives its
//! expected value from the source of the fact rather than from a second copy of
//! it. A claim that cannot be derived is a claim that goes stale silently, and
//! the front page is the worst place for that.

use std::collections::BTreeSet;
use std::path::Path;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file, panicking with the path on failure.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every `.rs` file under `src/mcp/`, concatenated.
///
/// The walk must leave `server.rs`: tools registered in the router submodules
/// answer calls exactly as much as ones written in `server.rs`, and a scanner
/// reading one file produces a floor that agrees with a stale page forever.
fn mcp_sources() -> String {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&repo().join("src/mcp"), &mut files);
    files.sort();
    assert!(
        files.len() >= 2,
        "the walk found {} file(s) under src/mcp — it is not reaching the \
         router submodules, so every count derived from it is a floor",
        files.len()
    );
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `(registered, read_only, write_capable)` tool counts from the attributes.
///
/// `read_only_hint = false` is counted only where it is an ATTRIBUTE argument,
/// never where a doc comment discusses one. `src/mcp/tools/compare.rs` explains
/// its own annotation in prose, and counting that line made the split 13 against
/// a registry of 66 — an off-by-one that reads as a missing tool.
fn mcp_tool_counts() -> (usize, usize, usize) {
    let src = mcp_sources();
    let registered = regex::Regex::new(r#"(?m)^\s+name = "[a-z0-9_]+","#)
        .expect("regex")
        .find_iter(&src)
        .count();
    // Counted on NON-COMMENT lines only. `src/mcp/tools/compare.rs` explains its
    // own annotation in a doc comment, and counting that line made the split 13
    // against a registry of 66 -- an off-by-one that reads as a missing tool.
    let hint = |needle: &str| {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(needle))
            .count()
    };
    let read_only = hint("read_only_hint = true");
    let write_capable = hint("read_only_hint = false");
    (registered, read_only, write_capable)
}

/// The homepage template.
fn homepage() -> String {
    read("website/templates/index.html")
}

/// The table row or card a marker sits in, not merely its line.
///
/// A capability table states its qualifier on the same line; a standards card
/// states it in an `<li>` several lines below the topic that names it. A gate
/// reading one line certifies the card as unqualified forever.
fn enclosing_block(html: &str, marker: &str) -> String {
    let at = html
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} anywhere on the homepage"));
    let start = html[..at].rfind('\n').map_or(0, |i| i + 1);
    let rest = &html[start..];
    let end = ["</tr>", "</div>"]
        .iter()
        .filter_map(|close| rest.find(close).map(|i| i + close.len()))
        .min()
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// The page with HTML and Tera comments removed.
///
/// A comment is not something a visitor reads, so a claim inside one is not a
/// claim the page makes. Both kinds are stripped: `{# … #}` carries the long
/// rationale notes this template is full of, and an HTML comment carries the
/// generated-block markers.
fn strip_comments(html: &str) -> String {
    let html = regex::Regex::new(r"(?s)<!--.*?-->")
        .expect("regex")
        .replace_all(html, "");
    regex::Regex::new(r"(?s)\{#.*?#\}")
        .expect("regex")
        .replace_all(&html, "")
        .into_owned()
}

// ── A. The MCP tool counts the page states in PROSE ──────────────────

/// The "N tools cover …" sentence equals the number of registered tools.
#[test]
fn homepage_prose_tool_count_matches_the_registry() {
    let (registered, _, _) = mcp_tool_counts();
    assert!(
        registered >= 20,
        "only {registered} tool registrations found — the pattern stopped \
         matching, so this gate is comparing the page against nothing"
    );
    let page = homepage();
    let re = regex::Regex::new(r"(\d+) tools cover").expect("regex");
    let stated: Vec<usize> = re
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"N tools cover\" sentence on the homepage, \
         found {}: {stated:?}. Two copies of one fact drift.",
        stated.len()
    );
    assert_eq!(
        stated[0], registered,
        "the homepage says {} MCP tools in prose while the server registers \
         {registered}. The tile is already derived; this sentence was not, and \
         the page served both numbers at once.",
        stated[0]
    );
}

/// The "N are read-only" sentence equals the `read_only_hint = true` count.
#[test]
fn homepage_read_only_split_matches_the_annotations() {
    let (registered, read_only, write_capable) = mcp_tool_counts();
    assert_eq!(
        read_only + write_capable,
        registered,
        "the read-only/write split ({read_only} + {write_capable}) does not \
         account for all {registered} registered tools — the annotation scan \
         is miscounting and no claim derived from it can be trusted"
    );
    let page = homepage();
    let re = regex::Regex::new(r"(\d+) are read-only").expect("regex");
    let stated: Vec<usize> = re
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"N are read-only\" sentence, found {}: {stated:?}",
        stated.len()
    );
    assert_eq!(
        stated[0], read_only,
        "the homepage says {} read-only MCP tools; {read_only} carry \
         `read_only_hint = true`",
        stated[0]
    );
}

/// The page's count of write-capable tools equals the annotations'.
///
/// Spelled as a digit word or a numeral: the sentence once read "the five that
/// write" while twelve did.
#[test]
fn homepage_write_capable_count_matches_the_annotations() {
    let (_, _, write_capable) = mcp_tool_counts();
    let page = homepage();
    let words = [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ];
    let re = regex::Regex::new(r"the ([a-z]+|\d+) that write").expect("regex");
    let stated: Vec<String> = re.captures_iter(&page).map(|c| c[1].to_string()).collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"the N that write\" phrase, found {}: {stated:?}",
        stated.len()
    );
    let stated_n = stated[0]
        .parse::<usize>()
        .ok()
        .or_else(|| words.iter().position(|w| *w == stated[0]))
        .unwrap_or_else(|| panic!("cannot read {:?} as a number", stated[0]));
    assert_eq!(
        stated_n, write_capable,
        "the homepage says {stated_n} write-capable MCP tools; \
         {write_capable} carry `read_only_hint = false`"
    );
}

// ── B. What the RELEASED binaries carry ──────────────────────────────

/// The published targets the release workflow compiles `bpf` into.
fn bpf_released_targets() -> Vec<String> {
    let wf = read(".github/workflows/release.yml");
    let idx = wf.find(r#"features="${features},bpf""#).unwrap_or_else(|| {
        panic!(
            "the release workflow no longer contains the literal \
             `features=\"${{features}},bpf\"` — the feature computation was \
             reshaped and this scan reads nothing, so any claim it certifies \
             is unfounded"
        )
    });
    // The `case` arm immediately above the assignment names the targets.
    wf[..idx]
        .lines()
        .rev()
        .take(4)
        .filter(|l| l.trim_end().ends_with(')') && l.contains('*'))
        .map(|l| l.trim().trim_end_matches(')').to_string())
        .collect()
}

/// The homepage must not say released binaries lack `bpf` while they carry it.
#[test]
fn homepage_bpf_claim_matches_the_release_workflow() {
    let targets = bpf_released_targets();
    assert!(
        !targets.is_empty(),
        "no target pattern found beside the bpf feature assignment in \
         .github/workflows/release.yml — the scan is reading the wrong lines"
    );
    let page = homepage();
    assert!(
        !page.contains("released binaries do not carry it"),
        "the homepage says released binaries do not carry the `bpf` feature, \
         but .github/workflows/release.yml compiles it into {targets:?}. A \
         visitor is being told a capability they already have is unavailable."
    );
}

/// Having established the released builds carry it, the page says which ones.
///
/// "Some released binaries carry it" is not actionable: the reader has to know
/// whether the artifact they downloaded is one of them. musl deliberately does
/// not carry it, so naming the family is the whole content of the claim.
#[test]
fn homepage_names_which_released_builds_carry_bpf() {
    let targets = bpf_released_targets();
    let family = if targets.iter().any(|t| t.contains("linux-gnu")) {
        "gnu"
    } else {
        panic!("bpf is compiled for {targets:?}, which this gate cannot name");
    };
    let page = homepage();
    let bpf_row = page
        .lines()
        .find(|l| l.contains("eBPF TLS capture"))
        .unwrap_or_else(|| panic!("no eBPF row on the homepage to check"));
    assert!(
        bpf_row.contains(family),
        "the homepage's eBPF row does not say which released builds carry the \
         feature. It is compiled for {targets:?}; the row must name the \
         {family} family so a reader can tell whether their download has it.\n\
         Row: {bpf_row}"
    );
}

/// musl is excluded on purpose, and the page must not imply otherwise.
#[test]
fn homepage_does_not_claim_bpf_for_the_static_musl_build() {
    let targets = bpf_released_targets();
    assert!(
        !targets.iter().any(|t| t.contains("musl")),
        "the release workflow now compiles `bpf` into a musl target ({targets:?}); \
         the homepage wording and this gate were written when it did not, so \
         both need revisiting rather than silently passing"
    );
}

// ── C. What the installer actually puts on a host ────────────────────

/// The installer script served from the site.
fn installer() -> String {
    read("website/static/install.sh")
}

/// The hero must not promise musl when the installer prefers gnu.
#[test]
fn hero_install_claim_matches_what_the_installer_selects() {
    let sh = installer();
    let prefers_gnu = sh.contains("unknown-linux-gnu.tar.gz");
    assert!(
        prefers_gnu,
        "install.sh no longer offers a gnu build — the hero's wording and this \
         gate were written against an installer that prefers one, so both need \
         revisiting rather than silently passing"
    );
    let page = homepage();
    let hero = page
        .lines()
        .find(|l| l.contains("hero-sub"))
        .unwrap_or_else(|| panic!("no hero-sub line on the homepage"));
    assert!(
        !hero.contains("One static musl binary"),
        "the hero promises \"One static musl binary\" while install.sh selects \
         the gnu build on every host at or above the glibc floor, and macOS \
         gets a Mach-O build that is not musl at all. Describe what the reader \
         is actually handed.\nHero: {hero}"
    );
}

/// "Zero dependencies" must not stand while the default build needs libpcap.
#[test]
fn hero_does_not_claim_zero_dependencies_while_the_default_build_links_one() {
    let sh = installer();
    assert!(
        sh.contains("needs libpcap"),
        "install.sh no longer says the gnu build needs libpcap — re-derive this \
         gate from whatever now states the dependency"
    );
    let page = homepage();
    let hero = page
        .lines()
        .find(|l| l.contains("hero-sub"))
        .unwrap_or_else(|| panic!("no hero-sub line on the homepage"));
    assert!(
        !hero.contains("zero dependencies"),
        "the hero claims zero dependencies while install.sh tells most Linux \
         hosts the build it chose \"needs libpcap: apt/dnf install libpcap\".\n\
         Hero: {hero}"
    );
}

/// The feature set the static musl tarballs are built with.
fn musl_feature_set() -> BTreeSet<String> {
    let wf = read(".github/workflows/release.yml");
    let line = wf
        .lines()
        .find(|l| l.trim_start().starts_with("noaudio_set="))
        .unwrap_or_else(|| {
            panic!(
                "no `noaudio_set=` assignment in .github/workflows/release.yml — \
                 the musl feature set is computed some other way now and this \
                 gate reads nothing"
            )
        });
    let set = line
        .split_once('=')
        .expect("an assignment has an =")
        .1
        .trim()
        .trim_matches('"');
    set.split(',').map(|s| s.trim().to_string()).collect()
}

/// A capability the static musl binary cannot perform is marked on the page.
///
/// The hero advertises one binary; the capability table lists what sipnab does.
/// `plugins` and `vcon` are in neither the musl tarballs nor the `-noaudio`
/// packages, so a row claiming them unconditionally describes a DIFFERENT
/// artifact from the one the hero points at.
#[test]
fn capabilities_missing_from_the_musl_build_say_so() {
    let features = musl_feature_set();
    assert!(
        features.contains("native") && features.contains("tui"),
        "the musl feature set scan produced {features:?}, which is not a \
         plausible feature list — it is reading the wrong line"
    );
    let page = homepage();
    // The rows that name a feature the static build lacks. Each must carry a
    // qualifier a reader can act on, in its own row.
    for (feature, row_marker) in [
        ("plugins", "WASM plugins"),
        ("vcon", "Virtualized Conversation"),
    ] {
        if features.contains(feature) {
            continue;
        }
        let row = enclosing_block(&page, row_marker);
        let qualified = row.contains("feature") || row.contains("musl") || row.contains("gnu");
        assert!(
            qualified,
            "the static musl build carries {features:?} and not `{feature}`, but \
             the {row_marker:?} row claims the capability with no qualification. \
             Say which builds carry it.\nRow: {row}"
        );
    }
}

// ── D. The filter language the page counts ───────────────────────────

/// `(distinct fields, accepted spellings, operators)` from `src/sip/dsl.rs`.
fn filter_dsl_shape() -> (usize, usize, usize) {
    let src = read("src/sip/dsl.rs");
    let variants = |enum_name: &str| -> usize {
        let start = src
            .find(&format!("enum {enum_name} {{"))
            .unwrap_or_else(|| panic!("no `enum {enum_name}` in src/sip/dsl.rs"));
        let body = &src[start..];
        let end = body
            .find("\n}")
            .unwrap_or_else(|| panic!("`enum {enum_name}` has no closing brace"));
        body[..end]
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.ends_with(',')
                    && !t.starts_with("//")
                    && t.chars().next().is_some_and(char::is_uppercase)
                    && t.trim_end_matches(',').chars().all(char::is_alphanumeric)
            })
            .count()
    };
    let fields = variants("Field");
    let operators = variants("Operator");
    // Accepted spellings: the `"name" => Field::X` arms, including the `|`
    // alternatives that make one field answer to two names.
    let spellings =
        regex::Regex::new(r#""([a-z0-9_.]+)"(?:\s*\|\s*"[a-z0-9_.]+")*\s*=>\s*Field::"#)
            .expect("regex")
            .find_iter(&src)
            .map(|m| m.as_str().matches('"').count() / 2)
            .sum();
    (fields, spellings, operators)
}

/// The homepage's operator count equals the operators the parser accepts.
#[test]
fn homepage_filter_operator_count_matches_the_parser() {
    let (_, _, operators) = filter_dsl_shape();
    assert!(
        operators >= 4,
        "only {operators} Operator variant(s) found — the enum scan stopped \
         matching and certifies any number the page prints"
    );
    let page = homepage();
    let re = regex::Regex::new(r"(\d+) operators").expect("regex");
    let stated: Vec<usize> = re
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"N operators\" claim on the homepage, found {}: {stated:?}",
        stated.len()
    );
    assert_eq!(
        stated[0], operators,
        "the homepage claims {} filter operators; the parser accepts {operators}",
        stated[0]
    );
}

/// The homepage's field count equals the field names the parser accepts.
#[test]
fn homepage_filter_field_count_matches_the_parser() {
    let (fields, spellings, _) = filter_dsl_shape();
    assert!(
        fields >= 20 && spellings >= fields,
        "the Field scan produced {fields} variant(s) and {spellings} spelling(s), \
         which cannot both be right — the extraction is broken"
    );
    let page = homepage();
    let re = regex::Regex::new(r"(\d+) fields").expect("regex");
    let stated: Vec<usize> = re
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"N fields\" claim on the homepage, found {}: {stated:?}",
        stated.len()
    );
    assert_eq!(
        stated[0], fields,
        "the homepage claims {} filter fields; the parser defines {fields} \
         (answering to {spellings} spellings, because an alias is not a field)",
        stated[0]
    );
}

/// Every operator the parser accepts appears in the filter DSL reference.
///
/// `in_subnet` shipped, parsed, matched addresses, and was in no document —
/// which is the same as not having shipped it.
#[test]
fn filter_doc_documents_every_operator_the_parser_accepts() {
    let src = read("src/sip/dsl.rs");
    let spellings: BTreeSet<String> =
        regex::Regex::new(r#"tag\("([^"]+)"\),\s*\|_\|\s*Operator::"#)
            .expect("regex")
            .captures_iter(&src)
            .map(|c| c[1].to_string())
            .collect();
    assert!(
        spellings.len() >= 4,
        "only {} operator spelling(s) extracted from the parser: {spellings:?}",
        spellings.len()
    );
    // In the operator TABLE, not anywhere in the file. Deleting the `in_subnet`
    // row while a note below still named it left this gate green -- a whole-file
    // substring is satisfied by a sentence saying an operator is NOT supported.
    let doc = read("docs/filter-dsl.md");
    let table: String = doc
        .lines()
        .skip_while(|l| !l.starts_with("## Operators"))
        .take_while(|l| !l.starts_with("## Values"))
        .filter(|l| l.trim_start().starts_with('|'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        table.lines().count() >= 6,
        "the operator table in docs/filter-dsl.md has {} row(s) — the section \
         headings moved and this gate is reading nothing",
        table.lines().count()
    );
    let missing: Vec<&String> = spellings
        .iter()
        .filter(|s| !table.contains(&format!("`{s}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "the parser accepts {missing:?}, which the operator table in \
         docs/filter-dsl.md does not list. An operator nobody documents is one \
         nobody can use."
    );
}

// ── E. The keys the page tells a reader to press ─────────────────────

/// Every `<kbd>` on the homepage, deduplicated.
fn kbd_labels() -> BTreeSet<String> {
    regex::Regex::new(r"<kbd>([^<]+)</kbd>")
        .expect("regex")
        .captures_iter(&homepage())
        .map(|c| c[1].to_string())
        .collect()
}

/// Every `.rs` file under `src/tui/`, concatenated.
fn tui_sources() -> String {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&repo().join("src/tui"), &mut files);
    files.sort();
    assert!(
        files.len() >= 5,
        "only {} file(s) under src/tui",
        files.len()
    );
    files
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every single-key `<kbd>` the homepage names is a key the TUI binds.
#[test]
fn every_tui_key_the_homepage_names_is_bound() {
    let tui = tui_sources();
    let mut unbound = Vec::new();
    for label in kbd_labels() {
        if label.starts_with('-') {
            continue; // a CLI flag, checked separately
        }
        let bound = if label.chars().count() == 1 {
            let c = label.chars().next().expect("one char");
            tui.contains(&format!("Char('{c}')"))
        } else {
            tui.contains(&format!("KeyCode::{label}"))
        };
        if !bound {
            unbound.push(label);
        }
    }
    assert!(
        unbound.is_empty(),
        "the homepage tells a reader to press {unbound:?}, and src/tui binds no \
         such key. A reader following the page presses it and nothing happens."
    );
}

/// The key scan is case-sensitive, which is the whole point of it.
///
/// The live page said `o` opens a capture while the binding is `O`. A scan that
/// folded case would have certified that, so this proves it does not.
#[test]
fn the_tui_key_scan_distinguishes_case() {
    let tui = tui_sources();
    assert!(
        tui.contains("Char('O')"),
        "src/tui no longer binds `O`; this gate's fixture is gone"
    );
    assert!(
        !tui.contains("Char('o')"),
        "src/tui now binds lowercase `o` as well — this gate proved case \
         mattered by relying on exactly one of the pair existing, so rewrite it \
         against a pair that still differs rather than deleting it"
    );
}

/// The `<kbd>` extraction finds the keys the page actually carries.
///
/// A regex that matched nothing would let every key claim pass.
#[test]
fn the_kbd_scan_reads_the_homepage() {
    let labels = kbd_labels();
    assert!(
        labels.len() >= 5,
        "only {} <kbd> element(s) found on the homepage: {labels:?} — the \
         markup changed and the key gates above certify nothing",
        labels.len()
    );
    assert!(
        labels.iter().any(|l| l.chars().count() == 1),
        "no single-character <kbd> found: {labels:?} — the TUI key gate has \
         nothing to check"
    );
    assert!(
        labels.iter().any(|l| l.starts_with("--")),
        "no flag-shaped <kbd> found: {labels:?} — the CLI flag gate has \
         nothing to check"
    );
}

// ── F. One fact, one number, and flags that exist ────────────────────

/// The MCP tile and the MCP prose state the same number.
///
/// This is the defect that produced this file: both were on one page, 66 and
/// 32, and each had a gate or an author who believed it.
#[test]
fn every_homepage_statement_of_the_tool_count_agrees() {
    let page = homepage();
    let tile: Vec<usize> = regex::Regex::new(r#"data-count="(\d+)" data-suffix=" MCP tools""#)
        .expect("regex")
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    let prose: Vec<usize> = regex::Regex::new(r"(\d+) tools cover")
        .expect("regex")
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(tile.len(), 1, "expected one MCP tile, found {tile:?}");
    assert_eq!(prose.len(), 1, "expected one prose count, found {prose:?}");
    assert_eq!(
        tile[0], prose[0],
        "the homepage's MCP tile says {} and its prose says {} — one page, one \
         fact, two numbers",
        tile[0], prose[0]
    );
}

/// Every CLI flag the homepage names is a flag the CLI defines.
#[test]
fn no_homepage_claim_names_a_flag_the_cli_does_not_define() {
    let cli = read("src/cli.rs");
    let page = homepage();
    // Flags the page shows a reader, which is `<code>` and `<kbd>` bodies and
    // nothing else. Reading the whole file swept up the CSS modifier classes
    // `feature-card--amber`, `--blue` and `--green` and the `--check` inside a
    // build comment, and reported four flags the CLI has never had. A scanner's
    // first red was its own bug, which is the usual way.
    let visible = strip_comments(&page);
    // Two patterns, not one with a backreference: the `regex` crate has none,
    // and `</\1>` compiled to a syntax error rather than to a wrong answer.
    let bodies_of = |tag: &str| -> String {
        regex::Regex::new(&format!(r"(?s)<{tag}\b[^>]*>(.*?)</{tag}>"))
            .expect("regex")
            .captures_iter(&visible)
            .map(|c| c[1].to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    let bodies = format!("{}\n{}", bodies_of("code"), bodies_of("kbd"));
    let flags: BTreeSet<String> = regex::Regex::new(r"--([a-z][a-z0-9-]{2,})")
        .expect("regex")
        .captures_iter(&bodies)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        flags.len() >= 3,
        "only {} flag(s) found on the homepage: {flags:?} — the scan is not \
         reading the page",
        flags.len()
    );
    let defined = |flag: &str| {
        let field = flag.replace('-', "_");
        cli.contains(&format!(r#"long = "{flag}""#)) || cli.contains(&format!("pub {field}:"))
    };
    let missing: Vec<&String> = flags.iter().filter(|f| !defined(f)).collect();
    assert!(
        missing.is_empty(),
        "the homepage names {missing:?}, which src/cli.rs defines no flag for. \
         A reader copying the page gets `unexpected argument`."
    );
}

/// Every docs page the capability table links to exists.
#[test]
fn every_capability_row_links_to_a_page_that_exists() {
    let page = homepage();
    let links: BTreeSet<String> = regex::Regex::new(r"get_url\(path='@/([^']+)'\)")
        .expect("regex")
        .captures_iter(&page)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        links.len() >= 8,
        "only {} internal link(s) found on the homepage: {links:?}",
        links.len()
    );
    let missing: Vec<&String> = links
        .iter()
        .filter(|rel| !repo().join("website/content").join(rel).exists())
        .collect();
    assert!(
        missing.is_empty(),
        "the homepage links to {missing:?}, which do not exist under \
         website/content — the row is advertising a page that 404s"
    );
}
