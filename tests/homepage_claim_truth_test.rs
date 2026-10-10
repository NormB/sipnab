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

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file; the error names the path.
fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
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
fn mcp_tool_counts() -> Result<(usize, usize, usize), TestError> {
    let src = mcp_sources();
    let registered = regex::Regex::new(r#"(?m)^\s+name = "[a-z0-9_]+","#)?
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
    Ok((registered, read_only, write_capable))
}

/// The homepage template.
fn homepage() -> Result<String, TestError> {
    read("website/templates/index.html")
}

/// The table row or card a marker sits in, not merely its line.
///
/// A capability table states its qualifier on the same line; a standards card
/// states it in an `<li>` several lines below the topic that names it. A gate
/// reading one line certifies the card as unqualified forever.
fn enclosing_block(html: &str, marker: &str) -> Result<String, TestError> {
    let at = html
        .find(marker)
        .ok_or_else(|| format!("no {marker:?} anywhere on the homepage"))?;
    let start = html[..at].rfind('\n').map_or(0, |i| i + 1);
    let rest = &html[start..];
    let end = ["</tr>", "</div>"]
        .iter()
        .filter_map(|close| rest.find(close).map(|i| i + close.len()))
        .min()
        .unwrap_or(rest.len());
    Ok(rest[..end].to_string())
}

/// The page with HTML and Tera comments removed.
///
/// A comment is not something a visitor reads, so a claim inside one is not a
/// claim the page makes. Both kinds are stripped: `{# … #}` carries the long
/// rationale notes this template is full of, and an HTML comment carries the
/// generated-block markers.
fn strip_comments(html: &str) -> Result<String, TestError> {
    let html = regex::Regex::new(r"(?s)<!--.*?-->")?.replace_all(html, "");
    Ok(regex::Regex::new(r"(?s)\{#.*?#\}")?
        .replace_all(&html, "")
        .into_owned())
}

// ── A. The MCP tool counts the page states in PROSE ──────────────────

/// The "N tools cover …" sentence equals the number of registered tools.
#[test]
fn homepage_prose_tool_count_matches_the_registry() -> Result<(), TestError> {
    let (registered, _, _) = mcp_tool_counts()?;
    assert!(
        registered >= 20,
        "only {registered} tool registrations found — the pattern stopped \
         matching, so this gate is comparing the page against nothing"
    );
    let page = homepage()?;
    let re = regex::Regex::new(r"(\d+) tools cover")?;
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
    Ok(())
}

/// The "N are read-only" sentence equals the `read_only_hint = true` count.
#[test]
fn homepage_read_only_split_matches_the_annotations() -> Result<(), TestError> {
    let (registered, read_only, write_capable) = mcp_tool_counts()?;
    assert_eq!(
        read_only + write_capable,
        registered,
        "the read-only/write split ({read_only} + {write_capable}) does not \
         account for all {registered} registered tools — the annotation scan \
         is miscounting and no claim derived from it can be trusted"
    );
    let page = homepage()?;
    let re = regex::Regex::new(r"(\d+) are read-only")?;
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
    Ok(())
}

/// The page's count of write-capable tools equals the annotations'.
///
/// Spelled as a digit word or a numeral: the sentence once read "the five that
/// write" while twelve did.
#[test]
fn homepage_write_capable_count_matches_the_annotations() -> Result<(), TestError> {
    let (_, _, write_capable) = mcp_tool_counts()?;
    let page = homepage()?;
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
    let re = regex::Regex::new(r"the ([a-z]+|\d+) that write")?;
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
        .ok_or_else(|| format!("cannot read {:?} as a number", stated[0]))?;
    assert_eq!(
        stated_n, write_capable,
        "the homepage says {stated_n} write-capable MCP tools; \
         {write_capable} carry `read_only_hint = false`"
    );
    Ok(())
}

// ── B. What the RELEASED binaries carry ──────────────────────────────

/// The published targets the release workflow compiles `bpf` into.
fn bpf_released_targets() -> Result<Vec<String>, TestError> {
    let wf = read(".github/workflows/release.yml")?;
    let idx = wf.find(r#"features="${features},bpf""#).ok_or(
        "the release workflow no longer contains the literal \
         `features=\"${features},bpf\"` — the feature computation was \
         reshaped and this scan reads nothing, so any claim it certifies \
         is unfounded",
    )?;
    // The `case` arm immediately above the assignment names the targets.
    Ok(wf[..idx]
        .lines()
        .rev()
        .take(4)
        .filter(|l| l.trim_end().ends_with(')') && l.contains('*'))
        .map(|l| l.trim().trim_end_matches(')').to_string())
        .collect())
}

/// The homepage must not say released binaries lack `bpf` while they carry it.
#[test]
fn homepage_bpf_claim_matches_the_release_workflow() -> Result<(), TestError> {
    let targets = bpf_released_targets()?;
    assert!(
        !targets.is_empty(),
        "no target pattern found beside the bpf feature assignment in \
         .github/workflows/release.yml — the scan is reading the wrong lines"
    );
    let page = homepage()?;
    assert!(
        !page.contains("released binaries do not carry it"),
        "the homepage says released binaries do not carry the `bpf` feature, \
         but .github/workflows/release.yml compiles it into {targets:?}. A \
         visitor is being told a capability they already have is unavailable."
    );
    Ok(())
}

/// Having established the released builds carry it, the page says which ones.
///
/// "Some released binaries carry it" is not actionable: the reader has to know
/// whether the artifact they downloaded is one of them. musl deliberately does
/// not carry it, so naming the family is the whole content of the claim.
#[test]
fn homepage_names_which_released_builds_carry_bpf() -> Result<(), TestError> {
    let targets = bpf_released_targets()?;
    let family = if targets.iter().any(|t| t.contains("linux-gnu")) {
        "gnu"
    } else {
        return Err(format!("bpf is compiled for {targets:?}, which this gate cannot name").into());
    };
    let page = homepage()?;
    let bpf_row = page
        .lines()
        .find(|l| l.contains("eBPF TLS capture"))
        .ok_or("no eBPF row on the homepage to check")?;
    assert!(
        bpf_row.contains(family),
        "the homepage's eBPF row does not say which released builds carry the \
         feature. It is compiled for {targets:?}; the row must name the \
         {family} family so a reader can tell whether their download has it.\n\
         Row: {bpf_row}"
    );
    Ok(())
}

/// musl is excluded on purpose, and the page must not imply otherwise.
#[test]
fn homepage_does_not_claim_bpf_for_the_static_musl_build() -> Result<(), TestError> {
    let targets = bpf_released_targets()?;
    assert!(
        !targets.iter().any(|t| t.contains("musl")),
        "the release workflow now compiles `bpf` into a musl target ({targets:?}); \
         the homepage wording and this gate were written when it did not, so \
         both need revisiting rather than silently passing"
    );
    Ok(())
}

// ── C. What the installer actually puts on a host ────────────────────

/// The installer script served from the site.
fn installer() -> Result<String, TestError> {
    read("website/static/install.sh")
}

/// The hero must not promise musl when the installer prefers gnu.
#[test]
fn hero_install_claim_matches_what_the_installer_selects() -> Result<(), TestError> {
    let sh = installer()?;
    let prefers_gnu = sh.contains("unknown-linux-gnu.tar.gz");
    assert!(
        prefers_gnu,
        "install.sh no longer offers a gnu build — the hero's wording and this \
         gate were written against an installer that prefers one, so both need \
         revisiting rather than silently passing"
    );
    let page = homepage()?;
    let hero = page
        .lines()
        .find(|l| l.contains("hero-sub"))
        .ok_or("no hero-sub line on the homepage")?;
    assert!(
        !hero.contains("One static musl binary"),
        "the hero promises \"One static musl binary\" while install.sh selects \
         the gnu build on every host at or above the glibc floor, and macOS \
         gets a Mach-O build that is not musl at all. Describe what the reader \
         is actually handed.\nHero: {hero}"
    );
    Ok(())
}

/// "Zero dependencies" must not stand while the default build needs libpcap.
#[test]
fn hero_does_not_claim_zero_dependencies_while_the_default_build_links_one() -> Result<(), TestError>
{
    let sh = installer()?;
    assert!(
        sh.contains("needs libpcap"),
        "install.sh no longer says the gnu build needs libpcap — re-derive this \
         gate from whatever now states the dependency"
    );
    let page = homepage()?;
    let hero = page
        .lines()
        .find(|l| l.contains("hero-sub"))
        .ok_or("no hero-sub line on the homepage")?;
    assert!(
        !hero.contains("zero dependencies"),
        "the hero claims zero dependencies while install.sh tells most Linux \
         hosts the build it chose \"needs libpcap: apt/dnf install libpcap\".\n\
         Hero: {hero}"
    );
    Ok(())
}

/// The feature set the static musl tarballs are built with.
fn musl_feature_set() -> Result<BTreeSet<String>, TestError> {
    let wf = read(".github/workflows/release.yml")?;
    let line = wf
        .lines()
        .find(|l| l.trim_start().starts_with("noaudio_set="))
        .ok_or(
            "no `noaudio_set=` assignment in .github/workflows/release.yml — \
             the musl feature set is computed some other way now and this \
             gate reads nothing",
        )?;
    let set = line
        .split_once('=')
        .ok_or("an assignment has an =")?
        .1
        .trim()
        .trim_matches('"');
    Ok(set.split(',').map(|s| s.trim().to_string()).collect())
}

/// A capability the static musl binary cannot perform is marked on the page.
///
/// The hero advertises one binary; the capability table lists what sipnab does.
/// `plugins` and `vcon` are in neither the musl tarballs nor the `-noaudio`
/// packages, so a row claiming them unconditionally describes a DIFFERENT
/// artifact from the one the hero points at.
#[test]
fn capabilities_missing_from_the_musl_build_say_so() -> Result<(), TestError> {
    let features = musl_feature_set()?;
    assert!(
        features.contains("native") && features.contains("tui"),
        "the musl feature set scan produced {features:?}, which is not a \
         plausible feature list — it is reading the wrong line"
    );
    // The vCon claim is a standards card, and the cards moved to their own
    // page; the qualifier has to travel with them.
    let page = homepage()? + &read("website/templates/standards.html")?;
    // The rows that name a feature the static build lacks. Each must carry a
    // qualifier a reader can act on, in its own row.
    for (feature, row_marker) in [
        ("plugins", "WASM plugins"),
        ("vcon", "Virtualized Conversation"),
        ("vcon", "Call records"),
    ] {
        if features.contains(feature) {
            continue;
        }
        let row = enclosing_block(&page, row_marker)?;
        let qualified = row.contains("feature") || row.contains("musl") || row.contains("gnu");
        assert!(
            qualified,
            "the static musl build carries {features:?} and not `{feature}`, but \
             the {row_marker:?} row claims the capability with no qualification. \
             Say which builds carry it.\nRow: {row}"
        );
    }
    Ok(())
}

/// Where the site says what the static musl tarball leaves out, it names
/// exactly what the release leaves out.
///
/// The download page said "the two things it leaves out are TUI audio playback
/// and WASM plugin loading" while the tarball also lacked vCon export, the
/// eBPF uprobe backend and, until PW-MUSL, archive reading. The install guide
/// said it "lacks only TUI audio playback". Each feature below is either
/// absent from the musl set and named in both places, or present and named in
/// neither.
#[test]
fn the_musl_build_s_omissions_are_named_where_the_site_describes_it() -> Result<(), TestError> {
    let features = musl_feature_set()?;
    assert!(
        features.contains("native") && features.contains("tui"),
        "the musl feature set scan produced {features:?}, which is not a \
         plausible feature list"
    );
    let download = read("website/templates/download.html")?;
    let lead = download
        .lines()
        .find(|l| l.contains("musl-linked and fully self-contained"))
        .ok_or("website/templates/download.html has no musl lead paragraph")?
        .to_string();
    let install = read("docs/install.md")?;
    let guide = install
        .split("\n\n")
        .find(|p| p.contains("get the static **musl** build"))
        .ok_or("docs/install.md has no paragraph describing the musl build")?
        .to_string();
    for (feature, words) in [
        ("audio", "audio playback"),
        ("plugins", "WASM plugin"),
        ("vcon", "vCon"),
        ("bpf", "eBPF"),
    ] {
        let absent = !features.contains(feature);
        for (place, text) in [("the download page", &lead), ("docs/install.md", &guide)] {
            assert_eq!(
                text.contains(words),
                absent,
                "the static musl build {} `{feature}`, and {place} {} \
                 {words:?} in what it says the tarball leaves out:\n{text}",
                if absent { "lacks" } else { "carries" },
                if absent {
                    "never mentions"
                } else {
                    "still lists"
                },
            );
        }
    }
    // Archives are carried now; a sentence that says the tarball leaves them
    // out would be the old claim back.
    assert!(
        features.contains("archive"),
        "release.yml no longer builds `archive` into the musl set: {features:?}"
    );
    for (place, text) in [("the download page", &lead), ("docs/install.md", &guide)] {
        assert!(
            text.contains("7z"),
            "{place} does not say the static musl build reads ZIP and 7z \
             archives, which it now does:\n{text}"
        );
    }
    Ok(())
}

/// The vcon.store guide's description, which search results and link previews
/// show, describes redaction as the guide does: `--redact` is off unless the
/// operator passes it, and today vcon.store refuses a redacted container. The
/// description said "Forward sipnab's redacted vCons", which told a reader the
/// forwarder redacts and named the one container the store refuses.
#[test]
fn the_vcon_store_description_leaves_redaction_to_the_operator() -> Result<(), TestError> {
    let page = read("website/content/docs/vcon-store.md")?;
    let description = page
        .lines()
        .find_map(|l| l.strip_prefix("description = "))
        .ok_or("website/content/docs/vcon-store.md has no description")?;
    assert!(
        description.contains("--redact") && description.contains("choice"),
        "the description does not say redacting is the operator's choice: {description}"
    );
    assert!(
        !description.contains("redacted vCons"),
        "the description says the forwarded containers are redacted: {description}"
    );
    assert!(
        read("src/cli.rs")?.contains(r#"long = "redact")]"#),
        "src/cli.rs has no --redact flag for the description to name"
    );
    Ok(())
}

/// The homepage's vCon tile ("Call records") says sipnab forwards vCons to
/// third-party stores, names the flag that does it and links the vcon.store
/// guide. Each part of that claim is held to the code: the flags exist with
/// the value the guide names, and the forwarder's tests deliver to a store
/// and exercise the vcon.store mode.
#[test]
fn the_homepage_vcon_forwarding_claim_is_backed_by_the_forwarder() -> Result<(), TestError> {
    let row = enclosing_block(&strip_comments(&homepage()?)?, "Call records")?;
    for needle in ["--vcon-forward", "vcon.store", "docs/vcon-store.md"] {
        assert!(
            row.contains(needle),
            "the homepage's vCon tile does not say {needle:?}:\n{row}"
        );
    }
    let cli = read("src/cli.rs")?;
    for flag in [
        r#"long = "vcon-forward","#,
        r#"long = "vcon-forward-compat","#,
        r#"long = "vcon-forward-kind","#,
        "crate::config::FORWARD_COMPAT.iter()",
        "crate::config::FORWARD_KINDS.iter()",
    ] {
        assert!(cli.contains(flag), "src/cli.rs has no {flag}");
    }
    // The names the two flags accept, declared once in src/config.rs.
    let config = read("src/config.rs")?;
    for names in [
        r#"pub const FORWARD_COMPAT: &[&str] = &["none", "vcon-store"];"#,
        r#"pub const FORWARD_KINDS: &[&str] = &["generic", "vcon-store", "conserver"];"#,
    ] {
        assert!(config.contains(names), "src/config.rs has no {names}");
    }
    let tests = read("tests/vcon_forward_test.rs")?;
    for test in [
        "fn a_container_is_posted_byte_for_byte_with_one_auth_header(",
        "fn vcon_store_mode_sends_extensions_as_an_object_and_keeps_the_file(",
        "fn a_spool_sipnab_wrote_is_delivered_byte_for_byte(",
    ] {
        assert!(
            tests.contains(test),
            "the forwarder's tests no longer carry {test}, which backs the homepage claim"
        );
    }
    Ok(())
}

// ── D. The filter language the page counts ───────────────────────────

/// `(distinct fields, accepted spellings, operators)` from `src/sip/dsl.rs`.
fn filter_dsl_shape() -> Result<(usize, usize, usize), TestError> {
    let src = read("src/sip/dsl.rs")?;
    let variants = |enum_name: &str| -> Result<usize, TestError> {
        let start = src
            .find(&format!("enum {enum_name} {{"))
            .ok_or_else(|| format!("no `enum {enum_name}` in src/sip/dsl.rs"))?;
        let body = &src[start..];
        let end = body
            .find("\n}")
            .ok_or_else(|| format!("`enum {enum_name}` has no closing brace"))?;
        Ok(body[..end]
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.ends_with(',')
                    && !t.starts_with("//")
                    && t.chars().next().is_some_and(char::is_uppercase)
                    && t.trim_end_matches(',').chars().all(char::is_alphanumeric)
            })
            .count())
    };
    let fields = variants("Field")?;
    let operators = variants("Operator")?;
    // Accepted spellings: the `"name" => Field::X` arms, including the `|`
    // alternatives that make one field answer to two names.
    let spellings =
        regex::Regex::new(r#""([a-z0-9_.]+)"(?:\s*\|\s*"[a-z0-9_.]+")*\s*=>\s*Field::"#)?
            .find_iter(&src)
            .map(|m| m.as_str().matches('"').count() / 2)
            .sum();
    Ok((fields, spellings, operators))
}

/// The homepage's operator count equals the operators the parser accepts.
#[test]
fn homepage_filter_operator_count_matches_the_parser() -> Result<(), TestError> {
    let (_, _, operators) = filter_dsl_shape()?;
    assert!(
        operators >= 4,
        "only {operators} Operator variant(s) found — the enum scan stopped \
         matching and certifies any number the page prints"
    );
    let page = homepage()?;
    let re = regex::Regex::new(r"(\d+) operators")?;
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
    Ok(())
}

/// The homepage's field count equals the field names the parser accepts.
#[test]
fn homepage_filter_field_count_matches_the_parser() -> Result<(), TestError> {
    let (fields, spellings, _) = filter_dsl_shape()?;
    assert!(
        fields >= 20 && spellings >= fields,
        "the Field scan produced {fields} variant(s) and {spellings} spelling(s), \
         which cannot both be right — the extraction is broken"
    );
    let page = homepage()?;
    let re = regex::Regex::new(r"(\d+) fields")?;
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
    Ok(())
}

/// Every operator the parser accepts appears in the filter DSL reference.
///
/// `in_subnet` shipped, parsed, matched addresses, and was in no document —
/// which is the same as not having shipped it.
#[test]
fn filter_doc_documents_every_operator_the_parser_accepts() -> Result<(), TestError> {
    let src = read("src/sip/dsl.rs")?;
    let spellings: BTreeSet<String> =
        regex::Regex::new(r#"tag\("([^"]+)"\),\s*\|_\|\s*Operator::"#)?
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
    let doc = read("docs/filter-dsl.md")?;
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
    Ok(())
}

// ── E. The keys the page tells a reader to press ─────────────────────

/// Every `<kbd>` on the homepage, deduplicated.
fn kbd_labels() -> Result<BTreeSet<String>, TestError> {
    Ok(regex::Regex::new(r"<kbd>([^<]+)</kbd>")?
        .captures_iter(&homepage()?)
        .map(|c| c[1].to_string())
        .collect())
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
fn every_tui_key_the_homepage_names_is_bound() -> Result<(), TestError> {
    let tui = tui_sources();
    let mut unbound = Vec::new();
    for label in kbd_labels()? {
        if label.starts_with('-') {
            continue; // a CLI flag, checked separately
        }
        let bound = if label.chars().count() == 1 {
            let c = label.chars().next().ok_or("one char")?;
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
    Ok(())
}

/// The key scan is case-sensitive, which is the whole point of it.
///
/// It once mattered live: the page said `o` opens a capture while the binding
/// was `O`, and a scan that folded case would have certified that. Lowercase
/// `o` is a binding of its own now (the SDP timeline), so this proves
/// case-sensitivity against `j` (bound, the scroll-down key) versus `J` (not) —
/// a pair that still differs.
#[test]
fn the_tui_key_scan_distinguishes_case() -> Result<(), TestError> {
    let tui = tui_sources();
    assert!(
        tui.contains("Char('j')"),
        "src/tui no longer binds `j`; this gate's fixture is gone"
    );
    assert!(
        !tui.contains("Char('J')"),
        "src/tui now binds uppercase `J` as well — this gate proved case \
         mattered by relying on exactly one of the pair existing, so rewrite it \
         against a pair that still differs rather than deleting it"
    );
    Ok(())
}

/// The `<kbd>` extraction finds the keys the page actually carries.
///
/// A regex that matched nothing would let every key claim pass.
#[test]
fn the_kbd_scan_reads_the_homepage() -> Result<(), TestError> {
    let labels = kbd_labels()?;
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
    Ok(())
}

// ── F. One fact, one number, and flags that exist ────────────────────

/// The MCP tile and the MCP prose state the same number.
///
/// This is the defect that produced this file: both were on one page, 66 and
/// 32, and each had a gate or an author who believed it.
#[test]
fn every_homepage_statement_of_the_tool_count_agrees() -> Result<(), TestError> {
    let page = homepage()?;
    let tile: Vec<usize> = regex::Regex::new(r#"data-count="(\d+)" data-suffix=" MCP tools""#)?
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    let prose: Vec<usize> = regex::Regex::new(r"(\d+) tools cover")?
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
    Ok(())
}

/// Every CLI flag the homepage names is a flag the CLI defines.
#[test]
fn no_homepage_claim_names_a_flag_the_cli_does_not_define() -> Result<(), TestError> {
    let cli = read("src/cli.rs")?;
    let page = homepage()?;
    // Flags the page shows a reader, which is `<code>` and `<kbd>` bodies and
    // nothing else. Reading the whole file swept up the CSS modifier classes
    // `feature-card--amber`, `--blue` and `--green` and the `--check` inside a
    // build comment, and reported four flags the CLI has never had. A scanner's
    // first red was its own bug, which is the usual way.
    let visible = strip_comments(&page)?;
    // Two patterns, not one with a backreference: the `regex` crate has none,
    // and `</\1>` compiled to a syntax error rather than to a wrong answer.
    let bodies_of = |tag: &str| -> Result<String, TestError> {
        Ok(
            regex::Regex::new(&format!(r"(?s)<{tag}\b[^>]*>(.*?)</{tag}>"))?
                .captures_iter(&visible)
                .map(|c| c[1].to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    let bodies = format!("{}\n{}", bodies_of("code")?, bodies_of("kbd")?);
    let flags: BTreeSet<String> = regex::Regex::new(r"--([a-z][a-z0-9-]{2,})")?
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
    Ok(())
}

/// Every docs page the capability table links to exists.
#[test]
fn every_capability_row_links_to_a_page_that_exists() -> Result<(), TestError> {
    let page = homepage()?;
    let links: BTreeSet<String> = regex::Regex::new(r"get_url\(path='@/([^']+)'\)")?
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
    Ok(())
}

// ── G. The safety claim ──────────────────────────────────────────────

/// `unsafe {` blocks in `src/`, excluding `#[cfg(test)]` modules.
///
/// The same rule `tests/unsafe_census_test.rs` applies, because a second count
/// of one fact is how `docs/fault-model.md` and
/// `docs/internals/build-ci-release.md` came to publish 16 and 49 for the same
/// tree. This walk is deliberately the simpler one: it only has to agree with
/// the census on the number the page prints, and the census test fails loudly
/// if the two ever diverge from the documentation.
fn non_test_unsafe_blocks() -> usize {
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
    walk(&repo().join("src"), &mut files);
    assert!(files.len() >= 20, "only {} file(s) under src/", files.len());
    let mut total = 0;
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let mut depth: i64 = 0;
        let mut in_test = false;
        let mut opened = false;
        for line in text.lines() {
            if !in_test && line.trim_start().starts_with("#[cfg(test)]") {
                in_test = true;
                depth = 0;
                opened = false;
                continue;
            }
            if in_test {
                depth += line.matches('{').count() as i64;
                if depth > 0 {
                    opened = true;
                }
                depth -= line.matches('}').count() as i64;
                if opened && depth <= 0 {
                    in_test = false;
                }
                continue;
            }
            total += line.matches("unsafe {").count();
        }
    }
    total
}

/// The homepage's `unsafe` count is the count the tree holds.
#[test]
fn homepage_unsafe_count_matches_the_tree() -> Result<(), TestError> {
    let blocks = non_test_unsafe_blocks();
    assert!(
        blocks >= 20,
        "the unsafe walk found only {blocks} block(s) — it stopped matching, so \
         it would certify any number the page prints"
    );
    let page = homepage()?;
    let re = regex::Regex::new(r"(\d+) <code>unsafe</code> blocks")?;
    let stated: Vec<usize> = re
        .captures_iter(&page)
        .filter_map(|c| c[1].parse().ok())
        .collect();
    assert_eq!(
        stated.len(),
        1,
        "expected exactly one \"N <code>unsafe</code> blocks\" claim on the \
         homepage, found {}: {stated:?}",
        stated.len()
    );
    assert_eq!(
        stated[0], blocks,
        "the homepage says {} unsafe blocks; src/ holds {blocks} outside \
         #[cfg(test)]",
        stated[0]
    );
    Ok(())
}

/// The page must not claim unqualified memory safety while `unsafe` exists.
///
/// It said "Memory-safe by construction" for as long as the row existed, beside
/// 88 `unsafe` blocks and no `#![forbid(unsafe_code)]` anywhere. "By
/// construction" names a property the build enforces, and nothing enforced it.
/// The honest sentence is also the stronger one: every block must state its own
/// soundness argument or the build fails.
#[test]
fn homepage_does_not_claim_memory_safety_the_build_does_not_enforce() -> Result<(), TestError> {
    let forbids = read("src/lib.rs")?.contains("forbid(unsafe_code)");
    let blocks = non_test_unsafe_blocks();
    if forbids || blocks == 0 {
        return Err(format!(
            "src/ now forbids unsafe or contains none ({blocks} blocks) — the \
             unqualified claim would be TRUE, so rewrite this gate against what \
             the tree now guarantees rather than deleting it"
        )
        .into());
    }
    let page = homepage()?.to_lowercase();
    for overclaim in [
        "memory-safe by construction",
        "memory safe by construction",
        "no unsafe code",
        "zero unsafe",
    ] {
        assert!(
            !page.contains(overclaim),
            "the homepage claims {overclaim:?} while src/ holds {blocks} \
             `unsafe` blocks and nothing forbids them"
        );
    }
    Ok(())
}

/// The page says the build rejects an undocumented `unsafe` block. It must.
///
/// This is the half of the claim that is not a count, and it is only true
/// because two separate settings agree: the lint is enabled in `Cargo.toml`,
/// and clippy is run with `-D warnings`. Either one alone makes the sentence
/// false.
#[test]
fn the_soundness_argument_claim_is_actually_enforced() -> Result<(), TestError> {
    let page = homepage()?;
    if !page.contains("soundness argument") {
        return Ok(()); // The page no longer makes the claim; nothing to hold it to.
    }
    // The ASSIGNMENT, not the substring. Renaming the lint to
    // `undocumented_unsafe_blocks_x` left this gate green, because the real
    // name is a prefix of the broken one -- a guard that passes on exactly the
    // edit it exists to catch.
    let manifest = read("Cargo.toml")?;
    let enabled = manifest.lines().any(|l| {
        let t = l.trim();
        t.starts_with("undocumented_unsafe_blocks")
            && t["undocumented_unsafe_blocks".len()..]
                .trim_start()
                .starts_with('=')
            && (t.contains("\"warn\"") || t.contains("\"deny\"") || t.contains("\"forbid\""))
    });
    assert!(
        enabled,
        "the homepage says the build rejects an `unsafe` block with no \
         soundness argument, but Cargo.toml sets no lint level for \
         `undocumented_unsafe_blocks`"
    );
    for gate in [".githooks/pre-commit", ".github/workflows/ci.yml"] {
        assert!(
            read(gate)?.contains("-D warnings"),
            "the homepage says the build REJECTS an undocumented `unsafe` \
             block, but {gate} does not run clippy with `-D warnings`, so the \
             lint is a warning nobody fails on"
        );
    }
    Ok(())
}

// ── H. The system map ────────────────────────────────────────────────

/// The `<figure class="sysmap">` block, comments stripped.
fn sysmap() -> Result<String, TestError> {
    let page = strip_comments(&homepage()?)?;
    let start = page
        .find(r#"<figure class="sysmap""#)
        .ok_or("the homepage has no system map")?;
    let end = page[start..]
        .find("</figure>")
        .ok_or("the system map closes")?
        + start;
    Ok(page[start..end].to_string())
}

/// Short flags (`-d`, `-I`) named in `<code>` bodies of `html`.
fn short_flags(html: &str) -> Result<BTreeSet<char>, TestError> {
    let code = regex::Regex::new(r"(?s)<code\b[^>]*>(.*?)</code>")?;
    let short = regex::Regex::new(r"(?:^|\s)-([A-Za-z])(?:\s|$)")?;
    Ok(code
        .captures_iter(html)
        .flat_map(|c| {
            short
                .captures_iter(&c[1])
                .map(|s| s[1].chars().next().unwrap_or('?'))
                .collect::<Vec<_>>()
        })
        .collect())
}

/// The ones `cli` does not define as `short = 'x'`.
fn undefined_shorts(flags: &BTreeSet<char>, cli: &str) -> Vec<char> {
    flags
        .iter()
        .copied()
        .filter(|c| !cli.contains(&format!("short = '{c}'")))
        .collect()
}

/// Zola's slug for a markdown heading: lowercase, runs of anything that is not
/// a letter or digit become one `-`, trimmed.
fn slug(heading: &str) -> String {
    let mut out = String::new();
    for ch in heading.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// `(page, anchor)` pairs whose anchor no heading of `page` produces, for every
/// `get_url(path='@/X.md') }}#anchor` link in `html`.
fn broken_anchors(
    html: &str,
    page_of: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>, TestError> {
    let link = regex::Regex::new(r"get_url\(path='@/([^']+)'\) \}\}#([a-z0-9-]+)")?;
    let mut out = Vec::new();
    for c in link.captures_iter(html) {
        let (rel, anchor) = (&c[1], &c[2]);
        let Some(md) = page_of(rel) else {
            out.push(format!("{rel}#{anchor}: page missing"));
            continue;
        };
        let found = md
            .lines()
            .filter_map(|l| l.strip_prefix('#'))
            .map(|l| slug(l.trim_start_matches('#').trim()))
            .any(|s| s == anchor);
        if !found {
            out.push(format!("{rel}#{anchor}"));
        }
    }
    Ok(out)
}

fn content_page(rel: &str) -> Option<String> {
    std::fs::read_to_string(repo().join("website/content").join(rel)).ok()
}

/// Norm, 2026-10-10: "How sipnab fits together" is the first section after
/// the hero, so the map now comes before the animation. It sat above the
/// animation from 2026-10-02, below it from 2026-10-09.
#[test]
fn the_system_map_sits_above_the_hero_animation() -> Result<(), TestError> {
    let page = homepage()?;
    let map = page
        .find(r#"<figure class="sysmap""#)
        .ok_or("no system map")?;
    let shot = page.find(r#"id="hero-shot""#).ok_or("no hero animation")?;
    assert!(
        map < shot,
        "the system map must come before the hero animation"
    );
    Ok(())
}

/// The three columns and the caption are there, in reading order, so the map
/// still says inputs, then processing, then outputs with styles off.
#[test]
fn the_system_map_reads_inputs_then_core_then_surfaces() -> Result<(), TestError> {
    let map = sysmap()?;
    let order: Vec<usize> = [
        "What it reads",
        "What it works out",
        "Where you read it",
        "<figcaption",
    ]
    .iter()
    .map(|h| {
        map.find(h)
            .ok_or_else(|| format!("the system map lacks {h:?}"))
    })
    .collect::<Result<_, _>>()?;
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "out of order: {order:?}"
    );
    assert_eq!(
        map.matches(r#"class="sysmap-stack""#).count(),
        1,
        "one processing stack"
    );
    assert_eq!(
        map[map.find(r#"class="sysmap-stack""#).unwrap_or(0)..]
            .split("</ol>")
            .next()
            .unwrap_or("")
            .matches("<li>")
            .count(),
        4,
        "the stack names four stages: unwrap, parse, track, judge"
    );
    Ok(())
}

/// Every short flag the map shows is one the CLI defines.
#[test]
fn every_short_flag_on_the_system_map_exists() -> Result<(), TestError> {
    let flags = short_flags(&sysmap()?)?;
    assert!(
        flags.len() >= 4,
        "only {flags:?} found; the scan is not reading the map"
    );
    let missing = undefined_shorts(&flags, &read("src/cli.rs")?);
    assert!(
        missing.is_empty(),
        "the system map shows -{missing:?}, which src/cli.rs does not define"
    );
    Ok(())
}

/// Every `#anchor` the map links to is a heading on the page it names.
#[test]
fn every_anchor_on_the_system_map_resolves() -> Result<(), TestError> {
    let broken = broken_anchors(&sysmap()?, &content_page)?;
    assert!(
        broken.is_empty(),
        "the system map links to anchors that do not exist: {broken:?}"
    );
    Ok(())
}

#[test]
fn the_short_flag_check_reports_an_undefined_letter() -> Result<(), TestError> {
    let flags = short_flags("<code>-d eth0</code> <code>-Z</code>")?;
    assert_eq!(flags, BTreeSet::from(['Z', 'd']));
    assert_eq!(undefined_shorts(&flags, "short = 'd'"), vec!['Z']);
    Ok(())
}

#[test]
fn the_anchor_check_reports_a_missing_heading_and_a_missing_page() -> Result<(), TestError> {
    let page = |rel: &str| {
        (rel == "docs/cli.md").then(|| "## Capture\n### TLS / decryption\n".to_string())
    };
    let html = "get_url(path='@/docs/cli.md') }}#capture get_url(path='@/docs/cli.md') }}#tls-decryption \
                get_url(path='@/docs/cli.md') }}#nope get_url(path='@/docs/gone.md') }}#x";
    assert_eq!(
        broken_anchors(html, &page)?,
        vec!["docs/cli.md#nope", "docs/gone.md#x: page missing"]
    );
    Ok(())
}
