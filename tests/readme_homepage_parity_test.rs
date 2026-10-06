// SPDX-License-Identifier: MIT OR Apache-2.0

//! The README, the home page and the code say the same thing.
//!
//! The README is the first page most readers see, on GitHub and on crates.io,
//! and the home page is the first page on sipnab.com. They drifted apart: the
//! README described a hero image that no longer showed what it said, called
//! released features unreleased, left out capabilities the home page listed,
//! and stated a tool count no gate read. Each test here pins one of those to
//! its source.

use std::collections::BTreeSet;

const README: &str = include_str!("../README.md");
const HOMEPAGE: &str = include_str!("../website/templates/index.html");
const SITE_CONFIG: &str = include_str!("../website/config.toml");

/// Every capability row on the home page, and the term that shows the README
/// covers it. A new home page row fails here until it is added, which is the
/// point: the README decides how to say it, but it cannot leave it out.
const CAPABILITIES: &[(&str, &str)] = &[
    ("Terminal UI and headless mode", "headless"),
    ("RTP quality analysis", "RTCP XR"),
    ("VoIP diagnosis", "one-way audio"),
    ("Relay statistics", "--rtpengine-control"),
    ("Filter DSL", "operators"),
    ("Security", "--fail2ban"),
    ("TLS/SRTP decryption", "SSLKEYLOGFILE"),
    ("WASM plugins", "--plugin"),
    ("eBPF TLS capture", "--uprobe-tls"),
    ("Export formats", "SIPp XML"),
    ("HEP v2/v3", "HEP v2/v3"),
    ("REST API", "REST API"),
    ("Prometheus metrics", "Prometheus"),
    ("MCP server", "MCP server"),
    ("Browser analysis", "WebAssembly"),
    ("Built in Rust", "`unsafe` blocks"),
];

/// The capability rows' titles, read from the home page's table.
fn homepage_capability_titles() -> BTreeSet<String> {
    let row = regex::Regex::new(r"<tr><td>(.*?)</td>").expect("pattern");
    let tag = regex::Regex::new(r"<[^>]+>").expect("pattern");
    row.captures_iter(HOMEPAGE)
        .map(|c| {
            let text = tag.replace_all(&c[1], "");
            // The eBPF row carries a "(root, same host)" qualifier.
            text.split('(').next().unwrap_or("").trim().to_string()
        })
        .collect()
}

#[test]
fn every_homepage_capability_row_is_in_the_readme() {
    let on_page = homepage_capability_titles();
    assert!(on_page.len() >= 15, "read only {} rows", on_page.len());
    let mapped: BTreeSet<String> = CAPABILITIES.iter().map(|(t, _)| t.to_string()).collect();
    assert_eq!(
        on_page, mapped,
        "the home page's capability rows and this mapping disagree: add a row \
         here, with the README term that covers it"
    );
    let missing: Vec<String> = CAPABILITIES
        .iter()
        .filter(|(_, term)| !README.contains(term))
        .map(|(title, term)| format!("{title}: README does not contain `{term}`"))
        .collect();
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn the_readme_hero_alt_text_matches_the_homepage() {
    let readme = regex::Regex::new(r"!\[([^\]]+)\]\(website/static/demos/hero-static\.webp\)")
        .expect("pattern");
    let readme_alt = readme
        .captures(README)
        .map(|c| c[1].to_string())
        .expect("the README shows the hero image");
    let page = regex::Regex::new(r#"(?s)<img[^>]*hero-static\.webp[^>]*>"#).expect("pattern");
    let img = page
        .find(HOMEPAGE)
        .expect("the home page shows the hero image")
        .as_str();
    let alt = regex::Regex::new(r#"alt="([^"]+)""#).expect("pattern");
    let page_alt = alt
        .captures(img)
        .map(|c| c[1].replace("&mdash;", "—"))
        .expect("the home page's hero image has alt text");
    assert_eq!(
        readme_alt, page_alt,
        "the two pages describe the same image differently"
    );
}

/// `(major, minor, patch)` from `a.b.c`.
fn version(v: &str) -> (u32, u32, u32) {
    let mut p = v
        .split('.')
        .map(|n| n.parse::<u32>().expect("numeric version"));
    (
        p.next().expect("major"),
        p.next().expect("minor"),
        p.next().expect("patch"),
    )
}

#[test]
fn the_readme_calls_nothing_released_unreleased() {
    let published = regex::Regex::new(r#"(?m)^published_version = "([0-9.]+)""#)
        .expect("pattern")
        .captures(SITE_CONFIG)
        .map(|c| version(&c[1]))
        .expect("website/config.toml names the published version");
    let landed =
        regex::Regex::new(r"landed after\s+release\s+([0-9]+\.[0-9]+\.[0-9]+)").expect("pattern");
    let stale: Vec<String> = landed
        .captures_iter(README)
        .filter(|c| version(&c[1]) < published)
        .map(|c| c[0].to_string())
        .collect();
    assert!(
        stale.is_empty(),
        "the README says these landed after a release, but a later one is \
         published, so they shipped: {stale:?}"
    );
}

/// Every MCP tool registration under `src/mcp`, with its read-only hint.
fn mcp_tools() -> (usize, usize) {
    let mut all = 0;
    let mut writing = 0;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read_dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).expect("read");
                // Attribute lines only: a doc comment that quotes the hint is
                // not a tool.
                for line in text.lines().map(str::trim_start) {
                    all += usize::from(line.starts_with("#[tool("));
                    writing += usize::from(line.starts_with("read_only_hint = false"));
                }
            }
        }
    }
    (all, writing)
}

#[test]
fn the_readme_tool_counts_match_the_server() {
    let (all, writing) = mcp_tools();
    assert!(all >= 60, "found only {all} tools");
    let total = regex::Regex::new(r"(\d+) tools").expect("pattern");
    let stated: Vec<usize> = total
        .captures_iter(README)
        .map(|c| c[1].parse().expect("number"))
        .collect();
    assert!(!stated.is_empty(), "the README states no tool count");
    assert!(
        stated.iter().all(|n| *n == all),
        "the README says {stated:?} tools; the server registers {all}"
    );
    let write = regex::Regex::new(r"(\d+) that\s+write").expect("pattern");
    let stated: Vec<usize> = write
        .captures_iter(README)
        .map(|c| c[1].parse().expect("number"))
        .collect();
    assert_eq!(
        stated,
        vec![writing],
        "the README must say how many tools write, once: the server has {writing}"
    );
}

/// The first capture of `pattern` in `text`, as numbers.
fn numbers(text: &str, pattern: &str) -> Option<Vec<u64>> {
    regex::Regex::new(pattern)
        .expect("pattern")
        .captures(text)
        .map(|c| {
            c.iter()
                .skip(1)
                .map(|m| m.expect("group").as_str().parse().expect("number"))
                .collect()
        })
}

/// Numbers both pages state agree. The home page's are gated against the
/// code (`homepage_claim_truth_test`, `homepage_unsafe_count_matches_the_tree`),
/// so agreeing with the home page is agreeing with the code.
#[test]
fn the_readme_and_the_homepage_state_the_same_numbers() {
    let tag = regex::Regex::new(r"<[^>]+>").expect("pattern");
    let page = tag.replace_all(HOMEPAGE, "");
    for (what, pattern) in [
        ("filter DSL size", r"(\d+) fields,\s+(\d+) operators"),
        ("unsafe block count", r"(\d+)\s+`?unsafe`?\s+blocks"),
    ] {
        let on_page =
            numbers(&page, pattern).unwrap_or_else(|| panic!("the home page states no {what}"));
        let in_readme =
            numbers(README, pattern).unwrap_or_else(|| panic!("the README states no {what}"));
        assert_eq!(
            in_readme, on_page,
            "{what}: README {in_readme:?}, home page {on_page:?}"
        );
    }
}
