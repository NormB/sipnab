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

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

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
fn homepage_capability_titles() -> Result<BTreeSet<String>, TestError> {
    let row = regex::Regex::new(r"<tr><td>(.*?)</td>")?;
    let tag = regex::Regex::new(r"<[^>]+>")?;
    Ok(row
        .captures_iter(HOMEPAGE)
        .map(|c| {
            let text = tag.replace_all(&c[1], "");
            // The eBPF row carries a "(root, same host)" qualifier.
            text.split('(').next().unwrap_or("").trim().to_string()
        })
        .collect())
}

#[test]
fn every_homepage_capability_row_is_in_the_readme() -> Result<(), TestError> {
    let on_page = homepage_capability_titles()?;
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
    Ok(())
}

#[test]
fn the_readme_hero_alt_text_matches_the_homepage() -> Result<(), TestError> {
    let readme = regex::Regex::new(r"!\[([^\]]+)\]\(website/static/demos/hero-static\.webp\)")?;
    let readme_alt = readme
        .captures(README)
        .map(|c| c[1].to_string())
        .ok_or("the README shows the hero image")?;
    let page = regex::Regex::new(r#"(?s)<img[^>]*hero-static\.webp[^>]*>"#)?;
    let img = page
        .find(HOMEPAGE)
        .ok_or("the home page shows the hero image")?
        .as_str();
    let alt = regex::Regex::new(r#"alt="([^"]+)""#)?;
    let page_alt = alt
        .captures(img)
        .map(|c| c[1].replace("&mdash;", "—"))
        .ok_or("the home page's hero image has alt text")?;
    assert_eq!(
        readme_alt, page_alt,
        "the two pages describe the same image differently"
    );
    Ok(())
}

/// `(major, minor, patch)` from `a.b.c`.
fn version(v: &str) -> Result<(u32, u32, u32), TestError> {
    let mut p = v
        .split('.')
        .map(|n| n.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    Ok((
        p.next().ok_or("major")?,
        p.next().ok_or("minor")?,
        p.next().ok_or("patch")?,
    ))
}

#[test]
fn the_readme_calls_nothing_released_unreleased() -> Result<(), TestError> {
    let published = regex::Regex::new(r#"(?m)^published_version = "([0-9.]+)""#)?
        .captures(SITE_CONFIG)
        .map(|c| version(&c[1]))
        .ok_or("website/config.toml names the published version")??;
    let landed = regex::Regex::new(r"landed after\s+release\s+([0-9]+\.[0-9]+\.[0-9]+)")?;
    let mut stale: Vec<String> = Vec::new();
    for c in landed.captures_iter(README) {
        if version(&c[1])? < published {
            stale.push(c[0].to_string());
        }
    }
    assert!(
        stale.is_empty(),
        "the README says these landed after a release, but a later one is \
         published, so they shipped: {stale:?}"
    );
    Ok(())
}

/// Every MCP tool registration under `src/mcp`, with its read-only hint.
fn mcp_tools() -> Result<(usize, usize), TestError> {
    let mut all = 0;
    let mut writing = 0;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp");
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)?;
                // Attribute lines only: a doc comment that quotes the hint is
                // not a tool.
                for line in text.lines().map(str::trim_start) {
                    all += usize::from(line.starts_with("#[tool("));
                    writing += usize::from(line.starts_with("read_only_hint = false"));
                }
            }
        }
    }
    Ok((all, writing))
}

#[test]
fn the_readme_tool_counts_match_the_server() -> Result<(), TestError> {
    let (all, writing) = mcp_tools()?;
    assert!(all >= 60, "found only {all} tools");
    let total = regex::Regex::new(r"(\d+) tools")?;
    let stated: Vec<usize> = total
        .captures_iter(README)
        .map(|c| -> Result<_, TestError> { Ok(c[1].parse()?) })
        .collect::<Result<_, TestError>>()?;
    assert!(!stated.is_empty(), "the README states no tool count");
    assert!(
        stated.iter().all(|n| *n == all),
        "the README says {stated:?} tools; the server registers {all}"
    );
    let write = regex::Regex::new(r"(\d+) that\s+write")?;
    let stated: Vec<usize> = write
        .captures_iter(README)
        .map(|c| -> Result<_, TestError> { Ok(c[1].parse()?) })
        .collect::<Result<_, TestError>>()?;
    assert_eq!(
        stated,
        vec![writing],
        "the README must say how many tools write, once: the server has {writing}"
    );
    Ok(())
}

/// The first capture of `pattern` in `text`, as numbers.
fn numbers(text: &str, pattern: &str) -> Result<Option<Vec<u64>>, TestError> {
    regex::Regex::new(pattern)?
        .captures(text)
        .map(|c| {
            c.iter()
                .skip(1)
                .map(|m| -> Result<_, TestError> { Ok(m.ok_or("group")?.as_str().parse()?) })
                .collect::<Result<_, TestError>>()
        })
        .transpose()
}

/// Numbers both pages state agree. The home page's are gated against the
/// code (`homepage_claim_truth_test`, `homepage_unsafe_count_matches_the_tree`),
/// so agreeing with the home page is agreeing with the code.
#[test]
fn the_readme_and_the_homepage_state_the_same_numbers() -> Result<(), TestError> {
    let tag = regex::Regex::new(r"<[^>]+>")?;
    let page = tag.replace_all(HOMEPAGE, "");
    for (what, pattern) in [
        ("filter DSL size", r"(\d+) fields,\s+(\d+) operators"),
        ("unsafe block count", r"(\d+)\s+`?unsafe`?\s+blocks"),
    ] {
        let on_page =
            numbers(&page, pattern)?.ok_or_else(|| format!("the home page states no {what}"))?;
        let in_readme =
            numbers(README, pattern)?.ok_or_else(|| format!("the README states no {what}"))?;
        assert_eq!(
            in_readme, on_page,
            "{what}: README {in_readme:?}, home page {on_page:?}"
        );
    }
    Ok(())
}

/// Every guide a homepage voice-stack tile links to is linked from the README
/// too, so a reader who starts on GitHub or crates.io can reach the same
/// guides. The tiles are read from the page, so a new guide on a tile fails
/// here until the README links it.
#[test]
fn every_homepage_tile_guide_is_linked_from_the_readme() -> Result<(), Box<dyn std::error::Error>> {
    let card = regex::Regex::new(r#"(?s)<div class="feature-card[^"]*">(.*?)</ul>\s*</div>"#)?;
    let guide = regex::Regex::new(r"@/docs/([a-z0-9-]+\.md)")?;
    let mut tiles = 0;
    let mut missing = Vec::new();
    for c in card.captures_iter(HOMEPAGE) {
        tiles += 1;
        for g in guide.captures_iter(&c[1]) {
            let path = format!("docs/{}", &g[1]);
            if !README.contains(&path) {
                missing.push(path);
            }
        }
    }
    assert!(tiles >= 6, "read only {tiles} tiles from the home page");
    assert!(
        missing.is_empty(),
        "the home page's tiles link these guides and the README does not: {missing:?}"
    );
    Ok(())
}

/// The README says which builds carry the vCon forwarder, as the home page's
/// "Call records" tile does: the static musl builds lack the `vcon` feature.
#[test]
fn the_readme_says_which_builds_forward_vcons() {
    let at = README.find("--vcon-forward").unwrap_or(0);
    let bullet = &README[at..README.len().min(at + 800)];
    assert!(
        bullet.contains("musl") || bullet.contains("gnu"),
        "the README names --vcon-forward without saying which builds carry it:\n{bullet}"
    );
}
