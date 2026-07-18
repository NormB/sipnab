//! End-to-end journey guards for the website artifacts: walk what a visitor
//! actually hits — nav links, docs pages, demo assets, and the VHS tapes that
//! produce them — and fail on the classes of breakage that shipped before:
//!
//! - 2026-07-18: demo tapes named "JetBrains Mono", which was NOT installed on
//!   the render box; VHS/ttyd silently fell back with broken metrics
//!   (stretched letter-spacing, clipped glyphs) and the mangled GIFs + hero
//!   PNG shipped to the homepage. `demo_tape_fonts_are_installed_monospace`
//!   makes that unshippable.
//! - Nav entries pointing at docs pages that don't exist (5 pages were once
//!   hidden the other way around — nav and content must stay in sync).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

// ---------------------------------------------------------------------------
// Font journey: every FontFamily a tape names must be an installed monospace
// family on the box that renders the demos.
// ---------------------------------------------------------------------------

/// Monospace font families installed on this machine, per fontconfig.
fn installed_mono_families() -> Option<BTreeSet<String>> {
    let out = Command::new("fc-list")
        .args([":spacing=mono", "family"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .flat_map(|l| l.split(','))
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect(),
    )
}

/// `Set FontFamily "X"` declarations across all demo tapes.
fn tape_font_families() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let re = regex::Regex::new(r#"(?m)^Set FontFamily\s+"([^"]+)""#).unwrap();
    for entry in std::fs::read_dir(repo().join("demos")).expect("demos dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("tape") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read tape");
        for cap in re.captures_iter(&text) {
            out.push((
                p.file_name().unwrap().to_string_lossy().into_owned(),
                cap[1].to_string(),
            ));
        }
    }
    out
}

#[test]
fn demo_tape_fonts_are_installed_monospace() {
    let fonts = tape_font_families();
    assert!(
        !fonts.is_empty(),
        "no FontFamily found in any tape — demos/common.tape must pin an \
         installed monospace font explicitly (maintainer mandate)"
    );
    // The demos are only ever rendered on Linux (this box, via `make -C
    // demos`), so the "font must be installed" contract only makes sense
    // there. On macOS/Windows CI the render never happens and fontconfig
    // reports a different family set (Menlo, Courier New, ...) — skip.
    if !cfg!(target_os = "linux") {
        eprintln!("demos render on Linux only; skipping installed-font check on this platform");
        return;
    }
    let Some(installed) = installed_mono_families() else {
        eprintln!("fc-list unavailable; skipping installed-font verification");
        return;
    };
    let missing: Vec<_> = fonts
        .iter()
        .filter(|(_, fam)| !installed.contains(fam.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "tapes name fonts that are NOT installed monospace families on this \
         box — VHS will silently fall back with broken metrics (stretched \
         spacing, clipped glyphs), exactly the bug that shipped on \
         2026-07-18:\n{missing:?}\ninstalled mono families: {installed:?}"
    );
}

// ---------------------------------------------------------------------------
// Demo-asset journey: index.html references <-> website/static/demos contents.
// ---------------------------------------------------------------------------

fn referenced_demo_assets() -> BTreeSet<String> {
    let re = regex::Regex::new(r#"get_url\(path='demos/([^']+)'\)"#).unwrap();
    let mut out = BTreeSet::new();
    for tpl in [
        "website/templates/index.html",
        "website/templates/base.html",
    ] {
        for cap in re.captures_iter(&read(tpl)) {
            out.insert(cap[1].to_string());
        }
    }
    // analyze.js fetches the sample pcap by URL path
    if read("website/static/js/analyze.js").contains("demos/sample-call.pcap") {
        out.insert("sample-call.pcap".to_string());
    }
    // The homepage demo JS derives a `<name>-poster.png` first-frame from each
    // GIF for prefers-reduced-motion, so those posters are referenced too.
    let posters: Vec<String> = out
        .iter()
        .filter(|f| f.ends_with(".gif"))
        .map(|f| f.replace(".gif", "-poster.png"))
        .collect();
    out.extend(posters);
    out
}

fn present_demo_assets() -> BTreeSet<String> {
    std::fs::read_dir(repo().join("website/static/demos"))
        .expect("static/demos dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn every_referenced_demo_asset_exists_and_none_are_orphaned() {
    let referenced = referenced_demo_assets();
    let present = present_demo_assets();
    assert!(
        referenced.len() >= 8,
        "suspiciously few referenced demo assets ({referenced:?}) — extractor broken?"
    );
    let broken: Vec<_> = referenced.difference(&present).collect();
    assert!(
        broken.is_empty(),
        "index references missing demo assets: {broken:?}"
    );
    let orphans: Vec<_> = present.difference(&referenced).collect();
    assert!(
        orphans.is_empty(),
        "unreferenced files shipping in static/demos (delete or wire up): {orphans:?}"
    );
}

#[test]
fn every_tape_output_is_a_referenced_site_asset() {
    // A tape whose Output lands in static/demos must correspond to a
    // referenced asset; the hero tape's Screenshot produces hero-static.png.
    let re = regex::Regex::new(r"(?m)^(?:Output|Screenshot)\s+(\S+)").unwrap();
    let referenced = referenced_demo_assets();
    let mut stale = Vec::new();
    for entry in std::fs::read_dir(repo().join("demos")).expect("demos dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("tape") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read tape");
        for cap in re.captures_iter(&text) {
            let out = &cap[1];
            if let Some(name) = out.strip_prefix("website/static/demos/")
                && !referenced.contains(name)
            {
                stale.push(format!(
                    "{}: renders {out} which nothing references",
                    p.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "tapes render unreferenced assets:\n{}",
        stale.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Nav journey: every docs link in the chrome resolves to a content page.
// ---------------------------------------------------------------------------

#[test]
fn every_nav_docs_link_resolves_to_a_content_page() {
    let re = regex::Regex::new(r"@/docs/([A-Za-z0-9_-]+\.md)").unwrap();
    let mut missing = Vec::new();
    let mut seen = 0;
    for tpl in [
        "website/templates/base.html",
        "website/templates/index.html",
    ] {
        for cap in re.captures_iter(&read(tpl)) {
            seen += 1;
            let page = repo().join("website/content/docs").join(&cap[1]);
            if !page.is_file() {
                missing.push(format!("{tpl}: @/docs/{}", &cap[1]));
            }
        }
    }
    assert!(
        seen >= 10,
        "nav link extractor found only {seen} links — broken?"
    );
    assert!(
        missing.is_empty(),
        "nav links to nonexistent docs pages:\n{}",
        missing.join("\n")
    );
}

#[test]
fn site_version_matches_crate_version() {
    // Guards the "homepage still shows the old version" defect: the Zola
    // config's version (homepage badge + download links) must equal the crate
    // version in Cargo.toml. Mirrors the pre-commit gate as a permanent test.
    let cargo = read("Cargo.toml");
    let crate_v = regex::Regex::new(r#"(?m)^version = "([^"]+)""#)
        .unwrap()
        .captures(&cargo)
        .expect("Cargo.toml version")[1]
        .to_string();
    let cfg = read("website/config.toml");
    let site_v = regex::Regex::new(r#"(?m)^version = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("config.toml version")[1]
        .to_string();
    assert_eq!(
        crate_v, site_v,
        "website/config.toml version ({site_v}) != Cargo.toml version \
         ({crate_v}) — the homepage badge and download links would show the \
         wrong version"
    );
}

#[test]
fn docs_page_weights_are_unique_and_descriptions_present() {
    let w_re = regex::Regex::new(r"(?m)^weight = (\d+)").unwrap();
    let d_re = regex::Regex::new(r"(?m)^description = ").unwrap();
    let mut weights: Vec<(u32, String)> = Vec::new();
    let mut missing_desc = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/content/docs")).expect("docs dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == "_index.md" {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read page");
        match w_re.captures(&text) {
            Some(c) => weights.push((c[1].parse().unwrap(), name.clone())),
            None => missing_desc.push(format!("{name}: no weight")),
        }
        if !d_re.is_match(&text) {
            missing_desc.push(format!("{name}: no description"));
        }
    }
    let mut dupes = Vec::new();
    weights.sort();
    for pair in weights.windows(2) {
        if pair[0].0 == pair[1].0 {
            dupes.push(format!(
                "weight {} used by {} and {}",
                pair[0].0, pair[0].1, pair[1].1
            ));
        }
    }
    assert!(
        dupes.is_empty() && missing_desc.is_empty(),
        "docs frontmatter problems:\n{}\n{}",
        dupes.join("\n"),
        missing_desc.join("\n")
    );
}
