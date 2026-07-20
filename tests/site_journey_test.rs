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

// ---------------------------------------------------------------------------
// Search-demo journey: every query the filter demo tape types must actually
// narrow the dialog list of the pcap the tape plays. Shipped broken on
// 2026-07-18: 04-filter.tape searched "INVITE"/"REGIS" against
// b2bua-asterisk.pcapng, but the search's full-text fallback scans raw
// message bytes and every dialog carries `Allow: ... INVITE ...` headers —
// the GIF showed "/INVITE" typed with the header pinned at "12 (12
// displayed)" for its whole runtime. A filter demo where nothing filters.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod search_demo_narrowing {
    use super::{read, repo};
    use crossterm::event::KeyCode;
    use sipnab::tui::App;
    use sipnab::tui::call_list::{SortColumn, displayed_dialogs};

    /// The pcap the tape plays and each search query it types (`Type "/"`
    /// immediately followed by another `Type "..."` line).
    fn tape_pcap_and_queries(tape: &str) -> (String, Vec<String>) {
        let cmd = regex::Regex::new(r#"(?m)^Type "sipnab [^"]*-I ([^"\s]+)"#).unwrap();
        let pcap = cmd
            .captures(tape)
            .expect("tape types a `sipnab -I <pcap>` command")[1]
            .to_string();
        let typed: Vec<String> = regex::Regex::new(r#"(?m)^Type "([^"]*)""#)
            .unwrap()
            .captures_iter(tape)
            .map(|c| c[1].to_string())
            .collect();
        let queries = typed
            .windows(2)
            .filter(|w| w[0] == "/")
            .map(|w| w[1].clone())
            .collect();
        (pcap, queries)
    }

    #[test]
    fn every_typed_search_query_narrows_the_demo_pcap() {
        let tape = read("demos/04-filter.tape");
        let (pcap_rel, queries) = tape_pcap_and_queries(&tape);
        assert!(
            !queries.is_empty(),
            "no '/'-search queries found in 04-filter.tape — extractor broken \
             or the demo was rewritten; update this guard alongside it"
        );
        let pcap = repo().join(&pcap_rel);
        assert!(pcap.is_file(), "tape references missing pcap: {pcap_rel}");

        // Load the pcap through the real file-open path, then type each
        // query exactly as the tape does and count the rows a viewer sees.
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Tab);
        app.open_path_clear_for_test();
        for c in pcap.to_string_lossy().chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        let shown_with = |app: &App, q: &str| {
            let store = app.dialog_store_ref().read();
            displayed_dialogs(&store, None, q, SortColumn::Index, true).len()
        };
        let total = shown_with(&app, "");
        assert!(
            total > 1,
            "expected a multi-dialog pcap, got {total} dialogs"
        );

        for q in &queries {
            app.handle_key(KeyCode::Char('/'));
            for c in q.chars() {
                app.handle_key(KeyCode::Char(c));
            }
            let shown = shown_with(&app, app.search_query());
            app.handle_key(KeyCode::Esc);
            assert!(
                shown > 0,
                "demo query \"/{q}\" matches nothing in {pcap_rel} — the \
                 viewer would watch the list vanish"
            );
            assert!(
                shown < total,
                "demo query \"/{q}\" matches all {total} dialogs in \
                 {pcap_rel} (full-text fallback scans raw messages, e.g. \
                 Allow: headers) — the list never visibly narrows, so the \
                 filter demo demonstrates nothing"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CSP journey: the production Content-Security-Policy allows inline <script>
// blocks by sha256 hash but does NOT grant 'unsafe-inline'/'unsafe-hashes',
// so inline event-handler attributes (onclick=, onkeydown=, oninput=, ...)
// are BLOCKED by the browser and silently do nothing. This shipped once: the
// homepage demo tabs + copy button used onclick="..." and every button was
// dead on the live site while returning HTTP 200. Wire events with
// addEventListener inside a hashed <script> instead. This guard makes an
// inline handler unshippable.
// ---------------------------------------------------------------------------
#[test]
fn no_inline_event_handlers_in_templates() {
    // Match an inline handler used as an HTML attribute (quote follows the `=`).
    // JS assignments like `el.onclick = fn` and prose don't have that shape, and
    // `<script>`/`<style>` bodies are stripped first so real JS never trips this.
    let re = regex::Regex::new(r#"(?i)\son(click|keydown|keyup|keypress|input|change|submit|mouseover|mouseout|focus|blur|load|error)\s*=\s*["']"#).unwrap();
    let block = regex::Regex::new(r"(?is)<(script|style)\b.*?</(script|style)>").unwrap();
    let dir = repo().join("website/templates");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read template");
        // Blank out script/style bodies (keep newlines so line numbers hold).
        let markup = block.replace_all(&text, |c: &regex::Captures| {
            c[0].chars()
                .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                .collect::<String>()
        });
        for (lineno, line) in markup.lines().enumerate() {
            if let Some(m) = re.find(line) {
                offenders.push(format!(
                    "{}:{}: inline handler `{}` — CSP blocks it; use addEventListener",
                    p.file_name().unwrap().to_string_lossy(),
                    lineno + 1,
                    m.as_str().trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "inline event handlers are CSP-blocked on the live site (buttons will silently do nothing):\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Download-page ToC journey: every other content-heavy page (the docs) gives
// the reader a left sidebar to jump around with; the download page shipped
// without one, leaving its six sections (installer, four platform panels,
// all-files table, verify) reachable only by scrolling. The sidebar must use
// the same doc-sidebar treatment as the docs pages, and every anchor it
// offers must resolve to a real id in the template — a ToC that points at
// nothing is worse than no ToC.
// ---------------------------------------------------------------------------

#[test]
fn download_page_has_left_toc_sidebar_like_docs() {
    let tpl = read("website/templates/download.html");

    let aside_at = tpl.find("<aside class=\"doc-sidebar").unwrap_or_else(|| {
        panic!(
            "download.html has no <aside class=\"doc-sidebar\"> — the download \
             page must carry the same left ToC treatment as the docs pages"
        )
    });
    let aside = &tpl[aside_at
        ..aside_at
            + tpl[aside_at..]
                .find("</aside>")
                .expect("doc-sidebar aside is unterminated")];

    // Every anchor the ToC offers must land on a real id in the template.
    let href = regex::Regex::new(r##"href="#([A-Za-z0-9_-]+)""##).unwrap();
    let anchors: Vec<String> = href
        .captures_iter(aside)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        anchors.len() >= 4,
        "download ToC lists only {} section link(s) — expected the page's \
         major sections (installer, platforms, all files, verify)",
        anchors.len()
    );
    for id in &anchors {
        assert!(
            tpl.contains(&format!("id=\"{id}\"")),
            "download ToC links to #{id} but no element in download.html \
             carries id=\"{id}\" — dead anchor"
        );
    }

    // The two sections visitors most often want must be one click away.
    for must in ["all-files", "verify"] {
        assert!(
            anchors.iter().any(|a| a == must),
            "download ToC is missing a link to #{must}"
        );
    }
}

// ---------------------------------------------------------------------------
// Footer journey: the site footer must appear on every page. base.html wraps
// it in `{% block footer %}` so a child template can blank it away with an
// empty override — analyze.html did exactly that, so the app page shipped
// with no footer at all (no nav links, no license, no credits).
// ---------------------------------------------------------------------------

#[test]
fn every_page_template_keeps_the_site_footer() {
    let base = read("website/templates/base.html");
    assert!(
        base.contains("class=\"site-footer\""),
        "base.html no longer renders .site-footer"
    );

    let empty_override = regex::Regex::new(r"\{%\s*block footer\s*%\}\s*\{%\s*endblock").unwrap();
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        if name == "base.html" {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read template");
        if empty_override.is_match(&text) {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "these templates blank the footer block, hiding the site footer on \
         their pages: {offenders:?}"
    );
}

// ---------------------------------------------------------------------------
// Sponsor/GitHub placement journey: the Patreon sponsor button, the GitHub
// Sponsors heart, and the GitHub link belong ONLY in the footer — the top nav
// carries navigation and search, nothing else. In the footer they render as
// icon links (svg + aria-label), not as "Support on Patreon"-style text, and
// the whole footer is ONE non-wrapping row: no footer-top/footer-bottom
// tiers, no "Built with Rust" credit.
// ---------------------------------------------------------------------------

/// Slice a named `{% block X %}...{% endblock %}` region out of base.html.
fn base_block(name: &str) -> String {
    let base = read("website/templates/base.html");
    let open = format!("{{% block {name} %}}");
    let start = base
        .find(&open)
        .unwrap_or_else(|| panic!("base.html has no `{open}`"));
    let end = base[start..]
        .find("{% endblock")
        .unwrap_or_else(|| panic!("`{open}` is unterminated"));
    base[start..start + end].to_string()
}

#[test]
fn sponsor_heart_and_github_live_only_in_the_footer() {
    let nav = base_block("nav");
    for banned in [
        "patreon_url",
        "github_sponsors_url",
        "config.extra.github_url",
    ] {
        assert!(
            !nav.contains(banned),
            "top nav still links `{banned}` — sponsor/heart/GitHub links \
             belong only in the footer"
        );
    }

    let footer = base_block("footer");
    for required in [
        "patreon_url",
        "github_sponsors_url",
        "config.extra.github_url",
    ] {
        assert!(
            footer.contains(required),
            "footer lost its `{required}` link — moving it out of the nav \
             must not drop it from the site"
        );
    }
}

#[test]
fn footer_is_one_non_wrapping_row_with_icon_sponsor_links() {
    let footer = base_block("footer");

    // One row, not two tiers.
    for tier in ["footer-top", "footer-bottom"] {
        assert!(
            !footer.contains(tier),
            "footer still has the two-tier `{tier}` layout — it must be a \
             single `footer-row`"
        );
    }
    assert!(
        footer.contains("class=\"footer-row\""),
        "footer has no .footer-row container"
    );

    // "Built with Rust" is gone.
    assert!(
        !footer.contains("Built with"),
        "footer still carries the `Built with Rust` credit"
    );

    // Patreon / GitHub Sponsors are icons, not text links.
    for text in ["Support on Patreon", ">GitHub Sponsors<"] {
        assert!(
            !footer.contains(text),
            "footer still renders `{text}` as a text link — use an icon"
        );
    }
    for (url, what) in [
        ("patreon_url", "Patreon"),
        ("github_sponsors_url", "GitHub Sponsors"),
    ] {
        let at = footer
            .find(url)
            .unwrap_or_else(|| panic!("footer has no `{url}` link"));
        let anchor_end = footer[at..]
            .find("</a>")
            .unwrap_or_else(|| panic!("`{url}` anchor is unterminated"));
        let anchor = &footer[at..at + anchor_end];
        assert!(
            anchor.contains("<svg") && anchor.contains("aria-label"),
            "the {what} footer link must be an svg icon with an aria-label"
        );
    }

    // The stylesheet must actually forbid wrapping on the row.
    let scss = read("website/sass/style.scss");
    let rule_at = scss
        .find(".footer-row")
        .expect("style.scss has no .footer-row rule");
    let rule_end = scss[rule_at..]
        .find('}')
        .expect(".footer-row rule is unterminated");
    let rule = &scss[rule_at..rule_at + rule_end];
    assert!(
        rule.contains("flex-wrap: nowrap"),
        ".footer-row must declare `flex-wrap: nowrap` so the footer never \
         breaks into a second line"
    );
}

// ---------------------------------------------------------------------------
// CSS cache-buster journey: the stylesheet link once used `?v=<version>`, so
// a site-only change (same crate version) shipped new HTML against CACHED old
// CSS — the single-row footer rendered as three unstyled block rows for every
// returning visitor until their cache expired. The buster must be Zola's
// content hash (`cachebust=true`), which changes whenever the CSS does.
// ---------------------------------------------------------------------------

#[test]
fn stylesheet_link_is_content_hash_cachebusted() {
    let base = read("website/templates/base.html");
    let link = base
        .lines()
        .find(|l| l.contains("style.css") && l.contains("stylesheet"))
        .expect("base.html has no style.css <link>");
    assert!(
        !link.contains("?v="),
        "style.css is busted by release version — a site-only change keeps \
         the URL identical and ships new HTML with stale cached CSS: {link}"
    );
    assert!(
        link.contains("cachebust=true"),
        "style.css link must use get_url(..., cachebust=true) so the URL \
         changes whenever the CSS content does: {link}"
    );
}

// ---------------------------------------------------------------------------
// Download-personas journey: the download page serves two audiences that the
// platform tabs alone don't. DevOps wants binaries with no interactive steps:
// the ghcr.io container image (published on every tag since v0.5.x but absent
// from the site for months), a version-pinned scripted install, raw artifact
// URLs with checksum sidecars, and latest-version discovery without HTML
// scraping. Developers want the source alongside the binaries: source
// archives for the tag, cargo install, and the build docs. Modeled on how
// rclone ("Downloads for scripting") and Prometheus (artifact table with
// checksums) organize theirs.
// ---------------------------------------------------------------------------

#[test]
fn download_page_serves_devops_and_source_personas() {
    let tpl = read("website/templates/download.html");

    // DevOps: container image, pinned + latest tags.
    assert!(
        tpl.contains("ghcr.io/normb/sipnab"),
        "download page must offer the ghcr.io/normb/sipnab container image \
         (docker.yml publishes it on every tag)"
    );
    // DevOps: an automation section, reachable from the page ToC.
    assert!(
        tpl.contains("id=\"automation\""),
        "download page needs an #automation section for the scripted/CI path"
    );
    assert!(
        tpl.contains("href=\"#automation\""),
        "the page ToC must link to #automation"
    );
    // DevOps: version-pinned scripted install (install.sh honors these).
    assert!(
        tpl.contains("SIPNAB_VERSION"),
        "automation section must document SIPNAB_VERSION for pinned installs"
    );
    // DevOps: latest-version discovery without scraping HTML.
    assert!(
        tpl.contains("api.github.com/repos/NormB/sipnab/releases/latest"),
        "automation section must show latest-version discovery via the \
         releases API"
    );
    // DevOps: checksum sidecars are linked next to the artifacts.
    assert!(
        tpl.contains(".tar.gz.sha256"),
        "artifact table must link the per-tarball .sha256 sidecars"
    );

    // Developers: source alongside binaries.
    assert!(
        tpl.contains("archive/refs/tags/v"),
        "source panel must link the tag's source archives"
    );
    assert!(
        tpl.contains("cargo install sipnab"),
        "source panel must offer cargo install (sipnab is on crates.io)"
    );
    assert!(
        tpl.contains("@/docs/build.md"),
        "source panel must link the Build-from-Source docs page"
    );
}

// ---------------------------------------------------------------------------
// CSP hash journey: the production CSP (a Cloudflare transform rule, managed
// by ops/cloudflare/refresh_csp_hashes.py) allows inline <script> blocks by
// sha256 hash, NOT 'unsafe-inline'. Editing an inline script without
// refreshing the rule ships a page whose script the browser silently blocks —
// the download page's platform tabs were dead in production for a day this
// way. This pin list makes the refresh step unforgettable: any inline-script
// edit fails here until the dev (a) deploys, (b) runs
// `python3 ops/cloudflare/refresh_csp_hashes.py`, and (c) re-pins.
//
// Pins are computed over the RAW TEMPLATE script bodies; where a script has
// no Tera syntax the pin equals the deployed CSP token exactly (all except
// base.html today).
// ---------------------------------------------------------------------------

#[test]
fn inline_script_edits_require_csp_hash_refresh() {
    use base64::Engine as _;
    use sha2::Digest as _;

    const PINNED: &[(&str, &str)] = &[
        (
            "base.html",
            "sha256-J1UbBOogoXxCXnxiSeI0gyXiVXXoOpudQyXbBuS54aI=",
        ),
        (
            "download.html",
            "sha256-Xtyi8+j9vCissO93mpqXa8azlys1i9B1bM6M7KOXx6Q=",
        ),
        (
            "index.html",
            "sha256-HQzT0Db6Er849zDjz/Oh1NAg+q8aPwW+sSXD928L7W4=",
        ),
        (
            "page.html",
            "sha256-M17DoO9piJx5EpFaDEJn5Q9DZKuTLZWWKx2H19xX9CU=",
        ),
        (
            "page.html",
            "sha256-UOwnn7uXvW/gl+mP2NGmMuxif0eKdH7ocCwmMTGCjcY=",
        ),
    ];

    // Same extraction semantics as refresh_csp_hashes.py: inline, executable.
    let tag = regex::Regex::new(r"(?is)<script([^>]*)>(.*?)</script>").unwrap();
    let mut found: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        let text = std::fs::read_to_string(&p).expect("read template");
        for cap in tag.captures_iter(&text) {
            let attrs = &cap[1];
            if attrs.contains("src=") || attrs.contains("ld+json") {
                continue;
            }
            let digest = sha2::Sha256::digest(cap[2].as_bytes());
            let token = format!(
                "sha256-{}",
                base64::engine::general_purpose::STANDARD.encode(digest)
            );
            found.push((name.clone(), token));
        }
    }
    found.sort();

    let mut pinned: Vec<(String, String)> = PINNED
        .iter()
        .map(|(f, h)| (f.to_string(), h.to_string()))
        .collect();
    pinned.sort();

    assert_eq!(
        found, pinned,
        "an inline <script> in website/templates/ changed. The production CSP \
         only allows inline scripts by sha256 hash — the edited script will be \
         SILENTLY BLOCKED in production until the Cloudflare rule is updated. \
         After this change deploys, run \
         `python3 ops/cloudflare/refresh_csp_hashes.py`, then update PINNED in \
         this test to the computed list above."
    );
}
