// SPDX-License-Identifier: MIT OR Apache-2.0

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
//!
//! Approach: all guards are static checks over the repo tree (templates,
//! tapes, content, stylesheets, CI workflows). Where a guard needs behavior,
//! it drives the real thing rather than a mock: the `tui`-gated modules load
//! the demo pcaps through the actual TUI `App`, and the CSP guards execute
//! `ops/cloudflare/refresh_csp_hashes.py` in dry-run mode.

// `Cli` lives behind the `native` feature, and this file's other 37 gates are
// site/doc checks that must keep compiling in every reduced combination — so
// the import and the one test that needs it are gated rather than the file.
#[cfg(feature = "native")]
use clap::CommandFactory;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Repository root, taken from `CARGO_MANIFEST_DIR`.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repo-relative file to a `String`, panicking with the path on
/// failure.
fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The YAML block of one named step: its `- name:` line through the last line
/// belonging to it. Panics if the step is absent or duplicated.
fn workflow_step_body(workflow: &str, step_name: &str) -> String {
    let text = read(workflow);
    let lines: Vec<&str> = text.lines().collect();
    let needle = format!("- name: {step_name}");
    let matches: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim() == needle)
        .map(|(i, _)| i)
        .collect();
    assert!(
        !matches.is_empty(),
        "{workflow} has no step named {step_name:?} — it was renamed or removed, \
         and every assertion about it is checking nothing"
    );
    assert_eq!(
        matches.len(),
        1,
        "{workflow} has {} steps named {step_name:?}. Duplicate names are legal, so \
         a scan taking the first match reads whichever an author put first — the \
         real step can be neutered behind a decoy",
        matches.len()
    );
    let start = matches[0];
    let indent = lines[start].len() - lines[start].trim_start().len();
    let mut out = vec![lines[start]];
    for l in &lines[start + 1..] {
        let t = l.trim_start();
        if t.is_empty() {
            out.push(l);
            continue;
        }
        let ind = l.len() - t.len();
        if ind < indent || (ind == indent && t.starts_with("- ")) {
            break;
        }
        out.push(l);
    }
    out.join("\n")
}

/// Run a workflow step's `run:` script against deliberately-wrong input and
/// assert it exits non-zero.
///
/// This is the only assertion here that tests the behavior rather than the
/// text. Structural checks — no `continue-on-error`, an `exit 1` present, an
/// `::error::` followed by an exit — each anchor on a pattern the author can
/// simply not use: downgrading `::error::` to `::warning::` and dropping the
/// exit defeated all of them, with the step still running and the build still
/// green. Executing the script cannot be sidestepped that way, because a step
/// that does not fail on bad input is precisely the defect.
///
/// # Arguments
/// * `subs` - `(from, to)` replacements for GitHub expressions like
///   `${{ matrix.target }}`, which bash cannot evaluate.
/// * `setup` - prepares a temp CWD holding the inputs the script reads, seeded
///   so the check must fail.
fn assert_step_fails_on_bad_input(
    workflow: &str,
    step_name: &str,
    subs: &[(&str, &str)],
    setup: &dyn Fn(&std::path::Path),
) {
    let body = workflow_step_body(workflow, step_name);
    // Take the run: block only, stopping at the next YAML key at run:'s own
    // indent. Reading to the end of the step handed bash whatever followed —
    // an ordinary `env:` block became a command, exit 127, and 127 satisfied
    // "exited non-zero", so a neutered step plus an env: block passed.
    let all: Vec<&str> = body.lines().collect();
    let run_at = all
        .iter()
        .position(|l| l.trim_start().starts_with("run:"))
        .unwrap_or_else(|| panic!("{workflow} step {step_name:?} has no `run:` block"));
    let run_indent = all[run_at].len() - all[run_at].trim_start().len();
    let block: Vec<&str> = all[run_at + 1..]
        .iter()
        .take_while(|l| {
            let t = l.trim_start();
            t.is_empty() || l.len() - t.len() > run_indent
        })
        .cloned()
        .collect();
    // Dedent by the block's own minimum indent rather than a fixed width, so a
    // differently-indented step does not yield garbage that then "fails" for
    // the wrong reason.
    let dedent = block
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut script = block
        .iter()
        .map(|l| {
            if l.len() >= dedent {
                &l[dedent..]
            } else {
                l.trim_start()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !script.trim().is_empty(),
        "{workflow} step {step_name:?}: could not extract a `run:` script — this \
         check is executing nothing"
    );
    for (from, to) in subs {
        script = script.replace(from, to);
    }

    let dir = std::env::temp_dir().join(format!(
        "sipnab-step-{}-{}",
        step_name.replace([' ', '(', ')', '/'], "-"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    setup(&dir);

    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(&dir)
        .output()
        .expect("run step script");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !out.status.success(),
        "{workflow} step {step_name:?} exited 0 on input its check should reject. \
         It runs, it may even annotate the problem, and the build stays green — \
         which is the state this gate exists to prevent.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A named workflow step still fails the build when its check fails.
///
/// Asserting the file *contains* some identifying string is a proxy: it stays
/// true through every way of neutering the step. This checks the four that
/// reach the same end state — the step runs, annotates the problem, and the
/// build stays green:
///
/// 1. `continue-on-error` on the step, which rewrites its conclusion to
///    success and leaves the truth in `outcome`, which nothing reads.
/// 2. `continue-on-error` on the enclosing JOB, which does the same thing one
///    level up and is invisible to anything reading only the step.
/// 3. Deleting the load-bearing `exit 1`. This step has three, and only the
///    one after the `::error::` annotation is the verdict — so "contains an
///    `exit 1`" passes with the verdict removed. Every `::error::` must be
///    followed by an exit, which is the property rather than a count.
/// 4. A decoy step with the same name earlier in the file. Duplicate step
///    names are legal in GitHub Actions, and a scan taking the first match
///    reads the decoy.
///
/// All four were demonstrated passing against the previous version of this
/// helper before it was rewritten.
///
/// # Arguments
/// * `guard` - the only `if:` allowed on the step, or `None` for unconditional.
fn assert_step_enforces(workflow: &str, step_name: &str, guard: Option<&str>) {
    let body = workflow_step_body(workflow, step_name);
    let step: Vec<&str> = body.lines().collect();
    let text = read(workflow);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim() == format!("- name: {step_name}"))
        .expect("step located by workflow_step_body");

    assert!(
        !body.contains("continue-on-error"),
        "{workflow} step {step_name:?} carries continue-on-error, which rewrites \
         its conclusion to success and leaves the real result in `outcome`, which \
         nothing reads — the step runs and its verdict is discarded"
    );

    // The enclosing job, found by walking back to the nearest 2-space key.
    let job_line = lines[..start]
        .iter()
        .rposition(|l| {
            let t = l.trim_start();
            l.len() - t.len() == 2 && t.ends_with(':') && !t.starts_with('#')
        })
        .unwrap_or_else(|| panic!("{workflow}: no enclosing job found for {step_name:?}"));
    // Every key belonging to this job, to the start of the next job — NOT the
    // text above `steps:`. YAML mappings are unordered, so `continue-on-error`
    // appended after the steps list is still a job-level key; the old scan
    // stopped at `steps:` and could not see it. Job keys sit one indent level
    // in from the job name, which excludes anything inside a step.
    let job_indent = lines[job_line].len() - lines[job_line].trim_start().len();
    let job_keys: String = lines[job_line + 1..]
        .iter()
        .take_while(|l| {
            let t = l.trim_start();
            t.is_empty() || l.len() - t.len() > job_indent
        })
        .filter(|l| {
            let t = l.trim_start();
            !t.is_empty() && l.len() - t.len() == job_indent + 2 && !t.starts_with('#')
        })
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !job_keys.contains("continue-on-error"),
        "{workflow}: the job containing {step_name:?} carries continue-on-error, \
         which discards the whole job's verdict — the step's own block being \
         clean says nothing"
    );

    // Every error annotation must actually fail the build. A count of `exit 1`
    // would be a proxy: this step has three, and only the one after the
    // `::error::` is the verdict.
    for (i, l) in step.iter().enumerate() {
        if !l.contains("::error::") {
            continue;
        }
        // Same line first: `{ echo "::error::..."; exit 1; }` is one line.
        let follows = l.contains("exit 1")
            || step[i + 1..]
                .iter()
                .take(3)
                .any(|n| n.contains("exit 1") || n.contains("exit $"));
        assert!(
            follows,
            "{workflow} step {step_name:?} emits an ::error:: annotation that is not \
             followed by a non-zero exit:\n  {}\nThe mismatch is reported and the \
             build stays green, which is the state this gate exists to prevent",
            l.trim()
        );
    }
    assert!(
        body.contains("exit 1"),
        "{workflow} step {step_name:?} no longer exits non-zero on failure"
    );

    let actual_guard = step
        .iter()
        .find(|l| l.trim_start().starts_with("if:"))
        .map(|l| l.trim().trim_start_matches("if:").trim().to_string());
    match guard {
        Some(want) => assert_eq!(
            actual_guard.as_deref(),
            Some(want),
            "{workflow} step {step_name:?} guard changed. It must run on exactly the \
             platform/target it was written for; a widened or falsified condition \
             skips it while the workflow stays green"
        ),
        None => assert!(
            actual_guard.is_none(),
            "{workflow} step {step_name:?} gained an `if:` guard ({actual_guard:?}) — \
             a guard is how a step stops running without its body changing"
        ),
    }
}

// ---------------------------------------------------------------------------
// Font journey: every FontFamily a tape names must be an installed monospace
// family on the box that renders the demos.
// ---------------------------------------------------------------------------

/// Monospace font families installed on this machine, per fontconfig.
///
/// # Returns
/// `None` when `fc-list` is unavailable or fails; otherwise the family set.
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
///
/// # Returns
/// (tape filename, font family) pairs for every declaration found.
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

/// Every FontFamily a demo tape names must be an installed monospace
/// family (2026-07-18 regression); skips off-Linux or when fc-list is missing.
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

/// Demo asset filenames the site actually references: `get_url` paths in
/// the homepage/base templates, the sample pcap fetched by `analyze.js`,
/// and the derived `-poster.png` first-frames of each animated demo.
///
/// # Returns
/// The referenced filenames (relative to `website/static/demos`).
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
    // animated demo (`.demo-panel img`, not the hero still) for
    // prefers-reduced-motion, so those posters are referenced too.
    let posters: Vec<String> = out
        .iter()
        .filter(|f| f.ends_with(".webp") && *f != "hero-static.webp")
        .map(|f| f.replace(".webp", "-poster.png"))
        .collect();
    out.extend(posters);
    out
}

/// Filenames actually shipped in `website/static/demos`.
fn present_demo_assets() -> BTreeSet<String> {
    std::fs::read_dir(repo().join("website/static/demos"))
        .expect("static/demos dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

/// Every referenced demo asset exists in static/demos and no shipped file is unreferenced.
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

// ---------------------------------------------------------------------------
// Homepage entry-point journey: what the page offers a stranger, and in what
// order. Two guards, both over website/templates/index.html.
//
// The site has a zero-install route -- the WASM analyzer at /analyze/, which
// parses a capture in the visitor's own browser -- and for a long time the
// homepage mentioned it only in one row of the capability table, below the
// demos, the features and the comparison. The nav and the footer carried it;
// the page that has to earn the click did not.
//
// And the demo wall led with eleven tabs, seven of them named after a sipnab
// INTERFACE ("Detail Pane", "Multi-Leg"), which is a question only an existing
// user knows to ask. The four outcome-titled ones lead; the rest are collapsed
// behind a disclosure. Collapsed, never deleted --
// `every_referenced_demo_asset_exists_and_none_are_orphaned` above fails on a
// shipped-but-unreferenced .webp, so a "tidy-up" that drops a tab breaks the
// build rather than quietly shrinking the demos.
// ---------------------------------------------------------------------------

/// The `<a …>` elements inside `haystack`, as (href, inner text) pairs.
///
/// `href="…"` holds a Tera call whose own quoting is single (`get_url(path='…')`),
/// so a double-quoted attribute value is still one capture.
fn anchors(haystack: &str) -> Vec<(String, String)> {
    regex::Regex::new(r#"(?s)<a\s[^>]*href="([^"]*)"[^>]*>(.*?)</a>"#)
        .unwrap()
        .captures_iter(haystack)
        .map(|c| (c[1].to_string(), c[2].trim().to_string()))
        .collect()
}

/// The homepage hero offers the zero-install browser analyzer, above the fold.
///
/// "Above the fold" is read structurally: everything before `<section
/// class="demos"`, the first thing after the hero. A CTA that slides below
/// that is a CTA the visitor scrolls past, and the capability-table row that
/// used to be the page's only mention of /analyze/ lives far below it — so a
/// move back to that row must fail this, not pass it.
#[test]
fn homepage_offers_a_zero_install_path() {
    let page = read("website/templates/index.html");
    let fold = page.find("<section class=\"demos\"").expect(
        "index.html no longer has a `<section class=\"demos\"` — this test locates the fold by it",
    );

    // The hero ELEMENT, not merely "the bytes before the demos section". Those
    // differ by the handful of characters between `</section>` and the next
    // `<section`, and a link parked in that gap is above the fold marker while
    // being in no section at all — which passed an earlier version of this
    // test. Asserting the hero closes above the fold keeps the fold marker
    // meaningful without letting the gap through.
    let hero_span = element_span(&page, "<section class=\"hero\">", "section");
    assert!(
        hero_span.end <= fold,
        "the hero section no longer closes before `<section class=\"demos\"` — \
         the page order this test reads has changed"
    );
    let hero = &page[hero_span.start..hero_span.end];

    let links = anchors(hero);
    // Anti-vacuity: the hero really does contain several links (the two RFC
    // references and the CTA row), so a regex that silently matched nothing
    // cannot make the assertion below pass by finding zero of zero.
    assert!(
        links.len() >= 3,
        "only {} links parsed out of the homepage hero — the anchor extractor \
         is broken, so the analyzer check below would be vacuous:\n{hero}",
        links.len()
    );

    let cta = links
        .iter()
        .find(|(href, _)| href.contains("@/analyze/"))
        .unwrap_or_else(|| {
            panic!(
                "the homepage hero offers no link to the browser analyzer. The \
                 zero-install path (`@/analyze/_index.md`) must be reachable \
                 from above the fold, not only from the nav, the footer and a \
                 capability-table row far below. Links found in the hero: {:?}",
                links.iter().map(|(h, _)| h).collect::<Vec<_>>()
            )
        });

    assert!(
        !cta.1.is_empty(),
        "the hero's analyzer link has no visible text: {cta:?}"
    );

    // A CTA, not a word buried in a sentence: it carries the button styling
    // the other two hero actions use.
    let cta_tag_at = hero.find("@/analyze/").expect("checked above");
    let tag_start = hero[..cta_tag_at]
        .rfind("<a ")
        .expect("the analyzer href is inside an <a> element");
    let tag_end = tag_start
        + hero[tag_start..]
            .find('>')
            .expect("unterminated <a> tag in the hero");
    let tag = &hero[tag_start..tag_end];
    assert!(
        tag.contains("class=\"btn"),
        "the hero's analyzer link is not styled as a call to action (no `btn` \
         class): {tag}"
    );

    // And it must say what the visitor is agreeing to. "Local" is the entire
    // pitch: a capture is evidence, and a stranger will not drop one into a
    // web page that might upload it.
    let lower = hero.to_lowercase();
    assert!(
        lower.contains("in your browser") || lower.contains("in the browser"),
        "the hero offers the analyzer without saying the capture is parsed in \
         the visitor's own browser — the one fact that makes uploading a \
         capture an acceptable ask"
    );
}

/// The demo wall leads with the four outcome-titled demos; the rest are collapsed.
///
/// Three properties, each one careless edit from being lost:
///
/// 1. Exactly the outcome set is visible. A twelfth tab appended to the
///    tablist rather than to the disclosure rebuilds the wall one tab at a
///    time, and nothing else in the suite would notice.
/// 2. Every other tab is still IN the tablist, inside `#demo-tabs-more`. They
///    are hidden, not removed; the orphaned-asset guard above makes removal a
///    build failure anyway.
/// 3. Tabs and panels still count the same. A tab whose panel was deleted (or
///    the reverse) is a control that does nothing.
///
/// The arrow-key roving is pinned here too, because it is the part that breaks
/// silently: it reads a flat `.demo-tab` list, and stepping onto a collapsed
/// tab focuses nothing (`.focus()` on `display:none` is a no-op) while still
/// clicking it — the panel changes under a focus ring that never moved.
#[test]
fn homepage_demo_wall_leads_with_outcomes() {
    let page = read("website/templates/index.html");

    // The four the wall leads with. Rewording one is fine; doing it silently
    // is not — an interface name creeping back to the front is exactly the
    // regression this pins.
    const OUTCOMES: [&str; 5] = [
        "Show me the whole call",
        "Why did it fail?",
        "Which RFC?",
        "Show me the bytes",
        "Same call?",
    ];

    let tablist = element_span(&page, "<div class=\"demo-tabs\" role=\"tablist\"", "div");
    let disclosure = element_span(&page, "<div class=\"demo-tabs-more\"", "div");
    assert!(
        tablist.start < disclosure.start && disclosure.end <= tablist.end,
        "`#demo-tabs-more` must sit INSIDE the tablist: the collapsed demos \
         stay part of the same tab set, they are merely not painted"
    );

    let tab = regex::Regex::new(
        r#"<button class="demo-tab[^"]*"[^>]*id="demo-tab-(\d+)"[^>]*>([^<]*)</button>"#,
    )
    .unwrap();
    let tabs: Vec<(usize, usize, String)> = tab
        .captures_iter(&page)
        .map(|c| {
            let m = c.get(0).expect("whole match");
            (
                m.start(),
                c[1].parse::<usize>().expect("numeric tab id"),
                c[2].trim().to_string(),
            )
        })
        .collect();

    // Anti-vacuity: a broken extractor must not pass by matching nothing.
    assert!(
        tabs.len() >= 8,
        "only {} demo tabs parsed out of index.html — the extractor is broken, \
         so every assertion below would be vacuous",
        tabs.len()
    );

    for (at, id, label) in &tabs {
        assert!(
            tablist.start < *at && *at < tablist.end,
            "demo tab {id} ({label:?}) is outside the `.demo-tabs` tablist"
        );
    }

    let (visible, collapsed): (Vec<_>, Vec<_>) = tabs
        .iter()
        .partition(|(at, _, _)| *at < disclosure.start || *at >= disclosure.end);

    let visible_labels: Vec<&str> = visible.iter().map(|(_, _, l)| l.as_str()).collect();
    assert_eq!(
        visible_labels, OUTCOMES,
        "the demo wall must lead with exactly the outcome-titled demos, in \
         order. Every other tab belongs inside `#demo-tabs-more`. If the \
         outcome set genuinely changed, update OUTCOMES here — deliberately."
    );
    let visible_ids: Vec<usize> = visible.iter().map(|(_, id, _)| *id).collect();
    assert_eq!(
        visible_ids,
        (0..OUTCOMES.len()).collect::<Vec<_>>(),
        "the visible tabs must be demo-tab-0 upward with no gap, so they \
         select the first panels in the same order"
    );
    assert!(
        !collapsed.is_empty(),
        "no tabs are inside `#demo-tabs-more` — the disclosure has nothing to \
         disclose, which means the wall is uncollapsed again"
    );

    // Tabs and panels describe the same set.
    let panels = page.matches("role=\"tabpanel\"").count();
    assert_eq!(
        tabs.len(),
        panels,
        "{} demo tabs against {panels} panels — every tab must control a panel \
         and every panel must be reachable from a tab",
        tabs.len()
    );
    for (_, id, label) in &tabs {
        assert!(
            page.contains(&format!("id=\"demo-panel-{id}\"")),
            "demo tab {id} ({label:?}) controls `demo-panel-{id}`, which does not exist"
        );
    }

    // The disclosure must start shut and be driven by a real control.
    let opener = element_open_tag(&page, "<div class=\"demo-tabs-more\"");
    assert!(
        opener.contains(" hidden"),
        "`#demo-tabs-more` must ship collapsed — otherwise the wall is back on \
         first paint: {opener}"
    );
    assert!(
        opener.contains("role=\"presentation\""),
        "`#demo-tabs-more` must carry role=\"presentation\" so the tablist \
         still owns only tabs: {opener}"
    );
    let toggle = element_open_tag(&page, "<button type=\"button\" class=\"demo-more-btn\"");
    assert!(
        toggle.contains("aria-controls=\"demo-tabs-more\"")
            && toggle.contains("aria-expanded=\"false\""),
        "the disclosure button must name what it controls and start collapsed: {toggle}"
    );
    let toggle_at = page
        .find("<button type=\"button\" class=\"demo-more-btn\"")
        .expect("checked above");
    assert!(
        toggle_at >= tablist.end,
        "the disclosure button is inside the tablist; a tablist may own only \
         tabs, so it must sit after `.demo-tabs` closes"
    );
    assert!(
        page.contains("getElementById('demo-tabs-more')"),
        "nothing in the homepage script opens `#demo-tabs-more` — the \
         disclosure button would be a dead control (and it cannot use \
         onclick=, which the CSP blocks)"
    );

    // The roving must skip collapsed tabs.
    assert!(
        page.contains("closest('.demo-tabs-more')"),
        "the arrow-key roving no longer filters out collapsed tabs. An \
         unfiltered `.demo-tab` list steps onto a hidden tab: focus stays put \
         (`.focus()` on display:none does nothing) while the click still \
         swaps the panel."
    );
}

/// Byte range of an element, from `open` to its depth-matched closing tag.
struct Span {
    start: usize,
    end: usize,
}

/// Locate `open` in `html` and return the span through its matching `</tag>`.
fn element_span(html: &str, open: &str, tag: &str) -> Span {
    let start = html
        .find(open)
        .unwrap_or_else(|| panic!("index.html has no `{open}`"));
    let open_pat = format!("<{tag}");
    let close_pat = format!("</{tag}>");
    let mut depth = 0usize;
    let mut i = start;
    while i < html.len() {
        let next_open = html[i..].find(&open_pat).map(|n| i + n);
        let next_close = html[i..].find(&close_pat).map(|n| i + n);
        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                i = o + open_pat.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                i = c + close_pat.len();
                if depth == 0 {
                    return Span { start, end: i };
                }
            }
            _ => break,
        }
    }
    panic!("`{open}` is never closed in index.html");
}

/// The full open tag (`<div …>`) beginning at `open`.
fn element_open_tag(html: &str, open: &str) -> String {
    let start = html
        .find(open)
        .unwrap_or_else(|| panic!("index.html has no `{open}`"));
    let end = start
        + html[start..]
            .find('>')
            .unwrap_or_else(|| panic!("`{open}` is an unterminated tag"));
    html[start..=end].to_string()
}

/// The homepage's JSON MCP examples must be the answers the tool actually gave.
///
/// The examples that are NOT a single JSON document -- the JSON-lines dialog
/// list and the drawn ladder the lead panel publishes -- are covered by
/// `every_published_mcp_example_comes_from_its_generated_file` at the end of
/// this file, which enumerates the directory instead of naming files.
///
/// The chain is `live binary -> website/data/mcp-examples/* -> index.html`.
/// `demos/gen-mcp-examples.sh --check` proves the first link and needs a built
/// binary to do it; this proves the second, and needs nothing, so it runs in
/// every CI job. Without it the page could be hand-edited to claim an answer no
/// file backs -- which is the marketing-screenshot failure demos/Makefile was
/// written to prevent, in the one medium a rendered recording cannot be
/// compared against.
///
/// The blocks are HTML-escaped on the page because `Contact: <sip:user@host>`
/// would otherwise close the `<code>` element early, so this unescapes before
/// comparing. `&amp;` is undone LAST: doing it first would turn a literal
/// `&amp;lt;` in the data into `<` and compare equal to the wrong thing.
#[test]
fn homepage_mcp_examples_match_their_generated_source() {
    let page = read("website/templates/index.html");
    for name in ["triage", "lint", "evidence", "correlate"] {
        let generated = read(&format!("website/data/mcp-examples/{name}.json"));
        let begin = format!("<!-- mcp-example:{name} BEGIN -->");
        let end = format!("<!-- mcp-example:{name} END -->");

        let open = page
            .find(&begin)
            .unwrap_or_else(|| panic!("index.html has no {begin} — run demos/gen-mcp-examples.sh"));
        let close = page
            .find(&end)
            .unwrap_or_else(|| panic!("index.html has no {end} — run demos/gen-mcp-examples.sh"));
        assert!(
            close > open,
            "{name}: END marker precedes BEGIN in index.html"
        );

        let published = page[open + begin.len()..close]
            .trim_matches('\n')
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");

        assert_eq!(
            published,
            generated.trim_end_matches('\n'),
            "the {name} block on the homepage is not website/data/mcp-examples/{name}.json. \
             Regenerate with `demos/gen-mcp-examples.sh` rather than editing the page."
        );

        // Parsing is the point of publishing JSON: a block that a reader
        // cannot paste into `jq` is not an example of anything.
        serde_json::from_str::<serde_json::Value>(&published)
            .unwrap_or_else(|e| panic!("the {name} block on the homepage is not valid JSON: {e}"));
    }
}

/// Each MCP panel must still show the claim its prose makes about it.
///
/// Separate from the equality test above on purpose: that one proves the page
/// matches the generated file, and would stay green if the tool started
/// answering something else entirely and the file was regenerated to match. A
/// verdict that stopped saying `signaling`, evidence that stopped reporting
/// `verified`, or a correlation that stopped admitting `heuristic_only` would
/// each make the surrounding copy false while every file agreed with every
/// other file.
#[test]
fn each_mcp_example_still_carries_the_claim_the_page_makes_about_it() {
    for (name, pointer, want) in [
        ("triage", "/verdict", "signaling"),
        ("lint", "/section", "12.1.1"),
        ("evidence", "/frames/0/status", "verified"),
        ("correlate", "/legs/0/strategy", "timing_heuristic"),
    ] {
        let v: serde_json::Value =
            serde_json::from_str(&read(&format!("website/data/mcp-examples/{name}.json")))
                .unwrap_or_else(|e| panic!("{name}.json is not valid JSON: {e}"));
        let got = v.pointer(pointer).unwrap_or_else(|| {
            panic!("{name}.json no longer has {pointer}, which the homepage describes")
        });
        assert_eq!(
            got, want,
            "{name}.json{pointer} is {got}, but the homepage copy says {want}"
        );
    }

    // The one the page states outright: the match is timing-only, and saying so
    // is the feature. A `false` here with the copy unchanged is a lie on the page.
    let correlate: serde_json::Value =
        serde_json::from_str(&read("website/data/mcp-examples/correlate.json")).expect("json");
    assert_eq!(
        correlate["heuristic_only"], true,
        "correlate.json no longer flags heuristic_only, which the homepage promises it does"
    );
}

/// Every tape Output/Screenshot landing in static/demos must map to a referenced asset (its .webp counterpart counts).
#[test]
fn every_tape_output_is_a_referenced_site_asset() {
    // A tape whose Output lands in static/demos must correspond to a
    // referenced asset. Tapes render GIF (and the hero tape screenshots PNG);
    // demos/Makefile converts each to the lossless WebP the site actually
    // ships, so a tape's .gif/.png output counts as referenced when its .webp
    // counterpart is.
    let re = regex::Regex::new(r"(?m)^(?:Output|Screenshot)\s+(\S+)").unwrap();
    let to_webp = regex::Regex::new(r"\.(gif|png)$").unwrap();
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
                && !referenced.contains(&to_webp.replace(name, ".webp").into_owned())
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

/// Every `@/docs` link in the base/index chrome resolves to an existing content page.
#[test]
fn every_nav_docs_link_resolves_to_a_content_page() {
    // `/` is in the class so subsection links (`@/docs/internals/x.md`) are
    // checked too. Without it the pattern simply did not match them, and a
    // broken developer-docs link in the nav would have passed silently.
    let re = regex::Regex::new(r"@/docs/([A-Za-z0-9_/-]+\.md)").unwrap();
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

/// The Zola config `version` equals the Cargo.toml crate version. It is a
/// committed mirror, not a value any page renders.
#[test]
fn site_version_matches_crate_version() {
    // Keeps the committed mirror honest: the Zola config's `version` must equal
    // the crate version in Cargo.toml, which the Pages "Sync site version" step
    // overwrites it from at build time anyway. Mirrors the pre-commit gate as a
    // permanent test.
    //
    // This is NOT the "homepage still shows the old version" guard it used to
    // claim to be. The badge (index.html), the footer and JSON-LD
    // `softwareVersion` (base.html) and every /download link (download.html)
    // read `published_version`, and nothing reads `config.extra.version`.
    // `site_advertises_only_a_released_version` below is what guards those.
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
         ({crate_v}) — the committed mirror has drifted from the crate. This \
         does NOT affect the homepage badge or /download: those read \
         published_version, guarded by site_advertises_only_a_released_version"
    );
}

/// The download page's release date matches the CHANGELOG entry it describes.
///
/// `release_date` had no gate at all and had drifted two days behind the
/// 0.5.44 CHANGELOG heading — the version beside it was gated, the date next
/// to it was not, so /download advertised the right version on the wrong day.
#[test]
fn site_release_date_matches_changelog() {
    let cfg = read("website/config.toml");
    // `published_version`, NOT `version`.
    //
    // `download.html` does `{% set v = config.extra.published_version %}` and
    // renders that version beside `release_date` in one sentence, so the date
    // belongs to the PUBLISHED release. Reading `version` here meant that at
    // every release cut this gate demanded the date of a release that did not
    // exist yet, while the page still showed the previous version — rendering
    // "v0.5.68 - released <the day 0.5.69 was cut>". That is the same
    // conflation the published_version split exists to prevent, enforced by
    // the gate meant to catch it.
    let site_v = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("config.toml published_version")[1]
        .to_string();
    let site_date = regex::Regex::new(r#"(?m)^release_date = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("config.toml release_date")[1]
        .to_string();

    let changelog = read("CHANGELOG.md");
    let heading = regex::Regex::new(r"(?m)^## \[([^\]]+)\] - (\d{4}-\d{2}-\d{2})").unwrap();
    let entry = heading
        .captures_iter(&changelog)
        .find(|c| c[1] == site_v)
        .unwrap_or_else(|| panic!("CHANGELOG.md has no `## [{site_v}]` heading"));

    assert_eq!(
        &entry[2], site_date,
        "website/config.toml release_date ({site_date}) != the CHANGELOG date \
         for {site_v} ({}) — /download would show the wrong release date",
        &entry[2]
    );
}

/// Every changelog entry sits under a version heading.
///
/// `site_release_date_matches_changelog` above searches for the heading naming
/// the CURRENT site version and asserts its date. That says nothing about the
/// entries: a `### Added` / `### Fixed` block belonging to no `## [x.y.z]` at
/// all satisfies it completely, because the heading it looks for is still
/// somewhere further down the file.
///
/// That is not hypothetical. An edit here replaced the `## [Unreleased]`
/// heading along with the text it anchored on, orphaning two sections directly
/// under the file header. It survived a commit, a push and a full CI run, and
/// was found by eye while cutting the next release — the changelog's own gate
/// had been green throughout, checking a version heading that was never the one
/// at risk.
///
/// The property that actually matters is structural: nothing announces a change
/// before the first release that contains one.
#[test]
fn no_changelog_entry_precedes_its_version_heading() {
    let changelog = read("CHANGELOG.md");
    let version_heading = regex::Regex::new(r"(?m)^## \[").expect("heading regex");
    let section = regex::Regex::new(r"(?m)^### ").expect("section regex");

    let first_version = version_heading
        .find(&changelog)
        .map(|m| m.start())
        .expect("CHANGELOG.md has no `## [` version heading at all");

    let orphans: Vec<&str> = section
        .find_iter(&changelog[..first_version])
        .map(|m| {
            changelog[m.start()..]
                .lines()
                .next()
                .unwrap_or("")
                .trim_end()
        })
        .collect();

    assert!(
        orphans.is_empty(),
        "CHANGELOG.md has {} section(s) before the first `## [version]` heading: \
         {orphans:?} — these entries belong to no release, and the date gate \
         cannot see them because it searches for the heading naming the current \
         site version, which is still present further down",
        orphans.len()
    );

    // The walk must be reading a real changelog, not an empty string that makes
    // "no orphans" vacuously true.
    //
    // A FLOOR here, where the sibling counters in this suite are exact pins,
    // and the difference is deliberate. Those count things that change only
    // when someone edits docs, so a bump is a conscious act; this one grows by
    // exactly one on every release, so pinning it would put a mandatory edit on
    // the release path — the kind of tax that eventually gets removed rather
    // than maintained.
    //
    // What is not deliberate is how loose it was. This read `>= 10` against 85,
    // in the gate added to fix precisely that defect class, one day earlier.
    // The floor now sits just under the real count: enough that adding
    // releases never trips it, tight enough that a heading pattern which
    // stopped matching — which drops this to roughly zero, not to 79 — fails
    // immediately.
    let versions = version_heading.find_iter(&changelog).count();
    assert!(
        versions >= 80,
        "only {versions} version headings found — the heading pattern stopped \
         matching and this gate is reporting a structure it did not check"
    );
}

/// A design doc that calls itself unimplemented must not describe a shipped flag.
///
/// `docs/design/dialog-tracking-modes.md` read "**Status:** spec, not yet
/// implemented" for six releases after `--dialog-track` shipped in 0.5.54 —
/// while `src/cli.rs` declared it, `cli_flag_behavior_test` exercised it under a
/// section header citing that very page, and `dialog_store.rs` pointed readers
/// at it for the design. `docs/internals/README.md` even recorded the drift in
/// the column that exists for exactly that, so it had been noticed and left.
///
/// A reader following the index to the rationale was told the feature did not
/// exist. The check is derivable rather than curated: a doc whose status says
/// it is not implemented must not name a long flag that `Cli` actually accepts.
///
/// Gated on `native` because that is where `Cli` lives, and this file's other
/// gates are site/doc checks that must keep compiling in every reduced feature
/// combination. Reflection over the real parser is the point — reading
/// `long = "..."` out of `src/cli.rs` instead would be a second parser to keep
/// in step with the first, which is the shape of defect this suite removes.
#[cfg(feature = "native")]
#[test]
fn an_unimplemented_design_doc_does_not_name_a_shipped_flag() {
    let real: std::collections::BTreeSet<String> = sipnab::cli::Cli::command()
        .get_arguments()
        .filter_map(|a| a.get_long().map(str::to_string))
        .collect();
    assert!(
        real.len() >= 50,
        "only {} long flags read from Cli — the reflection broke and this gate \
         cannot find a contradiction",
        real.len()
    );

    let flag = regex::Regex::new(r"`--([a-z][a-z0-9-]+)`").expect("flag regex");
    let mut problems = Vec::new();
    let mut checked = 0;

    let dir = repo().join("docs/design");
    for entry in std::fs::read_dir(&dir).expect("read docs/design/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read design doc");
        let Some(status) = text
            .lines()
            .find(|l| l.trim_start().starts_with("**Status:**"))
        else {
            continue;
        };
        checked += 1;
        let lower = status.to_ascii_lowercase();
        if !(lower.contains("not yet implemented") || lower.contains("not implemented")) {
            continue;
        }
        // Only the flag in the H1 — the doc's SUBJECT — not every flag it
        // happens to mention. A spec legitimately references existing flags
        // while describing something unbuilt ("renders alongside `--json`"), and
        // the first draft of this reported all of them: three findings for
        // dialog-tracking-modes, where one was the contradiction and two were
        // incidental. A gate that also cries about `--limit` teaches people to
        // skim its output, which is how the real line gets missed.
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let Some(title) = text.lines().find(|l| l.starts_with("# ")) else {
            continue;
        };
        for c in flag.captures_iter(title) {
            if real.contains(&c[1]) {
                problems.push(format!(
                    "{name}: status says unimplemented, but its subject --{} exists",
                    &c[1]
                ));
            }
        }
    }

    assert!(
        checked >= 3,
        "only {checked} design docs carry a `**Status:**` line — the scan \
         stopped matching and this gate is checking nothing"
    );
    problems.sort();
    problems.dedup();
    assert!(
        problems.is_empty(),
        "design doc(s) claim to be unimplemented while describing a shipped \
         flag:\n  {}",
        problems.join("\n  ")
    );
}

/// The site only advertises a version that exists as a published release.
///
/// Every download link on /download is built from `published_version`, so if
/// that names a version with no release behind it, every link 404s — the file
/// tiles, the checksum column, `SHA256SUMS.txt`, all of it.
///
/// That was live. `download.html` used `config.extra.version`, which the Pages
/// step overwrites from `Cargo.toml` on every build, so the moment a release
/// COMMIT landed on main the site advertised assets for a tag nobody had pushed
/// yet. The window is the whole commit → CI → tag → release-build cycle, and on
/// 0.5.61 it ran far longer: that release commit went red and was never tagged.
///
/// A local tag is the check because it is the same thing `release.yml` triggers
/// on — no network, and it cannot pass by being unable to look.
///
/// # It also checks the version is CURRENT, not merely real
///
/// Existence alone is the weaker half, and on 2026-08-05 the site sat two
/// releases behind on it: `published_version` read 0.5.80 while v0.5.81 and
/// v0.5.82 both had full 23-asset releases. Nothing failed, because v0.5.80
/// does exist — this gate asserted only that, while its name promised more.
/// Visitors were handed the older binary and there was no way to notice from
/// inside the repository.
///
/// Being one behind is LEGITIMATE and must stay allowed: between tagging vX and
/// vX's assets finishing publishing, advertising the previous release is the
/// correct state, and it is the whole reason the release procedure moves this
/// value in a separate later commit. Two or more behind is staleness — the
/// follow-up commit was forgotten.
///
/// Comparison is numeric, not lexical. `v0.5.8`, `v0.5.79` and `v0.5.80` are all
/// real tags here, and string order puts `v0.5.8` after `v0.5.79`; once a
/// `v0.5.9` follows `v0.5.10` it would be wrong in the other direction too.
#[test]
fn site_advertises_only_a_released_version() {
    /// `v1.2.3` → `(1, 2, 3)`. Anything else — `v0.5`, `v1.2.3.4`, `nightly` —
    /// is not a release tag and is skipped rather than guessed at.
    fn release_tag(tag: &str) -> Option<(u32, u32, u32)> {
        let mut parts = tag.strip_prefix('v')?.split('.');
        let v = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        parts.next().is_none().then_some(v)
    }

    let cfg = read("website/config.toml");
    let published = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("website/config.toml has no published_version")[1]
        .to_string();

    let out = Command::new("git")
        .args(["tag", "--list"])
        .current_dir(repo())
        .output()
        .expect("git tag --list");
    let tags: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();

    // A clone with no tags cannot answer the question. Say so rather than pass.
    assert!(
        tags.len() >= 5,
        "only {} git tags visible — this checkout cannot tell whether \
         published_version is real (a shallow clone fetches no tags); the gate \
         is not reporting a safety it can provide",
        tags.len()
    );

    let wanted = format!("v{published}");
    assert!(
        tags.contains(&wanted),
        "website/config.toml advertises published_version {published}, but no \
         `{wanted}` tag exists — every download link on /download would 404. \
         Bump published_version only AFTER the release publishes."
    );

    // Existence is settled; now currency.
    let mut releases: Vec<(u32, u32, u32)> = tags.iter().filter_map(|t| release_tag(t)).collect();
    releases.sort_unstable();
    releases.dedup();

    // Same refusal as above, one layer down: if nothing parsed as a release the
    // ranking below is vacuous and would pass whatever it was handed.
    assert!(
        releases.len() >= 5,
        "only {} tags parsed as releases — the ordering this gate ranks \
         published_version against does not exist, so a pass here means nothing",
        releases.len()
    );

    let published_v = release_tag(&wanted)
        .unwrap_or_else(|| panic!("published_version {published} is not an x.y.z version"));
    let position = releases
        .iter()
        .position(|v| *v == published_v)
        .expect("published_version has a tag, so it is in the release list");
    let behind = releases.len() - 1 - position;

    assert!(
        behind <= 1,
        "website/config.toml advertises published_version {published}, which is \
         {behind} releases behind the newest tag v{}.{}.{} — every download \
         link, the checksum column and SHA256SUMS.txt point at the older \
         build, and visitors get it silently.\n\n\
         One behind is allowed: that is the window between tagging a release \
         and its assets finishing publishing. Two or more means the follow-up \
         commit that moves published_version was forgotten.\n\n\
         Fix by setting published_version to the newest release whose assets \
         have actually published — check `gh release view` before trusting the \
         tag alone.",
        releases[releases.len() - 1].0,
        releases[releases.len() - 1].1,
        releases[releases.len() - 1].2,
    );
}

// ---------------------------------------------------------------------------
// Published-claim gates.
//
// The class of bug these exist for: a value that is *produced* in one place
// (a CI step, a built artifact) and independently *re-stated* somewhere a
// reader sees it. Every instance below shipped wrong, and every one of them
// had a passing gate — because the gate compared the claim to itself rather
// than to whatever produces it.
// ---------------------------------------------------------------------------

/// The `owner/repo` slug and the GHCR image name agree with what produces them,
/// and `/download` never hand-writes either.
///
/// Both were spelled out literally on the download page — "NormB/sipnab" in a
/// `gh attestation verify --repo` command, in a releases-API URL, and
/// "ghcr.io/normb/sipnab" in the docker recipes — while `github_url` sat in
/// config.toml. Copy-pasteable commands naming a repository are the worst place
/// for a stale slug: they fail in the reader's terminal, not in a build.
#[test]
fn published_repo_slugs_agree() {
    let cfg = read("website/config.toml");
    let field = |name: &str| {
        regex::Regex::new(&format!(r#"(?m)^{name} = "([^"]+)""#))
            .unwrap()
            .captures(&cfg)
            .unwrap_or_else(|| panic!("website/config.toml has no {name}"))[1]
            .to_string()
    };

    let url = field("github_url");
    let slug = field("github_repo");
    let expected = url
        .trim_end_matches('/')
        .rsplit("github.com/")
        .next()
        .expect("github_url is not a github.com URL")
        .to_string();
    assert_eq!(
        slug, expected,
        "github_repo is {slug} but github_url points at {expected} — a rename \
         would leave `gh --repo {slug}` commands aimed at nothing"
    );

    // GHCR requires a lowercase path, and docker.yml is what actually pushes.
    let image = field("ghcr_image");
    assert_eq!(
        image,
        image.to_lowercase(),
        "ghcr_image must be lowercase — GHCR rejects mixed case: {image}"
    );
    assert_eq!(
        image,
        format!("ghcr.io/{}", expected.to_lowercase()),
        "ghcr_image {image} does not match the repository docker.yml publishes \
         from ({expected})"
    );

    // The page must go through config for both, or these gates are decoration.
    let dl = read("website/templates/download.html");
    for literal in [slug.as_str(), image.as_str()] {
        assert!(
            !dl.contains(literal),
            "download.html hard-codes `{literal}` — use config.extra.github_repo \
             / config.extra.ghcr_image so a rename cannot strand a command"
        );
    }
}

/// Every published macOS floor matches what the pinned toolchain actually
/// targets, per architecture.
///
/// `/download` stated "macOS 12+" for both darwin tarballs. Nothing produced
/// that number — no `MACOSX_DEPLOYMENT_TARGET` in `release.yml`, no constant, no
/// doc. It existed only in the table a reader consults before downloading, which
/// is exactly the shape of the glibc floor bug below: a platform floor that is
/// *decided* by the build and independently *restated* where it is acted on. It
/// was wrong for both arches (11.0 and 10.12) and stating one number for both
/// concealed that they differ, so an Intel Mac on 10.15 was told to give up.
///
/// The source of truth is now `release.yml`, which pins
/// `MACOSX_DEPLOYMENT_TARGET` per target in its "Pin macOS deployment target"
/// step — at the two values rustc already defaulted to, so no binary changed.
/// This gate holds the published numbers to that pin, and separately refuses a
/// pin *below* the compiler's own default: config and workflow would agree on
/// paper while the page named an OS the binary cannot run on.
///
/// Before the pin, the floor was whatever rustc happened to default to and
/// nothing in the repository named it — which is why this comment said for two
/// releases that `release.yml` does not set a deployment target. It has since
/// 0.5.65; the workflow step and the sentences denying it shipped together.
///
/// `--print deployment-target` reads the built-in target spec, so it answers for
/// darwin targets whose std is not installed — this runs on Linux CI.
#[test]
fn published_macos_floors_match_the_toolchain() {
    let cfg = read("website/config.toml");

    let release = read(".github/workflows/release.yml");

    for (key, target) in [
        ("macos_floor_arm", "aarch64-apple-darwin"),
        ("macos_floor_intel", "x86_64-apple-darwin"),
    ] {
        let published = regex::Regex::new(&format!(r#"(?m)^{key} = "([^"]+)""#))
            .unwrap()
            .captures(&cfg)
            .unwrap_or_else(|| panic!("website/config.toml has no {key}"))[1]
            .to_string();

        // What the release actually builds against. `release.yml` now pins this
        // per target in the "Pin macOS deployment target" step, so the floor is a
        // decision recorded in the repository rather than a compiler default
        // nothing names.
        let enforced = regex::Regex::new(&format!(r#"{target}\) *floor="([0-9.]+)""#))
            .unwrap()
            .captures(&release)
            .unwrap_or_else(|| {
                panic!(
                    "release.yml has no `{target}) floor=\"X.Y\"` case — did the \
                     'Pin macOS deployment target' step move or change shape?"
                )
            })[1]
            .to_string();

        assert_eq!(
            published, enforced,
            "website/config.toml {key} is {published} but release.yml builds \
             {target} against macOS {enforced} — /download would state a minimum \
             the binaries do not have"
        );

        // A pinned floor BELOW the compiler's own default would be a claim the
        // binary cannot honor: rustc will not emit code for an older OS than it
        // targets, so the tarball would not run where the page says it does.
        // Above the default is legitimate (deliberately dropping old releases).
        let out = std::process::Command::new("rustc")
            .args(["--print", "deployment-target", "--target", target])
            .output()
            .expect("rustc --print deployment-target");
        assert!(
            out.status.success(),
            "rustc could not report the deployment target for {target}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Shaped `MACOSX_DEPLOYMENT_TARGET=11.0`.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let default = stdout
            .trim()
            .rsplit('=')
            .next()
            .expect("deployment-target output has no `=`")
            .trim()
            .to_string();
        assert!(
            !default.is_empty(),
            "rustc reported an empty deployment target for {target} — did the \
             `--print` output shape change? raw: {stdout:?}"
        );

        let parts = |v: &str| -> (u32, u32) {
            let mut it = v.split('.');
            (
                it.next().unwrap_or("0").parse().unwrap_or(0),
                it.next().unwrap_or("0").parse().unwrap_or(0),
            )
        };
        assert!(
            parts(&enforced) >= parts(&default),
            "release.yml pins {target} to macOS {enforced}, below the pinned \
             rustc's own default of {default} — rustc will not emit code for an \
             older OS than it targets, so the published floor would be a promise \
             the binary cannot keep"
        );
    }

    // The template must go through config; nothing may reintroduce a literal.
    let dl = read("website/templates/download.html");
    let hand_written = regex::Regex::new(r"macOS (\d+)(?:\.\d+)?\+").unwrap();
    let found: Vec<&str> = hand_written.find_iter(&dl).map(|m| m.as_str()).collect();
    assert!(
        found.is_empty(),
        "download.html hard-codes a macOS floor {found:?} — use \
         config.extra.macos_floor_arm / macos_floor_intel so the gate above \
         keeps it honest"
    );

    // The docs carry the artifact reference and cannot template, so their floors
    // ARE literals. Sweep them: every macOS version stated as a floor must be
    // one of the two real ones. This is the same prose sweep the glibc gate
    // does, and for the same reason — "macOS 12+" lived in exactly this kind of
    // sentence, and a floor in prose is as load-bearing as one in a variable.
    let arm = regex::Regex::new(r#"(?m)^macos_floor_arm = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("no macos_floor_arm")[1]
        .to_string();
    let intel = regex::Regex::new(r#"(?m)^macos_floor_intel = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("no macos_floor_intel")[1]
        .to_string();

    for path in [
        "docs/install.md",
        "website/content/docs/install.md",
        "README.md",
    ] {
        let text = read(path);
        for cap in hand_written.captures_iter(&text) {
            let stated = cap[1].to_string();
            let full = cap[0].trim_end_matches('+').trim_start_matches("macOS ");
            assert!(
                full == arm || full == intel,
                "{path} states a macOS floor of {stated} ({:?}), but the released \
                 binaries floor at {intel} (Intel) and {arm} (Apple Silicon) — \
                 the two differ and neither is {stated}",
                &cap[0]
            );
        }
    }
}

/// Every published glibc floor — two constants and the doc prose — matches the
/// one `release.yml` enforces.
///
/// `release.yml` moved the gnu builds into `rust:1-bookworm` (real floor 2.36)
/// and neither published constant followed. For eleven releases the site and the
/// installer both said 2.39, so `install.sh` pushed every Debian 12 host to the
/// musl build — which its own message notes has no TUI audio.
///
/// The prose sweep is here because the first version of this test checked only
/// the two constants and `release.yml`, and `build.md` went on telling readers
/// "requires glibc >= 2.39" underneath a green gate. A floor stated in a
/// sentence is as load-bearing as one in a variable: it is what a reader acts
/// on. Historical mentions ("it previously cut over at 2.39") are deliberately
/// not matched — only phrasings that state the *current* floor.
#[test]
fn published_glibc_floor_matches_release_gate() {
    let enforced = regex::Regex::new(r#"(?m)^\s*floor="([0-9]+\.[0-9]+)""#)
        .unwrap()
        .captures(&read(".github/workflows/release.yml"))
        .expect("release.yml: no `floor=\"X.Y\"` in the glibc gate — did the step move?")[1]
        .to_string();

    let site = regex::Regex::new(r#"(?m)^glibc_floor = "([^"]+)""#)
        .unwrap()
        .captures(&read("website/config.toml"))
        .expect("website/config.toml has no glibc_floor")[1]
        .to_string();

    let installer = regex::Regex::new(r#"(?m)^SIPNAB_GLIBC_FLOOR="([^"]+)""#)
        .unwrap()
        .captures(&read("website/static/install.sh"))
        .expect("install.sh has no SIPNAB_GLIBC_FLOOR")[1]
        .to_string();

    assert_eq!(
        site, enforced,
        "website/config.toml glibc_floor is {site} but release.yml enforces \
         {enforced} — /download would state the wrong minimum"
    );
    assert_eq!(
        installer, enforced,
        "install.sh SIPNAB_GLIBC_FLOOR is {installer} but release.yml enforces \
         {enforced} — the installer would hand hosts the wrong artifact"
    );

    // Every glibc version named anywhere in the published docs must be the
    // enforced floor, unless it is listed below as deliberately something else.
    //
    // This was three hand-written phrasings over a hand-written six-file list.
    // Both are proxies: a fourth wording escapes, and so does a seventh file.
    // Demonstrated — adding "requires glibc 2.39 or newer" to docs/install.md
    // and regenerating left every gate green with 2.39 published on the site,
    // which is the drift this gate was written after. The installer cut over at
    // 2.39 for eleven releases while the real floor was 2.36, so Debian 12 hosts
    // silently got the static build and lost TUI audio.
    //
    // Default-deny: new prose is checked because it is new, and a number that is
    // meant to differ has to be named here with its reason. The previous shape
    // was default-allow, which is why prose nobody thought to pattern-match
    // sailed through.
    //
    // CHANGELOG.md is excluded wholesale: it records the 2.39 incident, and a
    // gate forcing history to match the present would corrupt the record.
    const ILLUSTRATIVE: &[(&str, &str)] = &[
        // Cross-compilation examples naming OTHER systems' glibc, not sipnab's
        // floor: "if you build on Debian 13 / glibc 2.41 and deploy to Debian 12".
        ("contrib/observability/README.md", "2.41"),
        ("contrib/observability/README.md", "2.39"),
        ("website/content/docs/build.md", "2.41"),
    ];

    let out = std::process::Command::new("git")
        .args(["ls-files", "*.md"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    let tracked = String::from_utf8_lossy(&out.stdout);

    // A glibc-shaped version: `2.NN`, with the preceding character not part of
    // a longer identifier. Both halves earn their place — without the boundary
    // `libpcap0.8` reads as a version, and without the `2.` a line saying
    // "glibc >= 2.36 — Debian 12+, Ubuntu 23.04+" reports 23.04 as a glibc
    // version, then `rust:1.97-alpine` does the same. False positives are how a
    // gate gets muted, so the pattern has to be about glibc and not about
    // digits.
    //
    // This assumes glibc stays on the 2.x line, which has held since 1997. If a
    // glibc 3 ever ships, this goes blind rather than wrong — the count
    // assertion below is what would notice.
    let ver = regex::Regex::new(r"(?:^|[^A-Za-z0-9._-])(2\.\d+)").expect("version regex");

    let mut wrong = Vec::new();
    let mut checked = 0;
    for rel in tracked.lines() {
        if rel == "CHANGELOG.md"
            || rel.starts_with("docs/design/")
            || rel.starts_with("docs/research/")
            || rel.starts_with("docs/superpowers/")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(repo().join(rel)) else {
            continue;
        };
        for line in text.lines() {
            if !line.to_lowercase().contains("glibc") {
                continue;
            }
            for cap in ver.captures_iter(line) {
                let v = &cap[1];
                checked += 1;
                if v == enforced || ILLUSTRATIVE.iter().any(|(f, x)| *f == rel && *x == v) {
                    continue;
                }
                wrong.push(format!(
                    "{rel}: names glibc {v}, enforced is {enforced}\n      {}",
                    line.trim()
                ));
            }
        }
    }
    assert!(
        checked >= 20,
        "glibc sweep examined only {checked} version mentions (23 at the time of \
         writing) — the scan has gone blind, which is exactly how build.md kept \
         saying 2.39 under a green gate"
    );
    assert!(
        wrong.is_empty(),
        "documentation names a glibc version that is neither the enforced floor \
         nor listed as illustrative:\n  {}\n\nIf the number is deliberate (an \
         example naming another system's glibc), add it to ILLUSTRATIVE with the \
         reason. Do not change the floor to make this pass.",
        wrong.join("\n  ")
    );
}

/// The published binary-size ceiling is single-sourced and actually enforced.
///
/// The homepage tile said 5 MB while the shipped stripped musl binary was
/// 9.34 MB. The existing tile gate compared `data-count` to the tile's own
/// fallback text, so 5 == 5 passed while the claim was 87% under reality.
#[test]
fn published_binary_size_matches_the_enforced_ceiling() {
    let ceiling = regex::Regex::new(r#"(?m)^binary_size_ceiling_mb = "([0-9]+)""#)
        .unwrap()
        .captures(&read("website/config.toml"))
        .expect("website/config.toml has no binary_size_ceiling_mb")[1]
        .to_string();

    let idx = read("website/templates/index.html");
    assert!(
        idx.contains(&format!(
            r#"data-count="{ceiling}" data-suffix=" MB">{ceiling} MB<"#
        )),
        "the homepage binary-size tile does not quote the {ceiling} MB ceiling \
         from website/config.toml"
    );
    assert!(
        idx.contains(&format!("Under {ceiling} MB static binary")),
        "the homepage feature table does not quote the {ceiling} MB ceiling"
    );
    for doc in ["docs/install.md", "website/content/docs/build.md"] {
        assert!(
            read(doc).contains(&format!("<= {ceiling} MB")),
            "{doc} does not quote the {ceiling} MB ceiling from website/config.toml"
        );
    }

    // A claim nobody measures is the bug this replaces. The workflow step is
    // what compares it to a real artifact; without it this test only proves
    // four files agree on a number none of them checked.
    // Same reasoning as the test-count gate: the identifying string sits in
    // the step body, so its presence says nothing about whether the step still
    // fails the build.
    assert_step_enforces(
        ".github/workflows/release.yml",
        "Enforce published binary size (musl targets)",
        Some("contains(matrix.target, '-linux-musl')"),
    );
    // And prove it: a 1 MB ceiling against a 2 MB binary must fail.
    assert_step_fails_on_bad_input(
        ".github/workflows/release.yml",
        "Enforce published binary size (musl targets)",
        &[("${{ matrix.target }}", "x86_64-unknown-linux-musl")],
        &|dir| {
            std::fs::write(dir.join("website/config.toml"), "")
                .or_else(|_| {
                    std::fs::create_dir_all(dir)
                        .and_then(|()| std::fs::write(dir.join("website/config.toml"), ""))
                })
                .ok();
            std::fs::create_dir_all(dir.join("website")).expect("mkdir website");
            std::fs::write(
                dir.join("website/config.toml"),
                "binary_size_ceiling_mb = \"1\"\n",
            )
            .expect("write config");
            let bin = dir.join("target/x86_64-unknown-linux-musl/release");
            std::fs::create_dir_all(&bin).expect("mkdir target");
            std::fs::write(bin.join("sipnab"), vec![0u8; 2 * 1024 * 1024]).expect("write binary");
        },
    );
}

/// The homepage throughput tiles must quote figures that appear on the
/// benchmarks page, and name the release those figures were measured on.
///
/// The tiles read "2.5M pkts/s" and "12.5x sngrep (measured v0.5.18)" for
/// twenty-nine releases. Both came from a table on a corpus nobody could
/// rebuild, and nothing tied the tile to the page it linked to — so the
/// headline numbers on the front page were unfalsifiable by construction.
#[test]
fn homepage_throughput_tiles_match_the_benchmarks_page() {
    let idx = read("website/templates/index.html");
    let bench = read("website/content/docs/benchmarks.md");

    let measured = regex::Regex::new(r"released (\d+\.\d+\.\d+) artifact, checksum-verified")
        .unwrap()
        .captures(&bench)
        .expect("benchmarks page states no measured release")[1]
        .to_string();

    // Each tile: (data-count value, the string that must appear in a table row).
    // Both tiles describe the SAME operating point (--cores 4). The throughput
    // tile used to headline the 2-core peak, 2.32M, which is the least
    // reproducible point on the curve: a clean-clone rerun measured 2.23M and
    // replicates spanned 2.32-2.36M, while the 4-core figure reproduced within
    // 0.5%. A smaller number a reader can reproduce beats a larger one they
    // cannot — and quoting a 2-core throughput beside a 4-core ratio invited
    // the two tiles to be read as one result.
    // Re-measured on the released 0.5.89 artifact, 2026-08-08, after the
    // regression bisected to 0.5.84 was partly fixed: 2.06 -> 1.89M pkts/s and
    // 11.1 -> 9.9x sngrep. Updated here and on the benchmarks page in the same
    // commit, which is what this gate exists to force.
    // Re-measured on the released 0.5.104 artifact, 2026-08-17: 2.31M at four
    // cores (replicates 2.31/2.31/2.26M), updated together with the page —
    // again in one commit, again because this gate forces it.
    // Re-measured 2026-08-21: 3.26M at four cores (replicates 3.25/3.29/3.29M),
    // on a local release build of the fix for a regression that shipped in
    // 0.5.118 and survived to 0.5.121. `is_merged` read the ENTIRE capture into
    // memory and then rejected it on the first four bytes, costing 0.06 s of a
    // 0.16 s run: four cores fell 3.29 -> 2.40M. The tile is back where 0.5.117
    // was, not somewhere new. The tile held 0.5.121's 2.40M until the fix
    // shipped, because the released binary is what a visitor downloads and
    // quoting a number no published artifact produces is the failure this gate
    // exists to prevent. 0.5.122 published on 2026-08-21 and its own artifact
    // measures 3.23M at four cores, so the tile moved with it.
    // Note what let the regression ship for ten releases -- the
    // benchmark gate's baseline still recorded 0.5.104's 2.28M, so 2.40M read
    // as 105% of baseline and passed. THIS gate is the other half: it forces
    // the tile and the page to move together, but neither is measured in CI,
    // so bench/baseline.json is what has to catch the number changing.
    // The second tile used to read "12.2x sngrep". It was dropped on
    // 2026-08-10: it argued sipnab's headline claim as a RATIO AGAINST A
    // COMPETITOR, which both advertised that competitor on the most-visited
    // page and framed sipnab as an alternative to a local tool -- the position
    // docs/design/positioning.md explicitly declines. It was also redundant
    // with the tile beside it, since both argued speed. The tool comparison
    // stays on the benchmarks page, where a reader who navigates there is
    // asking the question and there is room for the caveat that the tools do
    // different amounts of work. Its replacement is gated by
    // `homepage_mcp_tool_tile_matches_the_server` below, which DERIVES the
    // count from the registrations rather than restating it.
    // One tile now, where there were two. Written as a binding rather than a
    // one-element loop because clippy::single_element_loop rejects the latter;
    // if a second throughput tile ever returns, restore the loop.
    let (count, suffix) = ("3.23", "M pkts/s");
    let tile = format!(r#"data-count="{count}" data-suffix="{suffix}""#);
    assert!(
        idx.contains(&tile),
        "homepage tile {count}{suffix} is gone or changed; if it was re-measured, \
         update this gate and the benchmarks page together"
    );
    // The figure itself must be findable on the page the tile links to.
    let cell = format!("{count}M");
    let ratio = format!("{count}×");
    // In a TABLE ROW, not anywhere in the file. A re-measured figure quoted in
    // prose ("down from the 2.06M this page reported on 0.5.47") satisfied a
    // whole-file substring while the tile and the table disagreed.
    let in_a_row = |needle: &str| {
        bench
            .lines()
            .any(|l| l.trim_start().starts_with('|') && l.contains(needle))
    };
    assert!(
        in_a_row(&cell) || in_a_row(&ratio),
        "homepage claims {count}{suffix} but no such figure appears in \
         website/content/docs/benchmarks.md — the front page is quoting a \
         number its own benchmarks page does not support"
    );

    assert!(
        idx.contains(&format!("(measured v{measured})")),
        "homepage tiles do not say they were measured on v{measured}, the release \
         the benchmarks page names — an undated throughput claim silently ages"
    );
}

/// The homepage's MCP tool count must equal the number of tools the server
/// actually registers.
///
/// DERIVED, not restated. This tile replaced "12.2x sngrep" on 2026-08-10, and
/// the tile it replaced is the cautionary tale: a hand-typed headline number
/// that stayed on the front page for twenty-nine releases because nothing
/// produced it. Counting the `name = "..."` registrations means adding a tool
/// fails this gate until the page moves with it, and removing one does too.
#[test]
fn homepage_mcp_tool_tile_matches_the_server() {
    let idx = read("website/templates/index.html");
    let (registered, in_server_rs, files) = registered_mcp_tool_count();

    // A parser that matches nothing would agree with any tile.
    assert!(
        registered >= 20,
        "only {registered} MCP tool registrations found — the pattern stopped \
         matching, so this gate is comparing the tile against nothing"
    );
    // The walk must actually leave server.rs. `ToolRouter` composes with `+`,
    // so a tool added in src/mcp/tools/*.rs is registered exactly as much as
    // one written in server.rs; a counter reading the single file agrees with
    // a stale tile forever. This gate read only server.rs until 0.5.130, when
    // 13 tools lived in six submodules and it certified 38 against a server
    // that answered tools/list with 51.
    assert!(
        files >= 2 && registered > in_server_rs,
        "the MCP tool walk found {registered} registration(s) across {files} \
         file(s), {in_server_rs} of them in src/mcp/server.rs — it is not \
         reaching the router submodules, so every count it produces is a floor"
    );

    let tile = format!(r#"data-count="{registered}" data-suffix=" MCP tools""#);
    assert!(
        idx.contains(&tile),
        "the homepage advertises a different MCP tool count than the server \
         registers ({registered}). Expected the tile to carry:\n  {tile}\n\
         Update website/templates/index.html — both the data-count and the \
         no-JS fallback text — in the same commit as the tool change."
    );
    assert!(
        idx.contains(&format!(">{registered} MCP tools<")),
        "the MCP tile's no-JS fallback text disagrees with its data-count \
         ({registered}); a visitor without JavaScript sees the stale number"
    );
}

/// The homepage states its automated-test count twice, and both must agree.
///
/// `.githooks/pre-commit` already checks both places against a real `cargo
/// test` run and has for some time, so this is not a missing gate — it is that
/// gate's coverage moved somewhere it cannot be bypassed. A hook only runs for
/// a clone with `core.hooksPath` set; a web edit, a contributor who never ran
/// the setup, or `--no-verify` all skip it, and nothing downstream would
/// notice. This test plus the `ci.yml` step put the same check on the CI side,
/// where the tile is pinned to the prose and both to the measured total.
///
/// The step lives in `ci.yml` because that is where the full suite already
/// runs, so it parses that run instead of invoking `cargo test` a second time.
/// The coverage job cannot host it: it runs `--skip cli_goldens`, so its total
/// is short of the real one by design.
#[test]
fn homepage_test_counts_agree_with_each_other() {
    let idx = read("website/templates/index.html");

    let tile = regex::Regex::new(r#"data-count="(\d{4,})" data-suffix="">"#)
        .unwrap()
        .captures(&idx)
        .expect("homepage has no automated-test tile")[1]
        .to_string();

    let prose = regex::Regex::new(r"(\d{4,}) automated tests")
        .unwrap()
        .captures(&idx)
        .expect("homepage feature table no longer states a test count")[1]
        .to_string();

    assert_eq!(
        tile, prose,
        "the homepage tile says {tile} automated tests and the feature table says \
         {prose} — they describe the same suite"
    );

    // Not `.contains("published_test_count")`: that string lives inside the
    // step body and survives continue-on-error, a dropped `exit 1`, and a
    // widened `if:`. Check the step still enforces.
    assert_step_enforces(
        ".github/workflows/ci.yml",
        "Enforce the published test count",
        Some("matrix.os == 'ubuntu-latest'"),
    );
    // And prove it: a homepage claiming 9999 tests against a run reporting 7
    // must fail. Structural checks alone were defeated by downgrading
    // ::error:: to ::warning:: and dropping the exit.
    assert_step_fails_on_bad_input(
        ".github/workflows/ci.yml",
        "Enforce the published test count",
        &[],
        &|dir| {
            std::fs::create_dir_all(dir.join("website/templates")).expect("mkdir");
            std::fs::write(
                dir.join("website/templates/index.html"),
                "<td>9999 automated tests</td>",
            )
            .expect("write index");
            std::fs::write(
                dir.join("test-output.txt"),
                "test result: ok. 7 passed; 0 failed;\n",
            )
            .expect("write output");
        },
    );
}

/// Every Rust toolchain pin in the repo names the same version.
///
/// The pin appears in six workflow steps, the Dockerfile base image and two
/// `rust-version` fields. "Keep in sync" by comment is what let the glibc floor
/// drift; this is the same shape of duplication with no comparison.
///
/// The actions are pinned by commit SHA (a moved tag is a supply-chain
/// injection, and OpenSSF Scorecard flags an unpinned one), so the version now
/// lives in the trailing `# X.Y.Z` comment Dependabot maintains. That comment
/// is the only place the version survives, which makes it load-bearing rather
/// than decorative — so this asserts the SHA is really a SHA. Without that, a
/// future edit could drop back to `@1.98.0`, silently contribute no pin here,
/// and leave the set empty rather than disagreeing.
#[test]
fn rust_toolchain_pins_agree() {
    let pin_re =
        regex::Regex::new(r"dtolnay/rust-toolchain@(\S+)\s*#\s*([0-9]+\.[0-9]+\.[0-9]+)").unwrap();
    let sha_re = regex::Regex::new(r"^[0-9a-f]{40}$").unwrap();
    let mut pins: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(repo().join(".github/workflows")).expect("workflows dir") {
        let p = entry.expect("entry").path();
        // GitHub accepts BOTH .yml and .yaml for workflows. Reading only one
        // makes the extension a proxy for "is a workflow", and a file named
        // the other way is invisible to every assertion below.
        if !p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read workflow");
        for c in pin_re.captures_iter(&text) {
            assert!(
                sha_re.is_match(&c[1]),
                "dtolnay/rust-toolchain in {} is pinned to {:?}, not a 40-hex commit SHA — \
                 a tag can be moved under you, and this gate reads the version from the \
                 trailing comment, so an unpinned ref contributes nothing here instead of \
                 disagreeing",
                p.display(),
                &c[1]
            );
            pins.insert(c[2].to_string());
        }
    }
    assert!(
        !pins.is_empty(),
        "no `dtolnay/rust-toolchain@<sha> # X.Y.Z` pin found in any workflow — the \
         version comment was dropped, and every comparison below would compare nothing"
    );
    assert_eq!(
        pins.len(),
        1,
        "workflows pin more than one Rust toolchain: {pins:?}"
    );
    let pin = pins.iter().next().expect("one pin").clone();
    let minor = pin.rsplit_once('.').expect("x.y.z").0.to_string();

    // Every tracked file, not two hand-named ones. The docstring says "*Every*
    // Rust toolchain pin in the repo names the same version" and the code read
    // `Dockerfile` and two manifests by name, so `harness/sipnab/Dockerfile`
    // could sit at rust:1.85 — nine minors below MSRV — and this stayed green.
    let files = git_tracked_files();
    let image_re = regex::Regex::new(r"FROM rust:([0-9]+\.[0-9]+)").expect("image regex");
    let msrv_re = regex::Regex::new(r#"(?m)^rust-version = "([^"]+)""#).expect("msrv regex");
    let mut images = 0usize;
    let mut msrvs = 0usize;
    let mut wrong = Vec::new();
    // A tag and its digest travel together; the same tag resolving to two
    // different digests in one repository means one of them was updated and
    // the other was not. Verifying a digest actually *is* the tag needs a
    // registry, which this suite cannot reach — this catches the drift that
    // happens without one.
    let tagged =
        regex::Regex::new(r"FROM (rust:[^\s@]+)@(sha256:[0-9a-f]{64})").expect("tag regex");
    let mut digests: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for rel in &files {
        let Ok(text) = std::fs::read_to_string(repo().join(rel)) else {
            continue;
        };
        for c in image_re.captures_iter(&text) {
            images += 1;
            if c[1] != *minor {
                wrong.push(format!(
                    "{rel} builds on rust:{} but CI pins {pin} — the image and CI \
                     would compile with different compilers",
                    &c[1]
                ));
            }
        }
        for c in tagged.captures_iter(&text) {
            digests
                .entry(c[1].to_string())
                .or_default()
                .insert(c[2].to_string());
        }
        if rel.ends_with("Cargo.toml")
            && let Some(c) = msrv_re.captures(&text)
        {
            msrvs += 1;
            if c[1] != *minor {
                wrong.push(format!(
                    "{rel} declares MSRV {} but the toolchain pin is {pin}; this \
                     project deliberately keeps MSRV equal to the pinned toolchain, \
                     so move both or neither",
                    &c[1]
                ));
            }
        }
    }
    for (tag, ds) in &digests {
        if ds.len() > 1 {
            wrong.push(format!(
                "{tag} is pinned to {} different digests across this repository \
                 ({ds:?}) — one was updated and the other was not",
                ds.len()
            ));
        }
    }
    // Floors, so a broken walk cannot pass as agreement.
    assert!(
        images >= 2,
        "found only {images} `FROM rust:X.Y` lines — the tracked-file walk is \
         reading nothing and this gate proves nothing"
    );
    assert!(
        msrvs >= 2,
        "found only {msrvs} rust-version declarations — same problem"
    );
    assert!(
        wrong.is_empty(),
        "Rust toolchain pins disagree:\n  {}",
        wrong.join("\n  ")
    );
}

/// Every git-tracked path, repo-relative.
fn git_tracked_files() -> Vec<String> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    let files: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    assert!(
        files.len() > 100,
        "git ls-files returned {} paths — the derivation is broken",
        files.len()
    );
    files
}

/// Every artifact `install.sh` can ask for is one the release actually builds.
///
/// `choose_artifact` composes target triples by hand. If the release matrix
/// renames or drops a target, the installer 404s on a live user's machine —
/// and the installer's own test suite would not notice, because it compares
/// `choose_artifact` against hard-coded strings, not against the matrix.
#[test]
fn installer_targets_match_release_matrix() {
    let matrix: BTreeSet<String> = regex::Regex::new(r"(?m)^\s*- target: (\S+)")
        .unwrap()
        .captures_iter(&read(".github/workflows/release.yml"))
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        matrix.len() >= 6,
        "release matrix extraction found only {} targets — regex broken?",
        matrix.len()
    );

    let suffixes: BTreeSet<String> =
        regex::Regex::new(r#"sipnab-\$\{_ver\}-\$\{_arch\}-([a-z0-9.-]+)\.tar\.gz"#)
            .unwrap()
            .captures_iter(&read("website/static/install.sh"))
            .map(|c| c[1].to_string())
            .collect();
    // Count the `echo`ed artifact names in choose_artifact and require the
    // regex to have found every one. The pattern `[a-z0-9.-]+` silently skips a
    // name built from anything else (a `${_flavor}` segment, an underscore), so
    // a new artifact form would contribute nothing rather than failing here.
    let installer = read("website/static/install.sh");
    let echoed = installer
        .lines()
        // `contains`, not `starts_with`: one arm is `darwin) echo "sipnab-…`,
        // so a line-prefix would miss it — the same proxy this gate is about.
        .filter(|l| l.contains("echo \"sipnab-"))
        .count();
    assert_eq!(
        suffixes.len(),
        echoed,
        "choose_artifact echoes {echoed} artifact names but the pattern matched \
         {} — a name the regex cannot read contributes nothing instead of failing, \
         so the comparison below silently narrows",
        suffixes.len()
    );
    assert!(
        !suffixes.is_empty(),
        "no artifact names found in install.sh — choose_artifact changed shape"
    );

    // A target in the matrix only becomes a downloadable tarball if the
    // packaging step runs for it. That step carries a guard, and the guard is
    // not read by the matrix scan above — so excluding a target there leaves it
    // building, publishing nothing, and this gate green while every install.sh
    // run for that platform 404s.
    //
    // Evaluating a GitHub expression here is not the job; noticing that it
    // changed is. Pin it, so widening the guard fails and forces whoever did it
    // to re-derive which targets still publish.
    const PACKAGING_GUARD: &str = "matrix.variant != 'noaudio'";
    let pack = workflow_step_body(
        ".github/workflows/release.yml",
        "Package (tar.gz + checksum)",
    );
    let guard = pack
        .lines()
        .find(|l| l.trim_start().starts_with("if:"))
        .map(|l| l.trim().trim_start_matches("if:").trim().to_string());
    assert_eq!(
        guard.as_deref(),
        Some(PACKAGING_GUARD),
        "the tarball packaging step's guard changed. Every target below is \
         compared against the matrix, but only targets reaching THIS step get a \
         tarball — a narrowed guard silently stops publishing one while the \
         matrix still lists it. Re-derive the published set, then update this \
         constant."
    );

    // install.sh only ever detects these two arches (detect_arch).
    let constructible: BTreeSet<String> = suffixes
        .iter()
        .flat_map(|s| {
            ["x86_64", "aarch64"]
                .iter()
                .map(move |a| format!("{a}-{s}"))
        })
        .collect();

    let missing: Vec<&String> = constructible.difference(&matrix).collect();
    assert!(
        missing.is_empty(),
        "install.sh would download artifacts the release never builds (404 on a \
         user's machine): {missing:?}"
    );
    let unreachable: Vec<&String> = matrix.difference(&constructible).collect();
    assert!(
        unreachable.is_empty(),
        "the release builds tarball targets install.sh can never ask for: \
         {unreachable:?}"
    );
}

/// Every `releases/latest/download/…` URL we publish names a versioned asset.
///
/// The release only ever uploads versioned filenames
/// (`sipnab-0.5.44-x86_64-unknown-linux-musl.tar.gz`,
/// `sipnab_0.5.44_amd64.deb`). A URL naming a bare, unversioned artifact can
/// therefore never resolve. `build-wiki.py` put exactly such a `curl` in the
/// wiki's front-page Quick Start, so the first command a wiki visitor could
/// run had always returned 404 — nothing compared the generator's download
/// URL to what the release publishes. Doc pages that keep a literal
/// `<version>` placeholder are fine: they tell the reader to substitute.
#[test]
fn published_download_urls_name_versioned_assets() {
    let re = regex::Regex::new(r"releases/latest/download/(\S+)").unwrap();
    let literal_version = regex::Regex::new(r"\d+\.\d+\.\d+").unwrap();
    // Every tracked file, not six named ones. The release uploads only
    // versioned filenames, so a bare `releases/latest/download/…` URL is a
    // permanent 404 — and neither download.html nor index.html was on the list,
    // which is the page whose entire purpose is downloading. Demonstrated: a
    // bare tarball link added to download.html passed.
    let out = std::process::Command::new("git")
        .args(["ls-files"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    let tracked = String::from_utf8_lossy(&out.stdout);
    let mut bare = Vec::new();
    let mut scanned = 0;
    for rel in tracked.lines() {
        let path = repo().join(rel);
        if !path.is_file() {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // binary
        };
        // tests/ describe the pattern rather than publish it — this file
        // contains the regex and the examples, and would flag itself.
        if rel.starts_with("tests/") || !text.contains("releases/latest/download/") {
            continue;
        }
        scanned += 1;
        for cap in re.captures_iter(&text) {
            let asset = cap[1].trim_end_matches(['"', ',', '`', ')', '\'']);
            // Versioned either by placeholder (docs tell you to substitute) or
            // by a literal x.y.z already in the name.
            let versioned = asset.contains("<version>") || literal_version.is_match(asset);
            if !versioned {
                bare.push(format!("{rel}: {asset}"));
            }
        }
    }
    assert!(
        scanned >= 3,
        "only {scanned} files mention releases/latest/download/ (3 at the time of writing) — the sweep has \
         gone blind and a bare, permanently-404 URL would pass"
    );
    assert!(
        bare.is_empty(),
        "download URLs naming an unversioned asset — the release publishes only \
         versioned filenames, so these 404:\n  {}",
        bare.join("\n  ")
    );
}

/// Docs frontmatter hygiene: every page has a description and weights never collide.
#[test]
fn docs_page_weights_are_unique_and_descriptions_present() {
    let w_re = regex::Regex::new(r"(?m)^weight = (\d+)").unwrap();
    let d_re = regex::Regex::new(r"(?m)^description = ").unwrap();
    // Keyed by directory: Zola sorts each section independently, so a weight
    // collision only matters between siblings. Subsections are walked too —
    // the generated developer docs live in one, and a flat read_dir would
    // have left their frontmatter ungated.
    let mut weights: Vec<(String, u32, String)> = Vec::new();
    let mut missing_desc = Vec::new();
    let mut dirs = vec![repo().join("website/content/docs")];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("docs dir") {
            let p = entry.expect("entry").path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().and_then(|e| e.to_str()) == Some("md") {
                files.push(p);
            }
        }
    }
    for p in files {
        let name = p
            .strip_prefix(repo().join("website/content/docs"))
            .expect("under docs")
            .to_string_lossy()
            .into_owned();
        let section = p.parent().expect("parent").to_string_lossy().into_owned();
        if p.file_name().unwrap() == "_index.md" {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read page");
        match w_re.captures(&text) {
            Some(c) => weights.push((section, c[1].parse().unwrap(), name.clone())),
            None => missing_desc.push(format!("{name}: no weight")),
        }
        if !d_re.is_match(&text) {
            missing_desc.push(format!("{name}: no description"));
        }
    }
    let mut dupes = Vec::new();
    weights.sort();
    for pair in weights.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 == pair[1].1 {
            dupes.push(format!(
                "weight {} used by {} and {}",
                pair[0].1, pair[0].2, pair[1].2
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
    ///
    /// # Returns
    /// The repo-relative pcap path and the search queries in tape order.
    ///
    /// Shared with `demo_terminal_method_rendering`, which replays the same
    /// tape at the same geometry to assert what the recording actually shows.
    pub(super) fn tape_pcap_and_queries(tape: &str) -> (String, Vec<String>) {
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

    /// Each `/` query 04-filter.tape types must match some but not all dialogs
    /// of its pcap, so the demo visibly narrows (2026-07-18 regression).
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
// Demo-terminal method rendering: at the tape's real cell geometry, every SIP
// method in the demo pcap must reach the screen WHOLE. Shipped broken for two
// weeks and reported as "the home page - search tab content still shows
// truncated methods": the 2026-07-20 fix widened the Method column to
// Length(9) so SUBSCRIBE would fit, and the Search tab still rendered
// "SUBSCR". The constraint was honest; the flex pool was not. At 88 columns
// the `.max(4)` floors on From/To over-claimed 3 cells, and ratatui rebalances
// an over-claiming row by taking cells back out of the fixed columns -- Method
// absorbing the largest share, all 3 of them here -- so the widening could
// never reach the screen. The gate that shipped alongside that fix asserted
// the requested `Constraint`, which is a request and not a rendered width, so
// it stayed green for every one of the two weeks the defect was live. This
// gate reads the rendered buffer instead.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod demo_terminal_method_rendering {
    use super::{read, repo};
    use crossterm::event::KeyCode;
    use ratatui::{Terminal, backend::TestBackend};
    use sipnab::tui::App;
    use sipnab::tui::call_list::{SortColumn, displayed_dialogs};

    /// Cell geometry of demos/common.tape: 1200x700 px, Padding 10, DejaVu
    /// Sans Mono at FontSize 20. Measured empirically (`stty size` inside a
    /// VHS probe tape) — xterm.js rounds glyph metrics, so px/font arithmetic
    /// over-estimates the grid: the naive figure is 98x28, the real one 88x27.
    /// Independently confirmed against the shipped recording, whose status
    /// line occupies exactly 88 cells and is cut mid-word at "F9 Ad".
    const DEMO_COLS: u16 = 88;
    /// Row half of the measured 88x27 VHS grid; see `DEMO_COLS` above.
    const DEMO_ROWS: u16 = 27;

    /// The terminal buffer as one string per row.
    fn buffer_rows(term: &Terminal<TestBackend>) -> Vec<String> {
        let buf = term.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
                    .collect()
            })
            .collect()
    }

    /// Every method the demo pcap puts on screen — unfiltered and under each
    /// query the tape types — must render as its whole token at the demo's
    /// real 88-column geometry.
    ///
    /// Mutation check: restore the `.max(4)` floors on `from_w`/`to_w` in
    /// `compute_column_widths` and this fails on the unfiltered screen with
    /// `"SUBSCRIBE"` absent (it renders `SUBSCR`), which is precisely the
    /// pixels the homepage Search tab shipped.
    #[test]
    fn demo_terminal_renders_every_sip_method_whole() {
        let tape = read("demos/04-filter.tape");
        let (pcap_rel, queries) = super::search_demo_narrowing::tape_pcap_and_queries(&tape);
        let pcap = repo().join(&pcap_rel);
        assert!(pcap.is_file(), "tape references missing pcap: {pcap_rel}");

        // Load through the real file-open path, exactly as the tape does.
        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Tab);
        app.open_path_clear_for_test();
        for c in pcap.to_string_lossy().chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        let mut term = Terminal::new(TestBackend::new(DEMO_COLS, DEMO_ROWS)).unwrap();

        // The tape lingers 3s on the unfiltered list before typing anything;
        // that screen carries every method in the capture, SUBSCRIBE included.
        assert_methods_render_whole(&mut app, &mut term, "unfiltered dialog list", "");

        // Then each query it types, on the same screen the recording shows.
        for q in &queries {
            app.handle_key(KeyCode::Char('/'));
            for c in q.chars() {
                app.handle_key(KeyCode::Char(c));
            }
            let typed = app.search_query().to_string();
            assert_methods_render_whole(&mut app, &mut term, &format!("search \"/{q}\""), &typed);
            app.handle_key(KeyCode::Esc);
        }
    }

    /// The distinct methods a viewer should be able to read for `query`.
    ///
    /// Derived from the dialog store rather than hardcoded, so re-cutting the
    /// demo pcap cannot silently narrow what this gate covers.
    fn expected_methods(app: &App, query: &str) -> Vec<String> {
        let store = app.dialog_store_ref().read();
        let mut methods: Vec<String> =
            displayed_dialogs(&store, None, query, SortColumn::Index, true)
                .iter()
                .map(|d| d.method.as_str().to_string())
                .collect();
        methods.sort();
        methods.dedup();
        methods
    }

    /// Render the current screen and assert every method on it is readable in
    /// full — the effect, not the `Constraint` that was requested.
    /// EVERY demo tape that opens a capture must render every SIP method whole
    /// at the recorded cell geometry — not just the one tape that was reported.
    ///
    /// `demo_terminal_renders_every_sip_method_whole` above reads
    /// `demos/04-filter.tape` and nothing else, because Search is the tab
    /// somebody happened to look at. Multi-Leg shipped `SUBSCRIB` for nineteen
    /// days with that gate green, on the same 88-column geometry, from the same
    /// column arithmetic. A guard scoped to the case that prompted it is a
    /// guard that passes confidently about everything it never opened.
    ///
    /// Driven off the tape list on disk, so a NEW tape is covered the day it
    /// lands rather than when someone remembers to extend a list here.
    #[test]
    fn every_demo_tape_renders_methods_whole() {
        let mut checked = 0usize;
        let mut dir: Vec<_> = std::fs::read_dir(repo().join("demos"))
            .expect("demos/ is readable")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("tape"))
            .collect();
        dir.sort();

        for tape_path in dir {
            let tape = std::fs::read_to_string(&tape_path).expect("tape is readable");
            // The pcap a tape opens, if it opens one. `hero` and the CLI demo
            // may not drive the call list at all.
            let Some(rel) = tape
                .lines()
                .filter_map(|l| l.split("sipnab -I ").nth(1))
                .filter_map(|r| r.split_whitespace().next())
                .map(|r| r.trim_matches('"').to_string())
                .next()
            else {
                continue;
            };
            let pcap = repo().join(&rel);
            if !pcap.is_file() {
                continue;
            }

            let mut app = App::new_test();
            app.handle_key(KeyCode::Char('O'));
            app.handle_key(KeyCode::Tab);
            app.open_path_clear_for_test();
            for c in pcap.to_string_lossy().chars() {
                app.handle_key(KeyCode::Char(c));
            }
            app.handle_key(KeyCode::Enter);

            let mut term = Terminal::new(TestBackend::new(DEMO_COLS, DEMO_ROWS)).unwrap();
            let what = format!("{} (unfiltered list)", tape_path.display());
            assert_methods_render_whole(&mut app, &mut term, &what, "");
            checked += 1;
        }

        // A walk that matched nothing would pass silently, which is the exact
        // failure mode this test exists to end.
        assert!(
            checked >= 4,
            "only {checked} demo tapes were checked — the tape walk or the \
             `sipnab -I` extraction stopped matching, so this gate is asserting \
             about almost nothing"
        );
    }

    fn assert_methods_render_whole(
        app: &mut App,
        term: &mut Terminal<TestBackend>,
        what: &str,
        query: &str,
    ) {
        term.draw(|f| app.render(f)).unwrap();
        let rows = buffer_rows(term);
        let expected = expected_methods(app, query);
        assert!(
            !expected.is_empty(),
            "{what}: no dialogs on screen, so this gate would assert nothing"
        );
        for method in &expected {
            assert!(
                rows.iter().any(|r| r.contains(method.as_str())),
                "{what}: at {DEMO_COLS}x{DEMO_ROWS} the Method column never renders \
                 {method:?} whole — the viewer, and every frame of the recorded demo, \
                 sees it cut. A wide enough Method `Constraint` is not sufficient: \
                 check that the column widths do not over-subscribe the row (see \
                 column_widths_never_oversubscribe_the_terminal).\n--- screen ---\n{}",
                rows.join("\n")
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
/// No template may use inline `on*=` handler attributes: the hash-based CSP silently blocks them.
#[test]
fn no_inline_event_handlers_in_templates() {
    // Match an inline handler used as an HTML attribute (quote follows the `=`).
    // JS assignments like `el.onclick = fn` and prose don't have that shape, and
    // `<script>`/`<style>` bodies are stripped first so real JS never trips this.
    // Any `on*=` attribute, not a hand-kept list of thirteen names. The CSP
    // grants neither `unsafe-inline` nor `unsafe-hashes`, so the browser blocks
    // ALL of them — the handler is dead on the live site while the page returns
    // 200. `onpointerdown="selectDemo(0)"` passed the old alternation, and
    // pointer events are the modern replacement for `onclick`, so that is the
    // likely way this returns.
    let re = regex::Regex::new(r#"(?i)\son[a-z]+\s*=\s*["']"#).unwrap();
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

/// download.html carries a doc-sidebar ToC whose anchors all resolve, including #all-files and #verify.
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

/// base.html renders .site-footer and no child template blanks the footer block away.
#[test]
fn every_page_template_keeps_the_site_footer() {
    let base = read("website/templates/base.html");
    assert!(
        base.contains("class=\"site-footer\""),
        "base.html no longer renders .site-footer"
    );

    // A body of only whitespace OR Tera comments is still an empty footer: an
    // override whose body is `{# keep the page clean #}` renders nothing, and a
    // one-line justification comment is the natural way a developer blanks a
    // block they think they do not need. /analyze shipped with no footer — no
    // nav, no license, no credits — which is the regression this test is named
    // after.
    let empty_override =
        regex::Regex::new(r"(?s)\{%\s*block footer\s*%\}((?:\s|\{#.*?#\})*)\{%\s*endblock")
            .unwrap();
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

/// Patreon, GitHub Sponsors, and GitHub links appear only in the footer block, never in the top nav.
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

/// The footer is a single non-wrapping .footer-row with svg icon sponsor
/// links: no two-tier layout, no text links, no "Built with" credit.
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
    let rule = scss_own_declarations(&scss, ".footer-row");
    assert!(
        rule.contains("flex-wrap: nowrap"),
        ".footer-row must declare `flex-wrap: nowrap` so the footer never \
         breaks into a second line; its own declarations are:\n{rule}"
    );
}

/// A rule's **own** declarations — nested rules excluded.
///
/// Slicing to the first `}` after the selector ends the slice at the first
/// *nested* rule's closing brace, so a `flex-wrap: nowrap` inside a child
/// selector satisfied a check on the parent — while the parent itself declared
/// `flex-wrap: wrap` and the footer broke onto a second line, the exact thing
/// the rule's comment says must never happen. Nesting a child above the
/// parent's own declarations is idiomatic SCSS and this stylesheet does it
/// elsewhere, so the shape is not exotic.
///
/// Braces are matched to depth, and only depth-1 text is returned.
fn scss_own_declarations(scss: &str, selector: &str) -> String {
    let at = scss
        .find(selector)
        .unwrap_or_else(|| panic!("style.scss has no `{selector}` rule"));
    let open = scss[at..]
        .find('{')
        .map(|n| at + n + 1)
        .unwrap_or_else(|| panic!("`{selector}` has no rule body"));

    let mut depth = 1usize;
    let mut own = String::new();
    for (i, c) in scss[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return own;
                }
            }
            _ if depth == 1 => own.push(scss[open + i..].chars().next().unwrap_or(c)),
            _ => {}
        }
    }
    panic!("`{selector}` rule is unterminated");
}

// ---------------------------------------------------------------------------
// CSS cache-buster journey: the stylesheet link once used `?v=<version>`, so
// a site-only change (same crate version) shipped new HTML against CACHED old
// CSS — the single-row footer rendered as three unstyled block rows for every
// returning visitor until their cache expired. The buster must be Zola's
// content hash (`cachebust=true`), which changes whenever the CSS does.
// ---------------------------------------------------------------------------

/// style.css is cachebusted by Zola content hash (cachebust=true), never by `?v=` release version.
#[test]
fn stylesheet_link_is_content_hash_cachebusted() {
    // EVERY css/js asset in EVERY template, not the first matching line of
    // base.html. `.find()` returned the first match, so a second, bad <link>
    // added right after the good one passed — and `analyze.html` was shipping
    // hand-bumped `?v=14` counters for its CSS and `?v=13` for its JS, the exact
    // regression this test's header describes, while the gate looked only at
    // base.html.
    //
    // Images are deliberately out of scope: a stale demo screenshot is
    // cosmetic, while stale CSS or JS against new HTML is a broken page. Those
    // still use `?v=` by choice.
    let asset = regex::Regex::new(
        r#"get_url\(\s*path\s*=\s*['"]([^'"]+\.(?:css|js))['"]([^)]*)\)([^">]*)"#,
    )
    .expect("asset regex");

    let mut problems = Vec::new();
    let mut seen = 0;
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&p).expect("read template");
        for cap in asset.captures_iter(&text) {
            seen += 1;
            let (path, args, trailing) = (&cap[1], &cap[2], &cap[3]);
            if !args.contains("cachebust=true") {
                problems.push(format!(
                    "{name}: {path} is not cachebust=true — a content change keeps the \
                     URL identical and ships new HTML against stale cached assets"
                ));
            }
            if trailing.contains("?v=") {
                problems.push(format!(
                    "{name}: {path} carries a hand-bumped `?v=` counter. Someone has to \
                     remember to increment it, and the history of this one reads 4, 5, \
                     … 14 — every bump is an occasion it was forgotten. Use \
                     cachebust=true, which changes when the content does."
                ));
            }
        }
    }

    assert!(
        seen >= 4,
        "only {seen} css/js assets found across the templates — the extractor \
         stopped matching and this gate is reporting a safety it is not providing"
    );
    assert!(
        problems.is_empty(),
        "template assets that will be served stale:\n  {}",
        problems.join("\n  ")
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

/// The download page keeps its DevOps content (container image, pinned
/// install, releases-API discovery, checksums) and source-persona content.
#[test]
fn download_page_serves_devops_and_source_personas() {
    let tpl = read("website/templates/download.html");

    // DevOps: container image, pinned + latest tags.
    //
    // Checked through the config key rather than the literal image name. This
    // asserted `tpl.contains("ghcr.io/normb/sipnab")`, which required the page to
    // hard-code the value that `published_repo_slugs_agree` requires it NOT to —
    // the two gates flatly contradicted each other, and the literal one would
    // have won by being older. What this test is for is that the page *offers a
    // container image*; where the name comes from is the other gate's business.
    assert!(
        tpl.contains("config.extra.ghcr_image"),
        "download page must offer the container image docker.yml publishes, via \
         config.extra.ghcr_image"
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
    // DevOps: latest-version discovery without scraping HTML. The repo slug
    // comes from config for the same reason as the image name above.
    assert!(
        tpl.contains("api.github.com/repos/{{ config.extra.github_repo }}/releases/latest"),
        "automation section must show latest-version discovery via the \
         releases API, with the repo slug from config.extra.github_repo"
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
// Provenance & authorship journey: sipnab is a security tool, so a rehosted
// or tampered copy of its artifacts must be detectable. Every release binary
// and the container image carry sigstore build-provenance attestations
// (verify with `gh attestation verify`), and the site states its authorship
// and content license so republished copies without attribution are a clean
// takedown case. These guards keep the attestation steps and the notice from
// being silently dropped.
// ---------------------------------------------------------------------------

/// Release/docker workflows keep their sigstore attestation steps and
/// permissions; the site keeps the verify text and CC BY footer license.
#[test]
fn releases_are_attested_and_site_content_is_licensed() {
    // Release artifacts: one attestation pass over everything uploaded.
    let rel = read(".github/workflows/release.yml");
    assert!(
        rel.contains("actions/attest-build-provenance@"),
        "release.yml lost its build-provenance attestation step"
    );
    for perm in ["id-token: write", "attestations: write"] {
        assert!(
            rel.contains(perm),
            "release.yml needs `{perm}` for sigstore attestations"
        );
    }

    // Container image: attested by digest and pushed to the registry.
    //
    // Located by STEP, not by whole-file `contains`. The string
    // "actions/attest-build-provenance@" survives the step being commented
    // out, and did — commenting the entire attest step left every gate green
    // while `gh attestation verify oci://ghcr.io/normb/sipnab:<tag>`, which the
    // download page tells users to run, failed for everyone.
    let docker = read(".github/workflows/docker.yml");
    let docker_steps: Vec<&str> = docker
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let docker_live = docker_steps.join("\n");
    assert!(
        docker_live.contains("- name: Attest image provenance"),
        "docker.yml has no live `Attest image provenance` step — it was removed \
         or commented out, and the image ships unattested while the download \
         page tells users to verify it"
    );
    assert!(
        docker_live.contains("actions/attest-build-provenance@"),
        "docker.yml lost its image attestation action"
    );
    // And the attestation is verified where it is created. release.yml has done
    // this since 0.5.49; docker.yml did not, which is why a commented-out step
    // could ship.
    assert!(
        docker_live.contains("- name: Verify the attestation we just created"),
        "docker.yml no longer verifies the attestation it just created — an \
         attestation nothing checks is the same evidence-free tick this gate exists \
         to refuse"
    );
    assert!(
        docker_live.contains("gh attestation verify"),
        "docker.yml's verification step no longer runs `gh attestation verify`"
    );
    for perm in ["id-token: write", "attestations: write"] {
        assert!(
            docker.contains(perm),
            "docker.yml needs `{perm}` for sigstore attestations"
        );
    }
    assert!(
        docker.contains("push-to-registry: true"),
        "the image attestation must be pushed to ghcr so \
         `gh attestation verify oci://...` works"
    );

    // The download page tells verifiers the attestation exists.
    let dl = read("website/templates/download.html");
    assert!(
        dl.contains("gh attestation verify"),
        "download verify section must mention `gh attestation verify`"
    );

    // Site footer: copyright + docs content license.
    let footer = base_block("footer");
    assert!(
        footer.contains("&copy;"),
        "footer must carry a copyright notice"
    );
    assert!(
        footer.contains("creativecommons.org/licenses/by/4.0"),
        "footer must link the docs content license (CC BY 4.0)"
    );
}

// ---------------------------------------------------------------------------
// Stat-tile journey: each homepage `.arch-stat` carries a `data-count` (the
// JS count-up target) AND visible fallback text (what no-JS / pre-animation
// visitors see). These drifted apart — data-count="2569" while the visible
// text still read 2562 — and the version-count pre-commit gate only checks
// data-count + prose, so the stale fallback shipped. This guard fails when a
// tile's integer fallback text disagrees with its own data-count.
// ---------------------------------------------------------------------------

/// Every homepage .arch-stat tile's visible fallback number equals its data-count animation target.
#[test]
fn homepage_stat_fallback_text_matches_data_count() {
    let html = read("website/templates/index.html");
    // Capture the data-count value and the element's inner text together.
    let re = regex::Regex::new(
        r#"(?s)<span class="arch-stat" data-count="([0-9.]+)"[^>]*>(.*?)</span>"#,
    )
    .unwrap();
    // The FIRST numeric run anywhere in the visible text, not only a run at
    // its very start. Requiring the number at offset zero and skipping the
    // tile when it was not there exempted every tile whose text opens with an
    // entity or a glyph — and on the one such tile that nothing else pins,
    // `data-count="11.1"` shipped beside visible text `≈7×`: a no-JS visitor
    // read ≈7× while the animation counted to 11.1×.
    let first_number = regex::Regex::new(r"[0-9]+(?:\.[0-9]+)?").expect("number regex");
    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for cap in re.captures_iter(&html) {
        let data = &cap[1];
        let text = cap[2].trim();
        checked += 1;
        let Some(num) = first_number.find(text).map(|m| m.as_str()) else {
            // A counting tile whose fallback carries no number at all leaves a
            // no-JS visitor with nothing where the statistic should be. That is
            // a finding, not a reason to skip.
            offenders.push(format!(
                "data-count={data} but the fallback text {text:?} contains no \
                 number — a no-JS visitor sees no statistic"
            ));
            continue;
        };
        if num != data {
            offenders.push(format!(
                "data-count={data} but fallback text reads {num:?} (full text: {text:?})"
            ));
        }
    }
    assert!(
        checked >= 3,
        "matched only {checked} stat tiles — the regex has stopped matching and \
         this gate is checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "homepage stat tile fallback text disagrees with its data-count \
         (no-JS visitors see the stale number):\n{}",
        offenders.join("\n")
    );
}

// ---------------------------------------------------------------------------
// MSRV journey: the download page once advertised "Rust 1.92+" while
// Cargo.toml's rust-version was 1.94 — a floor the site under-stated. The
// download page's Rust version claims must equal the crate's real MSRV.
// ---------------------------------------------------------------------------

/// Every "Rust x.y+" claim on the download page equals Cargo.toml's rust-version, and at least one exists.
#[test]
fn download_page_msrv_matches_cargo() {
    let cargo = read("Cargo.toml");
    let msrv = cargo
        .lines()
        .find_map(|l| l.strip_prefix("rust-version = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("Cargo.toml has no rust-version");

    let dl = read("website/templates/download.html");
    let rust_ref = regex::Regex::new(r"Rust (\d+\.\d+)\+").unwrap();
    let mut found_any = false;
    for cap in rust_ref.captures_iter(&dl) {
        found_any = true;
        assert_eq!(
            &cap[1], &msrv,
            "download.html advertises Rust {}+ but Cargo.toml rust-version is {msrv}",
            &cap[1]
        );
    }
    assert!(
        found_any,
        "download.html no longer states a 'Rust <x.y>+' floor — the MSRV \
         guard has nothing to check; update this test if that's intentional"
    );
}

// ---------------------------------------------------------------------------
// CSP hash journey: the production CSP (a Cloudflare transform rule, managed
// by ops/cloudflare/refresh_csp_hashes.py) allows inline <script> blocks by
// sha256 hash, NOT 'unsafe-inline'. Editing an inline script without
// refreshing the rule ships a page whose script the browser silently blocks —
// the download page's platform tabs were dead in production for a day this
// way, and the homepage demos/feature tabs for a morning on 2026-07-22.
// Since then pages.yml's `csp` job refreshes the rule automatically after
// every deploy (from the deployed artifact, via --site-dir); this pin list
// remains so an inline-script edit is a conscious, reviewed act.
//
// Pins are computed over the RAW TEMPLATE script bodies; where a script has
// no Tera syntax the pin equals the deployed CSP token exactly (all except
// base.html today).
// ---------------------------------------------------------------------------

/// The sha256 of every executable inline template script must equal the
/// PINNED list, making inline-script edits a conscious, reviewed act.
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
            "sha256-rFx04kn3jGSGf1MKxuWCk8HI8WZnRlpR9OD2RDUMHPI=",
        ),
        (
            // Re-pinned twice in 0.5.68. First for the hero swap — the static
            // screenshot is replaced by the animated demo on `load`, gated on
            // prefers-reduced-motion. Then again when CodeQL flagged that
            // version js/xss-through-dom (high): it read the animated URL out
            // of a data-attribute and assigned it to `hero.src`, and an image
            // src is a script-URL sink. The URL now comes from Zola.
            //
            // Note that pulls index.html into base.html's situation: its
            // script now contains a Tera expression, so THIS hash (over the
            // template) no longer equals the one production serves (over the
            // rendered page). That is fine and already the norm — the csp job
            // in pages.yml runs refresh_csp_hashes.py against the deployed
            // artifact, so Cloudflare gets the rendered hash. This pin is only
            // an acknowledgment gate for template edits.
            // Re-pinned again for the demo-wall disclosure: the tab wiring
            // now derives a tab's panel index from its own id rather than its
            // position in the NodeList (seven of the eleven tabs moved inside
            // `#demo-tabs-more`, so position and panel are no longer the same
            // thing), the arrow-key roving skips collapsed tabs, and the
            // disclosure button is wired here because the CSP blocks onclick=.
            // The hero's new /analyze/ CTA is a plain <a> and touched none of
            // this on purpose.
            // Re-pinned again for the lifecycle lead panel: a twelfth tab and
            // panel joined the wall, so the three comments here that counted
            // the tabs ("seven of the eleven", "all eleven", "tabs 0-3") each
            // named a number that had moved. No executable line changed --
            // the wiring already derives a tab's panel from its own id -- but
            // a comment edit changes the hash exactly as much as a code edit
            // does, and shipping the old hash would blank the whole script.
            "index.html",
            "sha256-jkZDUfcMSkaA5zdJk8XtpjPoyxBG3nGNd4tUw3NiJB4=",
        ),
        (
            "page.html",
            "sha256-UOwnn7uXvW/gl+mP2NGmMuxif0eKdH7ocCwmMTGCjcY=",
        ),
        (
            // Re-pinned in 0.5.44: the copy-button script now skips
            // `pre.mermaid`, which it was appending the word "copy" into.
            "page.html",
            "sha256-VEhaYG0u0qZoYQzwk4PgncTbqmZXsFNRY5GJxNQt7UI=",
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
         only allows inline scripts by sha256 hash. The pages.yml csp job \
         refreshes the Cloudflare rule automatically on deploy; update PINNED \
         in this test to the computed list above to acknowledge the change."
    );
}

/// The hero swaps a static screenshot for an animated demo after `load`. Four
/// properties make that safe, and each is one careless edit from being lost.
///
/// The animated file is 350 KiB against the static frame's 206 KiB. If the
/// swap ever moves off `load`, or the `fetchpriority` moves onto the animated
/// URL, the hero stops being a cheap LCP element and starts being the reason
/// the page scores badly — a regression that looks like nothing in review and
/// shows up only in field data.
///
/// Video was measured and rejected: 18 frames of terminal text over 14.2s is a
/// slideshow, and every encode smaller than the lossless WebP blurs the text
/// the demo exists to show.
#[test]
fn hero_swap_keeps_the_static_frame_as_the_lcp_element() {
    let html = std::fs::read_to_string(repo().join("website/templates/index.html"))
        .expect("read index.html");

    let hero_line = html
        .lines()
        .find(|l| l.contains("id=\"hero-shot\""))
        .expect("hero <img> must carry id=\"hero-shot\" — the swap looks it up by id");

    assert!(
        hero_line.contains("demos/hero-static.webp")
            && hero_line.contains("fetchpriority=\"high\""),
        "the STATIC frame must be the src with fetchpriority=\"high\"; putting \
         either on the animated file makes a 350 KiB asset the LCP element:\n{hero_line}"
    );
    // The animated URL must NOT ride on the element. Storing it in a
    // data-attribute and assigning it to `hero.src` is js/xss-through-dom
    // (CodeQL, high): an image src is a script-URL sink, so a DOM-sourced
    // string reaching it is an XSS flow whatever today's value happens to be.
    // The URL comes from the template instead, which deletes the source.
    assert!(
        !hero_line.contains("data-animated"),
        "the animated URL must not be stored on the element and read back — \
         DOM text into an image src is a script-URL sink:\n{hero_line}"
    );
    assert!(
        html.contains("get_url(path='demos/01-intro.webp') | json_encode | safe"),
        "the animated URL must be resolved by Zola into the script and escaped \
         with json_encode, matching how base.html injects config values"
    );
    assert!(
        hero_line.contains("width=\"1200\"") && hero_line.contains("height=\"700\""),
        "both files are 1200x700 and the dimensions must be declared, or the \
         swap shifts layout:\n{hero_line}"
    );

    assert!(
        html.contains("prefers-reduced-motion: reduce"),
        "the swap must honor prefers-reduced-motion — the animation loops \
         forever, which is what someone setting that asked not to receive"
    );
    assert!(
        html.contains("window.addEventListener('load'"),
        "the swap must wait for `load`; running it earlier puts the animated \
         fetch in contention with the LCP image"
    );
    assert!(
        html.contains("pre.onload"),
        "the animated image must decode before the swap, or a slow fetch \
         blanks the hero instead of leaving the screenshot up"
    );
}

// ---------------------------------------------------------------------------
// Docs nav drift: the docs sidebar (page.html + section.html nav_group
// lists) and the header dropdown (base.html) are HARDCODED page lists. The
// MCP walkthrough shipped reachable only from the /docs/ index cards
// because none of the three was updated. Every docs page must appear in
// all three, the two sidebar templates must agree, no nav entry may point
// at a deleted page, and page weights must be unique (prev/next order).
// ---------------------------------------------------------------------------

/// The docs pages, both sidebar nav_group lists, and the header dropdown
/// must be identical sets, and page weights must be unique.
#[test]
fn every_docs_page_is_in_the_sidebar_and_dropdown_navs() {
    let docs_dir = repo().join("website/content/docs");
    let mut pages: Vec<String> = std::fs::read_dir(&docs_dir)
        .expect("docs content dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".md") && n != "_index.md")
        .collect();
    pages.sort();

    let nav_paths = |template: &str| -> Vec<String> {
        let text = std::fs::read_to_string(repo().join("website/templates").join(template))
            .expect("read template");
        let group = regex::Regex::new(r#"nav_group\([^)]*paths=\[([^\]]*)\]"#).unwrap();
        let entry = regex::Regex::new(r#""([^"]+\.md)""#).unwrap();
        let mut out: Vec<String> = Vec::new();
        for c in group.captures_iter(&text) {
            for e in entry.captures_iter(c.get(1).expect("paths list").as_str()) {
                out.push(e[1].to_string());
            }
        }
        out.sort();
        out
    };

    let page_nav = nav_paths("page.html");
    let section_nav = nav_paths("section.html");
    assert_eq!(
        page_nav, section_nav,
        "page.html and section.html sidebar nav_group lists differ — update both"
    );
    assert_eq!(
        page_nav, pages,
        "docs sidebar (page.html/section.html nav_group paths) does not match \
         website/content/docs/*.md — a page is missing from the sidebar or a \
         nav entry points at a deleted page"
    );

    let base = std::fs::read_to_string(repo().join("website/templates/base.html"))
        .expect("read base.html");
    let dropdown =
        regex::Regex::new(r#"get_url\(path='@/docs/([a-z0-9-]+\.md)'\)[^>]*role="menuitem""#)
            .unwrap();
    let mut dropdown_pages: Vec<String> = dropdown
        .captures_iter(&base)
        .map(|c| c[1].to_string())
        .collect();
    dropdown_pages.sort();
    dropdown_pages.dedup();
    assert_eq!(
        dropdown_pages, pages,
        "header dropdown (base.html role=menuitem docs links) does not match \
         website/content/docs/*.md"
    );

    // Prev/next is weight-ordered; duplicate weights make the order arbitrary.
    let weight = regex::Regex::new(r"(?m)^weight = (\d+)$").unwrap();
    let mut weights: Vec<(u32, String)> = pages
        .iter()
        .map(|p| {
            let text = std::fs::read_to_string(docs_dir.join(p)).expect("read page");
            let w = weight
                .captures(&text)
                .unwrap_or_else(|| panic!("{p}: no `weight = N` in front matter"))[1]
                .parse::<u32>()
                .expect("weight parses");
            (w, p.clone())
        })
        .collect();
    weights.sort();
    for pair in weights.windows(2) {
        assert_ne!(
            pair[0].0, pair[1].0,
            "duplicate docs weight {}: {} and {} — prev/next order is arbitrary",
            pair[0].0, pair[0].1, pair[1].1
        );
    }
}

// ---------------------------------------------------------------------------
// CSP refresh --site-dir journey: pages.yml's post-deploy `csp` job runs
// refresh_csp_hashes.py against the BUILT site (the pages artifact) instead
// of fetching the live CDN, which can serve stale HTML for ~10 minutes after
// a deploy. These guards run the real script in --site-dir --dry-run mode
// against a fixture tree and pin the extraction semantics: executable inline
// scripts hashed recursively, src=/data blocks skipped, and an empty tree a
// hard error — a silently empty hash set would strip every pin from the
// production CSP.
// ---------------------------------------------------------------------------

/// CSP source token (quoted `sha256-BASE64`) for an inline script body.
fn csp_token(body: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "'sha256-{}'",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body.as_bytes()))
    )
}

/// Run `ops/cloudflare/refresh_csp_hashes.py` with the given arguments.
///
/// # Side effects
/// Spawns a `python3` child process.
///
/// # Returns
/// The process output (status, stdout, stderr).
fn run_csp_refresh(args: &[&str]) -> std::process::Output {
    std::process::Command::new("python3")
        .arg(repo().join("ops/cloudflare/refresh_csp_hashes.py"))
        .args(args)
        .output()
        .expect("run refresh_csp_hashes.py")
}

/// In --site-dir --dry-run mode the CSP refresher hashes executable inline
/// scripts recursively, skips src=/ld+json blocks, and prints the CSP.
#[test]
fn csp_refresh_site_dir_hashes_executable_inline_scripts() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Adversarial bodies: backslashes, quotes, an embedded NUL, multibyte.
    let root_body = "var s = \"back\\\\slash \\\"quoted\\\" \u{0} caf\u{e9} \u{1F600}\";";
    let sub_body = "console.log('nested page');";
    let module_body = "export const x = 1;";
    let data_body = "{\"@type\": \"SoftwareApplication\"}";
    std::fs::write(
        dir.path().join("index.html"),
        format!(
            "<html><body>\
             <script>{root_body}</script>\
             <script src=\"/app.js\"></script>\
             <script type=\"application/ld+json\">{data_body}</script>\
             </body></html>"
        ),
    )
    .expect("write index.html");
    std::fs::create_dir(dir.path().join("docs")).expect("mkdir docs");
    std::fs::write(
        dir.path().join("docs/index.html"),
        format!(
            "<html><body>\
             <script type=\"module\">{module_body}</script>\
             <script>{sub_body}</script>\
             </body></html>"
        ),
    )
    .expect("write docs/index.html");
    std::fs::write(dir.path().join("style.css"), "body {}").expect("write non-html");

    let out = run_csp_refresh(&["--site-dir", dir.path().to_str().unwrap(), "--dry-run"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "--site-dir --dry-run failed\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for (what, body) in [
        ("root inline", root_body),
        ("nested inline", sub_body),
        ("module", module_body),
    ] {
        assert!(
            stdout.contains(&csp_token(body)),
            "{what} script hash missing from output:\n{stdout}"
        );
    }
    assert!(
        !stdout.contains(&csp_token(data_body)),
        "ld+json data block must not be hashed:\n{stdout}"
    );
    assert!(
        stdout.contains("distinct inline-script hashes: 3"),
        "expected exactly 3 hashes (src= and ld+json excluded):\n{stdout}"
    );
    // Dry run must print the CSP that would ship, with the hashes in place.
    assert!(
        stdout.contains("script-src 'self' 'wasm-unsafe-eval'")
            && stdout.contains(&csp_token(root_body)),
        "dry run should print the resulting CSP:\n{stdout}"
    );
}

/// An HTML-free --site-dir must fail loudly rather than publish an empty hash set.
#[test]
fn csp_refresh_site_dir_empty_tree_is_an_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = run_csp_refresh(&["--site-dir", dir.path().to_str().unwrap(), "--dry-run"]);
    assert!(
        !out.status.success(),
        "an html-free --site-dir must fail loudly, not publish an empty CSP"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(".html"),
        "error should say no .html files were found: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Multi-leg demo journey: 10-multileg.tape opens the b2bua-asterisk.pcapng
// extended (multi-leg) call flow at the demo terminal geometry. Shipped broken
// on 2026-07-19: the participant header read "172.16.98172.16.98.101:5060
// 172.16...." (labels painted independently overwrite each other), the footer
// read "1172.16.98.101:5060172.16.98.145:40216", and arrow labels rendered as
// "INVITE (SD...". These guards replay the tape's exact keys against the real
// fixture at the real VHS cell geometry and fail on both defect classes.
// ---------------------------------------------------------------------------

#[cfg(feature = "tui")]
mod multileg_demo_ladder {
    use super::repo;
    use crossterm::event::KeyCode;
    use ratatui::{Terminal, backend::TestBackend};
    use sipnab::tui::App;

    /// Cell geometry of demos/10-multileg.tape: 1200x700 px, Padding 10,
    /// DejaVu Sans Mono at FontSize 19 -> 96 columns x 30 rows. Measured
    /// empirically (`stty size` inside a VHS probe tape) — xterm.js rounds
    /// glyph metrics, so px/font arithmetic over-estimates the grid (the
    /// common.tape FontSize 20 gives 88x27, NOT the naive 98x28).
    const DEMO_COLS: u16 = 96;
    /// Row half of the measured 96x30 VHS grid; see `DEMO_COLS` above.
    const DEMO_ROWS: u16 = 30;

    /// The terminal buffer as one string per row.
    fn buffer_rows(term: &Terminal<TestBackend>) -> Vec<String> {
        let buf = term.backend().buffer();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
                    .collect()
            })
            .collect()
    }

    /// Replay the 10-multileg tape's key sequence (load pcap, Down x5,
    /// Enter, `x`) and return the app plus the rendered demo-size screen.
    ///
    /// # Returns
    /// The app (extended flow active) and the rendered rows of the demo-size screen.
    fn extended_flow_screen() -> (App, Vec<String>) {
        let pcap = repo().join("tests/pcap-samples/b2bua-asterisk.pcapng");
        assert!(pcap.is_file(), "demo fixture missing: {}", pcap.display());

        let mut app = App::new_test();
        app.handle_key(KeyCode::Char('O'));
        app.handle_key(KeyCode::Tab);
        app.open_path_clear_for_test();
        for c in pcap.to_string_lossy().chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);

        let mut term = Terminal::new(TestBackend::new(DEMO_COLS, DEMO_ROWS)).unwrap();
        term.draw(|f| app.render(f)).unwrap();
        for _ in 0..5 {
            app.handle_key(KeyCode::Down);
            term.draw(|f| app.render(f)).unwrap();
        }
        app.handle_key(KeyCode::Enter);
        term.draw(|f| app.render(f)).unwrap();
        app.handle_key(KeyCode::Char('x'));
        assert!(app.extended_flow(), "x must enable extended flow");
        term.draw(|f| app.render(f)).unwrap();

        let rows = buffer_rows(&term);
        (app, rows)
    }

    /// Render the demo screen as a labeled dump for inclusion in failure
    /// messages only. `assert!`/`panic!` evaluate their format arguments
    /// lazily, so calling this inside a failure message keeps a passing run
    /// silent while still surfacing the full screen when something breaks.
    fn screen_dump(rows: &[String]) -> String {
        use std::fmt::Write as _;
        let mut s = format!("--- extended flow at {DEMO_COLS}x{DEMO_ROWS} ---\n");
        for (y, r) in rows.iter().enumerate() {
            let _ = writeln!(s, "{y:2} |{r}|");
        }
        s
    }

    /// The ladder's columns: everything left of the detail pane, whose top
    /// border corner sits on the first main-area row.
    fn ladder_split_col(rows: &[String]) -> usize {
        rows[3]
            .chars()
            .position(|c| c == '\u{250C}') // ┌
            .unwrap_or_else(|| panic!("no detail-pane corner in row 3: {:?}", rows[3]))
    }

    /// Every whitespace-separated token on the participant header row and
    /// the footer row must be one participant's label — either verbatim or
    /// as a `truncate()` prefix ending in "..." — and every participant
    /// must appear exactly once. Colliding overwrites ("172.16.98172.16...")
    /// match no label and fail.
    #[test]
    fn multileg_demo_participant_labels_never_collide() {
        let (app, rows) = extended_flow_screen();
        let labels = app.ladder_participant_labels_for_test();
        assert!(
            labels.len() >= 3,
            "expected a multi-leg (3+ participant) ladder, got {labels:?}\n{}",
            screen_dump(&rows)
        );
        let split = ladder_split_col(&rows);

        for label_row in [&rows[3], &rows[DEMO_ROWS as usize - 2]] {
            // The ladder's last column carries its scrollbar (█ thumb /
            // ║ track), never label text — blank it before tokenizing.
            let ladder_txt: String = label_row
                .chars()
                .take(split)
                .map(|c| {
                    if c == '\u{2588}' || c == '\u{2551}' {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
            let tokens: Vec<&str> = ladder_txt.split_whitespace().collect();
            assert_eq!(
                tokens.len(),
                labels.len(),
                "each participant must render exactly one label token, \
                 got {tokens:?} for participants {labels:?}\n{}",
                screen_dump(&rows)
            );
            let mut used = vec![false; labels.len()];
            for tok in &tokens {
                let matched = labels.iter().enumerate().find(|(i, l)| {
                    !used[*i]
                        && (l == tok
                            || (tok.ends_with("...")
                                && tok.len() > 3
                                && l.starts_with(&tok[..tok.len() - 3])))
                });
                match matched {
                    Some((i, _)) => used[i] = true,
                    None => panic!(
                        "label token {tok:?} matches no participant of {labels:?} \
                         — labels collided/overwrote each other in {ladder_txt:?}\n{}",
                        screen_dump(&rows)
                    ),
                }
            }
        }
    }

    /// At the demo geometry the common short arrow labels must render in
    /// full: a demo GIF showing "INVITE (SD..." demonstrates breakage, not
    /// the feature. (The ladder must widen at the expense of the detail
    /// pane until these fit.)
    #[test]
    fn multileg_demo_arrow_labels_are_not_truncated() {
        let (_app, rows) = extended_flow_screen();
        let split = ladder_split_col(&rows);
        // Arrow rows only: the participant label rows (header, footer) may
        // legitimately ellipsis-truncate long ip:port labels within their
        // own non-overlapping cells; the collision test above covers them.
        let ladder: Vec<String> = rows[4..DEMO_ROWS as usize - 2]
            .iter()
            .map(|r| r.chars().take(split).collect())
            .collect();
        let all = ladder.join("\n");

        for full in ["INVITE (SDP)", "100 Trying", "200 OK (SDP)"] {
            assert!(
                all.contains(full),
                "expected the full arrow label {full:?} somewhere in the \
                 ladder at demo width; ladder:\n{}\n{}",
                ladder.join("\n"),
                screen_dump(&rows)
            );
        }
        for row in &ladder {
            assert!(
                !row.contains("..."),
                "truncated label in the ladder at demo width: {row:?}\n{}",
                screen_dump(&rows)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The branch-protection gate must actually stand for the whole workflow.
// ---------------------------------------------------------------------------

/// `CI success` is the single required status check on `main`, and its own
/// comment promises it is "green only if every other job succeeded".
///
/// It was not. `needs:` named four of the seven jobs, leaving `install-sh`
/// (the end-user installer suite that sipnab.com serves) and `deb-package`
/// outside the gate entirely: either could fail while the required check
/// stayed green and the branch stayed mergeable. The aggregator pattern is
/// chosen precisely so protection survives adding a job — but only if adding
/// a job also adds it here, which nothing checked.
///
/// This is that check. It compares the `needs:` list against the jobs actually
/// defined in the file, so a new job either joins the gate or fails this test.
#[test]
fn ci_success_gates_every_job() {
    let yaml = read(".github/workflows/ci.yml");
    // Job keys are the 2-space-indented mapping keys under `jobs:`. Anchor on
    // that header first: `on:` also has 2-space children (`push:`), which a
    // whole-file scan would collect as phantom jobs.
    let jobs_block = yaml
        .split_once("\njobs:\n")
        .expect("ci.yml has no jobs: block")
        .1;
    let defined: BTreeSet<String> = jobs_block
        .lines()
        .filter_map(|l| {
            let name = l.strip_prefix("  ")?.strip_suffix(':')?;
            // The full legal charset, not this repo's house style. GitHub
            // allows `_` and uppercase in a job id, so a job named `wasm_build`
            // was invisible here: it could fail on every push while the single
            // required status check reported green. Every current id is
            // kebab-case, which is exactly why the narrower charset looked
            // right.
            (!name.starts_with(' ')
                && !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .then(|| name.to_string())
        })
        .collect();

    // The needs: list may wrap across lines, so read to the closing bracket
    // rather than to end-of-line.
    let after = jobs_block
        .split_once("needs: [")
        .expect("ci-success has no needs: list")
        .1;
    let list = &after[..after.find(']').expect("unterminated needs: list")];
    let gated: BTreeSet<String> = list
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let expected: BTreeSet<String> = defined
        .iter()
        .filter(|j| *j != "ci-success")
        .cloned()
        .collect();
    assert!(
        !expected.is_empty(),
        "parsed no jobs from ci.yml — the jobs: block changed shape"
    );
    let ungated: Vec<_> = expected.difference(&gated).collect();
    assert!(
        ungated.is_empty(),
        "these ci.yml jobs can fail while the required \"CI success\" check \
         stays green: {ungated:?}. Add them to ci-success's needs:."
    );
    let phantom: Vec<_> = gated.difference(&expected).collect();
    assert!(
        phantom.is_empty(),
        "ci-success needs jobs that no longer exist: {phantom:?}"
    );
}

// ---------------------------------------------------------------------------
// Packaging scripts hardcode repo paths. A rename must not outlive them.
// ---------------------------------------------------------------------------

/// Every repo-relative path a packaging script or workflow names must exist.
///
/// The packaging builders resolve inputs relative to the repo root as bare
/// literals — `cp packaging/sipnab.service ...`, `readlink -f
/// packaging/sipnab.service`, `gzip -c man/sipnab.1`. Nothing type-checks a
/// string in a shell script, so moving a file leaves the literal pointing at
/// nothing and the failure surfaces wherever that script runs.
///
/// For `build-deb.sh` that is a CI job. For `build-rpm.sh` and
/// `update-formula.sh` it is a release tag, which is the worst possible place
/// to discover it: the tag is already cut and the workflow is already halfway
/// through publishing. This test moves that discovery to every push.
#[test]
fn packaging_scripts_reference_existing_paths() {
    // Leading boundary matters: "/usr/share/man/man1/sipnab.1.gz" inside an
    // rpm spec heredoc contains the substring "man/man1/sipnab.1.gz", which
    // is not a repo path. Only accept a match that starts a path token.
    fn candidates(text: &str) -> Vec<String> {
        // Path roots a script may legitimately name. Curated, because a
        // derived list over-matches: `docker/build-push-action` is an Action
        // namespace and `fuzz/artifacts` is gitignored output, both of which a
        // blanket sweep reports as missing paths.
        //
        // What is NOT curated is the list's completeness. Six of sixteen
        // top-level directories were named and `ops/` — referenced by pages.yml
        // today — was not, silently, with no comment (the GENERATED exclusion
        // below does carry one). A reference to a nonexistent ops/ script
        // passed, and the csp job would then die on every site deploy, leaving
        // the Cloudflare CSP stale while the browser blocks the homepage inline
        // scripts, visible only in production.
        //
        // So every top-level directory must appear in one list or the other,
        // and a new one fails until someone decides which.
        const ROOTS: [&str; 15] = [
            "bpf/",
            "examples/",
            ".vale/",
            "packaging/",
            "LICENSES/",
            "contrib/",
            "man/",
            "scripts/",
            "tests/",
            "website/",
            "ops/",
            ".github/",
            ".githooks/",
            ".cargo/",
            ".config/",
        ];
        // Directories deliberately not treated as path roots, each with the
        // reason a match inside them would be a false positive.
        const NOT_PATH_ROOTS: [&str; 10] = [
            // Browser journey tests. node_modules/, test-results/ and
            // playwright-report/ are all gitignored build outputs, so a
            // packaging script naming a path under e2e/ would be naming
            // something git does not hold.
            "e2e/", "docker/",  // collides with the docker/* GitHub Actions namespace
            "fuzz/",    // artifacts/ and corpus growth are gitignored outputs
            "crates/",  // sbom.json and other build outputs are generated
            "src/",     // Rust module paths in prose, not file references
            "docs/",    // prose cites docs by markdown link, checked elsewhere
            "bench/",   // benchmark outputs are gitignored
            "benches/", // criterion output paths are generated
            "demos/",   // recorded asset paths are generated
            "harness/", // compose-generated volumes are runtime paths
        ];
        {
            let out = std::process::Command::new("git")
                .args(["ls-files"])
                .current_dir(repo())
                .output()
                .expect("git ls-files");
            let mut top: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|p| p.split_once('/').map(|(d, _)| format!("{d}/")))
                .collect();
            top.sort();
            top.dedup();
            let unclassified: Vec<&String> = top
                .iter()
                .filter(|d| !ROOTS.contains(&d.as_str()) && !NOT_PATH_ROOTS.contains(&d.as_str()))
                .collect();
            assert!(
                unclassified.is_empty(),
                "top-level directories in neither ROOTS nor NOT_PATH_ROOTS: {unclassified:?}. \
                 Add each to ROOTS if a script may name a path inside it, or to \
                 NOT_PATH_ROOTS with the reason a match there is a false positive. \
                 Leaving one out is how ops/ went unchecked."
            );
        }
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for (i, _) in text.char_indices() {
            let Some(root) = ROOTS.iter().find(|r| text[i..].starts_with(**r)) else {
                continue;
            };
            if i > 0 {
                let prev = bytes[i - 1] as char;
                if prev == '/' || prev.is_ascii_alphanumeric() || "._-".contains(prev) {
                    continue;
                }
            }
            let rest = &text[i..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || "./_-".contains(c)))
                .unwrap_or(rest.len());
            // Trailing '.' is sentence punctuation in comments ("...see
            // packaging/deb/build-deb.sh."), never part of a real path.
            let path = rest[..end].trim_end_matches(['/', '.']).to_string();
            // Skip anything interpolated, globbed, or a bare root mention.
            if path.len() > root.len() && !path.contains("..") {
                out.push(path);
            }
        }
        out
    }

    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for dir in [
        "packaging/deb",
        "packaging/rpm",
        "packaging/homebrew",
        ".github/workflows",
    ] {
        let Ok(entries) = std::fs::read_dir(repo().join(dir)) else {
            panic!("missing directory {dir} — packaging layout changed");
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.extension()
                .is_some_and(|x| x == "sh" || x == "yml" || x == "yaml")
            {
                files.push(p);
            }
        }
    }
    assert!(
        files.len() >= 8,
        "found only {} packaging/workflow files — the scan is not reaching them",
        files.len()
    );

    let mut missing: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap_or_default();
        for cand in candidates(&text) {
            // `$`-interpolated segments are runtime values, not literals.
            if cand.contains('$') {
                continue;
            }
            // Build OUTPUTS, not inputs: absent from a fresh checkout by
            // definition. This test passed locally and failed in CI for
            // exactly this reason — website/public is Zola's render target and
            // happened to exist on the machine that wrote the test.
            //
            // Deliberately an explicit list rather than "skip anything git
            // does not track". An untracked path is precisely what a stale
            // reference looks like after a file moves, so that rule would have
            // skipped `contrib/sipnab.service` and missed the bug this test
            // exists to catch. Add an entry only for something a workflow
            // creates, never for something it reads.
            // `sipnab_bg.wasm` joined this list in 0.5.107, when it stopped
            // being committed. pages.yml CREATES it — `wasm-pack build
            // --out-dir website/static/wasm` — so it satisfies the rule above
            // rather than bending it. It was removed from the repository
            // because OpenSSF Scorecard's Binary-Artifacts check flagged it at
            // high severity, correctly: a committed binary is not auditable
            // from its source, and this one had already served eleven releases
            // of stale analysis before the workflow began rebuilding it.
            //
            // `sipnab.js` is NOT here and must keep existing: it is text, the
            // export guard reads it, and its absence is a real failure.
            const GENERATED: [&str; 4] = [
                "website/public",
                "build/",
                "target/",
                "website/static/wasm/sipnab_bg.wasm",
            ];
            if GENERATED.iter().any(|g| cand.starts_with(g)) {
                continue;
            }
            checked += 1;
            if !repo().join(&cand).exists() {
                let rel = f.strip_prefix(repo()).unwrap_or(f).display();
                missing.push(format!("{rel} -> {cand}"));
            }
        }
    }
    // Pinned, not floored, for the same reason as the docs-page walk in
    // link_integrity_test: `>= 10` against a true 52 let four fifths of the
    // packaging references stop being checked without the gate noticing, and a
    // reference to a nonexistent path is precisely what this exists to catch.
    // Raised 59 -> 62 by the analyzer build added to pages.yml, which names
    // 5 more real-file references: the wasm out-dir, Cargo.lock as a cache key, and
    // scripts/check-wasm-exports.py as the post-build check. Attributed rather
    // than bumped: this gate exists to notice references it has stopped
    // checking, so a number that moves without a reason is the failure.
    // Raised 64 -> 66 by the cross-references added to .githooks/pre-commit and
    // .github/workflows/ci.yml, each naming tests/site_journey_test.rs as the
    // home of the invariant their shared test count depends on. Attributed per
    // file before moving: HEAD has 0 in each, the working tree has 1 in each,
    // and the path they name exists — which is exactly what this gate checks.
    // Raised 65 -> 70 by packaging/rpm/test-build-rpm.sh, the .rpm builder's
    // first test harness. Attributed per file: .github/workflows/ci.yml gains
    // exactly one (the new job's `run:` line), and the harness itself accounts
    // for the other four, naming the builder it drives and the .deb harness it
    // mirrors. packaging/rpm/build-rpm.sh and .github/workflows/release.yml
    // both changed in the same commit and both still scan 3 and 12, unmoved.
    // Raised 70 -> 72 by packaging/homebrew/test-real-sums.sh, which runs the
    // real formula generator against the real SHA256SUMS.txt of the latest
    // published release instead of a fixture. Attributed per file before
    // moving: the new harness names exactly one repo path
    // (packaging/homebrew/test-update-formula.sh, the fixture harness it
    // complements) and .github/workflows/ci.yml names exactly one more (the
    // new step's `run:` line). packaging/homebrew/test-update-formula.sh and
    // .github/workflows/release.yml both changed in the same commit and both
    // still scan the same count as before: the reference the fixture harness
    // gained is `$HERE/test-real-sums.sh`, which the `$` filter above skips.
    // Raised 72 -> 73 by the REL1 comment in .github/workflows/release.yml
    // explaining why that workflow cannot use `.github/actions/system-deps`.
    // Attributed by measurement, not by inspection: rewording that one line to
    // say "the shared composite action" instead of naming the path brought the
    // scan back to exactly 72, so the delta is that single new reference and
    // nothing else stopped being checked. The path is spelled out rather than
    // described precisely because this gate then verifies it still exists —
    // a note pointing at a directory that has moved is worse than no note.
    // Raised 73 -> 78 by the prose-gate path lists getting one source each.
    // Every one of the five is in .github/workflows/quality.yml, the only
    // scanned file the change touched: the two `run:` lines that now read
    // .config/codespell-paths.txt and .config/vale-paths.txt, and the comments
    // beside them naming those files and the two other runners that read them.
    // Attributed by measurement — .githooks/pre-push and scripts/preflight.sh
    // gained references too and are outside the four scanned directories, so
    // they contribute nothing here. No path went missing; only the count moved.
    //
    // The expected figure was written twice, in the assertion and again in its
    // own failure message, so raising one left the other naming the old number
    // — the drift this file exists to catch, in this file. One const now.
    // Raised 78 -> 79 by the Pagefind indexing step. Attributed by
    // MEASUREMENT, per file, before moving: with the step removed from
    // .github/workflows/quality.yml alone the scan reads 78, and with it
    // removed from .github/workflows/pages.yml alone it still reads 79 — so
    // the single new reference is the one in quality.yml's comment naming
    // pages.yml as the workflow its Pagefind pin must equal. pages.yml
    // contributes none: every path its step names is under website/public,
    // which the GENERATED list above skips because Zola creates it.
    // Raised 79 -> 81 by the accessibility and Lighthouse jobs added to
    // .github/workflows/quality.yml. Attributed by MEASUREMENT, per reference,
    // before moving: with both jobs deleted the scan reads 79; with them present
    // it reads 81; rewording the accessibility job's comment so it no longer
    // names `website/templates/*.html` brings it to 80, and separately rewording
    // the Chrome-resolution comment so it no longer names
    // `.github/actions/system-deps` also brings it to 80. So the delta is those
    // two comment references and nothing else stopped being checked. Both name
    // paths that exist, which is what this gate then verifies.
    //
    // A third candidate appeared and was FIXED rather than excluded. The axe
    // step first read `npx playwright test tests/accessibility.spec.js`, and the
    // scan reported `tests/accessibility.spec.js` as a repo path that does not
    // exist -- correctly: in a workflow file a bare `tests/` reads as
    // repository-root, and the spec lives under e2e/. The step now says
    // `./tests/...`, which is both unambiguous to a reader and, because the
    // preceding character is a slash, not a root-relative candidate.
    const EXPECTED_REFERENCES: usize = 81;
    assert_eq!(
        checked, EXPECTED_REFERENCES,
        "packaging path scan saw {checked} references, expected \
         {EXPECTED_REFERENCES}. More is \
         fine — bump this. FEWER means the candidate extractor stopped matching \
         and unverified paths pass unseen."
    );
    missing.sort();
    missing.dedup();
    assert!(
        missing.is_empty(),
        "packaging scripts name repo paths that do not exist:\n  {}",
        missing.join("\n  ")
    );
}

/// The SBOMs must be generated, attested, and published — all three.
///
/// A release artifact passes through three independent lists in release.yml:
/// the step that creates it, `attest-build-provenance`'s `subject-path`, and
/// `action-gh-release`'s `files`. Nothing ties them together, and the failure
/// is silent in both directions — an artifact missing from `subject-path`
/// publishes unattested beside attested ones, and an artifact missing from
/// `files` is built, checksummed, and attested but never uploaded. The SBOMs
/// were written into all of one of these lists on the first attempt.
///
/// This checks the wiring only. Whether the SBOMs have any *content* is
/// checked where it can actually be known — the component-count floor inside
/// the generation step, which reads the emitted document. A CycloneDX file
/// with zero components is valid JSON and uploads perfectly happily.
#[test]
fn release_publishes_and_attests_the_sboms() {
    let yaml = read(".github/workflows/release.yml");
    assert!(
        yaml.contains("cargo cyclonedx"),
        "release.yml no longer generates an SBOM"
    );
    for (marker, what) in [
        (
            "artifacts/sipnab-${version}.cdx.json",
            "the main binary SBOM",
        ),
        (
            "artifacts/sipnab-audio-${version}.cdx.json",
            "the audio plugin SBOM (alsa/cpal/rodio appear in no other SBOM)",
        ),
    ] {
        assert!(
            yaml.contains(marker),
            "release.yml stopped producing {what} at {marker}"
        );
    }

    // Both consumers glob *.cdx.json rather than naming versions.
    let subject = yaml
        .split_once("subject-path: |")
        .expect("no attest subject-path")
        .1;
    let subject = &subject[..subject.find("\n\n").unwrap_or(subject.len())];
    assert!(
        subject.contains("*.cdx.json"),
        "SBOMs are not in the attestation subject-path — they would publish \
         unattested beside attested artifacts:\n{subject}"
    );

    let files = yaml
        .split_once("files: |")
        .expect("no release files list")
        .1;
    let files = &files[..files.find("\n\n").unwrap_or(files.len())];
    assert!(
        files.contains("*.cdx.json"),
        "SBOMs are generated and attested but never uploaded to the release:\n{files}"
    );
}

/// The Vale style package is pinned to a release, not to "latest".
///
/// `Packages = Google` resolves through the registry to
/// `.../releases/latest/download/Google.zip`. CI runs `vale sync` on every job,
/// so that spelling makes the prose gates depend on whatever upstream published
/// most recently, with no commit in this repository. A local run cannot predict
/// CI, because a local styles tree is only as fresh as the last manual sync.
///
/// Google v0.7.0 shipped 2026-07-30 13:43 UTC and rewrote `Google.OxfordComma`
/// from a pattern allowing one word before the conjunction to a lookahead
/// allowing five. The rule had been measured, mutation-tested and enabled
/// against the previous package: local said 0 alerts, CI said 35, main went red.
///
/// This gate is the same contract `ci_actions_and_base_images_are_pinned_by_digest`
/// enforces below, for the one dependency that was outside it.
#[test]
fn vale_style_package_is_pinned_to_a_release() {
    let cfg = read(".vale.ini");
    let line = cfg
        .lines()
        .find(|l| l.trim_start().starts_with("Packages ="))
        .expect(
            ".vale.ini has no `Packages =` line — the Google style package is \
                 what every prose gate is built on",
        );
    let value = line
        .split_once('=')
        .expect("Packages line has no `=`")
        .1
        .trim();

    assert!(
        value.starts_with("https://"),
        "`Packages = {value}` names a registry package, which resolves to \
         releases/latest/download and re-floats on every `vale sync`. Pin the \
         full release URL instead."
    );
    assert!(
        !value.contains("/latest/"),
        "`Packages = {value}` points at a `latest` URL — the same floating \
         dependency by another spelling."
    );
    let version = regex::Regex::new(r"/download/(v[0-9]+\.[0-9]+\.[0-9]+)/")
        .unwrap()
        .captures(value)
        .unwrap_or_else(|| {
            panic!(
                "`Packages = {value}` carries no `/download/vX.Y.Z/` version — \
                 this gate cannot tell what it is pinned to"
            )
        })[1]
        .to_string();

    // The pinned version must be stated in prose too, so a reader upgrading
    // knows what they are moving from without parsing a URL.
    assert!(
        cfg.contains(&format!("Google {version} shipped")) || cfg.contains(&format!("{version}\n")),
        "the pin is {version} but .vale.ini never names that version in its \
         explanation — say which release is pinned and why"
    );
}

/// Every GitHub Action and every container base image is pinned by digest.
///
/// A tag is a moving pointer. `actions/checkout@v7` and
/// `ghcr.io/cross-rs/x86_64-unknown-linux-musl:main` both resolve to whatever
/// their owner last pushed, so an upstream compromise — or a well-meaning
/// force-push — silently changes what runs in CI and what is baked into the
/// image published to users. OpenSSF Scorecard flagged 72 unpinned references
/// here, which is what prompted this.
///
/// Pinning is only safe where it has an update path, so check that claim rather
/// than assume it. `.github/dependabot.yml` covers `github-actions` weekly
/// (which also maintains `container:` digests in workflows) and `docker` across
/// `directories: ["/**"]`.
///
/// That glob is load-bearing and was wrong. The docker entry read
/// `directory: "/"`, which is NOT recursive: it covered the root Dockerfile and
/// none of the other seven, so those digests were frozen with no update path —
/// the unpatched-CVE outcome this comment previously claimed was avoided. The
/// sentence was written in the same commit that created the situation it denied.
///
/// One deliberate exception remains: `dependency-name: "rust"` is on the docker
/// ignore list, because a tag bump there would contradict
/// `rust_toolchain_pins_agree`. Its digest moves by hand, with the toolchain.
///
/// SCOPE. This reads Dockerfiles and workflow `container:` keys — the images
/// that build and ship this project. It does NOT read
/// `contrib/observability/docker-compose.yml`, whose four images are pinned by
/// version tag rather than digest. That is a judgement, not an oversight: the
/// stack is a local example, is never built in CI and never shipped, a version
/// tag is far more stable than the floating tags this gate exists to catch,
/// and `directories: ["/**"]` now brings compose files under Dependabot.
/// Digest-freezing a dev stack nobody regenerates would trade a small risk for
/// the larger one of an unmaintained pin.
///
/// Repo-local actions (`uses: ./.github/actions/...`) are exempt, narrowly and
/// at the definition site below. They are not fetched: the path resolves to
/// this repository's own checkout at the commit being tested, which is the
/// same trust domain as the workflow file naming it. A path also takes no
/// `@sha`, so requiring one would make the rule unsatisfiable rather than
/// strict -- a gate demanding output its fixer can never produce. They still
/// count toward the totals, because they are dependencies.
#[test]
fn ci_actions_and_base_images_are_pinned_by_digest() {
    let digest = regex::Regex::new(r"@sha256:[0-9a-f]{64}").unwrap();
    let mut problems = Vec::new();
    let mut actions = 0;
    let mut images = 0;

    for entry in std::fs::read_dir(repo().join(".github/workflows")).expect("workflows dir") {
        let p = entry.expect("entry").path();
        // GitHub accepts BOTH .yml and .yaml for workflows. Reading only one
        // makes the extension a proxy for "is a workflow", and a file named
        // the other way is invisible to every assertion below.
        if !p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&p).expect("read workflow");
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            // A commented-out example is documentation, not a dependency.
            if t.starts_with('#') || !t.starts_with("uses:") && !t.starts_with("- uses:") {
                continue;
            }
            // A repo-local action (`uses: ./.github/actions/x`) is not fetched
            // from anywhere. It is THIS repository's content at the commit
            // under test, so it is already pinned by whatever pins the
            // workflow file that names it -- there is no upstream owner, no
            // moving tag, and no ref to compromise independently. There is
            // also no syntax to pin: a path takes no `@sha`, so demanding one
            // makes the rule unsatisfiable rather than strict. Counted as an
            // action for the totals, because it IS a dependency; just one
            // whose trust domain is identical to the caller's.
            let local = t
                .split_once("uses:")
                .map(|(_, v)| v.trim().starts_with("./"))
                .unwrap_or(false);
            if local {
                actions += 1;
                continue;
            }
            actions += 1;
            // Anchored on the ref, not `is_match` anywhere in the line: a
            // digest demoted into a trailing comment left the line matching
            // while the ref went back to a tag.
            let refpart = t
                .split_once('@')
                .map(|(_, r)| r.split_whitespace().next().unwrap_or(""));
            let pinned =
                refpart.is_some_and(|r| r.len() == 40 && r.chars().all(|c| c.is_ascii_hexdigit()));
            if !pinned {
                problems.push(format!(
                    "{name}:{}: {} — pin to a 40-hex commit SHA with the version in a \
                     trailing comment, e.g. `uses: actions/checkout@<sha> # v7`",
                    i + 1,
                    t
                ));
            } else if !line.contains('#') {
                // The version comment is what Dependabot reads to offer an
                // update. A pin without it is frozen, not maintained — the
                // outcome pinning is supposed to avoid.
                problems.push(format!(
                    "{name}:{}: {} — pinned but with no `# vN` version comment. \
                     Dependabot keys its update on that comment, so this pin is \
                     frozen rather than maintained.\n\
                     Note: this gate checks the SHA is well-formed and commented. \
                     It does NOT verify the SHA exists or belongs to the named \
                     repository — that needs the network and is review's job.",
                    i + 1,
                    t
                ));
            }
        }

        // `container:` and `services:` images run the job's steps, so they are
        // base images by any definition — release.yml built this project's gnu
        // binaries and .deb packages inside a floating `rust:1-bookworm` while
        // this gate read only Dockerfiles and reported every base image pinned.
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with('#') || !t.starts_with("container:") {
                continue;
            }
            let val = t.trim_start_matches("container:").trim();
            // `container: ${{ matrix.container }}` defers to the matrix entries,
            // which are scanned as their own `container:` lines.
            if val.is_empty() || val.starts_with("${{") {
                continue;
            }
            images += 1;
            if !digest.is_match(val) {
                problems.push(format!(
                    "{name}:{}: container {val} is not pinned by digest — the job's \
                     steps run inside it, so it is a base image; pin it as \
                     `image:tag@sha256:<64-hex>`",
                    i + 1
                ));
            }
        }
    }

    // Every Dockerfile in the tree, found rather than listed: a new one added
    // without a digest is exactly the case this exists to catch.
    let out = std::process::Command::new("git")
        .args(["ls-files", "Dockerfile", "*.Dockerfile", "**/Dockerfile*"])
        .current_dir(repo())
        .output()
        .expect("git ls-files");
    for rel in String::from_utf8_lossy(&out.stdout).lines() {
        for (i, line) in read(rel).lines().enumerate() {
            if !line.starts_with("FROM ") {
                continue;
            }
            images += 1;
            if !digest.is_match(line) {
                problems.push(format!(
                    "{rel}:{}: {} — pin the base image by digest, keeping the tag: \
                     `FROM image:tag@sha256:<64-hex>`",
                    i + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        actions >= 40 && images >= 4,
        "only {actions} action refs and {images} FROM lines examined — the scan \
         stopped matching and this gate is reporting a safety it is not providing"
    );
    assert!(
        problems.is_empty(),
        "unpinned CI dependencies ({} of {} actions + {} images):\n  {}",
        problems.len(),
        actions,
        images,
        problems.join("\n  ")
    );
}

/// A workflow's `paths:` filter must cover every repo file the workflow reads.
///
/// The filter decides whether the workflow runs at all, so a build input
/// outside it is a change that never reaches the thing it should rebuild —
/// and nothing reports that, because the workflow simply does not appear.
///
/// `pages.yml` derives the published site version from `Cargo.toml` ("so the
/// published site always matches the released binary") and runs
/// `ops/cloudflare/refresh_csp_hashes.py` against the deployed artifact, while
/// filtering on `website/**` alone. `wiki-sync.yml` already had this right —
/// it lists `docs/**`, its generator, and itself — which is the pattern.
#[test]
fn workflow_path_filters_cover_their_inputs() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Repo-relative paths named inside a workflow. Only tokens that exist as
    // real files count, so output paths (`build/wiki`, `site`) and bare
    // arguments do not produce false positives.
    let token = regex::Regex::new(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*\.[A-Za-z0-9]+").unwrap();
    let mut problems = Vec::new();
    let mut checked = 0;

    for entry in std::fs::read_dir(root.join(".github/workflows")).expect("workflows dir") {
        let p = entry.expect("entry").path();
        if !p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&p).expect("read workflow");

        // Only workflows that filter — an unfiltered workflow runs on every
        // push and cannot miss an input.
        let Some(pline) = text.lines().position(|l| l.trim() == "paths:") else {
            continue;
        };
        let globs: Vec<String> = text
            .lines()
            .skip(pline + 1)
            // Comment lines sit between entries in this repo's filters, so the
            // scan must step over them rather than stop at the first one.
            .take_while(|l| {
                let t = l.trim_start();
                t.starts_with("- ") || t.starts_with('#') || t.is_empty()
            })
            .filter(|l| !l.trim_start().starts_with('#'))
            .filter_map(|l| {
                let t = l
                    .trim()
                    .trim_start_matches("- ")
                    .trim_matches('\'')
                    .trim_matches('"');
                (!t.is_empty()).then(|| t.to_string())
            })
            .collect();
        assert!(
            !globs.is_empty(),
            "{name} has a `paths:` key this test could not read — it is checking nothing"
        );
        checked += 1;

        let covered = |rel: &str| {
            globs.iter().any(|g| match g.strip_suffix("/**") {
                Some(prefix) => rel.starts_with(&format!("{prefix}/")),
                None => g == rel || g.strip_suffix("/*").is_some_and(|p| rel.starts_with(p)),
            })
        };

        let mut seen = std::collections::BTreeSet::new();
        for m in token.find_iter(&text) {
            let rel = m.as_str().trim_end_matches(['"', '\'', ',', ')']);
            // The workflow file names itself in its own filter; skip the
            // .github/workflows/ self-reference and anything not a real file.
            if rel.starts_with(".github/")
                || !root.join(rel).is_file()
                || !seen.insert(rel.to_string())
            {
                continue;
            }
            if !covered(rel) {
                problems.push(format!(
                    "{name}: reads {rel}, which no `paths:` glob covers — a change to it \
                     will not trigger this workflow, and nothing will say so"
                ));
            }
        }
    }

    assert!(
        checked >= 2,
        "only {checked} path-filtered workflows examined — the filter parser stopped \
         matching and this gate is reporting a safety it is not providing"
    );
    assert!(
        problems.is_empty(),
        "workflow path filters that miss their own inputs:\n  {}",
        problems.join("\n  ")
    );
}

/// The analyze page must accept every capture the CLI can read, and it must
/// not decide by filename.
///
/// The page used to gate on a suffix allowlist (`.pcap`, `.pcapng`, `.cap`),
/// which is wrong in both directions on real files. `tcpdump -C -W` writes
/// `tg.pcap0` .. `tg.pcap9`, so the extension is `pcap0` and every member of a
/// ring buffer was refused; `SIP_CALL_RTP_G711` in this repository has no
/// extension at all; and one capture in a real directory is named `.pcap`
/// while its bytes are pcapng, which the old check accepted under the wrong
/// label. Meanwhile any junk renamed to `.pcap` sailed through.
///
/// So the page sniffs the leading bytes. This test holds that logic to the
/// fixtures the CLI is tested against: if sipnab can read it here, the browser
/// must not turn it away.
#[test]
fn the_analyze_page_accepts_every_capture_the_cli_reads() {
    let js = read("website/static/js/analyze.js");

    assert!(
        !js.contains("validExts"),
        "analyze.js is gating on a filename suffix again. Real captures are \
         named tg.pcap0 or carry no extension; identify them by content."
    );
    assert!(
        js.contains("function captureKind"),
        "the content sniffer is gone from analyze.js"
    );

    // Magic numbers the page claims to accept, read out of the source so this
    // cannot drift into asserting against itself.
    let listed: Vec<[u8; 4]> = regex::Regex::new(
        r"is\(0x([0-9a-f]{2}), 0x([0-9a-f]{2}), 0x([0-9a-f]{2}), 0x([0-9a-f]{2})\)",
    )
    .unwrap()
    .captures_iter(&js)
    .map(|c| {
        let b = |i: usize| u8::from_str_radix(&c[i], 16).unwrap();
        [b(1), b(2), b(3), b(4)]
    })
    .collect();
    assert!(
        listed.len() >= 5,
        "expected the four libpcap variants plus pcapng, found {} magic \
         numbers in analyze.js — the sniffer shape changed and this gate is \
         no longer reading it",
        listed.len()
    );

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pcap-samples");
    let mut checked = 0;
    let mut refused = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read pcap-samples") {
        let path = entry.expect("dir entry").path();
        if !path.is_file() {
            continue;
        }
        let mut head = [0u8; 4];
        {
            use std::io::Read;
            let mut f = std::fs::File::open(&path).expect("open sample");
            if f.read(&mut head).unwrap_or(0) < 4 {
                continue;
            }
        }
        // Microsoft NetMon 2.0 ("GMBU"). Two such samples are kept as
        // deliberate negative fixtures — libpcap cannot open them either, and
        // pcap_reader.rs asserts sipnab says so clearly. The browser refusing
        // them is the CLI's behavior, not a gap.
        //
        // Skipped by magic rather than by filename so a third NetMon sample
        // does not silently fail this, and without going through `input_set`,
        // which is `native`-gated — this gate is about the website and must
        // keep running in builds with no capture backend.
        if head == [0x47, 0x4d, 0x42, 0x55] {
            continue;
        }
        checked += 1;
        let gzip = head[0] == 0x1f && head[1] == 0x8b;
        if !gzip && !listed.contains(&head) {
            refused.push(format!(
                "{} (starts {:02x} {:02x} {:02x} {:02x})",
                path.file_name().unwrap().to_string_lossy(),
                head[0],
                head[1],
                head[2],
                head[3]
            ));
        }
    }

    assert!(
        refused.is_empty(),
        "the analyze page would refuse captures the CLI reads: {refused:?}"
    );
    assert!(
        checked >= 20,
        "only {checked} sample captures examined — the walk stopped reading \
         tests/pcap-samples and this gate checked almost nothing"
    );
}

/// Nothing interpolated into the JSON-LD block can terminate the script
/// element that holds it.
///
/// `base.html` renders four config values inside
/// `<script type="application/ld+json">` as `{{ x | json_encode | safe }}`.
/// A SAST scan flags all four as unescaped-output risks. `| safe` is not
/// removable here: `json_encode` emits the surrounding quotes, and without
/// `| safe` Tera HTML-escapes them to `&quot;`, which is not valid JSON and
/// breaks the structured data outright.
///
/// What makes the current code safe is that the values are static — three are
/// literals in `config.toml`, and `published_version` is written by release
/// automation. What was missing is anything holding them to that.
///
/// `json_encode` escapes JSON metacharacters but NOT `/`, so a value
/// containing `</script>` would close the element early and everything after
/// it would be parsed as markup. That is the whole exploit, and it needs only
/// an unlucky edit to `config.toml` to become real. This asserts the property
/// the safety rests on, so the edit fails here rather than shipping.
///
/// Deliberately checks the CONFIG rather than rendered HTML: rendering needs
/// zola, which CI installs for x86_64 only, and a gate that silently skips on
/// another architecture is the same failure as the corpus gates that reported
/// `ok` while proving nothing.
#[test]
fn no_config_value_in_the_json_ld_block_can_close_the_script_element() {
    let tpl = read("website/templates/base.html");
    let cfg = read("website/config.toml");

    // The keys base.html actually interpolates into the ld+json block, read
    // from the template so adding a fifth value cannot bypass this.
    let block_start = tpl
        .find("application/ld+json")
        .expect("base.html must still carry a JSON-LD block");
    let block_end = tpl[block_start..]
        .find("</script>")
        .map(|i| block_start + i)
        .expect("the JSON-LD block must be terminated");
    let block = &tpl[block_start..block_end];

    let key_re = regex::Regex::new(r"\{\{\s*config\.(?:extra\.)?([a-z_]+)\s*\|").expect("regex");
    let keys: Vec<String> = key_re
        .captures_iter(block)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        keys.len() >= 4,
        "expected at least the four known config interpolations in the \
         JSON-LD block, found {keys:?} — if the block was restructured, \
         update this gate rather than deleting it"
    );

    let val_re = |k: &str| {
        regex::Regex::new(&format!(r#"(?m)^\s*{k}\s*=\s*"([^"]*)""#)).expect("value regex")
    };
    let mut checked = 0;
    for k in &keys {
        let Some(c) = val_re(k).captures(&cfg) else {
            continue; // not a top-level scalar; covered by the shape check below
        };
        let v = &c[1];
        assert!(
            !v.contains("</"),
            "config value `{k}` contains `</`, which `json_encode` does NOT \
             escape — it would terminate the <script> element holding the \
             JSON-LD and turn the rest of the page into markup"
        );
        assert!(
            !v.contains('<') && !v.contains('>'),
            "config value `{k}` contains an angle bracket. Nothing needs one \
             here, and allowing them is what makes the `</script>` case \
             reachable at all"
        );
        checked += 1;
    }
    assert!(
        checked >= 3,
        "only {checked} of {} config values were found in config.toml to \
         check; the gate must read real values, not pass by finding none",
        keys.len()
    );
}

// ---------------------------------------------------------------------------
// Escaping-bypass journey: a SAST sweep flagged seven expressions in
// website/templates/ that leave Tera's HTML escaping through `| safe`. None is
// exploitable today and none can simply have the filter deleted — four are
// `json_encode` output whose own quotes escaping would mangle into `&quot;`,
// breaking the JSON-LD outright, and three are HTML that Zola already
// rendered, which escaping would print to the reader as source.
//
// So the finding is not "these seven are wrong". It is that nothing made the
// EIGHTH one a decision. `| safe` is nine characters typed while adding a
// feature, it produces a page that looks correct, and the value's provenance
// — the only thing that makes any of these safe — is invisible at the call
// site. The allowlist below is the missing half: adding a bypass fails here
// with the file and the expression named, and a bypass that stops being
// necessary has to be struck off rather than left to rot into a claim nobody
// checks.
// ---------------------------------------------------------------------------

/// Every escaping bypass in the site templates is on a reviewed allowlist, so
/// an eighth one cannot be added silently.
#[test]
fn every_escaping_bypass_in_the_site_templates_is_on_the_reviewed_allowlist() {
    // (template, the exact source line, why the value cannot be attacker-controlled).
    const ALLOWED: &[(&str, &str, &str)] = &[
        (
            "base.html",
            r#""name": {{ config.title | json_encode | safe }},"#,
            "a literal in website/config.toml; json_encode emits the JSON \
             string quotes and HTML-escaping them yields invalid JSON-LD",
        ),
        (
            "base.html",
            r#""softwareVersion": {{ config.extra.published_version | json_encode | safe }},"#,
            "written by release automation from Cargo.toml, never from a request",
        ),
        (
            "base.html",
            r#""url": {{ config.base_url | json_encode | safe }},"#,
            "a literal in website/config.toml",
        ),
        (
            "base.html",
            r#""description": {{ config.description | json_encode | safe }},"#,
            "a literal in website/config.toml",
        ),
        (
            "index.html",
            r#"var animated = {{ get_url(path='demos/01-intro.webp') | json_encode | safe }} + '?v=10';"#,
            "a build-time get_url() over a repo-relative literal path, resolved \
             into the script rather than read back out of the DOM (which is the \
             js/xss-through-dom form CodeQL rejected); json_encode supplies the \
             JS string quotes",
        ),
        (
            "page.html",
            "{{ page.content | safe }}",
            "HTML Zola rendered from a committed .md file; escaping it would \
             show every docs page as its own source",
        ),
        (
            "section.html",
            "{{ section.content | safe }}",
            "HTML Zola rendered from a committed _index.md, as page.html",
        ),
        (
            "notes.html",
            "{{ section.content | safe }}",
            "HTML Zola rendered from the committed notes/_index.md, as \
             section.html. Notes carry no user-submitted content: every one is \
             a file in this repository",
        ),
        (
            "note.html",
            "{{ page.content | safe }}",
            "HTML Zola rendered from a committed note .md, as page.html",
        ),
    ];

    // `| safe`, `|safe`, and Tera's block form. Not a search for the word
    // "safe": the justifications written beside these bypasses quote the
    // filter, so comments are blanked first — and a bypass inside a comment is
    // not a bypass.
    let bypass = regex::Regex::new(r"\|\s*safe\b|\{%-?\s*autoescape\s+false\b").expect("regex");
    let comment = regex::Regex::new(r"(?s)<!--.*?-->|\{#.*?#\}").expect("regex");

    let mut found: Vec<(String, String)> = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        scanned += 1;
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        let text = std::fs::read_to_string(&p).expect("read template");
        // Keep newlines so a comment never merges two lines into one entry.
        let body = comment.replace_all(&text, |c: &regex::Captures| {
            c[0].chars()
                .map(|ch| if ch == '\n' { '\n' } else { ' ' })
                .collect::<String>()
        });
        for line in body.lines() {
            if bypass.is_match(line) {
                found.push((name.clone(), line.trim().to_string()));
            }
        }
    }
    assert!(
        scanned >= 6,
        "only {scanned} templates were read — the directory walk found almost \
         nothing and this gate would pass by checking nothing"
    );

    found.sort();
    let mut allowed: Vec<(String, String)> = ALLOWED
        .iter()
        .map(|(f, e, _)| (f.to_string(), e.to_string()))
        .collect();
    allowed.sort();

    assert_eq!(
        found,
        allowed,
        "the set of escaping bypasses in website/templates/ changed. `| safe` \
         writes the value into the page verbatim, so a NEW one is only \
         acceptable when the value provably cannot come from anything a \
         visitor sends — add it to ALLOWED with that reason, or restore \
         escaping. A REMOVED one means a bypass stopped being necessary: \
         delete its ALLOWED entry so the list keeps describing the site \
         instead of a version of it that no longer exists.\n\
         Reasons currently on record:\n{}",
        ALLOWED
            .iter()
            .map(|(f, e, why)| format!("  {f}: {e}\n    -> {why}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// CSP asymmetry journey: production's script-src is hash-pinned at the
// Cloudflare edge, but the two policies this repository stores in its own
// tree — the meta tag in base.html and the reference set in static/_headers —
// both still granted `script-src 'unsafe-inline'`. That is not a second
// opinion, it is a weaker one being published under the same name: anyone
// adopting _headers believes they copied the real policy while running one
// under which an injected <script> executes.
//
// _headers can be made strict outright, because nothing enforces it today and
// a missing hash fails CLOSED (a visibly dead nav, not a silent hole). The
// meta tag cannot: a browser enforces every delivered policy independently,
// so a meta policy with no hashes would reject the very scripts the edge
// policy allows and blank the nav, the dropdown and search on every page. It
// keeps 'unsafe-inline' and adds `script-src-attr 'none'`, which closes the
// injected-handler half unconditionally and costs nothing, since
// no_inline_event_handlers_in_templates already proves there are none.
// ---------------------------------------------------------------------------

/// The source tokens of one CSP directive, e.g. `script-src` -> `["'self'"]`.
///
/// `None` means the policy does not carry the directive at all — a different
/// state from carrying it with no sources, and one that must not be silently
/// read as "nothing dangerous in it". Prefix matches are rejected so
/// `script-src-attr` can never answer a question asked about `script-src`.
fn csp_directive<'a>(policy: &'a str, name: &str) -> Option<Vec<&'a str>> {
    policy.split(';').map(str::trim).find_map(|d| {
        let rest = d.strip_prefix(name)?;
        if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
            return None;
        }
        Some(rest.split_whitespace().collect())
    })
}

/// The policy string of the `<meta http-equiv="Content-Security-Policy">` tag.
fn meta_csp(template: &str) -> String {
    let tpl = read(template);
    let tag = tpl
        .lines()
        .find(|l| l.contains(r#"http-equiv="Content-Security-Policy""#))
        .unwrap_or_else(|| {
            panic!(
                "{template} carries no meta CSP — on GitHub Pages that tag is \
                 the only policy a browser sees, so losing it is losing the \
                 whole browser-enforced layer"
            )
        });
    tag.split_once(r#"content=""#)
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(policy, _)| policy.to_string())
        .expect("the meta CSP must carry a quoted content= attribute")
}

/// The `Content-Security-Policy` value of a Cloudflare Pages / Netlify
/// `_headers` file, ignoring the `#` comments that name the header in prose.
fn headers_file_csp(rel: &str) -> String {
    let text = read(rel);
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("Content-Security-Policy:"))
        .unwrap_or_else(|| panic!("{rel} carries no Content-Security-Policy line"));
    line.split_once(':')
        .expect("a header line has a colon")
        .1
        .trim()
        .to_string()
}

/// Assert a `script-src` neither widens beyond the sources this site needs nor
/// leaves an injected inline handler executable.
fn assert_script_src_cannot_run_injected_script(where_: &str, policy: &str) {
    let script_src = csp_directive(policy, "script-src").unwrap_or_else(|| {
        panic!(
            "{where_} names no script-src. Inheriting it from default-src \
             works, but it hides the one directive this gate exists to watch — \
             state it explicitly"
        )
    });

    for token in &script_src {
        assert!(
            matches!(*token, "'self'" | "'unsafe-inline'" | "'wasm-unsafe-eval'")
                || token.starts_with("'sha256-"),
            "{where_} script-src carries `{token}`. The site loads scripts from \
             its own origin and nowhere else, so a host, a scheme, `*`, \
             `'unsafe-eval'` or `'unsafe-hashes'` here is a widening nobody \
             asked for: script-src = {script_src:?}"
        );
    }

    // The conditional is the real invariant, not a formality — it survives
    // 'unsafe-inline' being dropped later without turning into a false alarm.
    if script_src.contains(&"'unsafe-inline'") {
        assert_eq!(
            csp_directive(policy, "script-src-attr").as_deref(),
            Some(&["'none'"][..]),
            "{where_} grants script-src 'unsafe-inline' without \
             `script-src-attr 'none'`. That combination lets an injected \
             `onerror=`/`onclick=` attribute execute wherever this policy is \
             the only one delivered. The site has no handler attributes of its \
             own, so the directive costs nothing and closes the whole class"
        );
    }
}

/// Neither policy this repository stores lets an injected inline script run:
/// the reference header set is hash-only, and the meta tag's residual
/// `'unsafe-inline'` cannot execute a handler attribute.
#[test]
fn no_content_security_policy_this_repo_ships_lets_an_injected_script_run() {
    let meta = meta_csp("website/templates/base.html");
    assert_script_src_cannot_run_injected_script("base.html's meta CSP", &meta);

    // Checked before the shared helper: that helper's fallback for an
    // 'unsafe-inline' grant is `script-src-attr 'none'`, which is the right
    // answer for the meta tag and the WRONG one here — this file can simply be
    // strict, so a failure must say so rather than offer the concession.
    let file = headers_file_csp("website/static/_headers");
    let script_src = csp_directive(&file, "script-src")
        .expect("static/_headers must name script-src explicitly");
    assert!(
        !script_src.contains(&"'unsafe-inline'"),
        "static/_headers grants script-src 'unsafe-inline'. Nothing enforces \
         this file today, so nothing forced it to be weaker than production, \
         where script-src is hash-pinned at the Cloudflare edge. A reference \
         set that is weaker than the policy it claims to mirror is worse than \
         no reference at all — whoever adopts it believes they copied the real \
         one. Leave the hashes out (that fails closed) rather than reopening \
         inline execution: script-src = {script_src:?}"
    );
    assert_script_src_cannot_run_injected_script("static/_headers", &file);

    // style-src is the deliberate asymmetry and must not be "fixed" to match
    // script-src: the templates carry ~141 inline style= attributes, which CSP
    // cannot hash, so removing this silently unstyles the site.
    let style_src = csp_directive(&file, "style-src").expect("static/_headers must name style-src");
    assert!(
        style_src.contains(&"'unsafe-inline'"),
        "static/_headers dropped style-src 'unsafe-inline'. That one IS load \
         bearing — inline style= attributes are not hashable — and removing it \
         to match script-src breaks the rendering of every page"
    );
}

/// `--write-headers` regenerates the reference `_headers` policy from a built
/// site: the real hashes in, `'unsafe-inline'` out, every other line untouched.
#[test]
fn the_csp_refresher_rewrites_the_reference_headers_file_with_hashes_not_unsafe_inline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = "document.getElementById('x').addEventListener('click', function () {});";
    std::fs::write(
        dir.path().join("index.html"),
        format!("<html><body><script>{body}</script></body></html>"),
    )
    .expect("write index.html");

    // Seed from the file that actually ships, not a fixture: a fixture would
    // drift away from the real comments, indentation and eight other headers,
    // and then this gate would be proving something about the fixture.
    let source = read("website/static/_headers");
    let headers_path = dir.path().join("_headers");
    std::fs::write(&headers_path, &source).expect("seed _headers");

    let out = run_csp_refresh(&[
        "--site-dir",
        dir.path().to_str().expect("site dir path"),
        "--write-headers",
        headers_path.to_str().expect("_headers path"),
        "--dry-run",
    ]);
    assert!(
        out.status.success(),
        "--write-headers failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let written = std::fs::read_to_string(&headers_path).expect("read rewritten _headers");
    let policy = written
        .lines()
        .find(|l| l.trim_start().starts_with("Content-Security-Policy:"))
        .expect("the rewritten file must still carry a CSP line")
        .split_once(':')
        .expect("a header line has a colon")
        .1
        .to_string();

    let script_src =
        csp_directive(&policy, "script-src").expect("the written CSP names script-src");
    assert!(
        script_src.contains(&csp_token(body).as_str()),
        "the written policy must pin the built site's inline script by hash, \
         or the host that honors this file blocks it: script-src = {script_src:?}"
    );
    assert!(
        !script_src.contains(&"'unsafe-inline'"),
        "the generated policy reopened inline script execution — the hashes \
         exist precisely so it does not have to: script-src = {script_src:?}"
    );

    // Only the policy changes. The path patterns, the comments and the other
    // headers are reviewed content, and a generator that rewrites them is one
    // that can quietly drop HSTS or frame-ancestors on its next run.
    let src_lines: Vec<&str> = source.lines().collect();
    let out_lines: Vec<&str> = written.lines().collect();
    assert_eq!(
        src_lines.len(),
        out_lines.len(),
        "--write-headers added or dropped lines; it may only replace one"
    );
    let changed: Vec<usize> = (0..src_lines.len())
        .filter(|&i| src_lines[i] != out_lines[i])
        .collect();
    assert_eq!(
        changed.len(),
        1,
        "exactly one line — the CSP — may change; lines {changed:?} differ"
    );
    assert!(
        out_lines[changed[0]]
            .trim_start()
            .starts_with("Content-Security-Policy:"),
        "the one changed line must be the CSP, not `{}`",
        out_lines[changed[0]]
    );
}

/// The analyze page opens a capture inside a zip or tar.
///
/// Reported against a real file: dropping
/// `FIRST-2015_Hands-on_Network_Forensics_PCAP.zip` produced "does not look
/// like a capture file". Conference material, incident-response bundles and
/// vendor escalations arrive zipped far more often than as a bare pcap, so the
/// page turned away the common case and told the reader to go find a shell —
/// on the one page whose entire promise is that no install is needed.
#[test]
fn the_analyze_page_opens_captures_inside_archives() {
    let js = read("website/static/js/analyze.js");

    assert!(
        js.contains("return \"zip\"") && js.contains("return \"tar\""),
        "analyze.js no longer recognizes zip/tar containers"
    );
    for helper in [
        "function zipEntries",
        "function zipMemberBytes",
        "function tarEntries",
    ] {
        assert!(
            js.contains(helper),
            "{helper} is gone — archives cannot be unwrapped"
        );
    }
    assert!(
        js.contains("DecompressionStream"),
        "the deflate decoder is gone; a deflated zip member cannot be read"
    );
    // The central directory is authoritative. Local headers may carry zeroed
    // sizes with a trailing data descriptor, which is exactly the shape a
    // streamed archive has, so reading sizes from them yields 0 for the
    // archives most likely to be shared.
    assert!(
        js.contains("end-of-central-directory"),
        "zip parsing no longer goes through the central directory"
    );
}

/// The browser size guard measures what will be held in memory.
///
/// `file.size` is the size ON DISK, and for anything compressed that is the
/// wrong number in the dangerous direction: a 200 MB gzip expanding to 2 GB
/// passed a guard whose whole purpose was to stop the tab freezing. The
/// uncompressed length is knowable without decompressing — gzip's ISIZE
/// trailer, zip's central directory — and verified against real fixtures:
/// ISIZE reported 198831 for a file that is exactly 198831 bytes.
#[test]
fn the_analyze_size_guard_measures_the_decompressed_size() {
    let js = read("website/static/js/analyze.js");

    assert!(
        js.contains("MAX_ANALYZE_BYTES") && js.contains("function tooBig"),
        "the size guard was inlined again; it must be one named rule"
    );
    assert!(
        js.contains("ISIZE"),
        "the gzip uncompressed-size trailer is no longer consulted, so a \
         compressed capture is measured by its size on disk"
    );
    assert!(
        !js.contains("file.size > 250 * 1024 * 1024"),
        "the guard compares file.size against the cap directly again — that is \
         the compressed size for gzip/zip input, which is the case the cap exists for"
    );
}

/// A failure that is not sipnab's fault must not ask for a bug report.
///
/// The catch-all ended EVERY parse failure with "please open a GitHub issue",
/// including truncated downloads and files that were never captures. That
/// blames the tool for the input and sends noise to the tracker.
#[test]
fn the_analyze_page_asks_for_a_bug_report_only_when_it_earned_one() {
    // Comment lines are stripped first. The fix's own comment quotes the old
    // wording, and scanning the raw file matched THAT — a gate reading prose
    // about the code instead of the code, which is how a gate passes or fails
    // for reasons unrelated to behavior.
    let js: String = read("website/static/js/analyze.js")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    let issue_at = js
        .find("please open a GitHub issue")
        .expect("the bug-report invitation is gone entirely");
    // The invitation must sit inside a branch that first checked the bytes.
    let window_start = issue_at.saturating_sub(400);
    let context = &js[window_start..issue_at];
    // `captureKind`, not merely the name of the variable holding its result.
    // An earlier version of this gate accepted either, and a mutation that
    // replaced the call with `var looked = true` sailed through it: the
    // variable name survived, so the gate saw what it was looking for while
    // the check it stood for was gone.
    assert!(
        context.contains("captureKind("),
        "the GitHub-issue invitation is no longer guarded by an actual content \
         check, so every unreadable file asks the reader to file a bug"
    );
}

/// No test judges an export from whichever directory entry came first.
///
/// The shape is `read_dir(..).next().expect(..)`, and it is a test that reads
/// ONE arbitrary file and draws a conclusion about all of them. It is not a
/// hypothetical: `a_written_container_emits_no_explicit_null` did exactly this
/// and passed for two releases because the entry it drew was the answered
/// dialog. Container filenames gained a hash suffix, the order changed, CI drew
/// the failed dialog instead, and a correct container failed the build.
///
/// A local `cargo test` cannot catch this -- the same test passed here under
/// both `--features full` and `--all-features` while failing on the runner,
/// because what differed was the filesystem, not the feature set. So the gate
/// is static: it refuses the shape rather than trying to observe the flake.
///
/// Sorting first is the fix, and it is what `containers_in` in src/app/batch.rs
/// does. "All of them" and "the same one every time" are different guarantees
/// and a test usually wants both.
#[test]
fn no_test_judges_an_export_from_one_arbitrary_directory_entry() {
    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    for dir in ["src", "tests"] {
        for path in walkdir(std::path::Path::new(dir)) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            scanned += 1;
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !line.contains("read_dir(") {
                    continue;
                }
                // Code, not prose describing it. This gate's own doc comment
                // names the shape it refuses, and without this it reported
                // itself -- the same self-match a bare `pgrep -f` makes.
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with('*') {
                    continue;
                }
                // A quoted mention inside an assertion message is prose too.
                let before = line.split("read_dir(").next().unwrap_or("");
                if before.matches('"').count() % 2 == 1 {
                    continue;
                }
                // The statement, not the file: stop at the first `;` so an
                // unrelated `.expect(` further down cannot be blamed on this.
                let window: String = lines[i..lines.len().min(i + 7)]
                    .iter()
                    .map(|l| l.trim())
                    .collect::<Vec<_>>()
                    .join(" ");
                let stmt = window.split(';').next().unwrap_or("");
                if !stmt.contains(".next()") || stmt.contains("sort") {
                    continue;
                }
                let tail = stmt.rsplit(".next()").next().unwrap_or("");
                if tail.contains(".expect(") || tail.contains(".unwrap(") {
                    offenders.push(format!("{}:{}", path.display(), i + 1));
                }
            }
        }
    }

    assert!(
        scanned > 50,
        "only {scanned} .rs files were scanned, so this gate is checking \
         almost nothing -- the walk stopped matching"
    );
    assert!(
        offenders.is_empty(),
        "these tests judge an export from one arbitrary directory entry, so \
         their verdict depends on filesystem order: {offenders:?}\n\
         Collect and SORT the entries instead -- see `containers_in` in \
         src/app/batch.rs."
    );
}

/// No test may hide behind a feature that `--features full` does not enable.
///
/// The homepage advertises one automated-test count, and TWO gates pin it to a
/// measurement — `.githooks/pre-commit` step 5 against its `cargo test
/// --features full` run, and `ci.yml`'s "Enforce the published test count"
/// against `cargo test --all-features`. One number, two suites.
///
/// They agree today only because `full` and `all-features` differ by exactly
/// one feature, `wasm`, and nothing is tested behind it. That is a coincidence
/// with no guard on it. Add one `#[cfg(feature = "wasm")] #[test]` and the
/// number becomes unsatisfiable BY CONSTRUCTION: the hook demands N, CI
/// demands N+1, and no value of the homepage figure passes both. The fixer for
/// one gate is guaranteed to break the other.
///
/// The two gates cannot simply be merged. CI runs `--all-features` because it
/// includes `plugins`, whose test builds `crates/sipnab-plugin-example` for
/// `wasm32-unknown-unknown`; CI installs that target and a contributor's
/// machine may not have it, so the hook cannot run the same command. Both
/// commands are therefore correct, and what has to hold is the invariant
/// BETWEEN them — which is what this pins.
#[test]
fn no_test_hides_behind_a_feature_outside_full() {
    let toml = read("Cargo.toml");

    // Derive the gap from Cargo.toml rather than hard-coding "wasm", so a new
    // non-`full` feature is covered the day it is added.
    let feature_line = |name: &str| -> Option<String> {
        toml.lines()
            .find(|l| l.trim_start().starts_with(&format!("{name} = [")))
            .map(|l| l.to_string())
    };
    let members = |line: &str| -> Vec<String> {
        regex::Regex::new(r#""([a-z0-9-]+)""#)
            .unwrap()
            .captures_iter(line)
            .map(|c| c[1].to_string())
            .filter(|s| !s.starts_with("dep:"))
            .collect()
    };

    let full_line = feature_line("full").expect("Cargo.toml has no `full` feature");
    let mut in_full: Vec<String> = members(&full_line);
    // One level of expansion is enough: `full` names leaf features directly.
    for f in in_full.clone() {
        if let Some(l) = feature_line(&f) {
            in_full.extend(members(&l));
        }
    }

    let declared: Vec<String> = toml
        .lines()
        .skip_while(|l| !l.starts_with("[features]"))
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| l.split('=').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();

    let outside: Vec<String> = declared
        .into_iter()
        .filter(|f| f != "default" && f != "full" && !in_full.contains(f))
        .collect();
    assert!(
        !outside.is_empty(),
        "no feature sits outside `full` any more, so this gate has nothing to \
         check — if that is deliberate, delete it and the comments in \
         pre-commit and ci.yml that point at it"
    );

    // The two ways a test becomes feature-gated: a crate-level attribute on an
    // integration test file, and an attribute on a `#[test]` or `mod tests`.
    let mut found = Vec::new();
    for feat in &outside {
        let crate_gate = format!("#![cfg(feature = \"{feat}\")]");
        let item_gate = format!("#[cfg(feature = \"{feat}\")]");

        for dir in ["tests", "src"] {
            let walk = walkdir(std::path::Path::new(dir));
            for path in walk {
                let text = match std::fs::read_to_string(&path) {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if dir == "tests" && text.contains(&crate_gate) {
                    found.push(format!("{} is gated on `{feat}` in full", path.display()));
                }
                let lines: Vec<&str> = text.lines().collect();
                for (i, line) in lines.iter().enumerate() {
                    if !line.trim().starts_with(&item_gate) {
                        continue;
                    }
                    // Look ahead past other attributes for a test item.
                    for next in lines.iter().skip(i + 1).take(4) {
                        let t = next.trim();
                        if t.starts_with("#[test]") || t.starts_with("mod tests") {
                            found.push(format!(
                                "{}:{} gates a test on `{feat}`",
                                path.display(),
                                i + 1
                            ));
                            break;
                        }
                        if !t.starts_with('#') && !t.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
    }

    assert!(
        found.is_empty(),
        "a test is reachable under `--all-features` but not `--features full`, \
         so the hook and CI now count DIFFERENT suites against one homepage \
         number and no value satisfies both:\n  {}\n\nEither move the test \
         behind a feature `full` enables, or change both gates together so \
         they count the same command.",
        found.join("\n  ")
    );
}

/// Directory walk, files only.
fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    out
}

/// A design doc that says something is unbuilt must say HOW TO CHECK that, and
/// the check must still hold.
///
/// `an_unimplemented_design_doc_does_not_name_a_shipped_flag` above was written
/// for this defect class in 0.5.61 and missed five instances of it, for a
/// reason worth stating rather than patching around: it reads only the long
/// flags named in a doc's H1. That narrowing was deliberate and correct — an
/// earlier draft scanned every flag a doc mentioned and produced three findings
/// where one was real, and a gate that also cries about `--limit` teaches
/// people to skim it. But a doc whose subject is not a flag is invisible to it.
/// `icid-correlation.md` is titled "Correlating on `P-Charging-Vector`'s
/// `icid-value`". No flag, nothing checked, and the claim "Nothing here is
/// implemented" outlived the implementation by four days.
///
/// So this takes the other route, and it is the one those docs already invented:
/// make the claim falsifiable and then falsify it. Two docs cited a runnable
/// grep in their Status block. Checking those two found a real error in one and
/// an imprecise command in the other — a 100% hit rate among the claims that
/// could be checked at all, against eight that could not.
///
/// Why the timing makes this necessary rather than merely tidy: a design doc is
/// written when its author understands the problem, which is often minutes
/// before they solve it. `wasm-plugin-api.md` shipped its implementation IN THE
/// SAME COMMIT as the doc. `task-first-docs.md` was overtaken 18 minutes later,
/// `icid-correlation.md` 36 minutes later. Nobody was careless; the claim is
/// simply born with a short half-life and nothing re-reads it. A person cannot
/// be relied on to, which is what a gate is for.
#[test]
fn an_unimplemented_claim_cites_evidence_and_the_evidence_still_holds() {
    /// Ways this repo's docs say "this does not exist yet".
    const UNBUILT: &[&str] = &[
        "not implemented",
        "not yet implemented",
        "nothing implemented",
        "nothing here is implemented",
        "nothing rewritten",
        "implementation not started",
    ];

    let dir = repo().join("docs/design");
    let mut checked = 0;
    let mut problems = Vec::new();

    for entry in std::fs::read_dir(&dir).expect("read docs/design/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let text = std::fs::read_to_string(&path).expect("read design doc");

        // The Status BLOCK: the line plus its continuation, since the evidence
        // is usually a clause or two below the verdict.
        let Some(start) = text.find("**Status:**") else {
            continue;
        };
        let block: String = text[start..]
            .lines()
            .take_while(|l| !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let lower = block.to_ascii_lowercase();
        if !UNBUILT.iter().any(|p| lower.contains(p)) {
            continue;
        }
        checked += 1;

        // The evidence: a backticked grep. Restricted to `grep` with no shell
        // metacharacters — this executes what a document says, so the surface
        // it can name is deliberately tiny.
        // The `**Check:**` LINE specifically, not any grep in the block. A
        // Status block may discuss a command in prose — one doc names a
        // `grep -cE` that prints 0 and exits 1, correct as prose and wrong as
        // evidence — and picking the first backtick would run that instead.
        let cmd = block.split("**Check:**").nth(1).and_then(check_command);
        let Some(cmd) = cmd else {
            problems.push(format!(
                "{name}: claims something is unbuilt and names no way to check it. \
                 Add a backticked `grep ...` to the Status block, with what it \
                 should return — that is the difference between a claim a reader \
                 can verify and one they can only believe."
            ));
            continue;
        };
        if has_shell_syntax(&cmd) {
            problems.push(format!(
                "{name}: evidence command is not a plain grep: `{cmd}`"
            ));
            continue;
        }

        // What the doc says the command returns. "exits 1" and "matches
        // nothing" both mean: no hits.
        let expect_none = lower.contains("exits 1")
            || lower.contains("matches nothing")
            || lower.contains("returns nothing");
        if !expect_none && !lower.contains("exits 0") {
            problems.push(format!(
                "{name}: cites `{cmd}` but never says what it should return, so \
                 nothing can be compared against it"
            ));
            continue;
        }

        // The evidence has to be able to FALSIFY the claim above it, and a
        // grep confined to the CLI cannot. `live-fanout.md` said "Nothing here
        // is implemented" over `grep -rn 'fanout' src/cli.rs` exits 1, and it
        // passed this gate for as long as it existed — truthfully, because the
        // command tests REACHABILITY, while the sentence claimed EXISTENCE.
        // 221 lines of `src/capture/fanout.rs` and a tested
        // `capture_live_fanout` sat outside everything the check could see.
        //
        // So a claim that nothing is built must be evidenced against the tree
        // that would hold it. A narrower command is not weaker evidence, it is
        // evidence for a different proposition, and that is worse: it reads as
        // verified.
        if expect_none && cmd.contains("src/cli.rs") && !cmd.contains("src/ ") {
            problems.push(format!(
                "{name}: claims something is unbuilt, but checks only \
                 `src/cli.rs`. That proves no FLAG reaches it, not that it does \
                 not exist — a built-but-unwired module passes this check while \
                 the sentence above it is false. Grep the tree that would hold \
                 the implementation, or state the claim as \"nothing reaches \
                 it\" rather than \"nothing is implemented\"."
            ));
            continue;
        }

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .current_dir(repo())
            .output()
            .expect("run the doc's own evidence command");
        let found = out.status.success();
        let hits = String::from_utf8_lossy(&out.stdout).lines().count();

        if expect_none && found {
            problems.push(format!(
                "{name}: says `{cmd}` finds nothing, but it returns {hits} match(es). \
                 Either the thing shipped and the Status line is now false, or the \
                 command is too broad and is matching prose."
            ));
        } else if !expect_none && !found {
            problems.push(format!("{name}: says `{cmd}` matches, and it does not"));
        }
    }

    // Lowered 5 -> 4 when `mid-dialog-state-machine.md` stopped claiming to be
    // unbuilt, because it shipped. That is the only doc that left the set, and
    // it left in the one direction this floor must not block: a design that
    // gets built is supposed to fall out of a population defined by "claims
    // nothing exists yet". The floor is anti-vacuity — it catches the phrase
    // list drifting away from how the docs are actually written — so it moves
    // only with a named doc and a reason, never to make a run green.
    assert!(
        checked >= 4,
        "only {checked} design docs claim something is unbuilt — the phrase list \
         stopped matching and this gate is checking almost nothing"
    );
    problems.sort();
    assert!(
        problems.is_empty(),
        "a design doc's claim about what is unbuilt cannot be checked, or no \
         longer holds:\n  {}",
        problems.join("\n  ")
    );
}

/// True when a command carries shell syntax OUTSIDE single quotes.
///
/// The first version rejected these characters anywhere, and refused two honest
/// commands for it: `grep -c '#\[tool(' src/mcp/server.rs` and
/// `grep -n 'SipMethod::Bye =>' src/sip/dialog.rs`. Both hold their parenthesis
/// or angle bracket inside single quotes, where the shell treats them as
/// literal text. A gate that rejects correct input teaches people to work
/// around it, so it checks what actually matters: unquoted metacharacters.
fn has_shell_syntax(cmd: &str) -> bool {
    let mut in_quote = false;
    for c in cmd.chars() {
        if c == '\'' {
            in_quote = !in_quote;
        } else if !in_quote && matches!(c, '&' | ';' | '>' | '<' | '$' | '(' | '`' | '|') {
            return true;
        }
    }
    false
}

/// The `grep` a Status block offers as evidence, if any.
fn check_command(block: &str) -> Option<String> {
    regex::Regex::new(r"`(grep [^`]+)`")
        .unwrap()
        .captures(block)
        .map(|c| c[1].to_string())
}

/// Every `**Check:**` line in a design doc still returns what it claims.
///
/// The gate above only inspects docs claiming something is UNBUILT. A doc that
/// flips to IMPLEMENTED keeps its evidence line and nothing runs it again —
/// the same rot in the other direction, and the direction `icid-correlation.md`
/// is now in. A claim is worth checking whichever way it points.
#[test]
fn every_check_line_in_a_design_doc_still_holds() {
    let dir = repo().join("docs/design");
    let mut ran = 0;
    let mut problems = Vec::new();

    for entry in std::fs::read_dir(&dir).expect("read docs/design/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let text = std::fs::read_to_string(&path).expect("read design doc");

        for line in text
            .lines()
            .filter(|l| l.trim_start().starts_with("**Check:**"))
        {
            let Some(cmd) = check_command(line) else {
                problems.push(format!("{name}: a **Check:** line names no `grep`"));
                continue;
            };
            if has_shell_syntax(&cmd) {
                problems.push(format!("{name}: check is not a plain grep: `{cmd}`"));
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let expect_none = lower.contains("exits 1")
                || lower.contains("matches nothing")
                || lower.contains("returns nothing");
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .current_dir(repo())
                .output()
                .expect("run the doc's own check");
            ran += 1;
            let found = out.status.success();
            if expect_none && found {
                problems.push(format!(
                    "{name}: `{cmd}` should find nothing and returns {} match(es)",
                    String::from_utf8_lossy(&out.stdout).lines().count()
                ));
            } else if !expect_none && !found {
                problems.push(format!("{name}: `{cmd}` should match, and finds nothing"));
            }
        }
    }

    assert!(
        ran >= 6,
        "only {ran} **Check:** lines ran — they are being dropped from the docs \
         rather than kept true, and this gate is checking almost nothing"
    );
    problems.sort();
    assert!(
        problems.is_empty(),
        "a design doc's own evidence no longer returns what it claims:\n  {}",
        problems.join("\n  ")
    );
}

/// The published CLA page reproduces `CLA.md` exactly.
///
/// The agreement exists in three places and only one of them is the source.
/// `CLA.md` is that source. `website/content/cla.md` republishes it at
/// <https://sipnab.com/cla/>, and a gist that CLA Assistant serves shows it to
/// a contributor at signing time.
///
/// The website copy is HAND-WRITTEN, not generated. It sits at the top level of
/// `website/content/` with `template = "page.html"`, while
/// `scripts/build-site-pages.py` writes only into `website/content/docs/` and
/// stamps each page with a weight and a docs nav entry — so registering the CLA
/// in `PAGES` would move the page to `/docs/cla/` and break the `/cla/` URL
/// that README, the homepage card and CLA Assistant all point at. The generator
/// convention does not fit this page, which left the copy unguarded, which is
/// what this replaces.
///
/// Drift here is not cosmetic. A contributor who reads the site and then signs
/// has agreed to whatever the gist says, and the diff between the two is
/// exactly the part nobody consented to. The gist lives outside the repository
/// and no test can reach it; `MAINTAINERS.md` carries that half as an
/// instruction to whoever edits `CLA.md`.
#[test]
fn cla_page_reproduces_the_agreement() {
    let agreement = read("CLA.md");
    let page = read("website/content/cla.md");

    // The site demotes the H1 to an H2 because the page already carries a title
    // in its front matter. That single character is the only allowed difference.
    const H1: &str = "# SIPNAB Individual Contributor License Agreement";
    assert!(
        agreement.starts_with(H1),
        "CLA.md no longer opens with {H1:?} — this gate keys the two copies on \
         that heading, so it is now comparing something else"
    );
    let want = agreement.replacen(H1, &format!("#{H1}"), 1);

    // Guards against a page that "matches" because both sides went empty.
    assert!(
        want.len() > 4_000,
        "CLA.md is only {} bytes — too short to be the agreement, and a \
         comparison against it would prove nothing",
        want.len()
    );

    assert!(
        page.ends_with(&want),
        "website/content/cla.md no longer ends with the text of CLA.md.\n\
         The site page is hand-maintained: copy CLA.md in below the `---`, \
         demoting its `#` heading to `##`, and leave the front matter and the \
         sign-here block above it untouched.\n\
         A contributor reads the site and signs against the gist, so a diff \
         between these two is text somebody agreed to without seeing."
    );
}

/// Every route to the signing flow names THIS repository, and the sentence that
/// signs the agreement stays verbatim.
///
/// Two failures hide here, and neither one announces itself.
///
/// CLA Assistant keys signatures on `<owner>/<repo>` in the URL. A fork, a
/// rename, or a copied badge line leaves a link that loads a perfectly normal
/// signing page for a DIFFERENT project — the contributor signs, sees success,
/// and this repository records nothing. So the owner and repository come from
/// `Cargo.toml`'s `repository` field rather than a literal here: one identity,
/// declared once.
///
/// The second is the sign-off sentence. The bot matches the whole string, so
/// house-style editing — dropping "Document", lowercasing "CLA", trimming "I
/// hereby" — turns a signature into an ordinary comment. Nothing rejects it and
/// nothing tells the contributor, who has done the one thing asked of them and
/// is still blocked.
#[test]
fn the_signing_route_names_this_repository_and_quotes_the_bot_verbatim() {
    // The exact string CLA Assistant accepts as a signature. Editing this line
    // does not change what the bot matches; it only stops the docs from saying
    // so.
    const SIGN_OFF: &str = "I have read the CLA Document and I hereby sign the CLA";

    let contributing = read("CONTRIBUTING.md");
    assert!(
        contributing.contains(SIGN_OFF),
        "CONTRIBUTING.md no longer quotes the sentence CLA Assistant accepts:\n  \
         {SIGN_OFF:?}\n\
         The bot matches it whole, so a contributor who posts a reworded \
         version signs nothing and is told nothing."
    );

    let slug = regex::Regex::new(r"https://github\.com/([\w.-]+)/([\w.-]+)")
        .unwrap()
        .captures(&read("Cargo.toml"))
        .map(|c| format!("{}/{}", &c[1], &c[2]))
        .expect("Cargo.toml has no github.com `repository` URL to take the slug from");

    // Both shapes the service uses: the signing page `cla-assistant.io/o/r` and
    // the README badge `cla-assistant.io/readme/badge/o/r`.
    let link =
        regex::Regex::new(r"cla-assistant\.io/(?:readme/badge/)?([\w.-]+)/([\w.-]+)").unwrap();

    let mut wrong = Vec::new();
    let mut seen = 0usize;
    for file in [
        "README.md",
        "CONTRIBUTING.md",
        "MAINTAINERS.md",
        "website/content/cla.md",
    ] {
        for (i, line) in read(file).lines().enumerate() {
            for c in link.captures_iter(line) {
                seen += 1;
                let found = format!("{}/{}", &c[1], &c[2]);
                if found != slug {
                    wrong.push(format!("{file}:{}: names {found}", i + 1));
                }
            }
        }
    }

    // A regex that matches nothing reports every link correct.
    assert!(
        seen >= 4,
        "only {seen} cla-assistant.io repository links found across README, \
         CONTRIBUTING, MAINTAINERS and the site page — the links were removed \
         or reshaped, and this gate is checking almost nothing"
    );
    assert!(
        wrong.is_empty(),
        "these links send a contributor to the signing page for a repository \
         other than {slug}:\n  {}\n\
         The signature lands against whatever project the URL names, so this \
         one records none of it.",
        wrong.join("\n  ")
    );
}

/// `website/README.md` describes the deploy that actually happens.
///
/// It described a different one for long enough to matter: "The site is
/// rsync'd to a static-hosting host. There's no GitHub Actions automation",
/// while `.github/workflows/pages.yml` had been building and publishing
/// sipnab.com on every push to `main`. It also claimed the repository tracks
/// `website/public/`, which `.gitignore` excludes, and called the homepage
/// demos GIFs when `demos/Makefile` converts each one to WebP and deletes the
/// GIF in the same recipe.
///
/// A wrong runbook is worse than a missing one. Someone following it would
/// have gone looking for SSH credentials to a host that does not serve the
/// site, and reasoned about a `public/` directory git does not hold.
///
/// The `public/` half reads `.gitignore` rather than matching a phrase, so
/// this cannot be satisfied by rewording. If the ignore rule is ever dropped
/// and the directory genuinely becomes tracked, the assertion inverts on its
/// own instead of asserting yesterday's truth.
#[test]
fn website_readme_describes_the_real_deploy_path() {
    let readme = std::fs::read_to_string("website/README.md").expect("website/README.md");

    assert!(
        readme.contains("pages.yml"),
        "website/README.md does not name .github/workflows/pages.yml, which is \
         what actually publishes sipnab.com"
    );
    assert!(
        !readme.contains("no GitHub\nActions automation") && !readme.contains("no GitHub Actions"),
        "website/README.md still claims there is no GitHub Actions automation. \
         pages.yml builds the analyzer, runs zola, deploys to Pages and \
         refreshes the Cloudflare CSP on every push to main"
    );

    // Read the ignore rule rather than trusting either document.
    let ignored = std::fs::read_to_string(".gitignore")
        .expect(".gitignore")
        .lines()
        .any(|l| l.trim() == "website/public/" || l.trim() == "website/public");
    if ignored {
        // Match the CLAIM, not one phrasing of it. The first version of this
        // gate forbade the literal "repo tracks `public/`" and passed while a
        // second sentence forty-five lines further down still annotated the
        // directory as "committed for deploy stability" -- the same false
        // claim, worded differently, in the same file. A gate pinned to one
        // spelling is satisfied by a synonym.
        for claim in [
            "tracks `public/`",
            "committed for deploy",
            "commits `public/`",
        ] {
            assert!(
                !readme.contains(claim),
                "website/README.md says {claim:?}, but `.gitignore` excludes \
                 website/public/ and git holds none of it. A reader would go \
                 looking for a build artifact the repository does not have"
            );
        }
    }

    assert!(
        !readme.contains("demo tabs are GIFs"),
        "the homepage demos are WebP. demos/Makefile converts the VHS output \
         and deletes the intermediate GIF in the same recipe, so nothing under \
         static/demos/ is a GIF"
    );
}

/// A documented claim about a tracked path is checked against git, not prose.
///
/// Debt from a real miss. `website_readme_describes_the_real_deploy_path` was
/// written to stop `website/README.md` claiming the repository tracks
/// `website/public/`, and it forbade one literal string. Forty-five lines below
/// the sentence it policed, the same file annotated the same directory as
/// "Generated output (committed for deploy stability)" -- the identical false
/// claim, worded differently, and the gate passed. A reviewer reading the
/// annotated document found it; the gate could not.
///
/// So this asks git rather than matching a phrase. Whatever a document says
/// about a path, the ignore rules and the index decide the truth.
#[test]
fn no_document_claims_git_holds_a_directory_git_ignores() {
    // Directories the repository generates and does not track. Each is checked
    // against `.gitignore` below rather than trusted from this list.
    const GENERATED: [&str; 2] = ["website/public/", "e2e/node_modules/"];
    let ignore = std::fs::read_to_string(".gitignore").expect(".gitignore");

    let mut checked = 0;
    for dir in GENERATED {
        let ignored = ignore
            .lines()
            .any(|l| l.trim() == dir || l.trim() == dir.trim_end_matches('/'));
        assert!(
            ignored,
            "{dir} is in this test's generated list but `.gitignore` does not \
             exclude it. Either the ignore rule was dropped -- in which case the \
             directory is now tracked and this list is wrong -- or the list is \
             stale. Both need a human, not a silent pass"
        );
        let tracked = std::process::Command::new("git")
            .args(["ls-files", dir])
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false);
        assert!(
            !tracked,
            "`.gitignore` excludes {dir} yet git holds files under it. A \
             document describing either state would be wrong about the other"
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        GENERATED.len(),
        "not every generated directory was examined"
    );
}

/// The README's claims about `public/` agree with each other.
///
/// The first fix corrected one sentence and left a contradicting one further
/// down. A document that says two things about the same directory is worse than
/// one that says the wrong thing once: a reader believes whichever they reach
/// first, and neither statement looks provisional.
#[test]
fn the_website_readme_does_not_contradict_itself_about_public() {
    let readme = std::fs::read_to_string("website/README.md").expect("website/README.md");
    let says_ignored = readme.contains("`.gitignore` excludes");
    let says_held: Vec<&str> = [
        "tracks `public/`",
        "committed for deploy",
        "commits `public/`",
    ]
    .into_iter()
    .filter(|c| readme.contains(c))
    .collect();
    assert!(
        says_ignored,
        "website/README.md never states that `.gitignore` excludes public/. \
         Saying nothing is how the previous wrong claim survived a rewrite"
    );
    assert!(
        says_held.is_empty(),
        "website/README.md says `.gitignore` excludes public/ AND still claims \
         git holds it: {says_held:?}. A reader believes whichever they reach \
         first"
    );
}

/// Every tree in `.config/code-trees.txt` is classified by the packaging gate.
///
/// Adding `e2e/` turned three gates red one after another --
/// `code_tree_list_matches_the_repository`, then `NOT_PATH_ROOTS` in this file
/// -- each correct, each arriving only once the previous was fixed. Three
/// cycles for one omission.
///
/// This does NOT re-derive which directories exist; `code_tree_list_matches_the_repository`
/// already holds `.config/code-trees.txt` equal to the tracked tree, and a
/// second implementation of one rule is two things to keep true. It checks the
/// join instead: every tree that file names must be classified here as either a
/// path root or explicitly not one. That join is what nothing was checking.
#[test]
fn every_code_tree_is_classified_by_the_packaging_gate() {
    let trees = std::fs::read_to_string(".config/code-trees.txt").expect(".config/code-trees.txt");
    let named: Vec<String> = trees
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| format!("{}/", l.trim_end_matches('/')))
        .collect();
    assert!(
        named.len() >= 10,
        "only {} trees parsed from .config/code-trees.txt; the format changed \
         and this gate is comparing against almost nothing",
        named.len()
    );

    // Read this file's own two lists rather than restating them.
    let body = std::fs::read_to_string("tests/site_journey_test.rs").expect("this file");
    let listed = |name: &str| -> Vec<String> {
        let Some(i) = body.find(&format!("const {name}: [&str;")) else {
            return Vec::new();
        };
        let Some(j) = body[i..].find("];") else {
            return Vec::new();
        };
        regex::Regex::new(r#""([a-zA-Z0-9_.-]+/)""#)
            .expect("regex")
            .captures_iter(&body[i..i + j])
            .map(|c| c[1].to_string())
            .collect()
    };
    let mut classified = listed("ROOTS");
    classified.extend(listed("NOT_PATH_ROOTS"));
    assert!(
        classified.len() >= 10,
        "only {} directories read out of ROOTS/NOT_PATH_ROOTS; the extractor \
         stopped matching and every comparison below is vacuous",
        classified.len()
    );

    let missing: Vec<&String> = named.iter().filter(|d| !classified.contains(d)).collect();
    assert!(
        missing.is_empty(),
        "these trees are in .config/code-trees.txt but classified in neither \
         ROOTS nor NOT_PATH_ROOTS: {missing:?}. Adding a directory should fail \
         one gate, not three in sequence"
    );
}

/// The generated-directory list this file checks is not empty.
///
/// Guards the two tests above from going vacuous. An empty `GENERATED` array
/// satisfies both by examining nothing, which is the failure mode this
/// repository keeps finding in its own instruments.
#[test]
fn the_generated_directory_list_is_not_empty() {
    let body = std::fs::read_to_string("tests/site_journey_test.rs").expect("this file");
    let start = body
        .find("const GENERATED: [&str;")
        .expect("the GENERATED list");
    let decl = &body[start..start + 40];
    let n: usize = decl
        .split(';')
        .nth(1)
        .and_then(|t| t.split(']').next())
        .and_then(|t| t.trim().parse().ok())
        .expect("the array length");
    assert!(
        n >= 2,
        "GENERATED holds {n} entries; with fewer than two the paired \
         ignore/track assertions stop covering anything"
    );
}

/// Count the MCP tools the server registers, across the whole `src/mcp` tree.
///
/// Returns `(total, in_server_rs, files_walked)`. The two extra figures exist
/// so a caller can prove the walk left `server.rs`: rmcp's `ToolRouter`
/// composes with `+`, so `#[tool_router]` blocks in submodules register tools
/// exactly as much as the ones in `server.rs`, and a counter that reads a
/// single file reports a floor while looking like a total.
fn registered_mcp_tool_count() -> (usize, usize, usize) {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
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
    walk(std::path::Path::new("src/mcp"), &mut files);
    files.sort();

    let re = regex::Regex::new(r#"(?m)^\s+name = "[a-z0-9_]+","#).unwrap();
    let count_in = |p: &std::path::Path| {
        std::fs::read_to_string(p)
            .map(|s| re.find_iter(&s).count())
            .unwrap_or(0)
    };
    let total = files.iter().map(|f| count_in(f)).sum();
    let in_server_rs = count_in(std::path::Path::new("src/mcp/server.rs"));
    (total, in_server_rs, files.len())
}

/// Tools registered outside `server.rs` must be counted.
///
/// The concrete regression: on 0.5.130 six submodules under `src/mcp/tools/`
/// held 13 tools, `tools/list` answered 51, and the homepage gate certified a
/// tile reading 38 because it opened one file. Naming the submodules here
/// means deleting the walk — or narrowing it back to `server.rs` — fails
/// rather than quietly returning a smaller number that some tile will match.
#[test]
fn mcp_tool_walk_counts_tools_registered_outside_server_rs() {
    let (total, in_server_rs, files) = registered_mcp_tool_count();
    assert!(
        files >= 2,
        "the walk reached {files} file(s) under src/mcp; it is not recursing"
    );
    assert!(
        total > in_server_rs,
        "every one of the {total} MCP tool registrations is in server.rs — \
         either the router submodules were folded back in (update this test) \
         or the walk stopped recursing and is reporting a floor as a total"
    );

    // Each submodule that carries a #[tool_router] must contribute.
    let tools_dir = std::path::Path::new("src/mcp/tools");
    if tools_dir.is_dir() {
        let re = regex::Regex::new(r#"(?m)^\s+name = "[a-z0-9_]+","#).unwrap();
        let mut contributing = 0usize;
        for e in std::fs::read_dir(tools_dir)
            .expect("read src/mcp/tools")
            .flatten()
        {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "rs") {
                let src = std::fs::read_to_string(&p).unwrap_or_default();
                if re.find_iter(&src).count() > 0 {
                    contributing += 1;
                }
            }
        }
        assert!(
            contributing >= 2,
            "only {contributing} file(s) under src/mcp/tools register a tool; \
             the pattern that finds them has stopped matching"
        );
    }
}

/// The walk's own floor must be able to fail.
///
/// A helper that returns a plausible number when it can read nothing is the
/// failure this whole gate exists to prevent, so the guard is exercised
/// against a directory that does not exist rather than trusted.
#[test]
fn mcp_tool_walk_reports_nothing_when_it_can_read_nothing() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
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
    walk(std::path::Path::new("src/mcp-does-not-exist"), &mut files);
    assert_eq!(
        files.len(),
        0,
        "the walk invented files for a path that does not exist"
    );

    // And the real tree must not be empty, or the comparison above is vacuous.
    let (total, _, real_files) = registered_mcp_tool_count();
    assert!(
        real_files > 0 && total > 0,
        "src/mcp yielded {real_files} file(s) and {total} tool(s); this test \
         would pass identically against a deleted source tree"
    );
}

/// The homepage tile carries the count twice and both spellings must move.
///
/// `data-count` drives the JavaScript odometer; the text node is what a
/// visitor with JavaScript off reads. They are separate strings in the
/// template, so one can be updated alone — and the one left behind is the one
/// served to every crawler and every reader without JS.
#[test]
fn homepage_mcp_tile_carries_the_same_count_in_both_spellings() {
    let idx = read("website/templates/index.html");
    let attr = regex::Regex::new(r#"data-count="(\d+)" data-suffix=" MCP tools""#)
        .unwrap()
        .captures(&idx)
        .expect("no MCP tools tile with a data-count on the homepage");
    let text = regex::Regex::new(r">(\d+) MCP tools<")
        .unwrap()
        .captures(&idx)
        .expect("the MCP tools tile has no no-JS fallback text node");
    assert_eq!(
        &attr[1], &text[1],
        "the MCP tile's data-count says {} and its no-JS text says {}; a \
         reader without JavaScript is served the stale figure",
        &attr[1], &text[1]
    );
}

// ---------------------------------------------------------------------------
// Per-page metadata: the description in a docs page's front matter is the ONE
// string that reaches four surfaces — `<meta name="description">`, the
// `og:description` a social unfurl renders, the lead paragraph under the H1,
// and the card text on the docs landing index. `page.html` and `section.html`
// both fall back to `config.description` when a page has none, so a missing
// description does not fail a build or look wrong on the page: it silently
// publishes the site-wide blurb as that page's summary, and a search engine
// that sees the same sentence on fifty URLs collapses them.
//
// The gates below assert that outcome rather than the template string that
// produces it: present, unique, not the title restated, and never the
// site-wide fallback.
// ---------------------------------------------------------------------------

/// One docs page's front matter: repo-relative path, `title`, `description`.
///
/// `description` is the empty string when the key is absent — the callers
/// below report that as the failure rather than skipping the page, which is
/// how `website/content/docs/_index.md` went un-described: the older
/// `docs_page_weights_are_unique_and_descriptions_present` skips every
/// `_index.md`, so the docs landing page — the most-linked URL in the tree —
/// was outside every check.
fn docs_front_matter() -> Vec<(String, String, String)> {
    let root = repo().join("website/content/docs");
    let title_re = regex::Regex::new(r#"(?m)^title = "(.*)"\s*$"#).unwrap();
    let desc_re = regex::Regex::new(r#"(?m)^description = "(.*)"\s*$"#).unwrap();
    let mut dirs = vec![root.clone()];
    let mut out = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read website/content/docs") {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
            if p.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let rel = p
                .strip_prefix(repo())
                .expect("under repo")
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {rel}: {e}"));
            // Front matter only. A `description = "..."` line inside a fenced
            // code block in the body would otherwise be read as the page's own.
            let body = text.strip_prefix("+++\n").unwrap_or_else(|| {
                panic!("{rel} does not open with `+++` — it is not a Zola page")
            });
            let fm = match body.split_once("\n+++") {
                Some((fm, _)) => fm,
                None => panic!("{rel} has an unterminated `+++` front matter block"),
            };
            let title = title_re
                .captures(fm)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            let desc = desc_re
                .captures(fm)
                .map(|c| c[1].to_string())
                .unwrap_or_default();
            out.push((rel, title, desc));
        }
    }
    out.sort();
    // The sweep walks a directory rather than a registry, so a wrong root or a
    // broken extension filter yields an empty list that every assertion below
    // passes. 50 pages at the time of writing; the floor only has to be high
    // enough that a blind sweep cannot clear it.
    assert!(
        out.len() >= 40,
        "only {} page(s) found under website/content/docs — the front-matter \
         sweep has gone blind and every metadata gate built on it is vacuous",
        out.len()
    );
    out
}

/// Normalize a title or description for comparison: lowercase, collapsed
/// whitespace, no trailing period.
fn normalize_meta(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches('.')
        .to_string()
}

/// Every docs page carries its own `description`, `_index.md` included.
///
/// Without one, `page.html`/`section.html` substitute `config.description` and
/// the page ships the site-wide blurb as its meta description — invisible on
/// the page itself, wrong everywhere the page is quoted.
#[test]
fn every_docs_page_carries_its_own_meta_description() {
    let missing: Vec<String> = docs_front_matter()
        .into_iter()
        .filter(|(_, _, d)| d.trim().is_empty())
        .map(|(rel, _, _)| rel)
        .collect();
    assert!(
        missing.is_empty(),
        "docs page(s) with no `description` in their front matter — each one \
         publishes config.description as its own summary:\n  {}",
        missing.join("\n  ")
    );
}

/// No two docs pages share a description.
///
/// The failure mode this exists for is a generated description built from a
/// template string — "Reference documentation for {title}" — which is unique
/// per page only by accident and reads as boilerplate to a search engine. A
/// description repeated across URLs is worse than none: Google collapses the
/// duplicates and picks its own snippet.
#[test]
fn no_two_docs_pages_share_a_meta_description() {
    let mut by_desc: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (rel, _, desc) in docs_front_matter() {
        if desc.trim().is_empty() {
            continue; // reported by every_docs_page_carries_its_own_meta_description
        }
        by_desc.entry(normalize_meta(&desc)).or_default().push(rel);
    }
    let dupes: Vec<String> = by_desc
        .iter()
        .filter(|(_, pages)| pages.len() > 1)
        .map(|(desc, pages)| format!("{}\n    shared by: {}", desc, pages.join(", ")))
        .collect();
    assert!(
        dupes.is_empty(),
        "docs pages sharing one description — a search engine collapses \
         duplicate snippets, so the repeated pages compete with each other:\n  {}",
        dupes.join("\n  ")
    );
}

/// No docs description is the site-wide blurb.
///
/// The template fallback is `config.description`. Pasting that string into a
/// page's front matter satisfies "has a description" while producing exactly
/// the output the fallback already produced, so this checks the value rather
/// than its presence.
#[test]
fn no_docs_description_falls_back_to_the_site_wide_blurb() {
    let config = read("website/config.toml");
    let site_desc = regex::Regex::new(r#"(?m)^description = "(.*)"\s*$"#)
        .unwrap()
        .captures(&config)
        .map(|c| normalize_meta(&c[1]))
        .expect("website/config.toml has no top-level `description`");
    assert!(
        !site_desc.is_empty(),
        "config.toml's description is empty, so this comparison matches every \
         page and proves nothing"
    );
    let copies: Vec<String> = docs_front_matter()
        .into_iter()
        .filter(|(_, _, d)| normalize_meta(d) == site_desc)
        .map(|(rel, _, _)| rel)
        .collect();
    assert!(
        copies.is_empty(),
        "docs page(s) whose description is a copy of config.description — \
         identical to having none, and identical to each other:\n  {}",
        copies.join("\n  ")
    );
}

/// A description summarizes the page; it is never the title read back.
///
/// "Cookbook" / "Cookbook." / "Cookbook reference" all pass a presence check
/// and a uniqueness check while telling a reader nothing the `<title>` did not
/// already say. The floor is deliberately low — six words — because it is
/// there to catch a stub, not to legislate prose length; the shortest real
/// description in the tree at the time of writing runs seven.
#[test]
fn a_docs_description_is_never_the_page_title_restated() {
    let mut bad = Vec::new();
    for (rel, title, desc) in docs_front_matter() {
        if desc.trim().is_empty() {
            continue; // reported by every_docs_page_carries_its_own_meta_description
        }
        let n_desc = normalize_meta(&desc);
        let n_title = normalize_meta(&title);
        if !n_title.is_empty() && n_desc == n_title {
            bad.push(format!(
                "{rel}: description is the title verbatim ({desc:?})"
            ));
            continue;
        }
        // Strip a leading restatement of the title, then require the remainder
        // to actually say something: "Cookbook reference." leaves one word.
        let remainder = n_desc.strip_prefix(&n_title).unwrap_or(&n_desc);
        let words = remainder.split_whitespace().count();
        if words < 6 {
            bad.push(format!(
                "{rel}: description adds only {words} word(s) beyond the title \
                 ({desc:?})"
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "docs description(s) that restate the title instead of summarizing the \
         page:\n  {}",
        bad.join("\n  ")
    );
}

/// The base template emits the full social-card head, wired to the page.
///
/// Presence in `base.html` is only half of it: every one of these tags reads a
/// Tera block, and a block whose child override was dropped renders the
/// `config.*` default on every page while the tag itself still looks correct
/// in the template. So this asserts both ends — the tag in `base.html` and the
/// override in the two templates that render `website/content/docs/`.
#[test]
fn the_base_template_emits_the_social_card_meta_tags() {
    let base = read("website/templates/base.html");
    // (what it is, the substring that must appear on one line of base.html)
    let required: &[(&str, &str)] = &[
        (
            "meta description",
            r#"<meta name="description" content="{% block description %}"#,
        ),
        (
            "og:title",
            r#"<meta property="og:title" content="{% block og_title %}"#,
        ),
        (
            "og:description",
            r#"<meta property="og:description" content="{% block og_description %}"#,
        ),
        (
            "og:type",
            r#"<meta property="og:type" content="{% block og_type %}"#,
        ),
        ("og:url", r#"<meta property="og:url" content="#),
        ("og:image", r#"<meta property="og:image" content="#),
        ("twitter:card", r#"<meta name="twitter:card" content="#),
        ("twitter:image", r#"<meta name="twitter:image" content="#),
        ("canonical link", r#"<link rel="canonical" href="#),
    ];
    let mut absent = Vec::new();
    for (what, needle) in required {
        if !base.contains(needle) {
            absent.push(format!("{what}: no line containing {needle:?}"));
        }
    }
    assert!(
        absent.is_empty(),
        "website/templates/base.html is missing social-card metadata:\n  {}",
        absent.join("\n  ")
    );

    // og:url and canonical must be per-page, not the bare base_url — the
    // whole point of the pair is telling a crawler which URL this page is.
    for (what, tag) in [("og:url", "og:url"), ("canonical", r#"rel="canonical""#)] {
        let line = base
            .lines()
            .find(|l| l.contains(tag))
            .unwrap_or_else(|| panic!("no {what} line in base.html"));
        assert!(
            line.contains("current_path"),
            "{what} does not interpolate current_path, so every page on the \
             site declares the same URL: {line}"
        );
    }

    // og:image must name a file that ships. A 404 here is not a broken image
    // on the page — it is a card with no picture, which is only ever seen
    // somewhere else.
    let img_line = base
        .lines()
        .find(|l| l.contains(r#"property="og:image""#))
        .expect("no og:image line in base.html");
    let asset = regex::Regex::new(r#"content="[^"]*?/([A-Za-z0-9._-]+\.(?:png|jpg|jpeg|webp))""#)
        .unwrap()
        .captures(img_line)
        .unwrap_or_else(|| panic!("og:image names no image file: {img_line}"));
    let asset_path = repo().join("website/static").join(&asset[1]);
    assert!(
        asset_path.is_file(),
        "og:image points at /{} but website/static/{} does not exist — every \
         share of every page renders a card with a broken image",
        &asset[1],
        &asset[1]
    );

    // Both docs templates must feed their own description into both blocks.
    for (tpl, var) in [
        ("website/templates/page.html", "page.description"),
        ("website/templates/section.html", "section.description"),
    ] {
        let text = read(tpl);
        for block in ["description", "og_description"] {
            let line = text
                .lines()
                .find(|l| l.starts_with(&format!("{{% block {block} %}}")))
                .unwrap_or_else(|| {
                    panic!(
                        "{tpl} does not override `{block}`, so every page it \
                         renders publishes config.description as its summary"
                    )
                });
            assert!(
                line.contains(var),
                "{tpl}'s `{block}` block does not read {var}: {line}"
            );
        }
    }
}

/// Docs pages declare `og:type = article`, not the site-wide `website`.
///
/// `website` is right for the homepage, the download page and a section index;
/// a reference page is a document, and that is what tells an unfurler to
/// render it as one. The block defaults to `website` in `base.html` so a
/// template that says nothing keeps the old behavior, which means the
/// property lives in the override — check the override.
#[test]
fn docs_pages_declare_the_article_open_graph_type() {
    let base = read("website/templates/base.html");
    let default = regex::Regex::new(r"\{% block og_type %\}(\w+)\{% endblock og_type %\}")
        .unwrap()
        .captures(&base)
        .expect("base.html has no og_type block — og:type is hard-coded again");
    assert_eq!(
        &default[1], "website",
        "base.html's og_type default is {:?}; it must stay `website` so a \
         template that overrides nothing is unchanged",
        &default[1]
    );
    // page.html renders every page under website/content/docs/.
    let page = read("website/templates/page.html");
    let over = regex::Regex::new(r"\{% block og_type %\}(\w+)\{% endblock og_type %\}")
        .unwrap()
        .captures(&page)
        .expect(
            "website/templates/page.html does not override og_type, so every \
             docs page declares og:type=website",
        );
    assert_eq!(
        &over[1], "article",
        "page.html declares og:type={:?} for docs pages; expected `article`",
        &over[1]
    );
}

/// The Twitter card takes its title and text from the Open Graph fallback.
///
/// `base.html` deliberately carries no `twitter:title`/`twitter:description`:
/// X falls back to `og:title`/`og:description`, and Tera cannot render a block
/// twice, so a non-duplicating version is not expressible (the comment in
/// `base.html` records the build failure that proves it). Restating the values
/// would put the pair beside the templates that override `og_title` with a
/// literal, where the two copies drift apart silently.
///
/// So this is not a prohibition — it is the condition attached to adding them.
/// If the twitter pair ever appears, every template that overrides the og pair
/// must override the twitter pair too, or those pages ship a card that
/// disagrees with their own Open Graph tags.
#[test]
fn the_twitter_card_relies_on_the_open_graph_fallback() {
    let base = read("website/templates/base.html");
    assert!(
        base.contains(r#"<meta name="twitter:card" content="summary_large_image""#),
        "base.html declares no twitter:card, so nothing renders a card at all \
         and the og: fallback this test describes has nothing to fall back into"
    );

    // The templates the fallback actually depends on: every child that
    // replaces og_title or og_description with a value of its own.
    let mut overriders = Vec::new();
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name == "base.html" {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read template");
        if text.contains("{% block og_title %}") || text.contains("{% block og_description %}") {
            overriders.push((name, text));
        }
    }
    assert!(
        overriders.len() >= 3,
        "only {} template(s) override the og: pair (5 at the time of writing) \
         — the conditional below has no subjects and this gate is vacuous",
        overriders.len()
    );

    let has_tw_title = base.contains(r#"<meta name="twitter:title""#);
    let has_tw_desc = base.contains(r#"<meta name="twitter:description""#);
    if !(has_tw_title || has_tw_desc) {
        return; // the documented state: fallback only, nothing to keep in step
    }
    let mut unpaired = Vec::new();
    for (name, text) in &overriders {
        if has_tw_title
            && text.contains("{% block og_title %}")
            && !text.contains("{% block twitter_title %}")
        {
            unpaired.push(format!("{name}: overrides og_title but not twitter_title"));
        }
        if has_tw_desc
            && text.contains("{% block og_description %}")
            && !text.contains("{% block twitter_description %}")
        {
            unpaired.push(format!(
                "{name}: overrides og_description but not twitter_description"
            ));
        }
    }
    assert!(
        unpaired.is_empty(),
        "base.html now emits an explicit twitter: pair, so the og: fallback no \
         longer covers these templates and their cards disagree with their own \
         Open Graph tags:\n  {}",
        unpaired.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// Documentation-search journey: the docs landing page carries a Pagefind-backed
// search box. Three things have to hold at once for it to work on the live
// site, and each fails silently on its own:
//
//   1. The index does not exist unless a build step makes it. `zola build`
//      knows nothing about Pagefind and recreates its output directory from
//      scratch, so an index produced at the wrong moment is deleted by the
//      very build it was meant to describe.
//   2. Everything the box loads has to be same-origin. Production's CSP is
//      `script-src 'self'` with NO 'unsafe-inline' — a CDN would be blocked,
//      and so would an inline <script> whose sha256 is not in the Cloudflare
//      transform rule. That is how the homepage demos and feature tabs died
//      on 2026-07-22.
//   3. With JavaScript off it has to be ABSENT, not present-and-dead. An input
//      that accepts keystrokes and can never answer is worse than no input.
//
// All three return HTTP 200 when broken. Nothing a reader or a crawler sees
// distinguishes "search works" from "search box never appears".
// ---------------------------------------------------------------------------

/// `pages.yml` builds the search index from the rendered site, with a pinned Pagefind.
///
/// Order is the substance of this gate, not tidiness. `zola build` recreates
/// `website/public` from scratch, so an index written before it is deleted by
/// it; and `upload-pages-artifact` publishes that directory, so an index
/// written after the upload is never deployed. The step has to sit between the
/// two, and a workflow where it does not still goes green — it just publishes a
/// site whose search box never appears.
///
/// The version pin is checked the way every other hand-fetched binary in this
/// repository is: a tag names a release, it does not fix the bytes behind it.
#[test]
fn pages_workflow_indexes_the_built_site_with_a_pinned_pagefind() {
    let yaml = read(".github/workflows/pages.yml");

    let at = |needle: &str| -> usize {
        yaml.find(needle)
            .unwrap_or_else(|| panic!("pages.yml has no {needle:?} — the step was renamed"))
    };
    let build = at("- name: Build site");
    let index = at("- name: Index the site for search (Pagefind)");
    let upload = at("- name: Upload Pages artifact");
    assert!(
        build < index,
        "the Pagefind step runs BEFORE `zola build`, which recreates \
         website/public from scratch and deletes the index it just wrote"
    );
    assert!(
        index < upload,
        "the Pagefind step runs AFTER the Pages artifact upload, so the index \
         is built into a directory that has already been published without it"
    );

    let step = workflow_step_body(
        ".github/workflows/pages.yml",
        "Index the site for search (Pagefind)",
    );
    assert!(
        step.contains("pagefind --site website/public"),
        "the step does not index the directory Zola renders and \
         upload-pages-artifact publishes:\n{step}"
    );
    assert!(
        step.contains("sha256sum -c"),
        "the Pagefind download is installed without verifying its bytes:\n{step}"
    );
    assert!(
        step.contains("${PAGEFIND_VERSION}") && step.contains("${PAGEFIND_SHA256}"),
        "the download URL or the checksum is spelled out in the step instead of \
         reading the job's pins, so the two can disagree:\n{step}"
    );

    // The pin itself: a concrete version, not a moving tag. `latest`, `v1` and
    // an empty value all install "whatever is published today", which is the
    // property this asserts against.
    let version = regex::Regex::new(r"PAGEFIND_VERSION: '([^']+)'")
        .expect("regex")
        .captures(&yaml)
        .map(|c| c[1].to_string())
        .expect("pages.yml pins no PAGEFIND_VERSION");
    assert!(
        regex::Regex::new(r"^\d+\.\d+\.\d+$")
            .expect("regex")
            .is_match(&version),
        "PAGEFIND_VERSION is {version:?}, which is not an exact release. A \
         moving tag means the search index is built by a different binary on \
         every deploy, and nothing records which one produced the live index"
    );

    // The index is a build product and must be checked for, not assumed: a
    // Pagefind run that indexes nothing exits 0.
    assert!(
        step.contains("test -s website/public/pagefind/pagefind.js"),
        "nothing in the step fails when the index does not land. A missing \
         index is invisible from outside — the page still returns 200 and the \
         search box simply never appears:\n{step}"
    );
}

/// Every workflow that renders the site also indexes it, on the same pin.
///
/// `pages.yml` runs on push to `main`. If it is the only workflow that indexes,
/// a change that makes the index unbuildable is discovered by the deploy rather
/// than by the pull request — and the deploy is the run that publishes. The
/// quality job already renders the site for its link pass, so proving the index
/// still builds costs it one download.
///
/// This is written as a property over the workflow directory rather than as
/// "quality.yml also does it", so a THIRD workflow that starts building the
/// site cannot quietly ship a site with no search.
#[test]
fn every_workflow_that_builds_the_site_also_indexes_it() {
    let mut builders: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut pins: BTreeSet<String> = BTreeSet::new();
    // Built once: `clippy::regex_creation_in_loops` fires at `-D warnings`
    // under the pre-push flags (`--all-features --all-targets`), which the
    // pre-commit run does not use.
    let version_pin = regex::Regex::new(r"PAGEFIND_VERSION: '([^']+)'").expect("regex");

    for entry in std::fs::read_dir(repo().join(".github/workflows")).expect("workflows dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        let text = std::fs::read_to_string(&p).expect("read workflow");
        if !text.contains("run: zola build") {
            continue;
        }
        builders.push(name.clone());
        if !text.contains("pagefind --site website/public") {
            missing.push(name);
            continue;
        }
        for cap in version_pin.captures_iter(&text) {
            pins.insert(cap[1].to_string());
        }
    }

    assert!(
        builders.len() >= 2,
        "only {} workflow(s) run `zola build` — the scan stopped matching and \
         this gate is checking almost nothing: {builders:?}",
        builders.len()
    );
    assert!(
        missing.is_empty(),
        "these workflows render the site but never index it, so what they check \
         (and, for pages.yml, what they publish) is a site whose search box \
         never appears: {missing:?}"
    );
    assert_eq!(
        pins.len(),
        1,
        "the site-building workflows pin {} different Pagefind versions: {pins:?}. \
         One of them is checking an index built by a binary the other never runs",
        pins.len()
    );
}

/// The docs search loads nothing from an origin other than the site's own.
///
/// Production's `script-src 'self'` (no 'unsafe-inline', no CDN host) means a
/// `https://cdn.example/pagefind-ui.js` is not "slower", it is BLOCKED — the
/// box would render and never respond. The Pagefind runtime, its wasm and its
/// index chunks are therefore written into the site's own `/pagefind/` by the
/// build step, and the entry point named here is root-relative so it resolves
/// against whatever origin serves the page.
#[test]
fn docs_search_loads_only_same_origin_assets() {
    let js = read("website/static/js/docs-search.js");

    let entry = regex::Regex::new(r#"var PAGEFIND_JS = "([^"]*)";"#)
        .expect("regex")
        .captures(&js)
        .map(|c| c[1].to_string())
        .expect("docs-search.js names no PAGEFIND_JS entry point");
    assert!(
        entry.starts_with('/') && !entry.starts_with("//"),
        "the Pagefind entry point is {entry:?}. It must be root-relative: a \
         scheme-qualified or protocol-relative URL names an origin, and any \
         origin but the site's own is refused by `script-src 'self'`"
    );

    // Prose may cite a URL; code may not. Whole-line `//` comments are dropped
    // and the remainder must name no origin at all.
    let code: String = js
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("://"),
        "docs-search.js names an external origin in executable code. Under \
         `script-src 'self'` / `connect-src 'self'` that request is blocked, \
         and the box renders but never answers"
    );

    // And nothing in the templates may pull a script off another host either —
    // the search box's own script included. Every one goes through `get_url`,
    // which resolves against config.toml's base_url.
    let script_src = regex::Regex::new(r#"(?i)<script[^>]*\ssrc\s*=\s*"([^"]+)""#).expect("regex");
    let mut foreign = Vec::new();
    let mut seen = 0usize;
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = p.file_name().expect("name").to_string_lossy().to_string();
        let text = std::fs::read_to_string(&p).expect("read template");
        for cap in script_src.captures_iter(&text) {
            seen += 1;
            if cap[1].contains("://") {
                foreign.push(format!("{name}: {}", &cap[1]));
            }
        }
    }
    assert!(
        seen >= 3,
        "only {seen} `<script src=...>` tags found across the templates — the \
         extractor stopped matching and this half of the gate is vacuous"
    );
    assert!(
        foreign.is_empty(),
        "these templates load a script from a named origin rather than through \
         get_url; `script-src 'self'` blocks every one of them: {foreign:?}"
    );

    // The search box's script is one of those, and it must be external rather
    // than inline: an inline block only executes in production if its sha256 is
    // in the Cloudflare transform rule, which is regenerated from the DEPLOYED
    // html and therefore always one deploy behind a template edit.
    let section = read("website/templates/section.html");
    assert!(
        section.contains("get_url(path='js/docs-search.js', cachebust=true)"),
        "section.html no longer loads js/docs-search.js as an external, \
         cachebusted file"
    );
    // Same extraction semantics as refresh_csp_hashes.py and the PINNED gate:
    // a <script> is inline unless it carries `src=`. `regex` has no look-around,
    // and a hand-rolled negative match here would be the bug, not the check.
    let any_script = regex::Regex::new(r"(?is)<script([^>]*)>").expect("regex");
    let inline: Vec<String> = any_script
        .captures_iter(&section)
        .filter(|c| !c[1].contains("src=") && !c[1].contains("ld+json"))
        .map(|c| c[0].trim().to_string())
        .collect();
    assert!(
        inline.is_empty(),
        "section.html grew an inline <script>: {inline:?}. Production allows \
         inline blocks only by sha256, pinned in a rule refreshed from the \
         deployed HTML — so the first load after this deploy runs with it blocked"
    );
}

/// With JavaScript off the search box is absent, and the docs index is not.
///
/// The failure being excluded is a search box that renders, takes focus,
/// accepts every keystroke and can never answer — which is what shipping the
/// input visible would produce for a reader with scripting off, for a crawler,
/// and for any build of the site made without the Pagefind step. The box
/// therefore ships `hidden` and only the external script clears it, and only
/// after the engine has actually loaded.
///
/// The other half is what such a reader gets INSTEAD: the section template's
/// own "Reference" index, which lists the same pages a search would have
/// reached. Hiding the box would be no improvement if the fallback were also
/// behind JavaScript.
#[test]
fn docs_search_is_absent_rather_than_broken_without_javascript() {
    let section = read("website/templates/section.html");

    let box_tag = section
        .lines()
        .find(|l| l.contains(r#"id="doc-search""#))
        .unwrap_or_else(|| panic!("section.html renders no #doc-search container"))
        .to_string();
    assert!(
        box_tag.contains(" hidden"),
        "the #doc-search container does not ship `hidden`, so a reader with \
         scripting off — and a site built without the Pagefind step — is \
         served an input that swallows every keystroke:\n  {}",
        box_tag.trim()
    );

    // Only the script may reveal it, and it must do so from the branch that
    // runs after the engine resolved rather than unconditionally at load.
    let js = read("website/static/js/docs-search.js");
    assert!(
        js.contains("box.hidden = false"),
        "docs-search.js never reveals the box, so the search is dead even WITH \
         JavaScript"
    );
    let reveal = js.find("box.hidden = false").expect("checked above");
    let import = js
        .find("import(PAGEFIND_JS)")
        .expect("docs-search.js no longer imports the Pagefind entry point");
    assert!(
        import < reveal,
        "the box is revealed before the Pagefind import is even attempted, so a \
         site with no index shows a search box that can never answer"
    );

    // The no-JS fallback: rendered by Tera, not by script.
    assert!(
        section.contains(r#"<nav class="doc-index""#),
        "section.html no longer renders the documentation index, which is the \
         whole of what a reader without JavaScript gets in place of search"
    );
    let index_at = section
        .find(r#"<nav class="doc-index""#)
        .expect("checked above");
    assert!(
        section[..index_at].contains(r#"{% if section.pages | length > 0 %}"#),
        "the docs index is no longer guarded by `section.pages`; if it moved \
         behind anything else, check that a reader with scripting off still \
         gets it"
    );
}

/// Adding search did not reopen inline script execution or admit a new origin.
///
/// The reference policy in `website/static/_headers` is what a host honoring
/// that file enforces, and it is deliberately STRICTER than the meta tag in
/// base.html: no 'unsafe-inline' at all. The cheapest way to make a
/// third-party search widget work is to widen `script-src` — with
/// 'unsafe-inline' for its bootstrap, or with the CDN it is served from — and
/// either edit would go unnoticed, because widening a policy breaks nothing.
/// This holds the directive to `'self'` plus the wasm grant the analyzer
/// already needs, and `connect-src` to `'self'`, which is what makes the
/// Pagefind index chunks loadable and a remote index not.
#[test]
fn the_site_csp_grants_no_unsafe_inline_and_no_new_origin() {
    let headers = read("website/static/_headers");
    let policy = headers
        .lines()
        .find(|l| l.trim_start().starts_with("Content-Security-Policy:"))
        .expect("website/static/_headers carries no CSP line")
        .split_once(':')
        .expect("a header line has a colon")
        .1
        .to_string();

    let script_src = csp_directive(&policy, "script-src").expect("the CSP names script-src");
    assert!(
        !script_src.contains(&"'unsafe-inline'"),
        "the reference script-src regained 'unsafe-inline'. Anyone adopting \
         this file believes they copied the policy production enforces, while \
         actually running one under which an injected <script> executes: \
         script-src = {script_src:?}"
    );
    let allowed_script = ["'self'", "'wasm-unsafe-eval'"];
    let extra: Vec<&&str> = script_src
        .iter()
        .filter(|t| !allowed_script.contains(*t) && !t.starts_with("'sha256-"))
        .collect();
    assert!(
        extra.is_empty(),
        "script-src admits {extra:?} beyond {allowed_script:?}. The search \
         runtime is served from this site's own /pagefind/ precisely so that no \
         host has to be named here"
    );

    let connect_src = csp_directive(&policy, "connect-src").expect("the CSP names connect-src");
    assert_eq!(
        connect_src,
        vec!["'self'"],
        "connect-src is no longer 'self' alone. The search index is fetched \
         over it, and widening it is how a same-origin index quietly becomes a \
         request to somebody else's server"
    );

    // The meta tag is the enforceable layer on GitHub Pages, which cannot set
    // response headers. It grants 'unsafe-inline' by necessity (see base.html),
    // but it must not name a foreign origin either.
    let meta = meta_csp("website/templates/base.html");
    let meta_script = csp_directive(&meta, "script-src").expect("the meta CSP names script-src");
    let meta_extra: Vec<&&str> = meta_script
        .iter()
        .filter(|t| !t.starts_with('\'') && !t.starts_with("'sha256-"))
        .collect();
    assert!(
        meta_extra.is_empty(),
        "the meta CSP's script-src names the origin(s) {meta_extra:?}. A \
         browser enforces every delivered policy independently, so a host \
         named here and not in _headers is blocked in production anyway — the \
         only thing it buys is a page that works locally and not live"
    );
}

// ---------------------------------------------------------------------------
// Website Phase 3: the accessibility and performance gates.
//
// These three tests guard the WIRING, not the pages. The pages are checked by
// axe-core and Lighthouse in `.github/workflows/quality.yml`; what a Rust test
// can add is the property those two tools cannot check about themselves --
// that they are actually wired up, that they can actually fail, and that they
// are pointed at a page that actually rendered.
//
// The third of those is not hypothetical. Zola bakes absolute `config.base_url`
// URLs into every page, and `base.html`'s own `default-src 'self'` then blocks
// every one of them when the build is served from anywhere other than
// sipnab.com. The page still returns 200 and still renders its full HTML --
// with no stylesheet, no script and no images. Measured on 2026-08-28: axe
// reported ZERO violations on all five pages in that state, and Lighthouse
// scored the homepage 1.00 on performance with a 0.000 layout shift. Rebuilt
// with `--base-url http://127.0.0.1:1111`, the same five pages produced two
// genuine serious accessibility violations and a 0.11 layout shift on
// /download/. Both gates therefore assert the origin of the build they are
// about to measure, and `website_gates_measure_a_page_that_actually_rendered`
// holds the three places that port is written to the same value.
// ---------------------------------------------------------------------------

/// The port every part of the website test harness agrees on.
///
/// Written in four places -- the two `zola build --base-url` invocations in
/// `quality.yml`, `playwright.config.js`'s default `baseURL`, and every
/// `collect.url` in `e2e/lighthouserc.json` -- because each of those tools
/// reads its own configuration. Nothing but a test holds them together, and a
/// mismatch does not fail: it produces a measurement of an unstyled page.
const SITE_GATE_PORT: &str = "1111";

/// Both website gates exist in `quality.yml`, and each names a file that is
/// really on disk.
///
/// The failure this prevents is a job that looks present and runs nothing: a
/// step pointed at a spec file that was renamed, an `lhci` invocation whose
/// `--config` names a file that no longer exists (lhci then falls back to its
/// own defaults, which assert nothing at all and exit 0), or a
/// `continue-on-error` that turns a red step into a green job.
#[test]
fn quality_workflow_runs_the_accessibility_and_lighthouse_gates() {
    let yaml = read(".github/workflows/quality.yml");

    // Job keys, at the two-space indent `jobs:` entries use.
    for job in ["accessibility:", "lighthouse:"] {
        assert!(
            yaml.lines().any(|l| l == format!("  {job}")),
            ".github/workflows/quality.yml has no `{job}` job. The website's \
             accessibility and performance gates are not wired to anything, and \
             every page-level check they perform is unreachable"
        );
    }

    // The axe step must name the spec, and the spec must exist. A step running
    // `playwright test` with no path would run every spec in the directory,
    // which passes today and silently stops covering accessibility the moment
    // someone splits the file.
    let axe = workflow_step_body(
        ".github/workflows/quality.yml",
        "axe-core (WCAG 2 A/AA, serious + critical)",
    );
    assert!(
        axe.contains("tests/accessibility.spec.js"),
        "the axe step does not name e2e/tests/accessibility.spec.js:\n{axe}"
    );
    assert!(
        repo().join("e2e/tests/accessibility.spec.js").is_file(),
        "quality.yml runs e2e/tests/accessibility.spec.js and that file does not \
         exist -- the step fails, or worse, matches nothing and reports success"
    );

    // The Lighthouse step must name the config, and the config must exist.
    let lh = workflow_step_body(".github/workflows/quality.yml", "Lighthouse budgets");
    assert!(
        lh.contains("--config=lighthouserc.json"),
        "the Lighthouse step does not pass --config=lighthouserc.json. Without \
         it lhci searches for a config and, finding none, asserts NOTHING and \
         exits 0:\n{lh}"
    );
    assert!(
        repo().join("e2e/lighthouserc.json").is_file(),
        "quality.yml runs `lhci autorun --config=lighthouserc.json` from e2e/ \
         and that file does not exist. lhci reports the missing config and the \
         budgets stop being enforced"
    );

    // Neither runner step may be conditional or forgiving. `assert_step_enforces`
    // wants an `exit 1` in the body, which a `run: npx ...` step does not have,
    // so the two properties that do apply are checked directly here.
    for (name, body) in [
        ("axe-core (WCAG 2 A/AA, serious + critical)", &axe),
        ("Lighthouse budgets", &lh),
    ] {
        assert!(
            !body.contains("continue-on-error"),
            "quality.yml step {name:?} carries continue-on-error, which rewrites \
             its conclusion to success: the gate runs and its verdict is thrown away"
        );
        assert!(
            !body.lines().any(|l| l.trim_start().starts_with("if:")),
            "quality.yml step {name:?} gained an `if:` guard. A guard is how a \
             gate stops running without its body changing:\n{body}"
        );
    }
}

/// Every Lighthouse budget is a number somebody measured, not a number somebody
/// hoped for.
///
/// `e2e/lighthouserc.json` carries a `_measured` block -- provenance as data,
/// because JSON has no comments -- recording the date, the commit, how the
/// collection was run, and the WORST value observed across three runs for each
/// audit. This test pairs that block against `ci.assert`: every threshold must
/// have a measurement, and must sit on the permissive side of it.
///
/// Two failures it exists for. A budget added without measuring is one nobody
/// can size, and the usual outcome is a round number that either never fires or
/// fires on the commit that adds it. A budget RELAXED past its measurement is
/// the quieter one: moving `largest-contentful-paint` from 2000 to 8000 makes a
/// red build green and leaves a gate that reads as if it still enforces
/// something.
///
/// It also rejects `warn`. lhci accepts `["warn", {...}]`, which prints the
/// violation and exits 0 -- the same shape as `continue-on-error`, and just as
/// invisible in a green check.
#[test]
fn lighthouse_budgets_are_measured_not_aspirational() {
    let raw = read("e2e/lighthouserc.json");
    let rc: serde_json::Value =
        serde_json::from_str(&raw).expect("e2e/lighthouserc.json is not valid JSON");

    // Provenance. Without it the numbers below are unattributable, and the
    // pairing this test performs has nothing to pair against.
    let measured = &rc["_measured"];
    let date = measured["date"].as_str().unwrap_or_default();
    assert!(
        date.len() == 10 && date.starts_with("20") && date.matches('-').count() == 2,
        "e2e/lighthouserc.json `_measured.date` is {date:?}, not an ISO date. \
         A budget whose measurement has no date cannot be judged stale"
    );
    let commit = measured["commit"].as_str().unwrap_or_default();
    assert!(
        commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit()),
        "e2e/lighthouserc.json `_measured.commit` is {commit:?}, not a full \
         40-character SHA. An abbreviation stops resolving once the repository \
         grows, which is exactly when someone wants to re-derive the baseline"
    );

    let worst = &measured["worst"];
    assert!(
        worst.is_object(),
        "e2e/lighthouserc.json has no `_measured.worst` map, so no threshold \
         below can be shown to have come from a measurement"
    );

    // Walk every assertion in the matrix.
    let matrix = rc["ci"]["assert"]["assertMatrix"]
        .as_array()
        .expect("e2e/lighthouserc.json has no ci.assert.assertMatrix array");
    assert!(
        !matrix.is_empty(),
        "ci.assert.assertMatrix is empty -- lhci asserts nothing and exits 0"
    );
    assert!(
        rc["ci"]["assert"]["preset"].is_null(),
        "ci.assert names a `preset`. A preset substitutes Lighthouse's own \
         default assertions for the measured ones in this file, so the budgets \
         recorded in `_measured` stop being what is enforced"
    );

    let mut checked = 0usize;
    let mut unmeasured: Vec<String> = Vec::new();
    let mut relaxed: Vec<String> = Vec::new();

    for entry in matrix {
        let pattern = entry["matchingUrlPattern"]
            .as_str()
            .expect("every assertMatrix entry needs a matchingUrlPattern");
        let assertions = entry["assertions"]
            .as_object()
            .unwrap_or_else(|| panic!("assertMatrix entry {pattern:?} has no assertions map"));

        for (audit, spec) in assertions {
            let pair = spec.as_array().unwrap_or_else(|| {
                panic!("{audit} under {pattern:?} is not a [level, options] pair: {spec}")
            });
            assert_eq!(
                pair[0].as_str(),
                Some("error"),
                "{audit} under {pattern:?} is asserted at level {:?}. Only \
                 `error` fails the build; `warn` prints the violation and exits \
                 0, and `off` does not even print it",
                pair[0]
            );

            let opts = pair[1]
                .as_object()
                .unwrap_or_else(|| panic!("{audit} under {pattern:?} carries no options object"));
            let min_score = opts.get("minScore").and_then(serde_json::Value::as_f64);
            let max_numeric = opts
                .get("maxNumericValue")
                .and_then(serde_json::Value::as_f64);
            assert!(
                min_score.is_some() || max_numeric.is_some(),
                "{audit} under {pattern:?} sets neither minScore nor \
                 maxNumericValue, so it asserts nothing: {spec}"
            );
            checked += 1;

            // The measurement this threshold was derived from. Either a bare
            // number (the audit behaves the same on every page) or a map keyed
            // by path (it does not).
            let record = &worst[audit.as_str()];
            let observed = if record.is_number() {
                record.as_f64()
            } else if record.is_object() {
                // A per-page map under a catch-all pattern names no page in
                // particular, so there is no measurement to pair with. Reject
                // it rather than pick one and call the budget measured.
                assert_ne!(
                    pattern, ".*",
                    "{audit} is asserted for every URL but its measurement in \
                     `_measured.worst` is recorded per page. One of the two is \
                     wrong, and pairing them would mean choosing a page at random"
                );
                // The longest path the pattern's text contains wins:
                // "/docs/tui/" also contains "/docs/" and "/".
                record
                    .as_object()
                    .expect("checked is_object")
                    .iter()
                    .filter(|(path, _)| pattern.contains(path.as_str()))
                    .filter_map(|(path, v)| v.as_f64().map(|f| (path.len(), f)))
                    .max_by_key(|(len, _)| *len)
                    .map(|(_, v)| v)
            } else {
                None
            };

            let Some(observed) = observed else {
                unmeasured.push(format!("{audit} under {pattern:?}"));
                continue;
            };

            if let Some(budget) = max_numeric
                && budget < observed
            {
                relaxed.push(format!(
                    "{audit} under {pattern:?}: budget {budget} is BELOW the \
                     measured {observed}, so this gate is red on the commit \
                     that adds it"
                ));
            }
            if let Some(floor) = min_score
                && floor > observed
            {
                relaxed.push(format!(
                    "{audit} under {pattern:?}: floor {floor} is ABOVE the \
                     measured {observed}, so this gate is red on the commit \
                     that adds it"
                ));
            }
        }
    }

    assert!(
        unmeasured.is_empty(),
        "these Lighthouse budgets have no entry in `_measured.worst`, so nothing \
         records what they were derived from -- a threshold nobody measured is a \
         guess, and a guess is either unenforceable or already failing:\n  {}",
        unmeasured.join("\n  ")
    );
    assert!(
        relaxed.is_empty(),
        "these Lighthouse budgets contradict the measurement recorded beside \
         them:\n  {}",
        relaxed.join("\n  ")
    );
    // A walk that visits nothing reports a clean bill of health. 20 is under
    // the 21 the file carried when this test was written; the point is that the
    // matrix cannot be gutted to one token assertion while this stays green.
    assert!(
        checked >= 20,
        "only {checked} Lighthouse assertions were checked. The matrix was \
         emptied, or the walk stopped seeing it -- either way a pass here means \
         nothing"
    );
}

/// The three configurations that decide WHICH page gets measured agree on one
/// origin.
///
/// Zola renders every internal URL as an absolute `config.base_url` URL. Served
/// anywhere other than `https://sipnab.com`, `base.html`'s `default-src 'self'`
/// blocks the stylesheet, the script and every image as cross-origin, and the
/// page renders with no CSS at all. It still returns 200. It still contains all
/// of its text. axe finds nothing wrong with it, because a page with no
/// computed colors has no contrast to fail and no `overflow-x: auto` to make a
/// region unreachable; Lighthouse scores it 100, because nothing loaded.
///
/// So the build's `--base-url`, Playwright's `baseURL`, and Lighthouse's
/// `collect.url` all have to name the same origin, and each of the three lives
/// in a different file that the other two never read. This test is the only
/// thing holding them together -- and a mismatch does not fail loudly, it
/// produces a green run measuring an unstyled document.
#[test]
fn website_gates_measure_a_page_that_actually_rendered() {
    let yaml = read(".github/workflows/quality.yml");
    let expected_origin = format!("http://127.0.0.1:{SITE_GATE_PORT}");

    // 1. Both jobs build the site for the origin they serve it from.
    let builds: Vec<&str> = yaml
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("run: zola build"))
        .collect();
    let local_builds: Vec<&&str> = builds.iter().filter(|l| l.contains("--base-url")).collect();
    assert!(
        local_builds.len() >= 2,
        "quality.yml has {} `zola build --base-url ...` step(s); the \
         accessibility job and the Lighthouse job each need one. Without it the \
         site is built for https://sipnab.com and measured on 127.0.0.1, which \
         is a measurement of a page whose own CSP blocked its stylesheet:\n  {}",
        local_builds.len(),
        builds.join("\n  ")
    );
    for line in &local_builds {
        assert!(
            line.contains(&expected_origin),
            "a website gate builds with {line:?}, which is not {expected_origin}. \
             The server it is then measured on serves that origin, so its assets \
             are cross-origin and blocked"
        );
    }

    // 2. Both jobs refuse to measure a build that still points at production.
    // These steps carry `exit 1` after an `::error::`, so the shared helper's
    // full set of properties applies.
    for step in [
        "The built site references its own origin, not production",
        "The built site references its own origin, not production (lighthouse)",
    ] {
        assert_step_enforces(".github/workflows/quality.yml", step, None);
        let body = workflow_step_body(".github/workflows/quality.yml", step);
        assert!(
            body.contains("sipnab") && body.contains("style") && body.contains("grep"),
            "{step:?} no longer greps the built HTML for the origin of its own \
             stylesheet, which is the one cheap signal that separates a styled \
             page from an unstyled one:\n{body}"
        );
        assert!(
            body.contains(SITE_GATE_PORT),
            "{step:?} does not mention port {SITE_GATE_PORT}, so it is checking \
             for an origin nothing serves:\n{body}"
        );
    }

    // 3. Playwright's default base URL uses the same port.
    let pw = read("e2e/playwright.config.js");
    assert!(
        pw.contains(&expected_origin),
        "e2e/playwright.config.js does not default to {expected_origin}. The \
         accessibility job builds the site for that origin and then lets \
         Playwright start its own server; if the two disagree the run measures \
         a page whose assets were all blocked"
    );

    // 4. Every Lighthouse collect URL uses the same port, and the static server
    // it starts serves on it too.
    let rc: serde_json::Value = serde_json::from_str(&read("e2e/lighthouserc.json"))
        .expect("e2e/lighthouserc.json is not valid JSON");
    let urls = rc["ci"]["collect"]["url"]
        .as_array()
        .expect("e2e/lighthouserc.json has no ci.collect.url array");
    assert!(
        !urls.is_empty(),
        "ci.collect.url is empty -- lhci measures nothing and asserts over nothing"
    );
    for u in urls {
        let u = u.as_str().unwrap_or_default();
        assert!(
            u.starts_with(&expected_origin),
            "Lighthouse collects {u:?}, which is not on {expected_origin}. The \
             site is built for that origin, so anything else measures a page \
             with no CSS -- and scores it 100"
        );
    }
    let server = rc["ci"]["collect"]["startServerCommand"]
        .as_str()
        .expect("e2e/lighthouserc.json has no ci.collect.startServerCommand");
    assert!(
        server.contains(SITE_GATE_PORT),
        "Lighthouse starts its server with {server:?}, which does not serve port \
         {SITE_GATE_PORT}. Its collect URLs point there and would find nothing"
    );
    assert!(
        server.contains("website/public"),
        "Lighthouse serves {server:?} rather than the directory `zola build` \
         renders. It would measure whatever else is in that path"
    );

    // 5. The axe spec still gates on the ruleset and the severities it
    // documents. Narrowing `WCAG_TAGS` to `['wcag2a']` or `BLOCKING_IMPACTS` to
    // `['critical']` halves the gate while every test in that file keeps
    // passing, so the DECLARATIONS are pinned here.
    //
    // Whitespace-stripped and matched against the declaration, not against the
    // file. The first version of this check looked for the substring
    // `'wcag2aa'` anywhere in the spec -- and the spec's own header comment
    // explains the ruleset in prose, so dropping wcag2aa from the constant left
    // the string behind in the comment and this test went on passing. That was
    // caught by mutating it; the lesson is that a gate reading prose is not
    // reading the code.
    let spec = read("e2e/tests/accessibility.spec.js");
    let code: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
    for decl in [
        "constWCAG_TAGS=['wcag2a','wcag2aa'];",
        "constBLOCKING_IMPACTS=['serious','critical'];",
        "constINCOMPLETE_NOT_GATED=['color-contrast'];",
    ] {
        assert!(
            code.contains(decl),
            "e2e/tests/accessibility.spec.js no longer declares `{decl}` \
             (whitespace ignored). The gate's ruleset, its severity floor or its \
             one incomplete-rule exemption changed, and the page tests in that \
             file would keep passing while covering less"
        );
    }
    // The `incomplete` bucket is GATED, not merely printed. Dropping that is how
    // `aria-prohibited-attr` -- the one real defect the first run of this gate
    // found -- would have gone unreported, because axe returns it as undecided
    // rather than as a violation.
    //
    // Pinned to the expression that builds the blocking set, not to the string
    // `results.incomplete.filter`. That substring appears TWICE in the spec: once
    // here and once where the advisory list is assembled for printing. Replacing
    // this one with `[]` left the other in place, and the first version of this
    // check went on passing -- the same mutation-caught mistake as the ruleset
    // check above, one occurrence further along.
    for gating in [
        "constundecided=results.incomplete.filter((v)=>BLOCKING_IMPACTS.includes(v.impact)&&!INCOMPLETE_NOT_GATED.includes(v.id)",
        "return[...violations,...undecided];",
    ] {
        assert!(
            code.contains(gating),
            "e2e/tests/accessibility.spec.js no longer folds axe's `incomplete` \
             results into the set that fails a page (looking for `{gating}`, \
             whitespace ignored). Every rule axe cannot decide would pass silently, \
             and the four page tests would stay green while covering less"
        );
    }
}

// ---------------------------------------------------------------------------
// The lead demo panel: one capture, read end to end.
//
// The homepage used to open on a single failed INVITE — `stream_count: 0`, no
// media, no registration, no hangup — which is a poor first frame for a tool
// whose whole claim is seeing a call end to end. The lead panel now publishes
// two answers from one capture: the dialog list (the REGISTER, the OPTIONS
// keepalive, the subscriptions and the call) and the INVITE's ladder (three
// RTP streams, and the BYE that ended it).
//
// Two failure modes are worth a gate of their own:
//
// 1. A regenerated example that quietly lost one of the four things the panel
//    is FOR. The prose promises a lifecycle; a capture swap that drops the
//    OPTIONS leaves the prose lying and every file agreeing with every other.
// 2. A half-loaded answer. sipnab loads a capture in the BACKGROUND while the
//    MCP server is already answering, so a call issued straight after
//    `initialize` is answered from whatever has been parsed so far. Measured
//    on this capture: three runs out of three of the pre-poll
//    `demos/mcp-stdio.sh` rendered the INVITE as `Result: In Progress` with
//    the 200 and the BYE missing from a call that had both. That answer is
//    WRONG rather than merely short, and it looks entirely plausible on a
//    page.
// ---------------------------------------------------------------------------

/// One published example block: where it sits on the page, and what it says.
///
/// Returns the byte range of the whole marker pair together with the block's
/// content, HTML-unescaped so it can be compared against the generated file.
/// `&amp;` is undone LAST: doing it first would turn a literal `&amp;lt;` in
/// the data into `<` and compare equal to the wrong thing.
fn published_example_block(page: &str, name: &str) -> (Span, String) {
    let begin = format!("<!-- mcp-example:{name} BEGIN -->");
    let end = format!("<!-- mcp-example:{name} END -->");
    let open = page
        .find(&begin)
        .unwrap_or_else(|| panic!("index.html has no {begin} — run demos/gen-mcp-examples.sh"));
    let close = page
        .find(&end)
        .unwrap_or_else(|| panic!("index.html has no {end} — run demos/gen-mcp-examples.sh"));
    assert!(
        close > open,
        "{name}: END marker precedes BEGIN in index.html"
    );
    let body = page[open + begin.len()..close]
        .trim_matches('\n')
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    (
        Span {
            start: open,
            end: close + end.len(),
        },
        body,
    )
}

/// Every example block on the page is spliced in from a generated file, and
/// every generated file reaches the page.
///
/// The equality test earlier in this file names four files by hand and parses
/// each block as one JSON document. Neither holds for the lead panel: the
/// dialog list is a JSON-LINES stream (`jq -c`, one object per line, five
/// lines instead of sixty) and the ladder is a drawn report. This enumerates
/// the DIRECTORY instead, so an example added without a marker pair fails
/// here rather than generating happily into a file the page never reads.
///
/// Both directions matter. File-without-marker is an example that reports "ok"
/// from `demos/gen-mcp-examples.sh --check` while the page shows whatever it
/// showed before; marker-without-file is a hand-written block, which is the
/// marketing-screenshot failure the whole chain exists to prevent.
#[test]
fn every_published_mcp_example_comes_from_its_generated_file() {
    let page = read("website/templates/index.html");
    let dir = repo().join("website/data/mcp-examples");

    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("website/data/mcp-examples must exist") {
        let path = entry.expect("dir entry").path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_stem()
            .expect("file stem")
            .to_string_lossy()
            .to_string();
        let generated = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let (_, published) = published_example_block(&page, &name);
        assert_eq!(
            published,
            generated.trim_end_matches('\n'),
            "the {name} block on the homepage is not {}. Regenerate with \
             `demos/gen-mcp-examples.sh` rather than editing the page.",
            path.display()
        );
        on_disk.insert(name);
    }

    // Anti-vacuity: an empty directory would make the loop above prove nothing.
    // The two the lead panel is built from are named because losing either one
    // is the regression this whole section exists to catch.
    for want in ["lifecycle", "ladder"] {
        assert!(
            on_disk.contains(want),
            "website/data/mcp-examples has no {want} example, so the lead \
             demo panel has no generated source: found {on_disk:?}"
        );
    }

    let marker = regex::Regex::new(r"<!-- mcp-example:([a-z0-9-]+) BEGIN -->").unwrap();
    let on_page: BTreeSet<String> = marker
        .captures_iter(&page)
        .map(|c| c[1].to_string())
        .collect();
    assert_eq!(
        on_page, on_disk,
        "the example blocks on the homepage and the files in \
         website/data/mcp-examples name different sets. A block with no file \
         is hand-written; a file with no block never reaches a reader."
    );
}

/// The lead panel shows all four stages of a call's life, without a click.
///
/// Each fact is taken from the PUBLISHED DATA rather than from a string
/// spelled out here, so regenerating the examples from a capture that lacks a
/// registration, a keepalive, media or a hangup fails this test instead of
/// quietly shipping a lifecycle panel with no lifecycle in it. The method
/// names below are the requirement, not the data: they are what the panel
/// promises a reader.
#[test]
fn the_lead_demo_panel_shows_a_whole_call_lifecycle() {
    let page = read("website/templates/index.html");
    let lead = element_span(&page, "<div class=\"demo-panel active\"", "div");

    let (dialog_span, dialogs) = published_example_block(&page, "lifecycle");
    let (ladder_span, ladder) = published_example_block(&page, "ladder");
    for (what, span) in [("lifecycle", &dialog_span), ("ladder", &ladder_span)] {
        assert!(
            lead.start < span.start && span.end <= lead.end,
            "the {what} example is published outside the lead demo panel, so a \
             visitor has to click to reach it"
        );
    }

    // The fleet view: one row per dialog, keyed by the method it carries.
    let mut rows: BTreeMap<String, String> = BTreeMap::new();
    for line in dialogs.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("published dialog row is not JSON: {e}\n{line}"));
        let method = row["method"]
            .as_str()
            .unwrap_or_else(|| panic!("published dialog row has no method: {line}"))
            .to_string();
        rows.entry(method).or_insert_with(|| line.to_string());
    }
    for method in ["REGISTER", "OPTIONS", "INVITE"] {
        assert!(
            rows.contains_key(method),
            "the published dialog list has no {method}, which the lead panel's \
             prose promises. Regenerate from a capture that contains one, or \
             change the prose — found {:?}",
            rows.keys().collect::<Vec<_>>()
        );
    }
    let invite = &rows["INVITE"];
    let invite_row: serde_json::Value = serde_json::from_str(invite).expect("checked above");
    assert!(
        invite_row["msg_count"].as_u64().unwrap_or(0) > 2,
        "the published INVITE carries {} messages — an INVITE and one reply is \
         not a call anyone can follow: {invite}",
        invite_row["msg_count"]
    );

    // The call itself: media beside the signaling, and the hangup.
    let streams: Vec<&str> = ladder
        .lines()
        .filter(|l| l.trim_start().starts_with("RTP "))
        .collect();
    assert!(
        !streams.is_empty(),
        "the published ladder shows no RTP stream, so the lead panel's INVITE \
         has no media on it:\n{ladder}"
    );
    assert!(
        ladder.lines().any(|l| l.trim_start().starts_with("BYE ->")),
        "the published ladder shows no BYE transaction, so the call the lead \
         panel shows never ends:\n{ladder}"
    );
}

/// The lifecycle panel is the one a visitor sees first — no click, no arrow key.
///
/// `homepage_demo_wall_leads_with_outcomes` pins WHICH tabs are visible and in
/// what order. This pins which panel is actually PAINTED on first load, which
/// is a different fact carried by different markup: `class="demo-panel active"`
/// and `class="demo-tab active"`, either of which can be left on the wrong
/// element by an edit that reorders the wall.
#[test]
fn the_lifecycle_panel_is_the_one_a_visitor_sees_first() {
    let page = read("website/templates/index.html");

    let actives = page.matches("class=\"demo-panel active\"").count();
    assert_eq!(
        actives, 1,
        "exactly one demo panel may ship active; {actives} do, so first paint \
         shows either nothing or two panels at once"
    );
    let lead = element_span(&page, "<div class=\"demo-panel active\"", "div");
    // `[ "]` and not a bare prefix: the panels sit inside `<div
    // class="demo-panels">`, whose open tag matches `<div class="demo-panel`
    // and is 500 bytes earlier than any panel.
    let first_panel = regex::Regex::new(r#"<div class="demo-panel[ "]"#)
        .unwrap()
        .find(&page)
        .expect("index.html has no demo panels at all")
        .start();
    assert_eq!(
        first_panel, lead.start,
        "the active demo panel is not the first one in the document; a reader \
         with CSS off, or a crawler, gets the wall in the wrong order"
    );
    let lead_markup = &page[lead.start..lead.end];
    assert!(
        lead_markup.contains("id=\"demo-panel-0\""),
        "the active panel is not demo-panel-0, so the tab wiring (which reads \
         a tab's index off its own id) selects a different panel than the one \
         painted on load"
    );
    for name in ["lifecycle", "ladder"] {
        assert!(
            lead_markup.contains(&format!("<!-- mcp-example:{name} BEGIN -->")),
            "the panel a visitor sees first no longer carries the {name} \
             example — the whole-call demo is not what leads any more"
        );
    }

    let first_tab_at = page
        .find("<button class=\"demo-tab")
        .expect("index.html has no demo tabs at all");
    let first_tab = element_open_tag(&page[first_tab_at..], "<button class=\"demo-tab");
    assert!(
        first_tab.contains("class=\"demo-tab active\"")
            && first_tab.contains("aria-selected=\"true\"")
            && first_tab.contains("aria-controls=\"demo-panel-0\""),
        "the first tab must be the selected one and must control the panel \
         that ships active, or the strip lights one demo while showing \
         another: {first_tab}"
    );
}

/// The published ladder came from a capture that had FINISHED loading.
///
/// This is the guard against the load race, and the most valuable of the four.
/// sipnab parses a capture in the background while the MCP server answers, so
/// an answer taken too early is complete-looking and wrong: measured three
/// times out of three on this capture, the INVITE rendered `Result: In
/// Progress` with 8 of its 13 messages, no 200 and no BYE.
/// `demos/mcp-stdio.sh` now polls `capture_status.source_exhausted` before it
/// makes the real call; this proves the output on the page came from after
/// that poll.
///
/// The two blocks are generated by two SEPARATE runs of the server, which is
/// what makes the last assertion worth making: the dialog list's
/// `duration_sec` and the ladder's final transaction offset are the same
/// measurement taken twice, so a run that raced disagrees with one that did
/// not.
#[test]
fn the_published_ladder_shows_a_settled_capture() {
    let page = read("website/templates/index.html");
    let (_, dialogs) = published_example_block(&page, "lifecycle");
    let (_, ladder) = published_example_block(&page, "ladder");

    let result = ladder
        .lines()
        .find(|l| l.starts_with("Result:"))
        .unwrap_or_else(|| panic!("the published ladder has no Result line:\n{ladder}"));
    for in_flight in ["In Progress", "InCall", "Ringing", "Trying", "Proceeding"] {
        assert!(
            !result.contains(in_flight),
            "the published ladder reads {result:?} — that is a call still in \
             flight, which means the answer was taken before the capture had \
             been read to its end. Regenerate; do not hand-edit."
        );
    }

    let invite: serde_json::Value = dialogs
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|row| row["method"] == "INVITE")
        .unwrap_or_else(|| panic!("the published dialog list has no INVITE:\n{dialogs}"));
    let state = invite["state"]
        .as_str()
        .unwrap_or_else(|| panic!("the published INVITE has no state: {invite}"));
    assert_eq!(
        state, "Completed",
        "the published INVITE is {state:?}, not Completed — the fleet view was \
         taken from a half-loaded capture"
    );
    assert!(
        result.contains(state),
        "the dialog list calls the INVITE {state:?} and the ladder says \
         {result:?}. Two runs of the same tool over the same file disagree, \
         which is what a load race looks like."
    );
    assert!(
        result.contains("BYE"),
        "the published ladder's verdict is {result:?} — a settled read of this \
         call ends on its BYE"
    );

    let offsets = regex::Regex::new(r"\((\d+)ms\)").unwrap();
    let last_ms = offsets
        .captures_iter(&ladder)
        .filter_map(|c| c[1].parse::<f64>().ok())
        .fold(f64::MIN, f64::max);
    let duration_ms = invite["duration_sec"]
        .as_f64()
        .unwrap_or_else(|| panic!("the published INVITE has no duration_sec: {invite}"))
        * 1000.0;
    assert!(
        (last_ms - duration_ms).abs() < 1.0,
        "the ladder's last transaction lands at {last_ms}ms and the dialog \
         list calls the call {duration_ms}ms long. The two blocks come from \
         separate runs of the server, so they only agree when both read the \
         whole capture."
    );
}
