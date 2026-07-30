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
/// This is the only assertion here that tests the behaviour rather than the
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

/// The Zola config version (homepage badge, download links) equals the Cargo.toml crate version.
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

/// The download page's release date matches the CHANGELOG entry it describes.
///
/// `release_date` had no gate at all and had drifted two days behind the
/// 0.5.44 CHANGELOG heading — the version beside it was gated, the date next
/// to it was not, so /download advertised the right version on the wrong day.
#[test]
fn site_release_date_matches_changelog() {
    let cfg = read("website/config.toml");
    let site_v = regex::Regex::new(r#"(?m)^version = "([^"]+)""#)
        .unwrap()
        .captures(&cfg)
        .expect("config.toml version")[1]
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
#[test]
fn site_advertises_only_a_released_version() {
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
        // binary cannot honour: rustc will not emit code for an older OS than it
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
    for (count, suffix) in [("2.06", "M pkts/s"), ("11.1", "&times; sngrep")] {
        let tile = format!(r#"data-count="{count}" data-suffix="{suffix}""#);
        assert!(
            idx.contains(&tile),
            "homepage tile {count}{suffix} is gone or changed; if it was re-measured, \
             update this gate and the benchmarks page together"
        );
        // The figure itself must be findable on the page the tile links to.
        let cell = format!("{count}M");
        let ratio = format!("{count}×");
        // In a TABLE ROW, not anywhere in the file — the comment two lines up
        // already says "the string that must appear in a table row". A
        // re-measured figure quoted in prose ("down from the 2.06M this page
        // reported on 0.5.47") satisfied a whole-file substring while the
        // tile and the table disagreed.
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
    }

    assert!(
        idx.contains(&format!("(measured v{measured})")),
        "homepage tiles do not say they were measured on v{measured}, the release \
         the benchmarks page names — an undated throughput claim silently ages"
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
            // an acknowledgement gate for template edits.
            "index.html",
            "sha256-du3YYx2OY3UxQaGAjCIEIChqOcWygleJKR+ySMRn/WA=",
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
        "the swap must honour prefers-reduced-motion — the animation loops \
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
        const ROOTS: [&str; 12] = [
            ".vale/",
            "packaging/",
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
        const NOT_PATH_ROOTS: [&str; 9] = [
            "docker/",  // collides with the docker/* GitHub Actions namespace
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
            const GENERATED: [&str; 3] = ["website/public", "build/", "target/"];
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
    assert_eq!(
        checked, 56,
        "packaging path scan saw {checked} references, expected 56. More is \
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
