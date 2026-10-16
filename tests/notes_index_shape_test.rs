// SPDX-License-Identifier: MIT OR Apache-2.0

//! The notes index lists what a reader came for, and only that.
//!
//! `website/content/notes/` holds two kinds. How-tos say how to do a job and
//! feature notes say what a capability does. The index and the notes sidebar
//! render one group for each, how-tos first. The engineering record of what
//! went wrong in sipnab is not a note: it lives in
//! `docs/internals/postmortems.md`.
//!
//! This file holds that arrangement, and holds the failure it introduces:
//! filtering the list by kind means a note whose kind is not one of the two
//! renders NOWHERE. It would not 404 and it would not warn — it would simply
//! be missing from the index while its own page still built, which is the kind
//! of absence nobody notices.

use std::path::{Path, PathBuf};

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    let p = repo().join(rel);
    Ok(std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))?)
}

const TEMPLATE: &str = "website/templates/notes.html";

/// The kinds the index template renders a group for, in the order it renders
/// them.
const RENDERED_KINDS: &[&str] = &["howto", "feature"];

/// Every note's `kind`, with the file it came from.
fn note_kinds() -> Result<Vec<(String, String)>, TestError> {
    let dir = repo().join("website/content/notes");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| format!("read website/content/notes: {e}"))?
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "md") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "_index.md" {
            continue; // the section itself, not a note
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        let kind = body
            .lines()
            .find_map(|l| l.trim().strip_prefix("kind = "))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default();
        out.push((name, kind));
    }
    out.sort();
    Ok(out)
}

/// The index renders one open group per kind, how-tos first, and no archive.
///
/// The section once carried a third kind, post-mortems, collapsed behind a
/// `<details>`. That record moved to `docs/internals/postmortems.md`. A
/// disclosure left in the template would render an empty archive heading, or
/// collapse whatever kind was next put inside it.
#[test]
fn the_index_renders_each_kind_open_and_in_order() -> Result<(), TestError> {
    let tpl = read(TEMPLATE)?;
    let markup = strip_tera_comments(&tpl)?;
    assert!(
        !markup.contains("<details"),
        "{TEMPLATE} still has a disclosure; every group on the notes index \
         renders open"
    );
    assert!(
        !markup.contains("postmortem"),
        "{TEMPLATE} still selects post-mortems, a kind no note uses"
    );
    let mut last = 0usize;
    for kind in RENDERED_KINDS {
        let at = markup
            .find(&format!("value=\"{kind}\""))
            .ok_or_else(|| format!("{TEMPLATE} renders no group for {kind:?}"))?;
        assert!(
            at >= last,
            "the {kind} group renders before the group listed ahead of it in \
             RENDERED_KINDS; how-tos come first"
        );
        last = at;
    }
    Ok(())
}

/// The template with every Tera comment removed, so a gate reads markup and
/// not the prose that explains it.
fn strip_tera_comments(tpl: &str) -> Result<String, TestError> {
    let comment = regex::Regex::new(r"(?s)\{#.*?#\}")?;
    Ok(comment.replace_all(tpl, "").into_owned())
}

/// Every note has a kind the index actually renders.
///
/// The failure the split introduces. The template selects by kind, so a note
/// written with `kind = "reference"` — a value the stylesheet already has a
/// color for — renders in no group at all. Its own page builds, its link
/// resolves from the sidebar, and it is absent from the index with nothing
/// saying so.
#[test]
fn every_note_has_a_kind_the_index_renders() -> Result<(), TestError> {
    let notes = note_kinds()?;
    assert!(
        notes.len() >= 10,
        "only {} note(s) found; the scan is wrong and this gate proves nothing",
        notes.len()
    );

    let orphaned: Vec<String> = notes
        .iter()
        .filter(|(_, k)| !RENDERED_KINDS.contains(&k.as_str()))
        .map(|(f, k)| format!("  {f}: kind = {k:?}"))
        .collect();
    assert!(
        orphaned.is_empty(),
        "these notes have a kind the index renders no group for, so they \
         appear on the index nowhere while their own pages still build:\n{}\n\
         Add a group to {TEMPLATE} or give the note one of {RENDERED_KINDS:?}.",
        orphaned.join("\n")
    );
    Ok(())
}

/// The template renders a group for every kind it claims to.
///
/// The other direction: a group whose kind no note uses is dead template, and
/// a `RENDERED_KINDS` entry that matches nothing makes the gate above vacuous
/// for that kind.
#[test]
fn every_rendered_kind_is_a_kind_some_note_uses() -> Result<(), TestError> {
    let tpl = read(TEMPLATE)?;
    let notes = note_kinds()?;
    for kind in RENDERED_KINDS {
        assert!(
            tpl.contains(&format!("value=\"{kind}\"")),
            "{TEMPLATE} renders no group for {kind:?}, which this gate lists \
             as rendered"
        );
        assert!(
            notes.iter().any(|(_, k)| k == kind),
            "no note uses kind {kind:?}, so the group for it is dead template \
             and the orphan gate is vacuous for that kind"
        );
    }
    Ok(())
}

/// One row renderer, not two.
///
/// Both groups show the same thing. Two copies of that markup drift.
#[test]
fn every_group_shares_one_row_renderer() -> Result<(), TestError> {
    let tpl = read(TEMPLATE)?;
    let rows = tpl.matches("macros::note_row").count();
    assert!(
        rows >= RENDERED_KINDS.len(),
        "expected every group to call the shared row macro; found {rows} \
         call(s). A second copy of the row markup drifts from the first."
    );
    assert!(
        !tpl.contains("<li class=\"note-list-item\">"),
        "the index writes a note row inline instead of calling the shared \
         macro; that is the second copy this gate exists to prevent"
    );
    let macros = read("website/templates/macros.html")?;
    assert!(
        macros.contains("macro note_row"),
        "the shared row macro is gone from macros.html"
    );
    Ok(())
}

/// The scan reads the real template.
///
/// Anti-vacuity: every assertion above is a `find` on a string that a renamed
/// class or a rewritten template would simply not contain, and a `find` that
/// misses panics with a message about the wrong thing.
#[test]
fn the_notes_index_scan_reads_a_real_template() -> Result<(), TestError> {
    let tpl = read(TEMPLATE)?;
    assert!(
        tpl.len() > 500,
        "{TEMPLATE} is {} bytes; that is not the index template",
        tpl.len()
    );
    assert!(
        tpl.contains("section.pages"),
        "{TEMPLATE} no longer iterates the section's pages"
    );
    assert!(
        Path::new(&repo().join("website/content/notes")).is_dir(),
        "website/content/notes is not a directory"
    );
    Ok(())
}

/// The span of `html` from `open` to the first `close` after it.
fn span_between<'a>(html: &'a str, open: &str, close: &str) -> Result<&'a str, TestError> {
    let at = html
        .find(open)
        .ok_or_else(|| format!("no `{open}` in the template"))?;
    let end = html[at..]
        .find(close)
        .ok_or_else(|| format!("`{open}` is never followed by `{close}`"))?
        + at;
    Ok(&html[at..end])
}

/// The homepage's notes teaser shows how-tos and features, never post-mortems.
///
/// The teaser took the three newest notes of ANY kind, so the week a
/// post-mortem was written it advertised an account of what broke to every
/// first-time visitor. Post-mortems are no longer notes, but the teaser still
/// iterates a list selected by kind, so a kind added to the section later
/// reaches the homepage only by being named here.
#[test]
fn the_homepage_notes_teaser_leaves_out_the_postmortems() -> Result<(), TestError> {
    let page = read("website/templates/index.html")?;
    let block = span_between(&page, "<section class=\"notes-callout\"", "</section>")?;

    let for_re = regex::Regex::new(r"\{%-?\s*for\s+\w+\s+in\s+([^%]+?)\s*-?%\}")?;
    let iterated = for_re
        .captures(block)
        .ok_or_else(|| format!("the notes teaser has no for loop:\n{block}"))?[1]
        .to_string();
    assert!(
        !iterated.contains("notes.pages"),
        "the notes teaser iterates the section's pages directly ({iterated}), \
         so a post-mortem is on the homepage whenever it is among the newest"
    );

    // The name it iterates is built by a `set` earlier in the template.
    let var = iterated
        .split('|')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let set_re = regex::Regex::new(&format!(
        r"(?s)\{{%-?\s*set\s+{}\s*=\s*(.+?)-?%\}}",
        regex::escape(&var)
    ))?;
    let selection = set_re
        .captures(&page)
        .ok_or_else(|| format!("the teaser iterates `{var}`, which no `set` defines"))?[1]
        .to_string();
    for kind in ["howto", "feature"] {
        assert!(
            selection.contains(&format!("value=\"{kind}\"")),
            "the teaser's selection does not include {kind} notes: {selection}"
        );
    }
    assert!(
        !selection.contains("postmortem"),
        "the teaser's selection includes post-mortems: {selection}"
    );
    assert!(
        block.contains("How-tos and walkthroughs"),
        "the teaser is no longer titled for what it shows:\n{block}"
    );
    Ok(())
}

/// The notes sidebar lists both kinds open, how-tos first, and no archive.
///
/// Every note page carries the sidebar. It once held the post-mortems behind a
/// disclosure; a disclosure left behind would render an empty group heading
/// on every note page.
#[test]
fn the_notes_sidebar_lists_each_kind_open_and_in_order() -> Result<(), TestError> {
    let macros = read("website/templates/macros.html")?;
    let nav = span_between(&macros, "macro notes_nav(", "endmacro")?;
    assert!(
        !nav.contains("<details"),
        "the notes sidebar still has a disclosure:\n{nav}"
    );
    assert!(
        !nav.contains("postmortem"),
        "the notes sidebar still selects post-mortems, a kind no note uses"
    );
    let mut last = 0usize;
    for kind in RENDERED_KINDS {
        let at = nav
            .find(&format!("\"{kind}\""))
            .ok_or_else(|| format!("the notes sidebar has no {kind:?} group"))?;
        assert!(
            at >= last,
            "the sidebar's {kind} group renders out of order; how-tos come first"
        );
        last = at;
    }
    Ok(())
}

/// A kind chip reads "How-to" or "Feature", never the slug.
///
/// The chip printed the front-matter value, so a reader saw `howto`: an
/// identifier, not a word. The label comes from one macro so the index rows
/// and a note's own header cannot spell it two ways.
#[test]
fn a_kind_chip_shows_a_word_not_a_slug() -> Result<(), TestError> {
    let macros = read("website/templates/macros.html")?;
    let label = span_between(&macros, "macro kind_label", "endmacro")?;
    for (kind, word) in [("howto", "How-to"), ("feature", "Feature")] {
        assert!(
            label.contains(&format!("\"{kind}\"")) && label.contains(word),
            "kind_label does not map {kind:?} to {word:?}:\n{label}"
        );
    }
    assert!(
        !label.contains("postmortem"),
        "kind_label still maps post-mortems, a kind no note uses:\n{label}"
    );

    let chip = regex::Regex::new(r#"(?s)<span class="note-kind[^>]*>(.*?)</span>"#)?;
    let mut seen = 0;
    for tpl in [
        "website/templates/macros.html",
        "website/templates/note.html",
    ] {
        let text = read(tpl)?;
        for c in chip.captures_iter(&text) {
            seen += 1;
            assert!(
                c[1].contains("kind_label("),
                "{tpl} renders a kind chip without kind_label, so it prints \
                 the slug: {}",
                &c[0]
            );
        }
    }
    assert!(
        seen >= 2,
        "found {seen} kind chip(s); the scan is not reading them"
    );
    Ok(())
}

/// Dates are not space-padded.
///
/// `%e` pads a one-digit day with a SPACE, so the first nine days of a month
/// rendered as " 1 September 2026" -- a stray leading gap in every list.
/// `%-d` is the unpadded day.
#[test]
fn no_template_formats_a_space_padded_day() -> Result<(), TestError> {
    let mut seen = 0;
    for entry in std::fs::read_dir(repo().join("website/templates"))
        .map_err(|e| format!("templates dir: {e}"))?
    {
        let p = entry.map_err(|e| format!("entry: {e}"))?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let text = std::fs::read_to_string(&p).map_err(|e| format!("read template: {e}"))?;
        seen += text.matches("date(format=").count();
        assert!(
            !text.contains("%e"),
            "{} formats a date with %e, which pads a one-digit day with a space",
            p.display()
        );
    }
    assert!(
        seen >= 5,
        "found {seen} date filter(s); the scan is not reading the templates"
    );
    Ok(())
}

/// A note's description is plain text.
///
/// The description is printed as text in three places (the index row, the
/// homepage card and the note's own lead) and as a meta description, and
/// none of them renders Markdown. A link written into one showed the reader
/// its brackets and its URL.
#[test]
fn no_note_description_carries_markdown() -> Result<(), TestError> {
    let dir = repo().join("website/content/notes");
    let link = regex::Regex::new(r"\]\(|`|\*\*")?;
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir)
        .map_err(|e| format!("read notes: {e}"))?
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "md") {
            continue;
        }
        let body = std::fs::read_to_string(&path).unwrap_or_default();
        if let Some(desc) = body.lines().find_map(|l| l.strip_prefix("description = ")) {
            seen += 1;
            assert!(
                !link.is_match(desc),
                "{} has Markdown in its description, which renders as literal \
                 characters: {desc}",
                path.display()
            );
        }
    }
    assert!(
        seen >= 10,
        "read {seen} description(s); the scan is not reading the notes"
    );
    Ok(())
}
