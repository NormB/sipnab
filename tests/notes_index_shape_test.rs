// SPDX-License-Identifier: MIT OR Apache-2.0

//! The notes index leads with what a reader came for.
//!
//! `website/content/notes/` holds three kinds. How-tos say how to do a job and
//! feature notes say what a capability does; both are why somebody opens the
//! page. Post-mortems are a record worth keeping and a poor front page —
//! sixteen accounts of what broke bury the pages a reader wants, and a visitor
//! who lands on a wall of failures learns the wrong thing about the project.
//!
//! So the post-mortems collapse behind a `<details>` the reader opens
//! deliberately, and the other two stay expanded. This file holds that
//! arrangement, and holds the failure the arrangement introduces: filtering
//! the list by kind means a note whose kind is not one of the three renders
//! NOWHERE. It would not 404 and it would not warn — it would simply be
//! missing from the index while its own page still built, which is the kind of
//! absence nobody notices.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

const TEMPLATE: &str = "website/templates/notes.html";

/// The opening tag of the post-mortem disclosure.
///
/// The class is part of the anchor on purpose: a bare `<details` also matches
/// the Tera comment above it that explains why the disclosure exists, and two
/// gates here read that comment instead of the markup — one of them passing
/// because a sentence contains no `open` attribute.
const DISCLOSURE_TAG: &str = "<details class=\"note-archive\"";

/// The kinds the index template renders a group for.
const RENDERED_KINDS: &[&str] = &["howto", "feature", "postmortem"];

/// Every note's `kind`, with the file it came from.
fn note_kinds() -> Vec<(String, String)> {
    let dir = repo().join("website/content/notes");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .expect("read website/content/notes")
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
    out
}

/// Post-mortems are behind a disclosure, and it starts closed.
///
/// `<details>` without `open` is the whole mechanism: the titles are reachable
/// and the page does not open onto them.
#[test]
fn the_postmortems_sit_behind_a_closed_disclosure() {
    let tpl = read(TEMPLATE);
    // The real tag, not the word `<details>` inside the Tera comment that
    // explains the design. Matching the prose made this gate read a comment
    // and pass for a reason unrelated to the markup.
    let at = tpl
        .find(DISCLOSURE_TAG)
        .expect("the notes index no longer has a disclosure at all");
    let tag_end = tpl[at..].find('>').expect("unterminated <details") + at;
    let tag = &tpl[at..=tag_end];

    assert!(
        !tag.contains("open"),
        "the post-mortem disclosure is marked `open`, so the page still opens \
         onto sixteen accounts of what broke: {tag}"
    );
    let after = &tpl[at..];
    assert!(
        after.contains("value=\"postmortem\"") || after.contains("postmortems"),
        "the disclosure does not contain the post-mortem list; it is \
         collapsing something else"
    );
}

/// How-tos and features are NOT behind it.
///
/// The other half, and the one that would rot silently: moving a group inside
/// the disclosure hides it while every page still builds and every link still
/// resolves.
#[test]
fn howtos_and_features_render_outside_the_disclosure() {
    let tpl = read(TEMPLATE);
    let details_at = tpl.find(DISCLOSURE_TAG).expect("no disclosure");
    let before = &tpl[..details_at];

    for kind in ["howto", "feature"] {
        assert!(
            before.contains(&format!("value=\"{kind}\"")),
            "the {kind} group is not rendered before the disclosure, so it is \
             either inside it or gone. Those are what a reader came for."
        );
    }
    let after = &tpl[details_at..];
    for kind in ["howto", "feature"] {
        assert!(
            !after.contains(&format!("value=\"{kind}\"")),
            "a {kind} group is rendered INSIDE the post-mortem disclosure"
        );
    }
}

/// Every note has a kind the index actually renders.
///
/// The failure the split introduces. The template selects by kind, so a note
/// written with `kind = "reference"` — a value the stylesheet already has a
/// color for — renders in no group at all. Its own page builds, its link
/// resolves from the sidebar, and it is absent from the index with nothing
/// saying so.
#[test]
fn every_note_has_a_kind_the_index_renders() {
    let notes = note_kinds();
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
}

/// The template renders a group for every kind it claims to.
///
/// The other direction: a group whose kind no note uses is dead template, and
/// a `RENDERED_KINDS` entry that matches nothing makes the gate above vacuous
/// for that kind.
#[test]
fn every_rendered_kind_is_a_kind_some_note_uses() {
    let tpl = read(TEMPLATE);
    let notes = note_kinds();
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
}

/// The disclosure says how many it holds.
///
/// A closed `details` labeled only "Post-mortems" gives no reason to open it
/// and no sense of what is behind it. The count is the difference between a
/// heading and an affordance.
#[test]
fn the_disclosure_states_how_many_it_holds() {
    let tpl = read(TEMPLATE);
    let at = tpl.find(DISCLOSURE_TAG).expect("no disclosure");
    let summary_end = tpl[at..]
        .find("</summary>")
        .expect("the disclosure has no summary")
        + at;
    let summary = &tpl[at..summary_end];
    assert!(
        summary.contains("| length"),
        "the disclosure's summary does not render a count, so a reader cannot \
         tell whether it hides two notes or forty:\n{summary}"
    );
}

/// One row renderer, not two.
///
/// The open groups and the collapsed archive show the same thing. Two copies
/// of that markup drift, and the one that drifts is whichever nobody looks at
/// — which, by construction, is the collapsed one.
#[test]
fn the_open_groups_and_the_archive_share_one_row_renderer() {
    let tpl = read(TEMPLATE);
    let rows = tpl.matches("macros::note_row").count();
    assert!(
        rows >= 3,
        "expected every group to call the shared row macro; found {rows} \
         call(s). A second copy of the row markup drifts from the first."
    );
    assert!(
        !tpl.contains("<li class=\"note-list-item\">"),
        "the index writes a note row inline instead of calling the shared \
         macro; that is the second copy this gate exists to prevent"
    );
    let macros = read("website/templates/macros.html");
    assert!(
        macros.contains("macro note_row"),
        "the shared row macro is gone from macros.html"
    );
}

/// The scan reads the real template.
///
/// Anti-vacuity: every assertion above is a `find` on a string that a renamed
/// class or a rewritten template would simply not contain, and a `find` that
/// misses panics with a message about the wrong thing.
#[test]
fn the_notes_index_scan_reads_a_real_template() {
    let tpl = read(TEMPLATE);
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
}

/// The span of `html` from `open` to the first `close` after it.
fn span_between<'a>(html: &'a str, open: &str, close: &str) -> &'a str {
    let at = html
        .find(open)
        .unwrap_or_else(|| panic!("no `{open}` in the template"));
    let end = html[at..]
        .find(close)
        .unwrap_or_else(|| panic!("`{open}` is never followed by `{close}`"))
        + at;
    &html[at..end]
}

/// The homepage's notes teaser shows how-tos and features, never post-mortems.
///
/// The index collapses the post-mortems because they are a poor front page.
/// The homepage is the front page of the front page, and it took the three
/// newest notes of ANY kind, so the week a post-mortem was written it
/// advertised an account of what broke to every first-time visitor. The
/// teaser must iterate a list selected by kind, and the selection must name
/// both kinds a reader came for and not the one they did not.
#[test]
fn the_homepage_notes_teaser_leaves_out_the_postmortems() {
    let page = read("website/templates/index.html");
    let block = span_between(&page, "<section class=\"notes-callout\"", "</section>");

    let for_re = regex::Regex::new(r"\{%-?\s*for\s+\w+\s+in\s+([^%]+?)\s*-?%\}").unwrap();
    let iterated = for_re
        .captures(block)
        .unwrap_or_else(|| panic!("the notes teaser has no for loop:\n{block}"))[1]
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
    ))
    .unwrap();
    let selection = set_re
        .captures(&page)
        .unwrap_or_else(|| panic!("the teaser iterates `{var}`, which no `set` defines"))[1]
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
}

/// The notes sidebar collapses its post-mortem group, as the index does.
///
/// Every note page carries the sidebar, and it listed every post-mortem
/// uncollapsed under the how-tos and features, so the arrangement the index
/// makes was undone on every page a reader opened from it.
#[test]
fn the_notes_sidebar_collapses_the_postmortems() {
    let macros = read("website/templates/macros.html");
    let nav = span_between(&macros, "macro notes_nav(", "endmacro");

    let details_at = nav
        .find("<details")
        .unwrap_or_else(|| panic!("the notes sidebar has no disclosure:\n{nav}"));
    // The tag ends at the first `>` outside a Tera tag: the condition that
    // opens it is itself `... | length > 0`.
    let mut in_tera = false;
    let mut tag_end = None;
    let bytes = nav.as_bytes();
    for i in details_at..bytes.len() {
        if bytes[i..].starts_with(b"{%") {
            in_tera = true;
        } else if in_tera && bytes[i..].starts_with(b"%}") {
            in_tera = false;
        } else if !in_tera && bytes[i] == b'>' {
            tag_end = Some(i);
            break;
        }
    }
    let tag_end = tag_end.expect("unterminated <details");
    let tag = &nav[details_at..=tag_end];
    // Open only for a reader already on a post-mortem, so the page they are
    // on stays visible in its own sidebar. Never unconditionally.
    let unconditional = tag.replace(" open{% endif %}", "");
    assert!(
        !unconditional.contains(" open"),
        "the sidebar's post-mortem disclosure ships open: {tag}"
    );
    assert!(
        tag.contains("value=current") && tag.contains(" open{% endif %}"),
        "the sidebar's post-mortem disclosure does not open for a reader who \
         is ON a post-mortem, so the page they are reading is hidden in its \
         own sidebar: {tag}"
    );

    let inside = &nav[details_at..];
    assert!(
        inside.contains("\"postmortem\""),
        "the sidebar disclosure does not hold the post-mortem group"
    );
    for kind in ["howto", "feature"] {
        assert!(
            nav[..details_at].contains(&format!("\"{kind}\"")),
            "the {kind} group is not rendered before the sidebar disclosure"
        );
        assert!(
            !inside.contains(&format!("\"{kind}\"")),
            "the {kind} group is inside the sidebar's post-mortem disclosure"
        );
    }
}

/// A kind chip reads "How-to", "Feature" or "Post-mortem", never the slug.
///
/// The chip printed the front-matter value, so a reader saw `howto` and
/// `postmortem`: identifiers, not words. The label comes from one macro so the
/// index rows and a note's own header cannot spell it two ways.
#[test]
fn a_kind_chip_shows_a_word_not_a_slug() {
    let macros = read("website/templates/macros.html");
    let label = span_between(&macros, "macro kind_label", "endmacro");
    for (kind, word) in [
        ("howto", "How-to"),
        ("feature", "Feature"),
        ("postmortem", "Post-mortem"),
    ] {
        assert!(
            label.contains(&format!("\"{kind}\"")) && label.contains(word),
            "kind_label does not map {kind:?} to {word:?}:\n{label}"
        );
    }

    let chip = regex::Regex::new(r#"(?s)<span class="note-kind[^>]*>(.*?)</span>"#).unwrap();
    let mut seen = 0;
    for tpl in [
        "website/templates/macros.html",
        "website/templates/note.html",
    ] {
        let text = read(tpl);
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
}

/// Dates are not space-padded.
///
/// `%e` pads a one-digit day with a SPACE, so the first nine days of a month
/// rendered as " 1 September 2026" -- a stray leading gap in every list.
/// `%-d` is the unpadded day.
#[test]
fn no_template_formats_a_space_padded_day() {
    let mut seen = 0;
    for entry in std::fs::read_dir(repo().join("website/templates")).expect("templates dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read template");
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
}

/// A note's description is plain text.
///
/// The description is printed as text in three places (the index row, the
/// homepage card and the note's own lead) and as a meta description, and
/// none of them renders Markdown. A link written into one showed the reader
/// its brackets and its URL.
#[test]
fn no_note_description_carries_markdown() {
    let dir = repo().join("website/content/notes");
    let link = regex::Regex::new(r"\]\(|`|\*\*").unwrap();
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).expect("read notes").flatten() {
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
}
