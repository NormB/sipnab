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
