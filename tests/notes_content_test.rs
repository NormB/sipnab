// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What every note under `website/content/notes/` must carry so
//! both an engineer and a reader who is not one can use it, and so it stays in
//! step with the repository.
//!
//! The 2026-10-11 audit of all 34 notes found false or stale claims in most of
//! them, terms of art used without a definition, and repository paths that no
//! longer existed. These checks hold the rewritten notes to the shape that
//! fixed that:
//!
//! - an `## In short` section near the top, readable without the rest;
//! - a `## Terms used here` section defining the terms of art;
//! - every repository path a note names in a code span exists.
//!
//! The commands a note shows are run by `doc_commands_run_test`, which walks
//! the notes as it walks the guides.

use std::path::{Path, PathBuf};

#[path = "support/markdown.rs"]
mod markdown;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Repository root.
fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every note file, excluding the section index.
fn notes() -> Result<Vec<PathBuf>, TestError> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(repo().join("website/content/notes"))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .filter(|p| p.file_name().is_some_and(|n| n != "_index.md"))
        .collect();
    out.sort();
    // 23 notes on 2026-10-16, when the eleven post-mortems with no reader
    // task moved to docs/internals/postmortems.md. The floor is below that
    // with room for one more removal, and far above what a broken walk finds.
    assert!(
        out.len() >= 20,
        "only {} notes found; the walk is wrong",
        out.len()
    );
    Ok(out)
}

/// The note's text with fenced code blocks removed, so a heading-shaped line
/// inside a code sample is not read as a section.
fn prose(text: &str) -> String {
    let mut inside = false;
    let mut out = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn every_note_opens_with_a_plain_summary_and_defines_its_terms() -> Result<(), TestError> {
    let mut missing = Vec::new();
    for note in notes()? {
        let text = prose(&std::fs::read_to_string(&note)?);
        let name = note
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        let headings: Vec<&str> = text.lines().filter(|l| l.starts_with("## ")).collect();
        if headings.first() != Some(&"## In short") {
            missing.push(format!("{name}: the first section is not \"## In short\""));
        }
        if !headings.contains(&"## Terms used here") {
            missing.push(format!("{name}: no \"## Terms used here\" section"));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
    Ok(())
}

#[test]
fn every_repository_path_a_note_names_exists() -> Result<(), TestError> {
    // A code span naming a file under one of the repository's top-level
    // trees (`.config/code-trees.txt`, plus `docs`): `tests/pcap-samples/x.pcap`,
    // `src/app/batch.rs`, `docs/tls-capture.md`. A trailing `:line` is not part
    // of the path.
    let span = regex::Regex::new(
        r"`([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+?\.[A-Za-z0-9]+)(?::\d+(?:-\d+)?)?`",
    )?;
    let trees = markdown::code_trees();
    let mut absent = Vec::new();
    let mut seen = 0_usize;
    for note in notes()? {
        let text = std::fs::read_to_string(&note)?;
        let name = note
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        for c in span.captures_iter(&text) {
            let path = &c[1];
            let top = path.split('/').next().unwrap_or_default();
            if top != "docs" && !trees.contains(top) {
                continue;
            }
            seen += 1;
            if !repo().join(path).exists() {
                absent.push(format!("{name}: `{path}` does not exist"));
            }
        }
    }
    assert!(
        seen >= 10,
        "only {seen} repository paths found in the notes; the scan is wrong"
    );
    assert!(absent.is_empty(), "{}", absent.join("\n"));
    Ok(())
}

#[test]
fn every_note_links_the_guides_that_cover_its_ground() -> Result<(), TestError> {
    let mut missing = Vec::new();
    for note in notes()? {
        let text = prose(&std::fs::read_to_string(&note)?);
        let name = note
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        let Some(at) = text.find("\n## Related guides") else {
            missing.push(format!("{name}: no \"## Related guides\" section"));
            continue;
        };
        let section = &text[at + 1..];
        let section = section[3..]
            .find("\n## ")
            .map_or(section, |end| &section[..end + 3]);
        if !section.contains("(@/docs/") {
            missing.push(format!(
                "{name}: \"Related guides\" links no guide under @/docs/"
            ));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
    Ok(())
}

/// A note's `updated` date is shown on the page, and is never earlier than
/// the date it was first published.
#[test]
fn an_updated_note_says_so_and_its_dates_are_in_order() -> Result<(), TestError> {
    let template = std::fs::read_to_string(repo().join("website/templates/note.html"))?;
    assert!(
        template.contains("page.updated"),
        "website/templates/note.html does not render a note's `updated` date"
    );
    let date = regex::Regex::new(r"(?m)^date = (\d{4}-\d{2}-\d{2})")?;
    let updated = regex::Regex::new(r"(?m)^updated = (\d{4}-\d{2}-\d{2})")?;
    let mut out_of_order = Vec::new();
    let mut seen = 0_usize;
    for note in notes()? {
        let text = std::fs::read_to_string(&note)?;
        let name = note
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_owned();
        if let (Some(d), Some(u)) = (date.captures(&text), updated.captures(&text)) {
            seen += 1;
            if u[1] < d[1] {
                out_of_order.push(format!(
                    "{name}: updated {} is before date {}",
                    &u[1], &d[1]
                ));
            }
        }
    }
    assert!(seen >= 20, "only {seen} notes carry both dates");
    assert!(out_of_order.is_empty(), "{}", out_of_order.join("\n"));
    Ok(())
}
