// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every citation of the vCon core draft names the revision sipnab implements.
//!
//! sipnab implements `draft-ietf-vcon-vcon-core-04`. A link to a section of
//! `-03` sends a reader to text that `-04` changed or removed: `-03` section
//! 4.3 allowed a Dialog Object "with no parameters in it", and `-04` does not.
//! Section numbers alone do not reveal that, because `-04` kept every `-03`
//! number. So the gate is on the revision in the link, not on the number.
//!
//! Some references to an earlier revision are deliberate and stay:
//!
//! - released sections of `CHANGELOG.md`, which describe what a past release
//!   did against the draft it targeted;
//! - the dated notes under `website/content/notes/`, which describe a past
//!   release in the same way;
//! - the `-03` to `-04` comparison in `docs/design/vcon.md`, between its
//!   `vcon-core-03-comparison` markers;
//! - `-02` in the vcon.store pages and the forwarder, because vcon.store
//!   implements `-02` and those pages say so.
//!
//! Every `-04` anchor is also checked against the sections `-04` has, so a
//! mistyped section number fails here rather than in a reader's browser.

use std::path::Path;
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

/// The URL prefix of a revision of the core draft on the IETF Datatracker.
const DRAFT_URL: &str = "datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-";

/// The revision sipnab implements.
const CURRENT: &str = "04";

/// Every section and appendix anchor of `draft-ietf-vcon-vcon-core-04`, read
/// from the Datatracker HTML rendering of the draft.
const CORE_04_ANCHORS: &[&str] = &[
    "appendix-A",
    "appendix-A.1",
    "appendix-A.2",
    "appendix-A.3",
    "appendix-A.4",
    "appendix-A.5",
    "appendix-A.6",
    "appendix-A.7",
    "appendix-A.8",
    "appendix-A.9",
    "appendix-B",
    "appendix-C",
    "appendix-D",
    "appendix-E",
    "section-1",
    "section-1.1",
    "section-1.2",
    "section-1.3",
    "section-1.4",
    "section-2",
    "section-2.1",
    "section-2.2",
    "section-2.3",
    "section-2.3.1",
    "section-2.3.2",
    "section-2.4",
    "section-2.4.1",
    "section-2.4.2",
    "section-2.5",
    "section-3",
    "section-4",
    "section-4.1",
    "section-4.1.1",
    "section-4.1.2",
    "section-4.1.3",
    "section-4.1.4",
    "section-4.1.5",
    "section-4.1.6",
    "section-4.1.7",
    "section-4.1.8",
    "section-4.1.8.1",
    "section-4.1.9",
    "section-4.1.9.1",
    "section-4.1.10",
    "section-4.1.11",
    "section-4.1.12",
    "section-4.1.13",
    "section-4.2",
    "section-4.2.1",
    "section-4.2.2",
    "section-4.2.3",
    "section-4.2.4",
    "section-4.2.5",
    "section-4.2.6",
    "section-4.2.7",
    "section-4.2.8",
    "section-4.2.9",
    "section-4.2.10",
    "section-4.2.11",
    "section-4.2.12",
    "section-4.2.13",
    "section-4.3",
    "section-4.3.1",
    "section-4.3.1.1",
    "section-4.3.1.2",
    "section-4.3.1.3",
    "section-4.3.1.4",
    "section-4.3.1.5",
    "section-4.3.1.6",
    "section-4.3.2",
    "section-4.3.3",
    "section-4.3.4",
    "section-4.3.5",
    "section-4.3.6",
    "section-4.3.7",
    "section-4.3.8",
    "section-4.3.9",
    "section-4.3.10",
    "section-4.3.11",
    "section-4.3.12",
    "section-4.3.13",
    "section-4.3.13.1",
    "section-4.3.14",
    "section-4.3.15",
    "section-4.3.16",
    "section-4.4",
    "section-4.4.1",
    "section-4.4.2",
    "section-4.4.3",
    "section-4.4.4",
    "section-4.4.5",
    "section-4.4.6",
    "section-4.4.7",
    "section-4.5",
    "section-4.5.1",
    "section-4.5.2",
    "section-4.5.3",
    "section-4.5.4",
    "section-4.5.5",
    "section-4.5.6",
    "section-4.5.7",
    "section-4.5.8",
    "section-4.5.9",
    "section-5",
    "section-5.1",
    "section-5.2",
    "section-5.2.1",
    "section-5.2.2",
    "section-5.2.3",
    "section-5.3",
    "section-5.3.1",
    "section-5.3.2",
    "section-5.3.3",
    "section-5.4",
    "section-6",
    "section-6.1",
    "section-6.2",
    "section-6.3",
    "section-6.3.1",
    "section-6.3.2",
    "section-6.3.3",
    "section-6.3.4",
    "section-6.3.4.1",
    "section-6.3.4.1.1",
    "section-6.3.4.1.2",
    "section-6.3.5",
    "section-6.3.5.1",
    "section-6.3.5.1.1",
    "section-6.3.5.1.2",
    "section-6.3.6",
    "section-6.3.7",
    "section-6.3.8",
    "section-6.3.9",
    "section-6.4",
    "section-6.4.1",
    "section-6.5",
    "section-7",
    "section-7.1",
    "section-7.2",
    "section-7.3",
    "section-8",
    "section-8.1",
    "section-8.2",
];

/// Files whose references to an earlier revision are deliberate, and which
/// revisions each may name. `CHANGELOG.md` and the design page's comparison
/// are handled separately, because only part of each is exempt.
const EARLIER_REVISION_ALLOWED: &[(&str, &[&str])] = &[
    ("docs/vcon-store.md", &["02"]),
    ("website/content/docs/vcon-store.md", &["02"]),
    ("website/static/llms-full.txt", &["02"]),
];

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked file, as text; files that are not UTF-8 are skipped.
fn tracked_texts() -> Result<Vec<(String, String)>, TestError> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo())
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    assert!(out.status.success(), "git ls-files failed");
    let mut texts = Vec::new();
    for path in String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
    {
        let Ok(bytes) = std::fs::read(repo().join(path)) else {
            // Tracked but deleted in the working tree.
            continue;
        };
        if let Ok(text) = String::from_utf8(bytes) {
            texts.push((path.to_string(), text));
        }
    }
    Ok(texts)
}

/// The part of `path`'s text the revision rule applies to.
///
/// `CHANGELOG.md` up to its first released heading, which is the unreleased
/// section; the design page without its `-03` comparison; dated notes not at
/// all; every other file whole.
fn checked_part<'a>(path: &str, text: &'a str) -> std::borrow::Cow<'a, str> {
    if path.starts_with("website/content/notes/") {
        return std::borrow::Cow::Borrowed("");
    }
    if path == "CHANGELOG.md" {
        let released = text.find("\n## [0.").unwrap_or(text.len());
        return std::borrow::Cow::Borrowed(&text[..released]);
    }
    if path == "docs/design/vcon.md" {
        let start = "<!-- vcon-core-03-comparison:start -->";
        let end = "<!-- vcon-core-03-comparison:end -->";
        if let (Some(s), Some(e)) = (text.find(start), text.find(end)) {
            return std::borrow::Cow::Owned(format!("{}{}", &text[..s], &text[e..]));
        }
    }
    std::borrow::Cow::Borrowed(text)
}

/// Every `(revision, anchor)` linked on the Datatracker in `text`. The anchor
/// is empty for a link to the whole document.
fn draft_links(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (at, _) in text.match_indices(DRAFT_URL) {
        let rest = &text[at + DRAFT_URL.len()..];
        let revision: String = rest.chars().take_while(char::is_ascii_digit).collect();
        let after = &rest[revision.len()..];
        let anchor = after
            .strip_prefix('#')
            .map(|a| {
                a.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
                    .collect::<String>()
                    .trim_end_matches('.')
                    .to_string()
            })
            .unwrap_or_default();
        out.push((revision, anchor));
    }
    out
}

/// No tracked file links an earlier revision of the core draft, outside the
/// references kept on purpose.
#[test]
fn every_core_draft_link_names_the_revision_sipnab_implements() -> Result<(), TestError> {
    let texts = tracked_texts()?;
    let mut stale = Vec::new();
    let mut current = 0usize;
    for (path, text) in &texts {
        if path == "tests/vcon_draft_citation_test.rs" {
            continue;
        }
        let allowed: &[&str] = EARLIER_REVISION_ALLOWED
            .iter()
            .find(|(p, _)| p == path)
            .map_or(&[], |(_, revisions)| *revisions);
        for (revision, anchor) in draft_links(&checked_part(path, text)) {
            if revision == CURRENT {
                current += 1;
            } else if !allowed.contains(&revision.as_str()) {
                stale.push(format!("{path}: -{revision}#{anchor}"));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "{} link(s) to an earlier revision of draft-ietf-vcon-vcon-core; sipnab \
         implements -{CURRENT}. Point each at the -{CURRENT} section that says \
         the same thing (section 7.1 of docs/design/vcon.md maps the ones whose \
         text moved), or add the file to the allowlist with the reason:\n{}",
        stale.len(),
        stale.join("\n")
    );
    assert!(
        current >= 50,
        "only {current} link(s) to -{CURRENT} found; the scan is not reading \
         the files it claims to"
    );
    Ok(())
}

/// Every `-04` anchor in the tree is a section or appendix `-04` has.
#[test]
fn every_core_04_anchor_exists_in_core_04() -> Result<(), TestError> {
    let mut unknown = Vec::new();
    let mut checked = 0usize;
    for (path, text) in tracked_texts()? {
        if path == "tests/vcon_draft_citation_test.rs" {
            continue;
        }
        for (revision, anchor) in draft_links(&text) {
            if revision != CURRENT || anchor.is_empty() {
                continue;
            }
            checked += 1;
            if !CORE_04_ANCHORS.contains(&anchor.as_str()) {
                unknown.push(format!("{path}: #{anchor}"));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "anchor(s) draft-ietf-vcon-vcon-core-04 does not have:\n{}",
        unknown.join("\n")
    );
    assert!(checked >= 50, "only {checked} anchor(s) checked");
    Ok(())
}

/// The link reader finds the revision and the anchor, including an anchor
/// that ends a sentence.
#[test]
fn the_link_reader_separates_revision_and_anchor() {
    let text = "see https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6. \
                and (https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-03) and \
                https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-A.4)";
    assert_eq!(
        draft_links(text),
        vec![
            ("04".to_string(), "section-4.3.1.6".to_string()),
            ("03".to_string(), String::new()),
            ("04".to_string(), "appendix-A.4".to_string()),
        ]
    );
}
