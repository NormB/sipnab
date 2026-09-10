// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the install page claims about capture backends, the release proves.
//!
//! # The finding this exists for
//!
//! libpcap picks a capture backend from the device name, and sipnab passes the
//! name through untouched. Whether `netmap:eth0` reaches anything therefore
//! depends on the libpcap behind the binary — and the two artifact families
//! differ. Measured 2026-09-10 against published 0.5.162 artifacts:
//!
//! - the static musl tarballs embed libpcap 1.10.6 "with TPACKET_V3 and
//!   netmap", and answer `netmap open: cannot access netmap:lo`;
//! - the gnu tarballs, the packages and the Docker image link Debian's
//!   libpcap, built without it, and answer `No such device exists`.
//!
//! Two errors, one release, and nothing anywhere said so. `docs/install.md`
//! says it now, and `release.yml` refuses to publish a musl artifact whose
//! embedded libpcap lost the module — because a documented capability that
//! quietly disappears is worse than one that was never claimed.
//!
//! These tests hold the two halves to one word. The gate greps the artifact
//! for a backend name; the page tells a reader that name works. Renaming it in
//! one place and not the other leaves a page describing a check nobody runs.

use std::path::Path;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The backend name the release gate greps a musl artifact for.
fn gated_backend() -> String {
    let workflow = read(".github/workflows/release.yml");
    let step = workflow
        .split_once("Record the capture backends this artifact carries")
        .map(|(_, rest)| rest.to_string())
        .expect("release.yml must carry the capture-backend step");
    let line = step
        .lines()
        .find(|l| l.contains("grep -q"))
        .expect("the step must grep the embedded banner for a backend");
    // The shell line ends `grep -q netmap; then`, so take the first word
    // after the flag rather than the rest of the line.
    line.split_once("grep -q")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(|name| {
            name.trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_string()
        })
        .expect("checked above")
}

/// The release gate and the install page name the same backend.
#[test]
fn the_release_gate_and_the_install_page_name_the_same_backend() {
    let backend = gated_backend();
    assert!(
        backend.chars().all(|c| c.is_ascii_lowercase()),
        "extracted {backend:?} as a backend name, which is not one — the step's \
         shape changed and this gate is comparing nonsense"
    );
    let doc = read("docs/install.md");
    let section = doc
        .split_once("### Which capture backends an artifact can reach")
        .map(|(_, rest)| rest.to_string())
        .expect("docs/install.md must tell a reader which backends work");
    let section = section
        .split_once("\n### ")
        .map(|(s, _)| s.to_string())
        .unwrap_or(section);
    assert!(
        section.contains(&backend),
        "the release refuses to publish a musl artifact whose libpcap lost \
         {backend:?}, and the install page's capture-backend section never \
         mentions it. One of them is describing a different release."
    );
}

/// The page distinguishes the two artifact families.
///
/// A single sentence saying "netmap works" would be true of half the release
/// and false of the other half, which is the state this section was written to
/// end. The distinction is the content; a page that lost it would still
/// mention the backend and still mislead.
#[test]
fn the_install_page_says_which_artifacts_carry_it() {
    let doc = read("docs/install.md");
    let section = doc
        .split_once("### Which capture backends an artifact can reach")
        .and_then(|(_, rest)| rest.split_once("\n### "))
        .map(|(s, _)| s.to_string())
        .expect("the capture-backend section must exist and end at the next heading");
    for family in ["-linux-musl", "-linux-gnu"] {
        assert!(
            section.contains(family),
            "the capture-backend section never mentions {family} artifacts, so \
             a reader cannot tell which half of the release it describes"
        );
    }
    assert!(
        section.contains("Docker"),
        "the Docker image links Debian's libpcap like the packages do, and a \
         reader running the image has no other place to learn that"
    );
}
