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
//!
//! The page then described two families and the release ships three. The
//! `*-apple-darwin` tarballs and Homebrew on macOS load
//! `/usr/lib/libpcap.A.dylib`, the libpcap macOS ships, with no alternate
//! backend at all, and a reader holding one found no row. The later tests
//! pin that row, the build facts that make it true, the page's pointer to
//! `sipnab --version` (which names the running libpcap since CT6b), and the
//! warning that a `netmap:` capture takes the interface from the host.

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

/// The capture-backend section of the install page, up to the next heading.
fn backend_section() -> String {
    read("docs/install.md")
        .split_once("### Which capture backends an artifact can reach")
        .and_then(|(_, rest)| rest.split_once("\n### "))
        .map(|(s, _)| s.to_string())
        .expect("the capture-backend section must exist and end at the next heading")
}

/// The table cells of the section's row for one artifact family.
fn row_cells(section: &str, family: &str) -> Vec<String> {
    let row = section
        .lines()
        .find(|l| l.starts_with('|') && l.contains(family))
        .unwrap_or_else(|| panic!("the backend table has no row for {family} artifacts"));
    row.trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect()
}

/// The macOS family has a row of its own, and it says no alternate backend.
///
/// The table described the two Linux families and nothing else, so a reader
/// holding a `*-apple-darwin` tarball or a Homebrew install on a Mac found no
/// row at all and had to guess which of the two it resembled. It resembles
/// neither: the published darwin binaries load `/usr/lib/libpcap.A.dylib`
/// (their `LC_LOAD_DYLIB`, read from the 0.5.183 tarballs on 2026-09-21), the
/// libpcap Apple builds with netmap and DPDK both undefined, so every backend
/// column is `no`.
#[test]
fn the_install_page_gives_the_macos_family_its_own_row() {
    let section = backend_section();
    let cells = row_cells(&section, "-apple-darwin");
    assert_eq!(
        cells.len(),
        5,
        "the macOS row must fill the table's five columns: {cells:?}"
    );
    assert!(
        cells[0].contains("Homebrew"),
        "Homebrew on macOS installs the same darwin tarball, and a reader who \
         used brew needs to find their row: {cells:?}"
    );
    assert!(
        cells[1].contains("libpcap.A.dylib"),
        "the macOS row must name the library the darwin binaries load: {cells:?}"
    );
    assert_eq!(
        &cells[2..],
        ["no", "no", "no"],
        "macOS's own libpcap carries no alternate backend, so netmap, DPDK and \
         AF_XDP are all `no` on the macOS row"
    );
}

/// Nothing in the macOS build or its Homebrew formula brings a libpcap of its
/// own, which is what makes the macOS row's "the one macOS ships" true.
///
/// A `brew install libpcap` in the release job, or a `depends_on "libpcap"`
/// that reached the macOS half of the formula, would move the darwin binaries
/// onto a different library while the page went on naming Apple's.
#[test]
fn nothing_in_the_macos_build_brings_its_own_libpcap() {
    let workflow = read(".github/workflows/release.yml");
    for line in workflow.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        assert!(
            !(l.contains("brew") && l.contains("libpcap")),
            "release.yml installs a libpcap through Homebrew, so the darwin \
             artifacts no longer load macOS's own — fix docs/install.md's macOS \
             row or this step: {l}"
        );
        assert!(
            !l.contains("LIBPCAP_LIBDIR"),
            "release.yml points the pcap crate at a libpcap directory, so a \
             darwin build may no longer load macOS's own: {l}"
        );
    }

    let formula = read("packaging/homebrew/update-formula.sh");
    let macos = formula
        .split_once("on_macos do")
        .and_then(|(_, rest)| rest.split_once("on_linux do"))
        .map(|(block, _)| block.to_string())
        .expect("the formula must carry an on_macos block before on_linux");
    assert!(
        !macos.contains("depends_on"),
        "the formula's on_macos block gained a dependency, and docs/install.md \
         says Homebrew on macOS runs against macOS's own libpcap:\n{macos}"
    );
}

/// The page tells a reader to ask sipnab first, and keeps the `strings` probe
/// for a binary that predates the report.
///
/// `sipnab --version` names the running libpcap since CT6b. A page that still
/// sent every reader to `strings` would describe a probe that cannot see a gnu
/// build's library at all — the banner lives in the host's `libpcap.so`, not
/// in the binary.
#[test]
fn the_install_page_says_to_ask_sipnab_itself() {
    let section = backend_section();
    assert!(
        section.contains("sipnab --version"),
        "the capture-backend section must tell the reader to run \
         `sipnab --version`, which names the libpcap the binary runs"
    );
    assert!(
        section.contains("strings"),
        "keep the `strings` probe: a sipnab older than the report cannot answer \
         `--version` with its libpcap"
    );
}

/// Capturing on `netmap:` takes the interface away from the host, and the page
/// says so beside the table.
///
/// Measured 2026-09-21 on a veth pair under Debian 13 (kernel 6.12.105): a
/// UDP socket bound on the host received 0 of 5 datagrams while sipnab
/// captured on `netmap:<iface>`, against 5 of 5 during an ordinary capture on
/// the same interface. libpcap's netmap module takes the interface's rings
/// from the host stack for as long as the capture runs. An operator who reads
/// "yes" in the netmap column and points it at the interface carrying their
/// SIP service takes that service offline.
#[test]
fn the_install_page_warns_that_netmap_takes_the_interface_from_the_host() {
    // Prose wraps, and a callout wraps with `>` on every line, so compare
    // against the section as one line of words.
    let section = backend_section()
        .lines()
        .map(|l| l.trim_start_matches('>').trim())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        section.contains("dedicated to capture"),
        "the capture-backend section must say to use `netmap:` only on an \
         interface dedicated to capture"
    );
    assert!(
        section.contains("stops receiving"),
        "the capture-backend section must say the host stops receiving the \
         interface's traffic while a netmap capture runs"
    );
}
