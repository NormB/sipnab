// SPDX-License-Identifier: MIT OR Apache-2.0
//! The crate's front page on docs.rs shows examples that run and prove
//! something.
//!
//! docs.rs renders the `//!` block at the top of `src/lib.rs` as sipnab's
//! front page, and crates.io links to it. For 0.5.179 that page's Quick Start
//! was `no_run`, imported `parse_sip` and `parse_packet` without calling
//! either, and looped over a capture's packets doing nothing. The step a
//! reader needed, from a frame to a SIP message, was missing, and a doctest
//! that only compiles proved none of it. The same page promised a semver
//! contract the project had just decided not to make.
//!
//! `sipnab-bpf-types` is the second published crate, and its page was ungated:
//! 0.1.1 went up with no example at all, the same half-of-a-pair gap that
//! shipped 0.1.0 without a README. Its page is its README, included as the
//! crate root's documentation, so the gates below read the README and every
//! doc comment in its `src/lib.rs`.
//!
//! These gates read the page as text. The examples themselves run as doctests
//! in every `cargo test`, which is what makes them WORKING. This file is what
//! stops one from quietly becoming `no_run` again, or the page from shrinking
//! back to one example that asserts nothing.

use std::path::Path;

/// The `//!` lines at the top of `src/lib.rs`, without the marker.
fn front_page() -> Vec<String> {
    let lib = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read src/lib.rs");
    lib.lines()
        .skip_while(|l| !l.starts_with("//!"))
        .take_while(|l| l.starts_with("//!"))
        .map(|l| {
            l.strip_prefix("//!")
                .unwrap_or(l)
                .trim_start_matches(' ')
                .to_string()
        })
        .collect()
}

/// Every fenced code block on the page: its fence attributes and its body.
fn code_blocks(page: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut open: Option<(String, String)> = None;
    for line in page {
        let t = line.trim_start();
        match &mut open {
            None if t.starts_with("```") => open = Some((t[3..].to_string(), String::new())),
            Some(_) if t == "```" => out.extend(open.take()),
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    out
}

/// A block rustdoc runs as a Rust doctest: no language, or `rust` with
/// attributes. `text`, `toml`, `sh` and the like are shown, not run.
fn is_rust(attrs: &str) -> bool {
    attrs.split(',').map(str::trim).all(|a| {
        a.is_empty()
            || a == "rust"
            || a.starts_with("edition")
            || ["no_run", "ignore", "compile_fail", "should_panic"].contains(&a)
    })
}

#[test]
fn every_front_page_example_runs_and_asserts_something() {
    let blocks: Vec<(String, String)> = code_blocks(&front_page())
        .into_iter()
        .filter(|(attrs, _)| is_rust(attrs))
        .collect();
    assert!(
        blocks.len() >= 5,
        "the front page has {} Rust examples; it needs several, each showing a \
         different part of the crate",
        blocks.len()
    );
    for (attrs, body) in &blocks {
        for skip in ["no_run", "ignore", "compile_fail", "should_panic"] {
            assert!(
                !attrs.split(',').any(|a| a.trim() == skip),
                "a front-page example is marked `{skip}`, so `cargo test` does not \
                 run it:\n{body}"
            );
        }
        assert!(
            body.contains("assert"),
            "a front-page example asserts nothing, so running it proves \
             nothing:\n{body}"
        );
    }
}

#[test]
fn the_front_page_examples_cover_the_crate() {
    let page = front_page();
    let code: String = code_blocks(&page)
        .into_iter()
        .filter(|(attrs, _)| is_rust(attrs))
        .map(|(_, body)| body)
        .collect();
    for item in [
        "parse_sip",
        ".sdp()",
        "DialogStore",
        "FilterExpr",
        "select_dialogs",
        "PcapReader",
        "parse_packet",
        "parse_rtp_header",
        "estimate_mos",
    ] {
        assert!(
            code.contains(item),
            "no front-page example uses `{item}`; the page must show each part \
             of the crate a new user reaches for"
        );
    }
}

#[test]
fn the_front_page_says_the_library_api_is_unstable() {
    let page = front_page().join("\n");
    assert!(
        !page.contains("semver contract"),
        "the front page promises a semver contract; the library API is declared \
         unstable (docs/library.md)"
    );
    assert!(
        page.contains("not stable"),
        "the front page must say the library API is not stable, as \
         docs/library.md does, and tell a dependent to pin the exact release"
    );
}

// ── sipnab-bpf-types ─────────────────────────────────────────────────

/// The `sipnab-bpf-types` crate directory.
fn bpf_types() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/sipnab-bpf-types")
}

/// The crate's README, which is both its crates.io page and its docs.rs front
/// page.
fn bpf_types_readme() -> Vec<String> {
    std::fs::read_to_string(bpf_types().join("README.md"))
        .expect("read crates/sipnab-bpf-types/README.md")
        .lines()
        .map(str::to_string)
        .collect()
}

/// Every `///` and `//!` line in the crate's `src/lib.rs`, without the marker:
/// the item documentation docs.rs renders under the front page.
fn bpf_types_item_docs() -> Vec<String> {
    std::fs::read_to_string(bpf_types().join("src/lib.rs"))
        .expect("read crates/sipnab-bpf-types/src/lib.rs")
        .lines()
        .map(str::trim_start)
        .filter_map(|l| l.strip_prefix("///").or_else(|| l.strip_prefix("//!")))
        .map(|l| l.strip_prefix(' ').unwrap_or(l).to_string())
        .collect()
}

/// A fenced code block: its fence attributes and its body.
type Block = (String, String);

/// The Rust examples on the README and in the item docs, in that order.
fn bpf_types_examples() -> (Vec<Block>, Vec<Block>) {
    let rust = |page: &[String]| {
        code_blocks(page)
            .into_iter()
            .filter(|(attrs, _)| is_rust(attrs))
            .collect::<Vec<_>>()
    };
    (rust(&bpf_types_readme()), rust(&bpf_types_item_docs()))
}

/// The README is the docs.rs front page as well as the crates.io page, so the
/// examples on it run as doctests and the two pages cannot drift apart.
#[test]
fn the_bpf_types_front_page_is_its_readme() {
    let lib = std::fs::read_to_string(bpf_types().join("src/lib.rs"))
        .expect("read crates/sipnab-bpf-types/src/lib.rs");
    assert!(
        lib.contains(r#"#![doc = include_str!("../README.md")]"#),
        "crates/sipnab-bpf-types/src/lib.rs must include its README as the \
         crate documentation, so docs.rs shows the same page as crates.io and \
         the README's examples run as doctests"
    );
}

#[test]
fn every_bpf_types_example_runs_and_asserts_something() {
    let (readme, items) = bpf_types_examples();
    assert!(
        readme.len() >= 3,
        "the sipnab-bpf-types README has {} Rust examples; it needs several, \
         each showing a different part of reading a record",
        readme.len()
    );
    for (attrs, body) in readme.iter().chain(&items) {
        for skip in ["no_run", "ignore", "compile_fail", "should_panic"] {
            assert!(
                !attrs.split(',').any(|a| a.trim() == skip),
                "a sipnab-bpf-types example is marked `{skip}`, so `cargo test` \
                 does not run it:\n{body}"
            );
        }
        assert!(
            body.contains("assert"),
            "a sipnab-bpf-types example asserts nothing, so running it proves \
             nothing:\n{body}"
        );
    }
}

#[test]
fn the_bpf_types_examples_cover_the_crate() {
    let (readme, items) = bpf_types_examples();
    let code: String = readme.into_iter().chain(items).map(|(_, b)| b).collect();
    for item in [
        "TlsRecord::read",
        "socket_addrs",
        "HEADER_LEN",
        "MAX_PAYLOAD",
        "FLAG_HAS_TUPLE",
        "FLAG_TRUNCATED",
        "FAMILY_IPV4",
        "FAMILY_IPV6",
        "SockOffsets",
    ] {
        assert!(
            code.contains(item),
            "no sipnab-bpf-types example uses `{item}`; the page must show each \
             part of the record a reader has to get right"
        );
    }
}

/// Operator first: the page opens with how to turn the capture on, and every
/// flag it names is one sipnab actually has.
#[test]
fn the_bpf_types_readme_tells_an_operator_how_to_turn_the_capture_on() {
    let readme = bpf_types_readme().join("\n");
    for needle in [
        "--uprobe-backend bpf",
        "docs/uprobe-walkthrough.md",
        "docs/tls-capture.md",
    ] {
        assert!(
            readme.contains(needle),
            "the sipnab-bpf-types README must mention `{needle}`, so an operator \
             who lands on the crate page learns what it powers and where to read on"
        );
    }
    let cli = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli.rs"))
        .expect("read src/cli.rs");
    let mut flags: Vec<&str> = readme
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter_map(|w| w.strip_prefix("--"))
        .filter(|w| !w.is_empty() && !w.starts_with('-'))
        .collect();
    flags.sort_unstable();
    flags.dedup();
    assert!(!flags.is_empty(), "the README names no sipnab flag at all");
    for flag in flags {
        // Cargo's own flags are not sipnab's.
        if ["features", "release", "locked"].contains(&flag) {
            continue;
        }
        let long = format!("long = \"{flag}\"");
        let field = format!("pub {}:", flag.replace('-', "_"));
        assert!(
            cli.contains(&long) || cli.contains(&field),
            "the sipnab-bpf-types README names `--{flag}`, which src/cli.rs does \
             not define"
        );
    }
}
