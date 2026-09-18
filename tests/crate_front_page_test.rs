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
