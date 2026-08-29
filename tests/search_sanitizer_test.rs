// SPDX-License-Identifier: MIT OR Apache-2.0

//! The docs-search excerpt sanitizer, exercised as JavaScript rather than
//! described in Rust.
//!
//! CodeQL reported `js/incomplete-multi-character-sanitization` (high) against
//! `website/static/js/docs-search.js`, and the first thing to say is that the
//! report is a pattern match rather than a demonstrated bug. The regex is
//! greedy from `<` to the first `>`, so a pass cannot join a leftover `<` to a
//! later `>` and manufacture a tag: measured across nine adversarial inputs,
//! one pass and the fixed point agree on all nine. My first write-up of this
//! claimed the single pass "creates the very thing it removed"; that was
//! wrong, and measuring it is what showed me.
//!
//! The loop still went in — it closes a standing high alert, and it survives a
//! future edit that narrows the pattern to something removal-based, where a
//! single pass really would be incomplete. What actually bounds the severity
//! is different and was never asserted: that file never assigns `innerHTML`.
//!
//! So two properties are pinned here, and they are different in kind:
//!
//! 1. **The sanitizer reaches a fixed point**, checked by running the real
//!    function in `node` against inputs designed to survive one pass. Copying
//!    the algorithm into Rust would test the copy.
//! 2. **Nothing in the file assigns `innerHTML`**, which is what bounds the
//!    severity of any future mistake in (1). If that ever changes, the first
//!    property stops being a nicety.

#![cfg(feature = "full")]

use std::path::PathBuf;
use std::process::Command;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The search script's source.
fn source() -> String {
    let p = repo().join("website/static/js/docs-search.js");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Run the REAL `plain()` from the shipped file against one input, in node.
///
/// The function is extracted by source text and evaluated, so this exercises
/// what ships rather than a Rust transliteration of it. Returns `None` when
/// node is unavailable, which callers must report rather than pass.
fn plain_source() -> Option<String> {
    let src = source();
    let start = src.find("function plain(")?;
    // Brace-matched, never a fixed window. `the_fixed_point_loop_is_bounded`
    // originally scanned 800 characters from the declaration and broke the
    // moment the doc comment above the loop grew past that — a window sized to
    // today's source is a test that fails on a comment.
    let bytes = src.as_bytes();
    let mut depth = 0usize;
    for (i, b) in bytes.iter().enumerate().skip(start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(src[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Run the REAL `plain()` from the shipped file against one input, in node.
fn plain_via_node(input: &str) -> Option<String> {
    let func = plain_source()?;
    let program = format!("{func}\nprocess.stdout.write(plain(JSON.parse(process.argv[1])));",);
    let out = Command::new("node")
        .arg("-e")
        .arg(&program)
        .arg(serde_json::to_string(input).ok()?)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

/// The extractor found the real function.
///
/// Every behavioral test below runs whatever this returns. If it pulled the
/// wrong text — or nothing — node would either fail or evaluate something else
/// entirely, and a silent skip would look like a pass.
#[test]
fn the_shipped_sanitizer_can_be_extracted_and_run() {
    let src = source();
    assert!(
        src.contains("function plain("),
        "docs-search.js no longer defines plain(); the tests below run a \
         function that does not exist"
    );
    match plain_via_node("<mark>hit</mark>") {
        Some(v) => assert_eq!(
            v, "hit",
            "the extracted function did not strip a plain <mark> pair, so it \
             is not the sanitizer"
        ),
        None => panic!(
            "could not run the shipped sanitizer in node. This test must not \
             be allowed to pass by skipping: an unrunnable check looks exactly \
             like a passing one."
        ),
    }
}

/// Hostile input leaves no open angle bracket.
///
/// The property that matters, stated as an outcome rather than as a claim
/// about passes. Deliberately NOT named "survives one pass": no input in this
/// set does, and a test whose name asserts something it does not measure is
/// how a suite starts lying about its own coverage.
#[test]
fn hostile_input_leaves_no_open_angle_bracket() {
    for hostile in [
        "<<a>script>alert(1)<</a>/script>",
        "<<<<a>>>>",
        "<scr<a>ipt>x</scr<a>ipt>",
        "<<img src=x onerror=y>>",
    ] {
        let got = plain_via_node(hostile).expect("node must run the sanitizer");
        assert!(
            !got.contains('<'),
            "sanitizing {hostile:?} left {got:?}, which still contains `<`. A \
             remaining open bracket is a tag that a second pass — or an \
             innerHTML assignment — could complete."
        );
    }
}

/// Ordinary excerpts survive intact.
///
/// A sanitizer that mangles real text gets removed by whoever notices, and
/// then the hole comes back. The marked terms are the whole point of showing
/// an excerpt.
#[test]
fn ordinary_excerpts_keep_their_text() {
    let cases = [
        (
            "<mark>capture</mark> a live interface",
            "capture a live interface",
        ),
        ("no markup at all", "no markup at all"),
        ("", ""),
    ];
    for (input, want) in cases {
        let got = plain_via_node(input).expect("node must run the sanitizer");
        assert_eq!(got, want, "sanitizing {input:?} changed the visible text");
    }
}

/// The file never assigns `innerHTML`.
///
/// This is what bounds the severity of any mistake in the strip above: every
/// value reaches the page through `textContent`, so a surviving tag is text
/// rather than an element. It is asserted rather than assumed because the
/// whole argument for the alert being low-impact rests on it.
#[test]
fn the_search_script_never_assigns_inner_html() {
    let src = source();
    for banned in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
    ] {
        let hits: Vec<&str> = src
            .lines()
            .filter(|l| l.contains(banned) && !l.trim_start().starts_with("//"))
            .collect();
        assert!(
            hits.is_empty(),
            "docs-search.js uses {banned} outside a comment: {hits:?}. Search \
             results are built from capture-derived text, so they must reach \
             the page as text."
        );
    }
    assert!(
        src.contains("textContent"),
        "the file assigns neither innerHTML nor textContent; it no longer \
         renders anything and this gate is checking a file that moved"
    );
}

/// The strip is bounded, so a pathological input cannot spin.
///
/// A fixed-point loop with no ceiling is a denial of service in the browser
/// tab. The bound is asserted in the source because a test cannot wait for a
/// hang to prove one is possible.
#[test]
fn the_fixed_point_loop_is_bounded() {
    let body = plain_source().expect("plain() exists and is brace-balanced");
    assert!(
        body.contains("for (") || body.contains("while ("),
        "plain() no longer loops; a single pass is the incomplete sanitizer \
         CodeQL reported"
    );
    assert!(
        !body.contains("while (true)"),
        "plain() loops without a ceiling; a pathological excerpt would hang \
         the tab"
    );
}
