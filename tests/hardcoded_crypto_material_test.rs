// SPDX-License-Identifier: MIT OR Apache-2.0

//! No string literal may be handed to anything named like cryptographic material.
//!
//! # The defect this exists for
//!
//! CodeQL's `rust/hard-coded-cryptographic-value` raised nine alerts on `main`
//! in one commit: nine test fixtures in `src/security/digest_leak.rs` built a
//! 401 challenge with a literal `nonce` argument. Production code takes nonces
//! from the wire and was clean, but nothing local looked for the shape, the
//! alerts sat on the security tab, and three releases were tagged past them.
//! This is the local half of the fix: the same shape CodeQL flags, checked in
//! seconds before a commit, in production code AND in tests -- a fixture nonce
//! is derived, never pasted, so the scanner has nothing to say.

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Names that make a literal argument or assignment cryptographic material.
const MATERIAL: &[&str] = &[
    "nonce",
    "key",
    "secret",
    "iv",
    "salt",
    "password",
    "passphrase",
    "cnonce",
];

/// Splits a Rust file into (production, tests) at its `#[cfg(test)]` module.
fn split_cfg_test(src: &str) -> (&str, &str) {
    match src.find("#[cfg(test)]") {
        Some(i) => (&src[..i], &src[i..]),
        None => (src, ""),
    }
}

/// The one permitted exception: a line ending in `// material: fixture -- <why>`
/// names a literal that IS the test's subject (a parser that must accept these
/// bytes), with its reason beside it. Every exception is named, none is silent.
const EXCEPTION: &str = "// material: fixture --";

/// Lines where a string literal is handed to something named like material:
/// `nonce = "..."`, `nonce: "..."`, `let nonce = "..."`, and the call-site
/// shape CodeQL flagged, a literal `"n-…"` argument. `key` alone is matched
/// only as an assignment (`let key = "…"`, `key = "…"`): a struct field named
/// `key` is usually a lookup key, and `key: "jitter_warn_ms"` is not material.
fn offending_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in src.lines().enumerate() {
        let l = line.trim();
        if l.starts_with("//") || l.contains(EXCEPTION) {
            continue;
        }
        let material = MATERIAL.iter().filter(|m| **m != "key").any(|m| {
            l.contains(&format!("{m} = \""))
                || l.contains(&format!("{m}: \""))
                || l.contains(&format!("let {m} = \""))
        });
        let key_assigned = l.contains("let key = \"") || l.starts_with("key = \"");
        let nonce_arg = l.contains("\"n-") && l.contains('(');
        if material || key_assigned || nonce_arg {
            out.push((n + 1, l.to_string()));
        }
    }
    out
}

/// The 1-based line on which `part` begins inside `whole`, for absolute numbers.
fn first_line_of(whole: &str, part: &str) -> usize {
    let off = part.as_ptr() as usize - whole.as_ptr() as usize;
    whole[..off].matches('\n').count() + 1
}

fn rust_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).expect("read_dir") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut v = Vec::new();
    walk(&repo().join("src"), &mut v);
    v.sort();
    v
}

#[test]
fn production_code_hands_no_literal_to_cryptographic_material() {
    let mut bad = Vec::new();
    for p in rust_sources() {
        let src = std::fs::read_to_string(&p).expect("read");
        let (prod, _) = split_cfg_test(&src);
        for (n, l) in offending_lines(prod) {
            let n = n + first_line_of(&src, prod) - 1;
            bad.push(format!(
                "{}:{n}: {l}",
                p.strip_prefix(repo()).unwrap().display()
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "literal cryptographic material in production code:\n{}",
        bad.join("\n")
    );
}

/// Test fixtures too: CodeQL scans them, and a pasted nonce is what it flagged.
/// A fixture derives its nonce (see `digest_leak::tests::nonce_for`).
#[test]
fn test_fixtures_derive_their_nonces_rather_than_paste_them() {
    let mut bad = Vec::new();
    for p in rust_sources() {
        let src = std::fs::read_to_string(&p).expect("read");
        let (_, tests) = split_cfg_test(&src);
        for (n, l) in offending_lines(tests) {
            let n = n + first_line_of(&src, tests) - 1;
            bad.push(format!(
                "{}:{n}: {l}",
                p.strip_prefix(repo()).unwrap().display()
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "test code hands a literal to cryptographic material (CodeQL will flag each):\n{}",
        bad.join("\n")
    );
}

/// POSITIVE CONTROL: the matcher sees every shape it claims to.
#[test]
fn the_matcher_reports_each_literal_material_shape() {
    let src = "let nonce = \"abc\";\nlet a = Auth { secret: \"x\" };\nchallenge(\"a\", 1, \"b\", \"n-shared\");\n";
    let hits: Vec<usize> = offending_lines(src).into_iter().map(|(n, _)| n).collect();
    assert_eq!(hits, [1, 2, 3]);
}

/// A literal that is not material -- a Via branch, a display name -- is not reported.
#[test]
fn a_literal_that_is_not_material_is_not_reported() {
    let src = "let branch = \"z9hG4bK-a1\";\nlet name = \"alice\";\nlet nonce = extract_param(h, \"nonce\");\n";
    assert!(
        offending_lines(src).is_empty(),
        "{:?}",
        offending_lines(src)
    );
}

/// The splitter really separates production from tests, or the production
/// scan is silently reading fixtures and the fixture scan is reading nothing.
#[test]
fn the_cfg_test_splitter_keeps_fixtures_out_of_the_production_scan() {
    let src =
        "fn real() {}\n#[cfg(test)]\nmod tests {\n    fn f() { let nonce = \"pasted\"; }\n}\n";
    let (prod, tests) = split_cfg_test(src);
    assert!(
        offending_lines(prod).is_empty(),
        "production half must not see the fixture"
    );
    assert_eq!(offending_lines(tests).len(), 1, "the fixture half must");
    let (all, none) = split_cfg_test("fn only() {}\n");
    assert!(
        !all.is_empty() && none.is_empty(),
        "no test module: everything is production"
    );
}

/// A struct field named `key` holding a lookup name is not material.
#[test]
fn a_lookup_key_field_is_not_material() {
    let src = "Row { key: \"jitter_warn_ms\", .. }\nlet key = \"k3y\";\n";
    let hits: Vec<usize> = offending_lines(src).into_iter().map(|(n, _)| n).collect();
    assert_eq!(hits, [2], "only the assignment is material");
}

/// The named exception is honored, and only in its exact form with a reason.
#[test]
fn a_named_fixture_exception_is_honored_and_a_bare_one_is_not() {
    let ok = "let key = \"k3y\"; // material: fixture -- the parser must accept these bytes\n";
    assert!(
        offending_lines(ok).is_empty(),
        "a named exception with its reason is skipped"
    );
    let bare = "let key = \"k3y\"; // fixture\n";
    assert_eq!(
        offending_lines(bare).len(),
        1,
        "an unexplained comment is not an exception"
    );
}
