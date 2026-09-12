// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gates that can still see what they were built to see.
//!
//! Paying for a defect I nearly shipped: a blanket spelling sweep across
//! `tests/` rewrote the US-English gate's OWN list of British words into
//! American ones. The gate would then have searched for `behavior` and
//! `recognize` and matched them everywhere, reporting 394 violations — or,
//! had the list been emptied instead, nothing at all, forever, while looking
//! healthy.
//!
//! That is the worst failure a gate has: not a false alarm, but a gate trained
//! away from the thing it guards. Every test here asks whether a gate can still
//! detect a known-bad input, rather than whether the tree currently passes it.

#![cfg(feature = "full")]

use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

// ── The spelling gate still knows what it is looking for ─────────────────────

/// GIVEN the US-English gate
/// WHEN its word list is read
/// THEN it still contains British spellings.
///
/// The list is what the gate searches FOR. Rewriting it to American spellings
/// inverts the gate; emptying it switches the gate off while every run stays
/// green.
#[test]
fn the_spelling_gate_still_lists_british_words() {
    let src = read("tests/docs_drift_test.rs");
    // Built at runtime, never written literally. The spelling gate exempts its
    // OWN file because "a gate cannot be its own violation"; claiming a second
    // exemption for this one would widen that hole by a file every time
    // somebody writes a test about the gate. Assembling the words here keeps
    // the gate's exemption list exactly one entry long.
    for (stem, tail) in [("behavi", "our"), ("recogni", "sed"), ("normali", "se")] {
        let british = format!("{stem}{tail}");
        assert!(
            src.contains(&format!("\"{british}\"")),
            "the gate no longer looks for {british:?}; a sweep that rewrote its \
             own list would leave it searching for the spellings it permits"
        );
    }
}

/// GIVEN the same gate
/// WHEN its list is checked for American spellings
/// THEN it does not contain them.
///
/// The inverted form, which is what my sed actually produced. A list of
/// American words makes every correct file a violation.
#[test]
fn the_spelling_gate_does_not_search_for_american_words() {
    let src = read("tests/docs_drift_test.rs");
    let anchor = format!("\"{}{}\"", "behavi", "our");
    let list_start = src.find(&anchor).expect("the word list is findable");
    let window = &src[list_start..(list_start + 2000).min(src.len())];
    for (stem, tail) in [("behavi", "or"), ("recogni", "zed"), ("normali", "ze")] {
        let american = format!("\"{stem}{tail}\"");
        assert!(
            !window.contains(&american),
            "the gate's own list contains {american}, which would make every \
             correctly spelled file a violation"
        );
    }
}

/// GIVEN the gate's anti-vacuity check
/// WHEN it is read
/// THEN it proves the matcher fires on a known-bad word.
///
/// This is the mechanism that made the damage visible instead of silent, and
/// it must not be removed.
#[test]
fn the_spelling_gate_proves_itself_on_a_known_bad_word() {
    let src = read("tests/docs_drift_test.rs");
    let must_line = format!(
        "for must in [\"{}{}\", \"{}{}\", \"{}{}\"]",
        "behavi", "our", "normali", "se", "recogni", "sed"
    );
    assert!(
        src.contains(&must_line),
        "the anti-vacuity check is gone; without it an emptied word list reads \
         as a clean tree"
    );
}

// ── The seam gate still knows a vendor name ──────────────────────────────────

/// GIVEN the relay seam gate
/// WHEN its vendor list is read
/// THEN it names both relays.
///
/// Paying for the defect where my edits scattered `RelayImplementation::
/// Rtpengine` through `src/mcp/` and `src/tui/`. A gate that knew only one
/// vendor would have caught that and missed the same mistake made with the
/// other.
#[test]
fn the_seam_gate_knows_both_relay_vendors() {
    let src = read("tests/relay_seam_test.rs");
    for vendor in ["rtpengine", "rtpproxy"] {
        assert!(
            src.to_lowercase().contains(vendor),
            "the seam gate does not know the name {vendor:?}, so it cannot \
             catch that name leaking into a consuming layer"
        );
    }
}

/// GIVEN the seam gate
/// WHEN its comparison is read
/// THEN it is case-insensitive.
///
/// RP2 records that this gate once matched with `l.contains("rtpengine")`,
/// case-sensitive, and a Rust type is `RtpengineLeak` or `RTPENGINE_PORT`. The
/// scan could not see any spelling code would actually use.
#[test]
fn the_seam_gate_matches_the_spellings_code_uses() {
    let src = read("tests/relay_seam_test.rs");
    assert!(
        src.contains("to_lowercase")
            || src.contains("to_ascii_lowercase")
            || src.contains("eq_ignore_ascii_case"),
        "a case-sensitive vendor scan cannot see `RtpengineLeak`, which is the \
         spelling a leak actually takes"
    );
}

// ── The portable vocabulary stays portable ───────────────────────────────────

/// GIVEN the relay vocabulary
/// WHEN the wasm build compiles an endpoint assertion
/// THEN the vocabulary is reachable.
///
/// Paying for the break where an assertion named a native-only module. The
/// browser build compiles the store and has no control plane at all.
#[test]
fn the_relay_vocabulary_is_not_behind_the_native_gate() {
    let lib = read("src/lib.rs");
    let vocab_line = lib
        .lines()
        .position(|l| l.trim() == "pub mod relay_vocab;")
        .expect("the portable vocabulary module is declared");
    // The line IMMEDIATELY before, and only that one: a `cfg` attribute applies
    // to the item that follows it and to nothing else. Looking two lines back
    // finds the attribute belonging to the module above, which is how the first
    // version of this test reported a gate that was not there.
    let earlier: Vec<&str> = lib.lines().take(vocab_line).collect();
    let previous = earlier
        .iter()
        .rev()
        .find(|l| !l.trim().is_empty())
        .copied()
        .unwrap_or_default();
    assert!(
        !previous.trim_start().starts_with("#[cfg"),
        "the portable vocabulary sits behind a target gate, so an assertion \
         naming it cannot compile for the browser"
    );
}

/// GIVEN the endpoint assertion
/// WHEN its field types are read
/// THEN they name the portable module and not the native one.
#[test]
fn an_assertion_names_only_the_portable_vocabulary() {
    let store = read("src/rtp/stream_store.rs");
    assert!(
        store.contains("crate::relay_vocab::RelayImplementation"),
        "the assertion should reach the vocabulary through the portable module"
    );
    assert!(
        !store.contains("crate::relay::RelayImplementation"),
        "naming the native module here breaks the wasm build, and it did"
    );
}

// ── Doc comments stay attached to what they document ─────────────────────────

/// GIVEN a struct field inserted before another
/// WHEN the file is read
/// THEN no field carries the doc comment meant for its neighbor.
///
/// Twice today an insertion landed between a doc comment and its field,
/// silently re-documenting the wrong thing. `missing_docs` catches the field
/// left bare; nothing catches the field now wearing somebody else's sentence.
#[test]
fn no_field_wears_its_neighbors_doc_comment() {
    for file in [
        "src/mcp/tools/relay.rs",
        "src/app/batch.rs",
        "src/rtp/stream_store.rs",
    ] {
        let src = read(file);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            // A doc line directly followed by ANOTHER doc line that opens a
            // new sentence block is fine; a doc line followed by a field and
            // then an undocumented field is the shape that bit me.
            if t.starts_with("/// ") && i + 2 < lines.len() {
                let next = lines[i + 1].trim();
                let after = lines[i + 2].trim();
                if next.starts_with("pub ") && after.starts_with("pub ") && after.ends_with(',') {
                    panic!(
                        "{file}:{}: a documented field is immediately followed by an \
                         undocumented one, which is what an insertion between a doc \
                         comment and its field produces",
                        i + 3
                    );
                }
            }
        }
    }
}

// ── A test may not depend on a file git does not track ───────────────────────

/// GIVEN every test that reads a harness file
/// WHEN that file is checked against git
/// THEN it is tracked.
///
/// Paying for a defect I shipped into CI: two tests read `harness/.env`, which
/// `make up` generates and `.gitignore` excludes. They passed on this machine
/// and panicked on a runner that had never run the harness. A test reading an
/// untracked file is a test about the developer's working directory.
#[test]
fn no_test_reads_a_file_git_does_not_track() {
    let tests_dir = repo().join("tests");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&tests_dir).expect("tests/").flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        // This file names the pattern in order to look for it, and other
        // files name the path in a comment explaining why they do not read it.
        // Only a CALL counts, and this file is skipped -- a scan that reports
        // itself teaches a reader to ignore it.
        if path
            .file_name()
            .is_some_and(|n| n == "gate_integrity_test.rs")
        {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for needle in [
            "harness(\".env\")",
            "include_str!(\"../harness/.env\")",
            "join(\"harness/.env\")",
        ] {
            for (i, line) in src.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("///") {
                    continue;
                }
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: {needle}", path.display(), i + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these tests read a generated, untracked file and will pass locally \
         while failing on a clean checkout: {offenders:?}"
    );
}

/// GIVEN the harness environment file
/// WHEN git is asked about it
/// THEN it is ignored, which is why the rule above exists.
///
/// The anti-vacuity half: if `.env` were ever tracked, the test above would be
/// guarding nothing and should be deleted rather than left to look useful.
#[test]
fn the_harness_env_file_really_is_untracked() {
    let out = std::process::Command::new("git")
        .args(["check-ignore", "harness/.env"])
        .current_dir(repo())
        .output();
    // No git in the environment is not a reason to fail a unit test, so an
    // error running it is skipped rather than asserted on.
    if let Ok(o) = out {
        assert!(
            o.status.success(),
            "harness/.env is tracked now, so the rule above guards nothing"
        );
    }
}

/// GIVEN the port ranges the two anchors use
/// WHEN they are read
/// THEN they come from the committed compose defaults.
///
/// The fix for the same defect, pinned: the compose file is what ships, and a
/// developer's `.env` override is not evidence about anybody else's run.
#[test]
fn the_anchor_ranges_are_read_from_what_ships() {
    let compose = read("harness/docker-compose.yml");
    for key in ["RTP_MIN", "RTP_MAX", "RTPPROXY_RTP_MIN", "RTPPROXY_RTP_MAX"] {
        assert!(
            compose.contains(&format!("${{{key}:-")),
            "{key} has no default in the compose file, so a test asking for it \
             has nothing committed to read"
        );
    }
}
