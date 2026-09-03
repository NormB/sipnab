// SPDX-License-Identifier: MIT OR Apache-2.0

//! Two lines in `src/security/mod.rs` that must keep their relationship.
//!
//! # The defect these exist for
//!
//! Adding `pub mod destination;` by inserting directly beneath the line that
//! read `#[cfg(feature = "native")]` moved that attribute onto the new module:
//! `destination` became native-only and `detectors` -- which reaches
//! `crate::output` -- went unconditional, so the wasm build reached a module it
//! excludes. The generic attribute gate caught it; these pin the two facts that
//! matter here so the next scripted insert cannot swap them silently.
//! `destination` is pure and must build everywhere -- the bare machine is the
//! primary case -- and `detectors` must stay behind its feature gate.

use std::path::Path;

fn mod_rs() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/security/mod.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The line directly above `pub mod NAME;`, trimmed, or `None` at the top.
fn line_above(src: &str, decl: &str) -> Option<String> {
    let lines: Vec<&str> = src.lines().collect();
    let i = lines.iter().position(|l| l.trim() == decl)?;
    i.checked_sub(1).map(|j| lines[j].trim().to_string())
}

#[test]
fn destination_is_unconditional_so_a_bare_machine_has_it() {
    let above = line_above(&mod_rs(), "pub mod destination;").expect("declared");
    assert!(
        !above.starts_with("#["),
        "`pub mod destination;` sits under `{above}`: an attribute there gates a \
         pure module out of the wasm build, and probably stole it from the line below"
    );
}

#[test]
fn detectors_keeps_its_native_gate() {
    let above = line_above(&mod_rs(), "pub mod detectors;").expect("declared");
    assert_eq!(
        above, "#[cfg(feature = \"native\")]",
        "`detectors` reaches `crate::output`, which the wasm build does not compile"
    );
}

/// POSITIVE CONTROL: the reader sees the attribute when one is there.
#[test]
fn the_line_reader_reports_the_attribute_above_a_declaration() {
    let src = "pub mod a;\n#[cfg(feature = \"x\")]\npub mod b;\n";
    assert_eq!(
        line_above(src, "pub mod b;").as_deref(),
        Some("#[cfg(feature = \"x\")]")
    );
    assert_eq!(line_above(src, "pub mod a;"), None, "top of file");
}
