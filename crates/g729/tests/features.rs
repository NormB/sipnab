// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--all-features` (as CI runs it) must not switch on anything that needs
//! local oracle data or skips the table values check: those are cfg flags
//! (`--cfg g729_oracle`, and `cfg(fuzzing)` set by cargo-fuzz), never
//! features.

#[test]
fn the_manifest_declares_only_general_features() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))?;
    let section = manifest
        .split("[features]")
        .nth(1)
        .ok_or("Cargo.toml has no [features]")?
        .split("\n[")
        .next()
        .unwrap_or("");
    let mut names: Vec<&str> = section
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('=').next().map(str::trim))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["annex-b", "default", "std"]);
    Ok(())
}
