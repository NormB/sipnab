// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pre-push corpus gate builds with a profile that unwinds and skips LTO.
//!
//! The gate runs every corpus binary under one cargo profile. Two properties of
//! that profile decide whether the gate works and what it costs:
//!
//! * `panic = "unwind"`. Under `abort` a failing test kills its process before
//!   libtest prints the `failures:` list, and the gate blocks a push without
//!   being able to say what broke.
//! * no full LTO. The gate used `profiling`, which inherits release's
//!   `lto = true` and `codegen-units = 1`. Measured 2026-09-29 on 14 cores, the
//!   21 corpus binaries rebuilt in 827 s after a library change; with
//!   `lto = false` and 16 codegen units, 83 s. The run cost 161 s against
//!   174 s, so LTO saved 13 s per push and cost 12 minutes on every push that
//!   touched the library.

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// The profile the corpus gate passes to `cargo test`.
fn gate_profile() -> String {
    let hook = read(".githooks/pre-push");
    let line = hook
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("set -- --all-features --profile "))
        .expect("the corpus gate's `set -- --all-features --profile <name>` line");
    line.split_whitespace()
        .nth(4)
        .expect("a profile name after --profile")
        .to_string()
}

/// `key = value` lines of `[profile.<name>]` in Cargo.toml, verbatim.
fn profile_table(name: &str) -> Vec<(String, String)> {
    let cargo = read("Cargo.toml");
    let header = format!("[profile.{name}]");
    let Some(start) = cargo.find(&format!("\n{header}\n")) else {
        return Vec::new();
    };
    cargo[start + header.len() + 2..]
        .lines()
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| l.split_once(" = "))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn setting(table: &[(String, String)], key: &str) -> Option<String> {
    table.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

#[test]
fn the_corpus_gate_profile_exists_and_unwinds() {
    let name = gate_profile();
    let table = profile_table(&name);
    assert!(
        !table.is_empty(),
        "the corpus gate runs `--profile {name}`, and Cargo.toml has no [profile.{name}]"
    );
    assert_eq!(
        setting(&table, "panic").as_deref(),
        Some("\"unwind\""),
        "[profile.{name}] must set panic = \"unwind\": under abort a failing corpus \
         test dies before libtest names it"
    );
}

#[test]
fn the_corpus_gate_profile_skips_full_lto() {
    let name = gate_profile();
    let table = profile_table(&name);
    assert_eq!(
        setting(&table, "lto").as_deref(),
        Some("false"),
        "[profile.{name}] must set lto = false: full LTO made the corpus binaries \
         rebuild in 827 s after a library change, against 83 s without it"
    );
}

/// POSITIVE CONTROL: the table reader sees a profile Cargo.toml really has,
/// so an empty result above means a missing profile, not a broken reader.
#[test]
fn the_profile_reader_finds_the_release_profile() {
    let release = profile_table("release");
    assert_eq!(setting(&release, "lto").as_deref(), Some("true"));
    assert_eq!(setting(&release, "panic").as_deref(), Some("\"abort\""));
}
