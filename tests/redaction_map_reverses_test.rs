// SPDX-License-Identifier: MIT OR Apache-2.0

//! The redaction map must reverse the export, and reverse it to ORIGINALS.
//!
//! `--redact-map` is the artifact somebody uses to un-redact a capture they
//! were sent. It is written 0600 because it is exactly as sensitive as the
//! capture it came from, and it is only worth that if reversing a token yields
//! the value it stands for.
//!
//! On 2026-09-02 it did not. `src/output/vcon.rs` replaced the Call-ID in
//! `subject` with its token and then ran the whole string through `text()`
//! again, so the host inside the token — which looks like an ordinary
//! address — was tokenized a SECOND time. The map recorded both hops:
//!
//! ```text
//! 65.5.235.78                  -> 192.0.2.10     token -> original
//! 239.213.65.170               -> 65.5.235.78    token -> ANOTHER TOKEN
//! 253602a034d0e71e@65.5.235.78 -> call-2c9d47@192.0.2.10
//! ```
//!
//! Reversing `239.213.65.170` gave `65.5.235.78`, which reads as an IPv4
//! address and is not one. That is worse than a missing row: it is a wrong
//! answer wearing the shape of a right one, in the one file whose whole job is
//! to be authoritative about what a token stood for.
//!
//! The visible symptom was a `subject` nothing could reverse — the container
//! carried the once-tokenized address while the map keyed the twice-tokenized
//! one, so no row matched.
//!
//! The invariant below needs no knowledge of any original: **no value in the
//! map may itself be a key**. A token-to-token row is exactly that, and it
//! cannot hide behind a plausible-looking address.

#![cfg(feature = "vcon")]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const FIXTURE: &str = "website/static/demos/sample-call.pcap";

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> PathBuf {
    // The test binary lives beside the built `sipnab`.
    let mut p = std::env::current_exe().expect("current exe");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("sipnab")
}

/// One redacted export: the containers, and the map that should reverse them.
struct Export {
    dir: PathBuf,
    mappings: Vec<(String, String)>,
    containers: Vec<serde_json::Value>,
}

impl Export {
    fn run(name: &str) -> Self {
        Self::run_with_key(name, [0x5au8; 32])
    }

    /// The same export under a caller-chosen key.
    fn run_with_key(name: &str, key_bytes: [u8; 32]) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).expect("fixture dir");

        // A FIXED key, so the run is reproducible and a failure can be read.
        let key = dir.join("key");
        std::fs::write(&key, key_bytes).expect("write key");

        let map = dir.join("map.tsv");
        let out = Command::new(bin())
            .args([
                "-N",
                "-I",
                repo().join(FIXTURE).to_str().expect("fixture path"),
                "--export-vcon-when",
                "state == 'Completed'",
                "--export-vcon-dir",
                dir.join("out").to_str().expect("out dir"),
                "--redact",
                "--redact-key-file",
                key.to_str().expect("key path"),
                "--redact-map",
                map.to_str().expect("map path"),
                "--no-cli-print",
            ])
            .current_dir(repo())
            .output()
            .expect("run sipnab");
        assert!(
            out.status.success(),
            "the redacted export failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let mappings = std::fs::read_to_string(&map)
            .expect("read the redaction map")
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();

        let mut containers = Vec::new();
        for e in std::fs::read_dir(dir.join("out"))
            .expect("read out dir")
            .flatten()
        {
            if e.path().extension().is_some_and(|x| x == "json") {
                let text = std::fs::read_to_string(e.path()).unwrap_or_default();
                if let Ok(v) = serde_json::from_str(&text) {
                    containers.push(v);
                }
            }
        }
        Self {
            dir,
            mappings,
            containers,
        }
    }

    fn discard(self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// No token reverses to another token.
///
/// The invariant that needs no originals. A row whose value is itself a key
/// means the value was redacted twice, and whoever reverses it gets a token
/// back believing it is the real thing.
#[test]
fn no_mapping_reverses_to_another_token() {
    let export = Export::run("redact_map_chain");
    let keys: BTreeSet<&str> = export.mappings.iter().map(|(k, _)| k.as_str()).collect();

    let chained: Vec<String> = export
        .mappings
        .iter()
        .filter(|(_, v)| keys.contains(v.as_str()))
        .map(|(k, v)| format!("  {k} -> {v}   (and {v} is itself a token)"))
        .collect();

    let count = export.mappings.len();
    export.discard();

    assert!(
        count >= 4,
        "only {count} mapping(s); the export produced almost nothing and this \
         gate proves little"
    );
    assert!(
        chained.is_empty(),
        "the redaction map reverses {} token(s) to ANOTHER token. Whoever \
         un-redacts the export gets a value that looks like the real thing and \
         is not:\n{}",
        chained.len(),
        chained.join("\n")
    );
}

/// The subject reverses through the map.
///
/// The operator-visible half. `subject` is what a store searches on, so a
/// container whose subject no row can reverse is one nobody can trace back.
#[test]
fn the_container_subject_reverses_through_the_map() {
    let export = Export::run("redact_map_subject");
    let keys: BTreeSet<&str> = export.mappings.iter().map(|(k, _)| k.as_str()).collect();

    let mut unreversible = Vec::new();
    let mut checked = 0;
    for c in &export.containers {
        let Some(subject) = c.get("subject").and_then(|s| s.as_str()) else {
            continue;
        };
        // The token is the last whitespace-separated word: `SIP call <token>`.
        let Some(token) = subject.split_whitespace().last() else {
            continue;
        };
        if !token.contains('@') {
            continue; // not a Call-ID-shaped subject
        }
        checked += 1;
        if !keys.contains(token) {
            unreversible.push(format!(
                "  subject {subject:?} -> token {token:?} has no row"
            ));
        }
    }

    let containers = export.containers.len();
    export.discard();

    assert!(
        containers >= 1,
        "no containers were exported; this gate examined nothing"
    );
    assert!(
        checked >= 1,
        "no container carried a Call-ID-shaped subject; the extraction is \
         wrong and this gate proves nothing"
    );
    assert!(
        unreversible.is_empty(),
        "these subjects cannot be reversed through the map, so a consumer \
         holding both the container and the map still cannot say which call \
         it was:\n{}",
        unreversible.join("\n")
    );
}

/// Reversing the whole container leaves no token behind.
///
/// The end-to-end statement of what the map is for: apply every row and the
/// result should contain nothing that still needs reversing.
#[test]
fn applying_every_mapping_leaves_no_token_in_the_container() {
    let export = Export::run("redact_map_roundtrip");
    let mut leftover = Vec::new();
    let containers = export.containers.len();

    for c in &export.containers {
        let mut text = serde_json::to_string(c).unwrap_or_default();
        for (token, original) in &export.mappings {
            text = text.replace(token.as_str(), original.as_str());
        }
        // Any token still present after applying every row is one the map
        // could not account for.
        for (token, _) in &export.mappings {
            if text.contains(token.as_str()) {
                leftover.push(format!("  {token} survives a full reversal"));
            }
        }
    }
    export.discard();

    assert!(containers >= 1, "no containers exported");
    leftover.sort();
    leftover.dedup();
    assert!(
        leftover.is_empty(),
        "applying every mapping still leaves tokens in the container, so the \
         map is not a complete reversal of the export:\n{}",
        leftover.join("\n")
    );
}

// ── the six owed for the three that failed ──────────────────────────
//
// The three gates above failed before the fix, which is the point of writing
// them first — but a failing test is a debt at the standing rate, and the
// class is wider than the one defect. A redaction map is only worth its 0600
// if it is COMPLETE, SINGLE-HOP, UNAMBIGUOUS and KEYED. Each of those can
// break independently, and each breaks quietly.

/// No row reverses a token to itself.
///
/// A row whose key equals its value means nothing was redacted for that value
/// while the map claims something was. Reversing it is a no-op, and the reader
/// concludes the original was already a pseudonym.
#[test]
fn no_mapping_reverses_a_token_to_itself() {
    let export = Export::run("redact_map_identity");
    let identity: Vec<String> = export
        .mappings
        .iter()
        .filter(|(k, v)| k == v)
        .map(|(k, _)| format!("  {k} -> {k}"))
        .collect();
    let count = export.mappings.len();
    export.discard();

    assert!(
        count >= 4,
        "only {count} mapping(s); this gate proves little"
    );
    assert!(
        identity.is_empty(),
        "these rows reverse a token to itself, so the map asserts a redaction \
         that did not happen:\n{}",
        identity.join("\n")
    );
}

/// No token appears twice with different originals.
///
/// Two rows keying one token is an ambiguous reversal: whoever applies the map
/// gets whichever row they read first, and nothing says the other exists.
#[test]
fn no_token_is_mapped_to_two_different_originals() {
    let export = Export::run("redact_map_ambiguous");
    let mut seen: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    let mut clashes = Vec::new();
    for (k, v) in &export.mappings {
        match seen.get(k.as_str()) {
            Some(first) if *first != v.as_str() => {
                clashes.push(format!("  {k} -> {first}  AND  {k} -> {v}"));
            }
            Some(_) => {}
            None => {
                seen.insert(k, v);
            }
        }
    }
    let count = export.mappings.len();
    export.discard();

    assert!(
        count >= 4,
        "only {count} mapping(s); this gate proves little"
    );
    assert!(
        clashes.is_empty(),
        "these tokens reverse to more than one original, so a reversal is a \
         coin toss:\n{}",
        clashes.join("\n")
    );
}

/// No original survives unredacted in the container.
///
/// The promise the whole feature exists for, and it is checkable without
/// knowing the capture: every ORIGINAL is a value in the map, so if one still
/// appears in the exported container, redaction missed it. That is the failure
/// that puts a customer's address in a file somebody mailed to a vendor.
#[test]
fn no_original_survives_in_the_exported_container() {
    let export = Export::run("redact_map_leak");
    let mut leaks = Vec::new();
    let containers = export.containers.len();

    for c in &export.containers {
        let text = serde_json::to_string(c).unwrap_or_default();
        for (token, original) in &export.mappings {
            // An original that is also a token elsewhere would be a chained
            // row, which `no_mapping_reverses_to_another_token` owns.
            if original.len() >= 4 && text.contains(original.as_str()) {
                leaks.push(format!(
                    "  {original:?} appears in the container, though the map \
                     says it was replaced by {token:?}"
                ));
            }
        }
    }
    export.discard();

    assert!(
        containers >= 1,
        "no containers exported; this gate saw nothing"
    );
    leaks.sort();
    leaks.dedup();
    assert!(
        leaks.is_empty(),
        "these originals survived into the redacted export:\n{}",
        leaks.join("\n")
    );
}

/// The same key produces the same map, twice.
///
/// `--redact-key-file` exists so two captures of one incident redact
/// consistently. If a run were not deterministic, the same endpoint would carry
/// a different pseudonym in each file and the correlation the operator needs
/// would be destroyed by the tool meant to preserve it.
#[test]
fn one_key_produces_the_same_mapping_twice() {
    let a = Export::run("redact_det_a");
    let b = Export::run("redact_det_b");
    let (ma, mb) = (a.mappings.clone(), b.mappings.clone());
    let count = ma.len();
    a.discard();
    b.discard();

    assert!(
        count >= 4,
        "only {count} mapping(s); this gate proves little"
    );
    assert_eq!(
        ma, mb,
        "two runs with the same key produced different maps, so one endpoint \
         carries two pseudonyms across two captures of one incident"
    );
}

/// A different key produces different tokens.
///
/// The paired half. A map identical under every key would mean the pseudonyms
/// are a fixed function of the input — reversible by anyone who runs sipnab
/// once, which is not a pseudonym at all.
#[test]
fn a_different_key_produces_different_tokens() {
    let a = Export::run("redact_key_a");
    let tokens_a: BTreeSet<String> = a.mappings.iter().map(|(k, _)| k.clone()).collect();
    a.discard();

    let b = Export::run_with_key("redact_key_b", [0xa5u8; 32]);
    let tokens_b: BTreeSet<String> = b.mappings.iter().map(|(k, _)| k.clone()).collect();
    let count = tokens_b.len();
    b.discard();

    assert!(count >= 4, "only {count} token(s); this gate proves little");
    assert!(
        tokens_a.intersection(&tokens_b).count() == 0,
        "two different keys produced overlapping tokens, so the key is not \
         what determines the pseudonym"
    );
}

/// The map is written 0600.
///
/// It reverses every token in the export, so it is exactly as sensitive as the
/// capture. A map left world-readable beside a redacted file undoes the
/// redaction for anyone on the box.
#[test]
#[cfg(unix)]
fn the_map_file_is_written_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let export = Export::run("redact_map_mode");
    let mode = std::fs::metadata(export.dir.join("map.tsv"))
        .expect("stat the map")
        .permissions()
        .mode()
        & 0o777;
    export.discard();
    assert_eq!(
        mode, 0o600,
        "the redaction map is mode {mode:o}, not 0600. It reverses every token \
         in the export, so it is as sensitive as the capture it came from."
    );
}
