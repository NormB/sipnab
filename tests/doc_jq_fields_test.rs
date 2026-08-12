// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every field the docs tell a reader to `jq` must exist in the output the
//! same block produces.
//!
//! This gate exists because of a specific failure. `cli-reference.md` shipped
//!
//! ```text
//! sipnab -N -I capture.pcap --json | jq -r '.user_agent // empty' | sort -u
//! ```
//!
//! as the recipe for "distinct User-Agents". The NDJSON field is `ua`, so the
//! pipeline matched nothing, and `// empty` swallowed the miss: a reader got
//! zero lines and concluded the capture held no User-Agents. Nothing failed,
//! nothing warned, and the answer was wrong. That is worse than a broken
//! command, which at least announces itself.
//!
//! Prose review cannot catch this — `.user_agent` reads perfectly well. Only
//! running it against real output can, which is what this does: no `jq`
//! binary is required, because the check is "does this key exist in what the
//! documented mode emits", and that is answerable from the JSON itself.

#![cfg(feature = "native")]

use std::collections::BTreeSet;
use std::path::Path;

/// A documented pipeline: the output mode a block invokes, and the fields its
/// `jq` reads from it.
#[derive(Debug)]
struct Recipe {
    doc: String,
    mode: Mode,
    fields: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    /// `--json`: one object per SIP message.
    Messages,
    /// `--json-dialogs`: one object per dialog.
    Dialogs,
}

/// Fields that are legitimately absent from a flat key scan.
///
/// `jq` reaches into nested objects and arrays, and this gate only compares
/// top-level keys. A path like `.streams` is a real top-level key; a path like
/// `.mos` is read from inside an element of it. Rather than half-parse jq,
/// the nested readers are named here so the gate stays honest about what it
/// does and does not prove.
const NESTED_OR_DERIVED: &[&str] = &[
    "mos",               // inside .streams[] / .rtp
    "ssrc",              // inside .streams[]
    "dialogs",           // a wrapper the REST API returns, not NDJSON
    "streams",           // present on dialogs, read as an array
    "associated_dialog", // stream-scoped
    "duration_sec",      // dialog-scoped, name varies by surface
    "from_user",         // dialog-scoped
    "to_user",           // dialog-scoped
    "state",             // dialog-scoped
];

/// Pull `sipnab ... --json* ... | jq '...'` pairs out of fenced blocks.
fn recipes() -> Vec<Recipe> {
    let mut out = Vec::new();
    let docs = std::fs::read_dir("docs").expect("docs/ must exist");
    for entry in docs.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read doc");
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        for block in text.split("```").skip(1).step_by(2) {
            if !block.contains("sipnab") || !block.contains("jq") {
                continue;
            }
            // `--json-dialogs` must be tested before `--json`, since it
            // contains it as a prefix.
            let mode = if block.contains("--json-dialogs") {
                Mode::Dialogs
            } else if block.contains("--json") {
                Mode::Messages
            } else {
                continue;
            };

            let mut fields = BTreeSet::new();
            for (i, _) in block.match_indices(".") {
                let rest = &block[i + 1..];
                let end = rest
                    .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .unwrap_or(rest.len());
                if end == 0 {
                    continue;
                }
                let word = &rest[..end];
                // Only bare `.field` reads directly after a quote, space, or
                // pipe — not `foo.bar` inside a filename or a URL.
                let prev = block[..i].chars().next_back().unwrap_or(' ');
                if matches!(prev, '\'' | '"' | ' ' | '|' | '(' | '[')
                    && word.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                    && !NESTED_OR_DERIVED.contains(&word)
                {
                    fields.insert(word.to_string());
                }
            }
            if !fields.is_empty() {
                out.push(Recipe {
                    doc: name.clone(),
                    mode,
                    fields,
                });
            }
        }
    }
    out
}

/// Fixtures whose UNION exercises the conditional fields.
///
/// One successful call is not enough, and assuming it was produced a false
/// alarm the first time this ran: `signaling_diagnosis` is emitted only for a
/// dialog that FAILED, so a clean capture made three accurate doc lines look
/// broken. A gate that reports correct documentation as wrong is worse than no
/// gate — it trains readers to edit working text. Every fixture here earns its
/// place by contributing a field the others do not.
const FIXTURES: &[&str] = &[
    "tests/pcap-samples/sip-rtp-g711.pcap", // answered call with RTP
    "tests/pcap-samples/sip-auth-failure.pcapng", // failed: signaling_diagnosis
    "tests/pcap-samples/sip-problem-call.pcap", // failed with a final status
    "tests/pcap-samples/sip-register.pcap", // non-INVITE dialog
];

/// Top-level keys the given mode emits across every fixture.
fn keys_for(mode: Mode) -> BTreeSet<String> {
    let flag = match mode {
        Mode::Messages => "--json",
        Mode::Dialogs => "--json-dialogs",
    };
    let mut keys = BTreeSet::new();
    for pcap in FIXTURES {
        assert!(Path::new(pcap).exists(), "fixture missing: {pcap}");
        let mut args = vec!["-N", "-I", *pcap, flag];
        if mode == Mode::Dialogs {
            args.push("--no-cli-print");
        }
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .output()
            .expect("run sipnab");
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().filter(|l| l.starts_with('{')) {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(obj) = v.as_object() {
                keys.extend(obj.keys().cloned());
                // One level down, so `.timing.setup_ms` style reads resolve.
                for nested in obj.values().filter_map(|v| v.as_object()) {
                    keys.extend(nested.keys().cloned());
                }
            }
        }
    }
    assert!(
        !keys.is_empty(),
        "{flag} produced no JSON objects across {} fixtures; the gate would \
         pass vacuously",
        FIXTURES.len()
    );
    keys
}

/// Every documented `jq` field exists in the output its own block produces.
#[test]
fn documented_jq_fields_exist_in_the_output() {
    let recipes = recipes();
    assert!(
        recipes.len() >= 3,
        "found only {} doc pipelines to check — the extractor stopped matching, \
         which would let this gate pass while checking nothing",
        recipes.len()
    );

    let messages = keys_for(Mode::Messages);
    let dialogs = keys_for(Mode::Dialogs);

    let mut bad = Vec::new();
    for r in &recipes {
        let keys = match r.mode {
            Mode::Messages => &messages,
            Mode::Dialogs => &dialogs,
        };
        for f in &r.fields {
            if !keys.contains(f) {
                bad.push(format!(
                    "{}: `.{f}` is not a field of {} output",
                    r.doc,
                    match r.mode {
                        Mode::Messages => "--json",
                        Mode::Dialogs => "--json-dialogs",
                    }
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "documented jq recipes read fields that do not exist. A reader pastes \
         these and gets a confidently empty answer:\n  {}",
        bad.join("\n  ")
    );
}
