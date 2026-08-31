// SPDX-License-Identifier: MIT OR Apache-2.0

//! Adding a second media relay must not reach the layers above it.
//!
//! # What this is for
//!
//! sipnab talks to rtpengine today and will talk to rtpproxy next. The
//! vocabulary for that -- `ReadOnlyRelay`, `Reconciler`, `Attribution`,
//! `EndpointAssertion::relay_asserted` -- was never rtpengine-specific; it
//! lived under `src/rtpengine/` because that was the only implementation, and
//! a name is not a boundary. It now lives in `src/relay/`, and the vendor
//! module reaches it from below.
//!
//! The requirement this pins is not tidiness. It is three acceptance
//! conditions, and all three have to hold at once:
//!
//! 1. **Adding a relay adds no MCP tool.** A `query_rtpproxy` beside
//!    `query_relay` doubles the agent surface for no gain and leaves the
//!    surface-parity gate two families to keep in step.
//! 2. **Adding a relay touches no file under `src/mcp/`, `src/output/` or
//!    `src/tui/`.** Those consume attributions. They must not learn vendor
//!    names.
//! 3. **A gate enforces both**, or the seam erodes the first time somebody is
//!    in a hurry.
//!
//! This file is (3). Measured before it was written: `src/mcp/` held one
//! vendor reference, `src/output/` six and `src/tui/` two -- almost all of them
//! reaching `crate::rtpengine::media_creating_commands_seen()`, a count of
//! "commands that create media", which is a concept no vendor owns sitting
//! behind a name one vendor does.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file under one directory.
fn rust_files(rel: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join(rel)];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Names that belong to one relay implementation and to no other.
///
/// `ng` is deliberately absent as a bare token: `PcapNgReader` is pcapng and
/// has nothing to do with rtpengine's control protocol. A scanner that flagged
/// it would be trained away within a week, which is how a gate stops being
/// read.
const VENDOR_TOKENS: &[&str] = &["rtpengine", "rtpproxy", "bencode", "NgCommand", "NgMessage"];

/// Layers that consume attributions and must not know who produced them.
const CONSUMING_LAYERS: &[&str] = &["src/mcp", "src/output", "src/tui"];

/// A line that mentions a vendor outside a comment.
///
/// Comments are exempt on purpose. Explaining WHY a boundary exists means
/// naming what is on the other side of it, and a rule that forbade that would
/// make the code less legible in exchange for nothing.
fn vendor_code_lines(src: &str) -> Vec<String> {
    src.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter(|l| VENDOR_TOKENS.iter().any(|v| l.contains(v)))
        .map(str::to_string)
        .collect()
}

/// The scanners read a real tree.
#[test]
fn the_seam_scanners_read_a_real_tree() {
    for layer in CONSUMING_LAYERS {
        let files = rust_files(layer);
        assert!(
            files.len() >= 3,
            "found only {} file(s) under {layer}; the walk is not reaching them \
             and every rule below would report a clean boundary",
            files.len()
        );
    }
    assert!(
        repo().join("src/relay/mod.rs").is_file(),
        "src/relay/ is gone; the seam these rules describe does not exist"
    );
    assert!(
        !VENDOR_TOKENS.is_empty() && !CONSUMING_LAYERS.is_empty(),
        "the token or layer list is empty, so the scan matches nothing"
    );
}

/// No consuming layer names a relay vendor in code.
///
/// Acceptance condition 2. If this fires, adding rtpproxy will mean editing a
/// file whose job is rendering or answering, and the second relay will land as
/// a parallel code path rather than behind the seam.
#[test]
fn no_consuming_layer_names_a_relay_vendor() {
    let mut offenders = Vec::new();
    for layer in CONSUMING_LAYERS {
        for path in rust_files(layer) {
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            for line in vendor_code_lines(&src) {
                offenders.push(format!(
                    "  {}: {}",
                    path.display(),
                    &line[..line.len().min(90)]
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these files consume attributions and name a relay vendor in code:\n{}\n\n\
         Reach the concept through `crate::relay::` instead. A count of \
         media-creating commands, an attribution, a snapshot -- none of those \
         belong to one implementation, and naming one here is what makes the \
         second relay a second code path.",
        offenders.join("\n")
    );
}

/// No MCP tool is named after a relay vendor.
///
/// Acceptance condition 1. The agent surface describes what a caller wants to
/// know -- attribution, orphans, a relay query -- not which daemon answers.
#[test]
fn no_mcp_tool_is_named_after_a_relay_vendor() {
    let re = regex::Regex::new(r#"(?m)^\s+name = "([a-z0-9_]+)","#).expect("pattern");
    let mut tools = BTreeSet::new();
    for path in rust_files("src/mcp") {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for c in re.captures_iter(&src) {
            tools.insert(c[1].to_string());
        }
    }
    assert!(
        tools.len() >= 40,
        "found only {} MCP tool(s); the registration pattern has stopped \
         matching and this rule is examining nothing",
        tools.len()
    );
    let vendor: Vec<&String> = tools
        .iter()
        .filter(|t| {
            let l = t.to_ascii_lowercase();
            VENDOR_TOKENS
                .iter()
                .any(|v| l.contains(&v.to_ascii_lowercase()))
        })
        .collect();
    assert!(
        vendor.is_empty(),
        "these MCP tools are named after a relay implementation: {vendor:?}\n\n\
         A second relay must not add a tool. Two families answering the same \
         question is twice the surface, twice the documentation, and two things \
         for the parity gate to keep in step."
    );
}

/// The vendor module depends on the seam, not the other way round.
///
/// The direction is the whole point. If `src/relay/` imports from
/// `src/rtpengine/`, the abstraction is a folder rather than a boundary and a
/// second implementation has nowhere to attach.
#[test]
fn the_seam_does_not_depend_on_an_implementation() {
    let mut wrong = Vec::new();
    for path in rust_files("src/relay") {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for line in src.lines().map(str::trim) {
            if line.starts_with("//") {
                continue;
            }
            if line.starts_with("use ") && line.contains("rtpengine") {
                wrong.push(format!("  {}: {line}", path.display()));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "src/relay/ imports from a specific implementation:\n{}\n\nThe \
         dependency runs the other way: an implementation reaches the seam \
         from below. A seam that imports its own implementation cannot take a \
         second one.",
        wrong.join("\n")
    );
}

/// The seam writes down what an implementation owes.
///
/// A trait is a signature; a contract is a signature plus what it means. The
/// backlog entry asked for the definition explicitly -- "the boundary owes a
/// definition, not just a trait" -- because the next person adding a relay
/// needs to know what to provide and, just as much, what will never be asked.
#[test]
fn the_seam_states_what_an_implementation_owes() {
    let doc = std::fs::read_to_string(repo().join("src/relay/mod.rs")).expect("read relay/mod.rs");
    for owed in [
        "Decode a control message",
        "creates media",
        "EndpointAssertion",
        "authentication status",
    ] {
        assert!(
            doc.contains(owed),
            "src/relay/mod.rs no longer states that an implementation owes \
             {owed:?}. The contract is the documentation; without it the trait \
             is four signatures and a guess."
        );
    }
    assert!(
        doc.contains("must NOT"),
        "the seam no longer says what a relay must not be asked for. That half \
         is what keeps `delete` and `start recording` unreachable."
    );
}
