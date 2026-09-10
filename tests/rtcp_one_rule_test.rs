// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RTCP content rules live in one module, and the capture path uses them.
//!
//! # The defect
//!
//! `rtp::rtcp::looks_like_rtcp` gained RFC 3550 section 6.1's padding rule in
//! 0.5.164. `pipeline::is_rtcp_packet` — the function every captured datagram
//! on a media port actually reaches — kept a private copy of the length logic
//! and never heard about it. So the rule shipped applying to a function
//! nothing in the capture path calls, while the release note told operators it
//! was "one more bit of separation on the classifier that decides RTP against
//! RTCP for every datagram on a media port".
//!
//! Both halves were wrong in the way that is hardest to see: the code was
//! correct, its tests passed, and the sentence describing it was false. The
//! duplicate was not introduced by the padding change — it predated it, and
//! sat there agreeing with the original until the original moved.
//!
//! # What is gated here
//!
//! Behavior is gated in `src/pipeline.rs` itself, where
//! `the_muxed_verdict_is_the_public_classifiers_verdict` drives both functions
//! over the same fixtures. That test is the one that matters, and it is also
//! the one a second copy could pass by agreeing on the fixtures chosen.
//!
//! These are the structural half: the word-length arithmetic that decides how
//! far an RTCP sub-packet reaches belongs to one module, and any other site
//! computing it has to be named here with a reason. A new copy fails rather
//! than waiting for the two to disagree.
#![cfg(feature = "full")]

use std::path::{Path, PathBuf};

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The module that owns the RTCP wire rules.
const OWNER: &str = "src/rtp/rtcp.rs";

/// Functions outside [`OWNER`] allowed to compute an RTCP sub-packet's byte
/// length, each with the reason it answers a different question.
///
/// Paired with its justification deliberately. An exemption list with no
/// reasons is a list nobody can audit, and the first thing that happens to one
/// is that a new entry joins it silently.
const EXEMPT: &[(&str, &str)] = &[(
    "quoted_media_kind",
    "reads an ICMP quote, which is truncated by definition: the declared \
     length is EXPECTED to exceed the bytes present, so the framing question \
     this arithmetic answers elsewhere has no meaning here",
)];

/// Every `.rs` file under `src/`.
fn sources() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Path relative to the repository root, with forward slashes.
fn rel(p: &Path) -> String {
    p.strip_prefix(repo())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The name of the most recent `fn` declared at or before `line_idx`.
fn enclosing_fn(lines: &[&str], line_idx: usize) -> String {
    for line in lines[..=line_idx].iter().rev() {
        let t = line.trim_start();
        for prefix in ["pub fn ", "fn ", "pub(crate) fn ", "async fn "] {
            if let Some(rest) = t.strip_prefix(prefix) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    "<none>".to_string()
}

/// Sites computing an RTCP sub-packet's byte length, as `(file, fn, line)`.
///
/// The shape is the `(words + 1) * 4` conversion RFC 3550 section 6.4.1
/// defines: a length field counting 32-bit words minus one. Comments and
/// string literals are excluded — a doc comment explaining the formula is not
/// a second implementation of it.
fn word_length_sites() -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    for path in sources() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if !code.contains("+ 1) * 4") {
                continue;
            }
            out.push((rel(&path), enclosing_fn(&lines, i), i + 1));
        }
    }
    out
}

/// The scan finds the rule where it lives.
///
/// The fixture guard, and not a formality: this scan is a string match over
/// source, and a reformat that breaks the expression across two lines would
/// silently reduce it to finding nothing. A scan that matches nothing agrees
/// with every tree.
#[test]
fn the_scan_finds_the_word_length_rule_in_its_own_module() {
    let sites = word_length_sites();
    let owned = sites.iter().filter(|(f, _, _)| f == OWNER).count();
    assert!(
        owned > 0,
        "the scan found no RTCP word-length arithmetic in {OWNER}, so it has \
         stopped matching and proves nothing about anywhere else. Found: \
         {sites:?}"
    );
}

/// Nothing outside the RTCP module computes a sub-packet's length unnamed.
#[test]
fn the_rtcp_word_length_arithmetic_lives_in_one_module() {
    let unexplained: Vec<String> = word_length_sites()
        .into_iter()
        .filter(|(f, _, _)| f != OWNER)
        .filter(|(_, func, _)| !EXEMPT.iter().any(|(name, _)| name == func))
        .map(|(f, func, line)| format!("{f}:{line} in `{func}`"))
        .collect();
    assert!(
        unexplained.is_empty(),
        "these compute an RTCP sub-packet's byte length outside {OWNER}: \
         {unexplained:?}. A second copy agrees with the first until the first \
         moves — which is how the padding rule shipped applying to a function \
         the capture path never calls. Either call the rtcp module, or add the \
         function to EXEMPT with the reason it answers a different question"
    );
}

/// The muxed arm of the pipeline's classifier delegates rather than deciding.
///
/// Scoped to that function's body, not the file: `pipeline.rs` legitimately
/// mentions RTCP elsewhere, and a whole-file check would either pass on the
/// wrong evidence or fail on the right code.
#[test]
fn the_muxed_arm_delegates_to_the_rtcp_module() {
    let src = std::fs::read_to_string(repo().join("src/pipeline.rs"))
        .expect("src/pipeline.rs is in the tree");
    let start = src
        .find("pub fn is_rtcp_packet(")
        .expect("src/pipeline.rs still defines is_rtcp_packet");
    let body_start = start + src[start..].find('{').expect("the function has a body");
    let mut depth = 0i32;
    let mut end = body_start;
    for (offset, ch) in src[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_start + offset;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[body_start..=end];
    assert!(
        body.contains("looks_like_rtcp"),
        "is_rtcp_packet no longer asks rtp::rtcp for the content verdict, so \
         the two can disagree again. Body: {body}"
    );
    let code_only: String = body
        .lines()
        .filter_map(|l| l.split("//").next())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code_only.contains("* 4"),
        "is_rtcp_packet frames a sub-packet itself again; that arithmetic \
         belongs to {OWNER}"
    );
}
