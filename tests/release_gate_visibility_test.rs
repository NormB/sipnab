// SPDX-License-Identifier: MIT OR Apache-2.0

//! Gates that can only fail at release time, and the price of that.
//!
//! On 2026-08-31 the 0.5.139 tag was pushed against a green `main` and the
//! release build failed: the x86_64-musl artifact was 13,666,504 bytes against
//! a 13 MB ceiling. `main` had been green because "Enforce published binary
//! size" runs ONLY in `release.yml`. The fact that blocked the release was
//! knowable from any commit and was checked at the one moment where finding it
//! costs a tag, a failed workflow, and a fix commit that then leaves the tag
//! stale — which turned `main` red a second time, on a different gate.
//!
//! The lesson generalizes past that one step: **a gate that runs only at
//! release time can only be discovered at release time.** Some of those are
//! unavoidable — nothing can attest a build before the build exists — and the
//! point of this file is not to abolish them. It is to make each one a
//! DECISION with a reason attached, rather than an accident nobody noticed
//! until it cost a release.
//!
//! So every release-blocking gate must be named here with the reason it cannot
//! run earlier, and the list may not name a step that no longer exists. A list
//! like this is where coverage goes to die, so both directions are checked.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// The workflow whose failures block a release.
fn release_yml() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `- name:` step in the release workflow, in file order.
fn release_steps(src: &str) -> Vec<String> {
    src.lines()
        .filter_map(|l| l.trim().strip_prefix("- name: "))
        .map(|s| s.trim().to_string())
        .collect()
}

/// The steps that ASSERT something rather than produce something.
///
/// Matched on the verb the step name opens with, because that is what the
/// workflow's own authors use to mean "this can fail the release": `Enforce`,
/// `Verify`, `Compare`, `Smoke test`. A step that builds or uploads can fail
/// too, but it fails because the work did not happen -- there is nothing to
/// learn earlier. These fail because a FACT is wrong, and a fact can be
/// checked whenever anyone likes.
fn release_gates(src: &str) -> Vec<String> {
    const GATE_VERBS: &[&str] = &["Enforce ", "Verify ", "Compare ", "Smoke test "];
    release_steps(src)
        .into_iter()
        .filter(|s| GATE_VERBS.iter().any(|v| s.starts_with(v)))
        .collect()
}

/// Every release-blocking gate, and why it cannot run before the tag.
///
/// Each reason must say what makes the check impossible earlier, not merely
/// that it happens later. "It is in release.yml" is not a reason.
const RELEASE_ONLY_GATES: &[(&str, &str)] = &[
    (
        "Compare the tag against Cargo.toml",
        "there is no tag to compare against until one is pushed. This gate is \
         definitionally release-time and is the one that cannot be moved.",
    ),
    (
        "Verify the binary is stripped",
        "needs the cross-compiled release artifact. `main` builds debug and \
         checks nothing about the shipped file's symbols.",
    ),
    (
        "Smoke test the built binary",
        "runs the artifact that will be published, on the platform it was \
         built for. A debug build on the runner's own arch proves nothing \
         about a cross-compiled musl binary.",
    ),
    (
        "Enforce glibc floor (gnu Linux targets)",
        "reads the symbol versions of the shipped gnu binary. Nothing short of \
         that binary carries them.",
    ),
    (
        "Enforce published binary size (musl targets)",
        "KNOWN GAP, accepted deliberately: this measures a fact that any commit \
         could measure, and on 2026-08-31 it failed a release for 35,016 bytes \
         that `main` had been green about. Moving it earlier costs a full \
         cross-compiled release build per commit, which is the most expensive \
         thing in the release and would be paid on every push to catch a \
         boundary crossed roughly once a hundred releases. The mitigation is \
         the ceiling's own comment in `website/config.toml`, which now records \
         the measured size behind every move, so the remaining headroom is \
         readable without building anything.",
    ),
    (
        "Verify the attestation we just created",
        "nothing can verify an attestation before the attestation exists.",
    ),
];

/// Every release-blocking gate is named, with a reason it cannot run earlier.
#[test]
fn every_release_blocking_gate_declares_why_it_cannot_run_earlier() {
    let src = release_yml();
    let gates = release_gates(&src);

    assert!(
        gates.len() >= 5,
        "only {} release gate(s) matched; the step scan or the verb list has \
         stopped matching and this gate proves nothing: {gates:?}",
        gates.len()
    );

    let declared: BTreeSet<&str> = RELEASE_ONLY_GATES.iter().map(|(n, _)| *n).collect();
    let undeclared: Vec<&String> = gates
        .iter()
        .filter(|g| !declared.contains(g.as_str()))
        .collect();
    assert!(
        undeclared.is_empty(),
        "these steps can fail a release and nothing says why they cannot run \
         before the tag: {undeclared:?}\n\nAdd each to RELEASE_ONLY_GATES with \
         the reason, or move the check somewhere a commit can reach it. A gate \
         that runs only at release time can only be DISCOVERED at release \
         time, and discovering one costs a tag."
    );
}

/// Every declaration names a step the workflow still has, and gives a reason.
///
/// The other direction. Without this an entry outlives the step it excuses,
/// and a list naming something deleted asserts nothing while looking like it
/// asserts something.
#[test]
fn every_release_only_declaration_names_a_step_that_exists() {
    let src = release_yml();
    let steps: BTreeSet<String> = release_steps(&src).into_iter().collect();

    assert!(
        !RELEASE_ONLY_GATES.is_empty(),
        "the declaration list is empty, so the gate above proves nothing"
    );

    for (name, reason) in RELEASE_ONLY_GATES {
        assert!(
            steps.contains(*name),
            "RELEASE_ONLY_GATES names {name:?}, which release.yml no longer \
             has. Remove the entry or restore the step."
        );
        assert!(
            reason.len() > 60,
            "{name}'s reason must say what makes the check impossible earlier, \
             not merely that it happens later"
        );
    }
}

/// Moving the binary ceiling records the measurement that moved it.
///
/// The ceiling is a published claim -- the homepage quotes it -- so raising it
/// is a decision about what sipnab tells people, not a number to nudge until
/// the build passes. A raise without evidence is indistinguishable from one,
/// and the failure this file exists for was preceded by exactly 79,672 bytes of
/// headroom that nothing had written down.
#[test]
fn the_binary_ceiling_records_the_measurement_behind_it() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("website/config.toml");
    let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));

    let key = src
        .find("\nbinary_size_ceiling_mb = ")
        .expect("website/config.toml has no binary_size_ceiling_mb");

    // The contiguous comment block immediately above the key.
    let before = &src[..key];
    let comment: Vec<&str> = before
        .lines()
        .rev()
        .take_while(|l| l.trim_start().starts_with('#'))
        .collect();
    assert!(
        comment.len() >= 4,
        "the ceiling carries only {} comment line(s); it is a published claim \
         and must say what it rests on",
        comment.len()
    );

    let block: String = comment.join("\n");
    assert!(
        block.contains("bytes"),
        "the ceiling's comment records no byte measurement. Raising it is a \
         change to what the homepage tells people, so the evidence belongs \
         beside it: {block}"
    );
    let digits = block.chars().filter(char::is_ascii_digit).count();
    assert!(
        digits >= 12,
        "the ceiling's comment names too few figures ({digits} digits) to be \
         recording real measurements: {block}"
    );
}

/// The scanners read a real workflow.
///
/// Anti-vacuity. Every filter above narrows; a narrowing that reaches zero
/// exits 0 forever and looks exactly like a tree with nothing to report.
#[test]
fn the_release_workflow_scan_found_a_plausible_workflow() {
    let src = release_yml();
    let steps = release_steps(&src);
    let gates = release_gates(&src);

    // Measured 2026-08-31: 31 steps, 6 of them gates. Floors, not equalities,
    // so adding a step does not fail the suite -- but losing most of them does.
    assert!(
        steps.len() >= 20,
        "only {} step(s) parsed from release.yml; the `- name:` scan is wrong",
        steps.len()
    );
    assert!(
        gates.len() < steps.len(),
        "every step matched as a gate, so the verb filter is not filtering"
    );
    assert!(
        src.contains("binary_size_ceiling_mb"),
        "release.yml no longer reads the ceiling; the gate this file is about \
         has moved and these declarations describe a workflow that is gone"
    );
}
