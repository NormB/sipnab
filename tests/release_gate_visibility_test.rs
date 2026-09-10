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
        "KNOWN GAP, accepted deliberately and now cost a SECOND release: it \
         failed 0.5.139 for 35,016 bytes and 0.5.160 for 19,208, both against \
         a green `main`. Moving it earlier still costs a full cross-compiled \
         release build per commit, which is the most expensive thing in the \
         release and would be paid on every push to catch a boundary crossed \
         roughly once a hundred releases. What changed is the mitigation. It \
         used to be the ceiling's comment in `website/config.toml` recording \
         the size behind every MOVE, and that could not report headroom \
         between moves: it still described 0.5.138 while three releases went \
         past, so 0.5.159 shipped with 99,576 bytes left and nothing said so. \
         The comment now records every published release and two tests act on \
         it -- one demands a line for the current `published_version`, so a \
         release cannot be cut without re-measuring, and one fails while the \
         margin is thin, so the ceiling is raised at the release that gets \
         close rather than at the tag that fails.",
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

/// One line of the ceiling's measurement record: a version and a byte count.
#[derive(Debug, PartialEq, Eq)]
struct Measurement {
    version: String,
    bytes: i64,
}

/// The measurement LINES of a comment block, and nothing else in it.
///
/// Structured rather than grepped, because grepping is what made the first
/// draft of these tests vacuous: the block names `0.5.159` in a sentence and
/// carries six-figure byte counts in its own prose, so a test that asked "is
/// this version mentioned" and "are there three big numbers" passed against a
/// record with every measurement deleted.
///
/// A measurement line is `# <version>  <n,nnn,nnn> bytes` and nothing else is.
fn measurements(block: &str) -> Vec<Measurement> {
    let re = regex::Regex::new(r"(?m)^#\s+(\d+\.\d+\.\d+)\s+([0-9]{1,3}(?:,[0-9]{3})+)\s+bytes\b")
        .expect("pattern");
    re.captures_iter(block)
        .filter_map(|c| {
            Some(Measurement {
                version: c[1].to_string(),
                bytes: c[2].replace(',', "").parse().ok()?,
            })
        })
        .collect()
}

/// Owed, first of two, for a release the size gate failed a second time.
///
/// The 0.5.139 mitigation was a comment recording the measurement behind every
/// ceiling MOVE, and its stated purpose was that "the remaining headroom is
/// readable without building anything". It was not. Nothing required the
/// record to be refreshed between moves, so it described 0.5.138 while three
/// releases went past; 0.5.159 shipped with 99,576 bytes of headroom and
/// nobody could see that without downloading tarballs.
///
/// This demands a measurement LINE for the release currently published. A
/// release cannot be cut without moving `published_version`, and moving it
/// without re-measuring now fails here — which is the only thing that makes a
/// hand-kept record self-refreshing.
#[test]
fn the_binary_ceiling_records_every_published_release() {
    let src = ceiling_config();
    let published = regex::Regex::new(r#"(?m)^published_version = "([^"]+)""#)
        .unwrap()
        .captures(&src)
        .expect("website/config.toml has no published_version")[1]
        .to_string();
    let found = measurements(&ceiling_comment(&src));
    assert!(
        found.iter().any(|m| m.version == published),
        "the ceiling's record has no measurement line for {published}, the \
         release this tree currently advertises. Measure the shipped \
         x86_64-musl binary and add one — a version named in a sentence is not \
         a measurement. Recorded: {:?}",
        found.iter().map(|m| &m.version).collect::<Vec<_>>()
    );
}

/// Owed, second of two, and the half that acts on the record.
///
/// A refreshed record nobody reads is the 0.5.139 mitigation again. This one
/// fails while the margin is thin, so the ceiling is a decision taken at the
/// release that gets close rather than a surprise at the tag that fails.
///
/// The floor is 256 KiB, which is two ordinary releases at the growth this
/// project actually shows: 0.5.159 added 20,480 bytes and 0.5.160 added
/// 118,784. It is not a target — it is the point past which "one more release"
/// stops being a safe assumption.
#[test]
fn the_binary_ceiling_keeps_a_readable_margin() {
    let src = ceiling_config();
    let found = measurements(&ceiling_comment(&src));
    assert!(
        found.len() >= 3,
        "the ceiling's record carries {} measurement line(s); with fewer than \
         three there is no trend to read a margin from",
        found.len()
    );
    let (margin, largest, ceiling) = margin_of(&src, &found);
    assert!(
        margin > 0,
        "the record's largest measured binary is {largest} bytes, over the \
         {ceiling} MB ceiling. The release build will refuse this."
    );
    assert!(
        margin >= THIN_MARGIN,
        "only {margin} bytes of headroom under the {ceiling} MB ceiling, and \
         two ordinary releases of this project are about {THIN_MARGIN}. Raise \
         binary_size_ceiling_mb now, with the measurement, rather than \
         discovering it when a tag has already published nothing."
    );
}

/// Two ordinary releases of headroom, in bytes.
const THIN_MARGIN: i64 = 256 * 1024;

/// `(margin, largest_recorded, ceiling_mb)` for a config and its record.
///
/// Measured against the LARGEST recorded binary rather than the most recent
/// one: 0.5.158 was smaller than 0.5.157, so "the last line" is not reliably
/// the worst case.
fn margin_of(src: &str, found: &[Measurement]) -> (i64, i64, i64) {
    let ceiling: i64 = regex::Regex::new(r#"(?m)^binary_size_ceiling_mb = "([0-9]+)""#)
        .unwrap()
        .captures(src)
        .expect("no binary_size_ceiling_mb")[1]
        .parse()
        .expect("the ceiling is a number");
    let largest = found.iter().map(|m| m.bytes).max().unwrap_or(0);
    (ceiling * 1024 * 1024 - largest, largest, ceiling)
}

/// Owed, for a mutation that survived: deleting the measurement line for the
/// published release changed nothing, because the block names that version in
/// a sentence too.
#[test]
fn a_version_named_in_prose_is_not_a_measurement() {
    let prose = "\
# 15 -> 16 at 0.5.160, and the same shape again.\n\
# So 0.5.159 shipped one ordinary release away from tipping, over by 19,208.\n\
# The 118,784 bytes are a 66th MCP tool.\n";
    assert_eq!(
        measurements(prose),
        Vec::new(),
        "a version and a byte count in the same paragraph are not a \
         measurement line, and reading them as one is what let a record with \
         every measurement deleted pass"
    );
}

/// Owed, same mutation: the parser finds the real lines and reads both fields.
///
/// The paired half. A parser that matches nothing satisfies the test above
/// and every assertion built on it, which is the failure mode this whole file
/// is about.
#[test]
fn the_parser_reads_the_record_this_tree_carries() {
    let found = measurements(&ceiling_comment(&ceiling_config()));
    assert!(
        found.len() >= 3,
        "the parser found {} measurement line(s) in a record that has several",
        found.len()
    );
    for m in &found {
        assert!(
            m.bytes > 1_000_000,
            "{} parsed as {} bytes, which is not a binary size",
            m.version,
            m.bytes
        );
    }
}

/// Owed, for the second survivor: cutting the record to one line still passed,
/// because six-figure byte counts elsewhere in the prose met the count.
#[test]
fn a_thin_margin_is_refused_however_the_record_is_worded() {
    let src = "\
# 0.5.001  15,000,000 bytes\n\
# 0.5.002  16,700,000 bytes\n\
# 0.5.003  15,100,000 bytes\n\
binary_size_ceiling_mb = \"16\"\n";
    let found = measurements(src);
    assert_eq!(found.len(), 3, "the fixture must parse as three lines");
    let (margin, largest, _) = margin_of(src, &found);
    assert_eq!(
        largest, 16_700_000,
        "the margin must be measured against the LARGEST recorded binary, not \
         the last line — a release can be smaller than the one before it"
    );
    assert!(
        margin < THIN_MARGIN,
        "a record whose worst binary sits {margin} bytes under the ceiling \
         must read as thin"
    );
}

/// Owed, same survivor: a comfortable record reads as comfortable.
///
/// Without this the refusal above passes against a rule that refuses
/// everything, which is a different way of proving nothing.
#[test]
fn a_comfortable_margin_is_accepted() {
    let src = "\
# 0.5.001  10,000,000 bytes\n\
# 0.5.002  10,100,000 bytes\n\
# 0.5.003  10,050,000 bytes\n\
binary_size_ceiling_mb = \"16\"\n";
    let found = measurements(src);
    assert_eq!(found.len(), 3);
    let (margin, _, _) = margin_of(src, &found);
    assert!(
        margin >= THIN_MARGIN,
        "6.7 MB of headroom read as thin, so the floor refuses everything"
    );
}

/// `website/config.toml`, read once for the tests above.
fn ceiling_config() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("website/config.toml");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The contiguous comment block immediately above the ceiling key.
fn ceiling_comment(src: &str) -> String {
    let key = src
        .find("\nbinary_size_ceiling_mb = ")
        .expect("website/config.toml has no binary_size_ceiling_mb");
    let mut lines: Vec<&str> = src[..key]
        .lines()
        .rev()
        .take_while(|l| l.trim_start().starts_with('#'))
        .collect();
    lines.reverse();
    lines.join("\n")
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

/// The post-publish obligations are told to whoever pushes the tag.
///
/// Two gates now key on `published_version` and can only pass AFTER the
/// artifacts exist: the binary-ceiling record wants a measurement of the
/// shipped musl tarball, and the eBPF load record wants a run on a privileged
/// host with kernel BTF. Both are correct as post-release gates — the artifact
/// has to exist before anyone can measure or run it.
///
/// That makes them exactly the shape this file exists for. Neither can fire
/// before the tag, so the only thing standing between a maintainer and a
/// blocked follow-up commit is the prompt `pre-push` prints when a tag goes
/// up. A gate whose requirement is announced nowhere is discovered by failing.
#[test]
fn the_tag_prompt_names_every_post_publish_obligation() {
    let hook = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".githooks/pre-push"),
    )
    .expect("read .githooks/pre-push");
    let prompt = hook
        .split_once("is phase ONE")
        .map(|(_, rest)| rest.to_string())
        .expect(".githooks/pre-push must print a phase-two prompt when a tag is pushed");
    let prompt = prompt
        .split_once("\ndone")
        .map(|(p, _)| p.to_string())
        .unwrap_or(prompt);

    // Each requirement, and the file whose gate enforces it. Named rather than
    // derived: no rule connects a test to the sentence that should mention it,
    // which is why the connection has to be asserted somewhere.
    for (needle, why) in [
        (
            "published_version",
            "the site goes on offering the previous release",
        ),
        (
            "docs/install.md",
            "the download instructions name a version nobody can download",
        ),
        (
            "verify-bpf-load.sh",
            "the eBPF record blocks advertising a release nobody has loaded, and \
             the run needs a privileged host",
        ),
        (
            "docs/internals/uprobe-capture.md",
            "the load verification has nowhere to be recorded",
        ),
        (
            "musl",
            "the binary-ceiling record wants a measurement of the SHIPPED tarball",
        ),
    ] {
        assert!(
            prompt.contains(needle),
            "the tag prompt never mentions {needle}. Without it, {why} — and \
             the maintainer finds out when a follow-up commit is refused by a \
             gate that runs nowhere earlier."
        );
    }
}
