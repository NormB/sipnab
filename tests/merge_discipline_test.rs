// SPDX-License-Identifier: MIT OR Apache-2.0

//! A merge refusal names a mechanism; the loudest red check is a guess.
//!
//! # What happened
//!
//! Six Dependabot pull requests would not merge. `gh pr merge` answered with
//! the line GitHub prints when branch protection is holding a pull request
//! shut: "To use administrator privileges to immediately merge the pull
//! request, add the `--admin` flag." I read the check list, saw `license/cla`
//! red with "Contributor License Agreement is not signed yet", reasoned that a
//! bot cannot sign an agreement, concluded that was the blocker, and merged one
//! with `--admin`. That merge turned `main` red.
//!
//! The CLA check was never the blocker. Branch protection here requires exactly
//! one context, `CI success`, and that context was red for a reason with
//! nothing to do with agreements: this repository's own delivery gate,
//! `release_delivery_test::a_p0_marked_done_is_released_or_declared`, fires on
//! any commit past the newest tag that declares nothing in `CHANGELOG.md`. A
//! lockfile bump declares nothing — it ships nothing a reader needs told about,
//! and the bot that authors it cannot write a changelog entry — so the gate
//! reported all six bumps as undeclared releases and held every one of them
//! shut. The gate was working exactly as written. What it lacked was a name for
//! the one kind of post-tag commit that legitimately says nothing.
//!
//! `tests/support/release_logic.rs` now carries that name, `is_dependency_bump`,
//! and the gate returns early for a bump.
//!
//! # The lesson these tests hold
//!
//! I answered a question I had not asked correctly. "Which context does branch
//! protection require, and why is it failing" is answerable in a minute;
//! "which red check looks like the cause" is a guess, and `--admin` is the flag
//! that makes a guess irreversible. No test can force me to read a
//! required-check list, but the half of the story that lives in this repository
//! can be pinned: the exemption exists, the gate REACHES it rather than merely
//! importing it, it is narrow enough that it cannot swallow real work, and it
//! is distinct from the sibling exemption it is easy to confuse it with. Lose
//! any one of those and the six pull requests are back where they were, with
//! the same misleading red check sitting on top of the real one.

#![cfg(feature = "full")]

use std::fs;
use std::path::PathBuf;

#[path = "support/release_logic.rs"]
mod release_logic;

use release_logic::{
    ADVERTISEMENT_PATHS, DEPENDENCY_PATHS, advertisement_path, dependency_path, is_advertisement,
    is_dependency_bump,
};

/// The delivery gate whose refusal blocked the six pull requests.
const GATE_FN: &str = "a_p0_marked_done_is_released_or_declared";

/// The test binary that hosts the gate.
const GATE_FILE: &str = "tests/release_delivery_test.rs";

/// The support module the gate takes its decision logic from.
const LOGIC_FILE: &str = "tests/support/release_logic.rs";

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a repository file, naming the file when it cannot be read.
fn read(rel: &str) -> String {
    let path = repo().join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{rel} must be readable to judge the gate: {e}"))
}

/// A changeset in the shape the exemptions take.
fn changeset(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|p| (*p).to_string()).collect()
}

/// A concrete file path that a table entry is meant to match.
///
/// A trailing `/` is a directory in both tables, so the sample must be a CHILD
/// of it; the directory's own name is not a file and neither predicate accepts
/// it.
fn sample_of(entry: &str) -> String {
    match entry.strip_suffix('/') {
        Some(dir) => format!("{dir}/sample.yml"),
        None => entry.to_string(),
    }
}

/// The source of one top-level function, from its `fn` line to the lone `}`
/// that closes it.
fn function_body(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("{GATE_FILE} no longer defines fn {name}"));
    let mut body = String::new();
    for line in src[start..].lines() {
        body.push_str(line);
        body.push('\n');
        if line == "}" {
            break;
        }
    }
    body
}

/// Every name through which `needle` is reachable in `src`: the predicate
/// itself, plus each top-level function whose body calls it.
///
/// The gate does not call the predicate directly — it calls a wrapper that asks
/// git for the changeset first — so a rule demanding the literal name inside an
/// `if` would fail against a correct tree, and the obvious repair (accept the
/// import and stop) is the vacuous version of this check.
fn reaching_names(src: &str, needle: &str) -> Vec<String> {
    let mut names = vec![needle.to_string()];
    let mut current: Option<&str> = None;
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix("fn ") {
            current = rest.split('(').next();
        }
        if line.trim_start().starts_with("//") || !line.contains(needle) {
            continue;
        }
        if let Some(name) = current
            && !names.iter().any(|n| n.as_str() == name)
        {
            names.push(name.to_string());
        }
    }
    names
}

/// Whether `body` tests any of `names` in an `if` whose block returns early.
///
/// Brace depth rather than indentation: the arm this looks for carries several
/// comment lines between the condition and the `return;`, and a rule keyed on
/// adjacency would read that as an absent exemption.
fn guarded_early_return(body: &str, names: &[String]) -> bool {
    let lines: Vec<&str> = body.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || !trimmed.starts_with("if ") {
            continue;
        }
        if !names.iter().any(|n| line.contains(n.as_str())) {
            continue;
        }
        let mut depth: i32 = 0;
        let mut opened = false;
        for inner in &lines[index..] {
            for ch in inner.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth > 0 {
                opened = true;
            }
            if inner.trim() == "return;" {
                return true;
            }
            if opened && depth <= 0 {
                break;
            }
        }
    }
    false
}

// ── A. the exemption exists and the gate consults it ────────────────

/// The delivery gate exempts a dependency bump, and the exemption is reached.
///
/// Two halves of one fact. The predicate recognizes the changesets Dependabot
/// actually produces, and `a_p0_marked_done_is_released_or_declared` reaches it
/// through an `if` that RETURNS. Losing the first half blocks every bump again.
/// Losing the second is worse: the repair still reads as present in the tree
/// while the gate goes on refusing, and the next person to hit it has the same
/// misleading `license/cla` red check to reason from.
#[test]
fn a_dependency_bump_is_exempt_and_the_delivery_gate_reaches_the_exemption() {
    assert!(
        is_dependency_bump(&changeset(&["Cargo.lock"])),
        "a lone Cargo.lock update is not recognized as a dependency bump, so \
         the delivery gate reports it as an undeclared release and branch \
         protection holds the pull request shut"
    );
    assert!(
        is_dependency_bump(&changeset(&["Cargo.toml", "Cargo.lock"])),
        "the two-file changeset Dependabot produces for a Rust dependency is \
         not exempt; that is exactly the shape that left six pull requests \
         unmergeable"
    );
    assert!(
        is_dependency_bump(&changeset(&[".github/workflows/ci.yml"])),
        "a pinned-action bump is not exempt, so every workflow update \
         Dependabot opens fails `CI success` for a reason no reviewer of the \
         diff would guess"
    );

    let src = read(GATE_FILE);
    let names = reaching_names(&src, "is_dependency_bump");
    assert!(
        names.len() >= 2,
        "found only {} name(s) reaching is_dependency_bump in {GATE_FILE}; the \
         reader has stopped matching, and the rule below would then accept a \
         gate that never consults the exemption at all",
        names.len()
    );
    let gate = function_body(&src, GATE_FN);
    assert!(
        gate.lines().count() >= 20,
        "read only {} line(s) of fn {GATE_FN}; the extractor has lost the \
         function body and can prove nothing about what the gate does",
        gate.lines().count()
    );
    assert!(
        guarded_early_return(&gate, &names),
        "fn {GATE_FN} never returns early on the dependency-bump exemption \
         (looked for {names:?}). The exemption is dead code in that state: \
         every Dependabot pull request fails the one required context again, \
         and the only obvious red check is once more not the cause."
    );
}

// ── B. the exemption stays narrow ───────────────────────────────────

/// The exemption refuses any changeset that also carries real work.
///
/// An exemption's danger runs opposite to its purpose. Widen this one until it
/// covers a feature commit and the delivery gate stops existing: work shipped
/// past the newest tag would pass undeclared, which is the exact silence the
/// gate was written to break — three P0 fixes sat unshipped in a green tree
/// before it. So a manifest edit beside source is not a bump, a release version
/// bump that also moves the site config and the man page is not a bump, and an
/// empty changeset is not a bump either: "git reported nothing" must not read
/// as "there is nothing to declare".
#[test]
fn the_dependency_exemption_refuses_a_changeset_carrying_real_work() {
    let cases: &[(&str, &[&str])] = &[
        (
            "a manifest edit beside a source file",
            &["Cargo.toml", "src/main.rs"],
        ),
        (
            "a lockfile beside a parser change",
            &["Cargo.lock", "src/sip/parser.rs"],
        ),
        (
            "a workflow edit beside a source file",
            &[".github/workflows/ci.yml", "src/lib.rs"],
        ),
        (
            "a release version bump",
            &[
                "Cargo.toml",
                "Cargo.lock",
                "website/config.toml",
                "man/sipnab.1",
            ],
        ),
        ("an empty changeset", &[]),
    ];
    assert!(
        cases.len() >= 5,
        "only {} changeset(s) drive this rule; it has stopped exercising the \
         ways an exemption gets widened",
        cases.len()
    );

    let mut swallowed: Vec<&str> = Vec::new();
    for (what, files) in cases {
        if is_dependency_bump(&changeset(files)) {
            swallowed.push(what);
        }
    }
    assert!(
        swallowed.is_empty(),
        "the dependency exemption accepted {swallowed:?}. An exemption wide \
         enough to cover a commit like that removes the delivery gate: real \
         work then ships past the newest tag with nothing in CHANGELOG.md \
         saying so, and the suite stays green while it happens."
    );
}

// ── C. exact match, not prefix ──────────────────────────────────────

/// Every entry in `DEPENDENCY_PATHS` matches exactly; a directory matches only
/// its children.
///
/// This mirrors a defect the sibling table already had: its first version used
/// `starts_with` for every entry, which exempted `CHANGELOG.md.orig`,
/// `docs/install.md.bak` and `website/config.tomlx`. A prefix match here would
/// do the same for a backup or editor file sitting beside a manifest, and the
/// commit carrying it would read as "just a dependency bump" and skip the
/// delivery gate entirely.
#[test]
fn every_dependency_path_is_matched_exactly_and_not_by_prefix() {
    for named in [
        "Cargo.lock.bak",
        "Cargo.tomlx",
        "Dockerfile.dev",
        ".github/workflows-old/x.yml",
    ] {
        assert!(
            !dependency_path(named),
            "{named:?} is treated as a dependency manifest. A prefix match \
             exempts every backup, editor artifact and neighboring directory \
             whose name merely begins with a real one, and a commit carrying \
             one of them skips the delivery gate."
        );
    }
    for named in [".github/workflows/ci.yml", "Cargo.lock"] {
        assert!(
            dependency_path(named),
            "{named:?} is no longer a dependency manifest, so the changesets \
             Dependabot opens stop being exempt and block on `CI success`"
        );
    }

    assert!(
        !DEPENDENCY_PATHS.is_empty(),
        "the dependency table is empty, so the sweep below would report a \
         perfectly exact matcher having tested nothing"
    );
    let mut accepted: Vec<String> = Vec::new();
    let mut rejected: Vec<String> = Vec::new();
    for entry in DEPENDENCY_PATHS {
        if let Some(dir) = entry.strip_suffix('/') {
            accepted.push(format!("{dir}/ci.yml"));
            // A sibling directory, a longer directory name, and the bare
            // directory itself: all three are what a prefix match would take.
            rejected.push(format!("{dir}-old/x.yml"));
            rejected.push(format!("{dir}x/y.yml"));
            rejected.push(dir.to_string());
        } else {
            accepted.push((*entry).to_string());
            rejected.push(format!("{entry}.bak"));
            rejected.push(format!("{entry}.orig"));
            rejected.push(format!("{entry}.dev"));
            rejected.push(format!("{entry}x"));
        }
    }
    assert!(
        accepted.len() >= DEPENDENCY_PATHS.len() && rejected.len() >= DEPENDENCY_PATHS.len() * 3,
        "derived only {} acceptance(s) and {} rejection(s) from {} table \
         entries; the derivation has stopped covering the table",
        accepted.len(),
        rejected.len(),
        DEPENDENCY_PATHS.len()
    );

    let missed: Vec<&String> = accepted.iter().filter(|f| !dependency_path(f)).collect();
    assert!(
        missed.is_empty(),
        "these paths are named by DEPENDENCY_PATHS yet not matched: {missed:?}. \
         The bump they belong to stops being exempt and its pull request blocks."
    );
    let leaked: Vec<&String> = rejected.iter().filter(|f| dependency_path(f)).collect();
    assert!(
        leaked.is_empty(),
        "these paths are matched by prefix rather than exactly: {leaked:?}. \
         Anything whose name merely begins with a manifest's name then hides \
         inside a bump and ships past the delivery gate undeclared."
    );
}

// ── D. two exemptions, neither a superset of the other ──────────────

/// The advertisement and dependency exemptions disagree in both directions.
///
/// Both let the delivery gate return early, which makes them easy to conflate
/// and easy to "simplify" into one. They answer different questions. Phase two
/// of a release edits the changelog and the site to advertise a tag that
/// already exists; a dependency bump edits manifests and advertises nothing.
/// Collapse them and one of two failures follows: bumps block again, or a
/// changelog-and-site commit that is NOT advertising the newest tag gets waved
/// through as a bump. Both directions are pinned here, and so is the fact that
/// neither table is contained in the other.
#[test]
fn the_advertisement_and_dependency_exemptions_disagree_in_both_directions() {
    // A version triple chosen here rather than read from the tree, so the
    // question stays answerable in states this repository is not in.
    let tag = (1, 2, 3);

    let advertising = changeset(&["CHANGELOG.md", "website/config.toml", "docs/install.md"]);
    assert!(
        is_advertisement(&advertising, tag, tag),
        "phase two of a release is no longer recognized as advertising, so the \
         commit that publishes a tag reads as undeclared work"
    );
    assert!(
        !is_dependency_bump(&advertising),
        "the release advertisement is accepted as a dependency bump. The two \
         exemptions have merged, and a changelog-and-site commit that is behind \
         the newest tag then skips the gate through the wrong door"
    );

    let bumping = changeset(&["Cargo.toml", "Cargo.lock"]);
    assert!(
        is_dependency_bump(&bumping),
        "the dependency bump is not exempt, which is the state that left six \
         pull requests unmergeable"
    );
    assert!(
        !is_advertisement(&bumping, tag, tag),
        "a dependency bump is accepted as a release advertisement. The gate \
         would then treat a lockfile update as proof the newest tag has been \
         published, and a genuinely unadvertised release would pass"
    );

    // Neither table subsumes the other: each names at least one path the other
    // predicate refuses.
    let advertisement_only = ADVERTISEMENT_PATHS
        .iter()
        .map(|p| sample_of(p))
        .find(|f| !dependency_path(f));
    assert!(
        advertisement_only.is_some(),
        "every advertisement path is also a dependency path; the dependency \
         exemption has grown to contain its sibling and now waves through \
         changelog and website edits"
    );
    let dependency_only = DEPENDENCY_PATHS
        .iter()
        .map(|p| sample_of(p))
        .find(|f| !advertisement_path(f));
    assert!(
        dependency_only.is_some(),
        "every dependency path is also an advertisement path; the two \
         exemptions have stopped being distinct rules and one of them can be \
         deleted without any test noticing"
    );
}

// ── E. the scan is looking at something ─────────────────────────────

/// The gate and its decision logic are present and non-trivial.
///
/// Every rule above reads one of two files and a table. A deleted file, an
/// emptied table or a renamed gate would otherwise turn this whole binary into
/// a scan over nothing, and a scan over nothing agrees with any repository —
/// which is precisely how a missing gate stays invisible. The sizes are floors
/// under measurements, not equalities: they must survive ordinary edits and
/// still fail loudly on a stub.
#[test]
fn the_gate_and_its_decision_logic_are_present_and_non_trivial() {
    assert!(
        !DEPENDENCY_PATHS.is_empty(),
        "DEPENDENCY_PATHS is empty, so is_dependency_bump refuses every \
         changeset and the exemption silently stops existing"
    );
    // Measured at 9 entries on 2026-08-31; the floor is set low enough that
    // dropping a manifest from the table is a deliberate act, not churn.
    assert!(
        DEPENDENCY_PATHS.len() >= 4,
        "the dependency table has shrunk to {} entry/entries; below this it no \
         longer describes the manifests Dependabot touches, and the bumps it \
         stops covering block on `CI success`",
        DEPENDENCY_PATHS.len()
    );

    let gate_src = read(GATE_FILE);
    let logic_src = read(LOGIC_FILE);
    // Measured at 29680 and 6599 bytes on 2026-08-31.
    assert!(
        gate_src.len() >= 8_000,
        "{GATE_FILE} is only {} bytes; the delivery gates have been gutted and \
         the rules in this file are reading a stub",
        gate_src.len()
    );
    assert!(
        logic_src.len() >= 2_000,
        "{LOGIC_FILE} is only {} bytes; the decision logic every rule here \
         drives has been hollowed out",
        logic_src.len()
    );
    assert!(
        gate_src.contains(&format!("fn {GATE_FN}")),
        "{GATE_FILE} no longer defines fn {GATE_FN}. That is the gate branch \
         protection was reporting through `CI success`; without it, an \
         undeclared release ships and nothing says so."
    );
    assert!(
        logic_src.contains("pub fn is_dependency_bump"),
        "{LOGIC_FILE} no longer defines is_dependency_bump, so the exemption \
         the six blocked pull requests were waiting for is gone"
    );
}
