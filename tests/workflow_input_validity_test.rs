// SPDX-License-Identifier: MIT OR Apache-2.0

//! Workflow inputs the actions actually read, and gates that can still see.
//!
//! Written to pay for defects, and each test names the one it prevents.
//!
//! # The defect that motivated the file
//!
//! `no-cache-filter` is not an input to `docker/build-push-action`;
//! `no-cache-filters` is. GitHub WARNS on an unknown key and carries on, so a
//! fix that changed nothing looked like a fix, the step went green, the cache
//! was reused unchanged, and the vulnerability scan failed again on the same
//! stale layer. A warning in a log nobody reads is how a no-op passes for a
//! repair.
//!
//! # And the one underneath it
//!
//! That scan had been passing for weeks against a CACHED package-upgrade layer
//! — testing whatever Debian shipped the day the cache was filled. A scan that
//! passes because it is looking at old packages reports safety it never
//! checked.

#![cfg(feature = "full")]

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workflow(name: &str) -> String {
    let p = repo().join(".github/workflows").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Every `with:` key given to one action in one workflow.
fn keys_for_action(text: &str, action_prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_step = false;
    let mut in_with = false;
    let mut with_indent = 0usize;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with("- name:") || trimmed.starts_with("- uses:") {
            in_step = trimmed.contains(action_prefix);
            in_with = false;
        }
        if trimmed.starts_with("uses:") {
            in_step = trimmed.contains(action_prefix);
            in_with = false;
        }
        if in_step && trimmed.starts_with("with:") {
            in_with = true;
            with_indent = indent;
            continue;
        }
        if in_with {
            if !trimmed.is_empty() && indent <= with_indent {
                in_with = false;
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some((k, _)) = trimmed.split_once(':') {
                let k = k.trim();
                if !k.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    out.insert(k.to_string());
                }
            }
        }
    }
    out
}

/// Inputs `docker/build-push-action` accepts, from the warning it prints when
/// given one it does not.
const BUILD_PUSH_INPUTS: &[&str] = &[
    "add-hosts",
    "allow",
    "annotations",
    "attests",
    "build-args",
    "build-contexts",
    "builder",
    "cache-from",
    "cache-to",
    "call",
    "cgroup-parent",
    "context",
    "file",
    "labels",
    "load",
    "network",
    "no-cache",
    "no-cache-filters",
    "outputs",
    "platforms",
    "provenance",
    "pull",
    "push",
    "sbom",
    "secrets",
    "secret-envs",
    "secret-files",
    "shm-size",
    "ssh",
    "tags",
    "target",
    "ulimit",
    "github-token",
];

// ── The no-op fix ────────────────────────────────────────────────────────────

/// GIVEN the docker workflow
/// WHEN its build steps are read
/// THEN every input is one the action accepts.
///
/// The defect: `no-cache-filter` singular. Unknown inputs warn rather than
/// fail, so the step stayed green while doing nothing.
#[test]
fn every_build_push_input_is_one_the_action_reads() {
    let text = workflow("docker.yml");
    let used = keys_for_action(&text, "docker/build-push-action");
    assert!(
        !used.is_empty(),
        "found no build-push inputs at all; this scan has stopped matching and \
         would pass for a workflow with any typo in it"
    );
    let unknown: Vec<&String> = used
        .iter()
        .filter(|k| !BUILD_PUSH_INPUTS.contains(&k.as_str()))
        .collect();
    assert!(
        unknown.is_empty(),
        "these inputs are not read by docker/build-push-action, and an unknown \
         input only WARNS: {unknown:?}"
    );
}

/// GIVEN the cache-busting input
/// WHEN its exact spelling is checked
/// THEN it is the plural one.
#[test]
fn the_cache_bust_input_is_spelled_plural() {
    let text = workflow("docker.yml");
    assert!(
        text.contains("no-cache-filters:"),
        "the cache-bust is missing or singular"
    );
    assert!(
        !text.contains("no-cache-filter:"),
        "the singular spelling is not an input and does nothing"
    );
}

/// GIVEN the stage the cache-bust names
/// WHEN the Dockerfile is read
/// THEN that stage exists.
///
/// A filter naming a stage that does not exist is the same silent no-op by
/// another route: buildx has nothing to exclude and says nothing about it.
#[test]
fn the_cache_bust_names_a_stage_that_exists() {
    let text = workflow("docker.yml");
    let dockerfile = std::fs::read_to_string(repo().join("Dockerfile")).expect("Dockerfile");
    for line in text.lines() {
        if let Some(stage) = line.trim().strip_prefix("no-cache-filters:") {
            let stage = stage.trim();
            assert!(
                dockerfile.contains(&format!("AS {stage}")),
                "the build excludes stage {stage:?} from the cache and the \
                 Dockerfile has no such stage"
            );
        }
    }
}

// ── The scan that tested a stale image ───────────────────────────────────────

/// GIVEN the runtime stage
/// WHEN it upgrades packages
/// THEN the build refuses to cache it.
///
/// The defect underneath: a cached upgrade layer is the same packages forever,
/// so the vulnerability scan tested whatever Debian shipped when the cache was
/// filled. It passed for weeks and then failed with the image two point
/// releases behind.
#[test]
fn the_package_upgrade_layer_is_never_served_from_cache() {
    let dockerfile = std::fs::read_to_string(repo().join("Dockerfile")).expect("Dockerfile");
    assert!(
        dockerfile.contains("apt-get upgrade"),
        "the runtime stage no longer upgrades; this test is guarding nothing"
    );
    assert!(
        dockerfile.contains("AS runtime"),
        "the upgrading stage must be NAMED, or the build cannot exclude it"
    );
    let text = workflow("docker.yml");
    assert!(
        text.contains("no-cache-filters: runtime"),
        "the stage that upgrades packages is being served from cache"
    );
}

/// GIVEN every build step in the docker workflow
/// WHEN the cache-bust is counted
/// THEN each one has it.
///
/// One step fixed and another left cached would mean the scanned image and the
/// published image were built differently, which is worse than either.
#[test]
fn every_build_step_busts_the_same_cache() {
    let text = workflow("docker.yml");
    let builds = text.matches("docker/build-push-action").count();
    let busts = text.matches("no-cache-filters: runtime").count();
    assert!(
        builds > 0,
        "no build steps found; the scan stopped matching"
    );
    assert_eq!(
        busts, builds,
        "{builds} build step(s) and {busts} cache-bust(s): the scanned image \
         and the published image would not be built the same way"
    );
}

/// GIVEN the scan step
/// WHEN its settings are read
/// THEN it fails the build and ignores only what cannot be acted on.
#[test]
fn the_scan_can_still_fail_the_build() {
    let text = workflow("docker.yml");
    assert!(text.contains("ignore-unfixed: true"));
    assert!(
        text.contains("exit-code: '1'"),
        "a scan that cannot fail the build is a report, not a gate"
    );
    assert!(text.contains("severity: HIGH,CRITICAL"));
}
