//! Branch protection on `main` must match what this repository CLAIMS it is.
//!
//! GATE2 was closed by hand on 2026-08-23 by turning `enforce_admins` on, and
//! was reopened on 2026-08-26 when the API reported it off again. Nothing
//! noticed in between. A setting fixed by hand, with no gate holding it, is a
//! setting that reverts silently — and the cost is specific: the settings page
//! and `docs/internals/build-ci-release.md` go on describing a guarantee that
//! stopped existing, so a reader who checks the documentation is misled by it
//! rather than informed.
//!
//! This file does NOT assert that protection is enforced. That is a decision
//! about how the repository is worked, not a fact about the code, and it is
//! recorded in the backlog under GATE2. What this file asserts is that the
//! declared state and the real state are the SAME state, whichever one is
//! chosen. Flipping `enforce_admins` in the GitHub UI without touching the
//! documentation fails this test; so does editing the documentation to claim a
//! protection the API does not report.

use std::path::{Path, PathBuf};
use std::process::Command;

/// What this repository currently declares about `main`, in ONE place.
///
/// Changing protection means changing this constant and the prose in
/// `docs/internals/build-ci-release.md` together. The failure messages below
/// name both, because a gate whose fixer is ambiguous gets worked around.
const DECLARED_ENFORCE_ADMINS: bool = false;
const DECLARED_REQUIRES_PULL_REQUEST: bool = true;
const DECLARED_STATUS_CHECK: &str = "CI success";

fn repo() -> &'static Path {
    static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The live protection, or `None` when `gh` genuinely cannot answer.
fn live_protection() -> Option<serde_json::Value> {
    let out = Command::new("gh")
        .args(["api", "repos/NormB/sipnab/branches/main/protection"])
        .current_dir(repo())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

/// Prove `gh` cannot answer, rather than skipping quietly.
fn why_gh_cannot_answer() -> String {
    match Command::new("gh").arg("--version").output() {
        Err(e) => format!("gh is not installed ({e})"),
        Ok(o) if !o.status.success() => "gh exits non-zero".to_string(),
        Ok(_) => "gh works but cannot read the protection endpoint (no token, \
                  no network, or the endpoint now needs a scope it lacks)"
            .to_string(),
    }
}

/// 1. The live `enforce_admins` matches what this repository declares.
#[test]
fn the_enforce_admins_switch_matches_what_the_repository_declares() {
    let Some(p) = live_protection() else {
        eprintln!(
            "branch-protection-drift: cannot read protection — {}",
            why_gh_cannot_answer()
        );
        return;
    };
    let live = p["enforce_admins"]["enabled"].as_bool();
    assert_eq!(
        live,
        Some(DECLARED_ENFORCE_ADMINS),
        "`enforce_admins` on main is {live:?}, but this repository declares \
         {DECLARED_ENFORCE_ADMINS}. This exact drift is GATE2: the switch was \
         turned on by hand on 2026-08-23 and was off again by 2026-08-26 with \
         nothing reporting it. Change BOTH or neither:\n  \
         - DECLARED_ENFORCE_ADMINS in tests/branch_protection_drift_test.rs\n  \
         - the protection section of docs/internals/build-ci-release.md\n  \
         - the GATE2 entry in docs/design/backlog.md, which records WHY"
    );
}

/// 2. The required status check is still the one the release flow depends on.
#[test]
fn the_required_status_check_is_still_the_aggregate_ci_gate() {
    let Some(p) = live_protection() else {
        eprintln!(
            "branch-protection-drift: cannot read protection — {}",
            why_gh_cannot_answer()
        );
        return;
    };
    let contexts: Vec<String> = p["required_status_checks"]["contexts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        contexts.iter().any(|c| c == DECLARED_STATUS_CHECK),
        "main no longer requires the `{DECLARED_STATUS_CHECK}` check; it \
         requires {contexts:?}. `CI success` is the aggregate job every other \
         CI job feeds, so dropping it silently removes the only check that \
         speaks for the whole matrix."
    );
}

/// 3. The pull-request requirement matches what is declared.
#[test]
fn the_pull_request_requirement_matches_what_is_declared() {
    let Some(p) = live_protection() else {
        eprintln!(
            "branch-protection-drift: cannot read protection — {}",
            why_gh_cannot_answer()
        );
        return;
    };
    let live = p.get("required_pull_request_reviews").is_some();
    assert_eq!(
        live,
        DECLARED_REQUIRES_PULL_REQUEST,
        "main {} a pull request, but this repository declares that it {}. A \
         required status check cannot gate a DIRECT push — the push creates \
         the commit and its status together, so the check has nothing to run \
         against in time. Removing the pull-request requirement therefore \
         removes the only thing that gives `{DECLARED_STATUS_CHECK}` something \
         to gate.",
        if live { "requires" } else { "does not require" },
        if DECLARED_REQUIRES_PULL_REQUEST {
            "does"
        } else {
            "does not"
        }
    );
}

/// 4. The documentation states the same `enforce_admins` value as the constant.
///
/// Without this, the two halves of the declaration drift from each other and
/// the test above keeps passing while the page a reader consults is wrong.
#[test]
fn the_documentation_states_the_same_enforce_admins_value() {
    let doc = read("docs/internals/build-ci-release.md");
    assert!(
        doc.contains("enforce_admins"),
        "docs/internals/build-ci-release.md no longer mentions \
         `enforce_admins`. It is the switch that decides whether any other \
         protection setting means anything, so a page describing this \
         repository's gates without it describes gates that may all be \
         advisory."
    );
    // The page must say which way the switch is set, in a form a reader cannot
    // misread. Both spellings below are assertions of state, not prose about
    // the setting in general.
    let says_off = doc.contains("`enforce_admins` is OFF")
        || doc.contains("`enforce_admins.enabled` **false**");
    let says_on =
        doc.contains("`enforce_admins` is ON") || doc.contains("`enforce_admins.enabled` **true**");
    assert!(
        says_off || says_on,
        "docs/internals/build-ci-release.md mentions `enforce_admins` without \
         stating whether it is on or off. Say it in one of the forms this gate \
         recognizes, so the claim stays checkable:\n  \
         \"`enforce_admins` is OFF\" / \"`enforce_admins` is ON\""
    );
    assert!(
        !(says_off && says_on),
        "docs/internals/build-ci-release.md states BOTH that `enforce_admins` \
         is on and that it is off. One of them is a leftover from the \
         2026-08-23 change or the 2026-08-26 revert; delete the stale one."
    );
    assert_eq!(
        says_on,
        !DECLARED_ENFORCE_ADMINS as u8 == 0,
        "the documentation and DECLARED_ENFORCE_ADMINS disagree: the page says \
         `enforce_admins` is {}, the constant says {DECLARED_ENFORCE_ADMINS}. \
         These are the two halves of one declaration and must move together.",
        if says_on { "ON" } else { "OFF" }
    );
}
