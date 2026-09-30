// SPDX-License-Identifier: MIT OR Apache-2.0
//! The security policies OpenSSF Baseline asks for are written down, and each
//! written policy matches what the repository actually does.
//!
//! - BR-07.02: `SECURITY.md` says how secrets are stored and managed. It must
//!   name every secret a workflow reads, so a new secret cannot arrive
//!   undocumented.
//! - VM-06.01: `SECURITY.md` states the code-scanning policy, and the gate that
//!   enforces it (`code-scanning-clean`) still feeds the required `CI success`.
//! - GV-04.01: `MAINTAINERS.md` says how someone is given escalated access.
//! - OpenSSF Gold `code_review_standards`: `CONTRIBUTING.md` says who reviews a
//!   change, how, what is checked, and what makes it acceptable, naming the
//!   required checks exactly as `tests/branch_protection_drift_test.rs`
//!   declares them.
//! - OpenSSF Gold `require_2FA` and `secure_2FA`: `MAINTAINERS.md` requires
//!   two-factor authentication for write access and credentials, and does not
//!   accept SMS as the second factor.

use std::collections::BTreeSet;
use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The text of the `## {heading}` section of `doc`, up to the next `## `.
fn section(doc: &str, rel: &str, heading: &str) -> String {
    let marker = format!("## {heading}\n");
    let start = doc
        .find(&marker)
        .unwrap_or_else(|| panic!("{rel} has no `## {heading}` section"));
    let body = &doc[start + marker.len()..];
    body[..body.find("\n## ").unwrap_or(body.len())].to_string()
}

/// Every `secrets.NAME` a workflow reads, except the per-run `GITHUB_TOKEN`.
fn workflow_secrets() -> BTreeSet<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("read workflows") {
        let body = std::fs::read_to_string(entry.expect("entry").path()).expect("read workflow");
        for piece in body.split("secrets.").skip(1) {
            let name: String = piece
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() && name != "GITHUB_TOKEN" {
                out.insert(name);
            }
        }
    }
    out
}

#[test]
fn security_md_names_every_secret_a_workflow_reads() {
    let secrets = workflow_secrets();
    assert!(
        secrets.len() >= 3,
        "found only {secrets:?}; the workflow reader broke"
    );
    let doc = read("SECURITY.md");
    let text = section(&doc, "SECURITY.md", "Secrets and credentials");
    let missing: Vec<_> = secrets
        .iter()
        .filter(|s| !text.contains(s.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "workflows read {missing:?}, which the secrets section of SECURITY.md does \
         not name; say what each is for, who holds it and when it is rotated"
    );
    assert!(
        text.contains("trusted publishing"),
        "the secrets section must say crates.io publishing stores no token"
    );
}

#[test]
fn the_code_scanning_policy_is_stated_and_its_gate_is_required() {
    let doc = read("SECURITY.md");
    let text = section(&doc, "SECURITY.md", "Code scanning");
    assert!(
        text.contains("no open") && text.contains("reason"),
        "SECURITY.md's code-scanning section must state the policy: no open \
         alerts on `main`, and a dismissal carries a reason"
    );
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("  code-scanning-clean:"),
        "ci.yml no longer has the code-scanning-clean job the policy relies on"
    );
    let needs = ci
        .split("\n  ci-success:")
        .nth(1)
        .and_then(|rest| rest.split("needs:").nth(1))
        .map(|n| n.split(']').next().unwrap_or_default().to_string())
        .unwrap_or_default();
    assert!(
        needs.contains("code-scanning-clean"),
        "the required `CI success` job must need code-scanning-clean, or the \
         stated policy is advisory"
    );
}

#[test]
fn maintainers_md_says_how_escalated_access_is_granted() {
    let doc = read("MAINTAINERS.md");
    let text = section(&doc, "MAINTAINERS.md", "Getting commit access");
    for needle in ["reviewed pull requests", "MAINTAINERS.md"] {
        assert!(
            text.contains(needle),
            "MAINTAINERS.md's access section must mention {needle:?}"
        );
    }
}

/// The value of `const {name}: &str = "...";` in the branch-protection drift
/// test. That file is the one place the required checks are declared, and it
/// compares them with the live API; an integration test cannot import another
/// test's constants, so this reads the declaration rather than copying it.
fn drift_test_constant(name: &str) -> String {
    let src = read("tests/branch_protection_drift_test.rs");
    let marker = format!("const {name}: &str = \"");
    let start = src
        .find(&marker)
        .unwrap_or_else(|| panic!("branch_protection_drift_test.rs no longer declares {name}"))
        + marker.len();
    let end = src[start..].find('"').expect("unterminated constant") + start;
    src[start..end].to_string()
}

#[test]
fn contributing_md_states_the_code_review_requirements() {
    let doc = read("CONTRIBUTING.md");
    let text = section(&doc, "CONTRIBUTING.md", "Code review")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let status = drift_test_constant("DECLARED_STATUS_CHECK");
    let cla = drift_test_constant("DECLARED_CLA_CHECK");
    assert!(
        !status.is_empty() && !cla.is_empty(),
        "the reader of the drift test's constants broke"
    );
    for needle in [
        format!("`{status}`"),
        format!("`{cla}`"),
        "CODEOWNERS".to_string(),
        "signed".to_string(),
        "CLA".to_string(),
        "resolved".to_string(),
        "threat-model.md".to_string(),
        "PULL_REQUEST_TEMPLATE.md".to_string(),
    ] {
        assert!(
            text.contains(&needle),
            "CONTRIBUTING.md's code review section must mention {needle:?}"
        );
    }
}

#[test]
fn maintainers_md_requires_two_factor_authentication_without_sms() {
    let doc = read("MAINTAINERS.md");
    // Prose wraps at any word, so compare with every run of whitespace as one space.
    let text = section(&doc, "MAINTAINERS.md", "Getting commit access")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for needle in [
        "two-factor authentication",
        "authenticator app",
        "security key",
    ] {
        assert!(
            text.contains(needle),
            "MAINTAINERS.md's access section must require {needle:?}"
        );
    }
    assert!(
        text.contains("SMS is not accepted"),
        "MAINTAINERS.md's access section must say SMS is not an accepted second factor"
    );
}
