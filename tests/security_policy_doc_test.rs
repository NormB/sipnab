// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
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
//! - Governance: `GOVERNANCE.md` says who
//!   holds which role, how someone becomes a committer, how decisions are
//!   made, what a user can rely on while the maintainer is unavailable, and
//!   where a vulnerability is reported. It links the rules `MAINTAINERS.md`
//!   and `SECURITY.md` already state instead of copying them, and the pages a
//!   contributor reads first link it.

use std::collections::BTreeSet;
use std::path::Path;

/// Any error, boxed, so `?` works on I/O, parse and lookup failures alike.
type TestError = Box<dyn std::error::Error>;

fn read(rel: &str) -> Result<String, TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {rel}: {e}"))?)
}

/// The text of the `## {heading}` section of `doc`, up to the next `## `.
fn section(doc: &str, rel: &str, heading: &str) -> Result<String, TestError> {
    let marker = format!("## {heading}\n");
    let start = doc
        .find(&marker)
        .ok_or_else(|| format!("{rel} has no `## {heading}` section"))?;
    let body = &doc[start + marker.len()..];
    Ok(body[..body.find("\n## ").unwrap_or(body.len())].to_string())
}

/// Every `secrets.NAME` a workflow reads, except the per-run `GITHUB_TOKEN`.
fn workflow_secrets() -> Result<BTreeSet<String>, TestError> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read workflows: {e}"))? {
        let body = std::fs::read_to_string(entry.map_err(|e| format!("entry: {e}"))?.path())
            .map_err(|e| format!("read workflow: {e}"))?;
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
    Ok(out)
}

#[test]
fn security_md_names_every_secret_a_workflow_reads() -> Result<(), TestError> {
    let secrets = workflow_secrets()?;
    // 3 -> 2 (HOMEBREW-TAP-API-COMMIT-UNSIGNED): no workflow reads
    // HOMEBREW_TAP_TOKEN any more.
    assert!(
        secrets.len() >= 2,
        "found only {secrets:?}; the workflow reader broke"
    );
    let doc = read("SECURITY.md")?;
    let text = section(&doc, "SECURITY.md", "Secrets and credentials")?;
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
    Ok(())
}

#[test]
fn the_code_scanning_policy_is_stated_and_its_gate_is_required() -> Result<(), TestError> {
    let doc = read("SECURITY.md")?;
    let text = section(&doc, "SECURITY.md", "Code scanning")?;
    assert!(
        text.contains("no open") && text.contains("reason"),
        "SECURITY.md's code-scanning section must state the policy: no open \
         alerts on `main`, and a dismissal carries a reason"
    );
    let ci = read(".github/workflows/ci.yml")?;
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
    Ok(())
}

#[test]
fn maintainers_md_says_how_escalated_access_is_granted() -> Result<(), TestError> {
    let doc = read("MAINTAINERS.md")?;
    let text = section(&doc, "MAINTAINERS.md", "Getting commit access")?;
    for needle in ["reviewed pull requests", "MAINTAINERS.md"] {
        assert!(
            text.contains(needle),
            "MAINTAINERS.md's access section must mention {needle:?}"
        );
    }
    Ok(())
}

/// The value of `const {name}: &str = "...";` in the branch-protection drift
/// test. That file is the one place the required checks are declared, and it
/// compares them with the live API; an integration test cannot import another
/// test's constants, so this reads the declaration rather than copying it.
fn drift_test_constant(name: &str) -> Result<String, TestError> {
    let src = read("tests/branch_protection_drift_test.rs")?;
    let marker = format!("const {name}: &str = \"");
    let start = src
        .find(&marker)
        .ok_or_else(|| format!("branch_protection_drift_test.rs no longer declares {name}"))?
        + marker.len();
    let end = src[start..].find('"').ok_or("unterminated constant")? + start;
    Ok(src[start..end].to_string())
}

#[test]
fn contributing_md_states_the_code_review_requirements() -> Result<(), TestError> {
    let doc = read("CONTRIBUTING.md")?;
    let text = section(&doc, "CONTRIBUTING.md", "Code review")?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let status = drift_test_constant("DECLARED_STATUS_CHECK")?;
    let sign_off = drift_test_constant("DECLARED_SIGN_OFF_CHECK")?;
    assert!(
        !status.is_empty() && !sign_off.is_empty(),
        "the reader of the drift test's constants broke"
    );
    for needle in [
        format!("`{status}`"),
        format!("`{sign_off}`"),
        "CODEOWNERS".to_string(),
        "signed".to_string(),
        "sign-off".to_string(),
        "resolved".to_string(),
        "threat-model.md".to_string(),
        "PULL_REQUEST_TEMPLATE.md".to_string(),
    ] {
        assert!(
            text.contains(&needle),
            "CONTRIBUTING.md's code review section must mention {needle:?}"
        );
    }
    Ok(())
}

#[test]
fn maintainers_md_requires_two_factor_authentication_without_sms() -> Result<(), TestError> {
    let doc = read("MAINTAINERS.md")?;
    // Prose wraps at any word, so compare with every run of whitespace as one space.
    let text = section(&doc, "MAINTAINERS.md", "Getting commit access")?
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
    Ok(())
}

// ---------------------------------------------------------------------------
// Governance. Each rule is a pure function in `gov` over the text it reads,
// so one rule is driven three ways: with the real page (success), with a
// planted fault (failure) and with a shape it must read correctly (edge).
// ---------------------------------------------------------------------------

/// The `## {heading}` section of the page at `rel`, outside code blocks, with
/// every run of whitespace read as one space, because prose wraps at any word.
fn flat_section(rel: &str, heading: &str) -> Result<String, TestError> {
    Ok(gov::flat(&gov::section_body(&read(rel)?, heading)))
}

/// The sections `GOVERNANCE.md` must have, in the order a reader needs them.
const GOVERNANCE_SECTIONS: &[&str] = &[
    "Roles",
    "Becoming a committer",
    "How the project decides",
    "If the maintainer is unavailable",
    "Reporting a vulnerability",
    "Changing this document",
];

/// A page with every section and a correct roles table; each failure test
/// breaks one thing in it.
const PLANTED: &str = "# Governance\n\n## Roles\n\n\
| Role | Who | What the role can do |\n|---|---|---|\n\
| Maintainer | The table in [MAINTAINERS.md](MAINTAINERS.md) | Admin |\n\
| Committer | No one | Write |\n\
| Contributor | Anyone | Propose |\n\n\
## Becoming a committer\n\nAsk.\n\n## How the project decides\n\nPRs.\n\n\
## If the maintainer is unavailable\n\nFacts.\n\n## Reporting a vulnerability\n\n\
See SECURITY.md.\n\n## Changing this document\n\nA PR.\n";

/// The starter task form's shape, with the four fields required.
/// (Built with `concat!`: a `\` line continuation would drop the indentation
/// the form's items are found by.)
const FORM: &str = concat!(
    "name: Starter task\nbody:\n",
    "  - type: markdown\n    attributes:\n      value: Intro.\n",
    "  - type: textarea\n    id: task\n    validations:\n      required: true\n",
    "  - type: textarea\n    id: where\n    validations:\n      required: true\n",
    "  - type: textarea\n    id: test\n    validations:\n      required: true\n",
    "  - type: textarea\n    id: done\n    validations:\n      required: true\n",
);

/// The continuity section's facts, as GOVERNANCE.md states them.
const CONTINUITY: &str = "The project has one maintainer and no named successor, as \
[MAINTAINERS.md](MAINTAINERS.md#succession) states. MIT ([LICENSE-MIT](LICENSE-MIT)) or \
Apache ([LICENSE-APACHE](LICENSE-APACHE)). [SECURITY.md](SECURITY.md#verifying-a-release).";

/// The four destinations, named as GOVERNANCE.md names them.
const DESTINATIONS_TEXT: &str = "Releases go to four places: GitHub Releases on `NormB/sipnab`, \
the `sipnab` crate on crates.io, the container image `ghcr.io/normb/sipnab`, and the Homebrew \
tap `NormB/homebrew-tap`.";
const RELEASE_YML: &str = "jobs:\n  release:\n    steps:\n      - uses: softprops/action-gh-release@abc # v3\n  \
crates-io:\n    name: Publish\n  tap:\n    run: push to NormB/homebrew-tap\n";
const DOCKER_YML: &str = "env:\n  IMAGE: ghcr.io/normb/sipnab\n";

// Success: the real pages meet each rule.

#[test]
fn s01_governance_md_has_every_section_once_in_order() -> Result<(), TestError> {
    let found = gov::section_problems(&read("GOVERNANCE.md")?, GOVERNANCE_SECTIONS);
    assert!(found.is_empty(), "GOVERNANCE.md: {found:?}");
    Ok(())
}

#[test]
fn s02_the_roles_table_names_each_role_once() -> Result<(), TestError> {
    let found = gov::role_problems(&read("GOVERNANCE.md")?);
    assert!(found.is_empty(), "GOVERNANCE.md roles: {found:?}");
    Ok(())
}

/// The access and two-factor rules live in `MAINTAINERS.md`, where
/// `maintainers_md_requires_two_factor_authentication_without_sms` checks
/// them; a second copy here would drift from that one.
#[test]
fn s03_the_committer_section_links_the_access_rules_and_copies_none() -> Result<(), TestError> {
    let found = gov::access_problems(&flat_section("GOVERNANCE.md", "Becoming a committer")?);
    assert!(
        found.is_empty(),
        "GOVERNANCE.md committer section: {found:?}"
    );
    Ok(())
}

/// The reporting channel is stated once, in `SECURITY.md`;
/// `private_vulnerability_reporting_is_offered_and_described_consistently`
/// exists because two pages once named two different channels.
#[test]
fn s04_vulnerability_reports_go_to_security_md() -> Result<(), TestError> {
    let found =
        gov::vulnerability_problems(&flat_section("GOVERNANCE.md", "Reporting a vulnerability")?);
    assert!(
        found.is_empty(),
        "GOVERNANCE.md vulnerability section: {found:?}"
    );
    Ok(())
}

/// Decision (v), 2026-11-18: no named successor, stated as a fact.
#[test]
fn s05_the_continuity_section_states_facts_and_promises_no_successor() -> Result<(), TestError> {
    let text = flat_section("GOVERNANCE.md", "If the maintainer is unavailable")?;
    let found = gov::continuity_problems(&text);
    assert!(
        found.is_empty(),
        "GOVERNANCE.md continuity section: {found:?}"
    );
    Ok(())
}

/// Each place GOVERNANCE.md says a release goes is a place a workflow
/// publishes to.
#[test]
fn s06_each_release_destination_is_one_a_workflow_publishes_to() -> Result<(), TestError> {
    let text = flat_section("GOVERNANCE.md", "If the maintainer is unavailable")?;
    let found = gov::destination_problems(
        &text,
        &read(".github/workflows/release.yml")?,
        &read(".github/workflows/docker.yml")?,
    );
    assert!(
        found.is_empty(),
        "GOVERNANCE.md release destinations: {found:?}"
    );
    Ok(())
}

/// Decision (vi), 2026-11-18: the maintainer decides, and the pull request
/// that first grants commit access amends the rule.
#[test]
fn s07_the_decision_rule_and_its_amendment_are_stated() -> Result<(), TestError> {
    let found = gov::decision_problems(&flat_section("GOVERNANCE.md", "How the project decides")?);
    assert!(
        found.is_empty(),
        "GOVERNANCE.md decision section: {found:?}"
    );
    Ok(())
}

/// A starter task says what to change, where, how to test it and when it is
/// done, so someone new to the code can pick it up without asking.
#[test]
fn s08_the_starter_task_form_requires_its_four_fields() -> Result<(), TestError> {
    let found = gov::form_problems(&read(".github/ISSUE_TEMPLATE/starter_task.yml")?);
    assert!(found.is_empty(), "starter_task.yml: {found:?}");
    Ok(())
}

#[test]
fn s09_contributing_first_change_links_the_label_list_and_the_form() -> Result<(), TestError> {
    let found = gov::first_change_problems(&flat_section("CONTRIBUTING.md", "Your first change")?);
    assert!(found.is_empty(), "CONTRIBUTING.md first change: {found:?}");
    Ok(())
}

/// GOVERNANCE.md says CODEOWNERS names the maintainer for every path.
#[test]
fn s10_codeowners_names_the_maintainer_for_every_path() -> Result<(), TestError> {
    assert_eq!(
        gov::owner_of_every_path(&read(".github/CODEOWNERS")?).as_deref(),
        Some("@NormB"),
        "GOVERNANCE.md says .github/CODEOWNERS names the maintainer for every path"
    );
    Ok(())
}

#[test]
fn s11_maintainers_md_names_no_personal_address() -> Result<(), TestError> {
    let found = gov::personal_addresses(&read("MAINTAINERS.md")?);
    assert!(found.is_empty(), "MAINTAINERS.md names {found:?}");
    Ok(())
}

#[test]
fn s12_governance_md_names_no_personal_address() -> Result<(), TestError> {
    let found = gov::personal_addresses(&read("GOVERNANCE.md")?);
    assert!(found.is_empty(), "GOVERNANCE.md names {found:?}");
    Ok(())
}

#[test]
fn s13_readme_links_governance_md() -> Result<(), TestError> {
    assert!(
        gov::links_to(&read("README.md")?, "GOVERNANCE.md"),
        "README.md must link GOVERNANCE.md"
    );
    Ok(())
}

#[test]
fn s14_contributing_links_governance_md() -> Result<(), TestError> {
    assert!(
        gov::links_to(&read("CONTRIBUTING.md")?, "GOVERNANCE.md"),
        "CONTRIBUTING.md must link GOVERNANCE.md"
    );
    Ok(())
}

#[test]
fn s15_maintainers_links_governance_md() -> Result<(), TestError> {
    assert!(
        gov::links_to(&read("MAINTAINERS.md")?, "GOVERNANCE.md"),
        "MAINTAINERS.md must link GOVERNANCE.md"
    );
    Ok(())
}

#[test]
fn s16_support_links_governance_md() -> Result<(), TestError> {
    assert!(
        gov::links_to(&read("SUPPORT.md")?, "GOVERNANCE.md"),
        "SUPPORT.md must link GOVERNANCE.md"
    );
    Ok(())
}

/// The fixtures the failure tests break pass every rule unbroken, so each
/// failure below comes from the one planted fault.
#[test]
fn s17_the_unbroken_fixtures_pass() {
    assert!(
        gov::section_problems(PLANTED, GOVERNANCE_SECTIONS).is_empty(),
        "PLANTED sections"
    );
    assert!(gov::role_problems(PLANTED).is_empty(), "PLANTED roles");
    assert!(gov::form_problems(FORM).is_empty(), "FORM");
    assert!(
        gov::continuity_problems(CONTINUITY).is_empty(),
        "CONTINUITY"
    );
    assert!(
        gov::destination_problems(DESTINATIONS_TEXT, RELEASE_YML, DOCKER_YML).is_empty(),
        "DESTINATIONS_TEXT"
    );
}

// Failure: each rule refuses one planted fault, and says which.

/// `@`, joined to the samples at run time: this file is scanned as a tracked
/// file too, where tests/private_identity_test.rs's G1 refuses a literal
/// address at a domain somebody owns.
const AT: &str = "@";

fn has(found: &[String], needle: &str) -> bool {
    found.iter().any(|f| f.contains(needle))
}

#[test]
fn f01_a_missing_section_is_named() {
    let doc = PLANTED.replace("## Reporting a vulnerability\n", "");
    let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
    assert_eq!(
        found,
        ["no `## Reporting a vulnerability` section"],
        "{found:?}"
    );
}

#[test]
fn f02_a_section_twice_is_named() {
    let doc = format!("{PLANTED}\n## Roles\n");
    let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
    assert_eq!(found, ["`## Roles` appears 2 times"], "{found:?}");
}

#[test]
fn f03_a_section_out_of_order_is_named() {
    let doc = PLANTED
        .replace("## Changing this document", "## SWAP")
        .replace("## Roles\n", "## Changing this document\n")
        .replace("## SWAP", "## Roles");
    let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
    assert!(has(&found, "out of order"), "{found:?}");
}

#[test]
fn f04_a_missing_role_is_named() {
    let doc = PLANTED.replace("| Committer | No one | Write |\n", "");
    let found = gov::role_problems(&doc);
    assert_eq!(
        found,
        ["the roles table has no `Committer` row"],
        "{found:?}"
    );
}

#[test]
fn f05_a_role_twice_is_named() {
    let doc = PLANTED.replace(
        "| Contributor | Anyone | Propose |\n",
        "| Contributor | Anyone | Propose |\n| Contributor | Again | Propose |\n",
    );
    let found = gov::role_problems(&doc);
    assert_eq!(
        found,
        ["the roles table has 2 `Contributor` rows"],
        "{found:?}"
    );
}

#[test]
fn f06_a_maintainer_row_without_its_list_is_refused() {
    let doc = PLANTED.replace("The table in [MAINTAINERS.md](MAINTAINERS.md)", "Norm");
    let found = gov::role_problems(&doc);
    assert!(has(&found, "must link MAINTAINERS.md"), "{found:?}");
}

#[test]
fn f07_an_unknown_role_is_refused() {
    let doc = PLANTED.replace(
        "| Committer | No one | Write |",
        "| Successor | Someone | All |",
    );
    let found = gov::role_problems(&doc);
    assert!(has(&found, "names `Successor`"), "{found:?}");
}

#[test]
fn f08_a_copied_access_term_is_refused() {
    let found = gov::access_problems("Use TOTP. See MAINTAINERS.md#getting-commit-access.");
    assert_eq!(
        found,
        ["restates \"TOTP\" from MAINTAINERS.md; link it instead"],
        "{found:?}"
    );
}

#[test]
fn f09_a_committer_section_without_the_link_is_refused() {
    let found = gov::access_problems("Ask the maintainer.");
    assert!(
        has(&found, "must link MAINTAINERS.md#getting-commit-access"),
        "{found:?}"
    );
}

#[test]
fn f10_a_vulnerability_section_without_security_md_is_refused() {
    let found = gov::vulnerability_problems("Open an issue.");
    assert!(has(&found, "must link SECURITY.md"), "{found:?}");
}

#[test]
fn f11_a_vulnerability_section_that_restates_an_address_is_refused() {
    let found = gov::vulnerability_problems("[SECURITY.md](SECURITY.md) or security@example.org");
    assert!(has(&found, "restates an address"), "{found:?}");
}

#[test]
fn f12_a_continuity_section_without_its_succession_fact_is_refused() {
    let found = gov::continuity_problems(&CONTINUITY.replace("no named successor", "a successor"));
    assert!(has(&found, "no named successor"), "{found:?}");
}

#[test]
fn f13_a_continuity_section_that_promises_a_successor_is_refused() {
    let found = gov::continuity_problems(&format!("{CONTINUITY} A committer will take over."));
    assert!(has(&found, "will take over"), "{found:?}");
}

#[test]
fn f14_a_destination_left_out_is_named() {
    let text = DESTINATIONS_TEXT.replace("`NormB/homebrew-tap`", "a tap");
    let found = gov::destination_problems(&text, RELEASE_YML, DOCKER_YML);
    assert!(has(&found, "NormB/homebrew-tap"), "{found:?}");
}

#[test]
fn f15_a_destination_no_workflow_publishes_to_is_named() {
    let release = RELEASE_YML.replace("  crates-io:\n", "  crates:\n");
    let found = gov::destination_problems(DESTINATIONS_TEXT, &release, DOCKER_YML);
    assert!(has(&found, "crates.io"), "{found:?}");
}

#[test]
fn f16_a_missing_form_field_is_named() {
    let form = FORM.replace("id: done", "id: finished");
    let found = gov::form_problems(&form);
    assert_eq!(found, ["the form has no field `done`"], "{found:?}");
}

#[test]
fn f17_an_optional_form_field_is_named() {
    let form = FORM.replacen("required: true", "required: false", 1);
    let found = gov::form_problems(&form);
    assert_eq!(found, ["the field `task` is not required"], "{found:?}");
}

#[test]
fn f18_a_form_that_applies_a_label_is_refused() {
    let form = format!("labels: [\"good first issue\"]\n{FORM}");
    let found = gov::form_problems(&form);
    assert!(has(&found, "applies a label"), "{found:?}");
}

#[test]
fn f19_codeowners_without_a_catch_all_owns_no_path() {
    assert_eq!(
        gov::owner_of_every_path("/src/ @NormB\n"),
        None,
        "no `*` line"
    );
}

#[test]
fn f20_a_personal_address_is_found() {
    let found = gov::personal_addresses(&format!("Write to a.person{AT}gmail.com today."));
    assert_eq!(found, [format!("a.person{AT}gmail.com")], "{found:?}");
}

#[test]
fn f21_a_page_without_the_link_does_not_link() {
    assert!(
        !gov::links_to("See GOVERNANCE.md for the rules.", "GOVERNANCE.md"),
        "bare name"
    );
}

#[test]
fn f22_a_decision_section_without_the_amendment_is_refused() {
    let found = gov::decision_problems("The maintainer makes the final decision.");
    assert!(has(&found, "grants access"), "{found:?}");
}

// Edge: shapes each rule must read correctly.

#[test]
fn e01_trailing_spaces_and_crlf_line_ends_are_read() {
    let doc = PLANTED
        .replace("## Roles\n", "## Roles  \n")
        .replace('\n', "\r\n");
    let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
    assert!(found.is_empty(), "{found:?}");
    assert!(
        gov::role_problems(&doc).is_empty(),
        "CRLF table: {:?}",
        gov::role_problems(&doc)
    );
}

#[test]
fn e02_a_deeper_or_longer_heading_is_not_the_section() {
    for wrong in ["### Roles\n", "## Roles and duties\n"] {
        let doc = PLANTED.replace("## Roles\n", wrong);
        let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
        assert_eq!(found, ["no `## Roles` section"], "{wrong:?}: {found:?}");
    }
}

#[test]
fn e03_a_heading_in_a_code_block_is_not_a_section() {
    let doc = format!("{PLANTED}\n```\n## Roles\n```\n");
    let found = gov::section_problems(&doc, GOVERNANCE_SECTIONS);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e04_the_header_and_separator_rows_are_not_roles() {
    let rows = gov::roles(PLANTED);
    let names: Vec<&str> = rows.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(
        names,
        ["Maintainer", "Committer", "Contributor"],
        "{rows:?}"
    );
}

#[test]
fn e05_a_pipe_inside_code_stays_in_its_cell() {
    assert_eq!(
        gov::cells("| `a|b` | c |"),
        ["`a|b`", "c"],
        "a pipe between backticks does not split the cell"
    );
}

#[test]
fn e06_a_promise_is_found_in_any_case() {
    let found = gov::continuity_problems(&format!("{CONTINUITY} SOMEONE WILL TAKE OVER."));
    assert!(has(&found, "will take over"), "{found:?}");
}

#[test]
fn e07_relative_and_anchored_links_count_and_code_does_not() {
    assert!(
        gov::links_to("[g](./GOVERNANCE.md)", "GOVERNANCE.md"),
        "./ prefix"
    );
    assert!(
        gov::links_to("[g](GOVERNANCE.md#roles)", "GOVERNANCE.md"),
        "anchor"
    );
    assert!(
        !gov::links_to("```\n[g](GOVERNANCE.md)\n```\n", "GOVERNANCE.md"),
        "code block"
    );
}

#[test]
fn e08_codeowners_reads_the_last_catch_all_and_skips_comments() {
    assert_eq!(
        gov::owner_of_every_path("# * @someone\n* @first\n/docs/ @docs\n*   @NormB\n").as_deref(),
        Some("@NormB"),
        "GitHub applies the last matching line; a comment is not a line"
    );
}

#[test]
fn e09_reserved_addresses_are_not_personal() {
    let text = "a@example.com b@example.org c@ci.example.net d@host.invalid e@x.test f@y.example";
    let found = gov::personal_addresses(text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e10_an_extra_optional_form_field_is_allowed() {
    let form = format!("{FORM}  - type: input\n    id: version\n");
    let found = gov::form_problems(&form);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e11_a_field_id_must_match_whole() {
    let form = FORM.replace("id: task\n", "id: tasks\n");
    let found = gov::form_problems(&form);
    assert_eq!(found, ["the form has no field `task`"], "{found:?}");
}

#[test]
fn e12_an_empty_page_misses_every_section() {
    let found = gov::section_problems("", GOVERNANCE_SECTIONS);
    assert_eq!(found.len(), GOVERNANCE_SECTIONS.len(), "{found:?}");
}

#[test]
fn e13_only_the_first_table_of_the_roles_section_is_read() {
    let doc = PLANTED.replace(
        "\n## Becoming a committer",
        "\n| Area | Who |\n|---|---|\n| HEP | No one |\n\n## Becoming a committer",
    );
    assert!(
        gov::role_problems(&doc).is_empty(),
        "{:?}",
        gov::role_problems(&doc)
    );
}

#[test]
fn e14_another_fields_required_flag_does_not_count() {
    let form = FORM.replacen("required: true", "required: false", 1)
        + "  - type: textarea\n    id: extra\n    validations:\n      required: true\n";
    let found = gov::form_problems(&form);
    assert_eq!(found, ["the field `task` is not required"], "{found:?}");
}

#[test]
fn e15_an_address_ending_a_sentence_is_read_without_the_period() {
    let found = gov::personal_addresses(&format!("Mail x{AT}corp.co. Or (y{AT}corp.co)."));
    assert_eq!(
        found,
        [format!("x{AT}corp.co"), format!("y{AT}corp.co")],
        "{found:?}"
    );
}

#[test]
fn e16_the_projects_published_address_is_not_personal_and_a_lookalike_is() {
    let text = format!("security@sipnab.com SECURITY@SIPNAB.COM a{AT}sipnab.com.evil.co");
    let found = gov::personal_addresses(&text);
    assert_eq!(found, [format!("a{AT}sipnab.com.evil.co")], "{found:?}");
}

// ---------------------------------------------------------------------------
// The retired CLA (owner decisions (i), (iii) and (iv), 2026-11-18). No page
// sends a contributor to the signing flow or calls `license/cla` required; the
// pages that keep the agreement say it is retired; the code review section
// names the checks main requires.
// ---------------------------------------------------------------------------

/// The pages a contributor reads, and the site's copies of them.
const CONTRIBUTOR_PAGES: &[&str] = &[
    "README.md",
    "CONTRIBUTING.md",
    "MAINTAINERS.md",
    "website/content/cla.md",
    "website/content/docs/contributing.md",
    "website/templates/index.html",
    "docs/internals/build-ci-release.md",
];

/// The checks main requires that the code review section names.
fn required_checks() -> Result<Vec<String>, TestError> {
    Ok(vec![
        drift_test_constant("DECLARED_STATUS_CHECK")?,
        drift_test_constant("DECLARED_SIGN_OFF_CHECK")?,
    ])
}

const NOTICE: &str = "**This agreement is retired.** sipnab no longer collects signatures. \
Sign off instead: [Signing off commits](CONTRIBUTING.md#signing-off-commits).";

fn page_routes(rel: &str) -> Result<Vec<String>, TestError> {
    Ok(agreement::signing_routes(&read(rel)?))
}

#[test]
fn a01_readme_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[0])?;
    assert!(found.is_empty(), "README.md: {found:?}");
    Ok(())
}

#[test]
fn a02_contributing_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[1])?;
    assert!(found.is_empty(), "CONTRIBUTING.md: {found:?}");
    Ok(())
}

#[test]
fn a03_maintainers_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[2])?;
    assert!(found.is_empty(), "MAINTAINERS.md: {found:?}");
    Ok(())
}

#[test]
fn a04_the_retired_cla_page_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[3])?;
    assert!(found.is_empty(), "website/content/cla.md: {found:?}");
    Ok(())
}

#[test]
fn a05_the_site_contributing_page_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[4])?;
    assert!(
        found.is_empty(),
        "website/content/docs/contributing.md: {found:?}"
    );
    Ok(())
}

#[test]
fn a06_the_homepage_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[5])?;
    assert!(found.is_empty(), "website/templates/index.html: {found:?}");
    Ok(())
}

#[test]
fn a07_the_release_page_sends_no_one_to_the_signing_flow() -> Result<(), TestError> {
    let found = page_routes(CONTRIBUTOR_PAGES[6])?;
    assert!(
        found.is_empty(),
        "docs/internals/build-ci-release.md: {found:?}"
    );
    Ok(())
}

#[test]
fn a08_the_retired_cla_page_says_it_is_retired() -> Result<(), TestError> {
    // The body a reader sees, not the front matter's description.
    let page = read("website/content/cla.md")?;
    let body = page
        .splitn(3, "+++")
        .nth(2)
        .ok_or("website/content/cla.md has no front matter")?;
    let found = agreement::notice_problems(body);
    assert!(found.is_empty(), "website/content/cla.md body: {found:?}");
    Ok(())
}

#[test]
fn a09_contributings_agreement_section_says_it_is_retired() -> Result<(), TestError> {
    let text = flat_section("CONTRIBUTING.md", "Contributor license agreement")?;
    let found = agreement::notice_problems(&text);
    assert!(found.is_empty(), "CONTRIBUTING.md: {found:?}");
    Ok(())
}

#[test]
fn a10_maintainers_agreement_section_says_it_is_retired() -> Result<(), TestError> {
    let text = flat_section("MAINTAINERS.md", "The contributor agreement")?;
    let found = agreement::notice_problems(&text);
    assert!(found.is_empty(), "MAINTAINERS.md: {found:?}");
    Ok(())
}

#[test]
fn a11_the_site_contributing_copy_says_it_is_retired() -> Result<(), TestError> {
    let text = flat_section(
        "website/content/docs/contributing.md",
        "Contributor license agreement",
    )?;
    let found = agreement::notice_problems(&text);
    assert!(
        found.is_empty(),
        "website/content/docs/contributing.md: {found:?}"
    );
    Ok(())
}

#[test]
fn a12_the_code_review_section_names_every_required_check() -> Result<(), TestError> {
    let text = flat_section("CONTRIBUTING.md", "Code review")?;
    let found = agreement::unnamed_checks(&text, &required_checks()?);
    assert!(
        found.is_empty(),
        "CONTRIBUTING.md's code review section leaves out {found:?}"
    );
    Ok(())
}

#[test]
fn a13_no_contributor_page_calls_the_retired_check_required() -> Result<(), TestError> {
    for rel in CONTRIBUTOR_PAGES {
        let found = agreement::retired_check_called_required(&gov::flat(&read(rel)?));
        assert!(
            found.is_empty(),
            "{rel} calls `license/cla` required: {found:?}"
        );
    }
    Ok(())
}

#[test]
fn a14_the_drift_test_declares_dco_required() -> Result<(), TestError> {
    assert_eq!(
        drift_test_constant("DECLARED_SIGN_OFF_CHECK")?,
        "DCO",
        "the required sign-off check is the `DCO` job of pr-text.yml"
    );
    assert_eq!(
        drift_test_constant("RETIRED_CLA_CHECK")?,
        "license/cla",
        "the retired check the drift test refuses as required"
    );
    Ok(())
}

#[test]
fn a15_readme_links_the_sign_off_how_to() -> Result<(), TestError> {
    assert!(
        read("README.md")?.contains("(CONTRIBUTING.md#signing-off-commits)"),
        "README.md must link CONTRIBUTING.md#signing-off-commits"
    );
    Ok(())
}

#[test]
fn a16_the_unbroken_fixtures_pass() {
    assert!(agreement::notice_problems(NOTICE).is_empty(), "NOTICE");
    assert!(
        agreement::signing_routes(NOTICE).is_empty(),
        "NOTICE routes"
    );
    let checks = ["CI success".to_string(), "DCO".to_string()];
    assert!(
        agreement::unnamed_checks("Requires `CI success` and `DCO`.", &checks).is_empty(),
        "both named"
    );
}

#[test]
fn b01_a_signing_service_link_is_found() {
    let found = agreement::signing_routes("[sign](https://cla-assistant.io/NormB/sipnab)");
    assert_eq!(found, ["cla-assistant.io"], "{found:?}");
}

#[test]
fn b02_an_instruction_to_sign_is_found() {
    let found = agreement::signing_routes("Sign the CLA before your first pull request.");
    assert_eq!(found, ["sign the cla"], "{found:?}");
}

#[test]
fn b03_the_signing_sentence_is_found() {
    let found = agreement::signing_routes("> I have read the CLA Document and I hereby sign it");
    assert_eq!(found, ["hereby sign"], "{found:?}");
}

#[test]
fn b04_the_signing_bot_is_found() {
    let found = agreement::signing_routes("the `CLAassistant` bot comments");
    assert_eq!(found, ["claassistant"], "{found:?}");
}

#[test]
fn b05_a_badge_of_the_service_is_found() {
    let found =
        agreement::signing_routes("[![CLA](https://cla-assistant.io/readme/badge/NormB/sipnab)]");
    assert_eq!(found, ["cla-assistant.io"], "{found:?}");
}

#[test]
fn b06_a_sign_button_is_found() {
    let found = agreement::signing_routes("<a class=\"btn\" href=\"x\">Sign the CLA &rarr;</a>");
    assert_eq!(found, ["sign the cla"], "{found:?}");
}

#[test]
fn b07_a_notice_without_retired_is_refused() {
    let found = agreement::notice_problems(&NOTICE.replace("retired", "kept"));
    assert!(gov_has(&found, "retired"), "{found:?}");
}

#[test]
fn b08_a_notice_that_still_collects_signatures_is_refused() {
    let found = agreement::notice_problems(&NOTICE.replace("no longer collects", "collects"));
    assert!(
        gov_has(&found, "no longer collects signatures"),
        "{found:?}"
    );
}

#[test]
fn b09_a_notice_without_the_sign_off_link_is_refused() {
    let found = agreement::notice_problems(
        &NOTICE.replace("#signing-off-commits", "#pull-request-process"),
    );
    assert!(gov_has(&found, "signing-off-commits"), "{found:?}");
}

#[test]
fn b10_a_required_check_left_out_is_named() {
    let checks = ["CI success".to_string(), "DCO".to_string()];
    let found = agreement::unnamed_checks("Requires `CI success`.", &checks);
    assert_eq!(found, ["DCO"], "{found:?}");
}

#[test]
fn b11_calling_the_retired_check_required_is_found() {
    let found =
        agreement::retired_check_called_required("Branch protection requires `license/cla`.");
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn b12_the_old_pair_of_required_checks_is_found() {
    let found = agreement::retired_check_called_required(
        "It is fine. Branch protection on `main` requires `CI success` and `license/cla`. Done.",
    );
    assert_eq!(
        found,
        ["Branch protection on `main` requires `CI success` and `license/cla`"],
        "{found:?}"
    );
}

#[test]
fn b13_a_merge_that_waits_for_the_retired_check_is_found() {
    let found = agreement::retired_check_called_required(
        "A pull request cannot merge until the `license/cla` check passes.",
    );
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn b14_each_kind_of_route_is_reported_once() {
    let found = agreement::signing_routes(
        "Sign the CLA. Sign the CLA again at cla-assistant.io/x/y or cla-assistant.io/z.",
    );
    assert_eq!(found, ["cla-assistant.io", "sign the cla"], "{found:?}");
}

#[test]
fn b15_a_notice_with_every_fault_reports_each() {
    let found = agreement::notice_problems("This page holds an agreement.");
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn c01_a_route_is_found_in_any_case() {
    let found = agreement::signing_routes("SIGN THE CLA NOW");
    assert_eq!(found, ["sign the cla"], "{found:?}");
}

#[test]
fn c02_a_route_wrapped_across_lines_is_found() {
    let found = agreement::signing_routes("Please sign the\nCLA before you open it.");
    assert_eq!(found, ["sign the cla"], "{found:?}");
}

#[test]
fn c03_words_that_contain_cla_are_not_routes() {
    let found = agreement::signing_routes(
        "We declare and sign the clause and its claims; SIGN THE CLAUSE.",
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn c04_saying_the_cla_is_retired_is_not_a_route() {
    let found =
        agreement::signing_routes("The CLA is retired. Contributor License Agreement (retired).");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn c05_no_longer_requiring_the_retired_check_is_allowed() {
    for text in [
        "Branch protection no longer requires `license/cla`.",
        "Branch protection does not require `license/cla`, and CLA Assistant is off.",
        "Main requires `DCO` in place of the retired `license/cla`.",
    ] {
        let found = agreement::retired_check_called_required(text);
        assert!(found.is_empty(), "{text:?}: {found:?}");
    }
}

#[test]
fn c06_the_retired_check_in_another_sentence_than_requires_is_not_required() {
    let found = agreement::retired_check_called_required(
        "Branch protection requires `DCO`. The `license/cla` status was the old one.",
    );
    assert_eq!(
        found,
        ["The `license/cla` status was the old one"],
        "{found:?}"
    );
}

#[test]
fn c07_a_bare_check_name_without_backticks_is_not_named() {
    let checks = ["DCO".to_string()];
    let found = agreement::unnamed_checks("The DCO check is required.", &checks);
    assert_eq!(found, ["DCO"], "{found:?}");
}

#[test]
fn c08_an_empty_text_has_no_route_and_every_notice_fault() {
    assert!(agreement::signing_routes("").is_empty(), "empty routes");
    assert_eq!(agreement::notice_problems("").len(), 3, "empty notice");
}

#[test]
fn c09_crlf_text_is_read() {
    let found = agreement::signing_routes("Sign the\r\nCLA.\r\n");
    assert_eq!(found, ["sign the cla"], "{found:?}");
}

#[test]
fn c10_both_spellings_of_the_sign_off_link_count() {
    for link in [
        "(CONTRIBUTING.md#signing-off-commits)",
        "(@/docs/contributing.md#signing-off-commits)",
        "(#signing-off-commits)",
    ] {
        let text = NOTICE.replace("(CONTRIBUTING.md#signing-off-commits)", link);
        let found = agreement::notice_problems(&text);
        assert!(found.is_empty(), "{link}: {found:?}");
    }
}

#[test]
fn c11_retired_is_read_in_any_case() {
    let found = agreement::notice_problems(&NOTICE.replace("retired", "RETIRED"));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn c12_a_check_named_twice_is_named() {
    let checks = ["DCO".to_string()];
    assert!(
        agreement::unnamed_checks("`DCO`, then `DCO` again.", &checks).is_empty(),
        "named twice is named"
    );
}

#[test]
fn c13_a_requires_sentence_without_the_retired_check_is_allowed() {
    let found = agreement::retired_check_called_required(
        "Branch protection requires `CI success` and `DCO`.",
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn c14_a_longer_check_name_does_not_count_for_a_shorter_one() {
    let checks = ["DCO".to_string()];
    let found = agreement::unnamed_checks("`DCO (advisory)` runs.", &checks);
    assert_eq!(found, ["DCO"], "{found:?}");
}

#[test]
fn a17_the_homepage_carries_no_agreement_pill() -> Result<(), TestError> {
    assert!(
        !read("website/templates/index.html")?.contains("@/cla.md"),
        "the homepage still links the retired agreement as a trust claim"
    );
    Ok(())
}

#[test]
fn b16_a_signing_link_in_an_attribute_is_found() {
    let found =
        agreement::signing_routes("<a href=\"https://cla-assistant.io/NormB/sipnab\">go</a>");
    assert_eq!(found, ["cla-assistant.io"], "{found:?}");
}

#[test]
fn b17_calling_the_retired_check_a_required_check_is_found() {
    let found =
        agreement::retired_check_called_required("`license/cla` is a required check on `main`.");
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn c15_the_history_of_the_switch_is_allowed() {
    let text = "Until the switch to the DCO, contributors signed the CLA, and branch \
                protection required its `license/cla` status.";
    let found = agreement::retired_check_called_required(text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn c16_a_dot_inside_a_name_does_not_end_the_sentence() {
    let found = agreement::retired_check_called_required(
        "Run `check-dco.py` and it requires `license/cla`.",
    );
    assert_eq!(
        found,
        ["Run `check-dco.py` and it requires `license/cla`"],
        "{found:?}"
    );
}

fn gov_has(found: &[String], needle: &str) -> bool {
    found.iter().any(|f| f.contains(needle))
}

/// The retired-CLA rules, each a pure function of the text it reads.
mod agreement {
    /// What sends a contributor to the retired signing flow, lowercase: the
    /// service, its bot, an instruction to sign, and the sentence that signed.
    pub const ROUTES: &[&str] = &[
        "cla-assistant.io",
        "claassistant",
        "hereby sign",
        "sign the cla",
    ];

    /// Each kind of route in `text`, once, in ROUTES order; whitespace runs
    /// (line wraps) read as one space, case ignored.
    pub fn signing_routes(text: &str) -> Vec<String> {
        let flat = super::gov::flat(text).to_lowercase();
        ROUTES
            .iter()
            .filter(|r| {
                flat.match_indices(**r).any(|(at, _)| {
                    let end = at + r.len();
                    !flat[end..].starts_with(|c: char| c.is_ascii_alphanumeric())
                })
            })
            .map(|r| r.to_string())
            .collect()
    }

    /// What a page that keeps the agreement must say.
    pub fn notice_problems(text: &str) -> Vec<String> {
        let lower = super::gov::flat(text).to_lowercase();
        let mut out = Vec::new();
        if !lower.contains("retired") {
            out.push("the notice must say the agreement is retired".to_string());
        }
        if !lower.contains("no longer collects signatures") {
            out.push("the notice must say the project no longer collects signatures".to_string());
        }
        if !lower.contains("#signing-off-commits)") {
            out.push("the notice must link the signing-off-commits how-to".to_string());
        }
        out
    }

    /// Each of `checks` that `text` does not name in backticks.
    pub fn unnamed_checks(text: &str, checks: &[String]) -> Vec<String> {
        checks
            .iter()
            .filter(|c| !text.contains(&format!("`{c}`")))
            .cloned()
            .collect()
    }

    /// Words that make a sentence about `license/cla` history, not a claim
    /// that main requires it.
    const HISTORY: &[&str] = &[
        "no longer",
        "does not require",
        "retired",
        "until the switch",
    ];

    /// Each sentence of `text` that calls the retired check required.
    pub fn retired_check_called_required(text: &str) -> Vec<String> {
        text.split(". ")
            .map(|s| s.trim().trim_end_matches('.'))
            .filter(|s| s.contains("`license/cla`"))
            .filter(|s| {
                let lower = s.to_lowercase();
                !HISTORY.iter().any(|h| lower.contains(h))
            })
            .map(str::to_string)
            .collect()
    }
}

/// The governance rules, each a pure function of the text it reads.
mod gov {
    /// The lines of `doc` outside fenced code blocks, each without its line
    /// end or trailing spaces.
    pub fn prose_lines(doc: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut fenced = false;
        for line in doc.lines() {
            let line = line.trim_end();
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
            } else if !fenced {
                out.push(line);
            }
        }
        out
    }

    /// `text` with every run of whitespace read as one space.
    pub fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The prose lines of the `## {heading}` section, up to the next `## `.
    pub fn section_body(doc: &str, heading: &str) -> String {
        let lines = prose_lines(doc);
        let marker = format!("## {heading}");
        let Some(start) = lines.iter().position(|l| *l == marker) else {
            return String::new();
        };
        lines[start + 1..]
            .iter()
            .take_while(|l| !l.starts_with("## "))
            .map(|l| format!("{l}\n"))
            .collect()
    }

    /// Each of `wanted` that is missing, there more than once, or out of order.
    pub fn section_problems(doc: &str, wanted: &[&str]) -> Vec<String> {
        let headings: Vec<&str> = prose_lines(doc)
            .into_iter()
            .filter_map(|l| l.strip_prefix("## "))
            .collect();
        let mut out = Vec::new();
        let mut last: Option<usize> = None;
        for heading in wanted {
            let at: Vec<usize> = (0..headings.len())
                .filter(|&i| headings[i] == *heading)
                .collect();
            match at.as_slice() {
                [] => out.push(format!("no `## {heading}` section")),
                [i] => {
                    if last.is_some_and(|l| *i < l) {
                        out.push(format!(
                            "`## {heading}` is out of order; the order is {wanted:?}"
                        ));
                    }
                    last = Some(*i);
                }
                many => out.push(format!("`## {heading}` appears {} times", many.len())),
            }
        }
        out
    }

    /// The cells of one Markdown table row; a `|` between backticks stays in
    /// its cell.
    pub fn cells(row: &str) -> Vec<String> {
        let row = row.trim();
        let row = row.strip_prefix('|').unwrap_or(row);
        let row = row.strip_suffix('|').unwrap_or(row);
        let mut out = vec![String::new()];
        let mut code = false;
        for c in row.chars() {
            if c == '|' && !code {
                out.push(String::new());
                continue;
            }
            if c == '`' {
                code = !code;
            }
            if let Some(cell) = out.last_mut() {
                cell.push(c);
            }
        }
        out.into_iter().map(|c| c.trim().to_string()).collect()
    }

    /// The (role, who) rows of the first table in the `## Roles` section.
    pub fn roles(doc: &str) -> Vec<(String, String)> {
        section_body(doc, "Roles")
            .lines()
            .skip_while(|l| !l.starts_with('|'))
            .take_while(|l| l.starts_with('|'))
            .skip(2)
            .map(cells)
            .filter_map(|c| Some((c.first()?.clone(), c.get(1)?.clone())))
            .collect()
    }

    /// The roles GOVERNANCE.md defines, in its order.
    pub const ROLES: &[&str] = &["Maintainer", "Committer", "Contributor"];

    /// Each role missing or repeated, each row naming no defined role, and a
    /// Maintainer row that does not point at the list of people.
    pub fn role_problems(doc: &str) -> Vec<String> {
        let rows = roles(doc);
        let mut out = Vec::new();
        for role in ROLES {
            match rows.iter().filter(|(r, _)| r == role).count() {
                0 => out.push(format!("the roles table has no `{role}` row")),
                1 => {}
                n => out.push(format!("the roles table has {n} `{role}` rows")),
            }
        }
        for (role, _) in &rows {
            if !ROLES.contains(&role.as_str()) {
                out.push(format!(
                    "the roles table names `{role}`, which is not a role this page defines"
                ));
            }
        }
        if let Some((_, who)) = rows.iter().find(|(r, _)| r == "Maintainer")
            && !who.contains("(MAINTAINERS.md)")
        {
            out.push(
                "the `Maintainer` row must link MAINTAINERS.md, which lists the people".into(),
            );
        }
        out
    }

    /// Terms of the access rules that MAINTAINERS.md states and no other page
    /// copies.
    pub const ACCESS_TERMS: &[&str] = &["SMS", "authenticator app", "security key", "TOTP"];

    pub fn access_problems(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        if !text.contains("MAINTAINERS.md#getting-commit-access") {
            out.push("the committer section must link MAINTAINERS.md#getting-commit-access".into());
        }
        for term in ACCESS_TERMS {
            if text.contains(term) {
                out.push(format!(
                    "restates {term:?} from MAINTAINERS.md; link it instead"
                ));
            }
        }
        out
    }

    pub fn vulnerability_problems(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        if !(text.contains("(SECURITY.md)") || text.contains("(SECURITY.md#")) {
            out.push("the vulnerability section must link SECURITY.md".into());
        }
        if text.contains('@') {
            out.push("the vulnerability section restates an address SECURITY.md holds".into());
        }
        out
    }

    /// What the continuity section must state, and what it must not promise.
    pub const CONTINUITY_FACTS: &[&str] = &[
        "MAINTAINERS.md#succession",
        "no named successor",
        "SECURITY.md#verifying-a-release",
        "LICENSE-MIT",
        "LICENSE-APACHE",
    ];
    pub const PROMISES: &[&str] = &[
        "escrow",
        "will take over",
        "takes over",
        "designated successor",
    ];

    pub fn continuity_problems(text: &str) -> Vec<String> {
        let mut out: Vec<String> = CONTINUITY_FACTS
            .iter()
            .filter(|f| !text.contains(**f))
            .map(|f| format!("the continuity section must state {f:?}"))
            .collect();
        let lower = text.to_lowercase();
        out.extend(
            PROMISES
                .iter()
                .filter(|p| lower.contains(**p))
                .map(|p| format!("the continuity section says {p:?}: no such arrangement exists")),
        );
        out
    }

    /// Each release destination: how GOVERNANCE.md names it, whether
    /// docker.yml (true) or release.yml (false) publishes it, and the text in
    /// that workflow that does.
    pub const DESTINATIONS: &[(&str, bool, &str)] = &[
        (
            "GitHub Releases on `NormB/sipnab`",
            false,
            "uses: softprops/action-gh-release@",
        ),
        ("`sipnab` crate on crates.io", false, "\n  crates-io:\n"),
        (
            "`ghcr.io/normb/sipnab`",
            true,
            "IMAGE: ghcr.io/normb/sipnab\n",
        ),
        ("`NormB/homebrew-tap`", false, "NormB/homebrew-tap"),
    ];

    pub fn destination_problems(text: &str, release_yml: &str, docker_yml: &str) -> Vec<String> {
        let mut out = Vec::new();
        for (name, docker, evidence) in DESTINATIONS {
            if !text.contains(name) {
                out.push(format!("the release destinations leave out {name}"));
            }
            let workflow = if *docker { docker_yml } else { release_yml };
            if !workflow.contains(evidence) {
                out.push(format!(
                    "{name} is named, but no workflow publishes to it ({evidence:?})"
                ));
            }
        }
        out
    }

    pub fn decision_problems(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        if !text.contains("The maintainer makes the final decision") {
            out.push(
                "the decision section must say the maintainer makes the final decision".into(),
            );
        }
        if !text.contains("the change that grants access also updates this section") {
            out.push(
                "the decision section must say the change that grants access amends it".into(),
            );
        }
        out
    }

    /// The fields the starter task form requires.
    pub const FORM_FIELDS: &[&str] = &["task", "where", "test", "done"];

    /// The form's body items, each from its `  - type:` line to the next.
    fn form_items(yaml: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for line in yaml.lines() {
            if line.starts_with("  - type:") {
                out.push(String::new());
            }
            if let Some(item) = out.last_mut() {
                item.push_str(line);
                item.push('\n');
            }
        }
        out
    }

    pub fn form_problems(yaml: &str) -> Vec<String> {
        let items = form_items(yaml);
        let mut out = Vec::new();
        for field in FORM_FIELDS {
            let id = format!("id: {field}");
            match items.iter().find(|i| i.lines().any(|l| l.trim() == id)) {
                None => out.push(format!("the form has no field `{field}`")),
                Some(item) if !item.lines().any(|l| l.trim() == "required: true") => {
                    out.push(format!("the field `{field}` is not required"));
                }
                Some(_) => {}
            }
        }
        if yaml.lines().any(|l| l.starts_with("labels:")) || yaml.contains("good first issue") {
            out.push("the form applies a label; a maintainer adds `good first issue` after reading the task".into());
        }
        out
    }

    pub fn first_change_problems(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        if !text.contains("labels/good%20first%20issue") {
            out.push("the first-change section must link the `good first issue` list".into());
        }
        if !text.contains("starter_task.yml") {
            out.push("the first-change section must name the starter task form".into());
        }
        out
    }

    /// The owners GitHub applies to every path: the last `*` line wins.
    pub fn owner_of_every_path(codeowners: &str) -> Option<String> {
        codeowners
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| {
                let mut words = l.split_whitespace();
                (words.next() == Some("*")).then(|| words.collect::<Vec<_>>().join(" "))
            })
            .next_back()
    }

    /// Domains reserved for examples (RFC 2606, RFC 6761).
    fn reserved(domain: &str) -> bool {
        let d = domain.to_lowercase();
        ["example.com", "example.org", "example.net"]
            .iter()
            .any(|r| d == *r || d.ends_with(&format!(".{r}")))
            || [".example", ".invalid", ".test", ".localhost"]
                .iter()
                .any(|t| d.ends_with(t))
    }

    /// The project's own domain: its addresses (`security@sipnab.com`) are
    /// published, as tests/private_identity_test.rs lists them.
    const PROJECT_DOMAIN: &str = "sipnab.com";

    /// Every email address in `text` outside the reserved domains and the
    /// project's own.
    pub fn personal_addresses(text: &str) -> Vec<String> {
        text.split(|c: char| c.is_whitespace() || "<>()[]`\"',;".contains(c))
            .map(|w| w.trim_end_matches(['.', ':']))
            .filter_map(|w| {
                let (local, domain) = w.split_once('@')?;
                let published = domain.eq_ignore_ascii_case(PROJECT_DOMAIN);
                (!local.is_empty() && domain.contains('.') && !reserved(domain) && !published)
                    .then(|| w.to_string())
            })
            .collect()
    }

    /// Whether `text` links `target`, outside code blocks.
    pub fn links_to(text: &str, target: &str) -> bool {
        let prose = prose_lines(text).join("\n");
        prose.contains(&format!("]({target}")) || prose.contains(&format!("](./{target}"))
    }
}

// Published advisories and the reporting channels.
//
// `SECURITY.md` promises public disclosure after a fix. The list of what was
// disclosed is `.config/published-advisories.txt`, committed, so the test
// reads no network: the maintainer adds a line there when GitHub publishes an
// advisory, and `SECURITY.md` must link each one with its versions and CVEs.

/// The committed list of the repository's published security advisories.
const ADVISORY_LIST: &str = ".config/published-advisories.txt";

/// A list with one advisory, and a page that states it and both channels.
const LIST_ONE: &str = "GHSA-vjqw-738j-4chx 2026-11-25 0.5.218 0.5.247 0.5.248 CVE-2023-49092\n";
const DOC_ONE: &str = "# Security Policy\n\n## Reporting a Vulnerability\n\n\
Email **security@sipnab.com**, or open a private report at\n\
<https://github.com/NormB/sipnab/security/advisories/new>.\n\n\
## Published advisories\n\n\
- [GHSA-vjqw-738j-4chx](https://github.com/NormB/sipnab/security/advisories/GHSA-vjqw-738j-4chx),\n  \
published 2026-11-25. Affects 0.5.218 to 0.5.247; fixed in 0.5.248\n  \
(CVE-2023-49092).\n\n## Next\n\nText.\n";

/// A second advisory, for the lists of two.
const LINE_TWO: &str = "GHSA-2c3f-4g5h-6j7m 2026-12-01 0.5.250 0.5.260 0.5.261 -\n";
const ITEM_TWO: &str = "- [GHSA-2c3f-4g5h-6j7m](https://github.com/NormB/sipnab/security/advisories/GHSA-2c3f-4g5h-6j7m): \
0.5.250 to 0.5.260, fixed in 0.5.261.\n";

/// `DOC_ONE` with `ITEM_TWO` added to its advisory list.
fn doc_two() -> String {
    DOC_ONE.replace(
        "(CVE-2023-49092).\n",
        &format!("(CVE-2023-49092).\n{ITEM_TWO}"),
    )
}

/// The parsed list, failing the test on any problem in it.
fn parsed(text: &str) -> Vec<adv::Advisory> {
    let (list, problems) = adv::parse_list(text);
    assert!(problems.is_empty(), "list problems: {problems:?}");
    list
}

// Success: the real files, then the fixtures.

#[test]
fn adv_s01_security_md_links_every_published_advisory() -> Result<(), TestError> {
    let list = parsed(&read(ADVISORY_LIST)?);
    let found = adv::section_problems(&read("SECURITY.md")?, &list);
    assert!(
        found.is_empty(),
        "SECURITY.md against {ADVISORY_LIST}: {found:?}"
    );
    Ok(())
}

#[test]
fn adv_s02_security_md_names_both_reporting_channels() -> Result<(), TestError> {
    let found = adv::channel_problems(&read("SECURITY.md")?);
    assert!(
        found.is_empty(),
        "SECURITY.md reporting channels: {found:?}"
    );
    Ok(())
}

/// The first advisory stays listed: it is published, and a published advisory
/// is never withdrawn from the list.
#[test]
fn adv_s03_the_list_holds_the_rsa_advisory() -> Result<(), TestError> {
    let list = parsed(&read(ADVISORY_LIST)?);
    let rsa = list
        .iter()
        .find(|a| a.id == "GHSA-vjqw-738j-4chx")
        .ok_or("the list no longer holds GHSA-vjqw-738j-4chx")?;
    assert_eq!(
        rsa.patched, "0.5.248",
        "GHSA-vjqw-738j-4chx patched version"
    );
    assert_eq!(rsa.cves, ["CVE-2023-49092"], "GHSA-vjqw-738j-4chx CVEs");
    Ok(())
}

#[test]
fn adv_s04_the_fixture_page_meets_the_fixture_list() {
    let found = adv::section_problems(DOC_ONE, &parsed(LIST_ONE));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s05_the_fixture_page_names_both_channels() {
    let found = adv::channel_problems(DOC_ONE);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s06_a_line_is_read_into_its_fields() {
    let list = parsed(LIST_ONE);
    assert_eq!(list.len(), 1, "{list:?}");
    let a = &list[0];
    assert_eq!(a.id, "GHSA-vjqw-738j-4chx", "id");
    assert_eq!(a.published, "2026-11-25", "published");
    assert_eq!(a.first, "0.5.218", "first affected");
    assert_eq!(a.last, "0.5.247", "last affected");
    assert_eq!(a.patched, "0.5.248", "patched");
    assert_eq!(a.cves, ["CVE-2023-49092"], "CVEs");
}

#[test]
fn adv_s07_comments_and_blank_lines_are_not_advisories() {
    let text = format!(
        "# The published advisories.\n\n# Format: id date first last patched cves\n{LIST_ONE}\n"
    );
    assert_eq!(parsed(&text).len(), 1, "one advisory in {text:?}");
}

#[test]
fn adv_s08_two_advisories_both_stated_pass() {
    let list = parsed(&format!("{LIST_ONE}{LINE_TWO}"));
    assert_eq!(list.len(), 2, "{list:?}");
    let found = adv::section_problems(&doc_two(), &list);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s09_an_advisory_without_a_cve_needs_none_on_the_page() {
    let list = parsed(LINE_TWO);
    assert!(list[0].cves.is_empty(), "`-` is no CVE: {list:?}");
    let doc = format!("## Published advisories\n\n{ITEM_TWO}");
    let found = adv::section_problems(&doc, &list);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s10_several_cves_are_read_and_each_is_stated() {
    let line = LIST_ONE.replace("CVE-2023-49092", "CVE-2023-49092,CVE-2024-12345");
    let list = parsed(&line);
    assert_eq!(
        list[0].cves,
        ["CVE-2023-49092", "CVE-2024-12345"],
        "{list:?}"
    );
    let doc = DOC_ONE.replace("(CVE-2023-49092)", "(CVE-2023-49092, CVE-2024-12345)");
    let found = adv::section_problems(&doc, &list);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s11_the_private_report_form_may_be_a_named_link() {
    let doc = DOC_ONE.replace(
        "<https://github.com/NormB/sipnab/security/advisories/new>",
        "[the private report form](https://github.com/NormB/sipnab/security/advisories/new)",
    );
    let found = adv::channel_problems(&doc);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s12_one_affected_release_is_a_range_of_one() {
    let list = parsed(&LIST_ONE.replace("0.5.218 0.5.247", "0.5.247 0.5.247"));
    let doc = DOC_ONE.replace("Affects 0.5.218 to 0.5.247", "Affects 0.5.247");
    let found = adv::section_problems(&doc, &list);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s13_the_page_may_state_advisories_in_another_order() {
    let list = parsed(&format!("{LINE_TWO}{LIST_ONE}"));
    let found = adv::section_problems(&doc_two(), &list);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_s14_an_empty_list_needs_only_the_section() {
    let (list, problems) = adv::parse_list("# none yet\n");
    assert!(
        list.is_empty() && problems.is_empty(),
        "{list:?} {problems:?}"
    );
    let found = adv::section_problems("## Published advisories\n\nNone yet.\n", &list);
    assert!(found.is_empty(), "{found:?}");
}

// Failure: each rule refuses one planted fault, and says which.

#[test]
fn adv_f01_a_page_without_the_section_is_refused() {
    let doc = DOC_ONE.replace("## Published advisories", "## Advisories");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "no `## Published advisories` section"),
        "{found:?}"
    );
}

#[test]
fn adv_f02_a_listed_advisory_the_page_does_not_link_is_named() {
    let list = parsed(&format!("{LIST_ONE}{LINE_TWO}"));
    let found = adv::section_problems(DOC_ONE, &list);
    assert!(
        has(&found, "does not link GHSA-2c3f-4g5h-6j7m"),
        "{found:?}"
    );
}

#[test]
fn adv_f03_an_item_without_the_patched_version_is_refused() {
    let doc = DOC_ONE.replace("; fixed in 0.5.248", "");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "GHSA-vjqw-738j-4chx: no patched version 0.5.248"),
        "{found:?}"
    );
}

#[test]
fn adv_f04_an_item_without_its_cve_is_refused() {
    let doc = DOC_ONE.replace("\n  (CVE-2023-49092)", "");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "GHSA-vjqw-738j-4chx: no CVE-2023-49092"),
        "{found:?}"
    );
}

#[test]
fn adv_f05_an_advisory_the_list_does_not_hold_is_refused() {
    let found = adv::section_problems(&doc_two(), &parsed(LIST_ONE));
    assert!(
        has(
            &found,
            "names GHSA-2c3f-4g5h-6j7m, which .config/published-advisories.txt does not list"
        ),
        "{found:?}"
    );
}

/// The global advisory database also has a page per GHSA id, but the
/// repository's own advisory is the one the project publishes and updates.
#[test]
fn adv_f06_a_link_to_the_global_database_is_not_the_repository_advisory() {
    let doc = DOC_ONE.replace(
        "https://github.com/NormB/sipnab/security/advisories/GHSA-vjqw-738j-4chx",
        "https://github.com/advisories/GHSA-vjqw-738j-4chx",
    );
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "does not link GHSA-vjqw-738j-4chx"),
        "{found:?}"
    );
}

#[test]
fn adv_f07_a_line_with_a_missing_field_is_refused() {
    let (_, problems) =
        adv::parse_list("GHSA-vjqw-738j-4chx 2026-11-25 0.5.218 0.5.248 CVE-2023-49092\n");
    assert!(has(&problems, "line 1: 5 fields, want 6"), "{problems:?}");
}

#[test]
fn adv_f08_an_id_outside_the_ghsa_alphabet_is_refused() {
    for bad in [
        "GHSA-vjqw-738j-4cha",
        "GHSA-VJQW-738J-4CHX",
        "GHSA-vjqw-738j-4ch",
        "GSHA-vjqw-738j-4chx",
    ] {
        let (_, problems) = adv::parse_list(&LIST_ONE.replace("GHSA-vjqw-738j-4chx", bad));
        assert!(
            has(&problems, &format!("line 1: {bad} is not a GHSA id")),
            "{bad}: {problems:?}"
        );
    }
}

#[test]
fn adv_f09_an_impossible_date_is_refused() {
    for bad in [
        "2026-13-01",
        "2026-00-10",
        "2026-11-32",
        "26-11-25",
        "2026/11/25",
    ] {
        let (_, problems) = adv::parse_list(&LIST_ONE.replace("2026-11-25", bad));
        assert!(
            has(&problems, &format!("line 1: {bad} is not a date")),
            "{bad}: {problems:?}"
        );
    }
}

#[test]
fn adv_f10_a_patched_version_inside_the_affected_range_is_refused() {
    let (_, problems) = adv::parse_list(&LIST_ONE.replace("0.5.248 CVE", "0.5.247 CVE"));
    assert!(
        has(
            &problems,
            "line 1: patched 0.5.247 is not after the last affected 0.5.247"
        ),
        "{problems:?}"
    );
}

#[test]
fn adv_f11_a_range_that_ends_before_it_starts_is_refused() {
    let (_, problems) = adv::parse_list(&LIST_ONE.replace("0.5.218 0.5.247", "0.5.247 0.5.218"));
    assert!(
        has(
            &problems,
            "line 1: first affected 0.5.247 is after the last 0.5.218"
        ),
        "{problems:?}"
    );
}

#[test]
fn adv_f12_a_malformed_cve_is_refused() {
    for bad in [
        "CVE-23-49092",
        "CVE-2023-492",
        "cve-2023-49092",
        "RUSTSEC-2023-0071",
    ] {
        let (_, problems) = adv::parse_list(&LIST_ONE.replace("CVE-2023-49092", bad));
        assert!(
            has(&problems, &format!("line 1: {bad} is not a CVE id")),
            "{bad}: {problems:?}"
        );
    }
}

#[test]
fn adv_f13_an_advisory_listed_twice_is_refused() {
    let (_, problems) = adv::parse_list(&format!("{LIST_ONE}{LIST_ONE}"));
    assert!(
        has(&problems, "line 2: GHSA-vjqw-738j-4chx is listed twice"),
        "{problems:?}"
    );
}

#[test]
fn adv_f14_a_reporting_section_without_the_address_is_refused() {
    let doc = DOC_ONE.replace("Email **security@sipnab.com**, or open", "Open");
    let found = adv::channel_problems(&doc);
    assert!(
        has(&found, "does not name **security@sipnab.com**"),
        "{found:?}"
    );
}

#[test]
fn adv_f15_a_reporting_section_without_the_private_form_is_refused() {
    let doc = DOC_ONE.replace(
        ", or open a private report at\n<https://github.com/NormB/sipnab/security/advisories/new>",
        "",
    );
    let found = adv::channel_problems(&doc);
    assert!(
        has(
            &found,
            "does not link https://github.com/NormB/sipnab/security/advisories/new"
        ),
        "{found:?}"
    );
}

#[test]
fn adv_f16_an_item_without_the_first_affected_version_is_refused() {
    let doc = DOC_ONE.replace(
        "Affects 0.5.218 to 0.5.247",
        "Affects releases through 0.5.247",
    );
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(
            &found,
            "GHSA-vjqw-738j-4chx: no first affected version 0.5.218"
        ),
        "{found:?}"
    );
}

#[test]
fn adv_f17_a_version_with_a_v_prefix_is_refused() {
    let (_, problems) = adv::parse_list(&LIST_ONE.replace("0.5.248 CVE", "v0.5.248 CVE"));
    assert!(
        has(&problems, "line 1: v0.5.248 is not a version"),
        "{problems:?}"
    );
}

// Edge: shapes each rule must read correctly.

#[test]
fn adv_e01_an_item_in_a_code_block_is_not_stated() {
    let doc = DOC_ONE
        .replace("- [GHSA-vjqw", "```\n- [GHSA-vjqw")
        .replace("(CVE-2023-49092).\n", "(CVE-2023-49092).\n```\n");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "does not link GHSA-vjqw-738j-4chx"),
        "{found:?}"
    );
}

#[test]
fn adv_e02_a_deeper_or_longer_heading_is_not_the_section() {
    for wrong in [
        "### Published advisories",
        "## Published advisories and drafts",
    ] {
        let doc = DOC_ONE.replace("## Published advisories", wrong);
        let found = adv::section_problems(&doc, &parsed(LIST_ONE));
        assert!(
            has(&found, "no `## Published advisories` section"),
            "{wrong}: {found:?}"
        );
    }
}

#[test]
fn adv_e03_crlf_line_ends_and_trailing_spaces_are_read() {
    let list = parsed(&LIST_ONE.replace('\n', "  \r\n"));
    let doc = DOC_ONE.replace('\n', "\r\n");
    let found = adv::section_problems(&doc, &list);
    assert!(found.is_empty(), "{found:?}");
    let found = adv::channel_problems(&doc);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn adv_e04_runs_of_spaces_and_tabs_separate_fields() {
    let list = parsed(&LIST_ONE.replace(' ', " \t  "));
    assert_eq!(list[0].patched, "0.5.248", "{list:?}");
}

#[test]
fn adv_e05_versions_compare_by_number_not_by_text() {
    let line = "GHSA-vjqw-738j-4chx 2026-11-25 0.5.9 0.5.99 0.5.100 -\n";
    let (_, problems) = adv::parse_list(line);
    assert!(
        problems.is_empty(),
        "0.5.9 < 0.5.99 < 0.5.100: {problems:?}"
    );
}

#[test]
fn adv_e06_a_longer_version_does_not_stand_for_the_patched_one() {
    let doc = DOC_ONE.replace("fixed in 0.5.248", "fixed in 0.5.2480");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(has(&found, "no patched version 0.5.248"), "{found:?}");
}

#[test]
fn adv_e07_a_longer_cve_does_not_stand_for_the_listed_one() {
    let doc = DOC_ONE.replace("CVE-2023-49092", "CVE-2023-490921");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(has(&found, "no CVE-2023-49092"), "{found:?}");
}

#[test]
fn adv_e08_the_address_in_another_section_is_not_a_channel() {
    let doc = DOC_ONE
        .replace("Email **security@sipnab.com**, or open", "Open")
        .replace(
            "## Next\n\nText.",
            "## Next\n\nEmail **security@sipnab.com**.",
        );
    let found = adv::channel_problems(&doc);
    assert!(
        has(&found, "does not name **security@sipnab.com**"),
        "{found:?}"
    );
}

#[test]
fn adv_e09_a_longer_form_url_is_not_the_private_form() {
    let doc = DOC_ONE.replace("advisories/new>", "advisories/newest>");
    let found = adv::channel_problems(&doc);
    assert!(has(&found, "does not link"), "{found:?}");
}

#[test]
fn adv_e10_the_form_url_in_a_code_span_is_not_a_link() {
    let doc = DOC_ONE.replace(
        "<https://github.com/NormB/sipnab/security/advisories/new>",
        "`https://github.com/NormB/sipnab/security/advisories/new`",
    );
    let found = adv::channel_problems(&doc);
    assert!(has(&found, "does not link"), "{found:?}");
}

#[test]
fn adv_e11_one_advisory_stated_in_two_items_is_refused() {
    let doc = DOC_ONE.replace("(CVE-2023-49092).\n", "(CVE-2023-49092).\n- [GHSA-vjqw-738j-4chx](https://github.com/NormB/sipnab/security/advisories/GHSA-vjqw-738j-4chx) again.\n");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "GHSA-vjqw-738j-4chx is stated in 2 items"),
        "{found:?}"
    );
}

#[test]
fn adv_e12_the_section_twice_is_refused() {
    let doc = format!("{DOC_ONE}\n## Published advisories\n\nMore.\n");
    let found = adv::section_problems(&doc, &parsed(LIST_ONE));
    assert!(
        has(&found, "`## Published advisories` is there 2 times"),
        "{found:?}"
    );
}

#[test]
fn adv_e13_a_version_field_with_four_parts_is_refused() {
    let (_, problems) = adv::parse_list(&LIST_ONE.replace("0.5.248 CVE", "0.5.248.1 CVE"));
    assert!(
        has(&problems, "line 1: 0.5.248.1 is not a version"),
        "{problems:?}"
    );
}

/// The rules for the published advisories and the reporting channels, each a
/// pure function of the text it reads.
mod adv {
    /// One line of `.config/published-advisories.txt`.
    #[derive(Debug)]
    pub struct Advisory {
        pub id: String,
        pub published: String,
        pub first: String,
        pub last: String,
        pub patched: String,
        pub cves: Vec<String>,
    }

    use super::{ADVISORY_LIST, gov};
    use std::collections::BTreeSet;

    /// Where the repository's own advisories are published.
    const ADVISORY_URL: &str = "https://github.com/NormB/sipnab/security/advisories/";
    /// GitHub's private vulnerability reporting form for the repository.
    const FORM_URL: &str = "https://github.com/NormB/sipnab/security/advisories/new";
    /// The reporting address, in bold as `scripts/check-security-txt.py` reads it.
    const ADDRESS: &str = "**security@sipnab.com**";
    /// The characters of the three groups of a GHSA id.
    const GHSA_ALPHABET: &str = "23456789cfghjmpqrvwx";
    /// The section that lists the published advisories.
    const SECTION: &str = "Published advisories";

    /// Whether `id` is a GHSA id: `GHSA-` and three groups of four.
    fn is_ghsa(id: &str) -> bool {
        id.strip_prefix("GHSA-").is_some_and(|rest| {
            let groups: Vec<&str> = rest.split('-').collect();
            groups.len() == 3
                && groups
                    .iter()
                    .all(|g| g.len() == 4 && g.chars().all(|c| GHSA_ALPHABET.contains(c)))
        })
    }

    /// Whether `s` is a `YYYY-MM-DD` date with a possible month and day.
    fn is_date(s: &str) -> bool {
        let parts: Vec<&str> = s.split('-').collect();
        let digits = |p: &str, n: usize| p.len() == n && p.bytes().all(|b| b.is_ascii_digit());
        if parts.len() != 3 || !digits(parts[0], 4) || !digits(parts[1], 2) || !digits(parts[2], 2)
        {
            return false;
        }
        let month: u32 = parts[1].parse().unwrap_or(0);
        let day: u32 = parts[2].parse().unwrap_or(0);
        (1..=12).contains(&month) && (1..=31).contains(&day)
    }

    /// `s` as a `MAJOR.MINOR.PATCH` version, compared by number.
    fn version(s: &str) -> Option<[u64; 3]> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        let mut out = [0; 3];
        for (slot, p) in out.iter_mut().zip(&parts) {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *slot = p.parse().ok()?;
        }
        Some(out)
    }

    /// Whether `s` is a CVE id: `CVE-`, a four-digit year, four or more digits.
    fn is_cve(s: &str) -> bool {
        s.strip_prefix("CVE-")
            .and_then(|rest| rest.split_once('-'))
            .is_some_and(|(year, num)| {
                year.len() == 4
                    && num.len() >= 4
                    && year.bytes().chain(num.bytes()).all(|b| b.is_ascii_digit())
            })
    }

    /// The advisories of `text`, and every problem with a line of it. A line
    /// with a problem is not an advisory.
    pub fn parse_list(text: &str) -> (Vec<Advisory>, Vec<String>) {
        let mut list = Vec::new();
        let mut problems = Vec::new();
        let mut seen = BTreeSet::new();
        for (i, line) in text.lines().enumerate() {
            let n = i + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [id, published, first, last, patched, cves] = fields[..] else {
                problems.push(format!("line {n}: {} fields, want 6", fields.len()));
                continue;
            };
            let before = problems.len();
            if !is_ghsa(id) {
                problems.push(format!("line {n}: {id} is not a GHSA id"));
            } else if !seen.insert(id) {
                problems.push(format!("line {n}: {id} is listed twice"));
            }
            if !is_date(published) {
                problems.push(format!("line {n}: {published} is not a date"));
            }
            let versions: Vec<Option<[u64; 3]>> = [first, last, patched]
                .iter()
                .map(|v| {
                    let parsed = version(v);
                    if parsed.is_none() {
                        problems.push(format!("line {n}: {v} is not a version"));
                    }
                    parsed
                })
                .collect();
            if let [Some(f), Some(l), Some(p)] = versions[..] {
                if f > l {
                    problems.push(format!(
                        "line {n}: first affected {first} is after the last {last}"
                    ));
                }
                if p <= l {
                    problems.push(format!(
                        "line {n}: patched {patched} is not after the last affected {last}"
                    ));
                }
            }
            let cves: Vec<String> = if cves == "-" {
                Vec::new()
            } else {
                cves.split(',').map(str::to_string).collect()
            };
            for c in cves.iter().filter(|c| !is_cve(c)) {
                problems.push(format!("line {n}: {c} is not a CVE id"));
            }
            if problems.len() == before {
                list.push(Advisory {
                    id: id.to_string(),
                    published: published.to_string(),
                    first: first.to_string(),
                    last: last.to_string(),
                    patched: patched.to_string(),
                    cves,
                });
            }
        }
        (list, problems)
    }

    /// The list items of a section body: a `- ` line starts one, an indented
    /// line continues it, any other line ends it.
    fn items(body: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut open = false;
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("- ") {
                out.push(rest.to_string());
                open = true;
            } else if open && line.starts_with(' ') && !line.trim().is_empty() {
                if let Some(last) = out.last_mut() {
                    last.push(' ');
                    last.push_str(line.trim());
                }
            } else {
                open = false;
            }
        }
        out
    }

    /// The words of `text` that can be a version, a CVE or a GHSA id: runs
    /// of letters, digits, `.` and `-`, without a sentence's final `.`.
    fn words(text: &str) -> BTreeSet<&str> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
            .map(|w| w.trim_end_matches('.'))
            .filter(|w| !w.is_empty())
            .collect()
    }

    /// How the `## Published advisories` section of `doc` disagrees with
    /// `list`: each advisory is linked at the repository's advisory page in
    /// one list item that names its affected versions, its patched version
    /// and its CVEs, and the section names no advisory the list lacks.
    pub fn section_problems(doc: &str, list: &[Advisory]) -> Vec<String> {
        let marker = format!("## {SECTION}");
        let count = gov::prose_lines(doc)
            .iter()
            .filter(|l| **l == marker)
            .count();
        if count == 0 {
            return vec![format!("no `{marker}` section")];
        }
        let mut out = Vec::new();
        if count > 1 {
            out.push(format!("`{marker}` is there {count} times"));
        }
        let body = gov::section_body(doc, SECTION);
        let items = items(&body);
        for a in list {
            let link = format!("]({ADVISORY_URL}{})", a.id);
            let holding: Vec<&String> = items.iter().filter(|i| i.contains(&link)).collect();
            let item = match holding[..] {
                [item] => item,
                [] => {
                    out.push(format!(
                        "SECURITY.md does not link {} at {ADVISORY_URL}{}",
                        a.id, a.id
                    ));
                    continue;
                }
                _ => {
                    out.push(format!("{} is stated in {} items", a.id, holding.len()));
                    continue;
                }
            };
            let found = words(item);
            for (what, want) in [
                ("first affected version", &a.first),
                ("last affected version", &a.last),
                ("patched version", &a.patched),
            ] {
                if !found.contains(want.as_str()) {
                    out.push(format!("{}: no {what} {want}", a.id));
                }
            }
            for cve in a.cves.iter().filter(|c| !found.contains(c.as_str())) {
                out.push(format!("{}: no {cve}", a.id));
            }
        }
        let listed: BTreeSet<&str> = list.iter().map(|a| a.id.as_str()).collect();
        for id in words(&body).into_iter().filter(|w| w.starts_with("GHSA-")) {
            if !listed.contains(id) {
                out.push(format!(
                    "SECURITY.md names {id}, which {ADVISORY_LIST} does not list"
                ));
            }
        }
        out
    }

    /// How the `## Reporting a Vulnerability` section of `doc` fails to name
    /// the email address and to link the private report form.
    pub fn channel_problems(doc: &str) -> Vec<String> {
        let heading = "Reporting a Vulnerability";
        let body = gov::flat(&gov::section_body(doc, heading));
        if body.is_empty() {
            return vec![format!("no `## {heading}` section")];
        }
        let mut out = Vec::new();
        if !body.contains(ADDRESS) {
            out.push(format!("the reporting section does not name {ADDRESS}"));
        }
        if !(body.contains(&format!("<{FORM_URL}>")) || body.contains(&format!("]({FORM_URL})"))) {
            out.push(format!("the reporting section does not link {FORM_URL}"));
        }
        out
    }
}
