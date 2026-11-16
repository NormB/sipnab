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
    let cla = drift_test_constant("DECLARED_CLA_CHECK")?;
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
