// SPDX-License-Identifier: MIT OR Apache-2.0

//! The OpenSSF Best Practices Badge answer sheet must keep telling the truth.
//!
//! `docs/design/openssf-badge-answers.md` answers every passing-level criterion
//! and cites a file or a repository setting for each. That is a page full of
//! restated facts about the repo, which is the exact shape that rots: the sheet
//! shipped claiming 10 fuzz targets when there were 15, because the number came
//! from a truncated `ls` rather than from the directory.
//!
//! A badge submission is a **self-certification**. Nobody audits it, which is
//! precisely why the claims need something other than good intentions holding
//! them up. These tests check the mechanically checkable subset — the criteria
//! whose evidence is a file, a dependency, or a workflow line. The rest
//! (`know_secure_design`, `report_responses`) are judgements or history and are
//! deliberately not faked into assertions here.
//!
//! Scope note: this does not verify sipnab *deserves* the badge. It verifies
//! the sheet does not claim things that stopped being true.

use std::path::{Path, PathBuf};

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = repo().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn sheet() -> String {
    read("docs/design/openssf-badge-answers.md")
}

/// `license_location`, `floss_license`, `floss_license_osi` — the sheet says
/// both licence files sit at the repo root under a dual MIT/Apache-2.0 grant.
#[test]
fn licence_claims_hold() {
    for f in ["LICENSE-MIT", "LICENSE-APACHE"] {
        assert!(
            repo().join(f).is_file(),
            "the answer sheet cites {f} at the repo root for `license_location`"
        );
    }
    assert!(
        read("Cargo.toml").contains("MIT OR Apache-2.0"),
        "the sheet answers `floss_license` with a dual MIT/Apache-2.0 grant"
    );
}

/// `interact`, `contribution`, `report_process`, `vulnerability_report_process`
/// — every community-health file the sheet points a reader at must exist.
#[test]
fn cited_community_files_exist() {
    for f in [
        "SUPPORT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
        "MAINTAINERS.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/CODEOWNERS",
        ".github/dependabot.yml",
    ] {
        assert!(
            repo().join(f).is_file(),
            "the answer sheet cites {f}; a criterion answered 'Met' by a file \
             that no longer exists is a false certification"
        );
    }
}

/// `vulnerability_report_private` — a private route must actually be offered,
/// and the pages describing it must not disagree about which one it is.
///
/// They did. `ISSUE_TEMPLATE/config.yml` sends reporters to a GitHub advisory
/// while `SECURITY.md` asks for email, so which inbox a report lands in depended
/// on which page the reporter happened to read. Both are private, so nothing
/// leaked — but a channel nobody is watching is not a reporting channel, and the
/// divergence is invisible until someone tries to use it.
///
/// The criterion is satisfied by *either*, so this does not pick one. It
/// requires that a private route exists, and that `SUPPORT.md` does not assert a
/// different canonical channel than `SECURITY.md` — which it may not do at all,
/// since it defers rather than restating.
#[test]
fn private_vulnerability_reporting_is_offered_and_described_consistently() {
    let cfg = read(".github/ISSUE_TEMPLATE/config.yml");
    let security = read("SECURITY.md");

    assert!(
        cfg.contains("security/advisories/new"),
        "the issue chooser must keep routing security reports away from public \
         issues"
    );

    let has_private_route = security.contains("advisories/new")
        || security.contains("security@")
        || security.to_lowercase().contains("email");
    assert!(
        has_private_route,
        "`vulnerability_report_private` requires SECURITY.md to name some \
         private route; it names none"
    );

    // SUPPORT.md must defer rather than restate. A second copy of "the" channel
    // is a second thing to keep in agreement, and it already fell out of sync.
    let support = read("SUPPORT.md");
    assert!(
        support.contains("SECURITY.md"),
        "SUPPORT.md must point at SECURITY.md for the reporting channel"
    );
    if support.contains("security@") {
        assert!(
            security.contains("security@"),
            "SUPPORT.md names an email address that SECURITY.md does not — the \
             two pages disagree about where reports go"
        );
    }
}

/// `test_policy` — a MUST criterion, answered by quoting a specific line of
/// `CONTRIBUTING.md`. Quoting a line is only evidence while the line is there.
#[test]
fn the_quoted_test_policy_line_is_still_in_contributing() {
    const QUOTED: &str = "Add or update tests for new functionality";
    assert!(
        read("CONTRIBUTING.md").contains(QUOTED),
        "the sheet answers `test_policy` by quoting CONTRIBUTING.md: {QUOTED:?}"
    );
    assert!(
        sheet().contains(QUOTED),
        "the sheet must quote the policy verbatim, not paraphrase it — a \
         paraphrase cannot be checked against the source"
    );
}

/// `warnings`, `warnings_fixed`, `static_analysis`, `vulnerabilities_fixed_60_days`
/// — each is answered by a CI job. The jobs must exist and still be strict.
#[test]
fn cited_ci_gates_exist_and_are_strict() {
    let ci = read(".github/workflows/ci.yml");
    assert!(
        ci.contains("cargo clippy --all-features --all-targets -- -D warnings"),
        "`warnings`/`warnings_fixed` are answered Met because clippy is \
         deny-on-warning; a downgrade makes both answers false"
    );
    assert!(
        ci.contains("cargo-deny") || ci.contains("cargo deny"),
        "`vulnerabilities_fixed_60_days` cites cargo-deny in CI"
    );
    assert!(
        repo().join(".github/workflows/codeql.yml").is_file(),
        "`static_analysis` cites CodeQL"
    );
    assert!(
        repo().join(".github/workflows/scorecard.yml").is_file(),
        "the sheet distinguishes the badge from the Scorecard workflow, which \
         it says already runs"
    );
}

/// `crypto_floss`, `crypto_call`, `crypto_published` — the sheet answers these
/// by naming the crates sipnab leans on rather than reimplementing. Each named
/// crate must actually be a dependency, or the answer is describing a different
/// program.
#[test]
fn named_crypto_crates_are_real_dependencies() {
    let manifest = read("Cargo.toml");
    for krate in ["rustls", "ring", "aes", "hmac", "sha2"] {
        assert!(
            manifest.contains(&format!("\n{krate} = ")),
            "the sheet answers the crypto criteria by naming `{krate}`; it must \
             be a real dependency, since the claim is precisely that sipnab does \
             not roll its own"
        );
        assert!(
            sheet().contains(krate),
            "`{krate}` dropped out of the answer sheet's crypto evidence"
        );
    }
}

/// The dynamic-analysis answer states a fuzz-target count and lists every
/// target by name.
///
/// This is the assertion that would have caught the original error. The sheet
/// first claimed 10 targets against a real 15, because the number was read off
/// a truncated listing — the five it missed (`srtp_keys`, `stir_shaken`,
/// `tcp_reassembly`, `tls_records`, `websocket_frame`) are all attacker-facing
/// parsers, so the undercount understated exactly the evidence the criterion
/// wants. Both the count and the names are checked, because a count alone goes
/// stale silently the moment a target is renamed.
#[test]
fn fuzz_target_evidence_matches_the_fuzz_directory() {
    let dir = repo().join("fuzz/fuzz_targets");
    let mut targets: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rs"))
        .filter_map(|p: PathBuf| {
            p.file_stem()
                .and_then(|s| s.to_str())
                .map(std::string::ToString::to_string)
        })
        .collect();
    targets.sort();

    let text = sheet();
    assert!(
        text.contains(&format!("{} fuzz targets", targets.len())),
        "the answer sheet must state the real fuzz-target count ({}); it \
         previously said 10 against a real 15",
        targets.len()
    );
    for t in &targets {
        assert!(
            text.contains(&format!("`{t}`")),
            "fuzz target `{t}` exists but the answer sheet does not name it — \
             the sheet lists them individually so a rename cannot hide behind \
             an unchanged total"
        );
    }
    assert!(
        repo().join("tests/smoke_fuzz_test.rs").is_file(),
        "the sheet cites a no-nightly smoke tier at tests/smoke_fuzz_test.rs"
    );
}

/// The sheet's own framing must survive editing: it is a prepared answer sheet,
/// not a submission, and the badge is not the Scorecard.
///
/// Both distinctions are load-bearing. Someone skimming a page headed "OpenSSF"
/// while a green Scorecard badge sits in CI could easily conclude the badge is
/// already earned; the page says otherwise on purpose.
#[test]
fn the_sheet_does_not_claim_to_be_a_submission() {
    let text = sheet();
    assert!(
        text.contains("not the\nsubmission") || text.contains("not the submission"),
        "the sheet must say it is the prepared answers, not a submission"
    );
    assert!(
        text.contains("PROJECT_ID"),
        "the README badge markup cannot be written before registration assigns \
         a project ID; the sheet keeps it as a placeholder deliberately"
    );
    assert!(
        !read("README.md").contains("bestpractices.dev/projects/"),
        "no badge may appear in README.md until the project is registered — a \
         badge URL with a guessed ID renders as somebody else's project"
    );
}
