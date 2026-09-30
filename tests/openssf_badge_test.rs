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
/// both license files sit at the repo root under a dual MIT/Apache-2.0 grant.
#[test]
fn license_claims_hold() {
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
    // `--workspace` is required as well as `-D warnings`. Without it the
    // switches cover only the root package, and crates/sipnab-plugin-example
    // escaped the gate entirely while CI stayed green -- so the badge answer
    // was true of one crate and asserted for the repository.
    assert!(
        ci.contains("cargo clippy --workspace --all-features --all-targets -- -D warnings"),
        "`warnings`/`warnings_fixed` are answered Met because clippy is \
         deny-on-warning ACROSS THE WORKSPACE; dropping either the deny or the \
         workspace scope makes both answers false"
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

/// The sheet's own framing must survive editing: it distinguishes the prepared
/// answers from the submission form, and the badge from the Scorecard.
///
/// Both distinctions are load-bearing. Someone skimming a page headed "OpenSSF"
/// while a green Scorecard badge sits in CI could easily conclude the badge is
/// already earned; the page says otherwise on purpose.
///
/// The project registered as 13931 and the badge reads "passing" — checked
/// live against bestpractices.dev on 2026-08-06. That project ID must now
/// appear consistently everywhere the badge is wired: the sheet's own status
/// line, the README badge markup, and the CSP-safe homepage link (an
/// externally-hosted badge *image* would be blocked by the site's
/// `img-src 'self'` policy, which is why the homepage carries a text link
/// instead of the badge SVG). A placeholder or a mismatched ID in any one of
/// the three is exactly the kind of staleness this file exists to catch — it
/// is what let the homepage link go missing unnoticed until a maintainer
/// asked where it was.
#[test]
fn the_badge_is_registered_and_wired_consistently() {
    const PROJECT_URL: &str = "bestpractices.dev/projects/13931";

    let text = sheet();
    assert!(
        text.contains("not the\nsubmission") || text.contains("not the submission"),
        "the sheet must distinguish itself from the submission form"
    );
    assert!(
        !text.contains("PROJECT_ID"),
        "the project is registered as 13931; a lingering PROJECT_ID placeholder \
         means the sheet was never updated after registration"
    );
    assert!(
        text.contains(PROJECT_URL),
        "the sheet must cite the real registered project (13931), not a \
         placeholder or a different one"
    );

    let readme = read("README.md");
    assert!(
        readme.contains(&format!("{PROJECT_URL}/badge")) && readme.contains(PROJECT_URL),
        "the badge is registered and passing, so README.md must carry the real \
         badge markup for project 13931 — a missing or mismatched badge here is \
         what the maintainer could not find"
    );

    let homepage = read("website/templates/index.html");
    assert!(
        homepage.contains(PROJECT_URL),
        "the sipnab.com home page must link the same registered project — this \
         is the exact gap that went unnoticed: the badge existed in the answer \
         sheet and README but never reached the site a visitor actually looks at"
    );
}

/// The same project also holds the OpenSSF Baseline badge: level 1 achieved
/// 2026-09-30 (bestpractices.dev project JSON, `achieved_baseline_1_at`). The
/// README carries the badge image; the home page carries a text link for the
/// same `img-src 'self'` reason as the Best Practices badge above.
#[test]
fn the_baseline_badge_is_wired_in_readme_and_homepage() {
    const PROJECT_URL: &str = "https://www.bestpractices.dev/projects/13931";

    let readme = read("README.md");
    let markup = format!("[![OpenSSF Baseline]({PROJECT_URL}/baseline)]({PROJECT_URL})");
    assert!(
        readme.contains(&markup),
        "README.md must carry the Baseline badge exactly as bestpractices.dev \
         issues it: {markup}"
    );

    let homepage = read("website/templates/index.html");
    assert!(
        homepage.contains("OpenSSF Baseline — Level 1"),
        "the home page must name the Baseline level the project holds, in a \
         text link beside the Best Practices one"
    );
    assert!(
        !homepage.contains(&format!("{PROJECT_URL}/baseline")),
        "the home page must not load the badge image: the site CSP is \
         `img-src 'self'`, so an external badge renders as a broken image"
    );
}

/// `know_secure_design` and OpenSSF Baseline SA-03.01 (security assessment).
///
/// The sheet once answered `know_secure_design` by pointing at "an explicitly
/// documented threat model in SECURITY.md". SECURITY.md holds a reporting
/// scope list, which says what a reporter may send, not what an attacker is
/// likely to try or what stops them. A reviewer caught it. The assessment now
/// lives in `docs/threat-model.md`, and this test holds it to three things a
/// reader relies on:
///
/// 1. It names every trust boundary the reviewer asked for, as a heading, so a
///    boundary cannot quietly drop out of the document.
/// 2. Every repository path it cites exists, and every `path.rs::name`
///    citation names something that is really in that file. A mitigation
///    cited to a file that moved is a mitigation nobody can check.
/// 3. The sheet and SECURITY.md both point at it rather than at a document
///    that does not contain one.
#[test]
fn the_threat_model_exists_covers_each_boundary_and_cites_real_code() {
    const DOC: &str = "docs/threat-model.md";
    assert!(
        repo().join(DOC).is_file(),
        "{DOC} is the security assessment (Baseline SA-03.01) that \
         `know_secure_design` cites; it does not exist"
    );
    let doc = read(DOC);

    let headings: Vec<String> = doc
        .lines()
        .filter(|l| l.starts_with('#'))
        .map(str::to_lowercase)
        .collect();
    // (what the reviewer asked for, a phrase its heading must contain)
    let required = [
        ("assets", "assets"),
        ("packet capture input", "packet capture"),
        ("capture and archive files", "archive"),
        ("HEP senders", "hep"),
        ("REST API clients", "rest api"),
        ("MCP clients", "mcp"),
        ("exec hooks", "exec hook"),
        ("WASM plugins", "plugin"),
        ("TLS key material", "key material"),
        ("configuration files", "configuration"),
        ("residual risks", "residual risk"),
    ];
    for (what, needle) in required {
        assert!(
            headings.iter().any(|h| h.contains(needle)),
            "{DOC} has no heading covering {what} (looked for {needle:?} in a \
             heading); the assessment must name every trust boundary"
        );
    }

    // Every cited repository path must exist. Two citation forms are
    // recognized: a backtick span that starts with a tracked top-level
    // directory or names a root file, and a relative Markdown link.
    const ROOTS: [&str; 9] = [
        "src/", "docs/", "tests/", "crates/", "fuzz/", "scripts/", ".github/", "bpf/", "website/",
    ];
    let mut cited = 0usize;
    let mut problems = Vec::new();
    for span in doc.split('`').skip(1).step_by(2) {
        let (path, item) = match span.split_once("::") {
            Some((p, i)) => (p, Some(i)),
            None => (span, None),
        };
        let looks_like_path = !path.contains(' ')
            && (ROOTS.iter().any(|r| path.starts_with(r))
                || matches!(path, "SECURITY.md" | "Cargo.toml" | "deny.toml"));
        if !looks_like_path {
            continue;
        }
        cited += 1;
        let p = repo().join(path);
        if !p.exists() {
            problems.push(format!("`{span}`: {path} does not exist"));
            continue;
        }
        if let Some(item) = item {
            let body = std::fs::read_to_string(&p).unwrap_or_default();
            let defined = ["fn", "const", "struct", "enum"]
                .iter()
                .any(|kw| body.contains(&format!("{kw} {item}")));
            if !defined {
                problems.push(format!(
                    "`{span}`: {path} defines no fn/const/struct/enum named {item}"
                ));
            }
        }
    }
    // Links: a relative one resolves from docs/, and an absolute one into this
    // repository's main branch names a path that must exist here.
    const BLOB: &str = "https://github.com/NormB/sipnab/blob/main/";
    for chunk in doc.split("](").skip(1) {
        let target = chunk.split(')').next().unwrap_or("");
        let target = target.split('#').next().unwrap_or("");
        let resolved = if let Some(path) = target.strip_prefix(BLOB) {
            repo().join(path)
        } else if target.is_empty() || target.contains("://") || target.starts_with("mailto:") {
            continue;
        } else {
            repo().join("docs").join(target)
        };
        cited += 1;
        if !resolved.exists() {
            problems.push(format!("link ({target}) names nothing in this repository"));
        }
    }
    assert!(
        problems.is_empty(),
        "{DOC} cites paths or items that do not exist:\n  {}",
        problems.join("\n  ")
    );
    assert!(
        cited >= 25,
        "{DOC} cites only {cited} repository paths; every mitigation must cite \
         the code that implements it, so a count this low means citations were \
         dropped or the extractor stopped matching"
    );

    let row = sheet()
        .lines()
        .find(|l| l.starts_with("| `know_secure_design`"))
        .expect("the sheet has a `know_secure_design` row")
        .to_string();
    assert!(
        row.contains(DOC),
        "`know_secure_design` must cite {DOC}, not a file that holds no threat \
         model: {row}"
    );
    assert!(
        !row.contains("threat model in [`SECURITY.md`]"),
        "the row still claims SECURITY.md holds the threat model: {row}"
    );
    assert!(
        read("SECURITY.md").contains(DOC),
        "SECURITY.md must point a reader at {DOC}"
    );
}
