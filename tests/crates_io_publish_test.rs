// SPDX-License-Identifier: MIT OR Apache-2.0
//! crates.io gets a release from one job, after the GitHub release exists,
//! with a token that lives for that job alone.
//!
//! Until 0.5.180 every crates.io upload was typed by hand from a clean
//! worktree of the tag, after the Release workflow went green. The job that
//! replaces it has to keep what made the hand process safe:
//!
//! - **Order.** A tag push starts every tag workflow at once. A crates.io
//!   version can never be replaced, so an upload that ran beside a build that
//!   then failed would publish a version the GitHub release never gets. The
//!   job `needs: release`.
//! - **Which workflow.** crates.io trusted publishing matches the TOP-LEVEL
//!   workflow's file name (the `workflow_ref` claim) and refuses a token from
//!   a `workflow_run` or `pull_request_target` run outright (crates.io,
//!   `src/controllers/trustpub/tokens/exchange/mod.rs`, read 2026-09-18). So
//!   the job lives in `release.yml` itself, and the trusted-publisher entry on
//!   crates.io names `release.yml`.
//! - **No standing credential.** The token comes from
//!   `rust-lang/crates-io-auth-action`, which exchanges the job's OIDC
//!   identity and revokes the token when the job ends. A `secrets.` token
//!   would sit in the repository for anyone who can edit a workflow.
//! - **What was entered on crates.io.** That config cannot be read back
//!   without the owner's login, so `docs/internals/build-ci-release.md`
//!   records it, and this file holds the record to the workflow.

use std::path::Path;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn workflows() -> Vec<(String, String)> {
    let dir = repo().join(".github/workflows");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            let name = p
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            let body =
                std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            (name, body)
        })
        .collect();
    out.sort();
    assert!(out.len() >= 10, "found only {} workflows", out.len());
    out
}

/// A workflow's jobs as `(id, lines)`, comments dropped: the `jobs:` mapping
/// split at its two-space keys.
fn jobs(body: &str) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    let mut in_jobs = false;
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            in_jobs = trimmed.starts_with("jobs:");
        } else if in_jobs && indent == 2 && trimmed.ends_with(':') {
            out.push((trimmed.trim_end_matches(':').to_string(), Vec::new()));
        } else if in_jobs && let Some((_, lines)) = out.last_mut() {
            lines.push(line.to_string());
        }
    }
    out
}

/// The value of a job-level `key:` (four-space indent), unquoted when the
/// whole value is one quoted string.
fn job_key(lines: &[String], key: &str) -> Option<String> {
    lines.iter().find_map(|l| {
        let rest = l.strip_prefix("    ")?;
        if rest.starts_with(' ') {
            return None;
        }
        let value = rest.strip_prefix(key)?.strip_prefix(':')?.trim();
        let unquoted = ['\'', '"'].iter().find_map(|q| {
            value
                .strip_prefix(*q)?
                .strip_suffix(*q)
                .filter(|inner| !inner.contains(*q))
        });
        Some(unquoted.unwrap_or(value).to_string())
    })
}

/// The job's own `permissions:` block as `(scope, level)` pairs.
fn job_permissions(lines: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for l in lines {
        let indent = l.len() - l.trim_start().len();
        if indent == 4 {
            inside = l.trim() == "permissions:";
            continue;
        }
        if inside
            && indent == 6
            && let Some((k, v)) = l.trim().split_once(':')
        {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// Every job that uploads to crates.io, as `(workflow file, job id, lines)`.
fn publishing_jobs() -> Vec<(String, String, Vec<String>)> {
    let mut found = Vec::new();
    for (file, body) in workflows() {
        for (id, lines) in jobs(&body) {
            if lines.iter().any(|l| {
                l.contains("crates-io-auth-action")
                    || l.contains("publish-crates.py")
                    || l.contains("cargo publish")
            }) {
                found.push((file.clone(), id, lines));
            }
        }
    }
    found
}

fn the_publishing_job() -> (String, String, Vec<String>) {
    let mut found = publishing_jobs();
    assert_eq!(
        found
            .iter()
            .map(|(f, id, _)| format!("{f}:{id}"))
            .collect::<Vec<_>>(),
        ["release.yml:crates-io"],
        "exactly one job publishes to crates.io, and it is `crates-io` in \
         release.yml: crates.io accepts a token only from the workflow file \
         named in its trusted-publisher config"
    );
    found.remove(0)
}

#[test]
fn crates_io_gets_a_release_only_after_its_github_release_exists() {
    let (_, _, lines) = the_publishing_job();
    let needs = job_key(&lines, "needs").unwrap_or_default();
    assert!(
        needs
            .trim_matches(['[', ']'])
            .split(',')
            .any(|n| n.trim() == "release"),
        "the crates.io job needs `release` (it has `needs: {needs}`). A tag \
         push starts every tag workflow at once, and an upload that runs beside \
         a build that then fails publishes a version the GitHub release never \
         gets. crates.io cannot take it back."
    );
    let condition = job_key(&lines, "if").unwrap_or_default();
    for part in [
        "github.event_name == 'push'",
        "startsWith(github.ref, 'refs/tags/v')",
    ] {
        assert!(
            condition.contains(part),
            "the crates.io job's `if:` lacks `{part}` (it is `{condition}`). \
             release.yml also runs by workflow_dispatch to build without \
             releasing, and that run must not publish."
        );
    }
    assert_eq!(
        job_key(&lines, "environment").as_deref(),
        Some("crates-io"),
        "the crates.io job runs in the `crates-io` environment: its OIDC token \
         names that environment, and crates.io refuses a token whose \
         environment differs from its trusted-publisher config"
    );
}

#[test]
fn the_crates_io_token_lives_for_one_job() {
    let (_, _, lines) = the_publishing_job();
    let mut perms = job_permissions(&lines);
    perms.sort();
    assert_eq!(
        perms,
        [
            ("contents".to_string(), "read".to_string()),
            ("id-token".to_string(), "write".to_string()),
        ],
        "the crates.io job may read the tree and ask for an OIDC token, \
         nothing more"
    );
    let text = lines.join("\n");
    assert!(
        text.contains("CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}")
            && text.contains("id: auth")
            && text.contains("crates-io-auth-action@"),
        "the upload's token is the one crates-io-auth-action exchanged in this \
         job (step `id: auth`), which it revokes when the job ends"
    );
    assert!(
        text.contains("python3 scripts/publish-crates.py --tag \"${GITHUB_REF_NAME}\""),
        "the job uploads through scripts/publish-crates.py, which checks the \
         tag against Cargo.toml and asks crates.io about every crate before \
         uploading any"
    );
    for (file, body) in workflows() {
        for line in body.lines().filter(|l| !l.trim_start().starts_with('#')) {
            assert!(
                !(line.contains("secrets.") && line.contains("CARGO_REGISTRY_TOKEN")),
                "{file} hands cargo a token kept in repository secrets: {}",
                line.trim()
            );
        }
    }
}

#[test]
fn the_documented_trusted_publisher_matches_the_workflow() {
    let (file, _, lines) = the_publishing_job();
    let environment = job_key(&lines, "environment").unwrap_or_default();
    let doc = read("docs/internals/build-ci-release.md");
    for row in [
        "| Repository owner | `NormB` |".to_string(),
        "| Repository name | `sipnab` |".to_string(),
        format!("| Workflow filename | `{file}` |"),
        format!("| Environment | `{environment}` |"),
    ] {
        assert!(
            doc.lines().any(|l| l.trim() == row),
            "docs/internals/build-ci-release.md lacks the row `{row}`. It is \
             the record of what crates.io's trusted-publisher form holds for \
             sipnab and sipnab-bpf-types, and crates.io refuses a token that \
             does not match it."
        );
    }
}

/// POSITIVE CONTROL: the parsers read a job the way the checks above assume.
#[test]
fn the_job_reader_finds_keys_permissions_and_jobs() {
    let body = "on:\n  push:\njobs:\n  a:\n    needs: [build, release]\n    # if: nope\n    \
                if: github.event_name == 'push'\n    environment: crates-io\n    \
                permissions:\n      contents: read\n      id-token: write\n    steps:\n      \
                - run: echo\n  b:\n    runs-on: x\n";
    let parsed = jobs(body);
    assert_eq!(
        parsed.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    let a = &parsed[0].1;
    assert_eq!(job_key(a, "needs").as_deref(), Some("[build, release]"));
    assert_eq!(
        job_key(a, "if").as_deref(),
        Some("github.event_name == 'push'")
    );
    assert_eq!(job_key(a, "environment").as_deref(), Some("crates-io"));
    assert_eq!(
        job_permissions(a),
        [
            ("contents".to_string(), "read".to_string()),
            ("id-token".to_string(), "write".to_string()),
        ]
    );
}
