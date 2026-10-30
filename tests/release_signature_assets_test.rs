// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every release carries a signature and a provenance file AS ASSETS.
//!
//! OpenSSF Scorecard's Signed-Releases check scored 0 on every release up to
//! v0.5.231, although each one was attested with
//! `actions/attest-build-provenance`. Scorecard does not ask GitHub's
//! attestation API. It reads the asset names of the last five releases and
//! looks for a signature suffix (`probes/releasesAreSigned/impl.go`) and a
//! provenance suffix (`probes/releasesHaveProvenance/impl.go`). An attestation
//! that lives only in the API is invisible to it, and to anyone who mirrors
//! the release page.
//!
//! So the `release` job must:
//!
//! - sign `SHA256SUMS.txt` keylessly with `cosign sign-blob`, from the job's
//!   own OIDC identity, into a `.sigstore.json` bundle;
//! - copy the bundle that `attest-build-provenance` already writes to an
//!   `.intoto.jsonl` file;
//! - verify both files with the commands the docs give downloaders, before the
//!   release exists, so a broken chain fails the release instead of a user;
//! - name both files in the `files:` list of the step that publishes.
//!
//! There is no YAML parser among the dev-dependencies, so this reads the
//! workflow as text, split into jobs and steps by indentation. The checker is a
//! pure function of that text. The fixtures at the bottom drive it with each
//! fault it exists to catch, so a checker that stopped looking would fail
//! there as well as here.

type TestError = Box<dyn std::error::Error>;

/// Scorecard's signature suffixes, copied from
/// `probes/releasesAreSigned/impl.go` (ossf/scorecard at 6b98ea0a6a, read
/// 2026-10-28).
const SCORECARD_SIGNATURE_SUFFIXES: &[&str] = &[
    ".asc",
    ".minisig",
    ".sig",
    ".sign",
    ".sigstore",
    ".sigstore.json",
];

/// Scorecard's provenance suffixes, from
/// `probes/releasesHaveProvenance/impl.go` at the same commit.
const SCORECARD_PROVENANCE_SUFFIXES: &[&str] = &[".intoto.jsonl"];

/// The OIDC issuer of every GitHub Actions token. A signature from any other
/// issuer did not come from a workflow run.
const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The file the release signs. One signature over the checksum list covers
/// every artifact the list names.
const SIGNED_BLOB: &str = "artifacts/SHA256SUMS.txt";

fn read(rel: &str) -> Result<String, TestError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?)
}

/// Leading-space count of a line.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The body of the job that runs `softprops/action-gh-release`, with comment
/// lines removed. A commented-out step must not count as present.
fn publishing_job(workflow: &str) -> Option<String> {
    let lines: Vec<&str> = workflow
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    let jobs_at = lines.iter().position(|l| l.trim_end() == "jobs:")?;
    let mut jobs: Vec<Vec<&str>> = Vec::new();
    for line in &lines[jobs_at + 1..] {
        if indent(line) == 2 && line.trim_end().ends_with(':') {
            jobs.push(Vec::new());
        }
        if let Some(job) = jobs.last_mut() {
            job.push(line);
        }
    }
    jobs.into_iter()
        .find(|job| {
            job.iter()
                .any(|l| l.contains("softprops/action-gh-release@"))
        })
        .map(|job| job.join("\n"))
}

/// The job's steps, split at the indentation of its first `- ` item.
fn job_steps(job: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    let Some(start) = lines.iter().position(|l| l.trim_end().ends_with("steps:")) else {
        return Vec::new();
    };
    let Some(step_indent) = lines[start + 1..]
        .iter()
        .find(|l| l.trim_start().starts_with("- "))
        .map(|l| indent(l))
    else {
        return Vec::new();
    };
    let mut steps: Vec<String> = Vec::new();
    for line in &lines[start + 1..] {
        if indent(line) == step_indent && line.trim_start().starts_with("- ") {
            steps.push(String::new());
        }
        if let Some(step) = steps.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    steps
}

/// The lines of a `key: |` block scalar inside a step.
fn block_scalar(step: &str, key: &str) -> Vec<String> {
    let lines: Vec<&str> = step.lines().collect();
    let head = format!("{key}: |");
    let Some(at) = lines.iter().position(|l| l.trim() == head) else {
        return Vec::new();
    };
    let key_indent = indent(lines[at]);
    lines[at + 1..]
        .iter()
        .take_while(|l| l.trim().is_empty() || indent(l) > key_indent)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Shell commands in a step, with `\` continuations joined.
fn commands(step: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in step.lines() {
        let t = line.trim();
        if let Some(head) = t.strip_suffix('\\') {
            cur.push_str(head);
            cur.push(' ');
        } else {
            cur.push_str(t);
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

/// Whitespace tokens with surrounding quotes removed.
fn tokens(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'').to_string())
        .collect()
}

/// The value of `--flag v` or `--flag=v`.
fn flag(tokens: &[String], name: &str) -> Option<String> {
    let eq = format!("{name}=");
    tokens.iter().enumerate().find_map(|(i, t)| {
        if t == name {
            tokens.get(i + 1).cloned()
        } else {
            t.strip_prefix(&eq).map(str::to_string)
        }
    })
}

/// A `*`-only glob, where `*` matches within one path component, the way
/// `action-gh-release` expands its `files:` patterns.
fn glob_matches(pattern: &str, path: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == path,
        Some((head, rest)) => {
            let Some(tail) = path.strip_prefix(head) else {
                return false;
            };
            (0..=tail.len())
                .take_while(|&i| !tail[..i].contains('/'))
                .filter(|&i| tail.is_char_boundary(i))
                .any(|i| glob_matches(rest, &tail[i..]))
        }
    }
}

/// The first step at or after `from` holding a command that starts with
/// `prefix`, and that command's tokens.
fn find_command(steps: &[String], from: usize, prefix: &str) -> Option<(usize, Vec<String>)> {
    steps.iter().enumerate().skip(from).find_map(|(i, step)| {
        commands(step)
            .into_iter()
            .find(|c| c.starts_with(prefix))
            .map(|c| (i, tokens(&c)))
    })
}

/// Every reason the publishing job in `workflow` would publish a release that
/// Scorecard cannot see as signed and attested. Empty means none.
fn signing_gaps(workflow: &str) -> Vec<String> {
    let mut gaps: Vec<String> = Vec::new();
    let Some(job) = publishing_job(workflow) else {
        return vec!["no job runs softprops/action-gh-release".to_string()];
    };
    if !job.lines().any(|l| l.trim() == "id-token: write") {
        gaps.push("the publishing job does not grant `id-token: write`".to_string());
    }
    let steps = job_steps(&job);
    let Some(publish) = steps
        .iter()
        .position(|s| s.contains("softprops/action-gh-release@"))
    else {
        return vec!["the publishing job has no publish step".to_string()];
    };
    let uploads = block_scalar(&steps[publish], "files");
    let uploaded = |path: &str| uploads.iter().any(|g| glob_matches(g, path));

    // (a) The signature over the checksum list.
    match find_command(&steps[..publish], 0, "cosign sign-blob") {
        None => gaps.push("no step before the publish step runs `cosign sign-blob`".to_string()),
        Some((at, sign)) => {
            let bundle = flag(&sign, "--bundle").unwrap_or_default();
            if sign.last().map(String::as_str) != Some(SIGNED_BLOB) {
                gaps.push(format!("`cosign sign-blob` does not sign {SIGNED_BLOB}"));
            }
            if !bundle.ends_with(".sigstore.json") {
                gaps.push(format!(
                    "the signature bundle `{bundle}` is not named *.sigstore.json"
                ));
            }
            if !SCORECARD_SIGNATURE_SUFFIXES
                .iter()
                .any(|s| bundle.ends_with(s))
            {
                gaps.push(format!(
                    "Scorecard does not count `{bundle}` as a signature"
                ));
            }
            if !uploaded(&bundle) {
                gaps.push(format!(
                    "no `files:` pattern of the publish step uploads `{bundle}`: {uploads:?}"
                ));
            }
            match find_command(&steps[..publish], at, "cosign verify-blob") {
                None => gaps.push(
                    "no step between signing and publishing runs `cosign verify-blob`".to_string(),
                ),
                Some((_, verify)) => {
                    if flag(&verify, "--bundle").as_deref() != Some(bundle.as_str())
                        || verify.last().map(String::as_str) != Some(SIGNED_BLOB)
                    {
                        gaps.push(format!(
                            "`cosign verify-blob` does not check `{bundle}` against {SIGNED_BLOB}"
                        ));
                    }
                    if flag(&verify, "--certificate-oidc-issuer").as_deref() != Some(ACTIONS_ISSUER)
                    {
                        gaps.push(format!(
                            "`cosign verify-blob` does not pin the issuer to {ACTIONS_ISSUER}"
                        ));
                    }
                    if flag(&verify, "--certificate-identity").is_none()
                        && flag(&verify, "--certificate-identity-regexp").is_none()
                    {
                        gaps.push(
                            "`cosign verify-blob` does not pin the signing identity".to_string(),
                        );
                    }
                }
            }
        }
    }

    // (b) The provenance file, from the attestation the job already makes.
    let attest = steps[..publish]
        .iter()
        .position(|s| s.contains("actions/attest-build-provenance@"));
    let attest_id = attest.and_then(|i| {
        steps[i].lines().find_map(|l| {
            l.trim()
                .trim_start_matches("- ")
                .strip_prefix("id:")
                .map(|v| v.trim().to_string())
        })
    });
    match (attest, attest_id) {
        (None, _) => gaps.push("no step runs actions/attest-build-provenance".to_string()),
        (Some(_), None) => gaps.push(
            "the attest-build-provenance step has no `id:`, so its bundle-path cannot be read"
                .to_string(),
        ),
        (Some(at), Some(id)) => {
            let output = format!("steps.{id}.outputs.bundle-path");
            let copy = steps[..publish]
                .iter()
                .enumerate()
                .skip(at + 1)
                .find(|(_, s)| s.contains(&output));
            let target = copy.and_then(|(_, s)| {
                commands(s)
                    .iter()
                    .filter(|c| c.starts_with("cp "))
                    .flat_map(|c| tokens(c))
                    .find(|t| t.ends_with(".intoto.jsonl") || t.ends_with(".intoto.json"))
            });
            match (copy, target) {
                (None, _) => gaps.push(format!("no step after the attestation reads `{output}`")),
                (Some(_), None) => gaps.push(format!(
                    "the step reading `{output}` does not `cp` it to an *.intoto.jsonl file"
                )),
                (Some((copied_at, _)), Some(path)) => {
                    if !SCORECARD_PROVENANCE_SUFFIXES
                        .iter()
                        .any(|s| path.ends_with(s))
                    {
                        gaps.push(format!("Scorecard does not count `{path}` as provenance"));
                    }
                    if !uploaded(&path) {
                        gaps.push(format!(
                            "no `files:` pattern of the publish step uploads `{path}`: {uploads:?}"
                        ));
                    }
                    // `contains`, not `starts_with`: the real step captures the
                    // command's output with `out=$(gh attestation verify ...)`.
                    let verified = steps[copied_at..publish]
                        .iter()
                        .flat_map(|s| commands(s))
                        .filter(|c| c.contains("gh attestation verify"))
                        .any(|c| flag(&tokens(&c), "--bundle").as_deref() == Some(path.as_str()));
                    if !verified {
                        gaps.push(format!(
                            "no step between the copy and the publish step runs \
                             `gh attestation verify --bundle {path}`"
                        ));
                    }
                }
            }
        }
    }
    gaps
}

#[test]
fn the_release_job_publishes_a_verified_signature_and_provenance_asset() -> Result<(), TestError> {
    let gaps = signing_gaps(&read(".github/workflows/release.yml")?);
    assert!(
        gaps.is_empty(),
        "release.yml would publish a release that Scorecard's Signed-Releases \
         check scores 0:\n  {}",
        gaps.join("\n  ")
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixtures: the checker against each fault it exists to catch.
// ---------------------------------------------------------------------------

/// A minimal publishing job that satisfies every rule.
const GOOD: &str = r#"name: Release
jobs:
  build:
    steps:
      - run: make
  release:
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - name: Attest build provenance
        id: provenance
        uses: actions/attest-build-provenance@0000000000000000000000000000000000000000 # v4
        with:
          subject-path: |
            artifacts/SHA256SUMS.txt
      - name: Keep the provenance bundle as an asset
        env:
          BUNDLE: ${{ steps.provenance.outputs.bundle-path }}
        run: |
          version="${GITHUB_REF_NAME#v}"
          cp "$BUNDLE" "artifacts/sipnab-${version}.intoto.jsonl"
      - name: Sign the checksum list
        run: |
          cosign sign-blob --yes \
            --bundle artifacts/SHA256SUMS.txt.sigstore.json \
            artifacts/SHA256SUMS.txt
      - name: Verify
        run: |
          version="${GITHUB_REF_NAME#v}"
          cosign verify-blob \
            --bundle artifacts/SHA256SUMS.txt.sigstore.json \
            --certificate-identity "https://github.com/x" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            artifacts/SHA256SUMS.txt
          gh attestation verify artifacts/SHA256SUMS.txt \
            --bundle "artifacts/sipnab-${version}.intoto.jsonl" --repo x/y
      - name: Create GitHub Release
        uses: softprops/action-gh-release@0000000000000000000000000000000000000000 # v3
        with:
          files: |
            artifacts/SHA256SUMS.txt
            artifacts/*.sigstore.json
            artifacts/*.intoto.jsonl
"#;

/// `GOOD` with one exact substring replaced. Panics loudly if the substring is
/// absent, so a fixture whose fault never landed cannot pass as caught.
fn planted(from: &str, to: &str) -> String {
    assert_eq!(
        GOOD.matches(from).count(),
        1,
        "fixture fault `{from}` must occur exactly once in GOOD"
    );
    GOOD.replacen(from, to, 1)
}

fn assert_caught(fault: &str, workflow: &str, expect: &str) {
    let gaps = signing_gaps(workflow);
    assert!(
        gaps.iter().any(|g| g.contains(expect)),
        "fault `{fault}` was not reported as `{expect}`; got {gaps:?}"
    );
}

#[test]
fn the_good_fixture_has_no_gaps() {
    assert_eq!(signing_gaps(GOOD), Vec::<String>::new());
}

#[test]
fn a_release_that_does_not_upload_the_signature_is_caught() {
    assert_caught(
        "signature upload removed",
        &planted("            artifacts/*.sigstore.json\n", ""),
        "uploads `artifacts/SHA256SUMS.txt.sigstore.json`",
    );
}

#[test]
fn a_release_that_does_not_upload_the_provenance_is_caught() {
    assert_caught(
        "provenance upload removed",
        &planted("            artifacts/*.intoto.jsonl\n", ""),
        "uploads `artifacts/sipnab-${version}.intoto.jsonl`",
    );
}

#[test]
fn a_signature_scorecard_does_not_recognize_is_caught() {
    let wrong = GOOD.replace("SHA256SUMS.txt.sigstore.json", "SHA256SUMS.txt.bundle.json");
    assert_ne!(wrong, GOOD);
    assert_caught("signature misnamed", &wrong, "Scorecard does not count");
}

#[test]
fn a_provenance_file_scorecard_does_not_recognize_is_caught() {
    let wrong = GOOD.replace(".intoto.jsonl", ".intoto.json");
    assert_ne!(wrong, GOOD);
    assert_caught("provenance misnamed", &wrong, "Scorecard does not count");
}

#[test]
fn an_upload_pattern_that_misses_the_signature_is_caught() {
    assert_caught(
        "upload glob names another file",
        &planted("artifacts/*.sigstore.json\n", "artifacts/*.sig\n"),
        "uploads `artifacts/SHA256SUMS.txt.sigstore.json`",
    );
}

#[test]
fn a_release_without_signing_is_caught() {
    assert_caught(
        "sign step removed",
        &planted(
            "          cosign sign-blob --yes \\\n",
            "          true \\\n",
        ),
        "runs `cosign sign-blob`",
    );
}

#[test]
fn a_signature_that_is_never_verified_is_caught() {
    assert_caught(
        "verify-blob removed",
        &planted("          cosign verify-blob \\\n", "          true \\\n"),
        "runs `cosign verify-blob`",
    );
}

#[test]
fn a_verification_that_accepts_any_issuer_is_caught() {
    assert_caught(
        "issuer dropped",
        &planted(
            "            --certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n",
            "",
        ),
        "does not pin the issuer",
    );
}

#[test]
fn a_verification_that_accepts_any_identity_is_caught() {
    assert_caught(
        "identity dropped",
        &planted(
            "            --certificate-identity \"https://github.com/x\" \\\n",
            "",
        ),
        "does not pin the signing identity",
    );
}

#[test]
fn a_provenance_file_that_is_never_verified_is_caught() {
    assert_caught(
        "gh attestation verify removed",
        &planted(
            "          gh attestation verify artifacts/SHA256SUMS.txt \\\n",
            "          true \\\n",
        ),
        "gh attestation verify --bundle",
    );
}

#[test]
fn a_provenance_step_without_an_id_is_caught() {
    assert_caught(
        "attest id removed",
        &planted("        id: provenance\n", ""),
        "has no `id:`",
    );
}

#[test]
fn a_job_without_an_oidc_grant_is_caught() {
    assert_caught(
        "id-token removed",
        &planted("      id-token: write\n", ""),
        "id-token: write",
    );
}

#[test]
fn a_commented_out_signing_step_is_caught() {
    assert_caught(
        "sign step commented out",
        &planted(
            "          cosign sign-blob --yes \\\n",
            "          # cosign sign-blob --yes \\\n",
        ),
        "runs `cosign sign-blob`",
    );
}

#[test]
fn the_glob_matches_within_one_path_component() {
    assert!(glob_matches(
        "artifacts/*.sigstore.json",
        "artifacts/SHA256SUMS.txt.sigstore.json"
    ));
    assert!(glob_matches(
        "artifacts/*.intoto.jsonl",
        "artifacts/sipnab-${version}.intoto.jsonl"
    ));
    assert!(!glob_matches(
        "artifacts/*.sigstore.json",
        "artifacts/sub/x.sigstore.json"
    ));
    assert!(!glob_matches(
        "artifacts/*.sig",
        "artifacts/x.sigstore.json"
    ));
    assert!(glob_matches(
        "artifacts/SHA256SUMS.txt",
        "artifacts/SHA256SUMS.txt"
    ));
}
