// SPDX-License-Identifier: MIT OR Apache-2.0

//! CI pulls no container image from Docker Hub.
//!
//! On 2026-10-09 two workflows on main failed on Docker Hub, not on the code:
//!
//! - Quality, job "Docs (prose, spelling, links)": the codespell step was
//!   `codespell-project/actions-codespell`, a Docker container action whose
//!   Dockerfile starts `FROM python:3.13-alpine`. Building it answered
//!   `429 Too Many Requests` from registry-1.docker.io, and earlier the same
//!   day `504 Gateway Timeout` from auth.docker.io/token on three attempts.
//! - Docker, job docker: `docker/setup-buildx-action` ran
//!   `docker pull moby/buildkit:buildx-stable-1`, its own BuildKit engine,
//!   and auth.docker.io timed out five times. On another attempt the engine
//!   started and BuildKit resolving `rust:1.99-slim-trixie` and
//!   `debian:trixie-slim` from the Dockerfile answered 429.
//!
//! Every one of those pulls was anonymous: docker.yml logs in to GHCR only.
//! Docker Hub limits anonymous pulls per source address, and GitHub's hosted
//! runners share addresses.
//!
//! What these tests hold:
//!
//! 1. No job `container:` or `services:` image, and no `uses: docker://`
//!    image, names Docker Hub. Images named without a registry are Docker
//!    Hub's, so `rust:1-bookworm` counts.
//! 2. No action a workflow uses runs in a container pulled or built from
//!    Docker Hub. A remote action's `action.yml` cannot be read offline, so
//!    [`ACTIONS`] records what each one runs as, read from its `action.yml`
//!    at the pinned commit; an action missing from it fails until someone
//!    reads it. A composite action is classified by its own `action.yml`
//!    only: an action it calls in turn is not.
//! 3. Every `docker/setup-buildx-action` step starts its BuildKit engine from
//!    a digest-pinned image off Docker Hub, and tells BuildKit to fetch
//!    Docker Hub images through `mirror.gcr.io`, so `FROM rust:...` in a
//!    Dockerfile keeps its text and its digest and the bytes come from the
//!    mirror. Every workflow that builds an image sets buildx up.
//! 4. The images `cross` builds in (`Cross.toml`, `docker/cross/`) are not on
//!    Docker Hub, because release.yml runs `cross`, which calls the Docker
//!    CLI directly with no buildx configuration.
//! 5. codespell, which replaced the container action, is pinned once, in
//!    `scripts/requirements-codespell.txt`, and CI and the local hooks both
//!    run that version through `scripts/prose-gates.sh`.

use std::path::{Path, PathBuf};
use std::process::Command;

type TestError = Box<dyn std::error::Error>;

#[path = "support/executable.rs"]
mod executable;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The mirror Docker Hub images are fetched through.
const MIRROR: &str = "mirror.gcr.io";

/// The one place codespell's version is pinned.
const CODESPELL_REQUIREMENTS: &str = "scripts/requirements-codespell.txt";

/// The script every codespell runner sources.
const PROSE_GATES: &str = "scripts/prose-gates.sh";

/// What a remote action runs as, read from its `action.yml` at the commit the
/// workflows pin.
#[derive(Debug, Clone, Copy)]
enum Runs {
    /// `using: node*`: JavaScript on the runner, no image.
    Node,
    /// `using: composite`: steps on the runner, no image of its own.
    Composite,
    /// `using: docker`: the image the runner pulls, or for `image:
    /// Dockerfile` the image the Dockerfile builds `FROM`.
    Container(&'static str),
}

/// Every remote action the workflows use, without its `@ref`, and what it
/// runs as. Each entry was read from the action's `action.yml` at the SHA the
/// workflows pin (2026-10-09). A Dependabot bump that turns one into a
/// container action is not caught here; the image of an action already listed
/// as a container is.
const ACTIONS: &[(&str, Runs)] = &[
    ("actions/attest-build-provenance", Runs::Composite),
    ("actions/cache", Runs::Node),
    ("actions/cache/restore", Runs::Node),
    ("actions/cache/save", Runs::Node),
    ("actions/checkout", Runs::Node),
    ("actions/deploy-pages", Runs::Node),
    ("actions/download-artifact", Runs::Node),
    ("actions/setup-go", Runs::Node),
    ("actions/setup-node", Runs::Node),
    ("actions/upload-artifact", Runs::Node),
    ("actions/upload-pages-artifact", Runs::Composite),
    ("aquasecurity/trivy-action", Runs::Composite),
    ("codecov/codecov-action", Runs::Composite),
    ("docker/build-push-action", Runs::Node),
    ("docker/login-action", Runs::Node),
    ("docker/metadata-action", Runs::Node),
    ("docker/setup-buildx-action", Runs::Node),
    ("dtolnay/rust-toolchain", Runs::Composite),
    ("github/codeql-action/analyze", Runs::Node),
    ("github/codeql-action/init", Runs::Node),
    ("github/codeql-action/upload-sarif", Runs::Node),
    (
        "google/clusterfuzzlite/actions/build_fuzzers",
        Runs::Container("gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1"),
    ),
    (
        "google/clusterfuzzlite/actions/run_fuzzers",
        Runs::Container("gcr.io/oss-fuzz-base/clusterfuzzlite-run-fuzzers:v1"),
    ),
    (
        "google/osv-scanner-action/osv-scanner-action",
        Runs::Container("ghcr.io/google/osv-scanner-action:v2.6.0"),
    ),
    ("lycheeverse/lychee-action", Runs::Composite),
    (
        "ossf/scorecard-action",
        Runs::Container("ghcr.io/ossf/scorecard-action:v2.4.4"),
    ),
    ("rust-lang/crates-io-auth-action", Runs::Node),
    ("softprops/action-gh-release", Runs::Node),
    ("taiki-e/install-action", Runs::Composite),
];

// ---------------------------------------------------------------------------
// Pure helpers, each driven by fixtures below as well as by the real tree.
// ---------------------------------------------------------------------------

/// The registry an image reference pulls from, normalized the way Docker
/// does: the first path component is a registry host only when it holds a
/// `.` or a `:` or is `localhost`; otherwise the image is Docker Hub's.
fn registry(reference: &str) -> &str {
    let r = reference.trim().trim_start_matches("docker://");
    match r.split_once('/') {
        Some((first, _)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            match first {
                "docker.io" | "index.docker.io" | "registry-1.docker.io" => "docker.io",
                other => other,
            }
        }
        _ => "docker.io",
    }
}

/// True when `reference` names an image by content (`@sha256:` and 64 hex).
fn digest_pinned(reference: &str) -> bool {
    reference.split_once("@sha256:").is_some_and(|(_, d)| {
        let d = d.trim();
        d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit())
    })
}

/// `line` without indentation, a leading `- ` list marker or a trailing
/// ` #` comment, or `None` for a blank or comment line.
fn code(line: &str) -> Option<&str> {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let t = t.strip_prefix("- ").map_or(t, str::trim_start);
    Some(t.split(" #").next().unwrap_or(t).trim_end())
}

/// A YAML scalar without its quotes.
fn unquote(v: &str) -> &str {
    v.trim().trim_matches('"').trim_matches('\'')
}

/// Every image a workflow's runner pulls itself: job `container:` and
/// `services:` images (`container: X` or `image: X`, matrix values
/// included) and `uses: docker://X`. Expressions (`${{ ... }}`) are skipped;
/// the matrix values they read are found as `container:` lines in their own
/// right. Returns (1-based line, reference).
fn runner_images(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let Some(c) = code(line) else { continue };
        let value = c
            .strip_prefix("container:")
            .or_else(|| c.strip_prefix("image:"))
            .map(unquote)
            .or_else(|| {
                c.strip_prefix("uses:")
                    .map(unquote)
                    .filter(|u| u.starts_with("docker://"))
            });
        if let Some(v) = value
            && !v.is_empty()
            && !v.starts_with("${{")
            && !v.starts_with('|')
        {
            out.push((i + 1, v.to_string()));
        }
    }
    out
}

/// Every remote action a file uses, as `owner/repo[/path]` without `@ref`.
/// Local (`./`) actions and `docker://` images are left out.
fn remote_actions(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let u = unquote(code(line)?.strip_prefix("uses:")?);
            if u.starts_with("./") || u.starts_with("docker://") {
                return None;
            }
            Some((i + 1, u.split('@').next().unwrap_or(u).to_string()))
        })
        .collect()
}

/// Split a workflow into YAML list items, so a step's `uses:` and its
/// `with:` sit in one chunk.
fn steps(body: &str) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in body.lines() {
        if line.trim_start().starts_with("- ") && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

/// The `[registry."docker.io"]` table of a buildkitd config, as the lines
/// that follow its header up to the next table header.
fn docker_io_table(step: &str) -> Option<Vec<&str>> {
    let mut lines = step
        .lines()
        .skip_while(|l| l.trim() != r#"[registry."docker.io"]"#);
    lines.next()?;
    Some(
        lines
            .take_while(|l| !l.trim_start().starts_with('['))
            .collect(),
    )
}

/// Why one `docker/setup-buildx-action` step can still reach Docker Hub,
/// one entry per problem; empty when it cannot.
fn buildx_setup_problems(step: &str) -> Vec<String> {
    let mut out = Vec::new();
    // The engine. setup-buildx-action pulls `moby/buildkit:buildx-stable-1`
    // with the Docker daemon unless `driver-opts` names another image, and
    // that pull happens before any buildkitd config applies.
    let engine = step
        .lines()
        .filter_map(code)
        .find_map(|c| c.split_once("image=").map(|(_, img)| unquote(img)));
    match engine {
        None => out.push(
            "no `driver-opts: image=...`, so the BuildKit engine is \
             moby/buildkit from Docker Hub"
                .to_string(),
        ),
        Some(img) => {
            if registry(img) == "docker.io" {
                out.push(format!(
                    "the BuildKit engine `{img}` is pulled from Docker Hub"
                ));
            }
            if !digest_pinned(img) {
                out.push(format!(
                    "the BuildKit engine `{img}` is not pinned by digest"
                ));
            }
        }
    }
    // The images BuildKit resolves for `FROM`.
    if !step.contains("buildkitd-config-inline:") {
        out.push(
            "no `buildkitd-config-inline`, so `FROM` images resolve against \
             Docker Hub"
                .to_string(),
        );
    }
    match docker_io_table(step) {
        None => {
            out.push(r#"no `[registry."docker.io"]` table in the buildkitd config"#.to_string())
        }
        Some(table) => {
            let mirrored = table.iter().any(|l| {
                let t = l.trim();
                t.starts_with("mirrors") && t.contains(&format!("\"{MIRROR}\""))
            });
            if !mirrored {
                out.push(format!(
                    r#"`[registry."docker.io"]` does not set `mirrors = ["{MIRROR}"]`"#
                ));
            }
        }
    }
    out
}

/// True when a workflow builds an image: build-push-action, or a `docker
/// build` / `docker buildx build` command.
fn builds_an_image(text: &str) -> bool {
    text.lines().filter_map(code).any(|c| {
        c.contains("docker/build-push-action@")
            || c.contains("docker build ")
            || c.contains("docker buildx build")
    })
}

/// The `name==version` codespell pin in a requirements file.
fn codespell_pin(requirements: &str) -> Option<&str> {
    requirements.lines().find_map(|l| {
        l.trim().strip_prefix("codespell==").map(|v| {
            v.split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('\\')
        })
    })
}

// ---------------------------------------------------------------------------
// The tree.
// ---------------------------------------------------------------------------

/// Every workflow and local composite action file, as (label, text).
fn ci_files() -> Result<Vec<(String, String)>, TestError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repo().join(".github/workflows"))? {
        let path: PathBuf = entry?.path();
        if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            let name = path.file_name().and_then(|n| n.to_str()).ok_or("name")?;
            out.push((
                format!(".github/workflows/{name}"),
                std::fs::read_to_string(&path)?,
            ));
        }
    }
    for entry in std::fs::read_dir(repo().join(".github/actions"))? {
        let action = entry?.path().join("action.yml");
        if action.exists() {
            let label = action
                .strip_prefix(repo())
                .map_err(|e| format!("{}: {e}", action.display()))?
                .display()
                .to_string();
            out.push((label, std::fs::read_to_string(&action)?));
        }
    }
    out.sort();
    assert!(
        out.len() > 10,
        "found only {} workflow and action files; the scan is wrong",
        out.len()
    );
    Ok(out)
}

fn workflows() -> Result<Vec<(String, String)>, TestError> {
    Ok(ci_files()?
        .into_iter()
        .filter(|(l, _)| l.starts_with(".github/workflows/"))
        .collect())
}

#[test]
fn no_job_container_or_service_image_comes_from_docker_hub() -> Result<(), TestError> {
    let mut seen = 0;
    let mut bad = Vec::new();
    for (file, text) in workflows()? {
        for (line, image) in runner_images(&text) {
            seen += 1;
            if registry(&image) == "docker.io" {
                bad.push(format!(
                    "{file}:{line}: `{image}` is pulled from Docker Hub; name it \
                     through {MIRROR}/library/... with the same digest"
                ));
            }
        }
    }
    // release.yml's four bookworm build containers.
    assert!(
        seen >= 4,
        "found {seen} job images, fewer than release.yml's four `container:` \
         entries; the scan stopped seeing them"
    );
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    Ok(())
}

#[test]
fn no_action_runs_in_a_container_from_docker_hub() -> Result<(), TestError> {
    let mut used = std::collections::BTreeSet::new();
    let mut bad = Vec::new();
    for (file, text) in ci_files()? {
        for (line, action) in remote_actions(&text) {
            used.insert(action.clone());
            match ACTIONS.iter().find(|(name, _)| *name == action) {
                None => bad.push(format!(
                    "{file}:{line}: `{action}` is not in ACTIONS. Read its \
                     action.yml at the pinned SHA and record what `runs.using` \
                     is, and for `docker` the image it pulls or builds FROM"
                )),
                Some((_, Runs::Container(image))) if registry(image) == "docker.io" => {
                    bad.push(format!(
                        "{file}:{line}: `{action}` runs in `{image}`, pulled from \
                         Docker Hub anonymously. Run the tool as a step instead"
                    ));
                }
                Some(_) => {}
            }
        }
        // A local action is read directly.
        if file.ends_with("action.yml") {
            let using = text
                .lines()
                .filter_map(code)
                .find_map(|c| c.strip_prefix("using:").map(unquote))
                .ok_or_else(|| format!("{file}: no `using:`"))?;
            assert_ne!(
                using, "docker",
                "{file} is a Docker container action; extend this test to read \
                 its image"
            );
        }
    }
    // A stale row is a classification nobody re-reads.
    for (name, _) in ACTIONS {
        assert!(
            used.contains(*name),
            "ACTIONS lists `{name}`, which no workflow uses any more; remove it"
        );
    }
    assert!(used.len() >= 20, "only {} remote actions found", used.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    Ok(())
}

#[test]
fn every_buildx_setup_keeps_its_pulls_off_docker_hub() -> Result<(), TestError> {
    let mut setups = 0;
    let mut bad = Vec::new();
    for (file, text) in workflows()? {
        let mut here = 0;
        for step in steps(&text) {
            if !step
                .lines()
                .filter_map(code)
                .any(|c| c.starts_with("uses: docker/setup-buildx-action@"))
            {
                continue;
            }
            here += 1;
            for p in buildx_setup_problems(&step) {
                bad.push(format!("{file}: Set up Docker Buildx: {p}"));
            }
        }
        if builds_an_image(&text) && here == 0 {
            bad.push(format!(
                "{file} builds an image without docker/setup-buildx-action, so \
                 the Docker daemon resolves `FROM` against Docker Hub"
            ));
        }
        setups += here;
    }
    assert!(
        setups >= 1,
        "no docker/setup-buildx-action step found; the scan is wrong"
    );
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    Ok(())
}

#[test]
fn the_images_cross_builds_in_are_not_on_docker_hub() -> Result<(), TestError> {
    let mut images = Vec::new();
    let cross = std::fs::read_to_string(repo().join("Cross.toml"))?;
    for line in cross.lines() {
        if let Some(v) = line.trim().strip_prefix("image =") {
            images.push(("Cross.toml".to_string(), unquote(v).to_string()));
        }
    }
    for entry in std::fs::read_dir(repo().join("docker/cross"))? {
        let path = entry?.path();
        let text = std::fs::read_to_string(&path)?;
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("FROM ") {
                let image = rest.split_whitespace().next().unwrap_or("");
                images.push((path.display().to_string(), image.to_string()));
            }
        }
    }
    assert!(
        images.len() >= 4,
        "found {} cross images, fewer than Cross.toml's two plus docker/cross's two",
        images.len()
    );
    for (file, image) in images {
        assert_ne!(
            registry(&image),
            "docker.io",
            "{file}: cross pulls `{image}` from Docker Hub with the Docker CLI, \
             which no buildx mirror reaches"
        );
    }
    Ok(())
}

#[test]
fn codespell_is_pinned_once_and_ci_runs_it_through_the_shared_runner() -> Result<(), TestError> {
    let req = std::fs::read_to_string(repo().join(CODESPELL_REQUIREMENTS))
        .map_err(|e| format!("{CODESPELL_REQUIREMENTS}: {e}"))?;
    let pin = codespell_pin(&req).ok_or("no `codespell==` pin")?;
    assert!(
        !pin.is_empty(),
        "{CODESPELL_REQUIREMENTS}: empty codespell pin"
    );

    let gates = std::fs::read_to_string(repo().join(PROSE_GATES))?;
    assert!(
        gates
            .lines()
            .filter_map(code)
            .any(|c| c.contains(CODESPELL_REQUIREMENTS)),
        "{PROSE_GATES} does not read {CODESPELL_REQUIREMENTS} in code, so the \
         hooks cannot compare the local codespell with the one CI installs"
    );

    let quality = std::fs::read_to_string(repo().join(".github/workflows/quality.yml"))?;
    let lines: Vec<&str> = quality.lines().filter_map(code).collect();
    assert!(
        lines.iter().any(|c| c.contains("pip install")
            && c.contains("--require-hashes")
            && c.contains(&format!("-r {CODESPELL_REQUIREMENTS}"))),
        "quality.yml does not pip-install codespell from {CODESPELL_REQUIREMENTS}"
    );
    assert!(
        lines.iter().any(|c| c.contains(PROSE_GATES))
            && lines.iter().any(|c| c.contains("prose_codespell_run")),
        "quality.yml does not run codespell through {PROSE_GATES}'s \
         prose_codespell_run, so CI and the hooks can pass different arguments"
    );
    Ok(())
}

/// Run `prose_codespell_run` from the shared script with `stub_version` as
/// the only codespell on PATH. Returns (exit code, `$PROSE_REASON`).
fn run_codespell_gate(stub_version: &str) -> Result<(i32, String), TestError> {
    let tmp = tempfile::tempdir()?;
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin)?;
    executable::write_executable(
        &bin.join("codespell"),
        &format!("#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{stub_version}'; fi\nexit 0\n"),
    )?;
    let path = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))?;
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            ". ./{PROSE_GATES}; prose_codespell_run README.md; rc=$?; \
             [ -n \"$PROSE_OUTPUT\" ] && rm -f \"$PROSE_OUTPUT\"; \
             printf '%s\\n%s\\n' \"$rc\" \"$PROSE_REASON\""
        ))
        .current_dir(repo())
        .env("PATH", path)
        .env_remove("CODESPELL_BIN")
        .output()?;
    let text = String::from_utf8(out.stdout)?;
    let mut it = text.lines();
    let rc = it.next().ok_or("no rc")?.parse()?;
    Ok((rc, it.next().unwrap_or("").to_string()))
}

#[test]
fn the_shared_runner_accepts_the_pinned_codespell() -> Result<(), TestError> {
    let req = std::fs::read_to_string(repo().join(CODESPELL_REQUIREMENTS))?;
    let pin = codespell_pin(&req).ok_or("no pin")?;
    let (rc, reason) = run_codespell_gate(pin)?;
    assert_eq!(rc, 0, "codespell {pin} is the pin and must run: {reason}");
    Ok(())
}

#[test]
fn the_shared_runner_refuses_a_codespell_of_another_version() -> Result<(), TestError> {
    let (rc, reason) = run_codespell_gate("0.0.1")?;
    assert_eq!(
        rc, 2,
        "a codespell that is not the pinned version must report NOT CHECKED \
         (2), since its dictionary is not CI's; got {rc}: {reason}"
    );
    assert!(
        reason.contains("0.0.1"),
        "the reason must name the version found: {reason}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The helpers on fixtures.
// ---------------------------------------------------------------------------

#[test]
fn registry_follows_dockers_normalization() {
    for (r, want) in [
        ("rust:1-bookworm@sha256:ab", "docker.io"),
        ("library/debian:trixie-slim", "docker.io"),
        ("moby/buildkit:buildx-stable-1", "docker.io"),
        ("docker.io/library/rust:1", "docker.io"),
        ("index.docker.io/moby/buildkit", "docker.io"),
        ("docker://python:3.13-alpine", "docker.io"),
        ("mirror.gcr.io/library/rust:1", "mirror.gcr.io"),
        ("ghcr.io/cross-rs/x:main", "ghcr.io"),
        ("localhost:5000/x", "localhost:5000"),
        ("localhost/x", "localhost"),
        ("docker://gcr.io/a/b:v1", "gcr.io"),
    ] {
        assert_eq!(registry(r), want, "{r}");
    }
}

#[test]
fn runner_images_finds_container_service_and_docker_uses() {
    let wf = "\
jobs:
  a:
    container: ${{ matrix.container }}
    strategy:
      matrix:
        include:
          - container: rust:1-bookworm@sha256:00
    services:
      db:
        image: 'postgres:16'
    steps:
      # container: commented:out
      - uses: docker://alpine:3
      - uses: actions/checkout@abc
";
    let got: Vec<String> = runner_images(wf).into_iter().map(|(_, r)| r).collect();
    assert_eq!(
        got,
        [
            "rust:1-bookworm@sha256:00",
            "postgres:16",
            "docker://alpine:3"
        ]
    );
}

#[test]
fn buildx_setup_problems_names_each_missing_piece() {
    let digest = "0".repeat(64);
    let good = format!(
        "      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@f87e # v4
        with:
          driver-opts: |
            image=mirror.gcr.io/moby/buildkit:v0.33.1@sha256:{digest}
          buildkitd-config-inline: |
            [registry.\"docker.io\"]
              mirrors = [\"mirror.gcr.io\"]
"
    );
    assert!(
        buildx_setup_problems(&good).is_empty(),
        "{:?}",
        buildx_setup_problems(&good)
    );

    let bare = "      - uses: docker/setup-buildx-action@f87e # v4\n";
    assert_eq!(
        buildx_setup_problems(bare).len(),
        3,
        "{:?}",
        buildx_setup_problems(bare)
    );

    let hub_engine = good.replace("mirror.gcr.io/moby/buildkit", "moby/buildkit");
    assert_eq!(buildx_setup_problems(&hub_engine).len(), 1);

    let floating = good.replace(&format!("@sha256:{digest}"), "");
    assert_eq!(buildx_setup_problems(&floating).len(), 1);

    let other_table = good.replace(r#"[registry."docker.io"]"#, r#"[registry."ghcr.io"]"#);
    assert_eq!(buildx_setup_problems(&other_table).len(), 1);

    // The mirror line belongs to a later table, not to docker.io's.
    let wrong_table = good.replace(
        "              mirrors",
        "            [registry.\"quay.io\"]\n              mirrors",
    );
    assert_eq!(buildx_setup_problems(&wrong_table).len(), 1);
}

#[test]
fn remote_actions_skips_local_docker_and_comments() {
    let wf = "\
      - uses: actions/checkout@abc # v7
      - uses: ./.github/actions/free-disk
      - uses: docker://alpine:3
      #   uses: actions/setup-example@v1
      - uses: 'google/clusterfuzzlite/actions/build_fuzzers@884'
";
    let got: Vec<String> = remote_actions(wf).into_iter().map(|(_, a)| a).collect();
    assert_eq!(
        got,
        [
            "actions/checkout",
            "google/clusterfuzzlite/actions/build_fuzzers"
        ]
    );
}

#[test]
fn codespell_pin_reads_a_hashed_requirement() {
    let req = "# c\ncodespell==2.4.3 \\\n    --hash=sha256:aa\n";
    assert_eq!(codespell_pin(req), Some("2.4.3"));
    assert_eq!(codespell_pin("codespell>=2.2.4\n"), None);
}
