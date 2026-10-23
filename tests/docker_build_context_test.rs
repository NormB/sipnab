// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The Docker workflow builds the image twice from one build context.
//!
//! `docker.yml` builds `sipnab:smoke`, scans and smoke-tests it, and then
//! builds again to push. The second build reuses the first one's layers only
//! if the build context is the same, because the builder stage starts with
//! `COPY . .` and every layer after it depends on what that copied.
//!
//! Between the two builds the scan writes into the checkout: the Trivy
//! vulnerability database (about 60 MB, cached under `.cache/trivy`) and the
//! `trivy.sarif` report. Neither was in `.dockerignore`, so the second build
//! saw a different context and compiled sipnab again: two `cargo build
//! --release` runs of about 13 minutes each, against a 30-minute job timeout.
//! On 2026-10-23 three Docker runs hit that timeout and were canceled, one of
//! them on main, and the successful ones took 19 to 27 minutes.
//!
//! What this test holds: every path in the workspace that a step between the
//! two builds writes is excluded by `.dockerignore`. The paths are read from
//! the workflow, not listed here, so renaming the report or moving the cache
//! cannot slip past.

use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join(rel)).map_err(|e| format!("read {rel}: {e}"))?)
}

/// The text of `docker.yml` from the smoke build's step up to, not including,
/// the push build's step.
fn between_the_builds(wf: &str) -> Result<&str, TestError> {
    let start = wf
        .find("- name: Build image for smoke test")
        .ok_or("docker.yml has no `Build image for smoke test` step")?;
    let end = wf[start..]
        .find("- name: Build and push")
        .ok_or("docker.yml has no `Build and push` step after the smoke build")?;
    Ok(&wf[start..start + end])
}

/// Workspace-relative paths the steps in `text` write.
///
/// Two shapes write into the checkout: a value that starts with
/// `${{ github.workspace }}/` (a cache `path:`, a `*_CACHE_DIR` variable), and
/// an action's `output:` given as a relative path.
fn written_paths(text: &str) -> Vec<String> {
    const WS: &str = "${{ github.workspace }}/";
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let Some((key, value)) = l.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches(['\'', '"']);
        if let Some(rel) = value.strip_prefix(WS) {
            out.push(rel.trim_end_matches('/').to_string());
        } else if key.trim() == "output"
            && !value.is_empty()
            && !value.starts_with("${{")
            && !Path::new(value).is_absolute()
        {
            out.push(value.trim_start_matches("./").to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether `.dockerignore` leaves `path` out of the build context.
///
/// Patterns are applied in order and the last match wins, as Docker does, so
/// a later `!pattern` puts a path back. A pattern matches the path itself or
/// anything under it. Only the literal-prefix patterns this file uses are
/// understood; a glob in a pattern that would decide one of these paths fails
/// loudly rather than being guessed at.
fn excluded(dockerignore: &str, path: &str) -> Result<bool, TestError> {
    let mut verdict = false;
    for raw in dockerignore.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negate, pat) = match line.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, line),
        };
        let pat = pat.trim_start_matches('/').trim_end_matches('/');
        let literal = pat.trim_end_matches("/**");
        let matches = path == literal || path.starts_with(&format!("{literal}/"));
        if literal.contains(['*', '?', '[']) {
            // `*.pcap` and the like cannot decide a path with no such suffix;
            // anything else is a pattern this reader does not understand.
            if let Some(ext) = literal.strip_prefix("*.")
                && !ext.contains(['*', '?', '[', '/'])
            {
                if path.ends_with(&format!(".{ext}")) {
                    verdict = !negate;
                }
                continue;
            }
            return Err(format!(
                "`.dockerignore` pattern `{line}` is a glob this test cannot evaluate"
            )
            .into());
        }
        if matches {
            verdict = !negate;
        }
    }
    Ok(verdict)
}

#[test]
fn files_written_between_the_two_image_builds_stay_out_of_the_build_context()
-> Result<(), TestError> {
    let wf = read(".github/workflows/docker.yml")?;
    let ignore = read(".dockerignore")?;
    let paths = written_paths(between_the_builds(&wf)?);
    assert!(
        paths.len() >= 2,
        "found {} path(s) written between the builds ({paths:?}); the Trivy \
         cache and the SARIF report are two, so the reader has stopped \
         matching",
        paths.len()
    );
    let leaked: Vec<&String> = paths
        .iter()
        .filter(|p| !excluded(&ignore, p).unwrap_or(false))
        .collect();
    assert!(
        leaked.is_empty(),
        "these paths are written into the checkout between the smoke build and \
         the push build, and `.dockerignore` lets them into the build context, \
         so the push build's `COPY . .` sees a new context and compiles sipnab \
         a second time: {leaked:?}"
    );
    Ok(())
}

#[test]
fn the_reader_finds_the_paths_this_workflow_writes() -> Result<(), TestError> {
    let text = "      - name: Cache\n        with:\n          path: ${{ github.workspace }}/.cache/trivy\n      - name: Scan\n        env:\n          TRIVY_CACHE_DIR: ${{ github.workspace }}/.cache/trivy\n        with:\n          output: trivy.sarif\n          # output: commented.sarif\n          image-ref: sipnab:smoke\n";
    assert_eq!(written_paths(text), vec![".cache/trivy", "trivy.sarif"]);
    Ok(())
}

#[test]
fn a_later_reinclude_puts_a_path_back() -> Result<(), TestError> {
    let ignore = "target/\n.cache/\n*.pcap\n!.cache/trivy\n";
    assert!(excluded(ignore, "target")?);
    assert!(excluded(ignore, ".cache/other")?);
    assert!(
        !excluded(ignore, ".cache/trivy")?,
        "the `!` line re-includes it"
    );
    assert!(excluded(ignore, "x/y.pcap")?);
    assert!(!excluded(ignore, "trivy.sarif")?);
    assert!(
        excluded("**/odd\n", "odd").is_err(),
        "an unknown glob is refused"
    );
    Ok(())
}
