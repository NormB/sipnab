// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Dependabot watches every dependency file the repository tracks.
//!
//! Each tracked file below must be covered by an entry of `.github/dependabot.yml`
//! of its ecosystem whose `directory` (or one of whose `directories`, which may
//! use `*` for one path segment and `**` for any number) is the file's
//! directory, or be listed in [`EXCEPTIONS`] with the reason it needs none:
//!
//! | File | Ecosystem |
//! |---|---|
//! | `Cargo.lock` | `cargo` |
//! | `package-lock.json` | `npm` |
//! | `*requirements*.txt` | `pip` |
//! | `Dockerfile` | `docker` |
//! | `go.mod` with a `require` directive | `gomod` |
//! | `.github/actions/<name>/action.yml` | `github-actions`, `/.github/actions/<name>` |
//! | `.github/workflows/*` | `github-actions`, `/` |
//!
//! Found by OpenSSF Scorecard on 2026-10-28: `e2e/package-lock.json` carried a
//! zod release with a published advisory (GHSA-mrhx-c7xc-m3w5), and Dependabot
//! raised no alert because no `npm` entry existed. Earlier the same gap kept a
//! vulnerable `qs` in that lockfile for two weeks after its fix was released.
//!
//! The configuration is read line by line rather than with a YAML library: the
//! file uses one small subset (a list of `updates`, each with
//! `package-ecosystem` and a `directory` or `directories`), and no YAML crate
//! is a dependency of this repository.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

/// Any error a test can return.
type TestError = Box<dyn std::error::Error>;

/// Dependency files that need no Dependabot entry, with the reason.
const EXCEPTIONS: &[(&str, &str)] = &[(
    "clients/go/go.mod",
    "declares no dependency: no require directive and no go.sum \
     (the_go_client_still_declares_no_dependency holds that)",
)];

/// One `updates` entry of `dependabot.yml`: its ecosystem and the directory
/// patterns it watches.
#[derive(Debug, PartialEq, Eq)]
struct Update {
    /// The `package-ecosystem` value.
    ecosystem: String,
    /// The `directory` value and every `directories` entry.
    dirs: Vec<String>,
}

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The value after `key:` on `line`, unquoted, or `None` when the line does not
/// set `key`. A trailing comment is dropped.
fn value_of(line: &str, key: &str) -> Option<String> {
    let rest = line.trim_start().trim_start_matches("- ");
    let rest = rest.strip_prefix(key)?.strip_prefix(':')?;
    let rest = rest.split(" #").next().unwrap_or(rest).trim();
    Some(rest.trim_matches('"').trim_matches('\'').to_string())
}

/// Every quoted or bare item of an inline YAML list such as `["/", "/a"]`.
fn inline_list(text: &str) -> Vec<String> {
    text.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|item| item.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// The `updates` entries of a `dependabot.yml` text.
fn parse_updates(text: &str) -> Vec<Update> {
    let mut updates: Vec<Update> = Vec::new();
    let mut in_directories = false;
    for line in text.lines() {
        let content = line.split('#').next().unwrap_or("");
        if content.trim().is_empty() {
            continue;
        }
        if let Some(ecosystem) = value_of(content, "package-ecosystem") {
            updates.push(Update {
                ecosystem,
                dirs: Vec::new(),
            });
            in_directories = false;
            continue;
        }
        let Some(current) = updates.last_mut() else {
            continue;
        };
        if let Some(dir) = value_of(content, "directory") {
            current.dirs.push(dir);
            in_directories = false;
        } else if let Some(list) = value_of(content, "directories") {
            if list.is_empty() {
                in_directories = true;
            } else {
                current.dirs.extend(inline_list(&list));
                in_directories = false;
            }
        } else if in_directories && content.trim_start().starts_with("- ") {
            current
                .dirs
                .extend(inline_list(content.trim_start().trim_start_matches("- ")));
        } else {
            in_directories = false;
        }
    }
    updates
}

/// `/a/b/` and `a/b` as `/a/b`; the root as `/`.
fn normal(dir: &str) -> String {
    let trimmed = dir.trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Whether one path segment matches one pattern segment, where `*` stands for
/// any run of characters within the segment.
fn segment_matches(pattern: &str, segment: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == segment,
        Some((head, tail)) => {
            let Some(rest) = segment.strip_prefix(head) else {
                return false;
            };
            (0..=rest.len())
                .filter(|i| rest.is_char_boundary(*i))
                .any(|i| segment_matches(tail, &rest[i..]))
        }
    }
}

/// Whether a directory pattern of `dependabot.yml` matches `dir`, where `**`
/// stands for any number of path segments, none included.
fn glob_matches(pattern: &str, dir: &str) -> bool {
    fn walk(p: &[&str], d: &[&str]) -> bool {
        match p.split_first() {
            None => d.is_empty(),
            Some((&"**", rest)) => (0..=d.len()).any(|i| walk(rest, &d[i..])),
            Some((head, rest)) => match d.split_first() {
                Some((seg, d_rest)) => segment_matches(head, seg) && walk(rest, d_rest),
                None => false,
            },
        }
    }
    let pattern = normal(pattern);
    let dir = normal(dir);
    let p: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let d: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    walk(&p, &d)
}

/// The directory a tracked file sits in, as Dependabot names it.
fn directory_of(path: &str) -> String {
    match path.rsplit_once('/') {
        Some((parent, _)) => normal(parent),
        None => "/".to_string(),
    }
}

/// The compose-file name rule of Dependabot's `docker-compose` fetcher
/// (`dependabot-core` `docker/lib/dependabot/docker_compose/file_fetcher.rb`),
/// matched anywhere in the name and in any letter case, as it is there.
fn compose_name() -> Result<regex::Regex, regex::Error> {
    regex::Regex::new(r"(?i)(docker-)?compose(-\w+)?(\.[\w-]+)?\.ya?ml")
}

/// The Dependabot ecosystem that reads a file of this name, if any.
///
/// GitHub's Dependabot documentation (the supported-ecosystems page and the
/// options reference, read 2026-10-28) names the `package-ecosystem` values
/// but not the file names each reads, so these come from Dependabot's own file
/// fetchers in `dependabot/dependabot-core`. Docker:
/// `docker/lib/dependabot/docker/file_fetcher.rb` has
/// `DOCKER_REGEXP = /dockerfile|containerfile/i`, matched anywhere in the name
/// in any case, so `Dockerfile.<target>` and `<name>.Dockerfile` are read; its
/// YAML is read only as a Kubernetes resource (`apiVersion` and `kind`).
/// Compose: [`compose_name`]. The `package-ecosystem` of each lockfile is the
/// options reference's table (npm, pnpm and yarn are `npm`; pip, pip-compile,
/// pipenv and poetry are `pip`).
fn ecosystem_of(name: &str, compose: &regex::Regex) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if name == "Cargo.lock" {
        Some("cargo")
    } else if matches!(
        name,
        "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock" | "pnpm-lock.yaml"
    ) {
        Some("npm")
    } else if (name.contains("requirements") && (name.ends_with(".txt") || name.ends_with(".in")))
        || matches!(name, "Pipfile.lock" | "poetry.lock")
    {
        Some("pip")
    } else if name == "uv.lock" {
        Some("uv")
    } else if name == "Gemfile.lock" {
        Some("bundler")
    } else if name == "composer.lock" {
        Some("composer")
    } else if lower.contains("dockerfile") || lower.contains("containerfile") {
        Some("docker")
    } else if compose.is_match(name) {
        Some("docker-compose")
    } else if name == "go.mod" {
        Some("gomod")
    } else {
        None
    }
}

/// `(file, ecosystem, directory)` for each dependency file in `paths`. All
/// workflows count as one file in the directory `/`.
fn dependency_files(paths: &[String]) -> Result<Vec<(String, &'static str, String)>, regex::Error> {
    let compose = compose_name()?;
    let mut found = Vec::new();
    let mut workflows = false;
    for path in paths {
        let name = path.rsplit('/').next().unwrap_or(path);
        let in_actions = path.strip_prefix(".github/actions/").is_some_and(|rest| {
            matches!(
                rest.split_once('/'),
                Some((_, "action.yml" | "action.yaml"))
            )
        });
        let ecosystem = if path.starts_with(".github/workflows/") {
            workflows = true;
            None
        } else if in_actions {
            Some("github-actions")
        } else {
            ecosystem_of(name, &compose)
        };
        if let Some(ecosystem) = ecosystem {
            found.push((path.clone(), ecosystem, directory_of(path)));
        }
    }
    if workflows {
        found.push((
            ".github/workflows".to_string(),
            "github-actions",
            "/".to_string(),
        ));
    }
    Ok(found)
}

/// Whether some entry of `updates` of `ecosystem` watches `dir`.
fn covered(updates: &[Update], ecosystem: &str, dir: &str) -> bool {
    updates
        .iter()
        .filter(|u| u.ecosystem == ecosystem)
        .any(|u| u.dirs.iter().any(|pattern| glob_matches(pattern, dir)))
}

/// The files `git ls-files` lists in the repository.
fn tracked_files() -> Result<Vec<String>, TestError> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo())
        .output()?;
    if !out.status.success() {
        return Err(format!("git ls-files: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect())
}

/// **Every dependency file the repository tracks has a Dependabot entry.**
#[test]
fn dependabot_watches_every_dependency_file() -> Result<(), TestError> {
    let config = std::fs::read_to_string(repo().join(".github/dependabot.yml"))?;
    let updates = parse_updates(&config);
    let files = tracked_files()?;
    let found = dependency_files(&files)?;
    assert!(
        found.iter().any(|(_, e, _)| *e == "cargo") && found.len() >= 5,
        "control: the scan finds the root Cargo.lock and at least 5 dependency files: {found:?}"
    );
    let exceptions: BTreeMap<&str, &str> = EXCEPTIONS.iter().copied().collect();
    let missing: Vec<String> = found
        .iter()
        .filter(|(file, _, _)| !exceptions.contains_key(file.as_str()))
        .filter(|(_, ecosystem, dir)| !covered(&updates, ecosystem, dir))
        .map(|(file, ecosystem, dir)| format!("{file} (ecosystem {ecosystem}, directory {dir})"))
        .collect();
    assert!(
        missing.is_empty(),
        "no .github/dependabot.yml entry watches these dependency files, so a \
         vulnerable version in them raises no alert and gets no update:\n  {}",
        missing.join("\n  ")
    );
    Ok(())
}

/// Every exception names a tracked dependency file that no entry watches, with
/// a reason: an exception for a file that is gone, is no longer a dependency
/// file, or is now watched has outlived its reason.
#[test]
fn every_exception_names_a_tracked_dependency_file() -> Result<(), TestError> {
    let config = std::fs::read_to_string(repo().join(".github/dependabot.yml"))?;
    let updates = parse_updates(&config);
    let files = tracked_files()?;
    let found = dependency_files(&files)?;
    for (file, reason) in EXCEPTIONS {
        assert!(files.iter().any(|f| f == file), "{file} is not tracked");
        assert!(!reason.trim().is_empty(), "{file} needs a reason");
        let (_, ecosystem, dir) = found.iter().find(|(f, _, _)| f == file).ok_or_else(|| {
            format!("{file} is no longer a dependency file: remove it from EXCEPTIONS")
        })?;
        assert!(
            !covered(&updates, ecosystem, dir),
            "{file} is now watched by a {ecosystem} entry: remove it from EXCEPTIONS"
        );
    }
    Ok(())
}

/// The Go client's exception stays true: its `go.mod` declares no dependency
/// (no `require` directive) and it has no `go.sum`. Either appearing means it
/// has dependencies, and needs a `gomod` entry instead.
#[test]
fn the_go_client_still_declares_no_dependency() -> Result<(), TestError> {
    let go_mod = std::fs::read_to_string(repo().join("clients/go/go.mod"))?;
    assert!(
        !go_mod
            .lines()
            .any(|l| l.trim_start().starts_with("require")),
        "clients/go/go.mod gained a require directive: add a gomod entry and drop its exception"
    );
    assert!(
        !repo().join("clients/go/go.sum").exists(),
        "clients/go/go.sum exists: add a gomod entry and drop the exception"
    );
    Ok(())
}

/// The reader takes `directory`, a block `directories` list and an inline one,
/// and ignores comments.
#[test]
fn the_reader_takes_every_directory_form() {
    let text = r#"
version: 2
updates:
  # a comment
  - package-ecosystem: "cargo"
    directory: "/"
    groups:
      minor:
        update-types:
          - "minor"
  - package-ecosystem: npm
    directories:
      - "/e2e"   # the site tests
      - "/clients/typescript"
    schedule:
      interval: "weekly"
  - package-ecosystem: "docker"
    directories: ["/**", '/ops']
"#;
    assert_eq!(
        parse_updates(text),
        vec![
            Update {
                ecosystem: "cargo".into(),
                dirs: vec!["/".into()]
            },
            Update {
                ecosystem: "npm".into(),
                dirs: vec!["/e2e".into(), "/clients/typescript".into()]
            },
            Update {
                ecosystem: "docker".into(),
                dirs: vec!["/**".into(), "/ops".into()]
            },
        ]
    );
}

/// `/` matches the root only, `*` one segment, `**` any number.
#[test]
fn directory_patterns_match_as_dependabot_reads_them() {
    assert!(glob_matches("/", "/"));
    assert!(!glob_matches("/", "/e2e"));
    assert!(glob_matches("/e2e", "/e2e"));
    assert!(glob_matches("/e2e/", "/e2e"));
    assert!(!glob_matches("/e2e", "/e2e/sub"));
    assert!(glob_matches("/**", "/"));
    assert!(glob_matches("/**", "/harness/sipp"));
    assert!(glob_matches(
        "/.github/actions/*",
        "/.github/actions/free-disk"
    ));
    assert!(!glob_matches("/.github/actions/*", "/.github/actions/a/b"));
    assert!(!glob_matches("/.github/actions/*", "/.github/actions"));
    assert!(glob_matches("/clients/*-sdk", "/clients/go-sdk"));
    assert!(!glob_matches("/clients/*-sdk", "/clients/go"));
}

/// Each class of dependency file is found, in its own directory, named as
/// Dependabot's own file fetchers name them (`dependabot-core`: the docker
/// fetcher matches `dockerfile|containerfile` anywhere in a name, the compose
/// fetcher `(docker-)?compose(-\w+)?(\.[\w-]+)?\.ya?ml`); an ordinary file is not.
/// Every `go.mod` counts, with or without a `require`: one with none is
/// excused by name in [`EXCEPTIONS`], so the decision is written down.
#[test]
fn every_class_of_dependency_file_is_found() -> Result<(), TestError> {
    let paths: Vec<String> = [
        "Cargo.lock",
        "fuzz/Cargo.lock",
        "e2e/package-lock.json",
        "e2e/package.json",
        "clients/python/requirements-test.txt",
        "harness/sipp/Dockerfile",
        "bench/voipmonitor.Dockerfile",
        "docker/cross/Dockerfile.aarch64-unknown-linux-musl",
        "ops/Containerfile",
        "harness/docker-compose.single.yml",
        "contrib/compose.yaml",
        "web/npm-shrinkwrap.json",
        "web/yarn.lock",
        "web/pnpm-lock.yaml",
        "py/requirements-dev.in",
        "py/Pipfile.lock",
        "py/poetry.lock",
        "py/uv.lock",
        "rb/Gemfile.lock",
        "php/composer.lock",
        "clients/go/go.mod",
        "tools/empty/go.mod",
        ".github/actions/free-disk/action.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/fuzz.yml",
        "README.md",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let found: Vec<(String, &str, String)> = dependency_files(&paths)?;
    let as_tuples: Vec<(&str, &str, &str)> = found
        .iter()
        .map(|(f, e, d)| (f.as_str(), *e, d.as_str()))
        .collect();
    assert_eq!(
        as_tuples,
        vec![
            ("Cargo.lock", "cargo", "/"),
            ("fuzz/Cargo.lock", "cargo", "/fuzz"),
            ("e2e/package-lock.json", "npm", "/e2e"),
            (
                "clients/python/requirements-test.txt",
                "pip",
                "/clients/python"
            ),
            ("harness/sipp/Dockerfile", "docker", "/harness/sipp"),
            ("bench/voipmonitor.Dockerfile", "docker", "/bench"),
            (
                "docker/cross/Dockerfile.aarch64-unknown-linux-musl",
                "docker",
                "/docker/cross"
            ),
            ("ops/Containerfile", "docker", "/ops"),
            (
                "harness/docker-compose.single.yml",
                "docker-compose",
                "/harness"
            ),
            ("contrib/compose.yaml", "docker-compose", "/contrib"),
            ("web/npm-shrinkwrap.json", "npm", "/web"),
            ("web/yarn.lock", "npm", "/web"),
            ("web/pnpm-lock.yaml", "npm", "/web"),
            ("py/requirements-dev.in", "pip", "/py"),
            ("py/Pipfile.lock", "pip", "/py"),
            ("py/poetry.lock", "pip", "/py"),
            ("py/uv.lock", "uv", "/py"),
            ("rb/Gemfile.lock", "bundler", "/rb"),
            ("php/composer.lock", "composer", "/php"),
            ("clients/go/go.mod", "gomod", "/clients/go"),
            ("tools/empty/go.mod", "gomod", "/tools/empty"),
            (
                ".github/actions/free-disk/action.yml",
                "github-actions",
                "/.github/actions/free-disk"
            ),
            (".github/workflows", "github-actions", "/"),
        ]
    );
    Ok(())
}

/// An entry covers a file only when both its ecosystem and a directory match.
#[test]
fn coverage_needs_the_ecosystem_and_the_directory() {
    let updates = parse_updates(
        "updates:\n  - package-ecosystem: cargo\n    directory: /\n  - package-ecosystem: npm\n    directory: /e2e\n",
    );
    assert!(covered(&updates, "cargo", "/"));
    assert!(covered(&updates, "npm", "/e2e"));
    assert!(
        !covered(&updates, "npm", "/"),
        "cargo's / does not cover npm"
    );
    assert!(!covered(&updates, "npm", "/clients/typescript"));
    assert!(!covered(&updates, "pip", "/e2e"));
}
