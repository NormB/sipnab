// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//! The accepted advisories in `osv-scanner.toml` reach every lockfile the way
//! OpenSSF Scorecard reads them.
//!
//! osv-scanner reads `osv-scanner.toml` only from the directory of the
//! lockfile it scans, never from a parent directory (osv-scanner v2.5.1,
//! `internal/config/manager.go`). Scorecard v5.6.0, which
//! `ossf/scorecard-action` v2.5.0 runs, scans the repository with that library
//! and passes no configuration option. So a root-only file covers the root
//! `Cargo.lock` alone: a recursive osv-scanner 2.7.0 scan of main 2062140b1
//! with no `--config` reported RUSTSEC-2026-0543 in `fuzz/Cargo.lock`,
//! although the root file accepts it.
//!
//! The OSV workflow passed `--config=osv-scanner.toml`, which applies one file
//! to every lockfile, so the workflow was green where Scorecard reported.
//!
//! The rule held here:
//! - every directory that holds a lockfile osv-scanner reads has a tracked
//!   `osv-scanner.toml`, byte-identical to the root one;
//! - no copy stands in a directory without a lockfile;
//! - the OSV workflow scans recursively and passes no `--config`, so it reads
//!   the copies as Scorecard does and reports what Scorecard reports.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "support/tracked.rs"]
mod tracked;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// The configuration's name, which osv-scanner looks for beside a lockfile.
const CONFIG: &str = "osv-scanner.toml";

/// The workflow that runs osv-scanner on every pull request.
const WORKFLOW: &str = ".github/workflows/osv-scanner.yml";

/// The files osv-scanner 2.7.0 read in a recursive scan of a `git archive`
/// export of main 2062140b1, copied from its `Scanned <path> file` lines.
const SCANNED_ON_MAIN: &[&str] = &[
    "Cargo.lock",
    "bpf/Cargo.lock",
    "clients/go/go.mod",
    "clients/python/requirements-examples.txt",
    "clients/python/requirements-mcp.txt",
    "clients/python/requirements-test.txt",
    "clients/typescript/package-lock.json",
    "e2e/package-lock.json",
    "fuzz/Cargo.lock",
    "scripts/requirements-codespell.txt",
    "scripts/requirements-yang.txt",
];

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Whether osv-scanner reads the file at `path` as a lockfile: the file names
/// of its extractors for the ecosystems a repository like this one can hold,
/// and its Python rule (a `.txt` file whose name holds "requirements").
fn is_lockfile(path: &str) -> bool {
    const NAMES: &[&str] = &[
        "Cargo.lock",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "composer.lock",
    ];
    let name = path.rsplit('/').next().unwrap_or(path);
    NAMES.contains(&name) || (name.ends_with(".txt") && name.contains("requirements"))
}

/// The directory of a tracked `path`, "" for the root.
fn directory(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// The directories, other than the root, that hold a lockfile among
/// `tracked`.
fn lockfile_dirs<'a>(tracked: &[&'a str]) -> BTreeSet<&'a str> {
    tracked
        .iter()
        .filter(|p| is_lockfile(p))
        .map(|p| directory(p))
        .filter(|d| !d.is_empty())
        .collect()
}

/// What is wrong with the copies of the root configuration, given the
/// `tracked` files (as `git ls-files` lists them) and `read`, which gives a
/// tracked file's bytes. Each problem names the command that fixes it.
fn copy_problems(tracked: &[&str], read: &dyn Fn(&str) -> Option<Vec<u8>>) -> Vec<String> {
    let mut out = Vec::new();
    if !tracked.contains(&CONFIG) {
        out.push(format!("no tracked {CONFIG} at the root"));
        return out;
    }
    let Some(root_bytes) = read(CONFIG) else {
        out.push(format!("the root {CONFIG} cannot be read"));
        return out;
    };
    let dirs = lockfile_dirs(tracked);
    for dir in &dirs {
        let copy = format!("{dir}/{CONFIG}");
        if !tracked.contains(&copy.as_str()) {
            out.push(format!(
                "{dir}/ holds a lockfile but no tracked {CONFIG}: run `cp {CONFIG} {copy} && git add {copy}`"
            ));
            continue;
        }
        match read(&copy) {
            None => out.push(format!("{copy} cannot be read")),
            Some(bytes) if bytes != root_bytes => out.push(format!(
                "{copy} differs from the root {CONFIG}: edit the root file, then run `cp {CONFIG} {copy}`"
            )),
            Some(_) => {}
        }
    }
    for path in tracked {
        let dir = directory(path);
        let is_copy = !dir.is_empty() && path.rsplit('/').next() == Some(CONFIG);
        if is_copy && !dirs.contains(dir) {
            out.push(format!(
                "{path} stands where no lockfile is: run `git rm {path}`"
            ));
        }
    }
    out
}

/// What is wrong with the OSV workflow `text`: it must scan recursively and
/// must not pass a configuration file, so it reads the copy beside each
/// lockfile as Scorecard does. Comment lines do not count.
fn workflow_problems(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut recursive = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for token in line.split_whitespace() {
            let flag = token.trim_start_matches('-');
            let dashes = token.len() - flag.len();
            if !(1..=2).contains(&dashes) {
                continue;
            }
            let name = flag.split('=').next().unwrap_or(flag);
            if name == "config" {
                out.push(format!(
                    "`{token}` applies one file to every lockfile; Scorecard reads the copy beside each, so the workflow must too"
                ));
            }
            if name == "recursive" || (dashes == 1 && name == "r") {
                recursive = true;
            }
        }
    }
    if !recursive {
        out.push(
            "no `--recursive`: the scan must read every lockfile, as Scorecard's does".to_owned(),
        );
    }
    out
}

/// The files git tracks in this repository, as `git ls-files` lists them.
fn tracked_files() -> Result<Vec<String>, TestError> {
    tracked::ls_files(repo(), &[])
}

/// A `read` for unit tests: every path in `files` has its text, others none.
fn reader(files: &[(&str, &str)]) -> impl Fn(&str) -> Option<Vec<u8>> + use<> {
    let files: Vec<(String, Vec<u8>)> = files
        .iter()
        .map(|(p, t)| ((*p).to_owned(), t.as_bytes().to_vec()))
        .collect();
    move |path: &str| {
        files
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, t)| t.clone())
    }
}

const ROOT_TEXT: &str = "[[IgnoredVulns]]\nid = \"RUSTSEC-2026-0543\"\n";

/// A workflow step in the shape of the real one, with `extra` scan arguments.
fn step(extra: &str) -> String {
    format!(
        "      - name: Scan every lockfile\n        uses: google/osv-scanner-action/osv-scanner-action@0 # v2.7.0\n        with:\n          scan-args: |-\n            --format=sarif\n{extra}            --recursive\n            ./\n"
    )
}

// ---- The repository ------------------------------------------------------

#[test]
fn every_lockfile_has_the_root_configuration_beside_it() -> Result<(), TestError> {
    let tracked = tracked_files()?;
    let tracked: Vec<&str> = tracked.iter().map(String::as_str).collect();
    let read = |p: &str| std::fs::read(repo().join(p)).ok();
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "Scorecard reads {CONFIG} only beside each lockfile:\n{}",
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn the_workflow_reads_the_configuration_beside_each_lockfile() -> Result<(), TestError> {
    let text = std::fs::read_to_string(repo().join(WORKFLOW))?;
    let problems = workflow_problems(&text);
    assert!(
        problems.is_empty(),
        "{WORKFLOW} must scan as Scorecard does:\n{}",
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn the_repository_has_lockfiles_outside_the_root() -> Result<(), TestError> {
    let tracked = tracked_files()?;
    let tracked: Vec<&str> = tracked.iter().map(String::as_str).collect();
    let dirs = lockfile_dirs(&tracked);
    assert!(
        dirs.contains("fuzz"),
        "fuzz/Cargo.lock is the lockfile Scorecard reported; the rule must see it, found {dirs:?}"
    );
    assert!(
        dirs.len() >= 2,
        "the copy rule is only meaningful with lockfiles outside the root, found {dirs:?}"
    );
    Ok(())
}

#[test]
fn every_file_osv_scanner_read_on_main_is_a_lockfile() {
    for path in SCANNED_ON_MAIN {
        assert!(
            is_lockfile(path),
            "osv-scanner 2.7.0 read {path} on main, so the rule must count it as a lockfile"
        );
    }
}

#[test]
fn every_file_osv_scanner_read_on_main_is_still_tracked() -> Result<(), TestError> {
    let tracked = tracked_files()?;
    for path in SCANNED_ON_MAIN {
        assert!(
            tracked.iter().any(|t| t == path),
            "{path} is gone; re-run osv-scanner and update SCANNED_ON_MAIN"
        );
    }
    Ok(())
}

#[test]
fn no_tracked_dockerfile_counts_as_a_lockfile() -> Result<(), TestError> {
    let tracked = tracked_files()?;
    let dockerfiles: Vec<&String> = tracked
        .iter()
        .filter(|p| p.contains("Dockerfile"))
        .collect();
    assert!(
        !dockerfiles.is_empty(),
        "the repository has Dockerfiles; this test needs one to check"
    );
    for path in dockerfiles {
        assert!(
            !is_lockfile(path),
            "osv-scanner 2.7.0 did not read {path}, so it needs no copy"
        );
    }
    Ok(())
}

#[test]
fn the_root_configuration_still_accepts_chrono() -> Result<(), TestError> {
    let text = std::fs::read_to_string(repo().join(CONFIG))?;
    assert!(
        text.contains("id = \"RUSTSEC-2026-0543\""),
        "the copies exist to carry the chrono decision of 2026-11-17 to every lockfile"
    );
    Ok(())
}

// ---- Copies: success -------------------------------------------------------

#[test]
fn a_root_lockfile_alone_needs_no_copy() {
    let tracked = ["Cargo.lock", CONFIG];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert!(
        problems.is_empty(),
        "the root file covers the root lockfile: {problems:?}"
    );
}

#[test]
fn a_copy_beside_a_nested_lockfile_passes() {
    let tracked = [
        "Cargo.lock",
        CONFIG,
        "fuzz/Cargo.lock",
        "fuzz/osv-scanner.toml",
    ];
    let read = reader(&[(CONFIG, ROOT_TEXT), ("fuzz/osv-scanner.toml", ROOT_TEXT)]);
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "an equal copy beside fuzz/Cargo.lock passes: {problems:?}"
    );
}

#[test]
fn copies_beside_every_kind_of_lockfile_pass() {
    let tracked = [
        CONFIG,
        "bpf/Cargo.lock",
        "bpf/osv-scanner.toml",
        "clients/go/go.mod",
        "clients/go/osv-scanner.toml",
        "e2e/package-lock.json",
        "e2e/osv-scanner.toml",
        "scripts/requirements-yang.txt",
        "scripts/osv-scanner.toml",
    ];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "equal copies beside four ecosystems pass: {problems:?}"
    );
}

#[test]
fn two_lockfiles_in_one_directory_share_one_copy() {
    let tracked = [
        CONFIG,
        "clients/python/requirements-mcp.txt",
        "clients/python/requirements-test.txt",
        "clients/python/osv-scanner.toml",
    ];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "one copy serves a whole directory: {problems:?}"
    );
}

#[test]
fn a_root_configuration_without_a_root_lockfile_passes() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "the root file is the source even with no root lockfile: {problems:?}"
    );
}

#[test]
fn an_empty_root_configuration_copied_exactly_passes() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let read = |_: &str| Some(Vec::new());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "two empty files are byte-identical: {problems:?}"
    );
}

#[test]
fn files_that_are_not_lockfiles_need_no_copy() {
    let tracked = [
        CONFIG,
        "src/main.rs",
        "docs/index.md",
        "Dockerfile",
        "bpf/Cargo.toml",
    ];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert!(
        problems.is_empty(),
        "only lockfiles need a copy: {problems:?}"
    );
}

#[test]
fn the_repository_shape_with_all_copies_passes() {
    let mut tracked: Vec<String> = SCANNED_ON_MAIN.iter().map(|s| (*s).to_owned()).collect();
    tracked.push(CONFIG.to_owned());
    for dir in [
        "bpf",
        "clients/go",
        "clients/python",
        "clients/typescript",
        "e2e",
        "fuzz",
        "scripts",
    ] {
        tracked.push(format!("{dir}/{CONFIG}"));
    }
    let tracked: Vec<&str> = tracked.iter().map(String::as_str).collect();
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems.is_empty(),
        "the seven copies cover all eleven files: {problems:?}"
    );
}

// ---- Copies: failure -------------------------------------------------------

#[test]
fn main_before_the_fix_is_refused() {
    let mut tracked: Vec<&str> = SCANNED_ON_MAIN.to_vec();
    tracked.push(CONFIG);
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert_eq!(
        problems.len(),
        7,
        "main 2062140b1 had seven lockfile directories without a copy: {problems:?}"
    );
}

#[test]
fn a_lockfile_without_a_copy_beside_it_is_refused() {
    let tracked = [CONFIG, "Cargo.lock", "fuzz/Cargo.lock"];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert_eq!(problems.len(), 1, "fuzz/ lacks a copy: {problems:?}");
    assert!(
        problems[0].starts_with("fuzz/ holds a lockfile"),
        "the problem names fuzz/: {problems:?}"
    );
}

#[test]
fn the_missing_copy_problem_names_its_fix() {
    let tracked = [CONFIG, "fuzz/Cargo.lock"];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert!(
        problems.iter().any(|p| p.contains(
            "`cp osv-scanner.toml fuzz/osv-scanner.toml && git add fuzz/osv-scanner.toml`"
        )),
        "the problem gives the command that fixes it: {problems:?}"
    );
}

#[test]
fn each_directory_without_a_copy_is_named_once() {
    let tracked = [
        CONFIG,
        "clients/python/requirements-mcp.txt",
        "clients/python/requirements-test.txt",
        "e2e/package-lock.json",
    ];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert_eq!(
        problems.len(),
        2,
        "two directories, two problems: {problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.starts_with("clients/python/")),
        "clients/python/ is named: {problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.starts_with("e2e/")),
        "e2e/ is named: {problems:?}"
    );
}

#[test]
fn a_copy_that_differs_from_the_root_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let read = reader(&[
        (CONFIG, ROOT_TEXT),
        ("fuzz/osv-scanner.toml", "[[IgnoredVulns]]\n"),
    ]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        1,
        "the differing copy is refused: {problems:?}"
    );
    assert!(
        problems[0].contains("differs from the root"),
        "the problem says why: {problems:?}"
    );
}

#[test]
fn a_copy_with_an_extra_ignore_is_refused() {
    let tracked = [CONFIG, "e2e/package-lock.json", "e2e/osv-scanner.toml"];
    let more = format!("{ROOT_TEXT}[[IgnoredVulns]]\nid = \"GHSA-0000-0000-0000\"\n");
    let read = reader(&[(CONFIG, ROOT_TEXT), ("e2e/osv-scanner.toml", &more)]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        1,
        "a copy cannot accept more than the root does: {problems:?}"
    );
}

#[test]
fn a_copy_on_disk_that_git_does_not_track_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        1,
        "an untracked copy is not in the scanned tree: {problems:?}"
    );
}

#[test]
fn a_tracked_copy_that_cannot_be_read_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert_eq!(
        problems,
        vec!["fuzz/osv-scanner.toml cannot be read".to_owned()],
        "unreadable copy"
    );
}

#[test]
fn a_copy_where_no_lockfile_is_is_refused() {
    let tracked = [CONFIG, "Cargo.lock", "docs/osv-scanner.toml"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems,
        vec![
            "docs/osv-scanner.toml stands where no lockfile is: run `git rm docs/osv-scanner.toml`"
                .to_owned()
        ],
        "a stale copy is refused with its fix"
    );
}

#[test]
fn a_missing_root_configuration_is_refused() {
    let tracked = ["Cargo.lock", "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems,
        vec![format!("no tracked {CONFIG} at the root")],
        "the root file is the source"
    );
}

#[test]
fn an_unreadable_root_configuration_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let read = reader(&[("fuzz/osv-scanner.toml", ROOT_TEXT)]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems,
        vec![format!("the root {CONFIG} cannot be read")],
        "no source, no comparison"
    );
}

#[test]
fn a_copy_in_a_parent_directory_does_not_cover_a_deeper_lockfile() {
    let tracked = [CONFIG, "clients/osv-scanner.toml", "clients/go/go.mod"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        2,
        "clients/go needs its own copy and clients/ has none to cover: {problems:?}"
    );
}

// ---- Copies: edge ----------------------------------------------------------

#[test]
fn a_copy_that_differs_only_in_its_last_newline_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let trimmed = ROOT_TEXT.trim_end();
    let read = reader(&[(CONFIG, ROOT_TEXT), ("fuzz/osv-scanner.toml", trimmed)]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        1,
        "byte-identical means the newline too: {problems:?}"
    );
}

#[test]
fn a_copy_of_the_same_length_with_one_byte_changed_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let changed = ROOT_TEXT.replace("0543", "0544");
    assert_eq!(
        changed.len(),
        ROOT_TEXT.len(),
        "the fixture keeps the length"
    );
    let read = reader(&[(CONFIG, ROOT_TEXT), ("fuzz/osv-scanner.toml", &changed)]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(
        problems.len(),
        1,
        "a copy that accepts another advisory differs: {problems:?}"
    );
}

#[test]
fn a_copy_with_crlf_line_ends_is_refused() {
    let tracked = [CONFIG, "fuzz/Cargo.lock", "fuzz/osv-scanner.toml"];
    let crlf = ROOT_TEXT.replace('\n', "\r\n");
    let read = reader(&[(CONFIG, ROOT_TEXT), ("fuzz/osv-scanner.toml", &crlf)]);
    let problems = copy_problems(&tracked, &read);
    assert_eq!(problems.len(), 1, "line ends are bytes too: {problems:?}");
}

#[test]
fn a_deep_directory_needs_its_own_copy() {
    let tracked = [CONFIG, "a/b/c/Cargo.lock", "a/osv-scanner.toml"];
    let read = |_: &str| Some(ROOT_TEXT.as_bytes().to_vec());
    let problems = copy_problems(&tracked, &read);
    assert!(
        problems
            .iter()
            .any(|p| p.starts_with("a/b/c/ holds a lockfile")),
        "a/b/c needs its own copy: {problems:?}"
    );
}

#[test]
fn a_file_named_like_the_configuration_inside_its_name_is_not_a_copy() {
    let tracked = [
        CONFIG,
        "docs/osv-scanner.toml.md",
        "docs/old-osv-scanner.toml",
    ];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    assert!(
        problems.is_empty(),
        "only a file named exactly {CONFIG} is a copy: {problems:?}"
    );
}

#[test]
fn the_root_directory_is_the_empty_path() {
    assert_eq!(directory("Cargo.lock"), "", "a root path has no directory");
    assert_eq!(directory("fuzz/Cargo.lock"), "fuzz", "one level");
    assert_eq!(directory("clients/go/go.mod"), "clients/go", "two levels");
}

#[test]
fn an_empty_tree_reports_the_missing_root() {
    let problems = copy_problems(&[], &|_| None);
    assert_eq!(
        problems.len(),
        1,
        "an empty tree has no source file: {problems:?}"
    );
}

#[test]
fn problems_come_in_directory_order() {
    let tracked = [CONFIG, "zeta/Cargo.lock", "alpha/Cargo.lock", "mid/go.mod"];
    let problems = copy_problems(&tracked, &reader(&[(CONFIG, ROOT_TEXT)]));
    let firsts: Vec<&str> = problems
        .iter()
        .map(|p| p.split('/').next().unwrap_or(""))
        .collect();
    assert_eq!(
        firsts,
        ["alpha", "mid", "zeta"],
        "a stable order keeps the message readable"
    );
}

#[test]
fn lockfile_dirs_leave_out_the_root() {
    let dirs = lockfile_dirs(&["Cargo.lock", "fuzz/Cargo.lock"]);
    assert_eq!(
        dirs.into_iter().collect::<Vec<_>>(),
        ["fuzz"],
        "the root is the source, not a copy"
    );
}

// ---- Lockfile names --------------------------------------------------------

#[test]
fn cargo_npm_and_go_manifests_are_lockfiles() {
    for path in [
        "Cargo.lock",
        "a/package-lock.json",
        "a/npm-shrinkwrap.json",
        "go.mod",
        "a/yarn.lock",
        "a/pnpm-lock.yaml",
    ] {
        assert!(is_lockfile(path), "osv-scanner reads {path}");
    }
}

#[test]
fn python_ruby_and_php_lockfiles_are_lockfiles() {
    for path in [
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
        "Gemfile.lock",
        "composer.lock",
    ] {
        assert!(is_lockfile(path), "osv-scanner reads {path}");
    }
}

#[test]
fn any_requirements_text_file_is_a_lockfile() {
    for path in [
        "requirements.txt",
        "scripts/requirements-yang.txt",
        "dev-requirements.txt",
    ] {
        assert!(
            is_lockfile(path),
            "osv-scanner's Python extractor reads {path}"
        );
    }
}

#[test]
fn names_that_only_look_like_lockfiles_are_not_lockfiles() {
    for path in [
        "Cargo.lock.orig",
        "Cargo.toml",
        "notCargo.lock",
        "go.sum",
        "package.json",
        "requirements.md",
        "requirements/notes.txt",
        "docs/Cargo.lock.md",
    ] {
        assert!(
            !is_lockfile(path),
            "osv-scanner does not read {path} as a lockfile"
        );
    }
}

#[test]
fn a_lockfile_name_is_case_sensitive() {
    assert!(
        !is_lockfile("cargo.lock"),
        "the Cargo extractor matches Cargo.lock exactly"
    );
    assert!(
        !is_lockfile("GO.MOD"),
        "the Go extractor matches go.mod exactly"
    );
}

// ---- Workflow: success -----------------------------------------------------

#[test]
fn a_recursive_scan_without_a_configuration_passes() {
    let problems = workflow_problems(&step(""));
    assert!(
        problems.is_empty(),
        "the shape the fix leaves: {problems:?}"
    );
}

#[test]
fn naming_each_lockfile_as_well_passes() {
    let problems = workflow_problems(&step(
        "            --lockfile=./Cargo.lock\n            --lockfile=./fuzz/Cargo.lock\n",
    ));
    assert!(
        problems.is_empty(),
        "--lockfile reads the copy beside the file: {problems:?}"
    );
}

#[test]
fn a_comment_that_names_the_option_is_not_the_option() {
    let text = format!(
        "# The job used to pass --config=osv-scanner.toml.\n{}",
        step("")
    );
    let problems = workflow_problems(&text);
    assert!(
        problems.is_empty(),
        "a comment line is not an argument: {problems:?}"
    );
}

#[test]
fn the_short_recursive_flag_passes() {
    let text = "scan-args: -r ./\n";
    let problems = workflow_problems(text);
    assert!(problems.is_empty(), "-r is --recursive: {problems:?}");
}

#[test]
fn an_option_that_only_starts_like_config_is_not_config() {
    let problems = workflow_problems(&step("            --configuration-note=x\n"));
    assert!(
        problems.is_empty(),
        "only the config flag is refused: {problems:?}"
    );
}

#[test]
fn a_path_that_holds_the_word_config_is_not_the_option() {
    let problems = workflow_problems(&step("            --lockfile=./config/Cargo.lock\n"));
    assert!(problems.is_empty(), "a path is not a flag: {problems:?}");
}

// ---- Workflow: failure -----------------------------------------------------

#[test]
fn main_before_the_fix_is_refused_by_the_workflow_rule() {
    let problems = workflow_problems(&step("            --config=osv-scanner.toml\n"));
    assert_eq!(
        problems.len(),
        1,
        "main 2062140b1 passed --config: {problems:?}"
    );
    assert!(
        problems[0].contains("--config=osv-scanner.toml"),
        "the problem quotes the argument: {problems:?}"
    );
}

#[test]
fn a_config_option_with_a_space_is_refused() {
    let problems = workflow_problems(&step("            --config osv-scanner.toml\n"));
    assert_eq!(
        problems.len(),
        1,
        "the spaced form is the same option: {problems:?}"
    );
}

#[test]
fn a_single_dash_config_option_is_refused() {
    let problems = workflow_problems(&step("            -config=osv-scanner.toml\n"));
    assert_eq!(problems.len(), 1, "Go flags accept one dash: {problems:?}");
}

#[test]
fn a_config_option_on_the_scan_args_line_is_refused() {
    let text = "scan-args: --config=osv-scanner.toml --recursive ./\n";
    let problems = workflow_problems(text);
    assert_eq!(problems.len(), 1, "an inline argument counts: {problems:?}");
}

#[test]
fn a_scan_that_does_not_recurse_is_refused() {
    let text = "scan-args: |-\n  --lockfile=./Cargo.lock\n";
    let problems = workflow_problems(text);
    assert_eq!(
        problems.len(),
        1,
        "a scan of one lockfile misses the rest: {problems:?}"
    );
    assert!(
        problems[0].contains("--recursive"),
        "the problem names the flag: {problems:?}"
    );
}

#[test]
fn a_recursive_flag_only_in_a_comment_does_not_count() {
    let text = "# --recursive\nscan-args: --lockfile=./Cargo.lock\n";
    let problems = workflow_problems(text);
    assert_eq!(
        problems.len(),
        1,
        "a commented flag is not passed: {problems:?}"
    );
}

#[test]
fn a_config_option_and_no_recursion_are_both_named() {
    let text = "scan-args: --config=osv-scanner.toml ./\n";
    let problems = workflow_problems(text);
    assert_eq!(problems.len(), 2, "both faults are reported: {problems:?}");
}

// ---- Workflow: edge --------------------------------------------------------

#[test]
fn an_empty_workflow_is_refused_for_not_recursing() {
    let problems = workflow_problems("");
    assert_eq!(
        problems.len(),
        1,
        "no scan at all is no recursive scan: {problems:?}"
    );
}

#[test]
fn three_dashes_are_not_an_option() {
    let problems = workflow_problems(&step("            ---config=x\n"));
    assert!(
        problems.is_empty(),
        "osv-scanner rejects three dashes; it is not the option: {problems:?}"
    );
}

#[test]
fn an_indented_comment_line_is_still_a_comment() {
    let text = format!("        # --config=osv-scanner.toml\n{}", step(""));
    let problems = workflow_problems(&text);
    assert!(
        problems.is_empty(),
        "leading spaces do not make a comment an argument: {problems:?}"
    );
}

#[test]
fn a_bare_config_flag_with_no_value_is_refused() {
    let problems = workflow_problems(&step("            --config\n"));
    assert_eq!(
        problems.len(),
        1,
        "the flag alone is still the flag: {problems:?}"
    );
}

#[test]
fn the_repository_workflow_file_exists_and_names_the_action() -> Result<(), TestError> {
    let path: &Path = &repo().join(WORKFLOW);
    let text = std::fs::read_to_string(path)?;
    assert!(
        text.contains("google/osv-scanner-action/osv-scanner-action@"),
        "{WORKFLOW} no longer runs osv-scanner, so this rule checks nothing"
    );
    Ok(())
}

// ==== Every ignore matches a package a tracked lockfile holds ==============
//
// An ignore that matches nothing hides the next advisory filed under the same
// ID and keeps a stale reason in three files. GHSA-hp3w-g68c-fv3c (sprintf-js)
// stayed in osv-scanner.toml after #685 (3578a3bca) took sprintf-js out of
// e2e/package-lock.json; osv.dev withdrew the advisory on 2026-10-22.
//
// Whether an advisory is withdrawn needs the network, so this rule does not
// decide it. What it decides offline: the VEX statement of each ignore names
// the affected package as an OpenVEX subcomponent purl
// (`products[].subcomponents[]."@id"`, e.g. `pkg:cargo/chrono`), and a tracked
// lockfile of that ecosystem holds that package. That every ignore has a VEX
// statement and every statement an ignore is tests/vex_document_test.rs's
// rule; this one adds the package.

/// The VEX document that states each accepted advisory.
const VEX: &str = "vex/sipnab.openvex.json";

/// The ecosystem and name of an OpenVEX subcomponent purl,
/// `pkg:<type>/<name>[@version][?qualifiers][#subpath]`, with a scoped npm
/// name's `%40` decoded to `@`.
fn purl_package(purl: &str) -> Option<(String, String)> {
    let rest = purl.strip_prefix("pkg:")?;
    let (kind, path) = rest.split_once('/')?;
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let name = match path.rsplit_once('@') {
        Some((name, _version)) if !name.is_empty() => name,
        _ => path,
    };
    let name = name.replace("%40", "@");
    if kind.is_empty() || name.is_empty() {
        return None;
    }
    Some((kind.to_owned(), name))
}

/// A Python package name in its normalized form (PEP 503).
fn python_name(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Whether the lockfile at `path`, whose text is `text`, holds the package
/// `name` of the purl type `kind`.
fn lockfile_holds(path: &str, text: &str, kind: &str, name: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    match kind {
        "cargo" => {
            file == "Cargo.lock"
                && text
                    .lines()
                    .any(|l| l.trim() == format!("name = \"{name}\""))
        }
        "npm" => {
            if file != "package-lock.json" && file != "npm-shrinkwrap.json" {
                return false;
            }
            let Ok(doc) = serde_json::from_str::<serde_json::Value>(text) else {
                return false;
            };
            let direct = format!("node_modules/{name}");
            let nested = format!("/node_modules/{name}");
            doc["packages"].as_object().is_some_and(|packages| {
                packages
                    .keys()
                    .any(|k| *k == direct || k.ends_with(&nested))
            })
        }
        "pypi" => {
            if !(file.ends_with(".txt") && file.contains("requirements")) {
                return false;
            }
            let want = python_name(name);
            text.lines().any(|line| {
                let line = line.split('#').next().unwrap_or("").trim();
                let end = line
                    .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
                    .unwrap_or(line.len());
                !line.is_empty() && python_name(&line[..end]) == want
            })
        }
        "golang" => {
            file == "go.mod"
                && text.lines().any(|line| {
                    let line = line.trim();
                    !line.starts_with("module ") && line.split_whitespace().any(|t| t == name)
                })
        }
        _ => false,
    }
}

/// What is wrong with the ignores of the OSV configuration `config`, given
/// the VEX document `vex` and the tracked `lockfiles` as (path, text).
fn ignore_problems(
    config: &str,
    vex: &serde_json::Value,
    lockfiles: &[(&str, &str)],
) -> Vec<String> {
    let table: toml::Table = match config.parse() {
        Ok(t) => t,
        Err(e) => return vec![format!("{CONFIG} is not TOML: {e}")],
    };
    let ignores = table
        .get("IgnoredVulns")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let statements = vex["statements"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for ignore in &ignores {
        let Some(id) = ignore.get("id").and_then(toml::Value::as_str) else {
            out.push(format!("an [[IgnoredVulns]] entry of {CONFIG} has no id"));
            continue;
        };
        let Some(statement) = statements
            .iter()
            .find(|s| s["vulnerability"]["name"].as_str() == Some(id))
        else {
            out.push(format!("{id}: no statement in {VEX} backs this ignore"));
            continue;
        };
        let purls: Vec<&str> = statement["products"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| p["subcomponents"].as_array().into_iter().flatten())
            .filter_map(|c| c["@id"].as_str())
            .collect();
        if purls.is_empty() {
            out.push(format!(
                "{id}: its {VEX} statement names no package; add the affected one as products[].subcomponents[].\"@id\", a purl such as pkg:cargo/chrono"
            ));
            continue;
        }
        let mut held = false;
        for purl in &purls {
            let Some((kind, name)) = purl_package(purl) else {
                out.push(format!("{id}: `{purl}` is not a package purl"));
                held = true;
                continue;
            };
            if lockfiles
                .iter()
                .any(|(path, text)| lockfile_holds(path, text, &kind, &name))
            {
                held = true;
            }
        }
        if !held {
            out.push(format!(
                "{id}: no tracked lockfile holds {}; the ignore matches nothing: remove it from {CONFIG} and its copies, and its statement from {VEX}",
                purls.join(", ")
            ));
        }
    }
    out
}

/// A VEX document with one statement per (advisory, purls).
fn vex_doc(statements: &[(&str, &[&str])]) -> serde_json::Value {
    let statements: Vec<serde_json::Value> = statements
        .iter()
        .map(|(id, purls)| {
            let subs: Vec<serde_json::Value> = purls
                .iter()
                .map(|p| serde_json::json!({ "@id": p }))
                .collect();
            serde_json::json!({
                "vulnerability": { "name": id },
                "products": [{ "@id": "pkg:cargo/sipnab", "subcomponents": subs }],
            })
        })
        .collect();
    serde_json::json!({ "statements": statements })
}

/// An OSV configuration that ignores each of `ids`.
fn config_of(ids: &[&str]) -> String {
    ids.iter()
        .map(|id| format!("[[IgnoredVulns]]\nid = \"{id}\"\nreason = \"r\"\n"))
        .collect()
}

const CHRONO_LOCK: &str = "[[package]]\nname = \"chrono\"\nversion = \"0.4.45\"\n";
const NPM_LOCK: &str = r#"{"packages": {"": {}, "node_modules/argparse": {}, "node_modules/@lhci/cli": {}, "node_modules/a/node_modules/js-yaml": {}}}"#;

// ---- Ignores: the repository ----------------------------------------------

#[test]
fn every_ignore_matches_a_package_a_tracked_lockfile_holds() -> Result<(), TestError> {
    let config = std::fs::read_to_string(repo().join(CONFIG))?;
    let vex: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(repo().join(VEX))?)?;
    let tracked = tracked_files()?;
    let mut lockfiles = Vec::new();
    for path in tracked.iter().filter(|p| is_lockfile(p)) {
        lockfiles.push((path.clone(), std::fs::read_to_string(repo().join(path))?));
    }
    let lockfiles: Vec<(&str, &str)> = lockfiles
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let problems = ignore_problems(&config, &vex, &lockfiles);
    assert!(
        problems.is_empty(),
        "an ignore must match a package a tracked lockfile holds:\n{}",
        problems.join("\n")
    );
    Ok(())
}

#[test]
fn the_chrono_statement_names_chrono() -> Result<(), TestError> {
    let vex = std::fs::read_to_string(repo().join(VEX))?;
    assert!(
        vex.contains("\"@id\": \"pkg:cargo/chrono\""),
        "the RUSTSEC-2026-0543 statement names pkg:cargo/chrono as its subcomponent"
    );
    Ok(())
}

// ---- Ignores: success ------------------------------------------------------

#[test]
fn a_cargo_package_in_a_cargo_lock_passes() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert!(problems.is_empty(), "chrono is in Cargo.lock: {problems:?}");
}

#[test]
fn a_package_held_only_by_a_nested_lockfile_passes() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono"])]);
    let locks = [
        ("Cargo.lock", "[[package]]\nname = \"libc\"\n"),
        ("fuzz/Cargo.lock", CHRONO_LOCK),
    ];
    let problems = ignore_problems(&config_of(&["RUSTSEC-2026-0543"]), &vex, &locks);
    assert!(
        problems.is_empty(),
        "fuzz/Cargo.lock holds chrono: {problems:?}"
    );
}

#[test]
fn an_npm_package_in_a_package_lock_passes() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:npm/argparse"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("e2e/package-lock.json", NPM_LOCK)],
    );
    assert!(problems.is_empty(), "argparse is in the lock: {problems:?}");
}

#[test]
fn a_nested_npm_package_passes() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:npm/js-yaml"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("e2e/package-lock.json", NPM_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "a package under another's node_modules counts: {problems:?}"
    );
}

#[test]
fn a_scoped_npm_purl_passes() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:npm/%40lhci/cli@0.16.0"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("e2e/package-lock.json", NPM_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "%40lhci/cli is @lhci/cli: {problems:?}"
    );
}

#[test]
fn a_python_package_in_a_requirements_file_passes() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:pypi/codespell"])]);
    let locks = [("scripts/requirements-codespell.txt", "codespell==2.4.1\n")];
    let problems = ignore_problems(&config_of(&["GHSA-aaaa-bbbb-cccc"]), &vex, &locks);
    assert!(problems.is_empty(), "codespell is pinned: {problems:?}");
}

#[test]
fn a_python_name_matches_in_normalized_form() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:pypi/foo-bar"])]);
    let locks = [("requirements.txt", "Foo_Bar==1.0\n")];
    let problems = ignore_problems(&config_of(&["GHSA-aaaa-bbbb-cccc"]), &vex, &locks);
    assert!(
        problems.is_empty(),
        "PEP 503 names compare normalized: {problems:?}"
    );
}

#[test]
fn a_go_module_in_a_go_mod_passes() {
    let vex = vex_doc(&[("GO-2026-0001", &["pkg:golang/golang.org/x/net"])]);
    let locks = [(
        "clients/go/go.mod",
        "module example.com/c\n\nrequire golang.org/x/net v0.1.0\n",
    )];
    let problems = ignore_problems(&config_of(&["GO-2026-0001"]), &vex, &locks);
    assert!(problems.is_empty(), "the module is required: {problems:?}");
}

#[test]
fn a_purl_with_a_version_passes() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono@0.4.45"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "the version does not change the package: {problems:?}"
    );
}

#[test]
fn a_purl_with_qualifiers_passes() {
    let vex = vex_doc(&[(
        "RUSTSEC-2026-0543",
        &["pkg:cargo/chrono@0.4.45?repository_url=x#src"],
    )]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "qualifiers and subpath are not the name: {problems:?}"
    );
}

#[test]
fn one_held_package_of_two_is_enough() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/gone", "pkg:cargo/chrono"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "the ignore matches chrono: {problems:?}"
    );
}

#[test]
fn a_subcomponent_of_a_second_product_counts() {
    let vex = serde_json::json!({"statements": [{
        "vulnerability": {"name": "RUSTSEC-2026-0543"},
        "products": [{"@id": "pkg:cargo/a"}, {"@id": "pkg:cargo/b", "subcomponents": [{"@id": "pkg:cargo/chrono"}]}],
    }]});
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert!(
        problems.is_empty(),
        "every product's subcomponents count: {problems:?}"
    );
}

#[test]
fn a_configuration_with_no_ignore_passes() {
    let problems = ignore_problems("", &vex_doc(&[]), &[]);
    assert!(
        problems.is_empty(),
        "nothing ignored, nothing to match: {problems:?}"
    );
}

#[test]
fn two_held_ignores_pass() {
    let vex = vex_doc(&[
        ("RUSTSEC-2026-0543", &["pkg:cargo/chrono"]),
        ("GHSA-aaaa-bbbb-cccc", &["pkg:npm/argparse"]),
    ]);
    let locks = [
        ("Cargo.lock", CHRONO_LOCK),
        ("e2e/package-lock.json", NPM_LOCK),
    ];
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543", "GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &locks,
    );
    assert!(problems.is_empty(), "both packages are held: {problems:?}");
}

#[test]
fn an_ignore_with_a_review_date_passes() {
    let config =
        "[[IgnoredVulns]]\nid = \"RUSTSEC-2026-0543\"\nignoreUntil = 2027-02-15\nreason = \"r\"\n";
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono"])]);
    let problems = ignore_problems(config, &vex, &[("Cargo.lock", CHRONO_LOCK)]);
    assert!(problems.is_empty(), "a TOML date parses: {problems:?}");
}

// ---- Ignores: failure ------------------------------------------------------

#[test]
fn the_stale_sprintf_js_ignore_is_refused() {
    let vex = vex_doc(&[("GHSA-hp3w-g68c-fv3c", &["pkg:npm/sprintf-js"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-hp3w-g68c-fv3c"]),
        &vex,
        &[("e2e/package-lock.json", NPM_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "sprintf-js left e2e/ in #685: {problems:?}"
    );
    assert!(
        problems[0].contains("no tracked lockfile holds pkg:npm/sprintf-js"),
        "the problem names the package: {problems:?}"
    );
}

#[test]
fn the_stale_problem_names_its_fix() {
    let vex = vex_doc(&[("GHSA-hp3w-g68c-fv3c", &["pkg:npm/sprintf-js"])]);
    let problems = ignore_problems(&config_of(&["GHSA-hp3w-g68c-fv3c"]), &vex, &[]);
    assert!(
        problems.iter().any(|p| p.contains("remove it from osv-scanner.toml and its copies, and its statement from vex/sipnab.openvex.json")),
        "the problem says what to remove: {problems:?}"
    );
}

#[test]
fn an_ignore_without_a_vex_statement_is_refused() {
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex_doc(&[]),
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems,
        vec![format!(
            "RUSTSEC-2026-0543: no statement in {VEX} backs this ignore"
        )],
        "an ignore needs its statement"
    );
}

#[test]
fn a_statement_without_subcomponents_is_refused() {
    let vex = serde_json::json!({"statements": [{"vulnerability": {"name": "RUSTSEC-2026-0543"}, "products": [{"@id": "pkg:cargo/sipnab"}]}]});
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "the statement must name its package: {problems:?}"
    );
    assert!(
        problems[0].contains("names no package"),
        "the problem says why: {problems:?}"
    );
}

#[test]
fn an_empty_subcomponent_list_is_refused() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &[])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "an empty list names no package: {problems:?}"
    );
}

#[test]
fn a_cargo_package_no_lockfile_holds_is_refused() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", "[[package]]\nname = \"libc\"\n")],
    );
    assert_eq!(
        problems.len(),
        1,
        "chrono gone, the ignore is stale: {problems:?}"
    );
}

#[test]
fn the_ecosystem_must_match_the_lockfile() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:npm/chrono"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "an npm chrono is not the crate: {problems:?}"
    );
}

#[test]
fn a_python_package_no_requirements_file_holds_is_refused() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:pypi/requests"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("requirements.txt", "codespell==2.4.1\n")],
    );
    assert_eq!(problems.len(), 1, "requests is not pinned: {problems:?}");
}

#[test]
fn a_go_module_no_go_mod_holds_is_refused() {
    let vex = vex_doc(&[("GO-2026-0001", &["pkg:golang/golang.org/x/net"])]);
    let problems = ignore_problems(
        &config_of(&["GO-2026-0001"]),
        &vex,
        &[("go.mod", "module example.com/c\n")],
    );
    assert_eq!(
        problems.len(),
        1,
        "the module is not required: {problems:?}"
    );
}

#[test]
fn a_purl_that_is_not_a_package_is_refused() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["chrono"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems,
        vec!["RUSTSEC-2026-0543: `chrono` is not a package purl".to_owned()],
        "a bare name is no purl"
    );
}

#[test]
fn a_purl_type_no_lockfile_reads_is_refused() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:maven/org.example/lib"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "no tracked lockfile is a Maven one: {problems:?}"
    );
}

#[test]
fn a_configuration_that_is_not_toml_is_refused() {
    let problems = ignore_problems("[[IgnoredVulns]\nid =", &vex_doc(&[]), &[]);
    assert_eq!(problems.len(), 1, "a broken file is refused: {problems:?}");
    assert!(
        problems[0].contains("is not TOML"),
        "the problem says why: {problems:?}"
    );
}

#[test]
fn each_stale_ignore_is_named() {
    let vex = vex_doc(&[
        ("GHSA-aaaa-bbbb-cccc", &["pkg:npm/gone"]),
        ("RUSTSEC-2026-0001", &["pkg:cargo/gone"]),
    ]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc", "RUSTSEC-2026-0001"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        2,
        "both stale ignores are reported: {problems:?}"
    );
}

#[test]
fn an_npm_name_that_only_starts_the_same_is_refused() {
    let lock = r#"{"packages": {"node_modules/sprintf-js-extra": {}}}"#;
    let vex = vex_doc(&[("GHSA-hp3w-g68c-fv3c", &["pkg:npm/sprintf-js"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-hp3w-g68c-fv3c"]),
        &vex,
        &[("e2e/package-lock.json", lock)],
    );
    assert_eq!(
        problems.len(),
        1,
        "sprintf-js-extra is another package: {problems:?}"
    );
}

#[test]
fn an_ignore_without_an_id_is_refused() {
    let problems = ignore_problems("[[IgnoredVulns]]\nreason = \"r\"\n", &vex_doc(&[]), &[]);
    assert_eq!(
        problems.len(),
        1,
        "an entry must name its advisory: {problems:?}"
    );
}

// ---- Ignores: edge ---------------------------------------------------------

#[test]
fn a_cargo_name_that_only_starts_the_same_does_not_hold() {
    assert!(
        !lockfile_holds("Cargo.lock", "name = \"chrono-tz\"\n", "cargo", "chrono"),
        "chrono-tz is another crate"
    );
}

#[test]
fn a_cargo_dependency_line_is_not_a_package() {
    let lock = "[[package]]\nname = \"rmcp\"\ndependencies = [\n \"chrono\",\n]\n";
    assert!(
        !lockfile_holds("Cargo.lock", lock, "cargo", "chrono"),
        "only a name line is a package"
    );
}

#[test]
fn a_cargo_package_in_a_file_not_named_cargo_lock_does_not_hold() {
    assert!(
        !lockfile_holds("Cargo.toml", CHRONO_LOCK, "cargo", "chrono"),
        "only Cargo.lock is read"
    );
}

#[test]
fn a_package_lock_that_is_not_json_holds_nothing() {
    assert!(
        !lockfile_holds("package-lock.json", "{not json", "npm", "argparse"),
        "a broken lock holds nothing"
    );
}

#[test]
fn the_root_package_key_is_not_a_package() {
    assert!(
        !lockfile_holds("package-lock.json", NPM_LOCK, "npm", ""),
        "the empty key is the project itself"
    );
}

#[test]
fn an_npm_shrinkwrap_is_read_like_a_package_lock() {
    assert!(
        lockfile_holds("npm-shrinkwrap.json", NPM_LOCK, "npm", "argparse"),
        "both npm lock names are read"
    );
}

#[test]
fn a_python_comment_does_not_hold() {
    assert!(
        !lockfile_holds(
            "requirements.txt",
            "# requests is not used\n",
            "pypi",
            "requests"
        ),
        "a comment is no pin"
    );
}

#[test]
fn a_python_name_with_extras_holds() {
    assert!(
        lockfile_holds(
            "requirements.txt",
            "requests[socks]==2.0\n",
            "pypi",
            "requests"
        ),
        "extras follow the name"
    );
}

#[test]
fn a_python_name_with_a_marker_holds() {
    assert!(
        lockfile_holds(
            "requirements.txt",
            "requests==2.0 ; python_version >= \"3.9\"\n",
            "pypi",
            "requests"
        ),
        "a marker follows the pin"
    );
}

#[test]
fn a_python_name_that_only_starts_the_same_does_not_hold() {
    assert!(
        !lockfile_holds(
            "requirements.txt",
            "requests-oauthlib==1\n",
            "pypi",
            "requests"
        ),
        "another package"
    );
}

#[test]
fn the_module_line_of_a_go_mod_is_not_a_dependency() {
    assert!(
        !lockfile_holds(
            "go.mod",
            "module example.com/c\n",
            "golang",
            "example.com/c"
        ),
        "a module does not depend on itself"
    );
}

#[test]
fn a_purl_without_the_pkg_scheme_is_no_purl() {
    assert_eq!(
        purl_package("cargo/chrono"),
        None,
        "the pkg: scheme is required"
    );
    assert_eq!(
        purl_package("pkg:cargo"),
        None,
        "a type alone names no package"
    );
    assert_eq!(
        purl_package("pkg:/chrono"),
        None,
        "a name alone has no type"
    );
}

#[test]
fn a_purl_gives_its_type_and_name() {
    assert_eq!(
        purl_package("pkg:cargo/chrono@0.4.45"),
        Some(("cargo".into(), "chrono".into())),
        "version dropped"
    );
    assert_eq!(
        purl_package("pkg:npm/%40lhci/cli"),
        Some(("npm".into(), "@lhci/cli".into())),
        "scope decoded"
    );
    assert_eq!(
        purl_package("pkg:npm/%40lhci/cli@1"),
        Some(("npm".into(), "@lhci/cli".into())),
        "scope and version"
    );
}

#[test]
fn a_statement_is_matched_by_its_exact_advisory() {
    let vex = vex_doc(&[("RUSTSEC-2026-054", &["pkg:cargo/chrono"])]);
    let problems = ignore_problems(
        &config_of(&["RUSTSEC-2026-0543"]),
        &vex,
        &[("Cargo.lock", CHRONO_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "a prefix of the ID is another advisory: {problems:?}"
    );
}

#[test]
fn with_no_lockfile_every_ignore_is_stale() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/chrono"])]);
    let problems = ignore_problems(&config_of(&["RUSTSEC-2026-0543"]), &vex, &[]);
    assert_eq!(problems.len(), 1, "nothing holds chrono: {problems:?}");
}

#[test]
fn a_python_name_with_dots_matches_its_dashed_form() {
    assert!(
        lockfile_holds(
            "requirements.txt",
            "zope.interface==6\n",
            "pypi",
            "zope-interface"
        ),
        "PEP 503 maps dots to dashes"
    );
}

#[test]
fn a_go_module_with_a_longer_path_is_refused() {
    let vex = vex_doc(&[("GO-2026-0001", &["pkg:golang/golang.org/x/net"])]);
    let locks = [(
        "go.mod",
        "module example.com/c\nrequire golang.org/x/net2 v0.1.0\n",
    )];
    let problems = ignore_problems(&config_of(&["GO-2026-0001"]), &vex, &locks);
    assert_eq!(problems.len(), 1, "x/net2 is another module: {problems:?}");
}

#[test]
fn an_npm_package_named_only_in_a_package_json_is_refused() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:npm/argparse"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("e2e/package.json", NPM_LOCK)],
    );
    assert_eq!(
        problems.len(),
        1,
        "osv-scanner reads the lock, not the manifest: {problems:?}"
    );
}

#[test]
fn a_python_pin_in_a_file_that_is_not_text_is_refused() {
    let vex = vex_doc(&[("GHSA-aaaa-bbbb-cccc", &["pkg:pypi/codespell"])]);
    let problems = ignore_problems(
        &config_of(&["GHSA-aaaa-bbbb-cccc"]),
        &vex,
        &[("requirements.in", "codespell==2\n")],
    );
    assert_eq!(
        problems.len(),
        1,
        "osv-scanner reads requirements .txt files: {problems:?}"
    );
}

#[test]
fn a_purl_with_an_empty_version_keeps_its_name() {
    assert_eq!(
        purl_package("pkg:cargo/chrono@"),
        Some(("cargo".into(), "chrono".into())),
        "an empty version"
    );
}

#[test]
fn a_statement_with_no_ignore_is_left_to_the_vex_test() {
    let vex = vex_doc(&[("RUSTSEC-2026-0543", &["pkg:cargo/gone"])]);
    let problems = ignore_problems("", &vex, &[]);
    assert!(
        problems.is_empty(),
        "tests/vex_document_test.rs pairs statements with ignores: {problems:?}"
    );
}
