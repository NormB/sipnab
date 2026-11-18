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
