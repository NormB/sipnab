// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The Sanitizers workflow runs on push for every file its run step compiles.
//!
//! SANITIZERS-PATH-FILTER-SKIPS-COVERED-TESTS: `.github/workflows/sanitizers.yml`
//! ran on push only for itself, `ops/tsan/**`, `src/main.rs` and
//! `tests/support/server.rs`. Pull request #821 fixed `tests/hep_test.rs`, the
//! test ThreadSanitizer failed on in 0.5.258, and main's own CI never ran
//! ThreadSanitizer on it: the defects agent dispatched it by hand.
//!
//! The run step is the source. These tests read the `--test NAME` targets from
//! it, follow every file those targets compile under `tests/` (`mod` lines,
//! `#[path]`, `include!`, `include_str!` and `include_bytes!`, transitively), and
//! require the push filter to list exactly those files beside the fixed four.
//! A listed `tests/` path that no target compiles any more is refused as stale.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::Path;

const WORKFLOW: &str = ".github/workflows/sanitizers.yml";

/// The paths the filter keeps whatever the run step compiles.
const FIXED: &[&str] = &[
    ".github/workflows/sanitizers.yml",
    "ops/tsan/**",
    "src/main.rs",
];

/// The `--test NAME` targets in the workflow's run steps, in order, once each.
fn run_step_tests(workflow: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in workflow.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word != "--test" {
                continue;
            }
            let Some(name) = words.next() else { break };
            let name = name.trim_end_matches('\\').to_string();
            if !name.is_empty() && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// The `on.push.paths` entries, unquoted, in order.
fn push_paths(workflow: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_on = false;
    let mut in_push = false;
    let mut paths_indent: Option<usize> = None;
    for raw in workflow.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if indent == 0 {
            in_on = line == "on:";
            in_push = false;
            paths_indent = None;
            continue;
        }
        if !in_on {
            continue;
        }
        if let Some(pi) = paths_indent {
            if let Some(item) = line.strip_prefix("- ").filter(|_| indent > pi) {
                out.push(item.trim().trim_matches('\'').trim_matches('"').to_string());
                continue;
            }
            paths_indent = None;
        }
        if line.ends_with(':') && !line.starts_with("- ") && indent <= 2 {
            in_push = line == "push:";
            continue;
        }
        if in_push && line == "paths:" {
            paths_indent = Some(indent);
        }
    }
    out
}

/// `a/b/../c` -> `a/c`, `a/./b` -> `a/b`.
fn normalize(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    parts.join("/")
}

fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(d, _)| d)
}

fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        normalize(rel)
    } else {
        normalize(&format!("{dir}/{rel}"))
    }
}

/// The path a macro call names: `NAME!("p")`, or the crate-root form
/// `NAME!(concat!(env!("CARGO_MANIFEST_DIR"), "/p"))`, resolved against `dir`
/// (or the crate root). `Err` for any other argument.
fn macro_path(rest: &str, dir: &str) -> Result<String, String> {
    let rest = rest.trim_start();
    if let Some(lit) = rest.strip_prefix('"') {
        let end = lit
            .find('"')
            .ok_or_else(|| format!("an unterminated path in `{rest}`"))?;
        return Ok(join(dir, &lit[..end]));
    }
    let root = "concat!(env!(\"CARGO_MANIFEST_DIR\"),";
    if let Some(after) = rest.strip_prefix(root) {
        let after = after.trim_start();
        if let Some(lit) = after.strip_prefix('"') {
            let end = lit
                .find('"')
                .ok_or_else(|| format!("an unterminated path in `{rest}`"))?;
            return Ok(normalize(lit[..end].trim_start_matches('/')));
        }
    }
    Err(format!("a path that is not a literal: `{rest}`"))
}

/// How a file was reached, which decides where its `mod x;` children live.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// A crate root, a `mod.rs` or a `#[path]` file: children beside it.
    Dir,
    /// `name.rs` reached by `mod name;`: children in `name/`.
    Stem,
    /// Text pulled in by `include!`: parsed for its own includes and mods.
    Included,
    /// `include_str!`/`include_bytes!` data: compiled in, never parsed.
    Data,
}

/// The module name of a `mod NAME;` line, if the line is one.
fn mod_decl(line: &str) -> Option<&str> {
    let mut rest = line;
    if let Some(r) = rest.strip_prefix("pub") {
        let r = r.trim_start();
        rest = if let Some(r2) = r.strip_prefix('(') {
            r2.split_once(')')?.1.trim_start()
        } else {
            r
        };
    }
    let name = rest.strip_prefix("mod ")?.trim().strip_suffix(';')?.trim();
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(name)
    } else {
        None
    }
}

/// Every file the targets `roots` compile, the roots included: `mod` lines,
/// `#[path]`, `include!`, `include_str!` and `include_bytes!`, transitively.
/// `read` gives a file's text, or None when it does not exist. `Err` names a
/// file that is referenced but missing, or a path that is not a literal.
fn compiled_files(
    roots: &[String],
    read: &dyn Fn(&str) -> Option<String>,
) -> Result<BTreeSet<String>, String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<(String, Kind, String)> = VecDeque::new();
    for root in roots {
        queue.push_back((root.clone(), Kind::Dir, "the run step".to_string()));
    }
    while let Some((path, kind, from)) = queue.pop_front() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let text =
            read(&path).ok_or_else(|| format!("{from} names {path}, which does not exist"))?;
        if kind == Kind::Data {
            continue;
        }
        let dir = dir_of(&path).to_string();
        let child_dir = match kind {
            Kind::Stem => path.trim_end_matches(".rs").to_string(),
            _ => dir.clone(),
        };
        let mut pending_path: Option<String> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let Some(attr) = line.strip_prefix("#[path") {
                let attr = attr
                    .trim_start()
                    .strip_prefix('=')
                    .map(str::trim_start)
                    .unwrap_or("");
                pending_path = Some(macro_path(attr, &dir)?);
                continue;
            }
            if line.starts_with("#[") {
                continue;
            }
            if let Some(name) = mod_decl(line) {
                if let Some(p) = pending_path.take() {
                    queue.push_back((p, Kind::Dir, path.clone()));
                } else {
                    let flat = format!("{child_dir}/{name}.rs");
                    let nested = format!("{child_dir}/{name}/mod.rs");
                    if read(&flat).is_some() {
                        queue.push_back((normalize(&flat), Kind::Stem, path.clone()));
                    } else {
                        queue.push_back((normalize(&nested), Kind::Dir, path.clone()));
                    }
                }
                continue;
            }
            pending_path = None;
            for (mac, k) in [
                ("include!(", Kind::Included),
                ("include_str!(", Kind::Data),
                ("include_bytes!(", Kind::Data),
            ] {
                let mut search = line;
                while let Some(at) = search.find(mac) {
                    let before = &search[..at];
                    let is_word = before
                        .chars()
                        .last()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                    let rest = &search[at + mac.len()..];
                    if !is_word {
                        queue.push_back((macro_path(rest, &dir)?, k, path.clone()));
                    }
                    search = rest;
                }
            }
        }
    }
    Ok(seen)
}

/// The `tests/` paths the filter must list for `workflow`, from its run step.
fn derived_paths(
    workflow: &str,
    read: &dyn Fn(&str) -> Option<String>,
) -> Result<BTreeSet<String>, String> {
    let roots: Vec<String> = run_step_tests(workflow)
        .iter()
        .map(|t| format!("tests/{t}.rs"))
        .collect();
    if roots.is_empty() {
        return Err("the run step names no `--test` target".to_string());
    }
    compiled_files(&roots, read)
}

/// What is wrong with the filter of `workflow`: missing derived paths, stale
/// `tests/` paths, missing fixed paths. Empty when it agrees.
fn filter_problems(workflow: &str, read: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let derived = match derived_paths(workflow, read) {
        Ok(d) => d,
        Err(e) => return vec![e],
    };
    let listed: Vec<String> = push_paths(workflow);
    let mut problems = Vec::new();
    for p in &derived {
        if !listed.contains(p) {
            problems.push(format!("missing: {p} (the run step compiles it)"));
        }
    }
    for p in &listed {
        if p.starts_with("tests/") && !derived.contains(p) {
            problems.push(format!(
                "stale: {p} (no `--test` target of the run step compiles it)"
            ));
        }
    }
    for f in FIXED {
        if !listed.iter().any(|p| p == f) {
            problems.push(format!(
                "missing: {f} (kept whatever the run step compiles)"
            ));
        }
    }
    for p in &listed {
        if !p.starts_with("tests/") && !FIXED.contains(&p.as_str()) {
            problems.push(format!(
                "unknown: {p} (neither derived nor one of the fixed paths)"
            ));
        }
    }
    problems
}

fn fs_read(root: &Path) -> impl Fn(&str) -> Option<String> + '_ {
    move |p: &str| std::fs::read_to_string(root.join(p)).ok()
}

fn map_read(files: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect();
    move |p: &str| map.get(p).cloned()
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| (*p).to_string()).collect()
}

fn real_workflow() -> Result<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(WORKFLOW))
        .map_err(|e| format!("{WORKFLOW} must be readable: {e}"))
}

const SAMPLE: &str = "name: S\non:\n  schedule:\n    - cron: '1 2 * * 3'\n  workflow_dispatch:\n  push:\n    paths:\n      - '.github/workflows/sanitizers.yml'\n      - 'ops/tsan/**'\n      # a comment\n      - 'src/main.rs'\n      - \"tests/a_test.rs\"\n\njobs:\n  t:\n    steps:\n      - run: |\n          cargo test \\\n            --test a_test \\\n            2>&1\n";

// ---------------------------------------------------------------- the real tree

#[test]
fn success_the_real_run_step_names_its_five_targets() -> Result<(), String> {
    let tests = run_step_tests(&real_workflow()?);
    assert_eq!(
        tests,
        [
            "api_test",
            "api_token_test",
            "hep_test",
            "mcp_stdio_test",
            "cli_flag_behavior_test"
        ],
        "the run step's --test targets changed; the push filter follows them"
    );
    Ok(())
}

#[test]
fn success_the_real_push_filter_lists_exactly_what_the_run_step_compiles() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let problems = filter_problems(&real_workflow()?, &fs_read(root));
    assert!(
        problems.is_empty(),
        "{WORKFLOW}'s on.push.paths disagrees with its run step:\n  {}",
        problems.join("\n  ")
    );
    Ok(())
}

#[test]
fn success_the_real_closure_holds_the_support_files_hep_test_needed() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = derived_paths(&real_workflow()?, &fs_read(root))?;
    for p in [
        "tests/hep_test.rs",
        "tests/support/server.rs",
        "tests/support/timeout.rs",
        "tests/support/mod.rs",
    ] {
        assert!(files.contains(p), "{p} must be in the closure: {files:?}");
    }
    Ok(())
}

#[test]
fn success_every_real_filter_path_exists() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for p in push_paths(&real_workflow()?) {
        if let Some(dir) = p.strip_suffix("/**") {
            let n = std::fs::read_dir(root.join(dir))
                .map(|d| d.count())
                .unwrap_or(0);
            assert!(n > 0, "the filter's glob {p} must match a file");
        } else {
            assert!(
                root.join(&p).is_file(),
                "the filter names {p}, which does not exist"
            );
        }
    }
    Ok(())
}

#[test]
fn edge_the_real_closure_stays_under_tests() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = derived_paths(&real_workflow()?, &fs_read(root))?;
    assert!(
        files.iter().all(|p| p.starts_with("tests/")),
        "the closure left tests/: {files:?}"
    );
    Ok(())
}

// ---------------------------------------------------------------- run_step_tests

#[test]
fn success_one_test_target() {
    assert_eq!(
        run_step_tests("  cargo test --test a_test\n"),
        ["a_test"],
        "one --test target"
    );
}

#[test]
fn success_targets_on_continued_lines() {
    let text = "cargo test \\\n  --test a \\\n  --test b \\\n  2>&1\n";
    assert_eq!(
        run_step_tests(text),
        ["a", "b"],
        "each continued line's target, in order"
    );
}

#[test]
fn success_two_targets_on_one_line() {
    assert_eq!(
        run_step_tests("cargo test --test a --test b\n"),
        ["a", "b"],
        "two targets on one line"
    );
}

#[test]
fn failure_a_commented_target_is_not_run() {
    assert!(
        run_step_tests("  # --test old_test\n").is_empty(),
        "a comment names no target"
    );
}

#[test]
fn failure_no_target_is_empty() {
    assert!(
        run_step_tests("cargo test --lib\n").is_empty(),
        "no --test flag, no target"
    );
}

#[test]
fn edge_a_repeated_target_is_listed_once() {
    assert_eq!(
        run_step_tests("--test a\n--test a\n"),
        ["a"],
        "a repeated target once"
    );
}

#[test]
fn edge_a_trailing_backslash_is_not_part_of_the_name() {
    assert_eq!(
        run_step_tests("--test a\\\n"),
        ["a"],
        "the continuation backslash is dropped"
    );
}

#[test]
fn edge_a_dangling_test_flag_names_nothing() {
    assert!(
        run_step_tests("cargo test --test\n").is_empty(),
        "--test at the end of a line names nothing"
    );
}

// ---------------------------------------------------------------- push_paths

#[test]
fn success_the_sample_filter_is_read_in_order() {
    assert_eq!(
        push_paths(SAMPLE),
        [
            ".github/workflows/sanitizers.yml",
            "ops/tsan/**",
            "src/main.rs",
            "tests/a_test.rs"
        ],
        "both quote styles, comments skipped"
    );
}

#[test]
fn failure_a_workflow_without_push_has_no_paths() {
    assert!(
        push_paths("on:\n  workflow_dispatch:\njobs: {}\n").is_empty(),
        "no push trigger, no paths"
    );
}

#[test]
fn failure_a_pull_request_filter_is_not_the_push_filter() {
    let text =
        "on:\n  pull_request:\n    paths:\n      - 'a.rs'\n  push:\n    paths:\n      - 'b.rs'\n";
    assert_eq!(push_paths(text), ["b.rs"], "only on.push.paths");
}

#[test]
fn edge_a_paths_key_under_jobs_is_not_read() {
    let text =
        "on:\n  push:\n    paths:\n      - 'a.rs'\njobs:\n  x:\n    paths:\n      - 'b.rs'\n";
    assert_eq!(
        push_paths(text),
        ["a.rs"],
        "a later paths: outside on: is not the filter"
    );
}

#[test]
fn edge_a_job_named_push_is_not_the_trigger() {
    let text = "on:\n  workflow_dispatch:\njobs:\n  push:\n    paths:\n      - 'x.rs'\n";
    assert!(
        push_paths(text).is_empty(),
        "a job called push holds no trigger paths"
    );
}

#[test]
fn edge_mod_decl_refuses_a_name_that_is_not_an_identifier() {
    assert_eq!(
        mod_decl("mod a b;"),
        None,
        "a space is not part of a module name"
    );
    assert_eq!(
        mod_decl("mod a-b;"),
        None,
        "a hyphen is not part of a module name"
    );
}

#[test]
fn edge_branches_beside_paths_are_not_paths() {
    let text = "on:\n  push:\n    branches:\n      - main\n    paths:\n      - 'a.rs'\n";
    assert_eq!(push_paths(text), ["a.rs"], "branches are not paths");
}

#[test]
fn edge_a_filter_after_the_push_paths_ends_the_list() {
    let text = "on:\n  push:\n    paths:\n      - 'a.rs'\n    tags:\n      - 'v*'\n";
    assert_eq!(push_paths(text), ["a.rs"], "tags: ends the paths list");
}

// ---------------------------------------------------------------- compiled_files

fn roots(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_string()).collect()
}

#[test]
fn success_a_root_alone() {
    let read = map_read(&[("tests/a.rs", "fn main() {}\n")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs"])),
        "the root alone"
    );
}

#[test]
fn success_a_path_module() {
    let read = map_read(&[
        ("tests/a.rs", "#[path = \"support/s.rs\"]\nmod s;\n"),
        ("tests/support/s.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/support/s.rs"])),
        "#[path] names the file"
    );
}

#[test]
fn success_an_include_relative_to_the_including_file() {
    let read = map_read(&[
        ("tests/a.rs", "include!(\"support/t.rs\");\n"),
        ("tests/support/t.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/support/t.rs"])),
        "include! is relative to the file"
    );
}

#[test]
fn success_an_include_inside_a_path_module() {
    let read = map_read(&[
        (
            "tests/a.rs",
            "#[path = \"support/server.rs\"]\nmod server;\n",
        ),
        ("tests/support/server.rs", "include!(\"timeout.rs\");\n"),
        ("tests/support/timeout.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&[
            "tests/a.rs",
            "tests/support/server.rs",
            "tests/support/timeout.rs"
        ])),
        "server.rs's include resolves beside server.rs"
    );
}

#[test]
fn success_children_of_a_mod_rs_sit_beside_it() {
    let read = map_read(&[
        ("tests/a.rs", "#[path = \"support/mod.rs\"]\nmod support;\n"),
        ("tests/support/mod.rs", "pub mod schema;\n"),
        ("tests/support/schema.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&[
            "tests/a.rs",
            "tests/support/mod.rs",
            "tests/support/schema.rs"
        ])),
        "mod.rs children are its siblings"
    );
}

#[test]
fn success_a_plain_mod_from_a_root() {
    let read = map_read(&[("tests/a.rs", "mod helper;\n"), ("tests/helper.rs", "")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/helper.rs"])),
        "mod helper; beside the root"
    );
}

#[test]
fn success_a_nested_mod_rs() {
    let read = map_read(&[("tests/a.rs", "mod helper;\n"), ("tests/helper/mod.rs", "")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/helper/mod.rs"])),
        "mod helper; as helper/mod.rs"
    );
}

#[test]
fn success_include_str_data_is_compiled_in() {
    let read = map_read(&[
        (
            "tests/a.rs",
            "const X: &str = include_str!(\"data/x.json\");\n",
        ),
        ("tests/data/x.json", "{"),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/data/x.json"])),
        "include_str! data is a compiled input"
    );
}

#[test]
fn success_include_bytes_from_the_crate_root() {
    let read = map_read(&[
        (
            "tests/a.rs",
            "static B: &[u8] = include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/tests/data/b.bin\"));\n",
        ),
        ("tests/data/b.bin", "x"),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/data/b.bin"])),
        "the CARGO_MANIFEST_DIR form resolves from the crate root"
    );
}

#[test]
fn success_two_roots_share_a_support_file_once() {
    let read = map_read(&[
        ("tests/a.rs", "include!(\"support/t.rs\");\n"),
        ("tests/b.rs", "include!(\"support/t.rs\");\n"),
        ("tests/support/t.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs", "tests/b.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/b.rs", "tests/support/t.rs"])),
        "a shared file once"
    );
}

#[test]
fn success_a_pub_crate_mod() {
    let read = map_read(&[
        ("tests/a.rs", "pub(crate) mod helper;\n"),
        ("tests/helper.rs", ""),
    ]);
    assert!(
        compiled_files(&roots(&["tests/a.rs"]), &read).is_ok_and(|s| s.contains("tests/helper.rs")),
        "pub(crate) mod is a module"
    );
}

#[test]
fn success_a_child_of_a_plain_module_is_in_its_stem_dir() {
    let read = map_read(&[
        ("tests/a.rs", "mod helper;\n"),
        ("tests/helper.rs", "mod inner;\n"),
        ("tests/helper/inner.rs", ""),
    ]);
    assert!(
        compiled_files(&roots(&["tests/a.rs"]), &read)
            .is_ok_and(|s| s.contains("tests/helper/inner.rs")),
        "helper.rs's children live in helper/"
    );
}

#[test]
fn failure_a_missing_root() {
    let read = map_read(&[]);
    let err =
        compiled_files(&roots(&["tests/gone.rs"]), &read).expect_err("a missing root must fail");
    assert!(
        err.contains("tests/gone.rs") && err.contains("the run step"),
        "the error names it: {err}"
    );
}

#[test]
fn failure_a_missing_path_module() {
    let read = map_read(&[("tests/a.rs", "#[path = \"support/gone.rs\"]\nmod gone;\n")]);
    let err = compiled_files(&roots(&["tests/a.rs"]), &read)
        .expect_err("a missing #[path] file must fail");
    assert!(
        err.contains("tests/support/gone.rs") && err.contains("tests/a.rs"),
        "the error names both: {err}"
    );
}

#[test]
fn failure_a_missing_include() {
    let read = map_read(&[("tests/a.rs", "include!(\"support/gone.rs\");\n")]);
    let err =
        compiled_files(&roots(&["tests/a.rs"]), &read).expect_err("a missing include must fail");
    assert!(
        err.contains("tests/support/gone.rs"),
        "the error names it: {err}"
    );
}

#[test]
fn failure_a_missing_plain_mod() {
    let read = map_read(&[("tests/a.rs", "mod gone;\n")]);
    let err =
        compiled_files(&roots(&["tests/a.rs"]), &read).expect_err("a missing module must fail");
    assert!(
        err.contains("tests/gone/mod.rs"),
        "the error names the last place looked: {err}"
    );
}

#[test]
fn failure_a_non_literal_include() {
    let read = map_read(&[("tests/a.rs", "include!(some_macro!());\n")]);
    let err =
        compiled_files(&roots(&["tests/a.rs"]), &read).expect_err("a computed path must fail");
    assert!(err.contains("not a literal"), "the error says why: {err}");
}

#[test]
fn failure_an_unterminated_path() {
    let read = map_read(&[("tests/a.rs", "include!(\"support/t.rs);\n")]);
    let err = compiled_files(&roots(&["tests/a.rs"]), &read)
        .expect_err("an unterminated literal must fail");
    assert!(err.contains("unterminated"), "the error says why: {err}");
}

#[test]
fn failure_a_missing_data_file() {
    let read = map_read(&[("tests/a.rs", "const X: &str = include_str!(\"x.txt\");\n")]);
    let err = compiled_files(&roots(&["tests/a.rs"]), &read).expect_err("missing data must fail");
    assert!(err.contains("tests/x.txt"), "the error names it: {err}");
}

#[test]
fn edge_a_commented_mod_is_not_compiled() {
    let read = map_read(&[("tests/a.rs", "// mod gone;\n//! include!(\"gone.rs\");\n")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs"])),
        "comments compile nothing"
    );
}

#[test]
fn edge_an_inline_module_names_no_file() {
    let read = map_read(&[("tests/a.rs", "mod inline {\n    fn f() {}\n}\n")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs"])),
        "an inline module is no file"
    );
}

#[test]
fn edge_a_cfg_between_path_and_mod_keeps_the_path() {
    let read = map_read(&[
        ("tests/a.rs", "#[path = \"s/x.rs\"]\n#[cfg(unix)]\nmod x;\n"),
        ("tests/s/x.rs", ""),
    ]);
    assert!(
        compiled_files(&roots(&["tests/a.rs"]), &read).is_ok_and(|s| s.contains("tests/s/x.rs")),
        "another attribute between keeps #[path]"
    );
}

#[test]
fn edge_a_path_attribute_on_another_item_does_not_reach_a_later_mod() -> Result<(), String> {
    let read = map_read(&[
        ("tests/a.rs", "#[path = \"s/x.rs\"]\nfn f() {}\nmod y;\n"),
        ("tests/y.rs", ""),
        ("tests/s/x.rs", ""),
    ]);
    let files = compiled_files(&roots(&["tests/a.rs"]), &read)?;
    assert!(
        files.contains("tests/y.rs") && !files.contains("tests/s/x.rs"),
        "the attribute was the fn's: {files:?}"
    );
    Ok(())
}

#[test]
fn edge_a_parent_directory_in_a_path_is_resolved() {
    let read = map_read(&[
        ("tests/a.rs", "#[path = \"../build_script/g.rs\"]\nmod g;\n"),
        ("build_script/g.rs", ""),
    ]);
    assert!(
        compiled_files(&roots(&["tests/a.rs"]), &read)
            .is_ok_and(|s| s.contains("build_script/g.rs")),
        "../ is resolved"
    );
}

#[test]
fn edge_include_str_text_is_not_parsed() {
    let read = map_read(&[
        (
            "tests/a.rs",
            "const X: &str = include_str!(\"x.rs.txt\");\n",
        ),
        ("tests/x.rs.txt", "mod gone;\n"),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/x.rs.txt"])),
        "data is not Rust"
    );
}

#[test]
fn edge_a_cycle_terminates() {
    let read = map_read(&[
        ("tests/a.rs", "include!(\"b.rs\");\n"),
        ("tests/b.rs", "include!(\"a.rs\");\n"),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/b.rs"])),
        "a cycle ends"
    );
}

#[test]
fn edge_a_word_ending_in_include_is_not_the_macro() {
    let read = map_read(&[("tests/a.rs", "my_include!(\"gone.rs\");\n")]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs"])),
        "my_include! is not include!"
    );
}

#[test]
fn edge_two_includes_on_one_line() {
    let read = map_read(&[
        ("tests/a.rs", "include!(\"x.rs\"); include!(\"y.rs\");\n"),
        ("tests/x.rs", ""),
        ("tests/y.rs", ""),
    ]);
    assert_eq!(
        compiled_files(&roots(&["tests/a.rs"]), &read),
        Ok(set(&["tests/a.rs", "tests/x.rs", "tests/y.rs"])),
        "both includes on the line"
    );
}

#[test]
fn edge_normalize_drops_dot_segments() {
    assert_eq!(
        normalize("tests/./support/../x.rs"),
        "tests/x.rs",
        "dot segments are resolved"
    );
}

#[test]
fn edge_mod_decl_refuses_a_use_line() {
    assert_eq!(
        mod_decl("use foo::bar;"),
        None,
        "a use line is not a module"
    );
    assert_eq!(mod_decl("pub mod x;"), Some("x"), "pub mod x; is a module");
}

// ---------------------------------------------------------------- filter_problems

fn sample_read() -> impl Fn(&str) -> Option<String> {
    map_read(&[
        ("tests/a_test.rs", "include!(\"support/t.rs\");\n"),
        ("tests/support/t.rs", ""),
    ])
}

#[test]
fn failure_a_derived_file_missing_from_the_filter_is_named() {
    let problems = filter_problems(SAMPLE, &sample_read());
    assert_eq!(
        problems,
        ["missing: tests/support/t.rs (the run step compiles it)"],
        "the include is missing"
    );
}

#[test]
fn success_a_filter_that_lists_every_derived_file_agrees() {
    let text = SAMPLE.replace(
        "      - \"tests/a_test.rs\"\n",
        "      - \"tests/a_test.rs\"\n      - 'tests/support/t.rs'\n",
    );
    assert!(
        filter_problems(&text, &sample_read()).is_empty(),
        "the filter agrees"
    );
}

#[test]
fn failure_a_stale_tests_path_is_refused() {
    let text = SAMPLE.replace(
        "      - \"tests/a_test.rs\"\n",
        "      - \"tests/a_test.rs\"\n      - 'tests/support/t.rs'\n      - 'tests/old_test.rs'\n",
    );
    let problems = filter_problems(&text, &sample_read());
    assert_eq!(
        problems,
        ["stale: tests/old_test.rs (no `--test` target of the run step compiles it)"],
        "stale path"
    );
}

#[test]
fn failure_a_dropped_fixed_path_is_refused() {
    let text = SAMPLE.replace("      - 'ops/tsan/**'\n", "").replace(
        "      - \"tests/a_test.rs\"\n",
        "      - \"tests/a_test.rs\"\n      - 'tests/support/t.rs'\n",
    );
    let problems = filter_problems(&text, &sample_read());
    assert_eq!(
        problems,
        ["missing: ops/tsan/** (kept whatever the run step compiles)"],
        "ops/tsan/** is kept"
    );
}

#[test]
fn failure_an_unknown_path_is_refused() {
    let text = SAMPLE.replace(
        "      - \"tests/a_test.rs\"\n",
        "      - \"tests/a_test.rs\"\n      - 'tests/support/t.rs'\n      - 'docs/x.md'\n",
    );
    let problems = filter_problems(&text, &sample_read());
    assert_eq!(
        problems,
        ["unknown: docs/x.md (neither derived nor one of the fixed paths)"],
        "an unknown path"
    );
}

#[test]
fn failure_a_run_step_without_targets_is_refused() {
    let text = SAMPLE.replace("--test a_test", "--lib");
    let problems = filter_problems(&text, &sample_read());
    assert_eq!(
        problems,
        ["the run step names no `--test` target"],
        "no target is refused"
    );
}

#[test]
fn failure_a_target_whose_file_is_gone_is_refused() {
    let problems = filter_problems(SAMPLE, &map_read(&[]));
    assert_eq!(problems.len(), 1, "one problem: {problems:?}");
    assert!(
        problems[0].contains("tests/a_test.rs"),
        "it names the target: {problems:?}"
    );
}

#[test]
fn edge_a_new_target_in_the_run_step_needs_its_files() {
    let text = SAMPLE
        .replace(
            "--test a_test \\\n",
            "--test a_test \\\n            --test b_test \\\n",
        )
        .replace(
            "      - \"tests/a_test.rs\"\n",
            "      - \"tests/a_test.rs\"\n      - 'tests/support/t.rs'\n",
        );
    let read = map_read(&[
        ("tests/a_test.rs", "include!(\"support/t.rs\");\n"),
        ("tests/b_test.rs", ""),
        ("tests/support/t.rs", ""),
    ]);
    assert_eq!(
        filter_problems(&text, &read),
        ["missing: tests/b_test.rs (the run step compiles it)"],
        "a new target is required in the filter"
    );
}

#[test]
fn edge_problems_list_missing_before_stale() {
    let text = SAMPLE.replace("      - \"tests/a_test.rs\"\n", "      - 'tests/old.rs'\n");
    let problems = filter_problems(&text, &sample_read());
    assert_eq!(problems.len(), 3, "two missing and one stale: {problems:?}");
    assert!(
        problems[0].starts_with("missing") && problems[2].starts_with("stale"),
        "order: {problems:?}"
    );
}
