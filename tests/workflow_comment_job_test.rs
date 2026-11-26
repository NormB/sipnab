// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A comment in `release.yml` names only jobs the workflow defines.
//!
//! The comment over `release.yml`'s `permissions:` block described a `tap`
//! job that pushed to the Homebrew tap with a separate secret. That job had
//! been removed: scripts/post-release.py commits the formula, and the secret
//! was deleted. The comment still told a reader why a job that did not exist
//! needed no write permission.
//!
//! Two shapes of comment name a job:
//!
//! - A backticked word followed by `job` or `jobs`: "the `release` job",
//!   "`preflight` and `build` jobs". After another workflow's file name and
//!   `'s` ("pages.yml's `live` job"), it names a job of that workflow, which
//!   must define it.
//! - In a comment block that names one of the workflow's jobs, a backticked
//!   word that starts a clause or a list item ("`preflight` and `build` just
//!   check out", "and `tap` reads") is a job too, unless a word such as
//!   `feature`, `step` or `artifact` follows it.
//!
//! The rule covers `release.yml` only. Run over every workflow, it refuses
//! comments that name an event (ci.yml: "a `pull_request` job") or another
//! workflow's job without its file name (quality.yml: "CI's `check` job").

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

type TestError = Box<dyn std::error::Error>;

fn read(rel: &str) -> Result<String, TestError> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {rel}: {e}"))?)
}

/// Every workflow file, by its file name, for the cross-workflow references.
fn workflows() -> Result<BTreeMap<String, String>, TestError> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read workflows: {e}"))? {
        let path = entry.map_err(|e| format!("entry: {e}"))?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{} has no file name", path.display()))?
            .to_string();
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            let body = std::fs::read_to_string(&path).map_err(|e| format!("read {name}: {e}"))?;
            out.insert(name, body);
        }
    }
    Ok(out)
}

/// A workflow with two jobs, and a comment that names both correctly.
const WF: &str = "name: Fixture\non:\n  push:\n    tags: ['v*']\n\n\
# The `build` job makes the files, and `publish` ships them.\n\
permissions:\n  contents: read\n\njobs:\n  build:\n    runs-on: ubuntu-24.04\n    \
steps:\n      - run: make\n  publish:\n    needs: build\n    runs-on: ubuntu-24.04\n";

/// A second workflow, for the cross-workflow references.
const OTHER: &str = "name: Other\non: workflow_dispatch\njobs:\n  deploy:\n    runs-on: x\n  live:\n    runs-on: x\n";

/// `WF` with its comment line replaced by `comment` (one or more `#` lines).
fn wf_with(comment: &str) -> String {
    WF.replace(
        "# The `build` job makes the files, and `publish` ships them.\n",
        &format!("{comment}\n"),
    )
}

/// The problems `rule::problems` finds in `text` as `wf.yml`, with
/// `other.yml` as the only other workflow.
fn check(text: &str) -> Vec<String> {
    let others = BTreeMap::from([("other.yml".to_string(), OTHER.to_string())]);
    rule::problems("wf.yml", text, &others)
}

fn has(found: &[String], needle: &str) -> bool {
    found.iter().any(|f| f.contains(needle))
}

// Success: the real workflow, then the fixtures.

#[test]
fn s01_release_yml_comments_name_only_its_own_jobs() -> Result<(), TestError> {
    let all = workflows()?;
    let text = all
        .get("release.yml")
        .ok_or("no .github/workflows/release.yml")?;
    let found = rule::problems("release.yml", text, &all);
    assert!(found.is_empty(), "release.yml comments: {found:?}");
    Ok(())
}

/// Every `needs:` target is a job the reader found, so the job list the rule
/// checks against is the workflow's real one.
#[test]
fn s02_the_job_reader_finds_every_job_release_yml_needs() -> Result<(), TestError> {
    let text = read(".github/workflows/release.yml")?;
    let jobs = rule::job_ids(&text);
    assert!(jobs.contains("release"), "release.yml jobs: {jobs:?}");
    let mut needed = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("needs:") else {
            continue;
        };
        for id in rest
            .split(|c: char| "[], ".contains(c))
            .filter(|s| !s.is_empty())
        {
            needed.insert(id.to_string());
        }
    }
    assert!(!needed.is_empty(), "release.yml has no `needs:` lines");
    let unknown: Vec<_> = needed.difference(&jobs).collect();
    assert!(
        unknown.is_empty(),
        "needs: names {unknown:?}, not in {jobs:?}"
    );
    Ok(())
}

/// release.yml names a job of pages.yml; that job must exist there.
#[test]
fn s03_the_cross_workflow_reference_in_release_yml_resolves() -> Result<(), TestError> {
    let text = read(".github/workflows/release.yml")?;
    assert!(
        text.contains("pages.yml's `live` job"),
        "release.yml no longer names pages.yml's `live` job; s03 checks that reference"
    );
    let pages = read(".github/workflows/pages.yml")?;
    assert!(
        rule::job_ids(&pages).contains("live"),
        "pages.yml has no `live` job"
    );
    Ok(())
}

#[test]
fn s04_the_fixture_passes() {
    let found = check(WF);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s05_the_fixture_job_ids_are_read() {
    let jobs = rule::job_ids(WF);
    let want: BTreeSet<String> = ["build", "publish"].map(String::from).into();
    assert_eq!(jobs, want, "job ids of WF");
}

#[test]
fn s06_a_list_of_jobs_passes() {
    let found = check(&wf_with(
        "# The `build` and `publish` jobs run on every tag.",
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s07_another_workflows_job_named_with_its_file_passes() {
    let found = check(&wf_with("# This waits for other.yml's `deploy` job."));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s08_a_backticked_word_in_a_block_without_jobs_passes() {
    let found = check(&wf_with("# `full` minus `audio`, and `opus` stays out."));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s09_a_qualified_word_in_a_job_block_passes() {
    let found = check(&wf_with(
        "# The `build` job compiles it, and `full` feature builds stay; `make` step too.",
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s10_a_word_in_object_position_in_a_job_block_passes() {
    let found = check(&wf_with("# The `build` job runs `cosign` and then `make`."));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s11_job_ids_with_hyphens_and_underscores_are_read() {
    let text = WF.replace("  publish:\n", "  crates-io:\n  a_b:\n");
    let jobs = rule::job_ids(&text);
    assert!(
        jobs.contains("crates-io") && jobs.contains("a_b"),
        "{jobs:?}"
    );
    let found = check(&text.replace("`publish` ships", "`crates-io` ships"));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s12_a_comment_inside_the_jobs_block_is_read() {
    let text = WF.replace("  publish:\n", "  # The `publish` job ships.\n  publish:\n");
    let found = check(&text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn s13_a_job_block_whose_words_are_all_jobs_passes() {
    let found = check(&wf_with(
        "# `build` makes the files. `publish` ships them, and `build` must pass first.",
    ));
    assert!(found.is_empty(), "{found:?}");
}

// Failure: each shape of a missing job is refused, and named.

#[test]
fn f01_a_missing_job_followed_by_job_is_refused() {
    let found = check(&wf_with("# The `tap` job pushes the formula."));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f02_a_missing_job_followed_by_jobs_is_refused() {
    let found = check(&wf_with("# The `tap` jobs push the formula."));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f03_a_missing_job_in_a_list_of_jobs_is_refused() {
    let found = check(&wf_with("# The `build` and `tap` jobs run on every tag."));
    assert_eq!(
        found,
        ["wf.yml:6: `tap` is not a job of wf.yml"],
        "{found:?}"
    );
}

/// The defect itself: release.yml's comment as it stood before the fix.
#[test]
fn f04_the_old_release_yml_comment_is_refused() {
    let old = "# Read by default. Only the `release` job publishes, and it restates what it\n\
# needs in its own block. `preflight` and `build` just check out and upload\n\
# artifacts, and `tap` reads the release with github.token but pushes to\n\
# NormB/homebrew-tap with a separate secret — GITHUB_TOKEN cannot write to\n\
# another repository, so none of the three needs write here.";
    let text = wf_with(old)
        .replace("  build:\n", "  preflight:\n    runs-on: x\n  build:\n")
        .replace("  publish:\n", "  release:\n");
    let found = check(&text);
    assert_eq!(
        found,
        ["wf.yml:8: `tap` is not a job of wf.yml"],
        "{found:?}"
    );
}

#[test]
fn f05_a_missing_job_of_another_workflow_is_refused() {
    let found = check(&wf_with("# This waits for other.yml's `smoke` job."));
    assert!(
        has(&found, "`smoke` is not a job of other.yml"),
        "{found:?}"
    );
}

#[test]
fn f06_a_workflow_that_does_not_exist_is_refused() {
    let found = check(&wf_with("# This waits for gone.yml's `deploy` job."));
    assert!(has(&found, "gone.yml is not a workflow"), "{found:?}");
}

#[test]
fn f07_a_missing_job_after_a_comma_in_a_job_block_is_refused() {
    let found = check(&wf_with(
        "# The `build` job makes the files, `tap` pushes them.",
    ));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f08_a_missing_job_after_a_semicolon_in_a_job_block_is_refused() {
    let found = check(&wf_with(
        "# The `build` job makes the files; `tap` pushes them.",
    ));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f09_a_missing_job_after_a_parenthesis_in_a_job_block_is_refused() {
    let found = check(&wf_with(
        "# The `build` job makes the files (`tap` pushes them).",
    ));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f10_a_missing_job_that_opens_a_job_block_is_refused() {
    let found = check(&wf_with(
        "# `tap` pushes the formula. The `build` job makes it.",
    ));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f11_a_missing_job_after_or_in_a_job_block_is_refused() {
    let found = check(&wf_with("# Either `build` or `tap` may fail."));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f12_the_problem_names_the_line_of_the_word() {
    let found = check(&wf_with(
        "# The `build` job makes the files.\n# Then the `tap` job pushes.",
    ));
    assert_eq!(
        found,
        ["wf.yml:7: `tap` is not a job of wf.yml"],
        "{found:?}"
    );
}

#[test]
fn f13_a_key_under_on_is_not_a_job() {
    let found = check(&wf_with("# The `push` job starts it."));
    assert!(has(&found, "`push` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn f14_every_missing_job_is_named() {
    let found = check(&wf_with("# The `tap` job and the `sign` job are gone."));
    assert!(
        has(&found, "`tap` is not a job") && has(&found, "`sign` is not a job"),
        "{found:?}"
    );
}

// Edge: shapes the reader must get right.

#[test]
fn e01_crlf_line_ends_are_read() {
    let text = wf_with("# The `tap` job pushes.").replace('\n', "\r\n");
    let found = check(&text);
    assert_eq!(
        found,
        ["wf.yml:6: `tap` is not a job of wf.yml"],
        "{found:?}"
    );
    assert_eq!(rule::job_ids(&text).len(), 2, "CRLF job ids");
}

#[test]
fn e02_indented_comment_lines_are_one_block() {
    let found = check(&wf_with(
        "# The `build` job makes the files,\n  #  and `tap` pushes them.",
    ));
    assert!(has(&found, "`tap` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn e03_a_blank_line_ends_a_block() {
    let found = check(&wf_with(
        "# The `build` job makes the files.\n\n# `tap` and `opus` stay.",
    ));
    assert!(found.is_empty(), "the second block names no job: {found:?}");
}

#[test]
fn e04_a_yaml_line_ends_a_block() {
    let found = check(&wf_with(
        "# The `build` job makes the files.\nenv:\n  A: b\n# `tap` stays.",
    ));
    assert!(found.is_empty(), "the second block names no job: {found:?}");
}

#[test]
fn e05_a_trailing_comment_on_a_yaml_line_is_not_read() {
    let text = WF.replace("      - run: make\n", "      - run: make # the `tap` job\n");
    let found = check(&text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e06_a_hash_inside_a_run_string_is_not_a_comment() {
    let text = WF.replace(
        "      - run: make\n",
        "      - run: echo '# the `tap` job'\n",
    );
    let found = check(&text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e07_a_file_name_in_backticks_is_not_a_job_word() {
    let found = check(&wf_with(
        "# The `build` job reads `release.yml`, and `Cargo.toml` too.",
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e08_job_must_be_a_whole_word() {
    let found = check(&wf_with(
        "# `full` jobserver tokens and `audio` jobless builds.",
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e09_step_level_keys_are_not_job_ids() {
    let jobs = rule::job_ids(WF);
    for key in ["runs-on", "steps", "needs", "push", "tags", "contents"] {
        assert!(!jobs.contains(key), "{key} read as a job: {jobs:?}");
    }
}

#[test]
fn e10_a_prefix_of_a_job_id_is_not_the_job() {
    let found = check(&wf_with("# The `pub` job ships the files."));
    assert!(has(&found, "`pub` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn e11_job_ids_are_case_sensitive() {
    let found = check(&wf_with("# The `Build` job makes the files."));
    assert!(has(&found, "`Build` is not a job of wf.yml"), "{found:?}");
}

#[test]
fn e12_a_column_zero_comment_inside_jobs_does_not_end_them() {
    let text = WF.replace("  publish:\n", "# The `publish` job ships.\n  publish:\n");
    let jobs = rule::job_ids(&text);
    assert!(jobs.contains("publish"), "{jobs:?}");
    let found = check(&text);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn e13_a_top_level_key_after_jobs_ends_them() {
    let text = format!("{WF}concurrency:\n  group: x\n");
    let jobs = rule::job_ids(&text);
    assert!(!jobs.contains("group"), "{jobs:?}");
}

/// The rule, as pure functions of the workflow text.
mod rule {
    use std::collections::{BTreeMap, BTreeSet};

    /// Words after a backticked word that make it something other than a job.
    const QUALIFIERS: &[&str] = &[
        "feature",
        "features",
        "step",
        "steps",
        "artifact",
        "artifacts",
        "input",
        "inputs",
        "output",
        "outputs",
        "group",
        "flag",
        "command",
        "event",
        "key",
        "secret",
        "environment",
        "runner",
        "crate",
        "file",
        "variant",
        "variants",
        "target",
        "option",
        "field",
    ];

    /// What comes before a backticked word that starts a clause or a list item.
    const CLAUSE_STARTS: &[&str] = &[". ", ": ", "; ", ", ", "(", " and ", " or ", "— "];

    /// The job ids of a workflow: the keys two spaces in under `jobs:`.
    pub fn job_ids(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut in_jobs = false;
        for line in text.lines() {
            let line = line.trim_end();
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if !line.starts_with(' ') {
                in_jobs = line.split(" #").next().map(str::trim_end) == Some("jobs:");
                continue;
            }
            if in_jobs && !line.starts_with("   ") {
                let key = line
                    .trim_start()
                    .split(" #")
                    .next()
                    .unwrap_or("")
                    .trim_end();
                if let Some(id) = key.strip_suffix(':')
                    && !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    out.insert(id.to_string());
                }
            }
        }
        out
    }

    /// The full-line comments of `text`, in blocks of consecutive lines: each
    /// line's number and its text without the `#`.
    fn blocks(text: &str) -> Vec<Vec<(usize, String)>> {
        let mut out = Vec::new();
        let mut cur: Vec<(usize, String)> = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if let Some(body) = line.trim().strip_prefix('#') {
                cur.push((i + 1, body.trim().to_string()));
            } else if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            out.push(cur);
        }
        out
    }

    /// One backticked word of a block.
    struct Word<'a> {
        word: &'a str,
        line: usize,
        /// The word after it.
        next: &'a str,
        /// The file of `<file>.yml's` just before it.
        workflow: Option<&'a str>,
        /// Whether it starts a clause or a list item.
        opens_clause: bool,
    }

    /// The bare backticked words of `joined` (a block's lines joined by one
    /// space); `starts` holds each line's offset in it and its number.
    fn words<'a>(joined: &'a str, starts: &[(usize, usize)]) -> Vec<Word<'a>> {
        let mut out = Vec::new();
        let mut rest_at = 0;
        while let Some(open) = joined[rest_at..].find('`').map(|o| o + rest_at) {
            let Some(close) = joined[open + 1..].find('`').map(|c| c + open + 1) else {
                break;
            };
            rest_at = close + 1;
            let word = &joined[open + 1..close];
            let bare = !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !bare {
                continue;
            }
            let before = &joined[..open];
            let after = &joined[close + 1..];
            let next = after
                .strip_prefix(' ')
                .map(|a| {
                    a.split(|c: char| !c.is_ascii_alphabetic())
                        .next()
                        .unwrap_or("")
                })
                .unwrap_or("");
            let workflow = before.strip_suffix("'s ").and_then(|b| {
                let file = b.rsplit(' ').next().unwrap_or("");
                (file.ends_with(".yml") || file.ends_with(".yaml")).then_some(file)
            });
            let opens_clause =
                before.is_empty() || CLAUSE_STARTS.iter().any(|s| before.ends_with(s));
            let line = starts
                .iter()
                .take_while(|(at, _)| *at <= open)
                .last()
                .map_or(0, |(_, n)| *n);
            out.push(Word {
                word,
                line,
                next,
                workflow,
                opens_clause,
            });
        }
        out
    }

    /// Whether the word after a backticked word says it is a job.
    fn says_job(w: &str) -> bool {
        w == "job" || w == "jobs"
    }

    /// Every comment of `text` (the workflow `name`) that names a job the
    /// workflow, or the other workflow it names, does not define.
    pub fn problems(name: &str, text: &str, others: &BTreeMap<String, String>) -> Vec<String> {
        let own = job_ids(text);
        let mut out = Vec::new();
        for block in blocks(text) {
            let mut joined = String::new();
            let mut starts = Vec::new();
            for (n, body) in &block {
                if !joined.is_empty() {
                    joined.push(' ');
                }
                starts.push((joined.len(), *n));
                joined.push_str(body);
            }
            let words = words(&joined, &starts);
            let names_own_job = words
                .iter()
                .any(|w| w.workflow.is_none() && own.contains(w.word));
            for w in &words {
                let (word, line) = (w.word, w.line);
                if says_job(w.next) {
                    match w.workflow.filter(|f| *f != name) {
                        Some(file) => match others.get(file) {
                            None => out.push(format!("{name}:{line}: {file} is not a workflow")),
                            Some(other) if !job_ids(other).contains(word) => {
                                out.push(format!("{name}:{line}: `{word}` is not a job of {file}"))
                            }
                            Some(_) => {}
                        },
                        None if !own.contains(word) => {
                            out.push(format!("{name}:{line}: `{word}` is not a job of {name}"));
                        }
                        None => {}
                    }
                } else if names_own_job
                    && w.workflow.is_none()
                    && w.opens_clause
                    && !QUALIFIERS.contains(&w.next)
                    && !own.contains(word)
                {
                    out.push(format!("{name}:{line}: `{word}` is not a job of {name}"));
                }
            }
        }
        out
    }
}
