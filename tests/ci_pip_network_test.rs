// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every `pip install` in CI tolerates a slow read from PyPI.
//!
//! On 2026-10-01 the Check job on main failed in "Run every client program
//! against a replayed capture": pip was downloading a wheel from
//! files.pythonhosted.org at 8 kB/s, one socket read waited longer than pip's
//! 15-second default timeout, and pip raised `ReadTimeoutError` and exited 2.
//! The commit itself was fine; a rerun passed.
//!
//! pip's defaults, read from the pip 24.0 wheel that the runner's tracebacks
//! match line for line (`pip/_internal/cli/cmdoptions.py`): `--retries`
//! defaults to 5 and `--timeout` (alias `--default-timeout`) to 15 seconds.
//! The timeout applies to each socket operation. The retries are urllib3's,
//! applied to a request before its body streams; a read that times out in
//! the middle of a download is not retried, so the timeout is the setting
//! that covers the failure above and the retries cover connection errors and
//! the 5xx responses pip lists.
//!
//! pip reads every long option from a `PIP_<OPTION>` environment variable
//! (`pip/_internal/configuration.py`, `get_environ_vars` and
//! `_normalize_name`; `pip/_internal/cli/parser.py`, `_update_defaults`
//! looks each one up as `--<name>`). So `PIP_TIMEOUT`, `PIP_DEFAULT_TIMEOUT`
//! and `PIP_RETRIES` all apply. A command-line flag overrides them.
//!
//! These tests find every `pip install` in `.github/workflows/*.yml` and
//! `.github/actions/*/action.yml`, work out which values pip will use there
//! (flag, then step `env:`, then job `env:`, then workflow `env:`), and
//! require both to be above pip's defaults and the same at every site.

use std::collections::BTreeMap;
use std::path::Path;

type TestError = Box<dyn std::error::Error>;

/// pip 24.0's default for `--retries` (`cmdoptions.py`, `default=5`).
const PIP_DEFAULT_RETRIES: u32 = 5;

/// pip 24.0's default for `--timeout` in seconds (`cmdoptions.py`,
/// `default=15`).
const PIP_DEFAULT_TIMEOUT_SECS: f64 = 15.0;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// One `pip install` command and the values pip will use for it.
#[derive(Debug)]
struct Site {
    /// `file:job:step (line N)`.
    label: String,
    timeout: Result<f64, String>,
    retries: Result<u32, String>,
}

/// What scanning one file found.
#[derive(Debug, Default)]
struct Scan {
    sites: Vec<Site>,
    /// Package installs through a tool these tests do not model.
    unmodeled: Vec<String>,
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A blank line or a YAML (or shell) comment line.
fn is_noise(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// `line` without its indentation and without a leading `- ` list marker.
fn content(line: &str) -> &str {
    let t = line.trim_start();
    t.strip_prefix("- ").map_or(t, str::trim_start)
}

/// Indices of the lines that enclose line `i`, nearest first: each one is
/// the closest earlier line indented less than the one before it.
fn ancestors(lines: &[&str], i: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut cur = indent(lines[i]);
    for j in (0..i).rev() {
        if cur == 0 {
            break;
        }
        if is_noise(lines[j]) {
            continue;
        }
        if indent(lines[j]) < cur {
            out.push(j);
            cur = indent(lines[j]);
        }
    }
    out
}

/// The end (exclusive) of the block that line `start` opens.
fn block_end(lines: &[&str], start: usize) -> usize {
    let base = indent(lines[start]);
    (start + 1..lines.len())
        .find(|&j| !is_noise(lines[j]) && indent(lines[j]) <= base)
        .unwrap_or(lines.len())
}

/// The value of a `KEY: value` YAML scalar, without quotes or a trailing
/// comment.
fn scalar(value: &str) -> String {
    let v = value.split(" #").next().unwrap_or("").trim();
    v.trim_matches('"').trim_matches('\'').to_string()
}

/// The `key:` mapping entries at indentation `key_indent` within lines
/// `start..end`, where line `start` may carry a `- ` list marker.
fn keys_at(lines: &[&str], start: usize, end: usize, key_indent: usize) -> Vec<(usize, String)> {
    (start..end)
        .filter(|&j| !is_noise(lines[j]))
        .filter_map(|j| {
            let line = lines[j];
            let eff = if line.trim_start().starts_with("- ") {
                indent(line) + 2
            } else {
                indent(line)
            };
            (eff == key_indent).then(|| (j, content(line).to_string()))
        })
        .collect()
}

/// The variables of the `env:` mapping at `key_indent` in `start..end`.
fn env_of(lines: &[&str], start: usize, end: usize, key_indent: usize) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let Some((at, _)) = keys_at(lines, start, end, key_indent)
        .into_iter()
        .find(|(_, c)| c.trim_end() == "env:")
    else {
        return env;
    };
    for line in &lines[at + 1..block_end(lines, at).min(end)] {
        if is_noise(line) {
            continue;
        }
        if let Some((k, v)) = line.trim().split_once(':') {
            env.insert(k.trim().to_string(), scalar(v));
        }
    }
    env
}

/// The value given to `--flag N` or `--flag=N` in `tokens`, if any.
fn flag(tokens: &[&str], names: &[&str]) -> Option<String> {
    let mut found = None;
    for (k, tok) in tokens.iter().enumerate() {
        for name in names {
            if let Some(v) = tok.strip_prefix(&format!("{name}=")) {
                found = Some(v.to_string());
            } else if tok == name {
                found = tokens.get(k + 1).map(|v| (*v).to_string());
            }
        }
    }
    found
}

/// True when `tokens` run `pip install` (`pip`, `pip3`, `pip3.12`, or
/// `python -m pip`, any path prefix).
fn is_pip_install(tokens: &[&str]) -> bool {
    tokens.windows(2).any(|w| {
        let base = w[0].rsplit('/').next().unwrap_or(w[0]);
        let is_pip = base
            .strip_prefix("pip")
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'));
        is_pip && w[1] == "install"
    })
}

/// The installer `tokens` run that pip's settings do not reach, if any.
fn unmodeled_installer(tokens: &[&str]) -> Option<&'static str> {
    for w in tokens.windows(2) {
        let base = w[0].rsplit('/').next().unwrap_or(w[0]);
        match base {
            "uv" if matches!(w[1], "pip" | "add" | "sync" | "tool" | "run") => return Some("uv"),
            "uvx" => return Some("uvx"),
            "pipx" => return Some("pipx"),
            _ => {}
        }
    }
    None
}

/// The value one setting takes: a flag wins, then the environment, where
/// two names for the same option that disagree are ambiguous to pip.
fn resolve(
    flag_value: Option<String>,
    env: &BTreeMap<String, String>,
    names: &[&str],
) -> Result<String, String> {
    if let Some(v) = flag_value {
        return Ok(v);
    }
    let set: Vec<(&str, &String)> = names
        .iter()
        .filter_map(|n| env.get(*n).map(|v| (*n, v)))
        .collect();
    match set.as_slice() {
        [] => Err(format!(
            "unset (none of {} in env, no flag)",
            names.join(", ")
        )),
        [(_, v)] => Ok((*v).clone()),
        [(_, a), rest @ ..] if rest.iter().all(|(_, b)| b == a) => Ok((*a).clone()),
        _ => Err(format!(
            "ambiguous: {} disagree, and pip applies them in environment order",
            set.iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Every `pip install` in one workflow or composite action file.
///
/// `file` labels the findings. A workflow's top-level `env:` applies to
/// every job; a composite action has none of its own, and the environment
/// of the job that calls it is not visible here, so an action's pip must
/// carry its settings in its own steps.
fn scan(file: &str, text: &str) -> Scan {
    let lines: Vec<&str> = text.lines().collect();
    let is_workflow = !file.ends_with("action.yml");
    let mut out = Scan::default();
    for i in 0..lines.len() {
        if is_noise(lines[i]) {
            continue;
        }
        let chain: Vec<usize> = std::iter::once(i).chain(ancestors(&lines, i)).collect();
        if !chain.iter().any(|&j| content(lines[j]).starts_with("run:")) {
            continue;
        }
        // The logical command: this line plus any `\` continuations.
        let mut command = content(lines[i]).trim_start_matches("run:").to_string();
        let mut k = i;
        while command.trim_end().ends_with('\\') && k + 1 < lines.len() {
            k += 1;
            command = format!(
                "{} {}",
                command.trim_end().trim_end_matches('\\'),
                lines[k].trim()
            );
        }
        let tokens: Vec<&str> = command.split_whitespace().collect();
        let step = chain.windows(2).find_map(|w| {
            (lines[w[0]].trim_start().starts_with("- ")
                && content(lines[w[1]]).trim_end() == "steps:")
                .then_some(w[0])
        });
        let job = chain.windows(2).find_map(|w| {
            (indent(lines[w[1]]) == 0 && lines[w[1]].trim_end() == "jobs:").then_some(w[0])
        });
        let step_name = step.map_or_else(
            || "?".to_string(),
            |s| {
                keys_at(&lines, s, block_end(&lines, s), indent(lines[s]) + 2)
                    .into_iter()
                    .find_map(|(_, c)| c.strip_prefix("name:").map(scalar))
                    .unwrap_or_else(|| format!("step at line {}", s + 1))
            },
        );
        let job_name = job.map_or_else(
            || "runs".to_string(),
            |j| content(lines[j]).trim_end_matches(':').to_string(),
        );
        let label = format!("{file}:{job_name}:{step_name} (line {})", i + 1);
        if let Some(tool) = unmodeled_installer(&tokens) {
            out.unmodeled.push(format!(
                "{label}: installs with {tool}, which does not read PIP_*; \
                 extend this test to its own timeout and retry settings"
            ));
            continue;
        }
        if !is_pip_install(&tokens) {
            continue;
        }
        let mut env = BTreeMap::new();
        if is_workflow {
            env.extend(env_of(&lines, 0, lines.len(), 0));
        }
        if let Some(j) = job {
            let end = block_end(&lines, j);
            let key_indent = (j + 1..end)
                .find(|&n| !is_noise(lines[n]))
                .map_or(0, |n| indent(lines[n]));
            env.extend(env_of(&lines, j, end, key_indent));
        }
        if let Some(s) = step {
            env.extend(env_of(
                &lines,
                s,
                block_end(&lines, s),
                indent(lines[s]) + 2,
            ));
        }
        let timeout = resolve(
            flag(&tokens, &["--timeout", "--default-timeout"]),
            &env,
            &["PIP_TIMEOUT", "PIP_DEFAULT_TIMEOUT"],
        )
        .and_then(|v| {
            v.parse::<f64>()
                .map_err(|e| format!("`{v}` is not a number: {e}"))
        });
        let retries =
            resolve(flag(&tokens, &["--retries"]), &env, &["PIP_RETRIES"]).and_then(|v| {
                v.parse::<u32>()
                    .map_err(|e| format!("`{v}` is not a count: {e}"))
            });
        out.sites.push(Site {
            label,
            timeout,
            retries,
        });
    }
    out
}

/// Why each site does not tolerate a slow read, one line per problem.
fn defects(scan: &Scan) -> Vec<String> {
    let mut out = scan.unmodeled.clone();
    for site in &scan.sites {
        match &site.timeout {
            Ok(t) if *t > PIP_DEFAULT_TIMEOUT_SECS => {}
            Ok(t) => out.push(format!(
                "{}: timeout {t}s is not above pip's {PIP_DEFAULT_TIMEOUT_SECS}s default",
                site.label
            )),
            Err(e) => out.push(format!("{}: timeout {e}", site.label)),
        }
        match &site.retries {
            Ok(r) if *r > PIP_DEFAULT_RETRIES => {}
            Ok(r) => out.push(format!(
                "{}: retries {r} is not above pip's default of {PIP_DEFAULT_RETRIES}",
                site.label
            )),
            Err(e) => out.push(format!("{}: retries {e}", site.label)),
        }
    }
    out
}

/// Every workflow and composite action file, as (label, text).
fn ci_files() -> Result<Vec<(String, String)>, TestError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(repo().join(".github/workflows"))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yml") {
            let name = path.file_name().and_then(|n| n.to_str()).ok_or("name")?;
            out.push((
                format!(".github/workflows/{name}"),
                std::fs::read_to_string(&path)?,
            ));
        }
    }
    for entry in std::fs::read_dir(repo().join(".github/actions"))? {
        let dir = entry?.path();
        let action = dir.join("action.yml");
        if action.exists() {
            let name = dir.file_name().and_then(|n| n.to_str()).ok_or("name")?;
            out.push((
                format!(".github/actions/{name}/action.yml"),
                std::fs::read_to_string(&action)?,
            ));
        }
    }
    out.sort();
    Ok(out)
}

#[test]
fn every_ci_pip_install_has_a_longer_timeout_and_more_retries() -> Result<(), TestError> {
    let mut all = Scan::default();
    for (file, text) in ci_files()? {
        let found = scan(&file, &text);
        all.sites.extend(found.sites);
        all.unmodeled.extend(found.unmodeled);
    }
    assert!(
        !all.sites.is_empty(),
        "no `pip install` found in .github; the scan is wrong and this gate \
         proves nothing"
    );
    let problems = defects(&all);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    // One rule: every site uses the same values, so a change in one
    // workflow cannot leave another behind.
    let mut values: Vec<String> = all
        .sites
        .iter()
        .map(|s| format!("{:?}/{:?}", s.timeout, s.retries))
        .collect();
    values.sort();
    values.dedup();
    assert_eq!(
        values.len(),
        1,
        "pip timeout/retries differ between sites: {:#?}",
        all.sites
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The scanner, on fixtures that place the settings in each scope.
// ---------------------------------------------------------------------------

const BARE: &str = "\
name: t
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install
        run: |
          python3 -m venv .v
          # pip install in a comment is not a command
          .v/bin/python -m pip install -r r.txt
";

fn one(text: &str) -> Result<Site, TestError> {
    let mut s = scan(".github/workflows/t.yml", text);
    assert!(s.unmodeled.is_empty(), "{:?}", s.unmodeled);
    assert_eq!(s.sites.len(), 1, "{:?}", s.sites);
    s.sites.pop().ok_or_else(|| "no site".into())
}

#[test]
fn an_unguarded_install_is_named_by_file_job_and_step() -> Result<(), TestError> {
    let site = one(BARE)?;
    assert_eq!(
        site.label,
        ".github/workflows/t.yml:build:Install (line 11)"
    );
    let d = defects(&Scan {
        sites: vec![site],
        unmodeled: vec![],
    });
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d[0].contains("timeout unset"), "{d:?}");
    assert!(d[1].contains("retries unset"), "{d:?}");
    Ok(())
}

#[test]
fn workflow_env_reaches_every_job() -> Result<(), TestError> {
    let text = format!("env:\n  PIP_TIMEOUT: 60\n  PIP_RETRIES: '8'\n{BARE}");
    let site = one(&text)?;
    assert_eq!(site.timeout, Ok(60.0));
    assert_eq!(site.retries, Ok(8));
    Ok(())
}

#[test]
fn job_env_applies_and_step_env_overrides_it() -> Result<(), TestError> {
    let job = BARE.replace(
        "    runs-on: ubuntu-latest\n",
        "    runs-on: ubuntu-latest\n    env:\n      PIP_DEFAULT_TIMEOUT: 45\n      PIP_RETRIES: 9\n",
    );
    let site = one(&job)?;
    assert_eq!(site.timeout, Ok(45.0));
    assert_eq!(site.retries, Ok(9));
    let step = job.replace(
        "      - name: Install\n",
        "      - name: Install\n        env:\n          PIP_RETRIES: 3\n",
    );
    let site = one(&step)?;
    assert_eq!(site.retries, Ok(3), "the step's lower value must win");
    let d = defects(&Scan {
        sites: vec![site],
        unmodeled: vec![],
    });
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(d[0].contains("retries 3 is not above"), "{d:?}");
    Ok(())
}

#[test]
fn another_jobs_env_does_not_count() -> Result<(), TestError> {
    let text = BARE.replace(
        "jobs:\n",
        "jobs:\n  other:\n    runs-on: x\n    env:\n      PIP_TIMEOUT: 60\n      PIP_RETRIES: 8\n    steps:\n      - run: true\n",
    );
    let site = one(&text)?;
    assert!(site.timeout.is_err() && site.retries.is_err(), "{site:?}");
    Ok(())
}

#[test]
fn flags_override_env_including_continued_lines() -> Result<(), TestError> {
    let text = format!(
        "env:\n  PIP_TIMEOUT: 60\n  PIP_RETRIES: 8\n{}",
        BARE.replace(
            "-m pip install -r r.txt",
            "-m pip install \\\n            --timeout=10 --retries 2 -r r.txt"
        )
    );
    let site = one(&text)?;
    assert_eq!(site.timeout, Ok(10.0));
    assert_eq!(site.retries, Ok(2));
    Ok(())
}

#[test]
fn two_timeout_names_that_disagree_are_ambiguous() -> Result<(), TestError> {
    let text =
        format!("env:\n  PIP_TIMEOUT: 60\n  PIP_DEFAULT_TIMEOUT: 30\n  PIP_RETRIES: 8\n{BARE}");
    let site = one(&text)?;
    let err = site.timeout.err().ok_or("expected ambiguity")?;
    assert!(err.contains("ambiguous"), "{err}");
    Ok(())
}

#[test]
fn single_line_run_and_pip3_are_found() -> Result<(), TestError> {
    let text = "jobs:\n  j:\n    steps:\n      - run: pip3 install x\n";
    let site = one(text)?;
    assert_eq!(
        site.label,
        ".github/workflows/t.yml:j:step at line 4 (line 4)"
    );
    Ok(())
}

#[test]
fn a_step_name_mentioning_pip_install_is_not_a_command() {
    let text = "jobs:\n  j:\n    steps:\n      - name: pip install deps\n        run: true\n";
    let s = scan(".github/workflows/t.yml", text);
    assert!(s.sites.is_empty(), "{:?}", s.sites);
}

#[test]
fn a_composite_action_needs_its_own_settings() -> Result<(), TestError> {
    let text = "\
env:
  PIP_TIMEOUT: 60
  PIP_RETRIES: 8
runs:
  using: composite
  steps:
    - shell: bash
      run: python3 -m pip install x
    - shell: bash
      env:
        PIP_TIMEOUT: 60
        PIP_RETRIES: 8
      run: python3 -m pip install y
";
    let s = scan(".github/actions/a/action.yml", text);
    assert_eq!(s.sites.len(), 2, "{:?}", s.sites);
    assert!(s.sites[0].timeout.is_err(), "{:?}", s.sites[0]);
    assert_eq!(s.sites[1].timeout, Ok(60.0));
    assert_eq!(s.sites[1].retries, Ok(8));
    assert!(
        s.sites[0]
            .label
            .starts_with(".github/actions/a/action.yml:runs:")
    );
    Ok(())
}

#[test]
fn installers_that_ignore_pip_settings_are_reported() {
    for cmd in ["uv pip install x", "uvx ruff", "pipx install codespell"] {
        let text = format!("jobs:\n  j:\n    steps:\n      - run: {cmd}\n");
        let s = scan(".github/workflows/t.yml", &text);
        assert_eq!(s.unmodeled.len(), 1, "{cmd}: {:?}", s.unmodeled);
    }
}
