// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every `actions/checkout` keeps the job's token out of `.git/config`.
//!
//! checkout leaves the token there for later git commands unless the step
//! sets `persist-credentials: false`, and every later step in the job,
//! third-party actions included, can then read it. No checkout here needs
//! it: the wiki-sync job pushes the wiki with the token in the push URL,
//! the release workflow's tap job clones the Homebrew tap with its own
//! token in the URL, and neither uses a checkout's stored credentials. A
//! checkout that does need the token sets `persist-credentials: true` and
//! records why on a comment line in the step:
//! `# keeps the token: <reason>`.
//!
//! The workflows and the composite actions under `.github/actions/` are
//! both read, so a checkout moved into a shared action is held to the same
//! rule.

use std::path::{Path, PathBuf};

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

/// Every workflow file and composite action, by repository path and text.
fn all_workflows() -> Result<Vec<(String, String)>, TestError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths: Vec<PathBuf> = Vec::new();
    let workflows = root.join(".github/workflows");
    for entry in std::fs::read_dir(&workflows)
        .map_err(|e| format!("read {}: {e}", workflows.display()))?
        .flatten()
    {
        paths.push(entry.path());
    }
    let actions = root.join(".github/actions");
    if let Ok(dirs) = std::fs::read_dir(&actions) {
        for dir in dirs.flatten() {
            for name in ["action.yml", "action.yaml"] {
                paths.push(dir.path().join(name));
            }
        }
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for p in paths
        .into_iter()
        .filter(|p| p.is_file())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
    {
        let name = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(&p).map_err(|e| format!("read {name}: {e}"))?;
        out.push((name, text));
    }
    out.sort();
    assert!(
        out.len() >= 10,
        "workflows not found under {}",
        workflows.display()
    );
    Ok(out)
}

/// The checkouts in one workflow that leave the job's token in
/// `.git/config` without a recorded reason, as `<file>:<line>`.
fn checkouts_keeping_the_token(file: &str, yaml: &str) -> Vec<String> {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut bad = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        if !line.contains("uses: actions/checkout@") {
            continue;
        }
        // The step begins at its `- ` line: this one in the `- uses:`
        // form, or the nearest one above in the `- name:` then `uses:`
        // form, where `with:` sits at the same indent as `uses:`.
        let indent_of = |l: &str| l.len() - l.trim_start().len();
        let start = (0..=n)
            .rev()
            .find(|&k| lines[k].trim_start().starts_with("- "))
            .unwrap_or(n);
        let dash = indent_of(lines[start]);
        let step: Vec<&str> = lines[start + 1..]
            .iter()
            .take_while(|l| l.trim().is_empty() || indent_of(l) > dash)
            .map(|l| l.trim())
            .collect();
        let off = step.contains(&"persist-credentials: false");
        let kept_with_reason = step.contains(&"persist-credentials: true")
            && step.iter().any(|l| {
                l.strip_prefix("# keeps the token:")
                    .is_some_and(|why| !why.trim().is_empty())
            });
        if !off && !kept_with_reason {
            bad.push(format!("{file}:{}", n + 1));
        }
    }
    bad
}

#[test]
fn no_checkout_leaves_the_token_without_a_reason() -> Result<(), TestError> {
    let bad: Vec<String> = all_workflows()?
        .iter()
        .flat_map(|(f, y)| checkouts_keeping_the_token(f, y))
        .collect();
    assert!(
        bad.is_empty(),
        "checkout without persist-credentials: false or a recorded reason:\n{}",
        bad.join("\n")
    );
    Ok(())
}

#[test]
fn the_composite_actions_are_read_too() -> Result<(), TestError> {
    let names: Vec<String> = all_workflows()?.into_iter().map(|(n, _)| n).collect();
    assert!(
        names.iter().any(|n| n.starts_with(".github/actions/")),
        "no composite action was read: {names:?}"
    );
    assert!(names.iter().any(|n| n == ".github/workflows/ci.yml"));
    Ok(())
}

#[test]
fn checkouts_keeping_the_token_reads_each_step() {
    let co = "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n";
    let next = "      - run: make\n";
    // off
    let y = format!("{co}        with:\n          persist-credentials: false\n{next}");
    assert!(checkouts_keeping_the_token("a.yml", &y).is_empty());
    // not said: the default keeps the token
    let y = format!("{co}{next}");
    assert_eq!(checkouts_keeping_the_token("a.yml", &y), ["a.yml:1"]);
    // the next step's setting does not count for this checkout
    let y = format!("{co}{next}        with:\n          persist-credentials: false\n");
    assert_eq!(checkouts_keeping_the_token("a.yml", &y), ["a.yml:1"]);
    // kept, but with no reason, or an empty one
    let y = format!("{co}        with:\n          persist-credentials: true\n{next}");
    assert_eq!(checkouts_keeping_the_token("a.yml", &y), ["a.yml:1"]);
    let y = format!(
        "{co}        # keeps the token:\n        with:\n          persist-credentials: true\n{next}"
    );
    assert_eq!(checkouts_keeping_the_token("a.yml", &y), ["a.yml:1"]);
    // the `- name:` then `uses:` form, with `with:` beside `uses:`
    let named = "      - name: Checkout\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n";
    let y = format!("{named}        with:\n          persist-credentials: false\n{next}");
    assert!(checkouts_keeping_the_token("a.yml", &y).is_empty());
    let y = format!("{named}{next}        with:\n          persist-credentials: false\n");
    assert_eq!(checkouts_keeping_the_token("a.yml", &y), ["a.yml:2"]);
    // kept, with its reason
    let y = format!(
        "{co}        # keeps the token: pushes the tag\n        with:\n          persist-credentials: true\n{next}"
    );
    assert!(checkouts_keeping_the_token("a.yml", &y).is_empty());
}
