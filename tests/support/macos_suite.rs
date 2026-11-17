// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
//
// The rule that keeps the whole suite running on macOS, read from the text of
// .github/workflows/ci.yml. Included (`include!`) by the tests that hold it,
// so the rule is written once.
//
// The suite ran whole inside `check-macos` until 2026-11-16, when main's CI
// run 43880888975 canceled "Check (macos-26)" at its 45-minute cap: the
// suite step alone took 38.2 of the job's 45.5 minutes (22.3 to 38.2 over the
// four runs before it), against 2.9 to 4.6 for Clippy. It now runs in shards,
// as on Linux, in the macOS-only job `test-macos`, through the `test` job's
// own steps.

/// The cap no macOS suite job may exceed: the cap `check-macos` had when it
/// ran the suite. The fix was to split the work, not to raise the cap.
const MACOS_SUITE_CAP_MINUTES: u32 = 45;

/// The jobs of a workflow's text, as (id, body) in file order. A job starts
/// at a two-space-indented `id:` line under `jobs:`; comment lines are left
/// out of each body, so a name in a comment is never read as a setting.
fn macos_suite_jobs(ci: &str) -> Vec<(String, Vec<String>)> {
    let mut jobs: Vec<(String, Vec<String>)> = Vec::new();
    let mut in_jobs = false;
    // `lines` also ends a line at "\r\n".
    for line in ci.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_jobs = line == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        // A deeper line keeps a space after the two, which no id holds.
        let header = line
            .strip_prefix("  ")
            .and_then(|r| r.strip_suffix(':'))
            .filter(|id| {
                !id.is_empty()
                    && id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            });
        match (header, jobs.last_mut()) {
            (Some(id), _) => jobs.push((id.to_string(), Vec::new())),
            (None, Some((_, body))) => body.push(line.to_string()),
            (None, None) => {}
        }
    }
    jobs
}

/// The values of a matrix list `key: [a, b]` in a job body; `Err` when the
/// line is there but is not such a list.
fn macos_suite_list(body: &[String], key: &str) -> Option<Result<Vec<String>, String>> {
    let prefix = format!("        {key}: ");
    let value = body.iter().find_map(|l| l.strip_prefix(&prefix))?;
    let Some(inner) = value
        .trim()
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
    else {
        return Some(Err(value.to_string()));
    };
    // An empty item (`[1, 2,]`) stays in the list, where it matches no image
    // and parses as no shard number.
    Some(Ok(inner
        .split(',')
        .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"').to_string())
        .collect()))
}

/// The lines of the step named exactly `name` in a job body, from its
/// `- name:` line to the next line indented less than the step's fields
/// (the next step's `- ` line or the end of the steps).
fn macos_suite_step<'a>(body: &'a [String], name: &str) -> Option<&'a [String]> {
    let head = format!("      - name: {name}");
    let start = body.iter().position(|l| *l == head)?;
    let len = body[start + 1..]
        .iter()
        .position(|l| !l.starts_with("        "))
        .unwrap_or(body.len() - start - 1);
    Some(&body[start..=start + len])
}

/// Every problem with the macOS suite's layout in `ci` (the workflow's text);
/// empty when the layout holds.
#[allow(dead_code)]
fn macos_suite_problems(ci: &str) -> Vec<String> {
    let jobs = macos_suite_jobs(ci);
    let find = |id: &str| jobs.iter().find(|(j, _)| j == id).map(|(_, b)| b);
    let mut problems = Vec::new();
    let Some(test) = find("test") else {
        problems.push("ci.yml has no job `test`, whose steps the macOS suite runs".to_string());
        return problems;
    };
    if !test.iter().any(|l| l == "    steps: &test-steps") {
        problems.push("`test` does not define its steps as the anchor &test-steps".to_string());
    }
    match macos_suite_step(test, "Test") {
        None => problems.push("the `test` job has no step named Test".to_string()),
        Some(step) => {
            let text = step.join("\n");
            for needle in [
                "python3 scripts/parallel-tests.py",
                "--shard-index ${{ strategy.job-index }}",
                "--shard-count ${{ strategy.job-total }}",
                "-- --all-features",
            ] {
                if !text.contains(needle) {
                    problems.push(format!("the Test step lacks `{needle}`:\n{text}"));
                }
            }
            for (needle, shown) in [("--skip", "--skip"), (" -E ", "-E")] {
                if text.contains(needle) {
                    problems.push(format!("the Test step leaves tests out with `{shown}`"));
                }
            }
            if step.iter().any(|l| l.starts_with("        if:")) {
                problems.push(
                    "the Test step has an `if:`, which would skip the suite on one OS".to_string(),
                );
            }
        }
    }
    if find("check").is_some_and(|check| check.iter().any(|l| l.contains("parallel-tests.py"))) {
        problems
            .push("`check` runs parallel-tests.py, so macOS would run the suite twice".to_string());
    }
    let Some(mac) = find("test-macos") else {
        problems.push("ci.yml has no job `test-macos`, the macOS suite in shards".to_string());
        return problems;
    };
    if !mac.iter().any(|l| l == "    steps: *test-steps") {
        problems.push(
            "`test-macos` does not run the `test` job's steps through *test-steps".to_string(),
        );
    }
    match macos_suite_list(mac, "os") {
        Some(Ok(os)) if os == ["macos-26"] => {}
        other => problems.push(format!(
            "`test-macos` must run on macos-26 alone, not {other:?}"
        )),
    }
    match macos_suite_list(mac, "shard") {
        None => problems.push("`test-macos` has no shard list".to_string()),
        Some(Err(v)) => problems.push(format!("the shard list {v:?} is not a list of numbers")),
        Some(Ok(items)) => match items
            .iter()
            .map(|s| s.parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
        {
            Err(_) => problems.push(format!("the shard list {items:?} is not a list of numbers")),
            Ok(mut shards) => {
                let n = shards.len();
                shards.sort_unstable();
                let want: Vec<u32> = (1..).take(n).collect();
                if shards != want {
                    problems.push(format!(
                        "shards {items:?} must be numbered 1 to N, each once"
                    ));
                }
                if n < 2 {
                    problems.push("`test-macos` needs at least two shards".to_string());
                }
            }
        },
    }
    match mac
        .iter()
        .find_map(|l| l.strip_prefix("    timeout-minutes: "))
        .map(|v| v.trim().parse::<u32>())
    {
        Some(Ok(m)) if m > MACOS_SUITE_CAP_MINUTES => problems.push(format!(
            "`test-macos` has timeout-minutes {m}, above the {MACOS_SUITE_CAP_MINUTES}-minute cap"
        )),
        Some(Ok(_)) => {}
        _ => problems.push("`test-macos` has no timeout-minutes number".to_string()),
    }
    for field in ["if:", "continue-on-error:"] {
        if mac.iter().any(|l| l.starts_with(&format!("    {field}"))) {
            problems.push(format!("`test-macos` has a job-level `{field}`"));
        }
    }
    problems
}
