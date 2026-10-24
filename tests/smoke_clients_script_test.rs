// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every background job in `scripts/smoke-clients.sh` writes to a log that
//! exists before the job starts.
//!
//! `cmd 2>"$WORK/x.log" &` opens the log in the forked child, after the fork,
//! so the script can read the log before it exists. The HTTP MCP check polls
//! its log with `sed` for the port sipnab binds, and under `set -e` a `sed` on
//! a missing file ended the script: on 2026-10-24 the Check job on main
//! failed with `sed: can't read .../mcp-http.log`. A loop of that shape fails
//! about 8% of the time.
//!
//! What this test holds: every job the script starts in the background with
//! its output redirected into `$WORK` has that file created, with
//! `: >"$WORK/..."`, on an earlier line. The pre-commit hook does the same
//! for its own test log.

use std::path::PathBuf;

type TestError = Box<dyn std::error::Error>;

fn read(rel: &str) -> Result<String, TestError> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    Ok(std::fs::read_to_string(&path).map_err(|e| format!("read {rel}: {e}"))?)
}

/// For each line of `script` that starts a job in the background, the
/// `$WORK` paths it redirects into, with the line's number.
fn background_logs(script: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in script.lines().enumerate() {
        let code = line.trim();
        if code.starts_with('#') || !code.ends_with('&') || code.ends_with("&&") {
            continue;
        }
        let mut rest = code;
        while let Some(at) = rest.find(">\"$WORK/") {
            let path_start = at + 2;
            let Some(len) = rest[path_start..].find('"') else {
                break;
            };
            out.push((n + 1, rest[path_start..path_start + len].to_string()));
            rest = &rest[path_start + len..];
        }
    }
    out
}

/// Whether a line before `line` (1-based) creates `path` with `: >"path"`.
fn created_before(script: &str, line: usize, path: &str) -> bool {
    let create = format!(": >\"{path}\"");
    script
        .lines()
        .take(line - 1)
        .any(|l| !l.trim().starts_with('#') && l.trim() == create)
}

#[test]
fn every_background_log_exists_before_its_job_starts() -> Result<(), TestError> {
    let script = read("scripts/smoke-clients.sh")?;
    let logs = background_logs(&script);
    assert!(
        logs.len() >= 2,
        "found {} background job log(s) ({logs:?}); the REST servers and the \
         HTTP MCP server are two, so the reader has stopped matching",
        logs.len()
    );
    let missing: Vec<&(usize, String)> = logs
        .iter()
        .filter(|(line, path)| !created_before(&script, *line, path))
        .collect();
    assert!(
        missing.is_empty(),
        "scripts/smoke-clients.sh starts these jobs in the background without \
         creating their log first, so a read of the log can find no file and \
         end the script under set -e (line, log): {missing:?}"
    );
    Ok(())
}

#[test]
fn the_reader_finds_background_logs_and_their_creation() -> Result<(), TestError> {
    let script = "# cmd 2>\"$WORK/commented.log\" &\n\
                  : >\"$WORK/a.log\"\n\
                  cmd >/dev/null 2>\"$WORK/a.log\" &\n\
                  cmd 2>\"$WORK/b.log\" &\n\
                  cmd 2>\"$WORK/c.log\" && next\n";
    let logs = background_logs(script);
    assert_eq!(
        logs,
        vec![
            (3, "$WORK/a.log".to_string()),
            (4, "$WORK/b.log".to_string())
        ]
    );
    assert!(created_before(script, 3, "$WORK/a.log"));
    assert!(!created_before(script, 4, "$WORK/b.log"));
    assert!(
        !created_before(script, 2, "$WORK/a.log"),
        "the creation must come before the job's line"
    );
    Ok(())
}
