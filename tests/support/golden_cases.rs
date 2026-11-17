// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A runner for the `.trycmd` golden files under `tests/cli/`.
//!
//! RUSTSEC-2026-0542 (humantime unmaintained) reached the tree only through
//! the `trycmd` dev-dependency. This module reads the subset of its format the
//! goldens use, and reads it strictly:
//!
//! - A case is a `$ ` line inside a fence (```` ``` ````, ```` ```console ````
//!   or ```` ```trycmd ````); its expected output is every line after it up to
//!   the next `$ ` line or the closing fence. A `? success`, `? failed` or
//!   `? <code>` line right after the command sets the expected exit status;
//!   without one the command must exit 0.
//! - Expected output matches line by line after CRLF becomes LF and every
//!   backslash in the output becomes `/` (trycmd's path normalization); trailing
//!   empty lines on either side are not compared, as trycmd did not compare
//!   them. `[..]` inside a line matches any text on that line;
//!   a line that is exactly `...` matches zero or more lines. Any other text,
//!   `[CRITICAL]` included, is literal.
//! - The command is split as a POSIX shell splits words (single quotes,
//!   double quotes with `\"`/`\\`/`\$`/`` \` `` escapes, backslash outside
//!   quotes), and its first word must be a registered program.
//! - A file with no case, an unclosed fence, an unknown fence, output before a
//!   command, an unknown status or an unregistered program is an error: a
//!   golden that is skipped must never read as one that passed.
//!
//! stdout and stderr go to one pipe, so the output is in write order, as
//! trycmd recorded it. `TRYCMD=overwrite` rewrites the output of every case
//! that does not match, and keeps every case that does (wildcards included).

#![allow(dead_code)]

use std::io::Read;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The exit status a case expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Success,
    Failed,
    Code(i32),
}

/// One `$ ` command of a case file.
#[derive(Debug, Clone)]
pub struct Case {
    /// 1-based line of the `$ ` line.
    pub line: usize,
    pub argv: Vec<String>,
    pub status: Status,
    pub expected: Vec<String>,
    /// 0-based line indexes of the expected output in the file.
    pub output_lines: Range<usize>,
}

/// Every case of a `.trycmd` file's text.
pub fn parse(text: &str) -> Result<Vec<Case>, String> {
    let all: Vec<&str> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    // A final newline leaves one empty element that is not a line.
    let n = if text.ends_with('\n') {
        all.len() - 1
    } else {
        all.len()
    };
    let mut cases: Vec<Case> = Vec::new();
    let mut in_fence = false;
    let mut fence_line = 0;
    for (i, line) in all.iter().take(n).enumerate() {
        if let Some(info) = line.strip_prefix("```") {
            if in_fence {
                if !info.trim().is_empty() {
                    return Err(format!("line {}: a closing fence carries `{info}`", i + 1));
                }
                in_fence = false;
                continue;
            }
            let info = info.trim();
            if !matches!(info, "" | "console" | "trycmd") {
                return Err(format!("line {}: unknown fence ```{info}", i + 1));
            }
            in_fence = true;
            fence_line = i + 1;
            continue;
        }
        if !in_fence {
            continue;
        }
        if let Some(command) = line.strip_prefix("$ ") {
            if command.trim().is_empty() {
                return Err(format!("line {}: an empty command", i + 1));
            }
            let argv = split_command(command).map_err(|e| format!("line {}: {e}", i + 1))?;
            cases.push(Case {
                line: i + 1,
                argv,
                status: Status::Success,
                expected: Vec::new(),
                output_lines: i + 1..i + 1,
            });
            continue;
        }
        let Some(case) = cases.last_mut().filter(|c| c.line > fence_line) else {
            return Err(format!(
                "line {}: output before any `$ ` command in the fence",
                i + 1
            ));
        };
        // A status line counts only right after the command.
        if case.expected.is_empty()
            && case.output_lines.start == i
            && case.output_lines.start == case.line
            && let Some(status) = line.strip_prefix("? ")
        {
            case.status = match status.trim() {
                "success" => Status::Success,
                "failed" => Status::Failed,
                code => Status::Code(
                    code.parse()
                        .map_err(|_| format!("line {}: unknown status `{code}`", i + 1))?,
                ),
            };
            case.output_lines = i + 1..i + 1;
            continue;
        }
        case.expected.push((*line).to_string());
        case.output_lines.end = i + 1;
    }
    if in_fence {
        return Err(format!("line {fence_line}: the fence is not closed"));
    }
    if cases.is_empty() {
        return Err("no `$ ` command in a fence".to_string());
    }
    Ok(cases)
}

/// Words of a command line, as a POSIX shell splits them.
pub fn split_command(s: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => word.push(ch),
                        None => return Err("an unterminated single quote".to_string()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(ch @ ('"' | '\\' | '$' | '`')) => word.push(ch),
                            Some(ch) => {
                                word.push('\\');
                                word.push(ch);
                            }
                            None => return Err("an unterminated double quote".to_string()),
                        },
                        Some(ch) => word.push(ch),
                        None => return Err("an unterminated double quote".to_string()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.push(chars.next().ok_or("a trailing backslash")?);
            }
            ch => {
                in_word = true;
                word.push(ch);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

/// Whether one actual line matches one expected line: `[..]` matches any
/// text, everything else is literal and the whole line is anchored.
pub fn line_matches(pattern: &str, actual: &str) -> bool {
    let parts: Vec<&str> = pattern.split("[..]").collect();
    if parts.len() == 1 {
        return pattern == actual;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !actual.starts_with(first)
        || actual.len() < first.len() + last.len()
        || !actual.ends_with(last)
    {
        return false;
    }
    let mut rest = &actual[first.len()..actual.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

/// The lines of a command's output: CRLF as LF, every `\` as `/`, one final
/// newline dropped. trycmd normalized paths that way before comparing and
/// before writing a golden, so no golden holds a backslash: a JSON `\"`
/// is stored as `/"`.
pub fn normalize(actual: &str) -> Vec<String> {
    let text = actual.replace("\r\n", "\n").replace('\\', "/");
    let text = text.strip_suffix('\n').unwrap_or(&text);
    if text.is_empty() && !actual.contains('\n') {
        return Vec::new();
    }
    text.split('\n').map(str::to_string).collect()
}

/// Whether `actual` output matches the expected lines; a line `...` matches
/// zero or more lines.
pub fn output_matches(expected: &[String], actual: &str) -> bool {
    fn from(e: &[String], a: &[String]) -> bool {
        match e.first() {
            None => a.is_empty(),
            Some(line) if line == "..." => (0..=a.len()).any(|skip| from(&e[1..], &a[skip..])),
            Some(line) => {
                a.first().is_some_and(|got| line_matches(line, got)) && from(&e[1..], &a[1..])
            }
        }
    }
    // Trailing empty lines are not compared, on either side: trycmd wrote a
    // blank line before the closing fence of most goldens, and it did not
    // compare them either (all 98 passed under it with that line present).
    fn trimmed(lines: &[String]) -> &[String] {
        let end = lines
            .iter()
            .rposition(|l| !l.is_empty())
            .map_or(0, |i| i + 1);
        &lines[..end]
    }
    from(trimmed(expected), trimmed(&normalize(actual)))
}

/// Whether an exit code meets the expected status; None is a signal.
pub fn status_ok(status: &Status, code: Option<i32>) -> bool {
    match status {
        Status::Success => code == Some(0),
        Status::Failed => code.is_some_and(|c| c != 0),
        Status::Code(want) => code == Some(*want),
    }
}

/// `text` with the output of each case given `Some(output)` replaced by it.
pub fn overwrite(text: &str, cases: &[Case], outputs: &[Option<String>]) -> String {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    for (case, output) in cases.iter().zip(outputs).rev() {
        if let Some(output) = output {
            let new = normalize(output);
            lines.splice(case.output_lines.clone(), new);
        }
    }
    lines.join("\n")
}

include!("child_lifetime.rs");

/// How a case's command runs: the programs a case may name, the environment
/// added to the inherited one, the working directory and the deadline of
/// each case (its output included).
pub struct Runner {
    pub bins: Vec<(String, PathBuf)>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub deadline: Duration,
}

impl Runner {
    /// The case's combined output and exit code (None when a signal ended it).
    pub fn run_case(&self, case: &Case) -> Result<(String, Option<i32>), String> {
        let name = &case.argv[0];
        let program = self
            .bins
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| p.clone())
            .ok_or_else(|| format!("`{name}` is not a registered program"))?;
        let (mut reader, writer) = std::io::pipe().map_err(|e| format!("a pipe: {e}"))?;
        let mut command = Command::new(&program);
        command
            .args(&case.argv[1..])
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .stdout(writer.try_clone().map_err(|e| format!("a pipe: {e}"))?)
            .stderr(writer);
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let mut child = command
            .tied_to_test()
            .spawn()
            .map_err(|e| format!("start {}: {e}", program.display()))?;
        // The parent's copies of the write end go with the command.
        drop(command);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = reader.read_to_end(&mut out);
            let _ = tx.send(out);
        });
        let started = Instant::now();
        let past = || {
            format!(
                "`{}` ran past its deadline of {:?} and was ended",
                case.argv.join(" "),
                self.deadline
            )
        };
        let status = loop {
            match child.try_wait().map_err(|e| format!("wait: {e}"))? {
                Some(status) => break status,
                None if started.elapsed() >= self.deadline => {
                    end_group(&child);
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(past());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        // A process the command left behind can hold the pipe open; the
        // output is bounded by the same deadline.
        let left = self.deadline.saturating_sub(started.elapsed());
        match rx.recv_timeout(left) {
            Ok(out) => Ok((String::from_utf8_lossy(&out).into_owned(), status.code())),
            Err(_) => {
                end_group(&child);
                Err(past())
            }
        }
    }

    /// Every case of every file; the failures, each naming its file and line.
    /// With `overwrite`, a case that does not match is rewritten instead.
    pub fn run_files(&self, files: &[PathBuf], overwrite_mode: bool) -> Vec<String> {
        if files.is_empty() {
            return vec!["no .trycmd case file was found".to_string()];
        }
        let mut failures = Vec::new();
        for file in files {
            let text = match std::fs::read_to_string(file) {
                Ok(t) => t,
                Err(e) => {
                    failures.push(format!("{}: {e}", file.display()));
                    continue;
                }
            };
            let cases = match parse(&text) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("{}: {e}", file.display()));
                    continue;
                }
            };
            let mut rewrite: Vec<Option<String>> = Vec::new();
            for case in &cases {
                let at = format!("{}:{}", file.display(), case.line);
                match self.run_case(case) {
                    Err(e) => {
                        failures.push(format!("{at}: {e}"));
                        rewrite.push(None);
                    }
                    Ok((output, code)) => {
                        let matched = output_matches(&case.expected, &output);
                        if !status_ok(&case.status, code) {
                            failures.push(format!(
                                "{at}: exit {code:?}, expected {:?}\n{output}",
                                case.status
                            ));
                        }
                        if matched {
                            rewrite.push(None);
                        } else if overwrite_mode {
                            rewrite.push(Some(output));
                        } else {
                            failures.push(format!(
                                "{at}: output differs\n--- expected\n{}\n--- actual\n{output}",
                                case.expected.join("\n")
                            ));
                            rewrite.push(None);
                        }
                    }
                }
            }
            if overwrite_mode
                && rewrite.iter().any(Option::is_some)
                && let Err(e) = std::fs::write(file, overwrite(&text, &cases, &rewrite))
            {
                failures.push(format!("{}: write: {e}", file.display()));
            }
        }
        failures
    }
}

/// The `*.trycmd` files of `dir`, sorted.
pub fn case_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("list {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "trycmd"))
        .collect();
    out.sort();
    Ok(out)
}

/// Whether `TRYCMD=overwrite` asks for the goldens to be rewritten.
pub fn overwrite_requested() -> bool {
    std::env::var("TRYCMD").is_ok_and(|v| v == "overwrite")
}

/// End the case's whole process group: the child leads it (process_group(0)
/// above), so a process it started goes too.
fn end_group(child: &std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
