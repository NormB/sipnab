// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A message that decides the exit code is printed on stderr, whatever the
//! log level.
//!
//! The log is a view the operator can turn off: `SIPNAB_LOG=off` silences
//! every `tracing` event. A refusal that goes through `tracing::error!` and
//! then exits therefore exits 1 or 2 with nothing on stderr, and the operator
//! cannot tell why the run stopped. The query refusals (5c26fb512) and the
//! missing-feature refusals were fixed one at a time; this file holds the
//! rule for the rest of startup and for the gate that keeps it.
//!
//! Two halves:
//!
//! * the binary, driven to each refusal at `SIPNAB_LOG=off` and at
//!   `SIPNAB_LOG=info`, must print the refusal exactly once and exit with its
//!   code. Exactly once at `info` is the negative control: printing the
//!   refusal and also logging it shows the operator the same line twice.
//! * a scan of `src/` refuses a `tracing::error!` whose statement is followed
//!   by a process exit or by the exit code a caller exits with. Several
//!   refusals cannot be driven from a test (the TUI's, which need a terminal;
//!   a thread that fails to spawn), so the scan is what holds them.

#![cfg(all(unix, feature = "full"))]

#[path = "support/source_scan.rs"]
mod source_scan;

use std::path::Path;
use std::process::{Command, Stdio};

type TestError = Box<dyn std::error::Error>;

/// A small capture every run case reads.
const PCAP: &str = "tests/fixtures/sip_call.pcap";

/// Where a case sends its standard output.
#[derive(Clone, Copy)]
enum Stdout {
    /// Discarded.
    Null,
    /// `/dev/full`: every write fails with `ENOSPC`.
    Full,
}

/// One refusal, driven from the command line.
struct Case {
    /// What the case is, for the assertion messages.
    label: &'static str,
    /// The arguments, with `{tmp}` standing for a fresh temporary directory.
    args: &'static [&'static str],
    /// The exit code the refusal carries.
    code: i32,
    /// Text the refusal names, which must appear on exactly one stderr line.
    needle: &'static str,
    /// Where standard output goes.
    stdout: Stdout,
}

/// Every refusal this file drives. Each reaches a different exit site.
const CASES: &[Case] = &[
    Case {
        label: "argument validation (Cli::validate)",
        args: &[
            "-N",
            "-I",
            PCAP,
            "--no-cli-print",
            "--business-hours",
            "garbage",
        ],
        code: 2,
        needle: "--business-hours",
        stdout: Stdout::Null,
    },
    Case {
        label: "an archive password source that cannot be read",
        args: &[
            "-N",
            "-I",
            PCAP,
            "--no-cli-print",
            "--archive-password-file",
            "{tmp}/absent-password",
        ],
        code: 2,
        needle: "absent-password",
        stdout: Stdout::Null,
    },
    Case {
        label: "the run provenance record",
        args: &[
            "-N",
            "-I",
            PCAP,
            "--no-cli-print",
            "--run-provenance-file",
            "{tmp}/no/such/dir/provenance.json",
        ],
        code: 2,
        needle: "provenance.json",
        stdout: Stdout::Null,
    },
    Case {
        label: "a plan refusal (PlanError::exit)",
        args: &["-N", "-I", "{tmp}/missing.pcap", "--no-cli-print"],
        code: 1,
        needle: "missing.pcap",
        stdout: Stdout::Null,
    },
    Case {
        label: "a refusal after the capture opened (PlanError::exit_after)",
        args: &[
            "-N",
            "-I",
            PCAP,
            "--no-cli-print",
            "--api",
            "127.0.0.1:0",
            "--api-tls-cert",
            "{tmp}/absent-cert.pem",
            "--api-tls-key",
            "{tmp}/absent-key.pem",
        ],
        code: 2,
        needle: "absent-cert.pem",
        stdout: Stdout::Null,
    },
    Case {
        label: "a signing key file that cannot be read",
        args: &[
            "-N",
            "-I",
            PCAP,
            "--no-cli-print",
            "--api",
            "127.0.0.1:0",
            "--api-signing-key-file",
            "{tmp}/absent-signing-key",
        ],
        code: 2,
        needle: "absent-signing-key",
        stdout: Stdout::Null,
    },
    Case {
        label: "a spool directory that cannot be read",
        args: &["--vcon-spool-status", PCAP],
        code: 1,
        needle: "--vcon-spool-status",
        stdout: Stdout::Null,
    },
    Case {
        label: "standard output that cannot be written (an immediate command)",
        args: &["--print-yang-module"],
        code: 1,
        needle: "--print-yang-module",
        stdout: Stdout::Full,
    },
    Case {
        label: "standard output that cannot be written (a run's answer)",
        args: &["-N", "-I", PCAP],
        code: 1,
        needle: "Failed to write output",
        stdout: Stdout::Full,
    },
];

/// Run `case` at log level `level` and return its exit code and stderr.
fn run(case: &Case, level: &str, tmp: &Path) -> Result<(Option<i32>, String), TestError> {
    let tmp = tmp.to_str().ok_or("temporary directory is not UTF-8")?;
    let args: Vec<String> = case.args.iter().map(|a| a.replace("{tmp}", tmp)).collect();
    let stdout = match case.stdout {
        Stdout::Null => Stdio::null(),
        Stdout::Full => Stdio::from(std::fs::OpenOptions::new().write(true).open("/dev/full")?),
    };
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(&args)
        .env("SIPNAB_LOG", level)
        .env("NO_COLOR", "1")
        .env("XDG_STATE_HOME", tmp)
        .env_remove("SIPNAB_CONFIG")
        .stdin(Stdio::null())
        .stdout(stdout)
        .output()?;
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Every refusal is on stderr exactly once with logging off, and exactly once
/// with logging on, and the run exits with the refusal's code.
#[test]
fn every_startup_refusal_is_on_stderr_exactly_once_at_any_log_level() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for case in CASES {
        for level in ["off", "info"] {
            let tmp = tempfile::tempdir()?;
            let (code, stderr) = run(case, level, tmp.path())?;
            let lines = stderr.lines().filter(|l| l.contains(case.needle)).count();
            if code != Some(case.code) || lines != 1 {
                failures.push(format!(
                    "{} at SIPNAB_LOG={level}: exit {code:?} (want {}), {lines} line(s) \
                     naming {:?} (want 1); stderr:\n{stderr}",
                    case.label, case.code, case.needle
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n---\n"));
    Ok(())
}

// ── The source gate ─────────────────────────────────────────────────

/// One `error!` call whose statement is followed by an exit.
#[derive(Debug, PartialEq, Eq)]
struct Finding {
    /// 1-based line of the `error!` call.
    line: usize,
    /// The line that exits, trimmed.
    exit: String,
}

/// How far past an `error!` statement an exit still belongs to it: the rest
/// of the enclosing block, at most this many lines. `PlanError::exit_after`
/// runs a cleanup between the two.
const FOLLOWING_LINES: usize = 3;

/// The byte ranges of `src` that are code: comments, string literals and
/// character literals are blanked to spaces, newlines kept, so offsets and
/// line numbers are the file's own.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let blank = |c: u8| if c == b'\n' { b'\n' } else { b' ' };
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend(b"  ");
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == b'r'
            && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            // A raw string: r"..." or r#"..."#.
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            out.extend(std::iter::repeat_n(b' ', j + 1 - i));
            i = j + 1;
            while i < b.len() {
                let closes = b[i] == b'"'
                    && b.len() > i + hashes
                    && b[i + 1..=i + hashes].iter().all(|&h| h == b'#');
                if closes {
                    out.extend(std::iter::repeat_n(b' ', hashes + 1));
                    i += hashes + 1;
                    break;
                }
                out.push(blank(b[i]));
                i += 1;
            }
        } else if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < b.len() {
                if b[i] == b'\\' {
                    out.push(b' ');
                    if let Some(&n) = b.get(i + 1) {
                        out.push(blank(n));
                    }
                    i += 2;
                } else if b[i] == b'"' {
                    out.push(b' ');
                    i += 1;
                    break;
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == b'\'' {
            // A character literal ('x', '\n', '\''), or a lifetime ('a).
            let len = if b.get(i + 1) == Some(&b'\\') {
                b[i + 2..].iter().position(|&x| x == b'\'').map(|p| p + 3)
            } else if b.get(i + 2) == Some(&b'\'') {
                Some(3)
            } else {
                None
            };
            match len {
                Some(n) => {
                    out.extend(std::iter::repeat_n(b' ', n));
                    i += n;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether a trimmed line of code exits the process or is the exit code its
/// block hands back.
fn is_exit(line: &str) -> bool {
    if line.contains("release_run_and_exit(") || line.contains("process::exit(") {
        return true;
    }
    // A failure flag the run's exit code reads later: `lp.output_failed =
    // true;`, `self.failed = true;`.
    if let Some(target) = line.strip_suffix(" = true;") {
        let name = target.rsplit('.').next().unwrap_or(target);
        if name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') && name.contains("fail") {
            return true;
        }
    }
    // A bare exit code as the block's value or its return: `2`, `Some(2)`,
    // `return 1;`, `return Some(1);`.
    let value = line.strip_prefix("return ").unwrap_or(line);
    let value = value.strip_suffix(';').unwrap_or(value).trim();
    let value = value
        .strip_prefix("Some(")
        .and_then(|v| v.strip_suffix(')'))
        .unwrap_or(value);
    !value.is_empty() && value.len() <= 3 && value.bytes().all(|b| b.is_ascii_digit())
}

/// Every `error!` call in `src` (a Rust file's production part) whose
/// statement is followed, within the enclosing block, by an exit.
fn findings(src: &str) -> Vec<Finding> {
    let code = code_only(src);
    let bytes = code.as_bytes();
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find("error!(").map(|p| p + from) {
        from = at + "error!(".len();
        let preceded_by_ident = at > 0 && {
            let p = bytes[at - 1];
            p.is_ascii_alphanumeric() || p == b'_'
        };
        if preceded_by_ident {
            continue;
        }
        // The matching close of the macro's parentheses.
        let mut depth = 0usize;
        let mut end = None;
        for (k, &c) in bytes.iter().enumerate().skip(at + "error!".len()) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let line = code[..at].matches('\n').count() + 1;
        let rest = &code[end + 1..];
        let following = rest
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .take_while(|l| !l.starts_with('}'))
            .take(FOLLOWING_LINES);
        for l in following {
            if is_exit(l) {
                found.push(Finding {
                    line,
                    exit: l.to_string(),
                });
                break;
            }
        }
    }
    found
}

/// The tracked Rust files under `src/`, from the index rather than the disk,
/// with the hook's git variables removed so a run under `git commit` lists
/// this tree.
fn tracked_sources() -> Result<Vec<String>, TestError> {
    let out = Command::new("git")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["ls-files", "-z", "--", "src/*.rs"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_PREFIX")
        .env_remove("GIT_COMMON_DIR")
        .output()?;
    if !out.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(out.stdout)?
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect())
}

/// No production `error!` is followed by the exit it explains.
#[test]
fn no_refusal_that_decides_the_exit_code_goes_through_the_log() -> Result<(), TestError> {
    let files = tracked_sources()?;
    assert!(
        files.len() > 100,
        "expected the tree's sources, listed {}",
        files.len()
    );
    let mut all = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path))?;
        for f in findings(source_scan::production_source(&text)) {
            all.push(format!("{path}:{}: then `{}`", f.line, f.exit));
        }
    }
    assert!(
        all.is_empty(),
        "{} refusal(s) go through tracing::error! and then exit; SIPNAB_LOG=off \
         hides them. Print the refusal on stderr instead (stderr_line!, or \
         PlanError, whose exit prints it):\n{}",
        all.len(),
        all.join("\n")
    );
    Ok(())
}

/// The scan finds each shape of the defect.
#[test]
fn the_scan_finds_an_error_followed_by_an_exit() {
    let cases: &[(&str, &str)] = &[
        (
            "fn a() {\n    tracing::error!(\"{msg}\");\n    crate::capture::archive::release_run_and_exit(2);\n}\n",
            "crate::capture::archive::release_run_and_exit(2);",
        ),
        (
            "fn a() {\n    error!(\"x\");\n    std::process::exit(2);\n}\n",
            "std::process::exit(2);",
        ),
        (
            "fn a() -> Option<i32> {\n    match x {\n        Err(e) => {\n            tracing::error!(\"{e}\");\n            Some(2)\n        }\n    }\n}\n",
            "Some(2)",
        ),
        (
            "fn a() -> i32 {\n    if b {\n        tracing::error!(\n            \"multi (line) {}\",\n            c\n        );\n        return 1;\n    }\n    0\n}\n",
            "return 1;",
        ),
        (
            "fn exit_after(self) -> ! {\n    tracing::error!(\"{}\", self.message);\n    cleanup();\n    release_run_and_exit(self.exit_code);\n}\n",
            "release_run_and_exit(self.exit_code);",
        ),
        (
            "fn a() {\n    let x = y.map_err(|e| {\n        tracing::error!(\"bad: {e}\");\n        3\n    })?;\n}\n",
            "3",
        ),
        (
            "fn a() {\n    if let Some(e) = err {\n        tracing::error!(\"Failed to write output: {e}\");\n        lp.output_failed = true;\n    }\n}\n",
            "lp.output_failed = true;",
        ),
        (
            "fn fail(&mut self, m: &str) {\n    tracing::error!(\"{m}\");\n    self.failed = true;\n}\n",
            "self.failed = true;",
        ),
    ];
    for (src, exit) in cases {
        let found = findings(src);
        assert_eq!(found.len(), 1, "{src}\nfound {found:?}");
        assert_eq!(found[0].exit, *exit, "{src}");
    }
}

/// The scan does not flag a logged error the run continues past, an error
/// in a comment or a string, or an exit in another block.
#[test]
fn the_scan_passes_an_error_the_run_continues_past() {
    let cases: &[&str] = &[
        "fn a() {\n    tracing::error!(\"x\");\n    continue_the_run();\n}\n",
        "fn a() {\n    // tracing::error!(\"x\");\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    let s = \"tracing::error!(x)\";\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    if b {\n        tracing::error!(\"x\");\n    }\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    tracing::error!(\"x\");\n    let n = 2;\n    f(n);\n    g();\n    std::process::exit(2);\n}\n",
        "fn a() {\n    stderr_line!(\"x\");\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    my_error!(\"x\");\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    let r = r#\"error!(\"x\")\"#;\n    release_run_and_exit(2);\n}\n",
        "fn a() {\n    let c = '(';\n    tracing::error!(\"x\");\n    count += 1;\n}\n",
        "fn a() {\n    tracing::error!(\"x\");\n    self.failed = false;\n}\n",
        "fn a() {\n    tracing::error!(\"x\");\n    seen = true;\n}\n",
    ];
    for src in cases {
        assert_eq!(findings(src), Vec::new(), "{src}");
    }
}
