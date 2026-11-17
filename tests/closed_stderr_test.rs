// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A reader that goes away must not turn a finished run into a crash.
//!
//! `sipnab ... 2>&1 | head -1` closes the pipe that carries both stdout and
//! stderr after one line. Every later write fails with `EPIPE`. stdout already
//! treats that as the reader's choice; stderr did not: `eprintln!` panics when
//! its write fails, and so does the `eprintln!` tracing-subscriber uses to
//! report a log line it could not write. The panic hook then exited 101 and
//! wrote a crash report for a run that had done everything it was asked.
//!
//! Each test hands the child a pipe whose read end is already closed, so every
//! write to it fails from the first byte. Racing a real `head` would make the
//! failure depend on timing; this makes it depend only on sipnab.

#[path = "support/tracked.rs"]
mod tracked;

use std::process::{Command, Stdio};

/// The error a test returns: any error, boxed, so `?` works on I/O,
/// parse and JSON errors alike.
type TestError = Box<dyn std::error::Error>;

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A pipe nobody will ever read: the read end is dropped before the child
/// starts, so the child's writes to it fail with `EPIPE`.
fn reader_gone() -> Result<Stdio, TestError> {
    let (reader, writer) = std::io::pipe()?;
    drop(reader);
    Ok(Stdio::from(writer))
}

/// Run sipnab with `args`, stderr into a pipe with no reader, and return the
/// exit code. Crash reports go to a private directory, so a panic is visible
/// to the test as a file and never lands in the developer's own state
/// directory.
fn exit_code_with_stderr_gone(
    args: &[&str],
    log: &str,
    stdout: Stdio,
) -> Result<(i32, usize), TestError> {
    let state = tempfile::tempdir()?;
    let status = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("SIPNAB_LOG", log)
        .env("XDG_STATE_HOME", state.path())
        .env("HOME", state.path())
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(reader_gone()?)
        .status()?;
    let reports = walk_count(state.path());
    Ok((status.code().unwrap_or(-1), reports))
}

/// Number of files under `dir`, recursively.
fn walk_count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .map(|e| {
                    let p = e.path();
                    if p.is_dir() { walk_count(&p) } else { 1 }
                })
                .sum()
        })
        .unwrap_or(0)
}

/// The log lines a batch run writes to stderr must not crash it when nobody
/// reads stderr. This is the `tracing` path: the subscriber's own report of
/// the failed write was itself an `eprintln!`.
#[test]
fn log_lines_to_a_closed_stderr_do_not_crash_a_batch_run() -> Result<(), TestError> {
    let pcap = fixture("sip_call.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "info", Stdio::null())?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// sipnab's own `eprintln!` lines, with logging off so only they write to
/// stderr: a capture with RTP and no SIP prints its guidance that way.
#[test]
fn guidance_lines_to_a_closed_stderr_do_not_crash_a_batch_run() -> Result<(), TestError> {
    let pcap = fixture("turn_relay.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "off", Stdio::null())?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// `2>&1 | head`: stdout and stderr both lose their reader. stdout's
/// `BrokenPipe` already counted as success; stderr's must not undo that.
#[test]
fn both_streams_closed_is_a_clean_exit() -> Result<(), TestError> {
    let pcap = fixture("sip_call.pcap");
    let (code, reports) = exit_code_with_stderr_gone(&["-N", "-I", &pcap], "info", reader_gone()?)?;
    assert_eq!(code, 0, "exit {code}; 101 is the panic hook");
    assert_eq!(reports, 0, "a crash report was written");
    Ok(())
}

/// No source file writes to stderr with `eprintln!` or `eprint!`, which panic
/// when the write fails. `stderr_line!` (defined in `src/lib.rs`) writes the
/// same line and drops the error. One rule in one place: a new `eprintln!`
/// anywhere in `src/` would bring the crash back on its own path.
#[test]
fn no_source_file_uses_a_panicking_stderr_macro() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let listed = tracked::ls_files(root, &["--", "src/*.rs", "src/**/*.rs"])?;
    let mut files = 0;
    let mut offenders = Vec::new();
    for rel in listed.iter().map(String::as_str) {
        if rel.is_empty() {
            continue;
        }
        files += 1;
        let text = std::fs::read_to_string(root.join(rel))?;
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("eprintln!") || code.contains("eprint!") {
                offenders.push(format!("{rel}:{}", n + 1));
            }
        }
    }
    assert!(files >= 290, "read only {files} source files");
    assert!(
        offenders.is_empty(),
        "{} stderr write(s) that panic when stderr is a closed pipe; use \
         stderr_line!: {offenders:?}",
        offenders.len()
    );
    Ok(())
}

// ── Every tracing fmt builder drops the lines it cannot write ───────────
//
// tracing-subscriber's `fmt()` builder (0.3.23) sets `log_internal_errors`
// to true. Then a log line that cannot be written is reported with
// `eprintln!` to the same stderr, which panics when that write fails too.
// The run's own subscriber set it to false; the scanner-kill worker's did
// not, and a worker whose stderr lost its reader exited 101 at its next log
// line (WORKER-TRACING-PANICS-ON-CLOSED-STDERR). `eprintln!` is banned in
// `src/` above, but this one is inside the dependency, so the rule is on the
// builder: every tracing fmt builder in `src/` calls
// `.log_internal_errors(false)` in its own chain. The stderr subscribers go
// through one function, `output::cli_print::stderr_log_subscriber`.

/// How a tracing fmt builder breaks the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Breach {
    /// A builder whose own chain never calls `.log_internal_errors(false)`.
    Unquiet,
    /// `.log_internal_errors(true)`, anywhere.
    Loud,
    /// `fmt::init()` or `fmt::try_init()`: a builder with the default that
    /// cannot be configured at all.
    Unconfigurable,
}

/// One breach: the 1-based line it starts on and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Finding {
    line: usize,
    breach: Breach,
}

/// What [`log_builder_scan`] found in one file.
#[derive(Debug, Default, PartialEq, Eq)]
struct Scan {
    /// Tracing fmt builders seen, rule-abiding or not.
    builders: usize,
    breaches: Vec<Finding>,
}

/// One token of Rust source: an identifier or number, `::`, or one
/// punctuation character, with the 1-based line it is on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
    text: String,
    line: usize,
}

/// Whether `c` can be part of an identifier or a number.
fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `text` as tokens, leaving out whitespace, line and block comments (block
/// comments nest), string literals (raw ones included) and char literals. A
/// lifetime's quote is kept as a token of its own.
fn code_tokens(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut i = 0;
    // Advance past chars[i], counting a line break.
    let step = |i: &mut usize, line: &mut usize| {
        if at(*i) == Some('\n') {
            *line += 1;
        }
        *i += 1;
    };
    while let Some(c) = at(i) {
        let next = at(i + 1);
        if c.is_whitespace() {
            step(&mut i, &mut line);
        } else if c == '/' && next == Some('/') {
            while at(i).is_some_and(|c| c != '\n') {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0usize;
            while at(i).is_some() {
                if at(i) == Some('/') && at(i + 1) == Some('*') {
                    depth += 1;
                    i += 2;
                } else if at(i) == Some('*') && at(i + 1) == Some('/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    step(&mut i, &mut line);
                }
            }
        } else if c == '"' {
            i += 1;
            while let Some(c) = at(i) {
                if c == '\\' {
                    i += 1;
                    step(&mut i, &mut line);
                } else if c == '"' {
                    i += 1;
                    break;
                } else {
                    step(&mut i, &mut line);
                }
            }
        } else if c == '\'' {
            if next == Some('\\') {
                // An escape: skip the quote, the backslash and the escaped
                // character, then up to the closing quote.
                i += 3;
                while at(i).is_some_and(|c| c != '\'') {
                    i += 1;
                }
                i += 1;
            } else if at(i + 2) == Some('\'') {
                i += 3;
            } else {
                // A lifetime or a label.
                tokens.push(Token {
                    text: "'".to_string(),
                    line,
                });
                i += 1;
            }
        } else if ident_char(c) {
            let start = i;
            while at(i).is_some_and(ident_char) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let hashes = chars[i..].iter().take_while(|&&c| c == '#').count();
            if (word == "r" || word == "br") && at(i + hashes) == Some('"') {
                // A raw string: it ends at a quote followed by as many `#`.
                i += hashes + 1;
                while at(i).is_some() {
                    if at(i) == Some('"') && (1..=hashes).all(|k| at(i + k) == Some('#')) {
                        i += hashes + 1;
                        break;
                    }
                    step(&mut i, &mut line);
                }
            } else {
                tokens.push(Token { text: word, line });
            }
        } else if c == ':' && next == Some(':') {
            tokens.push(Token {
                text: "::".to_string(),
                line,
            });
            i += 2;
        } else {
            tokens.push(Token {
                text: c.to_string(),
                line,
            });
            i += 1;
        }
    }
    tokens
}

/// Whether the tokens from `i` on are exactly `parts`.
fn tokens_are(tokens: &[Token], i: usize, parts: &[&str]) -> bool {
    parts
        .iter()
        .enumerate()
        .all(|(k, part)| tokens.get(i + k).is_some_and(|t| t.text == *part))
}

/// If a tracing fmt builder starts at token `i`, the index just after the
/// call that makes it: `fmt()` (qualified or not, never a method `.fmt()`),
/// `fmt::Subscriber::builder()`, `SubscriberBuilder::default()`,
/// `fmt::layer()`, `fmt::Layer::default()` and `fmt::Layer::new()`.
fn builder_start(tokens: &[Token], i: usize) -> Option<usize> {
    let after_fmt_path = i >= 2 && tokens_are(tokens, i - 2, &["fmt", "::"]);
    let before = i.checked_sub(1).and_then(|p| tokens.get(p));
    let is_method_or_item = before.is_some_and(|t| t.text == "." || t.text == "fn");
    if tokens_are(tokens, i, &["fmt", "(", ")"]) && !is_method_or_item {
        return Some(i + 3);
    }
    if tokens_are(tokens, i, &["SubscriberBuilder", "::", "default", "(", ")"]) {
        return Some(i + 5);
    }
    if !after_fmt_path {
        return None;
    }
    if tokens_are(tokens, i, &["layer", "(", ")"]) {
        return Some(i + 3);
    }
    [
        ["Subscriber", "::", "builder", "(", ")"],
        ["Layer", "::", "default", "(", ")"],
        ["Layer", "::", "new", "(", ")"],
    ]
    .iter()
    .any(|parts| tokens_are(tokens, i, parts))
    .then_some(i + 5)
}

/// Whether the builder's own chain, from token `from` to the end of its
/// expression (a `;` or `,` at its own depth, or the bracket that closes
/// around it), calls `.log_internal_errors(false)` at that depth.
fn chain_sets_quiet(tokens: &[Token], from: usize) -> bool {
    let mut depth = 0usize;
    for j in from..tokens.len() {
        match tokens[j].text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" if depth == 0 => return false,
            ")" | "]" | "}" => depth -= 1,
            ";" | "," if depth == 0 => return false,
            "." if depth == 0
                && tokens_are(tokens, j, &[".", "log_internal_errors", "(", "false", ")"]) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Every tracing fmt builder in the Rust source `text`, and each breach of
/// the rule, outside comments and string literals, in file order.
fn log_builder_scan(text: &str) -> Scan {
    let tokens = code_tokens(text);
    let mut scan = Scan::default();
    for i in 0..tokens.len() {
        let line = tokens[i].line;
        if tokens_are(tokens.as_slice(), i, &["fmt", "::", "init", "(", ")"])
            || tokens_are(tokens.as_slice(), i, &["fmt", "::", "try_init", "(", ")"])
        {
            scan.breaches.push(Finding {
                line,
                breach: Breach::Unconfigurable,
            });
        }
        if let Some(after) = builder_start(&tokens, i) {
            scan.builders += 1;
            if !chain_sets_quiet(&tokens, after) {
                scan.breaches.push(Finding {
                    line,
                    breach: Breach::Unquiet,
                });
            }
        }
        if tokens_are(
            tokens.as_slice(),
            i,
            &[".", "log_internal_errors", "(", "true", ")"],
        ) {
            scan.breaches.push(Finding {
                line,
                breach: Breach::Loud,
            });
        }
    }
    scan
}

/// The breaches in `text`, as `(line, breach)` pairs, for short asserts.
fn breaches(text: &str) -> Vec<(usize, Breach)> {
    log_builder_scan(text)
        .breaches
        .iter()
        .map(|f| (f.line, f.breach))
        .collect()
}

/// Assert `text` holds exactly `builders` builders and no breach.
fn assert_clean(text: &str, builders: usize) {
    let scan = log_builder_scan(text);
    assert_eq!(
        scan,
        Scan {
            builders,
            breaches: Vec::new()
        },
        "expected {builders} builder(s) and no breach in:\n{text}"
    );
}

/// Every tracing fmt builder in `src/` drops a line it cannot write instead
/// of reporting it with a panicking `eprintln!`. The scan must see the
/// shared stderr builder, or it is blind and proves nothing.
#[test]
fn every_tracing_fmt_builder_in_src_drops_lines_it_cannot_write() -> Result<(), TestError> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let listed = tracked::ls_files(root, &["--", "src/*.rs", "src/**/*.rs"])?;
    let mut builders = 0;
    let mut found = Vec::new();
    let mut shared_seen = false;
    for rel in listed.iter().map(String::as_str) {
        if rel.is_empty() {
            continue;
        }
        let scan = log_builder_scan(&std::fs::read_to_string(root.join(rel))?);
        builders += scan.builders;
        shared_seen |= rel == "src/output/cli_print.rs" && scan.builders == 1;
        found.extend(
            scan.breaches
                .iter()
                .map(|f| format!("{rel}:{} {:?}", f.line, f.breach)),
        );
    }
    assert!(
        shared_seen,
        "the scan must see the one builder in src/output/cli_print.rs"
    );
    assert!(builders >= 3, "saw only {builders} tracing fmt builder(s)");
    assert!(
        found.is_empty(),
        "{} tracing fmt builder(s) would report a failed write with eprintln!, \
         which panics when stderr is closed; call .log_internal_errors(false) \
         in the builder's own chain, or use \
         output::cli_print::stderr_log_subscriber: {found:?}",
        found.len()
    );
    Ok(())
}

/// The shared stderr builder, as written in src/output/cli_print.rs, keeps
/// the rule: the one place the run and its worker get their subscriber.
#[test]
fn the_shared_stderr_builder_keeps_the_rule() -> Result<(), TestError> {
    let path = format!("{}/src/output/cli_print.rs", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path)?;
    assert!(
        text.contains("fn stderr_log_subscriber("),
        "the shared builder is in cli_print.rs"
    );
    assert_clean(&text, 1);
    Ok(())
}

/// The run's subscriber and the worker's both come from the shared builder:
/// neither file builds a fmt subscriber of its own any more.
#[test]
fn the_run_and_its_worker_use_the_shared_stderr_builder() -> Result<(), TestError> {
    let root = env!("CARGO_MANIFEST_DIR");
    for rel in [
        "src/app/bootstrap.rs",
        "src/process_isolation/worker_process.rs",
    ] {
        let text = std::fs::read_to_string(format!("{root}/{rel}"))?;
        assert!(
            text.contains("cli_print::stderr_log_subscriber("),
            "{rel} must take its subscriber from the shared builder"
        );
        assert_eq!(
            log_builder_scan(&text).builders,
            0,
            "{rel} must not build a fmt subscriber of its own"
        );
    }
    Ok(())
}

// Success: builders that keep the rule.

#[test]
fn a_qualified_builder_that_sets_it_on_one_line_is_clean() {
    assert_clean(
        "let s = tracing_subscriber::fmt().log_internal_errors(false).finish();",
        1,
    );
}

#[test]
fn a_multi_line_chain_that_sets_it_in_the_middle_is_clean() {
    assert_clean(
        "let s = tracing_subscriber::fmt()\n    .with_writer(std::io::stderr)\n    \
         .log_internal_errors(false)\n    .compact()\n    .finish();\n",
        1,
    );
}

#[test]
fn a_chain_that_sets_it_last_is_clean() {
    assert_clean(
        "let s = tracing_subscriber::fmt()\n    .with_ansi(false)\n    .log_internal_errors(false);\n",
        1,
    );
}

#[test]
fn a_bare_fmt_call_after_a_use_that_sets_it_is_clean() {
    assert_clean(
        "use tracing_subscriber::fmt;\nlet s = fmt().log_internal_errors(false).finish();\n",
        1,
    );
}

#[test]
fn a_subscriber_builder_that_sets_it_is_clean() {
    assert_clean(
        "let s = tracing_subscriber::fmt::Subscriber::builder().log_internal_errors(false).finish();",
        1,
    );
}

#[test]
fn a_default_subscriber_builder_that_sets_it_is_clean() {
    assert_clean(
        "let s = SubscriberBuilder::default().log_internal_errors(false).finish();",
        1,
    );
}

#[test]
fn a_fmt_layer_that_sets_it_is_clean() {
    assert_clean(
        "let l = tracing_subscriber::fmt::layer().log_internal_errors(false);",
        1,
    );
}

#[test]
fn a_default_fmt_layer_that_sets_it_is_clean() {
    assert_clean(
        "let l = fmt::Layer::default().log_internal_errors(false);",
        1,
    );
}

#[test]
fn a_builder_that_sets_it_and_then_inits_is_clean() {
    assert_clean(
        "tracing_subscriber::fmt().log_internal_errors(false).init();",
        1,
    );
}

#[test]
fn a_builder_passed_straight_to_a_call_that_sets_it_is_clean() {
    assert_clean(
        "let _ = set_global_default(tracing_subscriber::fmt().log_internal_errors(false).finish());",
        1,
    );
}

#[test]
fn spaces_and_line_breaks_inside_the_call_are_still_the_call() {
    assert_clean(
        "let s = tracing_subscriber :: fmt ( )\n    . log_internal_errors (\n        false\n    )\n    .finish();",
        1,
    );
}

#[test]
fn two_builders_that_both_set_it_are_both_counted_and_clean() {
    assert_clean(
        "let a = tracing_subscriber::fmt().log_internal_errors(false).finish();\n\
         let b = tracing_subscriber::fmt::layer().log_internal_errors(false);\n",
        2,
    );
}

// Failure: builders that break the rule, each named at its own line.

#[test]
fn a_qualified_builder_without_it_is_unquiet() {
    assert_eq!(
        breaches("let s = tracing_subscriber::fmt().with_ansi(false).finish();"),
        vec![(1, Breach::Unquiet)],
        "the builder's default reports a failed write with eprintln!"
    );
}

#[test]
fn a_multi_line_chain_without_it_is_named_at_its_first_line() {
    assert_eq!(
        breaches(
            "fn init() {\n    let s = tracing_subscriber::fmt()\n        .with_writer(std::io::stderr)\n        .finish();\n}\n"
        ),
        vec![(2, Breach::Unquiet)],
        "the finding names the line the builder starts on"
    );
}

#[test]
fn a_bare_fmt_call_without_it_is_unquiet() {
    assert_eq!(
        breaches("use tracing_subscriber::fmt;\nlet s = fmt().compact().finish();\n"),
        vec![(2, Breach::Unquiet)],
        "an unqualified fmt() after a use is the same builder"
    );
}

#[test]
fn a_subscriber_builder_without_it_is_unquiet() {
    assert_eq!(
        breaches("let s = fmt::Subscriber::builder().finish();"),
        vec![(1, Breach::Unquiet)],
        "Subscriber::builder() is the same builder as fmt()"
    );
}

#[test]
fn a_default_subscriber_builder_without_it_is_unquiet() {
    assert_eq!(
        breaches("let s = SubscriberBuilder::default().finish();"),
        vec![(1, Breach::Unquiet)],
        "SubscriberBuilder::default() is the same builder as fmt()"
    );
}

#[test]
fn a_fmt_layer_without_it_is_unquiet() {
    assert_eq!(
        breaches("let l = tracing_subscriber::fmt::layer().with_ansi(false);"),
        vec![(1, Breach::Unquiet)],
        "one rule for every fmt builder: a layer states it too"
    );
}

#[test]
fn setting_it_to_true_is_loud() {
    assert_eq!(
        breaches("let s = tracing_subscriber::fmt().log_internal_errors(true).finish();"),
        vec![(1, Breach::Unquiet), (1, Breach::Loud)],
        "true is the default that panics, said out loud"
    );
}

#[test]
fn the_fmt_init_shortcut_cannot_be_configured() {
    assert_eq!(
        breaches("fn main() {\n    tracing_subscriber::fmt::init();\n}\n"),
        vec![(2, Breach::Unconfigurable)],
        "fmt::init() installs the default builder"
    );
}

#[test]
fn the_fmt_try_init_shortcut_cannot_be_configured() {
    assert_eq!(
        breaches("let _ = fmt::try_init();"),
        vec![(1, Breach::Unconfigurable)],
        "fmt::try_init() installs the default builder"
    );
}

#[test]
fn a_builder_that_inits_without_it_is_unquiet() {
    assert_eq!(
        breaches("tracing_subscriber::fmt().with_target(true).init();"),
        vec![(1, Breach::Unquiet)],
        "init() on a builder that never set it"
    );
}

#[test]
fn a_value_that_is_not_the_literal_false_is_unquiet() {
    assert_eq!(
        breaches("let s = tracing_subscriber::fmt().log_internal_errors(quiet).finish();"),
        vec![(1, Breach::Unquiet)],
        "only the literal false can be checked here"
    );
}

#[test]
fn setting_it_in_a_later_statement_does_not_count() {
    assert_eq!(
        breaches("let b = tracing_subscriber::fmt();\nlet b = b.log_internal_errors(false);\n"),
        vec![(1, Breach::Unquiet)],
        "the rule is on the builder's own chain"
    );
}

#[test]
fn setting_it_inside_an_argument_does_not_count() {
    assert_eq!(
        breaches(
            "let s = tracing_subscriber::fmt().with_writer(move || other.log_internal_errors(false)).finish();"
        ),
        vec![(1, Breach::Unquiet)],
        "a call inside an argument is not on this builder"
    );
}

#[test]
fn a_neighbor_that_sets_it_does_not_cover_a_builder_that_does_not() {
    assert_eq!(
        breaches(
            "let pair = (tracing_subscriber::fmt().finish(), tracing_subscriber::fmt().log_internal_errors(false).finish());"
        ),
        vec![(1, Breach::Unquiet)],
        "the first builder's chain ends at the comma"
    );
}

// Edge: text that only looks like a builder, and where findings land.

#[test]
fn a_builder_in_a_line_comment_is_not_code() {
    assert_clean(
        "// let s = tracing_subscriber::fmt().finish();\nlet x = 1;\n",
        0,
    );
}

#[test]
fn a_builder_in_a_doc_comment_is_not_code() {
    assert_clean(
        "/// Unlike `tracing_subscriber::fmt::init()`, this sets it.\nfn f() {}\n",
        0,
    );
}

#[test]
fn a_builder_in_a_block_comment_is_not_code() {
    assert_clean(
        "/* tracing_subscriber::fmt().finish();\n   fmt::init(); */\nlet x = 1;\n",
        0,
    );
}

#[test]
fn a_nested_block_comment_ends_at_its_own_close() {
    assert_eq!(
        breaches("/* outer /* inner */ still a comment fmt() */\nlet s = fmt().finish();\n"),
        vec![(2, Breach::Unquiet)],
        "Rust block comments nest; the code after them is scanned"
    );
}

#[test]
fn a_builder_in_a_string_literal_is_not_code() {
    assert_clean(
        "let hint = \"use tracing_subscriber::fmt().finish() or fmt::init()\";\n",
        0,
    );
}

#[test]
fn a_builder_in_a_raw_string_is_not_code() {
    assert_clean(
        "let hint = r#\"say \"tracing_subscriber::fmt().finish()\" here\"#;\n",
        0,
    );
}

#[test]
fn an_escaped_quote_does_not_end_a_string() {
    assert_clean("let hint = \"a \\\" then fmt() inside\";\n", 0);
}

#[test]
fn a_quote_char_literal_does_not_open_a_string() {
    assert_eq!(
        breaches("let q = '\"';\nlet s = tracing_subscriber::fmt().finish();\n"),
        vec![(2, Breach::Unquiet)],
        "'\"' is a char, and the builder after it is code"
    );
}

#[test]
fn a_lifetime_is_not_a_char_literal() {
    assert_eq!(
        breaches("fn f(x: &'static str) {}\nlet s = tracing_subscriber::fmt().finish();\n"),
        vec![(2, Breach::Unquiet)],
        "'static is a lifetime with no closing quote; the builder after it is code"
    );
}

#[test]
fn a_display_impl_is_not_a_builder() {
    assert_clean(
        "trait Shape {\n    fn fmt();\n}\nimpl std::fmt::Display for X {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        self.0.fmt(f)\n    }\n}\n",
        0,
    );
}

#[test]
fn a_method_named_fmt_is_not_a_builder() {
    assert_clean("let r = value.fmt();\nlet t = other . fmt ( );\n", 0);
}

#[test]
fn text_with_no_builder_scans_to_nothing() {
    assert_clean("", 0);
}

#[test]
fn each_breach_is_named_at_its_own_line_in_order() {
    assert_eq!(
        breaches(
            "let a = tracing_subscriber::fmt().finish();\nlet ok = tracing_subscriber::fmt().log_internal_errors(false).finish();\n\nlet c = fmt::try_init();\n"
        ),
        vec![(1, Breach::Unquiet), (4, Breach::Unconfigurable)],
        "one finding per breach, at its line, in file order"
    );
}
