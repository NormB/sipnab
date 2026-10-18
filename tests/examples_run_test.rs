// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every program in `examples/` RUNS, the way its own comment says to run it.
//!
//! # Why this exists
//!
//! CI built all seven examples and ran one. `cargo build --examples` proves a
//! program compiles; it says nothing about whether `call_summary` still
//! prints the two dialogs its comment promises, or whether `rtp_quality`
//! still declines to score an opus stream. Six of the seven were checked by
//! nothing past the compiler.
//!
//! # What is run
//!
//! Each example's module comment carries one or more `cargo run … --example
//! NAME -- ARGS` commands in `sh` fences. Each is run here, from the
//! repository root so its capture paths resolve, as the binary `cargo test`
//! has just built beside the test (`target/<profile>/examples/NAME`). When a
//! `text` fence follows a command before the next one, every line of it must
//! appear in what the program printed: that is the output the comment
//! promises a reader.
//!
//! Two kinds of command are not run, each for a stated reason: one under
//! `sudo` (a test suite never escalates), and the part of a pipeline after
//! the first `|`, which belongs to another program (`curl` posting to a
//! conserver). The `cargo run` before the pipe is run.
//!
//! # Fresh binaries only
//!
//! `cargo test` builds the examples before it runs any test, so a whole-suite
//! run always sees current ones. `cargo test --test examples_run_test` alone
//! does not rebuild them, so this refuses an example binary older than any
//! source it is built from rather than checking a stale program.

#![cfg(feature = "full")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[path = "support/markdown.rs"]
mod markdown;

type TestError = Box<dyn std::error::Error>;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `examples/*.rs` program, by name, sorted.
fn example_names() -> Result<Vec<String>, TestError> {
    let mut names: Vec<String> = std::fs::read_dir(repo().join("examples"))?
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension().is_some_and(|x| x == "rs"))
                .then(|| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .flatten()
        })
        .collect();
    names.sort();
    Ok(names)
}

/// One command an example's comment documents, and the output it shows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Documented {
    /// `Some(name)` for `cargo run … --example name`, `None` for a `cargo
    /// run … --` that runs the sipnab binary itself.
    example: Option<String>,
    /// The arguments after `--`.
    args: Vec<String>,
    /// The `text` fence that follows the command, if one does before the next
    /// command: lines the program must print.
    shows: Vec<String>,
    /// Why the command is not run, when it is not.
    skipped: Option<&'static str>,
}

/// The module comment of a Rust source file, `//! ` stripped, as Markdown.
fn module_comment(src: &str) -> String {
    src.lines()
        .filter_map(|l| l.strip_prefix("//!"))
        .map(|l| l.strip_prefix(' ').unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A small word split: quotes respected, no expansion. `None` for a
/// construct it does not handle, which the caller reports.
fn shell_words(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(ch);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() || any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            (None, '$' | '`') => return None,
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !cur.is_empty() || any {
        out.push(cur);
    }
    Some(out)
}

/// Every `cargo run` command in one example's module comment.
fn documented_commands(src: &str) -> Result<Vec<Documented>, TestError> {
    let comment = module_comment(src);
    let mut out: Vec<Documented> = Vec::new();
    for fence in markdown::fences(&comment) {
        if fence.lang == "text" {
            // Output for the command just before it, if that command has
            // none yet.
            if let Some(last) = out.last_mut()
                && last.shows.is_empty()
            {
                last.shows = fence
                    .body
                    .lines()
                    .map(str::trim_end)
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            continue;
        }
        if fence.lang != "sh" {
            continue;
        }
        // Join continuations, one command per logical line.
        let mut logical: Vec<String> = Vec::new();
        let mut cur = String::new();
        for line in fence.body.lines() {
            let t = line.trim();
            if let Some(head) = t.strip_suffix('\\') {
                cur.push_str(head.trim_end());
                cur.push(' ');
            } else {
                cur.push_str(t);
                logical.push(std::mem::take(&mut cur));
            }
        }
        for line in logical {
            let line = line.split(" #").next().unwrap_or(&line).trim().to_owned();
            if line.is_empty() {
                continue;
            }
            let skipped = line.starts_with("sudo ").then_some(
                "runs under sudo, and a test suite never escalates; the same \
                 command without sudo is documented beside it and is run",
            );
            let cmd = line.strip_prefix("sudo -E ").unwrap_or(&line);
            // The pipeline after the first `|` is another program's.
            let cmd = cmd.split(" | ").next().unwrap_or(cmd).trim();
            let Some(rest) = cmd.strip_prefix("cargo run") else {
                return Err(
                    format!("a sh fence holds something other than cargo run: {line}").into(),
                );
            };
            let (opts, args) = match rest.split_once(" -- ") {
                Some((o, a)) => (o, a),
                None => (rest, ""),
            };
            let opts = shell_words(opts).ok_or_else(|| format!("cannot split {line:?}"))?;
            let args = shell_words(args).ok_or_else(|| format!("cannot split {line:?}"))?;
            let example = opts
                .windows(2)
                .find(|w| w[0] == "--example")
                .map(|w| w[1].clone());
            out.push(Documented {
                example,
                args,
                shows: Vec::new(),
                skipped,
            });
        }
    }
    // The same command shown twice (once plain, once piped onward) runs once.
    let mut unique: Vec<Documented> = Vec::new();
    for c in out {
        if !unique
            .iter()
            .any(|u| u.example == c.example && u.args == c.args && u.skipped == c.skipped)
        {
            unique.push(c);
        }
    }
    Ok(unique)
}

/// The newest modification time of any file under `dir`.
fn newest_under(dir: &Path) -> Result<SystemTime, TestError> {
    let mut newest = SystemTime::UNIX_EPOCH;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d)?.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                newest = newest.max(entry.metadata()?.modified()?);
            }
        }
    }
    Ok(newest)
}

/// Where cargo put the example binaries: beside the sipnab binary.
fn examples_dir() -> Result<PathBuf, TestError> {
    let bin = Path::new(env!("CARGO_BIN_EXE_sipnab"));
    Ok(bin
        .parent()
        .ok_or("the sipnab binary has no directory")?
        .join("examples"))
}

/// What one run printed, stdout and stderr together, and its exit code.
fn run(program: &Path, args: &[String]) -> Result<(Option<i32>, String, String), TestError> {
    let out = Command::new(program)
        .args(args)
        .current_dir(repo())
        .output()?;
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Every example has a documented command, and every documented command that
/// can be run, runs and prints what its comment shows.
#[test]
fn every_example_runs_as_its_comment_documents() -> Result<(), TestError> {
    let names = example_names()?;
    assert!(
        names.len() >= 7,
        "only {} example(s) under examples/: the walk is not reading the tree",
        names.len()
    );
    let dir = examples_dir()?;
    let sources_newest = newest_under(&repo().join("src"))?;
    let mut failures = Vec::new();
    let mut ran = 0_usize;
    let mut examples_run = std::collections::BTreeSet::new();
    for name in &names {
        let src_path = repo().join("examples").join(format!("{name}.rs"));
        let commands = documented_commands(&std::fs::read_to_string(&src_path)?)?;
        if !commands
            .iter()
            .any(|c| c.example.as_deref() == Some(name.as_str()))
        {
            failures.push(format!(
                "examples/{name}.rs documents no `cargo run --example {name}` command"
            ));
            continue;
        }
        for c in commands {
            if c.skipped.is_some() {
                continue;
            }
            let program = match &c.example {
                Some(ex) if ex != name => {
                    failures.push(format!("examples/{name}.rs documents --example {ex}"));
                    continue;
                }
                Some(ex) => {
                    let bin = dir.join(ex);
                    let built =
                        std::fs::metadata(&bin)
                            .and_then(|m| m.modified())
                            .map_err(|e| {
                                format!(
                                    "{} is not built ({e}). `cargo test` builds the examples; \
                                 a single `--test` run does not",
                                    bin.display()
                                )
                            })?;
                    let source = std::fs::metadata(&src_path)?.modified()?;
                    if built < source.max(sources_newest) {
                        return Err(format!(
                            "{} is older than its sources, so this would check a stale \
                             program. Run the whole suite (`cargo test --features full`) \
                             or `cargo build --features full --examples` first",
                            bin.display()
                        )
                        .into());
                    }
                    bin
                }
                None => PathBuf::from(env!("CARGO_BIN_EXE_sipnab")),
            };
            let (code, stdout, stderr) = run(&program, &c.args)?;
            ran += 1;
            examples_run.insert(name.clone());
            let printed: Vec<&str> = stdout
                .lines()
                .chain(stderr.lines())
                .map(str::trim_end)
                .collect();
            let missing: Vec<&String> = c
                .shows
                .iter()
                .filter(|want| !printed.contains(&want.as_str()))
                .collect();
            // A documented refusal is a non-zero exit whose message the
            // comment shows; anything else must succeed.
            let refusal_shown = !c.shows.is_empty()
                && c.shows
                    .iter()
                    .all(|w| stderr.lines().any(|l| l.trim_end() == w));
            if code != Some(0) && !refusal_shown {
                failures.push(format!(
                    "examples/{name}.rs: {} {:?} exited {code:?}\nstderr:\n{stderr}",
                    program.display(),
                    c.args
                ));
            }
            if !missing.is_empty() {
                failures.push(format!(
                    "examples/{name}.rs: {:?} did not print, as its comment shows:\n  {}\n\
                     it printed:\n{stdout}{stderr}",
                    c.args,
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join("\n  ")
                ));
            }
        }
    }
    println!(
        "examples run: {} of {}, {ran} documented command(s)",
        examples_run.len(),
        names.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    assert_eq!(
        examples_run.len(),
        names.len(),
        "every example must run at least once"
    );
    Ok(())
}

/// The command parser reads continuations, `text` fences, `sudo` and pipes
/// the way the comments use them.
#[test]
fn the_documented_command_parser_reads_what_the_comments_write() -> Result<(), TestError> {
    let src = "//! ```sh\n\
               //! cargo run --features native --example demo -- \\\n\
               //!     tests/a.pcap \"method == 'INVITE'\"\n\
               //! sudo -E cargo run --features native --example demo   # more\n\
               //! ```\n\
               //!\n\
               //! ```text\n\
               //! one line\n\
               //! ```\n\
               //!\n\
               //! ```sh\n\
               //! cargo run --features native --example demo -- \\\n\
               //!     tests/a.pcap \"method == 'INVITE'\" \\\n\
               //!   | curl -X POST \"$URL\"\n\
               //! ```\n";
    let got = documented_commands(src)?;
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0].example.as_deref(), Some("demo"));
    assert_eq!(got[0].args, vec!["tests/a.pcap", "method == 'INVITE'"]);
    assert!(got[0].skipped.is_none());
    assert!(got[1].skipped.is_some(), "a sudo command is not run");
    assert_eq!(
        got[1].shows,
        vec!["one line"],
        "the text fence after the sudo line"
    );
    Ok(())
}

/// `docs/library.md` counts the programs in `examples/` correctly.
///
/// It said "Four of the six programs" when there were seven: the seventh,
/// `tls_plaintext_records`, was added without the sentence that counts them.
#[test]
fn the_library_page_counts_the_examples_that_exist() -> Result<(), TestError> {
    let words = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    ];
    let number = |w: &str| words.iter().position(|x| x.eq_ignore_ascii_case(w));
    let page = std::fs::read_to_string(repo().join("docs/library.md"))?;
    let claim = regex::Regex::new(r"(\w+) of the (\w+) programs in \[`examples/`\]")?;
    let caps = claim
        .captures(&page)
        .ok_or("docs/library.md no longer says how many programs examples/ holds")?;
    let (part, whole) = (
        number(&caps[1]).ok_or("not a number word")?,
        number(&caps[2]).ok_or("not a number word")?,
    );
    let names = example_names()?;
    assert_eq!(
        whole,
        names.len(),
        "docs/library.md says {:?} programs; examples/ holds {}: {names:?}",
        &caps[2],
        names.len()
    );
    // The part is the table under the sentence: one row per library example.
    let section = page
        .split("## Worked examples")
        .nth(1)
        .and_then(|s| s.split("\n## ").next())
        .ok_or("docs/library.md has no Worked examples section")?;
    let rows = section
        .lines()
        .filter(|l| l.starts_with("| [`") && l.contains("../examples/"))
        .count();
    assert_eq!(
        part, rows,
        "docs/library.md says {:?} take the library path; its table has {rows} row(s)",
        &caps[1]
    );
    // Every example the sentence leaves out is named in the section.
    for name in &names {
        assert!(
            section.contains(&format!("`{name}`")) || section.contains(&format!("{name}.rs")),
            "docs/library.md's Worked examples section does not name {name}"
        );
    }
    Ok(())
}
