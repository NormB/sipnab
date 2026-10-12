// SPDX-License-Identifier: MIT OR Apache-2.0

//! `man/sipnab.1` describes the binary it ships beside.
//!
//! The page was hand-written and only its version and license were gated, so
//! it covered 35 of the program's flags, named none of the secret-bearing
//! environment variables, carried an exit-status list older than
//! `docs/cli-reference.md`, and rendered "theterminalviewer(1)" where a name
//! scrub had left `.BR the terminal viewer (1)` behind.
//!
//! # The coverage rule
//!
//! OPTIONS lists **every visible flag**, grouped under the same headings
//! `--help` uses, each with the first paragraph of its help, its listed
//! values, its default and the environment variable it reads. It is not
//! written by hand: [`render_options`] produces it from clap's metadata, the
//! same source `--help` prints, so the page cannot name a flag the program
//! lacks or miss one it has. A subset chosen by hand ("the core flags") would
//! need a second list that drifts from the first; listing every flag costs
//! nothing once it is generated. The full text of each flag stays in
//! `sipnab --help` and `docs/cli-reference.md`, and OPTIONS says so.
//!
//! ENVIRONMENT and EXIT STATUS are generated the same way: ENVIRONMENT from
//! [`sipnab::cli::ENVIRONMENT`], the table `--help` prints, and EXIT STATUS
//! from the exit-code table in `docs/cli-reference.md`. Every other section
//! is hand-written and gated by the rules below.
//!
//! # Regenerating
//!
//! `SIPNAB_MAN_APPLY=1 cargo test --features full --test man_page_test`
//! rewrites the generated regions in place; nothing else writes the file.

// The flag set is feature-dependent (`--plugin` exists only with `plugins`),
// and the man page describes the full-featured binary.
#![cfg(feature = "full")]

use clap::CommandFactory as _;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestError = Box<dyn std::error::Error>;

/// The environment variable that turns the comparison into a rewrite.
const APPLY_ENV: &str = "SIPNAB_MAN_APPLY";

/// The command that regenerates the page, quoted in every failure.
const FIXER: &str = "SIPNAB_MAN_APPLY=1 cargo test --features full --test man_page_test";

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The man page as committed.
fn man_page() -> Result<String, TestError> {
    Ok(std::fs::read_to_string(repo().join("man/sipnab.1"))?)
}

/// The text of one `.SH` section, header line excluded.
fn section<'a>(man: &'a str, name: &str) -> Option<&'a str> {
    let header = format!(".SH {name}\n");
    let start = man.find(&header)? + header.len();
    let rest = &man[start..];
    let end = rest.find("\n.SH ").map_or(rest.len(), |i| i + 1);
    Some(&rest[..end])
}

/// Undo the roff escapes that matter for reading names back out of the page.
fn unescape(text: &str) -> String {
    text.replace("\\-", "-")
        .replace("\\fB", "")
        .replace("\\fI", "")
        .replace("\\fR", "")
        .replace("\\fP", "")
        .replace("\\&", "")
}

// ── roff rendering ────────────────────────────────────────────────────────

/// Escape plain text for a roff text line: backslashes, hyphens, characters
/// outside ASCII, and a leading control character.
fn roff_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\e"),
            '-' => out.push_str("\\-"),
            '\u{2014}' => out.push_str("\\(em"),
            '\u{2013}' => out.push_str("\\(en"),
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{201c}' | '\u{201d}' => out.push('"'),
            c if c.is_ascii() => out.push(c),
            c => out.push_str(&format!("\\[u{:04X}]", u32::from(c))),
        }
    }
    out
}

/// Render one paragraph of the Markdown-flavored prose clap help and the
/// documentation use as a single roff text line: `code` and **bold** in bold,
/// a link as its text, everything else escaped.
fn md_to_roff(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = text.replace("\\|", "|");
    let mut out = String::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('`')
            && let Some(end) = after.find('`')
        {
            out.push_str("\\fB");
            out.push_str(&roff_escape(&after[..end]));
            out.push_str("\\fR");
            rest = &after[end + 1..];
        } else if let Some(after) = rest.strip_prefix("**")
            && let Some(end) = after.find("**")
        {
            out.push_str("\\fB");
            out.push_str(&md_to_roff(&after[..end]));
            out.push_str("\\fR");
            rest = &after[end + 2..];
        } else if let Some(after) = rest.strip_prefix('[')
            && let Some(close) = after.find("](")
            && let Some(end) = after[close + 2..].find(')')
        {
            out.push_str(&md_to_roff(&after[..close]));
            rest = &after[close + 2 + end + 1..];
        } else {
            let next = rest[1..]
                .find(['`', '*', '['])
                .map_or(rest.len(), |i| i + 1);
            out.push_str(&roff_escape(&rest[..next]));
            rest = &rest[next..];
        }
    }
    if out.starts_with('.') || out.starts_with('\'') {
        out.insert_str(0, "\\&");
    }
    out
}

/// End a help sentence with a period: clap drops the one that closed a
/// one-paragraph doc comment.
fn sentence(text: &str) -> String {
    let t = text.trim();
    if t.ends_with(['.', '!', '?']) || t.ends_with(".)") {
        t.to_string()
    } else {
        format!("{t}.")
    }
}

/// The `.TP` header for one argument: its switches and its value names.
fn option_header(arg: &clap::Arg) -> String {
    let mut names = Vec::new();
    if let Some(s) = arg.get_short() {
        names.push(format!("\\fB\\-{}\\fR", roff_escape(&s.to_string())));
    }
    if let Some(l) = arg.get_long() {
        names.push(format!("\\fB\\-\\-{}\\fR", roff_escape(l)));
    }
    let mut header = names.join(", ");
    if arg.get_action().takes_values() {
        let values: Vec<String> = arg
            .get_value_names()
            .map(|v| {
                v.iter()
                    .map(|n| format!("\\fI{}\\fR", roff_escape(n)))
                    .collect()
            })
            .unwrap_or_else(|| vec![format!("\\fI{}\\fR", roff_escape(arg.get_id().as_str()))]);
        let range = arg.get_num_args();
        let optional = range.is_some_and(|r| r.min_values() == 0);
        let many = range.is_some_and(|r| r.max_values() > values.len());
        let mut v = values.join(" ");
        if many {
            v.push_str("\\&...");
        }
        if optional {
            v = format!("[{v}]");
        }
        header.push(' ');
        header.push_str(&v);
    }
    header
}

/// The body lines for one argument: the first paragraph of its help, then
/// what `--help` prints in brackets after it.
fn option_body(arg: &clap::Arg) -> Vec<String> {
    let help = arg
        .get_help()
        .map(ToString::to_string)
        .or_else(|| {
            arg.get_long_help().map(|h| {
                h.to_string()
                    .split("\n\n")
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
        })
        .unwrap_or_default();
    let mut lines = Vec::new();
    if !help.trim().is_empty() {
        lines.push(md_to_roff(&sentence(&help)));
    }
    if !arg.is_hide_possible_values_set() {
        let values: Vec<String> = arg
            .get_possible_values()
            .iter()
            .filter(|v| !v.is_hide_set())
            .map(|v| format!("\\fB{}\\fR", roff_escape(v.get_name())))
            .collect();
        // A switch's implied true/false is not a value anyone types.
        if !values.is_empty() && arg.get_action().takes_values() {
            lines.push(format!("Values: {}.", values.join(", ")));
        }
    }
    if !arg.is_hide_default_value_set() && arg.get_action().takes_values() {
        let defaults: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|d| format!("\\fB{}\\fR", roff_escape(&d.to_string_lossy())))
            .collect();
        if !defaults.is_empty() {
            lines.push(format!("Default: {}.", defaults.join(", ")));
        }
    }
    if let Some(env) = arg.get_env() {
        lines.push(format!(
            "Also read from \\fB{}\\fR.",
            roff_escape(&env.to_string_lossy())
        ));
    }
    lines
}

/// The heading `--help` prints an argument under.
fn heading_of(arg: &clap::Arg) -> String {
    arg.get_help_heading().unwrap_or("Options").to_string()
}

/// Every option `--help` shows, in its order, grouped by heading in the
/// order the headings first appear.
fn visible_options() -> Vec<(String, Vec<clap::Arg>)> {
    let mut cmd = sipnab::cli::Cli::command();
    cmd.build();
    let mut groups: Vec<(String, Vec<clap::Arg>)> = Vec::new();
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() || arg.is_positional() {
            continue;
        }
        let heading = heading_of(arg);
        match groups.iter_mut().find(|(h, _)| *h == heading) {
            Some((_, args)) => args.push(arg.clone()),
            None => groups.push((heading, vec![arg.clone()])),
        }
    }
    groups
}

/// The OPTIONS section body, generated from clap.
fn render_options() -> String {
    let mut out = String::new();
    out.push_str(
        "Every option, grouped as \\fBsipnab \\-\\-help\\fR groups them. Each entry is the\n\
         first paragraph of the option's help;\n\
         .B sipnab \\-\\-help\n\
         prints the full text, and\n\
         .I docs/cli\\-reference.md\n\
         describes every option with its configuration key.\n",
    );
    for (heading, args) in visible_options() {
        out.push_str(&format!(".SS {}\n", roff_escape(&heading)));
        for arg in args {
            out.push_str(".TP\n");
            out.push_str(&option_header(&arg));
            out.push('\n');
            for line in option_body(&arg) {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    out
}

/// The exit-code rows of `docs/cli-reference.md`, as (code, meaning).
fn reference_exit_codes() -> Result<Vec<(String, String)>, TestError> {
    let text = std::fs::read_to_string(repo().join("docs/cli-reference.md"))?;
    let start = text
        .find("\n## Exit codes\n")
        .ok_or("docs/cli-reference.md has an `## Exit codes` section")?;
    let mut rows = Vec::new();
    for line in text[start..].lines().skip(2) {
        if line.starts_with("## ") {
            break;
        }
        let Some(rest) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((code, meaning)) = rest.split_once("` | ") else {
            continue;
        };
        if code.chars().all(|c| c.is_ascii_digit()) && !code.is_empty() {
            rows.push((
                code.to_string(),
                meaning
                    .trim_end_matches(" |")
                    .trim_end_matches('|')
                    .trim()
                    .to_string(),
            ));
        }
    }
    Ok(rows)
}

/// The EXIT STATUS section body, generated from `docs/cli-reference.md`.
fn render_exit_status() -> Result<String, TestError> {
    let mut out = String::new();
    for (code, meaning) in reference_exit_codes()? {
        out.push_str(&format!(
            ".TP\n.B {code}\n{}\n",
            md_to_roff(&sentence(&meaning))
        ));
    }
    Ok(out)
}

/// The ENVIRONMENT section body, generated from the table `--help` prints.
fn render_environment() -> String {
    let mut out = String::new();
    for (name, what) in sipnab::cli::ENVIRONMENT {
        out.push_str(&format!(
            ".TP\n.B {}\n{}\n",
            roff_escape(name),
            md_to_roff(&sentence(what))
        ));
    }
    out
}

/// The marker pair around a generated region.
fn markers(region: &str) -> (String, String) {
    (
        format!(".\\\" BEGIN GENERATED {region}: {FIXER}\n"),
        format!(".\\\" END GENERATED {region}\n"),
    )
}

/// Replace the body between `region`'s markers with `body`.
fn splice(man: &str, region: &str, body: &str) -> Result<String, TestError> {
    let (begin, end) = markers(region);
    let b = man
        .find(&begin)
        .ok_or_else(|| format!("man/sipnab.1 has no `{}` marker", begin.trim_end()))?;
    let e = man[b..]
        .find(&end)
        .map(|i| b + i)
        .ok_or_else(|| format!("man/sipnab.1 has no `{}` marker", end.trim_end()))?;
    Ok(format!("{}{body}{}", &man[..b + begin.len()], &man[e..]))
}

/// Whether the committed page carries exactly the generated regions; with
/// [`APPLY_ENV`] set, write them instead.
fn check_generated(region: &str, body: &str) -> Result<(), TestError> {
    let man = man_page()?;
    let want = splice(&man, region, body)?;
    if want == man {
        return Ok(());
    }
    if std::env::var_os(APPLY_ENV).is_some() {
        std::fs::write(repo().join("man/sipnab.1"), &want)?;
        eprintln!("man/sipnab.1: rewrote the {region} region");
        return Ok(());
    }
    let first = man
        .lines()
        .zip(want.lines())
        .position(|(a, b)| a != b)
        .map_or_else(|| "a line count".to_string(), |i| format!("line {}", i + 1));
    Err(format!(
        "man/sipnab.1's {region} region is not what its source generates \
         (first difference at {first}). Regenerate it: {FIXER}"
    )
    .into())
}

#[test]
fn the_options_section_is_generated_from_clap() -> Result<(), TestError> {
    check_generated("OPTIONS", &render_options())
}

#[test]
fn the_exit_status_section_is_generated_from_the_cli_reference() -> Result<(), TestError> {
    let rows = reference_exit_codes()?;
    assert!(
        rows.len() >= 4,
        "read {} exit-code row(s) from docs/cli-reference.md; the table moved",
        rows.len()
    );
    check_generated("EXIT STATUS", &render_exit_status()?)
}

#[test]
fn the_environment_section_is_generated_from_the_help_table() -> Result<(), TestError> {
    check_generated("ENVIRONMENT", &render_environment())
}

// ── coverage rules, independent of the generator ─────────────────────────

/// The long flags named on the `.TP` header lines of a section.
fn header_flags(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let lines: Vec<&str> = text.lines().collect();
    for pair in lines.windows(2) {
        if pair[0] == ".TP" {
            for token in unescape(pair[1]).split([' ', ',', '"']) {
                if let Some(name) = token.strip_prefix("--") {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

/// OPTIONS has an entry for every visible flag, under its `--help` heading.
#[test]
fn every_visible_flag_has_an_options_entry() -> Result<(), TestError> {
    let man = man_page()?;
    let options = section(&man, "OPTIONS").ok_or("man/sipnab.1 has an OPTIONS section")?;
    let listed = header_flags(options);
    let groups = visible_options();
    let mut missing = Vec::new();
    let mut total = 0;
    for (_, args) in &groups {
        for arg in args {
            if let Some(long) = arg.get_long() {
                total += 1;
                if !listed.contains(long) {
                    missing.push(format!("--{long}"));
                }
            }
        }
    }
    assert!(total > 300, "clap reports only {total} visible long flags");
    let headings: Vec<&str> = groups
        .iter()
        .map(|(h, _)| h.as_str())
        .filter(|h| !options.contains(&format!(".SS {}\n", roff_escape(h))))
        .collect();
    assert!(
        missing.is_empty() && headings.is_empty(),
        "man/sipnab.1 OPTIONS covers {} of {total} visible flags. Missing \
         headings: {headings:?}. Missing flags ({}): {}. Regenerate: {FIXER}",
        total - missing.len(),
        missing.len(),
        missing.join(" ")
    );
    Ok(())
}

/// The page with every generated region's body removed: the hand-written
/// text only.
fn hand_written(man: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in man.lines() {
        if line.starts_with(".\\\" BEGIN GENERATED ") {
            inside = true;
        } else if line.starts_with(".\\\" END GENERATED ") {
            inside = false;
        } else if !inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Every long flag the hand-written text names is a flag the program has.
///
/// The generated regions are left out: their option headers come from clap,
/// and their bodies quote `--help`, which names other programs' flags on
/// purpose (restic's `--password-command`, `docker login --password-stdin`).
#[test]
fn every_flag_the_page_names_exists() -> Result<(), TestError> {
    let mut cmd = sipnab::cli::Cli::command();
    cmd.build();
    let real: BTreeSet<String> = cmd
        .get_arguments()
        .filter_map(|a| a.get_long().map(str::to_string))
        .collect();
    let re = regex::Regex::new(r"--([a-z0-9][a-z0-9-]*)")?;
    let man = hand_written(&man_page()?);
    assert!(
        man.contains(".SH DESCRIPTION") && !man.contains(".SS Capture"),
        "the generated regions were not removed, or the page lost its text"
    );
    let mut phantoms = BTreeSet::new();
    for line in man.lines().filter(|l| !l.starts_with(".\\\"")) {
        for cap in re.captures_iter(&unescape(line)) {
            let name = cap[1].trim_end_matches('-');
            if !real.contains(name) {
                phantoms.insert(format!("--{name}"));
            }
        }
    }
    assert!(
        phantoms.is_empty(),
        "man/sipnab.1 names flags sipnab does not have: {phantoms:?}"
    );
    Ok(())
}

/// Environment variable names that `src/` reads but that are not settings.
///
/// Each is read only by a test, and a reader of the man page has no use for
/// it. The gate below still proves each one is read somewhere, so an entry
/// that outlives its reader is reported.
const TEST_ONLY_ENV: &[(&str, &str)] = &[
    (
        "SIPNAB_FANOUT_DEV",
        "the interface an ignored capture test opens",
    ),
    (
        "SIPNAB_CORPUS",
        "the external corpus directory a skipped test reads",
    ),
    (
        "SIPNAB_SETTINGS_APPLY",
        "the settings table fixer, run as a test",
    ),
];

/// Every `SIPNAB_*` environment variable `src/` reads, found by its reading
/// call: `env::var` / `env::var_os` / `EnvFilter::try_from_env` with a literal
/// name, a `const ..._ENV` / `const ENV_VAR` naming one, and clap's
/// `env = "..."`.
fn sipnab_env_reads() -> Result<BTreeSet<String>, TestError> {
    let re = regex::Regex::new(
        r#"(?:env::var(?:_os)?\(\s*|try_from_env\(\s*|env = |const [A-Z0-9_]*ENV(?:_VAR)?: &str = )"(SIPNAB_[A-Z0-9_]+)""#,
    )?;
    let mut out = BTreeSet::new();
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path)?;
                for cap in re.captures_iter(&text) {
                    out.insert(cap[1].to_string());
                }
            }
        }
    }
    Ok(out)
}

/// The environment variables a reader must be told about: every one a clap
/// flag reads, and every `SIPNAB_*` one `src/` reads outside a test.
fn operator_env() -> Result<BTreeSet<String>, TestError> {
    let reads = sipnab_env_reads()?;
    for (name, why) in TEST_ONLY_ENV {
        assert!(
            reads.contains(*name),
            "{name} is listed as test-only ({why}) but nothing in src/ reads it \
             any more; drop it from TEST_ONLY_ENV"
        );
    }
    let mut out: BTreeSet<String> = reads
        .into_iter()
        .filter(|n| !TEST_ONLY_ENV.iter().any(|(t, _)| t == n))
        .collect();
    let mut cmd = sipnab::cli::Cli::command();
    cmd.build();
    for arg in cmd.get_arguments() {
        if let Some(env) = arg.get_env() {
            out.insert(env.to_string_lossy().into_owned());
        }
    }
    // SIPNAB_CONFIG is read by `Config::load` through a helper that takes the
    // name as an argument, so the scanner sees its literal elsewhere; name it.
    out.insert("SIPNAB_CONFIG".to_string());
    Ok(out)
}

/// The scanner finds the readers that exist today, including the ones that
/// read through a named constant.
#[test]
fn the_environment_scanner_finds_every_kind_of_reader() -> Result<(), TestError> {
    let reads = sipnab_env_reads()?;
    for expected in [
        "SIPNAB_LOG",               // try_from_env
        "SIPNAB_NO_MMAP",           // env::var_os literal
        "SIPNAB_MCP_TOKEN",         // env::var literal
        "SIPNAB_ARCHIVE_PASSWORD",  // const ENV_VAR
        "SIPNAB_SECCOMP_ALLOWLIST", // const ALLOWLIST_ENV
        "SIPNAB_AUDIO_PLUGIN",      // const PLUGIN_OVERRIDE_ENV
        "SIPNAB_HEP_AUTH",          // clap env =
    ] {
        assert!(
            reads.contains(expected),
            "the scanner missed {expected}: {reads:?}"
        );
    }
    Ok(())
}

/// The man page's ENVIRONMENT section names every environment variable sipnab
/// reads for an operator.
#[test]
fn every_environment_variable_sipnab_reads_is_in_the_man_page() -> Result<(), TestError> {
    let man = man_page()?;
    let env = section(&man, "ENVIRONMENT").ok_or("man/sipnab.1 has an ENVIRONMENT section")?;
    let named: BTreeSet<String> = env
        .lines()
        .filter_map(|l| l.strip_prefix(".B "))
        .map(|n| unescape(n).trim().to_string())
        .collect();
    let missing: Vec<String> = operator_env()?
        .into_iter()
        .filter(|n| !named.contains(n))
        .collect();
    assert!(
        missing.is_empty(),
        "man/sipnab.1 ENVIRONMENT does not name: {missing:?}"
    );
    Ok(())
}

/// `--help` names every environment variable sipnab reads for an operator.
///
/// `help_env_values_test` governs the other half: a value is never printed.
#[test]
fn every_environment_variable_sipnab_reads_is_named_in_help() -> Result<(), TestError> {
    let mut cmd = sipnab::cli::Cli::command();
    let help = cmd.render_long_help().to_string();
    let missing: Vec<String> = operator_env()?
        .into_iter()
        .filter(|n| !help.contains(n.as_str()))
        .collect();
    assert!(missing.is_empty(), "sipnab --help never names: {missing:?}");
    Ok(())
}

// ── roff well-formedness ──────────────────────────────────────────────────

/// Font-alternating macros (`.BR`, `.IR`, ...) join their arguments with no
/// space between them, so two adjacent words run together:
/// `.BR the terminal viewer (1)` renders "theterminalviewer(1)".
fn run_together_words(man: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (n, line) in man.lines().enumerate() {
        let Some(args) = [".BR ", ".RB ", ".BI ", ".IB ", ".IR ", ".RI "]
            .iter()
            .find_map(|m| line.strip_prefix(m))
        else {
            continue;
        };
        let mut words = Vec::new();
        let mut rest = args.trim();
        while !rest.is_empty() {
            if let Some(q) = rest.strip_prefix('"') {
                let end = q.find('"').unwrap_or(q.len());
                words.push(&q[..end]);
                rest = q.get(end + 1..).unwrap_or("").trim_start();
            } else {
                let end = rest.find(' ').unwrap_or(rest.len());
                words.push(&rest[..end]);
                rest = rest[end..].trim_start();
            }
        }
        for pair in words.windows(2) {
            let ends = pair[0].chars().last().is_some_and(char::is_alphanumeric);
            let starts = pair[1].chars().next().is_some_and(char::is_alphanumeric);
            if ends && starts {
                found.push(format!("line {}: {line}", n + 1));
                break;
            }
        }
    }
    found
}

#[test]
fn no_macro_runs_two_words_together() -> Result<(), TestError> {
    let found = run_together_words(&man_page()?);
    assert!(
        found.is_empty(),
        "man/sipnab.1 joins words with no space between them; quote the \
         phrase or use .B:\n  {}",
        found.join("\n  ")
    );
    Ok(())
}

#[test]
fn the_run_together_check_catches_the_scrubbed_name() {
    assert_eq!(run_together_words(".BR the terminal viewer (1)\n").len(), 1);
    for fine in [
        ".BR tshark (1),",
        ".RB [ \\-d",
        ".BI \\-d \" iface\"",
        ".RB ( \"\\-N \\-\\-json\" )",
    ] {
        assert!(run_together_words(fine).is_empty(), "false hit: {fine}");
    }
}

/// groff, with every warning on, has nothing to say about the page.
#[test]
fn the_page_formats_without_warnings() -> Result<(), TestError> {
    let page = repo().join("man/sipnab.1");
    let out = match std::process::Command::new("groff")
        .args(["-man", "-ww", "-z"])
        .arg(Path::new(&page))
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            eprintln!("man page formatting... NOT CHECKED (groff not runnable: {e})");
            return Ok(());
        }
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.trim().is_empty(),
        "groff -man -ww -z man/sipnab.1 warned:\n{stderr}"
    );
    Ok(())
}

/// The renderer escapes what roff would otherwise read as markup.
#[test]
fn the_renderer_escapes_roff_markup() {
    assert_eq!(
        md_to_roff("Use `--x` \\ now"),
        "Use \\fB\\-\\-x\\fR \\e now"
    );
    assert_eq!(md_to_roff(".start"), "\\&.start");
    assert_eq!(md_to_roff("a — b"), "a \\(em b");
    assert_eq!(md_to_roff("see [the page](x.md)"), "see the page");
    assert_eq!(
        md_to_roff("**It denies nothing**"),
        "\\fBIt denies nothing\\fR"
    );
}
