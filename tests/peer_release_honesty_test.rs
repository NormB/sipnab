// SPDX-License-Identifier: MIT OR Apache-2.0

//! Documentation may not tell a reader to run a peer command that no released
//! build of that peer has.
//!
//! # The defect this exists for
//!
//! sipnab's TFPS surfaces -- six MCP tools, six REST routes, `--evidence-out`
//! -- were built against a TFPS branch that adds `--json` output and an
//! `ingest` subcommand. That branch is not merged and not proposed upstream,
//! so a reader following sipnab's own examples ran
//! `sipnab ... | tfps_ctl ingest` against a `tfps_ctl` that has no `ingest`,
//! and read tool descriptions promising JSON a released `tfps_ctl` never
//! emits. sipnab's features are real; the peer capability they need is not
//! published yet, and the documentation said otherwise.
//!
//! A feature may ship ahead of its peer. Instructions may not.

use std::path::Path;

/// Subcommands a released `tfps_ctl` accepts.
///
/// Read from sippulse/tfps's default branch:
/// `git show sippulse/master:crates/tfps/src/bin/tfps_ctl.rs` at `984577dc`,
/// checked 2026-09-18, and confirmed by running the binary built from it.
/// Absent from it, and so absent here: `dropped` and `ingest`. When a change
/// reaches TFPS's default branch, add it here in the same commit that
/// documents it.
const RELEASED_SUBCOMMANDS: &[&str] = &[
    "status",
    "stats",
    "banned",
    "unban",
    "ban",
    "sources",
    "source",
    "peers",
    "countries",
    "log",
    "forget",
];

/// Flags a released `tfps_ctl` accepts, from the same source.
///
/// `--json` joined on 2026-09-18, when sippulse/tfps#6 merged into `master`.
/// No tag carries it yet (v0.2.1 is the newest and rejects it), so every page
/// that tells a reader to use it also says to build TFPS from `master`.
/// `--a` and `--config` were accepted by v0.2.1 already and had been missing
/// from this list.
const RELEASED_FLAGS: &[&str] = &[
    "--a",
    "--all",
    "--bogus",
    "--config",
    "--country",
    "--db",
    "--help",
    "--ip",
    "--json",
    "--limit",
    "--map",
    "--peer",
    "--ttl",
    "--why",
];

fn docs() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "md")
                && let Ok(body) = std::fs::read_to_string(&p)
            {
                out.push((p.display().to_string(), body));
            }
        }
    }
    out
}

/// Every `tfps_ctl` invocation a line tells the reader to run.
///
/// Only inside a code span: prose that names the program ("`tfps_ctl` not
/// found on PATH") is not an instruction, and the words after it belong to
/// the sentence rather than to a command line. Reading whole lines caught
/// exactly that and flagged sipnab's own flags mentioned nearby.
fn invocations(line: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for span in line.split('`').skip(1).step_by(2) {
        let Some(i) = span.find("tfps_ctl ") else {
            continue;
        };
        // A command line, not a bare mention: the span begins with the program,
        // or pipes into it.
        let head = span[..i].trim_end_matches(['\\', '|', '$', ' ']);
        if !head.is_empty() {
            continue;
        }
        let words: Vec<String> = span[i + "tfps_ctl ".len()..]
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| "`\"'(),.".contains(c)).to_string())
            .filter(|w| !w.is_empty())
            .collect();
        if !words.is_empty() {
            out.push(words);
        }
    }
    out
}

/// What a line promises that a released peer cannot do.
fn unreleased_claims(line: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for words in invocations(line) {
        let sub = &words[0];
        if !sub.starts_with('-') && !RELEASED_SUBCOMMANDS.contains(&sub.as_str()) {
            bad.push(format!("subcommand `{sub}`"));
        }
        for w in &words {
            if w.starts_with("--") && !RELEASED_FLAGS.contains(&w.as_str()) {
                bad.push(format!("flag `{w}`"));
            }
        }
    }
    bad
}

#[test]
fn no_document_instructs_a_tfps_command_the_released_peer_lacks() {
    let mut problems = Vec::new();
    for (path, body) in docs() {
        for (n, line) in body.lines().enumerate() {
            for claim in unreleased_claims(line) {
                problems.push(format!("{path}:{}: {claim}", n + 1));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "documentation instructs peer commands no released TFPS has ({}):\n{}\n\n         The features here are sipnab's and real; the peer capability is on an \
         unmerged branch. Do not instruct it until it is released, and then add \
         it to RELEASED_SUBCOMMANDS/RELEASED_FLAGS in the same commit.",
        problems.len(),
        problems.join("\n")
    );
}

/// POSITIVE CONTROL: the reader sees an unreleased subcommand and an
/// unreleased flag, and does not flag a released invocation.
#[test]
fn the_reader_reports_unreleased_commands_and_leaves_released_ones_alone() {
    assert_eq!(
        unreleased_claims("run `tfps_ctl ingest` on the host"),
        ["subcommand `ingest`"]
    );
    assert_eq!(
        unreleased_claims("`tfps_ctl log --since 3600`"),
        ["flag `--since`"]
    );
    assert!(unreleased_claims("`tfps_ctl banned --limit 5`").is_empty());
    assert!(
        unreleased_claims("`tfps_ctl status --json`").is_empty(),
        "--json is on sippulse/tfps master since #6"
    );
    assert!(unreleased_claims("`tfps_ctl status`").is_empty());
    assert!(
        unreleased_claims("point --tfps-ctl at the tfps_ctl program").is_empty(),
        "prose naming the program is not an instruction"
    );
}

/// sipnab's own `--help` instructs too, and it is the page a reader meets
/// first. `--evidence-out` told readers to pipe into `tfps_ctl ingest`, a
/// subcommand no TFPS build has, and the document scan above never saw it:
/// it reads `docs/` alone, and the help text lives in `src/cli.rs`.
#[cfg(feature = "native")]
#[test]
fn no_cli_help_instructs_a_tfps_command_the_released_peer_lacks() {
    use clap::CommandFactory;
    let cmd = sipnab::cli::Cli::command();
    let mut problems = Vec::new();
    let mut scanned = 0usize;
    for arg in cmd.get_arguments() {
        let name = arg.get_long().unwrap_or(arg.get_id().as_str());
        for help in [arg.get_help(), arg.get_long_help()].into_iter().flatten() {
            scanned += 1;
            // One string per help text: a code span the renderer wrapped
            // across lines is still one command.
            let text = help.to_string().replace('\n', " ");
            for claim in unreleased_claims(&text) {
                problems.push(format!("--{name}: {claim}"));
            }
        }
    }
    assert!(
        scanned > 200
            && cmd
                .get_arguments()
                .any(|a| a.get_long() == Some("tfps-ctl")),
        "scanned {scanned} help texts without reaching --tfps-ctl; the walk has \
         stopped seeing the flags and this gate proves nothing"
    );
    problems.sort();
    problems.dedup();
    assert!(
        problems.is_empty(),
        "sipnab's --help instructs peer commands no released TFPS has:\n{}",
        problems.join("\n")
    );
}
