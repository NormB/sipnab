// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
/// TFPS v0.3.0 is the first release that carries it
/// (`sipnab::security::tfps::JSON_MODE_SINCE`), so every page that tells a
/// reader to use it names that release.
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

/// The JSON mode's release: sipnab's hint and every page say which TFPS
/// release has `tfps_ctl --json`. The hint lives in a module the `native`
/// feature builds, so these tests build with it.
#[cfg(feature = "native")]
mod json_mode_release {
    use super::docs;

    /// Wording that says no TFPS release has the JSON mode, in lower case.
    ///
    /// Each was on a docs page, or in sipnab's own hint, on 2026-11-10, ten days
    /// after TFPS v0.3.0 shipped the mode. A reader on a release that works was
    /// told to build from `master`.
    const NO_RELEASE_HAS_JSON: &[&str] = &[
        "no tagged release",
        "in no release yet",
        "no release carries it",
        "until a tagged release",
        "until the next release",
        "the latest release, v0.2.1",
        "v0.2.1, the newest",
        "the tfps in use is a release",
    ];

    /// Whether a line of text says no TFPS release has the JSON mode.
    fn says_no_release_has_json(line: &str) -> bool {
        let line = line.to_lowercase();
        NO_RELEASE_HAS_JSON.iter().any(|p| line.contains(p))
    }

    /// The pages that state which TFPS a reader needs: every docs page that names
    /// the release without the mode.
    fn pages_naming_the_release_without_json() -> Vec<(String, String)> {
        docs()
            .into_iter()
            .filter(|(path, body)| !path.contains("/design/") && body.contains("v0.2.1"))
            .collect()
    }

    #[test]
    fn the_hint_names_the_release_that_has_the_json_mode() {
        use sipnab::security::tfps::{JSON_MODE_HINT, JSON_MODE_SINCE};
        assert!(
            JSON_MODE_HINT.contains(JSON_MODE_SINCE),
            "an operator whose tfps_ctl rejects --json is not told which TFPS \
             release accepts it ({JSON_MODE_SINCE}): {JSON_MODE_HINT}"
        );
        assert!(
            !says_no_release_has_json(JSON_MODE_HINT),
            "the hint still says no TFPS release has --json: {JSON_MODE_HINT}"
        );
        assert!(
            !JSON_MODE_HINT.contains("build TFPS from master"),
            "the hint sends the operator to a source build although a release \
             has the mode: {JSON_MODE_HINT}"
        );
    }

    #[test]
    fn the_hint_still_says_which_releases_lack_the_mode_and_where_tfps_lives() {
        use sipnab::security::tfps::JSON_MODE_HINT;
        for needle in [
            "no JSON mode",
            "v0.2.1",
            "sippulse/tfps#6",
            "https://github.com/sippulse/tfps",
        ] {
            assert!(
                JSON_MODE_HINT.contains(needle),
                "hint lost `{needle}`: {JSON_MODE_HINT}"
            );
        }
    }

    #[test]
    fn the_first_release_with_json_is_a_version_tag() -> Result<(), Box<dyn std::error::Error>> {
        use sipnab::security::tfps::JSON_MODE_SINCE;
        let digits = JSON_MODE_SINCE
            .strip_prefix('v')
            .ok_or("a TFPS tag starts with v")?;
        let parts: Vec<&str> = digits.split('.').collect();
        assert_eq!(parts.len(), 3, "{JSON_MODE_SINCE} is not vX.Y.Z");
        assert!(
            parts.iter().all(|p| p.parse::<u32>().is_ok()),
            "{JSON_MODE_SINCE} is not vX.Y.Z"
        );
        assert_ne!(JSON_MODE_SINCE, "v0.2.1", "v0.2.1 rejects --json");
        Ok(())
    }

    #[test]
    fn no_document_says_no_tfps_release_has_the_json_mode() {
        let mut problems = Vec::new();
        let mut scanned = 0usize;
        for (path, body) in docs() {
            if path.contains("/design/") {
                continue;
            }
            scanned += 1;
            // Joined, so a phrase a line break splits is still one phrase.
            let lines: Vec<&str> = body.lines().collect();
            for (n, pair) in lines.windows(2).enumerate() {
                let joined = format!(
                    "{} {}",
                    pair[0].trim_start_matches(['>', ' ']),
                    pair[1].trim_start_matches(['>', ' '])
                );
                if says_no_release_has_json(pair[0])
                    || (!says_no_release_has_json(pair[1]) && says_no_release_has_json(&joined))
                {
                    problems.push(format!("{path}:{}: {}", n + 1, pair[0].trim()));
                }
            }
            if let Some(last) = lines.last()
                && says_no_release_has_json(last)
            {
                problems.push(format!("{path}:{}: {}", lines.len(), last.trim()));
            }
        }
        assert!(
            scanned > 80,
            "read {scanned} docs pages; the walk is broken"
        );
        assert!(
            problems.is_empty(),
            "these lines say no TFPS release has `tfps_ctl --json`. {} has it; \
             name that release:\n{}",
            sipnab::security::tfps::JSON_MODE_SINCE,
            problems.join("\n")
        );
    }

    #[test]
    fn every_page_that_names_the_release_without_json_names_the_one_with_it() {
        use sipnab::security::tfps::JSON_MODE_SINCE;
        let pages = pages_naming_the_release_without_json();
        assert!(
            pages.len() >= 5,
            "{} pages name v0.2.1; the peer notes on the TFPS guides, the tool \
             page, the config reference and the REST reference all did",
            pages.len()
        );
        let missing: Vec<&str> = pages
            .iter()
            .filter(|(_, body)| !body.contains(JSON_MODE_SINCE))
            .map(|(path, _)| path.as_str())
            .collect();
        assert!(
            missing.is_empty(),
            "these pages say v0.2.1 rejects `--json` and never say {JSON_MODE_SINCE} \
             accepts it:\n{}",
            missing.join("\n")
        );
    }

    /// POSITIVE CONTROL for the wording reader: it reports each stale phrase, in
    /// any case, and leaves a true statement about the releases alone.
    #[test]
    fn the_wording_reader_reports_stale_claims_and_leaves_true_ones_alone() {
        for stale in [
            "- No tagged release carries it yet. v0.2.1, the newest, rejects `--json`.",
            "- It is in no release yet. v0.2.1 answers `unknown option: --json`.",
            "- Master has it, merged on 2026-09-18. No release carries it yet.",
            "> rejects `--json`. Until a tagged release carries it, build from `master`.",
            "> Until the next release, build TFPS from its `master` branch.",
            "- The latest release, v0.2.1, has no `--json` option.",
            "- **`unknown option: --json`.** The TFPS in use is a release. Build master.",
            "NO TAGGED RELEASE has it",
        ] {
            assert!(says_no_release_has_json(stale), "not reported: {stale}");
        }
        for fine in [
            "- TFPS v0.3.0 and later have it. v0.2.1 and earlier reject `--json`.",
            "- TFPS came from a build of master at `984577dc`.",
            "no TFPS build has a dropped subcommand yet, released or on master",
            "Ask TFPS to release a source sipnab banned.",
            "",
        ] {
            assert!(!says_no_release_has_json(fine), "wrongly reported: {fine}");
        }
    }
}
