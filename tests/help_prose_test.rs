// SPDX-License-Identifier: MIT OR Apache-2.0

//! What `--help` says about a flag is a statement about the binary it ships
//! in, in the present tense.
//!
//! Two kinds of sentence break that, and both reached a release:
//!
//! - **A value the flag accepts, described as missing.** `--seccomp` listed
//!   `enforce` under `[possible values]` while its own text, and its row in
//!   `docs/cli-reference.md`, said the enforcing action was not implemented.
//!   Both statements were printed by one `--help`, and one of them was false.
//! - **History.** "This help used to say ...", "(previously ...)", "(#64)".
//!   An operator reading `--help` needs what the flag does now; the past
//!   belongs in `CHANGELOG.md` and the issue tracker, where it is dated.
//!
//! Both rules read clap's own metadata, so a flag added later is covered
//! without editing this file.

// The flag set is feature-dependent (`--plugin` exists only with `plugins`),
// and the documentation describes the full-featured binary.
#![cfg(feature = "full")]

use clap::CommandFactory as _;
use std::path::PathBuf;

type TestError = Box<dyn std::error::Error>;

/// The repository root.
fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Wording that says a capability does not exist yet.
///
/// Case-insensitive. Each alternative is a phrase that, in a help entry whose
/// flag lists its values, denies one of them.
const UNIMPLEMENTED: &str = r"(?i)\bnot (yet )?implemented\b|\bunimplemented\b|\bexists? yet\b|\bnot yet (supported|available)\b|\bno [a-z-]+ (mode|action|value) exists\b";

/// History wording that has no place in `--help`.
///
/// `used to` and `previously` narrate a change; `(#NNN)` cites an issue
/// number a reader of `--help` has no way to follow.
const HISTORY: &str = r"(?i)\bused to\b|\bpreviously\b|\(#\d+\)";

/// Every argument's full help text, by its long name (or value name for a
/// positional).
fn help_entries() -> Vec<(String, String, Vec<String>)> {
    let mut cmd = sipnab::cli::Cli::command();
    cmd.build();
    cmd.get_arguments()
        .map(|a| {
            let name = a
                .get_long()
                .map_or_else(|| a.get_id().to_string(), |l| format!("--{l}"));
            let text = a
                .get_long_help()
                .or_else(|| a.get_help())
                .map(ToString::to_string)
                .unwrap_or_default();
            let values = a
                .get_possible_values()
                .iter()
                .filter(|v| !v.is_hide_set())
                .map(|v| v.get_name().to_string())
                .collect();
            (name, text, values)
        })
        .collect()
}

/// The `docs/cli-reference.md` table row whose first cell names `flag`.
fn reference_row<'a>(reference: &'a str, flag: &str) -> Option<&'a str> {
    let code = format!("`{flag}`");
    reference.lines().find(|line| {
        line.starts_with('|')
            && line.split(" | ").next().is_some_and(|first| {
                first
                    .split(", ")
                    .any(|c| c.trim_start_matches("| ") == code)
            })
    })
}

/// Which help entries (and cli-reference rows) call something unimplemented
/// while the flag lists values.
fn unimplemented_claims(
    entries: &[(String, String, Vec<String>)],
    reference: &str,
) -> Result<Vec<String>, TestError> {
    let re = regex::Regex::new(UNIMPLEMENTED)?;
    let mut found = Vec::new();
    for (flag, text, values) in entries {
        if values.is_empty() {
            continue;
        }
        if let Some(m) = re.find(text) {
            found.push(format!(
                "{flag} --help (values {values:?}) says {:?}",
                m.as_str()
            ));
        }
        if let Some(row) = reference_row(reference, flag)
            && let Some(m) = re.find(row)
        {
            found.push(format!(
                "{flag} docs/cli-reference.md row (values {values:?}) says {:?}",
                m.as_str()
            ));
        }
    }
    Ok(found)
}

/// A flag that lists its values never describes one of them as missing.
///
/// The rule is narrowed to flags with `[possible values]` because that is
/// where the contradiction is printed on one screen: the value list is clap's
/// own, and a sentence denying a capability beside it is the stale half.
#[test]
fn no_flag_with_listed_values_calls_a_capability_unimplemented() -> Result<(), TestError> {
    let entries = help_entries();
    let with_values = entries.iter().filter(|(_, _, v)| !v.is_empty()).count();
    assert!(
        with_values >= 10,
        "only {with_values} flag(s) list possible values; the rule has stopped \
         reading clap's value lists"
    );
    let reference = std::fs::read_to_string(repo().join("docs/cli-reference.md"))?;
    let found = unimplemented_claims(&entries, &reference)?;
    assert!(
        found.is_empty(),
        "a flag lists a value while its text says a capability does not \
         exist. Describe what each listed value does now:\n  {}",
        found.join("\n  ")
    );
    Ok(())
}

/// The matcher catches the sentence that shipped, in both places it shipped.
#[test]
fn the_unimplemented_matcher_catches_the_seccomp_sentence() -> Result<(), TestError> {
    let entries = vec![(
        "--seccomp".to_string(),
        "It cannot end a run. The killing action a derived allowlist would use \
         is deliberately not implemented yet."
            .to_string(),
        vec!["off".to_string(), "log".to_string(), "enforce".to_string()],
    )];
    let reference =
        "| `--seccomp` | `<MODE>` | `off` | which is why no enforcing mode exists yet. |\n";
    let found = unimplemented_claims(&entries, reference)?;
    assert_eq!(found.len(), 2, "both surfaces are reported: {found:?}");
    // A flag without listed values is out of scope for this rule.
    let plain = vec![("--x".to_string(), "not implemented yet".to_string(), vec![])];
    assert!(unimplemented_claims(&plain, reference)?.is_empty());
    Ok(())
}

/// The history phrases found in a help text.
fn history_in(text: &str) -> Result<Vec<String>, TestError> {
    let re = regex::Regex::new(HISTORY)?;
    Ok(re.find_iter(text).map(|m| m.as_str().to_string()).collect())
}

/// `--help` states facts about this binary; it never narrates a change.
///
/// Nothing is allowlisted. A sentence that needs `used to` to make its point
/// can say what is true now instead, and the change it describes is dated in
/// `CHANGELOG.md`.
#[test]
fn help_carries_no_history() -> Result<(), TestError> {
    let mut cmd = sipnab::cli::Cli::command();
    let help = cmd.render_long_help().to_string();
    assert!(
        help.lines().count() > 1000,
        "the rendered --help is {} lines; this is not the full text",
        help.lines().count()
    );
    let mut found = Vec::new();
    for line in help.lines() {
        let phrases = history_in(line)?;
        if !phrases.is_empty() {
            let head: String = line.trim().chars().take(90).collect();
            found.push(format!("{phrases:?} in: {head}"));
        }
    }
    assert!(
        found.is_empty(),
        "--help narrates history; state what is true now:\n  {}",
        found.join("\n  ")
    );
    Ok(())
}

/// The history matcher catches each form that shipped and leaves present-tense
/// prose alone.
#[test]
fn the_history_matcher_catches_each_shipped_form() -> Result<(), TestError> {
    for shipped in [
        "This help used to say \"track simultaneously\"",
        "(previously an unrecognized transport passed parse silently)",
        "reaches the cap 27x sooner than one file (#64).",
    ] {
        assert_eq!(history_in(shipped)?.len(), 1, "missed: {shipped}");
    }
    for present in [
        "The eviction count is reported wherever a dialog count appears.",
        "Accepts only `stdio` or `http`; any other value is rejected at parse time.",
    ] {
        assert!(history_in(present)?.is_empty(), "false hit: {present}");
    }
    Ok(())
}
