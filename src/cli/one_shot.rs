// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The one-shot query flag registry.
//!
//! A one-shot query flag answers one question about the capture and exits:
//! `--talkers`, `--call-tree`, `--expect` and the rest of the CLI query family
//! (see `docs/design/par5-cli-queries.md`). Every such flag shares three rules
//! with the report flags that came before it:
//!
//! 1. whether it raises the TUI or implies `-N` ([`Cli::normalize`]),
//! 2. whether it needs `-N` typed beside it ([`Cli::validate`]), and
//! 3. whether it writes to stdout, which `--mcp` on stdio owns
//!    ([`Cli::validate`] again).
//!
//! Those rules used to be lists written inside `normalize` and `validate`, one
//! entry per flag. Each query flag instead declares itself once, as a
//! [`OneShot`], from its own `Args` struct's `one_shots` method, and the two
//! functions iterate the declarations. A new flag is then one edit, in the file
//! that owns it, and no two flags edit the same lines.
//!
//! [`Cli::normalize`]: super::Cli
//! [`Cli::validate`]: super::Cli::validate

/// One query flag's declaration of how it interacts with the run mode.
///
/// Built by an `Args` struct's `one_shots` method from its own parsed fields,
/// so `active` is a fact about this command line, not about the flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneShot {
    /// The flag as an operator types it, `--talkers`. Named in refusals.
    pub name: &'static str,
    /// Whether this command line set the flag.
    pub active: bool,
    /// Whether the flag implies `-N`, the way `--call-report` does: the run
    /// becomes headless without the operator typing it. When `false`, an
    /// active flag without `-N` is refused, the way `--report` is.
    pub implies_no_tui: bool,
    /// Whether the flag's answer is written to stdout. An active flag that
    /// does is refused beside `--mcp` on the stdio transport, whose JSON-RPC
    /// wire is stdout.
    pub owns_stdout: bool,
}

/// Whether any active one-shot implies `-N`.
///
/// # Arguments
///
/// * `shots` — every declared one-shot, active or not.
#[must_use]
pub fn any_implies_no_tui(shots: &[OneShot]) -> bool {
    shots.iter().any(|s| s.active && s.implies_no_tui)
}

/// The names of the active one-shots that need `-N` typed beside them.
///
/// A flag that implies `-N` is not listed: [`any_implies_no_tui`] already made
/// the run headless, and naming it here would refuse the operator for not
/// typing what the flag promised to set.
#[must_use]
pub fn needing_no_tui(shots: &[OneShot]) -> Vec<&'static str> {
    shots
        .iter()
        .filter(|s| s.active && !s.implies_no_tui)
        .map(|s| s.name)
        .collect()
}

/// The names of the active one-shots that write to stdout.
#[must_use]
pub fn writing_stdout(shots: &[OneShot]) -> Vec<&'static str> {
    shots
        .iter()
        .filter(|s| s.active && s.owns_stdout)
        .map(|s| s.name)
        .collect()
}

/// The registry's own rules, driven by declarations written here rather than
/// by any real flag, so they hold before the first query flag exists.
#[cfg(test)]
mod tests {
    use super::*;

    /// A declaration with every property chosen by the test.
    fn shot(name: &'static str, active: bool, implies: bool, stdout: bool) -> OneShot {
        OneShot {
            name,
            active,
            implies_no_tui: implies,
            owns_stdout: stdout,
        }
    }

    /// Only an ACTIVE flag that implies `-N` makes the run headless.
    #[test]
    fn only_an_active_implying_flag_implies_no_tui() {
        assert!(!any_implies_no_tui(&[]));
        assert!(!any_implies_no_tui(&[shot("--a", false, true, true)]));
        assert!(!any_implies_no_tui(&[shot("--a", true, false, true)]));
        assert!(any_implies_no_tui(&[
            shot("--a", true, false, true),
            shot("--b", true, true, false),
        ]));
    }

    /// A flag that implies `-N` is never refused for lacking it; an inactive
    /// flag is never named at all.
    #[test]
    fn needing_no_tui_names_active_non_implying_flags_only() {
        let shots = [
            shot("--implies", true, true, true),
            shot("--needs", true, false, true),
            shot("--idle", false, false, true),
        ];
        assert_eq!(needing_no_tui(&shots), vec!["--needs"]);
    }

    /// Only an active flag that writes stdout conflicts with the MCP wire.
    #[test]
    fn writing_stdout_names_active_stdout_flags_only() {
        let shots = [
            shot("--writes", true, true, true),
            shot("--file", true, true, false),
            shot("--idle", false, true, true),
        ];
        assert_eq!(writing_stdout(&shots), vec!["--writes"]);
    }
}
