// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Gate and relay query flags: a pass/fail exit for CI, and the relay's holdings.
//!
//! Owned by batch B4 of the CLI query family; see
//! `docs/design/par5-cli-queries.md` for what each batch owns. The struct is
//! flattened into [`super::Cli`] already, so adding a flag here edits only
//! this file: the flag is a field below, and its [`OneShot`] declaration is
//! an entry in [`GateArgs::one_shots`], which `normalize` and `validate` read.

use super::one_shot::OneShot;

/// Gate and relay query flags (`--expect`, `--relay-holdings`).
///
/// Split out of [`super::Cli`] so clap's generated parser builds this group
/// in its own stack frame, like every other group.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct GateArgs {
    /// Judge the capture against the expectations in a suite file
    /// (`sipnab.expect.toml`), print each rule's verdict, and exit with the
    /// suite's: 0 when every rule that ran passed, 1 when one failed, 2 when
    /// no rule ran.
    ///
    /// Each rule names a metric (`count`, `asr`, `lint_errors`, `mos_p<N>`),
    /// a comparison and a threshold, and may narrow by a `filter:` scope.
    /// The suite is read and checked before the capture is: a file that
    /// cannot be read or parsed, or a rule the evaluator refuses, exits 2
    /// naming it. Judges every dialog of the capture; each rule's own scope
    /// narrows it, and `--filter` does not. Honors `--lint-suppress-file` for
    /// `lint_errors` rules. With `--json`, one JSON object on the last line of
    /// stdout, the report the MCP `evaluate_expectations` tool returns.
    /// Makes the run headless, as `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "FILE",
        value_parser = parse_expect,
    )]
    pub expect: Option<crate::output::query::expectations::SuiteFile>,
}

/// Read and check an `--expect` suite file while the command line is
/// parsed, so a defect in the suite stops the run before the capture is read.
fn parse_expect(s: &str) -> Result<crate::output::query::expectations::SuiteFile, String> {
    crate::output::query::expectations::read_suite(std::path::Path::new(s))
}

impl GateArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        vec![OneShot {
            name: "--expect",
            active: self.expect.is_some(),
            implies_no_tui: true,
            owns_stdout: true,
        }]
    }
}
