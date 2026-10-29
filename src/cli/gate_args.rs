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
    /// suite's: 0 when every rule that ran passed, 3 when one failed, 2 when
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

    /// Ask the relay named by `--rtpengine-control` which calls it is
    /// holding right now, print their Call-IDs, and exit.
    ///
    /// The answer `GET /v1/relay/holdings` returns and the MCP `query_relay`
    /// tool lists. Asking transmits one `list` request, so it needs the same
    /// live source `--rtpengine-control` does (`-d`, `-L`); on `-I <file>` it
    /// asks nothing and exits 2. It runs before the capture opens: no packet
    /// is read and no other query is answered. Exits 0 with the list, 1 when
    /// the relay did not answer (`unreachable`), declined (`refused`) or
    /// answered with something that cannot be trusted (`suspect`). With
    /// `--json`, one JSON object on the last line of stdout, the body the
    /// REST route returns, including those classifications.
    #[arg(help_heading = "Queries", long, requires = "rtpengine_control")]
    pub relay_holdings: bool,

    /// The most Call-IDs `--relay-holdings` asks the relay for (default 32).
    /// When the relay returns that many it may hold more, and the answer
    /// says so (`truncated` under `--json`).
    ///
    /// The relay's own `list` limit, REST's `max_calls`. rtpengine answers
    /// over UDP, and a large limit may not fit in one datagram.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "CALLS",
        requires = "relay_holdings",
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    pub relay_holdings_max: Option<u32>,
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
        vec![
            OneShot {
                name: "--expect",
                active: self.expect.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--relay-holdings",
                active: self.relay_holdings,
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}
