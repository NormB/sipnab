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

/// Gate and relay query flags (`--expect`, `--relay-holdings`,
/// `--relay-sessions`).
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

    /// The most held calls one relay ask covers (default 32): the Call-IDs
    /// `--relay-holdings` asks for, the held calls `--relay-sessions`
    /// queries, and the default for the TUI sessions view and for REST and
    /// MCP asks that name no `max_calls`.
    ///
    /// The relay's own `list` limit. When the relay returns that many it may
    /// hold more, and the answer says so (`truncated` under `--json`).
    /// Above 1024 it is lowered to 1024 on every surface, and the answer
    /// says so; 0 exits 2. rtpengine answers a `list` above 32 over its
    /// stream transport. Needs `--rtpengine-control`.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "CALLS",
        value_parser = crate::relay::scan_cap::parse_cap_flag,
    )]
    pub relay_holdings_max: Option<u32>,

    /// Ask the relay named by `--rtpengine-control` which calls it holds and,
    /// for each, whether media reaches it each way; print the answer and exit.
    ///
    /// Sends one `list` and then one `query` per held call, up to
    /// `--relay-holdings-max` (default 32). For each party's RTP socket the
    /// answer says `never_received` (no packet in, and the relay never
    /// confirmed the socket), `stalled` (no packet for more than 2 s while
    /// another socket of the call received one), `flowing`, or
    /// `not_reported`, from the relay's own counters and clock. A call with an
    /// early media branch is shown with its counters and no verdict. Every
    /// value is `relay_reported`. The answer `GET /v1/relay/sessions?scan=true`
    /// returns. Needs a live source (`-d`, `-L`): on `-I <file>` it asks
    /// nothing and exits 2. Exits 0 with the answer, 1 when the relay did not
    /// answer the `list`. With `--json`, one JSON object on the last line of
    /// stdout.
    #[arg(help_heading = "Queries", long, requires = "rtpengine_control")]
    pub relay_sessions: bool,

    /// With `--relay-sessions`, ask about this Call-ID only: one `list` and one
    /// `query`, without querying the other held calls.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "CALL-ID",
        requires = "relay_sessions"
    )]
    pub relay_sessions_call: Option<String>,
}

/// Read and check an `--expect` suite file while the command line is
/// parsed, so a defect in the suite stops the run before the capture is read.
fn parse_expect(s: &str) -> Result<crate::output::query::expectations::SuiteFile, String> {
    crate::output::query::expectations::read_suite(std::path::Path::new(s))
}

impl GateArgs {
    /// Whether `--relay-holdings-max` was given on a run that names no relay
    /// to ask.
    ///
    /// The cap sets every surface's default (the one-shot flags, the TUI
    /// sessions view, REST and MCP), so a relay is all it needs. Checked by
    /// `Cli::validate`, which knows whether `--rtpengine-control` was given.
    #[must_use]
    pub const fn listing_cap_without_a_relay(&self, relay_named: bool) -> bool {
        self.relay_holdings_max.is_some() && !relay_named
    }

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
            OneShot {
                name: "--relay-sessions",
                active: self.relay_sessions,
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap needs a relay to ask: without one it is refused, with one it
    /// is not, whatever else is on the command line, and absent it asks for
    /// nothing.
    #[test]
    fn the_listing_cap_needs_a_relay_to_ask() {
        let with = |holdings: bool, sessions: bool, max: Option<u32>| GateArgs {
            relay_holdings: holdings,
            relay_sessions: sessions,
            relay_holdings_max: max,
            ..GateArgs::default()
        };
        assert!(
            with(false, false, Some(2)).listing_cap_without_a_relay(false),
            "a cap with no relay to ask is refused"
        );
        assert!(
            with(true, true, Some(2)).listing_cap_without_a_relay(false),
            "a one-shot flag does not stand in for the relay"
        );
        assert!(
            !with(false, false, Some(2)).listing_cap_without_a_relay(true),
            "with a relay, the cap is every surface's default"
        );
        assert!(
            !with(false, false, None).listing_cap_without_a_relay(false),
            "no cap, nothing to refuse"
        );
    }
}
