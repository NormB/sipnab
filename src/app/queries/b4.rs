// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B4's query arms: see `docs/design/par5-cli-queries.md` for the
//! flags this file owns. Each flag adds one `if` here that calls its core
//! function and hands the answer to [`QueryContext::answer`].

use super::{QueryContext, set_gate_exit};
use crate::output::query::expectations;

/// Render batch B4's queries that this command line asked for.
///
/// # Returns
///
/// `false` when one was asked for and could not be answered or written;
/// `true` otherwise, including when none was asked for.
pub(super) fn render(ctx: &QueryContext<'_>) -> bool {
    render_expect(ctx)
}

/// The exit status of a suite sipnab could not judge for a reason in the
/// invocation, as an unreadable suppression file is for `--lint`.
const USAGE: i32 = 2;

/// `--expect`: the capture judged against the suite, the report the MCP
/// `evaluate_expectations` tool returns, and the suite's exit status
/// recorded for the run to end with.
fn render_expect(ctx: &QueryContext<'_>) -> bool {
    let Some(file) = ctx.cli.gate_args.expect.as_ref() else {
        return true;
    };
    let suppressions = match ctx.lint_suppressions() {
        Ok(suppressions) => suppressions,
        Err(why) => {
            stderr_line!("--expect: {why}");
            set_gate_exit(USAGE);
            return true;
        }
    };
    let judged = crate::expect::evaluate(
        &file.suite.rules,
        &crate::expect::Inputs {
            dialogs: ctx.dialogs,
            streams: ctx.streams,
            thresholds: &ctx.alias,
            suppressions: suppressions.as_ref(),
        },
    );
    let report = match judged {
        Ok(report) => report,
        Err(e) => {
            stderr_line!("--expect {}: {e}", file.path.display());
            set_gate_exit(USAGE);
            return true;
        }
    };
    set_gate_exit(report.exit_code());
    let answer = expectations::ExpectAnswer {
        report,
        capture_identity: ctx.capture_identity(),
    };
    ctx.answer("--expect", &answer, |format| {
        expectations::render(&answer.report, format)
    })
}
