// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B1's query arms: see `docs/design/par5-cli-queries.md` for the
//! flags this file owns. Each flag adds one `if` here that calls its core
//! function and hands the answer to [`QueryContext::answer`].

use super::QueryContext;
use crate::output::query::timeline;

/// Render batch B1's queries that this command line asked for.
///
/// # Returns
///
/// `false` when one was asked for and could not be answered or written;
/// `true` otherwise, including when none was asked for.
pub(super) fn render(ctx: &QueryContext<'_>) -> bool {
    render_timeline(ctx)
}

/// `--timeline`: the call-volume histogram over the dialogs the run's filter
/// admits, the answer `GET /v1/timeline` returns. `false` when the store
/// refuses the span or the answer cannot be written.
fn render_timeline(ctx: &QueryContext<'_>) -> bool {
    let Some(width) = ctx.cli.aggregate_args.timeline else {
        return true;
    };
    let selection = ctx.selection();
    // A span too wide for the width is the store's refusal, the one REST
    // answers 422: no histogram, the reason on stderr, and a failed run.
    let answer = match timeline::timeline(
        selection.dialogs.iter().map(|(d, _)| *d),
        width,
        ctx.capture_identity(),
    ) {
        Ok(answer) => answer,
        Err(e) => {
            tracing::error!("--timeline: {e}");
            return false;
        }
    };
    ctx.answer("--timeline", &answer, |format| {
        timeline::render(&answer, format)
    })
}
