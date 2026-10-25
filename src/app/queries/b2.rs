// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B2's query arms: see `docs/design/par5-cli-queries.md` for the
//! flags this file owns. Each flag adds one `if` here that calls its core
//! function and hands the answer to [`QueryContext::answer`].

use super::{QueryContext, call_not_found};
use crate::output::query::{compare, correlated, tree};

/// Render batch B2's queries that this command line asked for.
///
/// # Returns
///
/// `false` when one was asked for and could not be answered or written;
/// `true` otherwise, including when none was asked for.
pub(super) fn render(ctx: &QueryContext<'_>) -> bool {
    render_call_tree(ctx) && render_correlate(ctx) && render_compare_dialogs(ctx)
}

/// `--compare-dialogs`: two named calls side by side, the answer
/// `GET /v1/dialogs/compare` returns. Both calls are read whatever the run's
/// filter admits; an unknown Call-ID on either side fails the run.
fn render_compare_dialogs(ctx: &QueryContext<'_>) -> bool {
    let Some([a_id, b_id]) = ctx.cli.call_query_args.compare_dialogs.as_deref() else {
        return true;
    };
    let Some(a) = ctx.dialogs.get(a_id) else {
        call_not_found(a_id);
        return false;
    };
    let Some(b) = ctx.dialogs.get(b_id) else {
        call_not_found(b_id);
        return false;
    };
    let answer = compare::comparison(a, b, ctx.capture_identity());
    ctx.answer("--compare-dialogs", &answer, |format| {
        compare::render(&answer, format)
    })
}

/// `--correlate`: the other legs of one named call, the answer
/// `GET /v1/dialogs/{call_id}/correlated` returns. Like `--call-tree`, it
/// reads the named call whatever the run's filter admits; an unknown
/// Call-ID fails the run.
fn render_correlate(ctx: &QueryContext<'_>) -> bool {
    let Some(call_id) = ctx.cli.call_query_args.correlate.as_deref() else {
        return true;
    };
    let Some(answer) =
        correlated::correlated(ctx.dialogs, call_id, ctx.row_cap, ctx.capture_identity())
    else {
        call_not_found(call_id);
        return false;
    };
    ctx.answer("--correlate", &answer, |format| {
        correlated::render(&answer, format)
    })
}

/// `--call-tree`: the legs reachable from one named call, the answer
/// `GET /v1/dialogs/{call_id}/tree` returns. The named call is read whatever
/// the run's filter admits, as `--call-report` reads it; an unknown Call-ID
/// fails the run.
fn render_call_tree(ctx: &QueryContext<'_>) -> bool {
    let Some(call_id) = ctx.cli.call_query_args.call_tree.as_deref() else {
        return true;
    };
    let Some(answer) = tree::call_tree(ctx.dialogs, call_id, ctx.row_cap, ctx.capture_identity())
    else {
        call_not_found(call_id);
        return false;
    };
    ctx.answer("--call-tree", &answer, |format| {
        tree::render(&answer, format)
    })
}
