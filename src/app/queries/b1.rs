// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B1's query arms: see `docs/design/par5-cli-queries.md` for the
//! flags this file owns. Each flag adds one `if` here that calls its core
//! function and hands the answer to [`QueryContext::answer`].

use super::QueryContext;
use crate::output::query::{DEFAULT_ROWS, aggregate, rates, talkers, timeline};
use crate::sip::talkers::TalkerDimension;

/// Render batch B1's queries that this command line asked for.
///
/// # Returns
///
/// `false` when one was asked for and could not be answered or written;
/// `true` otherwise, including when none was asked for.
pub(super) fn render(ctx: &QueryContext<'_>) -> bool {
    render_timeline(ctx) && render_count_by(ctx) && render_rates_by(ctx) && render_talkers(ctx)
}

/// `--count-by`: the dialogs the run's filter admits, counted by one
/// dimension and cut at `--top`, the answer `GET /v1/aggregate` returns.
fn render_count_by(ctx: &QueryContext<'_>) -> bool {
    let Some(key) = ctx.cli.aggregate_args.count_by.as_deref() else {
        return true;
    };
    let answer = aggregate::aggregate(&ctx.selection(), key, top(ctx), ctx.capture_identity());
    ctx.answer("--count-by", &answer, |format| {
        aggregate::render(&answer, format)
    })
}

/// `--rates-by`: carrier metrics for each value of one dimension over the
/// dialogs the run's filter admits, cut at `--top`, the answer
/// `GET /v1/dialogs/rates` returns with every metric.
fn render_rates_by(ctx: &QueryContext<'_>) -> bool {
    let Some(key) = ctx.cli.aggregate_args.rates_by.as_deref() else {
        return true;
    };
    let wanted = rates::all_metrics();
    let delay = crate::rtp::quality::MosDelay::from_capture(ctx.streams);
    let answer = match rates::rates(
        &ctx.selection(),
        delay,
        key,
        &wanted,
        top(ctx),
        ctx.capture_identity(),
    ) {
        Ok(answer) => answer,
        Err(why) => {
            stderr_line!("--rates-by: {why}");
            return false;
        }
    };
    ctx.answer("--rates-by", &answer, |format| {
        rates::render(&answer, format)
    })
}

/// `--talkers`: the busiest participants among the dialogs the run's filter
/// admits, cut at `--top`, the answer `GET /v1/talkers` returns.
fn render_talkers(ctx: &QueryContext<'_>) -> bool {
    let Some(dimension) = ctx.cli.aggregate_args.talkers else {
        return true;
    };
    // `--prefix-digits` was held to the zero rule when it was parsed; it
    // applies to `prefix` only, as REST's `prefix_digits` does.
    let dimension = match (dimension, ctx.cli.aggregate_args.prefix_digits) {
        (TalkerDimension::Prefix(_), Some(n)) => {
            TalkerDimension::Prefix(usize::try_from(n).unwrap_or(usize::MAX))
        }
        (dimension, _) => dimension,
    };
    let answer = talkers::talkers(
        &ctx.selection(),
        dimension,
        top(ctx),
        ctx.capture_identity(),
    );
    ctx.answer("--talkers", &answer, |format| {
        talkers::render(&answer, format)
    })
}

/// How many rows a ranked query keeps: `--top`, or REST's default page.
fn top(ctx: &QueryContext<'_>) -> usize {
    ctx.cli
        .aggregate_args
        .top
        .map_or(DEFAULT_ROWS, |n| usize::try_from(n).unwrap_or(usize::MAX))
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
            // On stderr, not through tracing: the reason decides the exit
            // code, so it is printed even with logging off.
            stderr_line!("--timeline: {e}");
            return false;
        }
    };
    ctx.answer("--timeline", &answer, |format| {
        timeline::render(&answer, format)
    })
}
