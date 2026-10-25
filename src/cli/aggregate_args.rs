// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Aggregate query flags: counts, rates, talkers and the time histogram.
//!
//! Owned by batch B1 of the CLI query family; see
//! `docs/design/par5-cli-queries.md` for what each batch owns. The struct is
//! flattened into [`super::Cli`] already, so adding a flag here edits only
//! this file: the flag is a field below, and its [`OneShot`] declaration is
//! an entry in [`AggregateArgs::one_shots`], which `normalize` and `validate` read.

use super::one_shot::OneShot;
use crate::sip::talkers::TalkerDimension;

/// Aggregate query flags (`--count-by`, `--rates-by`, `--talkers`, `--timeline`).
///
/// The shared `--top <N>` belongs here, beside the ranked answers it bounds;
/// it is added with its first reader, so the CLI never carries a flag that
/// nothing reads.
///
/// Split out of [`super::Cli`] so clap's generated parser builds this group
/// in its own stack frame, like every other group.
#[derive(clap::Args, Debug, Clone, Default)]
#[command(group(
    clap::ArgGroup::new(RANKED)
        .multiple(true)
        .args(["count_by", "rates_by", "talkers", "endpoint_ip", "endpoint_user"])
))]
pub struct AggregateArgs {
    /// Print the call volume over time: how many dialogs opened in each
    /// fixed-width interval, oldest first.
    ///
    /// The width is in seconds, 60 when the flag is given bare
    /// (`--timeline`, or `--timeline=300` for five minutes). Intervals align
    /// to the epoch, not to the first call, so two captures line up, and an
    /// empty interval is printed with a count of zero. Counts the dialogs the
    /// run's filter admits (`--filter`, the diagnostic aliases,
    /// `--since`/`--until`). With `--json`, one JSON object on the last line
    /// of stdout, the shape `GET /v1/timeline` returns. Makes the run
    /// headless, as `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "SECONDS",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = DEFAULT_TIMELINE_SECONDS,
        value_parser = parse_bucket_seconds,
    )]
    pub timeline: Option<u64>,

    /// Count the dialogs by one dimension: how many fall in each value,
    /// largest first, ties broken by value.
    ///
    /// One of `state`, `response_code`, `method`, `from.user`, `to.user`,
    /// `ua`, `src.ip`, `dst.ip`, `rtp.codec`. A dialog with no value counts
    /// under `(none)`. Keeps the first `--top` values (50 by default) and
    /// sums the rest in one line. Counts the dialogs the run's filter
    /// admits. With `--json`, one JSON object on the last line of stdout,
    /// the shape `GET /v1/aggregate` returns. Makes the run headless, as
    /// `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "DIMENSION",
        value_parser = parse_dimension,
    )]
    pub count_by: Option<String>,

    /// Print the carrier metrics of each value of one dimension: ASR, NER,
    /// ACD, post-dial delay (p50, p95), the 10th-percentile MOS and the
    /// retransmit rate.
    ///
    /// Every `--count-by` dimension, plus `to_domain`, `hour` and
    /// `next_hop`. Groups are largest first, cut at `--top`. A figure whose
    /// population is empty prints `-`, and `--json` names why. Counts the
    /// dialogs the run's filter admits. With `--json`, one JSON object on the
    /// last line of stdout, the shape `GET /v1/dialogs/rates` returns. Makes
    /// the run headless, as `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "DIMENSION",
        value_parser = parse_rates_dimension,
    )]
    pub rates_by: Option<String>,

    /// Rank the busiest participants: by the address that sent the messages
    /// (`ip`), the `User-Agent` or `Server` banner (`ua`), or the dialed
    /// number's leading digits (`prefix`).
    ///
    /// Most dialogs first, then most messages. Keeps the first `--top`
    /// talkers (50 by default). Counts the dialogs the run's filter admits.
    /// With `--json`, one JSON object on the last line of stdout, the shape
    /// `GET /v1/talkers` returns. Makes the run headless, as `--call-report`
    /// does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "BY",
        value_parser = parse_talker_dimension,
    )]
    pub talkers: Option<TalkerDimension>,

    /// How many leading digits `--talkers prefix` ranks the dialed number
    /// by (4 when not given). Only `prefix` reads it.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "N",
        requires = "talkers",
        value_parser = parse_prefix_digits,
    )]
    pub prefix_digits: Option<u32>,

    /// How many rows a ranked query keeps (`--count-by`, `--rates-by`,
    /// `--talkers`), or how many recent dialogs an endpoint rollup lists
    /// (`--endpoint-ip`, `--endpoint-user`); the rest are summed or counted.
    /// 50 when not given, the default page REST returns.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "N",
        requires = RANKED,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    pub top: Option<u64>,
}

/// The ranked query flags `--top` cuts, as one clap group, so `--top` alone
/// is refused naming them.
const RANKED: &str = "ranked";

/// Parse a `--talkers` dimension by the rule REST and MCP apply. `prefix`
/// takes its digits from `--prefix-digits`, applied where the query runs.
fn parse_talker_dimension(s: &str) -> Result<TalkerDimension, String> {
    TalkerDimension::parse(s, None)
}

/// Parse `--prefix-digits` by the rule REST applies to `prefix_digits`,
/// which refuses zero.
fn parse_prefix_digits(s: &str) -> Result<u32, String> {
    let n: u32 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a whole number of digits"))?;
    TalkerDimension::parse("prefix", Some(n))?;
    Ok(n)
}

/// Parse a `--rates-by` dimension by the rule REST and MCP apply, refusing
/// any other with the list of real ones.
fn parse_rates_dimension(s: &str) -> Result<String, String> {
    let key = s.trim();
    crate::output::query::rates::check_dimension(key, "--filter")?;
    Ok(key.to_string())
}

/// Parse a `--count-by` dimension by the rule REST applies, refusing any
/// other with the list of real ones.
fn parse_dimension(s: &str) -> Result<String, String> {
    let key = s.trim();
    crate::output::query::aggregate::check_dimension(key, "--filter")?;
    Ok(key.to_string())
}

/// A bare `--timeline`'s width as clap reads it: the text of
/// [`crate::output::query::timeline::DEFAULT_BUCKET_SECONDS`], which a unit
/// test holds equal to it.
const DEFAULT_TIMELINE_SECONDS: &str = "60";

/// Parse a `--timeline` width: a whole number of seconds above zero, refused
/// for zero by the rule REST and MCP apply.
fn parse_bucket_seconds(s: &str) -> Result<u64, String> {
    let n: u64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a whole number of seconds"))?;
    crate::output::query::timeline::bucket_width(Some(n)).map_err(str::to_string)
}

impl AggregateArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        vec![
            OneShot {
                name: "--timeline",
                active: self.timeline.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--count-by",
                active: self.count_by.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--rates-by",
                active: self.rates_by.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--talkers",
                active: self.talkers.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}

/// The flags' own parsing rules.
#[cfg(test)]
mod tests {
    use super::*;

    /// A dimension is checked by the rule REST applies; the refusal lists
    /// the real ones and names `--filter` as the way to narrow.
    #[test]
    fn a_dimension_is_checked_by_the_shared_rule() {
        assert_eq!(parse_dimension(" state "), Ok("state".to_string()));
        assert!(
            parse_dimension("bogus")
                .is_err_and(|e| e.contains("one of: state,") && e.contains("narrow with --filter")),
            "bogus"
        );
    }

    /// `--prefix-digits` refuses zero and text, with REST's reason for zero.
    #[test]
    fn prefix_digits_refuse_zero_and_text() {
        assert_eq!(parse_prefix_digits("5"), Ok(5));
        assert!(
            parse_prefix_digits("0").is_err_and(|e| e.contains("greater than zero")),
            "zero"
        );
        assert!(
            parse_prefix_digits("four").is_err_and(|e| e.contains("whole number")),
            "text"
        );
    }

    /// The bare flag's width is the shared default, not a second number.
    #[test]
    fn the_bare_timeline_width_is_the_shared_default() {
        assert_eq!(
            parse_bucket_seconds(DEFAULT_TIMELINE_SECONDS),
            Ok(crate::output::query::timeline::DEFAULT_BUCKET_SECONDS)
        );
    }

    /// Zero and text are refused, each naming why.
    #[test]
    fn a_zero_or_textual_width_is_refused() {
        assert!(
            parse_bucket_seconds("0").is_err_and(|e| e.contains("greater than zero")),
            "zero"
        );
        assert!(
            parse_bucket_seconds("minute").is_err_and(|e| e.contains("whole number")),
            "text"
        );
        assert_eq!(parse_bucket_seconds("300"), Ok(300));
    }
}
