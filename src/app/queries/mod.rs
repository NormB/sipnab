// SPDX-License-Identifier: MIT OR Apache-2.0

//! The one-shot query dispatcher: where every CLI query flag is rendered.
//!
//! A CLI query flag is a view of a core function that REST and MCP already
//! call. The rule, stated in `docs/design/par5-cli-queries.md`, is one core
//! function and three views of it: the REST route and the MCP tool serialize
//! its answer, and the CLI prints the same answer as a table, as Markdown under
//! `--markdown`, or under `--json` as one JSON object on the last line of
//! stdout with exactly the REST JSON shape.
//!
//! Two entry points, each called from exactly one place:
//!
//! - [`render`], the last link of the end-of-run report chain in
//!   `app::batch::generate_reports`, for every query answered from the final
//!   stores of this run. That chain runs on every headless path: `-I` files,
//!   live `-d` capture and `--hep-listen` through `BatchRunner::run_loop`, and
//!   `--cores` through `report_parallel_run`.
//! - [`startup`], from `app::bootstrap::run_startup_commands`, for the file
//!   jobs that read a set of files rather than this run's stores and exit
//!   before a capture opens.
//!
//! Each batch of query flags owns one file here (`b1.rs` to `b4.rs`) and adds
//! its flags' arms there, so parallel work never edits the same lines.

use serde::Serialize;

use crate::cli::Cli;
use crate::config::Config;
use crate::output::ReportFormat;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;
use crate::sip::dsl::{AliasThresholds, DialogSelection, FilterExpr};

mod b1;
mod b2;
mod b3;
mod b4;

/// Everything a query answered from the final stores renders from.
pub struct QueryContext<'a> {
    /// The parsed command line: which query, and in which format.
    pub cli: &'a Cli,
    /// The dialogs this run read.
    pub dialogs: &'a DialogStore,
    /// The RTP streams this run read.
    pub streams: &'a StreamStore,
    /// The one compiled filter: `--filter`, the diagnostic alias flags and the
    /// `--since`/`--until` window, ANDed. `None` selects every dialog.
    pub filter: Option<&'a FilterExpr>,
    /// The thresholds a diagnostic alias expands with, resolved from the
    /// command line and the config the way `--filter <alias>` resolves them.
    pub alias: AliasThresholds,
}

impl<'a> QueryContext<'a> {
    /// Build the context from the run's command line, config, stores and
    /// compiled filter.
    #[must_use]
    pub fn new(
        cli: &'a Cli,
        config: &Config,
        dialogs: &'a DialogStore,
        streams: &'a StreamStore,
        filter: Option<&'a FilterExpr>,
    ) -> Self {
        Self {
            cli,
            dialogs,
            streams,
            filter,
            alias: cli.alias_thresholds(config),
        }
    }

    /// The dialogs the compiled filter admits, with their streams.
    ///
    /// The one selection every query answers over, so `--filter` and the
    /// time window narrow a query exactly as they narrow `--report`.
    #[must_use]
    pub fn selection(&self) -> DialogSelection<'a> {
        crate::sip::dsl::select_dialogs(self.filter, self.dialogs, self.streams)
    }

    /// The `--lint-suppress-file` (or discovered `.sipnab-lint-suppress`)
    /// patterns, by the rule `--lint` reads them with.
    ///
    /// # Errors
    ///
    /// A ready-to-print reason when a named or discovered file cannot be read.
    pub fn lint_suppressions(&self) -> Result<Option<crate::sip::lint::SuppressionFile>, String> {
        super::batch::lint_suppressions(self.cli)
    }

    /// Write one query's answer to stdout in the run's format.
    ///
    /// # Arguments
    ///
    /// * `flag` — the query flag, named in a serialization failure.
    /// * `answer` — the core function's answer, serialized under `--json`.
    /// * `text` — renders the answer as a table in the given format.
    ///
    /// # Returns
    ///
    /// `false` when the answer could not be produced or written, which the
    /// report chain turns into exit 1.
    pub fn answer<T: Serialize>(
        &self,
        flag: &str,
        answer: &T,
        text: impl FnOnce(ReportFormat) -> String,
    ) -> bool {
        match render_answer(
            self.cli.output_args.json,
            table_format(self.cli),
            answer,
            text,
        ) {
            Ok(out) => super::batch::write_stdout(&out),
            Err(e) => {
                tracing::error!("{flag}: the answer did not serialize: {e}");
                false
            }
        }
    }
}

/// The table format a query renders in without `--json`: Markdown under
/// `--markdown`, text otherwise.
#[must_use]
pub fn table_format(cli: &Cli) -> ReportFormat {
    super::batch::table_report_format(cli)
}

/// The text one query writes: under `json`, the answer as one JSON object on
/// its own line; otherwise `text` rendered in `format`.
///
/// # Errors
///
/// The serializer's message when the answer cannot be written as JSON.
pub fn render_answer<T: Serialize>(
    json: bool,
    format: ReportFormat,
    answer: &T,
    text: impl FnOnce(ReportFormat) -> String,
) -> Result<String, String> {
    if json {
        serde_json::to_string(answer)
            .map(|line| format!("{line}\n"))
            .map_err(|e| e.to_string())
    } else {
        Ok(text(format))
    }
}

/// Render every query this command line asked for, from the final stores.
///
/// Each batch's arm runs only if every one before it succeeded, like the rest
/// of the report chain, so the exit status speaks for the first failure.
///
/// # Returns
///
/// `false` when a query that was asked for could not be answered or written.
pub fn render(ctx: &QueryContext<'_>) -> bool {
    #[cfg(test)]
    if ctx
        .cli
        .test_one_shots
        .iter()
        .any(|s| s.active && s.name == TEST_FAILING_QUERY)
    {
        return false;
    }
    b1::render(ctx) && b2::render(ctx) && b4::render(ctx)
}

/// A query a unit test declares to prove the report chain reaches [`render`]
/// and honors its answer: this one always fails to answer.
#[cfg(test)]
pub(crate) const TEST_FAILING_QUERY: &str = "--test-failing-query";

/// Run a file job this command line asked for, before any capture opens.
///
/// # Returns
///
/// The exit code when a file job ran; `None` when none was asked for and the
/// run continues.
pub fn startup(cli: &Cli) -> Option<i32> {
    #[cfg(test)]
    if cli
        .test_one_shots
        .iter()
        .any(|s| s.active && s.name == TEST_FILE_JOB)
    {
        return Some(TEST_FILE_JOB_EXIT);
    }
    b3::startup(cli)
}

/// A file job a unit test declares to prove `run_startup_commands` reaches
/// [`startup`] and exits with its code.
#[cfg(test)]
pub(crate) const TEST_FILE_JOB: &str = "--test-file-job";

/// The exit code [`TEST_FILE_JOB`] runs to: one no real path returns.
#[cfg(test)]
pub(crate) const TEST_FILE_JOB_EXIT: i32 = 77;

/// The output convention every query shares, and the dispatcher's own
/// behavior with no query flag set.
#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    type TestError = Box<dyn std::error::Error>;

    #[derive(Serialize)]
    struct Answer {
        total: u32,
        rows: Vec<&'static str>,
    }

    fn answer() -> Answer {
        Answer {
            total: 2,
            rows: vec!["a", "b"],
        }
    }

    /// Under `--json` the answer is ONE JSON object on its own line, parsed
    /// back to exactly the value serialized: the REST shape, not a wrapper.
    #[test]
    fn json_is_one_line_holding_exactly_the_answer() -> Result<(), TestError> {
        let out = render_answer(true, ReportFormat::Text, &answer(), |_| "table".into())?;
        assert!(out.ends_with('\n'), "terminated: {out:?}");
        assert_eq!(out.trim_end().lines().count(), 1, "one line: {out:?}");
        let back: serde_json::Value = serde_json::from_str(out.trim_end())?;
        assert_eq!(back, serde_json::to_value(answer())?);
        Ok(())
    }

    /// Without `--json` the table renders, in the format it was handed.
    #[test]
    fn without_json_the_table_renders_in_the_given_format() -> Result<(), TestError> {
        let out = render_answer(false, ReportFormat::Markdown, &answer(), |f| {
            format!("{f:?} table\n")
        })?;
        assert_eq!(out, "Markdown table\n");
        Ok(())
    }

    /// With no query flag set, the dispatcher writes nothing and succeeds,
    /// so the report chain it ends is unchanged for every existing run.
    #[test]
    fn no_query_flag_renders_nothing_and_succeeds() -> Result<(), TestError> {
        let cli = Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap"])?;
        let dialogs = DialogStore::new(10, false);
        let streams = StreamStore::new(10);
        let ctx = QueryContext::new(&cli, &Config::default(), &dialogs, &streams, None);
        assert!(render(&ctx));
        assert_eq!(startup(&cli), None);
        Ok(())
    }
}
