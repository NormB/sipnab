// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Batch B3's file jobs: see `docs/design/par5-cli-queries.md` for the flags
//! this file owns. A file job reads a set of files rather than this run's
//! stores, so it runs from `run_startup_commands` and exits before a capture
//! opens.

use crate::cli::Cli;

/// Run the file job this command line asked for, if any.
///
/// # Returns
///
/// The process exit code when a job ran; `None` when none was asked for.
pub(super) fn startup(cli: &Cli) -> Option<i32> {
    vcon_validate(cli)
        .or_else(|| compare_captures(cli))
        .or_else(|| find_in_files(cli))
}

/// `--find-in-files`: which of the files hold dialogs the run's filter
/// selects, the sweep the MCP `find_in_captures` tool runs. The filter is
/// the one a run of the same command line compiles, aliases and time window
/// included, so the job reads the config; each file's scratch stores hold
/// what an MCP server started by it would hold (`--mcp-max-rows`).
fn find_in_files(cli: &Cli) -> Option<i32> {
    use crate::capture::sweep::{StoppedBecause, SweepControl, SweepInput, sweep_files};
    use crate::output::query::find_files::{candidates, render};

    let paths = &cli.file_job_args.find_in_files;
    if paths.is_empty() {
        return None;
    }
    let loaded = match crate::app::bootstrap::load_config(cli) {
        Ok(loaded) => loaded,
        Err(e) => {
            stderr_line!("{}", e.message);
            return Some(e.exit_code);
        }
    };
    let filter = match crate::app::bootstrap::build_filter_expr(cli, &loaded.config) {
        Ok(Some(filter)) => filter,
        Ok(None) => {
            stderr_line!(
                "--find-in-files needs something to find: give --filter, or a diagnostic \
                 alias such as --problems, to say which dialogs to look for"
            );
            return Some(USAGE);
        }
        Err(e) => {
            stderr_line!("{}", e.message);
            return Some(e.exit_code);
        }
    };
    let files = match candidates(paths) {
        Ok(files) => files,
        Err(why) => {
            stderr_line!("--find-in-files: {why}");
            return Some(FAILED);
        }
    };
    // The command line's only stop is the process's: a SIGTERM or Ctrl-C ends
    // the sweep inside the file it is reading, and the answer says so.
    let stop = || crate::signals::shutdown_requested().then_some(StoppedBecause::Shutdown);
    let answer = sweep_files(
        &SweepInput {
            candidates: &files,
            filter: &filter,
            row_cap: cli.mcp_row_cap(&loaded.config),
            options: &crate::app::server_pipeline_options(cli, &loaded.config),
            max_files: files.len(),
        },
        &SweepControl {
            between_files: &stop,
            inside_file: &stop,
            examined: &|_| {},
        },
    );
    let written = super::write_answer(cli, "--find-in-files", &answer, |format| {
        render(&answer, format)
    });
    Some(match (written, answer.complete) {
        (true, true) => SUCCESS,
        _ => FAILED,
    })
}

/// The exit code of a usage error: the same file named twice.
const USAGE: i32 = 2;

/// `--compare-captures`: two capture files diffed by dimension, the answer
/// `GET /v1/captures/compare` returns. The files are read with the pipeline
/// options a run started by this command line would use, which need the
/// config, so the job reads it here.
fn compare_captures(cli: &Cli) -> Option<i32> {
    use crate::capture::compare::{CaptureRef, CompareError, resolve_dimensions};
    use crate::output::query::capture_compare::{Reporter, compare_files, render, view};

    let [a, b] = cli.file_job_args.compare_captures.as_deref()? else {
        return None;
    };
    let loaded = match crate::app::bootstrap::load_config(cli) {
        Ok(loaded) => loaded,
        Err(e) => {
            stderr_line!("{}", e.message);
            return Some(e.exit_code);
        }
    };
    let options = crate::app::server_pipeline_options(cli, &loaded.config);
    let requested = &cli.file_job_args.compare_dimensions;
    let top = cli
        .aggregate_args
        .top
        .map_or(crate::output::query::DEFAULT_ROWS, |n| {
            usize::try_from(n).unwrap_or(usize::MAX)
        });
    let (name_a, name_b) = (a.display().to_string(), b.display().to_string());
    // The dimensions were held to the vocabulary when they were parsed; the
    // same rule runs here to resolve the default and drop repeats, and any
    // refusal takes the comparison's own path.
    let compared = resolve_dimensions(Some(requested.as_slice())).and_then(|dimensions| {
        compare_files(
            CaptureRef {
                path: a,
                name: &name_a,
            },
            CaptureRef {
                path: b,
                name: &name_b,
            },
            &dimensions,
            &options,
            top,
        )
    });
    let answer = match compared {
        Ok(comparison) => view(comparison, Reporter::CommandLine),
        Err(e) => {
            stderr_line!("--compare-captures: {e}");
            return Some(match e {
                CompareError::SameFile { .. } | CompareError::UnknownDimension { .. } => USAGE,
                CompareError::Unreadable { .. } => FAILED,
            });
        }
    };
    let written = super::write_answer(cli, "--compare-captures", &answer, |format| {
        render(&answer, format)
    });
    Some(if written { SUCCESS } else { FAILED })
}

/// The exit code of a job that answered: a valid container, a comparison.
const SUCCESS: i32 = 0;

/// The exit code of an input that does not conform (an invalid container):
/// the tool worked, the input did not, the code the lint gate uses.
const NON_CONFORMANT: i32 = 3;

/// The exit code of a job that could not answer: a file it could not read
/// or check, a capture that yielded nothing, an answer stdout refused.
const FAILED: i32 = 1;

/// `--vcon-validate`: one container file checked against the vendored
/// schema, the answer `POST /v1/vcon/validate` returns.
fn vcon_validate(cli: &Cli) -> Option<i32> {
    let path = cli.file_job_args.vcon_validate.as_deref()?;
    #[cfg(feature = "vcon")]
    {
        use crate::output::query::vcon_validate::{render, validate_bytes};
        // A file that cannot be read and a document that cannot be validated
        // fail the job alike, each with its reason.
        let checked = std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| validate_bytes(&bytes).map_err(|why| why.to_string()));
        let answer = match checked {
            Ok(answer) => answer,
            Err(why) => {
                stderr_line!("--vcon-validate {}: {why}", path.display());
                return Some(FAILED);
            }
        };
        let shown = path.display().to_string();
        let written = super::write_answer(cli, "--vcon-validate", &answer, |format| {
            render(&shown, &answer, format)
        });
        Some(match (written, answer.errors.is_empty()) {
            (false, _) => FAILED,
            (true, true) => SUCCESS,
            (true, false) => NON_CONFORMANT,
        })
    }
    #[cfg(not(feature = "vcon"))]
    {
        let _ = (path, SUCCESS, NON_CONFORMANT, FAILED);
        Some(crate::app::bootstrap::report_uncompiled(
            &mut std::io::stderr().lock(),
            "--vcon-validate requires the 'vcon' feature (not compiled in)",
        ))
    }
}
