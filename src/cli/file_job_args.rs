// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! File job flags: questions about capture files and documents rather than one capture.
//!
//! Owned by batch B3 of the CLI query family; see
//! `docs/design/par5-cli-queries.md` for what each batch owns. The struct is
//! flattened into [`super::Cli`] already, so adding a flag here edits only
//! this file: the flag is a field below, and its [`OneShot`] declaration is
//! an entry in [`FileJobArgs::one_shots`], which `normalize` and `validate` read.

use super::one_shot::OneShot;

/// File job flags (`--find-in-files`, `--compare-captures`, `--vcon-validate`).
///
/// These run from `run_startup_commands`, before a capture opens, because
/// what they read is a set of files rather than the stores of this run.
///
/// Split out of [`super::Cli`] so clap's generated parser builds this group
/// in its own stack frame, like every other group.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct FileJobArgs {
    /// Check a vCon container file against sipnab's vendored schema
    /// (draft-ietf-vcon-vcon-core-04), and print the verdict and every
    /// finding.
    ///
    /// A signed or encrypted container is checked by the unsigned vCon
    /// inside. Exits 0 when the container is valid and 3 when it is invalid,
    /// so a CI step can gate on it; a file that cannot be read, is not JSON,
    /// or is not a container sipnab may validate exits 1. Runs before any
    /// capture opens and needs no `-I`. With `--json`, one JSON object on
    /// the last line of stdout, the shape `POST /v1/vcon/validate` returns.
    /// Needs the `vcon` feature.
    #[arg(help_heading = "Queries", long, value_name = "FILE")]
    pub vcon_validate: Option<std::path::PathBuf>,

    /// Compare two capture files: for each dimension, how many dialogs took
    /// each value in A (the baseline) and in B, and the change, largest
    /// movement first.
    ///
    /// Reads both files, then exits; needs no `-I`. The dimensions are
    /// `--compare-dimensions`, `state` and `response_code` by default, and
    /// `--top` keeps that many values per dimension (50 by default), summing
    /// the rest. The same file twice exits 2; a file that yields no dialogs
    /// exits 1. With `--json`, one JSON object on the last line of stdout,
    /// the shape `GET /v1/captures/compare` returns.
    #[arg(
        help_heading = "Queries",
        long,
        num_args = 2,
        value_names = ["A", "B"],
    )]
    pub compare_captures: Option<Vec<std::path::PathBuf>>,

    /// The dimensions `--compare-captures` diffs, comma-separated: any of
    /// `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`,
    /// `src.ip`, `dst.ip`, `rtp.codec`. `state,response_code` when not given.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "DIMENSIONS",
        value_delimiter = ',',
        requires = "compare_captures",
        value_parser = parse_compare_dimension,
    )]
    pub compare_dimensions: Vec<String>,
}

/// Parse one `--compare-dimensions` value by the rule REST applies to
/// `dimensions`, refusing any other with the vocabulary.
fn parse_compare_dimension(s: &str) -> Result<String, String> {
    crate::capture::compare::resolve_dimensions(Some(&[s.to_string()]))
        .map_err(|e| e.to_string())
        .map(|_| s.trim().to_string())
}

impl FileJobArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        vec![
            OneShot {
                name: "--vcon-validate",
                active: self.vcon_validate.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--compare-captures",
                active: self.compare_captures.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}
