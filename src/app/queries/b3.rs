// SPDX-License-Identifier: MIT OR Apache-2.0

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
    let _ = cli;
    None
}
