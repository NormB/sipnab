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
}

/// The exit code a valid container gives.
const VALID: i32 = 0;

/// The exit code an invalid container gives: the tool worked, the input is
/// non-conformant, the code the lint gate uses.
const INVALID: i32 = 3;

/// The exit code a document that could not be validated gives.
const NOT_VALIDATED: i32 = 1;

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
                return Some(NOT_VALIDATED);
            }
        };
        let shown = path.display().to_string();
        let written = super::write_answer(cli, "--vcon-validate", &answer, |format| {
            render(&shown, &answer, format)
        });
        Some(match (written, answer.errors.is_empty()) {
            (false, _) => NOT_VALIDATED,
            (true, true) => VALID,
            (true, false) => INVALID,
        })
    }
    #[cfg(not(feature = "vcon"))]
    {
        let _ = (path, VALID, INVALID, NOT_VALIDATED);
        stderr_line!("--vcon-validate requires the 'vcon' feature (not compiled in)");
        Some(2)
    }
}
