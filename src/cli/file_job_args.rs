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
pub struct FileJobArgs {}

impl FileJobArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        Vec::new()
    }
}
