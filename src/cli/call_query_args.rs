// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Single-call query flags: one call, or one pair of calls, at a time.
//!
//! Owned by batch B2 of the CLI query family; see
//! `docs/design/par5-cli-queries.md` for what each batch owns. The struct is
//! flattened into [`super::Cli`] already, so adding a flag here edits only
//! this file: the flag is a field below, and its [`OneShot`] declaration is
//! an entry in [`CallQueryArgs::one_shots`], which `normalize` and `validate` read.

use super::one_shot::OneShot;

/// Single-call query flags (`--call-tree`, `--correlate`, `--compare-dialogs`,
/// `--endpoint-ip`, `--endpoint-user`, `--export-audio`).
///
/// Split out of [`super::Cli`] so clap's generated parser builds this group
/// in its own stack frame, like every other group.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct CallQueryArgs {}

impl CallQueryArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        Vec::new()
    }
}
