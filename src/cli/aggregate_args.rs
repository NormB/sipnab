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

/// Aggregate query flags (`--count-by`, `--rates-by`, `--talkers`, `--timeline`).
///
/// The shared `--top <N>` belongs here, beside the ranked answers it bounds;
/// it is added with its first reader, so the CLI never carries a flag that
/// nothing reads.
///
/// Split out of [`super::Cli`] so clap's generated parser builds this group
/// in its own stack frame, like every other group.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct AggregateArgs {}

impl AggregateArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        Vec::new()
    }
}
