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
pub struct CallQueryArgs {
    /// Print every leg of one call as a tree across B2BUA, SBC and PBX hops:
    /// the legs sipnab matched to it by an identifier (`X-Call-ID`,
    /// `Session-ID`, SDP origin, P-Charging-Vector, a Via branch), each leg's
    /// own matches, and the legs a timing guess suggests, which the walk does
    /// not follow.
    ///
    /// The Call-ID must match exactly, and one the run did not track exits
    /// with status 1. With `--json`, one JSON object on the last line of
    /// stdout, the shape `GET /v1/dialogs/{call_id}/tree` returns. Makes the
    /// run headless, as `--call-report` does.
    #[arg(help_heading = "Queries", long, value_name = "CALL-ID")]
    pub call_tree: Option<String>,

    /// Print the other legs of one call and the strategy that matched each:
    /// an identifier the legs share, or a timing guess, with the gap
    /// between the two calls for a guess.
    ///
    /// The Call-ID must match exactly, and one the run did not track exits
    /// with status 1; a call with no other leg prints none. With `--json`,
    /// one JSON object on the last line of stdout, the shape
    /// `GET /v1/dialogs/{call_id}/correlated` returns. Makes the run
    /// headless, as `--call-report` does.
    #[arg(help_heading = "Queries", long, value_name = "CALL-ID")]
    pub correlate: Option<String>,

    /// Put two calls side by side: state, final response code, message
    /// count and methods for each, the fields that differ marked, and each
    /// call's diagnosis hints.
    ///
    /// Takes two Call-IDs, each matched exactly, and one the run did not
    /// track exits with status 1. With `--json`, one JSON object on the last
    /// line of stdout, the shape `GET /v1/dialogs/compare` returns. Makes
    /// the run headless, as `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        num_args = 2,
        value_names = ["CALL-ID-A", "CALL-ID-B"],
    )]
    pub compare_dialogs: Option<Vec<String>>,
}

impl CallQueryArgs {
    /// The one-shot declarations of this group's flags, active or not.
    ///
    /// Every flag in this struct that answers a query and exits declares
    /// itself here, once. See [`OneShot`] for what each field decides.
    #[must_use]
    pub fn one_shots(&self) -> Vec<OneShot> {
        vec![
            OneShot {
                name: "--call-tree",
                active: self.call_tree.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--correlate",
                active: self.correlate.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--compare-dialogs",
                active: self.compare_dialogs.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}
