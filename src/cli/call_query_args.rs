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
use crate::sip::endpoint::Selector;

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

    /// Print everything one address did: dialogs by method and state,
    /// messages sent and received, call outcomes, registration, the banners
    /// it sent, the signaling stack, its media, and its most recent dialogs.
    ///
    /// Covers every dialog the address took part in; `--filter` does not
    /// narrow it. `--top` bounds the recent dialogs (50 by default). With
    /// `--json`, one JSON object on the last line of stdout, the shape
    /// `GET /v1/endpoints` returns. Makes the run headless, as
    /// `--call-report` does.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "IP",
        conflicts_with = "endpoint_user",
        value_parser = parse_endpoint_ip,
    )]
    pub endpoint_ip: Option<Selector>,

    /// Print everything one SIP user did, matched against the user part of
    /// each dialog's From and To: the rollup `--endpoint-ip` prints for an
    /// address, without the message counts, which belong to an address.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "USER",
        value_parser = parse_endpoint_user,
    )]
    pub endpoint_user: Option<Selector>,

    /// Write one call's decoded RTP audio to a WAV file: mono for one
    /// stream, stereo for two.
    ///
    /// Asking for it is consent to hold the call's audio payload, which
    /// sipnab otherwise does not keep (as `--retain-audio` asks). The file is
    /// `--export-audio-out`, or the Call-ID made safe for a file name with
    /// `.wav` added, in the current directory; an existing file is never
    /// replaced. A Call-ID with neither a dialog nor a stream in the capture,
    /// or a call with nothing to decode, exits with status 1. Prints the
    /// export summary; with `--json`, one JSON object on the last line of
    /// stdout. Makes the run headless, as `--call-report` does.
    #[arg(help_heading = "Queries", long, value_name = "CALL-ID")]
    pub export_audio: Option<String>,

    /// The file `--export-audio` writes. It must not exist.
    #[arg(
        help_heading = "Queries",
        long,
        value_name = "FILE",
        requires = "export_audio"
    )]
    pub export_audio_out: Option<std::path::PathBuf>,
}

/// Parse `--endpoint-ip` by the rule REST and MCP apply to `ip`.
fn parse_endpoint_ip(s: &str) -> Result<Selector, String> {
    Selector::parse(Some(s), None)
}

/// Parse `--endpoint-user` by the rule REST and MCP apply to `user`.
fn parse_endpoint_user(s: &str) -> Result<Selector, String> {
    Selector::parse(None, Some(s))
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
            OneShot {
                name: "--endpoint-ip",
                active: self.endpoint_ip.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--endpoint-user",
                active: self.endpoint_user.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
            OneShot {
                name: "--export-audio",
                active: self.export_audio.is_some(),
                implies_no_tui: true,
                owns_stdout: true,
            },
        ]
    }
}
