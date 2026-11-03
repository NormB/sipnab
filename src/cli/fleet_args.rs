// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet inventory`: the command line of the command that reads the
//! inventory of many sipnab instances (docs/fleet.md).
//!
//! A command of its own, not flags of [`super::Cli`], for the reason
//! `sipnab g729` is one: it shares none of a capture run's flags, and
//! `src/main.rs` dispatches it on the first argument before the capture
//! command line is parsed. It opens no capture.

use std::path::PathBuf;

/// `sipnab fleet`: manage many sipnab instances as one fleet.
#[derive(clap::Parser, Debug)]
#[command(
    name = "sipnab fleet",
    about = "Read the inventory of many sipnab instances (docs/fleet.md)"
)]
pub struct FleetCli {
    /// What to do.
    #[command(subcommand)]
    pub command: FleetCommand,
}

/// The `sipnab fleet` commands.
#[derive(clap::Subcommand, Debug)]
pub enum FleetCommand {
    /// Ask every instance in a hosts file for its inventory, and report the
    /// fleet: each instance's build, binary and configuration digests,
    /// privilege and health, the instances that did not answer, and the
    /// findings across them.
    ///
    /// Exits 0 when every instance answered and there is no finding, 1 when
    /// an instance did not answer or there is a finding, and 2 when the
    /// hosts file cannot be used.
    Inventory {
        /// The hosts file: one `[[host]]` table per instance, with `name`,
        /// `url` and `token_file`, and optionally `ca_file`.
        #[arg(long, value_name = "FILE")]
        hosts: PathBuf,
        /// Print the report as JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Seconds to wait for each instance to connect and answer.
        #[arg(long, value_name = "SECS", default_value_t = 10,
              value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout: u64,
    },
}
