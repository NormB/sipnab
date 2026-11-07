// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet inventory` and `sipnab fleet serve`: the command line of the
//! commands that read the inventory of many sipnab instances and run a fleet
//! center (docs/fleet.md).
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
    about = "Read the inventory of many sipnab instances, or run a fleet center (docs/fleet.md)"
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
    /// Run a fleet center: take heartbeats from fleet members on
    /// `POST /v1/fleet/ingest`, keep the newest per member in a store file,
    /// and serve every member, with the ones gone silent, on
    /// `GET /v1/fleet/members`.
    ///
    /// Runs until SIGINT or SIGTERM, then exits 0. Exits 2 when an argument,
    /// the signing key, the store or the listener is refused.
    Serve {
        /// The address to serve on, `HOST:PORT`. Anything but loopback needs
        /// `--tls-cert` and `--tls-key`.
        #[arg(long, value_name = "ADDR")]
        listen: String,
        /// The store file. Created with mode 0600; refused when other users
        /// can read it.
        #[arg(long, value_name = "FILE")]
        store: PathBuf,
        /// The key member and reader tokens are minted with, readable by
        /// this user only. Mint each member's token with
        /// `sipnab --mint-token --token-scope fleet-report --token-id <member>`.
        #[arg(long, value_name = "FILE")]
        signing_key_file: PathBuf,
        /// Token ids that are no longer accepted, one per line: revoke one
        /// member by its id. Re-read when it changes.
        #[arg(long, value_name = "FILE")]
        revoked_file: Option<PathBuf>,
        /// The PEM certificate chain to serve HTTPS with.
        #[arg(long, value_name = "FILE", requires = "tls_key")]
        tls_cert: Option<String>,
        /// The PEM private key of `--tls-cert`, readable by this user only.
        #[arg(long, value_name = "FILE", requires = "tls_cert")]
        tls_key: Option<String>,
        /// Hours a member is kept after its last heartbeat.
        #[arg(long, value_name = "HOURS", default_value_t = 72,
              value_parser = clap::value_parser!(u64).range(1..=87_600))]
        retention_hours: u64,
        /// A member is silent once more than this many of its heartbeat
        /// intervals pass without one.
        #[arg(long, value_name = "N", default_value_t = 3,
              value_parser = clap::value_parser!(u32).range(1..=1000))]
        silent_after_missed: u32,
        /// A `Host` value to serve beyond loopback names and the bound
        /// address, such as the name members use (repeatable).
        #[arg(long, value_name = "HOST")]
        allowed_host: Vec<String>,
        /// Requests per second one address may make; 0 turns the limit off.
        #[arg(long, value_name = "N", default_value_t = 100)]
        rate_limit_per_peer: u32,
    },
}
