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
    /// Create the key a fleet center encrypts its store under: a new file,
    /// readable by this user only, holding 32 random bytes in base64.
    /// Prints the key's id, which is not secret.
    ///
    /// Back the file up. Without it the center's store cannot be read by
    /// anyone. Exits 2 when the file exists or cannot be written: a key
    /// file is never overwritten.
    Keygen {
        /// The key file to create.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Run a fleet center: take heartbeats from fleet members on
    /// `POST /v1/fleet/ingest`, keep the newest per member in a store file,
    /// and serve every member, with the ones gone silent, on
    /// `GET /v1/fleet/members`.
    ///
    /// Runs until SIGINT or SIGTERM, then exits 0. Exits 2 when an argument,
    /// the signing key, the store or the listener is refused.
    Serve(Box<ServeFlags>),
}

/// The flags of `sipnab fleet serve`.
#[derive(clap::Args, Debug)]
pub struct ServeFlags {
    /// The address to serve on, `HOST:PORT`. Anything but loopback needs
    /// `--tls-cert` and `--tls-key`.
    #[arg(long, value_name = "ADDR")]
    pub listen: String,
    /// The store file. Created with mode 0600; refused when other users
    /// can read it.
    #[arg(long, value_name = "FILE")]
    pub store: PathBuf,
    /// The key the store is encrypted under, readable by this user
    /// only. Required: the center stores nothing in clear. Create one
    /// with `sipnab fleet keygen --out FILE`, and back it up: without
    /// it the store cannot be read.
    #[arg(long, value_name = "FILE")]
    pub store_key_file: Option<PathBuf>,
    /// An earlier `--store-key-file` the store may still be under
    /// (repeatable). The store is rewritten under the current key at
    /// start, so the old key is needed for one start only.
    #[arg(long, value_name = "FILE")]
    pub store_old_key_file: Vec<PathBuf>,
    /// How the store is encrypted: sealed, modular or both. There is
    /// no unencrypted value. This build runs under `sealed` only.
    #[arg(long, value_name = "MODE", value_enum, default_value = "sealed")]
    pub store_encryption: Encryption,
    /// The key member and reader tokens are minted with, readable by
    /// this user only. Mint each member's token with
    /// `sipnab --mint-token --token-scope fleet-report --token-id <member>`.
    #[arg(long, value_name = "FILE")]
    pub signing_key_file: PathBuf,
    /// Token ids that are no longer accepted, one per line: revoke one
    /// member by its id. Re-read when it changes.
    #[arg(long, value_name = "FILE")]
    pub revoked_file: Option<PathBuf>,
    /// The PEM certificate chain to serve HTTPS with.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<String>,
    /// The PEM private key of `--tls-cert`, readable by this user only.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<String>,
    /// Require each member to present a TLS client certificate issued
    /// by a CA in this PEM file, as well as its token. Needs
    /// `--tls-cert`. Alone it means `--tls-client-auth required`.
    #[arg(long, value_name = "FILE")]
    pub tls_client_ca: Option<String>,
    /// When the center asks for a client certificate: off, optional or
    /// required. Default: required with `--tls-client-ca`, else off.
    #[arg(long, value_name = "MODE")]
    pub tls_client_auth: Option<crate::config::ClientAuthMode>,
    /// Hours a member is kept after its last heartbeat.
    #[arg(long, value_name = "HOURS", default_value_t = 72,
          value_parser = clap::value_parser!(u64).range(1..=87_600))]
    pub retention_hours: u64,
    /// A member is silent once more than this many of its heartbeat
    /// intervals pass without one.
    #[arg(long, value_name = "N", default_value_t = 3,
          value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub silent_after_missed: u32,
    /// A `Host` value to serve beyond loopback names and the bound
    /// address, such as the name members use (repeatable).
    #[arg(long, value_name = "HOST")]
    pub allowed_host: Vec<String>,
    /// Requests per second one address may make; 0 turns the limit off.
    #[arg(long, value_name = "N", default_value_t = 100)]
    pub rate_limit_per_peer: u32,
}

/// `--store-encryption`: how the center encrypts what it stores. There is
/// no unencrypted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Encryption {
    /// Each file sealed as one object.
    #[default]
    Sealed,
    /// Parquet modular encryption.
    Modular,
    /// Parquet modular encryption, then the file sealed as one object.
    Both,
}

impl Encryption {
    /// The name the flag takes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Modular => "modular",
            Self::Both => "both",
        }
    }

    /// Why this build cannot run under this value, or `None` when it can.
    #[must_use]
    pub fn unavailable(self) -> Option<String> {
        match self {
            Self::Sealed => None,
            Self::Modular | Self::Both => Some(format!(
                "--store-encryption {}: this build cannot read or write Parquet modular \
                 encryption; `sealed` is the one value it runs under",
                self.as_str()
            )),
        }
    }
}
