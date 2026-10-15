// SPDX-License-Identifier: MIT OR Apache-2.0

//! `sipnab g729 install` and `sipnab g729 status`: the command line of the
//! command that installs the G.729 codebook tables (docs/g729.md).
//!
//! A command of its own, not flags of [`super::Cli`]: it shares none of a
//! capture run's flags, and `src/main.rs` dispatches it on the first argument
//! before the capture command line is parsed. Declared in every `native`
//! build, so a build without the `g729` feature still describes the command
//! it refuses, and the documentation tests can read its flags from clap.

use std::path::PathBuf;

/// `sipnab g729`: the G.729 codebook tables on this host.
#[derive(clap::Parser, Debug)]
#[command(
    name = "sipnab g729",
    about = "Install or inspect the G.729 codebook tables (docs/g729.md)"
)]
pub struct G729Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: G729Command,
    /// The table file, as for a capture run; else `[g729] tables`, else
    /// `g729-tables.bin` beside the user config file.
    #[arg(long = "g729-tables", value_name = "PATH", global = true)]
    pub g729_tables: Option<PathBuf>,
    /// The config file to read `[g729] tables` from, as `-f` for a run.
    #[arg(short = 'f', long = "config", value_name = "FILE", global = true)]
    pub config: Option<String>,
    /// Read no config file.
    #[arg(long = "no-config", global = true)]
    pub no_config: bool,
}

/// What `sipnab g729 install --help` prints above its options. A string, not
/// the variant's doc comment, so the link prints as plain text in the help
/// and rustdoc does not refuse it as a bare URL.
pub const INSTALL_HELP: &str = "Build the G.729 codebook tables from the ITU-T G.729 software \
package and install them.

Downloads the package from itu.int, checks its sha256, builds the table file from it, and \
writes the file to g729-tables.bin in the directory of the user config file \
($XDG_CONFIG_HOME/sipnab, else ~/.config/sipnab), or to the path that --g729-tables or the \
`[g729] tables` config key names.

On a host without internet access, --from PATH reads a copy and opens no connection: the \
package zip, a directory extracted from it, or the g729-tables.bin of another host.

sipnab does not ship these values: the ITU-T publishes them in the reference C code of the \
package, whose notice keeps its authors' rights, so sipnab reads them from your own copy of \
the package. Details: https://github.com/NormB/sipnab/blob/main/crates/g729/PROVENANCE.md";

/// The `sipnab g729` commands.
#[derive(clap::Subcommand, Debug)]
pub enum G729Command {
    /// Build the G.729 codebook tables from the ITU-T G.729 software package
    /// and install them.
    ///
    /// The text `sipnab g729 install --help` prints is [`INSTALL_HELP`].
    #[command(long_about = INSTALL_HELP)]
    Install {
        /// Answer yes to the question before installing, for scripts and
        /// Dockerfiles.
        #[arg(long)]
        yes: bool,
        /// Install from the package zip, a directory extracted from it, or a
        /// table file from another host, without opening a connection.
        #[arg(long, value_name = "PATH")]
        from: Option<PathBuf>,
    },
    /// Say whether the tables are installed, where, and their values hash.
    Status,
}
