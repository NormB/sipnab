// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application layer (WS2): the testable seams between the CLI binary and
//! the library — companion-server startup, batch running, and bootstrap
//! planning. `main.rs` should only parse arguments, build a plan, and
//! dispatch into this module.

pub mod batch;
pub mod bootstrap;
pub mod relay_reconciler;
pub mod run_provenance;
pub mod servers;
#[cfg(feature = "tui")]
pub mod tui_mode;

/// The one append-only audit sink, reachable from every build that can write
/// a record — including the ones that carry no MCP server.
///
/// The implementation lives in `src/mcp/audit.rs` because that is where it
/// was written and where its tests are. It cannot STAY reachable only from
/// there: `pub mod mcp` is `#[cfg(feature = "mcp")]`, while the run
/// provenance record and the TUI action trail are wanted in the DEFAULT build
/// (`native,tui,audio,metrics`), which carries no `mcp` at all. CI compiles
/// `native,tui,audio` and `native,tui,tls,hep,api` for exactly this class of
/// break.
///
/// So one name, one source file, and exactly one compilation of it per build:
/// with `mcp` this re-exports the module the MCP server already holds — the
/// same types, not a copy — and without it the same file is compiled here
/// instead. A mutation to the sink therefore fails every surface's tests in
/// every feature combination, which is the property a second implementation
/// could not have.
#[cfg(feature = "mcp")]
pub use crate::mcp::audit;

/// The one append-only audit sink — see the `mcp` arm above for why this
/// module has two spellings and only ever one compilation.
#[cfg(not(feature = "mcp"))]
#[path = "../mcp/audit.rs"]
pub mod audit;

use std::sync::Arc;

use crate::cli::Cli;
use crate::config::Config;

/// Build a name resolver and the active name mode from CLI flags + config,
/// usable in any mode (TUI or headless). Loads the system hosts table, any
/// operator `--names` mapping files, the configured hosts file, and the inline
/// `[names.manual]` table. The TUI layer's name setup adds its own
/// persistence-file handling on top of this.
///
/// # Arguments
///
/// * `cli` — parsed command-line flags (`--resolve`, `--reverse-dns`,
///   `--names <file>` mappings).
/// * `config` — loaded configuration whose `[names]` section supplies the
///   fallback enable flags, hosts file, and inline manual table.
///
/// # Returns
///
/// The shared resolver plus the active `NameMode`: `Dns` when reverse DNS is
/// requested, `Names` when any manual-name source is configured, `Off`
/// otherwise.
///
/// # Side effects
///
/// Reads `/etc/hosts` and every configured mapping file from disk (failures
/// are logged and skipped, never fatal), and — when reverse DNS is enabled —
/// `NameResolver::with_limits` starts the background reverse-DNS lookup
/// machinery. Invalid `[names.manual]` entries are warned about via
/// `tracing` and ignored.
pub fn build_resolver(
    cli: &Cli,
    config: &Config,
) -> (Arc<crate::names::NameResolver>, crate::names::NameMode) {
    use crate::names::{NameMode, NameResolver};

    let cfg = &config.names;
    let reverse = cli.name_args.reverse_dns || cfg.reverse_dns.unwrap_or(false);
    let resolve = cli.name_args.resolve
        || reverse
        || cfg.enabled.unwrap_or(false)
        || !cli.name_args.names.is_empty()
        || cfg.hosts_file.is_some()
        || cfg.manual.as_ref().is_some_and(|m| !m.is_empty());

    let resolver = Arc::new(NameResolver::with_limits(
        reverse,
        cli.dns_cache_entries(config),
    ));
    // System hosts table (offline, cheap).
    let _ = resolver.load_hosts_file(std::path::Path::new("/etc/hosts"));
    // Operator-provided mapping files (manual layer, highest priority).
    for f in &cli.name_args.names {
        if let Err(e) = resolver.load_manual_file(std::path::Path::new(f)) {
            tracing::warn!("could not load names file {f}: {e}");
        }
    }
    if let Some(hf) = &cfg.hosts_file {
        let _ = resolver.load_manual_file(std::path::Path::new(hf));
    }
    // Inline [names.manual] table from the config (highest-priority manual layer).
    if let Some(manual) = &cfg.manual {
        for (ip_str, name) in manual {
            match ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) if crate::names::is_valid_name(name) => {
                    resolver.set_manual(ip, name.clone());
                }
                Ok(_) => tracing::warn!("ignoring invalid name for {ip_str:?} in [names.manual]"),
                Err(_) => tracing::warn!("ignoring invalid IP key {ip_str:?} in [names.manual]"),
            }
        }
    }

    let mode = if reverse {
        NameMode::Dns
    } else if resolve {
        NameMode::Names
    } else {
        NameMode::Off
    };
    (resolver, mode)
}
