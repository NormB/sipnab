//! Application layer (WS2): the testable seams between the CLI binary and
//! the library — companion-server startup, batch running, and bootstrap
//! planning. `main.rs` should only parse arguments, build a plan, and
//! dispatch into this module.

pub mod batch;
pub mod bootstrap;
pub mod servers;
#[cfg(feature = "tui")]
pub mod tui_mode;

use std::sync::Arc;

use crate::cli::Cli;
use crate::config::Config;

/// Build a name resolver and the active name mode from CLI flags + config,
/// usable in any mode (TUI or headless). Loads the system hosts table, any
/// operator `--names` mapping files, the configured hosts file, and the inline
/// `[names.manual]` table. The TUI layer's name setup adds its own
/// persistence-file handling on top of this.
pub fn build_resolver(
    cli: &Cli,
    config: &Config,
) -> (Arc<crate::names::NameResolver>, crate::names::NameMode) {
    use crate::names::{NameMode, NameResolver};

    let cfg = &config.names;
    let reverse = cli.reverse_dns || cfg.reverse_dns.unwrap_or(false);
    let resolve = cli.resolve
        || reverse
        || cfg.enabled.unwrap_or(false)
        || !cli.names.is_empty()
        || cfg.hosts_file.is_some()
        || cfg.manual.as_ref().is_some_and(|m| !m.is_empty());

    let resolver = Arc::new(NameResolver::with_reverse_dns(reverse));
    // System hosts table (offline, cheap).
    let _ = resolver.load_hosts_file(std::path::Path::new("/etc/hosts"));
    // Operator-provided mapping files (manual layer, highest priority).
    for f in &cli.names {
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
