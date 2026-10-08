// SPDX-License-Identifier: MIT OR Apache-2.0

//! Application layer (WS2): the testable seams between the CLI binary and
//! the library — companion-server startup, batch running, and bootstrap
//! planning. `main.rs` should only parse arguments, build a plan, and
//! dispatch into this module.

pub mod batch;
pub mod bootstrap;
#[cfg(all(unix, any(feature = "api", feature = "mcp")))]
pub mod journal_cli;
pub mod relay_poller;
pub mod relay_reconciler;
pub mod run_provenance;
pub mod servers;
#[cfg(feature = "tui")]
pub mod tui_mode;
#[cfg(feature = "vcon")]
pub mod vcon_forward;

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

/// What a caller resolved before its pipeline options are built: the two
/// switches a config file can also set, and the SIP port gate, whose answer
/// depends on the path (see [`pipeline_options`]).
///
/// Named fields rather than three positional arguments, two of them `bool`, so
/// a call site cannot swap `no_rtp` and `hep_parse` without saying so.
#[derive(Debug, Clone, Copy)]
pub struct PipelineDecisions {
    /// `--no-rtp` / `--rtp` / `[capture] no_rtp`, from [`Cli::no_rtp`].
    pub no_rtp: bool,
    /// Whether this path unwraps HEP: [`Cli::hep_parse`] where the packet
    /// still carries its wrapper, `false` where the loop already unwrapped it.
    pub hep_parse: bool,
    /// The SIP port gate: the run's `--portrange` where a file is read, `None`
    /// on the TUI's live capture, whose BPF filter already applied it.
    pub sip_portrange: Option<(u16, u16)>,
}

/// The pipeline options a run classifies packets with, from its command line
/// and the decisions its caller resolved.
///
/// The one place the run's flags become [`crate::pipeline::PipelineOptions`]:
/// the headless packet loop, the TUI, and the servers' capture-file readers
/// all build theirs here, so a flag added to one reaches the others.
#[must_use]
pub fn pipeline_options(cli: &Cli, decided: PipelineDecisions) -> crate::pipeline::PipelineOptions {
    crate::pipeline::PipelineOptions {
        no_dialog: cli.dialog_args.no_dialog,
        no_rtp: decided.no_rtp,
        sip_portrange: decided.sip_portrange,
        rtpproxy_control: cli.rtp_args.rtpproxy_control,
        quiet_bad_parse: cli.capture_args.quiet_bad_parse,
        hep_parse: decided.hep_parse,
    }
}

/// The pipeline options the REST and MCP servers read capture files with.
///
/// A file opened through a server is read with this run's `--hep-parse`,
/// `--no-rtp`, `--no-dialog`, `--rtpproxy-control` and `--quiet-bad-parse`.
/// It reads SIP on every port, not only `--portrange`: the TUI's own file open
/// does the same, and `open_capture` always did, so an agent opening a capture
/// whose SIP rides another port still sees its calls.
#[must_use]
pub fn server_pipeline_options(cli: &Cli, config: &Config) -> crate::pipeline::PipelineOptions {
    pipeline_options(
        cli,
        PipelineDecisions {
            no_rtp: cli.no_rtp(config),
            hep_parse: cli.hep_parse(config),
            sip_portrange: None,
        },
    )
}

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
    let reverse = cli.reverse_dns(config);
    let resolve = cli.resolve_names(config);

    let resolver = Arc::new(NameResolver::with_limits(
        reverse,
        cli.dns_cache_entries(config),
    ));
    // System hosts table (offline, cheap).
    let _ = resolver.load_hosts_file(std::path::Path::new("/etc/hosts"));
    load_manual_names(&resolver, &cli.name_args.names, cfg);

    let mode = if reverse {
        NameMode::Dns
    } else if resolve {
        NameMode::Names
    } else {
        NameMode::Off
    };
    (resolver, mode)
}

/// Load the manual name layer: the operator's `--names` files, the config's
/// `hosts_file`, then its inline `[names.manual]` table.
///
/// # Side effects
///
/// Reads each file; a `--names` file that fails to load is warned about, a
/// `hosts_file` that fails is skipped silently.
fn load_manual_names(
    resolver: &crate::names::NameResolver,
    names_files: &[String],
    cfg: &crate::config::NamesConfig,
) {
    // Operator-provided mapping files (manual layer, highest priority).
    for f in names_files {
        if let Err(e) = resolver.load_manual_file(std::path::Path::new(f)) {
            tracing::warn!("could not load names file {f}: {e}");
        }
    }
    if let Some(hf) = &cfg.hosts_file {
        let _ = resolver.load_manual_file(std::path::Path::new(hf));
    }
    // Inline [names.manual] table from the config (highest-priority manual layer).
    if let Some(manual) = &cfg.manual {
        apply_manual_table(resolver, manual);
    }
}

/// Apply an inline `[names.manual]` table, warning about and skipping an
/// entry whose key is not an IP address or whose name is not valid.
fn apply_manual_table(
    resolver: &crate::names::NameResolver,
    manual: &std::collections::BTreeMap<String, String>,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::NameMode;
    use std::net::{IpAddr, Ipv4Addr};

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// A headless CLI with no flags.
    fn cli() -> Cli {
        Cli::parse_from_args(["sipnab", "-N"])
    }

    /// Every run option a classifier reads comes from the command line or the
    /// caller's decisions, field by field, so none is left at its default.
    #[test]
    fn pipeline_options_carry_every_run_option() -> Result<(), TestError> {
        let cli = Cli::parse_from_args([
            "sipnab",
            "-N",
            "--no-dialog",
            "--quiet-bad-parse",
            "--rtpproxy-control",
            "192.0.2.40:7722",
        ]);
        let opts = pipeline_options(
            &cli,
            PipelineDecisions {
                no_rtp: true,
                hep_parse: true,
                sip_portrange: Some((5070, 5080)),
            },
        );
        assert!(opts.no_dialog, "--no-dialog");
        assert!(opts.quiet_bad_parse, "--quiet-bad-parse");
        assert_eq!(opts.rtpproxy_control, Some("192.0.2.40:7722".parse()?));
        assert!(opts.no_rtp, "the caller's no_rtp");
        assert!(opts.hep_parse, "the caller's hep_parse");
        assert_eq!(opts.sip_portrange, Some((5070, 5080)));

        let plain = pipeline_options(
            &cli_from(&[]),
            PipelineDecisions {
                no_rtp: false,
                hep_parse: false,
                sip_portrange: None,
            },
        );
        assert!(!plain.no_dialog && !plain.quiet_bad_parse && !plain.no_rtp);
        assert!(!plain.hep_parse);
        assert_eq!((plain.rtpproxy_control, plain.sip_portrange), (None, None));
        Ok(())
    }

    /// The servers read a FILE with the run's options: `-E`, `--no-rtp`,
    /// `--no-dialog`, and the `[capture]` keys a config file sets. Not the
    /// port range: a file opened through a server reads SIP on every port, as
    /// the TUI's own file open does and as `open_capture` always has (Norm,
    /// 2026-10-07: keep reading every port).
    #[test]
    fn server_pipeline_options_read_a_file_with_the_runs_options_on_every_port() {
        let flagged = server_pipeline_options(
            &cli_from(&["-E", "--no-rtp", "--no-dialog", "--portrange", "5070-5080"]),
            &Config::default(),
        );
        assert!(flagged.hep_parse, "-E reaches the servers");
        assert!(flagged.no_rtp, "--no-rtp reaches the servers");
        assert!(flagged.no_dialog, "--no-dialog reaches the servers");
        assert_eq!(
            flagged.sip_portrange, None,
            "a file opened through a server reads every port"
        );

        let mut keyed = Config::default();
        keyed.capture.hep_parse = Some(true);
        keyed.capture.no_rtp = Some(true);
        let from_config = server_pipeline_options(&cli_from(&[]), &keyed);
        assert!(
            from_config.hep_parse,
            "[capture] hep_parse reaches the servers"
        );
        assert!(from_config.no_rtp, "[capture] no_rtp reaches the servers");
    }

    /// A headless CLI with `args` after `-N`.
    fn cli_from(args: &[&str]) -> Cli {
        let mut argv = vec!["sipnab", "-N"];
        argv.extend_from_slice(args);
        Cli::parse_from_args(argv)
    }

    /// An inline `[names.manual]` entry with a valid name is applied; one
    /// whose name would corrupt the hosts format is skipped.
    #[test]
    fn the_manual_table_applies_valid_names_only() {
        let mut config = Config::default();
        config.names.manual = Some(
            [
                ("192.0.2.8".to_string(), "alpha".to_string()),
                ("192.0.2.9".to_string(), "bad\nname".to_string()),
            ]
            .into_iter()
            .collect(),
        );
        let (resolver, _) = build_resolver(&cli(), &config);
        let ip = |last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last));
        assert_eq!(
            resolver.name(ip(8), NameMode::Names).as_deref(),
            Some("alpha")
        );
        assert_eq!(resolver.name(ip(9), NameMode::Names), None);
    }

    /// `[names] hosts_file` reaches the manual layer.
    #[test]
    fn the_config_hosts_file_is_loaded() -> Result<(), TestError> {
        let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e:?}"))?;
        let hosts = dir.path().join("hosts");
        std::fs::write(&hosts, "192.0.2.10 bravo\n").map_err(|e| format!("write hosts: {e:?}"))?;
        let mut config = Config::default();
        config.names.hosts_file = Some(hosts.display().to_string());
        let (resolver, _) = build_resolver(&cli(), &config);
        assert_eq!(
            resolver
                .name(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), NameMode::Names)
                .as_deref(),
            Some("bravo")
        );
        Ok(())
    }
}
