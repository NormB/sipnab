// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bootstrap planning must be a pure, unit-testable Cli+Config → RunPlan
//! mapping (WS2c): given these arguments and this config, the plan is X —
//! no process exits buried in main(), no CLI-only coverage.
#![cfg(feature = "native")]

use sipnab::app::bootstrap::{self, RunMode};
use sipnab::capture::CaptureSource;
use sipnab::cli::Cli;
use sipnab::config::Config;

/// Parses `args` as if passed on a `sipnab` command line (the binary name is
/// prepended automatically).
///
/// # Arguments
/// * `args` — flags and positionals, without the leading program name.
///
/// # Returns
/// The parsed `Cli`; panics via clap on invalid input.
fn cli(args: &[&str]) -> Cli {
    let mut full = vec!["sipnab"];
    full.extend_from_slice(args);
    Cli::parse_from_args(full)
}

/// Source selection precedence: `-I file` beats `-d device` beats the
/// config-file device; with none set the plan defers to auto-detection.
#[test]
fn source_selection_precedence() {
    let mut config = Config::default();
    config.capture.device = Some("cfg0".into());

    let p = bootstrap::plan(&cli(&["-I", "x.pcap", "-d", "eth9"]), &config).expect("plan");
    assert!(
        matches!(p.source, Some(CaptureSource::File { .. })),
        "input file must win"
    );

    let p = bootstrap::plan(&cli(&["-d", "eth9"]), &config).expect("plan");
    match p.source {
        Some(CaptureSource::Live { ref device }) => assert_eq!(device, "eth9"),
        _ => panic!("CLI device must beat config device"),
    }

    let p = bootstrap::plan(&cli(&[]), &config).expect("plan");
    match p.source {
        Some(CaptureSource::Live { ref device }) => assert_eq!(device, "cfg0"),
        _ => panic!("config device must be used when CLI has none"),
    }

    let p = bootstrap::plan(&cli(&[]), &Config::default()).expect("plan");
    assert!(
        p.source.is_none(),
        "no source anywhere ⇒ defer to auto-detect at launch"
    );
}

/// Portrange resolution: CLI wins, then config, then the default; an
/// invalid range is a plan error with the argument-error exit code (2).
#[test]
fn portrange_resolution_and_error() {
    let mut config = Config::default();
    config.capture.portrange = Some("6000-6001".into());

    let p = bootstrap::plan(&cli(&["--portrange", "7000-7010", "-N"]), &config).expect("plan");
    assert_eq!(p.portrange, (7000, 7010));

    // Explicitly passing the DEFAULT range must still beat the config —
    // clap can't distinguish "defaulted" from "explicitly set to the
    // default" with a String field, so the flag is an Option now.
    let p = bootstrap::plan(&cli(&["--portrange", "5060-5061", "-N"]), &config).expect("plan");
    assert_eq!(
        p.portrange,
        (5060, 5061),
        "an explicit --portrange equal to the default must override config"
    );

    let p = bootstrap::plan(&cli(&["-N"]), &config).expect("plan");
    assert_eq!(p.portrange, (6000, 6001), "config fallback");

    let p = bootstrap::plan(&cli(&["-N"]), &Config::default()).expect("plan");
    assert_eq!(p.portrange, (5060, 5061), "built-in default");

    let err = match bootstrap::plan(&cli(&["--portrange", "9-1", "-N"]), &Config::default()) {
        Err(e) => e,
        Ok(_) => panic!("inverted range must fail"),
    };
    assert_eq!(err.exit_code, 2);
    assert!(err.message.contains("--portrange"), "got: {}", err.message);
}

/// The BPF filter is auto-generated from the portrange for live captures
/// only, and never overrides an explicit filter.
#[test]
fn bpf_autogeneration_rules() {
    let p = bootstrap::plan(&cli(&["-d", "eth0"]), &Config::default()).expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some("portrange 5060-5061"),
        "live capture with no explicit filter gets the portrange BPF"
    );

    let p = bootstrap::plan(
        &cli(&["-d", "eth0", "--portrange", "5080-5080"]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some("port 5080"),
        "degenerate range uses the single-port form"
    );

    // Positional trailing args are the explicit BPF filter (tcpdump-style).
    let p = bootstrap::plan(&cli(&["-d", "eth0", "udp"]), &Config::default()).expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some("udp"),
        "an explicit filter is never overridden"
    );

    let p = bootstrap::plan(&cli(&["-I", "x.pcap"]), &Config::default()).expect("plan");
    assert!(
        p.capture_config.bpf_filter.is_none(),
        "offline input gets no auto BPF"
    );
}

/// Mode precedence: `--cores N` with an offline input takes the multi-core
/// file path even when the TUI would otherwise run; `--no-tui` forces batch.
#[test]
fn run_mode_precedence() {
    let p =
        bootstrap::plan(&cli(&["--cores", "4", "-I", "x.pcap"]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::CoresFile));

    let p = bootstrap::plan(&cli(&["-I", "x.pcap", "-N"]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));

    #[cfg(feature = "tui")]
    {
        let p = bootstrap::plan(&cli(&["-I", "x.pcap"]), &Config::default()).expect("plan");
        assert!(matches!(p.mode, RunMode::Tui), "default is the TUI");
    }

    // --cores 1 is the ordinary single-threaded path, not CoresFile.
    let p = bootstrap::plan(
        &cli(&["--cores", "1", "-I", "x.pcap", "-N"]),
        &Config::default(),
    )
    .expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));
}

/// MCP forces batch mode (it owns stdio, so the TUI must not start).
#[cfg(feature = "mcp")]
#[test]
fn mcp_forces_batch_mode() {
    let p = bootstrap::plan(&cli(&["--mcp", "-I", "x.pcap"]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));
}

/// Autostop and split parsing feed the capture policy; errors are exit-2
/// plan errors carrying the flag name.
#[test]
fn policy_autostop_and_split() {
    let p = bootstrap::plan(
        &cli(&["-N", "--autostop", "duration:30", "-I", "x.pcap"]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.policy.autostop_duration,
        Some(std::time::Duration::from_secs(30))
    );
    assert_eq!(p.policy.autostop_filesize_mb, None);

    let err = match bootstrap::plan(
        &cli(&["-N", "--autostop", "bogus:1", "-I", "x.pcap"]),
        &Config::default(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("unknown autostop key must fail"),
    };
    assert_eq!(err.exit_code, 2);
    assert!(err.message.contains("--autostop"), "got: {}", err.message);
}
