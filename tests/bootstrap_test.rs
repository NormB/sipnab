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

/// A real capture, because `plan()` now resolves `-I` before returning.
///
/// It used to accept any string: `-I x.pcap` planned happily against a file
/// that did not exist, and the error surfaced later inside the capture thread.
/// Resolving up front is what lets a directory or a glob become a file list at
/// all, and it means a typo fails before any thread starts.
const FIXTURE: &str = "tests/pcap-samples/sip-rtp-g711.pcap";

/// Source selection precedence: `-I file` beats `-d device` beats the
/// config-file device; with none set the plan defers to auto-detection.
#[test]
fn source_selection_precedence() {
    let mut config = Config::default();
    config.capture.device = Some("cfg0".into());

    let p = bootstrap::plan(&cli(&["-I", FIXTURE, "-d", "eth9"]), &config).expect("plan");
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
///
/// The generated expression is encapsulation-aware — it is compared against
/// `bootstrap::auto_bpf_filter`, whose own tests pin it to exact frame counts
/// through libpcap. Here the question is only which runs get one.
#[test]
fn bpf_autogeneration_rules() {
    let p = bootstrap::plan(&cli(&["-d", "eth0"]), &Config::default()).expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some(bootstrap::auto_bpf_filter(5060, 5061, &[]).as_str()),
        "live capture with no explicit filter gets the auto-generated BPF"
    );
    assert!(
        p.capture_config
            .bpf_filter
            .as_deref()
            .is_some_and(|f| f.starts_with("portrange 5060-5061 or ")),
        "the untagged portrange must still lead the expression"
    );

    let p = bootstrap::plan(
        &cli(&["-d", "eth0", "--portrange", "5080-5080"]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some(bootstrap::auto_bpf_filter(5080, 5080, &[]).as_str()),
        "degenerate range uses the single-port form"
    );

    // Opt-in UDP tunnel coverage reaches the generated filter, and only when
    // asked for: it captures whole ports, so it can never be a default.
    let p = bootstrap::plan(
        &cli(&["-d", "eth0", "--capture-tunnels"]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some(bootstrap::auto_bpf_filter(5060, 5061, bootstrap::TUNNEL_PORTS_DEFAULT).as_str()),
        "--capture-tunnels adds the tunnel ports"
    );

    let p = bootstrap::plan(
        &cli(&["-d", "eth0", "--capture-tunnels=8472"]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some(bootstrap::auto_bpf_filter(5060, 5061, &[8472]).as_str()),
        "a custom tunnel port list is honoured verbatim"
    );

    // Positional trailing args are the explicit BPF filter (tcpdump-style).
    let p = bootstrap::plan(&cli(&["-d", "eth0", "udp"]), &Config::default()).expect("plan");
    assert_eq!(
        p.capture_config.bpf_filter.as_deref(),
        Some("udp"),
        "an explicit filter is never overridden"
    );

    let p = bootstrap::plan(&cli(&["-I", FIXTURE]), &Config::default()).expect("plan");
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
        bootstrap::plan(&cli(&["--cores", "4", "-I", FIXTURE]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::CoresFile));

    let p = bootstrap::plan(&cli(&["-I", FIXTURE, "-N"]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));

    #[cfg(feature = "tui")]
    {
        let p = bootstrap::plan(&cli(&["-I", FIXTURE]), &Config::default()).expect("plan");
        assert!(matches!(p.mode, RunMode::Tui), "default is the TUI");
    }

    // --cores 1 is the ordinary single-threaded path, not CoresFile.
    let p = bootstrap::plan(
        &cli(&["--cores", "1", "-I", FIXTURE, "-N"]),
        &Config::default(),
    )
    .expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));
}

/// MCP forces batch mode (it owns stdio, so the TUI must not start).
#[cfg(feature = "mcp")]
#[test]
fn mcp_forces_batch_mode() {
    let p = bootstrap::plan(&cli(&["--mcp", "-I", FIXTURE]), &Config::default()).expect("plan");
    assert!(matches!(p.mode, RunMode::Batch));
}

/// `--call-report` forces batch mode, because it is only ever read there.
///
/// `Cli::validate` waives the `-N` requirement for `--call-report` and its
/// doc comment states the flag "implies non-interactive output" — but the
/// run-mode selector never consulted `call_report`, so the documented
/// invocation started the TUI instead. `cli.call_report` is read in exactly
/// one place (`app::batch`), so in TUI mode the flag was silently ignored:
/// `sipnab -I capture.pcap --call-report <id> --markdown > report.md`
/// wrote 122 bytes of alt-screen and mouse-tracking escapes where the docs
/// promised a Markdown report, and exited 0. Measured against the real
/// binary: 6911 bytes with `-N`, 122 without.
///
/// Six published invocations used the no-`-N` form, so this was the
/// documented spelling, not a corner case.
#[test]
fn call_report_forces_batch_mode() {
    let p = bootstrap::plan(
        &cli(&["-I", FIXTURE, "--call-report", "abc123@host"]),
        &Config::default(),
    )
    .expect("plan");
    assert!(
        matches!(p.mode, RunMode::Batch),
        "--call-report must select batch; it is read nowhere else, so the TUI \
         silently discards it and emits terminal escapes to stdout"
    );

    // Still batch with the format flag the docs pair it with, and still batch
    // when -N is given explicitly (the two must not disagree).
    for args in [
        &["-I", FIXTURE, "--call-report", "abc123@host", "--markdown"][..],
        &["-I", FIXTURE, "--call-report", "abc123@host", "-N"][..],
    ] {
        let p = bootstrap::plan(&cli(args), &Config::default()).expect("plan");
        assert!(matches!(p.mode, RunMode::Batch), "{args:?} must be batch");
    }

    // The TUI is still the default when --call-report is absent, so this does
    // not turn every offline run into batch.
    #[cfg(feature = "tui")]
    {
        let p = bootstrap::plan(&cli(&["-I", FIXTURE]), &Config::default()).expect("plan");
        assert!(matches!(p.mode, RunMode::Tui));
    }
}

/// Autostop and split parsing feed the capture policy; errors are exit-2
/// plan errors carrying the flag name.
#[test]
fn policy_autostop_and_split() {
    let p = bootstrap::plan(
        &cli(&["-N", "--autostop", "duration:30", "-I", FIXTURE]),
        &Config::default(),
    )
    .expect("plan");
    assert_eq!(
        p.policy.autostop_duration,
        Some(std::time::Duration::from_secs(30))
    );
    assert_eq!(p.policy.autostop_filesize_mb, None);

    let err = match bootstrap::plan(
        &cli(&["-N", "--autostop", "bogus:1", "-I", FIXTURE]),
        &Config::default(),
    ) {
        Err(e) => e,
        Ok(_) => panic!("unknown autostop key must fail"),
    };
    assert_eq!(err.exit_code, 2);
    assert!(err.message.contains("--autostop"), "got: {}", err.message);
}
