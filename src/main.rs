// SPDX-License-Identifier: MIT OR Apache-2.0

//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! The binary is a thin dispatcher (WS2): parse arguments, run the
//! immediate commands, load config, build a `bootstrap::RunPlan`, launch
//! the capture, and hand off to the TUI or batch runner in `sipnab::app`.

// Same production-path panic policy as the library (tests exempt via
// clippy.toml).
#![warn(clippy::unwrap_used, clippy::expect_used)]

// Faster general-purpose allocator: sipnab's offline ingestion does one heap
// allocation per captured packet, so the allocator is on the hot path.
//
// NOT under ThreadSanitizer. mimalloc is C compiled by the `cc` crate, and
// `-Zsanitizer=thread` instruments Rust only, so TSan sees neither its
// alloc/free (no shadow reset when a block is recycled) nor its internal
// cross-thread synchronization (no happens-before edges). Every block mimalloc
// hands from one thread to another therefore reads as a data race. That is not
// a hypothetical: it made `sanitizers.yml` report a race on the file-capture
// path, and the report named `read`/`Vec::append_elements_unreserved` with no
// allocator frame in either stack — so a name-based TSan suppression could not
// have matched it. Removing the uninstrumented allocator is the only fix that
// addresses the cause.
//
// `cfg(sanitize = "thread")` would say this directly but is nightly-only
// (E0658), and the release build is pinned to stable; a Cargo feature would be
// worse still, since `--all-features` runs throughout this repo and would drop
// mimalloc from ordinary test builds. Hence a plain cfg, set by RUSTFLAGS in
// the sanitizer job and declared in build.rs so a typo cannot pass silently.
#[cfg(not(sipnab_tsan))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use sipnab::app::batch::{self, BatchProcessing};
use sipnab::app::bootstrap::{self, RunMode};
use sipnab::cli::Cli;
use sipnab::signals;

/// Binary entry point: run the startup sequence end to end.
///
/// Parses CLI arguments, initializes logging, runs the immediate commands
/// (`--setup-caps`, `--strip-secrets`, `--mint-token`), installs signal and
/// panic handlers, writes the run provenance record when
/// `--run-provenance-file` asked for one, loads and validates configuration,
/// plans the run, launches the capture, and dispatches to the TUI or batch
/// runner.
///
/// # Side effects
///
/// Installs the global mimalloc allocator, writes to stdout/stderr via
/// `tracing`, irreversibly blocks privilege escalation through `exec`,
/// installs SIGINT/SIGTERM/SIGUSR1 handlers and the panic hook,
/// opens capture devices, may drop privileges and chroot, and calls
/// `std::process::exit` for the immediate commands and on fatal errors
/// (exit code 2 on argument-validation failure, and on a provenance record
/// `--run-provenance-file` could not write).
fn main() {
    // 1. Parse CLI arguments and set up logging.
    let cli = Cli::parse_args();
    bootstrap::init_logging(&cli);

    // 2. Immediate commands that run before config load (--setup-caps,
    //    --strip-secrets).
    if let Some(code) = bootstrap::run_startup_commands(&cli) {
        std::process::exit(code);
    }

    // 2b. Give up the ability to gain privileges through exec, for every run
    //     mode and whether or not this process is root.
    //
    //     Here, and not inside `drop_privileges`, because it has no
    //     precondition and that function has two — `--no-priv-drop`, and "not
    //     root, nothing to shed" — both of which return before the flag was
    //     ever reached. `sipnab --setup-caps` runs capture as an ordinary user
    //     holding cap_net_raw, so it took the second of those and hardened
    //     nothing. See `privilege::block_privilege_escalation`.
    //
    //     After step 2 rather than before it: `--setup-caps` runs
    //     `sudo setcap`, and sudo is itself a setuid binary that this flag
    //     would render useless. Before step 3 so that no input has been read
    //     and no event hook can have been spawned. `--cores N -I file`
    //     dispatches without reaching `bootstrap::launch`, which is the other
    //     reason this does not live down there with the drop.
    if let Err(e) = sipnab::privilege::block_privilege_escalation() {
        // Not fatal: a kernel too old for PR_SET_NO_NEW_PRIVS is not a reason
        // to refuse to capture. Loud, though — this is the whole difference
        // between a hardened process and one that only logged that it was.
        tracing::warn!("Could not block privilege escalation through exec: {e}");
    }

    // 3. Signal handlers + argument-combination validation.
    signals::install_handlers();
    if let Err(msg) = cli.validate() {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }
    // 3b. Record how this run was invoked, when --run-provenance-file named a
    //     file. Here and not later: everything above this point either exits
    //     or is a decision about THIS argv, and everything below reads a
    //     config, opens a device or mints a credential. A record written after
    //     any of that would be a record of a run already in progress.
    //
    //     Fatal on failure, deliberately. A best-effort provenance line would
    //     leave its own absence ambiguous -- "not enabled" or "the disk was
    //     full" -- and no reader could tell which. Nothing is lost by stopping
    //     here: no packet has been read.
    if let Err(msg) = sipnab::app::run_provenance::write_record(&cli) {
        tracing::error!("{msg}");
        std::process::exit(2);
    }

    // 4. --mint-token: mint a signed bearer token and exit.
    if let Some(code) = bootstrap::run_mint_token(&cli) {
        std::process::exit(code);
    }

    // 5. Load configuration and apply [limits].
    let loaded = match bootstrap::load_config(&cli) {
        Ok(loaded) => loaded,
        Err(e) => e.exit(),
    };

    // 5b. Crash policy: from here on, a panic restores the terminal,
    //     writes a crash report per [crash], and exits or dumps core.
    sipnab::crash::install_panic_hook(sipnab::crash::CrashPolicy::from_config(
        &loaded.config.crash,
    ));
    if cli.config_args.panic_selftest {
        // gate: panic because --panic-selftest exists to exercise the crash
        // hook installed just above; the panic is the feature.
        panic!("panic-selftest: intentional panic to verify crash handling");
    }

    // 6. --dump-config: print the effective config and exit.
    if cli.config_args.dump_config {
        std::process::exit(bootstrap::dump_config(&loaded));
    }

    // 6b. --uprobe-list: report which TLS libraries this host is running and
    //     exit, without installing anything in the kernel. Answers the question
    //     that decides whether a uprobe capture is worth starting.
    if cli.tls_args.uprobe_list {
        std::process::exit(bootstrap::uprobe_list(&cli));
    }

    // 7. Decide everything up front: source, capture config, portrange,
    //    filters, policy, run mode.
    let plan = match bootstrap::plan(&cli, &loaded.config) {
        Ok(plan) => plan,
        Err(e) => e.exit(),
    };

    // 8. Multi-core offline reconstruction bypasses the capture thread.
    //
    //    It still needs the file set, and the set is already on the plan:
    //    `plan()` ran `input_set::resolve`, so `plan.source` holds the
    //    resolved, timestamp-ordered `Vec<PathBuf>`. Dispatching here — before
    //    `launch` — used to discard it and let `run_cores_file` re-derive the
    //    input from `cli.primary_input()`, i.e. the first `-I` *argument*. For
    //    `-I <directory>`, `-I '<glob>'` or repeated `-I` that argument is not
    //    a file, so the pcap opener was handed a directory and the run reported
    //    nothing while exiting 0.
    if matches!(plan.mode, RunMode::CoresFile) {
        let paths: &[std::path::PathBuf] = match plan.source {
            Some(sipnab::capture::CaptureSource::File { ref paths }) => paths,
            // `CoresFile` is only chosen when `-I` was given, so the source is
            // always `File`. An empty slice makes `run_cores_file` fail loudly
            // rather than silently analyzing nothing if that ever changes.
            _ => &[],
        };
        batch::run_cores_file(
            &cli,
            &loaded.config,
            &plan.capture_config,
            plan.portrange,
            paths,
            plan.filter_expr.as_ref(),
            plan.vcon_filter_expr.as_ref(),
        );
        return;
    }

    // 9. Launch the capture: channel, capture thread, readiness handshake,
    //    chroot, privilege drop, runtime hardening.
    let launched = bootstrap::launch(&cli, &loaded.config, plan.source, &plan.capture_config);

    // 10. Dispatch to the selected mode.
    match plan.mode {
        RunMode::Tui => {
            #[cfg(feature = "tui")]
            sipnab::app::tui_mode::run_tui_mode(
                cli,
                loaded.config,
                plan.capture_config,
                launched,
                plan.policy,
                #[cfg(feature = "metrics")]
                plan.metrics_bind,
            );
        }
        RunMode::Batch => {
            batch::run(
                cli,
                &loaded.config,
                plan.capture_config,
                launched.handle,
                launched.rx,
                BatchProcessing {
                    matcher: plan.matcher,
                    filter_expr: plan.filter_expr,
                    vcon_filter_expr: plan.vcon_filter_expr,
                    output_opts: plan.output_opts,
                    event_exec: plan.event_exec,
                    input_files: plan.input_files,
                    relay: launched.relay,
                    #[cfg(feature = "tls")]
                    keylog_source: launched.keylog_source,
                },
                plan.policy,
                launched.raw_kill_sock,
            );
        }
        // gate: unreachable because step 8 above returns for CoresFile before
        // the capture is launched, so this match never sees it.
        RunMode::CoresFile => unreachable!("handled before launch"),
    }
}
