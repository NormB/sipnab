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
/// panic handlers, reads the config file and declares the node name, writes
/// the run provenance record when `--run-provenance-file` asked for one, runs
/// the vCon forwarder when `--vcon-forward` names a spool, validates and
/// applies the configuration,
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
    // 0. The scanner-kill worker process is this binary too, started by a
    //    parent run with `--internal-kill-worker` as its FIRST argument. It is
    //    dispatched before the command line is parsed, so no combination of
    //    ordinary flags can reach it, and it never reaches anything below: it
    //    sets up its own logging and hardening and exits. See
    //    `process_isolation::worker_process`.
    if let Some(code) = sipnab::process_isolation::worker_process::run_if_requested() {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 0b. `sipnab g729 install|status`: the G.729 codebook tables. A command
    //     of its own, dispatched on the first argument before the capture
    //     command line is parsed, because it shares none of its flags and the
    //     trailing capture-filter positional would otherwise read `g729` as a
    //     filter. It opens no capture and exits.
    if std::env::args_os().nth(1).is_some_and(|a| a == "g729") {
        std::process::exit(run_g729_command());
    }

    // 1. Parse CLI arguments and set up logging.
    let cli = Cli::parse_args();
    bootstrap::init_logging(&cli);

    // 1b-4. Everything decided by the command line, and the config file read
    //       but not yet applied.
    run_immediate_steps(&cli);
    let read = run_validation_steps(&cli);

    // 5. Apply the configuration read in step 3a, and [limits].
    let loaded = match read.and_then(|read| bootstrap::apply_config(&cli, read)) {
        Ok(loaded) => loaded,
        Err(e) => e.exit(),
    };

    // 5b-6b. The crash policy, and the commands that need only the config.
    run_config_steps(&cli, &loaded);

    // 7. Decide everything up front: source, capture config, portrange,
    //    filters, policy, run mode.
    let plan = match bootstrap::plan(&cli, &loaded.config) {
        Ok(plan) => plan,
        Err(e) => e.exit(),
    };
    // The capture-source table's size, before any capture can name a source.
    sipnab::capture::packet::set_max_capture_sources(plan.max_capture_sources);
    // `-I` is resolved: from here on nothing waits on the terminal for an
    // archive password.
    bootstrap::end_archive_prompts();

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
        run_cores_file(&cli, &loaded, &plan);
        // Returning from `main` runs no destructor for a static, so the
        // members `-I` extracted are released explicitly on this way out too.
        sipnab::capture::archive::release_run();
        return;
    }

    // 9-10. Launch the capture and hand it to the selected mode.
    launch_and_dispatch(cli, loaded, plan);

    // A run that ends by returning, rather than through
    // `release_run_and_exit`, releases what `-I` extracted here.
    sipnab::capture::archive::release_run();
}

/// Step 0b of [`main`]: `sipnab g729 ...`, with `sipnab g729` as the
/// command's own name in its help and errors.
fn run_g729_command() -> i32 {
    #[cfg(feature = "g729")]
    {
        let args = std::iter::once(std::ffi::OsString::from("sipnab g729"))
            .chain(std::env::args_os().skip(2));
        sipnab::app::g729_install::main(args)
    }
    #[cfg(not(feature = "g729"))]
    {
        use std::io::Write as _;
        // `writeln!`, not `eprintln!`: a closed stderr must not panic.
        let _ = writeln!(std::io::stderr(), "{}", sipnab::rtp::g729_tables::NOT_BUILT);
        1
    }
}

/// Steps 1b to 2b of [`main`]: archive passwords, the immediate commands,
/// and the exec privilege block. Each step either continues or exits the
/// process.
fn run_immediate_steps(cli: &Cli) {
    // 1b. Archive passwords, from every source the operator configured,
    //     before anything below resolves `-I`: the immediate commands in step
    //     2 read inputs too. A source that cannot supply one is an argument
    //     error, the same as a malformed flag.
    if let Err(msg) = bootstrap::install_archive_passwords(cli) {
        tracing::error!("{msg}");
        sipnab::capture::archive::release_run_and_exit(2);
    }

    // 2. Immediate commands that run before config load (--setup-caps,
    //    --strip-secrets).
    if let Some(code) = bootstrap::run_startup_commands(cli) {
        sipnab::capture::archive::release_run_and_exit(code);
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
}

/// Steps 3 to 4 of [`main`]: signal handlers and argument validation, the
/// config file read, the node name, the run provenance record, and the
/// commands that exit (`--mint-token`, `--vcon-forward`, `--vcon-fetch`).
/// Each step either continues or exits the process.
///
/// # Returns
///
/// The config file as read in step 3a, or why it could not be read, for step
/// 5 to apply or refuse. A read that failed stops the run there, after the
/// record is written, as it did when step 5 also read the file.
fn run_validation_steps(cli: &Cli) -> Result<sipnab::config::LoadedConfig, bootstrap::PlanError> {
    // 3. Signal handlers + argument-combination validation.
    signals::install_handlers();
    if let Err(msg) = cli.validate() {
        tracing::error!("{}", msg);
        sipnab::capture::archive::release_run_and_exit(2);
    }
    // 3a. Read the config file, applying nothing in it yet. The one setting
    //     needed before step 5 is the node name, which the record below
    //     carries: declared after the record, it lost to the host name the
    //     record fixed by reading it first, and the record and every vCon of
    //     the run named the host instead of the node.
    let read = bootstrap::read_config(cli);
    bootstrap::declare_node_name(cli, read.as_ref().ok().map(|loaded| &loaded.config));

    // 3b. Record how this run was invoked, when --run-provenance-file named a
    //     file. Here and not later: everything above this point either exits,
    //     is a decision about THIS argv, or read the config file without
    //     applying it, and everything below applies the config, opens a device
    //     or mints a credential. A record written after any of that would be a
    //     record of a run already in progress.
    //
    //     Fatal on failure, deliberately. A best-effort provenance line would
    //     leave its own absence ambiguous -- "not enabled" or "the disk was
    //     full" -- and no reader could tell which. Nothing is lost by stopping
    //     here: no packet has been read.
    if let Err(msg) = sipnab::app::run_provenance::write_record(cli) {
        tracing::error!("{msg}");
        sipnab::capture::archive::release_run_and_exit(2);
    }

    // 4. --mint-token: mint a signed bearer token and exit.
    if let Some(code) = bootstrap::run_mint_token(cli) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 4b. --vcon-forward: deliver a vCon spool to a store, as a process of
    //     its own. It applies the config read in step 3a, for
    //     [vcon_forward], and opens no capture: it reads no packet, and clap refused every capture flag
    //     beside it.
    if let Some(code) = bootstrap::run_vcon_forward(cli, &read) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 4c. --vcon-fetch: read stored vCons back by uuid, as a process of its
    //     own, for the same reasons: it applies the config read in step 3a,
    //     for [vcon_fetch], and opens no capture.
    if let Some(code) = bootstrap::run_vcon_fetch(cli, &read) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 4d. --vcon-spool-status: print the export spool's state and exit. Reads
    //     files only; opens no capture and no connection.
    if let Some(code) = bootstrap::run_vcon_spool_status(cli) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 4e. --vcon-resign: re-sign a signed vCon for an archive and exit. It
    //     applies the config read in step 3a, for [vcon_input], and opens
    //     no capture and no connection.
    if let Some(code) = bootstrap::run_vcon_resign(cli, &read) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 4f. --vcon-audio-fetch: fetch, check and decrypt the audio a vCon
    //     names by url and exit. It applies the config read in step 3a, for
    //     [vcon_input], and opens no capture.
    if let Some(code) = bootstrap::run_vcon_audio_fetch(cli, &read) {
        sipnab::capture::archive::release_run_and_exit(code);
    }
    read
}

/// Steps 5b to 6b of [`main`]: the crash policy, then the commands that need
/// the loaded config and exit (`--panic-selftest`, `--dump-config`,
/// `--journal-show`/`--revert-actions`, `--uprobe-list`).
fn run_config_steps(cli: &Cli, loaded: &sipnab::config::LoadedConfig) {
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

    // 5c. Where this run finds the G.729 codebook tables: --g729-tables,
    //     [g729] tables, or the default file. Nothing is read until a G.729
    //     stream is decoded.
    sipnab::rtp::g729_tables::configure(
        cli.g729_table_location(
            &loaded.config,
            sipnab::rtp::g729_tables::default_table_file_here(),
        ),
        loaded.config.g729.auto_install.unwrap_or(false),
    );

    // 6. --dump-config: print the effective config and exit. A file a run
    //    would refuse when it plans is refused here too, so `-D` answers
    //    "would a run accept this file".
    if cli.config_args.dump_config {
        if let Err(e) = bootstrap::refuse_invalid_config(cli, &loaded.config) {
            e.exit();
        }
        sipnab::capture::archive::release_run_and_exit(bootstrap::dump_config(loaded));
    }

    // 6a. --journal-show / --revert-actions: see or back out what sipnab did
    //     to other systems, and exit. Before any capture: recovery must not
    //     wait for, or depend on, a packet source.
    if let Some(code) = bootstrap::run_journal_command(cli, &loaded.config) {
        sipnab::capture::archive::release_run_and_exit(code);
    }

    // 6b. --uprobe-list: report which TLS libraries this host is running and
    //     exit, without installing anything in the kernel. Answers the question
    //     that decides whether a uprobe capture is worth starting.
    if cli.tls_args.uprobe_list {
        sipnab::capture::archive::release_run_and_exit(bootstrap::uprobe_list(cli));
    }
}

/// Step 8 of [`main`]: multi-core offline reconstruction over the file set
/// the plan resolved.
fn run_cores_file(cli: &Cli, loaded: &sipnab::config::LoadedConfig, plan: &bootstrap::RunPlan) {
    let paths: &[std::path::PathBuf] = match &plan.source {
        Some(sipnab::capture::CaptureSource::File { paths }) => paths,
        // `CoresFile` is only chosen when `-I` was given, so the source is
        // always `File`. An empty slice makes `run_cores_file` fail loudly
        // rather than silently analyzing nothing if that ever changes.
        _ => &[],
    };
    batch::run_cores_file(
        cli,
        &loaded.config,
        &plan.capture_config,
        plan.portrange,
        paths,
        plan.filter_expr.as_ref(),
        &plan.vcon_rules,
    );
}

/// Steps 9 and 10 of [`main`]: launch the capture, then run the TUI or the
/// batch runner over it.
fn launch_and_dispatch(cli: Cli, loaded: sipnab::config::LoadedConfig, plan: bootstrap::RunPlan) {
    // 9. Launch the capture: channel, capture thread, readiness handshake,
    //    chroot, privilege drop, runtime hardening.
    let launched = bootstrap::launch(
        &cli,
        &loaded.config,
        plan.source,
        &plan.capture_config,
        &plan.mode,
    );

    // 10. Dispatch to the selected mode.
    match plan.mode {
        RunMode::Tui => {
            #[cfg(feature = "tui")]
            sipnab::app::tui_mode::run_tui_mode(
                cli,
                loaded.config,
                sipnab::config::ConfigOrigin {
                    source: loaded.source,
                    shadowed: loaded.shadowed,
                },
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
                batch::CaptureFeed {
                    handle: launched.handle,
                    rx: launched.rx,
                    kill_worker: launched.kill_worker,
                },
                BatchProcessing {
                    matcher: plan.matcher,
                    filter_expr: plan.filter_expr,
                    vcon_rules: plan.vcon_rules,
                    output_opts: plan.output_opts,
                    event_exec: plan.event_exec,
                    input_files: plan.input_files,
                    relay: launched.relay,
                    #[cfg(feature = "tls")]
                    keylog_source: launched.keylog_source,
                },
                plan.policy,
            );
        }
        // gate: unreachable because step 8 in `main` returns for CoresFile
        // before this function is called, so this match never sees it.
        RunMode::CoresFile => unreachable!("handled before launch"),
    }
}
