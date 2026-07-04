//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! The binary is a thin dispatcher (WS2): parse arguments, run the
//! immediate commands, load config, build a [`bootstrap::RunPlan`], launch
//! the capture, and hand off to the TUI or batch runner in `sipnab::app`.

// Same production-path panic policy as the library (tests exempt via
// clippy.toml).
#![warn(clippy::unwrap_used, clippy::expect_used)]

// Faster general-purpose allocator: sipnab's offline ingestion does one heap
// allocation per captured packet, so the allocator is on the hot path.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use sipnab::app::batch::{self, BatchProcessing};
use sipnab::app::bootstrap::{self, RunMode};
use sipnab::cli::Cli;
use sipnab::signals;

fn main() {
    // 1. Parse CLI arguments and set up logging.
    let cli = Cli::parse_args();
    bootstrap::init_logging(&cli);

    // 2. Immediate commands that run before config load (--setup-caps,
    //    --strip-secrets).
    if let Some(code) = bootstrap::run_startup_commands(&cli) {
        std::process::exit(code);
    }

    // 3. Signal handlers + argument-combination validation.
    signals::install_handlers();
    if let Err(msg) = cli.validate() {
        tracing::error!("{}", msg);
        std::process::exit(2);
    }
    cli.warn_unimplemented_flags();

    // 4. --mint-token: mint a signed bearer token and exit.
    if let Some(code) = bootstrap::run_mint_token(&cli) {
        std::process::exit(code);
    }

    // 5. Load configuration and apply [limits].
    let loaded = match bootstrap::load_config(&cli) {
        Ok(loaded) => loaded,
        Err(e) => e.exit(),
    };

    // 6. --dump-config: print the effective config and exit.
    if cli.dump_config {
        std::process::exit(bootstrap::dump_config(&loaded));
    }

    // 7. Decide everything up front: source, capture config, portrange,
    //    filters, policy, run mode.
    let plan = match bootstrap::plan(&cli, &loaded.config) {
        Ok(plan) => plan,
        Err(e) => e.exit(),
    };

    // 8. Multi-core offline reconstruction bypasses the capture thread.
    if matches!(plan.mode, RunMode::CoresFile) {
        batch::run_cores_file(&cli, &loaded.config, &plan.capture_config, plan.portrange);
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
                launched.handle,
                launched.rx,
                plan.policy,
                #[cfg(feature = "api")]
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
                    output_opts: plan.output_opts,
                    event_exec: plan.event_exec,
                },
                plan.policy,
            );
        }
        RunMode::CoresFile => unreachable!("handled before launch"),
    }
}
