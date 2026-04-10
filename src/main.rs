//! sipnab — SIP & RTP capture, analysis, and security tool.
//!
//! Entry point: parses CLI, sets up logging and signal handlers, loads config,
//! and dispatches to the appropriate mode.

use sipnab::cli::Cli;
use sipnab::config::Config;
use sipnab::signals;

fn main() {
    // 1. Parse CLI arguments
    let cli = Cli::parse_args();

    // 2. Setup logging (env var: SIPNAB_LOG, default: info; quiet overrides to warn)
    let default_level = if cli.quiet { "warn" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::new().filter_or("SIPNAB_LOG", default_level))
        .format_timestamp_millis()
        .init();

    // 3. Install signal handlers
    signals::install_handlers();

    // 4. Validate CLI argument combinations
    if let Err(msg) = cli.validate() {
        log::error!("{}", msg);
        std::process::exit(2);
    }

    // 5. Load configuration
    let loaded = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(loaded) => {
            if let Some(ref source) = loaded.source {
                log::info!("Loaded config from {}", source.display());
            }
            loaded
        }
        Err(e) => {
            log::error!("{}", e);
            std::process::exit(1);
        }
    };

    // 6. --dump-config: print version + effective config, then exit
    if cli.dump_config {
        println!("sipnab v{}", env!("CARGO_PKG_VERSION"));
        println!();
        if let Some(ref source) = loaded.source {
            println!("# Loaded from: {}", source.display());
        } else {
            println!("# No config file loaded (defaults only)");
        }
        println!("{}", loaded.config.dump());
        return;
    }

    // 7. Normal startup
    log::info!(
        "sipnab v{} — no capture engine yet (Phase 1.2)",
        env!("CARGO_PKG_VERSION")
    );
}
