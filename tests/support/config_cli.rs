// SPDX-License-Identifier: MIT OR Apache-2.0

//! The startup pipeline the config/CLI test program drives, in process.
//!
//! `main` runs, in order: archive passwords, the immediate commands, the
//! clap parse, `Cli::validate`, the provenance record, `--mint-token`,
//! `--vcon-forward`, `bootstrap::load_config`, the journal commands and
//! `bootstrap::plan`. The steps that act on the outside world (archive
//! password sources, immediate commands, the provenance record, minting,
//! forwarding, journal commands) are not run here. The four decision steps
//! are: parse, validate, load_config and plan. A setting that one of them
//! refuses is refused by the binary before anything runs, and the exit code
//! each one uses is the code the binary exits with. The binary-level tests
//! in `config_cli_flag_values_test.rs` hold the in-process codes to the
//! binary's.
//!
//! Every step runs under `catch_unwind`, so a panic is an outcome a test can
//! assert against rather than a test abort.

use std::panic::AssertUnwindSafe;
use std::path::Path;

use sipnab::cli::Cli;

/// The error a fallible helper returns.
pub type TestError = Box<dyn std::error::Error>;

/// Which pipeline step decided the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// clap refused the command line.
    Parse,
    /// `Cli::validate` refused it.
    Validate,
    /// `bootstrap::load_config` refused the file or the flag/file pair.
    Config,
    /// `bootstrap::plan` refused it.
    Plan,
    /// Every step accepted it.
    Accepted,
    /// clap printed help or the version (exit 0).
    Informational,
}

/// What the pipeline did with one command line and config file.
#[derive(Debug)]
pub struct Outcome {
    /// The step that decided it.
    pub stage: Stage,
    /// The exit code the binary uses for that decision.
    pub code: i32,
    /// The message the binary prints for it (empty when accepted).
    pub message: String,
    /// The parsed command line, when clap accepted it.
    pub cli: Option<Box<Cli>>,
    /// A panic message, when a step panicked.
    pub panic: Option<String>,
}

impl Outcome {
    /// Whether every step accepted the input.
    pub fn accepted(&self) -> bool {
        self.stage == Stage::Accepted
    }
}

/// Render a panic payload as text.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "non-string panic payload".to_string()
}

/// An outcome recording a panic in `stage`.
fn panicked(stage: Stage, payload: &(dyn std::any::Any + Send)) -> Outcome {
    Outcome {
        stage,
        code: 101,
        message: String::new(),
        cli: None,
        panic: Some(panic_text(payload)),
    }
}

/// An outcome recording a refusal.
fn refused(stage: Stage, code: i32, message: String, cli: Option<Box<Cli>>) -> Outcome {
    Outcome {
        stage,
        code,
        message,
        cli,
        panic: None,
    }
}

/// Parse `argv` exactly as the binary does, under `catch_unwind`.
fn parse_step(argv: &[String]) -> Result<Box<Cli>, Outcome> {
    let parsed = std::panic::catch_unwind(|| Cli::try_parse_from_args(argv.iter().cloned()));
    match parsed {
        Err(payload) => Err(panicked(Stage::Parse, payload.as_ref())),
        Ok(Err(e)) => {
            let code = e.exit_code();
            let stage = if code == 0 {
                Stage::Informational
            } else {
                Stage::Parse
            };
            Err(refused(stage, code, e.to_string(), None))
        }
        Ok(Ok(cli)) => Ok(Box::new(cli)),
    }
}

/// Run parse, validate, load_config and plan on `argv`.
///
/// `argv[0]` is the program name. When `config_file` is `Some`, `-f <file>`
/// is appended; otherwise `-F` is, so no file on the test host is read.
pub fn run(argv: &[String], config_file: Option<&Path>) -> Outcome {
    let mut full: Vec<String> = argv.to_vec();
    match config_file {
        Some(p) => {
            full.push("-f".to_string());
            full.push(p.display().to_string());
        }
        None => full.push("-F".to_string()),
    }
    run_exact(&full)
}

/// Run parse, validate, load_config and plan on exactly `argv`.
pub fn run_exact(argv: &[String]) -> Outcome {
    let cli = match parse_step(argv) {
        Ok(cli) => cli,
        Err(outcome) => return outcome,
    };
    let validated = std::panic::catch_unwind(AssertUnwindSafe(|| cli.validate()));
    match validated {
        Err(payload) => return panicked(Stage::Validate, payload.as_ref()),
        Ok(Err(e)) => return refused(Stage::Validate, 2, e.to_string(), Some(cli)),
        Ok(Ok(())) => {}
    }
    let loaded = std::panic::catch_unwind(AssertUnwindSafe(|| {
        sipnab::app::bootstrap::load_config(&cli)
    }));
    let loaded = match loaded {
        Err(payload) => return panicked(Stage::Config, payload.as_ref()),
        Ok(Err(e)) => return refused(Stage::Config, e.exit_code, e.message, Some(cli)),
        Ok(Ok(loaded)) => loaded,
    };
    let planned = std::panic::catch_unwind(AssertUnwindSafe(|| {
        sipnab::app::bootstrap::plan(&cli, &loaded.config).map(|_| ())
    }));
    match planned {
        Err(payload) => panicked(Stage::Plan, payload.as_ref()),
        Ok(Err(e)) => refused(Stage::Plan, e.exit_code, e.message, Some(cli)),
        Ok(Ok(())) => Outcome {
            stage: Stage::Accepted,
            code: 0,
            message: String::new(),
            cli: Some(cli),
            panic: None,
        },
    }
}

/// `["sipnab", "-N", args...]` as owned strings.
pub fn argv(args: &[&str]) -> Vec<String> {
    let mut v = vec!["sipnab".to_string(), "-N".to_string()];
    v.extend(args.iter().map(|s| (*s).to_string()));
    v
}

/// The text of one field in `cli`'s pretty Debug rendering: the lines from
/// `<field>: ` up to the next sibling field at the same indentation.
pub fn field_debug(cli: &Cli, field: &str) -> Option<String> {
    let text = format!("{cli:#?}");
    let lines: Vec<&str> = text.lines().collect();
    let needle = format!("{field}: ");
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with(&needle))?;
    let indent = lines[start].len() - lines[start].trim_start().len();
    let mut out = vec![lines[start].trim_start().to_string()];
    for l in &lines[start + 1..] {
        let this_indent = l.len() - l.trim_start().len();
        if this_indent <= indent {
            break;
        }
        out.push(l.trim().to_string());
    }
    Some(out.join(" "))
}
