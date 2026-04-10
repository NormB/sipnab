# Phase 1.1 — Project Scaffold & CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Initialize the sipnab Rust project with CLI parsing, config loading, logging, signal handling, CI pipeline, and documentation scaffold — everything needed before packet capture code begins.

**Architecture:** Single-binary Rust project using clap (derive) for CLI, serde + toml for config, env_logger for logging, and libc for signal handling. CI via GitHub Actions with cargo-audit and cargo-deny for supply chain security. All dependencies and feature flags declared upfront even if the implementing code ships in later phases.

**Tech Stack:** Rust 1.92+ (latest stable), clap 4.x (derive), serde + toml, log + env_logger, libc (signals), cargo-deny, GitHub Actions

---

## File Structure

```
sipnab/
├── Cargo.toml                    # All deps + feature flags for entire project
├── Cargo.lock                    # Committed (binary, not library)
├── deny.toml                     # cargo-deny config: licenses, advisories, bans
├── rustfmt.toml                  # Formatting config
├── .github/
│   └── workflows/
│       └── ci.yml                # CI: build, test, clippy, fmt, audit, deny
├── src/
│   ├── main.rs                   # Entry point: parse CLI, load config, setup logging, run
│   ├── cli.rs                    # clap derive: full unified flag set
│   └── config.rs                 # TOML config: load, merge with CLI, validate
├── tests/
│   ├── cli_test.rs               # CLI parsing integration tests
│   └── config_test.rs            # Config loading integration tests
├── README.md                     # Project description, build, license
├── CONTRIBUTING.md               # Build from source, test, style, PR process
├── SECURITY.md                   # Vulnerability reporting
├── LICENSE                       # GPLv3
├── docs/
│   ├── cli-reference.md          # Full flag reference
│   └── config-reference.md       # Config file reference
└── man/
    └── sipnab.1                  # Man page skeleton
```

---

### Task 1: Initialize Cargo Project

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`
- Create: `rustfmt.toml`
- Create: `LICENSE`

- [ ] **Step 1: Create Cargo.toml with all dependencies and feature flags**

```toml
[package]
name = "sipnab"
version = "0.1.0-alpha.1"
edition = "2021"
rust-version = "1.92"
authors = ["Norm Brandinger"]
description = "SIP & RTP capture, analysis, and security"
license = "GPL-3.0-only"
repository = "https://github.com/NormB/sipnab"
homepage = "https://sipnab.com"
keywords = ["sip", "voip", "rtp", "pcap", "sngrep"]
categories = ["command-line-utilities", "network-programming"]

[dependencies]
# Phase 1: Capture & core
pcap = "2"
etherparse = "0.16"
clap = { version = "4", features = ["derive", "env", "string"] }
regex = "1"
chrono = { version = "0.4", default-features = false, features = ["clock", "std"] }
log = "0.4"
env_logger = "0.11"
parking_lot = "0.12"
crossbeam-channel = "0.5"
libc = "0.2"

# Phase 2: SIP parsing & output
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
pcap-file = "2"
nom = "7"

# Phase 2: Error handling
anyhow = "1"
thiserror = "2"

# Phase 3: TUI
ratatui = { version = "0.29", optional = true }
crossterm = { version = "0.28", optional = true }
unicode-width = { version = "0.2", optional = true }

# Phase 5: TLS/Crypto (feature-gated)
zeroize = { version = "1", features = ["derive"], optional = true }
rustls = { version = "0.23", optional = true }
ring = { version = "0.17", optional = true }
base64 = { version = "0.22", optional = true }

# Phase 5: Metrics & API
axum = { version = "0.8", optional = true }
tokio = { version = "1", features = ["full"], optional = true }

# Phase 6: gRPC
tonic = { version = "0.12", optional = true }
prost = { version = "0.13", optional = true }

[features]
default = ["tui"]
tui = ["dep:ratatui", "dep:crossterm", "dep:unicode-width"]
tls = ["dep:zeroize", "dep:ring", "dep:base64"]
tls-wolfssl = ["tls"]
tls-openssl = ["tls"]
hep = []
grpc = ["dep:tonic", "dep:prost"]
api = ["dep:axum", "dep:tokio"]
full = ["tui", "tls", "hep", "grpc", "api"]

[profile.release]
lto = true
codegen-units = 1
strip = true

[[bin]]
name = "sipnab"
path = "src/main.rs"
```

- [ ] **Step 2: Create minimal main.rs**

```rust
fn main() {
    println!("sipnab v{}", env!("CARGO_PKG_VERSION"));
}
```

- [ ] **Step 3: Create rustfmt.toml**

```toml
max_width = 100
use_field_init_shorthand = true
```

- [ ] **Step 4: Create LICENSE file**

Copy the GPLv3 full text.

- [ ] **Step 5: Build and verify**

Run: `cargo build 2>&1`
Expected: Compiles with no errors. Warnings from unused deps are OK at this stage.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/main.rs rustfmt.toml LICENSE
git commit -m "feat: initialize cargo project with dependencies and feature flags"
```

---

### Task 2: CLI Argument Parsing

**Files:**
- Create: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/cli_test.rs`

- [ ] **Step 1: Write failing test for CLI parsing**

Create `tests/cli_test.rs`:

```rust
use std::process::Command;

#[test]
fn cli_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--version")
        .output()
        .expect("failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("sipnab"), "Expected 'sipnab' in version output: {stdout}");
}

#[test]
fn cli_no_tui_flag() {
    // -N flag should be accepted (no TUI mode)
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "--help"])
        .output()
        .expect("failed to execute");
    // --help always succeeds
    assert!(output.status.success());
}

#[test]
fn cli_capture_flags_accepted() {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["--help"])
        .output()
        .expect("failed to execute");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Verify key flags appear in help
    assert!(stdout.contains("--from"), "Missing --from flag");
    assert!(stdout.contains("--to"), "Missing --to flag");
    assert!(stdout.contains("--json"), "Missing --json flag");
    assert!(stdout.contains("--filter"), "Missing --filter flag");
    assert!(stdout.contains("--report"), "Missing --report flag");
    assert!(stdout.contains("--call-report"), "Missing --call-report flag");
    assert!(stdout.contains("--problems"), "Missing --problems flag");
    assert!(stdout.contains("--kill-scanner"), "Missing --kill-scanner flag");
    assert!(stdout.contains("--no-rtp"), "Missing --no-rtp flag");
}

#[test]
fn cli_invalid_flag_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .arg("--nonexistent-flag")
        .output()
        .expect("failed to execute");
    assert!(!output.status.success());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test cli_test 2>&1`
Expected: FAIL — `sipnab` binary doesn't parse args yet.

- [ ] **Step 3: Write cli.rs with full unified flag set**

Create `src/cli.rs`:

```rust
//! Command-line interface for sipnab.
//!
//! Unifies all sngrep and sipgrep flags into a single clap-derived struct.
//! See `docs/cli-reference.md` for the full flag reference.

use clap::Parser;
use std::path::PathBuf;

/// sipnab — SIP & RTP capture, analysis, and security
#[derive(Parser, Debug)]
#[command(name = "sipnab", version, about, long_about = None)]
pub struct Cli {
    // ── Capture source flags ──────────────────────────────────────────

    /// Capture device (comma-separated for multi-device)
    #[arg(short = 'd', long = "device")]
    pub device: Option<String>,

    /// Read from pcap/pcap-ng file
    #[arg(short = 'I', long = "input")]
    pub input: Option<PathBuf>,

    /// Write matched packets to pcap
    #[arg(short = 'O', long = "output")]
    pub output: Option<PathBuf>,

    /// Pcap buffer size in MB
    #[arg(short = 'B', long = "buffer")]
    pub buffer_mb: Option<u32>,

    /// Set capture snaplen
    #[arg(long = "snaplen")]
    pub snaplen: Option<u32>,

    /// Capture from all listed devices simultaneously
    #[arg(long = "multi-device")]
    pub multi_device: bool,

    /// SIP port range (default: 5060-5061)
    #[arg(long = "portrange", default_value = "5060-5061")]
    pub portrange: String,

    /// BPF filter expression (positional, after all flags)
    #[arg(trailing_var_arg = true)]
    pub bpf_filter: Vec<String>,

    /// Read BPF filter from file
    #[arg(long = "bpf-file")]
    pub bpf_file: Option<PathBuf>,

    // ── Mode flags ────────────────────────────────────────────────────

    /// No TUI — CLI output mode
    #[arg(short = 'N', long = "no-interface")]
    pub no_interface: bool,

    /// Only INVITE dialogs
    #[arg(short = 'c', long = "calls-only")]
    pub calls_only: bool,

    /// Accepted for sngrep compat (no-op: RTP is on by default)
    #[arg(short = 'r', hide = true)]
    pub rtp_compat: bool,

    /// Disable RTP/RTCP capture and analysis
    #[arg(long = "no-rtp")]
    pub no_rtp: bool,

    /// Capture telephone-event RTP
    #[arg(short = 't', long = "telephone-event")]
    pub telephone_event: bool,

    /// Quiet (no dialog count in -N mode)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    // ── Matching flags ────────────────────────────────────────────────

    /// Case-insensitive match
    #[arg(short = 'i', long = "ignore-case")]
    pub ignore_case: bool,

    /// Invert match
    #[arg(short = 'v', long = "invert-match")]
    pub invert_match: bool,

    /// Word-regex match
    #[arg(short = 'w', long = "word")]
    pub word: bool,

    /// Single-line match mode
    #[arg(long = "single-line")]
    pub single_line: bool,

    /// Match From header user
    #[arg(long = "from")]
    pub from_pattern: Option<String>,

    /// Match To header user
    #[arg(long = "to")]
    pub to_pattern: Option<String>,

    /// Match Contact header
    #[arg(long = "contact")]
    pub contact_pattern: Option<String>,

    /// Match User-Agent header
    #[arg(long = "ua")]
    pub ua_pattern: Option<String>,

    /// Filter DSL expression
    #[arg(long = "filter")]
    pub filter_expr: Option<String>,

    // ── Diagnostic filter aliases ─────────────────────────────────────

    /// Show only calls with detected issues
    #[arg(long = "problems")]
    pub problems: bool,

    /// Show only calls with PDD > 3 seconds
    #[arg(long = "slow-setup")]
    pub slow_setup: bool,

    /// Show only calls with duration < 5 seconds (wangiri pattern)
    #[arg(long = "short-calls")]
    pub short_calls: bool,

    /// Show only calls with one-way audio detected
    #[arg(long = "one-way")]
    pub one_way: bool,

    /// Show only calls with SDP/actual media address mismatch
    #[arg(long = "nat-issues")]
    pub nat_issues: bool,

    // ── Output flags ──────────────────────────────────────────────────

    /// JSON output (NDJSON to stdout)
    #[arg(long = "json")]
    pub json: bool,

    /// Pretty-printed JSON output
    #[arg(long = "json-pretty")]
    pub json_pretty: bool,

    /// Print dialog report on exit
    #[arg(long = "report")]
    pub report: bool,

    /// Generate structured diagnosis report for a specific call
    #[arg(long = "call-report")]
    pub call_report: Option<String>,

    /// Use Markdown format for --call-report output
    #[arg(long = "markdown")]
    pub markdown: bool,

    /// Raw hex+ASCII packet dump
    #[arg(long = "hexdump")]
    pub hexdump: bool,

    /// Delta timestamps
    #[arg(long = "delta-time")]
    pub delta_time: bool,

    /// Print N trailing context packets after match
    #[arg(long = "after", short = 'A')]
    pub after_context: Option<usize>,

    /// Show empty packets
    #[arg(long = "show-empty")]
    pub show_empty: bool,

    /// Line-buffered stdout
    #[arg(long = "line-buffer")]
    pub line_buffer: bool,

    /// Color mode: auto, always, never
    #[arg(long = "color", default_value = "auto")]
    pub color: String,

    /// Max payload display size
    #[arg(long = "payload-limit")]
    pub payload_limit: Option<usize>,

    /// Text dump to file
    #[arg(short = 'T', long = "text-dump")]
    pub text_dump: Option<PathBuf>,

    /// Print Wireshark display filters for matched dialogs
    #[arg(long = "wireshark")]
    pub wireshark: bool,

    /// Generate tshark command lines
    #[arg(long = "tshark-filter")]
    pub tshark_filter: bool,

    /// Output in fail2ban-parseable format
    #[arg(long = "fail2ban")]
    pub fail2ban: bool,

    /// Group concurrent call counts by field
    #[arg(long = "group-by")]
    pub group_by: Option<String>,

    // ── Dialog flags ──────────────────────────────────────────────────

    /// Dialog limit (default: 100000)
    #[arg(short = 'l', long = "limit", default_value = "100000")]
    pub dialog_limit: usize,

    /// Rotate dialogs when limit reached
    #[arg(short = 'R', long = "rotate")]
    pub rotate: bool,

    /// Enable dialog tracking in CLI mode
    #[arg(long = "dialog-track")]
    pub dialog_track: bool,

    /// Disable dialog matching
    #[arg(long = "no-dialog")]
    pub no_dialog: bool,

    /// Tag matched dialogs
    #[arg(long = "tag")]
    pub tag: Option<String>,

    // ── Capture control ───────────────────────────────────────────────

    /// Capture N packets then exit
    #[arg(long = "count", short = 'n')]
    pub count: Option<usize>,

    /// Capture for N seconds then exit
    #[arg(long = "duration")]
    pub duration: Option<u64>,

    /// Stop after condition: duration:N or filesize:N
    #[arg(long = "autostop")]
    pub autostop: Option<String>,

    /// Rotate pcap output: duration:N or filesize:N
    #[arg(long = "split")]
    pub split: Option<String>,

    /// Replay pcap with original timing
    #[arg(long = "replay")]
    pub replay: bool,

    /// Use PCAP-NG format for output
    #[arg(long = "pcapng")]
    pub pcapng: bool,

    // ── RTP flags ─────────────────────────────────────────────────────

    /// Quality metrics interval in seconds (default: 1)
    #[arg(long = "rtp-interval", default_value = "1")]
    pub rtp_interval: u64,

    /// Max RTP stream entries (default: 50000; 0 = unlimited)
    #[arg(long = "max-streams", default_value = "50000")]
    pub max_streams: usize,

    /// MOS threshold for --on-quality-exec (default: 3.0)
    #[arg(long = "quality-threshold", default_value = "3.0")]
    pub quality_threshold: f64,

    // ── Security flags ────────────────────────────────────────────────

    /// Auto-respond to friendly-scanner
    #[arg(long = "kill-scanner")]
    pub kill_scanner: bool,

    /// Kill scanner with custom UA match
    #[arg(long = "kill-ua")]
    pub kill_ua: Option<String>,

    /// Response code for kill mode (default: 200)
    #[arg(long = "kill-response", default_value = "200")]
    pub kill_response: u16,

    /// Enable toll fraud / IRSF detection
    #[arg(long = "fraud-detect")]
    pub fraud_detect: bool,

    /// Alert on registration flood
    #[arg(long = "reg-flood")]
    pub reg_flood: Option<u32>,

    /// Detect SIP digest auth vulnerabilities
    #[arg(long = "digest-leak")]
    pub digest_leak: bool,

    /// Alerting rule (repeatable)
    #[arg(long = "alert")]
    pub alert: Vec<String>,

    /// Execute command on alert
    #[arg(long = "alert-exec")]
    pub alert_exec: Option<String>,

    /// Decode and display STIR/SHAKEN Identity headers
    #[arg(long = "stir-shaken")]
    pub stir_shaken: bool,

    // ── Event exec hooks ──────────────────────────────────────────────

    /// Execute command on dialog event
    #[arg(long = "on-dialog-exec")]
    pub on_dialog_exec: Option<String>,

    /// Execute command on quality degradation
    #[arg(long = "on-quality-exec")]
    pub on_quality_exec: Option<String>,

    /// Max event exec invocations per second (default: 10)
    #[arg(long = "exec-rate-limit", default_value = "10")]
    pub exec_rate_limit: u32,

    // ── Network listener flags ────────────────────────────────────────

    /// Prometheus metrics endpoint (default bind: 127.0.0.1)
    #[arg(long = "metrics")]
    pub metrics: Option<String>,

    /// Basic auth for metrics endpoint
    #[arg(long = "metrics-auth")]
    pub metrics_auth: Option<String>,

    /// REST API daemon mode (default bind: 127.0.0.1)
    #[arg(long = "api")]
    pub api: Option<String>,

    /// API authentication key
    #[arg(long = "api-key")]
    pub api_key: Option<String>,

    /// TLS certificate for API endpoint
    #[arg(long = "api-tls-cert")]
    pub api_tls_cert: Option<PathBuf>,

    /// TLS private key for API endpoint
    #[arg(long = "api-tls-key")]
    pub api_tls_key: Option<PathBuf>,

    /// Max API concurrent connections (default: 100)
    #[arg(long = "api-max-conn", default_value = "100")]
    pub api_max_conn: usize,

    /// HEP listen address (default bind: 127.0.0.1)
    #[arg(short = 'L', long = "hep-listen")]
    pub hep_listen: Option<String>,

    /// HEP send destination
    #[arg(short = 'H', long = "hep-send")]
    pub hep_send: Option<String>,

    /// Enable HEP parsing
    #[arg(short = 'E', long = "hep-parse")]
    pub hep_parse: bool,

    /// HEP source IP allowlist (repeatable)
    #[arg(long = "hep-allow")]
    pub hep_allow: Vec<String>,

    /// HEP rate limit (default: 50000)
    #[arg(long = "hep-rate-limit", default_value = "50000")]
    pub hep_rate_limit: u32,

    /// Send alerts to syslog
    #[arg(long = "syslog")]
    pub syslog: bool,

    // ── TLS/Decryption flags ──────────────────────────────────────────

    /// TLS RSA private key file
    #[arg(short = 'k', long = "key")]
    pub tls_key: Option<PathBuf>,

    /// TLS key log file (NSS SSLKEYLOGFILE format)
    #[arg(long = "keylog")]
    pub keylog: Option<PathBuf>,

    /// Watch keylog file for new keys in real-time
    #[arg(long = "keylog-watch")]
    pub keylog_watch: bool,

    /// DTLS key log file
    #[arg(long = "dtls-keylog")]
    pub dtls_keylog: Option<PathBuf>,

    /// Manual SRTP key file (testing only)
    #[arg(long = "srtp-keys")]
    pub srtp_keys: Option<PathBuf>,

    /// Pcap export mode when decryption active
    #[arg(long = "pcap-export-mode", default_value = "decrypted")]
    pub pcap_export_mode: String,

    /// Allow core dumps when decryption active
    #[arg(long = "allow-coredump")]
    pub allow_coredump: bool,

    // ── Privilege flags ───────────────────────────────────────────────

    /// Drop privileges to this user after device open
    #[arg(long = "user")]
    pub priv_user: Option<String>,

    /// Don't drop privileges after opening capture
    #[arg(long = "no-priv-drop")]
    pub no_priv_drop: bool,

    /// Chroot to directory after device open
    #[arg(long = "chroot")]
    pub chroot: Option<PathBuf>,

    // ── Resource limit flags ──────────────────────────────────────────

    /// Max reassembly table entries (default: 10000)
    #[arg(long = "max-reassembly", default_value = "10000")]
    pub max_reassembly: usize,

    // ── Config flags ──────────────────────────────────────────────────

    /// Read config from file
    #[arg(short = 'f', long = "config")]
    pub config: Option<PathBuf>,

    /// Skip default config file
    #[arg(short = 'F', long = "no-config")]
    pub no_config: bool,

    /// Dump config and exit
    #[arg(short = 'D', long = "dump-config")]
    pub dump_config: bool,
}

impl Cli {
    /// Parse CLI arguments. Wraps clap::Parser::parse() for testability.
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Parse from an iterator (for testing).
    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::parse_from(args)
    }

    /// Returns true if any output mode requiring -N is active without -N being set.
    pub fn validate(&self) -> Result<(), String> {
        if (self.json || self.json_pretty || self.report || self.hexdump || self.fail2ban)
            && !self.no_interface
            && self.call_report.is_none()
        {
            return Err(
                "Output flags (--json, --report, --hexdump, --fail2ban) require -N (no TUI mode)"
                    .to_string(),
            );
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Update main.rs to use CLI**

```rust
mod cli;
mod config;

use cli::Cli;

fn main() {
    let cli = Cli::parse_args();

    if let Err(e) = cli.validate() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Placeholder — will be replaced in subsequent tasks
    if cli.dump_config {
        println!("sipnab v{} — config dump not yet implemented", env!("CARGO_PKG_VERSION"));
        return;
    }

    println!(
        "sipnab v{} — no capture engine yet (Phase 1.2)",
        env!("CARGO_PKG_VERSION")
    );
}
```

- [ ] **Step 5: Create empty config.rs placeholder**

```rust
//! Configuration file loading and merging for sipnab.
//!
//! Config file locations (first match wins):
//! 1. `--config <path>` (explicit)
//! 2. `$SIPNAB_CONFIG` (environment variable)
//! 3. `~/.config/sipnab/sipnab.toml`
//! 4. `~/.sipnabrc`
//! 5. `/etc/sipnab/sipnab.toml`
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --test cli_test 2>&1`
Expected: All 4 tests PASS.

- [ ] **Step 7: Run clippy and fmt**

Run: `cargo clippy -- -D warnings 2>&1 && cargo fmt --check 2>&1`
Expected: Clean.

- [ ] **Step 8: Commit**

```bash
git add src/cli.rs src/main.rs tests/cli_test.rs
git commit -m "feat: add CLI argument parsing with full unified flag set"
```

---

### Task 3: Configuration File Loading

**Files:**
- Modify: `src/config.rs`
- Create: `tests/config_test.rs`

- [ ] **Step 1: Write failing tests for config loading**

Create `tests/config_test.rs`:

```rust
use std::io::Write;
use tempfile::NamedTempFile;

// We test config by importing the library directly
// For now, use process-based tests since we don't have a lib target

#[test]
fn config_explicit_path_loads() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[capture]
device = "eth0"
portrange = "5060-5061"
"#
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-D", "-f", f.path().to_str().unwrap()])
        .output()
        .expect("failed to execute");
    assert!(output.status.success(), "Config load failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eth0"), "Config device not loaded: {stdout}");
}

#[test]
fn config_env_var_loads() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[capture]
device = "lo"
"#
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-D"])
        .env("SIPNAB_CONFIG", f.path().to_str().unwrap())
        .output()
        .expect("failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lo"), "Env config not loaded: {stdout}");
}

#[test]
fn config_unknown_key_warns() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[capture]
device = "eth0"
unknown_key = "value"
"#
    )
    .unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-D", "-f", f.path().to_str().unwrap()])
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("failed to execute");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown") || stderr.contains("Unknown"),
        "No warning for unknown key: {stderr}"
    );
}

#[test]
fn config_no_config_flag_skips() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-D", "-F"])
        .output()
        .expect("failed to execute");
    assert!(output.status.success());
}

#[test]
fn config_missing_explicit_file_errors() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-D", "-f", "/nonexistent/path/sipnab.toml"])
        .output()
        .expect("failed to execute");
    assert!(!output.status.success());
}
```

- [ ] **Step 2: Add tempfile dev-dependency**

Add to `Cargo.toml`:
```toml
[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test config_test 2>&1`
Expected: FAIL — config loading not implemented.

- [ ] **Step 4: Implement config.rs**

```rust
//! Configuration file loading and merging for sipnab.
//!
//! Config file locations (first match wins):
//! 1. `--config <path>` (explicit)
//! 2. `$SIPNAB_CONFIG` (environment variable)
//! 3. `~/.config/sipnab/sipnab.toml`
//! 4. `~/.sipnabrc`
//! 5. `/etc/sipnab/sipnab.toml`

use log::warn;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level configuration file structure.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub display: DisplayConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub privilege: PrivilegeConfig,
    #[serde(default)]
    pub theme: ThemeConfig,
    #[serde(default)]
    pub keybindings: KeybindingsConfig,
}

/// `[capture]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub device: Option<String>,
    pub portrange: Option<String>,
    pub buffer_mb: Option<u32>,
    pub snaplen: Option<u32>,
    pub rtp: Option<bool>,
}

/// `[display]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DisplayConfig {
    pub only_calls: Option<bool>,
    pub autoscroll: Option<bool>,
    pub columns: Option<Vec<String>>,
}

/// `[filter]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct FilterConfig {
    pub from: Option<String>,
    pub to: Option<String>,
}

/// `[security]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub scanner_patterns: Option<Vec<String>>,
    pub reg_flood_threshold: Option<u32>,
    pub irsf_prefixes: Option<PathBuf>,
}

/// `[limits]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct LimitsConfig {
    pub max_dialogs: Option<usize>,
    pub max_streams: Option<usize>,
    pub max_reassembly: Option<usize>,
    pub hep_rate_limit: Option<u32>,
    pub exec_rate_limit: Option<u32>,
    pub api_max_connections: Option<usize>,
}

/// `[privilege]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PrivilegeConfig {
    pub user: Option<String>,
    pub chroot: Option<PathBuf>,
}

/// `[theme]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ThemeConfig {
    pub highlight: Option<String>,
    pub invite: Option<String>,
    pub bye: Option<String>,
    pub error: Option<String>,
}

/// `[keybindings]` section.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct KeybindingsConfig {
    pub quit: Option<String>,
    pub filter: Option<String>,
    pub save: Option<String>,
}

impl Config {
    /// Load configuration from the first available source.
    ///
    /// Priority:
    /// 1. Explicit path (`--config`)
    /// 2. `$SIPNAB_CONFIG` env var
    /// 3. `~/.config/sipnab/sipnab.toml`
    /// 4. `~/.sipnabrc`
    /// 5. `/etc/sipnab/sipnab.toml`
    pub fn load(explicit_path: Option<&Path>, skip_default: bool) -> anyhow::Result<Self> {
        // Explicit path — must exist
        if let Some(path) = explicit_path {
            return Self::load_file(path);
        }

        // Environment variable
        if let Ok(env_path) = std::env::var("SIPNAB_CONFIG") {
            let path = PathBuf::from(&env_path);
            if path.exists() {
                return Self::load_file(&path);
            }
            warn!("SIPNAB_CONFIG={env_path} does not exist, skipping");
        }

        if skip_default {
            return Ok(Self::default());
        }

        // Default locations
        let candidates = Self::default_paths();
        for path in &candidates {
            if path.exists() {
                return Self::load_file(path);
            }
        }

        Ok(Self::default())
    }

    fn load_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {e}", path.display()))?;

        // First try strict parsing (deny_unknown_fields)
        match toml::from_str::<Config>(&content) {
            Ok(config) => Ok(config),
            Err(e) => {
                let err_str = e.to_string();
                // If the error is about unknown fields, warn and try lenient parse
                if err_str.contains("unknown field") {
                    warn!("Config file {}: {err_str}", path.display());
                    // Parse leniently via toml::Value, then re-serialize known fields
                    let value: toml::Value = toml::from_str(&content)?;
                    Self::warn_unknown_keys(&value, "");
                    let config = Self::from_value_lenient(&value);
                    Ok(config)
                } else {
                    Err(anyhow::anyhow!(
                        "Failed to parse config file {}: {e}",
                        path.display()
                    ))
                }
            }
        }
    }

    fn warn_unknown_keys(value: &toml::Value, prefix: &str) {
        let known_sections = [
            "capture", "display", "filter", "security", "limits", "privilege", "theme",
            "keybindings",
        ];
        if let Some(table) = value.as_table() {
            for (key, val) in table {
                let full_key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if prefix.is_empty() && !known_sections.contains(&key.as_str()) {
                    warn!("Unknown config section: [{key}]");
                }
                if val.is_table() {
                    Self::warn_unknown_keys(val, &full_key);
                }
            }
        }
    }

    fn from_value_lenient(value: &toml::Value) -> Self {
        // Re-serialize only known sections
        let mut config = Self::default();
        if let Some(table) = value.as_table() {
            if let Some(v) = table.get("capture") {
                if let Ok(c) = v.clone().try_into() {
                    config.capture = c;
                }
            }
            if let Some(v) = table.get("display") {
                if let Ok(c) = v.clone().try_into() {
                    config.display = c;
                }
            }
            if let Some(v) = table.get("filter") {
                if let Ok(c) = v.clone().try_into() {
                    config.filter = c;
                }
            }
            if let Some(v) = table.get("security") {
                if let Ok(c) = v.clone().try_into() {
                    config.security = c;
                }
            }
            if let Some(v) = table.get("limits") {
                if let Ok(c) = v.clone().try_into() {
                    config.limits = c;
                }
            }
            if let Some(v) = table.get("privilege") {
                if let Ok(c) = v.clone().try_into() {
                    config.privilege = c;
                }
            }
            if let Some(v) = table.get("theme") {
                if let Ok(c) = v.clone().try_into() {
                    config.theme = c;
                }
            }
            if let Some(v) = table.get("keybindings") {
                if let Ok(c) = v.clone().try_into() {
                    config.keybindings = c;
                }
            }
        }
        config
    }

    fn default_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(home) = dirs_next_home() {
            paths.push(home.join(".config").join("sipnab").join("sipnab.toml"));
            paths.push(home.join(".sipnabrc"));
        }
        paths.push(PathBuf::from("/etc/sipnab/sipnab.toml"));
        paths
    }

    /// Format config as displayable string for --dump-config.
    pub fn dump(&self) -> String {
        format!("{self:#?}")
    }
}

/// Get home directory without pulling in the full `dirs` crate.
fn dirs_next_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = Config::default();
        assert!(config.capture.device.is_none());
        assert!(config.limits.max_dialogs.is_none());
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
[capture]
device = "eth0"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("eth0"));
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
[capture]
device = "eth0"
portrange = "5060-5061"
buffer_mb = 2
snaplen = 65535
rtp = true

[display]
only_calls = false
autoscroll = true
columns = ["index", "method", "from", "to"]

[filter]
from = ""
to = ""

[security]
scanner_patterns = ["friendly-scanner", "sipvicious"]
reg_flood_threshold = 50

[limits]
max_dialogs = 100000
max_streams = 50000
max_reassembly = 10000
hep_rate_limit = 50000
exec_rate_limit = 10
api_max_connections = 100

[privilege]
user = "sipnab"

[theme]
highlight = "white_on_blue"
invite = "green"
bye = "red"
error = "red_bold"

[keybindings]
quit = "q"
filter = "F7"
save = "F2"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.device.as_deref(), Some("eth0"));
        assert_eq!(config.limits.max_dialogs, Some(100000));
        assert_eq!(config.theme.invite.as_deref(), Some("green"));
    }

    #[test]
    fn skip_default_returns_empty() {
        let config = Config::load(None, true).unwrap();
        assert!(config.capture.device.is_none());
    }

    #[test]
    fn missing_explicit_file_errors() {
        let result = Config::load(Some(Path::new("/nonexistent/file.toml")), false);
        assert!(result.is_err());
    }
}
```

- [ ] **Step 5: Update main.rs to load config and dump**

Replace `main.rs` with:

```rust
mod cli;
mod config;

use cli::Cli;
use config::Config;

fn main() {
    // Parse CLI
    let cli = Cli::parse_args();

    // Setup logging (must be before config load so warnings are visible)
    setup_logging();

    if let Err(e) = cli.validate() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    // Load config
    let config = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if cli.dump_config {
        println!("sipnab v{}", env!("CARGO_PKG_VERSION"));
        println!("{}", config.dump());
        return;
    }

    println!(
        "sipnab v{} — no capture engine yet (Phase 1.2)",
        env!("CARGO_PKG_VERSION")
    );
}

fn setup_logging() {
    env_logger::Builder::from_env(
        env_logger::Env::new()
            .filter_or("SIPNAB_LOG", "info")
    )
    .format_timestamp_millis()
    .init();
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test 2>&1`
Expected: All unit tests and integration tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/main.rs tests/config_test.rs Cargo.toml
git commit -m "feat: add TOML config file loading with priority chain and unknown key warnings"
```

---

### Task 4: Signal Handling

**Files:**
- Create: `src/signals.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write unit test for signal flag**

Add to `src/signals.rs` (we'll test the flag mechanism, not actual signal delivery from integration tests since that's OS-dependent):

```rust
//! Signal handling for sipnab.
//!
//! Handles SIGINT/SIGTERM for clean shutdown and SIGUSR1 for pcap rotation.
//! Uses atomic flags that can be polled from the main loop.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static ROTATE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Returns true if SIGINT or SIGTERM was received.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

/// Returns true if SIGUSR1 was received (and resets the flag).
pub fn rotation_requested() -> bool {
    ROTATE_REQUESTED.swap(false, Ordering::Relaxed)
}

/// Install signal handlers. Call once at startup.
pub fn install_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, signal_handler_rotate as libc::sighandler_t);
    }
}

extern "C" fn signal_handler(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

extern "C" fn signal_handler_rotate(_sig: libc::c_int) {
    ROTATE_REQUESTED.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_flag_default_false() {
        // Reset for test isolation
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        assert!(!shutdown_requested());
    }

    #[test]
    fn shutdown_flag_set() {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
        assert!(shutdown_requested());
        // Reset
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn rotation_flag_resets_on_read() {
        ROTATE_REQUESTED.store(true, Ordering::Relaxed);
        assert!(rotation_requested()); // reads true, resets to false
        assert!(!rotation_requested()); // now false
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test signals 2>&1`
Expected: All 3 tests PASS.

- [ ] **Step 3: Wire signals into main.rs**

Add `mod signals;` to `main.rs` and call `signals::install_handlers()` after logging setup:

```rust
mod cli;
mod config;
mod signals;

use cli::Cli;
use config::Config;
use log::info;

fn main() {
    let cli = Cli::parse_args();
    setup_logging();
    signals::install_handlers();

    if let Err(e) = cli.validate() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }

    let config = match Config::load(cli.config.as_deref(), cli.no_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    if cli.dump_config {
        println!("sipnab v{}", env!("CARGO_PKG_VERSION"));
        println!("{}", config.dump());
        return;
    }

    info!("sipnab v{} starting", env!("CARGO_PKG_VERSION"));
    println!(
        "sipnab v{} — no capture engine yet (Phase 1.2)",
        env!("CARGO_PKG_VERSION")
    );
}

fn setup_logging() {
    env_logger::Builder::from_env(env_logger::Env::new().filter_or("SIPNAB_LOG", "info"))
        .format_timestamp_millis()
        .init();
}
```

- [ ] **Step 4: Run all tests**

Run: `cargo test 2>&1`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/signals.rs src/main.rs
git commit -m "feat: add signal handling for clean shutdown and pcap rotation"
```

---

### Task 5: CI Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `deny.toml`

- [ ] **Step 1: Create GitHub Actions CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  check:
    name: Check (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt

      - name: Install libpcap (Linux)
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libpcap-dev

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Build
        run: cargo build --all-features

      - name: Test
        run: cargo test --all-features

      - name: Clippy
        run: cargo clippy --all-features -- -D warnings

      - name: Format check
        run: cargo fmt --check

  audit:
    name: Security audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Install cargo-deny
        run: cargo install cargo-deny

      - name: Audit
        run: cargo audit

      - name: Deny check
        run: cargo deny check
```

- [ ] **Step 2: Create deny.toml**

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "GPL-3.0",
    "OpenSSL",
]
copyleft = "allow"
default = "deny"

[bans]
multiple-versions = "warn"
wildcards = "allow"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

- [ ] **Step 3: Run cargo deny locally to verify**

Run: `cargo install cargo-deny 2>/dev/null; cargo deny check 2>&1`
Expected: PASS (or only warnings, no errors).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml deny.toml
git commit -m "ci: add GitHub Actions pipeline with audit and deny checks"
```

---

### Task 6: Documentation Scaffold

**Files:**
- Create: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `docs/cli-reference.md`
- Create: `docs/config-reference.md`
- Create: `man/sipnab.1`

- [ ] **Step 1: Create README.md**

```markdown
# sipnab

**SIP & RTP capture, analysis, and security**

sipnab unifies [sngrep](https://github.com/irontec/sngrep) (interactive SIP TUI) and [sipgrep](https://github.com/sipcapture/sipgrep) (CLI SIP regex matcher) into a single Rust binary, treats SIP signaling and RTP media as equal peers, then adds VoIP diagnosis, security analysis, and structured output that neither tool provides.

> **Status:** Under active development. Not yet ready for production use.

## Build from Source

Requires Rust 1.92+ and libpcap headers.

```bash
# macOS (libpcap included with Xcode CLI tools)
cargo build --release

# Linux
sudo apt-get install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel     # Fedora/RHEL
cargo build --release
```

## Quick Start

```bash
# Interactive TUI (sngrep-like)
sudo sipnab -d eth0

# CLI mode (sipgrep-like)
sudo sipnab -N -d eth0 --from 1001

# JSON streaming
sudo sipnab -N -d eth0 --json | jq .

# Read pcap file
sipnab -N -I capture.pcap --report

# Diagnose a specific call
sipnab -N -I capture.pcap --call-report <call-id>

# Show only problematic calls
sipnab -N -d eth0 --problems
```

## Feature Flags

| Flag | Description |
|------|-------------|
| `tui` (default) | Interactive terminal UI |
| `tls` | TLS decryption (pure-Rust crypto) |
| `hep` | HEP v2/v3 (Homer) protocol |
| `grpc` | gRPC API |
| `api` | REST API + Prometheus metrics |
| `full` | All features |

## Documentation

- [CLI Reference](docs/cli-reference.md)
- [Config Reference](docs/config-reference.md)
- [Implementation Plan](implementation-plan-v6.md)

## License

GPLv3. See [LICENSE](LICENSE).
```

- [ ] **Step 2: Create CONTRIBUTING.md**

```markdown
# Contributing to sipnab

## Building from Source

```bash
git clone git@github.com:NormB/sipnab.git
cd sipnab
cargo build
cargo test
```

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs))
- libpcap headers (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on Fedora)
- macOS: Xcode Command Line Tools (includes libpcap)

## Running Tests

```bash
cargo test                    # all tests
cargo test sip::parser        # single module
cargo test --test cli_test    # single integration test
```

## Code Style

- `cargo fmt` before committing (enforced in CI)
- `cargo clippy -- -D warnings` must pass (enforced in CI)
- No `.unwrap()` on external input — use `?`, `.unwrap_or()`, or `match`
- Rustdoc on all public types and functions

## Pull Request Process

1. Fork and create a feature branch
2. Write tests first (TDD)
3. Ensure `cargo test`, `cargo clippy`, `cargo fmt --check` all pass
4. Open a PR against `main`
```

- [ ] **Step 3: Create SECURITY.md**

```markdown
# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in sipnab, please report it responsibly.

**Email:** security@sipnab.com

**What to include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Acknowledgment within 48 hours
- Assessment within 7 days
- Fix or mitigation within 30 days for critical issues

## Scope

sipnab handles network traffic capture, TLS/SRTP decryption keys, and runs with elevated privileges. Security issues in these areas are considered critical:

- Parser crashes on crafted input (denial of service)
- Key material leakage (information disclosure)
- Privilege escalation after privilege drop
- Scanner kill amplification
- API authentication bypass

## Supported Versions

Only the latest release receives security updates.
```

- [ ] **Step 4: Create docs/cli-reference.md**

```markdown
# sipnab CLI Reference

## Usage

```
sipnab [FLAGS] [OPTIONS] [BPF_FILTER...]
```

## Modes

| Flag | Mode |
|------|------|
| (none) | Interactive TUI |
| `-N` | CLI output (no TUI) |
| `-N --json` | NDJSON streaming |
| `-N --call-report <id>` | Single-call diagnosis report |

## Capture Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-d <dev>` | Capture device | — |
| `-I <pcap>` | Read from pcap file | — |
| `-O <pcap>` | Write to pcap | — |
| `-B <mb>` | Pcap buffer size (MB) | 2 |
| `--snaplen <n>` | Capture snaplen | 65535 |
| `--portrange <range>` | SIP port range | 5060-5061 |
| `--multi-device` | Multi-device capture | off |
| `--no-rtp` | Disable RTP capture | off (RTP on) |
| `-n, --count <n>` | Stop after N packets | — |
| `--duration <secs>` | Stop after N seconds | — |
| `--replay` | Replay with original timing | off |
| `--pcapng` | Use PCAP-NG format | off |

## Filter Flags

| Flag | Description |
|------|-------------|
| `--from <pattern>` | Match From header |
| `--to <pattern>` | Match To header |
| `--ua <pattern>` | Match User-Agent |
| `--contact <pattern>` | Match Contact header |
| `-i` | Case-insensitive |
| `-v` | Invert match |
| `-w, --word` | Word-boundary match |
| `--filter <expr>` | Filter DSL expression |
| `--problems` | Show only problematic calls |
| `--slow-setup` | PDD > 3 seconds |
| `--short-calls` | Duration < 5 seconds |
| `--one-way` | One-way audio detected |
| `--nat-issues` | NAT mismatch detected |

## Output Flags

| Flag | Description |
|------|-------------|
| `--json` | NDJSON output |
| `--json-pretty` | Pretty JSON |
| `--report` | Dialog summary on exit |
| `--call-report <id>` | Single-call diagnosis |
| `--markdown` | Markdown for call-report |
| `--hexdump` | Hex+ASCII dump |
| `--fail2ban` | Fail2ban format |
| `--wireshark` | Wireshark display filters |
| `--tshark-filter` | tshark commands |
| `--delta-time` | Delta timestamps |
| `-A, --after <n>` | Trailing context packets |
| `--color <mode>` | auto, always, never |

For the complete flag set, run `sipnab --help`.
```

- [ ] **Step 5: Create docs/config-reference.md**

```markdown
# sipnab Configuration Reference

## File Locations (first match wins)

1. `--config <path>` (explicit)
2. `$SIPNAB_CONFIG` environment variable
3. `~/.config/sipnab/sipnab.toml`
4. `~/.sipnabrc`
5. `/etc/sipnab/sipnab.toml`

Use `-F` / `--no-config` to skip default config file loading.

## Format

TOML. All sections and keys are optional — unset values use built-in defaults.

## Sections

### `[capture]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `device` | string | — | Capture device name |
| `portrange` | string | `"5060-5061"` | SIP port range |
| `buffer_mb` | integer | 2 | Pcap buffer size (MB) |
| `snaplen` | integer | 65535 | Capture snaplen |
| `rtp` | boolean | true | Enable RTP capture |

### `[display]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `only_calls` | boolean | false | Show only INVITE dialogs |
| `autoscroll` | boolean | true | Auto-scroll to new dialogs |
| `columns` | string[] | (built-in) | Visible columns |

### `[filter]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `from` | string | — | Default From filter |
| `to` | string | — | Default To filter |

### `[security]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `scanner_patterns` | string[] | (built-in) | Scanner UA patterns |
| `reg_flood_threshold` | integer | 50 | REGISTER flood threshold |
| `irsf_prefixes` | path | — | Custom IRSF prefix file |

### `[limits]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_dialogs` | integer | 100000 | Max dialog store entries |
| `max_streams` | integer | 50000 | Max RTP stream entries |
| `max_reassembly` | integer | 10000 | Max reassembly entries |
| `hep_rate_limit` | integer | 50000 | HEP input rate limit |
| `exec_rate_limit` | integer | 10 | Event exec rate limit |
| `api_max_connections` | integer | 100 | API max connections |

### `[privilege]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `user` | string | `"sipnab"` | Drop-to user after device open |
| `chroot` | path | — | Chroot directory |

### `[theme]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `highlight` | string | `"white_on_blue"` | Highlight color |
| `invite` | string | `"green"` | INVITE method color |
| `bye` | string | `"red"` | BYE method color |
| `error` | string | `"red_bold"` | Error response color |

### `[keybindings]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `quit` | string | `"q"` | Quit key |
| `filter` | string | `"F7"` | Open filter dialog |
| `save` | string | `"F2"` | Save dialog |
```

- [ ] **Step 6: Create man page skeleton**

Create `man/sipnab.1`:

```
.TH SIPNAB 1 "2026-04-09" "sipnab 0.1.0-alpha.1" "User Commands"
.SH NAME
sipnab \- SIP & RTP capture, analysis, and security
.SH SYNOPSIS
.B sipnab
[\fIOPTIONS\fR] [\fIBPF_FILTER\fR...]
.SH DESCRIPTION
sipnab captures and analyzes SIP signaling and RTP media traffic. It operates
in three modes: interactive TUI (default), CLI output (\fB\-N\fR), and
JSON streaming (\fB\-N \-\-json\fR).
.PP
RTP streams are treated as first-class entities alongside SIP dialogs.
One-way audio, NAT mismatch, and quality degradation are detected automatically.
.SH OPTIONS
.TP
.B \-d \fIdevice\fR
Capture from network device (comma-separated for multi-device).
.TP
.B \-I \fIfile\fR
Read from pcap or pcap-ng file.
.TP
.B \-N
No TUI \(em CLI output mode.
.TP
.B \-\-json
NDJSON output (requires \fB\-N\fR).
.TP
.B \-\-filter \fIexpr\fR
Filter DSL expression.
.TP
.B \-\-problems
Show only calls with detected issues.
.TP
.B \-\-call-report \fIcall-id\fR
Generate structured diagnosis report for a specific call.
.PP
See \fBsipnab \-\-help\fR for the complete flag reference.
.SH ENVIRONMENT
.TP
.B SIPNAB_LOG
Logging level (trace, debug, info, warn, error, off). Default: info.
.TP
.B SIPNAB_CONFIG
Path to configuration file.
.SH FILES
.TP
.I ~/.config/sipnab/sipnab.toml
User configuration file.
.TP
.I /etc/sipnab/sipnab.toml
System-wide configuration file.
.SH LICENSE
GPLv3
.SH SEE ALSO
.BR sngrep (1),
.BR tshark (1),
.BR tcpdump (1)
```

- [ ] **Step 7: Commit all documentation**

```bash
git add README.md CONTRIBUTING.md SECURITY.md docs/ man/
git commit -m "docs: add README, CONTRIBUTING, SECURITY, CLI reference, config reference, man page"
```

---

### Task 7: Final Gate Verification

- [ ] **Step 1: Run full test suite**

Run: `cargo test 2>&1`
Expected: All tests PASS.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --all-features -- -D warnings 2>&1`
Expected: Clean.

- [ ] **Step 3: Run fmt check**

Run: `cargo fmt --check 2>&1`
Expected: Clean.

- [ ] **Step 4: Run cargo audit**

Run: `cargo audit 2>&1`
Expected: No known vulnerabilities.

- [ ] **Step 5: Run cargo deny**

Run: `cargo deny check 2>&1`
Expected: PASS.

- [ ] **Step 6: Verify config loading from all sources**

Run manually:
```bash
# Explicit path
echo '[capture]\ndevice = "test"' > /tmp/test-sipnab.toml
cargo run -- -N -D -f /tmp/test-sipnab.toml

# Env var
SIPNAB_CONFIG=/tmp/test-sipnab.toml cargo run -- -N -D

# Skip default
cargo run -- -N -D -F

# Unknown key warning
echo '[capture]\ndevice = "test"\nbogus = "value"' > /tmp/test-sipnab.toml
SIPNAB_LOG=warn cargo run -- -N -D -f /tmp/test-sipnab.toml 2>&1 | grep -i unknown
```

- [ ] **Step 7: Verify logging levels**

Run:
```bash
SIPNAB_LOG=trace cargo run -- -N 2>&1 | head -5   # should show trace output
SIPNAB_LOG=off cargo run -- -N 2>&1 | head -5      # should show no log output
```

- [ ] **Step 8: Tag phase complete**

```bash
git tag -a v0.0.1-scaffold -m "Phase 1.1: Project scaffold complete"
```
