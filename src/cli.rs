//! Command-line argument parsing for sipnab.
//!
//! Uses clap derive to define the full unified flag set, combining sngrep and
//! sipgrep flags along with sipnab-specific additions for security analysis,
//! RTP quality monitoring, and event-driven automation.

use clap::Parser;

/// Build a version string including git commit hash and optional tag.
///
/// Examples: "0.1.0-alpha.1 (abc12345)", "0.1.0-alpha.1 (v0.1.0 abc12345-dirty)"
pub fn build_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let commit = env!("SIPNAB_GIT_COMMIT");
    let tag = env!("SIPNAB_GIT_TAG");
    let dirty = env!("SIPNAB_GIT_DIRTY");

    if commit.is_empty() {
        return version.to_string();
    }
    let mut parts = String::new();
    if !tag.is_empty() {
        parts.push_str(tag);
        parts.push(' ');
    }
    parts.push_str(commit);
    parts.push_str(dirty);
    format!("{version} ({parts})")
}

/// SIP & RTP capture, analysis, and security tool.
///
/// sipnab unifies the capabilities of sngrep and sipgrep into a single binary
/// with added security analysis, RTP quality monitoring, and machine-readable
/// output formats.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "sipnab",
    version = build_version(),
    about = "SIP & RTP capture, analysis, and security",
    long_about = "sipnab — SIP & RTP capture, analysis, and security tool.\n\n\
        Unifies sngrep + sipgrep with added security analysis, RTP quality \
        monitoring, and machine-readable output.",
    after_help = "EXAMPLES:\n  \
        sipnab -d eth0                    Capture on eth0\n  \
        sipnab -I capture.pcap           Read from pcap file\n  \
        sipnab -N --json                 Non-interactive JSON output\n  \
        sipnab --problems                Show problematic calls\n  \
        sipnab --kill-scanner            Detect SIP scanners\n  \
        sipnab --from alice --to bob     Filter by From/To headers\n  \
        sipnab 'INVITE sip:'             BPF display filter"
)]
pub struct Cli {
    // ── Capture ──────────────────────────────────────────────────────
    /// Network interface to capture on.
    #[arg(short = 'd', long = "device", value_name = "IFACE")]
    pub device: Option<String>,

    /// Read packets from a pcap file instead of live capture.
    #[arg(short = 'I', long = "input", value_name = "FILE")]
    pub input: Option<String>,

    /// Write captured packets to a pcap file.
    #[arg(short = 'O', long = "output", value_name = "FILE")]
    pub output: Option<String>,

    /// Kernel capture buffer size in MiB.
    #[arg(short = 'B', long = "buffer", value_name = "MIB")]
    pub buffer: Option<u32>,

    /// Snapshot length for packet capture (bytes).
    #[arg(long, value_name = "BYTES")]
    pub snaplen: Option<u32>,

    /// SIP port range to capture.
    #[arg(long, value_name = "RANGE", default_value = "5060-5061")]
    pub portrange: String,

    /// Capture on all available interfaces.
    #[arg(long)]
    pub multi_device: bool,

    /// Disable RTP capture and analysis.
    #[arg(long)]
    pub no_rtp: bool,

    /// Read BPF filter from a file.
    #[arg(long, value_name = "FILE")]
    pub bpf_file: Option<String>,

    /// Stop after capturing N packets.
    #[arg(short = 'n', long = "count", value_name = "N")]
    pub count: Option<u64>,

    /// Stop after capturing for this duration (e.g., "30s", "5m", "1h").
    #[arg(long, value_name = "DURATION")]
    pub duration: Option<String>,

    /// Autostop condition (e.g., "filesize:100", "duration:60").
    #[arg(long, value_name = "CONDITION")]
    pub autostop: Option<String>,

    /// Split output files (e.g., "filesize:50" for 50 MiB chunks).
    #[arg(long, value_name = "CONDITION")]
    pub split: Option<String>,

    /// Replay packets from a pcap file at original timing.
    #[arg(long)]
    pub replay: bool,

    /// Use pcapng format for output files.
    #[arg(long)]
    pub pcapng: bool,

    // ── Mode ─────────────────────────────────────────────────────────
    /// Non-interactive mode (no TUI). Required for batch/output flags.
    #[arg(short = 'N', long = "no-tui")]
    pub no_tui: bool,

    /// Show only SIP dialogs (calls), not standalone messages.
    #[arg(short = 'c', long = "calls-only")]
    pub calls_only: bool,

    /// Compatibility no-op (sngrep -r flag).
    #[arg(short = 'r', hide = true)]
    pub _sngrep_r: bool,

    /// Capture and display telephone-event (DTMF) RTP payloads.
    #[arg(short = 't', long = "telephone-event")]
    pub telephone_event: bool,

    /// Suppress informational output; only show results.
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    // ── Matching ─────────────────────────────────────────────────────
    /// Case-insensitive matching for header filters and patterns.
    #[arg(short = 'i', long = "ignore-case")]
    pub ignore_case: bool,

    /// Invert the match: show messages that do NOT match.
    #[arg(short = 'v', long = "invert")]
    pub invert: bool,

    /// Match whole words only.
    #[arg(short = 'w', long = "word")]
    pub word: bool,

    /// Treat multi-line SIP headers as a single line for matching.
    #[arg(long)]
    pub single_line: bool,

    /// Filter by SIP From header (regex pattern).
    #[arg(long, value_name = "PATTERN")]
    pub from: Option<String>,

    /// Filter by SIP To header (regex pattern).
    #[arg(long, value_name = "PATTERN")]
    pub to: Option<String>,

    /// Filter by SIP Contact header (regex pattern).
    #[arg(long, value_name = "PATTERN")]
    pub contact: Option<String>,

    /// Filter by User-Agent header (regex pattern).
    #[arg(long, value_name = "PATTERN")]
    pub ua: Option<String>,

    /// Advanced filter DSL expression.
    #[arg(long, value_name = "EXPR")]
    pub filter: Option<String>,

    // ── Diagnostic aliases ───────────────────────────────────────────
    /// Show calls with detected problems (retransmits, timeouts, errors).
    #[arg(long)]
    pub problems: bool,

    /// Show calls with slow setup time (>3s by default).
    #[arg(long)]
    pub slow_setup: bool,

    /// Show calls shorter than 5 seconds.
    #[arg(long)]
    pub short_calls: bool,

    /// Show calls with potential one-way audio issues.
    #[arg(long)]
    pub one_way: bool,

    /// Show calls with NAT-related issues (Contact/Via mismatch).
    #[arg(long)]
    pub nat_issues: bool,

    // ── Output ───────────────────────────────────────────────────────
    /// Output results as JSON (one object per line).
    #[arg(long)]
    pub json: bool,

    /// Output results as pretty-printed JSON.
    #[arg(long)]
    pub json_pretty: bool,

    /// Generate a summary report after capture completes.
    #[arg(long)]
    pub report: bool,

    /// Generate a detailed report for a specific Call-ID.
    #[arg(long, value_name = "CALL-ID")]
    pub call_report: Option<String>,

    /// Format report output as Markdown.
    #[arg(long)]
    pub markdown: bool,

    /// Include hex dump of SIP payloads.
    #[arg(long)]
    pub hexdump: bool,

    /// Show delta time between consecutive messages.
    #[arg(long)]
    pub delta_time: bool,

    /// Show N messages after each match (like grep -A).
    #[arg(short = 'A', long = "after", value_name = "N")]
    pub after: Option<usize>,

    /// Show messages with empty bodies.
    #[arg(long)]
    pub show_empty: bool,

    /// Flush output after each line (useful for piping).
    #[arg(long)]
    pub line_buffer: bool,

    /// Color output mode.
    #[arg(long, value_name = "WHEN", default_value = "auto")]
    pub color: String,

    /// Maximum payload bytes to display.
    #[arg(long, value_name = "BYTES")]
    pub payload_limit: Option<usize>,

    /// Dump raw SIP message text (like sipgrep -T).
    #[arg(short = 'T', long = "text-dump")]
    pub text_dump: bool,

    /// Launch Wireshark with a display filter for the current capture.
    #[arg(long)]
    pub wireshark: bool,

    /// Generate a tshark-compatible display filter string.
    #[arg(long, value_name = "EXPR")]
    pub tshark_filter: Option<String>,

    /// Output in fail2ban-compatible format for SIP security events.
    #[arg(long)]
    pub fail2ban: bool,

    /// Group output by field (e.g., "call-id", "from", "method").
    #[arg(long, value_name = "FIELD")]
    pub group_by: Option<String>,

    // ── Dialog ───────────────────────────────────────────────────────
    /// Maximum number of dialogs to track simultaneously.
    #[arg(
        short = 'l',
        long = "limit",
        value_name = "N",
        default_value = "100000"
    )]
    pub limit: u64,

    /// Rotate dialog storage when limit is reached (discard oldest).
    #[arg(short = 'R', long = "rotate")]
    pub rotate: bool,

    /// Track dialogs using this method (e.g., "call-id", "branch").
    #[arg(long, value_name = "METHOD")]
    pub dialog_track: Option<String>,

    /// Disable dialog tracking entirely (message-only mode).
    #[arg(long)]
    pub no_dialog: bool,

    /// Filter dialogs by tag value.
    #[arg(long, value_name = "TAG")]
    pub tag: Option<String>,

    // ── RTP ──────────────────────────────────────────────────────────
    /// RTP statistics reporting interval in seconds.
    #[arg(long, value_name = "SECS", default_value = "1")]
    pub rtp_interval: u32,

    /// Maximum number of RTP streams to track simultaneously.
    #[arg(long, value_name = "N", default_value = "50000")]
    pub max_streams: u64,

    /// MOS quality threshold for alerts (1.0-5.0 scale).
    #[arg(long, value_name = "MOS", default_value = "3.0")]
    pub quality_threshold: f64,

    // ── Security ─────────────────────────────────────────────────────
    /// Detect and report SIP scanning activity.
    #[arg(long)]
    pub kill_scanner: bool,

    /// Detect specific User-Agent strings associated with scanners.
    #[arg(long, value_name = "PATTERN")]
    pub kill_ua: Option<String>,

    /// SIP response code to use in scanner kill reports.
    #[arg(long, value_name = "CODE", default_value = "200", value_parser = clap::value_parser!(u16).range(100..=699))]
    pub kill_response: u16,

    /// Enable fraud detection heuristics.
    #[arg(long)]
    pub fraud_detect: bool,

    /// Detect registration flood attacks.
    #[arg(long)]
    pub reg_flood: bool,

    /// Detect digest credential leaks in SIP messages.
    #[arg(long)]
    pub digest_leak: bool,

    /// Alert channels (repeatable: "syslog", "json", "exec").
    #[arg(long, value_name = "CHANNEL")]
    pub alert: Vec<String>,

    /// Execute this command when an alert fires.
    #[arg(long, value_name = "CMD")]
    pub alert_exec: Option<String>,

    /// Validate STIR/SHAKEN identity headers.
    #[arg(long)]
    pub stir_shaken: bool,

    // ── Event execution ──────────────────────────────────────────────
    /// Execute command when a dialog state changes.
    #[arg(long, value_name = "CMD")]
    pub on_dialog_exec: Option<String>,

    /// Execute command when RTP quality drops below threshold.
    #[arg(long, value_name = "CMD")]
    pub on_quality_exec: Option<String>,

    /// Maximum exec invocations per second (rate limit).
    #[arg(long, value_name = "N", default_value = "10")]
    pub exec_rate_limit: u32,

    // ── Network listeners ────────────────────────────────────────────
    /// Enable Prometheus metrics endpoint (e.g., "0.0.0.0:9090").
    #[arg(long, value_name = "ADDR")]
    pub metrics: Option<String>,

    /// Bearer token for metrics endpoint authentication.
    #[arg(long, value_name = "TOKEN")]
    pub metrics_auth: Option<String>,

    /// Enable REST API endpoint (e.g., "0.0.0.0:8080").
    #[arg(long, value_name = "ADDR")]
    pub api: Option<String>,

    /// API key for REST API authentication.
    #[arg(long, value_name = "KEY", env = "SIPNAB_API_KEY")]
    pub api_key: Option<String>,

    /// TLS certificate for API endpoint.
    #[arg(long, value_name = "FILE")]
    pub api_tls_cert: Option<String>,

    /// TLS private key for API endpoint.
    #[arg(long, value_name = "FILE")]
    pub api_tls_key: Option<String>,

    /// Maximum concurrent API connections.
    #[arg(long, value_name = "N", default_value = "100")]
    pub api_max_conn: u32,

    /// Listen for HEP (Homer Encapsulation Protocol) packets.
    #[arg(short = 'L', long = "hep-listen", value_name = "ADDR")]
    pub hep_listen: Option<String>,

    /// Send captured packets via HEP to a remote collector.
    #[arg(short = 'H', long = "hep-send", value_name = "ADDR")]
    pub hep_send: Option<String>,

    /// Parse incoming HEP packets (enable HEP decoding).
    #[arg(short = 'E', long = "hep-parse")]
    pub hep_parse: bool,

    /// Allowed source addresses for HEP input (repeatable).
    #[arg(long, value_name = "ADDR")]
    pub hep_allow: Vec<String>,

    /// Maximum HEP packets per second.
    #[arg(long, value_name = "N", default_value = "50000")]
    pub hep_rate_limit: u64,

    /// Send alerts to syslog.
    #[arg(long)]
    pub syslog: bool,

    // ── TLS / Decryption ─────────────────────────────────────────────
    /// TLS private key file for SIP-TLS decryption.
    #[arg(short = 'k', long = "tls-key", value_name = "FILE")]
    pub tls_key: Option<String>,

    /// TLS key log file (NSS SSLKEYLOGFILE format).
    #[arg(long, value_name = "FILE")]
    pub keylog: Option<String>,

    /// Watch key log file for new entries (live decryption).
    #[arg(long)]
    pub keylog_watch: bool,

    /// DTLS key log file for SRTP key extraction.
    #[arg(long, value_name = "FILE")]
    pub dtls_keylog: Option<String>,

    /// SRTP master keys file for RTP decryption.
    #[arg(long, value_name = "FILE")]
    pub srtp_keys: Option<String>,

    /// Pcap export mode for encrypted traffic.
    #[arg(long, value_name = "MODE", default_value = "decrypted")]
    pub pcap_export_mode: String,

    /// Allow core dumps (do not call prctl to disable).
    #[arg(long)]
    pub allow_coredump: bool,

    // ── Privilege ────────────────────────────────────────────────────
    /// Drop privileges to this user after opening capture devices.
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,

    /// Do not drop privileges after opening capture devices.
    #[arg(long)]
    pub no_priv_drop: bool,

    /// Chroot to this directory after initialization.
    #[arg(long, value_name = "DIR")]
    pub chroot: Option<String>,

    // ── Resource limits ──────────────────────────────────────────────
    /// Maximum concurrent TCP/TLS reassembly sessions.
    #[arg(long, value_name = "N", default_value = "10000")]
    pub max_reassembly: u64,

    // ── Config ───────────────────────────────────────────────────────
    /// Path to configuration file.
    #[arg(short = 'f', long = "config", value_name = "FILE")]
    pub config: Option<String>,

    /// Skip loading any configuration file.
    #[arg(short = 'F', long = "no-config")]
    pub no_config: bool,

    /// Dump the effective configuration and exit.
    #[arg(short = 'D', long = "dump-config")]
    pub dump_config: bool,

    // ── Positional ───────────────────────────────────────────────────
    /// BPF display filter expression (trailing positional arguments).
    #[arg(trailing_var_arg = true, value_name = "BPF_FILTER")]
    pub bpf_filter: Vec<String>,
}

impl Cli {
    /// Parse CLI arguments from the real process arguments.
    pub fn parse_args() -> Self {
        Cli::parse()
    }

    /// Parse CLI arguments from an iterator (for testing).
    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Cli::parse_from(args)
    }

    /// Validate argument combinations and return an error message if invalid.
    ///
    /// Checks that output-only flags (`--json`, `--report`, `--hexdump`,
    /// `--fail2ban`) require non-interactive mode (`-N`) unless `--call-report`
    /// is specified (which implies non-interactive output).
    pub fn validate(&self) -> Result<(), String> {
        let output_flags_used: Vec<&str> = [
            (self.json, "--json"),
            (self.json_pretty, "--json-pretty"),
            (self.report, "--report"),
            (self.hexdump, "--hexdump"),
            (self.fail2ban, "--fail2ban"),
        ]
        .iter()
        .filter(|(active, _)| *active)
        .map(|(_, name)| *name)
        .collect();

        if !output_flags_used.is_empty() && !self.no_tui && self.call_report.is_none() {
            return Err(format!(
                "Output flags ({}) require -N/--no-tui mode (or --call-report)",
                output_flags_used.join(", ")
            ));
        }

        Ok(())
    }

    /// Print warnings to stderr for CLI flags that are set but not yet
    /// implemented. Call after parsing and validation so the user knows
    /// their flag was accepted but has no effect.
    pub fn warn_unimplemented_flags(&self) {
        // All flags are now implemented. Feature-gated flags produce errors
        // at startup in main.rs when the required feature is not compiled in.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cli = Cli::parse_from_args(["sipnab"]);
        assert_eq!(cli.portrange, "5060-5061");
        assert_eq!(cli.limit, 100000);
        assert_eq!(cli.rtp_interval, 1);
        assert_eq!(cli.max_streams, 50000);
        assert!((cli.quality_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(cli.kill_response, 200);
        assert_eq!(cli.exec_rate_limit, 10);
        assert_eq!(cli.api_max_conn, 100);
        assert_eq!(cli.hep_rate_limit, 50000);
        assert_eq!(cli.pcap_export_mode, "decrypted");
        assert_eq!(cli.max_reassembly, 10000);
        assert_eq!(cli.color, "auto");
        assert!(!cli.no_tui);
    }

    #[test]
    fn capture_flags_parse() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "-d",
            "eth0",
            "-I",
            "in.pcap",
            "-O",
            "out.pcap",
            "--no-rtp",
            "--multi-device",
        ]);
        assert_eq!(cli.device.as_deref(), Some("eth0"));
        assert_eq!(cli.input.as_deref(), Some("in.pcap"));
        assert_eq!(cli.output.as_deref(), Some("out.pcap"));
        assert!(cli.no_rtp);
        assert!(cli.multi_device);
    }

    #[test]
    fn matching_flags_parse() {
        let cli = Cli::parse_from_args([
            "sipnab", "--from", "alice", "--to", "bob", "--ua", "friendly", "-i", "-v", "-w",
        ]);
        assert_eq!(cli.from.as_deref(), Some("alice"));
        assert_eq!(cli.to.as_deref(), Some("bob"));
        assert_eq!(cli.ua.as_deref(), Some("friendly"));
        assert!(cli.ignore_case);
        assert!(cli.invert);
        assert!(cli.word);
    }

    #[test]
    fn output_flags_require_no_tui() {
        let cli = Cli::parse_from_args(["sipnab", "--json"]);
        assert!(cli.validate().is_err());

        let cli = Cli::parse_from_args(["sipnab", "-N", "--json"]);
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn call_report_bypasses_no_tui_requirement() {
        let cli = Cli::parse_from_args(["sipnab", "--json", "--call-report", "abc123"]);
        assert!(cli.validate().is_ok());
    }

    #[test]
    fn security_flags_parse() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "--kill-scanner",
            "--fraud-detect",
            "--alert",
            "syslog",
            "--alert",
            "json",
        ]);
        assert!(cli.kill_scanner);
        assert!(cli.fraud_detect);
        assert_eq!(cli.alert, vec!["syslog", "json"]);
    }

    #[test]
    fn bpf_filter_positional() {
        let cli = Cli::parse_from_args(["sipnab", "host", "10.0.0.1", "and", "port", "5060"]);
        assert_eq!(
            cli.bpf_filter,
            vec!["host", "10.0.0.1", "and", "port", "5060"]
        );
    }

    #[test]
    fn validate_multiple_output_flags() {
        let cli = Cli::parse_from_args(["sipnab", "--json", "--report", "--fail2ban"]);
        let err = cli.validate().unwrap_err();
        assert!(err.contains("--json"));
        assert!(err.contains("--report"));
        assert!(err.contains("--fail2ban"));
    }
}
