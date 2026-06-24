//! Command-line argument parsing for sipnab.
//!
//! Uses clap derive to define the full unified flag set, combining sngrep and
//! sipgrep flags along with sipnab-specific additions for security analysis,
//! RTP quality monitoring, and event-driven automation.

use clap::Parser;

/// Build a version string including git commit hash, optional tag,
/// and the list of compile-time features that were enabled.
///
/// Examples:
/// - `0.3.1 (abc12345) features: native,tui,audio`
/// - `0.3.1 (v0.3.1 abc12345-dirty) features: native,tui,audio,tls,hep,api,mcp,mcp-http`
pub fn build_version() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let commit = env!("SIPNAB_GIT_COMMIT");
    let tag = env!("SIPNAB_GIT_TAG");
    let dirty = env!("SIPNAB_GIT_DIRTY");

    let features = compiled_features();
    let features_part = if features.is_empty() {
        String::new()
    } else {
        format!(" features: {}", features.join(","))
    };

    if commit.is_empty() {
        return format!("{version}{features_part}").trim_end().to_string();
    }
    let mut parts = String::new();
    if !tag.is_empty() {
        parts.push_str(tag);
        parts.push(' ');
    }
    parts.push_str(commit);
    parts.push_str(dirty);
    format!("{version} ({parts}){features_part}")
}

/// List of Cargo features compiled into this binary.
///
/// Walked statically via `cfg!(feature = "...")`. Feature names match
/// the `[features]` block in `Cargo.toml`.
fn compiled_features() -> Vec<&'static str> {
    let mut out = Vec::new();
    if cfg!(feature = "native") {
        out.push("native");
    }
    if cfg!(feature = "tui") {
        out.push("tui");
    }
    if cfg!(feature = "audio") {
        out.push("audio");
    }
    if cfg!(feature = "tls") {
        out.push("tls");
    }
    if cfg!(feature = "hep") {
        out.push("hep");
    }
    if cfg!(feature = "api") {
        out.push("api");
    }
    if cfg!(feature = "mcp") {
        out.push("mcp");
    }
    if cfg!(feature = "mcp-http") {
        out.push("mcp-http");
    }
    if cfg!(feature = "wasm") {
        out.push("wasm");
    }
    out
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

    /// Memory budget in MiB for the in-flight packet queue between capture and
    /// processing (default 64). The queue grows under load up to this budget and
    /// shrinks when idle; overrides `[capture] buffer_budget_mb`.
    #[arg(long = "buffer-budget", value_name = "MIB")]
    pub buffer_budget: Option<u32>,

    /// Snapshot length for packet capture (bytes).
    #[arg(long, value_name = "BYTES")]
    pub snaplen: Option<u32>,

    /// SIP port range to capture.
    #[arg(long, value_name = "RANGE", default_value = "5060-5061")]
    pub portrange: String,

    /// Capture on the selected interfaces given as a comma-separated list to
    /// `-d` (e.g. `-d eth0,docker0 --multi-device`), opening one capture per
    /// interface. Without this flag, the zero-argument default already sniffs
    /// ALL interfaces via the "any" pseudo-device.
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

    // ── Name resolution ──────────────────────────────────────────────
    /// Resolve IP addresses to names for display (manual mappings + hosts).
    /// Sets the TUI's initial name-resolution mode; press `n` to cycle it
    /// (Off / Static / DNS).
    #[arg(long = "resolve")]
    pub resolve: bool,

    /// Also use reverse DNS (PTR) lookups for name resolution. Implies
    /// `--resolve`. Off by default (it emits DNS queries for captured IPs).
    #[arg(long = "reverse-dns")]
    pub reverse_dns: bool,

    /// Load IP -> name mappings from an `/etc/hosts`-format file. Repeatable.
    #[arg(long = "names", value_name = "FILE")]
    pub names: Vec<String>,

    /// Default From/To column display mode in the TUI. Cycled at runtime with
    /// the `u` key. Overrides the `[display] from_to` config value.
    #[arg(long = "from-to-mode", value_enum, value_name = "MODE")]
    pub from_to_mode: Option<FromToModeArg>,

    /// Write a copy of the input pcapng (`-I`) to this path with all decryption
    /// secrets (DSBs) removed, then exit. The input is never modified.
    #[arg(long = "strip-secrets", value_name = "OUTPUT")]
    pub strip_secrets: Option<String>,

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

    /// Filter DSL expression OR a diagnostic alias. Accepts full
    /// expressions (e.g. "method == 'INVITE' and rtp.mos < 3.5") and
    /// alias names like "problems" or "codec-asym" — see
    /// docs/filter-dsl.md.
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
    /// Output NDJSON: one JSON object per SIP message, pipeable to jq.
    /// Schema in docs/output-formats.md.
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

    /// Suppress the per-message stream (reports still print). Combine
    /// with --report or --call-report for summary-only output:
    /// `sipnab -N -I file.pcap --report --no-cli-print`.
    #[arg(long = "no-cli-print")]
    pub no_cli_print: bool,

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

    /// Evict the oldest dialog when the `--limit` capacity is reached (LRU).
    /// This is the **default**; the flag is kept for back-compat / explicitness.
    #[arg(short = 'R', long = "rotate", overrides_with = "no_rotate")]
    pub rotate: bool,

    /// Disable dialog rotation: at `--limit` capacity, drop *new* dialogs instead
    /// of evicting the oldest. Inverts the safe default (which rotates) — only use
    /// when you must preserve the earliest dialogs and accept losing newer ones.
    #[arg(long = "no-rotate", overrides_with = "rotate")]
    pub no_rotate: bool,

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

    /// HTTP Basic auth credentials (`user:pass`) required by the metrics
    /// endpoint. When set, requests must send `Authorization: Basic <base64>`.
    #[arg(long, value_name = "USER:PASS")]
    pub metrics_auth: Option<String>,

    /// Enable REST API endpoint (e.g., "0.0.0.0:8080").
    #[arg(long, value_name = "ADDR")]
    pub api: Option<String>,

    /// API key for REST API authentication (static shared secret, no expiry).
    #[arg(long, value_name = "KEY", env = "SIPNAB_API_KEY")]
    pub api_key: Option<String>,

    /// HMAC signing key for REST API self-describing bearer tokens
    /// (repeatable). The FIRST key mints; ALL keys are accepted on verify,
    /// enabling signing-key rotation with overlap. Also read from
    /// SIPNAB_API_SIGNING_KEY.
    #[arg(
        long = "api-signing-key",
        value_name = "KEY",
        env = "SIPNAB_API_SIGNING_KEY"
    )]
    pub api_signing_key: Vec<String>,

    /// Read one REST API HMAC signing key from a file (contents trimmed).
    /// Prepended to any --api-signing-key values so it is the minting key.
    #[arg(long = "api-signing-key-file", value_name = "FILE")]
    pub api_signing_key_file: Option<String>,

    /// Revocation denylist file for REST API tokens: one revoked token id per
    /// line (blanks and `#` comments ignored). Reloaded when the file changes.
    #[arg(long = "api-revoked-file", value_name = "FILE")]
    pub api_revoked_file: Option<String>,

    /// TTL in seconds for a minted REST API token (used with --mint-token).
    #[arg(long = "api-token-ttl", value_name = "SECS", default_value = "3600")]
    pub api_token_ttl: i64,

    /// TLS certificate for API endpoint.
    #[arg(long, value_name = "FILE")]
    pub api_tls_cert: Option<String>,

    /// TLS private key for API endpoint.
    #[arg(long, value_name = "FILE")]
    pub api_tls_key: Option<String>,

    /// Maximum concurrent API connections.
    #[arg(long, value_name = "N", default_value = "100")]
    pub api_max_conn: u32,

    // ── MCP (Model Context Protocol) ──────────────────────────────────
    /// Run sipnab as an MCP server (Model Context Protocol) instead of TUI/CLI.
    /// Implies --no-tui. Default transport is stdio; --mcp-transport selects
    /// http (requires the mcp-http feature).
    #[arg(long)]
    pub mcp: bool,

    /// MCP transport: "stdio" (default) or "http".
    #[arg(
        long = "mcp-transport",
        value_name = "TRANSPORT",
        default_value = "stdio"
    )]
    pub mcp_transport: String,

    /// Bind address for the HTTP MCP transport (default 127.0.0.1:8731).
    #[arg(long = "mcp-bind", value_name = "ADDR")]
    pub mcp_bind: Option<String>,

    /// Bearer token for HTTP MCP transport. Reads from env SIPNAB_MCP_TOKEN
    /// when not given via the flag; required for non-loopback binds.
    #[arg(long = "mcp-token", value_name = "TOKEN", env = "SIPNAB_MCP_TOKEN")]
    pub mcp_token: Option<String>,

    /// Read the MCP bearer token from a file (preferred over env in
    /// systemd units).
    #[arg(long = "mcp-token-file", value_name = "FILE")]
    pub mcp_token_file: Option<String>,

    /// HMAC signing key for HTTP MCP self-describing bearer tokens
    /// (repeatable). The FIRST key mints; ALL keys are accepted on verify,
    /// enabling signing-key rotation with overlap. Also read from
    /// SIPNAB_MCP_SIGNING_KEY.
    #[arg(
        long = "mcp-signing-key",
        value_name = "KEY",
        env = "SIPNAB_MCP_SIGNING_KEY"
    )]
    pub mcp_signing_key: Vec<String>,

    /// Read one HTTP MCP HMAC signing key from a file (contents trimmed).
    /// Prepended to any --mcp-signing-key values so it is the minting key.
    #[arg(long = "mcp-signing-key-file", value_name = "FILE")]
    pub mcp_signing_key_file: Option<String>,

    /// Revocation denylist file for HTTP MCP tokens: one revoked token id per
    /// line (blanks and `#` comments ignored). Reloaded when the file changes.
    #[arg(long = "mcp-revoked-file", value_name = "FILE")]
    pub mcp_revoked_file: Option<String>,

    /// TTL in seconds for a minted HTTP MCP token (used with --mint-token).
    #[arg(long = "mcp-token-ttl", value_name = "SECS", default_value = "3600")]
    pub mcp_token_ttl: i64,

    /// Additional `Host` header values the HTTP MCP server will accept
    /// (repeatable). rmcp's DNS-rebind protection defaults to allowing
    /// only `localhost`, `127.0.0.1`, and `::1`. Add the public hostname
    /// or bind IP here when clients connect via that name. Use `*` to
    /// disable host checking entirely (not recommended; pair the
    /// resulting open binding with a network-level allowlist).
    #[arg(long = "mcp-allowed-host", value_name = "HOST")]
    pub mcp_allowed_host: Vec<String>,

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

    /// Emit each security alert as a structured JSON line on stderr (in addition
    /// to the human `[ALERT]` line) — a stable machine channel that survives log
    /// format changes. stdout stays reserved for `--json` / MCP.
    #[arg(long)]
    pub alert_json: bool,

    // ── TLS / Decryption ─────────────────────────────────────────────
    /// TLS private key (PEM) for TLS 1.2 RSA-key-exchange decryption. Only
    /// non-PFS RSA handshakes; ECDHE/DHE (forward secrecy) need --keylog.
    #[arg(short = 'k', long = "tls-key", value_name = "FILE")]
    pub tls_key: Option<String>,

    /// TLS key log file (NSS SSLKEYLOGFILE format).
    #[arg(long, value_name = "FILE")]
    pub keylog: Option<String>,

    /// Watch key log file for new entries (live decryption).
    #[arg(long)]
    pub keylog_watch: bool,

    /// DTLS key log (NSS SSLKEYLOGFILE): extracts SRTP keys from DTLS-SRTP
    /// handshakes via the RFC 5764 exporter (AES-CM profiles).
    #[arg(long, value_name = "FILE")]
    pub dtls_keylog: Option<String>,

    /// SRTP master-keys file for media decryption (AES-CM, RFC 3711). Also
    /// honors SDES `a=crypto` keys learned from SDP.
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

    /// Grant this binary the Linux capabilities needed for live capture
    /// (`cap_net_raw,cap_net_admin+ep` via setcap) so it can run without
    /// sudo, then exit. Re-invokes itself through sudo when not already root.
    #[arg(long = "setup-caps")]
    pub setup_caps: bool,

    // ── Resource limits ──────────────────────────────────────────────
    /// Maximum concurrent TCP/TLS reassembly sessions.
    #[arg(long, value_name = "N", default_value = "10000")]
    pub max_reassembly: u64,

    /// CPU cores for OFFLINE pcap reconstruction (`-I`). 1 = the standard
    /// single-threaded path. >1 shards packets by host pair across N worker
    /// threads for multi-core throughput on large captures; covers dialog +
    /// RTP-stream reconstruction and `--report`/`--json`. Advanced features
    /// (live capture, per-message output ordering, security detectors, SRTP
    /// decrypt) use the single-threaded path regardless.
    #[arg(long, value_name = "N", default_value = "1")]
    pub cores: usize,

    // ── Token minting ────────────────────────────────────────────────
    /// Mint a signed bearer token from the first configured signing key,
    /// print it to stdout, and exit. TTL comes from --api-token-ttl (or
    /// --mcp-token-ttl); id from --token-id (or auto-derived). Does NOT start
    /// capture or any server.
    #[arg(long = "mint-token")]
    pub mint_token: bool,

    /// Token id (jti) for --mint-token. Defaults to a derived unique id.
    #[arg(long = "token-id", value_name = "ID")]
    pub token_id: Option<String>,

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

/// From/To column display mode selectable on the command line.
///
/// clap renders the variants in kebab-case (`default`, `host-port`, `user`,
/// `user-host-port`), matching the `[display] from_to` config spellings and
/// `tui::FromToMode::as_config_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FromToModeArg {
    Default,
    HostPort,
    User,
    UserHostPort,
}

impl FromToModeArg {
    /// The canonical config/string spelling for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::HostPort => "host-port",
            Self::User => "user",
            Self::UserHostPort => "user-host-port",
        }
    }
}

impl Cli {
    /// Parse CLI arguments from the real process arguments.
    pub fn parse_args() -> Self {
        Cli::parse()
    }

    /// Whether the dialog store evicts the oldest dialog at `--limit` capacity.
    /// Defaults to `true` (SNB-0004): a privileged sniffer must bound dialog
    /// state safely without dropping new legitimate calls. `--no-rotate` opts out.
    pub fn rotate_enabled(&self) -> bool {
        !self.no_rotate
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
    pub fn validate(&self) -> Result<(), crate::Error> {
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
            return Err(crate::Error::CliValidation(format!(
                "Output flags ({}) require -N/--no-tui mode (or --call-report)",
                output_flags_used.join(", ")
            )));
        }

        // Phase 8.1 — MCP mode owns stdout (JSON-RPC wire); reject any flag
        // combination that would also try to write to stdout.
        if self.mcp {
            if !self.no_tui {
                return Err(crate::Error::CliValidation(
                    "--mcp implies non-interactive mode; pass -N/--no-tui as well".to_string(),
                ));
            }
            let stdout_flags: Vec<&str> = [
                (self.json, "--json"),
                (self.json_pretty, "--json-pretty"),
                (self.report, "--report"),
                (self.hexdump, "--hexdump"),
                (self.wireshark, "--wireshark"),
                (self.call_report.is_some(), "--call-report"),
                (self.tshark_filter.is_some(), "--tshark-filter"),
            ]
            .iter()
            .filter(|(active, _)| *active)
            .map(|(_, name)| *name)
            .collect();
            if !stdout_flags.is_empty() {
                return Err(crate::Error::CliValidation(format!(
                    "--mcp uses stdout for the JSON-RPC wire and cannot be combined with \
                     stdout-writing flags ({})",
                    stdout_flags.join(", ")
                )));
            }
            // Token + bind validation for non-loopback HTTP transport happens
            // in the http transport module (Phase 8.2); for stdio there is no
            // network surface to validate.
            if self.mcp_transport != "stdio" && self.mcp_transport != "http" {
                return Err(crate::Error::CliValidation(format!(
                    "--mcp-transport must be 'stdio' or 'http', got '{}'",
                    self.mcp_transport
                )));
            }
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
    fn cores_flag_parses() {
        // `--cores N` selects the multi-core offline reconstruction core count.
        let cli = Cli::parse_from_args(["sipnab", "--cores", "4", "-I", "x.pcap"]);
        assert_eq!(cli.cores, 4);
    }

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
        assert_eq!(cli.cores, 1, "single-threaded by default");
        assert_eq!(cli.color, "auto");
        assert!(!cli.no_tui);
        assert!(!cli.setup_caps);
        // Dialog rotation is ON by default (SNB-0004): at --limit capacity the
        // store evicts the oldest dialog rather than dropping new legitimate
        // calls — a privileged sniffer must bound dialog state safely by default.
        assert!(cli.rotate_enabled(), "rotate must default ON");
    }

    #[test]
    fn rotate_defaults_on_and_negation_works() {
        // default: rotate on
        assert!(Cli::parse_from_args(["sipnab"]).rotate_enabled());
        // explicit --rotate / -R: still on (affirms the default, back-compat)
        assert!(Cli::parse_from_args(["sipnab", "--rotate"]).rotate_enabled());
        assert!(Cli::parse_from_args(["sipnab", "-R"]).rotate_enabled());
        // --no-rotate opts out → drop-new-at-capacity
        assert!(!Cli::parse_from_args(["sipnab", "--no-rotate"]).rotate_enabled());
        // last flag wins when both are given
        assert!(!Cli::parse_from_args(["sipnab", "--rotate", "--no-rotate"]).rotate_enabled());
        assert!(Cli::parse_from_args(["sipnab", "--no-rotate", "--rotate"]).rotate_enabled());
    }

    #[test]
    fn setup_caps_flag_parses() {
        let cli = Cli::parse_from_args(["sipnab", "--setup-caps"]);
        assert!(cli.setup_caps);
    }

    #[test]
    fn name_resolution_flags_parse() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "--resolve",
            "--reverse-dns",
            "--names",
            "/etc/hosts",
            "--names",
            "/tmp/names",
        ]);
        assert!(cli.resolve);
        assert!(cli.reverse_dns);
        assert_eq!(
            cli.names,
            vec!["/etc/hosts".to_string(), "/tmp/names".to_string()]
        );
    }

    #[test]
    fn buffer_flags_parse_and_reject_invalid() {
        // Kernel capture buffer (--buffer / -B).
        assert_eq!(
            Cli::parse_from_args(["sipnab", "--buffer", "32"]).buffer,
            Some(32)
        );
        assert_eq!(
            Cli::parse_from_args(["sipnab", "-B", "16"]).buffer,
            Some(16)
        );
        // In-flight queue memory budget (--buffer-budget).
        let cli = Cli::parse_from_args(["sipnab", "--buffer-budget", "128"]);
        assert_eq!(cli.buffer_budget, Some(128));
        assert_eq!(Cli::parse_from_args(["sipnab"]).buffer_budget, None);
        // Non-numeric values are rejected by clap.
        assert!(Cli::try_parse_from(["sipnab", "--buffer-budget", "huge"]).is_err());
        assert!(Cli::try_parse_from(["sipnab", "--buffer", "huge"]).is_err());
    }

    #[test]
    fn from_to_mode_flag_parses_and_rejects_invalid() {
        let cli = Cli::parse_from_args(["sipnab", "--from-to-mode", "host-port"]);
        assert_eq!(cli.from_to_mode, Some(FromToModeArg::HostPort));
        let cli = Cli::parse_from_args(["sipnab", "--from-to-mode", "user-host-port"]);
        assert_eq!(cli.from_to_mode, Some(FromToModeArg::UserHostPort));
        // Absent → None (falls back to config/default).
        assert_eq!(Cli::parse_from_args(["sipnab"]).from_to_mode, None);
        // Invalid value is rejected by clap (I4).
        assert!(Cli::try_parse_from(["sipnab", "--from-to-mode", "bogus"]).is_err());
    }

    #[test]
    fn strip_secrets_flag_parses() {
        let cli =
            Cli::parse_from_args(["sipnab", "-I", "in.pcapng", "--strip-secrets", "out.pcapng"]);
        assert_eq!(cli.strip_secrets.as_deref(), Some("out.pcapng"));
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
        assert!(err.to_string().contains("--json"));
        assert!(err.to_string().contains("--report"));
        assert!(err.to_string().contains("--fail2ban"));
    }
}
