// SPDX-License-Identifier: MIT OR Apache-2.0

//! Command-line argument parsing for sipnab.
//!
//! Uses clap derive to define the full unified flag set, combining sngrep and
//! sipgrep flags along with sipnab-specific additions for security analysis,
//! RTP quality monitoring, and event-driven automation.

use clap::Parser;

/// Value of `--hep-rate-limit-per-peer`: disabled, a fixed cap, or `auto`
/// (derive a fair per-peer cap from the global ceiling and the number of
/// allowed sources at startup).
///
/// Defined here (not in the feature-gated `capture::hep` module) so the
/// always-compiled CLI struct can name it even in builds without the `hep`
/// feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerPeerLimit {
    /// No per-peer cap; only the global ceiling applies.
    Off,
    /// A fixed packets-per-second cap per source IP.
    Fixed(u64),
    /// Derive per-peer = `global / allowlist_len` at startup.
    Auto,
}

impl std::str::FromStr for PerPeerLimit {
    type Err = String;

    /// Parse a `--hep-rate-limit-per-peer` value: `auto`, `off`/`disabled`,
    /// or a packets-per-second number (`0` normalizes to `Off`).
    /// Case-insensitive; surrounding whitespace is ignored.
    ///
    /// # Errors
    /// Any other string yields a descriptive message naming the accepted
    /// forms and echoing the rejected input.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "off" | "disabled" => Ok(Self::Off),
            other => other
                .parse::<u64>()
                .map(|n| if n == 0 { Self::Off } else { Self::Fixed(n) })
                .map_err(|_| format!("expected a number, 'auto', or 'off', got '{s}'")),
        }
    }
}

impl PerPeerLimit {
    /// Resolve a concrete per-peer packets/second cap from the global ceiling
    /// and the number of source-allowlist entries.
    ///
    /// `Auto` divides the global ceiling evenly across the allowed sources so
    /// no single peer can exceed its fair share, flooring at 1 pps — integer
    /// division with more sources than the ceiling would otherwise yield 0,
    /// which means DISABLED and would silently drop the cap. With no
    /// allowlist there is no sender count to divide by, so it stays disabled
    /// (only the global ceiling applies). `Off` yields 0; `Fixed(n)` passes
    /// through.
    pub fn resolve(self, global: u64, allowlist_len: usize) -> u64 {
        match self {
            Self::Off => 0,
            Self::Fixed(n) => n,
            Self::Auto => {
                if allowlist_len == 0 {
                    0
                } else {
                    (global / allowlist_len as u64).max(1)
                }
            }
        }
    }
}

/// Authentication mode for the HEP `0x000e` chunk (`--hep-auth-mode`).
///
/// Defined here (not in the feature-gated `capture::hep` module) so the
/// always-compiled CLI struct can name it even without the `hep` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HepAuthMode {
    /// The chunk carries the shared secret verbatim (Homer-compatible, but
    /// the secret rides in cleartext and is replayable by an on-path sniffer).
    #[default]
    Plain,
    /// The chunk carries a timestamped, per-message HMAC token: resists
    /// on-path replay by binding the payload, a timestamp, and a nonce under
    /// HMAC-SHA256. sipnab-to-sipnab only — a stock Homer/Kamailio sender does
    /// not produce it.
    Hmac,
}

impl std::str::FromStr for HepAuthMode {
    type Err = String;

    /// Parse a `--hep-auth-mode` value: `plain` or `hmac`.
    /// Case-insensitive; surrounding whitespace is ignored.
    ///
    /// # Errors
    /// Any other string yields a message naming the two accepted modes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "hmac" => Ok(Self::Hmac),
            other => Err(format!("expected 'plain' or 'hmac', got '{other}'")),
        }
    }
}

/// Build a version string including git commit hash, optional tag,
/// and the list of compile-time features that were enabled.
///
/// Pure: assembled entirely from compile-time `env!` values baked in by
/// the build script (`SIPNAB_GIT_*`); with no recorded commit it falls
/// back to the bare crate version plus the feature list.
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
/// the `[features]` block in `Cargo.toml`. Returns an empty vector when
/// no listed feature is enabled.
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
    if cfg!(feature = "metrics") {
        out.push("metrics");
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
        sipnab -e 'INVITE sip:'          Grep SIP payload, follow the dialog\n  \
        sipnab 'host 10.0.0.1 and port 5060'   BPF capture filter"
)]
pub struct Cli {
    // ── Capture ──────────────────────────────────────────────────────
    /// Network interface to capture on.
    ///
    /// Omit it and sipnab picks a default, which differs by platform.
    ///
    /// ON LINUX: the "any" pseudo-device, capturing on ALL interfaces at once,
    /// loopback included. SIP proxies frequently talk to themselves over
    /// loopback, so capturing only eth0 would miss that traffic. Promiscuous
    /// mode does not apply to "any". Pass `-d any` to be explicit.
    ///
    /// ON MACOS/BSD: libpcap's default device, chosen from the routing table,
    /// falling back to the first non-loopback interface. That is ONE
    /// interface, not all of them, so name `-d` explicitly if you need another.
    ///
    /// Ignored when `-I` is given: `-I` reads a file and never opens an
    /// interface.
    #[arg(
        help_heading = "Capture",
        short = 'd',
        long = "device",
        value_name = "IFACE"
    )]
    pub device: Option<String>,

    /// Read packets from a capture file, directory, or glob instead of live
    /// capture. Repeatable.
    ///
    /// Files are read in the order their packets were captured, never by
    /// filename — `tcpdump -C -W` writes a ring buffer that wraps, so
    /// `tg.pcap7` can hold older traffic than `tg.pcap0`.
    #[arg(
        help_heading = "Capture",
        short = 'I',
        long = "input",
        value_name = "FILE|DIR|GLOB",
        action = clap::ArgAction::Append
    )]
    pub input: Vec<String>,

    /// Descend into subdirectories when `-I` names a directory.
    ///
    /// Off by default: recursing silently can analyse several times the
    /// traffic you pointed at, and nothing in the output would say so.
    #[arg(help_heading = "Capture", long = "recursive")]
    pub recursive: bool,

    /// Read only files whose name matches this pattern when `-I` names a
    /// directory, e.g. `--input-name 'tg.pcap[0-4]'`.
    ///
    /// Matched against the filename alone, so it behaves the same at every
    /// depth under `--recursive`.
    #[arg(
        help_heading = "Capture",
        long = "input-name",
        value_name = "GLOB",
        requires = "input"
    )]
    pub input_name: Option<String>,

    /// Write captured packets to a pcap file.
    #[arg(
        help_heading = "Capture",
        short = 'O',
        long = "output",
        value_name = "FILE"
    )]
    pub output: Option<String>,

    /// Kernel capture buffer size in MiB (default 64). The ring libpcap fills
    /// and sipnab drains: raise it on busy links, lower it on small hosts or
    /// when capturing many interfaces at once (the cost is per device). See
    /// `docs/tuning-capture.md`.
    #[arg(
        help_heading = "Capture",
        short = 'B',
        long = "buffer",
        value_name = "MIB"
    )]
    pub buffer: Option<u32>,

    /// Memory budget in MiB for the in-flight packet queue between capture and
    /// processing (default 64). The queue grows under load up to this budget and
    /// shrinks when idle; overrides `[capture] buffer_budget_mb`.
    #[arg(help_heading = "Capture", long = "buffer-budget", value_name = "MIB")]
    pub buffer_budget: Option<u32>,

    /// Snapshot length for packet capture (bytes).
    #[arg(help_heading = "Capture", long, value_name = "BYTES")]
    pub snaplen: Option<u32>,

    /// Parse only the first N bytes of each packet (sipgrep -S). Caps what the
    /// SIP parser and matchers inspect, independent of the capture snaplen
    /// (`--snaplen`) and the display truncation (`--payload-limit`).
    #[arg(
        help_heading = "Capture",
        short = 'S',
        long = "limitlen",
        value_name = "BYTES"
    )]
    pub limitlen: Option<usize>,

    /// Disable IP-fragment and TCP-segment reassembly; every packet is parsed
    /// standalone. The inverse of sipgrep's `-a`. Useful for pure single-packet
    /// UDP scanning where reassembly is only overhead.
    #[arg(help_heading = "Capture", long = "no-reassembly")]
    pub no_reassembly: bool,

    /// Quiet bad-parse packets (sipgrep -x): suppress the per-packet
    /// diagnostic emitted when a SIP-looking packet fails to parse. The packet
    /// is dropped either way; this only silences the "SIP parse error" notice
    /// on a noisy link (visible under -v / debug logging).
    #[arg(help_heading = "Capture", short = 'x', long = "quiet-bad-parse")]
    pub quiet_bad_parse: bool,

    /// SIP port range to capture [default: 5060-5061].
    ///
    /// Signalling only — media is never gated, because RTP uses
    /// SDP-negotiated dynamic ports.
    ///
    /// The default is narrow, and SIP on other ports is ordinary: carriers and
    /// SBCs use 5070, 5080 and others routinely. Reading a file, SIP whose
    /// source and destination are both outside the range is skipped, and it
    /// then appears in no message count, no dialog, and no output format. That
    /// used to be silent; sipnab now counts what it skipped and says so,
    /// naming the busiest ports so there is something to widen to. Pass
    /// `--portrange 1-65535` to analyse everything the capture holds.
    ///
    /// Live capture also turns this into the BPF filter when no explicit
    /// filter is given, so there the kernel drops the traffic and nothing
    /// downstream — this counter included — can see it was there.
    ///
    /// An `Option` (not a clap default) so an explicit `--portrange 5060-5061`
    /// still overrides a config-file range.
    #[arg(help_heading = "Capture", long, value_name = "RANGE")]
    pub portrange: Option<String>,

    /// Capture on the selected interfaces given as a comma-separated list to
    /// `-d` (e.g. `-d eth0,docker0 --multi-device`), opening one capture per
    /// interface. Without this flag, the zero-argument default already sniffs
    /// ALL interfaces via the "any" pseudo-device.
    #[arg(help_heading = "Capture", long)]
    pub multi_device: bool,

    /// Disable RTP capture and analysis.
    #[arg(help_heading = "Capture", long)]
    pub no_rtp: bool,

    /// Do not put the interface into promiscuous mode (sipgrep -p). By default
    /// promiscuous mode is enabled for a named device (never for the "any"
    /// pseudo-device, which does not support it).
    #[arg(help_heading = "Capture", short = 'p', long = "no-promisc")]
    pub no_promisc: bool,

    /// Read BPF filter from a file.
    #[arg(help_heading = "Capture", long, value_name = "FILE")]
    pub bpf_file: Option<String>,

    /// Also capture ALL traffic on the UDP tunnel ports, so SIP inside GTP-U,
    /// VXLAN or GENEVE reaches sipnab. Defaults to 2152,4789,6081 when given
    /// with no value; pass a comma-separated list for non-standard ports
    /// (e.g. `--capture-tunnels=8472` for Linux's pre-IANA VXLAN port).
    ///
    /// OFF by default because it is not a narrowing filter: BPF cannot walk a
    /// GTP-U extension-header chain to reach the inner port, so the only way
    /// to cover these is to take everything on the port. On a mobile core or a
    /// data-centre fabric that is the entire user plane. Without it the
    /// auto-generated filter still sees VLAN/QinQ/PPPoE/MPLS-encapsulated SIP,
    /// which cost nothing to add. Ignored when you supply your own filter.
    #[arg(
        help_heading = "Capture",
        long,
        value_name = "PORTS",
        num_args = 0..=1,
        default_missing_value = crate::app::bootstrap::TUNNEL_PORTS_DEFAULT_LIST,
    )]
    pub capture_tunnels: Option<String>,

    /// Stop after receiving N packets. Counts every packet received from the
    /// capture source; for a HEP listener that includes packets later dropped
    /// by the source allowlist, rate limiter, or authentication.
    #[arg(
        help_heading = "Capture",
        short = 'n',
        long = "count",
        value_name = "N"
    )]
    pub count: Option<u64>,

    /// Stop after capturing for this duration (e.g., "30s", "5m", "1h").
    #[arg(help_heading = "Capture", long, value_name = "DURATION")]
    pub duration: Option<String>,

    /// Autostop condition (e.g., "filesize:100", "duration:60").
    #[arg(help_heading = "Capture", long, value_name = "CONDITION")]
    pub autostop: Option<String>,

    /// Split output files (e.g., "filesize:50" for 50 MiB chunks).
    #[arg(help_heading = "Capture", long, value_name = "CONDITION")]
    pub split: Option<String>,

    /// Replay packets from a pcap file at original timing.
    #[arg(help_heading = "Capture", long)]
    pub replay: bool,

    /// Use pcapng format for output files.
    #[arg(help_heading = "Capture", long)]
    pub pcapng: bool,

    // ── Mode ─────────────────────────────────────────────────────────
    /// Non-interactive mode (no TUI). Required for batch/output flags.
    #[arg(help_heading = "Mode", short = 'N', long = "no-tui")]
    pub no_tui: bool,

    /// Show only SIP dialogs (calls), not standalone messages.
    #[arg(help_heading = "Mode", short = 'c', long = "calls-only")]
    pub calls_only: bool,

    /// Compatibility no-op (sngrep -r flag).
    #[arg(help_heading = "Mode", short = 'r', hide = true)]
    pub _sngrep_r: bool,

    /// Decode telephone-event (DTMF) RTP payloads and log each event, with the
    /// digit VALUE masked as `x`.
    ///
    /// One `info` line per completed event carries everything an operator
    /// diagnoses with — that a digit arrived, its duration, its SSRC, its time —
    /// and withholds the value, because on live traffic those values are PINs,
    /// calling-card numbers, account numbers and card numbers. Pass
    /// `--dtmf-cleartext` to log the values themselves.
    ///
    /// The masked lines go to the log at `info`, so `-N` shows them and the TUI
    /// does not (TUI mode floors the level at `error` to protect the alternate
    /// screen). `--quiet` floors it at `warn` and hides them too. No report,
    /// JSON field or MCP tool carries the digits — only the count is retained.
    #[arg(help_heading = "Mode", short = 't', long = "telephone-event")]
    pub telephone_event: bool,

    /// Log decoded DTMF digit VALUES in cleartext, not masked. Off by default.
    ///
    /// This publishes the caller's keypresses. After answer, DTMF digits are
    /// routinely voicemail PINs, calling-card numbers, account numbers and
    /// credit-card numbers with their CVVs, and they arrive in the clear no
    /// matter how the signalling was protected. Everyone who can read this
    /// run's log can read them: the terminal, the redirected file, journald,
    /// and whatever log aggregator ships them onward.
    ///
    /// Needs `-t` (it only affects what `-t` decodes) and `SIPNAB_LOG=debug`:
    /// the cleartext line is emitted at `debug`, one level below the masked
    /// `info` line, so it never appears in a default-level log. The masked line
    /// is still emitted, so nothing is lost by leaving this off.
    #[arg(help_heading = "Mode", long = "dtmf-cleartext")]
    pub dtmf_cleartext: bool,

    /// Suppress informational output; only show results.
    #[arg(help_heading = "Mode", short = 'q', long = "quiet")]
    pub quiet: bool,

    // ── Name resolution ──────────────────────────────────────────────
    /// Resolve IP addresses to names for display (manual mappings + hosts).
    /// Sets the TUI's initial name-resolution mode; press `n` to cycle it
    /// (Off / Static / DNS).
    #[arg(help_heading = "Name resolution", long = "resolve")]
    pub resolve: bool,

    /// Also use reverse DNS (PTR) lookups for name resolution. Implies
    /// `--resolve`. Off by default (it emits DNS queries for captured IPs).
    #[arg(help_heading = "Name resolution", long = "reverse-dns")]
    pub reverse_dns: bool,

    /// Load IP -> name mappings from an `/etc/hosts`-format file. Repeatable.
    #[arg(help_heading = "Name resolution", long = "names", value_name = "FILE")]
    pub names: Vec<String>,

    /// Default From/To column display mode in the TUI. Cycled at runtime with
    /// the `u` key. Overrides the `[display] from_to` config value.
    #[arg(
        help_heading = "Name resolution",
        long = "from-to-mode",
        value_enum,
        value_name = "MODE"
    )]
    pub from_to_mode: Option<FromToModeArg>,

    /// Write a copy of the input pcapng (`-I`) to this path with all decryption
    /// secrets (DSBs) removed, then exit. The input is never modified.
    ///
    /// `-I` must resolve to exactly ONE capture. A directory or glob naming a
    /// single file is fine; a set is refused, because this flag names one
    /// output path and a set has nowhere to go. Stripping only the first would
    /// hand over the rest with their keys intact while reporting success.
    #[arg(
        help_heading = "Name resolution",
        long = "strip-secrets",
        value_name = "OUTPUT"
    )]
    pub strip_secrets: Option<String>,

    /// Resolve a frame pointer emitted by a previous run and print that frame,
    /// then exit. Takes `<source>#<ordinal>` or `<source>#<ordinal>@<digest>`,
    /// the form carried by the `frame` field of `--json-dialogs`, `--report`,
    /// the REST API and MCP.
    ///
    /// With a digest, the frame's bytes are checked against it: a capture that
    /// was rotated, truncated or recompressed since the pointer was made is
    /// REFUSED rather than answered with whatever now sits at that position.
    /// Without one — the form a human types — the frame is printed and marked
    /// UNVERIFIED, because there is nothing to check it against.
    #[arg(
        help_heading = "Name resolution",
        long = "show-frame",
        value_name = "POINTER"
    )]
    pub show_frame: Option<String>,

    // ── Matching ─────────────────────────────────────────────────────
    /// SIP payload match-expression (the sngrep/sipgrep positional match
    /// expression). A regex tested against the whole raw SIP message; once any
    /// message in a dialog matches, every later message of that dialog is shown
    /// too (dialog-following). Honors -i/-v/-w/--single-line. Separate from the
    /// trailing BPF filter positional.
    #[arg(
        help_heading = "Matching",
        short = 'e',
        long = "match",
        value_name = "PATTERN"
    )]
    pub match_expr: Option<String>,

    /// Case-insensitive matching for header filters and patterns.
    #[arg(help_heading = "Matching", short = 'i', long = "ignore-case")]
    pub ignore_case: bool,

    /// Invert the match: show messages that do NOT match.
    #[arg(help_heading = "Matching", short = 'v', long = "invert")]
    pub invert: bool,

    /// Match whole words only.
    #[arg(help_heading = "Matching", short = 'w', long = "word")]
    pub word: bool,

    /// Treat multi-line SIP headers as a single line for matching.
    #[arg(help_heading = "Matching", long)]
    pub single_line: bool,

    /// Filter by SIP From header (regex pattern).
    #[arg(help_heading = "Matching", long, value_name = "PATTERN")]
    pub from: Option<String>,

    /// Filter by SIP To header (regex pattern).
    #[arg(help_heading = "Matching", long, value_name = "PATTERN")]
    pub to: Option<String>,

    /// Filter by SIP Contact header (regex pattern).
    #[arg(help_heading = "Matching", long, value_name = "PATTERN")]
    pub contact: Option<String>,

    /// Filter by User-Agent header (regex pattern).
    #[arg(help_heading = "Matching", long, value_name = "PATTERN")]
    pub ua: Option<String>,

    /// Filter DSL expression OR a diagnostic alias. Accepts full
    /// expressions (e.g. "method == 'INVITE' and rtp.mos < 3.5") and
    /// alias names like "problems" or "codec-asym" — see
    /// docs/filter-dsl.md.
    #[arg(help_heading = "Matching", long, value_name = "EXPR")]
    pub filter: Option<String>,

    // ── Diagnostic aliases ───────────────────────────────────────────
    /// Show calls with detected problems (retransmits, timeouts, errors).
    #[arg(help_heading = "Diagnostic aliases", long)]
    pub problems: bool,

    /// Show calls with slow setup time (>3s by default).
    #[arg(help_heading = "Diagnostic aliases", long)]
    pub slow_setup: bool,

    /// Show calls shorter than 5 seconds.
    #[arg(help_heading = "Diagnostic aliases", long)]
    pub short_calls: bool,

    /// Show calls with potential one-way audio issues.
    #[arg(help_heading = "Diagnostic aliases", long)]
    pub one_way: bool,

    /// Show calls whose RTP arrived from an address no SDP in the dialog
    /// advertised — the signature of a NAT rewriting the media source.
    #[arg(help_heading = "Diagnostic aliases", long)]
    pub nat_issues: bool,

    // ── Output ───────────────────────────────────────────────────────
    /// Output NDJSON: one JSON object per SIP message, pipeable to jq.
    /// Schema in docs/output-formats.md.
    #[arg(help_heading = "Output", long)]
    pub json: bool,

    /// Output results as pretty-printed JSON.
    #[arg(help_heading = "Output", long)]
    pub json_pretty: bool,

    /// Output NDJSON: one JSON object per DIALOG, emitted after capture.
    ///
    /// `--json` is per message; this is per call. Use it when the question is
    /// "which calls failed and why" rather than "what did the wire carry" —
    /// the per-message stream makes you join `status_code` back to `call_id`
    /// yourself, and a filter like `state == 'Failed'` selects dialogs while
    /// `--json` then emits every message of them, provisional responses
    /// included. Same object the REST API returns per dialog, one line each.
    #[arg(help_heading = "Output", long)]
    pub json_dialogs: bool,

    /// Load a WASM plugin that adds its own dialog detections. Repeatable.
    ///
    /// A plugin is a sandboxed pure function from one dialog to zero or more
    /// findings, which then render beside the built-in ones. It runs with no
    /// imports at all — no filesystem, no network, no clock — so it cannot
    /// reach anything outside the bytes it is handed.
    ///
    /// Loading a plugin is still a trust decision: it sees the dialog's
    /// headers, credentials included, and can copy them into a finding that
    /// prints. Treat a `.wasm` the way you would treat a patch.
    ///
    /// See `docs/design/wasm-plugin-api.md` for the ABI and a worked example.
    #[cfg(feature = "plugins")]
    #[arg(help_heading = "Output", long, value_name = "PATH")]
    pub plugin: Vec<std::path::PathBuf>,

    /// Generate a summary report after capture completes.
    #[arg(help_heading = "Output", long)]
    pub report: bool,

    /// Generate a detailed report for a specific Call-ID.
    #[arg(help_heading = "Output", long, value_name = "CALL-ID")]
    pub call_report: Option<String>,

    /// Format report output as Markdown.
    #[arg(help_heading = "Output", long)]
    pub markdown: bool,

    /// Include hex dump of SIP payloads.
    #[arg(help_heading = "Output", long)]
    pub hexdump: bool,

    /// Show delta time between consecutive messages.
    #[arg(help_heading = "Output", long)]
    pub delta_time: bool,

    /// Show N messages after each match (like grep -A).
    #[arg(help_heading = "Output", short = 'A', long = "after", value_name = "N")]
    pub after: Option<usize>,

    /// Show the full header block of messages that have no body (responses,
    /// OPTIONS, REGISTER, ACK, BYE, ...). Without this, bodyless messages show
    /// only their one-line summary; messages that carry a body always show
    /// their full detail.
    #[arg(help_heading = "Output", long, visible_alias = "full")]
    pub show_empty: bool,

    /// Annotate the transport tag with the IANA IP protocol number, e.g.
    /// `UDP(17)` / `TCP(6)` (sipgrep -N). `-N` itself is `--no-tui` here, so
    /// this flag is long-only. TLS/WS report their TCP carrier's number (6).
    #[arg(help_heading = "Output", long = "proto-number")]
    pub proto_number: bool,

    /// Flush output after each line (useful for piping).
    #[arg(help_heading = "Output", long)]
    pub line_buffer: bool,

    /// Color output mode.
    ///
    /// Accepts only `auto`, `always`, or `never`; any other value is rejected
    /// at parse time (rather than silently falling back to `auto` downstream).
    ///
    /// Deliberately has NO clap `default_value`, for the reason given on
    /// `--mcp-max-rows`: a default fills this field whether or not the operator
    /// typed the flag, so "not given" and "given the default" become
    /// indistinguishable and `[display] color` has nothing to override. That is
    /// exactly why that key was silently ignored. The default lives in
    /// [`Self::DEFAULT_COLOR`] and is applied by [`Self::color_mode`].
    #[arg(
        help_heading = "Output",
        long,
        value_name = "WHEN",
        value_parser = clap::builder::PossibleValuesParser::new(["auto", "always", "never"])
    )]
    pub color: Option<String>,

    /// Maximum payload bytes to display.
    #[arg(help_heading = "Output", long, value_name = "BYTES")]
    pub payload_limit: Option<usize>,

    /// Dump raw SIP message text (like sipgrep -T).
    #[arg(help_heading = "Output", short = 'T', long = "text-dump")]
    pub text_dump: bool,

    /// Suppress the per-message stream (reports still print). Combine
    /// with --report or --call-report for summary-only output:
    /// `sipnab -N -I file.pcap --report --no-cli-print`.
    #[arg(help_heading = "Output", long = "no-cli-print")]
    pub no_cli_print: bool,

    /// Launch Wireshark with a display filter for the current capture.
    #[arg(help_heading = "Output", long)]
    pub wireshark: bool,

    /// Run the RFC conformance linter over every dialog and print the findings.
    ///
    /// Informational on its own: it changes what is printed, never the exit
    /// code. Pair it with `--lint-fail-on` to make a pipeline stop.
    ///
    /// The linter reads what the capture actually contains against what the
    /// cited RFC section calls for, so a finding names a section rather than
    /// an opinion. `sipnab --help-rules` is not a thing; the catalogue is in
    /// docs/sip-lint-rules.md and over MCP as `explain_rule`.
    #[arg(help_heading = "Output", long)]
    pub lint: bool,

    /// Exit 3 when the linter reports a finding at or above this severity.
    ///
    /// This is the CI gate: `sipnab -I calls.pcap --lint --lint-fail-on error`
    /// fails the build on a non-conformant capture and says which rule and
    /// which RFC section.
    ///
    /// Exit 3 is deliberately NOT 1 or 2. A pipeline has to tell three things
    /// apart: sipnab broke (1), the invocation was wrong (2), and the CAPTURE
    /// is non-conformant (3). Collapsing the third into the first would make a
    /// failing gate indistinguishable from a failing tool, and the usual
    /// response to those differs completely.
    ///
    /// `info` is accepted and pointless — that severity exists for findings
    /// that are never a reason to fail a build.
    #[arg(
        help_heading = "Output",
        long = "lint-fail-on",
        value_name = "SEVERITY",
        requires = "lint"
    )]
    pub lint_fail_on: Option<String>,

    /// Findings one lint rule may report for one dialog.
    ///
    /// A dialog that retransmits an `INVITE` eleven times trips a message rule
    /// eleven times and every one of them is true, so the cap is what decides
    /// whether the other rules stay readable underneath. Config:
    /// `[limits] lint_max_per_rule`.
    #[arg(
        help_heading = "Output",
        long = "lint-max-per-rule",
        value_name = "N",
        requires = "lint"
    )]
    pub lint_max_per_rule: Option<u64>,

    /// Generate a tshark-compatible display filter string.
    #[arg(help_heading = "Output", long, value_name = "EXPR")]
    pub tshark_filter: Option<String>,

    /// Output in fail2ban-compatible format for SIP security events.
    #[arg(help_heading = "Output", long)]
    pub fail2ban: bool,

    /// Group batch output so messages sharing a field value are emitted
    /// together: one of `call-id`, `from`, `to`, `method`, `src`, `dst`.
    /// Messages are reordered, not reformatted, so `--json` output stays one
    /// valid object per line. Requires `-N`/`--no-tui`, and buffers until the
    /// capture ends (bounded — see `output::group`).
    #[arg(help_heading = "Output", long, value_name = "FIELD")]
    pub group_by: Option<String>,

    /// Distinct `--group-by` keys one run may retain (default 10000). Config:
    /// `[limits] max_groups`.
    ///
    /// Past it the buffer refuses new keys and warns that the output is
    /// incomplete — honest, and until now unfixable: `-l`/`--limit` bounds
    /// tracked dialogs and never reached this map.
    #[arg(
        help_heading = "Output",
        long = "max-groups",
        value_name = "N",
        requires = "group_by",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_groups: Option<u64>,

    /// Messages `--group-by` may buffer across every group (default 200000).
    /// Config: `[limits] max_grouped_messages`.
    ///
    /// The other half of `--max-groups`, and a different question: that one
    /// bounds how many groups exist, this one how much rendered output they
    /// hold between them. Grouping cannot stream — the last packet may belong
    /// to the first group — so this is memory held until the capture ends.
    #[arg(
        help_heading = "Output",
        long = "max-grouped-messages",
        value_name = "N",
        requires = "group_by",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_grouped_messages: Option<u64>,

    // ── Dialog ───────────────────────────────────────────────────────
    /// Maximum dialogs the store may hold in TOTAL over the run (default
    /// 100000). NOT a concurrency limit: nothing removes a completed dialog,
    /// so this bound scales with UPTIME, not with load.
    ///
    /// This help used to say "track simultaneously", which is the reading an
    /// operator wants and not the behaviour that exists. A box carrying five
    /// concurrent calls still evicts once 100,000 calls have COMPLETED, and
    /// eviction drops the OLDEST dialogs — the worst ones to lose for a
    /// post-mortem. A multi-file set feeds one store, so a 27-file directory
    /// reaches the cap 27x sooner than one file (#64).
    ///
    /// Completed dialogs are retained on purpose: `--report` and
    /// `--call-report` answer about calls that already ended, and evicting
    /// them on completion would break exactly the after-the-fact analysis
    /// sipnab exists for. Whether the right fix is a separate retention window
    /// for completed dialogs, a time-based bound, or something else is the
    /// retention umbrella's decision (#160), not this flag's.
    ///
    /// The eviction count IS reported wherever a dialog count appears (#68),
    /// so a run that hits this says so rather than quietly answering from a
    /// truncated store.
    #[arg(help_heading = "Dialog", short = 'l', long = "limit", value_name = "N")]
    pub limit: Option<u64>,

    /// Evict the oldest dialog when the `--limit` capacity is reached (LRU).
    /// This is the **default**; the flag is kept for back-compat / explicitness.
    #[arg(
        help_heading = "Dialog",
        short = 'R',
        long = "rotate",
        overrides_with = "no_rotate"
    )]
    pub rotate: bool,

    /// Disable dialog rotation: at `--limit` capacity, drop *new* dialogs instead
    /// of evicting the oldest. Inverts the safe default (which rotates) — only use
    /// when you must preserve the earliest dialogs and accept losing newer ones.
    #[arg(help_heading = "Dialog", long = "no-rotate", overrides_with = "rotate")]
    pub no_rotate: bool,

    /// How to group messages into tracked units: `call-id` (default, one unit
    /// per dialog) or `branch` (one unit per SIP transaction).
    ///
    /// `branch` is for captures where one Call-ID is reused across many
    /// transactions — load generators, proxies under test. Note that a single
    /// call yields SEVERAL units under `branch`: RFC 3261 gives the ACK to a
    /// 2xx a new branch and the BYE another. That is the transaction view, not
    /// a miscount.
    #[arg(help_heading = "Dialog", long, value_name = "METHOD", value_parser = parse_dialog_track)]
    pub dialog_track: Option<crate::sip::dialog_store::DialogTracking>,

    /// Disable dialog tracking entirely (message-only mode).
    #[arg(help_heading = "Dialog", long)]
    pub no_dialog: bool,

    /// Filter dialogs by tag value.
    #[arg(help_heading = "Dialog", long, value_name = "TAG")]
    pub tag: Option<String>,

    // ── RTP ──────────────────────────────────────────────────────────
    /// Accepted and ignored: periodic RTP statistics reporting is not built.
    ///
    /// The flag stays so an existing invocation keeps working, and sipnab warns
    /// when you pass a value, because the alternative is a runbook that quietly
    /// reports nothing. See docs/cli-reference.md.
    #[arg(help_heading = "RTP", long, value_name = "SECS", default_value = "1")]
    pub rtp_interval: u32,

    /// Maximum number of RTP streams to track simultaneously.
    #[arg(help_heading = "RTP", long, value_name = "N")]
    pub max_streams: Option<u64>,

    /// Lost RTP sequence numbers retained per stream, for the Packet Loss Map
    /// and the burst/gap analysis. Config: `[limits] max_lost_sequences`.
    ///
    /// The shipped 1000 is about a minute of a call losing 1 % at 50 packets a
    /// second, so on the half-hour call an operator actually escalates the map
    /// shows the tail and says so. Raising it costs two bytes per retained
    /// loss per stream, and widens the burst/gap window in step.
    ///
    /// No clap `default_value`, for the reason given on
    /// [`Self::mcp_max_rows`]: a populated field cannot tell "not typed" from
    /// "typed the default". The default lives in
    /// [`crate::rtp::stream::DEFAULT_LOST_SEQ_LOG_CAP`].
    #[arg(
        help_heading = "RTP",
        long = "max-lost-sequences",
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_lost_sequences: Option<u64>,

    /// MOS quality threshold for alerts (1.0-5.0 scale).
    #[arg(help_heading = "RTP", long, value_name = "MOS", default_value = "3.0")]
    pub quality_threshold: f64,

    // ── Security ─────────────────────────────────────────────────────
    /// Detect and report SIP scanning activity.
    #[arg(help_heading = "Security", long)]
    pub kill_scanner: bool,

    /// Detect specific User-Agent strings associated with scanners.
    #[arg(help_heading = "Security", long, value_name = "PATTERN")]
    pub kill_ua: Option<String>,

    /// SIP response code to use in scanner kill reports.
    ///
    /// No clap `default_value`, for the reason given on `--color`: it made
    /// `[security] kill_response` unreachable. The range check stays — dropping
    /// the default must not drop the validation. Default in
    /// [`Self::DEFAULT_KILL_RESPONSE`], applied by [`Self::kill_response_code`].
    #[arg(help_heading = "Security", long, value_name = "CODE", value_parser = clap::value_parser!(u16).range(100..=699))]
    pub kill_response: Option<u16>,

    /// Targeted scanner kill (sipgrep -K): send the kill response to any SIP
    /// request whose source matches ADDR and an optional port range, e.g.
    /// `10.0.0.1:5060-5090` or `[::1]:5060`, regardless of UA/behavioral
    /// detection. Repeatable. Spawns the kill worker on its own; `--kill-scanner`
    /// is not required.
    #[arg(
        help_heading = "Security",
        short = 'K',
        long = "kill-target",
        value_name = "ADDR[:PORT-RANGE]"
    )]
    pub kill_target: Vec<String>,

    /// How to source the scanner-kill response packet (Linux only; other
    /// platforms always use `ephemeral`). `auto` forges the victim's ip:port
    /// via a raw socket when `CAP_NET_RAW` is available (already granted for
    /// live capture), so the reply appears to come from the port the scanner
    /// targeted — falling back to an ephemeral UDP source otherwise. `raw`
    /// requires the spoof and errors if the raw socket cannot be opened;
    /// `ephemeral` never spoofs.
    #[arg(
        help_heading = "Security",
        long = "kill-spoof",
        value_name = "MODE",
        value_enum,
        default_value = "auto"
    )]
    pub kill_spoof: KillSpoof,

    /// Allow scanner-kill to send active responses for packets received via
    /// the HEP listener. OFF by default: a HEP sender asserts the inner
    /// src/dst addresses, so absent `--hep-auth` an attacker could aim the
    /// kill response at a victim of their choosing (SN-01). Only enable when
    /// HEP input is authenticated and trusted.
    #[arg(help_heading = "Security", long = "hep-allow-kill")]
    pub hep_allow_kill: bool,

    /// Enable fraud detection heuristics.
    #[arg(help_heading = "Security", long)]
    pub fraud_detect: bool,

    /// Detect registration flood attacks.
    #[arg(help_heading = "Security", long)]
    pub reg_flood: bool,

    /// REGISTER requests per second from one source before `--reg-flood`
    /// reports a flood.
    ///
    /// No clap `default_value`, so `[security] reg_flood_threshold` can take
    /// effect; the default lives in [`Self::DEFAULT_REG_FLOOD_THRESHOLD`] and
    /// is applied by [`Self::reg_flood_threshold`].
    ///
    /// The shipped 50/s is a carrier-registrar figure: it never sees the
    /// ten-a-second brute force a small PBX gets, and it fires all through a
    /// re-REGISTER storm on a registrar recovering from a restart. The right
    /// value is a property of the registrar being watched.
    #[arg(
        help_heading = "Security",
        long = "reg-flood-threshold",
        value_name = "N"
    )]
    pub reg_flood_threshold: Option<u32>,

    /// Scanner-kill responses per second sipnab may put on the wire.
    ///
    /// This is the blast radius of the one feature that TRANSMITS. The kill
    /// path answers packets whose source address the sender chose, so every
    /// response is aimed by somebody else; the cap is what keeps a misfiring
    /// signature from becoming a reflector. There is no unlimited setting and
    /// `0` is refused — see `[security] kill_rate_limit`.
    ///
    /// A per-destination cap of 3/minute applies underneath this and is not
    /// tunable, so raising this widens how many DISTINCT hosts may be answered
    /// per second, never how hard any one of them is hit.
    ///
    /// The `range(1..)` is what makes the sentence above true of THIS flag.
    /// `[security] kill_rate_limit` refuses 0 in `SecurityConfig::validate`,
    /// but that guards the config FILE; without this the flag accepted 0 while
    /// its own doc comment said it was refused. Two spellings of one policy
    /// that disagree, with the documentation describing whichever one the
    /// reader is not using.
    #[arg(
        help_heading = "Security",
        long = "kill-rate-limit",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub kill_rate_limit: Option<u32>,

    /// Business hours as `START-END` in whole UTC hours, e.g. `8-18`.
    ///
    /// Turns on the off-hours fraud detection, which is otherwise unreachable:
    /// with no window declared there is no "outside" for a call to fall in.
    /// A wrapping range (`22-6`) is the overnight window.
    ///
    /// Requires `--fraud-detect`, which is what runs the detector.
    #[arg(
        help_heading = "Security",
        long = "business-hours",
        value_name = "START-END"
    )]
    pub business_hours: Option<String>,

    /// Measured call duration, in seconds, below which `--fraud-detect` counts
    /// a completed call as "short" for wangiri detection.
    #[arg(
        help_heading = "Security",
        long = "fraud-short-call",
        value_name = "SECS"
    )]
    pub fraud_short_call_secs: Option<u64>,

    /// Short calls to one destination prefix before `--fraud-detect` reports
    /// wangiri.
    #[arg(
        help_heading = "Security",
        long = "fraud-wangiri-calls",
        value_name = "N"
    )]
    pub fraud_wangiri_calls: Option<u32>,

    /// Consecutive refused numbers before `--fraud-detect` reports sequential
    /// scanning.
    #[arg(
        help_heading = "Security",
        long = "fraud-sequential-calls",
        value_name = "N"
    )]
    pub fraud_sequential_calls: Option<u64>,

    /// Multiple of a source's own baseline call rate that `--fraud-detect`
    /// reports as a volume spike.
    #[arg(
        help_heading = "Security",
        long = "fraud-volume-multiplier",
        value_name = "N"
    )]
    pub fraud_volume_multiplier: Option<u32>,

    /// Calls a source must place inside the volume window before
    /// `--fraud-detect` will report a spike at all.
    #[arg(
        help_heading = "Security",
        long = "fraud-volume-min-calls",
        value_name = "N"
    )]
    pub fraud_volume_min_calls: Option<u32>,

    /// Probes from one source inside the scanner window, above which
    /// `--kill-scanner` reports a rate detection.
    ///
    /// Behind an SBC every source collapses to one address, so ordinary
    /// aggregated traffic clears the shipped ten in five seconds and the whole
    /// site is reported as one scanner.
    ///
    /// `range(1..)` because `0` reports the first probe of any kind; the
    /// matching `[security] scanner_behavioral_probes` refuses `0` too, so the
    /// file cannot be the lenient way in.
    #[arg(
        help_heading = "Security",
        long = "scanner-behavioral-probes",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub scanner_behavioral_probes: Option<u32>,

    /// Distinct target extensions from one source inside the scanner window,
    /// above which `--kill-scanner` reports extension enumeration.
    #[arg(
        help_heading = "Security",
        long = "scanner-enumeration-targets",
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub scanner_enumeration_targets: Option<u64>,

    /// Rejected probes inside the scanner window at which a source reads as
    /// probing rather than operating.
    ///
    /// This is the evidence gate, not a rate: neither behavioural signal
    /// reports anything until a source clears this or
    /// `--scanner-unanswered-probes`, which is what separates an enumeration
    /// sweep from a trunk running keepalives at the same rate.
    #[arg(
        help_heading = "Security",
        long = "scanner-rejected-probes",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub scanner_rejected_probes: Option<u32>,

    /// Unanswered probes inside the scanner window at which a source reads as
    /// sweeping, provided they are also the majority of what it sent.
    #[arg(
        help_heading = "Security",
        long = "scanner-unanswered-probes",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub scanner_unanswered_probes: Option<u32>,

    /// How much capture time one scanner window spans, in seconds.
    ///
    /// Every scanner count is "per window", so this is the binding constraint
    /// on a paced sweep rather than the counts: one probe every ten seconds
    /// never puts two probes inside the shipped five-second window, so the rate
    /// and the spread both stay at one however low the counts go.
    #[arg(
        help_heading = "Security",
        long = "scanner-window",
        value_name = "SECS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub scanner_window_secs: Option<u64>,

    /// How much more evidence `--kill-scanner` needs from a source that has
    /// completed a registration or a call with us.
    ///
    /// A registered endpoint that starts probing is a compromised phone and is
    /// worth reporting, but it is also the peer whose ordinary traffic looks
    /// most like probing and the peer a false positive costs most.
    #[arg(
        help_heading = "Security",
        long = "scanner-established-factor",
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub scanner_established_factor: Option<u32>,

    /// How long a probe may go without a response before `--kill-scanner`
    /// counts it as unanswered, in milliseconds.
    ///
    /// The shipped 500 is RFC 3261's Timer T1, the round-trip estimate at which
    /// SIP itself gives up waiting and retransmits. Raise it on a link whose
    /// round trip is longer than that; without any grace, "unanswered" means
    /// "not answered YET" and a client that pipelines faster than the round
    /// trip reads as a sweep into a hole.
    #[arg(
        help_heading = "Security",
        long = "scanner-answer-grace",
        value_name = "MS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub scanner_answer_grace_ms: Option<u64>,

    /// Security findings kept in memory for later retrieval.
    ///
    /// `0` keeps none. Findings are the deduplicated record of what fired, so
    /// an agent polling for them sees at most this many between polls.
    #[arg(help_heading = "Security", long = "findings-history", value_name = "N")]
    pub findings_history: Option<u64>,

    /// Detect digest credential leaks in SIP messages.
    #[arg(help_heading = "Security", long)]
    pub digest_leak: bool,

    /// Alert channels (repeatable: "syslog", "json", "exec").
    #[arg(help_heading = "Security", long, value_name = "CHANNEL")]
    pub alert: Vec<String>,

    /// Execute this command when an alert fires.
    #[arg(help_heading = "Security", long, value_name = "CMD")]
    pub alert_exec: Option<String>,

    /// Report STIR/SHAKEN Identity claims (no signature verification).
    ///
    /// Decodes the RFC 8224 Identity header's PASSporT and reports the
    /// attestation level, the originating and destination numbers, and the
    /// origination ID.
    ///
    /// It does NOT verify the signature. Doing so means fetching the
    /// certificate the token references and checking the signature over it,
    /// and sipnab makes no outbound request to analyse a capture. The one
    /// check applied locally is `iat` freshness (RFC 8224 Section 4.4), which
    /// reports `Expired`.
    ///
    /// So an attestation of `A` here means the originator CLAIMED full
    /// attestation, not that anything confirmed the claim. A forged Identity
    /// header reports exactly like a genuine one. Do not treat this flag's
    /// output as grounds for trusting a calling number.
    #[arg(help_heading = "Security", long)]
    pub stir_shaken: bool,

    // ── Event execution ──────────────────────────────────────────────
    /// Execute command when a dialog state changes.
    #[arg(help_heading = "Event execution", long, value_name = "CMD")]
    pub on_dialog_exec: Option<String>,

    /// Execute command when RTP quality drops below threshold.
    #[arg(help_heading = "Event execution", long, value_name = "CMD")]
    pub on_quality_exec: Option<String>,

    /// Maximum exec invocations per second (rate limit).
    #[arg(
        help_heading = "Event execution",
        long,
        value_name = "N",
        default_value = "10"
    )]
    pub exec_rate_limit: u32,

    // ── Network listeners ────────────────────────────────────────────
    /// Enable Prometheus metrics endpoint (e.g., "127.0.0.1:9090"). A
    /// non-loopback bind (e.g. "0.0.0.0:9090") is refused unless
    /// --metrics-auth / --metrics-auth-file is also set.
    #[arg(help_heading = "Network listeners", long, value_name = "ADDR")]
    pub metrics: Option<String>,

    /// HTTP Basic auth credentials (`user:pass`) required by the metrics
    /// endpoint. When set, requests must send `Authorization: Basic <base64>`.
    /// Prefer --metrics-auth-file so the secret is not visible in the process
    /// list. Basic credentials are base64-encoded, not encrypted: terminate
    /// TLS upstream for non-loopback exposure.
    #[arg(help_heading = "Network listeners", long, value_name = "USER:PASS")]
    pub metrics_auth: Option<String>,

    /// Read the metrics Basic-auth `user:pass` from a file (contents trimmed),
    /// keeping the secret out of the process list. Takes precedence over
    /// --metrics-auth when both are set.
    #[arg(help_heading = "Network listeners", long, value_name = "FILE")]
    pub metrics_auth_file: Option<std::path::PathBuf>,

    /// Enable REST API endpoint (e.g., "0.0.0.0:8080").
    #[arg(help_heading = "Network listeners", long, value_name = "ADDR")]
    pub api: Option<String>,

    /// API key for REST API authentication (static shared secret, no expiry).
    #[arg(
        help_heading = "Network listeners",
        long,
        value_name = "KEY",
        env = "SIPNAB_API_KEY"
    )]
    pub api_key: Option<String>,

    /// HMAC signing key for REST API self-describing bearer tokens
    /// (repeatable). The FIRST key mints; ALL keys are accepted on verify,
    /// enabling signing-key rotation with overlap. Also read from
    /// SIPNAB_API_SIGNING_KEY.
    #[arg(
        help_heading = "Network listeners",
        long = "api-signing-key",
        value_name = "KEY",
        env = "SIPNAB_API_SIGNING_KEY"
    )]
    pub api_signing_key: Vec<String>,

    /// Read one REST API HMAC signing key from a file (contents trimmed).
    /// Prepended to any --api-signing-key values so it is the minting key.
    #[arg(
        help_heading = "Network listeners",
        long = "api-signing-key-file",
        value_name = "FILE"
    )]
    pub api_signing_key_file: Option<String>,

    /// Revocation denylist file for REST API tokens: one revoked token id per
    /// line (blanks and `#` comments ignored). Reloaded when the file changes.
    #[arg(
        help_heading = "Network listeners",
        long = "api-revoked-file",
        value_name = "FILE"
    )]
    pub api_revoked_file: Option<String>,

    /// TTL in seconds for a minted REST API token (used with --mint-token).
    #[arg(
        help_heading = "Network listeners",
        long = "api-token-ttl",
        value_name = "SECS",
        default_value = "3600"
    )]
    pub api_token_ttl: i64,

    /// TLS certificate for API endpoint.
    #[arg(help_heading = "Network listeners", long, value_name = "FILE")]
    pub api_tls_cert: Option<String>,

    /// TLS private key for API endpoint.
    #[arg(help_heading = "Network listeners", long, value_name = "FILE")]
    pub api_tls_key: Option<String>,

    /// Maximum concurrent API connections.
    #[arg(
        help_heading = "Network listeners",
        long,
        value_name = "N",
        default_value = "100"
    )]
    pub api_max_conn: u32,

    // ── MCP (Model Context Protocol) ──────────────────────────────────
    /// Run sipnab as an MCP server (Model Context Protocol) instead of TUI/CLI.
    /// Implies --no-tui. Default transport is stdio; --mcp-transport selects
    /// http (requires the mcp-http feature).
    #[arg(help_heading = "MCP (Model Context Protocol)", long)]
    pub mcp: bool,

    /// MCP transport: "stdio" (default) or "http".
    ///
    /// Accepts only `stdio` or `http`; any other value is rejected at parse
    /// time (previously an unrecognized transport passed parse silently and was
    /// only caught later, and only when `--mcp` was also set).
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-transport",
        value_name = "TRANSPORT",
        default_value = "stdio",
        value_parser = clap::builder::PossibleValuesParser::new(["stdio", "http"])
    )]
    pub mcp_transport: String,

    /// Bind address for the HTTP MCP transport (default 127.0.0.1:8731).
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-bind",
        value_name = "ADDR"
    )]
    pub mcp_bind: Option<String>,

    /// Bearer token for HTTP MCP transport. Reads from env SIPNAB_MCP_TOKEN
    /// when not given via the flag; required for non-loopback binds.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-token",
        value_name = "TOKEN",
        env = "SIPNAB_MCP_TOKEN"
    )]
    pub mcp_token: Option<String>,

    /// Read the MCP bearer token from a file (preferred over env in
    /// systemd units).
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-token-file",
        value_name = "FILE"
    )]
    pub mcp_token_file: Option<String>,

    /// HMAC signing key for HTTP MCP self-describing bearer tokens
    /// (repeatable). The FIRST key mints; ALL keys are accepted on verify,
    /// enabling signing-key rotation with overlap. Also read from
    /// SIPNAB_MCP_SIGNING_KEY.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-signing-key",
        value_name = "KEY",
        env = "SIPNAB_MCP_SIGNING_KEY"
    )]
    pub mcp_signing_key: Vec<String>,

    /// Read one HTTP MCP HMAC signing key from a file (contents trimmed).
    /// Prepended to any --mcp-signing-key values so it is the minting key.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-signing-key-file",
        value_name = "FILE"
    )]
    pub mcp_signing_key_file: Option<String>,

    /// Revocation denylist file for HTTP MCP tokens: one revoked token id per
    /// line (blanks and `#` comments ignored). Reloaded when the file changes.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-revoked-file",
        value_name = "FILE"
    )]
    pub mcp_revoked_file: Option<String>,

    /// TTL in seconds for a minted HTTP MCP token (used with --mint-token).
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-token-ttl",
        value_name = "SECS",
        default_value = "3600"
    )]
    pub mcp_token_ttl: i64,

    /// Maximum tool calls the MCP server runs at once (`0` = unlimited).
    ///
    /// A call that cannot take a slot immediately is refused with a
    /// retry-shortly error, not queued: queueing an unbounded backlog behind
    /// the cap is the resource exhaustion the cap exists to prevent. The
    /// default mirrors `--api-max-conn`; it bounds a flooding client without
    /// impeding an agent's ordinary handful of parallel calls. Applies to both
    /// stdio and HTTP servers, though a network-exposed HTTP server is the case
    /// it matters for.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-max-concurrent",
        value_name = "N",
        default_value = "100"
    )]
    pub mcp_max_concurrent: u32,

    /// One-way network delay of the observed path, in milliseconds.
    ///
    /// The one MOS input a passive tap cannot measure. Declaring it beats an
    /// RTCP-reported round trip, which an unauthenticated packet can move; see
    /// [`crate::rtp::quality::DelaySource`]. No clap `default_value`, for the
    /// reason given on `--mcp-max-rows`.
    #[arg(help_heading = "Analysis", long = "one-way-delay", value_name = "MS")]
    pub one_way_delay_ms: Option<f64>,

    /// Post-dial delay, in seconds, over which a call is reported as slow.
    ///
    /// The default is ITU-T E.721's 95th-percentile target for an
    /// INTERNATIONAL connection, because a capture does not say what kind of
    /// call it holds. A network that knows its own traffic is local or toll
    /// wants a tighter number (6.0 and 8.0 respectively). Config:
    /// `[diagnosis] post_dial_delay_secs`.
    #[arg(help_heading = "Analysis", long = "pdd-threshold", value_name = "SECS")]
    pub pdd_threshold_secs: Option<f64>,

    /// Seconds a `2xx` may go unacknowledged before the missing `ACK` is
    /// reported as a fault rather than as a capture that stopped early.
    /// Default: RFC 3261 Timer H (32 s). Config:
    /// `[diagnosis] ack_timeout_secs`.
    #[arg(help_heading = "Analysis", long = "ack-timeout", value_name = "SECS")]
    pub ack_timeout_secs: Option<f64>,

    /// Seconds an `INVITE` may sit without a final response before the silence
    /// is reported. Default: RFC 3261 Timer C (180 s). Below it, every call
    /// still ringing when the capture stopped is reported. Config:
    /// `[diagnosis] no_final_response_secs`.
    #[arg(
        help_heading = "Analysis",
        long = "no-final-response-timeout",
        value_name = "SECS"
    )]
    pub no_final_response_secs: Option<f64>,

    /// Percentage difference between the two legs' durations that counts as
    /// asymmetric. Config: `[diagnosis] duration_asymmetry_pct`.
    #[arg(
        help_heading = "Analysis",
        long = "duration-asymmetry-pct",
        value_name = "PCT"
    )]
    pub duration_asymmetry_pct: Option<f64>,

    /// Absolute difference, in seconds, between the two legs' durations that
    /// counts as asymmetric. Both this and the percentage must be exceeded,
    /// so raising either one alone quiets the detection. Config:
    /// `[diagnosis] duration_asymmetry_secs`.
    #[arg(
        help_heading = "Analysis",
        long = "duration-asymmetry-secs",
        value_name = "SECS"
    )]
    pub duration_asymmetry_secs: Option<f64>,

    /// Milliseconds after the `200 OK` that media may start before it is
    /// reported as late. Config: `[diagnosis] late_media_ms`.
    #[arg(help_heading = "Analysis", long = "late-media-ms", value_name = "MS")]
    pub late_media_ms: Option<i64>,

    /// Jitter, in milliseconds, at or above which the colour column turns
    /// yellow. Config: `[quality] jitter_warn_ms`.
    ///
    /// None of the eight quality flags carries a clap `default_value`, for the
    /// reason spelled out on [`Self::mcp_max_rows`]: a populated field cannot
    /// tell "not typed" from "typed the default", and its config key would
    /// have nothing left to override.
    #[arg(help_heading = "Analysis", long = "jitter-warn-ms", value_name = "MS")]
    pub jitter_warn_ms: Option<f64>,

    /// Jitter, in milliseconds, at or above which the colour column turns red.
    /// Config: `[quality] jitter_bad_ms`.
    #[arg(help_heading = "Analysis", long = "jitter-bad-ms", value_name = "MS")]
    pub jitter_bad_ms: Option<f64>,

    /// Packet loss, in percent, at or above which the colour column turns
    /// yellow. Config: `[quality] loss_warn_pct`.
    #[arg(help_heading = "Analysis", long = "loss-warn-pct", value_name = "PCT")]
    pub loss_warn_pct: Option<f64>,

    /// Packet loss, in percent, at or above which the colour column turns red.
    /// Config: `[quality] loss_bad_pct`.
    #[arg(help_heading = "Analysis", long = "loss-bad-pct", value_name = "PCT")]
    pub loss_bad_pct: Option<f64>,

    /// MOS below which the colour column turns yellow. MOS bands run downward,
    /// so this must sit at or above `--mos-bad`. Config: `[quality] mos_warn`.
    #[arg(help_heading = "Analysis", long = "mos-warn", value_name = "MOS")]
    pub mos_warn: Option<f64>,

    /// MOS below which the colour column turns red.
    /// Config: `[quality] mos_bad`.
    #[arg(help_heading = "Analysis", long = "mos-bad", value_name = "MOS")]
    pub mos_bad: Option<f64>,

    /// Round trip, in milliseconds, at or above which the colour column turns
    /// yellow. Config: `[quality] rtt_warn_ms`.
    #[arg(help_heading = "Analysis", long = "rtt-warn-ms", value_name = "MS")]
    pub rtt_warn_ms: Option<f64>,

    /// Round trip, in milliseconds, at or above which the colour column turns
    /// red. Config: `[quality] rtt_bad_ms`.
    #[arg(help_heading = "Analysis", long = "rtt-bad-ms", value_name = "MS")]
    pub rtt_bad_ms: Option<f64>,

    /// Maximum rows in one list-style MCP response.
    ///
    /// Deliberately has NO clap `default_value`: that is what made
    /// `[display] color` and `[security] kill_response` unreachable from
    /// config — clap fills the field whether or not the operator typed the
    /// flag, so "not given" and "given the default" become indistinguishable
    /// and the config key has nothing to override. The default lives in
    /// [`Self::DEFAULT_MCP_MAX_ROWS`] and is applied by
    /// [`Self::mcp_row_cap`].
    ///
    /// The right ceiling belongs to the CONSUMER, not to sipnab: an agent with
    /// a small context window wants far fewer than 1000 rows and a batch
    /// consumer piping to a file wants far more.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-max-rows",
        value_name = "N"
    )]
    pub mcp_max_rows: Option<u64>,

    /// Maximum bytes of SIP body or matched snippet in one MCP response.
    ///
    /// `--mcp-max-rows` for the WIDTH of a row rather than their number, and
    /// the tighter of the two on a body question: a caller may ask for one
    /// dialog and still be answered with a clipped `INVITE`. An SDP body
    /// carrying a dozen codecs and ICE candidates passes the 4096-byte
    /// default, and the agent reading the clipped half cannot tell a truncated
    /// answer from a short one.
    ///
    /// No clap `default_value`, for the reason given on
    /// [`Self::mcp_max_rows`]. The default lives in
    /// [`crate::mcp::shape::DEFAULT_MAX_BODY_BYTES`].
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-max-body-bytes",
        value_name = "N",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub mcp_max_body_bytes: Option<u64>,

    /// Maximum MCP tool calls one peer may make per second (`0` = unlimited).
    ///
    /// The other half of `--mcp-max-concurrent`, and a different question:
    /// that one bounds calls IN FLIGHT, this one bounds their ARRIVAL RATE. An
    /// agent that never exceeds the concurrency cap and simply loops as fast
    /// as it is answered is unbounded under the cap alone — it holds one slot
    /// at a time and asks again the moment it is free. A call over this cap is
    /// refused with the same retry-shortly error the concurrency cap returns,
    /// never queued.
    ///
    /// A peer is the source IP over HTTP (the address, not the socket, so
    /// reconnecting does not mint a fresh allowance) and the pipe itself over
    /// stdio. The per-peer accounting is shared with
    /// `--hep-rate-limit-per-peer`, which meters HEP packets the same way.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-rate-limit-per-peer",
        value_name = "N",
        default_value = "100"
    )]
    pub mcp_rate_limit_per_peer: u32,

    /// Additional `Host` header values the HTTP MCP server will accept
    /// (repeatable). rmcp's DNS-rebind protection defaults to allowing
    /// only `localhost`, `127.0.0.1`, and `::1`. Add the public hostname
    /// or bind IP here when clients connect via that name. Use `*` to
    /// disable host checking entirely (not recommended; pair the
    /// resulting open binding with a network-level allowlist).
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-allowed-host",
        value_name = "HOST"
    )]
    pub mcp_allowed_host: Vec<String>,

    /// Directory the MCP file tools may read from and write to.
    ///
    /// `export_capture`, `export_audio` and `list_captures` are all confined to
    /// this directory and refuse to run without it. They take a FILENAME, never
    /// a path: anything containing a separator, a `..`, or an absolute prefix
    /// is rejected before touching the filesystem.
    ///
    /// That is the whole security model, and it is deliberately not
    /// negotiable. An agent-supplied path is an arbitrary file write wearing a
    /// feature's clothes — `export_capture(path="/etc/cron.d/x")` is a remote
    /// code execution primitive, not an export. Naming one directory means the
    /// worst an agent can do is fill it.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-file-root",
        value_name = "DIR"
    )]
    pub mcp_file_root: Option<String>,

    /// Allow the `shutdown_server` MCP tool to stop this process.
    ///
    /// Off by default, so a stock server cannot be stopped by an agent. Even
    /// when on, the tool defaults to a dry run and refuses to discard an
    /// unsaved live capture unless the caller asks for that explicitly.
    ///
    /// An LLM drives this surface. It should not be able to end a capture an
    /// operator is depending on because it read "we can stop looking at this
    /// now" as an instruction.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-allow-shutdown"
    )]
    pub mcp_allow_shutdown: bool,

    /// Retain RTP audio payload in memory so the `export_audio` MCP tool can
    /// decode it.
    ///
    /// Off by default: call audio is content, not signalling, and holding it
    /// should be a decision an operator makes rather than a side effect of
    /// enabling an MCP server. Without this flag `export_audio` refuses and
    /// its refusal says retention was off for the run — a capture setting,
    /// not a finding that the call was silent.
    ///
    /// Costs a per-packet payload clone and buffers up to `[limits]
    /// max_audio_frames` frames (default 1500) per stream across at most
    /// `--max-streams` streams. Requires --mcp, because the MCP server is the
    /// only batch-mode consumer that can read the buffers back — retaining
    /// without it would spend the memory on audio nothing in the run can
    /// reach.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "retain-audio",
        requires = "mcp"
    )]
    pub retain_audio: bool,

    /// Allow the `open_capture` MCP tool to load a different capture.
    ///
    /// Off by default, so a stock server holds the capture it was started on.
    /// The tool reads only files inside `--mcp-file-root`, refuses while the
    /// current source is a live interface or is still being read, and mints a
    /// new capture identity that every later answer carries — so a swap cannot
    /// reach a consumer as an ordinary update.
    ///
    /// It still discards the analysis an operator may be reading. Enable it on
    /// a long-lived server working through a corpus; leave it off where a
    /// restart with a different `-I` costs nothing.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-allow-open-capture"
    )]
    pub mcp_allow_open_capture: bool,

    /// Name this box reports as, on every answer it gives.
    ///
    /// Defaults to the system hostname. It appears in `capture_identity.node`
    /// on every MCP and REST response, so an agent querying an SBC and two
    /// PBXes at once can tell WHICH of them saw a given fact — "answered with
    /// 407" is an incomplete finding until you know where.
    ///
    /// Distinct from the capture instance, which rotates when a different
    /// capture is loaded. The node is the box and stays put, so a capture
    /// restart does not read as a topology change.
    ///
    /// NOTE: the default puts your hostname on the wire, which is usually
    /// wanted and occasionally not. Set this to override it. Clipped to 64
    /// characters.
    #[arg(help_heading = "Output", long = "node-name", value_name = "NAME")]
    pub node_name: Option<String>,

    /// Permit the `save_findings` MCP tool to record an agent's conclusion.
    ///
    /// The ONLY write verb on sipnab's whole network surface, and off by
    /// default because its caller is a language model reading text an attacker
    /// may have put on the wire. What makes it safe is not that the text is
    /// trustworthy: it is that the write reaches nothing. A finding goes to the
    /// log and is readable by no tool, appears in no query result, and feeds no
    /// analysis, so it cannot come back as evidence in a later answer.
    ///
    /// Bounded at 1000 findings per process, after which writes are REFUSED
    /// rather than silently dropped — that bound exists to keep an agent in a
    /// loop from filling the operator's journal.
    #[arg(
        help_heading = "MCP (Model Context Protocol)",
        long = "mcp-allow-save-findings"
    )]
    pub mcp_allow_save_findings: bool,

    // ── HEP (Homer Encapsulation Protocol) ───────────────────────────
    /// Listen for HEP (Homer Encapsulation Protocol) packets.
    #[arg(
        help_heading = "HEP",
        short = 'L',
        long = "hep-listen",
        value_name = "ADDR"
    )]
    pub hep_listen: Option<String>,

    /// Send captured packets via HEP to a remote collector.
    #[arg(
        help_heading = "HEP",
        short = 'H',
        long = "hep-send",
        value_name = "ADDR"
    )]
    pub hep_send: Option<String>,

    /// Capture-agent id (HEP 0x000c chunk) stamped on every packet sent via
    /// `--hep-send`. Distinguishes this agent to the Homer collector. Default 1.
    #[arg(help_heading = "HEP", long = "hep-id", value_name = "ID")]
    pub hep_id: Option<u32>,

    /// Homer authenticate key (HEP 0x000e chunk) added to every packet sent via
    /// `--hep-send`. Prefer the env var over the flag so the secret is not
    /// visible in the process list.
    #[arg(
        help_heading = "HEP",
        long = "hep-auth",
        value_name = "KEY",
        env = "SIPNAB_HEP_AUTH"
    )]
    pub hep_auth: Option<String>,

    /// Read the HEP shared secret from a file (contents trimmed), keeping it
    /// out of the process list. Takes precedence over --hep-auth. When set on
    /// a `--hep-listen` receiver it ENABLES receiver-side authentication:
    /// incoming HEP packets must carry a matching 0x000e auth-key chunk or
    /// they are dropped.
    #[arg(help_heading = "HEP", long = "hep-auth-file", value_name = "FILE")]
    pub hep_auth_file: Option<std::path::PathBuf>,

    /// HEP authentication mode: `plain` (default) sends/expects the shared
    /// secret verbatim in the 0x000e chunk (Homer-compatible, but replayable
    /// by an on-path sniffer); `hmac` sends/expects a per-message HMAC token
    /// (timestamp + nonce + HMAC-SHA256 over the payload) that resists replay.
    /// `hmac` is sipnab-to-sipnab only — a stock Homer/Kamailio peer will not
    /// understand it.
    #[arg(
        help_heading = "HEP",
        long = "hep-auth-mode",
        value_name = "plain|hmac",
        default_value = "plain"
    )]
    pub hep_auth_mode: HepAuthMode,

    /// Parse incoming HEP packets (enable HEP decoding).
    #[arg(help_heading = "HEP", short = 'E', long = "hep-parse")]
    pub hep_parse: bool,

    /// Allowed source addresses for HEP input (repeatable).
    #[arg(help_heading = "HEP", long, value_name = "ADDR")]
    pub hep_allow: Vec<String>,

    /// Maximum HEP packets per second (global ceiling across all senders).
    /// `0` disables the global ceiling (consistent with `off` on the
    /// per-peer knob); the per-peer cap, if set, still applies.
    #[arg(help_heading = "HEP", long, value_name = "N")]
    pub hep_rate_limit: Option<u64>,

    /// Maximum HEP packets per second from any single source IP: a number,
    /// `off` (0, the default), or `auto`. Adds fairness in multi-sender
    /// deployments so one flooding peer cannot consume the whole
    /// --hep-rate-limit allowance and starve others. `auto` divides the
    /// global ceiling evenly across the --hep-allow sources (disabled when no
    /// allowlist is set). Leave at `off` for the common single-collector
    /// topology.
    #[arg(
        help_heading = "HEP",
        long,
        value_name = "N|auto|off",
        default_value = "off"
    )]
    pub hep_rate_limit_per_peer: PerPeerLimit,

    // ── Alert channels (grouped with --alert / --alert-exec under Security) ──
    /// Send alerts to syslog.
    #[arg(help_heading = "Security", long)]
    pub syslog: bool,

    /// Emit each security alert as a structured JSON line on stderr (in addition
    /// to the human `[ALERT]` line) — a stable machine channel that survives log
    /// format changes. stdout stays reserved for `--json` / MCP.
    #[arg(help_heading = "Security", long)]
    pub alert_json: bool,

    // ── TLS / Decryption ─────────────────────────────────────────────
    /// TLS private key (PEM) for TLS 1.2 RSA-key-exchange decryption. Only
    /// non-PFS RSA handshakes; ECDHE/DHE (forward secrecy) need --keylog.
    #[arg(
        help_heading = "TLS / Decryption",
        short = 'k',
        long = "tls-key",
        value_name = "FILE"
    )]
    pub tls_key: Option<String>,

    /// TLS key log file (NSS SSLKEYLOGFILE format).
    #[arg(help_heading = "TLS / Decryption", long, value_name = "FILE")]
    pub keylog: Option<String>,

    /// Watch key log file for new entries (live decryption).
    #[arg(help_heading = "TLS / Decryption", long)]
    pub keylog_watch: bool,

    /// DTLS key log (NSS SSLKEYLOGFILE): extracts SRTP keys from DTLS-SRTP
    /// handshakes via the RFC 5764 exporter (AES-CM profiles).
    #[arg(help_heading = "TLS / Decryption", long, value_name = "FILE")]
    pub dtls_keylog: Option<String>,

    /// SRTP master-keys file for media decryption (AES-CM, RFC 3711). Also
    /// honors SDES `a=crypto` keys learned from SDP.
    #[arg(help_heading = "TLS / Decryption", long, value_name = "FILE")]
    pub srtp_keys: Option<String>,

    /// Pcap export mode for encrypted traffic.
    ///
    /// Accepts only `decrypted`, `encrypted+dsb`, or `raw`; any other value is
    /// rejected at parse time (rather than late in bootstrap validation).
    #[arg(
        help_heading = "TLS / Decryption",
        long,
        value_name = "MODE",
        default_value = "decrypted",
        value_parser =
            clap::builder::PossibleValuesParser::new(["decrypted", "encrypted+dsb", "raw"])
    )]
    pub pcap_export_mode: String,

    /// Allow core dumps (do not call prctl to disable).
    #[arg(help_heading = "TLS / Decryption", long)]
    pub allow_coredump: bool,

    // ── Privilege ────────────────────────────────────────────────────
    /// Drop privileges to this user after opening capture devices.
    #[arg(help_heading = "Privilege", long, value_name = "USER")]
    pub user: Option<String>,

    /// Do not drop privileges after opening capture devices.
    #[arg(help_heading = "Privilege", long)]
    pub no_priv_drop: bool,

    /// Chroot to this directory after initialization.
    #[arg(help_heading = "Privilege", long, value_name = "DIR")]
    pub chroot: Option<String>,

    /// Grant this binary the Linux capabilities needed for live capture
    /// (`cap_net_raw,cap_net_admin+ep` via setcap) so it can run without
    /// sudo, then exit. Re-invokes itself through sudo when not already root.
    #[arg(help_heading = "Privilege", long = "setup-caps")]
    pub setup_caps: bool,

    // ── Resource limits ──────────────────────────────────────────────
    /// Maximum concurrent TCP/TLS reassembly sessions.
    #[arg(help_heading = "Resource limits", long, value_name = "N")]
    pub max_reassembly: Option<u64>,

    /// Bytes of pcapng sipnab reads into memory for embedded names and TLS
    /// secrets (default 2 GiB). Config: `[limits] max_metadata_file_bytes`.
    ///
    /// A `tcpdump -C` or `dumpcap -b` ring member routinely passes the default
    /// on a host with the RAM to spare, and the refusal is fatal. Raising it
    /// lets ONE file claim that much memory — twice over while
    /// `--strip-secrets` writes its copy — on nothing but a file size, before
    /// sipnab can tell the file is a capture at all. Raise it for captures you
    /// produced, not for one that arrived from outside.
    #[arg(
        help_heading = "Resource limits",
        long = "max-metadata-file-bytes",
        value_name = "BYTES",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_metadata_file_bytes: Option<u64>,

    /// Bytes a gzip-compressed capture may inflate to (default 1 GiB). Config:
    /// `[limits] max_gunzip_bytes`.
    ///
    /// The documented workaround for the refusal — gunzip the file and open
    /// the plain one — costs the disk the compression was saving, which is why
    /// this moves. It bounds what sipnab inflates itself: the embedded names
    /// and TLS secrets in a `.pcapng.gz`, the copy `--strip-secrets` rewrites,
    /// and the whole capture in the browser build. A `-I capture.pcap.gz`
    /// packet stream is inflated by libpcap and is not bounded by this.
    ///
    /// It is a gzip-bomb guard: inflation stops one byte past the cap, so
    /// raising it to N lets a few kilobytes claim N bytes of RAM. Raise it for
    /// archives you compressed yourself.
    #[arg(
        help_heading = "Resource limits",
        long = "max-gunzip-bytes",
        value_name = "BYTES",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_gunzip_bytes: Option<u64>,

    /// CPU cores for OFFLINE pcap reconstruction (`-I`). 1 = the standard
    /// single-threaded path. >1 shards packets by host pair across N worker
    /// threads for multi-core throughput on large captures; covers dialog +
    /// RTP-stream reconstruction and `--report`/`--json`. Advanced features
    /// (live capture, per-message output ordering, security detectors, SRTP
    /// decrypt) use the single-threaded path regardless.
    #[arg(
        help_heading = "Resource limits",
        long,
        value_name = "N",
        default_value = "1"
    )]
    pub cores: usize,

    // ── Token minting ────────────────────────────────────────────────
    /// Mint a signed bearer token from the first configured signing key,
    /// print it to stdout, and exit. TTL comes from --api-token-ttl (or
    /// --mcp-token-ttl); id from --token-id (or auto-derived). Does NOT start
    /// capture or any server.
    #[arg(help_heading = "Token minting", long = "mint-token")]
    pub mint_token: bool,

    /// Token id (jti) for --mint-token. Defaults to a derived unique id.
    #[arg(help_heading = "Token minting", long = "token-id", value_name = "ID")]
    pub token_id: Option<String>,

    /// Scope for --mint-token: `full` (default), `metrics`, or `read`.
    ///
    /// A `metrics` token reaches `GET /metrics` and nothing else — mint one for
    /// a scrape job rather than handing it a credential that also reads
    /// /v1/dialogs and the message bodies underneath. REST API tokens only.
    ///
    /// A `read` token reaches the MCP tools annotated read-only and nothing
    /// else — mint one for a diagnostic agent rather than handing it a
    /// credential that can also stop the server, export files, or repoint the
    /// capture. MCP tokens only.
    #[arg(
        help_heading = "Token minting",
        long = "token-scope",
        value_name = "SCOPE",
        default_value = "full",
        value_parser = ["full", "metrics", "read"]
    )]
    pub token_scope: String,

    // ── Config ───────────────────────────────────────────────────────
    /// Path to configuration file.
    #[arg(
        help_heading = "Config",
        short = 'f',
        long = "config",
        value_name = "FILE"
    )]
    pub config: Option<String>,

    /// Skip loading any configuration file.
    #[arg(help_heading = "Config", short = 'F', long = "no-config")]
    pub no_config: bool,

    /// Dump the effective configuration and exit.
    #[arg(help_heading = "Config", short = 'D', long = "dump-config")]
    pub dump_config: bool,

    /// Panic immediately after startup (crash-handling self-test: verifies
    /// the `[crash]` report/backtrace/core policy end to end).
    #[arg(help_heading = "Config", long = "panic-selftest", hide = true)]
    pub panic_selftest: bool,

    /// Generate a shell completion script on stdout and exit.
    /// Example: `sipnab --completions bash > /etc/bash_completion.d/sipnab`.
    #[arg(help_heading = "Config", long = "completions", value_name = "SHELL")]
    pub completions: Option<clap_complete::Shell>,

    // ── Positional ───────────────────────────────────────────────────
    /// BPF display filter expression (trailing positional arguments).
    #[arg(trailing_var_arg = true, value_name = "BPF_FILTER")]
    pub bpf_filter: Vec<String>,
}

/// Source-address strategy for the scanner-kill response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum KillSpoof {
    /// Spoof the victim's ip:port via a raw socket when `CAP_NET_RAW` is
    /// available, else fall back to an ephemeral UDP source.
    #[default]
    Auto,
    /// Require raw-socket spoofing; error if it cannot be opened.
    Raw,
    /// Never spoof; always send from an ephemeral UDP source.
    Ephemeral,
}

/// From/To column display mode selectable on the command line.
///
/// clap renders the variants in kebab-case (`default`, `host-port`, `user`,
/// `user-host-port`), matching the `[display] from_to` config spellings and
/// `tui::FromToMode::as_config_str`. Variant semantics mirror
/// `tui::FromToMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FromToModeArg {
    /// Username if present, else `host[:port]`.
    Default,
    /// `host[:port]` only.
    HostPort,
    /// Username only (the legacy behavior).
    User,
    /// `user@host:port` when both exist, else whichever exists.
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
    /// Built-in caps, used when neither the CLI nor `[limits]` names one.
    ///
    /// These were `default_value` attributes on the flags themselves, which is
    /// why `[limits]` could never take effect: clap filled the field in
    /// whether or not the operator passed anything, so "not given" and "given
    /// the default" were indistinguishable and the config key had nothing to
    /// override. The flags are now `Option`, and the default lives here.
    pub const DEFAULT_DIALOG_LIMIT: u64 = 100_000;
    /// Default RTP stream table cap — see [`Self::DEFAULT_DIALOG_LIMIT`].
    pub const DEFAULT_MAX_STREAMS: u64 = 50_000;
    /// Default TCP reassembly session cap — see [`Self::DEFAULT_DIALOG_LIMIT`].
    pub const DEFAULT_MAX_REASSEMBLY: u64 = 10_000;
    /// Default MCP response row ceiling — see [`Self::DEFAULT_DIALOG_LIMIT`].
    pub const DEFAULT_MCP_MAX_ROWS: u64 = 1_000;
    /// Default MCP body/snippet ceiling, in bytes — see
    /// [`Self::DEFAULT_DIALOG_LIMIT`].
    ///
    /// The number lives here rather than in `mcp::shape` because this module
    /// is compiled into every native build while that one is not, so a single
    /// definition can serve both — `mcp::shape::DEFAULT_MAX_BODY_BYTES` reads
    /// it from here.
    pub const DEFAULT_MCP_MAX_BODY_BYTES: u64 = 4_096;
    /// Default colour mode. `auto` means "colour when stdout is a terminal".
    pub const DEFAULT_COLOR: &'static str = "auto";
    /// Default scanner-kill response code. `200 OK` is the sipgrep default: it
    /// ends the scan without telling the scanner anything about the target.
    pub const DEFAULT_KILL_RESPONSE: u16 = 200;
    /// Default HEP global ingest ceiling — see [`Self::DEFAULT_DIALOG_LIMIT`].
    pub const DEFAULT_HEP_RATE_LIMIT: u64 = 50_000;
    /// Default registration-flood threshold, in REGISTER/s from one source.
    pub const DEFAULT_REG_FLOOD_THRESHOLD: u32 = 50;
    /// Default ceiling on scanner-kill responses per second.
    ///
    /// Ten, and deliberately small: this bounds packets sipnab TRANSMITS in
    /// reply to packets an attacker sent, so the failure it guards is sipnab
    /// becoming a reflector aimed at whoever the attacker forged as the
    /// source. The same figure as `--exec-rate-limit`, so an operator who has
    /// tuned one has tuned their intuition for the other.
    pub const DEFAULT_KILL_RATE_LIMIT: u32 = 10;
    /// Default cap on findings one lint rule may report for one dialog.
    pub const DEFAULT_LINT_MAX_PER_RULE: u64 = 25;
    /// Default number of security findings held in memory.
    pub const DEFAULT_FINDINGS_HISTORY: u64 = 1_000;

    /// Dialog cap: `--limit`, else `[limits] dialog_limit`, else the default.
    ///
    /// The explicit flag wins because it is the more specific instruction —
    /// the same precedence the boolean settings use (`cli.no_rtp ||
    /// config.capture.no_rtp`), stated here because a numeric setting cannot
    /// express it with an `||`.
    #[must_use]
    pub fn dialog_limit(&self, config: &crate::config::Config) -> usize {
        self.limit
            .or(config.limits.dialog_limit)
            .unwrap_or(Self::DEFAULT_DIALOG_LIMIT) as usize
    }

    /// Declared one-way delay: `--one-way-delay`, else `[media] one_way_delay_ms`.
    ///
    /// `None` means the operator declared nothing, which is DIFFERENT from
    /// declaring the default — the resolver then falls back to what the far
    /// end reported, and only then to the assumption.
    #[must_use]
    pub fn declared_one_way_delay_ms(&self, config: &crate::config::Config) -> Option<f64> {
        self.one_way_delay_ms.or(config.media.one_way_delay_ms)
    }

    /// MCP response ceiling: `--mcp-max-rows`, else `[limits] mcp_max_rows`,
    /// else the default. See [`Self::dialog_limit`] for the precedence rule.
    ///
    /// Bounds rows in ONE list-style MCP response. Unrelated to
    /// [`Self::dialog_limit`], which bounds dialogs tracked over the whole run
    /// and defaults 100x higher -- the two are confused often enough that the
    /// difference is worth stating here.
    #[must_use]
    pub fn mcp_row_cap(&self, config: &crate::config::Config) -> usize {
        self.mcp_max_rows
            .or(config.limits.mcp_max_rows)
            .unwrap_or(Self::DEFAULT_MCP_MAX_ROWS) as usize
    }

    /// MCP body/snippet ceiling: `--mcp-max-body-bytes`, else
    /// `[limits] mcp_max_body_bytes`, else the default. See
    /// [`Self::dialog_limit`] for the precedence rule.
    ///
    /// Bounds the WIDTH of a row where [`Self::mcp_row_cap`] bounds their
    /// number. A caller can always ask for fewer rows; nothing it can send
    /// widens one, which is why this needed an operator setting more than the
    /// row cap did.
    #[must_use]
    pub fn mcp_body_cap(&self, config: &crate::config::Config) -> usize {
        self.mcp_max_body_bytes
            .or(config.limits.mcp_max_body_bytes)
            .unwrap_or(Self::DEFAULT_MCP_MAX_BODY_BYTES) as usize
    }

    /// Per-stream loss-log retention: `--max-lost-sequences`, else
    /// `[limits] max_lost_sequences`, else the shipped default. See
    /// [`Self::dialog_limit`] for the precedence rule.
    ///
    /// The default is sourced from
    /// [`crate::rtp::stream::DEFAULT_LOST_SEQ_LOG_CAP`] rather than restated,
    /// so the shipped figure has one definition and the resolver cannot
    /// disagree with the code it feeds.
    #[must_use]
    pub fn lost_sequence_log_cap(&self, config: &crate::config::Config) -> usize {
        self.max_lost_sequences
            .or(config.limits.max_lost_sequences)
            .map_or(crate::rtp::stream::DEFAULT_LOST_SEQ_LOG_CAP, |v| v as usize)
    }

    /// `--group-by` caps: the flags, else `[limits] max_groups` /
    /// `max_grouped_messages`, else the shipped pair.
    ///
    /// Resolved as a PAIR because that is how `GroupBuffer` consumes them, and
    /// a resolver per cap is a resolver a call site can half-apply.
    #[must_use]
    pub fn group_caps(&self, config: &crate::config::Config) -> crate::output::group::GroupCaps {
        let shipped = crate::output::group::GroupCaps::default();
        crate::output::group::GroupCaps {
            groups: self
                .max_groups
                .or(config.limits.max_groups)
                .map_or(shipped.groups, |v| v as usize),
            buffered: self
                .max_grouped_messages
                .or(config.limits.max_grouped_messages)
                .map_or(shipped.buffered, |v| v as usize),
        }
    }

    /// In-memory pcapng ceiling: `--max-metadata-file-bytes`, else
    /// `[limits] max_metadata_file_bytes`, else the shipped default.
    ///
    /// A memory-exhaustion guard, so the shipped default stays where it is and
    /// raising it is the operator's declaration that they trust the file. See
    /// [`crate::capture::pcapng_meta::DEFAULT_MAX_METADATA_FILE_BYTES`] for
    /// what that exposes.
    #[must_use]
    pub fn metadata_file_byte_cap(&self, config: &crate::config::Config) -> u64 {
        self.max_metadata_file_bytes
            .or(config.limits.max_metadata_file_bytes)
            .unwrap_or(crate::capture::pcapng_meta::DEFAULT_MAX_METADATA_FILE_BYTES)
    }

    /// Gzip inflation ceiling: `--max-gunzip-bytes`, else
    /// `[limits] max_gunzip_bytes`, else the shipped default.
    ///
    /// A gzip-bomb guard, on the same terms as
    /// [`Self::metadata_file_byte_cap`] — see
    /// [`crate::capture::pcap_reader::DEFAULT_MAX_GUNZIP_BYTES`].
    #[must_use]
    pub fn gunzip_byte_cap(&self, config: &crate::config::Config) -> u64 {
        self.max_gunzip_bytes
            .or(config.limits.max_gunzip_bytes)
            .unwrap_or(crate::capture::pcap_reader::DEFAULT_MAX_GUNZIP_BYTES)
    }

    /// Colour mode: `--color`, else `[display] color`, else the default.
    ///
    /// Both this and [`Self::kill_response_code`] exist because the flags used
    /// to carry a clap `default_value`, which made their config keys dead —
    /// the field was already populated, so there was nothing left to override.
    #[must_use]
    pub fn color_mode(&self, config: &crate::config::Config) -> String {
        self.color
            .clone()
            .or_else(|| config.display.color.clone())
            .unwrap_or_else(|| Self::DEFAULT_COLOR.to_string())
    }

    /// Scanner-kill response code: `--kill-response`, else
    /// `[security] kill_response`, else the default.
    ///
    /// A config value outside 100..=699 is refused by
    /// [`crate::config::Config::validate`] rather than clamped here — the flag
    /// is range-checked by clap, and the key must not be the lenient way in.
    #[must_use]
    pub fn kill_response_code(&self, config: &crate::config::Config) -> u16 {
        self.kill_response
            .or(config.security.kill_response)
            .unwrap_or(Self::DEFAULT_KILL_RESPONSE)
    }

    /// RTP stream cap: `--max-streams`, else `[limits] max_streams`, else the
    /// default. See [`Self::dialog_limit`] for the precedence rule.
    #[must_use]
    pub fn max_streams_limit(&self, config: &crate::config::Config) -> usize {
        self.max_streams
            .or(config.limits.max_streams)
            .unwrap_or(Self::DEFAULT_MAX_STREAMS) as usize
    }

    /// TCP reassembly cap: `--max-reassembly`, else `[limits] max_reassembly`,
    /// else the default. See [`Self::dialog_limit`].
    #[must_use]
    pub fn max_reassembly_limit(&self, config: &crate::config::Config) -> usize {
        self.max_reassembly
            .or(config.limits.max_reassembly)
            .unwrap_or(Self::DEFAULT_MAX_REASSEMBLY) as usize
    }

    /// HEP global ingest ceiling: `--hep-rate-limit`, else
    /// `[limits] hep_rate_limit`, else the default. See [`Self::dialog_limit`].
    ///
    /// `0` disables the ceiling, and that is a real setting rather than
    /// "unset" — which is exactly why this is an `Option` and not a `u64`
    /// defaulted to 0.
    #[must_use]
    pub fn hep_rate_limit_resolved(&self, config: &crate::config::Config) -> u64 {
        self.hep_rate_limit
            .or(config.limits.hep_rate_limit)
            .unwrap_or(Self::DEFAULT_HEP_RATE_LIMIT)
    }

    /// Registration-flood threshold: `--reg-flood-threshold`, else
    /// `[security] reg_flood_threshold`, else the default. See
    /// [`Self::dialog_limit`] for the precedence rule.
    #[must_use]
    pub fn reg_flood_threshold(&self, config: &crate::config::Config) -> u32 {
        self.reg_flood_threshold
            .or(config.security.reg_flood_threshold)
            .unwrap_or(Self::DEFAULT_REG_FLOOD_THRESHOLD)
    }

    /// Scanner-kill transmit ceiling: `--kill-rate-limit`, else
    /// `[security] kill_rate_limit`, else the default.
    ///
    /// Returns the number itself rather than an `Option`, because the worker
    /// reads `None` as "apply your own default" and a resolver that can return
    /// `None` is a resolver a caller can silently bypass — which is exactly
    /// how this cap came to be unreachable in the first place.
    #[must_use]
    pub fn kill_rate_limit(&self, config: &crate::config::Config) -> u32 {
        self.kill_rate_limit
            .or(config.security.kill_rate_limit)
            .unwrap_or(Self::DEFAULT_KILL_RATE_LIMIT)
    }

    /// Declared business hours: `--business-hours`, else
    /// `[security] business_hours`, else none.
    ///
    /// `None` means the operator declared nothing, which is DIFFERENT from
    /// declaring a window: with no window there is no "outside", so the
    /// off-hours detection stays off rather than guessing office hours.
    ///
    /// # Errors
    ///
    /// `crate::Error::ConfigInvalid` when the spec is not two whole hours in
    /// `0..=23` separated by `-`.
    pub fn business_hours(
        &self,
        config: &crate::config::Config,
    ) -> Result<Option<(u8, u8)>, crate::Error> {
        match self
            .business_hours
            .as_deref()
            .or(config.security.business_hours.as_deref())
        {
            Some(spec) => crate::config::parse_business_hours(spec).map(Some),
            None => Ok(None),
        }
    }

    /// Fraud trigger points: each flag, else its `[security]` key, else the
    /// built-in. See [`Self::dialog_limit`] for the precedence rule.
    #[must_use]
    pub fn fraud_thresholds(
        &self,
        config: &crate::config::Config,
    ) -> crate::security::fraud_detect::FraudThresholds {
        let built_in = crate::security::fraud_detect::FraudThresholds::BUILT_IN;
        let sec = &config.security;
        crate::security::fraud_detect::FraudThresholds {
            short_call_secs: self
                .fraud_short_call_secs
                .or(sec.fraud_short_call_secs)
                .unwrap_or(built_in.short_call_secs),
            wangiri_calls: self
                .fraud_wangiri_calls
                .or(sec.fraud_wangiri_calls)
                .unwrap_or(built_in.wangiri_calls),
            sequential_calls: self
                .fraud_sequential_calls
                .or(sec.fraud_sequential_calls)
                .map_or(built_in.sequential_calls, |v| v as usize),
            volume_multiplier: self
                .fraud_volume_multiplier
                .or(sec.fraud_volume_multiplier)
                .unwrap_or(built_in.volume_multiplier),
            volume_min_calls: self
                .fraud_volume_min_calls
                .or(sec.fraud_volume_min_calls)
                .unwrap_or(built_in.volume_min_calls),
        }
    }

    /// Scanner trigger points: each flag, else its `[security]` key, else the
    /// built-in. See [`Self::dialog_limit`] for the precedence rule.
    ///
    /// [`crate::security::scanner_detect::ScannerThresholds::window_secs`] is
    /// resolved here alongside the counts because it is the only one of them
    /// that can reach a sweep paced more slowly than the window: the counts are
    /// all per-window, so under a five-second window a probe every ten seconds
    /// leaves every counter at one whatever they are set to.
    #[must_use]
    pub fn scanner_thresholds(
        &self,
        config: &crate::config::Config,
    ) -> crate::security::scanner_detect::ScannerThresholds {
        let built_in = crate::security::scanner_detect::ScannerThresholds::BUILT_IN;
        let sec = &config.security;
        crate::security::scanner_detect::ScannerThresholds {
            behavioral_probes: self
                .scanner_behavioral_probes
                .or(sec.scanner_behavioral_probes)
                .unwrap_or(built_in.behavioral_probes),
            enumeration_targets: self
                .scanner_enumeration_targets
                .or(sec.scanner_enumeration_targets)
                .map_or(built_in.enumeration_targets, |v| v as usize),
            rejected_probes: self
                .scanner_rejected_probes
                .or(sec.scanner_rejected_probes)
                .unwrap_or(built_in.rejected_probes),
            unanswered_probes: self
                .scanner_unanswered_probes
                .or(sec.scanner_unanswered_probes)
                .unwrap_or(built_in.unanswered_probes),
            window_secs: self
                .scanner_window_secs
                .or(sec.scanner_window_secs)
                .unwrap_or(built_in.window_secs),
            established_factor: self
                .scanner_established_factor
                .or(sec.scanner_established_factor)
                .unwrap_or(built_in.established_factor),
            answer_grace_ms: self
                .scanner_answer_grace_ms
                .or(sec.scanner_answer_grace_ms)
                .unwrap_or(built_in.answer_grace_ms),
        }
    }

    /// Findings-history depth: `--findings-history`, else
    /// `[security] findings_history`, else the default.
    #[must_use]
    pub fn findings_history(&self, config: &crate::config::Config) -> usize {
        self.findings_history
            .or(config.security.findings_history)
            .unwrap_or(Self::DEFAULT_FINDINGS_HISTORY) as usize
    }

    /// Lint per-rule cap: `--lint-max-per-rule`, else
    /// `[limits] lint_max_per_rule`, else the default.
    #[must_use]
    pub fn lint_max_per_rule(&self, config: &crate::config::Config) -> usize {
        self.lint_max_per_rule
            .or(config.limits.lint_max_per_rule)
            .unwrap_or(Self::DEFAULT_LINT_MAX_PER_RULE) as usize
    }

    /// Signalling diagnosis thresholds: each flag, else its `[diagnosis]` key,
    /// else the standards figure.
    #[must_use]
    pub fn signaling_thresholds(
        &self,
        config: &crate::config::Config,
    ) -> crate::sip::diagnosis::SignalingThresholds {
        let built_in = crate::sip::diagnosis::SignalingThresholds::BUILT_IN;
        let d = &config.diagnosis;
        crate::sip::diagnosis::SignalingThresholds {
            post_dial_delay_sec: self
                .pdd_threshold_secs
                .or(d.post_dial_delay_secs)
                .unwrap_or(built_in.post_dial_delay_sec),
            ack_timeout_sec: self
                .ack_timeout_secs
                .or(d.ack_timeout_secs)
                .unwrap_or(built_in.ack_timeout_sec),
            no_final_response_sec: self
                .no_final_response_secs
                .or(d.no_final_response_secs)
                .unwrap_or(built_in.no_final_response_sec),
        }
    }

    /// The numbers the diagnostic filter aliases compare against.
    ///
    /// Composed from the three resolved threshold sets rather than resolved
    /// again here, so `--problems` cannot disagree with the diagnosis it
    /// reports, the colour an operator sees, or the fraud detector's idea of a
    /// short call. Each part has already applied its own
    /// flag-over-key-over-default precedence; a fourth chain here is exactly
    /// the drift this replaces.
    #[must_use]
    pub fn alias_thresholds(
        &self,
        config: &crate::config::Config,
    ) -> crate::sip::dsl::AliasThresholds {
        crate::sip::dsl::AliasThresholds::from_parts(
            &self.signaling_thresholds(config),
            &self.quality_bands(config),
            &self.fraud_thresholds(config),
        )
    }

    /// Media asymmetry thresholds: each flag, else its `[diagnosis]` key, else
    /// the built-in.
    #[must_use]
    pub fn asymmetry_thresholds(
        &self,
        config: &crate::config::Config,
    ) -> crate::rtp::diagnosis::AsymmetryThresholds {
        let built_in = crate::rtp::diagnosis::AsymmetryThresholds::BUILT_IN;
        let d = &config.diagnosis;
        crate::rtp::diagnosis::AsymmetryThresholds {
            duration_pct_delta: self
                .duration_asymmetry_pct
                .or(d.duration_asymmetry_pct)
                .unwrap_or(built_in.duration_pct_delta),
            duration_min_delta_sec: self
                .duration_asymmetry_secs
                .or(d.duration_asymmetry_secs)
                .unwrap_or(built_in.duration_min_delta_sec),
            late_media_threshold_ms: self
                .late_media_ms
                .or(d.late_media_ms)
                .unwrap_or(built_in.late_media_threshold_ms),
        }
    }

    /// Quality colour bands: each flag, else its `[quality]` key, else the
    /// shipped boundary. See [`Self::dialog_limit`] for the precedence rule.
    ///
    /// Resolved ONCE, at startup, and handed to the views. That is the whole
    /// point of the type: `QualityBands` exists because four panes each banded
    /// jitter and loss with their own numbers and disagreed about the same
    /// stream. A config every view read for itself would rebuild that defect
    /// with extra steps, so no view constructs a band set — each is given the
    /// one this returns.
    ///
    /// The result is checked by [`crate::rtp::bands::QualityBands::validate`]
    /// in `crate::app::bootstrap::load_config`, not here. An unreachable
    /// middle is a property of the PAIR, and either half of a pair may come
    /// from the file while the other comes from the command line.
    #[must_use]
    pub fn quality_bands(&self, config: &crate::config::Config) -> crate::rtp::bands::QualityBands {
        let built_in = crate::rtp::bands::QualityBands::default();
        let q = &config.quality;
        crate::rtp::bands::QualityBands {
            jitter_warn_ms: self
                .jitter_warn_ms
                .or(q.jitter_warn_ms)
                .unwrap_or(built_in.jitter_warn_ms),
            jitter_bad_ms: self
                .jitter_bad_ms
                .or(q.jitter_bad_ms)
                .unwrap_or(built_in.jitter_bad_ms),
            loss_warn_pct: self
                .loss_warn_pct
                .or(q.loss_warn_pct)
                .unwrap_or(built_in.loss_warn_pct),
            loss_bad_pct: self
                .loss_bad_pct
                .or(q.loss_bad_pct)
                .unwrap_or(built_in.loss_bad_pct),
            mos_warn: self.mos_warn.or(q.mos_warn).unwrap_or(built_in.mos_warn),
            mos_bad: self.mos_bad.or(q.mos_bad).unwrap_or(built_in.mos_bad),
            rtt_warn_ms: self
                .rtt_warn_ms
                .or(q.rtt_warn_ms)
                .unwrap_or(built_in.rtt_warn_ms),
            rtt_bad_ms: self
                .rtt_bad_ms
                .or(q.rtt_bad_ms)
                .unwrap_or(built_in.rtt_bad_ms),
        }
    }

    /// Whether any `-I` was given.
    #[must_use]
    pub fn has_input(&self) -> bool {
        !self.input.is_empty()
    }

    /// The first `-I` argument, for labelling and for the single-file paths
    /// that predate multi-file input.
    ///
    /// This is the *spec* as typed, which may be a directory or a glob rather
    /// than a file. Callers that need actual files must resolve them through
    /// [`crate::capture::input_set::resolve`]; the features still using this
    /// (Wireshark hand-off, embedded-secret loading, `--strip-secrets`) act on
    /// one concrete file by nature.
    #[must_use]
    pub fn primary_input(&self) -> Option<&str> {
        self.input.first().map(String::as_str)
    }

    /// How `-I` arguments should be expanded.
    ///
    /// `native`-only: resolution opens each candidate through libpcap to
    /// order the set and to tell a capture from a README, so it cannot
    /// exist in a build with no capture backend.
    #[cfg(feature = "native")]
    #[must_use]
    pub fn input_resolve_options(&self) -> crate::capture::input_set::ResolveOptions {
        crate::capture::input_set::ResolveOptions {
            recursive: self.recursive,
            name_glob: self.input_name.clone(),
        }
    }

    /// Parse CLI arguments from the real process arguments.
    ///
    /// # Side effects
    /// Reads the process argument list and the `env = "..."`-tagged
    /// environment variables (e.g. `SIPNAB_API_KEY`); on a parse error,
    /// `--help`, or `--version`, clap prints to stdout/stderr and exits
    /// the process without returning.
    pub fn parse_args() -> Self {
        let mut cli = Cli::parse();
        cli.normalize();
        cli
    }

    /// Apply the "implies" relationships between flags, once, at the parse
    /// boundary, so every consumer downstream reads one already-settled truth.
    ///
    /// `--call-report` implies `-N`. That was always the stated contract —
    /// [`Cli::validate`] waives the `-N` requirement for it on exactly those
    /// grounds — but nothing applied it, and four separate places derived
    /// interactivity for themselves from the raw `no_tui` flag:
    /// [`crate::app::bootstrap::plan`] chose the run mode, `app::batch` gated
    /// `--hexdump`, per-message output and `--report` on it, and
    /// [`crate::app::bootstrap::init_logging`] silenced logs for a TUI that was
    /// not going to start. So `sipnab -I capture.pcap --call-report <id>
    /// --markdown > report.md` launched the TUI and wrote 122 bytes of
    /// alt-screen and mouse-tracking escape codes, exit 0 — `call_report` is
    /// read only in `app::batch`, so the TUI did not override the flag, it
    /// discarded it. Six published invocations used that spelling.
    ///
    /// Normalizing here rather than at each reader is deliberate: the next
    /// output gate added to `app::batch` will be written `&& cli.no_tui` like
    /// the three before it, and that is only correct if `no_tui` already means
    /// "non-interactive" rather than "the user typed `-N`".
    ///
    /// `validate` still carries its own `call_report.is_none()` guard, because
    /// a `Cli` built directly in a test never passes through here.
    fn normalize(&mut self) {
        if self.call_report.is_some() {
            self.no_tui = true;
        }
    }

    /// Whether the dialog store evicts the oldest dialog at `--limit` capacity.
    /// Defaults to `true` (SNB-0004): a privileged sniffer must bound dialog
    /// state safely without dropping new legitimate calls. `--no-rotate` opts out.
    pub fn rotate_enabled(&self) -> bool {
        !self.no_rotate
    }

    /// Parse CLI arguments from an iterator (for testing).
    ///
    /// # Arguments
    /// * `args` - full argument list; the first item must be the binary
    ///   name, exactly as in a real `argv`.
    ///
    /// # Side effects
    /// Reads the `env = "..."`-tagged environment variables; on a parse
    /// error clap prints the error and exits the process.
    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let mut cli = Cli::parse_from(args);
        cli.normalize();
        cli
    }

    /// Validate argument combinations and return an error message if invalid.
    ///
    /// Checks that output-only flags (`--json`, `--report`, `--hexdump`,
    /// `--fail2ban`) require non-interactive mode (`-N`) unless `--call-report`
    /// is specified (which implies non-interactive output). Also rejects
    /// `--mcp` without `-N`, `--mcp` combined with stdout-writing flags
    /// (MCP owns stdout for the JSON-RPC wire), an unknown
    /// `--mcp-transport` value, and any malformed `--kill-target` spec.
    ///
    /// # Errors
    /// `crate::Error::CliValidation` with a user-facing message for each
    /// rejected combination. Pure — no side effects.
    pub fn validate(&self) -> Result<(), crate::Error> {
        // Refused here rather than at the point of use, because the point of
        // use is inside the detector setup: a bad spec accepted at startup
        // becomes a fraud run with off-hours detection silently missing, which
        // is the failure mode this whole change exists to remove. `[security]
        // business_hours` is checked by `SecurityConfig::validate` for the
        // same reason; clap cannot check a range spec by itself.
        if let Some(spec) = self.business_hours.as_deref() {
            crate::config::parse_business_hours(spec)?;
        }
        // --rtp-interval parses, defaults and documents itself, and nothing
        // reads it. Saying so beats accepting a value and reporting nothing,
        // because docs/cli-reference.md used to teach "stats every 5 seconds"
        // as a worked example. Warn rather than refuse: an existing invocation
        // keeps working, and the operator learns the interval is not honoured.
        if self.rtp_interval != 1 {
            tracing::warn!(
                "--rtp-interval {} is accepted and ignored: periodic RTP statistics \
                 reporting is not implemented, so no interval report will appear. \
                 Stream statistics are reported once, at end of capture.",
                self.rtp_interval
            );
        }
        let output_flags_used: Vec<&str> = [
            (self.json, "--json"),
            (self.json_dialogs, "--json-dialogs"),
            (self.json_pretty, "--json-pretty"),
            (self.report, "--report"),
            (self.hexdump, "--hexdump"),
            (self.fail2ban, "--fail2ban"),
            (self.group_by.is_some(), "--group-by"),
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

        // Reject an unknown --group-by field at startup. This flag previously
        // parsed into the struct and was never read, so any value — including a
        // typo — was accepted and silently produced ungrouped output.
        if let Some(ref field) = self.group_by {
            crate::output::group::GroupField::parse(field).map_err(crate::Error::CliValidation)?;
        }

        // MCP mode owns stdout (JSON-RPC wire); reject any flag
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
            // in the http transport module; for stdio there is no
            // network surface to validate.
            if self.mcp_transport != "stdio" && self.mcp_transport != "http" {
                return Err(crate::Error::CliValidation(format!(
                    "--mcp-transport must be 'stdio' or 'http', got '{}'",
                    self.mcp_transport
                )));
            }
        }

        // Fail fast on a malformed --kill-target so a typo can't silently leave
        // an attacker unblocked.
        for spec in &self.kill_target {
            crate::security::scanner_kill::KillTarget::parse(spec)
                .map_err(|e| crate::Error::CliValidation(format!("--kill-target '{spec}': {e}")))?;
        }

        Ok(())
    }

    /// Resolve the metrics Basic-auth credential, preferring
    /// `--metrics-auth-file` over the inline `--metrics-auth` so the secret
    /// can be kept out of the process argument list.
    ///
    /// Returns `Ok(None)` when neither source is set; see
    /// `resolve_file_or_inline_secret` for the error and file-read
    /// semantics.
    pub fn resolve_metrics_auth(&self) -> Result<Option<String>, String> {
        resolve_file_or_inline_secret(
            self.metrics_auth.as_deref(),
            self.metrics_auth_file.as_deref(),
            "--metrics-auth-file",
        )
    }

    /// Resolve the HEP shared secret, preferring `--hep-auth-file` over the
    /// inline `--hep-auth` / `SIPNAB_HEP_AUTH` value. Used both to stamp
    /// outgoing packets (`--hep-send`) and to authenticate incoming ones
    /// (`--hep-listen`).
    ///
    /// Returns `Ok(None)` when neither source is set; see
    /// `resolve_file_or_inline_secret` for the error and file-read
    /// semantics.
    pub fn resolve_hep_auth(&self) -> Result<Option<String>, String> {
        resolve_file_or_inline_secret(
            self.hep_auth.as_deref(),
            self.hep_auth_file.as_deref(),
            "--hep-auth-file",
        )
    }
}

/// Resolve a secret from an optional file (preferred) or an optional inline
/// value. A file's contents are trimmed of surrounding whitespace; an empty
/// or unreadable file is an error naming `flag`, so a mis-set secret fails
/// loudly instead of silently disabling authentication.
///
/// # Arguments
/// * `inline` - secret given directly via a flag or environment variable.
/// * `file` - path whose trimmed contents are the secret; wins over `inline`.
/// * `flag` - file-flag name used in error messages (e.g. `--hep-auth-file`).
///
/// # Returns
/// `Ok(Some(secret))` from the file when `file` is set, else from `inline`;
/// `Ok(None)` when neither source is set.
///
/// # Errors
/// The file cannot be read, or its trimmed contents are empty.
///
/// # Side effects
/// Reads `file` from the filesystem when set.
pub fn resolve_file_or_inline_secret(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
    flag: &str,
) -> Result<Option<String>, String> {
    if let Some(path) = file {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("{flag} '{}': {e}", path.display()))?;
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Err(format!("{flag} '{}': file is empty", path.display()));
        }
        return Ok(Some(trimmed.to_string()));
    }
    Ok(inline.map(str::to_string))
}

/// Unit tests for CLI parsing, flag defaults, argument validation, and
/// file-vs-inline secret resolution.
/// Parse `--dialog-track`, rejecting anything that is not a known method.
///
/// The flag this replaces accepted every value — `--dialog-track telepathy`
/// exited 0 and changed nothing — so a typo silently selected the default.
fn parse_dialog_track(s: &str) -> Result<crate::sip::dialog_store::DialogTracking, String> {
    s.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Help-heading placement (P2 item 1) ──────────────────────────────

    /// The HEP flags and the syslog / alert-json alert channels used to be
    /// mis-filed under the "MCP (Model Context Protocol)" help heading. HEP
    /// flags now live under a dedicated "HEP" heading; the alert channels under
    /// "Security" (alongside the other alert flags). None may remain under the
    /// MCP heading. Asserted via clap introspection.
    ///
    /// (Flag names are written here without the leading dashes on purpose: the
    /// `flag_coverage` gate treats a `--flag` token in any test text as a
    /// reference, and syslog is a deliberately-waived entry there.)
    #[test]
    fn hep_and_alert_flags_are_not_under_mcp_heading() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let heading_of = |long: &str| -> Option<String> {
            cmd.get_arguments()
                .find(|a| a.get_long() == Some(long))
                .and_then(|a| a.get_help_heading())
                .map(|h| h.to_string())
        };
        for long in [
            "hep-listen",
            "hep-send",
            "hep-id",
            "hep-auth",
            "hep-auth-file",
            "hep-auth-mode",
            "hep-parse",
            "hep-allow",
            "hep-rate-limit",
            "hep-rate-limit-per-peer",
        ] {
            assert_eq!(
                heading_of(long).as_deref(),
                Some("HEP"),
                "{long} must be grouped under the HEP heading, not MCP"
            );
        }
        for long in ["syslog", "alert-json"] {
            assert_eq!(
                heading_of(long).as_deref(),
                Some("Security"),
                "{long} is an alert channel and belongs under Security, not MCP"
            );
        }
    }

    // ── Parse-time value validation (P2 item 2) ─────────────────────────

    /// `--color` rejects an out-of-set value at PARSE time rather than silently
    /// falling back to `auto` in the downstream match.
    #[test]
    fn color_rejects_unknown_value_at_parse_time() {
        let err = Cli::try_parse_from(["sipnab", "--color", "bogus"])
            .expect_err("an unknown --color value must be rejected at parse time");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    /// Every documented `--color` value still parses and round-trips.
    #[test]
    fn color_accepts_documented_values() {
        for v in ["auto", "always", "never"] {
            let cli = Cli::try_parse_from(["sipnab", "--color", v])
                .unwrap_or_else(|e| panic!("--color {v} must parse: {e}"));
            let cfg = crate::config::Config::default();
            assert_eq!(cli.color_mode(&cfg), v, "an explicit --color must win");
        }
    }

    /// With no flag and no config key, the resolved colour mode is `auto`.
    ///
    /// Asserts the RESOLVER, not the field. `cli.color == "auto"` was the old
    /// assertion and it passed for the wrong reason: clap filled the field
    /// from a `default_value`, which is precisely what made `[display] color`
    /// unreachable. A test that reads the field cannot tell a working key from
    /// a dead one.
    #[test]
    fn color_default_is_auto() {
        let cli = Cli::try_parse_from(["sipnab"]).unwrap();
        let cfg = crate::config::Config::default();
        assert_eq!(cli.color, None, "no flag given, so the field stays empty");
        assert_eq!(cli.color_mode(&cfg), "auto");
    }

    /// `[display] color` is honoured when the flag is absent, and loses to it
    /// when present. This is the wiring the old field-assertion could not see.
    #[test]
    fn config_color_is_reachable_and_the_flag_still_wins() {
        let mut cfg = crate::config::Config::default();
        cfg.display.color = Some("always".to_string());

        let cli = Cli::try_parse_from(["sipnab"]).unwrap();
        assert_eq!(
            cli.color_mode(&cfg),
            "always",
            "[display] color must reach the run when no --color is given"
        );

        let cli = Cli::try_parse_from(["sipnab", "--color", "never"]).unwrap();
        assert_eq!(
            cli.color_mode(&cfg),
            "never",
            "--color must beat the config key"
        );
    }

    /// `[security] kill_rate_limit` reaches the resolver, and
    /// `--kill-rate-limit` beats it.
    ///
    /// That the resolved number actually bounds what goes on the wire is
    /// asserted separately, against the worker's own ledger, in
    /// `app::batch::tests::the_configured_kill_rate_limit_bounds_what_the_worker_sends`
    /// — a resolver test alone would pass against a caller that never asked.
    #[test]
    fn config_kill_rate_limit_is_reachable_and_the_flag_still_wins() {
        let mut cfg = crate::config::Config::default();
        cfg.security.kill_rate_limit = Some(7);
        let cli = Cli::try_parse_from(["sipnab"]).expect("parse");
        assert_eq!(
            cli.kill_rate_limit(&cfg),
            7,
            "[security] kill_rate_limit must reach the run when no flag is given"
        );
        let cli = Cli::try_parse_from(["sipnab", "--kill-rate-limit", "3"]).expect("parse");
        assert_eq!(
            cli.kill_rate_limit(&cfg),
            3,
            "--kill-rate-limit must beat [security] kill_rate_limit"
        );
        assert_eq!(
            Cli::try_parse_from(["sipnab"])
                .expect("parse")
                .kill_rate_limit(&crate::config::Config::default()),
            Cli::DEFAULT_KILL_RATE_LIMIT
        );
    }

    /// The same, for `[security] findings_history`.
    ///
    /// The effect — that the resolved depth bounds what the findings buffer
    /// retains — is asserted in
    /// `app::batch::tests::the_configured_findings_history_bounds_what_is_retained`.
    #[test]
    fn config_findings_history_is_reachable_and_the_flag_still_wins() {
        let mut cfg = crate::config::Config::default();
        cfg.security.findings_history = Some(25);
        let cli = Cli::try_parse_from(["sipnab"]).expect("parse");
        assert_eq!(cli.findings_history(&cfg), 25);
        let cli = Cli::try_parse_from(["sipnab", "--findings-history", "5"]).expect("parse");
        assert_eq!(
            cli.findings_history(&cfg),
            5,
            "--findings-history must beat [security] findings_history"
        );
        // Zero is a real setting — keep nothing — not "unset".
        let cli = Cli::try_parse_from(["sipnab", "--findings-history", "0"]).expect("parse");
        assert_eq!(cli.findings_history(&cfg), 0);
    }

    /// The same, for `[security] kill_response`.
    #[test]
    fn config_kill_response_is_reachable_and_the_flag_still_wins() {
        let mut cfg = crate::config::Config::default();
        cfg.security.kill_response = Some(486);

        let cli = Cli::try_parse_from(["sipnab"]).unwrap();
        assert_eq!(
            cli.kill_response_code(&cfg),
            486,
            "[security] kill_response must reach the run when no flag is given"
        );

        let cli = Cli::try_parse_from(["sipnab", "--kill-response", "603"]).unwrap();
        assert_eq!(
            cli.kill_response_code(&cfg),
            603,
            "the flag must beat the key"
        );

        let cli = Cli::try_parse_from(["sipnab"]).unwrap();
        assert_eq!(
            cli.kill_response_code(&crate::config::Config::default()),
            Cli::DEFAULT_KILL_RESPONSE,
            "neither given: the named default, not a clap-filled field"
        );
    }

    /// `--mcp-transport` rejects an unknown transport at parse time — the old
    /// free-text String let a typo pass parse and only fail (or be silently
    /// ignored) later, and only when `--mcp` was also set.
    #[test]
    fn mcp_transport_rejects_unknown_value_at_parse_time() {
        let err = Cli::try_parse_from(["sipnab", "--mcp-transport", "carrier-pigeon"])
            .expect_err("an unknown --mcp-transport must be rejected at parse time");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    /// Both documented transports still parse and round-trip.
    #[test]
    fn mcp_transport_accepts_documented_values() {
        for v in ["stdio", "http"] {
            let cli = Cli::try_parse_from(["sipnab", "--mcp-transport", v])
                .unwrap_or_else(|e| panic!("--mcp-transport {v} must parse: {e}"));
            assert_eq!(cli.mcp_transport, v);
        }
    }

    /// The pcap-export-mode flag constrains its accepted values at parse time.
    /// Asserted via clap introspection of the arg's possible values (by the
    /// arg's long name, not by passing the flag on a parse line) so the flag
    /// stays where the `flag_coverage` gate's waiver list has it.
    #[test]
    fn pcap_export_mode_possible_values_are_constrained() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some("pcap-export-mode"))
            .expect("pcap-export-mode arg exists");
        let vals: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|pv| pv.get_name().to_string())
            .collect();
        assert_eq!(vals, vec!["decrypted", "encrypted+dsb", "raw"]);
    }

    /// A set secret file wins over the inline value and is whitespace-trimmed.
    #[test]
    fn resolve_secret_prefers_file_over_inline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "  file-secret\n").unwrap();
        let got = resolve_file_or_inline_secret(Some("inline"), Some(&path), "--x").unwrap();
        assert_eq!(
            got.as_deref(),
            Some("file-secret"),
            "file wins and is trimmed"
        );
    }

    /// With no file set, the inline secret is returned as-is.
    #[test]
    fn resolve_secret_falls_back_to_inline() {
        let got = resolve_file_or_inline_secret(Some("inline"), None, "--x").unwrap();
        assert_eq!(got.as_deref(), Some("inline"));
    }

    /// Neither source set resolves to `Ok(None)` (no secret configured).
    #[test]
    fn resolve_secret_none_when_neither_set() {
        let got = resolve_file_or_inline_secret(None, None, "--x").unwrap();
        assert_eq!(got, None);
    }

    /// A whitespace-only secret file errors loudly, naming the flag.
    #[test]
    fn resolve_secret_empty_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, "   \n").unwrap();
        let err = resolve_file_or_inline_secret(None, Some(&path), "--x").unwrap_err();
        assert!(err.contains("--x"), "error names the flag, got: {err}");
        assert!(
            err.contains("empty"),
            "error explains emptiness, got: {err}"
        );
    }

    /// A nonexistent secret file errors, naming the flag.
    #[test]
    fn resolve_secret_missing_file_is_error() {
        let path = std::path::Path::new("/nonexistent/sipnab/secret");
        let err = resolve_file_or_inline_secret(None, Some(path), "--x").unwrap_err();
        assert!(err.contains("--x"), "error names the flag, got: {err}");
    }

    /// `--cores N` parses into the offline reconstruction core count.
    #[test]
    fn cores_flag_parses() {
        // `--cores N` selects the multi-core offline reconstruction core count.
        let cli = Cli::parse_from_args(["sipnab", "--cores", "4", "-I", "x.pcap"]);
        assert_eq!(cli.cores, 4);
    }

    /// HEP auth-file, per-peer rate limit, HEP-kill opt-in, and metrics
    /// auth-file flags all parse together.
    #[test]
    fn security_secret_and_kill_flags_parse() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "-L",
            "127.0.0.1:9060",
            "--hep-auth-file",
            "/etc/sipnab/hep.key",
            "--hep-rate-limit-per-peer",
            "5000",
            "--hep-allow-kill",
            "--metrics",
            "127.0.0.1:9090",
            "--metrics-auth-file",
            "/etc/sipnab/metrics.cred",
        ]);
        assert_eq!(
            cli.hep_auth_file.as_deref(),
            Some(std::path::Path::new("/etc/sipnab/hep.key"))
        );
        assert_eq!(cli.hep_rate_limit_per_peer, PerPeerLimit::Fixed(5000));
        assert!(
            cli.hep_allow_kill,
            "--hep-allow-kill opts into HEP scanner-kill"
        );
        assert_eq!(
            cli.metrics_auth_file.as_deref(),
            Some(std::path::Path::new("/etc/sipnab/metrics.cred"))
        );
    }

    /// HEP-origin scanner-kill and the per-peer cap both default off.
    #[test]
    fn hep_allow_kill_defaults_off() {
        let cli = Cli::parse_from_args(["sipnab", "-L", "127.0.0.1:9060"]);
        assert!(
            !cli.hep_allow_kill,
            "HEP-origin scanner-kill must be opt-in (SN-01)"
        );
        assert_eq!(
            cli.hep_rate_limit_per_peer,
            PerPeerLimit::Off,
            "per-peer cap off by default"
        );
    }

    /// `--hep-rate-limit-per-peer auto` parses to `PerPeerLimit::Auto`.
    #[test]
    fn hep_rate_limit_per_peer_accepts_auto() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "-L",
            "127.0.0.1:9060",
            "--hep-rate-limit-per-peer",
            "auto",
        ]);
        assert_eq!(cli.hep_rate_limit_per_peer, PerPeerLimit::Auto);
    }

    /// A non-numeric, non-keyword per-peer value is rejected at parse time.
    #[test]
    fn hep_rate_limit_per_peer_rejects_invalid_value() {
        let err = Cli::try_parse_from([
            "sipnab",
            "-L",
            "127.0.0.1:9060",
            "--hep-rate-limit-per-peer",
            "sometimes",
        ]);
        assert!(
            err.is_err(),
            "non-numeric, non-keyword value must be rejected"
        );
    }

    /// `PerPeerLimit::from_str` accepts auto/off/numbers (0 = off),
    /// case-insensitively, and rejects everything else.
    #[test]
    fn per_peer_limit_from_str() {
        use std::str::FromStr;
        assert_eq!(PerPeerLimit::from_str("auto"), Ok(PerPeerLimit::Auto));
        assert_eq!(PerPeerLimit::from_str("AUTO"), Ok(PerPeerLimit::Auto));
        assert_eq!(PerPeerLimit::from_str("off"), Ok(PerPeerLimit::Off));
        assert_eq!(PerPeerLimit::from_str("0"), Ok(PerPeerLimit::Off));
        assert_eq!(
            PerPeerLimit::from_str("5000"),
            Ok(PerPeerLimit::Fixed(5000))
        );
        assert!(PerPeerLimit::from_str("fast").is_err());
        assert!(PerPeerLimit::from_str("-1").is_err());
    }

    /// `resolve` maps Off to 0, passes Fixed through, and divides the
    /// global ceiling for Auto (staying off with an empty allowlist).
    #[test]
    fn per_peer_limit_resolve() {
        assert_eq!(PerPeerLimit::Off.resolve(50000, 4), 0);
        assert_eq!(PerPeerLimit::Fixed(2000).resolve(50000, 4), 2000);
        // Fixed ignores the allowlist entirely.
        assert_eq!(PerPeerLimit::Fixed(2000).resolve(50000, 0), 2000);
        // Auto divides the ceiling across the allowlist.
        assert_eq!(PerPeerLimit::Auto.resolve(40000, 4), 10000);
        // Auto with no allowlist stays disabled (nothing to divide by).
        assert_eq!(PerPeerLimit::Auto.resolve(50000, 0), 0);
    }

    /// Auto with more allowlist entries than the global ceiling must floor
    /// at 1 pps, not truncate to 0 — a 0 here means DISABLED, silently
    /// removing the per-peer cap the operator asked for.
    #[test]
    fn per_peer_limit_auto_floors_at_one() {
        assert_eq!(PerPeerLimit::Auto.resolve(5, 10), 1);
        // Exact division and the normal case are unchanged.
        assert_eq!(PerPeerLimit::Auto.resolve(10, 10), 1);
        assert_eq!(PerPeerLimit::Auto.resolve(40000, 4), 10000);
    }

    /// `HepAuthMode::from_str` accepts plain/hmac case-insensitively,
    /// rejects other strings, and defaults to `Plain`.
    #[test]
    fn hep_auth_mode_from_str() {
        use std::str::FromStr;
        assert_eq!(HepAuthMode::from_str("plain"), Ok(HepAuthMode::Plain));
        assert_eq!(HepAuthMode::from_str("HMAC"), Ok(HepAuthMode::Hmac));
        assert!(HepAuthMode::from_str("sigv4").is_err());
        assert_eq!(HepAuthMode::default(), HepAuthMode::Plain);
    }

    /// `--hep-auth-mode hmac` parses; the flag defaults to `plain`.
    #[test]
    fn hep_auth_mode_flag_parses() {
        let cli =
            Cli::parse_from_args(["sipnab", "-L", "127.0.0.1:9060", "--hep-auth-mode", "hmac"]);
        assert_eq!(cli.hep_auth_mode, HepAuthMode::Hmac);
        let default = Cli::parse_from_args(["sipnab", "-L", "127.0.0.1:9060"]);
        assert_eq!(
            default.hep_auth_mode,
            HepAuthMode::Plain,
            "plain is the default mode"
        );
    }

    /// A bare `sipnab` invocation yields the documented default values
    /// for every defaulted flag, including rotate-on (SNB-0004).
    #[test]
    fn defaults_are_sane() {
        let cli = Cli::parse_from_args(["sipnab"]);
        assert_eq!(
            cli.portrange, None,
            "portrange is an Option so an explicit default beats config"
        );
        // The three caps are Options for the same reason portrange is: with a
        // clap `default_value` the field is filled whether or not the operator
        // passed anything, so `[limits]` had nothing to override and was dead.
        // Unset on the CLI; the default now comes from the resolver.
        assert_eq!(cli.limit, None);
        assert_eq!(cli.max_streams, None);
        let cfg = crate::config::Config::default();
        assert_eq!(cli.dialog_limit(&cfg), 100_000);
        assert_eq!(cli.max_streams_limit(&cfg), 50_000);
        assert_eq!(cli.rtp_interval, 1);
        assert!((cli.quality_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(cli.kill_response_code(&cfg), 200);
        assert_eq!(cli.exec_rate_limit, 10);
        assert_eq!(cli.api_max_conn, 100);
        assert_eq!(cli.mcp_max_concurrent, 100);
        assert_eq!(cli.mcp_rate_limit_per_peer, 100);
        assert_eq!(cli.hep_rate_limit, None);
        assert_eq!(cli.hep_rate_limit_resolved(&cfg), 50_000);
        assert_eq!(cli.pcap_export_mode, "decrypted");
        assert_eq!(cli.max_reassembly, None);
        assert_eq!(cli.max_reassembly_limit(&cfg), 10_000);
        assert_eq!(cli.cores, 1, "single-threaded by default");
        assert_eq!(cli.color_mode(&cfg), "auto");
        assert!(!cli.no_tui);
        assert!(!cli.setup_caps);
        // Dialog rotation is ON by default (SNB-0004): at --limit capacity the
        // store evicts the oldest dialog rather than dropping new legitimate
        // calls — a privileged sniffer must bound dialog state safely by default.
        assert!(cli.rotate_enabled(), "rotate must default ON");
    }

    /// The `--mcp-max-concurrent` cap parses as a number, and `0` is accepted
    /// as the "unlimited" spelling — the value the MCP server turns into no cap
    /// at all rather than a zero-permit semaphore that refuses every call.
    #[test]
    fn mcp_max_concurrent_parses_including_the_unlimited_zero() {
        let capped = Cli::parse_from_args(["sipnab", "--mcp-max-concurrent", "5"]);
        assert_eq!(capped.mcp_max_concurrent, 5);
        let unlimited = Cli::parse_from_args(["sipnab", "--mcp-max-concurrent", "0"]);
        assert_eq!(
            unlimited.mcp_max_concurrent, 0,
            "0 must parse as the unlimited spelling, not be rejected"
        );
    }

    /// The `--mcp-rate-limit-per-peer` cap parses as a number, and `0` is
    /// accepted as the "unlimited" spelling — the same convention
    /// `--mcp-max-concurrent` uses, so the two MCP caps read alike rather than
    /// one meaning "off" by 0 and the other refusing every call.
    #[test]
    fn mcp_rate_limit_per_peer_parses_including_the_unlimited_zero() {
        let capped = Cli::parse_from_args(["sipnab", "--mcp-rate-limit-per-peer", "5"]);
        assert_eq!(capped.mcp_rate_limit_per_peer, 5);
        let unlimited = Cli::parse_from_args(["sipnab", "--mcp-rate-limit-per-peer", "0"]);
        assert_eq!(
            unlimited.mcp_rate_limit_per_peer, 0,
            "0 must parse as the unlimited spelling, not be rejected"
        );
    }

    /// `--call-report` sets `no_tui` at the parse boundary, and only then.
    ///
    /// Every interactivity decision in the process reads `no_tui`: the run
    /// mode, the three output gates in `app::batch`, and log suppression. If
    /// the implication is not applied here they disagree, which is how
    /// `--call-report <id> --markdown` came to emit terminal escape codes
    /// instead of a report.
    #[test]
    fn call_report_normalizes_to_non_interactive() {
        let cli = Cli::parse_from_args(["sipnab", "-I", "x.pcap", "--call-report", "a@b"]);
        assert!(
            cli.no_tui,
            "--call-report must imply -N, or the run-mode selector and the \
             app::batch output gates disagree about whether a TUI is running"
        );
        assert!(cli.validate().is_ok());

        // Output flags are legal alongside it precisely because it is now
        // non-interactive -- this is the combination validate() waives.
        let cli =
            Cli::parse_from_args(["sipnab", "-I", "x.pcap", "--call-report", "a@b", "--json"]);
        assert!(cli.no_tui);
        assert!(cli.validate().is_ok());

        // Without it, nothing is implied and the TUI remains the default.
        let cli = Cli::parse_from_args(["sipnab", "-I", "x.pcap"]);
        assert!(!cli.no_tui, "no --call-report must leave the TUI default");

        // An explicit -N is unchanged, not doubly applied.
        let cli = Cli::parse_from_args(["sipnab", "-I", "x.pcap", "-N"]);
        assert!(cli.no_tui);
    }

    /// Rotation defaults on; `--no-rotate` opts out; when both flags are
    /// given the last one wins.
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

    /// `--setup-caps` parses into the capability-setup boolean.
    #[test]
    fn setup_caps_flag_parses() {
        let cli = Cli::parse_from_args(["sipnab", "--setup-caps"]);
        assert!(cli.setup_caps);
    }

    /// `--resolve`, `--reverse-dns`, and repeatable `--names` files parse.
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

    /// `-B`/`--buffer` and `--buffer-budget` parse numbers and reject
    /// non-numeric values.
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

    /// `--from-to-mode` parses the kebab-case modes, is `None` when
    /// absent, and rejects unknown values.
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

    /// `--strip-secrets OUTPUT` parses alongside `-I`.
    #[test]
    fn strip_secrets_flag_parses() {
        let cli =
            Cli::parse_from_args(["sipnab", "-I", "in.pcapng", "--strip-secrets", "out.pcapng"]);
        assert_eq!(cli.strip_secrets.as_deref(), Some("out.pcapng"));
    }

    /// Device, input/output pcap, `--no-rtp`, and `--multi-device` parse.
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
        assert_eq!(cli.primary_input(), Some("in.pcap"));
        assert_eq!(cli.output.as_deref(), Some("out.pcap"));
        assert!(cli.no_rtp);
        assert!(cli.multi_device);
    }

    /// Header filters (`--from`/`--to`/`--ua`) and the `-i`/`-v`/`-w`
    /// match modifiers parse.
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

    /// `validate` rejects `--json` without `-N` and accepts it with `-N`.
    #[test]
    fn output_flags_require_no_tui() {
        let cli = Cli::parse_from_args(["sipnab", "--json"]);
        assert!(cli.validate().is_err());

        let cli = Cli::parse_from_args(["sipnab", "-N", "--json"]);
        assert!(cli.validate().is_ok());
    }

    /// `--call-report` implies non-interactive output, so output flags
    /// validate without an explicit `-N`.
    #[test]
    fn call_report_bypasses_no_tui_requirement() {
        let cli = Cli::parse_from_args(["sipnab", "--json", "--call-report", "abc123"]);
        assert!(cli.validate().is_ok());
    }

    /// `--kill-scanner`, `--fraud-detect`, and repeatable `--alert` parse.
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

    /// Trailing positional words are collected verbatim as the BPF filter.
    #[test]
    fn bpf_filter_positional() {
        let cli = Cli::parse_from_args(["sipnab", "host", "10.0.0.1", "and", "port", "5060"]);
        assert_eq!(
            cli.bpf_filter,
            vec!["host", "10.0.0.1", "and", "port", "5060"]
        );
    }

    /// `-S`/`--limitlen` and `--no-reassembly` parse; both default off.
    #[test]
    fn limitlen_and_no_reassembly_flags_parse() {
        // Short form.
        let cli = Cli::parse_from_args(["sipnab", "-S", "512", "--no-reassembly"]);
        assert_eq!(cli.limitlen, Some(512));
        assert!(cli.no_reassembly);
        // Long form (`--limitlen`).
        let long = Cli::parse_from_args(["sipnab", "--limitlen", "256"]);
        assert_eq!(long.limitlen, Some(256));
        let d = Cli::parse_from_args(["sipnab"]);
        assert_eq!(d.limitlen, None);
        assert!(!d.no_reassembly);
    }

    /// `--hep-id` and `--hep-auth` parse; both are `None` when absent.
    #[test]
    fn hep_id_and_auth_flags_parse() {
        let cli = Cli::parse_from_args(["sipnab", "--hep-id", "7", "--hep-auth", "secret"]);
        assert_eq!(cli.hep_id, Some(7));
        assert_eq!(cli.hep_auth.as_deref(), Some("secret"));
        let none = Cli::parse_from_args(["sipnab"]);
        assert_eq!(none.hep_id, None);
        assert_eq!(none.hep_auth, None);
    }

    /// `-p` and `--no-promisc` both set the flag; it defaults off.
    #[test]
    fn no_promisc_short_and_long_flags() {
        assert!(Cli::parse_from_args(["sipnab", "-p"]).no_promisc);
        assert!(Cli::parse_from_args(["sipnab", "--no-promisc"]).no_promisc);
        assert!(!Cli::parse_from_args(["sipnab"]).no_promisc);
    }

    /// `--capture-tunnels` takes an optional value: bare it means the three
    /// IANA tunnel ports, with `=` it means exactly what was typed, and absent
    /// it stays `None` so the auto-filter keeps its narrow default.
    ///
    /// The bare form's default is the `TUNNEL_PORTS_DEFAULT_LIST` constant the
    /// filter builder resolves, so the flag's advertised default and the ports
    /// actually captured cannot drift apart.
    #[test]
    fn capture_tunnels_optional_value() {
        assert_eq!(
            Cli::parse_from_args(["sipnab", "--capture-tunnels"])
                .capture_tunnels
                .as_deref(),
            Some(crate::app::bootstrap::TUNNEL_PORTS_DEFAULT_LIST)
        );
        assert_eq!(
            Cli::parse_from_args(["sipnab", "--capture-tunnels=8472"])
                .capture_tunnels
                .as_deref(),
            Some("8472")
        );
        assert_eq!(
            Cli::parse_from_args(["sipnab"]).capture_tunnels.as_deref(),
            None
        );
    }

    /// `--kill-spoof` defaults to auto, parses raw/ephemeral, and rejects
    /// unknown modes.
    #[test]
    fn kill_spoof_flag_parses_with_auto_default() {
        assert_eq!(Cli::parse_from_args(["sipnab"]).kill_spoof, KillSpoof::Auto);
        assert_eq!(
            Cli::parse_from_args(["sipnab", "--kill-spoof", "raw"]).kill_spoof,
            KillSpoof::Raw
        );
        assert_eq!(
            Cli::parse_from_args(["sipnab", "--kill-spoof", "ephemeral"]).kill_spoof,
            KillSpoof::Ephemeral
        );
        // Unknown mode is rejected by clap's value-enum parsing.
        assert!(Cli::try_parse_from(["sipnab", "--kill-spoof", "bogus"]).is_err());
    }

    /// `-K`/`--kill-target` is repeatable and does not steal the trailing
    /// BPF positional.
    #[test]
    fn kill_target_repeatable_and_coexists() {
        let cli = Cli::parse_from_args([
            "sipnab",
            "-K",
            "10.0.0.1:5060-5090",
            "--kill-target",
            "192.168.1.5",
            "host 10.0.0.1",
        ]);
        assert_eq!(cli.kill_target, vec!["10.0.0.1:5060-5090", "192.168.1.5"]);
        assert_eq!(cli.bpf_filter, vec!["host 10.0.0.1"]);
    }

    /// `validate` fails fast on a malformed `--kill-target` spec.
    #[test]
    fn validate_rejects_bad_kill_target() {
        let cli = Cli::parse_from_args(["sipnab", "-K", "not-an-ip"]);
        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("--kill-target"));
    }

    /// `validate` accepts well-formed v4 port-range and bracketed v6 targets.
    #[test]
    fn validate_accepts_good_kill_targets() {
        let cli = Cli::parse_from_args(["sipnab", "-K", "10.0.0.1:5060-5090", "-K", "[::1]:5060"]);
        assert!(cli.validate().is_ok());
    }

    /// `-e` and `--match` both set the payload match expression.
    #[test]
    fn match_expr_short_and_long_flags() {
        let short = Cli::parse_from_args(["sipnab", "-e", "INVITE sip:"]);
        assert_eq!(short.match_expr.as_deref(), Some("INVITE sip:"));

        let long = Cli::parse_from_args(["sipnab", "--match", "sipsak"]);
        assert_eq!(long.match_expr.as_deref(), Some("sipsak"));

        let none = Cli::parse_from_args(["sipnab"]);
        assert_eq!(none.match_expr, None);
    }

    /// `--proto-number` (long-only) parses; defaults off.
    #[test]
    fn proto_number_flag_parses() {
        // Long-only: `-N` is already taken by `--no-tui`.
        assert!(Cli::parse_from_args(["sipnab", "--proto-number"]).proto_number);
        assert!(!Cli::parse_from_args(["sipnab"]).proto_number);
    }

    /// `--show-empty` and its `--full` alias both set the flag.
    #[test]
    fn show_empty_flag_and_full_alias_parse() {
        assert!(Cli::parse_from_args(["sipnab", "--show-empty"]).show_empty);
        // `--full` is a visible alias of --show-empty.
        assert!(Cli::parse_from_args(["sipnab", "--full"]).show_empty);
        assert!(!Cli::parse_from_args(["sipnab"]).show_empty);
    }

    /// `-x` and `--quiet-bad-parse` both set the flag; defaults off.
    #[test]
    fn quiet_bad_parse_short_and_long_flags() {
        assert!(Cli::parse_from_args(["sipnab", "-x"]).quiet_bad_parse);
        assert!(Cli::parse_from_args(["sipnab", "--quiet-bad-parse"]).quiet_bad_parse);
        assert!(!Cli::parse_from_args(["sipnab"]).quiet_bad_parse);
    }

    /// The `-e` payload expression and the trailing BPF positional stay
    /// independent — neither steals the other's tokens.
    #[test]
    fn match_expr_coexists_with_bpf_positional() {
        // The payload match-expression (-e) and the trailing BPF positional
        // are independent: neither steals the other's tokens.
        let cli = Cli::parse_from_args(["sipnab", "-e", "friendly-scanner", "host", "10.0.0.1"]);
        assert_eq!(cli.match_expr.as_deref(), Some("friendly-scanner"));
        assert_eq!(cli.bpf_filter, vec!["host", "10.0.0.1"]);
    }

    /// The validation error names every offending output flag at once.
    #[test]
    fn validate_multiple_output_flags() {
        let cli = Cli::parse_from_args(["sipnab", "--json", "--report", "--fail2ban"]);
        let err = cli.validate().unwrap_err();
        assert!(err.to_string().contains("--json"));
        assert!(err.to_string().contains("--report"));
        assert!(err.to_string().contains("--fail2ban"));
    }

    /// Every `[quality]` key moves the band a measurement lands in, and every
    /// flag outranks the key it shadows.
    ///
    /// The assertion is on the BAND, not on the field holding the number. Eight
    /// keys that deserialise and are then never consulted is exactly the defect
    /// this wiring exists to prevent, and a field-equality test passes just as
    /// happily when nothing downstream reads the value. Banding a measurement
    /// is the effect an operator sees, so that is what is checked.
    ///
    /// All eight are covered rather than one representative, because the
    /// precedence chain is written out per field: a copy-paste slip in the
    /// seventh is invisible to a test that exercises the first.
    #[test]
    fn every_quality_key_moves_its_band_and_every_flag_outranks_its_key() {
        use crate::rtp::bands::{Band, QualityBands};

        /// One boundary: how to set it from a file, how to set it from the
        /// command line, and a measurement whose band moves when it does.
        struct Case {
            key: &'static str,
            flag: &'static str,
            set_key: fn(&mut crate::config::QualityConfig),
            band_of: fn(&QualityBands, f64) -> Band,
            measurement: f64,
            /// The band the measurement falls in with nothing overridden.
            shipped: Band,
            /// The band it moves to once the file sets this boundary.
            with_key: Band,
            /// A flag value chosen to put the measurement back in `shipped`,
            /// so "the flag won" and "the key was ignored" cannot look alike.
            flag_value: &'static str,
        }

        let cases = [
            Case {
                key: "jitter_warn_ms",
                flag: "--jitter-warn-ms",
                set_key: |q| q.jitter_warn_ms = Some(10.0),
                band_of: |b, v| b.jitter(v),
                measurement: 12.0,
                shipped: Band::Good,
                with_key: Band::Warning,
                flag_value: "20",
            },
            Case {
                key: "jitter_bad_ms",
                flag: "--jitter-bad-ms",
                set_key: |q| q.jitter_bad_ms = Some(35.0),
                band_of: |b, v| b.jitter(v),
                measurement: 40.0,
                shipped: Band::Warning,
                with_key: Band::Bad,
                flag_value: "45",
            },
            Case {
                key: "loss_warn_pct",
                flag: "--loss-warn-pct",
                set_key: |q| q.loss_warn_pct = Some(0.25),
                band_of: |b, v| b.loss(v),
                measurement: 0.5,
                shipped: Band::Good,
                with_key: Band::Warning,
                flag_value: "0.75",
            },
            Case {
                key: "loss_bad_pct",
                flag: "--loss-bad-pct",
                set_key: |q| q.loss_bad_pct = Some(2.0),
                band_of: |b, v| b.loss(v),
                measurement: 3.0,
                shipped: Band::Warning,
                with_key: Band::Bad,
                flag_value: "4",
            },
            Case {
                key: "mos_warn",
                flag: "--mos-warn",
                set_key: |q| q.mos_warn = Some(4.3),
                band_of: |b, v| b.mos(v),
                measurement: 4.2,
                shipped: Band::Good,
                with_key: Band::Warning,
                flag_value: "4.1",
            },
            Case {
                key: "mos_bad",
                flag: "--mos-bad",
                set_key: |q| q.mos_bad = Some(3.6),
                band_of: |b, v| b.mos(v),
                measurement: 3.5,
                shipped: Band::Warning,
                with_key: Band::Bad,
                flag_value: "3.4",
            },
            Case {
                key: "rtt_warn_ms",
                flag: "--rtt-warn-ms",
                set_key: |q| q.rtt_warn_ms = Some(150.0),
                band_of: |b, v| b.rtt(v),
                measurement: 200.0,
                shipped: Band::Good,
                with_key: Band::Warning,
                flag_value: "250",
            },
            Case {
                key: "rtt_bad_ms",
                flag: "--rtt-bad-ms",
                set_key: |q| q.rtt_bad_ms = Some(500.0),
                band_of: |b, v| b.rtt(v),
                measurement: 600.0,
                shipped: Band::Warning,
                with_key: Band::Bad,
                flag_value: "700",
            },
        ];

        let bare = Cli::parse_from_args(["sipnab", "-I", "x.pcap"]);

        for c in &cases {
            // Anti-vacuity: the measurement must start where the case claims,
            // or a "moved" band below would be the fixture and not the wiring.
            let shipped = bare.quality_bands(&crate::config::Config::default());
            assert_eq!(
                (c.band_of)(&shipped, c.measurement),
                c.shipped,
                "{}: {} must start in {:?}, or this case proves nothing",
                c.key,
                c.measurement,
                c.shipped
            );

            let mut tuned = crate::config::Config::default();
            (c.set_key)(&mut tuned.quality);
            assert_eq!(
                (c.band_of)(&bare.quality_bands(&tuned), c.measurement),
                c.with_key,
                "[quality] {} must reach the bands the views paint from",
                c.key
            );

            let flagged = Cli::parse_from_args(["sipnab", "-I", "x.pcap", c.flag, c.flag_value]);
            assert_eq!(
                (c.band_of)(&flagged.quality_bands(&tuned), c.measurement),
                c.shipped,
                "{} must outrank the [quality] {} it shadows",
                c.flag,
                c.key
            );

            // A file that moves one boundary must not disturb the other seven.
            let moved_one = bare.quality_bands(&tuned);
            let shipped_set = QualityBands::default();
            let differences = [
                moved_one.jitter_warn_ms != shipped_set.jitter_warn_ms,
                moved_one.jitter_bad_ms != shipped_set.jitter_bad_ms,
                moved_one.loss_warn_pct != shipped_set.loss_warn_pct,
                moved_one.loss_bad_pct != shipped_set.loss_bad_pct,
                moved_one.mos_warn != shipped_set.mos_warn,
                moved_one.mos_bad != shipped_set.mos_bad,
                moved_one.rtt_warn_ms != shipped_set.rtt_warn_ms,
                moved_one.rtt_bad_ms != shipped_set.rtt_bad_ms,
            ]
            .iter()
            .filter(|d| **d)
            .count();
            assert_eq!(
                differences, 1,
                "setting {} alone must leave the other seven at their defaults",
                c.key
            );
        }
    }

    /// Every truncation/refusal cap resolves flag over key over the SHIPPED
    /// CONSTANT, and the shipped figure is read from the constant the
    /// enforcement site uses rather than restated here.
    ///
    /// Sourcing the default from the constant is the half worth stating: a
    /// resolver carrying its own copy of the number agrees with the code today
    /// and silently disagrees the day one of them moves, which is a limit
    /// documented at one value and enforced at another.
    ///
    /// Each case sets the key and the flag to DIFFERENT values, so "the flag
    /// won" and "the key was never read" cannot look alike.
    #[test]
    fn every_truncation_cap_resolves_flag_over_key_over_the_shipped_constant() {
        /// One cap: how to set it from a file, how to set it from the command
        /// line, and how to ask the resolver what it decided.
        struct Case {
            key: &'static str,
            flag: &'static str,
            set_key: fn(&mut crate::config::LimitsConfig),
            key_value: u64,
            flag_value: &'static str,
            flag_number: u64,
            shipped: u64,
            resolve: fn(&Cli, &crate::config::Config) -> u64,
            /// Arguments the flag cannot be given without.
            requires: &'static [&'static str],
        }

        let cases = [
            Case {
                key: "max_lost_sequences",
                flag: "--max-lost-sequences",
                set_key: |l| l.max_lost_sequences = Some(5_000),
                key_value: 5_000,
                flag_value: "250",
                flag_number: 250,
                shipped: crate::rtp::stream::DEFAULT_LOST_SEQ_LOG_CAP as u64,
                resolve: |c, cfg| c.lost_sequence_log_cap(cfg) as u64,
                requires: &[],
            },
            Case {
                key: "max_groups",
                flag: "--max-groups",
                set_key: |l| l.max_groups = Some(42),
                key_value: 42,
                flag_value: "7",
                flag_number: 7,
                shipped: crate::output::group::DEFAULT_MAX_GROUPS as u64,
                resolve: |c, cfg| c.group_caps(cfg).groups as u64,
                requires: &["--group-by", "call-id"],
            },
            Case {
                key: "max_grouped_messages",
                flag: "--max-grouped-messages",
                set_key: |l| l.max_grouped_messages = Some(900),
                key_value: 900,
                flag_value: "80",
                flag_number: 80,
                shipped: crate::output::group::DEFAULT_MAX_BUFFERED as u64,
                resolve: |c, cfg| c.group_caps(cfg).buffered as u64,
                requires: &["--group-by", "call-id"],
            },
            Case {
                key: "max_metadata_file_bytes",
                flag: "--max-metadata-file-bytes",
                set_key: |l| l.max_metadata_file_bytes = Some(4_294_967_296),
                key_value: 4_294_967_296,
                flag_value: "8589934592",
                flag_number: 8_589_934_592,
                shipped: crate::capture::pcapng_meta::DEFAULT_MAX_METADATA_FILE_BYTES,
                resolve: Cli::metadata_file_byte_cap,
                requires: &[],
            },
            Case {
                key: "max_gunzip_bytes",
                flag: "--max-gunzip-bytes",
                set_key: |l| l.max_gunzip_bytes = Some(2_147_483_648),
                key_value: 2_147_483_648,
                flag_value: "4294967296",
                flag_number: 4_294_967_296,
                shipped: crate::capture::pcap_reader::DEFAULT_MAX_GUNZIP_BYTES,
                resolve: Cli::gunzip_byte_cap,
                requires: &[],
            },
            Case {
                key: "mcp_max_body_bytes",
                flag: "--mcp-max-body-bytes",
                set_key: |l| l.mcp_max_body_bytes = Some(65_536),
                key_value: 65_536,
                flag_value: "1024",
                flag_number: 1024,
                shipped: Cli::DEFAULT_MCP_MAX_BODY_BYTES,
                resolve: |c, cfg| c.mcp_body_cap(cfg) as u64,
                requires: &[],
            },
        ];

        for c in &cases {
            let mut bare_args: Vec<&str> = vec!["sipnab", "-N", "-I", "x.pcap"];
            bare_args.extend_from_slice(c.requires);
            let bare = Cli::parse_from_args(bare_args.clone());

            // Anti-vacuity: the key and flag values must differ from the
            // shipped figure, or every assertion below passes on a broken
            // resolver.
            assert_ne!(
                c.key_value, c.shipped,
                "{}: key value is the default",
                c.key
            );
            assert_ne!(
                c.flag_number, c.key_value,
                "{}: flag and key values must differ",
                c.key
            );

            assert_eq!(
                (c.resolve)(&bare, &crate::config::Config::default()),
                c.shipped,
                "with neither given, {} must resolve to the constant the code \
                 enforces",
                c.key
            );

            let mut tuned = crate::config::Config::default();
            (c.set_key)(&mut tuned.limits);
            assert_eq!(
                (c.resolve)(&bare, &tuned),
                c.key_value,
                "[limits] {} must reach the resolver",
                c.key
            );

            let mut flag_args = bare_args;
            flag_args.push(c.flag);
            flag_args.push(c.flag_value);
            let flagged = Cli::parse_from_args(flag_args);
            assert_eq!(
                (c.resolve)(&flagged, &tuned),
                c.flag_number,
                "{} must outrank the [limits] {} it shadows",
                c.flag,
                c.key
            );
        }
    }

    /// `0` is refused by clap on every byte/count cap, so the permissive
    /// reading — "unlimited" — cannot be reached from the command line either.
    ///
    /// The config layer refuses it by name; a flag that accepted it would make
    /// the guard bypassable by the shorter route.
    #[test]
    fn zero_is_refused_on_every_truncation_flag() {
        for flag in [
            "--max-lost-sequences",
            "--max-metadata-file-bytes",
            "--max-gunzip-bytes",
            "--mcp-max-body-bytes",
        ] {
            let err = Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap", flag, "0"])
                .expect_err("0 must be refused");
            assert!(
                err.to_string().contains("0"),
                "{flag} must refuse 0 and say so: {err}"
            );
        }
        for flag in ["--max-groups", "--max-grouped-messages"] {
            let err = Cli::try_parse_from([
                "sipnab",
                "-N",
                "-I",
                "x.pcap",
                "--group-by",
                "call-id",
                flag,
                "0",
            ])
            .expect_err("0 must be refused");
            assert!(
                err.to_string().contains("0"),
                "{flag} must refuse 0 and say so: {err}"
            );
        }
    }

    /// `--max-groups` and `--max-grouped-messages` arm nothing without
    /// `--group-by`, so clap refuses them alone.
    ///
    /// The same rule commit 30a5689 applied to the detection flags: a flag
    /// accepted and then ignored looks, from the operator's side, exactly like
    /// one that worked.
    #[test]
    fn the_group_caps_are_refused_without_the_grouping_they_bound() {
        for flag in ["--max-groups", "--max-grouped-messages"] {
            let err = Cli::try_parse_from(["sipnab", "-N", "-I", "x.pcap", flag, "5"])
                .expect_err("must require --group-by");
            assert!(
                err.to_string().contains("--group-by"),
                "{flag} without --group-by must name what it needs: {err}"
            );
        }
    }
}
