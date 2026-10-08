// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every config-file key, with accepted, boundary and refused values.
//!
//! [`KEY_SPECS`] has one row per key sipnab recognizes: every `[section] key`
//! a flag row in `sipnab::settings::FLAGS` names, plus every key in
//! `sipnab::settings::FILE_ONLY`. That union is the recognized-key table,
//! which the `settings` unit tests hold equal to the loader's own. So a key
//! added to the loader without a row here fails
//! `every_key_has_exactly_one_spec_row`.
//!
//! Each value is written to a config file and run through the startup
//! pipeline (`support/config_cli.rs`: parse, `Cli::validate`,
//! `bootstrap::load_config`, `bootstrap::plan`) with `-f`:
//!
//! - an accepted value must load and read back from `--dump-config`'s
//!   serialization (`Config::dump`) as the value written, at the same
//!   `[section] key`;
//! - a refused value must fail before anything runs (exit 1 from
//!   `load_config`, exit 2 from `plan`) with a message naming the key and
//!   no run of spaces in it;
//! - a value of the wrong TOML type is refused for every key;
//! - nothing panics.
//!
//! The rows were first generated from the loader's observed behavior and
//! then reviewed against each key's documentation; every disagreement found
//! is a defect with its own test in `config_cli_defects_test.rs`.
#![cfg(feature = "full")]

#[path = "support/config_cli.rs"]
mod config_cli;

use std::collections::BTreeSet;

use config_cli::{Outcome, Stage, TestError, argv, field_debug, run};
use sipnab::settings::{FILE_ONLY, FLAGS, Link};

/// The shape of a key's value and what the row asserts about it.
#[derive(Debug)]
enum KeyKind {
    /// A TOML boolean.
    Bool,
    /// A TOML integer, accepted from `lo` to `hi` inclusive.
    Int { lo: i128, hi: i128 },
    /// A TOML float.
    Real {
        accept: &'static [&'static str],
        reject: &'static [&'static str],
    },
    /// Any other value, as TOML literals. `ctx` is written into the same
    /// section first (the other half of a certificate/key pair).
    Literal {
        accept: &'static [&'static str],
        reject: &'static [&'static str],
        ctx: &'static str,
    },
}

/// One row per recognized key.
type KeySpec = (&'static str, &'static str, KeyKind);

/// Every key sipnab recognizes.
static KEY_SPECS: &[KeySpec] = &[
    (
        "action_limits",
        "address_cooldown_secs",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "action_limits",
        "default_ban_secs",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "action_limits",
        "max_ban_secs",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "action_limits",
        "per_caller_per_minute",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "action_limits",
        "per_minute",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "actions",
        "tfps",
        KeyKind::Literal {
            accept: &["[]", "[\"rest\"]"],
            reject: &[
                "[\"x\"]",
                "[\"syslog\"]",
                "[\"json\", \"syslog\"]",
                "[\"full\"]",
                "[\"tfps\"]",
                "[\"From\", \"Call-ID\"]",
            ],
            ctx: "",
        },
    ),
    (
        "api",
        "allowed_hosts",
        KeyKind::Literal {
            accept: &["[]", "[\"x\"]", "[\"syslog\"]", "[\"json\", \"syslog\"]"],
            reject: &["[1]"],
            ctx: "",
        },
    ),
    (
        "api",
        "tls_cert",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_key = \"/nonexistent/sipnab-key\"",
        },
    ),
    (
        "api",
        "tls_key",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_cert = \"/nonexistent/sipnab-cert\"",
        },
    ),
    (
        "capture",
        "bpf_filter",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    (
        "capture",
        "buffer",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "capture",
        "buffer_budget_mb",
        KeyKind::Int {
            lo: 0,
            hi: 4294967295,
        },
    ),
    (
        "capture",
        "device",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    ("capture", "hep_parse", KeyKind::Bool),
    ("capture", "no_rtp", KeyKind::Bool),
    (
        "capture",
        "node_name",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "capture",
        "portrange",
        KeyKind::Literal {
            accept: &["\"5060-5061\"", "\"8-18\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
            ],
            ctx: "",
        },
    ),
    ("capture", "promisc", KeyKind::Bool),
    (
        "capture",
        "snaplen",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "capture",
        "ws_ports",
        KeyKind::Literal {
            accept: &["\"5060-5061\"", "\"8-18\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
            ],
            ctx: "",
        },
    ),
    ("crash", "backtrace", KeyKind::Bool),
    ("crash", "core", KeyKind::Bool),
    (
        "crash",
        "report_dir",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    ("crash", "reports", KeyKind::Bool),
    (
        "diagnosis",
        "ack_timeout_secs",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "1e308"],
            reject: &["0.0", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "diagnosis",
        "cn_suppression_ratio",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0"],
            reject: &[
                "0.0", "5.0", "100.0", "101.0", "1e308", "-1.0", "nan", "inf", "-inf",
            ],
        },
    ),
    (
        "diagnosis",
        "duration_asymmetry_pct",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0", "5.0", "100.0"],
            reject: &["0.0", "101.0", "1e308", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "diagnosis",
        "duration_asymmetry_secs",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "1e308"],
            reject: &["0.0", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "diagnosis",
        "late_media_ms",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "diagnosis",
        "no_final_response_secs",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "1e308"],
            reject: &["0.0", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "diagnosis",
        "post_dial_delay_secs",
        KeyKind::Real {
            accept: &["0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "1e308"],
            reject: &["0.0", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "display",
        "color",
        KeyKind::Literal {
            accept: &["\"auto\"", "\"always\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    ("display", "delta_time", KeyKind::Bool),
    (
        "display",
        "from_to",
        KeyKind::Literal {
            accept: &[
                "\"default\"",
                "\"host-port\"",
                "\"user\"",
                "\"user-host-port\"",
            ],
            reject: &["\"x\"", "\"\"", "\"hostport\"", "\"Host-Port\""],
            ctx: "",
        },
    ),
    (
        "display",
        "payload_limit",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "display",
        "visible_columns",
        KeyKind::Literal {
            accept: &["[]", "[\"From\", \"To\"]", "[\"#\", \"state\", \"PDD\"]"],
            reject: &["[\"x\"]", "[\"From\", \"Too\"]", "[1]", "\"From\""],
            ctx: "",
        },
    ),
    (
        "filter",
        "expression",
        KeyKind::Literal {
            accept: &["\"method == \\\"INVITE\\\"\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "filter",
        "from",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    (
        "filter",
        "to",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    (
        "hep",
        "tls_ca",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "hep",
        "tls_cert",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "hep",
        "tls_extra_ca",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "hep",
        "tls_key",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "journal",
        "dir",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "autoscroll",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "clear_calls",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "column_selector",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "extended_flow",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "filter",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "help",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "pause",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "quit",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "save",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "search",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "keybindings",
        "settings",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"q\""],
            reject: &[
                "\"\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
                "\"/nonexistent/sipnab-x\"",
            ],
            ctx: "",
        },
    ),
    (
        "limits",
        "api_max_rows",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "api_rate_limit_per_peer",
        KeyKind::Int {
            lo: 0,
            hi: 4294967295,
        },
    ),
    (
        "limits",
        "dialog_limit",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "exec_queue_depth",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "hep_rate_limit",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "idle_compact_after_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "keep_messages_per_idle_dialog",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "lint_max_per_rule",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_audio_frames",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_capture_sources",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_grouped_messages",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_groups",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_gunzip_bytes",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_header_line",
        KeyKind::Int {
            lo: 256,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_headers_per_message",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_lost_sequences",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_messages_per_dialog",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_metadata_file_bytes",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_reassembly",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_streams",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_tcp_buffer",
        KeyKind::Int {
            lo: 8192,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "max_tracked_peers",
        KeyKind::Int {
            lo: 2,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "mcp_max_body_bytes",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "mcp_max_findings",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "mcp_max_rows",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "mcp_max_wait_seconds",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "mcp_sweep_deadline_ms",
        KeyKind::Int {
            lo: 1,
            hi: 43200000,
        },
    ),
    (
        "limits",
        "mcp_sweep_max_files",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "limits",
        "metrics_max_conn",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "limits",
        "quality_interval_secs",
        KeyKind::Int { lo: 1, hi: 300 },
    ),
    (
        "limits",
        "reassembly_ttl_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "mcp",
        "bundles",
        KeyKind::Literal {
            accept: &["{}"],
            reject: &[
                "{ a = 1.0 }",
                "{ g711 = 0.0 }",
                "{ PCMU = 0.0 }",
                "{ a = -1.0 }",
                "{ a = \"x\" }",
            ],
            ctx: "",
        },
    ),
    ("mcp", "output_schemas", KeyKind::Bool),
    (
        "mcp",
        "tls_cert",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_key = \"/nonexistent/sipnab-key\"",
        },
    ),
    (
        "mcp",
        "tls_key",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_cert = \"/nonexistent/sipnab-cert\"",
        },
    ),
    (
        "mcp",
        "tools",
        KeyKind::Literal {
            accept: &["[\"full\"]", "[\"tfps\"]"],
            reject: &[
                "[]",
                "[\"x\"]",
                "[\"syslog\"]",
                "[\"json\", \"syslog\"]",
                "[\"rest\"]",
                "[\"From\", \"Call-ID\"]",
            ],
            ctx: "",
        },
    ),
    (
        "media",
        "codec_ie",
        KeyKind::Literal {
            accept: &["{}", "{ a = 1.0 }", "{ g711 = 0.0 }", "{ PCMU = 0.0 }"],
            reject: &["{ a = -1.0 }", "{ a = \"x\" }"],
            ctx: "",
        },
    ),
    (
        "media",
        "listening_context",
        KeyKind::Literal {
            accept: &["\"monotic\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "media",
        "one_way_delay_ms",
        KeyKind::Real {
            accept: &[
                "0.0", "0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "1e308",
            ],
            reject: &["-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "metrics",
        "tls_cert",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_key = \"/nonexistent/sipnab-key\"",
        },
    ),
    (
        "metrics",
        "tls_key",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\""],
            reject: &["\"\""],
            ctx: "tls_cert = \"/nonexistent/sipnab-cert\"",
        },
    ),
    (
        "names",
        "dns_cache_entries",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    ("names", "enabled", KeyKind::Bool),
    (
        "names",
        "hosts_file",
        KeyKind::Literal {
            accept: &["\"/dev/null\""],
            reject: &["\"x\"", "\"\"", "\"/nonexistent/sipnab-x\"", "\"/var/tmp\""],
            ctx: "",
        },
    ),
    (
        "names",
        "manual",
        KeyKind::Literal {
            accept: &[
                "{}",
                "{ \"10.0.0.1\" = \"edge\" }",
                "{ \"2001:db8::1\" = \"core\" }",
            ],
            reject: &[
                "{ a = \"x\" }",
                "{ \"10.0.0.1\" = \"\" }",
                "{ \"10.0.0.1\" = 1 }",
                "[]",
            ],
            ctx: "",
        },
    ),
    ("names", "persist_to_config", KeyKind::Bool),
    ("names", "reverse_dns", KeyKind::Bool),
    (
        "privilege",
        "chroot",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    ("privilege", "no_priv_drop", KeyKind::Bool),
    (
        "privilege",
        "user",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    (
        "quality",
        "jitter_bad_ms",
        KeyKind::Real {
            accept: &["100.0", "101.0", "1e308"],
            reject: &[
                "0.0", "0.001", "0.5", "1.0", "5.0", "-1.0", "nan", "inf", "-inf",
            ],
        },
    ),
    (
        "quality",
        "jitter_warn_ms",
        KeyKind::Real {
            accept: &["0.0", "0.001", "0.5", "1.0", "5.0"],
            reject: &["100.0", "101.0", "1e308", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "quality",
        "loss_bad_pct",
        KeyKind::Real {
            accept: &["1.0", "5.0", "100.0"],
            reject: &[
                "0.0", "0.001", "0.5", "101.0", "1e308", "-1.0", "nan", "inf", "-inf",
            ],
        },
    ),
    (
        "quality",
        "loss_warn_pct",
        KeyKind::Real {
            accept: &["0.0", "0.001", "0.5", "1.0", "5.0"],
            reject: &["100.0", "101.0", "1e308", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "quality",
        "mos_bad",
        KeyKind::Real {
            accept: &["0.0", "0.001", "0.5", "1.0"],
            reject: &[
                "5.0", "100.0", "101.0", "1e308", "-1.0", "nan", "inf", "-inf",
            ],
        },
    ),
    (
        "quality",
        "mos_warn",
        KeyKind::Real {
            accept: &["5.0"],
            reject: &[
                "0.0", "0.001", "0.5", "1.0", "100.0", "101.0", "1e308", "-1.0", "nan", "inf",
                "-inf",
            ],
        },
    ),
    (
        "quality",
        "rtt_bad_ms",
        KeyKind::Real {
            accept: &["1e308"],
            reject: &[
                "0.0", "0.001", "0.5", "1.0", "5.0", "100.0", "101.0", "-1.0", "nan", "inf", "-inf",
            ],
        },
    ),
    (
        "quality",
        "rtt_warn_ms",
        KeyKind::Real {
            accept: &["0.0", "0.001", "0.5", "1.0", "5.0", "100.0", "101.0"],
            reject: &["1e308", "-1.0", "nan", "inf", "-inf"],
        },
    ),
    (
        "security",
        "alert",
        KeyKind::Literal {
            accept: &["[]", "[\"syslog\"]", "[\"json\", \"syslog\"]"],
            reject: &[
                "[\"x\"]",
                "[\"full\"]",
                "[\"tfps\"]",
                "[\"rest\"]",
                "[\"From\", \"Call-ID\"]",
                "[\"X-CID\"]",
            ],
            ctx: "",
        },
    ),
    (
        "security",
        "alert_exec",
        KeyKind::Literal {
            accept: &["\"x\"", "\"\"", "\" \"", "\"0\""],
            reject: &[],
            ctx: "",
        },
    ),
    (
        "security",
        "business_hours",
        KeyKind::Literal {
            accept: &["\"8-18\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"127.0.0.1:9999\"",
            ],
            ctx: "",
        },
    ),
    (
        "security",
        "findings_history",
        KeyKind::Int {
            lo: 0,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "fraud_destination",
        KeyKind::Literal {
            accept: &["\"\"", "\" \"", "\"CU,KP\""],
            reject: &[
                "\"x\"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
                "\"127.0.0.1:9999\"",
                "\"/var/tmp\"",
            ],
            ctx: "",
        },
    ),
    ("security", "fraud_detect", KeyKind::Bool),
    (
        "security",
        "fraud_sequential_calls",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "fraud_short_call_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "fraud_volume_min_calls",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "fraud_volume_multiplier",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "fraud_volume_window_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "fraud_wangiri_calls",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "fraud_wangiri_window_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "hep_hmac_window_secs",
        KeyKind::Int { lo: 1, hi: 300 },
    ),
    (
        "security",
        "kill_rate_limit",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "kill_response",
        KeyKind::Int { lo: 100, hi: 699 },
    ),
    ("security", "kill_scanner", KeyKind::Bool),
    (
        "security",
        "reg_flood_threshold",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "reg_flood_transaction_timeout_ms",
        KeyKind::Int {
            lo: 1000,
            hi: 600000,
        },
    ),
    (
        "security",
        "reg_flood_window_secs",
        KeyKind::Int { lo: 1, hi: 3600 },
    ),
    (
        "security",
        "scanner_answer_grace_ms",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "scanner_behavioral_probes",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "scanner_enumeration_targets",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "security",
        "scanner_established_factor",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "scanner_rejected_probes",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "scanner_unanswered_probes",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "security",
        "scanner_window_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "sip",
        "active_idle_window_secs",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "sip",
        "leg_correlation_window_ms",
        KeyKind::Int {
            lo: 1,
            hi: i64::MAX as i128,
        },
    ),
    (
        "sip",
        "xcid_headers",
        KeyKind::Literal {
            accept: &["[]", "[\"x\"]", "[\"syslog\"]", "[\"json\", \"syslog\"]"],
            reject: &["[1]"],
            ctx: "",
        },
    ),
    (
        "tfps",
        "ctl",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "tfps",
        "db",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"5060-5061\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "theme",
        "accent",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "background",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "bad",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "border",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "foreground",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "good",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "header",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "highlight",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "muted",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "selected",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "status_bg",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "theme",
        "warning",
        KeyKind::Literal {
            accept: &["\"red\""],
            reject: &[
                "\"x\"",
                "\"\"",
                "\" \"",
                "\"0\"",
                "\"5060-5061\"",
                "\"8-18\"",
            ],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "auth_file",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"/var/spool/sipnab-vcon\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "backoff_cap",
        KeyKind::Int {
            lo: 2,
            hi: 4294967295,
        },
    ),
    (
        "vcon_forward",
        "backoff_first",
        KeyKind::Int { lo: 1, hi: 300 },
    ),
    (
        "vcon_forward",
        "ca",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"/var/spool/sipnab-vcon\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "compat",
        KeyKind::Literal {
            accept: &["\"none\"", "\"vcon-store\""],
            reject: &["\"x\"", "\"\"", "\" \"", "\"VCON-STORE\"", "\"off\""],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "done",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"/var/spool/sipnab-vcon\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "failed",
        KeyKind::Literal {
            accept: &["\"x\"", "\" \"", "\"0\"", "\"/var/spool/sipnab-vcon\""],
            reject: &["\"\""],
            ctx: "",
        },
    ),
    ("vcon_forward", "interval", KeyKind::Int { lo: 1, hi: 3600 }),
    (
        "vcon_forward",
        "kind",
        KeyKind::Literal {
            accept: &["\"generic\"", "\"vcon-store\"", "\"conserver\""],
            reject: &["\"x\"", "\"\"", "\" \"", "\"VCON-STORE\"", "\"none\""],
            ctx: "",
        },
    ),
    (
        "vcon_forward",
        "max_error_body",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "vcon_forward",
        "max_response_head",
        KeyKind::Int {
            lo: 1,
            hi: 4294967295,
        },
    ),
    (
        "vcon_forward",
        "replace_url",
        KeyKind::Literal {
            accept: &[
                "\"https://store.example.com/v1/vcons/{uuid}\"",
                "\"x\"",
                "\"\"",
            ],
            reject: &[],
            ctx: "",
        },
    ),
    ("vcon_forward", "timeout", KeyKind::Int { lo: 1, hi: 600 }),
    (
        "vcon_forward",
        "url",
        KeyKind::Literal {
            accept: &["\"https://store.example.com/v1/vcons\"", "\"x\"", "\"\""],
            reject: &[],
            ctx: "",
        },
    ),
];

/// Every recognized `(section, key)`, from the settings table.
fn recognized_keys() -> BTreeSet<(&'static str, &'static str)> {
    let mut keys = BTreeSet::new();
    for (_, link) in FLAGS {
        if let Link::Key(section, key, _) = link {
            keys.insert((*section, *key));
        }
    }
    for (section, key, _) in FILE_ONLY {
        keys.insert((*section, *key));
    }
    keys
}

/// A loaded file and its pipeline outcome.
struct Loaded {
    /// The pipeline's verdict.
    outcome: Outcome,
    /// `[section] key` read back from `Config::dump`, when the file loaded.
    dumped: Option<toml::Value>,
}

/// Write `[section]\n{ctx}\n{key} = {literal}` and run the pipeline on it.
fn load(section: &str, key: &str, literal: &str, ctx: &str) -> Result<Loaded, TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    let body = if ctx.is_empty() {
        format!("[{section}]\n{key} = {literal}\n")
    } else {
        format!("[{section}]\n{ctx}\n{key} = {literal}\n")
    };
    std::fs::write(&path, body)?;
    let outcome = run(&argv(&[]), Some(&path));
    let dumped = if outcome.accepted() {
        let loaded = sipnab::config::Config::load(Some(&path.display().to_string()), false)?;
        let text = loaded.config.dump()?;
        let value: toml::Value = toml::from_str(&text)?;
        value.get(section).and_then(|s| s.get(key)).cloned()
    } else {
        None
    };
    Ok(Loaded { outcome, dumped })
}

/// Whether two TOML values are the same setting: equal, or equal numbers.
fn same_value(written: &toml::Value, read: &toml::Value) -> bool {
    match (written, read) {
        (toml::Value::Integer(a), toml::Value::Float(b))
        | (toml::Value::Float(b), toml::Value::Integer(a)) => (*a as f64) == *b,
        (toml::Value::Float(a), toml::Value::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        (toml::Value::Table(a), toml::Value::Table(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| same_value(v, w)))
        }
        _ => written == read,
    }
}

/// Parse a TOML literal as a value.
fn literal_value(literal: &str) -> Result<toml::Value, TestError> {
    let doc: toml::Table = toml::from_str(&format!("v = {literal}"))?;
    doc.get("v")
        .cloned()
        .ok_or_else(|| "literal did not parse".into())
}

/// A mismatch when `literal` is not accepted and read back unchanged.
fn check_accepted(
    section: &str,
    key: &str,
    literal: &str,
    ctx: &str,
) -> Result<Option<String>, TestError> {
    let what = format!("[{section}] {key} = {literal}");
    let l = load(section, key, literal, ctx)?;
    if let Some(p) = &l.outcome.panic {
        return Ok(Some(format!("{what}: panicked: {p}")));
    }
    if !l.outcome.accepted() {
        return Ok(Some(format!(
            "{what}: want accepted, got {:?}/{}: {}",
            l.outcome.stage, l.outcome.code, l.outcome.message
        )));
    }
    let written = literal_value(literal)?;
    match l.dumped {
        Some(read) if same_value(&written, &read) => Ok(None),
        // An empty table or list may serialize as absent.
        None if written.as_table().is_some_and(toml::Table::is_empty)
            || written.as_array().is_some_and(Vec::is_empty) =>
        {
            Ok(None)
        }
        other => Ok(Some(format!("{what}: read back as {other:?}"))),
    }
}

/// Whether `message` names `[section] key`: in that spelling, as the dotted
/// path TOML errors use, or as the `[section.key]` table it is.
fn names_key(message: &str, section: &str, key: &str) -> bool {
    message.contains(&format!("[{section}] {key}"))
        || message.contains(&format!("{section}.{key}"))
        || message.contains(&format!("[{section}.{key}]"))
}

/// A mismatch when `literal` is not refused with exit 1 naming the key.
fn check_refused(
    section: &str,
    key: &str,
    literal: &str,
    ctx: &str,
) -> Result<Option<String>, TestError> {
    let what = format!("[{section}] {key} = {literal}");
    let l = load(section, key, literal, ctx)?;
    let o = &l.outcome;
    if let Some(p) = &o.panic {
        return Ok(Some(format!("{what}: panicked: {p}")));
    }
    if o.accepted() {
        return Ok(Some(format!("{what}: want refused, was accepted")));
    }
    // A refused config value exits 1, whichever step refuses it: one class
    // of error, one exit code. `load_config` refuses most keys; `plan`
    // refuses the ones it resolves (a filter expression, a port range, an
    // action or alert name, an MCP tool).
    if !matches!(o.stage, Stage::Config | Stage::Plan) || o.code != 1 {
        return Ok(Some(format!(
            "{what}: want a config or plan refusal, got {:?}/{}: {}",
            o.stage, o.code, o.message
        )));
    }
    if !names_key(&o.message, section, key) {
        return Ok(Some(format!(
            "{what}: refusal does not name the key: {}",
            o.message
        )));
    }
    if o.message.contains("   ") {
        return Ok(Some(format!(
            "{what}: refusal has a run of spaces: {}",
            o.message
        )));
    }
    Ok(None)
}

/// Turn collected mismatches into a test result.
fn verdict(failures: Vec<String>) -> Result<(), TestError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("{} failure(s):\n{}", failures.len(), failures.join("\n")).into())
    }
}

/// Whether `literal` deserializes into `Config` at `[section] key`.
fn deserializes(section: &str, key: &str, literal: &str) -> bool {
    toml::from_str::<sipnab::config::Config>(&format!("[{section}]\n{key} = {literal}\n")).is_ok()
}

/// The kind the deserializer implies for a key.
fn kind_name_of(section: &str, key: &str) -> &'static str {
    if deserializes(section, key, "true") {
        "Bool"
    } else if deserializes(section, key, "1") && !deserializes(section, key, "1.5") {
        "Int"
    } else if deserializes(section, key, "1.5") {
        "Real"
    } else {
        "Literal"
    }
}

/// The name of a row's kind.
fn kind_name(kind: &KeyKind) -> &'static str {
    match kind {
        KeyKind::Bool => "Bool",
        KeyKind::Int { .. } => "Int",
        KeyKind::Real { .. } => "Real",
        KeyKind::Literal { .. } => "Literal",
    }
}

/// The registry: one row per recognized key, none for a key that is not
/// recognized, each row's kind matching what the key deserializes as.
#[test]
fn every_key_has_exactly_one_spec_row() -> Result<(), TestError> {
    let keys = recognized_keys();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for (section, key, kind) in KEY_SPECS {
        if !seen.insert((*section, *key)) {
            failures.push(format!("[{section}] {key}: more than one row"));
        }
        if !keys.contains(&(*section, *key)) {
            failures.push(format!(
                "[{section}] {key}: row for a key sipnab does not recognize"
            ));
        }
        if kind_name_of(section, key) != kind_name(kind) {
            failures.push(format!(
                "[{section}] {key}: row says {}, the loader says {}",
                kind_name(kind),
                kind_name_of(section, key)
            ));
        }
    }
    for (section, key) in &keys {
        if !seen.contains(&(*section, *key)) {
            failures.push(format!("[{section}] {key}: no row in KEY_SPECS; add one"));
        }
    }
    if keys.len() < 150 {
        failures.push(format!("only {} recognized keys", keys.len()));
    }
    verdict(failures)
}

/// Booleans: both values load and read back; anything else is refused.
#[test]
fn bool_keys_accept_both_values_and_refuse_others() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, kind) in KEY_SPECS {
        if !matches!(kind, KeyKind::Bool) {
            continue;
        }
        for v in ["true", "false"] {
            failures.extend(check_accepted(section, key, v, "")?);
        }
        for v in ["\"true\"", "1", "\"yes\""] {
            failures.extend(check_refused(section, key, v, "")?);
        }
    }
    verdict(failures)
}

/// Integers: both edges and the middle load and read back; one past each
/// edge (where TOML can write it) and every non-integer is refused.
#[test]
fn int_keys_accept_their_range_and_refuse_its_neighbors() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, kind) in KEY_SPECS {
        let KeyKind::Int { lo, hi } = kind else {
            continue;
        };
        let mid = lo + (hi - lo) / 2;
        for v in [*lo, mid, *hi] {
            failures.extend(check_accepted(section, key, &v.to_string(), "")?);
        }
        let mut refused: Vec<String> = vec!["\"1\"".into(), "1.5".into(), "true".into()];
        if *lo > i128::from(i64::MIN) {
            refused.push((lo - 1).to_string());
        }
        if *hi < i128::from(i64::MAX) {
            refused.push((hi + 1).to_string());
        }
        for v in refused {
            failures.extend(check_refused(section, key, &v, "")?);
        }
    }
    verdict(failures)
}

/// Floats: each accepted value reads back as written; each refused value is
/// refused naming the key, and `nan` is always among them.
#[test]
fn real_keys_accept_and_refuse_their_listed_values() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, kind) in KEY_SPECS {
        let KeyKind::Real { accept, reject } = kind else {
            continue;
        };
        for v in *accept {
            failures.extend(check_accepted(section, key, v, "")?);
        }
        for v in *reject {
            failures.extend(check_refused(section, key, v, "")?);
        }
        if !reject.contains(&"nan") {
            failures.push(format!(
                "[{section}] {key}: nan is not among the refused values"
            ));
        }
        failures.extend(check_refused(section, key, "\"1.0\"", "")?);
    }
    verdict(failures)
}

/// Strings, lists and tables: each accepted literal reads back as written;
/// each refused one is refused naming the key.
#[test]
fn literal_keys_accept_and_refuse_their_listed_values() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, kind) in KEY_SPECS {
        let KeyKind::Literal {
            accept,
            reject,
            ctx,
        } = kind
        else {
            continue;
        };
        for v in *accept {
            failures.extend(check_accepted(section, key, v, ctx)?);
        }
        for v in *reject {
            failures.extend(check_refused(section, key, v, ctx)?);
        }
    }
    verdict(failures)
}

/// Every key refuses every TOML type it is not, naming the key.
#[test]
fn every_key_refuses_the_wrong_toml_type() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, kind) in KEY_SPECS {
        let wrong: &[&str] = match kind {
            KeyKind::Bool => &["\"x\"", "1", "1.5", "[]", "{}"],
            KeyKind::Int { .. } => &["\"x\"", "true", "1.5", "[]", "{}"],
            KeyKind::Real { .. } => &["\"x\"", "true", "[]", "{}"],
            KeyKind::Literal { .. } => &["true", "1.5"],
        };
        for v in wrong {
            failures.extend(check_refused(section, key, v, "")?);
        }
    }
    verdict(failures)
}

/// Values no row lists cannot panic any step, and end in exit 0, 1 or 2.
#[test]
fn hostile_key_values_never_panic() -> Result<(), TestError> {
    let huge = format!("\"{}\"", "a".repeat(65_536));
    let hostile = [
        huge.as_str(),
        "\"\\u0000\"",
        "\"${HOME}\"",
        "\"\\u202e\"",
        "-9223372036854775808",
        "9223372036854775807",
        "-0.0",
        "1e-320",
        "[[]]",
        "{ a = { b = { c = 1 } } }",
        "1979-05-27T07:32:00Z",
    ];
    let mut failures = Vec::new();
    for (section, key, _) in KEY_SPECS {
        for v in hostile {
            let l = load(section, key, v, "")?;
            if let Some(p) = &l.outcome.panic {
                failures.push(format!("[{section}] {key}: panicked: {p}"));
            } else if !(0..=2).contains(&l.outcome.code) {
                failures.push(format!("[{section}] {key}: exit {}", l.outcome.code));
            }
        }
    }
    verdict(failures)
}

/// A file that is not TOML, and a section that is not a table, are refused
/// with exit 1 naming the file.
#[test]
fn malformed_files_are_refused_naming_the_file() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for body in [
        "[capture\n",
        "capture = 1\n",
        "[capture]\nsnaplen = \n",
        "[capture]\nsnaplen = 1\nsnaplen = 2\n",
        "\u{feff}[capture]\nsnaplen = 1\n\u{0}",
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("broken.toml");
        std::fs::write(&path, body)?;
        let o = run(&argv(&[]), Some(&path));
        if o.panic.is_some() || o.accepted() || o.code != 1 || !o.message.contains("broken.toml") {
            failures.push(format!("{body:?}: {:?}/{} {}", o.stage, o.code, o.message));
        }
    }
    verdict(failures)
}

/// Unknown keys are tolerated (a file written for a newer sipnab still
/// starts) and reported by `Config::unknown_keys`, by full path.
#[test]
fn unknown_keys_load_and_are_reported() -> Result<(), TestError> {
    let body = "[capture]\nsnaplenn = 1\n[nosuchsection]\nx = 1\n";
    let unknown = sipnab::config::Config::unknown_keys(body)?;
    let mut failures = Vec::new();
    for want in ["capture.snaplenn", "nosuchsection"] {
        if !unknown.iter().any(|u| u.contains(want)) {
            failures.push(format!("{want} not reported in {unknown:?}"));
        }
    }
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    std::fs::write(&path, body)?;
    let o = run(&argv(&[]), Some(&path));
    if !o.accepted() {
        failures.push(format!(
            "a file with unknown keys was refused: {}",
            o.message
        ));
    }
    // And a known key still lands when an unknown one sits beside it.
    std::fs::write(&path, "[display]\ncolor = \"never\"\nnosuch = 1\n")?;
    let o = run(&argv(&[]), Some(&path));
    let color = o.cli.as_deref().and_then(|c| field_debug(c, "color"));
    if !o.accepted() || color.is_none() {
        failures.push(format!("known key beside an unknown one: {:?}", o.message));
    }
    verdict(failures)
}

/// The literal for one random draw from one key row.
fn drawn_literal(kind: &KeyKind, accept: bool, pick: usize) -> Option<String> {
    match kind {
        KeyKind::Bool => Some(if accept { "true" } else { "\"maybe\"" }.to_string()),
        KeyKind::Int { lo, hi } => {
            let mid = lo + (hi - lo) / 2;
            let v = if accept {
                [*lo, mid, *hi][pick % 3]
            } else {
                [lo - 1, hi + 1, lo - 1][pick % 3]
            };
            let in_toml = i128::from(i64::MIN) <= v && v <= i128::from(i64::MAX);
            in_toml.then(|| v.to_string())
        }
        KeyKind::Real {
            accept: a,
            reject: r,
        } => {
            let list = if accept { *a } else { *r };
            list.get(pick % list.len().max(1)).map(|s| (*s).to_string())
        }
        KeyKind::Literal {
            accept: a,
            reject: r,
            ..
        } => {
            let list = if accept || r.is_empty() { *a } else { *r };
            list.get(pick % list.len().max(1)).map(|s| (*s).to_string())
        }
    }
}

/// Random config files of up to six keys, each with an accepted or a
/// refused value from its row, from a fixed seed: nothing panics, every run
/// ends in exit 0, 1 or 2, and every refusal names one of the keys written.
#[test]
fn random_config_files_hold_the_invariants() -> Result<(), TestError> {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
    let config = Config {
        cases: 300,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    let draws = prop::collection::vec((0..KEY_SPECS.len(), any::<bool>(), 0usize..64), 1..7);
    let outcome = runner.run(&draws, |picks| {
        let mut by_section: std::collections::BTreeMap<&str, Vec<String>> =
            std::collections::BTreeMap::new();
        let mut written: Vec<(&str, &str)> = Vec::new();
        for (index, accept, pick) in picks {
            let Some((section, key, kind)) = KEY_SPECS.get(index) else {
                continue;
            };
            if written.contains(&(*section, *key)) {
                continue;
            }
            let Some(lit) = drawn_literal(kind, accept, pick) else {
                continue;
            };
            // The other half of a pair is written once, as context, and is
            // then not drawn again.
            let partner = match kind {
                KeyKind::Literal { ctx, .. } if !ctx.is_empty() => {
                    ctx.split(" =").next().map(|k| (*ctx, k))
                }
                _ => None,
            };
            let lines = by_section.entry(section).or_default();
            if let Some((ctx, partner_key)) = partner
                && !written
                    .iter()
                    .any(|(s, k)| s == section && *k == partner_key)
            {
                lines.push(ctx.to_string());
                if let Some((_, k, _)) = KEY_SPECS
                    .iter()
                    .find(|(s, k, _)| s == section && *k == partner_key)
                {
                    written.push((section, k));
                }
            }
            lines.push(format!("{key} = {lit}"));
            written.push((section, key));
        }
        let body: String = by_section
            .iter()
            .map(|(s, lines)| format!("[{s}]\n{}\n", lines.join("\n")))
            .collect();
        std::fs::write(&path, &body).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let o = run(&argv(&[]), Some(&path));
        if let Some(p) = &o.panic {
            return Err(TestCaseError::fail(format!("{body}: panicked: {p}")));
        }
        if !(0..=2).contains(&o.code) {
            return Err(TestCaseError::fail(format!("{body}: exit {}", o.code)));
        }
        if !o.accepted() && !written.iter().any(|(s, k)| names_key(&o.message, s, k)) {
            return Err(TestCaseError::fail(format!(
                "{body}: {:?}/{} names no written key: {}",
                o.stage, o.code, o.message
            )));
        }
        Ok(())
    });
    outcome.map_err(|e| e.to_string().into())
}

/// Run the startup pipeline as a forwarder (`--vcon-forward /var/tmp` and
/// `extra`) on a file holding `[vcon_forward]` and `body`.
fn forward_with(body: &str, extra: &[&str]) -> Result<Outcome, TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    std::fs::write(&path, format!("[vcon_forward]\n{body}\n"))?;
    let mut args = vec!["--vcon-forward", "/var/tmp"];
    args.extend_from_slice(extra);
    Ok(run(&argv(&args), Some(&path)))
}

/// The forwarder's URL, replace URL, credential and back-off keys are checked
/// when the forwarder runs, by the rule its flags follow, before anything is
/// sent. Each refusal names the key; a refusal that two settings cause names
/// both. A URL the file alone gave exits 1, as every refused config value
/// does; a refusal the command line takes part in, or a setting
/// `--vcon-forward` needs and nothing gave, exits 2.
#[test]
fn forwarder_keys_are_checked_when_the_forwarder_runs() -> Result<(), TestError> {
    const BASE: &str = "url = \"http://127.0.0.1:9/v1/vcons\"\nauth_file = \"/nonexistent/auth\"";
    let mut failures = Vec::new();
    let accepted = forward_with(BASE, &[])?;
    if !accepted.accepted() {
        failures.push(format!(
            "url and auth_file from the file: want accepted, got {:?}/{}: {}",
            accepted.stage, accepted.code, accepted.message
        ));
    }
    let refused: &[(&str, &[&str], &[&str], i32)] = &[
        (
            "url = \"x\"\nauth_file = \"/nonexistent/auth\"",
            &[],
            &["[vcon_forward] url"],
            1,
        ),
        (
            "url = \"\"\nauth_file = \"/nonexistent/auth\"",
            &[],
            &["[vcon_forward] url"],
            1,
        ),
        (
            "url = \"ftp://127.0.0.1/v1\"\nauth_file = \"/nonexistent/auth\"",
            &[],
            &["[vcon_forward] url"],
            1,
        ),
        (
            "url = \"https://user:pw@store.example.com/v1\"\nauth_file = \"/nonexistent/auth\"",
            &[],
            &["[vcon_forward] url"],
            1,
        ),
        (BASE, &["--vcon-forward-url=x"], &["--vcon-forward-url"], 2),
        (
            "auth_file = \"/nonexistent/auth\"",
            &[],
            &["--vcon-forward-url", "[vcon_forward] url"],
            2,
        ),
        (
            "url = \"http://127.0.0.1:9/v1/vcons\"",
            &[],
            &["--vcon-forward-auth-file", "[vcon_forward] auth_file"],
            2,
        ),
        (
            &format!("{BASE}\nreplace_url = \"http://127.0.0.1:9/v1/vcons/fixed\""),
            &[],
            &["[vcon_forward] replace_url"],
            1,
        ),
        (
            &format!("{BASE}\nreplace_url = \"x{{uuid}}\""),
            &[],
            &["[vcon_forward] replace_url"],
            1,
        ),
        (
            BASE,
            &["--vcon-forward-auth=Authorization: Bearer from-the-flag"],
            &["--vcon-forward-auth", "[vcon_forward] auth_file"],
            2,
        ),
        (
            &format!("{BASE}\nbackoff_first = 10"),
            &["--vcon-forward-backoff-cap=5"],
            &["[vcon_forward] backoff_first", "--vcon-forward-backoff-cap"],
            2,
        ),
        (
            &format!("{BASE}\nbackoff_cap = 5"),
            &["--vcon-forward-backoff-first=10"],
            &["--vcon-forward-backoff-first", "[vcon_forward] backoff_cap"],
            2,
        ),
    ];
    for (body, extra, names, code) in refused {
        let o = forward_with(body, extra)?;
        let what = format!("{body:?} with {extra:?}");
        if let Some(p) = &o.panic {
            failures.push(format!("{what}: panicked: {p}"));
        } else if o.accepted() || o.stage != Stage::Config || o.code != *code {
            failures.push(format!(
                "{what}: want a refusal from load_config with exit {code}, got {:?}/{}: {}",
                o.stage, o.code, o.message
            ));
        } else if let Some(missing) = names.iter().find(|n| !o.message.contains(*n)) {
            failures.push(format!(
                "{what}: refusal does not name {missing}: {}",
                o.message
            ));
        }
        if o.message.contains("from-the-flag") {
            failures.push(format!(
                "{what}: the refusal quotes the credential: {}",
                o.message
            ));
        }
    }
    verdict(failures)
}
