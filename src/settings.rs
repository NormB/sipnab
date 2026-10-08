// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one table that says which command-line flag and which config-file key
//! set the same thing.
//!
//! sipnab has two ways to set most things, and nothing used to tie them
//! together. `-E` had no key until issue #343 asked for one, and `--device`,
//! `--portrange` and twenty-one other flags had keys their reference rows never
//! mentioned. The flags live in `src/cli.rs`, the keys in `src/config.rs`, and
//! the two references in `docs/`. Each was kept by hand, so each drifted.
//!
//! This table is the link. Every long flag the CLI defines (and the trailing
//! capture-filter positional) has exactly one row in [`FLAGS`], and every key
//! `KNOWN_KEYS` accepts is either named by a flag row or listed in
//! [`FILE_ONLY`] with the reason it has no flag. The tests below hold the CLI,
//! the config table and both references to it, so a new flag or key cannot
//! land unclassified, and a reference row cannot drop the pairing.
//!
//! A flag that should have a key and does not yet is [`Link::Pending`]. Those
//! are counted in [`PENDING_FLAGS`], and the count may only fall.
//!
//! Fixer: `SIPNAB_SETTINGS_APPLY=1 cargo test --features full --lib settings`
//! rewrites the reference rows to what the table says, then
//! `python3 scripts/build-site-pages.py` carries them to the website.

/// What a command-line flag is to the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// The flag and this `[section] key` set the same thing, combined as
    /// [`Merge`] says.
    Key(&'static str, &'static str, Merge),
    /// A command that does its job and exits instead of running a capture.
    Action,
    /// Names this run's input or output.
    Input,
    /// Carries a secret value. It belongs in a file, never in sipnab.toml.
    Secret,
    /// Per-invocation intent that would surprise as a standing default.
    PerRun,
    /// A standing setting that should have a key and does not yet.
    Pending,
}

/// How a flag and its key combine when both are given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merge {
    /// The flag's value replaces the key's.
    Override,
    /// Either one turns it on. The flag has no "off" form, so a file that
    /// turns it on can only be undone with `--no-config`.
    Either,
    /// Both apply: the flag's values are added to the key's.
    Union,
    /// The flag forces the setting off whatever the key says.
    Off,
}

/// Why a config key has no flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOnly {
    /// A terminal-UI preference: colors, key bindings, layout.
    Tui,
    /// A table or map with no single-value flag shape.
    Table,
    /// A deployment tuning figure no one-off run needs to change.
    Tuning,
}

/// Every long flag (without the dashes) and the capture-filter positional
/// (`<BPF_FILTER>`), each with what it is to the config file.
pub const FLAGS: &[(&str, Link)] = &[
    (
        "<BPF_FILTER>",
        Link::Key("capture", "bpf_filter", Merge::Override),
    ),
    (
        "ack-timeout",
        Link::Key("diagnosis", "ack_timeout_secs", Merge::Override),
    ),
    (
        "active-idle-window",
        Link::Key("sip", "active_idle_window_secs", Merge::Override),
    ),
    ("after", Link::PerRun),
    ("alert", Link::Key("security", "alert", Merge::Override)),
    (
        "alert-exec",
        Link::Key("security", "alert_exec", Merge::Override),
    ),
    ("alert-json", Link::Key("security", "alert", Merge::Either)),
    ("allow-action", Link::Key("actions", "tfps", Merge::Union)),
    ("allow-coredump", Link::Pending),
    ("analyze", Link::PerRun),
    ("api", Link::Pending),
    ("api-accept-archive-passwords", Link::Pending),
    ("api-allow-relay-query", Link::Pending),
    (
        "api-allowed-host",
        Link::Key("api", "allowed_hosts", Merge::Override),
    ),
    ("api-file-root", Link::Pending),
    ("api-key", Link::Secret),
    ("api-max-conn", Link::Pending),
    (
        "api-max-rows",
        Link::Key("limits", "api_max_rows", Merge::Override),
    ),
    (
        "api-rate-limit-per-peer",
        Link::Key("limits", "api_rate_limit_per_peer", Merge::Override),
    ),
    ("api-revoked-file", Link::Pending),
    ("api-signing-key", Link::Secret),
    ("api-signing-key-file", Link::Pending),
    (
        "api-tls-cert",
        Link::Key("api", "tls_cert", Merge::Override),
    ),
    ("api-tls-key", Link::Key("api", "tls_key", Merge::Override)),
    ("api-token-ttl", Link::PerRun),
    ("archive-password", Link::Secret),
    ("archive-password-command", Link::Pending),
    ("archive-password-encoding", Link::PerRun),
    ("archive-password-file", Link::Pending),
    ("archive-password-stdin", Link::PerRun),
    ("autostop", Link::PerRun),
    (
        "bpf-file",
        Link::Key("capture", "bpf_filter", Merge::Override),
    ),
    ("buffer", Link::Key("capture", "buffer", Merge::Override)),
    (
        "buffer-budget",
        Link::Key("capture", "buffer_budget_mb", Merge::Override),
    ),
    (
        "business-hours",
        Link::Key("security", "business_hours", Merge::Override),
    ),
    ("call-report", Link::PerRun),
    ("calls-only", Link::Pending),
    (
        "capture-profile",
        Link::Key("capture", "snaplen", Merge::Override),
    ),
    ("capture-tunnels", Link::Pending),
    ("chroot", Link::Key("privilege", "chroot", Merge::Override)),
    (
        "cn-suppression-ratio",
        Link::Key("diagnosis", "cn_suppression_ratio", Merge::Override),
    ),
    ("color", Link::Key("display", "color", Merge::Override)),
    ("completions", Link::Action),
    ("config", Link::PerRun),
    ("contact", Link::Pending),
    ("content-deny-header", Link::Pending),
    ("content-deny-tombstone", Link::Pending),
    ("cores", Link::Pending),
    ("count", Link::PerRun),
    (
        "delta-time",
        Link::Key("display", "delta_time", Merge::Override),
    ),
    ("device", Link::Key("capture", "device", Merge::Override)),
    ("dialog-track", Link::Pending),
    ("digest-leak", Link::Pending),
    (
        "dns-cache-entries",
        Link::Key("names", "dns_cache_entries", Merge::Override),
    ),
    ("dtls-keylog", Link::Pending),
    ("dtmf-cleartext", Link::PerRun),
    ("dump-config", Link::Action),
    ("duration", Link::PerRun),
    (
        "duration-asymmetry-pct",
        Link::Key("diagnosis", "duration_asymmetry_pct", Merge::Override),
    ),
    (
        "duration-asymmetry-secs",
        Link::Key("diagnosis", "duration_asymmetry_secs", Merge::Override),
    ),
    ("evidence-out", Link::Input),
    (
        "exec-queue-depth",
        Link::Key("limits", "exec_queue_depth", Merge::Override),
    ),
    ("exec-rate-limit", Link::Pending),
    ("export-vcon", Link::PerRun),
    ("export-vcon-dir", Link::Input),
    ("export-vcon-when", Link::Pending),
    ("fail2ban", Link::PerRun),
    ("filter", Link::Key("filter", "expression", Merge::Override)),
    (
        "findings-history",
        Link::Key("security", "findings_history", Merge::Override),
    ),
    (
        "fraud-destination",
        Link::Key("security", "fraud_destination", Merge::Override),
    ),
    (
        "fraud-detect",
        Link::Key("security", "fraud_detect", Merge::Override),
    ),
    (
        "fraud-sequential-calls",
        Link::Key("security", "fraud_sequential_calls", Merge::Override),
    ),
    (
        "fraud-short-call",
        Link::Key("security", "fraud_short_call_secs", Merge::Override),
    ),
    (
        "fraud-volume-min-calls",
        Link::Key("security", "fraud_volume_min_calls", Merge::Override),
    ),
    (
        "fraud-volume-multiplier",
        Link::Key("security", "fraud_volume_multiplier", Merge::Override),
    ),
    (
        "fraud-volume-window",
        Link::Key("security", "fraud_volume_window_secs", Merge::Override),
    ),
    (
        "fraud-wangiri-calls",
        Link::Key("security", "fraud_wangiri_calls", Merge::Override),
    ),
    (
        "fraud-wangiri-window",
        Link::Key("security", "fraud_wangiri_window_secs", Merge::Override),
    ),
    ("from", Link::Key("filter", "from", Merge::Override)),
    (
        "from-to-mode",
        Link::Key("display", "from_to", Merge::Override),
    ),
    ("group-by", Link::PerRun),
    ("hep-allow", Link::Pending),
    ("hep-allow-kill", Link::Pending),
    ("hep-auth", Link::Secret),
    ("hep-auth-file", Link::Pending),
    ("hep-auth-mode", Link::Pending),
    (
        "hep-hmac-window",
        Link::Key("security", "hep_hmac_window_secs", Merge::Override),
    ),
    ("hep-id", Link::Pending),
    ("hep-listen", Link::Pending),
    ("hep-listen-transport", Link::Pending),
    (
        "hep-parse",
        Link::Key("capture", "hep_parse", Merge::Override),
    ),
    (
        "hep-rate-limit",
        Link::Key("limits", "hep_rate_limit", Merge::Override),
    ),
    ("hep-rate-limit-per-peer", Link::Pending),
    ("hep-send", Link::Pending),
    ("hep-send-transport", Link::Pending),
    ("hep-senders", Link::PerRun),
    ("hep-silence-warn", Link::Pending),
    ("hep-tls-ca", Link::Key("hep", "tls_ca", Merge::Override)),
    (
        "hep-tls-cert",
        Link::Key("hep", "tls_cert", Merge::Override),
    ),
    (
        "hep-tls-extra-ca",
        Link::Key("hep", "tls_extra_ca", Merge::Override),
    ),
    ("hep-tls-key", Link::Key("hep", "tls_key", Merge::Override)),
    ("hexdump", Link::PerRun),
    ("ignore-case", Link::PerRun),
    ("input", Link::Input),
    ("input-name", Link::Input),
    ("invert", Link::PerRun),
    (
        "jitter-bad-ms",
        Link::Key("quality", "jitter_bad_ms", Merge::Override),
    ),
    (
        "jitter-warn-ms",
        Link::Key("quality", "jitter_warn_ms", Merge::Override),
    ),
    ("journal-dir", Link::Key("journal", "dir", Merge::Override)),
    ("journal-show", Link::Action),
    ("json", Link::PerRun),
    ("json-analyze", Link::PerRun),
    ("json-dialogs", Link::PerRun),
    ("json-pretty", Link::PerRun),
    ("json-stun", Link::PerRun),
    ("keylog", Link::Pending),
    ("keylog-fd", Link::PerRun),
    ("keylog-watch", Link::Pending),
    (
        "kill-rate-limit",
        Link::Key("security", "kill_rate_limit", Merge::Override),
    ),
    (
        "kill-response",
        Link::Key("security", "kill_response", Merge::Override),
    ),
    (
        "kill-scanner",
        Link::Key("security", "kill_scanner", Merge::Override),
    ),
    ("kill-spoof", Link::Pending),
    ("kill-target", Link::Pending),
    ("kill-ua", Link::Pending),
    (
        "late-media-ms",
        Link::Key("diagnosis", "late_media_ms", Merge::Override),
    ),
    (
        "leg-correlation-window",
        Link::Key("sip", "leg_correlation_window_ms", Merge::Override),
    ),
    (
        "limit",
        Link::Key("limits", "dialog_limit", Merge::Override),
    ),
    ("limitlen", Link::Pending),
    ("line-buffer", Link::PerRun),
    ("lint", Link::PerRun),
    ("lint-fail-on", Link::PerRun),
    (
        "lint-max-per-rule",
        Link::Key("limits", "lint_max_per_rule", Merge::Override),
    ),
    ("lint-no-suppress", Link::PerRun),
    ("lint-suppress-file", Link::PerRun),
    (
        "loss-bad-pct",
        Link::Key("quality", "loss_bad_pct", Merge::Override),
    ),
    (
        "loss-warn-pct",
        Link::Key("quality", "loss_warn_pct", Merge::Override),
    ),
    ("markdown", Link::PerRun),
    ("match", Link::PerRun),
    (
        "max-capture-sources",
        Link::Key("limits", "max_capture_sources", Merge::Override),
    ),
    (
        "max-grouped-messages",
        Link::Key("limits", "max_grouped_messages", Merge::Override),
    ),
    (
        "max-groups",
        Link::Key("limits", "max_groups", Merge::Override),
    ),
    (
        "max-gunzip-bytes",
        Link::Key("limits", "max_gunzip_bytes", Merge::Override),
    ),
    (
        "max-lost-sequences",
        Link::Key("limits", "max_lost_sequences", Merge::Override),
    ),
    (
        "max-metadata-file-bytes",
        Link::Key("limits", "max_metadata_file_bytes", Merge::Override),
    ),
    (
        "max-reassembly",
        Link::Key("limits", "max_reassembly", Merge::Override),
    ),
    (
        "max-streams",
        Link::Key("limits", "max_streams", Merge::Override),
    ),
    (
        "max-tcp-buffer",
        Link::Key("limits", "max_tcp_buffer", Merge::Override),
    ),
    ("mcp", Link::PerRun),
    ("mcp-allow-open-capture", Link::Pending),
    ("mcp-allow-relay-query", Link::Pending),
    ("mcp-allow-save-findings", Link::Pending),
    ("mcp-allow-shutdown", Link::Pending),
    ("mcp-allow-tls-capture", Link::Pending),
    ("mcp-allowed-host", Link::Pending),
    ("mcp-audit-file", Link::Pending),
    ("mcp-bind", Link::Pending),
    ("mcp-evidence-ring", Link::Pending),
    ("mcp-file-root", Link::Pending),
    (
        "mcp-max-body-bytes",
        Link::Key("limits", "mcp_max_body_bytes", Merge::Override),
    ),
    ("mcp-max-concurrent", Link::Pending),
    (
        "mcp-max-findings",
        Link::Key("limits", "mcp_max_findings", Merge::Override),
    ),
    (
        "mcp-max-rows",
        Link::Key("limits", "mcp_max_rows", Merge::Override),
    ),
    (
        "mcp-max-wait-seconds",
        Link::Key("limits", "mcp_max_wait_seconds", Merge::Override),
    ),
    (
        "mcp-output-schemas",
        Link::Key("mcp", "output_schemas", Merge::Override),
    ),
    ("mcp-rate-limit-per-peer", Link::Pending),
    ("mcp-resource-url", Link::Pending),
    ("mcp-revoked-file", Link::Pending),
    ("mcp-sampling-budget", Link::Pending),
    ("mcp-signing-key", Link::Secret),
    ("mcp-signing-key-file", Link::Pending),
    (
        "mcp-sweep-deadline-ms",
        Link::Key("limits", "mcp_sweep_deadline_ms", Merge::Override),
    ),
    (
        "mcp-sweep-max-files",
        Link::Key("limits", "mcp_sweep_max_files", Merge::Override),
    ),
    (
        "mcp-tls-cert",
        Link::Key("mcp", "tls_cert", Merge::Override),
    ),
    ("mcp-tls-key", Link::Key("mcp", "tls_key", Merge::Override)),
    ("mcp-token", Link::Secret),
    ("mcp-token-file", Link::Pending),
    ("mcp-token-ttl", Link::PerRun),
    ("mcp-tools", Link::Key("mcp", "tools", Merge::Override)),
    ("mcp-transport", Link::Pending),
    ("metrics", Link::Pending),
    ("metrics-auth", Link::Secret),
    ("metrics-auth-file", Link::Pending),
    (
        "metrics-max-conn",
        Link::Key("limits", "metrics_max_conn", Merge::Override),
    ),
    (
        "metrics-tls-cert",
        Link::Key("metrics", "tls_cert", Merge::Override),
    ),
    (
        "metrics-tls-key",
        Link::Key("metrics", "tls_key", Merge::Override),
    ),
    ("mint-token", Link::Action),
    ("mos-bad", Link::Key("quality", "mos_bad", Merge::Override)),
    (
        "mos-warn",
        Link::Key("quality", "mos_warn", Merge::Override),
    ),
    ("multi-device", Link::Pending),
    ("names", Link::Key("names", "hosts_file", Merge::Union)),
    ("nat-issues", Link::PerRun),
    ("no-cli-print", Link::PerRun),
    ("no-config", Link::PerRun),
    (
        "no-delta-time",
        Link::Key("display", "delta_time", Merge::Off),
    ),
    ("no-dialog", Link::Pending),
    (
        "no-final-response-timeout",
        Link::Key("diagnosis", "no_final_response_secs", Merge::Override),
    ),
    (
        "no-fraud-detect",
        Link::Key("security", "fraud_detect", Merge::Off),
    ),
    (
        "no-hep-parse",
        Link::Key("capture", "hep_parse", Merge::Off),
    ),
    (
        "no-kill-scanner",
        Link::Key("security", "kill_scanner", Merge::Off),
    ),
    ("no-password-prompt", Link::Pending),
    (
        "no-priv-drop",
        Link::Key("privilege", "no_priv_drop", Merge::Override),
    ),
    ("no-promisc", Link::Key("capture", "promisc", Merge::Off)),
    ("no-reassembly", Link::Pending),
    ("no-resolve", Link::Key("names", "enabled", Merge::Off)),
    (
        "no-reverse-dns",
        Link::Key("names", "reverse_dns", Merge::Off),
    ),
    ("no-rotate", Link::Pending),
    ("no-rtp", Link::Key("capture", "no_rtp", Merge::Override)),
    ("no-tui", Link::PerRun),
    (
        "node-name",
        Link::Key("capture", "node_name", Merge::Override),
    ),
    ("notes", Link::Input),
    ("on-dialog-exec", Link::Pending),
    ("on-quality-exec", Link::Pending),
    ("one-way", Link::PerRun),
    (
        "one-way-delay",
        Link::Key("media", "one_way_delay_ms", Merge::Override),
    ),
    ("output", Link::Input),
    ("panic-selftest", Link::Action),
    (
        "payload-limit",
        Link::Key("display", "payload_limit", Merge::Override),
    ),
    ("pcap-export-mode", Link::Pending),
    ("pcapng", Link::PerRun),
    (
        "pdd-threshold",
        Link::Key("diagnosis", "post_dial_delay_secs", Merge::Override),
    ),
    ("plugin", Link::Pending),
    (
        "portrange",
        Link::Key("capture", "portrange", Merge::Override),
    ),
    ("print-yang-module", Link::Action),
    (
        "priv-drop",
        Link::Key("privilege", "no_priv_drop", Merge::Off),
    ),
    ("problems", Link::PerRun),
    ("proto-number", Link::Pending),
    (
        "quality-interval",
        Link::Key("limits", "quality_interval_secs", Merge::Override),
    ),
    ("quality-threshold", Link::Pending),
    ("quiet", Link::PerRun),
    ("quiet-bad-parse", Link::Pending),
    (
        "reassembly-ttl",
        Link::Key("limits", "reassembly_ttl_secs", Merge::Override),
    ),
    ("recommend-block", Link::PerRun),
    ("recursive", Link::PerRun),
    ("redact", Link::Pending),
    ("redact-keep-prefix", Link::Pending),
    ("redact-key-file", Link::Pending),
    ("redact-map", Link::Input),
    ("reg-flood", Link::Pending),
    (
        "reg-flood-threshold",
        Link::Key("security", "reg_flood_threshold", Merge::Override),
    ),
    (
        "reg-flood-transaction-timeout",
        Link::Key(
            "security",
            "reg_flood_transaction_timeout_ms",
            Merge::Override,
        ),
    ),
    (
        "reg-flood-window",
        Link::Key("security", "reg_flood_window_secs", Merge::Override),
    ),
    ("relay-compare", Link::PerRun),
    ("relay-stats", Link::PerRun),
    ("relay-stats-call", Link::PerRun),
    ("relay-stats-interval", Link::PerRun),
    ("relay-stats-list", Link::PerRun),
    ("replay", Link::PerRun),
    ("report", Link::PerRun),
    ("resolve", Link::Key("names", "enabled", Merge::Override)),
    ("retain-audio", Link::Pending),
    (
        "reverse-dns",
        Link::Key("names", "reverse_dns", Merge::Override),
    ),
    ("revert-actions", Link::Action),
    ("rotate", Link::Pending),
    ("rtp", Link::Key("capture", "no_rtp", Merge::Off)),
    ("rtpengine-control", Link::Pending),
    ("rtpproxy-control", Link::Pending),
    (
        "rtt-bad-ms",
        Link::Key("quality", "rtt_bad_ms", Merge::Override),
    ),
    (
        "rtt-warn-ms",
        Link::Key("quality", "rtt_warn_ms", Merge::Override),
    ),
    ("run-provenance-file", Link::Pending),
    ("sandbox", Link::Pending),
    (
        "scanner-answer-grace",
        Link::Key("security", "scanner_answer_grace_ms", Merge::Override),
    ),
    (
        "scanner-behavioral-probes",
        Link::Key("security", "scanner_behavioral_probes", Merge::Override),
    ),
    (
        "scanner-enumeration-targets",
        Link::Key("security", "scanner_enumeration_targets", Merge::Override),
    ),
    (
        "scanner-established-factor",
        Link::Key("security", "scanner_established_factor", Merge::Override),
    ),
    (
        "scanner-rejected-probes",
        Link::Key("security", "scanner_rejected_probes", Merge::Override),
    ),
    (
        "scanner-unanswered-probes",
        Link::Key("security", "scanner_unanswered_probes", Merge::Override),
    ),
    (
        "scanner-window",
        Link::Key("security", "scanner_window_secs", Merge::Override),
    ),
    ("seccomp", Link::Pending),
    ("setup-caps", Link::Action),
    ("short-calls", Link::PerRun),
    ("show-empty", Link::Pending),
    ("show-frame", Link::Action),
    ("single-line", Link::PerRun),
    ("slow-setup", Link::PerRun),
    ("snaplen", Link::Key("capture", "snaplen", Merge::Override)),
    ("split", Link::Pending),
    ("split-keep", Link::Pending),
    ("srtp-keys", Link::Pending),
    ("stir-shaken", Link::Pending),
    ("strip-secrets", Link::Action),
    ("stun", Link::PerRun),
    ("syslog", Link::Key("security", "alert", Merge::Either)),
    ("tag", Link::PerRun),
    ("telephone-event", Link::Pending),
    ("text-dump", Link::PerRun),
    ("tfps-ctl", Link::Key("tfps", "ctl", Merge::Override)),
    ("tls-key", Link::Pending),
    ("tls-lockon-window", Link::Pending),
    ("to", Link::Key("filter", "to", Merge::Override)),
    ("token-id", Link::PerRun),
    ("token-scope", Link::PerRun),
    ("tshark-filter", Link::PerRun),
    ("tui-audit-file", Link::Pending),
    ("ua", Link::Pending),
    ("uprobe-backend", Link::Pending),
    ("uprobe-flavor", Link::Pending),
    ("uprobe-library", Link::Pending),
    ("uprobe-list", Link::Action),
    ("uprobe-symbol", Link::Pending),
    ("uprobe-tls", Link::Pending),
    ("user", Link::Key("privilege", "user", Merge::Override)),
    ("vcon-digest", Link::Pending),
    // The forwarder is a mode of its own, like `--mint-token`: it captures
    // nothing, so no capture config key applies to it. Its standing settings
    // are `[vcon_forward]` keys; the spool and `--vcon-forward-once` are this
    // run's input and intent, and the credential's value is a secret.
    ("vcon-forward", Link::Action),
    ("vcon-forward-auth", Link::Secret),
    (
        "vcon-forward-auth-file",
        Link::Key("vcon_forward", "auth_file", Merge::Override),
    ),
    (
        "vcon-forward-backoff-cap",
        Link::Key("vcon_forward", "backoff_cap", Merge::Override),
    ),
    (
        "vcon-forward-backoff-first",
        Link::Key("vcon_forward", "backoff_first", Merge::Override),
    ),
    (
        "vcon-forward-ca",
        Link::Key("vcon_forward", "ca", Merge::Override),
    ),
    (
        "vcon-forward-compat",
        Link::Key("vcon_forward", "compat", Merge::Override),
    ),
    (
        "vcon-forward-done",
        Link::Key("vcon_forward", "done", Merge::Override),
    ),
    (
        "vcon-forward-failed",
        Link::Key("vcon_forward", "failed", Merge::Override),
    ),
    (
        "vcon-forward-interval",
        Link::Key("vcon_forward", "interval", Merge::Override),
    ),
    (
        "vcon-forward-kind",
        Link::Key("vcon_forward", "kind", Merge::Override),
    ),
    (
        "vcon-forward-max-error-body",
        Link::Key("vcon_forward", "max_error_body", Merge::Override),
    ),
    (
        "vcon-forward-max-response-head",
        Link::Key("vcon_forward", "max_response_head", Merge::Override),
    ),
    ("vcon-forward-once", Link::PerRun),
    (
        "vcon-forward-replace-url",
        Link::Key("vcon_forward", "replace_url", Merge::Override),
    ),
    (
        "vcon-forward-timeout",
        Link::Key("vcon_forward", "timeout", Merge::Override),
    ),
    (
        "vcon-forward-url",
        Link::Key("vcon_forward", "url", Merge::Override),
    ),
    ("vcon-max-inline-media", Link::Pending),
    ("vcon-out", Link::Input),
    ("wireshark", Link::PerRun),
    ("word", Link::PerRun),
    ("write-annotated", Link::Action),
    (
        "ws-portrange",
        Link::Key("capture", "ws_ports", Merge::Override),
    ),
    ("yang-analyze", Link::PerRun),
];

/// Every config key no flag sets, as `(section, key, why)`.
pub const FILE_ONLY: &[(&str, &str, FileOnly)] = &[
    ("action_limits", "per_minute", FileOnly::Tuning),
    ("action_limits", "per_caller_per_minute", FileOnly::Tuning),
    ("action_limits", "address_cooldown_secs", FileOnly::Tuning),
    ("action_limits", "default_ban_secs", FileOnly::Tuning),
    ("action_limits", "max_ban_secs", FileOnly::Tuning),
    ("tfps", "db", FileOnly::Tuning),
    ("media", "codec_ie", FileOnly::Table),
    ("media", "listening_context", FileOnly::Tuning),
    ("crash", "reports", FileOnly::Tuning),
    ("crash", "backtrace", FileOnly::Tuning),
    ("crash", "report_dir", FileOnly::Tuning),
    ("crash", "core", FileOnly::Tuning),
    ("display", "visible_columns", FileOnly::Tui),
    ("sip", "xcid_headers", FileOnly::Tuning),
    ("limits", "max_header_line", FileOnly::Tuning),
    ("limits", "max_headers_per_message", FileOnly::Tuning),
    ("limits", "max_messages_per_dialog", FileOnly::Tuning),
    ("limits", "idle_compact_after_secs", FileOnly::Tuning),
    ("limits", "keep_messages_per_idle_dialog", FileOnly::Tuning),
    ("limits", "max_audio_frames", FileOnly::Tuning),
    ("limits", "max_tracked_peers", FileOnly::Tuning),
    ("mcp", "bundles", FileOnly::Table),
    ("names", "manual", FileOnly::Table),
    ("names", "persist_to_config", FileOnly::Tui),
    ("theme", "background", FileOnly::Tui),
    ("theme", "foreground", FileOnly::Tui),
    ("theme", "highlight", FileOnly::Tui),
    ("theme", "header", FileOnly::Tui),
    ("theme", "selected", FileOnly::Tui),
    ("theme", "accent", FileOnly::Tui),
    ("theme", "good", FileOnly::Tui),
    ("theme", "warning", FileOnly::Tui),
    ("theme", "bad", FileOnly::Tui),
    ("theme", "muted", FileOnly::Tui),
    ("theme", "border", FileOnly::Tui),
    ("theme", "status_bg", FileOnly::Tui),
    ("keybindings", "quit", FileOnly::Tui),
    ("keybindings", "help", FileOnly::Tui),
    ("keybindings", "filter", FileOnly::Tui),
    ("keybindings", "save", FileOnly::Tui),
    ("keybindings", "search", FileOnly::Tui),
    ("keybindings", "settings", FileOnly::Tui),
    ("keybindings", "pause", FileOnly::Tui),
    ("keybindings", "autoscroll", FileOnly::Tui),
    ("keybindings", "extended_flow", FileOnly::Tui),
    ("keybindings", "clear_calls", FileOnly::Tui),
    ("keybindings", "column_selector", FileOnly::Tui),
];

/// Flags the CLI defines only when a cargo feature is compiled in, as
/// `(flag, feature)`. A build without the feature has no such flag, and its
/// [`FLAGS`] row is then not a phantom.
pub const FEATURE_GATED: &[(&str, &str)] = &[("plugin", "plugins")];

/// Whether `feature` is compiled into this build. Only the features
/// [`FEATURE_GATED`] names need an answer.
pub fn feature_enabled(feature: &str) -> bool {
    feature == "plugins" && cfg!(feature = "plugins")
}

/// How many [`FLAGS`] rows are [`Link::Pending`]. Lower it when a pending flag
/// gets its key; it may never rise.
pub const PENDING_FLAGS: usize = 98;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Any error a test can return; `?` converts into it.
    type TestError = Box<dyn std::error::Error>;

    /// Every name the CLI accepts in [`FLAGS`]' spelling: long flags without
    /// dashes, positionals as `<VALUE_NAME>`. `help` and `version` are clap's.
    fn cli_names() -> BTreeSet<String> {
        use clap::CommandFactory;
        let cmd = crate::cli::Cli::command();
        let mut out = BTreeSet::new();
        for a in cmd.get_arguments() {
            if let Some(l) = a.get_long() {
                if l != "help" && l != "version" {
                    out.insert(l.to_string());
                }
            } else if a.is_positional() {
                let v = a
                    .get_value_names()
                    .and_then(|v| v.first())
                    .map_or_else(|| a.get_id().to_string(), ToString::to_string);
                out.insert(format!("<{v}>"));
            }
        }
        out
    }

    /// Every `(section, key)` the config file accepts.
    fn config_keys() -> BTreeSet<(String, String)> {
        crate::config::known_keys()
            .iter()
            .filter(|(s, _)| !s.is_empty())
            .flat_map(|(s, ks)| ks.iter().map(move |k| ((*s).to_string(), (*k).to_string())))
            .collect()
    }

    fn read(rel: &str) -> Result<String, TestError> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        Ok(std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?)
    }

    /// What is wrong with `table` against the names the CLI defines: names
    /// with no row, names with two, and rows for names the CLI lacks.
    fn flag_errors(cli: &BTreeSet<String>, table: &[(&str, Link)]) -> Vec<String> {
        let mut seen = BTreeMap::<&str, usize>::new();
        for (f, _) in table {
            *seen.entry(f).or_default() += 1;
        }
        let mut errors = Vec::new();
        for f in cli.iter().filter(|f| !seen.contains_key(f.as_str())) {
            errors.push(format!("not classified: {f}"));
        }
        for (f, _) in seen.iter().filter(|(_, n)| **n > 1) {
            errors.push(format!("listed twice: {f}"));
        }
        for f in seen.keys().filter(|f| !cli.contains(**f)) {
            errors.push(format!("not a flag the CLI defines: {f}"));
        }
        errors
    }

    /// What is wrong with the key half: keys nothing names, keys named by a
    /// flag AND listed file-only, file-only twice, and names that are not keys.
    fn key_errors(
        keys: &BTreeSet<(String, String)>,
        table: &[(&str, Link)],
        file_only: &[(&str, &str, FileOnly)],
    ) -> Vec<String> {
        let mut named = BTreeMap::<(String, String), Vec<String>>::new();
        for (f, l) in table {
            if let Link::Key(s, k, _) = l {
                named
                    .entry(((*s).into(), (*k).into()))
                    .or_default()
                    .push(format!("--{f}"));
            }
        }
        let mut listed = BTreeSet::new();
        let mut errors = Vec::new();
        for (s, k, _) in file_only {
            let sk = ((*s).to_string(), (*k).to_string());
            if let Some(fs) = named.get(&sk) {
                errors.push(format!("[{s}] {k} is file-only but {fs:?} set it"));
            }
            if !listed.insert(sk) {
                errors.push(format!("[{s}] {k} is file-only twice"));
            }
        }
        for sk in named.keys().chain(listed.iter()) {
            if !keys.contains(sk) {
                errors.push(format!(
                    "[{}] {} is not a key the config file accepts",
                    sk.0, sk.1
                ));
            }
        }
        for (s, k) in keys
            .iter()
            .filter(|sk| !named.contains_key(*sk) && !listed.contains(*sk))
        {
            errors.push(format!("unclassified key: [{s}] {k}"));
        }
        errors
    }

    #[test]
    fn every_flag_has_exactly_one_row() -> Result<(), TestError> {
        let compiled_out: Vec<&str> = FEATURE_GATED
            .iter()
            .filter(|(_, feature)| !feature_enabled(feature))
            .map(|(flag, _)| *flag)
            .collect();
        let table: Vec<(&str, Link)> = FLAGS
            .iter()
            .copied()
            .filter(|(f, _)| !compiled_out.contains(f))
            .collect();
        let errors = flag_errors(&cli_names(), &table);
        assert!(
            errors.is_empty(),
            "src/settings.rs FLAGS ({}):\n{}",
            errors.len(),
            errors.join("\n")
        );
        Ok(())
    }

    #[test]
    fn every_config_key_is_named_once() -> Result<(), TestError> {
        let errors = key_errors(&config_keys(), FLAGS, FILE_ONLY);
        assert!(
            errors.is_empty(),
            "src/settings.rs keys ({}):\n{}",
            errors.len(),
            errors.join("\n")
        );
        Ok(())
    }

    fn names(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(ToString::to_string).collect()
    }

    fn keyset(v: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        v.iter()
            .map(|(s, k)| ((*s).to_string(), (*k).to_string()))
            .collect()
    }

    #[test]
    fn a_complete_flag_table_passes() -> Result<(), TestError> {
        let t = [
            ("device", Link::Key("capture", "device", Merge::Override)),
            ("json", Link::PerRun),
        ];
        assert_eq!(
            flag_errors(&names(&["device", "json"]), &t),
            Vec::<String>::new()
        );
        Ok(())
    }

    #[test]
    fn a_flag_with_no_row_is_reported_by_name() -> Result<(), TestError> {
        let t = [("device", Link::PerRun)];
        assert_eq!(
            flag_errors(&names(&["device", "json"]), &t),
            vec!["not classified: json"]
        );
        Ok(())
    }

    #[test]
    fn a_flag_listed_twice_is_reported() -> Result<(), TestError> {
        let t = [("json", Link::PerRun), ("json", Link::Input)];
        assert_eq!(
            flag_errors(&names(&["json"]), &t),
            vec!["listed twice: json"]
        );
        Ok(())
    }

    #[test]
    fn a_row_for_a_flag_the_cli_lacks_is_reported() -> Result<(), TestError> {
        let t = [("json", Link::PerRun), ("jsno", Link::PerRun)];
        assert_eq!(
            flag_errors(&names(&["json"]), &t),
            vec!["not a flag the CLI defines: jsno"]
        );
        Ok(())
    }

    #[test]
    fn a_complete_key_half_passes() -> Result<(), TestError> {
        let keys = keyset(&[("capture", "device"), ("theme", "accent")]);
        let t = [("device", Link::Key("capture", "device", Merge::Override))];
        let file_only_list = [("theme", "accent", FileOnly::Tui)];
        assert_eq!(key_errors(&keys, &t, &file_only_list), Vec::<String>::new());
        Ok(())
    }

    #[test]
    fn an_unclassified_key_is_reported() -> Result<(), TestError> {
        let keys = keyset(&[("capture", "device"), ("capture", "snaplen")]);
        let t = [("device", Link::Key("capture", "device", Merge::Override))];
        assert_eq!(
            key_errors(&keys, &t, &[]),
            vec!["unclassified key: [capture] snaplen"]
        );
        Ok(())
    }

    #[test]
    fn a_key_both_flagged_and_file_only_is_reported() -> Result<(), TestError> {
        let keys = keyset(&[("capture", "device")]);
        let t = [("device", Link::Key("capture", "device", Merge::Override))];
        let file_only_list = [("capture", "device", FileOnly::Tuning)];
        assert_eq!(
            key_errors(&keys, &t, &file_only_list),
            vec![r#"[capture] device is file-only but ["--device"] set it"#]
        );
        Ok(())
    }

    #[test]
    fn a_file_only_key_listed_twice_is_reported() -> Result<(), TestError> {
        let keys = keyset(&[("theme", "accent")]);
        let file_only_list = [
            ("theme", "accent", FileOnly::Tui),
            ("theme", "accent", FileOnly::Tui),
        ];
        assert_eq!(
            key_errors(&keys, &[], &file_only_list),
            vec!["[theme] accent is file-only twice"]
        );
        Ok(())
    }

    #[test]
    fn a_key_the_config_file_does_not_accept_is_reported() -> Result<(), TestError> {
        let keys = keyset(&[("capture", "device")]);
        let t = [
            ("device", Link::Key("capture", "device", Merge::Override)),
            ("snaplen", Link::Key("capture", "snaplenn", Merge::Override)),
        ];
        assert_eq!(
            key_errors(&keys, &t, &[]),
            vec!["[capture] snaplenn is not a key the config file accepts"]
        );
        Ok(())
    }

    /// Long flags clap hides from `--help`: internal hooks, not documented.
    fn hidden_flags() -> BTreeSet<String> {
        use clap::CommandFactory;
        crate::cli::Cli::command()
            .get_arguments()
            .filter(|a| a.is_hide_set())
            .filter_map(|a| a.get_long().map(ToString::to_string))
            .collect()
    }

    /// The flags a CLI-reference row names in its first cell: `--long`
    /// without dashes, or `<BPF_FILTER>`. Empty for a line that is not a row.
    fn row_flags(line: &str) -> Vec<String> {
        let Some(rest) = line.strip_prefix("| ") else {
            return Vec::new();
        };
        let Some((first, _)) = rest.split_once(" | ") else {
            return Vec::new();
        };
        let mut names = Vec::new();
        for tok in first.split('`').skip(1).step_by(2) {
            if let Some(l) = tok.strip_prefix("--") {
                names.push(l.split(['=', ' ', '[']).next().unwrap_or(l).to_string());
            } else if tok.starts_with("<BPF_FILTER>") {
                names.push("<BPF_FILTER>".to_string());
            }
        }
        names
    }

    /// The `Config:` suffix a reference row carries for a key-linked flag.
    fn config_tag(s: &str, k: &str) -> String {
        format!("Config: `[{s}] {k}`")
    }

    /// Append `sentence` to the last cell of a table row.
    fn append_to_row(line: &str, sentence: &str) -> String {
        let body = line.trim_end().strip_suffix('|').unwrap_or(line).trim_end();
        let sep = if body.ends_with('.') { " " } else { ". " };
        format!("{body}{sep}{sentence} |")
    }

    /// `docs/cli-reference.md` as [`FLAGS`] says it should read, and what a
    /// person must fix because a machine should not guess.
    fn fix_cli_reference_with(
        md: &str,
        table: &[(&str, Link)],
        hidden: &BTreeSet<String>,
    ) -> (String, Vec<String>) {
        let links: BTreeMap<&str, Link> = table.iter().copied().collect();
        let mut seen = BTreeSet::new();
        let mut errors = Vec::new();
        let mut out = Vec::new();
        for line in md.lines() {
            let mut line = line.to_string();
            for name in row_flags(&line) {
                seen.insert(name.clone());
                match links.get(name.as_str()) {
                    Some(Link::Key(s, k, _)) => {
                        let tag = config_tag(s, k);
                        if line.contains(&tag) {
                        } else if line.contains("Config: `[") {
                            errors.push(format!("--{name}: row names another key than {tag}"));
                        } else {
                            line = append_to_row(&line, &tag);
                        }
                    }
                    Some(_) if line.contains("Config: `[") => {
                        errors.push(format!(
                            "--{name}: row names a key; src/settings.rs links none"
                        ));
                    }
                    _ => {}
                }
            }
            out.push(line);
        }
        for (flag, _) in table {
            if !seen.contains(*flag) && !hidden.contains(*flag) {
                errors.push(format!("--{flag}: no row in docs/cli-reference.md"));
            }
        }
        let mut text = out.join("\n");
        if md.ends_with('\n') {
            text.push('\n');
        }
        (text, errors)
    }

    /// The sentence a config-reference row carries about its flags.
    fn flag_sentence(flags: &[(&str, Merge)]) -> String {
        let parts: Vec<String> = flags
            .iter()
            .map(|(f, m)| {
                let f = if f.starts_with('<') {
                    format!("`{f}`")
                } else {
                    format!("`--{f}`")
                };
                match m {
                    Merge::Override => format!("{f} overrides it"),
                    Merge::Either => format!("{f} also turns it on"),
                    Merge::Union => format!("{f} adds to it"),
                    Merge::Off => format!("{f} forces it off"),
                }
            })
            .collect();
        let mut s = parts.join("; ");
        if let Some(c) = s.get(..1) {
            s.replace_range(..1, &c.to_uppercase());
        }
        s
    }

    /// `docs/config-reference.md` as [`FLAGS`] says it should read, and the
    /// keys with no row at all (a row is prose a person writes).
    fn fix_config_reference_with(
        md: &str,
        table: &[(&'static str, Link)],
        keys: &BTreeSet<(String, String)>,
    ) -> (String, Vec<String>) {
        let mut flags_of = BTreeMap::<(String, String), Vec<(&str, Merge)>>::new();
        for (f, l) in table {
            if let Link::Key(s, k, m) = l {
                flags_of
                    .entry(((*s).into(), (*k).into()))
                    .or_default()
                    .push((f, *m));
            }
        }
        let mut section = String::new();
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for line in md.lines() {
            let mut line = line.to_string();
            if line.starts_with("##") {
                let h = line.trim_start_matches('#').trim().trim_matches('`');
                if let Some(name) = h.strip_prefix('[').and_then(|h| h.split(']').next()) {
                    section = name.to_string();
                }
            } else if let Some(key) = line
                .strip_prefix("| `")
                .and_then(|r| r.split_once('`'))
                .map(|(k, _)| k.to_string())
            {
                let sk = (section.clone(), key);
                if seen.insert(sk.clone())
                    && let Some(fs) = flags_of.get(&sk)
                {
                    // Every flag that sets the key is named; a row naming one
                    // of them still owes a sentence for each of the others.
                    let missing: Vec<(&str, Merge)> = fs
                        .iter()
                        .copied()
                        .filter(|(f, _)| {
                            let spelled = if f.starts_with('<') {
                                (*f).to_string()
                            } else {
                                format!("--{f}")
                            };
                            !line.contains(&format!("`{spelled}`"))
                        })
                        .collect();
                    if !missing.is_empty() {
                        line = append_to_row(&line, &flag_sentence(&missing));
                    }
                }
            }
            out.push(line);
        }
        let errors = keys
            .iter()
            .filter(|sk| !seen.contains(*sk))
            .map(|(s, k)| format!("[{s}] {k}: no row in docs/config-reference.md"))
            .collect();
        let mut text = out.join("\n");
        if md.ends_with('\n') {
            text.push('\n');
        }
        (text, errors)
    }

    fn fix_cli_reference(md: &str) -> (String, Vec<String>) {
        fix_cli_reference_with(md, FLAGS, &hidden_flags())
    }

    fn fix_config_reference(md: &str) -> (String, Vec<String>) {
        fix_config_reference_with(md, FLAGS, &config_keys())
    }

    /// Gate and fixer in one: the reference must already read as the fixer
    /// would write it. `SIPNAB_SETTINGS_APPLY=1` writes the fix instead.
    fn hold_reference(rel: &str, fix: fn(&str) -> (String, Vec<String>)) -> Result<(), TestError> {
        let md = read(rel)?;
        let (fixed, errors) = fix(&md);
        if std::env::var_os("SIPNAB_SETTINGS_APPLY").is_some() && fixed != md {
            let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
            std::fs::write(&p, &fixed).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        let stale: Vec<String> = md
            .lines()
            .zip(fixed.lines())
            .filter(|(a, b)| a != b)
            .map(|(a, _)| a.chars().take(90).collect())
            .collect();
        assert!(
            errors.is_empty()
                && (stale.is_empty() || std::env::var_os("SIPNAB_SETTINGS_APPLY").is_some()),
            "{rel} disagrees with src/settings.rs.\n\
             For a person ({}):\n{}\n\
             Rows the fixer rewrites ({}; run SIPNAB_SETTINGS_APPLY=1 cargo test \
             --features full --lib settings, then python3 scripts/build-site-pages.py):\n{}",
            errors.len(),
            errors.join("\n"),
            stale.len(),
            stale.join("\n")
        );
        Ok(())
    }

    #[test]
    fn every_cli_reference_row_says_its_config_key() -> Result<(), TestError> {
        hold_reference("docs/cli-reference.md", fix_cli_reference)?;
        Ok(())
    }

    #[test]
    fn every_config_key_has_a_row_naming_its_flags() -> Result<(), TestError> {
        hold_reference("docs/config-reference.md", fix_config_reference)?;
        Ok(())
    }

    const DEV: (&str, Link) = ("device", Link::Key("capture", "device", Merge::Override));

    fn none() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn the_fixer_appends_the_key_to_a_keyed_row() -> Result<(), TestError> {
        let md = "| `-d`, `--device` | `<IFACE>` | -- | Capture interface |\n";
        let (out, errors) = fix_cli_reference_with(md, &[DEV], &none());
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            out,
            "| `-d`, `--device` | `<IFACE>` | -- | Capture interface. Config: `[capture] device` |\n"
        );
        Ok(())
    }

    #[test]
    fn the_fixer_does_not_double_a_full_stop() -> Result<(), TestError> {
        let md = "| `--device` | x | -- | Capture interface. |\n";
        let (out, _) = fix_cli_reference_with(md, &[DEV], &none());
        assert_eq!(
            out,
            "| `--device` | x | -- | Capture interface. Config: `[capture] device` |\n"
        );
        Ok(())
    }

    #[test]
    fn the_fixer_leaves_a_correct_row_unchanged() -> Result<(), TestError> {
        let md = "| `--device` | x | -- | Interface. Config: `[capture] device` |\n";
        let (out, errors) = fix_cli_reference_with(md, &[DEV], &none());
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(out, md);
        Ok(())
    }

    #[test]
    fn the_fixer_refuses_to_guess_over_a_different_key() -> Result<(), TestError> {
        let md = "| `--device` | x | -- | Interface. Config: `[capture] devices` |\n";
        let (out, errors) = fix_cli_reference_with(md, &[DEV], &none());
        assert_eq!(out, md, "a wrong key is for a person, not rewritten");
        assert_eq!(
            errors,
            vec!["--device: row names another key than Config: `[capture] device`"]
        );
        Ok(())
    }

    #[test]
    fn the_fixer_reports_a_key_on_a_flag_the_table_does_not_link() -> Result<(), TestError> {
        let md = "| `--json` | -- | off | NDJSON. Config: `[display] json` |\n";
        let (_, errors) = fix_cli_reference_with(md, &[("json", Link::PerRun)], &none());
        assert_eq!(
            errors,
            vec!["--json: row names a key; src/settings.rs links none"]
        );
        Ok(())
    }

    #[test]
    fn the_fixer_reports_a_visible_flag_with_no_row() -> Result<(), TestError> {
        let (_, errors) =
            fix_cli_reference_with("no table here\n", &[("json", Link::PerRun)], &none());
        assert_eq!(errors, vec!["--json: no row in docs/cli-reference.md"]);
        Ok(())
    }

    #[test]
    fn a_hidden_flag_needs_no_row() -> Result<(), TestError> {
        let hidden = names(&["panic-selftest"]);
        let (_, errors) =
            fix_cli_reference_with("x\n", &[("panic-selftest", Link::Action)], &hidden);
        assert!(errors.is_empty(), "{errors:?}");
        Ok(())
    }

    #[test]
    fn the_positional_filter_is_matched_by_its_value_name() -> Result<(), TestError> {
        let t = [(
            "<BPF_FILTER>",
            Link::Key("capture", "bpf_filter", Merge::Override),
        )];
        let md = "| `<BPF_FILTER>...` | positional | -- | Capture filter |\n";
        let (out, errors) = fix_cli_reference_with(md, &t, &none());
        assert!(errors.is_empty(), "{errors:?}");
        assert!(out.contains("Config: `[capture] bpf_filter` |"), "{out}");
        Ok(())
    }

    #[test]
    fn a_flag_with_a_value_suffix_is_still_found() -> Result<(), TestError> {
        let t = [("capture-tunnels", Link::Pending)];
        let md = "| `--capture-tunnels[=PORTS]` | x | off | Tunnels |\n";
        let (_, errors) = fix_cli_reference_with(md, &t, &none());
        assert!(errors.is_empty(), "{errors:?}");
        Ok(())
    }

    #[test]
    fn every_merge_has_its_own_sentence() -> Result<(), TestError> {
        assert_eq!(
            flag_sentence(&[("portrange", Merge::Override)]),
            "`--portrange` overrides it"
        );
        assert_eq!(
            flag_sentence(&[("hep-parse", Merge::Either)]),
            "`--hep-parse` also turns it on"
        );
        assert_eq!(
            flag_sentence(&[("names", Merge::Union)]),
            "`--names` adds to it"
        );
        assert_eq!(
            flag_sentence(&[("no-promisc", Merge::Off)]),
            "`--no-promisc` forces it off"
        );
        assert_eq!(
            flag_sentence(&[
                ("bpf-file", Merge::Override),
                ("<BPF_FILTER>", Merge::Override)
            ]),
            "`--bpf-file` overrides it; `<BPF_FILTER>` overrides it"
        );
        Ok(())
    }

    fn cfg_md(row: &str) -> String {
        format!(
            "### [capture]\n\n| Key | Type | Default | Description |\n|---|---|---|---|\n{row}\n"
        )
    }

    #[test]
    fn the_config_fixer_names_the_flag_in_a_row_that_does_not() -> Result<(), TestError> {
        let md = cfg_md("| `device` | string | -- | Default interface |");
        let (out, errors) =
            fix_config_reference_with(&md, &[DEV], &keyset(&[("capture", "device")]));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            out.contains("| Default interface. `--device` overrides it |"),
            "{out}"
        );
        Ok(())
    }

    #[test]
    fn the_config_fixer_leaves_a_row_that_names_the_flag() -> Result<(), TestError> {
        let md = cfg_md("| `device` | string | -- | Interface; `--device` wins |");
        let (out, _) = fix_config_reference_with(&md, &[DEV], &keyset(&[("capture", "device")]));
        assert_eq!(out, md);
        Ok(())
    }

    /// A row naming one of a key's flags still gets a sentence for each flag
    /// it does not name: here the switch's off flag.
    #[test]
    fn the_config_fixer_names_each_flag_a_row_lacks() -> Result<(), TestError> {
        let t = [
            (
                "kill-scanner",
                Link::Key("security", "kill_scanner", Merge::Override),
            ),
            (
                "no-kill-scanner",
                Link::Key("security", "kill_scanner", Merge::Off),
            ),
        ];
        let md = "### [security]\n\n| `kill_scanner` | bool | false | Answer scanners. `--kill-scanner` overrides it |\n";
        let (out, errors) =
            fix_config_reference_with(md, &t, &keyset(&[("security", "kill_scanner")]));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            out.contains("`--kill-scanner` overrides it. `--no-kill-scanner` forces it off |"),
            "{out}"
        );
        let (again, _) =
            fix_config_reference_with(&out, &t, &keyset(&[("security", "kill_scanner")]));
        assert_eq!(again, out, "a row naming every flag is left alone");
        Ok(())
    }

    #[test]
    fn the_config_fixer_reports_a_key_with_no_row() -> Result<(), TestError> {
        let md = cfg_md("| `device` | string | -- | Interface. `--device` overrides it |");
        let keys = keyset(&[("capture", "device"), ("capture", "snaplen")]);
        let (_, errors) = fix_config_reference_with(&md, &[DEV], &keys);
        assert_eq!(
            errors,
            vec!["[capture] snaplen: no row in docs/config-reference.md"]
        );
        Ok(())
    }

    #[test]
    fn a_row_belongs_to_the_heading_above_it_in_any_style() -> Result<(), TestError> {
        for heading in ["### [capture]", "### `[capture]`", "## `[capture]`"] {
            let md = format!("{heading}\n\n| `device` | s | -- | Interface |\n");
            let (out, errors) =
                fix_config_reference_with(&md, &[DEV], &keyset(&[("capture", "device")]));
            assert!(errors.is_empty(), "{heading}: {errors:?}");
            assert!(out.contains("`--device` overrides it"), "{heading}: {out}");
        }
        Ok(())
    }

    #[test]
    fn a_same_named_key_in_another_section_is_not_confused() -> Result<(), TestError> {
        let md = "### [display]\n\n| `device` | s | -- | Not the capture one |\n";
        let keys = keyset(&[("capture", "device")]);
        let (out, errors) = fix_config_reference_with(md, &[DEV], &keys);
        assert_eq!(
            out, md,
            "a [display] row must not be edited for a [capture] key"
        );
        assert_eq!(
            errors,
            vec!["[capture] device: no row in docs/config-reference.md"]
        );
        Ok(())
    }

    #[test]
    fn the_fixers_reach_a_fixed_point_on_the_real_references() -> Result<(), TestError> {
        for (rel, fix) in [
            (
                "docs/cli-reference.md",
                fix_cli_reference as fn(&str) -> (String, Vec<String>),
            ),
            ("docs/config-reference.md", fix_config_reference),
        ] {
            let (once, _) = fix(&read(rel)?);
            let (twice, _) = fix(&once);
            assert_eq!(once, twice, "{rel}: a second pass of the fixer changed it");
        }
        Ok(())
    }

    /// Each feature-gated flag is in the CLI exactly when its feature is
    /// compiled in. CI's feature matrix runs this both ways.
    #[test]
    fn a_feature_gated_flag_exists_exactly_when_its_feature_is_on() -> Result<(), TestError> {
        let cli = cli_names();
        for (flag, feature) in FEATURE_GATED {
            assert_eq!(
                cli.contains(*flag),
                feature_enabled(feature),
                "--{flag} and feature {feature:?} disagree in this build"
            );
        }
        Ok(())
    }

    /// FEATURE_GATED names every `#[cfg(feature = ...)]` argument in cli.rs,
    /// so a newly gated flag cannot pass the gate in one build and fail it in
    /// another.
    #[test]
    fn the_feature_gated_list_matches_cli_rs() -> Result<(), TestError> {
        let src = read("src/cli.rs")?;
        let lines: Vec<&str> = src.lines().map(str::trim).collect();
        let mut gated = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let Some(feature) = line
                .strip_prefix("#[cfg(feature = \"")
                .and_then(|r| r.strip_suffix("\")]"))
            else {
                continue;
            };
            let Some(arg) = lines[i + 1..].iter().find(|l| !l.starts_with("///")) else {
                continue;
            };
            if !arg.starts_with("#[arg(") {
                continue;
            }
            // `long = "x"`, or a bare `long` that takes the field's name.
            let long = arg
                .split("long = \"")
                .nth(1)
                .and_then(|r| r.split('"').next())
                .map_or_else(
                    || {
                        lines[i + 1..]
                            .iter()
                            .find_map(|l| l.strip_prefix("pub ").and_then(|r| r.split(':').next()))
                            .unwrap_or("?")
                            .replace('_', "-")
                    },
                    ToString::to_string,
                );
            gated.push((long, feature.to_string()));
        }
        let listed: Vec<(String, String)> = FEATURE_GATED
            .iter()
            .map(|(f, x)| ((*f).to_string(), (*x).to_string()))
            .collect();
        assert_eq!(
            gated, listed,
            "FEATURE_GATED must list exactly the feature-gated flags in src/cli.rs"
        );
        Ok(())
    }

    /// A switch a file can turn on and no flag can turn off is the defect the
    /// `--no-X` flags removed. `Either` survives only where both sources add
    /// to a list on purpose: `--syslog` and `--alert-json` each add an alert
    /// channel to `[security] alert`, and neither is a switch.
    #[test]
    fn no_switch_is_one_way() -> Result<(), TestError> {
        let either: Vec<&str> = FLAGS
            .iter()
            .filter(|(_, l)| matches!(l, Link::Key(_, _, Merge::Either)))
            .map(|(f, _)| *f)
            .collect();
        assert_eq!(
            either,
            vec!["alert-json", "syslog"],
            "a one-way switch needs its off flag"
        );
        Ok(())
    }

    /// Every switch's off flag forces the same key off.
    #[test]
    fn every_off_flag_forces_its_key_off() -> Result<(), TestError> {
        for (off, key) in [
            ("no-hep-parse", ("capture", "hep_parse")),
            ("rtp", ("capture", "no_rtp")),
            ("no-delta-time", ("display", "delta_time")),
            ("priv-drop", ("privilege", "no_priv_drop")),
            ("no-fraud-detect", ("security", "fraud_detect")),
            ("no-kill-scanner", ("security", "kill_scanner")),
            ("no-reverse-dns", ("names", "reverse_dns")),
            ("no-resolve", ("names", "enabled")),
        ] {
            let row = FLAGS.iter().find(|(f, _)| *f == off).map(|(_, l)| *l);
            assert_eq!(row, Some(Link::Key(key.0, key.1, Merge::Off)), "--{off}");
        }
        Ok(())
    }

    /// Where a switch's key is read outside its resolver in `src/cli.rs`, as
    /// `(file, line)`. Each of those was a `flag || key` that no off flag could
    /// undo; the resolvers are the one place a switch is decided.
    fn inline_switch_reads(files: &[(String, String)]) -> Vec<String> {
        let keys = [
            "capture.hep_parse",
            "capture.no_rtp",
            "display.delta_time",
            "privilege.no_priv_drop",
            "security.fraud_detect",
            "security.kill_scanner",
            "names.reverse_dns",
            "names.enabled",
        ];
        let mut hits = Vec::new();
        for (path, text) in files {
            if path.ends_with("src/cli.rs")
                || path.ends_with("src/config.rs")
                || path.ends_with("src/settings.rs")
            {
                continue;
            }
            for (i, line) in text.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if keys.iter().any(|k| {
                    code.contains(&format!("{k}.unwrap_or("))
                        || code.contains(&format!(
                            "cfg.{}.unwrap_or(",
                            k.split('.').nth(1).unwrap_or("")
                        ))
                }) {
                    hits.push(format!("{path}:{}", i + 1));
                }
            }
        }
        hits
    }

    fn rust_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && let Ok(t) = std::fs::read_to_string(&p)
                {
                    out.push((p.display().to_string(), t));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    #[test]
    fn no_switch_is_decided_outside_its_resolver() -> Result<(), TestError> {
        let hits = inline_switch_reads(&rust_sources());
        assert!(
            hits.is_empty(),
            "switch keys read inline instead of through their Cli resolver: {hits:?}"
        );
        Ok(())
    }

    #[test]
    fn the_inline_read_scan_reports_a_flag_or_key_merge() -> Result<(), TestError> {
        let files = vec![(
            "src/app/x.rs".to_string(),
            "let k = cli.security_args.kill_scanner || config.security.kill_scanner.unwrap_or(false);\n\
             let r = cli.name_args.resolve || cfg.enabled.unwrap_or(false);\n\
             // config.security.kill_scanner.unwrap_or(false) in a comment\n"
                .to_string(),
        )];
        assert_eq!(
            inline_switch_reads(&files),
            vec!["src/app/x.rs:1", "src/app/x.rs:2"]
        );
        Ok(())
    }

    #[test]
    fn the_pending_count_is_recorded_and_only_falls() -> Result<(), TestError> {
        let n = FLAGS.iter().filter(|(_, l)| *l == Link::Pending).count();
        assert_eq!(
            n, PENDING_FLAGS,
            "FLAGS has {n} Link::Pending rows but PENDING_FLAGS says {PENDING_FLAGS}. \
             Lower PENDING_FLAGS when a flag gets its key; a new flag gets a key, \
             not a Pending row."
        );
        Ok(())
    }
}
