// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests that verify the actual default value of every CLI parameter.
//!
//! Each test parses a minimal argument list (`["sipnab", "-N"]`) and asserts the
//! default for one field.  This catches documentation drift — if a default
//! changes in `src/cli.rs`, the corresponding test here will fail.
#![cfg(feature = "native")]

use clap::Parser;
use sipnab::cli::Cli;

/// Helper: parse with `-N` (non-interactive) and no other flags.
///
/// # Returns
/// The `Cli` produced by the minimal parse, i.e. every field at its default.
fn defaults() -> Cli {
    Cli::try_parse_from(["sipnab", "-N"]).expect("minimal parse should succeed")
}

// ═══════════════════════════════════════════════════════════════════════
//  Capture
// ═══════════════════════════════════════════════════════════════════════

/// `device` parses to `None` so the capture device is auto-detected at runtime.
#[test]
fn default_device_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.device.is_none(),
        "device should be None by default (auto-detect at runtime)"
    );
}

/// `input` (offline pcap path) defaults to `None`.
#[test]
fn default_input_is_none() {
    let cli = defaults();
    assert!(!cli.has_input(), "input should be None by default");
}

/// `output` (pcap write path) defaults to `None`.
#[test]
fn default_output_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.output.is_none(),
        "output should be None by default"
    );
}

/// `buffer` defaults to `None` on the CLI struct; the effective size is
/// applied later in `app::bootstrap` from `capture::DEFAULT_BUFFER_MB`.
#[test]
fn default_buffer_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.buffer.is_none(),
        "buffer should be None (OS default)"
    );
}

/// `snaplen` defaults to `None`, deferring to the OS default snap length.
#[test]
fn default_snaplen_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.snaplen.is_none(),
        "snaplen should be None (OS default)"
    );
}

/// `portrange` stays `None` at the CLI layer; the 5060-5061 default is applied later by `plan()`.
#[test]
fn default_portrange() {
    let cli = defaults();
    assert_eq!(
        cli.capture_args.portrange, None,
        "portrange stays None at the CLI layer; plan() applies the 5060-5061 default"
    );
}

/// `multi_device` defaults to off.
#[test]
fn default_multi_device_is_false() {
    let cli = defaults();
    assert!(
        !cli.capture_args.multi_device,
        "multi_device should default to false"
    );
}

/// `no_rtp` defaults to off, so RTP analysis is enabled.
#[test]
fn default_no_rtp_is_false() {
    let cli = defaults();
    assert!(!cli.capture_args.no_rtp, "no_rtp should default to false");
}

/// `bpf_file` defaults to `None`.
#[test]
fn default_bpf_file_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.bpf_file.is_none(),
        "bpf_file should be None by default"
    );
}

/// `count` (packet-count limit) defaults to `None` (unlimited).
#[test]
fn default_count_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.count.is_none(),
        "count should be None by default"
    );
}

/// `duration` defaults to `None` (no time limit).
#[test]
fn default_duration_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.duration.is_none(),
        "duration should be None by default"
    );
}

/// `autostop` defaults to `None` (no autostop condition).
#[test]
fn default_autostop_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.autostop.is_none(),
        "autostop should be None by default"
    );
}

/// `split` defaults to `None` (no output rotation).
#[test]
fn default_split_is_none() {
    let cli = defaults();
    assert!(
        cli.capture_args.split.is_none(),
        "split should be None by default"
    );
}

/// `replay` (timed pcap replay) defaults to off.
#[test]
fn default_replay_is_false() {
    let cli = defaults();
    assert!(!cli.capture_args.replay, "replay should default to false");
}

/// `pcapng` defaults to off, so output is classic pcap format.
#[test]
fn default_pcapng_is_false() {
    let cli = defaults();
    assert!(!cli.capture_args.pcapng, "pcapng should default to false");
}

/// The positional `bpf_filter` words default to an empty list.
#[test]
fn default_bpf_filter_is_empty() {
    let cli = defaults();
    assert!(
        cli.bpf_filter.is_empty(),
        "bpf_filter should be empty by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Mode
// ═══════════════════════════════════════════════════════════════════════

/// A bare `sipnab` invocation (no `-N`) leaves `no_tui` false, so the TUI is the default mode.
#[test]
fn default_no_tui_is_false() {
    // We test with bare parse (no -N) to verify the actual default.
    let cli = Cli::try_parse_from(["sipnab"]).expect("bare parse should succeed");
    assert!(!cli.mode_args.no_tui, "no_tui should default to false");
}

/// Passing `-N` sets `no_tui` to true.
#[test]
fn no_tui_set_when_passed() {
    let cli = defaults();
    assert!(cli.mode_args.no_tui, "-N should set no_tui to true");
}

/// `calls_only` defaults to off.
#[test]
fn default_calls_only_is_false() {
    let cli = defaults();
    assert!(
        !cli.mode_args.calls_only,
        "calls_only should default to false"
    );
}

/// `telephone_event` (DTMF display) defaults to off.
#[test]
fn default_telephone_event_is_false() {
    let cli = defaults();
    assert!(
        !cli.mode_args.telephone_event,
        "telephone_event should default to false"
    );
}

/// `quiet` defaults to off.
#[test]
fn default_quiet_is_false() {
    let cli = defaults();
    assert!(!cli.mode_args.quiet, "quiet should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  Matching
// ═══════════════════════════════════════════════════════════════════════

/// `ignore_case` matching defaults to off (case-sensitive).
#[test]
fn default_ignore_case_is_false() {
    let cli = defaults();
    assert!(
        !cli.matching_args.ignore_case,
        "ignore_case should default to false"
    );
}

/// `invert` (negated match) defaults to off.
#[test]
fn default_invert_is_false() {
    let cli = defaults();
    assert!(!cli.matching_args.invert, "invert should default to false");
}

/// `word` (whole-word match) defaults to off.
#[test]
fn default_word_is_false() {
    let cli = defaults();
    assert!(!cli.matching_args.word, "word should default to false");
}

/// `single_line` output mode defaults to off.
#[test]
fn default_single_line_is_false() {
    let cli = defaults();
    assert!(
        !cli.matching_args.single_line,
        "single_line should default to false"
    );
}

/// The `from` header match defaults to `None`.
#[test]
fn default_from_is_none() {
    let cli = defaults();
    assert!(
        cli.matching_args.from.is_none(),
        "from should be None by default"
    );
}

/// The `to` header match defaults to `None`.
#[test]
fn default_to_is_none() {
    let cli = defaults();
    assert!(
        cli.matching_args.to.is_none(),
        "to should be None by default"
    );
}

/// The `contact` header match defaults to `None`.
#[test]
fn default_contact_is_none() {
    let cli = defaults();
    assert!(
        cli.matching_args.contact.is_none(),
        "contact should be None by default"
    );
}

/// The `ua` (User-Agent) match defaults to `None`.
#[test]
fn default_ua_is_none() {
    let cli = defaults();
    assert!(
        cli.matching_args.ua.is_none(),
        "ua should be None by default"
    );
}

/// The display `filter` expression defaults to `None`.
#[test]
fn default_filter_is_none() {
    let cli = defaults();
    assert!(
        cli.matching_args.filter.is_none(),
        "filter should be None by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Diagnostic aliases
// ═══════════════════════════════════════════════════════════════════════

/// The `problems` diagnostic alias defaults to off.
#[test]
fn default_problems_is_false() {
    let cli = defaults();
    assert!(!cli.alias_args.problems, "problems should default to false");
}

/// The `slow_setup` diagnostic alias defaults to off.
#[test]
fn default_slow_setup_is_false() {
    let cli = defaults();
    assert!(
        !cli.alias_args.slow_setup,
        "slow_setup should default to false"
    );
}

/// The `short_calls` diagnostic alias defaults to off.
#[test]
fn default_short_calls_is_false() {
    let cli = defaults();
    assert!(
        !cli.alias_args.short_calls,
        "short_calls should default to false"
    );
}

/// The `one_way` (one-way audio) diagnostic alias defaults to off.
#[test]
fn default_one_way_is_false() {
    let cli = defaults();
    assert!(!cli.alias_args.one_way, "one_way should default to false");
}

/// The `nat_issues` diagnostic alias defaults to off.
#[test]
fn default_nat_issues_is_false() {
    let cli = defaults();
    assert!(
        !cli.alias_args.nat_issues,
        "nat_issues should default to false"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Output
// ═══════════════════════════════════════════════════════════════════════

/// `json` output defaults to off.
#[test]
fn default_json_is_false() {
    let cli = defaults();
    assert!(!cli.output_args.json, "json should default to false");
}

/// `json_pretty` output defaults to off.
#[test]
fn default_json_pretty_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.json_pretty,
        "json_pretty should default to false"
    );
}

/// `report` (end-of-run summary) defaults to off.
#[test]
fn default_report_is_false() {
    let cli = defaults();
    assert!(!cli.output_args.report, "report should default to false");
}

/// `call_report` defaults to `None`.
#[test]
fn default_call_report_is_none() {
    let cli = defaults();
    assert!(
        cli.output_args.call_report.is_none(),
        "call_report should be None by default"
    );
}

/// `markdown` output defaults to off.
#[test]
fn default_markdown_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.markdown,
        "markdown should default to false"
    );
}

/// `hexdump` payload display defaults to off.
#[test]
fn default_hexdump_is_false() {
    let cli = defaults();
    assert!(!cli.output_args.hexdump, "hexdump should default to false");
}

/// `delta_time` timestamps default to off.
#[test]
fn default_delta_time_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.delta_time,
        "delta_time should default to false"
    );
}

/// `after` (context lines) defaults to `None`.
#[test]
fn default_after_is_none() {
    let cli = defaults();
    assert!(
        cli.output_args.after.is_none(),
        "after should be None by default"
    );
}

/// `show_empty` (keepalive display) defaults to off.
#[test]
fn default_show_empty_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.show_empty,
        "show_empty should default to false"
    );
}

/// `line_buffer` (line-buffered stdout) defaults to off.
#[test]
fn default_line_buffer_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.line_buffer,
        "line_buffer should default to false"
    );
}

/// `color` is unset by default, and RESOLVES to `auto` (TTY-detected).
///
/// The field is `None` rather than a clap-filled `"auto"` on purpose: a
/// `default_value` here is what made `[display] color` unreachable, because it
/// left nothing for the config key to override. The default now lives in
/// `Cli::DEFAULT_COLOR` and is applied by `Cli::color_mode`.
#[test]
fn default_color() {
    let cli = defaults();
    assert_eq!(
        cli.output_args.color, None,
        "no --color given, so the field stays empty"
    );
    assert_eq!(
        cli.color_mode(&sipnab::config::Config::default()),
        "auto",
        "resolved default color should be auto"
    );
}

/// `payload_limit` defaults to `None` (untruncated payloads).
#[test]
fn default_payload_limit_is_none() {
    let cli = defaults();
    assert!(
        cli.output_args.payload_limit.is_none(),
        "payload_limit should be None by default"
    );
}

/// `text_dump` defaults to off.
#[test]
fn default_text_dump_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.text_dump,
        "text_dump should default to false"
    );
}

/// `wireshark` handoff defaults to off.
#[test]
fn default_wireshark_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.wireshark,
        "wireshark should default to false"
    );
}

/// `tshark_filter` defaults to `None`.
#[test]
fn default_tshark_filter_is_none() {
    let cli = defaults();
    assert!(
        cli.output_args.tshark_filter.is_none(),
        "tshark_filter should be None by default"
    );
}

/// `fail2ban` log output defaults to off.
#[test]
fn default_fail2ban_is_false() {
    let cli = defaults();
    assert!(
        !cli.output_args.fail2ban,
        "fail2ban should default to false"
    );
}

/// `group_by` aggregation defaults to `None`.
#[test]
fn default_group_by_is_none() {
    let cli = defaults();
    assert!(
        cli.output_args.group_by.is_none(),
        "group_by should be None by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Dialog
// ═══════════════════════════════════════════════════════════════════════

/// The dialog-store `limit` defaults to 100000 entries.
#[test]
fn default_limit() {
    let cli = defaults();
    assert_eq!(
        cli.dialog_args.limit, None,
        "--limit is an Option so [limits] dialog_limit can take effect; the \
         default lives in Cli::dialog_limit"
    );
    assert_eq!(
        cli.dialog_limit(&sipnab::config::Config::default()),
        100_000
    );
}

/// SNB-0004 regression pin: `rotate_enabled()` is true by default (LRU eviction at capacity) and `no_rotate` is off.
#[test]
fn dialog_rotation_is_enabled_by_default() {
    // SNB-0004: rotation is ON by default — at --limit capacity the store evicts
    // the oldest dialog (LRU) rather than dropping new legitimate calls. The bare
    // `--rotate` flag field stays false-by-absence; the effective policy is via
    // rotate_enabled() (`--no-rotate` opts out).
    let cli = defaults();
    assert!(cli.rotate_enabled(), "dialog rotation must default ON");
    assert!(!cli.dialog_args.no_rotate, "--no-rotate is off by default");
}

#[test]
fn default_no_dialog_is_false() {
    let cli = defaults();
    assert!(
        !cli.dialog_args.no_dialog,
        "no_dialog should default to false"
    );
}

/// `tag` defaults to `None`.
#[test]
fn default_tag_is_none() {
    let cli = defaults();
    assert!(
        cli.dialog_args.tag.is_none(),
        "tag should be None by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  RTP
// ═══════════════════════════════════════════════════════════════════════

/// `max_streams` defaults to 50000 RTP streams.
#[test]
fn default_max_streams() {
    let cli = defaults();
    assert_eq!(
        cli.rtp_args.max_streams, None,
        "--max-streams is an Option so [limits] max_streams can take effect"
    );
    assert_eq!(
        cli.max_streams_limit(&sipnab::config::Config::default()),
        50_000,
        "the resolved default is still 50000"
    );
}

/// `quality_threshold` defaults to a MOS of 3.0.
#[test]
fn default_quality_threshold() {
    let cli = defaults();
    assert!(
        (cli.rtp_args.quality_threshold - 3.0).abs() < f64::EPSILON,
        "default quality_threshold should be 3.0, got {}",
        cli.rtp_args.quality_threshold
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Security
// ═══════════════════════════════════════════════════════════════════════

/// `kill_scanner` defaults to off.
#[test]
fn default_kill_scanner_is_false() {
    let cli = defaults();
    assert!(
        !cli.security_args.kill_scanner,
        "kill_scanner should default to false"
    );
}

/// `kill_ua` defaults to `None`.
#[test]
fn default_kill_ua_is_none() {
    let cli = defaults();
    assert!(
        cli.security_args.kill_ua.is_none(),
        "kill_ua should be None by default"
    );
}

/// `kill_response` is unset by default, and RESOLVES to SIP status 200.
///
/// Same reasoning as `default_color`: the flag carries no clap default, so
/// `[security] kill_response` has something to override.
#[test]
fn default_kill_response() {
    let cli = defaults();
    assert_eq!(
        cli.security_args.kill_response, None,
        "no flag given, so the field stays empty"
    );
    assert_eq!(
        cli.kill_response_code(&sipnab::config::Config::default()),
        200,
        "resolved default kill_response should be 200"
    );
}

/// `fraud_detect` defaults to off.
#[test]
fn default_fraud_detect_is_false() {
    let cli = defaults();
    assert!(
        !cli.security_args.fraud_detect,
        "fraud_detect should default to false"
    );
}

/// `reg_flood` detection defaults to off.
#[test]
fn default_reg_flood_is_false() {
    let cli = defaults();
    assert!(
        !cli.security_args.reg_flood,
        "reg_flood should default to false"
    );
}

/// `digest_leak` detection defaults to off.
#[test]
fn default_digest_leak_is_false() {
    let cli = defaults();
    assert!(
        !cli.security_args.digest_leak,
        "digest_leak should default to false"
    );
}

/// The `alert` sink list defaults to empty.
#[test]
fn default_alert_is_empty() {
    let cli = defaults();
    assert!(
        cli.security_args.alert.is_empty(),
        "alert should be empty by default"
    );
}

/// `alert_exec` defaults to `None`.
#[test]
fn default_alert_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.security_args.alert_exec.is_none(),
        "alert_exec should be None by default"
    );
}

/// `stir_shaken` verification defaults to off.
#[test]
fn default_stir_shaken_is_false() {
    let cli = defaults();
    assert!(
        !cli.security_args.stir_shaken,
        "stir_shaken should default to false"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Event execution
// ═══════════════════════════════════════════════════════════════════════

/// `on_dialog_exec` hook defaults to `None`.
#[test]
fn default_on_dialog_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.exec_args.on_dialog_exec.is_none(),
        "on_dialog_exec should be None by default"
    );
}

/// `on_quality_exec` hook defaults to `None`.
#[test]
fn default_on_quality_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.exec_args.on_quality_exec.is_none(),
        "on_quality_exec should be None by default"
    );
}

/// `exec_rate_limit` defaults to 10 executions.
#[test]
fn default_exec_rate_limit() {
    let cli = defaults();
    assert_eq!(
        cli.exec_args.exec_rate_limit, 10,
        "default exec_rate_limit should be 10"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Network listeners
// ═══════════════════════════════════════════════════════════════════════

/// The `metrics` (Prometheus) bind address defaults to `None` (disabled).
#[test]
fn default_metrics_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.metrics.is_none(),
        "metrics should be None by default"
    );
}

/// `metrics_auth` defaults to `None`.
#[test]
fn default_metrics_auth_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.metrics_auth.is_none(),
        "metrics_auth should be None by default"
    );
}

/// The `api` bind address defaults to `None` (REST API disabled).
#[test]
fn default_api_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.api.is_none(),
        "api should be None by default"
    );
}

/// `api_key` defaults to `None` (no static API auth).
#[test]
fn default_api_key_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.api_key.is_none(),
        "api_key should be None by default"
    );
}

/// `api_tls_cert` defaults to `None`.
#[test]
fn default_api_tls_cert_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.api_tls_cert.is_none(),
        "api_tls_cert should be None by default"
    );
}

/// `api_tls_key` defaults to `None`.
#[test]
fn default_api_tls_key_is_none() {
    let cli = defaults();
    assert!(
        cli.listener_args.api_tls_key.is_none(),
        "api_tls_key should be None by default"
    );
}

/// `api_max_conn` defaults to 100 concurrent connections.
#[test]
fn default_api_max_conn() {
    let cli = defaults();
    assert_eq!(
        cli.listener_args.api_max_conn, 100,
        "default api_max_conn should be 100"
    );
}

/// `hep_listen` defaults to `None` (HEP server disabled).
#[test]
fn default_hep_listen_is_none() {
    let cli = defaults();
    assert!(
        cli.hep_args.hep_listen.is_none(),
        "hep_listen should be None by default"
    );
}

/// `hep_send` defaults to `None` (no HEP forwarding).
#[test]
fn default_hep_send_is_none() {
    let cli = defaults();
    assert!(
        cli.hep_args.hep_send.is_none(),
        "hep_send should be None by default"
    );
}

/// `hep_parse` defaults to off.
#[test]
fn default_hep_parse_is_false() {
    let cli = defaults();
    assert!(!cli.hep_args.hep_parse, "hep_parse should default to false");
}

/// The `hep_allow` source allowlist defaults to empty.
#[test]
fn default_hep_allow_is_empty() {
    let cli = defaults();
    assert!(
        cli.hep_args.hep_allow.is_empty(),
        "hep_allow should be empty by default"
    );
}

/// `hep_rate_limit` defaults to 50000 packets.
#[test]
fn default_hep_rate_limit() {
    let cli = defaults();
    assert_eq!(
        cli.hep_args.hep_rate_limit, None,
        "--hep-rate-limit is an Option so [limits] hep_rate_limit can take effect"
    );
    assert_eq!(
        cli.hep_rate_limit_resolved(&sipnab::config::Config::default()),
        50_000,
        "the resolved default is still 50000"
    );
}

/// `syslog` logging defaults to off.
#[test]
fn default_syslog_is_false() {
    let cli = defaults();
    assert!(!cli.security_args.syslog, "syslog should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS / Decryption
// ═══════════════════════════════════════════════════════════════════════

/// `tls_key` (RSA private key) defaults to `None`.
#[test]
fn default_tls_key_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_args.tls_key.is_none(),
        "tls_key should be None by default"
    );
}

/// `keylog` (SSLKEYLOGFILE path) defaults to `None`.
#[test]
fn default_keylog_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_args.keylog.is_none(),
        "keylog should be None by default"
    );
}

/// `keylog_watch` (tail the keylog) defaults to off.
#[test]
fn default_keylog_watch_is_false() {
    let cli = defaults();
    assert!(
        !cli.tls_args.keylog_watch,
        "keylog_watch should default to false"
    );
}

/// `tls_lockon_window` defaults to `None`, meaning the built-in ceiling.
///
/// `None` rather than the number itself, so the default lives in one place —
/// beside the search that spends it — instead of being restated here where it
/// could drift from the value the decryptor actually uses.
#[test]
fn default_tls_lockon_window_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_args.tls_lockon_window.is_none(),
        "tls_lockon_window should be None by default, deferring to the decryptor"
    );
}

/// An explicit `--tls-lockon-window` is carried through as given.
#[test]
fn tls_lockon_window_is_parsed_from_the_flag() {
    let cli = Cli::try_parse_from(["sipnab", "-N", "--tls-lockon-window", "8388608"])
        .expect("an explicit lock-on window should parse");
    assert_eq!(
        cli.tls_args.tls_lockon_window,
        Some(8_388_608),
        "the record ceiling must reach the decryptor unmodified"
    );
}

/// `dtls_keylog` defaults to `None`.
#[test]
fn default_dtls_keylog_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_args.dtls_keylog.is_none(),
        "dtls_keylog should be None by default"
    );
}

/// `srtp_keys` defaults to `None`.
#[test]
fn default_srtp_keys_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_args.srtp_keys.is_none(),
        "srtp_keys should be None by default"
    );
}

/// `pcap_export_mode` defaults to the string `decrypted`.
#[test]
fn default_pcap_export_mode() {
    let cli = defaults();
    assert_eq!(
        cli.tls_args.pcap_export_mode, "decrypted",
        "default pcap_export_mode should be decrypted"
    );
}

/// `allow_coredump` defaults to off (core dumps stay disabled).
#[test]
fn default_allow_coredump_is_false() {
    let cli = defaults();
    assert!(
        !cli.tls_args.allow_coredump,
        "allow_coredump should default to false"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Privilege
// ═══════════════════════════════════════════════════════════════════════

/// `user` (privilege-drop target) defaults to `None`.
#[test]
fn default_user_is_none() {
    let cli = defaults();
    assert!(
        cli.privilege_args.user.is_none(),
        "user should be None by default"
    );
}

/// `no_priv_drop` defaults to off, so privilege drop stays enabled.
#[test]
fn default_no_priv_drop_is_false() {
    let cli = defaults();
    assert!(
        !cli.privilege_args.no_priv_drop,
        "no_priv_drop should default to false"
    );
}

/// `chroot` defaults to `None`.
#[test]
fn default_chroot_is_none() {
    let cli = defaults();
    assert!(
        cli.privilege_args.chroot.is_none(),
        "chroot should be None by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Resource limits
// ═══════════════════════════════════════════════════════════════════════

/// `max_reassembly` (TCP reassembly buffers) defaults to 10000.
#[test]
fn default_max_reassembly() {
    let cli = defaults();
    assert_eq!(
        cli.limits_args.max_reassembly, None,
        "--max-reassembly is an Option so [limits] max_reassembly can take effect"
    );
    assert_eq!(
        cli.max_reassembly_limit(&sipnab::config::Config::default()),
        10_000,
        "the resolved default is still 10000"
    );
}

/// `cores` defaults to 1 — the single-threaded path.
///
/// Load-bearing beyond documentation drift: `app::bootstrap` warns when
/// `--cores > 1` is combined with a live source, because parallel
/// reconstruction is offline-only. A default above 1 would fire that warning on
/// every live capture nobody asked for it on.
#[test]
fn default_cores_is_one() {
    assert_eq!(
        defaults().limits_args.cores,
        1,
        "--cores must default to the single-threaded path"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Config
// ═══════════════════════════════════════════════════════════════════════

/// `config` (explicit config-file path) defaults to `None`.
#[test]
fn default_config_is_none() {
    let cli = defaults();
    assert!(
        cli.config_args.config.is_none(),
        "config should be None by default"
    );
}

/// `no_config` defaults to off, so config discovery runs.
#[test]
fn default_no_config_is_false() {
    let cli = defaults();
    assert!(
        !cli.config_args.no_config,
        "no_config should default to false"
    );
}

/// `dump_config` defaults to off.
#[test]
fn default_dump_config_is_false() {
    let cli = defaults();
    assert!(
        !cli.config_args.dump_config,
        "dump_config should default to false"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Validation
// ═══════════════════════════════════════════════════════════════════════

/// The all-defaults `-N` parse passes `Cli::validate()` without error.
#[test]
fn defaults_pass_validation() {
    let cli = defaults();
    assert!(
        cli.validate().is_ok(),
        "default arguments with -N should pass validation"
    );
}
