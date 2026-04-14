//! Tests that verify the actual default value of every CLI parameter.
//!
//! Each test parses a minimal argument list (`["sipnab", "-N"]`) and asserts the
//! default for one field.  This catches documentation drift — if a default
//! changes in `src/cli.rs`, the corresponding test here will fail.

use clap::Parser;
use sipnab::cli::Cli;

/// Helper: parse with `-N` (non-interactive) and no other flags.
fn defaults() -> Cli {
    Cli::try_parse_from(["sipnab", "-N"]).expect("minimal parse should succeed")
}

// ═══════════════════════════════════════════════════════════════════════
//  Capture
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_device_is_none() {
    let cli = defaults();
    assert!(
        cli.device.is_none(),
        "device should be None by default (auto-detect at runtime)"
    );
}

#[test]
fn default_input_is_none() {
    let cli = defaults();
    assert!(cli.input.is_none(), "input should be None by default");
}

#[test]
fn default_output_is_none() {
    let cli = defaults();
    assert!(cli.output.is_none(), "output should be None by default");
}

#[test]
fn default_buffer_is_none() {
    let cli = defaults();
    assert!(cli.buffer.is_none(), "buffer should be None (OS default)");
}

#[test]
fn default_snaplen_is_none() {
    let cli = defaults();
    assert!(cli.snaplen.is_none(), "snaplen should be None (OS default)");
}

#[test]
fn default_portrange() {
    let cli = defaults();
    assert_eq!(
        cli.portrange, "5060-5061",
        "default portrange should be 5060-5061"
    );
}

#[test]
fn default_multi_device_is_false() {
    let cli = defaults();
    assert!(!cli.multi_device, "multi_device should default to false");
}

#[test]
fn default_no_rtp_is_false() {
    let cli = defaults();
    assert!(!cli.no_rtp, "no_rtp should default to false");
}

#[test]
fn default_bpf_file_is_none() {
    let cli = defaults();
    assert!(cli.bpf_file.is_none(), "bpf_file should be None by default");
}

#[test]
fn default_count_is_none() {
    let cli = defaults();
    assert!(cli.count.is_none(), "count should be None by default");
}

#[test]
fn default_duration_is_none() {
    let cli = defaults();
    assert!(cli.duration.is_none(), "duration should be None by default");
}

#[test]
fn default_autostop_is_none() {
    let cli = defaults();
    assert!(
        cli.autostop.is_none(),
        "autostop should be None by default"
    );
}

#[test]
fn default_split_is_none() {
    let cli = defaults();
    assert!(cli.split.is_none(), "split should be None by default");
}

#[test]
fn default_replay_is_false() {
    let cli = defaults();
    assert!(!cli.replay, "replay should default to false");
}

#[test]
fn default_pcapng_is_false() {
    let cli = defaults();
    assert!(!cli.pcapng, "pcapng should default to false");
}

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

#[test]
fn default_no_tui_is_false() {
    // We test with bare parse (no -N) to verify the actual default.
    let cli = Cli::try_parse_from(["sipnab"]).expect("bare parse should succeed");
    assert!(!cli.no_tui, "no_tui should default to false");
}

#[test]
fn no_tui_set_when_passed() {
    let cli = defaults();
    assert!(cli.no_tui, "-N should set no_tui to true");
}

#[test]
fn default_calls_only_is_false() {
    let cli = defaults();
    assert!(!cli.calls_only, "calls_only should default to false");
}

#[test]
fn default_telephone_event_is_false() {
    let cli = defaults();
    assert!(
        !cli.telephone_event,
        "telephone_event should default to false"
    );
}

#[test]
fn default_quiet_is_false() {
    let cli = defaults();
    assert!(!cli.quiet, "quiet should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  Matching
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_ignore_case_is_false() {
    let cli = defaults();
    assert!(!cli.ignore_case, "ignore_case should default to false");
}

#[test]
fn default_invert_is_false() {
    let cli = defaults();
    assert!(!cli.invert, "invert should default to false");
}

#[test]
fn default_word_is_false() {
    let cli = defaults();
    assert!(!cli.word, "word should default to false");
}

#[test]
fn default_single_line_is_false() {
    let cli = defaults();
    assert!(!cli.single_line, "single_line should default to false");
}

#[test]
fn default_from_is_none() {
    let cli = defaults();
    assert!(cli.from.is_none(), "from should be None by default");
}

#[test]
fn default_to_is_none() {
    let cli = defaults();
    assert!(cli.to.is_none(), "to should be None by default");
}

#[test]
fn default_contact_is_none() {
    let cli = defaults();
    assert!(cli.contact.is_none(), "contact should be None by default");
}

#[test]
fn default_ua_is_none() {
    let cli = defaults();
    assert!(cli.ua.is_none(), "ua should be None by default");
}

#[test]
fn default_filter_is_none() {
    let cli = defaults();
    assert!(cli.filter.is_none(), "filter should be None by default");
}

// ═══════════════════════════════════════════════════════════════════════
//  Diagnostic aliases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_problems_is_false() {
    let cli = defaults();
    assert!(!cli.problems, "problems should default to false");
}

#[test]
fn default_slow_setup_is_false() {
    let cli = defaults();
    assert!(!cli.slow_setup, "slow_setup should default to false");
}

#[test]
fn default_short_calls_is_false() {
    let cli = defaults();
    assert!(!cli.short_calls, "short_calls should default to false");
}

#[test]
fn default_one_way_is_false() {
    let cli = defaults();
    assert!(!cli.one_way, "one_way should default to false");
}

#[test]
fn default_nat_issues_is_false() {
    let cli = defaults();
    assert!(!cli.nat_issues, "nat_issues should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  Output
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_json_is_false() {
    let cli = defaults();
    assert!(!cli.json, "json should default to false");
}

#[test]
fn default_json_pretty_is_false() {
    let cli = defaults();
    assert!(!cli.json_pretty, "json_pretty should default to false");
}

#[test]
fn default_report_is_false() {
    let cli = defaults();
    assert!(!cli.report, "report should default to false");
}

#[test]
fn default_call_report_is_none() {
    let cli = defaults();
    assert!(
        cli.call_report.is_none(),
        "call_report should be None by default"
    );
}

#[test]
fn default_markdown_is_false() {
    let cli = defaults();
    assert!(!cli.markdown, "markdown should default to false");
}

#[test]
fn default_hexdump_is_false() {
    let cli = defaults();
    assert!(!cli.hexdump, "hexdump should default to false");
}

#[test]
fn default_delta_time_is_false() {
    let cli = defaults();
    assert!(!cli.delta_time, "delta_time should default to false");
}

#[test]
fn default_after_is_none() {
    let cli = defaults();
    assert!(cli.after.is_none(), "after should be None by default");
}

#[test]
fn default_show_empty_is_false() {
    let cli = defaults();
    assert!(!cli.show_empty, "show_empty should default to false");
}

#[test]
fn default_line_buffer_is_false() {
    let cli = defaults();
    assert!(!cli.line_buffer, "line_buffer should default to false");
}

#[test]
fn default_color() {
    let cli = defaults();
    assert_eq!(cli.color, "auto", "default color should be auto");
}

#[test]
fn default_payload_limit_is_none() {
    let cli = defaults();
    assert!(
        cli.payload_limit.is_none(),
        "payload_limit should be None by default"
    );
}

#[test]
fn default_text_dump_is_false() {
    let cli = defaults();
    assert!(!cli.text_dump, "text_dump should default to false");
}

#[test]
fn default_wireshark_is_false() {
    let cli = defaults();
    assert!(!cli.wireshark, "wireshark should default to false");
}

#[test]
fn default_tshark_filter_is_none() {
    let cli = defaults();
    assert!(
        cli.tshark_filter.is_none(),
        "tshark_filter should be None by default"
    );
}

#[test]
fn default_fail2ban_is_false() {
    let cli = defaults();
    assert!(!cli.fail2ban, "fail2ban should default to false");
}

#[test]
fn default_group_by_is_none() {
    let cli = defaults();
    assert!(
        cli.group_by.is_none(),
        "group_by should be None by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Dialog
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_limit() {
    let cli = defaults();
    assert_eq!(cli.limit, 100_000, "default limit should be 100000");
}

#[test]
fn default_rotate_is_false() {
    let cli = defaults();
    assert!(!cli.rotate, "rotate should default to false");
}

#[test]
fn default_dialog_track_is_none() {
    let cli = defaults();
    assert!(
        cli.dialog_track.is_none(),
        "dialog_track should be None by default"
    );
}

#[test]
fn default_no_dialog_is_false() {
    let cli = defaults();
    assert!(!cli.no_dialog, "no_dialog should default to false");
}

#[test]
fn default_tag_is_none() {
    let cli = defaults();
    assert!(cli.tag.is_none(), "tag should be None by default");
}

// ═══════════════════════════════════════════════════════════════════════
//  RTP
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_rtp_interval() {
    let cli = defaults();
    assert_eq!(cli.rtp_interval, 1, "default rtp_interval should be 1");
}

#[test]
fn default_max_streams() {
    let cli = defaults();
    assert_eq!(cli.max_streams, 50_000, "default max_streams should be 50000");
}

#[test]
fn default_quality_threshold() {
    let cli = defaults();
    assert!(
        (cli.quality_threshold - 3.0).abs() < f64::EPSILON,
        "default quality_threshold should be 3.0, got {}",
        cli.quality_threshold
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Security
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_kill_scanner_is_false() {
    let cli = defaults();
    assert!(!cli.kill_scanner, "kill_scanner should default to false");
}

#[test]
fn default_kill_ua_is_none() {
    let cli = defaults();
    assert!(cli.kill_ua.is_none(), "kill_ua should be None by default");
}

#[test]
fn default_kill_response() {
    let cli = defaults();
    assert_eq!(
        cli.kill_response, 200,
        "default kill_response should be 200"
    );
}

#[test]
fn default_fraud_detect_is_false() {
    let cli = defaults();
    assert!(!cli.fraud_detect, "fraud_detect should default to false");
}

#[test]
fn default_reg_flood_is_false() {
    let cli = defaults();
    assert!(!cli.reg_flood, "reg_flood should default to false");
}

#[test]
fn default_digest_leak_is_false() {
    let cli = defaults();
    assert!(!cli.digest_leak, "digest_leak should default to false");
}

#[test]
fn default_alert_is_empty() {
    let cli = defaults();
    assert!(cli.alert.is_empty(), "alert should be empty by default");
}

#[test]
fn default_alert_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.alert_exec.is_none(),
        "alert_exec should be None by default"
    );
}

#[test]
fn default_stir_shaken_is_false() {
    let cli = defaults();
    assert!(!cli.stir_shaken, "stir_shaken should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  Event execution
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_on_dialog_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.on_dialog_exec.is_none(),
        "on_dialog_exec should be None by default"
    );
}

#[test]
fn default_on_quality_exec_is_none() {
    let cli = defaults();
    assert!(
        cli.on_quality_exec.is_none(),
        "on_quality_exec should be None by default"
    );
}

#[test]
fn default_exec_rate_limit() {
    let cli = defaults();
    assert_eq!(
        cli.exec_rate_limit, 10,
        "default exec_rate_limit should be 10"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Network listeners
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_metrics_is_none() {
    let cli = defaults();
    assert!(
        cli.metrics.is_none(),
        "metrics should be None by default"
    );
}

#[test]
fn default_metrics_auth_is_none() {
    let cli = defaults();
    assert!(
        cli.metrics_auth.is_none(),
        "metrics_auth should be None by default"
    );
}

#[test]
fn default_api_is_none() {
    let cli = defaults();
    assert!(cli.api.is_none(), "api should be None by default");
}

#[test]
fn default_api_key_is_none() {
    let cli = defaults();
    assert!(
        cli.api_key.is_none(),
        "api_key should be None by default"
    );
}

#[test]
fn default_api_tls_cert_is_none() {
    let cli = defaults();
    assert!(
        cli.api_tls_cert.is_none(),
        "api_tls_cert should be None by default"
    );
}

#[test]
fn default_api_tls_key_is_none() {
    let cli = defaults();
    assert!(
        cli.api_tls_key.is_none(),
        "api_tls_key should be None by default"
    );
}

#[test]
fn default_api_max_conn() {
    let cli = defaults();
    assert_eq!(
        cli.api_max_conn, 100,
        "default api_max_conn should be 100"
    );
}

#[test]
fn default_hep_listen_is_none() {
    let cli = defaults();
    assert!(
        cli.hep_listen.is_none(),
        "hep_listen should be None by default"
    );
}

#[test]
fn default_hep_send_is_none() {
    let cli = defaults();
    assert!(
        cli.hep_send.is_none(),
        "hep_send should be None by default"
    );
}

#[test]
fn default_hep_parse_is_false() {
    let cli = defaults();
    assert!(!cli.hep_parse, "hep_parse should default to false");
}

#[test]
fn default_hep_allow_is_empty() {
    let cli = defaults();
    assert!(
        cli.hep_allow.is_empty(),
        "hep_allow should be empty by default"
    );
}

#[test]
fn default_hep_rate_limit() {
    let cli = defaults();
    assert_eq!(
        cli.hep_rate_limit, 50_000,
        "default hep_rate_limit should be 50000"
    );
}

#[test]
fn default_syslog_is_false() {
    let cli = defaults();
    assert!(!cli.syslog, "syslog should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  TLS / Decryption
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_tls_key_is_none() {
    let cli = defaults();
    assert!(
        cli.tls_key.is_none(),
        "tls_key should be None by default"
    );
}

#[test]
fn default_keylog_is_none() {
    let cli = defaults();
    assert!(cli.keylog.is_none(), "keylog should be None by default");
}

#[test]
fn default_keylog_watch_is_false() {
    let cli = defaults();
    assert!(!cli.keylog_watch, "keylog_watch should default to false");
}

#[test]
fn default_dtls_keylog_is_none() {
    let cli = defaults();
    assert!(
        cli.dtls_keylog.is_none(),
        "dtls_keylog should be None by default"
    );
}

#[test]
fn default_srtp_keys_is_none() {
    let cli = defaults();
    assert!(
        cli.srtp_keys.is_none(),
        "srtp_keys should be None by default"
    );
}

#[test]
fn default_pcap_export_mode() {
    let cli = defaults();
    assert_eq!(
        cli.pcap_export_mode, "decrypted",
        "default pcap_export_mode should be decrypted"
    );
}

#[test]
fn default_allow_coredump_is_false() {
    let cli = defaults();
    assert!(
        !cli.allow_coredump,
        "allow_coredump should default to false"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Privilege
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_user_is_none() {
    let cli = defaults();
    assert!(cli.user.is_none(), "user should be None by default");
}

#[test]
fn default_no_priv_drop_is_false() {
    let cli = defaults();
    assert!(!cli.no_priv_drop, "no_priv_drop should default to false");
}

#[test]
fn default_chroot_is_none() {
    let cli = defaults();
    assert!(cli.chroot.is_none(), "chroot should be None by default");
}

// ═══════════════════════════════════════════════════════════════════════
//  Resource limits
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_max_reassembly() {
    let cli = defaults();
    assert_eq!(
        cli.max_reassembly, 10_000,
        "default max_reassembly should be 10000"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Config
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn default_config_is_none() {
    let cli = defaults();
    assert!(cli.config.is_none(), "config should be None by default");
}

#[test]
fn default_no_config_is_false() {
    let cli = defaults();
    assert!(!cli.no_config, "no_config should default to false");
}

#[test]
fn default_dump_config_is_false() {
    let cli = defaults();
    assert!(!cli.dump_config, "dump_config should default to false");
}

// ═══════════════════════════════════════════════════════════════════════
//  Validation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn defaults_pass_validation() {
    let cli = defaults();
    assert!(
        cli.validate().is_ok(),
        "default arguments with -N should pass validation"
    );
}
