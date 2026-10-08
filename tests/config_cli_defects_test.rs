// SPDX-License-Identifier: MIT OR Apache-2.0

//! Defects the config/CLI test program found, one test per defect class.
//!
//! Each was a setting that one surface accepted and the other refused, or a
//! value accepted on both and then ignored with nothing said. The
//! generated matrices in `config_cli_flag_values_test.rs` and
//! `config_cli_key_values_test.rs` keep every flag and key covered; these
//! tests name the classes so a regression reads as the defect it is.
#![cfg(feature = "full")]

#[path = "support/config_cli.rs"]
mod config_cli;

use config_cli::{Outcome, Stage, TestError, argv, field_debug, run};

/// What a refusal must look like.
struct Refusal<'a> {
    /// The step that must refuse.
    stage: Stage,
    /// The exit code it must carry.
    code: i32,
    /// Text the message must contain (the flag or key).
    names: &'a str,
    /// Text the message must not contain (the other surface's spelling).
    not_names: Option<&'a str>,
}

/// Check one outcome against `want`, describing any mismatch.
fn check_refusal(what: &str, o: &Outcome, want: &Refusal<'_>) -> Option<String> {
    if o.panic.is_some() {
        return Some(format!("{what}: panicked: {:?}", o.panic));
    }
    if o.stage != want.stage || o.code != want.code {
        return Some(format!(
            "{what}: want {:?}/{} got {:?}/{} ({})",
            want.stage, want.code, o.stage, o.code, o.message
        ));
    }
    if !o.message.contains(want.names) {
        return Some(format!(
            "{what}: message does not name {}: {}",
            want.names, o.message
        ));
    }
    if let Some(bad) = want.not_names
        && o.message.contains(bad)
    {
        return Some(format!(
            "{what}: message names {bad}, which the operator did not write: {}",
            o.message
        ));
    }
    None
}

/// Turn collected mismatches into a test result.
fn verdict(failures: Vec<String>) -> Result<(), TestError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

/// Write `body` as a config file in a fresh directory and run `args`
/// against it.
fn run_with_file(args: &[&str], body: &str) -> Result<Outcome, TestError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    std::fs::write(&path, body)?;
    Ok(run(&argv(args), Some(&path)))
}

/// A flag value must be refused by clap (exit 2) naming the flag.
fn flag_refused(flag: &str, value: &str) -> Option<String> {
    let arg = format!("--{flag}={value}");
    let o = run(&argv(&[&arg]), None);
    let want = Refusal {
        stage: Stage::Parse,
        code: 2,
        names: &format!("--{flag}"),
        not_names: None,
    };
    check_refusal(&arg, &o, &want)
}

/// A flag value must be accepted.
fn flag_accepted(flag: &str, value: &str) -> Option<String> {
    let arg = format!("--{flag}={value}");
    let o = run(&argv(&[&arg]), None);
    (!o.accepted()).then(|| format!("{arg}: refused: {:?}/{} {}", o.stage, o.code, o.message))
}

/// A config key value must be refused at load (exit 1) naming the key.
fn key_refused(section: &str, key: &str, toml_value: &str) -> Result<Option<String>, TestError> {
    let body = format!("[{section}]\n{key} = {toml_value}\n");
    let o = run_with_file(&[], &body)?;
    let want = Refusal {
        stage: Stage::Config,
        code: 1,
        names: key,
        not_names: None,
    };
    Ok(check_refusal(&body, &o, &want))
}

/// A config key value must be accepted.
fn key_accepted(section: &str, key: &str, toml_value: &str) -> Result<Option<String>, TestError> {
    let body = format!("[{section}]\n{key} = {toml_value}\n");
    let o = run_with_file(&[], &body)?;
    Ok((!o.accepted()).then(|| format!("{body}: refused: {:?}/{} {}", o.stage, o.code, o.message)))
}

/// The six `[diagnosis]` thresholds whose flags accepted what their keys
/// refuse: 0, a negative, a non-finite value, and (for the percentage)
/// anything above 100.
#[test]
fn diagnosis_threshold_flags_refuse_what_their_keys_refuse() -> Result<(), TestError> {
    let secs = [
        "pdd-threshold",
        "ack-timeout",
        "no-final-response-timeout",
        "duration-asymmetry-secs",
    ];
    let mut failures = Vec::new();
    for flag in secs {
        for v in ["0", "-1", "NaN", "inf", "-inf"] {
            failures.extend(flag_refused(flag, v));
        }
        for v in ["0.001", "1", "32.5", "86400"] {
            failures.extend(flag_accepted(flag, v));
        }
    }
    for v in ["0", "-1", "NaN", "inf", "100.01", "101"] {
        failures.extend(flag_refused("duration-asymmetry-pct", v));
    }
    for v in ["0.01", "5", "100"] {
        failures.extend(flag_accepted("duration-asymmetry-pct", v));
    }
    for v in ["0", "-1", "-9223372036854775808"] {
        failures.extend(flag_refused("late-media-ms", v));
    }
    for v in ["1", "500", "9223372036854775807"] {
        failures.extend(flag_accepted("late-media-ms", v));
    }
    verdict(failures)
}

/// `--mcp-max-rows`, `--max-streams` and `--max-reassembly` accepted 0,
/// which `[limits]` refuses because a zero cap is a typo turned into
/// silence (no rows, no streams, no reassembly).
#[test]
fn limit_flags_refuse_zero_like_their_keys() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for flag in ["mcp-max-rows", "max-streams", "max-reassembly"] {
        failures.extend(flag_refused(flag, "0"));
        failures.extend(flag_accepted(flag, "1"));
        failures.extend(flag_accepted(flag, "18446744073709551615"));
    }
    verdict(failures)
}

/// `[display] color` accepted any string and ran in `auto` with nothing
/// said; `--color` refuses everything but auto, always and never.
#[test]
fn display_color_key_refuses_what_the_flag_refuses() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["\"x\"", "\"\"", "\"Always\"", "\"on\""] {
        failures.extend(key_refused("display", "color", v)?);
    }
    for v in ["\"auto\"", "\"always\"", "\"never\""] {
        failures.extend(key_accepted("display", "color", v)?);
    }
    verdict(failures)
}

/// `--one-way-delay` and `[media] one_way_delay_ms` accepted a negative or
/// non-finite delay, which the MOS resolver then discarded without a word,
/// so the score used a delay the operator had not declared.
#[test]
fn one_way_delay_refuses_negative_and_non_finite_on_both_surfaces() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["-1", "-0.5", "NaN", "inf", "-inf"] {
        failures.extend(flag_refused("one-way-delay", v));
    }
    for v in ["0", "0.5", "150", "1000"] {
        failures.extend(flag_accepted("one-way-delay", v));
    }
    // An accepted declaration is the number written, in the field the MOS
    // resolver reads.
    let o = run(&argv(&["--one-way-delay=0.5"]), None);
    let landed = o
        .cli
        .as_deref()
        .and_then(|c| field_debug(c, "one_way_delay_ms"));
    if !landed.as_deref().is_some_and(|t| t.contains("0.5")) {
        failures.push(format!("--one-way-delay=0.5 landed as {landed:?}"));
    }
    for v in ["-1.0", "nan", "inf", "-inf"] {
        failures.extend(key_refused("media", "one_way_delay_ms", v)?);
    }
    for v in ["0.0", "150.0", "1000"] {
        failures.extend(key_accepted("media", "one_way_delay_ms", v)?);
    }
    verdict(failures)
}

/// The eight quality-band flags accepted a negative or non-finite boundary
/// and the run was then refused at config load, exit 1, naming a
/// `[quality]` key the operator never wrote. A bad flag value is an
/// argument error: exit 2, naming the flag.
#[test]
fn quality_band_flags_refuse_non_finite_and_negative_by_flag_name() -> Result<(), TestError> {
    let flags = [
        "jitter-warn-ms",
        "jitter-bad-ms",
        "loss-warn-pct",
        "loss-bad-pct",
        "mos-warn",
        "mos-bad",
        "rtt-warn-ms",
        "rtt-bad-ms",
    ];
    let mut failures = Vec::new();
    for flag in flags {
        for v in ["-1", "NaN", "inf", "-inf"] {
            failures.extend(flag_refused(flag, v));
        }
    }
    verdict(failures)
}

/// `--business-hours x` was refused with a message about
/// `[security] business_hours`, a key the operator did not write.
#[test]
fn business_hours_flag_refusal_names_the_flag() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["x", "", "8", "8-24", "25-3", "8-8", "-1-5"] {
        let arg = format!("--business-hours={v}");
        let o = run(&argv(&[&arg]), None);
        let want = Refusal {
            stage: Stage::Validate,
            code: 2,
            names: "--business-hours",
            not_names: Some("[security]"),
        };
        failures.extend(check_refusal(&arg, &o, &want));
    }
    for v in ["\"x\"", "\"8-8\"", "\"8-24\""] {
        failures.extend(key_refused("security", "business_hours", v)?);
    }
    verdict(failures)
}

/// `[limits] api_rate_limit_per_peer` above `u32::MAX` was clamped to
/// `u32::MAX` with nothing said; `--api-rate-limit-per-peer` refuses it.
#[test]
fn api_rate_limit_key_refuses_what_the_flag_refuses() -> Result<(), TestError> {
    let mut failures = Vec::new();
    failures.extend(key_refused(
        "limits",
        "api_rate_limit_per_peer",
        "4294967296",
    )?);
    failures.extend(key_accepted(
        "limits",
        "api_rate_limit_per_peer",
        "4294967295",
    )?);
    failures.extend(flag_refused("api-rate-limit-per-peer", "4294967296"));
    failures.extend(flag_accepted("api-rate-limit-per-peer", "4294967295"));
    verdict(failures)
}

/// Path keys whose flags refuse an empty path accepted `""`.
#[test]
fn empty_path_keys_are_refused_like_their_flags() -> Result<(), TestError> {
    let pairs = [
        ("journal", "dir", "journal-dir"),
        ("tfps", "ctl", "tfps-ctl"),
        ("hep", "tls_ca", "hep-tls-ca"),
        ("hep", "tls_cert", "hep-tls-cert"),
        ("hep", "tls_key", "hep-tls-key"),
        ("hep", "tls_extra_ca", "hep-tls-extra-ca"),
    ];
    let mut failures = Vec::new();
    for (section, key, flag) in pairs {
        failures.extend(key_refused(section, key, "\"\"")?);
        let arg = format!("--{flag}=");
        let o = run(&argv(&[&arg]), None);
        if o.stage != Stage::Parse || o.code != 2 {
            failures.push(format!("{arg}: want Parse/2, got {:?}/{}", o.stage, o.code));
        }
    }
    // The two path keys with no flag follow the same rule.
    for (section, key) in [("tfps", "db"), ("crash", "report_dir")] {
        failures.extend(key_refused(section, key, "\"\"")?);
        failures.extend(key_accepted(section, key, "\"/var/tmp/sipnab-test\"")?);
    }
    verdict(failures)
}

/// `--count 0` read no packet, `--limitlen 0` parsed no byte, and
/// `--cores 0` ran as `--cores 1`, each exiting 0 with nothing said.
#[test]
fn zero_counts_that_do_nothing_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for flag in ["count", "limitlen", "cores"] {
        failures.extend(flag_refused(flag, "0"));
        failures.extend(flag_accepted(flag, "1"));
    }
    verdict(failures)
}

/// A MOS boundary above 5 and a loss boundary above 100 % can never be
/// reached, so the color column could never show the band it names. Both
/// were accepted on both surfaces.
#[test]
fn quality_boundaries_outside_their_scale_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (flag, key, bad, good) in [
        ("mos-warn", "mos_warn", "5.01", "4.5"),
        ("mos-bad", "mos_bad", "5.5", "3"),
        ("loss-warn-pct", "loss_warn_pct", "100.5", "1"),
        ("loss-bad-pct", "loss_bad_pct", "101", "100"),
    ] {
        failures.extend(flag_refused(flag, bad));
        failures.extend(flag_accepted(flag, good));
        let o = run_with_file(&[], &format!("[quality]\n{key} = {bad}\n"))?;
        let want = Refusal {
            stage: Stage::Config,
            code: 1,
            names: key,
            not_names: None,
        };
        failures.extend(check_refusal(
            &format!("[quality] {key} = {bad}"),
            &o,
            &want,
        ));
    }
    verdict(failures)
}

/// A refusal message is read by an operator: no run of spaces left behind
/// by a string literal broken across lines without a continuation.
#[test]
fn config_refusal_messages_have_no_space_runs() -> Result<(), TestError> {
    let o = run_with_file(&[], "[limits]\nexec_queue_depth = 0\n")?;
    if o.stage != Stage::Config {
        return Err(format!("want Config refusal, got {:?}", o.stage).into());
    }
    if o.message.contains("   ") {
        return Err(format!("message has a run of spaces: {:?}", o.message).into());
    }
    Ok(())
}

/// `--duration 0` (and `0s`, `0m`, `0h`) stopped a live capture before its
/// first packet and exited 0, the `--count 0` defect in time units.
#[test]
fn zero_duration_is_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["0", "0s", "0m", "0h"] {
        let arg = format!("--duration={v}");
        let o = run(&argv(&[&arg]), None);
        let want = Refusal {
            stage: Stage::Plan,
            code: 2,
            names: "--duration",
            not_names: None,
        };
        failures.extend(check_refusal(&arg, &o, &want));
    }
    for v in ["1", "1s", "5m", "1h"] {
        failures.extend(flag_accepted("duration", v));
    }
    verdict(failures)
}

/// An empty inline secret was refused naming the FILE flag:
/// `--hep-auth ""` said "--hep-auth-file: the value is empty" and
/// `--metrics-auth ""` said "--metrics-auth-file".
#[test]
fn empty_inline_secret_refusal_names_the_inline_flag() -> Result<(), TestError> {
    let mut failures = Vec::new();
    let args = ["--hep-listen=127.0.0.1:0", "--hep-auth="];
    let o = run(&argv(&args), None);
    let want = Refusal {
        stage: Stage::Plan,
        code: 2,
        names: "--hep-auth",
        not_names: Some("--hep-auth-file"),
    };
    failures.extend(check_refusal(&args.join(" "), &o, &want));
    // The metrics credential is resolved when the metrics server starts,
    // after planning, so its resolver is driven directly.
    let cli = sipnab::cli::Cli::try_parse_from_args(argv(&[
        "--metrics=127.0.0.1:0",
        "--metrics-auth=",
        "-F",
    ]))?;
    match cli.resolve_metrics_auth() {
        Ok(v) => failures.push(format!("--metrics-auth \"\": accepted as {v:?}")),
        Err(msg) if !msg.contains("--metrics-auth") || msg.contains("--metrics-auth-file") => {
            failures.push(format!(
                "--metrics-auth \"\": message names the wrong flag: {msg}"
            ));
        }
        Err(_) => {}
    }
    verdict(failures)
}

/// `--ws-portrange` and `--portrange` share one grammar and one parser, but
/// a malformed `--ws-portrange` exited 1 (an environment error) where the
/// same value in `--portrange` exits 2 (an argument error). The key keeps
/// exit 1, as every config refusal does.
#[test]
fn malformed_ws_portrange_flag_is_an_argument_error() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["x", "", "5061-5060", "0-65536"] {
        for flag in ["portrange", "ws-portrange"] {
            let arg = format!("--{flag}={v}");
            let o = run(&argv(&[&arg]), None);
            if o.code != 2 || !o.message.contains(&format!("--{flag}")) {
                failures.push(format!(
                    "{arg}: want exit 2 naming the flag, got {:?}/{} {}",
                    o.stage, o.code, o.message
                ));
            }
        }
    }
    failures.extend(key_refused("capture", "ws_ports", "\"5061-5060\"")?);
    verdict(failures)
}

/// `--kill-ua ""` compiled to `(?i)`, which matches every User-Agent, so
/// with `--kill-scanner` every caller was a scanner; a pattern that is not a
/// regular expression was skipped with a warning and the run went on
/// without it. Both are refused before anything runs.
#[test]
fn kill_ua_refuses_empty_and_invalid_patterns() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["", " ", "(", "[a-", "a{99999999}"] {
        let arg = format!("--kill-ua={v}");
        let o = run(&argv(&["--kill-scanner", &arg]), None);
        let want = Refusal {
            stage: Stage::Parse,
            code: 2,
            names: "--kill-ua",
            not_names: None,
        };
        failures.extend(check_refusal(&arg, &o, &want));
    }
    for v in ["friendly-scanner", "sip(vicious|cli)", "^pplsip$"] {
        let arg = format!("--kill-ua={v}");
        let o = run(&argv(&["--kill-scanner", &arg]), None);
        if !o.accepted() {
            failures.push(format!("{arg}: refused: {}", o.message));
        }
    }
    verdict(failures)
}

/// `--alert jsno` (an unknown channel, unlike an unknown rule) was logged as
/// a warning and the run went on with no alert channel, exit 0.
#[test]
fn unknown_alert_channel_is_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["bogus", "jsno", "", " "] {
        let arg = format!("--alert={v}");
        let o = run(&argv(&[&arg]), None);
        let want = Refusal {
            stage: Stage::Plan,
            code: 2,
            names: "alert channel",
            not_names: None,
        };
        failures.extend(check_refusal(&arg, &o, &want));
    }
    for v in ["syslog", "json", "JSON", "scanner:5/60s"] {
        failures.extend(flag_accepted("alert", v));
    }
    let o = run_with_file(&[], "[security]\nalert = [\"jsno\"]\n")?;
    if o.accepted() || !o.message.contains("jsno") {
        failures.push(format!(
            "[security] alert = [\"jsno\"]: {:?}/{} {}",
            o.stage, o.code, o.message
        ));
    }
    verdict(failures)
}

/// `--fraud-destination` accepted any text. A code the dial plan does not
/// label (`US`, which the plan calls `NANP`; `XX`; `USA`) can never match a
/// call, so the destination watch was silently empty.
#[test]
fn unknown_fraud_destination_is_refused_on_both_surfaces() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["x", "USA", "XX", "US", "CU,XX", "1", "CU,,US"] {
        let arg = format!("--fraud-destination={v}");
        let o = run(&argv(&["--fraud-detect", &arg]), None);
        let want = Refusal {
            stage: Stage::Validate,
            code: 2,
            names: "--fraud-destination",
            not_names: None,
        };
        failures.extend(check_refusal(&arg, &o, &want));
        failures.extend(key_refused(
            "security",
            "fraud_destination",
            &format!("{v:?}"),
        )?);
    }
    for v in ["CU", "cu,kp", "DO,VG,MA", "NANP"] {
        let arg = format!("--fraud-destination={v}");
        let o = run(&argv(&["--fraud-detect", &arg]), None);
        if !o.accepted() {
            failures.push(format!("{arg}: refused: {}", o.message));
        }
        failures.extend(key_accepted(
            "security",
            "fraud_destination",
            &format!("{v:?}"),
        )?);
    }
    verdict(failures)
}

/// A quality-band flag that crossed its partner boundary was refused at
/// config load, exit 1, naming `[quality] <key>` even though the operator
/// wrote the flag. It is an argument error: exit 2, naming the flag.
#[test]
fn quality_band_ordering_refusal_names_the_flag() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (flag, v) in [
        ("jitter-bad-ms", "1"),
        ("jitter-warn-ms", "100"),
        ("loss-bad-pct", "0.5"),
        ("mos-warn", "1"),
        ("mos-bad", "5"),
        ("rtt-bad-ms", "5"),
    ] {
        let arg = format!("--{flag}={v}");
        let o = run(&argv(&[&arg]), None);
        let key = flag.replace('-', "_");
        let want = Refusal {
            stage: Stage::Config,
            code: 2,
            names: &format!("--{flag}"),
            not_names: Some(&format!("[quality] {key}")),
        };
        failures.extend(check_refusal(&arg, &o, &want));
    }
    // The same crossing from the file is still a config error naming keys.
    let o = run_with_file(&[], "[quality]\njitter_bad_ms = 1.0\n")?;
    let want = Refusal {
        stage: Stage::Config,
        code: 1,
        names: "[quality] jitter_bad_ms",
        not_names: None,
    };
    failures.extend(check_refusal("[quality] jitter_bad_ms = 1.0", &o, &want));
    verdict(failures)
}

/// A refusal of a blank value has nothing to quote, so it must name the
/// flag: `-I ""` said only "'' does not exist".
#[test]
fn blank_value_refusals_name_the_flag() -> Result<(), TestError> {
    let mut failures = Vec::new();
    let cases: [(&[&str], &str, &str); 5] = [
        (&[], "input", "-I"),
        (&["-I", "tests/fixtures"], "input-name", "--input-name"),
        (&[], "bpf-file", "--bpf-file"),
        (&[], "alert", "--alert"),
        (&[], "uprobe-library", "--uprobe-library"),
    ];
    for (ctx, flag, names) in cases {
        for v in ["", " "] {
            let arg = format!("--{flag}={v}");
            let mut args: Vec<&str> = ctx.to_vec();
            args.push(&arg);
            let o = run(&argv(&args), None);
            if o.accepted() || !o.message.contains(names) {
                failures.push(format!("{arg}: {:?}/{} {}", o.stage, o.code, o.message));
            }
        }
    }
    verdict(failures)
}

/// A `[theme]` color or `[keybindings]` key the TUI cannot parse was
/// dropped when the TUI started, with only a log warning the TUI screen
/// covers, so `accent = "magneta"` left the default in force.
#[test]
fn unparseable_theme_colors_and_keys_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, bad, good) in [
        ("theme", "accent", "\"magneta\"", "\"magenta\""),
        ("theme", "status_bg", "\"#12345\"", "\"#123456\""),
        ("theme", "highlight", "\"\"", "\"yellow\""),
        ("keybindings", "quit", "\"\"", "\"q\""),
        ("keybindings", "help", "\"ctrl-banana\"", "\"F1\""),
    ] {
        failures.extend(key_refused(section, key, bad)?);
        failures.extend(key_accepted(section, key, good)?);
    }
    verdict(failures)
}

/// `[display] from_to`, `[display] visible_columns` and `[names.manual]`
/// accepted values the TUI then dropped with a log warning its screen
/// covers: an unknown From/To mode, a column label that is not a column
/// (`["x"]` hid every column), an IP key that is not an address.
#[test]
fn tui_display_and_manual_name_typos_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (section, key, bad, good) in [
        ("display", "from_to", "\"hostport\"", "\"host-port\""),
        ("display", "from_to", "\"\"", "\"user\""),
        (
            "display",
            "visible_columns",
            "[\"x\"]",
            "[\"From\", \"To\"]",
        ),
        (
            "display",
            "visible_columns",
            "[\"From\", \"Too\"]",
            "[\"#\", \"state\"]",
        ),
    ] {
        failures.extend(key_refused(section, key, bad)?);
        failures.extend(key_accepted(section, key, good)?);
    }
    for (bad, good) in [
        ("\"sbc\" = \"edge\"", "\"10.0.0.1\" = \"edge\""),
        ("\"10.0.0.1\" = \"\"", "\"2001:db8::1\" = \"core\""),
    ] {
        let o = run_with_file(&[], &format!("[names.manual]\n{bad}\n"))?;
        let want = Refusal {
            stage: Stage::Config,
            code: 1,
            names: "[names.manual]",
            not_names: None,
        };
        failures.extend(check_refusal(bad, &o, &want));
        let o = run_with_file(&[], &format!("[names.manual]\n{good}\n"))?;
        if !o.accepted() {
            failures.push(format!("{good}: refused: {}", o.message));
        }
    }
    verdict(failures)
}

/// A names file that cannot be read (`--names`, `[names] hosts_file`) was
/// warned about, or for the key skipped without a word, and the run went on
/// without the names the operator asked for.
#[test]
fn unreadable_names_files_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for v in ["/nonexistent/sipnab-names", ""] {
        let arg = format!("--names={v}");
        let o = run(&argv(&[&arg]), None);
        if o.accepted() || o.code != 1 || !o.message.contains("--names") {
            failures.push(format!("{arg}: {:?}/{} {}", o.stage, o.code, o.message));
        }
        failures.extend(key_refused("names", "hosts_file", &format!("{v:?}"))?);
    }
    failures.extend(flag_accepted("names", "/dev/null"));
    failures.extend(key_accepted("names", "hosts_file", "\"/dev/null\"")?);
    verdict(failures)
}

/// A refused config value exited 1 when `load_config` refused it and 2 when
/// `plan` did (`[capture] portrange`, `[filter] expression`, `[actions]
/// tfps`, `[mcp] tools`, `[security] alert`, `[filter] from` and `to`), and 2
/// for half a TLS pair written in the file. One class of error, one exit
/// code: a value from the config file exits 1, a value from the command line
/// exits 2, whichever step refuses it. Each message names the key the
/// operator wrote, not the flag they did not.
#[test]
fn refused_config_values_exit_1_wherever_they_are_refused() -> Result<(), TestError> {
    let mut failures = Vec::new();
    let keys: [(&str, &str, &str, &str); 9] = [
        (
            "capture",
            "portrange = \"x\"",
            "[capture] portrange",
            "--portrange",
        ),
        (
            "filter",
            "expression = \"x\"",
            "[filter] expression",
            "--filter",
        ),
        (
            "actions",
            "tfps = [\"x\"]",
            "[actions] tfps",
            "--allow-action",
        ),
        ("mcp", "tools = [\"x\"]", "[mcp] tools", "--mcp-tools"),
        ("security", "alert = [\"x\"]", "[security] alert", "--alert"),
        (
            "security",
            "alert = [\"bogus:5/60s\"]",
            "[security] alert",
            "--alert",
        ),
        ("filter", "from = \"(\"", "[filter] from", "--from"),
        ("filter", "to = \"(\"", "[filter] to", "--to"),
        (
            "api",
            "tls_cert = \"/nonexistent/cert.pem\"",
            "[api] tls_cert",
            "\0",
        ),
    ];
    for (section, line, names, flag) in keys {
        let body = format!("[{section}]\n{line}\n");
        let o = run_with_file(&[], &body)?;
        if !matches!(o.stage, Stage::Config | Stage::Plan) || o.code != 1 {
            failures.push(format!(
                "{body}: want exit 1, got {:?}/{} {}",
                o.stage, o.code, o.message
            ));
            continue;
        }
        if !o.message.contains(names) {
            failures.push(format!("{body}: does not name {names}: {}", o.message));
        }
        if o.message.contains(&format!("{flag} ")) || o.message.contains(&format!("{flag}:")) {
            failures.push(format!("{body}: names {flag}, not written: {}", o.message));
        }
    }
    // The same refusals from the command line stay argument errors.
    let flags: [&[&str]; 8] = [
        &["--portrange=x"],
        &["--filter=x"],
        &["--mcp-tools=x"],
        &["--alert=x"],
        &["--alert=bogus:5/60s"],
        &["--from=("],
        &["--to=("],
        &["--api-tls-cert=/nonexistent/cert.pem"],
    ];
    for args in flags {
        let o = run(&argv(args), None);
        let flag = args[0].split('=').next().unwrap_or_default();
        if o.accepted() || o.code != 2 || !o.message.contains(flag) {
            failures.push(format!(
                "{args:?}: want exit 2 naming {flag}, got {:?}/{} {}",
                o.stage, o.code, o.message
            ));
        }
    }
    verdict(failures)
}

/// The binary exits with the code the in-process pipeline reports for a
/// refused config value: `[capture] portrange` (refused while planning) and
/// `[vcon_forward] url` (refused by the forwarder, which runs before the
/// capture pipeline) exit 1; the same values as flags exit 2.
#[test]
fn binary_exit_code_follows_where_the_refused_value_came_from() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let spool = dir.path().join("spool");
    std::fs::create_dir(&spool)?;
    let spool = spool.display().to_string();
    let cases: [(&str, Vec<&str>, i32, &str); 4] = [
        (
            "[capture]\nportrange = \"x\"\n",
            vec!["-N"],
            1,
            "[capture] portrange",
        ),
        ("", vec!["-N", "--portrange=x"], 2, "--portrange"),
        (
            "[vcon_forward]\nurl = \"x\"\nauth_file = \"/nonexistent/auth\"\n",
            vec!["--vcon-forward", &spool, "--vcon-forward-once"],
            1,
            "[vcon_forward] url",
        ),
        (
            "[vcon_forward]\nauth_file = \"/nonexistent/auth\"\n",
            vec![
                "--vcon-forward",
                &spool,
                "--vcon-forward-once",
                "--vcon-forward-url=x",
            ],
            2,
            "--vcon-forward-url",
        ),
    ];
    let mut failures = Vec::new();
    for (body, args, code, names) in cases {
        let path = dir.path().join("sipnab.toml");
        std::fs::write(&path, body)?;
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args)
            .arg("-f")
            .arg(&path)
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_CONFIG")
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.code() != Some(code) || !stderr.contains(names) {
            failures.push(format!(
                "{body:?} {args:?}: want exit {code} naming {names}, got {:?}: {stderr}",
                out.status.code()
            ));
        }
    }
    verdict(failures)
}

/// `--keylog` naming a file that does not exist logged an ERROR and the run
/// exited 0 without decrypting anything, while `--tls-key` and
/// `--dtls-keylog` refuse the same condition with exit 1. All three refuse
/// it alike: exit 1, `Failed to load --<flag> <path>: <reason>`.
#[test]
fn missing_key_files_refuse_the_run_alike() -> Result<(), TestError> {
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let mut failures = Vec::new();
    for flag in ["--keylog", "--tls-key", "--dtls-keylog"] {
        let missing = "/nonexistent/sipnab-key-file";
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "-F", "--no-cli-print", "-I", pcap, flag, missing])
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_CONFIG")
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        let want = format!("Failed to load {flag} {missing}: ");
        if out.status.code() != Some(1) || !stderr.contains(&want) {
            failures.push(format!(
                "{flag} {missing}: want exit 1 and {want:?}, got {:?}: {stderr}",
                out.status.code()
            ));
        }
    }
    verdict(failures)
}

/// `--snaplen 0` captured no byte of any packet and `--buffer 0` asked the
/// kernel for no ring, each accepted with nothing said, as were `[capture]
/// snaplen = 0` and `[capture] buffer = 0`. Refused on both surfaces by the
/// rule `--count 0` and the `[limits]` counts follow.
#[test]
fn zero_snaplen_and_buffer_are_refused_on_both_surfaces() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (flag, key) in [("snaplen", "snaplen"), ("buffer", "buffer")] {
        failures.extend(flag_refused(flag, "0"));
        failures.extend(flag_accepted(flag, "1"));
        failures.extend(flag_accepted(flag, "4294967295"));
        failures.extend(key_refused("capture", key, "0")?);
        failures.extend(key_accepted("capture", key, "1")?);
    }
    verdict(failures)
}

/// An empty `--api-tls-cert`, `--mcp-tls-cert` or `--metrics-tls-cert` (or
/// key), and the same empty path in `[api]`, `[mcp]` or `[metrics]`, was
/// accepted at startup and failed only when the listener tried to open "".
/// Refused by the empty-path rule the `[hep]` TLS paths follow: the flag
/// exits 2 at parse, the key exits 1 at load, each naming itself.
#[test]
fn empty_listener_tls_paths_are_refused_on_both_surfaces() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for section in ["api", "mcp", "metrics"] {
        for (half, other) in [("cert", "key"), ("key", "cert")] {
            let flag = format!("--{section}-tls-{half}");
            let other_flag = format!("--{section}-tls-{other}=/nonexistent/sipnab-{other}");
            let arg = format!("{flag}=");
            let o = run(&argv(&[&arg, &other_flag]), None);
            let want = Refusal {
                stage: Stage::Parse,
                code: 2,
                names: &flag,
                not_names: None,
            };
            failures.extend(check_refusal(&arg, &o, &want));
            let body = format!(
                "[{section}]\ntls_{half} = \"\"\ntls_{other} = \"/nonexistent/sipnab-{other}\"\n"
            );
            let o = run_with_file(&[], &body)?;
            let want = Refusal {
                stage: Stage::Config,
                code: 1,
                names: &format!("[{section}] tls_{half}"),
                not_names: None,
            };
            failures.extend(check_refusal(&body, &o, &want));
        }
    }
    verdict(failures)
}

/// `--exec-rate-limit 0` and `--api-max-conn 0` switch the limit off, which
/// neither the help text nor the reference row said; `0` read as a limit of
/// nothing. The help and the reference row each say what `0` does.
#[test]
fn zero_meaning_no_limit_is_stated_where_the_flag_is_documented() -> Result<(), TestError> {
    use clap::CommandFactory;
    let reference = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/cli-reference.md"
    ))?;
    let cmd = sipnab::cli::Cli::command();
    let mut failures = Vec::new();
    for flag in ["exec-rate-limit", "api-max-conn"] {
        let help = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some(flag))
            .and_then(|a| a.get_help().map(ToString::to_string))
            .unwrap_or_default();
        if !help.contains("`0` means no limit") {
            failures.push(format!("--{flag} help: {help:?}"));
        }
        let row = reference
            .lines()
            .find(|l| l.starts_with(&format!("| `--{flag}` |")))
            .unwrap_or_default();
        if !row.contains("`0` means no limit") {
            failures.push(format!("--{flag} reference row: {row:?}"));
        }
    }
    verdict(failures)
}

/// HEP options that only the listener (`-L`) or the sender (`--hep-send`)
/// reads were accepted on a run with neither, and did nothing: `--hep-allow
/// 192.0.2.1` on a pcap run looked like an allowlist and was none. Given on
/// the command line, each is refused naming what it needs. `-E` is not a HEP
/// surface for them: it unwraps HEP found in the capture and reads no
/// allowlist, rate limit or credential.
#[test]
fn hep_options_without_their_surface_are_refused_on_the_command_line() -> Result<(), TestError> {
    let listener = ["--hep-listen=127.0.0.1:0"];
    let sender = ["--hep-send=127.0.0.1:9"];
    // (option, the surfaces that make it live, the flag a refusal must name)
    let cases: [(&str, &[&[&str]], &str); 7] = [
        ("--hep-allow=192.0.2.1", &[&listener], "--hep-listen"),
        ("--hep-rate-limit=10", &[&listener], "--hep-listen"),
        ("--hep-rate-limit-per-peer=5", &[&listener], "--hep-listen"),
        ("--hep-hmac-window=60", &[&listener], "--hep-listen"),
        ("--hep-auth-mode=hmac", &[&listener, &sender], "--hep-send"),
        ("--hep-auth-file=/nonexistent/k", &[&sender], "--hep-send"),
        ("--hep-id=7", &[&sender], "--hep-send"),
    ];
    let mut failures = Vec::new();
    for (opt, surfaces, needs) in cases {
        for extra in [
            &[][..],
            &["-E"][..],
            &["-I", "tests/fixtures/sip_call.pcap"][..],
        ] {
            let mut args: Vec<&str> = extra.to_vec();
            args.push(opt);
            let o = run(&argv(&args), None);
            if o.accepted() || o.code != 2 || !o.message.contains(needs) {
                failures.push(format!(
                    "{args:?}: want exit 2 naming {needs}, got {:?}/{} {}",
                    o.stage, o.code, o.message
                ));
            }
        }
        for surface in surfaces {
            let mut args: Vec<&str> = surface.to_vec();
            args.push(opt);
            let o = run(&argv(&args), None);
            if o.stage == Stage::Parse {
                failures.push(format!("{args:?}: refused at parse: {}", o.message));
            }
        }
    }
    verdict(failures)
}

/// The same settings from a config file are not refused, since one file
/// serves runs with and without a listener, but a run they cannot affect
/// says so at startup, naming the key.
#[test]
fn hep_keys_without_their_surface_warn_naming_the_key() -> Result<(), TestError> {
    let pcap = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sip_call.pcap");
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sipnab.toml");
    let mut failures = Vec::new();
    for (section, line, key) in [
        ("limits", "hep_rate_limit = 10", "[limits] hep_rate_limit"),
        (
            "security",
            "hep_hmac_window_secs = 60",
            "[security] hep_hmac_window_secs",
        ),
    ] {
        std::fs::write(&path, format!("[{section}]\n{line}\n"))?;
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(["-N", "--no-cli-print", "-I", pcap, "-f"])
            .arg(&path)
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_CONFIG")
            .output()?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        let warned = stderr
            .lines()
            .any(|l| l.contains("WARN") && l.contains(key) && l.contains("--hep-listen"));
        if out.status.code() != Some(0) || !warned {
            failures.push(format!(
                "{key}: want exit 0 and a warning naming it, got {:?}: {stderr}",
                out.status.code()
            ));
        }
    }
    verdict(failures)
}
