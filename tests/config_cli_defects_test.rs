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
