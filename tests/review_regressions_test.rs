// SPDX-License-Identifier: MIT OR Apache-2.0

//! Regression corpus for the September 18 operator-contract review.
//! Each scenario checks an exported artifact, selected traffic, authentication
//! configuration, or startup verdict rather than a private implementation detail.
#![cfg(feature = "native")]

use clap::Parser;
use sipnab::capture::{PcapExportMode, PcapWriter};
use sipnab::cli::Cli;
use sipnab::security::{AlertEngine, AlertRule};

#[path = "support/run.rs"]
mod run_support;

const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// Given key material, only the explicit secret-bearing mode exports a DSB.
#[test]
fn exported_secrets_require_an_explicit_mode() {
    let dir = tempfile::tempdir().unwrap();
    let keylog = dir.path().join("keys.log");
    let secret = b"CLIENT_RANDOM 00112233 aabbccdd\n";
    std::fs::write(&keylog, secret).unwrap();
    let cli = Cli::try_parse_from(["sipnab"]).unwrap();
    let default = PcapExportMode::parse_mode(&cli.tls_args.pcap_export_mode).unwrap();
    for (name, mode, expected) in [
        ("default", default, 0),
        ("raw", PcapExportMode::Raw, 0),
        ("explicit", PcapExportMode::EncryptedWithDsb, 1),
    ] {
        let path = dir.path().join(format!("{name}.pcapng"));
        let mut writer = PcapWriter::with_format(&path, 1, None, None, true, mode).unwrap();
        writer.maybe_write_keylog_dsb(&keylog).unwrap();
        writer.finish().unwrap();
        let bytes = std::fs::read(path).unwrap();
        let mut reader = pcap_file::pcapng::PcapNgReader::new(&bytes[..]).unwrap();
        let mut secrets = 0;
        while let Some(block) = reader.next_block() {
            if let pcap_file::pcapng::Block::Unknown(block) = block.unwrap()
                && block.type_ == 0x0000000a
            {
                secrets += 1;
                assert!(block.value.windows(secret.len()).any(|w| w == secret));
            }
        }
        assert_eq!(secrets, expected, "{name} export's DSB count");
    }
}

/// Asking for unsupported plaintext export fails before creating an artifact.
#[test]
fn unsupported_plaintext_export_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("plaintext.pcapng");
    let (_, stderr, code) = run_support::run(
        &[
            "--no-config",
            "-N",
            "-I",
            FIXTURE,
            "--pcapng",
            "-O",
            output.to_str().unwrap(),
            "--pcap-export-mode",
            "decrypted",
        ],
        Some("warn"),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("decrypted") && stderr.contains("not supported"),
        "{stderr}"
    );
    assert!(!output.exists(), "refusal must precede creating the output");
    assert!(
        PcapWriter::with_format(&output, 1, None, None, true, PcapExportMode::Decrypted).is_err(),
        "library callers must receive the same refusal"
    );
    assert!(!output.exists());
}

/// A registration-flood rule controls the actual detector's emitted kind.
#[test]
fn hyphenated_registration_rule_gates_real_detector_events() {
    let rule = AlertRule::parse("reg-flood:2/1m:0s").unwrap();
    let mut engine = AlertEngine::new(vec![rule], None);
    let ip = "192.0.2.1".parse().unwrap();
    let at = chrono::Utc::now();
    assert!(!engine.fire("reg_flood", ip, "first", at));
    assert!(engine.fire("reg_flood", ip, "second", at));
}

/// A rule naming no detector must fail startup instead of silently doing nothing.
#[test]
fn unknown_alert_rule_is_refused() {
    let (_, stderr, code) = run_support::run(
        &[
            "--no-config",
            "-N",
            "-I",
            FIXTURE,
            "--alert",
            "5xx-rate:10/1m",
        ],
        Some("warn"),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("5xx-rate") && stderr.contains("Unknown alert"),
        "{stderr}"
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("sipnab.toml");
    std::fs::write(&config, "[security]\nalert = [\"5xx-rate:10/1m\"]\n").unwrap();
    let (_, stderr, code) = run_support::run(
        &["--config", config.to_str().unwrap(), "-N", "-I", FIXTURE],
        Some("warn"),
    );
    assert_eq!(code, Some(2), "config rule: {stderr}");
    assert!(stderr.contains("Unknown alert"), "{stderr}");
    for name in ["scanner", "fraud", "digest", "reg-flood", "reg_flood"] {
        let rule = format!("{name}:2/1m");
        let (_, stderr, code) = run_support::run(
            &["--no-config", "-N", "-I", FIXTURE, "--alert", &rule],
            Some("warn"),
        );
        assert_eq!(code, Some(0), "valid rule {name}: {stderr}");
    }
}

/// Explicit filters narrow diagnostic selection instead of replacing it.
#[test]
fn explicit_filter_preserves_diagnostic_selection() {
    let run = |extra: &[&str]| {
        let mut args = vec!["--no-config", "-N", "-I", FIXTURE, "--json-dialogs"];
        args.extend_from_slice(extra);
        let (out, err, code) = run_support::run(&args, Some("warn"));
        assert_eq!(code, Some(0), "{err}");
        out.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect::<Vec<_>>()
    };
    let all = run(&["--filter", "retransmits >= 0"]);
    assert!(!all.is_empty(), "fixture must contain a selectable dialog");
    let selected = run(&["--problems"]);
    assert_ne!(all, selected, "fixture must distinguish healthy traffic");
    assert_eq!(
        run(&["--problems", "--filter", "retransmits >= 0"]),
        selected
    );
}

/// The published flag description agrees with the existing cross-line behavior.
#[test]
fn single_line_help_describes_restricting_dot_matching() {
    let (help, _, code) = run_support::run(&["--help"], Some("warn"));
    assert_eq!(code, Some(0));
    assert!(help.contains("Prevent '.' from matching newlines"));
}

/// Operator instructions must not promise actions and fields absent from the product.
#[test]
fn operator_docs_do_not_promise_missing_behavior() {
    for (path, false_claims) in [
        (
            "docs/cli-reference.md",
            vec![
                "Launch Wireshark",
                "Hand the capture to Wireshark",
                "hand the capture to Wireshark",
            ],
        ),
        (
            "docs/tui-walkthrough.md",
            vec!["accepts the full", "jitter, loss, and MOS"],
        ),
        (
            "docs/keybindings.md",
            vec!["<span class=\"t-header\">Filter:</span>"],
        ),
        (
            "docs/examples.md",
            vec![
                "isolated kill-child",
                "which does include them",
                "hands it to Wireshark",
                "`--wireshark` needs Wireshark installed",
            ],
        ),
        ("docs/mcp-deploy.md", vec!["a packaged variant ships in"]),
        (
            "src/mcp/tools/await_condition.rs",
            vec!["backlog.md` DECLINES"],
        ),
    ] {
        let content = std::fs::read_to_string(path).unwrap();
        for claim in false_claims {
            assert!(!content.contains(claim), "{path} still promises {claim}");
        }
    }
}

/// A successful diagnostic selection can still be narrowed to no dialogs.
#[test]
fn explicit_filter_narrows_a_matching_diagnostic_alias() {
    let run = |filter: &str| {
        run_support::run(
            &[
                "--no-config",
                "-N",
                "-I",
                FIXTURE,
                "--json-dialogs",
                "--short-calls",
                "--fraud-short-call",
                "120",
                "--filter",
                filter,
            ],
            Some("warn"),
        )
    };
    let (selected, err, code) = run("retransmits >= 0");
    assert_eq!(code, Some(0), "{err}");
    assert!(
        selected.lines().any(|l| l.starts_with('{')),
        "fixture must match the alias"
    );
    let (excluded, err, code) = run("retransmits > 100");
    assert_eq!(code, Some(0), "{err}");
    assert!(!excluded.lines().any(|l| l.starts_with('{')));
}

/// Resolve secrets in child processes so parallel tests never mutate the environment.
#[cfg(feature = "mcp-http")]
#[test]
fn token_file_beats_environment_but_explicit_token_beats_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, " file-token\n").unwrap();
    for scenario in ["file", "explicit", "environment"] {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "token_precedence_child", "--nocapture"])
            .env("SIPNAB_REVIEW_TOKEN_CASE", scenario)
            .env("SIPNAB_REVIEW_TOKEN_FILE", &file)
            .env("SIPNAB_MCP_TOKEN", "environment-token")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{scenario}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

/// Child entry point for the isolated token-precedence scenarios above.
#[cfg(feature = "mcp-http")]
#[test]
fn token_precedence_child() {
    let Ok(case) = std::env::var("SIPNAB_REVIEW_TOKEN_CASE") else {
        return;
    };
    let file = std::env::var("SIPNAB_REVIEW_TOKEN_FILE").unwrap();
    let mut args = vec!["sipnab"];
    if case != "environment" {
        args.extend(["--mcp-token-file", &file]);
    }
    if case == "explicit" {
        args.extend(["--mcp-token", "explicit-token"]);
    }
    let cli = Cli::parse_from_args(args);
    let config = sipnab::app::servers::resolve_mcp_verifier_config(&cli);
    let expected = format!("{case}-token");
    assert_eq!(config.static_keys.len(), 1);
    assert!(
        config.static_keys[0] == expected,
        "wrong token source for {case}"
    );
}
