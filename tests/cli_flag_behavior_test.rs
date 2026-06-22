//! Behavioral coverage for CLI flags that were in the T6.2 `KNOWN_UNTESTED`
//! debt baseline (verification plan M6 burn-down). Each test exercises the
//! flag's real effect, not just its name.
#![cfg(feature = "api")] // `api` implies `native` (pcap + mint + auth available)

use std::io::Write;
use std::process::Command;

use sipnab::auth::{TokenVerifier, VerifierConfig};

const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// Run the binary from the crate root with a quiet, deterministic env; return stdout.
fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("SIPNAB_LOG", "off")
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    assert!(
        out.status.success(),
        "sipnab {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

fn ndjson_lines(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("ndjson"))
        .collect()
}

#[test]
fn count_limits_message_output() {
    // --count N stops after N packets → at most N messages.
    let msgs = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--count", "3", "--json"]));
    assert_eq!(msgs.len(), 3, "--count 3 must yield exactly 3 messages");
}

#[test]
fn calls_only_emits_only_call_associated_messages() {
    // --calls-only suppresses standalone messages → every emitted message
    // carries a call_id.
    let msgs = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--calls-only", "--json"]));
    assert!(!msgs.is_empty(), "--calls-only should still emit the call");
    for m in &msgs {
        assert!(
            m.get("call_id").and_then(|v| v.as_str()).is_some(),
            "--calls-only must not emit standalone (call_id-less) messages: {m}"
        );
    }
}

#[test]
fn text_dump_emits_raw_sip() {
    // --text-dump prints the raw SIP message text (request line + headers).
    let out = run(&["-N", "-I", FIXTURE, "--text-dump"]);
    assert!(
        out.contains("INVITE sip:1002@10.0.0.2 SIP/2.0"),
        "--text-dump must contain the raw SIP request line"
    );
    assert!(out.contains("Via: SIP/2.0/UDP"), "raw headers expected");
}

#[test]
fn pcapng_output_writes_pcapng_magic() {
    // -O <file> --pcapng writes a PCAP-NG file (Section Header Block magic).
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("out.pcapng");
    run(&[
        "-N",
        "-I",
        FIXTURE,
        "-O",
        out_path.to_str().unwrap(),
        "--pcapng",
    ]);
    let bytes = std::fs::read(&out_path).expect("read written pcapng");
    assert!(bytes.len() >= 4, "pcapng too short");
    assert_eq!(&bytes[..4], &[0x0a, 0x0d, 0x0d, 0x0a], "pcapng SHB magic");
}

#[test]
fn mint_with_api_signing_key_file_and_ttl_roundtrips_with_expiry() {
    // --api-signing-key-file (key from a file) + --api-token-ttl (lifetime):
    // mint a token via the CLI, then verify it round-trips and expires per TTL.
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("api.key");
    let key = b"file-loaded-signing-key-0123456789";
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key)
        .unwrap();

    let token = run(&[
        "--mint-token",
        "--api-signing-key-file",
        key_path.to_str().unwrap(),
        "--api-token-ttl",
        "60",
        "--token-id",
        "burn-down-1",
    ])
    .trim()
    .to_string();
    assert!(token.starts_with("s1."), "minted token shape: {token}");

    let verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
    });
    let now = chrono::Utc::now().timestamp();
    assert!(verifier.verify(&token, now), "token must verify now");
    assert!(
        !verifier.verify(&token, now + 61),
        "token minted with --api-token-ttl 60 must be expired at now+61"
    );
}

// Minting from an MCP signing key needs the `mcp` feature (the MCP verifier
// config is mcp-gated); only run this where mcp is compiled in.
#[cfg(feature = "mcp")]
#[test]
fn mint_with_mcp_signing_key_file_produces_token() {
    // --mcp-signing-key-file: mint using an MCP signing key loaded from a file.
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("mcp.key");
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(b"mcp-file-signing-key-987654321")
        .unwrap();

    let token = run(&[
        "--mint-token",
        "--mcp-signing-key-file",
        key_path.to_str().unwrap(),
        "--token-id",
        "burn-down-mcp",
    ])
    .trim()
    .to_string();
    assert!(
        token.starts_with("s1.") && token.matches('.').count() == 2,
        "minted MCP token shape: {token}"
    );
}

#[test]
fn limit_caps_tracked_dialogs() {
    // --limit N caps the number of dialogs tracked. The RTP fixture has 2
    // dialogs; --limit 1 must keep only 1 in the report.
    let rtp = "tests/pcap-samples/sip-rtp-g711.pcap";
    let full = run(&["-N", "-I", rtp, "--report", "--no-cli-print"]);
    let full_rows = full.lines().filter(|l| l.contains('@')).count();
    assert!(
        full_rows >= 2,
        "RTP fixture should have ≥2 dialogs, got {full_rows}"
    );

    let capped = run(&[
        "-N",
        "-I",
        rtp,
        "--limit",
        "1",
        "--report",
        "--no-cli-print",
    ]);
    let capped_rows = capped.lines().filter(|l| l.contains('@')).count();
    assert_eq!(capped_rows, 1, "--limit 1 must keep exactly one dialog");
}

#[test]
fn config_file_is_loaded() {
    // --config: the loader reads the file and --dump-config reflects it.
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = dir.path().join("c.toml");
    std::fs::File::create(&cfg)
        .unwrap()
        .write_all(b"[display]\npayload_limit = 99\n")
        .unwrap();

    let out = run(&["-D", "--config", cfg.to_str().unwrap()]);
    assert!(
        out.contains("Loaded from:"),
        "must report the loaded source"
    );
    assert!(
        out.contains("payload_limit = 99"),
        "--config values must appear in the dumped config:\n{out}"
    );
}

#[test]
fn bpf_file_filters_from_a_file() {
    // --bpf-file: a matching filter passes all packets; a non-matching one
    // passes none — proving the BPF is read from the file and applied.
    let dir = tempfile::tempdir().expect("tempdir");
    let matching = dir.path().join("match.bpf");
    std::fs::File::create(&matching)
        .unwrap()
        .write_all(b"udp port 5060\n")
        .unwrap();
    let none = dir.path().join("none.bpf");
    std::fs::File::create(&none)
        .unwrap()
        .write_all(b"tcp port 80\n")
        .unwrap();

    let pass = ndjson_lines(&run(&[
        "-N",
        "-I",
        FIXTURE,
        "--bpf-file",
        matching.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(
        pass.len(),
        7,
        "matching --bpf-file must pass all 7 messages"
    );

    let drop = ndjson_lines(&run(&[
        "-N",
        "-I",
        FIXTURE,
        "--bpf-file",
        none.to_str().unwrap(),
        "--json",
    ]));
    assert!(drop.is_empty(), "non-matching --bpf-file must pass none");
}

#[test]
fn on_dialog_exec_runs_per_dialog() {
    // --on-dialog-exec: the command runs as dialogs complete. Use a command
    // that creates a marker file and assert it exists afterward.
    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("fired");
    run(&[
        "-N",
        "-I",
        FIXTURE,
        "--on-dialog-exec",
        &format!("touch {}", marker.to_str().unwrap()),
    ]);
    assert!(
        marker.exists(),
        "--on-dialog-exec command must run for the fixture's dialog"
    );
}

#[test]
fn ignore_case_matches_case_insensitively() {
    // The fixture's User-Agent is "sipnab-test/1.0". A wrong-case --ua pattern
    // matches nothing by default but matches with --ignore-case.
    let sensitive = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--ua", "SIPNAB", "--json"]));
    assert!(
        sensitive.is_empty(),
        "case-sensitive --ua SIPNAB must not match"
    );
    let insensitive = ndjson_lines(&run(&[
        "-N",
        "-I",
        FIXTURE,
        "--ua",
        "SIPNAB",
        "--ignore-case",
        "--json",
    ]));
    assert!(
        !insensitive.is_empty(),
        "--ignore-case must match the differently-cased User-Agent"
    );
}

#[test]
fn invert_shows_non_matching() {
    // Every message's From is 1001, so --from 1001 matches all; --invert flips
    // it to none.
    let matched = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--from", "1001", "--json"]));
    assert_eq!(matched.len(), 7, "--from 1001 should match all 7 messages");
    let inverted = ndjson_lines(&run(&[
        "-N", "-I", FIXTURE, "--from", "1001", "--invert", "--json",
    ]));
    assert!(
        inverted.is_empty(),
        "--invert must drop the matching messages"
    );
}

#[test]
fn word_matches_whole_words_only() {
    // "nab" is a substring of the UA "sipnab-test" but not a whole word, so
    // --word excludes it while a plain substring match includes it.
    let substring = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--ua", "nab", "--json"]));
    assert!(!substring.is_empty(), "substring --ua nab should match");
    let whole = ndjson_lines(&run(&[
        "-N", "-I", FIXTURE, "--ua", "nab", "--word", "--json",
    ]));
    assert!(whole.is_empty(), "--word must require a whole-word match");
}

#[test]
fn after_shows_trailing_context() {
    // --after N is grep -A: N messages after each match. The UA appears on one
    // request; --after 2 adds the two following messages.
    let match_only = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--ua", "sipnab", "--json"]));
    assert_eq!(match_only.len(), 1, "exactly one message carries the UA");
    let with_after = ndjson_lines(&run(&[
        "-N", "-I", FIXTURE, "--ua", "sipnab", "--after", "2", "--json",
    ]));
    assert_eq!(with_after.len(), 3, "--after 2 adds two trailing messages");
}

#[test]
fn tag_labels_dialogs() {
    // --tag applies the given tag to dialogs; it shows in the report Tags column.
    let out = run(&[
        "-N",
        "-I",
        FIXTURE,
        "--tag",
        "burndown-tag",
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        out.contains("burndown-tag"),
        "--tag value must appear in the report:\n{out}"
    );
}

/// SNB-0004: dialog rotation is ON by default. With `--limit` below the call
/// count and no `--rotate` flag, the store must evict the OLDEST dialog (keep the
/// newest) — not drop new legitimate calls. `--no-rotate` inverts it. This runs
/// the real binary end-to-end so a miswired call site (there are two) can't pass
/// silently. The fixture has two sequential calls: 1-1966 (older) then 1-1968.
#[test]
fn dialog_rotation_defaults_on_keep_newest() {
    let fx = "tests/pcap-samples/sip-rtp-g711.pcap";
    let default = run(&["-N", "-I", fx, "--limit", "1", "--report", "--no-cli-print"]);
    assert!(
        default.contains("1-1968@10.0.2.20") && !default.contains("1-1966@10.0.2.20"),
        "default rotation must keep the NEWEST call (1-1968), evicting 1-1966:\n{default}"
    );
    let no_rotate = run(&[
        "-N",
        "-I",
        fx,
        "--limit",
        "1",
        "--no-rotate",
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        no_rotate.contains("1-1966@10.0.2.20") && !no_rotate.contains("1-1968@10.0.2.20"),
        "--no-rotate must keep the OLDEST call (1-1966), dropping 1-1968:\n{no_rotate}"
    );
}
