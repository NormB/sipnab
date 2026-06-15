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
