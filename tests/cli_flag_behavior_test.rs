// SPDX-License-Identifier: MIT OR Apache-2.0

//! Behavioral coverage for CLI flags that were in the T6.2 `KNOWN_UNTESTED`
//! debt baseline (verification plan M6 burn-down). Each test exercises the
//! flag's real effect, not just its name.
#![cfg(feature = "api")] // `api` implies `native` (pcap + mint + auth available)

use std::io::Write;

use sipnab::auth::{TokenVerifier, VerifierConfig};

#[path = "support/run.rs"]
mod run_support;

/// Crate-root-relative path to the 7-message SIP call fixture used by most
/// tests here.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";

/// Run the binary under the shared test baseline (see [`run_support::run`])
/// with `SIPNAB_LOG=off`; return stdout, asserting the process exited 0.
///
/// # Arguments
/// * `args` — CLI arguments passed to the `sipnab` binary.
///
/// # Returns
/// The process's stdout; panics if the process exits non-zero.
///
/// # Side effects
/// Spawns the compiled `sipnab` binary as a subprocess.
fn run(args: &[&str]) -> String {
    let (stdout, stderr, code) = run_support::run(args, Some("off"));
    assert!(code == Some(0), "sipnab {args:?} failed: {stderr}");
    stdout
}

/// Parses every line of `s` that starts with `{` as a JSON value (NDJSON
/// message output).
///
/// # Arguments
/// * `s` — raw stdout from a `--json` run.
///
/// # Returns
/// The parsed JSON objects, one per emitted message.
fn ndjson_lines(s: &str) -> Vec<serde_json::Value> {
    s.lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("ndjson"))
        .collect()
}

/// `--count 3` stops capture after 3 packets, yielding exactly 3 JSON messages.
#[test]
fn count_limits_message_output() {
    // --count N stops after N packets → at most N messages.
    let msgs = ndjson_lines(&run(&["-N", "-I", FIXTURE, "--count", "3", "--json"]));
    assert_eq!(msgs.len(), 3, "--count 3 must yield exactly 3 messages");
}

/// `--calls-only` still emits the fixture call, and every emitted message
/// carries a `call_id` (no standalone messages).
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

/// `--text-dump` output contains the raw SIP request line and Via header.
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

/// `-O <file> --pcapng` writes a file starting with the PCAP-NG Section
/// Header Block magic (0x0a0d0d0a).
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

/// A token minted via `--mint-token --api-signing-key-file --api-token-ttl 60`
/// verifies now and is rejected at now+61.
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
    assert!(token.starts_with("s2."), "minted token shape: {token}");

    let verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
        audience: sipnab::auth::AUDIENCE_API.to_string(),
    });
    let now = chrono::Utc::now().timestamp();
    assert!(verifier.verify(&token, now), "token must verify now");
    assert!(
        !verifier.verify(&token, now + 61),
        "token minted with --api-token-ttl 60 must be expired at now+61"
    );

    // Minted from --api-signing-key-file, so the MCP surface must refuse it
    // even though it is configured with the very same signing key.
    let mcp_verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
        audience: sipnab::auth::AUDIENCE_MCP.to_string(),
    });
    assert!(
        !mcp_verifier.verify(&token, now),
        "an --api-signing-key token must not authenticate against HTTP MCP"
    );
}

// Minting from an MCP signing key needs the `mcp` feature (the MCP verifier
// config is mcp-gated); only run this where mcp is compiled in.
/// `--mint-token --mcp-signing-key-file` produces a well-formed `s2.` token
/// with exactly two dot separators, bound to the `mcp` audience.
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
        token.starts_with("s2.") && token.matches('.').count() == 2,
        "minted MCP token shape: {token}"
    );

    // Minted from --mcp-signing-key-file, so the REST API must refuse it even
    // when configured with the identical signing key.
    let key = b"mcp-file-signing-key-987654321";
    let now = chrono::Utc::now().timestamp();
    let api_verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
        audience: sipnab::auth::AUDIENCE_API.to_string(),
    });
    assert!(
        !api_verifier.verify(&token, now),
        "an --mcp-signing-key token must not authenticate against the REST API"
    );
}

/// `--limit 1` on a two-dialog fixture leaves exactly one dialog in the report.
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

/// `--config <file>` is loaded: `--dump-config` reports the source and echoes
/// the file's `payload_limit = 99` value.
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

/// `--bpf-file` applies the filter read from the file: a matching filter
/// passes all 7 messages, a non-matching one passes zero.
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

/// `--on-dialog-exec` runs the command when a dialog completes, proven by a
/// `touch`-created marker file existing afterward.
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

/// A wrong-case `--ua SIPNAB` matches nothing by default but matches the
/// fixture's `sipnab-test/1.0` UA with `--ignore-case`.
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

/// `--from 1001` matches all 7 messages; adding `--invert` flips the match to
/// zero messages.
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

/// `--ua nab` matches as a substring but yields nothing with `--word`, since
/// "nab" is not a whole word in `sipnab-test`.
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

/// `--after 2` (grep `-A` style) adds the two messages following the single
/// UA match, growing output from 1 to 3 messages.
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

/// The `--tag` value appears in the report's Tags column.
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

// ---------------------------------------------------------------------------
// Flags that the coverage ratchet counted as tested because their names
// appeared in a COMMENT somewhere under tests/. Five flags were covered that
// way; these are the real behaviour tests that replace the prose.
// ---------------------------------------------------------------------------

#[path = "support/pcap_build.rs"]
mod pcap_build;

/// `--rotate` states the default explicitly; it must behave as the default
/// does (keep the NEWEST dialog at capacity), not merely parse.
#[test]
fn rotate_explicitly_keeps_the_newest_dialog() {
    let fx = "tests/pcap-samples/sip-rtp-g711.pcap";
    let explicit = run(&[
        "-N",
        "-I",
        fx,
        "--limit",
        "1",
        "--rotate",
        "--report",
        "--no-cli-print",
    ]);
    let default = run(&["-N", "-I", fx, "--limit", "1", "--report", "--no-cli-print"]);
    assert_eq!(
        explicit.trim(),
        default.trim(),
        "--rotate must be identical to the default it documents"
    );
    assert!(
        explicit.contains("1-1968@10.0.2.20"),
        "--rotate must retain the NEWEST call:\n{explicit}"
    );
}

/// `--duration` must reject an unparseable value instead of ignoring it — a
/// capture that silently ran forever because "5 minutes" was not "5m" is a
/// worse outcome than a startup error.
#[test]
fn duration_rejects_an_unparseable_value() {
    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--duration",
            "five-minutes",
            "--no-cli-print",
        ],
        // SIPNAB_LOG must stay on. The rejection is reported through the
        // logger, so with `off` the user gets a bare exit code and no reason —
        // worth knowing, and pinned here so the message cannot quietly vanish.
        Some("error"),
    );
    assert_ne!(code, Some(0), "--duration must reject 'five-minutes'");
    assert!(
        err.to_lowercase().contains("duration"),
        "rejecting --duration must say what was wrong:\n{err}"
    );
}

/// `--strip-secrets` must remove the Decryption Secrets Block and leave the
/// input untouched.
///
/// No checked-in sample carries a DSB, so the fixture is built here.
#[test]
fn strip_secrets_removes_the_dsb_and_preserves_the_input() {
    const DSB: u32 = 0x0000_000a;
    let dir = tempfile::tempdir().expect("tempdir");
    let input = dir.path().join("with-secrets.pcapng");
    let output = dir.path().join("stripped.pcapng");

    let frame = pcap_build::udp_frame(
        [10, 1, 0, 1],
        [10, 2, 0, 1],
        5060,
        5060,
        b"OPTIONS sip:a@b SIP/2.0\r\nCall-ID: strip-test\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    );
    pcap_build::write_pcapng_with_dsb(&input, "CLIENT_RANDOM 0011 22334455\n", &frame);
    let before = std::fs::read(&input).expect("read input");
    assert_eq!(
        pcap_build::count_pcapng_blocks(&input, DSB),
        1,
        "fixture must start with exactly one DSB"
    );

    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            input.to_str().unwrap(),
            "--strip-secrets",
            output.to_str().unwrap(),
            "--no-cli-print",
        ],
        Some("off"),
    );
    assert_eq!(code, Some(0), "--strip-secrets must succeed:\n{err}");
    assert_eq!(
        pcap_build::count_pcapng_blocks(&output, DSB),
        0,
        "the stripped copy must contain no Decryption Secrets Block"
    );
    assert_eq!(
        std::fs::read(&input).expect("re-read input"),
        before,
        "--strip-secrets must never modify its input"
    );
}

/// `-E`/`--hep-parse` must decode HEP-encapsulated SIP out of a capture.
///
/// No checked-in sample carries HEP traffic, so the fixture is built with the
/// production encoder (`build_hep_v3`) and wrapped in real UDP frames — the
/// same wire format `--hep-listen` consumes, but read from a file so the test
/// needs no socket.
///
/// Without the flag those datagrams are opaque UDP payloads, so the Call-ID
/// must NOT surface; with it, it must. Asserting both directions is what makes
/// this a test of the flag rather than of the parser.
#[cfg(feature = "hep")]
#[test]
fn hep_parse_decodes_encapsulated_sip_from_a_capture() {
    use chrono::Utc;
    use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};

    const CALL_ID: &str = "hepflag1";
    let sip = format!(
        "INVITE sip:b@ex.invalid SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKhep1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:a@example.invalid>;tag=hep1\r\n\
         To: <sip:b@example.invalid>\r\n\
         Call-ID: {CALL_ID}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Length: 0\r\n\r\n"
    );

    let ep = HepEndpoint {
        src_addr: "10.1.0.1".parse().unwrap(),
        dst_addr: "10.2.0.1".parse().unwrap(),
        src_port: 5060,
        dst_port: 5060,
    };
    let hep = build_hep_v3(&ep, Utc::now(), HepProtocol::Sip, 0, None, sip.as_bytes());

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hep.pcap");
    // HEP rides UDP/9060 by convention.
    let frame = pcap_build::udp_frame([10, 1, 0, 1], [10, 2, 0, 1], 9060, 9060, &hep);
    pcap_build::write_pcap(&path, &[frame]);

    let with_flag = run(&[
        "-N",
        "-I",
        path.to_str().unwrap(),
        "--hep-parse",
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        with_flag.contains(CALL_ID),
        "--hep-parse must decode the encapsulated INVITE:\n{with_flag}"
    );

    let without = run(&[
        "-N",
        "-I",
        path.to_str().unwrap(),
        "--report",
        "--no-cli-print",
    ]);
    assert!(
        !without.contains(CALL_ID),
        "without --hep-parse the HEP payload must stay opaque, else the flag \
         gates nothing:\n{without}"
    );
}
