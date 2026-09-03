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
    assert!(
        verifier.verify(&token, now, sipnab::auth::SCOPE_FULL),
        "token must verify now"
    );
    assert!(
        !verifier.verify(&token, now + 61, sipnab::auth::SCOPE_FULL),
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
        !mcp_verifier.verify(&token, now, sipnab::auth::SCOPE_FULL),
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
        !api_verifier.verify(&token, now, sipnab::auth::SCOPE_FULL),
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
// way; these are the real behavior tests that replace the prose.
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
        transport: sipnab::net::TransportProto::Udp,
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

/// A registration flood carried by HEP is not written to the fail2ban jail
/// log, and the same flood off the wire is.
///
/// `--hep-listen 0.0.0.0:9060 --hep-allow 198.51.100.0/24 --reg-flood --fail2ban`:
/// any host in that range, or a UDP source spoofed into it, can send HEP-wrapped
/// REGISTERs whose inner source is the customer's SBC, and the jail bans the
/// SBC. The inner addresses are the sender's claim. The kill path has refused
/// to act on that claim without `--hep-allow-kill` since SN-01; the ban path
/// wrote the line unconditionally, and a firewall rule outlives the process
/// that asked for it.
///
/// Driven against a real `--hep-listen` on loopback with real HEP datagrams,
/// because that listener is the path that tags addressing as HEP-asserted.
/// The run is stopped with SIGTERM, the shutdown path the listener is known
/// to take cleanly. Both directions are asserted: the finding still reaches
/// stderr (a human is told), the jail line does not (a firewall is not), the
/// run says so once at startup, `--hep-allow-kill` admits the line, and the
/// same flood read off the wire is written without any opt-in.
#[cfg(all(feature = "hep", target_os = "linux"))]
#[test]
fn a_hep_carried_register_flood_is_not_written_to_the_jail_log() {
    use chrono::Utc;
    use sipnab::capture::hep::{HepEndpoint, HepProtocol, build_hep_v3};
    use std::io::Read;

    const SBC: [u8; 4] = [10, 1, 0, 1];
    const REGISTRAR: [u8; 4] = [10, 2, 0, 1];
    const SILENT_BY_DESIGN: &str = "writes nothing for detections carried by HEP";
    let endpoint = |src: [u8; 4], dst: [u8; 4]| HepEndpoint {
        src_addr: std::net::IpAddr::from(src),
        dst_addr: std::net::IpAddr::from(dst),
        src_port: 5060,
        dst_port: 5060,
        transport: sipnab::net::TransportProto::Udp,
    };
    let register = |i: usize| {
        format!(
            "REGISTER sip:10.2.0.1 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKf2b{i}\r\n\
             Max-Forwards: 70\r\n\
             From: <sip:alice@10.1.0.1>;tag=f{i}\r\n\
             To: <sip:alice@10.2.0.1>\r\n\
             Call-ID: f2b-{i}@10.1.0.1\r\n\
             CSeq: 1 REGISTER\r\n\
             Authorization: Digest username=\"alice\", realm=\"10.2.0.1\", nonce=\"n\", \
             uri=\"sip:10.2.0.1\", response=\"0\"\r\n\
             Content-Length: 0\r\n\r\n"
        )
    };
    let refusal = |i: usize| {
        format!(
            "SIP/2.0 401 Unauthorized\r\n\
             Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKf2b{i}\r\n\
             From: <sip:alice@10.1.0.1>;tag=f{i}\r\n\
             To: <sip:alice@10.2.0.1>;tag=t{i}\r\n\
             Call-ID: f2b-{i}@10.1.0.1\r\n\
             CSeq: 1 REGISTER\r\n\
             Content-Length: 0\r\n\r\n"
        )
    };
    // Three refused registrations: one more than a threshold of 2 allows.
    let exchange: Vec<(String, [u8; 4], [u8; 4])> = (0..3)
        .flat_map(|i| [(register(i), SBC, REGISTRAR), (refusal(i), REGISTRAR, SBC)])
        .collect();

    /// Bind an ephemeral UDP port and release it, so the listener can take it.
    fn free_udp_port() -> u16 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let p = s.local_addr().expect("read it back").port();
        drop(s);
        p
    }

    /// Whether a UDP socket is bound to 127.0.0.1:`port`, read from the
    /// kernel's own table rather than inferred from a log line.
    fn udp_port_bound(port: u16) -> bool {
        let needle = format!("0100007F:{port:04X}");
        std::fs::read_to_string("/proc/net/udp")
            .map(|t| t.lines().any(|l| l.contains(&needle)))
            .unwrap_or(false)
    }

    // Run the listener, deliver `exchange` to it as HEP, stop it, and return
    // (stdout, stderr).
    let listen = |extra: &[&str]| -> (String, String) {
        let port = free_udp_port();
        let bind = format!("127.0.0.1:{port}");
        let mut args = vec![
            "-N",
            "--hep-listen",
            &bind,
            "--hep-parse",
            "--reg-flood",
            "--reg-flood-threshold",
            "2",
            "--fail2ban",
        ];
        args.extend_from_slice(extra);
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(&args)
            .env("NO_COLOR", "1")
            .env("SIPNAB_LOG", "warn")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sipnab");

        let ready_by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !udp_port_bound(port) {
            assert!(
                std::time::Instant::now() < ready_by,
                "the HEP listener never bound {bind}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
        for (sip, src, dst) in &exchange {
            let hep = build_hep_v3(
                &endpoint(*src, *dst),
                Utc::now(),
                HepProtocol::Sip,
                0,
                None,
                sip.as_bytes(),
            );
            sock.send_to(&hep, &bind).expect("send HEP");
        }
        // Let the datagrams drain through the receive loop, then stop the run
        // the way an operator does.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let status = std::process::Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed");
        let exit_by = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if child.try_wait().expect("try_wait").is_some() {
                break;
            }
            if std::time::Instant::now() >= exit_by {
                let _ = child.kill();
                panic!("sipnab did not exit within 30 s of SIGTERM");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut stdout = String::new();
        let mut stderr = String::new();
        child
            .stdout
            .take()
            .expect("stdout piped")
            .read_to_string(&mut stdout)
            .expect("read stdout");
        child
            .stderr
            .take()
            .expect("stderr piped")
            .read_to_string(&mut stderr)
            .expect("read stderr");
        (stdout, stderr)
    };

    let (stdout, stderr) = listen(&[]);
    assert!(
        stderr
            .lines()
            .any(|l| l.contains("[ALERT]") && l.contains("reg_flood")),
        "the flood must still reach a human on stderr -- only the jail line is \
         origin-gated:\n{stderr}"
    );
    assert!(
        !stdout.contains("reg_flood src="),
        "a HEP-carried flood reached the jail log: the inner source address is the \
         sender's claim, and this line bans it:\n{stdout}"
    );
    assert!(
        stderr.contains(SILENT_BY_DESIGN),
        "an operator running --fail2ban over HEP input without the opt-in must be told \
         at startup that the jail log stays empty by design:\n{stderr}"
    );

    let (stdout, stderr) = listen(&["--hep-allow-kill"]);
    assert!(
        stdout.contains("reg_flood src=10.1.0.1 count=3"),
        "--hep-allow-kill must admit the HEP-carried flood to the jail log, the same \
         way it admits it to the wire:\n{stdout}"
    );
    assert!(
        !stderr.contains(SILENT_BY_DESIGN),
        "with the opt-in given, the startup warning is wrong:\n{stderr}"
    );

    // Control: the same six messages read off the wire, with no opt-in.
    let dir = tempfile::tempdir().expect("tempdir");
    let wire_pcap = dir.path().join("wire-flood.pcap");
    let frames: Vec<(Vec<u8>, u64)> = exchange
        .iter()
        .enumerate()
        .map(|(i, (sip, src, dst))| {
            (
                pcap_build::udp_frame(*src, *dst, 5060, 5060, sip.as_bytes()),
                i as u64 * 10_000,
            )
        })
        .collect();
    pcap_build::write_pcap_at(&wire_pcap, &frames, 1);
    let (stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            wire_pcap.to_str().expect("utf-8 path"),
            "--reg-flood",
            "--reg-flood-threshold",
            "2",
            "--fail2ban",
        ],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "the wire run failed:\n{stderr}");
    assert!(
        stdout.contains("reg_flood src=10.1.0.1 count=3"),
        "control: the same flood read off the wire must reach the jail log, else the \
         gate above is vacuous:\n{stdout}"
    );
}

/// `--reg-flood --fail2ban` arms a producer of jail lines, so the startup
/// warning that this run "will emit nothing" must stay quiet -- and with no
/// producer armed it must print. The warning looked at the scanner detector
/// alone, so `sipnab -d eth0 --reg-flood --fail2ban -N` announced an empty
/// jail log and then wrote `reg_flood src=` lines into it.
///
/// Through the real binary: the predicate is unit-tested beside the warning,
/// and this pins that the run consults it with the flood detector it
/// actually built rather than with the flag alone.
#[test]
fn the_empty_jail_log_warning_is_silent_when_reg_flood_is_armed() {
    const SILENCE_WARNING: &str = "An empty jail log means";

    let (_, stderr, code) = run_support::run(
        &["-N", "-I", FIXTURE, "--reg-flood", "--fail2ban"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "the --reg-flood run failed:\n{stderr}");
    assert!(
        !stderr.contains(SILENCE_WARNING),
        "--reg-flood writes jail lines, so the run must not announce that it \
         will emit nothing:\n{stderr}"
    );

    // Control: with no producer armed, the warning is the one thing the run
    // can say about the empty log it is about to leave behind.
    let (_, stderr, code) = run_support::run(&["-N", "-I", FIXTURE, "--fail2ban"], Some("warn"));
    assert_eq!(code, Some(0), "the unarmed run failed:\n{stderr}");
    assert!(
        stderr.contains(SILENCE_WARNING),
        "control: nothing armed must still warn of the coming silence:\n{stderr}"
    );
}

/// A capture truncated by a full disk must not report success.
///
/// `src/capture/writer.rs` has unit tests proving the writer surfaces ENOSPC,
/// and `run_loop` logged it — but the process still exited 0, so
/// `sipnab -O out.pcap && next-step` ran the next step on partial data. The
/// coverage stopped at the writer boundary; this asserts the property a script
/// actually depends on.
///
/// /dev/full fails every write, which is how the writer's own ENOSPC tests
/// simulate a full disk. The capture must be large enough to spill the
/// BufWriter, or nothing reaches the device and there is no error to find.
///
/// Linux-gated, not `cfg(unix)`: /dev/full is a Linux device and macOS is also
/// unix, so the looser gate ran this on a runner with no such file. That is
/// the same `target_os = "linux"` the writer's own ENOSPC module uses.
#[cfg(target_os = "linux")]
#[test]
fn output_write_failure_exits_nonzero() {
    let dir = tempfile::tempdir().expect("tempdir");
    let big = dir.path().join("big.pcap");
    let frames: Vec<Vec<u8>> = (0..600)
        .flat_map(|i| {
            pcap_build::sip_call_frames(&format!("wf-{i}@t"), &format!("{i:06x}"), "a", "b")
        })
        .collect();
    pcap_build::write_pcap(&big, &frames);

    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            big.to_str().unwrap(),
            "-O",
            "/dev/full",
            "--pcapng",
            "--no-cli-print",
        ],
        Some("error"),
    );
    assert_ne!(
        code,
        Some(0),
        "a capture whose output could not be written must not exit 0 — \
         stderr was:\n{err}"
    );
    assert!(
        err.to_lowercase().contains("write"),
        "the failure must say what went wrong:\n{err}"
    );

    // And the same run against a writable path must still succeed, so the
    // gate cannot be satisfied by failing everything.
    let good = dir.path().join("good.pcapng");
    let (_o2, e2, code2) = run_support::run(
        &[
            "-N",
            "-I",
            big.to_str().unwrap(),
            "-O",
            good.to_str().unwrap(),
            "--pcapng",
            "--no-cli-print",
        ],
        Some("error"),
    );
    assert_eq!(code2, Some(0), "a writable output must still exit 0:\n{e2}");
    assert!(
        std::fs::metadata(&good).expect("output written").len() > 0,
        "the control run must actually produce a file"
    );
}

/// Emitted output that could not be written must fail — unless the reader
/// simply went away.
///
/// `BatchSink` swallowed every write error alike. That was right for a
/// downstream `| head`, which must never fail the capture, and wrong for a
/// full disk: `sipnab --json > out.ndjson` wrote a truncated file and exited 0.
/// The two are indistinguishable to `write_all` and opposite in meaning.
///
/// All three cases are asserted together on purpose. Surfacing ENOSPC is easy
/// to do in a way that also breaks the pipe case — the first version of this
/// fix boxed the error with `io::Error::other`, which resets the kind, and
/// `| head` started exiting 1.
///
/// Linux-gated for /dev/full, as above.
#[cfg(target_os = "linux")]
#[test]
fn json_output_distinguishes_a_full_disk_from_a_closed_pipe() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().expect("tempdir");
    let cap = dir.path().join("cap.pcap");
    let frames: Vec<Vec<u8>> = (0..400)
        .flat_map(|i| {
            pcap_build::sip_call_frames(&format!("js-{i}@t"), &format!("{i:06x}"), "a", "b")
        })
        .collect();
    pcap_build::write_pcap(&cap, &frames);
    let input = cap.to_str().expect("utf-8 path");

    // 1. A writable destination succeeds and actually emits.
    let good = dir.path().join("out.ndjson");
    let status = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", input, "--json"])
        .stdout(std::fs::File::create(&good).expect("create out"))
        .stderr(Stdio::null())
        .status()
        .expect("spawn");
    assert!(status.success(), "writable output must exit 0");
    assert!(
        std::fs::metadata(&good).expect("out written").len() > 0,
        "the control must actually emit NDJSON, or the other two prove nothing"
    );

    // 2. A full disk is data loss and must fail.
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let status = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", input, "--json"])
        .stdout(full)
        .stderr(Stdio::null())
        .status()
        .expect("spawn");
    assert!(
        !status.success(),
        "--json to a full disk must not report success"
    );

    // 3. A closed pipe is the reader's choice and must NOT fail.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", input, "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    // Drop the read end immediately: the next write gets EPIPE.
    drop(child.stdout.take());
    let status = child.wait().expect("wait");
    assert!(
        status.success() || status.code().is_none(),
        "a closed downstream pipe must not fail the capture (got {status:?}) — \
         this is the case a naive ENOSPC fix breaks"
    );
}

/// `--report` must fail cleanly on an unwritable stdout, not panic — and a
/// closed pipe must still be fine.
///
/// It used `print!`, which panics if stdout cannot be written, so
/// `sipnab --report > /full/disk` died with exit 101 and a Rust backtrace
/// while `-O` and `--json` reported the identical condition as a clean error.
#[cfg(target_os = "linux")]
#[test]
fn report_output_fails_cleanly_and_tolerates_a_closed_pipe() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().expect("tempdir");
    let cap = dir.path().join("cap.pcap");
    let frames: Vec<Vec<u8>> = (0..400)
        .flat_map(|i| {
            pcap_build::sip_call_frames(&format!("rp-{i}@t"), &format!("{i:06x}"), "a", "b")
        })
        .collect();
    pcap_build::write_pcap(&cap, &frames);
    let input = cap.to_str().expect("utf-8 path");

    // Full disk: a clean non-zero, and specifically NOT a panic (101).
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", input, "--report"])
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "--report to a full disk must not exit 0"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("panicked"),
        "must fail cleanly rather than panic:\n{err}"
    );
    assert_ne!(
        out.status.code(),
        Some(101),
        "101 is the panic exit; the failure should be reported, not unwound"
    );

    // Closed pipe: still success.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I", input, "--report"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    drop(child.stdout.take());
    let status = child.wait().expect("wait");
    assert!(
        status.success() || status.code().is_none(),
        "a closed pipe must not fail --report (got {status:?})"
    );
}

/// A report that could not be produced must exit non-zero on the `--cores`
/// path too.
///
/// `generate_reports` returns false for exactly this, and its doc says the
/// caller exits non-zero so "scripts must be able to trust the exit code" —
/// but the two multi-core callers discarded the value, so an unknown
/// `--call-report` id exited 0 there and 1 everywhere else.
#[test]
fn unknown_call_report_fails_on_the_multicore_path() {
    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--cores",
            "4",
            "--call-report",
            "definitely-not-a-call-id",
        ],
        Some("error"),
    );
    assert_ne!(
        code,
        Some(0),
        "an unknown --call-report id must fail on --cores too:\n{err}"
    );
}

// ── --dialog-track (docs/design/dialog-tracking-modes.md) ──────────────────

/// The sipp corpus reuses one Call-ID across many transactions, so the two
/// modes must disagree about how many units exist.
///
/// This disagreement is the only proof the flag is wired to anything. The
/// version removed in 0.5.52 was declared and never read, so `call-id`,
/// `branch` and an invented value all produced byte-identical output — and its
/// only "coverage" was a test asserting its default was None, which passed
/// precisely because it did nothing.
#[test]
fn dialog_track_branch_splits_what_call_id_merges() {
    let fx = "tests/pcap-samples/sipp-branch-scenario.pcapng";
    let count = |mode: &str| -> usize {
        run(&[
            "-N",
            "-I",
            fx,
            "--dialog-track",
            mode,
            "--report",
            "--no-cli-print",
        ])
        .lines()
        .filter(|l| l.split_whitespace().next().is_some_and(|w| w.contains('@')))
        .count()
    };
    let by_call_id = count("call-id");
    let by_branch = count("branch");
    assert!(
        by_call_id > 0 && by_branch > 0,
        "both modes must track something"
    );
    assert!(
        by_branch > by_call_id,
        "branch must split what call-id merges ({by_branch} vs {by_call_id})"
    );
}

/// `call-id` is the default, so passing it explicitly must change nothing.
#[test]
fn dialog_track_call_id_is_the_default() {
    let fx = "tests/pcap-samples/sipp-branch-scenario.pcapng";
    let explicit = run(&[
        "-N",
        "-I",
        fx,
        "--dialog-track",
        "call-id",
        "--report",
        "--no-cli-print",
    ]);
    let default = run(&["-N", "-I", fx, "--report", "--no-cli-print"]);
    assert_eq!(
        explicit, default,
        "--dialog-track call-id must be the default"
    );
}

/// One ordinary call is one dialog but SEVERAL transactions.
///
/// RFC 3261 gives the ACK to a 2xx a new branch (§17.1.1.3) and the BYE
/// another, so `branch` reports more units for a single call. Asserted here
/// rather than left to be discovered as an apparent miscount.
#[test]
fn dialog_track_branch_splits_a_single_call_into_transactions() {
    let count = |args: &[&str]| -> usize {
        run(args)
            .lines()
            .filter(|l| l.split_whitespace().next().is_some_and(|w| w.contains('@')))
            .count()
    };
    let as_dialog = count(&["-N", "-I", FIXTURE, "--report", "--no-cli-print"]);
    let as_txns = count(&[
        "-N",
        "-I",
        FIXTURE,
        "--dialog-track",
        "branch",
        "--report",
        "--no-cli-print",
    ]);
    assert_eq!(as_dialog, 1, "the fixture is one dialog");
    assert!(
        as_txns > as_dialog,
        "one call is several transactions ({as_txns} vs {as_dialog})"
    );
}

/// An unknown method is rejected at startup.
///
/// The removed flag accepted `--dialog-track telepathy` and exited 0, so a
/// typo silently selected the default.
#[test]
fn dialog_track_rejects_an_unknown_method() {
    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--dialog-track",
            "telepathy",
            "--no-cli-print",
        ],
        Some("error"),
    );
    assert_ne!(code, Some(0), "an unknown method must fail");
    assert!(
        err.contains("telepathy") || err.to_lowercase().contains("dialog-track"),
        "the error must name the rejected value:\n{err}"
    );
}

/// The `--cores` path builds its own per-worker stores, so the flag has to be
/// carried through the parallel config — a separate code path that would
/// otherwise ignore it silently.
#[test]
fn dialog_track_applies_on_the_multicore_path() {
    let fx = "tests/pcap-samples/sipp-branch-scenario.pcapng";
    let count = |args: &[&str]| -> usize {
        run(args)
            .lines()
            .filter(|l| l.split_whitespace().next().is_some_and(|w| w.contains('@')))
            .count()
    };
    let single = count(&[
        "-N",
        "-I",
        fx,
        "--dialog-track",
        "branch",
        "--report",
        "--no-cli-print",
    ]);
    let parallel = count(&[
        "-N",
        "-I",
        fx,
        "--cores",
        "4",
        "--dialog-track",
        "branch",
        "--report",
        "--no-cli-print",
    ]);
    assert_eq!(
        single, parallel,
        "--cores must group identically to single-core ({parallel} vs {single})"
    );
}

/// A Call-ID still resolves in branch mode, where it names several units.
///
/// `--call-report`, the REST API, the MCP tools and the TUI all look a dialog
/// up by Call-ID; branch mode must not break that.
#[test]
fn call_report_resolves_by_call_id_in_branch_mode() {
    let (_out, err, code) = run_support::run(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--dialog-track",
            "branch",
            "--call-report",
            "test-call-1@10.0.0.1",
            "--no-cli-print",
        ],
        Some("error"),
    );
    assert_eq!(
        code,
        Some(0),
        "a Call-ID must still resolve under branch tracking:\n{err}"
    );
}

/// A startup failure after the capture thread is spawned exits cleanly.
///
/// `bootstrap::launch` starts the capture thread before the readiness
/// hand-shake, the chroot and the privilege drop, and every failure from there
/// on used to call `std::process::exit` directly — which joins nothing, so the
/// capture thread was abandoned mid-read while still holding its source. That
/// is invisible to an ordinary test run: the exit code and the message are the
/// same either way, and the process dies before anything can observe the
/// difference.
///
/// It is NOT invisible under ThreadSanitizer, which reports the abandoned
/// thread as a thread leak — and this suite is one of the five the sanitizer
/// job runs. So this test is the guard: ordinarily it asserts the contract
/// below, and under `sanitizers.yml` it additionally forces the leak to
/// reappear if `capture::stop_and_join` is ever dropped from these paths.
/// `-I <missing>` is the everyday version (a mistyped filename), which is why
/// it earns a test rather than being left to the exotic ones.
#[test]
fn startup_failures_after_the_capture_thread_starts_exit_cleanly() {
    // A missing file is now rejected during planning, BEFORE any thread is
    // spawned — `-I` resolves directories and globs into a file list, and that
    // resolution validates what it is handed. Still exit 1, and the message is
    // more direct than the old "failed to open" from inside the reader.
    //
    // Note what this costs: this probe no longer reaches the post-hand-shake
    // path, so the thread-leak contract described above now rests ENTIRELY on
    // the chroot case below. Do not delete that one as redundant — it is the
    // only remaining probe that gets past the hand-shake.
    let (_out, err, code) = run_support::run(&["-N", "-I", "/nonexistent.pcap"], Some("error"));
    assert_eq!(
        code,
        Some(1),
        "a missing capture file must exit 1, not {code:?}:\n{err}"
    );
    assert!(
        err.contains("does not exist"),
        "the failure must name the missing path:\n{err}"
    );

    // Post-hand-shake failure: the file opens, the capture thread is running,
    // and a later startup step fails.
    let (_out, err, code) = run_support::run(
        &["-N", "-I", FIXTURE, "--chroot", "/nonexistent-dir"],
        Some("error"),
    );
    assert_eq!(
        code,
        Some(1),
        "an unusable --chroot must exit 1, not {code:?}:\n{err}"
    );
    assert!(
        err.contains("Failed to chroot"),
        "the failure must name chroot as the cause:\n{err}"
    );
}

/// `--token-scope metrics` mints a token the verifier treats as scrape-only,
/// and `--token-scope full` (the default) mints one that is not.
///
/// The library tests prove the verifier honors the claim and the API tests
/// prove the routes demand it; this covers the wiring in between — the CLI flag
/// reaching `auth::mint`. A flag that never reached it would mint `full` tokens
/// while the operator believed they were scoping them, which is the failure
/// worth catching: it is silent, and it fails open.
#[test]
fn token_scope_flag_mints_a_scope_the_verifier_honours() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("api.key");
    let key = b"scope-flag-signing-key-0123456789";
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key)
        .unwrap();

    let mint = |scope: &str| {
        run(&[
            "--mint-token",
            "--token-scope",
            scope,
            "--api-signing-key-file",
            key_path.to_str().unwrap(),
            "--token-id",
            "scope-flag",
        ])
        .trim()
        .to_string()
    };

    let verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
        audience: sipnab::auth::AUDIENCE_API.to_string(),
    });
    let now = chrono::Utc::now().timestamp();

    let scoped = mint("metrics");
    assert!(
        verifier.verify(&scoped, now, sipnab::auth::SCOPE_METRICS),
        "--token-scope metrics must mint a token accepted for metrics"
    );
    assert!(
        !verifier.verify(&scoped, now, sipnab::auth::SCOPE_FULL),
        "--token-scope metrics must NOT mint a token accepted for full access — \
         the flag would otherwise be decorative"
    );

    let full = mint("full");
    assert!(
        verifier.verify(&full, now, sipnab::auth::SCOPE_FULL),
        "--token-scope full must mint a full-access token"
    );
}

/// `--token-scope metrics` is refused for the MCP surface at mint time.
///
/// MCP has no `/metrics`, so a scrape-only MCP token could never authenticate
/// anything. Failing at mint beats handing the operator a token that silently
/// works nowhere.
/// `--json-dialogs` emits one JSON object per dialog, not per message.
///
/// The distinction is the point of the flag. `--json` is a per-message stream,
/// so a dialog-level filter like `state == 'Failed'` selects dialogs and then
/// emits every message of them — provisional responses included, which is what
/// made a bare `100 Trying` show up under a failure query. One line per call is
/// the shape an operator triaging failures actually wants.
#[test]
fn json_dialogs_emits_one_object_per_dialog() {
    let out = run(&[
        "-N",
        "-I",
        "tests/pcap-samples/sip-488-codec-reject.pcapng",
        "--json-dialogs",
        "--no-cli-print",
        "--quiet",
    ]);
    let lines: Vec<&str> = out.trim().lines().filter(|l| l.starts_with('{')).collect();
    assert!(
        !lines.is_empty(),
        "expected at least one dialog object, got:\n{out}"
    );
    let mut failed_with_a_code = 0;
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("line is not JSON: {e}\n{line}"));
        assert!(v.get("call_id").is_some(), "every record names its dialog");
        assert!(v.get("state").is_some(), "every record carries its state");
        if v.get("state").and_then(serde_json::Value::as_str) == Some("Failed") {
            assert!(
                v.get("final_status_code").is_some(),
                "a failed dialog must say WHICH code failed it, or the reader is \
                 back to grepping the message stream: {line}"
            );
            failed_with_a_code += 1;
        }
    }
    assert!(
        failed_with_a_code > 0,
        "this capture contains a 488-rejected call; if none is Failed the \
         fixture or the state machine changed"
    );
}

// Mints and inspects an MCP token, so it needs the surface that
// issues one. The file is gated on `api`, which does not imply `mcp`:
// under `native,tui,tls,hep,api` the mint refuses and the assertion
// reads that correct refusal as a wrong claim.
#[cfg(feature = "mcp")]
#[test]
fn token_scope_metrics_is_refused_for_the_mcp_surface() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("mcp.key");
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(b"mcp-scope-signing-key-0123456789")
        .unwrap();

    let (_out, err, code) = run_support::run(
        &[
            "--mint-token",
            "--token-scope",
            "metrics",
            "--mcp-signing-key-file",
            key_path.to_str().unwrap(),
        ],
        Some("error"),
    );

    assert_ne!(code, Some(0), "minting must fail, got success:\n{err}");
    assert!(
        err.contains("/metrics"),
        "the error must say why — MCP has no metrics endpoint:\n{err}"
    );
}

/// `--token-scope read` is refused for the REST API surface at mint time.
///
/// The REST API has no read-only scope — its routes are one trust domain
/// apart from `/metrics` — so a `read` API token would verify and then be
/// refused by every route. Failing at mint beats shipping a token that opens
/// nothing.
#[test]
fn token_scope_read_is_refused_for_the_api_surface() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("api.key");
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(b"api-read-scope-signing-key-01234")
        .unwrap();

    let (_out, err, code) = run_support::run(
        &[
            "--mint-token",
            "--token-scope",
            "read",
            "--api-signing-key-file",
            key_path.to_str().unwrap(),
        ],
        Some("error"),
    );

    assert_ne!(code, Some(0), "minting must fail, got success:\n{err}");
    assert!(
        err.contains("MCP surface only"),
        "the error must say the scope belongs to MCP:\n{err}"
    );
}

/// `--token-scope read` mints an MCP token whose claim survives verification
/// as `read` — the claim the MCP dispatch layer then enforces per tool.
///
/// Same wiring concern as the metrics case above: a flag that never reached
/// `auth::mint` would mint `full` tokens while the operator believed they
/// were confining a diagnostic agent, and that failure is silent and open.
// Mints and inspects an MCP token, so it needs the surface that
// issues one. The file is gated on `api`, which does not imply `mcp`:
// under `native,tui,tls,hep,api` the mint refuses and the assertion
// reads that correct refusal as a wrong claim.
#[cfg(feature = "mcp")]
#[test]
fn token_scope_read_mints_an_mcp_token_carrying_the_read_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("mcp.key");
    let key = b"mcp-read-scope-signing-key-01234";
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(key)
        .unwrap();

    let token = run(&[
        "--mint-token",
        "--token-scope",
        "read",
        "--mcp-signing-key-file",
        key_path.to_str().unwrap(),
        "--token-id",
        "read-scope-flag",
    ])
    .trim()
    .to_string();

    let verifier = TokenVerifier::new(VerifierConfig {
        signing_keys: vec![key.to_vec()],
        static_keys: vec![],
        revoked_file: None,
        audience: sipnab::auth::AUDIENCE_MCP.to_string(),
    });
    let now = chrono::Utc::now().timestamp();

    assert_eq!(
        verifier.verify_claims(&token, now).map(|a| a.scope),
        Some(sipnab::auth::SCOPE_READ.to_string()),
        "--token-scope read must mint a token whose accepted claim is read"
    );
    assert!(
        !verifier.verify(&token, now, sipnab::auth::SCOPE_FULL),
        "a read token must NOT satisfy a full requirement — the flag would \
         otherwise be decorative"
    );
}

/// `-I` silently beats `-d`, so sipnab must say so.
///
/// Both flags parse together and the file wins: sipnab reads it, never touches
/// the interface, and the output is byte-identical to a correct run. Someone
/// adapting a documented pcap command to watch live traffic adds `-d` and
/// leaves `-I` in place, and an agent then answers questions about a stale
/// capture with total confidence. For a diagnostic tool a confident wrong
/// answer is worse than a crash — nobody has reason to doubt it.
#[test]
fn passing_both_input_and_device_warns_that_the_file_wins() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-d",
            "eth0",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--no-cli-print",
        ])
        .output()
        .expect("spawn sipnab");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--input") && stderr.contains("--device"),
        "expected a warning naming both flags, got:\n{stderr}"
    );
    assert!(
        stderr.contains("Drop -I"),
        "the warning must say how to fix it, not merely that it happened:\n{stderr}"
    );
}

/// `--alert syslog` must enable syslog, not warn and do nothing.
///
/// This flag is declared "Alert channels (repeatable: syslog, json, exec)" and
/// every documented example passes a channel name, but it was fed to
/// `AlertRule::parse`, whose grammar is `<name>:<threshold>/<window>`. So the
/// documented invocation warned "Skipping invalid alert rule 'syslog'" and
/// enabled nothing — while `docs/examples.md` told the reader it was writing to
/// LOCAL0.
///
/// For a security path that is the worst shape of bug available: not a crash,
/// not a wrong answer, but an operator who believes alerting is on. Nothing
/// fires and nothing says so.
#[test]
fn alert_channel_names_are_accepted_not_parsed_as_rules() {
    for channel in ["syslog", "json"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args([
                "-N",
                "-I",
                "tests/fixtures/sip_call.pcap",
                "--alert",
                channel,
                "--no-cli-print",
            ])
            .output()
            .expect("spawn sipnab");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("Skipping invalid alert rule"),
            "--alert {channel} must be accepted as a channel; got:\n{stderr}"
        );
        assert!(
            !stderr.contains("Unknown alert channel"),
            "--alert {channel} is a documented channel and must not be rejected:\n{stderr}"
        );
    }
}

/// An unrecognized channel says what the valid ones are.
///
/// Silently ignoring it would reproduce the original bug in a new place.
#[test]
fn an_unknown_alert_channel_names_the_valid_ones() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--alert",
            "definitely-not-a-channel",
            "--no-cli-print",
        ])
        .output()
        .expect("spawn sipnab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Unknown alert channel") && stderr.contains("syslog"),
        "an unknown channel must be reported AND the valid ones listed:\n{stderr}"
    );
}

/// The old rule grammar still parses, so anyone who found it in the source
/// keeps working. A value containing ':' is a rule; a bare word is a channel.
#[test]
fn alert_rule_syntax_still_parses() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-N",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--alert",
            // Window needs a unit suffix (s/m/h) — the grammar is
            // <name>:<threshold>/<window>[:<cooldown>].
            "scanner:10/60s",
            "--no-cli-print",
        ])
        .output()
        .expect("spawn sipnab");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Skipping invalid alert rule"),
        "a well-formed rule must still parse:\n{stderr}"
    );
    assert!(
        !stderr.contains("Unknown alert channel"),
        "a value with ':' is a rule, not a channel:\n{stderr}"
    );
}

/// `--cores N` refuses the outputs it cannot produce instead of emitting none.
///
/// The parallel reader shards by host pair and rebuilds dialogs per shard. It
/// has no per-message stream, no capture writer and no replay clock, so asking
/// for one used to produce nothing at all and exit 0 — beside a summary line
/// that reported the messages it had just found. Measured on a real capture
/// before this refusal: `--json` gave 13,460 lines at `--cores 1` and 0 at
/// `--cores 4`; `--text-dump` gave 194,321 and 0; `-O` wrote a 100 MB file and
/// then no file at all.
///
/// An empty output that exits 0 reads as "there was nothing to report", which
/// is the one conclusion the run had already disproved. Refusing is not the
/// whole answer — these could be implemented — but it is the honest answer.
#[test]
fn cores_refuses_the_outputs_it_cannot_produce() {
    for flag in ["--json", "--text-dump", "--fail2ban"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args([
                "-N",
                "--cores",
                "4",
                "-I",
                "tests/fixtures/sip_call.pcap",
                flag,
            ])
            .output()
            .expect("spawn sipnab");
        assert_eq!(
            out.status.code(),
            Some(2),
            "`--cores 4 {flag}` must refuse rather than emit nothing and exit 0"
        );
        assert!(
            out.stdout.is_empty(),
            "a refused run must not also write output for {flag}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(flag) && stderr.contains("cannot produce"),
            "the refusal must name the flag it cannot honor, so the operator \
             knows which one to drop; got:\n{stderr}"
        );
    }
}

/// The whole-capture views still work under `--cores`, so the refusal above is
/// specific rather than a blanket ban on combining the flags.
#[test]
fn cores_still_produces_the_whole_capture_views() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args([
            "-N",
            "--cores",
            "4",
            "-I",
            "tests/fixtures/sip_call.pcap",
            "--json-dialogs",
        ])
        .output()
        .expect("spawn sipnab");
    assert_eq!(
        out.status.code(),
        Some(0),
        "--json-dialogs is produced by the parallel path and must not be refused"
    );
    assert!(
        !out.stdout.is_empty(),
        "--json-dialogs under --cores must still emit dialogs"
    );
}

/// `--retain-audio` without `--mcp` is refused at the real CLI boundary.
///
/// The flag arms an in-memory buffer only the MCP `export_audio` tool can
/// read back, so without `--mcp` it would retain call audio nothing in the
/// run can reach. A flag that parses and silently does nothing is the
/// `--alert` defect class; clap's `requires = "mcp"` makes the combination
/// unrepresentable, and this pins the refusal as the process's actual
/// behavior — exit non-zero, and an error that names the missing flag so
/// the operator learns the remedy rather than just the rejection.
#[test]
fn retain_audio_without_mcp_is_refused_with_the_remedy_named() {
    let (_stdout, stderr, code) = run_support::run(&["-N", "--retain-audio"], Some("off"));
    assert_ne!(
        code,
        Some(0),
        "--retain-audio without --mcp must be a hard CLI error, not a silent no-op"
    );
    assert!(
        stderr.contains("--mcp"),
        "the refusal must name --mcp so the operator learns the remedy: {stderr}"
    );
}

/// A capture big enough to rotate several times at `--split filesize:1`
/// (1 MB), so a retention bound has older files to remove.
const BIG_FIXTURE: &str = "tests/pcap-samples/sipp-branch-scenario.pcapng";

/// Every file the run wrote into its output directory, sorted by name.
///
/// # Arguments
/// * `dir` — the directory the run was pointed at.
///
/// # Returns
/// The file names in `dir`, sorted.
fn split_family(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read output dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// `--split` with no `--split-keep` writes every rotation and deletes none of
/// them.
///
/// This is the property a future refactor is most likely to break, and the
/// one whose failure destroys evidence: a capture is very often the only copy
/// there will ever be, so an operator who never asked for a ring buffer keeps
/// every file the run produced.
#[test]
fn split_without_a_bound_keeps_every_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("out.pcap");
    let (_stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "--no-cli-print",
            "-I",
            BIG_FIXTURE,
            "-O",
            out.to_str().unwrap(),
            "--split",
            "filesize:1",
        ],
        Some("info"),
    );
    assert_eq!(code, Some(0), "run failed: {stderr}");

    let family = split_family(dir.path());
    assert!(
        family.len() >= 4,
        "the fixture must rotate at least three times for this to prove \
         anything; got {family:?}"
    );
    let expected: Vec<String> = std::iter::once("out.pcap".to_string())
        .chain((1..family.len()).map(|n| format!("out_{n:05}.pcap")))
        .collect();
    assert_eq!(
        family, expected,
        "every rotation survives when no bound was asked for"
    );
    assert!(
        !stderr.contains("deleted by --split-keep"),
        "an unbounded run must not report a deletion: {stderr}"
    );
}

/// `--split-keep 2` leaves exactly the two newest files and reports what it
/// removed.
///
/// The count it reports is checked against the disk rather than taken on
/// trust: the run created `deleted + 2` files, so the survivors must be the
/// last two sequence numbers of that set. A bound that kept the right NUMBER
/// of files while deleting the wrong ones fails here.
#[test]
fn split_keep_leaves_the_newest_files_and_reports_the_deletions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("out.pcap");
    let (_stdout, stderr, code) = run_support::run(
        &[
            "-N",
            "--no-cli-print",
            "-I",
            BIG_FIXTURE,
            "-O",
            out.to_str().unwrap(),
            "--split",
            "filesize:1",
            "--split-keep",
            "2",
        ],
        Some("info"),
    );
    assert_eq!(code, Some(0), "run failed: {stderr}");

    let deleted: usize = stderr
        .split_once(" older split file(s) deleted by --split-keep")
        .and_then(|(before, _)| before.rsplit(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("the run must say what it deleted: {stderr}"));
    assert!(
        deleted >= 2,
        "the fixture must produce more than two files, or the bound proves \
         nothing; deleted {deleted}"
    );

    // `deleted + 2` files were created, numbered 0 (`out.pcap`) upward, so the
    // survivors are the last two of that run.
    assert_eq!(
        split_family(dir.path()),
        vec![
            format!("out_{deleted:05}.pcap"),
            format!("out_{:05}.pcap", deleted + 1),
        ],
        "the survivors are the newest two files the run wrote"
    );
}

/// `--evidence-out` publishes one JSON line per source-naming finding, and
/// nothing at all without the flag.
///
/// The evidence path is how a firewall learns what sipnab saw, so the flag
/// has to be driven end to end and not merely parsed: an operator who pipes
/// it into `tfps_ctl ingest` is trusting these bytes.
#[test]
fn evidence_out_writes_a_line_per_finding_and_nothing_without_the_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("evidence.jsonl");
    let target = path.to_string_lossy().to_string();

    // A capture with no scanner in it still exercises the whole path: the
    // sink opens, the run completes, and an empty file is the honest answer.
    run(&[
        "-N",
        "-I",
        FIXTURE,
        "--kill-scanner",
        "--evidence-out",
        &target,
    ]);
    assert!(path.exists(), "the sink is opened when the run starts");

    // Standard output carries the same lines when the target is `-`, and a
    // run without the flag carries none of them.
    let with = run(&["-N", "-I", FIXTURE, "--kill-scanner", "--evidence-out", "-"]);
    let without = run(&["-N", "-I", FIXTURE, "--kill-scanner"]);
    let evidence = |s: &str| s.lines().filter(|l| l.contains("\"src_ip\"")).count();
    assert_eq!(evidence(&without), 0, "no flag, no evidence: {without}");
    assert!(
        evidence(&with) >= evidence(&without),
        "the flag never publishes less than its absence"
    );
}

/// A path sipnab cannot write is refused before the first packet, not after
/// the first finding an hour later.
#[test]
fn evidence_out_refuses_an_unwritable_path_at_startup() {
    let (_, stderr, code) = run_support::run(
        &[
            "-N",
            "-I",
            FIXTURE,
            "--evidence-out",
            "/nonexistent-dir/evidence.jsonl",
        ],
        Some("error"),
    );
    assert_eq!(code, Some(2), "an unwritable sink is an argument error");
    assert!(
        stderr.contains("--evidence-out"),
        "the message names the flag and the path: {stderr}"
    );
}
