// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch-mode paths no other suite drove, end to end through the built binary:
//! the relay asks a file run refuses, the end-of-run capture-quality, LLMNR and
//! ICMP summaries, the key files the decryptors load at startup, the vCon
//! redaction map, `--vcon-digest`, `--wireshark` with nothing to filter,
//! STIR/SHAKEN extraction, the `SIPNAB_PERF_STATS` probe, and the startup
//! refusals and notices around `--cores`, `--sandbox` and `--hep-send`.
//!
//! Every capture is built here, into a temporary directory, from the committed
//! frame builders -- or is one of the committed `tests/fixtures/` captures.
//! Every run gets its own `HOME` and `XDG_CONFIG_HOME`, so no user
//! configuration is read and nothing is written outside the tempdir.

#![cfg(feature = "full")]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use std::path::Path;
use std::process::Command;

use pcap_build::{udp_frame, write_pcap, write_pcapng_with_dsb};

/// The committed two-party call every flag-only case reads.
const SIP_CALL: &str = "tests/fixtures/sip_call.pcap";
/// The one dialog in [`SIP_CALL`].
const SIP_CALL_ID: &str = "test-call-1@10.0.0.1";

/// What one finished run left behind.
struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Outcome {
    /// Both streams, for failure messages.
    fn dump(&self) -> String {
        format!("--- stdout\n{}\n--- stderr\n{}", self.stdout, self.stderr)
    }
}

/// Run the binary to completion with a private home and `SIPNAB_LOG=info`.
fn sipnab(args: &[&str]) -> Outcome {
    sipnab_env(args, &[])
}

/// As [`sipnab`], with extra environment variables.
fn sipnab_env(args: &[&str], env: &[(&str, &str)]) -> Outcome {
    let home = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sipnab"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(args)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("SIPNAB_CONFIG")
        .env_remove("SIPNAB_PERF_STATS")
        .env("SIPNAB_LOG", "info")
        .env("NO_COLOR", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run sipnab");
    Outcome {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A path as the `&str` the argument list wants.
fn s(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// One SIP message as a wire payload: start line, headers, empty body.
fn sip(start: &str, headers: &[&str]) -> Vec<u8> {
    let mut m = format!("{start}\r\n");
    for h in headers {
        m.push_str(h);
        m.push_str("\r\n");
    }
    m.push_str("Content-Length: 0\r\n\r\n");
    m.into_bytes()
}

/// An INVITE for `call_id` from 192.0.2.10 to 192.0.2.20, with `extra`
/// headers appended.
fn invite(call_id: &str, extra: &[&str]) -> Vec<u8> {
    let call = format!("Call-ID: {call_id}");
    let mut headers = vec![
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-paths",
        "Max-Forwards: 70",
        "From: <sip:alice@example.com>;tag=a1",
        "To: <sip:bob@example.com>",
        call.as_str(),
        "CSeq: 1 INVITE",
        "Contact: <sip:alice@192.0.2.10>",
    ];
    headers.extend_from_slice(extra);
    sip("INVITE sip:bob@example.com SIP/2.0", &headers)
}

// ── Relay asks on a file run ──────────────────────────────────────────────

/// Every relay ask on a run that names no relay says which flag to add, and
/// the run still completes.
#[test]
fn relay_asks_naming_no_relay_are_told_which_flag_to_add() {
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--relay-stats",
        "--relay-stats-interval",
        "5",
        "--relay-compare",
        SIP_CALL_ID,
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    for needle in [
        "--relay-stats needs a relay to ask",
        "--relay-stats-interval needs a relay to poll",
        "--relay-compare needs a relay to ask",
    ] {
        assert!(run.stderr.contains(needle), "{needle}\n{}", run.dump());
    }
}

/// With a relay named, every ask on a file run is refused as offline -- and
/// nothing reaches the address named, which this test owns and watches.
#[test]
fn relay_asks_on_a_file_run_are_refused_and_nothing_is_sent() {
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the watched port");
    watch.set_nonblocking(true).expect("nonblocking");
    let relay = watch.local_addr().expect("address").to_string();
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--rtpengine-control",
        &relay,
        "--relay-stats",
        "--relay-stats-interval",
        "5",
        "--relay-compare",
        SIP_CALL_ID,
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    for needle in [
        "--relay-stats will not ask a relay on a run that reads a file",
        "--relay-stats-interval will not poll a relay on a run that reads a file",
        "--relay-compare will not ask a relay on a run that reads a file",
    ] {
        assert!(run.stderr.contains(needle), "{needle}\n{}", run.dump());
    }
    let mut buf = [0u8; 64];
    assert!(
        watch.recv_from(&mut buf).is_err(),
        "a file run must not transmit to the relay it names"
    );
}

// ── End-of-run summaries ──────────────────────────────────────────────────

/// Write a classic Ethernet pcap whose records carry explicit timestamps and
/// captured lengths: `(frame, ts_sec, ts_usec, captured)`.
fn write_raw_pcap(path: &Path, records: &[(Vec<u8>, u32, u32, usize)]) {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&65535u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    for (frame, sec, usec, captured) in records {
        let incl = (*captured).min(frame.len());
        b.extend_from_slice(&sec.to_le_bytes());
        b.extend_from_slice(&usec.to_le_bytes());
        b.extend_from_slice(&(incl as u32).to_le_bytes());
        b.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        b.extend_from_slice(&frame[..incl]);
    }
    std::fs::write(path, b).expect("write pcap");
}

/// A record whose microseconds field is out of range is stamped with the wall
/// clock, and the capture-quality summary says so: every timing figure drawn
/// from that capture is unreliable, even though every frame decoded.
#[test]
fn a_misdated_record_is_named_in_the_capture_quality_summary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("quality.pcap");
    let frame = udp_frame(
        [192, 0, 2, 10],
        [192, 0, 2, 20],
        5060,
        5060,
        &invite("quality@192.0.2.10", &[]),
    );
    write_raw_pcap(
        &pcap,
        &[
            (frame.clone(), 1_700_000_000, 0, usize::MAX),
            // 1.5 million microseconds is not a time of day.
            (frame, 1_700_000_001, 1_500_000, usize::MAX),
        ],
    );
    let run = sipnab(&["-N", "-I", s(&pcap)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(
            "capture quality: 1 packet(s) had a corrupt capture timestamp and were stamped \
             with the wall clock"
        ),
        "{}",
        run.dump()
    );
}

/// One LLMNR message: a query for `name` from its sender, or a response
/// claiming `name` for `owner`.
fn llmnr(id: u16, name: &str, answer: Option<[u8; 4]>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&(if answer.is_some() { 0x8000u16 } else { 0 }).to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // one question
    m.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes());
    m.push(u8::try_from(name.len()).expect("short label"));
    m.extend_from_slice(name.as_bytes());
    m.push(0);
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    if let Some(addr) = answer {
        m.extend_from_slice(&[0xC0, 0x0C]); // the question's name
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&30u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&addr);
    }
    m
}

/// LLMNR on the segment is summarized as a host roster: who answered for
/// which name, which lookups nothing answered, what each host looked up, and
/// -- past eight -- how many more there were rather than a silent cut.
#[test]
fn llmnr_on_the_segment_is_summarized_as_a_capped_host_roster() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("llmnr.pcap");
    let group = [224, 0, 0, 252];
    let mut frames = Vec::new();
    // One host looks up ten names, and one of them is answered below.
    for n in 0..10u16 {
        frames.push(udp_frame(
            [10, 9, 0, 99],
            group,
            51_000 + n,
            5355,
            &llmnr(100 + n, &format!("printer{n}"), None),
        ));
    }
    // Ten more hosts each look up a name nothing answers.
    for h in 0..10u8 {
        frames.push(udp_frame(
            [10, 9, 0, 10 + h],
            group,
            50_000 + u16::from(h),
            5355,
            &llmnr(u16::from(h), &format!("share{h}"), None),
        ));
    }
    frames.push(udp_frame(
        [10, 9, 0, 200],
        [10, 9, 0, 99],
        5355,
        51_000,
        &llmnr(100, "printer0", Some([10, 9, 0, 200])),
    ));
    write_pcap(&pcap, &frames);

    let run = sipnab(&["-N", "-I", s(&pcap)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    let err = &run.stderr;
    assert!(
        err.contains("LLMNR: 21 packet(s) from 12 host(s)"),
        "{}",
        run.dump()
    );
    assert!(
        err.contains("LLMNR: hostname(s) claimed on this segment: printer0."),
        "{}",
        run.dump()
    );
    assert!(
        err.contains("LLMNR: name(s) queried that nothing answered for:")
            && err.contains(", and 11 more."),
        "nineteen unanswered names, eight shown:\n{}",
        run.dump()
    );
    assert!(
        err.contains("LLMNR:   10.9.0.99 looked up printer0, printer1")
            && err.contains("printer7, and 2 more"),
        "{}",
        run.dump()
    );
    assert!(
        err.contains("LLMNR:   ... and 4 more host(s)."),
        "twelve hosts were seen, eight are listed:\n{}",
        run.dump()
    );
}

/// An Ethernet/IPv4 ICMP port-unreachable from a router, quoting a UDP
/// datagram 192.0.2.10:5060 -> 192.0.2.20:5060 carrying `quoted_sip`.
fn icmp_quoting_sip(quoted_sip: &[u8]) -> Vec<u8> {
    let udp_len = (8 + quoted_sip.len()) as u16;
    let mut quoted = vec![0x45, 0x00];
    quoted.extend_from_slice(&(20 + udp_len).to_be_bytes());
    quoted.extend_from_slice(&[0x00, 0x07, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    quoted.extend_from_slice(&[192, 0, 2, 10]);
    quoted.extend_from_slice(&[192, 0, 2, 20]);
    quoted.extend_from_slice(&5060u16.to_be_bytes());
    quoted.extend_from_slice(&5060u16.to_be_bytes());
    quoted.extend_from_slice(&udp_len.to_be_bytes());
    quoted.extend_from_slice(&[0x00, 0x00]);
    quoted.extend_from_slice(quoted_sip);

    let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&quoted);
    let total = (20 + icmp.len()) as u16;
    let mut pkt = vec![
        0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 3, 0x08, 0x00, 0x45, 0x00,
    ];
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x09, 0x00, 0x00, 64, 1, 0x00, 0x00]);
    pkt.extend_from_slice(&[198, 51, 100, 1]);
    pkt.extend_from_slice(&[192, 0, 2, 10]);
    pkt.extend_from_slice(&icmp);
    pkt
}

/// An ICMP error quoting a SIP request names the endpoint that did not answer,
/// and a quote cut before its Call-ID is counted as evidence against no call
/// rather than dropped.
#[test]
fn icmp_errors_quoting_sip_name_the_unreachable_endpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("icmp.pcap");
    let full = invite("icmp@192.0.2.10", &[]);
    write_pcap(
        &pcap,
        &[
            udp_frame([192, 0, 2, 10], [192, 0, 2, 20], 5060, 5060, &full),
            icmp_quoting_sip(&full),
            // RFC 1812 lets a router quote only what fits; this one stopped
            // after the request line, before any Call-ID.
            icmp_quoting_sip(b"INVITE sip:bob@example.com SIP/2.0\r\n"),
        ],
    );
    let run = sipnab(&["-N", "-I", s(&pcap)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(
            "ICMP: 2 error(s) quoting a SIP request, naming 1 unreachable endpoint(s). \
             Busiest: 192.0.2.20:5060 (2,"
        ),
        "{}",
        run.dump()
    );
    assert!(
        run.stderr
            .contains("ICMP: 1 error(s) quoted too little to name a Call-ID"),
        "{}",
        run.dump()
    );
}

// ── Key files loaded at startup ───────────────────────────────────────────

/// An `--srtp-keys` file that cannot be read refuses the run with exit 1 and
/// names the file, rather than analyzing encrypted media as noise.
#[test]
fn an_unreadable_srtp_key_file_refuses_the_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("absent.keys");
    let run = sipnab(&["-N", "-I", SIP_CALL, "--srtp-keys", s(&missing)]);
    assert_eq!(run.code, Some(1), "{}", run.dump());
    assert!(
        run.stderr
            .contains(&format!("Failed to load --srtp-keys {}", missing.display())),
        "{}",
        run.dump()
    );
}

/// A readable `--srtp-keys` file is loaded and announced with its key count.
#[test]
fn a_readable_srtp_key_file_is_loaded_and_announced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = dir.path().join("media.keys");
    // 30 bytes of key||salt, base64: AES_CM_128_HMAC_SHA1_80's master length.
    std::fs::write(&keys, format!("ssrc=4660 key={}\n", "A".repeat(40))).expect("write keys");
    let run = sipnab(&["-N", "-I", SIP_CALL, "--srtp-keys", s(&keys)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "SRTP decryption active: 1 key(s) from {}",
            keys.display()
        )),
        "{}",
        run.dump()
    );
}

/// One NSS key-log line with a client random and a master secret.
fn keylog_line(fill: char) -> String {
    format!(
        "CLIENT_RANDOM {} {}\n",
        fill.to_string().repeat(64),
        fill.to_string().repeat(96)
    )
}

/// A `--dtls-keylog` file is loaded and announced with its entry count.
#[test]
fn a_dtls_keylog_is_loaded_and_announced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keylog = dir.path().join("dtls.keylog");
    std::fs::write(&keylog, keylog_line('a') + &keylog_line('b')).expect("write keylog");
    let run = sipnab(&["-N", "-I", SIP_CALL, "--dtls-keylog", s(&keylog)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "DTLS-SRTP active: 2 keylog entr(ies) from {}",
            keylog.display()
        )),
        "{}",
        run.dump()
    );
}

/// A capture carrying its own TLS secrets in a Decryption Secrets Block
/// decrypts with no `--keylog`: the secrets are found and announced.
#[test]
fn secrets_embedded_in_the_capture_arm_decryption_without_a_keylog() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("dsb.pcapng");
    let frame = udp_frame(
        [192, 0, 2, 10],
        [192, 0, 2, 20],
        5060,
        5060,
        &invite("dsb@192.0.2.10", &[]),
    );
    write_pcapng_with_dsb(&pcap, &keylog_line('c'), &frame);
    let run = sipnab(&["-N", "-I", s(&pcap)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "TLS decryption active: 1 secret(s) from embedded DSB in {}",
            pcap.display()
        )),
        "{}",
        run.dump()
    );
}

/// With a `--keylog` already loaded, the embedded secrets are ADDED to it and
/// the addition is announced -- neither source replaces the other.
#[test]
fn embedded_secrets_are_added_to_a_keylog_already_loaded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("dsb.pcapng");
    let keylog = dir.path().join("session.keylog");
    std::fs::write(&keylog, keylog_line('d')).expect("write keylog");
    let frame = udp_frame(
        [192, 0, 2, 10],
        [192, 0, 2, 20],
        5060,
        5060,
        &invite("dsb2@192.0.2.10", &[]),
    );
    write_pcapng_with_dsb(&pcap, &keylog_line('e'), &frame);
    let run = sipnab(&["-N", "-I", s(&pcap), "--keylog", s(&keylog)]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "TLS decryption: +1 embedded DSB secret(s) from {}",
            pcap.display()
        )),
        "{}",
        run.dump()
    );
}

// ── vCon export: redaction map and digests ────────────────────────────────

/// `--redact-map` writes the token table owner-readable only, and the run
/// reports the redaction it applied.
#[cfg(unix)]
#[test]
fn the_redaction_map_is_written_owner_readable_and_the_redaction_reported() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("call.vcon.json");
    let map = dir.path().join("tokens.map");
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--export-vcon",
        SIP_CALL_ID,
        "--vcon-out",
        s(&out),
        "--redact",
        "--redact-map",
        s(&map),
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains("Redaction: ") && run.stderr.contains("classes, key "),
        "{}",
        run.dump()
    );
    assert!(
        run.stderr.contains(&format!(
            "token mapping(s) to '{}' (mode 0600)",
            map.display()
        )),
        "{}",
        run.dump()
    );
    let mode = std::fs::metadata(&map)
        .expect("map written")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the map reverses every pseudonym");
    assert!(out.exists(), "the container is written too");
}

/// An existing `--redact-map` is never overwritten: it may be the only way
/// back from tokens already sent somewhere. The run fails and writes nothing.
#[test]
fn an_existing_redaction_map_is_refused_and_nothing_is_exported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("call.vcon.json");
    let map = dir.path().join("tokens.map");
    std::fs::write(&map, "earlier export's table\n").expect("write map");
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--export-vcon",
        SIP_CALL_ID,
        "--vcon-out",
        s(&out),
        "--redact",
        "--redact-map",
        s(&map),
    ]);
    assert_eq!(run.code, Some(1), "{}", run.dump());
    assert!(
        run.stderr
            .contains("already exists and sipnab will not write over it"),
        "{}",
        run.dump()
    );
    assert_eq!(
        std::fs::read_to_string(&map).expect("map still there"),
        "earlier export's table\n",
        "the earlier table is untouched"
    );
    assert!(!out.exists(), "nothing is exported after the refusal");
}

/// A `--redact-key-file` that cannot be read is fatal: a fresh key would make
/// tokens that join against nothing, silently.
#[test]
fn an_unreadable_redaction_key_file_refuses_the_export() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("call.vcon.json");
    let key = dir.path().join("absent.key");
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--export-vcon",
        SIP_CALL_ID,
        "--vcon-out",
        s(&out),
        "--redact",
        "--redact-key-file",
        s(&key),
    ]);
    assert_eq!(run.code, Some(1), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "cannot read --redact-key-file '{}'",
            key.display()
        )),
        "{}",
        run.dump()
    );
    assert!(!out.exists(), "nothing is exported after the refusal");
}

/// `--vcon-digest` prints one `sha256sum`-format line per container on
/// stdout, and the digest is the digest of the bytes written.
#[test]
fn vcon_digest_prints_a_sha256sum_line_for_each_container_written() {
    use sha2::Digest;
    let dir = tempfile::tempdir().expect("tempdir");
    let export = dir.path().join("vcons");
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--no-cli-print",
        "--export-vcon-when",
        "response_code >= 200",
        "--export-vcon-dir",
        s(&export),
        "--vcon-digest",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    let lines: Vec<&str> = run.stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "one container, one line:\n{}", run.dump());
    let (digest, name) = lines[0].split_once("  ").expect("two-space separator");
    let bytes = std::fs::read(export.join(name)).expect("the named container exists");
    let expected: String = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(digest, expected, "the digest is of the bytes on disk");
}

// ── Output switches ───────────────────────────────────────────────────────

/// `--wireshark` on a capture holding no SIP says so, rather than printing an
/// empty display filter that matches nothing.
#[test]
fn wireshark_with_no_dialogs_says_there_is_nothing_to_filter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("rtp-only.pcap");
    write_pcap(
        &pcap,
        &[udp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            40_000,
            40_002,
            &[0u8; 32],
        )],
    );
    let run = sipnab(&["-N", "-I", s(&pcap), "--wireshark"]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr
            .contains("No SIP dialogs to generate Wireshark filter for."),
        "{}",
        run.dump()
    );
    assert!(
        run.stdout.trim().is_empty(),
        "no filter is printed:\n{}",
        run.dump()
    );
}

/// Base64url without padding, as a JWT segment.
fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `--stir-shaken` reports each Identity header's attestation and numbers,
/// and warns about one that does not parse instead of treating it as absent.
#[test]
fn stir_shaken_reports_each_identity_and_warns_on_a_corrupt_one() {
    let header = b64url(
        br#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.com/sp.pem"}"#,
    );
    let claims = b64url(
        br#"{"attest":"A","dest":{"tn":["12025551212"]},"iat":1700000000,"orig":{"tn":"12025550100"},"origid":"0b4f3a52-1c7e-4d3b-9b1d-2d6a0f7e8c11"}"#,
    );
    let identity = format!(
        "Identity: {header}.{claims}.{};info=<https://cert.example.com/sp.pem>;alg=ES256;ppt=shaken",
        b64url(b"not-a-real-signature")
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("shaken.pcap");
    write_pcap(
        &pcap,
        &[
            udp_frame(
                [192, 0, 2, 10],
                [192, 0, 2, 20],
                5060,
                5060,
                &invite("shaken@192.0.2.10", &[identity.as_str()]),
            ),
            udp_frame(
                [192, 0, 2, 10],
                [192, 0, 2, 20],
                5060,
                5060,
                &invite(
                    "forged@192.0.2.10",
                    &["Identity: not.a.passport;ppt=shaken"],
                ),
            ),
        ],
    );
    let run = sipnab(&["-N", "-I", s(&pcap), "--stir-shaken"]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains("STIR/SHAKEN: attest=")
            && run.stderr.contains("orig=12025550100")
            && run.stderr.contains("12025551212"),
        "{}",
        run.dump()
    );
    assert!(
        run.stderr
            .contains("STIR/SHAKEN: unparseable Identity header"),
        "{}",
        run.dump()
    );
}

/// `SIPNAB_PERF_STATS` prints the per-run work counters that scale with call
/// count, and the dialog and stream counts are this capture's.
#[test]
fn the_perf_stats_probe_prints_this_runs_work_counters() {
    let run = sipnab_env(
        &["-N", "-I", SIP_CALL, "--no-cli-print"],
        &[("SIPNAB_PERF_STATS", "1")],
    );
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains("[perf-stats] dialogs=1 streams="),
        "{}",
        run.dump()
    );
}

/// The probe is off unless asked for: an ordinary run prints no counters.
#[test]
fn the_perf_stats_probe_is_silent_unless_asked() {
    let run = sipnab(&["-N", "-I", SIP_CALL, "--no-cli-print"]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(!run.stderr.contains("[perf-stats]"), "{}", run.dump());
}

// ── Startup refusals and notices ──────────────────────────────────────────

/// `--cores N` cannot write `-O`: the parallel reader has no capture writer,
/// so the run is refused with exit 2 and the flag named, instead of writing an
/// empty file and exiting 0.
#[test]
fn cores_with_an_output_file_is_refused_and_names_the_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("out.pcap");
    let run = sipnab(&["-N", "-I", SIP_CALL, "--cores", "2", "-O", s(&out)]);
    assert_eq!(run.code, Some(2), "{}", run.dump());
    assert!(
        run.stderr.contains("--cores 2 cannot produce -O/--output"),
        "{}",
        run.dump()
    );
    assert!(!out.exists(), "nothing is written after the refusal");
}

/// `--metrics` on the `--cores` path is said out loud as not served, rather
/// than left to be discovered by an empty dashboard.
#[test]
fn metrics_on_the_parallel_reader_is_reported_as_not_served() {
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--cores",
        "2",
        "--no-cli-print",
        "--metrics",
        "127.0.0.1:0",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr
            .contains("--metrics is ignored with --cores 2: the parallel offline reader"),
        "{}",
        run.dump()
    );
    assert!(
        run.stderr.contains("(2 cores)"),
        "the parallel reader ran and reported its core count:\n{}",
        run.dump()
    );
}

/// Several inputs are read in capture-time order, and the run says how many
/// files it is about to read and which comes first.
#[test]
fn several_inputs_are_announced_with_their_count_and_the_first_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let early = dir.path().join("early.pcap");
    let late = dir.path().join("late.pcap");
    std::fs::copy(SIP_CALL, &early).expect("copy fixture");
    std::fs::copy(SIP_CALL, &late).expect("copy fixture");
    let run = sipnab(&["-N", "-I", s(&late), "-I", s(&early), "--no-cli-print"]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr
            .contains("Reading 2 capture files in timestamp order"),
        "{}",
        run.dump()
    );
}

/// `--sandbox best-effort` reports what it installed either way: enforced
/// where the kernel has Landlock, not active (and why) where it does not --
/// and the file run completes under it.
#[test]
fn a_best_effort_sandbox_reports_its_state_and_the_run_completes() {
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--no-cli-print",
        "--sandbox",
        "best-effort",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains("path sandbox ENFORCED")
            || run.stderr.contains("path sandbox NOT active"),
        "{}",
        run.dump()
    );
}

/// `--hep-send` with an inline secret forwards the capture's SIP to the
/// collector named -- a loopback socket this test owns -- and says the stream
/// is authenticated.
#[test]
fn hep_send_with_a_secret_forwards_authenticated_hep_to_the_collector() {
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("read timeout");
    let addr = collector.local_addr().expect("address").to_string();
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--no-cli-print",
        "--hep-send",
        &addr,
        "--hep-auth",
        "collector-secret",
    ]);
    assert_eq!(run.code, Some(0), "{}", run.dump());
    assert!(
        run.stderr.contains(&format!(
            "HEP sender targeting {addr} over udp (capture id 1, authenticated)"
        )),
        "{}",
        run.dump()
    );
    let mut buf = [0u8; 65536];
    let (n, _) = collector
        .recv_from(&mut buf)
        .expect("a HEP datagram arrives");
    assert_eq!(&buf[..4], b"HEP3", "HEP v3 framing");
    assert!(
        buf[..n].windows(16).any(|w| w == b"collector-secret"),
        "the auth chunk carries the configured secret"
    );
}

/// An unreadable `--hep-auth-file` refuses the run instead of forwarding the
/// capture's signaling unauthenticated -- nothing reaches the collector.
///
/// The resolver refuses an unreadable file "so a mis-set secret fails loudly
/// instead of silently disabling authentication", and `-L` already turns the
/// same refusal into exit 2. `--hep-send` logged it and sent anyway.
#[test]
fn an_unreadable_hep_auth_file_refuses_the_run_and_sends_nothing() {
    let collector = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind collector");
    collector.set_nonblocking(true).expect("nonblocking");
    let addr = collector.local_addr().expect("address").to_string();
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("hep.secret");
    let run = sipnab(&[
        "-N",
        "-I",
        SIP_CALL,
        "--no-cli-print",
        "--hep-send",
        &addr,
        "--hep-auth-file",
        s(&missing),
    ]);
    assert_eq!(run.code, Some(2), "{}", run.dump());
    assert!(
        run.stderr.contains("HEP auth: --hep-auth-file"),
        "{}",
        run.dump()
    );
    let mut buf = [0u8; 64];
    assert!(
        collector.recv_from(&mut buf).is_err(),
        "no unauthenticated HEP may reach the collector"
    );
}

// ── Snapped frames and the packet count ───────────────────────────────────

/// Three INVITEs on UDP 5060 with the middle one recorded `cut` bytes short of
/// its wire length -- `incl_len` below `orig_len`, which is what a snaplen
/// does -- or all three whole when `cut` is zero.
fn three_invites_one_cut(path: &Path, cut: usize) {
    let frames: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            udp_frame(
                [192, 0, 2, 10],
                [192, 0, 2, 20],
                5060,
                5060,
                &invite(&format!("snap-{i}@192.0.2.10"), &[]),
            )
        })
        .collect();
    let kept = frames[1].len() - cut;
    write_raw_pcap(
        path,
        &[
            (frames[0].clone(), 1_700_000_000, 0, usize::MAX),
            (frames[1].clone(), 1_700_000_001, 0, kept),
            (frames[2].clone(), 1_700_000_002, 0, usize::MAX),
        ],
    );
}

/// The default reader, then `--cores 2`, over the same capture.
fn on_both_readers(pcap: &Path) -> [(&'static str, Outcome); 2] {
    [
        ("default reader", sipnab(&["-N", "-I", s(pcap)])),
        ("--cores 2", sipnab(&["-N", "-I", s(pcap), "--cores", "2"])),
    ]
}

/// A frame the capture cut short is reported as cut short on the default
/// reader AND on `--cores`, and is never described as a frame that "reached
/// sipnab intact".
///
/// Before, the counter lived in the one packet constructor only the `--cores`
/// reader called, so the default reader never counted a snapped frame at all
/// -- and both readers filed the frame, which the decoder rejects because the
/// bytes its IP header promises were never captured, as a "decode error" that
/// had "reached sipnab intact".
#[test]
fn a_snapped_frame_is_reported_as_snapped_on_every_reader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("snapped.pcap");
    three_invites_one_cut(&pcap, 20);
    for (reader, run) in on_both_readers(&pcap) {
        assert_eq!(run.code, Some(0), "{reader}\n{}", run.dump());
        assert!(
            run.stderr
                .contains("1 frame(s) arrived truncated by the capture's snaplen"),
            "{reader}: the snapped frame must be counted exactly once\n{}",
            run.dump()
        );
        assert!(
            !run.stderr.contains("reached sipnab intact"),
            "{reader}: a frame the capture cut short did not arrive intact\n{}",
            run.dump()
        );
        assert!(
            run.stderr.contains("Reasons: truncated frame (1)."),
            "{reader}: the frame produced nothing because it was cut short, \
             not because its format is unreadable\n{}",
            run.dump()
        );
    }
}

/// The negative control: a capture with nothing cut short reports no truncated
/// frame on either reader.
#[test]
fn an_intact_capture_reports_no_truncated_frame_on_either_reader() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("intact.pcap");
    three_invites_one_cut(&pcap, 0);
    for (reader, run) in on_both_readers(&pcap) {
        assert_eq!(run.code, Some(0), "{reader}\n{}", run.dump());
        assert!(
            !run.stderr.contains("arrived truncated"),
            "{reader}: nothing was cut short\n{}",
            run.dump()
        );
        assert!(
            run.stderr.contains("sipnab: 3 packets"),
            "{reader}\n{}",
            run.dump()
        );
    }
}

/// An Ethernet ARP who-has, captured whole: a frame no decoder here turns into
/// a parsed packet, with nothing about the capture to blame.
fn arp_frame() -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0x08, 0x06]);
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 192, 0, 2, 10]);
    f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 192, 0, 2, 20]);
    f
}

/// Every record a `--cores` run reads is in its packet count, exactly as on
/// the default reader -- including a frame that produced nothing.
///
/// The `--cores` summary printed the count of PARSED packets, so a 3-record
/// capture holding one undecodable frame said "2 packets" there and "3 packets"
/// on the default reader, and put the undecodable frame at "1 of 2" -- 50%,
/// which is the share at which the notice declares the run mostly blind.
#[test]
fn a_cores_run_counts_every_record_it_read_as_the_default_reader_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = dir.path().join("with-arp.pcap");
    let sip = |i: u32| {
        udp_frame(
            [192, 0, 2, 10],
            [192, 0, 2, 20],
            5060,
            5060,
            &invite(&format!("count-{i}@192.0.2.10"), &[]),
        )
    };
    write_raw_pcap(
        &pcap,
        &[
            (sip(0), 1_700_000_000, 0, usize::MAX),
            (arp_frame(), 1_700_000_001, 0, usize::MAX),
            (sip(1), 1_700_000_002, 0, usize::MAX),
        ],
    );
    for (reader, run) in on_both_readers(&pcap) {
        assert_eq!(run.code, Some(0), "{reader}\n{}", run.dump());
        assert!(
            run.stderr.contains("sipnab: 3 packets"),
            "{reader}: three records were read\n{}",
            run.dump()
        );
        assert!(
            run.stderr.contains("NOT DECODED: 1 of 3 frame(s) (33.3%)"),
            "{reader}: the share is of frames READ\n{}",
            run.dump()
        );
    }
}
