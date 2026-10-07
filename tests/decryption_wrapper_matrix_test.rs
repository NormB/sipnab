// SPDX-License-Identifier: MIT OR Apache-2.0

//! Decryption answers the same whatever the capture arrived wrapped in.
//!
//! Every decryption path sipnab has is run over one synthetic capture presented
//! five ways — as it is, gzip-compressed, as a tar member, as a `.tgz` member,
//! and gzip-compressed inside a `.tgz` — and the decrypted content must be
//! IDENTICAL across all five. Each row also proves the plain column actually
//! decrypted something, so an answer that is identical because every column
//! decrypted nothing fails instead of passing.
//!
//! | Row | Key material | What proves decryption |
//! |---|---|---|
//! | TLS, `--keylog` | a keylog file | the SIP inside the TLS records becomes a dialog |
//! | TLS, embedded DSB | a pcapng Decryption Secrets Block | the same, with no `--keylog` |
//! | SRTP, SDES | `a=crypto` in the SDP | the RFC 4733 digits inside the SRTP payloads |
//! | DTLS-SRTP | `--dtls-keylog` | the same, keyed by the DTLS exporter |
//! | ESP, NULL encryption | none: RFC 2410 has no key | the SIP inside the ESP becomes messages |
//!
//! The ciphertext is sealed here, with `ring` and `aes` directly, and shares no
//! code with the decryptors it checks. Every fixture is built in the test; no
//! capture bytes are committed.
#![cfg(all(feature = "native", feature = "tls"))]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/tar_build.rs"]
mod tar_build;

use tar_build::{Entry, gzip_or_panic, tar};
#[path = "support/encrypted_captures.rs"]
mod encrypted_captures;
use encrypted_captures::*;

// ── The five presentations ──────────────────────────────────────────────

/// How one capture is presented to `-I`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    Plain,
    Gzip,
    TarMember,
    TgzMember,
    GzipInTgz,
}

const WRAPPERS: [Wrapper; 5] = [
    Wrapper::Plain,
    Wrapper::Gzip,
    Wrapper::TarMember,
    Wrapper::TgzMember,
    Wrapper::GzipInTgz,
];

/// Write `capture` (a file named `name`) under `dir` presented as `how`, and
/// return the path to hand `-I`.
fn present(dir: &Path, name: &str, capture: &[u8], how: Wrapper) -> PathBuf {
    let member = format!("caps/{name}");
    let (file, bytes) = match how {
        Wrapper::Plain => (name.to_string(), capture.to_vec()),
        Wrapper::Gzip => (format!("{name}.gz"), gzip_or_panic(capture)),
        Wrapper::TarMember => ("set.tar".to_string(), tar(&[Entry::file(&member, capture)])),
        Wrapper::TgzMember => (
            "set.tgz".to_string(),
            gzip_or_panic(&tar(&[Entry::file(&member, capture)])),
        ),
        Wrapper::GzipInTgz => {
            let inner = gzip_or_panic(capture);
            let member_gz = format!("{member}.gz");
            (
                "set.tgz".to_string(),
                gzip_or_panic(&tar(&[Entry::file(&member_gz, &inner)])),
            )
        }
    };
    let path = dir.join(file);
    std::fs::write(&path, bytes).expect("write presented capture");
    path
}

/// Run the binary with `TMPDIR` pointed at a private directory, so nothing it
/// unpacks lands anywhere shared.
fn sipnab(args: &[&str], log: &str, tmpdir: &Path) -> (String, String, Option<i32>) {
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(args)
        .env("TMPDIR", tmpdir)
        .env("SIPNAB_LOG", log)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn sipnab");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
    )
}

/// Run one row across every wrapper and require one answer.
///
/// `observe` turns a run into the decrypted content it produced; `proof` is
/// what the plain column must contain for the row to mean anything.
fn matrix(
    row: &str,
    name: &str,
    capture: &[u8],
    extra: &[&str],
    log: &str,
    observe: &dyn Fn(&str, &str) -> String,
    proof: &str,
) {
    let mut answers = Vec::new();
    for how in WRAPPERS {
        let dir = tempfile::tempdir().expect("dir");
        let tmp = tempfile::tempdir().expect("tmp");
        let input = present(dir.path(), name, capture, how);
        let spec = input.display().to_string();
        let mut args = vec!["-N", "-I", spec.as_str()];
        args.extend_from_slice(extra);
        let (stdout, stderr, code) = sipnab(&args, log, tmp.path());
        assert_eq!(code, Some(0), "{row} / {how:?}: exit status\n{stderr}");
        answers.push((how, observe(&stdout, &stderr)));
    }
    let (_, plain) = &answers[0];
    assert!(
        plain.contains(proof),
        "{row}: the plain capture did not decrypt, so every column agreeing \
         would prove nothing. Expected to see {proof:?} in:\n{plain}"
    );
    for (how, answer) in &answers[1..] {
        assert_eq!(
            answer, plain,
            "{row}: {how:?} decrypts differently from plain"
        );
    }
}

// ── TLS 1.3 ────────────────────────────────────────────────────────────

/// The SIP messages a run printed with `--json`: what the decryption produced.
fn sip_messages(stdout: &str, _stderr: &str) -> String {
    let mut out: Vec<String> = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v.get("call_id").is_some())
        .map(|v| {
            format!(
                "{} {} {}",
                v["call_id"].as_str().unwrap_or_default(),
                v["method"].as_str().unwrap_or_default(),
                v["status_code"]
            )
        })
        .collect();
    out.sort();
    out.join("\n")
}

#[test]
fn tls_with_a_keylog_decrypts_the_same_in_every_wrapper() {
    let keydir = tempfile::tempdir().expect("keys");
    let keylog = keydir.path().join("session.keylog");
    std::fs::write(&keylog, tls_keylog()).expect("keylog");
    let keylog = keylog.display().to_string();
    matrix(
        "TLS --keylog",
        "tls.pcap",
        &classic_pcap_or_panic(&tls_session_frames_or_panic()),
        &["--keylog", &keylog, "--json", "--portrange", "1-65535"],
        "warn",
        &sip_messages,
        TLS_CALL_ID,
    );
}

#[test]
fn tls_with_embedded_secrets_decrypts_the_same_in_every_wrapper() {
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("dsb.pcapng");
    pcap_build::write_pcapng_with_dsb_frames_or_panic(
        &p,
        &tls_keylog(),
        &tls_session_frames_or_panic(),
    );
    let capture = std::fs::read(&p).expect("read");
    matrix(
        "TLS embedded DSB",
        "dsb.pcapng",
        &capture,
        &["--json", "--portrange", "1-65535"],
        "warn",
        &sip_messages,
        TLS_CALL_ID,
    );
}

// ── SRTP ───────────────────────────────────────────────────────────────

/// The DTMF digits a run decoded, in order, from its cleartext debug lines.
fn dtmf_digits(_stdout: &str, stderr: &str) -> String {
    stderr
        .lines()
        .filter_map(|l| l.split_once("DTMF cleartext digit='").map(|(_, r)| r))
        .filter_map(|r| r.chars().next())
        .collect()
}

#[test]
fn srtp_keyed_by_sdes_decrypts_the_same_in_every_wrapper() {
    matrix(
        "SRTP SDES",
        "sdes.pcap",
        &classic_pcap_or_panic(&sdes_call_frames_or_panic()),
        &["-t", "--dtmf-cleartext", "--no-cli-print"],
        "sipnab=debug",
        &dtmf_digits,
        "42",
    );
}

// ── DTLS-SRTP ──────────────────────────────────────────────────────────

const DTLS_CLIENT_RANDOM: [u8; 32] = [0x61; 32];
const DTLS_SERVER_RANDOM: [u8; 32] = [0x16; 32];
const DTLS_MASTER: [u8; 48] = [0x2d; 48];

/// The TLS 1.2 PRF with SHA-256 (RFC 5246 section 5).
fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);
    let mut a = ring::hmac::sign(&key, &label_seed).as_ref().to_vec();
    let mut out = Vec::new();
    while out.len() < len {
        let mut input = a.clone();
        input.extend_from_slice(&label_seed);
        out.extend_from_slice(ring::hmac::sign(&key, &input).as_ref());
        a = ring::hmac::sign(&key, &a).as_ref().to_vec();
    }
    out.truncate(len);
    out
}

fn dtls_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    let len3 = [(len >> 16) as u8, (len >> 8) as u8, len as u8];
    let mut hs = vec![msg_type];
    hs.extend_from_slice(&len3);
    hs.extend_from_slice(&[0, 0]); // message_seq
    hs.extend_from_slice(&[0, 0, 0]); // fragment_offset
    hs.extend_from_slice(&len3); // fragment_length
    hs.extend_from_slice(body);
    let mut rec = vec![22u8, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// DTLS hellos that negotiate SRTP_AES128_CM_HMAC_SHA1_80, then DTMF "42" as
/// SRTP keyed by the DTLS-SRTP exporter.
fn dtls_srtp_frames() -> Vec<Vec<u8>> {
    let a = [10, 7, 0, 1];
    let b = [10, 7, 0, 2];
    let (pa, pb) = (41_000u16, 51_000u16);
    let mut ch = vec![0xfe, 0xfd];
    ch.extend_from_slice(&DTLS_CLIENT_RANDOM);
    ch.extend_from_slice(&[0, 0]); // session id, cookie
    ch.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2b]);
    ch.extend_from_slice(&[0x01, 0x00]);
    let mut sh = vec![0xfe, 0xfd];
    sh.extend_from_slice(&DTLS_SERVER_RANDOM);
    sh.push(0);
    sh.extend_from_slice(&[0xc0, 0x2b, 0x00]);
    let use_srtp = [0x00u8, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00];
    sh.extend_from_slice(&(use_srtp.len() as u16).to_be_bytes());
    sh.extend_from_slice(&use_srtp);

    let mut seed = DTLS_CLIENT_RANDOM.to_vec();
    seed.extend_from_slice(&DTLS_SERVER_RANDOM);
    let km = prf_sha256(&DTLS_MASTER, b"EXTRACTOR-dtls_srtp", &seed, 60);
    let (client_key, client_salt) = (&km[0..16], &km[32..46]);

    let mut frames = vec![
        pcap_build::udp_frame(a, b, pa, pb, &dtls_handshake(1, &ch)),
        pcap_build::udp_frame(b, a, pb, pa, &dtls_handshake(2, &sh)),
    ];
    for p in dtmf_srtp_or_panic(client_key, client_salt, 0x0bad_cafe, &[4, 2]) {
        frames.push(pcap_build::udp_frame(a, b, pa, pb, &p));
    }
    frames
}

#[test]
fn dtls_srtp_decrypts_the_same_in_every_wrapper() {
    let keydir = tempfile::tempdir().expect("keys");
    let keylog = keydir.path().join("dtls.keylog");
    std::fs::write(
        &keylog,
        format!(
            "CLIENT_RANDOM {} {}\n",
            hex(&DTLS_CLIENT_RANDOM),
            hex(&DTLS_MASTER)
        ),
    )
    .expect("keylog");
    let keylog = keylog.display().to_string();
    matrix(
        "DTLS-SRTP",
        "dtls.pcap",
        &classic_pcap_or_panic(&dtls_srtp_frames()),
        &[
            "--dtls-keylog",
            &keylog,
            "-t",
            "--dtmf-cleartext",
            "--no-cli-print",
        ],
        "sipnab=debug",
        &dtmf_digits,
        "42",
    );
}

// ── ESP with NULL encryption ───────────────────────────────────────────
//
// An IMS Gm interface in a lab runs IPsec ESP with NULL encryption (RFC
// 2410): no key, but the SIP sits between an ESP header and trailer that
// have to be proven and peeled.

const ESP_CALL_ID: &str = "matrix-esp-1@test";
const ESP_PHONE: [u8; 4] = [10, 1, 0, 1];
const ESP_PCSCF: [u8; 4] = [10, 2, 0, 1];

/// One's-complement sum folded to 16 bits, then inverted.
fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = parts.concat();
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Ethernet + IPv4 (protocol 50) + ESP carrying a checksummed UDP datagram,
/// RFC 4303 default padding, and a 12-octet ICV (HMAC-SHA-1-96's length).
fn esp_null_udp_frame(src: [u8; 4], dst: [u8; 4], seq: u32, sip: &[u8]) -> Vec<u8> {
    let udp_len = (8 + sip.len()) as u16;
    let mut udp = Vec::new();
    udp.extend_from_slice(&5060u16.to_be_bytes());
    udp.extend_from_slice(&5060u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(sip);
    let pseudo = [&src[..], &dst[..], &[0, 17], &udp_len.to_be_bytes()[..]].concat();
    let ck = internet_checksum(&[&pseudo, &udp]);
    udp[6..8].copy_from_slice(&ck.to_be_bytes());

    let mut esp = Vec::new();
    esp.extend_from_slice(&0x0000_4D2Au32.to_be_bytes()); // SPI
    esp.extend_from_slice(&seq.to_be_bytes());
    esp.extend_from_slice(&udp);
    let pad = (4 - (udp.len() + 2) % 4) % 4;
    esp.extend((1..=pad as u8).collect::<Vec<u8>>());
    esp.push(pad as u8);
    esp.push(17); // next header: UDP
    esp.extend_from_slice(&[0xA7; 12]); // ICV: NULL encryption still authenticates

    let total = (20 + esp.len()) as u16;
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 64, 50, 0x00, 0x00]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let ck = internet_checksum(&[&ip]);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());

    let mut frame = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&esp);
    frame
}

/// A whole call between a phone and its P-CSCF, every message inside ESP.
fn esp_null_call_frames() -> Vec<Vec<u8>> {
    pcap_build::sip_call(ESP_CALL_ID, "esp1", "phone", "pcscf")
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            let (src, dst) = if i % 2 == 0 {
                (ESP_PHONE, ESP_PCSCF)
            } else {
                (ESP_PCSCF, ESP_PHONE)
            };
            esp_null_udp_frame(src, dst, i as u32 + 1, msg.as_bytes())
        })
        .collect()
}

#[test]
fn esp_with_null_encryption_decodes_the_same_in_every_wrapper() {
    matrix(
        "ESP NULL",
        "esp.pcap",
        &classic_pcap_or_panic(&esp_null_call_frames()),
        &["--json"],
        "warn",
        &sip_messages,
        ESP_CALL_ID,
    );
}

// ── SIP over secure WebSocket ─────────────────────────────────────────

/// Run sipnab over `frames` with the session's keylog, returning the
/// `(what, transport)` of each message of the test call, and stderr.
fn decrypt_wss(frames: &[Vec<u8>]) -> (Vec<(String, String)>, String) {
    let dir = tempfile::tempdir().expect("dir");
    let tmp = tempfile::tempdir().expect("tmp");
    let keylog = dir.path().join("session.keylog");
    std::fs::write(&keylog, tls_keylog()).expect("keylog");
    let capture = dir.path().join("wss.pcap");
    std::fs::write(&capture, classic_pcap_or_panic(frames)).expect("capture");
    let (stdout, stderr, code) = sipnab(
        &[
            "-N",
            "-I",
            capture.to_str().unwrap(),
            "--keylog",
            keylog.to_str().unwrap(),
            "--json",
            "--portrange",
            "1-65535",
        ],
        "warn",
        tmp.path(),
    );
    assert_eq!(code, Some(0), "{stderr}");
    let messages = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["call_id"] == WSS_CALL_ID)
        .map(|v| {
            let what = v["method"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v["status_code"].to_string());
            (
                what,
                v["transport"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    (messages, stderr)
}

/// The expected pair: the INVITE and its 180, both over WSS.
fn invite_and_ringing_over_wss() -> Vec<(String, String)> {
    vec![
        ("INVITE".to_string(), "WSS".to_string()),
        ("180".to_string(), "WSS".to_string()),
    ]
}

/// **Decrypted WSS is SIP, labeled WSS** (found reproducing issue #301).
///
/// With the keys, the TLS records of a WSS leg decrypted, and what came out
/// was WebSocket frames. The decrypted path framed plaintext as SIP and
/// dropped anything else, and WebSocket unwrapping ran only on plain TCP, so
/// the lab saw 12 records recovered and no SIP at all. The frames are
/// recognized by their shape and their SIP content, not by port: TLS already
/// said what this is, and 7443 is outside the default WebSocket port set.
#[test]
fn a_decrypted_wss_session_is_sip_over_wss() {
    let (invite, ringing) = wss_messages();
    let frames = wss_session_or_panic(
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[ws_text_frame(ringing.as_bytes(), None)],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, invite_and_ringing_over_wss(), "{stderr}");
}

/// **OpenSIPS's shape: one frame, two TLS records.** OpenSIPS writes the
/// 4-byte WebSocket frame header in one TLS record and the payload in the
/// next. A decrypted record was only recognized when it was one whole frame,
/// so every message the proxy SENT over WSS was lost, with nothing counted:
/// the lab saw the client's INVITE, ACK and BYE and none of the proxy's 100,
/// 180, 200 and 200.
#[test]
fn a_websocket_frame_split_across_two_tls_records_is_one_message() {
    let (invite, ringing) = wss_messages();
    let frame = ws_text_frame(ringing.as_bytes(), None);
    assert_eq!(
        &frame[1..2],
        &[126],
        "a 16-bit length makes the header 4 bytes"
    );
    let (header, payload) = frame.split_at(4);
    let frames = wss_session_or_panic(
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[header.to_vec(), payload.to_vec()],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, invite_and_ringing_over_wss(), "{stderr}");
    assert!(!stderr.contains("NOT DECODED"), "{stderr}");
}

/// The masked client direction splits the same way, the mask key included.
#[test]
fn a_masked_frame_split_inside_its_header_is_one_message() {
    let (invite, ringing) = wss_messages();
    let frame = ws_text_frame(invite.as_bytes(), Some(WS_MASK));
    // Header is 2 + 2 + 4 bytes; cut inside the mask key.
    let (head, rest) = frame.split_at(6);
    let frames = wss_session_or_panic(
        &[head.to_vec(), rest.to_vec()],
        &[ws_text_frame(ringing.as_bytes(), None)],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, invite_and_ringing_over_wss(), "{stderr}");
}

/// Two frames in one TLS record are two messages.
#[test]
fn two_websocket_frames_in_one_tls_record_are_two_messages() {
    let (invite, ringing) = wss_messages();
    let trying = ringing.replace("180 Ringing", "100 Trying");
    let mut both = ws_text_frame(trying.as_bytes(), None);
    both.extend_from_slice(&ws_text_frame(ringing.as_bytes(), None));
    let frames = wss_session_or_panic(&[ws_text_frame(invite.as_bytes(), Some(WS_MASK))], &[both]);
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(
        messages,
        vec![
            ("INVITE".to_string(), "WSS".to_string()),
            ("100".to_string(), "WSS".to_string()),
            ("180".to_string(), "WSS".to_string()),
        ],
        "{stderr}"
    );
}

/// A message fragmented across two frames ([RFC 6455 section 5.4](https://www.rfc-editor.org/rfc/rfc6455#section-5.4)):
/// a text frame with FIN clear, then a continuation frame with FIN set.
#[test]
fn a_message_fragmented_across_two_websocket_frames_is_one_message() {
    let (invite, ringing) = wss_messages();
    let (first, second) = ringing.as_bytes().split_at(30);
    let frames = wss_session_or_panic(
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[
            ws_frame_raw(false, 1, first, None),
            ws_frame_raw(true, 0, second, None),
        ],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, invite_and_ringing_over_wss(), "{stderr}");
}

/// A frame whose rest never arrives is counted as NOT DECODED, never lost in
/// silence: here the capture ends after the 4-byte header record.
#[test]
fn an_abandoned_partial_websocket_frame_is_counted() {
    let (invite, ringing) = wss_messages();
    let frame = ws_text_frame(ringing.as_bytes(), None);
    let frames = wss_session_or_panic(
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[frame[..4].to_vec()],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(
        messages,
        vec![("INVITE".to_string(), "WSS".to_string())],
        "{stderr}"
    );
    let not_decoded = stderr
        .lines()
        .find(|l| l.starts_with("NOT DECODED:"))
        .unwrap_or_else(|| panic!("the abandoned frame must be counted: {stderr}"));
    assert!(not_decoded.contains("truncated frame (1)"), "{not_decoded}");
}

// ── The HTTP upgrade, however it is split ──────────────────────────────

/// The INVITE with the 100 and 180 that answer it, all over WSS.
fn invite_trying_ringing() -> (String, String, String, Vec<(String, String)>) {
    let (invite, ringing) = wss_messages();
    let trying = ringing.replace("180 Ringing", "100 Trying");
    let want = ["INVITE", "100", "180"]
        .iter()
        .map(|w| (w.to_string(), "WSS".to_string()))
        .collect();
    (invite, trying, ringing, want)
}

/// **OpenSIPS's 101 in three records.** OpenSIPS writes `101 Switching
/// Protocols` as the headers up to `Sec-WebSocket-Accept: `, then the 28-byte
/// accept key, then the closing blank line alone. Only a record STARTING with
/// the status line was taken for the handshake, so the other two were read as
/// frame bytes, and the proxy's first reply after the upgrade was lost into a
/// refused frame.
#[test]
fn a_101_split_across_three_records_is_followed_by_every_frame() {
    let (invite, trying, ringing, want) = invite_trying_ringing();
    let key_at = SWITCHING.find("Sec-WebSocket-Accept: ").unwrap() + "Sec-WebSocket-Accept: ".len();
    let blank_at = SWITCHING.len() - 4;
    let head = SWITCHING.as_bytes();
    let frames = wss_session_with_or_panic(
        &[UPGRADE.as_bytes().to_vec()],
        &[
            head[..key_at].to_vec(),
            head[key_at..blank_at].to_vec(),
            head[blank_at..].to_vec(),
        ],
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[
            ws_text_frame(trying.as_bytes(), None),
            ws_text_frame(ringing.as_bytes(), None),
        ],
    );
    assert_eq!(&head[blank_at..], b"\r\n\r\n");
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, want, "{stderr}");
    assert!(!stderr.contains("NOT DECODED"), "{stderr}");
}

/// The client's upgrade request split across records, after the line that
/// names the upgrade, so the first record already says this is WebSocket and
/// the second is the rest of the HTTP head, not frames.
#[test]
fn an_upgrade_request_split_across_records_is_followed_by_every_frame() {
    let (invite, trying, ringing, want) = invite_trying_ringing();
    let head = UPGRADE.as_bytes();
    let cut = UPGRADE.find("Connection: ").unwrap();
    assert!(UPGRADE[..cut].contains("websocket"));
    let frames = wss_session_with_or_panic(
        &[head[..cut].to_vec(), head[cut..].to_vec()],
        &[SWITCHING.as_bytes().to_vec()],
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[
            ws_text_frame(trying.as_bytes(), None),
            ws_text_frame(ringing.as_bytes(), None),
        ],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(messages, want, "{stderr}");
    assert!(!stderr.contains("NOT DECODED"), "{stderr}");
}

/// The 101 and the first frame in one record: frames start at the first byte
/// after the blank line that ends the HTTP head.
#[test]
fn a_101_and_the_first_frame_in_one_record_both_count() {
    let (invite, trying, ringing, want) = invite_trying_ringing();
    let mut first = SWITCHING.as_bytes().to_vec();
    first.extend_from_slice(&ws_text_frame(trying.as_bytes(), None));
    let frames = wss_session_with_or_panic(
        &[UPGRADE.as_bytes().to_vec()],
        &[first],
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[ws_text_frame(ringing.as_bytes(), None)],
    );
    let (mut messages, stderr) = decrypt_wss(&frames);
    // Compared as a set: this fixture writes every handshake record before
    // the client's INVITE, so the 100 riding in the 101's record is captured
    // first. The point is that it counts at all.
    let mut want = want;
    messages.sort();
    want.sort();
    assert_eq!(messages, want, "{stderr}");
    assert!(!stderr.contains("NOT DECODED"), "{stderr}");
}

/// An upgrade whose HTTP head never ends is counted, not lost in silence.
#[test]
fn an_upgrade_that_never_finishes_is_counted() {
    let (invite, _, _, _) = invite_trying_ringing();
    let key_at = SWITCHING.find("Sec-WebSocket-Accept: ").unwrap();
    let frames = wss_session_with_or_panic(
        &[UPGRADE.as_bytes().to_vec()],
        &[SWITCHING.as_bytes()[..key_at].to_vec()],
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[],
    );
    let (messages, stderr) = decrypt_wss(&frames);
    assert_eq!(
        messages,
        vec![("INVITE".to_string(), "WSS".to_string())],
        "{stderr}"
    );
    let not_decoded = stderr
        .lines()
        .find(|l| l.starts_with("NOT DECODED:"))
        .unwrap_or_else(|| panic!("the unfinished upgrade must be counted: {stderr}"));
    assert!(not_decoded.contains("truncated frame (1)"), "{not_decoded}");
}
