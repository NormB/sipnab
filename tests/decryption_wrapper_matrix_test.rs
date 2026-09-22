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

use tar_build::{Entry, gzip, tar};

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
        Wrapper::Gzip => (format!("{name}.gz"), gzip(capture)),
        Wrapper::TarMember => ("set.tar".to_string(), tar(&[Entry::file(&member, capture)])),
        Wrapper::TgzMember => (
            "set.tgz".to_string(),
            gzip(&tar(&[Entry::file(&member, capture)])),
        ),
        Wrapper::GzipInTgz => {
            let inner = gzip(capture);
            let member_gz = format!("{member}.gz");
            (
                "set.tgz".to_string(),
                gzip(&tar(&[Entry::file(&member_gz, &inner)])),
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

const CLIENT_RANDOM: [u8; 32] = [0x5a; 32];
const SERVER_RANDOM: [u8; 32] = [0xa5; 32];
const CLIENT_SECRET: [u8; 32] = [0x31; 32];
const SERVER_SECRET: [u8; 32] = [0x42; 32];
const TLS_CALL_ID: &str = "matrix-tls-1@test";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The keylog a TLS 1.3 stack would have written for this session.
fn tls_keylog() -> String {
    format!(
        "CLIENT_TRAFFIC_SECRET_0 {cr} {c}\nSERVER_TRAFFIC_SECRET_0 {cr} {s}\n",
        cr = hex(&CLIENT_RANDOM),
        c = hex(&CLIENT_SECRET),
        s = hex(&SERVER_SECRET)
    )
}

/// HKDF-Expand-Label (RFC 8446 section 7.1) with an empty context.
fn expand_label(secret: &[u8], label: &str, len: usize) -> Vec<u8> {
    struct Len(usize);
    impl ring::hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = ring::hkdf::Prk::new_less_safe(ring::hkdf::HKDF_SHA256, secret);
    let full = format!("tls13 {label}");
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let info_parts = [info.as_slice()];
    let okm = prk.expand(&info_parts, Len(len)).expect("expand");
    let mut out = vec![0u8; len];
    okm.fill(&mut out).expect("fill");
    out
}

/// One TLS 1.3 application-data record: `plaintext` sealed with AES-128-GCM
/// under the key and IV `secret` derives to, at record sequence `seq`.
fn tls13_record(secret: &[u8], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    use ring::aead;
    let key = expand_label(secret, "key", 16);
    let iv = expand_label(secret, "iv", 12);
    let mut inner = plaintext.to_vec();
    inner.push(23); // the real content type: application_data
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let ct_len = (inner.len() + aead::AES_128_GCM.tag_len()) as u16;
    let mut aad = vec![23u8, 0x03, 0x03];
    aad.extend_from_slice(&ct_len.to_be_bytes());
    let sealing =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).expect("key"));
    sealing
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut inner,
        )
        .expect("seal");
    let mut rec = aad;
    rec.extend_from_slice(&inner);
    rec
}

/// A TLS handshake record holding one handshake message.
fn tls_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = vec![msg_type];
    let len = body.len();
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(body);
    let mut rec = vec![22u8, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// A TLS 1.3 ClientHello and ServerHello for AES-128-GCM-SHA256.
fn tls13_hellos() -> (Vec<u8>, Vec<u8>) {
    let supported_versions_ch = [0x00u8, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04];
    let mut ch = vec![0x03, 0x03];
    ch.extend_from_slice(&CLIENT_RANDOM);
    ch.push(0); // session id
    ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    ch.extend_from_slice(&[0x01, 0x00]); // compression: null
    ch.extend_from_slice(&(supported_versions_ch.len() as u16).to_be_bytes());
    ch.extend_from_slice(&supported_versions_ch);

    let supported_versions_sh = [0x00u8, 0x2b, 0x00, 0x02, 0x03, 0x04];
    let mut sh = vec![0x03, 0x03];
    sh.extend_from_slice(&SERVER_RANDOM);
    sh.push(0);
    sh.extend_from_slice(&[0x13, 0x01]);
    sh.push(0);
    sh.extend_from_slice(&(supported_versions_sh.len() as u16).to_be_bytes());
    sh.extend_from_slice(&supported_versions_sh);
    (tls_handshake(1, &ch), tls_handshake(2, &sh))
}

/// SIP over TLS on 5061: the hellos in the clear, then an INVITE and its
/// answer as TLS 1.3 application data.
fn tls_session_frames() -> Vec<Vec<u8>> {
    let a = [10, 9, 0, 1];
    let b = [10, 9, 0, 2];
    let (client, server) = (40_111u16, 5061u16);
    let via = format!("Via: SIP/2.0/TLS 10.9.0.1:{client};branch=z9hG4bKmatrix1\r\n");
    let common = format!(
        "{via}From: <sips:alice@10.9.0.1>;tag=ma\r\nTo: <sips:bob@10.9.0.2>\r\n\
         Call-ID: {TLS_CALL_ID}\r\nCSeq: 1 INVITE\r\n"
    );
    let invite = format!(
        "INVITE sips:bob@10.9.0.2 SIP/2.0\r\n{common}Max-Forwards: 70\r\n\
         Contact: <sips:alice@10.9.0.1:{client}>\r\nContent-Length: 0\r\n\r\n"
    );
    let ringing = format!("SIP/2.0 180 Ringing\r\n{common}Content-Length: 0\r\n\r\n");
    let (ch, sh) = tls13_hellos();
    let c1 = tls13_record(&CLIENT_SECRET, 0, invite.as_bytes());
    let s1 = tls13_record(&SERVER_SECRET, 0, ringing.as_bytes());
    let mut cseq = 1000u32;
    let mut sseq = 5000u32;
    let mut frames = vec![
        pcap_build::tcp_frame(a, b, client, server, cseq, 0x02, b""),
        pcap_build::tcp_frame(b, a, server, client, sseq, 0x12, b""),
    ];
    cseq += 1;
    sseq += 1;
    for (from_client, payload) in [(true, &ch), (false, &sh), (true, &c1), (false, &s1)] {
        if from_client {
            frames.push(pcap_build::tcp_frame(
                a, b, client, server, cseq, 0x18, payload,
            ));
            cseq += payload.len() as u32;
        } else {
            frames.push(pcap_build::tcp_frame(
                b, a, server, client, sseq, 0x18, payload,
            ));
            sseq += payload.len() as u32;
        }
    }
    frames
}

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

fn classic_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let dir = tempfile::tempdir().expect("dir");
    let p = dir.path().join("c.pcap");
    pcap_build::write_pcap(&p, frames);
    std::fs::read(&p).expect("read")
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
        &classic_pcap(&tls_session_frames()),
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
    pcap_build::write_pcapng_with_dsb_frames(&p, &tls_keylog(), &tls_session_frames());
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

/// AES-128 in counter mode from `iv`, as RFC 3711 section 4.1.1 runs it.
fn aes_cm(key: &[u8], iv: [u8; 16], len: usize) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut out = Vec::with_capacity(len);
    let mut counter = u128::from_be_bytes(iv);
    while out.len() < len {
        let mut block = aes::Block::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// RFC 3711 section 4.3.1 key derivation with a key derivation rate of 0.
fn srtp_kdf(master_key: &[u8], master_salt: &[u8], label: u8, len: usize) -> Vec<u8> {
    let mut x = [0u8; 16];
    x[..14].copy_from_slice(master_salt);
    x[7] ^= label;
    aes_cm(master_key, x, len)
}

/// The RTP header fields one SRTP packet carries.
#[derive(Clone, Copy)]
struct RtpHead {
    ssrc: u32,
    seq: u16,
    ts: u32,
    pt: u8,
    marker: bool,
}

/// One SRTP packet: an RTP header and `payload`, encrypted and tagged under
/// the AES_CM_128_HMAC_SHA1_80 suite.
fn srtp_packet(master_key: &[u8], master_salt: &[u8], head: &RtpHead, payload: &[u8]) -> Vec<u8> {
    let RtpHead {
        ssrc,
        seq,
        ts,
        pt,
        marker,
    } = *head;
    let session_key = srtp_kdf(master_key, master_salt, 0x00, 16);
    let auth_key = srtp_kdf(master_key, master_salt, 0x01, 20);
    let session_salt = srtp_kdf(master_key, master_salt, 0x02, 14);
    let mut header = vec![0x80, pt | if marker { 0x80 } else { 0 }];
    header.extend_from_slice(&seq.to_be_bytes());
    header.extend_from_slice(&ts.to_be_bytes());
    header.extend_from_slice(&ssrc.to_be_bytes());
    // IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16), ROC 0.
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&session_salt);
    for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
        iv[4 + i] ^= b;
    }
    let index = u64::from(seq);
    for (i, b) in index.to_be_bytes()[2..].iter().enumerate() {
        iv[8 + i] ^= b;
    }
    let ks = aes_cm(&session_key, iv, payload.len());
    let mut packet = header;
    packet.extend(payload.iter().zip(&ks).map(|(p, k)| p ^ k));
    let mut authed = packet.clone();
    authed.extend_from_slice(&0u32.to_be_bytes()); // ROC
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &auth_key),
        &authed,
    );
    packet.extend_from_slice(&tag.as_ref()[..10]);
    packet
}

/// RFC 4733 telephone-event packets for `digits`: three packets per digit,
/// the last of them with the end bit, each digit its own event timestamp.
fn dtmf_srtp(master_key: &[u8], master_salt: &[u8], ssrc: u32, digits: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut seq = 100u16;
    for (n, digit) in digits.iter().enumerate() {
        let ts = 16_000 + n as u32 * 8_000;
        for (i, dur) in [160u16, 320, 480].iter().enumerate() {
            let end = i == 2;
            let payload = [
                *digit,
                if end { 0x80 | 10 } else { 10 },
                (dur >> 8) as u8,
                *dur as u8,
            ];
            out.push(srtp_packet(
                master_key,
                master_salt,
                &RtpHead {
                    ssrc,
                    seq,
                    ts,
                    pt: 101,
                    marker: i == 0,
                },
                &payload,
            ));
            seq += 1;
        }
    }
    out
}

const SRTP_KEY: [u8; 16] = [0x7c; 16];
const SRTP_SALT: [u8; 14] = [0x3e; 14];

fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A call whose SDP carries SDES keys, then DTMF "42" as SRTP from the caller.
fn sdes_call_frames() -> Vec<Vec<u8>> {
    let a = [10, 8, 0, 1];
    let b = [10, 8, 0, 2];
    let mut inline = SRTP_KEY.to_vec();
    inline.extend_from_slice(&SRTP_SALT);
    let crypto = format!(
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
        base64(&inline)
    );
    let sdp = |ip: &str, port: u16| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\n{crypto}"
        )
    };
    let head = "Via: SIP/2.0/UDP 10.8.0.1:5060;branch=z9hG4bKsdes1\r\n\
                From: <sip:alice@10.8.0.1>;tag=sa\r\nTo: <sip:bob@10.8.0.2>\r\n\
                Call-ID: matrix-sdes-1@test\r\nCSeq: 1 INVITE\r\n";
    let offer = sdp("10.8.0.1", 40_000);
    let answer = sdp("10.8.0.2", 50_000);
    let invite = format!(
        "INVITE sip:bob@10.8.0.2 SIP/2.0\r\n{head}Max-Forwards: 70\r\n\
         Contact: <sip:alice@10.8.0.1>\r\nContent-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{offer}",
        offer.len()
    );
    let ok = format!(
        "SIP/2.0 200 OK\r\n{head}Contact: <sip:bob@10.8.0.2>\r\n\
         Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{answer}",
        answer.len()
    );
    let mut frames = vec![
        pcap_build::udp_frame(a, b, 5060, 5060, invite.as_bytes()),
        pcap_build::udp_frame(b, a, 5060, 5060, ok.as_bytes()),
    ];
    for p in dtmf_srtp(&SRTP_KEY, &SRTP_SALT, 0x1234_5678, &[4, 2]) {
        frames.push(pcap_build::udp_frame(a, b, 40_000, 50_000, &p));
    }
    frames
}

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
        &classic_pcap(&sdes_call_frames()),
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
    for p in dtmf_srtp(client_key, client_salt, 0x0bad_cafe, &[4, 2]) {
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
        &classic_pcap(&dtls_srtp_frames()),
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
        &classic_pcap(&esp_null_call_frames()),
        &["--json"],
        "warn",
        &sip_messages,
        ESP_CALL_ID,
    );
}
