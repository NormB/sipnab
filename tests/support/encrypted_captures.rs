// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted captures built in code, with the keys that open them: SIP over
//! TLS 1.3 (with its keylog), SRTP keyed by SDES, and SIP over secure
//! WebSocket. Every byte is known, so a test can compare what sipnab decrypted
//! or exported against the exact plaintext that went in.
//!
//! Shared by `decryption_wrapper_matrix_test` and `decrypted_export_test`; the
//! including test must also declare `mod pcap_build` (support/pcap_build.rs).

#![allow(dead_code)]

/// The error a fallible helper here returns: any error, boxed, so `?` works
/// on I/O and crypto errors alike.
pub type TestError = Box<dyn std::error::Error>;

pub const CLIENT_RANDOM: [u8; 32] = [0x5a; 32];
pub const SERVER_RANDOM: [u8; 32] = [0xa5; 32];
pub const CLIENT_SECRET: [u8; 32] = [0x31; 32];
pub const SERVER_SECRET: [u8; 32] = [0x42; 32];
pub const TLS_CALL_ID: &str = "matrix-tls-1@test";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The keylog a TLS 1.3 stack would have written for this session.
pub fn tls_keylog() -> String {
    format!(
        "CLIENT_TRAFFIC_SECRET_0 {cr} {c}\nSERVER_TRAFFIC_SECRET_0 {cr} {s}\n",
        cr = hex(&CLIENT_RANDOM),
        c = hex(&CLIENT_SECRET),
        s = hex(&SERVER_SECRET)
    )
}

/// HKDF-Expand-Label (RFC 8446 section 7.1) with an empty context.
pub fn expand_label(secret: &[u8], label: &str, len: usize) -> Result<Vec<u8>, TestError> {
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
    let okm = prk
        .expand(&info_parts, Len(len))
        .map_err(|_| "HKDF expand")?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out).map_err(|_| "HKDF fill")?;
    Ok(out)
}

/// One TLS 1.3 application-data record: `plaintext` sealed with AES-128-GCM
/// under the key and IV `secret` derives to, at record sequence `seq`.
pub fn tls13_record(secret: &[u8], seq: u64, plaintext: &[u8]) -> Result<Vec<u8>, TestError> {
    use ring::aead;
    let key = expand_label(secret, "key", 16)?;
    let iv = expand_label(secret, "iv", 12)?;
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
    let sealing = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &key).map_err(|_| "AES-128-GCM key")?,
    );
    sealing
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&aad),
            &mut inner,
        )
        .map_err(|_| "AES-128-GCM seal")?;
    let mut rec = aad;
    rec.extend_from_slice(&inner);
    Ok(rec)
}

/// A TLS handshake record holding one handshake message.
pub fn tls_handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
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
pub fn tls13_hellos() -> (Vec<u8>, Vec<u8>) {
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
pub fn tls_session_frames() -> Result<Vec<Vec<u8>>, TestError> {
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
    let c1 = tls13_record(&CLIENT_SECRET, 0, invite.as_bytes())?;
    let s1 = tls13_record(&SERVER_SECRET, 0, ringing.as_bytes())?;
    let mut cseq = 1000u32;
    let mut sseq = 5000u32;
    let mut frames = vec![
        super::pcap_build::tcp_frame(a, b, client, server, cseq, 0x02, b""),
        super::pcap_build::tcp_frame(b, a, server, client, sseq, 0x12, b""),
    ];
    cseq += 1;
    sseq += 1;
    for (from_client, payload) in [(true, &ch), (false, &sh), (true, &c1), (false, &s1)] {
        if from_client {
            frames.push(super::pcap_build::tcp_frame(
                a, b, client, server, cseq, 0x18, payload,
            ));
            cseq += payload.len() as u32;
        } else {
            frames.push(super::pcap_build::tcp_frame(
                b, a, server, client, sseq, 0x18, payload,
            ));
            sseq += payload.len() as u32;
        }
    }
    Ok(frames)
}

pub fn classic_pcap(frames: &[Vec<u8>]) -> std::io::Result<Vec<u8>> {
    let dir = tempfile::tempdir()?;
    let p = dir.path().join("c.pcap");
    super::pcap_build::write_pcap(&p, frames)?;
    std::fs::read(&p)
}

/// AES-128 in counter mode from `iv`, as RFC 3711 section 4.1.1 runs it.
pub fn aes_cm(key: &[u8], iv: [u8; 16], len: usize) -> Result<Vec<u8>, TestError> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).map_err(|_| "AES-128 key length")?;
    let mut out = Vec::with_capacity(len);
    let mut counter = u128::from_be_bytes(iv);
    while out.len() < len {
        let mut block = aes::Block::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(block.as_slice());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

/// RFC 3711 section 4.3.1 key derivation with a key derivation rate of 0.
pub fn srtp_kdf(
    master_key: &[u8],
    master_salt: &[u8],
    label: u8,
    len: usize,
) -> Result<Vec<u8>, TestError> {
    let mut x = [0u8; 16];
    x[..14].copy_from_slice(master_salt);
    x[7] ^= label;
    aes_cm(master_key, x, len)
}

/// The RTP header fields one SRTP packet carries.
#[derive(Clone, Copy)]
pub struct RtpHead {
    pub ssrc: u32,
    pub seq: u16,
    pub ts: u32,
    pub pt: u8,
    pub marker: bool,
}

/// One SRTP packet: an RTP header and `payload`, encrypted and tagged under
/// the AES_CM_128_HMAC_SHA1_80 suite.
pub fn srtp_packet(
    master_key: &[u8],
    master_salt: &[u8],
    head: &RtpHead,
    payload: &[u8],
) -> Result<Vec<u8>, TestError> {
    let RtpHead {
        ssrc,
        seq,
        ts,
        pt,
        marker,
    } = *head;
    let session_key = srtp_kdf(master_key, master_salt, 0x00, 16)?;
    let auth_key = srtp_kdf(master_key, master_salt, 0x01, 20)?;
    let session_salt = srtp_kdf(master_key, master_salt, 0x02, 14)?;
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
    let ks = aes_cm(&session_key, iv, payload.len())?;
    let mut packet = header;
    packet.extend(payload.iter().zip(&ks).map(|(p, k)| p ^ k));
    let mut authed = packet.clone();
    authed.extend_from_slice(&0u32.to_be_bytes()); // ROC
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &auth_key),
        &authed,
    );
    packet.extend_from_slice(&tag.as_ref()[..10]);
    Ok(packet)
}

/// RFC 4733 telephone-event packets for `digits`: three packets per digit,
/// the last of them with the end bit, each digit its own event timestamp.
pub fn dtmf_srtp(
    master_key: &[u8],
    master_salt: &[u8],
    ssrc: u32,
    digits: &[u8],
) -> Result<Vec<Vec<u8>>, TestError> {
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
            )?);
            seq += 1;
        }
    }
    Ok(out)
}

pub const SRTP_KEY: [u8; 16] = [0x7c; 16];
pub const SRTP_SALT: [u8; 14] = [0x3e; 14];

pub fn base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A call whose SDP carries SDES keys, then DTMF "42" as SRTP from the caller.
pub fn sdes_call_frames() -> Result<Vec<Vec<u8>>, TestError> {
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
        super::pcap_build::udp_frame(a, b, 5060, 5060, invite.as_bytes()),
        super::pcap_build::udp_frame(b, a, 5060, 5060, ok.as_bytes()),
    ];
    for p in dtmf_srtp(&SRTP_KEY, &SRTP_SALT, 0x1234_5678, &[4, 2])? {
        frames.push(super::pcap_build::udp_frame(a, b, 40_000, 50_000, &p));
    }
    Ok(frames)
}

pub const WSS_CALL_ID: &str = "wss-decrypt-1@test";

/// A WebSocket text frame (RFC 6455 section 5.2) carrying `payload`, masked
/// with `key` when the client sends it, as section 5.3 requires.
pub fn ws_text_frame(payload: &[u8], key: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0x81u8]; // FIN + text
    let mask_bit = if key.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(mask_bit | n as u8),
        n => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    match key {
        Some(k) => {
            out.extend_from_slice(&k);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// The INVITE and 180 of one call over WSS.
pub fn wss_messages() -> (String, String) {
    let common = format!(
        "Via: SIP/2.0/WSS df7jal23ls0d.invalid;branch=z9hG4bKwss1\r\n\
         From: <sip:alice@10.9.1.1>;tag=wa\r\nTo: <sip:bob@10.9.1.2>\r\n\
         Call-ID: {WSS_CALL_ID}\r\nCSeq: 1 INVITE\r\n"
    );
    let invite = format!(
        "INVITE sip:bob@10.9.1.2 SIP/2.0\r\n{common}Max-Forwards: 70\r\n\
         Contact: <sip:alice@df7jal23ls0d.invalid;transport=ws>\r\nContent-Length: 0\r\n\r\n"
    );
    let ringing = format!("SIP/2.0 180 Ringing\r\n{common}Content-Length: 0\r\n\r\n");
    (invite, ringing)
}

/// The client's masking key for every frame it sends in these fixtures.
pub const WS_MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// A TLS 1.3 session on 7443, the port the lab's OpenSIPS used, which is not
/// in sipnab's default WebSocket port set: the hellos in the clear, the HTTP
/// upgrade and its 101 as application data, then each direction's further
/// decrypted records in order, one TLS record each.
pub fn wss_session(
    client_records: &[Vec<u8>],
    server_records: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, TestError> {
    wss_session_with(
        &[UPGRADE.as_bytes().to_vec()],
        &[SWITCHING.as_bytes().to_vec()],
        client_records,
        server_records,
    )
}

/// The client's HTTP upgrade request ([RFC 6455 section 4.1](https://www.rfc-editor.org/rfc/rfc6455#section-4.1)).
pub const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: 10.9.1.2:7443\r\nUpgrade: websocket\r\n\
                       Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                       Sec-WebSocket-Protocol: sip\r\nSec-WebSocket-Version: 13\r\n\r\n";

/// The server's `101 Switching Protocols` answer.
pub const SWITCHING: &str = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Protocol: sip\r\n\
                         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

/// [`wss_session`] with each side's handshake given as the TLS records it
/// is written in, so a test can split it the way a server does.
pub fn wss_session_with(
    client_head: &[Vec<u8>],
    server_head: &[Vec<u8>],
    client_records: &[Vec<u8>],
    server_records: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, TestError> {
    let a = [10, 9, 1, 1];
    let b = [10, 9, 1, 2];
    let (client, server) = (40_211u16, 7443u16);
    let (ch, sh) = tls13_hellos();
    let mut sends: Vec<(bool, Vec<u8>)> = vec![(true, ch), (false, sh)];
    let mut cseq_n = 0u64;
    let mut sseq_n = 0u64;
    for r in client_head {
        sends.push((true, tls13_record(&CLIENT_SECRET, cseq_n, r)?));
        cseq_n += 1;
    }
    for r in server_head {
        sends.push((false, tls13_record(&SERVER_SECRET, sseq_n, r)?));
        sseq_n += 1;
    }
    // Client records first, then server records: a request, then its answer.
    for r in client_records {
        sends.push((true, tls13_record(&CLIENT_SECRET, cseq_n, r)?));
        cseq_n += 1;
    }
    for r in server_records {
        sends.push((false, tls13_record(&SERVER_SECRET, sseq_n, r)?));
        sseq_n += 1;
    }
    let mut cseq = 1000u32;
    let mut sseq = 5000u32;
    let mut frames = vec![
        super::pcap_build::tcp_frame(a, b, client, server, cseq, 0x02, b""),
        super::pcap_build::tcp_frame(b, a, server, client, sseq, 0x12, b""),
    ];
    cseq += 1;
    sseq += 1;
    for (from_client, payload) in sends {
        if from_client {
            frames.push(super::pcap_build::tcp_frame(
                a, b, client, server, cseq, 0x18, &payload,
            ));
            cseq += payload.len() as u32;
        } else {
            frames.push(super::pcap_build::tcp_frame(
                b, a, server, client, sseq, 0x18, &payload,
            ));
            sseq += payload.len() as u32;
        }
    }
    Ok(frames)
}

/// A WebSocket frame with an explicit FIN bit and opcode.
pub fn ws_frame_raw(fin: bool, opcode: u8, payload: &[u8], key: Option<[u8; 4]>) -> Vec<u8> {
    let mut f = ws_text_frame(payload, key);
    f[0] = if fin { 0x80 } else { 0 } | opcode;
    f
}
