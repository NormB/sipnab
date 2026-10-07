// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--pcap-export-mode decrypted`, end to end.
//!
//! The mode used to exit 2 (RVW1, 3ada003c: before that it embedded TLS keys
//! while the docs promised plaintext). Approved 2026-09-29 (backlog
//! PCAPX-DEC): it writes what sipnab decrypted as plaintext -- SIP from TLS
//! and WSS as plain TCP frames, SRTP as plain RTP -- on the captured
//! addresses, ports and times, everything else as captured, and never any key
//! material. These run the real binary over captures built in code with their
//! keys (tests/support/encrypted_captures.rs), so every expected byte is
//! known, and read the exported file back.

#![cfg(all(feature = "native", feature = "tls"))]

use std::path::{Path, PathBuf};

#[path = "support/encrypted_captures.rs"]
mod encrypted_captures;
#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run_support;

use encrypted_captures::*;

/// One frame read back from an export: its bytes and its pcapng comments.
#[derive(Debug)]
struct Frame {
    data: Vec<u8>,
    comments: Vec<String>,
}

/// An export, read back: the section comment (pcapng) and every frame.
struct Export {
    section_comments: Vec<String>,
    frames: Vec<Frame>,
    dsb_blocks: usize,
    raw: Vec<u8>,
}

fn read_export(path: &Path) -> Export {
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
    use pcap_file::pcapng::blocks::section_header::SectionHeaderOption;
    let raw = std::fs::read(path).expect("the export exists");
    let mut out = Export {
        section_comments: Vec::new(),
        frames: Vec::new(),
        dsb_blocks: 0,
        raw: raw.clone(),
    };
    if raw.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        let mut reader = pcap_file::pcapng::PcapNgReader::new(&raw[..]).expect("pcapng");
        for opt in &reader.section().options {
            if let SectionHeaderOption::Comment(c) = opt {
                out.section_comments.push(c.to_string());
            }
        }
        while let Some(block) = reader.next_block() {
            match block.expect("a block") {
                pcap_file::pcapng::Block::EnhancedPacket(epb) => out.frames.push(Frame {
                    data: epb.data.to_vec(),
                    comments: epb
                        .options
                        .iter()
                        .filter_map(|o| match o {
                            EnhancedPacketOption::Comment(c) => Some(c.to_string()),
                            _ => None,
                        })
                        .collect(),
                }),
                pcap_file::pcapng::Block::Unknown(b) if b.type_ == 0x0000_000a => {
                    out.dsb_blocks += 1;
                }
                _ => {}
            }
        }
    } else {
        let mut reader = pcap_file::pcap::PcapReader::new(&raw[..]).expect("pcap");
        while let Some(p) = reader.next_packet() {
            out.frames.push(Frame {
                data: p.expect("a packet").data.to_vec(),
                comments: Vec::new(),
            });
        }
    }
    out
}

/// The transport payload of an Ethernet/IPv4 TCP or UDP frame, with its
/// protocol and ports.
fn l4(frame: &[u8]) -> Option<(u8, u16, u16, &[u8])> {
    if frame.len() < 34 || frame[12..14] != [0x08, 0x00] {
        return None;
    }
    let ihl = usize::from(frame[14] & 0x0f) * 4;
    let proto = frame[23];
    let t = 14 + ihl;
    let sport = u16::from_be_bytes([frame[t], frame[t + 1]]);
    let dport = u16::from_be_bytes([frame[t + 2], frame[t + 3]]);
    let start = match proto {
        6 => t + usize::from(frame[t + 12] >> 4) * 4,
        17 => t + 8,
        _ => return None,
    };
    Some((proto, sport, dport, &frame[start..]))
}

fn tcp_payloads(x: &Export) -> Vec<Vec<u8>> {
    x.frames
        .iter()
        .filter_map(|f| l4(&f.data))
        .filter(|(p, _, _, pl)| *p == 6 && !pl.is_empty())
        .map(|(_, _, _, pl)| pl.to_vec())
        .collect()
}

struct Run {
    export: Export,
    stderr: String,
    code: Option<i32>,
    _dir: tempfile::TempDir,
}

/// Run sipnab over `frames` (classic pcap) with `extra` flags and the
/// decrypted export to `out_name`.
fn export(frames: &[Vec<u8>], keylog: bool, out_name: &str, extra: &[&str]) -> Run {
    let dir = tempfile::tempdir().expect("dir");
    let input = dir.path().join("in.pcap");
    pcap_build::write_pcap_or_panic(&input, frames);
    let kl = dir.path().join("keys.log");
    std::fs::write(&kl, tls_keylog()).expect("keylog");
    let out: PathBuf = dir.path().join(out_name);
    let mut args: Vec<String> = ["--no-config", "-N", "-I"].map(String::from).to_vec();
    args.push(input.display().to_string());
    if keylog {
        args.extend(["--keylog".into(), kl.display().to_string()]);
    }
    if out_name.ends_with(".pcapng") {
        args.push("--pcapng".into());
    }
    args.extend(["-O".into(), out.display().to_string()]);
    args.extend(["--pcap-export-mode".into(), "decrypted".into()]);
    args.extend(extra.iter().map(|s| s.to_string()));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let (_, stderr, code) = run_support::run_or_panic(&argv, Some("warn"));
    let export = if out.exists() {
        read_export(&out)
    } else {
        panic!("no export written (exit {code:?}):\n{stderr}")
    };
    Run {
        export,
        stderr,
        code,
        _dir: dir,
    }
}

/// The INVITE and 180 of the TLS test call, as the session carries them.
fn tls_call_messages() -> (Vec<u8>, Vec<u8>) {
    let frames = tls_session_frames_or_panic();
    let _ = frames;
    let (client, _server) = (40_111u16, 5061u16);
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
    (invite.into_bytes(), ringing.into_bytes())
}

// ── The mode runs ────────────────────────────────────────────────────────

#[test]
fn the_decrypted_mode_runs_and_exits_zero() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
}

#[test]
fn a_capture_with_nothing_encrypted_is_exported_byte_for_byte() {
    let frames = vec![
        pcap_build::udp_frame(
            [10, 1, 0, 1],
            [10, 1, 0, 2],
            5060,
            5060,
            b"OPTIONS sip:a SIP/2.0\r\n\r\n",
        ),
        pcap_build::udp_frame(
            [10, 1, 0, 2],
            [10, 1, 0, 1],
            5060,
            5060,
            b"SIP/2.0 200 OK\r\n\r\n",
        ),
    ];
    let r = export(&frames, false, "out.pcap", &[]);
    let got: Vec<Vec<u8>> = r.export.frames.iter().map(|f| f.data.clone()).collect();
    assert_eq!(got, frames);
}

// ── TLS ──────────────────────────────────────────────────────────────────

#[test]
fn sip_over_tls_is_exported_as_the_plaintext_messages() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    let (invite, ringing) = tls_call_messages();
    let payloads = tcp_payloads(&r.export);
    assert_eq!(payloads, vec![invite, ringing], "{}", r.stderr);
}

#[test]
fn no_tls_record_of_a_decrypted_connection_is_left_in_the_export() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    for p in tcp_payloads(&r.export) {
        assert!(
            !(p.len() > 5 && (p[0] == 0x16 || p[0] == 0x17) && p[1] == 0x03),
            "a TLS record survived: {:02x?}",
            &p[..5]
        );
    }
}

#[test]
fn a_decrypted_export_holds_no_key_material() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    assert_eq!(r.export.dsb_blocks, 0, "no Decryption Secrets Block");
    for secret in [&CLIENT_SECRET[..], &SERVER_SECRET[..]] {
        assert!(
            !r.export.raw.windows(secret.len()).any(|w| w == secret),
            "a traffic secret's bytes are in the file"
        );
    }
    let keylog = tls_keylog();
    for line in keylog.lines() {
        let hex_secret = line.rsplit(' ').next().expect("a secret");
        assert!(
            !r.export
                .raw
                .windows(hex_secret.len())
                .any(|w| w == hex_secret.as_bytes()),
            "the keylog's text is in the file"
        );
    }
}

#[test]
fn the_export_reads_back_as_the_same_call_with_no_keys() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcap", &[]);
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("again.pcap");
    std::fs::write(&path, &r.export.raw).expect("write");
    let (stdout, stderr, code) = run_support::run_or_panic(
        &["--no-config", "-N", "-I", path.to_str().unwrap(), "--json"],
        Some("warn"),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.contains(TLS_CALL_ID),
        "the plaintext re-reads as the call:\n{stdout}"
    );
}

// ── SRTP ─────────────────────────────────────────────────────────────────

#[test]
fn srtp_is_exported_as_rtp_carrying_the_plaintext() {
    let frames = sdes_call_frames_or_panic();
    let r = export(&frames, false, "out.pcapng", &[]);
    let rtp: Vec<Vec<u8>> = r
        .export
        .frames
        .iter()
        .filter_map(|f| l4(&f.data))
        .filter(|(p, s, d, _)| *p == 17 && *s == 40_000 && *d == 50_000)
        .map(|(_, _, _, pl)| pl.to_vec())
        .collect();
    assert_eq!(rtp.len(), 6, "every DTMF packet: {}", r.stderr);
    for (i, pkt) in rtp.iter().enumerate() {
        assert_eq!(
            pkt.len(),
            12 + 4,
            "header and 4-byte event, no auth tag: {pkt:02x?}"
        );
        let digit = if i < 3 { 4 } else { 2 };
        let end = i % 3 == 2;
        assert_eq!(pkt[12], digit, "the event's digit, decrypted");
        assert_eq!(
            pkt[13],
            if end { 0x80 | 10 } else { 10 },
            "end bit and volume"
        );
    }
}

// ── WSS ──────────────────────────────────────────────────────────────────

#[test]
fn sip_over_wss_is_exported_as_plain_sip() {
    let (invite, ringing) = wss_messages();
    let frames = wss_session_or_panic(
        &[ws_text_frame(invite.as_bytes(), Some(WS_MASK))],
        &[ws_text_frame(ringing.as_bytes(), None)],
    );
    let r = export(&frames, true, "out.pcapng", &[]);
    let payloads = tcp_payloads(&r.export);
    assert_eq!(
        payloads,
        vec![invite.into_bytes(), ringing.into_bytes()],
        "SIP, with no WebSocket framing: {}",
        r.stderr
    );
    let comments: Vec<&String> = r.export.frames.iter().flat_map(|f| &f.comments).collect();
    assert!(
        comments
            .iter()
            .all(|c| c.as_str() == "sipnab: decrypted from WSS"),
        "{comments:?}"
    );
}

// ── What the file and the run say ───────────────────────────────────────

#[test]
fn the_pcapng_section_says_it_was_decrypted_and_holds_no_keys() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    let c = r.export.section_comments.join("\n");
    assert!(
        c.contains("decrypted by sipnab") && c.contains("no keys"),
        "{c:?}"
    );
}

#[test]
fn each_rebuilt_frame_names_what_it_was_decrypted_from() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    let rebuilt: Vec<&Frame> = r
        .export
        .frames
        .iter()
        .filter(|f| !f.comments.is_empty())
        .collect();
    assert_eq!(rebuilt.len(), 2);
    assert!(
        rebuilt
            .iter()
            .all(|f| f.comments == ["sipnab: decrypted from TLS"])
    );
}

#[test]
fn classic_pcap_works_too() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcap", &[]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    assert_eq!(tcp_payloads(&r.export).len(), 2);
}

#[test]
fn the_run_ends_with_the_export_counts() {
    let r = export(&tls_session_frames_or_panic(), true, "out.pcapng", &[]);
    assert!(
        r.stderr.contains("decrypted export: 2 SIP from TLS")
            && r.stderr.contains("captured segments replaced"),
        "{}",
        r.stderr
    );
}
