// SPDX-License-Identifier: MIT OR Apache-2.0

//! Disclosure gate for RFC 4733 telephone-event decoding: the digit VALUE must
//! not reach the log unless an operator asked for it, twice.
//!
//! A DTMF digit decoded after answer is not a diagnostic detail, it is the
//! caller's secret — voicemail PINs, calling-card numbers, account numbers and
//! card numbers are all keyed in as telephone-events, in the clear, however
//! well the signaling itself was protected. sipnab used to write those values
//! to the log at `info`, which is the widest surface it has: the terminal, a
//! redirected file, journald, and every aggregator that ships journald onward.
//!
//! These tests assert the EFFECT on real log output from a real run, not the
//! presence of a flag or a branch:
//!
//! * `-t` alone, even at the most permissive log level, must never emit the
//!   digit — and must still emit the event, or the absence proves nothing.
//! * `-t --dtmf-cleartext` at `debug` must emit it, or the opt-in is a lie.
//! * `-t --dtmf-cleartext` at `info` must still not emit it, which is what
//!   makes "cleartext lives one level below the default" a real second gate
//!   rather than a comment.
#![cfg(feature = "native")]

use std::path::PathBuf;

#[path = "support/pcap_build.rs"]
mod pcap_build;

#[path = "support/run.rs"]
mod run_support;

/// The RFC 4733 event code fed to every run here, and the character it decodes
/// to.
///
/// `7` is chosen so the assertion "the value never appears" can be made against
/// the whole log message rather than one quoted field: neither the duration
/// (`200ms`) nor the SSRC (`0xdeadbeef`) this fixture produces contains a `7`,
/// so a stray `7` anywhere in a `DTMF …` message is the leak itself.
const EVENT_CODE: u8 = 7;

/// The character [`EVENT_CODE`] decodes to — the value that must stay out of a
/// default log.
const DIGIT: char = '7';

/// SSRC of the synthetic telephone-event stream. All-hex-letters plus digits
/// that are not [`DIGIT`], for the reason given on [`EVENT_CODE`].
const SSRC: u32 = 0xdead_beef;

/// Telephone-event duration in RTP timestamp units: 1600 at 8 kHz = 200 ms,
/// again digit-free apart from `2` and `0`.
const DURATION_TS: u16 = 1600;

/// Signaling source, media source: 10.0.0.1. Media flows toward 10.0.0.2.
const CALLER: [u8; 4] = [10, 0, 0, 1];

/// Callee address; the SDP `c=` line and the RTP destination.
const CALLEE: [u8; 4] = [10, 0, 0, 2];

/// UDP port the synthetic SDP negotiates for audio.
const MEDIA_PORT: u16 = 40000;

/// RTP payload type the synthetic SDP negotiates for `telephone-event`.
const TE_PAYLOAD_TYPE: u8 = 101;

/// An INVITE whose SDP negotiates `telephone-event/8000` on
/// [`TE_PAYLOAD_TYPE`], so the RTP that follows is resolved from signaling
/// rather than guessed by the heuristic (the heuristic path deliberately does
/// no DTMF decode at all, which would make these tests vacuous).
fn invite_with_telephone_event_sdp() -> Vec<u8> {
    let sdp = format!(
        "v=0\r\n\
         o=- 1 1 IN IP4 10.0.0.2\r\n\
         s=-\r\n\
         c=IN IP4 10.0.0.2\r\n\
         t=0 0\r\n\
         m=audio {MEDIA_PORT} RTP/AVP {TE_PAYLOAD_TYPE}\r\n\
         a=rtpmap:{TE_PAYLOAD_TYPE} telephone-event/8000\r\n"
    );
    let msg = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-dtmf-mask\r\n\
         From: Alice <sip:alice@example.com>;tag=a1b2\r\n\
         To: Bob <sip:bob@example.com>\r\n\
         Call-ID: dtmf-mask-gate@example.com\r\n\
         CSeq: 1 INVITE\r\n\
         Max-Forwards: 70\r\n\
         Contact: <sip:alice@10.0.0.1:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {sdp}",
        sdp.len()
    );
    msg.into_bytes()
}

/// One RTP packet carrying a COMPLETED telephone-event (End bit set) for
/// [`EVENT_CODE`]; only completed events are reported, so the End bit is what
/// makes this packet produce a log line at all.
fn rtp_telephone_event() -> Vec<u8> {
    let mut rtp: Vec<u8> = vec![
        0x80,                   // V=2, no padding/extension, 0 CSRC
        TE_PAYLOAD_TYPE & 0x7F, // marker=0 + payload type
        0x00,
        0x01, // sequence number
        0x00,
        0x00,
        0x00,
        0x00, // RTP timestamp
    ];
    rtp.extend_from_slice(&SSRC.to_be_bytes());
    rtp.push(EVENT_CODE);
    rtp.push(0x80); // E bit set, volume 0
    rtp.extend_from_slice(&DURATION_TS.to_be_bytes());
    rtp
}

/// Write the two-packet capture (SDP offer, then the completed telephone-event)
/// into a fresh temp directory and return its path.
///
/// # Side effects
/// Creates a directory under the system temp dir; the caller keeps the
/// [`tempfile::TempDir`] alive for the run's duration.
fn dtmf_capture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("telephone-event.pcap");
    let frames = vec![
        pcap_build::udp_frame(
            CALLER,
            CALLEE,
            5060,
            5060,
            &invite_with_telephone_event_sdp(),
        ),
        pcap_build::udp_frame(CALLER, CALLEE, 40001, MEDIA_PORT, &rtp_telephone_event()),
    ];
    pcap_build::write_pcap(&path, &frames);
    (dir, path)
}

/// Run sipnab over the synthetic capture and return `(stdout, stderr)`.
///
/// Both streams are returned because both are places a digit could surface:
/// the tracing subscriber writes to stderr, and per-message / report output
/// goes to stdout.
///
/// # Arguments
/// * `extra` — arguments appended after `-N -I <capture> -t`.
/// * `level` — the `SIPNAB_LOG` level for the run.
///
/// # Side effects
/// Spawns the compiled binary once.
fn dtmf_run(extra: &[&str], level: &str) -> (String, String) {
    let (_dir, path) = dtmf_capture();
    let capture = path.to_string_lossy().into_owned();
    let mut args = vec!["-N", "-I", capture.as_str(), "-t"];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = run_support::run(&args, Some(level));
    assert_eq!(code, Some(0), "sipnab exited {code:?}\nstderr:\n{stderr}");
    (stdout, stderr)
}

/// Every log message from `DTMF` onward, one per line that carries one.
///
/// The slice starts at `DTMF` on purpose: the subscriber prefixes each line
/// with a timestamp and target, and a timestamp contains arbitrary digits. An
/// assertion made against the whole line would fail (or pass) for reasons that
/// have nothing to do with the message sipnab wrote.
fn dtmf_messages(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|line| line.find("DTMF").map(|i| &line[i..]))
        .collect()
}

/// With `-t` alone, the decoded digit VALUE appears nowhere in the log, at any
/// level, while the event itself is still reported.
///
/// Run at `debug` deliberately: `debug` is the most permissive level sipnab
/// emits at, so if the value is absent here it is absent everywhere. Asserting
/// absence at a level that suppresses the line would prove nothing.
#[test]
fn the_decoded_digit_value_is_masked_out_of_the_log_by_default() {
    let (stdout, stderr) = dtmf_run(&[], "debug");
    let messages = dtmf_messages(&stderr);

    // stdout too, in its one plausible spelling. The log is the surface this
    // ticket is about, but a future change that pipes the digit into
    // per-message output or a report would be the same disclosure through a
    // different pipe, and it would arrive formatted the way the log line
    // formats it. Not a full audit of stdout — a `7` cannot be searched for
    // there, since Max-Forwards and Content-Length are full of digits.
    assert!(
        !stdout.contains(&format!("digit='{DIGIT}'")),
        "the decoded digit value reached stdout without --dtmf-cleartext"
    );

    // Guard against a vacuous pass: if no event decoded, "the digit is absent"
    // is true for the wrong reason and this gate would never fail.
    assert!(
        !messages.is_empty(),
        "no DTMF event was decoded, so the absence of the digit proves \
         nothing — the fixture or the decode path has drifted\nstderr:\n{stderr}"
    );

    for msg in &messages {
        assert!(
            !msg.contains(DIGIT),
            "the decoded digit value reached the log without --dtmf-cleartext: \
             {msg:?}"
        );
    }
    assert!(
        messages.iter().any(|m| m.contains("digit='x'")),
        "the masked event line is missing — the diagnostic must survive \
         masking, not be dropped by it\nDTMF messages: {messages:?}"
    );
}

/// `--dtmf-cleartext` at `debug` does emit the value, so the opt-in is real.
///
/// Paired with the default-masked test above, this is what proves masking is a
/// policy and not simply a broken decoder.
#[test]
fn dtmf_cleartext_emits_the_digit_value_at_debug_level() {
    let (_stdout, stderr) = dtmf_run(&["--dtmf-cleartext"], "debug");
    let messages = dtmf_messages(&stderr);
    assert!(
        messages
            .iter()
            .any(|m| m.contains(&format!("digit='{DIGIT}'"))),
        "--dtmf-cleartext did not disclose the digit at debug level, so the \
         opt-in does nothing\nDTMF messages: {messages:?}"
    );
}

/// Even with `--dtmf-cleartext`, a default-level (`info`) log carries no value.
///
/// This is the second of the two independent acts the design requires: passing
/// the flag is not enough, the operator must also raise the log level. Without
/// this test the choice of `debug` for the cleartext line is an unverified
/// comment.
#[test]
fn dtmf_cleartext_stays_below_the_default_log_level() {
    let (_stdout, stderr) = dtmf_run(&["--dtmf-cleartext"], "info");
    let messages = dtmf_messages(&stderr);
    assert!(
        !messages.is_empty(),
        "no DTMF event was reported at info level — the masked line must \
         still be emitted with the flag on\nstderr:\n{stderr}"
    );
    for msg in &messages {
        assert!(
            !msg.contains(DIGIT),
            "--dtmf-cleartext leaked the digit into a default-level log, so \
             raising SIPNAB_LOG is not the second gate it is documented to \
             be: {msg:?}"
        );
    }
}
