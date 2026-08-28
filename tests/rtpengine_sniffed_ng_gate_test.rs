// SPDX-License-Identifier: MIT OR Apache-2.0

//! VAL8: sniffed rtpengine `ng` is unauthenticated input and must not be
//! read as if it were addressed to sipnab.
//!
//! # What was wrong
//!
//! sipnab reads rtpengine's mirrored control plane two ways. One is
//! DELIVERED — `--hep-listen`, a socket the operator bound, which
//! `--hep-allow` and `--hep-auth` can guard. The other is SNIFFED: a HEP
//! datagram seen on the wire on its way to somebody else's collector.
//!
//! The sniffed arm had no gate of any kind. Any UDP datagram, from any
//! source, to any port, whose payload decoded as `ng` was believed — and
//! believing it means taking a Call-ID verbatim out of the correlation-id
//! chunk and binding media at an address out of the SDP. Anything able to put
//! a datagram on the captured segment could therefore name a call and point
//! it at a socket of its choosing. `--hep-allow` did not apply; it governs
//! the listener only. Meanwhile `docs/rtpengine.md` told operators a
//! `media-relay` assertion was "authoritative about the port".
//!
//! # What the tests assert
//!
//! Effects on real bytes, end to end: a crafted datagram is written into a
//! pcap and the shipped binary is run over it, so the assertion is about what
//! a report says, not about what a predicate returns.
//!
//! The positive control comes FIRST. A rejection test proves nothing if the
//! crafted packet was malformed and never arrived, so the same bytes are
//! shown being believed on the HEP port before any test claims they are
//! refused elsewhere.
//!
//! # What this does NOT claim
//!
//! The port gate is not authentication and nothing here says it is. A
//! datagram sent to the HEP port from anywhere is still believed — asserted
//! below, deliberately, so the residual is pinned rather than forgotten. The
//! authenticated path is `--hep-listen` with `--hep-auth --hep-auth-mode
//! hmac`.

#![cfg(all(feature = "native", feature = "hep"))]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{udp_frame, write_pcap};

/// The Call-ID a crafted datagram tries to introduce.
const FORGED_CALL_ID: &str = "ATTACKER-CHOSEN-CALLID";
/// The Call-ID a legitimate mirror introduces.
const HONEST_CALL_ID: &str = "km-honest-mirror@sipnab";
/// The media socket both of them name.
const MEDIA_IP: [u8; 4] = [10, 0, 0, 40];
const MEDIA_PORT: u16 = 38664;
/// The far end of that media.
const PARTY_IP: [u8; 4] = [10, 0, 0, 60];
const PARTY_PORT: u16 = 40002;
/// The HEP port, the only destination a sniffed mirror is believed on.
const HEP_PORT: u16 = 9060;
/// A port a collector might plausibly be on, and which is not the HEP port.
const OFF_PORT: u16 = 12345;
/// The relay's own address, as the source of a legitimate mirror.
const RELAY_IP: [u8; 4] = [10, 0, 0, 40];
/// The collector the relay reports to.
const COLLECTOR_IP: [u8; 4] = [10, 0, 0, 60];
/// An address with no relationship to anything in the capture.
const ATTACKER_IP: [u8; 4] = [192, 168, 66, 66];
/// The address the attacker addresses its datagram to.
const ATTACKER_DST_IP: [u8; 4] = [192, 168, 77, 77];

// ── Crafting the bytes ───────────────────────────────────────────────

/// One HEP v3 chunk, vendor 0.
fn chunk(out: &mut Vec<u8>, chunk_type: u16, data: &[u8]) {
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&chunk_type.to_be_bytes());
    out.extend_from_slice(&((6 + data.len()) as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// An rtpengine `ng` REPLY: no `call-id` of its own, so the correlation-id
/// chunk is the only thing that can name the call. Shaped exactly like the
/// live reply in `tests/fixtures/rtpengine-ng-hep.pcap`.
fn ng_reply(media_ip: [u8; 4], media_port: u16) -> Vec<u8> {
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {a}.{b}.{c}.{d}\r\ns=-\r\nc=IN IP4 {a}.{b}.{c}.{d}\r\nt=0 0\r\n\
         m=audio {media_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        a = media_ip[0],
        b = media_ip[1],
        c = media_ip[2],
        d = media_ip[3],
    );
    format!("cookie1 d3:sdp{}:{sdp}6:result2:oke", sdp.len()).into_bytes()
}

/// A HEP v3 datagram carrying a mirrored `ng` message under rtpengine's own
/// capture protocol (0x3d), with `call_id` in the correlation-id chunk.
fn hep_ng(call_id: &str, media_ip: [u8; 4], media_port: u16) -> Vec<u8> {
    let payload = ng_reply(media_ip, media_port);
    let mut body = Vec::new();
    chunk(&mut body, 0x0001, &[2]); // IPv4
    chunk(&mut body, 0x0002, &[17]); // UDP
    chunk(&mut body, 0x0003, &[127, 0, 0, 1]); // the relay's ng socket
    chunk(&mut body, 0x0004, &[127, 0, 0, 1]);
    chunk(&mut body, 0x0007, &43734u16.to_be_bytes());
    chunk(&mut body, 0x0008, &2223u16.to_be_bytes());
    chunk(&mut body, 0x0009, &1_700_000_000u32.to_be_bytes());
    chunk(&mut body, 0x000a, &0u32.to_be_bytes());
    chunk(&mut body, 0x000b, &[0x3d]); // rtpengine's ng capture protocol
    chunk(&mut body, 0x000c, &2001u32.to_be_bytes());
    chunk(&mut body, 0x0011, call_id.as_bytes());
    chunk(&mut body, 0x000f, &payload);

    let mut pkt = Vec::with_capacity(6 + body.len());
    pkt.extend_from_slice(b"HEP3");
    pkt.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

/// Twenty RTP packets each way on the socket the control plane names, so
/// there is real media for an assertion to be about.
fn media_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for seq in 0u16..20 {
        for (src, sport, dst, dport, ssrc) in [
            (PARTY_IP, PARTY_PORT, MEDIA_IP, MEDIA_PORT, 0x1111_2222u32),
            (MEDIA_IP, MEDIA_PORT, PARTY_IP, PARTY_PORT, 0x3333_4444u32),
        ] {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&seq.to_be_bytes());
            rtp.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            rtp.extend_from_slice(&ssrc.to_be_bytes());
            rtp.extend_from_slice(&[0xff; 160]);
            frames.push(udp_frame(src, dst, sport, dport, &rtp));
        }
    }
    frames
}

/// Write a capture into a fresh temp directory and return its path plus the
/// directory guard that deletes it.
fn capture(name: &str, frames: &[Vec<u8>]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);
    write_pcap(&path, frames);
    (dir, path)
}

/// Run sipnab over `path` and return `(stdout, stderr)`.
fn run(path: &Path, extra: &[&str]) -> (String, String) {
    let mut args: Vec<String> = vec![
        "-N".into(),
        "-I".into(),
        path.to_string_lossy().into_owned(),
        "--no-cli-print".into(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(&args)
        .env("SIPNAB_LOG", "warn")
        .output()
        .expect("run sipnab");
    assert!(
        out.status.success(),
        "sipnab exited {:?}; stderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ── The positive control, first ──────────────────────────────────────

/// A sniffed mirror on the HEP port is believed, and names the call.
///
/// This is the arrival proof the rest of the file rests on. Every rejection
/// below uses these same crafted bytes with only the destination port
/// changed, so if this passes, a datagram that is later refused was refused
/// for the reason under test rather than because it was malformed, was
/// dropped by the reader, or never reached the classifier.
///
/// It is also a no-regression guard: the sniffed path is the whole reason
/// this feature exists on a standalone relay, and a gate that closed it
/// entirely would be worse than the hole it replaced.
#[test]
fn a_sniffed_mirror_on_the_hep_port_is_believed_and_names_the_call() {
    let mut frames = vec![udp_frame(
        RELAY_IP,
        COLLECTOR_IP,
        59652,
        HEP_PORT,
        &hep_ng(HONEST_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    frames.extend(media_frames());
    let (_dir, path) = capture("mirror-on-hep-port.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        stdout.contains(HONEST_CALL_ID),
        "a mirror on the HEP port must still name its call; report was:\n{stdout}"
    );
    assert!(
        !stdout.contains("Orphaned Streams"),
        "and the media it named must stop being orphaned; report was:\n{stdout}"
    );
}

// ── The gate ─────────────────────────────────────────────────────────

/// The same bytes, addressed to a port that is not the HEP port, name
/// nothing.
///
/// Byte-for-byte the datagram from the control above; only the UDP
/// destination port differs. Both halves are asserted — the Call-ID is
/// absent AND the media is back to being orphaned — because a report that
/// merely omitted the string could still have applied the binding.
#[test]
fn a_sniffed_ng_datagram_on_an_unexpected_port_names_no_call() {
    let mut frames = vec![udp_frame(
        RELAY_IP,
        COLLECTOR_IP,
        59652,
        OFF_PORT,
        &hep_ng(HONEST_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    frames.extend(media_frames());
    let (_dir, path) = capture("mirror-off-port.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        !stdout.contains(HONEST_CALL_ID),
        "a mirror on UDP/{OFF_PORT} must not name a call; report was:\n{stdout}"
    );
    assert!(
        stdout.contains("Orphaned Streams"),
        "and its media must stay orphaned; report was:\n{stdout}"
    );
}

/// A Call-ID the attacker chose, in the correlation-id chunk, from an
/// unrelated source, to an unrelated address and port: exactly the reported
/// attack, and it names nothing.
///
/// The correlation-id chunk is the sharp end of this. An `ng` REPLY carries
/// no `call-id` of its own — see `src/rtpengine/ng.rs` — so that chunk is the
/// ONLY thing naming the call, and it is copied verbatim out of a datagram
/// nothing authenticated.
#[test]
fn an_attacker_chosen_call_id_from_an_arbitrary_source_names_nothing() {
    let mut frames = vec![udp_frame(
        ATTACKER_IP,
        ATTACKER_DST_IP,
        1111,
        OFF_PORT,
        &hep_ng(FORGED_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    frames.extend(media_frames());
    let (_dir, path) = capture("attacker-callid.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        !stdout.contains(FORGED_CALL_ID),
        "an attacker-chosen Call-ID must not name a call anywhere in the \
         report:\n{stdout}"
    );
    assert!(
        stdout.contains("Orphaned Streams"),
        "the media it tried to claim must stay orphaned:\n{stdout}"
    );

    // The same claim on the JSON door, which is what a machine consumer
    // reads. A key absent from the report but present in --json would be the
    // same bug wearing a different hat.
    let (json, _) = run(&path, &["--json"]);
    assert!(
        !json.contains(FORGED_CALL_ID),
        "nor may it surface on --json:\n{json}"
    );
}

/// A refused datagram cannot overwrite an attribution that was believed.
///
/// The one that matters most in practice: the relay's own mirror names the
/// media, and a crafted datagram then tries to rename the SAME socket to a
/// call of the attacker's choosing. The honest name must survive and the
/// forged one must never appear.
#[test]
fn a_refused_datagram_does_not_alter_an_attribution_already_made() {
    let mut frames = vec![
        udp_frame(
            RELAY_IP,
            COLLECTOR_IP,
            59652,
            HEP_PORT,
            &hep_ng(HONEST_CALL_ID, MEDIA_IP, MEDIA_PORT),
        ),
        udp_frame(
            ATTACKER_IP,
            ATTACKER_DST_IP,
            1111,
            OFF_PORT,
            &hep_ng(FORGED_CALL_ID, MEDIA_IP, MEDIA_PORT),
        ),
    ];
    frames.extend(media_frames());
    let (_dir, path) = capture("overwrite-attempt.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        stdout.contains(HONEST_CALL_ID),
        "the relay's own name must survive:\n{stdout}"
    );
    assert!(
        !stdout.contains(FORGED_CALL_ID),
        "and the forged one must never appear:\n{stdout}"
    );
}

/// The refusal is ANNOUNCED, not silent.
///
/// A gate that drops traffic without saying so produces the worst symptom in
/// this codebase's catalog: a collector that receives nothing, which an
/// operator attributes to routing, to a firewall, to a dead relay — anything
/// but a rule inside sipnab. The line names the port it refused and the
/// authenticated path to use instead.
#[test]
fn the_refusal_names_the_port_and_the_alternative() {
    let mut frames = vec![udp_frame(
        RELAY_IP,
        COLLECTOR_IP,
        59652,
        OFF_PORT,
        &hep_ng(HONEST_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    frames.extend(media_frames());
    let (_dir, path) = capture("refusal-is-announced.pcap", &frames);
    let (_, stderr) = run(&path, &["--report"]);

    assert!(
        stderr.contains(&OFF_PORT.to_string()),
        "the warning must name the port it refused; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("--hep-listen"),
        "and point at the path that can actually authenticate a sender; \
         stderr was:\n{stderr}"
    );
}

/// A refused control datagram is still control traffic, not media.
///
/// It is consumed rather than handed on to the RTP classifier. Letting it
/// fall through would trade one bug for another: a crafted datagram shaped to
/// pass the RTP pre-filter would become a phantom stream, which is the
/// failure the LLMNR arm above it in the pipeline exists to prevent.
#[test]
fn a_refused_ng_datagram_is_not_reconsidered_as_media() {
    let frames = vec![udp_frame(
        ATTACKER_IP,
        ATTACKER_DST_IP,
        1111,
        OFF_PORT,
        &hep_ng(FORGED_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    let (_dir, path) = capture("refused-is-not-media.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        !stdout.contains("192.168.77.77"),
        "the refused datagram must not appear as a media endpoint:\n{stdout}"
    );
    assert!(
        !stdout.contains("192.168.66.66"),
        "nor may its source:\n{stdout}"
    );
}

/// A refused datagram is still CLASSIFIED as control traffic.
///
/// The end-to-end test above cannot separate "consumed" from "fell through
/// to the media classifier", because a datagram that begins `HEP3` fails the
/// RTP version check either way and produces nothing observable. So the
/// decision is pinned where it is made: the refusal returns an EMPTY link
/// list, which the pipeline arm consumes, rather than `None`, which would
/// hand the bytes on.
///
/// It matters because the alternative trades one bug for another. A datagram
/// shaped to pass the RTP pre-filter while still decoding as `ng` would
/// become a phantom stream — the exact failure the LLMNR arm sitting above
/// this one in `classify_packet` was written to prevent, after two 23-byte
/// queries became two phantom RTP streams in a real capture.
#[test]
fn a_refused_datagram_is_classified_as_control_traffic_not_handed_on() {
    let datagram = hep_ng(FORGED_CALL_ID, MEDIA_IP, MEDIA_PORT);
    assert_eq!(
        sipnab::rtpengine::sniffed_ng_sdp_links(HEP_PORT, &datagram).map(|l| l.len()),
        Some(1),
        "premise: on the HEP port these bytes really do name a media endpoint"
    );
    assert_eq!(
        sipnab::rtpengine::sniffed_ng_sdp_links(OFF_PORT, &datagram)
            .as_ref()
            .map(Vec::len),
        Some(0),
        "a refusal is an EMPTY link list — control traffic that named nothing \
         — not `None`, which would hand the datagram to the media classifier"
    );
    assert!(
        sipnab::rtpengine::sniffed_ng_sdp_links(OFF_PORT, b"not a hep datagram at all").is_none(),
        "and something that is not control plane at all is still `None`, so \
         ordinary traffic keeps being classified"
    );
}

/// The residual, pinned on purpose: a mirror from ANY source is believed on
/// the HEP port.
///
/// The port gate narrows what is a candidate; it authenticates nobody, and
/// `--hep-allow` still does not reach this path. Asserting the limit keeps
/// the documentation honest — `docs/rtpengine.md` says exactly this — and
/// makes it impossible to quietly come to believe the sniffed path is
/// authenticated. If a later change DOES gate the source, this test fails and
/// whoever made the change gets to update the sentence that promised it.
#[test]
fn a_mirror_from_any_source_is_still_believed_on_the_hep_port() {
    let mut frames = vec![udp_frame(
        ATTACKER_IP,
        ATTACKER_DST_IP,
        1111,
        HEP_PORT,
        &hep_ng(FORGED_CALL_ID, MEDIA_IP, MEDIA_PORT),
    )];
    frames.extend(media_frames());
    let (_dir, path) = capture("unlisted-source-on-hep-port.pcap", &frames);
    let (stdout, _) = run(&path, &["--report"]);

    assert!(
        stdout.contains(FORGED_CALL_ID),
        "the sniffed path is NOT authenticated: a datagram from any source \
         is believed on the HEP port, and the docs say so. If this now fails, \
         the source is gated — update docs/rtpengine.md and this test \
         together; report was:\n{stdout}"
    );
}

/// The committed relay fixture is unaffected.
///
/// The real capture, from a real rtpengine, is addressed to the HEP port, so
/// the gate must be invisible to it. This is the regression guard with the
/// most authority in the file because nothing about it was crafted.
#[test]
fn the_committed_relay_fixture_is_still_attributed() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rtpengine-ng-hep.pcap");
    let (stdout, _) = run(&fixture, &["--report"]);
    assert!(
        stdout.contains("km-670bd208@sipnab"),
        "the fixture's relay-named call must survive the gate:\n{stdout}"
    );
    assert!(
        !stdout.contains("Orphaned Streams"),
        "and none of its streams may go back to being orphans:\n{stdout}"
    );
}
