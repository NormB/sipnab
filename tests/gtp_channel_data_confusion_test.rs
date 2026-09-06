// SPDX-License-Identifier: MIT OR Apache-2.0

//! GTPv2-C control traffic must not be reported as relayed media.
//!
//! # The defect this file exists for
//!
//! Found on a real LTE capture on 2026-09-06. sipnab reported a four-packet
//! RTP stream — SSRC `0x02000200`, codec PCMU, `mos: 1.0`, `mos_grounded:
//! true` — between two hosts on UDP 2123. The four packets were GTPv2-C
//! `Create Session Response` and `Modify Bearer Response`: control plane, not
//! media, and not even user traffic.
//!
//! A TURN ChannelData frame and a GTPv2-C message have the same header shape:
//! two bytes that must fall in `0x4000..=0x7FFF`, then a length that excludes
//! those first four octets. GTPv2's first octet is `0x48` whenever the TEID
//! flag is set, so it is always in the window, and both specifications define
//! Length identically — so sipnab unwrapped four bytes and read what followed
//! as an RTP header, taking the first information element as the SSRC.
//!
//! # Why this file rather than only the unit tests
//!
//! `src/stun.rs` proves the port rule refuses the frame. That is one function.
//! What an operator experiences is a *stream in a report*, which is the whole
//! pipeline: classify, heuristic, stream store, and the report writer. A unit
//! test cannot fail if a later caller reaches for the port-blind entry point
//! again, and the port-blind one still exists because callers without ports
//! legitimately need it.
#![cfg(feature = "native")]

#[path = "support/pcap_build.rs"]
mod pcap_build;

use pcap_build::{udp_frame, write_pcap};
use std::process::Command;

/// A GTPv2-C message: flags with the TEID bit set, message type, length
/// covering everything after the first four octets, TEID, sequence, then a
/// body.
///
/// `msg_type` is the caller's so a test can build the specific messages the
/// real capture carried. `body_len` sets the declared length, which is what
/// makes the frame satisfy ChannelData's whole-datagram check.
fn gtpv2_c(msg_type: u8, body_len: usize) -> Vec<u8> {
    // 8 octets follow the 4-octet preamble before the body: TEID and sequence.
    let declared = 8 + body_len;
    let mut m = vec![0x48, msg_type];
    m.extend_from_slice(&u16::try_from(declared).expect("fits").to_be_bytes());
    m.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // TEID
    m.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]); // sequence + spare
    // A body whose first four bytes are what the defect reported as the SSRC.
    m.extend_from_slice(&[0x02, 0x00, 0x02, 0x00]);
    m.extend(std::iter::repeat_n(0u8, body_len.saturating_sub(4)));
    assert_eq!(
        m.len(),
        4 + declared,
        "the length field must cover the rest"
    );
    m
}

/// Run sipnab over `frames` and return its stderr, which carries the summary.
fn run_over(frames: &[Vec<u8>]) -> String {
    let dir = tempfile::tempdir().expect("temp dir");
    let pcap = dir.path().join("c.pcap");
    write_pcap(&pcap, frames);
    let out = Command::new(env!("CARGO_BIN_EXE_sipnab"))
        .args(["-N", "-I"])
        .arg(&pcap)
        .arg("--report")
        .output()
        .expect("sipnab runs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A capture of nothing but GTPv2-C yields no stream at all.
///
/// The regression test for the defect as an operator met it. Four messages,
/// which is above the heuristic's three-packet promotion threshold, so a
/// capture that produced a stream here would produce one in the field.
#[test]
fn gtp_c_control_traffic_produces_no_media_stream() {
    let frames: Vec<Vec<u8>> = [0x21u8, 0x23, 0x21, 0x23]
        .iter()
        .map(|t| udp_frame([127, 0, 0, 3], [127, 0, 0, 2], 2123, 2123, &gtpv2_c(*t, 99)))
        .collect();

    let out = run_over(&frames);
    assert!(
        out.contains("0 RTP packets across 0 streams"),
        "GTP-C must not become media. Got:\n{out}"
    );
    assert!(
        !out.contains("0x02000200"),
        "the first information element must never surface as an SSRC:\n{out}"
    );
}

/// The same bytes on ports that are not GTP still unwrap.
///
/// The other half, and the one that keeps the fix honest: the discriminator
/// has to be the port, because the four header bytes genuinely cannot tell the
/// two protocols apart. If this test ever fails, the fix stopped being a port
/// rule and became a byte rule that also rejects real relayed media.
#[test]
fn the_same_bytes_on_relay_ports_are_still_unwrapped() {
    let frames: Vec<Vec<u8>> = (0..4)
        .map(|_| {
            udp_frame(
                [198, 51, 100, 3],
                [198, 51, 100, 2],
                49152,
                50000,
                &gtpv2_c(0x21, 99),
            )
        })
        .collect();

    let out = run_over(&frames);
    assert!(
        !out.contains("0 RTP packets across 0 streams"),
        "on non-GTP ports the wrapper is still a wrapper, so sipnab must look \
         inside it. Got:\n{out}"
    );
}

/// GTP-U is refused too, and its user plane still reaches the parsers.
///
/// 2152 carries real SIP inside G-PDUs — the COLTE capture that exposed this
/// defect has a REGISTER inside one — so refusing ChannelData on 2152 must not
/// disturb the tunnel decapsulator, which runs on a different path.
#[test]
fn gtp_u_port_is_refused_without_touching_tunnel_decapsulation() {
    let frames: Vec<Vec<u8>> = (0..4)
        .map(|_| {
            udp_frame(
                [127, 0, 0, 3],
                [127, 0, 0, 2],
                2152,
                2152,
                &gtpv2_c(0x21, 99),
            )
        })
        .collect();

    let out = run_over(&frames);
    assert!(
        out.contains("0 RTP packets across 0 streams"),
        "a ChannelData-shaped datagram on the GTP-U port is not media:\n{out}"
    );
}
