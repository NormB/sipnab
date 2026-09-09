// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP/RTCP stream analysis, quality metrics, and audio export.
//!
//! This module provides RTP and RTCP packet parsing, stream lifecycle
//! tracking, heuristic discovery (for streams without SDP signaling),
//! and media path diagnosis. RTP streams are first-class entities that
//! peer with SIP dialogs via cross-references rather than being children
//! of dialogs.
//!
//! Core types: `RtpStream`, `StreamKey`, `StreamStore`.
//! Functions: `estimate_mos`, `parse_rtp_header`.
//!
//! # Architecture
//!
//! - `parser` — RTP header parsing (RFC 3550)
//! - `rtcp` — RTCP compound packet parsing (SR, RR, BYE)
//! - `stream` — Individual stream state and quality tracking
//! - `stream_store` — Indexed collection of streams with lifecycle management
//! - `heuristic` — RTP detection without SDP signaling
//! - `diagnosis` — Media path issue detection (one-way audio, NAT, no media)
//! - `amplitude` — What the decoded samples did: dead air and hard clipping
//! - `amr` — The AMR/AMR-WB payload header, read for the frame mode

pub mod amplitude;
pub mod amr;
pub mod audio_export;
pub mod bands;
pub mod diagnosis;
pub mod dtmf;
pub mod emodel_wb;
pub mod g711;
pub mod heuristic;
pub mod loss_map;
pub mod opus_decode;
pub mod parser;
#[cfg(feature = "audio")]
pub mod playback;
pub mod quality;
pub mod rtcp;
#[cfg(feature = "tls")]
pub mod srtp;
pub mod stream;
pub mod stream_store;
pub mod wav;

/// Quick check whether a UDP payload is likely an RTP packet.
///
/// Validates the minimum length (12 bytes), RTP version (2), and
/// payload type range (0-127, which is always true for the 7-bit field).
/// This is a fast pre-filter before the full `parser::parse_rtp_header`
/// call — it avoids allocating error context for non-RTP traffic.
pub fn is_rtp_packet(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    // Payload type is bits 0-6 of byte 1 (always 0-127 by construction).
    // Filter out clearly invalid PTs: RTCP uses 200-204 range which maps
    // to PT 72-76 when reading bits 0-6. However some valid dynamic PTs
    // overlap, so we only reject the impossible range and leave full
    // validation to the parser.
    let pt = data[1] & 0x7F;
    // The WHOLE reserved band, not just 72-76. RFC 3551 §6 leaves payload
    // types 64-95 unassigned precisely so that RTCP packet types 192-223
    // remain distinguishable from RTP, and RFC 5761 §4 makes that explicit for
    // multiplexed sessions.
    //
    // Rejecting only 72-76 (RTCP 200-204) let types 205-207 and 192-199 —
    // which fold to 77-79 and 64-71 — through as media. That is not
    // theoretical: a snaplen-truncated RTCP XR failed the length-framing test
    // used on muxed ports, fell through here, and was reported as an RTP
    // stream whose "SSRC" was really the XR block header.
    !(64..=95).contains(&pt)
}

/// Unit tests for the `is_rtp_packet` pre-filter.
#[cfg(test)]
mod tests {
    /// A truncated RTCP packet is not accepted as RTP.
    ///
    /// # The defect
    ///
    /// On a muxed (even) port, `is_rtcp_packet` requires the RTCP length field
    /// to frame the datagram. A capture truncated by a snaplen fails that
    /// test, falls through to `is_rtp_packet`, and was accepted as media —
    /// because only payload types 72-76 (RTCP 200-204) were rejected. RTCP
    /// types 205-207 and 192-199 fold to RTP payload types 77-79 and 64-71 and
    /// sailed through.
    ///
    /// Measured: a truncated XR (RTCP 207) produced an "RTP stream" whose SSRC
    /// `0x07000008` was really the XR block header — `BT=7, block length=8`. A
    /// control packet rendered as a media stream, and sipnab ships both
    /// `--snaplen` and a `--capture-profile signaling` that truncate.
    ///
    /// # The rule
    ///
    /// RFC 3551 §6 leaves payload types 64-95 unassigned precisely so RTCP
    /// packet types 192-223 remain distinguishable, and RFC 5761 §4 makes that
    /// explicit for multiplexed sessions. Nothing legitimate sends RTP on
    /// those types.
    #[test]
    fn a_truncated_rtcp_packet_is_not_mistaken_for_rtp() {
        // First octet of each: V=2 with the RTCP type in the second.
        for rtcp_pt in [200u8, 201, 202, 203, 204, 205, 206, 207, 192, 199, 208, 223] {
            let mut pkt = vec![0x80, rtcp_pt, 0x00, 0x0A];
            pkt.extend_from_slice(&[0u8; 20]);
            assert!(
                !is_rtp_packet(&pkt),
                "RTCP packet type {rtcp_pt} must not read as RTP"
            );
        }
    }

    /// Real RTP payload types are still accepted.
    ///
    /// The regression guard, and the reason the rejected band is 64-95 rather
    /// than something wider: static types 0-34 and the dynamic range 96-127
    /// are what real media uses, and refusing any of them would make sipnab
    /// blind to ordinary calls.
    #[test]
    fn real_rtp_payload_types_are_still_accepted() {
        for pt in [0u8, 8, 9, 18, 34, 96, 101, 111, 127] {
            let mut pkt = vec![0x80, pt, 0x00, 0x0A];
            pkt.extend_from_slice(&[0u8; 20]);
            assert!(is_rtp_packet(&pkt), "payload type {pt} is real RTP");
        }
    }

    /// The reserved band's boundaries are exact.
    ///
    /// 63 is the last assignable static type and 96 the first dynamic one;
    /// an off-by-one at either end either lets RTCP through or blinds sipnab
    /// to a real codec.
    #[test]
    fn the_reserved_payload_band_has_exact_boundaries() {
        let build = |pt: u8| {
            let mut pkt = vec![0x80, pt, 0x00, 0x0A];
            pkt.extend_from_slice(&[0u8; 20]);
            pkt
        };
        assert!(is_rtp_packet(&build(63)), "63 is below the reserved band");
        assert!(!is_rtp_packet(&build(64)), "64 opens the reserved band");
        assert!(!is_rtp_packet(&build(95)), "95 closes it");
        assert!(is_rtp_packet(&build(96)), "96 is the first dynamic type");
    }

    use super::*;

    /// A well-formed 12-byte header (V=2, PT=0) is accepted as RTP.
    #[test]
    fn is_rtp_valid_packet() {
        let mut data = vec![0x80, 0x00]; // V=2, PT=0
        data.extend_from_slice(&[0u8; 10]); // rest of header
        assert!(is_rtp_packet(&data));
    }

    /// A buffer shorter than the 12-byte minimum is rejected.
    #[test]
    fn is_rtp_too_short() {
        assert!(!is_rtp_packet(&[0x80, 0x00, 0x00]));
    }

    /// A packet with RTP version != 2 is rejected.
    #[test]
    fn is_rtp_wrong_version() {
        let mut data = vec![0x00, 0x00]; // V=0
        data.extend_from_slice(&[0u8; 10]);
        assert!(!is_rtp_packet(&data));
    }

    /// A payload type in the RTCP range (72) is rejected as non-RTP.
    #[test]
    fn is_rtp_rtcp_pt_rejected() {
        // PT=72 (maps to RTCP SR type 200)
        let mut data = vec![0x80, 72];
        data.extend_from_slice(&[0u8; 10]);
        assert!(!is_rtp_packet(&data));
    }

    /// A dynamic payload type (96) is accepted.
    #[test]
    fn is_rtp_dynamic_pt_accepted() {
        // PT=96 (dynamic range)
        let mut data = vec![0x80, 96];
        data.extend_from_slice(&[0u8; 10]);
        assert!(is_rtp_packet(&data));
    }

    /// The marker bit (M=1) in byte 1 does not affect RTP classification.
    #[test]
    fn is_rtp_with_marker_bit() {
        // M=1, PT=0 → byte1 = 0x80
        let mut data = vec![0x80, 0x80];
        data.extend_from_slice(&[0u8; 10]);
        assert!(is_rtp_packet(&data));
    }
}
