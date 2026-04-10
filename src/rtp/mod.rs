//! RTP stream engine for sipnab.
//!
//! This module provides RTP and RTCP packet parsing, stream lifecycle
//! tracking, heuristic discovery (for streams without SDP signaling),
//! and media path diagnosis. RTP streams are first-class entities that
//! peer with SIP dialogs via cross-references rather than being children
//! of dialogs.
//!
//! # Architecture
//!
//! - [`parser`] — RTP header parsing (RFC 3550)
//! - [`rtcp`] — RTCP compound packet parsing (SR, RR, BYE)
//! - [`stream`] — Individual stream state and quality tracking
//! - [`stream_store`] — Indexed collection of streams with lifecycle management
//! - [`heuristic`] — RTP detection without SDP signaling
//! - [`diagnosis`] — Media path issue detection (one-way audio, NAT, no media)

pub mod diagnosis;
pub mod dtmf;
pub mod heuristic;
pub mod parser;
pub mod quality;
pub mod rtcp;
pub mod stream;
pub mod stream_store;

/// Quick check whether a UDP payload is likely an RTP packet.
///
/// Validates the minimum length (12 bytes), RTP version (2), and
/// payload type range (0-127, which is always true for the 7-bit field).
/// This is a fast pre-filter before the full [`parser::parse_rtp_header`]
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
    // PT 72-76 are RTCP packet types (200-204) and not valid RTP PTs
    !(72..=76).contains(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_rtp_valid_packet() {
        let mut data = vec![0x80, 0x00]; // V=2, PT=0
        data.extend_from_slice(&[0u8; 10]); // rest of header
        assert!(is_rtp_packet(&data));
    }

    #[test]
    fn is_rtp_too_short() {
        assert!(!is_rtp_packet(&[0x80, 0x00, 0x00]));
    }

    #[test]
    fn is_rtp_wrong_version() {
        let mut data = vec![0x00, 0x00]; // V=0
        data.extend_from_slice(&[0u8; 10]);
        assert!(!is_rtp_packet(&data));
    }

    #[test]
    fn is_rtp_rtcp_pt_rejected() {
        // PT=72 (maps to RTCP SR type 200)
        let mut data = vec![0x80, 72];
        data.extend_from_slice(&[0u8; 10]);
        assert!(!is_rtp_packet(&data));
    }

    #[test]
    fn is_rtp_dynamic_pt_accepted() {
        // PT=96 (dynamic range)
        let mut data = vec![0x80, 96];
        data.extend_from_slice(&[0u8; 10]);
        assert!(is_rtp_packet(&data));
    }

    #[test]
    fn is_rtp_with_marker_bit() {
        // M=1, PT=0 → byte1 = 0x80
        let mut data = vec![0x80, 0x80];
        data.extend_from_slice(&[0u8; 10]);
        assert!(is_rtp_packet(&data));
    }
}
