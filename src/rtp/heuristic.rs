//! Heuristic RTP discovery without SDP.
//!
//! When sipnab sees UDP traffic that does not match any SDP-negotiated
//! media endpoint, the heuristic engine tries to identify it as RTP by
//! looking for patterns: consistent SSRC, incrementing sequence numbers,
//! valid RTP version, and even destination ports.
//!
//! A candidate is promoted after [`CONSECUTIVE_THRESHOLD`] consecutive
//! packets pass validation.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::capture::ParsedPacket;
use crate::capture::parse::TransportProto;

use super::parser::{RtpHeader, parse_rtp_header};

/// Number of consecutive valid RTP packets required before declaring detection.
const CONSECUTIVE_THRESHOLD: u32 = 3;

/// Heuristic RTP stream detector for traffic without SDP signaling.
///
/// Tracks candidate flows by their source/destination address pair. Once
/// a candidate accumulates enough consecutive valid RTP packets with
/// consistent properties, it is promoted and the parsed header is returned.
pub struct RtpHeuristic {
    /// Candidate tracking by address pair.
    candidates: HashMap<(SocketAddr, SocketAddr), HeuristicCandidate>,
}

/// Internal state for a candidate RTP flow.
struct HeuristicCandidate {
    /// Number of consecutive valid RTP packets seen.
    consecutive_valid: u32,
    /// Last observed RTP sequence number.
    last_seq: u16,
    /// Last observed payload type.
    last_pt: u8,
    /// SSRC that must remain consistent.
    ssrc: u32,
}

impl RtpHeuristic {
    /// Create a new heuristic detector.
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
        }
    }

    /// Check a packet for heuristic RTP detection.
    ///
    /// Only considers UDP packets with even destination ports (RTP convention).
    /// Returns `Some(RtpHeader)` when the consecutive-valid threshold is met,
    /// indicating high confidence that this flow is RTP.
    pub fn check(&mut self, parsed: &ParsedPacket) -> Option<RtpHeader> {
        // Only consider UDP
        if parsed.transport != TransportProto::Udp {
            return None;
        }

        // RTP convention: even destination port
        if !parsed.dst_port.is_multiple_of(2) {
            return None;
        }

        // Skip very small payloads (RTP minimum is 12 bytes)
        if parsed.payload.len() < 12 {
            return None;
        }

        // Try parsing as RTP
        let header = match parse_rtp_header(&parsed.payload) {
            Ok(h) => h,
            Err(_) => {
                // Invalid RTP — reset candidate if one existed
                let key = (
                    SocketAddr::new(parsed.src_addr, parsed.src_port),
                    SocketAddr::new(parsed.dst_addr, parsed.dst_port),
                );
                self.candidates.remove(&key);
                return None;
            }
        };

        let key = (
            SocketAddr::new(parsed.src_addr, parsed.src_port),
            SocketAddr::new(parsed.dst_addr, parsed.dst_port),
        );

        let candidate = self.candidates.entry(key).or_insert(HeuristicCandidate {
            consecutive_valid: 0,
            last_seq: header.sequence.wrapping_sub(1), // so first packet counts as incrementing
            last_pt: header.payload_type,
            ssrc: header.ssrc,
        });

        // Validate consistency
        let seq_incrementing = header.sequence == candidate.last_seq.wrapping_add(1);
        let ssrc_consistent = header.ssrc == candidate.ssrc;
        let pt_consistent = header.payload_type == candidate.last_pt;

        if seq_incrementing && ssrc_consistent && pt_consistent {
            candidate.consecutive_valid += 1;
            candidate.last_seq = header.sequence;

            if candidate.consecutive_valid >= CONSECUTIVE_THRESHOLD {
                return Some(header);
            }
        } else {
            // Reset with current packet as new baseline
            candidate.consecutive_valid = 1;
            candidate.last_seq = header.sequence;
            candidate.last_pt = header.payload_type;
            candidate.ssrc = header.ssrc;
        }

        None
    }
}

impl Default for RtpHeuristic {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::DateTime;

    use super::*;
    use crate::capture::parse::TransportProto;

    /// Build a ParsedPacket with a valid RTP payload.
    fn make_rtp_parsed(seq: u16, ssrc: u32, pt: u8, dst_port: u16) -> ParsedPacket {
        let mut payload = Vec::with_capacity(172);
        // byte 0: V=2, P=0, X=0, CC=0
        payload.push(0x80);
        // byte 1: M=0, PT
        payload.push(pt & 0x7F);
        payload.extend_from_slice(&seq.to_be_bytes());
        payload.extend_from_slice(&((seq as u32) * 160).to_be_bytes());
        payload.extend_from_slice(&ssrc.to_be_bytes());
        // 160 bytes of audio payload
        payload.extend_from_slice(&[0xFF; 160]);

        ParsedPacket {
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).expect("valid"),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 50000,
            dst_port,
            transport: TransportProto::Udp,
            payload,
            ip_id: None,
            tcp_seq: None,
            tcp_flags: None,
            fragment_offset: None,
            more_fragments: false,
            ip_protocol: 17,
        }
    }

    #[test]
    fn three_consecutive_valid_packets_detected() {
        let mut heuristic = RtpHeuristic::new();

        // Packets 1 and 2: not yet at threshold
        assert!(
            heuristic
                .check(&make_rtp_parsed(100, 0xABCD, 0, 20000))
                .is_none()
        );
        assert!(
            heuristic
                .check(&make_rtp_parsed(101, 0xABCD, 0, 20000))
                .is_none()
        );

        // Packet 3: threshold met
        let result = heuristic.check(&make_rtp_parsed(102, 0xABCD, 0, 20000));
        assert!(
            result.is_some(),
            "Should detect RTP after 3 consecutive packets"
        );
        let hdr = result.unwrap();
        assert_eq!(hdr.ssrc, 0xABCD);
        assert_eq!(hdr.sequence, 102);
    }

    #[test]
    fn two_packets_not_detected() {
        let mut heuristic = RtpHeuristic::new();
        assert!(
            heuristic
                .check(&make_rtp_parsed(100, 0xABCD, 0, 20000))
                .is_none()
        );
        assert!(
            heuristic
                .check(&make_rtp_parsed(101, 0xABCD, 0, 20000))
                .is_none()
        );
        // Only 2 — not enough
    }

    #[test]
    fn invalid_packets_not_detected() {
        let mut heuristic = RtpHeuristic::new();

        // Non-RTP payload (version != 2)
        let mut pkt = make_rtp_parsed(100, 0xABCD, 0, 20000);
        pkt.payload[0] = 0x00; // V=0
        assert!(heuristic.check(&pkt).is_none());
    }

    #[test]
    fn odd_destination_port_ignored() {
        let mut heuristic = RtpHeuristic::new();

        // RTP convention: odd port is RTCP, not RTP
        for seq in 100..110 {
            assert!(
                heuristic
                    .check(&make_rtp_parsed(seq, 0xABCD, 0, 20001))
                    .is_none()
            );
        }
    }

    #[test]
    fn ssrc_change_resets_candidate() {
        let mut heuristic = RtpHeuristic::new();

        assert!(
            heuristic
                .check(&make_rtp_parsed(100, 0xAAAA, 0, 20000))
                .is_none()
        );
        assert!(
            heuristic
                .check(&make_rtp_parsed(101, 0xAAAA, 0, 20000))
                .is_none()
        );
        // Different SSRC → reset
        assert!(
            heuristic
                .check(&make_rtp_parsed(102, 0xBBBB, 0, 20000))
                .is_none()
        );
        // Need 3 more with new SSRC
        assert!(
            heuristic
                .check(&make_rtp_parsed(103, 0xBBBB, 0, 20000))
                .is_none()
        );
        assert!(
            heuristic
                .check(&make_rtp_parsed(104, 0xBBBB, 0, 20000))
                .is_some()
        );
    }

    #[test]
    fn tcp_ignored() {
        let mut heuristic = RtpHeuristic::new();

        let mut pkt = make_rtp_parsed(100, 0xABCD, 0, 20000);
        pkt.transport = TransportProto::Tcp;
        assert!(heuristic.check(&pkt).is_none());
    }

    #[test]
    fn sequence_gap_resets_candidate() {
        let mut heuristic = RtpHeuristic::new();

        assert!(
            heuristic
                .check(&make_rtp_parsed(100, 0xABCD, 0, 20000))
                .is_none()
        );
        assert!(
            heuristic
                .check(&make_rtp_parsed(101, 0xABCD, 0, 20000))
                .is_none()
        );
        // Gap: 101 → 105 (not consecutive)
        assert!(
            heuristic
                .check(&make_rtp_parsed(105, 0xABCD, 0, 20000))
                .is_none()
        );
    }
}
