//! RTP header parser (RFC 3550).
//!
//! Parses the fixed 12-byte RTP header plus variable-length CSRC list
//! and optional header extension. Computes the payload offset so callers
//! can locate the media data without re-walking the header.

use anyhow::{Result, ensure};

/// A parsed RTP packet header.
///
/// Fields map directly to RFC 3550 Section 5.1. The `payload_offset`
/// indicates where the media payload begins relative to the start of
/// the RTP data passed to [`parse_rtp_header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// RTP version (must be 2).
    pub version: u8,
    /// Padding flag — if set, the packet contains padding octets at the end.
    pub padding: bool,
    /// Extension flag — if set, the fixed header is followed by an extension.
    pub extension: bool,
    /// Number of CSRC identifiers following the fixed header.
    pub csrc_count: u8,
    /// Marker bit — profile-dependent semantics (e.g., end of talkspurt).
    pub marker: bool,
    /// RTP payload type (0-127).
    pub payload_type: u8,
    /// RTP sequence number, incrementing by one for each packet.
    pub sequence: u16,
    /// RTP timestamp derived from the sampling clock.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Byte offset from the start of `data` where the payload begins.
    pub payload_offset: usize,
}

/// Minimum RTP header size: V/P/X/CC(1) + M/PT(1) + seq(2) + ts(4) + SSRC(4).
const RTP_FIXED_HEADER_LEN: usize = 12;

/// Parse an RTP header from raw bytes.
///
/// Validates the minimum length and version field, then walks past the
/// CSRC list and any header extension to compute `payload_offset`.
///
/// # Errors
///
/// Returns an error if the data is too short for the declared header
/// fields or if the RTP version is not 2.
pub fn parse_rtp_header(data: &[u8]) -> Result<RtpHeader> {
    ensure!(
        data.len() >= RTP_FIXED_HEADER_LEN,
        "RTP packet too short: {} bytes (minimum {})",
        data.len(),
        RTP_FIXED_HEADER_LEN
    );

    let byte0 = data[0];
    let version = (byte0 >> 6) & 0x03;
    ensure!(version == 2, "RTP version {version}, expected 2");

    let padding = (byte0 >> 5) & 0x01 != 0;
    let extension = (byte0 >> 4) & 0x01 != 0;
    let csrc_count = byte0 & 0x0F;

    let byte1 = data[1];
    let marker = (byte1 >> 7) & 0x01 != 0;
    let payload_type = byte1 & 0x7F;

    let sequence = u16::from_be_bytes([data[2], data[3]]);
    let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    // Advance past CSRC list (4 bytes per entry)
    let mut offset = RTP_FIXED_HEADER_LEN + (csrc_count as usize) * 4;
    ensure!(
        data.len() >= offset,
        "RTP packet too short for {} CSRC entries: {} bytes, need {}",
        csrc_count,
        data.len(),
        offset
    );

    // Handle header extension (RFC 3550 Section 5.3.1)
    if extension {
        ensure!(
            data.len() >= offset + 4,
            "RTP packet too short for extension header at offset {offset}"
        );
        // Extension header: 2-byte profile-defined field + 2-byte length (in 32-bit words)
        let ext_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + ext_length * 4;
        ensure!(
            data.len() >= offset,
            "RTP packet too short for extension payload: need {offset}, have {}",
            data.len()
        );
    }

    Ok(RtpHeader {
        version,
        padding,
        extension,
        csrc_count,
        marker,
        payload_type,
        sequence,
        timestamp,
        ssrc,
        payload_offset: offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid RTP packet (12-byte header + payload).
    fn build_rtp(ssrc: u32, seq: u16, ts: u32, pt: u8, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(12 + payload.len());
        // byte 0: V=2, P=0, X=0, CC=0 → 0x80
        pkt.push(0x80);
        // byte 1: M=0, PT
        pkt.push(pt & 0x7F);
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&ts.to_be_bytes());
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_valid_rtp_header() {
        let data = build_rtp(0xDEADBEEF, 1234, 160000, 0, &[0xFF; 160]);
        let hdr = parse_rtp_header(&data).expect("valid RTP");

        assert_eq!(hdr.version, 2);
        assert!(!hdr.padding);
        assert!(!hdr.extension);
        assert_eq!(hdr.csrc_count, 0);
        assert!(!hdr.marker);
        assert_eq!(hdr.payload_type, 0);
        assert_eq!(hdr.sequence, 1234);
        assert_eq!(hdr.timestamp, 160000);
        assert_eq!(hdr.ssrc, 0xDEADBEEF);
        assert_eq!(hdr.payload_offset, 12);
    }

    #[test]
    fn parse_rtp_with_csrc() {
        let mut data = Vec::new();
        // byte 0: V=2, P=0, X=0, CC=2 → 0x82
        data.push(0x82);
        data.push(0); // PT=0
        data.extend_from_slice(&100u16.to_be_bytes());
        data.extend_from_slice(&8000u32.to_be_bytes());
        data.extend_from_slice(&0x11111111u32.to_be_bytes()); // SSRC
        // Two CSRC entries
        data.extend_from_slice(&0xAAAAAAAAu32.to_be_bytes());
        data.extend_from_slice(&0xBBBBBBBBu32.to_be_bytes());
        // Payload
        data.extend_from_slice(&[0x00; 40]);

        let hdr = parse_rtp_header(&data).expect("RTP with CSRC");
        assert_eq!(hdr.csrc_count, 2);
        assert_eq!(hdr.payload_offset, 12 + 8); // 12 fixed + 2*4 CSRC
    }

    #[test]
    fn parse_rtp_with_extension() {
        let mut data = Vec::new();
        // byte 0: V=2, P=0, X=1, CC=0 → 0x90
        data.push(0x90);
        data.push(8); // PT=8 (PCMA)
        data.extend_from_slice(&500u16.to_be_bytes());
        data.extend_from_slice(&40000u32.to_be_bytes());
        data.extend_from_slice(&0x22222222u32.to_be_bytes()); // SSRC
        // Extension header: profile=0xBEDE, length=2 (two 32-bit words)
        data.extend_from_slice(&[0xBE, 0xDE]);
        data.extend_from_slice(&2u16.to_be_bytes());
        // Extension data: 8 bytes (2 words)
        data.extend_from_slice(&[0x01; 8]);
        // Payload
        data.extend_from_slice(&[0xFF; 80]);

        let hdr = parse_rtp_header(&data).expect("RTP with extension");
        assert!(hdr.extension);
        assert_eq!(hdr.payload_type, 8);
        // 12 fixed + 4 ext header + 8 ext data = 24
        assert_eq!(hdr.payload_offset, 24);
    }

    #[test]
    fn parse_rtp_with_marker() {
        let mut data = build_rtp(0x12345678, 999, 80000, 0, &[0x00; 20]);
        // Set marker bit: byte1 high bit
        data[1] |= 0x80;

        let hdr = parse_rtp_header(&data).expect("RTP with marker");
        assert!(hdr.marker);
        assert_eq!(hdr.payload_type, 0);
    }

    #[test]
    fn too_short_returns_error() {
        let data = [0x80, 0x00, 0x00]; // Only 3 bytes
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_version_returns_error() {
        // Version 3 instead of 2
        let mut data = build_rtp(1, 1, 1, 0, &[0; 10]);
        data[0] = 0xC0; // V=3
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    #[test]
    fn version_0_returns_error() {
        let mut data = build_rtp(1, 1, 1, 0, &[0; 10]);
        data[0] = 0x00; // V=0
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    #[test]
    fn csrc_count_exceeds_data_returns_error() {
        let mut data = Vec::new();
        // CC=15 but no CSRC data
        data.push(0x8F); // V=2, CC=15
        data.push(0x00);
        data.extend_from_slice(&[0x00; 10]); // rest of fixed header
        // Only 12 bytes total, need 12 + 60 = 72
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }
}
