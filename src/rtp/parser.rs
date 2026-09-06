// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTP header parser (RFC 3550).
//!
//! Parses the fixed 12-byte RTP header plus variable-length CSRC list
//! and optional header extension. Computes the payload offset so callers
//! can locate the media data without re-walking the header.

use crate::error::ParseError;

/// A parsed RTP packet header.
///
/// Fields map directly to RFC 3550 Section 5.1. The `payload_offset`
/// indicates where the media payload begins relative to the start of
/// the RTP data passed to `parse_rtp_header`.
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

impl RtpHeader {
    /// The packet's payload, with RFC 3550 padding removed.
    ///
    /// # Why this exists
    ///
    /// RFC 3550 §5.1: "If the padding bit is set, the packet contains one or
    /// more additional padding octets at the end which are not part of the
    /// payload. The last octet of the padding contains a count of how many
    /// padding octets should be ignored, including itself."
    ///
    /// The `padding` flag was parsed and then read by nothing, so padding was
    /// counted as payload — inflating the octet total an operator reads as a
    /// bitrate, and being pushed into the audio buffer, where it became
    /// samples in every exported WAV and vCon.
    ///
    /// # Arguments
    ///
    /// * `packet` — the whole RTP packet these fields were parsed from.
    ///
    /// # Returns
    ///
    /// The payload slice. Empty when the packet is shorter than its own
    /// header, or when the padding count is impossible — it is wire-supplied,
    /// so a corrupt or hostile packet may claim more padding than there is
    /// payload, and the arithmetic must saturate rather than wrap.
    #[must_use]
    pub fn payload<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        let Some(body) = packet.get(self.payload_offset..) else {
            return &[];
        };
        if !self.padding {
            return body;
        }
        // §5.1 counts the length octet itself, so the minimum legal value is
        // 1; zero is malformed and yields nothing rather than a wrapped span.
        let Some(&pad) = body.last() else {
            return &[];
        };
        let pad = pad as usize;
        if pad == 0 || pad > body.len() {
            return &[];
        }
        &body[..body.len() - pad]
    }
}

/// Minimum RTP header size: V/P/X/CC(1) + M/PT(1) + seq(2) + ts(4) + SSRC(4).
const RTP_FIXED_HEADER_LEN: usize = 12;

/// Parse an RTP header from raw bytes.
///
/// Validates the minimum length and version field, then walks past the
/// CSRC list and any header extension to compute `payload_offset`.
///
/// # Arguments
///
/// * `data` — raw RTP packet bytes in network (big-endian) byte order,
///   starting at the first byte of the fixed header.
///
/// # Returns
///
/// The parsed `RtpHeader`, with `payload_offset` pointing at the first
/// media payload byte within `data`.
///
/// # Errors
///
/// `ParseError::TooShort` when the data is too short for the declared
/// header fields; `ParseError::BadRtpVersion` when the version is not 2.
///
/// # Examples
///
/// ```
/// use sipnab::rtp::parser::parse_rtp_header;
///
/// // 12-byte fixed header: V=2, PT=0 (PCMU), seq=1, ts=160, SSRC=0x1234.
/// let data = [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 160, 0, 0, 0x12, 0x34, 0xFF];
/// let h = parse_rtp_header(&data)?;
/// assert_eq!(h.payload_type, 0);
/// assert_eq!(h.sequence, 1);
/// assert_eq!(h.payload_offset, 12); // media starts after the fixed header
///
/// // Truncated input is a matchable error:
/// use sipnab::ParseError;
/// assert!(matches!(
///     parse_rtp_header(&[0x80, 0x00]),
///     Err(ParseError::TooShort { need: 12, got: 2, .. })
/// ));
/// # Ok::<(), sipnab::ParseError>(())
/// ```
pub fn parse_rtp_header(data: &[u8]) -> Result<RtpHeader, ParseError> {
    if data.len() < RTP_FIXED_HEADER_LEN {
        return Err(ParseError::TooShort {
            what: "RTP header",
            need: RTP_FIXED_HEADER_LEN,
            got: data.len(),
        });
    }

    let byte0 = data[0];
    let version = (byte0 >> 6) & 0x03;
    if version != 2 {
        return Err(ParseError::BadRtpVersion { version });
    }

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
    if data.len() < offset {
        return Err(ParseError::TooShort {
            what: "RTP CSRC list",
            need: offset,
            got: data.len(),
        });
    }

    // Handle header extension (RFC 3550 Section 5.3.1)
    if extension {
        if data.len() < offset + 4 {
            return Err(ParseError::TooShort {
                what: "RTP extension header",
                need: offset + 4,
                got: data.len(),
            });
        }
        // Extension header: 2-byte profile-defined field + 2-byte length (in 32-bit words)
        let ext_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4 + ext_length * 4;
        if data.len() < offset {
            return Err(ParseError::TooShort {
                what: "RTP extension payload",
                need: offset,
                got: data.len(),
            });
        }
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

/// Unit tests for RTP header parsing: happy path, CSRC lists, header
/// extensions, marker bit, and truncation/version error handling.
#[cfg(test)]
mod tests {
    /// Padding octets are not payload.
    ///
    /// RFC 3550 §5.1: "If the padding bit is set, the packet contains one or
    /// more additional padding octets at the end which are not part of the
    /// payload. The last octet of the padding contains a count of how many
    /// padding octets should be ignored, including itself."
    ///
    /// The `padding` flag was decoded and never read. Nothing stripped the
    /// octets, so they were counted into the octet total an operator reads as
    /// a bitrate, and — worse — pushed into the audio buffer, becoming samples
    /// in every exported WAV and vCon.
    #[test]
    fn padding_octets_are_excluded_from_the_payload() {
        // V=2, P=1, PT=0, 160 octets of G.711 then 4 octets of padding whose
        // last byte is the count, per §5.1.
        let mut pkt = vec![0xA0, 0x00, 0x03, 0xE8, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        pkt.extend(std::iter::repeat_n(0xD5u8, 160));
        pkt.extend_from_slice(&[0, 0, 0, 4]);

        let hdr = parse_rtp_header(&pkt).expect("parses");
        assert!(hdr.padding, "the P bit is set");
        assert_eq!(
            hdr.payload(&pkt).len(),
            160,
            "164 octets arrived; 160 are payload"
        );
        assert!(
            hdr.payload(&pkt).iter().all(|b| *b == 0xD5),
            "no padding octet reaches the payload"
        );
    }

    /// With no padding bit the whole tail is payload.
    ///
    /// The regression guard: almost every RTP packet is this, and a stripper
    /// that ran unconditionally would eat a real audio octet from each one.
    #[test]
    fn without_the_padding_bit_the_whole_tail_is_payload() {
        let mut pkt = vec![0x80, 0x00, 0x03, 0xE8, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        pkt.extend(std::iter::repeat_n(0xD5u8, 160));
        let hdr = parse_rtp_header(&pkt).expect("parses");
        assert!(!hdr.padding);
        assert_eq!(hdr.payload(&pkt).len(), 160);
    }

    /// A padding count larger than the packet cannot underflow.
    ///
    /// The count is wire-supplied, so a malicious or corrupt packet can claim
    /// more padding than there is payload. That must yield an empty payload,
    /// never a panic and never a wrapped length.
    #[test]
    fn an_impossible_padding_count_yields_an_empty_payload() {
        let mut pkt = vec![0xA0, 0x00, 0x03, 0xE8, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        pkt.extend_from_slice(&[0x00, 0xFF]); // claims 255 octets of padding
        let hdr = parse_rtp_header(&pkt).expect("parses");
        assert!(hdr.payload(&pkt).is_empty());
    }

    /// A padding count of zero is impossible and is treated as no payload.
    ///
    /// §5.1 counts the length octet itself, so the minimum legal value is 1.
    /// Zero is malformed; refusing to trust it keeps the arithmetic total.
    #[test]
    fn a_zero_padding_count_is_malformed_and_yields_nothing() {
        let mut pkt = vec![0xA0, 0x00, 0x03, 0xE8, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44];
        pkt.extend_from_slice(&[0xD5, 0x00]);
        let hdr = parse_rtp_header(&pkt).expect("parses");
        assert!(hdr.payload(&pkt).is_empty());
    }

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

    /// A plain 12-byte header parses with every field decoded and
    /// `payload_offset` at 12.
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

    /// Two CSRC entries advance `payload_offset` by 8 bytes past the
    /// fixed header.
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

    /// A header extension (2-word body) moves `payload_offset` past the
    /// 4-byte extension header plus its data.
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

    /// Setting the high bit of byte 1 yields `marker == true` without
    /// disturbing the payload type.
    #[test]
    fn parse_rtp_with_marker() {
        let mut data = build_rtp(0x12345678, 999, 80000, 0, &[0x00; 20]);
        // Set marker bit: byte1 high bit
        data[1] |= 0x80;

        let hdr = parse_rtp_header(&data).expect("RTP with marker");
        assert!(hdr.marker);
        assert_eq!(hdr.payload_type, 0);
    }

    /// A 3-byte input (shorter than the fixed header) is rejected.
    #[test]
    fn too_short_returns_error() {
        let data = [0x80, 0x00, 0x00]; // Only 3 bytes
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    /// Version 3 in the V bits is rejected with an error.
    #[test]
    fn wrong_version_returns_error() {
        // Version 3 instead of 2
        let mut data = build_rtp(1, 1, 1, 0, &[0; 10]);
        data[0] = 0xC0; // V=3
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    /// Version 0 is rejected with an error.
    ///
    /// Version 0 is where STUN would land, since its two leading bits are
    /// always zero — but no STUN reaches here any more: `classify_packet`
    /// claims it, along with TURN ChannelData and LLMNR, before the media
    /// checks run. This test guards the parser's own contract against
    /// garbage traffic, not against a protocol sipnab now decodes.
    #[test]
    fn version_0_returns_error() {
        let mut data = build_rtp(1, 1, 1, 0, &[0; 10]);
        data[0] = 0x00; // V=0
        let result = parse_rtp_header(&data);
        assert!(result.is_err());
    }

    /// CC=15 with no CSRC data present errors instead of reading past the
    /// buffer.
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
