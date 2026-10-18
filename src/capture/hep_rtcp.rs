// SPDX-License-Identifier: MIT OR Apache-2.0

//! RTCP as HOMER stores it: the JSON body heplify puts in HEP protocol type 5.
//!
//! sipnab forwarded RTCP to the collector as the raw binary datagram. HOMER's
//! collector, heplify-server, does not decode binary RTCP: for every protocol
//! type other than SIP and ISUP it only converts the payload to UTF-8
//! (`decoder/decoder.go`, the `toUTF8` call), and homer-ui's QoS tab then runs
//! `JSON.parse` on what was stored. A binary report arrives there as text that
//! no parser accepts.
//!
//! So the body is JSON, in the exact shape heplify sends. The shape is
//! heplify's `rtcpPacketJSON` in `src/decoder/rtcp.go` (sipcapture/heplify at
//! 47e9064b, lines 30-95), which states it mirrors heplify v1.67.1's
//! `protos/rtcp.go` `RTCP_Packet`. The rules for which bytes fill which field
//! are heplify's `ParseRTCP` (same file, lines 109-216), followed one for one,
//! quirks included:
//!
//! - Only the FIRST packet of a compound datagram is read. A sender report
//!   followed by SDES gives `"type":200` and `"sdes_ssrc":0`.
//! - A datagram that opens with BYE, APP or a feedback message has no body:
//!   heplify returns nil and sends nothing, and so does sipnab.
//! - `report_blocks` is `null`, not `[]`, when there are none: Go marshals a
//!   nil slice that way.
//! - `voip_metrics` appears only when an XR carries a VoIP Metrics block, and
//!   its jitter-buffer fields only when they are non-zero (`omitempty`).
//!
//! The tests below hold the output byte for byte against what heplify's own
//! `ParseRTCP` printed for the same input, run from that commit.

use std::fmt::Write as _;

/// RTCP sender report packet type ([RFC 3550 section 6.4.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.1)).
const SR: u8 = 200;
/// RTCP receiver report packet type ([RFC 3550 section 6.4.2](https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.2)).
const RR: u8 = 201;
/// RTCP source description packet type ([RFC 3550 section 6.5](https://www.rfc-editor.org/rfc/rfc3550.html#section-6.5)).
const SDES: u8 = 202;
/// RTCP extended report packet type ([RFC 3611 section 2](https://www.rfc-editor.org/rfc/rfc3611.html#section-2)).
const XR: u8 = 207;

/// Encode one RTCP datagram as the JSON body heplify sends in HEP type 5.
///
/// heplify's `ParseRTCP` (`src/decoder/rtcp.go`, lines 109-216, at 47e9064b),
/// rule for rule. The first packet of the datagram decides everything:
///
/// - SR (200): needs 28 bytes; SSRC, sender information, then the report
///   blocks that fit.
/// - RR (201): SSRC, then the report blocks that fit.
/// - SDES (202): `sdes_ssrc` only.
/// - XR (207): SSRC, then a walk of the report blocks, where a VoIP Metrics
///   block (BT=7) fills `report_blocks_xr` and `voip_metrics`.
/// - anything else: no body.
///
/// One deliberate departure. heplify computes an XR block's length in
/// 16-bit arithmetic, so a block declaring length 0xFFFF wraps to zero bytes
/// and its loop never advances. Here the length is computed without
/// wrapping, the block is longer than any datagram, and the walk stops. That
/// input hangs heplify; it cannot hang the capture thread.
///
/// # Returns
///
/// `None` when heplify would send nothing for these bytes: fewer than 8
/// bytes, a version other than 2, a sender report under 28 bytes, or a first
/// packet that is none of SR, RR, SDES and XR.
pub fn rtcp_to_heplify_json(rtcp: &[u8]) -> Option<String> {
    if rtcp.len() < 8 || (rtcp[0] >> 6) & 0x03 != 2 {
        return None;
    }
    let report_count = rtcp[0] & 0x1f;
    let packet_type = rtcp[1];
    let mut body = Body {
        packet_type,
        report_count,
        ..Body::default()
    };
    match packet_type {
        SR => {
            if rtcp.len() < 28 {
                return None;
            }
            body.ssrc = be32(rtcp, 4);
            body.sender = [
                be32(rtcp, 8),
                be32(rtcp, 12),
                be32(rtcp, 16),
                be32(rtcp, 20),
                be32(rtcp, 24),
            ];
            body.blocks = report_blocks(rtcp, 28, report_count);
        }
        RR => {
            body.ssrc = be32(rtcp, 4);
            body.blocks = report_blocks(rtcp, 8, report_count);
        }
        SDES => body.sdes_ssrc = be32(rtcp, 4),
        XR => {
            body.ssrc = be32(rtcp, 4);
            let mut offset = 8;
            while offset + 4 <= rtcp.len() {
                let block_len = crate::rtp::rtcp::xr_block_len([
                    rtcp[offset],
                    rtcp[offset + 1],
                    rtcp[offset + 2],
                    rtcp[offset + 3],
                ]);
                if offset + block_len > rtcp.len() {
                    break;
                }
                let block = &rtcp[offset..offset + block_len];
                if block[0] == 7 && block_len >= 20 {
                    body.xr = Some(xr_summary(block));
                    if block_len >= 28 {
                        body.voip = Some(block);
                    }
                }
                offset += block_len;
            }
        }
        _ => return None,
    }
    Some(body.render())
}

/// What one RTCP datagram contributes to the JSON body; zero where heplify's
/// struct would hold its zero value.
#[derive(Default)]
struct Body<'a> {
    /// `type`.
    packet_type: u8,
    /// `report_count`: the header's count, as declared.
    report_count: u8,
    /// `ssrc`.
    ssrc: u32,
    /// `sender_information`: NTP MSW, NTP LSW, RTP timestamp, packets, octets.
    sender: [u32; 5],
    /// `report_blocks`; empty renders as `null`.
    blocks: Vec<[u32; 7]>,
    /// `report_blocks_xr`, from a VoIP Metrics block; `None` renders zeros.
    xr: Option<[u32; 10]>,
    /// The VoIP Metrics block `voip_metrics` is read from, when one held 28
    /// bytes or more.
    voip: Option<&'a [u8]>,
    /// `sdes_ssrc`.
    sdes_ssrc: u32,
}

impl Body<'_> {
    /// The JSON text, field for field in the order Go's `json.Marshal`
    /// writes heplify's struct.
    fn render(&self) -> String {
        let mut out = String::with_capacity(512);
        let [msw, lsw, rtp_ts, packets, octets] = self.sender;
        let _ = write!(
            out,
            r#"{{"sender_information":{{"ntp_timestamp_sec":{msw},"ntp_timestamp_usec":{lsw},"rtp_timestamp":{rtp_ts},"packets":{packets},"octets":{octets}}},"ssrc":{},"type":{},"report_count":{},"report_blocks":"#,
            self.ssrc, self.packet_type, self.report_count
        );
        if self.blocks.is_empty() {
            out.push_str("null");
        } else {
            out.push('[');
            for (i, [ssrc, lost, cumulative, highest, jitter, lsr, dlsr]) in
                self.blocks.iter().enumerate()
            {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(
                    out,
                    r#"{{"source_ssrc":{ssrc},"fraction_lost":{lost},"packets_lost":{cumulative},"highest_seq_no":{highest},"ia_jitter":{jitter},"lsr":{lsr},"dlsr":{dlsr}}}"#
                );
            }
            out.push(']');
        }
        let [
            kind,
            id,
            lost,
            discard,
            burst_d,
            gap_d,
            burst_ms,
            gap_ms,
            rtt,
            esd,
        ] = self.xr.unwrap_or_default();
        let _ = write!(
            out,
            r#","report_blocks_xr":{{"type":{kind},"id":{id},"fraction_lost":{lost},"fraction_discard":{discard},"burst_density":{burst_d},"gap_density":{gap_d},"burst_duration":{burst_ms},"gap_duration":{gap_ms},"round_trip_delay":{rtt},"end_system_delay":{esd}}}"#
        );
        if let Some(block) = self.voip {
            render_voip_metrics(&mut out, block);
        }
        let _ = write!(out, r#","sdes_ssrc":{}}}"#, self.sdes_ssrc);
        out
    }
}

/// heplify's `parseXRBlockV1`: the first 20 bytes of a VoIP Metrics block,
/// in `report_blocks_xr` order. The caller has checked BT=7 and the length.
fn xr_summary(block: &[u8]) -> [u32; 10] {
    [
        u32::from(block[0]),
        be32(block, 4),
        u32::from(block[8]),
        u32::from(block[9]),
        u32::from(block[10]),
        u32::from(block[11]),
        u32::from(be16(block, 12)),
        u32::from(be16(block, 14)),
        u32::from(be16(block, 16)),
        u32::from(be16(block, 18)),
    ]
}

/// heplify's `parseVoIPMetricsBlockFull` rendered as `,"voip_metrics":{...}`.
///
/// MOS is the octet over ten as a Go `float64`, which `encoding/json` writes
/// as the shortest decimal that reads back to the same value: `4.5`, `0`,
/// `25.5`. Rust's `Display` for `f64` writes the same shortest decimal, and
/// with no exponent at these magnitudes, so the two agree. The jitter-buffer
/// fields are `omitempty` in heplify: absent when zero, and zero when the
/// block is shorter than 36 bytes.
fn render_voip_metrics(out: &mut String, block: &[u8]) {
    let mos = |octet: u8| f64::from(octet) / 10.0;
    let _ = write!(
        out,
        r#","voip_metrics":{{"ssrc":{},"loss_rate":{},"discard_rate":{},"burst_density":{},"gap_density":{},"burst_duration":{},"gap_duration":{},"round_trip_delay":{},"end_system_delay":{},"signal_level":{},"noise_level":{},"rerl":{},"gmin":{},"r_factor":{},"ext_r_factor":{},"mos_cq":{},"mos_lq":{}"#,
        be32(block, 4),
        block[8],
        block[9],
        block[10],
        block[11],
        be16(block, 12),
        be16(block, 14),
        be16(block, 16),
        be16(block, 18),
        i8::from_be_bytes([block[20]]),
        i8::from_be_bytes([block[21]]),
        block[22],
        block[23],
        block[24],
        block[25],
        mos(block[26]),
        mos(block[27]),
    );
    if block.len() >= 36 {
        let tail: [(&str, u16); 4] = [
            ("rx_config", u16::from(block[28])),
            ("jb_nominal", be16(block, 30)),
            ("jb_maximum", be16(block, 32)),
            ("jb_abs_max", be16(block, 34)),
        ];
        for (name, value) in tail {
            if value != 0 {
                let _ = write!(out, r#","{name}":{value}"#);
            }
        }
    }
    out.push('}');
}

/// heplify's `parseReceiverReportBlock` for each of `count` blocks starting
/// at `offset`, stopping at the first that does not fit whole.
fn report_blocks(rtcp: &[u8], mut offset: usize, count: u8) -> Vec<[u32; 7]> {
    let mut blocks = Vec::new();
    for _ in 0..count {
        if offset + 24 > rtcp.len() {
            break;
        }
        blocks.push([
            be32(rtcp, offset),
            u32::from(rtcp[offset + 4]),
            u32::from_be_bytes([0, rtcp[offset + 5], rtcp[offset + 6], rtcp[offset + 7]]),
            be32(rtcp, offset + 8),
            be32(rtcp, offset + 12),
            be32(rtcp, offset + 16),
            be32(rtcp, offset + 20),
        ]);
        offset += 24;
    }
    blocks
}

/// The big-endian `u32` at `at`. Every caller has checked the length.
fn be32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// The big-endian `u16` at `at`. Every caller has checked the length.
fn be16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

/// A real sender report followed by SDES (CNAME "ACLTP ChannelHandle 30"),
/// as captured. heplify carries it as `benchPacket` in v1.67.1's
/// `protos/rtcp_test.go`, line 79.
#[cfg(test)]
pub(crate) const CAPTURED_SR_SDES: &[u8] = &[
    0x81, 0xc8, 0x0, 0xc, 0x58, 0xf3, 0x3d, 0xea, 0x0, 0x2, 0x4f, 0xfb, 0x82, 0x8f, 0x5b, 0x92,
    0x11, 0x4a, 0xc, 0x42, 0x0, 0x0, 0x2, 0xed, 0x0, 0x1, 0xca, 0xcf, 0xd2, 0xbd, 0x4e, 0x3e, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x0, 0x0, 0x14, 0x86, 0xe9, 0xf, 0x9d, 0x0, 0x3, 0x44,
    0xdd, 0x81, 0xca, 0x0, 0x8, 0x58, 0xf3, 0x3d, 0xea, 0x1, 0x16, 0x41, 0x43, 0x4c, 0x54, 0x50,
    0x20, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x20, 0x33,
    0x30, 0x0, 0x0, 0x0, 0x0,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// heplify v1.67.1's `testPacket` (`protos/rtcp_test.go`, lines 9-68): a
    /// receiver report, SDES, BYE, a picture loss indication and a rapid
    /// resynchronization request in one compound datagram.
    const RR_SDES_BYE_PSFB_RTPFB: &[u8] = &[
        0x81, 0xc9, 0x0, 0x7, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x46, 0xe1, 0x0, 0x0, 0x1, 0x11, 0x9, 0xf3, 0x64, 0x32, 0x0, 0x2, 0x4a, 0x79,
        0x81, 0xca, 0x0, 0xc, 0x90, 0x2f, 0x9e, 0x2e, 0x1, 0x26, 0x7b, 0x39, 0x63, 0x30, 0x30,
        0x65, 0x62, 0x39, 0x32, 0x2d, 0x31, 0x61, 0x66, 0x62, 0x2d, 0x39, 0x64, 0x34, 0x39, 0x2d,
        0x61, 0x34, 0x37, 0x64, 0x2d, 0x39, 0x31, 0x66, 0x36, 0x34, 0x65, 0x65, 0x65, 0x36, 0x39,
        0x66, 0x35, 0x7d, 0x0, 0x0, 0x0, 0x0, 0x81, 0xcb, 0x0, 0x1, 0x90, 0x2f, 0x9e, 0x2e, 0x81,
        0xce, 0x0, 0x2, 0x90, 0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e, 0x85, 0xcd, 0x0, 0x2, 0x90,
        0x2f, 0x9e, 0x2e, 0x90, 0x2f, 0x9e, 0x2e,
    ];

    /// The all-zero `report_blocks_xr` object every non-XR body carries.
    const XR_ZERO: &str = r#""report_blocks_xr":{"type":0,"id":0,"fraction_lost":0,"fraction_discard":0,"burst_density":0,"gap_density":0,"burst_duration":0,"gap_duration":0,"round_trip_delay":0,"end_system_delay":0}"#;

    /// The all-zero `sender_information` object every non-SR body carries.
    const SI_ZERO: &str = r#""sender_information":{"ntp_timestamp_sec":0,"ntp_timestamp_usec":0,"rtp_timestamp":0,"packets":0,"octets":0}"#;

    /// An RTCP XR (sender `0x01020304`) carrying one VoIP Metrics block of
    /// `block_len` bytes about `0xaabbccdd`. The same builder fed heplify's
    /// `ParseRTCP` to produce the expected strings below.
    fn xr_voip(mos_cq: u8, block_len: usize) -> Vec<u8> {
        let pkt_len = 8 + block_len;
        let mut b = vec![0u8; pkt_len];
        b[0] = 0x80;
        b[1] = XR;
        b[2..4].copy_from_slice(&((pkt_len / 4 - 1) as u16).to_be_bytes());
        b[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        let blk = &mut b[8..];
        blk[0] = 7;
        blk[2..4].copy_from_slice(&((block_len / 4 - 1) as u16).to_be_bytes());
        blk[4..8].copy_from_slice(&0xaabb_ccddu32.to_be_bytes());
        blk[8..12].copy_from_slice(&[12, 3, 40, 2]);
        blk[12..14].copy_from_slice(&120u16.to_be_bytes());
        blk[14..16].copy_from_slice(&3000u16.to_be_bytes());
        blk[16..18].copy_from_slice(&85u16.to_be_bytes());
        blk[18..20].copy_from_slice(&40u16.to_be_bytes());
        blk[20..26].copy_from_slice(&[0xEC, 0xB5, 127, 16, 87, 127]);
        blk[26] = mos_cq;
        blk[27] = 39;
        if block_len >= 36 {
            blk[28] = 1;
            blk[30..32].copy_from_slice(&50u16.to_be_bytes());
            blk[32..34].copy_from_slice(&120u16.to_be_bytes());
            blk[34..36].copy_from_slice(&200u16.to_be_bytes());
        }
        b
    }

    /// The captured report, byte for byte as heplify encodes it: the first
    /// packet (the SR) is read, the SDES behind it is not.
    #[test]
    fn a_captured_sender_report_encodes_exactly_as_heplify_does() {
        let expected = format!(
            r#"{{"sender_information":{{"ntp_timestamp_sec":151547,"ntp_timestamp_usec":2190433170,"rtp_timestamp":290065474,"packets":749,"octets":117455}},"ssrc":1492336106,"type":200,"report_count":1,"report_blocks":[{{"source_ssrc":3535621694,"fraction_lost":0,"packets_lost":0,"highest_seq_no":513,"ia_jitter":20,"lsr":2263420829,"dlsr":214237}}],{XR_ZERO},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(CAPTURED_SR_SDES).as_deref(),
            Some(expected.as_str())
        );
    }

    /// A receiver report heading a compound datagram: its one block, the
    /// sender information zeroed, and nothing from the packets behind it.
    #[test]
    fn a_receiver_report_encodes_exactly_as_heplify_does() {
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":2419039790,"type":201,"report_count":1,"report_blocks":[{{"source_ssrc":3160316480,"fraction_lost":0,"packets_lost":0,"highest_seq_no":18145,"ia_jitter":273,"lsr":166945842,"dlsr":150137}}],{XR_ZERO},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(RR_SDES_BYE_PSFB_RTPFB).as_deref(),
            Some(expected.as_str())
        );
    }

    /// A report count larger than the blocks present: heplify keeps the
    /// declared count and emits only the blocks that fit.
    #[test]
    fn a_report_count_past_the_data_keeps_the_count_and_the_blocks_that_fit() {
        let mut rr = RR_SDES_BYE_PSFB_RTPFB[..32].to_vec();
        rr[0] = 0x82;
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":2419039790,"type":201,"report_count":2,"report_blocks":[{{"source_ssrc":3160316480,"fraction_lost":0,"packets_lost":0,"highest_seq_no":18145,"ia_jitter":273,"lsr":166945842,"dlsr":150137}}],{XR_ZERO},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&rr).as_deref(),
            Some(expected.as_str())
        );
    }

    /// No report blocks is `null`, as Go marshals a nil slice; `[]` would be
    /// a different document.
    #[test]
    fn no_report_blocks_is_null_not_an_empty_array() {
        let rr = [0x80, RR, 0, 1, 0xde, 0xad, 0xbe, 0xef];
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":3735928559,"type":201,"report_count":0,"report_blocks":null,{XR_ZERO},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&rr).as_deref(),
            Some(expected.as_str())
        );

        let mut sr = vec![0u8; 28];
        sr[0] = 0x80;
        sr[1] = SR;
        sr[2..4].copy_from_slice(&6u16.to_be_bytes());
        sr[4..8].copy_from_slice(&0xd24e_3e30u32.to_be_bytes());
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":3528343088,"type":200,"report_count":0,"report_blocks":null,{XR_ZERO},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&sr).as_deref(),
            Some(expected.as_str())
        );
    }

    /// SDES first: `sdes_ssrc` set, `ssrc` zero.
    #[test]
    fn a_source_description_fills_sdes_ssrc_only() {
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":0,"type":202,"report_count":1,"report_blocks":null,{XR_ZERO},"sdes_ssrc":2419039790}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&RR_SDES_BYE_PSFB_RTPFB[32..84]).as_deref(),
            Some(expected.as_str())
        );
    }

    /// An XR VoIP Metrics block fills both `report_blocks_xr` and
    /// `voip_metrics`, with MOS as a decimal and the jitter-buffer tail.
    #[test]
    fn an_extended_report_carries_voip_metrics_as_heplify_does() {
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":16909060,"type":207,"report_count":0,"report_blocks":null,"report_blocks_xr":{{"type":7,"id":2864434397,"fraction_lost":12,"fraction_discard":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40}},"voip_metrics":{{"ssrc":2864434397,"loss_rate":12,"discard_rate":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40,"signal_level":-20,"noise_level":-75,"rerl":127,"gmin":16,"r_factor":87,"ext_r_factor":127,"mos_cq":4.5,"mos_lq":3.9,"rx_config":1,"jb_nominal":50,"jb_maximum":120,"jb_abs_max":200}},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&xr_voip(45, 36)).as_deref(),
            Some(expected.as_str())
        );
    }

    /// A full 36-byte block whose jitter-buffer tail is all zero omits those
    /// fields, as Go's `omitempty` does; it does not print them as `0`.
    #[test]
    fn zero_jitter_buffer_fields_are_omitted_as_go_omits_them() {
        let mut xr = xr_voip(45, 36);
        xr[36..44].fill(0);
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":16909060,"type":207,"report_count":0,"report_blocks":null,"report_blocks_xr":{{"type":7,"id":2864434397,"fraction_lost":12,"fraction_discard":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40}},"voip_metrics":{{"ssrc":2864434397,"loss_rate":12,"discard_rate":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40,"signal_level":-20,"noise_level":-75,"rerl":127,"gmin":16,"r_factor":87,"ext_r_factor":127,"mos_cq":4.5,"mos_lq":3.9}},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&xr).as_deref(),
            Some(expected.as_str())
        );
    }

    /// A 28-byte VoIP Metrics block has no jitter-buffer tail, so those
    /// fields are omitted; a zero MOS is still printed, as `0`.
    #[test]
    fn a_short_voip_metrics_block_omits_the_jitter_buffer_fields() {
        let expected = format!(
            r#"{{{SI_ZERO},"ssrc":16909060,"type":207,"report_count":0,"report_blocks":null,"report_blocks_xr":{{"type":7,"id":2864434397,"fraction_lost":12,"fraction_discard":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40}},"voip_metrics":{{"ssrc":2864434397,"loss_rate":12,"discard_rate":3,"burst_density":40,"gap_density":2,"burst_duration":120,"gap_duration":3000,"round_trip_delay":85,"end_system_delay":40,"signal_level":-20,"noise_level":-75,"rerl":127,"gmin":16,"r_factor":87,"ext_r_factor":127,"mos_cq":0,"mos_lq":3.9}},"sdes_ssrc":0}}"#
        );
        assert_eq!(
            rtcp_to_heplify_json(&xr_voip(0, 28)).as_deref(),
            Some(expected.as_str())
        );
    }

    /// What heplify sends nothing for, sipnab sends nothing for: a BYE first,
    /// a version other than 2, and a sender report too short to hold its
    /// sender information.
    #[test]
    fn what_heplify_will_not_encode_has_no_body() {
        let bye = &RR_SDES_BYE_PSFB_RTPFB[84..92];
        assert_eq!(rtcp_to_heplify_json(bye), None, "BYE first");
        assert_eq!(
            rtcp_to_heplify_json(&[0x41, RR, 0, 1, 0, 0, 0, 1]),
            None,
            "version 1"
        );
        assert_eq!(
            rtcp_to_heplify_json(&CAPTURED_SR_SDES[..27]),
            None,
            "a sender report one byte short of its sender information"
        );
        assert_eq!(rtcp_to_heplify_json(&[0x80, RR, 0]), None, "under 8 bytes");
    }
}
