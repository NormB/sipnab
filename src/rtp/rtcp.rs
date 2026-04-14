//! RTCP packet parser (RFC 3550).
//!
//! Parses compound RTCP packets from a single UDP payload. Handles
//! Sender Reports (SR, PT=200), Receiver Reports (RR, PT=201), and
//! BYE (PT=203). Unknown packet types are preserved as [`RtcpPacket::Unknown`]
//! so the parser never silently drops data.

use anyhow::{Result, ensure};

// ── RTCP packet types ────────────────────────────────────────────────

/// RTCP packet type: Sender Report.
const RTCP_PT_SR: u8 = 200;
/// RTCP packet type: Receiver Report.
const RTCP_PT_RR: u8 = 201;
/// RTCP packet type: BYE.
const RTCP_PT_BYE: u8 = 203;
/// RTCP Extended Report (RFC 3611).
const RTCP_PT_XR: u8 = 207;

// ── Public types ─────────────────────────────────────────────────────

/// A single RTCP packet within a compound RTCP payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    /// Sender Report (PT=200).
    SenderReport(SenderReport),
    /// Receiver Report (PT=201).
    ReceiverReport(ReceiverReport),
    /// BYE (PT=203).
    Bye(RtcpBye),
    /// Extended Report (PT=207, RFC 3611).
    ExtendedReport(ExtendedReport),
    /// Unrecognized RTCP packet type, preserved for completeness.
    Unknown {
        /// The unrecognized packet type value.
        packet_type: u8,
    },
}

/// RTCP Sender Report (RFC 3550 Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    /// SSRC of the sender.
    pub ssrc: u32,
    /// NTP timestamp (64-bit wallclock time).
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to the NTP timestamp.
    pub rtp_timestamp: u32,
    /// Total number of RTP data packets sent.
    pub packet_count: u32,
    /// Total number of payload octets sent.
    pub octet_count: u32,
    /// Reception report blocks from this sender.
    pub reports: Vec<ReceptionReport>,
}

/// RTCP Receiver Report (RFC 3550 Section 6.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    /// SSRC of the receiver generating this report.
    pub ssrc: u32,
    /// Reception report blocks.
    pub reports: Vec<ReceptionReport>,
}

/// A single reception report block (shared by SR and RR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReport {
    /// SSRC of the source being reported about.
    pub ssrc: u32,
    /// Fraction of packets lost since last report (0-255).
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24-bit signed, stored as u32).
    pub cumulative_lost: u32,
    /// Extended highest sequence number received.
    pub highest_seq: u32,
    /// Interarrival jitter estimate.
    pub jitter: u32,
    /// Last SR timestamp (middle 32 bits of NTP from last SR received).
    pub last_sr: u32,
    /// Delay since last SR in 1/65536 second units.
    pub delay_since_sr: u32,
}

/// RTCP BYE packet (RFC 3550 Section 6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpBye {
    /// List of SSRCs leaving the session.
    pub ssrc_list: Vec<u32>,
}

/// RTCP Extended Report (RFC 3611).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedReport {
    /// SSRC of the XR originator.
    pub ssrc: u32,
    /// Report blocks.
    pub blocks: Vec<XrBlock>,
}

/// RTCP XR report block types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrBlock {
    /// VoIP Metrics Report Block (BT=7, RFC 3611 Section 4.7).
    VoipMetrics(VoipMetrics),
    /// Receiver Reference Time (BT=4).
    ReceiverReferenceTime {
        /// NTP timestamp (64-bit).
        ntp_timestamp: u64,
    },
    /// Loss RLE (BT=1).
    LossRle {
        /// SSRC of the source being reported.
        ssrc: u32,
        /// Raw RLE data.
        data: Vec<u8>,
    },
    /// Duplicate RLE (BT=2).
    DuplicateRle {
        /// SSRC of the source being reported.
        ssrc: u32,
        /// Raw RLE data.
        data: Vec<u8>,
    },
    /// Unknown block type.
    Unknown {
        /// The unrecognized block type value.
        block_type: u8,
    },
}

/// VoIP Metrics Report Block (RFC 3611 Section 4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoipMetrics {
    /// SSRC of the source being reported.
    pub ssrc: u32,
    /// Fraction of RTP data packets lost (0-255).
    pub loss_rate: u8,
    /// Fraction of RTP data packets discarded (0-255).
    pub discard_rate: u8,
    /// Fraction of RTP data packets within burst periods (0-255).
    pub burst_density: u8,
    /// Fraction of RTP data packets within gap periods (0-255).
    pub gap_density: u8,
    /// Mean duration of burst periods (ms).
    pub burst_duration: u16,
    /// Mean duration of gap periods (ms).
    pub gap_duration: u16,
    /// Round trip delay (ms).
    pub round_trip_delay: u16,
    /// End system delay (ms).
    pub end_system_delay: u16,
    /// Voice signal relative level (dBm0).
    pub signal_level: u8,
    /// Noise level (dBm0).
    pub noise_level: u8,
    /// Residual echo return loss (dB).
    pub rerl: u8,
    /// Gap threshold.
    pub gmin: u8,
    /// Voice quality R factor.
    pub r_factor: u8,
    /// External R factor.
    pub ext_r_factor: u8,
    /// MOS for listening quality (x10).
    pub mos_lq: u8,
    /// MOS for conversational quality (x10).
    pub mos_cq: u8,
    /// Nominal jitter buffer delay (ms).
    pub jb_nominal: u16,
    /// Maximum jitter buffer delay (ms).
    pub jb_maximum: u16,
    /// Absolute maximum jitter buffer delay (ms).
    pub jb_abs_max: u16,
}

// ── Parser ───────────────────────────────────────────────────────────

/// Minimum RTCP packet header: version/padding/count(1) + PT(1) + length(2).
const RTCP_HEADER_LEN: usize = 4;

/// Parse a compound RTCP payload into individual packets.
///
/// RTCP packets are compound: a single UDP datagram may contain multiple
/// RTCP packets concatenated back-to-back. This function iterates through
/// the payload, parsing each sub-packet. Malformed trailing bytes are
/// silently skipped (real-world RTCP sometimes has padding).
///
/// Returns an empty `Vec` if no valid RTCP packets are found.
pub fn parse_rtcp(data: &[u8]) -> Vec<RtcpPacket> {
    let mut packets = Vec::new();
    let mut offset = 0;

    while offset + RTCP_HEADER_LEN <= data.len() {
        let byte0 = data[offset];
        let version = (byte0 >> 6) & 0x03;
        if version != 2 {
            break; // Not RTCP or corrupt — stop iteration
        }
        let count = (byte0 & 0x1F) as usize;
        let packet_type = data[offset + 1];
        let length_field = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let packet_len = (length_field + 1) * 4; // length is in 32-bit words minus one

        if offset + packet_len > data.len() {
            break; // Truncated — stop
        }

        let pkt_data = &data[offset..offset + packet_len];

        match packet_type {
            RTCP_PT_SR => {
                if let Ok(sr) = parse_sender_report(pkt_data, count) {
                    packets.push(RtcpPacket::SenderReport(sr));
                }
            }
            RTCP_PT_RR => {
                if let Ok(rr) = parse_receiver_report(pkt_data, count) {
                    packets.push(RtcpPacket::ReceiverReport(rr));
                }
            }
            RTCP_PT_BYE => {
                if let Ok(bye) = parse_bye(pkt_data, count) {
                    packets.push(RtcpPacket::Bye(bye));
                }
            }
            RTCP_PT_XR => {
                if let Ok(xr) = parse_extended_report(pkt_data) {
                    packets.push(RtcpPacket::ExtendedReport(xr));
                }
            }
            _ => {
                packets.push(RtcpPacket::Unknown { packet_type });
            }
        }

        offset += packet_len;
    }

    packets
}

/// Parse reception report blocks starting at the given offset.
fn parse_report_blocks(data: &[u8], offset: usize, count: usize) -> Result<Vec<ReceptionReport>> {
    let mut reports = Vec::with_capacity(count);
    let mut pos = offset;

    for _ in 0..count {
        ensure!(
            pos + 24 <= data.len(),
            "Reception report block truncated at offset {pos}"
        );

        let ssrc = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let fraction_lost = data[pos + 4];
        // Cumulative lost is 24-bit signed, stored in bytes 5..8
        let cumulative_lost = u32::from_be_bytes([0, data[pos + 5], data[pos + 6], data[pos + 7]]);
        let highest_seq =
            u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
        let jitter = u32::from_be_bytes([
            data[pos + 12],
            data[pos + 13],
            data[pos + 14],
            data[pos + 15],
        ]);
        let last_sr = u32::from_be_bytes([
            data[pos + 16],
            data[pos + 17],
            data[pos + 18],
            data[pos + 19],
        ]);
        let delay_since_sr = u32::from_be_bytes([
            data[pos + 20],
            data[pos + 21],
            data[pos + 22],
            data[pos + 23],
        ]);

        reports.push(ReceptionReport {
            ssrc,
            fraction_lost,
            cumulative_lost,
            highest_seq,
            jitter,
            last_sr,
            delay_since_sr,
        });

        pos += 24;
    }

    Ok(reports)
}

/// Parse Sender Report body (after the 4-byte RTCP header).
fn parse_sender_report(data: &[u8], report_count: usize) -> Result<SenderReport> {
    // SR: 4 header + 4 SSRC + 20 sender info + N*24 report blocks
    let min_len = 4 + 4 + 20 + report_count * 24;
    ensure!(
        data.len() >= min_len,
        "SR too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ntp_hi = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let ntp_lo = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let ntp_timestamp = ((ntp_hi as u64) << 32) | (ntp_lo as u64);
    let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

    let reports = parse_report_blocks(data, 28, report_count)?;

    Ok(SenderReport {
        ssrc,
        ntp_timestamp,
        rtp_timestamp,
        packet_count,
        octet_count,
        reports,
    })
}

/// Parse Receiver Report body (after the 4-byte RTCP header).
fn parse_receiver_report(data: &[u8], report_count: usize) -> Result<ReceiverReport> {
    // RR: 4 header + 4 SSRC + N*24 report blocks
    let min_len = 4 + 4 + report_count * 24;
    ensure!(
        data.len() >= min_len,
        "RR too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let reports = parse_report_blocks(data, 8, report_count)?;

    Ok(ReceiverReport { ssrc, reports })
}

/// Parse BYE packet body (after the 4-byte RTCP header).
fn parse_bye(data: &[u8], ssrc_count: usize) -> Result<RtcpBye> {
    let min_len = 4 + ssrc_count * 4;
    ensure!(
        data.len() >= min_len,
        "BYE too short: {} bytes, need at least {min_len}",
        data.len()
    );

    let mut ssrc_list = Vec::with_capacity(ssrc_count);
    for i in 0..ssrc_count {
        let pos = 4 + i * 4;
        let ssrc = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        ssrc_list.push(ssrc);
    }

    Ok(RtcpBye { ssrc_list })
}

/// Parse Extended Report body (RFC 3611).
fn parse_extended_report(data: &[u8]) -> Result<ExtendedReport> {
    ensure!(data.len() >= 8, "XR too short: {} bytes", data.len());

    let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let mut blocks = Vec::new();
    let mut pos = 8;

    while pos + 4 <= data.len() {
        let block_type = data[pos];
        let block_length = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize * 4;

        if pos + 4 + block_length > data.len() {
            break;
        }

        let block_data = &data[pos + 4..pos + 4 + block_length];

        let block = match block_type {
            7 if block_length >= 32 => match parse_voip_metrics(block_data) {
                Ok(vm) => XrBlock::VoipMetrics(vm),
                Err(_) => XrBlock::Unknown { block_type },
            },
            4 if block_length >= 8 => {
                let ntp = u64::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                    block_data[4],
                    block_data[5],
                    block_data[6],
                    block_data[7],
                ]);
                XrBlock::ReceiverReferenceTime {
                    ntp_timestamp: ntp,
                }
            }
            1 if block_length >= 4 => {
                let rle_ssrc = u32::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                ]);
                XrBlock::LossRle {
                    ssrc: rle_ssrc,
                    data: block_data[4..].to_vec(),
                }
            }
            2 if block_length >= 4 => {
                let rle_ssrc = u32::from_be_bytes([
                    block_data[0],
                    block_data[1],
                    block_data[2],
                    block_data[3],
                ]);
                XrBlock::DuplicateRle {
                    ssrc: rle_ssrc,
                    data: block_data[4..].to_vec(),
                }
            }
            _ => XrBlock::Unknown { block_type },
        };

        blocks.push(block);
        pos += 4 + block_length;
    }

    Ok(ExtendedReport { ssrc, blocks })
}

/// Parse VoIP Metrics report block data (RFC 3611 Section 4.7).
fn parse_voip_metrics(data: &[u8]) -> Result<VoipMetrics> {
    ensure!(
        data.len() >= 32,
        "VoIP Metrics block too short: {} bytes",
        data.len()
    );
    Ok(VoipMetrics {
        ssrc: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        loss_rate: data[4],
        discard_rate: data[5],
        burst_density: data[6],
        gap_density: data[7],
        burst_duration: u16::from_be_bytes([data[8], data[9]]),
        gap_duration: u16::from_be_bytes([data[10], data[11]]),
        round_trip_delay: u16::from_be_bytes([data[12], data[13]]),
        end_system_delay: u16::from_be_bytes([data[14], data[15]]),
        signal_level: data[16],
        noise_level: data[17],
        rerl: data[18],
        gmin: data[19],
        r_factor: data[20],
        ext_r_factor: data[21],
        mos_lq: data[22],
        mos_cq: data[23],
        jb_nominal: u16::from_be_bytes([data[24], data[25]]),
        jb_maximum: u16::from_be_bytes([data[26], data[27]]),
        jb_abs_max: u16::from_be_bytes([data[28], data[29]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Sender Report RTCP packet.
    fn build_sr(ssrc: u32, ntp: u64, rtp_ts: u32, pkt_count: u32, oct_count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        // Header: V=2, P=0, RC=0, PT=200
        data.push(0x80); // V=2, P=0, RC=0
        data.push(200); // PT=SR
        // Length: (28 - 4) / 4 = 6
        data.extend_from_slice(&6u16.to_be_bytes());
        data.extend_from_slice(&ssrc.to_be_bytes());
        data.extend_from_slice(&((ntp >> 32) as u32).to_be_bytes());
        data.extend_from_slice(&((ntp & 0xFFFFFFFF) as u32).to_be_bytes());
        data.extend_from_slice(&rtp_ts.to_be_bytes());
        data.extend_from_slice(&pkt_count.to_be_bytes());
        data.extend_from_slice(&oct_count.to_be_bytes());
        data
    }

    /// Build a Receiver Report RTCP packet with one report block.
    fn build_rr_with_report(
        reporter_ssrc: u32,
        source_ssrc: u32,
        fraction_lost: u8,
        jitter: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        // Header: V=2, P=0, RC=1, PT=201
        data.push(0x81); // V=2, P=0, RC=1
        data.push(201); // PT=RR
        // Length: (8 + 24 - 4) / 4 = 7
        data.extend_from_slice(&7u16.to_be_bytes());
        data.extend_from_slice(&reporter_ssrc.to_be_bytes());
        // Report block
        data.extend_from_slice(&source_ssrc.to_be_bytes());
        data.push(fraction_lost);
        data.extend_from_slice(&[0x00, 0x00, 0x05]); // cumulative lost = 5
        data.extend_from_slice(&1000u32.to_be_bytes()); // highest seq
        data.extend_from_slice(&jitter.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // last SR
        data.extend_from_slice(&0u32.to_be_bytes()); // delay since SR
        data
    }

    /// Build a BYE RTCP packet.
    fn build_bye(ssrcs: &[u32]) -> Vec<u8> {
        let mut data = Vec::new();
        let rc = ssrcs.len() as u8;
        data.push(0x80 | rc); // V=2, P=0, RC
        data.push(203); // PT=BYE
        let length = ssrcs.len() as u16; // (4 + N*4 - 4) / 4 = N
        data.extend_from_slice(&length.to_be_bytes());
        for ssrc in ssrcs {
            data.extend_from_slice(&ssrc.to_be_bytes());
        }
        data
    }

    #[test]
    fn parse_sender_report_basic() {
        let data = build_sr(0xAABBCCDD, 0x1122334455667788, 160000, 100, 16000);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::SenderReport(sr) => {
                assert_eq!(sr.ssrc, 0xAABBCCDD);
                assert_eq!(sr.ntp_timestamp, 0x1122334455667788);
                assert_eq!(sr.rtp_timestamp, 160000);
                assert_eq!(sr.packet_count, 100);
                assert_eq!(sr.octet_count, 16000);
                assert!(sr.reports.is_empty());
            }
            other => panic!("Expected SenderReport, got {other:?}"),
        }
    }

    #[test]
    fn parse_receiver_report_with_block() {
        let data = build_rr_with_report(0x11111111, 0x22222222, 25, 320);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::ReceiverReport(rr) => {
                assert_eq!(rr.ssrc, 0x11111111);
                assert_eq!(rr.reports.len(), 1);
                let r = &rr.reports[0];
                assert_eq!(r.ssrc, 0x22222222);
                assert_eq!(r.fraction_lost, 25);
                assert_eq!(r.jitter, 320);
                assert_eq!(r.cumulative_lost, 5);
                assert_eq!(r.highest_seq, 1000);
            }
            other => panic!("Expected ReceiverReport, got {other:?}"),
        }
    }

    #[test]
    fn parse_bye_multiple_ssrcs() {
        let data = build_bye(&[0xAAAAAAAA, 0xBBBBBBBB]);
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);

        match &packets[0] {
            RtcpPacket::Bye(bye) => {
                assert_eq!(bye.ssrc_list, vec![0xAAAAAAAA, 0xBBBBBBBB]);
            }
            other => panic!("Expected Bye, got {other:?}"),
        }
    }

    #[test]
    fn parse_compound_sr_plus_rr() {
        let mut data = build_sr(0x10, 0, 0, 50, 8000);
        data.extend_from_slice(&build_rr_with_report(0x20, 0x10, 10, 100));
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 2);

        assert!(matches!(&packets[0], RtcpPacket::SenderReport(_)));
        assert!(matches!(&packets[1], RtcpPacket::ReceiverReport(_)));
    }

    #[test]
    fn empty_data_returns_empty() {
        let packets = parse_rtcp(&[]);
        assert!(packets.is_empty());
    }

    #[test]
    fn truncated_packet_stops_cleanly() {
        // Valid SR header but truncated body
        let data = [0x80, 200, 0x00, 0x06, 0x00]; // Length says 28 bytes but only 5
        let packets = parse_rtcp(&data);
        assert!(packets.is_empty());
    }

    #[test]
    fn unknown_packet_type_preserved() {
        let mut data = Vec::new();
        data.push(0x80); // V=2
        data.push(210); // Unknown PT
        data.extend_from_slice(&0u16.to_be_bytes()); // length=0 → 4 bytes total
        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);
        assert!(matches!(
            &packets[0],
            RtcpPacket::Unknown { packet_type: 210 }
        ));
    }

    #[test]
    fn parse_xr_voip_metrics() {
        // Build a minimal XR packet with VoIP Metrics block
        let mut data = Vec::new();
        // RTCP header: V=2, P=0, reserved=0, PT=207, length=10 (44 bytes total)
        data.push(0x80); // V=2, P=0, count=0
        data.push(207); // PT=XR
        data.extend_from_slice(&10u16.to_be_bytes()); // length in 32-bit words minus 1
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // SSRC

        // XR block: BT=7 (VoIP Metrics), type-specific=0, length=8 (32 bytes)
        data.push(7); // block type
        data.push(0); // type-specific
        data.extend_from_slice(&8u16.to_be_bytes()); // block length in 32-bit words

        // VoIP Metrics data (32 bytes)
        data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // SSRC
        data.push(10); // loss_rate
        data.push(5); // discard_rate
        data.push(20); // burst_density
        data.push(15); // gap_density
        data.extend_from_slice(&100u16.to_be_bytes()); // burst_duration
        data.extend_from_slice(&200u16.to_be_bytes()); // gap_duration
        data.extend_from_slice(&50u16.to_be_bytes()); // round_trip_delay
        data.extend_from_slice(&25u16.to_be_bytes()); // end_system_delay
        data.push(128); // signal_level
        data.push(64); // noise_level
        data.push(32); // rerl
        data.push(16); // gmin
        data.push(80); // r_factor
        data.push(70); // ext_r_factor
        data.push(35); // mos_lq
        data.push(40); // mos_cq
        data.extend_from_slice(&60u16.to_be_bytes()); // jb_nominal
        data.extend_from_slice(&80u16.to_be_bytes()); // jb_maximum
        data.extend_from_slice(&120u16.to_be_bytes()); // jb_abs_max
        // Pad to full block (30 bytes of metrics data + 2 padding = 32)
        data.extend_from_slice(&[0, 0]);

        let packets = parse_rtcp(&data);
        assert_eq!(packets.len(), 1);
        match &packets[0] {
            RtcpPacket::ExtendedReport(xr) => {
                assert_eq!(xr.ssrc, 0x12345678);
                assert_eq!(xr.blocks.len(), 1);
                match &xr.blocks[0] {
                    XrBlock::VoipMetrics(vm) => {
                        assert_eq!(vm.ssrc, 0xAABBCCDD);
                        assert_eq!(vm.loss_rate, 10);
                        assert_eq!(vm.r_factor, 80);
                        assert_eq!(vm.mos_lq, 35);
                    }
                    other => panic!("Expected VoipMetrics, got {:?}", other),
                }
            }
            other => panic!("Expected ExtendedReport, got {:?}", other),
        }
    }

    #[test]
    fn parse_xr_truncated() {
        // XR with header but SSRC field would be at bytes 4..8, which is missing
        // Length=0 means total packet = 4 bytes (just the header)
        let data = vec![0x80, 207, 0, 0];
        let packets = parse_rtcp(&data);
        // parse_extended_report requires >= 8 bytes, so this should fail silently
        assert!(
            packets.is_empty()
                || packets
                    .iter()
                    .all(|p| !matches!(p, RtcpPacket::ExtendedReport(_)))
        );
    }
}
