//! Media path diagnosis for RTP streams.
//!
//! Analyzes RTP streams associated with a SIP dialog to detect common
//! VoIP issues: one-way audio, NAT traversal problems, and missing media.
//! Generates human-readable hints for each detected condition.

use std::net::IpAddr;

use super::stream::RtpStream;
use crate::sip::sdp::{SdpSession, effective_address};

/// Result of diagnosing media conditions for a dialog's RTP streams.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct MediaDiagnosis {
    /// True if audio flows in only one direction.
    pub one_way_audio: bool,
    /// True if the SDP-negotiated address differs from the observed RTP source.
    pub nat_mismatch: bool,
    /// True if SDP was negotiated but no RTP packets were observed.
    pub no_media: bool,
    /// SDP-negotiated media address string (from `c=` line).
    pub sdp_media: Option<String>,
    /// Observed RTP source address string.
    pub actual_media: Option<String>,
    /// Human-readable diagnostic hints.
    pub hints: Vec<String>,
}

/// Diagnose media path issues for a dialog's associated RTP streams.
///
/// Examines the stream list and optional SDP session to detect:
/// - **One-way audio:** Streams exist in only one direction while the dialog
///   has been established long enough for bidirectional media.
/// - **NAT mismatch:** The SDP `c=` address differs from the actual RTP
///   packet source address, indicating NAT rewriting.
/// - **No media:** SDP was negotiated but zero RTP packets have arrived.
///
/// Returns a [`MediaDiagnosis`] with boolean flags and descriptive hints.
pub fn diagnose_media(
    dialog_streams: &[&RtpStream],
    sdp_info: Option<&SdpSession>,
) -> MediaDiagnosis {
    let mut diag = MediaDiagnosis::default();

    // No media detection
    if dialog_streams.is_empty() {
        if sdp_info.is_some() {
            diag.no_media = true;
            diag.hints
                .push("SDP negotiated but zero RTP packets observed.".to_string());
        }
        return diag;
    }

    // Collect unique directed endpoints to detect one-way audio.
    // A "direction" is (src_ip, dst_ip) — if we only see one direction,
    // audio is one-way.
    let mut directions: Vec<(IpAddr, IpAddr)> = Vec::new();
    for stream in dialog_streams {
        let dir = (stream.key.src.ip(), stream.key.dst.ip());
        if !directions.contains(&dir) {
            directions.push(dir);
        }
    }

    // Check for reverse direction
    let has_bidirectional = directions
        .iter()
        .any(|(src, dst)| directions.iter().any(|(s2, d2)| s2 == dst && d2 == src));

    if !has_bidirectional && !dialog_streams.is_empty() {
        // Check if comfort noise explains the asymmetry before flagging one-way audio
        let total_cn: u32 = dialog_streams.iter().map(|s| s.cn_frames).sum();
        let total_packets: u64 = dialog_streams.iter().map(|s| s.packet_count).sum();
        let cn_suppressed = if total_cn > 0 && total_packets > 0 {
            let cn_ratio = total_cn as f64 / total_packets as f64;
            if cn_ratio > 0.3 {
                diag.hints.push(format!(
                    "Asymmetric media may be due to comfort noise ({:.0}% CN frames).",
                    cn_ratio * 100.0
                ));
                true
            } else {
                false
            }
        } else {
            false
        };

        if !cn_suppressed {
            diag.one_way_audio = true;
            if let Some(dir) = directions.first() {
                diag.hints.push(format!(
                    "RTP from {} -> {} only. No reverse media flow detected.",
                    dir.0, dir.1
                ));
            }
        }
    }

    // NAT mismatch detection: compare SDP c= address against actual RTP source
    if let Some(sdp) = sdp_info {
        for media in &sdp.media {
            if let Some(addr_str) = effective_address(media, sdp) {
                diag.sdp_media = Some(addr_str.clone());

                if let Ok(sdp_addr) = addr_str.parse::<IpAddr>() {
                    // Check if any stream's source address differs from SDP
                    for stream in dialog_streams {
                        let actual_src = stream.key.src.ip();
                        if actual_src != sdp_addr {
                            diag.nat_mismatch = true;
                            diag.actual_media = Some(actual_src.to_string());
                            diag.hints.push(format!(
                                "SDP c= address ({sdp_addr}) differs from actual RTP source ({actual_src}) \
                                 — likely NAT issue."
                            ));
                            break;
                        }
                    }
                }
            }
        }
    }

    // Combine one-way + NAT hint
    if diag.one_way_audio && diag.nat_mismatch {
        diag.hints.push(
            "One-way audio combined with NAT mismatch — media likely being sent to \
             the wrong address."
                .to_string(),
        );
    }

    diag
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use chrono::DateTime;

    use super::*;
    use crate::rtp::parser::RtpHeader;
    use crate::rtp::stream::{RtpStream, StreamKey};
    use crate::sip::sdp::{SdpConnection, SdpDirection, SdpMedia, SdpSession};

    fn ts() -> DateTime<chrono::Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid")
    }

    fn make_stream(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> RtpStream {
        let key = StreamKey {
            ssrc: 0x12345678,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_ip)), src_port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst_ip)), dst_port),
        };
        let hdr = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence: 100,
            timestamp: 0,
            ssrc: 0x12345678,
            payload_offset: 12,
        };
        let mut stream = RtpStream::new(key, &hdr, ts());
        // Simulate some packets
        for i in 1..10u16 {
            let h = RtpHeader {
                sequence: 100 + i,
                timestamp: i as u32 * 160,
                ..hdr.clone()
            };
            stream.update(&h, ts(), 160);
        }
        stream
    }

    fn make_sdp(addr: &str, port: u16) -> SdpSession {
        SdpSession {
            origin: None,
            session_name: None,
            connection: Some(SdpConnection {
                addr: addr.to_string(),
            }),
            media: vec![SdpMedia {
                media_type: "audio".to_string(),
                port,
                proto: "RTP/AVP".to_string(),
                formats: vec!["0".to_string()],
                connection: None,
                direction: SdpDirection::SendRecv,
                rtpmap: Vec::new(),
                fmtp: Vec::new(),
                ptime: None,
                crypto: Vec::new(),
                ice_candidates: Vec::new(),
            }],
        }
    }

    #[test]
    fn bidirectional_streams_no_one_way() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let s2 = make_stream([10, 0, 0, 2], [10, 0, 0, 1], 30000, 20000);
        let streams: Vec<&RtpStream> = vec![&s1, &s2];

        let diag = diagnose_media(&streams, None);
        assert!(!diag.one_way_audio);
        assert!(diag.hints.is_empty() || !diag.hints.iter().any(|h| h.contains("only")));
    }

    #[test]
    fn unidirectional_streams_flags_one_way() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, None);
        assert!(diag.one_way_audio);
        assert!(diag.hints.iter().any(|h| h.contains("only")));
    }

    #[test]
    fn sdp_address_differs_from_actual_flags_nat() {
        // SDP says 192.168.1.100, but actual RTP source is 10.0.0.1
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("192.168.1.100", 20000);

        let diag = diagnose_media(&streams, Some(&sdp));
        assert!(diag.nat_mismatch);
        assert_eq!(diag.sdp_media.as_deref(), Some("192.168.1.100"));
        assert_eq!(diag.actual_media.as_deref(), Some("10.0.0.1"));
        assert!(diag.hints.iter().any(|h| h.contains("NAT")));
    }

    #[test]
    fn sdp_address_matches_no_nat_flag() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("10.0.0.1", 20000);

        let diag = diagnose_media(&streams, Some(&sdp));
        assert!(!diag.nat_mismatch);
    }

    #[test]
    fn no_rtp_with_sdp_flags_no_media() {
        let streams: Vec<&RtpStream> = vec![];
        let sdp = make_sdp("10.0.0.1", 20000);

        let diag = diagnose_media(&streams, Some(&sdp));
        assert!(diag.no_media);
        assert!(diag.hints.iter().any(|h| h.contains("zero RTP")));
    }

    #[test]
    fn no_streams_no_sdp_is_clean() {
        let streams: Vec<&RtpStream> = vec![];
        let diag = diagnose_media(&streams, None);
        assert!(!diag.no_media);
        assert!(!diag.one_way_audio);
        assert!(!diag.nat_mismatch);
        assert!(diag.hints.is_empty());
    }

    #[test]
    fn comfort_noise_suppresses_one_way_audio() {
        // Create a unidirectional stream with high CN ratio (>30%)
        let mut s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        // packet_count is 10 (initial + 9 updates), set cn_frames > 30%
        s1.cn_frames = 5; // 5/10 = 50% CN
        let streams: Vec<&RtpStream> = vec![&s1];

        let diag = diagnose_media(&streams, None);
        // With high CN ratio, one_way_audio should NOT be flagged
        assert!(!diag.one_way_audio, "one_way_audio should be suppressed by comfort noise");
        assert!(
            diag.hints.iter().any(|h| h.contains("comfort noise")),
            "hints should mention comfort noise: {:?}",
            diag.hints
        );
    }

    #[test]
    fn one_way_plus_nat_gives_combined_hint() {
        let s1 = make_stream([10, 0, 0, 1], [10, 0, 0, 2], 20000, 30000);
        let streams: Vec<&RtpStream> = vec![&s1];
        let sdp = make_sdp("192.168.1.100", 20000);

        let diag = diagnose_media(&streams, Some(&sdp));
        assert!(diag.one_way_audio);
        assert!(diag.nat_mismatch);
        assert!(diag.hints.iter().any(|h| h.contains("wrong address")));
    }
}
