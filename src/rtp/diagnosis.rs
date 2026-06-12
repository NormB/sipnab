//! Media path diagnosis for RTP streams.
//!
//! Analyzes RTP streams associated with a SIP dialog to detect common
//! VoIP issues: one-way audio, NAT traversal problems, missing media,
//! and (Phase 8.7) per-call asymmetry signals — codec/ptime/payload-type
//! mismatches across the two legs, duration asymmetry, and late media.
//! Generates human-readable hints for each detected condition.

use std::net::IpAddr;

use super::stream::RtpStream;
use crate::sip::dialog::SipDialog;
use crate::sip::sdp::{SdpSession, effective_address};

/// Codec asymmetry — A leg uses one codec, B leg uses another.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CodecAsymmetry {
    pub a_codec: String,
    pub b_codec: String,
}

/// Packetization-time asymmetry — A leg sends 20 ms frames, B leg 30 ms (etc.).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PtimeAsymmetry {
    pub a_ptime_ms: u32,
    pub b_ptime_ms: u32,
}

/// Payload-type asymmetry — same negotiated codec, different RTP PTs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PayloadTypeAsymmetry {
    pub a_pt: u8,
    pub b_pt: u8,
}

/// Duration asymmetry — one leg's stream lasted noticeably longer than the other.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DurationAsymmetry {
    pub a_duration_sec: f64,
    pub b_duration_sec: f64,
    pub delta_sec: f64,
}

/// Late media — RTP for a leg started significantly after the 200 OK.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LateMedia {
    /// "a" or "b" identifying which leg was late.
    pub leg: String,
    pub delay_after_200_ok_ms: i64,
}

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

    // ── Phase 8.7: per-call asymmetry signals ──
    /// Codec mismatch across the two legs of the call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codec_asymmetry: Option<CodecAsymmetry>,
    /// Packetization-time mismatch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptime_asymmetry: Option<PtimeAsymmetry>,
    /// Payload-type mismatch (same codec negotiated, different PTs observed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_type_asymmetry: Option<PayloadTypeAsymmetry>,
    /// Duration mismatch between the two legs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_asymmetry: Option<DurationAsymmetry>,
    /// Media that started long after the 200 OK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub late_media: Option<LateMedia>,
}

/// Threshold knobs for the asymmetry detectors. Values are chosen to match
/// industry-standard triage signals without being so tight they false-positive
/// on healthy calls.
#[derive(Debug, Clone)]
pub struct AsymmetryThresholds {
    /// Minimum percentage delta between leg durations to flag (default 5%).
    pub duration_pct_delta: f64,
    /// Minimum absolute delta between leg durations to flag (default 2.0 s).
    pub duration_min_delta_sec: f64,
    /// Late-media trigger threshold in milliseconds after 200 OK (default 500).
    pub late_media_threshold_ms: i64,
}

impl Default for AsymmetryThresholds {
    fn default() -> Self {
        Self {
            duration_pct_delta: 5.0,
            duration_min_delta_sec: 2.0,
            late_media_threshold_ms: 500,
        }
    }
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

/// Phase 8.7 — per-call asymmetry checks comparing the two RTP legs of a
/// SIP call. Mutates `diag` in place; returns nothing. Each check sets a
/// `Some(_)` field when an asymmetry is detected and leaves the field
/// `None` otherwise. Callers obtain a diagnosis via [`diagnose_media`]
/// first, then enrich it with this function.
///
/// `dialog` is used only for the `late_media` check (needs `answered_at`).
/// Pass `None` to skip that check.
///
/// "A leg" / "B leg" pairing: if there are exactly two streams, the first
/// in the slice is A, the second is B. If there's a clear bidirectional
/// pair (src/dst swap), they're paired and ordered by `first_seen`. With
/// 0 or 1 stream, no asymmetry is computed.
pub fn diagnose_asymmetry(
    diag: &mut MediaDiagnosis,
    dialog: Option<&SipDialog>,
    dialog_streams: &[&RtpStream],
    thresholds: &AsymmetryThresholds,
) {
    // Need at least two streams to compare.
    let (a, b) = match pick_leg_pair(dialog_streams) {
        Some(pair) => pair,
        None => return,
    };

    // ── Codec asymmetry ────────────────────────────────────────────
    if let (Some(ac), Some(bc)) = (a.codec.as_deref(), b.codec.as_deref())
        && ac != bc
    {
        diag.codec_asymmetry = Some(CodecAsymmetry {
            a_codec: ac.to_string(),
            b_codec: bc.to_string(),
        });
        diag.hints.push(format!(
            "Codec asymmetry: A leg uses {ac}, B leg uses {bc} — likely a \
             transcoding B2BUA on the path."
        ));
    }

    // ── Payload-type asymmetry ─────────────────────────────────────
    // Only meaningful when codecs match but PTs differ (otherwise a codec
    // asymmetry already explains the PT mismatch).
    if a.payload_type != b.payload_type && a.codec.is_some() && a.codec == b.codec {
        diag.payload_type_asymmetry = Some(PayloadTypeAsymmetry {
            a_pt: a.payload_type,
            b_pt: b.payload_type,
        });
        diag.hints.push(format!(
            "Payload-type asymmetry: same codec, different PTs ({} vs {}) — \
             middlebox rewriting or SDP/answer mismatch.",
            a.payload_type, b.payload_type
        ));
    }

    // ── Ptime asymmetry ────────────────────────────────────────────
    let a_ptime = inferred_ptime_ms(a);
    let b_ptime = inferred_ptime_ms(b);
    if let (Some(ap), Some(bp)) = (a_ptime, b_ptime) {
        // Allow 2 ms slack to absorb wall-clock jitter on inter-arrival
        // measurements; SDP-derived ptimes are exact.
        if ap.abs_diff(bp) > 2 {
            diag.ptime_asymmetry = Some(PtimeAsymmetry {
                a_ptime_ms: ap,
                b_ptime_ms: bp,
            });
            diag.hints.push(format!(
                "Ptime asymmetry: {ap} ms vs {bp} ms — different framing per leg."
            ));
        }
    }

    // ── Duration asymmetry ─────────────────────────────────────────
    let a_dur = stream_duration_sec(a);
    let b_dur = stream_duration_sec(b);
    let delta = (a_dur - b_dur).abs();
    let max_dur = a_dur.max(b_dur).max(0.001); // avoid div-by-zero
    let pct_delta = (delta / max_dur) * 100.0;
    if delta >= thresholds.duration_min_delta_sec && pct_delta >= thresholds.duration_pct_delta {
        diag.duration_asymmetry = Some(DurationAsymmetry {
            a_duration_sec: a_dur,
            b_duration_sec: b_dur,
            delta_sec: delta,
        });
        diag.hints.push(format!(
            "Duration asymmetry: A leg lasted {a_dur:.1}s, B leg {b_dur:.1}s \
             (Δ {delta:.1}s) — one side may have hung up or dropped media early."
        ));
    }

    // ── Late media ─────────────────────────────────────────────────
    if let Some(d) = dialog
        && let Some(answered) = d.timing.answered_at
    {
        // Earliest first_seen among the two legs is the start of media.
        let media_start = a.first_seen.min(b.first_seen);
        let delay_ms = (media_start - answered).num_milliseconds();
        if delay_ms > thresholds.late_media_threshold_ms {
            let leg = if a.first_seen <= b.first_seen {
                "a"
            } else {
                "b"
            };
            diag.late_media = Some(LateMedia {
                leg: leg.to_string(),
                delay_after_200_ok_ms: delay_ms,
            });
            diag.hints.push(format!(
                "Late media: RTP started {delay_ms} ms after 200 OK — far end \
                 was slow to send, or the media path wasn't ready when signalling \
                 completed."
            ));
        }
    }
}

/// Pick the two legs of a dialog. With exactly two streams, return them
/// ordered by `first_seen` (A leg = earliest). With more streams, pick the
/// two that form a bidirectional pair (src↔dst), again ordered by
/// `first_seen`. Returns `None` when no valid pair exists.
fn pick_leg_pair<'a>(streams: &[&'a RtpStream]) -> Option<(&'a RtpStream, &'a RtpStream)> {
    if streams.len() < 2 {
        return None;
    }
    if streams.len() == 2 {
        let mut ordered = [streams[0], streams[1]];
        ordered.sort_by_key(|s| s.first_seen);
        return Some((ordered[0], ordered[1]));
    }
    // Look for a bidirectional pair.
    for (i, a) in streams.iter().enumerate() {
        for b in streams.iter().skip(i + 1) {
            if a.key.src.ip() == b.key.dst.ip() && a.key.dst.ip() == b.key.src.ip() {
                let mut pair = [*a, *b];
                pair.sort_by_key(|s| s.first_seen);
                return Some((pair[0], pair[1]));
            }
        }
    }
    None
}

/// Infer ptime in ms from a stream's RTP timestamp progression.
///
/// Each RTP packet's timestamp moves forward by `samples_per_frame`. With
/// the stream's clock rate we get ms/frame = (samples_per_frame /
/// clock_rate) * 1000. We need at least two timestamps to estimate.
fn inferred_ptime_ms(s: &RtpStream) -> Option<u32> {
    if s.packet_count < 2 {
        return None;
    }
    let total_packets = s.packet_count;
    let dur = (s.last_seen - s.first_seen).num_milliseconds() as f64;
    if dur <= 0.0 {
        return None;
    }
    let avg_ms = dur / (total_packets - 1) as f64;
    if !(5.0..=200.0).contains(&avg_ms) {
        return None;
    }
    // Round to the nearest 10 ms which is the standard quantization for
    // packetization (10/20/30/40 ms are the only realistic values).
    let rounded = ((avg_ms / 10.0).round() * 10.0) as u32;
    Some(rounded)
}

/// Wall-clock duration of a stream in seconds.
fn stream_duration_sec(s: &RtpStream) -> f64 {
    let ms = (s.last_seen - s.first_seen).num_milliseconds();
    ms as f64 / 1000.0
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
        assert!(
            !diag.one_way_audio,
            "one_way_audio should be suppressed by comfort noise"
        );
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

    // ── Phase 8.7 — asymmetry tests ─────────────────────────────────

    /// Build a stream with explicit codec / payload type / timestamp progression
    /// so the asymmetry tests can assemble realistic-looking pairs.
    fn make_stream_with_pt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        pt: u8,
        codec: &str,
        clock_rate: u32,
        ptime_ms: u32,
        first_seen_offset_secs: i64,
        packet_count: u64,
    ) -> RtpStream {
        let key = StreamKey {
            ssrc: 0xABCDEF00 ^ pt as u32,
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(src_ip)), 20000),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(dst_ip)), 30000),
        };
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: pt,
            sequence: 100,
            timestamp: 0,
            ssrc: key.ssrc,
            payload_offset: 12,
        };
        let first_seen = ts() + chrono::Duration::seconds(first_seen_offset_secs);
        let mut s = RtpStream::new(key, &header, first_seen);
        s.codec = Some(codec.to_string());
        s.clock_rate = clock_rate;
        s.packet_count = packet_count;
        // Inferred ptime depends on (last_seen - first_seen) / (packet_count-1)
        let span_ms = ptime_ms as i64 * (packet_count as i64 - 1).max(1);
        s.last_seen = first_seen + chrono::Duration::milliseconds(span_ms);
        s
    }

    fn make_dialog_with_answer(secs_after_epoch: i64) -> SipDialog {
        use crate::sip::SipMessage;
        use crate::sip::message::SipHeader;
        use crate::sip::method::SipMethod;
        use std::borrow::Cow;
        let mk_hdr = |name: &'static str, value: &str| SipHeader {
            name: Cow::Borrowed(name),
            value: value.to_string(),
        };
        let invite = SipMessage {
            timestamp: ts(),
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 5060,
            dst_port: 5060,
            transport: crate::capture::parse::TransportProto::Udp,
            is_request: true,
            method: Some(SipMethod::Invite),
            request_uri: Some("sip:b@10.0.0.2".to_string()),
            status_code: None,
            reason: None,
            headers: vec![
                mk_hdr("Call-ID", "asym-test@10.0.0.1"),
                mk_hdr("From", "<sip:a@10.0.0.1>;tag=A"),
                mk_hdr("To", "<sip:b@10.0.0.2>"),
                mk_hdr("CSeq", "1 INVITE"),
            ],
            body: Vec::new(),
            raw: Vec::new(),
            parse_error: false,
            is_retransmission: false,
        };
        let mut d = SipDialog::new(&invite).expect("dialog from INVITE");
        d.timing.invite_sent = Some(ts());
        d.timing.answered_at = Some(ts() + chrono::Duration::seconds(secs_after_epoch));
        d
    }

    #[test]
    fn codec_asymmetry_detected_when_legs_differ() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 18, "G729", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag.codec_asymmetry.expect("codec asymmetry should be set");
        assert_eq!(asym.a_codec, "PCMU");
        assert_eq!(asym.b_codec, "G729");
    }

    #[test]
    fn codec_asymmetry_negative_when_legs_match() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_none());
    }

    #[test]
    fn payload_type_asymmetry_detected_when_codec_matches_pt_differs() {
        // Both legs use PCMA codec but different PTs (one static 8, one dyn 96)
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 8, "PCMA", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 96, "PCMA", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag
            .payload_type_asymmetry
            .expect("PT asymmetry should be set");
        assert_eq!((asym.a_pt, asym.b_pt), (8, 96));
    }

    #[test]
    fn payload_type_asymmetry_skipped_when_codec_differs() {
        // Codec already differs — payload-type field should NOT be set, since
        // the codec asymmetry message already covers it.
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 8, "PCMA", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_some());
        assert!(diag.payload_type_asymmetry.is_none());
    }

    #[test]
    fn ptime_asymmetry_detected_20_vs_30() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 30, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let asym = diag.ptime_asymmetry.expect("ptime asymmetry should be set");
        assert_eq!(asym.a_ptime_ms, 20);
        assert_eq!(asym.b_ptime_ms, 30);
    }

    #[test]
    fn ptime_asymmetry_negative_when_legs_match() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.ptime_asymmetry.is_none());
    }

    #[test]
    fn duration_asymmetry_detected_when_above_thresholds() {
        // A leg: 30s, B leg: 25s → 5s delta, ~17% pct delta. Above 5%/2s default.
        let mut a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 1500);
        a.last_seen = a.first_seen + chrono::Duration::seconds(30);
        let mut b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 1250);
        b.last_seen = b.first_seen + chrono::Duration::seconds(25);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        let dur = diag
            .duration_asymmetry
            .expect("duration asymmetry should be set");
        assert!((dur.a_duration_sec - 30.0).abs() < 0.01);
        assert!((dur.b_duration_sec - 25.0).abs() < 0.01);
        assert!((dur.delta_sec - 5.0).abs() < 0.01);
    }

    #[test]
    fn duration_asymmetry_negative_below_minimum_delta() {
        // 30s vs 29.5s — delta 0.5s, below 2.0s minimum.
        let mut a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 1500);
        a.last_seen = a.first_seen + chrono::Duration::seconds(30);
        let mut b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 1475);
        b.last_seen = b.first_seen + chrono::Duration::milliseconds(29_500);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.duration_asymmetry.is_none());
    }

    #[test]
    fn late_media_detected_when_rtp_starts_after_threshold() {
        // 200 OK at +0s; RTP starts at +1.5s → 1500 ms delay > 500 ms default
        let dialog = make_dialog_with_answer(0);
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 2, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 2, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(
            &mut diag,
            Some(&dialog),
            &streams,
            &AsymmetryThresholds::default(),
        );
        let lm = diag.late_media.expect("late_media should be set");
        assert!(lm.delay_after_200_ok_ms >= 1_500);
    }

    #[test]
    fn late_media_negative_when_rtp_starts_quickly() {
        let dialog = make_dialog_with_answer(0);
        // RTP at 0s = same as 200 OK; well below 500ms threshold.
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let b = make_stream_with_pt([10, 0, 0, 2], [10, 0, 0, 1], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a, &b];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(
            &mut diag,
            Some(&dialog),
            &streams,
            &AsymmetryThresholds::default(),
        );
        assert!(diag.late_media.is_none());
    }

    #[test]
    fn asymmetry_skipped_with_single_stream() {
        let a = make_stream_with_pt([10, 0, 0, 1], [10, 0, 0, 2], 0, "PCMU", 8000, 20, 0, 100);
        let streams: Vec<&RtpStream> = vec![&a];

        let mut diag = diagnose_media(&streams, None);
        diagnose_asymmetry(&mut diag, None, &streams, &AsymmetryThresholds::default());
        assert!(diag.codec_asymmetry.is_none());
        assert!(diag.ptime_asymmetry.is_none());
        assert!(diag.payload_type_asymmetry.is_none());
        assert!(diag.duration_asymmetry.is_none());
        assert!(diag.late_media.is_none());
    }
}
