//! Per-packet protocol routing: the testable core of the capture
//! pipeline.
//!
//! Extracted from main.rs so the routing logic (SIP vs RTCP vs RTP vs
//! heuristic, WebSocket unwrapping, port-range gating) is exercisable
//! as a library API instead of only through the binary.

use std::sync::Arc;

use parking_lot::RwLock;

use crate::capture::parse::{ParsedPacket, TransportProto};
use crate::capture::websocket;
use crate::rtp;
use crate::rtp::stream_store::StreamStore;
use crate::sip;
use crate::sip::dialog_store::DialogStore;

/// Check whether a source or destination port falls within the configured range.
pub fn port_in_range(src_port: u16, dst_port: u16, range: (u16, u16)) -> bool {
    let (lo, hi) = range;
    (src_port >= lo && src_port <= hi) || (dst_port >= lo && dst_port <= hi)
}

/// Check if a UDP payload looks like RTCP.
///
/// RTCP convention: odd destination port (RTP port + 1), version=2,
/// and payload type in the 200-204 range.
pub fn is_rtcp_packet(data: &[u8], dst_port: u16) -> bool {
    if data.len() < 8 {
        return false;
    }
    // RTCP typically uses odd port (RTP+1)
    if dst_port.is_multiple_of(2) {
        return false;
    }
    let version = (data[0] >> 6) & 0x03;
    if version != 2 {
        return false;
    }
    let pt = data[1];
    (200..=204).contains(&pt)
}

/// Try to unwrap a WebSocket frame from a TCP packet on common WS ports.
///
/// Returns `Some(payload)` if the packet is TCP, the destination or source
/// port is a common WebSocket port (80, 443, 8080, 8443), and the data
/// contains a valid WebSocket data frame wrapping SIP content.
pub fn try_websocket_unwrap(pp: &ParsedPacket) -> Option<Vec<u8>> {
    if pp.transport != TransportProto::Tcp {
        return None;
    }

    // Only attempt on common WebSocket ports
    let is_ws_port =
        websocket::WS_PORTS.contains(&pp.dst_port) || websocket::WS_PORTS.contains(&pp.src_port);
    if !is_ws_port {
        return None;
    }

    if !websocket::is_websocket_frame(&pp.payload) {
        return None;
    }

    match websocket::unwrap_websocket_frame(&pp.payload) {
        Ok(Some(payload)) if sip::is_sip_message(&payload) => Some(payload),
        _ => None,
    }
}

/// Options controlling which protocols the pipeline tracks.
#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineOptions {
    /// Skip dialog tracking for SIP messages.
    pub no_dialog: bool,
    /// Skip RTP/RTCP media tracking.
    pub no_rtp: bool,
}

/// Optional media-decryption state threaded through the live pipeline: the SRTP
/// context (`--srtp-keys` + SDES `a=crypto`) and the DTLS-SRTP extractor
/// (`--dtls-keylog`). Both absent in non-`tls` builds; construct with
/// [`Default`] and populate the fields when a `tls` build has keys.
#[derive(Default)]
pub struct MediaDecrypt<'a> {
    /// SRTP context that authenticates and decrypts RTP payloads in place.
    #[cfg(feature = "tls")]
    pub srtp: Option<&'a mut crate::rtp::srtp::SrtpContext>,
    /// DTLS-SRTP extractor that recovers SRTP keys from DTLS handshakes.
    #[cfg(feature = "tls")]
    pub dtls: Option<&'a mut crate::capture::dtls::DtlsSrtpExtractor>,
    #[cfg(not(feature = "tls"))]
    _marker: std::marker::PhantomData<&'a ()>,
}

/// Route one parsed packet into the dialog / stream stores.
///
/// The shared-store protocol pipeline: WebSocket unwrap, SIP parse +
/// dialog tracking + SDP-to-stream linking, RTCP matching, RTP (header
/// or heuristic). Parsing happens OUTSIDE the store locks; each store
/// is write-locked once, briefly. This is the TUI-mode per-packet path
/// and the testable core that batch mode's richer pipeline mirrors.
///
/// `decrypt` carries optional SRTP/DTLS-SRTP key state; when present, SRTP
/// payloads are authenticated and decrypted before media analysis, SDES keys
/// are learned from SDP, and DTLS handshakes feed the SRTP key store.
pub fn process_packet(
    pp: &ParsedPacket,
    dialog_store: &Arc<RwLock<DialogStore>>,
    stream_store: &Arc<RwLock<StreamStore>>,
    rtp_heuristic: &mut rtp::heuristic::RtpHeuristic,
    opts: &PipelineOptions,
    decrypt: &mut MediaDecrypt<'_>,
) {
    // `decrypt` is only consumed by the `tls`-gated media-decryption paths.
    #[cfg(not(feature = "tls"))]
    let _ = &decrypt;

    // Try WebSocket unwrapping for TCP on common WS ports
    let ws_payload = try_websocket_unwrap(pp);
    let effective_transport = if ws_payload.is_some() {
        TransportProto::Ws
    } else {
        pp.transport
    };
    // Owned ws frames become Bytes; otherwise share the packet buffer.
    let effective_payload: bytes::Bytes = match ws_payload {
        Some(v) => v.into(),
        None => pp.payload.clone(),
    };
    let effective_payload = &effective_payload;

    // Try SIP detection first — parse OUTSIDE the lock, then do a quick
    // write-lock-and-release to minimize contention with the TUI render thread.
    if sip::is_sip_message(effective_payload) {
        if let Ok(sip_msg) = sip::parser::parse_sip_bytes(
            effective_payload,
            pp.timestamp,
            pp.src_addr,
            pp.dst_addr,
            pp.src_port,
            pp.dst_port,
            effective_transport,
        ) && !opts.no_dialog
        {
            // Extract SDP link info before acquiring any lock.
            // Clone media descriptions so codec/clock_rate can be propagated
            // to RTP streams with dynamic payload types (e.g., Opus).
            let sdp_links: Vec<(std::net::IpAddr, u16, String, sip::sdp::SdpMedia)> =
                if let Some(sdp) = sip_msg.sdp()
                    && let Some(call_id) = sip_msg.call_id()
                {
                    sdp.media
                        .iter()
                        .filter_map(|media| {
                            let addr_str = sip::sdp::effective_address(media, &sdp);
                            addr_str
                                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
                                .map(|ip| (ip, media.port, call_id.to_string(), media.clone()))
                        })
                        .collect()
                } else {
                    Vec::new()
                };

            // Quick write to dialog store, then release
            {
                dialog_store.write().process_message(sip_msg);
            }

            // Link SDP media endpoints to RTP streams (separate lock)
            if !sdp_links.is_empty() {
                let mut ss = stream_store.write();
                for (ip, port, call_id, media) in &sdp_links {
                    ss.link_to_dialog_with_sdp(*ip, *port, call_id, media);
                }
            }

            // Feed SDES `a=crypto` key material into the SRTP context.
            #[cfg(feature = "tls")]
            if let Some(ctx) = decrypt.srtp.as_deref_mut() {
                for (ip, port, _cid, media) in &sdp_links {
                    if !media.crypto.is_empty() {
                        ctx.add_sdes(Some(ip.to_string()), Some(*port), &media.crypto);
                    }
                }
            }
        }
        return;
    }

    // RTP/RTCP detection
    if opts.no_rtp || pp.transport != TransportProto::Udp {
        return;
    }

    // DTLS-SRTP: recover SRTP keys from DTLS handshakes and hand them to the
    // SRTP context. DTLS packets are not RTP, so handle and return.
    #[cfg(feature = "tls")]
    if crate::capture::dtls::is_dtls(&pp.payload) {
        let keys = decrypt
            .dtls
            .as_deref_mut()
            .map(|ext| ext.process_dtls(&pp.payload))
            .unwrap_or_default();
        if !keys.is_empty()
            && let Some(ctx) = decrypt.srtp.as_deref_mut()
        {
            ctx.add_keys(keys);
        }
        return;
    }

    if is_rtcp_packet(&pp.payload, pp.dst_port) {
        let rtcp_packets = rtp::rtcp::parse_rtcp(&pp.payload);
        if !rtcp_packets.is_empty() {
            stream_store.write().process_rtcp(&rtcp_packets);
        }
        return;
    }

    if rtp::is_rtp_packet(&pp.payload)
        && let Ok(rtp_hdr) = rtp::parser::parse_rtp_header(&pp.payload)
    {
        // SRTP: substitute a decrypted payload when a key authenticates it.
        #[cfg(feature = "tls")]
        let srtp_pp: Option<ParsedPacket> = decrypt.srtp.as_deref_mut().and_then(|ctx| {
            ctx.decrypt(&pp.payload, rtp_hdr.payload_offset)
                .map(|plain| {
                    let mut d = pp.clone();
                    d.payload = plain.into();
                    d
                })
        });
        #[cfg(not(feature = "tls"))]
        let srtp_pp: Option<ParsedPacket> = None;
        let rtp_pp: &ParsedPacket = srtp_pp.as_ref().unwrap_or(pp);

        stream_store
            .write()
            .process_rtp(rtp_pp, &rtp_hdr, rtp_pp.timestamp);
        return;
    }

    if let Some(rtp_hdr) = rtp_heuristic.check(pp) {
        stream_store.write().process_rtp(pp, &rtp_hdr, pp.timestamp);
    }
}
