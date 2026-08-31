// SPDX-License-Identifier: MIT OR Apache-2.0

//! rtpengine control-plane decoding.
//!
//! A standalone media relay carries no SIP. sipnab installed on one sees two
//! sockets of RTP per call and nothing that names the call, so every stream is
//! reported orphaned — a capture full of evidence, presented as unattributable
//! noise. The signaling that would name it is on that box, in rtpengine's own
//! `ng` control protocol, which carries the Call-ID and the relay's port
//! allocation. That pair is exactly the key that ties locally captured RTP to
//! a SIP dialog captured on a different host.
//!
//! # Where the messages come from
//!
//! rtpengine can mirror its whole control plane to a Homer collector with
//! `--homer-enable-ng`, which sends the exact wire bytes of every command in
//! both directions and puts the Call-ID in the HEP correlation-id chunk.
//! That last detail is why this path was chosen over sniffing `ng` off the
//! wire: an `ng` REPLY — the half that carries the relay's allocated ports —
//! contains no `call-id` of its own. Measured against rtpengine 12.5.1, a
//! reply's bencode body is `d3:sdp136:v=0...e` and nothing more. Sniffing
//! would therefore need a cookie-to-call transaction map, plus handling for
//! UDP, TCP, HTTP, WebSocket and a UNIX socket that cannot be captured at all.
//! Over HEP the correlation chunk names the call on every packet, request and
//! reply alike, and that whole problem does not exist.
//!
//! # What a relay's forwarding mode does and does not change
//!
//! rtpengine forwards either in userspace or, with `--table=N` and the
//! `xt_RTPENGINE` kernel module, inside netfilter. This was measured rather
//! than assumed, because if kernel-forwarded media were invisible to
//! `AF_PACKET` then attributing it would be pointless. On rtpengine 12.5.1
//! with kernel forwarding confirmed active — `/proc/rtpengine/0/list` showing
//! the module itself accounting 250 packets per stream — a capture on the
//! relay saw 500 of 500 ingress and 500 of 500 egress packets. Both directions
//! are fully visible in both modes.
//!
//! The reason is structural, not incidental: `AF_PACKET`'s receive tap runs
//! before netfilter, and the module re-injects through the normal transmit
//! path, which passes the transmit tap. sipnab therefore captures a relay the
//! same way whatever mode it is in, and nothing here needs to know which.

pub mod bencode;
pub mod control;
pub mod ng;

use std::sync::atomic::{AtomicU64, Ordering};

/// rtpengine's default HEP "capture protocol type" for mirrored `ng` traffic.
///
/// `--homer-ng-capture-proto` can change it, so this is a default and not a
/// certainty; [`is_ng_over_hep`] therefore also accepts a payload that parses
/// as `ng` under any protocol number. Confirmed as 0x3d against rtpengine
/// 12.5.1 in `tests/fixtures/rtpengine-ng-hep.pcap`.
pub const NG_HEP_CAPTURE_PROTO: u8 = 0x3d;

/// Does this HEP packet carry an rtpengine `ng` message?
///
/// Accepts either the documented capture protocol or anything that actually
/// decodes as `ng`, because the protocol number is configurable at the sending
/// end. The structural check is not loose: `ng` is a cookie, a space, and a
/// complete bencode dictionary consuming the rest of the datagram, which SIP
/// and RTP do not accidentally satisfy.
#[must_use]
pub fn is_ng_over_hep(capture_proto: u8, payload: &[u8]) -> bool {
    capture_proto == NG_HEP_CAPTURE_PROTO || ng::parse(payload).is_ok()
}

/// UDP destination ports a SNIFFED HEP mirror is believed on.
///
/// 9060 is the HEP port: sipnab's own `--hep-listen` default, the value
/// `docs/rtpengine.md` uses in every `homer =` example, and what both
/// committed rtpengine fixtures are addressed to.
///
/// The gate exists because the sniffed path has no authentication of any
/// kind. It reads a datagram addressed to somebody else, off a segment
/// anything can transmit on, and takes the Call-ID verbatim out of the
/// correlation-id chunk — so before this, ANY UDP datagram whose payload
/// bencode-decoded named a call and bound media to an address of the
/// sender's choosing, from any source, to any port. A port gate does not
/// authenticate anything, and nothing here should be read as claiming it
/// does; what it does is stop every datagram on the wire from being a
/// candidate, which is the difference between "one port an operator can
/// reason about" and "all 65535".
///
/// A collector on a non-standard port therefore loses SNIFFED decoding, and
/// that is the deliberate trade. The delivered path — `--hep-listen`, with
/// `--hep-auth --hep-auth-mode hmac` — is the one that can actually
/// authenticate a sender, and it is unaffected.
pub const HEP_MIRROR_PORTS: &[u16] = &[9060];

/// How many sniffed `ng` datagrams were refused for arriving on a port
/// outside [`HEP_MIRROR_PORTS`].
static SNIFFED_NG_OFF_PORT: AtomicU64 = AtomicU64::new(0);

/// Whether a sniffed HEP mirror addressed to `dst_port` is believed.
#[must_use]
pub fn sniffed_mirror_port_allowed(dst_port: u16) -> bool {
    HEP_MIRROR_PORTS.contains(&dst_port)
}

/// How many sniffed `ng` datagrams this process refused on the port gate.
#[must_use]
pub fn sniffed_ng_refused_off_port() -> u64 {
    SNIFFED_NG_OFF_PORT.load(Ordering::Relaxed)
}

/// Reset the off-port tally. Test-only: the count is process-global.
#[cfg(test)]
pub fn reset_sniffed_ng_off_port_count() {
    SNIFFED_NG_OFF_PORT.store(0, Ordering::Relaxed);
}

/// Decode a SNIFFED HEP datagram — one read off the wire on its way to
/// somebody else's collector, wrapper intact — as rtpengine control plane.
///
/// # Returns
///
/// * `None` when the datagram is not sniffed rtpengine control plane at all,
///   so the rest of the pipeline should go on classifying it.
/// * `Some(links)` when it IS control plane. The list is empty both when the
///   message named no endpoint (a `delete`, a `ping`, a reply to one) and
///   when the datagram was refused by the port gate; either way it is control
///   traffic and must not be reconsidered as media.
///
/// # Side effects
///
/// On a refusal, bumps the [`sniffed_ng_refused_off_port`] tally and warns
/// once per process — once, because a mirror aimed at a non-standard port
/// produces this on every control datagram, and a line per packet is its own
/// outage.
#[cfg(feature = "hep")]
#[must_use]
pub fn sniffed_ng_sdp_links(
    dst_port: u16,
    datagram: &[u8],
) -> Option<Vec<(std::net::IpAddr, u16, String, crate::sip::sdp::SdpMedia)>> {
    let hep = crate::capture::hep::parse_hep(datagram).ok()?;
    if !is_ng_over_hep(hep.protocol.to_byte(), &hep.payload) {
        return None;
    }
    if !sniffed_mirror_port_allowed(dst_port) {
        SNIFFED_NG_OFF_PORT.fetch_add(1, Ordering::Relaxed);
        static OFF_PORT_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !OFF_PORT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                "ignoring a sniffed rtpengine ng datagram addressed to UDP port \
                 {dst_port}: sniffed control plane is unauthenticated input, so it \
                 is only believed on the HEP port ({}). Anything may put a \
                 datagram on this segment, and a believed one names a call and \
                 binds media to an address of the sender's choosing. If your \
                 collector really is on {dst_port}, have rtpengine deliver to \
                 sipnab instead: --hep-listen, with --hep-auth --hep-auth-mode \
                 hmac.",
                HEP_MIRROR_PORTS
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        return Some(Vec::new());
    }
    Some(sdp_links_from_ng(
        &hep.payload,
        hep.correlation_id.as_deref(),
    ))
}

/// The SDP media endpoints an `ng` message asserts, tied to their call.
///
/// `correlation_id` is the HEP correlation-id chunk, which rtpengine fills
/// with the Call-ID on every message in both directions. It is what names a
/// REPLY -- the half carrying the relay's own allocated ports, which has no
/// `call-id` of its own (see [`ng`]).
///
/// Returns empty rather than erroring on anything unusable. A control message
/// that does not name a call, or carries no SDP, or whose SDP does not parse,
/// simply contributes no endpoints; it is not a reason to fail the packet.
#[must_use]
pub fn sdp_links_from_ng(
    payload: &[u8],
    correlation_id: Option<&str>,
) -> Vec<(std::net::IpAddr, u16, String, crate::sip::sdp::SdpMedia)> {
    let Ok(msg) = ng::parse(payload) else {
        return Vec::new();
    };

    // Recording and forking commands are COUNTED, never attributed. Their
    // streams belong to the call without being one of its two legs, and a
    // recording leg counted as an ordinary leg turns a two-party call into a
    // three-stream one -- which is what the media analysis then reasons about.
    if let Some(ng::NgCommand::MediaCreating(_)) = msg.command {
        crate::relay::note_media_creating_command();
        return Vec::new();
    }

    // The body names the call on requests; the correlation-id names it on
    // replies. Preferring the body means a passive wire capture, which has no
    // correlation-id, still works for the request half.
    let call_id = match msg
        .call_id
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .or_else(|| correlation_id.map(str::to_owned))
    {
        Some(id) if !id.is_empty() => id,
        _ => return Vec::new(),
    };

    let Some(sdp_bytes) = msg.sdp else {
        return Vec::new();
    };
    let Ok(sdp) = crate::sip::sdp::parse_sdp(sdp_bytes) else {
        return Vec::new();
    };
    crate::pipeline::extract_sdp_links(&sdp, &call_id)
}
