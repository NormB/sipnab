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
pub mod ng;

use std::sync::atomic::{AtomicU64, Ordering};

/// rtpengine's default HEP "capture protocol type" for mirrored `ng` traffic.
///
/// `--homer-ng-capture-proto` can change it, so this is a default and not a
/// certainty; [`is_ng_over_hep`] therefore also accepts a payload that parses
/// as `ng` under any protocol number. Confirmed as 0x3d against rtpengine
/// 12.5.1 in `tests/fixtures/rtpengine-ng-hep.pcap`.
pub const NG_HEP_CAPTURE_PROTO: u8 = 0x3d;

/// How many media-creating commands were seen without being attributed.
///
/// A plain counter, deliberately: RE5 attributes recording streams from
/// rtpengine's recording spool, not by decoding these commands, so what is
/// owed here is a HONEST COUNT and not an attribution. A run that saw
/// `start recording` and says nothing is the failure this project already
/// named once -- a forensics tool that cannot say what it did not attribute.
static MEDIA_CREATING_SEEN: AtomicU64 = AtomicU64::new(0);

/// Record that a media-creating command went past unattributed.
pub fn note_media_creating_command() {
    MEDIA_CREATING_SEEN.fetch_add(1, Ordering::Relaxed);
}

/// How many media-creating commands this process has seen.
#[must_use]
pub fn media_creating_commands_seen() -> u64 {
    MEDIA_CREATING_SEEN.load(Ordering::Relaxed)
}

/// Reset the counter. Test-only: the tally is process-global.
#[cfg(test)]
pub fn reset_media_creating_count() {
    MEDIA_CREATING_SEEN.store(0, Ordering::Relaxed);
}

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
        note_media_creating_command();
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
