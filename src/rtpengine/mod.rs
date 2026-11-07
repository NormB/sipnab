// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
/// as `ng` under any protocol number. Confirmed as 0x3d against a live
/// rtpengine 12.5.1, whose wire shapes `tests/fixtures/rtpengine-ng-hep.pcap`
/// keeps.
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
    sniffed_ng(
        dst_port,
        datagram,
        chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
    )
    .map(|ng| ng.sdp_links)
}

/// What one SNIFFED `ng` HEP copy asserts: its media endpoints, and the
/// engine an `offer` or `delete` reached.
#[cfg(feature = "hep")]
#[derive(Debug, Clone)]
pub struct SniffedNg {
    /// The media endpoints, as [`sniffed_ng_sdp_links`] returns them.
    pub sdp_links: Vec<(std::net::IpAddr, u16, String, crate::sip::sdp::SdpMedia)>,
    /// The engine the request reached, named by the copy's capture id.
    pub engine_sighting: Option<(String, crate::relay_vocab::EngineSighting)>,
}

/// [`sniffed_ng_sdp_links`], with the engine sighting the copy makes.
///
/// `received` is when the datagram was captured; the time the copy carries is
/// used when it carries one. Both halves pass the same port gate: a copy off
/// the HEP port asserts nothing.
#[cfg(feature = "hep")]
#[must_use]
pub fn sniffed_ng(
    dst_port: u16,
    datagram: &[u8],
    received: chrono::DateTime<chrono::Utc>,
) -> Option<SniffedNg> {
    let hep = crate::capture::hep::parse_hep(datagram).ok()?;
    if !is_ng_over_hep(hep.protocol.to_byte(), &hep.payload) {
        return None;
    }
    if !sniffed_mirror_port_believed(dst_port) {
        return Some(SniffedNg {
            sdp_links: Vec::new(),
            engine_sighting: None,
        });
    }
    let engine_sighting = hep.capture_id.and_then(|id| {
        engine_sighting_from_ng(
            &hep.payload,
            hep.correlation_id.as_deref(),
            crate::relay_vocab::EngineIdentity::HomerId(id),
            Some(std::net::SocketAddr::new(hep.dst_addr, hep.dst_port)),
            hep.timestamp.unwrap_or(received),
        )
    });
    Some(SniffedNg {
        sdp_links: sdp_links_from_ng(&hep.payload, hep.correlation_id.as_deref()),
        engine_sighting,
    })
}

/// Whether sniffed `ng` addressed to `dst_port` is believed, counting and
/// warning on a refusal.
///
/// The one gate for both ways sniffed `ng` arrives: a HEP datagram read with
/// its wrapper intact ([`sniffed_ng_sdp_links`]) and one `--hep-parse`
/// unwrapped first. Two copies of the check would let one of them drift
/// open, which is how `--hep-parse` came to bypass it.
///
/// # Side effects
///
/// On a refusal, bumps the [`sniffed_ng_refused_off_port`] tally and warns
/// once per process.
#[cfg(feature = "hep")]
#[must_use]
pub fn sniffed_mirror_port_believed(dst_port: u16) -> bool {
    static OFF_PORT_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    match port_gate(dst_port, &SNIFFED_NG_OFF_PORT, &OFF_PORT_WARNED) {
        PortGate::Believed => true,
        PortGate::Refused { warn } => {
            if warn {
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
            false
        }
    }
}

/// What the port gate decided for one sniffed `ng` datagram.
#[cfg(feature = "hep")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortGate {
    /// On a port in [`HEP_MIRROR_PORTS`]: believed.
    Believed,
    /// Off it: refused.
    Refused {
        /// Whether this is the first refusal `warned` has seen, so the
        /// warning is logged once.
        warn: bool,
    },
}

/// The port gate's decision for `dst_port`, counting a refusal in `refused`.
/// The counter and the warned flag are arguments so a test can give each case
/// its own; the process uses [`SNIFFED_NG_OFF_PORT`] and one flag.
#[cfg(feature = "hep")]
fn port_gate(
    dst_port: u16,
    refused: &AtomicU64,
    warned: &std::sync::atomic::AtomicBool,
) -> PortGate {
    if sniffed_mirror_port_allowed(dst_port) {
        return PortGate::Believed;
    }
    refused.fetch_add(1, Ordering::Relaxed);
    PortGate::Refused {
        warn: !warned.swap(true, Ordering::Relaxed),
    }
}

/// The off-port tally: each refusal counted once, the warning due once, and
/// nothing counted for a datagram on the HEP port.
#[cfg(all(test, feature = "hep"))]
mod off_port_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    /// A port that is not in [`HEP_MIRROR_PORTS`].
    const OFF_PORT: u16 = 5070;

    /// Each off-port datagram adds one to the tally; one on the HEP port
    /// adds nothing.
    #[test]
    fn an_off_port_datagram_is_counted_once_and_an_on_port_one_not_at_all() {
        let (refused, warned) = (AtomicU64::new(0), AtomicBool::new(false));
        assert_eq!(
            port_gate(HEP_MIRROR_PORTS[0], &refused, &warned),
            PortGate::Believed,
            "a datagram on the HEP port is believed"
        );
        assert_eq!(
            refused.load(Ordering::Relaxed),
            0,
            "an on-port datagram is not counted"
        );
        for n in 1..=3 {
            assert!(
                matches!(
                    port_gate(OFF_PORT, &refused, &warned),
                    PortGate::Refused { .. }
                ),
                "an off-port datagram is refused"
            );
            assert_eq!(refused.load(Ordering::Relaxed), n, "one count per refusal");
        }
    }

    /// The warning is logged once, for the first refusal, whatever port
    /// later refusals arrive on.
    #[test]
    fn the_warning_is_due_on_the_first_refusal_only() {
        let (refused, warned) = (AtomicU64::new(0), AtomicBool::new(false));
        assert_eq!(
            port_gate(OFF_PORT, &refused, &warned),
            PortGate::Refused { warn: true },
            "the first refusal warns"
        );
        assert_eq!(
            port_gate(OFF_PORT, &refused, &warned),
            PortGate::Refused { warn: false },
            "a second refusal does not warn"
        );
        assert_eq!(
            port_gate(OFF_PORT + 1, &refused, &warned),
            PortGate::Refused { warn: false },
            "a refusal on another port does not warn again"
        );
    }

    /// The process-wide gate refuses an off port and raises the public
    /// tally. Other tests in this process may refuse datagrams at the same
    /// time, so the tally is checked to have risen, not by how much.
    #[test]
    fn the_process_gate_refuses_an_off_port_and_raises_the_public_tally() {
        let before = sniffed_ng_refused_off_port();
        assert!(
            !sniffed_mirror_port_believed(OFF_PORT),
            "the process gate refuses an off port"
        );
        assert!(
            sniffed_ng_refused_off_port() > before,
            "the public tally rose"
        );
        assert!(
            sniffed_mirror_port_believed(HEP_MIRROR_PORTS[0]),
            "the HEP port is believed"
        );
    }
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

/// The `ng` implementation of the relay control seam.
///
/// Reaches UP to `crate::relay`, never the other way: the seam declares what a
/// control message is, and this satisfies that declaration for one protocol.
/// A second relay adds a sibling here and changes nothing above.
#[derive(Debug, Clone, Copy, Default)]
pub struct NgControlDecoder;

impl crate::relay::ControlDecoder for NgControlDecoder {
    fn decode(&self, payload: &[u8], dst_port: u16) -> Option<crate::relay::DecodedControl> {
        // Encapsulation is tried FIRST: a mirrored control message is wrapped,
        // and asking the bare parser first would read the envelope as a
        // malformed message rather than recognizing it.
        #[cfg(feature = "hep")]
        if let Ok(hep) = crate::capture::hep::parse_hep(payload)
            && is_ng_over_hep(hep.protocol.to_byte(), &hep.payload)
        {
            return Some(crate::relay::DecodedControl {
                delivery: crate::relay::ControlDelivery::Encapsulated,
                message: describe_ng_message(&hep.payload)?,
                correlation_id: hep.correlation_id.clone(),
                on_believed_mirror_port: Some(sniffed_mirror_port_allowed(dst_port)),
            });
        }
        let _ = dst_port;
        Some(crate::relay::DecodedControl {
            delivery: crate::relay::ControlDelivery::BareDatagram,
            message: describe_ng_message(payload)?,
            correlation_id: None,
            on_believed_mirror_port: None,
        })
    }
}

/// Describe one `ng` payload in the seam's vocabulary.
fn describe_ng_message(payload: &[u8]) -> Option<crate::relay::ControlMessage> {
    use ng::NgCommand;
    let msg = ng::parse(payload).ok()?;
    Some(crate::relay::ControlMessage {
        command: msg.command.map(|c| match c {
            NgCommand::Offer => "offer".to_string(),
            NgCommand::Answer => "answer".to_string(),
            NgCommand::Delete => "delete".to_string(),
            NgCommand::MediaCreating(name) | NgCommand::Other(name) => name.to_string(),
        }),
        call_id: msg.call_id.map(|b| String::from_utf8_lossy(b).into_owned()),
        sdp_bytes: msg.sdp.map(<[u8]>::len),
    })
}

/// The engine sighting one `ng` message makes, tied to its call.
///
/// Only a REQUEST counts, and only `offer` and `delete`: an `offer` is the
/// proxy choosing this engine for the call, and a `delete` is the proxy
/// releasing it there. A reply says nothing new about which engine was asked,
/// and `query`, `list` and `statistics` are questions (sipnab's own among
/// them, since rtpengine copies those too) that choose nothing.
///
/// `correlation_id` names the call when the body does not. `engine` and
/// `reported_listen_ng` are what the caller knows of the receiver: the HEP
/// capture id and destination chunk for a HEP copy, or the destination of a
/// captured request.
///
/// `None` for anything else, and for a request that names no call.
#[must_use]
pub fn engine_sighting_from_ng(
    payload: &[u8],
    correlation_id: Option<&str>,
    engine: crate::relay_vocab::EngineIdentity,
    reported_listen_ng: Option<std::net::SocketAddr>,
    at: chrono::DateTime<chrono::Utc>,
) -> Option<(String, crate::relay_vocab::EngineSighting)> {
    let msg = ng::parse(payload).ok()?;
    let verb = match msg.command? {
        ng::NgCommand::Offer => crate::relay_vocab::EngineVerb::Offer,
        ng::NgCommand::Delete => crate::relay_vocab::EngineVerb::Delete,
        _ => return None,
    };
    let call_id = msg
        .call_id
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .or_else(|| correlation_id.map(str::to_owned))
        .filter(|id| !id.is_empty())?;
    Some((
        call_id,
        crate::relay_vocab::EngineSighting {
            at,
            engine,
            verb,
            reported_listen_ng,
            frame: None,
        },
    ))
}

#[cfg(test)]
mod engine_sighting_tests {
    use super::*;
    use crate::relay_vocab::{EngineIdentity, EngineSighting, EngineVerb};
    use chrono::TimeZone;

    type TestError = Box<dyn std::error::Error>;

    fn at() -> Result<chrono::DateTime<chrono::Utc>, TestError> {
        Ok(chrono::Utc
            .timestamp_opt(1_793_800_000, 0)
            .single()
            .ok_or("a fixed instant")?)
    }

    fn sighting(
        payload: &[u8],
        correlation_id: Option<&str>,
    ) -> Result<Option<(String, EngineSighting)>, TestError> {
        Ok(engine_sighting_from_ng(
            payload,
            correlation_id,
            EngineIdentity::HomerId(2002),
            Some("127.0.0.1:2223".parse()?),
            at()?,
        ))
    }

    /// An `offer` and a `delete` name their call and the engine that
    /// received them, with the destination the copy reported.
    #[test]
    fn an_offer_and_a_delete_are_sightings_of_the_receiving_engine() -> Result<(), TestError> {
        let offer = sighting(
            b"c2 d7:call-id18:c1@example.invalid7:command5:offer8:from-tag2:fte",
            None,
        )?;
        assert_eq!(
            offer,
            Some((
                "c1@example.invalid".to_string(),
                EngineSighting {
                    at: at()?,
                    engine: EngineIdentity::HomerId(2002),
                    verb: EngineVerb::Offer,
                    reported_listen_ng: Some("127.0.0.1:2223".parse()?),
                    frame: None,
                }
            )),
            "an offer is a sighting of the engine that received it"
        );
        let delete = sighting(
            b"c7 d7:call-id18:c1@example.invalid7:command6:delete8:from-tag2:fte",
            None,
        )?;
        assert_eq!(
            delete.map(|(c, s)| (c, s.verb)),
            Some(("c1@example.invalid".to_string(), EngineVerb::Delete)),
            "a delete is a sighting too"
        );
        Ok(())
    }

    /// A request whose body names no call is named by the correlation id; one
    /// named by neither is no sighting.
    #[test]
    fn the_correlation_id_names_a_call_the_body_does_not() -> Result<(), TestError> {
        let body = b"c2 d7:command5:offere";
        assert_eq!(
            sighting(body, Some("c9@example.invalid"))?.map(|(c, _)| c),
            Some("c9@example.invalid".to_string()),
            "the correlation id names the call"
        );
        assert_eq!(sighting(body, None)?, None, "no call named, no sighting");
        assert_eq!(sighting(body, Some(""))?, None, "an empty id names no call");
        Ok(())
    }

    /// A sniffed HEP copy is dated by the time it carries, not by when sipnab
    /// captured it, so copies from several engines order by when each engine
    /// saw its request.
    #[cfg(feature = "hep")]
    #[test]
    fn a_sniffed_copy_is_dated_by_the_time_it_carries() -> Result<(), TestError> {
        let ep = crate::capture::hep::HepEndpoint {
            src_addr: std::net::IpAddr::from([192, 0, 2, 30]),
            dst_addr: std::net::IpAddr::from([127, 0, 0, 1]),
            src_port: 40000,
            dst_port: 2223,
            transport: crate::net::TransportProto::Udp,
        };
        let carried = at()?;
        let datagram = crate::capture::hep::build_hep_v3_correlated(
            &ep,
            carried,
            crate::capture::hep::HepProtocol::Unknown(NG_HEP_CAPTURE_PROTO),
            2001,
            None,
            Some(b"c1@example.invalid"),
            b"c2 d7:call-id18:c1@example.invalid7:command5:offer8:from-tag2:fte",
        );
        let received = carried + chrono::TimeDelta::seconds(30);
        let got = sniffed_ng(HEP_MIRROR_PORTS[0], &datagram, received)
            .and_then(|ng| ng.engine_sighting)
            .map(|(_, s)| s.at);
        assert_eq!(got, Some(carried), "the time the copy carries");
        Ok(())
    }

    /// A reply, a question and a request that chooses nothing are no
    /// sighting: they would otherwise make sipnab's own `query` move a call.
    #[test]
    fn replies_and_questions_are_not_sightings() -> Result<(), TestError> {
        for payload in [
            &b"c2 d3:sdp3:v=06:result2:oke"[..],
            &b"c4 d7:call-id18:c1@example.invalid7:command5:querye"[..],
            &b"c3 d7:command6:answer7:call-id18:c1@example.invalid8:from-tag2:fte"[..],
            &b"c5 d7:command4:liste"[..],
            &b"not ng at all"[..],
        ] {
            assert_eq!(
                sighting(payload, Some("c1@example.invalid"))?,
                None,
                "not a sighting: {}",
                String::from_utf8_lossy(payload)
            );
        }
        Ok(())
    }
}
