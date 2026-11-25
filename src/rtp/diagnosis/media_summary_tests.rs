// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! [`MediaContext`] read from the per-message media summary
//! ([`crate::sip::message::MediaLine`]) is the context the full SDP parse
//! gave: the same advertised addresses and endpoints, the same primary
//! address text, the same `expects_media`, whether the messages came in
//! through `process_message` or the pipeline's `process_message_read`.
//!
//! The reference below is the rule `MediaContext` applied to a parsed
//! [`SdpSession`] before the summary existed, kept here verbatim so the two
//! can be compared on every SDP shape the diagnosis has to read.
//!
//! RFC 5737 / RFC 3849 addresses and `example.com` names only.

use super::{CaptureMedia, MediaContext};
use crate::net::TransportProto;
use crate::sip::SipMessage;
use crate::sip::dialog_store::DialogStore;
use crate::sip::parser::parse_sip;
use crate::sip::sdp::{SdpDirection, SdpSession, effective_address};
use crate::test_utils::build_sip_message;
use std::net::IpAddr;

type TestError = Box<dyn std::error::Error>;

/// What the context holds about the SDP, by the rule before the summary.
#[derive(Debug, Default, PartialEq)]
struct Reference {
    advertised: Vec<IpAddr>,
    advertised_ports: Vec<(IpAddr, u16)>,
    primary: Option<String>,
    expects_media: bool,
}

/// The pre-summary rule, folded over `sessions` in order.
fn reference(sessions: &[SdpSession]) -> Reference {
    let mut r = Reference::default();
    for sdp in sessions {
        for media in &sdp.media {
            let Some(addr) = effective_address(media, sdp) else {
                continue;
            };
            if r.primary.is_none() {
                r.primary = Some(addr.clone());
            }
            let parsed = addr.parse::<IpAddr>().ok();
            if let Some(ip) = parsed
                && !r.advertised.contains(&ip)
            {
                r.advertised.push(ip);
            }
            let black_holed = parsed.is_some_and(|ip| ip.is_unspecified());
            let carries_rtp = media.proto.to_ascii_uppercase().contains("RTP");
            let asks_for_rtp = carries_rtp && media.port != 0 && !black_holed;
            if let Some(ip) = parsed
                && asks_for_rtp
            {
                let endpoint = (ip, media.port);
                if !r.advertised_ports.contains(&endpoint) {
                    r.advertised_ports.push(endpoint);
                }
            }
            if asks_for_rtp && media.direction != SdpDirection::Inactive {
                r.expects_media = true;
            }
        }
    }
    r
}

/// The SDP half of `ctx`, in the reference's shape.
fn view(ctx: &MediaContext) -> Reference {
    Reference {
        advertised: ctx.advertised.clone(),
        advertised_ports: ctx.advertised_ports.clone(),
        primary: ctx.primary.clone(),
        expects_media: ctx.expects_media,
    }
}

/// An SDP body: `c` at session level (none when empty), then `media`.
fn sdp(c: &str, media: &[&str]) -> String {
    let mut s = String::from("v=0\r\no=- 7 7 IN IP4 192.0.2.1\r\ns=-\r\n");
    if !c.is_empty() {
        s.push_str(c);
        s.push_str("\r\n");
    }
    s.push_str("t=0 0\r\n");
    for m in media {
        s.push_str(m);
        s.push_str("\r\n");
    }
    s
}

/// The INVITE carrying `offer` and the 200 carrying `answer`, parsed.
fn call(call_id: &str, offer: &str, answer: &str) -> Result<[SipMessage; 2], TestError> {
    let one = |first: &str, to: &str, body: &str, at: i64| -> Result<SipMessage, TestError> {
        let cid = format!("Call-ID: {call_id}");
        let raw = build_sip_message(
            first,
            &[
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-summary",
                "From: <sip:a@example.com>;tag=a1",
                to,
                &cid,
                "CSeq: 1 INVITE",
                "Content-Type: application/sdp",
            ],
            body.as_bytes(),
        );
        parse_sip(
            &raw,
            chrono::DateTime::from_timestamp(1_700_000_000 + at, 0).unwrap_or_default(),
            [192, 0, 2, 1].into(),
            [192, 0, 2, 2].into(),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("the fixture must parse: {e:?}").into())
    };
    Ok([
        one(
            "INVITE sip:b@example.com SIP/2.0",
            "To: <sip:b@example.com>",
            offer,
            0,
        )?,
        one(
            "SIP/2.0 200 OK",
            "To: <sip:b@example.com>;tag=b1",
            answer,
            1,
        )?,
    ])
}

/// For one offer and answer: the context from the summary (over a store
/// filled either way) equals the reference over the full parses, and
/// `from_session` of each body equals the reference over that body.
fn check(offer: &str, answer: &str) -> Result<(), TestError> {
    let msgs = call("summary@example.com", offer, answer)?;
    let sessions: Vec<SdpSession> = msgs.iter().filter_map(SipMessage::sdp).collect();
    let want = reference(&sessions);

    let mut unread = DialogStore::new(8, false);
    for m in msgs.clone() {
        unread.process_message(m);
    }
    let d = unread.iter().next().ok_or("the call opened a dialog")?;
    let ctx = MediaContext::for_dialog(d, CaptureMedia::Observed);
    assert_eq!(view(&ctx), want, "summary filled on first read");
    assert!(ctx.negotiated(), "an offer and an answer");

    #[cfg(not(target_arch = "wasm32"))]
    {
        use crate::sip::sdp::SdpRead;
        let mut piped = DialogStore::new(8, false);
        for m in msgs.clone() {
            let read = SdpRead::Read(m.sdp().map(Box::new));
            piped.process_message_read(m, &read);
        }
        let d = piped.iter().next().ok_or("the call opened a dialog")?;
        let kept = MediaContext::for_dialog(d, CaptureMedia::Observed);
        assert_eq!(view(&kept), want, "a store filled by the pipeline's path");
        assert_eq!(
            format!("{kept:?}"),
            format!("{ctx:?}"),
            "one context either way"
        );
    }

    for s in &sessions {
        let one = MediaContext::from_session(s, CaptureMedia::Observed);
        assert_eq!(
            view(&one),
            reference(std::slice::from_ref(s)),
            "from_session"
        );
    }
    Ok(())
}

/// A plain audio offer and answer.
#[test]
fn a_plain_audio_call_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP4 192.0.2.10", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &["m=audio 20000 RTP/AVP 0"]),
    )
}

/// Media-level `c=` lines that differ from the session's.
#[test]
fn media_level_addresses_read_the_same() -> Result<(), TestError> {
    check(
        &sdp(
            "c=IN IP4 192.0.2.10",
            &[
                "m=audio 16384 RTP/AVP 0\r\nc=IN IP4 192.0.2.11",
                "m=video 16386 RTP/AVP 96",
            ],
        ),
        &sdp(
            "",
            &[
                "m=audio 20000 RTP/AVP 0\r\nc=IN IP4 198.51.100.20",
                "m=video 0 RTP/AVP 96",
            ],
        ),
    )
}

/// A host name in `c=`: the primary text, and no IP.
#[test]
fn a_host_name_address_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP4 media.example.com", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &["m=audio 20000 RTP/AVP 0"]),
    )
}

/// IPv6 in capitals and uncompressed: the primary text as written.
#[test]
fn ipv6_as_written_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP6 2001:DB8::A", &["m=audio 16384 RTP/AVP 0"]),
        &sdp(
            "c=IN IP6 2001:db8:0:0:0:0:0:b",
            &["m=audio 20000 RTP/AVP 0"],
        ),
    )
}

/// The RFC 2543 hold address asks for no media.
#[test]
fn a_hold_address_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP4 0.0.0.0", &["m=audio 16384 RTP/AVP 0"]),
        &sdp(
            "c=IN IP4 198.51.100.20",
            &["m=audio 20000 RTP/AVP 0\r\na=inactive"],
        ),
    )
}

/// T.38 beside audio, and a declined video line.
#[test]
fn t38_and_a_declined_line_read_the_same() -> Result<(), TestError> {
    check(
        &sdp(
            "c=IN IP4 192.0.2.10",
            &[
                "m=image 16384 udptl t38",
                "m=video 0 RTP/AVP 96",
                "m=audio 16386 RTP/SAVP 0",
            ],
        ),
        &sdp("c=IN IP4 198.51.100.20", &["m=image 20000 udptl t38"]),
    )
}

/// Inactive and one-way lines.
#[test]
fn directions_read_the_same() -> Result<(), TestError> {
    check(
        &sdp(
            "c=IN IP4 192.0.2.10",
            &["m=audio 16384 RTP/AVP 0\r\na=inactive"],
        ),
        &sdp(
            "c=IN IP4 198.51.100.20",
            &["m=audio 20000 RTP/AVP 0\r\na=recvonly"],
        ),
    )
}

/// No `c=` anywhere in the offer.
#[test]
fn an_offer_without_an_address_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &["m=audio 20000 RTP/AVP 0"]),
    )
}

/// An IPv4 address with a leading zero is text, not an IP.
#[test]
fn a_leading_zero_address_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP4 192.0.2.010", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &["m=audio 20000 RTP/AVP 0"]),
    )
}

/// The same endpoint twice is listed once.
#[test]
fn a_repeated_endpoint_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp(
            "c=IN IP4 192.0.2.10",
            &["m=audio 16384 RTP/AVP 0", "m=audio 16384 RTP/AVP 8"],
        ),
        &sdp("c=IN IP4 192.0.2.10", &["m=audio 16384 RTP/AVP 0"]),
    )
}

/// An answer with no `m=` line.
#[test]
fn an_answer_without_media_reads_the_same() -> Result<(), TestError> {
    check(
        &sdp("c=IN IP4 192.0.2.10", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &[]),
    )
}

/// Two contexts of one dialog parse each message's SDP at most once.
#[test]
fn two_contexts_of_one_dialog_parse_each_sdp_once() -> Result<(), TestError> {
    let msgs = call(
        "twice@example.com",
        &sdp("c=IN IP4 192.0.2.10", &["m=audio 16384 RTP/AVP 0"]),
        &sdp("c=IN IP4 198.51.100.20", &["m=audio 20000 RTP/AVP 0"]),
    )?;
    let mut store = DialogStore::new(8, false);
    for m in msgs {
        store.process_message(m);
    }
    let d = store.iter().next().ok_or("the call opened a dialog")?;
    crate::test_utils::clear_parses();
    let a = MediaContext::for_dialog(d, CaptureMedia::Observed);
    let b = MediaContext::for_dialog(d, CaptureMedia::Observed);
    assert_eq!(format!("{a:?}"), format!("{b:?}"), "one context");
    let (_, sdp_parses, read) = crate::test_utils::worst_parses();
    assert_eq!(read, 2, "both messages were read");
    assert_eq!(
        sdp_parses, 1,
        "a message's SDP was parsed {sdp_parses} times"
    );
    Ok(())
}
