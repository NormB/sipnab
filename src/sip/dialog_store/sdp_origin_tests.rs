// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The `sdp_origin` strategy at store level: a B2BUA that passes the origin
//! through is an identifier match, and calls that reuse one origin are not.
//!
//! Every fixture is synthetic. Addresses are RFC 5737 documentation addresses
//! (RFC 3849 for IPv6) and names are `example.com`. The rule under test is in
//! [`crate::sip::sdp_origin`].
//!
//! The legs carry no `Session-ID`, no correlation header and distinct Via
//! branches, so `sdp_origin` is the only identifier strategy that can match.
//! The timing heuristic can still match legs that share an address and start
//! within two seconds; the assertions name the strategy they are about.

use super::{CorrelationReason, DialogStore};
use crate::net::TransportProto;
use crate::sip::SipMessage;
use crate::sip::parser::parse_sip;
use chrono::{DateTime, TimeDelta, Utc};
use std::net::{IpAddr, Ipv4Addr};

type TestError = Box<dyn std::error::Error>;

/// The origin SIPp's built-in `uac` scenario writes into every call.
const SIPP_ORIGIN: &str = "user1 53655765 2353687637 IN IP4 192.0.2.1";
/// An origin a caller wrote once, for one session.
const ORIGIN: &str = "alice 2890844526 2890842807 IN IP4 192.0.2.1";
/// An origin the callee wrote once, for its answer.
const ANSWER_ORIGIN: &str = "bob 3724394400 3724394400 IN IP4 198.51.100.30";

/// One hop: the sending socket and the receiving socket.
#[derive(Clone, Copy)]
struct Hop {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
}

impl Hop {
    /// The same sockets, the other way round, for a response.
    fn back(self) -> Self {
        Self {
            src: self.dst,
            sport: self.dport,
            dst: self.src,
            dport: self.sport,
        }
    }
}

/// An RFC 5737 address.
fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// A hop from `src`:5060 to `dst`:5060.
fn hop(src: IpAddr, dst: IpAddr) -> Hop {
    Hop {
        src,
        sport: 5060,
        dst,
        dport: 5060,
    }
}

/// The caller.
fn uac() -> IpAddr {
    v4(192, 0, 2, 1)
}
/// The first proxy or B2BUA.
fn sbc() -> IpAddr {
    v4(192, 0, 2, 10)
}
/// A second B2BUA.
fn sbc2() -> IpAddr {
    v4(198, 51, 100, 20)
}
/// A callee.
fn uas() -> IpAddr {
    v4(198, 51, 100, 30)
}
/// A second callee.
fn uas2() -> IpAddr {
    v4(203, 0, 113, 40)
}

/// A fixed instant plus `us` microseconds.
fn at(us: i64) -> Result<DateTime<Utc>, TestError> {
    let base = DateTime::from_timestamp(1_700_000_000, 0).ok_or("a fixed instant")?;
    Ok(base + TimeDelta::microseconds(us))
}

/// An SDP body whose origin line is `o=` followed by `origin_value` verbatim.
fn sdp(origin_value: &str) -> String {
    format!(
        "v=0\r\no={origin_value}\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n\
         m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

/// An SDP body with no origin line at all.
fn sdp_without_origin() -> String {
    "v=0\r\ns=-\r\nc=IN IP4 198.51.100.7\r\nt=0 0\r\n\
     m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        .to_string()
}

/// Parse `first_line` plus the dialog headers of `call_id` and `body`, as sent
/// on `hop` at `us`.
fn message(
    first_line: &str,
    call_id: &str,
    cseq: &str,
    hop: Hop,
    body: Option<&str>,
    us: i64,
) -> Result<SipMessage, TestError> {
    let body = body.unwrap_or("");
    let via = format!(
        "Via: SIP/2.0/UDP {}:5060;branch=z9hG4bK-{call_id}-{}",
        hop.src,
        cseq.replace(' ', "-")
    );
    let cid = format!("Call-ID: {call_id}");
    let from = format!("From: <sip:alice@example.com>;tag=f-{call_id}");
    // The dialog-forming INVITE has no To tag; responses and later requests do.
    let to = if first_line.starts_with("SIP/2.0") || !cseq.starts_with("1 ") {
        format!("To: <sip:bob@example.com>;tag=t-{call_id}")
    } else {
        "To: <sip:bob@example.com>".to_string()
    };
    let cseq = format!("CSeq: {cseq}");
    let len = format!("Content-Length: {}", body.len());
    let mut headers = vec![
        via.as_str(),
        from.as_str(),
        to.as_str(),
        cid.as_str(),
        cseq.as_str(),
    ];
    if !body.is_empty() {
        headers.push("Content-Type: application/sdp");
    }
    headers.push(&len);
    let raw = crate::test_utils::build_sip_message(first_line, &headers, body.as_bytes());
    Ok(parse_sip(
        &raw,
        at(us)?,
        hop.src,
        hop.dst,
        hop.sport,
        hop.dport,
        TransportProto::Udp,
    )
    .map_err(|e| format!("should parse: {e:?}"))?)
}

/// An INVITE on `hop` at `us`, with `body` when given.
fn invite(call_id: &str, hop: Hop, body: Option<&str>, us: i64) -> Result<SipMessage, TestError> {
    message(
        "INVITE sip:bob@example.com SIP/2.0",
        call_id,
        "1 INVITE",
        hop,
        body,
        us,
    )
}

/// A response to the INVITE that `hop` carried, sent back on it at `us`.
fn reply(
    status: &str,
    call_id: &str,
    hop: Hop,
    body: Option<&str>,
    us: i64,
) -> Result<SipMessage, TestError> {
    message(
        &format!("SIP/2.0 {status}"),
        call_id,
        "1 INVITE",
        hop.back(),
        body,
        us,
    )
}

/// One leg: an INVITE whose offer has `origin` at `start` microseconds and a
/// bodiless 200 OK at `end`, so the dialog lives from `start` to `end`.
fn leg(
    store: &mut DialogStore,
    call_id: &str,
    hop: Hop,
    origin: &str,
    start: i64,
    end: i64,
) -> Result<(), TestError> {
    store.process_message(invite(call_id, hop, Some(&sdp(origin)), start)?);
    store.process_message(reply("200 OK", call_id, hop, None, end)?);
    Ok(())
}

/// The legs `call_id` is tied to by `sdp_origin`, as (Call-ID, score).
fn by_origin(store: &DialogStore, call_id: &str) -> Vec<(String, u8)> {
    let mut found: Vec<(String, u8)> = store
        .find_correlated_scored(call_id)
        .iter()
        .filter(|r| r.reason == CorrelationReason::SdpOrigin)
        .map(|r| (r.dialog.call_id.clone(), r.score))
        .collect();
    found.sort();
    found
}

/// `(call_id, 90)` for each of `ids`, sorted, for comparing with [`by_origin`].
fn at_90(ids: &[&str]) -> Vec<(String, u8)> {
    let mut v: Vec<(String, u8)> = ids.iter().map(|id| ((*id).to_string(), 90)).collect();
    v.sort();
    v
}

/// The A leg (caller to SBC) and the B leg (SBC to callee) of one call through
/// a B2BUA that forwards the offer untouched: the shape every success case
/// starts from.
fn passthrough(origin_a: &str, origin_b: &str) -> Result<DialogStore, TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        origin_a,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc(), uas()),
        origin_b,
        2_000,
        890_000,
    )?;
    Ok(store)
}

// ── SUCCESS: a B2BUA passed the origin through ───────────────────────────

/// The base case: two legs on two hops, set up together, one origin.
#[test]
fn a_b2bua_passing_the_offer_through_is_an_identifier_match() -> Result<(), TestError> {
    let store = passthrough(ORIGIN, ORIGIN)?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a b2bua passing the offer through is an identifier match"
    );
    let (name, identifier) = CorrelationReason::SdpOrigin.strategy();
    assert_eq!(
        (name, identifier),
        ("sdp_origin", true),
        "a b2bua passing the offer through is an identifier match"
    );
    Ok(())
}

/// The match is the same asked from the B leg.
#[test]
fn the_match_holds_asked_from_the_b_leg() -> Result<(), TestError> {
    let store = passthrough(ORIGIN, ORIGIN)?;
    assert_eq!(
        by_origin(&store, "b@example.com"),
        at_90(&["a@example.com"]),
        "the match holds asked from the b leg"
    );
    Ok(())
}

/// A re-INVITE later in the call bumps `sess-version` on both legs; the tuple
/// excludes the version, so the legs still match.
#[test]
fn a_re_invite_that_bumps_the_version_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let a = hop(uac(), sbc());
    let b = hop(sbc(), uas());
    store.process_message(invite("a@example.com", a, None, 0)?);
    store.process_message(invite("b@example.com", b, None, 1_000)?);
    let bumped = sdp("alice 2890844526 2890842808 IN IP4 192.0.2.1");
    store.process_message(message(
        "INVITE sip:bob@example.com SIP/2.0",
        "a@example.com",
        "2 INVITE",
        a,
        Some(&bumped),
        30_000_000,
    )?);
    store.process_message(message(
        "INVITE sip:bob@example.com SIP/2.0",
        "b@example.com",
        "2 INVITE",
        b,
        Some(&bumped),
        30_001_000,
    )?);
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a re invite that bumps the version keeps the match"
    );
    Ok(())
}

/// Hold: the re-INVITE carries `a=sendonly` and a bumped version; the legs
/// still match on the origin the initial offer and the hold share.
#[test]
fn a_hold_re_invite_keeps_the_match() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    let hold = "v=0\r\no=alice 2890844526 2890842809 IN IP4 192.0.2.1\r\ns=-\r\n\
                c=IN IP4 198.51.100.7\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=sendonly\r\n";
    for (call_id, h, us) in [
        ("a@example.com", hop(uac(), sbc()), 600_000),
        ("b@example.com", hop(sbc(), uas()), 601_000),
    ] {
        store.process_message(message(
            "INVITE sip:bob@example.com SIP/2.0",
            call_id,
            "2 INVITE",
            h,
            Some(hold),
            us,
        )?);
    }
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a hold re invite keeps the match"
    );
    Ok(())
}

/// Early media: the B2BUA re-originated the offer, so the offers differ, but
/// it passed the callee's 183 answer through, and the answer's origin ties
/// the legs.
#[test]
fn an_early_media_answer_passed_through_is_a_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let a = hop(uac(), sbc());
    let b = hop(sbc(), uas());
    store.process_message(invite("a@example.com", a, Some(&sdp(ORIGIN)), 0)?);
    let reoriginated = sdp("sbc 1111111111 1111111111 IN IP4 192.0.2.10");
    store.process_message(invite("b@example.com", b, Some(&reoriginated), 1_000)?);
    let answer = sdp(ANSWER_ORIGIN);
    store.process_message(reply(
        "183 Session Progress",
        "b@example.com",
        b,
        Some(&answer),
        50_000,
    )?);
    store.process_message(reply(
        "183 Session Progress",
        "a@example.com",
        a,
        Some(&answer),
        51_000,
    )?);
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "an early media answer passed through is a match"
    );
    Ok(())
}

/// A late offer: neither INVITE carries SDP, and the callee's offer in the
/// 200 OK crosses the B2BUA.
#[test]
fn a_late_offer_in_the_200_is_a_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let a = hop(uac(), sbc());
    let b = hop(sbc(), uas());
    store.process_message(invite("a@example.com", a, None, 0)?);
    store.process_message(invite("b@example.com", b, None, 1_000)?);
    let offer = sdp(ANSWER_ORIGIN);
    store.process_message(reply("200 OK", "b@example.com", b, Some(&offer), 80_000)?);
    store.process_message(reply("200 OK", "a@example.com", a, Some(&offer), 81_000)?);
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a late offer in the 200 is a match"
    );
    Ok(())
}

/// A B2BUA that forks to two callees on two hosts: the A leg matches both.
#[test]
fn a_forking_b2bua_ties_the_a_leg_to_both_forks() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    leg(
        &mut store,
        "b2@example.com",
        hop(sbc(), uas2()),
        ORIGIN,
        2_100,
        400_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b2@example.com", "b@example.com"]),
        "a forking b2bua ties the a leg to both forks"
    );
    Ok(())
}

/// The two forks of one call carry one session's offer and match each other.
#[test]
fn the_forks_of_one_call_match_each_other() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    leg(
        &mut store,
        "b2@example.com",
        hop(sbc(), uas2()),
        ORIGIN,
        2_100,
        400_000,
    )?;
    assert_eq!(
        by_origin(&store, "b2@example.com"),
        at_90(&["a@example.com", "b@example.com"]),
        "the forks of one call match each other"
    );
    Ok(())
}

/// A chain of two B2BUAs is three legs, each on its own hop; the first leg
/// matches the other two.
#[test]
fn a_chain_of_two_b2buas_ties_all_three_legs() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "l1@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "l2@example.com",
        hop(sbc(), sbc2()),
        ORIGIN,
        1_000,
        899_000,
    )?;
    leg(
        &mut store,
        "l3@example.com",
        hop(sbc2(), uas()),
        ORIGIN,
        2_000,
        898_000,
    )?;
    assert_eq!(
        by_origin(&store, "l1@example.com"),
        at_90(&["l2@example.com", "l3@example.com"]),
        "a chain of two b2buas ties all three legs"
    );
    assert_eq!(
        by_origin(&store, "l3@example.com"),
        at_90(&["l1@example.com", "l2@example.com"]),
        "a chain of two b2buas ties all three legs"
    );
    Ok(())
}

/// The call tree walks a chain of `sdp_origin` edges and reports each as an
/// identifier match.
#[test]
fn the_call_tree_walks_a_b2bua_chain_by_origin() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "l1@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "l2@example.com",
        hop(sbc(), sbc2()),
        ORIGIN,
        1_000,
        899_000,
    )?;
    leg(
        &mut store,
        "l3@example.com",
        hop(sbc2(), uas()),
        ORIGIN,
        2_000,
        898_000,
    )?;
    let tree = store
        .correlation_tree("l1@example.com", 10)
        .ok_or("a tree")?;
    let mut ids: Vec<&str> = tree.legs.iter().map(|l| l.call_id.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(
        ids,
        ["l1@example.com", "l2@example.com", "l3@example.com"],
        "the call tree walks a b2bua chain by origin"
    );
    for l in tree.legs.iter().skip(1) {
        assert_eq!(l.strategy, Some("sdp_origin"), "{}", l.call_id);
        assert_eq!(l.identifier_match, Some(true), "{}", l.call_id);
    }
    Ok(())
}

/// An hour-long call whose B leg was set up at the start still matches when
/// asked about at the end.
#[test]
fn a_long_call_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let hour = 3_600_000_000;
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        hour,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc(), uas()),
        ORIGIN,
        2_000,
        hour - 1_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a long call keeps the match"
    );
    Ok(())
}

/// A B2BUA that retries the same next hop after a 503: the two tries never
/// overlap, so they do not show the origin reused, and the A leg matches
/// both.
#[test]
fn a_retry_to_the_same_next_hop_after_a_failure_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let next = hop(sbc(), uas());
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        900_000,
    )?;
    store.process_message(invite("try1@example.com", next, Some(&sdp(ORIGIN)), 1_000)?);
    store.process_message(reply(
        "503 Service Unavailable",
        "try1@example.com",
        next,
        None,
        40_000,
    )?);
    leg(
        &mut store,
        "try2@example.com",
        next,
        ORIGIN,
        50_000,
        890_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["try1@example.com", "try2@example.com"]),
        "a retry to the same next hop after a failure keeps the match"
    );
    Ok(())
}

/// Failover to a second callee on another host after the first one failed.
#[test]
fn a_failover_to_another_next_hop_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let first = hop(sbc(), uas());
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        900_000,
    )?;
    store.process_message(invite(
        "try1@example.com",
        first,
        Some(&sdp(ORIGIN)),
        1_000,
    )?);
    store.process_message(reply(
        "408 Request Timeout",
        "try1@example.com",
        first,
        None,
        32_000,
    )?);
    leg(
        &mut store,
        "try2@example.com",
        hop(sbc(), uas2()),
        ORIGIN,
        33_000,
        890_000,
    )?;
    assert!(
        by_origin(&store, "a@example.com").contains(&("try2@example.com".to_string(), 90)),
        "a failover to another next hop keeps the match: "
    );
    Ok(())
}

/// A proxy and a B2BUA on one host, talking over one address on two ports:
/// the two legs are two hops, so the legs match.
#[test]
fn a_one_host_b2bua_on_two_ports_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let host = sbc();
    let a = Hop {
        src: host,
        sport: 5060,
        dst: host,
        dport: 5080,
    };
    let b = Hop {
        src: host,
        sport: 5080,
        dst: host,
        dport: 5090,
    };
    leg(&mut store, "a@example.com", a, ORIGIN, 0, 900_000)?;
    leg(&mut store, "b@example.com", b, ORIGIN, 1_000, 899_000)?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a one host b2bua on two ports keeps the match"
    );
    Ok(())
}

/// A hairpin through an SBC: proxy to SBC, then SBC back to the proxy.
#[test]
fn a_hairpin_through_an_sbc_keeps_the_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "a@example.com",
        hop(sbc(), sbc2()),
        ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc2(), sbc()),
        ORIGIN,
        1_000,
        899_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a hairpin through an sbc keeps the match"
    );
    Ok(())
}

/// The reproduction's own legs: three calls placed one after the other by
/// SIPp through a proxy, every call with SIPp's constant origin. Each call's
/// A leg still matches its own B leg.
#[test]
fn each_sequential_sipp_call_keeps_its_own_b_leg() -> Result<(), TestError> {
    let store = sipp_sequential()?;
    assert_eq!(
        by_origin(&store, "1-th-call@example.com"),
        at_90(&["1-th-call-b@example.com"]),
        "each sequential sipp call keeps its own b leg"
    );
    assert_eq!(
        by_origin(&store, "3-th-call@example.com"),
        at_90(&["3-th-call-b@example.com"]),
        "each sequential sipp call keeps its own b leg"
    );
    Ok(())
}

// ── FAILURE: one origin, unrelated calls ─────────────────────────────────

/// Three SIPp calls through a proxy, one second apart, each with an A leg
/// (SIPp to proxy) and a B leg (proxy to callee), all with one origin.
fn sipp_sequential() -> Result<DialogStore, TestError> {
    let mut store = DialogStore::new(100, false);
    for n in 0..3_i64 {
        let start = n * 1_000_000;
        leg(
            &mut store,
            &format!("{}-th-call@example.com", n + 1),
            hop(uac(), sbc()),
            SIPP_ORIGIN,
            start,
            start + 600_000,
        )?;
        leg(
            &mut store,
            &format!("{}-th-call-b@example.com", n + 1),
            hop(sbc(), uas()),
            SIPP_ORIGIN,
            start + 1_000,
            start + 599_000,
        )?;
    }
    Ok(store)
}

/// The defect as found: SIPp's constant origin tied calls 2 and 3 to call 1
/// as an identifier match at 90.
#[test]
fn sdp_origin_reused_across_calls_is_not_an_identifier_match() -> Result<(), TestError> {
    let store = sipp_sequential()?;
    let found = by_origin(&store, "1-th-call@example.com");
    for other in [
        "2-th-call@example.com",
        "3-th-call@example.com",
        "2-th-call-b@example.com",
        "3-th-call-b@example.com",
    ] {
        assert!(
            found.iter().all(|(id, _)| id != other),
            "{other} is another call: {found:?}"
        );
    }
    Ok(())
}

/// One phone's two calls, a minute apart, on one hop, with one origin.
#[test]
fn one_phones_consecutive_calls_do_not_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "first@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        30_000_000,
    )?;
    leg(
        &mut store,
        "second@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        90_000_000,
        120_000_000,
    )?;
    assert!(
        by_origin(&store, "first@example.com").is_empty(),
        "one phones consecutive calls do not match: {:?}",
        by_origin(&store, "first@example.com")
    );
    assert!(
        by_origin(&store, "second@example.com").is_empty(),
        "one phones consecutive calls do not match: {:?}",
        by_origin(&store, "second@example.com")
    );
    Ok(())
}

/// A load test: twenty concurrent SIPp calls, each with an A leg and a B leg,
/// one origin. No leg matches any other by that origin.
#[test]
fn many_concurrent_calls_sharing_one_origin_match_nothing_by_it() -> Result<(), TestError> {
    let store = sipp_concurrent(20)?;
    for n in 1..=20 {
        let id = format!("{n}-load@example.com");
        assert_eq!(by_origin(&store, &id), Vec::new(), "{id}");
    }
    Ok(())
}

/// [`many_concurrent_calls_sharing_one_origin_match_nothing_by_it`]'s
/// fixture: `calls` calls 100 ms apart, each lasting 10 s.
fn sipp_concurrent(calls: i64) -> Result<DialogStore, TestError> {
    let mut store = DialogStore::new(1000, false);
    for n in 0..calls {
        let start = n * 100_000;
        leg(
            &mut store,
            &format!("{}-load@example.com", n + 1),
            hop(uac(), sbc()),
            SIPP_ORIGIN,
            start,
            start + 10_000_000,
        )?;
        leg(
            &mut store,
            &format!("{}-load-b@example.com", n + 1),
            hop(sbc(), uas()),
            SIPP_ORIGIN,
            start + 1_000,
            start + 9_999_000,
        )?;
    }
    Ok(store)
}

/// In that load test a call's own B leg is not reported by the origin either:
/// the origin is shown not to be unique, so it identifies nothing, and the
/// answer says less rather than guess which leg is which call's.
#[test]
fn in_a_load_test_even_a_calls_own_b_leg_is_not_an_origin_match() -> Result<(), TestError> {
    let store = sipp_concurrent(5)?;
    assert!(
        by_origin(&store, "3-load@example.com").is_empty(),
        "in a load test even a calls own b leg is not an origin match: {:?}",
        by_origin(&store, "3-load@example.com")
    );
    assert!(
        by_origin(&store, "3-load-b@example.com").is_empty(),
        "in a load test even a calls own b leg is not an origin match: {:?}",
        by_origin(&store, "3-load-b@example.com")
    );
    Ok(())
}

/// Two concurrent calls from one phone, on one hop, with one origin.
#[test]
fn two_concurrent_calls_from_one_phone_do_not_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "first@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        30_000_000,
    )?;
    leg(
        &mut store,
        "second@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        5_000_000,
        40_000_000,
    )?;
    assert!(
        by_origin(&store, "first@example.com").is_empty(),
        "two concurrent calls from one phone do not match: {:?}",
        by_origin(&store, "first@example.com")
    );
    Ok(())
}

/// Reuse shown by two other dialogs withholds the match from a pair that
/// would otherwise qualify: the origin is not unique in this capture.
#[test]
fn reuse_shown_elsewhere_in_the_capture_withholds_the_match() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    leg(
        &mut store,
        "x1@example.com",
        hop(uas2(), sbc2()),
        ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "x2@example.com",
        hop(uas2(), sbc2()),
        ORIGIN,
        10_000,
        900_000,
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "reuse shown elsewhere in the capture withholds the match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// Reuse seen only on the far side, on the proxy-to-callee hop, as a capture
/// taken there sees a load test.
#[test]
fn reuse_seen_only_on_the_far_hop_is_still_reuse() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    for n in 0..3_i64 {
        leg(
            &mut store,
            &format!("{n}-far@example.com"),
            hop(sbc(), uas()),
            SIPP_ORIGIN,
            n * 100_000,
            n * 100_000 + 5_000_000,
        )?;
    }
    assert!(
        by_origin(&store, "0-far@example.com").is_empty(),
        "reuse seen only on the far hop is still reuse: {:?}",
        by_origin(&store, "0-far@example.com")
    );
    Ok(())
}

/// Calls placed one after the other share an origin in the offer and in the
/// answer; neither ties them.
#[test]
fn calls_reusing_both_offer_and_answer_origins_do_not_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let h = hop(uac(), sbc());
    let answer = sdp(ANSWER_ORIGIN);
    for (call_id, start) in [("done@example.com", 0), ("pending@example.com", 2_700_000)] {
        store.process_message(invite(call_id, h, Some(&sdp(ORIGIN)), start)?);
        store.process_message(reply("200 OK", call_id, h, Some(&answer), start + 2_000)?);
        store.process_message(message(
            "BYE sip:bob@example.com SIP/2.0",
            call_id,
            "2 BYE",
            h,
            None,
            start + 600_000,
        )?);
    }
    assert!(
        by_origin(&store, "done@example.com").is_empty(),
        "calls reusing both offer and answer origins do not match: {:?}",
        by_origin(&store, "done@example.com")
    );
    Ok(())
}

/// When the origin no longer ties two consecutive calls, a weaker strategy
/// that matches still reports them, at its own strength: here the timing
/// heuristic, as a guess.
#[test]
fn a_withheld_origin_match_falls_through_to_a_timing_guess() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "first@example.com",
        hop(uac(), sbc()),
        SIPP_ORIGIN,
        0,
        500_000,
    )?;
    leg(
        &mut store,
        "second@example.com",
        hop(uac(), sbc()),
        SIPP_ORIGIN,
        1_000_000,
        1_500_000,
    )?;
    let found = store.find_correlated_scored("first@example.com");
    assert_eq!(found.len(), 1, "one leg");
    assert_eq!(
        found[0].reason,
        CorrelationReason::TimingHeuristic,
        "a withheld origin match falls through to a timing guess"
    );
    assert_eq!(
        found[0].score, 50,
        "a withheld origin match falls through to a timing guess"
    );
    assert!(!found[0].reason.strategy().1, "a guess, not an identifier");
    Ok(())
}

/// The call tree does not cross from one SIPp call to the next.
#[test]
fn the_call_tree_does_not_cross_a_reused_origin() -> Result<(), TestError> {
    let store = sipp_sequential()?;
    let tree = store
        .correlation_tree("1-th-call@example.com", 50)
        .ok_or("a tree")?;
    let crossed: Vec<&str> = tree
        .legs
        .iter()
        .filter(|l| l.identifier_match == Some(true))
        .map(|l| l.call_id.as_str())
        .filter(|id| !id.starts_with("1-"))
        .collect();
    assert!(crossed.is_empty(), "{crossed:?}");
    Ok(())
}

/// The defect's two Call-IDs, set up on two hops with one origin, the way
/// the reproduction's legs were: `o=` lines that are not the six RFC 8866
/// fields, or whose numbers are not numbers, identify nothing.
fn malformed_pair(origin_value: &str) -> Result<DialogStore, TestError> {
    passthrough(origin_value, origin_value)
}

#[test]
fn an_origin_with_five_fields_matches_nothing() -> Result<(), TestError> {
    let store = malformed_pair("alice 2890844526 IN IP4 192.0.2.1")?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an origin with five fields matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

#[test]
fn an_origin_with_seven_fields_matches_nothing() -> Result<(), TestError> {
    let store = malformed_pair("alice 2890844526 2890842807 IN IP4 192.0.2.1 extra")?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an origin with seven fields matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// [RFC 8866 section 9](https://www.rfc-editor.org/rfc/rfc8866.html#section-9): `sess-id = 1*DIGIT`.
#[test]
fn an_origin_whose_sess_id_is_not_digits_matches_nothing() -> Result<(), TestError> {
    let store = malformed_pair("alice 28908x4526 2890842807 IN IP4 192.0.2.1")?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an origin whose sess id is not digits matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// [RFC 8866 section 9](https://www.rfc-editor.org/rfc/rfc8866.html#section-9): `sess-version = 1*DIGIT`.
#[test]
fn an_origin_whose_sess_version_is_not_digits_matches_nothing() -> Result<(), TestError> {
    let store = malformed_pair("alice 2890844526 -1 IN IP4 192.0.2.1")?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an origin whose sess version is not digits matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

#[test]
fn an_empty_origin_matches_nothing() -> Result<(), TestError> {
    let store = malformed_pair("")?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an empty origin matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

#[test]
fn sdp_without_an_origin_line_matches_nothing() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let body = sdp_without_origin();
    store.process_message(invite("a@example.com", hop(uac(), sbc()), Some(&body), 0)?);
    store.process_message(invite(
        "b@example.com",
        hop(sbc(), uas()),
        Some(&body),
        1_000,
    )?);
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "sdp without an origin line matches nothing: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

#[test]
fn legs_without_a_body_match_nothing_by_origin() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.process_message(invite("a@example.com", hop(uac(), sbc()), None, 0)?);
    store.process_message(invite("b@example.com", hop(sbc(), uas()), None, 1_000)?);
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "legs without a body match nothing by origin: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

// ── EDGE ─────────────────────────────────────────────────────────────────

/// An IPv6 origin (RFC 3849 address) passed through matches.
#[test]
fn an_ipv6_origin_passed_through_matches() -> Result<(), TestError> {
    let o = "alice 2890844526 2890842807 IN IP6 2001:db8::1";
    let store = passthrough(o, o)?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "an ipv6 origin passed through matches"
    );
    Ok(())
}

/// One address string under two address types is two origins.
#[test]
fn the_same_address_under_another_address_type_does_not_match() -> Result<(), TestError> {
    let store = passthrough(
        "alice 2890844526 2890842807 IN IP4 192.0.2.1",
        "alice 2890844526 2890842807 IN IP6 192.0.2.1",
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "the same address under another address type does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// A different network type is a different origin.
#[test]
fn another_network_type_does_not_match() -> Result<(), TestError> {
    let store = passthrough(
        "alice 2890844526 2890842807 IN IP4 192.0.2.1",
        "alice 2890844526 2890842807 XX IP4 192.0.2.1",
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "another network type does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// Two legs on two hops, the second starting at the instant the first ended:
/// the rule is inclusive, so they match.
#[test]
fn a_leg_starting_at_the_instant_the_other_ended_matches() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        500_000,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc(), uas()),
        ORIGIN,
        500_000,
        900_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a leg starting at the instant the other ended matches"
    );
    Ok(())
}

/// One microsecond later, they do not.
#[test]
fn a_leg_starting_one_microsecond_after_the_other_ended_does_not_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        500_000,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc(), uas()),
        ORIGIN,
        500_001,
        900_000,
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "a leg starting one microsecond after the other ended does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// Two legs a capture stamped with one instant, each a single message.
#[test]
fn two_legs_stamped_with_one_instant_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    store.process_message(invite(
        "a@example.com",
        hop(uac(), sbc()),
        Some(&sdp(ORIGIN)),
        7,
    )?);
    store.process_message(invite(
        "b@example.com",
        hop(sbc(), uas()),
        Some(&sdp(ORIGIN)),
        7,
    )?);
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "two legs stamped with one instant match"
    );
    Ok(())
}

/// An origin seen again a day later, on another hop, does not match.
#[test]
fn an_origin_reused_after_a_long_gap_does_not_match() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let day = 86_400_000_000;
    leg(
        &mut store,
        "a@example.com",
        hop(uac(), sbc()),
        ORIGIN,
        0,
        60_000_000,
    )?;
    leg(
        &mut store,
        "b@example.com",
        hop(sbc(), uas()),
        ORIGIN,
        day,
        day + 60_000_000,
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an origin reused after a long gap does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// The tuple is compared as written: a username in another case is another
/// username.
#[test]
fn a_username_in_another_case_does_not_match() -> Result<(), TestError> {
    let store = passthrough(
        "alice 2890844526 2890842807 IN IP4 192.0.2.1",
        "Alice 2890844526 2890842807 IN IP4 192.0.2.1",
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "a username in another case does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// An IPv6 address in another case is compared as written too: a B2BUA that
/// forwards the line forwards its bytes, and one that rewrites it has made
/// a new line.
#[test]
fn an_ipv6_address_in_another_case_does_not_match() -> Result<(), TestError> {
    let store = passthrough(
        "alice 2890844526 2890842807 IN IP6 2001:db8::a",
        "alice 2890844526 2890842807 IN IP6 2001:DB8::A",
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "an ipv6 address in another case does not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// Runs of spaces between the fields still split into the same six fields.
#[test]
fn extra_spaces_between_fields_still_match() -> Result<(), TestError> {
    let store = passthrough(ORIGIN, "alice  2890844526   2890842807 IN  IP4 192.0.2.1")?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "extra spaces between fields still match"
    );
    Ok(())
}

/// A tab between two fields still splits.
#[test]
fn a_tab_between_fields_still_matches() -> Result<(), TestError> {
    let store = passthrough(ORIGIN, "alice\t2890844526 2890842807 IN IP4 192.0.2.1")?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a tab between fields still matches"
    );
    Ok(())
}

/// Trailing whitespace after the address is not part of it.
#[test]
fn trailing_whitespace_still_matches() -> Result<(), TestError> {
    let store = passthrough(ORIGIN, "alice 2890844526 2890842807 IN IP4 192.0.2.1  ")?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "trailing whitespace still matches"
    );
    Ok(())
}

/// A 4096-character username passed through matches.
#[test]
fn a_very_long_username_passed_through_matches() -> Result<(), TestError> {
    let o = format!(
        "{} 2890844526 2890842807 IN IP4 192.0.2.1",
        "u".repeat(4096)
    );
    let store = passthrough(&o, &o)?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a very long username passed through matches"
    );
    Ok(())
}

/// Two 4096-character usernames that differ in the last character do not.
#[test]
fn very_long_usernames_differing_in_the_last_character_do_not_match() -> Result<(), TestError> {
    let one = format!(
        "{}a 2890844526 2890842807 IN IP4 192.0.2.1",
        "u".repeat(4095)
    );
    let two = format!(
        "{}b 2890844526 2890842807 IN IP4 192.0.2.1",
        "u".repeat(4095)
    );
    let store = passthrough(&one, &two)?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "very long usernames differing in the last character do not match: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// The documented limit: a parallel fork to two contacts through one next
/// hop puts two overlapping legs on one hop, which is what reuse looks like,
/// so the match is withheld rather than guessed.
#[test]
fn a_parallel_fork_through_one_next_hop_is_withheld() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    leg(
        &mut store,
        "b2@example.com",
        hop(sbc(), uas()),
        ORIGIN,
        2_100,
        400_000,
    )?;
    assert!(
        by_origin(&store, "a@example.com").is_empty(),
        "a parallel fork through one next hop is withheld: {:?}",
        by_origin(&store, "a@example.com")
    );
    Ok(())
}

/// SIPp with `-t un` sends each call from its own port. The sending port is
/// not part of the hop, so concurrent calls still show the origin reused.
#[test]
fn concurrent_calls_from_one_host_on_different_ports_show_reuse() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    for (n, sport) in [(1_i64, 40_001_u16), (2, 40_002), (3, 40_003)] {
        let h = Hop {
            src: uac(),
            sport,
            dst: sbc(),
            dport: 5060,
        };
        leg(
            &mut store,
            &format!("{n}-un@example.com"),
            h,
            SIPP_ORIGIN,
            n * 100_000,
            n * 100_000 + 5_000_000,
        )?;
        leg(
            &mut store,
            &format!("{n}-un-b@example.com"),
            hop(sbc(), uas()),
            SIPP_ORIGIN,
            n * 100_000 + 1_000,
            n * 100_000 + 4_999_000,
        )?;
    }
    assert!(
        by_origin(&store, "1-un@example.com").is_empty(),
        "concurrent calls from one host on different ports show reuse: {:?}",
        by_origin(&store, "1-un@example.com")
    );
    Ok(())
}

/// Reuse of one origin does not withhold a match on another: each origin is
/// judged on its own carriers.
#[test]
fn a_reused_origin_does_not_withhold_a_unique_one() -> Result<(), TestError> {
    let mut store = passthrough(ORIGIN, ORIGIN)?;
    leg(
        &mut store,
        "x1@example.com",
        hop(uac(), sbc()),
        SIPP_ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "x2@example.com",
        hop(uac(), sbc()),
        SIPP_ORIGIN,
        10_000,
        900_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a reused origin does not withhold a unique one"
    );
    assert!(
        by_origin(&store, "x1@example.com").is_empty(),
        "a reused origin does not withhold a unique one: {:?}",
        by_origin(&store, "x1@example.com")
    );
    Ok(())
}

/// A leg that carries both a reused origin and a unique one matches by the
/// unique one.
#[test]
fn a_leg_carrying_a_unique_origin_beside_a_reused_one_matches() -> Result<(), TestError> {
    let mut store = DialogStore::new(100, false);
    let a = hop(uac(), sbc());
    let b = hop(sbc(), uas());
    // Each leg's offer has SIPp's origin; each answer the unique one.
    for (call_id, h, us) in [("a@example.com", a, 0), ("b@example.com", b, 1_000)] {
        store.process_message(invite(call_id, h, Some(&sdp(SIPP_ORIGIN)), us)?);
        store.process_message(reply(
            "200 OK",
            call_id,
            h,
            Some(&sdp(ANSWER_ORIGIN)),
            us + 80_000,
        )?);
    }
    // And two concurrent calls on one hop show SIPp's origin reused.
    leg(
        &mut store,
        "x1@example.com",
        hop(uas2(), sbc()),
        SIPP_ORIGIN,
        0,
        900_000,
    )?;
    leg(
        &mut store,
        "x2@example.com",
        hop(uas2(), sbc()),
        SIPP_ORIGIN,
        10_000,
        900_000,
    )?;
    assert_eq!(
        by_origin(&store, "a@example.com"),
        at_90(&["b@example.com"]),
        "a leg carrying a unique origin beside a reused one matches"
    );
    Ok(())
}
